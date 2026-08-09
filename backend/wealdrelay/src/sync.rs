// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `SUB` and `RECON`, as the socket performs them.
//!
//! `src/negentropy/` decides and this module does the I/O: read the group's items,
//! turn a reconciliation answer into frames, backfill a cursor, hand a live
//! envelope to the hub. Split out of `src/ws.rs` rather than added to it, because
//! `ws.rs` is the framing layer and these are two protocol operations with database
//! reads in them.
//!
//! ## Frame order is part of the protocol, not an implementation detail
//!
//! On `RECON` the pushes go out **before** the answering `RECON` frame. The
//! client's next round is computed against what it holds
//! (`negentropy::advance`), so a client that received the answer first would
//! compute its next message against a stale set and ask again for envelopes
//! already in flight. WebSocket delivery on one connection is ordered, so sending
//! pushes first is a guarantee and not a race that usually resolves the right way.
//!
//! On `SUB` the acknowledgement goes out **first**, because it carries the head the
//! client needs in order to know whether the backfill that follows is complete.
//!
//! ## A truncated backfill is not a lie
//!
//! `log::MAX_BACKFILL` bounds the database read and `SYNC_PUSH_LIMIT` bounds what
//! reaches the socket in one response. A client further behind sees that the head
//! in its acknowledgement is beyond what arrived and reconciles. Nothing is
//! dropped; the client simply uses the mechanism built for catching up.

use std::sync::Arc;

use crate::frame::{ErrorCode, Frame, FrameError};
use crate::health::RelayState;
use crate::hub::ConnectionId;
use crate::log;
use crate::negentropy::{self, Message, Mode, Range};
use crate::ws::queue_all;

/// One response also needs its control frame (`RECON`) or acknowledgement
/// (`SUB_ACK`) to fit in the outbound queue.  Keep the data batch below that
/// bound; a client that is further behind already has the protocol machinery to
/// ask another reconciliation round.
const SYNC_PUSH_LIMIT: usize = crate::session::SEND_QUEUE_BOUND - 1;

/// The bytes one response's pushes may occupy.
///
/// The frame count above is not a size. `SYNC_PUSH_LIMIT` envelopes at the megabyte
/// the schema allows is a quarter of a gigabyte on one connection, which is what
/// `ws::SEND_QUEUE_BYTE_BUDGET` exists to refuse. A batch built to the frame count
/// alone would therefore be refused by the queue and the connection would end, which
/// would turn a memory bound into a disconnect for every client of a group with large
/// envelopes: the same failure the handshake replay had, arrived at from the other
/// side. So the batch is cut to what the queue will actually take.
///
/// `MAX_FRAME_BYTES` is held back for the `RECON` or `SUB_ACK` that follows the
/// pushes. That frame is what tells the client the round is not finished, so a batch
/// that filled the budget and left no room for it would strand exactly the client it
/// was serving.
const SYNC_PUSH_BYTES: usize = crate::ws::SEND_QUEUE_BYTE_BUDGET - crate::frame::MAX_FRAME_BYTES;

/// How many of these frames fit in one response's byte allowance.
///
/// At least one, always: a single envelope larger than the allowance still has to be
/// sendable, and `ws::try_queue` takes one frame of any size against an empty queue
/// for the same reason.
fn fits_in_budget<T>(items: &[T], allowance: usize, cost: impl Fn(&T) -> usize) -> usize {
    if allowance == 0 {
        // No room at all, which is a queue that already holds a replay or a backlog
        // rather than a client this batch can serve. Nothing is taken, and the
        // acknowledgement the client already has names a head beyond what arrived.
        return 0;
    }
    let mut spent = 0usize;
    let mut taken = 0usize;
    for item in items {
        let next = spent.saturating_add(cost(item));
        if taken > 0 && next > allowance {
            break;
        }
        spent = next;
        taken += 1;
    }
    taken
}

/// How many push frames may be queued now, against what the queue already holds.
///
/// The two constants above describe an empty queue, and by the time a batch is built
/// the queue is not empty: `subscribe` has queued the `SUB_ACK` and then the group's
/// entire MLS replay through `queue_all_awaiting`, which by design leaves up to the
/// whole bound outstanding. A batch built to the constants was then handed to
/// `queue_all`, which treats a full queue as a client that has stopped reading and
/// ends the connection, so a group with a large handshake log was unsubscribable for
/// any client even slightly behind, identically on every reconnect. Truncating is
/// what `specs/backend/relay/operations.md` asks for ("cut to fit that budget rather
/// than built to the frame count and then refused"), and it is safe here because the
/// acknowledgement already carries a head beyond what arrives.
///
/// One slot and one frame's bytes are held back for the `SUB_ACK` or `RECON` that
/// closes the round, for the reason `SYNC_PUSH_BYTES` gives.
fn push_frame_allowance(sender: &crate::ws::OutboundSender) -> usize {
    sender.free_slots().saturating_sub(1).min(SYNC_PUSH_LIMIT)
}

fn push_byte_allowance(sender: &crate::ws::OutboundSender) -> usize {
    crate::ws::SEND_QUEUE_BYTE_BUDGET
        .saturating_sub(sender.queued_bytes())
        .saturating_sub(crate::frame::MAX_FRAME_BYTES)
        .min(SYNC_PUSH_BYTES)
}

/// Reopen every span holding an omitted id as a fingerprint.
///
/// Extracted because there are now two reasons a response is short of what the client
/// asked for, the frame count and the byte allowance, and both owe the client the same
/// thing: a range left open so it drives another round. A `skip` here would falsely
/// claim the omitted ids had settled and strand the client forever.
fn reopen_omitted(
    reply: &mut Message,
    incoming: &Message,
    items: &[negentropy::Item],
    omitted: &[negentropy::Id],
) {
    if omitted.is_empty() {
        return;
    }
    // A set rather than a nested scan. The pair of `any` calls this replaces was
    // O(spans x omitted x items) over a vector that is the whole group, which is the
    // same whole-group cost `log::items` is filed for (WEALD-210) paid a second time
    // in memory. One pass per span against a hash lookup says the same thing.
    let omitted: std::collections::HashSet<negentropy::Id> = omitted.iter().copied().collect();
    for (lower, upper, _) in incoming.spans() {
        if items
            .iter()
            .any(|item| item.seq >= lower && item.seq < upper && omitted.contains(&item.id))
        {
            let mine: Vec<_> = items
                .iter()
                .copied()
                .filter(|item| item.seq >= lower && item.seq < upper)
                .collect();
            // Every arm of `negentropy::respond` emits a range ending at its
            // span's upper bound, so this always matches exactly once. Written
            // as a filtered loop rather than as `find` and an `if let` for that
            // reason: the `else` of the `if let` was a branch no input could
            // reach, and a silent no-op there would be precisely the stranding
            // this block exists to prevent. A loop that runs once says the same
            // thing without carrying an arm nobody can test, and it stays
            // correct if a future `respond` ever emits two.
            for range in reply.ranges.iter_mut().filter(|range| range.upper == upper) {
                *range = Range::new(
                    upper,
                    Mode::Fingerprint(crate::negentropy::fingerprint(&mine)),
                );
            }
        }
    }
}

/// Answer one `RECON` round. Returns false when the connection should end.
pub async fn reconcile(
    sender: &crate::ws::OutboundSender,
    state: &Arc<RelayState>,
    group: Vec<u8>,
    payload: Vec<u8>,
) -> bool {
    let incoming = match Message::decode(&payload) {
        Ok(message) => message,
        // One bad frame on a session that is otherwise fine. The client is told
        // which rule it broke, in the closed registry's terms, and the connection
        // continues: a peer whose reconciliation payload is malformed can still
        // `SEND` and still `SUB`.
        Err(error) => return queue_all(sender, vec![Frame::Error(FrameError::new(error.code()))]),
    };

    let Some(database) = &state.database else {
        return queue_all(
            sender,
            vec![Frame::Error(FrameError::new(ErrorCode::Backpressure))],
        );
    };

    let items = match log::items(database.pool(), &group).await {
        Ok(items) => items,
        Err(_) => {
            return queue_all(
                sender,
                vec![Frame::Error(FrameError::new(ErrorCode::Backpressure))],
            )
        }
    };

    let mut response = negentropy::respond(&items, &incoming);

    // A valid empty id-list can ask for an entire group's history.  Sending that
    // history as one run used to overflow the per-connection queue and close the
    // socket.  Push one bounded batch and leave every range with omitted ids open
    // as a fingerprint, so the client drives the next (smaller) round after it has
    // applied this batch.
    //
    // The frame count is the first cut and it also bounds the read below. The second
    // cut is by size and cannot be made until the envelopes are in hand.
    let frame_allowance = push_frame_allowance(sender);
    let mut omitted: Vec<negentropy::Id> = if response.push.len() > frame_allowance {
        response.push.split_off(frame_allowance)
    } else {
        Vec::new()
    };

    // Anything that vanished between the item read and now is skipped rather than
    // reported: `log::envelopes_for` documents why, and it is a function so that the
    // skip is provable against a real database rather than by inspection.
    let envelopes = match log::envelopes_for(database.pool(), &group, &response.push).await {
        Ok(envelopes) => envelopes,
        Err(_) => {
            return queue_all(
                sender,
                vec![Frame::Error(FrameError::new(ErrorCode::Backpressure))],
            )
        }
    };
    // The second cut. Everything past it joins the ids the frame count already
    // omitted, and the ranges are reopened once, against both.
    let mut envelopes = envelopes;
    // The frame's own cost, measured as the empty frame plus its payload rather than
    // by building the frame: the allowance is spent on the envelope bytes and the rest
    // is the header allowance `Frame::queued_bytes` already accounts for.
    let sendable = fits_in_budget(&envelopes, push_byte_allowance(sender), |(_, bytes)| {
        Frame::Push {
            envelope: Vec::new(),
        }
        .queued_bytes()
            + bytes.len()
    });
    omitted.extend(envelopes.split_off(sendable).into_iter().map(|(id, _)| id));
    reopen_omitted(&mut response.reply, &incoming, &items, &omitted);

    let mut frames: Vec<Frame> = envelopes
        .into_iter()
        .map(|(_, envelope)| Frame::Push { envelope })
        .collect();
    frames.push(Frame::Recon {
        group,
        payload: response.reply.encode(),
    });
    queue_all(sender, frames)
}

/// Register a subscription, acknowledge it, and backfill from the cursor.
pub async fn subscribe(
    sender: &crate::ws::OutboundSender,
    state: &Arc<RelayState>,
    connection: ConnectionId,
    group: Vec<u8>,
    from_seq: u64,
    protocol_version: u16,
) -> bool {
    let head = crate::ws::head_seq(state, &group).await;

    if !queue_all(
        sender,
        vec![Frame::SubAck {
            group: group.clone(),
            // `max` with the client's cursor, unchanged from step 4: a client that
            // names a cursor beyond the head is told its own number rather than
            // being invited to walk backwards.
            head_seq: head.max(from_seq),
        }],
    ) {
        return false;
    }

    // Registered after the acknowledgement and before the backfill read, which is
    // the one order with neither a hole nor a frame out of sequence. Registering
    // first would let a live push arrive ahead of the acknowledgement that carries
    // the head; registering after the backfill would lose anything accepted while
    // the backfill query ran. Between the two, an envelope accepted in the gap is
    // both fanned out and returned by the query, and a client deduplicates it
    // without coordination because the hash is a content address
    // (`specs/backend/relay/migration.md`, dual transport).
    state
        .hub
        .subscribe(&group, connection, sender.clone(), protocol_version)
        .await;

    let Some(database) = &state.database else {
        // No database is not a reason to refuse the subscription: the client is
        // registered, the acknowledgement went out, and the honest backfill from a
        // relay that cannot read its log is none. `/readyz` reports the outage.
        return true;
    };

    // Handshake messages first, in their own order, and all of them from zero.
    //
    // Not "since the client's cursor", because that cursor is the envelope log's
    // and the two sequences are unrelated. And not partially, because MLS state is
    // built by applying every message in order from the group's creation: a member
    // that joined at epoch 9 still has to process the commits that produced epochs
    // 1 through 9 to hold a tree it can decrypt against. A client that already has
    // them discards the ones it recognises, which costs a comparison; a client that
    // is missing one cannot decrypt anything published after it, which costs the
    // group.
    //
    // Before the envelopes on purpose. An envelope encrypted under epoch N is
    // unreadable until the commit that produced epoch N has been applied, so a
    // backfill in the other order hands a client ciphertext it must buffer and then
    // reprocess.
    // `queue_all_awaiting` rather than `queue_all`, and the difference is a group's
    // joinability. This run's length is the group's epoch count, not anything the
    // client chose, so a group that has committed more times than `SEND_QUEUE_BOUND`
    // would refuse every subscription from every member, permanently, and reconnecting
    // would meet the same wall. Truncating instead is not available: there is no
    // reconciliation for MLS state and a member missing one commit cannot decrypt
    // anything published after it. So the replay waits for the writer to make room and
    // the queue bound still holds across it.
    match crate::handshake::store::since(database.pool(), &group, 0).await {
        Ok(messages) => {
            if !crate::ws::queue_all_awaiting(
                sender,
                messages
                    .into_iter()
                    .map(|stored| Frame::Handshake {
                        group: group.clone(),
                        seq: stored.seq,
                        message: stored.message,
                    })
                    .collect(),
            )
            .await
            {
                return false;
            }
        }
        Err(_) => {
            return queue_all(
                sender,
                vec![Frame::Error(FrameError::new(ErrorCode::Backpressure))],
            )
        }
    }

    // Bounded by the frame count and then by the byte allowance, for the reason
    // `SYNC_PUSH_BYTES` gives. Truncating here is safe in a way it is not for the
    // handshake replay above: the acknowledgement already sent carries a head beyond
    // what arrives, and the client reconciles for the rest.
    match log::since(database.pool(), &group, from_seq).await {
        Ok(envelopes) => {
            let mut envelopes: Vec<Vec<u8>> = envelopes
                .into_iter()
                .take(push_frame_allowance(sender))
                .collect();
            let sendable = fits_in_budget(&envelopes, push_byte_allowance(sender), |bytes| {
                Frame::Push {
                    envelope: Vec::new(),
                }
                .queued_bytes()
                    + bytes.len()
            });
            envelopes.truncate(sendable);
            queue_all(
                sender,
                envelopes
                    .into_iter()
                    .map(|envelope| Frame::Push { envelope })
                    .collect(),
            )
        }
        Err(_) => queue_all(
            sender,
            vec![Frame::Error(FrameError::new(ErrorCode::Backpressure))],
        ),
    }
}

/// Hand one accepted envelope to every other subscriber.
///
/// The bytes carry the relay-assigned `seq` and `ts`, which is what makes a
/// receiving client's cursor advance without a second round trip. The content
/// address is unaffected by both fields (`envelope::content_hash`), so the pushed
/// envelope still verifies against its own hash.
pub async fn deliver(
    state: &Arc<RelayState>,
    envelope: &crate::envelope::Envelope,
    seq: u64,
    now_ms: u64,
    from: ConnectionId,
) {
    let mut delivered = envelope.clone();
    delivered.seq = seq;
    delivered.ts = now_ms;
    let bytes = delivered.encode();
    // The hub counts its own downgrades, so there is one place a full queue is
    // recorded rather than one per call site.
    state.hub.fanout(&envelope.group, &bytes, from).await;
}
