// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The socket. WebSocket in, frames out, and the queue bounds that make
//! backpressure real.
//!
//! Every protocol rule lives in `src/session.rs`. This module does four things
//! and nothing else: read a message, decode it, hand it to the session, and
//! perform whatever work the session deferred. That division is why the rules are
//! testable without a network and why this file's own tests are about framing.
//!
//! ## Backpressure is a bound, not an intention
//!
//! `specs/backend/relay/operations.md`: a relay under load slows down rather than
//! dropping envelopes, because a dropped envelope is a hole in an author chain and
//! therefore a security alarm on somebody else's screen. Concretely:
//!
//! - The per-connection send queue is bounded. When it is full the writer stops,
//!   which stops the reader, which stops reading the socket, which pushes back
//!   through TCP. Nothing is accepted and discarded.
//! - A subscriber that cannot keep up is **told** and downgraded to
//!   reconciliation, so it catches up by range fetch instead of stalling the
//!   fanout for everyone. Silence would be indistinguishable from a relay that
//!   had dropped its envelopes.
//! - `ephemeral` is the only kind that may be shed, which is why it is the only
//!   kind the relay is permitted to drop at all. Nothing in this step writes one.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt as _, StreamExt as _};
use tokio::sync::mpsc;

use crate::accept::{self, Accepted};
use crate::envelope::Envelope;
use crate::frame::{ErrorCode, Frame, FrameDecodeError, FrameError, MAX_FRAME_BYTES};
use crate::health::RelayState;
use crate::session::{Reaction, Session, Work, SEND_QUEUE_BOUND};

/// What a connection's writer half is told to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    Frame(Frame),
    /// A WebSocket ping, for the liveness exchange the idle deadline is built on
    /// (`crate::deadline`).
    ///
    /// Not a `Frame`, because it is not one: it carries no protocol meaning, a
    /// conforming client's transport answers it without its application ever
    /// seeing it, and putting it in the frame table would have meant a wire tag
    /// and a version bump for something the WebSocket layer already defines. It
    /// spends nothing against the byte budget for the reason `Close` does not:
    /// the queue is most likely to be full exactly when the relay most needs to
    /// find out whether anybody is still reading it.
    Ping,
    /// Flush and close.
    Close,
}

/// Why a subscriber was downgraded, as the client is told it.
///
/// A frame rather than a log line: the client has to know that it is now
/// responsible for catching up by reconciliation, and a relay that only logged it
/// would leave the client believing it was still live.
pub fn downgrade_frame(group: &[u8]) -> Frame {
    Frame::SubAck {
        group: group.to_vec(),
        // Zero rather than a head: the client is being told to reconcile from
        // whatever it holds, and naming a head would invite it to trust a cursor
        // that the downgrade means it cannot.
        head_seq: 0,
    }
}

/// The result of trying to queue one frame for a slow client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Queued {
    Sent,
    /// The bound was hit. The caller downgrades the subscriber rather than
    /// dropping the envelope.
    Full,
    /// The connection has gone.
    Closed,
}

/// The bytes one connection may hold queued but not yet written.
///
/// The frame count alone was not a bound on anything that matters. A `Push` carries
/// an envelope, whose `ct` the schema caps at 1 MiB, so `SEND_QUEUE_BOUND` frames of
/// it is about 257 MiB on one connection, and `handshake::MAX_MESSAGE_BYTES` gets to
/// half of that per frame by another route. Nothing capped the number of connections
/// doing it at once, so a handful of backlogged clients was an out-of-memory kill,
/// which is a worse failure than the one the bound exists to prevent: the whole point
/// of `specs/backend/relay/operations.md` "Backpressure" is that a slow consumer
/// degrades to reconciliation while everybody else keeps going.
///
/// Eight mebibytes, which is eight of the largest envelope the relay will accept, or
/// several thousand of the small ones a busy group actually produces. Sized so that a
/// modest instance can hold a few hundred connections at their ceiling at once rather
/// than so that any single connection is comfortable: a connection that reaches this
/// is by definition not keeping up, and the protocol has an answer for that.
pub const SEND_QUEUE_BYTE_BUDGET: usize = 8 * 1024 * 1024;

/// The sending half of a connection's outbound queue, bounded in both units.
///
/// A wrapper rather than a bare `mpsc::Sender` because `tokio` bounds a channel by
/// message count and there is no count that is also a memory bound when messages
/// differ in size by three orders of magnitude. The frame count is still enforced by
/// the channel underneath: it is the right bound for the many-small-frames case, and
/// the byte budget is the right one for the few-large-frames case, so both are kept.
///
/// The byte budget is a `Semaphore` rather than a counter, because a caller that
/// cannot proceed has to be able to wait for room without polling for it
/// (`queue_all_awaiting`), and a semaphore is the primitive that both refuses
/// immediately and waits, against the same accounting.
#[derive(Debug, Clone)]
pub struct OutboundSender {
    inner: mpsc::Sender<Outbound>,
    budget: Arc<tokio::sync::Semaphore>,
}

/// The receiving half, which returns a frame's bytes to the budget as it takes it.
#[derive(Debug)]
pub struct OutboundReceiver {
    inner: mpsc::Receiver<Outbound>,
    budget: Arc<tokio::sync::Semaphore>,
}

/// What one frame costs against the byte budget, as a permit count.
///
/// Clamped to the whole budget so an outsized frame is expensive rather than
/// unsendable: a frame that could never acquire its permits would be refused on every
/// connection forever, which is a worse failure than briefly holding the queue alone.
/// Nothing the relay sends today comes close (`MAX_FRAME_BYTES` is one mebibyte
/// against a budget of eight), so the clamp is a guard on a future frame rather than
/// a path with traffic on it.
fn permits_for(frame: &Frame) -> u32 {
    let cost = frame.queued_bytes().min(SEND_QUEUE_BYTE_BUDGET);
    u32::try_from(cost).unwrap_or(u32::MAX)
}

impl OutboundSender {
    /// Bytes currently queued and not yet written.
    pub fn queued_bytes(&self) -> usize {
        SEND_QUEUE_BYTE_BUDGET - self.budget.available_permits()
    }

    /// Frames that can still be queued before the channel's own bound is reached.
    ///
    /// Exposed for the same reason [`OutboundSender::queued_bytes`] is: a batch built
    /// to a constant derived from the empty queue is a batch that gets refused when
    /// something is already in it, and a refused control run ends the connection. See
    /// `sync::subscribe`.
    pub fn free_slots(&self) -> usize {
        self.inner.capacity()
    }

    /// Ask the channel to close, without waiting.
    ///
    /// `try_send` rather than `send`, for the reason `close_on_deadline` gives:
    /// `Close` spends no budget, but it still occupies one of the 256 channel
    /// slots, and the writer task only drains those by awaiting the socket. A
    /// peer that has stopped reading therefore parks the writer forever, so an
    /// awaiting close parks its caller forever too, on precisely the connection
    /// this call exists to let go of. That leaked the connection slot, the hub
    /// entries and the send budget at `handle_message`, and stalled a whole
    /// rotation at `Hub::evict`, where one wedged victim blocked every later
    /// one.
    ///
    /// A full queue means the peer is 256 frames behind and will not read a
    /// polite close either; dropping the sender is what actually ends the
    /// socket. False means "not queued", and no caller treats that as failure.
    pub fn close(&self) -> bool {
        self.inner.try_send(Outbound::Close).is_ok()
    }

    /// Queue a liveness ping, without waiting.
    ///
    /// `try_send` rather than `send`, and the failure is not an error. A full
    /// queue means this connection already has 256 frames the peer has not taken,
    /// which answers the question the ping was going to ask more directly than the
    /// ping would: there is no need to probe a peer that is visibly behind, and
    /// waiting for room here would park the reader on the one connection where
    /// nobody is draining. False means "not queued"; the deadline logic treats the
    /// probe as sent either way, so a wedged peer is still closed on schedule.
    pub fn try_ping(&self) -> bool {
        self.inner.try_send(Outbound::Ping).is_ok()
    }
}

impl OutboundReceiver {
    pub async fn recv(&mut self) -> Option<Outbound> {
        let taken = self.inner.recv().await;
        self.release(taken.as_ref());
        taken
    }

    pub fn try_recv(&mut self) -> Result<Outbound, mpsc::error::TryRecvError> {
        let taken = self.inner.try_recv();
        self.release(taken.as_ref().ok());
        taken
    }

    /// Give back what the frame reserved, measured from the frame itself rather than
    /// carried alongside it. `queued_bytes` is a pure function of the frame and the
    /// frame is immutable in the queue, so the two halves cannot disagree.
    fn release(&self, taken: Option<&Outbound>) {
        if let Some(Outbound::Frame(frame)) = taken {
            self.budget.add_permits(permits_for(frame) as usize);
        }
    }
}

/// Queue one frame without waiting.
///
/// `try_send` and not `send`. Awaiting a full queue inside the fanout would make
/// one slow subscriber stall every other subscriber to the same group, which is
/// exactly the failure the downgrade rule exists to avoid.
pub fn try_queue(sender: &OutboundSender, frame: Frame) -> Queued {
    let cost = permits_for(&frame);
    // Acquired before the send and given back if it fails, so two callers racing on
    // the last of the budget cannot both be told there was room.
    let Ok(permit) = sender.budget.try_acquire_many(cost) else {
        return Queued::Full;
    };

    match sender.inner.try_send(Outbound::Frame(frame)) {
        Ok(()) => {
            // The bytes are now the receiver's to give back.
            permit.forget();
            Queued::Sent
        }
        // The permit is dropped here, which returns it.
        Err(mpsc::error::TrySendError::Full(_)) => Queued::Full,
        Err(mpsc::error::TrySendError::Closed(_)) => Queued::Closed,
    }
}

/// Encode a frame for the wire, or refuse it as over the cap.
///
/// The writer's authoritative length check: `Frame::queued_bytes` is an estimate
/// for the queue budget, so the ceiling every peer enforces (`MAX_FRAME_BYTES`,
/// the same bound `Frame::decode` and `handle_message` apply inbound) has to be
/// measured against the encoded bytes themselves. `Err` carries the offending
/// length so the caller can say what it refused.
pub fn encode_bounded(frame: &Frame) -> Result<Vec<u8>, usize> {
    let bytes = frame.encode();
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(bytes.len());
    }
    Ok(bytes)
}

/// How long teardown waits for the writer task to finish its last send.
///
/// Five seconds is a drain, not a deadline: every frame still queued is already
/// bounded by `SEND_QUEUE_BYTE_BUDGET`, so a peer reading at any usable rate is
/// finished well inside it, and a peer reading at none is not going to be finished
/// by a larger number.
pub const WRITER_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A connection's outbound channel, bounded by ``SEND_QUEUE_BOUND`` frames and
/// ``SEND_QUEUE_BYTE_BUDGET`` bytes, whichever is reached first.
pub fn outbound_channel() -> (OutboundSender, OutboundReceiver) {
    let (inner_sender, inner_receiver) = mpsc::channel(SEND_QUEUE_BOUND);
    let budget = Arc::new(tokio::sync::Semaphore::new(SEND_QUEUE_BYTE_BUDGET));
    (
        OutboundSender {
            inner: inner_sender,
            budget: Arc::clone(&budget),
        },
        OutboundReceiver {
            inner: inner_receiver,
            budget,
        },
    )
}

/// Serve one WebSocket connection.
/// Serve one connection, told where it came from.
///
/// The source is used by one path and one only: the redeem budget in
/// `specs/backend/relay/invites.md`, which is per source and per token. It is hashed
/// with the workspace salt before it reaches a table and is never logged, so what
/// the relay retains is a value it cannot turn back into an address. `None` when the
/// router was mounted without connection info, which is a deployment behind a proxy
/// that passes none: the budget then falls back to the token and the device, which
/// narrows it rather than opening it.
pub async fn serve_connection(socket: WebSocket, state: Arc<RelayState>, source: Option<String>) {
    // The hub identity for this connection. Allocated before the first frame so a
    // `SUB` arriving in the same TCP segment as `AUTH` has somewhere to register,
    // and allocated here rather than inside so it can name the span the whole
    // connection runs under.
    let connection = state.hub.connect();
    // The correlation handle every line from this socket carries.
    //
    // Until this span existed a relay's log was a flat sequence with nothing tying
    // two lines to the same connection, so reconstructing one client's session
    // during an incident meant guessing from timestamps. `conn` is the hub's own
    // per-process counter: opaque, allocated in arrival order, meaningless outside
    // this process and reset by a restart. That is deliberate and it is the whole
    // reason it is safe to log. It is not a principal, not a group, not a device
    // and not a source address: `source` is never logged anywhere in this file
    // (see the doc comment above), and a trace id derived from it would put the
    // address in the log under a different name.
    //
    // `instrument` rather than `span.enter()`, because a guard held across an
    // `.await` attaches the span to whatever the runtime polls next. Everything
    // this connection does, including every `handle_message` below it, inherits
    // the field without one call site passing it.
    use tracing::Instrument as _;
    serve_connection_inner(socket, state, source, connection)
        .instrument(tracing::info_span!("relay_connection", conn = connection))
        .await;
}

async fn serve_connection_inner(
    socket: WebSocket,
    state: Arc<RelayState>,
    source: Option<String>,
    connection: crate::hub::ConnectionId,
) {
    let (mut sink, mut stream) = socket.split();
    let (sender, mut receiver) = outbound_channel();
    tracing::debug!("connection opened");

    // The writer is its own task so the bound is real: when it is full the reader
    // below stops making progress, which stops it reading the socket.
    let writer_state = Arc::clone(&state);
    let mut writer = tokio::spawn(async move {
        loop {
            match receiver.recv().await {
                Some(Outbound::Frame(frame)) => {
                    // The outbound mirror of the inbound `MAX_FRAME_BYTES` gate at
                    // `handle_message`. Every conforming peer refuses a frame over
                    // the cap by the same symmetric rule, so writing one is not a
                    // send, it is a silent permanent wedge for this group with
                    // nothing in telemetry pointing at the cause. Counted, logged
                    // with the tag and the length, told to the peer as a real
                    // error, and then the connection is closed: an attributable
                    // failure instead of an invisible one.
                    let bytes = match encode_bounded(&frame) {
                        Ok(bytes) => bytes,
                        Err(length) => {
                            writer_state
                                .oversized_outbound_frames
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            tracing::error!(
                                tag = ?frame.tag(),
                                length,
                                cap = MAX_FRAME_BYTES,
                                "relay built an outbound frame over the wire cap; closing the connection"
                            );
                            let apology =
                                Frame::Error(FrameError::new(ErrorCode::EnvelopeTooLarge));
                            let _ = sink.send(Message::Binary(apology.encode())).await;
                            let _ = sink.close().await;
                            break;
                        }
                    };
                    // A write that fails is a client that has gone without saying so.
                    // Ending the task is the whole of the response: there is nobody to
                    // tell, and a writer that kept trying would hold a task, a queue
                    // and a socket per vanished client.
                    if sink.send(Message::Binary(bytes)).await.is_err() {
                        break;
                    }
                }
                // The liveness probe. A write that fails is the same answer a
                // missing pong would have been, one round trip earlier, so the
                // writer ends here exactly as it does for a frame.
                Some(Outbound::Ping) => {
                    if sink.send(Message::Ping(Vec::new())).await.is_err() {
                        break;
                    }
                }
                // A close the session asked for, or the reader loop ending and
                // dropping the last sender. The same thing from the writer's side, and
                // in both cases whatever was already queued has been written first,
                // because a bounded channel yields what it holds before it reports
                // that its senders have gone.
                Some(Outbound::Close) | None => {
                    let _ = sink.close().await;
                    break;
                }
            }
        }
    });

    let mut session = Session::new(&state.config);
    session.set_source(source.clone());
    let mut holds_unauthenticated_source_share = true;

    // The deadlines, and the monotonic origin they are measured from.
    //
    // `tokio::time::Instant` rather than `state.now_ms()`. The relay clock is wall
    // time, it is what an accepted envelope's receipt is recorded against, and the
    // suites pin it to a fixed instant so their vectors are stable; measuring a
    // deadline against it would mean every connection in those suites lived
    // forever, and would mean a real relay's deadlines moving when NTP stepped its
    // clock. This one only ever goes forwards, and `tokio::time::pause` advances it
    // without anybody sleeping, which is what makes the deadlines testable at all.
    let opened = tokio::time::Instant::now();
    let elapsed_ms = move || u64::try_from(opened.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut deadlines = crate::deadline::Deadlines::new(&state.config, 0);

    loop {
        // Decide before waiting, so the wait is bounded by whichever deadline is
        // nearest rather than by the peer's willingness to speak.
        let wait = match deadlines.next(elapsed_ms()) {
            crate::deadline::Next::Expired(expiry) => {
                close_on_deadline(&sender, &state, expiry);
                break;
            }
            crate::deadline::Next::Probe(window) => {
                // Recorded as probed whether or not it was queued: `try_ping`
                // fails on a queue the peer is not draining, which is not a
                // reason to give that peer another idle interval.
                let _ = sender.try_ping();
                deadlines.probed(elapsed_ms());
                window
            }
            crate::deadline::Next::Wait(remaining) => remaining,
        };

        let message = match tokio::time::timeout(wait, stream.next()).await {
            // The wait ran out. Nothing is decided here: the loop goes back to
            // `next`, which is the one place a deadline is evaluated, so a probe
            // and an expiry cannot come to disagree about the same instant.
            Err(_) => continue,
            // The stream ended, or the transport failed. Either way the peer is
            // gone and there is nothing to tell it.
            Ok(None) | Ok(Some(Err(_))) => break,
            Ok(Some(Ok(message))) => message,
        };

        // Anything at all counts as evidence the peer is there, including the pong
        // that answers a probe and including a ping of its own. What the message
        // *means* is the session's business; whether somebody sent it is this
        // deadline's, and they are different questions.
        deadlines.saw_message(elapsed_ms());

        // Receipt time belongs to this message, not to the HTTP upgrade that
        // opened the socket. In particular, a long-lived client must not make a
        // newly accepted envelope look as old as its connection.
        let now_ms = state.now_ms();
        if !handle_message(&sender, &state, &mut session, connection, message, now_ms).await {
            break;
        }
        // Checked after every message rather than at the one call site that sends
        // `AUTH_ACK`, because there are two of them (the ordinary path and the
        // bootstrap path) and they are reached through deferred work rather than
        // returned from here. `Deadlines::authenticated` is idempotent, so asking
        // repeatedly costs a branch and cannot extend anything.
        if matches!(
            session.state(),
            crate::session::State::Ready | crate::session::State::Bootstrapping
        ) {
            deadlines.authenticated(elapsed_ms());
            if holds_unauthenticated_source_share {
                state
                    .release_unauthenticated_connection(source.as_deref())
                    .await;
                holds_unauthenticated_source_share = false;
            }
        }
    }

    // Before the sender is dropped, so no fanout can queue onto a connection whose
    // reader has stopped. A hub entry outliving its socket would be fanned out to
    // once per accepted envelope for the life of the process.
    state.hub.disconnect(connection).await;
    // And out of every call it was in, for the same reason and a louder one: a
    // stale participant would be sent fifty media frames a second rather than one
    // envelope per write.
    state.calls.forget(connection).await;

    // Dropped rather than sent a `Close`. Queuing one here would be a frame like any
    // other, so it would wait for room on a queue that is full precisely when the
    // client has stopped reading, which is the case where the relay most needs to let
    // go of the connection.
    drop(sender);
    // Bounded, then aborted. `sink.send` has no timeout of its own, so a peer that
    // stops reading at the TCP level parks the writer inside a single send for as
    // long as it likes. Awaiting that join unbounded would hand the connection slot
    // released below to the peer's read rate, which is the exact hold `deadline.rs`
    // exists to end: the reader gives up on schedule and the slot leaks anyway.
    // The wait is a courtesy to a slow but live peer, not a guarantee to a hostile
    // one, so on expiry the task is aborted, which drops the sink and closes the
    // socket underneath it.
    if tokio::time::timeout(WRITER_DRAIN_TIMEOUT, &mut writer)
        .await
        .is_err()
    {
        writer.abort();
    }
    // Last, and on every path out of this function, because this is the only
    // function that can know the connection is finished. `relay_socket` took the
    // slot before the upgrade; releasing it there would have released it while the
    // socket was still open, and releasing it only on the clean path would leak
    // one per client that vanished.
    if holds_unauthenticated_source_share {
        state
            .release_unauthenticated_connection(source.as_deref())
            .await;
    }
    state.release_connection();
    // The close line, under the same span as everything this connection did. Debug
    // rather than info for the reason `logging.rs` gives about group ids one layer
    // up: a line per socket at info level on a busy relay is a log nobody reads,
    // and the aggregate an operator actually watches is
    // `weald_relay_connections` on `/metrics`. What this is for is the incident
    // where somebody already has a `conn` from an error line and needs the rest of
    // that socket's story.
    tracing::debug!(
        authenticated = !holds_unauthenticated_source_share,
        "connection closed"
    );
}

/// Decide about one incoming message. Returns false when the connection should
/// end.
///
/// Public for the same reason `perform` below is: what a client is told for each
/// kind of message it can send is a decision rather than plumbing, and the only
/// part of it that needs a socket is the socket itself. A text message, a message
/// past the length gate, a ping and a close are each answered differently, and a
/// function reachable only through an upgraded WebSocket would be a function whose
/// answers nobody had checked one at a time.
///
/// There is no separate check for a session that closed itself. Every reaction
/// that ends a session is a `ReplyAndClose`, which ends the connection here, so a
/// second check on `Session::state` would be the same decision written twice and
/// no path could reach the copy.
pub async fn handle_message(
    sender: &OutboundSender,
    state: &Arc<RelayState>,
    session: &mut Session,
    connection: crate::hub::ConnectionId,
    message: Message,
    now_ms: u64,
) -> bool {
    let bytes = match message {
        Message::Binary(bytes) => bytes,
        // Text is not a frame. The wire format is deterministic CBOR, and a
        // text frame is a client that has not read it.
        Message::Text(_) => {
            let _ = try_queue(
                sender,
                Frame::Error(FrameError::new(ErrorCode::MalformedHeader)),
            );
            return false;
        }
        // Ping and pong are the transport's, and axum answers ping itself.
        Message::Ping(_) | Message::Pong(_) => return true,
        // So is a close. The peer has said it is going and there is no frame to send
        // it, so the session stops here and the reader goes back for the end of the
        // stream: letting the transport finish its own close handshake is what makes
        // the client's close a close rather than a dropped socket.
        Message::Close(_) => return true,
    };

    if bytes.len() > MAX_FRAME_BYTES {
        // Refused on length before anything is parsed. The allocation itself is
        // bounded a layer down: the upgrade sets `max_message_size` to
        // `health::WS_MAX_MESSAGE_BYTES`, so nothing materially larger than a
        // legal frame is ever reassembled and this check is what remains for the
        // sliver between the two ceilings.
        let _ = try_queue(
            sender,
            Frame::Error(FrameError::new(ErrorCode::EnvelopeTooLarge)),
        );
        return false;
    }

    let frame = match Frame::decode(&bytes) {
        Ok(frame) => frame,
        Err(error) => {
            // A frame, always, and then the close. `operations.md` requires
            // that a client never gets a dropped connection without a frame:
            // it cannot otherwise tell a protocol error from a network one.
            let _ = try_queue(sender, Frame::Error(FrameError::new(error.code())));
            // A version failure aborts. Anything else is one bad frame on a
            // session that is otherwise fine, so the connection continues.
            return !matches!(error, FrameDecodeError::UnsupportedVersion(_));
        }
    };

    match session.handle(frame, now_ms) {
        Reaction::Reply(frames) => queue_all(sender, frames),
        Reaction::ReplyAndClose(frames) => {
            let _ = queue_all(sender, frames);
            let _ = sender.close();
            false
        }
        Reaction::Defer(work) => perform(sender, state, session, connection, work, now_ms).await,
    }
}

/// Send the frames a refusal produced and end the session.
///
/// Deferred work can decide to end a session: an `AUTH` that fails the access set is
/// a close, and it is decided after a database round trip rather than in the frame
/// table. `Session::rejected` returns the frames rather than a `Reaction` for exactly
/// this caller, because a `Reaction` here needed arms for a reply that continues and
/// for work that defers work, and neither can happen: work never defers work and a
/// refusal never continues.
fn refuse(sender: &OutboundSender, frames: Vec<Frame>) -> bool {
    let _ = queue_all(sender, frames);
    false
}

/// Seconds a client is told to wait before reconnecting after a deadline closed
/// its connection.
///
/// Five, matching the `Retry-After` on the 503 a connection past
/// `WEALD_RELAY_MAX_CONNECTIONS` gets, because they are the same message: this
/// relay has a bound and you met it. A client that reconnects immediately after
/// being closed for holding a slot is the behaviour the deadline exists to stop.
const DEADLINE_RETRY_AFTER_SECONDS: u32 = 5;

/// Close a connection whose deadline elapsed, and count it.
///
/// The same close path a refusal takes, deliberately: a frame first and then the
/// socket, because `specs/backend/relay/operations.md` requires that a client
/// never gets a dropped connection without a frame, since it cannot otherwise tell
/// a protocol decision from a network failure. `queue_all` rather than
/// `OutboundSender::close`, which is also what `refuse` does and for the sharper
/// reason here: `close` waits for room, and the idle deadline fires precisely when
/// the peer may have stopped draining, so awaiting a slot on its queue would hang
/// the one connection this function exists to let go of. Returning ends the reader
/// loop, which drops the sender, which is what closes the socket.
///
/// `quota/rate_limited` rather than a new code. It is the code this taxonomy
/// already has for a per-connection limit carrying a retry interval, and the
/// client behaviour the registry prescribes for `quota` (wait the named interval,
/// then come back) is exactly right for both deadlines. Inventing
/// `retry/handshake_timeout` would have added two rows to a published protocol
/// registry, and therefore two negative vectors and a client release, to say
/// something a client already knows how to act on. The distinction an operator
/// needs is between a deadline and a crash, and that is what the counters are
/// for; the distinction a client needs is what to do next, and that is the class.
fn close_on_deadline(
    sender: &OutboundSender,
    state: &Arc<RelayState>,
    expiry: crate::deadline::Expiry,
) {
    let _ = queue_all(
        sender,
        vec![Frame::Error(
            FrameError::new(ErrorCode::RateLimited).retry_after(DEADLINE_RETRY_AFTER_SECONDS),
        )],
    );
    state.record_deadline(expiry);
}

/// What the access set said about a connecting device.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Admitted {
    /// Admitted, and the salted hash this connection is known by.
    InSet {
        entry: Vec<u8>,
        workspace: Option<String>,
    },
    Bootstrap(String),
    Refused(ErrorCode),
}

/// May this device open this socket?
///
/// The workspace comes from the groups named in `CONNECT`, resolved against the
/// relay's own group table rather than from anything the client asserts. A
/// connection that named no group this relay knows has named no workspace, and a
/// relay that guessed one would be a relay checking a stranger against somebody
/// else's access set.
///
/// The whole read is `access::store::admission`'s, so there is one arm here for a
/// relay that could not look rather than one per query.
async fn admit(state: &Arc<RelayState>, session: &Session, device_key: &[u8]) -> Admitted {
    use crate::access::store::{self, Verdict};
    use crate::config::AccessSetMode;

    if matches!(state.config.access_set, AccessSetMode::Off) {
        // `environments.md` allows exactly one ci suite to run with enforcement off,
        // to assert that `/readyz` reports the difference. It is `enforce` in every
        // environment we operate, and the health surface says which one this is.
        // Unsalted here on purpose: with no set there is no salt to be consistent
        // with, and a hash of the key alone is a stable handle for eviction that
        // claims nothing about membership.
        return Admitted::InSet {
            entry: crate::access::entry_hash(device_key, b""),
            // This narrowly scoped CI diagnostic mode deliberately makes no
            // membership or workspace claim. Production profiles enforce access
            // sets and therefore bind a workspace below.
            workspace: None,
        };
    }
    let Some(database) = &state.database else {
        // No database is no answer, not a yes. A relay that admitted everyone while
        // it could not look would fail open in exactly the incident where the check
        // matters.
        return Admitted::Refused(ErrorCode::Backpressure);
    };
    match store::admission(database.pool(), session.requested(), device_key).await {
        Ok(Verdict::Admitted { entry, workspace }) => Admitted::InSet {
            entry,
            workspace: Some(workspace),
        },
        Ok(Verdict::Bootstrap(workspace)) => Admitted::Bootstrap(workspace),
        Ok(Verdict::UnknownGroup) => Admitted::Refused(ErrorCode::GroupUnknown),
        Ok(Verdict::Refused) => Admitted::Refused(ErrorCode::WriterNotInAccessSet),
        Err(_) => Admitted::Refused(ErrorCode::Backpressure),
    }
}

/// Refuse a target group unless it belongs to the workspace that admitted this
/// socket.  This check is intentionally before log, subscription, and envelope
/// work: authenticating for workspace A must not create an oracle or a write path
/// for workspace B (BR-013).
/// Answers with the pool the caller may then use, rather than with unit.
///
/// A caller that had to look the database up again after this returned would
/// carry a second "no database" arm that nothing can reach: the check below has
/// already answered `retry/backpressure` in that case. Two of those arms existed
/// and neither was reachable, which is how they were found: the coverage floor
/// reported them as lines no test could execute, and the correct fix for
/// unreachable code is to delete it rather than to write a test that cannot run.
pub(crate) async fn authorize_group<'a>(
    state: &'a Arc<RelayState>,
    session: &Session,
    group: &[u8],
) -> Result<&'a sqlx::PgPool, ErrorCode> {
    let Some(database) = &state.database else {
        return Err(ErrorCode::Backpressure);
    };
    let Some(workspace) = session.authorized_workspace() else {
        // Reachable with `WEALD_RELAY_ACCESS_SET=off`, the one ci diagnostic mode
        // where a session is admitted without a workspace claim. A group is a
        // workspace's, so a session that carries no workspace cannot be shown to
        // be entitled to one, and the honest answer is the same refusal a stranger
        // gets rather than an admission by default.
        return Err(ErrorCode::WriterNotInAccessSet);
    };
    match crate::access::store::workspace_of(database.pool(), group).await {
        Ok(Some(found)) if found == workspace => Ok(database.pool()),
        Ok(Some(_)) => Err(ErrorCode::WriterNotInAccessSet),
        Ok(None) => Err(ErrorCode::GroupUnknown),
        Err(_) => Err(ErrorCode::Backpressure),
    }
}

/// One `ACCESS` publication.
///
/// The rules are `crate::access::judge`'s and the transaction is
/// `crate::access::store::publish`'s. What is decided here is what the client is
/// told and what happens to other people's sockets, which is the half that needs a
/// relay rather than a function.
async fn rotate_access_set(
    sender: &OutboundSender,
    state: &Arc<RelayState>,
    session: &mut Session,
    body: Vec<u8>,
) -> bool {
    use crate::access::{store, AccessSet};

    // An empty body is the state query rather than a publication: `wire.md` requires
    // the genesis set's entries to be `BLAKE3(pubkey || workspace_salt)` and the salt
    // is the relay's, so without an answer here no client could build the first set
    // and the flow the whole section describes had no client-side path at all. The
    // shapes cannot be confused: no encoding of an `AccessSet` is zero bytes long.
    if body.is_empty() {
        return report_access_state(sender, state, session).await;
    }

    let candidate = match AccessSet::decode(&body) {
        Ok(candidate) => candidate,
        Err(error) => return queue_all(sender, vec![Frame::Error(FrameError::new(error.code()))]),
    };
    let Some(database) = &state.database else {
        return queue_all(
            sender,
            vec![Frame::Error(FrameError::new(ErrorCode::Backpressure))],
        );
    };

    // `publish_for` resolves the workspace from the groups this connection named,
    // and falls back to the bootstrap reservation when they name nothing this relay
    // knows. That fallback is the genesis case and only the genesis case: a trust
    // root publishing the first set has no groups yet, because groups are made by
    // the trust root. Neither half reads the session's memory, which is the rule a
    // relay that served one workspace's state to another would have broken.
    // A session that was admitted rotates the set of the workspace it was admitted
    // into, never the first group id it happened to name: group ids are
    // client-derived, so a member of A can squat an id B also names, and resolving
    // by first match would judge B's own rotation against A's chain and refuse it
    // forever. `state_for` already takes the bound workspace for the same reason.
    // The group-resolved form stays for a session that carries no claim, which is
    // the founding publication and `WEALD_RELAY_ACCESS_SET=off`.
    let published = match session.authorized_workspace() {
        // The founding publication, which is also where this workspace's first group
        // rows come from. Version zero is the genesis set and only the genesis set:
        // `judge` accepts it only when the workspace has no prior, so this arm cannot
        // be reached twice. It is a separate arm because `AUTH` binds the workspace it
        // admitted the founder into, on the provisional grant its reservation wrote,
        // so the founding publication arrives here rather than at `publish_for`, and
        // a genesis that registered no groups left the founder naming ids no row
        // exists for and refused `denied/group_unknown` for ever (WEALD-L304).
        Some(workspace) if candidate.version == 0 => store::publish_founding(
            database.pool(),
            workspace,
            &candidate,
            &body,
            session.requested(),
        )
        .await
        .map(store::Published::Accepted),
        Some(workspace) => store::publish(database.pool(), workspace, &candidate, &body)
            .await
            .map(store::Published::Accepted),
        None => store::publish_for(database.pool(), session.requested(), &candidate, &body).await,
    };
    match published {
        Ok(store::Published::Accepted(accepted)) => {
            // The half of offboarding the relay owns. An `ACCESS` frame that drops
            // an entry closes that device's open connections immediately; combined
            // with the MLS epoch change that removes read access to future content,
            // removal becomes one action with both halves enforced.
            for entry in &accepted.disconnect {
                state.hub.evict(entry).await;
            }
            // Answered with the accepted set echoed back, so a client learns the
            // digest its next publication must name without a second round trip.
            queue_all(
                sender,
                vec![Frame::Access {
                    body: accepted.digest.clone(),
                }],
            )
        }
        Ok(store::Published::UnknownGroup) => queue_all(
            sender,
            vec![Frame::Error(FrameError::new(ErrorCode::GroupUnknown))],
        ),
        Err(store::StoreError::Refused(error)) => {
            queue_all(sender, vec![Frame::Error(FrameError::new(error.code()))])
        }
        // A relay that could not look has not learned that anything is wrong with the
        // publication. `retry` and an open socket: the client's correct response is
        // backoff and a verbatim resend.
        Err(store::StoreError::Database(_)) => queue_all(
            sender,
            vec![Frame::Error(FrameError::new(ErrorCode::Backpressure))],
        ),
    }
}

/// Store one recovery wrap under its blinded tag.
///
/// `specs/backend/relay/groups.md`. What the relay does here is deliberately
/// small: it decodes a record it cannot open, checks that the slot moves forward,
/// and writes it. It does not learn whose wrap this is, because the index is a tag
/// derived from the group's own epoch secret and not from any recovery key, and it
/// cannot check the seal, because it holds no key that could.
///
/// The group is authorized the same way a `RECON` is, so a device outside the
/// access set cannot write into a group's wrap table.
async fn publish_wrap(
    sender: &OutboundSender,
    state: &Arc<RelayState>,
    session: &mut Session,
    body: Vec<u8>,
) -> bool {
    use crate::recovery::{store, RecoveryWrap};

    let wrap = match RecoveryWrap::decode(&body) {
        Ok(wrap) => wrap,
        // The same one-place mapping the refusal below uses: a record too large is
        // a size problem and everything else is a shape problem, and a client fixes
        // those differently.
        Err(error) => return queue_all(sender, vec![Frame::Error(FrameError::new(error.code()))]),
    };
    let pool = match authorize_group(state, session, &wrap.group).await {
        Ok(pool) => pool,
        Err(code) => return queue_all(sender, vec![Frame::Error(FrameError::new(code))]),
    };

    match store::publish(pool, &wrap).await {
        // Answered with the tag, so a publisher knows which slot moved without a
        // second round trip and without the relay repeating the ciphertext.
        Ok(_) => queue_all(
            sender,
            vec![Frame::Wrap {
                body: wrap.tag.clone(),
            }],
        ),
        // One arm, and the mapping lives on the error rather than here, so the
        // wire code for a refusal is decided in one place and walked by
        // `tests/recovery_unit.rs` rather than re-derived at each call site.
        Err(store::StoreError::Refused(error)) => {
            queue_all(sender, vec![Frame::Error(FrameError::new(error.code()))])
        }
        // A relay that could not write has not learned anything is wrong with the
        // wrap. `retry` and an open socket, exactly as a refused rotation gets.
        Err(store::StoreError::Database(_)) => queue_all(
            sender,
            vec![Frame::Error(FrameError::new(ErrorCode::Backpressure))],
        ),
    }
}

/// One step of an invite redemption.
///
/// `specs/backend/relay/invites.md` steps 4 to 7. The relay's part is small and
/// deliberately so: it verifies a code it never learns, takes a seat atomically,
/// serves ciphertext it cannot open, and records which scopes a joiner has entered.
/// It cannot tell whether the joiner belongs in the workspace, because that is what
/// the invite's signature says and what every other client checks.
///
/// Every refusal is `invite::UNAVAILABLE`. Not one code per reason: an endpoint that
/// answered "wrong code" differently from "no such token" is an endpoint that
/// confirms which tokens exist, and this one is reachable without authenticating.
/// Issue, list or revoke an invite, for a session that has authenticated.
///
/// The workspace comes from the session's own authorization and the device key from
/// what it authenticated with, so neither is taken from the frame: a caller that could
/// name its own workspace here would be a caller that could issue invites into
/// somebody else's.
async fn administer_invite(
    sender: &OutboundSender,
    state: &Arc<RelayState>,
    session: &Session,
    body: Vec<u8>,
) -> bool {
    use crate::invite::admin::{self, Request};

    let request = match Request::decode(&body) {
        Ok(request) => request,
        Err(error) => return queue_all(sender, vec![Frame::Error(FrameError::new(error.code()))]),
    };
    // `Ready` is the only state this work item is produced from, so both of these are
    // present by construction. Handled rather than unwrapped anyway: an unwrap in the
    // privileged path is a panic waiting for a state machine change nobody re-read.
    //
    // Checked before the database is looked for, not after. Who the caller is does
    // not depend on whether this relay can reach Postgres, and answering `retry` to
    // a caller that will never be allowed to do this would invite it to come back
    // forever. It also makes the guard reachable in a test, which the other order
    // did not: a relay with no database answered `retry` first, so the arm that
    // exists for a state-machine change nobody re-read could never itself be run.
    let (Some(workspace), Some(device_key)) =
        (session.authorized_workspace(), session.device_key())
    else {
        return queue_all(
            sender,
            vec![Frame::Error(FrameError::new(
                ErrorCode::WriterNotInAccessSet,
            ))],
        );
    };
    let Some(database) = &state.database else {
        return queue_all(
            sender,
            vec![Frame::Error(FrameError::new(ErrorCode::Backpressure))],
        );
    };

    match admin::handle(
        database.pool(),
        workspace,
        device_key,
        request,
        state.now_ms() as i64,
    )
    .await
    {
        Ok(response) => {
            // The half of revocation the hub owns. `store::revoke` voids every grant
            // derived from the invite, but a voided grant is only read at `AUTH`, so a
            // joiner already holding a socket kept it until it disconnected. The
            // grant's `device_hash` is the salted `entry_hash` the hub indexes
            // connections by (`access::store::admits`), which is the same key an
            // `ACCESS` publication evicts with above.
            if let admin::Response::Revoked { token } = &response {
                // Scoped to this workspace before anything is closed: the tombstone is
                // keyed by token alone, so an admin of another workspace must not be
                // able to close its connections by presenting its token.
                if crate::invite::store::belongs_to(database.pool(), token, workspace)
                    .await
                    .unwrap_or(false)
                {
                    if let Ok(Some(hashes)) =
                        crate::invite::store::tombstoned_hashes(database.pool(), token).await
                    {
                        for hash in &hashes {
                            state.hub.evict(hash).await;
                        }
                    }
                }
            }
            queue_all(
                sender,
                vec![Frame::Invite {
                    body: response.encode(),
                }],
            )
        }
        Err(error) => queue_all(sender, vec![Frame::Error(FrameError::new(error.code()))]),
    }
}

async fn redeem(
    sender: &OutboundSender,
    state: &Arc<RelayState>,
    session: &Session,
    body: Vec<u8>,
) -> bool {
    use crate::invite::redeem::{Request, Response};
    use crate::invite::reserve::{self, Verdict};
    use crate::invite::{store, UNAVAILABLE};

    let refuse = |sender: &OutboundSender| {
        queue_all(sender, vec![Frame::Error(FrameError::new(UNAVAILABLE))])
    };

    let request = match Request::decode(&body) {
        Ok(request) => request,
        Err(error) => return queue_all(sender, vec![Frame::Error(FrameError::new(error.code()))]),
    };
    let Some(database) = &state.database else {
        return queue_all(
            sender,
            vec![Frame::Error(FrameError::new(ErrorCode::Backpressure))],
        );
    };
    let pool = database.pool();

    // Which workspace this token belongs to, which the relay reads from the record
    // rather than taking from the caller: a joiner that named its own workspace could
    // have its device hashed against another workspace's salt.
    let token = match &request {
        Request::Reserve { token, .. }
        | Request::Bundles { token, .. }
        | Request::Record { token, .. }
        | Request::Commit { token, .. } => token.clone(),
    };
    let fetched = store::fetch(pool, &token).await.ok().flatten();

    // The `Record` step answers before this refusal, deliberately (WEALD-L152).
    //
    // Every other step needs the record to do anything, so a token that does not
    // resolve gets the one flat refusal. `Record` is different: its whole
    // specified behaviour is to answer an empty body for a token that is absent,
    // unreadable, revoked, spent or expired, indistinguishable from a live token
    // with no record. Gating it on the fetch made the refusal a
    // token-existence oracle on an unauthenticated, budget-free path: a real
    // token answered `Frame::Join`, a guessed one answered `UNAVAILABLE`, and
    // brute-force enumeration became verifiable.
    if matches!(request, Request::Record { .. }) {
        return record_step(sender, state, fetched);
    }

    let Some(record) = fetched else {
        // Absent, unreadable, or a body that does not decode. One answer, because
        // the difference between them is exactly what this endpoint refuses to tell.
        return refuse(sender);
    };
    let Ok(salt) = crate::access::store::salt(pool, &record.workspace_id).await else {
        return queue_all(
            sender,
            vec![Frame::Error(FrameError::new(ErrorCode::Backpressure))],
        );
    };

    // The source, hashed with the workspace salt before it goes anywhere. A relay
    // that stored an address would be storing the one fact about a joiner it has no
    // use for after the budget is spent.
    let source = reserve::source_hash(session.source().unwrap_or("unknown"), &salt);

    match request {
        Request::Reserve {
            code,
            nonce,
            device,
            ..
        } => {
            let device_hash = crate::access::entry_hash(&device, &salt);
            match reserve::reserve(
                pool,
                &token,
                &code,
                &nonce,
                &device_hash,
                &source,
                state.now_ms() as i64,
            )
            .await
            {
                Ok(Verdict::Reserved { expires_at_ms }) => queue_all(
                    sender,
                    vec![Frame::Join {
                        body: Response::Reserved { expires_at_ms }.encode(),
                    }],
                ),
                Ok(Verdict::Unavailable) => refuse(sender),
                // One arm, and the mapping lives on the error: a relay that could not
                // look answers `retry`, and everything else is the one generic
                // refusal this path is allowed to give.
                Err(error) => queue_all(sender, vec![Frame::Error(FrameError::new(error.code()))]),
            }
        }
        // Answered above, before the record is known to exist, so that the
        // refusal is not an existence oracle. Unreachable here.
        Request::Record { .. } => refuse(sender),
        Request::Bundles { group, .. } => {
            match store::bundles_for(pool, &token, &group, state.now_ms() as i64).await {
                // Ciphertext, served back. The relay holds no key for any of it: the
                // private half of `update_pub` is derived by the joiner from bytes that
                // travelled in a URL fragment.
                Ok(bundles) => queue_all(
                    sender,
                    vec![Frame::Join {
                        body: Response::Bundles(bundles).encode(),
                    }],
                ),
                Err(_) => queue_all(
                    sender,
                    vec![Frame::Error(FrameError::new(ErrorCode::Backpressure))],
                ),
            }
        }
        Request::Commit {
            nonce,
            device,
            group,
            ..
        } => {
            let device_hash = crate::access::entry_hash(&device, &salt);
            match reserve::scope_commit(
                pool,
                &token,
                &nonce,
                &device_hash,
                &group,
                state.now_ms() as i64,
            )
            .await
            {
                Ok(Some(receipt)) => queue_all(
                    sender,
                    vec![Frame::Join {
                        body: Response::Committed { receipt }.encode(),
                    }],
                ),
                Ok(None) => refuse(sender),
                Err(error) => queue_all(sender, vec![Frame::Error(FrameError::new(error.code()))]),
            }
        }
    }
}

/// The `Record` step's answer, which never depends on whether the token exists.
///
/// A live, unexpired invite gets its stored record, exactly as its issuer signed
/// it. Everything else, absent, unreadable, revoked, spent or expired, gets the
/// same empty body: this path is pre-AUTH and burns no code-attempt budget, and
/// the record carries `code_hash`, the Argon2id hash of the one-time code, so a
/// distinguishable answer would both confirm a guessed token and hand out the
/// material for an offline attack on a revoked invite's code.
fn record_step(
    sender: &OutboundSender,
    state: &Arc<RelayState>,
    fetched: Option<crate::invite::store::Record>,
) -> bool {
    use crate::invite::redeem::Response;
    use crate::invite::store;

    let body = match fetched {
        Some(record)
            if record.state == store::State::Live && state.now_ms() < record.invite.expires =>
        {
            record.body
        }
        _ => Vec::new(),
    };
    queue_all(
        sender,
        vec![Frame::Join {
            body: Response::Record { body }.encode(),
        }],
    )
}

/// Store one MLS handshake message and hand it to everybody else in the group.
///
/// `specs/backend/relay/groups.md`: the relay stores and forwards this and cannot
/// derive a group secret from it. What it adds is an order, which the group cannot
/// supply for itself: two members committing at the same moment produce two
/// messages, and every member has to apply them in one agreed sequence or the group
/// forks.
///
/// The publisher is acknowledged with the assigned sequence number and everybody
/// else is pushed the message. Both are the same frame, because a member that
/// reconnects and replays the log has to see exactly what a member that was
/// connected saw.
async fn publish_handshake(
    sender: &OutboundSender,
    state: &Arc<RelayState>,
    session: &mut Session,
    connection: crate::hub::ConnectionId,
    group: Vec<u8>,
    message: Vec<u8>,
) -> bool {
    use crate::handshake::{store, Handshake};

    // The bounds are not checked here. `store::append` checks them, and a second
    // check in front of it would be a second place for the two to disagree while
    // making the store's own refusal arm unreachable from the socket.
    //
    // So the group is authorized first and the bytes are judged second, which is
    // the same order every other group-addressed frame uses: a session that has no
    // business in a group learns that, and learns nothing about whether its
    // message would otherwise have been acceptable.
    let handshake = Handshake { group, message };
    let pool = match authorize_group(state, session, &handshake.group).await {
        Ok(pool) => pool,
        Err(code) => return queue_all(sender, vec![Frame::Error(FrameError::new(code))]),
    };

    let limit = crate::log_budget::limit_bytes(&state.config);
    match store::append_within(pool, &handshake, limit).await {
        Ok(appended) => {
            let frame = Frame::Handshake {
                group: handshake.group.clone(),
                seq: appended.seq(),
                message: handshake.message.clone(),
            };
            // Everybody else first, then the acknowledgement to the publisher. The
            // order matters for nobody's correctness and it keeps the publisher's
            // own `seq` the last thing it sees for this message, which is what its
            // cursor advances on.
            state
                .hub
                .fanout_frame(
                    &handshake.group,
                    &frame,
                    connection,
                    crate::hub::MIN_FANOUT_VERSION,
                )
                .await;
            // A commit that reaches every member or the group forks, so a member who
            // is asleep is exactly the member who needs waking. After the append, off
            // this task.
            crate::push::dispatch::after_commit(
                state,
                handshake.group.clone(),
                crate::push::Category::Handshake,
            );
            queue_all(sender, vec![frame])
        }
        Err(store::StoreError::Refused(error)) => {
            queue_all(sender, vec![Frame::Error(FrameError::new(error.code()))])
        }
        // A relay that could not store a commit has not learned anything is wrong
        // with it. `retry` and an open socket: the client's correct response is to
        // resend the same bytes, which the content address makes free.
        Err(store::StoreError::Database(_)) => queue_all(
            sender,
            vec![Frame::Error(FrameError::new(ErrorCode::Backpressure))],
        ),
        // The same ceiling `SEND` refuses on, because handshake bytes are counted
        // by the same counter. Nothing was written.
        Err(store::StoreError::LogBudgetExhausted { .. }) => queue_all(
            sender,
            vec![Frame::Error(FrameError::new(ErrorCode::LogBudgetExhausted))],
        ),
    }
}

/// One ephemeral beat.
///
/// The access-set check is `authorize_group`, reused rather than copied: the
/// requirement in `specs/backend/relay/presence.md` is that a beat is admitted by
/// exactly the check `SEND` is admitted by, and two copies of a rule are two
/// places for it to drift.
///
/// Then fanout, and then nothing. No sequence number, no acknowledgement, no row.
/// No other connected subscriber means the beat is discarded, which is normal and
/// is not an error: a member beating into a room nobody is watching has said
/// nothing that needed keeping.
async fn publish_live(
    sender: &OutboundSender,
    state: &Arc<RelayState>,
    session: &mut Session,
    connection: crate::hub::ConnectionId,
    group: Vec<u8>,
    epoch: u64,
    ct: Vec<u8>,
) -> bool {
    if let Err(code) = authorize_group(state, session, &group).await {
        return queue_all(sender, vec![Frame::Error(FrameError::new(code))]);
    }
    let frame = Frame::Live {
        group: group.clone(),
        epoch,
        ct,
    };
    // Version 2 and above only. A version 1 subscriber never learns the frame
    // existed, which is what makes a version 1 client keep working unchanged.
    state.hub.fanout_frame(&group, &frame, connection, 2).await;
    true
}

/// One key-package publication or fetch.
async fn key_packages(
    sender: &OutboundSender,
    state: &Arc<RelayState>,
    session: &mut Session,
    body: crate::frame::KeysBody,
) -> bool {
    let answer = crate::keys::handle(state, session, body).await;
    if queue_all(sender, vec![answer.frame]) {
        return true;
    }
    // The fetch deleted the packages in the statement that selected them, so a
    // queue that refused the answer has destroyed one-time keys that reached
    // nobody. The shelf is finite and a peer can repeat the fetch, so without
    // this the whole shelf walks away and the device stops being addable while
    // believing it is stocked. Restoring only ever touches the rows this call
    // consumed.
    if !answer.restore.is_empty() {
        if let Some(database) = &state.database {
            let workspace = answer.restore_workspace.clone().unwrap_or_default();
            if let Err(error) =
                crate::keys::store::restore(database.pool(), &workspace, &answer.restore).await
            {
                tracing::warn!(
                    error = %error,
                    count = answer.restore.len(),
                    "keys: an undelivered fetch could not be restored to the shelf"
                );
            }
        }
    }
    false
}

/// One push-wake registration, clear or query.
///
/// The authorization is the same one every other frame gets and is deliberately not
/// a new rule: the principal is the authenticated session's, named by the workspace's
/// own salted entry hash, so a registration can only ever be made against the device
/// that opened the socket. There is no field on the frame that could name another
/// device and no code path here that would read one.
async fn wake_registration(
    sender: &OutboundSender,
    state: &Arc<RelayState>,
    session: &Session,
    body: crate::frame::WakeBody,
    now_ms: u64,
) -> bool {
    let answer = wake_answer(state, session, body, now_ms).await;
    queue_all(sender, vec![answer])
}

/// The answer itself, as one frame.
///
/// Split from the queueing for the reason `media::handle` is: a test drives this
/// directly and sees exactly the frame the socket path queues, so the two cannot
/// disagree about what a refusal looks like.
pub async fn wake_answer(
    state: &Arc<RelayState>,
    session: &Session,
    body: crate::frame::WakeBody,
    now_ms: u64,
) -> Frame {
    use crate::frame::WakeBody;

    // Answered before anything else, and without a database. `Query` is how a client
    // learns whether to register at all, so a relay whose Postgres is unreachable
    // must still be able to say "push is on here, and this is the ringer": the
    // alternative is a client that treats an outage as push being unavailable and
    // holds no registration afterwards.
    if matches!(body, WakeBody::Query) {
        return Frame::Wake(state.push.capability());
    }
    // Denied before the database is touched, because the answer does not depend on
    // it. `denied` and not `reject`: the frame is well formed and the answer would
    // change if the operator changed one variable, so the client re-reads state with
    // `Query` rather than resending this.
    if !state.push.enabled() {
        return Frame::Error(FrameError::new(ErrorCode::PushNotConfigured));
    }
    let Some(database) = &state.database else {
        return Frame::Error(FrameError::new(ErrorCode::PushBackpressure));
    };
    // The same refusal a stranger gets, and reachable the same way `keys::handle`'s
    // is: with `WEALD_RELAY_ACCESS_SET=off`, the one mode that admits a session with
    // no workspace claim. A registration belongs to a workspace.
    let (Some(workspace), Some(device_key)) =
        (session.authorized_workspace(), session.device_key())
    else {
        return Frame::Error(FrameError::new(ErrorCode::WriterNotInAccessSet));
    };
    let pool = database.pool();
    let Ok(salt) = crate::access::store::salt(pool, workspace).await else {
        return Frame::Error(FrameError::new(ErrorCode::PushBackpressure));
    };
    let entry = crate::access::entry_hash(device_key, &salt);

    match body {
        WakeBody::Register {
            handle,
            categories,
            expires_at,
        } => {
            // An expiry already past is `push.md` section 4's stated refusal, and one
            // beyond the ringer's thirty day lifetime is a row the janitor sweep could
            // never reap: either way the bytes are permanently wrong for this
            // principal, so it is a reject and the client re-mints at the ringer.
            if !crate::push::expiry_in_bounds(expires_at, now_ms) {
                return Frame::Error(FrameError::new(ErrorCode::PushHandleMalformed));
            }
            // The ceiling is charged before the write, because the write is what it
            // exists to protect. Per principal rather than per connection, so a device
            // that reconnects does not get a fresh allowance.
            if !state.push_rate.allow(&entry, now_ms).await {
                return Frame::Error(
                    FrameError::new(ErrorCode::PushRegistrationRate)
                        .retry_after(3600)
                        .detail(u64::from(crate::push::REGISTRATIONS_PER_HOUR).to_be_bytes()),
                );
            }
            match crate::push::store::register(
                pool, workspace, &entry, &handle, categories, expires_at,
            )
            .await
            {
                Ok(crate::push::store::Registered::Stored) => {
                    Frame::Wake(WakeBody::Registered { expires_at })
                }
                // Another principal holds this handle. A reject, because the bytes are
                // permanently wrong for this principal however the relay is
                // configured: the client's fix is to ask the ringer for a handle of
                // its own, never to resend this one. The answer is the same whether
                // the other claimant is in this workspace or another, so it is not an
                // oracle for who else has registered.
                Ok(crate::push::store::Registered::HandleTaken) => {
                    Frame::Error(FrameError::new(ErrorCode::PushHandleMalformed))
                }
                Err(_) => Frame::Error(FrameError::new(ErrorCode::PushBackpressure)),
            }
        }
        // `Cleared` whether a row was there or not. The client's desired state has
        // been reached either way, and a distinguishable answer would turn this into
        // an oracle for whether a principal had registered.
        WakeBody::Clear => match crate::push::store::clear(pool, workspace, &entry).await {
            Ok(_) => Frame::Wake(WakeBody::Cleared),
            Err(_) => Frame::Error(FrameError::new(ErrorCode::PushBackpressure)),
        },
        // `session.rs` refuses the relay-to-client forms and `Query` is answered
        // above, so nothing reaches here. This arm exists because the type is one enum
        // in both directions; it gives the same answer the session table gives, so the
        // two cannot disagree.
        WakeBody::Registered { .. }
        | WakeBody::Cleared
        | WakeBody::Query
        | WakeBody::Capability { .. } => Frame::Error(FrameError::new(ErrorCode::MalformedHeader)),
    }
}

/// Answer the state query: the workspace salt and the head of the set chain.
///
/// Deliberately narrow. It reports what a publisher needs to address its next
/// publication and nothing else: not the entries, not the authorizers, not a count.
/// A client that wanted the set itself is asking for a membership fact, and the
/// relay does not hand those out to whoever opened a socket.
async fn report_access_state(
    sender: &OutboundSender,
    state: &Arc<RelayState>,
    session: &Session,
) -> bool {
    use crate::access::store;

    let Some(database) = &state.database else {
        return queue_all(
            sender,
            vec![Frame::Error(FrameError::new(ErrorCode::Backpressure))],
        );
    };
    // Answered from the workspace this session was admitted to, and from nothing
    // else. `store::state_for` resolves the first requested group that names any
    // workspace, while `store::admission` binds the session to the first requested
    // group that actually admits the device, so the two disagree exactly when a
    // client names groups from two workspaces: a member of B naming one of A's
    // group ids first would be handed A's salt, which is the value every entry
    // hash is keyed on, and A's set head. That is the cross-tenant oracle
    // `authorize_group` exists to refuse (BR-013), so the admitted workspace wins.
    //
    // The group-resolved form remains only for a session that carries no workspace
    // claim at all, which is `WEALD_RELAY_ACCESS_SET=off`: there is no tenancy
    // boundary in that mode to cross.
    //
    // The one exception is the founding device, and it is re-established from the
    // tables rather than remembered: a device holding the live, unconsumed
    // reservation on a workspace's bootstrap invite is asking for the salt with
    // which to build that workspace's first set, and there are no groups to resolve
    // it from because the set it is building is what admits the device that will
    // make them.
    let resolved = match session.authorized_workspace() {
        Some(workspace) => store::state_of(database.pool(), workspace).await.map(Some),
        None => store::state_for(database.pool(), session.requested()).await,
    };
    let found = match resolved {
        Ok(Some(state)) => Ok(Some(state)),
        Ok(None) => {
            // A session with no device key has not authenticated, and an empty key
            // matches no reservation, so it finds no workspace by exactly the same
            // route rather than by a second arm no request can reach.
            let key = session.device_key().unwrap_or_default();
            match crate::invite::genesis::founding_workspace(database.pool(), key).await {
                Ok(Some(workspace)) => store::state_of(database.pool(), &workspace).await.map(Some),
                Ok(None) => Ok(None),
                Err(error) => Err(crate::access::store::StoreError::Database(
                    error.to_string(),
                )),
            }
        }
        Err(error) => Err(error),
    };
    match found {
        Ok(Some(found)) => queue_all(
            sender,
            vec![Frame::Access {
                body: crate::access::encode_state(&found),
            }],
        ),
        Ok(None) => queue_all(
            sender,
            vec![Frame::Error(FrameError::new(ErrorCode::GroupUnknown))],
        ),
        Err(_) => queue_all(
            sender,
            vec![Frame::Error(FrameError::new(ErrorCode::Backpressure))],
        ),
    }
}

/// Queue a run of frames, in order, ending the connection if one cannot be queued.
///
/// Public because `crate::sync` queues the `SUB` and `RECON` answers and must do it
/// under exactly this rule: a control frame that cannot be queued means the client
/// has stopped reading, and holding the socket open for it is worse than closing.
pub fn queue_all(sender: &OutboundSender, frames: Vec<Frame>) -> bool {
    for frame in frames {
        // A control frame that cannot be queued means the client is not reading
        // and the queue is full of things it has not taken. Ending the connection
        // is the honest outcome: the alternative is holding a socket open for a
        // peer that has stopped listening.
        if try_queue(sender, frame) != Queued::Sent {
            return false;
        }
    }
    true
}

/// How long one frame of a run that cannot be truncated waits for room.
///
/// Ten seconds, and the number is chosen against what exhausting it means rather
/// than as a round figure: the writer task's only job is to move a queued frame onto
/// the socket, so ten seconds without room is not a slow client, it is a client that
/// has stopped taking bytes at all. A healthy peer on a bad connection drains
/// continuously and never spends this.
pub const REPLAY_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Queue a run of frames that may not be shortened, waiting for room between them.
///
/// The difference from ``queue_all`` is the whole reason this exists. `queue_all`
/// treats a full queue as a client that has stopped reading, which is right for a
/// control frame and right for anything the client can ask for again. It is wrong
/// for a run whose length is a property of the data rather than of the client: an
/// MLS replay longer than ``SEND_QUEUE_BOUND`` would fail against a peer that is
/// reading as fast as it can, and no amount of reconnecting would help, because the
/// group's history is what does not fit.
///
/// So room is waited for rather than demanded. The connection still ends if the
/// wait is exhausted, which keeps the behaviour a genuinely stalled client gets, and
/// the queue bound still holds: at most ``SEND_QUEUE_BOUND`` frames are outstanding
/// at any moment no matter how long the run is. Waiting here stops the reader loop
/// for this connection, which is the backpressure `operations.md` asks for: it
/// travels out through TCP rather than being absorbed by the relay.
pub async fn queue_all_awaiting(sender: &OutboundSender, frames: Vec<Frame>) -> bool {
    for frame in frames {
        let cost = permits_for(&frame);
        // Both bounds are waited on, in the order they are spent. The byte budget
        // first, because acquiring the permits is what reserves the memory, and then
        // room in the channel itself. A timeout on either ends the connection: there
        // is no arm here that sends part of a run and reports success.
        let Ok(Ok(permit)) = tokio::time::timeout(
            REPLAY_DRAIN_TIMEOUT,
            sender.budget.clone().acquire_many_owned(cost),
        )
        .await
        else {
            return false;
        };

        match tokio::time::timeout(
            REPLAY_DRAIN_TIMEOUT,
            sender.inner.send(Outbound::Frame(frame)),
        )
        .await
        {
            // The bytes are now the receiver's to give back, exactly as in
            // `try_queue`.
            Ok(Ok(())) => permit.forget(),
            // The permit is dropped with the frame, which returns it.
            Ok(Err(_)) | Err(_) => return false,
        }
    }
    true
}

/// Perform the work a session deferred. Returns false when the connection should
/// end.
///
/// Public so the deferred-work answers are reachable without a socket. What is
/// being checked is which frame a client receives for each kind of work, and that
/// is a decision rather than a piece of plumbing: a `SEND` carrying an
/// undecodable envelope must come back as a `reject`, and a relay whose database
/// has gone must answer `retry` rather than closing the socket in silence.
pub async fn perform(
    sender: &OutboundSender,
    state: &Arc<RelayState>,
    session: &mut Session,
    connection: crate::hub::ConnectionId,
    work: Work,
    now_ms: u64,
) -> bool {
    match work {
        Work::Authenticate {
            device_key,
            signature,
            challenge,
        } => {
            // Possession first. The signature is over the challenge **this**
            // connection issued, so a signature captured from another session
            // proves nothing here.
            if !crate::access::verify(&device_key, &challenge, &signature) {
                return refuse(sender, session.rejected(ErrorCode::WriterNotInAccessSet));
            }
            // Then membership. This is the check that makes revocation real: a
            // device the current access set does not carry cannot open a socket at
            // all, whatever it once held.
            match admit(state, session, &device_key).await {
                Admitted::InSet { entry, workspace } => {
                    // Told to the hub before the acknowledgement goes out, so a
                    // revocation that lands in the same instant closes this socket
                    // rather than missing it by a frame.
                    state.hub.identify(&entry, connection, sender.clone()).await;
                    // And membership is read again after the registration, because
                    // the first read and `identify` do not happen under one lock.
                    // A rotation that committed between them found an empty
                    // `principals` entry when it evicted, so its `evict` closed
                    // zero sockets and this one would have stayed authorized
                    // indefinitely. The two reads bracket the registration: a
                    // rotation that lands before this second read is seen by it,
                    // and one that lands after it finds the socket registered and
                    // closes it. Either way no admitted socket survives the set
                    // that dropped its device.
                    match admit(state, session, &device_key).await {
                        Admitted::InSet {
                            entry: confirmed, ..
                        } if confirmed == entry => {}
                        _ => {
                            state.hub.disconnect(connection).await;
                            return refuse(
                                sender,
                                session.rejected(ErrorCode::WriterNotInAccessSet),
                            );
                        }
                    }
                    let remaining = key_packages_remaining(state, &device_key).await;
                    let ack = session.authenticated(remaining);
                    if let Some(workspace) = workspace {
                        session.bind_workspace(workspace);
                    }
                    // Remembered for one reader, which asks the database again with
                    // it: a device admitted on a provisional grant is founding a
                    // workspace whose groups do not exist yet, and the salt it needs
                    // for its first access set can only be resolved through the seat
                    // it holds.
                    session.bind_device(device_key.clone());
                    queue_all(sender, vec![ack])
                }
                Admitted::Bootstrap(workspace) => {
                    let remaining = key_packages_remaining(state, &device_key).await;
                    let ack = session.bootstrapping(remaining);
                    session.bind_workspace(workspace);
                    session.bind_device(device_key.clone());
                    queue_all(sender, vec![ack])
                }
                Admitted::Refused(code) => refuse(sender, session.rejected(code)),
            }
        }
        Work::Accept { envelope } => {
            // The budget first, ahead of the decode, ahead of `authorize_group`'s
            // read and therefore ahead of the transaction `accept::accept` opens.
            // A budget charged after the database has done the work measures the
            // damage rather than preventing it, which is the whole objection this
            // answers (`crate::send_budget`).
            //
            // `device_key` is bound at `AUTH` and `State::Ready` is reachable only
            // through it, so the fallback is unreachable; it is an empty key
            // rather than an unbudgeted pass so that a future path into `Ready`
            // without a bound device is metered rather than exempt.
            let device = session.device_key().unwrap_or(&[]).to_vec();
            if let Err(refusal) = state
                .send_budget
                .charge(&device, envelope.len() as u64, now_ms)
                .await
            {
                // A frame on a socket that stays up. The connection's reads are
                // untouched: this is a statement about its writes.
                return queue_all(
                    sender,
                    vec![Frame::Error(refusal.to_frame_error(&state.send_budget))],
                );
            }
            let decoded = match Envelope::decode(&envelope) {
                Ok(decoded) => decoded,
                Err(error) => {
                    return queue_all(sender, vec![Frame::Error(FrameError::new(error.code()))])
                }
            };
            let pool = match authorize_group(state, session, &decoded.group).await {
                Ok(pool) => pool,
                Err(code) => return queue_all(sender, vec![Frame::Error(FrameError::new(code))]),
            };
            match accept::accept(pool, &state.config, &decoded, now_ms).await {
                Ok(outcome) => {
                    // The live path. Only a fresh store is fanned out: a duplicate
                    // is an envelope every subscriber has already been sent, and
                    // pushing it again would double a retry on every other screen.
                    if let Accepted::Stored { seq } = outcome {
                        crate::sync::deliver(state, &decoded, seq, now_ms, connection).await;
                        // And the wake, for the admitted principals of this group who
                        // are not holding a socket. After the commit and off this
                        // task, so a `SEND_ACK` is never delayed by one and a ringer
                        // that hangs is invisible from here
                        // (`crate::push::dispatch`). Only a fresh store, never a
                        // duplicate: a retry is an envelope everybody has already been
                        // told about, and waking a phone for it twice is the same
                        // defect as pushing it twice.
                        crate::push::dispatch::after_commit(
                            state,
                            decoded.group.clone(),
                            crate::push::Category::Message,
                        );
                    }
                    // Both outcomes carry a sequence number, and the client cannot
                    // tell them apart. That is deliberate: a retry is answered with
                    // the number the original write was given, so the client's
                    // cursor never moves backwards and it never renumbers a chain
                    // link.
                    let seq = match outcome {
                        Accepted::Stored { seq } | Accepted::Duplicate { seq } => seq,
                    };
                    queue_all(
                        sender,
                        vec![Frame::SendAck {
                            hash: decoded.hash,
                            seq,
                        }],
                    )
                }
                Err(error) => queue_all(sender, vec![Frame::Error(error.to_frame())]),
            }
        }
        Work::Subscribe { group, from_seq } => {
            if let Err(code) = authorize_group(state, session, &group).await {
                // Refused means no subscription was created, so the slot the `SUB` arm
                // took for it is given back. See `Session::forget_subscription`.
                //
                // Unless this connection was already subscribed. A repeated `SUB` for
                // a group this socket holds is refused without touching the live hub
                // entry (`Hub::subscribe` is idempotent and this path never reaches
                // it), so forgetting the group there would drop the session's record
                // of a subscription that is still being fanned out to. A client that
                // re-`SUB`s its 256 groups while the database is briefly unreachable
                // would zero its counter with 256 entries live and could then take
                // 256 more, repeatably.
                if !state.hub.holds(&group, connection).await {
                    session.forget_subscription(&group);
                }
                return queue_all(sender, vec![Frame::Error(FrameError::new(code))]);
            }
            crate::sync::subscribe(
                sender,
                state,
                connection,
                group,
                from_seq,
                session.negotiated_version(),
            )
            .await
        }
        Work::Reconcile { group, payload } => {
            if let Err(code) = authorize_group(state, session, &group).await {
                return queue_all(sender, vec![Frame::Error(FrameError::new(code))]);
            }
            crate::sync::reconcile(sender, state, group, payload).await
        }
        Work::RotateAccessSet { body } => rotate_access_set(sender, state, session, body).await,
        Work::PublishWrap { body } => publish_wrap(sender, state, session, body).await,
        Work::Redeem { body } => redeem(sender, state, session, body).await,
        Work::AdministerInvite { body } => administer_invite(sender, state, session, body).await,
        Work::PublishHandshake { group, message } => {
            publish_handshake(sender, state, session, connection, group, message).await
        }
        Work::PublishLive { group, epoch, ct } => {
            publish_live(sender, state, session, connection, group, epoch, ct).await
        }
        Work::PublishCall {
            call_id,
            group,
            epoch,
            kind,
            body,
        } => {
            crate::calls::socket::publish_call(
                sender, state, session, connection, call_id, group, epoch, kind, body,
            )
            .await
        }
        Work::PublishMedia {
            call_id,
            stream,
            seq,
            ct,
        } => {
            crate::calls::socket::publish_media(sender, state, connection, call_id, stream, seq, ct)
                .await
        }
        Work::KeyPackages { body } => key_packages(sender, state, session, body).await,
        Work::WakeRegistration { body } => {
            wake_registration(sender, state, session, body, now_ms).await
        }
        Work::BlobTicket { payload } => {
            let answer = crate::media::handle(state, session, payload, &state.media_rate).await;
            queue_all(sender, vec![answer])
        }
        Work::DropBefore { payload } => {
            let answer = crate::lifecycle::handle(state, session, payload).await;
            queue_all(sender, vec![answer])
        }
    }
}

/// What the relay answers when it cannot look.
///
/// Public, and for the same reason `storage::object_name` and
/// `logging::redact_ranges` are: the honest answer from a relay with no database is
/// reachable in production only when a dependency has gone, and a function that
/// could only be tested by taking the database away mid-request would be a
/// function whose answer nobody had checked. `/readyz` reports the outage; these
/// decide what a client in flight is told meanwhile.
///
/// Unused key packages for one device.
///
/// `operations.md`: the relay reports the connecting device's own unused count on
/// `AUTH`, so a client tops up before it runs out rather than after. Zero when
/// there is no database, because the honest answer to "how many do you hold" from
/// a relay that cannot look is none.
pub async fn key_packages_remaining(state: &Arc<RelayState>, device_key: &[u8]) -> u32 {
    let Some(database) = &state.database else {
        return 0;
    };
    let hash = blake3::hash(device_key);
    let count: Option<i64> = sqlx::query_scalar(
        "select count(*) from relay_key_package \
         where device_hash = $1 and consumed_at is null and expires_at > now()",
    )
    .bind(hash.as_bytes().as_slice())
    .fetch_optional(database.pool())
    .await
    .ok()
    .flatten();
    u32::try_from(count.unwrap_or_default()).unwrap_or(u32::MAX)
}

/// The highest sequence number a group holds, or zero for an empty one.
///
/// `None` means the relay could not read it, which is deliberately not the same
/// value as an empty group. `sync::subscribe` names this number in `SUB_ACK`, and
/// the whole reason a truncated backfill is honest is that the ack names a head
/// beyond what arrived, so the client knows to come back for the rest. A failed
/// read reported as zero collapses to `head.max(from_seq)`, which is the client's
/// own cursor: it concludes it is fully caught up and never reconciles, and the
/// envelopes it skipped surface later as a hole in somebody else's author chain.
/// A relay with no database is a different case and still answers zero: nothing is
/// claimed that is not true, and the honest backfill from a log it cannot read is
/// none.
pub async fn head_seq(state: &Arc<RelayState>, group: &[u8]) -> Option<u64> {
    let Some(database) = &state.database else {
        return Some(0);
    };
    let head: Option<i64> =
        sqlx::query_scalar("select max(seq) from relay_envelope where group_id = $1")
            .bind(group)
            .fetch_optional(database.pool())
            .await
            .ok()?
            .flatten();
    Some(u64::try_from(head.unwrap_or_default()).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{keys, Config, Values};

    /// A relay with no database and nothing dialled. Enough for the two refusals
    /// that are decided before any query runs.
    fn stateless() -> Arc<RelayState> {
        let config = Config::resolve(&Values::from_pairs([
            (keys::HOSTNAME, "relay.acme.com"),
            (keys::DATABASE_URL, "postgres://weald@localhost/weald_relay"),
            (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
            (keys::RELEASE_CHECK, "off"),
        ]))
        .expect("the configuration resolves");
        Arc::new(RelayState::new(config, None, None))
    }

    fn ready_session(state: &Arc<RelayState>) -> Session {
        Session::new(&state.config)
    }

    /// The one frame the outbound queue took, or nothing.
    fn taken(receiver: &mut OutboundReceiver) -> Option<Frame> {
        match receiver.try_recv() {
            Ok(Outbound::Frame(frame)) => Some(frame),
            _ => None,
        }
    }

    /// Both of `administer_invite`'s guards, called directly.
    ///
    /// They are guards on states the session machine says cannot happen: `INVITE`
    /// is deferred only from `Ready`, and a `Ready` session has both a workspace
    /// and a device key. That is exactly why they are worth executing at least
    /// once. They were written so a later change to the machine fails as a refusal
    /// rather than as a panic in the privileged path, and a guard nobody has ever
    /// run is a guard nobody knows the behaviour of. Reached here rather than over
    /// a socket because no sequence of frames can reach them, which is the claim.
    #[tokio::test]
    async fn the_admin_path_refuses_rather_than_panics_when_its_preconditions_do_not_hold() {
        let state = stateless();

        // No database. `retry`, not a refusal: nothing has been learned about the
        // request.
        let (sender, mut receiver) = outbound_channel();
        let mut session = ready_session(&state);
        session.bind_workspace("ws-unit".to_string());
        session.bind_device(vec![0x01; 32]);
        let request = crate::invite::admin::Request::List.encode();
        assert!(administer_invite(&sender, &state, &session, request.clone()).await);
        assert_eq!(
            taken(&mut receiver),
            Some(Frame::Error(FrameError::new(ErrorCode::Backpressure)))
        );

        // A body that is not a request at all, refused before the database is even
        // looked for.
        let (sender, mut receiver) = outbound_channel();
        assert!(administer_invite(&sender, &state, &session, vec![0xff, 0xff]).await);
        assert!(matches!(taken(&mut receiver), Some(Frame::Error(_))));

        // A session with no device key. Not reachable from `Ready`, and the answer
        // is the same one a writer outside the access set gets.
        let (sender, mut receiver) = outbound_channel();
        let mut anonymous = ready_session(&state);
        anonymous.bind_workspace("ws-unit".to_string());
        assert!(administer_invite(&sender, &state, &anonymous, request).await);
        assert_eq!(
            taken(&mut receiver),
            Some(Frame::Error(FrameError::new(
                ErrorCode::WriterNotInAccessSet
            )))
        );
    }
}
