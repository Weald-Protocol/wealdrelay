// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! What a client is told for each of the two call frames.
//!
//! Split from `crate::ws` rather than added to it. `ws.rs` is the framing layer
//! and these are two protocol operations with a registry behind them, which is
//! the same division `sync.rs` and `keys.rs` already sit on.
//!
//! ## The asymmetry, which is the whole design
//!
//! `publish_call` does the expensive thing once: `authorize_group`, which is a
//! Postgres read, at a hundred and twenty frames a minute. `publish_media` does
//! the cheap thing constantly: one map lookup, at fifty frames a second per
//! stream, with no database anywhere on the path. What connects them is that
//! admission to a call is only ever granted by the expensive half, so the cheap
//! half can trust the membership it finds without re-deriving it.

use std::sync::Arc;

use crate::frame::{Frame, FrameError};
use crate::health::RelayState;
use crate::session::Session;
use crate::ws::{authorize_group, queue_all};

use super::{CallKind, CALL_ID_BYTES, CALL_PROTOCOL_VERSION, STREAM_BYTES};

/// One call signalling frame.
///
/// Four things in this order, and the order is the security property. The group
/// is checked against the session's access set by the same function `SEND` is
/// checked by. Then the call id is checked against the registry, which refuses an
/// id already open against a different group. Then membership is applied. Only
/// then is anything forwarded, so a refused frame reaches nobody.
///
/// Fanout is at the **group**, not at the call. An offer has to reach a person
/// who is not in the call yet, which is the entire point of an offer, and there
/// is no other set to send it to. That is also why signalling is rate limited an
/// order of magnitude below media: a frame that reaches every subscribed device
/// is a frame that has to be rare.
#[allow(clippy::too_many_arguments)]
pub async fn publish_call(
    sender: &crate::ws::OutboundSender,
    state: &Arc<RelayState>,
    session: &mut Session,
    connection: crate::hub::ConnectionId,
    call_id: [u8; CALL_ID_BYTES],
    group: Vec<u8>,
    epoch: u64,
    kind: CallKind,
    body: Vec<u8>,
) -> bool {
    if let Err(code) = authorize_group(state, session, &group).await {
        return queue_all(sender, vec![Frame::Error(FrameError::new(code))]);
    }

    if kind.joins() {
        if let Err(refusal) = state
            .calls
            .join(&call_id, &group, connection, sender.clone())
            .await
        {
            return queue_all(
                sender,
                vec![Frame::Error(FrameError::new(refusal.code()).detail(
                    refusal.detail(state.calls.max_concurrent()).to_be_bytes(),
                ))],
            );
        }
    } else {
        // The same call id check the joining kinds get, and for a sharper reason.
        // Fanout is at the group named on the frame, and leaving is applied to the
        // call id: a `bye` that named a group the sender is admitted to but that is
        // not the call's own group would take the sender out of the call while
        // telling a different room about it, so the people actually on the call
        // would never learn it ended and would hold a participant the relay has
        // already dropped. Refused rather than repaired, symmetric with `join`.
        if let Some(open) = state.calls.group_of(&call_id).await {
            if open != group {
                let refusal = super::JoinRefusal::GroupMismatch;
                return queue_all(
                    sender,
                    vec![Frame::Error(FrameError::new(refusal.code()).detail(
                        refusal.detail(state.calls.max_concurrent()).to_be_bytes(),
                    ))],
                );
            }
        }
        // Leaving a call you were not in is still not an error: a client that
        // declines an offer it never accepted is doing exactly the right thing, and
        // answering it with a refusal would make the normal path noisy. So is
        // leaving a call this process is not carrying, which is what the `None`
        // above falls through to.
        state.calls.leave(&call_id, connection).await;
    }

    let frame = Frame::Call {
        call_id: call_id.to_vec(),
        group: group.clone(),
        epoch,
        kind: kind as u8,
        body,
    };
    // Version 3 and above only. A version 1 or 2 subscriber never learns the frame
    // existed, which is what keeps every older client working unchanged.
    state
        .hub
        .fanout_frame(&group, &frame, connection, CALL_PROTOCOL_VERSION)
        .await;
    // And then nothing. No acknowledgement and no sequence number, because nothing
    // was kept: the same silence a `LIVE` gets, for the same reason.
    true
}

/// One media frame.
///
/// No database, no hash, no sequence number, no group lookup. The registry
/// answers both questions at once: whether this connection is in this call, and
/// who else is. A sender that is not in the call is refused with the same code an
/// unadmitted group gets, because that is exactly what it is: a claim on a
/// conversation this session was never admitted to.
pub async fn publish_media(
    sender: &crate::ws::OutboundSender,
    state: &Arc<RelayState>,
    connection: crate::hub::ConnectionId,
    call_id: [u8; CALL_ID_BYTES],
    stream: [u8; STREAM_BYTES],
    seq: u64,
    ct: Vec<u8>,
) -> bool {
    let frame = Frame::Media {
        call_id: call_id.to_vec(),
        stream: stream.to_vec(),
        seq,
        ct,
    };
    match state.calls.route(&call_id, connection, &frame).await {
        // Shed counts are the registry's and are deliberately not told to the
        // sender. There is nothing it could usefully do: the next frame is 20 ms
        // away, and a per-frame answer would double the traffic on exactly the
        // connection that is already too slow.
        Ok(_) => true,
        Err(code) => queue_all(sender, vec![Frame::Error(FrameError::new(code))]),
    }
}
