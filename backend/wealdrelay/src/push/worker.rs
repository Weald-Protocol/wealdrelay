// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The single worker that drains the wake queue.
//!
//! One task per process, not one per wake. Everything that can wait on a network
//! lives here, which is what keeps the `SEND` path clear: the accept side enqueues
//! and returns, and the worst a ringer can do to a writer is nothing at all.
//!
//! ## The loop, and why it is shaped like this
//!
//! Sleep until either something is enqueued or the earliest window closes; take
//! everything that is due; send each one; repeat. No polling, because the ordinary
//! state of this worker is an empty queue, and no per-wake task, because a thousand
//! detached tasks against one hung ringer is a thousand sockets rather than one.
//!
//! ## Nothing here retries
//!
//! A wake that was not accepted is counted and forgotten. `429` sleeps for the
//! interval the ringer named and then carries on with the next wake, which is a pause
//! rather than a retry: the wakes that arrive during it coalesce in the queue and are
//! shed at its bound, so the relay's memory is bounded by the queue and by nothing
//! else. `404` deletes the row that named the handle.

use std::sync::Arc;

use crate::health::RelayState;

use super::ringer::Outcome;
use super::Category;

/// Drain the queue until the task is cancelled, which is when the relay stops.
pub async fn run(state: Arc<RelayState>) {
    // Push off means there is nothing to drain and nowhere to send it. `spawn`
    // already declines to start a worker then; this is here so the function is
    // total, and it is reachable from a test that calls it directly against a relay
    // with push off rather than only through `spawn`.
    let Some(url) = state.push.settings.wake_url.clone() else {
        return;
    };
    let ringer = super::ringer::shared();
    let token = state.push.settings.token.clone();
    loop {
        state.push.wait_for_work(state.now_ms()).await;
        let due = state.push.take_due(state.now_ms()).await;
        for (handle, category) in due {
            deliver(&state, &ringer, &url, token.as_deref(), &handle, category).await;
        }
    }
}

/// One wake, and everything its answer implies.
///
/// Public so a test can drive exactly one delivery against a real listener without
/// racing the loop above, which is how the `404` and `429` behaviours are proved:
/// asserting them through the loop would mean asserting on a sleep.
pub async fn deliver(
    state: &Arc<RelayState>,
    ringer: &super::ringer::Ringer,
    url: &str,
    token: Option<&str>,
    handle: &[u8],
    category: Category,
) {
    let outcome = ringer.wake(url, token, handle, category).await;
    state.push.record(outcome);
    match outcome {
        // The ringer has told us this device is gone. Deleting the row is not
        // tidiness: a handle the ringer will never resolve is a row the relay would
        // otherwise consult and ring on every accepted envelope, forever.
        Outcome::Unknown => {
            if let Some(database) = &state.database {
                // Best effort. A database that cannot answer has already made
                // `/readyz` say so, and failing to delete a dead row is not a reason
                // to stop waking everybody else.
                let _ = super::store::delete_by_handle(database.pool(), handle).await;
            }
        }
        Outcome::Paused { seconds } => {
            state.push.note_pause();
            // Bounded, so a ringer answering `Retry-After: 86400` cannot park this
            // worker for a day. Past the cap the relay simply keeps offering wakes
            // and keeps being told to wait, which costs one request per window and
            // recovers on its own.
            let capped = seconds.min(MAX_PAUSE_SECONDS);
            tokio::time::sleep(std::time::Duration::from_secs(capped)).await;
        }
        Outcome::Accepted | Outcome::Refused | Outcome::Unreachable => {}
    }
}

/// The longest a `429` may hold this worker.
///
/// Sixty seconds. `ringer.md` rate limits per handle at thirty wakes a minute, so a
/// legitimate `Retry-After` from our own ringer is seconds; the cap is against a
/// ringer, ours or somebody else's, that names an interval nobody intended.
pub const MAX_PAUSE_SECONDS: u64 = 60;
