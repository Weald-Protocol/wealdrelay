// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Who gets woken for one accepted thing, and when the asking happens.
//!
//! Three call sites, one function: an envelope accepted on the accept path
//! (`crate::ws`), a handshake message appended, and a `CALL` frame of kind `offer`.
//! Each is a category (`specs/backend/relay/push.md` section 4) and nothing else
//! about them differs, so they share this.
//!
//! ## After the commit, and off the caller's task
//!
//! ``after_commit`` spawns. That is the whole latency claim: a `SEND_ACK` is never
//! delayed by a wake, and a ringer that accepts a connection and then hangs for
//! thirty seconds cannot be observed from the writer's side at all. The detached
//! task does one indexed read and some queue arithmetic; the network is the worker's
//! problem and the worker is already asleep somewhere else.
//!
//! Detached tasks are how this crate already handles work that must not block a
//! socket, and the same caveat applies: nothing here holds a lock across an await
//! that a socket also needs, and nothing here answers the client, so a task that is
//! cancelled at shutdown leaves nothing half done. A wake that is lost because the
//! process stopped is a wake the client's reconciliation covers, which is the whole
//! reason push is allowed to be best effort.
//!
//! ## Presence suppression
//!
//! A principal holding a socket is dropped from the list. Push exists for a device
//! that is not connected: waking one that is would be a duplicate notification on
//! the screen the user is already looking at, and it would hand the ringer a timing
//! it has no business having. The question is asked of `crate::hub`, which is the
//! only place that knows, and it is asked per principal by entry hash rather than by
//! group, because a group's subscriber list is deliberately not a membership graph.

use std::sync::Arc;

use crate::health::RelayState;

use super::Category;

/// Queue the wakes for one accepted thing, off the caller's task.
///
/// Returns immediately. Does nothing at all when push is off, which is the default
/// and a supported deployment: no task, no read, no queue entry.
pub fn after_commit(state: &Arc<RelayState>, group: Vec<u8>, category: Category) {
    if !state.push.enabled() {
        return;
    }
    let state = Arc::clone(state);
    tokio::spawn(async move {
        wake_group(&state, &group, category).await;
    });
}

/// The body of the above, awaited rather than spawned.
///
/// Public because every test of this behaviour wants to await it: asserting on a
/// spawned task means asserting on a scheduler, and the property being proved (who is
/// enqueued) is not about timing. The one property that *is* about timing, that a
/// hung ringer costs a `SEND` nothing, is proved through ``after_commit`` and a real
/// listener.
pub async fn wake_group(state: &Arc<RelayState>, group: &[u8], category: Category) {
    let Some(database) = &state.database else {
        // A relay with no database cannot answer who is admitted, and a wake sent to
        // a guess would be a wake sent to the wrong device. Silence is the honest
        // answer, and `/readyz` is already reporting why.
        return;
    };
    let now_ms = state.now_ms();
    let Ok(candidates) =
        super::store::wakeable_for_group(database.pool(), group, category, now_ms).await
    else {
        return;
    };
    for candidate in candidates {
        // Connected now, so not woken. Asked per principal at dispatch time rather
        // than remembered, because a device that disconnected a moment ago is exactly
        // the device this feature exists for.
        if state.hub.connections_for(&candidate.entry_hash).await > 0 {
            continue;
        }
        state.push.enqueue(candidate.handle, category, now_ms).await;
    }
}
