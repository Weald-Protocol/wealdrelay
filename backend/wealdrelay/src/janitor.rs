// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The collector task: the one caller with a clock that the sweeps were written for.
//!
//! Every sweep in this crate was built as a function rather than as a timer of its
//! own, so that it is reachable from a test without waiting and so that there is one
//! scheduler to reason about instead of six. This module is that scheduler. Before
//! it existed the process spawned four tasks (two listeners, the push worker and the
//! per-socket writer) and none of them ever called a sweep, which meant the product's
//! deletion guarantee was implemented in functions nothing in the binary ran:
//! retention deletions never happened, and the bytes behind an abandoned upload were
//! charged to the workspace's quota forever.
//!
//! ## What one pass does, and in what order
//!
//! Stale multipart sessions are aborted first, because aborting one only marks the
//! session and leaves its reservation unfinalized; the unclaimed pass that follows is
//! what actually clears the object and returns the bytes. Doing it in the other order
//! would still be correct, but it would take two intervals rather than one.
//!
//! Then, per workspace, the 24-hour unclaimed-upload pass; then, per (workspace,
//! group), the storage-listing pass and the retention pass. Last the three
//! non-media sweeps, which are plain expiry deletes: push handles, superseded
//! recovery wraps, and spent bootstrap handoffs.
//!
//! ## Failure is per pass, never per run
//!
//! No step's failure stops the ones after it. A storage outage means the media
//! passes delete nothing this interval (`media::gc` already refuses to record a
//! deletion it could not confirm), and it must not also mean that expired push
//! handles survive. The pass returns what it did and the loop logs it; nothing here
//! retries, because the next interval is the retry.
//!
//! ## Logging
//!
//! Aggregate counts only. A per-group line would put a group id in the log on every
//! interval, which is exactly the identifier `logging.rs` scrubs, so the summary
//! names how many scopes were examined and never which ones.

use std::sync::Arc;

use crate::health::RelayState;

/// How long between passes when the operator names nothing.
///
/// Fifteen minutes is chosen against the grace periods the passes enforce, not
/// against how fast a deletion could run: the shortest window any pass acts on is
/// the 24-hour unclaimed grace, so a pass every quarter hour is prompt by two
/// orders of magnitude while costing one scan of a table that only holds live
/// reservations.
pub const DEFAULT_INTERVAL_MS: u64 = 15 * 60 * 1000;

/// The fraction of the interval that jitter can add, as a divisor.
///
/// Ten percent, one-sided. Enough that a fleet restarted together does not scan
/// Postgres in lockstep forever, small enough that the interval an operator set is
/// still the interval they observe.
const JITTER_DIVISOR: u64 = 10;

/// How many passes between storage-listing sweeps.
///
/// Every other sweep in a pass reads Postgres, which we have already paid for by the
/// gigabyte and the hour. `media::gc::sweep_unreferenced_storage` is the exception:
/// it calls `Store::list` once per (workspace, group), and a list is a Cloudflare
/// Class A operation at $4.50 per million, then one `head` per listed object at
/// $0.36 per million. At the default interval that is 96 lists per group per day,
/// about 2,900 a month, for a sweep whose whole job is to catch objects the database
/// has no reservation for. A twenty-group workspace spends about $0.26 a month on
/// it; a two-hundred-group workspace spends about $2.59, which on its own exceeds
/// the entire object-storage operations line the unit-economics model books for a
/// Team instance. It is the only vendor meter in this crate that scales with how
/// often we look rather than with what a customer did.
///
/// So it runs daily rather than quarter-hourly. That is not a weakening of a
/// guarantee: the two passes that implement promises, the 24-hour unclaimed grace
/// and retention, keep the full cadence, and this one is a reconcile against
/// bookkeeping that is supposed to already be correct. An object it would find is an
/// object some earlier pass failed to delete, and waiting a day to notice costs the
/// customer's quota a day of bytes it was already charged for.
///
/// 96 rather than a duration, because the operator sets one interval and this stays
/// a fixed multiple of whatever they set rather than a second clock that can be
/// configured into disagreeing with the first.
pub const STORAGE_LISTING_EVERY: u64 = 96;

/// What one pass did, for the log line and for a test to assert on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pass {
    /// (workspace, group) pairs examined by the two per-group media passes.
    pub scopes: u32,
    /// Objects removed from storage across all three media passes.
    pub blobs_deleted: u32,
    /// Bytes returned to quota by the unclaimed pass and the retention pass.
    pub bytes_released: i64,
    /// Expired multipart sessions marked aborted.
    pub multipart_aborted: u64,
    /// Push registrations dropped because their stated expiry had passed.
    pub push_handles_dropped: u64,
    /// Superseded recovery wraps dropped past their retention window.
    pub recovery_wraps_dropped: u64,
    /// Bootstrap handoff ciphertexts dropped past their window.
    pub handoffs_dropped: u64,
    /// Invite seats returned by expiring an abandoned reservation.
    pub invite_seats_released: u64,
    /// Scopes the storage-listing sweep actually listed, which is a billed Class A
    /// operation each. Zero on the passes between `STORAGE_LISTING_EVERY`, and the
    /// number an operator reads to see what the sweep costs.
    pub storage_listings: u32,
    /// Whether a set restore marker stopped the storage-listing sweep from running
    /// at all this pass. The operator's signal that the suppression is live, and
    /// the field a test asserts on rather than reading a log line.
    pub storage_listing_suppressed: bool,
}

/// Run every sweep once.
///
/// Public because this is the unit the tests drive: asserting the collector works by
/// waiting for a timer would be asserting on a sleep. The loop below adds the clock
/// and nothing else.
pub async fn pass(state: &RelayState) -> Pass {
    pass_with(state, true).await
}

/// One pass, choosing whether the storage-listing sweep runs.
///
/// Split out for `STORAGE_LISTING_EVERY`: the listing sweep is the one sweep that
/// costs money per look rather than per deletion, so the loop runs it on a multiple
/// of the interval and every other sweep on the interval. `pass` keeps its meaning,
/// which is "everything", so a test that wants the whole collector still gets it.
pub async fn pass_with(state: &RelayState, list_storage: bool) -> Pass {
    let mut summary = Pass::default();
    let Some(database) = state.database.as_ref() else {
        return summary;
    };
    let pool = database.pool();
    let now_ms = state.now_ms();

    // One countdown per pass, before any group is touched. The marker suppresses
    // the storage-listing sweep after a database restore, and a pass that spent one
    // count per (workspace, group) would exhaust four passes of protection inside a
    // single interval of a four-group workspace. The sweep itself re-reads the
    // marker and refuses on its own, so a direct caller is protected too; this is
    // only what makes the count mean passes.
    if list_storage {
        if let Some(remaining) = crate::media::restore::consume_one(pool).await {
            summary.storage_listing_suppressed = true;
            tracing::info!(
                passes_remaining_before = remaining,
                "collector: the storage-listing sweep is suppressed by the restore marker"
            );
        }
    }
    let list_storage = list_storage && !summary.storage_listing_suppressed;

    if let Some(storage) = state.storage.as_ref() {
        // Marked aborted only. The reservation stays unfinalized, so the unclaimed
        // pass immediately below is what clears the object and returns the bytes,
        // and it applies the same 24-hour grace to a multipart upload as to any
        // other, rather than this path inventing a second rule.
        match crate::media::store::stale_multipart_sessions(pool).await {
            Ok(sessions) => {
                for (session_id, _reservation_id) in sessions {
                    if crate::media::store::abort_multipart(pool, session_id)
                        .await
                        .is_ok()
                    {
                        summary.multipart_aborted += 1;
                    }
                    // The part objects are the one thing the unclaimed pass cannot
                    // reach: parts live under the synthetic `_multipart` workspace
                    // (`media::part_key`) and that pass walks real workspaces, so
                    // without this they outlive every collector.
                    if let Ok(parts) = crate::media::store::recorded_parts(pool, session_id).await {
                        for part_number in parts {
                            let _ = storage
                                .delete(&crate::media::part_key_for(session_id, part_number))
                                .await;
                        }
                    }
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "could not list stale multipart sessions");
            }
        }

        match crate::media::store::active_scopes(pool).await {
            Ok(scopes) => {
                // One unclaimed pass per workspace rather than per scope: the pass
                // reads the whole stale list and filters it to the workspace, so
                // running it once per group would be one full scan per group.
                let mut workspaces: Vec<String> = scopes
                    .iter()
                    .map(|(workspace, _)| workspace.clone())
                    .collect();
                workspaces.dedup();
                for workspace in &workspaces {
                    let report =
                        crate::media::gc::sweep_unclaimed(pool, storage, workspace, now_ms).await;
                    summary.blobs_deleted += report.deleted;
                    summary.bytes_released += report.deleted_bytes;
                }
                for (workspace, group) in &scopes {
                    summary.scopes += 1;
                    if list_storage {
                        let unreferenced = crate::media::gc::sweep_unreferenced_storage(
                            pool,
                            storage,
                            workspace,
                            group,
                            now_ms,
                            state.config.gc_min_object_age_seconds,
                        )
                        .await;
                        summary.blobs_deleted += unreferenced.deleted;
                        summary.storage_listings += 1;
                    }
                    let retention =
                        crate::media::gc::sweep_retention(pool, storage, workspace, group, now_ms)
                            .await;
                    summary.blobs_deleted += retention.deleted;
                    summary.bytes_released += retention.deleted_bytes;
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "could not list media scopes");
            }
        }
    }

    // The three plain expiry deletes. Each is independent of the media passes and of
    // each other, so a storage outage above must not stop any of them.
    match crate::push::store::sweep_expired(pool, now_ms).await {
        Ok(dropped) => summary.push_handles_dropped = dropped,
        Err(error) => tracing::warn!(error = %error, "could not sweep expired push handles"),
    }
    match crate::recovery::store::sweep_prior(pool).await {
        Ok(dropped) => summary.recovery_wraps_dropped = dropped,
        Err(error) => tracing::warn!(error = %error, "could not sweep prior recovery wraps"),
    }
    match crate::invite::handoff::sweep_expired(pool).await {
        Ok(dropped) => summary.handoffs_dropped = dropped,
        Err(error) => tracing::warn!(error = %error, "could not sweep expired bootstrap handoffs"),
    }
    // Capacity is decremented on reserve and only this pass returns it, so an
    // abandoned setup that never calls `release_expired` burns a seat forever
    // instead of freeing it ten minutes after the reservation lapsed.
    match crate::invite::reserve::release_expired(pool, now_ms as i64).await {
        Ok(freed) => summary.invite_seats_released = freed,
        Err(error) => {
            tracing::warn!(error = %error, "could not release expired invite reservations")
        }
    }
    summary
}

/// A one-sided jitter under a tenth of the interval.
///
/// Failure of the operating system's randomness is not fatal here: a collector that
/// refused to run because it could not be random would be strictly worse than one
/// that runs on the exact interval, which is what a zero returns.
fn jitter_ms(interval_ms: u64) -> u64 {
    let span = interval_ms / JITTER_DIVISOR;
    if span == 0 {
        return 0;
    }
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return 0;
    }
    u64::from_le_bytes(bytes) % span
}

/// Sweep, sleep, repeat, until the task is cancelled with the rest of the process.
pub async fn run(state: Arc<RelayState>) {
    let interval_ms = state.config.janitor_interval_ms;
    // Counts passes so the storage-listing sweep can run on a multiple of the
    // interval. Starts at zero and is incremented before the test, so the first pass
    // of a fresh process is not a listing one: a relay that has just started has the
    // least to reconcile and the listing sweep is the most expensive thing it could
    // do on boot.
    let mut passes: u64 = 0;
    loop {
        // Sleep first. A relay that has just started has nothing to collect that one
        // interval of patience loses, and starting a full scan inside the same
        // moment as the listeners bind is the one time the process is busiest.
        let wait = interval_ms.saturating_add(jitter_ms(interval_ms));
        tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
        passes = passes.wrapping_add(1);
        let list_storage = passes % STORAGE_LISTING_EVERY == 0;
        let summary = pass_with(&state, list_storage).await;
        let storage_listings = summary.storage_listings;
        let scopes = summary.scopes;
        let blobs_deleted = summary.blobs_deleted;
        let bytes_released = summary.bytes_released;
        let multipart_aborted = summary.multipart_aborted;
        let push_handles_dropped = summary.push_handles_dropped;
        let recovery_wraps_dropped = summary.recovery_wraps_dropped;
        let handoffs_dropped = summary.handoffs_dropped;
        let invite_seats_released = summary.invite_seats_released;
        let storage_listing_suppressed = summary.storage_listing_suppressed;
        tracing::info!(
            scopes,
            blobs_deleted,
            bytes_released,
            multipart_aborted,
            push_handles_dropped,
            recovery_wraps_dropped,
            handoffs_dropped,
            invite_seats_released,
            storage_listings,
            storage_listing_suppressed,
            "collector pass"
        );
    }
}

/// Start the collector, when there is a database for it to collect from.
///
/// `None` without one, which is `--check-config` and the config suites: those drive
/// `prepare` too, and neither should have a scanner running behind them.
pub fn spawn(state: &Arc<RelayState>) -> Option<tokio::task::JoinHandle<()>> {
    state.database.as_ref()?;
    Some(tokio::spawn(run(Arc::clone(state))))
}
