// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Garbage collection: the two mechanisms `media.md` says are both required.
//!
//! **The unclaimed-upload collector.** A reservation with no manifest claim
//! after 24 hours: the gap between `BLOB put` and the retention manifest that
//! should have followed it, when the client crashed, lost its connection, or
//! never uploaded at all.
//!
//! **The retention-driven collector.** A blob that *was* claimed, is absent from
//! the group's latest valid manifest, and has a threshold-authorized policy or
//! destruction record whose grace period and `not_before` have passed.
//!
//! A third pass, the storage-listing sweep, is not a third mechanism so much as
//! the seam between the two: it finds objects in the bucket that never went
//! through a relay reservation at all (`BLOB put` was skipped, or the object was
//! placed directly), which neither of the above could ever see because both
//! start from a database row.
//!
//! Every pass writes one `relay_gc_run` row, which is the artifact
//! `phases-relay.md` step 9 asks for: "the GC run log and the storage accounting
//! against the quota."

use sqlx::PgPool;

use super::retention;
use super::store;
use crate::storage::{BlobKey, Store};

/// Never delete anything reserved more recently than this. `media.md`: "An
/// upload with no accepted manifest claim is collected after 24 hours".
pub const UNCLAIMED_GRACE_SECONDS: i64 = 24 * 60 * 60;

/// Never delete an unreferenced object younger than this, whatever the database
/// says about it.
///
/// Forty-eight hours, against a stated recovery-point objective of twelve
/// (`specs/backend/cloud/backup-dr.md`). The sweep below decides that an object is
/// garbage because this database holds no reservation for it, and a database
/// restored to an earlier point holds no reservation for anything uploaded since:
/// without a floor, the mechanism that exists to survive an incident hands the
/// janitor a list of every object the restore was too old to know about, on a live
/// bucket with no versioning and no object lock. Four times the RPO rather than
/// twice, because the objective bounds how much a restore loses and not how long
/// the restore takes, and the cost of being generous is that an object planted
/// directly in the bucket survives an extra day.
///
/// Configurable, and configured from `WEALD_RELAY_GC_MIN_OBJECT_AGE_SECONDS`
/// rather than from this constant at the call site: the relay cannot know the
/// cadence the control plane captures at, so the control plane sets the floor on
/// the instance's environment when it provisions, and this value is what a relay
/// with nobody telling it anything uses. Zero is a legal setting and means no
/// floor, which is the self-hoster who takes no backups at all.
pub const DEFAULT_MIN_OBJECT_AGE_SECONDS: u64 = 48 * 60 * 60;

/// The floor under every retention-driven deletion, regardless of policy.
/// `media.md`: "The existing 30-day grace period remains a floor; a policy can
/// lengthen it but never shorten it."
pub const MEDIA_GRACE_FLOOR_DAYS: u32 = 30;

/// What one mechanism's pass did, for the run log and the artifact.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub examined: u32,
    pub deleted: u32,
    pub deleted_bytes: i64,
    pub note: String,
}

async fn log_run(
    pool: &PgPool,
    mechanism: &str,
    started_at_ms: u64,
    finished_at_ms: u64,
    report: &Report,
) {
    let result = sqlx::query(
        "insert into relay_gc_run \
         (started_at, finished_at, mechanism, examined_count, deleted_count, deleted_bytes, note) \
         values (to_timestamp($1), to_timestamp($2), $3, $4, $5, $6, $7)",
    )
    .bind(started_at_ms as f64 / 1000.0)
    .bind(finished_at_ms as f64 / 1000.0)
    .bind(mechanism)
    .bind(report.examined as i32)
    .bind(report.deleted as i32)
    .bind(report.deleted_bytes)
    .bind(&report.note)
    .execute(pool)
    .await;
    if let Err(error) = result {
        tracing::warn!(mechanism, error = %error, "could not write the gc run log");
    }
}

/// Whether the object behind `key` is gone from storage.
///
/// A storage outage must never be mistaken for "already gone" (`media.md`'s
/// negative proof), so the transient case is reported separately and every
/// caller stops on it rather than marking a database row deleted for an object
/// still sitting in an unreachable bucket. A terminal refusal is the opposite
/// case and is also not a deletion: the backend answered, and its answer was no,
/// so the row stays and the next pass tries again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cleared {
    /// Deleted, or already absent. Both backends answer `Ok` for an object that
    /// was never written, which is the success case for an interrupted upload.
    Gone,
    /// The backend could not be reached, or refused. Nothing has been deleted
    /// and nothing may be recorded as deleted.
    Kept,
}

async fn clear_object(storage: &Store, key: &BlobKey) -> Cleared {
    match storage.delete(key).await {
        Ok(()) => Cleared::Gone,
        Err(_) => Cleared::Kept,
    }
}

fn object_key(workspace: &str, group: &[u8], hash: &[u8]) -> Option<BlobKey> {
    BlobKey::new(workspace, super::hex(group), super::hex(hash)).ok()
}

/// The 24-hour unclaimed-upload collector, for one workspace.
pub async fn sweep_unclaimed(
    pool: &PgPool,
    storage: &Store,
    workspace: &str,
    now_ms: u64,
) -> Report {
    sweep_unclaimed_after(pool, storage, workspace, now_ms, UNCLAIMED_GRACE_SECONDS).await
}

/// The same collector with the grace named by the caller.
///
/// The window is a product promise measured in a day, which is longer than any
/// probe against a running relay can wait, so before this existed the only proof
/// that an unclaimed object is ever deleted was a unit test calling this function.
/// The collector passes `Config::media_unclaimed_grace_seconds`, whose default is
/// `UNCLAIMED_GRACE_SECONDS`, so a relay nobody configured behaves exactly as it
/// did; an operator running a probe instance shortens it and drives one pass.
/// Nothing else about eligibility moves: a finalized reservation is still never
/// touched, and a claimed object is still out of this sweep's reach entirely.
pub async fn sweep_unclaimed_after(
    pool: &PgPool,
    storage: &Store,
    workspace: &str,
    now_ms: u64,
    grace_seconds: i64,
) -> Report {
    let started = now_ms;
    let mut report = Report::default();
    let stale = match store::stale_unclaimed(pool, grace_seconds).await {
        Ok(rows) => rows,
        Err(error) => {
            report.note = format!(
                "could not list stale reservations: {}",
                crate::logging::scrub(&error.to_string())
            );
            log_run(pool, "unclaimed", started, started, &report).await;
            return report;
        }
    };
    for (row_workspace, group, hash, reservation_id) in stale {
        if row_workspace != workspace {
            continue;
        }
        report.examined += 1;
        let Some(key) = object_key(workspace, &group, &hash) else {
            continue;
        };
        // An object that was never written answers `Ok` on both backends, which
        // is the ordinary case here: the client took a reservation and crashed
        // before the PUT. Anything else leaves the reservation exactly as it is,
        // because `media.md`'s negative proof is that an outage never causes a
        // deletion, and releasing the reservation while the object may still be
        // in the bucket would let a later, legitimate manifest claim collide
        // with a reservation that no longer exists.
        if clear_object(storage, &key).await == Cleared::Kept {
            continue;
        }
        if let Ok(Some(bytes)) = store::release(pool, workspace, reservation_id).await {
            report.deleted += 1;
            report.deleted_bytes += bytes;
        }
    }
    let finished = now_ms;
    log_run(pool, "unclaimed", started, finished, &report).await;
    report
}

/// Objects in storage with no reservation row at all: never went through `BLOB
/// put`, so neither of the other two mechanisms can see them. An object with no
/// reservation is either a planted object or a bug, and neither should accumulate.
///
/// Two things hold it back, and both exist because "no row" is not only what a
/// planted object looks like. It is also what every legitimate object uploaded
/// after a restore point looks like the moment the database is rolled back to it.
///
/// - `min_age_seconds`: an object younger than the floor is never deleted here,
///   and an object whose age the backend would not report is never deleted either.
///   Absence of an age is not evidence of age.
/// - The restore marker: while it is set, this sweep deletes nothing at all
///   (`super::restore`), which covers a recovery point older than any floor.
///
/// Neither weakens the guarantee the pass carries, because it carries none: the
/// two passes that implement product promises are the 24-hour unclaimed grace and
/// retention, and this one is a reconcile against bookkeeping that is supposed to
/// already be correct.
pub async fn sweep_unreferenced_storage(
    pool: &PgPool,
    storage: &Store,
    workspace: &str,
    group: &[u8],
    now_ms: u64,
    min_age_seconds: u64,
) -> Report {
    let started = now_ms;
    let mut report = Report::default();
    // Checked, never counted down. `crate::janitor` spends one pass of the marker
    // per collector pass; this sweep runs once per (workspace, group) inside that
    // pass, so counting down here would burn the whole marker on one interval of a
    // twenty-group workspace.
    if super::restore::suppressed(pool).await {
        report.note = "suppressed: a restore marker is set".to_string();
        tracing::info!(
            "media: the storage-listing sweep is suppressed by the restore marker and deleted nothing"
        );
        log_run(pool, "unreferenced_storage", started, started, &report).await;
        return report;
    }
    let listed = match storage.list_entries(workspace, &super::hex(group)).await {
        Ok(names) => names,
        Err(error) => {
            report.note = format!(
                "could not list storage: {}",
                crate::logging::scrub(&error.to_string())
            );
            log_run(pool, "unreferenced_storage", started, started, &report).await;
            return report;
        }
    };
    let known = match store::claimed_hashes(pool, workspace, group).await {
        Ok(hashes) => hashes
            .into_iter()
            .map(|h| super::hex(&h))
            .collect::<Vec<_>>(),
        Err(error) => {
            report.note = format!(
                "could not list known reservations: {}",
                crate::logging::scrub(&error.to_string())
            );
            log_run(pool, "unreferenced_storage", started, started, &report).await;
            return report;
        }
    };
    let floor_ms = min_age_seconds.saturating_mul(1000);
    let mut too_young = 0u32;
    for entry in listed {
        let name = entry.name;
        report.examined += 1;
        if known.contains(&name) {
            continue;
        }
        // Younger than the floor, or of an age the backend would not state. Both
        // are kept: the object is either a legitimate upload whose row a restore
        // rolled away, or one whose age nothing here can vouch for, and a
        // permanent deletion is not a decision to take on either.
        if floor_ms > 0 {
            let age_ms = entry
                .modified_ms
                .map(|modified| now_ms.saturating_sub(modified));
            match age_ms {
                Some(age) if age >= floor_ms => {}
                _ => {
                    too_young += 1;
                    continue;
                }
            }
        }
        let Ok(key) = BlobKey::new(workspace, super::hex(group), name.clone()) else {
            continue;
        };
        let size = storage.head(&key).await.ok().flatten().map(|info| info.len);
        if clear_object(storage, &key).await == Cleared::Gone {
            report.deleted += 1;
            report.deleted_bytes += size.unwrap_or(0) as i64;
        }
    }
    if too_young > 0 {
        report.note = format!(
            "{too_young} unreferenced object(s) kept: younger than the {min_age_seconds}s age floor, \
             or of an age the backend did not state"
        );
    }
    let finished = now_ms;
    log_run(pool, "unreferenced_storage", started, finished, &report).await;
    report
}

/// Whether one already-claimed blob may be physically removed right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Eligibility {
    /// Still named in the group's latest valid manifest: never a candidate.
    Live,
    /// The group is frozen by a retention-control conflict: no retention-driven
    /// deletion runs for it at all.
    Frozen,
    /// Absent from the latest manifest, but no authorized policy or destruction
    /// has yet made it, or its grace period has not elapsed.
    NotYetDue,
    /// Everything lined up: absent from the current manifest, and a
    /// threshold-authorized record's `not_before` and grace period have passed.
    Eligible,
}

pub async fn eligible(
    pool: &PgPool,
    // Unused for now: every policy and destruction record is already scoped to
    // one group, and a group belongs to exactly one workspace, so there is
    // nothing this parameter adds yet. Kept in the signature because
    // `sweep_retention` calls this per (workspace, group) pair and a future
    // workspace-wide policy override is the obvious next reader of it.
    _workspace: &str,
    group: &[u8],
    hash: &[u8],
    claimed_at_ms: u64,
    now_ms: u64,
) -> Result<Eligibility, store::StoreError> {
    if retention::is_frozen(pool, group)
        .await
        .map_err(|error| store::StoreError::Database(error.to_string()))?
    {
        return Ok(Eligibility::Frozen);
    }
    let latest = retention::latest_manifest(pool, group)
        .await
        .map_err(|error| store::StoreError::Database(error.to_string()))?;
    if let Some(latest) = &latest {
        if latest.blobs.iter().any(|claimed| claimed == hash) {
            return Ok(Eligibility::Live);
        }
    }

    // A destruction record targeting this exact object wins outright, over and
    // under the policy floor both, because it is the client's explicit tombstone
    // path (`media.md`, "Explicit tombstones") rather than the ambient policy.
    if let Some(destruction) = retention::active_destruction(pool, group, "blob", hash)
        .await
        .map_err(|error| store::StoreError::Database(error.to_string()))?
    {
        let not_before_ms = destruction.not_before_secs.saturating_mul(1000);
        if now_ms >= not_before_ms {
            return Ok(Eligibility::Eligible);
        }
        return Ok(Eligibility::NotYetDue);
    }

    let Some(policy) = retention::active_policy(pool, group)
        .await
        .map_err(|error| store::StoreError::Database(error.to_string()))?
    else {
        return Ok(Eligibility::NotYetDue);
    };
    let grace_days = policy.media_after_days.max(MEDIA_GRACE_FLOOR_DAYS);
    let grace_ms = u64::from(grace_days) * 24 * 60 * 60 * 1000;
    let due_at = claimed_at_ms.saturating_add(grace_ms);
    let not_before_ms = policy.not_before_secs.saturating_mul(1000);
    if now_ms >= due_at && now_ms >= not_before_ms {
        Ok(Eligibility::Eligible)
    } else {
        Ok(Eligibility::NotYetDue)
    }
}

/// The retention-driven collector, for one workspace and group.
///
/// The deletion clock is `store::ClaimedBlob::claimed_at_ms`, which is
/// `relay_blob_reservation.finalized_at`: the relay's own receipt time for the
/// first accepted manifest claim, read in the same statement as the rest of the
/// row and never taken from anything a client sent.
pub async fn sweep_retention(
    pool: &PgPool,
    storage: &Store,
    workspace: &str,
    group: &[u8],
    now_ms: u64,
) -> Report {
    let started = now_ms;
    let mut report = Report::default();
    let finalized = match store::finalized_reservations(pool, workspace, group).await {
        Ok(rows) => rows,
        Err(error) => {
            report.note = format!(
                "could not list finalized reservations: {}",
                crate::logging::scrub(&error.to_string())
            );
            log_run(pool, "retention", started, started, &report).await;
            return report;
        }
    };
    let mut stranded = 0u32;
    for row in finalized {
        report.examined += 1;
        let verdict =
            match eligible(pool, workspace, group, &row.hash, row.claimed_at_ms, now_ms).await {
                Ok(verdict) => verdict,
                Err(_) => continue,
            };
        if verdict != Eligibility::Eligible {
            continue;
        }
        let Some(key) = object_key(workspace, group, &row.hash) else {
            continue;
        };
        // The object leaves storage before the row leaves the database. A crash
        // between the two is an orphaned storage delete, which costs nothing; the
        // other order would leave a quota row undercounting an object still in
        // the bucket.
        if clear_object(storage, &key).await == Cleared::Kept {
            continue;
        }
        // The object is already gone by here, so a failed row delete is not a
        // no-op: it leaves a finalized row attesting to an object that no longer
        // exists, with its bytes still charged to the workspace and no pass that
        // ever comes back for it. `is_ok()` alone made that invisible, reporting
        // `deleted: 0` with an empty note and no log line, so the one state an
        // operator needs to see looked exactly like a sweep with nothing to do
        // (WEALD-318). `reserve` now retires such a row when the object is
        // re-uploaded, which is a repair on a path that may never be taken, so the
        // failure is still worth saying out loud.
        match store::finish_deletion(pool, workspace, row.reservation_id).await {
            Ok(()) => {
                report.deleted += 1;
                report.deleted_bytes += row.bytes;
            }
            Err(error) => {
                stranded += 1;
                tracing::warn!(
                    %error,
                    bytes = row.bytes,
                    "media: the object was deleted but its reservation row survives, bytes stay charged"
                );
            }
        }
    }
    if stranded > 0 {
        // Appended rather than assigned: every other note in this module is a
        // whole-pass failure that returns immediately, and this one is a count of
        // rows inside a pass that otherwise succeeded.
        report.note = format!(
            "{stranded} object(s) deleted whose reservation row could not be removed; \
             their bytes remain charged"
        );
    }
    let finished = now_ms;
    log_run(pool, "retention", started, finished, &report).await;
    report
}
