// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The restore marker: what stops the storage-listing sweep after a database has
//! been rolled back.
//!
//! `specs/backend/cloud/backup-dr.md` states an RPO of twelve hours, and a restore
//! is the mechanism that promise is made of. The storage-listing sweep decides
//! liveness by asking this database, so the moment the database is older than the
//! bucket, every object uploaded in between looks like garbage to it. The age
//! floor in `super::gc` covers the ordinary case, and this covers the case the
//! floor cannot: a restore to a point further back than any floor worth having.
//!
//! Two mechanisms rather than one because they fail differently. The floor is
//! automatic and needs nobody to remember anything; the marker is exact and
//! covers an arbitrarily old recovery point. Neither is a substitute for the
//! other.
//!
//! **Who writes it.** Whoever completed the database half of the restore, which is
//! the control plane's restore job for a hosted instance and the operator for a
//! self-hosted one, by `POST /gc/restore-marker` on the relay with the operator
//! bearer (`crate::health`). It is written after the restore, never before, so a
//! restore cannot roll its own marker away.
//!
//! **How it clears.** Each collector pass that finds it set logs the suppression
//! and counts it down by one; the pass that takes it to zero deletes the row. It
//! is a count of passes rather than a wall-clock window because a pass is the unit
//! of the thing being suppressed, so an instance whose collector is not running
//! cannot silently spend its protection while nothing is protected.

use sqlx::PgPool;

/// How many collector passes a freshly written marker suppresses.
///
/// Four. The storage-listing sweep runs once per `janitor::STORAGE_LISTING_EVERY`
/// passes, which is daily at the default interval, so four is roughly four days of
/// cover: long enough that the object half of a restore
/// (`backup-dr.md`, `scripts/backup-restore.mjs`) has been run and the clients
/// have reconciled, short enough that the reconcile against bookkeeping is not
/// switched off for a season by an operator who forgot.
pub const DEFAULT_SUPPRESSED_PASSES: i32 = 4;

/// Set the marker, replacing any marker already there.
///
/// Replacing rather than adding: two restores in a week should leave the second
/// one's full protection, not the first one's remainder.
pub async fn set(pool: &PgPool, passes: i32, reason: &str) -> Result<i32, sqlx::Error> {
    let passes = passes.max(0);
    sqlx::query(
        "insert into relay_gc_restore_marker (id, set_at, passes_remaining, reason) \
         values (true, now(), $1, $2) \
         on conflict (id) do update set \
           set_at = now(), passes_remaining = excluded.passes_remaining, reason = excluded.reason",
    )
    .bind(passes)
    .bind(reason)
    .execute(pool)
    .await?;
    Ok(passes)
}

/// How many passes are still suppressed, or `None` when no marker is set.
///
/// A database that cannot answer returns the error rather than `None`. The one
/// caller that acts on it treats a failure as "suppressed", because the question
/// being asked is whether a permanent deletion is safe and an unavailable answer
/// is not a yes.
pub async fn remaining(pool: &PgPool) -> Result<Option<i32>, sqlx::Error> {
    let row: Option<(i32,)> =
        sqlx::query_as("select passes_remaining from relay_gc_restore_marker where id")
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(passes,)| passes).filter(|passes| *passes > 0))
}

/// Whether the sweep is suppressed right now, without changing anything.
///
/// `true` when the marker is set and when the marker could not be read at all.
pub async fn suppressed(pool: &PgPool) -> bool {
    match remaining(pool).await {
        Ok(remaining) => remaining.is_some(),
        Err(error) => {
            tracing::warn!(
                error = %error,
                "media: the restore marker could not be read, so the storage-listing sweep is suppressed"
            );
            true
        }
    }
}

/// Spend one pass of the marker, and answer how many were left before this call.
///
/// `None` means there was nothing to spend and the sweep may run. Exactly one
/// caller counts down, `crate::janitor`, so a pass that touches twenty groups
/// spends one pass of protection rather than twenty.
pub async fn consume_one(pool: &PgPool) -> Option<i32> {
    let before = match remaining(pool).await {
        Ok(Some(before)) => before,
        Ok(None) => return None,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "media: the restore marker could not be read, so this pass runs no storage-listing sweep"
            );
            // Reported as suppressed with an unknown remainder. Nothing is
            // decremented, because decrementing what could not be read would spend
            // protection on a database that is not answering.
            return Some(-1);
        }
    };
    let result = if before <= 1 {
        sqlx::query("delete from relay_gc_restore_marker where id")
            .execute(pool)
            .await
            .map(|_| ())
    } else {
        sqlx::query(
            "update relay_gc_restore_marker set passes_remaining = passes_remaining - 1 where id",
        )
        .execute(pool)
        .await
        .map(|_| ())
    };
    if let Err(error) = result {
        tracing::warn!(error = %error, "media: the restore marker could not be counted down");
    }
    Some(before)
}

/// Remove the marker outright. The operator's way to say the restore is settled
/// before the count runs out.
pub async fn clear(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("delete from relay_gc_restore_marker where id")
        .execute(pool)
        .await?;
    Ok(())
}
