// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Recovery wraps against Postgres: the slot, its predecessor, and the sweep.
//!
//! Every rule lives in the parent module and none of them live here. What is here
//! is the transaction boundary, the same split `invite::store` and `access::store`
//! make.
//!
//! ## What this module cannot do
//!
//! It cannot open a wrap. `ct` appears in three statements: one that writes it, one
//! that copies the superseded value into the prior slot, and one that serves it
//! back. There is no key anywhere in this crate that could open one, which is
//! checkable by grep rather than asserted.
//!
//! ## Why the write is one transaction with a row lock
//!
//! Publishing a wrap does three things that have to happen together: refuse a
//! replacement that does not advance the epoch, move the superseded row into the
//! prior slot with its expiry, and install the new row. Done as three unguarded
//! round trips, two committers racing on one slot interleave and the prior slot
//! ends up holding a value that was never current.
//!
//! The first attempt was one statement with data-modifying CTEs, and it was wrong
//! in a way worth recording: CTE branches all see the same snapshot, so a `delete`
//! and an `insert ... on conflict` against the same table in one statement do not
//! see each other. The prior slot silently never got written, and the tests caught
//! it. What is here instead is `select ... for update` inside a transaction, which
//! makes a second committer wait rather than decide, and `on conflict do nothing`
//! for the empty-slot case, where there is no row to lock and the loser has to be
//! told the same thing a replay is told.

use sqlx::{PgPool, Row};

use super::{RecoveryWrap, WrapError, PRIOR_RETENTION_DAYS};

/// Why a database call could not answer.
///
/// Separate from ``WrapError``, exactly as `invite::store::StoreError` is separate
/// from `InviteError`: one is a client that published something wrong and the other
/// is a relay that could not look. A correct client told to stop retrying because
/// the relay's disk was full would be the relay lying about whose fault it was.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("recovery wrap store: {0}")]
    Database(String),
    #[error("{0}")]
    Refused(#[from] WrapError),
}

fn db(error: sqlx::Error) -> StoreError {
    StoreError::Database(crate::logging::scrub(&error.to_string()))
}

/// One stored wrap, as the relay holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub group: Vec<u8>,
    pub tag: Vec<u8>,
    pub epoch: u64,
    pub ct: Vec<u8>,
}

/// What a publication did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Published {
    /// The slot was empty and now holds this wrap.
    Created,
    /// The slot held an older epoch. It has been moved to the prior slot with a
    /// 30-day expiry and replaced.
    Replaced { superseded: u64 },
}

/// Store a wrap, or refuse it.
///
/// The group row must already exist, which it does for any group the relay has
/// carried an envelope for. A wrap for a group the relay has never seen is a
/// foreign key violation and is reported as a database refusal rather than
/// invented into existence: the relay does not learn that a group exists from a
/// wrap, it learns it from traffic.
pub async fn publish(pool: &PgPool, wrap: &RecoveryWrap) -> Result<Published, StoreError> {
    wrap.check()?;
    let epoch = i64::try_from(wrap.epoch)
        .map_err(|_| StoreError::Database("epoch is out of range".into()))?;

    let mut tx = pool.begin().await.map_err(db)?;

    // `for update`, so a second committer publishing into the same slot waits here
    // rather than reading the same epoch and deciding the same thing. This lock is
    // the concurrency control for the whole function: everything below it operates
    // on a row nobody else can move.
    //
    // Written as a transaction rather than one statement with CTEs, which was the
    // first attempt and is wrong. Data-modifying CTEs all see the same snapshot, so
    // a `delete` and an `insert ... on conflict` against one table in one statement
    // do not see each other: the delete removed the row the insert was still
    // conflicting against, and the prior slot silently never got written. The tests
    // caught it, which is the argument for having written them first.
    let existing: Option<(i64, Vec<u8>)> = sqlx::query_as(
        "select epoch, ct from relay_recovery_wrap where group_id = $1 and tag = $2 for update",
    )
    .bind(&wrap.group)
    .bind(&wrap.tag)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?;

    let published = match existing {
        None => {
            // A new slot. `on conflict do nothing` rather than an unguarded insert,
            // because two committers can both find the slot empty: `for update`
            // locks rows that exist and there is nothing here to lock yet. The
            // loser is told the same thing a replay is told.
            let inserted = sqlx::query(
                "insert into relay_recovery_wrap (group_id, tag, epoch, ct) values ($1, $2, $3, $4) \
                 on conflict (group_id, tag) do nothing",
            )
            .bind(&wrap.group)
            .bind(&wrap.tag)
            .bind(epoch)
            .bind(&wrap.ct)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
            if inserted.rows_affected() == 0 {
                let current: i64 = sqlx::query_scalar(
                    "select epoch from relay_recovery_wrap where group_id = $1 and tag = $2",
                )
                .bind(&wrap.group)
                .bind(&wrap.tag)
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
                return Err(StoreError::Refused(WrapError::NotNewer {
                    stored: current as u64,
                    offered: wrap.epoch,
                }));
            }
            Published::Created
        }
        Some((stored_epoch, stored_ct)) => {
            RecoveryWrap::check_replacement(stored_epoch as u64, wrap.epoch)?;
            // The superseded value goes into the prior slot before the current one
            // is overwritten, and the prior slot holds one wrap deep: a second
            // replacement overwrites it rather than accumulating.
            sqlx::query(
                "insert into relay_recovery_wrap_prior (group_id, tag, epoch, ct, expires_at) \
                 values ($1, $2, $3, $4, now() + ($5 || ' days')::interval) \
                 on conflict (group_id, tag) do update set \
                     epoch = excluded.epoch, ct = excluded.ct, \
                     superseded_at = now(), expires_at = excluded.expires_at",
            )
            .bind(&wrap.group)
            .bind(&wrap.tag)
            .bind(stored_epoch)
            .bind(&stored_ct)
            .bind(PRIOR_RETENTION_DAYS.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;

            sqlx::query(
                "update relay_recovery_wrap set epoch = $3, ct = $4, updated_at = now() \
                 where group_id = $1 and tag = $2",
            )
            .bind(&wrap.group)
            .bind(&wrap.tag)
            .bind(epoch)
            .bind(&wrap.ct)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
            Published::Replaced {
                superseded: stored_epoch as u64,
            }
        }
    };

    tx.commit().await.map_err(db)?;
    Ok(published)
}

/// The current wrap in a slot, if there is one.
pub async fn current(
    pool: &PgPool,
    group: &[u8],
    tag: &[u8],
) -> Result<Option<Stored>, StoreError> {
    let row = sqlx::query(
        "select tag, epoch, ct from relay_recovery_wrap where group_id = $1 and tag = $2",
    )
    .bind(group)
    .bind(tag)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    row.map(|row| stored_from(group, row)).transpose()
}

/// The superseded wrap in a slot, if one is still inside its retention window.
///
/// An expired prior row answers `None` rather than being served, even before the
/// sweep has run. Retention is a promise about how long a value remains available,
/// not a promise about when a row is deleted, and a reader that served a value past
/// its window would make the sweep's timing observable.
pub async fn prior(pool: &PgPool, group: &[u8], tag: &[u8]) -> Result<Option<Stored>, StoreError> {
    let row = sqlx::query(
        "select tag, epoch, ct from relay_recovery_wrap_prior \
         where group_id = $1 and tag = $2 and expires_at > now()",
    )
    .bind(group)
    .bind(tag)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    row.map(|row| stored_from(group, row)).transpose()
}

/// Every wrap the relay holds for one group.
///
/// A count and a set of opaque slots. Ordered by tag so that a caller reading two
/// groups gets a stable comparison, which is what the blindness evidence does.
pub async fn for_group(pool: &PgPool, group: &[u8]) -> Result<Vec<Stored>, StoreError> {
    let rows = sqlx::query(
        "select tag, epoch, ct from relay_recovery_wrap where group_id = $1 order by tag",
    )
    .bind(group)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    rows.into_iter()
        .map(|row| stored_from(group, row))
        .collect()
}

/// Drop every prior slot whose retention window has closed.
///
/// Returns how many rows went. Called by the same sweep that expires reservations;
/// safe to call at any time and safe to call twice.
pub async fn sweep_prior(pool: &PgPool) -> Result<u64, StoreError> {
    let result = sqlx::query("delete from relay_recovery_wrap_prior where expires_at <= now()")
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(result.rows_affected())
}

/// Remove a slot entirely, current and prior.
///
/// `specs/backend/relay/lifecycle.md`, step 4 of removal: "delete every
/// `recovery.wrap` sealed to the removed user's recovery key". The caller names
/// tags, because the relay cannot compute one: it has no recovery key and no epoch
/// secret, so which slots belong to a departing person is a fact only a member
/// holds. That is the blinding working rather than a gap in this function.
pub async fn forget(pool: &PgPool, group: &[u8], tags: &[Vec<u8>]) -> Result<u64, StoreError> {
    if tags.is_empty() {
        return Ok(0);
    }
    let current =
        sqlx::query("delete from relay_recovery_wrap where group_id = $1 and tag = any($2)")
            .bind(group)
            .bind(tags)
            .execute(pool)
            .await
            .map_err(db)?;
    let prior =
        sqlx::query("delete from relay_recovery_wrap_prior where group_id = $1 and tag = any($2)")
            .bind(group)
            .bind(tags)
            .execute(pool)
            .await
            .map_err(db)?;
    Ok(current.rows_affected() + prior.rows_affected())
}

/// One row, read back.
///
/// The group is passed in rather than read out of the row. Every caller filtered
/// on it, so re-reading it would be asking the database to hand back a value the
/// caller already has, and would add a decode that can fail for a field that
/// cannot have changed.
fn stored_from(group: &[u8], row: sqlx::postgres::PgRow) -> Result<Stored, StoreError> {
    let epoch: i64 = row.try_get("epoch").map_err(db)?;
    Ok(Stored {
        group: group.to_vec(),
        tag: row.try_get("tag").map_err(db)?,
        epoch: epoch as u64,
        ct: row.try_get("ct").map_err(db)?,
    })
}
