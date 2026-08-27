// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The database half of text compaction: what a checkpoint anchors, what a drop
//! removes, and the run log it leaves behind.
//!
//! `specs/backend/relay/lifecycle.md`. Nothing in this file decides to delete
//! anything. It is called with an instruction that has already been verified and
//! authorized, and its whole job is to make the deletion exact: everything below
//! the barrier goes, every anchor stays, and the numbers are written down.

use sqlx::{PgPool, Row};

/// Why a lifecycle store call could not answer.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("lifecycle store: {0}")]
    Database(String),
}

fn db(error: sqlx::Error) -> StoreError {
    StoreError::Database(error.to_string())
}

/// What one accepted `drop_before` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DropOutcome {
    pub deleted: u64,
    pub bytes: u64,
    pub kept: u64,
}

/// The sequence number the relay assigned one envelope, if it holds it.
///
/// The barrier of a compaction: everything below the checkpoint's own place in
/// the log is what the checkpoint replaces. Read here rather than taken from the
/// instruction, because `seq` is the relay's own numbering and no client has it.
pub async fn seq_of(pool: &PgPool, group: &[u8], hash: &[u8]) -> Result<Option<u64>, StoreError> {
    let seq: Option<i64> =
        sqlx::query_scalar("select seq from relay_envelope where group_id = $1 and hash = $2")
            .bind(group)
            .bind(hash)
            .fetch_optional(pool)
            .await
            .map_err(db)?;
    Ok(seq.map(|value| value as u64))
}

/// Is every hash in `wanted` an envelope this group holds?
///
/// Returns the ones that are missing, because a refusal that named no reason
/// would leave a client guessing which snapshot it failed to publish. The relay
/// "rejects a drop with an incomplete manifest ... rather than guessing which
/// envelopes are safe to lose", so this is asked before anything is written.
pub async fn missing_envelopes(
    pool: &PgPool,
    group: &[u8],
    wanted: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, StoreError> {
    if wanted.is_empty() {
        return Ok(Vec::new());
    }
    // One statement, not one round trip per hash: a manifest may name up to
    // `MAX_SNAPSHOTS` (4096) snapshots, and a sequential loop made a single
    // frame cost thousands of sequential queries against the relay's small
    // shared pool, which one member could repeat at socket speed (WEALD-L264).
    let held: Vec<Vec<u8>> = sqlx::query_scalar(
        "select hash from relay_envelope where group_id = $1 and hash = any($2)",
    )
    .bind(group)
    .bind(wanted)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    let held: std::collections::HashSet<&[u8]> = held.iter().map(|h| h.as_slice()).collect();
    let mut missing = Vec::new();
    for hash in wanted {
        if !held.contains(hash.as_slice()) {
            missing.push(hash.clone());
        }
    }
    Ok(missing)
}

/// Record the checkpoint and its anchors, then drop what the barrier allows.
///
/// One transaction. A run that recorded the anchors and then failed to delete
/// would be harmless, but one that deleted and then failed to record its anchors
/// would leave the next drop free to remove the very snapshots this checkpoint
/// depends on, so the two are never apart.
pub async fn drop_before(
    pool: &PgPool,
    group: &[u8],
    manifest_hash: &[u8],
    barrier_seq: u64,
    epoch: u64,
    snapshots: &[Vec<u8>],
) -> Result<DropOutcome, StoreError> {
    let mut tx = pool.begin().await.map_err(db)?;

    sqlx::query(
        "insert into relay_checkpoint (group_id, manifest_hash, barrier_seq, epoch) \
         values ($1, $2, $3, $4) \
         on conflict (group_id, manifest_hash) do update set barrier_seq = excluded.barrier_seq",
    )
    .bind(group)
    .bind(manifest_hash)
    .bind(barrier_seq as i64)
    .bind(epoch as i64)
    .execute(&mut *tx)
    .await
    .map_err(db)?;

    // The checkpoint's own envelope is an anchor as much as the snapshots are:
    // it is the signature a joiner verifies history from once the changes beneath
    // it are gone.
    //
    // One statement, not one per hash: a `DROP` may name `MAX_SNAPSHOTS` (4096)
    // snapshots, and the loop that wrote them one at a time made a single frame cost
    // thousands of sequential round trips against the relay's small shared pool,
    // which one admitted member could repeat at socket speed (BR-039). This is the
    // same correction `missing_envelopes` already carries for the read half.
    let anchors: Vec<Vec<u8>> = std::iter::once(manifest_hash.to_vec())
        .chain(snapshots.iter().cloned())
        .collect();
    sqlx::query(
        "insert into relay_checkpoint_anchor (group_id, manifest_hash, hash) \
         select $1, $2, h from unnest($3::bytea[]) as h on conflict do nothing",
    )
    .bind(group)
    .bind(manifest_hash)
    .bind(&anchors)
    .execute(&mut *tx)
    .await
    .map_err(db)?;

    // Anchors are read across every checkpoint this group has, not just this one.
    // An older checkpoint's snapshots are still the anchor for anybody verifying
    // from it, and a newer barrier that swept them would strand exactly the
    // history the older checkpoint promised.
    //
    // The two numbers come back as scalars rather than as columns of one row,
    // and that is deliberate: an aggregate the query itself casts can never fail
    // to decode, so a `try_get` on one carries an error arm no database state can
    // reach. What can fail is the statement, and that is what these report.
    //
    // Everything below the barrier, anchors included. What survives is then this
    // minus what the delete removed, which is a subtraction rather than a second
    // count of the same table: a count taken after the delete would be a third
    // statement whose only job is to re-derive a number this one already has.
    let below: i64 = sqlx::query_scalar(
        "select count(*)::bigint from relay_envelope e \
         where e.group_id = $1 and e.seq < $2",
    )
    .bind(group)
    .bind(barrier_seq as i64)
    .fetch_one(&mut *tx)
    .await
    .map_err(db)?;
    let bytes: i64 = sqlx::query_scalar(
        "select coalesce(sum(octet_length(ct)), 0)::bigint from relay_envelope e \
         where e.group_id = $1 and e.seq < $2 \
           and not exists ( \
               select 1 from relay_checkpoint_anchor a \
               where a.group_id = e.group_id and a.hash = e.hash \
           )",
    )
    .bind(group)
    .bind(barrier_seq as i64)
    .fetch_one(&mut *tx)
    .await
    .map_err(db)?;
    let removed = sqlx::query(
        "delete from relay_envelope e \
         where e.group_id = $1 and e.seq < $2 \
           and not exists ( \
               select 1 from relay_checkpoint_anchor a \
               where a.group_id = e.group_id and a.hash = e.hash \
           )",
    )
    .bind(group)
    .bind(barrier_seq as i64)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    let deleted = removed.rows_affected() as i64;

    let kept = below - deleted;

    sqlx::query(
        "insert into relay_drop_run \
         (group_id, manifest_hash, barrier_seq, deleted_count, deleted_bytes, kept_count) \
         values ($1, $2, $3, $4, $5, $6)",
    )
    .bind(group)
    .bind(manifest_hash)
    .bind(barrier_seq as i64)
    .bind(deleted)
    .bind(bytes)
    .bind(kept)
    .execute(&mut *tx)
    .await
    .map_err(db)?;

    tx.commit().await.map_err(db)?;
    Ok(DropOutcome {
        deleted: deleted as u64,
        bytes: bytes as u64,
        kept: kept as u64,
    })
}

/// One row of the run log, newest first. The operator-facing artifact: what was
/// compacted, when, and how much it reclaimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropRun {
    pub manifest_hash: Vec<u8>,
    pub barrier_seq: u64,
    pub deleted_count: u64,
    pub deleted_bytes: u64,
    pub kept_count: u64,
}

pub async fn runs(pool: &PgPool, group: &[u8]) -> Result<Vec<DropRun>, StoreError> {
    let rows = sqlx::query(
        "select manifest_hash, barrier_seq, deleted_count, deleted_bytes, kept_count \
         from relay_drop_run where group_id = $1 order by ran_at desc, id desc",
    )
    .bind(group)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let barrier: i64 = row.try_get("barrier_seq").map_err(db)?;
        let deleted: i64 = row.try_get("deleted_count").map_err(db)?;
        let bytes: i64 = row.try_get("deleted_bytes").map_err(db)?;
        let kept: i64 = row.try_get("kept_count").map_err(db)?;
        out.push(DropRun {
            manifest_hash: row.try_get("manifest_hash").map_err(db)?,
            barrier_seq: barrier as u64,
            deleted_count: deleted as u64,
            deleted_bytes: bytes as u64,
            kept_count: kept as u64,
        });
    }
    Ok(out)
}

/// Every hash this group keeps forever, across every checkpoint it has accepted.
pub async fn anchors(pool: &PgPool, group: &[u8]) -> Result<Vec<Vec<u8>>, StoreError> {
    let rows = sqlx::query(
        "select distinct hash from relay_checkpoint_anchor where group_id = $1 order by hash",
    )
    .bind(group)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(row.try_get("hash").map_err(db)?);
    }
    Ok(out)
}
