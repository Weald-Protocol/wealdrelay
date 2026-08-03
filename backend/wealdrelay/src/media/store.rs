// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Quota, reservations and multipart sessions against Postgres.
//!
//! `relay_quota` and `relay_blob_reservation` are `migration 0001`'s, laid down
//! before this step existed. `relay_quota.reserved_bytes` moves to
//! `stored_bytes` at exactly one moment: `claim`, called when a valid retention
//! manifest first names a hash (`specs/backend/relay/media.md`, "the relay uses
//! its immutable receipt time for the blob's first accepted manifest claim").
//! That is also the moment `relay_blob_reservation.finalized_at` is set, which is
//! why the column exists rather than a second one: there is exactly one place a
//! blob's lifecycle clock is set, and it is this function.
//!
//! Every quota decision holds `relay_quota`'s row for the width of its
//! transaction (`select ... for update`), so two reservations racing for the same
//! workspace's last few bytes serialize on that lock rather than both reading a
//! stale total and both succeeding. Because the lock is taken before any other
//! statement in ``reserve``, it also serializes two concurrent first-reservations
//! of the very same object, which is what makes the unique index on
//! `(workspace, group, hash)` a backstop rather than the only thing standing
//! between two writers and a doubled count.

use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Why a store call could not answer.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("media store: {0}")]
    Database(String),
}

fn db(error: sqlx::Error) -> StoreError {
    StoreError::Database(error.to_string())
}

/// Is this nullable timestamp column set?
///
/// The three lifecycle flags on the rows below (`finalized`, `completed`,
/// `aborted`) are each "this timestamp is there". Asking the database for the
/// answer, as `(finalized_at is not null) as finalized`, produces a value whose
/// type Postgres itself guarantees, so the decode below could never fail and no
/// test could ever make it. Reading the timestamp and answering in Rust keeps one
/// failure the relay actually has to survive: a column that is not the type the
/// reader expects, which is what a bad migration or a hand-edited database is.
fn is_set(row: &sqlx::postgres::PgRow, column: &str) -> Result<bool, StoreError> {
    let at: Option<sqlx::types::time::OffsetDateTime> = row.try_get(column).map_err(db)?;
    Ok(at.is_some())
}

/// What `reserve` decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reserved {
    /// A fresh or refreshed reservation, good for another window from now.
    Active { reservation_id: Uuid },
    /// The object is already stored: `exists`, the free retry.
    AlreadyStored,
    /// The workspace does not have `bytes` left against its plan.
    OverQuota,
}

/// Ensure a workspace's quota row exists, with the given limit.
///
/// `on conflict do update` rather than `do nothing`: a relay restarted with a
/// changed `WEALD_RELAY_MAX_STORAGE_GB` should enforce the new limit on its next
/// reservation, not the one it booted with months ago.
pub async fn ensure_quota_row(
    pool: &PgPool,
    workspace: &str,
    limit_bytes: Option<i64>,
) -> Result<(), StoreError> {
    sqlx::query(
        "insert into relay_quota (workspace_id, limit_bytes) values ($1, $2) \
         on conflict (workspace_id) do update set limit_bytes = excluded.limit_bytes",
    )
    .bind(workspace)
    .bind(limit_bytes)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(())
}

/// Stored and reserved bytes, and the configured limit, for one workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    pub stored_bytes: i64,
    pub reserved_bytes: i64,
    pub limit_bytes: Option<i64>,
}

pub async fn usage(pool: &PgPool, workspace: &str) -> Result<Usage, StoreError> {
    let row = sqlx::query(
        "select stored_bytes, reserved_bytes, limit_bytes from relay_quota where workspace_id = $1",
    )
    .bind(workspace)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    Ok(match row {
        Some(row) => Usage {
            stored_bytes: row.try_get("stored_bytes").map_err(db)?,
            reserved_bytes: row.try_get("reserved_bytes").map_err(db)?,
            limit_bytes: row.try_get("limit_bytes").map_err(db)?,
        },
        None => Usage {
            stored_bytes: 0,
            reserved_bytes: 0,
            limit_bytes: None,
        },
    })
}

/// Reserve `bytes` for one object, atomically against the workspace's plan.
///
/// Checked at `BLOB put`, before any presigned URL is issued
/// (`specs/backend/relay/media.md`, "Quota"). `already_stored` is checked first
/// and treated as a short circuit: an object that already exists needs no
/// reservation at all, which is what makes a retry after a dropped upload free. A
/// second `reserve` for an object already reserved (an in-flight retry) refreshes
/// the existing reservation's expiry instead of taking a second helping of quota.
pub async fn reserve(
    pool: &PgPool,
    workspace: &str,
    group: &[u8],
    hash: &[u8],
    bytes: i64,
    already_stored: bool,
    ttl_seconds: i64,
) -> Result<Reserved, StoreError> {
    if already_stored {
        return Ok(Reserved::AlreadyStored);
    }
    let mut tx = pool.begin().await.map_err(db)?;
    let quota_row = sqlx::query(
        "select stored_bytes, reserved_bytes, limit_bytes from relay_quota \
         where workspace_id = $1 for update",
    )
    .bind(workspace)
    .fetch_one(&mut *tx)
    .await
    .map_err(db)?;
    let stored: i64 = quota_row.try_get("stored_bytes").map_err(db)?;
    let reserved: i64 = quota_row.try_get("reserved_bytes").map_err(db)?;
    let limit: Option<i64> = quota_row.try_get("limit_bytes").map_err(db)?;

    // An in-flight reservation for this exact object, held by an earlier attempt
    // at the same upload. Refreshed rather than doubled: the bytes it already
    // holds are still charged, and charging them again would let a client that
    // keeps retrying its own upload eventually push a workspace over quota by
    // itself.
    let existing = sqlx::query(
        "select reservation_id from relay_blob_reservation \
         where workspace_id = $1 and group_id = $2 and blob_hash = $3 and finalized_at is null \
         for update",
    )
    .bind(workspace)
    .bind(group)
    .bind(hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?;
    if let Some(existing) = existing {
        let reservation_id: Uuid = existing.try_get("reservation_id").map_err(db)?;
        sqlx::query(
            "update relay_blob_reservation set expires_at = now() + make_interval(secs => $2) \
             where reservation_id = $1",
        )
        .bind(reservation_id)
        .bind(ttl_seconds as f64)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        return Ok(Reserved::Active { reservation_id });
    }

    if let Some(limit) = limit {
        if stored + reserved + bytes > limit {
            // Nothing to undo: the transaction is dropped on return, which rolls
            // back the row lock and leaves the quota row exactly as it was.
            return Ok(Reserved::OverQuota);
        }
    }

    let reservation_id = Uuid::new_v4();
    sqlx::query(
        "insert into relay_blob_reservation \
         (reservation_id, workspace_id, group_id, blob_hash, bytes, expires_at) \
         values ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))",
    )
    .bind(reservation_id)
    .bind(workspace)
    .bind(group)
    .bind(hash)
    .bind(bytes)
    .bind(ttl_seconds as f64)
    .execute(&mut *tx)
    .await
    .map_err(db)?;

    sqlx::query(
        "update relay_quota set reserved_bytes = reserved_bytes + $2, updated_at = now() \
         where workspace_id = $1",
    )
    .bind(workspace)
    .bind(bytes)
    .execute(&mut *tx)
    .await
    .map_err(db)?;

    tx.commit().await.map_err(db)?;
    Ok(Reserved::Active { reservation_id })
}

/// One reservation row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    pub reservation_id: Uuid,
    pub hash: Vec<u8>,
    pub bytes: i64,
    pub finalized: bool,
}

pub async fn find_active_reservation(
    pool: &PgPool,
    workspace: &str,
    group: &[u8],
    hash: &[u8],
) -> Result<Option<Reservation>, StoreError> {
    let row = sqlx::query(
        "select reservation_id, blob_hash, bytes, finalized_at \
         from relay_blob_reservation \
         where workspace_id = $1 and group_id = $2 and blob_hash = $3 \
         order by created_at desc limit 1",
    )
    .bind(workspace)
    .bind(group)
    .bind(hash)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some(Reservation {
        reservation_id: row.try_get("reservation_id").map_err(db)?,
        hash: row.try_get("blob_hash").map_err(db)?,
        bytes: row.try_get("bytes").map_err(db)?,
        // Derived here rather than by the query. `(finalized_at is not null) as
        // finalized` is a boolean Postgres computes and guarantees the type of, so
        // the error arm on reading it back can never be taken and no test can
        // produce it: a failure path nobody has run is not a handled failure.
        // Reading the column itself has a failure a retyped column produces, which
        // is the database fault this branch is here for.
        finalized: is_set(&row, "finalized_at")?,
    }))
}

/// Mark the reservation for `(workspace, group, hash)` finalized: the relay now
/// has independent confirmation the object exists (a valid manifest claimed it),
/// and its bytes move from reserved to stored. A second claim (a later manifest
/// naming the same hash again) is a no-op: `finalized_at` is only ever set once,
/// which is what the `finalized_at is null` guard enforces.
pub async fn claim(
    pool: &PgPool,
    workspace: &str,
    group: &[u8],
    hash: &[u8],
) -> Result<bool, StoreError> {
    let mut tx = pool.begin().await.map_err(db)?;
    let row = sqlx::query(
        "update relay_blob_reservation set finalized_at = now() \
         where workspace_id = $1 and group_id = $2 and blob_hash = $3 and finalized_at is null \
         returning bytes",
    )
    .bind(workspace)
    .bind(group)
    .bind(hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?;
    let Some(row) = row else {
        tx.commit().await.map_err(db)?;
        return Ok(false);
    };
    let bytes: i64 = row.try_get("bytes").map_err(db)?;
    sqlx::query(
        "update relay_quota set reserved_bytes = greatest(reserved_bytes - $2, 0), \
         stored_bytes = stored_bytes + $2, updated_at = now() where workspace_id = $1",
    )
    .bind(workspace)
    .bind(bytes)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok(true)
}

/// Release one reservation's bytes back to the workspace without finalizing it,
/// and remove the row. Used by an explicit abort and by the 24-hour
/// unclaimed-upload collector.
pub async fn release(
    pool: &PgPool,
    workspace: &str,
    reservation_id: Uuid,
) -> Result<Option<i64>, StoreError> {
    let mut tx = pool.begin().await.map_err(db)?;
    let row = sqlx::query(
        "delete from relay_blob_reservation \
         where workspace_id = $1 and reservation_id = $2 and finalized_at is null \
         returning bytes",
    )
    .bind(workspace)
    .bind(reservation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?;
    let Some(row) = row else {
        tx.commit().await.map_err(db)?;
        return Ok(None);
    };
    let bytes: i64 = row.try_get("bytes").map_err(db)?;
    sqlx::query(
        "update relay_quota set reserved_bytes = greatest(reserved_bytes - $2, 0), \
         updated_at = now() where workspace_id = $1",
    )
    .bind(workspace)
    .bind(bytes)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok(Some(bytes))
}

/// Record that a claimed blob's object has been physically deleted: its bytes
/// leave `stored_bytes` and its reservation row is removed. Only ever called
/// after `media::gc` has decided the object is eligible under
/// `specs/backend/relay/media.md`'s deletion rule, and after the object itself
/// has already been removed from storage, so a crash between the two leaves an
/// orphaned-but-harmless storage delete rather than a quota row that undercounts
/// something still in the bucket.
pub async fn finish_deletion(
    pool: &PgPool,
    workspace: &str,
    reservation_id: Uuid,
) -> Result<(), StoreError> {
    let mut tx = pool.begin().await.map_err(db)?;
    let row = sqlx::query(
        "delete from relay_blob_reservation \
         where workspace_id = $1 and reservation_id = $2 and finalized_at is not null \
         returning bytes",
    )
    .bind(workspace)
    .bind(reservation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?;
    if let Some(row) = row {
        let bytes: i64 = row.try_get("bytes").map_err(db)?;
        sqlx::query(
            "update relay_quota set stored_bytes = greatest(stored_bytes - $2, 0), \
             updated_at = now() where workspace_id = $1",
        )
        .bind(workspace)
        .bind(bytes)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    }
    tx.commit().await.map_err(db)?;
    Ok(())
}

/// One claimed blob, and the moment the relay recorded the claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedBlob {
    pub reservation_id: Uuid,
    pub hash: Vec<u8>,
    pub bytes: i64,
    /// Milliseconds since the epoch, read from `finalized_at`.
    /// `specs/backend/relay/media.md`: "the relay uses its immutable receipt
    /// time for the blob's first accepted manifest claim, not a client-supplied
    /// media timestamp". It is read in the same statement as the rest of the
    /// row rather than by a second query per blob, so there is no window in
    /// which a concurrent deletion could leave the collector holding a
    /// reservation with no clock.
    pub claimed_at_ms: u64,
}

/// Every claimed (finalized) reservation for one workspace and group, for the
/// retention-driven collector to check each against the latest manifest.
pub async fn finalized_reservations(
    pool: &PgPool,
    workspace: &str,
    group: &[u8],
) -> Result<Vec<ClaimedBlob>, StoreError> {
    let rows = sqlx::query(
        "select reservation_id, blob_hash, bytes, \
                extract(epoch from finalized_at)::bigint as claimed_at \
         from relay_blob_reservation \
         where workspace_id = $1 and group_id = $2 and finalized_at is not null",
    )
    .bind(workspace)
    .bind(group)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    rows.into_iter()
        .map(|row| {
            let claimed_at: i64 = row.try_get("claimed_at").map_err(db)?;
            Ok(ClaimedBlob {
                reservation_id: row.try_get("reservation_id").map_err(db)?,
                hash: row.try_get("blob_hash").map_err(db)?,
                bytes: row.try_get("bytes").map_err(db)?,
                claimed_at_ms: (claimed_at.max(0) as u64) * 1000,
            })
        })
        .collect()
}

/// Every reservation older than `older_than_seconds` that was never finalized:
/// the 24-hour unclaimed-upload collector's candidate list.
pub async fn stale_unclaimed(
    pool: &PgPool,
    older_than_seconds: i64,
) -> Result<Vec<(String, Vec<u8>, Vec<u8>, Uuid)>, StoreError> {
    let rows = sqlx::query(
        "select workspace_id, group_id, blob_hash, reservation_id from relay_blob_reservation \
         where finalized_at is null and created_at < now() - make_interval(secs => $1)",
    )
    .bind(older_than_seconds as f64)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    rows.into_iter()
        .map(|row| {
            Ok((
                row.try_get("workspace_id").map_err(db)?,
                row.try_get("group_id").map_err(db)?,
                row.try_get("blob_hash").map_err(db)?,
                row.try_get("reservation_id").map_err(db)?,
            ))
        })
        .collect()
}

/// Every claimed blob for one workspace and group, with its reserved byte count
/// (the size the relay charges it at). This is the set the storage-listing
/// collector checks a bucket key against.
pub async fn claimed_hashes(
    pool: &PgPool,
    workspace: &str,
    group: &[u8],
) -> Result<Vec<Vec<u8>>, StoreError> {
    let rows = sqlx::query(
        "select blob_hash from relay_blob_reservation \
         where workspace_id = $1 and group_id = $2",
    )
    .bind(workspace)
    .bind(group)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    rows.into_iter()
        .map(|row| row.try_get("blob_hash").map_err(db))
        .collect()
}

// MARK: Multipart sessions.

pub async fn create_multipart(
    pool: &PgPool,
    reservation_id: Uuid,
    upload_id: &str,
    part_size: i64,
    ttl_seconds: i64,
) -> Result<Uuid, StoreError> {
    let session_id = Uuid::new_v4();
    sqlx::query(
        "insert into relay_blob_multipart \
         (session_id, reservation_id, upload_id, part_size, expires_at) \
         values ($1, $2, $3, $4, now() + make_interval(secs => $5))",
    )
    .bind(session_id)
    .bind(reservation_id)
    .bind(upload_id)
    .bind(part_size)
    .bind(ttl_seconds as f64)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(session_id)
}

/// A multipart session, resolved with the reservation it spends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartSession {
    pub session_id: Uuid,
    pub reservation_id: Uuid,
    pub workspace: String,
    pub group: Vec<u8>,
    pub hash: Vec<u8>,
    pub upload_id: String,
    pub part_size: i64,
    pub total_bytes: i64,
    pub completed: bool,
    pub aborted: bool,
}

pub async fn find_multipart(
    pool: &PgPool,
    session_id: Uuid,
) -> Result<Option<MultipartSession>, StoreError> {
    let row = sqlx::query(
        "select m.session_id, m.reservation_id, m.upload_id, m.part_size, \
                m.completed_at, m.aborted_at, \
                r.workspace_id, r.group_id, r.blob_hash, r.bytes \
         from relay_blob_multipart m \
         join relay_blob_reservation r on r.reservation_id = m.reservation_id \
         where m.session_id = $1",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some(MultipartSession {
        session_id: row.try_get("session_id").map_err(db)?,
        reservation_id: row.try_get("reservation_id").map_err(db)?,
        workspace: row.try_get("workspace_id").map_err(db)?,
        group: row.try_get("group_id").map_err(db)?,
        hash: row.try_get("blob_hash").map_err(db)?,
        upload_id: row.try_get("upload_id").map_err(db)?,
        part_size: row.try_get("part_size").map_err(db)?,
        total_bytes: row.try_get("bytes").map_err(db)?,
        completed: is_set(&row, "completed_at")?,
        aborted: is_set(&row, "aborted_at")?,
    }))
}

/// Record (or refresh) one part's issuance. `expected_len` is immutable once a
/// part number has been issued: a second request for the same part number with a
/// different length is refused by the caller before this is reached, per
/// `media.md`'s "part numbers, expected ciphertext lengths and the reservation id
/// are immutable".
pub async fn record_part(
    pool: &PgPool,
    session_id: Uuid,
    part_number: i32,
    expected_len: i64,
) -> Result<(), StoreError> {
    sqlx::query(
        "insert into relay_blob_multipart_part (session_id, part_number, expected_len) \
         values ($1, $2, $3) \
         on conflict (session_id, part_number) do update set issued_at = now()",
    )
    .bind(session_id)
    .bind(part_number)
    .bind(expected_len)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(())
}

pub async fn expected_len_of(
    pool: &PgPool,
    session_id: Uuid,
    part_number: i32,
) -> Result<Option<i64>, StoreError> {
    let row = sqlx::query(
        "select expected_len from relay_blob_multipart_part \
         where session_id = $1 and part_number = $2",
    )
    .bind(session_id)
    .bind(part_number)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    row.map(|row| row.try_get("expected_len").map_err(db))
        .transpose()
}

pub async fn complete_multipart(pool: &PgPool, session_id: Uuid) -> Result<(), StoreError> {
    sqlx::query("update relay_blob_multipart set completed_at = now() where session_id = $1")
        .bind(session_id)
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(())
}

pub async fn abort_multipart(pool: &PgPool, session_id: Uuid) -> Result<(), StoreError> {
    sqlx::query("update relay_blob_multipart set aborted_at = now() where session_id = $1")
        .bind(session_id)
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(())
}

/// Every multipart session past its expiry with no completion: aborted, its
/// reservation released, alongside the plain unclaimed-upload sweep.
pub async fn stale_multipart_sessions(pool: &PgPool) -> Result<Vec<(Uuid, Uuid)>, StoreError> {
    let rows = sqlx::query(
        "select session_id, reservation_id from relay_blob_multipart \
         where completed_at is null and aborted_at is null and expires_at < now()",
    )
    .fetch_all(pool)
    .await
    .map_err(db)?;
    rows.into_iter()
        .map(|row| {
            Ok((
                row.try_get("session_id").map_err(db)?,
                row.try_get("reservation_id").map_err(db)?,
            ))
        })
        .collect()
}
