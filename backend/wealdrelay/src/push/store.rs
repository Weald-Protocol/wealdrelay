// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The registration table against Postgres.
//!
//! The rules are in the parent module and in `migrations/0009_push.sql`. What is
//! here is the transaction boundary, the same split `access`, `handshake`, `keys`
//! and `invite` make.
//!
//! ## Why uniqueness is the database's job
//!
//! A second principal claiming a handle that is already registered is the only way
//! one device could steal another's wakes, so it is refused by a unique index rather
//! than by a read followed by a write. Two devices registering the same handle in
//! the same instant is exactly the interleaving a check-then-insert loses, and it is
//! not a race a relay can be careful about: it has to be one the database cannot
//! permit.
//!
//! ## Why the deletion on drop is in the caller's transaction
//!
//! ``delete_for_entries`` takes a transaction rather than a pool. A principal whose
//! access-set entry has been dropped must not keep a wake capability, and doing the
//! deletion after the set was accepted would leave a window in which the entry is
//! gone and the capability is not. The window is short and the consequence is
//! permanent, which is the combination that argues for one transaction.

use sqlx::{PgPool, Postgres, Row, Transaction};

/// Why a registration call could not answer. One variant, because there is one
/// failure: the database.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("push handle store: {0}")]
    Database(String),
}

fn db(error: sqlx::Error) -> StoreError {
    StoreError::Database(crate::logging::scrub(&error.to_string()))
}

/// Whether a failure was the unique index on `handle` refusing a second claim.
///
/// Read from the driver's own classification rather than from the message text, so a
/// Postgres release that rewords `23505` does not turn a refusal into an outage.
fn is_handle_taken(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
}

/// What a registration did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registered {
    /// Stored, replacing whatever this principal had in this workspace.
    Stored,
    /// The handle belongs to another principal. Refused rather than moved: a handle
    /// is a capability the device minted, and honouring a claim on somebody else's
    /// would let one device take over another's wakes.
    HandleTaken,
}

/// One live registration, as the wake path reads it.
///
/// `entry_hash` is carried because the wake path has to ask the hub whether this
/// principal is holding a socket, and the hub is keyed by entry hash. It is the same
/// name the access set uses and it is not a device key.
#[derive(Clone, PartialEq, Eq)]
pub struct Wakeable {
    pub entry_hash: Vec<u8>,
    pub handle: Vec<u8>,
    pub categories: u8,
}

/// Redacted, like every other type that holds a handle.
impl std::fmt::Debug for Wakeable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wakeable")
            .field("entry_hash", &crate::logging::hex_prefix(&self.entry_hash))
            .field("handle", &crate::logging::NeverLogged)
            .field("categories", &self.categories)
            .finish()
    }
}

/// Milliseconds since the epoch, as Postgres wants a `timestamptz` argument.
fn seconds(now_ms: u64) -> f64 {
    now_ms as f64 / 1000.0
}

/// Store a registration against one principal in one workspace.
///
/// An upsert on the primary key, so re-registering replaces rather than
/// accumulates: a device that rotates weekly holds one row for the year.
pub async fn register(
    pool: &PgPool,
    workspace: &str,
    entry_hash: &[u8],
    handle: &[u8],
    categories: u8,
    expires_at_ms: u64,
) -> Result<Registered, StoreError> {
    let outcome = sqlx::query(
        "insert into relay_push_handle \
             (workspace_id, entry_hash, handle, categories, expires_at, updated_at) \
         values ($1, $2, $3, $4, to_timestamp($5), now()) \
         on conflict (workspace_id, entry_hash) do update \
         set handle = excluded.handle, categories = excluded.categories, \
             expires_at = excluded.expires_at, updated_at = now()",
    )
    .bind(workspace)
    .bind(entry_hash)
    .bind(handle)
    .bind(i16::from(categories))
    .bind(seconds(expires_at_ms))
    .execute(pool)
    .await;
    match outcome {
        Ok(_) => Ok(Registered::Stored),
        Err(error) if is_handle_taken(&error) => Ok(Registered::HandleTaken),
        Err(error) => Err(db(error)),
    }
}

/// Forget one principal's registration in one workspace.
///
/// Returns whether a row was there, which the caller does **not** put on the wire:
/// `Clear` with no row is answered `Cleared` exactly like `Clear` with one, because
/// the client's desired state has been reached either way and a distinguishable
/// answer would make this an oracle for whether a principal had registered.
pub async fn clear(pool: &PgPool, workspace: &str, entry_hash: &[u8]) -> Result<bool, StoreError> {
    let deleted =
        sqlx::query("delete from relay_push_handle where workspace_id = $1 and entry_hash = $2")
            .bind(workspace)
            .bind(entry_hash)
            .execute(pool)
            .await
            .map_err(db)?;
    Ok(deleted.rows_affected() > 0)
}

/// One principal's registration, or `None`. For the tests and for the store's own
/// round trip; nothing on the wire returns this.
pub async fn find(
    pool: &PgPool,
    workspace: &str,
    entry_hash: &[u8],
) -> Result<Option<(Vec<u8>, u8, u64)>, StoreError> {
    let row = sqlx::query(
        "select handle, categories, \
                (extract(epoch from expires_at) * 1000)::bigint as expires_ms \
         from relay_push_handle where workspace_id = $1 and entry_hash = $2",
    )
    .bind(workspace)
    .bind(entry_hash)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let handle: Vec<u8> = row.try_get("handle").map_err(db)?;
    let categories: i16 = row.try_get("categories").map_err(db)?;
    let expires: i64 = row.try_get("expires_ms").map_err(db)?;
    Ok(Some((
        handle,
        // The column is constrained to 1..7, so both conversions are total against
        // any row the database will hold. Written saturating rather than fallible so
        // there is no arm here that only a corrupted database could reach, which is
        // the same choice `log::row_to_item` makes and for the same reason.
        u8::try_from(categories).unwrap_or_default(),
        u64::try_from(expires).unwrap_or_default(),
    )))
}

/// Every live registration that would be woken for one category in one group.
///
/// The membership question is the access set's, asked here in one statement rather
/// than by loading the set: a registration counts only if its principal is in the
/// newest accepted set of the workspace that owns the group. So a device that was
/// admitted last week and has since been dropped is not woken even in the moment
/// before its row is deleted, which makes the deletion a tidiness measure rather
/// than the security boundary.
pub async fn wakeable_for_group(
    pool: &PgPool,
    group: &[u8],
    category: super::Category,
    now_ms: u64,
) -> Result<Vec<Wakeable>, StoreError> {
    let rows = sqlx::query(
        "select p.entry_hash, p.handle, p.categories \
         from relay_push_handle p \
         join relay_group g on g.workspace_id = p.workspace_id \
         join relay_access_entry e \
              on e.workspace_id = p.workspace_id and e.entry_hash = p.entry_hash \
             and e.version = (select max(version) from relay_access_set \
                              where workspace_id = p.workspace_id) \
         where g.group_id = $1 \
           and p.expires_at > to_timestamp($2) \
           and (p.categories & $3) <> 0 \
         order by p.entry_hash",
    )
    .bind(group)
    .bind(seconds(now_ms))
    .bind(i16::from(category.bit()))
    .fetch_all(pool)
    .await
    .map_err(db)?;
    rows.into_iter()
        .map(|row| {
            Ok(Wakeable {
                entry_hash: row.try_get("entry_hash").map_err(db)?,
                handle: row.try_get("handle").map_err(db)?,
                categories: u8::try_from(row.try_get::<i16, _>("categories").map_err(db)?)
                    .unwrap_or_default(),
            })
        })
        .collect()
}

/// Delete the row for one handle, because the ringer answered `404`.
///
/// The ringer has told us the device is gone, and keeping the row would be keeping a
/// dead capability that the relay would go on trying to ring on every accepted
/// envelope. Keyed on the handle alone, which is what the ringer named and the only
/// thing it knows.
pub async fn delete_by_handle(pool: &PgPool, handle: &[u8]) -> Result<u64, StoreError> {
    let deleted = sqlx::query("delete from relay_push_handle where handle = $1")
        .bind(handle)
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(deleted.rows_affected())
}

/// Drop every registration whose stated expiry has passed.
///
/// The existing collector's shape rather than a timer of its own: a caller with a
/// clock runs it, exactly as `media::gc`'s passes are run, so there is no second
/// scheduler to reason about and the pass is reachable from a test without waiting.
pub async fn sweep_expired(pool: &PgPool, now_ms: u64) -> Result<u64, StoreError> {
    let deleted = sqlx::query("delete from relay_push_handle where expires_at <= to_timestamp($1)")
        .bind(seconds(now_ms))
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(deleted.rows_affected())
}

/// Drop the registrations of principals an access-set publication removed.
///
/// Takes the caller's transaction, so the entry and the capability disappear
/// together. Called by `access::store::publish` with `effects.removed`, which is the
/// list whose sockets are also closed: the two halves of offboarding the relay owns.
pub async fn delete_for_entries(
    transaction: &mut Transaction<'_, Postgres>,
    workspace: &str,
    entries: &[Vec<u8>],
) -> Result<u64, StoreError> {
    if entries.is_empty() {
        // No statement at all for the ordinary publication, which removes nobody.
        // `= any('{}')` would be correct and would still be a round trip inside
        // somebody else's transaction.
        return Ok(0);
    }
    let deleted = sqlx::query(
        "delete from relay_push_handle where workspace_id = $1 and entry_hash = any($2)",
    )
    .bind(workspace)
    .bind(entries)
    .execute(&mut **transaction)
    .await
    .map_err(db)?;
    Ok(deleted.rows_affected())
}

/// The registration ceiling: five per principal per hour.
///
/// Process-local and in memory, which is the shape `media::RateLimiter` already
/// uses for the per-device blob budget, and it is the right shape for the same
/// reason: the ceiling exists so a device with a retry loop cannot spend the
/// relay's write capacity, and that is a property of this process's load rather
/// than a fact worth a table and a collector of its own.
///
/// Keyed by entry hash, so it is per principal rather than per connection: a device
/// that reconnects does not get a fresh allowance, which is the hole a
/// per-connection budget would leave.
#[derive(Debug, Default)]
pub struct RateLimiter {
    principals: tokio::sync::Mutex<std::collections::HashMap<Vec<u8>, Vec<u64>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this principal may register once more, charging it when it may.
    ///
    /// A sliding window over the timestamps rather than a fixed bucket, because a
    /// fixed hour boundary would admit ten registrations either side of it and the
    /// ceiling is about the rate rather than about the clock. Five timestamps per
    /// registered principal is a trivial amount of memory, and the vector is pruned
    /// on every call so it cannot grow.
    pub async fn allow(&self, entry_hash: &[u8], now_ms: u64) -> bool {
        let mut principals = self.principals.lock().await;
        let attempts = principals.entry(entry_hash.to_vec()).or_default();
        attempts.retain(|at| now_ms.saturating_sub(*at) < super::RATE_WINDOW_MS);
        if attempts.len() >= super::REGISTRATIONS_PER_HOUR as usize {
            return false;
        }
        attempts.push(now_ms);
        true
    }
}
