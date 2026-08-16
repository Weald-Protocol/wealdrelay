// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The key-package shelf against Postgres.
//!
//! The rules are in the parent module. What is here is the transaction boundary,
//! the same split `access`, `handshake`, `invite` and `recovery` make.
//!
//! ## Why the fetch consumes in one statement
//!
//! Serving the same package twice would hand two dm groups the same joiner leaf
//! key. A select followed by an update would let two concurrent fetches read the
//! same rows before either wrote, so the selection and the consumption are one
//! statement: an `update ... where id in (select ... for update skip locked)`
//! with a `returning`. Two callers racing take disjoint rows or one takes none,
//! and there is no interleaving in which a row is returned twice.

use sqlx::{Executor, PgPool, Postgres, Row};

use super::{LIFETIME_DAYS, MAX_OUTSTANDING};

/// Why a database call could not answer.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("key package store: {0}")]
    Database(String),
}

fn db(error: sqlx::Error) -> StoreError {
    StoreError::Database(crate::logging::scrub(&error.to_string()))
}

/// What a publication did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Published {
    /// Stored. `remaining` is the shelf's depth afterwards, which is the number
    /// `AUTH_ACK` has reported since step 5 and which now has a publisher.
    Stored { remaining: u32 },
    /// The publication would have taken the device over ``MAX_OUTSTANDING``.
    /// Nothing was stored: a partial accept would leave the publisher unable to
    /// tell how many of its packages the relay took.
    OverCap,
}

/// The relay's device handle. `blake3` of the key, matching
/// `ws::key_packages_remaining`, which has counted this table since step 5.
fn device_hash(device_key: &[u8]) -> Vec<u8> {
    blake3::hash(device_key).as_bytes().to_vec()
}

async fn outstanding<'a, E>(executor: E, workspace: &str, hash: &[u8]) -> Result<i64, StoreError>
where
    E: Executor<'a, Database = Postgres>,
{
    let count: i64 = sqlx::query_scalar(
        "select count(*) from relay_key_package \
         where workspace_id = $1 and device_hash = $2 \
           and consumed_at is null and expires_at > now()",
    )
    .bind(workspace)
    .bind(hash)
    .fetch_one(executor)
    .await
    .map_err(db)?;
    Ok(count)
}

/// The advisory lock one shelf is serialized on.
///
/// Derived in this process rather than with `hashtext`, so the number does not
/// depend on a Postgres internal whose stability across versions is not promised.
/// A shelf is `(workspace, device_hash)` and nothing else takes this lock, so two
/// devices publishing at the same moment never wait on each other.
fn shelf_lock(workspace: &str, hash: &[u8]) -> i64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"weald key package shelf v1");
    hasher.update(workspace.as_bytes());
    hasher.update(hash);
    let digest = hasher.finalize();
    i64::from_be_bytes(digest.as_bytes()[..8].try_into().expect("eight bytes"))
}

/// Store packages against the authenticated device key.
pub async fn publish(
    pool: &PgPool,
    workspace: &str,
    device_key: &[u8],
    packages: &[Vec<u8>],
) -> Result<Published, StoreError> {
    let hash = device_hash(device_key);
    // The count and the inserts are one transaction under one advisory lock on
    // this shelf. Read committed alone is not enough: two `KEYS/Publish` frames
    // for the same device both read the same `held`, both find room, and both
    // insert, so the cap `wire.md` states is exceeded by whatever concurrency the
    // publisher can arrange. The lock is taken for the transaction and released by
    // commit or rollback, so a dropped connection cannot park a shelf.
    let mut transaction = pool.begin().await.map_err(db)?;
    sqlx::query("select pg_advisory_xact_lock($1)")
        .bind(shelf_lock(workspace, &hash))
        .execute(&mut *transaction)
        .await
        .map_err(db)?;

    let held = outstanding(&mut *transaction, workspace, &hash).await?;
    let incoming = i64::try_from(packages.len()).unwrap_or(i64::MAX);
    if held.saturating_add(incoming) > MAX_OUTSTANDING {
        // Nothing was written, so the rollback is the whole of the undo.
        return Ok(Published::OverCap);
    }
    for package in packages {
        sqlx::query(
            "insert into relay_key_package \
                 (workspace_id, device_hash, package, expires_at) \
             values ($1, $2, $3, now() + make_interval(days => $4))",
        )
        .bind(workspace)
        .bind(&hash)
        .bind(package.as_slice())
        .bind(i32::try_from(LIFETIME_DAYS).unwrap_or(90))
        .execute(&mut *transaction)
        .await
        .map_err(db)?;
    }
    let remaining = outstanding(&mut *transaction, workspace, &hash).await?;
    transaction.commit().await.map_err(db)?;
    Ok(Published::Stored {
        remaining: u32::try_from(remaining).unwrap_or(u32::MAX),
    })
}

/// One package taken off a shelf, with the row it came from.
///
/// The id travels with the bytes so a delivery that never happened can be undone.
/// A consumed package that reached nobody is a package destroyed, and the shelf is
/// finite: `restore` is the only thing standing between a full outbound queue and
/// a device that can never be added to another group.
pub struct Served {
    pub id: i64,
    pub package: Vec<u8>,
}

/// Take at most `count` packages off one device's shelf, consuming them.
pub async fn fetch(
    pool: &PgPool,
    workspace: &str,
    device_key: &[u8],
    count: u8,
) -> Result<Vec<Vec<u8>>, StoreError> {
    Ok(fetch_served(pool, workspace, device_key, count)
        .await?
        .into_iter()
        .map(|served| served.package)
        .collect())
}

/// `fetch`, keeping the row ids so the caller can put them back if the answer is
/// never delivered.
pub async fn fetch_served(
    pool: &PgPool,
    workspace: &str,
    device_key: &[u8],
    count: u8,
) -> Result<Vec<Served>, StoreError> {
    let hash = device_hash(device_key);
    let rows = sqlx::query(
        "update relay_key_package set consumed_at = now() \
         where id in ( \
             select id from relay_key_package \
             where workspace_id = $1 and device_hash = $2 \
               and consumed_at is null and expires_at > now() \
             order by id \
             limit $3 \
             for update skip locked \
         ) \
         returning id, package",
    )
    .bind(workspace)
    .bind(&hash)
    .bind(i64::from(count))
    .fetch_all(pool)
    .await
    .map_err(db)?;
    rows.into_iter()
        .map(|row| {
            Ok(Served {
                id: row.try_get("id").map_err(db)?,
                package: row.try_get("package").map_err(db)?,
            })
        })
        .collect()
}

/// Put back packages whose answer was never delivered.
///
/// Only rows this call consumed are named, and the update re-checks
/// `consumed_at is not null` so a restore can never resurrect a package that was
/// already served to somebody: the invariant that no package is handed out twice
/// is the reason this shelf exists.
pub async fn restore(pool: &PgPool, ids: &[i64]) -> Result<(), StoreError> {
    if ids.is_empty() {
        return Ok(());
    }
    sqlx::query(
        "update relay_key_package set consumed_at = null \
         where id = any($1) and consumed_at is not null",
    )
    .bind(ids)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(())
}
