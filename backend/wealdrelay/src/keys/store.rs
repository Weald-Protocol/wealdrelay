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

use sqlx::{PgPool, Row};

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

async fn outstanding(pool: &PgPool, workspace: &str, hash: &[u8]) -> Result<i64, StoreError> {
    let count: i64 = sqlx::query_scalar(
        "select count(*) from relay_key_package \
         where workspace_id = $1 and device_hash = $2 \
           and consumed_at is null and expires_at > now()",
    )
    .bind(workspace)
    .bind(hash)
    .fetch_one(pool)
    .await
    .map_err(db)?;
    Ok(count)
}

/// Store packages against the authenticated device key.
pub async fn publish(
    pool: &PgPool,
    workspace: &str,
    device_key: &[u8],
    packages: &[Vec<u8>],
) -> Result<Published, StoreError> {
    let hash = device_hash(device_key);
    let held = outstanding(pool, workspace, &hash).await?;
    let incoming = i64::try_from(packages.len()).unwrap_or(i64::MAX);
    if held.saturating_add(incoming) > MAX_OUTSTANDING {
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
        .execute(pool)
        .await
        .map_err(db)?;
    }
    let remaining = outstanding(pool, workspace, &hash).await?;
    Ok(Published::Stored {
        remaining: u32::try_from(remaining).unwrap_or(u32::MAX),
    })
}

/// Take at most `count` packages off one device's shelf, consuming them.
pub async fn fetch(
    pool: &PgPool,
    workspace: &str,
    device_key: &[u8],
    count: u8,
) -> Result<Vec<Vec<u8>>, StoreError> {
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
         returning package",
    )
    .bind(workspace)
    .bind(&hash)
    .bind(i64::from(count))
    .fetch_all(pool)
    .await
    .map_err(db)?;
    rows.into_iter()
        .map(|row| row.try_get::<Vec<u8>, _>("package").map_err(db))
        .collect()
}
