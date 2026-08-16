// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Handshake messages against Postgres: the sequence, the resend, and the replay.
//!
//! The rules are in the parent module. What is here is the transaction boundary,
//! the same split `access`, `invite` and `recovery` make.
//!
//! ## Why the sequence is taken under a lock
//!
//! The order is the product here. Two members committing at the same moment must
//! be given different sequence numbers, and the numbers must be dense, because a
//! joining client replays them in order and a gap it cannot explain is a group it
//! cannot enter. `max(seq) + 1` computed outside a lock hands the same number to
//! both, so the insert is one statement against a locked group row.

use sqlx::PgPool;

use super::{Handshake, HandshakeError};

/// Why a database call could not answer.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("handshake store: {0}")]
    Database(String),
    #[error("{0}")]
    Refused(#[from] HandshakeError),
}

fn db(error: sqlx::Error) -> StoreError {
    StoreError::Database(crate::logging::scrub(&error.to_string()))
}

/// One stored message, in the order it must be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub seq: u64,
    pub message: Vec<u8>,
}

/// What an append did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Appended {
    /// Stored at this sequence number.
    Stored(u64),
    /// Already held, at the sequence number it was given the first time. A resend
    /// after a dropped connection, answered with the number it already has rather
    /// than with an error, which is the promise `SEND` makes for envelopes.
    Duplicate(u64),
}

impl Appended {
    pub fn seq(self) -> u64 {
        match self {
            Self::Stored(seq) | Self::Duplicate(seq) => seq,
        }
    }
}

/// Store one handshake message and return its place in the order.
pub async fn append(pool: &PgPool, handshake: &Handshake) -> Result<Appended, StoreError> {
    handshake.check()?;
    let hash = handshake.hash();

    // The group row is locked first, so two concurrent committers serialise here
    // rather than racing on `max(seq)`. `relay_group` is the natural lock: it is
    // the row that says the group exists, and taking it costs one index lookup.
    let mut tx = pool.begin().await.map_err(db)?;
    let locked = sqlx::query("select 1 as present from relay_group where group_id = $1 for update")
        .bind(&handshake.group)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
    if locked.is_none() {
        // A group the relay has never carried traffic for. It does not learn that a
        // group exists from a handshake message any more than it does from a wrap.
        return Err(StoreError::Database("unknown group".into()));
    }

    // "Has this exact message already landed" and "what number is next" in one
    // statement. Two round trips would answer the same thing at the same isolation,
    // under the same lock, at twice the cost, and would give this function a second
    // read failure to handle that says nothing the first one does not.
    let (existing, next): (Option<i64>, i64) = sqlx::query_as(
        "select (select seq from relay_handshake where group_id = $1 and hash = $2) as existing, \
                coalesce(max(seq) + 1, 0) as next \
         from relay_handshake where group_id = $1",
    )
    .bind(&handshake.group)
    .bind(&hash)
    .fetch_one(&mut *tx)
    .await
    .map_err(db)?;
    if let Some(seq) = existing {
        return Ok(Appended::Duplicate(seq as u64));
    }

    sqlx::query(
        "insert into relay_handshake (group_id, seq, message, hash) values ($1, $2, $3, $4)",
    )
    .bind(&handshake.group)
    .bind(next)
    .bind(&handshake.message)
    .bind(&hash)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok(Appended::Stored(next as u64))
}

/// Every message for a group from `from_seq` onward, in order.
///
/// This is what a joining or reconnecting client replays to reach the group's
/// current epoch. Ordered by the relay's own sequence, which is the only order in
/// which the messages can be applied at all.
///
/// Unbounded on purpose, and therefore not what the subscribe path calls: a full
/// replay of a long-lived group is that whole log resident at once, and every
/// message may be near `MAX_FRAME_BYTES`. `page` is the bounded read; this stays
/// for callers that genuinely want the log in hand.
pub async fn since(pool: &PgPool, group: &[u8], from_seq: u64) -> Result<Vec<Stored>, StoreError> {
    page(pool, group, from_seq, None).await
}

/// One page of the replay: the same read with a row limit.
///
/// The subscribe path reads a page, drains it to the socket, then reads from the
/// sequence after the last row it saw, so peak residency is one page rather than a
/// group's entire commit history. Paging is safe where truncating is not: every
/// message is still delivered, in the same order, and a commit appended while the
/// replay is in flight lands in a later page.
pub async fn page(
    pool: &PgPool,
    group: &[u8],
    from_seq: u64,
    limit: Option<u32>,
) -> Result<Vec<Stored>, StoreError> {
    let from = i64::try_from(from_seq).unwrap_or(i64::MAX);
    // The absent case becomes the largest row count the reader could ever produce
    // rather than a second query string, so there is one statement here and no way
    // for the two to drift apart.
    let limit = i64::from(limit.unwrap_or(u32::MAX));
    // `query_as` rather than `query` plus a `try_get` per column. Both decode, but
    // this way a row the reader cannot make sense of fails the query itself and
    // there is one failure path instead of three. That matters here more than
    // elsewhere: a replay that came back short rather than failing is a member that
    // applies what it got, believes it is current, and then cannot decrypt anything
    // published since.
    let rows: Vec<(i64, Vec<u8>)> = sqlx::query_as(
        "select seq, message from relay_handshake where group_id = $1 and seq >= $2 \
         order by seq limit $3",
    )
    .bind(group)
    .bind(from)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    Ok(rows
        .into_iter()
        .map(|(seq, message)| Stored {
            seq: seq as u64,
            message,
        })
        .collect())
}

/// The next sequence number a group would hand out.
///
/// Read by `/readyz` style callers and by the subscribe path, which tells a client
/// where the handshake log currently ends so it knows when its replay is complete.
pub async fn head(pool: &PgPool, group: &[u8]) -> Result<u64, StoreError> {
    let next: i64 = sqlx::query_scalar(
        "select coalesce(max(seq) + 1, 0) from relay_handshake where group_id = $1",
    )
    .bind(group)
    .fetch_one(pool)
    .await
    .map_err(db)?;
    Ok(next as u64)
}
