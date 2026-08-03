// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Reading the envelope log back out: the queries reconciliation and backfill run.
//!
//! Separate from `accept.rs`, which writes. The read side has different failure
//! semantics and a different reason to exist: `accept` is the trust boundary and
//! answers with an error class per refusal, while everything here is a cursor read
//! whose only interesting failure is "the database has gone", which the caller
//! turns into `retry/backpressure` exactly as the write path does.
//!
//! ## Nothing here is derived from content
//!
//! The queries select `hash`, `seq` and the eight header fields. There is no
//! predicate on `ct` anywhere in this module and there is nowhere for one to go: a
//! query that filtered on ciphertext would be a query the relay could not run
//! without reading it, and the schema deliberately has no column that would let it
//! (`migrations/0001_relay_schema.sql`).
//!
//! ## Why the item set is loaded whole for a group
//!
//! ``items`` reads every `(seq, hash)` pair for one group, which is 40 bytes a row.
//! A hundred thousand envelopes is four megabytes, and the alternative, streaming one
//! range per round trip, would hold a transaction open across a client's think time.
//! The bound that matters is `MAX_ITEMS_PER_RECONCILE` below: past it the relay
//! reconciles the newest window and tells the client, rather than loading an
//! unbounded set into memory because a peer asked it to.
//!
//! This comment used to claim the read was "one index-only scan of
//! `relay_envelope_group_seq_idx`". It is not, and the correction is worth keeping
//! rather than quietly deleting. That index is `(group_id, seq)` and the query also
//! selects `hash`, which is not in it, so the planner has to visit the heap per row
//! or take the `(group_id, hash)` primary key and sort. `ct` is TOASTed out of line,
//! so the main tuples stay narrow and the visit is cheaper than the column list
//! suggests, but it is a heap visit and the difference is not nothing at a hundred
//! thousand rows. `include (hash)` on the seq index would make the original claim
//! true; whether that is the right change, or whether the whole-group reload should
//! go, is WEALD-210, which wants a measurement on the reference machine first.
//!
//! The cost that made this worth filing is not one read. It is that the read happens
//! on **every** reconciliation round, three to five times per reconnecting client,
//! against a pool of sixteen connections, so a relay restart turns it into a herd.

use sqlx::{PgPool, Row};

use crate::envelope::{Encryption, Envelope};
use crate::negentropy::Item;

/// The most items one reconciliation round will load for a group.
///
/// A million, which at 40 bytes a row is 40 MB and covers a corpus far past
/// anything `specs/backend/build/local-harness.md` describes. A group past it
/// reconciles over its newest million and the older tail is reached by
/// `SUB` with an explicit cursor, which is the case compaction
/// (`specs/backend/relay/lifecycle.md`) is supposed to prevent from ever arising.
pub const MAX_ITEMS_PER_RECONCILE: i64 = 1_000_000;

/// The most envelopes one `SUB` reads before the client is told to reconcile
/// instead.
///
/// A client that has been away long enough to be further behind than this is
/// better served by range reconciliation, which moves what is missing rather than
/// everything after a cursor. The socket sends a smaller batch bounded by its own
/// queue; this database bound prevents an unnecessarily large read before that
/// continuation decision.
pub const MAX_BACKFILL: i64 = 4096;

/// Why a read failed. One variant, because there is one failure: the database.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("envelope log read failed: {reason}")]
pub struct LogError {
    pub reason: String,
}

fn log_error(error: sqlx::Error) -> LogError {
    LogError {
        reason: crate::logging::scrub(&error.to_string()),
    }
}

/// Every `(seq, hash)` the group holds, ascending by `seq`.
pub async fn items(pool: &PgPool, group: &[u8]) -> Result<Vec<Item>, LogError> {
    let rows = sqlx::query(
        "select seq, hash from relay_envelope where group_id = $1 \
         order by seq desc limit $2",
    )
    .bind(group)
    .bind(MAX_ITEMS_PER_RECONCILE)
    .fetch_all(pool)
    .await
    .map_err(log_error)?;

    // Newest first out of the database so the bound keeps the newest window, then
    // reversed: everything downstream binary-searches this slice and needs it
    // ascending.
    let mut items: Vec<Item> = rows.iter().map(row_to_item).collect();
    items.reverse();
    Ok(items)
}

fn row_to_item(row: &sqlx::postgres::PgRow) -> Item {
    let seq: i64 = row.get("seq");
    let hash: Vec<u8> = row.get("hash");
    Item {
        // `seq` is `bigint not null` with a `>= 1` constraint, and `hash` is
        // `bytea` with a 32 byte constraint, both enforced by the schema. The
        // conversions are written as saturating rather than fallible so there is no
        // arm here that only a corrupted database could reach: a truncated hash
        // would fail its own constraint on the way in.
        seq: u64::try_from(seq).unwrap_or_default(),
        id: crate::negentropy::id_from_slice(&hash),
    }
}

/// One envelope, whole, by group and content address.
///
/// Returns the encoded bytes rather than the struct: every caller is about to put
/// it in a `PUSH` frame, and re-encoding at each call site would be one more place
/// for the canonical encoding to drift.
pub async fn envelope_bytes(
    pool: &PgPool,
    group: &[u8],
    hash: &[u8],
) -> Result<Option<Vec<u8>>, LogError> {
    let row = sqlx::query(
        "select v, enc, epoch, seq, ts, ct from relay_envelope \
         where group_id = $1 and hash = $2",
    )
    .bind(group)
    .bind(hash)
    .fetch_optional(pool)
    .await
    .map_err(log_error)?;
    Ok(row.map(|row| encode_row(&row, group, hash)))
}

/// Several envelopes by content address, skipping any that are no longer there.
///
/// The skip is the interesting part and it is why this is a function rather than a
/// loop at the call site: an id can disappear between the item read that named it
/// and the fetch, because compaction (`specs/backend/relay/lifecycle.md`) may have
/// removed it. The honest answer is to serve what is still there. The next
/// reconciliation round agrees, because the client is reconciling against what the
/// relay holds now rather than against what it held a moment ago.
///
/// One query, not one per id. The predicate is `hash = any($2)` against the
/// `(group_id, hash)` primary key, so the database does the same index probes it
/// did as a loop and the round trips collapse to one. That matters because the
/// caller is bounded by `SYNC_PUSH_LIMIT` (255) and every one of those round trips
/// held a slot in a pool of sixteen for its whole latency.
///
/// The returned order is the caller's `ids` order, restored here rather than asked
/// of the database: `any()` says nothing about the order rows come back in, and the
/// resulting `PUSH` sequence is recorded in the reconciliation vectors.
pub async fn envelopes_for(
    pool: &PgPool,
    group: &[u8],
    ids: &[crate::negentropy::Id],
) -> Result<Vec<(crate::negentropy::Id, Vec<u8>)>, LogError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let wanted: Vec<Vec<u8>> = ids.iter().map(|id| id.to_vec()).collect();
    let rows = sqlx::query(
        "select v, enc, epoch, seq, ts, ct, hash from relay_envelope \
         where group_id = $1 and hash = any($2)",
    )
    .bind(group)
    .bind(&wanted)
    .fetch_all(pool)
    .await
    .map_err(log_error)?;

    let mut found: std::collections::HashMap<crate::negentropy::Id, Vec<u8>> =
        std::collections::HashMap::with_capacity(rows.len());
    for row in &rows {
        let hash: Vec<u8> = row.get("hash");
        found.insert(
            crate::negentropy::id_from_slice(&hash),
            encode_row(row, group, &hash),
        );
    }

    // Ids the query did not answer for are the ones compaction removed between the
    // item read and now, and they are skipped: the whole point of the doc comment
    // above.
    //
    // `remove` rather than `get`, for two reasons. It avoids cloning every envelope
    // out of the map, which at a megabyte apiece is the cost this change exists to
    // remove. And it means a repeated id yields one envelope rather than the two the
    // per-id loop would have served. That is a deliberate difference and not one any
    // caller can observe: `response.push` is a `BTreeSet`
    // (`negentropy/reconcile.rs:147`), so the only caller cannot present a duplicate,
    // and serving the same envelope twice was never useful.
    Ok(ids
        .iter()
        .filter_map(|id| found.remove(id).map(|envelope| (*id, envelope)))
        .collect())
}

/// Envelopes at or after a cursor, ascending, bounded by ``MAX_BACKFILL``.
///
/// Ascending because a client applying a backfill wants the oldest first: its
/// author-chain check is cheaper when links arrive in the order they were written,
/// even though the CRDT layer above does not care.
pub async fn since(pool: &PgPool, group: &[u8], from_seq: u64) -> Result<Vec<Vec<u8>>, LogError> {
    let rows = sqlx::query(
        "select v, enc, epoch, seq, ts, ct, hash from relay_envelope \
         where group_id = $1 and seq >= $2 order by seq asc limit $3",
    )
    .bind(group)
    .bind(i64::try_from(from_seq).unwrap_or(i64::MAX))
    .bind(MAX_BACKFILL)
    .fetch_all(pool)
    .await
    .map_err(log_error)?;
    Ok(rows
        .iter()
        .map(|row| {
            let hash: Vec<u8> = row.get("hash");
            encode_row(row, group, &hash)
        })
        .collect())
}

/// One row, as the envelope bytes the wire carries.
///
/// `seq` and `ts` are the relay's own, filled in here, which is exactly what
/// `wire.md` says they are: assigned on accept and advisory afterwards. The
/// content address is untouched by both, which is why a pushed envelope's hash
/// still verifies on the client.
fn encode_row(row: &sqlx::postgres::PgRow, group: &[u8], hash: &[u8]) -> Vec<u8> {
    let v: i16 = row.get("v");
    let enc: i16 = row.get("enc");
    let epoch: i64 = row.get("epoch");
    let seq: i64 = row.get("seq");
    let ts: i64 = row.get("ts");
    let ct: Vec<u8> = row.get("ct");
    Envelope {
        // The schema constrains `v = 1` and `enc in (0, 1)`, so both conversions
        // are total against any row the database will hold. Written without a
        // failure arm for the same reason `row_to_item` is: an arm reachable only
        // from a corrupted database is an arm no test can reach honestly.
        v: u8::try_from(v).unwrap_or(crate::envelope::VERSION),
        enc: Encryption::from_u8(u8::try_from(enc).unwrap_or_default()).unwrap_or(Encryption::None),
        group: group.to_vec(),
        epoch: u64::try_from(epoch).unwrap_or_default(),
        seq: u64::try_from(seq).unwrap_or_default(),
        ts: u64::try_from(ts).unwrap_or_default(),
        hash: hash.to_vec(),
        ct,
    }
    .encode()
}
