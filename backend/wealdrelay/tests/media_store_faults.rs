// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! What the media store answers when the database cannot answer it.
//!
//! `tests/media_store.rs` proves quota, reservations and multipart sessions right
//! when Postgres works. This file proves them right when Postgres does not, and
//! that half is where the money and the attachments are. Every statement behind a
//! reservation has a failure path and only one answer on it is safe:
//! `StoreError::Database`, never a verdict, never a panic, never a success.
//!
//! The stakes are the ones `specs/backend/relay/media.md` states:
//!
//! - A reservation reported as `Active` whose row did not land is a presigned
//!   upload URL against quota nobody charged, which is the one thing the
//!   reservation exists to prevent.
//! - A `claim` reported as done that did not commit is a blob whose bytes are
//!   still filed as reserved, and whose lifecycle clock was never set. The relay
//!   uses "its immutable receipt time for the blob's first accepted manifest
//!   claim", so a claim that did not land is a blob with no clock at all.
//! - A `release` or a `finish_deletion` reported as done that did not commit is
//!   reclaimed bytes that were never reclaimed. That number is billed and it is
//!   what an operator reads to decide whether a workspace is out of room.
//! - A read that failed must never read as an empty answer. `finalized_reservations`
//!   and `claimed_hashes` are the collector's candidate lists, and "I could not
//!   find out" treated as "nothing objects" is how a database blip deletes
//!   somebody's attachments.
//!
//! Nothing here is a mock. Every fault is a real state of a real Postgres in a
//! database of this test's own: a nulled column, a retyped one, a domain over a
//! built-in type, a trigger that refuses a write, a deferred constraint that fires
//! at commit, a closed pool. Faults are injected one statement at a time, because
//! a function whose first statement fails never reaches its third, and "the store
//! handles database errors" proven on the first statement is nothing said about
//! the fourth.

mod support;

use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::media::store::{self, Reserved, StoreError};

use support::{config_for, Running, Scratch};

const WORKSPACE: &str = "ws-media";
/// `decode(repeat('51', 32), 'hex')` in the injected SQL below.
const GROUP_BYTE: u8 = 0x51;
/// `decode(repeat('a1', 32), 'hex')`.
const HASH_BYTE: u8 = 0xa1;
const TTL: i64 = 900;

fn group() -> Vec<u8> {
    vec![GROUP_BYTE; 32]
}

fn hash() -> Vec<u8> {
    vec![HASH_BYTE; 32]
}

async fn prepared(label: &str) -> (Scratch, tempfile::TempDir, Arc<RelayState>) {
    let scratch = Scratch::new(label).await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(1)).await;
    let state = Arc::clone(&relay.state);
    relay.shutdown().await;
    (scratch, blobs, state)
}

/// The same, with the workspace's quota row already there, which is the state
/// every reservation is taken against.
async fn with_quota(label: &str) -> (Scratch, tempfile::TempDir, Arc<RelayState>) {
    let (scratch, blobs, state) = prepared(label).await;
    store::ensure_quota_row(pool_of(&state), WORKSPACE, None)
        .await
        .expect("a quota row");
    (scratch, blobs, state)
}

fn pool_of(state: &Arc<RelayState>) -> &PgPool {
    state.database.as_ref().expect("a database").pool()
}

/// A second pool, opened after an injected schema change.
///
/// Retyping a column invalidates Postgres's cached plan for a statement already
/// prepared on a connection, and the failure then arrives from the query rather
/// than from the decode of its answer. A connection that has never seen the old
/// shape prepares against the new one, which is how a retyped column reaches the
/// reader as the decode failure it is meant to be.
async fn fresh_pool(scratch: &Scratch) -> PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&scratch.url)
        .await
        .expect("a pool against the injected schema")
}

// MARK: Injecting faults

/// Run one statement of injected database state, and insist that it landed.
///
/// An injection that silently failed would leave a test that proves the happy path
/// twice, which is worse than no test: it would report the fault path as covered.
async fn inject(pool: &PgPool, statement: &str) {
    if let Err(error) = sqlx::query(statement).execute(pool).await {
        panic!("the injected database state must land: {statement}: {error}");
    }
}

async fn inject_all(pool: &PgPool, statements: &[&str]) {
    for statement in statements {
        inject(pool, statement).await;
    }
}

/// A trigger function that refuses whatever write it is attached to.
async fn refusing_function(pool: &PgPool) {
    inject(
        pool,
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected: this write cannot land'; end $$",
    )
    .await;
}

/// Refuse one statement class against one table, leaving reads of it alone.
///
/// Statement level rather than row level, because an `update` that matches no row
/// fires no row trigger and this store has updates and deletes that legitimately
/// match none.
async fn refuse_statements(pool: &PgPool, table: &str, event: &str) {
    refusing_function(pool).await;
    inject(
        pool,
        &format!(
            "create trigger weald_injected_{event} before {event} on {table} \
             for each statement execute function weald_injected_refusal()"
        ),
    )
    .await;
}

/// Always paired with `refuse_statements`. A trigger left installed is not this
/// test's fault any more, it is the next case's, and that is a bug that reads as a
/// pass.
async fn stop_refusing(pool: &PgPool, table: &str, event: &str) {
    inject(
        pool,
        &format!("drop trigger weald_injected_{event} on {table}"),
    )
    .await;
}

/// Let every statement succeed and make the commit fail, which is what a deferred
/// constraint does and what a database at the end of its disk does.
///
/// Statement level on the way in and deferred on the way out: the trigger on
/// `table` queues a row into a table whose own constraint trigger is deferred to
/// commit time and refuses it there. Statement level matters because the three
/// functions that release bytes all have a path where their first statement
/// matches no row at all, and that path still has to commit.
async fn commit_fails_after(pool: &PgPool, table: &str, event: &str) {
    refusing_function(pool).await;
    inject_all(
        pool,
        &[
            "create table if not exists weald_injected_deferred (id int)",
            "drop trigger if exists weald_injected_at_commit on weald_injected_deferred",
            "create constraint trigger weald_injected_at_commit \
             after insert on weald_injected_deferred \
             deferrable initially deferred for each row \
             execute function weald_injected_refusal()",
            "create or replace function weald_injected_queue() returns trigger \
             language plpgsql as $$ \
             begin insert into weald_injected_deferred values (1); return null; end $$",
        ],
    )
    .await;
    inject(
        pool,
        &format!(
            "create trigger weald_injected_commit_{event} before {event} on {table} \
             for each statement execute function weald_injected_queue()"
        ),
    )
    .await;
}

async fn stop_failing_the_commit(pool: &PgPool, table: &str, event: &str) {
    inject(
        pool,
        &format!("drop trigger weald_injected_commit_{event} on {table}"),
    )
    .await;
}

/// A column that answers the question it is filtered by and is then not there to
/// be read.
///
/// Some columns cannot simply be nulled: the reader finds its row *by* them, so a
/// null row is a row the query never returns and the decode is never reached. The
/// state that does reach it is a relation whose column does not answer the same way
/// twice, which is what a view over a function that lies about being `stable` is.
/// Contrived as a cause and ordinary as an effect: the reader is handed a row whose
/// column it cannot read, which is the only thing it is being asked about, and
/// answering anything but `Database` there would be a hash, a session or a
/// reservation invented out of a failed read.
async fn install_fading(pool: &PgPool) {
    let fading = |name: &str, kind: &str| {
        format!(
            "create or replace function weald_injected_fading_{name}(v {kind}) returns {kind} \
             language plpgsql stable as $$ begin \
             if nextval('weald_injected_calls') = 1 then return v; else return null; end if; \
             end $$"
        )
    };
    inject(pool, "create sequence if not exists weald_injected_calls").await;
    for (name, kind) in [("time", "timestamptz"), ("bytes", "bytea"), ("id", "uuid")] {
        inject(pool, &fading(name, kind)).await;
    }
}

/// Always before a call that reads through a fading column, because the count is
/// per query and not per test.
async fn rewind_fading(pool: &PgPool) {
    inject(pool, "alter sequence weald_injected_calls restart").await;
}

/// One reservation row, written directly rather than through `reserve`, so the
/// test decides exactly which column is unreadable.
async fn seed_reservation(pool: &PgPool, columns: &str, values: &str) -> Uuid {
    let id = Uuid::new_v4();
    inject(
        pool,
        &format!(
            "insert into relay_blob_reservation \
             (reservation_id, workspace_id, group_id, blob_hash, bytes, expires_at{columns}) \
             values ('{id}', '{WORKSPACE}', decode(repeat('51', 32), 'hex'), \
                     decode(repeat('a1', 32), 'hex'), 100, now() + interval '1 hour'{values})"
        ),
    )
    .await;
    id
}

/// The one correct answer on every fault path.
///
/// Named as a claim rather than as a matcher: a store that could not read or write
/// its own accounting may not answer a number, because every number it returns is
/// either charged to somebody or read as permission to delete.
#[track_caller]
fn is_told_to_come_back<T>(outcome: Result<T, StoreError>, what: &str) {
    match outcome {
        Err(StoreError::Database(_)) => {}
        Ok(_) => panic!(
            "{what}: a store that could not reach its accounting must answer come back, \
             and answered as though it had"
        ),
    }
}

// MARK: A database that is not there at all

#[tokio::test]
async fn a_closed_pool_answers_come_back_on_every_entry_point() {
    // A relay shutting down, from inside a request that arrived a moment too early.
    // Every entry point is called, because this is the one fault that reaches all of
    // them, and every one has to answer the same way. `reserve`, `claim`, `release`
    // and `finish_deletion` cannot even open their transaction here, which is the
    // earliest any of them can fail and the only place a failure costs nothing.
    let (scratch, _blobs, state) = with_quota("mediafault_closed").await;
    let pool = pool_of(&state).clone();
    let session = Uuid::new_v4();
    let reservation = Uuid::new_v4();
    pool.close().await;

    is_told_to_come_back(
        store::ensure_quota_row(&pool, WORKSPACE, None).await,
        "ensure_quota_row",
    );
    is_told_to_come_back(store::usage(&pool, WORKSPACE).await, "usage");
    is_told_to_come_back(
        store::reserve(&pool, WORKSPACE, &group(), &hash(), 10, false, TTL).await,
        "reserve",
    );
    is_told_to_come_back(
        store::find_active_reservation(&pool, WORKSPACE, &group(), &hash()).await,
        "find_active_reservation",
    );
    is_told_to_come_back(
        store::claim(&pool, WORKSPACE, &group(), &hash()).await,
        "claim",
    );
    is_told_to_come_back(
        store::release(&pool, WORKSPACE, reservation).await,
        "release",
    );
    is_told_to_come_back(
        store::finish_deletion(&pool, WORKSPACE, reservation).await,
        "finish_deletion",
    );
    is_told_to_come_back(
        store::finalized_reservations(&pool, WORKSPACE, &group()).await,
        "finalized_reservations",
    );
    is_told_to_come_back(store::stale_unclaimed(&pool, 60).await, "stale_unclaimed");
    is_told_to_come_back(
        store::claimed_hashes(&pool, WORKSPACE, &group()).await,
        "claimed_hashes",
    );
    is_told_to_come_back(
        store::create_multipart(&pool, reservation, "upload", 1024, TTL).await,
        "create_multipart",
    );
    is_told_to_come_back(
        store::find_multipart(&pool, session).await,
        "find_multipart",
    );
    is_told_to_come_back(
        store::record_part(&pool, session, 1, 1024).await,
        "record_part",
    );
    is_told_to_come_back(
        store::expected_len_of(&pool, session, 1).await,
        "expected_len_of",
    );
    is_told_to_come_back(
        store::complete_multipart(&pool, session).await,
        "complete_multipart",
    );
    is_told_to_come_back(
        store::abort_multipart(&pool, session).await,
        "abort_multipart",
    );
    is_told_to_come_back(
        store::stale_multipart_sessions(&pool).await,
        "stale_multipart_sessions",
    );

    scratch.drop_database().await;
}

// MARK: The quota row

#[tokio::test]
async fn a_quota_row_the_relay_cannot_read_is_never_a_workspace_with_room() {
    // `usage` is what an operator reads and what the reservation path locks. Every
    // one of its three columns fails dangerously if defaulted: stored or reserved
    // bytes read as zero would hand a full workspace unlimited room, and a limit
    // read as absent means unlimited, which is the same mistake with the plan
    // removed. The same three columns are read again under `select ... for update`
    // inside `reserve`, where the answer decides whether a presigned URL is issued
    // at all, so each is broken for both readers at once.
    let (scratch, _blobs, state) = with_quota("mediafault_quota_read").await;
    let pool = pool_of(&state);

    inject_all(
        pool,
        &[
            "alter table relay_quota drop constraint relay_quota_stored_not_negative",
            "alter table relay_quota drop constraint relay_quota_reserved_not_negative",
            "alter table relay_quota alter column stored_bytes drop not null",
            "alter table relay_quota alter column reserved_bytes drop not null",
        ],
    )
    .await;

    for (what, column) in [
        ("no stored total", "stored_bytes"),
        ("no reserved total", "reserved_bytes"),
    ] {
        inject(
            pool,
            &format!("update relay_quota set {column} = null where workspace_id = '{WORKSPACE}'"),
        )
        .await;
        is_told_to_come_back(
            store::usage(pool, WORKSPACE).await,
            &format!("usage against a quota row with {what}"),
        );
        is_told_to_come_back(
            store::reserve(pool, WORKSPACE, &group(), &hash(), 10, false, TTL).await,
            &format!("reserve against a quota row with {what}"),
        );
        inject(
            pool,
            &format!("update relay_quota set {column} = 0 where workspace_id = '{WORKSPACE}'"),
        )
        .await;
    }

    // The limit, which is nullable by design: a null is "unlimited" and needs no
    // decoding, so the unreadable case for this column is a value that is not a
    // number at all. That is what a schema drifted under a running relay looks
    // like, and a plan the relay cannot read must not read as no plan.
    inject_all(
        pool,
        &[
            &format!(
                "update relay_quota set limit_bytes = 4096 where workspace_id = '{WORKSPACE}'"
            ),
            "alter table relay_quota alter column limit_bytes type text \
             using limit_bytes::text",
        ],
    )
    .await;
    let fresh = fresh_pool(&scratch).await;
    is_told_to_come_back(
        store::usage(&fresh, WORKSPACE).await,
        "usage against a limit that is not a number",
    );
    is_told_to_come_back(
        store::reserve(&fresh, WORKSPACE, &group(), &hash(), 10, false, TTL).await,
        "reserve against a limit that is not a number",
    );

    // And the whole row gone from under the reader, which is a workspace whose
    // quota table no longer has the column the accounting is kept in.
    inject(&fresh, "alter table relay_quota drop column stored_bytes").await;
    let after = fresh_pool(&scratch).await;
    is_told_to_come_back(
        store::usage(&after, WORKSPACE).await,
        "usage against a quota table with no stored total",
    );
    fresh.close().await;
    after.close().await;

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_reservation_against_a_workspace_with_no_quota_row_is_refused_rather_than_granted() {
    // `reserve` locks the workspace's quota row with `select ... for update` and
    // reads exactly one row, because every decision it makes needs that row's
    // totals. A workspace with no row is a workspace the relay was never told the
    // plan for, and the safe answer is not "unlimited": it is to refuse and let the
    // caller find out why.
    let (scratch, _blobs, state) = prepared("mediafault_no_quota_row").await;
    let pool = pool_of(&state);

    is_told_to_come_back(
        store::reserve(pool, WORKSPACE, &group(), &hash(), 10, false, TTL).await,
        "reserve with no quota row to lock",
    );

    scratch.drop_database().await;
}

// MARK: The reservation transaction

#[tokio::test]
async fn an_in_flight_reservation_the_relay_cannot_refresh_is_never_reported_as_active() {
    // A second `reserve` for an object already reserved is an upload being retried,
    // and it refreshes the existing reservation rather than taking a second helping
    // of quota. Three ways that refresh fails, in the order the function meets them:
    // the lookup that finds the in-flight row, the update that extends it, and the
    // commit. `Active` returned over any of them would hand the client a
    // reservation id whose expiry is whatever it already was, so the upload URL
    // would be issued against a reservation that expires under it.
    let (scratch, _blobs, state) = with_quota("mediafault_refresh").await;
    let pool = pool_of(&state);
    let first = store::reserve(pool, WORKSPACE, &group(), &hash(), 10, false, TTL)
        .await
        .unwrap();
    assert!(matches!(first, Reserved::Active { .. }));

    // The update that extends the expiry.
    refuse_statements(pool, "relay_blob_reservation", "update").await;
    is_told_to_come_back(
        store::reserve(pool, WORKSPACE, &group(), &hash(), 10, false, TTL).await,
        "a refresh the database will not take",
    );
    stop_refusing(pool, "relay_blob_reservation", "update").await;

    // The commit after it.
    commit_fails_after(pool, "relay_blob_reservation", "update").await;
    is_told_to_come_back(
        store::reserve(pool, WORKSPACE, &group(), &hash(), 10, false, TTL).await,
        "a refresh that cannot commit",
    );
    stop_failing_the_commit(pool, "relay_blob_reservation", "update").await;

    // The reservation is unchanged and still refreshable, which is the claim: the
    // transaction rolled back rather than half applying.
    assert!(matches!(
        store::reserve(pool, WORKSPACE, &group(), &hash(), 10, false, TTL)
            .await
            .unwrap(),
        Reserved::Active { .. }
    ));

    // The identifier of the row it found. `not null` in the schema and the reader
    // has no branch for a null, which is right only if a row it cannot read is
    // refused: a reservation id read as anything else is an upload URL bound to a
    // reservation that does not exist.
    inject_all(
        pool,
        &[
            "delete from relay_blob_reservation",
            "alter table relay_blob_reservation \
             drop constraint relay_blob_reservation_pkey cascade",
            "alter table relay_blob_reservation alter column reservation_id drop not null",
            "insert into relay_blob_reservation \
             (reservation_id, workspace_id, group_id, blob_hash, bytes, expires_at) \
             values (null, 'ws-media', decode(repeat('51', 32), 'hex'), \
                     decode(repeat('a1', 32), 'hex'), 100, now() + interval '1 hour')",
        ],
    )
    .await;
    is_told_to_come_back(
        store::reserve(pool, WORKSPACE, &group(), &hash(), 10, false, TTL).await,
        "an in-flight reservation with no identifier",
    );

    // And the lookup itself, against a table that no longer has the column the
    // in-flight test is made of.
    inject(
        pool,
        "alter table relay_blob_reservation drop column finalized_at cascade",
    )
    .await;
    is_told_to_come_back(
        store::reserve(pool, WORKSPACE, &group(), &hash(), 10, false, TTL).await,
        "a lookup for an in-flight reservation that cannot run",
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_reservation_whose_accounting_does_not_land_is_never_reported_as_active() {
    // The two writes a fresh reservation makes after its row: the quota row's
    // reserved total, and the commit that makes both durable. `Active` is the answer
    // that causes a presigned PUT URL to be issued, so `Active` over an uncharged
    // reservation is exactly the state `media.md`'s quota section exists to prevent:
    // bytes uploaded against a plan that never counted them.
    let (scratch, _blobs, state) = with_quota("mediafault_reserve_write").await;
    let pool = pool_of(&state);

    refuse_statements(pool, "relay_quota", "update").await;
    is_told_to_come_back(
        store::reserve(pool, WORKSPACE, &group(), &hash(), 10, false, TTL).await,
        "a reservation whose bytes cannot be charged",
    );
    stop_refusing(pool, "relay_quota", "update").await;
    assert_eq!(
        store::usage(pool, WORKSPACE).await.unwrap().reserved_bytes,
        0,
        "a refused reservation charged the workspace anyway"
    );

    commit_fails_after(pool, "relay_blob_reservation", "insert").await;
    is_told_to_come_back(
        store::reserve(pool, WORKSPACE, &group(), &hash(), 10, false, TTL).await,
        "a reservation that cannot commit",
    );
    stop_failing_the_commit(pool, "relay_blob_reservation", "insert").await;

    let rows: i64 = sqlx::query_scalar("select count(*) from relay_blob_reservation")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(rows, 0, "a reservation that did not commit left a row");
    assert_eq!(
        store::usage(pool, WORKSPACE).await.unwrap().reserved_bytes,
        0,
        "a reservation that did not commit charged the workspace"
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_reservation_row_the_relay_cannot_read_is_not_a_reservation() {
    // What `find_active_reservation` answers decides whether a PUT is a fresh
    // upload, a retry, or an already-stored object. Its three stored columns are
    // `not null` in the schema and the reader has no branch for a null, which is
    // the right shape only if the row it cannot read is refused rather than
    // defaulted: a byte count read as zero would charge nothing for the upload, and
    // a hash read as empty would answer about the wrong object entirely.
    let (scratch, _blobs, state) = with_quota("mediafault_reservation_read").await;
    let pool = pool_of(&state);

    inject_all(
        pool,
        &[
            "alter table relay_blob_reservation \
             drop constraint relay_blob_reservation_pkey cascade",
            "alter table relay_blob_reservation \
             drop constraint relay_blob_reservation_bytes_positive",
            "alter table relay_blob_reservation alter column reservation_id drop not null",
            "alter table relay_blob_reservation alter column bytes drop not null",
        ],
    )
    .await;

    for (what, column) in [
        ("no identifier", "reservation_id"),
        ("no byte count", "bytes"),
    ] {
        seed_reservation(pool, "", "").await;
        inject(
            pool,
            &format!("update relay_blob_reservation set {column} = null"),
        )
        .await;
        is_told_to_come_back(
            store::find_active_reservation(pool, WORKSPACE, &group(), &hash()).await,
            &format!("a reservation with {what}"),
        );
        inject(pool, "delete from relay_blob_reservation").await;
    }

    // The hash cannot be nulled and still be found, because the lookup is by hash:
    // a null hash is a row this query never returns. The state that does reach the
    // decode is a hash that answers the lookup and is then unreadable, and the
    // answer must not be a reservation whose hash the relay made up. The object key
    // a delete or a presigned URL is built on is that hash.
    seed_reservation(pool, "", "").await;
    install_fading(pool).await;
    inject_all(
        pool,
        &[
            "alter table relay_blob_reservation rename to weald_injected_reservation_rows",
            "create view relay_blob_reservation as \
             select reservation_id, workspace_id, group_id, \
                    weald_injected_fading_bytes(blob_hash) as blob_hash, bytes, created_at, \
                    expires_at, finalized_at \
             from weald_injected_reservation_rows",
        ],
    )
    .await;
    rewind_fading(pool).await;
    let fresh = fresh_pool(&scratch).await;
    is_told_to_come_back(
        store::find_active_reservation(&fresh, WORKSPACE, &group(), &hash()).await,
        "a reservation whose hash is not bytes",
    );
    fresh.close().await;

    scratch.drop_database().await;
}

// MARK: The claim, which is the one moment a blob's clock is set

#[tokio::test]
async fn a_claim_that_does_not_commit_is_never_reported_as_a_claim() {
    // `claim` is called when a valid retention manifest first names a hash, and it
    // is the only place a blob's lifecycle clock is set. Reported as done when it
    // did not land, the manifest reads as accepted while the blob it claimed stays
    // unclaimed: its bytes are still filed as reserved, the 24-hour unclaimed-upload
    // collector will eventually delete the object out from under a manifest that
    // names it, and nothing anywhere records that the group ever asked to keep it.
    //
    // Four failures, in the order `claim` meets them: the byte count returned by the
    // finalizing update, the quota update that moves those bytes, the commit after
    // it, and the commit on the path where the update matched no row at all.
    let (scratch, _blobs, state) = with_quota("mediafault_claim").await;
    let pool = pool_of(&state);

    // A claim that matches nothing still commits, and that commit can still fail.
    // A second manifest naming an already-claimed hash takes this path, and `false`
    // is the answer that says "already claimed, nothing to do": answering it over a
    // failed commit would be a guess about a transaction whose fate is unknown.
    commit_fails_after(pool, "relay_blob_reservation", "update").await;
    is_told_to_come_back(
        store::claim(pool, WORKSPACE, &group(), &hash()).await,
        "a claim that matched nothing and could not commit",
    );
    stop_failing_the_commit(pool, "relay_blob_reservation", "update").await;

    inject_all(
        pool,
        &[
            "alter table relay_blob_reservation \
             drop constraint relay_blob_reservation_bytes_positive",
            "alter table relay_blob_reservation alter column bytes drop not null",
        ],
    )
    .await;
    seed_reservation(pool, "", "").await;
    inject(pool, "update relay_blob_reservation set bytes = null").await;
    is_told_to_come_back(
        store::claim(pool, WORKSPACE, &group(), &hash()).await,
        "a claim whose byte count cannot be read",
    );
    // The finalizing update rolled back with the transaction, so the reservation is
    // still unclaimed rather than half claimed.
    let finalized: i64 = sqlx::query_scalar(
        "select count(*) from relay_blob_reservation where finalized_at is not null",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(finalized, 0, "a failed claim finalized the reservation");

    inject(pool, "update relay_blob_reservation set bytes = 100").await;
    refuse_statements(pool, "relay_quota", "update").await;
    is_told_to_come_back(
        store::claim(pool, WORKSPACE, &group(), &hash()).await,
        "a claim whose bytes cannot move from reserved to stored",
    );
    stop_refusing(pool, "relay_quota", "update").await;

    commit_fails_after(pool, "relay_quota", "update").await;
    is_told_to_come_back(
        store::claim(pool, WORKSPACE, &group(), &hash()).await,
        "a claim that cannot commit",
    );
    stop_failing_the_commit(pool, "relay_quota", "update").await;

    // Nothing was claimed and nothing was charged, and the claim still works once
    // the database will take it.
    assert_eq!(store::usage(pool, WORKSPACE).await.unwrap().stored_bytes, 0);
    assert!(store::claim(pool, WORKSPACE, &group(), &hash())
        .await
        .unwrap());

    scratch.drop_database().await;
}

// MARK: Giving bytes back, which is the number an operator is billed by

#[tokio::test]
async fn a_release_that_does_not_commit_is_never_reported_as_reclaimed_bytes() {
    // `release` answers with the number of bytes it gave back, and that number is
    // the workspace's headroom: it is what the next reservation is checked against
    // and what an operator reads to decide whether a workspace is out of room.
    // Reported over a transaction that did not commit, the bytes stay charged
    // forever and no later call will ever release them again, because the row it
    // would have deleted is still there and still unfinalized.
    let (scratch, _blobs, state) = with_quota("mediafault_release").await;
    let pool = pool_of(&state);

    // The commit on the path where the delete matched nothing: an abort for a
    // reservation somebody else already released. `None` says "there was nothing to
    // give back", which is a claim about the database, not a fallback for one that
    // did not answer.
    commit_fails_after(pool, "relay_blob_reservation", "delete").await;
    is_told_to_come_back(
        store::release(pool, WORKSPACE, Uuid::new_v4()).await,
        "a release that matched nothing and could not commit",
    );
    stop_failing_the_commit(pool, "relay_blob_reservation", "delete").await;

    inject_all(
        pool,
        &[
            "alter table relay_blob_reservation \
             drop constraint relay_blob_reservation_bytes_positive",
            "alter table relay_blob_reservation alter column bytes drop not null",
        ],
    )
    .await;
    let reservation = seed_reservation(pool, "", "").await;
    inject(pool, "update relay_blob_reservation set bytes = null").await;
    is_told_to_come_back(
        store::release(pool, WORKSPACE, reservation).await,
        "a release whose byte count cannot be read",
    );
    let rows: i64 = sqlx::query_scalar("select count(*) from relay_blob_reservation")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(rows, 1, "a failed release deleted the reservation anyway");

    inject_all(
        pool,
        &[
            "update relay_blob_reservation set bytes = 100",
            &format!(
                "update relay_quota set reserved_bytes = 100 where workspace_id = '{WORKSPACE}'"
            ),
        ],
    )
    .await;
    refuse_statements(pool, "relay_quota", "update").await;
    is_told_to_come_back(
        store::release(pool, WORKSPACE, reservation).await,
        "a release whose bytes cannot be given back",
    );
    stop_refusing(pool, "relay_quota", "update").await;

    commit_fails_after(pool, "relay_quota", "update").await;
    is_told_to_come_back(
        store::release(pool, WORKSPACE, reservation).await,
        "a release that cannot commit",
    );
    stop_failing_the_commit(pool, "relay_quota", "update").await;

    // The bytes are still charged and the row is still there, so the release is
    // still possible: a refusal, not a loss.
    assert_eq!(
        store::usage(pool, WORKSPACE).await.unwrap().reserved_bytes,
        100
    );
    assert_eq!(
        store::release(pool, WORKSPACE, reservation).await.unwrap(),
        Some(100)
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_deletion_whose_accounting_does_not_commit_is_never_reported_as_reclaimed() {
    // `finish_deletion` is called after the object itself has already left storage,
    // so it is the only record that those bytes are gone. Reported as done over a
    // transaction that did not commit, the workspace is billed forever for an object
    // that no longer exists and no sweep will ever correct it, because the sweep
    // works from the reservation rows and this one still says the blob is stored.
    let (scratch, _blobs, state) = with_quota("mediafault_finish").await;
    let pool = pool_of(&state);

    inject_all(
        pool,
        &[
            "alter table relay_blob_reservation \
             drop constraint relay_blob_reservation_bytes_positive",
            "alter table relay_blob_reservation alter column bytes drop not null",
        ],
    )
    .await;
    let reservation = seed_reservation(pool, ", finalized_at", ", now()").await;
    inject(pool, "update relay_blob_reservation set bytes = null").await;
    is_told_to_come_back(
        store::finish_deletion(pool, WORKSPACE, reservation).await,
        "a deletion whose byte count cannot be read",
    );

    inject_all(
        pool,
        &[
            "update relay_blob_reservation set bytes = 100",
            &format!(
                "update relay_quota set stored_bytes = 100 where workspace_id = '{WORKSPACE}'"
            ),
        ],
    )
    .await;
    refuse_statements(pool, "relay_quota", "update").await;
    is_told_to_come_back(
        store::finish_deletion(pool, WORKSPACE, reservation).await,
        "a deletion whose bytes cannot leave the stored total",
    );
    stop_refusing(pool, "relay_quota", "update").await;

    commit_fails_after(pool, "relay_quota", "update").await;
    is_told_to_come_back(
        store::finish_deletion(pool, WORKSPACE, reservation).await,
        "a deletion that cannot commit",
    );
    stop_failing_the_commit(pool, "relay_quota", "update").await;

    assert_eq!(
        store::usage(pool, WORKSPACE).await.unwrap().stored_bytes,
        100,
        "a deletion that did not commit reclaimed bytes anyway"
    );
    store::finish_deletion(pool, WORKSPACE, reservation)
        .await
        .unwrap();
    assert_eq!(store::usage(pool, WORKSPACE).await.unwrap().stored_bytes, 0);

    scratch.drop_database().await;
}

// MARK: The collector's candidate lists

#[tokio::test]
async fn a_claimed_blob_the_relay_cannot_read_is_never_a_candidate_for_deletion() {
    // `finalized_reservations` is the retention collector's candidate list, and the
    // clock it reads is the whole of the grace period: `media.md` says the relay
    // "uses its immutable receipt time for the blob's first accepted manifest
    // claim", and the 30-day floor is measured from it. A claim time read as zero is
    // a blob claimed in 1970, which is due for deletion the instant it is uploaded.
    // A hash or a byte count read as empty would delete the wrong object or
    // mis-account the right one, and a reservation id read as nothing would leave
    // the accounting pointing at no row at all.
    let (scratch, _blobs, state) = with_quota("mediafault_finalized_read").await;
    let pool = pool_of(&state);

    inject_all(
        pool,
        &[
            "alter table relay_blob_reservation \
             drop constraint relay_blob_reservation_pkey cascade",
            "alter table relay_blob_reservation \
             drop constraint relay_blob_reservation_bytes_positive",
            "alter table relay_blob_reservation alter column reservation_id drop not null",
            "alter table relay_blob_reservation alter column blob_hash drop not null",
            "alter table relay_blob_reservation alter column bytes drop not null",
        ],
    )
    .await;

    for (what, column) in [
        ("no identifier", "reservation_id"),
        ("no hash", "blob_hash"),
        ("no byte count", "bytes"),
    ] {
        seed_reservation(pool, ", finalized_at", ", now()").await;
        inject(
            pool,
            &format!("update relay_blob_reservation set {column} = null"),
        )
        .await;
        is_told_to_come_back(
            store::finalized_reservations(pool, WORKSPACE, &group()).await,
            &format!("a claimed blob with {what}"),
        );
        inject(pool, "delete from relay_blob_reservation").await;
    }

    // The claim time itself, which cannot be nulled and still be selected: the query
    // asks only for rows whose claim time is set. The state that produces one is a
    // column whose value answers the filter and then is not there to be read, which
    // is what a view over a function that does not answer the same way twice is. The
    // point is the reader's: a candidate list that could not read a clock must not
    // be a candidate list.
    install_fading(pool).await;
    inject_all(
        pool,
        &[
            "alter table relay_blob_reservation rename to weald_injected_reservation_rows",
            "create view relay_blob_reservation as \
             select reservation_id, workspace_id, group_id, blob_hash, bytes, created_at, \
                    expires_at, weald_injected_fading_time(finalized_at) as finalized_at \
             from weald_injected_reservation_rows",
            "insert into weald_injected_reservation_rows \
             (reservation_id, workspace_id, group_id, blob_hash, bytes, expires_at, finalized_at) \
             values (gen_random_uuid(), 'ws-media', decode(repeat('51', 32), 'hex'), \
                     decode(repeat('a1', 32), 'hex'), 100, now(), now())",
        ],
    )
    .await;
    rewind_fading(pool).await;
    let fresh = fresh_pool(&scratch).await;
    is_told_to_come_back(
        store::finalized_reservations(&fresh, WORKSPACE, &group()).await,
        "a claimed blob whose claim time cannot be read",
    );
    fresh.close().await;

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_stale_reservation_the_relay_cannot_read_is_never_a_candidate_for_release() {
    // The 24-hour unclaimed-upload sweep works from these four columns and deletes
    // an object in storage from them. Every one of them is `not null` in the schema
    // and the reader has no branch for a null, which is right only if a row it
    // cannot read stops the sweep: a workspace, group or hash read as empty is a
    // delete aimed at the wrong key, and a reservation id read as nothing is bytes
    // released against no reservation.
    let (scratch, _blobs, state) = with_quota("mediafault_stale_read").await;
    let pool = pool_of(&state);

    inject_all(
        pool,
        &[
            "alter table relay_blob_reservation \
             drop constraint relay_blob_reservation_pkey cascade",
            "alter table relay_blob_reservation \
             drop constraint relay_blob_reservation_bytes_positive",
            "alter table relay_blob_reservation alter column reservation_id drop not null",
            "alter table relay_blob_reservation alter column workspace_id drop not null",
            "alter table relay_blob_reservation alter column group_id drop not null",
            "alter table relay_blob_reservation alter column blob_hash drop not null",
        ],
    )
    .await;

    for (what, column) in [
        ("no workspace", "workspace_id"),
        ("no group", "group_id"),
        ("no hash", "blob_hash"),
        ("no identifier", "reservation_id"),
    ] {
        seed_reservation(pool, ", created_at", ", now() - interval '2 days'").await;
        inject(
            pool,
            &format!("update relay_blob_reservation set {column} = null"),
        )
        .await;
        is_told_to_come_back(
            store::stale_unclaimed(pool, 60).await,
            &format!("a stale reservation with {what}"),
        );
        inject(pool, "delete from relay_blob_reservation").await;
    }

    scratch.drop_database().await;
}

// MARK: Multipart sessions

#[tokio::test]
async fn a_multipart_session_the_relay_cannot_read_is_never_a_session_it_may_complete() {
    // A session resolves to the reservation it spends, and every column of it is
    // load-bearing: the upload id is what S3 completes against, the part size is
    // what every issued part URL was sized to, and the workspace, group and hash are
    // the object key the assembled blob lands on. A session read with any of them
    // missing would complete an upload against the wrong key or against no
    // reservation, and the byte total is what the workspace is charged when the
    // claim lands.
    let (scratch, _blobs, state) = with_quota("mediafault_multipart_read").await;
    let pool = pool_of(&state);
    let reservation = seed_reservation(pool, "", "").await;
    let session = store::create_multipart(pool, reservation, "an-upload", 5 << 20, TTL)
        .await
        .unwrap();

    inject_all(
        pool,
        &[
            "alter table relay_blob_multipart \
             drop constraint relay_blob_multipart_part_size_positive",
            "alter table relay_blob_multipart alter column upload_id drop not null",
            "alter table relay_blob_multipart alter column part_size drop not null",
            "alter table relay_blob_reservation \
             drop constraint relay_blob_reservation_bytes_positive",
            "alter table relay_blob_reservation alter column workspace_id drop not null",
            "alter table relay_blob_reservation alter column group_id drop not null",
            "alter table relay_blob_reservation alter column blob_hash drop not null",
            "alter table relay_blob_reservation alter column bytes drop not null",
        ],
    )
    .await;

    for (what, table, column) in [
        ("no workspace", "relay_blob_reservation", "workspace_id"),
        ("no group", "relay_blob_reservation", "group_id"),
        ("no hash", "relay_blob_reservation", "blob_hash"),
        ("no upload id", "relay_blob_multipart", "upload_id"),
        ("no part size", "relay_blob_multipart", "part_size"),
        ("no byte total", "relay_blob_reservation", "bytes"),
    ] {
        inject(pool, &format!("update {table} set {column} = null")).await;
        is_told_to_come_back(
            store::find_multipart(pool, session).await,
            &format!("a multipart session with {what}"),
        );
        inject(
            pool,
            &match column {
                "workspace_id" => format!("update {table} set {column} = '{WORKSPACE}'"),
                "group_id" => {
                    format!("update {table} set {column} = decode(repeat('51', 32), 'hex')")
                }
                "blob_hash" => {
                    format!("update {table} set {column} = decode(repeat('a1', 32), 'hex')")
                }
                "upload_id" => format!("update {table} set {column} = 'an-upload'"),
                _ => format!("update {table} set {column} = 100"),
            },
        )
        .await;
    }

    // The two identifiers cannot be nulled and still be found: one is what the
    // session is looked up by and the other is what it is joined to its reservation
    // on, so a null in either is a row this query never returns. Each is instead
    // made to answer its own filter and then be unreadable. A session id invented
    // out of a failed read is a COMPLETE aimed at somebody else's upload, and a
    // reservation id invented out of one is bytes charged to no reservation.
    install_fading(pool).await;
    inject(
        pool,
        "alter table relay_blob_multipart rename to weald_injected_multipart_rows",
    )
    .await;
    for (what, session_column, reservation_column) in [
        (
            "an identifier it cannot read back",
            "weald_injected_fading_id(session_id) as session_id",
            "reservation_id",
        ),
        (
            "a reservation it cannot read back",
            "session_id",
            "weald_injected_fading_id(reservation_id) as reservation_id",
        ),
    ] {
        inject(pool, "drop view if exists relay_blob_multipart").await;
        inject(
            pool,
            &format!(
                "create view relay_blob_multipart as \
                 select {session_column}, {reservation_column}, upload_id, part_size, \
                        created_at, expires_at, completed_at, aborted_at \
                 from weald_injected_multipart_rows"
            ),
        )
        .await;
        rewind_fading(pool).await;
        let fresh = fresh_pool(&scratch).await;
        is_told_to_come_back(
            store::find_multipart(&fresh, session).await,
            &format!("a multipart session with {what}"),
        );
        fresh.close().await;
    }

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_lifecycle_clock_the_relay_cannot_read_is_never_read_as_unset() {
    // Three flags decide three irreversible things: `finalized` decides whether a
    // PUT is a fresh upload or a retry of a stored object, `completed` decides
    // whether a COMPLETE assembles an upload a second time, and `aborted` decides
    // whether parts are still being issued against a session somebody gave up on.
    // Each of them is "this timestamp is set", and each is read from the timestamp
    // rather than from a boolean the query computes, precisely so this fault has
    // somewhere to land: a column that is not the type the reader expects, which is
    // what a half-applied migration or a hand-repaired database leaves behind.
    //
    // The answer on all three is the same and it is the whole point of reading them
    // in Rust: a clock that cannot be read is never `false`. False would mean an
    // upload accepted against a claimed blob, a second assembly of a completed
    // session, and parts issued into an aborted one.
    let (scratch, _blobs, state) = with_quota("mediafault_lifecycle_clock").await;
    let pool = pool_of(&state);
    let reservation = seed_reservation(pool, "", "").await;
    let session = store::create_multipart(pool, reservation, "an-upload", 5 << 20, TTL)
        .await
        .unwrap();

    // The claim clock, read by the lookup a PUT is decided on. Set before it is
    // retyped: a null decodes as "not set" without the reader ever looking at the
    // column's type, which is right (an unclaimed blob has no clock) and is why the
    // fault has to be a clock that is there and is not a time.
    inject_all(
        pool,
        &[
            "update relay_blob_reservation set finalized_at = now()",
            "alter table relay_blob_reservation alter column finalized_at type text \
             using finalized_at::text",
        ],
    )
    .await;
    let fresh = fresh_pool(&scratch).await;
    is_told_to_come_back(
        store::find_active_reservation(&fresh, WORKSPACE, &group(), &hash()).await,
        "a reservation whose claim clock is not a time",
    );
    fresh.close().await;

    // The completion clock and the abort clock, one at a time. Separately, because a
    // reader that stopped at the first unreadable column would leave the second
    // proven by nothing: `completed` is read before `aborted`, so a session whose
    // completion clock is fine and whose abort clock is not is the only state that
    // reaches the second read at all.
    for (what, column) in [
        ("its completion clock", "completed_at"),
        ("its abort clock", "aborted_at"),
    ] {
        let set = format!("update relay_blob_multipart set {column} = now()");
        let retype = format!(
            "alter table relay_blob_multipart alter column {column} type text \
             using {column}::text"
        );
        inject_all(pool, &[set.as_str(), retype.as_str()]).await;
        let fresh = fresh_pool(&scratch).await;
        is_told_to_come_back(
            store::find_multipart(&fresh, session).await,
            &format!("a multipart session the relay cannot read {what} of"),
        );
        fresh.close().await;
        inject(
            pool,
            &format!(
                "alter table relay_blob_multipart alter column {column} type timestamptz \
                 using {column}::timestamptz"
            ),
        )
        .await;
    }

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_stale_multipart_session_the_relay_cannot_read_is_never_swept() {
    // The expiry sweep aborts sessions nobody finished and releases the reservations
    // they hold. Both identifiers it reads are `not null` in the schema and the
    // reader has no branch for a null, which is right only if a row it cannot read
    // stops the sweep: a session id read as nothing aborts no session, and a
    // reservation id read as nothing releases bytes against no reservation while
    // reporting them as released.
    let (scratch, _blobs, state) = with_quota("mediafault_stale_multipart").await;
    let pool = pool_of(&state);
    let reservation = seed_reservation(pool, "", "").await;
    store::create_multipart(pool, reservation, "an-upload", 5 << 20, -60)
        .await
        .unwrap();

    inject_all(
        pool,
        &[
            "alter table relay_blob_multipart \
             drop constraint relay_blob_multipart_pkey cascade",
            "alter table relay_blob_multipart \
             drop constraint relay_blob_multipart_reservation_id_fkey",
            "alter table relay_blob_multipart alter column session_id drop not null",
            "alter table relay_blob_multipart alter column reservation_id drop not null",
        ],
    )
    .await;

    for (what, column) in [
        ("no identifier", "session_id"),
        ("no reservation", "reservation_id"),
    ] {
        inject(
            pool,
            &format!("update relay_blob_multipart set {column} = null"),
        )
        .await;
        is_told_to_come_back(
            store::stale_multipart_sessions(pool).await,
            &format!("a stale session with {what}"),
        );
        inject(
            pool,
            &format!("update relay_blob_multipart set {column} = gen_random_uuid()"),
        )
        .await;
    }

    scratch.drop_database().await;
}
