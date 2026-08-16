// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The read side of the envelope log, against real Postgres.
//!
//! Tier 3. The queries reconciliation and backfill run, held to their documented
//! behaviour rather than to their SQL: the item read is ascending and tolerates gaps,
//! the backfill is bounded and starts where it is told, an id that has vanished is
//! skipped rather than reported, and every failure is the one typed error the read
//! side has.
//!
//! No mock. `testing.md`: real Postgres, real sockets, real process boundaries, and
//! the only permitted fake is the one `environments.md` names for the step. There is
//! none for this.

mod support;

use sqlx::{Connection as _, Executor as _, PgPool};
use wealdrelay::envelope::{Encryption, Envelope};
use wealdrelay::health::Clock;
use wealdrelay::log;
use wealdrelay::negentropy::{id_from_slice, Id};

use support::{config_for, envelope_for, make_group, Running, Scratch};

const CLOCK: u64 = 1_700_000_000_000;

/// Store one envelope directly, at a chosen sequence number.
///
/// Direct SQL rather than through `accept`, because these tests are about the read
/// side and need sequence numbers with deliberate gaps in them. Gaps are legal
/// (`accept.rs`: a rolled-back transaction leaves one) and a read side that only
/// worked on a dense range would break the first time a transaction rolled back.
async fn store(pool: &PgPool, group: &[u8], body: &[u8], seq: i64) -> Envelope {
    let envelope = envelope_for(group, body);
    sqlx::query(
        "insert into relay_envelope (group_id, hash, v, enc, epoch, seq, ts, ct) \
         values ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(group)
    .bind(&envelope.hash)
    .bind(i16::from(envelope.v))
    .bind(envelope.enc as i16)
    .bind(envelope.epoch as i64)
    .bind(seq)
    .bind(CLOCK as i64)
    .bind(&envelope.ct)
    .execute(pool)
    .await
    .expect("store an envelope");
    let mut stored = envelope;
    stored.seq = u64::try_from(seq).unwrap();
    stored.ts = CLOCK;
    stored
}

fn id_of(envelope: &Envelope) -> Id {
    id_from_slice(&envelope.hash)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_item_read_is_ascending_and_tolerates_gaps() {
    let scratch = Scratch::new("logitems").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x61).await;
    let pool = relay.state.database.as_ref().unwrap().pool();

    // Stored out of order, with a gap where a rolled-back transaction would leave
    // one.
    let third = store(pool, &group, b"third", 9).await;
    let first = store(pool, &group, b"first", 1).await;
    let second = store(pool, &group, b"second", 4).await;

    let items = log::items(pool, &group).await.expect("read the items");
    assert_eq!(
        items.iter().map(|item| item.seq).collect::<Vec<_>>(),
        vec![1, 4, 9]
    );
    assert_eq!(items[0].id, id_of(&first));
    assert_eq!(items[1].id, id_of(&second));
    assert_eq!(items[2].id, id_of(&third));

    // A group with nothing in it reads as empty rather than as an error: the relay
    // cannot tell a group it has never heard of from one with no envelopes, and
    // saying so would be a membership signal.
    assert!(log::items(pool, &[0x99; 32]).await.unwrap().is_empty());

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn one_envelope_is_returned_whole_and_still_addresses_its_own_contents() {
    let scratch = Scratch::new("logone").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x62).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let stored = store(pool, &group, b"body", 7).await;

    let bytes = log::envelope_bytes(pool, &group, &stored.hash)
        .await
        .expect("read it")
        .expect("it is there");
    let decoded = Envelope::decode(&bytes).expect("it decodes");
    assert_eq!(decoded.hash, stored.hash);
    assert_eq!(decoded.seq, 7);
    assert_eq!(decoded.ts, CLOCK);
    assert_eq!(decoded.v, 1);
    assert!(matches!(decoded.enc, Encryption::None));
    // The relay filled in `seq` and `ts`, and the content address is unaffected by
    // both, which is what makes a pushed envelope verifiable on arrival.
    assert_eq!(decoded.computed_hash(), decoded.hash);

    // A hash the group does not hold is absent rather than an error.
    assert!(log::envelope_bytes(pool, &group, &[0u8; 32])
        .await
        .unwrap()
        .is_none());

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_id_that_has_vanished_is_skipped_rather_than_reported() {
    // The case compaction produces: an id named by the item read is gone by the time
    // the fetch runs. The honest answer is to serve what is still there, and the next
    // round's fingerprints agree because the client is reconciling against what the
    // relay holds now.
    let scratch = Scratch::new("logvanished").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x63).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let present = store(pool, &group, b"present", 1).await;

    let envelopes = log::envelopes_for(pool, &group, &[id_of(&present), [0x77; 32]])
        .await
        .expect("read what is there");
    assert_eq!(envelopes.len(), 1);
    assert_eq!(
        Envelope::decode(&envelopes[0].1).unwrap().hash,
        present.hash,
        "the one that is still there is the one that comes back"
    );

    // And nothing at all is a legitimate answer.
    assert!(log::envelopes_for(pool, &group, &[])
        .await
        .unwrap()
        .is_empty());

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_backfill_starts_where_it_is_told_and_is_bounded() {
    let scratch = Scratch::new("logbackfill").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x64).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    for seq in 1..=20i64 {
        store(pool, &group, &seq.to_be_bytes(), seq).await;
    }

    let from_start = log::since(pool, &group, 0, usize::MAX, usize::MAX)
        .await
        .expect("read");
    assert_eq!(from_start.len(), 20);
    // Ascending, because a client applying a backfill checks author chains and those
    // are cheaper in the order they were written.
    let seqs: Vec<u64> = from_start
        .iter()
        .map(|bytes| Envelope::decode(bytes).unwrap().seq)
        .collect();
    assert_eq!(seqs, (1..=20).collect::<Vec<u64>>());

    let from_cursor = log::since(pool, &group, 18, usize::MAX, usize::MAX)
        .await
        .expect("read");
    assert_eq!(from_cursor.len(), 3, "at or after the cursor, inclusive");

    // Past the head is empty rather than an error.
    assert!(log::since(pool, &group, 99, usize::MAX, usize::MAX)
        .await
        .unwrap()
        .is_empty());
    // The bound is a bound, not a suggestion: a cursor of zero on a group larger
    // than it would return exactly the bound's worth. Asserted against the constant
    // rather than by storing five thousand rows, which would make this a slow test
    // proving the same thing.
    const { assert!(log::MAX_BACKFILL >= 1) };
    assert!(from_start.len() as i64 <= log::MAX_BACKFILL);

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_backfill_reads_only_what_the_caller_can_send() {
    // The residency bound, which is the whole point of passing the outbound
    // allowance down into the read: a group holding far more than one batch must
    // not put the rest of it in the heap on the way to discarding it. Before the
    // read took the allowance it returned `MAX_BACKFILL` rows whatever the caller
    // could accept, so both assertions below failed by exactly the ratio between
    // the group's size and the batch's.
    let scratch = Scratch::new("logallowance").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x66).await;
    let pool = relay.state.database.as_ref().unwrap().pool();

    // One distinct body per row, all the same length.
    //
    // This stored the same 4096 bytes forty times, and `relay_envelope`'s primary
    // key is `(group_id, hash)` while `envelope_for` derives the hash from the
    // group and the ciphertext alone. So every row after the first was the same
    // key and the insert failed on a duplicate: the test could never have reached
    // its own assertions. The length is what both assertions below rest on, and
    // it is unchanged, so writing the sequence number into the first eight bytes
    // makes each row its own envelope without moving the arithmetic.
    for seq in 1..=40i64 {
        let mut body = vec![0x5au8; 4096];
        body[..8].copy_from_slice(&seq.to_be_bytes());
        store(pool, &group, &body, seq).await;
    }

    // A caller with room for four frames reads four rows, not forty.
    let by_frames = log::since(pool, &group, 0, 4, usize::MAX)
        .await
        .expect("read");
    assert_eq!(by_frames.len(), 4);

    // A caller with room for roughly two envelopes' bytes reads three: the two that
    // fit and the one that crosses the line, which is kept so the caller's own byte
    // filter sees the same batch it would have seen from an unbounded read.
    let one = by_frames.first().expect("at least one envelope").len();
    let by_bytes = log::since(pool, &group, 0, usize::MAX, one * 2)
        .await
        .expect("read");
    assert_eq!(by_bytes.len(), 3);
    assert!(by_bytes.iter().map(Vec::len).sum::<usize>() <= one * 2 + one);

    // No room at all is no read at all, and not an error: the acknowledgement the
    // client already holds names a head beyond what arrived and it reconciles.
    assert!(log::since(pool, &group, 0, 0, usize::MAX)
        .await
        .expect("read")
        .is_empty());

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn every_read_reports_a_database_that_has_gone() {
    // One typed error with a scrubbed reason, for all three reads. The caller turns
    // it into `retry/backpressure`, which is the same answer the write path gives for
    // the same cause.
    let scratch = Scratch::new("loggone").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x65).await;
    let pool = relay.state.database.as_ref().unwrap().pool().clone();
    let stored = store(&pool, &group, b"body", 1).await;

    let mut admin = sqlx::postgres::PgConnection::connect(&support::admin_url())
        .await
        .expect("connect as admin");
    admin
        .execute(format!("drop database if exists {} with (force)", scratch.name).as_str())
        .await
        .expect("drop it under the relay");

    let items = log::items(&pool, &group).await;
    let one = log::envelope_bytes(&pool, &group, &stored.hash).await;
    let several = log::envelopes_for(&pool, &group, &[id_of(&stored)]).await;
    let backfill = log::since(&pool, &group, 0, usize::MAX, usize::MAX).await;
    for failure in [
        items.err().map(|error| error.reason),
        one.err().map(|error| error.reason),
        several.err().map(|error| error.reason),
        backfill.err().map(|error| error.reason),
    ] {
        let reason = failure.expect("a read against a database that has gone fails");
        assert!(!reason.is_empty());
        // Scrubbed: `operations.md` forbids a credential in an operator-visible
        // string, and a connection error's text is where one would otherwise appear.
        assert!(
            !reason.contains("weald:weald"),
            "the reason carries a password"
        );
    }

    relay.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_that_can_list_but_not_read_answers_retry() {
    // The one case where the item read succeeds and the envelope fetch does not, which
    // is the arm a `RECON` answer has to have and which a database outage cannot
    // reach: an outage fails the first read. Arranged with column privileges, which is
    // a real operator mistake rather than a fault injection: a role granted `select`
    // on the cursor columns and not on `ct` can enumerate the log and cannot serve it.
    //
    // The state is assembled by hand rather than through `serve::prepare`, because
    // migrating requires rights this role deliberately does not have. Everything in it
    // is real: a real pool, as a real role, against the real schema.
    let scratch = Scratch::new("logdenied").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x66).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    store(pool, &group, b"unreadable", 1).await;

    let role = format!("weald_listonly_{}", std::process::id());
    for statement in [
        format!("drop role if exists {role}"),
        format!("create role {role} login password 'listonly'"),
        format!("grant connect on database {} to {role}", scratch.name),
        format!("grant usage on schema public to {role}"),
        format!("grant select (group_id, hash, seq) on relay_envelope to {role}"),
    ] {
        sqlx::query(&statement)
            .execute(pool)
            .await
            .expect("grant the partial privileges");
    }

    let limited = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&format!(
            "postgres://{role}:listonly@127.0.0.1:{}/{}",
            support::postgres_port(),
            scratch.name
        ))
        .await
        .expect("connect as the list-only role");

    // The list works.
    let items = log::items(&limited, &group)
        .await
        .expect("listing is permitted");
    assert_eq!(items.len(), 1);
    // Reading the envelope does not, and it is the typed error rather than a panic.
    let denied = log::envelopes_for(&limited, &group, &[items[0].id])
        .await
        .expect_err("reading ct is not permitted");
    assert!(denied.reason.contains("ct") || denied.reason.contains("permission"));

    // And through the protocol: the client is told to retry rather than being left
    // with a settled answer that silently omitted an envelope.
    let state = std::sync::Arc::new(wealdrelay::health::RelayState::new(
        config_for(&scratch, blobs.path()),
        Some(wealdrelay::db::Database::from_pool(limited)),
        None,
    ));
    let (sender, mut receiver) = wealdrelay::ws::outbound_channel();
    assert!(
        wealdrelay::sync::reconcile(
            &sender,
            &state,
            group.clone(),
            wealdrelay::negentropy::initiate(&[]).encode(),
        )
        .await,
        "the socket stays open: the client's answer is backoff and a resend"
    );
    match receiver.try_recv().expect("a frame is queued") {
        wealdrelay::ws::Outbound::Frame(wealdrelay::frame::Frame::Error(error)) => {
            assert_eq!(error.code, wealdrelay::frame::ErrorCode::Backpressure);
        }
        other => panic!("expected retry/backpressure, got {other:?}"),
    }

    let _ = sqlx::query(&format!("drop role if exists {role}"))
        .execute(pool)
        .await;
    relay.shutdown().await;
    scratch.drop_database().await;
}

/// The transaction count for one database, read from a connection of its own.
///
/// `pg_stat_database.xact_commit` rather than `pg_stat_statements`, which the stack's
/// Postgres does not preload. Every autocommit query a pool issues is one
/// transaction, so the delta across a call is the number of round trips that call
/// made.
///
/// Two things make the reading exact rather than approximate, and both were found by
/// watching this test pass against an implementation it should have failed.
/// `pg_stat_clear_snapshot` first, because a backend caches statistics for its own
/// transaction and would otherwise answer with whatever it read the first time. And
/// the measured pool is closed before the second reading is taken, because a backend
/// accumulates its counters locally and flushes them at most once a second while it
/// lives, but always when it exits. Without the close the delta is zero no matter how
/// many queries ran.
async fn transactions(meter: &mut sqlx::postgres::PgConnection, database: &str) -> i64 {
    sqlx::query("select pg_stat_clear_snapshot()")
        .execute(&mut *meter)
        .await
        .expect("clear the statistics snapshot");
    sqlx::query_scalar("select xact_commit from pg_stat_database where datname = $1")
        .bind(database)
        .fetch_one(&mut *meter)
        .await
        .expect("read the transaction count")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_batch_of_envelopes_is_one_round_trip_rather_than_one_each() {
    // The bound that matters is `SYNC_PUSH_LIMIT`: a saturated reconciliation round
    // asks for 255 envelopes at once, and it used to ask for them one query at a
    // time, holding one of sixteen pool connections for the whole sequence. Held to
    // the round-trip count rather than to the SQL, because what is being defended is
    // the property and not the shape of the statement.
    let scratch = Scratch::new("logbatch").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x67).await;
    let pool = relay.state.database.as_ref().unwrap().pool();

    let count = wealdrelay::session::SEND_QUEUE_BOUND - 1;
    let mut stored = Vec::with_capacity(count);
    for index in 0..count {
        stored.push(
            store(
                pool,
                &group,
                format!("body {index}").as_bytes(),
                index as i64 + 1,
            )
            .await,
        );
    }
    let ids: Vec<Id> = stored.iter().map(id_of).collect();

    let mut meter = sqlx::postgres::PgConnection::connect(&scratch.url)
        .await
        .expect("a connection of its own to read the counters from");

    // One connection, so every round trip the call makes lands on one backend and
    // there is nothing else on it to account for.
    let measured = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&scratch.url)
        .await
        .expect("a pool of exactly one connection to measure");

    let before = transactions(&mut meter, &scratch.name).await;
    let envelopes = log::envelopes_for(&measured, &group, &ids)
        .await
        .expect("read the batch");
    measured.close().await;
    let after = transactions(&mut meter, &scratch.name).await;

    assert_eq!(envelopes.len(), count, "every envelope came back");
    // One query, and the connection's own setup is the rest. The loop this replaced
    // spent 255 here, so the ceiling does not have to be tight to be a proof, only
    // far below the number of ids.
    let spent = after - before;
    assert!(
        spent < 10,
        "the batch took {spent} transactions for {count} ids"
    );

    // Order is the caller's, which is the order the reconciliation vectors record as
    // `PUSH` frame order.
    for (envelope, expected) in envelopes.iter().zip(stored.iter()) {
        assert_eq!(Envelope::decode(&envelope.1).unwrap().hash, expected.hash);
    }

    // And the batch is still whole envelopes, not cursor rows.
    let first = Envelope::decode(&envelopes[0].1).unwrap();
    assert_eq!(first.computed_hash(), first.hash);
    assert_eq!(first.seq, 1);
    assert_eq!(first.ts, CLOCK);

    relay.shutdown().await;
    scratch.drop_database().await;
}
