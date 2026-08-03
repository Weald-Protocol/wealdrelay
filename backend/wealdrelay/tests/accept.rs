// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The accept path, against a real Postgres.
//!
//! `specs/backend/relay/operations.md` fixes both the shape and the order of what
//! happens to one `SEND`, and `specs/backend/relay/wire.md` turns a client's whole
//! retry story on it. Neither is provable against a mock: the properties under
//! test here are a row lock, a unique index and a transaction rolling back, and a
//! fake of Postgres would be a fake of exactly the thing being asserted.
//!
//! The database comes from the local harness (`scripts/weald-stack up`). If it is
//! not there these tests **fail** rather than skip, for the reason
//! `specs/backend/build/testing.md` gives: a skipped integration proof that
//! reports success is the failure mode this programme exists to prevent.
//!
//! Each test gets a database of its own, created and dropped here, because no
//! test may share a database name with another.

use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, Executor as _, PgConnection, PgPool};

use wealdrelay::accept::{accept, floor_byte, AcceptError, Accepted};
use wealdrelay::config::{keys, Config, MinEncryption, Values, WriteMode};
use wealdrelay::db::Database;
use wealdrelay::envelope::{content_hash, Encryption, Envelope, EnvelopeError, VERSION};
use wealdrelay::frame::ErrorCode;

/// A fixed relay-observed receipt time. `operations.md` puts the clock in the
/// caller's hands so nothing under test reads it, and a constant here means a
/// stored `ts` is comparable across runs.
const NOW_MS: u64 = 1_700_000_000_000;

// MARK: The harness

/// Where the harness puts Postgres. The port is the harness's default and is
/// overridable by the same variable the harness uses.
fn postgres_port() -> String {
    std::env::var("WEALD_STACK_PG_PORT").unwrap_or_else(|_| "54032".to_string())
}

fn admin_url() -> String {
    format!(
        "postgres://weald:weald@127.0.0.1:{}/weald_relay",
        postgres_port()
    )
}

/// Fail with the command that fixes it, rather than skipping.
fn require_reachable(port: &str, what: &str) {
    let address: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .expect("a valid address");
    if TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_err() {
        panic!(
            "{what} is not reachable on 127.0.0.1:{port}. This is an integration test and it \
             does not skip: run `scripts/weald-stack up` and try again."
        );
    }
}

/// A database of its own, named after the test, dropped when the test says so.
struct Scratch {
    name: String,
    url: String,
}

impl Scratch {
    async fn new(label: &str) -> Self {
        require_reachable(&postgres_port(), "Postgres");
        // The name carries the pid as well as the label, so two runs of the suite
        // on one machine do not collide and a leftover database from a killed run
        // does not block the next one.
        let name = format!("weald_accept_{label}_{}", std::process::id());
        let mut admin = PgConnection::connect(&admin_url())
            .await
            .expect("connect to the harness Postgres");
        admin
            .execute(format!("drop database if exists {name}").as_str())
            .await
            .expect("drop any leftover scratch database");
        admin
            .execute(format!("create database {name}").as_str())
            .await
            .expect("create the scratch database");
        let url = format!(
            "postgres://weald:weald@127.0.0.1:{}/{name}",
            postgres_port()
        );
        Self { name, url }
    }

    /// A migrated database, and a pool.
    ///
    /// Ten connections rather than one per concurrent caller: the harness server
    /// allows a hundred in total and the suite runs its tests in parallel, so a
    /// pool sized to the largest fan-out below would exhaust the server and every
    /// test would fail on something other than what it is for. Ten is enough for
    /// the row lock to be the thing the callers queue on, which is what the
    /// concurrency tests are about, and the acquire timeout is long enough that a
    /// caller waiting behind the lock is never mistaken for backpressure.
    async fn pool(&self) -> PgPool {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(30))
            .connect(&self.url)
            .await
            .expect("connect a pool to the scratch database");
        Database::from_pool(pool.clone())
            .migrate()
            .await
            .expect("migrate the scratch database from zero");
        pool
    }

    async fn drop_database(&self) {
        let Ok(mut admin) = PgConnection::connect(&admin_url()).await else {
            return;
        };
        let _ = admin
            .execute(format!("drop database if exists {} with (force)", self.name).as_str())
            .await;
    }
}

/// A relay configuration with the two knobs the accept path reads.
fn config_with(min_encryption: MinEncryption, write_mode: WriteMode) -> Config {
    let mut config = Config::resolve(&Values::from_pairs([
        (keys::HOSTNAME, "localhost".to_string()),
        (
            keys::DATABASE_URL,
            format!("postgres://weald:weald@127.0.0.1:{}/x", postgres_port()),
        ),
        (
            keys::STORAGE_URL,
            "file:///tmp/weald-accept-blobs".to_string(),
        ),
    ]))
    .expect("the accept configuration resolves");
    config.min_encryption = min_encryption;
    config.write_mode = write_mode;
    config
}

/// The ordinary case: writes allowed, no encryption floor.
fn config() -> Config {
    config_with(MinEncryption::None, WriteMode::Full)
}

/// A group that exists, so `denied/group_unknown` is not the answer to everything.
async fn known_group(pool: &PgPool, byte: u8) -> Vec<u8> {
    let group = vec![byte; 32];
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(&group)
        .bind("ws-accept")
        .execute(pool)
        .await
        .expect("create the group");
    group
}

/// A well-formed envelope, addressed by its own fields.
fn envelope(group: &[u8], ct: &[u8]) -> Envelope {
    Envelope {
        v: VERSION,
        enc: Encryption::None,
        group: group.to_vec(),
        epoch: 3,
        // Both relay-assigned, and both zero as an envelope arrives.
        seq: 0,
        ts: 0,
        hash: content_hash(VERSION, Encryption::None, group, 3, ct),
        ct: ct.to_vec(),
    }
}

async fn row_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("select count(*) from relay_envelope")
        .fetch_one(pool)
        .await
        .expect("count the envelope table")
}

async fn next_seq(pool: &PgPool, group: &[u8]) -> i64 {
    sqlx::query_scalar("select next_seq from relay_group where group_id = $1")
        .bind(group)
        .fetch_one(pool)
        .await
        .expect("read the group counter")
}

// MARK: Sequence assignment

#[tokio::test]
async fn sequence_numbers_start_at_one_and_are_per_group() {
    // `operations.md`: sequence assignment is a per-group counter, so the numbers
    // in one group are dense from one and a second group starts again at one. Two
    // groups sharing a counter would interleave, and a client reconciling group B
    // would see a range full of numbers that belong to group A.
    let scratch = Scratch::new("perseq").await;
    let pool = scratch.pool().await;
    let first = known_group(&pool, 1).await;
    let second = known_group(&pool, 2).await;

    for expected in 1..=3u64 {
        let body = format!("first group message {expected}");
        let outcome = accept(&pool, &config(), &envelope(&first, body.as_bytes()), NOW_MS)
            .await
            .expect("a well-formed envelope into a known group is stored");
        assert_eq!(outcome, Accepted::Stored { seq: expected });
    }
    for expected in 1..=3u64 {
        let body = format!("second group message {expected}");
        let outcome = accept(
            &pool,
            &config(),
            &envelope(&second, body.as_bytes()),
            NOW_MS,
        )
        .await
        .expect("stored");
        assert_eq!(
            outcome,
            Accepted::Stored { seq: expected },
            "the second group must number from one rather than continuing the first"
        );
    }

    // The stored rows carry the numbers that were handed out, and the two groups
    // hold the same three numbers rather than six between them.
    for group in [&first, &second] {
        let seqs: Vec<i64> =
            sqlx::query_scalar("select seq from relay_envelope where group_id = $1 order by seq")
                .bind(group)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    // And the row the relay wrote is the wire header plus `ct`, with the relay's
    // own clock in `ts` rather than anything the client said.
    let (v, enc, epoch, ts, ct): (i16, i16, i64, i64, Vec<u8>) = sqlx::query_as(
        "select v, enc, epoch, ts, ct from relay_envelope where group_id = $1 and seq = 1",
    )
    .bind(&first)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((v, enc, epoch, ts), (1, 0, 3, NOW_MS as i64));
    assert_eq!(ct, b"first group message 1");

    scratch.drop_database().await;
}

// MARK: The duplicate, which is what makes a retry safe

#[tokio::test]
async fn a_duplicate_hash_is_answered_with_the_existing_seq_and_is_not_an_error() {
    // `wire.md`'s promise: a client that retries verbatim after a dropped
    // connection is always safe. That is only true if the second call is answered
    // with the number the first one got. An error would leave the client unable to
    // tell whether its write landed, and a *new* number would move its cursor and
    // force it to renumber an author chain link.
    let scratch = Scratch::new("dupe").await;
    let pool = scratch.pool().await;
    let group = known_group(&pool, 3).await;
    let message = envelope(&group, b"sent once, delivered twice");

    let first = accept(&pool, &config(), &message, NOW_MS).await.unwrap();
    assert_eq!(first, Accepted::Stored { seq: 1 });

    // The retry. A different `now_ms`, because a client resending an hour later is
    // the case this exists for, and the answer must not depend on it.
    let second = accept(&pool, &config(), &message, NOW_MS + 3_600_000)
        .await
        .expect("a duplicate is not an error");
    assert_eq!(second, Accepted::Duplicate { seq: 1 });
    assert_eq!(
        second.seq(),
        first.seq(),
        "the retry moved the client's cursor"
    );

    // One row, and it still carries the first receipt time: a retry does not
    // rewrite what was stored.
    assert_eq!(row_count(&pool).await, 1);
    let ts: i64 = sqlx::query_scalar("select ts from relay_envelope")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(ts, NOW_MS as i64);

    // `seq()` reads through both variants, because a caller writing an
    // acknowledgement frame does not care which one it got.
    assert_eq!(Accepted::Stored { seq: 9 }.seq(), 9);
    assert_eq!(Accepted::Duplicate { seq: 9 }.seq(), 9);
    assert_ne!(Accepted::Stored { seq: 9 }, Accepted::Duplicate { seq: 9 });
    assert!(format!("{second:?}").contains("Duplicate"));

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_duplicate_takes_no_lock_so_the_group_counter_does_not_advance() {
    // The order in `operations.md` is load-bearing: the duplicate is resolved
    // before the counter is touched. The observable form of "took no lock" is that
    // `next_seq` is where it was, because advancing it is the only thing the lock
    // is taken for. A relay that checked for the duplicate inside the transaction
    // would make every retry queue behind every other writer in the group, which
    // is the pathology a client that retries on every dropped connection would hit
    // hardest.
    let scratch = Scratch::new("dupelock").await;
    let pool = scratch.pool().await;
    let group = known_group(&pool, 4).await;
    let message = envelope(&group, b"one message");

    accept(&pool, &config(), &message, NOW_MS).await.unwrap();
    let after_store = next_seq(&pool, &group).await;
    assert_eq!(after_store, 2);

    for _ in 0..5 {
        assert_eq!(
            accept(&pool, &config(), &message, NOW_MS).await.unwrap(),
            Accepted::Duplicate { seq: 1 }
        );
    }
    assert_eq!(
        next_seq(&pool, &group).await,
        after_store,
        "a duplicate advanced the group counter, so it took the lock"
    );
    assert_eq!(row_count(&pool).await, 1);

    scratch.drop_database().await;
}

// MARK: The refusals that need database state

#[tokio::test]
async fn an_envelope_for_a_group_that_does_not_exist_is_group_unknown_and_stores_nothing() {
    // Group existence is state `Envelope::validate` cannot see, so it is checked
    // here and answered with the registry's own code. A relay that created the
    // group implicitly would let any peer allocate storage in a workspace it has
    // no relationship with.
    let scratch = Scratch::new("nogroup").await;
    let pool = scratch.pool().await;
    let missing = vec![0x5au8; 32];

    let error = accept(&pool, &config(), &envelope(&missing, b"nowhere"), NOW_MS)
        .await
        .expect_err("must refuse");
    assert_eq!(error, AcceptError::GroupUnknown);
    assert_eq!(error.code(), ErrorCode::GroupUnknown);
    assert_eq!(row_count(&pool).await, 0);
    // And no group row was created on the way past.
    let groups: i64 = sqlx::query_scalar("select count(*) from relay_group")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(groups, 0);

    scratch.drop_database().await;
}

#[tokio::test]
async fn an_envelope_into_a_frozen_group_is_refused_and_stores_nothing() {
    // `media.md`: a group whose retention control chain has a contested successor
    // is frozen, and a write into it is `denied/group_frozen`.
    //
    // The number the refused write claimed is not spent. The refusal returns
    // before the commit, so the transaction that incremented `next_seq` rolls back
    // with it and the counter is restored: the next successful write into the
    // group gets the number the frozen one would have had. `operations.md` says
    // gaps in `seq` are legal and clients tolerate them, and this test is where
    // that is documented, but legal is not the same as produced. Nothing on this
    // path leaves one, and the assertion below is on what the relay actually does
    // rather than on what it is permitted to do, because a test asserting a gap
    // would be asserting a rollback that did not work.
    let scratch = Scratch::new("frozen").await;
    let pool = scratch.pool().await;
    let group = known_group(&pool, 6).await;

    accept(
        &pool,
        &config(),
        &envelope(&group, b"before the freeze"),
        NOW_MS,
    )
    .await
    .expect("stored before the group was frozen");

    sqlx::query("update relay_group set frozen_reason = $1 where group_id = $2")
        .bind("contested retention successor")
        .bind(&group)
        .execute(&pool)
        .await
        .unwrap();

    let error = accept(
        &pool,
        &config(),
        &envelope(&group, b"during the freeze"),
        NOW_MS,
    )
    .await
    .expect_err("must refuse");
    assert_eq!(error, AcceptError::GroupFrozen);
    assert_eq!(error.code(), ErrorCode::GroupFrozen);
    // Nothing was stored, and the counter went back with the transaction.
    assert_eq!(row_count(&pool).await, 1);
    assert_eq!(next_seq(&pool, &group).await, 2);

    sqlx::query("update relay_group set frozen_reason = null where group_id = $1")
        .bind(&group)
        .execute(&pool)
        .await
        .unwrap();
    let after = accept(
        &pool,
        &config(),
        &envelope(&group, b"after the thaw"),
        NOW_MS,
    )
    .await
    .expect("a thawed group accepts writes again");
    assert_eq!(after, Accepted::Stored { seq: 2 });
    // The numbering is dense across the freeze, which is the stronger of the two
    // legal outcomes and the one a reconciling client walks fastest.
    let seqs: Vec<i64> =
        sqlx::query_scalar("select seq from relay_envelope where group_id = $1 order by seq")
            .bind(&group)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(seqs, vec![1, 2]);

    scratch.drop_database().await;
}

#[tokio::test]
async fn read_only_refuses_before_any_validation_work() {
    // A relay in maintenance is not going to store this whatever it says, so
    // hashing a megabyte of ciphertext first would be work done for an answer
    // already decided. The proof of the ordering is an envelope that is *also*
    // invalid: if validation ran first the answer would be `hash_mismatch`, and it
    // is `service_read_only` instead.
    let scratch = Scratch::new("readonly").await;
    let pool = scratch.pool().await;
    let group = known_group(&pool, 7).await;
    let mut broken = envelope(&group, b"refused before it is read");
    broken.hash = vec![0u8; 32];
    // Wrong in three ways at once, so no single earlier check could account for
    // the answer.
    broken.v = VERSION + 1;
    broken.ct = vec![0u8; (1 << 20) + 1];

    let read_only = config_with(MinEncryption::None, WriteMode::ReadOnly);
    let error = accept(&pool, &read_only, &broken, NOW_MS)
        .await
        .expect_err("a read-only relay refuses");
    assert_eq!(error, AcceptError::ReadOnly);
    assert_eq!(error.code(), ErrorCode::ServiceReadOnly);
    assert_eq!(row_count(&pool).await, 0);

    // The same envelope against a relay that takes writes is refused for what is
    // wrong with it, which is what makes the assertion above about ordering rather
    // than about the envelope.
    let error = accept(&pool, &config(), &broken, NOW_MS)
        .await
        .expect_err("must refuse");
    assert_eq!(
        error,
        AcceptError::Envelope(EnvelopeError::UnsupportedVersion(VERSION + 1))
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn every_envelope_error_reaches_the_caller_through_accept_with_its_own_code() {
    // `Envelope::validate` is the trust boundary and `accept` is the only caller
    // of it in the relay. A conversion that collapsed its refusals into one code
    // would leave a client unable to tell "upgrade your build" from "do not send
    // that again", and both arrive on the same failed `SEND`.
    let scratch = Scratch::new("codes").await;
    let pool = scratch.pool().await;
    let group = known_group(&pool, 8).await;

    let mut wrong_version = envelope(&group, b"v99");
    wrong_version.v = 99;

    // An `enc` the relay does not carry cannot be built through `Encryption`, so
    // this is the shape the check has to survive: a valid enum value under a floor
    // that refuses it. The unknown-`enc` byte itself is refused a layer earlier,
    // at decode, and that is proven in `tests/envelope.rs`.
    let plaintext = envelope(&group, b"plaintext under an mls floor");

    let mut wrong_hash = envelope(&group, b"addressed as something else");
    wrong_hash.hash = vec![0xffu8; 32];

    let mut too_large = envelope(&group, b"placeholder");
    too_large.ct = vec![0u8; (1 << 20) + 1];
    too_large.hash = too_large.computed_hash();

    let cases: Vec<(&str, Envelope, MinEncryption, EnvelopeError, ErrorCode)> = vec![
        (
            "a version this build does not speak",
            wrong_version,
            MinEncryption::None,
            EnvelopeError::UnsupportedVersion(99),
            ErrorCode::ProtocolUnsupported,
        ),
        (
            "plaintext under an mls floor",
            plaintext,
            MinEncryption::Mls,
            EnvelopeError::PlaintextRefused,
            ErrorCode::PlaintextRefused,
        ),
        (
            "a hash that is not the envelope's own address",
            wrong_hash,
            MinEncryption::None,
            EnvelopeError::HashMismatch,
            ErrorCode::HashMismatch,
        ),
        (
            "a ciphertext over the ceiling",
            too_large,
            MinEncryption::None,
            EnvelopeError::CiphertextTooLarge((1 << 20) + 1),
            ErrorCode::EnvelopeTooLarge,
        ),
    ];

    for (label, message, floor, expected, code) in cases {
        let error = match accept(
            &pool,
            &config_with(floor, WriteMode::Full),
            &message,
            NOW_MS,
        )
        .await
        {
            Ok(outcome) => panic!("{label} must be refused, got {outcome:?}"),
            Err(error) => error,
        };
        assert_eq!(error, AcceptError::Envelope(expected), "{label}");
        assert_eq!(error.code(), code, "{label}");
        // Nothing reached the table on any of them, because validation runs before
        // the transaction opens.
        assert_eq!(row_count(&pool).await, 0, "{label} stored something");
    }

    // An `enc` byte the relay does not carry is the one refusal on this list that
    // cannot arrive through `accept`: `Encryption` has no value to hold it, so the
    // decoder refuses it before an `Envelope` exists at all (`tests/envelope.rs`).
    // The mapping is still asserted here, because it is the code a client receives
    // on a failed `SEND` whichever layer produced it.
    let unknown_enc: AcceptError = EnvelopeError::UnknownEncryption(2).into();
    assert_eq!(unknown_enc.code(), ErrorCode::MalformedHeader);

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_database_that_has_gone_away_is_backpressure_and_does_not_leak_the_password() {
    // `operations.md`: `SEND` never returns `retry` for contention, only for
    // infrastructure. A database that is gone is infrastructure, and the client's
    // correct response is backoff and a verbatim resend rather than treating the
    // message as refused. A panic here would take the connection task with it and
    // the client would learn nothing at all.
    //
    // The message is scrubbed, because the driver's own errors quote the
    // connection URL and an operator pasting a relay log into an issue should not
    // be pasting the database password with it.
    let scratch = Scratch::new("dbgone").await;
    let pool = scratch.pool().await;
    let group = known_group(&pool, 9).await;
    let message = envelope(&group, b"into a database that is not there");

    pool.close().await;

    let error = accept(&pool, &config(), &message, NOW_MS)
        .await
        .expect_err("a closed pool cannot store anything");
    assert!(
        matches!(error, AcceptError::Backpressure(_)),
        "a database failure must be backpressure, not a reject: {error:?}"
    );
    assert_eq!(error.code(), ErrorCode::Backpressure);
    let AcceptError::Backpressure(detail) = &error else {
        unreachable!("asserted above")
    };
    assert!(!detail.is_empty(), "backpressure with no reason at all");
    assert!(
        !detail.contains("weald:weald"),
        "the backpressure message leaked a credential: {detail}"
    );
    assert!(error.to_string().starts_with("retry/backpressure"));

    scratch.drop_database().await;
}

// MARK: Concurrency, which is the whole point of the gate

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn thirty_concurrent_distinct_envelopes_get_a_dense_run_of_sequence_numbers() {
    // The gate's property. Sequence assignment is a single `UPDATE ... RETURNING`
    // inside the transaction that inserts the envelope, so thirty writers into one
    // group are serialised by the row lock and by nothing else. A repeated number
    // would break the unique index on `(group_id, seq)` and a lost one would leave
    // a reconciling client waiting forever for something that was never coming.
    let scratch = Scratch::new("race30").await;
    let pool = scratch.pool().await;
    let group = known_group(&pool, 10).await;

    let mut tasks = Vec::new();
    for index in 0..30u64 {
        let pool = pool.clone();
        let message = envelope(&group, format!("distinct message {index}").as_bytes());
        tasks.push(tokio::spawn(async move {
            accept(&pool, &config(), &message, NOW_MS).await
        }));
    }

    let mut seqs = Vec::new();
    for task in tasks {
        let outcome = task
            .await
            .expect("no accept panicked")
            .expect("every distinct envelope is stored");
        assert!(
            matches!(outcome, Accepted::Stored { .. }),
            "a distinct envelope was reported as a duplicate: {outcome:?}"
        );
        seqs.push(outcome.seq());
    }
    seqs.sort_unstable();
    assert_eq!(
        seqs,
        (1..=30u64).collect::<Vec<_>>(),
        "the assigned numbers are not exactly 1..=30 with no gap and no repeat"
    );
    assert_eq!(row_count(&pool).await, 30);

    // The database agrees with what the callers were told, which is the assertion
    // that would catch a number handed out and then not committed.
    let stored: Vec<i64> =
        sqlx::query_scalar("select seq from relay_envelope where group_id = $1 order by seq")
            .bind(&group)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(stored, (1..=30i64).collect::<Vec<_>>());
    assert_eq!(next_seq(&pool, &group).await, 31);

    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn thirty_concurrent_copies_of_one_envelope_are_stored_once() {
    // The race the pre-transaction duplicate check cannot win: thirty callers all
    // find nothing, all claim a number, and all try to insert the same content
    // address. `on conflict do nothing` decides, and the twenty-nine losers roll
    // back and re-read rather than failing. This is the arm that makes a client
    // resending on a flaky link safe even when its earlier attempt is still in
    // flight, which is the case a serial retry test cannot reach.
    let scratch = Scratch::new("racedupe").await;
    let pool = scratch.pool().await;
    let group = known_group(&pool, 11).await;
    let message = envelope(&group, b"one message, thirty attempts");

    let mut tasks = Vec::new();
    for _ in 0..30 {
        let pool = pool.clone();
        let message = message.clone();
        tasks.push(tokio::spawn(async move {
            accept(&pool, &config(), &message, NOW_MS).await
        }));
    }

    let mut stored = 0;
    let mut duplicates = 0;
    let mut seqs = Vec::new();
    for task in tasks {
        let outcome = task
            .await
            .expect("no accept panicked")
            .expect("no failures");
        match outcome {
            Accepted::Stored { .. } => stored += 1,
            Accepted::Duplicate { .. } => duplicates += 1,
        }
        seqs.push(outcome.seq());
    }
    assert_eq!(stored, 1, "exactly one caller stored the row");
    assert_eq!(duplicates, 29);
    // Every caller was told the same number, which is what makes a retry answerable
    // without the client having to reconcile two answers.
    let winner = seqs[0];
    assert!(
        seqs.iter().all(|seq| *seq == winner),
        "the callers were told different numbers: {seqs:?}"
    );
    assert_eq!(row_count(&pool).await, 1);
    let stored_seq: i64 = sqlx::query_scalar("select seq from relay_envelope")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored_seq as u64, winner);

    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unrelated_groups_do_not_contend() {
    // The reason the counter is a row per group rather than one for the relay:
    // thirty people and a dozen agents writing into one workspace must not queue
    // behind a different workspace. Interleaved here, so a shared lock or a shared
    // counter would show up as numbering that is neither independent nor dense.
    let scratch = Scratch::new("threeway").await;
    let pool = scratch.pool().await;
    let mut groups = Vec::new();
    for byte in 20..23u8 {
        groups.push(known_group(&pool, byte).await);
    }

    let mut tasks = Vec::new();
    for index in 0..30u64 {
        let group = groups[(index % 3) as usize].clone();
        let pool = pool.clone();
        let message = envelope(&group, format!("interleaved {index}").as_bytes());
        tasks.push(tokio::spawn(async move {
            (
                group,
                accept(&pool, &config(), &message, NOW_MS).await.unwrap(),
            )
        }));
    }
    for task in tasks {
        let (_, outcome) = task.await.expect("no accept panicked");
        assert!(matches!(outcome, Accepted::Stored { .. }), "{outcome:?}");
    }

    for group in &groups {
        let seqs: Vec<i64> =
            sqlx::query_scalar("select seq from relay_envelope where group_id = $1 order by seq")
                .bind(group)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            seqs,
            (1..=10i64).collect::<Vec<_>>(),
            "one group's numbering is not independent and dense"
        );
        assert_eq!(next_seq(&pool, group).await, 11);
    }
    assert_eq!(row_count(&pool).await, 30);

    scratch.drop_database().await;
}

// MARK: The database failing at each point on the path
//
// `accept` reports a database failure as `retry/backpressure` at eight separate
// places, and every one of them is a different moment: a transaction that never
// opened, a counter that could not be claimed, an insert that did not run, a
// commit that did not land. Collapsing them would be harmless to the client,
// which sees one code either way, but leaving them untested would not: an arm
// that has never run is an arm that could be returning `Ok` and nobody would
// know until a relay under a failing database started acknowledging writes it
// had not stored.
//
// A real Postgres does not fail on demand at a chosen statement, so the tests
// below drive it two ways. The first severs the connection the moment a named
// statement goes past, which is not a mock of Postgres: the database and the
// driver are both real and what is simulated is the network between them going
// away. The second puts a column of the wrong type where the accept path expects
// one, which is what an operator's hand-edited schema looks like from the
// driver's side, and is the same shape `tests/integration.rs` uses to reach the
// migration runner's own error arms.

/// A TCP proxy in front of the harness Postgres that cuts the connection dead the
/// moment the client sends a statement containing `marker`.
///
/// Bytes are forwarded verbatim in both directions until the marker appears, so
/// everything before it really happened against the real server. Returns the port
/// to point a connection at.
async fn postgres_that_dies_at(marker: &'static [u8]) -> u16 {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    require_reachable(&postgres_port(), "Postgres");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback proxy");
    let port = listener.local_addr().expect("local address").port();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let upstream = format!("127.0.0.1:{}", postgres_port());
                let Ok(server) = tokio::net::TcpStream::connect(upstream).await else {
                    return;
                };
                let (mut from_client, mut to_client) = client.into_split();
                let (mut from_server, mut to_server) = server.into_split();
                let forward = async move {
                    // Everything the client has sent so far, so a marker split
                    // across two reads is still seen.
                    let mut sent: Vec<u8> = Vec::new();
                    let mut buffer = vec![0_u8; 8192];
                    loop {
                        let Ok(read) = from_client.read(&mut buffer).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        sent.extend_from_slice(&buffer[..read]);
                        if sent.windows(marker.len()).any(|window| window == marker) {
                            return;
                        }
                        if to_server.write_all(&buffer[..read]).await.is_err() {
                            return;
                        }
                    }
                };
                let back = async move {
                    let _ = tokio::io::copy(&mut from_server, &mut to_client).await;
                };
                tokio::select! {
                    () = forward => {},
                    () = back => {},
                }
            });
        }
    });
    port
}

/// A pool onto the scratch database through a proxy that will sever the
/// connection at `marker`. `sslmode` is disabled so the statements are visible to
/// the proxy: a session the proxy could not read would be a proxy that never cut
/// anything and a test that passed for the wrong reason.
async fn severing_pool(scratch: &Scratch, marker: &'static [u8]) -> PgPool {
    let port = postgres_that_dies_at(marker).await;
    let url = format!(
        "postgres://weald:weald@127.0.0.1:{port}/{}?sslmode=disable",
        scratch.name
    );
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&url)
        .await
        .expect("the proxy carries a healthy connection until the marker is sent")
}

/// The shared assertion: whatever went wrong with the database, the client is told
/// to back off and resend, and the message does not carry the password.
fn assert_backpressure(error: &AcceptError, at: &str) {
    assert!(
        matches!(error, AcceptError::Backpressure(_)),
        "the failure at {at} is not backpressure: {error:?}"
    );
    assert_eq!(error.code(), ErrorCode::Backpressure);
    assert!(
        !error.to_string().contains("weald:weald"),
        "the failure at {at} leaked a credential: {error}"
    );
}

#[tokio::test]
async fn a_transaction_that_cannot_be_opened_is_backpressure() {
    // The first database call after the duplicate check. A relay that carried on
    // without a transaction would run the counter claim and the insert outside
    // one, and a failure between them would leave a number handed out and no row.
    let scratch = Scratch::new("nobegin").await;
    let setup = scratch.pool().await;
    let group = known_group(&setup, 30).await;

    let pool = severing_pool(&scratch, b"BEGIN").await;
    let error = accept(
        &pool,
        &config(),
        &envelope(&group, b"no transaction"),
        NOW_MS,
    )
    .await
    .expect_err("must refuse");
    assert_backpressure(&error, "begin");
    assert_eq!(row_count(&setup).await, 0);

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_counter_claim_that_cannot_run_is_backpressure() {
    // The `UPDATE ... RETURNING` is both the existence check and the sequence
    // assignment, so a failure here means the relay does not know whether the
    // group exists, let alone what number to give the envelope. Reporting it as
    // `group_unknown` would tell a client never to retry a write that was only
    // ever refused by a network fault.
    let scratch = Scratch::new("noclaim").await;
    let setup = scratch.pool().await;
    let group = known_group(&setup, 31).await;

    let pool = severing_pool(&scratch, b"update relay_group set next_seq").await;
    let error = accept(&pool, &config(), &envelope(&group, b"no counter"), NOW_MS)
        .await
        .expect_err("must refuse");
    assert_backpressure(&error, "the counter claim");
    assert_eq!(row_count(&setup).await, 0);
    // The transaction went away with the connection, so the counter is where it
    // was and the number this call would have taken is still there to be given
    // out.
    assert_eq!(next_seq(&setup, &group).await, 1);

    scratch.drop_database().await;
}

#[tokio::test]
async fn an_insert_that_cannot_run_is_backpressure() {
    // The write itself. This is the arm where an `Ok` would be a lie a client
    // acts on: it would move its cursor past an envelope the relay never stored,
    // and nothing above layer 2 would ever ask for it again.
    let scratch = Scratch::new("noinsert").await;
    let setup = scratch.pool().await;
    let group = known_group(&setup, 32).await;

    let pool = severing_pool(&scratch, b"insert into relay_envelope").await;
    let error = accept(
        &pool,
        &config(),
        &envelope(&group, b"never written"),
        NOW_MS,
    )
    .await
    .expect_err("must refuse");
    assert_backpressure(&error, "the insert");
    assert_eq!(row_count(&setup).await, 0);
    assert_eq!(next_seq(&setup, &group).await, 1);

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_commit_that_cannot_land_is_backpressure_and_not_a_stored_envelope() {
    // The most dangerous one to get wrong. A commit that failed and was read as
    // success would have the relay acknowledge a `seq` for an envelope the server
    // rolled back, and the first anybody would hear of it is a client reconciling
    // a hole it can never fill.
    let scratch = Scratch::new("nocommit").await;
    let setup = scratch.pool().await;
    let group = known_group(&setup, 33).await;

    let pool = severing_pool(&scratch, b"COMMIT").await;
    let error = accept(
        &pool,
        &config(),
        &envelope(&group, b"never committed"),
        NOW_MS,
    )
    .await
    .expect_err("must refuse");
    assert_backpressure(&error, "the commit");
    // The server rolled the transaction back when the connection went away, so
    // neither the row nor the number survived and a resend has a clean run at it.
    assert_eq!(row_count(&setup).await, 0);
    assert_eq!(next_seq(&setup, &group).await, 1);
    let retry = accept(
        &setup,
        &config(),
        &envelope(&group, b"never committed"),
        NOW_MS,
    )
    .await
    .expect("the resend the client is told to make succeeds");
    assert_eq!(retry, Accepted::Stored { seq: 1 });

    scratch.drop_database().await;
}

/// Hold a transaction open with the envelope's row inserted and uncommitted, so
/// the accept path's own insert reaches `on conflict do nothing` and finds
/// nothing to report. This is the race arm, made deterministic: the duplicate
/// check cannot see the row and the insert cannot miss it.
async fn blocking_writer(url: &str, group: &[u8], message: &Envelope) -> sqlx::PgConnection {
    let mut connection = PgConnection::connect(url).await.expect("a second writer");
    connection.execute("begin").await.expect("begin");
    sqlx::query(
        "insert into relay_envelope (group_id, hash, v, enc, epoch, seq, ts, ct) \
         values ($1, $2, 1, 0, 3, 1, $3, $4)",
    )
    .bind(group)
    .bind(&message.hash)
    .bind(NOW_MS as i64)
    .bind(&message.ct)
    .execute(&mut connection)
    .await
    .expect("the other writer stores the row first");
    connection
}

#[tokio::test]
async fn a_rollback_that_cannot_run_after_a_conflict_is_backpressure() {
    // The loser of the race rolls back before it re-reads, because the number it
    // claimed is not going to be used and holding the transaction open would hold
    // the group's counter row with it. A rollback that failed and was ignored
    // would leave that lock held for as long as the connection lived, which is the
    // one way a relay with no head chain can still make unrelated writers queue.
    let scratch = Scratch::new("norollback").await;
    let setup = scratch.pool().await;
    let group = known_group(&setup, 34).await;
    let message = envelope(&group, b"two writers, one address");
    let mut blocker = blocking_writer(&scratch.url, &group, &message).await;

    let pool = severing_pool(&scratch, b"ROLLBACK").await;
    let racing = tokio::spawn({
        let message = message.clone();
        async move { accept(&pool, &config(), &message, NOW_MS).await }
    });
    // Long enough for the accept to have claimed its number and be waiting on the
    // other writer's uncommitted row.
    tokio::time::sleep(Duration::from_millis(500)).await;
    blocker.execute("commit").await.expect("commit");

    let error = racing.await.expect("no panic").expect_err("must refuse");
    assert_backpressure(&error, "the rollback");
    // The other writer's row is the only one, which is what the loser would have
    // reported the number of had it got that far.
    assert_eq!(row_count(&setup).await, 1);

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_group_row_the_relay_cannot_read_is_backpressure_rather_than_a_wrong_answer() {
    // `frozen_reason` and the counter are read out of the row the claim returns,
    // and both reads are fallible. A schema where either column is not the type
    // the relay expects is what a hand-edited database looks like from the
    // driver's side, and the answer has to be "try again shortly" rather than a
    // guess: reading an unreadable `frozen_reason` as absent would accept writes
    // into a frozen group, and reading an unreadable counter as anything at all
    // would assign a number nothing agrees with.
    let scratch = Scratch::new("badgroup").await;
    let pool = scratch.pool().await;
    let group = known_group(&pool, 35).await;

    // The freeze marker, as something that is not text and is not null either. A
    // null of any type reads as "not frozen" whatever the column is declared as,
    // which is correct: absence is absence. It is a present value the relay cannot
    // read that has to stop the write.
    sqlx::query("alter table relay_group alter column frozen_reason type bigint using 0")
        .execute(&pool)
        .await
        .expect("put a column of the wrong type where the relay reads the freeze marker");
    let error = accept(
        &pool,
        &config(),
        &envelope(&group, b"unreadable freeze"),
        NOW_MS,
    )
    .await
    .expect_err("must refuse");
    assert_backpressure(&error, "the freeze marker");
    assert_eq!(row_count(&pool).await, 0);

    // And the counter, as something that is not a bigint.
    sqlx::query("alter table relay_group alter column frozen_reason type text using null")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("alter table relay_group alter column next_seq type numeric")
        .execute(&pool)
        .await
        .expect("put a column of the wrong type where the relay reads the counter");
    let error = accept(
        &pool,
        &config(),
        &envelope(&group, b"unreadable counter"),
        NOW_MS,
    )
    .await
    .expect_err("must refuse");
    assert_backpressure(&error, "the counter");
    assert_eq!(row_count(&pool).await, 0);

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_stored_seq_the_relay_cannot_read_is_backpressure_on_both_reads_of_it() {
    // `existing_seq` is called twice: once before the transaction, to answer a
    // retry without taking a lock, and once after a conflict, to find out what
    // number the winner was given. Both decode a `seq` out of the row, and a
    // column the driver cannot read as a bigint has to fail rather than be treated
    // as absent: absent means "not stored" on the first call, which would send the
    // relay on to write a second copy of something it already holds.
    let scratch = Scratch::new("badseq").await;
    let pool = scratch.pool().await;
    let group = known_group(&pool, 36).await;
    let message = envelope(&group, b"a number nobody can read");

    sqlx::query("alter table relay_envelope alter column seq type numeric")
        .execute(&pool)
        .await
        .expect("put a column of the wrong type where the relay reads the sequence number");

    // The second read first, because reaching it needs the row to be invisible to
    // the first one: another writer holds it uncommitted, so the duplicate check
    // finds nothing, the insert conflicts, and the re-read is what fails.
    let mut blocker = blocking_writer(&scratch.url, &group, &message).await;
    let racing = tokio::spawn({
        let pool = pool.clone();
        let message = message.clone();
        async move { accept(&pool, &config(), &message, NOW_MS).await }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    blocker.execute("commit").await.expect("commit");
    let error = racing.await.expect("no panic").expect_err("must refuse");
    assert_backpressure(&error, "the re-read after a conflict");

    // And now the row is committed and visible, so the duplicate check itself is
    // the read that fails.
    let error = accept(&pool, &config(), &message, NOW_MS)
        .await
        .expect_err("must refuse");
    assert_backpressure(&error, "the duplicate check");
    assert_eq!(row_count(&pool).await, 1);

    scratch.drop_database().await;
}

// MARK: What the client is told, with no database in the way

#[test]
fn every_accept_failure_carries_a_code_and_a_frame() {
    // A `SEND` that failed without a code leaves a client unable to tell "do not
    // retry" from "try again shortly", so every variant is mapped and every frame
    // is buildable. The frames carry nothing content derived, because there is
    // nothing on this path that is not opaque to the relay.
    let cases = [
        (
            AcceptError::Envelope(EnvelopeError::HashMismatch),
            ErrorCode::HashMismatch,
        ),
        (AcceptError::GroupUnknown, ErrorCode::GroupUnknown),
        (AcceptError::GroupFrozen, ErrorCode::GroupFrozen),
        (AcceptError::ReadOnly, ErrorCode::ServiceReadOnly),
        (
            AcceptError::Backpressure("pool closed".to_string()),
            ErrorCode::Backpressure,
        ),
    ];
    for (error, code) in &cases {
        assert_eq!(error.code(), *code, "{error:?}");
        let frame = error.to_frame();
        assert_eq!(frame.code, *code);
        assert!(frame.retry_after.is_none());
        assert!(frame.detail.is_none());
        assert!(!error.to_string().is_empty());
        assert_eq!(error.clone(), *error);
    }
    // The envelope's own refusal passes through unchanged rather than being
    // renamed, which is what lets one `From` cover all six of them.
    let converted: AcceptError = EnvelopeError::PlaintextRefused.into();
    assert_eq!(
        converted,
        AcceptError::Envelope(EnvelopeError::PlaintextRefused)
    );
    assert_eq!(converted.code(), ErrorCode::PlaintextRefused);
    assert!(format!("{converted:?}").contains("PlaintextRefused"));
}

#[test]
fn the_encryption_floor_is_reported_as_the_byte_the_wire_format_carries() {
    // `CONNECT` acknowledges with the floor, so a client learns before it sends
    // whether plaintext will be taken. The mapping is the same one `enc` uses on
    // the envelope, because two numberings for one concept is a client refusing
    // the relay it is talking to.
    assert_eq!(floor_byte(MinEncryption::None), 0);
    assert_eq!(floor_byte(MinEncryption::Mls), 1);
    assert_eq!(floor_byte(MinEncryption::None), Encryption::None as u8);
    assert_eq!(floor_byte(MinEncryption::Mls), Encryption::Mls as u8);
}
