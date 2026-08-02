// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! What the invite store answers when the database cannot answer it.
//!
//! `tests/invite_store.rs` and `tests/invite_genesis.rs` prove these paths right
//! when Postgres works. This file proves them right when it does not, and the
//! stakes are not generic. An invite path that guessed on a failed read would
//! either burn a seat nobody used, admit a device against a code it could not
//! check, or tell a joiner their invite is dead when the relay simply could not
//! look. Every one of those is worse than "come back in a minute".
//!
//! The correct answer on every fault path is `StoreError::Database`, never a
//! verdict. `Verdict::Unavailable` in particular is a decision, not an error: it
//! is what a joiner is told when the code is wrong, and a relay that answered it
//! for a failed query would tell somebody with a valid invite that their invite is
//! no good.
//!
//! Nothing here is mocked. Every fault is a real state of a real Postgres in a
//! database of this test's own: a table renamed away, a trigger that refuses a
//! write, a closed pool. Faults are injected one table at a time, because a
//! function whose first query fails never reaches its fourth.

mod support;

use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey};
use sqlx::PgPool;
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::invite::code::Code;
use wealdrelay::invite::reserve::{self, Verdict};
use wealdrelay::invite::store::{self, StoreError};
use wealdrelay::invite::{self, EncBundle, Invite};

use support::{config_for, Running, Scratch};

const WORKSPACE: &str = "ws-invite-faults";
const NOW: i64 = 1_700_000_000_000;

async fn prepared(label: &str) -> (Scratch, tempfile::TempDir, Arc<RelayState>) {
    let scratch = Scratch::new(label).await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(1)).await;
    let state = Arc::clone(&relay.state);
    relay.shutdown().await;
    (scratch, blobs, state)
}

fn pool_of(state: &Arc<RelayState>) -> &PgPool {
    state.database.as_ref().expect("a database").pool()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn root() -> Vec<u8> {
    vec![0x11; 32]
}

fn nonce(seed: u8) -> Vec<u8> {
    vec![seed; 16]
}

fn issue(token_seed: u8, code: Code, uses: u8) -> Invite {
    let issuer = key(1);
    let token = vec![token_seed; 16];
    let code_hash = invite::code::hash(code, &token).unwrap().to_vec();
    let mut record = Invite {
        token,
        workspace: root(),
        issuer: issuer.verifying_key().to_bytes().to_vec(),
        issued_at: NOW as u64,
        expires: NOW as u64 + invite::DEFAULT_EXPIRY_MS,
        uses,
        code_hash,
        scopes: vec![root()],
        caps: vec![b"chat.read".to_vec()],
        update_pub: vec![0x33; 32],
        bundles: vec![EncBundle {
            group: root(),
            epoch: 1,
            ct: b"sealed group info".to_vec(),
        }],
        sig: vec![0u8; 64],
    };
    record.sig = issuer.sign(&record.digest_input()).to_bytes().to_vec();
    record
}

async fn inject(pool: &PgPool, statement: &str) {
    if let Err(error) = sqlx::query(statement).execute(pool).await {
        panic!("the injected database state must land: {statement}: {error}");
    }
}

/// Rename a table away, run something against it, and put it back.
async fn without_table<F, T>(pool: &PgPool, table: &str, body: F) -> T
where
    F: std::future::Future<Output = T>,
{
    inject(pool, &format!("alter table {table} rename to weald_parked")).await;
    let outcome = body.await;
    inject(pool, &format!("alter table weald_parked rename to {table}")).await;
    outcome
}

/// A trigger that refuses one statement class on one table.
///
/// The blunter `without_table` cannot reach every arm: a function that reads a
/// table before it writes it fails at the read, so the write's own failure path is
/// never exercised. A trigger leaves the table readable and refuses exactly the
/// statement class named.
async fn refuse(pool: &PgPool, table: &str, event: &str) {
    inject(
        pool,
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected'; end $$",
    )
    .await;
    inject(
        pool,
        &format!(
            "create trigger weald_injected_{event}_{table} before {event} on {table} \
             for each statement execute function weald_injected_refusal()"
        ),
    )
    .await;
}

async fn stop_refusing(pool: &PgPool, table: &str, event: &str) {
    inject(
        pool,
        &format!("drop trigger weald_injected_{event}_{table} on {table}"),
    )
    .await;
}

/// The one correct answer on every fault path.
#[track_caller]
fn is_told_to_come_back<T: std::fmt::Debug>(outcome: Result<T, StoreError>, what: &str) {
    match outcome {
        Err(StoreError::Database(_)) => {}
        other => panic!(
            "{what}: a relay that could not look must answer come back, and answered {other:?}"
        ),
    }
}

#[tokio::test]
async fn creating_a_record_reports_the_table_it_could_not_write() {
    let (scratch, _blobs, state) = prepared("invitefault_create").await;
    let pool = pool_of(&state);
    let record = issue(0xa1, Code::from_bits(1), 1);

    // Every table `create` touches, one at a time. The record spans four of them
    // and a partial write is the failure mode that matters: an invite row with no
    // scope rows is an invite that admits nobody and cannot be diagnosed.
    for table in [
        "relay_invite",
        "relay_invite_scope",
        "relay_invite_bundle",
        "relay_workspace",
    ] {
        let outcome = without_table(pool, table, async {
            store::create(pool, WORKSPACE, &record, NOW).await
        })
        .await;
        is_told_to_come_back(outcome, &format!("create with no {table}"));
        assert!(
            store::fetch(pool, &record.token)
                .await
                .expect("read")
                .is_none(),
            "a failed create left a record behind after {table}"
        );
    }

    // And the commit itself. Every statement lands and the transaction does not,
    // which an implementation that ignored the commit's result would report as a
    // stored invite.
    inject(
        pool,
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected'; end $$",
    )
    .await;
    inject(
        pool,
        "create constraint trigger weald_injected_commit after insert on relay_invite \
         deferrable initially deferred for each row execute function weald_injected_refusal()",
    )
    .await;
    is_told_to_come_back(
        store::create(pool, WORKSPACE, &record, NOW).await,
        "create whose commit is refused",
    );
    inject(pool, "drop trigger weald_injected_commit on relay_invite").await;

    assert!(store::fetch(pool, &record.token)
        .await
        .expect("read")
        .is_none());
    scratch.drop_database().await;
}

#[tokio::test]
async fn every_read_answers_come_back_rather_than_answering_absent() {
    let (scratch, _blobs, state) = prepared("invitefault_reads").await;
    let pool = pool_of(&state);
    let record = issue(0xb1, Code::from_bits(2), 1);
    store::create(pool, WORKSPACE, &record, NOW)
        .await
        .expect("seed");

    // "Not found" and "could not look" are different answers to a joiner, and the
    // difference decides whether they retry or throw the invite away.
    let outcome = without_table(pool, "relay_invite", async {
        store::fetch(pool, &record.token).await
    })
    .await;
    is_told_to_come_back(outcome, "fetch");

    let outcome = without_table(pool, "relay_invite", async {
        store::live_tokens(pool, WORKSPACE).await
    })
    .await;
    is_told_to_come_back(outcome, "live_tokens");

    let outcome = without_table(pool, "relay_invite_bundle", async {
        store::bundles_for(pool, &record.token, &root()).await
    })
    .await;
    is_told_to_come_back(outcome, "bundles_for");

    let outcome = without_table(pool, "relay_invite_tombstone", async {
        store::tombstoned_hashes(pool, &record.token).await
    })
    .await;
    is_told_to_come_back(outcome, "tombstoned_hashes");

    let outcome = without_table(pool, "relay_invite_attempt", async {
        reserve::attempt_volume(pool, &record.token).await
    })
    .await;
    is_told_to_come_back(outcome, "attempt_volume");

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_record_whose_stored_body_does_not_decode_is_refused_rather_than_served() {
    let (scratch, _blobs, state) = prepared("invitefault_body").await;
    let pool = pool_of(&state);
    let record = issue(0xb2, Code::from_bits(3), 1);
    store::create(pool, WORKSPACE, &record, NOW)
        .await
        .expect("seed");

    // The relay serves `body` back byte for byte rather than re-encoding from
    // columns, so that a client verifies the issuer's signature over the issuer's
    // bytes. The other side of that promise is this: a body that does not decode
    // is a refusal and not a record assembled from whatever the columns held.
    inject(
        pool,
        "update relay_invite set body = decode('ff','hex') where true",
    )
    .await;
    let outcome = store::fetch(pool, &record.token).await;
    assert!(
        matches!(outcome, Err(StoreError::Refused(_))),
        "a corrupt body was served: {outcome:?}"
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn ending_a_record_reports_every_table_it_could_not_reach() {
    let (scratch, _blobs, state) = prepared("invitefault_terminate").await;
    let pool = pool_of(&state);
    let record = issue(0xc1, Code::from_bits(4), 1);
    store::create(pool, WORKSPACE, &record, NOW)
        .await
        .expect("seed");

    // Revocation writes a tombstone before it deletes ciphertext, so each step is
    // a place the transaction can fail and each must roll the whole thing back: a
    // record with its bundles deleted and its state still live is an invite that
    // looks usable and admits nobody.
    for table in [
        "relay_invite",
        "relay_invite_reservation",
        "relay_invite_tombstone",
        "relay_invite_bundle",
    ] {
        let outcome = without_table(pool, table, async {
            store::revoke(pool, &record.token).await
        })
        .await;
        is_told_to_come_back(outcome, &format!("revoke with no {table}"));
        assert_eq!(
            store::fetch(pool, &record.token)
                .await
                .expect("read")
                .expect("the record survives")
                .state,
            store::State::Live,
            "a failed revocation changed the state anyway, after {table}"
        );
    }

    // A token that is not there is `false` rather than an error, and that path is
    // separate from every fault above.
    assert!(!store::revoke(pool, &[0x00; 16]).await.expect("read"));
    assert!(!store::mark_spent(pool, &[0x00; 16]).await.expect("read"));

    scratch.drop_database().await;
}

#[tokio::test]
async fn refreshing_a_bundle_reports_the_table_it_could_not_reach() {
    let (scratch, _blobs, state) = prepared("invitefault_refresh").await;
    let pool = pool_of(&state);
    let record = issue(0xd1, Code::from_bits(5), 1);
    store::create(pool, WORKSPACE, &record, NOW)
        .await
        .expect("seed");
    let bundle = EncBundle {
        group: root(),
        epoch: 2,
        ct: b"a fresher group info".to_vec(),
    };

    for table in ["relay_invite_scope", "relay_invite_bundle"] {
        let outcome = without_table(pool, table, async {
            store::refresh_bundle(pool, &record.token, &bundle).await
        })
        .await;
        is_told_to_come_back(outcome, &format!("refresh_bundle with no {table}"));
    }

    // A group the invite does not scope is `false`, not an error: a member
    // refreshing a bundle for the wrong group is wrong, not unlucky.
    assert!(!store::refresh_bundle(
        pool,
        &record.token,
        &EncBundle {
            group: vec![0x77; 32],
            epoch: 2,
            ct: b"not in scope".to_vec(),
        }
    )
    .await
    .expect("read"));

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_reservation_that_cannot_read_answers_come_back_and_never_unavailable() {
    let (scratch, _blobs, state) = prepared("invitefault_reserve").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(6);
    let record = issue(0xe1, code, 4);
    store::create(pool, WORKSPACE, &record, NOW)
        .await
        .expect("seed");
    let device = vec![0x52; 32];
    let source = vec![0x51; 32];

    // The distinction this test exists for: `Unavailable` is what a joiner with a
    // wrong code is told, and it is indistinguishable from "this invite is spent".
    // Answering it because a query failed would tell somebody holding a perfectly
    // good invite that their invite is dead.
    for table in [
        "relay_invite_attempt",
        "relay_invite",
        "relay_invite_reservation",
    ] {
        let outcome = without_table(pool, table, async {
            reserve::reserve(
                pool,
                &record.token,
                &code.grouped(),
                &nonce(1),
                &device,
                &source,
                NOW,
            )
            .await
        })
        .await;
        is_told_to_come_back(outcome, &format!("reserve with no {table}"));
    }

    // A code that is not even the right shape. Refused, and it costs an attempt
    // exactly as a wrong code does: the budget is per tuple and a joiner cannot
    // spend fewer attempts by sending nonsense.
    let before = reserve::attempt_volume(pool, &record.token)
        .await
        .expect("read");
    assert_eq!(
        reserve::reserve(
            pool,
            &record.token,
            "not-a-code",
            &nonce(2),
            &device,
            &source,
            NOW
        )
        .await
        .expect("read"),
        Verdict::Unavailable
    );
    let after = reserve::attempt_volume(pool, &record.token)
        .await
        .expect("read");
    assert!(
        after.failures > before.failures,
        "an unparseable code cost nothing: {before:?} then {after:?}"
    );

    // And the same request with no attempt table to record against is a database
    // answer rather than a silent success.
    let outcome = without_table(pool, "relay_invite_attempt", async {
        reserve::reserve(
            pool,
            &record.token,
            "not-a-code",
            &nonce(3),
            &device,
            &source,
            NOW,
        )
        .await
    })
    .await;
    is_told_to_come_back(outcome, "an unparseable code with no attempt table");

    scratch.drop_database().await;
}

#[tokio::test]
async fn the_seat_paths_report_the_table_they_could_not_reach() {
    let (scratch, _blobs, state) = prepared("invitefault_seats").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(7);
    let record = issue(0xf1, code, 4);
    store::create(pool, WORKSPACE, &record, NOW)
        .await
        .expect("seed");
    let device = vec![0x62; 32];
    let source = vec![0x61; 32];
    let Verdict::Reserved { .. } = reserve::reserve(
        pool,
        &record.token,
        &code.grouped(),
        &nonce(4),
        &device,
        &source,
        NOW,
    )
    .await
    .expect("a seat") else {
        panic!("the seed reservation must succeed")
    };

    for table in ["relay_invite_reservation", "relay_invite_scope_commit"] {
        let outcome = without_table(pool, table, async {
            reserve::scope_commit(pool, &record.token, &nonce(4), &device, &root(), NOW).await
        })
        .await;
        is_told_to_come_back(outcome, &format!("scope_commit with no {table}"));
    }

    let outcome = without_table(pool, "relay_invite_reservation", async {
        reserve::extend(pool, &record.token, &nonce(4)).await
    })
    .await;
    is_told_to_come_back(outcome, "extend");

    let outcome = without_table(pool, "relay_invite_reservation", async {
        reserve::release_expired(pool, NOW).await
    })
    .await;
    is_told_to_come_back(outcome, "release_expired");

    scratch.drop_database().await;
}

#[tokio::test]
async fn genesis_reports_the_table_it_could_not_reach() {
    let (scratch, _blobs, state) = prepared("invitefault_genesis").await;
    let pool = pool_of(&state);

    // First run mints the workspace's one bootstrap invite and writes entry zero
    // of the transparency log. Every table in that sequence is a place it can
    // fail, and a half-minted genesis is a workspace with a trust root nobody can
    // verify, so the whole thing has to be refused rather than partly done.
    // Entry zero of the transparency log is deliberately not in this list.
    // `invites.md` puts it at consumption, meaning acceptance of the genesis access
    // set, rather than at minting: the log begins with the workspace's trust root
    // being admitted, and minting a key nobody has redeemed is not that.
    for table in ["relay_genesis", "relay_invite", "relay_workspace"] {
        let outcome = without_table(pool, table, async {
            invite::genesis::ensure(pool, WORKSPACE, NOW).await
        })
        .await;
        is_told_to_come_back(outcome, &format!("ensure with no {table}"));
        // Scoped to this workspace: the relay bootstraps its own at startup
        // (`serve::bootstrap`), so a count over the whole table would be counting
        // that one and would say nothing about this attempt.
        let genesis_rows: i64 =
            sqlx::query_scalar("select count(*) from relay_genesis where workspace_id = $1")
                .bind(WORKSPACE)
                .fetch_one(pool)
                .await
                .expect("count");
        assert_eq!(
            genesis_rows, 0,
            "a failed genesis left a genesis row behind, after {table}"
        );
        // And no invite either. Both halves land together or neither does: an
        // invite with no genesis row is a live single-use bootstrap invite that
        // `read` cannot see, so the next call would mint a second one and the
        // workspace would have two.
        let invite_rows: i64 =
            sqlx::query_scalar("select count(*) from relay_invite where workspace_id = $1")
                .bind(WORKSPACE)
                .fetch_one(pool)
                .await
                .expect("count");
        assert_eq!(
            invite_rows, 0,
            "a failed genesis left a bootstrap invite behind, after {table}"
        );
    }

    invite::genesis::ensure(pool, WORKSPACE, NOW)
        .await
        .expect("a genesis");

    let outcome = without_table(pool, "relay_transparency_log", async {
        invite::genesis::log(pool, WORKSPACE).await
    })
    .await;
    is_told_to_come_back(outcome, "log");

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_closed_pool_answers_come_back_on_every_entry_point() {
    let (scratch, _blobs, state) = prepared("invitefault_closed").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(8);
    let record = issue(0xa9, code, 1);
    store::create(pool, WORKSPACE, &record, NOW)
        .await
        .expect("seed");
    pool.close().await;

    is_told_to_come_back(store::create(pool, WORKSPACE, &record, NOW).await, "create");
    is_told_to_come_back(store::fetch(pool, &record.token).await, "fetch");
    is_told_to_come_back(store::live_tokens(pool, WORKSPACE).await, "live_tokens");
    is_told_to_come_back(store::revoke(pool, &record.token).await, "revoke");
    is_told_to_come_back(store::mark_spent(pool, &record.token).await, "mark_spent");
    is_told_to_come_back(
        store::tombstoned_hashes(pool, &record.token).await,
        "tombstoned_hashes",
    );
    is_told_to_come_back(
        store::bundles_for(pool, &record.token, &root()).await,
        "bundles_for",
    );
    is_told_to_come_back(
        store::refresh_bundle(
            pool,
            &record.token,
            &EncBundle {
                group: root(),
                epoch: 3,
                ct: b"ct".to_vec(),
            },
        )
        .await,
        "refresh_bundle",
    );
    is_told_to_come_back(
        reserve::reserve(
            pool,
            &record.token,
            &code.grouped(),
            &nonce(9),
            &[0x72; 32],
            &[0x71; 32],
            NOW,
        )
        .await,
        "reserve",
    );
    is_told_to_come_back(
        reserve::scope_commit(pool, &record.token, &nonce(9), &[0x72; 32], &root(), NOW).await,
        "scope_commit",
    );
    is_told_to_come_back(
        reserve::extend(pool, &record.token, &nonce(9)).await,
        "extend",
    );
    is_told_to_come_back(reserve::release_expired(pool, NOW).await, "release_expired");
    is_told_to_come_back(
        reserve::attempt_volume(pool, &record.token).await,
        "attempt_volume",
    );
    is_told_to_come_back(
        invite::genesis::ensure(pool, WORKSPACE, NOW).await,
        "genesis::ensure",
    );
    is_told_to_come_back(invite::genesis::log(pool, WORKSPACE).await, "genesis::log");

    scratch.drop_database().await;
}

// MARK: The arms a parked table cannot reach

#[tokio::test]
async fn a_failed_attempt_that_cannot_be_recorded_is_reported_rather_than_swallowed() {
    let (scratch, _blobs, state) = prepared("invitefault_attempt").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(11);
    let record = issue(0xb5, code, 2);
    store::create(pool, WORKSPACE, &record, NOW)
        .await
        .expect("seed");
    let device = vec![0x82; 32];
    let source = vec![0x81; 32];

    // The attempt budget is the whole of the brute-force defence on a 12-character
    // code. A failure the relay could not record is a failure that did not count,
    // so an attacker whose guesses all coincided with a write outage would get
    // unlimited tries. The refusal has to reach the caller.
    refuse(pool, "relay_invite_attempt", "insert").await;
    is_told_to_come_back(
        reserve::reserve(
            pool,
            &record.token,
            &Code::from_bits(0xbad).grouped(),
            &nonce(5),
            &device,
            &source,
            NOW,
        )
        .await,
        "a wrong code whose attempt cannot be recorded",
    );
    is_told_to_come_back(
        reserve::reserve(
            pool,
            &record.token,
            "not-a-code",
            &nonce(5),
            &device,
            &source,
            NOW,
        )
        .await,
        "an unparseable code whose attempt cannot be recorded",
    );
    stop_refusing(pool, "relay_invite_attempt", "insert").await;

    // The seat is intact: a refused write is not a spent invite.
    assert_eq!(
        store::fetch(pool, &record.token)
            .await
            .expect("read")
            .expect("the record")
            .remaining,
        2
    );
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_seat_that_cannot_be_taken_is_reported_rather_than_reported_as_taken() {
    let (scratch, _blobs, state) = prepared("invitefault_seat").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(12);
    let record = issue(0xb6, code, 2);
    store::create(pool, WORKSPACE, &record, NOW)
        .await
        .expect("seed");
    let device = vec![0x84; 32];
    let source = vec![0x83; 32];

    // The seat decrement and the reservation insert are one statement, so this is
    // the arm where the invite is live, the code is right, and the write fails.
    refuse(pool, "relay_invite_reservation", "insert").await;
    is_told_to_come_back(
        reserve::reserve(
            pool,
            &record.token,
            &code.grouped(),
            &nonce(6),
            &device,
            &source,
            NOW,
        )
        .await,
        "a reservation that cannot be written",
    );
    stop_refusing(pool, "relay_invite_reservation", "insert").await;

    // And the provisional grant, which is the other half of a reservation: a seat
    // taken with no grant behind it is a joiner who cannot open the socket the
    // external commit needs, and reporting success there would strand them.
    refuse(pool, "relay_provisional_grant", "insert").await;
    is_told_to_come_back(
        reserve::reserve(
            pool,
            &record.token,
            &code.grouped(),
            &nonce(7),
            &device,
            &source,
            NOW,
        )
        .await,
        "a reservation whose grant cannot be written",
    );
    stop_refusing(pool, "relay_provisional_grant", "insert").await;

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_scope_commit_reports_every_statement_it_could_not_run() {
    let (scratch, _blobs, state) = prepared("invitefault_commit").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(13);
    let record = issue(0xb7, code, 8);
    store::create(pool, WORKSPACE, &record, NOW)
        .await
        .expect("seed");
    let device = vec![0x86; 32];
    let source = vec![0x85; 32];

    // A fresh seat per fault. A scope commit that succeeds consumes the
    // reservation, and a consumed reservation takes a different path, so reusing
    // one would quietly stop testing the arm it was aimed at.
    let seat = |n: u8| {
        let token = record.token.clone();
        let device = device.clone();
        let source = source.clone();
        async move {
            reserve::reserve(
                pool,
                &token,
                &code.grouped(),
                &nonce(n),
                &device,
                &source,
                NOW,
            )
            .await
            .expect("a seat");
        }
    };

    // The scope check, the commit write, the count, and then the consumption that
    // spends the seat and issues the durable grant. Each is a place the relay can
    // fail after the joiner has already committed to a group, and each has to be a
    // "come back" rather than a silent half-join.
    seat(20).await;
    let outcome = without_table(pool, "relay_invite_scope", async {
        reserve::scope_commit(pool, &record.token, &nonce(20), &device, &root(), NOW).await
    })
    .await;
    is_told_to_come_back(outcome, "scope_commit with no relay_invite_scope");

    seat(21).await;
    refuse(pool, "relay_invite_scope_commit", "insert").await;
    is_told_to_come_back(
        reserve::scope_commit(pool, &record.token, &nonce(21), &device, &root(), NOW).await,
        "scope_commit whose receipt cannot be written",
    );
    stop_refusing(pool, "relay_invite_scope_commit", "insert").await;

    seat(22).await;
    refuse(pool, "relay_invite_reservation", "update").await;
    is_told_to_come_back(
        reserve::scope_commit(pool, &record.token, &nonce(22), &device, &root(), NOW).await,
        "scope_commit whose consumption cannot be recorded",
    );
    stop_refusing(pool, "relay_invite_reservation", "update").await;

    seat(23).await;
    refuse(pool, "relay_provisional_grant", "update").await;
    is_told_to_come_back(
        reserve::scope_commit(pool, &record.token, &nonce(23), &device, &root(), NOW).await,
        "scope_commit whose durable grant cannot be written",
    );
    stop_refusing(pool, "relay_provisional_grant", "update").await;

    scratch.drop_database().await;
}

#[tokio::test]
async fn ending_a_record_reports_the_statement_it_could_not_run() {
    let (scratch, _blobs, state) = prepared("invitefault_terminate2").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(14);
    let record = issue(0xb8, code, 2);
    store::create(pool, WORKSPACE, &record, NOW)
        .await
        .expect("seed");
    let device = vec![0x88; 32];
    let source = vec![0x87; 32];
    reserve::reserve(
        pool,
        &record.token,
        &code.grouped(),
        &nonce(9),
        &device,
        &source,
        NOW,
    )
    .await
    .expect("a seat");

    // The state change itself, which `without_table` cannot reach because the same
    // table is read first.
    refuse(pool, "relay_invite", "update").await;
    is_told_to_come_back(
        store::revoke(pool, &record.token).await,
        "revoke whose state change is refused",
    );
    stop_refusing(pool, "relay_invite", "update").await;

    // And the grant revocation, which happens after the transaction commits: the
    // invite is revoked and a device it admitted still holds a live grant. Reported
    // rather than swallowed, because that gap is exactly what an admin revoking an
    // invite is trying to close.
    refuse(pool, "relay_provisional_grant", "update").await;
    is_told_to_come_back(
        store::revoke(pool, &record.token).await,
        "revoke whose grants cannot be voided",
    );
    stop_refusing(pool, "relay_provisional_grant", "update").await;

    scratch.drop_database().await;
}

#[tokio::test]
async fn refreshing_a_bundle_reports_the_statement_it_could_not_run() {
    let (scratch, _blobs, state) = prepared("invitefault_refresh2").await;
    let pool = pool_of(&state);
    let record = issue(0xb9, Code::from_bits(15), 1);
    store::create(pool, WORKSPACE, &record, NOW)
        .await
        .expect("seed");
    let bundle = EncBundle {
        group: root(),
        epoch: 2,
        ct: b"a fresher group info".to_vec(),
    };

    // The retention step: three candidates are kept per (token, group), so the
    // refresh writes and then deletes. A delete that fails must not be reported as
    // a successful refresh, or the table grows without bound under a client that
    // republishes on every commit.
    refuse(pool, "relay_invite_bundle", "delete").await;
    is_told_to_come_back(
        store::refresh_bundle(pool, &record.token, &bundle).await,
        "refresh_bundle whose retention delete is refused",
    );
    stop_refusing(pool, "relay_invite_bundle", "delete").await;

    refuse(pool, "relay_invite_bundle", "insert").await;
    is_told_to_come_back(
        store::refresh_bundle(pool, &record.token, &bundle).await,
        "refresh_bundle whose insert is refused",
    );
    stop_refusing(pool, "relay_invite_bundle", "insert").await;

    scratch.drop_database().await;
}

#[tokio::test]
async fn minting_genesis_reports_the_statement_it_could_not_run() {
    let (scratch, _blobs, state) = prepared("invitefault_mint").await;
    let pool = pool_of(&state);

    // `relay_genesis` is read before it is written, so parking the table fails at
    // the read and the write's own arm needs a trigger.
    refuse(pool, "relay_genesis", "insert").await;
    is_told_to_come_back(
        invite::genesis::ensure(pool, WORKSPACE, NOW).await,
        "ensure whose genesis row is refused",
    );
    stop_refusing(pool, "relay_genesis", "insert").await;

    // And at commit, after every statement has succeeded.
    inject(
        pool,
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected'; end $$",
    )
    .await;
    inject(
        pool,
        "create constraint trigger weald_injected_commit after insert on relay_genesis \
         deferrable initially deferred for each row execute function weald_injected_refusal()",
    )
    .await;
    is_told_to_come_back(
        invite::genesis::ensure(pool, WORKSPACE, NOW).await,
        "ensure whose commit is refused",
    );
    inject(pool, "drop trigger weald_injected_commit on relay_genesis").await;

    // Nothing survives either attempt, and the workspace can still be minted once.
    let invites: i64 =
        sqlx::query_scalar("select count(*) from relay_invite where workspace_id = $1")
            .bind(WORKSPACE)
            .fetch_one(pool)
            .await
            .expect("count");
    assert_eq!(invites, 0);
    invite::genesis::ensure(pool, WORKSPACE, NOW)
        .await
        .expect("a genesis");
    let invites: i64 =
        sqlx::query_scalar("select count(*) from relay_invite where workspace_id = $1")
            .bind(WORKSPACE)
            .fetch_one(pool)
            .await
            .expect("count");
    assert_eq!(invites, 1, "exactly one bootstrap invite, ever");

    scratch.drop_database().await;
}

#[tokio::test]
async fn the_last_reads_and_the_last_commit_are_reported_too() {
    let (scratch, _blobs, state) = prepared("invitefault_tail").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(16);
    let record = issue(0xba, code, 4);
    store::create(pool, WORKSPACE, &record, NOW)
        .await
        .expect("seed");
    let device = vec![0x8a; 32];
    let source = vec![0x89; 32];
    reserve::reserve(
        pool,
        &record.token,
        &code.grouped(),
        &nonce(30),
        &device,
        &source,
        NOW,
    )
    .await
    .expect("a seat");

    // The scope lookup inside `scope_commit`, which a parked table cannot reach
    // because an earlier query counts the same table through a subselect that does
    // not touch this column. Renaming the column is the narrower fault and it hits
    // exactly the statement this arm is about.
    inject(
        pool,
        "alter table relay_invite_scope rename column group_id to weald_parked_column",
    )
    .await;
    is_told_to_come_back(
        reserve::scope_commit(pool, &record.token, &nonce(30), &device, &root(), NOW).await,
        "scope_commit whose scope lookup fails",
    );
    inject(
        pool,
        "alter table relay_invite_scope rename column weald_parked_column to group_id",
    )
    .await;

    // Revocation's commit, after every statement in it has succeeded. A
    // transaction reported as done that did not commit would leave an invite live
    // that an admin has been told is revoked.
    inject(
        pool,
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected'; end $$",
    )
    .await;
    inject(
        pool,
        "create constraint trigger weald_injected_commit after update on relay_invite \
         deferrable initially deferred for each row execute function weald_injected_refusal()",
    )
    .await;
    is_told_to_come_back(
        store::revoke(pool, &record.token).await,
        "revoke whose commit is refused",
    );
    inject(pool, "drop trigger weald_injected_commit on relay_invite").await;
    assert_eq!(
        store::fetch(pool, &record.token)
            .await
            .expect("read")
            .expect("the record")
            .state,
        store::State::Live,
        "a refused commit revoked the invite anyway"
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_scope_commit_that_cannot_count_what_it_wrote_is_reported() {
    let (scratch, _blobs, state) = prepared("invitefault_count").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(17);
    let record = issue(0xbb, code, 4);
    store::create(pool, WORKSPACE, &record, NOW)
        .await
        .expect("seed");
    let device = vec![0x8c; 32];
    let source = vec![0x8b; 32];
    reserve::reserve(
        pool,
        &record.token,
        &code.grouped(),
        &nonce(31),
        &device,
        &source,
        NOW,
    )
    .await
    .expect("a seat");

    // The count decides whether the seat is spent, so a failed count must not read
    // as "not all scopes committed yet": that would leave a reservation live and
    // the joiner's grant provisional for ever.
    //
    // The receipt is written and then counted, both against the same table, so
    // neither a parked table nor a trigger can separate them: parking breaks the
    // write and triggers do not fire on `select`. A view over the real table can:
    // an insert through an auto-updatable view is rewritten onto the base table
    // and never evaluates the view's `where`, while every select does.
    inject(
        pool,
        "alter table relay_invite_scope_commit rename to weald_real_commit",
    )
    .await;
    inject(
        pool,
        "create view relay_invite_scope_commit as \
         select token, join_nonce, group_id, receipt from weald_real_commit \
         where 1 / (case when true then 0 else 1 end) = 1",
    )
    .await;

    is_told_to_come_back(
        reserve::scope_commit(pool, &record.token, &nonce(31), &device, &root(), NOW).await,
        "scope_commit whose count cannot run",
    );

    inject(pool, "drop view relay_invite_scope_commit").await;
    inject(
        pool,
        "alter table weald_real_commit rename to relay_invite_scope_commit",
    )
    .await;

    // And the same commit succeeds once the view is gone, so the fault was the
    // read and nothing else.
    assert!(
        reserve::scope_commit(pool, &record.token, &nonce(31), &device, &root(), NOW)
            .await
            .expect("read")
            .is_some()
    );

    scratch.drop_database().await;
}
