// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! What the recovery wrap store answers when the database cannot answer it.
//!
//! `tests/recovery_store.rs` proves the store right when Postgres works. This file
//! proves it right when Postgres does not. Every statement behind a wrap has a
//! failure path, and the only correct answer on all of them is
//! `StoreError::Database`: a relay that could not write a wrap must say "come
//! back", never report a wrap as stored when it did not land, never report a slot
//! as empty because the read failed, and never panic.
//!
//! The stakes are specific rather than generic. A `publish` that returned success
//! on a failed write would leave a person with no wrap for a group at the epoch
//! they need, and they would find out during a recovery, which is the one flow
//! whose entire purpose is not losing data.
//!
//! Nothing here is a mock. Every fault is a real state of a real Postgres in a
//! database of this test's own: a dropped table, a trigger that refuses a write, a
//! closed pool. Faults are injected one statement at a time, because a function
//! whose first statement fails never reaches its third.

mod support;

use std::sync::Arc;

use sqlx::PgPool;
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::recovery::store::{self, StoreError};
use wealdrelay::recovery::RecoveryWrap;

use support::{config_for, make_group, Running, Scratch};

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

fn wrap(group: &[u8], tag: u8, epoch: u64, ct: &[u8]) -> RecoveryWrap {
    RecoveryWrap {
        group: group.to_vec(),
        epoch,
        tag: vec![tag; 32],
        ct: ct.to_vec(),
    }
}

async fn inject(pool: &PgPool, statement: &str) {
    if let Err(error) = sqlx::query(statement).execute(pool).await {
        panic!("the injected database state must land: {statement}: {error}");
    }
}

/// A trigger that refuses whatever write it is attached to.
async fn refuse_statements(pool: &PgPool, table: &str, event: &str) {
    inject(
        pool,
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected: this write cannot land'; end $$",
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

/// The one correct answer on every fault path.
#[track_caller]
fn is_told_to_come_back<T: std::fmt::Debug>(outcome: Result<T, StoreError>, what: &str) {
    match outcome {
        Err(StoreError::Database(_)) => {}
        other => panic!(
            "{what}: a relay that could not write must answer come back, and answered {other:?}"
        ),
    }
}

#[tokio::test]
async fn every_read_answers_come_back_rather_than_answering_empty() {
    let (scratch, _blobs, state) = prepared("wrapfault_reads").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x21).await;
    store::publish(pool, &wrap(&group, 0x01, 1, b"ct"))
        .await
        .expect("seed");

    // A slot that cannot be read is not a slot that is empty. The difference is
    // the difference between "the relay is having a bad minute" and "your wrap is
    // gone", and a client acts very differently on the two.
    inject(
        pool,
        "alter table relay_recovery_wrap rename to parked_away",
    )
    .await;
    is_told_to_come_back(store::current(pool, &group, &[0x01; 32]).await, "current");
    is_told_to_come_back(store::for_group(pool, &group).await, "for_group");
    inject(
        pool,
        "alter table parked_away rename to relay_recovery_wrap",
    )
    .await;

    inject(
        pool,
        "alter table relay_recovery_wrap_prior rename to parked_away",
    )
    .await;
    is_told_to_come_back(store::prior(pool, &group, &[0x01; 32]).await, "prior");
    is_told_to_come_back(store::sweep_prior(pool).await, "sweep_prior");
    inject(
        pool,
        "alter table parked_away rename to relay_recovery_wrap_prior",
    )
    .await;

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_publication_that_cannot_read_the_slot_is_not_a_publication() {
    let (scratch, _blobs, state) = prepared("wrapfault_lock").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x22).await;

    // The `for update` read is the first statement and the whole concurrency
    // control. If it cannot run, nothing below it may run either.
    inject(
        pool,
        "alter table relay_recovery_wrap rename to parked_away",
    )
    .await;
    is_told_to_come_back(
        store::publish(pool, &wrap(&group, 0x02, 1, b"ct")).await,
        "publish with no table to lock",
    );
    inject(
        pool,
        "alter table parked_away rename to relay_recovery_wrap",
    )
    .await;

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_refused_insert_is_reported_rather_than_reported_as_stored() {
    let (scratch, _blobs, state) = prepared("wrapfault_insert").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x23).await;

    refuse_statements(pool, "relay_recovery_wrap", "insert").await;
    is_told_to_come_back(
        store::publish(pool, &wrap(&group, 0x03, 1, b"ct")).await,
        "publish into a table that refuses inserts",
    );
    inject(
        pool,
        "drop trigger weald_injected_insert_relay_recovery_wrap on relay_recovery_wrap",
    )
    .await;

    // And the transaction rolled back, so there is no half-written slot.
    assert!(store::for_group(pool, &group)
        .await
        .expect("read")
        .is_empty());

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_replacement_that_cannot_park_the_old_wrap_does_not_overwrite_the_new_one() {
    let (scratch, _blobs, state) = prepared("wrapfault_park").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x24).await;
    store::publish(pool, &wrap(&group, 0x04, 1, b"first"))
        .await
        .expect("seed");

    // This is the fault with the worst failure mode if it were ignored: the prior
    // slot is the availability guarantee for a recovery that arrives mid-handoff,
    // so a replacement that silently skipped parking would narrow that window to
    // nothing without anybody noticing. The whole publication is refused instead.
    refuse_statements(pool, "relay_recovery_wrap_prior", "insert").await;
    is_told_to_come_back(
        store::publish(pool, &wrap(&group, 0x04, 2, b"second")).await,
        "publish when the prior slot cannot be written",
    );
    inject(
        pool,
        "drop trigger weald_injected_insert_relay_recovery_wrap_prior on relay_recovery_wrap_prior",
    )
    .await;

    // The current slot is untouched: still the wrap that was really current.
    let current = store::current(pool, &group, &[0x04; 32])
        .await
        .expect("read")
        .expect("a wrap");
    assert_eq!(current.epoch, 1);
    assert_eq!(current.ct, b"first".to_vec());

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_replacement_that_cannot_install_the_new_wrap_leaves_the_old_one_current() {
    let (scratch, _blobs, state) = prepared("wrapfault_install").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x25).await;
    store::publish(pool, &wrap(&group, 0x05, 1, b"first"))
        .await
        .expect("seed");

    refuse_statements(pool, "relay_recovery_wrap", "update").await;
    is_told_to_come_back(
        store::publish(pool, &wrap(&group, 0x05, 2, b"second")).await,
        "publish when the current slot cannot be updated",
    );
    inject(
        pool,
        "drop trigger weald_injected_update_relay_recovery_wrap on relay_recovery_wrap",
    )
    .await;

    let current = store::current(pool, &group, &[0x05; 32])
        .await
        .expect("read")
        .expect("a wrap");
    assert_eq!(current.epoch, 1);
    // The rollback took the parked row with it, so the prior slot does not hold a
    // wrap that was never superseded.
    assert_eq!(
        store::prior(pool, &group, &[0x05; 32]).await.expect("read"),
        None
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn removal_that_cannot_delete_says_so_rather_than_reporting_a_removal() {
    let (scratch, _blobs, state) = prepared("wrapfault_forget").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x26).await;
    store::publish(pool, &wrap(&group, 0x06, 1, b"one"))
        .await
        .expect("seed");
    store::publish(pool, &wrap(&group, 0x06, 2, b"two"))
        .await
        .expect("replace");

    // Offboarding is the caller here, and a delete reported as done that did not
    // happen would leave a departed person's wrap in place while the roster said
    // they were gone.
    refuse_statements(pool, "relay_recovery_wrap", "delete").await;
    is_told_to_come_back(
        store::forget(pool, &group, &[vec![0x06; 32]]).await,
        "forget the current slot",
    );
    inject(
        pool,
        "drop trigger weald_injected_delete_relay_recovery_wrap on relay_recovery_wrap",
    )
    .await;

    refuse_statements(pool, "relay_recovery_wrap_prior", "delete").await;
    is_told_to_come_back(
        store::forget(pool, &group, &[vec![0x06; 32]]).await,
        "forget the prior slot",
    );
    inject(
        pool,
        "drop trigger weald_injected_delete_relay_recovery_wrap_prior on relay_recovery_wrap_prior",
    )
    .await;

    scratch.drop_database().await;
}

#[tokio::test]
async fn losing_the_race_for_an_empty_slot_is_told_the_same_thing_a_replay_is_told() {
    let (scratch, _blobs, state) = prepared("wrapfault_race").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x2A).await;

    // The one branch a real race reaches only sometimes, made deterministic. Both
    // committers find the slot empty, so neither has a row to lock: `for update`
    // locks rows that exist and there is nothing there yet. The loser's insert
    // conflicts and affects nothing, and it must then be told what a replay is
    // told rather than reporting a publication that did not happen.
    //
    // The other writer is a trigger that inserts the winning row and suppresses
    // the incoming one, which is exactly the state the loser's transaction would
    // observe. A real Postgres, a real conflict, no test double: the alternative
    // is `tokio::join!` and hoping the interleaving lands, which is a test that
    // passes for reasons nobody controls.
    inject(
        pool,
        "create or replace function weald_injected_race() returns trigger language plpgsql \
         as $$ begin \
           if pg_trigger_depth() = 1 then \
             insert into relay_recovery_wrap (group_id, tag, epoch, ct) \
               values (new.group_id, new.tag, 99, new.ct); \
             return null; \
           end if; \
           return new; \
         end $$",
    )
    .await;
    inject(
        pool,
        "create trigger weald_injected_race before insert on relay_recovery_wrap \
         for each row execute function weald_injected_race()",
    )
    .await;

    let outcome = store::publish(pool, &wrap(&group, 0x0A, 1, b"the loser")).await;
    match outcome {
        Err(StoreError::Refused(wealdrelay::recovery::WrapError::NotNewer { stored, offered })) => {
            assert_eq!(stored, 99, "the refusal names the epoch that won");
            assert_eq!(offered, 1);
        }
        other => panic!("expected the loser to be refused, got {other:?}"),
    }

    inject(
        pool,
        "drop trigger weald_injected_race on relay_recovery_wrap",
    )
    .await;
    // Nothing of the loser's survives. In this simulation the winning row was
    // written by a trigger inside the loser's own transaction, so the refusal
    // rolls it back too, and the slot is empty rather than holding epoch 99. That
    // is the honest reading of what this test proves and what it does not: the
    // loser's answer is proven here, the winner's row surviving is proven in
    // `recovery_store.rs` by two real transactions.
    let held = store::for_group(pool, &group).await.expect("read");
    assert!(
        held.is_empty(),
        "the refused transaction left something behind: {held:?}"
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_suppressed_insert_with_nothing_in_the_slot_is_still_come_back() {
    let (scratch, _blobs, state) = prepared("wrapfault_vanished").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x2B).await;

    // The insert affects nothing and the slot is still empty afterwards, which is
    // not a state either branch of `publish` expects: it is neither "somebody else
    // won" nor "this landed". The relay must say come back rather than reporting a
    // publication or inventing a winner.
    inject(
        pool,
        "create or replace function weald_injected_vanish() returns trigger \
         language plpgsql as $$ begin return null; end $$",
    )
    .await;
    inject(
        pool,
        "create trigger weald_injected_vanish before insert on relay_recovery_wrap \
         for each row execute function weald_injected_vanish()",
    )
    .await;

    is_told_to_come_back(
        store::publish(pool, &wrap(&group, 0x0B, 1, b"ct")).await,
        "publish whose insert vanished",
    );

    inject(
        pool,
        "drop trigger weald_injected_vanish on relay_recovery_wrap",
    )
    .await;
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_transaction_that_fails_at_commit_is_not_a_stored_wrap() {
    let (scratch, _blobs, state) = prepared("wrapfault_commit").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x2C).await;

    // Every statement succeeds and the commit does not. This is the failure that
    // an implementation which returned before committing, or which ignored the
    // commit's result, would report as success: the caller would believe a wrap
    // exists for this epoch and nothing would be there.
    inject(
        pool,
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected: not at commit time'; end $$",
    )
    .await;
    inject(
        pool,
        "create constraint trigger weald_injected_commit after insert on relay_recovery_wrap \
         deferrable initially deferred for each row execute function weald_injected_refusal()",
    )
    .await;

    is_told_to_come_back(
        store::publish(pool, &wrap(&group, 0x0C, 1, b"ct")).await,
        "publish whose commit is refused",
    );

    inject(
        pool,
        "drop trigger weald_injected_commit on relay_recovery_wrap",
    )
    .await;
    assert!(store::for_group(pool, &group)
        .await
        .expect("read")
        .is_empty());
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_row_whose_epoch_is_not_a_number_is_reported_rather_than_decoded() {
    let (scratch, _blobs, state) = prepared("wrapfault_epoch").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x27).await;
    store::publish(pool, &wrap(&group, 0x07, 1, b"ct"))
        .await
        .expect("seed");

    // A column that is not the type the reader expects. Unreachable through this
    // crate's own writes, which is the point: the reader must answer "come back"
    // for a row it cannot make sense of rather than panicking inside a `try_get`.
    inject(
        pool,
        "alter table relay_recovery_wrap drop constraint relay_recovery_wrap_epoch_not_negative",
    )
    .await;
    inject(
        pool,
        "alter table relay_recovery_wrap alter column epoch type text using epoch::text",
    )
    .await;
    is_told_to_come_back(store::current(pool, &group, &[0x07; 32]).await, "current");
    is_told_to_come_back(store::for_group(pool, &group).await, "for_group");

    scratch.drop_database().await;
}

/// One database per undecodable column, deliberately.
///
/// The first version of this did all three in one test and only the first one
/// counted. Changing a column's type or its nullability invalidates Postgres's
/// cached plan for every prepared statement over that table, so the second
/// injection's failure arrives as "cached plan must not change result type" from
/// the query and the decode path is never reached. The test still passed, because
/// the answer is `Database` either way, and the coverage report was the only thing
/// that noticed. A separate database per column is what makes each case actually
/// exercise the field it names.
#[tokio::test]
async fn a_row_with_a_null_tag_is_reported_rather_than_decoded() {
    let (scratch, _blobs, state) = prepared("wrapfault_nulltag").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x2D).await;
    store::publish(pool, &wrap(&group, 0x0D, 1, b"ct"))
        .await
        .expect("seed");

    inject(
        pool,
        "alter table relay_recovery_wrap drop constraint relay_recovery_wrap_pkey",
    )
    .await;
    inject(
        pool,
        "alter table relay_recovery_wrap alter column tag drop not null",
    )
    .await;
    inject(pool, "update relay_recovery_wrap set tag = null").await;

    is_told_to_come_back(
        store::for_group(pool, &group).await,
        "for_group with a null tag",
    );
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_row_with_a_null_ciphertext_is_reported_rather_than_decoded() {
    let (scratch, _blobs, state) = prepared("wrapfault_nullct").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x2E).await;
    store::publish(pool, &wrap(&group, 0x0E, 1, b"ct"))
        .await
        .expect("seed");

    // The last field the reader takes. A reader that handled the first field's
    // failure and unwrapped the last would still panic on a row it could not read,
    // and a panic inside a connection handler is a dropped socket rather than a
    // "come back".
    inject(
        pool,
        "alter table relay_recovery_wrap drop constraint relay_recovery_wrap_ct_is_not_empty",
    )
    .await;
    inject(
        pool,
        "alter table relay_recovery_wrap alter column ct drop not null",
    )
    .await;
    inject(pool, "update relay_recovery_wrap set ct = null").await;

    is_told_to_come_back(
        store::for_group(pool, &group).await,
        "for_group with a null ct",
    );
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_closed_pool_answers_come_back_on_every_entry_point() {
    let (scratch, _blobs, state) = prepared("wrapfault_closed").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x28).await;
    pool.close().await;

    is_told_to_come_back(
        store::publish(pool, &wrap(&group, 0x08, 1, b"ct")).await,
        "publish",
    );
    is_told_to_come_back(store::current(pool, &group, &[0x08; 32]).await, "current");
    is_told_to_come_back(store::prior(pool, &group, &[0x08; 32]).await, "prior");
    is_told_to_come_back(store::for_group(pool, &group).await, "for_group");
    is_told_to_come_back(store::sweep_prior(pool).await, "sweep_prior");
    is_told_to_come_back(
        store::forget(pool, &group, &[vec![0x08; 32]]).await,
        "forget",
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_database_message_carrying_a_credential_is_scrubbed_before_it_is_reported() {
    let (scratch, _blobs, state) = prepared("wrapfault_scrub").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x29).await;

    // Postgres puts the text of a failed statement into some errors, and a relay
    // that logged one verbatim would be a relay that logs whatever a message
    // happened to contain. `logging::scrub` is applied on the way out, so the
    // check here is that the path runs at all rather than that scrub works, which
    // is `tests/logging.rs`.
    inject(
        pool,
        "create or replace function weald_injected_refusal() returns trigger language plpgsql \
         as $$ begin raise exception 'injected postgres://weald:hunter2@127.0.0.1:5432/x'; end $$",
    )
    .await;
    inject(
        pool,
        "create trigger weald_injected_scrub before insert on relay_recovery_wrap \
         for each statement execute function weald_injected_refusal()",
    )
    .await;

    let error = store::publish(pool, &wrap(&group, 0x09, 1, b"ct"))
        .await
        .expect_err("the trigger refuses");
    let message = error.to_string();
    assert!(
        !message.contains("hunter2"),
        "a credential reached the error text: {message}"
    );

    scratch.drop_database().await;
}
