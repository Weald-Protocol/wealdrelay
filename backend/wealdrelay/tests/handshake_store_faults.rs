// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! What the handshake store answers when the database cannot answer it.
//!
//! The stakes here are the group's continuity. A commit reported as stored that
//! did not land is a member that believes the group is at epoch N+1 while everyone
//! else is at N, and MLS has no way back from that except somebody committing
//! again. A replay that came back short is a joining member holding a tree it
//! cannot decrypt against. So every failure path answers `Database`, meaning come
//! back, and never a sequence number or a short list.
//!
//! Nothing here is mocked: the faults are real states of a real Postgres, one
//! statement at a time.

mod support;

use std::sync::Arc;

use sqlx::PgPool;
use wealdrelay::handshake::store::{self, StoreError};
use wealdrelay::handshake::Handshake;
use wealdrelay::health::{Clock, RelayState};

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

fn message(group: &[u8], body: &[u8]) -> Handshake {
    Handshake {
        group: group.to_vec(),
        message: body.to_vec(),
    }
}

async fn inject(pool: &PgPool, statement: &str) {
    if let Err(error) = sqlx::query(statement).execute(pool).await {
        panic!("the injected database state must land: {statement}: {error}");
    }
}

#[track_caller]
fn is_told_to_come_back<T: std::fmt::Debug>(outcome: Result<T, StoreError>, what: &str) {
    match outcome {
        Err(StoreError::Database(_)) => {}
        other => panic!(
            "{what}: a relay that could not store a commit must answer come back, and answered \
             {other:?}"
        ),
    }
}

#[tokio::test]
async fn an_append_that_cannot_run_is_never_reported_as_stored() {
    let (scratch, _blobs, state) = prepared("handshakefault_append").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x31).await;

    // The group lock, which is the first statement and the whole ordering
    // guarantee. If it cannot run, nothing below it may.
    inject(pool, "alter table relay_group rename to weald_parked").await;
    is_told_to_come_back(
        store::append(pool, &message(&group, b"a commit")).await,
        "append with no group table to lock",
    );
    inject(pool, "alter table weald_parked rename to relay_group").await;

    // The duplicate check and the sequence read, both against the handshake table.
    inject(pool, "alter table relay_handshake rename to weald_parked").await;
    is_told_to_come_back(
        store::append(pool, &message(&group, b"a commit")).await,
        "append with no handshake table",
    );
    is_told_to_come_back(store::since(pool, &group, 0).await, "since");
    is_told_to_come_back(store::head(pool, &group).await, "head");
    inject(pool, "alter table weald_parked rename to relay_handshake").await;

    // The insert itself.
    inject(
        pool,
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected'; end $$",
    )
    .await;
    inject(
        pool,
        "create trigger weald_injected before insert on relay_handshake \
         for each statement execute function weald_injected_refusal()",
    )
    .await;
    is_told_to_come_back(
        store::append(pool, &message(&group, b"a commit")).await,
        "append whose insert is refused",
    );
    inject(pool, "drop trigger weald_injected on relay_handshake").await;

    // And the commit, after every statement has succeeded. An implementation that
    // ignored the commit's result would hand the publisher a sequence number for a
    // message no other member will ever see.
    inject(
        pool,
        "create constraint trigger weald_injected_commit after insert on relay_handshake \
         deferrable initially deferred for each row execute function weald_injected_refusal()",
    )
    .await;
    is_told_to_come_back(
        store::append(pool, &message(&group, b"a commit")).await,
        "append whose commit is refused",
    );
    inject(
        pool,
        "drop trigger weald_injected_commit on relay_handshake",
    )
    .await;

    // Nothing landed through any of that, so the order still starts at zero.
    assert_eq!(store::head(pool, &group).await.expect("head"), 0);
    assert_eq!(
        store::append(pool, &message(&group, b"a commit"))
            .await
            .expect("the retry lands")
            .seq(),
        0
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_replay_that_cannot_be_decoded_is_reported_rather_than_returned_short() {
    let (scratch, _blobs, state) = prepared("handshakefault_replay").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x32).await;
    store::append(pool, &message(&group, b"a commit"))
        .await
        .expect("seed");

    // A short replay is worse than no replay: a member would apply what it got,
    // believe it was current, and then fail to decrypt everything published since.
    // So a row the reader cannot decode is a refusal and not a shorter list.
    //
    // Nulled rather than retyped, because changing a column's type invalidates
    // Postgres's cached plan and the failure then arrives from the query rather
    // than from the decode.
    inject(
        pool,
        "alter table relay_handshake alter column message drop not null",
    )
    .await;
    inject(pool, "update relay_handshake set message = null").await;
    is_told_to_come_back(
        store::since(pool, &group, 0).await,
        "since with a null message",
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_closed_pool_answers_come_back_on_every_entry_point() {
    let (scratch, _blobs, state) = prepared("handshakefault_closed").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x34).await;
    pool.close().await;

    is_told_to_come_back(
        store::append(pool, &message(&group, b"a commit")).await,
        "append",
    );
    is_told_to_come_back(store::since(pool, &group, 0).await, "since");
    is_told_to_come_back(store::head(pool, &group).await, "head");

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_replay_cursor_past_what_a_sequence_can_hold_is_answered_rather_than_wrapped() {
    let (scratch, _blobs, state) = prepared("handshakefault_cursor").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x35).await;
    store::append(pool, &message(&group, b"a commit"))
        .await
        .expect("seed");

    // A cursor a client could only send by being wrong about the protocol. It is
    // answered with an empty replay rather than by wrapping into a negative
    // sequence, which would return the whole log to a client claiming to be past
    // the end of it.
    assert!(store::since(pool, &group, u64::MAX)
        .await
        .expect("read")
        .is_empty());

    scratch.drop_database().await;
}
