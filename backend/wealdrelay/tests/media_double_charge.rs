// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! One object, charged once, even after the object goes missing under its own row.
//!
//! `relay_blob_reservation`'s unique index on `(workspace_id, group_id, blob_hash)`
//! is partial, `where finalized_at is null`, and `reserve` used to look only for a
//! row with `finalized_at is null`. So a *finalized* row plus an absent object (the
//! state the retention sweep leaves if it deletes the object and then cannot delete
//! the row, and the state an operator leaves by removing a bucket object) made the
//! re-upload insert a second row, charge quota again, and `claim` add the same
//! object's bytes to `stored_bytes` a second time. Nothing ever reclaimed the first
//! charge: the eventual delete removes one row and subtracts one helping
//! (WEALD-318).
//!
//! These tests are about the arithmetic on the quota row, so they assert the row and
//! never the code that wrote it. The precondition is built the way production
//! reaches it, a finalized row whose object is not in the store, rather than by
//! hand-editing `stored_bytes`.

mod support;

use std::sync::Arc;

use sqlx::{PgPool, Row as _};
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::media::store::{self, Reserved};

use support::{blob_hash, config_for, make_group, Running, Scratch};

const TTL: i64 = 900;
const WORKSPACE: &str = "ws-double";

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

fn reservation_id(reserved: &Reserved) -> uuid::Uuid {
    match reserved {
        Reserved::Active { reservation_id } => *reservation_id,
        other => panic!("expected an active reservation, got {other:?}"),
    }
}

async fn rows_for(pool: &PgPool, group: &[u8], hash: &[u8]) -> i64 {
    let row = sqlx::query(
        "select count(*) as held from relay_blob_reservation \
         where workspace_id = $1 and group_id = $2 and blob_hash = $3",
    )
    .bind(WORKSPACE)
    .bind(group)
    .bind(hash)
    .fetch_one(pool)
    .await
    .expect("count the reservation rows");
    row.try_get("held").expect("a count")
}

/// The whole bug, end to end: store, lose the object, upload again, claim again.
///
/// The assertion that fails before the fix is the second `stored_bytes`: it read 800
/// for one 400-byte object, and no path ever brought it back down to 400.
#[tokio::test]
async fn re_uploading_an_object_whose_row_survived_charges_it_once() {
    let (scratch, _blobs, state) = prepared("double_recharge").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x81).await;
    let hash = blob_hash(0xb1);
    store::ensure_quota_row(pool, WORKSPACE, Some(10_000))
        .await
        .unwrap();

    // A first, ordinary upload: reserved, then claimed by a manifest.
    let first = store::reserve(pool, WORKSPACE, &group, &hash, 400, false, TTL)
        .await
        .expect("the first reservation");
    let first_id = reservation_id(&first);
    assert!(store::claim(pool, WORKSPACE, &group, &hash)
        .await
        .expect("the claim"));
    let usage = store::usage(pool, WORKSPACE).await.unwrap();
    assert_eq!(usage.stored_bytes, 400);
    assert_eq!(usage.reserved_bytes, 0);

    // The object leaves the store while its finalized row stays: the crash window
    // the retention sweep documents, or a `finish_deletion` that failed. Nothing is
    // done to the database here, which is the point; only the object is gone, and
    // `already_stored` is what the caller computes from the store.
    assert_eq!(rows_for(pool, &group, &hash).await, 1);

    // The re-upload. `already_stored` false, because the object really is absent.
    let again = store::reserve(pool, WORKSPACE, &group, &hash, 400, false, TTL)
        .await
        .expect("the re-upload reservation");
    let again_id = reservation_id(&again);
    assert_ne!(
        again_id, first_id,
        "the stale finalized row must be retired, not handed back as live"
    );
    // The stale row is gone and its charge with it, so the workspace is holding one
    // reservation for one object rather than a stored charge plus a reservation.
    let usage = store::usage(pool, WORKSPACE).await.unwrap();
    assert_eq!(
        usage.stored_bytes, 0,
        "the retired row's bytes must go back to the workspace"
    );
    assert_eq!(usage.reserved_bytes, 400);
    assert_eq!(rows_for(pool, &group, &hash).await, 1);

    // And the second claim lands the object at its true size, once.
    assert!(store::claim(pool, WORKSPACE, &group, &hash)
        .await
        .expect("the second claim"));
    let usage = store::usage(pool, WORKSPACE).await.unwrap();
    assert_eq!(
        usage.stored_bytes, 400,
        "one object was charged twice against stored_bytes"
    );
    assert_eq!(usage.reserved_bytes, 0);
    assert_eq!(
        rows_for(pool, &group, &hash).await,
        1,
        "one object must not leave two reservation rows behind"
    );

    scratch.drop_database().await;
}

/// A workspace already double-charged is reconciled for the object it re-uploads.
///
/// Two finalized rows for one triple is a state the partial index permits and the
/// old code produced. Retiring every stale row rather than one is what makes the
/// re-upload a repair instead of a third charge.
#[tokio::test]
async fn an_already_double_charged_object_is_reconciled_by_its_next_upload() {
    let (scratch, _blobs, state) = prepared("double_reconcile").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x82).await;
    let hash = blob_hash(0xb2);
    store::ensure_quota_row(pool, WORKSPACE, Some(10_000))
        .await
        .unwrap();

    // The corrupt state as the old code left it: two finalized rows, both charged.
    for _ in 0..2 {
        sqlx::query(
            "insert into relay_blob_reservation \
             (reservation_id, workspace_id, group_id, blob_hash, bytes, expires_at, finalized_at) \
             values (gen_random_uuid(), $1, $2, $3, 400, now() + interval '1 hour', now())",
        )
        .bind(WORKSPACE)
        .bind(&group)
        .bind(&hash)
        .execute(pool)
        .await
        .expect("plant a finalized row");
    }
    sqlx::query("update relay_quota set stored_bytes = 800 where workspace_id = $1")
        .bind(WORKSPACE)
        .execute(pool)
        .await
        .expect("plant the double charge");
    assert_eq!(rows_for(pool, &group, &hash).await, 2);

    let again = store::reserve(pool, WORKSPACE, &group, &hash, 400, false, TTL)
        .await
        .expect("the re-upload reservation");
    reservation_id(&again);
    assert!(store::claim(pool, WORKSPACE, &group, &hash)
        .await
        .expect("the claim"));

    let usage = store::usage(pool, WORKSPACE).await.unwrap();
    assert_eq!(
        usage.stored_bytes, 400,
        "both phantom charges should have been reclaimed, leaving one object's bytes"
    );
    assert_eq!(usage.reserved_bytes, 0);
    assert_eq!(rows_for(pool, &group, &hash).await, 1);

    scratch.drop_database().await;
}

/// The paths that must not change.
///
/// An in-flight retry still refreshes rather than doubling, and an object that is
/// actually present is still free. The stale-row retirement sits between those two
/// and must be invisible to both, or it has traded one accounting bug for another.
#[tokio::test]
async fn a_retry_and_an_existing_object_are_unaffected() {
    let (scratch, _blobs, state) = prepared("double_unaffected").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x83).await;
    let hash = blob_hash(0xb3);
    store::ensure_quota_row(pool, WORKSPACE, Some(10_000))
        .await
        .unwrap();

    let first = store::reserve(pool, WORKSPACE, &group, &hash, 400, false, TTL)
        .await
        .expect("the first reservation");
    let id = reservation_id(&first);
    // In flight, not finalized: the same row comes back and the charge stands still.
    let retry = store::reserve(pool, WORKSPACE, &group, &hash, 400, false, TTL)
        .await
        .expect("the retry");
    assert_eq!(retry, Reserved::Active { reservation_id: id });
    assert_eq!(
        store::usage(pool, WORKSPACE).await.unwrap().reserved_bytes,
        400
    );
    assert_eq!(rows_for(pool, &group, &hash).await, 1);

    assert!(store::claim(pool, WORKSPACE, &group, &hash)
        .await
        .expect("the claim"));
    // Finalized *and* the object is present, which is the ordinary steady state: the
    // short circuit answers first and the finalized row is never touched.
    let free = store::reserve(pool, WORKSPACE, &group, &hash, 400, true, TTL)
        .await
        .expect("the free retry");
    assert_eq!(free, Reserved::AlreadyStored);
    let usage = store::usage(pool, WORKSPACE).await.unwrap();
    assert_eq!(usage.stored_bytes, 400);
    assert_eq!(usage.reserved_bytes, 0);
    assert_eq!(
        rows_for(pool, &group, &hash).await,
        1,
        "the steady state must keep its finalized row"
    );

    scratch.drop_database().await;
}
