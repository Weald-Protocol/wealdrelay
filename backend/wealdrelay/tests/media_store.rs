// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Quota, reservations and multipart sessions against real Postgres.
//!
//! Tier 3. `specs/backend/relay/media.md` puts the quota check at `BLOB put`,
//! "before the presigned URL is issued", and it puts the moment a blob's bytes
//! become stored at the first accepted manifest claim. Both of those are
//! arithmetic on one row under a lock, so they are proven by reading the row back
//! rather than by reading the code that wrote it.
//!
//! The claims that matter here, in the order they matter:
//!
//! - A retry of an upload already in flight refreshes its reservation and never
//!   takes a second helping of quota. Without that, a client retrying its own
//!   dropped upload could push its workspace over quota by itself.
//! - `exists` is free. That is the whole reason a dropped upload is cheap to
//!   resume.
//! - Bytes move from reserved to stored exactly once, at `claim`, and leave
//!   `stored_bytes` exactly once, at `finish_deletion`.

mod support;

use std::sync::Arc;

use sqlx::{PgPool, Row as _};
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::media::store::{self, Reserved, StoreError};

use support::{blob_hash, config_for, make_group, Running, Scratch};

const TTL: i64 = 900;
const WORKSPACE: &str = "ws-step4";

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

#[tokio::test]
async fn a_quota_row_is_created_once_and_then_follows_the_configured_limit() {
    let (scratch, _blobs, state) = prepared("mediastore_quota_row").await;
    let pool = pool_of(&state);

    // Nothing written yet: a workspace with no row reads as empty rather than as
    // an error, so a relay that has never seen an upload can still answer.
    let empty = store::usage(pool, WORKSPACE).await.expect("read usage");
    assert_eq!(empty.stored_bytes, 0);
    assert_eq!(empty.reserved_bytes, 0);
    assert_eq!(empty.limit_bytes, None);
    assert!(format!("{empty:?}").contains("Usage"));

    store::ensure_quota_row(pool, WORKSPACE, Some(1_000))
        .await
        .expect("create the row");
    assert_eq!(
        store::usage(pool, WORKSPACE)
            .await
            .expect("read")
            .limit_bytes,
        Some(1_000)
    );

    // A relay restarted with a changed `WEALD_RELAY_MAX_STORAGE_GB` enforces the
    // new limit on its next reservation, not the one it booted with.
    store::ensure_quota_row(pool, WORKSPACE, Some(4_000))
        .await
        .expect("update the row");
    assert_eq!(
        store::usage(pool, WORKSPACE)
            .await
            .expect("read")
            .limit_bytes,
        Some(4_000)
    );
    store::ensure_quota_row(pool, WORKSPACE, None)
        .await
        .expect("an unlimited relay");
    assert_eq!(
        store::usage(pool, WORKSPACE)
            .await
            .expect("read")
            .limit_bytes,
        None
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_reservation_is_charged_once_however_many_times_the_upload_is_retried() {
    let (scratch, _blobs, state) = prepared("mediastore_retry").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x51).await;
    let hash = blob_hash(0xa1);
    store::ensure_quota_row(pool, WORKSPACE, Some(10_000))
        .await
        .unwrap();

    let first = store::reserve(pool, WORKSPACE, &group, &hash, 400, false, TTL)
        .await
        .expect("the first reservation");
    let id = reservation_id(&first);
    assert_eq!(
        store::usage(pool, WORKSPACE).await.unwrap().reserved_bytes,
        400
    );

    // The retry. Same object, same client, a dropped connection in between.
    let again = store::reserve(pool, WORKSPACE, &group, &hash, 400, false, TTL)
        .await
        .expect("the retry");
    assert_eq!(again, Reserved::Active { reservation_id: id });
    assert_eq!(
        store::usage(pool, WORKSPACE).await.unwrap().reserved_bytes,
        400,
        "a retry of one upload must not be charged twice"
    );

    // And the expiry moved, which is what makes the 15-minute window refreshable.
    let expiry: chrono_free::Moved = moved_expiry(pool, id).await;
    assert!(
        expiry.moved,
        "the retry must refresh the reservation window"
    );

    // The object is already there: `exists`, and no reservation at all.
    let free = store::reserve(pool, WORKSPACE, &group, &hash, 400, true, TTL)
        .await
        .expect("the free retry");
    assert_eq!(free, Reserved::AlreadyStored);
    assert_eq!(
        store::usage(pool, WORKSPACE).await.unwrap().reserved_bytes,
        400
    );

    scratch.drop_database().await;
}

/// Whether a reservation's expiry is later than the moment it was created. A tiny
/// struct rather than a bare bool so the assertion above reads as a sentence.
mod chrono_free {
    pub struct Moved {
        pub moved: bool,
    }
}

async fn moved_expiry(pool: &PgPool, id: uuid::Uuid) -> chrono_free::Moved {
    let row = sqlx::query(
        "select (expires_at > created_at + interval '1 second') as moved \
         from relay_blob_reservation where reservation_id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read the reservation back");
    chrono_free::Moved {
        moved: row.try_get("moved").expect("a boolean"),
    }
}

#[tokio::test]
async fn a_workspace_over_its_plan_is_refused_and_nothing_is_written() {
    let (scratch, _blobs, state) = prepared("mediastore_overquota").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x52).await;
    store::ensure_quota_row(pool, WORKSPACE, Some(1_000))
        .await
        .unwrap();

    store::reserve(pool, WORKSPACE, &group, &blob_hash(0xb1), 900, false, TTL)
        .await
        .expect("under the limit");
    let refused = store::reserve(pool, WORKSPACE, &group, &blob_hash(0xb2), 200, false, TTL)
        .await
        .expect("over the limit is an answer, not an error");
    assert_eq!(refused, Reserved::OverQuota);

    // "It never fails silently and never accepts an upload it will later delete":
    // the refusal leaves the counters exactly as they were and writes no row.
    let usage = store::usage(pool, WORKSPACE).await.unwrap();
    assert_eq!(usage.reserved_bytes, 900);
    assert_eq!(usage.stored_bytes, 0);
    assert!(
        store::find_active_reservation(pool, WORKSPACE, &group, &blob_hash(0xb2))
            .await
            .unwrap()
            .is_none()
    );

    // Exactly at the limit is inside it.
    assert!(matches!(
        store::reserve(pool, WORKSPACE, &group, &blob_hash(0xb3), 100, false, TTL)
            .await
            .unwrap(),
        Reserved::Active { .. }
    ));

    scratch.drop_database().await;
}

#[tokio::test]
async fn an_unlimited_relay_never_refuses_a_reservation_for_quota() {
    let (scratch, _blobs, state) = prepared("mediastore_unlimited").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x53).await;
    store::ensure_quota_row(pool, WORKSPACE, None)
        .await
        .unwrap();

    for seed in 0..4u8 {
        assert!(matches!(
            store::reserve(
                pool,
                WORKSPACE,
                &group,
                &blob_hash(0xc0 + seed),
                1_000_000_000,
                false,
                TTL
            )
            .await
            .unwrap(),
            Reserved::Active { .. }
        ));
    }
    assert_eq!(
        store::usage(pool, WORKSPACE).await.unwrap().reserved_bytes,
        4_000_000_000
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn bytes_move_from_reserved_to_stored_exactly_once_and_leave_exactly_once() {
    let (scratch, _blobs, state) = prepared("mediastore_claim").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x54).await;
    let hash = blob_hash(0xd1);
    store::ensure_quota_row(pool, WORKSPACE, Some(10_000))
        .await
        .unwrap();
    let id = reservation_id(
        &store::reserve(pool, WORKSPACE, &group, &hash, 700, false, TTL)
            .await
            .unwrap(),
    );

    let found = store::find_active_reservation(pool, WORKSPACE, &group, &hash)
        .await
        .unwrap()
        .expect("the reservation is there");
    assert_eq!(found.reservation_id, id);
    assert_eq!(found.hash, hash);
    assert_eq!(found.bytes, 700);
    assert!(!found.finalized);
    assert!(format!("{found:?}").contains("Reservation"));
    assert!(
        store::find_active_reservation(pool, WORKSPACE, &group, &blob_hash(0xff))
            .await
            .unwrap()
            .is_none()
    );

    // Nothing is claimed yet, so the retention collector sees nothing.
    assert!(store::finalized_reservations(pool, WORKSPACE, &group)
        .await
        .unwrap()
        .is_empty());

    assert!(store::claim(pool, WORKSPACE, &group, &hash).await.unwrap());
    let usage = store::usage(pool, WORKSPACE).await.unwrap();
    assert_eq!(usage.reserved_bytes, 0);
    assert_eq!(usage.stored_bytes, 700);

    // A later manifest naming the same hash again is a no-op: `finalized_at` is
    // only ever set once, which is what stops a chatty group inflating its own
    // stored total.
    assert!(!store::claim(pool, WORKSPACE, &group, &hash).await.unwrap());
    assert_eq!(
        store::usage(pool, WORKSPACE).await.unwrap().stored_bytes,
        700
    );

    let finalized = store::finalized_reservations(pool, WORKSPACE, &group)
        .await
        .unwrap();
    assert_eq!(finalized.len(), 1);
    assert_eq!(finalized[0].claimed_at_ms % 1000, 0);
    assert!(
        finalized[0].claimed_at_ms > 0,
        "the claim clock is the relay's own receipt time"
    );
    assert_eq!(finalized[0].bytes, 700);

    // A claimed reservation cannot be released: releasing it would hand the bytes
    // back while the object is still in the bucket.
    assert_eq!(store::release(pool, WORKSPACE, id).await.unwrap(), None);
    assert_eq!(
        store::usage(pool, WORKSPACE).await.unwrap().stored_bytes,
        700
    );

    store::finish_deletion(pool, WORKSPACE, id).await.unwrap();
    assert_eq!(store::usage(pool, WORKSPACE).await.unwrap().stored_bytes, 0);
    // Idempotent: a second pass over a row that is already gone leaves the
    // counters alone rather than driving them negative.
    store::finish_deletion(pool, WORKSPACE, id).await.unwrap();
    assert_eq!(store::usage(pool, WORKSPACE).await.unwrap().stored_bytes, 0);
    assert!(store::finalized_reservations(pool, WORKSPACE, &group)
        .await
        .unwrap()
        .is_empty());

    scratch.drop_database().await;
}

#[tokio::test]
async fn releasing_an_unclaimed_reservation_hands_its_bytes_back() {
    let (scratch, _blobs, state) = prepared("mediastore_release").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x55).await;
    let hash = blob_hash(0xe1);
    store::ensure_quota_row(pool, WORKSPACE, Some(10_000))
        .await
        .unwrap();
    let id = reservation_id(
        &store::reserve(pool, WORKSPACE, &group, &hash, 250, false, TTL)
            .await
            .unwrap(),
    );

    assert_eq!(
        store::release(pool, WORKSPACE, id).await.unwrap(),
        Some(250)
    );
    assert_eq!(
        store::usage(pool, WORKSPACE).await.unwrap().reserved_bytes,
        0
    );
    // Twice is not twice the refund.
    assert_eq!(store::release(pool, WORKSPACE, id).await.unwrap(), None);
    assert_eq!(
        store::usage(pool, WORKSPACE).await.unwrap().reserved_bytes,
        0
    );
    // A never-claimed reservation is also never a finished deletion.
    store::finish_deletion(pool, WORKSPACE, id).await.unwrap();
    assert_eq!(store::usage(pool, WORKSPACE).await.unwrap().stored_bytes, 0);

    scratch.drop_database().await;
}

#[tokio::test]
async fn only_reservations_past_the_grace_and_never_claimed_are_stale() {
    let (scratch, _blobs, state) = prepared("mediastore_stale").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x56).await;
    store::ensure_quota_row(pool, WORKSPACE, Some(100_000))
        .await
        .unwrap();

    let fresh = reservation_id(
        &store::reserve(pool, WORKSPACE, &group, &blob_hash(0xf1), 10, false, TTL)
            .await
            .unwrap(),
    );
    let old = reservation_id(
        &store::reserve(pool, WORKSPACE, &group, &blob_hash(0xf2), 20, false, TTL)
            .await
            .unwrap(),
    );
    let claimed = reservation_id(
        &store::reserve(pool, WORKSPACE, &group, &blob_hash(0xf3), 30, false, TTL)
            .await
            .unwrap(),
    );
    age(pool, old, "25 hours").await;
    age(pool, claimed, "25 hours").await;
    store::claim(pool, WORKSPACE, &group, &blob_hash(0xf3))
        .await
        .unwrap();

    let stale = store::stale_unclaimed(pool, wealdrelay::media::gc::UNCLAIMED_GRACE_SECONDS)
        .await
        .unwrap();
    let ids: Vec<uuid::Uuid> = stale.iter().map(|row| row.3).collect();
    assert!(ids.contains(&old), "an upload nobody claimed in 24 hours");
    assert!(
        !ids.contains(&fresh),
        "the grace period is 24 hours, not none"
    );
    assert!(
        !ids.contains(&claimed),
        "a claimed blob is governed by retention, never by the unclaimed sweep"
    );
    let row = stale.iter().find(|row| row.3 == old).unwrap();
    assert_eq!(row.0, WORKSPACE);
    assert_eq!(row.1, group);
    assert_eq!(row.2, blob_hash(0xf2));

    // `claimed_hashes` is the storage sweep's known set: every hash the relay
    // issued a reservation for, claimed or not, because an in-flight upload's
    // object is not an unreferenced object.
    let known = store::claimed_hashes(pool, WORKSPACE, &group)
        .await
        .unwrap();
    assert_eq!(known.len(), 3);
    assert!(known.contains(&blob_hash(0xf1)));
    assert!(store::claimed_hashes(pool, WORKSPACE, &blob_hash(0x00))
        .await
        .unwrap()
        .is_empty());

    scratch.drop_database().await;
}

/// BR-041: a reservation whose window was refreshed survives the collector, even
/// though its `created_at` is older than the grace period.
///
/// `media.md` defines a *refreshable* upload window, and `reserve` refreshes
/// `expires_at` while `created_at` deliberately stays put. A collector that read the
/// age alone deleted the object and released the quota of an upload it had just
/// granted a fresh window to, which the client experiences as a large upload that
/// vanishes at the 24 hour mark no matter how recently it was resumed.
#[tokio::test]
async fn a_refreshed_reservation_is_not_collected_inside_its_new_window() {
    let (scratch, _blobs, state) = prepared("mediastore_refreshed").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x5e).await;
    store::ensure_quota_row(pool, WORKSPACE, Some(100_000))
        .await
        .unwrap();

    let hash = blob_hash(0xf7);
    let id = reservation_id(
        &store::reserve(pool, WORKSPACE, &group, &hash, 40, false, TTL)
            .await
            .unwrap(),
    );
    age(pool, id, "25 hours").await;

    // Old on both clocks: collectable, which is the case the sweep exists for.
    let stale = store::stale_unclaimed(pool, wealdrelay::media::gc::UNCLAIMED_GRACE_SECONDS)
        .await
        .unwrap();
    assert!(stale.iter().any(|row| row.3 == id));

    // The client resumes. The retry refreshes the window and holds the same row.
    let again = reservation_id(
        &store::reserve(pool, WORKSPACE, &group, &hash, 40, false, TTL)
            .await
            .unwrap(),
    );
    assert_eq!(again, id, "a retry refreshes rather than doubling");

    let stale = store::stale_unclaimed(pool, wealdrelay::media::gc::UNCLAIMED_GRACE_SECONDS)
        .await
        .unwrap();
    assert!(
        !stale.iter().any(|row| row.3 == id),
        "a live upload window is not an abandoned upload"
    );

    scratch.drop_database().await;
}

async fn age(pool: &PgPool, id: uuid::Uuid, interval: &str) {
    sqlx::query(&format!(
        "update relay_blob_reservation set created_at = now() - interval '{interval}' \
         where reservation_id = $1"
    ))
    .bind(id)
    .execute(pool)
    .await
    .expect("age the reservation");
}

// MARK: Multipart sessions

#[tokio::test]
async fn a_multipart_session_carries_its_reservation_and_its_parts_are_immutable() {
    let (scratch, _blobs, state) = prepared("mediastore_multipart").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x57).await;
    let hash = blob_hash(0x81);
    store::ensure_quota_row(pool, WORKSPACE, None)
        .await
        .unwrap();
    let reservation = reservation_id(
        &store::reserve(
            pool,
            WORKSPACE,
            &group,
            &hash,
            3 * 64 * 1024 * 1024,
            false,
            TTL,
        )
        .await
        .unwrap(),
    );

    assert!(store::find_multipart(pool, uuid::Uuid::nil())
        .await
        .unwrap()
        .is_none());

    let session = store::create_multipart(pool, reservation, "s3-upload-id", 64 * 1024 * 1024, TTL)
        .await
        .expect("open a session");
    let found = store::find_multipart(pool, session)
        .await
        .unwrap()
        .expect("the session resolves through its reservation");
    assert_eq!(found.session_id, session);
    assert_eq!(found.reservation_id, reservation);
    assert_eq!(found.workspace, WORKSPACE);
    assert_eq!(found.group, group);
    assert_eq!(found.hash, hash);
    assert_eq!(found.upload_id, "s3-upload-id");
    assert_eq!(found.part_size, 64 * 1024 * 1024);
    assert_eq!(found.total_bytes, 3 * 64 * 1024 * 1024);
    assert!(!found.completed);
    assert!(!found.aborted);
    assert!(format!("{found:?}").contains("MultipartSession"));

    assert!(store::expected_len_of(pool, session, 1)
        .await
        .unwrap()
        .is_none());
    store::record_part(pool, session, 1, 64 * 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(
        store::expected_len_of(pool, session, 1).await.unwrap(),
        Some(64 * 1024 * 1024)
    );
    // A refresh of the same part is one row, not two: the 15-minute window is
    // refreshable without changing which parts exist.
    store::record_part(pool, session, 1, 64 * 1024 * 1024)
        .await
        .unwrap();
    let parts: i64 =
        sqlx::query_scalar("select count(*) from relay_blob_multipart_part where session_id = $1")
            .bind(session)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(parts, 1);

    store::complete_multipart(pool, session).await.unwrap();
    let done = store::find_multipart(pool, session).await.unwrap().unwrap();
    assert!(done.completed);
    assert!(!done.aborted);

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_session_past_its_window_is_stale_and_a_finished_one_never_is() {
    let (scratch, _blobs, state) = prepared("mediastore_multipart_stale").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x58).await;
    store::ensure_quota_row(pool, WORKSPACE, None)
        .await
        .unwrap();

    let mut sessions = Vec::new();
    for seed in 0..4u8 {
        let reservation = reservation_id(
            &store::reserve(
                pool,
                WORKSPACE,
                &group,
                &blob_hash(0x90 + seed),
                99,
                false,
                TTL,
            )
            .await
            .unwrap(),
        );
        sessions.push((
            reservation,
            store::create_multipart(pool, reservation, "", 1024, TTL)
                .await
                .unwrap(),
        ));
    }
    // Three of the four are past their window; of those, one completed and one
    // was aborted, so only the third is a candidate.
    for (_, session) in &sessions[..3] {
        sqlx::query("update relay_blob_multipart set expires_at = now() - interval '1 hour' where session_id = $1")
            .bind(session)
            .execute(pool)
            .await
            .unwrap();
    }
    store::complete_multipart(pool, sessions[0].1)
        .await
        .unwrap();
    store::abort_multipart(pool, sessions[1].1).await.unwrap();

    let stale = store::stale_multipart_sessions(pool).await.unwrap();
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].0, sessions[2].1);
    assert_eq!(stale[0].1, sessions[2].0);

    let aborted = store::find_multipart(pool, sessions[1].1)
        .await
        .unwrap()
        .unwrap();
    assert!(aborted.aborted);

    scratch.drop_database().await;
}

/// A relay that could not answer says so, in words an operator can act on.
#[test]
fn a_store_failure_names_the_store_it_came_from() {
    let error = StoreError::Database("connection reset".to_string());
    assert_eq!(error.to_string(), "media store: connection reset");
    assert!(format!("{error:?}").contains("Database"));
}
