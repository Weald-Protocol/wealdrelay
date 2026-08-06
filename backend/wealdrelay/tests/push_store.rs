// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The registration table against real Postgres.
//!
//! The harness database from `scripts/weald-stack`, a scratch database per test, and
//! the relay's own migrations. Nothing here is a fake: the uniqueness that stops one
//! device stealing another's wakes is a unique index, the range on `categories` is a
//! check constraint, and both are asserted by asking the database to break them.

mod support;

use wealdrelay::health::Clock;
use wealdrelay::push::store::{self, Registered};
use wealdrelay::push::{Category, ALL_CATEGORIES};

use support::{
    config_for, default_device, device_from, entry_hash_of, make_group, make_group_in,
    other_device, wake_expiry, wake_handle, Running, Scratch,
};

const CLOCK: u64 = 1_700_000_000_000;
const WORKSPACE: &str = "ws-step4";

/// A relay with a database and a group, which is what every test here starts from.
async fn relay(label: &str, group_byte: u8) -> (Scratch, tempfile::TempDir, Running, Vec<u8>) {
    let scratch = Scratch::new(label).await;
    let blobs = tempfile::tempdir().unwrap();
    let running = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&running.state, group_byte).await;
    (scratch, blobs, running, group)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_registration_round_trips_and_replaces_itself() {
    let (scratch, _blobs, relay, _group) = relay("push_store_round_trip", 0x60).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let entry = entry_hash_of(pool, WORKSPACE, &default_device()).await;

    assert_eq!(
        store::register(
            pool,
            WORKSPACE,
            &entry,
            &wake_handle(1),
            ALL_CATEGORIES,
            wake_expiry(CLOCK)
        )
        .await
        .expect("the store answers"),
        Registered::Stored
    );
    let (handle, categories, expires) = store::find(pool, WORKSPACE, &entry)
        .await
        .expect("the store answers")
        .expect("a row");
    assert_eq!(handle, wake_handle(1));
    assert_eq!(categories, ALL_CATEGORIES);
    // Postgres holds a `timestamptz` to microsecond precision and the wire carries
    // milliseconds, so the two agree to the millisecond and are compared as such.
    assert_eq!(expires, wake_expiry(CLOCK));

    // The same principal again: one row, the new values.
    store::register(
        pool,
        WORKSPACE,
        &entry,
        &wake_handle(2),
        Category::Message.bit(),
        wake_expiry(CLOCK) + 1000,
    )
    .await
    .expect("the store answers");
    let (handle, categories, _) = store::find(pool, WORKSPACE, &entry)
        .await
        .expect("the store answers")
        .expect("a row");
    assert_eq!(handle, wake_handle(2));
    assert_eq!(categories, Category::Message.bit());
    let rows: i64 = sqlx::query_scalar("select count(*) from relay_push_handle")
        .fetch_one(pool)
        .await
        .expect("count");
    assert_eq!(rows, 1);

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_handle_is_unique_across_the_whole_table() {
    // Not merely within a workspace. The unique index is the only thing that stops a
    // second principal claiming a handle that is already registered, and that claim
    // is refused rather than repaired.
    let (scratch, _blobs, relay, _group) = relay("push_store_unique", 0x61).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let ada = entry_hash_of(pool, WORKSPACE, &default_device()).await;
    let bo = entry_hash_of(pool, WORKSPACE, &other_device()).await;

    assert_eq!(
        store::register(
            pool,
            WORKSPACE,
            &ada,
            &wake_handle(9),
            1,
            wake_expiry(CLOCK)
        )
        .await
        .expect("the store answers"),
        Registered::Stored
    );
    assert_eq!(
        store::register(pool, WORKSPACE, &bo, &wake_handle(9), 1, wake_expiry(CLOCK))
            .await
            .expect("a refusal is an answer, not an error"),
        Registered::HandleTaken
    );
    // The first claimant keeps it and the second holds nothing.
    assert!(store::find(pool, WORKSPACE, &bo)
        .await
        .expect("the store answers")
        .is_none());
    assert_eq!(
        store::find(pool, WORKSPACE, &ada)
            .await
            .expect("the store answers")
            .expect("a row")
            .0,
        wake_handle(9)
    );
    // And re-registering the same handle to the same principal is not a conflict: it
    // is the same row being written again, which is what rotation does every week.
    assert_eq!(
        store::register(
            pool,
            WORKSPACE,
            &ada,
            &wake_handle(9),
            3,
            wake_expiry(CLOCK)
        )
        .await
        .expect("the store answers"),
        Registered::Stored
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_schema_refuses_a_shape_the_wire_would_never_produce() {
    // The check constraints, asserted by asking the database to break them. The codec
    // refuses all three on the way in; these are the second line, and they are what
    // makes a bug in a future call site a failed statement rather than a stored row
    // whose meaning nothing agrees on.
    let (scratch, _blobs, relay, _group) = relay("push_store_constraints", 0x62).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let entry = entry_hash_of(pool, WORKSPACE, &default_device()).await;

    for (label, handle, categories) in [
        ("a short handle", vec![0u8; 15], 1i16),
        ("a long handle", vec![0u8; 17], 1),
        ("an empty mask", wake_handle(3), 0),
        ("an undefined bit", wake_handle(3), 8),
    ] {
        let outcome = sqlx::query(
            "insert into relay_push_handle \
                 (workspace_id, entry_hash, handle, categories, expires_at) \
             values ($1, $2, $3, $4, now() + interval '1 day')",
        )
        .bind(WORKSPACE)
        .bind(&entry)
        .bind(&handle)
        .bind(categories)
        .execute(pool)
        .await;
        assert!(outcome.is_err(), "{label} should not be storable");
    }
    // And a 32-byte entry hash is required, which is what the access set produces.
    let outcome = sqlx::query(
        "insert into relay_push_handle \
             (workspace_id, entry_hash, handle, categories, expires_at) \
         values ($1, $2, $3, 1, now() + interval '1 day')",
    )
    .bind(WORKSPACE)
    .bind(vec![0u8; 8])
    .bind(wake_handle(4))
    .execute(pool)
    .await;
    assert!(outcome.is_err(), "an entry hash is 32 bytes");

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_registration_is_swept_and_is_never_woken_meanwhile() {
    let (scratch, _blobs, relay, group) = relay("push_store_expiry", 0x63).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let entry = entry_hash_of(pool, WORKSPACE, &default_device()).await;
    let expires = CLOCK + 60_000;
    store::register(
        pool,
        WORKSPACE,
        &entry,
        &wake_handle(5),
        ALL_CATEGORIES,
        expires,
    )
    .await
    .expect("the store answers");

    // Before the expiry it is wakeable.
    assert_eq!(
        store::wakeable_for_group(pool, &group, Category::Message, expires - 1)
            .await
            .expect("the store answers")
            .len(),
        1
    );
    // After it, the lookup skips it even though the row is still there, so an expiry
    // that has passed is never a wake regardless of when the sweep last ran.
    assert!(
        store::wakeable_for_group(pool, &group, Category::Message, expires + 1)
            .await
            .expect("the store answers")
            .is_empty()
    );

    assert_eq!(
        store::sweep_expired(pool, expires - 1)
            .await
            .expect("the sweep runs"),
        0,
        "nothing is collected early"
    );
    assert_eq!(
        store::sweep_expired(pool, expires + 1)
            .await
            .expect("the sweep runs"),
        1
    );
    assert!(store::find(pool, WORKSPACE, &entry)
        .await
        .expect("the store answers")
        .is_none());

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_an_access_entry_drops_its_registration_in_the_same_transaction() {
    // `push.md` section 2: a principal who is no longer admitted must not keep a wake
    // capability. Driven through `access::store::publish`, which is the real
    // offboarding path, rather than by calling the deletion directly.
    let scratch = Scratch::new("push_store_offboard").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let ada = default_device();
    let bo = other_device();
    let group = make_group_in(
        &relay.state,
        "ws-drop",
        0x64,
        &[ada.clone(), bo.clone()],
        &[ada.clone()],
    )
    .await;
    let pool = relay.state.database.as_ref().unwrap().pool();

    let bo_entry = entry_hash_of(pool, "ws-drop", &bo).await;
    let ada_entry = entry_hash_of(pool, "ws-drop", &ada).await;
    for (entry, seed) in [(&ada_entry, 0x21), (&bo_entry, 0x22)] {
        store::register(
            pool,
            "ws-drop",
            entry,
            &wake_handle(seed),
            ALL_CATEGORIES,
            wake_expiry(CLOCK),
        )
        .await
        .expect("the store answers");
    }
    assert_eq!(
        store::wakeable_for_group(pool, &group, Category::Message, CLOCK)
            .await
            .expect("the store answers")
            .len(),
        2
    );

    // Version 1 of the set, naming Ada and the recovery principal and not Bo.
    support::publish_set_without(&relay.state, "ws-drop", &ada, &[bo.clone()]).await;

    assert!(
        store::find(pool, "ws-drop", &bo_entry)
            .await
            .expect("the store answers")
            .is_none(),
        "the dropped principal's wake capability went with the entry"
    );
    assert!(
        store::find(pool, "ws-drop", &ada_entry)
            .await
            .expect("the store answers")
            .is_some(),
        "and nobody else's did"
    );
    assert_eq!(
        store::wakeable_for_group(pool, &group, Category::Message, CLOCK)
            .await
            .expect("the store answers")
            .len(),
        1
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_group_lookup_is_the_access_set_and_the_mask_and_nothing_else() {
    let scratch = Scratch::new("push_store_lookup").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let ada = default_device();
    let bo = other_device();
    let group = make_group_in(
        &relay.state,
        "ws-l",
        0x65,
        &[ada.clone(), bo.clone()],
        &[ada.clone()],
    )
    .await;
    // A second workspace with its own group and its own device, which must never
    // appear in the first group's answer.
    let stranger = device_from(0x51);
    let elsewhere = make_group_in(
        &relay.state,
        "ws-m",
        0x66,
        &[stranger.clone()],
        &[stranger.clone()],
    )
    .await;
    let pool = relay.state.database.as_ref().unwrap().pool();

    let ada_entry = entry_hash_of(pool, "ws-l", &ada).await;
    let bo_entry = entry_hash_of(pool, "ws-l", &bo).await;
    let stranger_entry = entry_hash_of(pool, "ws-m", &stranger).await;
    // Ada wants everything, Bo wants calls only, the stranger wants everything in a
    // workspace this group is not in.
    store::register(
        pool,
        "ws-l",
        &ada_entry,
        &wake_handle(0x31),
        ALL_CATEGORIES,
        wake_expiry(CLOCK),
    )
    .await
    .expect("the store answers");
    store::register(
        pool,
        "ws-l",
        &bo_entry,
        &wake_handle(0x32),
        Category::Call.bit(),
        wake_expiry(CLOCK),
    )
    .await
    .expect("the store answers");
    store::register(
        pool,
        "ws-m",
        &stranger_entry,
        &wake_handle(0x33),
        ALL_CATEGORIES,
        wake_expiry(CLOCK),
    )
    .await
    .expect("the store answers");

    let message = store::wakeable_for_group(pool, &group, Category::Message, CLOCK)
        .await
        .expect("the store answers");
    assert_eq!(
        message.len(),
        1,
        "a masked-out wake is not sent rather than sent and ignored"
    );
    assert_eq!(message[0].handle, wake_handle(0x31));
    assert_eq!(message[0].entry_hash, ada_entry);

    let call = store::wakeable_for_group(pool, &group, Category::Call, CLOCK)
        .await
        .expect("the store answers");
    assert_eq!(call.len(), 2, "both registered for calls");

    // The other workspace's device is in neither answer, and its own group's answer
    // holds only itself.
    assert!(!message
        .iter()
        .chain(call.iter())
        .any(|row| row.handle == wake_handle(0x33)));
    let other = store::wakeable_for_group(pool, &elsewhere, Category::Message, CLOCK)
        .await
        .expect("the store answers");
    assert_eq!(other.len(), 1);
    assert_eq!(other[0].handle, wake_handle(0x33));

    // A group nobody has heard of wakes nobody, rather than failing.
    assert!(
        store::wakeable_for_group(pool, &[0x99; 32], Category::Message, CLOCK)
            .await
            .expect("the store answers")
            .is_empty()
    );

    // And the row's own rendering carries no handle, which is the absence a log would
    // otherwise breach.
    let rendered = format!("{:?}", message[0]);
    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("31, 31"));

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_handle_the_ringer_does_not_know_is_deleted_by_handle_alone() {
    // The `404` path's database half. Keyed on the handle, because that is what the
    // ringer named and the only thing it knows.
    let (scratch, _blobs, relay, _group) = relay("push_store_delete_by_handle", 0x67).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let entry = entry_hash_of(pool, WORKSPACE, &default_device()).await;
    store::register(
        pool,
        WORKSPACE,
        &entry,
        &wake_handle(0x41),
        1,
        wake_expiry(CLOCK),
    )
    .await
    .expect("the store answers");

    assert_eq!(
        store::delete_by_handle(pool, &wake_handle(0x41))
            .await
            .expect("the store answers"),
        1
    );
    assert!(store::find(pool, WORKSPACE, &entry)
        .await
        .expect("the store answers")
        .is_none());
    // A second `404` for the same handle deletes nothing and is not an error: two
    // wakes can be in flight for a device that has just signed out.
    assert_eq!(
        store::delete_by_handle(pool, &wake_handle(0x41))
            .await
            .expect("the store answers"),
        0
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn clearing_reports_whether_a_row_was_there_without_the_wire_ever_seeing_it() {
    let (scratch, _blobs, relay, _group) = relay("push_store_clear", 0x68).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let entry = entry_hash_of(pool, WORKSPACE, &default_device()).await;

    assert!(
        !store::clear(pool, WORKSPACE, &entry)
            .await
            .expect("the store answers"),
        "nothing to clear"
    );
    store::register(
        pool,
        WORKSPACE,
        &entry,
        &wake_handle(0x51),
        1,
        wake_expiry(CLOCK),
    )
    .await
    .expect("the store answers");
    assert!(store::clear(pool, WORKSPACE, &entry)
        .await
        .expect("the store answers"));

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_rate_limiter_is_per_principal_and_slides() {
    // No database: the ceiling is process-local, which is the shape the blob budget
    // already uses. It is here rather than in the unit suite because it is the same
    // object the socket path charges, and this asserts the window rather than the
    // wiring.
    let limiter = store::RateLimiter::new();
    let ada = vec![0x01; 32];
    let bo = vec![0x02; 32];
    for _ in 0..wealdrelay::push::REGISTRATIONS_PER_HOUR {
        assert!(limiter.allow(&ada, CLOCK).await);
    }
    assert!(!limiter.allow(&ada, CLOCK).await);
    // Another principal has its own allowance.
    assert!(limiter.allow(&bo, CLOCK).await);
    // And the window slides rather than snapping to a clock boundary: an hour after
    // the first attempt, one slot is free again.
    assert!(
        limiter
            .allow(&ada, CLOCK + wealdrelay::push::RATE_WINDOW_MS)
            .await
    );
}
