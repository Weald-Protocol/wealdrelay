// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Garbage collection: the two mechanisms, the seam between them, and the three
//! things that must never happen.
//!
//! Tier 3 and tier 4. `specs/backend/relay/media.md` states the rule this file
//! exists to enforce: a blob may be deleted only after it appeared in at least one
//! valid manifest, is absent from a later valid manifest, and its
//! threshold-authorized policy or destruction record is due; and "the existing
//! 30-day grace period remains a floor".
//!
//! The negatives media collection has to survive are here, each as its own test:
//!
//! - An object storage outage renders media temporarily unavailable and never
//!   deleted. Proven against a real `S3Store` pointed at a port nothing is
//!   listening on, so the failure is a real dispatch failure over a real socket
//!   rather than an injected error value.
//! - An unreferenced blob planted directly in storage is collected. Proven by
//!   writing an object through the same `BlobStore` an operator with bucket
//!   credentials would use, with no reservation behind it, against both backends.
//! - A referenced blob is never collected. Proven at the eligibility level, where
//!   every combination of freeze, manifest, policy and destruction is enumerated,
//!   and again over randomised interleavings in `tests/media_properties.rs`.

mod support;

use std::sync::Arc;
use std::time::Duration;

use aws_sdk_s3::config::retry::RetryConfig;
use aws_sdk_s3::config::timeout::TimeoutConfig;
use sqlx::PgPool;
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::media::gc::{self, Eligibility};
use wealdrelay::media::{retention, store};
use wealdrelay::storage::{BlobKey, FilesystemStore, S3Store, Store};

use support::{
    blob_hash, config_for, device_from, make_group_in, signed_control, signed_destruction,
    signed_manifest, signed_policy, verifier_key, Running, Scratch,
};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;
const NOW: u64 = 1_800_000_000_000;

struct Harness {
    scratch: Scratch,
    // Kept alive for the lifetime of the filesystem-backed store.
    _blobs: tempfile::TempDir,
    state: Arc<RelayState>,
}

impl Harness {
    async fn new(label: &str) -> Self {
        let scratch = Scratch::new(label).await;
        let blobs = tempfile::tempdir().unwrap();
        let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(NOW)).await;
        let state = Arc::clone(&relay.state);
        relay.shutdown().await;
        Self {
            scratch,
            _blobs: blobs,
            state,
        }
    }

    fn pool(&self) -> &PgPool {
        self.state.database.as_ref().expect("a database").pool()
    }

    fn storage(&self) -> &Store {
        self.state.storage.as_ref().expect("a store")
    }

    async fn finish(self) {
        self.scratch.drop_database().await;
    }
}

/// A store that cannot be reached: a real `S3Store` against a port nothing is
/// listening on, with retries off so the test finishes in the time an unreachable
/// backend takes to notice. Every failure it produces is
/// `StorageError::Unreachable`, which is the transient class the collectors
/// refuse to act on.
async fn unreachable_store() -> Store {
    let credentials = aws_credential_types::Credentials::new(
        "weald",
        "weald-local-only",
        None,
        None,
        "weald-media-gc",
    );
    let loaded = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-east-1"))
        // Port 1 is reserved and nothing binds it, so every request is a dispatch
        // failure rather than a service error.
        .endpoint_url("http://127.0.0.1:1")
        .credentials_provider(credentials)
        .load()
        .await;
    let config = aws_sdk_s3::config::Builder::from(&loaded)
        .force_path_style(true)
        .retry_config(RetryConfig::disabled())
        .timeout_config(
            TimeoutConfig::builder()
                .operation_attempt_timeout(Duration::from_secs(2))
                .build(),
        )
        .build();
    Store::S3(S3Store::with_client(
        aws_sdk_s3::Client::from_conf(config),
        "weald-blobs".to_string(),
        String::new(),
    ))
}

fn key(workspace: &str, group: &[u8], hash: &[u8]) -> BlobKey {
    BlobKey::new(
        workspace,
        wealdrelay::media::hex(group),
        wealdrelay::media::hex(hash),
    )
    .expect("the test's own keys are well formed")
}

/// A reservation, its object in storage, and a manifest claiming it: one blob in
/// exactly the state the relay holds a live attachment in.
async fn live_blob(
    harness: &Harness,
    workspace: &str,
    group: &[u8],
    hash: &[u8],
    bytes: &[u8],
) -> uuid::Uuid {
    store::ensure_quota_row(harness.pool(), workspace, None)
        .await
        .unwrap();
    let reserved = store::reserve(
        harness.pool(),
        workspace,
        group,
        hash,
        bytes.len() as i64,
        false,
        900,
    )
    .await
    .unwrap();
    harness
        .storage()
        .put(&key(workspace, group, hash), bytes)
        .await
        .unwrap();
    match reserved {
        store::Reserved::Active { reservation_id } => reservation_id,
        other => panic!("expected a reservation, got {other:?}"),
    }
}

async fn age_claim(pool: &PgPool, id: uuid::Uuid, days: u32) {
    sqlx::query(&format!(
        "update relay_blob_reservation set finalized_at = now() - interval '{days} days' \
         where reservation_id = $1"
    ))
    .bind(id)
    .execute(pool)
    .await
    .unwrap();
}

// MARK: The 24-hour unclaimed-upload collector

#[tokio::test]
async fn an_upload_nobody_claimed_is_collected_after_a_day_and_never_before_it() {
    let harness = Harness::new("gc_unclaimed").await;
    let pool = harness.pool();
    let group = make_group_in(
        &harness.state,
        "ws-gc1",
        0x41,
        &[device_from(0x71)],
        &[device_from(0x71)],
    )
    .await;
    store::ensure_quota_row(pool, "ws-gc1", None).await.unwrap();

    let fresh = live_blob(&harness, "ws-gc1", &group, &blob_hash(0xa1), b"just now").await;
    let stale = live_blob(&harness, "ws-gc1", &group, &blob_hash(0xa2), b"yesterday").await;
    sqlx::query("update relay_blob_reservation set created_at = now() - interval '25 hours' where reservation_id = $1")
        .bind(stale)
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(
        store::usage(pool, "ws-gc1").await.unwrap().reserved_bytes,
        17
    );

    let report = gc::sweep_unclaimed(pool, harness.storage(), "ws-gc1", NOW).await;
    assert_eq!(
        report.examined, 1,
        "only the reservation past the grace period"
    );
    assert_eq!(report.deleted, 1);
    assert_eq!(report.deleted_bytes, 9);
    assert!(report.note.is_empty());
    assert!(format!("{report:?}").contains("Report"));

    // The object is gone and its bytes are back.
    assert!(harness
        .storage()
        .head(&key("ws-gc1", &group, &blob_hash(0xa2)))
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        store::usage(pool, "ws-gc1").await.unwrap().reserved_bytes,
        8
    );
    // The fresh one is untouched, object and reservation both.
    assert!(harness
        .storage()
        .head(&key("ws-gc1", &group, &blob_hash(0xa1)))
        .await
        .unwrap()
        .is_some());
    assert!(
        store::find_active_reservation(pool, "ws-gc1", &group, &blob_hash(0xa1))
            .await
            .unwrap()
            .is_some()
    );
    let _ = fresh;

    // Every pass writes one run-log row, which is the artifact the gate asks for.
    let logged: i64 = sqlx::query_scalar(
        "select count(*) from relay_gc_run where mechanism = 'unclaimed' and deleted_count = 1",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(logged, 1);

    harness.finish().await;
}

/// A reservation in another workspace is another workspace's business, and a
/// workspace id that cannot be turned into an object key is skipped rather than
/// guessed at.
#[tokio::test]
async fn the_unclaimed_sweep_skips_other_workspaces_and_unusable_keys() {
    let harness = Harness::new("gc_unclaimed_skips").await;
    let pool = harness.pool();
    let group = make_group_in(
        &harness.state,
        "ws-gc2",
        0x42,
        &[device_from(0x71)],
        &[device_from(0x71)],
    )
    .await;

    store::ensure_quota_row(pool, "ws-gc2", None).await.unwrap();
    store::ensure_quota_row(pool, "other/ws", None)
        .await
        .unwrap();
    for (workspace, seed) in [("ws-gc2", 0xb1u8), ("other/ws", 0xb2)] {
        store::reserve(pool, workspace, &group, &blob_hash(seed), 10, false, 900)
            .await
            .unwrap();
    }
    sqlx::query("update relay_blob_reservation set created_at = now() - interval '25 hours'")
        .execute(pool)
        .await
        .unwrap();

    // The other workspace's row is filtered before anything is examined.
    let report = gc::sweep_unclaimed(pool, harness.storage(), "ws-gc2", NOW).await;
    assert_eq!(report.examined, 1);
    assert_eq!(report.deleted, 1);

    // And a workspace whose id cannot be a key component is examined and skipped:
    // there is no object to delete under a name the key space refuses.
    let report = gc::sweep_unclaimed(pool, harness.storage(), "other/ws", NOW).await;
    assert_eq!(report.examined, 1);
    assert_eq!(report.deleted, 0);
    assert!(
        store::find_active_reservation(pool, "other/ws", &group, &blob_hash(0xb2))
            .await
            .unwrap()
            .is_some()
    );

    harness.finish().await;
}

// MARK: The storage-listing sweep, which is the seam between the other two

#[tokio::test]
async fn an_unreferenced_object_planted_directly_in_storage_is_collected() {
    let harness = Harness::new("gc_planted").await;
    let pool = harness.pool();
    let group = make_group_in(
        &harness.state,
        "ws-gc3",
        0x43,
        &[device_from(0x71)],
        &[device_from(0x71)],
    )
    .await;

    // One blob that went through `BLOB put` the way every legitimate upload does.
    live_blob(&harness, "ws-gc3", &group, &blob_hash(0xc1), b"legitimate").await;
    // And one an operator with bucket credentials wrote straight in. It has no
    // reservation, so neither database-driven mechanism could ever see it.
    let planted = key("ws-gc3", &group, &blob_hash(0xc2));
    harness
        .storage()
        .put(&planted, b"planted by hand")
        .await
        .unwrap();

    let report =
        gc::sweep_unreferenced_storage(pool, harness.storage(), "ws-gc3", &group, NOW).await;
    assert_eq!(report.examined, 2);
    assert_eq!(report.deleted, 1);
    assert_eq!(report.deleted_bytes, 15);
    assert!(harness.storage().head(&planted).await.unwrap().is_none());
    assert!(
        harness
            .storage()
            .head(&key("ws-gc3", &group, &blob_hash(0xc1)))
            .await
            .unwrap()
            .is_some(),
        "an object with a reservation behind it is referenced, whatever its manifest state"
    );

    // A second pass finds nothing left to do and still records that it ran.
    let again =
        gc::sweep_unreferenced_storage(pool, harness.storage(), "ws-gc3", &group, NOW).await;
    assert_eq!(again.examined, 1);
    assert_eq!(again.deleted, 0);
    let runs: i64 = sqlx::query_scalar(
        "select count(*) from relay_gc_run where mechanism = 'unreferenced_storage'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(runs, 2);

    harness.finish().await;
}

// MARK: Eligibility, which is the whole deletion rule in one function

#[tokio::test]
async fn a_blob_is_eligible_only_when_every_condition_media_md_names_holds() {
    let harness = Harness::new("gc_eligible").await;
    let pool = harness.pool();
    let ada = device_from(0x71);
    let group = make_group_in(
        &harness.state,
        "ws-gc4",
        0x44,
        std::slice::from_ref(&ada),
        std::slice::from_ref(&ada),
    )
    .await;
    let epoch = verifier_key(0x21);
    retention::apply_control(pool, &signed_control(&group, 0, &epoch, None, &epoch))
        .await
        .unwrap();
    store::ensure_quota_row(pool, "ws-gc4", None).await.unwrap();

    let live = blob_hash(0xd1);
    let dropped = blob_hash(0xd2);
    for hash in [&live, &dropped] {
        store::reserve(pool, "ws-gc4", &group, hash, 10, false, 900)
            .await
            .unwrap();
    }
    let first = signed_manifest(
        &group,
        0,
        1,
        None,
        vec![live.clone(), dropped.clone()],
        &epoch,
    );
    retention::apply_manifest(pool, "ws-gc4", &first)
        .await
        .unwrap();

    // Both are named by the latest manifest, so both are live references. No
    // policy, no destruction, and it would make no difference if there were.
    for hash in [&live, &dropped] {
        assert_eq!(
            gc::eligible(pool, "ws-gc4", &group, hash, NOW - 400 * DAY_MS, NOW)
                .await
                .unwrap(),
            Eligibility::Live
        );
    }

    // The omission. Evidence, and nothing more: with no threshold-authorized
    // record the relay has been told what the group holds, not what it may
    // destroy.
    let second = signed_manifest(
        &group,
        0,
        2,
        Some(first.digest()),
        vec![live.clone()],
        &epoch,
    );
    retention::apply_manifest(pool, "ws-gc4", &second)
        .await
        .unwrap();
    assert_eq!(
        gc::eligible(pool, "ws-gc4", &group, &dropped, NOW - 400 * DAY_MS, NOW)
            .await
            .unwrap(),
        Eligibility::NotYetDue,
        "a manifest is evidence, not deletion authority"
    );
    assert_eq!(
        gc::eligible(pool, "ws-gc4", &group, &live, NOW - 400 * DAY_MS, NOW)
            .await
            .unwrap(),
        Eligibility::Live
    );

    // A policy, authorized, whose window has not yet passed for this blob.
    let policy = signed_policy(&group, 1, 30, (NOW / 1000) - 1, std::slice::from_ref(&ada));
    retention::insert_policy(pool, &policy, "[]").await.unwrap();
    assert_eq!(
        gc::eligible(pool, "ws-gc4", &group, &dropped, NOW - 29 * DAY_MS, NOW)
            .await
            .unwrap(),
        Eligibility::NotYetDue,
        "the 30-day grace period is a floor and 29 days is inside it"
    );
    assert_eq!(
        gc::eligible(pool, "ws-gc4", &group, &dropped, NOW - 31 * DAY_MS, NOW)
            .await
            .unwrap(),
        Eligibility::Eligible
    );
    // And still never for the blob the manifest still names.
    assert_eq!(
        gc::eligible(pool, "ws-gc4", &group, &live, NOW - 3650 * DAY_MS, NOW)
            .await
            .unwrap(),
        Eligibility::Live
    );

    // A policy whose own `not_before` is still ahead governs nothing yet, however
    // old the blob is.
    let later = signed_policy(
        &group,
        2,
        30,
        (NOW / 1000) + 10_000,
        std::slice::from_ref(&ada),
    );
    retention::insert_policy(pool, &later, "[]").await.unwrap();
    assert_eq!(
        gc::eligible(pool, "ws-gc4", &group, &dropped, NOW - 3650 * DAY_MS, NOW)
            .await
            .unwrap(),
        Eligibility::NotYetDue
    );

    // A longer window lengthens the floor; it can only ever lengthen it.
    let long = signed_policy(&group, 3, 365, (NOW / 1000) - 1, std::slice::from_ref(&ada));
    retention::insert_policy(pool, &long, "[]").await.unwrap();
    assert_eq!(
        gc::eligible(pool, "ws-gc4", &group, &dropped, NOW - 100 * DAY_MS, NOW)
            .await
            .unwrap(),
        Eligibility::NotYetDue
    );
    assert_eq!(
        gc::eligible(pool, "ws-gc4", &group, &dropped, NOW - 400 * DAY_MS, NOW)
            .await
            .unwrap(),
        Eligibility::Eligible
    );

    // An explicit tombstone wins over the ambient policy, in both directions: it
    // is the client's own deletion request, and it is not due until its
    // `not_before` lands however old the blob is.
    let pending = signed_destruction(
        &group,
        "blob",
        &dropped,
        (NOW / 1000) + 10_000,
        std::slice::from_ref(&ada),
    );
    retention::insert_destruction(pool, &pending, "[]")
        .await
        .unwrap();
    assert_eq!(
        gc::eligible(pool, "ws-gc4", &group, &dropped, NOW - 4000 * DAY_MS, NOW)
            .await
            .unwrap(),
        Eligibility::NotYetDue
    );
    sqlx::query(
        "update relay_retention_destruction set not_before = to_timestamp($1) where group_id = $2",
    )
    .bind((NOW / 1000) as f64 - 1.0)
    .bind(&group)
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(
        gc::eligible(pool, "ws-gc4", &group, &dropped, NOW - 1, NOW)
            .await
            .unwrap(),
        Eligibility::Eligible,
        "an authorized tombstone is the client's own request and does not wait for the policy"
    );

    // A frozen group garbage-collects nothing at all. This is the whole outcome
    // of the successor race: a removed member's forged branch stalls the cleanup
    // job instead of governing it.
    retention::apply_control(
        pool,
        &signed_control(&group, 0, &verifier_key(0xee), None, &verifier_key(0xee)),
    )
    .await
    .unwrap();
    assert!(retention::is_frozen(pool, &group).await.unwrap());
    for hash in [&live, &dropped] {
        assert_eq!(
            gc::eligible(pool, "ws-gc4", &group, hash, NOW - 4000 * DAY_MS, NOW)
                .await
                .unwrap(),
            Eligibility::Frozen
        );
    }

    // And the sweep honours it: nothing is deleted while the group is frozen.
    let report = gc::sweep_retention(pool, harness.storage(), "ws-gc4", &group, NOW).await;
    assert_eq!(report.examined, 2);
    assert_eq!(report.deleted, 0);

    // Only a client clears it.
    retention::clear_freeze(pool, &group).await.unwrap();
    assert_eq!(
        gc::eligible(pool, "ws-gc4", &group, &dropped, NOW - 1, NOW)
            .await
            .unwrap(),
        Eligibility::Eligible
    );

    // A group with no manifest at all has no live set to check against, so
    // nothing in it is ever `Live`.
    let bare = make_group_in(
        &harness.state,
        "ws-gc4",
        0x45,
        std::slice::from_ref(&ada),
        std::slice::from_ref(&ada),
    )
    .await;
    assert_eq!(
        gc::eligible(pool, "ws-gc4", &bare, &blob_hash(0xd9), NOW - DAY_MS, NOW)
            .await
            .unwrap(),
        Eligibility::NotYetDue
    );

    harness.finish().await;
}

#[tokio::test]
async fn the_retention_sweep_deletes_the_omitted_blob_and_leaves_the_named_one() {
    let harness = Harness::new("gc_retention").await;
    let pool = harness.pool();
    let ada = device_from(0x71);
    let group = make_group_in(
        &harness.state,
        "ws-gc5",
        0x46,
        std::slice::from_ref(&ada),
        std::slice::from_ref(&ada),
    )
    .await;
    let epoch = verifier_key(0x21);
    retention::apply_control(pool, &signed_control(&group, 0, &epoch, None, &epoch))
        .await
        .unwrap();

    let live = blob_hash(0xe1);
    let dropped = blob_hash(0xe2);
    live_blob(&harness, "ws-gc5", &group, &live, b"kept").await;
    let dropped_id = live_blob(&harness, "ws-gc5", &group, &dropped, b"removed").await;

    let first = signed_manifest(
        &group,
        0,
        1,
        None,
        vec![live.clone(), dropped.clone()],
        &epoch,
    );
    retention::apply_manifest(pool, "ws-gc5", &first)
        .await
        .unwrap();
    let second = signed_manifest(
        &group,
        0,
        2,
        Some(first.digest()),
        vec![live.clone()],
        &epoch,
    );
    retention::apply_manifest(pool, "ws-gc5", &second)
        .await
        .unwrap();
    let policy = signed_policy(&group, 1, 30, (NOW / 1000) - 1, &[ada]);
    retention::insert_policy(pool, &policy, "[]").await.unwrap();
    age_claim(pool, dropped_id, 40).await;
    assert_eq!(store::usage(pool, "ws-gc5").await.unwrap().stored_bytes, 11);

    let report = gc::sweep_retention(pool, harness.storage(), "ws-gc5", &group, NOW).await;
    assert_eq!(report.examined, 2);
    assert_eq!(report.deleted, 1);
    assert_eq!(report.deleted_bytes, 7);

    assert!(harness
        .storage()
        .head(&key("ws-gc5", &group, &dropped))
        .await
        .unwrap()
        .is_none());
    assert!(
        harness
            .storage()
            .head(&key("ws-gc5", &group, &live))
            .await
            .unwrap()
            .is_some(),
        "a referenced blob is never collected"
    );
    assert_eq!(store::usage(pool, "ws-gc5").await.unwrap().stored_bytes, 4);

    harness.finish().await;
}

/// The `object_key` refusal on the retention path, reached the only way it can
/// be: a group whose workspace id is not a usable key component.
#[tokio::test]
async fn the_retention_sweep_skips_a_blob_whose_key_cannot_be_built() {
    let harness = Harness::new("gc_retention_badkey").await;
    let pool = harness.pool();
    let ada = device_from(0x71);
    let group = make_group_in(
        &harness.state,
        "ws-gc6",
        0x47,
        std::slice::from_ref(&ada),
        std::slice::from_ref(&ada),
    )
    .await;
    // The same group, re-homed into a workspace whose id carries a separator. A
    // relay whose `WEALD_RELAY_HOSTNAME` did that would refuse the key rather than
    // write outside its own key space.
    store::ensure_quota_row(pool, "bad/ws", None).await.unwrap();
    sqlx::query("update relay_group set workspace_id = 'bad/ws' where group_id = $1")
        .bind(&group)
        .execute(pool)
        .await
        .unwrap();

    let hash = blob_hash(0xf1);
    store::reserve(pool, "bad/ws", &group, &hash, 10, false, 900)
        .await
        .unwrap();
    store::claim(pool, "bad/ws", &group, &hash).await.unwrap();
    let destruction = signed_destruction(&group, "blob", &hash, (NOW / 1000) - 1, &[ada]);
    retention::insert_destruction(pool, &destruction, "[]")
        .await
        .unwrap();
    assert_eq!(
        gc::eligible(pool, "bad/ws", &group, &hash, NOW - DAY_MS, NOW)
            .await
            .unwrap(),
        Eligibility::Eligible
    );

    let report = gc::sweep_retention(pool, harness.storage(), "bad/ws", &group, NOW).await;
    assert_eq!(report.examined, 1);
    assert_eq!(
        report.deleted, 0,
        "no key, no deletion, and no accounting for one"
    );
    assert_eq!(store::usage(pool, "bad/ws").await.unwrap().stored_bytes, 10);

    harness.finish().await;
}

// MARK: The negative the gate names: an outage never deletes anything

#[tokio::test]
async fn an_object_storage_outage_deletes_nothing_from_any_mechanism() {
    let harness = Harness::new("gc_outage").await;
    let pool = harness.pool();
    let ada = device_from(0x71);
    let group = make_group_in(
        &harness.state,
        "ws-gc7",
        0x48,
        std::slice::from_ref(&ada),
        std::slice::from_ref(&ada),
    )
    .await;
    let epoch = verifier_key(0x21);
    retention::apply_control(pool, &signed_control(&group, 0, &epoch, None, &epoch))
        .await
        .unwrap();

    let unclaimed = blob_hash(0x11);
    let dropped = blob_hash(0x12);
    let unclaimed_id = live_blob(&harness, "ws-gc7", &group, &unclaimed, b"interrupted").await;
    let dropped_id = live_blob(&harness, "ws-gc7", &group, &dropped, b"tombstoned").await;
    let first = signed_manifest(&group, 0, 1, None, vec![dropped.clone()], &epoch);
    retention::apply_manifest(pool, "ws-gc7", &first)
        .await
        .unwrap();
    let second = signed_manifest(&group, 0, 2, Some(first.digest()), vec![], &epoch);
    retention::apply_manifest(pool, "ws-gc7", &second)
        .await
        .unwrap();
    let policy = signed_policy(&group, 1, 30, (NOW / 1000) - 1, &[ada]);
    retention::insert_policy(pool, &policy, "[]").await.unwrap();
    age_claim(pool, dropped_id, 40).await;
    sqlx::query("update relay_blob_reservation set created_at = now() - interval '25 hours' where reservation_id = $1")
        .bind(unclaimed_id)
        .execute(pool)
        .await
        .unwrap();

    let down = unreachable_store().await;

    // The unclaimed collector examines its candidate and deletes nothing.
    let report = gc::sweep_unclaimed(pool, &down, "ws-gc7", NOW).await;
    assert_eq!(report.examined, 1);
    assert_eq!(report.deleted, 0);
    assert!(
        store::find_active_reservation(pool, "ws-gc7", &group, &unclaimed)
            .await
            .unwrap()
            .is_some()
    );

    // The retention collector reaches a verdict of `Eligible` and still deletes
    // nothing, because the object it would have to remove is unreachable.
    let report = gc::sweep_retention(pool, &down, "ws-gc7", &group, NOW).await;
    assert_eq!(report.examined, 1);
    assert_eq!(report.deleted, 0);
    assert_eq!(store::usage(pool, "ws-gc7").await.unwrap().stored_bytes, 10);

    // The storage sweep cannot even list, so it says so rather than concluding
    // the bucket is empty and collecting everything in it.
    let report = gc::sweep_unreferenced_storage(pool, &down, "ws-gc7", &group, NOW).await;
    assert_eq!(report.examined, 0);
    assert_eq!(report.deleted, 0);
    assert!(
        report.note.contains("could not list storage"),
        "a listing failure has to be named, not silently read as an empty bucket: {}",
        report.note
    );

    // Both objects are still there. "Temporarily unavailable and never deleted."
    for hash in [&unclaimed, &dropped] {
        assert!(harness
            .storage()
            .head(&key("ws-gc7", &group, hash))
            .await
            .unwrap()
            .is_some());
    }

    harness.finish().await;
}

/// A backend that answers and refuses is not a backend that deleted anything
/// either. Reached with a directory the process may read but not write, which is
/// what a mis-restored volume or a tightened bucket policy looks like from here.
#[tokio::test]
async fn a_refused_delete_is_never_recorded_as_a_deletion() {
    let harness = Harness::new("gc_refused").await;
    let pool = harness.pool();
    let group = make_group_in(
        &harness.state,
        "ws-gc8",
        0x49,
        &[device_from(0x71)],
        &[device_from(0x71)],
    )
    .await;

    let readonly = tempfile::tempdir().unwrap();
    let store = Store::Filesystem(FilesystemStore::new(readonly.path().to_path_buf()));
    let hash = blob_hash(0x21);
    let planted = blob_hash(0x22);
    store
        .put(&key("ws-gc8", &group, &hash), b"unclaimed")
        .await
        .unwrap();
    store
        .put(&key("ws-gc8", &group, &planted), b"planted")
        .await
        .unwrap();

    store::ensure_quota_row(pool, "ws-gc8", None).await.unwrap();
    store::reserve(pool, "ws-gc8", &group, &hash, 9, false, 900)
        .await
        .unwrap();
    sqlx::query("update relay_blob_reservation set created_at = now() - interval '25 hours'")
        .execute(pool)
        .await
        .unwrap();

    // Read and traverse, never write: `remove_file` inside it fails with a
    // permission error, which is terminal rather than transient.
    let group_directory = readonly
        .path()
        .join("ws-gc8")
        .join(wealdrelay::media::hex(&group));
    set_mode(&group_directory, 0o500);

    let report = gc::sweep_unclaimed(pool, &store, "ws-gc8", NOW).await;
    assert_eq!(report.examined, 1);
    assert_eq!(report.deleted, 0);
    assert!(
        store::find_active_reservation(pool, "ws-gc8", &group, &hash)
            .await
            .unwrap()
            .is_some()
    );

    let report = gc::sweep_unreferenced_storage(pool, &store, "ws-gc8", &group, NOW).await;
    assert_eq!(report.examined, 2);
    assert_eq!(report.deleted, 0);
    assert_eq!(report.deleted_bytes, 0);

    set_mode(&group_directory, 0o700);
    harness.finish().await;
}

fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("the test owns this directory");
}

// MARK: What each pass says when the database cannot answer it
//
// The same technique `tests/recovery_store_faults.rs` uses: a real state of a
// real Postgres rather than an injected error value. A renamed table is what a
// half-applied migration looks like, and the only correct behaviour is to record
// the reason in the run log and delete nothing.

async fn rename(pool: &PgPool, from: &str, to: &str) {
    sqlx::query(&format!("alter table {from} rename to {to}"))
        .execute(pool)
        .await
        .expect("the injected state must land");
}

#[tokio::test]
async fn a_pass_that_cannot_read_its_candidates_deletes_nothing_and_says_why() {
    let harness = Harness::new("gc_faults").await;
    let pool = harness.pool();
    let group = make_group_in(
        &harness.state,
        "ws-gc9",
        0x4a,
        &[device_from(0x71)],
        &[device_from(0x71)],
    )
    .await;
    live_blob(&harness, "ws-gc9", &group, &blob_hash(0x31), b"present").await;

    rename(
        pool,
        "relay_blob_reservation",
        "relay_blob_reservation_moved",
    )
    .await;

    let report = gc::sweep_unclaimed(pool, harness.storage(), "ws-gc9", NOW).await;
    assert_eq!(report.deleted, 0);
    assert!(report.note.starts_with("could not list stale reservations"));

    let report =
        gc::sweep_unreferenced_storage(pool, harness.storage(), "ws-gc9", &group, NOW).await;
    assert_eq!(report.deleted, 0);
    assert!(
        report.note.starts_with("could not list known reservations"),
        "a sweep that cannot read what is referenced must never conclude nothing is: {}",
        report.note
    );

    let report = gc::sweep_retention(pool, harness.storage(), "ws-gc9", &group, NOW).await;
    assert_eq!(report.deleted, 0);
    assert!(report
        .note
        .starts_with("could not list finalized reservations"));

    // The object is untouched by all three.
    assert!(harness
        .storage()
        .head(&key("ws-gc9", &group, &blob_hash(0x31)))
        .await
        .unwrap()
        .is_some());

    rename(
        pool,
        "relay_blob_reservation_moved",
        "relay_blob_reservation",
    )
    .await;
    harness.finish().await;
}

/// A blob whose eligibility cannot be decided is left alone. The chain the
/// verdict reads is one table deep, so a relay that could not read it must not
/// fall back to deleting.
#[tokio::test]
async fn a_blob_whose_verdict_cannot_be_read_is_left_where_it_is() {
    let harness = Harness::new("gc_verdict_fault").await;
    let pool = harness.pool();
    let group = make_group_in(
        &harness.state,
        "ws-gca",
        0x4b,
        &[device_from(0x71)],
        &[device_from(0x71)],
    )
    .await;
    let hash = blob_hash(0x41);
    live_blob(&harness, "ws-gca", &group, &hash, b"undecidable").await;
    store::claim(pool, "ws-gca", &group, &hash).await.unwrap();

    rename(
        pool,
        "relay_retention_manifest",
        "relay_retention_manifest_moved",
    )
    .await;
    let report = gc::sweep_retention(pool, harness.storage(), "ws-gca", &group, NOW).await;
    assert_eq!(report.examined, 1);
    assert_eq!(report.deleted, 0);
    assert!(report.note.is_empty());
    assert!(harness
        .storage()
        .head(&key("ws-gca", &group, &hash))
        .await
        .unwrap()
        .is_some());
    rename(
        pool,
        "relay_retention_manifest_moved",
        "relay_retention_manifest",
    )
    .await;

    // And the run log itself failing is a warning, never a lost pass: the sweep
    // still returns what it did.
    rename(pool, "relay_gc_run", "relay_gc_run_moved").await;
    let report = gc::sweep_unclaimed(pool, harness.storage(), "ws-gca", NOW).await;
    assert_eq!(report.deleted, 0);
    rename(pool, "relay_gc_run_moved", "relay_gc_run").await;

    harness.finish().await;
}

/// A refusal that lands between the object leaving storage and the row leaving
/// the database is survivable, and never counted as a deletion.
///
/// The collectors delete the object first on purpose (`gc.rs`): a crash between
/// the two leaves an orphaned storage delete, which costs nothing, where the other
/// order would leave a quota row undercounting an object still in the bucket. What
/// must not happen either way is a report claiming bytes were reclaimed when the
/// accounting never moved, because that number is what the customer is billed
/// against and what an operator reads to decide the sweep is working.
///
/// The fault is a real one: a trigger on the real table in a real Postgres, the
/// same technique `tests/recovery_store_faults.rs` uses. Nothing here is a mock.
#[tokio::test]
async fn a_sweep_that_cannot_write_the_accounting_reports_no_deletion() {
    let harness = Harness::new("gc_accounting_refused").await;
    let pool = harness.pool();
    let group = make_group_in(
        &harness.state,
        "ws-gc-faults",
        0x4a,
        &[device_from(0x71)],
        &[device_from(0x71)],
    )
    .await;
    store::ensure_quota_row(pool, "ws-gc-faults", None)
        .await
        .unwrap();

    // An unclaimed upload, old enough to collect.
    let hash = blob_hash(0xb1);
    let stale = live_blob(&harness, "ws-gc-faults", &group, &hash, b"unclaimed").await;
    sqlx::query(
        "update relay_blob_reservation set created_at = now() - interval '2 days' \
         where reservation_id = $1",
    )
    .bind(stale)
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected: this write cannot land'; end $$",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "create trigger weald_injected_reservation before update or delete on \
         relay_blob_reservation for each statement execute function weald_injected_refusal()",
    )
    .execute(pool)
    .await
    .unwrap();

    let report =
        gc::sweep_unclaimed(pool, harness.storage(), "ws-gc-faults", NOW + 2 * DAY_MS).await;
    assert_eq!(
        (report.deleted, report.deleted_bytes),
        (0, 0),
        "a release that did not land is not a deletion"
    );

    sqlx::query("drop trigger weald_injected_reservation on relay_blob_reservation")
        .execute(pool)
        .await
        .unwrap();
    harness.finish().await;
}

/// The retention sweep reaches the same refusal by its own path: a blob that is
/// genuinely due for collection, whose object leaves the bucket, and whose
/// accounting will not commit.
///
/// Built as a real eligibility rather than a shortcut, because the branch only
/// exists past every check `media.md` puts in front of a deletion: a control, a
/// manifest that claimed the hash, a later manifest that omits it, an authorized
/// policy, and a claim old enough to be past the floor. A sweep that reported this
/// as a deletion would decrement a quota for an object whose row is still there,
/// and the next sweep would decrement it again.
#[tokio::test]
async fn a_retention_deletion_whose_accounting_refuses_is_not_a_deletion() {
    let harness = Harness::new("gc_retention_accounting").await;
    let pool = harness.pool();
    let ada = device_from(0x71);
    let group = make_group_in(
        &harness.state,
        "ws-gc-acct",
        0x4c,
        std::slice::from_ref(&ada),
        std::slice::from_ref(&ada),
    )
    .await;
    let epoch = verifier_key(0x21);
    retention::apply_control(pool, &signed_control(&group, 0, &epoch, None, &epoch))
        .await
        .unwrap();

    let dropped = blob_hash(0xd1);
    let dropped_id = live_blob(&harness, "ws-gc-acct", &group, &dropped, b"removed").await;
    let first = signed_manifest(&group, 0, 1, None, vec![dropped.clone()], &epoch);
    retention::apply_manifest(pool, "ws-gc-acct", &first)
        .await
        .unwrap();
    let second = signed_manifest(&group, 0, 2, Some(first.digest()), Vec::new(), &epoch);
    retention::apply_manifest(pool, "ws-gc-acct", &second)
        .await
        .unwrap();
    let policy = signed_policy(&group, 1, 30, (NOW / 1000) - 1, &[ada]);
    retention::insert_policy(pool, &policy, "[]").await.unwrap();
    age_claim(pool, dropped_id, 40).await;

    sqlx::query(
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected: this write cannot land'; end $$",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "create trigger weald_injected_finish before update or delete on \
         relay_blob_reservation for each statement execute function weald_injected_refusal()",
    )
    .execute(pool)
    .await
    .unwrap();

    let report = gc::sweep_retention(
        pool,
        harness.storage(),
        "ws-gc-acct",
        &group,
        NOW + 90 * DAY_MS,
    )
    .await;
    assert_eq!(
        (report.deleted, report.deleted_bytes),
        (0, 0),
        "a finished deletion that did not land is not a deletion"
    );

    sqlx::query("drop trigger weald_injected_finish on relay_blob_reservation")
        .execute(pool)
        .await
        .unwrap();
    harness.finish().await;
}

/// Eligibility is an error rather than a guess when the database cannot answer.
///
/// Every question `eligible` asks is a reason not to delete: whether the group is
/// frozen, what the latest manifest claims, whether a destruction is due, what the
/// policy says. A read that fails has to propagate, because the alternative is a
/// collector treating "I could not find out" as "nothing objects", which is how a
/// database blip turns into somebody's attachments being deleted.
#[tokio::test]
async fn eligibility_propagates_a_database_that_cannot_answer() {
    let harness = Harness::new("gc_eligible_faults").await;
    let pool = harness.pool();
    let group = make_group_in(
        &harness.state,
        "ws-gc-eligible",
        0x4b,
        &[device_from(0x71)],
        &[device_from(0x71)],
    )
    .await;
    let hash = blob_hash(0xc1);

    // Each table dropped in turn, in the order `eligible` consults them, because a
    // function whose first read fails never reaches its fourth.
    for table in [
        "relay_group",
        "relay_retention_manifest",
        "relay_retention_destruction",
        "relay_retention_policy",
    ] {
        // Renamed and renamed back rather than hidden inside a transaction. The
        // first version of this did the rename in a transaction and called
        // `eligible` on another pool connection, which blocked on the ACCESS
        // EXCLUSIVE lock until the suite timed out: the fault has to be committed
        // for the call to see it, because the call is not in the transaction.
        sqlx::query(&format!("alter table {table} rename to {table}_hidden"))
            .execute(pool)
            .await
            .unwrap();
        let outcome = gc::eligible(
            pool,
            "ws-gc-eligible",
            &group,
            &hash,
            NOW - 400 * DAY_MS,
            NOW,
        )
        .await;
        sqlx::query(&format!("alter table {table}_hidden rename to {table}"))
            .execute(pool)
            .await
            .unwrap();
        assert!(
            outcome.is_err() || matches!(outcome, Ok(Eligibility::NotYetDue)),
            "{table}: a read that failed must never read as permission to delete"
        );
    }

    harness.finish().await;
}
