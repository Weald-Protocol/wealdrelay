// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The collector task: that a pass actually runs every sweep, and that running it
//! deletes nothing the eligibility rules did not authorize.
//!
//! `specs/backend/relay/janitor.md`. These are the proofs the collector's ticket
//! asks for, and every one of them fails against a tree with no collector in it,
//! because before this module existed nothing in the binary called any sweep at
//! all: the passes were `pub` functions whose only callers were tests.
//!
//! Real Postgres and a real filesystem-backed store, like the rest of the media
//! suites. The interval is not exercised here on purpose: asserting that a task
//! wakes up would be asserting on a sleep, so the loop's one job (call `pass` on a
//! clock) is left to `run` and the work `pass` does is proven directly.

mod support;

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use sqlx::PgPool;
use wealdrelay::config::{keys, Config, Values};
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::invite::code::Code;
use wealdrelay::invite::reserve::{self, Verdict};
use wealdrelay::invite::store as invite_store;
use wealdrelay::invite::{self, EncBundle, Invite};
use wealdrelay::media::{retention, store};
use wealdrelay::storage::{BlobKey, Store};

use support::{
    blob_hash, config_for, device_from, make_group_in, signed_control, signed_manifest,
    verifier_key, Running, Scratch,
};

const NOW: u64 = 1_800_000_000_000;

struct Harness {
    scratch: Scratch,
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

fn key(workspace: &str, group: &[u8], hash: &[u8]) -> BlobKey {
    BlobKey::new(
        workspace,
        wealdrelay::media::hex(group),
        wealdrelay::media::hex(hash),
    )
    .expect("the test's own keys are well formed")
}

/// A reservation with its object written: the state an upload is in between `BLOB
/// put` and the manifest claim that should follow it.
async fn reserved_blob(harness: &Harness, workspace: &str, group: &[u8], hash: &[u8], body: &[u8]) {
    store::reserve(
        harness.pool(),
        workspace,
        group,
        hash,
        body.len() as i64,
        false,
        900,
    )
    .await
    .unwrap();
    harness
        .storage()
        .put(&key(workspace, group, hash), body)
        .await
        .unwrap();
}

/// The headline proof. An upload nobody ever claimed is gone from the bucket and
/// its bytes are back in the workspace's quota after exactly one collector pass,
/// with no test anywhere calling a sweep by hand.
#[tokio::test]
async fn one_pass_collects_an_abandoned_upload_and_returns_its_bytes() {
    let harness = Harness::new("janitor_unclaimed").await;
    let pool = harness.pool();
    let group = make_group_in(
        &harness.state,
        "ws-jan1",
        0x51,
        &[device_from(0x71)],
        &[device_from(0x71)],
    )
    .await;
    store::ensure_quota_row(pool, "ws-jan1", None)
        .await
        .unwrap();

    let hash = blob_hash(0xb1);
    reserved_blob(&harness, "ws-jan1", &group, &hash, b"abandoned").await;
    sqlx::query(
        "update relay_blob_reservation set created_at = now() - interval '25 hours' \
         where workspace_id = 'ws-jan1'",
    )
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(
        store::usage(pool, "ws-jan1").await.unwrap().reserved_bytes,
        9,
        "the bytes are charged while the reservation stands"
    );

    let summary = wealdrelay::janitor::pass(&harness.state).await;

    assert_eq!(summary.blobs_deleted, 1);
    assert_eq!(summary.bytes_released, 9);
    assert_eq!(
        summary.scopes, 1,
        "one (workspace, group) pair was examined"
    );
    assert!(harness
        .storage()
        .head(&key("ws-jan1", &group, &hash))
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        store::usage(pool, "ws-jan1").await.unwrap().reserved_bytes,
        0,
        "and the quota is released, which is the half nothing did before"
    );

    harness.finish().await;
}

/// The negative proof. A blob named by the group's latest valid manifest is a live
/// attachment, and a collector that ran on a timer must not turn that into a
/// deletion. Nothing is removed, from storage or from the reservation table.
#[tokio::test]
async fn a_pass_never_deletes_a_blob_a_live_manifest_still_names() {
    let harness = Harness::new("janitor_live").await;
    let pool = harness.pool();
    let ada = device_from(0x71);
    let group = make_group_in(
        &harness.state,
        "ws-jan2",
        0x52,
        std::slice::from_ref(&ada),
        std::slice::from_ref(&ada),
    )
    .await;
    let epoch = verifier_key(0x21);
    retention::apply_control(pool, &signed_control(&group, 0, &epoch, None, &epoch))
        .await
        .unwrap();
    store::ensure_quota_row(pool, "ws-jan2", None)
        .await
        .unwrap();

    let hash = blob_hash(0xb2);
    reserved_blob(&harness, "ws-jan2", &group, &hash, b"live").await;
    retention::apply_manifest(
        pool,
        "ws-jan2",
        &signed_manifest(&group, 0, 1, None, vec![hash.clone()], &epoch),
    )
    .await
    .unwrap();
    // Old enough that every grace period the passes enforce has elapsed. The only
    // thing standing between this object and deletion is the manifest.
    sqlx::query(
        "update relay_blob_reservation set created_at = now() - interval '400 days', \
                finalized_at = now() - interval '400 days' \
         where workspace_id = 'ws-jan2'",
    )
    .execute(pool)
    .await
    .unwrap();

    let summary = wealdrelay::janitor::pass(&harness.state).await;

    assert_eq!(
        summary.blobs_deleted, 0,
        "a referenced blob is never a candidate"
    );
    assert_eq!(summary.bytes_released, 0);
    assert!(
        harness
            .storage()
            .head(&key("ws-jan2", &group, &hash))
            .await
            .unwrap()
            .is_some(),
        "the object is still in the bucket"
    );
    assert_eq!(
        store::claimed_hashes(pool, "ws-jan2", &group)
            .await
            .unwrap()
            .len(),
        1,
        "and its reservation row is still there"
    );

    harness.finish().await;
}

/// A multipart session past its expiry is aborted by a pass. Aborting is all this
/// step does: the reservation stays unfinalized so the unclaimed pass is what
/// eventually returns the bytes, under the same 24-hour grace as any other upload.
#[tokio::test]
async fn one_pass_aborts_an_expired_multipart_session() {
    let harness = Harness::new("janitor_multipart").await;
    let pool = harness.pool();
    let group = make_group_in(
        &harness.state,
        "ws-jan3",
        0x53,
        &[device_from(0x71)],
        &[device_from(0x71)],
    )
    .await;
    store::ensure_quota_row(pool, "ws-jan3", None)
        .await
        .unwrap();

    let hash = blob_hash(0xb3);
    // `already_stored: false`. Passing true short circuits to `AlreadyStored` and
    // never writes a reservation row, so there would be nothing for a multipart
    // session to hang off.
    let reserved = store::reserve(pool, "ws-jan3", &group, &hash, 4096, false, 900)
        .await
        .unwrap();
    let store::Reserved::Active { reservation_id } = reserved else {
        panic!("expected a reservation, got {reserved:?}");
    };
    store::create_multipart(pool, reservation_id, "upload-jan3", 1024, 60)
        .await
        .unwrap();
    sqlx::query("update relay_blob_multipart set expires_at = now() - interval '1 hour'")
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(
        store::stale_multipart_sessions(pool).await.unwrap().len(),
        1
    );

    let summary = wealdrelay::janitor::pass(&harness.state).await;

    assert_eq!(summary.multipart_aborted, 1);
    assert!(
        store::stale_multipart_sessions(pool)
            .await
            .unwrap()
            .is_empty(),
        "an aborted session is never a candidate again"
    );

    harness.finish().await;
}

/// The seat-recovery proof the ticket asks for. Capacity is decremented on
/// reserve and only `invite::reserve::release_expired` returns it; before this
/// pass called that function an abandoned setup burned a seat permanently, and a
/// two-use invite with one stalled reservation and one still-live reservation
/// would refuse forever. One collector pass must free exactly the stalled seat
/// and leave the live one alone.
#[tokio::test]
async fn one_pass_frees_a_seat_an_abandoned_reservation_never_returned() {
    use ed25519_dalek::Signer as _;

    let harness = Harness::new("janitor_invite").await;
    let pool = harness.pool();

    let issuer = SigningKey::from_bytes(&[0x21; 32]);
    let token = vec![0x22; 16];
    let code = Code::from_bits(6);
    let code_hash = invite::code::hash(code, &token).unwrap().to_vec();
    let group = vec![0x23; 32];
    let mut invite_record = Invite {
        token: token.clone(),
        workspace: group.clone(),
        issuer: issuer.verifying_key().to_bytes().to_vec(),
        issued_at: NOW,
        expires: NOW + 30 * 24 * 60 * 60 * 1000,
        uses: 2,
        code_hash,
        scopes: vec![group.clone()],
        caps: vec![b"chat.read".to_vec()],
        update_pub: vec![0x33; 32],
        bundles: vec![EncBundle {
            group: group.clone(),
            epoch: 1,
            ct: b"sealed group info".to_vec(),
        }],
        sig: vec![0u8; 64],
    };
    invite_record.sig = issuer
        .sign(&invite_record.digest_input())
        .to_bytes()
        .to_vec();
    invite_store::create(pool, "ws-jan-invite", &invite_record, NOW as i64)
        .await
        .unwrap();

    // A reservation made ten minutes and one second before the fixed clock the
    // collector reads: expired by the time `pass` runs, exactly the abandoned-setup
    // case the ticket describes.
    let stalled_now = NOW as i64 - (reserve::RESERVATION_SECONDS + 1) * 1000;
    let stalled = reserve::reserve(
        pool,
        &token,
        &code.grouped(),
        &[0x41; 16],
        &[0x51; 32],
        &[0x61; 32],
        stalled_now,
    )
    .await
    .unwrap();
    assert!(matches!(stalled, Verdict::Reserved { .. }));

    // A second, still-live reservation taken just now: the pass must not touch it.
    let live = reserve::reserve(
        pool,
        &token,
        &code.grouped(),
        &[0x42; 16],
        &[0x52; 32],
        &[0x62; 32],
        NOW as i64,
    )
    .await
    .unwrap();
    assert!(matches!(live, Verdict::Reserved { .. }));

    assert_eq!(
        invite_store::fetch(pool, &token)
            .await
            .unwrap()
            .unwrap()
            .remaining,
        0,
        "both seats are taken before the pass runs"
    );

    let summary = wealdrelay::janitor::pass(&harness.state).await;

    assert_eq!(summary.invite_seats_released, 1);
    assert_eq!(
        invite_store::fetch(pool, &token)
            .await
            .unwrap()
            .unwrap()
            .remaining,
        1,
        "the stalled seat came back and the live one was left alone"
    );

    // Idempotent: a second pass frees nothing more.
    let again = wealdrelay::janitor::pass(&harness.state).await;
    assert_eq!(again.invite_seats_released, 0);

    harness.finish().await;
}

/// The storage-listing sweep is the one sweep that costs a vendor operation per
/// look rather than per deletion, so the loop runs it on a multiple of the interval
/// and `pass_with(state, false)` is the pass that skips it. Every other sweep still
/// runs, and the scope walk still happens, because the retention pass shares it.
#[tokio::test]
async fn a_pass_can_skip_the_storage_listing_without_skipping_anything_else() {
    let harness = Harness::new("janitor_listing_cadence").await;
    let group = make_group_in(
        &harness.state,
        "ws-jan6",
        0x66,
        &[device_from(0x76)],
        &[device_from(0x76)],
    )
    .await;
    store::ensure_quota_row(harness.pool(), "ws-jan6", None)
        .await
        .unwrap();
    reserved_blob(&harness, "ws-jan6", &group, &blob_hash(0xb6), b"listed").await;

    let skipped = wealdrelay::janitor::pass_with(&harness.state, false).await;
    assert_eq!(
        skipped.storage_listings, 0,
        "no object storage was listed, which is the billed operation"
    );
    assert_eq!(
        skipped.scopes, 1,
        "the scope was still walked, because retention runs on the same list"
    );

    let listed = wealdrelay::janitor::pass_with(&harness.state, true).await;
    assert_eq!(listed.storage_listings, 1);
    assert_eq!(listed.scopes, 1);

    // `pass` means everything, so it is the listing variant and stays that way for
    // every test that predates the split.
    assert_eq!(
        wealdrelay::janitor::pass(&harness.state)
            .await
            .storage_listings,
        1
    );

    // The cadence itself: one listing pass in ninety-six, and never on the first
    // pass of a fresh process.
    // `const` blocks, because both of these are assertions about a constant and
    // clippy refuses a runtime `assert!` that can only ever hold or only ever
    // fail. A const block is the stronger form anyway: it fails the build rather
    // than one test run, which is what an assertion about a compile-time value
    // deserves.
    const { assert!(wealdrelay::janitor::STORAGE_LISTING_EVERY > 1) };
    let listing_passes = (1..=wealdrelay::janitor::STORAGE_LISTING_EVERY)
        .filter(|pass| pass % wealdrelay::janitor::STORAGE_LISTING_EVERY == 0)
        .count();
    assert_eq!(listing_passes, 1);
    const { assert!(1 % wealdrelay::janitor::STORAGE_LISTING_EVERY != 0) };

    harness.finish().await;
}

/// The work list is the distinct (workspace, group) pairs that have reserved a
/// blob, so two groups in one workspace are two scopes and a workspace that never
/// reserved anything is none.
#[tokio::test]
async fn the_work_list_is_every_scope_that_ever_reserved_a_blob() {
    let harness = Harness::new("janitor_scopes").await;
    let pool = harness.pool();
    let first = make_group_in(
        &harness.state,
        "ws-jan4",
        0x54,
        &[device_from(0x71)],
        &[device_from(0x71)],
    )
    .await;
    let second = make_group_in(
        &harness.state,
        "ws-jan4",
        0x55,
        &[device_from(0x71)],
        &[device_from(0x71)],
    )
    .await;
    store::ensure_quota_row(pool, "ws-jan4", None)
        .await
        .unwrap();

    assert!(
        store::active_scopes(pool).await.unwrap().is_empty(),
        "nothing reserved, nothing to sweep"
    );
    reserved_blob(&harness, "ws-jan4", &first, &blob_hash(0xb4), b"one").await;
    reserved_blob(&harness, "ws-jan4", &second, &blob_hash(0xb5), b"two").await;

    let scopes = store::active_scopes(pool).await.unwrap();
    assert_eq!(scopes.len(), 2);
    assert!(scopes.iter().all(|(workspace, _)| workspace == "ws-jan4"));
    assert_eq!(wealdrelay::janitor::pass(&harness.state).await.scopes, 2);

    harness.finish().await;
}

/// No database, no collector. `prepare` and `--check-config` drive the same code
/// path and neither should have a scanner running behind it.
#[tokio::test]
async fn no_database_means_no_collector_and_an_empty_pass() {
    let scratch = Scratch::new("janitor_nodb").await;
    let blobs = tempfile::tempdir().unwrap();
    // Built directly rather than through a running relay, because the case being
    // proven is the one where connecting never happened.
    let bare = Arc::new(RelayState::new(
        config_for(&scratch, blobs.path()),
        None,
        None,
    ));

    assert!(wealdrelay::janitor::spawn(&bare).is_none());
    assert_eq!(
        wealdrelay::janitor::pass(&bare).await,
        wealdrelay::janitor::Pass::default()
    );

    scratch.drop_database().await;
}

/// The interval is an operator setting with a documented default, and zero is
/// refused rather than read as "off", because a task that scans without pause is
/// not a posture anyone deploys.
#[test]
fn the_collector_interval_defaults_and_refuses_zero() {
    // The three keys `server.md` calls a complete configuration, and nothing else.
    let base = [
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@localhost/weald_relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
    ];
    let resolved = Config::resolve(&Values::from_pairs(base)).expect("the default resolves");
    assert_eq!(
        resolved.janitor_interval_ms,
        wealdrelay::janitor::DEFAULT_INTERVAL_MS
    );

    let named = Config::resolve(&Values::from_pairs(
        base.into_iter()
            .chain([(keys::JANITOR_INTERVAL_MS, "60000")]),
    ))
    .expect("an explicit interval resolves");
    assert_eq!(named.janitor_interval_ms, 60_000);

    assert!(
        Config::resolve(&Values::from_pairs(
            base.into_iter().chain([(keys::JANITOR_INTERVAL_MS, "0")]),
        ))
        .is_err(),
        "zero is refused rather than read as off"
    );
}

/// A restore marker stops the storage-listing sweep for the passes it names, and
/// stops nothing else.
///
/// The countdown belongs here rather than to the sweep, because the sweep runs once
/// per (workspace, group): a marker counted down there would spend four passes of
/// protection inside one interval of a four-group workspace. Two groups here, so
/// that the pass proves the count is a count of passes.
#[tokio::test]
async fn a_restore_marker_suppresses_the_listing_sweep_pass_by_pass() {
    let harness = Harness::new("janitor_restore_marker").await;
    let pool = harness.pool();
    for (seed, hash) in [(0x67u8, 0xb7u8), (0x68, 0xb8)] {
        let group = make_group_in(
            &harness.state,
            "ws-jan7",
            seed,
            &[device_from(0x76)],
            &[device_from(0x76)],
        )
        .await;
        store::ensure_quota_row(pool, "ws-jan7", None)
            .await
            .unwrap();
        reserved_blob(&harness, "ws-jan7", &group, &blob_hash(hash), b"listed").await;
    }

    let passes = wealdrelay::media::restore::DEFAULT_SUPPRESSED_PASSES;
    wealdrelay::media::restore::set(pool, passes, "database restore")
        .await
        .unwrap();

    for expected in [4, 3, 2, 1] {
        assert_eq!(
            wealdrelay::media::restore::remaining(pool).await.unwrap(),
            Some(expected)
        );
        let summary = wealdrelay::janitor::pass(&harness.state).await;
        assert!(
            summary.storage_listing_suppressed,
            "the marker is set, so this pass lists nothing"
        );
        assert_eq!(summary.storage_listings, 0);
        assert_eq!(
            summary.scopes, 2,
            "the retention pass is untouched: only the listing sweep is suppressed"
        );
    }

    // Spent. The next pass is an ordinary one.
    assert_eq!(
        wealdrelay::media::restore::remaining(pool).await.unwrap(),
        None
    );
    let summary = wealdrelay::janitor::pass(&harness.state).await;
    assert!(!summary.storage_listing_suppressed);
    assert_eq!(summary.storage_listings, 2);

    // A pass that was not going to list anyway spends nothing, so the protection is
    // not burned by the ninety-five passes between listings.
    wealdrelay::media::restore::set(pool, 2, "another restore")
        .await
        .unwrap();
    let skipped = wealdrelay::janitor::pass_with(&harness.state, false).await;
    assert!(!skipped.storage_listing_suppressed);
    assert_eq!(
        wealdrelay::media::restore::remaining(pool).await.unwrap(),
        Some(2)
    );

    harness.finish().await;
}
