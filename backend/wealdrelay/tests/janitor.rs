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
    blob_hash, config_for, config_with, device_from, make_group_in, signed_control,
    signed_manifest, verifier_key, Running, Scratch,
};

const NOW: u64 = 1_800_000_000_000;

struct Harness {
    scratch: Scratch,
    _blobs: tempfile::TempDir,
    state: Arc<RelayState>,
}

impl Harness {
    async fn new(label: &str) -> Self {
        Self::with(label, config_for).await
    }

    /// The same harness with a configuration of the caller's choosing, for the two
    /// proofs that are about a setting rather than about a sweep.
    async fn with(label: &str, configure: impl Fn(&Scratch, &std::path::Path) -> Config) -> Self {
        let scratch = Scratch::new(label).await;
        let blobs = tempfile::tempdir().unwrap();
        let relay = Running::start(configure(&scratch, blobs.path()), Clock::Fixed(NOW)).await;
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

    fn blobs(&self) -> &std::path::Path {
        self._blobs.path()
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

/// The unclaimed grace is an operator setting with the promised default, and zero
/// is legal because a probe instance is exactly the deployment that wants an
/// unfinalized reservation collectable on the next pass.
#[test]
fn the_unclaimed_grace_defaults_to_the_promised_day_and_accepts_zero() {
    let base = [
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@localhost/weald_relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
    ];
    let resolved = Config::resolve(&Values::from_pairs(base)).expect("the default resolves");
    assert_eq!(
        resolved.media_unclaimed_grace_seconds,
        wealdrelay::media::gc::UNCLAIMED_GRACE_SECONDS as u64,
        "the default is the 24 hours media.md promises"
    );

    let named = Config::resolve(&Values::from_pairs(
        base.into_iter()
            .chain([(keys::MEDIA_UNCLAIMED_GRACE_SECONDS, "0")]),
    ))
    .expect("zero resolves");
    assert_eq!(named.media_unclaimed_grace_seconds, 0);

    assert!(
        Config::resolve(&Values::from_pairs(
            base.into_iter()
                .chain([(keys::MEDIA_UNCLAIMED_GRACE_SECONDS, "a day")]),
        ))
        .is_err(),
        "a word is not a number of seconds"
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

// MARK: The forced pass

/// One request against the private router, without binding a port. The same shape
/// `health_operator.rs` uses, kept local because this suite needs a POST with a
/// body and that one does not.
async fn post(
    state: &Arc<RelayState>,
    uri: &str,
    authorization: Option<&str>,
    body: &str,
) -> (axum::http::StatusCode, String) {
    use tower::ServiceExt as _;
    let mut request = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri(uri)
        .header(axum::http::header::CONTENT_TYPE, "application/json");
    if let Some(value) = authorization {
        request = request.header(axum::http::header::AUTHORIZATION, value);
    }
    let response = wealdrelay::health::private_router(Arc::clone(state))
        .oneshot(
            request
                .body(axum::body::Body::from(body.to_string()))
                .expect("a request"),
        )
        .await
        .expect("the router answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("a body");
    (status, String::from_utf8_lossy(&bytes).to_string())
}

const OPERATOR: &str = "operator-bearer-for-the-forced-sweep";

/// The proof that closes the multiplayer scenario "a file nobody attached
/// disappears" (mp.30 in `.claude/skills/multiplayer-scenarios/scenarios.json`).
///
/// The behaviour is real and its window is a day, so no probe against a running
/// relay could ever see it: the collector's own clock is a quarter hour and the
/// grace it enforces is 24 hours. Two operator surfaces make it observable in one
/// session, and this test drives both exactly as an operator would. The grace is
/// shortened by `WEALD_RELAY_MEDIA_UNCLAIMED_GRACE_SECONDS` and the pass is forced
/// by `POST /gc/sweep` with the operator bearer. The claimed object in the same
/// workspace is the half that makes the deletion mean anything.
#[tokio::test]
async fn a_forced_pass_with_a_short_grace_deletes_only_the_unclaimed_object() {
    let harness = Harness::with("janitor_forced", |scratch, blobs| {
        config_with(
            scratch,
            blobs,
            [
                (keys::MEDIA_UNCLAIMED_GRACE_SECONDS, "0".to_string()),
                (keys::OPERATOR_TOKEN, OPERATOR.to_string()),
            ],
        )
    })
    .await;
    let pool = harness.pool();
    let ada = device_from(0x71);
    let group = make_group_in(
        &harness.state,
        "ws-jan9",
        0x59,
        std::slice::from_ref(&ada),
        std::slice::from_ref(&ada),
    )
    .await;
    let epoch = verifier_key(0x29);
    retention::apply_control(pool, &signed_control(&group, 0, &epoch, None, &epoch))
        .await
        .unwrap();
    store::ensure_quota_row(pool, "ws-jan9", None)
        .await
        .unwrap();

    // The attachment somebody sent: reserved, stored, and named by a valid manifest.
    let claimed = blob_hash(0xc1);
    reserved_blob(&harness, "ws-jan9", &group, &claimed, b"attached").await;
    retention::apply_manifest(
        pool,
        "ws-jan9",
        &signed_manifest(&group, 0, 1, None, vec![claimed.clone()], &epoch),
    )
    .await
    .unwrap();

    // The upload nobody ever claimed: reserved and stored seconds ago, which is
    // why the shortened grace is the whole point. Nothing here backdates a row.
    let unclaimed = blob_hash(0xc2);
    reserved_blob(&harness, "ws-jan9", &group, &unclaimed, b"orphan").await;

    // The bearer first, because a route that runs the collector for anybody who can
    // reach the private port is worse than no route.
    let (status, body) = post(&harness.state, "/gc/sweep", None, "{}").await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    assert!(body.contains("operator token required"), "{body}");
    assert!(
        harness
            .storage()
            .head(&key("ws-jan9", &group, &unclaimed))
            .await
            .unwrap()
            .is_some(),
        "a refused request deleted something"
    );

    let (status, body) = post(
        &harness.state,
        "/gc/sweep",
        Some(&format!("Bearer {OPERATOR}")),
        "{\"storage_listing\":false}",
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let summary: serde_json::Value = serde_json::from_str(&body).expect("a pass summary");
    assert_eq!(summary["blobs_deleted"], 1, "{body}");
    assert_eq!(
        summary["storage_listings"], 0,
        "the caller asked for no listing"
    );

    assert!(
        harness
            .storage()
            .head(&key("ws-jan9", &group, &unclaimed))
            .await
            .unwrap()
            .is_none(),
        "the unclaimed object is still in the bucket"
    );
    assert!(
        harness
            .storage()
            .head(&key("ws-jan9", &group, &claimed))
            .await
            .unwrap()
            .is_some(),
        "the claimed object was collected, which is data loss"
    );
    assert_eq!(
        store::claimed_hashes(pool, "ws-jan9", &group)
            .await
            .unwrap()
            .len(),
        1,
        "the claimed reservation is still charged and nothing else is"
    );

    harness.finish().await;
}

/// The default is the promise. A relay nobody configured leaves an upload from a
/// minute ago alone, so the shortened grace above is a setting and not a change of
/// behaviour.
#[tokio::test]
async fn the_default_grace_leaves_a_fresh_unclaimed_upload_alone() {
    let harness = Harness::new("janitor_grace_default").await;
    let pool = harness.pool();
    let group = make_group_in(
        &harness.state,
        "ws-jan10",
        0x5a,
        &[device_from(0x71)],
        &[device_from(0x71)],
    )
    .await;
    store::ensure_quota_row(pool, "ws-jan10", None)
        .await
        .unwrap();
    let hash = blob_hash(0xc3);
    reserved_blob(&harness, "ws-jan10", &group, &hash, b"fresh").await;

    let summary = wealdrelay::janitor::pass(&harness.state).await;

    assert_eq!(summary.blobs_deleted, 0);
    assert!(
        harness
            .storage()
            .head(&key("ws-jan10", &group, &hash))
            .await
            .unwrap()
            .is_some(),
        "the default grace collected an upload that is seconds old"
    );

    harness.finish().await;
}

/// WEALD-L404: a pass whose part deletes fail leaves the session stale, so the
/// next healthy pass is the retry.
///
/// The abort used to be recorded first, and `stale_multipart_sessions` demands
/// `aborted_at is null`, so one storage outage dropped those sessions out of the
/// only selector that could ever reach their part objects again. The parts live
/// under the synthetic `_multipart` workspace, which neither gc sweep walks, so
/// they were orphaned in the bucket permanently while the summary still counted
/// the pass as a successful abort.
#[tokio::test]
async fn a_failed_part_delete_keeps_the_multipart_session_eligible() {
    let harness = Harness::new("janitor_multipart_retry").await;
    let pool = harness.pool();
    let group = make_group_in(
        &harness.state,
        "ws-jan9",
        0x59,
        &[device_from(0x79)],
        &[device_from(0x79)],
    )
    .await;
    store::ensure_quota_row(pool, "ws-jan9", None)
        .await
        .unwrap();

    let hash = blob_hash(0xb9);
    let reserved = store::reserve(pool, "ws-jan9", &group, &hash, 4096, false, 900)
        .await
        .unwrap();
    let store::Reserved::Active { reservation_id } = reserved else {
        panic!("expected a reservation, got {reserved:?}");
    };
    let session_id = store::create_multipart(pool, reservation_id, "upload-jan9", 1024, 60)
        .await
        .unwrap();
    store::record_part(pool, session_id, 1, 1024).await.unwrap();
    let part = wealdrelay::media::part_key_for(session_id, 1);
    harness.storage().put(&part, &[0x11; 16]).await.unwrap();
    sqlx::query("update relay_blob_multipart set expires_at = now() - interval '1 hour'")
        .execute(pool)
        .await
        .unwrap();

    // The injected outage: the directory holding the part object is made
    // read-only, so `remove_file` fails the way an unreachable bucket would.
    let part_directory = find_part_directory(harness.blobs());
    let original = std::fs::metadata(&part_directory).unwrap().permissions();
    let mut locked = original.clone();
    std::os::unix::fs::PermissionsExt::set_mode(&mut locked, 0o555);
    std::fs::set_permissions(&part_directory, locked).unwrap();

    let summary = wealdrelay::janitor::pass(&harness.state).await;

    assert_eq!(
        summary.multipart_aborted, 0,
        "a pass that cleaned nothing does not report an abort"
    );
    assert_eq!(
        store::stale_multipart_sessions(pool).await.unwrap().len(),
        1,
        "the session is still a candidate for the next pass"
    );
    assert!(
        harness.storage().get(&part).await.is_ok(),
        "the part object survived the failed pass"
    );

    std::fs::set_permissions(&part_directory, original).unwrap();

    let summary = wealdrelay::janitor::pass(&harness.state).await;

    assert_eq!(
        summary.multipart_aborted, 1,
        "the healthy pass is the retry"
    );
    assert!(
        harness.storage().get(&part).await.is_err(),
        "and it removed the part object"
    );
    assert!(
        store::stale_multipart_sessions(pool)
            .await
            .unwrap()
            .is_empty(),
        "an aborted session is never a candidate again"
    );

    harness.finish().await;
}

/// A session already marked aborted whose part objects survived is still swept.
///
/// The client-driven abort path (`media::mod::handle_multipart_abort`) deletes
/// the part objects with `let _ =` and marks the session aborted regardless, so
/// one failed delete there left objects nothing could ever reach: the janitor's
/// selector used to demand `aborted_at is null`. The marker that ends retries is
/// now the absence of part rows, so this session stays selectable and a healthy
/// pass removes the object (WEALD-L404).
#[tokio::test]
async fn an_aborted_session_with_surviving_parts_is_still_swept() {
    let harness = Harness::new("janitor_multipart_aborted_orphan").await;
    let pool = harness.pool();
    let group = make_group_in(
        &harness.state,
        "ws-jan10",
        0x5a,
        &[device_from(0x7a)],
        &[device_from(0x7a)],
    )
    .await;
    store::ensure_quota_row(pool, "ws-jan10", None)
        .await
        .unwrap();

    let hash = blob_hash(0xba);
    let reserved = store::reserve(pool, "ws-jan10", &group, &hash, 4096, false, 900)
        .await
        .unwrap();
    let store::Reserved::Active { reservation_id } = reserved else {
        panic!("expected a reservation, got {reserved:?}");
    };
    let session_id = store::create_multipart(pool, reservation_id, "upload-jan10", 1024, 60)
        .await
        .unwrap();
    store::record_part(pool, session_id, 1, 1024).await.unwrap();
    let part = wealdrelay::media::part_key_for(session_id, 1);
    harness.storage().put(&part, &[0x22; 16]).await.unwrap();
    // Exactly what the client path leaves behind when its delete failed: the row
    // aborted, the part object still in the bucket.
    sqlx::query(
        "update relay_blob_multipart set aborted_at = now(), \
         expires_at = now() - interval '1 hour'",
    )
    .execute(pool)
    .await
    .unwrap();

    assert_eq!(
        store::stale_multipart_sessions(pool).await.unwrap().len(),
        1,
        "an aborted session with part rows is still a candidate"
    );

    let _ = wealdrelay::janitor::pass(&harness.state).await;

    assert!(
        harness.storage().get(&part).await.is_err(),
        "the orphaned part object was deleted"
    );
    assert!(
        store::recorded_parts(pool, session_id)
            .await
            .unwrap()
            .is_empty(),
        "and the part rows are gone, so it never comes back"
    );
    assert!(
        store::stale_multipart_sessions(pool)
            .await
            .unwrap()
            .is_empty(),
        "a swept session leaves the candidate list for good"
    );

    harness.finish().await;
}

/// The one directory under the blob root holding a `_multipart` part object.
fn find_part_directory(root: &std::path::Path) -> std::path::PathBuf {
    fn walk(at: &std::path::Path, found: &mut Option<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(at) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if found.is_none() {
                *found = Some(path.parent().unwrap().to_path_buf());
            }
        }
    }
    let mut found = None;
    walk(root, &mut found);
    found.expect("a part object was written under the blob root")
}
