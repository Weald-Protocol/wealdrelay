// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Invites against real Postgres: the record, the seat, the code, and the bundles.
//!
//! Nothing here is mocked and nothing here is skipped. The database is the harness
//! Postgres from `scripts/weald-stack`, the migrations are the ones the binary
//! embeds, and the seat arithmetic is proven by taking seats rather than by reading
//! the SQL.
//!
//! The negatives lead, because they are what the design is for: an invite missing
//! its workspace root never reaches the table, five wrong codes cool one tuple down
//! without burning the invite, and every refusal a joiner can provoke answers with
//! the same word.

mod support;

use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey};
use sqlx::{PgPool, Row as _};
use wealdrelay::access::store as access_store;
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::invite::code::Code;
use wealdrelay::invite::reserve::{self, Verdict};
use wealdrelay::invite::store::{self, State, StoreError};
use wealdrelay::invite::{self, EncBundle, Invite, InviteError};

use support::{config_for, Running, Scratch};

const WORKSPACE: &str = "ws-invite";
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

fn token(seed: u8) -> Vec<u8> {
    vec![seed; 16]
}

fn nonce(seed: u8) -> Vec<u8> {
    vec![seed; 16]
}

/// One record, with a real Argon2id hash of a real code.
fn issue(issuer: &SigningKey, token: Vec<u8>, code: Code, uses: u8, expires: u64) -> Invite {
    let code_hash = invite::code::hash(code, &token).unwrap().to_vec();
    let mut record = Invite {
        token,
        workspace: root(),
        issuer: issuer.verifying_key().to_bytes().to_vec(),
        issued_at: NOW as u64,
        expires,
        uses,
        code_hash,
        scopes: vec![root()],
        caps: vec![b"chat.read".to_vec()],
        update_pub: vec![0x33; 32],
        bundles: vec![EncBundle {
            group: root(),
            epoch: 1,
            ct: b"sealed group info one".to_vec(),
        }],
        sig: vec![0u8; 64],
    };
    record.sig = issuer.sign(&record.digest_input()).to_bytes().to_vec();
    record
}

fn ordinary(seed: u8, code: Code) -> Invite {
    issue(
        &key(1),
        token(seed),
        code,
        1,
        NOW as u64 + invite::DEFAULT_EXPIRY_MS,
    )
}

// MARK: The negatives

#[tokio::test]
async fn the_relay_rejects_a_record_that_omits_its_declared_workspace_root() {
    let (scratch, _blobs, state) = prepared("root").await;
    let pool = pool_of(&state);
    let issuer = key(1);

    let mut record = ordinary(0xa1, Code::from_bits(1));
    record.scopes = vec![vec![0x44; 32]];
    record.bundles = vec![EncBundle {
        group: vec![0x44; 32],
        epoch: 1,
        ct: b"x".to_vec(),
    }];
    record.sig = issuer.sign(&record.digest_input()).to_bytes().to_vec();

    let refused = store::create(pool, WORKSPACE, &record, NOW).await;
    assert!(matches!(
        refused,
        Err(StoreError::Refused(InviteError::MissingWorkspaceRoot))
    ));
    // And nothing was written: a refused record must not be findable.
    assert!(store::fetch(pool, &record.token).await.unwrap().is_none());

    // A scopeless record cannot buy the bootstrap exemption through this door
    // either. `create` never passes it, and that is the whole of the rule.
    let mut scopeless = ordinary(0xa2, Code::from_bits(1));
    scopeless.scopes.clear();
    scopeless.bundles.clear();
    scopeless.caps = vec![b"admin".to_vec()];
    scopeless.sig = issuer.sign(&scopeless.digest_input()).to_bytes().to_vec();
    assert!(matches!(
        store::create(pool, WORKSPACE, &scopeless, NOW).await,
        Err(StoreError::Refused(InviteError::ScopelessAndNotBootstrap))
    ));
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_tampered_or_expired_record_never_reaches_the_table() {
    let (scratch, _blobs, state) = prepared("tamper").await;
    let pool = pool_of(&state);

    let mut tampered = ordinary(0xb1, Code::from_bits(2));
    tampered.uses = 5;
    assert!(matches!(
        store::create(pool, WORKSPACE, &tampered, NOW).await,
        Err(StoreError::Refused(InviteError::BadSignature))
    ));

    let expired = ordinary(0xb2, Code::from_bits(2));
    assert!(matches!(
        store::create(pool, WORKSPACE, &expired, expired.expires as i64).await,
        Err(StoreError::Refused(InviteError::Expired))
    ));
    scratch.drop_database().await;
}

#[tokio::test]
async fn five_wrong_codes_cool_one_tuple_down_and_burn_nothing() {
    let (scratch, _blobs, state) = prepared("cooldown").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(0x0f0f0f);
    // Ten seats, so "the invite is not burnt" is a claim with something to lose.
    let record = issue(
        &key(1),
        token(0xc1),
        code,
        10,
        NOW as u64 + invite::DEFAULT_EXPIRY_MS,
    );
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();

    let wrong = Code::from_bits(0x0f0f0e).grouped();
    let source = vec![0x51; 32];
    let device = vec![0x52; 32];
    for attempt in 1..=5 {
        let verdict = reserve::reserve(
            pool,
            &record.token,
            &wrong,
            &nonce(1),
            &device,
            &source,
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(verdict, Verdict::Unavailable, "attempt {attempt}");
    }

    // The tuple is cooled down, and the right code from that tuple gets the same
    // generic answer: telling them they are throttled would confirm the token exists.
    assert_eq!(
        reserve::reserve(
            pool,
            &record.token,
            &code.grouped(),
            &nonce(1),
            &device,
            &source,
            NOW
        )
        .await
        .unwrap(),
        Verdict::Unavailable
    );

    // Nothing was burnt. All ten seats are there and the invite is live.
    let stored = store::fetch(pool, &record.token).await.unwrap().unwrap();
    assert_eq!(stored.remaining, 10);
    assert_eq!(stored.state, State::Live);
    // A fresh device value from the cooled source buys nothing: the cooldown is
    // keyed on the source because the device is whatever bytes the caller supplied
    // (WEALD-287), so a guesser minting a new device per attempt is still bounded.
    let other_device = vec![0x53; 32];
    assert_eq!(
        reserve::reserve(
            pool,
            &record.token,
            &code.grouped(),
            &nonce(2),
            &other_device,
            &source,
            NOW
        )
        .await
        .unwrap(),
        Verdict::Unavailable
    );
    // A colleague on their own address is untouched and joins on the first try.
    let other_source = vec![0x54; 32];
    assert!(matches!(
        reserve::reserve(
            pool,
            &record.token,
            &code.grouped(),
            &nonce(2),
            &other_device,
            &other_source,
            NOW
        )
        .await
        .unwrap(),
        Verdict::Reserved { .. }
    ));

    // And the cooldown ends. Fifteen minutes later the first tuple is served again.
    let later = NOW + 16 * 60 * 1000;
    assert!(matches!(
        reserve::reserve(
            pool,
            &record.token,
            &code.grouped(),
            &nonce(3),
            &device,
            &source,
            later
        )
        .await
        .unwrap(),
        Verdict::Reserved { .. }
    ));
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_fresh_device_per_attempt_buys_no_fresh_allowance_and_writes_no_fresh_row() {
    // WEALD-287. The device value in a `Reserve` frame is an arbitrary byte string
    // chosen by the caller, pre-authentication. The old cooldown key included it,
    // so every attempt with a new device was a new tuple with `failures = 1` and
    // the five-guess bound was unbounded from one address. The key is now the
    // source, and this is the property: N attempts with N distinct device values
    // from one source are refused after the configured ceiling.
    let (scratch, _blobs, state) = prepared("device_minting").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(0x0a0a0a);
    let record = issue(
        &key(1),
        token(0xc7),
        code,
        10,
        NOW as u64 + invite::DEFAULT_EXPIRY_MS,
    );
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();

    let wrong = Code::from_bits(0x0a0a0b).grouped();
    let source = vec![0x58; 32];
    // Far more attempts than the ceiling, every one wearing a fresh device.
    for attempt in 0u8..20 {
        let device = vec![attempt; 32];
        let verdict = reserve::reserve(
            pool,
            &record.token,
            &wrong,
            &nonce(attempt),
            &device,
            &source,
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(verdict, Verdict::Unavailable, "attempt {attempt}");
    }

    // The right code from that source, on yet another fresh device, is refused:
    // the source is cooled down and the device is not part of the key.
    assert_eq!(
        reserve::reserve(
            pool,
            &record.token,
            &code.grouped(),
            &nonce(0x30),
            &[0xee; 32],
            &source,
            NOW
        )
        .await
        .unwrap(),
        Verdict::Unavailable
    );

    // One row for the source, not one per minted device: the attempt table is
    // bounded by real addresses rather than by strings the guesser invents.
    let rows: i64 =
        sqlx::query_scalar("select count(*) from relay_invite_attempt where token = $1")
            .bind(&record.token)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(rows, 1, "a minted device wrote its own row");

    // And the cooled attempts stopped counting failures: the early return happens
    // before the code is parsed or hashed, so a token in cooldown never reaches
    // Argon2id and never moves the counter.
    let failures: i32 =
        sqlx::query_scalar("select failures from relay_invite_attempt where token = $1")
            .bind(&record.token)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        failures,
        wealdrelay::invite::code::MAX_FAILURES,
        "attempts inside the cooldown still ran the verification path"
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_guesser_spread_over_many_sources_is_bounded_by_the_token_ceiling() {
    // The second half of WEALD-287: dropping the device from the key must not
    // leave "one source per guess" as the workaround, so the token itself cools
    // down once the failures across every source reach the global ceiling.
    let (scratch, _blobs, state) = prepared("distributed").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(0x0b0b0b);
    let record = issue(
        &key(1),
        token(0xc8),
        code,
        10,
        NOW as u64 + invite::DEFAULT_EXPIRY_MS,
    );
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();

    let wrong = Code::from_bits(0x0b0b0c).grouped();
    let per_source = i64::from(wealdrelay::invite::code::MAX_FAILURES);
    let sources_to_ceiling = wealdrelay::invite::code::MAX_TOKEN_FAILURES / per_source;
    for source_index in 0..sources_to_ceiling {
        let source = vec![0x80 + source_index as u8; 32];
        for attempt in 0..per_source {
            let verdict = reserve::reserve(
                pool,
                &record.token,
                &wrong,
                &nonce(attempt as u8),
                &[0x59; 32],
                &source,
                NOW,
            )
            .await
            .unwrap();
            assert_eq!(verdict, Verdict::Unavailable);
        }
    }

    // A brand-new source holding the right code is refused: the token-wide sum
    // has reached the ceiling, so a distributed guesser gains nothing by
    // rotating addresses.
    assert_eq!(
        reserve::reserve(
            pool,
            &record.token,
            &code.grouped(),
            &nonce(0x40),
            &[0x59; 32],
            &[0xaa; 32],
            NOW
        )
        .await
        .unwrap(),
        Verdict::Unavailable
    );

    // Nothing was burnt, exactly as with the per-source cooldown.
    let stored = store::fetch(pool, &record.token).await.unwrap().unwrap();
    assert_eq!(stored.remaining, 10);
    assert_eq!(stored.state, State::Live);

    // After the cooldown interval the stale rows are swept by the next failed
    // attempt, so the table is bounded and the token recovers.
    let later = NOW + 16 * 60 * 1000;
    let _ = reserve::reserve(
        pool,
        &record.token,
        &wrong,
        &nonce(0x41),
        &[0x59; 32],
        &[0xab; 32],
        later,
    )
    .await
    .unwrap();
    let rows: i64 =
        sqlx::query_scalar("select count(*) from relay_invite_attempt where token = $1")
            .bind(&record.token)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(rows, 1, "stale attempt rows were not swept");

    // And the right code from an untainted source is served again.
    assert!(matches!(
        reserve::reserve(
            pool,
            &record.token,
            &code.grouped(),
            &nonce(0x42),
            &[0x59; 32],
            &[0xac; 32],
            later
        )
        .await
        .unwrap(),
        Verdict::Reserved { .. }
    ));

    scratch.drop_database().await;
}

#[tokio::test]
async fn the_issuer_is_told_volume_and_is_told_no_address() {
    let (scratch, _blobs, state) = prepared("volume").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(9);
    let record = ordinary(0xd1, code);
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();

    let empty = reserve::attempt_volume(pool, &record.token).await.unwrap();
    assert_eq!(empty.failures, 0);
    assert_eq!(empty.tuples, 0);

    let wrong = Code::from_bits(10).grouped();
    let salt = access_store::salt(pool, WORKSPACE).await.unwrap();
    for (index, address) in ["203.0.113.7", "198.51.100.9"].iter().enumerate() {
        let source = reserve::source_hash(address, &salt);
        // The source is a salted hash before it ever reaches a column, so there is
        // nothing in the table for a notification to leak.
        assert_ne!(source, address.as_bytes());
        assert_eq!(source.len(), 32);
        for _ in 0..=index {
            reserve::reserve(
                pool,
                &record.token,
                &wrong,
                &nonce(1),
                &[0x60 + index as u8; 32],
                &source,
                NOW,
            )
            .await
            .unwrap();
        }
    }

    let volume = reserve::attempt_volume(pool, &record.token).await.unwrap();
    assert_eq!(volume.failures, 3);
    assert_eq!(volume.tuples, 2);
    // The whole notification is two numbers. There is no field for an address and
    // nowhere for one to go.
    assert_eq!(format!("{volume:?}").matches("hash").count(), 0);
    scratch.drop_database().await;
}

#[tokio::test]
async fn every_way_to_fail_a_redemption_answers_the_same_word() {
    let (scratch, _blobs, state) = prepared("flat").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(11);
    let source = vec![0x71; 32];
    let device = vec![0x72; 32];

    // Nonexistent.
    assert_eq!(
        reserve::reserve(
            pool,
            &token(0xff),
            &code.grouped(),
            &nonce(1),
            &device,
            &source,
            NOW
        )
        .await
        .unwrap(),
        Verdict::Unavailable
    );

    // Expired.
    let expiring = ordinary(0xe1, code);
    store::create(pool, WORKSPACE, &expiring, NOW)
        .await
        .unwrap();
    assert_eq!(
        reserve::reserve(
            pool,
            &expiring.token,
            &code.grouped(),
            &nonce(1),
            &device,
            &source,
            expiring.expires as i64
        )
        .await
        .unwrap(),
        Verdict::Unavailable
    );

    // Revoked.
    let revoked = ordinary(0xe2, code);
    store::create(pool, WORKSPACE, &revoked, NOW).await.unwrap();
    assert!(store::revoke(pool, &revoked.token).await.unwrap());
    assert_eq!(
        reserve::reserve(
            pool,
            &revoked.token,
            &code.grouped(),
            &nonce(1),
            &device,
            &source,
            NOW
        )
        .await
        .unwrap(),
        Verdict::Unavailable
    );

    // Spent.
    let spent = ordinary(0xe3, code);
    store::create(pool, WORKSPACE, &spent, NOW).await.unwrap();
    assert!(store::mark_spent(pool, &spent.token).await.unwrap());
    assert_eq!(
        reserve::reserve(
            pool,
            &spent.token,
            &code.grouped(),
            &nonce(1),
            &device,
            &source,
            NOW
        )
        .await
        .unwrap(),
        Verdict::Unavailable
    );

    // Out of capacity: one seat, taken by somebody else.
    let single = ordinary(0xe4, code);
    store::create(pool, WORKSPACE, &single, NOW).await.unwrap();
    assert!(matches!(
        reserve::reserve(
            pool,
            &single.token,
            &code.grouped(),
            &nonce(1),
            &device,
            &source,
            NOW
        )
        .await
        .unwrap(),
        Verdict::Reserved { .. }
    ));
    assert_eq!(
        reserve::reserve(
            pool,
            &single.token,
            &code.grouped(),
            &nonce(2),
            &[0x73; 32],
            &source,
            NOW
        )
        .await
        .unwrap(),
        Verdict::Unavailable
    );

    // A terminate against a token that is not there is not an error either.
    assert!(!store::revoke(pool, &token(0xfe)).await.unwrap());
    scratch.drop_database().await;
}

// MARK: The record

#[tokio::test]
async fn a_stored_record_is_served_back_byte_for_byte() {
    let (scratch, _blobs, state) = prepared("bytes").await;
    let pool = pool_of(&state);
    let record = ordinary(0x01, Code::from_bits(3));
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();

    let stored = store::fetch(pool, &record.token).await.unwrap().unwrap();
    assert_eq!(stored.body, record.encode());
    assert_eq!(stored.invite, record);
    assert_eq!(stored.state, State::Live);
    assert_eq!(stored.remaining, 1);
    assert!(!stored.bootstrap);
    assert_eq!(stored.workspace_id, WORKSPACE);
    // The client verifies the issuer's signature over the bytes the relay served, so
    // this is the property that keeps the relay out of the trust path.
    assert!(stored.invite.signature_verifies());

    assert_eq!(
        store::live_tokens(pool, WORKSPACE).await.unwrap(),
        vec![record.token.clone()]
    );
    scratch.drop_database().await;
}

#[tokio::test]
async fn revocation_writes_the_tombstone_before_it_deletes_the_ciphertext() {
    let (scratch, _blobs, state) = prepared("revoke").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(4);
    let record = ordinary(0x02, code);
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();

    let device = vec![0x81; 32];
    assert!(matches!(
        reserve::reserve(
            pool,
            &record.token,
            &code.grouped(),
            &nonce(1),
            &device,
            &[0x82; 32],
            NOW
        )
        .await
        .unwrap(),
        Verdict::Reserved { .. }
    ));
    // The reservation is a connection credential, so the joiner is admitted.
    assert_eq!(
        access_store::admits(pool, WORKSPACE, &[]).await.unwrap(),
        access_store::Admission::Refused
    );
    let live: i64 = sqlx::query(
        "select count(*) as n from relay_provisional_grant \
         where workspace_id = $1 and device_hash = $2 and voided_at is null",
    )
    .bind(WORKSPACE)
    .bind(&device)
    .fetch_one(pool)
    .await
    .unwrap()
    .get("n");
    assert_eq!(live, 1);

    assert!(store::revoke(pool, &record.token).await.unwrap());

    // The tombstone survives with exactly what enforcement needs.
    assert_eq!(
        store::tombstoned_hashes(pool, &record.token)
            .await
            .unwrap()
            .unwrap(),
        vec![device.clone()]
    );
    assert!(store::tombstoned_hashes(pool, &token(0xfd))
        .await
        .unwrap()
        .is_none());
    // The ciphertext does not.
    assert!(store::bundles_for(pool, &record.token, &root())
        .await
        .unwrap()
        .is_empty());
    assert!(store::live_tokens(pool, WORKSPACE)
        .await
        .unwrap()
        .is_empty());
    // And the grant is void immediately: an unredeemed link dies and an issued
    // provisional grant is closed.
    let voided: i64 = sqlx::query(
        "select count(*) as n from relay_provisional_grant \
         where workspace_id = $1 and device_hash = $2 and voided_reason = 'revoked'",
    )
    .bind(WORKSPACE)
    .bind(&device)
    .fetch_one(pool)
    .await
    .unwrap()
    .get("n");
    assert_eq!(voided, 1);
    scratch.drop_database().await;
}

/// Revoking mid-join stops the join, and the joiner's own frames cannot undo it.
///
/// The failure this pins: `terminate` marks the invite but leaves the reservation
/// standing, so a commit judged against the reservation alone kept being accepted,
/// and the final one called `grant`, whose upsert used to clear `voided_at` and
/// re-arm the grant to the invite's original expiry. Revocation was undone by the
/// party it was aimed at. WEALD-286.
#[tokio::test]
async fn revoking_mid_join_stops_the_commits_and_the_last_one_cannot_revive_the_grant() {
    let (scratch, _blobs, state) = prepared("revoke_midjoin").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(41);
    let record = ordinary(0x2a, code);
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();
    let device = vec![0x91; 32];

    assert!(matches!(
        reserve::reserve(
            pool,
            &record.token,
            &code.grouped(),
            &nonce(1),
            &device,
            &[0x92; 32],
            NOW
        )
        .await
        .unwrap(),
        Verdict::Reserved { .. }
    ));

    // The admin revokes between two frames of the same join.
    assert!(store::revoke(pool, &record.token).await.unwrap());
    assert!(access_store::grant_is_voided(pool, WORKSPACE, &device)
        .await
        .unwrap());

    // Every remaining Commit is refused, including the last one.
    assert!(
        reserve::scope_commit(pool, &record.token, &nonce(1), &device, &root(), NOW)
            .await
            .unwrap()
            .is_none()
    );

    // The seat was not spent by a refused commit, and the grant is still void.
    let consumed: bool = sqlx::query(
        "select consumed_at is not null as done from relay_invite_reservation \
         where token = $1 and join_nonce = $2",
    )
    .bind(&record.token)
    .bind(nonce(1))
    .fetch_one(pool)
    .await
    .unwrap()
    .get("done");
    assert!(!consumed);
    assert!(access_store::grant_is_voided(pool, WORKSPACE, &device)
        .await
        .unwrap());

    // Specifically: granting again cannot clear voided_reason = 'revoked'.
    assert!(
        !access_store::grant(pool, WORKSPACE, &device, record.expires as i64)
            .await
            .unwrap()
    );
    let reason: String = sqlx::query_scalar(
        "select voided_reason from relay_provisional_grant \
         where workspace_id = $1 and device_hash = $2",
    )
    .bind(WORKSPACE)
    .bind(&device)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(reason, "revoked");

    // And redeeming again with the same device does not buy a fresh grant, so a
    // revoked joiner cannot walk back through the door the revocation shut.
    assert!(matches!(
        reserve::reserve(
            pool,
            &record.token,
            &code.grouped(),
            &nonce(2),
            &device,
            &[0x92; 32],
            NOW
        )
        .await
        .unwrap(),
        Verdict::Unavailable
    ));
    scratch.drop_database().await;
}

/// Revocation ends the parked-join extension too, and leaves no live reservation
/// behind. The extension is what made a revoked in-flight join worth waiting for: it
/// widens a ten minute seat to the invite's whole expiry. WEALD-345.
#[tokio::test]
async fn revocation_leaves_no_live_reservation_and_no_extendable_one() {
    let (scratch, _blobs, state) = prepared("revoke_extend").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(44);
    let record = ordinary(0x2d, code);
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();
    let device = vec![0x97; 32];

    reserve::reserve(
        pool,
        &record.token,
        &code.grouped(),
        &nonce(1),
        &device,
        &[0x98; 32],
        NOW,
    )
    .await
    .unwrap();
    assert!(store::revoke(pool, &record.token).await.unwrap());

    // Zero live reservations for the token, because terminate releases them in its
    // own transaction rather than trusting a cascade that never fires on an update.
    let live: i64 = sqlx::query(
        "select count(*) as n from relay_invite_reservation \
         where token = $1 and released_at is null",
    )
    .bind(&record.token)
    .fetch_one(pool)
    .await
    .unwrap()
    .get("n");
    assert_eq!(live, 0);

    // And the extension is refused, so a parked joiner cannot widen a dead seat.
    assert!(!reserve::extend(pool, &record.token, &nonce(1))
        .await
        .unwrap());
    scratch.drop_database().await;
}

/// The negative half: an uninterrupted join still completes, so the checks above
/// refuse only what they are aimed at.
#[tokio::test]
async fn an_uninterrupted_join_still_commits_and_spends_its_seat() {
    let (scratch, _blobs, state) = prepared("uninterrupted").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(42);
    let record = ordinary(0x2b, code);
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();
    let device = vec![0x93; 32];

    assert!(matches!(
        reserve::reserve(
            pool,
            &record.token,
            &code.grouped(),
            &nonce(1),
            &device,
            &[0x94; 32],
            NOW
        )
        .await
        .unwrap(),
        Verdict::Reserved { .. }
    ));
    assert!(
        reserve::scope_commit(pool, &record.token, &nonce(1), &device, &root(), NOW)
            .await
            .unwrap()
            .is_some()
    );
    assert!(!access_store::grant_is_voided(pool, WORKSPACE, &device)
        .await
        .unwrap());
    scratch.drop_database().await;
}

/// An invite that ran out of time cannot be committed against, even by a
/// reservation that was live when it was taken. The expiry used to be selected and
/// used only as a grant duration, never enforced. WEALD-286.
#[tokio::test]
async fn a_commit_after_the_invite_expires_is_refused() {
    let (scratch, _blobs, state) = prepared("commit_after_expiry").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(43);
    let record = ordinary(0x2c, code);
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();
    let device = vec![0x95; 32];

    reserve::reserve(
        pool,
        &record.token,
        &code.grouped(),
        &nonce(1),
        &device,
        &[0x96; 32],
        NOW,
    )
    .await
    .unwrap();

    let after = record.expires as i64 + 1;
    assert!(
        reserve::scope_commit(pool, &record.token, &nonce(1), &device, &root(), after)
            .await
            .unwrap()
            .is_none()
    );
    scratch.drop_database().await;
}

// MARK: Bundles

#[tokio::test]
async fn a_refresh_keeps_the_newest_three_and_the_relay_reads_none_of_them() {
    let (scratch, _blobs, state) = prepared("bundles").await;
    let pool = pool_of(&state);
    let record = ordinary(0x03, Code::from_bits(5));
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();

    for epoch in 2..=5u64 {
        assert!(store::refresh_bundle(
            pool,
            &record.token,
            &EncBundle {
                group: root(),
                epoch,
                ct: format!("sealed at {epoch}").into_bytes(),
            }
        )
        .await
        .unwrap());
    }

    let held = store::bundles_for(pool, &record.token, &root())
        .await
        .unwrap();
    // Three refreshed candidates plus the pinned one the issuer sealed into the
    // signed record, which pruning never evicts. WEALD-338.
    assert_eq!(held.len(), store::RETAINED_BUNDLES as usize + 1);
    // Newest first, and the ciphertext is exactly what was uploaded: the relay
    // stored it and served it and has no key that could open it.
    assert_eq!(held[0].epoch, 5);
    assert_eq!(held[0].ct, b"sealed at 5");
    assert_eq!(held[2].epoch, 3);
    assert_eq!(held[3].epoch, 1);
    assert_eq!(held[3].ct, b"sealed group info one");

    // A bogus high-epoch upload cannot mask the last valid one, because three
    // candidates are kept and the invitee accepts only an MLS-valid GroupInfo.
    assert!(store::refresh_bundle(
        pool,
        &record.token,
        &EncBundle {
            group: root(),
            epoch: 9_999,
            ct: b"garbage".to_vec(),
        }
    )
    .await
    .unwrap());
    let after = store::bundles_for(pool, &record.token, &root())
        .await
        .unwrap();
    assert!(after.iter().any(|bundle| bundle.epoch == 5));

    // A group the invite does not scope, an empty seal and an oversized seal are all
    // refused, and none of them is an error the uploader can act on differently.
    for refused in [
        EncBundle {
            group: vec![0x44; 32],
            epoch: 1,
            ct: b"x".to_vec(),
        },
        EncBundle {
            group: root(),
            epoch: 1,
            ct: Vec::new(),
        },
        EncBundle {
            group: root(),
            epoch: 1,
            ct: vec![0u8; invite::MAX_BUNDLE_BYTES + 1],
        },
    ] {
        assert!(!store::refresh_bundle(pool, &record.token, &refused)
            .await
            .unwrap());
    }
    // And a refresh against a revoked invite is refused too.
    assert!(store::revoke(pool, &record.token).await.unwrap());
    assert!(!store::refresh_bundle(
        pool,
        &record.token,
        &EncBundle {
            group: root(),
            epoch: 6,
            ct: b"late".to_vec(),
        }
    )
    .await
    .unwrap());
    scratch.drop_database().await;
}

/// The negative proof for WEALD-338. `refresh_bundle` cannot verify group membership
/// or ciphertext validity, so an admitted workspace principal can upload as many
/// bogus candidates as it likes. Before the pin, more than `RETAINED_BUNDLES` of them
/// at distinct epochs evicted the candidate the issuer signed, every joiner rejected
/// every retained candidate as MLS-invalid, and an insider parked every outstanding
/// invite without revoking one.
#[tokio::test]
async fn a_flood_of_bogus_updates_cannot_evict_the_candidate_the_issuer_sealed() {
    let (scratch, _blobs, state) = prepared("bundle_flood").await;
    let pool = pool_of(&state);
    let record = ordinary(0x3e, Code::from_bits(77));
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();
    let issued = record.bundles[0].clone();

    // Far more than the retention bound, at distinct epochs, so every unpinned row
    // is evicted several times over.
    for epoch in 2..=40u64 {
        assert!(store::refresh_bundle(
            pool,
            &record.token,
            &EncBundle {
                group: root(),
                epoch,
                ct: b"bogus".to_vec(),
            }
        )
        .await
        .unwrap());
    }

    // The attacker also collides with the issued row's own epoch, which would evict
    // the valid candidate by overwrite rather than by pruning.
    assert!(store::refresh_bundle(
        pool,
        &record.token,
        &EncBundle {
            group: root(),
            epoch: issued.epoch,
            ct: b"bogus overwrite".to_vec(),
        }
    )
    .await
    .unwrap());

    let held = store::bundles_for(pool, &record.token, &root())
        .await
        .unwrap();
    // The valid candidate is still retrievable, byte for byte, and the table is
    // still bounded: the unpinned rows plus exactly one pinned row.
    let pinned = held
        .iter()
        .find(|bundle| bundle.epoch == issued.epoch)
        .expect("the issued candidate survives a flood");
    assert_eq!(pinned.ct, issued.ct);
    assert_eq!(held.len(), store::RETAINED_BUNDLES as usize + 1);
    scratch.drop_database().await;
}

// MARK: Seats

#[tokio::test]
async fn a_reservation_is_idempotent_for_its_nonce_and_returns_its_seat_on_expiry() {
    let (scratch, _blobs, state) = prepared("seats").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(6);
    let record = issue(
        &key(1),
        token(0x04),
        code,
        2,
        NOW as u64 + invite::DEFAULT_EXPIRY_MS,
    );
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();
    let device = vec![0x91; 32];
    let source = vec![0x92; 32];

    let first = reserve::reserve(
        pool,
        &record.token,
        &code.grouped(),
        &nonce(1),
        &device,
        &source,
        NOW,
    )
    .await
    .unwrap();
    let again = reserve::reserve(
        pool,
        &record.token,
        &code.grouped(),
        &nonce(1),
        &device,
        &source,
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(first, again, "a retry took a second seat");
    assert_eq!(
        first,
        Verdict::Reserved {
            expires_at_ms: NOW + reserve::RESERVATION_SECONDS * 1000
        }
    );
    assert_eq!(
        store::fetch(pool, &record.token)
            .await
            .unwrap()
            .unwrap()
            .remaining,
        1
    );

    // Abandoned setup: the seat comes back after ten minutes rather than burning one
    // of two invitations permanently.
    let later = NOW + (reserve::RESERVATION_SECONDS + 1) * 1000;
    assert_eq!(reserve::release_expired(pool, later).await.unwrap(), 1);
    assert_eq!(
        store::fetch(pool, &record.token)
            .await
            .unwrap()
            .unwrap()
            .remaining,
        2
    );
    // Idempotent: a second sweep releases nothing.
    assert_eq!(reserve::release_expired(pool, later).await.unwrap(), 0);
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_reservation_never_outlives_its_invite() {
    let (scratch, _blobs, state) = prepared("shortlife").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(7);
    // An invite with two minutes to live: the ten-minute window is clamped to it.
    let record = issue(&key(1), token(0x05), code, 1, NOW as u64 + 120_000);
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();
    let verdict = reserve::reserve(
        pool,
        &record.token,
        &code.grouped(),
        &nonce(1),
        &[0xa1; 32],
        &[0xa2; 32],
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(
        verdict,
        Verdict::Reserved {
            expires_at_ms: NOW + 120_000
        }
    );
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_parked_join_extends_once_and_never_past_the_invite() {
    let (scratch, _blobs, state) = prepared("parked").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(8);
    let record = ordinary(0x06, code);
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();
    reserve::reserve(
        pool,
        &record.token,
        &code.grouped(),
        &nonce(1),
        &[0xb1; 32],
        &[0xb2; 32],
        NOW,
    )
    .await
    .unwrap();

    assert!(reserve::extend(pool, &record.token, &nonce(1))
        .await
        .unwrap());
    // Once, and only once.
    assert!(!reserve::extend(pool, &record.token, &nonce(1))
        .await
        .unwrap());
    // And not for a nonce that never reserved anything.
    assert!(!reserve::extend(pool, &record.token, &nonce(2))
        .await
        .unwrap());

    // The seat now survives the ten-minute window, which is the whole point: the
    // parked-join path must not expire the seat it is waiting on.
    let later = NOW + (reserve::RESERVATION_SECONDS + 1) * 1000;
    assert_eq!(reserve::release_expired(pool, later).await.unwrap(), 0);
    let held: f64 = sqlx::query(
        "select (extract(epoch from expires_at) * 1000)::double precision as ms \
         from relay_invite_reservation where token = $1",
    )
    .bind(&record.token)
    .fetch_one(pool)
    .await
    .unwrap()
    .get("ms");
    assert_eq!(held as u64, record.expires);

    // And the credential the seat is useless without. `reserve` grants the device a
    // provisional grant expiring with the ten minute reservation, and admission reads
    // that row's own expiry rather than the reservation's, so an extension that moved
    // only the seat left the joiner refused at AUTH while holding a live seat: exactly
    // the case the extension exists to prevent, one layer down. WEALD-475.
    let credential: f64 = sqlx::query(
        "select (extract(epoch from expires_at) * 1000)::double precision as ms \
         from relay_provisional_grant where workspace_id = $1 and device_hash = $2",
    )
    .bind(WORKSPACE)
    // `0xb1u8`, not `0xb1`: an untyped integer literal makes this an `[i32; 32]`
    // and Postgres refuses `bytea = integer[]` at parse time.
    .bind(&[0xb1u8; 32][..])
    .fetch_one(pool)
    .await
    .unwrap()
    .get("ms");
    assert_eq!(
        credential as u64, record.expires,
        "the grant expired with the seat"
    );
    scratch.drop_database().await;
}

// MARK: The external commit

#[tokio::test]
async fn a_scope_commit_is_bound_to_its_reservation_and_consumes_the_seat_once() {
    let (scratch, _blobs, state) = prepared("commit").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(12);
    let record = ordinary(0x07, code);
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();
    let device = vec![0xc1; 32];
    reserve::reserve(
        pool,
        &record.token,
        &code.grouped(),
        &nonce(1),
        &device,
        &[0xc2; 32],
        NOW,
    )
    .await
    .unwrap();

    // A device that is not the one the seat was held for cannot use it.
    assert!(
        reserve::scope_commit(pool, &record.token, &nonce(1), &[0xcc; 32], &root(), NOW)
            .await
            .unwrap()
            .is_none()
    );
    // Nor can a group the invite does not scope.
    assert!(
        reserve::scope_commit(pool, &record.token, &nonce(1), &device, &[0x44; 32], NOW)
            .await
            .unwrap()
            .is_none()
    );
    // Nor a nonce that reserved nothing.
    assert!(
        reserve::scope_commit(pool, &record.token, &nonce(9), &device, &root(), NOW)
            .await
            .unwrap()
            .is_none()
    );

    let receipt = reserve::scope_commit(pool, &record.token, &nonce(1), &device, &root(), NOW)
        .await
        .unwrap()
        .expect("the reserved scope commits");
    assert_eq!(receipt.len(), 32);
    // A duplicate retry returns the original receipt rather than a second one.
    let retry = reserve::scope_commit(pool, &record.token, &nonce(1), &device, &root(), NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retry, receipt);

    // The final required scope commit consumed the seat, and the grant was promoted
    // to the invite's own expiry rather than reissued.
    let consumed: bool = sqlx::query(
        "select consumed_at is not null as done from relay_invite_reservation \
         where token = $1 and join_nonce = $2",
    )
    .bind(&record.token)
    .bind(nonce(1))
    .fetch_one(pool)
    .await
    .unwrap()
    .get("done");
    assert!(consumed);
    let grant_expiry: f64 = sqlx::query(
        "select (extract(epoch from expires_at) * 1000)::double precision as ms from relay_provisional_grant \
         where workspace_id = $1 and device_hash = $2",
    )
    .bind(WORKSPACE)
    .bind(&device)
    .fetch_one(pool)
    .await
    .unwrap()
    .get("ms");
    assert_eq!(grant_expiry as u64, record.expires);

    // A consumed reservation is not released by the sweep, and the seat it spent
    // does not come back.
    let later = NOW + (reserve::RESERVATION_SECONDS + 1) * 1000;
    assert_eq!(reserve::release_expired(pool, later).await.unwrap(), 0);
    assert_eq!(
        store::fetch(pool, &record.token)
            .await
            .unwrap()
            .unwrap()
            .remaining,
        0
    );
    scratch.drop_database().await;
}

#[tokio::test]
async fn an_expired_reservation_cannot_commit_and_a_consumed_one_still_can_retry() {
    let (scratch, _blobs, state) = prepared("commit_expiry").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(13);
    let record = ordinary(0x08, code);
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();
    let device = vec![0xd1; 32];
    reserve::reserve(
        pool,
        &record.token,
        &code.grouped(),
        &nonce(1),
        &device,
        &[0xd2; 32],
        NOW,
    )
    .await
    .unwrap();

    let expired = NOW + (reserve::RESERVATION_SECONDS + 1) * 1000;
    assert!(
        reserve::scope_commit(pool, &record.token, &nonce(1), &device, &root(), expired)
            .await
            .unwrap()
            .is_none()
    );

    // Commit inside the window, then retry long after it: a consumed reservation
    // answers a retry, because the seat is already spent and the client that lost
    // the receipt has nothing left to spend.
    reserve::scope_commit(pool, &record.token, &nonce(1), &device, &root(), NOW)
        .await
        .unwrap()
        .unwrap();
    assert!(
        reserve::scope_commit(pool, &record.token, &nonce(1), &device, &root(), expired)
            .await
            .unwrap()
            .is_some()
    );
    // Extending a consumed reservation does nothing.
    assert!(!reserve::extend(pool, &record.token, &nonce(1))
        .await
        .unwrap());
    scratch.drop_database().await;
}

#[tokio::test]
async fn two_scopes_take_two_commits_before_the_seat_is_spent() {
    let (scratch, _blobs, state) = prepared("two_scopes").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(14);
    let second = vec![0x22; 32];
    let issuer = key(1);
    let mut record = ordinary(0x09, code);
    record.scopes = vec![root(), second.clone()];
    record.bundles = vec![
        EncBundle {
            group: root(),
            epoch: 1,
            ct: b"root".to_vec(),
        },
        EncBundle {
            group: second.clone(),
            epoch: 1,
            ct: b"channel".to_vec(),
        },
    ];
    record.sig = issuer.sign(&record.digest_input()).to_bytes().to_vec();
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();

    let device = vec![0xe1; 32];
    reserve::reserve(
        pool,
        &record.token,
        &code.grouped(),
        &nonce(1),
        &device,
        &[0xe2; 32],
        NOW,
    )
    .await
    .unwrap();
    reserve::scope_commit(pool, &record.token, &nonce(1), &device, &root(), NOW)
        .await
        .unwrap()
        .unwrap();
    let half: bool = sqlx::query(
        "select consumed_at is not null as done from relay_invite_reservation \
         where token = $1 and join_nonce = $2",
    )
    .bind(&record.token)
    .bind(nonce(1))
    .fetch_one(pool)
    .await
    .unwrap()
    .get("done");
    assert!(!half, "the seat was spent before every scope had committed");

    reserve::scope_commit(pool, &record.token, &nonce(1), &device, &second, NOW)
        .await
        .unwrap()
        .unwrap();
    let done: bool = sqlx::query(
        "select consumed_at is not null as done from relay_invite_reservation \
         where token = $1 and join_nonce = $2",
    )
    .bind(&record.token)
    .bind(nonce(1))
    .fetch_one(pool)
    .await
    .unwrap()
    .get("done");
    assert!(done);
    scratch.drop_database().await;
}

#[tokio::test]
async fn the_store_error_says_which_half_failed() {
    // A client that published something wrong and a relay that could not look are
    // different answers, and a caller that conflated them would tell a correct client
    // to stop retrying.
    let refused = StoreError::Refused(InviteError::Expired);
    assert!(refused.to_string().contains("expired"));
    let database = StoreError::Database("connection reset".to_string());
    assert!(database.to_string().starts_with("invite store:"));
    let coded = StoreError::Code(invite::code::CodeError::WrongLength(3));
    assert!(coded.to_string().contains("invite code:"));
    assert_eq!(State::from_label("live"), State::Live);
    assert_eq!(State::from_label("spent"), State::Spent);
    assert_eq!(State::from_label("revoked"), State::Revoked);
    assert_eq!(State::from_label("nonsense"), State::Revoked);
    for state in [State::Live, State::Spent, State::Revoked] {
        assert!(!state.label().is_empty());
    }
}

#[tokio::test]
async fn a_synchronized_burst_of_wrong_codes_spends_the_budget_once() {
    // WEALD-336. The guess budget used to be read before Argon2id and written after
    // it, so every connection in a burst read the same count below the ceiling, ran
    // the verifier, and only then incremented. Sixty-four sockets from one address
    // therefore bought sixty-four Argon2id calls against a five-guess budget, which
    // is the amplification the budget exists to deny.
    //
    // The proof is the charge count, because the charge is now the gate: a slot is
    // taken before the code is parsed and a verification cannot happen without one.
    // Before the fix this row reads sixty-four.
    let (scratch, _blobs, state) = prepared("burst").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(0x5150);
    let record = issue(
        &key(1),
        token(0xe7),
        code,
        10,
        NOW as u64 + invite::DEFAULT_EXPIRY_MS,
    );
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();

    const BURST: usize = 64;
    let wrong = Code::from_bits(0x5151).grouped();
    let source = vec![0x81; 32];
    let gate = Arc::new(tokio::sync::Barrier::new(BURST));
    let mut attempts = Vec::with_capacity(BURST);
    for index in 0..BURST {
        let pool = pool.clone();
        let token = record.token.clone();
        let wrong = wrong.clone();
        let source = source.clone();
        let gate = Arc::clone(&gate);
        attempts.push(tokio::spawn(async move {
            // Every task lands on the pre-check together, which is exactly the
            // window a check-then-charge budget cannot see.
            gate.wait().await;
            reserve::reserve(
                &pool,
                &token,
                &wrong,
                &nonce(index as u8),
                &[0x82; 32],
                &source,
                NOW,
            )
            .await
            .unwrap()
        }));
    }
    for attempt in attempts {
        assert_eq!(attempt.await.unwrap(), Verdict::Unavailable);
    }

    let charged: i32 =
        sqlx::query_scalar("select failures from relay_invite_attempt where token = $1")
            .bind(&record.token)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        charged,
        wealdrelay::invite::code::MAX_FAILURES,
        "a synchronized burst reached the verifier more than the budget allows"
    );
    // And the pair is cooled down afterwards, from the burst alone.
    assert_eq!(
        reserve::reserve(
            pool,
            &record.token,
            &code.grouped(),
            &nonce(0xff),
            &[0x82; 32],
            &source,
            NOW
        )
        .await
        .unwrap(),
        Verdict::Unavailable
    );
    // Nothing was burnt: the budget is a guess budget, not a seat.
    let stored = store::fetch(pool, &record.token).await.unwrap().unwrap();
    assert_eq!(stored.remaining, 10);
    assert_eq!(stored.state, State::Live);
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_correct_code_gives_its_guess_slot_back() {
    // The charge happens before the code is checked, so an honest joiner passes
    // through the guess budget. Five colleagues behind one office address must not
    // cool that address down by joining successfully, so the slot is refunded once
    // the 60-bit code has been shown. WEALD-336.
    let (scratch, _blobs, state) = prepared("refund").await;
    let pool = pool_of(&state);
    let code = Code::from_bits(0x2b2b);
    let record = issue(
        &key(1),
        token(0xe8),
        code,
        10,
        NOW as u64 + invite::DEFAULT_EXPIRY_MS,
    );
    store::create(pool, WORKSPACE, &record, NOW).await.unwrap();

    let source = vec![0x91; 32];
    for joiner in 0..6u8 {
        assert!(
            matches!(
                reserve::reserve(
                    pool,
                    &record.token,
                    &code.grouped(),
                    &nonce(joiner),
                    &[0x90 + joiner; 32],
                    &source,
                    NOW,
                )
                .await
                .unwrap(),
                Verdict::Reserved { .. }
            ),
            "joiner {joiner} was refused by a budget it never spent"
        );
    }
    let charged: i32 =
        sqlx::query_scalar("select failures from relay_invite_attempt where token = $1")
            .bind(&record.token)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(charged, 0, "a correct code kept its guess slot");
    // The issuer is told about guesses, and six correct joins are not guesses.
    let volume = reserve::attempt_volume(pool, &record.token).await.unwrap();
    assert_eq!(volume.failures, 0);
    assert_eq!(volume.tuples, 0);
    scratch.drop_database().await;
}
