// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The retention control chain, the manifest chain, and the threshold that is the
//! only thing that ever authorizes a deletion.
//!
//! Tier 3 and tier 4. `specs/backend/relay/media.md` divides authority in two and
//! this file is written around that division, because merging the two halves is
//! the single change that would turn a departing insider into a data-loss event:
//!
//! - The epoch-derived **verifier** proves a current group member produced a
//!   complete retention view. "A manifest is evidence, not deletion authority."
//! - A **threshold-authorized** `RetentionPolicy` or `RetentionDestruction`,
//!   checked against the workspace's access-set authorizers, is what permits
//!   deletion at all.
//!
//! The successor race gets the most space here, and it is the negative proof the
//! gate names: a second, differently signed control for the same `(group, epoch)`
//! "is not rejected and forgotten", it freezes the group, and "only a client can
//! clear a freeze". The removed member who forges a branch on their way out gets a
//! stalled cleanup job and a visible alarm, never a deletion.

mod support;

use std::sync::Arc;

use sqlx::PgPool;
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::media::retention::{
    self, Authorization, ControlOutcome, ManifestOutcome, StoreError,
};
use wealdrelay::media::store;

use support::{
    blob_hash, config_for, device_from, make_group_in, sign_all, signed_control,
    signed_destruction, signed_manifest, signed_policy, verifier_key, Running, Scratch,
};

const DAY: u64 = 24 * 60 * 60;

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

/// A workspace whose access set names `authorizers`, and one group inside it.
async fn workspace_with(
    state: &Arc<RelayState>,
    workspace: &str,
    byte: u8,
    authorizers: &[ed25519_dalek::SigningKey],
) -> Vec<u8> {
    let devices: Vec<ed25519_dalek::SigningKey> = authorizers.to_vec();
    make_group_in(state, workspace, byte, &devices, authorizers).await
}

// MARK: The control chain

#[tokio::test]
async fn the_genesis_control_signs_for_itself_and_every_successor_signs_under_the_last() {
    let (scratch, _blobs, state) = prepared("retention_chain").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-chain", 0x61, &[device_from(0x71)]).await;

    // Epoch zero: "emitted by the group creator with the first epoch's verifier",
    // so its authority is the verifier signing for itself. That is exactly the
    // possession proof a founder has and nobody else does.
    let epoch0 = verifier_key(0x21);
    let genesis = signed_control(&group, 0, &epoch0, None, &epoch0);
    assert_eq!(
        retention::apply_control(pool, &genesis).await.unwrap(),
        ControlOutcome::Accepted
    );

    // The identical record again. A client that retried after a dropped socket
    // must not be told its group is now frozen.
    assert_eq!(
        retention::apply_control(pool, &genesis).await.unwrap(),
        ControlOutcome::Accepted
    );

    // Epoch one, signed by epoch zero's verifier and naming its digest.
    let epoch1 = verifier_key(0x22);
    let rotated = signed_control(&group, 1, &epoch1, Some(genesis.digest()), &epoch0);
    assert_eq!(
        retention::apply_control(pool, &rotated).await.unwrap(),
        ControlOutcome::Accepted
    );
    assert!(!retention::is_frozen(pool, &group).await.unwrap());

    let note: String = sqlx::query_scalar(
        "select signer_note from relay_retention_control where group_id = $1 and epoch = 1",
    )
    .bind(&group)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(note, "rotation");

    scratch.drop_database().await;
}

#[tokio::test]
async fn every_way_a_control_can_be_wrong_is_refused_with_its_reason() {
    let (scratch, _blobs, state) = prepared("retention_control_bad").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-badctl", 0x62, &[device_from(0x71)]).await;
    let epoch0 = verifier_key(0x21);

    // A genesis control naming a predecessor is claiming to follow something that
    // by definition does not exist.
    let false_genesis = signed_control(&group, 0, &epoch0, Some(blob_hash(9)), &epoch0);
    assert_eq!(
        retention::apply_control(pool, &false_genesis)
            .await
            .unwrap(),
        ControlOutcome::Invalid("genesis control names a predecessor")
    );

    // A genesis control whose signature is not the verifier's own.
    let impostor = signed_control(&group, 0, &epoch0, None, &verifier_key(0x99));
    assert_eq!(
        retention::apply_control(pool, &impostor).await.unwrap(),
        ControlOutcome::Invalid("signature does not verify")
    );

    // Epoch two before epoch one exists: the chain has no anchor to check against.
    let orphan = signed_control(&group, 2, &verifier_key(0x23), Some(blob_hash(9)), &epoch0);
    assert_eq!(
        retention::apply_control(pool, &orphan).await.unwrap(),
        ControlOutcome::Invalid("no control for the prior epoch")
    );

    let genesis = signed_control(&group, 0, &epoch0, None, &epoch0);
    assert_eq!(
        retention::apply_control(pool, &genesis).await.unwrap(),
        ControlOutcome::Accepted
    );

    // A successor that names no predecessor at all.
    let unanchored = signed_control(&group, 1, &verifier_key(0x22), None, &epoch0);
    assert_eq!(
        retention::apply_control(pool, &unanchored).await.unwrap(),
        ControlOutcome::Invalid("non-genesis control names no predecessor")
    );

    // A successor naming the wrong predecessor. This is the one a forger with a
    // captured record reaches for, and the digest covers the whole prior record,
    // signature included, so there is nothing to substitute.
    let mispointed = signed_control(&group, 1, &verifier_key(0x22), Some(blob_hash(7)), &epoch0);
    assert_eq!(
        retention::apply_control(pool, &mispointed).await.unwrap(),
        ControlOutcome::Invalid("prev_control_hash does not match the prior epoch's control")
    );

    // A successor with the right shape, signed by a key that is not the prior
    // epoch's verifier.
    let unsigned = signed_control(
        &group,
        1,
        &verifier_key(0x22),
        Some(genesis.digest()),
        &verifier_key(0x99),
    );
    assert_eq!(
        retention::apply_control(pool, &unsigned).await.unwrap(),
        ControlOutcome::Invalid("signature does not verify")
    );

    // None of the refusals wrote a row, so the epoch is still open to the
    // legitimate successor.
    let real = signed_control(
        &group,
        1,
        &verifier_key(0x22),
        Some(genesis.digest()),
        &epoch0,
    );
    assert_eq!(
        retention::apply_control(pool, &real).await.unwrap(),
        ControlOutcome::Accepted
    );
    assert!(!retention::is_frozen(pool, &group).await.unwrap());

    scratch.drop_database().await;
}

/// The negative proof `media.md`'s successor-race section is written for: the
/// member being removed by a commit held the prior epoch's verifier too, and can
/// sign a successor naming a verifier they invented. The relay cannot tell an
/// invented successor from a derived one and is not asked to. It freezes.
#[tokio::test]
async fn a_second_differently_signed_control_freezes_the_group_rather_than_governing_it() {
    let (scratch, _blobs, state) = prepared("retention_freeze").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-freeze", 0x63, &[device_from(0x71)]).await;
    let epoch0 = verifier_key(0x21);
    let genesis = signed_control(&group, 0, &epoch0, None, &epoch0);
    retention::apply_control(pool, &genesis).await.unwrap();

    // The honest successor lands first, which is what "honest members publish
    // theirs in the same batch as the commit" buys under normal operation.
    let honest = verifier_key(0x22);
    let real = signed_control(&group, 1, &honest, Some(genesis.digest()), &epoch0);
    assert_eq!(
        retention::apply_control(pool, &real).await.unwrap(),
        ControlOutcome::Accepted
    );

    // The departing member's branch. Correctly signed by the prior verifier,
    // because they held it, and naming a verifier only they know.
    let forged = signed_control(
        &group,
        1,
        &verifier_key(0xee),
        Some(genesis.digest()),
        &epoch0,
    );
    assert_eq!(
        retention::apply_control(pool, &forged).await.unwrap(),
        ControlOutcome::ConflictFroze
    );
    assert!(retention::is_frozen(pool, &group).await.unwrap());

    // Resubmission is not conflict. A client that retries after a dropped socket
    // sends the identical record, and the relay has to answer "already accepted"
    // rather than freeze the group: freezing on a retry would make an ordinary
    // reconnect stop a workspace collecting media until somebody resolved it.
    assert_eq!(
        retention::apply_control(pool, &real).await.unwrap(),
        ControlOutcome::Accepted,
        "the identical record again is the same record"
    );

    // Stored as evidence, never as a winner: the settled row is untouched.
    let settled: Vec<u8> = sqlx::query_scalar(
        "select verifier from relay_retention_control where group_id = $1 and epoch = 1",
    )
    .bind(&group)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(settled, honest.verifying_key().to_bytes().to_vec());
    let conflicts: i64 = sqlx::query_scalar(
        "select count(*) from relay_retention_control_conflict where group_id = $1",
    )
    .bind(&group)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(conflicts, 1);

    // A second forgery finds the group already frozen. It is still evidence, and
    // the answer distinguishes the two so a report can say how many arrived.
    let again = signed_control(
        &group,
        1,
        &verifier_key(0xef),
        Some(genesis.digest()),
        &epoch0,
    );
    assert_eq!(
        retention::apply_control(pool, &again).await.unwrap(),
        ControlOutcome::ConflictAlreadyFrozen
    );
    let conflicts: i64 = sqlx::query_scalar(
        "select count(*) from relay_retention_control_conflict where group_id = $1",
    )
    .bind(&group)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(conflicts, 2);

    // "Only a client can clear a freeze." Members derive the correct verifier
    // from their own MLS state and publish a resolution; the relay applies it
    // without being able to evaluate it, which is the correct division.
    retention::clear_freeze(pool, &group).await.unwrap();
    assert!(!retention::is_frozen(pool, &group).await.unwrap());

    // A group the relay has never heard of is not frozen, and asking is not an
    // error: `/readyz` reports on groups it holds.
    assert!(!retention::is_frozen(pool, &blob_hash(0x00)).await.unwrap());

    scratch.drop_database().await;
}

// MARK: The manifest chain

#[tokio::test]
async fn a_manifest_advances_by_one_names_its_predecessor_and_claims_what_it_holds() {
    let (scratch, _blobs, state) = prepared("retention_manifest").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-manifest", 0x64, &[device_from(0x71)]).await;
    let epoch0 = verifier_key(0x21);
    retention::apply_control(pool, &signed_control(&group, 0, &epoch0, None, &epoch0))
        .await
        .unwrap();

    store::ensure_quota_row(pool, "ws-manifest", None)
        .await
        .unwrap();
    for seed in [0xa1u8, 0xa2] {
        store::reserve(
            pool,
            "ws-manifest",
            &group,
            &blob_hash(seed),
            100,
            false,
            900,
        )
        .await
        .unwrap();
    }

    assert!(retention::latest_manifest(pool, &group)
        .await
        .unwrap()
        .is_none());

    let first = signed_manifest(
        &group,
        0,
        1,
        None,
        vec![blob_hash(0xa1), blob_hash(0xa2)],
        &epoch0,
    );
    let digest = match retention::apply_manifest(pool, "ws-manifest", &first)
        .await
        .unwrap()
    {
        ManifestOutcome::Accepted { digest } => digest,
        other => panic!("expected an accepted manifest, got {other:?}"),
    };
    assert_eq!(digest, first.digest());

    // Accepting a manifest is what claims its blobs: bytes move from reserved to
    // stored at the relay's own receipt time and nowhere else.
    let usage = store::usage(pool, "ws-manifest").await.unwrap();
    assert_eq!(usage.stored_bytes, 200);
    assert_eq!(usage.reserved_bytes, 0);

    let latest = retention::latest_manifest(pool, &group)
        .await
        .unwrap()
        .expect("a manifest is on file");
    assert_eq!(latest.sequence, 1);
    assert_eq!(latest.digest, digest);
    assert_eq!(latest.blobs, vec![blob_hash(0xa1), blob_hash(0xa2)]);

    // The omission: a second manifest naming only one of them. This is the whole
    // deletion signal, and it is a signal rather than an instruction.
    let second = signed_manifest(
        &group,
        0,
        2,
        Some(digest.clone()),
        vec![blob_hash(0xa1)],
        &epoch0,
    );
    assert!(matches!(
        retention::apply_manifest(pool, "ws-manifest", &second)
            .await
            .unwrap(),
        ManifestOutcome::Accepted { .. }
    ));
    assert_eq!(
        retention::latest_manifest(pool, &group)
            .await
            .unwrap()
            .unwrap()
            .blobs,
        vec![blob_hash(0xa1)]
    );
    // Re-claiming an already claimed hash costs nothing extra.
    assert_eq!(
        store::usage(pool, "ws-manifest")
            .await
            .unwrap()
            .stored_bytes,
        200
    );

    scratch.drop_database().await;
}

/// "A manifest that fails verification is retained as evidence but never used for
/// deletion." Each refusal below writes a rejection row and leaves the chain where
/// it was, so a forged manifest cannot advance the sequence past a real one.
#[tokio::test]
async fn a_manifest_that_fails_verification_is_evidence_and_never_the_latest() {
    let (scratch, _blobs, state) = prepared("retention_manifest_bad").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-badman", 0x65, &[device_from(0x71)]).await;
    let epoch0 = verifier_key(0x21);

    // No control for the epoch at all: nothing to check a signature against.
    let orphan = signed_manifest(&group, 0, 1, None, vec![blob_hash(0xa1)], &epoch0);
    assert_eq!(
        retention::apply_manifest(pool, "ws-badman", &orphan)
            .await
            .unwrap(),
        ManifestOutcome::Invalid("no retention control for this epoch".to_string())
    );

    retention::apply_control(pool, &signed_control(&group, 0, &epoch0, None, &epoch0))
        .await
        .unwrap();

    // Signed by something other than the epoch's verifier.
    let forged = signed_manifest(
        &group,
        0,
        1,
        None,
        vec![blob_hash(0xa1)],
        &verifier_key(0xee),
    );
    assert_eq!(
        retention::apply_manifest(pool, "ws-badman", &forged)
            .await
            .unwrap(),
        ManifestOutcome::Invalid(
            "signature does not verify against the epoch verifier".to_string()
        )
    );

    // A first manifest whose sequence does not start at one.
    let skipped = signed_manifest(&group, 0, 4, None, vec![blob_hash(0xa1)], &epoch0);
    assert_eq!(
        retention::apply_manifest(pool, "ws-badman", &skipped)
            .await
            .unwrap(),
        ManifestOutcome::Invalid("sequence does not advance by exactly one".to_string())
    );

    // A first manifest naming a predecessor that cannot exist.
    let anchored = signed_manifest(
        &group,
        0,
        1,
        Some(blob_hash(3)),
        vec![blob_hash(0xa1)],
        &epoch0,
    );
    assert_eq!(
        retention::apply_manifest(pool, "ws-badman", &anchored)
            .await
            .unwrap(),
        ManifestOutcome::Invalid(
            "prev_manifest_hash does not match the latest manifest".to_string()
        )
    );

    store::ensure_quota_row(pool, "ws-badman", None)
        .await
        .unwrap();
    let real = signed_manifest(&group, 0, 1, None, vec![blob_hash(0xa1)], &epoch0);
    let digest = match retention::apply_manifest(pool, "ws-badman", &real)
        .await
        .unwrap()
    {
        ManifestOutcome::Accepted { digest } => digest,
        other => panic!("{other:?}"),
    };

    // A successor naming the wrong predecessor, now that there is one to name.
    let mispointed = signed_manifest(&group, 0, 2, Some(blob_hash(3)), vec![], &epoch0);
    assert_eq!(
        retention::apply_manifest(pool, "ws-badman", &mispointed)
            .await
            .unwrap(),
        ManifestOutcome::Invalid(
            "prev_manifest_hash does not match the latest manifest".to_string()
        )
    );
    // And one that repeats a sequence already used.
    let repeat = signed_manifest(&group, 0, 1, None, vec![], &epoch0);
    assert_eq!(
        retention::apply_manifest(pool, "ws-badman", &repeat)
            .await
            .unwrap(),
        ManifestOutcome::Invalid("sequence does not advance by exactly one".to_string())
    );

    // Every one of them is on file as evidence, and none of them is the latest.
    let rejected: i64 = sqlx::query_scalar(
        "select count(*) from relay_retention_manifest_rejected where group_id = $1",
    )
    .bind(&group)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(rejected, 6);
    let latest = retention::latest_manifest(pool, &group)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(latest.sequence, 1);
    assert_eq!(latest.digest, digest);

    scratch.drop_database().await;
}

// MARK: The threshold, which is the only thing that authorizes a deletion

#[tokio::test]
async fn two_authorizers_means_two_distinct_signatures_and_nothing_less() {
    let (scratch, _blobs, state) = prepared("retention_threshold").await;
    let pool = pool_of(&state);
    let ada = device_from(0x71);
    let bo = device_from(0x72);
    let stranger = device_from(0x7f);
    let group = workspace_with(&state, "ws-two", 0x66, &[ada.clone(), bo.clone()]).await;
    let now = 1_000_000u64;

    // Both authorizers. "One signer may propose; the second sees an explicit
    // summary of the affected retention rule or deletion before approving."
    let both = signed_policy(&group, 1, 30, now + 8 * DAY, &[ada.clone(), bo.clone()]);
    assert_eq!(
        retention::authorize(
            pool,
            "ws-two",
            &both.signing_bytes(),
            &both.signatures,
            both.not_before,
            now
        )
        .await
        .unwrap(),
        Authorization::Threshold
    );

    // One of them alone. A workspace with two authorizers has no solo path, and
    // the seven-day grace is not a substitute for the second signature.
    let alone = signed_policy(&group, 1, 30, now + 400 * DAY, std::slice::from_ref(&ada));
    assert_eq!(
        retention::authorize(
            pool,
            "ws-two",
            &alone.signing_bytes(),
            &alone.signatures,
            alone.not_before,
            now
        )
        .await
        .unwrap(),
        Authorization::Insufficient
    );

    // The same authorizer twice. Two signatures, one signer: still one.
    let mut doubled = alone.clone();
    doubled.signatures.push(doubled.signatures[0].clone());
    assert_eq!(
        retention::authorize(
            pool,
            "ws-two",
            &doubled.signing_bytes(),
            &doubled.signatures,
            doubled.not_before,
            now
        )
        .await
        .unwrap(),
        Authorization::Insufficient
    );

    // An authorizer and somebody who is not one.
    let outsider = signed_policy(
        &group,
        1,
        30,
        now + 8 * DAY,
        &[ada.clone(), stranger.clone()],
    );
    assert_eq!(
        retention::authorize(
            pool,
            "ws-two",
            &outsider.signing_bytes(),
            &outsider.signatures,
            outsider.not_before,
            now
        )
        .await
        .unwrap(),
        Authorization::Insufficient
    );

    // Two authorizers named, one of the two signatures a forgery. A signature
    // that does not verify is not a signature.
    let mut forged = both.clone();
    forged.signatures[1].sig = vec![0u8; 64];
    assert_eq!(
        retention::authorize(
            pool,
            "ws-two",
            &forged.signing_bytes(),
            &forged.signatures,
            forged.not_before,
            now
        )
        .await
        .unwrap(),
        Authorization::Insufficient
    );

    // And two real signatures over a different body do not authorize this one.
    let elsewhere = signed_policy(&group, 2, 60, now + 8 * DAY, &[ada, bo]);
    assert_eq!(
        retention::authorize(
            pool,
            "ws-two",
            &both.signing_bytes(),
            &elsewhere.signatures,
            both.not_before,
            now
        )
        .await
        .unwrap(),
        Authorization::Insufficient
    );

    scratch.drop_database().await;
}

/// "A genuinely single-authorizer workspace may use one signature, but every
/// destructive action has a seven-day `not_before`." The floor is measured from
/// the relay's own receipt of the record, never from what the record claims,
/// which is what stops a backdated `not_before` buying an earlier execution.
#[tokio::test]
async fn a_sole_authorizer_gets_seven_days_measured_by_the_relays_own_clock() {
    let (scratch, _blobs, state) = prepared("retention_sole").await;
    let pool = pool_of(&state);
    let ada = device_from(0x71);
    let group = workspace_with(&state, "ws-solo", 0x67, std::slice::from_ref(&ada)).await;
    let now = 1_000_000u64;

    let graced = signed_destruction(
        &group,
        "blob",
        &blob_hash(0xa1),
        now + 7 * DAY,
        std::slice::from_ref(&ada),
    );
    assert_eq!(
        retention::authorize(
            pool,
            "ws-solo",
            &graced.signing_bytes(),
            &graced.signatures,
            graced.not_before,
            now
        )
        .await
        .unwrap(),
        Authorization::SoleAuthorizerGraced
    );

    // One second inside the floor is inside it.
    let hasty = signed_destruction(
        &group,
        "blob",
        &blob_hash(0xa1),
        now + 7 * DAY - 1,
        std::slice::from_ref(&ada),
    );
    assert_eq!(
        retention::authorize(
            pool,
            "ws-solo",
            &hasty.signing_bytes(),
            &hasty.signatures,
            hasty.not_before,
            now
        )
        .await
        .unwrap(),
        Authorization::SoleAuthorizerTooSoon
    );

    // The backdate. The record claims a `not_before` seven days after a moment
    // long past, which would be due immediately if the relay believed it.
    let backdated = signed_destruction(&group, "blob", &blob_hash(0xa1), 7 * DAY, &[ada]);
    assert_eq!(
        retention::authorize(
            pool,
            "ws-solo",
            &backdated.signing_bytes(),
            &backdated.signatures,
            backdated.not_before,
            now
        )
        .await
        .unwrap(),
        Authorization::SoleAuthorizerTooSoon,
        "a client-supplied not_before must never be read as the relay's own time"
    );

    // A sole-authorizer workspace with no valid signature at all.
    let unsigned = signed_destruction(&group, "blob", &blob_hash(0xa1), now + 8 * DAY, &[]);
    assert_eq!(
        retention::authorize(
            pool,
            "ws-solo",
            &unsigned.signing_bytes(),
            &unsigned.signatures,
            unsigned.not_before,
            now
        )
        .await
        .unwrap(),
        Authorization::Insufficient
    );

    scratch.drop_database().await;
}

/// A workspace the relay cannot check a signer against authorizes nothing. Fails
/// closed: the answer to "who may destroy this" is never "anyone" because the
/// roster could not be read.
#[tokio::test]
async fn a_workspace_with_nobody_to_check_against_authorizes_nothing() {
    let (scratch, _blobs, state) = prepared("retention_noauth").await;
    let pool = pool_of(&state);
    let ada = device_from(0x71);
    let group = workspace_with(&state, "ws-none", 0x68, std::slice::from_ref(&ada)).await;
    let record = signed_destruction(&group, "blob", &blob_hash(0xa1), 9_000_000, &[ada]);

    // A workspace with no access set published at all.
    assert_eq!(
        retention::authorize(
            pool,
            "ws-never-seen",
            &record.signing_bytes(),
            &record.signatures,
            record.not_before,
            1
        )
        .await
        .unwrap(),
        Authorization::NoAuthorizers
    );

    // And a published set whose authorizer principals are gone from under it: a
    // half-restored dump, which is a real state a real database can be in and the
    // only one that reaches this arm, because `AccessSet::check_shape` refuses an
    // empty authorizer list on the way in.
    sqlx::query(
        "delete from relay_access_principal where workspace_id = $1 and role = 'authorizer'",
    )
    .bind("ws-none")
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(
        retention::authorize(
            pool,
            "ws-none",
            &record.signing_bytes(),
            &record.signatures,
            record.not_before,
            1
        )
        .await
        .unwrap(),
        Authorization::NoAuthorizers
    );

    scratch.drop_database().await;
}

// MARK: Storing what was authorized

#[tokio::test]
async fn a_policy_is_stored_by_version_and_the_latest_uncancelled_one_governs() {
    let (scratch, _blobs, state) = prepared("retention_policy_rows").await;
    let pool = pool_of(&state);
    let ada = device_from(0x71);
    let group = workspace_with(&state, "ws-pol", 0x69, std::slice::from_ref(&ada)).await;

    assert!(retention::active_policy(pool, &group)
        .await
        .unwrap()
        .is_none());

    let first = signed_policy(&group, 1, 30, 1_000, std::slice::from_ref(&ada));
    retention::insert_policy(pool, &first, "[]").await.unwrap();
    let active = retention::active_policy(pool, &group)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.version, 1);
    assert_eq!(active.media_after_days, 30);
    assert_eq!(active.not_before_secs, 1_000);

    let second = signed_policy(&group, 2, 90, 2_000, std::slice::from_ref(&ada));
    retention::insert_policy(pool, &second, "[]").await.unwrap();
    let active = retention::active_policy(pool, &group)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.version, 2);
    assert_eq!(active.media_after_days, 90);

    // A cancelled policy stops governing. `media.md` makes a cancellation
    // possible until execution, and the read has to honour it.
    sqlx::query("update relay_retention_policy set cancelled_at = now() where group_id = $1 and version = 2")
        .bind(&group)
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(
        retention::active_policy(pool, &group)
            .await
            .unwrap()
            .unwrap()
            .version,
        1
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_destruction_is_idempotent_on_group_kind_and_target() {
    let (scratch, _blobs, state) = prepared("retention_destruction_rows").await;
    let pool = pool_of(&state);
    let ada = device_from(0x71);
    let group = workspace_with(&state, "ws-des", 0x6a, std::slice::from_ref(&ada)).await;
    let target = blob_hash(0xa1);

    assert!(retention::active_destruction(pool, &group, "blob", &target)
        .await
        .unwrap()
        .is_none());

    let record = signed_destruction(&group, "blob", &target, 5_000, std::slice::from_ref(&ada));
    assert!(retention::insert_destruction(pool, &record, "[]")
        .await
        .unwrap());
    // "It is idempotent on (group, kind, target_digest)": a client retrying its
    // own request must not be told the second attempt failed.
    assert!(!retention::insert_destruction(pool, &record, "[]")
        .await
        .unwrap());

    let active = retention::active_destruction(pool, &group, "blob", &target)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.not_before_secs, 5_000);

    // A destruction issued under a policy carries that policy's version, which is
    // how an audit tells "the admin's retention rule reached this object" apart
    // from "somebody deleted this object by hand" (`media.md`: a one-off
    // destruction is required for a deletion outside policy).
    let under_policy_target = blob_hash(0xa2);
    let mut under_policy = signed_destruction(
        &group,
        "blob",
        &under_policy_target,
        7_000,
        std::slice::from_ref(&ada),
    );
    under_policy.policy_version = Some(3);
    under_policy.signatures = sign_all(&under_policy.signing_bytes(), std::slice::from_ref(&ada));
    assert!(retention::insert_destruction(pool, &under_policy, "[]")
        .await
        .unwrap());
    let stored: Option<i64> = sqlx::query_scalar(
        "select policy_version from relay_retention_destruction          where group_id = $1 and kind = 'blob' and target_digest = $2",
    )
    .bind(&group)
    .bind(&under_policy_target)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(stored, Some(3), "the policy version reaches the row");

    // A different kind over the same digest is a different record.
    let other = signed_destruction(&group, "text", &target, 6_000, &[ada]);
    assert!(retention::insert_destruction(pool, &other, "[]")
        .await
        .unwrap());
    assert_eq!(
        retention::active_destruction(pool, &group, "text", &target)
            .await
            .unwrap()
            .unwrap()
            .not_before_secs,
        6_000
    );

    // "A cancellation is another threshold-authorized clear record and is
    // possible until not_before": once cancelled, it stops being active.
    sqlx::query("update relay_retention_destruction set cancelled_at = now() where group_id = $1 and kind = 'blob'")
        .bind(&group)
        .execute(pool)
        .await
        .unwrap();
    assert!(retention::active_destruction(pool, &group, "blob", &target)
        .await
        .unwrap()
        .is_none());

    scratch.drop_database().await;
}

#[test]
fn a_retention_store_failure_names_the_store_it_came_from() {
    let error = StoreError::Database("pool closed".to_string());
    assert_eq!(error.to_string(), "retention store: pool closed");
    assert!(format!("{error:?}").contains("Database"));
}

/// A manifest whose claims cannot be written is an error, never a silent
/// acceptance.
///
/// Accepting a manifest is what moves bytes from reserved to stored, and it is
/// also what tells the collector a hash is claimed. A manifest recorded as
/// accepted whose claims never landed would leave the relay believing a blob is
/// unreferenced while every member's client believes it is safe, which is the
/// exact state `media.md`'s grace period exists to make impossible.
#[tokio::test]
async fn a_manifest_whose_claims_cannot_be_written_is_refused() {
    let (scratch, _blobs, state) = prepared("retention_claim_refused").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-claim", 0x6b, &[device_from(0x71)]).await;
    let epoch0 = verifier_key(0x21);
    retention::apply_control(pool, &signed_control(&group, 0, &epoch0, None, &epoch0))
        .await
        .unwrap();
    store::ensure_quota_row(pool, "ws-claim", None)
        .await
        .unwrap();
    store::reserve(pool, "ws-claim", &group, &blob_hash(0xa1), 10, false, 900)
        .await
        .unwrap();

    // A real refusal from a real Postgres, on the table the claim writes.
    sqlx::query(
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected: this write cannot land'; end $$",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "create trigger weald_injected_claim before update on relay_blob_reservation \
         for each statement execute function weald_injected_refusal()",
    )
    .execute(pool)
    .await
    .unwrap();

    let manifest = signed_manifest(&group, 0, 1, None, vec![blob_hash(0xa1)], &epoch0);
    assert!(
        retention::apply_manifest(pool, "ws-claim", &manifest)
            .await
            .is_err(),
        "a claim that could not be written must not read as an accepted manifest"
    );

    sqlx::query("drop trigger weald_injected_claim on relay_blob_reservation")
        .execute(pool)
        .await
        .unwrap();
    scratch.drop_database().await;
}
