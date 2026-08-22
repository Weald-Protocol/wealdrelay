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
use wealdrelay::media::gc;
use wealdrelay::media::retention::{
    self, Authorization, ControlOutcome, ManifestOutcome, StoreError,
};
use wealdrelay::media::store;

use support::{
    blob_hash, config_for, device_from, make_group_in, sign_all, signed_control,
    signed_destruction, signed_manifest, signed_policy, signed_resolution, verifier_key, Running,
    Scratch,
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
    // WEALD-L294: this is the actual wire message, not a direct pool call —
    // until it existed, nothing could ever reach `clear_freeze` and a frozen
    // group had no client-reachable recovery.
    let bad_verifier = signed_resolution(&group, 1, &verifier_key(0x99));
    assert_eq!(
        retention::resolve_freeze(pool, &bad_verifier)
            .await
            .unwrap(),
        retention::ResolveOutcome::UnknownVerifier,
        "a verifier that never appeared for this epoch resolves nothing"
    );
    assert!(retention::is_frozen(pool, &group).await.unwrap());

    let resolution = signed_resolution(&group, 1, &honest);
    assert_eq!(
        retention::resolve_freeze(pool, &resolution).await.unwrap(),
        retention::ResolveOutcome::Cleared
    );
    assert!(!retention::is_frozen(pool, &group).await.unwrap());

    // A group the relay has never heard of is not frozen, and asking is not an
    // error: `/readyz` reports on groups it holds.
    assert!(!retention::is_frozen(pool, &blob_hash(0x00)).await.unwrap());

    scratch.drop_database().await;
}

/// The race the freeze exists for. Before `apply_control` used `on conflict do
/// nothing` and re-read the winner, two distinct valid successors could both pass
/// the pre-insert read seeing no row for the epoch; one insert won on the bare
/// `(group_id, epoch)` primary key and the other failed with a database error
/// that never reached the conflict-and-freeze path. Run it enough times, with a
/// fresh group each time, that a fix which only wins the race by luck would show
/// its seams.
#[tokio::test]
async fn racing_two_valid_successors_always_leaves_one_control_one_conflict_and_a_frozen_group() {
    let (scratch, _blobs, state) = prepared("retention_race").await;
    let pool = pool_of(&state);

    for round in 0u8..20 {
        let group = workspace_with(
            &state,
            &format!("ws-race-{round}"),
            0x70 + round,
            &[device_from(0x71)],
        )
        .await;
        let epoch0 = verifier_key(0x21);
        let genesis = signed_control(&group, 0, &epoch0, None, &epoch0);
        retention::apply_control(pool, &genesis).await.unwrap();

        let a = signed_control(
            &group,
            1,
            &verifier_key(0x81 + round),
            Some(genesis.digest()),
            &epoch0,
        );
        let b = signed_control(
            &group,
            1,
            &verifier_key(0x91 + round),
            Some(genesis.digest()),
            &epoch0,
        );

        let pool_a = pool.clone();
        let pool_b = pool.clone();
        let (outcome_a, outcome_b) = tokio::join!(
            tokio::spawn(async move { retention::apply_control(&pool_a, &a).await.unwrap() }),
            tokio::spawn(async move { retention::apply_control(&pool_b, &b).await.unwrap() }),
        );
        let (outcome_a, outcome_b) = (outcome_a.unwrap(), outcome_b.unwrap());

        // Exactly one side is the winner and the other the loser: never both
        // Accepted (that would mean the primary key did not hold) and never
        // neither (that would mean the race dropped a control on the floor).
        let winners = [&outcome_a, &outcome_b]
            .into_iter()
            .filter(|o| **o == ControlOutcome::Accepted)
            .count();
        let losers = [&outcome_a, &outcome_b]
            .into_iter()
            .filter(|o| **o == ControlOutcome::ConflictFroze)
            .count();
        assert_eq!(
            (winners, losers),
            (1, 1),
            "round {round}: {outcome_a:?} / {outcome_b:?}"
        );

        let controls: i64 = sqlx::query_scalar(
            "select count(*) from relay_retention_control where group_id = $1 and epoch = 1",
        )
        .bind(&group)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(controls, 1, "round {round}: exactly one settled control");

        let conflicts: i64 = sqlx::query_scalar(
            "select count(*) from relay_retention_control_conflict where group_id = $1",
        )
        .bind(&group)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(conflicts, 1, "round {round}: exactly one conflict artifact");

        assert!(
            retention::is_frozen(pool, &group).await.unwrap(),
            "round {round}: the group is frozen"
        );
    }

    scratch.drop_database().await;
}

/// WEALD-L183. A device the workspace admits, holding no group membership and no
/// prior-epoch key material, mints a keypair and publishes an epoch-0
/// `RetentionControl` for a group that already has one.
///
/// Before the fix this was two attacks in one frame. The forged genesis was not
/// the settled record, so it took the successor-race path and froze the group,
/// and `gc::eligible` then answered `Frozen` for every blob of that group
/// forever: no policy, no tombstone and no sweep ran again. One frame per group
/// id turned a whole workspace's retention off, and the deletions the product
/// promises silently stopped happening. Against a group with no genesis yet, the
/// same frame made the impostor the chain root instead.
///
/// A genesis is claimed once. A second one signed by a different verifier is
/// refused, and refusal is the whole point: it must not freeze, because a freeze
/// a non-member can set is the denial of service being fixed.
#[tokio::test]
async fn a_forged_genesis_control_from_a_non_member_is_refused_and_never_freezes_the_group() {
    let (scratch, _blobs, state) = prepared("retention_forged_genesis").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-forged", 0x6f, &[device_from(0x71)]).await;

    // The founder's chain, and one blob claimed under it, so there is real
    // eligibility to compare against rather than the empty case.
    let epoch0 = verifier_key(0x21);
    let genesis = signed_control(&group, 0, &epoch0, None, &epoch0);
    assert_eq!(
        retention::apply_control(pool, &genesis).await.unwrap(),
        ControlOutcome::Accepted
    );
    store::ensure_quota_row(pool, "ws-forged", None)
        .await
        .unwrap();
    store::reserve(pool, "ws-forged", &group, &blob_hash(0xa1), 100, false, 900)
        .await
        .unwrap();
    let manifest = signed_manifest(&group, 0, 1, None, vec![blob_hash(0xa1)], &epoch0);
    assert!(matches!(
        retention::apply_manifest(pool, "ws-forged", &manifest)
            .await
            .unwrap(),
        ManifestOutcome::Accepted { .. }
    ));
    let before = gc::eligible(pool, "ws-forged", &group, &blob_hash(0xa1), 1_000, 2_000)
        .await
        .unwrap();
    assert_eq!(before, gc::Eligibility::Live);

    // Mallory: enrolled in the workspace, in no way a member of this group, and
    // the key she signs with is one she generated a moment ago.
    let mallory = verifier_key(0xbe);
    let forged = signed_control(&group, 0, &mallory, None, &mallory);
    assert_eq!(
        retention::apply_control(pool, &forged).await.unwrap(),
        ControlOutcome::Invalid("group already has a genesis control")
    );

    // Refused, not recorded, and above all not frozen.
    assert!(
        !retention::is_frozen(pool, &group).await.unwrap(),
        "a non-member must not be able to freeze a group"
    );
    let conflicts: i64 = sqlx::query_scalar(
        "select count(*) from relay_retention_control_conflict where group_id = $1",
    )
    .bind(&group)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(conflicts, 0);

    // The group's control is exactly the one the founder settled.
    let settled: Vec<u8> = sqlx::query_scalar(
        "select verifier from relay_retention_control where group_id = $1 and epoch = 0",
    )
    .bind(&group)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(settled, epoch0.verifying_key().to_bytes().to_vec());

    // And garbage collection answers what it answered before the frame arrived.
    let after = gc::eligible(pool, "ws-forged", &group, &blob_hash(0xa1), 1_000, 2_000)
        .await
        .unwrap();
    assert_eq!(after, before);
    assert_ne!(after, gc::Eligibility::Frozen);

    // The founder's own record, resent byte for byte, is still a retry.
    assert_eq!(
        retention::apply_control(pool, &genesis).await.unwrap(),
        ControlOutcome::Accepted
    );

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
        ManifestOutcome::Invalid("no retention control for this group".to_string())
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

/// The removed member's manifest. Once the group rotates, the key the departing
/// device still holds signs for an epoch that is no longer the latest, and an
/// omission from the newest manifest is exactly what `gc::eligible` reads as
/// permission to delete. The epoch transition check `latest_control` delegates is
/// therefore made for manifests too, not only for `drop_before`.
#[tokio::test]
async fn a_manifest_signed_by_a_superseded_epoch_is_refused_and_never_the_latest() {
    let (scratch, _blobs, state) = prepared("retention_manifest_stale_epoch").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-staleman", 0x6d, &[device_from(0x71)]).await;
    let epoch0 = verifier_key(0x21);
    let genesis = signed_control(&group, 0, &epoch0, None, &epoch0);
    retention::apply_control(pool, &genesis).await.unwrap();

    store::ensure_quota_row(pool, "ws-staleman", None)
        .await
        .unwrap();
    for seed in [0xa1u8, 0xa2] {
        store::reserve(
            pool,
            "ws-staleman",
            &group,
            &blob_hash(seed),
            100,
            false,
            900,
        )
        .await
        .unwrap();
    }
    let real = signed_manifest(
        &group,
        0,
        1,
        None,
        vec![blob_hash(0xa1), blob_hash(0xa2)],
        &epoch0,
    );
    let digest = match retention::apply_manifest(pool, "ws-staleman", &real)
        .await
        .unwrap()
    {
        ManifestOutcome::Accepted { digest } => digest,
        other => panic!("expected an accepted manifest, got {other:?}"),
    };

    // The rotation that removed the device: epoch one is now the group's latest.
    let epoch1 = verifier_key(0x22);
    retention::apply_control(
        pool,
        &signed_control(&group, 1, &epoch1, Some(genesis.digest()), &epoch0),
    )
    .await
    .unwrap();

    // Correctly signed for epoch zero, correctly sequenced, correctly anchored,
    // and dropping a blob the remaining members still hold.
    let stale = signed_manifest(
        &group,
        0,
        2,
        Some(digest.clone()),
        vec![blob_hash(0xa1)],
        &epoch0,
    );
    assert_eq!(
        retention::apply_manifest(pool, "ws-staleman", &stale)
            .await
            .unwrap(),
        ManifestOutcome::Invalid("manifest epoch is not the group's latest epoch".to_string())
    );

    // The chain is where it was, and the omitted blob is still named by it, so
    // nothing it holds has become a collection candidate.
    let latest = retention::latest_manifest(pool, &group)
        .await
        .unwrap()
        .expect("the honest manifest is still the latest");
    assert_eq!(latest.sequence, 1);
    assert_eq!(latest.digest, digest);
    assert_eq!(latest.blobs, vec![blob_hash(0xa1), blob_hash(0xa2)]);

    let rejected: i64 = sqlx::query_scalar(
        "select count(*) from relay_retention_manifest_rejected where group_id = $1",
    )
    .bind(&group)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(rejected, 1);

    // A manifest at the current epoch, signed by the key that survived the
    // rotation, still advances the chain.
    let fresh = signed_manifest(&group, 1, 2, Some(digest), vec![blob_hash(0xa1)], &epoch1);
    assert!(matches!(
        retention::apply_manifest(pool, "ws-staleman", &fresh)
            .await
            .unwrap(),
        ManifestOutcome::Accepted { .. }
    ));

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

// MARK: The chain position a joiner resyncs against (WEALD-L355)

/// The relay is the authority on where a group's manifest chain is, and it can
/// now say so.
///
/// Before this, no response on the media wire carried the group's position, so a
/// client had nothing but its own device log to derive `sequence` and
/// `prev_manifest_hash` from. That is right for the device that founded the
/// group and permanently wrong for every other one: a joiner's log is empty, it
/// sends `sequence = 1` into a group already past it, `apply_manifest` refuses
/// with "sequence does not advance by exactly one", and because the local log
/// only advances on an ack it never gets, it sends the same refused record for
/// the life of the group.
#[tokio::test]
async fn the_position_reports_the_group_chain_so_a_joiner_can_resync() {
    let (scratch, _blobs, state) = prepared("retention_position").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-position", 0x66, &[device_from(0x71)]).await;

    // A group with nothing at all: no control, no manifest. The digest, not the
    // epoch, is what says "no chain", because epoch zero is a real epoch.
    let empty = retention::position(pool, &group).await.unwrap();
    assert_eq!(empty.control_digest, None);
    assert_eq!(empty.next_sequence, retention::FIRST_MANIFEST_SEQUENCE);
    assert_eq!(empty.prev_manifest_hash, None);
    assert!(empty.blobs.is_empty());

    let epoch0 = verifier_key(0x21);
    let genesis = signed_control(&group, 0, &epoch0, None, &epoch0);
    retention::apply_control(pool, &genesis).await.unwrap();

    let founded = retention::position(pool, &group).await.unwrap();
    assert_eq!(founded.control_epoch, 0);
    assert_eq!(founded.control_digest, Some(genesis.digest()));
    assert_eq!(founded.next_sequence, retention::FIRST_MANIFEST_SEQUENCE);

    let first = signed_manifest(
        &group,
        0,
        retention::FIRST_MANIFEST_SEQUENCE,
        None,
        vec![blob_hash(1), blob_hash(2)],
        &epoch0,
    );
    let ManifestOutcome::Accepted { digest } =
        retention::apply_manifest(pool, "ws-position", &first)
            .await
            .unwrap()
    else {
        panic!("the founder's first manifest must be accepted")
    };

    // What a joiner reads. Everything it needs and nothing it could have guessed:
    // the sequence to name, the predecessor to name, the epoch to sign under, and
    // the claim set it must not shrink.
    let after = retention::position(pool, &group).await.unwrap();
    assert_eq!(after.next_sequence, 2);
    assert_eq!(after.prev_manifest_hash, Some(digest.clone()));
    assert_eq!(after.control_epoch, 0);
    assert_eq!(after.control_digest, Some(genesis.digest()));
    assert_eq!(after.blobs, vec![blob_hash(1), blob_hash(2)]);

    // The joiner's old behaviour, kept as the negative half: sequence 1 with no
    // predecessor, which is what an empty device log produces.
    let stale = signed_manifest(&group, 0, 1, None, vec![blob_hash(3)], &epoch0);
    assert_eq!(
        retention::apply_manifest(pool, "ws-position", &stale)
            .await
            .unwrap(),
        ManifestOutcome::Invalid("sequence does not advance by exactly one".to_string())
    );

    // The same device, rebuilt from the reported position and carrying the claim
    // set forward, is accepted.
    let resynced = signed_manifest(
        &group,
        after.control_epoch,
        after.next_sequence,
        after.prev_manifest_hash.clone(),
        {
            let mut blobs = after.blobs.clone();
            blobs.push(blob_hash(3));
            blobs
        },
        &epoch0,
    );
    assert!(matches!(
        retention::apply_manifest(pool, "ws-position", &resynced)
            .await
            .unwrap(),
        ManifestOutcome::Accepted { .. }
    ));

    // And the founder's two blobs are still claimed, which is the third half of
    // WEALD-L355: an omission is the only deletion signal the relay has, so a
    // joiner publishing only what it can see would have un-claimed them.
    let settled = retention::position(pool, &group).await.unwrap();
    assert_eq!(
        settled.blobs,
        vec![blob_hash(1), blob_hash(2), blob_hash(3)]
    );

    scratch.drop_database().await;
}

/// The position reports the newest control, not the genesis one, so a joiner
/// that lived through a rotation signs under the epoch the relay actually holds.
#[tokio::test]
async fn the_position_names_the_newest_control_epoch() {
    let (scratch, _blobs, state) = prepared("retention_position_epoch").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-posepoch", 0x67, &[device_from(0x71)]).await;

    let epoch0 = verifier_key(0x21);
    let epoch1 = verifier_key(0x22);
    let genesis = signed_control(&group, 0, &epoch0, None, &epoch0);
    retention::apply_control(pool, &genesis).await.unwrap();
    let rotated = signed_control(&group, 1, &epoch1, Some(genesis.digest()), &epoch0);
    retention::apply_control(pool, &rotated).await.unwrap();

    let position = retention::position(pool, &group).await.unwrap();
    assert_eq!(position.control_epoch, 1);
    assert_eq!(position.control_digest, Some(rotated.digest()));

    // A joiner holding the keys for epochs 0 and 1 publishes the successor for
    // epoch 2 by naming exactly this digest, which is the anchor that used to be
    // available only to the device holding epoch zero.
    let epoch2 = verifier_key(0x23);
    let successor = signed_control(
        &group,
        2,
        &epoch2,
        Some(position.control_digest.clone().unwrap()),
        &epoch1,
    );
    assert_eq!(
        retention::apply_control(pool, &successor).await.unwrap(),
        ControlOutcome::Accepted
    );

    scratch.drop_database().await;
}
