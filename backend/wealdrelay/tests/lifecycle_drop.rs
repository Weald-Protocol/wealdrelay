// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Text compaction against a real Postgres: what a `drop_before` removes, what it
//! must never remove, and every refusal on the way.
//!
//! Tier 3 and tier 4. `specs/backend/relay/lifecycle.md` is unusually blunt about
//! the stakes here, so this file is written against its sentences rather than
//! against the implementation:
//!
//! - "The relay verifies the retention-key transition chain, the authorization,
//!   and that all named snapshot envelopes are present and retained before
//!   deleting anything below the barrier; it keeps the checkpoint and its
//!   snapshots forever as the anchor."
//! - "A relay rejects a drop with an incomplete manifest or missing authorization
//!   rather than guessing which envelopes are safe to lose."
//! - "A frozen retention chain freezes text compaction too."
//! - "The failure mode is a storage bill, which is recoverable, rather than
//!   history a departing member arranged to have deleted, which is not."
//!
//! Every envelope below is a real row written through `accept::accept`, the same
//! path a `SEND` frame takes, and every deletion is the real statement running
//! against the real table. Nothing is mocked, because the thing being proven is
//! which rows survive.

mod support;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sqlx::PgPool;
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::lifecycle::{self, store as lifecycle_store, wire, Refusal};
use wealdrelay::media::retention;

use support::{
    config_for, device_from, envelope_for, make_group_in, signed_control, signed_destruction,
    signed_drop, signed_policy, verifier_key, Running, Scratch,
};

const NOW_MS: u64 = 1_800_000_000_000;
const NOW_SECS: u64 = NOW_MS / 1000;
const WORKSPACE: &str = "ws-lifecycle";

struct Harness {
    scratch: Scratch,
    _blobs: tempfile::TempDir,
    state: Arc<RelayState>,
    config: wealdrelay::config::Config,
    written: AtomicU64,
}

impl Harness {
    async fn new(label: &str) -> Self {
        let scratch = Scratch::new(label).await;
        let blobs = tempfile::tempdir().unwrap();
        let config = config_for(&scratch, blobs.path());
        let relay = Running::start(config.clone(), Clock::Fixed(NOW_MS)).await;
        let state = Arc::clone(&relay.state);
        relay.shutdown().await;
        Self {
            scratch,
            _blobs: blobs,
            state,
            config,
            written: AtomicU64::new(0),
        }
    }

    fn pool(&self) -> &PgPool {
        self.state.database.as_ref().expect("a database").pool()
    }

    /// One group with an authorizer pair, which is what a threshold-authorized
    /// record is checked against.
    async fn group(&self, byte: u8) -> Vec<u8> {
        make_group_in(
            &self.state,
            WORKSPACE,
            byte,
            &[device_from(0x71), device_from(0x72)],
            &[device_from(0x71), device_from(0x72)],
        )
        .await
    }

    /// Write `count` envelopes into the group and answer with their hashes in the
    /// order the relay numbered them.
    ///
    /// The body counter is per harness and never restarts, because an envelope's
    /// hash is its content address: two calls that wrote "record 0" would be one
    /// envelope stored once and a test that believed it had two.
    async fn fill(&self, group: &[u8], count: usize) -> Vec<Vec<u8>> {
        let mut hashes = Vec::with_capacity(count);
        for _ in 0..count {
            let index = self.written.fetch_add(1, Ordering::Relaxed);
            let envelope = envelope_for(group, format!("record {index}").as_bytes());
            wealdrelay::accept::accept(self.pool(), &self.config, &envelope, NOW_MS)
                .await
                .expect("the envelope is accepted");
            hashes.push(envelope.hash.clone());
        }
        hashes
    }

    async fn seq_of(&self, group: &[u8], hash: &[u8]) -> i64 {
        sqlx::query_scalar("select seq from relay_envelope where group_id = $1 and hash = $2")
            .bind(group)
            .bind(hash)
            .fetch_one(self.pool())
            .await
            .expect("the envelope is there")
    }

    async fn hashes(&self, group: &[u8]) -> Vec<Vec<u8>> {
        sqlx::query_scalar("select hash from relay_envelope where group_id = $1 order by seq")
            .bind(group)
            .fetch_all(self.pool())
            .await
            .expect("read the log")
    }

    /// The retention chain at epoch zero, which is what a `drop_before` is signed
    /// under until a commit rotates it.
    async fn chain(&self, group: &[u8], epoch: u64) {
        let key = verifier_key(0x51 + epoch as u8);
        let record = if epoch == 0 {
            signed_control(group, 0, &key, None, &key)
        } else {
            let prior = verifier_key(0x51 + (epoch - 1) as u8);
            let prior_control = signed_control(group, epoch - 1, &prior, None, &prior);
            signed_control(group, epoch, &key, Some(prior_control.digest()), &prior)
        };
        let outcome = retention::apply_control(self.pool(), &record)
            .await
            .expect("the control lands");
        assert_eq!(
            outcome,
            retention::ControlOutcome::Accepted,
            "epoch {epoch}"
        );
    }

    /// A due policy, which is the ordinary authorization a steward's compaction
    /// runs under.
    async fn policy(&self, group: &[u8], version: u64, not_before: u64) {
        let record = signed_policy(
            group,
            version,
            180,
            not_before,
            &[device_from(0x71), device_from(0x72)],
        );
        let authorization = retention::authorize(
            self.pool(),
            WORKSPACE,
            &record.signing_bytes(),
            &record.signatures,
            record.not_before,
            NOW_SECS,
        )
        .await
        .expect("authorization is checkable");
        assert_eq!(authorization, retention::Authorization::Threshold);
        retention::insert_policy(self.pool(), &record, "[]")
            .await
            .expect("the policy lands");
    }

    async fn finish(self) {
        self.scratch.drop_database().await;
    }
}

fn instruction(
    group: &[u8],
    manifest: &[u8],
    snapshots: Vec<Vec<u8>>,
    epoch: u64,
) -> wire::DropBefore {
    signed_drop(
        group,
        manifest,
        snapshots,
        epoch,
        Some(1),
        None,
        &verifier_key(0x51 + epoch as u8),
    )
}

// MARK: The compaction itself

#[tokio::test]
async fn a_drop_removes_everything_below_the_barrier_and_the_anchors_survive_it() {
    let harness = Harness::new("lifecycle_drop").await;
    let group = harness.group(0x41).await;
    harness.chain(&group, 0).await;
    harness.policy(&group, 1, NOW_SECS - 1).await;

    // Ten records, then a checkpoint envelope and one snapshot, which is the
    // shape a steward writes: the snapshot replaces what is below, the checkpoint
    // names it, and both are above the material they replace.
    let old = harness.fill(&group, 10).await;
    let snapshot = harness.fill(&group, 1).await[0].clone();
    let manifest = harness.fill(&group, 1).await[0].clone();
    let above = harness.fill(&group, 2).await;
    let barrier = harness.seq_of(&group, &manifest).await as u64;

    let record = instruction(&group, &manifest, vec![snapshot.clone()], 0);
    let outcome = lifecycle::drop_before(harness.pool(), WORKSPACE, &record, NOW_SECS)
        .await
        .expect("the relay could look")
        .expect("the instruction is accepted");

    // Ten went, the snapshot stayed. The snapshot is below the barrier and is an
    // anchor, which is the one exception the barrier has.
    assert_eq!(outcome.deleted, 10);
    assert_eq!(outcome.kept, 1, "the snapshot below the barrier survived");
    assert!(outcome.bytes > 0, "bytes reclaimed were counted");

    let left = harness.hashes(&group).await;
    assert!(
        !left.iter().any(|hash| old.contains(hash)),
        "history below the barrier survived a drop that reported removing it"
    );
    assert!(left.contains(&snapshot), "the snapshot was collected");
    assert!(left.contains(&manifest), "the checkpoint was collected");
    for hash in &above {
        assert!(
            left.contains(hash),
            "an envelope above the barrier was lost"
        );
    }

    // The run log, which is the artifact an operator reads.
    let runs = lifecycle_store::runs(harness.pool(), &group)
        .await
        .expect("the run log");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].deleted_count, 10);
    assert_eq!(runs[0].kept_count, 1);
    assert_eq!(runs[0].barrier_seq, barrier);
    assert_eq!(runs[0].manifest_hash, manifest);
    assert!(format!("{:?}", runs[0]).contains("DropRun"));

    // And the anchors are recorded, so a later barrier cannot sweep them.
    let anchors = lifecycle_store::anchors(harness.pool(), &group)
        .await
        .expect("the anchors");
    assert_eq!(anchors.len(), 2);
    assert!(anchors.contains(&snapshot) && anchors.contains(&manifest));

    harness.finish().await;
}

#[tokio::test]
async fn a_second_drop_never_sweeps_an_earlier_checkpoints_snapshots() {
    // The compounding failure: compact once, then compact again with a barrier
    // above the first checkpoint. A relay that only protected the newest
    // checkpoint's anchors would delete the snapshot the first checkpoint
    // promised, and anybody verifying from that checkpoint would find nothing.
    let harness = Harness::new("lifecycle_two_drops").await;
    let group = harness.group(0x42).await;
    harness.chain(&group, 0).await;
    harness.policy(&group, 1, NOW_SECS - 1).await;

    harness.fill(&group, 3).await;
    let first_snapshot = harness.fill(&group, 1).await[0].clone();
    let first_manifest = harness.fill(&group, 1).await[0].clone();
    let _first_barrier = harness.seq_of(&group, &first_manifest).await as u64;
    lifecycle::drop_before(
        harness.pool(),
        WORKSPACE,
        &instruction(&group, &first_manifest, vec![first_snapshot.clone()], 0),
        NOW_SECS,
    )
    .await
    .expect("the relay could look")
    .expect("the first instruction is accepted");

    harness.fill(&group, 3).await;
    let second_snapshot = harness.fill(&group, 1).await[0].clone();
    let second_manifest = harness.fill(&group, 1).await[0].clone();
    let _second_barrier = harness.seq_of(&group, &second_manifest).await as u64;
    let outcome = lifecycle::drop_before(
        harness.pool(),
        WORKSPACE,
        &instruction(&group, &second_manifest, vec![second_snapshot.clone()], 0),
        NOW_SECS,
    )
    .await
    .expect("the relay could look")
    .expect("the second instruction is accepted");

    let left = harness.hashes(&group).await;
    assert!(
        left.contains(&first_snapshot),
        "the older checkpoint's snapshot was swept by a newer barrier"
    );
    assert!(left.contains(&first_manifest), "the older checkpoint went");
    assert!(left.contains(&second_snapshot));
    assert_eq!(
        outcome.kept, 3,
        "both anchors of the first checkpoint and the second's snapshot"
    );

    harness.finish().await;
}

#[tokio::test]
async fn a_one_off_compaction_runs_on_a_destruction_record_instead_of_a_policy() {
    // "A one-off compact-now request instead carries a due `RetentionDestruction`
    // authorization." The admin-visible lever, which is the same instruction with
    // a different permission behind it.
    let harness = Harness::new("lifecycle_destruction").await;
    let group = harness.group(0x43).await;
    harness.chain(&group, 0).await;

    harness.fill(&group, 4).await;
    let manifest = harness.fill(&group, 1).await[0].clone();
    let _barrier = harness.seq_of(&group, &manifest).await as u64;

    let digest = vec![0x9a; 32];
    let record = signed_destruction(
        &group,
        lifecycle::DESTRUCTION_KIND,
        &digest,
        NOW_SECS - 1,
        &[device_from(0x71), device_from(0x72)],
    );
    retention::insert_destruction(harness.pool(), &record, "[]")
        .await
        .expect("the destruction lands");

    let instruction = signed_drop(
        &group,
        &manifest,
        Vec::new(),
        0,
        None,
        Some(digest.clone()),
        &verifier_key(0x51),
    );
    let outcome = lifecycle::drop_before(harness.pool(), WORKSPACE, &instruction, NOW_SECS)
        .await
        .expect("the relay could look")
        .expect("a due destruction authorizes the compaction");
    assert_eq!(outcome.deleted, 4);

    // And not before it is due.
    let early_digest = vec![0x9b; 32];
    let early = signed_destruction(
        &group,
        lifecycle::DESTRUCTION_KIND,
        &early_digest,
        NOW_SECS + 60,
        &[device_from(0x71), device_from(0x72)],
    );
    retention::insert_destruction(harness.pool(), &early, "[]")
        .await
        .expect("the destruction lands");
    harness.fill(&group, 2).await;
    let later_manifest = harness.fill(&group, 1).await[0].clone();
    let _later_barrier = harness.seq_of(&group, &later_manifest).await as u64;
    let refused = lifecycle::drop_before(
        harness.pool(),
        WORKSPACE,
        &signed_drop(
            &group,
            &later_manifest,
            Vec::new(),
            0,
            None,
            Some(early_digest),
            &verifier_key(0x51),
        ),
        NOW_SECS,
    )
    .await
    .expect("the relay could look")
    .expect_err("a destruction that is not due authorizes nothing");
    assert_eq!(refused, Refusal::AuthorizationNotDue);
    assert_eq!(refused.reason(), "authorization_not_due");

    harness.finish().await;
}

// MARK: The negatives, one per way history is lost

#[tokio::test]
async fn a_manifest_that_fails_verification_refuses_to_run() {
    // The gate's negative, and the important one: "A relay rejects a drop with an
    // incomplete manifest ... rather than guessing which envelopes are safe to
    // lose." A snapshot the relay is not holding means the barrier has nothing
    // behind it, and dropping under it destroys history rather than compacting it.
    let harness = Harness::new("lifecycle_incomplete").await;
    let group = harness.group(0x44).await;
    harness.chain(&group, 0).await;
    harness.policy(&group, 1, NOW_SECS - 1).await;

    let before = harness.fill(&group, 5).await;
    let manifest = harness.fill(&group, 1).await[0].clone();
    let _barrier = harness.seq_of(&group, &manifest).await as u64;

    // A snapshot nobody ever published.
    let refusal = lifecycle::drop_before(
        harness.pool(),
        WORKSPACE,
        &instruction(&group, &manifest, vec![vec![0xee; 32]], 0),
        NOW_SECS,
    )
    .await
    .expect("the relay could look")
    .expect_err("an incomplete manifest is refused");
    assert_eq!(refusal, Refusal::IncompleteManifest { missing: 1 });
    assert_eq!(refusal.reason(), "incomplete_manifest:1");

    // A checkpoint envelope nobody published either, which is the same refusal
    // for the anchor itself.
    let refusal = lifecycle::drop_before(
        harness.pool(),
        WORKSPACE,
        &instruction(&group, &[0xef; 32], Vec::new(), 0),
        NOW_SECS,
    )
    .await
    .expect("the relay could look")
    .expect_err("a checkpoint the relay does not hold is refused");
    assert_eq!(refusal, Refusal::IncompleteManifest { missing: 1 });

    // And nothing moved. A refusal is never a partial run.
    assert_eq!(harness.hashes(&group).await.len(), 6);
    for hash in &before {
        assert!(harness.hashes(&group).await.contains(hash));
    }
    assert!(lifecycle_store::runs(harness.pool(), &group)
        .await
        .expect("the run log")
        .is_empty());

    harness.finish().await;
}

#[tokio::test]
async fn a_frozen_chain_freezes_text_compaction_too() {
    // "A frozen retention chain freezes text compaction too. A group whose
    // control chain is contested stops dropping anything until a member resolves
    // the conflict." The freeze is what a removed member's forged successor buys
    // them, and it must buy them a storage bill rather than a deletion.
    let harness = Harness::new("lifecycle_frozen").await;
    let group = harness.group(0x45).await;
    harness.chain(&group, 0).await;
    harness.policy(&group, 1, NOW_SECS - 1).await;
    harness.fill(&group, 3).await;
    let manifest = harness.fill(&group, 1).await[0].clone();
    let _barrier = harness.seq_of(&group, &manifest).await as u64;

    // A second, differently signed control for the same epoch: the successor race
    // from `media.md`, run for real rather than asserted.
    let genuine = verifier_key(0x51);
    let forged = signed_control(&group, 0, &verifier_key(0x7f), None, &verifier_key(0x7f));
    let outcome = retention::apply_control(harness.pool(), &forged)
        .await
        .expect("the conflicting control is stored as evidence");
    assert_eq!(outcome, retention::ControlOutcome::ConflictFroze);

    let refusal = lifecycle::drop_before(
        harness.pool(),
        WORKSPACE,
        &instruction(&group, &manifest, Vec::new(), 0),
        NOW_SECS,
    )
    .await
    .expect("the relay could look")
    .expect_err("a frozen group drops nothing");
    assert_eq!(refusal, Refusal::GroupFrozen);
    assert_eq!(refusal.reason(), "group_frozen");
    assert_eq!(harness.hashes(&group).await.len(), 4);

    // And it runs again once a member resolves the conflict, which is the only
    // way a freeze clears.
    retention::clear_freeze(harness.pool(), &group)
        .await
        .expect("a member resolved it");
    let outcome = lifecycle::drop_before(
        harness.pool(),
        WORKSPACE,
        &signed_drop(&group, &manifest, Vec::new(), 0, Some(1), None, &genuine),
        NOW_SECS,
    )
    .await
    .expect("the relay could look")
    .expect("the resolved group compacts");
    assert_eq!(outcome.deleted, 3);

    harness.finish().await;
}

#[tokio::test]
async fn an_instruction_signed_by_a_superseded_epoch_is_refused() {
    // The removed member's own instruction. They held the previous epoch's
    // verifier and can still sign with it; what they cannot do is sign as the
    // epoch the commit that removed them created. The chain's newest control is
    // the only authority a drop may claim.
    let harness = Harness::new("lifecycle_stale_epoch").await;
    let group = harness.group(0x46).await;
    harness.chain(&group, 0).await;
    harness.chain(&group, 1).await;
    harness.policy(&group, 1, NOW_SECS - 1).await;
    harness.fill(&group, 3).await;
    let manifest = harness.fill(&group, 1).await[0].clone();
    let _barrier = harness.seq_of(&group, &manifest).await as u64;

    let refusal = lifecycle::drop_before(
        harness.pool(),
        WORKSPACE,
        &instruction(&group, &manifest, Vec::new(), 0),
        NOW_SECS,
    )
    .await
    .expect("the relay could look")
    .expect_err("an old epoch's verifier is not the chain's authority");
    assert_eq!(refusal, Refusal::StaleEpoch { latest: 1 });
    assert_eq!(refusal.reason(), "stale_epoch:1");
    assert_eq!(harness.hashes(&group).await.len(), 4);

    // The current epoch's verifier is accepted, which is what makes the refusal
    // above about authority rather than about the chain being unreadable.
    let outcome = lifecycle::drop_before(
        harness.pool(),
        WORKSPACE,
        &instruction(&group, &manifest, Vec::new(), 1),
        NOW_SECS,
    )
    .await
    .expect("the relay could look")
    .expect("the current epoch compacts");
    assert_eq!(outcome.deleted, 3);

    harness.finish().await;
}

#[tokio::test]
async fn a_signature_that_is_not_the_epochs_verifier_is_refused() {
    let harness = Harness::new("lifecycle_bad_sig").await;
    let group = harness.group(0x47).await;
    harness.chain(&group, 0).await;
    harness.policy(&group, 1, NOW_SECS - 1).await;
    harness.fill(&group, 2).await;
    let manifest = harness.fill(&group, 1).await[0].clone();
    let _barrier = harness.seq_of(&group, &manifest).await as u64;

    let forged = signed_drop(
        &group,
        &manifest,
        Vec::new(),
        0,
        Some(1),
        None,
        // Anybody's key. The record is well formed and permits nothing.
        &verifier_key(0x7e),
    );
    let refusal = lifecycle::drop_before(harness.pool(), WORKSPACE, &forged, NOW_SECS)
        .await
        .expect("the relay could look")
        .expect_err("a signature from the wrong key is refused");
    assert_eq!(refusal, Refusal::BadSignature);
    assert_eq!(refusal.reason(), "bad_signature");

    // A record whose fields were edited after signing: the signature verifies
    // against the bytes that were signed, and these are not those bytes.
    // An edited instruction: the snapshot list is part of what was signed, so
    // adding an entry after signing is the same forgery as any other field.
    let mut tampered = instruction(&group, &manifest, Vec::new(), 0);
    tampered.snapshots.push(vec![0xcc; 32]);
    let refusal = lifecycle::drop_before(harness.pool(), WORKSPACE, &tampered, NOW_SECS)
        .await
        .expect("the relay could look")
        .expect_err("an edited instruction is refused");
    assert_eq!(refusal, Refusal::BadSignature);
    assert_eq!(harness.hashes(&group).await.len(), 3);

    harness.finish().await;
}

#[tokio::test]
async fn an_instruction_with_no_due_authorization_deletes_nothing() {
    // "A relay rejects a drop with ... missing authorization." Four shapes of
    // missing, because each is a different mistake and one of them is an attack:
    // no authorization named at all, a policy version that is not the active one,
    // a policy that has not come due, and a destruction record nobody signed.
    let harness = Harness::new("lifecycle_unauthorized").await;
    let group = harness.group(0x48).await;
    harness.chain(&group, 0).await;
    harness.fill(&group, 3).await;
    let manifest = harness.fill(&group, 1).await[0].clone();
    let _barrier = harness.seq_of(&group, &manifest).await as u64;
    let key = verifier_key(0x51);

    // Nothing named.
    let refusal = lifecycle::drop_before(
        harness.pool(),
        WORKSPACE,
        &signed_drop(&group, &manifest, Vec::new(), 0, None, None, &key),
        NOW_SECS,
    )
    .await
    .expect("the relay could look")
    .expect_err("an instruction naming no authority permits nothing");
    assert_eq!(refusal, Refusal::NoAuthorization);
    assert_eq!(refusal.reason(), "no_authorization");

    // A policy version with no policy behind it.
    let refusal = lifecycle::drop_before(
        harness.pool(),
        WORKSPACE,
        &instruction(&group, &manifest, Vec::new(), 0),
        NOW_SECS,
    )
    .await
    .expect("the relay could look")
    .expect_err("a policy that does not exist authorizes nothing");
    assert_eq!(refusal, Refusal::NoAuthorization);

    // A destruction record nobody wrote.
    let refusal = lifecycle::drop_before(
        harness.pool(),
        WORKSPACE,
        &signed_drop(
            &group,
            &manifest,
            Vec::new(),
            0,
            None,
            Some(vec![0xcd; 32]),
            &key,
        ),
        NOW_SECS,
    )
    .await
    .expect("the relay could look")
    .expect_err("a destruction record that does not exist authorizes nothing");
    assert_eq!(refusal, Refusal::NoAuthorization);

    // A policy that exists at a different version than the one claimed.
    harness.policy(&group, 2, NOW_SECS - 1).await;
    let refusal = lifecycle::drop_before(
        harness.pool(),
        WORKSPACE,
        &instruction(&group, &manifest, Vec::new(), 0),
        NOW_SECS,
    )
    .await
    .expect("the relay could look")
    .expect_err("a version that is not the active policy authorizes nothing");
    assert_eq!(refusal, Refusal::NoAuthorization);

    // And a policy that is real, current, and not yet due.
    harness.policy(&group, 3, NOW_SECS + 3600).await;
    let refusal = lifecycle::drop_before(
        harness.pool(),
        WORKSPACE,
        &signed_drop(&group, &manifest, Vec::new(), 0, Some(3), None, &key),
        NOW_SECS,
    )
    .await
    .expect("the relay could look")
    .expect_err("a policy that has not come due authorizes nothing");
    assert_eq!(refusal, Refusal::AuthorizationNotDue);

    assert_eq!(harness.hashes(&group).await.len(), 4, "nothing was dropped");

    harness.finish().await;
}

#[tokio::test]
async fn a_group_with_no_retention_chain_compacts_nothing() {
    let harness = Harness::new("lifecycle_no_chain").await;
    let group = harness.group(0x49).await;
    harness.policy(&group, 1, NOW_SECS - 1).await;
    harness.fill(&group, 2).await;
    let manifest = harness.fill(&group, 1).await[0].clone();
    let _barrier = harness.seq_of(&group, &manifest).await as u64;

    let refusal = lifecycle::drop_before(
        harness.pool(),
        WORKSPACE,
        &instruction(&group, &manifest, Vec::new(), 0),
        NOW_SECS,
    )
    .await
    .expect("the relay could look")
    .expect_err("a group with no control chain has no verifier to check against");
    assert_eq!(refusal, Refusal::NoChain);
    assert_eq!(refusal.reason(), "no_retention_chain");
    assert!(format!("{refusal:?}").contains("NoChain"));

    harness.finish().await;
}
