// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The property step 9's gate names: a blob is reclaimed if and only if no live
//! reference exists, across randomised delete and compaction interleavings.
//!
//! Tier 2, against a real Postgres and a real object store rather than a model of
//! them, because the thing under test is a decision made by joining four tables
//! and a bucket listing and there is no version of it that is pure.
//!
//! One case is: some blobs, uploaded, claimed by a first retention manifest, and
//! then a randomised sequence of
//!
//! - **omit**, a later valid manifest that drops one of them, which is the only
//!   deletion signal a blind relay ever gets;
//! - **restore**, a later valid manifest that names it again, which is what an
//!   undo or a second group's reference looks like;
//! - **authorize**, a threshold-authorized `RetentionDestruction` for one blob,
//!   which is the explicit tombstone path;
//! - **sweep**, the retention collector running.
//!
//! After every single step, both directions are asserted:
//!
//! 1. **Nothing referenced is ever gone.** Every blob named by the latest valid
//!    manifest still has its object and its stored bytes, whatever the sequence
//!    was. This is the direction that matters: it is a customer's attachments.
//! 2. **Everything unreferenced and authorized is gone after the next sweep.**
//!    A collector that never collected would satisfy (1) trivially, so the
//!    liveness direction is asserted just as hard, along with the quota
//!    arithmetic that has to follow it.
//!
//! The randomised part is the interleaving, not the shape: a sweep can land
//! between any two manifests, a restore can arrive after a tombstone was already
//! authorized, and a blob can be dropped and named again several times before
//! anything runs.

mod support;

use std::sync::{Arc, OnceLock};

use proptest::prelude::*;
use sqlx::PgPool;
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::media::{gc, retention, store};
use wealdrelay::storage::{BlobKey, Store};

use support::{
    config_for, device_from, seed_access_set_with_authorizers, signed_control, signed_destruction,
    signed_manifest, signed_policy, verifier_key, Running, Scratch,
};

const WS: &str = "ws-media-prop";
const NOW: u64 = 1_800_000_000_000;

/// One tokio runtime and one database for the whole property run.
///
/// Per case would mean creating and dropping a Postgres database a few dozen
/// times, which is minutes of `createdb` and nothing else. Each case gets its own
/// group instead, which is the isolation that actually matters: every table the
/// collector reads is keyed by group.
struct World {
    runtime: tokio::runtime::Runtime,
    state: Arc<RelayState>,
    _scratch: Scratch,
    _blobs: tempfile::TempDir,
}

static WORLD: OnceLock<World> = OnceLock::new();

fn world() -> &'static World {
    WORLD.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let (scratch, blobs, state) = runtime.block_on(async {
            let scratch = Scratch::new("media_props").await;
            let blobs = tempfile::tempdir().unwrap();
            let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(NOW)).await;
            let state = Arc::clone(&relay.state);
            relay.shutdown().await;
            (scratch, blobs, state)
        });
        World {
            runtime,
            state,
            _scratch: scratch,
            _blobs: blobs,
        }
    })
}

fn pool() -> &'static PgPool {
    world().state.database.as_ref().expect("a database").pool()
}

fn storage() -> &'static Store {
    world().state.storage.as_ref().expect("a store")
}

/// The case count is small on purpose and it is a number rather than a shrug:
/// every case here creates a group, uploads objects, and runs the collector
/// against a real database, so the cost per case is milliseconds of I/O rather
/// than microseconds of arithmetic. Raised in ci through the environment, the way
/// `tests/properties.rs` raises its own.
fn config() -> ProptestConfig {
    let cases = std::env::var("WEALD_MEDIA_PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(48);
    ProptestConfig {
        cases,
        // One group per case, and a shrunk case re-runs against a fresh group, so
        // shrinking is safe here even though the world is shared.
        max_shrink_iters: 256,
        ..ProptestConfig::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Omit(usize),
    Restore(usize),
    Authorize(usize),
    Sweep,
}

fn ops() -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec((0u8..4, 0usize..4), 1..14).prop_map(|raw| {
        raw.into_iter()
            .map(|(kind, index)| match kind {
                0 => Op::Omit(index),
                1 => Op::Restore(index),
                2 => Op::Authorize(index),
                _ => Op::Sweep,
            })
            .collect()
    })
}

/// A group id nobody else in this run uses.
fn next_group_id() -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let ordinal = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut group = vec![0u8; 32];
    group[..8].copy_from_slice(&ordinal.to_be_bytes());
    group[8] = 0x9e;
    group
}

fn key(group: &[u8], hash: &[u8]) -> BlobKey {
    BlobKey::new(
        WS,
        wealdrelay::media::hex(group),
        wealdrelay::media::hex(hash),
    )
    .expect("a well formed key")
}

fn blob_hash_of(group: &[u8], index: usize) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(group);
    hasher.update(&(index as u64).to_be_bytes());
    hasher.finalize().as_bytes().to_vec()
}

/// The size of blob `index`, chosen so that a wrong blob being collected changes
/// the quota total by a distinguishable amount.
fn blob_bytes(index: usize) -> usize {
    16 + index * 7
}

proptest! {
    #![proptest_config(config())]

    /// The whole gate part, in one test.
    #[test]
    fn a_blob_is_reclaimed_exactly_when_no_live_reference_remains(
        count in 1usize..5,
        with_policy in any::<bool>(),
        program in ops(),
    ) {
        world().runtime.block_on(run_case(count, with_policy, program))?;
    }
}

async fn run_case(count: usize, with_policy: bool, program: Vec<Op>) -> Result<(), TestCaseError> {
    let ada = device_from(0x71);
    let group = next_group_id();
    let state = &world().state;
    // The workspace's access set is published once for the whole run: it is what
    // `retention::authorize` checks a destruction record against, and it is the
    // same for every case. The group itself is per case, because every table the
    // collector reads is keyed by group and that is the isolation that matters.
    if wealdrelay::access::store::current(pool(), WS)
        .await
        .expect("read the current access set")
        .prior
        .is_none()
    {
        seed_access_set_with_authorizers(
            state,
            WS,
            std::slice::from_ref(&ada),
            std::slice::from_ref(&ada),
        )
        .await;
    }
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(&group)
        .bind(WS)
        .execute(pool())
        .await
        .expect("the case's own group");

    let epoch = verifier_key(0x21);
    retention::apply_control(pool(), &signed_control(&group, 0, &epoch, None, &epoch))
        .await
        .expect("the genesis control");

    // Every blob uploaded, reserved and put in the bucket, exactly as `BLOB put`
    // followed by a real transfer leaves it.
    let hashes: Vec<Vec<u8>> = (0..count)
        .map(|index| blob_hash_of(&group, index))
        .collect();
    store::ensure_quota_row(pool(), WS, None).await.unwrap();
    for (index, hash) in hashes.iter().enumerate() {
        store::reserve(
            pool(),
            WS,
            &group,
            hash,
            blob_bytes(index) as i64,
            false,
            900,
        )
        .await
        .unwrap();
        storage()
            .put(&key(&group, hash), &vec![index as u8; blob_bytes(index)])
            .await
            .unwrap();
    }

    // The first manifest names all of them, which is what claims them.
    let mut sequence = 1u64;
    let mut previous: Option<Vec<u8>> = None;
    let mut live: Vec<bool> = vec![true; count];
    let mut authorized: Vec<bool> = vec![false; count];
    let mut collected: Vec<bool> = vec![false; count];
    publish(&group, &epoch, &mut sequence, &mut previous, &hashes, &live).await;

    // Their claims are aged past the 30-day floor, so a policy, if this case has
    // one, is actually due rather than merely present.
    sqlx::query(
        "update relay_blob_reservation set finalized_at = now() - interval '40 days' \
         where workspace_id = $1 and group_id = $2",
    )
    .bind(WS)
    .bind(&group)
    .execute(pool())
    .await
    .unwrap();

    if with_policy {
        let policy = signed_policy(&group, 1, 30, NOW / 1000 - 1, std::slice::from_ref(&ada));
        retention::insert_policy(pool(), &policy, "[]")
            .await
            .unwrap();
    }

    check(&group, &hashes, &live, &collected).await?;

    for step in program {
        match step {
            Op::Omit(index) if index < count && live[index] => {
                live[index] = false;
                publish(&group, &epoch, &mut sequence, &mut previous, &hashes, &live).await;
            }
            // A manifest naming a hash the relay has already collected is a client
            // that is wrong about what exists, not an interleaving of this rule,
            // so a restore only applies while the object is still there.
            Op::Restore(index) if index < count && !live[index] && !collected[index] => {
                live[index] = true;
                publish(&group, &epoch, &mut sequence, &mut previous, &hashes, &live).await;
            }
            Op::Authorize(index) if index < count && !authorized[index] => {
                authorized[index] = true;
                let record = signed_destruction(
                    &group,
                    "blob",
                    &hashes[index],
                    NOW / 1000 - 1,
                    std::slice::from_ref(&ada),
                );
                retention::insert_destruction(pool(), &record, "[]")
                    .await
                    .unwrap();
            }
            Op::Sweep => {
                gc::sweep_retention(pool(), storage(), WS, &group, NOW).await;
                for index in 0..count {
                    if !live[index] && (with_policy || authorized[index]) {
                        collected[index] = true;
                    }
                }
            }
            // An op whose precondition does not hold is a no-op rather than a
            // rejected case: rejecting would bias the generated programs towards
            // the shapes that happen to be applicable early.
            _ => {}
        }
        check(&group, &hashes, &live, &collected).await?;
    }
    Ok(())
}

/// One valid manifest naming exactly the blobs currently referenced.
async fn publish(
    group: &[u8],
    epoch: &ed25519_dalek::SigningKey,
    sequence: &mut u64,
    previous: &mut Option<Vec<u8>>,
    hashes: &[Vec<u8>],
    live: &[bool],
) {
    let named: Vec<Vec<u8>> = hashes
        .iter()
        .zip(live)
        .filter(|&(_, live)| *live)
        .map(|(hash, _)| hash.clone())
        .collect();
    let manifest = signed_manifest(group, 0, *sequence, previous.clone(), named, epoch);
    match retention::apply_manifest(pool(), WS, &manifest).await {
        Ok(retention::ManifestOutcome::Accepted { digest }) => {
            *previous = Some(digest);
            *sequence += 1;
        }
        other => panic!("the property's own manifests must be valid: {other:?}"),
    }
}

/// Both directions of the iff, plus the quota arithmetic that has to follow it.
async fn check(
    group: &[u8],
    hashes: &[Vec<u8>],
    live: &[bool],
    collected: &[bool],
) -> Result<(), TestCaseError> {
    for (index, hash) in hashes.iter().enumerate() {
        let present = storage()
            .head(&key(group, hash))
            .await
            .expect("the store answers")
            .is_some();
        prop_assert_eq!(
            present,
            !collected[index],
            "blob {} is {} in storage and the model says collected = {}",
            index,
            if present { "present" } else { "absent" },
            collected[index]
        );
        if live[index] {
            prop_assert!(
                present,
                "blob {} is named by the latest manifest and must never be collected",
                index
            );
        }
    }

    // The relay's own accounting has to agree with what is in the bucket, or the
    // customer is billed for bytes that are not there.
    let expected: i64 = (0..hashes.len())
        .filter(|index| !collected[*index])
        .map(|index| blob_bytes(index) as i64)
        .sum();
    let held = held_bytes(group).await;
    prop_assert_eq!(
        held,
        expected,
        "stored bytes for this group disagree with what survived"
    );
    Ok(())
}

async fn held_bytes(group: &[u8]) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "select coalesce(sum(bytes), 0)::bigint from relay_blob_reservation \
         where workspace_id = $1 and group_id = $2 and finalized_at is not null",
    )
    .bind(WS)
    .bind(group)
    .fetch_one(pool())
    .await
    .unwrap()
}
