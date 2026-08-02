// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The access set against real Postgres: the transaction, the chain, and the one
//! question `AUTH` asks.
//!
//! Step 6's integration half. Nothing here is mocked and nothing here is skipped:
//! the harness Postgres is the database, the migrations are the ones the binary
//! embeds, and the compare-and-swap is proven by two writers racing rather than by
//! reading the SQL.
//!
//! The rules themselves are in `tests/access.rs`. What is here is everything that
//! needs rows: that a published set becomes the prior state of the next one, that a
//! concurrent publication of the same version loses, that a removed principal stops
//! being admitted, and that a provisional grant dies exactly when the three rules
//! say it does.

mod support;

use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey};
use sqlx::{PgPool, Row as _};
use wealdrelay::access::store::{self, Admission, StoreError};
use wealdrelay::access::{AccessError, AccessSet, QuorumSignature, RecoveryQuorum, SignedAs};
use wealdrelay::health::{Clock, RelayState};

use support::{config_for, Running, Scratch};

const WORKSPACE: &str = "ws-access";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pk(signer: &SigningKey) -> Vec<u8> {
    signer.verifying_key().to_bytes().to_vec()
}

fn sorted(mut items: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    items.sort();
    items.dedup();
    items
}

/// A relay with a database and nothing else running. `serve::prepare` rather than a
/// bare pool, because the migrations are the binary's and a suite that created its
/// own tables would be testing its own schema.
async fn prepared(label: &str) -> (Scratch, tempfile::TempDir, Arc<RelayState>) {
    let scratch = Scratch::new(label).await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(1)).await;
    let state = Arc::clone(&relay.state);
    // The listener is not needed by this suite, so it is stopped and the state kept.
    relay.shutdown().await;
    (scratch, blobs, state)
}

fn pool_of(state: &Arc<RelayState>) -> &PgPool {
    state.database.as_ref().expect("a database").pool()
}

/// One set, built against a live salt so its entries are the hashes this relay will
/// compute at `AUTH`.
fn build(
    salt: &[u8],
    version: u64,
    prev_hash: Vec<u8>,
    members: &[&SigningKey],
    authorizers: &[&SigningKey],
    recovery: &[&SigningKey],
) -> AccessSet {
    let hash = |signer: &SigningKey| wealdrelay::access::entry_hash(&pk(signer), salt);
    let mut entries: Vec<Vec<u8>> = members.iter().map(|k| hash(k)).collect();
    entries.extend(authorizers.iter().map(|k| hash(k)));
    entries.extend(recovery.iter().map(|k| hash(k)));
    AccessSet {
        workspace: vec![0x77; 32],
        version,
        prev_hash,
        issued_at: 1,
        entries: sorted(entries),
        authorizers: sorted(authorizers.iter().map(|k| pk(k)).collect()),
        recovery: sorted(recovery.iter().map(|k| pk(k)).collect()),
        quorum: None,
        pending: Vec::new(),
        signer: vec![0u8; 32],
        sig: vec![0u8; 64],
    }
}

fn sign(mut set: AccessSet, signer: &SigningKey) -> AccessSet {
    set.signer = pk(signer);
    set.sig = signer.sign(&set.digest_input()).to_bytes().to_vec();
    set
}

async fn publish(pool: &PgPool, set: &AccessSet) -> Result<store::Accepted, StoreError> {
    store::publish(pool, WORKSPACE, set, &set.encode()).await
}

// MARK: The salt

#[tokio::test]
async fn a_workspace_salt_is_created_once_and_never_changes() {
    let (scratch, _blobs, state) = prepared("salt").await;
    let pool = pool_of(&state);
    let first = store::salt(pool, WORKSPACE).await.unwrap();
    let again = store::salt(pool, WORKSPACE).await.unwrap();
    assert_eq!(first, again, "a second read invented a new salt");
    assert_eq!(first.len(), 32);
    // A different workspace gets a different salt, which is the whole point: a
    // stolen set is not linkable against key material seen elsewhere.
    let other = store::salt(pool, "ws-other").await.unwrap();
    assert_ne!(first, other);
    scratch.drop_database().await;
}

// MARK: The chain

#[tokio::test]
async fn a_published_set_becomes_the_state_the_next_one_is_judged_against() {
    let (scratch, _blobs, state) = prepared("chain").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();

    // Nothing published: no prior, no probation, and the salt.
    let empty = store::current(pool, WORKSPACE).await.unwrap();
    assert!(empty.prior.is_none());
    assert!(empty.probations.is_empty());
    assert_eq!(empty.salt, salt);

    let genesis = sign(
        build(&salt, 0, vec![0u8; 32], &[], &[&key(1)], &[&key(0x3f)]),
        &key(1),
    );
    let accepted = publish(pool, &genesis).await.unwrap();
    assert_eq!(accepted.version, 0);
    assert_eq!(accepted.digest, genesis.digest().to_vec());
    assert_eq!(accepted.signed_as, SignedAs::Authorizer);
    assert!(accepted.disconnect.is_empty());
    assert!(accepted.opened_probation.is_none());
    assert!(accepted.cleared_probation.is_empty());

    // Read back: the version, the digest, the entries and both principal lists.
    let current = store::current(pool, WORKSPACE).await.unwrap();
    let prior = current.prior.expect("a prior set");
    assert_eq!(prior.version, 0);
    assert_eq!(prior.digest, genesis.digest().to_vec());
    assert_eq!(prior.entries, genesis.entries);
    assert_eq!(prior.authorizers, genesis.authorizers);
    assert_eq!(prior.recovery, genesis.recovery);
    assert!(prior.quorum.is_none());

    // And the next publication follows it.
    let second = sign(
        build(
            &salt,
            1,
            prior.digest.clone(),
            &[&key(5)],
            &[&key(1)],
            &[&key(0x3f)],
        ),
        &key(1),
    );
    assert_eq!(publish(pool, &second).await.unwrap().version, 1);
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_registered_quorum_is_stored_and_read_back_without_its_signatures() {
    let (scratch, _blobs, state) = prepared("quorum").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    let mut set = build(&salt, 0, vec![0u8; 32], &[], &[&key(1)], &[&key(0x3f)]);
    set.quorum = Some(RecoveryQuorum {
        threshold: 2,
        keys: sorted(vec![pk(&key(0x81)), pk(&key(0x82))]),
        // Carried on the wire and never stored: a confirmation belongs to one
        // transition and is not part of the state that transition produced.
        sigs: vec![QuorumSignature {
            key: pk(&key(0x81)),
            sig: vec![0u8; 64],
        }],
    });
    let set = sign(set, &key(1));
    publish(pool, &set).await.unwrap();

    let stored = store::current(pool, WORKSPACE)
        .await
        .unwrap()
        .prior
        .unwrap()
        .quorum
        .expect("a stored quorum");
    assert_eq!(stored.threshold, 2);
    assert_eq!(stored.keys, sorted(vec![pk(&key(0x81)), pk(&key(0x82))]));
    assert!(stored.sigs.is_empty());
    scratch.drop_database().await;
}

#[tokio::test]
async fn two_publications_of_one_version_do_not_both_win() {
    // The compare-and-swap, proven by racing rather than by reading the SQL. Both
    // candidates are valid against the same prior state, which is exactly the case a
    // check-then-insert would let through twice.
    let (scratch, _blobs, state) = prepared("cas").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    let genesis = sign(
        build(&salt, 0, vec![0u8; 32], &[], &[&key(1)], &[&key(0x3f)]),
        &key(1),
    );
    publish(pool, &genesis).await.unwrap();
    let prior = genesis.digest().to_vec();

    let one = sign(
        build(
            &salt,
            1,
            prior.clone(),
            &[&key(5)],
            &[&key(1)],
            &[&key(0x3f)],
        ),
        &key(1),
    );
    let two = sign(
        build(
            &salt,
            1,
            prior.clone(),
            &[&key(6)],
            &[&key(1)],
            &[&key(0x3f)],
        ),
        &key(1),
    );
    let (first, second) = tokio::join!(publish(pool, &one), publish(pool, &two));
    let winners = [&first, &second].iter().filter(|r| r.is_ok()).count();
    assert_eq!(winners, 1, "both publications of version 1 were accepted");
    let loser = if first.is_err() { first } else { second };
    match loser {
        Err(StoreError::Refused(AccessError::VersionNotNext { .. })) => {}
        other => panic!("the loser must be told to replay, got {other:?}"),
    }

    // One row, and the head is version 1.
    let rows: i64 = sqlx::query_scalar("select count(*) from relay_access_set")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(rows, 2, "genesis plus exactly one version 1");
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_refused_publication_writes_nothing() {
    let (scratch, _blobs, state) = prepared("refused").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    // Signed by a key that is in no list.
    let stranger = sign(
        build(&salt, 0, vec![0u8; 32], &[], &[&key(1)], &[&key(0x3f)]),
        &key(9),
    );
    assert!(matches!(
        publish(pool, &stranger).await,
        Err(StoreError::Refused(AccessError::SignerNotPermitted))
    ));
    let rows: i64 = sqlx::query_scalar("select count(*) from relay_access_set")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
    scratch.drop_database().await;
}

// MARK: The rotation, its rate limit and its probation

#[tokio::test]
async fn a_rotation_opens_a_probation_and_counts_against_the_window() {
    let (scratch, _blobs, state) = prepared("rotate").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    let genesis = sign(
        build(
            &salt,
            0,
            vec![0u8; 32],
            &[&key(5)],
            &[&key(1)],
            &[&key(0x3f)],
        ),
        &key(1),
    );
    publish(pool, &genesis).await.unwrap();

    assert!(!store::rotated_recently(pool, WORKSPACE, &pk(&key(0x3f)))
        .await
        .unwrap());

    let hash = |signer: &SigningKey| wealdrelay::access::entry_hash(&pk(signer), &salt);
    let mut rotation = build(
        &salt,
        1,
        genesis.digest().to_vec(),
        &[&key(5)],
        &[&key(1), &key(7)],
        &[&key(0x4f)],
    );
    rotation.pending = vec![hash(&key(5))];
    let rotation = sign(rotation, &key(0x3f));
    let accepted = publish(pool, &rotation).await.unwrap();
    assert_eq!(accepted.signed_as, SignedAs::Recovery);
    assert_eq!(accepted.opened_probation, Some(pk(&key(7))));
    assert_eq!(accepted.disconnect, vec![hash(&key(0x3f))]);

    // The probation is readable, with what it pinned.
    let current = store::current(pool, WORKSPACE).await.unwrap();
    assert_eq!(current.probations.len(), 1);
    assert_eq!(current.probations[0].device, pk(&key(7)));
    assert_eq!(current.probations[0].introduced_at, 1);
    assert_eq!(current.probations[0].pending, vec![hash(&key(5))]);

    // The rate limit is now against this principal, and it is recorded even though
    // the principal's key has already been rotated out.
    assert!(store::rotated_recently(pool, WORKSPACE, &pk(&key(0x3f)))
        .await
        .unwrap());
    assert!(!store::rotated_recently(pool, WORKSPACE, &pk(&key(0x4f)))
        .await
        .unwrap());

    // A second rotation by the same principal is refused on the window, whatever
    // else is true of it. It cannot be published from the same prior state anyway,
    // so the check is made against the state that would otherwise permit it.
    let prior = store::current(pool, WORKSPACE)
        .await
        .unwrap()
        .prior
        .unwrap();
    let mut again = build(
        &salt,
        prior.version + 1,
        prior.digest.clone(),
        &[&key(5)],
        &[&key(1), &key(7), &key(8)],
        &[&key(0x4f)],
    );
    again.entries = sorted(
        prior
            .entries
            .iter()
            .cloned()
            .chain([hash(&key(8))])
            .collect(),
    );
    let again = sign(again, &key(0x3f));
    // `0x3f` is no longer a recovery principal, so it is refused on membership: the
    // rotate-on-use rule takes the key out of the set that could use it.
    assert!(matches!(
        publish(pool, &again).await,
        Err(StoreError::Refused(AccessError::SignerNotPermitted))
    ));
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_probation_is_cleared_by_the_publication_that_confirms_it() {
    let (scratch, _blobs, state) = prepared("clear").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    let genesis = sign(
        build(
            &salt,
            0,
            vec![0u8; 32],
            &[&key(5)],
            &[&key(1)],
            &[&key(0x3f)],
        ),
        &key(1),
    );
    publish(pool, &genesis).await.unwrap();
    let rotation = sign(
        build(
            &salt,
            1,
            genesis.digest().to_vec(),
            &[&key(5)],
            &[&key(1), &key(7)],
            &[&key(0x4f)],
        ),
        &key(0x3f),
    );
    publish(pool, &rotation).await.unwrap();

    let confirm = sign(
        build(
            &salt,
            2,
            rotation.digest().to_vec(),
            &[&key(5)],
            &[&key(1), &key(7)],
            &[&key(0x4f)],
        ),
        &key(1),
    );
    let accepted = publish(pool, &confirm).await.unwrap();
    assert_eq!(accepted.cleared_probation, vec![pk(&key(7))]);

    // Cleared rather than deleted: the transparency log names the rotation that
    // created the probation and the publication that ended it.
    let current = store::current(pool, WORKSPACE).await.unwrap();
    assert!(current.probations.is_empty(), "still on probation");
    let cleared: i64 =
        sqlx::query_scalar("select cleared_version from relay_access_probation where device = $1")
            .bind(pk(&key(7)))
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(cleared, 2);
    scratch.drop_database().await;
}

// MARK: What AUTH asks

#[tokio::test]
async fn admission_follows_the_newest_set_and_nothing_older() {
    let (scratch, _blobs, state) = prepared("admits").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();

    // Before any set: refused, and no reason beyond the code.
    assert_eq!(
        store::admits(pool, WORKSPACE, &pk(&key(5))).await.unwrap(),
        Admission::Refused
    );

    let genesis = sign(
        build(
            &salt,
            0,
            vec![0u8; 32],
            &[&key(5)],
            &[&key(1)],
            &[&key(0x3f)],
        ),
        &key(1),
    );
    publish(pool, &genesis).await.unwrap();
    assert_eq!(
        store::admits(pool, WORKSPACE, &pk(&key(5))).await.unwrap(),
        Admission::InSet
    );
    assert_eq!(
        store::admits(pool, WORKSPACE, &pk(&key(9))).await.unwrap(),
        Admission::Refused
    );

    // Removed in the next version. The older version still carries the hash, and
    // admission must follow the newest set only: reading any version would make
    // revocation cosmetic.
    let second = sign(
        build(
            &salt,
            1,
            genesis.digest().to_vec(),
            &[],
            &[&key(1)],
            &[&key(0x3f)],
        ),
        &key(1),
    );
    publish(pool, &second).await.unwrap();
    assert_eq!(
        store::admits(pool, WORKSPACE, &pk(&key(5))).await.unwrap(),
        Admission::Refused
    );
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_provisional_grant_dies_by_expiry_by_revocation_and_by_being_superseded() {
    let (scratch, _blobs, state) = prepared("grants").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    let hash = |signer: &SigningKey| wealdrelay::access::entry_hash(&pk(signer), &salt);
    let genesis = sign(
        build(&salt, 0, vec![0u8; 32], &[], &[&key(1)], &[&key(0x3f)]),
        &key(1),
    );
    publish(pool, &genesis).await.unwrap();

    let joiner = key(0x21);
    let hour_ahead = 1_000i64 * 60 * 60 * 24 * 365 * 100;

    // A live grant admits, and says which of the two ways it was admitted, because
    // the two have different lifetimes.
    store::grant(pool, WORKSPACE, &hash(&joiner), hour_ahead)
        .await
        .unwrap();
    assert_eq!(
        store::admits(pool, WORKSPACE, &pk(&joiner)).await.unwrap(),
        Admission::Provisional
    );

    // Expiry, in relay time. A grant is bounded at birth and never renewable.
    store::grant(pool, WORKSPACE, &hash(&joiner), 1_000)
        .await
        .unwrap();
    assert_eq!(
        store::admits(pool, WORKSPACE, &pk(&joiner)).await.unwrap(),
        Admission::Refused
    );

    // Revocation, explicitly. The second attempt reports that there was nothing left
    // to void, so a caller can tell a revocation from a no-op.
    store::grant(pool, WORKSPACE, &hash(&joiner), hour_ahead)
        .await
        .unwrap();
    assert!(store::revoke_grant(pool, WORKSPACE, &hash(&joiner))
        .await
        .unwrap());
    assert!(!store::revoke_grant(pool, WORKSPACE, &hash(&joiner))
        .await
        .unwrap());
    assert_eq!(
        store::admits(pool, WORKSPACE, &pk(&joiner)).await.unwrap(),
        Admission::Refused
    );

    // Superseded, implicitly, and only after having been seen. A set that has not
    // caught up with the joiner must not void the grant.
    store::grant(pool, WORKSPACE, &hash(&joiner), hour_ahead)
        .await
        .unwrap();
    let without = sign(
        build(
            &salt,
            1,
            genesis.digest().to_vec(),
            &[],
            &[&key(1)],
            &[&key(0x3f)],
        ),
        &key(1),
    );
    publish(pool, &without).await.unwrap();
    assert_eq!(
        store::admits(pool, WORKSPACE, &pk(&joiner)).await.unwrap(),
        Admission::Provisional,
        "a set that never carried the joiner voided their grant"
    );

    // Now a set that carries them, and then one that does not.
    let carried = sign(
        build(
            &salt,
            2,
            without.digest().to_vec(),
            &[&joiner],
            &[&key(1)],
            &[&key(0x3f)],
        ),
        &key(1),
    );
    publish(pool, &carried).await.unwrap();
    assert_eq!(
        store::admits(pool, WORKSPACE, &pk(&joiner)).await.unwrap(),
        Admission::InSet
    );
    let dropped = sign(
        build(
            &salt,
            3,
            carried.digest().to_vec(),
            &[],
            &[&key(1)],
            &[&key(0x3f)],
        ),
        &key(1),
    );
    publish(pool, &dropped).await.unwrap();
    assert_eq!(
        store::admits(pool, WORKSPACE, &pk(&joiner)).await.unwrap(),
        Admission::Refused
    );
    let reason: String = sqlx::query_scalar(
        "select voided_reason from relay_provisional_grant where device_hash = $1",
    )
    .bind(hash(&joiner))
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(reason, "superseded");
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_group_names_its_workspace_and_an_unknown_group_names_none() {
    let (scratch, _blobs, state) = prepared("workspaceof").await;
    let pool = pool_of(&state);
    store::salt(pool, WORKSPACE).await.unwrap();
    let group = vec![0x71; 32];
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(&group)
        .bind(WORKSPACE)
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(
        store::workspace_of(pool, &group).await.unwrap().as_deref(),
        Some(WORKSPACE)
    );
    assert_eq!(store::workspace_of(pool, &[0x72; 32]).await.unwrap(), None);
    scratch.drop_database().await;
}

// MARK: The property

#[tokio::test]
async fn exactly_the_currently_authorised_principals_are_admitted() {
    // Step 6's property gate: "for any sequence of grants and revocations, exactly
    // the currently authorized principals can open a socket". Randomised over both
    // mechanisms at once, because the two interact: a grant is voided implicitly by
    // a publication, and a publication's removals are the other half of offboarding.
    //
    // Seeded, so a failure is reproducible from one number rather than being a story
    // about a run nobody can repeat.
    let (scratch, _blobs, state) = prepared("property").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    let hash = |signer: &SigningKey| wealdrelay::access::entry_hash(&pk(signer), &salt);

    let mut seed = 20_260_729u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    let pool_of_devices: Vec<SigningKey> = (0x30..0x38).map(key).collect();
    let genesis = sign(
        build(&salt, 0, vec![0u8; 32], &[], &[&key(1)], &[&key(0x3f)]),
        &key(1),
    );
    publish(pool, &genesis).await.unwrap();

    // The model: who the set names, and who holds a live grant. Kept as plain sets
    // here, so what the database answers is compared against a statement of the rule
    // rather than against another query.
    let mut in_set: Vec<u8> = Vec::new();
    let mut granted: Vec<u8> = Vec::new();
    let mut seen: Vec<u8> = Vec::new();
    let mut head = genesis.clone();
    let mut publications = 0usize;
    let mut grants = 0usize;
    let mut revocations = 0usize;

    for _ in 0..40 {
        match next() % 3 {
            // Publish a set naming a random subset of the pool.
            0 => {
                let mut members: Vec<u8> = Vec::new();
                for device in &pool_of_devices {
                    if next() % 2 == 0 {
                        members.push(device.to_bytes()[0]);
                    }
                }
                let keys: Vec<SigningKey> = members.iter().map(|seed| key(*seed)).collect();
                let candidate = sign(
                    build(
                        &salt,
                        head.version + 1,
                        head.digest().to_vec(),
                        &keys.iter().collect::<Vec<_>>(),
                        &[&key(1)],
                        &[&key(0x3f)],
                    ),
                    &key(1),
                );
                publish(pool, &candidate).await.unwrap();
                head = candidate;
                in_set = members.clone();
                // The implicit-void rule, modelled: a granted device the set carried
                // once and does not carry now is void.
                for device in members.iter() {
                    if granted.contains(device) && !seen.contains(device) {
                        seen.push(*device);
                    }
                }
                granted.retain(|device| !(seen.contains(device) && !members.contains(device)));
                publications += 1;
            }
            // Grant one device provisionally.
            1 => {
                let device =
                    pool_of_devices[(next() as usize) % pool_of_devices.len()].to_bytes()[0];
                store::grant(
                    pool,
                    WORKSPACE,
                    &hash(&key(device)),
                    1_000i64 * 60 * 60 * 24 * 365 * 100,
                )
                .await
                .unwrap();
                if !granted.contains(&device) {
                    granted.push(device);
                }
                // A re-granted device starts over: `grant` clears the void.
                seen.retain(|held| held != &device);
                grants += 1;
            }
            // Revoke one.
            _ => {
                let device =
                    pool_of_devices[(next() as usize) % pool_of_devices.len()].to_bytes()[0];
                store::revoke_grant(pool, WORKSPACE, &hash(&key(device)))
                    .await
                    .unwrap();
                granted.retain(|held| held != &device);
                seen.retain(|held| held != &device);
                revocations += 1;
            }
        }

        // The property, over the whole pool every round: admitted exactly when the
        // newest set carries the device or a live grant does, and never otherwise.
        for device in &pool_of_devices {
            let seed = device.to_bytes()[0];
            let expected = if in_set.contains(&seed) {
                Admission::InSet
            } else if granted.contains(&seed) {
                Admission::Provisional
            } else {
                Admission::Refused
            };
            assert_eq!(
                store::admits(pool, WORKSPACE, &pk(device)).await.unwrap(),
                expected,
                "device {seed:#04x} after {publications} publications, {grants} grants, \
                 {revocations} revocations"
            );
        }
    }
    assert!(
        publications > 0 && grants > 0 && revocations > 0,
        "the sequence exercised {publications} publications, {grants} grants, \
         {revocations} revocations"
    );
    scratch.drop_database().await;
}

// MARK: The dump

#[tokio::test]
async fn the_access_tables_hold_salted_hashes_and_the_keys_they_must_verify_and_nothing_else() {
    // Step 6's artifact: "the access set table dump showing salted hashes and nothing
    // else". Written to `build-evidence/step-06/` rather than only asserted, because
    // what the relay learns from these tables is a claim, and a claim with no dump
    // behind it is a promise.
    //
    // What is legitimately clear here, and why: `relay_access_principal` holds
    // authorizer, recovery and quorum pubkeys, because the relay verifies signatures
    // by them and a hash cannot do that. Every *member* is a hash. That distinction is
    // the whole of the blindness claim for this table set, so the test asserts it in
    // both directions: no member key appears anywhere, and the principal keys that do
    // appear are exactly the ones the set named as signers.
    let (scratch, _blobs, state) = prepared("dump").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    let member = key(0x5c);
    let genesis = sign(
        build(
            &salt,
            0,
            vec![0u8; 32],
            &[&member],
            &[&key(1)],
            &[&key(0x3f)],
        ),
        &key(1),
    );
    publish(pool, &genesis).await.unwrap();
    store::grant(
        pool,
        WORKSPACE,
        &wealdrelay::access::entry_hash(&pk(&key(0x21)), &salt),
        1_000i64 * 60 * 60 * 24 * 365 * 100,
    )
    .await
    .unwrap();

    let mut dump = String::from(
        "step 6, the access set as the relay holds it\n\
         every row of every access table for one workspace, after a genesis publication\n\
         and one provisional grant\n\n",
    );
    for table in [
        "relay_workspace",
        "relay_access_set",
        "relay_access_entry",
        "relay_access_principal",
        "relay_access_quorum",
        "relay_access_probation",
        "relay_recovery_rotation",
        "relay_provisional_grant",
    ] {
        dump.push_str(&format!("--- {table}\n"));
        let rows = sqlx::query(&format!(
            "select row_to_json(t)::text as row from {table} t order by 1"
        ))
        .fetch_all(pool)
        .await
        .unwrap();
        if rows.is_empty() {
            dump.push_str("(no rows)\n");
        }
        for row in rows {
            let text: String = row.try_get("row").unwrap();
            dump.push_str(&text);
            dump.push('\n');
        }
        dump.push('\n');
    }

    // No member key, anywhere. The member is in the set as a hash and the relay never
    // saw the key at all until that device connects, at which point it hashes what was
    // presented rather than storing it.
    let member_hex = hex(&pk(&member));
    assert!(
        !dump.to_lowercase().contains(&member_hex),
        "a member pubkey is in the dump"
    );
    // The joiner's key is not there either: a grant carries no more than an entry does.
    assert!(!dump.to_lowercase().contains(&hex(&pk(&key(0x21)))));
    // The signer keys are there, and that is the design rather than a leak.
    assert!(dump.to_lowercase().contains(&hex(&pk(&key(1)))));
    assert!(dump.to_lowercase().contains(&hex(&pk(&key(0x3f)))));
    // And the body of the publication is stored byte for byte, which is what makes the
    // signature checkable by anyone reading the table. It carries the same clear signer
    // keys and no others.
    let bodies: i64 = sqlx::query_scalar("select count(*) from relay_access_set where body <> ''")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(bodies, 1);

    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build-evidence/step-06");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("access-set-dump.txt"), &dump).unwrap();

    scratch.drop_database().await;
}

/// Lowercase hex, for the one place a dump is searched for a key.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A publication that names no group this relay knows, and is not a genesis.
///
/// The genesis fallback in `publish_for` is deliberately narrow: one authorizer,
/// holding a live bootstrap reservation. This is the other side of that condition,
/// and it matters because the fallback is the only path that can publish into a
/// workspace without naming one of its groups. A set with two authorizers is a
/// rotation of an established workspace, and a rotation whose groups this relay does
/// not know is a rotation for somebody else's relay.
#[tokio::test]
async fn a_publication_with_no_known_group_and_two_authorizers_is_refused() {
    let (scratch, _blobs, state) = prepared("publish_two_authorizers").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.expect("a salt");

    let first = key(1);
    let second = key(2);
    let mut set = build(
        &salt,
        0,
        vec![0u8; 32],
        &[&first, &second],
        &[&first, &second],
        &[&first],
    );
    set.sig = first.sign(&set.digest_input()).to_bytes().to_vec();
    assert_eq!(
        set.authorizers.len(),
        2,
        "the fixture must name two authorizers"
    );

    assert_eq!(
        store::publish_for(pool, &[vec![0xAA; 32]], &set, &set.encode())
            .await
            .expect("a verdict"),
        store::Published::UnknownGroup,
        "a two-authorizer set reached a workspace it never named"
    );

    scratch.drop_database().await;
}

/// The genesis lookups both paths make, when the lookup itself cannot run.
///
/// `publish_for` and `admission` each fall back to "is this device founding a
/// workspace" when the connection names no group they know. A relay whose genesis
/// table it cannot read must say so rather than answer the fallback's negative,
/// because the two mean opposite things to a joiner: come back, or you are nobody.
#[tokio::test]
async fn a_genesis_lookup_that_cannot_run_is_reported_by_both_paths() {
    let (scratch, _blobs, state) = prepared("genesis_lookup_fault").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.expect("a salt");
    let first = key(1);
    let set = build(&salt, 0, vec![0u8; 32], &[&first], &[&first], &[&first]);

    sqlx::query("alter table relay_genesis rename to weald_parked")
        .execute(pool)
        .await
        .expect("park the genesis table");

    assert!(
        matches!(
            store::publish_for(pool, &[vec![0xAB; 32]], &set, &set.encode()).await,
            Err(store::StoreError::Database(_))
        ),
        "a publication whose genesis lookup failed was answered as an unknown group"
    );
    assert!(
        matches!(
            store::admission(pool, &[vec![0xAB; 32]], &pk(&first)).await,
            Err(store::StoreError::Database(_))
        ),
        "an admission whose genesis lookup failed was answered as an unknown group"
    );

    sqlx::query("alter table weald_parked rename to relay_genesis")
        .execute(pool)
        .await
        .expect("restore the genesis table");
    scratch.drop_database().await;
}
