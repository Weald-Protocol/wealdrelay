// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The key-package shelf against real Postgres.
//!
//! One claim here is worth more than the rest, and it is the reason the fetch is
//! a single statement: **a package is never served twice.** Serving the same one
//! to two callers would hand two different private conversations the same joiner
//! leaf key, which is the failure this shelf exists to prevent. It is asserted
//! across concurrent interleavings rather than argued for in a comment.

mod support;

use std::collections::HashSet;

use wealdrelay::keys::{store, MAX_OUTSTANDING};

use support::{config_for, default_device, other_device, Running, Scratch};
use wealdrelay::health::Clock;

const CLOCK: u64 = 1_700_000_000_000;
const WORKSPACE: &str = "acme";

async fn pool(relay: &Running) -> &sqlx::PgPool {
    relay.state.database.as_ref().expect("a database").pool()
}

fn key_bytes(device: &ed25519_dalek::SigningKey) -> Vec<u8> {
    use ed25519_dalek::VerifyingKey;
    let verifying: VerifyingKey = device.verifying_key();
    verifying.to_bytes().to_vec()
}

fn package(seed: u8) -> Vec<u8> {
    vec![seed; 48]
}

#[tokio::test(flavor = "multi_thread")]
async fn publishing_fills_the_shelf_the_auth_ack_has_been_counting_since_step_5() {
    let scratch = Scratch::new("keys_publish").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let pool = pool(&relay).await;
    let device = key_bytes(&default_device());

    let published = store::publish(pool, WORKSPACE, &device, &[package(1), package(2)])
        .await
        .expect("publish");
    assert_eq!(published, store::Published::Stored { remaining: 2 });

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fetch_consumes_and_the_same_package_is_never_served_twice() {
    let scratch = Scratch::new("keys_one_time").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let pool = pool(&relay).await;
    let device = key_bytes(&default_device());

    let packages: Vec<Vec<u8>> = (0..16).map(package).collect();
    store::publish(pool, WORKSPACE, &device, &packages)
        .await
        .expect("publish");

    // Eight concurrent fetchers of two each, which is exactly the shelf. Every
    // package must come out once and no package twice, whatever order the
    // statements interleave in.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let pool = pool.clone();
        let device = device.clone();
        handles.push(tokio::spawn(async move {
            store::fetch(&pool, WORKSPACE, &device, 2)
                .await
                .expect("fetch")
        }));
    }
    let mut served: Vec<Vec<u8>> = Vec::new();
    for handle in handles {
        served.extend(handle.await.expect("join"));
    }
    let distinct: HashSet<Vec<u8>> = served.iter().cloned().collect();
    assert_eq!(
        served.len(),
        distinct.len(),
        "a key package was served twice, which would hand two dm groups one joiner leaf key"
    );
    assert_eq!(served.len(), 16, "the whole shelf should have been served");

    // And the shelf is empty afterwards, which is not an error.
    assert!(store::fetch(pool, WORKSPACE, &device, 1)
        .await
        .expect("fetch")
        .is_empty());

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn over_the_cap_stores_nothing_rather_than_evicting_the_oldest() {
    // A silent discard would produce an unaddable member with no error anywhere:
    // the publisher believes it has a shelf, and the first person to open a
    // conversation with it finds nothing and is told nothing.
    let scratch = Scratch::new("keys_cap").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let pool = pool(&relay).await;
    let device = key_bytes(&default_device());

    let full: Vec<Vec<u8>> = (0..MAX_OUTSTANDING)
        .map(|index| vec![u8::try_from(index % 251).unwrap_or(0); 48])
        .collect();
    assert_eq!(
        store::publish(pool, WORKSPACE, &device, &full)
            .await
            .expect("publish"),
        store::Published::Stored {
            remaining: u32::try_from(MAX_OUTSTANDING).unwrap()
        }
    );
    assert_eq!(
        store::publish(pool, WORKSPACE, &device, &[package(200)])
            .await
            .expect("publish"),
        store::Published::OverCap
    );
    // Nothing was taken, so the shelf still holds exactly the cap.
    let served = store::fetch(pool, WORKSPACE, &device, 8)
        .await
        .expect("fetch");
    assert_eq!(served.len(), 8);

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn one_devices_shelf_is_not_anothers() {
    let scratch = Scratch::new("keys_per_device").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let pool = pool(&relay).await;
    let ada = key_bytes(&default_device());
    let bo = key_bytes(&other_device());

    store::publish(pool, WORKSPACE, &ada, &[package(1)])
        .await
        .expect("publish");
    assert!(
        store::fetch(pool, WORKSPACE, &bo, 1)
            .await
            .expect("fetch")
            .is_empty(),
        "one device's fetch drew from another's shelf"
    );
    assert_eq!(
        store::fetch(pool, WORKSPACE, &ada, 1)
            .await
            .expect("fetch")
            .len(),
        1
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn one_workspaces_shelf_is_not_anothers() {
    // The membership half of the same rule. A device key is global and a shelf is
    // not: a fetch scoped only by device would let a member of one workspace draw
    // down a shelf published in another.
    let scratch = Scratch::new("keys_per_workspace").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let pool = pool(&relay).await;
    let device = key_bytes(&default_device());

    store::publish(pool, WORKSPACE, &device, &[package(1)])
        .await
        .expect("publish");
    assert!(store::fetch(pool, "other", &device, 1)
        .await
        .expect("fetch")
        .is_empty());

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_shelf_is_an_answer_and_not_an_error() {
    let scratch = Scratch::new("keys_empty").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let pool = pool(&relay).await;

    // The correct client behaviour is to wait for the peer to top up rather than
    // to retry, and an error here would invite exactly the retry loop that drains
    // a shelf.
    let served = store::fetch(pool, WORKSPACE, &key_bytes(&default_device()), 4)
        .await
        .expect("an empty shelf is not a failure");
    assert!(served.is_empty());

    relay.shutdown().await;
    scratch.drop_database().await;
}

/// WEALD-314. The cap was a count followed by a loop of inserts on the pool, so
/// two `KEYS/Publish` frames for one device both read the same shelf depth, both
/// found room, and both stored: the hundred-outstanding bound in `wire.md` held
/// only for a publisher that never used two connections. The publication is now
/// one transaction under an advisory lock on the shelf, so one of the two racers
/// is `OverCap` and the shelf never exceeds the cap.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_publications_cannot_take_one_shelf_over_the_cap() {
    let scratch = Scratch::new("keys_cap_race").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let pool = pool(&relay).await;
    let device = key_bytes(&default_device());

    // Two publications that each fit on their own and cannot both fit.
    let half = usize::try_from(MAX_OUTSTANDING).unwrap() / 2 + 1;
    let batch = |offset: u8| -> Vec<Vec<u8>> {
        (0..half)
            .map(|index| vec![offset.wrapping_add(u8::try_from(index % 251).unwrap_or(0)); 48])
            .collect()
    };

    let (one, two) = (batch(0), batch(128));
    let (first, second) = tokio::join!(
        store::publish(pool, WORKSPACE, &device, &one),
        store::publish(pool, WORKSPACE, &device, &two),
    );
    let outcomes = [first.expect("publish"), second.expect("publish")];
    assert!(
        outcomes.contains(&store::Published::OverCap),
        "one of two racing publications must be refused, got {outcomes:?}"
    );

    // And the shelf itself is within the cap, which is the claim the wire bound
    // makes and the one a count-then-insert could not keep.
    let depth: i64 = sqlx::query_scalar(
        "select count(*) from relay_key_package \
         where workspace_id = $1 and consumed_at is null and expires_at > now()",
    )
    .bind(WORKSPACE)
    .fetch_one(pool)
    .await
    .expect("count");
    assert!(
        depth <= MAX_OUTSTANDING,
        "the shelf holds {depth}, over the {MAX_OUTSTANDING} cap"
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

/// WEALD-L150. The fetch consumes in the statement that selects, so a package
/// whose answer never reaches the socket is destroyed. The shelf is finite and a
/// peer can repeat the fetch, so an undelivered answer must be put back.
#[tokio::test(flavor = "multi_thread")]
async fn an_undelivered_fetch_is_restored_to_the_shelf() {
    let scratch = Scratch::new("keys_restore").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let pool = pool(&relay).await;
    let device = key_bytes(&default_device());

    store::publish(pool, WORKSPACE, &device, &[package(1), package(2)])
        .await
        .expect("publish");

    let served = store::fetch_served(pool, WORKSPACE, &device, 2)
        .await
        .expect("fetch");
    assert_eq!(served.len(), 2);
    assert!(store::fetch(pool, WORKSPACE, &device, 2)
        .await
        .expect("fetch")
        .is_empty());

    store::restore(pool, WORKSPACE, &served)
        .await
        .expect("restore");
    let again = store::fetch_served(pool, WORKSPACE, &device, 2)
        .await
        .expect("fetch");
    assert_eq!(again.len(), 2, "a restored shelf is servable again");
    let recovered: HashSet<Vec<u8>> = again.into_iter().map(|s| s.package).collect();
    assert_eq!(
        recovered,
        HashSet::from([package(1), package(2)]),
        "the same packages come back, not new ones"
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

/// WEALD-L155. A handed-out package is deleted, not marked. The module's own
/// contract says the relay deletes what it hands out, and the rows are cleartext
/// leaf key material, so a row surviving the handout is retention the module
/// says does not happen. Asserted on the table, not on `outstanding`, which
/// counts only live rows and so cannot see the leak.
#[tokio::test(flavor = "multi_thread")]
async fn a_served_package_leaves_no_row_behind() {
    let scratch = Scratch::new("keys_delete_on_handout").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let pool = pool(&relay).await;
    let device = key_bytes(&default_device());

    store::publish(pool, WORKSPACE, &device, &[package(3), package(4)])
        .await
        .expect("publish");
    let served = store::fetch(pool, WORKSPACE, &device, 2)
        .await
        .expect("fetch");
    assert_eq!(served.len(), 2);

    let rows: i64 = sqlx::query_scalar(
        "select count(*) from relay_key_package where workspace_id = $1 and device_hash = $2",
    )
    .bind(WORKSPACE)
    .bind(blake3::hash(&device).as_bytes().to_vec())
    .fetch_one(pool)
    .await
    .expect("count");
    assert_eq!(rows, 0, "a served package is deleted, not left consumed");

    relay.shutdown().await;
    scratch.drop_database().await;
}

/// WEALD-L155. Nothing swept expired packages either, so a shelf that was never
/// fetched from grew forever. One collector pass removes them.
#[tokio::test(flavor = "multi_thread")]
async fn one_collector_pass_removes_an_expired_package() {
    let scratch = Scratch::new("keys_sweep_expired").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let pool = pool(&relay).await;
    let device = key_bytes(&other_device());

    sqlx::query(
        // `created_at` is set too: the schema checks `expires_at > created_at`, so a
        // row that expired yesterday must have been created before that.
        "insert into relay_key_package (workspace_id, device_hash, package, created_at, expires_at) \
         values ($1, $2, $3, now() - interval '3 days', now() - interval '1 day')",
    )
    .bind(WORKSPACE)
    .bind(blake3::hash(&device).as_bytes().to_vec())
    .bind(package(9))
    .execute(pool)
    .await
    .expect("insert expired");

    let dropped = store::sweep_expired(pool).await.expect("sweep");
    assert!(dropped >= 1, "the expired package is swept");
    let rows: i64 = sqlx::query_scalar("select count(*) from relay_key_package")
        .fetch_one(pool)
        .await
        .expect("count");
    assert_eq!(rows, 0);

    relay.shutdown().await;
    scratch.drop_database().await;
}
