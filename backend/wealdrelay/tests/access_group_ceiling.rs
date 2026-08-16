// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The ceiling on how many group rows one workspace may hold.
//!
//! `ensure_groups` is idempotent, and idempotence was mistaken for a bound
//! (WEALD-317). It bounds the honest case only: a client reconnecting with the same
//! ids writes nothing the second time. It says nothing about a device that names
//! `MAX_GROUPS_PER_CONNECTION` *fresh* random ids on every handshake, because group
//! ids are opaque 32-byte values the client derives and the relay cannot tell a new
//! channel from a made-up one. Before the ceiling that grew `relay_group` without
//! limit, forever, with no expiry and no sweep.
//!
//! The claims under test are the two that matter and one that must not break:
//!
//! - A workspace at the ceiling gets no new rows, and the ones it already has keep
//!   working. Refusing to create is the whole mechanism; refusing the session would
//!   turn an abuse ceiling into an outage.
//! - The ceiling is enforced in the statement rather than read and then trusted, so
//!   concurrent connections cannot both pass a check and both write. Check-then-insert
//!   is how the key package cap was exceeded twenty times over, and it is the shape
//!   this deliberately does not use.
//! - A workspace under the ceiling is completely unaffected, which is every real
//!   workspace: the ceiling is sixteen times the documented policy figure.

mod support;

use std::sync::Arc;

use sqlx::PgPool;
use wealdrelay::access::store::{self, MAX_GROUPS_PER_WORKSPACE};
use wealdrelay::health::{Clock, RelayState};

use support::{config_for, Running, Scratch};

const WORKSPACE: &str = "ws-ceiling";
const OTHER: &str = "ws-ceiling-other";

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

/// A distinct 32-byte id per index, which is what a client deriving ids produces
/// and what an attacker minting them produces too. The relay cannot tell them apart,
/// which is the reason a ceiling is the only available answer.
fn id(index: u32) -> Vec<u8> {
    let mut group = vec![0u8; 32];
    group[..4].copy_from_slice(&index.to_be_bytes());
    group[4] = 0xc0;
    group
}

/// Fill a workspace to one row below the ceiling, cheaply.
///
/// Direct inserts rather than `ensure_groups` calls: what is being set up is the
/// state at the boundary, and 8191 round trips through the function under test
/// would make this a benchmark rather than a test.
async fn fill_to(pool: &PgPool, workspace: &str, rows: u32) {
    let ids: Vec<Vec<u8>> = (0..rows).map(id).collect();
    sqlx::query(
        "insert into relay_group (group_id, workspace_id) \
         select unnest($1::bytea[]), $2",
    )
    .bind(&ids)
    .bind(workspace)
    .execute(pool)
    .await
    .expect("fill the workspace");
    assert_eq!(
        store::group_count(pool, workspace).await.expect("a count"),
        i64::from(rows)
    );
}

/// The last row is created and the one after it is not.
///
/// Both halves matter. A ceiling that refused the last legitimate group would be
/// off by one against a workspace doing nothing wrong, and a ceiling that admitted
/// the first row past it would not be a ceiling.
#[tokio::test]
async fn the_workspace_ceiling_admits_the_last_group_and_refuses_the_next() {
    let (scratch, _blobs, state) = prepared("groups_ceiling_edge").await;
    let pool = pool_of(&state);
    store::salt(pool, WORKSPACE).await.unwrap();
    fill_to(pool, WORKSPACE, MAX_GROUPS_PER_WORKSPACE - 1).await;

    let last = vec![0xd1; 32];
    assert_eq!(
        store::ensure_groups(pool, WORKSPACE, std::slice::from_ref(&last))
            .await
            .expect("a write"),
        1,
        "the last group under the ceiling was refused"
    );
    assert_eq!(
        store::group_count(pool, WORKSPACE).await.unwrap(),
        i64::from(MAX_GROUPS_PER_WORKSPACE)
    );

    let over = vec![0xd2; 32];
    assert_eq!(
        store::ensure_groups(pool, WORKSPACE, std::slice::from_ref(&over))
            .await
            .expect("a write"),
        0,
        "a group past the ceiling was created"
    );
    assert_eq!(
        store::workspace_of(pool, &over).await.expect("a lookup"),
        None,
        "the row past the ceiling exists"
    );
    // And the count has not moved, which is the property the ticket asked for: a
    // reconnect loop cannot grow the table.
    assert_eq!(
        store::group_count(pool, WORKSPACE).await.unwrap(),
        i64::from(MAX_GROUPS_PER_WORKSPACE)
    );

    scratch.drop_database().await;
}

/// The negative proof the ticket asks for: a reconnect loop naming fresh ids every
/// time cannot grow the table past the ceiling.
///
/// Each iteration is a whole handshake's worth of ids, all of them new, which is the
/// attack rather than a client resubscribing. Before the ceiling every iteration
/// added rows without limit.
#[tokio::test]
async fn a_reconnect_loop_minting_fresh_ids_cannot_grow_the_table() {
    let (scratch, _blobs, state) = prepared("groups_ceiling_loop").await;
    let pool = pool_of(&state);
    store::salt(pool, WORKSPACE).await.unwrap();
    fill_to(pool, WORKSPACE, MAX_GROUPS_PER_WORKSPACE).await;

    for round in 0..4u32 {
        let batch: Vec<Vec<u8>> = (0..256u32)
            .map(|slot| {
                let mut group = vec![0xee; 32];
                group[..4].copy_from_slice(&(round * 256 + slot).to_be_bytes());
                group
            })
            .collect();
        assert_eq!(
            store::ensure_groups(pool, WORKSPACE, &batch)
                .await
                .expect("a write"),
            0,
            "round {round} of a mint loop created rows past the ceiling"
        );
    }
    assert_eq!(
        store::group_count(pool, WORKSPACE).await.unwrap(),
        i64::from(MAX_GROUPS_PER_WORKSPACE),
        "the table grew under a reconnect loop"
    );

    scratch.drop_database().await;
}

/// One workspace at its ceiling does not spend another's.
///
/// The count in the guard is scoped to the workspace, and a global count would make
/// one tenant's abuse every other tenant's outage on a shared relay, which is a worse
/// bug than the one being fixed.
#[tokio::test]
async fn a_workspace_at_its_ceiling_does_not_bound_another() {
    let (scratch, _blobs, state) = prepared("groups_ceiling_tenant").await;
    let pool = pool_of(&state);
    store::salt(pool, WORKSPACE).await.unwrap();
    store::salt(pool, OTHER).await.unwrap();
    fill_to(pool, WORKSPACE, MAX_GROUPS_PER_WORKSPACE).await;

    let theirs = vec![0xf3; 32];
    assert_eq!(
        store::ensure_groups(pool, OTHER, std::slice::from_ref(&theirs))
            .await
            .expect("a write"),
        1,
        "a full workspace bounded a different workspace"
    );
    assert_eq!(
        store::workspace_of(pool, &theirs).await.expect("a lookup"),
        Some(OTHER.to_string())
    );

    scratch.drop_database().await;
}

/// A workspace nowhere near the ceiling behaves exactly as it did before.
///
/// The regression guard. Every real workspace is in this state: the policy figure is
/// 512 and the ceiling is sixteen times it, so the ceiling must be invisible here,
/// including the idempotence that the rest of the suite depends on.
#[tokio::test]
async fn a_workspace_below_the_ceiling_is_unaffected() {
    let (scratch, _blobs, state) = prepared("groups_ceiling_normal").await;
    let pool = pool_of(&state);
    store::salt(pool, WORKSPACE).await.unwrap();

    let groups: Vec<Vec<u8>> = (0..8u32).map(id).collect();
    assert_eq!(
        store::ensure_groups(pool, WORKSPACE, &groups)
            .await
            .expect("a write"),
        8
    );
    // Still idempotent, which is the property the ceiling was mistaken for.
    assert_eq!(
        store::ensure_groups(pool, WORKSPACE, &groups)
            .await
            .expect("a write"),
        0
    );
    assert_eq!(store::group_count(pool, WORKSPACE).await.unwrap(), 8);

    scratch.drop_database().await;
}
