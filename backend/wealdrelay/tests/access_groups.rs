// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Where a group row comes from.
//!
//! Until 2026-08-04 the answer was "`scripts/weald-stack provision`, with `psql`",
//! which is a thing a laptop can do and a hosted customer cannot. Step 20's launch
//! gate went looking for the production path and found there was none: nothing in
//! the relay ever wrote a `relay_group` row, so a provisioned relay could complete
//! enrolment and then answer `denied/group_unknown` to every subscription its own
//! founder made, permanently.
//!
//! `access::store::ensure_groups` is the answer and this suite is its boundary. The
//! claim under test is not "groups get created" but the narrow shape of who may
//! create one, because the objection the old rule raised is real and is what the
//! bound exists for: a stranger with a socket must not be able to allocate storage
//! on somebody else's plan.
//!
//! - A device the workspace's current access set carries, naming a group with no
//!   row, gets it created under that workspace.
//! - A device holding only a provisional grant does not. A joiner mid-redemption is
//!   the one principal that is admitted without the set naming it, and it is
//!   excluded deliberately.
//! - The founding device's groups are created by the publication that admits it,
//!   which is the only moment they can be: the reservation that resolves the
//!   workspace is destroyed by that same publication.
//! - A group id already belonging to another workspace is left where it is.
//! - A group id that is not 32 bytes is skipped rather than sent, so a malformed
//!   `CONNECT` cannot turn a session into `retry/backpressure`.

mod support;

use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey};
use sqlx::PgPool;
use wealdrelay::access::store::{self, StoreError};
use wealdrelay::access::AccessSet;
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::invite::{genesis, reserve};

use support::{config_for, Running, Scratch};

const WORKSPACE: &str = "ws-groups";
const OTHER: &str = "ws-groups-other";
/// Wall-clock milliseconds, for the fixtures whose rows are filtered by SQL
/// `now()` rather than by an injected clock.
///
/// `specs/backend/build/testing.md` forbids a wall-clock read inside anything
/// under test, and the relay honours that: every expiry the relay owns is
/// evaluated against its own injected clock, which is why `prepared` starts it at
/// `Clock::Fixed(1)`. Two expiries are not the relay's. A provisional grant's and
/// a bootstrap reservation's both live in Postgres and are compared against the
/// *database's* clock by `expires_at > now()` (`access::store::admission`,
/// `invite::genesis::founding_workspace`).
///
/// This suite first wrote a frozen 2023 into those columns, which is already
/// expired the moment it lands, so two fixtures silently produced the refusal
/// they were written to prove the absence of: `Verdict::Refused` for what should
/// have been a live grant, and `Published::UnknownGroup` for a founding set.
/// Nothing was wrong with the relay; the fixture was asserting against a clock
/// the query does not read.
///
/// So a real clock here, deliberately and narrowly, and only for a value handed
/// to Postgres. The alternative is a database whose `now()` is injectable, which
/// is a much larger change than these rows justify. Nothing in this suite is
/// timing-sensitive: every expiry it writes is ten minutes out, so a slow machine
/// cannot change an answer.
fn wall_clock_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_millis() as i64
}

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

/// One set against a live salt, so its entries are the hashes `AUTH` will compute.
fn build(salt: &[u8], members: &[&SigningKey], authorizers: &[&SigningKey]) -> AccessSet {
    let hash = |signer: &SigningKey| wealdrelay::access::entry_hash(&pk(signer), salt);
    let mut entries: Vec<Vec<u8>> = members.iter().map(|k| hash(k)).collect();
    entries.extend(authorizers.iter().map(|k| hash(k)));
    AccessSet {
        workspace: vec![0x77; 32],
        version: 0,
        prev_hash: vec![0u8; 32],
        issued_at: 1,
        entries: sorted(entries),
        authorizers: sorted(authorizers.iter().map(|k| pk(k)).collect()),
        recovery: sorted(authorizers.iter().map(|k| pk(k)).collect()),
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

async fn register(pool: &PgPool, workspace: &str, group: &[u8]) {
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(group)
        .bind(workspace)
        .execute(pool)
        .await
        .expect("register a group");
}

async fn owner_of(pool: &PgPool, group: &[u8]) -> Option<String> {
    store::workspace_of(pool, group).await.expect("a lookup")
}

// MARK: The member's path

/// The ordinary case, and the one the hosted tier could not do at all: a member
/// names a group nobody has registered, and the relay records it as theirs.
///
/// The connection also names a group that already exists, because that is what a
/// real `CONNECT` looks like after the first channel: the workspace is resolved
/// from the known one and the unknown one is created beside it.
#[tokio::test]
async fn a_member_naming_a_new_group_gets_it_created_under_their_workspace() {
    let (scratch, _blobs, state) = prepared("groups_member").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    let root = vec![0x11; 32];
    let fresh = vec![0x12; 32];
    register(pool, WORKSPACE, &root).await;

    let member = key(1);
    let set = sign(build(&salt, &[], &[&member]), &member);
    store::publish(pool, WORKSPACE, &set, &set.encode())
        .await
        .expect("the genesis set");

    assert_eq!(
        owner_of(pool, &fresh).await,
        None,
        "the fixture is not clean"
    );
    let verdict = store::admission(pool, &[root.clone(), fresh.clone()], &pk(&member))
        .await
        .expect("a verdict");
    assert!(
        matches!(verdict, store::Verdict::Admitted { .. }),
        "a member of the set was not admitted: {verdict:?}"
    );
    assert_eq!(
        owner_of(pool, &fresh).await.as_deref(),
        Some(WORKSPACE),
        "the member's new group was not created"
    );

    scratch.drop_database().await;
}

/// The bound. A joiner holding a provisional grant is admitted, and creates nothing.
///
/// This is the one principal the relay admits without the accepted set naming it,
/// which makes it the one principal that could mint groups without a member ever
/// agreeing. `ensure_groups` is called from the `InSet` arm only, and this is the
/// test that keeps it there.
#[tokio::test]
async fn a_provisionally_granted_joiner_creates_nothing() {
    let (scratch, _blobs, state) = prepared("groups_provisional").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    let root = vec![0x21; 32];
    let fresh = vec![0x22; 32];
    register(pool, WORKSPACE, &root).await;

    let member = key(1);
    let set = sign(build(&salt, &[], &[&member]), &member);
    store::publish(pool, WORKSPACE, &set, &set.encode())
        .await
        .expect("the genesis set");

    let joiner = key(9);
    let hash = wealdrelay::access::entry_hash(&pk(&joiner), &salt);
    // Ten minutes into the future by the database's clock, because that is the
    // clock `admission` compares this column against. See `wall_clock_ms`.
    store::grant(pool, WORKSPACE, &hash, wall_clock_ms() + 600_000)
        .await
        .expect("a grant");

    let verdict = store::admission(pool, &[root.clone(), fresh.clone()], &pk(&joiner))
        .await
        .expect("a verdict");
    assert!(
        matches!(verdict, store::Verdict::Admitted { .. }),
        "a live provisional grant must still admit: {verdict:?}"
    );
    assert_eq!(
        owner_of(pool, &fresh).await,
        None,
        "a joiner mid-redemption allocated a group"
    );

    scratch.drop_database().await;
}

/// A device the set does not carry is refused, and leaves nothing behind.
///
/// The refusal was already proven elsewhere; what is proven here is that the
/// refused path did not write first. A relay that created the row and then said no
/// would have handed a stranger the storage anyway.
#[tokio::test]
async fn a_stranger_is_refused_and_allocates_nothing() {
    let (scratch, _blobs, state) = prepared("groups_stranger").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    let root = vec![0x31; 32];
    let fresh = vec![0x32; 32];
    register(pool, WORKSPACE, &root).await;

    let member = key(1);
    let set = sign(build(&salt, &[], &[&member]), &member);
    store::publish(pool, WORKSPACE, &set, &set.encode())
        .await
        .expect("the genesis set");

    assert_eq!(
        store::admission(pool, &[root, fresh.clone()], &pk(&key(0x5a)))
            .await
            .expect("a verdict"),
        store::Verdict::Refused
    );
    assert_eq!(
        owner_of(pool, &fresh).await,
        None,
        "a refused device left a group row behind"
    );

    scratch.drop_database().await;
}

// MARK: The founder's path

/// The founding publication creates the workspace's first groups.
///
/// It has to happen here and nowhere else. The genesis fallback resolves the
/// workspace from the device's live bootstrap reservation, and accepting the set
/// consumes that reservation and destroys the genesis key. A founder that
/// reconnected afterwards would name groups with no rows, resolve no workspace, and
/// be answered `denied/group_unknown` for ever: the workspace would be sealed shut
/// by its own successful enrolment.
#[tokio::test]
async fn the_founding_publication_creates_the_workspaces_first_groups() {
    let (scratch, _blobs, state) = prepared("groups_genesis").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    let root = vec![0x41; 32];

    let run = match genesis::ensure(pool, WORKSPACE, wall_clock_ms())
        .await
        .expect("mints")
    {
        genesis::Ensured::Minted(run) => run,
        other => panic!("a fresh relay mints, got {other:?}"),
    };
    let founder = key(3);
    let device_hash = wealdrelay::access::entry_hash(&pk(&founder), &salt);
    assert!(
        matches!(
            reserve::reserve(
                pool,
                &run.token,
                &run.code.grouped(),
                &[0x41; 16],
                &device_hash,
                // Salted and hashed, as `ws.rs` does before it ever calls this.
                // Migration 0012 re-keyed the attempt counter on (token, source)
                // and constrains the source to 32 bytes, so a raw string here is
                // refused by the database rather than counted against anyone.
                &reserve::source_hash("203.0.113.7", &salt),
                wall_clock_ms(),
            )
            .await
            .expect("a reservation"),
            reserve::Verdict::Reserved { .. }
        ),
        "the fixture must hold the bootstrap seat"
    );

    let set = sign(build(&salt, &[], &[&founder]), &founder);
    let published = store::publish_for(pool, std::slice::from_ref(&root), &set, &set.encode())
        .await
        .expect("a verdict");
    assert!(
        matches!(published, store::Published::Accepted(_)),
        "the founding set was refused: {published:?}"
    );
    assert_eq!(
        owner_of(pool, &root).await.as_deref(),
        Some(WORKSPACE),
        "the founder's own group was not created by the publication that admitted it"
    );

    // And the whole point of doing it there: the founder can come back. The
    // reservation is spent, so the only thing that can resolve the workspace now is
    // the row the publication wrote.
    assert!(
        matches!(
            store::admission(pool, &[root], &pk(&founder))
                .await
                .expect("a verdict"),
            store::Verdict::Admitted { .. }
        ),
        "the founder could not reconnect to the workspace it founded"
    );

    scratch.drop_database().await;
}

// MARK: The edges of ensure_groups itself

/// A group id belonging to another workspace is left where it is.
///
/// `on conflict (group_id) do nothing` rather than an upsert, so naming somebody
/// else's group id is not a way to take it. The device is then refused by
/// `ws::authorize_group` exactly as it was before, which is the behaviour this
/// assertion protects.
#[tokio::test]
async fn a_group_that_belongs_to_another_workspace_is_not_moved() {
    let (scratch, _blobs, state) = prepared("groups_no_theft").await;
    let pool = pool_of(&state);
    store::salt(pool, WORKSPACE).await.unwrap();
    store::salt(pool, OTHER).await.unwrap();
    let theirs = vec![0x51; 32];
    register(pool, OTHER, &theirs).await;

    assert_eq!(
        store::ensure_groups(pool, WORKSPACE, std::slice::from_ref(&theirs))
            .await
            .expect("a write"),
        0,
        "an existing group was counted as created"
    );
    assert_eq!(
        owner_of(pool, &theirs).await.as_deref(),
        Some(OTHER),
        "one workspace took another's group id"
    );

    scratch.drop_database().await;
}

/// Idempotent, and quiet about a group id that is not 32 bytes.
///
/// The length is a check constraint on the table, so sending a short one would come
/// back as a database error and be reported to the client as `retry/backpressure`:
/// a malformed `CONNECT` would read as a relay having a bad day. Filtered instead,
/// which leaves the group uncreated and the eventual answer `denied/group_unknown`,
/// which is what it is.
#[tokio::test]
async fn a_second_call_writes_nothing_and_a_malformed_id_is_skipped() {
    let (scratch, _blobs, state) = prepared("groups_idempotent").await;
    let pool = pool_of(&state);
    store::salt(pool, WORKSPACE).await.unwrap();
    let good = vec![0x61; 32];
    let short = vec![0x62; 8];
    let long = vec![0x63; 33];

    assert_eq!(
        store::ensure_groups(
            pool,
            WORKSPACE,
            &[good.clone(), short.clone(), long.clone()]
        )
        .await
        .expect("a write"),
        1,
        "exactly one of the three is a group id"
    );
    assert_eq!(owner_of(pool, &good).await.as_deref(), Some(WORKSPACE));
    assert_eq!(owner_of(pool, &short).await, None);
    assert_eq!(owner_of(pool, &long).await, None);

    assert_eq!(
        store::ensure_groups(pool, WORKSPACE, std::slice::from_ref(&good))
            .await
            .expect("a write"),
        0,
        "a second call created the group again"
    );

    scratch.drop_database().await;
}

/// A relay that cannot write says come back, rather than reporting nothing created.
///
/// The two are opposite instructions to the caller: zero created is a fact about a
/// database that answered, and this is a database that did not. `admission` carries
/// the error out with `?`, so a member whose group could not be written is told to
/// retry rather than admitted into a workspace whose group is missing.
#[tokio::test]
async fn a_write_that_cannot_run_is_reported_rather_than_counted() {
    let (scratch, _blobs, state) = prepared("groups_fault").await;
    let pool = pool_of(&state);
    store::salt(pool, WORKSPACE).await.unwrap();

    sqlx::query("alter table relay_group rename to weald_parked")
        .execute(pool)
        .await
        .expect("park the group table");
    assert!(
        matches!(
            store::ensure_groups(pool, WORKSPACE, &[vec![0x71; 32]]).await,
            Err(StoreError::Database(_))
        ),
        "a write that could not run was reported as nothing to do"
    );
    sqlx::query("alter table weald_parked rename to relay_group")
        .execute(pool)
        .await
        .expect("restore the group table");

    scratch.drop_database().await;
}

/// A squatted group id does not decide which workspace a connection is judged in.
///
/// Group ids are client-derived and travel in invite `scopes`, so a member of one
/// workspace can name an id another workspace is about to create, and the
/// conflict-blind insert binds that row to the squatter. Resolving the connection
/// from the first named group with a row then handed the squatter a second, larger
/// win: the victim's own device, naming the squatted id alongside its own groups,
/// resolved into the squatter's workspace, was not in that access set, and was
/// refused for the entire session rather than for the one group.
///
/// So resolution prefers a named workspace that actually carries this device. The
/// squatted row is still not moved, because an opaque 32-byte id carries no proof
/// of who derived it and a blind relay cannot adjudicate that; the group stays
/// refused, and the rest of the session works.
#[tokio::test]
async fn a_squatted_group_id_does_not_capture_the_victims_session() {
    let (scratch, _blobs, state) = prepared("groups_squat").await;
    let pool = pool_of(&state);
    let victim_salt = store::salt(pool, WORKSPACE).await.unwrap();
    store::salt(pool, OTHER).await.unwrap();

    // The victim's own group, and the id the squatter got there first with. The
    // squatted one is named first, which is the ordering the old resolution lost on.
    let mine = vec![0x71; 32];
    let squatted = vec![0x72; 32];
    register(pool, WORKSPACE, &mine).await;
    register(pool, OTHER, &squatted).await;

    let member = key(4);
    let set = sign(build(&victim_salt, &[], &[&member]), &member);
    store::publish(pool, WORKSPACE, &set, &set.encode())
        .await
        .expect("the genesis set");

    let verdict = store::admission(pool, &[squatted.clone(), mine.clone()], &pk(&member))
        .await
        .expect("a verdict");
    match verdict {
        store::Verdict::Admitted { workspace, .. } => assert_eq!(
            workspace, WORKSPACE,
            "a squatted id chose the workspace the victim was judged in"
        ),
        other => panic!("the victim was locked out of its own workspace: {other:?}"),
    }

    // And nothing was taken back either: the squatted row stays where it is, so the
    // one group remains refused rather than silently rebound.
    assert_eq!(
        owner_of(pool, &squatted).await.as_deref(),
        Some(OTHER),
        "resolution rebound a group id it cannot prove ownership of"
    );

    scratch.drop_database().await;
}

/// WEALD-L161. `relay_group` rows exist before genesis on every provisioned relay,
/// so a workspace resolved from a group id alone is a workspace anyone who knows
/// that id can name. A `Bootstrap` verdict is one `ACCESS` frame away from being
/// the workspace's trust root, so it belongs only to the device holding the live,
/// unconsumed reservation on that workspace's bootstrap invite.
#[tokio::test]
async fn a_provisioned_group_with_no_set_does_not_bootstrap_a_stranger() {
    let (scratch, _blobs, state) = prepared("groups_bootstrap_stranger").await;
    let pool = pool_of(&state);
    let provisioned = vec![0x71; 32];
    register(pool, WORKSPACE, &provisioned).await;

    // No access set for this workspace and no reservation for this device: the
    // exact state of a freshly provisioned relay whose founder has not published.
    assert_eq!(
        store::admission(pool, std::slice::from_ref(&provisioned), &pk(&key(0x6c)))
            .await
            .expect("a verdict"),
        store::Verdict::Refused,
        "a stranger naming a provisioned group id was offered the trust root"
    );

    scratch.drop_database().await;
}
