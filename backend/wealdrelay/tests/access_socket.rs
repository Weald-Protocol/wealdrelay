// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `ACCESS` over a real socket, and what a publication does to other people's
//! sockets.
//!
//! Step 6's integration and negative proofs from `specs/backend/build/phases-relay.md`.
//! The pure rules are `tests/access.rs` and the transaction is `tests/access_store.rs`;
//! what only a relay can prove is here: that a genesis set can be published by the
//! one connection a workspace has before it has a set, that a revocation closes the
//! revoked device's socket rather than waiting for it to reconnect, and that a device
//! admitted minutes earlier on a live invite is cut off by the same publication.
//!
//! The timings this suite measures are written to `build-evidence/step-06/`, because
//! "a revoked device's socket closes within seconds" is a number and a number nobody
//! wrote down is not evidence.

mod support;

use std::time::{Duration, Instant};

use ed25519_dalek::{Signer as _, SigningKey};
use sqlx::{Connection as _, Executor as _};
use wealdrelay::access::{self, store, AccessSet};
use wealdrelay::frame::{ErrorCode, Frame, PROTOCOL_VERSION};
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::invite::{genesis, reserve};

use support::{
    config_for, default_device, device_from, envelope_for, other_device, Client, Running, Scratch,
};

const CLOCK: u64 = 1_700_000_000_000;
const WORKSPACE: &str = "ws-step6";

fn pk(signer: &SigningKey) -> Vec<u8> {
    signer.verifying_key().to_bytes().to_vec()
}

fn sorted(mut items: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    items.sort();
    items.dedup();
    items
}

/// Hold this workspace's one bootstrap seat for `device`, as a real joiner does.
///
/// The bootstrap hole is one frame wide and it is also one *device* wide. A
/// workspace with no access set is not an open door: `relay_group` rows exist
/// before genesis on every provisioned relay, so resolving a workspace from a
/// group id alone would let anyone who learned that id become its trust root.
/// `access::store::admission` therefore answers `Bootstrap` only to the device
/// holding the live, unconsumed reservation on the genesis invite
/// (`invite::genesis::founding_workspace`).
///
/// These tests predate that narrowing and used to reach the hole by knowing a
/// group id, which is exactly what it now refuses, so each of them mints genesis
/// and takes the seat first. That is not a workaround: it is the sequence a real
/// first client performs, and going through it is what makes the rest of the
/// assertion about the socket rather than about an admission nobody could get.
/// The reservation's expiry is written against the database's own `now()`
/// (`genesis::founding_workspace` filters on `r.expires_at > now()`), so the
/// mint and the reservation take the real clock and not this suite's fixed
/// `CLOCK`. `CLOCK` is 2023 and every reservation stamped with it is already
/// expired before it is read, which is a fixture that grants no seat at all.
/// Nothing timing-sensitive rests on it: the expiry is ten minutes out.
fn wall_clock_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_millis() as i64
}

async fn hold_bootstrap_seat(state: &std::sync::Arc<RelayState>, device: &SigningKey) {
    let pool = state.database.as_ref().expect("a database").pool();
    let salt = store::salt(pool, WORKSPACE)
        .await
        .expect("a workspace salt");
    let run = match genesis::ensure(pool, WORKSPACE, wall_clock_ms())
        .await
        .expect("mints the genesis invite")
    {
        genesis::Ensured::Minted(run) => run,
        other => panic!("a fresh relay mints, got {other:?}"),
    };
    let reserved = reserve::reserve(
        pool,
        &run.token,
        &run.code.grouped(),
        &[0x41; 16],
        &access::entry_hash(&pk(device), &salt),
        // Salted and hashed, as `ws.rs` does before it ever calls this: migration
        // 0012 re-keyed the attempt counter on the source and constrains it to 32
        // bytes, so a raw string is refused by the database.
        &reserve::source_hash("203.0.113.7", &salt),
        wall_clock_ms(),
    )
    .await
    .expect("a reservation");
    assert!(
        matches!(reserved, reserve::Verdict::Reserved { .. }),
        "the fixture must hold the bootstrap seat, got {reserved:?}"
    );
}

/// A group in a workspace with no access set: the state every workspace starts in.
async fn bare_group(state: &std::sync::Arc<RelayState>, byte: u8) -> Vec<u8> {
    let group = vec![byte; 32];
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(&group)
        .bind(WORKSPACE)
        .execute(state.database.as_ref().expect("a database").pool())
        .await
        .expect("create the group");
    group
}

/// A set naming these devices, signed by the first of them, against the live salt.
fn set_for(
    salt: &[u8],
    version: u64,
    prev_hash: Vec<u8>,
    devices: &[&SigningKey],
    signer: &SigningKey,
) -> AccessSet {
    let recovery = device_from(0x3f);
    let mut entries: Vec<Vec<u8>> = devices
        .iter()
        .map(|device| access::entry_hash(&pk(device), salt))
        .collect();
    entries.push(access::entry_hash(&pk(&recovery), salt));
    let mut set = AccessSet {
        workspace: vec![0x77; 32],
        version,
        prev_hash,
        issued_at: CLOCK,
        entries: sorted(entries),
        authorizers: vec![pk(&default_device())],
        recovery: vec![pk(&recovery)],
        quorum: None,
        pending: Vec::new(),
        signer: pk(signer),
        sig: vec![0u8; 64],
    };
    set.sig = signer.sign(&set.digest_input()).to_bytes().to_vec();
    set
}

async fn salt_of(state: &std::sync::Arc<RelayState>) -> Vec<u8> {
    store::salt(
        state.database.as_ref().expect("a database").pool(),
        WORKSPACE,
    )
    .await
    .expect("a workspace salt")
}

fn evidence(name: &str, body: &str) {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build-evidence/step-06");
    std::fs::create_dir_all(&directory).expect("the evidence directory");
    std::fs::write(directory.join(name), body).expect("write the evidence");
}

// MARK: The bootstrap hole, and how narrow it is

#[tokio::test(flavor = "multi_thread")]
async fn a_workspace_publishes_its_genesis_set_over_the_one_socket_it_can_open() {
    // The first connection a workspace ever takes has no set to be checked against.
    // Refusing it would make the workspace unreachable forever, so it is admitted to
    // exactly one frame.
    let scratch = Scratch::new("bootstrap").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = bare_group(&relay.state, 0x81).await;
    let salt = salt_of(&relay.state).await;
    hold_bootstrap_seat(&relay.state, &default_device()).await;

    // Knowing a group id is not a way in, and this is the assertion that says so.
    //
    // The hole this test is named for used to be exactly one frame wide and open
    // to anyone who could name a group of a workspace with no set. That was too
    // wide: `relay_group` rows exist before genesis on every provisioned relay, so
    // a stranger who learned an id could have become the workspace's trust root.
    // `access::store::admission` now answers a device that holds no seat on the
    // genesis invite with the refusal a stranger gets, and the session ends there
    // rather than being admitted to a frame.
    let mut stranger = Client::connect(relay.address).await;
    let challenge = stranger
        .handshake_to_challenge(vec![group.clone()], CLOCK)
        .await;
    let outsider = device_from(0x5c);
    stranger
        .send_frame(&Frame::Auth {
            device_key: pk(&outsider),
            signature: outsider.sign(&challenge).to_bytes().to_vec(),
        })
        .await;
    match stranger.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(
        stranger.recv().await.is_none(),
        "a device that cannot be admitted must not keep the socket"
    );

    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], CLOCK).await;

    // The genesis set, published over that one frame.
    let genesis = set_for(
        &salt,
        0,
        vec![0u8; 32],
        &[&default_device()],
        &default_device(),
    );
    client
        .send_frame(&Frame::Access {
            body: genesis.encode(),
        })
        .await;
    match client.recv_frame().await {
        // Answered with the accepted digest, so the client knows what its next
        // publication must name without a second round trip.
        Frame::Access { body } => assert_eq!(body, genesis.digest().to_vec()),
        other => panic!("expected an Access answer, got {other:?}"),
    }

    // And now the workspace works: a new connection authenticates against the set
    // and may write.
    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], CLOCK).await;
    let envelope = envelope_for(&group, b"after the genesis set");
    client
        .send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::SendAck { seq, .. } => assert_eq!(seq, 1),
        other => panic!("expected a SendAck, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

/// The founding publication also registers the groups the founder named.
///
/// WEALD-L304. A workspace's groups are created by its trust root, so at the moment
/// the genesis set is published there is no row for any of them, and `AUTH` has
/// already bound the workspace it admitted this session into. The publication
/// therefore takes the workspace-resolved path, which used to write the set and
/// nothing else: the founder reconnected, named its own root group, and was answered
/// `denied/group_unknown` for ever, with the genesis key destroyed and no second
/// invite to be had.
///
/// Asserted through the socket and then through the database, because the failure was
/// invisible from the publishing session: it was accepted, and the workspace was dead.
#[tokio::test(flavor = "multi_thread")]
async fn the_founding_publication_registers_the_groups_the_founder_named() {
    let scratch = Scratch::new("founding_groups").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let salt = salt_of(&relay.state).await;
    hold_bootstrap_seat(&relay.state, &default_device()).await;
    // No row for this id, which is the real founding state: the trust root has not
    // been admitted, so it has not made a group yet.
    let root = vec![0x9au8; 32];
    let pool = relay.state.database.as_ref().expect("a database").pool();
    let held: i64 = sqlx::query_scalar("select count(*) from relay_group where group_id = $1")
        .bind(&root)
        .fetch_one(pool)
        .await
        .expect("count the group rows");
    assert_eq!(held, 0, "the founder's group must not exist before genesis");

    let mut founder = Client::connect(relay.address).await;
    founder.handshake(vec![root.clone()], CLOCK).await;
    let genesis = set_for(
        &salt,
        0,
        vec![0u8; 32],
        &[&default_device()],
        &default_device(),
    );
    founder
        .send_frame(&Frame::Access {
            body: genesis.encode(),
        })
        .await;
    match founder.recv_frame().await {
        Frame::Access { body } => assert_eq!(body, genesis.digest().to_vec()),
        other => panic!("expected an Access answer, got {other:?}"),
    }

    let registered: i64 = sqlx::query_scalar(
        "select count(*) from relay_group where group_id = $1 and workspace_id = $2",
    )
    .bind(&root)
    .bind(WORKSPACE)
    .fetch_one(pool)
    .await
    .expect("count the group rows");
    assert_eq!(
        registered, 1,
        "the founding publication must register the group the founder named"
    );

    // The whole point of the row: the founder can come back and write.
    let mut again = Client::connect(relay.address).await;
    again.handshake(vec![root.clone()], CLOCK).await;
    let envelope = envelope_for(&root, b"the founder came back");
    again
        .send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
    match again.recv_frame().await {
        Frame::SendAck { seq, .. } => assert_eq!(seq, 1),
        other => panic!("expected a SendAck, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_the_set_does_not_name_cannot_open_a_socket() {
    // The negative proof for `AUTH`. Before step 6 this handshake succeeded with a
    // made-up key and 64 bytes of nothing.
    let scratch = Scratch::new("stranger").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = bare_group(&relay.state, 0x82).await;
    let salt = salt_of(&relay.state).await;
    store::publish(
        relay.state.database.as_ref().unwrap().pool(),
        WORKSPACE,
        &set_for(
            &salt,
            0,
            vec![0u8; 32],
            &[&default_device()],
            &default_device(),
        ),
        &set_for(
            &salt,
            0,
            vec![0u8; 32],
            &[&default_device()],
            &default_device(),
        )
        .encode(),
    )
    .await
    .expect("the genesis set");

    // A key in no list, with a signature that verifies over the challenge. Possession
    // is proven and membership is not, which is the case the old check could not
    // tell from a member.
    let stranger = device_from(0x99);
    let mut client = Client::connect(relay.address).await;
    let challenge = client
        .handshake_to_challenge(vec![group.clone()], CLOCK)
        .await;
    client
        .send_frame(&Frame::Auth {
            device_key: pk(&stranger),
            signature: stranger.sign(&challenge).to_bytes().to_vec(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::WriterNotInAccessSet);
            assert_eq!(error.code.qualified(), "denied/writer_not_in_access_set");
        }
        other => panic!("expected a denial, got {other:?}"),
    }
    // And the socket ends: a peer that cannot prove membership has nothing else to
    // say, and leaving it open would let it keep guessing.
    assert!(
        client.recv().await.is_none(),
        "the relay left a refused connection open"
    );

    // A member key with a signature over somebody else's challenge is refused too,
    // on possession rather than on membership.
    let mut client = Client::connect(relay.address).await;
    client
        .handshake_to_challenge(vec![group.clone()], CLOCK)
        .await;
    client
        .send_frame(&Frame::Auth {
            device_key: pk(&default_device()),
            signature: default_device()
                .sign(b"another challenge")
                .to_bytes()
                .to_vec(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("expected a denial, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_authenticated_workspace_cannot_be_used_to_read_or_write_another_workspace() {
    // BR-013 / `wire.md`: CONNECT may name several groups, but AUTH admits a
    // device to one relay-resolved workspace.  The second group's presence in the
    // handshake is not a capability to read, reconcile, subscribe, or write it.
    let scratch = Scratch::new("workspace_scope").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let pool = relay.state.database.as_ref().expect("a database").pool();
    let allowed = vec![0xa1; 32];
    let forbidden = vec![0xb1; 32];
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2), ($3, $4)")
        .bind(&allowed)
        .bind("workspace-a")
        .bind(&forbidden)
        .bind("workspace-b")
        .execute(pool)
        .await
        .expect("create isolated workspaces");
    support::seed_access_set(&relay.state, "workspace-a", &[default_device()]).await;
    support::seed_access_set(&relay.state, "workspace-b", &[other_device()]).await;

    let mut client = Client::connect(relay.address).await;
    // Ordering is deliberate: the vulnerable revision selected workspace A here,
    // then treated the whole requested list as an authorization grant.
    client
        .handshake(vec![allowed.clone(), forbidden.clone()], CLOCK)
        .await;

    // The rightful workspace continues to work, proving this is a scope check and
    // not an accidental refusal after multi-group CONNECT.
    client
        .send_frame(&Frame::Sub {
            group: allowed.clone(),
            from_seq: 0,
        })
        .await;
    match client.recv_frame().await {
        Frame::SubAck { group, .. } => assert_eq!(group, allowed),
        other => panic!("expected the authorized subscription, got {other:?}"),
    }

    client
        .send_frame(&Frame::Sub {
            group: forbidden.clone(),
            from_seq: 0,
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("cross-workspace SUB must be denied, got {other:?}"),
    }

    // Scope is enforced before parsing or consulting reconciliation state, so a
    // malformed payload cannot turn the other workspace into a protocol oracle.
    client
        .send_frame(&Frame::Recon {
            group: forbidden.clone(),
            payload: vec![0xff],
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("cross-workspace RECON must be denied, got {other:?}"),
    }

    client
        .send_frame(&Frame::Send {
            envelope: envelope_for(&forbidden, b"must not persist").encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("cross-workspace SEND must be denied, got {other:?}"),
    }
    let persisted: i64 =
        sqlx::query_scalar("select count(*) from relay_envelope where group_id = $1")
            .bind(&forbidden)
            .fetch_one(pool)
            .await
            .expect("count forbidden envelopes");
    assert_eq!(persisted, 0, "a denied SEND must not reach storage");

    relay.shutdown().await;
    scratch.drop_database().await;
}

// MARK: Revocation closes sockets

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_device_loses_its_open_socket_and_cannot_come_back() {
    // The half of offboarding the relay owns. Removal is one action: the MLS epoch
    // change takes away future content, and this takes away the socket.
    let scratch = Scratch::new("revoke").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = bare_group(&relay.state, 0x83).await;
    let salt = salt_of(&relay.state).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let genesis = set_for(
        &salt,
        0,
        vec![0u8; 32],
        &[&default_device(), &other_device()],
        &default_device(),
    );
    store::publish(pool, WORKSPACE, &genesis, &genesis.encode())
        .await
        .expect("the genesis set");

    let mut ada = Client::connect(relay.address).await;
    let mut bo = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    bo.handshake_as(&other_device(), vec![group.clone()], CLOCK)
        .await;

    // Bo is removed by a publication over Ada's socket, which is how a client does
    // it: the relay is told by an authorizer and not by an operator.
    let removal = set_for(
        &salt,
        1,
        genesis.digest().to_vec(),
        &[&default_device()],
        &default_device(),
    );
    let started = Instant::now();
    ada.send_frame(&Frame::Access {
        body: removal.encode(),
    })
    .await;
    match ada.recv_frame().await {
        Frame::Access { body } => assert_eq!(body, removal.digest().to_vec()),
        other => panic!("expected an Access answer, got {other:?}"),
    }

    // Bo's socket closes, without Bo having sent anything.
    let closed = tokio::time::timeout(Duration::from_secs(5), bo.recv())
        .await
        .expect("Bo's socket must close within seconds");
    assert!(closed.is_none(), "Bo got a frame rather than a close");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "the eviction took {elapsed:?}"
    );

    // And Bo cannot reconnect. A close that only lasted until the next dial would be
    // theatre.
    let mut again = Client::connect(relay.address).await;
    let challenge = again
        .handshake_to_challenge(vec![group.clone()], CLOCK)
        .await;
    again
        .send_frame(&Frame::Auth {
            device_key: pk(&other_device()),
            signature: other_device().sign(&challenge).to_bytes().to_vec(),
        })
        .await;
    match again.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("expected a denial, got {other:?}"),
    }

    // Ada is untouched: a revocation closes one principal's sockets and not the
    // workspace's.
    let envelope = envelope_for(&group, b"still here");
    ada.send_frame(&Frame::Send {
        envelope: envelope.encode(),
    })
    .await;
    match ada.recv_frame().await {
        Frame::SendAck { .. } => {}
        other => panic!("the publisher lost its own session, got {other:?}"),
    }

    evidence(
        "disconnect-timing.txt",
        &format!(
            "step 6, revocation to socket close\n\
             device removed by an ACCESS publication over another device's socket\n\
             elapsed_ms={}\n\
             budget_ms=5000\n\
             reconnect_after_revocation=denied/writer_not_in_access_set\n\
             publisher_session_survived=true\n",
            elapsed.as_millis()
        ),
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_that_joined_on_a_live_invite_is_cut_off_by_the_same_publication() {
    // The case a provisional grant would have kept connected: a device that joined
    // minutes ago on an invite that has not expired. Its grant is live, so nothing
    // about the invite has changed, and it must still lose the socket.
    let scratch = Scratch::new("provisional").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = bare_group(&relay.state, 0x84).await;
    let salt = salt_of(&relay.state).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let genesis = set_for(
        &salt,
        0,
        vec![0u8; 32],
        &[&default_device()],
        &default_device(),
    );
    store::publish(pool, WORKSPACE, &genesis, &genesis.encode())
        .await
        .expect("the genesis set");

    // The joiner, admitted on a grant with a long life left.
    let joiner = device_from(0x21);
    let joiner_hash = access::entry_hash(&pk(&joiner), &salt);
    let far_future = 1_000i64 * 60 * 60 * 24 * 365 * 100;
    store::grant(pool, WORKSPACE, &joiner_hash, far_future)
        .await
        .expect("the grant");
    let mut joined = Client::connect(relay.address).await;
    joined
        .handshake_as(&joiner, vec![group.clone()], CLOCK)
        .await;

    // The set catches up with them, and then the next one drops them. That ordering
    // is what tells "never caught up" from "deliberately dropped".
    let carried = set_for(
        &salt,
        1,
        genesis.digest().to_vec(),
        &[&default_device(), &joiner],
        &default_device(),
    );
    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&Frame::Access {
        body: carried.encode(),
    })
    .await;
    assert!(matches!(ada.recv_frame().await, Frame::Access { .. }));

    let dropped = set_for(
        &salt,
        2,
        carried.digest().to_vec(),
        &[&default_device()],
        &default_device(),
    );
    let started = Instant::now();
    ada.send_frame(&Frame::Access {
        body: dropped.encode(),
    })
    .await;
    assert!(matches!(ada.recv_frame().await, Frame::Access { .. }));

    let closed = tokio::time::timeout(Duration::from_secs(5), joined.recv())
        .await
        .expect("the joiner's socket must close within seconds");
    assert!(
        closed.is_none(),
        "the joiner got a frame rather than a close"
    );
    let elapsed = started.elapsed();

    // The grant is void as well as the socket being closed, so the joiner cannot
    // reconnect under the invite it joined with.
    assert_eq!(
        store::admits(pool, WORKSPACE, &pk(&joiner)).await.unwrap(),
        store::Admission::Refused
    );

    evidence(
        "provisional-disconnect-timing.txt",
        &format!(
            "step 6, revocation of a device holding a live provisional grant\n\
             grant_expiry_remaining=about 100 years\n\
             elapsed_ms={}\n\
             budget_ms=5000\n\
             grant_after_removal=refused\n",
            elapsed.as_millis()
        ),
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn no_admitted_socket_survives_a_rotation_driven_concurrently_with_admissions() {
    // WEALD-290. `admit()` used to read the access set and only afterwards
    // register the socket with the hub, so a rotation that committed between the
    // two found an empty `principals` entry, closed zero connections, and the
    // just-revoked device kept a live authorized socket indefinitely. The fix
    // brackets the registration with a second membership read; this drives a
    // burst of admissions concurrently with the rotation that drops them, round
    // after round, and asserts no admitted socket outlives the set that dropped
    // its device.
    let scratch = Scratch::new("rotation_race").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = bare_group(&relay.state, 0x8c).await;
    let salt = salt_of(&relay.state).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let bo_entry = access::entry_hash(&pk(&other_device()), &salt);

    let genesis = set_for(
        &salt,
        0,
        vec![0u8; 32],
        &[&default_device(), &other_device()],
        &default_device(),
    );
    store::publish(pool, WORKSPACE, &genesis, &genesis.encode())
        .await
        .expect("the genesis set");
    let mut prev = genesis.digest().to_vec();
    let mut version = 1;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;

    for round in 0..10u32 {
        // A burst of Bo sockets racing towards `Ready`, spawned first so their
        // admissions interleave with the publication below.
        let mut racers = tokio::task::JoinSet::new();
        for _ in 0..4 {
            let address = relay.address;
            let group = group.clone();
            racers.spawn(async move {
                let mut bo = Client::connect(address).await;
                let challenge = bo.handshake_to_challenge(vec![group], CLOCK).await;
                bo.send_frame(&Frame::Auth {
                    device_key: pk(&other_device()),
                    signature: other_device().sign(&challenge).to_bytes().to_vec(),
                })
                .await;
                // Whatever the race decided (an ack, a refusal, or a close), the
                // socket is held open so a survivor would be visible below.
                let _ = tokio::time::timeout(Duration::from_secs(5), bo.recv()).await;
                bo
            });
        }

        // The rotation, concurrent with the burst: Bo is dropped.
        let removal = set_for(
            &salt,
            version,
            prev,
            &[&default_device()],
            &default_device(),
        );
        ada.send_frame(&Frame::Access {
            body: removal.encode(),
        })
        .await;
        match ada.recv_frame().await {
            Frame::Access { body } => assert_eq!(body, removal.digest().to_vec()),
            other => panic!("round {round}: expected an Access answer, got {other:?}"),
        }

        let clients: Vec<Client> = {
            let mut clients = Vec::new();
            while let Some(joined) = racers.join_next().await {
                clients.push(joined.expect("a racer finishes"));
            }
            clients
        };

        // The invariant: once the set that drops Bo is published and the burst
        // has settled, no admitted socket for Bo survives. The hub is the ground
        // truth revocation acts on, so it is what is asserted.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let held = relay.state.hub.connections_for(&bo_entry).await;
            if held == 0 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "round {round}: {held} revoked socket(s) survived the rotation"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        drop(clients);

        // Bo is re-admitted for the next round, so every round races a fresh
        // removal rather than re-asserting the last one.
        prev = removal.digest().to_vec();
        version += 1;
        let restore = set_for(
            &salt,
            version,
            prev,
            &[&default_device(), &other_device()],
            &default_device(),
        );
        ada.send_frame(&Frame::Access {
            body: restore.encode(),
        })
        .await;
        match ada.recv_frame().await {
            Frame::Access { body } => assert_eq!(body, restore.digest().to_vec()),
            other => panic!("round {round}: expected the restore ack, got {other:?}"),
        }
        prev = restore.digest().to_vec();
        version += 1;
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

// MARK: Probation, and that time is not a promotion

#[tokio::test(flavor = "multi_thread")]
async fn a_recovery_introduced_device_may_not_remove_more_however_long_it_waits() {
    // The negative proof `phases-relay.md` asks for: a recovery-introduced device
    // attempting a removal before confirmation by a pre-existing authorizer is
    // refused, including after every simulated time advance. There is no timer to
    // advance, which is the point: time cannot tell the owner who lost a laptop from
    // somebody who copied a phrase.
    let scratch = Scratch::new("probation").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = bare_group(&relay.state, 0x85).await;
    let salt = salt_of(&relay.state).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let hash = |device: &SigningKey| access::entry_hash(&pk(device), &salt);

    // A workspace with an owner, a bystander, and a recovery principal.
    let owner = default_device();
    let bystander = other_device();
    let recovery = device_from(0x3f);
    let genesis = set_for(&salt, 0, vec![0u8; 32], &[&owner, &bystander], &owner);
    store::publish(pool, WORKSPACE, &genesis, &genesis.encode())
        .await
        .expect("the genesis set");

    // The rotation: the recovery principal introduces device `7`, pinning nothing.
    let replacement = device_from(0x77);
    let mut rotation = AccessSet {
        workspace: vec![0x77; 32],
        version: 1,
        prev_hash: genesis.digest().to_vec(),
        issued_at: CLOCK,
        entries: sorted(
            genesis
                .entries
                .iter()
                .filter(|entry| *entry != &hash(&recovery))
                .cloned()
                .chain([hash(&replacement), hash(&device_from(0x4f))])
                .collect(),
        ),
        authorizers: sorted(vec![pk(&owner), pk(&replacement)]),
        recovery: vec![pk(&device_from(0x4f))],
        quorum: None,
        pending: Vec::new(),
        signer: pk(&recovery),
        sig: vec![0u8; 64],
    };
    rotation.sig = recovery.sign(&rotation.digest_input()).to_bytes().to_vec();
    store::publish(pool, WORKSPACE, &rotation, &rotation.encode())
        .await
        .expect("the rotation");

    // The replacement device connects, which it may: it is an entry.
    let mut probationary = Client::connect(relay.address).await;
    probationary
        .handshake_as(&replacement, vec![group.clone()], CLOCK)
        .await;

    // It attempts to remove the bystander, which its rotation did not pin. Refused,
    // and refused again after the probation is aged by a year: no timer promotes it.
    for (label, age_days) in [("immediately", 0i64), ("after a year", 365)] {
        if age_days > 0 {
            sqlx::query(
                "update relay_access_probation \
                 set created_at = now() - make_interval(days => $1) where device = $2",
            )
            .bind(age_days as i32)
            .bind(pk(&replacement))
            .execute(pool)
            .await
            .expect("age the probation");
        }
        let prior = store::current(pool, WORKSPACE)
            .await
            .unwrap()
            .prior
            .expect("a prior set");
        let mut overreach = AccessSet {
            workspace: vec![0x77; 32],
            version: prior.version + 1,
            prev_hash: prior.digest.clone(),
            issued_at: CLOCK,
            entries: sorted(
                prior
                    .entries
                    .iter()
                    .filter(|entry| *entry != &hash(&bystander))
                    .cloned()
                    .collect(),
            ),
            authorizers: sorted(vec![pk(&owner), pk(&replacement)]),
            recovery: vec![pk(&device_from(0x4f))],
            quorum: None,
            pending: Vec::new(),
            signer: pk(&replacement),
            sig: vec![0u8; 64],
        };
        overreach.sig = replacement
            .sign(&overreach.digest_input())
            .to_bytes()
            .to_vec();
        probationary
            .send_frame(&Frame::Access {
                body: overreach.encode(),
            })
            .await;
        match probationary.recv_frame().await {
            Frame::Error(error) => assert_eq!(
                error.code,
                ErrorCode::WriterNotInAccessSet,
                "the overreach was accepted {label}"
            ),
            other => panic!("expected a refusal {label}, got {other:?}"),
        }
        // The bystander is still an entry, so the refusal was not cosmetic.
        assert_eq!(
            store::admits(pool, WORKSPACE, &pk(&bystander))
                .await
                .unwrap(),
            store::Admission::InSet,
            "the bystander was removed {label}"
        );
    }

    // What it may do is publish a set that removes nothing, and a pre-existing
    // authorizer clears the probation by carrying it.
    let prior = store::current(pool, WORKSPACE)
        .await
        .unwrap()
        .prior
        .unwrap();
    let mut confirm = AccessSet {
        workspace: vec![0x77; 32],
        version: prior.version + 1,
        prev_hash: prior.digest.clone(),
        issued_at: CLOCK,
        entries: prior.entries.clone(),
        authorizers: sorted(vec![pk(&owner), pk(&replacement)]),
        recovery: vec![pk(&device_from(0x4f))],
        quorum: None,
        pending: Vec::new(),
        signer: pk(&owner),
        sig: vec![0u8; 64],
    };
    confirm.sig = owner.sign(&confirm.digest_input()).to_bytes().to_vec();
    let accepted = store::publish(pool, WORKSPACE, &confirm, &confirm.encode())
        .await
        .expect("the confirmation");
    assert_eq!(accepted.cleared_probation, vec![pk(&replacement)]);

    evidence(
        "probation-refusals.txt",
        "step 6, a recovery-introduced device attempting an unpinned removal\n\
         immediately: denied/writer_not_in_access_set\n\
         after a year of simulated age: denied/writer_not_in_access_set\n\
         cleared only by a publication from the authorizer that predates the rotation\n",
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

// MARK: What a publication does when it is wrong, or when the relay cannot look

#[tokio::test(flavor = "multi_thread")]
async fn an_undecodable_publication_is_refused_and_the_session_survives() {
    let scratch = Scratch::new("badaccess").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = bare_group(&relay.state, 0x86).await;
    let salt = salt_of(&relay.state).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let genesis = set_for(
        &salt,
        0,
        vec![0u8; 32],
        &[&default_device()],
        &default_device(),
    );
    store::publish(pool, WORKSPACE, &genesis, &genesis.encode())
        .await
        .unwrap();

    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], CLOCK).await;
    client
        .send_frame(&Frame::Access {
            body: vec![0x01, 0x02, 0x03],
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::MalformedHeader),
        other => panic!("expected a rejection, got {other:?}"),
    }

    // A well-formed set that does not follow the head is refused as a denial rather
    // than a rejection, because fetching the head and reissuing can fix it.
    let stale = set_for(
        &salt,
        5,
        vec![0x11; 32],
        &[&default_device()],
        &default_device(),
    );
    client
        .send_frame(&Frame::Access {
            body: stale.encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::WriterNotInAccessSet);
        }
        other => panic!("expected a denial, got {other:?}"),
    }

    // And the session is still usable, so a client that got its version wrong does
    // not lose its socket over it.
    let envelope = envelope_for(&group, b"session survives");
    client
        .send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
    assert!(matches!(client.recv_frame().await, Frame::SendAck { .. }));

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_publication_the_relay_cannot_store_answers_retry_rather_than_closing() {
    // A relay that cannot look must not fail open and must not close the socket in
    // silence: the client's correct response is backoff and a verbatim resend.
    let scratch = Scratch::new("accessdbgone").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = bare_group(&relay.state, 0x87).await;
    let salt = salt_of(&relay.state).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let genesis = set_for(
        &salt,
        0,
        vec![0u8; 32],
        &[&default_device()],
        &default_device(),
    );
    store::publish(pool, WORKSPACE, &genesis, &genesis.encode())
        .await
        .unwrap();

    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], CLOCK).await;

    let mut admin = sqlx::postgres::PgConnection::connect(&support::admin_url())
        .await
        .expect("connect as admin");
    admin
        .execute(format!("drop database if exists {} with (force)", scratch.name).as_str())
        .await
        .expect("drop it under the relay");

    let next = set_for(
        &salt,
        1,
        genesis.digest().to_vec(),
        &[&default_device()],
        &default_device(),
    );
    client
        .send_frame(&Frame::Access {
            body: next.encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::Backpressure);
            assert!(error.code.class().is_retryable());
        }
        other => panic!("expected retry/backpressure, got {other:?}"),
    }

    // A device that cannot be checked is not admitted either. Failing open here would
    // be failing open in exactly the incident where the check matters.
    let mut stranger = Client::connect(relay.address).await;
    let challenge = stranger
        .handshake_to_challenge(vec![group.clone()], CLOCK)
        .await;
    stranger
        .send_frame(&Frame::Auth {
            device_key: pk(&default_device()),
            signature: default_device().sign(&challenge).to_bytes().to_vec(),
        })
        .await;
    match stranger.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::Backpressure),
        other => panic!("expected retry/backpressure, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_naming_no_group_this_relay_knows_is_refused() {
    // The workspace is the relay's own answer for one of the connection's groups,
    // never something the client asserts. A connection that named no known group has
    // named no workspace, and a relay that guessed one would be checking a stranger
    // against somebody else's access set.
    let scratch = Scratch::new("nogroup").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let mut client = Client::connect(relay.address).await;
    let challenge = client
        .handshake_to_challenge(vec![vec![0xee; 32]], CLOCK)
        .await;
    client
        .send_frame(&Frame::Auth {
            device_key: pk(&default_device()),
            signature: default_device().sign(&challenge).to_bytes().to_vec(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::GroupUnknown),
        other => panic!("expected an unknown-group refusal, got {other:?}"),
    }
    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn with_enforcement_off_a_publication_still_needs_a_group_this_relay_knows() {
    // `environments.md` allows exactly one ci suite to run with enforcement off, to
    // assert that the difference is reported. This is that suite's other half: with
    // the access check off, `AUTH` admits without consulting a workspace, so `ACCESS`
    // is the frame that has to find one, and a connection that named no known group
    // is told rather than being left to think its publication landed.
    let scratch = Scratch::new("enforceoff").await;
    let blobs = tempfile::tempdir().unwrap();
    let mut config = config_for(&scratch, blobs.path());
    config.access_set = wealdrelay::config::AccessSetMode::Off;
    let relay = Running::start(config, Clock::Fixed(CLOCK)).await;
    assert_eq!(
        relay.state.readiness().await.access_set,
        "off",
        "the health surface must report the difference"
    );

    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![vec![0xef; 32]], CLOCK).await;
    let salt = salt_of(&relay.state).await;
    let genesis = set_for(
        &salt,
        0,
        vec![0u8; 32],
        &[&default_device()],
        &default_device(),
    );
    client
        .send_frame(&Frame::Access {
            body: genesis.encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::GroupUnknown),
        other => panic!("expected an unknown-group refusal, got {other:?}"),
    }
    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_only_relay_says_so_to_a_bootstrapping_session_too() {
    // `write_mode` is reported on the acknowledgement, and a workspace with no set
    // yet gets the same answer as one with one: a read-only relay that told a
    // bootstrapping client it could write would be lying at the one moment the client
    // is deciding what to do next.
    let scratch = Scratch::new("readonlyboot").await;
    let blobs = tempfile::tempdir().unwrap();
    let mut config = config_for(&scratch, blobs.path());
    config.write_mode = wealdrelay::config::WriteMode::ReadOnly;
    let relay = Running::start(config, Clock::Fixed(CLOCK)).await;
    let group = bare_group(&relay.state, 0x88).await;
    hold_bootstrap_seat(&relay.state, &default_device()).await;

    let mut client = Client::connect(relay.address).await;
    client
        .send_frame(&Frame::Connect {
            version: PROTOCOL_VERSION,
            groups: vec![group.clone()],
            sent_at: CLOCK,
        })
        .await;
    assert!(matches!(
        client.recv_frame().await,
        Frame::ConnectAck { .. }
    ));
    let challenge = match client.recv_frame().await {
        Frame::AuthChallenge { challenge } => challenge,
        other => panic!("expected an AuthChallenge, got {other:?}"),
    };
    client
        .send_frame(&Frame::Auth {
            device_key: pk(&default_device()),
            signature: default_device().sign(&challenge).to_bytes().to_vec(),
        })
        .await;
    match client.recv_frame().await {
        Frame::AuthAck { write_mode, .. } => assert_eq!(write_mode, 1),
        other => panic!("expected an AuthAck, got {other:?}"),
    }
    relay.shutdown().await;
    scratch.drop_database().await;
}

// MARK: The state query

#[tokio::test(flavor = "multi_thread")]
async fn the_state_query_answers_the_salt_and_the_head_and_nothing_about_membership() {
    // A client cannot build one entry without the salt, so before this existed the
    // genesis publication `wire.md` requires of the trust root was unbuildable by any
    // real client: only a test reaching into the database could produce one. An empty
    // `ACCESS` body is that question, and the answer is deliberately two facts.
    let scratch = Scratch::new("accessstate").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = bare_group(&relay.state, 0x91).await;
    let salt = salt_of(&relay.state).await;
    hold_bootstrap_seat(&relay.state, &default_device()).await;

    // Before genesis, asked by the one connection the workspace can open.
    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], CLOCK).await;
    client.send_frame(&Frame::Access { body: Vec::new() }).await;
    let (answered_salt, head) = match client.recv_frame().await {
        Frame::Access { body } => decode_state(&body),
        other => panic!("expected an Access answer, got {other:?}"),
    };
    assert_eq!(
        answered_salt, salt,
        "the salt is the one the relay hashes with"
    );
    assert_eq!(head, None, "a workspace with no set has no head");

    // The client can now do what the answer is for: build a set whose entries hash
    // against that salt, and publish it.
    let genesis = set_for(
        &salt,
        0,
        vec![0u8; 32],
        &[&default_device()],
        &default_device(),
    );
    client
        .send_frame(&Frame::Access {
            body: genesis.encode(),
        })
        .await;
    assert!(matches!(client.recv_frame().await, Frame::Access { .. }));

    // After genesis the head is the version and digest the next publication has to
    // name, which is the whole reason a client asks a second time.
    client.send_frame(&Frame::Access { body: Vec::new() }).await;
    match client.recv_frame().await {
        Frame::Access { body } => {
            let (again, head) = decode_state(&body);
            assert_eq!(again, salt);
            assert_eq!(head, Some((0, genesis.digest().to_vec())));
            // Two facts and no third. An entry count would be a membership fact, and
            // this answer goes to anybody who can open a socket.
            assert_eq!(
                body,
                wealdrelay::access::encode_state(&store::State {
                    salt: salt.clone(),
                    head: Some((0, genesis.digest().to_vec())),
                })
            );
        }
        other => panic!("expected an Access answer, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_state_query_answers_the_admitted_workspace_and_never_a_named_group() {
    // This test used to assert the opposite, and the rule it asserted was the
    // weaker one. The state query resolved a workspace from the groups the
    // connection named, on every query, so deleting the group made the query
    // unanswerable and the relay said so.
    //
    // Resolving from the named groups is a cross-tenant oracle (BR-013). The salt
    // is the value every entry hash is keyed on, and `store::state_for` answers
    // the first named group that resolves to any workspace, while `store::admission`
    // binds the session to the first group that actually *admits* the device. Those
    // disagree exactly when a client names groups from two workspaces: a member of
    // B naming one of A's ids first was handed A's salt and A's set head.
    //
    // So `report_access_state` now answers from the workspace this session was
    // admitted to and from nothing else, and that is what is asserted here: the
    // named groups cannot move the answer, whether they vanish or belong to
    // somebody else.
    let scratch = Scratch::new("accessstatenogroup").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = bare_group(&relay.state, 0x92).await;
    let salt = salt_of(&relay.state).await;
    hold_bootstrap_seat(&relay.state, &default_device()).await;
    let pool = relay.state.database.as_ref().unwrap().pool();

    // Another tenant on the same relay, with a group id this client will name.
    let foreign_group = vec![0x93; 32];
    sqlx::query("insert into relay_workspace (workspace_id, salt) values ($1, $2)")
        .bind("ws-someone-else")
        .bind(vec![0xABu8; 32])
        .execute(pool)
        .await
        .expect("the other workspace");
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(&foreign_group)
        .bind("ws-someone-else")
        .execute(pool)
        .await
        .expect("the other workspace's group");

    let mut client = Client::connect(relay.address).await;
    client
        .handshake(vec![foreign_group.clone(), group.clone()], CLOCK)
        .await;

    // Named first, and it still does not decide the answer.
    client.send_frame(&Frame::Access { body: Vec::new() }).await;
    match client.recv_frame().await {
        Frame::Access { body } => {
            let (answered, _) = decode_state(&body);
            assert_eq!(
                answered, salt,
                "the salt answered must be the admitted workspace's, never a named group's"
            );
            assert_ne!(answered, vec![0xABu8; 32]);
        }
        other => panic!("expected an Access answer, got {other:?}"),
    }

    // And the group going away does not change it either, because it was never
    // what the answer was resolved from.
    sqlx::query("delete from relay_group where group_id = $1")
        .bind(&group)
        .execute(pool)
        .await
        .expect("unregister the group");
    client.send_frame(&Frame::Access { body: Vec::new() }).await;
    match client.recv_frame().await {
        Frame::Access { body } => assert_eq!(decode_state(&body).0, salt),
        other => panic!("expected an Access answer, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_state_query_the_relay_cannot_answer_is_a_retry_and_not_a_guess() {
    // The same rule as a publication the relay cannot store: a relay that could not
    // look has learned nothing, and inventing a salt would make every entry hash the
    // client built unverifiable forever.
    let scratch = Scratch::new("accessstatedbgone").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = bare_group(&relay.state, 0x93).await;
    let salt = salt_of(&relay.state).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let genesis = set_for(
        &salt,
        0,
        vec![0u8; 32],
        &[&default_device()],
        &default_device(),
    );
    store::publish(pool, WORKSPACE, &genesis, &genesis.encode())
        .await
        .unwrap();

    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], CLOCK).await;

    let mut admin = sqlx::postgres::PgConnection::connect(&support::admin_url())
        .await
        .expect("connect as admin");
    admin
        .execute(format!("drop database if exists {} with (force)", scratch.name).as_str())
        .await
        .expect("drop it under the relay");

    client.send_frame(&Frame::Access { body: Vec::new() }).await;
    match client.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::Backpressure);
            assert!(error.code.class().is_retryable());
        }
        other => panic!("expected retry/backpressure, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

/// The client's half of `access::encode_state`, for the assertions above.
fn decode_state(body: &[u8]) -> (Vec<u8>, Option<(u64, Vec<u8>)>) {
    let mut reader = wealdrelay::cbor::Reader::new(body);
    reader.array(2).expect("a two field answer");
    let salt = reader.bytes().expect("the salt");
    if reader.optional_is_null().expect("a head or null") {
        reader.finish().expect("nothing after the answer");
        return (salt, None);
    }
    reader.array(2).expect("a version and a digest");
    let version = reader.uint().expect("the version");
    let digest = reader.bytes().expect("the digest");
    reader.finish().expect("nothing after the answer");
    (salt, Some((version, digest)))
}

/// WEALD-L159. The state query resolved the first requested group that named any
/// workspace, while admission binds the session to the first group that actually
/// admits the device. The two disagree exactly when a client names groups from two
/// workspaces, and the disagreement handed out another tenant's salt, which is the
/// value every entry hash is keyed on, plus the head a rotation has to name.
#[tokio::test(flavor = "multi_thread")]
async fn the_state_query_answers_from_the_admitted_workspace_and_not_a_named_stranger() {
    let scratch = Scratch::new("accessstate_cross").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let pool = relay.state.database.as_ref().expect("a database").pool();

    // The victim's workspace, which the attacker is not in and only knows one
    // group id of.
    let victim_group = bare_group(&relay.state, 0x9c).await;
    let victim_salt = salt_of(&relay.state).await;

    // The attacker's own workspace, where they are a genuine member.
    let attacker_key = device_from(0xa7);
    let attacker_group = support::make_group_in(
        &relay.state,
        "ws-stranger",
        0x9d,
        std::slice::from_ref(&attacker_key),
        std::slice::from_ref(&attacker_key),
    )
    .await;
    let attacker_salt = store::salt(pool, "ws-stranger")
        .await
        .expect("the stranger workspace salt");
    assert_ne!(victim_salt, attacker_salt);

    // The victim's group is named first, so first-found resolution reaches it.
    let mut attacker = Client::connect(relay.address).await;
    attacker
        .handshake_as(
            &attacker_key,
            vec![victim_group.clone(), attacker_group.clone()],
            CLOCK,
        )
        .await;
    attacker
        .send_frame(&Frame::Access { body: Vec::new() })
        .await;
    match attacker.recv_frame().await {
        Frame::Access { body } => {
            let (answered, _head) = decode_state(&body);
            assert_ne!(
                answered, victim_salt,
                "the state query handed out another workspace's salt"
            );
            assert_eq!(
                answered, attacker_salt,
                "the answer is the admitted workspace's own state"
            );
        }
        Frame::Error(_) => {}
        other => panic!("expected a state answer or a refusal, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}
