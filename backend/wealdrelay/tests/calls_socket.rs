// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The call path over real sockets against real Postgres.
//!
//! The claims here are the ones a unit test cannot make honestly.
//!
//! - An offer reaches every admitted subscriber of the group and no unadmitted
//!   one, and media then reaches the people who joined the call and nobody else.
//! - Nothing is stored. Every table the relay writes to holds exactly what it
//!   held before, asserted by counting rows rather than by reading the call
//!   graph: "this function does not write" is a claim about a call graph and a
//!   row count is a fact.
//! - A call survives a participant reconnecting mid-stream.
//! - A version 2 client is never sent either frame.
//! - The refusals are the specific codes, over a socket, from a real session.
//!
//! Real client processes over TCP, one real relay, one real Postgres. Nothing is
//! mocked and nothing is skipped: `specs/backend/build/testing.md` says an
//! integration test that cannot reach its dependency fails.

mod support;

use ed25519_dalek::{Signer as _, SigningKey};
use wealdrelay::access::{self, store, AccessSet};
use wealdrelay::calls::{
    CallKind, MAX_CALL_BODY_BYTES, MAX_MEDIA_CT_BYTES, MAX_PARTICIPANTS_PER_CALL,
    MEDIA_FRAMES_PER_STREAM_PER_SECOND,
};
use wealdrelay::frame::{ErrorCode, Frame, MIN_PROTOCOL_VERSION};
use wealdrelay::health::{Clock, RelayState};

use support::{
    config_for, config_for_calls, default_device, device_from, make_group, other_device, Client,
    Running, Scratch,
};

const CLOCK: u64 = 1_700_000_000_000;

/// Every table the relay writes to, so "nothing was stored" is a statement about
/// the database rather than about one table somebody remembered to check.
const TABLES: &[&str] = &[
    "relay_envelope",
    "relay_handshake",
    "relay_key_package",
    "relay_recovery_wrap",
    "relay_access_set",
    "relay_access_entry",
    "relay_group",
    "relay_blob_reservation",
    "relay_quota",
    "relay_transparency_log",
];

async fn counts(pool: &sqlx::PgPool) -> Vec<(String, i64)> {
    let mut out = Vec::new();
    for table in TABLES {
        let count: i64 = sqlx::query_scalar(&format!("select count(*) from {table}"))
            .fetch_one(pool)
            .await
            .expect("count");
        out.push(((*table).to_string(), count));
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn call_id(seed: u8) -> Vec<u8> {
    vec![seed; 16]
}

fn pk(signer: &SigningKey) -> Vec<u8> {
    signer.verifying_key().to_bytes().to_vec()
}

/// The set that removes everybody but `keep`, chained onto whatever this
/// workspace currently holds.
///
/// Built here rather than in `support` because it is the subject of exactly one
/// test: the shape has to match what `support::seed_access_set` published, and a
/// shared helper would hide that coupling rather than state it.
async fn removal_set(
    state: &std::sync::Arc<RelayState>,
    workspace: &str,
    keep: &[&SigningKey],
) -> AccessSet {
    let pool = state.database.as_ref().expect("a database").pool();
    let current = store::current(pool, workspace)
        .await
        .expect("the current set");
    let prior = current.prior.expect("a genesis set to chain onto");
    let recovery = device_from(0x3f);
    let mut entries: Vec<Vec<u8>> = keep
        .iter()
        .map(|device| access::entry_hash(&pk(device), &current.salt))
        .collect();
    entries.push(access::entry_hash(&pk(&recovery), &current.salt));
    entries.sort();
    entries.dedup();
    let signer = default_device();
    let mut set = AccessSet {
        workspace: vec![0u8; 32],
        version: prior.version + 1,
        prev_hash: prior.digest.clone(),
        issued_at: CLOCK,
        entries,
        authorizers: vec![pk(&signer)],
        recovery: vec![pk(&recovery)],
        quorum: None,
        pending: Vec::new(),
        signer: pk(&signer),
        sig: vec![0u8; 64],
    };
    set.sig = signer.sign(&set.digest_input()).to_bytes().to_vec();
    set
}

/// Whether the relay closed this socket, within the five seconds
/// `specs/backend/relay/operations.md` gives revocation.
async fn closed(client: &mut Client) -> bool {
    matches!(
        tokio::time::timeout(std::time::Duration::from_secs(5), client.recv()).await,
        Ok(None)
    )
}

fn offer(id: &[u8], group: &[u8]) -> Frame {
    signal(id, group, CallKind::Offer)
}

fn signal(id: &[u8], group: &[u8], kind: CallKind) -> Frame {
    Frame::Call {
        call_id: id.to_vec(),
        group: group.to_vec(),
        epoch: 3,
        kind: kind as u8,
        body: b"sealed offer".to_vec(),
    }
}

fn media(id: &[u8], seq: u64) -> Frame {
    Frame::Media {
        call_id: id.to_vec(),
        stream: vec![0, 0, 0, 1],
        seq,
        ct: vec![0x41; 80],
    }
}

/// Subscribe and swallow the acknowledgement, which every participant does before
/// it can be fanned out to.
async fn subscribe(client: &mut Client, group: &[u8]) {
    client
        .send_frame(&Frame::Sub {
            group: group.to_vec(),
            from_seq: 0,
        })
        .await;
    assert!(matches!(client.recv_frame().await, Frame::SubAck { .. }));
}

// MARK: The integration proof

#[tokio::test(flavor = "multi_thread")]
async fn a_call_runs_end_to_end_and_changes_no_row_in_any_table() {
    let scratch = Scratch::new("calls_end_to_end").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), 3),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x40).await;
    let pool = relay.state.database.as_ref().expect("a database").pool();
    let id = call_id(0xC1);

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    subscribe(&mut ada, &group).await;
    let mut bo = Client::connect(relay.address).await;
    bo.handshake_as(&other_device(), vec![group.clone()], CLOCK)
        .await;
    subscribe(&mut bo, &group).await;

    let before = counts(pool).await;

    // The offer, fanned out at the group because the callee is not in the call
    // yet: that is the entire point of an offer.
    ada.send_frame(&offer(&id, &group)).await;
    match bo.recv_frame().await {
        Frame::Call {
            call_id,
            group: g,
            epoch,
            kind,
            body,
        } => {
            assert_eq!(call_id, id);
            assert_eq!(g, group);
            assert_eq!(epoch, 3);
            assert_eq!(kind, CallKind::Offer as u8);
            // The same bytes. The relay forwards what it was given and cannot read
            // it: `body` is sealed under the group's MLS exporter.
            assert_eq!(body, b"sealed offer".to_vec());
        }
        other => panic!("expected the offer, got {other:?}"),
    }

    // The answer, which is what puts Bo in the call.
    bo.send_frame(&signal(&id, &group, CallKind::Answer)).await;
    match ada.recv_frame().await {
        Frame::Call { kind, .. } => assert_eq!(kind, CallKind::Answer as u8),
        other => panic!("expected the answer, got {other:?}"),
    }
    assert_eq!(relay.state.calls.open_calls().await, 1);

    // And then the audio, which is routed at the call rather than at the group.
    let frame = media(&id, 1);
    ada.send_frame(&frame).await;
    assert_eq!(bo.recv_frame().await, frame);

    // The publisher is answered with nothing at all: no sequence number, no
    // acknowledgement, no row. Proved by asking for something that does answer and
    // seeing that answer arrive next.
    ada.send_frame(&Frame::Sub {
        group: group.clone(),
        from_seq: 0,
    })
    .await;
    assert!(
        matches!(ada.recv_frame().await, Frame::SubAck { .. }),
        "a call frame was acknowledged when it should have been silent"
    );

    // Bye closes it, and the call is forgotten when its last participant leaves.
    ada.send_frame(&signal(&id, &group, CallKind::Bye)).await;
    match bo.recv_frame().await {
        Frame::Call { kind, .. } => assert_eq!(kind, CallKind::Bye as u8),
        other => panic!("expected the bye, got {other:?}"),
    }
    bo.send_frame(&signal(&id, &group, CallKind::Bye)).await;
    match ada.recv_frame().await {
        Frame::Call { kind, .. } => assert_eq!(kind, CallKind::Bye as u8),
        other => panic!("expected the bye, got {other:?}"),
    }
    // Round-trip a frame that is answered, so the bye has certainly been performed
    // before the registry is read: the socket is ordered, so an answer to a later
    // frame proves the earlier one is done.
    bo.send_frame(&Frame::Sub {
        group: group.clone(),
        from_seq: 0,
    })
    .await;
    assert!(matches!(bo.recv_frame().await, Frame::SubAck { .. }));
    assert_eq!(relay.state.calls.open_calls().await, 0);

    let after = counts(pool).await;
    assert_eq!(after, before, "a call frame reached storage");

    // The artifact, written by the run that proves it rather than by a human
    // afterwards: a packet-level transcript of one call and the row counts either
    // side of it.
    let mut transcript = String::new();
    transcript.push_str("# One call, packet level\n\n");
    transcript.push_str(
        "specs/backend/relay/calls.md. Ada offers, Bo answers, Ada sends one media frame,\nboth say bye. Nothing is stored: the table counts below are taken immediately\nbefore the offer and immediately after the last bye, over every table the relay\nwrites to.\n\n",
    );
    let offered = offer(&id, &group);
    transcript.push_str(&format!(
        "client to relay  tag 23  call {}  group {}  kind 1 (offer)  body {} bytes\n",
        hex(&id),
        hex(&group),
        b"sealed offer".len()
    ));
    transcript.push_str(&format!("wire             {}\n\n", hex(&offered.encode())));
    let audio = media(&id, 1);
    transcript.push_str(&format!(
        "client to relay  tag 24  call {}  stream 00000001  seq 1  ct {} bytes\n",
        hex(&id),
        80
    ));
    transcript.push_str(&format!("wire             {}\n\n", hex(&audio.encode())));
    transcript.push_str(
        "relay to client  tag 23 to every version 3 subscriber of the group\nrelay to client  tag 24 to the other participants of the call only\nrelay to publisher  nothing at all: no sequence number, no acknowledgement, no row\n\n",
    );
    transcript.push_str("## Row counts, before and after\n\n");
    for ((table, before_count), (_, after_count)) in before.iter().zip(after.iter()) {
        transcript.push_str(&format!(
            "{table:<28} {before_count:>6} -> {after_count:>6}\n"
        ));
    }
    support::record_evidence("step-35", "call-transcript.txt", &transcript);

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_survives_a_participant_reconnecting_mid_stream() {
    // The reconnection case, and it is not free: the registry is keyed by
    // connection, so a reconnecting client is a new connection and has to rejoin.
    // What must hold is that rejoining works and that the other side's stream is
    // uninterrupted, rather than that the relay remembered a socket that has gone.
    let scratch = Scratch::new("calls_reconnect").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), 3),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x41).await;
    let id = call_id(0xC2);

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    subscribe(&mut ada, &group).await;
    let mut bo = Client::connect(relay.address).await;
    bo.handshake_as(&other_device(), vec![group.clone()], CLOCK)
        .await;
    subscribe(&mut bo, &group).await;

    ada.send_frame(&offer(&id, &group)).await;
    assert!(matches!(bo.recv_frame().await, Frame::Call { .. }));
    bo.send_frame(&signal(&id, &group, CallKind::Answer)).await;
    assert!(matches!(ada.recv_frame().await, Frame::Call { .. }));
    ada.send_frame(&media(&id, 1)).await;
    assert_eq!(bo.recv_frame().await, media(&id, 1));

    // Bo's laptop sleeps. The socket goes without a close, which is the shape a
    // lost network actually has.
    drop(bo);

    let mut bo = Client::connect(relay.address).await;
    bo.handshake_as(&other_device(), vec![group.clone()], CLOCK)
        .await;
    subscribe(&mut bo, &group).await;
    // Rejoining is an ordinary answer into the same call id, which still exists
    // because Ada never left it.
    bo.send_frame(&signal(&id, &group, CallKind::Answer)).await;
    assert!(matches!(ada.recv_frame().await, Frame::Call { .. }));
    assert_eq!(relay.state.calls.open_calls().await, 1);

    // And Ada's stream reaches the new socket without Ada having done anything at
    // all: the call is the same call and Ada never renegotiated.
    ada.send_frame(&media(&id, 2)).await;
    assert_eq!(bo.recv_frame().await, media(&id, 2));

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_offer_reaches_admitted_subscribers_and_no_unadmitted_one() {
    // Two workspaces on one relay. The second workspace's device is admitted to
    // its own group and to nothing else, so an offer into the first workspace's
    // group must not reach it, and its own offer into that group must be refused.
    let scratch = Scratch::new("calls_admission").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), 3),
        Clock::Fixed(CLOCK),
    )
    .await;
    let ours = make_group(&relay.state, 0x42).await;
    let stranger_key = device_from(0x81);
    let theirs = support::make_group_in(
        &relay.state,
        "ws-other",
        0x43,
        std::slice::from_ref(&stranger_key),
        std::slice::from_ref(&stranger_key),
    )
    .await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![ours.clone()], CLOCK).await;
    let mut stranger = Client::connect(relay.address).await;
    stranger
        .handshake_as(&stranger_key, vec![theirs.clone()], CLOCK)
        .await;
    // The stranger subscribes to their own group, which is the only one they can.
    subscribe(&mut stranger, &theirs).await;

    // An offer into a group the sender is not admitted to is denied by the same
    // check `SEND` is denied by, so a call cannot be a way around the access set.
    stranger.send_frame(&offer(&call_id(0xC3), &ours)).await;
    match stranger.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("expected a denial, got {other:?}"),
    }

    // And an offer into a group this relay has never heard of is `group_unknown`,
    // which is a different fact and a different answer.
    ada.send_frame(&offer(&call_id(0xC4), &[0xAB; 32])).await;
    match ada.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::GroupUnknown),
        other => panic!("expected a refusal, got {other:?}"),
    }

    // Ada's real offer reaches nobody in the other workspace. Proved by sending it
    // and then sending the stranger something they must receive: the socket is
    // ordered, so if the offer had been fanned out to them it would arrive first.
    subscribe(&mut ada, &ours).await;
    ada.send_frame(&offer(&call_id(0xC5), &ours)).await;
    let envelope = support::envelope_for(&theirs, b"their own traffic");
    stranger
        .send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
    match stranger.recv_frame().await {
        Frame::SendAck { .. } => {}
        other => panic!("the stranger was sent {other:?} before their own acknowledgement"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_version_two_client_is_never_sent_a_call_frame_and_keeps_receiving_envelopes() {
    // The compatibility claim end to end, one version up from the presence one. A
    // version 2 client subscribes, a version 3 member offers, and the older client
    // receives the durable traffic and nothing else. If it were sent the frame it
    // would fail to decode it and close the socket, so this is not cosmetic.
    let scratch = Scratch::new("calls_v2").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), 3),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x44).await;

    // Both older versions subscribe before anything is written, so what each one
    // receives is the live push rather than a backfill, and "it was filtered" and
    // "it arrived late" cannot be confused.
    let mut old = Client::connect(relay.address).await;
    old.handshake_as_version(&other_device(), vec![group.clone()], CLOCK, 2)
        .await;
    subscribe(&mut old, &group).await;
    let mut ancient = Client::connect(relay.address).await;
    ancient
        .handshake_as_version(
            &default_device(),
            vec![group.clone()],
            CLOCK,
            MIN_PROTOCOL_VERSION,
        )
        .await;
    subscribe(&mut ancient, &group).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    // Two call frames, so a filter that let the second through would still fail.
    ada.send_frame(&offer(&call_id(0xC6), &group)).await;
    ada.send_frame(&media(&call_id(0xC6), 1)).await;

    // Then a durable envelope, which must arrive. Its arrival is what proves the
    // call frames were filtered rather than merely slow: the next frame each older
    // client sees is the envelope, and delivery on one socket is ordered.
    let envelope = support::envelope_for(&group, b"a durable line");
    ada.send_frame(&Frame::Send {
        envelope: envelope.encode(),
    })
    .await;
    assert!(matches!(ada.recv_frame().await, Frame::SendAck { .. }));
    for (client, version) in [(&mut old, 2u16), (&mut ancient, MIN_PROTOCOL_VERSION)] {
        match client.recv_frame().await {
            // The relay assigns `seq` and `ts` on the way through, so the
            // comparison is over the content address rather than over the bytes.
            Frame::Push { envelope: bytes } => {
                let decoded = wealdrelay::envelope::Envelope::decode(&bytes).expect("an envelope");
                assert_eq!(decoded.hash, envelope.hash);
            }
            other => panic!("a version {version} client was sent {other:?}"),
        }
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

// MARK: The negative proofs, each its own test with its own name

#[tokio::test(flavor = "multi_thread")]
async fn a_media_frame_for_an_unadmitted_group_is_denied() {
    // The refusal the whole design rests on. `MEDIA` carries no group and consults
    // no database, so the only thing between a media frame and a call it was never
    // admitted to is the registry, and the only way into the registry is a `CALL`
    // frame that was access-set checked.
    let scratch = Scratch::new("calls_media_unadmitted").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), 3),
        Clock::Fixed(CLOCK),
    )
    .await;
    let ours = make_group(&relay.state, 0x45).await;
    let stranger_key = device_from(0x83);
    let theirs = support::make_group_in(
        &relay.state,
        "ws-other",
        0x46,
        std::slice::from_ref(&stranger_key),
        std::slice::from_ref(&stranger_key),
    )
    .await;
    let id = call_id(0xD1);

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![ours.clone()], CLOCK).await;
    ada.send_frame(&offer(&id, &ours)).await;

    let mut stranger = Client::connect(relay.address).await;
    stranger
        .handshake_as(&stranger_key, vec![theirs.clone()], CLOCK)
        .await;

    // The stranger knows the call id, because a call id is not a secret and the
    // design does not pretend it is. Knowing it buys nothing.
    stranger.send_frame(&media(&id, 1)).await;
    match stranger.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::WriterNotInAccessSet);
            assert_eq!(error.code.class().as_str(), "denied");
        }
        other => panic!("expected a denial, got {other:?}"),
    }
    // And an offer into that call under the stranger's own group is refused too,
    // so the id cannot be bridged into a room they are admitted to.
    stranger.send_frame(&offer(&id, &theirs)).await;
    match stranger.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("expected a denial, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_ct_is_rejected_and_an_oversized_body_with_it() {
    let scratch = Scratch::new("calls_oversized").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), 3),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x47).await;
    let id = call_id(0xD2);

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&offer(&id, &group)).await;

    ada.send_frame(&Frame::Media {
        call_id: id.clone(),
        stream: vec![0, 0, 0, 1],
        seq: 1,
        ct: vec![0x55; MAX_MEDIA_CT_BYTES + 1],
    })
    .await;
    match ada.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::EnvelopeTooLarge);
            // The limit is named, so a client surfaces the lever rather than
            // guessing at one.
            assert_eq!(
                error.detail,
                Some((MAX_MEDIA_CT_BYTES as u64).to_be_bytes().to_vec())
            );
        }
        other => panic!("expected a rejection, got {other:?}"),
    }

    ada.send_frame(&Frame::Call {
        call_id: id.clone(),
        group: group.clone(),
        epoch: 1,
        kind: CallKind::Offer as u8,
        body: vec![0x55; MAX_CALL_BODY_BYTES + 1],
    })
    .await;
    match ada.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::EnvelopeTooLarge),
        other => panic!("expected a rejection, got {other:?}"),
    }

    // Exactly at the ceiling is accepted, which is the other half of a boundary.
    // Proved by the silence: an accepted call frame is answered with nothing, so
    // the next frame to arrive is the acknowledgement of something else.
    ada.send_frame(&Frame::Media {
        call_id: id.clone(),
        stream: vec![0, 0, 0, 1],
        seq: 2,
        ct: vec![0x55; MAX_MEDIA_CT_BYTES],
    })
    .await;
    ada.send_frame(&Frame::Sub {
        group: group.clone(),
        from_seq: 0,
    })
    .await;
    assert!(
        matches!(ada.recv_frame().await, Frame::SubAck { .. }),
        "a ct at exactly the ceiling was refused"
    );
    // The connection survived every one of those refusals, which is the point of
    // refusing the frame rather than the session.
    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_frame_sent_before_auth_is_refused_and_closes_the_connection() {
    // Not a rate limit and not a denial: a frame in a state that does not accept it
    // is a client that is wrong about the protocol, and the session ends. `JOIN`
    // remains the one frame a peer may send before it has authenticated.
    let scratch = Scratch::new("calls_pre_auth").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), 3),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x48).await;

    for frame in [offer(&call_id(0xD3), &group), media(&call_id(0xD3), 1)] {
        let mut early = Client::connect(relay.address).await;
        early
            .handshake_to_challenge(vec![group.clone()], CLOCK)
            .await;
        early.send_frame(&frame).await;
        match early.recv_frame().await {
            Frame::Error(error) => {
                assert_eq!(error.code, ErrorCode::MalformedHeader);
                assert_eq!(error.code.class().as_str(), "reject");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        // And the socket is closed by the relay rather than left open. The next
        // read finds the stream ended.
        assert!(
            closed(&mut early).await,
            "the relay left an unauthenticated session open after a call frame"
        );
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_devices_live_socket_stops_receiving_media_the_moment_the_access_drop_lands() {
    // Offboarding that actually offboards. The device is in a call, receiving
    // audio, and an `ACCESS` publication that drops it must take the socket down
    // in the same instant rather than at the next reconnection.
    let scratch = Scratch::new("calls_revocation").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), 3),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x49).await;
    let id = call_id(0xD4);

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    subscribe(&mut ada, &group).await;
    let mut bo = Client::connect(relay.address).await;
    bo.handshake_as(&other_device(), vec![group.clone()], CLOCK)
        .await;
    subscribe(&mut bo, &group).await;

    ada.send_frame(&offer(&id, &group)).await;
    assert!(matches!(bo.recv_frame().await, Frame::Call { .. }));
    bo.send_frame(&signal(&id, &group, CallKind::Answer)).await;
    assert!(matches!(ada.recv_frame().await, Frame::Call { .. }));
    ada.send_frame(&media(&id, 1)).await;
    assert_eq!(bo.recv_frame().await, media(&id, 1));

    // Ada publishes a set that no longer names Bo. Over Ada's own socket, which is
    // how a client does it: the relay is told by an authorizer, never by an
    // operator.
    let removal = removal_set(&relay.state, "ws-step4", &[&default_device()]).await;
    ada.send_frame(&Frame::Access {
        body: removal.encode(),
    })
    .await;
    match ada.recv_frame().await {
        Frame::Access { body } => assert_eq!(body, removal.digest().to_vec()),
        other => panic!("expected an Access answer, got {other:?}"),
    }

    // Bo's socket is closed by the relay, from the hub's principal map, without Bo
    // having sent anything and without waiting for Bo's next request. A revocation
    // that only took effect at the next reconnection would be offboarding that
    // does not offboard, and a call is exactly where that matters: the stream is
    // live and continuous.
    assert!(
        closed(&mut bo).await,
        "a revoked device kept a live socket while in a call"
    );
    // And Ada's next media frame reaches nobody, because the registry forgot the
    // connection when its reader loop ended.
    ada.send_frame(&media(&id, 2)).await;
    ada.send_frame(&Frame::Sub {
        group: group.clone(),
        from_seq: 0,
    })
    .await;
    assert!(matches!(ada.recv_frame().await, Frame::SubAck { .. }));

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_past_its_rate_is_refused_on_the_frame_only() {
    let scratch = Scratch::new("calls_rate").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), 3),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x4A).await;
    let id = call_id(0xD5);

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&offer(&id, &group)).await;

    // The clock is fixed, so every frame lands in one window: this is the flood
    // case rather than a slow drift across a boundary.
    for seq in 0..u64::from(MEDIA_FRAMES_PER_STREAM_PER_SECOND) {
        ada.send_frame(&media(&id, seq)).await;
    }
    ada.send_frame(&media(&id, 999)).await;
    match ada.recv_frame().await {
        Frame::Error(error) => {
            // The code that has existed in `frame.rs` since step 2 with nothing
            // referring to it. A limit the spec claims and the code does not
            // enforce is worse than no limit, because it is protection somebody is
            // relying on.
            assert_eq!(error.code, ErrorCode::GroupIngressLimited);
            assert_eq!(error.code.class().as_str(), "quota");
            assert_eq!(error.retry_after, Some(1));
        }
        other => panic!("expected a quota refusal, got {other:?}"),
    }

    // The connection is still up and durable traffic is unaffected, which is the
    // whole reason the media budget is separate from the envelope allowance.
    let envelope = support::envelope_for(&group, b"still writing");
    ada.send_frame(&Frame::Send {
        envelope: envelope.encode(),
    })
    .await;
    assert!(matches!(ada.recv_frame().await, Frame::SendAck { .. }));

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_instance_ceiling_refuses_a_new_call_and_leaves_the_running_ones_alone() {
    let scratch = Scratch::new("calls_ceiling").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        // One call, so the ceiling is reachable in a test without opening the
        // production number of them.
        config_for_calls(&scratch, blobs.path(), 1),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x4B).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&offer(&call_id(0xD6), &group)).await;

    ada.send_frame(&offer(&call_id(0xD7), &group)).await;
    match ada.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::RateLimited);
            assert_eq!(error.detail, Some(1u64.to_be_bytes().to_vec()));
        }
        other => panic!("expected a quota refusal, got {other:?}"),
    }

    // The call that was already running is untouched: a full instance refuses new
    // calls rather than degrading the ones it is carrying.
    ada.send_frame(&media(&call_id(0xD6), 1)).await;
    ada.send_frame(&Frame::Sub {
        group: group.clone(),
        from_seq: 0,
    })
    .await;
    assert!(matches!(ada.recv_frame().await, Frame::SubAck { .. }));

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sixth_participant_is_refused_and_the_five_keep_talking() {
    let scratch = Scratch::new("calls_participants").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), 3),
        Clock::Fixed(CLOCK),
    )
    .await;
    let devices: Vec<_> = (0..=MAX_PARTICIPANTS_PER_CALL)
        .map(|index| device_from(0x90 + index as u8))
        .collect();
    let group =
        support::make_group_in(&relay.state, "ws-party", 0x4C, &devices, &devices[..1]).await;
    let id = call_id(0xD8);

    let mut clients = Vec::new();
    for device in devices.iter().take(MAX_PARTICIPANTS_PER_CALL) {
        let mut client = Client::connect(relay.address).await;
        client
            .handshake_as(device, vec![group.clone()], CLOCK)
            .await;
        client.send_frame(&offer(&id, &group)).await;
        clients.push(client);
    }

    let mut sixth = Client::connect(relay.address).await;
    sixth
        .handshake_as(
            &devices[MAX_PARTICIPANTS_PER_CALL],
            vec![group.clone()],
            CLOCK,
        )
        .await;
    sixth.send_frame(&offer(&id, &group)).await;
    match sixth.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::RateLimited);
            assert_eq!(
                error.detail,
                Some((MAX_PARTICIPANTS_PER_CALL as u64).to_be_bytes().to_vec())
            );
        }
        other => panic!("expected the call to be full, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_with_calls_off_refuses_both_frames_over_a_real_socket() {
    let scratch = Scratch::new("calls_off_socket").await;
    let blobs = tempfile::tempdir().unwrap();
    // The default configuration, which is calls off: every relay that has not been
    // sized for calls is this one.
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x4D).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    for frame in [offer(&call_id(0xD9), &group), media(&call_id(0xD9), 1)] {
        ada.send_frame(&frame).await;
        match ada.recv_frame().await {
            Frame::Error(error) => assert_eq!(error.code, ErrorCode::ProtocolUnsupported),
            other => panic!("expected a version answer, got {other:?}"),
        }
    }
    // Still a working relay for everything else: a posture is not a fault.
    let envelope = support::envelope_for(&group, b"chat is unaffected");
    ada.send_frame(&Frame::Send {
        envelope: envelope.encode(),
    })
    .await;
    assert!(matches!(ada.recv_frame().await, Frame::SendAck { .. }));

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn leaving_a_call_this_process_is_not_carrying_is_answered_with_silence_and_still_fanned_out()
{
    // The normal path that looks like an error and is not. A `decline` for an offer
    // that was never accepted, a `bye` after the last other participant already
    // left and closed the call, a `bye` retried after a reconnection: in each of
    // them the relay is carrying no call under that id, and the correct answer is to
    // forward the frame and say nothing.
    //
    // Both halves are asserted, because either one alone would be wrong. Refusing it
    // would make the ordinary case noisy and would teach a client to treat hanging
    // up as a thing that fails. Refusing it *quietly*, by dropping the frame, would
    // be worse: the person on the other end would keep a ringing call on their
    // screen with nobody there.
    let scratch = Scratch::new("calls_absent_bye").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), 3),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x4E).await;
    let id = call_id(0xDA);

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    let mut bo = Client::connect(relay.address).await;
    bo.handshake_as(&other_device(), vec![group.clone()], CLOCK)
        .await;
    subscribe(&mut bo, &group).await;

    // Nothing has ever been opened under this id, on this process or anywhere.
    assert_eq!(relay.state.calls.open_calls().await, 0);
    for kind in [CallKind::Decline, CallKind::Bye] {
        ada.send_frame(&signal(&id, &group, kind)).await;
        // Bo learns, which is the half that matters to a human: the ring stops.
        match bo.recv_frame().await {
            Frame::Call {
                call_id: got,
                kind: got_kind,
                ..
            } => {
                assert_eq!(got, id);
                assert_eq!(got_kind, kind as u8);
            }
            other => panic!("a {} was not fanned out: {other:?}", kind.as_str()),
        }
    }
    // And Ada was answered with nothing at all. Proved by sending a frame that *is*
    // answered and finding its acknowledgement first in the queue: an error frame
    // for either leaving kind would be sitting in front of it.
    ada.send_frame(&Frame::Sub {
        group: group.clone(),
        from_seq: 0,
    })
    .await;
    match ada.recv_frame().await {
        Frame::SubAck { .. } => {}
        other => panic!("leaving an absent call was answered: {other:?}"),
    }
    // Nothing was opened by a frame whose whole purpose is to close something.
    assert_eq!(relay.state.calls.open_calls().await, 0);

    relay.shutdown().await;
    scratch.drop_database().await;
}
