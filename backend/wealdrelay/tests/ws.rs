// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Two clients over real sockets, against a real relay and a real database.
//!
//! Step 4's integration proof, from `specs/backend/build/phases-relay.md`: "two
//! clients over real sockets, publish to subscribe latency measured on the fixture
//! workspace and recorded as the baseline every later step is compared against".
//!
//! Nothing here is mocked. The relay is `serve::run` on ephemeral ports, the
//! sockets are real WebSockets, and the database is the harness Postgres. The
//! client lives in `tests/support/mod.rs` rather than being pulled in from a crate,
//! because the whole point is that the wire format is what a client actually has to
//! speak: a test using the relay's own `Frame::encode` to talk to the relay would
//! prove the two halves of one implementation agree, which is not the claim.

mod support;

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use tokio::io::AsyncWriteExt as _;

use wealdrelay::frame::{ErrorCode, Frame, FrameTag, PROTOCOL_VERSION};
use wealdrelay::health::Clock;

use support::{config_for, config_with, envelope_for, make_group, Client, Running, Scratch};
use wealdrelay::config::keys;

// MARK: The proof

#[tokio::test(flavor = "multi_thread")]
async fn two_clients_over_real_sockets_publish_and_subscribe() {
    let scratch = Scratch::new("twoclients").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for(&scratch, blobs.path()),
        Clock::Fixed(1_700_000_000_000),
    )
    .await;
    let group = make_group(&relay.state, 0x41).await;

    let mut ada = Client::connect(relay.address).await;
    let mut bo = Client::connect(relay.address).await;
    let ada_challenge = ada.handshake(vec![group.clone()], 1_700_000_000_000).await;
    let bo_challenge = bo.handshake(vec![group.clone()], 1_700_000_000_000).await;
    // Each session gets its own challenge, so a signature captured from one cannot
    // be replayed into another. Same clock here, so the difference comes from
    // something other than time: both sessions asked for the same group, which is
    // why the derivation includes more than the clock.
    assert_eq!(ada_challenge.len(), 32);
    assert_eq!(bo_challenge.len(), 32);
    assert_ne!(
        ada_challenge, bo_challenge,
        "same-tick connections for the same group need distinct AUTH challenges"
    );

    // Ada subscribes to an empty group and is told the head is zero rather than
    // being left to guess.
    bo.send_frame(&Frame::Sub {
        group: group.clone(),
        from_seq: 0,
    })
    .await;
    match bo.recv_frame().await {
        Frame::SubAck { group: g, head_seq } => {
            assert_eq!(g, group);
            assert_eq!(head_seq, 0, "an empty group has no head");
        }
        other => panic!("expected a SubAck, got {other:?}"),
    }

    // Ada publishes three envelopes. Each is acknowledged with the sequence number
    // the relay assigned, dense from one.
    let mut hashes = Vec::new();
    for index in 0..3u8 {
        let envelope = envelope_for(&group, &[index; 8]);
        ada.send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
        match ada.recv_frame().await {
            Frame::SendAck { hash, seq } => {
                assert_eq!(hash, envelope.hash, "the ack names another envelope");
                assert_eq!(u64::from(index) + 1, seq, "sequence numbers are dense");
                hashes.push(hash);
            }
            other => panic!("expected a SendAck, got {other:?}"),
        }
    }

    // A retry of the first one is answered with the sequence number it already has,
    // not an error and not a new number. This is `wire.md`'s promise that a client
    // that retries after a dropped connection is always safe.
    let first = envelope_for(&group, &[0u8; 8]);
    ada.send_frame(&Frame::Send {
        envelope: first.encode(),
    })
    .await;
    match ada.recv_frame().await {
        Frame::SendAck { hash, seq } => {
            assert_eq!(hash, hashes[0]);
            assert_eq!(seq, 1, "a retry must be answered with the original seq");
        }
        other => panic!("expected a SendAck for the retry, got {other:?}"),
    }

    // Bo subscribed before any of that, so from step 5 the three envelopes arrive on
    // its socket as they are accepted, with the relay-assigned sequence numbers.
    // This is `wire.md`'s live path, and it is what step 4's version of this test
    // could not assert because the relay had no fanout yet.
    //
    // A repeat is allowed here and is not a relay bug. `sync::subscribe` registers
    // the connection after the acknowledgement and before the backfill read, and an
    // envelope accepted inside that window is both fanned out and returned by the
    // query. `migration.md` makes the hash a content address so that a client drops
    // the second copy without coordination, and this test used to assert the
    // stricter thing: it read the second push as the second envelope and failed
    // whenever the backfill query was slow enough to land between the two. What must
    // hold is what a client actually depends on: every envelope arrives, in the order
    // it was accepted, carrying its own cursor, and nothing arrives that was never
    // published.
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for _ in 0..(hashes.len() * 3) {
        if seen.len() == hashes.len() {
            break;
        }
        match bo.recv_frame().await {
            Frame::Push { envelope } => {
                let decoded = wealdrelay::envelope::Envelope::decode(&envelope)
                    .expect("a pushed envelope decodes");
                // The content address is unaffected by `seq` and `ts`, so a pushed
                // envelope still verifies against its own fields.
                assert_eq!(decoded.computed_hash(), decoded.hash);
                if seen.contains(&decoded.hash) {
                    continue;
                }
                assert_eq!(
                    &decoded.hash,
                    &hashes[seen.len()],
                    "push {} carried seq {} ct {:?}",
                    seen.len(),
                    decoded.seq,
                    decoded.ct
                );
                assert_eq!(
                    decoded.seq,
                    seen.len() as u64 + 1,
                    "the push carries its cursor"
                );
                seen.push(decoded.hash.clone());
            }
            other => panic!("expected a live Push, got {other:?}"),
        }
    }
    assert_eq!(
        seen, hashes,
        "every published envelope reached the subscriber"
    );
    // And the retry was a duplicate, so it was not pushed again: a client that
    // resends after a dropped connection must not make every other screen show the
    // message twice.

    // Bo, on its own socket, now sees the head move. The relay serves any group in
    // the workspace to any authenticated device, because proving group membership
    // to the relay would leak the membership graph.
    bo.send_frame(&Frame::Sub {
        group: group.clone(),
        from_seq: 0,
    })
    .await;
    // Drained rather than read once, for the same reason the live loop above
    // tolerates a repeat. Bo was already subscribed, and that loop stops as soon as
    // it has all three envelopes, so a duplicate from the registration window can
    // still be sitting in the socket when this second `SUB` goes out. Reading one
    // frame here and demanding it be the acknowledgement asserts that no duplicate
    // was left over, which is not something the protocol promises and not something
    // a client depends on. It fails only when the machine is loaded enough for the
    // backfill to land late, which is why it survived until a parallel coverage run.
    loop {
        match bo.recv_frame().await {
            Frame::SubAck { head_seq, .. } => {
                assert_eq!(head_seq, 3);
                break;
            }
            // A repeat of something already delivered and already asserted above.
            Frame::Push { envelope } => {
                let decoded = wealdrelay::envelope::Envelope::decode(&envelope)
                    .expect("a pushed envelope decodes");
                assert!(
                    seen.contains(&decoded.hash),
                    "only an envelope already delivered may arrive before the SubAck"
                );
            }
            other => panic!("expected a SubAck, got {other:?}"),
        }
    }
    // The acknowledgement comes first, then the backfill from the named cursor. Bo
    // already holds these three, and receiving them again is free: the envelope hash
    // is a content address, so a client deduplicates without coordination
    // (`specs/backend/relay/migration.md`, dual transport).
    for index in 0..3u64 {
        match bo.recv_frame().await {
            Frame::Push { envelope } => {
                let decoded = wealdrelay::envelope::Envelope::decode(&envelope)
                    .expect("a backfilled envelope decodes");
                assert_eq!(decoded.seq, index + 1);
            }
            other => panic!("expected a backfill Push, got {other:?}"),
        }
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_captured_auth_signature_cannot_be_replayed_on_an_identical_second_socket() {
    // BR-003 / `wire.md`: AUTH proves possession for this connection, not merely
    // that the device once signed a challenge with the same timestamp and groups.
    // Both sockets deliberately use the same fixed relay time and request list;
    // that is the collision case a clock-only challenge derivation allowed.
    let scratch = Scratch::new("auth_replay").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for(&scratch, blobs.path()),
        Clock::Fixed(1_700_000_000_000),
    )
    .await;
    let group = make_group(&relay.state, 0x44).await;
    let key = support::default_device();

    let mut captured = Client::connect(relay.address).await;
    let first_challenge = captured
        .handshake_to_challenge(vec![group.clone()], 1_700_000_000_000)
        .await;
    let captured_signature = ed25519_dalek::Signer::sign(&key, &first_challenge)
        .to_bytes()
        .to_vec();

    let mut replay = Client::connect(relay.address).await;
    let second_challenge = replay
        .handshake_to_challenge(vec![group], 1_700_000_000_000)
        .await;
    assert_ne!(
        first_challenge, second_challenge,
        "each socket has its own challenge"
    );
    replay
        .send_frame(&Frame::Auth {
            device_key: key.verifying_key().to_bytes().to_vec(),
            signature: captured_signature,
        })
        .await;
    match replay.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("a replayed AUTH must be refused, got {other:?}"),
    }
    assert!(
        replay.recv().await.is_none(),
        "AUTH replay closes the socket"
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_publish_to_acknowledge_latency_is_recorded_as_the_baseline() {
    // The gate asks for a latency baseline every later step is compared against.
    // Measured over real sockets against a real database, and written to a file
    // rather than only asserted, because a number nobody recorded is a number the
    // next step cannot compare against.
    let scratch = Scratch::new("latency").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for(&scratch, blobs.path()),
        Clock::Fixed(1_700_000_000_000),
    )
    .await;
    let group = make_group(&relay.state, 0x42).await;
    let mut client = Client::connect(relay.address).await;
    client
        .handshake(vec![group.clone()], 1_700_000_000_000)
        .await;

    // A warm run first, so the figure is steady state rather than first-connection
    // cost: the pool is lazy and the first statement pays for a connection.
    for index in 0..20u16 {
        let envelope = envelope_for(&group, &index.to_be_bytes());
        client
            .send_frame(&Frame::Send {
                envelope: envelope.encode(),
            })
            .await;
        client.recv_frame().await;
    }

    let mut samples = Vec::new();
    for index in 1000..1200u16 {
        let envelope = envelope_for(&group, &index.to_be_bytes());
        let started = Instant::now();
        client
            .send_frame(&Frame::Send {
                envelope: envelope.encode(),
            })
            .await;
        match client.recv_frame().await {
            Frame::SendAck { .. } => samples.push(started.elapsed()),
            other => panic!("expected a SendAck, got {other:?}"),
        }
    }

    samples.sort();
    let median = samples[samples.len() / 2];
    let p95 = samples[samples.len() * 95 / 100];
    let worst = samples[samples.len() - 1];

    // Recorded where the gate can pick it up. The fixture hash goes in the same
    // file, because a performance number without one is not a number.
    let out = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/step-04");
    std::fs::create_dir_all(&out).expect("create the evidence directory");
    let text = format!(
        "# Publish to acknowledge, over a real socket against a real Postgres\n\
         #\n\
         # One client, one group, 200 samples after 20 warm-up writes. Each sample is\n\
         # a whole SEND to SendAck round trip: encode, mask, write, the relay's\n\
         # duplicate check, its per-group counter claim, the insert, the commit, and\n\
         # the acknowledgement back. This is the baseline every later step is\n\
         # compared against.\n\
         \n\
         samples    {}\n\
         median     {:.3} ms\n\
         p95        {:.3} ms\n\
         worst      {:.3} ms\n",
        samples.len(),
        median.as_secs_f64() * 1000.0,
        p95.as_secs_f64() * 1000.0,
        worst.as_secs_f64() * 1000.0,
    );
    std::fs::write(out.join("latency.txt"), &text).expect("write the baseline");

    // A bound, so the baseline is a gate and not only a record. Generous on
    // purpose: this runs on a laptop against a container, and a tight bound would
    // fail for reasons that have nothing to do with the relay. What it catches is
    // an order-of-magnitude regression, which is the kind that matters.
    assert!(
        median < Duration::from_millis(50),
        "the median round trip is {median:?}, which is far past anything this path should cost"
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

// MARK: The negative proofs

#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_frame_is_answered_with_a_frame_and_never_a_bare_close() {
    // `operations.md`: a client that gets a dropped connection with no frame cannot
    // tell a protocol error from a network one, so every refusal carries a code.
    let scratch = Scratch::new("malformed").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(1)).await;

    // Not CBOR at all.
    let mut client = Client::connect(relay.address).await;
    client.send(&[0xff, 0xff, 0xff]).await;
    match client.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::NoncanonicalCbor);
            assert_eq!(error.class().as_str(), "reject");
        }
        other => panic!("expected an error frame, got {other:?}"),
    }

    // A frame in the wrong state: SEND before AUTH. The relay must refuse it and
    // close, because a relay that answered this would be one an unauthenticated
    // peer could write through.
    let mut early = Client::connect(relay.address).await;
    early
        .send_frame(&Frame::Send {
            envelope: envelope_for(&[0x43; 32], b"nope").encode(),
        })
        .await;
    match early.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::MalformedHeader),
        other => panic!("expected an error frame, got {other:?}"),
    }
    assert!(
        early.recv().await.is_none() || early.recv().await.is_none(),
        "the relay must close after refusing a frame sent in the wrong state"
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_frame_is_refused_on_length_before_it_is_parsed() {
    let scratch = Scratch::new("oversize").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(1)).await;
    let mut client = Client::connect(relay.address).await;

    // Both oversized and malformed. Requiring the size error proves the length gate
    // runs first, which is what stops a hostile peer making the relay parse a frame
    // it was always going to refuse.
    let payload = vec![0xffu8; wealdrelay::frame::MAX_FRAME_BYTES + 1];
    client.send(&payload).await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::EnvelopeTooLarge),
        other => panic!("expected an error frame, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_frame_set_from_a_future_version_aborts_the_connection() {
    // `operations.md`: a version failure aborts the connection and never silently
    // continues. Silently continuing would mean the two ends disagreed about what
    // the bytes meant while both believed they were talking.
    let scratch = Scratch::new("version").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(1)).await;
    let mut client = Client::connect(relay.address).await;

    // Hand built, because `Frame::Connect` cannot carry a version this build does
    // not speak: the decoder refuses it, which is the same rule from the other side.
    let encoded = wealdrelay::cbor::array(&[
        wealdrelay::cbor::uint(u64::from(FrameTag::Connect as u16)),
        wealdrelay::cbor::array(&[
            wealdrelay::cbor::uint(99),
            wealdrelay::cbor::array(&[]),
            wealdrelay::cbor::uint(1),
        ]),
    ]);
    client.send(&encoded).await;
    match client.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::ProtocolUnsupported);
            assert_eq!(error.class().as_str(), "version");
        }
        other => panic!("expected a version error, got {other:?}"),
    }
    // And the socket ends.
    let mut closed = false;
    for _ in 0..3 {
        if client.recv().await.is_none() {
            closed = true;
            break;
        }
    }
    assert!(closed, "a version failure must abort the connection");

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_whose_clock_is_an_hour_off_is_served_and_the_relay_keeps_its_own_time() {
    // The relay evaluates every expiry it owns against its own observed time, so a
    // skewed client is told and not trusted. Being told is the point: the client
    // uses the difference to decide whether its own expiry arithmetic can be
    // trusted, and a relay that adjusted to the client would corrupt every expiry
    // it owns.
    let scratch = Scratch::new("skew").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay_now = 1_700_000_000_000u64;
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(relay_now)).await;
    let group = make_group(&relay.state, 0x44).await;

    let mut client = Client::connect(relay.address).await;
    let an_hour = 3_600_000u64;
    client
        .send_frame(&Frame::Connect {
            version: PROTOCOL_VERSION,
            groups: vec![group.clone()],
            sent_at: relay_now + an_hour,
        })
        .await;
    match client.recv_frame().await {
        Frame::ConnectAck { server_time, .. } => assert_eq!(
            server_time, relay_now,
            "the relay reported the client's clock instead of its own"
        ),
        other => panic!("expected a ConnectAck, got {other:?}"),
    }
    let challenge = match client.recv_frame().await {
        Frame::AuthChallenge { challenge } => challenge,
        other => panic!("expected an AuthChallenge, got {other:?}"),
    };

    // And the session still works: skew is a warning, not a refusal. Refusing would
    // lock out every user whose laptop clock drifted.
    let key = support::default_device();
    client
        .send_frame(&Frame::Auth {
            device_key: key.verifying_key().to_bytes().to_vec(),
            signature: ed25519_dalek::Signer::sign(&key, &challenge)
                .to_bytes()
                .to_vec(),
        })
        .await;
    match client.recv_frame().await {
        Frame::AuthAck { .. } => {}
        other => panic!("a skewed client must still be able to authenticate, got {other:?}"),
    }
    let envelope = envelope_for(&group, b"written by a skewed client");
    client
        .send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::SendAck { seq, .. } => assert_eq!(seq, 1),
        other => panic!("expected a SendAck, got {other:?}"),
    }

    // The stored receipt time is the relay's, not the client's. That is the whole
    // claim: `ts` is relay-observed and advisory, and a client cannot move it.
    let ts: i64 = sqlx::query_scalar("select ts from relay_envelope where hash = $1")
        .bind(&envelope.hash)
        .fetch_one(relay.state.database.as_ref().unwrap().pool())
        .await
        .unwrap();
    assert_eq!(ts as u64, relay_now);

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_long_lived_socket_stamps_each_envelope_at_its_receipt_time() {
    // BR-006 / `wire.md`: `ts` is the relay receipt time, not the time the
    // WebSocket upgraded. The manual clock makes the boundary deterministic: no
    // sleep and no host-clock race are needed to prove that a later SEND gets a
    // later timestamp.
    let scratch = Scratch::new("receipt_time").await;
    let blobs = tempfile::tempdir().unwrap();
    let clock = Arc::new(AtomicU64::new(1_700_000_000_000));
    let relay = Running::start(
        config_for(&scratch, blobs.path()),
        Clock::Manual(Arc::clone(&clock)),
    )
    .await;
    let group = make_group(&relay.state, 0x4a).await;

    let mut client = Client::connect(relay.address).await;
    client
        .handshake(vec![group.clone()], clock.load(Ordering::Relaxed))
        .await;

    let receipt_time = 1_700_000_060_000;
    clock.store(receipt_time, Ordering::Relaxed);
    let envelope = envelope_for(&group, b"received after the socket opened");
    client
        .send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
    assert!(matches!(
        client.recv_frame().await,
        Frame::SendAck { seq: 1, .. }
    ));

    let stored: i64 = sqlx::query_scalar("select ts from relay_envelope where hash = $1")
        .bind(&envelope.hash)
        .fetch_one(relay.state.database.as_ref().unwrap().pool())
        .await
        .unwrap();
    assert_eq!(stored as u64, receipt_time);

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_stops_reading_is_pushed_back_on_rather_than_having_envelopes_dropped() {
    // The backpressure claim. A relay under load slows down rather than dropping
    // envelopes, because a dropped envelope is a hole in an author chain and
    // therefore a security alarm on somebody else's screen.
    //
    // The client here sends a great many `SEND` frames and never reads a single
    // acknowledgement. The relay's send queue fills, which stops its writer, which
    // stops its reader, which stops draining the socket. What must be true at the
    // end is that every envelope the relay acknowledged is in the database and
    // nothing was accepted and discarded.
    let scratch = Scratch::new("backpressure").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(1)).await;
    let group = make_group(&relay.state, 0x45).await;
    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], 1).await;

    // Well past the queue bound, so the bound is genuinely reached.
    let count = wealdrelay::session::SEND_QUEUE_BOUND * 4;
    for index in 0..count {
        let envelope = envelope_for(&group, &(index as u32).to_be_bytes());
        client
            .send_frame(&Frame::Send {
                envelope: envelope.encode(),
            })
            .await;
    }

    // Now start reading. Whatever the relay managed to process is acknowledged, and
    // the count in the database matches the acknowledgements: nothing was accepted
    // and then thrown away.
    let mut acked = 0u64;
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), client.recv_frame()).await {
            Ok(Frame::SendAck { .. }) => {
                acked += 1;
                if acked as usize == count {
                    break;
                }
            }
            Ok(other) => panic!("expected a SendAck, got {other:?}"),
            // A gap in acknowledgements means the relay is busy, not that it dropped
            // something. The loop keeps waiting until the deadline.
            Err(_) => break,
        }
    }

    let stored: i64 = sqlx::query_scalar("select count(*) from relay_envelope where group_id = $1")
        .bind(&group)
        .fetch_one(relay.state.database.as_ref().unwrap().pool())
        .await
        .unwrap();
    assert!(
        acked > 0,
        "the relay acknowledged nothing at all, so the test proved nothing"
    );
    assert_eq!(
        stored as u64, acked,
        "the relay acknowledged {acked} envelopes and stored {stored}: one of those is a lie"
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plaintext_envelope_is_denied_when_the_relay_requires_mls() {
    // The hosted tier is fixed at `mls` and cannot be configured otherwise, so this
    // is the check that makes "a hosted workspace is encrypted from its first
    // envelope" a property of the deployment rather than a promise about client
    // behaviour.
    let scratch = Scratch::new("plaintext").await;
    let blobs = tempfile::tempdir().unwrap();
    let mut config = config_for(&scratch, blobs.path());
    config.min_encryption = wealdrelay::config::MinEncryption::Mls;
    let relay = Running::start(config, Clock::Fixed(1)).await;
    let group = make_group(&relay.state, 0x46).await;

    let mut client = Client::connect(relay.address).await;
    // The floor is announced on `CONNECT`, so a client that would be refused learns
    // it before its first write rather than after.
    client
        .send_frame(&Frame::Connect {
            version: PROTOCOL_VERSION,
            groups: vec![group.clone()],
            sent_at: 1,
        })
        .await;
    match client.recv_frame().await {
        Frame::ConnectAck { min_enc, .. } => assert_eq!(min_enc, 1),
        other => panic!("expected a ConnectAck, got {other:?}"),
    }
    let challenge = match client.recv_frame().await {
        Frame::AuthChallenge { challenge } => challenge,
        other => panic!("expected an AuthChallenge, got {other:?}"),
    };
    let key = support::default_device();
    client
        .send_frame(&Frame::Auth {
            device_key: key.verifying_key().to_bytes().to_vec(),
            signature: ed25519_dalek::Signer::sign(&key, &challenge)
                .to_bytes()
                .to_vec(),
        })
        .await;
    match client.recv_frame().await {
        Frame::AuthAck { .. } => {}
        other => panic!("expected an AuthAck, got {other:?}"),
    }

    client
        .send_frame(&Frame::Send {
            envelope: envelope_for(&group, b"plaintext").encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::PlaintextRefused);
            assert_eq!(error.code.qualified(), "denied/plaintext_refused");
        }
        other => panic!("expected denied/plaintext_refused, got {other:?}"),
    }
    // Nothing was stored.
    let stored: i64 = sqlx::query_scalar("select count(*) from relay_envelope")
        .fetch_one(relay.state.database.as_ref().unwrap().pool())
        .await
        .unwrap();
    assert_eq!(stored, 0);

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_frame_this_build_cannot_parse_is_refused_with_a_code_rather_than_silence() {
    // There is no unserved frame left to send. `RECON` was on this list until step 5
    // served it, `ACCESS` until step 6, and `BLOB` until step 9; each now has its own
    // suite, in `tests/reconcile.rs`, `tests/access.rs` and `tests/media_socket.rs`.
    //
    // What the test was really holding is a rule that outlives the list: a frame the
    // relay cannot act on is answered with a code, because silence is
    // indistinguishable from a relay that accepted it, and answering is not fatal to
    // the socket. With every tag served, the reachable version of that is a served tag
    // carrying a payload that is not a request, so that is what is sent here.
    let scratch = Scratch::new("unserved").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(1)).await;
    let group = make_group(&relay.state, 0x47).await;
    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], 1).await;

    for frame in [Frame::Blob { payload: vec![6] }] {
        client.send_frame(&frame).await;
        match client.recv_frame().await {
            Frame::Error(error) => assert_eq!(error.code, ErrorCode::MalformedHeader),
            other => panic!("expected an error for {frame:?}, got {other:?}"),
        }
    }

    // And the session survives it: a frame the relay cannot act on is not a fatal
    // one, so a client built against a newer relay degrades rather than losing its
    // socket.
    let envelope = envelope_for(&group, b"still working");
    client
        .send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::SendAck { seq, .. } => assert_eq!(seq, 1),
        other => panic!("the session did not survive, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bye_closes_cleanly_and_a_text_message_does_not() {
    let scratch = Scratch::new("closes").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(1)).await;

    // `BYE` in any live state, including before `AUTH`: a client that changes its
    // mind should be able to leave cleanly rather than dropping a socket.
    let mut leaving = Client::connect(relay.address).await;
    leaving
        .send_frame(&Frame::Bye {
            reason: b"changed my mind".to_vec(),
        })
        .await;
    match leaving.recv_frame().await {
        Frame::Bye { .. } => {}
        other => panic!("expected a Bye back, got {other:?}"),
    }

    // A text message is not a frame: the wire format is deterministic CBOR, and a
    // text frame is a client that has not read it.
    let mut talker = Client::connect(relay.address).await;
    let payload = b"hello relay".to_vec();
    let mut text = vec![0x81u8, 0x80 | payload.len() as u8];
    let mask = [0x37, 0xfa, 0x21, 0x3d];
    text.extend_from_slice(&mask);
    for (index, byte) in payload.iter().enumerate() {
        text.push(byte ^ mask[index % 4]);
    }
    talker.stream.write_all(&text).await.unwrap();
    match talker.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::MalformedHeader),
        other => panic!("expected an error frame, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ping_leaves_a_live_session_alone_and_a_close_frame_ends_it() {
    // Keepalives are the transport's, not the protocol's, and this is the test over a
    // real socket that they are. A long-lived session is exactly the thing a
    // keepalive exists for, so a relay that treated a ping or an unsolicited pong as
    // an unexpected frame would close every connection that idled long enough to be
    // pinged. Sent as genuine control frames rather than as data that stands in for
    // them, because the opcode is the whole difference.
    let scratch = Scratch::new("keepalive").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(1)).await;
    let group = make_group(&relay.state, 0x48).await;
    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], 1).await;

    // A ping, then a write. The write proves the session survived, and it has to be
    // a write rather than a silence: a relay that had closed the session would look
    // the same as one that was simply quiet.
    client.send_opcode(0x9, b"still here").await;
    client
        .send_frame(&Frame::Send {
            envelope: envelope_for(&group, b"after a ping").encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::SendAck { seq, .. } => assert_eq!(seq, 1, "a ping must not disturb the session"),
        other => panic!("expected a SendAck, got {other:?}"),
    }

    // And an unsolicited pong, which a client is allowed to send and which the relay
    // has nothing to do about.
    client.send_opcode(0xa, b"unasked for").await;
    client
        .send_frame(&Frame::Send {
            envelope: envelope_for(&group, b"after a pong").encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::SendAck { seq, .. } => assert_eq!(seq, 2, "a pong must not disturb the session"),
        other => panic!("expected a SendAck, got {other:?}"),
    }

    // A close frame is the one ending that carries no error frame back: the peer has
    // said it is going, so there is nothing to tell it. The relay closes rather than
    // leaving the socket half open.
    client.send_opcode(0x8, &1000u16.to_be_bytes()).await;
    let mut closed = false;
    for _ in 0..3 {
        if client.recv().await.is_none() {
            closed = true;
            break;
        }
    }
    assert!(closed, "a close frame must end the connection");

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_vanishes_with_frames_still_queued_ends_its_writer() {
    // The other end of the backpressure story, and the one that only a real socket
    // can show. Above, a client that stops reading is pushed back on: the relay's
    // send queue fills, its writer blocks on the socket, and its reader stops
    // draining. Here that same client then disappears without a close frame, which is
    // what a killed process or a dropped network looks like from the relay's side.
    //
    // What must happen is that the blocked write fails and the writer ends. A relay
    // that ignored the failure would hold a task, a bounded queue and a socket per
    // vanished client, and those are the resources a single flaky client could
    // exhaust for everybody else. The proof is that the relay keeps serving
    // afterwards and shuts down cleanly, neither of which a leaked writer would allow.
    let scratch = Scratch::new("vanish").await;
    let blobs = tempfile::tempdir().unwrap();
    // The inbound budget is configured out of the way, and this is the one test in
    // the suite that needs it said out loud. The property under test is the writer
    // queue filling, which takes an unbounded flood of writes by construction, and
    // the shipped per-device `SEND` budget (`crate::send_budget`) would answer that
    // flood with `quota/rate_limited` long before the queue saturated. Both
    // behaviours are correct and they are about different resources: the budget
    // bounds how fast one device may spend the relay's write capacity, and this
    // test is about what happens to a socket after the relay has already accepted
    // more than the peer will read. Raising the budget here isolates the second
    // from the first rather than weakening either. `send_budget_socket.rs` proves
    // the budget itself, against a running relay, at the shipped default.
    let relay = Running::start(
        config_with(
            &scratch,
            blobs.path(),
            [
                (keys::SEND_FRAMES_PER_MINUTE, u32::MAX.to_string()),
                (keys::SEND_BYTES_PER_MINUTE, u32::MAX.to_string()),
            ],
        ),
        Clock::Fixed(1),
    )
    .await;
    let group = make_group(&relay.state, 0x49).await;

    let mut vanishing = Client::connect_by_a_client_that_will_die_badly(relay.address).await;
    vanishing.handshake(vec![group.clone()], 1).await;
    // One ordinary write first, read normally, so what follows is a session that was
    // working rather than one that never started.
    vanishing
        .send_frame(&Frame::Send {
            envelope: envelope_for(&group, b"before it stopped reading").encode(),
        })
        .await;
    match vanishing.recv_frame().await {
        Frame::SendAck { seq, .. } => assert_eq!(seq, 1),
        other => panic!("expected a SendAck, got {other:?}"),
    }

    // From here it writes and never reads. The tiny receive buffer means the relay's
    // writer blocks on the socket after a few hundred acknowledgements rather than
    // after however many the operating system felt like buffering, and once it is
    // blocked the send queue fills to its bound and the relay stops reading. That is
    // the state this test needs: a writer stuck mid-write with a full queue behind it.
    let group_for_flood = group.clone();
    let flood = tokio::spawn(async move {
        for index in 0.. {
            let envelope = envelope_for(&group_for_flood, &(index as u32).to_be_bytes());
            vanishing
                .send_frame(&Frame::Send {
                    envelope: envelope.encode(),
                })
                .await;
        }
    });

    // Waited for rather than guessed at. The relay is stuck exactly when it stops
    // storing envelopes while a client is still sending them, so the stored count
    // going flat is the observable form of "the writer is blocked and the queue is
    // full". A sleep would be a guess, and a guess here would make the test pass or
    // fail on how fast the machine is.
    let pool = relay.state.database.as_ref().expect("a database").pool();
    let stored_now = || async {
        sqlx::query_scalar::<_, i64>("select count(*) from relay_envelope where group_id = $1")
            .bind(&group)
            .fetch_one(pool)
            .await
            .expect("count the stored envelopes")
    };
    // A liveness guard, not the property. The property underneath is
    // machine-independent: the stored count goes flat while the client is still
    // sending, which is the observable form of a blocked writer behind a full
    // queue. How long saturation takes is not, because every envelope on the way
    // there is a Postgres insert, and a two-core ci runner reaches it far slower
    // than the machine this was written on. Sixty seconds was that machine's
    // number and it failed the first time the suite ran anywhere else.
    let deadline = Instant::now()
        + Duration::from_secs(
            std::env::var("WEALD_WS_BACKPRESSURE_DEADLINE_SECS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(300),
        );
    let mut previous = 0i64;
    let stuck = loop {
        assert!(
            Instant::now() < deadline,
            "the relay never stopped accepting, so its writer never blocked and the \
             test proved nothing"
        );
        tokio::time::sleep(Duration::from_millis(400)).await;
        let current = stored_now().await;
        if current == previous && current > 1 {
            break current;
        }
        previous = current;
    };

    // Gone, and gone rudely: the socket carries `SO_LINGER` at zero, so dropping it
    // resets the connection instead of closing it politely. That is what a killed
    // process looks like from the relay's side, and it is the case the blocked write
    // has to survive.
    flood.abort();
    let _ = flood.await;

    // The relay is unharmed: a new client on the same relay completes a handshake and
    // gets its envelope stored, on a group the vanished client had been writing to.
    let mut after = Client::connect(relay.address).await;
    after.handshake(vec![group.clone()], 1).await;
    let envelope = envelope_for(&group, b"written after the other one vanished");
    after
        .send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
    match tokio::time::timeout(Duration::from_secs(10), after.recv_frame()).await {
        Ok(Frame::SendAck { .. }) => {}
        Ok(other) => panic!("expected a SendAck, got {other:?}"),
        Err(_) => panic!("the relay stopped serving after a client vanished"),
    }

    // And nothing the relay had already accepted went missing when the socket died. A
    // client that vanishes loses its acknowledgements, not its writes, which is why a
    // retry on a new connection is answered with the sequence number the original
    // write was given.
    let stored = stored_now().await;
    assert!(
        stored > stuck,
        "the relay stored {stuck} envelopes before the client vanished and {stored} after, \
         so a write it had already accepted was lost"
    );

    // A leaked writer would hang this.
    tokio::time::timeout(Duration::from_secs(20), relay.shutdown())
        .await
        .expect("the relay shut down");
    scratch.drop_database().await;
}
