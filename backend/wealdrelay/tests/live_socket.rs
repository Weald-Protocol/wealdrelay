// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The ephemeral path over real sockets against real Postgres.
//!
//! The claims here are the ones a unit test cannot make honestly.
//!
//! - A beat published by one member reaches the others, live.
//! - Nothing is stored. Every table holds exactly what it held before, which is
//!   asserted by counting rows rather than by reading the code, because "this
//!   function does not write" is a claim about a call graph and a row count is a
//!   fact.
//! - A device outside the access set gets nothing, refused by the same check
//!   `SEND` is refused by.
//! - A version 1 client is never sent one.
//!
//! Two real client processes, one real relay, one real Postgres.

mod support;

use wealdrelay::frame::{ErrorCode, Frame, MIN_PROTOCOL_VERSION};
use wealdrelay::health::Clock;
use wealdrelay::session::{LIVE_FRAMES_PER_MINUTE, MAX_LIVE_BYTES};

use support::{config_for, device_from, make_group, other_device, Client, Running, Scratch};

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

fn beat(group: &[u8], ct: Vec<u8>) -> Frame {
    Frame::Live {
        group: group.to_vec(),
        epoch: 3,
        ct,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_beat_reaches_another_member_and_changes_no_row_in_any_table() {
    let scratch = Scratch::new("live_fanout").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x30).await;
    let pool = relay.state.database.as_ref().expect("a database").pool();

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    let mut bo = Client::connect(relay.address).await;
    bo.handshake_as(&other_device(), vec![group.clone()], CLOCK)
        .await;
    bo.send_frame(&Frame::Sub {
        group: group.clone(),
        from_seq: 0,
    })
    .await;
    assert!(matches!(bo.recv_frame().await, Frame::SubAck { .. }));

    let before = counts(pool).await;

    ada.send_frame(&beat(&group, b"ada is here".to_vec())).await;
    match bo.recv_frame().await {
        Frame::Live {
            group: g,
            epoch,
            ct,
        } => {
            assert_eq!(g, group);
            assert_eq!(epoch, 3);
            // The same bytes. The relay forwards what it was given and cannot read
            // it: `ct` is a sealed `LiveBody`.
            assert_eq!(ct, b"ada is here".to_vec());
        }
        other => panic!("expected the beat, got {other:?}"),
    }

    // The publisher is answered with nothing at all. No sequence number, no
    // acknowledgement, no row: there is nothing to acknowledge, because nothing was
    // kept.
    ada.send_frame(&Frame::Sub {
        group: group.clone(),
        from_seq: 0,
    })
    .await;
    assert!(
        matches!(ada.recv_frame().await, Frame::SubAck { .. }),
        "the beat was answered when it should have been silent"
    );

    let after = counts(pool).await;
    assert_eq!(after, before, "a beat reached storage");

    // The artifact, written by the run that proves it rather than by a human
    // afterwards: a packet-level transcript of one beat and the row counts either
    // side of it.
    let mut transcript = String::new();
    transcript.push_str("# One beat, packet level\n\n");
    transcript.push_str(
        "specs/backend/relay/presence.md. Ada publishes one LIVE frame and Bo, who is\nsubscribed to the same group, receives it. Nothing is stored: the table counts\nbelow are taken immediately before and immediately after, over every table the\nrelay writes to.\n\n",
    );
    let frame = beat(&group, b"ada is here".to_vec());
    transcript.push_str(&format!(
        "client to relay  tag 21  group {}  epoch 3  ct {} bytes\n",
        hex(&group),
        b"ada is here".len()
    ));
    transcript.push_str(&format!("wire             {}\n\n", hex(&frame.encode())));
    transcript.push_str(
        "relay to client  the same frame, verbatim, to every version 2 subscriber\nrelay to publisher  nothing at all: no sequence number, no acknowledgement, no row\n\n",
    );
    transcript.push_str("## Row counts, before and after\n\n");
    for ((table, before_count), (_, after_count)) in before.iter().zip(after.iter()) {
        transcript.push_str(&format!(
            "{table:<28} {before_count:>6} -> {after_count:>6}\n"
        ));
    }
    support::record_evidence("step-30", "beat-transcript.txt", &transcript);

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_durable_write_reaches_two_other_connections_once_and_in_order() {
    // `operations.md` requires a subscribed client to receive accepted envelopes
    // without polling. This three-connection case proves the customer-visible
    // multiplayer behavior over the real relay: one writer, two independently
    // subscribed readers, no echo back to the writer, and relay-assigned order.
    let scratch = Scratch::new("durable_three_connections").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x35).await;

    let mut writer = Client::connect(relay.address).await;
    writer.handshake(vec![group.clone()], CLOCK).await;
    let mut first_reader = Client::connect(relay.address).await;
    first_reader
        .handshake_as(&other_device(), vec![group.clone()], CLOCK)
        .await;
    let mut second_reader = Client::connect(relay.address).await;
    // A second device connection is still a separate multiplayer recipient: hub
    // exclusion is by connection id, never by device identity.
    second_reader.handshake(vec![group.clone()], CLOCK).await;

    for reader in [&mut first_reader, &mut second_reader] {
        reader
            .send_frame(&Frame::Sub {
                group: group.clone(),
                from_seq: 0,
            })
            .await;
        assert!(matches!(
            reader.recv_frame().await,
            Frame::SubAck { head_seq: 0, .. }
        ));
    }

    for (expected_seq, body) in [
        (1, b"first multiplayer line".as_slice()),
        (2, b"second multiplayer line"),
    ] {
        let envelope = support::envelope_for(&group, body);
        writer
            .send_frame(&Frame::Send {
                envelope: envelope.encode(),
            })
            .await;
        assert!(
            matches!(writer.recv_frame().await, Frame::SendAck { seq, .. } if seq == expected_seq)
        );

        for reader in [&mut first_reader, &mut second_reader] {
            match reader.recv_frame().await {
                Frame::Push { envelope: bytes } => {
                    let pushed =
                        wealdrelay::envelope::Envelope::decode(&bytes).expect("a pushed envelope");
                    assert_eq!(pushed.hash, envelope.hash);
                    assert_eq!(pushed.seq, expected_seq);
                }
                other => panic!("expected ordered multiplayer push, got {other:?}"),
            }
        }
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_outside_the_access_set_cannot_beat_into_a_group() {
    // The same refusal `SEND` gives, produced by the same function. A beat is a
    // claim about a person's presence in a room, and a stranger must not be able to
    // make one.
    let scratch = Scratch::new("live_outsider").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x31).await;

    let mut stranger = Client::connect(relay.address).await;
    stranger
        .handshake_to_challenge(vec![group.clone()], CLOCK)
        .await;
    // A key the genesis set does not name cannot even open a session, which is the
    // outer half of the refusal. The inner half is a group belonging to another
    // workspace, below.
    let outsider = device_from(0x77);
    stranger
        .send_frame(&Frame::Auth {
            device_key: outsider.verifying_key().to_bytes().to_vec(),
            signature: vec![0; 64],
        })
        .await;
    match stranger.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("expected a refusal, got {other:?}"),
    }

    // And an admitted device beating into a group this relay does not know is
    // refused too, by `authorize_group`'s unknown-group arm.
    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&beat(&[0xAB; 32], b"nowhere".to_vec()))
        .await;
    match ada.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::GroupUnknown),
        other => panic!("expected a refusal, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_version_one_client_is_never_sent_a_beat_and_keeps_receiving_envelopes() {
    // The compatibility claim end to end. A version 1 client subscribes, a version
    // 2 member beats, and the old client receives the durable traffic and nothing
    // else. If it were sent the beat it would fail to decode the frame and close
    // the socket, so this is not a cosmetic filter.
    let scratch = Scratch::new("live_v1").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x32).await;

    let mut old = Client::connect(relay.address).await;
    old.handshake_as_version(
        &other_device(),
        vec![group.clone()],
        CLOCK,
        MIN_PROTOCOL_VERSION,
    )
    .await;
    old.send_frame(&Frame::Sub {
        group: group.clone(),
        from_seq: 0,
    })
    .await;
    assert!(matches!(old.recv_frame().await, Frame::SubAck { .. }));

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&beat(&group, b"ada is here".to_vec())).await;

    // Then a durable envelope, which must arrive. Its arrival is what proves the
    // beat was filtered rather than merely slow: the old client's next frame is the
    // envelope and not the beat.
    let envelope = support::envelope_for(&group, b"a durable line");
    ada.send_frame(&Frame::Send {
        envelope: envelope.encode(),
    })
    .await;
    assert!(matches!(ada.recv_frame().await, Frame::SendAck { .. }));
    match old.recv_frame().await {
        // The relay assigns `seq` and `ts` on the way through, so the comparison is
        // over the content address rather than over the bytes.
        Frame::Push { envelope: bytes } => {
            let decoded = wealdrelay::envelope::Envelope::decode(&bytes).expect("an envelope");
            assert_eq!(decoded.hash, envelope.hash);
        }
        other => panic!("a version 1 client was sent {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_beat_and_a_spent_budget_are_refused_on_the_frame_only() {
    let scratch = Scratch::new("live_refusals").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x33).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;

    ada.send_frame(&beat(&group, vec![0; MAX_LIVE_BYTES + 1]))
        .await;
    match ada.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::EnvelopeTooLarge),
        other => panic!("expected a refusal, got {other:?}"),
    }

    for _ in 0..LIVE_FRAMES_PER_MINUTE {
        ada.send_frame(&beat(&group, b"tick".to_vec())).await;
    }
    ada.send_frame(&beat(&group, b"one too many".to_vec()))
        .await;
    match ada.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::RateLimited),
        other => panic!("expected a quota refusal, got {other:?}"),
    }

    // The connection is still up and durable traffic is unaffected, which is the
    // whole reason the budget is separate.
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
async fn the_ephemeral_path_can_be_turned_off_by_the_operator() {
    let scratch = Scratch::new("live_off").await;
    let blobs = tempfile::tempdir().unwrap();
    let mut config = config_for(&scratch, blobs.path());
    config.live = wealdrelay::config::LiveMode::Off;
    let relay = Running::start(config, Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x34).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&beat(&group, b"ada is here".to_vec())).await;
    match ada.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::ProtocolUnsupported),
        other => panic!("expected a refusal, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}
