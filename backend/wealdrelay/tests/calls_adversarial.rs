// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Hand-constructed hostile call frames, against a real relay.
//!
//! The shape `specs/agents/networked/ledger.json` uses for its fifth gate, and
//! the reason it is a separate suite from the negative proofs is the reason that
//! ledger gives: a negative proof asks whether a legitimate client that got
//! something wrong is answered correctly, and an adversarial proof asks whether a
//! peer trying to get something is stopped. The frames below are built byte by
//! byte rather than generated, because a generator explores the space a
//! well-formed encoder can reach and an attacker is not using our encoder.
//!
//! Every case here is a thing somebody would actually try:
//!
//! - a call id colliding with another session's, to bridge two rooms
//! - one media frame replayed a thousand times, to see whether the relay keeps
//!   any per-frame state an attacker could exhaust
//! - a `CALL` naming a group the sender can see and is not admitted to
//! - a declared length that disagrees with the actual length
//! - a client that opens the maximum number of groups and starts a call in each
//!
//! ## Fuzzing
//!
//! No fuzz target is added to `backend/weald-mls/fuzz`. That corpus fuzzes the
//! MLS C ABI, where the input is an attacker-controlled buffer crossing a memory
//! unsafe boundary. The call frames cross no such boundary: they are read by
//! `src/cbor.rs`, which is safe Rust with no unsafe block and no allocation
//! before a length check, and its whole input space is already covered by the
//! `proptest` round trip in `tests/calls_unit.rs` plus the hand-built rejections
//! here. A fuzz target over a safe parser with a property test already on it
//! would add run time rather than coverage.

mod support;

use wealdrelay::calls::{CallKind, MAX_MEDIA_CT_BYTES};
use wealdrelay::cbor;
use wealdrelay::frame::{ErrorCode, Frame, FrameTag};
use wealdrelay::health::Clock;
use wealdrelay::session::MAX_GROUPS_PER_CONNECTION;

use support::{config_for_calls, device_from, make_group, other_device, Client, Running, Scratch};

const CLOCK: u64 = 1_700_000_000_000;

fn call_id(seed: u8) -> Vec<u8> {
    vec![seed; 16]
}

fn offer(id: &[u8], group: &[u8]) -> Frame {
    Frame::Call {
        call_id: id.to_vec(),
        group: group.to_vec(),
        epoch: 3,
        kind: CallKind::Offer as u8,
        body: b"sealed".to_vec(),
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

#[tokio::test(flavor = "multi_thread")]
async fn a_call_id_colliding_with_another_sessions_cannot_bridge_two_rooms() {
    // The attack the registry's group check exists for. Two workspaces on one
    // relay, and a device admitted to the second guesses or observes a call id
    // from the first. Both of its groups are legitimate for it; the answer is
    // still no, because a call is a conversation inside one room and the id was
    // bound to that room when the call opened.
    let scratch = Scratch::new("calls_adv_collision").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), 8),
        Clock::Fixed(CLOCK),
    )
    .await;
    let ours = make_group(&relay.state, 0x60).await;
    let attacker_key = device_from(0xA1);
    let theirs = support::make_group_in(
        &relay.state,
        "ws-adv",
        0x61,
        std::slice::from_ref(&attacker_key),
        std::slice::from_ref(&attacker_key),
    )
    .await;
    let id = call_id(0xE1);

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![ours.clone()], CLOCK).await;
    ada.send_frame(&offer(&id, &ours)).await;

    let mut attacker = Client::connect(relay.address).await;
    attacker
        .handshake_as(&attacker_key, vec![theirs.clone()], CLOCK)
        .await;

    // Under the attacker's own group, which they are genuinely admitted to.
    attacker.send_frame(&offer(&id, &theirs)).await;
    match attacker.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::WriterNotInAccessSet);
            // Denied, not quota. The class matters: `quota` tells a client to
            // retry after an interval, and retrying this forever is exactly what
            // an attacker would do if we told them to.
            assert_eq!(error.code.class().as_str(), "denied");
            assert!(!error.code.class().is_retryable());
        }
        other => panic!("a colliding call id was not refused: {other:?}"),
    }
    // And under Ada's group, which they are not admitted to, for completeness:
    // both doors are shut, by two different checks.
    attacker.send_frame(&offer(&id, &ours)).await;
    match attacker.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("expected a denial, got {other:?}"),
    }
    // Media under the id buys nothing either: the attacker never joined.
    attacker.send_frame(&media(&id, 1)).await;
    match attacker.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("expected a denial, got {other:?}"),
    }
    // The call the attacker was reaching for is untouched: still one call, still
    // Ada's, still in Ada's group.
    assert_eq!(relay.state.calls.open_calls().await, 1);
    assert_eq!(
        relay
            .state
            .calls
            .group_of(&<[u8; 16]>::try_from(id.as_slice()).unwrap())
            .await,
        Some(ours)
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn one_media_frame_replayed_a_thousand_times_is_rate_limited_and_keeps_no_state() {
    // Two claims. The first is that replay is not special: the relay copies `seq`
    // and never interprets it, so a thousand copies of frame 7 are a thousand
    // frames, refused by the rate limit like any other flood rather than by a
    // dedupe table. The second is that no per-frame state accumulates, which is
    // what a dedupe table would be and what an attacker would fill.
    let scratch = Scratch::new("calls_adv_replay").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), 8),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x62).await;
    let id = call_id(0xE2);

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&offer(&id, &group)).await;

    let replayed = media(&id, 7);
    for _ in 0..1000 {
        ada.send_frame(&replayed).await;
    }
    // Exactly one refusal comes back, not nine hundred and forty. Answering every
    // frame of a flood is an amplifier, and the answers would be queued on the
    // flooder's own bounded outbound queue, so a relay that complained about each
    // one would fill that queue and drop the connection: a rate limit that turns
    // into a disconnect is a denial of service an attacker can aim at somebody
    // else's call. `MediaBudget::refusal_to_report` allows one per second.
    let mut refusals = 0;
    let mut acknowledged = false;
    let envelope = support::envelope_for(&group, b"unaffected");
    ada.send_frame(&Frame::Send {
        envelope: envelope.encode(),
    })
    .await;
    while !acknowledged {
        match ada.recv_frame().await {
            Frame::Error(error) => {
                assert_eq!(error.code, ErrorCode::GroupIngressLimited);
                assert_eq!(error.retry_after, Some(1));
                refusals += 1;
            }
            // The session is alive and durable traffic still works, which is the
            // whole reason the media budget is separate from the envelope one.
            Frame::SendAck { .. } => acknowledged = true,
            other => panic!("expected a refusal or the acknowledgement, got {other:?}"),
        }
    }
    assert_eq!(
        refusals, 1,
        "the relay answered a flood frame by frame, which is an amplifier"
    );
    // And exactly one call is open, holding exactly the one participant. A relay
    // keeping anything per frame would show it here.
    assert_eq!(relay.state.calls.open_calls().await, 1);

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_claiming_a_visible_group_the_sender_is_not_admitted_to_is_denied() {
    // "Visible" is the point. Group ids are not secrets: they appear in `CONNECT`,
    // and a member of one workspace on a shared relay may well learn another's.
    // Knowing the id buys nothing, because admission is checked against the
    // workspace that admitted the socket rather than against what the frame
    // asserts.
    let scratch = Scratch::new("calls_adv_visible").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), 8),
        Clock::Fixed(CLOCK),
    )
    .await;
    let ours = make_group(&relay.state, 0x63).await;
    let attacker_key = device_from(0xA2);
    let theirs = support::make_group_in(
        &relay.state,
        "ws-adv2",
        0x64,
        std::slice::from_ref(&attacker_key),
        std::slice::from_ref(&attacker_key),
    )
    .await;

    let mut attacker = Client::connect(relay.address).await;
    // Naming the victim's group in `CONNECT` does not help either: `CONNECT`
    // groups are advisory and admission resolves the workspace from the relay's
    // own table.
    attacker
        .handshake_as(&attacker_key, vec![theirs.clone(), ours.clone()], CLOCK)
        .await;
    attacker.send_frame(&offer(&call_id(0xE3), &ours)).await;
    match attacker.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("expected a denial, got {other:?}"),
    }
    assert_eq!(relay.state.calls.open_calls().await, 0);

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declared_length_that_disagrees_with_the_actual_length_is_refused() {
    // Four shapes of the same lie, each built by hand. A decoder that trusted the
    // declaration would read past the buffer; a decoder that trusted the buffer
    // would let a peer smuggle bytes past every length check the relay has.
    let scratch = Scratch::new("calls_adv_length").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), 8),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x65).await;

    // A byte string whose header claims more than follows.
    let mut over_declared = vec![0x82];
    over_declared.extend_from_slice(&cbor::uint(FrameTag::Media as u64));
    over_declared.push(0x84);
    over_declared.push(0x50); // 16-byte string
    over_declared.extend_from_slice(&[0xE4; 8]); // but only eight bytes follow
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "a byte string shorter than its header claims",
            over_declared,
        ),
        ("a ct whose header claims a megabyte and carries nothing", {
            let mut bytes = vec![0x82];
            bytes.extend_from_slice(&cbor::uint(FrameTag::Media as u64));
            bytes.push(0x84);
            bytes.extend_from_slice(&cbor::bytes(&call_id(0xE4)));
            bytes.extend_from_slice(&cbor::bytes(&[0, 0, 0, 1]));
            bytes.extend_from_slice(&cbor::uint(1));
            // 0x5a followed by a four-byte length of one mebibyte.
            bytes.extend_from_slice(&[0x5a, 0x00, 0x10, 0x00, 0x00]);
            bytes
        }),
        ("an array header claiming five fields with four present", {
            let mut bytes = vec![0x82];
            bytes.extend_from_slice(&cbor::uint(FrameTag::Call as u64));
            bytes.push(0x85);
            bytes.extend_from_slice(&cbor::bytes(&call_id(0xE4)));
            bytes.extend_from_slice(&cbor::bytes(&[0x65; 32]));
            bytes.extend_from_slice(&cbor::uint(1));
            bytes.extend_from_slice(&cbor::uint(1));
            bytes
        }),
        (
            "an indefinite-length byte string, which this wire format does not carry",
            {
                let mut bytes = vec![0x82];
                bytes.extend_from_slice(&cbor::uint(FrameTag::Media as u64));
                bytes.push(0x84);
                bytes.push(0x5f); // indefinite length
                bytes.extend_from_slice(&[0x41, 0xE4, 0xff]);
                bytes.extend_from_slice(&cbor::bytes(&[0, 0, 0, 1]));
                bytes.extend_from_slice(&cbor::uint(1));
                bytes.extend_from_slice(&cbor::bytes(b"x"));
                bytes
            },
        ),
    ];

    for (what, bytes) in cases {
        let mut client = Client::connect(relay.address).await;
        client.handshake(vec![group.clone()], CLOCK).await;
        client.send(&bytes).await;
        match client.recv_frame().await {
            Frame::Error(error) => assert_eq!(
                error.code,
                ErrorCode::NoncanonicalCbor,
                "{what}: wrong code"
            ),
            other => panic!("{what}: expected a rejection, got {other:?}"),
        }
        // One bad frame is not a bad session: the connection continues, which is
        // what `operations.md` says a `reject` means for everything but a version
        // failure.
        client
            .send_frame(&Frame::Sub {
                group: group.clone(),
                from_seq: 0,
            })
            .await;
        assert!(
            matches!(client.recv_frame().await, Frame::SubAck { .. }),
            "{what}: the session did not survive one bad frame"
        );
    }

    // Nothing opened a call along the way.
    assert_eq!(relay.state.calls.open_calls().await, 0);

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_opening_every_group_it_may_and_a_call_in_each_is_stopped_by_the_ceiling() {
    // The resource-exhaustion case. One socket, the maximum groups a connection
    // may name, and a call in each. What must hold is that the instance ceiling
    // binds rather than the client's ambition, that the refusals name the ceiling,
    // and that the process is still serving afterwards.
    let scratch = Scratch::new("calls_adv_many").await;
    let blobs = tempfile::tempdir().unwrap();
    let ceiling = 4u32;
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), ceiling),
        Clock::Fixed(CLOCK),
    )
    .await;
    // One group is enough to prove the ceiling: the attacker's leverage is the
    // number of call ids, not the number of groups, because a call id is what
    // consumes a slot. The group count is exercised on the same socket below.
    let group = make_group(&relay.state, 0x66).await;

    let mut attacker = Client::connect(relay.address).await;
    // The maximum a `CONNECT` may name, which is the widest the client can make
    // its own admission question.
    let mut requested = vec![group.clone()];
    requested.extend((0..MAX_GROUPS_PER_CONNECTION - 1).map(|index| {
        let mut id = vec![0u8; 32];
        id[0] = 0x70;
        id[1..3].copy_from_slice(&(index as u16).to_be_bytes());
        id
    }));
    assert_eq!(requested.len(), MAX_GROUPS_PER_CONNECTION);
    attacker.handshake(requested, CLOCK).await;

    // The ceiling that binds one socket is its **share** of the table, not the
    // whole table. A quarter, never less than one (`CallRegistry::share`): a
    // finite table with no per-source share is a table one source takes, and on
    // the hosted tier this process carries many workspaces, so a socket allowed
    // to fill it would be refusing every other customer's calls (WEALD-340).
    // This test used to let the attacker have the entire table and only then
    // expect a refusal, which is the behaviour the share was added to remove.
    let share = (ceiling / 4).max(1);
    let mut opened = 0u32;
    let mut refused = 0u32;
    for index in 0..64u8 {
        attacker.send_frame(&offer(&call_id(index), &group)).await;
        opened += 1;
        if opened > share {
            match attacker.recv_frame().await {
                Frame::Error(error) => {
                    assert_eq!(error.code, ErrorCode::RateLimited);
                    // The instance ceiling, still, and on purpose: both refusals
                    // carry the same code and the same number so an attacker
                    // cannot tell which of the two it found. The operator gets
                    // the distinction from the `share_refused` counter instead.
                    assert_eq!(
                        error.detail,
                        Some(u64::from(ceiling).to_be_bytes().to_vec())
                    );
                    refused += 1;
                }
                other => panic!("expected the ceiling to bind, got {other:?}"),
            }
        }
    }
    assert!(refused > 0, "the ceiling never bound");
    assert_eq!(
        relay.state.calls.open_calls().await,
        share as usize,
        "one socket took more than its share of the instance's call table"
    );

    // And the relay is still serving, on this socket and on a fresh one.
    let envelope = support::envelope_for(&group, b"still up");
    attacker
        .send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
    assert!(matches!(attacker.recv_frame().await, Frame::SendAck { .. }));
    let mut bystander = Client::connect(relay.address).await;
    bystander
        .handshake_as(&other_device(), vec![group.clone()], CLOCK)
        .await;
    bystander
        .send_frame(&Frame::Sub {
            group: group.clone(),
            from_seq: 0,
        })
        .await;
    assert!(matches!(bystander.recv_frame().await, Frame::SubAck { .. }));

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_kind_outside_the_closed_set_is_refused_rather_than_forwarded() {
    // Including 240, the retired `0x00F0 ephemeral` value. A relay that forwarded
    // an unrecognised kind would be a relay whose routing semantics a future
    // client could change without a version bump, and forwarding 240 in particular
    // would quietly revive a reservation `presence.md` retired on purpose.
    let scratch = Scratch::new("calls_adv_kind").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), 8),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x67).await;

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

    for kind in [0u8, 5, 240, 255] {
        ada.send_frame(&Frame::Call {
            call_id: call_id(0xE5),
            group: group.clone(),
            epoch: 1,
            kind,
            body: b"sealed".to_vec(),
        })
        .await;
        match ada.recv_frame().await {
            Frame::Error(error) => assert_eq!(
                error.code,
                ErrorCode::MalformedHeader,
                "kind {kind} was not refused as a protocol error"
            ),
            other => panic!("kind {kind} produced {other:?}"),
        }
    }

    // And none of them reached Bo. Proved by sending Bo something that must
    // arrive: delivery on one socket is ordered, so a forwarded frame would be
    // ahead of it.
    let envelope = support::envelope_for(&group, b"the next thing bo sees");
    ada.send_frame(&Frame::Send {
        envelope: envelope.encode(),
    })
    .await;
    assert!(matches!(ada.recv_frame().await, Frame::SendAck { .. }));
    match bo.recv_frame().await {
        Frame::Push { .. } => {}
        other => panic!("an unrecognised kind was forwarded: {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_media_frame_far_over_the_ceiling_is_refused_without_the_relay_holding_it() {
    // The allocation question. `MAX_FRAME_BYTES` bounds what is read off the
    // socket at all, and the media ceiling is enforced on the decoded length
    // before the payload is copied into a frame, cloned into a queue or charged
    // against a budget. What is asserted here is the observable half: the refusal
    // names the media ceiling rather than the frame ceiling, so the check that
    // fired is the cheap one.
    let scratch = Scratch::new("calls_adv_oversize").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), 8),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x68).await;
    let id = call_id(0xE6);

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&offer(&id, &group)).await;

    // Half a megabyte, which is inside the frame ceiling and three hundred times
    // the media one.
    ada.send_frame(&Frame::Media {
        call_id: id.clone(),
        stream: vec![0, 0, 0, 1],
        seq: 1,
        ct: vec![0x77; 512 * 1024],
    })
    .await;
    match ada.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::EnvelopeTooLarge);
            assert_eq!(
                error.detail,
                Some((MAX_MEDIA_CT_BYTES as u64).to_be_bytes().to_vec()),
                "the refusal named the frame ceiling rather than the media ceiling"
            );
        }
        other => panic!("expected a rejection, got {other:?}"),
    }
    // Nothing was routed and the call is intact.
    assert_eq!(relay.state.calls.open_calls().await, 1);

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bye_under_the_wrong_group_cannot_hang_up_somebody_elses_call() {
    // The collision attack turned around. Joining a call bound to another room is
    // refused, so the next thing to try is leaving one: a `bye` is applied to the
    // call id and fanned out at the group named on the frame, so a frame that named
    // a group the sender is genuinely admitted to and a call id belonging to another
    // room would, without the check, take a participant out of a call while telling
    // a different room about it. Nobody actually on the call would learn it ended,
    // and they would keep fanning audio at a participant the relay had dropped.
    //
    // Worth its own test rather than a line in the collision one, because the two
    // halves of `publish_call` are different code: joining consults the registry to
    // decide admission, and leaving used to consult nothing at all.
    let scratch = Scratch::new("calls_adv_bye_group").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_calls(&scratch, blobs.path(), 8),
        Clock::Fixed(CLOCK),
    )
    .await;
    let ours = make_group(&relay.state, 0x68).await;
    let attacker_key = device_from(0xA8);
    let theirs = support::make_group_in(
        &relay.state,
        "ws-adv-bye",
        0x69,
        std::slice::from_ref(&attacker_key),
        std::slice::from_ref(&attacker_key),
    )
    .await;
    let id = call_id(0xE8);

    // Ada and Bo are on a call in Ada's group.
    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![ours.clone()], CLOCK).await;
    let mut bo = Client::connect(relay.address).await;
    bo.handshake_as(&other_device(), vec![ours.clone()], CLOCK)
        .await;
    ada.send_frame(&offer(&id, &ours)).await;
    bo.send_frame(&Frame::Call {
        call_id: id.clone(),
        group: ours.clone(),
        epoch: 3,
        kind: CallKind::Answer as u8,
        body: b"sealed".to_vec(),
    })
    .await;
    // Both signalling frames are round-tripped on their **own** connections, which
    // is the only thing that orders them. A `CALL` is answered with nothing at all,
    // so the way to know one has been performed is to send a frame behind it that is
    // answered and wait for that: one socket's acknowledgement says nothing about
    // another socket's queue. Asserting the registry after Ada's ack alone would be
    // a race that passes on an idle machine and hangs on a busy one, waiting
    // forever for audio Bo had not yet joined to receive.
    for (client, group) in [(&mut ada, &ours), (&mut bo, &ours)] {
        client
            .send_frame(&Frame::Sub {
                group: group.clone(),
                from_seq: 0,
            })
            .await;
        assert!(matches!(client.recv_frame().await, Frame::SubAck { .. }));
    }
    assert_eq!(relay.state.calls.open_calls().await, 1);

    let mut attacker = Client::connect(relay.address).await;
    attacker
        .handshake_as(&attacker_key, vec![theirs.clone()], CLOCK)
        .await;
    for kind in [CallKind::Bye, CallKind::Decline] {
        attacker
            .send_frame(&Frame::Call {
                call_id: id.clone(),
                group: theirs.clone(),
                epoch: 3,
                kind: kind as u8,
                body: b"sealed".to_vec(),
            })
            .await;
        match attacker.recv_frame().await {
            Frame::Error(error) => {
                assert_eq!(error.code, ErrorCode::WriterNotInAccessSet);
                // Denied rather than quota, for the reason the collision test gives:
                // `quota` tells a client to retry after an interval, and retrying
                // this forever is exactly what an attacker would do.
                assert_eq!(error.code.class().as_str(), "denied");
                assert!(!error.code.class().is_retryable());
            }
            other => panic!(
                "a {} under the wrong group was not refused: {other:?}",
                kind.as_str()
            ),
        }
    }

    // The call is untouched: still open, still two participants, and Ada's audio
    // still reaches Bo.
    assert_eq!(relay.state.calls.open_calls().await, 1);
    ada.send_frame(&media(&id, 1)).await;
    assert_eq!(bo.recv_frame().await, media(&id, 1));

    relay.shutdown().await;
    scratch.drop_database().await;
}
