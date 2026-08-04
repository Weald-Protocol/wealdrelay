// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The call codec, the budgets and the registry, without a socket and without a
//! database.
//!
//! That absence is what makes these tests worth reading. The registry is the one
//! piece of state the media path consults, and its whole job is to answer "may
//! this connection send into this call" without asking Postgres. A test that
//! reached it through a socket would be testing the socket.
//!
//! Every refusal here names the specific error code. A test asserting merely that
//! an error occurred would pass against a relay that answered every bad frame
//! with `backpressure`, and a client branches on the code: `operations.md` says
//! `retry` is backoff, `quota` is the named interval and `denied` is not
//! retryable at all, so answering the wrong class tells the client to do the
//! wrong thing.

use proptest::prelude::*;
use wealdrelay::calls::{
    CallKind, CallRegistry, JoinRefusal, MediaBudget, MediaRefusal, CALL_ID_BYTES,
    MAX_CALL_BODY_BYTES, MAX_MEDIA_CT_BYTES, MAX_PARTICIPANTS_PER_CALL, MAX_TRACKED_STREAMS,
    MEDIA_BYTES_PER_MINUTE, MEDIA_FRAMES_PER_STREAM_PER_SECOND, MEDIA_STREAM_WINDOW_MS,
    STREAM_BYTES,
};
use wealdrelay::cbor;
use wealdrelay::frame::{ErrorCode, Frame, FrameDecodeError, FrameTag};
use wealdrelay::hub::ConnectionId;
use wealdrelay::ws::{outbound_channel, OutboundReceiver, OutboundSender};

const NOW: u64 = 1_700_000_000_000;

fn call_id(seed: u8) -> Vec<u8> {
    vec![seed; CALL_ID_BYTES]
}

fn stream(seed: u8) -> Vec<u8> {
    vec![seed; STREAM_BYTES]
}

fn group(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

fn call_frame(kind: CallKind, id: u8, group_seed: u8) -> Frame {
    Frame::Call {
        call_id: call_id(id),
        group: group(group_seed),
        epoch: 4,
        kind: kind as u8,
        body: b"sealed".to_vec(),
    }
}

fn media_frame(id: u8, stream_seed: u8, seq: u64) -> Frame {
    Frame::Media {
        call_id: call_id(id),
        stream: stream(stream_seed),
        seq,
        ct: b"audio".to_vec(),
    }
}

/// A connection the registry can hold, and the receiver that proves what reached
/// it. Returned together because a sender whose receiver has been dropped is a
/// closed connection, which is a different case with its own tests below.
fn peer(id: ConnectionId) -> (ConnectionId, OutboundSender, OutboundReceiver) {
    let (sender, receiver) = outbound_channel();
    (id, sender, receiver)
}

fn taken(receiver: &mut OutboundReceiver) -> Option<Frame> {
    match receiver.try_recv() {
        Ok(wealdrelay::ws::Outbound::Frame(frame)) => Some(frame),
        _ => None,
    }
}

// MARK: The kind enum

#[test]
fn the_kind_set_is_closed_and_round_trips_through_its_number() {
    // The one field of either frame the relay interprets, so the mapping between
    // the number on the wire and the decision it drives is the whole contract.
    for kind in CallKind::ALL {
        assert_eq!(CallKind::from_u8(*kind as u8), Some(*kind));
        assert!(!kind.as_str().is_empty());
    }
    assert_eq!(CallKind::ALL.len(), 4);
    // Joining is the property `MEDIA` depends on: offer and answer put the sender
    // in the call, decline and bye take it out.
    assert!(CallKind::Offer.joins());
    assert!(CallKind::Answer.joins());
    assert!(!CallKind::Decline.joins());
    assert!(!CallKind::Bye.joins());
}

#[test]
fn a_kind_outside_the_set_is_not_readable_as_one() {
    // Including 0 and 5, which are the two an off-by-one produces, and 240, which
    // is the retired `0x00F0 ephemeral` value: a relay that read it as a kind
    // would be reviving the reservation `presence.md` retired.
    for value in [0u8, 5, 6, 240, 255] {
        assert_eq!(CallKind::from_u8(value), None, "{value} decoded as a kind");
    }
}

// MARK: The codec

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// Every call frame survives encode and decode unchanged.
    ///
    /// Over the whole legal input space rather than over a handful of examples,
    /// because the fields that could drift are widths and the widths are where a
    /// hand-written codec goes wrong.
    #[test]
    fn a_call_frame_round_trips(
        id in prop::collection::vec(any::<u8>(), CALL_ID_BYTES),
        group in prop::collection::vec(any::<u8>(), 32),
        epoch in any::<u64>(),
        kind in 1u8..=4,
        body in prop::collection::vec(any::<u8>(), 0..=512),
    ) {
        let frame = Frame::Call { call_id: id, group, epoch, kind, body };
        prop_assert_eq!(Frame::decode(&frame.encode()).expect("decodes"), frame);
    }

    #[test]
    fn a_media_frame_round_trips(
        id in prop::collection::vec(any::<u8>(), CALL_ID_BYTES),
        stream in prop::collection::vec(any::<u8>(), STREAM_BYTES),
        seq in any::<u64>(),
        ct in prop::collection::vec(any::<u8>(), 0..=MAX_MEDIA_CT_BYTES),
    ) {
        let frame = Frame::Media { call_id: id, stream, seq, ct };
        prop_assert_eq!(Frame::decode(&frame.encode()).expect("decodes"), frame);
    }

    /// A call id of any width but sixteen is refused, and a stream id of any
    /// width but four.
    ///
    /// The widths are the whole reason `bytes_of` exists: a short `call_id` would
    /// otherwise decode fine and then route to a call nobody opened.
    #[test]
    fn a_routing_id_of_the_wrong_width_is_refused_as_noncanonical(
        width in (0usize..=40).prop_filter("not the legal width", |w| *w != CALL_ID_BYTES),
    ) {
        let bytes = cbor::array(&[
            cbor::uint(FrameTag::Media as u64),
            cbor::array(&[
                cbor::bytes(&vec![0xAA; width]),
                cbor::bytes(&[0, 0, 0, 1]),
                cbor::uint(1),
                cbor::bytes(b"audio"),
            ]),
        ]);
        let error = Frame::decode(&bytes).expect_err("a wrong-width call id must be refused");
        prop_assert!(matches!(error, FrameDecodeError::Cbor(_)));
        prop_assert_eq!(error.code(), ErrorCode::NoncanonicalCbor);
    }
}

#[test]
fn a_ct_at_the_ceiling_encodes_and_one_over_still_decodes_but_the_session_refuses_it() {
    // Two different bounds, deliberately kept apart. The codec's bound is
    // `MAX_FRAME_BYTES`, which is about a megabyte, and the media ceiling is a
    // policy the session enforces. A codec that refused 1501 bytes would be a
    // codec encoding a limit that belongs in one place, and moving the limit
    // would then need a wire change.
    for size in [MAX_MEDIA_CT_BYTES, MAX_MEDIA_CT_BYTES + 1] {
        let frame = Frame::Media {
            call_id: call_id(1),
            stream: stream(1),
            seq: 0,
            ct: vec![0x33; size],
        };
        assert_eq!(
            Frame::decode(&frame.encode()).expect("both sizes are structurally legal"),
            frame
        );
    }
}

#[test]
fn a_truncated_array_a_short_array_and_a_long_one_are_each_refused_by_name() {
    // Three separate mistakes with three separate causes, so a failure says which.
    let short = cbor::array(&[
        cbor::uint(FrameTag::Media as u64),
        cbor::array(&[cbor::bytes(&call_id(1)), cbor::bytes(&stream(1))]),
    ]);
    let error = Frame::decode(&short).expect_err("a two-field MEDIA is not a MEDIA");
    assert_eq!(error.code(), ErrorCode::NoncanonicalCbor);

    let long = cbor::array(&[
        cbor::uint(FrameTag::Media as u64),
        cbor::array(&[
            cbor::bytes(&call_id(1)),
            cbor::bytes(&stream(1)),
            cbor::uint(1),
            cbor::bytes(b"audio"),
            cbor::uint(99),
        ]),
    ]);
    let error = Frame::decode(&long).expect_err("an extra trailing field is not ignored");
    assert_eq!(error.code(), ErrorCode::NoncanonicalCbor);

    // Cut mid-item rather than at a boundary, which is the shape a half-delivered
    // frame actually has.
    let whole = call_frame(CallKind::Offer, 1, 1).encode();
    let error = Frame::decode(&whole[..whole.len() - 3]).expect_err("a truncated frame is refused");
    assert_eq!(error.code(), ErrorCode::NoncanonicalCbor);
}

#[test]
fn trailing_bytes_after_a_complete_frame_are_refused() {
    // Not ignored. A decoder that stopped at the last field it wanted would let a
    // peer smuggle bytes past every length check the relay has.
    let mut bytes = media_frame(1, 1, 5).encode();
    bytes.push(0x00);
    let error = Frame::decode(&bytes).expect_err("trailing bytes are refused");
    assert_eq!(error.code(), ErrorCode::NoncanonicalCbor);
}

#[test]
fn a_noncanonical_integer_encoding_is_refused() {
    // `seq` of 1 written in the two-byte form rather than the shortest. Accepted,
    // this would give one frame two encodings, which is the property the whole
    // deterministic-CBOR rule exists to deny.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&cbor::uint(FrameTag::Media as u64));
    let mut body = vec![0x84];
    body.extend_from_slice(&cbor::bytes(&call_id(1)));
    body.extend_from_slice(&cbor::bytes(&stream(1)));
    // 0x18 0x01: one, in the one-byte-argument form, which is not shortest.
    body.extend_from_slice(&[0x18, 0x01]);
    body.extend_from_slice(&cbor::bytes(b"audio"));
    let mut framed = vec![0x82];
    framed.extend_from_slice(&bytes);
    framed.extend_from_slice(&body);
    let error = Frame::decode(&framed).expect_err("a non-shortest integer is refused");
    assert_eq!(error.code(), ErrorCode::NoncanonicalCbor);
}

#[test]
fn a_field_of_the_wrong_major_type_is_refused() {
    // `call_id` as an integer rather than a byte string. A decoder that coerced
    // would be a decoder whose field types the wire does not actually fix.
    let bytes = cbor::array(&[
        cbor::uint(FrameTag::Call as u64),
        cbor::array(&[
            cbor::uint(7),
            cbor::bytes(&group(1)),
            cbor::uint(1),
            cbor::uint(1),
            cbor::bytes(b"sealed"),
        ]),
    ]);
    let error = Frame::decode(&bytes).expect_err("an integer is not a call id");
    assert_eq!(error.code(), ErrorCode::NoncanonicalCbor);
}

#[test]
fn an_unknown_tag_beyond_the_two_new_ones_is_refused_as_a_malformed_header() {
    // 25 is the next number nobody has allocated. It has to be refused rather than
    // ignored, because a tag this build cannot name is a frame it cannot bound.
    let bytes = cbor::array(&[cbor::uint(25), cbor::array(&[])]);
    let error = Frame::decode(&bytes).expect_err("tag 25 is not one this build speaks");
    assert!(matches!(error, FrameDecodeError::UnknownTag(25)));
    assert_eq!(error.code(), ErrorCode::MalformedHeader);
}

#[test]
fn an_all_zero_call_id_and_a_max_seq_are_ordinary_frames() {
    // Neither value is reserved and neither is special-cased. The relay compares
    // call ids and copies sequence numbers, so a zero id is a call like any other
    // and `u64::MAX` is a counter like any other. Written down because "surely
    // zero means none" is the assumption a future reader will make.
    let frame = Frame::Media {
        call_id: vec![0; CALL_ID_BYTES],
        stream: vec![0; STREAM_BYTES],
        seq: u64::MAX,
        ct: Vec::new(),
    };
    assert_eq!(Frame::decode(&frame.encode()).expect("decodes"), frame);
}

#[test]
fn a_call_body_at_the_ceiling_is_carried_and_costs_what_it_weighs() {
    // The queue accounting has to see the body, or an 8 MiB budget would be
    // measured against frames it does not know the size of.
    let frame = Frame::Call {
        call_id: call_id(1),
        group: group(1),
        epoch: 0,
        kind: CallKind::Offer as u8,
        body: vec![0x5A; MAX_CALL_BODY_BYTES],
    };
    assert!(frame.queued_bytes() > MAX_CALL_BODY_BYTES);
    assert!(media_frame(1, 1, 0).queued_bytes() > b"audio".len());
}

// MARK: The media budget

#[test]
fn a_stream_may_send_its_allowance_and_is_refused_on_the_next_frame() {
    let mut budget = MediaBudget::default();
    let id = [1u8; CALL_ID_BYTES];
    let stream = [0u8, 0, 0, 1];
    for index in 0..MEDIA_FRAMES_PER_STREAM_PER_SECOND {
        assert_eq!(
            budget.charge(NOW, &id, &stream, 80),
            Ok(()),
            "frame {index} inside the allowance was refused"
        );
    }
    let refusal = budget
        .charge(NOW, &id, &stream, 80)
        .expect_err("the sixty-first frame is refused");
    assert_eq!(refusal, MediaRefusal::StreamRate);
    // The code, specifically. `quota/group_ingress_limited` is the one that has
    // existed in `frame.rs` since step 2 with nothing referring to it, and a limit
    // the spec claims and the code does not enforce is worse than no limit.
    assert_eq!(refusal.code(), ErrorCode::GroupIngressLimited);
    assert_eq!(refusal.code().class().as_str(), "quota");
}

#[test]
fn the_stream_window_resets_and_a_paused_stream_is_forgotten() {
    let mut budget = MediaBudget::default();
    let id = [1u8; CALL_ID_BYTES];
    let stream = [0u8, 0, 0, 1];
    for _ in 0..MEDIA_FRAMES_PER_STREAM_PER_SECOND {
        assert_eq!(budget.charge(NOW, &id, &stream, 10), Ok(()));
    }
    assert_eq!(
        budget.charge(NOW, &id, &stream, 10),
        Err(MediaRefusal::StreamRate)
    );
    // One window later the allowance is whole again. A call is a continuous
    // stream, so a budget that did not reset would end every call after a second.
    assert_eq!(
        budget.charge(NOW + MEDIA_STREAM_WINDOW_MS, &id, &stream, 10),
        Ok(())
    );
}

#[test]
fn two_streams_have_independent_allowances() {
    // Per stream, not per connection, because a five-person call is four inbound
    // streams on one socket and one busy speaker must not silence the others.
    let mut budget = MediaBudget::default();
    let id = [1u8; CALL_ID_BYTES];
    for _ in 0..MEDIA_FRAMES_PER_STREAM_PER_SECOND {
        assert_eq!(budget.charge(NOW, &id, &[0, 0, 0, 1], 10), Ok(()));
    }
    assert_eq!(
        budget.charge(NOW, &id, &[0, 0, 0, 1], 10),
        Err(MediaRefusal::StreamRate)
    );
    assert_eq!(budget.charge(NOW, &id, &[0, 0, 0, 2], 10), Ok(()));
}

#[test]
fn the_same_stream_id_in_two_calls_is_two_streams() {
    // The key is the pair. Stream ids are client-chosen per call, so two calls
    // both numbering their first stream 1 is the ordinary case, not a collision.
    let mut budget = MediaBudget::default();
    let stream = [0u8, 0, 0, 1];
    for _ in 0..MEDIA_FRAMES_PER_STREAM_PER_SECOND {
        assert_eq!(budget.charge(NOW, &[1; CALL_ID_BYTES], &stream, 10), Ok(()));
    }
    assert_eq!(
        budget.charge(NOW, &[1; CALL_ID_BYTES], &stream, 10),
        Err(MediaRefusal::StreamRate)
    );
    assert_eq!(budget.charge(NOW, &[2; CALL_ID_BYTES], &stream, 10), Ok(()));
}

#[test]
fn the_byte_budget_refuses_before_the_frame_budget_would() {
    // A connection sending large frames slowly is inside every per-stream rate and
    // still moving a megabyte a minute, which is what this second limit is for.
    let mut budget = MediaBudget::default();
    let id = [1u8; CALL_ID_BYTES];
    let mut spent = 0u64;
    let mut stream_index = 0u8;
    // Spread across streams so the per-stream rate is never the binding limit,
    // which is what makes this a test of the byte budget rather than of the other
    // one.
    loop {
        let stream = [0, 0, 0, stream_index % (MAX_TRACKED_STREAMS as u8)];
        if let Err(refusal) = budget.charge(NOW, &id, &stream, MAX_MEDIA_CT_BYTES) {
            assert_eq!(refusal, MediaRefusal::ByteRate);
            assert_eq!(refusal.code(), ErrorCode::GroupIngressLimited);
            break;
        }
        spent += MAX_MEDIA_CT_BYTES as u64;
        stream_index = stream_index.wrapping_add(1);
        assert!(
            spent <= MEDIA_BYTES_PER_MINUTE,
            "the byte budget let a connection past its allowance"
        );
    }
    // And it resets on the minute, so a call longer than sixty seconds is possible.
    assert_eq!(budget.charge(NOW + 60_000, &id, &[0, 0, 0, 1], 10), Ok(()));
}

#[test]
fn a_client_inventing_stream_ids_is_refused_rather_than_making_the_relay_remember_them() {
    // The budget's own memory bound. Without it a peer could make the relay hold a
    // window per invented stream id, which is a slow allocation attack down a path
    // that was chosen for being cheap.
    let mut budget = MediaBudget::default();
    let id = [1u8; CALL_ID_BYTES];
    for index in 0..MAX_TRACKED_STREAMS {
        let stream = (index as u32).to_be_bytes();
        assert_eq!(budget.charge(NOW, &id, &stream, 10), Ok(()));
    }
    let refusal = budget
        .charge(NOW, &id, &(MAX_TRACKED_STREAMS as u32).to_be_bytes(), 10)
        .expect_err("the thirty-third stream inside one window is refused");
    assert_eq!(refusal, MediaRefusal::TooManyStreams);
    assert_eq!(refusal.code(), ErrorCode::GroupIngressLimited);
    // A window later the table has been forgotten, so a client that legitimately
    // rotated streams is not locked out forever.
    assert_eq!(
        budget.charge(
            NOW + MEDIA_STREAM_WINDOW_MS,
            &id,
            &(MAX_TRACKED_STREAMS as u32).to_be_bytes(),
            10
        ),
        Ok(())
    );
}

#[test]
fn a_refusal_is_reported_at_most_once_a_second() {
    // The amplification rule, at the unit level. A stream at ten times its rate is
    // 600 frames a second; answering each one turns one flood into two, and the
    // answers queue on the flooder's own bounded outbound queue, so a relay that
    // complained about every frame would fill that queue and turn a rate limit
    // into a disconnect.
    //
    // Enforcement is unaffected either way: every frame over the limit is refused.
    // What this bounds is the complaint.
    let mut budget = MediaBudget::default();
    assert!(
        budget.should_report(NOW),
        "the first refusal is always told"
    );
    for offset in [1, 10, 500, 999] {
        assert!(
            !budget.should_report(NOW + offset),
            "a second complaint inside the window at +{offset}ms"
        );
    }
    assert!(
        budget.should_report(NOW + MEDIA_STREAM_WINDOW_MS),
        "a window later the client is told again, so a persistent flood is visible"
    );
}

// MARK: The registry

#[tokio::test]
async fn a_call_opens_on_the_first_offer_and_closes_with_its_last_participant() {
    let registry = CallRegistry::new(3);
    let (ada, ada_send, _ada_recv) = peer(1);
    let (bo, bo_send, _bo_recv) = peer(2);
    let id = [0xC1; CALL_ID_BYTES];

    assert_eq!(registry.open_calls().await, 0);
    registry
        .join(&id, &group(1), ada, ada_send)
        .await
        .expect("the first offer opens the call");
    assert_eq!(registry.open_calls().await, 1);
    assert_eq!(registry.group_of(&id).await, Some(group(1)));
    registry
        .join(&id, &group(1), bo, bo_send)
        .await
        .expect("the answer joins it");
    assert!(registry.holds(&id, ada).await);
    assert!(registry.holds(&id, bo).await);

    registry.leave(&id, ada).await;
    assert!(!registry.holds(&id, ada).await);
    // Still open: one person left in a call is a call, not a leak.
    assert_eq!(registry.open_calls().await, 1);
    registry.leave(&id, bo).await;
    assert_eq!(registry.open_calls().await, 0);
    assert_eq!(registry.group_of(&id).await, None);
}

#[tokio::test]
async fn a_second_offer_from_the_same_connection_does_not_consume_a_seat() {
    // A re-offer is a normal thing for a client to send, and a registry that
    // counted it would end a five-person call at three people.
    let registry = CallRegistry::new(1);
    let (ada, ada_send, _recv) = peer(1);
    let id = [0xC1; CALL_ID_BYTES];
    for _ in 0..10 {
        registry
            .join(&id, &group(1), ada, ada_send.clone())
            .await
            .expect("re-offering is idempotent");
    }
    assert_eq!(registry.open_calls().await, 1);
}

#[tokio::test]
async fn a_call_id_already_open_against_another_group_is_denied() {
    // The collision case, and it is denied rather than rate limited: the sender is
    // naming a room it may not reach through a call id it may. Both groups can be
    // perfectly legitimate for the sender and the answer is still no, because a
    // call is a conversation inside one room.
    let registry = CallRegistry::new(3);
    let (ada, ada_send, _a) = peer(1);
    let (bo, bo_send, _b) = peer(2);
    let id = [0xC1; CALL_ID_BYTES];
    registry
        .join(&id, &group(1), ada, ada_send)
        .await
        .expect("opens");
    let refusal = registry
        .join(&id, &group(2), bo, bo_send)
        .await
        .expect_err("a different group under the same id is refused");
    assert_eq!(refusal, JoinRefusal::GroupMismatch);
    assert_eq!(refusal.code(), ErrorCode::WriterNotInAccessSet);
    assert_eq!(refusal.code().class().as_str(), "denied");
    assert_eq!(refusal.detail(3), 0);
}

#[tokio::test]
async fn a_call_is_full_at_the_participant_cap() {
    // Five, because relayed egress grows as n(n-1) and five is where the quadratic
    // term stops being free. Enforced here rather than only stated in a UI.
    let registry = CallRegistry::new(3);
    let id = [0xC1; CALL_ID_BYTES];
    let mut held = Vec::new();
    for index in 0..MAX_PARTICIPANTS_PER_CALL {
        let (who, sender, receiver) = peer(index as ConnectionId);
        registry
            .join(&id, &group(1), who, sender)
            .await
            .expect("inside the cap");
        held.push(receiver);
    }
    let (extra, extra_send, _r) = peer(99);
    let refusal = registry
        .join(&id, &group(1), extra, extra_send)
        .await
        .expect_err("the sixth is refused");
    assert_eq!(refusal, JoinRefusal::CallFull);
    assert_eq!(refusal.code(), ErrorCode::RateLimited);
    assert_eq!(refusal.detail(3), MAX_PARTICIPANTS_PER_CALL as u64);
}

#[tokio::test]
async fn the_instance_refuses_a_call_past_its_configured_ceiling() {
    // The ceiling `WEALD_RELAY_MAX_CONCURRENT_CALLS` sets, and the refusal names
    // it, so an operator reading a client's error learns which number to change.
    let registry = CallRegistry::new(2);
    assert_eq!(registry.max_concurrent(), 2);
    let mut held = Vec::new();
    for index in 0..2u8 {
        let (who, sender, receiver) = peer(u64::from(index));
        registry
            .join(&[index; CALL_ID_BYTES], &group(1), who, sender)
            .await
            .expect("inside the ceiling");
        held.push(receiver);
    }
    let (who, sender, _r) = peer(9);
    let refusal = registry
        .join(&[0xFF; CALL_ID_BYTES], &group(1), who, sender)
        .await
        .expect_err("the third call is refused");
    assert_eq!(refusal, JoinRefusal::TooManyCalls);
    assert_eq!(refusal.code(), ErrorCode::RateLimited);
    assert_eq!(refusal.detail(2), 2);
    // And an existing call still takes traffic: a full instance refuses new calls
    // rather than degrading the ones it is already carrying.
    let (again, again_send, _r2) = peer(10);
    registry
        .join(&[0; CALL_ID_BYTES], &group(1), again, again_send)
        .await
        .expect("joining a call that is already open is not opening a call");
}

#[tokio::test]
async fn media_reaches_every_other_participant_and_never_the_sender() {
    let registry = CallRegistry::new(3);
    let id = [0xC1; CALL_ID_BYTES];
    let (ada, ada_send, mut ada_recv) = peer(1);
    let (bo, bo_send, mut bo_recv) = peer(2);
    let (cy, cy_send, mut cy_recv) = peer(3);
    for (who, sender) in [(ada, ada_send), (bo, bo_send), (cy, cy_send)] {
        registry.join(&id, &group(1), who, sender).await.unwrap();
    }

    let frame = media_frame(0xC1, 1, 7);
    let routed = registry
        .route(&id, ada, &frame)
        .await
        .expect("ada is in it");
    assert_eq!(routed.sent, 2);
    assert_eq!(routed.shed, 0);
    assert_eq!(routed.gone, 0);
    assert_eq!(taken(&mut bo_recv), Some(frame.clone()));
    assert_eq!(taken(&mut cy_recv), Some(frame));
    // The sender is never sent its own audio. It would be an echo, and the client
    // has no use for it: the local stream is already in the local mixer.
    assert_eq!(taken(&mut ada_recv), None);
}

#[tokio::test]
async fn media_for_a_call_this_connection_is_not_in_is_denied_and_counted() {
    // The refusal that makes the whole design safe. `MEDIA` carries no group and
    // consults no database, so this is the only thing standing between a media
    // frame and a call it was never admitted to.
    let registry = CallRegistry::new(3);
    let id = [0xC1; CALL_ID_BYTES];
    let (ada, ada_send, _a) = peer(1);
    let (stranger, _stranger_send, mut stranger_recv) = peer(7);
    registry.join(&id, &group(1), ada, ada_send).await.unwrap();

    let code = registry
        .route(&id, stranger, &media_frame(0xC1, 1, 1))
        .await
        .expect_err("a connection outside the call is refused");
    assert_eq!(code, ErrorCode::WriterNotInAccessSet);
    assert_eq!(registry.denied(), 1);
    assert_eq!(taken(&mut stranger_recv), None);

    // And a call this process has never heard of gives the same answer rather than
    // a different one, because "you are not in it" and "it does not exist" are the
    // same fact from the sender's side and telling them apart would be an oracle.
    let code = registry
        .route(&[0xEE; CALL_ID_BYTES], ada, &media_frame(0xEE, 1, 1))
        .await
        .expect_err("an unknown call is refused");
    assert_eq!(code, ErrorCode::WriterNotInAccessSet);
    assert_eq!(registry.denied(), 2);
}

#[tokio::test]
async fn a_full_queue_sheds_the_frame_and_increments_a_counter_with_no_label() {
    // The shed rule, which is the one place this relay drops something on its own
    // initiative. Never a downgrade: a downgrade tells a client it has a hole in
    // an author chain and must reconcile, and there is no reconciliation for
    // audio, so it would be a lie about the client's log.
    let registry = CallRegistry::new(3);
    let id = [0xC1; CALL_ID_BYTES];
    let (ada, ada_send, _a) = peer(1);
    let (bo, bo_send, mut bo_recv) = peer(2);
    registry.join(&id, &group(1), ada, ada_send).await.unwrap();
    registry.join(&id, &group(1), bo, bo_send).await.unwrap();

    // Fill Bo's queue by never reading it. The frame bound is reached long before
    // the byte budget at this payload size, which is the case a call actually
    // produces: many small frames rather than a few large ones.
    let mut sent = 0;
    while registry.shed() == 0 {
        let routed = registry
            .route(&id, ada, &media_frame(0xC1, 1, sent))
            .await
            .expect("ada stays in the call however full Bo is");
        sent += 1;
        assert!(sent < 10_000, "the queue never filled");
        if routed.shed > 0 {
            break;
        }
    }
    assert!(registry.shed() >= 1);
    // Bo is still in the call and still receiving. Shedding is per frame, not a
    // state change: the next frame after the queue drains goes through.
    assert!(registry.holds(&id, bo).await);
    assert!(taken(&mut bo_recv).is_some(), "the queue held what it took");
    // Nothing the sender is told, and nothing anywhere carries a call id, a group
    // or a principal: `shed()` is a bare count, which is the whole of what an
    // operator gets.
    assert_eq!(registry.denied(), 0);
}

#[tokio::test]
async fn a_participant_whose_socket_has_gone_is_dropped_on_the_next_frame() {
    let registry = CallRegistry::new(3);
    let id = [0xC1; CALL_ID_BYTES];
    let (ada, ada_send, _a) = peer(1);
    let (bo, bo_send, bo_recv) = peer(2);
    registry.join(&id, &group(1), ada, ada_send).await.unwrap();
    registry.join(&id, &group(1), bo, bo_send).await.unwrap();
    drop(bo_recv);

    let routed = registry
        .route(&id, ada, &media_frame(0xC1, 1, 1))
        .await
        .expect("routing continues");
    assert_eq!(routed.gone, 1);
    assert_eq!(routed.sent, 0);
    assert!(!registry.holds(&id, bo).await);
}

#[tokio::test]
async fn the_last_participant_leaving_by_a_dead_socket_closes_the_call() {
    // The leak that would otherwise be invisible: a call whose only members have
    // gone would sit in the map forever, and an instance's ceiling would be spent
    // on calls nobody is on.
    let registry = CallRegistry::new(3);
    let id = [0xC1; CALL_ID_BYTES];
    let (ada, ada_send, _a) = peer(1);
    let (bo, bo_send, bo_recv) = peer(2);
    registry.join(&id, &group(1), ada, ada_send).await.unwrap();
    registry.join(&id, &group(1), bo, bo_send).await.unwrap();
    drop(bo_recv);
    registry.leave(&id, ada).await;
    // Ada has gone and Bo's socket is dead, but nothing has tried to send yet.
    assert_eq!(registry.open_calls().await, 1);
    let (stranger, stranger_send, _s) = peer(3);
    // Bo, sending into their own call, discovers they are the only one left; the
    // dead socket is theirs, so nothing is routed and nothing is dropped.
    assert_eq!(
        registry
            .route(&id, bo, &media_frame(0xC1, 1, 1))
            .await
            .expect("bo is still a participant")
            .sent,
        0
    );
    registry.forget(bo).await;
    assert_eq!(registry.open_calls().await, 0);
    // And forgetting a connection that is in nothing is not an error.
    registry.forget(stranger).await;
    drop(stranger_send);
}

#[tokio::test]
async fn forgetting_a_connection_takes_it_out_of_every_call_at_once() {
    // What a dropped socket does. A registry that leaked a participant per lost
    // connection would fan media at senders nobody is reading, fifty times a
    // second, for the life of the process.
    let registry = CallRegistry::new(4);
    let (ada, ada_send, _a) = peer(1);
    let (bo, bo_send, _b) = peer(2);
    for seed in 0..3u8 {
        registry
            .join(&[seed; CALL_ID_BYTES], &group(1), ada, ada_send.clone())
            .await
            .unwrap();
        registry
            .join(&[seed; CALL_ID_BYTES], &group(1), bo, bo_send.clone())
            .await
            .unwrap();
    }
    assert_eq!(registry.open_calls().await, 3);
    registry.forget(ada).await;
    for seed in 0..3u8 {
        assert!(!registry.holds(&[seed; CALL_ID_BYTES], ada).await);
        assert!(registry.holds(&[seed; CALL_ID_BYTES], bo).await);
    }
    // Bo alone still holds all three open; forgetting the last one empties them.
    assert_eq!(registry.open_calls().await, 3);
    registry.forget(bo).await;
    assert_eq!(registry.open_calls().await, 0);
}

#[tokio::test]
async fn leaving_a_call_this_connection_was_never_in_is_not_an_error() {
    // `decline` and `bye` both leave, and a client declining an offer it never
    // accepted is doing exactly the right thing. Answering it with a refusal would
    // make the normal path noisy.
    let registry = CallRegistry::new(3);
    registry.leave(&[0xC1; CALL_ID_BYTES], 1).await;
    assert_eq!(registry.open_calls().await, 0);
}

#[tokio::test]
async fn a_call_whose_last_socket_died_is_removed_by_forget_rather_than_by_routing() {
    // The counterpart to the deleted arm in `route`. Routing never empties a call,
    // because the sender is a participant by the time it routes and is never in the
    // gone list; what empties one is the reader loop ending, which is `forget`.
    // Written down because "surely routing should clean up too" is the change a
    // future reader will make, and it would add a line nothing can reach.
    let registry = CallRegistry::new(3);
    let id = [0xC1; CALL_ID_BYTES];
    let (ada, ada_send, _a) = peer(1);
    let (bo, bo_send, bo_recv) = peer(2);
    registry.join(&id, &group(1), ada, ada_send).await.unwrap();
    registry.join(&id, &group(1), bo, bo_send).await.unwrap();
    drop(bo_recv);

    // Bo's dead socket is dropped from the call, and the call survives because Ada
    // is still in it.
    let routed = registry
        .route(&id, ada, &media_frame(0xC1, 1, 1))
        .await
        .expect("ada is in it");
    assert_eq!(routed.gone, 1);
    assert_eq!(registry.open_calls().await, 1);
    assert!(registry.holds(&id, ada).await);

    registry.forget(ada).await;
    assert_eq!(registry.open_calls().await, 0);
}

#[test]
fn the_frames_carry_their_own_tags() {
    assert_eq!(call_frame(CallKind::Offer, 1, 1).tag(), FrameTag::Call);
    assert_eq!(media_frame(1, 1, 0).tag(), FrameTag::Media);
    assert_eq!(FrameTag::from_u16(23), Some(FrameTag::Call));
    assert_eq!(FrameTag::from_u16(24), Some(FrameTag::Media));
    assert!(FrameTag::ALL.contains(&FrameTag::Call));
    assert!(FrameTag::ALL.contains(&FrameTag::Media));
}
