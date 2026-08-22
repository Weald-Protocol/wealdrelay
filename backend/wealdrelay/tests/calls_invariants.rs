// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The call invariants the other suites state but do not pin: exact accounting,
//! window edges, seat arithmetic, and the two answers a client is given when it is
//! over a limit.
//!
//! `calls_unit.rs` proves each rule fires. This file proves each rule fires *at the
//! right number*, which is a different claim and the one that rots first. A budget
//! that refused one frame early would pass every existing test in this repository:
//! the refusal happens, the code is right, the connection survives. What it would
//! break is a call, silently, once a second, on the machine of somebody who cannot
//! read this source.
//!
//! Three things here are regression anchors for defects found by writing them:
//!
//! - A refused frame must not spend the byte budget. If it did, a client whose
//!   stream is momentarily over rate would have its whole connection's minute
//!   consumed by frames that were never routed.
//! - Idempotent re-admission has to be decided before the participant cap, or a
//!   client re-offering into a call it is already in gets told the call is full.
//! - Being over one limit has to name that limit's interval. `retry_after` is an
//!   instruction, and telling a client to come back in a second against a window
//!   that resets in a minute produces fifty-nine more refusals.

use wealdrelay::calls::{
    CallKind, CallRegistry, JoinRefusal, MediaBudget, MediaRefusal, CALL_ID_BYTES,
    MAX_MEDIA_CT_BYTES, MAX_PARTICIPANTS_PER_CALL, MAX_TRACKED_STREAMS, MEDIA_BYTES_PER_MINUTE,
    MEDIA_FRAMES_PER_STREAM_PER_SECOND, MEDIA_STREAM_WINDOW_MS, STREAM_BYTES,
};
use wealdrelay::config::{keys, Config, Values};
use wealdrelay::frame::{ErrorCode, Frame, PROTOCOL_VERSION};
use wealdrelay::hub::ConnectionId;
use wealdrelay::session::{Reaction, Session, State, Work};
use wealdrelay::ws::{outbound_channel, Outbound, OutboundReceiver, OutboundSender};

const NOW: u64 = 1_900_000_000_000;

fn call_id(seed: u8) -> [u8; CALL_ID_BYTES] {
    [seed; CALL_ID_BYTES]
}

fn stream(seed: u8) -> [u8; STREAM_BYTES] {
    [seed; STREAM_BYTES]
}

fn group(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

fn media(id: u8, seq: u64) -> Frame {
    Frame::Media {
        call_id: call_id(id).to_vec(),
        stream: stream(1).to_vec(),
        seq,
        ct: b"audio".to_vec(),
    }
}

fn peer(id: ConnectionId) -> (ConnectionId, OutboundSender, OutboundReceiver) {
    let (sender, receiver) = outbound_channel();
    (id, sender, receiver)
}

fn delivered(receiver: &mut OutboundReceiver) -> usize {
    let mut count = 0;
    while let Ok(Outbound::Frame(_)) = receiver.try_recv() {
        count += 1;
    }
    count
}

// MARK: Seat arithmetic

/// The ordering defect this anchors: a registry that checked the participant cap
/// before checking whether the sender was already a participant would refuse a
/// re-offer from inside a full call. Re-offering is normal (it is how a client
/// recovers a lost signalling frame), and a five-person call is exactly where the
/// recovery matters most, so the two checks being in this order is the difference
/// between a self-healing call and one that cannot be repaired once it is full.
#[tokio::test]
async fn a_re_offer_from_somebody_already_in_a_full_call_is_admitted() {
    let registry = CallRegistry::new(4);
    let mut held = Vec::new();
    for id in 0..MAX_PARTICIPANTS_PER_CALL as ConnectionId {
        let (connection, sender, receiver) = peer(id);
        registry
            .join(&call_id(7), &group(1), connection, sender)
            .await
            .expect("the first five take the seats");
        held.push(receiver);
    }

    let (sixth, sender, _sixth_receiver) = peer(99);
    assert_eq!(
        registry.join(&call_id(7), &group(1), sixth, sender).await,
        Err(JoinRefusal::CallFull),
        "a sixth participant takes a seat"
    );

    // And the first, again. Not a seat: it already holds one.
    let (again, sender, _again_receiver) = peer(0);
    registry
        .join(&call_id(7), &group(1), again, sender)
        .await
        .expect("a re-offer from an existing participant is admitted");

    // Proven by fanout width rather than by a length accessor the registry does
    // not expose: one sender, four recipients, which is five seats and not six.
    let routed = registry
        .route(&call_id(7), 0, &media(7, 1))
        .await
        .expect("the sender is in the call");
    assert_eq!(routed.sent, MAX_PARTICIPANTS_PER_CALL - 1);
    assert_eq!(routed.shed, 0);
    assert_eq!(routed.gone, 0);
}

#[tokio::test]
async fn a_closed_call_gives_its_seat_on_the_instance_ceiling_back() {
    // The ceiling is a live count and not a lifetime one. A registry that leaked a
    // seat per closed call would take an instance to its limit over a day of
    // ordinary use and then refuse every call until it was restarted, which is the
    // failure an operator cannot diagnose from the outside: the count is right, the
    // calls are gone, and nothing connects.
    let registry = CallRegistry::new(1);
    let (first, sender, _first) = peer(1);
    registry
        .join(&call_id(1), &group(1), first, sender)
        .await
        .expect("the one seat");

    let (second, sender, _second) = peer(2);
    assert_eq!(
        registry.join(&call_id(2), &group(1), second, sender).await,
        Err(JoinRefusal::TooManyCalls),
    );
    assert_eq!(registry.open_calls().await, 1);

    registry.leave(&call_id(1), first).await;
    assert_eq!(registry.open_calls().await, 0, "the call is forgotten");

    let (second, sender, _second) = peer(2);
    registry
        .join(&call_id(2), &group(1), second, sender)
        .await
        .expect("the seat came back");
    assert_eq!(registry.open_calls().await, 1);
}

#[tokio::test]
async fn one_connection_cannot_take_the_whole_table_from_another_workspace() {
    // WEALD-L182. The table is process-wide, so a device that opened a fresh call
    // id at its frame budget and never said `Bye` used to fill it and every later
    // offer in the process was refused, including offers between members of
    // unrelated workspaces on a shared hosted relay. The share is what makes the
    // abuser the one refused.
    let registry = CallRegistry::new(8);
    let (greedy, _sender, _keep) = peer(1);
    let mut opened = 0usize;
    for index in 0..8u8 {
        let (_, sender, receiver) = peer(1);
        std::mem::forget(receiver);
        match registry
            .join(&call_id(index + 10), &group(1), greedy, sender)
            .await
        {
            Ok(()) => opened += 1,
            Err(JoinRefusal::TooManyCalls) => break,
            Err(other) => panic!("unexpected refusal {other:?}"),
        }
    }
    assert!(
        opened < 8,
        "one connection must not be able to open the whole table"
    );
    assert!(
        registry.share_refused() >= 1,
        "the abuser is what was refused"
    );

    // And a different connection, in a different workspace, is still admitted.
    let (other, sender, _other_keep) = peer(2);
    registry
        .join(&call_id(200), &group(2), other, sender)
        .await
        .expect("an unrelated workspace still gets a call");
}

#[tokio::test]
async fn a_call_that_carries_nothing_is_collected() {
    // The other half of WEALD-L182: entries were removed only by `Bye` or by the
    // socket ending, so a silent participant on a live socket held its share of the
    // table for the life of the process.
    let registry = CallRegistry::new(4);
    let (connection, sender, _keep) = peer(1);
    registry
        .join(&call_id(1), &group(1), connection, sender)
        .await
        .expect("the call opens");
    assert_eq!(registry.open_calls().await, 1);
    assert_eq!(registry.sweep_idle(std::time::Duration::ZERO).await, 1);
    assert_eq!(registry.open_calls().await, 0, "the silent call is gone");
}

#[tokio::test]
async fn an_instance_configured_to_carry_no_calls_carries_none() {
    // Zero is reachable: `max_concurrent_calls` is an operator's number, and the
    // conversion in `health.rs` produces zero for a relay with calls off. What must
    // not happen is the boundary reading as unlimited, which is what `> 0` instead
    // of `>= max` would produce.
    let registry = CallRegistry::new(0);
    let (connection, sender, _receiver) = peer(1);
    assert_eq!(
        registry
            .join(&call_id(1), &group(1), connection, sender)
            .await,
        Err(JoinRefusal::TooManyCalls),
    );
    assert_eq!(registry.open_calls().await, 0);
}

// MARK: Isolation between two calls one connection is on

#[tokio::test]
async fn a_connection_on_two_calls_at_once_never_crosses_their_audio() {
    // One person, two calls, same group: the registry's keying is the only thing
    // keeping the two apart, because the group check cannot tell them apart and the
    // media path does not consult it. A map keyed by anything coarser than the call
    // id would put one call's audio into the other's, which is the worst failure
    // this feature has: a private conversation delivered to somebody entitled to the
    // room but not to the call.
    let registry = CallRegistry::new(8);
    let (host, host_sender, _host) = peer(1);
    for id in [call_id(0xA), call_id(0xB)] {
        registry
            .join(&id, &group(1), host, host_sender.clone())
            .await
            .expect("the host is on both calls");
    }
    let (on_a, sender, mut a_receiver) = peer(2);
    registry
        .join(&call_id(0xA), &group(1), on_a, sender)
        .await
        .expect("joins A");
    let (on_b, sender, mut b_receiver) = peer(3);
    registry
        .join(&call_id(0xB), &group(1), on_b, sender)
        .await
        .expect("joins B");

    let routed = registry
        .route(&call_id(0xA), host, &media(0xA, 1))
        .await
        .expect("the host is on A");
    assert_eq!(routed.sent, 1, "one recipient, and it is not the sender");
    assert_eq!(delivered(&mut a_receiver), 1);
    assert_eq!(delivered(&mut b_receiver), 0, "B heard A's audio");

    // And the reverse, so the test cannot pass by the calls being ordered.
    registry
        .route(&call_id(0xB), host, &media(0xB, 1))
        .await
        .expect("the host is on B");
    assert_eq!(delivered(&mut b_receiver), 1);
    assert_eq!(delivered(&mut a_receiver), 0, "A heard B's audio");

    // Leaving one leaves exactly one.
    registry.leave(&call_id(0xA), host).await;
    assert!(!registry.holds(&call_id(0xA), host).await);
    assert!(registry.holds(&call_id(0xB), host).await);
    assert_eq!(
        registry.open_calls().await,
        2,
        "A still has its other member"
    );
}

#[tokio::test]
async fn the_registry_answers_what_it_holds_and_nothing_it_does_not() {
    let registry = CallRegistry::new(4);
    assert_eq!(registry.group_of(&call_id(1)).await, None);
    assert!(!registry.holds(&call_id(1), 1).await);

    let (connection, sender, _receiver) = peer(1);
    registry
        .join(&call_id(1), &group(9), connection, sender)
        .await
        .expect("opens the call");
    assert_eq!(registry.group_of(&call_id(1)).await, Some(group(9)));
    assert!(registry.holds(&call_id(1), 1).await);
    assert!(!registry.holds(&call_id(1), 2).await, "a stranger is held");
    assert!(
        !registry.holds(&call_id(2), 1).await,
        "another call is held"
    );

    registry.forget(connection).await;
    assert_eq!(
        registry.group_of(&call_id(1)).await,
        None,
        "an emptied call is forgotten rather than left group-bound"
    );
}

#[tokio::test]
async fn a_call_of_one_routes_to_nobody_and_is_not_an_error() {
    // The state a call is in for the whole ring: the caller has offered, nobody has
    // answered, and the client is already sending. An error here would put a refusal
    // on the sender's socket fifty times a second during every unanswered call.
    let registry = CallRegistry::new(4);
    let (alone, sender, mut receiver) = peer(1);
    registry
        .join(&call_id(3), &group(1), alone, sender)
        .await
        .expect("opens the call");

    let routed = registry
        .route(&call_id(3), alone, &media(3, 1))
        .await
        .expect("a call of one is a call");
    assert_eq!((routed.sent, routed.shed, routed.gone), (0, 0, 0));
    assert_eq!(delivered(&mut receiver), 0, "the sender heard itself");
    assert_eq!(
        registry.denied(),
        0,
        "an unanswered call counted as a denial"
    );
}

#[tokio::test]
async fn an_empty_payload_is_carried_rather_than_treated_as_absent() {
    // A zero-length `ct` is under every ceiling and the relay cannot see inside a
    // sealed payload anyway, so there is nothing here to judge. What must not happen
    // is a length of zero taking a different path from a length of one.
    let registry = CallRegistry::new(4);
    let (from, sender, _from) = peer(1);
    registry
        .join(&call_id(4), &group(1), from, sender)
        .await
        .expect("opens");
    let (to, sender, mut receiver) = peer(2);
    registry
        .join(&call_id(4), &group(1), to, sender)
        .await
        .expect("joins");

    let frame = Frame::Media {
        call_id: call_id(4).to_vec(),
        stream: stream(1).to_vec(),
        seq: 0,
        ct: Vec::new(),
    };
    let routed = registry
        .route(&call_id(4), from, &frame)
        .await
        .expect("routed");
    assert_eq!(routed.sent, 1);
    assert_eq!(delivered(&mut receiver), 1);
}

// MARK: Exact budget accounting

/// How many maximum-sized frames fit inside one connection's minute.
fn full_size_frames_per_minute() -> u64 {
    MEDIA_BYTES_PER_MINUTE / MAX_MEDIA_CT_BYTES as u64
}

/// Spend `frames` maximum-sized frames, spreading them across as many streams as
/// the per-stream rate requires, and answer the first refusal.
fn spend(budget: &mut MediaBudget, frames: u64, wasteful: bool) -> Option<MediaRefusal> {
    let mut accepted = 0u64;
    let mut index = 0u8;
    while accepted < frames {
        let this_stream = stream(index);
        for _ in 0..MEDIA_FRAMES_PER_STREAM_PER_SECOND {
            if accepted == frames {
                break;
            }
            match budget.charge(NOW, &call_id(1), &this_stream, MAX_MEDIA_CT_BYTES) {
                Ok(()) => accepted += 1,
                Err(refusal) => return Some(refusal),
            }
        }
        if wasteful {
            // Frames the stream window has already refused. They must cost the
            // connection's minute nothing at all: the whole point of refusing is
            // that nothing was carried.
            //
            // Which of the two refusals comes back is not the claim and is not
            // asserted. The byte window is checked first, so once the connection is
            // within one frame of its minute a saturated stream answers `ByteRate`
            // rather than `StreamRate`. Both are refusals, neither charges, and
            // pinning the order here would pin an implementation detail that the
            // exact-boundary assertion below already covers properly.
            for _ in 0..25 {
                assert!(
                    budget
                        .charge(NOW, &call_id(1), &this_stream, MAX_MEDIA_CT_BYTES)
                        .is_err(),
                    "a saturated stream accepted another frame"
                );
            }
        }
        index += 1;
        assert!(
            u64::from(index) < MAX_TRACKED_STREAMS as u64,
            "the byte budget outlived the stream table"
        );
    }
    None
}

#[test]
fn the_minute_of_bytes_is_spent_to_the_frame_and_a_refused_frame_costs_nothing() {
    let fits = full_size_frames_per_minute();

    let mut clean = MediaBudget::default();
    assert_eq!(
        spend(&mut clean, fits, false),
        None,
        "the budget refused early"
    );
    assert_eq!(
        clean.charge(NOW, &call_id(1), &stream(200), MAX_MEDIA_CT_BYTES),
        Err(MediaRefusal::ByteRate),
        "the budget carried one frame past its minute"
    );

    // The same arithmetic, with a flood of refused frames threaded through it. The
    // boundary has to land in exactly the same place: if a refusal spent bytes, this
    // budget would run out early and the assertion above would fire here instead.
    let mut flooded = MediaBudget::default();
    assert_eq!(
        spend(&mut flooded, fits, true),
        None,
        "refused frames were charged against the minute"
    );
    assert_eq!(
        flooded.charge(NOW, &call_id(1), &stream(200), MAX_MEDIA_CT_BYTES),
        Err(MediaRefusal::ByteRate),
    );
}

#[test]
fn both_windows_end_on_their_stated_millisecond_and_not_one_earlier() {
    // Half-open at the top: a window that reset at `width - 1` would give a client
    // an extra frame every second, and one that reset at `width + 1` would refuse a
    // client that had waited exactly as long as it was told to.
    let mut budget = MediaBudget::default();
    for _ in 0..MEDIA_FRAMES_PER_STREAM_PER_SECOND {
        budget
            .charge(NOW, &call_id(1), &stream(1), 10)
            .expect("the allowance");
    }
    assert_eq!(
        budget.charge(
            NOW + MEDIA_STREAM_WINDOW_MS - 1,
            &call_id(1),
            &stream(1),
            10
        ),
        Err(MediaRefusal::StreamRate),
        "the stream window ended a millisecond early"
    );
    budget
        .charge(NOW + MEDIA_STREAM_WINDOW_MS, &call_id(1), &stream(1), 10)
        .expect("the stream window ends when it says it does");

    let mut budget = MediaBudget::default();
    assert_eq!(
        spend(&mut budget, full_size_frames_per_minute(), false),
        None
    );
    assert_eq!(
        budget.charge(NOW + 59_999, &call_id(1), &stream(200), MAX_MEDIA_CT_BYTES),
        Err(MediaRefusal::ByteRate),
        "the byte window ended a millisecond early"
    );
    budget
        .charge(NOW + 60_000, &call_id(1), &stream(200), MAX_MEDIA_CT_BYTES)
        .expect("the byte window ends when it says it does");
}

#[test]
fn the_stream_table_never_grows_past_its_bound_however_long_the_flood_runs() {
    // A refusal proves the check fired. Only the count proves the table did not grow
    // behind it, and a client rotating stream ids is the one case where the two come
    // apart: it never repeats an id, so nothing it sends can ever be pruned by reuse.
    let mut budget = MediaBudget::default();
    for index in 0..MAX_TRACKED_STREAMS {
        budget
            .charge(NOW, &call_id(1), &stream(index as u8), 1)
            .expect("the table's allowance");
    }
    assert_eq!(budget.tracked_streams(), MAX_TRACKED_STREAMS);

    for index in 0..1_000u32 {
        let invented = (index.to_be_bytes()[2], index.to_be_bytes()[3]);
        let id = [0xFF, 0xEE, invented.0, invented.1];
        assert_eq!(
            budget.charge(NOW, &call_id(1), &id, 1),
            Err(MediaRefusal::TooManyStreams),
        );
        assert_eq!(
            budget.tracked_streams(),
            MAX_TRACKED_STREAMS,
            "a refused stream took a seat in the table"
        );
    }
}

#[test]
fn each_refusal_names_its_own_lever_and_its_own_interval() {
    // One error code for three causes is deliberate: a client's response to all
    // three is the same shape. The interval is not the same, and neither is the
    // number the client shows a human. A byte-rate refusal answered with a one
    // second interval is an instruction to come back and be refused fifty-nine more
    // times, which is the flood the once-a-second answer exists to prevent.
    assert_eq!(
        MediaRefusal::StreamRate.code(),
        ErrorCode::GroupIngressLimited
    );
    assert_eq!(
        MediaRefusal::ByteRate.code(),
        ErrorCode::GroupIngressLimited
    );
    assert_eq!(
        MediaRefusal::TooManyStreams.code(),
        ErrorCode::GroupIngressLimited
    );

    assert_eq!(MediaRefusal::StreamRate.retry_after(), 1);
    assert_eq!(MediaRefusal::TooManyStreams.retry_after(), 1);
    assert_eq!(MediaRefusal::ByteRate.retry_after(), 60);

    assert_eq!(
        MediaRefusal::StreamRate.detail(),
        u64::from(MEDIA_FRAMES_PER_STREAM_PER_SECOND)
    );
    assert_eq!(MediaRefusal::ByteRate.detail(), MEDIA_BYTES_PER_MINUTE);
    assert_eq!(
        MediaRefusal::TooManyStreams.detail(),
        MAX_TRACKED_STREAMS as u64
    );

    // Every detail names a limit this build actually enforces, so a client that
    // surfaced one could never show a number nothing checks.
    for refusal in [
        MediaRefusal::StreamRate,
        MediaRefusal::ByteRate,
        MediaRefusal::TooManyStreams,
    ] {
        assert!(refusal.detail() > 0);
        assert!(refusal.retry_after() > 0);
    }
}

// MARK: What the client is actually told

fn config_with_calls() -> Config {
    Config::resolve(&Values::from_pairs(vec![
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@localhost/weald_relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
        (keys::CALLS, "on"),
        (keys::MAX_CONCURRENT_CALLS, "16"),
    ]))
    .expect("configuration resolves")
}

fn ready(config: &Config) -> Session {
    let mut session = Session::new(config);
    session.handle(
        Frame::Connect {
            version: PROTOCOL_VERSION,
            groups: vec![group(1)],
            sent_at: NOW,
        },
        NOW,
    );
    session.authenticated(0);
    assert_eq!(session.state(), State::Ready);
    session
}

fn audio(stream_seed: u8, bytes: usize) -> Frame {
    Frame::Media {
        call_id: call_id(0xC1).to_vec(),
        stream: stream(stream_seed).to_vec(),
        seq: 1,
        ct: vec![0u8; bytes],
    }
}

/// The one error a reaction carries, with its interval and its limit.
fn answer(reaction: &Reaction) -> (ErrorCode, Option<u32>, Option<u64>) {
    match reaction {
        Reaction::Reply(frames) | Reaction::ReplyAndClose(frames) => match frames.as_slice() {
            [Frame::Error(error)] => (
                error.code,
                error.retry_after,
                error.detail.as_ref().map(|bytes| {
                    u64::from_be_bytes(
                        <[u8; 8]>::try_from(bytes.as_slice()).expect("an eight byte detail"),
                    )
                }),
            ),
            other => panic!("expected one error frame, got {other:?}"),
        },
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_connection_over_its_minute_of_bytes_is_told_to_come_back_in_a_minute() {
    let config = config_with_calls();
    let mut session = ready(&config);

    let mut accepted = 0u64;
    let mut refusal = None;
    'outer: for index in 0..MAX_TRACKED_STREAMS as u8 {
        for _ in 0..MEDIA_FRAMES_PER_STREAM_PER_SECOND {
            match session.handle(audio(index, MAX_MEDIA_CT_BYTES), NOW) {
                Reaction::Defer(Work::PublishMedia { .. }) => accepted += 1,
                other => {
                    refusal = Some(other);
                    break 'outer;
                }
            }
        }
    }

    let refusal = refusal.expect("the minute of bytes is finite");
    assert_eq!(
        accepted,
        full_size_frames_per_minute(),
        "the session spent a different minute from the budget's"
    );
    assert_eq!(
        answer(&refusal),
        (
            ErrorCode::GroupIngressLimited,
            Some(60),
            Some(MEDIA_BYTES_PER_MINUTE)
        ),
        "a byte-rate refusal named the per-second lever"
    );
}

#[test]
fn a_stream_over_its_rate_is_told_to_come_back_in_a_second() {
    let config = config_with_calls();
    let mut session = ready(&config);
    for _ in 0..MEDIA_FRAMES_PER_STREAM_PER_SECOND {
        assert!(matches!(
            session.handle(audio(1, 10), NOW),
            Reaction::Defer(Work::PublishMedia { .. })
        ));
    }
    assert_eq!(
        answer(&session.handle(audio(1, 10), NOW)),
        (
            ErrorCode::GroupIngressLimited,
            Some(1),
            Some(u64::from(MEDIA_FRAMES_PER_STREAM_PER_SECOND))
        ),
    );
}

#[test]
fn a_client_inventing_stream_ids_is_told_how_many_it_may_hold() {
    let config = config_with_calls();
    let mut session = ready(&config);
    for index in 0..MAX_TRACKED_STREAMS as u8 {
        assert!(matches!(
            session.handle(audio(index, 10), NOW),
            Reaction::Defer(Work::PublishMedia { .. })
        ));
    }
    assert_eq!(
        answer(&session.handle(audio(MAX_TRACKED_STREAMS as u8, 10), NOW)),
        (
            ErrorCode::GroupIngressLimited,
            Some(1),
            Some(MAX_TRACKED_STREAMS as u64)
        ),
    );
}

// MARK: The kinds that leave

#[test]
fn the_leaving_kinds_are_the_ones_that_do_not_join_and_the_set_is_exhaustive() {
    // `joins()` is read by exactly one branch in `publish_call`, and that branch
    // decides between taking a seat and giving one up. A kind that answered wrongly
    // would either leak a participant on every decline or drop one on every offer,
    // and neither shows up as an error anywhere.
    let joining: Vec<_> = CallKind::ALL.iter().filter(|k| k.joins()).collect();
    let leaving: Vec<_> = CallKind::ALL.iter().filter(|k| !k.joins()).collect();
    assert_eq!(joining.len() + leaving.len(), CallKind::ALL.len());
    assert_eq!(joining, vec![&CallKind::Offer, &CallKind::Answer]);
    assert_eq!(leaving, vec![&CallKind::Decline, &CallKind::Bye]);
}

#[tokio::test]
async fn a_group_mismatch_names_the_denial_class_rather_than_a_quota() {
    // The classes are not interchangeable: `operations.md` has `denied` meaning do
    // not retry and `quota` meaning retry after the stated interval. A mismatch
    // answered as a quota would have every client in the room retrying a call id it
    // will never be allowed to use.
    assert_eq!(
        JoinRefusal::GroupMismatch.code(),
        ErrorCode::WriterNotInAccessSet
    );
    assert_eq!(JoinRefusal::TooManyCalls.code(), ErrorCode::RateLimited);
    assert_eq!(JoinRefusal::CallFull.code(), ErrorCode::RateLimited);

    // And the class is kept by the interval as well as by the code. A `quota` answer
    // is defined as "retry after the named interval", and one that named none was an
    // answer a client could not act on: the Android client drops a non-terminal error
    // with no interval, so a call refused by a full instance or a full call rang out
    // its whole ringing timeout and then reported no answer. A `denied` still names
    // none, because it will be refused identically forever.
    assert_eq!(JoinRefusal::GroupMismatch.retry_after(), None);
    assert_eq!(JoinRefusal::TooManyCalls.retry_after(), Some(5));
    assert_eq!(JoinRefusal::CallFull.retry_after(), Some(5));
    for refusal in [JoinRefusal::TooManyCalls, JoinRefusal::CallFull] {
        assert_eq!(refusal.code(), ErrorCode::RateLimited);
        assert!(
            refusal.retry_after().is_some(),
            "every quota refusal names an interval"
        );
    }

    // And the detail names the lever the operator or the user can act on.
    assert_eq!(JoinRefusal::GroupMismatch.detail(16), 0);
    assert_eq!(JoinRefusal::TooManyCalls.detail(16), 16);
    assert_eq!(
        JoinRefusal::CallFull.detail(16),
        MAX_PARTICIPANTS_PER_CALL as u64
    );

    // The registry decides it before anything is fanned out, for both directions of
    // the mismatch, so neither room can be reached through the other's call id.
    let registry = CallRegistry::new(4);
    let (first, sender, _first) = peer(1);
    registry
        .join(&call_id(5), &group(1), first, sender)
        .await
        .expect("opens against group one");
    let (second, sender, _second) = peer(2);
    assert_eq!(
        registry.join(&call_id(5), &group(2), second, sender).await,
        Err(JoinRefusal::GroupMismatch),
    );
    assert_eq!(registry.group_of(&call_id(5)).await, Some(group(1)));
}
