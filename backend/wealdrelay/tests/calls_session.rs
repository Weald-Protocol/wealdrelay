// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The call frames at the session layer: without a socket, without a registry and
//! without a database.
//!
//! This is the layer `calls_unit.rs` skips and `calls_socket.rs` reaches only
//! through a real connection, and it is where the ordering lives. Six things
//! happen to a `CALL` before anything is routed, in a fixed order, and the order
//! is a security property rather than a style: the kind is read before a budget is
//! charged, so a peer cannot spend somebody's allowance with garbage; the ceiling
//! is checked before the payload is copied, so an oversized frame costs nothing to
//! refuse; and every one of them happens before the group is authorized, which is
//! the check that costs a database read.
//!
//! Driving `Session::handle` directly is what makes that order observable. Over a
//! socket the only visible difference between "refused for its kind" and "refused
//! for its budget" is the error code, and a relay that charged first and read the
//! kind second would answer identically to this one while being exploitable.
//! Here the budget's remaining allowance is a thing a test can measure.
//!
//! Every refusal names its code for the reason `calls_unit.rs` gives: a client
//! branches on the class, and `operations.md` has `retry`, `quota` and `denied`
//! meaning three incompatible things.

use wealdrelay::calls::{
    CallKind, CALL_FRAMES_PER_MINUTE, MAX_CALL_BODY_BYTES, MAX_MEDIA_CT_BYTES, MAX_TRACKED_STREAMS,
    MEDIA_BYTES_PER_MINUTE, MEDIA_FRAMES_PER_STREAM_PER_SECOND, MEDIA_STREAM_WINDOW_MS,
};
use wealdrelay::config::{keys, Config, Values};
use wealdrelay::frame::{ErrorCode, Frame, PROTOCOL_VERSION};
use wealdrelay::session::{Reaction, Session, State, Work, FRAME_BUDGET_WINDOW_MS};

const NOW: u64 = 1_800_000_000_000;

fn group(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

fn call_id(byte: u8) -> Vec<u8> {
    vec![byte; 16]
}

fn stream(byte: u8) -> Vec<u8> {
    vec![byte; 4]
}

/// A relay that carries calls, which is opt-in and needs its ceiling stated.
fn config_with_calls() -> Config {
    config(&[(keys::CALLS, "on"), (keys::MAX_CONCURRENT_CALLS, "16")])
}

fn config(pairs: &[(&'static str, &'static str)]) -> Config {
    let mut values = vec![
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@localhost/weald_relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
    ];
    for (key, value) in pairs {
        values.retain(|(existing, _)| existing != key);
        values.push((key, value));
    }
    Config::resolve(&Values::from_pairs(values)).expect("configuration resolves")
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

fn signal(kind: u8, body: Vec<u8>) -> Frame {
    Frame::Call {
        call_id: call_id(0xC1),
        group: group(1),
        epoch: 4,
        kind,
        body,
    }
}

fn audio(stream_seed: u8, ct: Vec<u8>) -> Frame {
    Frame::Media {
        call_id: call_id(0xC1),
        stream: stream(stream_seed),
        seq: 1,
        ct,
    }
}

fn refusal(reaction: &Reaction) -> ErrorCode {
    match reaction {
        Reaction::Reply(frames) | Reaction::ReplyAndClose(frames) => match frames.as_slice() {
            [Frame::Error(error)] => error.code,
            other => panic!("expected one error frame, got {other:?}"),
        },
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The `detail` an answer carries, so a client can surface the lever it hit
/// rather than guess at one.
fn detail(reaction: &Reaction) -> Option<Vec<u8>> {
    match reaction {
        Reaction::Reply(frames) | Reaction::ReplyAndClose(frames) => match frames.as_slice() {
            [Frame::Error(error)] => error.detail.clone(),
            other => panic!("expected one error frame, got {other:?}"),
        },
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The interval an answer names, which is the field a well-behaved client sleeps
/// on.
fn retry_after(reaction: &Reaction) -> Option<u32> {
    match reaction {
        Reaction::Reply(frames) | Reaction::ReplyAndClose(frames) => match frames.as_slice() {
            [Frame::Error(error)] => error.retry_after,
            other => panic!("expected one error frame, got {other:?}"),
        },
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// MARK: What is decided, and in what order

#[test]
fn every_signalling_kind_is_deferred_with_its_fields_intact() {
    let config = config_with_calls();
    for kind in CallKind::ALL {
        let mut session = ready(&config);
        match session.handle(signal(*kind as u8, b"sealed".to_vec()), NOW) {
            Reaction::Defer(Work::PublishCall {
                call_id: id,
                group: g,
                epoch,
                kind: decided,
                body,
            }) => {
                // The narrowed id is what the work item carries, so the socket
                // layer has nothing left to convert and no arm for a width that
                // cannot occur.
                assert_eq!(id.to_vec(), call_id(0xC1));
                assert_eq!(g, group(1));
                assert_eq!(epoch, 4);
                assert_eq!(decided, *kind);
                assert_eq!(body, b"sealed");
            }
            other => panic!("{} was not deferred: {other:?}", kind.as_str()),
        }
    }
}

#[test]
fn a_media_frame_is_deferred_with_both_ids_narrowed() {
    let config = config_with_calls();
    let mut session = ready(&config);
    match session.handle(audio(7, vec![9; 80]), NOW) {
        Reaction::Defer(Work::PublishMedia {
            call_id: id,
            stream: s,
            seq,
            ct,
        }) => {
            assert_eq!(id.to_vec(), call_id(0xC1));
            assert_eq!(s.to_vec(), stream(7));
            assert_eq!(seq, 1);
            assert_eq!(ct, vec![9; 80]);
        }
        other => panic!("media was not deferred: {other:?}"),
    }
}

#[test]
fn an_unreadable_kind_is_refused_before_it_can_spend_a_budget() {
    // The ordering claim, and the reason it is not cosmetic: if the budget were
    // charged first, a peer could exhaust a connection's signalling allowance with
    // frames that were never going to be routed, and the connection's own call
    // would then be unable to hang up.
    let config = config_with_calls();
    let mut session = ready(&config);
    for byte in [0u8, 5, 6, 240, 255] {
        let reaction = session.handle(signal(byte, b"sealed".to_vec()), NOW);
        assert_eq!(
            refusal(&reaction),
            ErrorCode::MalformedHeader,
            "kind {byte} was not refused as malformed"
        );
    }
    // And the whole allowance is still there, which is the half that would have
    // been silently lost.
    for _ in 0..CALL_FRAMES_PER_MINUTE {
        assert!(matches!(
            session.handle(signal(CallKind::Offer as u8, b"s".to_vec()), NOW),
            Reaction::Defer(Work::PublishCall { .. })
        ));
    }
}

#[test]
fn both_ceilings_are_inclusive_and_name_themselves() {
    let config = config_with_calls();
    let mut session = ready(&config);

    // Exactly at the ceiling is carried. A bound a client cannot reach is a bound
    // a client cannot plan against.
    assert!(matches!(
        session.handle(
            signal(CallKind::Offer as u8, vec![0; MAX_CALL_BODY_BYTES]),
            NOW
        ),
        Reaction::Defer(Work::PublishCall { .. })
    ));
    let reaction = session.handle(
        signal(CallKind::Offer as u8, vec![0; MAX_CALL_BODY_BYTES + 1]),
        NOW,
    );
    assert_eq!(refusal(&reaction), ErrorCode::EnvelopeTooLarge);
    assert_eq!(
        detail(&reaction),
        Some((MAX_CALL_BODY_BYTES as u64).to_be_bytes().to_vec())
    );

    assert!(matches!(
        session.handle(audio(1, vec![0; MAX_MEDIA_CT_BYTES]), NOW),
        Reaction::Defer(Work::PublishMedia { .. })
    ));
    let reaction = session.handle(audio(1, vec![0; MAX_MEDIA_CT_BYTES + 1]), NOW);
    assert_eq!(refusal(&reaction), ErrorCode::EnvelopeTooLarge);
    assert_eq!(
        detail(&reaction),
        Some((MAX_MEDIA_CT_BYTES as u64).to_be_bytes().to_vec())
    );
}

#[test]
fn an_oversized_media_frame_is_refused_without_spending_the_stream() {
    // Refused on the declared length, before anything is charged. A relay that
    // charged first would let one oversized frame cost a legitimate frame's seat
    // in the same window.
    let config = config_with_calls();
    let mut session = ready(&config);
    for _ in 0..200 {
        assert_eq!(
            refusal(&session.handle(audio(1, vec![0; MAX_MEDIA_CT_BYTES + 1]), NOW)),
            ErrorCode::EnvelopeTooLarge
        );
    }
    for _ in 0..MEDIA_FRAMES_PER_STREAM_PER_SECOND {
        assert!(matches!(
            session.handle(audio(1, vec![0; 80]), NOW),
            Reaction::Defer(Work::PublishMedia { .. })
        ));
    }
}

// MARK: The budgets

#[test]
fn the_signalling_budget_refuses_the_frame_and_keeps_the_connection() {
    let config = config_with_calls();
    let mut session = ready(&config);
    for _ in 0..CALL_FRAMES_PER_MINUTE {
        assert!(matches!(
            session.handle(signal(CallKind::Offer as u8, b"s".to_vec()), NOW),
            Reaction::Defer(Work::PublishCall { .. })
        ));
    }
    let reaction = session.handle(signal(CallKind::Offer as u8, b"s".to_vec()), NOW);
    assert_eq!(refusal(&reaction), ErrorCode::RateLimited);
    assert_eq!(
        detail(&reaction),
        Some(u64::from(CALL_FRAMES_PER_MINUTE).to_be_bytes().to_vec())
    );
    // The frame only. A refused offer must not take down a call already running on
    // the same socket, and a socket that closed here would drop the audio too.
    assert_eq!(session.state(), State::Ready);
    assert!(matches!(
        session.handle(audio(1, vec![0; 80]), NOW),
        Reaction::Defer(Work::PublishMedia { .. })
    ));
    // And the window resets.
    assert!(matches!(
        session.handle(
            signal(CallKind::Bye as u8, b"s".to_vec()),
            NOW + FRAME_BUDGET_WINDOW_MS
        ),
        Reaction::Defer(Work::PublishCall { .. })
    ));
}

#[test]
fn the_media_budget_answers_a_flood_once_and_then_stops_answering() {
    // The amplification bound, at the layer that decides it. Six hundred refusals
    // answered six hundred times is a relay doubling a flood it is already
    // refusing, and the answers would queue on the flooder's own bounded outbound
    // queue and turn a rate limit into a disconnect.
    let config = config_with_calls();
    let mut session = ready(&config);
    for _ in 0..MEDIA_FRAMES_PER_STREAM_PER_SECOND {
        assert!(matches!(
            session.handle(audio(1, vec![0; 80]), NOW),
            Reaction::Defer(Work::PublishMedia { .. })
        ));
    }
    let first = session.handle(audio(1, vec![0; 80]), NOW);
    assert_eq!(refusal(&first), ErrorCode::GroupIngressLimited);
    assert_eq!(
        detail(&first),
        Some(
            u64::from(MEDIA_FRAMES_PER_STREAM_PER_SECOND)
                .to_be_bytes()
                .to_vec()
        )
    );
    // Every one after it is refused in silence: nothing was accepted, and what is
    // economised is the complaint rather than the enforcement.
    for _ in 0..600 {
        assert_eq!(
            session.handle(audio(1, vec![0; 80]), NOW),
            Reaction::Reply(Vec::new())
        );
    }
    // Still silent at the last millisecond of the window: the interval is the
    // window's width and not merely "sometimes".
    let later = NOW + MEDIA_STREAM_WINDOW_MS - 1;
    for _ in 0..MEDIA_FRAMES_PER_STREAM_PER_SECOND + 1 {
        assert_eq!(
            session.handle(audio(1, vec![0; 80]), later),
            Reaction::Reply(Vec::new())
        );
    }
    // And a window later a client that is still wrong is told again, because the
    // answer carrying `retry_after` is the only thing that tells it to slow down.
    // The new window's allowance is spent first, since a fresh window carries
    // frames rather than refusing them.
    let next = NOW + MEDIA_STREAM_WINDOW_MS;
    for _ in 0..MEDIA_FRAMES_PER_STREAM_PER_SECOND {
        assert!(matches!(
            session.handle(audio(1, vec![0; 80]), next),
            Reaction::Defer(Work::PublishMedia { .. })
        ));
    }
    assert_eq!(
        refusal(&session.handle(audio(1, vec![0; 80]), next)),
        ErrorCode::GroupIngressLimited
    );
}

#[test]
fn each_media_limit_names_its_own_interval_and_its_own_ceiling() {
    // One code for three causes, and deliberately not one interval. A client
    // refused for its minute of bytes and told to come back in a second will be
    // refused fifty-nine more times, which is the flood the single answer per
    // window exists to prevent arriving by the front door. So the code is shared
    // and the `retry_after` and `detail` are not, and all three are asserted
    // through the session rather than against the enum, because the mapping only
    // matters where it reaches a client.
    let config = config_with_calls();

    // Per stream, per second.
    let mut stream_limited = ready(&config);
    for _ in 0..MEDIA_FRAMES_PER_STREAM_PER_SECOND {
        stream_limited.handle(audio(1, vec![0; 80]), NOW);
    }
    let answer = stream_limited.handle(audio(1, vec![0; 80]), NOW);
    assert_eq!(refusal(&answer), ErrorCode::GroupIngressLimited);
    assert_eq!(retry_after(&answer), Some(1));
    assert_eq!(
        detail(&answer),
        Some(
            u64::from(MEDIA_FRAMES_PER_STREAM_PER_SECOND)
                .to_be_bytes()
                .to_vec()
        )
    );

    // Bytes per connection, per minute. Spent across enough streams that no
    // per-stream rate is touched, so the answer can only be the byte limit: this is
    // the one case where naming the wrong ceiling would send a client back in a
    // second against a window with fifty-nine to run.
    let mut byte_limited = ready(&config);
    let mut spent = 0u64;
    let mut id = 0u8;
    while spent + 1_024 <= MEDIA_BYTES_PER_MINUTE {
        assert!(matches!(
            byte_limited.handle(audio(id, vec![0; 1_024]), NOW),
            Reaction::Defer(Work::PublishMedia { .. })
        ));
        spent += 1_024;
        id = (id + 1) % (MAX_TRACKED_STREAMS as u8);
    }
    let answer = byte_limited.handle(audio(id, vec![0; 1_024]), NOW);
    assert_eq!(refusal(&answer), ErrorCode::GroupIngressLimited);
    assert_eq!(retry_after(&answer), Some(60));
    assert_eq!(
        detail(&answer),
        Some(MEDIA_BYTES_PER_MINUTE.to_be_bytes().to_vec())
    );

    // Distinct streams tracked, per window.
    let mut table_limited = ready(&config);
    for seed in 0..MAX_TRACKED_STREAMS {
        table_limited.handle(audio(seed as u8, vec![0; 80]), NOW);
    }
    let answer = table_limited.handle(audio(200, vec![0; 80]), NOW);
    assert_eq!(refusal(&answer), ErrorCode::GroupIngressLimited);
    assert_eq!(retry_after(&answer), Some(1));
    assert_eq!(
        detail(&answer),
        Some((MAX_TRACKED_STREAMS as u64).to_be_bytes().to_vec())
    );
}

#[test]
fn a_client_inventing_stream_ids_is_refused_and_the_connection_survives() {
    let config = config_with_calls();
    let mut session = ready(&config);
    for id in 0..MAX_TRACKED_STREAMS {
        assert!(matches!(
            session.handle(audio(id as u8, vec![0; 80]), NOW),
            Reaction::Defer(Work::PublishMedia { .. })
        ));
    }
    assert_eq!(
        refusal(&session.handle(audio(200, vec![0; 80]), NOW)),
        ErrorCode::GroupIngressLimited
    );
    assert_eq!(session.state(), State::Ready);
    // A stream it already had is still carried, because the refusal is about the
    // table's size and not about this connection being in disgrace.
    assert!(matches!(
        session.handle(audio(0, vec![0; 80]), NOW),
        Reaction::Defer(Work::PublishMedia { .. })
    ));
}

#[test]
fn the_three_budgets_do_not_starve_each_other() {
    // Signalling, media and envelopes are three allowances on purpose. A spent one
    // must never refuse another, or a call that ran out of signalling would take
    // chat down with it.
    let config = config_with_calls();
    let mut session = ready(&config);
    for _ in 0..CALL_FRAMES_PER_MINUTE {
        session.handle(signal(CallKind::Offer as u8, b"s".to_vec()), NOW);
    }
    assert_eq!(
        refusal(&session.handle(signal(CallKind::Offer as u8, b"s".to_vec()), NOW)),
        ErrorCode::RateLimited
    );
    assert!(matches!(
        session.handle(audio(1, vec![0; 80]), NOW),
        Reaction::Defer(Work::PublishMedia { .. })
    ));
    assert!(matches!(
        session.handle(
            Frame::Send {
                envelope: vec![7; 16]
            },
            NOW
        ),
        Reaction::Defer(Work::Accept { .. })
    ));
}

// MARK: The clock

#[test]
fn a_backwards_clock_does_not_freeze_the_signalling_budget() {
    // `Clock::System` is a wall clock, so an NTP correction moves `now_ms`
    // backwards. A window that asked only whether enough time had passed answered
    // "no" across such a step and stayed spent for the correction plus the whole
    // window after it: a one second correction became a minute in which a client
    // could not hang up a call it had already started.
    let config = config_with_calls();
    let mut session = ready(&config);
    for _ in 0..CALL_FRAMES_PER_MINUTE {
        session.handle(signal(CallKind::Offer as u8, b"s".to_vec()), NOW);
    }
    assert_eq!(
        refusal(&session.handle(signal(CallKind::Offer as u8, b"s".to_vec()), NOW)),
        ErrorCode::RateLimited
    );
    assert!(
        matches!(
            session.handle(signal(CallKind::Bye as u8, b"s".to_vec()), NOW - 1_000),
            Reaction::Defer(Work::PublishCall { .. })
        ),
        "a one second clock correction left the signalling budget frozen"
    );
}

#[test]
fn a_backwards_clock_does_not_freeze_the_media_budget() {
    let config = config_with_calls();
    let mut session = ready(&config);
    for id in 0..MAX_TRACKED_STREAMS {
        session.handle(audio(id as u8, vec![0; 80]), NOW);
    }
    assert_eq!(
        refusal(&session.handle(audio(200, vec![0; 80]), NOW)),
        ErrorCode::GroupIngressLimited
    );
    assert!(
        matches!(
            session.handle(audio(200, vec![0; 80]), NOW - 1_000),
            Reaction::Defer(Work::PublishMedia { .. })
        ),
        "a one second clock correction left the stream table frozen"
    );
}

// MARK: When calls are off, and before a session may speak

#[test]
fn a_relay_with_calls_off_refuses_both_frames_as_unsupported() {
    // The honest answer, and specifically not a `denied` or a `quota`: nothing is
    // wrong with the client and nothing about the group. This instance does not
    // carry calls, which is a fact about the deployment that a version 3 client
    // states in the interface as calls being unavailable here.
    let config = config(&[(keys::CALLS, "off")]);
    let mut session = ready(&config);
    assert_eq!(
        refusal(&session.handle(signal(CallKind::Offer as u8, b"s".to_vec()), NOW)),
        ErrorCode::ProtocolUnsupported
    );
    assert_eq!(
        refusal(&session.handle(audio(1, vec![0; 80]), NOW)),
        ErrorCode::ProtocolUnsupported
    );
    // And the connection is untouched: chat on a relay that carries no calls is
    // exactly as good as chat on one that does.
    assert_eq!(session.state(), State::Ready);
    assert!(matches!(
        session.handle(
            Frame::Send {
                envelope: vec![7; 16]
            },
            NOW
        ),
        Reaction::Defer(Work::Accept { .. })
    ));
}

#[test]
fn neither_call_frame_is_accepted_before_the_session_is_ready() {
    // `JOIN` is the only pre-auth frame there is. A `CALL` names a group and
    // claims a place in a conversation inside it, which is a stronger claim than a
    // beat rather than a weaker one, and a `MEDIA` claims a call that could only
    // have been opened by an authenticated `CALL`.
    let config = config_with_calls();
    for frame in [
        signal(CallKind::Offer as u8, b"s".to_vec()),
        audio(1, vec![0; 80]),
    ] {
        let mut fresh = Session::new(&config);
        let reaction = fresh.handle(frame.clone(), NOW);
        assert!(
            matches!(reaction, Reaction::ReplyAndClose(_)),
            "a call frame before CONNECT did not close the connection: {reaction:?}"
        );

        let mut connected = Session::new(&config);
        connected.handle(
            Frame::Connect {
                version: PROTOCOL_VERSION,
                groups: vec![group(1)],
                sent_at: NOW,
            },
            NOW,
        );
        let reaction = connected.handle(frame, NOW);
        assert!(
            matches!(reaction, Reaction::ReplyAndClose(_)),
            "a call frame before authentication did not close the connection: {reaction:?}"
        );
    }
}
