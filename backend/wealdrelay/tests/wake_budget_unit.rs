// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The `WAKE` frame budget, without a socket and without a database.
//!
//! `WAKE` was the last mutating, pool-touching arm the session frame table
//! deferred with no ceiling of any kind. Every form costs two round trips
//! against the shared eight connection pool: the workspace salt read, then the
//! handle row. The registration ceiling in `push::store` covers only the
//! `Register` branch, so `Clear` and `Query` reached Postgres at socket speed
//! (WEALD-L452).
//!
//! The claim worth holding is the negative one: a refused frame is answered
//! from session state rather than deferred, so it reaches no database at all,
//! and the connection survives the refusal.

use wealdrelay::config::{keys, Config, Values};
use wealdrelay::frame::{ErrorCode, Frame, WakeBody, PROTOCOL_VERSION};
use wealdrelay::session::{
    Reaction, Session, State, Work, FRAME_BUDGET_WINDOW_MS, WAKE_FRAMES_PER_MINUTE,
};

const NOW: u64 = 1_700_000_000_000;

fn config() -> Config {
    Config::resolve(&Values::from_pairs(vec![
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@localhost/weald_relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
    ]))
    .expect("configuration resolves")
}

fn ready(config: &Config) -> Session {
    let mut session = Session::new(config);
    session.handle(
        Frame::Connect {
            version: PROTOCOL_VERSION,
            groups: vec![vec![1; 32]],
            sent_at: NOW,
        },
        NOW,
    );
    session.authenticated(0);
    assert_eq!(session.state(), State::Ready);
    session
}

fn refusal(reaction: &Reaction) -> ErrorCode {
    match reaction {
        Reaction::Reply(frames) | Reaction::ReplyAndClose(frames) => match frames.as_slice() {
            [Frame::Error(error)] => error.code,
            other => panic!("expected exactly one error frame, got {other:?}"),
        },
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn drain(session: &mut Session, body: WakeBody) {
    for _ in 0..WAKE_FRAMES_PER_MINUTE {
        assert!(matches!(
            session.handle(Frame::Wake(body.clone()), NOW),
            Reaction::Defer(Work::WakeRegistration { .. })
        ));
    }
}

#[test]
fn the_wake_budget_refuses_a_clear_and_keeps_the_connection() {
    let config = config();
    let mut session = ready(&config);
    drain(&mut session, WakeBody::Clear);
    // Refused rather than deferred: neither the salt read nor the delete runs.
    let reaction = session.handle(Frame::Wake(WakeBody::Clear), NOW);
    assert_eq!(refusal(&reaction).qualified(), "quota/rate_limited");
    assert_eq!(session.state(), State::Ready);
    assert!(matches!(
        session.handle(Frame::Wake(WakeBody::Clear), NOW + FRAME_BUDGET_WINDOW_MS),
        Reaction::Defer(Work::WakeRegistration { .. })
    ));
}

#[test]
fn the_wake_budget_refuses_a_query_too() {
    let config = config();
    let mut session = ready(&config);
    drain(&mut session, WakeBody::Query);
    let reaction = session.handle(Frame::Wake(WakeBody::Query), NOW);
    assert_eq!(refusal(&reaction).qualified(), "quota/rate_limited");
    assert_eq!(session.state(), State::Ready);
}

/// One allowance for the frame, not one per form: a peer cannot spend a fresh
/// window by alternating `Clear` and `Query` against the same connection.
#[test]
fn the_forms_share_one_allowance() {
    let config = config();
    let mut session = ready(&config);
    drain(&mut session, WakeBody::Clear);
    let reaction = session.handle(Frame::Wake(WakeBody::Query), NOW);
    assert_eq!(refusal(&reaction).qualified(), "quota/rate_limited");
}

/// The permanently-wrong refusals stay above the charge, so a malformed
/// registration is still answered for what it is rather than for the budget.
#[test]
fn a_malformed_expiry_is_refused_for_its_own_reason() {
    let config = config();
    let mut session = ready(&config);
    let reaction = session.handle(
        Frame::Wake(WakeBody::Register {
            handle: vec![9; 16],
            categories: 1,
            expires_at: 1,
        }),
        NOW,
    );
    assert_eq!(refusal(&reaction), ErrorCode::PushHandleMalformed);
    assert_eq!(session.state(), State::Ready);
}
