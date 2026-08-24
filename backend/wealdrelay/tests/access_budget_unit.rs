// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The `ACCESS` frame budget, without a socket and without a database.
//!
//! The rotation judgement hashes every principal and reads the prior set, and
//! the `Frame::Access` arm deferred that work with no ceiling of any kind while
//! every sibling arm charged first (WEALD-460, formerly WEALD-L139). One
//! admitted device could pipeline maximal rosters at line rate against a
//! runtime every other workspace on the instance shares.
//!
//! The claim worth holding is the negative one: the frame past the ceiling is
//! answered from session state rather than deferred, so it reaches no database
//! at all, and the connection survives the refusal.

use wealdrelay::config::{keys, Config, Values};
use wealdrelay::frame::{ErrorCode, Frame, PROTOCOL_VERSION};
use wealdrelay::session::{
    Reaction, Session, State, Work, ACCESS_FRAMES_PER_MINUTE, FRAME_BUDGET_WINDOW_MS,
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

/// A body the judgement would spend real CPU on, never decoded here: the point
/// is that the ceiling is charged before anything looks at it.
fn body() -> Vec<u8> {
    vec![7; 400_000]
}

fn drain(session: &mut Session) {
    for _ in 0..ACCESS_FRAMES_PER_MINUTE {
        assert!(matches!(
            session.handle(Frame::Access { body: body() }, NOW),
            Reaction::Defer(Work::RotateAccessSet { .. })
        ));
    }
}

#[test]
fn the_access_budget_refuses_a_maximal_rotation_and_keeps_the_connection() {
    let config = config();
    let mut session = ready(&config);
    drain(&mut session);
    // Refused rather than deferred: neither the prior-set read nor a single
    // keyed hash of the roster runs.
    let reaction = session.handle(Frame::Access { body: body() }, NOW);
    assert_eq!(refusal(&reaction).qualified(), "quota/rate_limited");
    assert_eq!(session.state(), State::Ready);
    // And the ceiling is a window, not a life sentence.
    assert!(matches!(
        session.handle(Frame::Access { body: body() }, NOW + FRAME_BUDGET_WINDOW_MS),
        Reaction::Defer(Work::RotateAccessSet { .. })
    ));
}
