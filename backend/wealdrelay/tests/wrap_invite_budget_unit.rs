// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The `WRAP` and `INVITE` frame budgets, without a socket and without a database.
//!
//! Both were deferred straight to their work with no budget of any kind: a wrap
//! inserts a row per recovery key and invite administration reads the record and
//! writes rows, so an unbudgeted frame of either kind was free durable-write work
//! for any admitted device pipelining at line rate (WEALD-L217). `HANDSHAKE` and
//! `ACCESS` had already been given the same wall for the same reason.
//!
//! As with the sibling budgets, the claim worth holding is the negative one. A
//! refused frame must do no work, and "no work" is only visible in the reaction,
//! because the row writes are reached through `Reaction::Defer`. So each test
//! asserts the reaction is a refusal rather than a deferral, not merely that the
//! error code says rate limited.

use wealdrelay::config::{keys, Config, Values};
use wealdrelay::frame::{ErrorCode, Frame, PROTOCOL_VERSION};
use wealdrelay::session::{
    Reaction, Session, State, Work, FRAME_BUDGET_WINDOW_MS, INVITE_FRAMES_PER_MINUTE,
    WRAP_FRAMES_PER_MINUTE,
};

const NOW: u64 = 1_700_000_000_000;

fn group(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

fn config() -> Config {
    Config::resolve(&Values::from_pairs(vec![
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@localhost/weald_relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
    ]))
    .expect("configuration resolves")
}

/// A session in `Ready`, the only state either frame is accepted in.
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

fn wrap() -> Frame {
    Frame::Wrap { body: vec![9; 64] }
}

fn invite() -> Frame {
    Frame::Invite { body: vec![8; 64] }
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

#[test]
fn the_wrap_budget_refuses_the_frame_and_keeps_the_connection() {
    let config = config();
    let mut session = ready(&config);
    for _ in 0..WRAP_FRAMES_PER_MINUTE {
        assert!(matches!(
            session.handle(wrap(), NOW),
            Reaction::Defer(Work::PublishWrap { .. })
        ));
    }
    // The frame past the budget is refused, and refused without deferring: no row
    // is written, which is the property that bounds the table rather than merely
    // slowing the flood down.
    let reaction = session.handle(wrap(), NOW);
    assert_eq!(refusal(&reaction).qualified(), "quota/rate_limited");
    // The socket stays up, like every other frame budget.
    assert_eq!(session.state(), State::Ready);
    // And the window resets, so one burst never locks a device out for good.
    assert!(matches!(
        session.handle(wrap(), NOW + FRAME_BUDGET_WINDOW_MS),
        Reaction::Defer(Work::PublishWrap { .. })
    ));
}

#[test]
fn the_invite_budget_refuses_the_frame_and_keeps_the_connection() {
    let config = config();
    let mut session = ready(&config);
    for _ in 0..INVITE_FRAMES_PER_MINUTE {
        assert!(matches!(
            session.handle(invite(), NOW),
            Reaction::Defer(Work::AdministerInvite { .. })
        ));
    }
    let reaction = session.handle(invite(), NOW);
    assert_eq!(refusal(&reaction).qualified(), "quota/rate_limited");
    assert_eq!(session.state(), State::Ready);
    // A refused invite budget does not touch the join path's own budget: a person
    // redeeming on this socket is still bounded only by `JOIN`'s allowance.
    assert!(matches!(
        session.handle(Frame::Join { body: vec![1; 16] }, NOW),
        Reaction::Defer(Work::Redeem { .. })
    ));
}

#[test]
fn the_two_budgets_are_independent_counters() {
    let config = config();
    let mut session = ready(&config);
    // Spending `WRAP` to its wall does not spend `INVITE`: the two protect
    // different tables, so exhausting one must not hand a second flood a discount
    // on the other.
    for _ in 0..WRAP_FRAMES_PER_MINUTE {
        assert!(matches!(
            session.handle(wrap(), NOW),
            Reaction::Defer(Work::PublishWrap { .. })
        ));
    }
    assert!(matches!(
        session.handle(invite(), NOW),
        Reaction::Defer(Work::AdministerInvite { .. })
    ));
}
