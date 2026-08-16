// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The `HANDSHAKE` frame budget, without a socket and without a database.
//!
//! `HANDSHAKE` is the most expensive durable write on the socket per frame: each
//! one takes `relay_group ... for update`, appends a row of up to the 512 KiB
//! handshake ceiling to a log nothing compacts, and fans the whole message out to
//! every subscriber. It was deferred straight to `Work::PublishHandshake` with no
//! budget of any kind, and `send_budget::charge` runs in the `Work::Accept` arm
//! only, so nothing bounded the path: one admitted device could serialise every
//! real committer in a group behind that row lock while growing a log the relay has
//! no operation to shrink (WEALD-349).
//!
//! As with the `SUB` and `RECON` budgets, the claim worth holding is the negative
//! one. A refused frame must do no work, and "no work" is only visible in the
//! reaction, because the row lock and the insert are reached through
//! `Reaction::Defer`. So each test asserts the reaction is a refusal rather than a
//! deferral, not merely that the error code says rate limited.

use wealdrelay::config::{keys, Config, Values};
use wealdrelay::frame::{ErrorCode, Frame, PROTOCOL_VERSION};
use wealdrelay::session::{
    Reaction, Session, State, Work, FRAME_BUDGET_WINDOW_MS, HANDSHAKE_FRAMES_PER_MINUTE,
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

/// A session in `Ready`, the only state `HANDSHAKE` is accepted in.
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

fn handshake(byte: u8) -> Frame {
    Frame::Handshake {
        group: group(byte),
        seq: 0,
        message: vec![9; 64],
    }
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
fn the_handshake_budget_refuses_the_frame_and_keeps_the_connection() {
    let config = config();
    let mut session = ready(&config);
    for _ in 0..HANDSHAKE_FRAMES_PER_MINUTE {
        assert!(matches!(
            session.handle(handshake(1), NOW),
            Reaction::Defer(Work::PublishHandshake { .. })
        ));
    }
    // The frame past the budget is refused, and refused without deferring: no row
    // lock is taken and no row is appended, which is the property that bounds the
    // log rather than merely slowing the flood down.
    let reaction = session.handle(handshake(1), NOW);
    assert_eq!(refusal(&reaction).qualified(), "quota/rate_limited");
    // The socket stays up, like every other frame budget, and the durable envelope
    // path is untouched: a committer flood is a client to slow down, not a peer to
    // disconnect.
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
    // And the window resets, so one burst never locks a committer out for good.
    assert!(matches!(
        session.handle(handshake(1), NOW + FRAME_BUDGET_WINDOW_MS),
        Reaction::Defer(Work::PublishHandshake { .. })
    ));
}

#[test]
fn the_budget_is_per_connection_and_counts_every_group() {
    let config = config();
    let mut session = ready(&config);
    // Spread across groups rather than repeated on one, because the resource the
    // budget protects is the process, not a single group's row lock: a flood that
    // rotates the group id must meet the same wall.
    for i in 0..HANDSHAKE_FRAMES_PER_MINUTE {
        assert!(matches!(
            session.handle(handshake((i % 251) as u8), NOW),
            Reaction::Defer(Work::PublishHandshake { .. })
        ));
    }
    let reaction = session.handle(handshake(200), NOW);
    assert_eq!(refusal(&reaction).qualified(), "quota/rate_limited");
}
