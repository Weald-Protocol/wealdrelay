// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The `SUB` and `RECON` frame budgets, without a socket and without a database.
//!
//! These two frames are the largest amplifiers on the socket: a `RECON` is around
//! fifty bytes and costs an `authorize_group` query plus `log::items`,
//! `log::envelopes_for` and `reopen_omitted` over the window, and a repeated `SUB`
//! re-reads a group's log from `from_seq`. They were the only expensive frames not
//! charged against a per-connection budget, so one admitted device could starve
//! every other member of the workspace (WEALD-298).
//!
//! The claim these tests exist to hold is the negative one. A refused frame must do
//! no work at all, and "no work" is not visible in the code: it is visible in the
//! reaction, because every database round trip on these paths is reached through
//! `Reaction::Defer`. A refusal that answered `Reply` while still deferring would
//! pass a rate-limit assertion and fail the point of the budget, so each test
//! asserts the reaction is not a deferral rather than only asserting the code.

use wealdrelay::config::{keys, Config, Values};
use wealdrelay::frame::{ErrorCode, Frame, PROTOCOL_VERSION};
use wealdrelay::session::{
    Reaction, Session, State, Work, FRAME_BUDGET_WINDOW_MS, RECON_FRAMES_PER_MINUTE,
    SUB_FRAMES_PER_MINUTE,
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

fn sub(byte: u8) -> Frame {
    Frame::Sub {
        group: group(byte),
        from_seq: 0,
    }
}

fn recon(byte: u8) -> Frame {
    Frame::Recon {
        group: group(byte),
        payload: vec![0x60, 0x01],
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
fn the_sub_budget_refuses_the_frame_and_keeps_the_connection() {
    let config = config();
    let mut session = ready(&config);
    // One group, repeated, which is the amplifier: every one of these re-reads the
    // group's log from `from_seq`.
    for _ in 0..SUB_FRAMES_PER_MINUTE {
        assert!(matches!(
            session.handle(sub(1), NOW),
            Reaction::Defer(Work::Subscribe { .. })
        ));
    }
    let reaction = session.handle(sub(1), NOW);
    assert_eq!(refusal(&reaction).qualified(), "quota/rate_limited");
    // The socket stays up. A subscription flood is a client to slow down, not a peer
    // to disconnect, and the durable path is unaffected.
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
    // And the window resets, so one burst never locks a client out for good.
    assert!(matches!(
        session.handle(sub(1), NOW + FRAME_BUDGET_WINDOW_MS),
        Reaction::Defer(Work::Subscribe { .. })
    ));
}

#[test]
fn a_full_cold_start_fits_inside_the_sub_budget() {
    // The bound this budget must not break: a connection subscribing every group it
    // is allowed to hold. A ceiling at or below `MAX_GROUPS_PER_CONNECTION` would
    // present as a network fault on the largest legitimate workspace.
    assert!(SUB_FRAMES_PER_MINUTE as usize > wealdrelay::session::MAX_GROUPS_PER_CONNECTION);
    let config = config();
    let mut session = ready(&config);
    for index in 0..wealdrelay::session::MAX_GROUPS_PER_CONNECTION {
        let mut id = vec![0; 32];
        id[..8].copy_from_slice(&(index as u64).to_be_bytes());
        assert!(matches!(
            session.handle(
                Frame::Sub {
                    group: id,
                    from_seq: 0
                },
                NOW
            ),
            Reaction::Defer(Work::Subscribe { .. })
        ));
    }
}

#[test]
fn the_recon_budget_refuses_the_frame_and_does_no_work() {
    let config = config();
    let mut session = ready(&config);
    for _ in 0..RECON_FRAMES_PER_MINUTE {
        assert!(matches!(
            session.handle(recon(1), NOW),
            Reaction::Defer(Work::Reconcile { .. })
        ));
    }
    let reaction = session.handle(recon(1), NOW);
    assert_eq!(refusal(&reaction).qualified(), "quota/rate_limited");
    // The whole point: no `Work` leaves the session for the refused frame, so the
    // query, the item scan and the span reopen never run.
    assert!(!matches!(reaction, Reaction::Defer(_)));
    assert_eq!(session.state(), State::Ready);
    assert!(matches!(
        session.handle(recon(1), NOW + FRAME_BUDGET_WINDOW_MS),
        Reaction::Defer(Work::Reconcile { .. })
    ));
}

#[test]
fn the_two_budgets_are_independent_of_each_other() {
    // Separate for the same reason `LIVE` and `KEYS` are separate from each other and
    // from the envelope allowance: no one path may starve another. A client that has
    // spent its reconciliation budget must still be able to subscribe.
    let config = config();
    let mut session = ready(&config);
    for _ in 0..RECON_FRAMES_PER_MINUTE {
        session.handle(recon(1), NOW);
    }
    assert_eq!(
        refusal(&session.handle(recon(1), NOW)).qualified(),
        "quota/rate_limited"
    );
    assert!(matches!(
        session.handle(sub(2), NOW),
        Reaction::Defer(Work::Subscribe { .. })
    ));
}

#[test]
fn a_refused_sub_does_not_record_the_subscription() {
    // The charge is taken before `subscribed` is touched, so a refused frame leaves
    // no session state behind either. Were it the other way around, a flood would
    // still fill the group table it was refused from using.
    let config = config();
    let mut session = ready(&config);
    for _ in 0..SUB_FRAMES_PER_MINUTE {
        session.handle(sub(1), NOW);
    }
    let before = session.subscribed().len();
    let reaction = session.handle(sub(9), NOW);
    assert_eq!(refusal(&reaction).qualified(), "quota/rate_limited");
    assert_eq!(session.subscribed().len(), before);
}
