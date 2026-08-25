// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Every deferred work item is held to its declared cost, over the whole frame
//! table, without a socket and without a database.
//!
//! The recurring defect class this file exists to end: a new frame arm defers
//! durable work with no frame budget and no `read_only` refusal, and the hole
//! is found later by somebody attacking the relay. WEALD-L253 (`WRAP`),
//! WEALD-L264 (`DROP`), WEALD-L403 (`BLOB`) and WEALD-L452 (`WAKE`) are four
//! instances of one shape, each fixed on its own. The shape kept recurring
//! because nothing in the tree stated the rule; every proof was per frame.
//!
//! Two halves make the class non-recurring. `Work::policy` in
//! `src/session.rs` is a wildcard-free match, so a new work item does not
//! compile until its author declares what it costs. This file holds the
//! declaration to what the frame table actually does: a declared budget is
//! charged and bites, a declared write is refused from session state while the
//! instance is quiesced, and `label` below is exhaustive too, so a new variant
//! cannot reach the table without a row here naming the frame that produces
//! it.

use wealdrelay::calls::{CallKind, CALL_ID_BYTES, STREAM_BYTES};
use wealdrelay::config::{keys, Config, Values, WriteMode};
use wealdrelay::frame::{ErrorCode, Frame, KeysBody, WakeBody, PROTOCOL_VERSION};
use wealdrelay::session::{
    Durability, Reaction, Session, State, Work, WriteRefusal, FRAME_BUDGET_WINDOW_MS,
};

const NOW: u64 = 1_700_000_000_000;

/// Every work item the frame table can defer, named. Exhaustive and
/// wildcard-free: a new `Work` variant fails to compile here.
fn label(work: &Work) -> &'static str {
    match work {
        Work::Authenticate { .. } => "Authenticate",
        Work::Accept { .. } => "Accept",
        Work::Subscribe { .. } => "Subscribe",
        Work::Reconcile { .. } => "Reconcile",
        Work::RotateAccessSet { .. } => "RotateAccessSet",
        Work::BlobTicket { .. } => "BlobTicket",
        Work::DropBefore { .. } => "DropBefore",
        Work::PublishWrap { .. } => "PublishWrap",
        Work::Redeem { .. } => "Redeem",
        Work::AdministerInvite { .. } => "AdministerInvite",
        Work::PublishHandshake { .. } => "PublishHandshake",
        Work::PublishLive { .. } => "PublishLive",
        Work::KeyPackages {
            body: KeysBody::Publish { .. },
        } => "KeyPackages/publish",
        Work::KeyPackages { .. } => "KeyPackages/fetch",
        Work::WakeRegistration {
            body: WakeBody::Register { .. },
        } => "WakeRegistration/register",
        Work::WakeRegistration {
            body: WakeBody::Clear,
        } => "WakeRegistration/clear",
        Work::WakeRegistration { .. } => "WakeRegistration/query",
        Work::PublishCall { .. } => "PublishCall",
        Work::PublishMedia { .. } => "PublishMedia",
    }
}

/// Every label the table above can produce. Held equal to what the rows below
/// actually exercise, so a new work item cannot be added without a row that
/// drives it through `Session::handle`.
const EVERY_WORK_ITEM: &[&str] = &[
    "Authenticate",
    "Accept",
    "Subscribe",
    "Reconcile",
    "RotateAccessSet",
    "BlobTicket",
    "DropBefore",
    "PublishWrap",
    "Redeem",
    "AdministerInvite",
    "PublishHandshake",
    "PublishLive",
    "KeyPackages/publish",
    "KeyPackages/fetch",
    "WakeRegistration/register",
    "WakeRegistration/clear",
    "WakeRegistration/query",
    "PublishCall",
    "PublishMedia",
];

fn config() -> Config {
    Config::resolve(&Values::from_pairs(vec![
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@localhost/weald_relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
        (keys::LIVE, "on"),
        (keys::CALLS, "on"),
        (keys::MAX_CONCURRENT_CALLS, "16"),
    ]))
    .expect("configuration resolves")
}

/// A fresh session in the state the row's frame is sent from. `Authenticate` is
/// the one row sent from `Challenged`, and `Redeem` is the one row sent before
/// any authentication at all; everything else is `Ready`.
fn session_for(config: &Config, label: &str) -> Session {
    let mut session = Session::new(config);
    session.handle(
        Frame::Connect {
            version: PROTOCOL_VERSION,
            groups: vec![vec![1; 32]],
            sent_at: NOW,
        },
        NOW,
    );
    match label {
        "Authenticate" | "Redeem" => assert_eq!(session.state(), State::Challenged),
        _ => {
            session.authenticated(0);
            assert_eq!(session.state(), State::Ready);
        }
    }
    session
}

/// One frame per work item, in the same order as ``EVERY_WORK_ITEM``.
fn frames() -> Vec<Frame> {
    vec![
        Frame::Auth {
            device_key: vec![9; 32],
            signature: vec![8; 64],
        },
        Frame::Send {
            envelope: vec![1; 64],
        },
        Frame::Sub {
            group: vec![1; 32],
            from_seq: 0,
        },
        Frame::Recon {
            group: vec![1; 32],
            payload: vec![2; 32],
        },
        Frame::Access { body: vec![3; 64] },
        Frame::Blob {
            payload: vec![4; 64],
        },
        Frame::Drop {
            payload: vec![5; 64],
        },
        Frame::Wrap { body: vec![6; 64] },
        Frame::Join { body: vec![7; 64] },
        Frame::Invite { body: vec![8; 64] },
        Frame::Handshake {
            group: vec![1; 32],
            seq: 0,
            message: vec![9; 64],
        },
        Frame::Live {
            group: vec![1; 32],
            epoch: 1,
            ct: vec![1; 32],
        },
        Frame::Keys(KeysBody::Publish {
            packages: vec![vec![1; 32]],
        }),
        Frame::Keys(KeysBody::Fetch {
            device: vec![2; 32],
            count: 1,
        }),
        Frame::Wake(WakeBody::Register {
            handle: vec![3; 16],
            categories: 1,
            expires_at: NOW + 86_400_000,
        }),
        Frame::Wake(WakeBody::Clear),
        Frame::Wake(WakeBody::Query),
        Frame::Call {
            call_id: vec![4; CALL_ID_BYTES],
            group: vec![1; 32],
            epoch: 1,
            kind: CallKind::Offer as u8,
            body: vec![5; 32],
        },
        Frame::Media {
            call_id: vec![4; CALL_ID_BYTES],
            stream: vec![6; STREAM_BYTES],
            seq: 1,
            ct: vec![7; 32],
        },
    ]
}

fn deferred(reaction: Reaction) -> Work {
    match reaction {
        Reaction::Defer(work) => work,
        other => panic!("expected a deferral, got {other:?}"),
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

/// Every frame in ``frames`` is accepted and produces the work item its row
/// names, and between them the rows cover every work item `label` can name.
/// Without this the two tests below could pass while silently skipping a
/// variant nobody wrote a row for.
#[test]
fn every_work_item_the_frame_table_can_defer_has_a_row() {
    let config = config();
    let observed: Vec<&'static str> = frames()
        .into_iter()
        .zip(EVERY_WORK_ITEM)
        .map(|(frame, expected)| {
            let mut session = session_for(&config, expected);
            label(&deferred(session.handle(frame, NOW)))
        })
        .collect();
    assert_eq!(observed, EVERY_WORK_ITEM);
}

/// A declared frames-per-minute ceiling is charged by the frame table, bites at
/// the declared count, refuses the frame rather than the connection, and starts
/// a fresh window. This is the claim WEALD-L253, L264, L403 and L452 each had
/// to prove one frame at a time.
#[test]
fn every_declared_budget_is_charged_and_bites_at_its_declared_ceiling() {
    let config = config();
    let mut checked = 0;
    for (frame, name) in frames().into_iter().zip(EVERY_WORK_ITEM) {
        let mut session = session_for(&config, name);
        let policy = deferred(session.handle(frame.clone(), NOW)).policy();
        let Some(allowance) = policy.frames_per_minute else {
            continue;
        };
        checked += 1;
        // One frame is already spent above, so the ceiling is reached after
        // `allowance - 1` more and the next one is refused.
        for _ in 1..allowance {
            assert!(
                matches!(session.handle(frame.clone(), NOW), Reaction::Defer(_)),
                "{name} refused inside its own allowance"
            );
        }
        let reaction = session.handle(frame.clone(), NOW);
        assert_eq!(
            refusal(&reaction).qualified(),
            "quota/rate_limited",
            "{name} is not rate limited at its declared ceiling"
        );
        assert_ne!(
            session.state(),
            State::Closed,
            "{name} closed the connection over a rate limit"
        );
        assert!(
            matches!(
                session.handle(frame, NOW + FRAME_BUDGET_WINDOW_MS),
                Reaction::Defer(_)
            ),
            "{name} did not start a fresh window"
        );
    }
    // Sixteen of the nineteen items carry a frames-per-minute ceiling; the
    // other three are `Authenticate` (one per connection, bounded by the
    // handshake deadline), `Accept` (per-device `send_budget`) and
    // `PublishMedia` (per-stream `MediaBudget`).
    assert_eq!(checked, 16);
}

/// A declared durable write whose refusal belongs to the frame table is
/// answered from session state while the instance is quiesced: no deferral, no
/// pool, no budget spent. The two declared exceptions are named rather than
/// skipped.
#[test]
fn every_declared_write_is_refused_from_session_state_while_quiesced() {
    let mut config = config();
    config.write_mode = WriteMode::ReadOnly;
    let full = self::config();
    let mut writes = 0;
    for (frame, name) in frames().into_iter().zip(EVERY_WORK_ITEM) {
        // The policy is read from a session that is taking writes, because a
        // quiesced one may never produce the work item at all: that refusal is
        // exactly what is under test.
        let policy = deferred(session_for(&full, name).handle(frame.clone(), NOW)).policy();
        if policy.durability != Durability::Write {
            assert_eq!(
                policy.write_refusal,
                WriteRefusal::NotAWrite,
                "{name} owes no refusal but declares one"
            );
            continue;
        }
        writes += 1;
        let mut session = session_for(&config, name);
        let reaction = session.handle(frame, NOW);
        match policy.write_refusal {
            WriteRefusal::FrameTable => {
                assert_eq!(
                    refusal(&reaction),
                    ErrorCode::ServiceReadOnly,
                    "{name} is a durable write that reaches the pool while quiesced"
                );
                assert_eq!(
                    session.state(),
                    State::Ready,
                    "{name} closed the connection"
                );
            }
            // `BLOB`: the payload is opaque here, so `media::handle` answers
            // it above the pool. Pinned by
            // `blob_drop_budget_unit::only_the_write_shaped_media_requests_are_writes`.
            WriteRefusal::Handler => {
                assert_eq!(name, &"BlobTicket");
                assert!(matches!(reaction, Reaction::Defer(Work::BlobTicket { .. })));
            }
            // `JOIN`: a redemption is how a device becomes able to speak, and
            // quiescing an instance must not lock a workspace's new devices out
            // of it.
            WriteRefusal::ServedWhileQuiesced => {
                assert_eq!(name, &"Redeem");
                assert!(matches!(reaction, Reaction::Defer(Work::Redeem { .. })));
            }
            WriteRefusal::NotAWrite => panic!("{name} is a write declaring no refusal"),
        }
    }
    // Eleven of the nineteen items write durably.
    assert_eq!(writes, 11);
}
