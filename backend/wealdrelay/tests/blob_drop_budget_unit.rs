// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The `BLOB` and `DROP` frame budgets, without a socket and without a database.
//!
//! Both arms deferred straight to their work with no budget of any kind. A media
//! request costs an authorization query, a quota row and, for a put, a
//! transaction holding the workspace's single quota row for update (WEALD-L403);
//! a compaction instruction reads the retention chain and checks a manifest
//! naming up to 4096 snapshots before the signature is ever authorized
//! (WEALD-L264). Either was free durable work for one admitted device
//! pipelining at line rate.
//!
//! As with the sibling budgets, the claim worth holding is the negative one: a
//! refused frame must be answered from session state rather than deferred, so it
//! reaches no database at all.

use wealdrelay::config::{keys, Config, Values, WriteMode};
use wealdrelay::frame::{ErrorCode, Frame, PROTOCOL_VERSION};
use wealdrelay::session::{
    Reaction, Session, State, Work, BLOB_FRAMES_PER_MINUTE, DROP_FRAMES_PER_MINUTE,
    FRAME_BUDGET_WINDOW_MS,
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

fn blob() -> Frame {
    Frame::Blob {
        payload: vec![7; 64],
    }
}

fn drop_frame() -> Frame {
    Frame::Drop {
        payload: vec![6; 64],
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
fn the_blob_budget_refuses_the_frame_and_keeps_the_connection() {
    let config = config();
    let mut session = ready(&config);
    for _ in 0..BLOB_FRAMES_PER_MINUTE {
        assert!(matches!(
            session.handle(blob(), NOW),
            Reaction::Defer(Work::BlobTicket { .. })
        ));
    }
    let reaction = session.handle(blob(), NOW);
    assert_eq!(refusal(&reaction).qualified(), "quota/rate_limited");
    assert_eq!(session.state(), State::Ready);
    assert!(matches!(
        session.handle(blob(), NOW + FRAME_BUDGET_WINDOW_MS),
        Reaction::Defer(Work::BlobTicket { .. })
    ));
}

#[test]
fn the_drop_budget_refuses_the_frame_and_keeps_the_connection() {
    let config = config();
    let mut session = ready(&config);
    for _ in 0..DROP_FRAMES_PER_MINUTE {
        assert!(matches!(
            session.handle(drop_frame(), NOW),
            Reaction::Defer(Work::DropBefore { .. })
        ));
    }
    // Refused rather than deferred: the 4097-query manifest check never starts.
    let reaction = session.handle(drop_frame(), NOW);
    assert_eq!(refusal(&reaction).qualified(), "quota/rate_limited");
    assert_eq!(session.state(), State::Ready);
    assert!(matches!(
        session.handle(drop_frame(), NOW + FRAME_BUDGET_WINDOW_MS),
        Reaction::Defer(Work::DropBefore { .. })
    ));
}

#[test]
fn a_read_only_instance_refuses_drop_from_session_state() {
    let mut config = config();
    config.write_mode = WriteMode::ReadOnly;
    let mut session = ready(&config);
    let reaction = session.handle(drop_frame(), NOW);
    assert_eq!(refusal(&reaction), ErrorCode::ServiceReadOnly);
    assert_eq!(session.state(), State::Ready);
}

/// The frame table cannot see inside a `BLOB` payload, so `read_only` is decided
/// by the request kind in `media::handle`, above the pool. This is that split:
/// every request that writes says so, every read says it does not (WEALD-L403).
#[test]
fn only_the_write_shaped_media_requests_are_writes() {
    use wealdrelay::media::wire::Request;
    assert!(Request::Put {
        workspace: vec![1; 16],
        group: vec![2; 32],
        hash: vec![3; 32],
        ciphertext_len: 1024,
    }
    .is_write());
    assert!(Request::MultipartAbort {
        session_id: vec![4; 16]
    }
    .is_write());
    assert!(!Request::Get {
        workspace: vec![1; 16],
        group: vec![2; 32],
        hash: vec![3; 32],
    }
    .is_write());
    assert!(!Request::List {
        workspace: vec![1; 16],
        group: vec![2; 32],
    }
    .is_write());
    assert!(!Request::RetentionPosition { group: vec![2; 32] }.is_write());
    // WEALD-L453: a quota read stays a read — the gate lets it through and
    // `handle_quota` skips its `ensure_quota_row` write when the session
    // refuses writes, so the classification and that skip are a pair.
    assert!(!Request::Quota { group: vec![2; 32] }.is_write());
}
