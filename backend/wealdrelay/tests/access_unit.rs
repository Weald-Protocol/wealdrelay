// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The access-set paths that need neither a socket nor a database.
//!
//! Two things live here. What a relay whose Postgres has gone tells a client that
//! publishes an access set, which is a decision and not plumbing: the honest answer
//! is `retry` and an open socket, because a publication that could not be stored may
//! well be storable in a minute. And the hub's principal index, which is what makes
//! eviction on revocation possible: a connection is filed under the salted hash the
//! access check computed, and filing it twice would leave a stale sender behind after
//! the first close.
//!
//! `tests/ws_unit.rs` already holds the equivalent tests for `SEND` and `SUB` against
//! a relay with no database. This is a separate file rather than more of that one
//! because that file is already long, and a suite nobody can read is a suite nobody
//! maintains.

use std::sync::Arc;

use wealdrelay::config::{keys, Config, Values};
use wealdrelay::frame::{ErrorCode, Frame};
use wealdrelay::health::RelayState;
use wealdrelay::hub::Hub;
use wealdrelay::session::{Session, Work};
use wealdrelay::ws::{outbound_channel, Outbound};

fn config() -> Config {
    Config::resolve(&Values::from_pairs([
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@localhost/weald_relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
    ]))
    .expect("configuration resolves")
}

/// A relay whose Postgres is not there. Not a stub of one: `RelayState::database` is
/// genuinely optional, because `serve::prepare` starts the process so `/readyz` can
/// report an unreachable dependency rather than the relay failing to boot and
/// reporting nothing.
fn blind() -> Arc<RelayState> {
    Arc::new(RelayState::new(config(), None, None))
}

/// A connection id. Any value: what it is for is telling one connection's
/// subscriptions apart from another's.
fn hub_id() -> u64 {
    7
}

fn queued(receiver: &mut wealdrelay::ws::OutboundReceiver) -> Frame {
    match receiver.try_recv() {
        Ok(Outbound::Frame(frame)) => frame,
        other => panic!("expected a queued frame, got {other:?}"),
    }
}

#[tokio::test]
async fn a_publication_to_a_relay_with_no_database_is_told_to_retry() {
    // Answered before the set is judged, because judging it would be work whose
    // result could not be stored. `retry/backpressure` and the session stays open:
    // the client's correct response is backoff and a verbatim resend.
    let state = blind();
    let (sender, mut receiver) = outbound_channel();
    let mut session = Session::new(&state.config);
    let alive = wealdrelay::ws::perform(
        &sender,
        &state,
        &mut session,
        hub_id(),
        // A body that would decode, so the refusal is about the database and not
        // about the bytes.
        Work::RotateAccessSet {
            body: valid_enough_body(),
        },
        1,
    )
    .await;
    assert!(alive, "a relay that cannot store must not close the socket");
    let frame = queued(&mut receiver);
    match frame {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::Backpressure);
            assert!(error.code.class().is_retryable());
        }
        other => panic!("expected retry/backpressure, got {other:?}"),
    }
}

#[tokio::test]
async fn a_state_query_to_a_relay_with_no_database_is_told_to_retry() {
    // The same answer as a publication, for a stronger reason: the salt is the one
    // value a client cannot guess and cannot check, so a relay that invented one would
    // have every entry hash built against it be permanently unverifiable. Saying
    // "come back" is the only honest answer a relay that cannot look can give.
    let state = blind();
    let (sender, mut receiver) = outbound_channel();
    let mut session = Session::new(&state.config);
    let alive = wealdrelay::ws::perform(
        &sender,
        &state,
        &mut session,
        hub_id(),
        // Empty: the query rather than a publication.
        Work::RotateAccessSet { body: Vec::new() },
        1,
    )
    .await;
    assert!(alive, "a relay that cannot look must not close the socket");
    match queued(&mut receiver) {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::Backpressure);
            assert!(error.code.class().is_retryable());
        }
        other => panic!("expected retry/backpressure, got {other:?}"),
    }
}

/// A set that decodes. Its contents do not matter: nothing gets as far as judging it.
fn valid_enough_body() -> Vec<u8> {
    use wealdrelay::access::AccessSet;
    AccessSet {
        workspace: vec![0x77; 32],
        version: 0,
        prev_hash: vec![0u8; 32],
        issued_at: 1,
        entries: vec![vec![0x01; 32]],
        authorizers: vec![vec![0x02; 32]],
        recovery: vec![vec![0x03; 32]],
        quorum: None,
        pending: Vec::new(),
        signer: vec![0x02; 32],
        sig: vec![0u8; 64],
    }
    .encode()
}

#[tokio::test]
async fn a_principal_is_filed_once_per_connection_and_evicting_it_closes_every_socket() {
    // The index eviction reads. Filing one connection twice would leave a stale
    // sender behind after the first close, and a revocation that closed a socket
    // nobody was on would look like it had worked.
    let hub = Hub::new();
    let entry = vec![0x5a; 32];
    let first = hub.connect();
    let (sender, mut receiver) = outbound_channel();

    hub.identify(&entry, first, sender.clone()).await;
    assert_eq!(hub.connections_for(&entry).await, 1);
    // The same connection again, which is what a second `AUTH` would do if the frame
    // table ever stopped refusing one.
    hub.identify(&entry, first, sender.clone()).await;
    assert_eq!(hub.connections_for(&entry).await, 1, "filed twice");

    // A second connection by the same principal, which is ordinary: one person with
    // a laptop and a phone.
    let second = hub.connect();
    let (other_sender, mut other_receiver) = outbound_channel();
    hub.identify(&entry, second, other_sender).await;
    assert_eq!(hub.connections_for(&entry).await, 2);

    // Eviction closes both and reports how many, which is what the recorded
    // revocation-to-disconnect timing is measured against.
    assert_eq!(hub.evict(&entry).await, 2);
    assert!(matches!(receiver.try_recv(), Ok(Outbound::Close)));
    assert!(matches!(other_receiver.try_recv(), Ok(Outbound::Close)));
    assert_eq!(hub.connections_for(&entry).await, 0);

    // Evicting a principal that holds nothing is zero and not an error: the outcome
    // the caller asked for is that it is not connected.
    assert_eq!(hub.evict(&entry).await, 0);
    assert_eq!(hub.connections_for(&[0x5b; 32]).await, 0);
}
