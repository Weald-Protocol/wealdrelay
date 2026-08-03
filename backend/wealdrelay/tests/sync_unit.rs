// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! What `SUB` and `RECON` answer when the relay cannot look, without a socket.
//!
//! Tier 1, and the same argument `tests/ws_unit.rs` makes: `RelayState::database` is
//! genuinely optional, because `serve::prepare` starts the process so that `/readyz`
//! can report an unreachable dependency rather than the relay failing to boot and
//! reporting nothing. So this is the real production state of a relay whose Postgres
//! has gone, and what a client in flight is told meanwhile is a decision rather than
//! plumbing.

use std::sync::Arc;

use wealdrelay::config::{keys, Config, Values};
use wealdrelay::frame::{ErrorCode, Frame};
use wealdrelay::health::RelayState;
use wealdrelay::negentropy::{initiate, Message};
use wealdrelay::sync;
use wealdrelay::ws::{outbound_channel, Outbound};

const CONNECTION: wealdrelay::hub::ConnectionId = 3;

fn group(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

fn blind() -> Arc<RelayState> {
    let config = Config::resolve(&Values::from_pairs([
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@localhost/weald_relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
    ]))
    .expect("configuration resolves");
    Arc::new(RelayState::new(config, None, None))
}

fn frame(receiver: &mut wealdrelay::ws::OutboundReceiver) -> Frame {
    match receiver.try_recv().expect("a frame is queued") {
        Outbound::Frame(frame) => frame,
        other => panic!("expected a frame, got {other:?}"),
    }
}

fn error_code(frame: &Frame) -> ErrorCode {
    match frame {
        Frame::Error(error) => error.code,
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_relay_that_cannot_look_tells_a_reconciling_client_to_retry() {
    // `retry/backpressure`, not `reject`: the payload was fine and the client's
    // correct response is to back off and send the same bytes again.
    let state = blind();
    let (sender, mut receiver) = outbound_channel();
    assert!(
        sync::reconcile(&sender, &state, group(1), initiate(&[]).encode()).await,
        "an outage is not a reason to close the socket"
    );
    let queued = frame(&mut receiver);
    assert_eq!(error_code(&queued), ErrorCode::Backpressure);
    assert!(error_code(&queued).class().is_retryable());
}

#[tokio::test]
async fn a_malformed_payload_is_refused_before_the_relay_looks_for_a_database() {
    // The order matters for the same reason it does on the accept path: a client that
    // sent something malformed must be told that, and not told to retry, or it will
    // resend the same broken bytes for ever. Asserting it against a relay with no
    // database is what proves the order.
    let state = blind();
    let (sender, mut receiver) = outbound_channel();
    assert!(sync::reconcile(&sender, &state, group(1), vec![0xff]).await);
    assert_eq!(
        error_code(&frame(&mut receiver)),
        ErrorCode::NoncanonicalCbor
    );
}

#[tokio::test]
async fn a_subscription_against_a_blind_relay_is_registered_and_acknowledged() {
    // The subscription is real even though the backfill cannot be: the client is in
    // the hub, so it receives anything accepted once the database returns, and the
    // honest backfill from a relay that cannot read its log is none. `/readyz`
    // reports the outage; this is what the client in flight is told.
    let state = blind();
    let (sender, mut receiver) = outbound_channel();
    assert!(sync::subscribe(&sender, &state, CONNECTION, group(2), 0).await);
    match frame(&mut receiver) {
        Frame::SubAck { group: g, head_seq } => {
            assert_eq!(g, group(2));
            assert_eq!(head_seq, 0);
        }
        other => panic!("expected a SubAck, got {other:?}"),
    }
    assert!(receiver.try_recv().is_err(), "no backfill without a log");
    assert_eq!(state.hub.subscribers(&group(2)).await, 1);
}

#[tokio::test]
async fn a_cursor_beyond_the_head_is_answered_with_the_clients_own_number() {
    // Unchanged from step 4: a client that names a cursor past the head is not
    // invited to walk backwards.
    let state = blind();
    let (sender, mut receiver) = outbound_channel();
    assert!(sync::subscribe(&sender, &state, CONNECTION, group(2), 99).await);
    match frame(&mut receiver) {
        Frame::SubAck { head_seq, .. } => assert_eq!(head_seq, 99),
        other => panic!("expected a SubAck, got {other:?}"),
    }
}

#[tokio::test]
async fn a_subscription_whose_acknowledgement_cannot_be_queued_ends_the_connection() {
    let state = blind();
    let (sender, receiver) = outbound_channel();
    for _ in 0..wealdrelay::session::SEND_QUEUE_BOUND {
        let _ = wealdrelay::ws::try_queue(&sender, Frame::Bye { reason: Vec::new() });
    }
    assert!(
        !sync::subscribe(&sender, &state, CONNECTION, group(2), 0).await,
        "a client that is not reading its acknowledgement is not being served"
    );
    drop(receiver);
}

#[tokio::test]
async fn an_answer_that_cannot_be_queued_ends_the_connection() {
    let state = blind();
    let (sender, receiver) = outbound_channel();
    for _ in 0..wealdrelay::session::SEND_QUEUE_BOUND {
        let _ = wealdrelay::ws::try_queue(&sender, Frame::Bye { reason: Vec::new() });
    }
    assert!(!sync::reconcile(&sender, &state, group(1), vec![0xff]).await);
    drop(receiver);
}

#[tokio::test]
async fn a_settled_message_is_what_a_converged_client_sends() {
    // The shape of the last frame in an exchange, asserted here so the constant has
    // a test rather than only a comment: a settled cover decodes, and it is
    // recognised as settled by the side that receives it.
    let encoded = Message::settled().encode();
    let decoded = Message::decode(&encoded).expect("a settled cover decodes");
    assert!(decoded.is_settled());
    assert_eq!(decoded.spans().len(), 1);
    assert_eq!(decoded.spans()[0].0, 0);
    assert_eq!(decoded.spans()[0].1, u64::MAX);
}
