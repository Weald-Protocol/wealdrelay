// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The socket layer's decisions, without a socket.
//!
//! `tests/ws.rs` is the integration proof: two clients, real WebSockets, a real
//! Postgres. This file is the other half of the same claim, and it exists because
//! several of the answers the relay owes a client are answers it only gives when
//! something has gone wrong. A queue that is full, a connection that has gone, a
//! subscriber too slow to keep up, an envelope that does not decode, a database
//! that is not there: each of those has a defined answer in
//! `specs/backend/relay/operations.md`, and each of them is either impossible or
//! unreliable to arrange through a socket on demand. Arranged directly here, they
//! are checked one at a time.
//!
//! Nothing is faked. The session is a real `Session`, the channel is the real
//! bounded channel a connection gets, and the state is a real `RelayState`. The
//! only thing missing is the WebSocket.

use std::sync::Arc;

use axum::extract::ws::Message;
use wealdrelay::config::{keys, Config, Values};
use wealdrelay::envelope::{content_hash, Encryption, Envelope};
use wealdrelay::frame::{ErrorCode, Frame, FrameError, PROTOCOL_VERSION};
use wealdrelay::health::RelayState;
use wealdrelay::session::{Session, State, Work, SEND_QUEUE_BOUND};
use wealdrelay::ws::{
    downgrade_frame, handle_message, head_seq, key_packages_remaining, outbound_channel, perform,
    try_queue, Outbound, Queued,
};

/// The relay's clock. Fixed, because the harness forbids ambient time inside
/// anything under test: a wall-clock read makes a failure unreproducible.
const NOW: u64 = 1_700_000_000_000;

/// The hub identity a connection carries. Any value: what it is
/// for is telling one connection's subscriptions apart from another's, and these
/// tests drive one connection at a time.
const CONNECTION: wealdrelay::hub::ConnectionId = 7;

/// A group id, at the width the frame decoder enforces.
fn group(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

/// The three required keys and nothing else.
fn config() -> Config {
    Config::resolve(&Values::from_pairs([
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@localhost/weald_relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
    ]))
    .expect("configuration resolves")
}

/// A relay that has no database.
///
/// Not a stub of one: `RelayState::database` is genuinely optional, because
/// `serve::prepare` starts the process so that `/readyz` can report an unreachable
/// dependency rather than the relay failing to boot and reporting nothing. So this
/// is the real production state of a relay whose Postgres has gone, and the tests
/// below are about what a client in flight is told meanwhile.
fn blind() -> Arc<RelayState> {
    Arc::new(RelayState::new(config(), None, None))
}

fn envelope_for(group: &[u8], body: &[u8]) -> Envelope {
    let ct = body.to_vec();
    Envelope {
        v: 1,
        enc: Encryption::None,
        group: group.to_vec(),
        epoch: 0,
        seq: 0,
        ts: 0,
        hash: content_hash(1, Encryption::None, group, 0, &ct),
        ct,
    }
}

/// The next queued frame, or a failure naming what was there instead.
fn queued(receiver: &mut wealdrelay::ws::OutboundReceiver) -> Frame {
    match receiver.try_recv() {
        Ok(Outbound::Frame(frame)) => frame,
        other => panic!("expected a queued frame, got {other:?}"),
    }
}

fn error_code(frame: &Frame) -> ErrorCode {
    match frame {
        Frame::Error(error) => error.code,
        other => panic!("expected an error frame, got {other:?}"),
    }
}

// MARK: The bound

#[test]
fn a_full_queue_is_reported_rather_than_waited_on() {
    // `try_send` and not `send`, and that choice is the whole of the downgrade rule.
    // Awaiting a full queue inside the fanout would make one slow subscriber stall
    // every other subscriber to the same group, so the relay is told the queue is
    // full and downgrades that one subscriber instead of holding up the rest.
    let (sender, _receiver) = outbound_channel();
    for index in 0..SEND_QUEUE_BOUND {
        assert_eq!(
            try_queue(
                &sender,
                Frame::SubAck {
                    group: group(1),
                    head_seq: index as u64,
                }
            ),
            Queued::Sent,
            "the queue refused a frame before the bound was reached"
        );
    }
    assert_eq!(
        try_queue(
            &sender,
            Frame::SubAck {
                group: group(1),
                head_seq: 0,
            }
        ),
        Queued::Full,
        "the bound is not a bound if the frame past it is accepted"
    );
}

#[test]
fn a_connection_that_has_gone_is_reported_as_closed_and_not_as_full() {
    // The two are answered differently upstream: full means downgrade this
    // subscriber and keep serving it by reconciliation, gone means there is nobody
    // to serve. A layer that confused them would either downgrade a subscriber that
    // no longer exists or hold a socket open for a peer that has stopped listening.
    let (sender, receiver) = outbound_channel();
    drop(receiver);
    assert_eq!(
        try_queue(
            &sender,
            Frame::SubAck {
                group: group(1),
                head_seq: 7,
            }
        ),
        Queued::Closed
    );
}

#[test]
fn a_downgraded_subscriber_is_told_so_with_a_head_of_zero() {
    // A frame rather than a log line: the client has to learn that it is now
    // responsible for catching up by reconciliation, and a relay that only logged
    // the downgrade would leave the client believing it was still live. Silence is
    // indistinguishable from a relay that dropped its envelopes.
    //
    // Zero rather than a head, and that is the part worth protecting. The client is
    // being told to reconcile from whatever it holds; naming a head would invite it
    // to trust a cursor that the downgrade means it cannot.
    assert_eq!(
        downgrade_frame(&group(3)),
        Frame::SubAck {
            group: group(3),
            head_seq: 0,
        }
    );
}

#[tokio::test]
async fn a_client_that_has_stopped_reading_ends_the_connection() {
    // A control frame that cannot be queued means the queue is already full of
    // things the client has not taken. Ending the connection is the honest outcome:
    // the alternative is holding a socket open, and a per-connection queue, for a
    // peer that has stopped listening. The client's envelopes are safe either way,
    // because a retry after a dropped connection is answered with the sequence
    // number the original write was given.
    let state = blind();
    let mut session = Session::new(&state.config);
    let (sender, _receiver) = outbound_channel();
    for _ in 0..SEND_QUEUE_BOUND {
        try_queue(
            &sender,
            Frame::SubAck {
                group: group(1),
                head_seq: 0,
            },
        );
    }

    assert!(
        !perform(
            &sender,
            &state,
            &mut session,
            CONNECTION,
            Work::Reconcile {
                group: group(1),
                payload: vec![1, 2, 3],
            },
            NOW,
        )
        .await,
        "the connection must end when its answer cannot be queued"
    );
}

// MARK: What a relay with no database says

#[tokio::test]
async fn an_undecodable_envelope_is_rejected_before_the_relay_looks_for_a_database() {
    // `reject/noncanonical_cbor`, and the order matters: the envelope is refused on
    // its own bytes, so a client that sent something malformed is told that and not
    // told to retry. Asserting it against a relay with no database is what proves
    // the order, because a relay that checked its database first would answer this
    // with `retry/backpressure` and the client would resend the same broken bytes
    // for ever.
    let state = blind();
    let mut session = Session::new(&state.config);
    let (sender, mut receiver) = outbound_channel();

    assert!(
        perform(
            &sender,
            &state,
            &mut session,
            CONNECTION,
            Work::Accept {
                envelope: vec![0xff, 0xff],
            },
            NOW,
        )
        .await,
        "a bad envelope is not a fatal frame: the session survives it"
    );
    let frame = queued(&mut receiver);
    assert_eq!(error_code(&frame), ErrorCode::NoncanonicalCbor);
    assert_eq!(error_code(&frame).qualified(), "reject/noncanonical_cbor");
}

#[tokio::test]
async fn a_relay_that_cannot_look_tells_the_client_to_retry_rather_than_rejecting_it() {
    // `retry/backpressure` for a well formed envelope the relay cannot store. Retry
    // and not reject, because the distinction is the client's whole recovery
    // strategy: the envelope is fine, the relay cannot look at its database, and the
    // client should back off and resend the same bytes verbatim. Rejecting would
    // tell it the envelope was at fault and that resending is pointless, which would
    // turn a dependency outage into lost writes.
    let state = blind();
    let mut session = Session::new(&state.config);
    let (sender, mut receiver) = outbound_channel();

    assert!(
        perform(
            &sender,
            &state,
            &mut session,
            CONNECTION,
            Work::Accept {
                envelope: envelope_for(&group(4), b"perfectly good").encode(),
            },
            NOW,
        )
        .await,
        "an outage does not end the session: the client is meant to retry on it"
    );
    let frame = queued(&mut receiver);
    assert_eq!(error_code(&frame), ErrorCode::Backpressure);
    assert_eq!(error_code(&frame).qualified(), "retry/backpressure");
}

#[tokio::test]
async fn a_relay_that_cannot_look_reports_no_key_packages_and_no_head() {
    // Zero for both, because the honest answer to "how many do you hold" from a
    // relay that cannot look is none. `/readyz` is where the outage is reported;
    // these two decide what a client already in flight is told, and inventing a
    // count or a head would be worse than saying nothing because the client would
    // act on it: a device that was told it still had key packages would not top up.
    let state = blind();
    assert_eq!(key_packages_remaining(&state, &[0x11; 32]).await, 0);
    assert_eq!(head_seq(&state, &group(5)).await, 0);

    // And the same two answers as a client sees them, through the work the session
    // deferred. `AUTH` is the exception and the important one: a relay that cannot
    // read its access set does not admit. Answering `retry` here rather than
    // `AuthAck` is the difference between failing closed and failing open in
    // exactly the incident where the check matters.
    let mut session = Session::new(&state.config);
    let (sender, mut receiver) = outbound_channel();
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]);
    let challenge = vec![0x22; 32];
    let signature = ed25519_dalek::Signer::sign(&key, &challenge)
        .to_bytes()
        .to_vec();
    assert!(
        !perform(
            &sender,
            &state,
            &mut session,
            CONNECTION,
            Work::Authenticate {
                device_key: key.verifying_key().to_bytes().to_vec(),
                signature,
                challenge,
            },
            NOW,
        )
        .await,
        "a relay that cannot look must close the connection rather than admit it"
    );
    assert_eq!(
        queued(&mut receiver),
        Frame::Error(FrameError::new(ErrorCode::Backpressure))
    );

    // A session without an authenticated workspace may not read a group while the
    // relay cannot resolve it. The group check happens before subscription work,
    // so a database outage is `retry/backpressure`, never a guessed head or a
    // cross-workspace read. `head_seq` above separately proves the helper's
    // fail-closed value for a caller that has already authorized its group.
    let mut session = Session::new(&state.config);
    session.authenticated(0);
    assert!(
        perform(
            &sender,
            &state,
            &mut session,
            CONNECTION,
            Work::Subscribe {
                group: group(5),
                from_seq: 9,
            },
            NOW,
        )
        .await
    );
    assert_eq!(
        queued(&mut receiver),
        Frame::Error(FrameError::new(ErrorCode::Backpressure)),
        "a relay that cannot authorize a group must tell the client to retry"
    );
}

// MARK: Messages that are not frames

fn connect_message() -> Message {
    Message::Binary(
        Frame::Connect {
            version: PROTOCOL_VERSION,
            groups: vec![group(1)],
            sent_at: NOW,
        }
        .encode(),
    )
}

#[tokio::test]
async fn a_ping_or_a_pong_is_the_transports_and_leaves_the_session_where_it_was() {
    // Ping and pong belong to the WebSocket layer, and axum answers ping itself. The
    // rule being protected is that neither one is a protocol event: a keepalive must
    // not consume the session's turn, produce a frame, or advance the state machine.
    // A relay that treated a keepalive as an unexpected frame would close every
    // connection that idled long enough for one.
    let state = blind();
    let mut session = Session::new(&state.config);
    let (sender, mut receiver) = outbound_channel();

    for keepalive in [Message::Ping(vec![1, 2, 3]), Message::Pong(Vec::new())] {
        assert!(
            handle_message(&sender, &state, &mut session, CONNECTION, keepalive, NOW).await,
            "a keepalive must not end the connection"
        );
        assert!(
            receiver.try_recv().is_err(),
            "a keepalive must not produce a frame"
        );
        assert_eq!(session.state(), State::Fresh);
    }

    // And the session is still able to start: the `CONNECT` after the keepalives is
    // treated as the first frame, which it is.
    assert!(
        handle_message(
            &sender,
            &state,
            &mut session,
            CONNECTION,
            connect_message(),
            NOW
        )
        .await
    );
    assert!(matches!(queued(&mut receiver), Frame::ConnectAck { .. }));
    assert!(matches!(queued(&mut receiver), Frame::AuthChallenge { .. }));
    assert_eq!(session.state(), State::Challenged);
}

#[tokio::test]
async fn a_close_message_is_answered_with_nothing_at_all() {
    // The one ending that carries no frame, and the exception is the point: a close is
    // the peer saying it has gone, so there is nobody left to tell anything. Every
    // other ending carries a code, because a client that got a dropped connection with
    // no frame cannot tell a protocol error from a network one.
    //
    // The session stops here without the relay closing anything itself. The reader goes
    // back to the stream, which has one thing left to report, and letting the transport
    // finish its own close handshake is what makes the client's close a close rather
    // than a socket that vanished.
    let state = blind();
    let mut session = Session::new(&state.config);
    let (sender, mut receiver) = outbound_channel();

    assert!(
        handle_message(
            &sender,
            &state,
            &mut session,
            CONNECTION,
            Message::Close(None),
            NOW
        )
        .await
    );
    assert!(
        receiver.try_recv().is_err(),
        "there is no peer left to send a frame to"
    );
}

#[tokio::test]
async fn a_reply_that_cannot_be_queued_ends_the_connection() {
    // The same rule as the deferred work above, on the path that answers a frame
    // directly. `CONNECT` is answered with two frames and neither can be queued
    // here, so the client never learns its session started. Continuing would leave a
    // session the relay believed was live and the client believed had never begun.
    let state = blind();
    let mut session = Session::new(&state.config);
    let (sender, _receiver) = outbound_channel();
    for _ in 0..SEND_QUEUE_BOUND {
        try_queue(
            &sender,
            Frame::SubAck {
                group: group(1),
                head_seq: 0,
            },
        );
    }

    assert!(
        !handle_message(
            &sender,
            &state,
            &mut session,
            CONNECTION,
            connect_message(),
            NOW
        )
        .await
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_send_queue_is_bounded_in_bytes_as_well_as_in_frames() {
    // The frame count alone bounded nothing that matters. `SEND_QUEUE_BOUND` frames
    // of the largest envelope the schema allows is about 257 MiB on one connection,
    // and nothing capped how many connections could be doing it at once, so a few
    // backlogged clients were an out-of-memory kill: worse than the failure the bound
    // exists to prevent, because it takes every other connection on the process with
    // it.
    let (sender, mut receiver) = wealdrelay::ws::outbound_channel();

    // Frames at the wire ceiling. Refusal must arrive on the byte budget, long before
    // the frame count.
    let large = wealdrelay::frame::MAX_FRAME_BYTES - 4096;
    let mut accepted = 0usize;
    loop {
        let queued = wealdrelay::ws::try_queue(
            &sender,
            Frame::Push {
                envelope: vec![0u8; large],
            },
        );
        if queued != wealdrelay::ws::Queued::Sent {
            assert_eq!(
                queued,
                wealdrelay::ws::Queued::Full,
                "the client is present"
            );
            break;
        }
        accepted += 1;
        assert!(
            accepted < SEND_QUEUE_BOUND,
            "the byte budget must be reached before the frame count, not after it"
        );
    }

    assert!(
        sender.queued_bytes() <= wealdrelay::ws::SEND_QUEUE_BYTE_BUDGET,
        "the queue holds {} bytes against a budget of {}",
        sender.queued_bytes(),
        wealdrelay::ws::SEND_QUEUE_BYTE_BUDGET
    );
    assert!(
        accepted >= 4,
        "the budget must still admit a useful batch, took only {accepted}"
    );

    // Taking one frame off the queue returns its bytes, so a client that is reading
    // keeps making room. Without this the budget would be a one-way ratchet and a
    // long-lived connection would stop being able to send anything at all.
    let taken = receiver.try_recv().expect("a frame is queued");
    assert!(matches!(taken, wealdrelay::ws::Outbound::Frame(_)));
    assert_eq!(
        wealdrelay::ws::try_queue(
            &sender,
            Frame::Push {
                envelope: vec![0u8; large],
            }
        ),
        wealdrelay::ws::Queued::Sent,
        "room made by the reader is room the next frame can use"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn many_small_frames_still_stop_at_the_frame_count() {
    // The other half of the bound, and the case the frame count was always right
    // about. A byte budget alone would let a client queue tens of thousands of tiny
    // frames, which is its own kind of unbounded.
    let (sender, _receiver) = wealdrelay::ws::outbound_channel();
    for index in 0..SEND_QUEUE_BOUND {
        assert_eq!(
            wealdrelay::ws::try_queue(
                &sender,
                Frame::SubAck {
                    group: vec![0x11; 32],
                    head_seq: index as u64,
                }
            ),
            wealdrelay::ws::Queued::Sent
        );
    }
    assert_eq!(
        wealdrelay::ws::try_queue(
            &sender,
            Frame::SubAck {
                group: vec![0x11; 32],
                head_seq: 0,
            }
        ),
        wealdrelay::ws::Queued::Full,
        "the frame count is still enforced under the byte budget"
    );
    assert!(sender.queued_bytes() < wealdrelay::ws::SEND_QUEUE_BYTE_BUDGET);
}
