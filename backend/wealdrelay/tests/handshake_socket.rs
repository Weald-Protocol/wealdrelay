// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `HANDSHAKE` over real sockets: fanout, replay, and what the relay refuses.
//!
//! This is the frame that makes encryption possible at all: without it a member
//! that commits has no way to tell the rest of the group, and a member that joins
//! has no way to catch up. So the claims here are the ones a group's life depends
//! on.
//!
//! - A message published by one connected member reaches the others, live.
//! - A member that was not connected gets every message in order when it
//!   subscribes, from the beginning, because MLS state is built by applying all of
//!   them and not the recent ones.
//! - Handshake messages arrive before the envelopes encrypted under the epochs they
//!   produce, or a client is handed ciphertext it cannot open yet.
//! - A device outside the group cannot publish into it.
//!
//! Two real client processes, one real relay, one real Postgres.

mod support;

use wealdrelay::frame::{ErrorCode, Frame};
use wealdrelay::handshake::MAX_MESSAGE_BYTES;
use wealdrelay::health::Clock;
use wealdrelay::session::SEND_QUEUE_BOUND;
use wealdrelay::ws::{outbound_channel, try_queue};

use support::{config_for, envelope_for, make_group, other_device, Client, Running, Scratch};

const CLOCK: u64 = 1_700_000_000_000;

#[tokio::test(flavor = "multi_thread")]
async fn a_commit_reaches_every_other_member_and_the_publisher_learns_its_place() {
    let scratch = Scratch::new("handshake_fanout").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x21).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    let mut bo = Client::connect(relay.address).await;
    bo.handshake_as(&other_device(), vec![group.clone()], CLOCK)
        .await;

    // Bo subscribes, so it is live for fanout. The subscription acknowledgement
    // comes back first.
    bo.send_frame(&Frame::Sub {
        group: group.clone(),
        from_seq: 0,
    })
    .await;
    assert!(matches!(bo.recv_frame().await, Frame::SubAck { .. }));

    ada.send_frame(&Frame::Handshake {
        group: group.clone(),
        seq: 0,
        message: b"ada's commit".to_vec(),
    })
    .await;
    match ada.recv_frame().await {
        Frame::Handshake { seq, message, .. } => {
            assert_eq!(seq, 0, "the first message in a group is number zero");
            assert_eq!(message, b"ada's commit".to_vec());
        }
        other => panic!("expected the assigned sequence, got {other:?}"),
    }
    match bo.recv_frame().await {
        Frame::Handshake { seq, message, .. } => {
            assert_eq!(seq, 0);
            // The same bytes, not a summary: the relay forwards what it was given
            // and could not paraphrase it if it wanted to.
            assert_eq!(message, b"ada's commit".to_vec());
        }
        other => panic!("expected a fanned-out handshake, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_member_that_was_away_replays_every_message_in_order_before_any_envelope() {
    let scratch = Scratch::new("handshake_replay").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x22).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    for body in [b"create".as_slice(), b"add bo", b"commit"] {
        ada.send_frame(&Frame::Handshake {
            group: group.clone(),
            seq: 0,
            message: body.to_vec(),
        })
        .await;
        assert!(matches!(ada.recv_frame().await, Frame::Handshake { .. }));
    }
    // And one envelope, which is what those commits made readable.
    let envelope = envelope_for(&group, b"content at the latest epoch");
    ada.send_frame(&Frame::Send {
        envelope: envelope.encode(),
    })
    .await;
    assert!(matches!(ada.recv_frame().await, Frame::SendAck { .. }));

    // Bo arrives now, holding nothing.
    let mut bo = Client::connect(relay.address).await;
    bo.handshake_as(&other_device(), vec![group.clone()], CLOCK)
        .await;
    bo.send_frame(&Frame::Sub {
        group: group.clone(),
        from_seq: 0,
    })
    .await;

    assert!(matches!(bo.recv_frame().await, Frame::SubAck { .. }));
    // Every handshake message, from zero, in order. Not "since a cursor": MLS
    // state is built by applying all of them, so a member joining at the latest
    // epoch still needs the commits that produced the earlier ones.
    let mut seen = Vec::new();
    for _ in 0..3 {
        match bo.recv_frame().await {
            Frame::Handshake { seq, message, .. } => seen.push((seq, message)),
            other => panic!("expected a handshake before any envelope, got {other:?}"),
        }
    }
    assert_eq!(
        seen,
        vec![
            (0, b"create".to_vec()),
            (1, b"add bo".to_vec()),
            (2, b"commit".to_vec()),
        ]
    );
    // Only then the envelope. The order is the point: an envelope encrypted under
    // an epoch a client has not reached is ciphertext it would have to buffer.
    match bo.recv_frame().await {
        // Compared by content address rather than byte for byte: a pushed envelope
        // carries the relay-assigned `seq` and `ts`, and neither is covered by the
        // hash, which is exactly why the hash is what a client verifies.
        Frame::Push { envelope: bytes } => {
            let pushed = wealdrelay::envelope::Envelope::decode(&bytes).expect("decodes");
            assert_eq!(pushed.hash, envelope.hash);
            assert_eq!(pushed.ct, envelope.ct);
        }
        other => panic!("expected the envelope after the handshakes, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resend_after_a_dropped_connection_does_not_move_the_order() {
    let scratch = Scratch::new("handshake_socket_resend").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x23).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&Frame::Handshake {
        group: group.clone(),
        seq: 0,
        message: b"a commit".to_vec(),
    })
    .await;
    assert!(matches!(ada.recv_frame().await, Frame::Handshake { .. }));

    // The acknowledgement was lost, so the client sends the identical bytes on a
    // new connection. It must be told the number it already has: a second place in
    // the order would make every member apply the same commit twice.
    let mut again = Client::connect(relay.address).await;
    again.handshake(vec![group.clone()], CLOCK).await;
    again
        .send_frame(&Frame::Handshake {
            group: group.clone(),
            seq: 0,
            message: b"a commit".to_vec(),
        })
        .await;
    match again.recv_frame().await {
        Frame::Handshake { seq, .. } => assert_eq!(seq, 0),
        other => panic!("expected the original sequence, got {other:?}"),
    }

    // And the log holds one message, which is what a joining member will replay.
    let mut bo = Client::connect(relay.address).await;
    bo.handshake_as(&other_device(), vec![group.clone()], CLOCK)
        .await;
    bo.send_frame(&Frame::Sub {
        group: group.clone(),
        from_seq: 0,
    })
    .await;
    assert!(matches!(bo.recv_frame().await, Frame::SubAck { .. }));
    match bo.recv_frame().await {
        Frame::Handshake { seq, .. } => assert_eq!(seq, 0),
        other => panic!("expected one handshake, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn what_the_relay_refuses_and_what_it_does_when_it_cannot_store_one() {
    let scratch = Scratch::new("handshake_refusals").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x24).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;

    ada.send_frame(&Frame::Handshake {
        group: group.clone(),
        seq: 0,
        message: Vec::new(),
    })
    .await;
    match ada.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::MalformedHeader),
        other => panic!("expected malformed_header, got {other:?}"),
    }

    ada.send_frame(&Frame::Handshake {
        group: group.clone(),
        seq: 0,
        message: vec![0u8; MAX_MESSAGE_BYTES + 1],
    })
    .await;
    match ada.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::EnvelopeTooLarge),
        other => panic!("expected envelope_too_large, got {other:?}"),
    }

    // A group this session did not authenticate against. The same refusal a
    // `RECON` for it would get: authenticating for one workspace is not a write
    // path into another.
    ada.send_frame(&Frame::Handshake {
        group: vec![0xEE; 32],
        seq: 0,
        message: b"not mine".to_vec(),
    })
    .await;
    match ada.recv_frame().await {
        Frame::Error(error) => assert!(
            matches!(
                error.code,
                ErrorCode::GroupUnknown | ErrorCode::WriterNotInAccessSet
            ),
            "expected a denial, got {:?}",
            error.code
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }

    // And a relay that cannot write one says come back, with the socket open: a
    // commit is not wrong because the relay is having a bad minute, and the client
    // resends the same bytes, which the content address makes free.
    let pool = relay.state.database.as_ref().expect("a database").pool();
    sqlx::query(
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected'; end $$",
    )
    .execute(pool)
    .await
    .expect("the injected function lands");
    sqlx::query(
        "create trigger weald_injected before insert on relay_handshake \
         for each statement execute function weald_injected_refusal()",
    )
    .execute(pool)
    .await
    .expect("the injected trigger lands");

    ada.send_frame(&Frame::Handshake {
        group: group.clone(),
        seq: 0,
        message: b"a commit nobody can store".to_vec(),
    })
    .await;
    match ada.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::Backpressure);
            assert_eq!(error.code.qualified(), "retry/backpressure");
        }
        other => panic!("expected backpressure, got {other:?}"),
    }

    sqlx::query("drop trigger weald_injected on relay_handshake")
        .execute(pool)
        .await
        .expect("stop refusing");
    ada.send_frame(&Frame::Handshake {
        group: group.clone(),
        seq: 0,
        message: b"a commit nobody can store".to_vec(),
    })
    .await;
    match ada.recv_frame().await {
        Frame::Handshake { seq, .. } => assert_eq!(seq, 0, "the retry is the first message stored"),
        other => panic!("expected the retry to land, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_subscriber_is_told_to_retry_when_the_handshake_log_cannot_be_read() {
    let scratch = Scratch::new("handshake_backfill_fault").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x25).await;
    let pool = relay.state.database.as_ref().expect("a database").pool();

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;

    sqlx::query("alter table relay_handshake rename to parked_away")
        .execute(pool)
        .await
        .expect("park the handshake table");

    ada.send_frame(&Frame::Sub {
        group: group.clone(),
        from_seq: 0,
    })
    .await;
    assert!(matches!(ada.recv_frame().await, Frame::SubAck { .. }));
    match ada.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::Backpressure),
        other => panic!("expected backpressure, got {other:?}"),
    }

    sqlx::query("alter table parked_away rename to relay_handshake")
        .execute(pool)
        .await
        .expect("restore the handshake table");
    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_subscriber_that_cannot_take_its_replay_ends_the_connection() {
    let scratch = Scratch::new("handshake_backfill_full").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x26).await;
    let pool = relay.state.database.as_ref().expect("a database").pool();
    wealdrelay::handshake::store::append(
        pool,
        &wealdrelay::handshake::Handshake {
            group: group.clone(),
            message: b"a commit the subscriber will never read".to_vec(),
        },
    )
    .await
    .expect("seed the handshake log");

    // A queue with exactly one slot left: enough for the acknowledgement, not
    // enough for the replay behind it, and nothing draining it. A client in that
    // state has stopped reading, and the honest outcome is to end the connection
    // rather than hold a socket and a queue open for a peer that is not listening.
    // It cannot be a downgrade: a client told to reconcile can recover envelopes it
    // missed, and there is no reconciliation for MLS state. A member missing one
    // commit cannot decrypt anything published after it, so a silently truncated
    // replay would be worse than a closed socket.
    //
    // The replay waits `ws::REPLAY_DRAIN_TIMEOUT` for room before it gives up, which
    // is what makes a long replay to a healthy client work
    // (`a_group_with_more_commits_than_the_queue_is_still_joinable`). Nothing here
    // ever drains, so the wait is spent and the outcome is the one this test names.
    // That wait is why this test takes ten seconds.
    let (sender, _receiver) = outbound_channel();
    for _ in 0..SEND_QUEUE_BOUND - 1 {
        try_queue(
            &sender,
            Frame::SubAck {
                group: group.clone(),
                head_seq: 0,
            },
        );
    }

    let alive = wealdrelay::sync::subscribe(
        &sender,
        &relay.state,
        relay.state.hub.connect(),
        group.clone(),
        0,
        wealdrelay::frame::PROTOCOL_VERSION,
    )
    .await;
    assert!(
        !alive,
        "a subscriber that could not take its handshake replay must not be left connected"
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_group_with_more_commits_than_the_queue_is_still_joinable() {
    // The case that is not a slow client. `a_subscriber_that_cannot_take_its_replay`
    // above is about a peer that has stopped reading, and ending that connection is
    // right. This is a peer that is reading as fast as it can, refused because the
    // group's own history is longer than one queue.
    //
    // The replay must not be truncated: there is no reconciliation for MLS state and
    // a member missing one commit cannot decrypt anything published after it. So the
    // only correct behaviour is to keep sending until the client has all of it, at
    // whatever rate the client can take it, which means the replay has to wait on the
    // writer rather than fail the moment the queue is full.
    //
    // Sized so the socket buffers cannot hide the problem: enough messages to overrun
    // the queue several times over, each large enough that the kernel cannot absorb
    // the lot while the relay fills the queue. A workspace that has done this much
    // membership churn is a workspace that has been used, not an attack.
    let scratch = Scratch::new("handshake_mature_group").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x2c).await;
    let pool = relay.state.database.as_ref().expect("a database").pool();

    let count = SEND_QUEUE_BOUND * 2;
    for index in 0..count {
        let mut message = vec![0u8; 96 * 1024];
        // Distinct bodies, because the store deduplicates a resend by content
        // address and identical messages would collapse into one row.
        message[..8].copy_from_slice(&(index as u64).to_be_bytes());
        wealdrelay::handshake::store::append(
            pool,
            &wealdrelay::handshake::Handshake {
                group: group.clone(),
                message,
            },
        )
        .await
        .expect("seed one commit");
    }

    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], CLOCK).await;
    client
        .send_frame(&Frame::Sub {
            group: group.clone(),
            from_seq: 0,
        })
        .await;
    assert!(matches!(client.recv_frame().await, Frame::SubAck { .. }));

    // Every commit, in order, from zero. Read with a timeout so a relay that has
    // closed the socket fails as a closed socket rather than by hanging the suite.
    for expected in 0..count {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(20), client.recv())
            .await
            .expect("the replay did not stall")
            .unwrap_or_else(|| {
                panic!("the relay closed after {expected} of {count} commits: a group this size cannot be joined")
            });
        match Frame::decode(&frame).expect("a frame") {
            Frame::Handshake { seq, .. } => assert_eq!(
                seq, expected as u64,
                "commits arrive in order, from the beginning"
            ),
            other => panic!("expected commit {expected}, got {other:?}"),
        }
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}
