// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The subscriber registry: fanout, downgrade, and cleanup.
//!
//! Tier 1. Real channels, real bounds, no socket, because every interesting case
//! here is a case a socket makes hard to arrange on demand: a queue that is exactly
//! full, a receiver that has been dropped, a connection that vanished without
//! unsubscribing.
//!
//! The rule under test throughout is `specs/backend/relay/operations.md`'s: a relay
//! under load slows down or downgrades a subscriber to reconciliation, and never
//! drops an envelope, because a dropped envelope is a hole in an author chain and
//! therefore a security alarm on somebody else's screen.

use wealdrelay::frame::Frame;
use wealdrelay::hub::{Delivery, Hub};
use wealdrelay::session::SEND_QUEUE_BOUND;
use wealdrelay::ws::{outbound_channel, Outbound};

fn group(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

fn envelope(seed: u8) -> Vec<u8> {
    vec![seed; 16]
}

fn pushed(receiver: &mut wealdrelay::ws::OutboundReceiver) -> Vec<u8> {
    match receiver.try_recv().expect("a frame is queued") {
        Outbound::Frame(Frame::Push { envelope }) => envelope,
        other => panic!("expected a push, got {other:?}"),
    }
}

/// The downgrade frame, as the client reads it: a head of zero, which means
/// "reconcile from what you hold rather than trusting a cursor".
fn downgrade(receiver: &mut wealdrelay::ws::OutboundReceiver, expected: &[u8]) {
    match receiver.try_recv().expect("a frame is queued") {
        Outbound::Frame(Frame::SubAck { group, head_seq }) => {
            assert_eq!(group, expected);
            assert_eq!(head_seq, 0);
        }
        other => panic!("expected the downgrade frame, got {other:?}"),
    }
}

#[test]
fn connection_ids_are_unique_per_connection() {
    let hub = Hub::new();
    assert_ne!(hub.connect(), hub.connect());
}

#[tokio::test]
async fn a_subscriber_receives_what_it_asked_for_and_not_what_it_wrote() {
    let hub = Hub::new();
    let (reader_sender, mut reader) = outbound_channel();
    let (writer_sender, mut writer) = outbound_channel();
    let reader_id = hub.connect();
    let writer_id = hub.connect();
    hub.subscribe(&group(1), reader_id, reader_sender).await;
    hub.subscribe(&group(1), writer_id, writer_sender).await;

    let outcomes = hub.fanout(&group(1), &envelope(9), writer_id).await;
    assert_eq!(outcomes, vec![(reader_id, Delivery::Sent)]);
    assert_eq!(pushed(&mut reader), envelope(9));
    // The writer already has it and has been answered with a `SEND_ACK`. Pushing it
    // back would double every local write on the screen of whoever wrote it.
    assert!(writer.try_recv().is_err());
}

#[tokio::test]
async fn a_group_nobody_is_subscribed_to_fans_out_to_nobody() {
    let hub = Hub::new();
    assert!(hub.fanout(&group(2), &envelope(1), 0).await.is_empty());
    assert_eq!(hub.subscribers(&group(2)).await, 0);
}

#[tokio::test]
async fn subscribing_twice_delivers_once() {
    // A client re-subscribes after a downgrade. If the hub kept both entries it
    // would receive every subsequent envelope twice, and a client cannot tell a
    // duplicated push from a relay that has forked its log.
    let hub = Hub::new();
    let (sender, mut receiver) = outbound_channel();
    let id = hub.connect();
    hub.subscribe(&group(1), id, sender.clone()).await;
    hub.subscribe(&group(1), id, sender).await;
    assert_eq!(hub.subscribers(&group(1)).await, 1);

    hub.fanout(&group(1), &envelope(3), u64::MAX).await;
    assert_eq!(pushed(&mut receiver), envelope(3));
    assert!(receiver.try_recv().is_err());
}

#[tokio::test]
async fn two_groups_are_independent() {
    let hub = Hub::new();
    let (first_sender, mut first) = outbound_channel();
    let (second_sender, mut second) = outbound_channel();
    hub.subscribe(&group(1), hub.connect(), first_sender).await;
    hub.subscribe(&group(2), hub.connect(), second_sender).await;

    hub.fanout(&group(1), &envelope(1), u64::MAX).await;
    assert_eq!(pushed(&mut first), envelope(1));
    assert!(second.try_recv().is_err());
}

#[tokio::test]
async fn a_full_queue_downgrades_the_subscriber_and_keeps_every_envelope_it_took() {
    // The bound is real and the answer to hitting it is a downgrade, not a drop.
    let hub = Hub::new();
    let (sender, mut receiver) = outbound_channel();
    let id = hub.connect();
    hub.subscribe(&group(1), id, sender).await;
    for _ in 0..SEND_QUEUE_BOUND {
        hub.fanout(&group(1), &envelope(1), u64::MAX).await;
    }
    assert_eq!(hub.downgrades(), 0);

    assert_eq!(
        hub.fanout(&group(1), &envelope(2), u64::MAX).await,
        vec![(id, Delivery::Downgraded)]
    );
    assert_eq!(hub.downgrades(), 1);

    // Every envelope the queue accepted is still on it. That is the property that
    // matters: the relay slowed down, and nothing was silently discarded.
    let mut seen = 0;
    while receiver.try_recv().is_ok() {
        seen += 1;
    }
    assert_eq!(seen, SEND_QUEUE_BOUND);
    assert_eq!(hub.subscribers(&group(1)).await, 1);
}

#[tokio::test]
async fn a_downgrade_owed_is_delivered_ahead_of_the_next_envelope() {
    // The queue is full exactly when there is no room for the frame that says so, so
    // the downgrade is owed rather than lost, and it goes out ahead of the next
    // envelope the subscriber can take. Without this the client would see a gap in
    // its push stream and nothing telling it to reconcile, which is
    // indistinguishable from a relay that dropped an envelope.
    let hub = Hub::new();
    let (sender, mut receiver) = outbound_channel();
    let id = hub.connect();
    hub.subscribe(&group(1), id, sender).await;
    for _ in 0..SEND_QUEUE_BOUND {
        hub.fanout(&group(1), &envelope(1), u64::MAX).await;
    }
    assert_eq!(
        hub.fanout(&group(1), &envelope(2), u64::MAX).await,
        vec![(id, Delivery::Downgraded)]
    );
    // Still full, and the downgrade is still owed rather than counted twice.
    assert_eq!(
        hub.fanout(&group(1), &envelope(2), u64::MAX).await,
        vec![(id, Delivery::Downgraded)]
    );
    assert_eq!(hub.downgrades(), 1);

    // The client drains. The next fanout tells it to reconcile, then delivers.
    while receiver.try_recv().is_ok() {}
    assert_eq!(
        hub.fanout(&group(1), &envelope(3), u64::MAX).await,
        vec![(id, Delivery::Sent)]
    );
    downgrade(&mut receiver, &group(1));
    assert_eq!(pushed(&mut receiver), envelope(3));

    // And it is live again: the owed frame is not re-sent for ever.
    hub.fanout(&group(1), &envelope(4), u64::MAX).await;
    assert_eq!(pushed(&mut receiver), envelope(4));
}

#[tokio::test]
async fn a_connection_that_has_gone_is_removed_on_the_first_fanout() {
    let hub = Hub::new();
    let (sender, receiver) = outbound_channel();
    let id = hub.connect();
    hub.subscribe(&group(1), id, sender).await;
    drop(receiver);

    assert_eq!(
        hub.fanout(&group(1), &envelope(1), u64::MAX).await,
        vec![(id, Delivery::Gone)]
    );
    // Removed, so the relay does not fan out to a vanished client once per accepted
    // envelope for the life of the process.
    assert_eq!(hub.subscribers(&group(1)).await, 0);
}

#[tokio::test]
async fn a_subscriber_that_vanishes_while_a_downgrade_is_owed_is_removed() {
    let hub = Hub::new();
    let (sender, receiver) = outbound_channel();
    let id = hub.connect();
    hub.subscribe(&group(1), id, sender).await;
    for _ in 0..SEND_QUEUE_BOUND {
        hub.fanout(&group(1), &envelope(1), u64::MAX).await;
    }
    assert_eq!(
        hub.fanout(&group(1), &envelope(2), u64::MAX).await,
        vec![(id, Delivery::Downgraded)]
    );
    drop(receiver);
    assert_eq!(
        hub.fanout(&group(1), &envelope(2), u64::MAX).await,
        vec![(id, Delivery::Gone)]
    );
    assert_eq!(hub.subscribers(&group(1)).await, 0);
}

#[tokio::test]
async fn disconnect_removes_every_subscription_and_the_empty_groups_with_them() {
    let hub = Hub::new();
    let (sender, _receiver) = outbound_channel();
    let (other_sender, _other) = outbound_channel();
    let id = hub.connect();
    let other = hub.connect();
    hub.subscribe(&group(1), id, sender.clone()).await;
    hub.subscribe(&group(2), id, sender).await;
    hub.subscribe(&group(2), other, other_sender).await;

    hub.disconnect(id).await;
    assert_eq!(hub.subscribers(&group(1)).await, 0);
    assert_eq!(hub.subscribers(&group(2)).await, 1);

    // Disconnecting one nobody knows about is not an error: the reader loop
    // disconnects unconditionally, including for a connection that never subscribed.
    hub.disconnect(u64::MAX).await;
    assert_eq!(hub.subscribers(&group(2)).await, 1);
}
