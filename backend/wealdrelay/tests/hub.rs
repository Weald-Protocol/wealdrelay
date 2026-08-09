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

mod support;

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
    hub.subscribe(
        &group(1),
        reader_id,
        reader_sender,
        wealdrelay::frame::PROTOCOL_VERSION,
    )
    .await;
    hub.subscribe(
        &group(1),
        writer_id,
        writer_sender,
        wealdrelay::frame::PROTOCOL_VERSION,
    )
    .await;

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
    hub.subscribe(
        &group(1),
        id,
        sender.clone(),
        wealdrelay::frame::PROTOCOL_VERSION,
    )
    .await;
    hub.subscribe(&group(1), id, sender, wealdrelay::frame::PROTOCOL_VERSION)
        .await;
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
    hub.subscribe(
        &group(1),
        hub.connect(),
        first_sender,
        wealdrelay::frame::PROTOCOL_VERSION,
    )
    .await;
    hub.subscribe(
        &group(2),
        hub.connect(),
        second_sender,
        wealdrelay::frame::PROTOCOL_VERSION,
    )
    .await;

    hub.fanout(&group(1), &envelope(1), u64::MAX).await;
    assert_eq!(pushed(&mut first), envelope(1));
    assert!(second.try_recv().is_err());
}

#[tokio::test]
async fn two_members_receive_each_ordered_push_once_while_the_writer_and_other_group_do_not() {
    // Multiplayer fanout invariant: every subscribed connection in the written
    // group sees the same durable sequence, once. A writer has its SEND_ACK
    // instead, and a subscription in another group is not a wildcard. This is the
    // in-process companion to the real-WebSocket proof in `live_socket.rs`.
    let hub = Hub::new();
    let (first_sender, mut first) = outbound_channel();
    let (second_sender, mut second) = outbound_channel();
    let (writer_sender, mut writer) = outbound_channel();
    let (other_sender, mut other) = outbound_channel();
    let first_id = hub.connect();
    let second_id = hub.connect();
    let writer_id = hub.connect();
    let other_id = hub.connect();

    for (id, sender) in [
        (first_id, first_sender),
        (second_id, second_sender),
        (writer_id, writer_sender),
    ] {
        hub.subscribe(&group(1), id, sender, wealdrelay::frame::PROTOCOL_VERSION)
            .await;
    }
    hub.subscribe(
        &group(2),
        other_id,
        other_sender,
        wealdrelay::frame::PROTOCOL_VERSION,
    )
    .await;

    for body in [envelope(7), envelope(8)] {
        assert_eq!(
            hub.fanout(&group(1), &body, writer_id).await,
            vec![(first_id, Delivery::Sent), (second_id, Delivery::Sent)]
        );
    }

    assert_eq!(pushed(&mut first), envelope(7));
    assert_eq!(pushed(&mut first), envelope(8));
    assert_eq!(pushed(&mut second), envelope(7));
    assert_eq!(pushed(&mut second), envelope(8));
    assert!(writer.try_recv().is_err());
    assert!(other.try_recv().is_err());
}

#[tokio::test]
async fn a_full_queue_downgrades_the_subscriber_and_keeps_every_envelope_it_took() {
    // The bound is real and the answer to hitting it is a downgrade, not a drop.
    let hub = Hub::new();
    let (sender, mut receiver) = outbound_channel();
    let id = hub.connect();
    hub.subscribe(&group(1), id, sender, wealdrelay::frame::PROTOCOL_VERSION)
        .await;
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
    hub.subscribe(&group(1), id, sender, wealdrelay::frame::PROTOCOL_VERSION)
        .await;
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
    hub.subscribe(&group(1), id, sender, wealdrelay::frame::PROTOCOL_VERSION)
        .await;
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
    hub.subscribe(&group(1), id, sender, wealdrelay::frame::PROTOCOL_VERSION)
        .await;
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
    hub.subscribe(
        &group(1),
        id,
        sender.clone(),
        wealdrelay::frame::PROTOCOL_VERSION,
    )
    .await;
    hub.subscribe(&group(2), id, sender, wealdrelay::frame::PROTOCOL_VERSION)
        .await;
    hub.subscribe(
        &group(2),
        other,
        other_sender,
        wealdrelay::frame::PROTOCOL_VERSION,
    )
    .await;

    hub.disconnect(id).await;
    assert_eq!(hub.subscribers(&group(1)).await, 0);
    assert_eq!(hub.subscribers(&group(2)).await, 1);

    // Disconnecting one nobody knows about is not an error: the reader loop
    // disconnects unconditionally, including for a connection that never subscribed.
    hub.disconnect(u64::MAX).await;
    assert_eq!(hub.subscribers(&group(2)).await, 1);
}

// MARK: The ephemeral path

fn beat(group: &[u8]) -> Frame {
    Frame::Live {
        group: group.to_vec(),
        epoch: 3,
        ct: vec![7; 32],
    }
}

#[tokio::test]
async fn a_beat_reaches_a_version_two_subscriber_and_never_a_version_one_subscriber() {
    // The compatibility claim, on the relay's side. A version 1 client is not
    // "sent a frame it ignores": it is never sent one at all, because a frame tag
    // it does not know is a decode failure and a closed socket at its end.
    let hub = Hub::new();
    let (new_sender, mut new_client) = outbound_channel();
    let (old_sender, mut old_client) = outbound_channel();
    let (writer_sender, _writer) = outbound_channel();
    let new_id = hub.connect();
    let old_id = hub.connect();
    let writer_id = hub.connect();
    hub.subscribe(&group(1), new_id, new_sender, 2).await;
    hub.subscribe(&group(1), old_id, old_sender, 1).await;
    hub.subscribe(&group(1), writer_id, writer_sender, 2).await;

    let outcomes = hub
        .fanout_frame(&group(1), &beat(&group(1)), writer_id, 2)
        .await;
    assert!(outcomes.contains(&(new_id, Delivery::Sent)));
    assert!(outcomes.contains(&(old_id, Delivery::NotSpoken)));
    assert!(matches!(
        new_client.try_recv().expect("a frame is queued"),
        Outbound::Frame(Frame::Live { .. })
    ));
    assert!(
        old_client.try_recv().is_err(),
        "a v1 client was sent a v2 frame"
    );
}

#[tokio::test]
async fn a_durable_fanout_still_reaches_a_version_one_subscriber() {
    // The other half, and the one that would be quietly broken by a filter applied
    // everywhere: `HANDSHAKE` and `PUSH` keep reaching everybody.
    let hub = Hub::new();
    let (old_sender, mut old_client) = outbound_channel();
    let writer_id = hub.connect();
    let old_id = hub.connect();
    hub.subscribe(&group(1), old_id, old_sender, 1).await;

    let outcomes = hub.fanout(&group(1), &envelope(4), writer_id).await;
    assert_eq!(outcomes, vec![(old_id, Delivery::Sent)]);
    assert_eq!(pushed(&mut old_client), envelope(4));
}

#[tokio::test]
async fn a_full_queue_sheds_a_beat_silently_and_never_downgrades() {
    // A downgrade is a claim about durable state: it tells a client it has a hole
    // in an author chain and must reconcile. A shed beat is nothing of the kind and
    // the next one is 20 seconds away, so telling a client to reconcile because a
    // presence dot was late would be a lie about its log.
    let hub = Hub::new();
    let (sender, mut receiver) = outbound_channel();
    let id = hub.connect();
    let writer_id = hub.connect();
    hub.subscribe(&group(1), id, sender, 2).await;

    for seed in 0..SEND_QUEUE_BOUND {
        let outcomes = hub
            .fanout(&group(1), &envelope(seed as u8), writer_id)
            .await;
        assert_eq!(outcomes, vec![(id, Delivery::Sent)]);
    }

    let before = hub.downgrades();
    let outcomes = hub
        .fanout_frame(&group(1), &beat(&group(1)), writer_id, 2)
        .await;
    assert_eq!(outcomes, vec![(id, Delivery::Shed)]);
    assert_eq!(hub.shed(), 1);
    assert_eq!(
        hub.downgrades(),
        before,
        "a shed beat moved the downgrade counter"
    );

    // And every durable envelope the subscriber accepted is still there, in order.
    for seed in 0..SEND_QUEUE_BOUND {
        assert_eq!(pushed(&mut receiver), envelope(seed as u8));
    }
    assert!(
        receiver.try_recv().is_err(),
        "a beat took a durable queue slot"
    );

    // The saturation half of step 30's artifact: the shed count, from the run that
    // produced it.
    support::record_evidence(
        "step-30",
        "saturation.txt",
        &format!(
            "# Shedding under saturation\n\nspecs/backend/relay/presence.md. A subscriber's queue is filled to its bound\n({SEND_QUEUE_BOUND} durable frames), then one LIVE frame is fanned out to it.\n\nshed              {}\ndowngrades        {}\ndurable delivered {SEND_QUEUE_BOUND}\n\nA shed beat does not set downgrade_owed and does not move the downgrade counter.\nA downgrade is a claim about durable state: it tells a client it has a hole in an\nauthor chain and must reconcile. A beat is not durable and the next one is 20\nseconds away, so shedding is silent to the client and visible only to the\noperator, here.\n\nOrdering: a downgrade already owed from an earlier round is discharged ahead of\nthe shed, at the first opportunity of any kind. That is durable state the\nsubscriber is already entitled to, and a notice that waited for the next durable\nframe was never delivered at all when none followed. The beat itself is still\nnever queued, which is the invariant the ordering protects.\n",
            hub.shed(),
            hub.downgrades()
        ),
    );
}

#[tokio::test]
async fn a_beat_discharges_an_owed_downgrade_before_it_is_shed() {
    // The debt goes out ahead of the beat, and the beat is still shed rather than
    // queued. Both halves matter: an owed downgrade is durable state the subscriber
    // is already entitled to, so it takes the first slot of any kind that appears
    // (`specs/backend/relay/presence.md`), while the ephemeral frame that created
    // the opportunity never spends a slot of its own.
    let hub = Hub::new();
    let (sender, mut receiver) = outbound_channel();
    let id = hub.connect();
    let writer_id = hub.connect();
    hub.subscribe(&group(1), id, sender, 2).await;
    for seed in 0..SEND_QUEUE_BOUND {
        hub.fanout(&group(1), &envelope(seed as u8), writer_id)
            .await;
    }
    // One more envelope, which cannot be queued: the subscriber now owes a
    // downgrade.
    assert_eq!(
        hub.fanout(&group(1), &envelope(200), writer_id).await,
        vec![(id, Delivery::Downgraded)]
    );

    // With no room at all, the beat round reports the debt rather than the shed:
    // there was no slot for the notice either, so nothing was discharged and the
    // subscriber is still owed one.
    assert_eq!(
        hub.fanout_frame(&group(1), &beat(&group(1)), writer_id, 2)
            .await,
        vec![(id, Delivery::Downgraded)]
    );

    // Drain one slot and beat again. Now the notice fits, so it goes out, and the
    // beat that carried the opportunity is shed rather than taking the slot it
    // just freed for itself.
    assert_eq!(pushed(&mut receiver), envelope(0));
    assert_eq!(
        hub.fanout_frame(&group(1), &beat(&group(1)), writer_id, 2)
            .await,
        vec![(id, Delivery::Shed)]
    );
    for seed in 1..SEND_QUEUE_BOUND {
        assert_eq!(pushed(&mut receiver), envelope(seed as u8));
    }
    downgrade(&mut receiver, &group(1));

    // And the debt is settled: a further beat is an ordinary shed with nothing
    // owed behind it.
    hub.fanout(&group(1), &envelope(201), writer_id).await;
    assert_eq!(pushed(&mut receiver), envelope(201));
}

#[tokio::test]
async fn an_owed_downgrade_is_discharged_by_a_beat_when_no_envelope_follows() {
    // The regression: the owed downgrade used to be attempted only ahead of the next
    // *durable* frame, and the ephemeral arm took an early exit before it. So a
    // subscriber whose queue filled and then drained was never told it had a hole for
    // as long as its group had no further write, went on receiving beats as though it
    // were live, and lost the notice entirely when `disconnect` dropped its entry. An
    // undeclared hole in an author chain is a security alarm on somebody else's
    // screen, so the debt is discharged at the first opportunity of any kind.
    let hub = Hub::new();
    let (sender, mut receiver) = outbound_channel();
    let id = hub.connect();
    let writer_id = hub.connect();
    hub.subscribe(&group(1), id, sender, 2).await;

    for _ in 0..SEND_QUEUE_BOUND {
        hub.fanout(&group(1), &envelope(1), writer_id).await;
    }
    assert_eq!(
        hub.fanout(&group(1), &envelope(2), writer_id).await,
        vec![(id, Delivery::Downgraded)]
    );
    assert_eq!(hub.downgrades(), 1);

    // The client catches up on everything it was sent. Its queue is now empty, it is
    // missing one envelope, and it has been told nothing.
    let mut drained = 0;
    while receiver.try_recv().is_ok() {
        drained += 1;
    }
    assert_eq!(drained, SEND_QUEUE_BOUND);

    // No further envelope is ever published to this group. The only traffic is a beat.
    let outcomes = hub
        .fanout_frame(&group(1), &beat(&group(1)), writer_id, 2)
        .await;
    assert_eq!(outcomes, vec![(id, Delivery::Sent)]);

    // The downgrade goes first, then the beat: the client learns it must reconcile
    // before it reads anything that would look like a live stream.
    downgrade(&mut receiver, &group(1));
    match receiver.try_recv().expect("the beat is queued") {
        Outbound::Frame(Frame::Live { group: at, .. }) => assert_eq!(at, group(1)),
        other => panic!("expected the beat, got {other:?}"),
    }
    assert!(receiver.try_recv().is_err());

    // And the debt is settled: a second beat is not preceded by a second downgrade.
    hub.fanout_frame(&group(1), &beat(&group(1)), writer_id, 2)
        .await;
    match receiver.try_recv().expect("the second beat is queued") {
        Outbound::Frame(Frame::Live { .. }) => {}
        other => panic!("the downgrade was sent twice: {other:?}"),
    }
    assert_eq!(hub.downgrades(), 1);
}
