// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The call registry under real concurrency, on a multi-threaded runtime.
//!
//! Every other call suite drives the registry from one task, which is the one
//! thing production never does. A relay carrying fifty calls has a reader loop per
//! socket, each on whichever worker thread tokio gave it, and each calling `join`,
//! `leave`, `route` and `forget` against one shared map with no coordination
//! beyond the mutex inside it. The interleavings that produces are not reachable
//! from a sequential test, and three of them would be defects an operator sees
//! only under load:
//!
//! 1. **A seat granted twice.** `join` reads the participant count and then pushes,
//!    and two connections racing on the last seat of a call or the last call of an
//!    instance must not both be admitted. That is one critical section, and this
//!    file is what proves it stayed one.
//! 2. **A leak under a disconnect storm.** Sockets die concurrently with the
//!    frames still in flight behind them. Every one of those reader loops calls
//!    `forget`, and what has to be true afterwards is that the process holds
//!    nothing: not a call with no participants, not a participant nobody is
//!    reading.
//! 3. **A frame to a stranger.** `route` walks a participant list that another
//!    task may be editing. A media frame reaching a connection that had already
//!    left is a call whose membership the relay got wrong, which is the one
//!    mistake on this path that is a confidentiality failure rather than a
//!    capacity one.
//!
//! Nothing here is timing-dependent in its assertions. The concurrency creates the
//! interleavings; every claim is checked after the tasks have been joined, so a
//! slow machine makes this file slower and never flakier.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use wealdrelay::calls::{
    CallRegistry, JoinRefusal, CALL_ID_BYTES, MAX_PARTICIPANTS_PER_CALL, STREAM_BYTES,
};
use wealdrelay::frame::{ErrorCode, Frame};
use wealdrelay::ws::{outbound_channel, Outbound, OutboundReceiver, OutboundSender};

fn call_of(seed: u8) -> [u8; CALL_ID_BYTES] {
    [seed; CALL_ID_BYTES]
}

fn group_of(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

fn media_of(call: u8, seq: u64) -> Frame {
    Frame::Media {
        call_id: call_of(call).to_vec(),
        stream: [1u8; STREAM_BYTES].to_vec(),
        seq,
        ct: vec![9; 80],
    }
}

/// A connection whose receiver is held for the life of the test, so a `Closed` is
/// never an accident of a dropped channel.
fn peer() -> (OutboundSender, OutboundReceiver) {
    outbound_channel()
}

fn drain(receiver: &mut OutboundReceiver) -> usize {
    let mut taken = 0;
    while let Ok(Outbound::Frame(_)) = receiver.try_recv() {
        taken += 1;
    }
    taken
}

/// Twenty connections racing for the five seats in one call.
///
/// Exactly ``MAX_PARTICIPANTS_PER_CALL`` are admitted and the rest are told
/// `CallFull`, whatever order the scheduler ran them in. A check-then-push that
/// was not one critical section would admit six here on some runs and five on
/// others, which is the shape of bug that passes review and fails in a customer's
/// meeting.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn twenty_connections_racing_for_five_seats_fill_it_exactly_once() {
    let registry = Arc::new(CallRegistry::new(8));
    let admitted = Arc::new(AtomicUsize::new(0));
    let full = Arc::new(AtomicUsize::new(0));
    // Held so no sender is closed under the racing joins.
    let mut held = Vec::new();

    let mut tasks = Vec::new();
    for connection in 0..20u64 {
        let (sender, receiver) = peer();
        held.push(receiver);
        let registry = Arc::clone(&registry);
        let admitted = Arc::clone(&admitted);
        let full = Arc::clone(&full);
        tasks.push(tokio::spawn(async move {
            match registry
                .join(&call_of(1), &group_of(1), connection, sender)
                .await
            {
                Ok(()) => admitted.fetch_add(1, Ordering::Relaxed),
                Err(JoinRefusal::CallFull) => full.fetch_add(1, Ordering::Relaxed),
                Err(other) => panic!("unexpected refusal: {other:?}"),
            };
        }));
    }
    for task in tasks {
        task.await.expect("a task");
    }

    assert_eq!(admitted.load(Ordering::Relaxed), MAX_PARTICIPANTS_PER_CALL);
    assert_eq!(full.load(Ordering::Relaxed), 20 - MAX_PARTICIPANTS_PER_CALL);
    // And the registry agrees with the count it handed out: exactly five
    // connections are held, not four and not six.
    let mut inside = 0;
    for connection in 0..20u64 {
        if registry.holds(&call_of(1), connection).await {
            inside += 1;
        }
    }
    assert_eq!(inside, MAX_PARTICIPANTS_PER_CALL);
    assert_eq!(registry.open_calls().await, 1);
}

/// The same race one level up: many connections opening distinct calls against an
/// instance ceiling.
///
/// The ceiling is the operator's sizing decision, and an instance that carried one
/// more call than it was sized for under load is an instance whose limit means
/// nothing. Every admitted call is a distinct id and the count is exact.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_opens_never_exceed_the_instance_ceiling() {
    const CEILING: usize = 4;
    let registry = Arc::new(CallRegistry::new(CEILING));
    let mut held = Vec::new();
    let mut tasks = Vec::new();
    for call in 0..32u8 {
        let (sender, receiver) = peer();
        held.push(receiver);
        let registry = Arc::clone(&registry);
        tasks.push(tokio::spawn(async move {
            registry
                .join(&call_of(call), &group_of(1), u64::from(call), sender)
                .await
                .map(|()| call)
        }));
    }

    let mut opened = HashSet::new();
    let mut refused = 0;
    for task in tasks {
        match task.await.expect("a task") {
            Ok(call) => {
                assert!(opened.insert(call), "call {call} was opened twice");
            }
            Err(JoinRefusal::TooManyCalls) => refused += 1,
            Err(other) => panic!("unexpected refusal: {other:?}"),
        }
    }
    assert_eq!(opened.len(), CEILING);
    assert_eq!(refused, 32 - CEILING);
    assert_eq!(registry.open_calls().await, CEILING);
    // The refusal names the lever, so a client surfaces the ceiling rather than a
    // shrug. Never content-derived: it is the configured number and nothing else.
    assert_eq!(JoinRefusal::TooManyCalls.detail(CEILING), CEILING as u64);
}

/// Routing while participants join and leave underneath it.
///
/// The claim is the confidentiality one: a frame is never delivered to a
/// connection that is not in the call at the moment it is delivered. Asserted by
/// counting, after the storm, what each connection actually received against
/// whether it was ever a member at all: a connection that never joined must have
/// received nothing, whatever raced with what.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_media_frame_never_reaches_a_connection_that_never_joined() {
    let registry = Arc::new(CallRegistry::new(8));
    // Four members and four strangers. The strangers hold open sockets on the same
    // process and share the group; the only thing they never did is join the call,
    // which is the entire distinction the media path rests on.
    let mut members = Vec::new();
    let mut strangers = Vec::new();
    for connection in 0..4u64 {
        let (sender, receiver) = peer();
        registry
            .join(&call_of(1), &group_of(1), connection, sender)
            .await
            .expect("a seat");
        members.push(receiver);
    }
    for _ in 0..4 {
        let (sender, receiver) = peer();
        // Kept alive and deliberately never joined. The sender is dropped into a
        // holder so the channel stays open.
        strangers.push((sender, receiver));
    }

    let mut tasks = Vec::new();
    // Senders, hammering.
    for connection in 0..4u64 {
        let registry = Arc::clone(&registry);
        tasks.push(tokio::spawn(async move {
            for seq in 0..200u64 {
                let _ = registry
                    .route(&call_of(1), connection, &media_of(1, seq))
                    .await;
            }
        }));
    }
    // Churn: one member leaving and rejoining underneath the fanout. Its receiver
    // is kept with the members rather than the strangers, because a connection
    // that rejoins is a member again and audio reaching it is correct.
    let (sender, receiver) = peer();
    members.push(receiver);
    {
        let registry = Arc::clone(&registry);
        tasks.push(tokio::spawn(async move {
            for _ in 0..50 {
                registry.leave(&call_of(1), 3).await;
                let _ = registry
                    .join(&call_of(1), &group_of(1), 3, sender.clone())
                    .await;
            }
        }));
    }
    for task in tasks {
        task.await.expect("a task");
    }

    // Not one frame reached a connection that never joined.
    for (index, (_, receiver)) in strangers.iter_mut().enumerate() {
        assert_eq!(
            drain(receiver),
            0,
            "a connection that never joined received audio (stranger {index})"
        );
    }
    // And the members did receive audio, so the assertion above is not passing
    // because nothing was routed at all.
    let delivered: usize = members.iter_mut().map(drain).sum();
    assert!(delivered > 0, "no audio was routed, so nothing was proven");
}

/// A disconnect storm leaves nothing behind.
///
/// Sockets die concurrently while frames are still being routed behind them, which
/// is what a relay restart on the other side of a load balancer looks like. Every
/// reader loop ends and calls `forget`, and the process must then hold no call at
/// all: an empty call still holding its id is a seat under the instance ceiling
/// that nobody can use and nothing will ever free, and at fifty frames a second a
/// leaked participant is a stream fanned at a socket nobody is reading for the
/// life of the process.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_disconnect_storm_leaves_no_call_and_no_participant_behind() {
    let registry = Arc::new(CallRegistry::new(64));
    let mut held = Vec::new();
    // Sixteen calls, and every connection is in two of them, so `forget` has to be
    // the thing that empties a call rather than `leave` being called with the right
    // id. Two seats taken directly and two inherited from the neighbouring call,
    // which is four of the five a call may hold.
    for call in 0..16u8 {
        for seat in 0..2u64 {
            let connection = u64::from(call) * 2 + seat;
            let (sender, receiver) = peer();
            held.push(receiver);
            registry
                .join(&call_of(call), &group_of(1), connection, sender.clone())
                .await
                .expect("a seat");
            // The same connection in a second call.
            let _ = registry
                .join(&call_of((call + 1) % 16), &group_of(1), connection, sender)
                .await;
        }
    }
    assert_eq!(registry.open_calls().await, 16);

    let mut tasks = Vec::new();
    for call in 0..16u8 {
        let registry = Arc::clone(&registry);
        tasks.push(tokio::spawn(async move {
            for seq in 0..100u64 {
                let connection = u64::from(call) * 2;
                let _ = registry
                    .route(&call_of(call), connection, &media_of(call, seq))
                    .await;
            }
        }));
    }
    for connection in 0..32u64 {
        let registry = Arc::clone(&registry);
        tasks.push(tokio::spawn(async move {
            registry.forget(connection).await;
        }));
    }
    for task in tasks {
        task.await.expect("a task");
    }

    assert_eq!(
        registry.open_calls().await,
        0,
        "a call outlived every one of its participants"
    );
    // Nothing is routable any more, and the answer is the denial rather than a
    // silent success against an empty participant list.
    assert_eq!(
        registry.route(&call_of(0), 0, &media_of(0, 1)).await,
        Err(ErrorCode::WriterNotInAccessSet)
    );
}

/// `forget` is idempotent and safe to call concurrently for the same connection.
///
/// A reader loop can end more than one way, and the cleanup runs on the path that
/// ends it. Two of them arriving at once must not double-remove a seat belonging
/// to somebody else, which is what a removal by index rather than by identity
/// would do.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_forgets_of_one_connection_take_only_that_connection() {
    let registry = Arc::new(CallRegistry::new(8));
    let mut held = Vec::new();
    for connection in 0..5u64 {
        let (sender, receiver) = peer();
        held.push(receiver);
        registry
            .join(&call_of(1), &group_of(1), connection, sender)
            .await
            .expect("a seat");
    }

    let mut tasks = Vec::new();
    for _ in 0..16 {
        let registry = Arc::clone(&registry);
        tasks.push(tokio::spawn(async move {
            registry.forget(2).await;
            registry.leave(&call_of(1), 2).await;
        }));
    }
    for task in tasks {
        task.await.expect("a task");
    }

    for connection in [0u64, 1, 3, 4] {
        assert!(
            registry.holds(&call_of(1), connection).await,
            "connection {connection} was removed by somebody else's cleanup"
        );
    }
    assert!(!registry.holds(&call_of(1), 2).await);
    assert_eq!(registry.open_calls().await, 1);
}

/// The two counters are counters, under contention.
///
/// `shed` and `denied` are the only observability the media path has, deliberately
/// unlabelled so they carry no call id, no group and no principal. Unlabelled is
/// only useful if the number is right, so this asserts the exact count after a
/// concurrent storm of denials: a relaxed counter that lost increments would
/// under-report a live attack.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_denial_counter_is_exact_under_contention() {
    let registry = Arc::new(CallRegistry::new(8));
    const TASKS: u64 = 16;
    const EACH: u64 = 100;

    let mut tasks = Vec::new();
    for connection in 0..TASKS {
        let registry = Arc::clone(&registry);
        tasks.push(tokio::spawn(async move {
            for seq in 0..EACH {
                assert_eq!(
                    registry
                        .route(&call_of(9), connection, &media_of(9, seq))
                        .await,
                    Err(ErrorCode::WriterNotInAccessSet)
                );
            }
        }));
    }
    for task in tasks {
        task.await.expect("a task");
    }
    assert_eq!(registry.denied(), TASKS * EACH);
    assert_eq!(registry.shed(), 0);
    // And no call was created by a frame for one that does not exist. A media
    // frame is never an admission.
    assert_eq!(registry.open_calls().await, 0);
}

/// A wedged participant is shed and keeps its seat, while the others keep talking.
///
/// The shed rule under contention rather than in isolation: one slow reader must
/// cost the call its own frames and nobody else's. A relay that closed the call or
/// downgraded the sender would turn one bad network into everybody's dropped call.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn one_wedged_participant_costs_only_its_own_audio() {
    let registry = Arc::new(CallRegistry::new(8));
    let (speaker, mut speaker_rx) = peer();
    let (healthy, mut healthy_rx) = peer();
    let (wedged, wedged_rx) = peer();
    registry
        .join(&call_of(1), &group_of(1), 1, speaker)
        .await
        .expect("a seat");
    registry
        .join(&call_of(1), &group_of(1), 2, healthy)
        .await
        .expect("a seat");
    registry
        .join(&call_of(1), &group_of(1), 3, wedged)
        .await
        .expect("a seat");

    // The wedged connection never reads. The healthy one is drained on the same
    // task, immediately after each frame, which is deliberately not a spawned
    // drainer: a reader racing the router would make the count a measurement of
    // the scheduler, and this assertion is about the shed rule rather than about
    // how fast a machine happens to be.
    let mut delivered = 0;
    let mut shed_seen = false;
    for seq in 0..2_000u64 {
        let routed = registry
            .route(&call_of(1), 1, &media_of(1, seq))
            .await
            .expect("the speaker is a participant");
        assert_eq!(routed.gone, 0, "a queue that filled was reported as gone");
        assert_eq!(routed.sent + routed.shed, 2);
        shed_seen |= routed.shed > 0;
        delivered += drain(&mut healthy_rx);
    }

    assert!(
        shed_seen,
        "the wedged queue never filled, so nothing was shed"
    );
    assert!(registry.shed() > 0);
    // The wedged participant kept its seat. One late packet is not a reason to drop
    // somebody from a call, and there is no reconciliation for audio to fall back
    // on, so the frame is the only thing that may be lost.
    assert!(registry.holds(&call_of(1), 3).await);
    assert_eq!(registry.open_calls().await, 1);
    // The healthy participant received every single frame. Not most of them: a
    // reader that keeps up is owed the whole stream, and a relay that dropped one
    // of its frames because somebody else's queue was full would be making one bad
    // network into everybody's bad call.
    let total = delivered + drain(&mut healthy_rx);
    assert_eq!(
        total, 2_000,
        "the healthy participant lost audio while another connection was wedged"
    );
    // And the speaker never received its own audio.
    assert_eq!(drain(&mut speaker_rx), 0);
    drop(wedged_rx);
}
