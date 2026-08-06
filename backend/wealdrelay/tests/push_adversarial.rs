// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The push path under a hostile or broken counterparty.
//!
//! Six things that must hold when something is wrong: a second principal cannot take
//! a handle somebody else registered, a handle never reaches a log line, a connected
//! principal is never woken, a ringer that hangs for thirty seconds costs `SEND`
//! nothing, a `404` deletes the row, and a `429` pauses the worker rather than
//! filling a queue.
//!
//! The ringers here are real listeners on loopback answering real HTTP, and the
//! relay's own pooled client is what talks to them. `specs/backend/relay/push.md`
//! section 4 states the latency requirement as a test rather than as prose, and this
//! is that test.

mod support;

use std::time::{Duration, Instant};

use wealdrelay::frame::{ErrorCode, Frame, WakeBody};
use wealdrelay::health::Clock;
use wealdrelay::push::store;
use wealdrelay::push::{ringer, worker, Category, ALL_CATEGORIES};

use support::{
    config_for_push, default_device, entry_hash_of, make_group, other_device, wake_expiry,
    wake_handle, Client, HangingRinger, RecordingRinger, Running, Scratch,
};

const CLOCK: u64 = 1_700_000_000_000;
const WORKSPACE: &str = "ws-step4";

#[tokio::test(flavor = "multi_thread")]
async fn a_second_principal_cannot_take_a_handle_that_is_already_registered() {
    // The only way one device could steal another's wakes, refused by a unique index
    // rather than by a read followed by a write. Both devices are in the same
    // workspace here, which is the case a check-then-insert would most plausibly lose.
    let scratch = Scratch::new("push_adversarial_theft").await;
    let blobs = tempfile::tempdir().unwrap();
    let ringer = RecordingRinger::accepting().await;
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), &ringer.url(), 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x80).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&Frame::Wake(WakeBody::Register {
        handle: wake_handle(0xAA),
        categories: ALL_CATEGORIES,
        expires_at: wake_expiry(CLOCK),
    }))
    .await;
    assert!(matches!(
        ada.recv_frame().await,
        Frame::Wake(WakeBody::Registered { .. })
    ));

    let mut thief = Client::connect(relay.address).await;
    thief
        .handshake_as(&other_device(), vec![group.clone()], CLOCK)
        .await;
    thief
        .send_frame(&Frame::Wake(WakeBody::Register {
            handle: wake_handle(0xAA),
            categories: ALL_CATEGORIES,
            expires_at: wake_expiry(CLOCK),
        }))
        .await;
    match thief.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::PushHandleMalformed),
        other => panic!("the theft was not refused: {other:?}"),
    }

    // And the thief holds nothing at all, so a later wake for that handle still
    // belongs to the device that minted it.
    let pool = relay.state.database.as_ref().unwrap().pool();
    let thief_entry = entry_hash_of(pool, WORKSPACE, &other_device()).await;
    assert!(store::find(pool, WORKSPACE, &thief_entry)
        .await
        .expect("the store answers")
        .is_none());

    ringer.stop();
    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_handle_never_reaches_a_rendering_anything_could_log() {
    // The first of section 2's three absences, checked at every surface a handle
    // passes through: the frame, the body, the store's row type, and the scrubbing
    // pass that catches whatever a library nobody audited put in an error message.
    let handle = wake_handle(0xBE);
    let hex: String = handle.iter().map(|byte| format!("{byte:02x}")).collect();

    let frame = Frame::Wake(WakeBody::Register {
        handle: handle.clone(),
        categories: ALL_CATEGORIES,
        expires_at: wake_expiry(CLOCK),
    });
    for rendering in [format!("{frame:?}"), format!("{:?}", frame.tag())] {
        assert!(
            !rendering.contains(&hex) && !rendering.contains("190"),
            "a handle reached a rendering: {rendering}"
        );
    }
    assert!(
        format!("{frame:?}").contains("[redacted]"),
        "the body redacts rather than omitting, so a reader sees that something was held back"
    );

    // The scrubbing pass, which is the second line of defence rather than the first.
    // A hex handle is thirty two characters and can be all lowercase, so the
    // long-run pass would not claim it: it is claimed by its field name.
    for line in [
        format!("handle={hex}"),
        format!("\"handle\": \"{hex}\""),
        format!("push_handle: {hex}"),
    ] {
        let scrubbed = wealdrelay::logging::scrub(&line);
        assert!(
            !scrubbed.contains(&hex),
            "a labelled handle survived the scrubber: {scrubbed}"
        );
        assert!(scrubbed.contains("[redacted]"));
    }

    // And the store's own row, which is the only type that holds a handle beside an
    // entry hash.
    let row = store::Wakeable {
        entry_hash: vec![0x11; 32],
        handle,
        categories: ALL_CATEGORIES,
    };
    let rendered = format!("{row:?}");
    assert!(!rendered.contains(&hex));
    assert!(rendered.contains("[redacted]"));
    // The entry hash is a correlation handle rather than a capability, and it is
    // already what every access-set log line carries, so it is rendered as a prefix.
    assert!(rendered.contains("111111"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_principal_holding_a_socket_is_not_woken() {
    // Push exists for a device that is not connected. Waking one that is would be a
    // duplicate notification on the screen the user is already looking at, and it
    // would hand the ringer a timing it has no business having.
    let scratch = Scratch::new("push_adversarial_connected").await;
    let blobs = tempfile::tempdir().unwrap();
    let ringer = RecordingRinger::accepting().await;
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), &ringer.url(), 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x81).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let entry = entry_hash_of(pool, WORKSPACE, &default_device()).await;
    store::register(
        pool,
        WORKSPACE,
        &entry,
        &wake_handle(0xC1),
        ALL_CATEGORIES,
        wake_expiry(CLOCK),
    )
    .await
    .expect("the store answers");

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    assert_eq!(relay.state.hub.connections_for(&entry).await, 1);

    wealdrelay::push::dispatch::wake_group(&relay.state, &group, Category::Message).await;
    assert_eq!(
        relay.state.push.queued().await,
        0,
        "a connected principal is dropped before the queue, not after"
    );

    // The same device, disconnected, is woken: the suppression is about now rather
    // than about the registration.
    drop(ada);
    for _ in 0..100 {
        if relay.state.hub.connections_for(&entry).await == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    wealdrelay::push::dispatch::wake_group(&relay.state, &group, Category::Message).await;
    assert_eq!(relay.state.push.queued().await, 1);

    ringer.stop();
    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ringer_that_hangs_for_thirty_seconds_costs_send_nothing() {
    // The requirement `push.md` section 4 states as a test. The listener accepts the
    // connection and then says nothing at all, holding the stream so the relay sees an
    // open socket rather than a reset, which is the worst case: a refused connection
    // would fail fast and prove less.
    let scratch = Scratch::new("push_adversarial_hang").await;
    let blobs = tempfile::tempdir().unwrap();
    let hanging = HangingRinger::start().await;
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), &hanging.url(), 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x82).await;
    let pool = relay.state.database.as_ref().unwrap().pool();

    // A registered principal who is not connected, so every accepted envelope really
    // does produce a wake against the hanging ringer.
    let sleeper = entry_hash_of(pool, WORKSPACE, &other_device()).await;
    store::register(
        pool,
        WORKSPACE,
        &sleeper,
        &wake_handle(0xD1),
        ALL_CATEGORIES,
        wake_expiry(CLOCK),
    )
    .await
    .expect("the store answers");
    let worker = wealdrelay::push::spawn(&relay.state).expect("push is on, so there is a worker");

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;

    let mut slowest = Duration::ZERO;
    for index in 0..12u8 {
        let envelope = support::envelope_for(&group, &[index; 32]);
        let started = Instant::now();
        ada.send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
        assert!(matches!(ada.recv_frame().await, Frame::SendAck { .. }));
        slowest = slowest.max(started.elapsed());
    }
    assert!(
        slowest < Duration::from_secs(1),
        "the slowest SEND took {slowest:?} against a ringer that answers nothing; the wake is \
         supposed to be off the writer's task entirely"
    );

    worker.abort();
    hanging.stop();
    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ringer_that_answers_404_deletes_the_row() {
    // The ringer has told us the device is gone. Keeping the row would be keeping a
    // dead capability the relay consults on every accepted envelope, forever.
    let scratch = Scratch::new("push_adversarial_404").await;
    let blobs = tempfile::tempdir().unwrap();
    let gone = RecordingRinger::answering(404, None).await;
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), &gone.url(), 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let _group = make_group(&relay.state, 0x83).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let entry = entry_hash_of(pool, WORKSPACE, &default_device()).await;
    store::register(
        pool,
        WORKSPACE,
        &entry,
        &wake_handle(0xE1),
        ALL_CATEGORIES,
        wake_expiry(CLOCK),
    )
    .await
    .expect("the store answers");

    // One delivery, driven directly rather than through the loop: asserting this
    // through the worker would mean asserting on a sleep.
    worker::deliver(
        &relay.state,
        &ringer::shared(),
        &gone.url(),
        None,
        &wake_handle(0xE1),
        Category::Message,
    )
    .await;

    let seen = gone.wait_for(1).await;
    assert_eq!(seen.len(), 1, "the ringer was asked exactly once");
    // The request carries the handle and the category, and nothing else: an extra
    // field is how a group identifier eventually arrives in a payload.
    assert!(seen[0].contains("\"category\":\"message\""));
    assert!(seen[0].starts_with("{\"handle\":\""));
    assert_eq!(seen[0].matches(':').count(), 2, "two fields, no more");

    assert!(
        store::find(pool, WORKSPACE, &entry)
            .await
            .expect("the store answers")
            .is_none(),
        "a 404 is an instruction to forget the row"
    );
    assert_eq!(relay.state.push.failed(), 1);
    assert_eq!(
        relay.state.push.health(),
        wealdrelay::push::Health::Configured,
        "a ringer that answers is reachable, whatever it says"
    );

    gone.stop();
    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ringer_that_answers_429_pauses_the_worker_for_the_interval_it_named() {
    // A pause rather than a retry. Nothing is requeued: the wakes that arrive during
    // it coalesce and are shed at the queue's bound, both of which are bounded.
    let scratch = Scratch::new("push_adversarial_429").await;
    let blobs = tempfile::tempdir().unwrap();
    let limited = RecordingRinger::answering(429, Some(1)).await;
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), &limited.url(), 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let _group = make_group(&relay.state, 0x84).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let entry = entry_hash_of(pool, WORKSPACE, &default_device()).await;
    store::register(
        pool,
        WORKSPACE,
        &entry,
        &wake_handle(0xF1),
        ALL_CATEGORIES,
        wake_expiry(CLOCK),
    )
    .await
    .expect("the store answers");

    let started = Instant::now();
    worker::deliver(
        &relay.state,
        &ringer::shared(),
        &limited.url(),
        None,
        &wake_handle(0xF1),
        Category::Call,
    )
    .await;
    let elapsed = started.elapsed();

    assert_eq!(relay.state.push.pauses(), 1);
    assert!(
        elapsed >= Duration::from_secs(1),
        "the worker returned in {elapsed:?}, which is not the interval the ringer asked for"
    );
    assert!(
        elapsed < Duration::from_secs(worker::MAX_PAUSE_SECONDS),
        "and the pause is bounded"
    );
    // The row is untouched: a rate limit says nothing about whether the device exists.
    assert!(store::find(pool, WORKSPACE, &entry)
        .await
        .expect("the store answers")
        .is_some());
    assert_eq!(
        relay.state.push.failed(),
        0,
        "being told to wait is not a failed wake"
    );

    limited.stop();
    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ringer_that_refuses_is_counted_and_dropped_and_one_that_is_not_there_is_unreachable() {
    // Everything else the ringer can say. Counted and dropped, never retried into a
    // queue that could grow, and the row survives: a `500` from a ringer is a fault at
    // the ringer rather than a fact about the device.
    let scratch = Scratch::new("push_adversarial_refused").await;
    let blobs = tempfile::tempdir().unwrap();
    let refusing = RecordingRinger::answering(500, None).await;
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), &refusing.url(), 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let _group = make_group(&relay.state, 0x85).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let entry = entry_hash_of(pool, WORKSPACE, &default_device()).await;
    store::register(
        pool,
        WORKSPACE,
        &entry,
        &wake_handle(0x1A),
        ALL_CATEGORIES,
        wake_expiry(CLOCK),
    )
    .await
    .expect("the store answers");

    let shared = ringer::shared();
    worker::deliver(
        &relay.state,
        &shared,
        &refusing.url(),
        Some("a-bearer-the-ringer-checks"),
        &wake_handle(0x1A),
        Category::Handshake,
    )
    .await;
    assert_eq!(relay.state.push.failed(), 1);
    assert!(store::find(pool, WORKSPACE, &entry)
        .await
        .expect("the store answers")
        .is_some());
    assert_eq!(relay.state.push.queued().await, 0, "nothing was requeued");

    // A ringer that is not there at all. Reported `unreachable`, which is what
    // `/readyz` says and is deliberately still ready.
    let nowhere = format!("http://127.0.0.1:{}/v1/wake", reserved_port().await);
    worker::deliver(
        &relay.state,
        &shared,
        &nowhere,
        None,
        &wake_handle(0x1A),
        Category::Message,
    )
    .await;
    assert_eq!(
        relay.state.push.health(),
        wealdrelay::push::Health::Unreachable
    );
    assert_eq!(relay.state.push.failed(), 2);

    // And a url that is not a url is refused rather than panicking on the wake path.
    worker::deliver(
        &relay.state,
        &shared,
        "not a url",
        None,
        &wake_handle(0x1A),
        Category::Message,
    )
    .await;
    assert_eq!(relay.state.push.failed(), 3);

    refusing.stop();
    relay.shutdown().await;
    scratch.drop_database().await;
}

/// A port nothing is listening on: bound, read, and released before it is used.
///
/// Racy in principle and deliberate in practice, for the reason the harness binds
/// port zero everywhere else: the alternative is a hard-coded port, which is the one
/// thing `testing.md` forbids because two suites would then share it.
async fn reserved_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("an address").port();
    drop(listener);
    port
}

#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_envelope_wakes_the_sleeping_member_and_the_writer_is_never_woken() {
    // The whole path, end to end, with a real ringer: Ada writes, Bo is registered and
    // asleep, and exactly one wake arrives naming Bo's handle and the `message`
    // category. Ada is connected and is the writer, so she is woken neither way.
    let scratch = Scratch::new("push_adversarial_end_to_end").await;
    let blobs = tempfile::tempdir().unwrap();
    let ringer = RecordingRinger::accepting().await;
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), &ringer.url(), 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x86).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let bo = entry_hash_of(pool, WORKSPACE, &other_device()).await;
    let ada = entry_hash_of(pool, WORKSPACE, &default_device()).await;
    store::register(
        pool,
        WORKSPACE,
        &bo,
        &wake_handle(0x2B),
        ALL_CATEGORIES,
        wake_expiry(CLOCK),
    )
    .await
    .expect("the store answers");
    store::register(
        pool,
        WORKSPACE,
        &ada,
        &wake_handle(0x2A),
        ALL_CATEGORIES,
        wake_expiry(CLOCK),
    )
    .await
    .expect("the store answers");
    let worker = wealdrelay::push::spawn(&relay.state).expect("a worker");

    let mut writer = Client::connect(relay.address).await;
    writer.handshake(vec![group.clone()], CLOCK).await;
    let envelope = support::envelope_for(&group, b"wake bo");
    writer
        .send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
    assert!(matches!(writer.recv_frame().await, Frame::SendAck { .. }));

    let seen = ringer.wait_for(1).await;
    assert_eq!(seen.len(), 1, "one sleeping member, one wake");
    let bo_hex: String = wake_handle(0x2B)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert!(seen[0].contains(&bo_hex));
    assert!(seen[0].contains("\"category\":\"message\""));

    worker.abort();
    ringer.stop();
    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_with_push_off_starts_no_worker_and_a_worker_started_anyway_returns() {
    // Two halves of the same rule. `spawn` declines to start a worker when there is
    // nothing to drain and nowhere to send it, and `run` is total anyway, so a caller
    // that starts one by hand against a push-off relay gets a task that ends rather
    // than a loop that spins on an empty queue forever.
    let scratch = Scratch::new("push_adversarial_no_worker").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        support::config_for(&scratch, blobs.path()),
        Clock::Fixed(CLOCK),
    )
    .await;

    assert!(
        wealdrelay::push::spawn(&relay.state).is_none(),
        "a relay with no outbound leg has nothing to run"
    );
    tokio::time::timeout(
        Duration::from_secs(2),
        worker::run(std::sync::Arc::clone(&relay.state)),
    )
    .await
    .expect("the worker returns rather than looping on a relay with push off");

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_access_state_query_grows_no_field_that_could_hold_a_handle() {
    // The second of section 2's three absences. `ACCESS` carries exactly two facts,
    // and this asserts it against a relay that is holding a registration for the
    // device doing the asking: the bytes that come back must contain neither the
    // handle nor anything else the push table holds.
    let scratch = Scratch::new("push_adversarial_access_state").await;
    let blobs = tempfile::tempdir().unwrap();
    let ringer = RecordingRinger::accepting().await;
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), &ringer.url(), 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x87).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let entry = entry_hash_of(pool, WORKSPACE, &default_device()).await;
    let handle = wake_handle(0x3C);
    store::register(
        pool,
        WORKSPACE,
        &entry,
        &handle,
        ALL_CATEGORIES,
        wake_expiry(CLOCK),
    )
    .await
    .expect("the store answers");

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&Frame::Access { body: Vec::new() }).await;
    match ada.recv_frame().await {
        Frame::Access { body } => {
            assert!(
                !body.windows(handle.len()).any(|window| window == handle),
                "the state query carried the handle"
            );
            // And it is still the two-fact document it has always been rather than a
            // longer one that happens not to hold this handle.
            assert!(
                body.len() < 128,
                "the state document grew: {} bytes",
                body.len()
            );
        }
        other => panic!("expected the access state, got {other:?}"),
    }

    ringer.stop();
    relay.shutdown().await;
    scratch.drop_database().await;
}
