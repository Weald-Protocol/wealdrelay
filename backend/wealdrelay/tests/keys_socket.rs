// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `KEYS` over real sockets against real Postgres.
//!
//! The frame that makes a private conversation possible without both people being
//! online at once. What is asserted here is what a client can actually do with it,
//! and what a stranger cannot: publish against the authenticated device key, fetch
//! a peer's package once, and get nothing at all from outside the workspace.

mod support;

use wealdrelay::frame::{ErrorCode, Frame, KeysBody};
use wealdrelay::health::Clock;
use wealdrelay::session::{KEYS_FRAMES_PER_MINUTE, MAX_KEY_PACKAGE_FETCH};

use support::{config_for, make_group, other_device, Client, Running, Scratch};

const CLOCK: u64 = 1_700_000_000_000;

fn package(seed: u8) -> Vec<u8> {
    vec![seed; 48]
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_publishes_and_a_peer_fetches_exactly_once() {
    let scratch = Scratch::new("keys_socket_round_trip").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x40).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&Frame::Keys(KeysBody::Publish {
        packages: vec![package(1), package(2)],
    }))
    .await;
    match ada.recv_frame().await {
        Frame::Keys(KeysBody::Published { remaining }) => assert_eq!(remaining, 2),
        other => panic!("expected a shelf depth, got {other:?}"),
    }

    let bo_key = other_device();
    let mut bo = Client::connect(relay.address).await;
    bo.handshake_as(&bo_key, vec![group.clone()], CLOCK).await;

    let ada_device = support::default_device()
        .verifying_key()
        .to_bytes()
        .to_vec();
    bo.send_frame(&Frame::Keys(KeysBody::Fetch {
        device: ada_device.clone(),
        count: 1,
    }))
    .await;
    let first = match bo.recv_frame().await {
        Frame::Keys(KeysBody::Bundles { packages }) => {
            assert_eq!(packages.len(), 1);
            packages[0].clone()
        }
        other => panic!("expected a bundle, got {other:?}"),
    };

    // The second fetch gets the other package and never the first: a package
    // served twice would hand two dm groups the same joiner leaf key.
    bo.send_frame(&Frame::Keys(KeysBody::Fetch {
        device: ada_device.clone(),
        count: 1,
    }))
    .await;
    match bo.recv_frame().await {
        Frame::Keys(KeysBody::Bundles { packages }) => assert_ne!(packages[0], first),
        other => panic!("expected a bundle, got {other:?}"),
    }

    // And the shelf is empty, which is an answer rather than an error.
    bo.send_frame(&Frame::Keys(KeysBody::Fetch {
        device: ada_device,
        count: 1,
    }))
    .await;
    assert!(matches!(bo.recv_frame().await, Frame::Keys(KeysBody::None)));

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fetch_for_a_device_outside_the_access_set_is_refused() {
    // Checked against the target device and not only the requester. Without it any
    // admitted device could enumerate a shelf belonging to a workspace it is not
    // in, which is a membership oracle as well as a theft of one-time keys.
    let scratch = Scratch::new("keys_socket_outsider").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x41).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&Frame::Keys(KeysBody::Fetch {
        device: vec![0x99; 32],
        count: 1,
    }))
    .await;
    match ada.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("expected a refusal, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fetch_above_the_cap_is_refused_because_higher_is_enumeration() {
    let scratch = Scratch::new("keys_socket_cap").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x42).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&Frame::Keys(KeysBody::Fetch {
        device: vec![0x11; 32],
        count: MAX_KEY_PACKAGE_FETCH + 1,
    }))
    .await;
    match ada.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::EnvelopeTooLarge),
        other => panic!("expected a refusal, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_keys_budget_refuses_the_frame_and_keeps_the_connection() {
    // A roster prefetch is a startup burst, not a stream, so the budget is thirty
    // a minute and it is spent on the frame rather than on the socket.
    let scratch = Scratch::new("keys_socket_budget").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x43).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    for _ in 0..KEYS_FRAMES_PER_MINUTE {
        ada.send_frame(&Frame::Keys(KeysBody::Publish {
            packages: vec![package(3)],
        }))
        .await;
        let _ = ada.recv_frame().await;
    }
    ada.send_frame(&Frame::Keys(KeysBody::Publish {
        packages: vec![package(3)],
    }))
    .await;
    match ada.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::RateLimited),
        other => panic!("expected a quota refusal, got {other:?}"),
    }

    // The connection is still up: durable traffic is unaffected by a spent key
    // budget, exactly as it is by a spent presence budget.
    let envelope = support::envelope_for(&group, b"still writing");
    ada.send_frame(&Frame::Send {
        envelope: envelope.encode(),
    })
    .await;
    assert!(matches!(ada.recv_frame().await, Frame::SendAck { .. }));

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_to_client_form_sent_upward_closes_the_connection() {
    // A client sending a reply form is a client that is wrong about the protocol,
    // and the frame table's answer to that is the same everywhere: refuse and
    // close, rather than guess at what it meant.
    let scratch = Scratch::new("keys_socket_wrong_form").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x44).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&Frame::Keys(KeysBody::Published { remaining: 3 }))
        .await;
    match ada.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::MalformedHeader),
        other => panic!("expected a refusal, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn keys_before_auth_is_refused_like_every_frame_except_join() {
    let scratch = Scratch::new("keys_socket_pre_auth").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x45).await;

    let mut stranger = Client::connect(relay.address).await;
    stranger
        .handshake_to_challenge(vec![group.clone()], CLOCK)
        .await;
    stranger
        .send_frame(&Frame::Keys(KeysBody::Publish {
            packages: vec![package(1)],
        }))
        .await;
    match stranger.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::MalformedHeader),
        other => panic!("expected a refusal, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}
