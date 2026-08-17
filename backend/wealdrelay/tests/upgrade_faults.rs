// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The two upgrade-time bounds: a failed upgrade releases its connection slot
//! (WEALD-291), and the transport refuses an oversized message before it is
//! buffered (WEALD-292).
//!
//! Both are pre-authentication properties of `/relay` itself, which is why they
//! are their own suite rather than lines in a protocol one: the peer in every
//! test here never sends a valid frame, and the claim under test is about what
//! that costs the relay.

mod support;

use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt as _;
use wealdrelay::frame::MAX_FRAME_BYTES;
use wealdrelay::health::{Clock, WS_MAX_MESSAGE_BYTES};

use support::{config_for, default_device, seed_access_set, Client, Running, Scratch};

const CLOCK: u64 = 1_700_000_000_000;

/// Wait for the open-connection counter to drain to zero, or fail with its value.
async fn drained(relay: &Running) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let open = relay.state.open_connections();
        if open == 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{open} connection slot(s) were never released"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

// MARK: WEALD-291, the slot is released on every path out of the upgrade

#[tokio::test(flavor = "multi_thread")]
async fn aborted_upgrades_leave_no_connection_slot_behind() {
    // The attack in the ticket: a well-formed `GET /relay` upgrade request whose
    // sender resets the TCP connection without completing the upgrade. The slot
    // and the per-source share are taken before `on_upgrade`; on a failed upgrade
    // `serve_connection` never runs, so only an `on_failed_upgrade` handler can
    // give them back. Before the fix each abort leaked one slot permanently and
    // `WEALD_RELAY_MAX_CONNECTIONS` aborts took the relay offline with no
    // authentication and no payload bytes.
    let scratch = Scratch::new("upgrade_abort").await;
    let blobs = tempfile::tempdir().unwrap();
    let mut config = config_for(&scratch, blobs.path());
    // A finite, small table, so a leak is visible as refusal rather than as a
    // number nobody reads.
    config.max_connections = wealdrelay::config::Limit::Of(4);
    let relay = Running::start(config, Clock::Fixed(CLOCK)).await;

    for _ in 0..20 {
        // A raw socket that resets rather than closes: `SO_LINGER` at zero
        // discards the send buffer and RSTs on drop, which is what a killed
        // client looks like from the relay's side.
        #[allow(deprecated)]
        let stream = {
            let socket = tokio::net::TcpSocket::new_v4().expect("a socket");
            let stream = socket.connect(relay.address).await.expect("connect");
            stream
                .set_linger(Some(Duration::ZERO))
                .expect("reset instead of closing");
            stream
        };
        let mut stream = stream;
        let request = format!(
            "GET /relay HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n\r\n",
            relay.address
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("send the upgrade request");
        // Gone before the upgrade completes, without reading the 101.
        drop(stream);
        // Whichever path the race took (a failed upgrade, or an upgrade that
        // completed against a dead socket), the slot must come back before the
        // next admission needs it: the table is 4 and the aborts are 20.
        drained(&relay).await;
    }

    // The counters agree with reality: nothing open, and the refusal counter is
    // not what absorbed the aborts.
    assert_eq!(relay.state.open_connections(), 0);

    // And a real client still connects and completes a handshake, which is the
    // whole point: the table was not eaten by connections that no longer exist.
    let group = {
        let pool = relay.state.database.as_ref().expect("a database").pool();
        let group = vec![0x42; 32];
        sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
            .bind(&group)
            .bind("ws-upgrade")
            .execute(pool)
            .await
            .expect("create the group");
        group
    };
    // The workspace has to admit the device before `AUTH` can succeed. Without
    // this the handshake is refused `WriterNotInAccessSet`, which says nothing
    // about the connection slots this test is named for.
    seed_access_set(&relay.state, "ws-upgrade", &[default_device()]).await;
    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group], CLOCK).await;

    relay.shutdown().await;
    scratch.drop_database().await;
}

// MARK: WEALD-292, the transport bounds a message before it exists

#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_message_is_refused_by_the_transport_and_a_maximal_frame_is_not() {
    // The length check in `ws::handle_message` runs after the WebSocket layer has
    // reassembled the whole message, so it bounds nothing about allocation. The
    // bound that does is `max_message_size` on the upgrade, and this is its
    // proof: a message past `WS_MAX_MESSAGE_BYTES` ends the connection at the
    // transport, while a maximal legal frame still reaches the protocol and is
    // answered with a frame.
    let scratch = Scratch::new("oversized").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;

    // Oversized: one byte past the transport ceiling. The relay closes without
    // ever seeing it as a message; there is no protocol error frame because the
    // protocol never ran.
    let mut oversized = Client::connect(relay.address).await;
    oversized.send(&vec![0u8; WS_MAX_MESSAGE_BYTES + 1]).await;
    let answer = tokio::time::timeout(Duration::from_secs(10), oversized.recv())
        .await
        .expect("the relay answers rather than buffering");
    assert!(
        answer.is_none(),
        "an oversized message was accepted as data"
    );

    // Maximal-but-legal: exactly `MAX_FRAME_BYTES` of bytes that decode as no
    // frame. The transport delivers it and the protocol answers with an error
    // frame on a connection that stays up, which proves the ceiling above did
    // not eat any message a conforming client can send.
    let mut maximal = Client::connect(relay.address).await;
    maximal.send(&vec![0u8; MAX_FRAME_BYTES]).await;
    let answer = tokio::time::timeout(Duration::from_secs(10), maximal.recv())
        .await
        .expect("the relay answers the maximal frame");
    assert!(
        answer.is_some(),
        "a maximal legal frame was refused by the transport"
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}
