// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The two connection deadlines, over a real socket against a real relay.
//!
//! `deadline_unit.rs` proves the arithmetic. What it cannot prove is that the
//! arithmetic is wired to anything: that a socket which says nothing is actually
//! closed, that the connection slot it was holding actually comes back, that a
//! client which is doing the right thing is left alone, and that an operator can
//! see which of the two happened. Those are claims about a running process and
//! they are made here, against `serve::run` on an ephemeral port with the
//! hand-written client every other socket suite uses.
//!
//! The deadlines are configured down to a few hundred milliseconds. That is the
//! one liberty taken: the durations are configuration, so a suite that used the
//! shipped ten seconds and five minutes would be a suite nobody runs. Everything
//! else is the shipped path, including the frame the client is sent on the way
//! out and the counters the relay increments.
//!
//! Real elapsed time rather than `tokio::time::pause`, because the relay is
//! running in tasks of its own and pausing the clock under it would freeze the
//! process being tested rather than the test. The waits are therefore sized so
//! that a slow machine cannot make them flaky: every "still open" assertion runs
//! well past the deadline it is claiming did not fire, and every "was closed"
//! assertion is bounded by a timeout an order of magnitude past the deadline it
//! is waiting for.

mod support;

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use wealdrelay::deadline::Expiry;
use wealdrelay::frame::{ErrorCode, Frame};
use wealdrelay::health::Clock;

use support::{config_for, make_group, Client, Running, Scratch};

const CLOCK: u64 = 1_700_000_000_000;

/// Short enough that the suite is quick, long enough that an honest client on a
/// loaded machine finishes its handshake well inside it.
const SHORT: Duration = Duration::from_millis(600);
/// A deadline nothing in a test should ever reach.
const NEVER: Duration = Duration::from_secs(600);

/// How long a test waits for a close it is certain is coming.
///
/// Deliberately far above any deadline this suite sets, because it is not
/// measuring one: it is the point at which "the relay never closed the
/// connection" stops being a slow machine and starts being a defect. It was
/// `SHORT * 20`, twelve seconds, and the 0.1.10 release runner blew through it on
/// a stalled scheduler while the relay behaved correctly. Two minutes is still an
/// order of magnitude below `NEVER`, so the idle deadline cannot be what fires
/// inside it.
const PATIENCE: Duration = Duration::from_secs(120);

/// What arrived on the wire, at the WebSocket framing layer rather than the
/// protocol one.
///
/// The shared harness's `recv` deliberately swallows pings and pongs, because
/// every other suite is about frames and a stray pong reported as a closed
/// connection would fail thirty tests for the wrong reason. This suite is about
/// exactly those control frames, so it reads them itself: a ping is the liveness
/// exchange under test, and whether the client answers it is the difference
/// between the two idle-deadline cases below.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    /// A ping arrived and this client answered it, as a conforming client's
    /// transport does without its application being involved.
    AnsweredPing,
    /// A ping arrived and this client deliberately said nothing.
    IgnoredPing,
    Data(Vec<u8>),
    Closed,
    /// Nothing arrived inside the window, which for a "still open" assertion is
    /// the passing outcome.
    Quiet,
}

async fn read_exactly(client: &mut Client, wanted: usize) -> Option<Vec<u8>> {
    while client.buffer.len() < wanted {
        let mut chunk = [0u8; 4096];
        let read = client.stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        client.buffer.extend_from_slice(&chunk[..read]);
    }
    Some(client.buffer.drain(..wanted).collect())
}

/// One WebSocket frame, header and all. A server never masks, so there is no
/// mask key to skip.
async fn read_frame(client: &mut Client) -> Option<(u8, Vec<u8>)> {
    let header = read_exactly(client, 2).await?;
    let opcode = header[0] & 0x0f;
    let length = match header[1] & 0x7f {
        126 => {
            let bytes = read_exactly(client, 2).await?;
            u16::from_be_bytes([bytes[0], bytes[1]]) as usize
        }
        127 => {
            let bytes = read_exactly(client, 8).await?;
            let mut wide = [0u8; 8];
            wide.copy_from_slice(&bytes);
            u64::from_be_bytes(wide) as usize
        }
        small => small as usize,
    };
    let payload = read_exactly(client, length).await?;
    Some((opcode, payload))
}

/// Wait up to `within` for one frame, answering a ping if `answer_pings`.
async fn watch(client: &mut Client, within: Duration, answer_pings: bool) -> Seen {
    match tokio::time::timeout(within, read_frame(client)).await {
        Err(_) => Seen::Quiet,
        Ok(None) => Seen::Closed,
        Ok(Some((0x8, _))) => Seen::Closed,
        Ok(Some((0x9, payload))) => {
            if answer_pings {
                client.send_opcode(0xa, &payload).await;
                Seen::AnsweredPing
            } else {
                Seen::IgnoredPing
            }
        }
        Ok(Some((_, payload))) => Seen::Data(payload),
    }
}

/// Read until the socket closes, collecting what the relay said on the way out.
///
/// The claim being made is `operations.md`'s: a client never gets a dropped
/// connection without a frame, because it cannot otherwise tell a decision the
/// relay made from a network that failed.
async fn drain_to_close(client: &mut Client, within: Duration, answer_pings: bool) -> Vec<Frame> {
    let deadline = Instant::now() + within;
    let mut frames = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(!left.is_zero(), "the relay never closed the connection");
        match watch(client, left, answer_pings).await {
            Seen::Closed => return frames,
            Seen::Data(payload) => {
                frames.push(Frame::decode(&payload).expect("the relay sent a frame"))
            }
            Seen::Quiet => panic!("the relay never closed the connection"),
            Seen::AnsweredPing | Seen::IgnoredPing => {}
        }
    }
}

/// The frame a deadline close sends: `quota/rate_limited`, carrying the interval.
fn assert_deadline_refusal(frames: &[Frame]) {
    let error = frames
        .iter()
        .find_map(|frame| match frame {
            Frame::Error(error) => Some(error),
            _ => None,
        })
        .unwrap_or_else(|| panic!("the relay closed without a frame, got {frames:?}"));
    assert_eq!(error.code, ErrorCode::RateLimited);
    assert!(
        error.retry_after.is_some(),
        "a client told to come back later is told how much later"
    );
    // Never anything derived from the peer. The close is about a clock.
    assert_eq!(error.detail, None);
}

/// A relay whose two deadlines are set explicitly.
///
/// Built by resolving the ordinary integration configuration and then setting the
/// two fields, rather than by a bespoke `Values` map, so this suite inherits every
/// other setting the shipped configuration resolves and cannot drift from it.
async fn relay_with(
    scratch: &Scratch,
    blobs: &std::path::Path,
    handshake: Duration,
    idle: Duration,
) -> Running {
    let mut config = config_for(scratch, blobs);
    config.handshake_timeout_ms = handshake.as_millis() as u64;
    config.idle_timeout_ms = idle.as_millis() as u64;
    Running::start(config, Clock::Fixed(CLOCK)).await
}

// MARK: The handshake deadline

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_that_never_authenticates_is_closed_at_the_handshake_deadline() {
    let scratch = Scratch::new("deadline_handshake").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = relay_with(&scratch, blobs.path(), SHORT, NEVER).await;

    // The attack, exactly: upgrade, hold the slot, send nothing at all. Not one
    // byte is written to this socket after the HTTP handshake.
    let opened = Instant::now();
    let mut client = Client::connect(relay.address).await;
    assert_eq!(
        relay.state.open_connections(),
        1,
        "the slot is taken at the upgrade, which is what makes the deadline necessary"
    );

    let frames = drain_to_close(&mut client, PATIENCE, false).await;
    let took = opened.elapsed();

    assert_deadline_refusal(&frames);
    // Not before the deadline, which would refuse honest clients. This half is a
    // real bound and stays: a relay that closed early would fail it on any machine.
    assert!(
        took >= SHORT,
        "closed after {took:?}, before the {SHORT:?} deadline it was given"
    );
    // The other half of the old assertion, that it was *this* deadline and not
    // something else eventually, was a wall-clock ceiling of twelve seconds. It is
    // gone, because the counters below answer the same question exactly rather than
    // by inference: `deadline_closes(Handshake)` is 1 and `Idle` is 0, so the close
    // is attributed to the deadline under test by the relay itself. A ceiling on
    // elapsed time was measuring the runner, and on the 0.1.10 release run it
    // failed while the relay did precisely the right thing.

    // The slot comes back. This is the whole point: a deadline that closed the
    // socket and leaked its slot would leave the relay just as unreachable.
    let mut settled = false;
    for _ in 0..100 {
        if relay.state.open_connections() == 0 {
            settled = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(settled, "the connection slot was never given back");

    // And the operator can tell this from a crash, which is the only reason the
    // counters exist.
    assert_eq!(relay.state.deadline_closes(Expiry::Handshake), 1);
    assert_eq!(relay.state.deadline_closes(Expiry::Idle), 0);
    let stats = relay.state.readiness().await.call_stats;
    assert_eq!(stats.connections_closed_handshake_deadline, 1);
    assert_eq!(stats.connections_closed_idle_deadline, 0);
    assert_eq!(
        stats.connections_refused, 0,
        "a deadline is not a refusal and must not be counted as one"
    );

    relay.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn every_slot_a_silent_attacker_took_is_returned_and_the_relay_serves_a_real_client() {
    let scratch = Scratch::new("deadline_slots").await;
    let blobs = tempfile::tempdir().unwrap();
    let mut config = config_for(&scratch, blobs.path());
    // Longer than `SHORT` elsewhere in this suite, because four sockets have to
    // be opened and the table observed full *before* the first one expires, and
    // a deadline tight enough to be quick is one a loaded machine can outrun.
    // Nothing about the claim depends on the number.
    let handshake = SHORT * 5;
    config.handshake_timeout_ms = handshake.as_millis() as u64;
    config.idle_timeout_ms = NEVER.as_millis() as u64;
    // A ceiling small enough to fill, which is the attack at scale in miniature:
    // with no handshake deadline these four sockets are the whole relay, forever,
    // for the cost of four file descriptors.
    config.max_connections = wealdrelay::config::Limit::Of(4);
    let relay = Running::start(config, Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x41).await;

    // Opened concurrently rather than one after another. The harness client's
    // upgrade is not fast enough on every machine for four serial connections to
    // land inside any deadline short enough to be worth waiting for, and an
    // attacker opening sockets does not take turns either.
    let mut opening = Vec::new();
    for _ in 0..4 {
        let address = relay.address;
        opening.push(tokio::spawn(async move { Client::connect(address).await }));
    }
    let mut silent = Vec::new();
    for handle in opening {
        silent.push(handle.await.expect("a client connected"));
    }
    assert_eq!(relay.state.open_connections(), 4, "the relay is full");

    // A real device, arriving while the table is full, is refused before the
    // upgrade. That is the pre-existing cap behaving correctly and it is the
    // denial of service being fixed.
    let refused = tokio::net::TcpStream::connect(relay.address).await.unwrap();
    let mut refused = refused;
    refused
        .write_all(
            format!(
                "GET /relay HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
                 Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n\r\n",
                relay.address
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), refused.read_to_end(&mut response)).await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 503"),
        "a full relay refuses before the upgrade"
    );

    // The deadlines fire, and the relay comes back on its own with nobody
    // restarting anything.
    for client in silent.iter_mut() {
        let _ = drain_to_close(client, PATIENCE, false).await;
    }
    let mut settled = false;
    for _ in 0..200 {
        if relay.state.open_connections() == 0 {
            settled = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(settled, "the relay never recovered its connection table");
    assert_eq!(relay.state.deadline_closes(Expiry::Handshake), 4);

    // And the device that was locked out gets in, over the same relay process.
    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group], CLOCK).await;
    relay.shutdown().await;
}

// MARK: The negative cases, which are the ones that keep the deadlines honest

#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_authenticates_inside_the_window_is_left_alone() {
    let scratch = Scratch::new("deadline_authed").await;
    let blobs = tempfile::tempdir().unwrap();
    // A handshake deadline that has long since passed by the end of this test,
    // and an idle deadline that has not. If authenticating did not stop the
    // handshake clock, this connection would be closed part way through.
    let relay = relay_with(&scratch, blobs.path(), SHORT, NEVER).await;
    let group = make_group(&relay.state, 0x42).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;

    // Well past the handshake deadline, doing nothing.
    tokio::time::sleep(SHORT * 4).await;
    assert_eq!(
        relay.state.deadline_closes(Expiry::Handshake),
        0,
        "an authenticated connection is not still being timed against the handshake"
    );
    assert_eq!(relay.state.open_connections(), 1);

    // Still a working session rather than merely an unclosed socket: it answers.
    ada.send_frame(&Frame::Sub {
        group: group.clone(),
        from_seq: 0,
    })
    .await;
    match ada.recv_frame().await {
        Frame::SubAck { group: acked, .. } => assert_eq!(acked, group),
        other => panic!("expected a SubAck, got {other:?}"),
    }

    assert_eq!(relay.state.deadline_closes(Expiry::Idle), 0);
    relay.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_still_working_through_its_handshake_is_not_cut_off_mid_challenge() {
    let scratch = Scratch::new("deadline_midway").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = relay_with(&scratch, blobs.path(), SHORT, NEVER).await;
    let group = make_group(&relay.state, 0x43).await;

    // `CONNECT`, then a pause inside the window, then `AUTH`. A real client on a
    // bad link looks like this, and a deadline that measured "time since the last
    // byte" rather than "time since the upgrade" would be indistinguishable here
    // while being useless against a peer that dribbles a byte a minute.
    let mut ada = Client::connect(relay.address).await;
    let challenge = ada.handshake_to_challenge(vec![group.clone()], CLOCK).await;
    tokio::time::sleep(SHORT / 2).await;

    let device = support::default_device();
    use ed25519_dalek::Signer as _;
    ada.send_frame(&Frame::Auth {
        device_key: device.verifying_key().to_bytes().to_vec(),
        signature: device.sign(&challenge).to_bytes().to_vec(),
    })
    .await;
    match ada.recv_frame().await {
        Frame::AuthAck { .. } => {}
        other => panic!("expected an AuthAck, got {other:?}"),
    }

    assert_eq!(relay.state.deadline_closes(Expiry::Handshake), 0);
    relay.shutdown().await;
}

// MARK: The idle deadline and its liveness exchange

#[tokio::test(flavor = "multi_thread")]
async fn a_quiet_client_that_answers_the_liveness_ping_keeps_its_connection() {
    let scratch = Scratch::new("deadline_quiet").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = relay_with(&scratch, blobs.path(), NEVER, SHORT).await;
    let group = make_group(&relay.state, 0x44).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;

    // Several idle intervals of complete application-level silence, answering
    // pings and nothing else. This is a member with the app open and nothing to
    // say, which is the ordinary state of a workspace and must not cost them
    // their connection.
    let mut pings = 0;
    let until = Instant::now() + SHORT * 5;
    while Instant::now() < until {
        match watch(&mut ada, Duration::from_millis(100), true).await {
            Seen::AnsweredPing => pings += 1,
            Seen::Closed => panic!("a live client was closed for being quiet"),
            Seen::Quiet => {}
            other => panic!("unexpected traffic on an idle connection: {other:?}"),
        }
    }

    assert!(
        pings >= 1,
        "the relay never asked whether the peer was there, so the deadline is not being enforced"
    );
    assert_eq!(
        relay.state.deadline_closes(Expiry::Idle),
        0,
        "answering the probe is what keeps the connection, and it did"
    );
    assert_eq!(relay.state.open_connections(), 1);

    // And it is still a session rather than a socket.
    ada.send_frame(&Frame::Sub {
        group: group.clone(),
        from_seq: 0,
    })
    .await;
    match ada.recv_frame().await {
        Frame::SubAck { .. } => {}
        other => panic!("expected a SubAck, got {other:?}"),
    }

    relay.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_authenticated_peer_that_stops_answering_is_closed_on_the_idle_deadline() {
    let scratch = Scratch::new("deadline_idle").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = relay_with(&scratch, blobs.path(), NEVER, SHORT).await;
    let group = make_group(&relay.state, 0x45).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group], CLOCK).await;

    // The wedged peer: its socket is open, its kernel is acknowledging segments,
    // and its application is never going to speak again. TCP cannot tell this
    // from the test above; the liveness exchange can, and that difference is the
    // reason the exchange exists.
    let frames = drain_to_close(&mut ada, PATIENCE, false).await;
    assert_deadline_refusal(&frames);

    assert_eq!(relay.state.deadline_closes(Expiry::Idle), 1);
    assert_eq!(
        relay.state.deadline_closes(Expiry::Handshake),
        0,
        "an authenticated connection never expires against the handshake deadline"
    );
    let stats = relay.state.readiness().await.call_stats;
    assert_eq!(stats.connections_closed_idle_deadline, 1);
    assert_eq!(stats.connections_closed_handshake_deadline, 0);

    relay.shutdown().await;
}
