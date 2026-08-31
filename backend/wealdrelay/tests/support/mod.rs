// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The shared integration harness: a scratch database, a running relay, and a
//! hand-written WebSocket client.
//!
//! Extracted from `tests/ws.rs` when step 5 added a second integration suite over
//! the same wire. One harness rather than two, because two would drift and the
//! whole value of a hand-rolled client is that it speaks the protocol a real client
//! has to speak rather than the relay's own encoder talking to itself.
//!
//! Nothing here is a mock. The database is the harness Postgres from
//! `scripts/weald-stack`, the relay is `serve::run` on ephemeral ports, and the
//! sockets are real WebSockets with real masking and a real close handshake.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use sqlx::{Connection, Executor as _, PgConnection};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use wealdrelay::access::AccessSet;
use wealdrelay::config::{keys, Config, Values};
use wealdrelay::envelope::{content_hash, Encryption, Envelope};
use wealdrelay::frame::{Frame, PROTOCOL_VERSION};
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::serve;

// MARK: The harness

pub fn postgres_port() -> String {
    std::env::var("WEALD_STACK_PG_PORT").unwrap_or_else(|_| "54032".to_string())
}

pub fn admin_url() -> String {
    format!(
        "postgres://weald:weald@127.0.0.1:{}/weald_relay",
        postgres_port()
    )
}

/// A database of its own per test, because `testing.md` forbids two tests sharing
/// a database name or a port.
pub struct Scratch {
    pub name: String,
    pub url: String,
}

impl Scratch {
    pub async fn new(label: &str) -> Self {
        // The label reaches Postgres as part of an identifier, and an identifier
        // is not a string: `recon-over-queue` is a subtraction to the parser and
        // every statement naming it is a syntax error before it is anything else.
        // Normalised here rather than at the call sites, because a caller has no
        // reason to know that and the failure it produces names the harness
        // rather than the label that caused it.
        let label: String = label
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let name = format!("weald_step4_ws_{label}_{}", std::process::id());
        let mut admin = PgConnection::connect(&admin_url()).await.expect(
            "Postgres is not reachable. This is an integration test and it does not skip: \
             run `scripts/weald-stack up`.",
        );
        admin
            .execute(format!("drop database if exists {name}").as_str())
            .await
            .expect("drop a leftover");
        admin
            .execute(format!("create database {name}").as_str())
            .await
            .expect("create the scratch database");
        let url = format!(
            "postgres://weald:weald@127.0.0.1:{}/{name}",
            postgres_port()
        );
        Self { name, url }
    }

    pub async fn drop_database(&self) {
        if let Ok(mut admin) = PgConnection::connect(&admin_url()).await {
            let _ = admin
                .execute(format!("drop database if exists {} with (force)", self.name).as_str())
                .await;
        }
    }
}

/// The deadlines every suite runs with, and why they are not the production ones.
///
/// `WEALD_RELAY_HANDSHAKE_TIMEOUT_MS` defaults to ten seconds, which is right for a
/// relay on the internet and wrong for a test binary sharing a runner with the
/// harness containers and every other suite. On the 0.1.9 release runner a
/// handshake that would normally complete in milliseconds was reaped mid-`CONNECT`
/// and the client read `quota/rate_limited` where it expected a `ConnectAck`,
/// failing a test about device revocation that has nothing to do with deadlines.
/// A single test file took 223 seconds of wall clock in that run, so ten seconds
/// of scheduling delay is not an outlandish thing to hit.
///
/// The two deadlines want different numbers here, and treating them as one
/// number is what broke 0.1.12.
///
/// The handshake deadline is two minutes. Ten was the first attempt and it turned
/// a fast failure into a slow one: a socket that wedges before authenticating
/// holds the suite for the length of the deadline, and the 0.1.11 run sat on
/// `cargo test` for nearly two hours instead of failing in twenty minutes. Two
/// minutes is still two orders of magnitude above what a handshake takes on an
/// idle machine, and it keeps a hang cheap to diagnose.
///
/// The idle deadline is an hour, and briefly setting it to two minutes alongside
/// the handshake one was a straight mistake: it is *shorter* than the production
/// default of five minutes, so the harness reaped established sockets sooner than
/// a real relay would. `calls_socket.rs` holds five participants open across a
/// file that took 393 seconds on the 0.1.12 runner, and the sixth-participant
/// refusal came back as a deadline close (`RateLimited` with no detail) instead
/// of the call ceiling (`RateLimited` carrying 5). A test asserting a refusal
/// reason got a different refusal, which is worse than a timeout: it looks like a
/// logic failure. Nothing in these suites is testing what happens to a
/// long-established idle socket, so the clock comes off it.
///
/// Nothing is weakened by it: the deadlines are proven by
/// `tests/deadline_socket.rs`, which sets its own short ones deliberately, and by
/// `tests/deadline_unit.rs`, which resolves configuration through its own helper
/// and still asserts the production defaults are what an operator gets. What this
/// removes is a clock running underneath thirty suites that are testing something
/// else.
fn deadline_pairs() -> [(&'static str, String); 2] {
    [
        (keys::HANDSHAKE_TIMEOUT_MS, "120000".to_string()),
        (keys::IDLE_TIMEOUT_MS, "3600000".to_string()),
    ]
}

pub fn config_for(scratch: &Scratch, blobs: &std::path::Path) -> Config {
    Config::resolve(&Values::from_pairs(
        [
            (keys::HOSTNAME, "localhost".to_string()),
            (keys::DATABASE_URL, scratch.url.clone()),
            (keys::STORAGE_URL, format!("file://{}", blobs.display())),
            (keys::LISTEN, "127.0.0.1:0".to_string()),
            (keys::OBSERVABILITY_LISTEN, "127.0.0.1:0".to_string()),
            (keys::RELEASE_CHECK, "off".to_string()),
        ]
        .into_iter()
        .chain(deadline_pairs()),
    ))
    .expect("the integration configuration resolves")
}

/// The same, with the call path on and sized.
///
/// A separate helper rather than a flag on `config_for`, because
/// `WEALD_RELAY_CALLS` is off by default and every suite that is not about calls
/// should be running against the default posture. A shared helper that quietly
/// turned the feature on would mean thirty suites exercising a path none of them
/// is testing.
///
/// `max_calls` is a parameter because the ceiling is what several of the refusals
/// are about, and a test that wanted to prove one would otherwise have to open
/// the configured number of calls first.
pub fn config_for_calls(scratch: &Scratch, blobs: &std::path::Path, max_calls: u32) -> Config {
    Config::resolve(&Values::from_pairs(
        [
            (keys::HOSTNAME, "localhost".to_string()),
            (keys::DATABASE_URL, scratch.url.clone()),
            (keys::STORAGE_URL, format!("file://{}", blobs.display())),
            (keys::LISTEN, "127.0.0.1:0".to_string()),
            (keys::OBSERVABILITY_LISTEN, "127.0.0.1:0".to_string()),
            (keys::RELEASE_CHECK, "off".to_string()),
            (keys::CALLS, "on".to_string()),
            (keys::MAX_CONCURRENT_CALLS, max_calls.to_string()),
        ]
        .into_iter()
        .chain(deadline_pairs()),
    ))
    .expect("the call configuration resolves")
}

/// The call path explicitly off.
///
/// `WEALD_RELAY_CALLS` is `on` by default, so a suite that is about the refusals an
/// operator who turned calls off owes its clients has to say so: `config_for` used
/// to be that posture and is not any more.
pub fn config_for_calls_off(scratch: &Scratch, blobs: &std::path::Path) -> Config {
    Config::resolve(&Values::from_pairs(
        [
            (keys::HOSTNAME, "localhost".to_string()),
            (keys::DATABASE_URL, scratch.url.clone()),
            (keys::STORAGE_URL, format!("file://{}", blobs.display())),
            (keys::LISTEN, "127.0.0.1:0".to_string()),
            (keys::OBSERVABILITY_LISTEN, "127.0.0.1:0".to_string()),
            (keys::RELEASE_CHECK, "off".to_string()),
            (keys::CALLS, "off".to_string()),
        ]
        .into_iter()
        .chain(deadline_pairs()),
    ))
    .expect("the calls-off configuration resolves")
}

/// A relay, running, with the address a client connects to.
pub struct Running {
    pub address: std::net::SocketAddr,
    pub state: Arc<RelayState>,
    pub stop: Option<tokio::sync::oneshot::Sender<()>>,
    pub task: tokio::task::JoinHandle<Result<(), serve::ServeError>>,
}

impl Running {
    pub async fn start(config: Config, clock: Clock) -> Self {
        Self::start_with(config, clock, |_| {}).await
    }

    /// The same, with one hook into the prepared state before it is shared.
    ///
    /// Step 9 needs it: `media` behaves differently against an S3-compatible
    /// bucket than against the filesystem backend (a real presigned request
    /// rather than a token over the relay's own listener), and pointing a relay
    /// at the harness MinIO means handing it a client built for that endpoint
    /// rather than one built from the ambient AWS chain. Nothing is faked here:
    /// the store the hook installs is the same `storage::Store` `storage::open`
    /// returns, talking to the same MinIO the storage contract suite uses.
    pub async fn start_with(
        config: Config,
        clock: Clock,
        mutate: impl FnOnce(&mut RelayState),
    ) -> Self {
        let mut state = serve::prepare(config).await.expect("prepare the relay");
        state.clock = clock;
        mutate(&mut state);
        let state = Arc::new(state);
        let (public, private) = serve::bind(&state).await.expect("bind");
        let address = public.local_addr().expect("a public address");
        let (stop, wait) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(serve::run(
            Arc::clone(&state),
            public,
            private,
            async move {
                let _ = wait.await;
            },
        ));
        Self {
            address,
            state,
            stop: Some(stop),
            task,
        }
    }

    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = self.task.await;
    }
}

// MARK: A client, written the way a client has to be

/// A WebSocket client over a raw TCP socket.
///
/// Hand rolled deliberately. A client crate would be fine for convenience, but
/// the masking rule, the frame header and the close handshake are the parts of the
/// protocol a real client has to get right, and a test that outsourced them would
/// not notice a relay that only worked with one library.
pub struct Client {
    pub stream: TcpStream,
    /// Bytes read from the socket and not yet consumed as a message.
    pub buffer: Vec<u8>,
    /// Ping payloads this client owes a pong for, oldest first.
    ///
    /// The relay's idle deadline is application level and answered at the
    /// transport level: after `WEALD_RELAY_IDLE_TIMEOUT_MS` of hearing nothing
    /// from a peer it sends a liveness ping and closes the connection if nothing
    /// comes back inside the probe window (`src/deadline.rs`, `Next::Probe`).
    /// `last_seen_ms` counts "a ping, a pong, a close and a frame" alike, so any
    /// answer keeps the socket, and a client that answers none is by definition
    /// the wedged peer that deadline exists to remove.
    ///
    /// This harness consumed a ping and replied with nothing, so **every test
    /// client here was a wedged client after five idle minutes**. It never
    /// showed up because no test was quiet for that long, until the 24-hour call
    /// soak: its callee only ever listens, so it was probed at five minutes,
    /// answered nothing, and was closed, and `recv_frame`'s expect turned that
    /// into a panic in a spawned task two minutes into a run that would then have
    /// taken a day to report. The gate could never have passed.
    ///
    /// Recorded here rather than answered in `take_message` because that method
    /// is synchronous and a pong is a write. `recv` drains this before it waits
    /// on the socket again, which is the only point where both are possible.
    pending_pongs: Vec<Vec<u8>>,
}

/// Loopback addresses this host will actually let a socket bind, `want` of them at
/// most and `least` of them at minimum, 127.0.0.1 first and then aliases.
///
/// BR-032 is about sockets arriving from *distinct sources*, so which alias block
/// a host happens to carry is not part of any claim. Hard coding `127.0.0.x` made
/// relay proofs a property of one machine's `lo0` alias set, and a host aliased to
/// a different block failed tests about the relay. Panics naming the fix when the
/// host has none, because skipping would turn an adversarial proof green silently.
pub fn distinct_loopback_sources(want: usize, least: usize) -> Vec<std::net::IpAddr> {
    const CANDIDATES: [[u8; 4]; 9] = [
        [127, 0, 0, 2],
        [127, 0, 0, 3],
        [127, 0, 0, 4],
        [127, 0, 0, 5],
        [127, 0, 2, 2],
        [127, 0, 2, 3],
        [127, 0, 2, 4],
        [127, 0, 2, 5],
        [127, 0, 1, 2],
    ];
    let mut found = vec![std::net::IpAddr::from([127, 0, 0, 1])];
    for octets in CANDIDATES {
        if found.len() >= want {
            break;
        }
        let address = std::net::IpAddr::from(octets);
        if std::net::TcpListener::bind(std::net::SocketAddr::new(address, 0)).is_ok() {
            found.push(address);
        }
    }
    assert!(
        found.len() >= least,
        "this host offers {} bindable loopback source(s) and the proof needs {least}. \
         Alias one: sudo ifconfig lo0 alias 127.0.0.2 up (it does not survive a \
         reboot; `scripts/weald-stack up` reports the set).",
        found.len()
    );
    found.truncate(want);
    found
}

impl Client {
    pub async fn connect(address: std::net::SocketAddr) -> Self {
        Self::upgrade(TcpStream::connect(address).await.expect("connect")).await
    }

    /// Connect from a chosen loopback source.
    ///
    /// BR-032 caps how much of a finite connection table one *source* may hold
    /// before it authenticates, so a test that needs several unauthenticated
    /// sockets open at once needs several sources: four connections from one
    /// address is the attack that control exists to refuse, not a full table.
    /// Anything above `127.0.0.1` needs an alias on macOS and none on Linux
    /// (`scripts/weald-stack up` reports the line).
    pub async fn connect_from(address: std::net::SocketAddr, source: std::net::IpAddr) -> Self {
        let socket = match source {
            std::net::IpAddr::V4(_) => tokio::net::TcpSocket::new_v4().expect("an IPv4 socket"),
            std::net::IpAddr::V6(_) => tokio::net::TcpSocket::new_v6().expect("an IPv6 socket"),
        };
        socket
            .bind(std::net::SocketAddr::new(source, 0))
            .unwrap_or_else(|error| {
                panic!(
                    "bind the chosen source {source}: {error}\n\
                     On macOS every loopback address above 127.0.0.1 needs an alias:\n\
                     \x20   sudo ifconfig lo0 alias {source} up\n\
                     It does not survive a reboot. `scripts/weald-stack up` reports the set."
                )
            });
        Self::upgrade(socket.connect(address).await.expect("connect")).await
    }

    /// A client whose kernel receive buffer is tiny and which resets rather than
    /// closes.
    ///
    /// The small buffer is so that a client which stops reading blocks the relay's
    /// writer within a few hundred frames rather than after however many the
    /// operating system felt like buffering. `SO_LINGER` at zero is so that dropping
    /// the socket sends a reset, which is what a killed client process looks like
    /// from the relay's side, rather than the polite close a well behaved client
    /// sends. Those two settings are the only thing unusual about it.
    ///
    /// `set_linger` is deprecated because a non-zero linger blocks the thread on
    /// drop. Zero is the case that does not: it discards the send buffer and resets
    /// immediately, which is the whole reason it is here.
    #[allow(deprecated)]
    pub async fn connect_by_a_client_that_will_die_badly(address: std::net::SocketAddr) -> Self {
        let socket = tokio::net::TcpSocket::new_v4().expect("a socket");
        socket
            .set_recv_buffer_size(1024)
            .expect("shrink the receive buffer");
        let stream = socket.connect(address).await.expect("connect");
        stream
            .set_linger(Some(Duration::ZERO))
            .expect("reset instead of closing");
        Self::upgrade(stream).await
    }

    pub async fn upgrade(mut stream: TcpStream) -> Self {
        // The handshake. A fixed key, because the server's accept value is a
        // function of it and nothing in this test depends on it being random.
        let host = stream.peer_addr().expect("a peer address");
        let request = format!(
            "GET /relay HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("send the handshake");

        // Read to the end of the headers, and no further: anything after them is a
        // frame this client still has to consume.
        let mut buffer = Vec::new();
        let mut byte = [0u8; 1];
        while !buffer.ends_with(b"\r\n\r\n") {
            let read = stream.read(&mut byte).await.expect("read the response");
            assert_eq!(read, 1, "the relay closed during the handshake");
            buffer.push(byte[0]);
        }
        let response = String::from_utf8_lossy(&buffer);
        assert!(
            response.starts_with("HTTP/1.1 101"),
            "the relay refused the upgrade: {response}"
        );
        Self {
            stream,
            buffer: Vec::new(),
            pending_pongs: Vec::new(),
        }
    }

    /// Send one binary message. Masked, because a client that did not mask would be
    /// closed by any conforming server, and the relay is one.
    pub async fn send(&mut self, payload: &[u8]) {
        self.send_opcode(0x2, payload).await;
    }

    /// Send one message with an opcode of the caller's choosing, so a test can put a
    /// real ping, pong or close on the wire rather than a data frame that stands in
    /// for one.
    pub async fn send_opcode(&mut self, opcode: u8, payload: &[u8]) {
        let mut frame = vec![0x80 | opcode];
        let mask = [0x37, 0xfa, 0x21, 0x3d];
        match payload.len() {
            length if length < 126 => frame.push(0x80 | length as u8),
            length if length <= u16::MAX as usize => {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&(length as u16).to_be_bytes());
            }
            length => {
                frame.push(0x80 | 127);
                frame.extend_from_slice(&(length as u64).to_be_bytes());
            }
        }
        frame.extend_from_slice(&mask);
        for (index, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask[index % 4]);
        }
        self.stream.write_all(&frame).await.expect("send a frame");
    }

    pub async fn send_frame(&mut self, frame: &Frame) {
        self.send(&frame.encode()).await;
    }

    /// Read one message payload, or `None` if the relay closed.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        loop {
            if let Some(message) = self.take_message() {
                // Owed pongs go out before the message is handed up, not after:
                // a caller that stops reading once it has what it wanted would
                // otherwise leave the answer unsent for ever, which is the exact
                // state that gets a connection closed.
                self.answer_pings().await;
                return message;
            }
            self.answer_pings().await;
            let mut chunk = [0u8; 8192];
            let read = self.stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                return None;
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    /// A whole message from the buffer, if one is there. The outer option is
    /// "enough bytes"; the inner is "a data frame rather than a close".
    pub fn take_message(&mut self) -> Option<Option<Vec<u8>>> {
        if self.buffer.len() < 2 {
            return None;
        }
        let opcode = self.buffer[0] & 0x0f;
        let indicator = self.buffer[1] & 0x7f;
        // A server never masks, so there is no mask key to skip.
        let (length, header) = match indicator {
            126 => {
                if self.buffer.len() < 4 {
                    return None;
                }
                (
                    u16::from_be_bytes([self.buffer[2], self.buffer[3]]) as usize,
                    4,
                )
            }
            127 => {
                if self.buffer.len() < 10 {
                    return None;
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&self.buffer[2..10]);
                (u64::from_be_bytes(bytes) as usize, 10)
            }
            small => (small as usize, 2),
        };
        if self.buffer.len() < header + length {
            return None;
        }
        let payload = self.buffer[header..header + length].to_vec();
        self.buffer.drain(..header + length);
        // 0x8 is close. 0x9 and 0xa are ping and pong, which are the transport's:
        // consumed and skipped, and if nothing whole is left behind them the answer
        // is "not enough bytes yet" rather than "closed". Reporting a closed
        // connection because a pong arrived on its own would make every test that
        // provokes one fail for the wrong reason.
        match opcode {
            0x8 => Some(None),
            // A ping is owed a pong carrying the same payload, and a pong is
            // owed nothing. Both are still evidence the peer is there, so both
            // are skipped past to whatever data frame follows.
            0x9 => {
                self.pending_pongs.push(payload);
                self.take_message()
            }
            0xa => self.take_message(),
            _ => Some(Some(payload)),
        }
    }

    /// Answer every ping this client has been sent and not yet replied to.
    ///
    /// Public so a test that wants to prove the deadline *fires* can decline to
    /// call it: silence is now something a test chooses rather than something
    /// the harness does to every test by accident.
    pub async fn answer_pings(&mut self) {
        if self.pending_pongs.is_empty() {
            return;
        }
        for payload in std::mem::take(&mut self.pending_pongs) {
            self.send_opcode(0xa, &payload).await;
        }
    }

    /// One decoded frame, or a failure naming what arrived instead.
    pub async fn recv_frame(&mut self) -> Frame {
        let payload = self.recv().await.expect("the relay closed unexpectedly");
        Frame::decode(&payload).expect("the relay sent something that is not a frame")
    }

    /// Walk the handshake to a Ready session, and return the challenge the relay
    /// issued so a caller can check it was used.
    ///
    /// Signed by ``default_device()``, which is the device every suite's genesis
    /// access set names. Step 6 made `AUTH` a real check: the signature is verified
    /// against the challenge this connection issued, and the key is tested against
    /// the workspace's access set, so a handshake with a made-up key and a made-up
    /// signature is now a closed socket rather than an `AuthAck`.
    pub async fn handshake(&mut self, groups: Vec<Vec<u8>>, client_clock: u64) -> Vec<u8> {
        self.handshake_as(&default_device(), groups, client_clock)
            .await
    }

    /// The same, as a named device.
    pub async fn handshake_as(
        &mut self,
        key: &SigningKey,
        groups: Vec<Vec<u8>>,
        client_clock: u64,
    ) -> Vec<u8> {
        self.handshake_as_version(key, groups, client_clock, PROTOCOL_VERSION)
            .await
    }

    /// The same, offering a stated maximum version.
    ///
    /// The whole of the version 1 client's side of the compatibility claim: it
    /// offers 1, the relay selects 1, and it never receives a frame version 2
    /// added.
    pub async fn handshake_as_version(
        &mut self,
        key: &SigningKey,
        groups: Vec<Vec<u8>>,
        client_clock: u64,
        offered: u16,
    ) -> Vec<u8> {
        let challenge = self
            .handshake_to_challenge_offering(groups, client_clock, offered)
            .await;
        self.send_frame(&Frame::Auth {
            device_key: key.verifying_key().to_bytes().to_vec(),
            signature: Signer::sign(key, &challenge).to_bytes().to_vec(),
        })
        .await;
        match self.recv_frame().await {
            Frame::AuthAck { .. } => {}
            other => panic!("expected an AuthAck, got {other:?}"),
        }
        challenge
    }

    /// `CONNECT` and stop at the challenge, for a caller that wants to answer it
    /// wrongly on purpose.
    pub async fn handshake_to_challenge(
        &mut self,
        groups: Vec<Vec<u8>>,
        client_clock: u64,
    ) -> Vec<u8> {
        self.handshake_to_challenge_offering(groups, client_clock, PROTOCOL_VERSION)
            .await
    }

    /// The same, offering a stated maximum version and asserting the selection.
    pub async fn handshake_to_challenge_offering(
        &mut self,
        groups: Vec<Vec<u8>>,
        client_clock: u64,
        offered: u16,
    ) -> Vec<u8> {
        self.send_frame(&Frame::Connect {
            version: offered,
            groups,
            sent_at: client_clock,
        })
        .await;
        match self.recv_frame().await {
            // `min(offered, the relay's maximum)`. A client that offers less is
            // served at what it offered, which is what makes a version 1 client keep
            // working against this build.
            Frame::ConnectAck { version, .. } => {
                assert_eq!(version, offered.min(PROTOCOL_VERSION))
            }
            other => panic!("expected a ConnectAck, got {other:?}"),
        }
        match self.recv_frame().await {
            Frame::AuthChallenge { challenge } => challenge,
            other => panic!("expected an AuthChallenge, got {other:?}"),
        }
    }
}

// MARK: Devices and the genesis access set

/// The device every suite connects as unless it says otherwise.
///
/// Fixed bytes rather than generated, so a failure reproduces and so the entry hash
/// in a dumped table is the same on every machine. It is a secret in no sense: it is
/// in a test file in a public repository, which is exactly why no production path
/// may ever accept a hard-coded key.
pub fn default_device() -> SigningKey {
    SigningKey::from_bytes(&[0x31; 32])
}

/// A second device, for the tests that need two.
pub fn other_device() -> SigningKey {
    SigningKey::from_bytes(&[0x32; 32])
}

pub fn device_from(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Publish a genesis access set naming these devices, straight into the database.
///
/// Seeded rather than sent over a socket, and the distinction matters. What the
/// socket path does is proven by its own tests in `tests/access.rs`, which drive
/// `ACCESS` frames end to end. Every *other* suite needs a workspace that admits its
/// client, and making forty tests walk a publication to get there would make the
/// access set the subject of every one of them.
pub async fn seed_access_set(state: &Arc<RelayState>, workspace: &str, devices: &[SigningKey]) {
    let pool = state.database.as_ref().expect("a database").pool();
    seed_access_set_directly(pool, workspace, devices).await;
}

/// The same, against a pool rather than a running relay's state.
///
/// The load harness needs it: its relay is a separate operating-system process,
/// so there is no `RelayState` to reach through, and seeding through a second
/// connection to the same database is exactly what an enrolment would do anyway.
pub async fn seed_access_set_directly(
    pool: &sqlx::PgPool,
    workspace: &str,
    devices: &[SigningKey],
) {
    let salt = wealdrelay::access::store::salt(pool, workspace)
        .await
        .expect("a workspace salt");
    let signer = devices.first().expect("at least one device").clone();
    let mut entries: Vec<Vec<u8>> = devices
        .iter()
        .map(|device| wealdrelay::access::entry_hash(&device.verifying_key().to_bytes(), &salt))
        .collect();
    // The recovery principal, which every set must have: `wire.md` requires
    // `recovery` to be non-empty and every recovery key to hash to an entry.
    let recovery = device_from(0x3f);
    entries.push(wealdrelay::access::entry_hash(
        &recovery.verifying_key().to_bytes(),
        &salt,
    ));
    entries.sort();
    entries.dedup();

    let mut set = AccessSet {
        workspace: vec![0u8; 32],
        version: 0,
        prev_hash: vec![0u8; 32],
        issued_at: 0,
        entries,
        authorizers: vec![signer.verifying_key().to_bytes().to_vec()],
        recovery: vec![recovery.verifying_key().to_bytes().to_vec()],
        quorum: None,
        pending: Vec::new(),
        signer: signer.verifying_key().to_bytes().to_vec(),
        sig: vec![0u8; 64],
    };
    set.sig = Signer::sign(&signer, &set.digest_input())
        .to_bytes()
        .to_vec();
    let body = set.encode();
    wealdrelay::access::store::publish(pool, workspace, &set, &body)
        .await
        .expect("the genesis access set is accepted");
}

/// The same as ``seed_access_set``, but with an explicit `authorizers` list
/// rather than the first device alone. Needed by the media step's threshold
/// tests, which have to exercise both the two-authorizer and the
/// sole-authorizer paths on purpose rather than getting whichever one
/// ``seed_access_set`` happens to produce.
pub async fn seed_access_set_with_authorizers(
    state: &Arc<RelayState>,
    workspace: &str,
    devices: &[SigningKey],
    authorizers: &[SigningKey],
) {
    let pool = state.database.as_ref().expect("a database").pool();
    let salt = wealdrelay::access::store::salt(pool, workspace)
        .await
        .expect("a workspace salt");
    let signer = devices.first().expect("at least one device").clone();
    let mut entries: Vec<Vec<u8>> = devices
        .iter()
        .map(|device| wealdrelay::access::entry_hash(&device.verifying_key().to_bytes(), &salt))
        .collect();
    let recovery = device_from(0x3f);
    entries.push(wealdrelay::access::entry_hash(
        &recovery.verifying_key().to_bytes(),
        &salt,
    ));
    entries.sort();
    entries.dedup();

    let mut set = AccessSet {
        workspace: vec![0u8; 32],
        version: 0,
        prev_hash: vec![0u8; 32],
        issued_at: 0,
        entries,
        authorizers: {
            // `AccessSet::check_shape` requires every principal list to be
            // sorted and unique, so the caller passes the keys it means and the
            // ordering is decided here rather than at each call site.
            let mut keys: Vec<Vec<u8>> = authorizers
                .iter()
                .map(|key| key.verifying_key().to_bytes().to_vec())
                .collect();
            keys.sort();
            keys.dedup();
            keys
        },
        recovery: vec![recovery.verifying_key().to_bytes().to_vec()],
        quorum: None,
        pending: Vec::new(),
        signer: signer.verifying_key().to_bytes().to_vec(),
        sig: vec![0u8; 64],
    };
    set.sig = Signer::sign(&signer, &set.digest_input())
        .to_bytes()
        .to_vec();
    let body = set.encode();
    wealdrelay::access::store::publish(pool, workspace, &set, &body)
        .await
        .expect("the genesis access set is accepted");
}

/// A group the relay knows about, in a workspace whose access set admits the two
/// devices every suite uses.
///
/// The access set half is seeded here rather than at each of the thirty call sites.
/// Step 6 made `enforce` the default in every environment, so a group in a workspace
/// with no set puts every connecting client into `Bootstrapping`, where the only
/// frame it may send is `ACCESS`. Before step 6 that state did not exist and this
/// helper did not need to know about it.
pub async fn make_group(state: &Arc<RelayState>, byte: u8) -> Vec<u8> {
    let pool = state.database.as_ref().expect("a database").pool();
    if wealdrelay::access::store::current(pool, "ws-step4")
        .await
        .expect("read the current access set")
        .prior
        .is_none()
    {
        seed_access_set(state, "ws-step4", &[default_device(), other_device()]).await;
    }
    let group = vec![byte; 32];
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(&group)
        .bind("ws-step4")
        .execute(pool)
        .await
        .expect("create the group");
    group
}

pub fn envelope_for(group: &[u8], body: &[u8]) -> Envelope {
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

/// Record one reconciliation exchange's cost, for step 5's artifact.
///
/// Written to a file rather than only asserted, because "the reconcile round count
/// against corpus size" is a gate deliverable and a number nobody wrote down is a
/// number the next step cannot compare against.
///
/// Two things here were wrong on the first attempt and are worth the comment:
///
/// - The path was relative, and `cargo test` runs with the crate directory as its
///   working directory, so the file landed in `backend/wealdrelay/target/` where the
///   gate does not look. It is now anchored at the repository root through
///   `CARGO_MANIFEST_DIR`, which is the only path that is the same wherever the test
///   is invoked from.
/// - It appended, so re-running the suite accumulated duplicate rows and the artifact
///   grew a history nobody asked for. One file per label, truncated, and the gate
///   concatenates them: tests run in parallel, so a single shared file cannot be
///   truncated safely by any of them.
pub fn record_recon_rounds(label: &str, corpus: usize, rounds: usize) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let directory = root.join("target").join("step-05");
    let _ = std::fs::create_dir_all(&directory);
    let slug: String = label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let _ = std::fs::write(
        directory.join(format!("recon-rounds-{slug}.txt")),
        format!("{label}\tcorpus {corpus}\trounds {rounds}\n"),
    );
}

/// Write one evidence file for a gate, under the directory that gate reads.
///
/// `WEALD_GATE_EVIDENCE_DIR` when the harness set it, which is what `--out`
/// redirects, and the checked-in default otherwise. The default matters: a suite
/// that hard-coded `build-evidence/step-NN` wrote into the wrong place under
/// `--out` and the artifact part then asserted on whatever an earlier local run
/// had left there, which is a false green that survives a clean checkout only by
/// accident.
pub fn record_evidence(step: &str, name: &str, contents: &str) {
    let directory = match std::env::var("WEALD_GATE_EVIDENCE_DIR") {
        Ok(dir) if !dir.is_empty() => std::path::PathBuf::from(dir),
        _ => std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("build-evidence")
            .join(step),
    };
    let _ = std::fs::create_dir_all(&directory);
    let _ = std::fs::write(directory.join(name), contents);
}

// MARK: Step 9, media blobs
//
// The retention chain is signed with the same `ed25519_dalek` keys every other
// suite uses and verified by the same `access::verify` the relay calls, so a
// fixture here is a record a client could actually have produced. Nothing below
// reimplements a signature: each helper fills the record's own `signing_bytes`
// into `Signer::sign` and puts the result where the relay reads it.

use wealdrelay::lifecycle::wire::DropBefore;
use wealdrelay::media::wire::{
    RetentionControl, RetentionDestruction, RetentionManifest, RetentionPolicy,
    RetentionResolution, Signature,
};

/// The configuration `config_for` builds, plus whatever else the caller needs.
/// Written as extra pairs rather than as a second builder so there is one place
/// the base configuration lives.
pub fn config_with(
    scratch: &Scratch,
    blobs: &std::path::Path,
    extra: impl IntoIterator<Item = (&'static str, String)>,
) -> Config {
    let mut pairs = vec![
        (keys::HOSTNAME, "localhost".to_string()),
        (keys::DATABASE_URL, scratch.url.clone()),
        (keys::STORAGE_URL, format!("file://{}", blobs.display())),
        (keys::LISTEN, "127.0.0.1:0".to_string()),
        (keys::OBSERVABILITY_LISTEN, "127.0.0.1:0".to_string()),
        (keys::RELEASE_CHECK, "off".to_string()),
    ];
    pairs.extend(deadline_pairs());
    // After the deadlines, so a caller that means to set a short one still can.
    pairs.extend(extra);
    Config::resolve(&Values::from_pairs(pairs)).expect("the integration configuration resolves")
}

/// A group in a named workspace, with an access set naming `devices` and
/// `authorizers`. `make_group` is the one-workspace convenience over this.
pub async fn make_group_in(
    state: &Arc<RelayState>,
    workspace: &str,
    byte: u8,
    devices: &[SigningKey],
    authorizers: &[SigningKey],
) -> Vec<u8> {
    let pool = state.database.as_ref().expect("a database").pool();
    if wealdrelay::access::store::current(pool, workspace)
        .await
        .expect("read the current access set")
        .prior
        .is_none()
    {
        seed_access_set_with_authorizers(state, workspace, devices, authorizers).await;
    }
    let group = vec![byte; 32];
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(&group)
        .bind(workspace)
        .execute(pool)
        .await
        .expect("create the group");
    group
}

/// Publish the next access set for a workspace, dropping the named devices.
///
/// The real offboarding path: `access::store::publish` judges it, applies it in one
/// transaction and returns the entries it removed, which is the list whose sockets
/// are closed and whose push registrations are deleted. A test that deleted the
/// registration directly would prove nothing about the transaction it has to be in.
pub async fn publish_set_without(
    state: &Arc<RelayState>,
    workspace: &str,
    signer: &SigningKey,
    dropped: &[SigningKey],
) {
    let pool = state.database.as_ref().expect("a database").pool();
    let salt = wealdrelay::access::store::salt(pool, workspace)
        .await
        .expect("a workspace salt");
    let prior = wealdrelay::access::store::current(pool, workspace)
        .await
        .expect("read the current access set")
        .prior
        .expect("a genesis set to build on");
    let going: Vec<Vec<u8>> = dropped
        .iter()
        .map(|device| wealdrelay::access::entry_hash(&device.verifying_key().to_bytes(), &salt))
        .collect();
    let mut next = AccessSet {
        workspace: vec![0u8; 32],
        version: prior.version + 1,
        prev_hash: prior.digest.clone(),
        issued_at: 0,
        entries: prior
            .entries
            .iter()
            .filter(|entry| !going.contains(entry))
            .cloned()
            .collect(),
        authorizers: prior.authorizers.clone(),
        recovery: prior.recovery.clone(),
        quorum: None,
        pending: Vec::new(),
        signer: signer.verifying_key().to_bytes().to_vec(),
        sig: vec![0u8; 64],
    };
    next.sig = Signer::sign(signer, &next.digest_input())
        .to_bytes()
        .to_vec();
    let body = next.encode();
    let accepted = wealdrelay::access::store::publish(pool, workspace, &next, &body)
        .await
        .expect("the publication is accepted");
    assert_eq!(
        accepted.disconnect.len(),
        going.len(),
        "the publication removed exactly the devices it was asked to"
    );
}

/// A 32-byte blob hash from one seed byte, so a failure names the blob.
pub fn blob_hash(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

/// The epoch-derived retention verifier a group's members would derive from
/// their MLS state. A plain signing key here, because the relay only ever sees
/// the public half and cannot tell how it was derived: that is the whole point
/// of `media.md`'s division of authority.
pub fn verifier_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn signed_control(
    group: &[u8],
    epoch: u64,
    key: &SigningKey,
    prev_control_hash: Option<Vec<u8>>,
    authority: &SigningKey,
) -> RetentionControl {
    let mut record = RetentionControl {
        group: group.to_vec(),
        epoch,
        verifier: key.verifying_key().to_bytes().to_vec(),
        prev_control_hash,
        sig: vec![0u8; 64],
    };
    record.sig = Signer::sign(authority, &record.signing_bytes())
        .to_bytes()
        .to_vec();
    record
}

/// A `RetentionResolution` self-signed by `key`, naming `key` as the epoch's
/// genuine verifier — the WEALD-L294 recovery message.
pub fn signed_resolution(group: &[u8], epoch: u64, key: &SigningKey) -> RetentionResolution {
    let mut record = RetentionResolution {
        group: group.to_vec(),
        epoch,
        verifier: key.verifying_key().to_bytes().to_vec(),
        sig: vec![0u8; 64],
    };
    record.sig = Signer::sign(key, &record.signing_bytes())
        .to_bytes()
        .to_vec();
    record
}

pub fn signed_manifest(
    group: &[u8],
    epoch: u64,
    sequence: u64,
    prev_manifest_hash: Option<Vec<u8>>,
    blobs: Vec<Vec<u8>>,
    key: &SigningKey,
) -> RetentionManifest {
    let mut record = RetentionManifest {
        group: group.to_vec(),
        epoch,
        sequence,
        prev_manifest_hash,
        blobs,
        sig: vec![0u8; 64],
    };
    record.sig = Signer::sign(key, &record.signing_bytes())
        .to_bytes()
        .to_vec();
    record
}

pub fn signed_policy(
    group: &[u8],
    version: u64,
    media_after_days: u32,
    not_before: u64,
    signers: &[SigningKey],
) -> RetentionPolicy {
    let mut record = RetentionPolicy {
        group: group.to_vec(),
        version,
        media_after_days,
        text_after_days: media_after_days,
        not_before,
        authorizers: signers
            .iter()
            .map(|key| key.verifying_key().to_bytes().to_vec())
            .collect(),
        signatures: Vec::new(),
    };
    record.signatures = sign_all(&record.signing_bytes(), signers);
    record
}

pub fn signed_destruction(
    group: &[u8],
    kind: &str,
    target_digest: &[u8],
    not_before: u64,
    signers: &[SigningKey],
) -> RetentionDestruction {
    let mut record = RetentionDestruction {
        group: group.to_vec(),
        kind: kind.as_bytes().to_vec(),
        target_digest: target_digest.to_vec(),
        policy_version: None,
        not_before,
        authorizers: signers
            .iter()
            .map(|key| key.verifying_key().to_bytes().to_vec())
            .collect(),
        signatures: Vec::new(),
    };
    record.signatures = sign_all(&record.signing_bytes(), signers);
    record
}

/// One signed `drop_before`, ready for `lifecycle::drop_before` or a `DROP` frame.
///
/// Signed by the epoch's retention verifier, which is the same key the media
/// chain's manifests are signed by: `lifecycle.md` says the instruction is "signed
/// with the relay-verifiable retention signing key", and there is one such key per
/// epoch per group.
pub fn signed_drop(
    group: &[u8],
    manifest_hash: &[u8],
    snapshots: Vec<Vec<u8>>,
    epoch: u64,
    policy_version: Option<u64>,
    destruction_digest: Option<Vec<u8>>,
    key: &SigningKey,
) -> DropBefore {
    let mut record = DropBefore {
        group: group.to_vec(),
        manifest_hash: manifest_hash.to_vec(),
        snapshots,
        epoch,
        policy_version,
        destruction_digest,
        sig: vec![0u8; 64],
    };
    record.sig = Signer::sign(key, &record.signing_bytes())
        .to_bytes()
        .to_vec();
    record
}

/// One `Signature` per signer over the same canonical body, which is what
/// `retention::authorize` checks against the workspace's access-set authorizers.
pub fn sign_all(signing_bytes: &[u8], signers: &[SigningKey]) -> Vec<Signature> {
    signers
        .iter()
        .map(|key| Signature {
            key: key.verifying_key().to_bytes().to_vec(),
            sig: Signer::sign(key, signing_bytes).to_bytes().to_vec(),
        })
        .collect()
}

/// One HTTP request against loopback, with a binary body and a binary answer.
///
/// Written here rather than pulled in as a dependency for the reason
/// `tests/integration.rs` gives for its own one-line GET: the whole need is a
/// handful of requests against a relay on 127.0.0.1, and a client crate would be
/// a dependency the relay does not otherwise have. This one carries a body and
/// returns bytes, because step 9 uploads ciphertext through a presigned URL and
/// a lossy string would not survive it.
pub async fn http_request(
    address: std::net::SocketAddr,
    method: &str,
    path_and_query: &str,
    body: &[u8],
) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(address).await.expect("connect");
    let head = format!(
        "{method} {path_and_query} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    );
    // Both writes are allowed to fail. A server that has already decided to
    // refuse closes the connection without draining the body, and the useful
    // thing then is its answer, not the write error: a test that panicked here
    // would report a broken pipe where the relay behaved exactly as intended.
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body).await;
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response).await;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("a header terminator");
    let headers = String::from_utf8_lossy(&response[..split]).to_string();
    let status = headers
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, response[split + 4..].to_vec())
}

// MARK: Step 37, the ringer
//
// Nothing here is a mock of the ringer. It is a real TCP listener on loopback
// speaking real HTTP/1.1, which is what `specs/backend/relay/ringer.md` route 3
// specifies and what the relay's own pooled client actually talks to. The relay is
// under test; the party on the other end is a listener whose answers a test chooses,
// which is the same shape `tests/media_*` uses for MinIO.

/// A ringer that records what it was asked and answers with a chosen status.
pub struct RecordingRinger {
    pub address: std::net::SocketAddr,
    requests: Arc<tokio::sync::Mutex<Vec<String>>>,
    /// The whole conversation, head and body, oldest first. The bodies alone say
    /// what the relay meant; the heads say what it actually put on the wire, which
    /// is the only thing a contract with another implementation on the far side of
    /// it can be asserted against. See `tests/push_ringer_wire.rs`.
    raw_requests: Arc<tokio::sync::Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl RecordingRinger {
    /// Answer every wake with `202` and no body, which is the ordinary case.
    pub async fn accepting() -> Self {
        Self::answering(202, None).await
    }

    /// Answer every wake with a chosen status, and optionally a `Retry-After`.
    pub async fn answering(status: u16, retry_after: Option<u64>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a ringer");
        let address = listener.local_addr().expect("a ringer address");
        let requests = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let raw_requests = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let raw_recorded = Arc::clone(&raw_requests);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let recorded = Arc::clone(&recorded);
                let raw_recorded = Arc::clone(&raw_recorded);
                tokio::spawn(async move {
                    let (head, body) = read_http_request_raw(&mut stream).await;
                    // The head keeps its trailing blank line, so this is the request
                    // exactly as it sat on the wire.
                    raw_recorded.lock().await.push(format!("{head}{body}"));
                    recorded.lock().await.push(body);
                    let extra = match retry_after {
                        Some(seconds) => format!("Retry-After: {seconds}\r\n"),
                        None => String::new(),
                    };
                    let response =
                        format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\n{extra}\r\n");
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                    // Held open briefly so the relay's pooled connection is reused
                    // rather than reset under it, which is what a real ringer does.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                });
            }
        });
        Self {
            address,
            requests,
            raw_requests,
            task,
        }
    }

    /// The url `WEALD_RELAY_PUSH_URL` is set to. `ringer.md` route 3's path.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}/v1/wake", self.address.port())
    }

    /// Every request body it has been sent, oldest first.
    pub async fn requests(&self) -> Vec<String> {
        self.requests.lock().await.clone()
    }

    /// Every request as it arrived, request line and headers and body, oldest
    /// first, headers lowercased exactly as they were read off the stream.
    pub async fn raw_requests(&self) -> Vec<String> {
        self.raw_requests.lock().await.clone()
    }

    /// Wait until at least `count` requests have arrived, or give up.
    ///
    /// A bounded wait rather than a sleep, so a passing test is fast and a failing one
    /// says how many arrived instead of timing out the whole suite.
    pub async fn wait_for(&self, count: usize) -> Vec<String> {
        for _ in 0..200 {
            let seen = self.requests().await;
            if seen.len() >= count {
                return seen;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        self.requests().await
    }

    pub fn stop(self) {
        self.task.abort();
    }
}

/// A ringer that accepts a connection and then says nothing at all.
///
/// The listener `push.md` section 4's requirement is stated against: "a ringer that
/// accepts a connection and then hangs for thirty seconds adds no measurable latency
/// to `SEND` on the same process". It holds the accepted stream so the relay sees an
/// open connection rather than a reset.
pub struct HangingRinger {
    pub address: std::net::SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl HangingRinger {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a hanging ringer");
        let address = listener.local_addr().expect("an address");
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                // Kept, never read, never answered. Dropping it would send a FIN and
                // the relay would learn the answer immediately, which is the opposite
                // of the case being proved.
                held.push(stream);
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
        Self { address, task }
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}/v1/wake", self.address.port())
    }

    pub fn stop(self) {
        self.task.abort();
    }
}

/// Read one HTTP/1.1 request off a socket and return its body.
///
/// Deliberately small: headers to the terminator, then exactly `Content-Length`
/// bytes. The relay is the only client, it always sends a length, and a test listener
/// that implemented chunked encoding would be testing itself.
async fn read_http_request(stream: &mut TcpStream) -> String {
    read_http_request_raw(stream).await.1
}

/// The whole request: `(head, body)`, the head ending before the blank line that
/// separates it from the body. The head keeps its original case; only the copy
/// used to find `content-length` is lowercased, because header names arrive in
/// whatever case the client's HTTP stack felt like writing.
async fn read_http_request_raw(stream: &mut TcpStream) -> (String, String) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            // The peer went away mid-request, which is a test tearing down. An empty
            // body is the honest record of it.
            _ => return (String::new(), String::new()),
        }
    }
    let headers = String::from_utf8_lossy(&head).to_ascii_lowercase();
    let length = headers
        .split("content-length:")
        .nth(1)
        .and_then(|rest| rest.split("\r\n").next())
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    if length > 0 && stream.read_exact(&mut body).await.is_err() {
        return (String::new(), String::new());
    }
    let head = String::from_utf8_lossy(&head).to_string();
    let body = String::from_utf8_lossy(&body).to_string();
    (head, body)
}

/// A relay with push on, pointed at `wake_url`.
///
/// A helper of its own rather than a flag on `config_for`, for the reason
/// `config_for_calls` is one: `WEALD_RELAY_PUSH` is off by default and every suite
/// that is not about push should run against the default posture. `coalesce_ms` is a
/// parameter because the window is what several of the queue rules are about, and a
/// test proving one would otherwise have to wait two seconds to see it.
pub fn config_for_push(
    scratch: &Scratch,
    blobs: &std::path::Path,
    wake_url: &str,
    coalesce_ms: u64,
) -> Config {
    config_with(
        scratch,
        blobs,
        [
            (keys::PUSH, "on".to_string()),
            (keys::PUSH_URL, wake_url.to_string()),
            (keys::PUSH_COALESCE_MS, coalesce_ms.to_string()),
        ],
    )
}

/// A 16-byte wake handle from one seed byte, so a failure names the handle without
/// anything having to print it.
pub fn wake_handle(seed: u8) -> Vec<u8> {
    vec![seed; wealdrelay::push::HANDLE_BYTES]
}

/// A stated expiry a week out from the relay's clock, which is the rotation period
/// `push.md` assumes.
pub fn wake_expiry(now_ms: u64) -> u64 {
    now_ms + 7 * 24 * 60 * 60 * 1000
}

/// The salted entry hash for one device in one workspace, which is the only name the
/// relay has for a principal and the key the registration table uses.
pub async fn entry_hash_of(pool: &sqlx::PgPool, workspace: &str, device: &SigningKey) -> Vec<u8> {
    let salt = wealdrelay::access::store::salt(pool, workspace)
        .await
        .expect("a workspace salt");
    wealdrelay::access::entry_hash(&device.verifying_key().to_bytes(), &salt)
}

/// Wait until the hub has let go of one principal's last socket.
///
/// Waited for and then asserted rather than slept through, for the reason
/// `push_adversarial.rs` records: a test that pushes on before the socket is reaped
/// proves the suppression it was trying to lift, and the failure lands somewhere
/// else entirely. Panics rather than returning, because every caller's next line is
/// only meaningful once this is true.
pub async fn wait_until_disconnected(state: &Arc<RelayState>, entry_hash: &[u8]) {
    let give_up = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while state.hub.connections_for(entry_hash).await != 0 && std::time::Instant::now() < give_up {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        state.hub.connections_for(entry_hash).await,
        0,
        "the socket was never let go, so a wake for this principal would be suppressed"
    );
}

/// The path and query of a presigned URL, which is all a test needs: the host in
/// it is `WEALD_RELAY_LISTEN` as configured, and an integration relay is bound to
/// port zero, so the request goes to the address the relay actually got.
pub fn path_of(url: &str) -> String {
    let without_scheme = url.strip_prefix("http://").expect("an http url");
    let (_, path) = without_scheme.split_once('/').expect("a path");
    format!("/{path}")
}
