// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Sequence assignment across three relay processes.
//!
//! Step 4's property gate: "sequence assignment is total-ordered and gap-free
//! under randomised concurrent publishes across three processes"
//! (`specs/backend/build/phases-relay.md`), and the configuration note says `ci`
//! runs a two-process relay specifically to exercise this, "which single-process
//! runs cannot".
//!
//! Three real processes, not three tasks. That distinction is the whole test. A
//! single process assigning sequence numbers can be correct by accident: an
//! in-process mutex, a `&mut self` somewhere, or tokio's own scheduling can
//! serialise the claims without anybody having designed for it. Three operating
//! system processes share nothing but the database, so what is being tested is the
//! `UPDATE ... RETURNING` against the per-group counter row and nothing else.
//!
//! ## Why Redis is not in this test
//!
//! `phases-relay.md` says "sequence assignment, correct across multiple relay
//! processes via Redis", and `specs/backend/relay/operations.md` is clearer about
//! the division: Redis carries **fanout**, and "a missed Redis message costs a
//! subscriber its live push and is repaired by reconciliation on the next round
//! trip, so Redis is never the source of truth for whether an envelope was
//! accepted".
//!
//! Sequence assignment is therefore Postgres's, and it has to be: a counter in
//! Redis would be a second source of truth for a number that has to agree with the
//! rows in the envelope table, and the two could diverge on any failover. The plan
//! file's wording is corrected in the same commit as this test, because a gate that
//! asked for the number to come from Redis would have been asking for the weaker
//! design.

use std::process::{Command, Stdio};
use std::time::Duration;

use sqlx::{Connection, Executor as _, PgConnection, Row};

fn postgres_port() -> String {
    std::env::var("WEALD_STACK_PG_PORT").unwrap_or_else(|_| "54032".to_string())
}

fn admin_url() -> String {
    format!(
        "postgres://weald:weald@127.0.0.1:{}/weald_relay",
        postgres_port()
    )
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn scratch(label: &str) -> String {
    let name = format!("weald_step4_mp_{label}_{}", std::process::id());
    let mut admin = PgConnection::connect(&admin_url()).await.expect(
        "Postgres is not reachable. This is an integration test and it does not skip: \
         run `scripts/weald-stack up`.",
    );
    admin
        .execute(format!("drop database if exists {name}").as_str())
        .await
        .unwrap();
    admin
        .execute(format!("create database {name}").as_str())
        .await
        .unwrap();
    name
}

async fn drop_database(name: &str) {
    if let Ok(mut admin) = PgConnection::connect(&admin_url()).await {
        let _ = admin
            .execute(format!("drop database if exists {name} with (force)").as_str())
            .await;
    }
}

/// One relay process.
struct Relay {
    child: std::process::Child,
    port: u16,
}

impl Relay {
    fn start(database: &str, blobs: &std::path::Path, redis: Option<&str>) -> Self {
        let port = free_port();
        let private = free_port();
        let mut command = Command::new(env!("CARGO_BIN_EXE_wealdrelay"));
        command.env_clear();
        for key in ["PATH", "HOME", "LLVM_PROFILE_FILE"] {
            if let Ok(value) = std::env::var(key) {
                command.env(key, value);
            }
        }
        command
            .env("WEALD_RELAY_HOSTNAME", "localhost")
            .env(
                "WEALD_RELAY_DATABASE_URL",
                format!(
                    "postgres://weald:weald@127.0.0.1:{}/{database}",
                    postgres_port()
                ),
            )
            .env(
                "WEALD_RELAY_STORAGE_URL",
                format!("file://{}", blobs.display()),
            )
            .env("WEALD_RELAY_LISTEN", format!("127.0.0.1:{port}"))
            .env(
                "WEALD_RELAY_OBSERVABILITY_LISTEN",
                format!("127.0.0.1:{private}"),
            )
            .env("WEALD_RELAY_RELEASE_CHECK", "off")
            .current_dir(blobs)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if let Some(redis) = redis {
            command.env("WEALD_RELAY_REDIS_URL", redis);
            // A Redis url is how `server.md` says a deployment declares more than
            // one instance, and step 30 made `process` fanout refuse to start in
            // that shape rather than serve every member half the room. This suite
            // is about sequence assignment across processes and not about
            // presence, so it declares the ephemeral path off, which is the
            // deployment shape a multi-instance operator on this build actually
            // has: no beats, presence reported as unavailable, and every durable
            // guarantee intact.
            command.env("WEALD_RELAY_LIVE", "off");
        }
        let child = command.spawn().expect("spawn a relay");
        Self { child, port }
    }

    /// Wait until it answers, or fail with what it said on the way out.
    fn wait_for_liveness(&mut self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().expect("check the child") {
                // With what it said on the way out. A status code alone names the
                // class of failure and not the failure, and this one only happens
                // when three processes start at once, which is the case nobody can
                // reproduce by hand from a number.
                let mut said = String::new();
                if let Some(mut stderr) = self.child.stderr.take() {
                    use std::io::Read as _;
                    let _ = stderr.read_to_string(&mut said);
                }
                panic!("a relay exited early with {status:?}: {said}");
            }
            if std::net::TcpStream::connect_timeout(
                &format!("127.0.0.1:{}", self.port).parse().unwrap(),
                Duration::from_millis(200),
            )
            .is_ok()
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("a relay never opened its socket on {}", self.port);
    }

    fn stop(mut self) {
        #[cfg(unix)]
        // Safety: the pid is this child's and `SIGTERM` is the signal the relay
        // installs a handler for.
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while std::time::Instant::now() < deadline {
            if self.child.try_wait().unwrap().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
    }
}

/// A client that speaks just enough of the protocol to publish.
///
/// The same hand-rolled WebSocket as `tests/ws.rs`, kept separate rather than
/// shared because a helper module between two integration binaries would be
/// compiled into both and its own coverage attributed to whichever ran first.
mod client {
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;

    use ed25519_dalek::{Signer as _, SigningKey};
    use wealdrelay::frame::{Frame, PROTOCOL_VERSION};

    pub struct Client {
        stream: TcpStream,
        buffer: Vec<u8>,
    }

    impl Client {
        pub fn connect(port: u16) -> Self {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
            stream
                .write_all(
                    format!(
                        "GET /relay HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: Upgrade\r\n\
                         Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
                         Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .expect("handshake");
            let mut headers = Vec::new();
            let mut byte = [0u8; 1];
            while !headers.ends_with(b"\r\n\r\n") {
                assert_eq!(stream.read(&mut byte).expect("read"), 1);
                headers.push(byte[0]);
            }
            assert!(
                String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 101"),
                "the relay refused the upgrade"
            );
            Self {
                stream,
                buffer: Vec::new(),
            }
        }

        pub fn send(&mut self, frame: &Frame) {
            let payload = frame.encode();
            let mut out = vec![0x82u8];
            let mask = [0x37, 0xfa, 0x21, 0x3d];
            match payload.len() {
                length if length < 126 => out.push(0x80 | length as u8),
                length if length <= u16::MAX as usize => {
                    out.push(0x80 | 126);
                    out.extend_from_slice(&(length as u16).to_be_bytes());
                }
                length => {
                    out.push(0x80 | 127);
                    out.extend_from_slice(&(length as u64).to_be_bytes());
                }
            }
            out.extend_from_slice(&mask);
            for (index, byte) in payload.iter().enumerate() {
                out.push(byte ^ mask[index % 4]);
            }
            self.stream.write_all(&out).expect("send");
        }

        pub fn recv(&mut self) -> Frame {
            loop {
                if let Some(payload) = self.take() {
                    return Frame::decode(&payload).expect("a frame");
                }
                let mut chunk = [0u8; 8192];
                let read = self.stream.read(&mut chunk).expect("read");
                assert!(read > 0, "the relay closed unexpectedly");
                self.buffer.extend_from_slice(&chunk[..read]);
            }
        }

        fn take(&mut self) -> Option<Vec<u8>> {
            if self.buffer.len() < 2 {
                return None;
            }
            let opcode = self.buffer[0] & 0x0f;
            let indicator = self.buffer[1] & 0x7f;
            let (length, header) = match indicator {
                126 if self.buffer.len() >= 4 => (
                    u16::from_be_bytes([self.buffer[2], self.buffer[3]]) as usize,
                    4,
                ),
                127 if self.buffer.len() >= 10 => {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&self.buffer[2..10]);
                    (u64::from_be_bytes(bytes) as usize, 10)
                }
                126 | 127 => return None,
                small => (small as usize, 2),
            };
            if self.buffer.len() < header + length {
                return None;
            }
            let payload = self.buffer[header..header + length].to_vec();
            self.buffer.drain(..header + length);
            match opcode {
                // A close frame is the relay refusing this connection, and reading
                // its body as CBOR would report `Truncated` rather than the refusal
                // that actually happened. Step 6 made that a reachable outcome, so
                // it is named here.
                0x8 => panic!("the relay closed the connection: {payload:?}"),
                // Ping and pong carry no frame, so they are consumed and the caller
                // keeps waiting for the next data frame.
                0x9 | 0xa => self.take(),
                _ => Some(payload),
            }
        }

        /// Walk the handshake to Ready as this device.
        ///
        /// Step 6 made `AUTH` a real check, so the challenge the relay issued has to
        /// be signed by a key the workspace's access set admits. Before that, a
        /// made-up key and 64 bytes of `0x22` walked straight through.
        pub fn handshake(&mut self, group: &[u8], key: &SigningKey) {
            self.send(&Frame::Connect {
                version: PROTOCOL_VERSION,
                groups: vec![group.to_vec()],
                sent_at: 1_700_000_000_000,
            });
            match self.recv() {
                Frame::ConnectAck { .. } => {}
                other => panic!("expected a ConnectAck, got {other:?}"),
            }
            let challenge = match self.recv() {
                Frame::AuthChallenge { challenge } => challenge,
                other => panic!("expected an AuthChallenge, got {other:?}"),
            };
            self.send(&Frame::Auth {
                device_key: key.verifying_key().to_bytes().to_vec(),
                signature: key.sign(&challenge).to_bytes().to_vec(),
            });
            match self.recv() {
                Frame::AuthAck { .. } => {}
                other => panic!("expected an AuthAck, got {other:?}"),
            }
        }
    }
}

use client::Client;
use ed25519_dalek::{Signer as _, SigningKey};
use wealdrelay::access::{self, AccessSet};
use wealdrelay::envelope::{content_hash, Encryption, Envelope};
use wealdrelay::frame::Frame;

/// The device these three processes connect as.
fn device() -> SigningKey {
    SigningKey::from_bytes(&[0x31; 32])
}

/// A genesis access set for one workspace, written straight into the database.
///
/// Seeded rather than published over a socket for the same reason
/// `tests/support/mod.rs` seeds it: the socket path is proven by `tests/access.rs`,
/// and this suite is about sequence assignment across processes. What it needs from
/// step 6 is a workspace that admits its client, since `WEALD_RELAY_ACCESS_SET`
/// is `enforce` in every environment including this one.
async fn seed_access_set(database: &str, workspace: &str, devices: &[SigningKey]) {
    let pool = sqlx::PgPool::connect(&format!(
        "postgres://weald:weald@127.0.0.1:{}/{database}",
        postgres_port()
    ))
    .await
    .expect("a pool against the scratch database");
    let salt = access::store::salt(&pool, workspace)
        .await
        .expect("a workspace salt");
    let signer = devices.first().expect("at least one device").clone();
    let recovery = SigningKey::from_bytes(&[0x3f; 32]);
    let mut entries: Vec<Vec<u8>> = devices
        .iter()
        .map(|device| access::entry_hash(&device.verifying_key().to_bytes(), &salt))
        .collect();
    entries.push(access::entry_hash(
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
    set.sig = signer.sign(&set.digest_input()).to_bytes().to_vec();
    let body = set.encode();
    access::store::publish(&pool, workspace, &set, &body)
        .await
        .expect("the genesis access set is accepted");
    pool.close().await;
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

/// A seeded generator, so a failure is reproducible from the seed and not a story
/// about a run nobody can repeat.
struct Seeded(u64);

impl Seeded {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let mut z = self.0;
        z ^= z >> 33;
        z = z.wrapping_mul(0xff51_afd7_ed55_8ccd);
        z ^= z >> 33;
        z
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sequence_assignment_is_total_ordered_and_gap_free_across_three_processes() {
    let database = scratch("seq").await;
    let blobs = tempfile::tempdir().unwrap();
    let admin = format!(
        "postgres://weald:weald@127.0.0.1:{}/{database}",
        postgres_port()
    );

    // Three processes, sharing nothing but the database. `WEALD_RELAY_REDIS_URL` is
    // set on all three because `ci` runs them that way, and the point of setting it
    // is to show that the sequence numbers do not come from it: Redis is fanout, and
    // Postgres is the source of truth for whether an envelope was accepted.
    //
    // Since step 30 that url also declares a second instance, so `Relay::start`
    // turns the ephemeral path off alongside it. That is not a workaround: it is
    // the configuration a three-instance deployment on this build has, and running
    // this suite in any other shape would be running it against a deployment the
    // relay refuses to start.
    let redis_port =
        std::env::var("WEALD_STACK_REDIS_PORT").unwrap_or_else(|_| "54079".to_string());
    let redis = format!("redis://127.0.0.1:{redis_port}");
    let mut relays: Vec<Relay> = (0..3)
        .map(|_| Relay::start(&database, blobs.path(), Some(&redis)))
        .collect();
    for relay in &mut relays {
        relay.wait_for_liveness();
    }

    // Two groups, so the test also shows that unrelated groups do not contend: each
    // is numbered independently and densely.
    let mut connection = PgConnection::connect(&admin).await.unwrap();
    let groups: Vec<Vec<u8>> = vec![vec![0x51; 32], vec![0x52; 32]];
    for group in &groups {
        sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
            .bind(group)
            .bind("ws-mp")
            .execute(&mut connection)
            .await
            .unwrap();
    }
    seed_access_set(&database, "ws-mp", &[device()]).await;

    // Randomised: which process, which group, in an order the seed decides. Every
    // envelope is distinct, so every one has to get its own number.
    let mut random = Seeded(20_260_729);
    let per_process = 40usize;
    let total = per_process * relays.len();
    let mut plan: Vec<(usize, usize, u32)> = Vec::with_capacity(total);
    for index in 0..total {
        let relay = (random.next() % relays.len() as u64) as usize;
        let group = (random.next() % groups.len() as u64) as usize;
        plan.push((relay, group, index as u32));
    }

    // One thread per process, all publishing at once, so the claims genuinely
    // overlap rather than being interleaved by a scheduler that could serialise
    // them.
    let ports: Vec<u16> = relays.iter().map(|relay| relay.port).collect();
    let mut handles = Vec::new();
    for (which, port) in ports.iter().copied().enumerate() {
        let mine: Vec<(usize, u32)> = plan
            .iter()
            .filter(|(relay, _, _)| *relay == which)
            .map(|(_, group, body)| (*group, *body))
            .collect();
        let groups = groups.clone();
        handles.push(std::thread::spawn(move || {
            let mut acks: Vec<(usize, Vec<u8>, u64)> = Vec::new();
            // One connection per group, because a session subscribes per group and
            // opening one per envelope would be testing connection setup.
            let mut clients: Vec<Client> = groups
                .iter()
                .map(|group| {
                    let mut client = Client::connect(port);
                    client.handshake(group, &device());
                    client
                })
                .collect();
            for (group, body) in mine {
                let envelope = envelope_for(&groups[group], &body.to_be_bytes());
                clients[group].send(&Frame::Send {
                    envelope: envelope.encode(),
                });
                match clients[group].recv() {
                    Frame::SendAck { hash, seq } => {
                        assert_eq!(hash, envelope.hash, "an ack named another envelope");
                        acks.push((group, hash, seq));
                    }
                    other => panic!("expected a SendAck, got {other:?}"),
                }
            }
            acks
        }));
    }

    let mut acks: Vec<(usize, Vec<u8>, u64)> = Vec::new();
    for handle in handles {
        acks.extend(handle.join().expect("a publishing thread panicked"));
    }
    assert_eq!(acks.len(), total, "not every publish was acknowledged");

    // The property, per group: the numbers the relays handed out are exactly
    // 1..=count, with no gap and no repeat. Total-ordered means every envelope has
    // one number and no number has two envelopes.
    for (index, group) in groups.iter().enumerate() {
        let mut assigned: Vec<u64> = acks
            .iter()
            .filter(|(which, _, _)| *which == index)
            .map(|(_, _, seq)| *seq)
            .collect();
        let count = assigned.len() as u64;
        assigned.sort_unstable();
        let expected: Vec<u64> = (1..=count).collect();
        assert_eq!(
            assigned, expected,
            "group {index} got {assigned:?} rather than a dense 1..={count}"
        );

        // And the database agrees. An acknowledgement the rows do not support would
        // mean a relay told a client a number it had not stored.
        let rows = sqlx::query("select seq from relay_envelope where group_id = $1 order by seq")
            .bind(group)
            .fetch_all(&mut connection)
            .await
            .unwrap();
        let stored: Vec<u64> = rows
            .iter()
            .map(|row| row.get::<i64, _>("seq") as u64)
            .collect();
        assert_eq!(
            stored, expected,
            "group {index} stored {stored:?} rather than a dense 1..={count}"
        );
    }

    // Every envelope is present exactly once, whichever process took it.
    let distinct: i64 = sqlx::query_scalar("select count(distinct hash) from relay_envelope")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(distinct as usize, total);

    for relay in relays {
        relay.stop();
    }
    drop_database(&database).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retry_against_a_different_process_is_answered_with_the_original_sequence_number() {
    // The property that makes a relay fleet safe to sit behind a load balancer. A
    // client whose connection drops reconnects to whichever process it lands on, and
    // resends verbatim. If the second process assigned a new number, the client
    // would hold two sequence numbers for one envelope and its author chain would
    // look forked to every receiver.
    let database = scratch("retry").await;
    let blobs = tempfile::tempdir().unwrap();
    let admin = format!(
        "postgres://weald:weald@127.0.0.1:{}/{database}",
        postgres_port()
    );

    let mut first = Relay::start(&database, blobs.path(), None);
    first.wait_for_liveness();
    let mut second = Relay::start(&database, blobs.path(), None);
    second.wait_for_liveness();

    let mut connection = PgConnection::connect(&admin).await.unwrap();
    let group = vec![0x53; 32];
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(&group)
        .bind("ws-retry")
        .execute(&mut connection)
        .await
        .unwrap();
    seed_access_set(&database, "ws-retry", &[device()]).await;

    let envelope = envelope_for(&group, b"written once, sent twice");
    let (first_port, second_port) = (first.port, second.port);
    let group_for_thread = group.clone();
    let envelope_for_thread = envelope.clone();
    let seqs = std::thread::spawn(move || {
        let mut original = Client::connect(first_port);
        original.handshake(&group_for_thread, &device());
        original.send(&Frame::Send {
            envelope: envelope_for_thread.encode(),
        });
        let first_seq = match original.recv() {
            Frame::SendAck { seq, .. } => seq,
            other => panic!("expected a SendAck, got {other:?}"),
        };
        // The connection is dropped, and the retry goes to the other process.
        drop(original);
        let mut retried = Client::connect(second_port);
        retried.handshake(&group_for_thread, &device());
        retried.send(&Frame::Send {
            envelope: envelope_for_thread.encode(),
        });
        let second_seq = match retried.recv() {
            Frame::SendAck { seq, .. } => seq,
            other => panic!("expected a SendAck for the retry, got {other:?}"),
        };
        (first_seq, second_seq)
    })
    .join()
    .expect("the publishing thread panicked");

    assert_eq!(seqs.0, 1);
    assert_eq!(
        seqs.1, seqs.0,
        "a retry against another process got a different sequence number"
    );
    let rows: i64 = sqlx::query_scalar("select count(*) from relay_envelope")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(rows, 1, "the retry stored a second copy");

    first.stop();
    second.stop();
    drop_database(&database).await;
}
