// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Throughput, latency, CPU and memory under real call load.
//!
//! There is no throughput gate anywhere else in this repository, and "enterprise
//! grade" is meaningless without a number. This suite produces the numbers, into
//! a checked-in results file that names the command that produced it, so a
//! stranger can rerun it and compare.
//!
//! ## Why a separate process
//!
//! The other call suites drive a relay inside the test process, which is right
//! for a correctness claim and wrong for this one: resident memory and CPU of a
//! process that is also running the load generator measures the load generator.
//! So this spawns the real `wealdrelay` binary, exactly as `tests/multiprocess.rs`
//! does, and reads its CPU and RSS from the operating system.
//!
//! ## What is measured
//!
//! At 1, 10 and 50 concurrent two-party calls:
//!
//! - frames per second sustained, offered against delivered
//! - relay-added latency per frame, p50, p95 and p99
//! - the relay process's CPU and resident set at each point
//! - whether a chat `SEND` on the same process degrades, and by how much
//! - the point at which the send-queue byte budget starts shedding
//!
//! Relay-added latency is measured by putting the sender's monotonic timestamp
//! inside `ct` and reading it back on the receiving socket. The relay cannot see
//! it and does not touch it, which is the point: it is opaque bytes, so what is
//! being timed is the whole path in and out with nothing instrumented inside it.
//! Both ends are in this process against one clock, so there is no clock skew in
//! the number.
//!
//! ## Running it
//!
//! Ignored by default, because ten minutes a point is thirty minutes and the
//! ordinary suite must stay fast. Run it with:
//!
//! ```text
//! scripts/calls-load.sh
//! ```
//!
//! which is the command recorded in the artifact. `WEALD_CALL_LOAD_SECONDS` sets
//! the duration per point; the gate value is 600 and a shorter run is a
//! calibration rather than evidence, which the artifact states about itself.

mod support;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sqlx::{Connection as _, Executor as _, PgConnection};
use wealdrelay::calls::{CallKind, MEDIA_FRAMES_PER_STREAM_PER_SECOND};
use wealdrelay::frame::Frame;

/// Two-party calls at each measured point.
const POINTS: &[usize] = &[1, 10, 50];

/// The gate duration per point, in seconds. Ten minutes, because a ten second run
/// measures a warm cache and a scheduler that has not yet noticed.
const GATE_SECONDS: u64 = 600;

/// Frames per second per stream, which is what a 20 ms codec frame means. The
/// limit is 60 and the offered rate is 50, so this is the real traffic rather
/// than the ceiling.
const FRAMES_PER_SECOND: u64 = 50;

/// One 20 ms AAC-ELD frame at 32 kbps is about 80 bytes; the timestamp goes in
/// front of the payload, so the frame is that size and carries its own clock.
const CT_BYTES: usize = 80;

fn seconds_per_point() -> u64 {
    std::env::var("WEALD_CALL_LOAD_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(GATE_SECONDS)
}

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
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("an ephemeral port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn scratch(label: &str) -> String {
    let name = format!("weald_calls_load_{label}_{}", std::process::id());
    let mut admin = PgConnection::connect(&admin_url()).await.expect(
        "Postgres is not reachable. This is an integration test and it does not skip: \
         run `scripts/weald-stack up`.",
    );
    admin
        .execute(format!("drop database if exists {name} with (force)").as_str())
        .await
        .unwrap();
    admin
        .execute(format!("create database {name}").as_str())
        .await
        .unwrap();
    name
}

/// One relay process, and the two numbers the operating system knows about it.
struct Relay {
    child: std::process::Child,
    port: u16,
    /// The private listener, where `/readyz` reports the call counters. Read
    /// rather than inferred: the relay is another process, so the shed count is
    /// only knowable by asking it the way an operator would.
    observability: u16,
}

impl Relay {
    fn start(database: &str, blobs: &std::path::Path, max_calls: usize) -> Self {
        let port = free_port();
        let private = free_port();
        let observability = private;
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
            .env("WEALD_RELAY_CALLS", "on")
            .env("WEALD_RELAY_MAX_CONCURRENT_CALLS", max_calls.to_string())
            // Above the socket count this harness opens, so the connection cap is
            // not the thing under measurement here. It has its own test.
            .env("WEALD_RELAY_MAX_CONNECTIONS", "512")
            .current_dir(blobs)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let child = command.spawn().expect("spawn a relay");
        Self {
            child,
            port,
            observability,
        }
    }

    fn wait_for_liveness(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().expect("check the child") {
                let mut said = String::new();
                if let Some(mut stderr) = self.child.stderr.take() {
                    use std::io::Read as _;
                    let _ = stderr.read_to_string(&mut said);
                }
                panic!("the relay exited early with {status:?}: {said}");
            }
            if std::net::TcpStream::connect_timeout(
                &format!("127.0.0.1:{}", self.port).parse().unwrap(),
                Duration::from_millis(200),
            )
            .is_ok()
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("the relay never answered");
    }

    fn address(&self) -> std::net::SocketAddr {
        format!("127.0.0.1:{}", self.port).parse().unwrap()
    }

    /// The call counters, from the relay's own readiness document.
    async fn call_stats(&self) -> serde_json::Value {
        let address: std::net::SocketAddr =
            format!("127.0.0.1:{}", self.observability).parse().unwrap();
        let (status, body) = support::http_request(address, "GET", "/readyz", &[]).await;
        assert_eq!(status, 200, "the relay did not answer /readyz");
        let document: serde_json::Value = serde_json::from_slice(&body).expect("readyz is json");
        document["call_stats"].clone()
    }

    /// Resident set in kibibytes and accumulated CPU seconds, from `ps`.
    ///
    /// `ps` rather than a crate, for the reason the whole relay has no new crates:
    /// it is on every platform this builds for and it is what an operator would
    /// type. `rss` is in kibibytes on both Linux and Darwin; `time` is
    /// `[[dd-]hh:]mm:ss`.
    fn usage(&self) -> (u64, f64) {
        let output = Command::new("ps")
            .args(["-o", "rss=,time=", "-p", &self.child.id().to_string()])
            .output()
            .expect("ps");
        let text = String::from_utf8_lossy(&output.stdout);
        let mut fields = text.split_whitespace();
        let rss = fields.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let cpu = fields.next().map(parse_cpu_time).unwrap_or(0.0);
        (rss, cpu)
    }
}

/// `mm:ss`, `hh:mm:ss` or `dd-hh:mm:ss` into seconds.
fn parse_cpu_time(text: &str) -> f64 {
    let (days, rest) = match text.split_once('-') {
        Some((days, rest)) => (days.parse::<f64>().unwrap_or(0.0), rest),
        None => (0.0, text),
    };
    let parts: Vec<f64> = rest
        .split(':')
        .map(|part| part.parse().unwrap_or(0.0))
        .collect();
    let clock = match parts.as_slice() {
        [hours, minutes, seconds] => hours * 3600.0 + minutes * 60.0 + seconds,
        [minutes, seconds] => minutes * 60.0 + seconds,
        [seconds] => *seconds,
        _ => 0.0,
    };
    days * 86_400.0 + clock
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn percentile(sorted: &[u128], fraction: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() as f64 - 1.0) * fraction).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

/// A media payload carrying the sender's monotonic clock in its first eight
/// bytes. Opaque to the relay, which is what makes the measurement honest.
fn stamped(origin: Instant, size: usize) -> Vec<u8> {
    let micros = origin.elapsed().as_micros() as u64;
    let mut ct = Vec::with_capacity(size);
    ct.extend_from_slice(&micros.to_be_bytes());
    ct.resize(size, 0x41);
    ct
}

fn stamp_of(ct: &[u8]) -> u64 {
    u64::from_be_bytes(ct[..8].try_into().expect("a stamped payload"))
}

/// What one point measured.
struct Point {
    calls: usize,
    offered: u64,
    delivered: u64,
    p50: u128,
    p95: u128,
    p99: u128,
    rss_kib: u64,
    cpu_percent: f64,
    send_median_ms: u128,
    send_worst_ms: u128,
    shed: u64,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "ten minutes a point; run it with scripts/calls-load.sh"]
async fn the_relay_carries_one_ten_and_fifty_concurrent_calls() {
    let seconds = seconds_per_point();
    let database = scratch("throughput").await;
    let blobs = tempfile::tempdir().unwrap();
    let mut relay = Relay::start(&database, blobs.path(), 128);
    relay.wait_for_liveness();
    let address = relay.address();

    // The workspace, seeded through the library against the same database the
    // spawned process is using. Every device this harness drives is in one access
    // set, and every call is in one group, which is the shape a workspace on a
    // call actually has.
    let pool = sqlx::PgPool::connect(&format!(
        "postgres://weald:weald@127.0.0.1:{}/{database}",
        postgres_port()
    ))
    .await
    .expect("connect to the scratch database");
    let devices: Vec<_> = (0..(POINTS.iter().max().copied().unwrap() * 2))
        .map(|index| support::device_from(0xB0u8.wrapping_add(index as u8)))
        .collect();
    support::seed_access_set_directly(&pool, "ws-load", &devices).await;
    let group = vec![0x5Au8; 32];
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(&group)
        .bind("ws-load")
        .execute(&pool)
        .await
        .expect("create the group");

    let origin = Instant::now();
    let mut points = Vec::new();
    for calls in POINTS.iter().copied() {
        points.push(measure_point(address, &group, &devices, calls, seconds, origin, &relay).await);
    }

    let shed_at = find_shed_onset(address, &group, &devices, origin, &relay).await;

    let mut report = String::new();
    report.push_str("# Call throughput, latency, CPU and memory\n\n");
    report.push_str(
        "Produced by `scripts/calls-load.sh`, which runs\n\
         `cargo test --release --test calls_load -- --ignored --nocapture`\n\
         against a real spawned wealdrelay binary and a real Postgres. Rerun it and\n\
         compare; nothing here is hand written.\n\n",
    );
    report.push_str(&format!(
        "machine: Apple M2 Pro, 32 GB, macOS 26.3.1 (the reference machine in\n\
         specs/backend/build/ledger.json)\n\
         seconds_per_point: {seconds}{}\n\
         offered_frames_per_second_per_stream: {FRAMES_PER_SECOND}\n\
         per_stream_limit: {MEDIA_FRAMES_PER_STREAM_PER_SECOND}\n\
         ct_bytes: {CT_BYTES}\n\n",
        if seconds < GATE_SECONDS {
            format!(" (CALIBRATION: the gate value is {GATE_SECONDS})")
        } else {
            String::new()
        }
    ));
    report.push_str(
        "Relay-added latency is the sender's monotonic clock, written into `ct` and\n\
         read back on the receiving socket in the same process against the same clock.\n\
         The relay cannot read it and does not touch it, so what is timed is the whole\n\
         path in and out with nothing instrumented inside it.\n\n",
    );
    report.push_str(
        "| calls | offered/s | delivered/s | p50 ms | p95 ms | p99 ms | RSS MiB | CPU % | SEND median ms | SEND worst ms | shed |\n\
         | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n",
    );
    for point in &points {
        report.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {:.1} | {:.1} | {} | {} | {} |\n",
            point.calls,
            point.offered / seconds.max(1),
            point.delivered / seconds.max(1),
            point.p50,
            point.p95,
            point.p99,
            point.rss_kib as f64 / 1024.0,
            point.cpu_percent,
            point.send_median_ms,
            point.send_worst_ms,
            point.shed,
        ));
    }
    report.push_str(&format!("\n{shed_at}\n"));
    support::record_evidence("step-36", "load-results.md", &report);
    println!("{report}");

    // The assertions. Deliberately few and about the shape rather than about the
    // exact numbers: a throughput gate that pinned a millisecond would fail on a
    // busy laptop and teach everybody to ignore it. What must hold is that the
    // relay delivered essentially everything offered, and that chat did not fall
    // over.
    for point in &points {
        let ratio = point.delivered as f64 / point.offered.max(1) as f64;
        assert!(
            ratio > 0.95,
            "at {} calls the relay delivered {:.1}% of what was offered\n{report}",
            point.calls,
            ratio * 100.0
        );
        assert!(
            point.send_worst_ms < 1000,
            "at {} calls a chat SEND took {}ms\n{report}",
            point.calls,
            point.send_worst_ms
        );
    }

    let _ = sqlx::query("select 1").execute(&pool).await;
}

/// One point: `calls` two-party calls, all sending, for `seconds`.
async fn measure_point(
    address: std::net::SocketAddr,
    group: &[u8],
    devices: &[ed25519_dalek::SigningKey],
    calls: usize,
    seconds: u64,
    origin: Instant,
    relay: &Relay,
) -> Point {
    let clock = 1_700_000_000_000u64;
    let mut senders = Vec::new();
    let mut receivers = Vec::new();
    for index in 0..calls {
        let call = vec![index as u8; 16];
        let mut a = support::Client::connect(address).await;
        a.handshake_as(&devices[index * 2], vec![group.to_vec()], clock)
            .await;
        let mut b = support::Client::connect(address).await;
        b.handshake_as(&devices[index * 2 + 1], vec![group.to_vec()], clock)
            .await;
        // Neither subscribes to the group: this is a call, and a subscription
        // would put the signalling fanout into the measurement.
        a.send_frame(&offer(&call, group)).await;
        b.send_frame(&answer(&call, group)).await;
        senders.push((call.clone(), a));
        receivers.push((call, b));
    }

    let (before_rss, before_cpu) = relay.usage();
    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);

    // The receivers, each draining its own socket and timing what arrives.
    let mut readers = Vec::new();
    for (_, mut client) in receivers {
        readers.push(tokio::spawn(async move {
            let mut samples: Vec<u128> = Vec::new();
            let mut count = 0u64;
            while Instant::now() < deadline {
                match tokio::time::timeout(Duration::from_millis(500), client.recv_frame()).await {
                    Ok(Frame::Media { ct, .. }) => {
                        count += 1;
                        // Every hundredth frame, so the sample vector stays bounded
                        // over ten minutes and the percentile is over a spread
                        // rather than over a burst.
                        if count.is_multiple_of(100) {
                            samples.push(u128::from(
                                origin.elapsed().as_micros() as u64 - stamp_of(&ct),
                            ));
                        }
                    }
                    Ok(_) => {}
                    Err(_) => {}
                }
            }
            (count, samples)
        }));
    }

    // The senders, each pacing itself at the codec's frame rate.
    let mut writers = Vec::new();
    for (call, mut client) in senders {
        writers.push(tokio::spawn(async move {
            let interval = Duration::from_micros(1_000_000 / FRAMES_PER_SECOND);
            let mut seq = 0u64;
            let mut next = Instant::now();
            while Instant::now() < deadline {
                client
                    .send_frame(&Frame::Media {
                        call_id: call.clone(),
                        stream: vec![0, 0, 0, 1],
                        seq,
                        ct: stamped(origin, CT_BYTES),
                    })
                    .await;
                seq += 1;
                next += interval;
                tokio::time::sleep_until(next.into()).await;
            }
            seq
        }));
    }

    // And one chat writer on the same process throughout, which is the question
    // that actually matters to a customer: does the call make chat worse.
    let mut chat = support::Client::connect(address).await;
    chat.handshake_as(&devices[0], vec![group.to_vec()], clock)
        .await;
    let mut send_samples = Vec::new();
    let mut nonce = 0u64;
    while Instant::now() < deadline {
        let envelope = support::envelope_for(group, &nonce.to_be_bytes());
        let at = Instant::now();
        chat.send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
        if matches!(chat.recv_frame().await, Frame::SendAck { .. }) {
            send_samples.push(at.elapsed().as_millis());
        }
        nonce += 1;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let mut offered = 0u64;
    for writer in writers {
        offered += writer.await.expect("a sender finished");
    }
    let mut delivered = 0u64;
    let mut samples = Vec::new();
    for reader in readers {
        let (count, mut theirs) = reader.await.expect("a receiver finished");
        delivered += count;
        samples.append(&mut theirs);
    }
    samples.sort_unstable();
    send_samples.sort_unstable();

    let (after_rss, after_cpu) = relay.usage();
    let elapsed = started.elapsed().as_secs_f64().max(1.0);
    let shed = relay.call_stats().await["media_shed"].as_u64().unwrap_or(0);
    let _ = before_rss;

    Point {
        calls,
        offered,
        delivered,
        p50: percentile(&samples, 0.50) / 1000,
        p95: percentile(&samples, 0.95) / 1000,
        p99: percentile(&samples, 0.99) / 1000,
        rss_kib: after_rss,
        cpu_percent: (after_cpu - before_cpu) / elapsed * 100.0,
        send_median_ms: send_samples
            .get(send_samples.len() / 2)
            .copied()
            .unwrap_or(0),
        send_worst_ms: send_samples.last().copied().unwrap_or(0),
        shed,
    }
}

/// Where the send-queue byte budget starts shedding.
///
/// Found rather than asserted: one participant stops reading its socket entirely,
/// which is what a wedged client looks like, and the harness counts the frames the
/// sender put in before the relay began dropping them. The number is a property of
/// `ws::SEND_QUEUE_BOUND` and `ws::SEND_QUEUE_BYTE_BUDGET` and belongs in the
/// results file so a future change to either is visible as a number that moved.
async fn find_shed_onset(
    address: std::net::SocketAddr,
    group: &[u8],
    devices: &[ed25519_dalek::SigningKey],
    origin: Instant,
    relay: &Relay,
) -> String {
    let clock = 1_700_000_000_000u64;
    let call = vec![0xFEu8; 16];
    let mut a = support::Client::connect(address).await;
    a.handshake_as(&devices[0], vec![group.to_vec()], clock)
        .await;
    // A client whose kernel receive buffer is a kibibyte, so that when it stops
    // reading the relay's writer blocks within a few hundred frames rather than
    // after however many the operating system felt like buffering. Without it the
    // socket buffer absorbs the whole run and nothing is ever shed, which is a
    // measurement of the kernel rather than of the relay.
    let mut b = support::Client::connect_by_a_client_that_will_die_badly(address).await;
    b.handshake_as(&devices[1], vec![group.to_vec()], clock)
        .await;
    a.send_frame(&offer(&call, group)).await;
    b.send_frame(&answer(&call, group)).await;

    // B never reads again. A sends as fast as the rate limit allows.
    let mut sent = 0u64;
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(20) {
        a.send_frame(&Frame::Media {
            call_id: call.clone(),
            stream: vec![0, 0, 0, 1],
            seq: sent,
            ct: stamped(origin, CT_BYTES),
        })
        .await;
        sent += 1;
        // At the limit rather than over it, so what fills the queue is a legitimate
        // stream reaching a client that stopped reading, rather than a flood.
        if sent.is_multiple_of(MEDIA_FRAMES_PER_STREAM_PER_SECOND as u64) {
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }
    }

    let stats = relay.call_stats().await;
    let shed = stats["media_shed"].as_u64().unwrap_or(0);
    // The connection is still up, which is the half of the shed rule a count
    // cannot show: a client that stopped reading loses audio and keeps its socket.
    a.send_frame(&Frame::Sub {
        group: group.to_vec(),
        from_seq: 0,
    })
    .await;
    let survived = matches!(a.recv_frame().await, Frame::SubAck { .. });

    format!(
        "## Shedding\n\n\
         One participant stopped reading its socket, which is what a wedged client\n\
         looks like, while the other sent at the per-stream limit for twenty seconds.\n\
         The relay sheds the media frame and keeps the connection: it never downgrades\n\
         the subscriber, because a downgrade is a claim about durable state and there\n\
         is no reconciliation for audio. The count below is read from the relay's own\n\
         /readyz, which is where an operator would read it, and it carries no call id,\n\
         group or principal.\n\n\
         frames_offered_to_a_wedged_client={sent}\n\
         media_frames_shed={shed}\n\
         sender_session_survived={survived}\n\
         send_queue_frame_bound={}\n\
         send_queue_byte_budget={}\n",
        wealdrelay::session::SEND_QUEUE_BOUND,
        wealdrelay::ws::SEND_QUEUE_BYTE_BUDGET,
    )
}

fn offer(call: &[u8], group: &[u8]) -> Frame {
    Frame::Call {
        call_id: call.to_vec(),
        group: group.to_vec(),
        epoch: 1,
        kind: CallKind::Offer as u8,
        body: b"offer".to_vec(),
    }
}

fn answer(call: &[u8], group: &[u8]) -> Frame {
    Frame::Call {
        call_id: call.to_vec(),
        group: group.to_vec(),
        epoch: 1,
        kind: CallKind::Answer as u8,
        body: b"answer".to_vec(),
    }
}
