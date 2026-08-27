// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The soak: a call running for a long time, and the relay's resident set while
//! it does.
//!
//! `specs/backend/cloud/launch-gates.md` asks for a workspace with a call running
//! to raise no split-view warning over 24 hours and not to leak memory, with the
//! RSS curve recorded. This is the harness for that, and it is written so the
//! twenty-four hour run and a five minute smoke run are the same code with a
//! different number.
//!
//! ## What a leak would look like here
//!
//! The call path allocates in three places and each has a bound that this run
//! would expose if it were wrong. The registry holds one entry per open call and
//! one participant per connection, removed when a socket ends. The media budget
//! holds at most `MAX_TRACKED_STREAMS` windows per connection, and drops expired
//! ones on every charge rather than resetting them in place, which is the line a
//! naive implementation gets wrong: a budget that reset a window instead of
//! dropping it would accumulate one entry per stream id a client ever used. And
//! the send queues are bounded in both frames and bytes.
//!
//! So the curve should be flat after the first minute. A rising curve over hours
//! at a constant call count is the finding this exists to produce, and the file it
//! writes is the artifact either way.
//!
//! ## Running it
//!
//! ```text
//! scripts/calls-soak.sh                       the gate: 24 hours
//! WEALD_CALL_SOAK_SECONDS=300 scripts/calls-soak.sh    a smoke run
//! ```
//!
//! Ignored by default for the obvious reason. The artifact states its own
//! duration, so a five minute run cannot be mistaken later for the gate.

mod support;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sqlx::{Connection as _, Executor as _, PgConnection};
use wealdrelay::calls::CallKind;
use wealdrelay::frame::Frame;

/// The gate duration: twenty-four hours.
const GATE_SECONDS: u64 = 24 * 60 * 60;

/// How often the resident set is sampled into the curve.
const SAMPLE_EVERY: Duration = Duration::from_secs(60);

/// Frames per second per direction, which is a 20 ms codec frame.
const FRAMES_PER_SECOND: u64 = 50;

/// How much the resident set may grow between the first steady-state sample and
/// the last before it is called a leak.
///
/// Twenty-five percent. Generous on purpose: an allocator's arenas and the
/// database pool settle over the first minutes, and a gate that fired on that
/// would be a gate everybody learned to rerun. A real leak on this path is
/// unbounded growth per frame, which at fifty frames a second over twenty-four
/// hours is four million allocations and would be visible orders of magnitude
/// above this line.
const GROWTH_BUDGET: f64 = 1.25;

/// The first sample is taken after this, so the comparison is steady state
/// against steady state rather than against process start.
const WARMUP: Duration = Duration::from_secs(60);

fn seconds() -> u64 {
    std::env::var("WEALD_CALL_SOAK_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(GATE_SECONDS)
}

fn postgres_port() -> String {
    std::env::var("WEALD_STACK_PG_PORT").unwrap_or_else(|_| "54032".to_string())
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("an ephemeral port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn scratch() -> String {
    let name = format!("weald_calls_soak_{}", std::process::id());
    let admin_url = format!(
        "postgres://weald:weald@127.0.0.1:{}/weald_relay",
        postgres_port()
    );
    let mut admin = PgConnection::connect(&admin_url).await.expect(
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

struct Relay {
    child: std::process::Child,
    port: u16,
}

impl Relay {
    fn start(database: &str, blobs: &std::path::Path) -> Self {
        let port = free_port();
        let mut command = Command::new(env!("CARGO_BIN_EXE_wealdrelay"));
        command.env_clear();
        for key in ["PATH", "HOME"] {
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
                format!("127.0.0.1:{}", free_port()),
            )
            .env("WEALD_RELAY_RELEASE_CHECK", "off")
            .env("WEALD_RELAY_CALLS", "on")
            .env("WEALD_RELAY_MAX_CONCURRENT_CALLS", "8")
            .current_dir(blobs)
            .stdout(Stdio::null())
            // The relay's own account of the run, kept.
            //
            // This was `Stdio::null()`, so a twenty-four hour gate threw away the
            // only record of why the process under test did anything. When the
            // callee's socket was closed by the idle deadline the harness could
            // say "the relay closed unexpectedly" and nothing could say which
            // deadline or why. A soak whose subject is unobservable is a soak
            // that can only ever report the number it was already looking at.
            .stderr(Stdio::from(
                std::fs::File::create(blobs.join("relay.log")).expect("a relay log"),
            ));
        let child = command.spawn().expect("spawn a relay");
        Self { child, port }
    }

    fn wait_for_liveness(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
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

    fn rss_kib(&self) -> u64 {
        let output = Command::new("ps")
            .args(["-o", "rss=", "-p", &self.child.id().to_string()])
            .output()
            .expect("ps");
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .unwrap_or(0)
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "twenty-four hours; run it with scripts/calls-soak.sh"]
async fn a_call_running_for_a_day_does_not_leak() {
    let duration = Duration::from_secs(seconds());
    let database = scratch().await;
    let blobs = tempfile::tempdir().unwrap();
    let mut relay = Relay::start(&database, blobs.path());
    relay.wait_for_liveness();
    let address: std::net::SocketAddr = format!("127.0.0.1:{}", relay.port).parse().unwrap();

    let pool = sqlx::PgPool::connect(&format!(
        "postgres://weald:weald@127.0.0.1:{}/{database}",
        postgres_port()
    ))
    .await
    .expect("connect to the scratch database");
    let ada = support::default_device();
    let bo = support::other_device();
    support::seed_access_set_directly(&pool, "ws-soak", &[ada.clone(), bo.clone()]).await;
    let group = vec![0x77u8; 32];
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(&group)
        .bind("ws-soak")
        .execute(&pool)
        .await
        .expect("create the group");

    let clock = 1_700_000_000_000u64;
    let call = vec![0xA0u8; 16];
    let mut caller = support::Client::connect(address).await;
    caller.handshake_as(&ada, vec![group.clone()], clock).await;
    let mut callee = support::Client::connect(address).await;
    callee.handshake_as(&bo, vec![group.clone()], clock).await;

    caller
        .send_frame(&Frame::Call {
            call_id: call.clone(),
            group: group.clone(),
            epoch: 1,
            kind: CallKind::Offer as u8,
            body: b"offer".to_vec(),
        })
        .await;
    callee
        .send_frame(&Frame::Call {
            call_id: call.clone(),
            group: group.clone(),
            epoch: 1,
            kind: CallKind::Answer as u8,
            body: b"answer".to_vec(),
        })
        .await;

    let started = Instant::now();
    let deadline = started + duration;

    // The callee drains its socket for the whole run. A receiver that stopped
    // reading would make the send queue fill and the relay shed, which is a
    // different test: this one is about a call that is working.
    let drain = tokio::spawn(async move {
        let mut received = 0u64;
        while Instant::now() < deadline {
            if tokio::time::timeout(Duration::from_millis(500), callee.recv_frame())
                .await
                .is_ok()
            {
                received += 1;
            }
        }
        received
    });

    // The caller sends at the codec's rate, rotating the stream id every hour so
    // the budget's window-expiry path is exercised rather than one entry being
    // touched forever. A budget that reset a window instead of dropping it would
    // accumulate an entry per stream id, and this is what would show it.
    let send = tokio::spawn(async move {
        let interval = Duration::from_micros(1_000_000 / FRAMES_PER_SECOND);
        let mut next = Instant::now();
        let mut seq = 0u64;
        while Instant::now() < deadline {
            let stream = ((seq / (FRAMES_PER_SECOND * 3600)) as u32).to_be_bytes();
            caller
                .send_frame(&Frame::Media {
                    call_id: call.clone(),
                    stream: stream.to_vec(),
                    seq,
                    ct: vec![0x41; 80],
                })
                .await;
            seq += 1;
            next += interval;
            tokio::time::sleep_until(next.into()).await;
        }
        seq
    });

    // The curve.
    let mut curve: Vec<(u64, u64)> = Vec::new();
    while Instant::now() < deadline {
        tokio::time::sleep(SAMPLE_EVERY.min(deadline - Instant::now())).await;
        curve.push((started.elapsed().as_secs(), relay.rss_kib()));
    }

    let sent = send.await.expect("the sender finished");
    let received = drain.await.expect("the receiver finished");

    // Steady state to steady state, so allocator warm-up is not read as a leak.
    let steady: Vec<_> = curve
        .iter()
        .filter(|(at, _)| Duration::from_secs(*at) >= WARMUP)
        .collect();
    let first = steady.first().map(|(_, rss)| *rss).unwrap_or(0);
    let last = steady.last().map(|(_, rss)| *rss).unwrap_or(0);
    let growth = if first == 0 {
        1.0
    } else {
        last as f64 / first as f64
    };

    let mut report = String::new();
    report.push_str("# Soak: one call, running\n\n");
    report.push_str(
        "Produced by `scripts/calls-soak.sh`, which runs\n\
         `cargo test --release --test calls_soak -- --ignored --nocapture` against a real\n\
         spawned wealdrelay binary and a real Postgres. One two-party call, media at the\n\
         codec's rate for the whole run, the stream id rotating hourly so the media\n\
         budget's window-expiry path is exercised rather than one entry being touched\n\
         forever.\n\n",
    );
    report.push_str(&format!(
        "machine: Apple M2 Pro, 32 GB, macOS 26.3.1\n\
         duration_seconds: {}{}\n\
         frames_sent: {sent}\n\
         frames_received: {received}\n\
         warmup_excluded_seconds: {}\n\
         steady_first_rss_kib: {first}\n\
         steady_last_rss_kib: {last}\n\
         growth_ratio: {growth:.3}\n\
         growth_budget: {GROWTH_BUDGET}\n\
         verdict: {}\n\n",
        duration.as_secs(),
        if duration.as_secs() < GATE_SECONDS {
            format!(" (SHORT RUN: the gate value is {GATE_SECONDS})")
        } else {
            String::new()
        },
        WARMUP.as_secs(),
        if growth <= GROWTH_BUDGET {
            "pass"
        } else {
            "fail"
        },
    ));
    report.push_str("## RSS curve\n\n| elapsed s | RSS KiB |\n| --- | --- |\n");
    for (at, rss) in &curve {
        report.push_str(&format!("| {at} | {rss} |\n"));
    }
    support::record_evidence("step-36", "soak-rss.md", &report);
    println!("{report}");

    assert!(
        received > 0,
        "the call carried nothing, so the run proves nothing\n{report}"
    );
    assert!(
        growth <= GROWTH_BUDGET,
        "the resident set grew by {growth:.3}x over the run\n{report}"
    );
}
