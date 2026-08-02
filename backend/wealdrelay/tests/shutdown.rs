// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `serve` and `shutdown`, driven in this process by real signals.
//!
//! `specs/backend/relay/server.md` requires the relay to stop on `SIGTERM` as well
//! as `SIGINT`, because a container is stopped with the first and a terminal with
//! the second, and a relay that only handled `SIGINT` would be killed rather than
//! stopped by every orchestrator there is. `tests/process.rs` proves that against
//! the spawned binary, which is the proof that matters to an operator. This file
//! proves the same thing about the functions, so a change to the select that broke
//! one arm fails in a test that names the arm.
//!
//! **There is exactly one test in this file, and that is deliberate.** Signal
//! handling is process-wide: a raised `SIGINT` is delivered to whatever else in the
//! same binary happens to be waiting on one. Cargo gives each integration test file
//! its own process, so one test here disturbs nothing.
//!
//! The handlers are installed before anything is raised. A `SIGTERM` arriving at a
//! process with no handler installed for it terminates that process, and the
//! process in question is the test runner.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sqlx::{Connection as _, Executor as _, PgConnection};
use wealdrelay::config::{keys, Config, Values};
use wealdrelay::serve;

/// Where the harness puts Postgres, matching `tests/integration.rs`. Overridable
/// by the same variable the harness uses, so a machine already running something
/// on 54032 configures both in one place.
fn postgres_port() -> String {
    std::env::var("WEALD_STACK_PG_PORT").unwrap_or_else(|_| "54032".to_string())
}

fn admin_url() -> String {
    format!(
        "postgres://weald:weald@127.0.0.1:{}/weald_relay",
        postgres_port()
    )
}

/// A database of its own, dropped at the end. This is an integration test and it
/// fails rather than skips: a shutdown proof that reported success without ever
/// having started the relay would be worse than no proof at all.
struct Scratch {
    name: String,
    url: String,
}

impl Scratch {
    async fn new(label: &str) -> Self {
        let name = format!("weald_shutdown_{label}_{}", std::process::id());
        let mut admin = PgConnection::connect(&admin_url())
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "Postgres is not reachable on 127.0.0.1:{}: {error}. This is an integration \
                 test and it does not skip: run `scripts/weald-stack up` and try again.",
                    postgres_port()
                )
            });
        admin
            .execute(format!("drop database if exists {name}").as_str())
            .await
            .expect("drop any leftover scratch database");
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

    async fn drop_database(&self) {
        let Ok(mut admin) = PgConnection::connect(&admin_url()).await else {
            return;
        };
        let _ = admin
            .execute(format!("drop database if exists {} with (force)", self.name).as_str())
            .await;
    }
}

fn config_for(url: &str, blobs: &std::path::Path, listen: &str) -> Config {
    Config::resolve(&Values::from_pairs([
        (keys::HOSTNAME, "localhost".to_string()),
        (keys::DATABASE_URL, url.to_string()),
        (keys::STORAGE_URL, format!("file://{}", blobs.display())),
        // Port zero on both, so this test shares no port with any other.
        (keys::LISTEN, listen.to_string()),
        (keys::OBSERVABILITY_LISTEN, "127.0.0.1:0".to_string()),
        (keys::ACCESS_SET, "enforce".to_string()),
        // Off, so no test makes an outbound request to the release feed.
        (keys::RELEASE_CHECK, "off".to_string()),
    ]))
    .expect("the shutdown configuration resolves")
}

/// Run `serve` and send the process `signal` until it stops, or fail loudly.
///
/// `serve` is awaited on this task rather than spawned. The future holds a sqlx
/// connection across an await and the compiler cannot prove it `Send` when it is
/// the argument to `tokio::spawn`, so the signals come from a plain thread beside
/// it instead.
///
/// Raised in a loop rather than once after a sleep. The relay installs its own
/// handlers somewhere inside `serve`, and a single raise timed against a sleep
/// would be a race that passes on a quiet machine and hangs on a busy one.
/// Repeating is harmless: the keepers the test holds absorb every extra one.
async fn serve_until(config: Config, signal: i32, name: &str) {
    let stop = Arc::new(AtomicBool::new(false));
    let raiser = std::thread::spawn({
        let stop = Arc::clone(&stop);
        move || {
            while !stop.load(Ordering::Relaxed) {
                // Safety: the handler for this signal is installed for the lifetime
                // of the test, so the default action of terminating the test runner
                // cannot happen. Sent to the process rather than to this thread, so
                // the kernel delivers it wherever it is not blocked.
                unsafe {
                    libc::kill(libc::getpid(), signal);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    });

    let outcome = tokio::time::timeout(Duration::from_secs(60), serve::serve(config)).await;
    stop.store(true, Ordering::Relaxed);
    raiser.join().expect("the signalling thread must not panic");

    outcome
        .unwrap_or_else(|_| panic!("the relay did not stop on {name}"))
        .unwrap_or_else(|error| panic!("serving must end cleanly on {name}, got {error}"));
}

#[test]
fn the_relay_serves_until_a_signal_and_reports_a_listener_it_cannot_bind() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime for the whole test");

    runtime.block_on(async {
        // The subscriber, so the startup line is really formatted rather than
        // skipped by a disabled callsite. That line is what an operator reads to
        // learn which addresses the relay bound and what posture it is enforcing,
        // and a field that panicked when rendered would only ever show up here.
        let _ = wealdrelay::logging::install("info");

        // Installed first and held for the whole test. Everything below raises
        // signals at this process, and a raise that landed before a handler existed
        // would kill the test runner rather than fail a test.
        let _sigint_keeper =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .expect("install a SIGINT handler for the lifetime of the test");
        let _sigterm_keeper =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install a SIGTERM handler for the lifetime of the test");

        let scratch = Scratch::new("signals").await;
        let blobs = tempfile::tempdir().expect("a scratch blob directory");

        // A terminal stops the relay with SIGINT.
        serve_until(
            config_for(&scratch.url, blobs.path(), "127.0.0.1:0"),
            libc::SIGINT,
            "SIGINT",
        )
        .await;

        // An orchestrator stops it with SIGTERM. Both arms of the select, because a
        // relay that only handled one would be killed rather than stopped by
        // whichever half of the world uses the other.
        serve_until(
            config_for(&scratch.url, blobs.path(), "127.0.0.1:0"),
            libc::SIGTERM,
            "SIGTERM",
        )
        .await;

        // A port already in use is reported by `serve` rather than swallowed. The
        // relay connects and migrates before it binds, so this failure happens
        // after the database is real and it still has to come back as a typed
        // error naming the address the operator has to change.
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("take a port");
        let address = occupied.local_addr().expect("local address").to_string();
        let error = serve::serve(config_for(&scratch.url, blobs.path(), &address))
            .await
            .expect_err("a port already in use must refuse");
        assert!(
            matches!(error, wealdrelay::serve::ServeError::Bind { .. }),
            "expected a bind failure, got {error}"
        );
        assert!(error.to_string().contains(&address), "{error}");
        assert_eq!(error.exit_code(), 69);
        drop(occupied);

        // A process that cannot install a `SIGTERM` handler still has to stop on
        // `SIGINT`, so the terminate half of the select waits forever rather than
        // completing and shutting the relay down the moment it started. No
        // operating system this runs on refuses to install the handler, so the case
        // is given to the function directly.
        let never = serve::on_terminate(Err(std::io::Error::other(
            "this kernel will not install a SIGTERM handler",
        )));
        assert!(
            tokio::time::timeout(Duration::from_millis(250), never)
                .await
                .is_err(),
            "a terminate handler that could not be installed must never fire"
        );

        // And the shape the relay actually uses is a stream, which fires once.
        let stream = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install a SIGTERM handler");
        let fired = tokio::spawn(serve::on_terminate(Ok(stream)));
        while !fired.is_finished() {
            // Safety: the keeper above holds the handler open.
            unsafe {
                libc::raise(libc::SIGTERM);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        fired.await.expect("the terminate wait must not panic");

        scratch.drop_database().await;
    });
}
