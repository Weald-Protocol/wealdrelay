// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The real process, started against real dependencies and stopped with a real
//! signal.
//!
//! The other suites drive `serve::run` with a shutdown future, which is how one
//! process can both serve and assert. This one is the counterpart: the relay runs
//! as its own process, answers over a real socket, is sent `SIGTERM` the way an
//! orchestrator stops a container, and is required to exit zero.
//!
//! That last part is the whole point. A relay that ignored `SIGTERM` would be
//! killed rather than stopped by every orchestrator there is, and every deploy
//! would look like a crash in the logs.

use std::io::Read as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Variables the coverage run needs the child to keep.
///
/// `env_clear` is deliberate: a variable set on the developer's machine must not
/// make a test pass that would fail in ci. But clearing everything also clears
/// `LLVM_PROFILE_FILE`, and then the child writes no profile and `src/main.rs`
/// reports as uncovered, which would be a coverage hole created by the test that
/// exists to close it.
fn keep_instrumentation(command: &mut Command) {
    for key in [
        "PATH",
        "HOME",
        "LLVM_PROFILE_FILE",
        "CARGO_LLVM_COV",
        "CARGO_LLVM_COV_TARGET_DIR",
    ] {
        if let Ok(value) = std::env::var(key) {
            command.env(key, value);
        }
    }
}

use sqlx::{Connection, Executor as _, PgConnection};

fn postgres_port() -> String {
    std::env::var("WEALD_STACK_PG_PORT").unwrap_or_else(|_| "54032".to_string())
}

fn admin_url() -> String {
    format!(
        "postgres://weald:weald@127.0.0.1:{}/weald_relay",
        postgres_port()
    )
}

/// Two ports nothing else is using, learned by binding and releasing. There is a
/// race between releasing and the child binding, and it is accepted deliberately:
/// the alternative is a fixed port, which `specs/backend/build/testing.md` forbids
/// because it makes two suites on one machine collide.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn scratch_database(label: &str) -> String {
    let name = format!("weald_step3_proc_{label}_{}", std::process::id());
    let mut admin = PgConnection::connect(&admin_url())
        .await
        .expect("Postgres is not reachable: run `scripts/weald-stack up`");
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

fn get(url: &str) -> Option<(u16, String)> {
    use std::io::Write as _;
    let without_scheme = url.strip_prefix("http://")?;
    let (authority, path) = without_scheme.split_once('/')?;
    let mut stream =
        std::net::TcpStream::connect_timeout(&authority.parse().ok()?, Duration::from_millis(500))
            .ok()?;
    stream
        .write_all(
            format!("GET /{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
    let mut text = String::new();
    stream.read_to_string(&mut text).ok()?;
    let status = text.split_whitespace().nth(1)?.parse().ok()?;
    let body = text.split_once("\r\n\r\n").map_or("", |(_, body)| body);
    Some((status, body.to_string()))
}

/// Poll until the relay answers, or fail with what the process said.
fn wait_for_liveness(port: u16, child: &mut std::process::Child) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("check the child") {
            panic!("the relay exited early with {status:?}");
        }
        if let Some((200, _)) = get(&format!("http://127.0.0.1:{port}/healthz")) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    panic!("the relay never answered /healthz on {port}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_relay_serves_over_real_sockets_and_stops_on_sigterm() {
    let name = scratch_database("sigterm").await;
    let blobs = tempfile::tempdir().unwrap();
    let public = free_port();
    let private = free_port();

    let mut builder = Command::new(env!("CARGO_BIN_EXE_wealdrelay"));
    builder.env_clear();
    keep_instrumentation(&mut builder);
    let mut child = builder
        .env("WEALD_RELAY_HOSTNAME", "localhost")
        .env(
            "WEALD_RELAY_DATABASE_URL",
            format!(
                "postgres://weald:weald@127.0.0.1:{}/{name}",
                postgres_port()
            ),
        )
        .env(
            "WEALD_RELAY_STORAGE_URL",
            format!("file://{}", blobs.path().display()),
        )
        .env("WEALD_RELAY_LISTEN", format!("127.0.0.1:{public}"))
        .env(
            "WEALD_RELAY_OBSERVABILITY_LISTEN",
            format!("127.0.0.1:{private}"),
        )
        .env("WEALD_RELAY_ACCESS_SET", "enforce")
        .env("WEALD_RELAY_RELEASE_CHECK", "off")
        .current_dir(blobs.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the relay");

    wait_for_liveness(public, &mut child);

    // The public listener answers liveness and refuses readiness.
    assert_eq!(
        get(&format!("http://127.0.0.1:{public}/healthz"))
            .expect("a response")
            .0,
        200
    );
    assert_eq!(
        get(&format!("http://127.0.0.1:{public}/readyz"))
            .expect("a response")
            .0,
        404,
        "the public listener must not serve readiness"
    );

    // The private one answers the whole document, and it is truthful: this relay
    // really does have a database and a directory.
    let (status, body) = get(&format!("http://127.0.0.1:{private}/readyz")).expect("a response");
    assert_eq!(status, 200, "{body}");
    let document: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(document["ready"], true, "{body}");
    assert_eq!(document["access_set"], "enforce");
    assert_eq!(document["database"]["ok"], true);
    assert_eq!(document["storage"]["ok"], true);

    // Stop it the way a container is stopped.
    #[cfg(unix)]
    {
        // Safety: the pid is this child's, and `SIGTERM` is the signal the relay
        // installs a handler for.
        let sent = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
        assert_eq!(sent, 0, "SIGTERM could not be delivered");
    }

    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the relay did not stop within twenty seconds of SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    assert_eq!(
        status.code(),
        Some(0),
        "a relay stopped with SIGTERM must exit zero, not look like a crash"
    );

    // The logs it wrote are JSON, and they do not carry the database password.
    let mut logs = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut logs);
    }
    if let Some(mut stderr) = child.stderr.take() {
        let mut extra = String::new();
        let _ = stderr.read_to_string(&mut extra);
        logs.push_str(&extra);
    }
    assert!(
        logs.contains("wealdrelay listening"),
        "the relay did not log that it was listening: {logs}"
    );
    // Every log line is JSON. The first-run enrollment banner is not a log line and
    // is excluded by name rather than by a loosened rule.
    //
    // `specs/backend/relay/server.md` requires both things and they are different
    // things: logs are structured for a collector, and the bootstrap banner is a
    // one-time handoff to the person at the terminal, carrying the invite link, the
    // one-time code and the genesis fingerprint they have to pin. Emitting it as JSON
    // would put the code somewhere a log collector keeps, which is the opposite of a
    // value that exists to be read once and typed. Every one of its lines is prefixed
    // `weald: `, so the exclusion is exact and a stray unstructured log line is still
    // caught. The same run is asserted to contain the banner below, so this exclusion
    // cannot quietly cover an empty case.
    assert!(
        logs.lines()
            .filter(|line| !line.trim().is_empty())
            .filter(|line| !line.trim_start().starts_with("weald: "))
            .all(|line| line.trim_start().starts_with('{')),
        "a log line was not JSON: {logs}"
    );
    // And the banner is there, on a relay whose database has never been enrolled.
    // `server.md`: first run generates a single-use genesis key and prints the
    // enrollment URL. A relay that served without ever printing one would be a relay
    // nobody can join, which is a failure with no error message.
    assert!(
        logs.contains("weald:   invite link")
            && logs.contains("weald:   invite code")
            && logs.contains("weald:   genesis key"),
        "the relay did not print its first-run enrollment banner: {logs}"
    );
    // The scrubbing layer is on the real path, not only in its own unit test.
    assert!(
        !logs.contains("weald:weald"),
        "the relay logged its database credentials: {logs}"
    );

    drop_database(&name).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_process_against_the_same_database_starts_cleanly() {
    // The rolling upgrade, as two processes rather than two calls: `server.md` says
    // an old process and a new one run against the same database during a deploy, so
    // the second one must migrate to a no-op and serve.
    let name = scratch_database("rolling").await;
    let blobs = tempfile::tempdir().unwrap();

    let mut children = Vec::new();
    let mut ports = Vec::new();
    for _ in 0..2 {
        let public = free_port();
        let private = free_port();
        let mut builder = Command::new(env!("CARGO_BIN_EXE_wealdrelay"));
        builder.env_clear();
        keep_instrumentation(&mut builder);
        let mut child = builder
            .env("WEALD_RELAY_HOSTNAME", "localhost")
            .env(
                "WEALD_RELAY_DATABASE_URL",
                format!(
                    "postgres://weald:weald@127.0.0.1:{}/{name}",
                    postgres_port()
                ),
            )
            .env(
                "WEALD_RELAY_STORAGE_URL",
                format!("file://{}", blobs.path().display()),
            )
            .env("WEALD_RELAY_LISTEN", format!("127.0.0.1:{public}"))
            .env(
                "WEALD_RELAY_OBSERVABILITY_LISTEN",
                format!("127.0.0.1:{private}"),
            )
            .env("WEALD_RELAY_RELEASE_CHECK", "off")
            .current_dir(blobs.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the relay");
        wait_for_liveness(public, &mut child);
        children.push(child);
        ports.push(private);
    }

    // Both are ready at once, against one database.
    for private in ports {
        let (status, body) =
            get(&format!("http://127.0.0.1:{private}/readyz")).expect("a response");
        assert_eq!(status, 200, "{body}");
    }

    for mut child in children {
        #[cfg(unix)]
        // Safety: as above.
        unsafe {
            libc::kill(child.id() as i32, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
    }

    drop_database(&name).await;
}
