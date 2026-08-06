// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Starting the process: dependencies, migrations, two listeners, shutdown.
//!
//! Order matters and is chosen rather than inherited. The relay connects and
//! migrates **before** it binds anything. A relay that answered `/healthz` while
//! its schema was half-applied would be told by an orchestrator that it was fine,
//! and traffic would arrive against a database that could not take it.
//!
//! The two listeners are separate because
//! `specs/backend/relay/server.md` requires them to be: public `/healthz` says
//! nothing but "alive", and detailed readiness binds to loopback by default so a
//! self-hoster running the same digest as the hosted tier does not publish
//! storage, usage or security-state metadata to the internet.

use std::future::IntoFuture as _;
use std::sync::Arc;

use crate::config::Config;
use crate::db::Database;
use crate::health::{private_router, public_router, RelayState};
use crate::EXIT_UNAVAILABLE;

/// Why the process could not start.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("{0}")]
    Database(#[from] crate::db::DbError),
    #[error("{0}")]
    Storage(#[from] crate::storage::StorageError),
    #[error("cannot bind {address}: {reason}")]
    Bind { address: String, reason: String },
}

impl ServeError {
    /// Every startup failure here is a dependency that is not there, which is
    /// `EX_UNAVAILABLE` rather than `EX_CONFIG`: the configuration was valid and
    /// the thing it named did not answer.
    pub fn exit_code(&self) -> i32 {
        EXIT_UNAVAILABLE
    }
}

/// Connect, migrate, bind, and serve until a signal arrives.
pub async fn serve(config: Config) -> Result<(), ServeError> {
    let state = Arc::new(prepare(config).await?);
    let (public, private) = bind(&state).await?;
    run(state, public, private, shutdown()).await;
    Ok(())
}

/// Bind both listeners. Separate from ``run`` so a test can bind port zero and
/// learn the assigned port, which is what
/// `specs/backend/build/testing.md` means by "no shared ports: the harness assigns
/// both".
pub async fn bind(
    state: &Arc<RelayState>,
) -> Result<(tokio::net::TcpListener, tokio::net::TcpListener), ServeError> {
    let public = tokio::net::TcpListener::bind(&state.config.listen)
        .await
        .map_err(|error| ServeError::Bind {
            address: state.config.listen.clone(),
            reason: error.to_string(),
        })?;
    // Nagle off, on the public listener only.
    //
    // `specs/peer-calls.md` section 2: a 20 ms media frame is exactly the traffic
    // Nagle was designed to coalesce, and coalescing it is pure added latency with
    // no bandwidth won, because the frames are already the size they are going to
    // be. The observability listener is left alone: it carries request-response
    // JSON, which is what Nagle is good for.
    set_nodelay(&public);
    let private = tokio::net::TcpListener::bind(&state.config.observability_listen)
        .await
        .map_err(|error| ServeError::Bind {
            address: state.config.observability_listen.clone(),
            reason: error.to_string(),
        })?;
    Ok((public, private))
}

/// `TCP_NODELAY`, set on the listening socket so every socket accepted from it
/// inherits it.
///
/// ## Why the listener and not the connection
///
/// Because there is no connection to reach. `axum::serve` in 0.7 takes a
/// `tokio::net::TcpListener` by value and accepts inside its own loop; the
/// accepted `TcpStream` is never handed to this crate, and `IncomingStream`
/// exposes two addresses and no socket. Reaching it would mean either a direct
/// `hyper` dependency and a hand-rolled accept loop, or a different HTTP crate,
/// and `specs/peer-calls.md` section 4 spends the whole dependency budget on
/// having neither.
///
/// Inheritance is a real guarantee rather than a hope, and it is asserted rather
/// than assumed: `tests/nodelay.rs` sets the option on a listener, accepts a real
/// connection and reads the option back off the accepted socket, so the platform
/// the suite runs on has proved it. Both platforms this relay runs on copy the
/// option to the child socket, Linux through `sk_clone_lock` and Darwin through
/// `sonewconn`.
///
/// ## Why the FFI is written out here
///
/// Neither `std` nor `tokio` exposes `setsockopt` on a listener, and the crates
/// that do (`socket2`, `libc` as a runtime dependency) are crates. The zero new
/// crates rule in `specs/peer-calls.md` section 4 is not a stylistic preference:
/// three independent builders have to agree on this image's digest
/// (`specs/backend/relay/verification.md`), and every dependency is a thing they
/// each have to fetch and agree about. Two constants and one extern declaration
/// is a smaller surface than a crate, and both constants are fixed by POSIX and
/// identical on every platform this builds for.
///
/// A failure is logged and not fatal. Nagle costs latency on a call and nothing
/// at all on chat, so a relay that could not clear it is degraded rather than
/// broken, and refusing to start would take a working chat relay down for a
/// feature that may be switched off.
fn set_nodelay(listener: &tokio::net::TcpListener) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;

        // POSIX: `IPPROTO_TCP` is 6 by the IANA protocol number, and
        // `TCP_NODELAY` is 1 on Linux and on every BSD including Darwin.
        const IPPROTO_TCP: i32 = 6;
        const TCP_NODELAY: i32 = 1;

        extern "C" {
            fn setsockopt(
                socket: i32,
                level: i32,
                name: i32,
                value: *const core::ffi::c_void,
                len: u32,
            ) -> i32;
        }

        let enable: i32 = 1;
        // Safety: the file descriptor is owned by `listener` and outlives this
        // call, and the pointer is to a live `i32` whose length is passed
        // alongside it, which is the contract `setsockopt` documents for an
        // integer-valued option.
        let outcome = unsafe {
            setsockopt(
                listener.as_raw_fd(),
                IPPROTO_TCP,
                TCP_NODELAY,
                std::ptr::addr_of!(enable).cast(),
                u32::try_from(std::mem::size_of::<i32>()).unwrap_or(4),
            )
        };
        if outcome != 0 {
            let reason = std::io::Error::last_os_error().to_string();
            tracing::warn!(
                reason,
                "could not clear Nagle on the public listener; call latency will include the \
                 coalescing delay"
            );
        }
    }
}

/// The same call the relay makes on its own listener, reachable from a test.
///
/// Public because the property it depends on is a platform one: an accepted
/// socket inherits the option from the socket it was accepted on. That cannot be
/// asserted through `bind`, because `axum::serve` owns the accept loop and never
/// yields the accepted stream, so `tests/calls_capacity.rs` performs its own
/// accept against this exact function. A test that reimplemented the `setsockopt`
/// would be a test of the test.
pub fn set_nodelay_for_test(listener: &tokio::net::TcpListener) {
    set_nodelay(listener);
}

/// Serve both routers until `until` completes.
///
/// The shutdown future is a parameter rather than a call to ``shutdown`` inside,
/// so this function is reachable from a test without sending the test process a
/// signal. The signal path is proven separately, by the integration suite sending
/// `SIGTERM` to the real binary.
pub async fn run(
    state: Arc<RelayState>,
    public: tokio::net::TcpListener,
    private: tokio::net::TcpListener,
    until: impl std::future::Future<Output = ()>,
) {
    // Every field is computed into a local before the macro rather than written
    // inside it. This is the line an operator reads to learn which addresses the
    // relay bound and what posture it is enforcing, and as ordinary statements the
    // expressions behind it are ordinary covered code rather than macro output.
    let described = state
        .storage
        .as_ref()
        .map_or_else(|| "none".to_string(), |store| store.describe());
    let listen = state.config.listen.as_str();
    let observability_listen = state.config.observability_listen.as_str();
    let storage = described.as_str();
    let access_set = state.config.access_set_label();
    let min_enc = state.config.min_enc_label();
    tracing::info!(
        listen,
        observability_listen,
        storage,
        access_set,
        min_enc,
        "wealdrelay listening"
    );

    // No graceful-shutdown future on either listener. The server futures are
    // spawned directly rather than inside an `async move` block, so there is no
    // code after the await that an aborted task could never run.
    //
    // The public listener now carries the relay socket as well as `/healthz`, so a
    // client connection is aborted along with the listener when the process stops.
    // That is the right outcome for this step: a session holds no uncommitted
    // state, because `accept` commits before it acknowledges, so a client that
    // loses its socket mid-write either sees the acknowledgement or retries and is
    // answered with the same sequence number.
    let public_state = Arc::clone(&state);
    let public_task = tokio::spawn(
        // With connection info, because the redeem path is rate limited per source
        // (`specs/backend/relay/invites.md`, "Rate limits") and a relay that could
        // not tell two sources apart would apply one budget to the whole internet.
        axum::serve(
            public,
            public_router(public_state)
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .into_future(),
    );
    let private_state = Arc::clone(&state);
    let private_task = tokio::spawn(
        axum::serve(private, private_router(private_state).into_make_service()).into_future(),
    );

    // The wake worker, when push is on. Started here rather than in `prepare`,
    // because `prepare` is also what `--check-config` and the store suites drive and
    // neither of those should have an outbound leg running behind them. `None` when
    // push is off, which is the default and a supported deployment.
    let push_worker = crate::push::spawn(&state);

    until.await;
    public_task.abort();
    private_task.abort();
    if let Some(worker) = push_worker {
        // Aborted rather than awaited. The worker's loop has no exit and nothing it
        // holds needs unwinding: a wake in flight is best effort by construction, and
        // a wake still in the queue is one the client's reconciliation covers.
        worker.abort();
    }
    tracing::info!("wealdrelay stopped");
}

/// Everything that has to work before a socket is opened.
///
/// Public because the integration suite drives it directly: the proof that
/// migrations run from zero and that `/readyz` is truthful is a proof about this
/// function, and going through a spawned process to reach it would make the
/// failure harder to read without making it more real. The suite also runs the
/// built binary, for the parts that are about the process.
pub async fn prepare(config: Config) -> Result<RelayState, ServeError> {
    let database =
        Database::connect_with_pool_size(&config.database_url, config.db_pool_size).await?;
    // Migrations before the listener, not after: see the module comment.
    database.migrate().await?;
    bootstrap(&database, &config).await;
    let storage = crate::storage::open(&config.storage).await?;
    Ok(RelayState::new(
        config,
        Some(database),
        Some(Arc::new(storage)),
    ))
}

/// The workspace id a fresh relay bootstraps.
///
/// `specs/backend/relay/server.md` describes bootstrap as a property of the relay
/// rather than of a workspace: first run generates one single-use genesis key and
/// prints one enrollment URL, and the first device to open it becomes the trust
/// root. A relay serves one instance, so its own hostname is the identity that key
/// belongs to, and deriving the id from it means a relay restarted with the same
/// configuration bootstraps the same workspace rather than a second one.
pub fn bootstrap_workspace(hostname: &str) -> String {
    format!("ws:{hostname}")
}

/// Mint the genesis key on first run, and print what a self-hoster has to pin.
///
/// `server.md`, "Bootstrap": first run migrates the schema and generates a single-use
/// genesis key, then prints the enrollment URL carrying the hostname and the
/// genesis-key fingerprint. Redemption destroys the key and writes entry zero of the
/// transparency log, so this is where a workspace's history starts.
///
/// Deliberately not fatal. A relay that could not mint one is a relay that cannot be
/// enrolled *yet*, which is a condition `/readyz` reports and an operator fixes; it is
/// not a reason to refuse to serve a workspace that was enrolled last year. The
/// alternative would let one unreachable table take down an instance that had no need
/// of it.
pub async fn bootstrap(database: &Database, config: &Config) {
    let workspace = bootstrap_workspace(&config.hostname);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis() as i64)
        .unwrap_or_default();
    match crate::invite::genesis::ensure(database.pool(), &workspace, now).await {
        Ok(crate::invite::genesis::Ensured::Minted(run)) => {
            // To stdout, once, and never again for this relay. The code is in it
            // because for a self-hoster the genesis key never left their machine;
            // `genesis::banner` says why at more length.
            println!("{}", crate::invite::genesis::banner(&config.hostname, &run));
            // Rendered before the macro rather than inside it. A `tracing` field
            // expression is evaluated only when a subscriber wants the record, so an
            // expression written inline is code that does not run when nothing is
            // listening, which is every test in this crate.
            let fingerprint = crate::invite::genesis::hex(&run.fingerprint);
            tracing::info!(
                workspace = %workspace,
                fingerprint = %fingerprint,
                "minted the genesis key"
            );
        }
        Ok(crate::invite::genesis::Ensured::Existing {
            fingerprint,
            redeemed,
            token,
            ..
        }) => {
            // Reprint the link while the workspace is still empty. The banner is
            // printed once, at mint, and an operator who lost that scrollback used
            // to have no way back: the link was recoverable from the database all
            // along and nothing showed it to them. The code is not reprinted and
            // cannot be, which `genesis::reminder` says out loud so nobody goes
            // looking for a reissue flag that must never exist.
            if !redeemed {
                println!(
                    "{}",
                    crate::invite::genesis::reminder(&config.hostname, &token, &fingerprint)
                );
            }
            let fingerprint = crate::invite::genesis::hex(&fingerprint);
            tracing::info!(
                workspace = %workspace,
                fingerprint = %fingerprint,
                redeemed,
                "genesis key already exists"
            );
        }
        Err(error) => {
            let reason = crate::logging::scrub(&error.to_string());
            tracing::warn!(
                workspace = %workspace,
                error = %reason,
                "could not mint a genesis key; this relay cannot be enrolled until it can"
            );
        }
    }
}

/// Wait for a signal. `SIGTERM` as well as `SIGINT`, because a container is
/// stopped with the first and a terminal with the second, and a relay that only
/// handled `SIGINT` would be killed rather than stopped by every orchestrator
/// there is.
pub async fn shutdown() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = on_terminate(tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate(),
    ));
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => tracing::info!("shutting down on interrupt"),
        () = terminate => tracing::info!("shutting down on terminate"),
    }
}

/// Wait on a `SIGTERM` stream, or forever if the handler could not be installed.
///
/// Public, and taking the fallible result rather than producing it, for the same
/// reason `crate::storage::object_name` is shaped that way: an operating system
/// that refuses to install a `SIGTERM` handler cannot be produced by a hermetic
/// test, and as a function over the result it can be handed one. The behaviour it
/// protects is that a process which cannot install the handler still stops on
/// `SIGINT`, because refusing to start over it would be worse than the gap.
#[cfg(unix)]
pub async fn on_terminate(stream: std::io::Result<tokio::signal::unix::Signal>) {
    match stream {
        Ok(mut stream) => {
            stream.recv().await;
        }
        Err(_) => std::future::pending::<()>().await,
    }
}
