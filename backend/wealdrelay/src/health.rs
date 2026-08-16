// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The two health surfaces, and why they are two.
//!
//! `specs/backend/relay/server.md`: "The public listener serves only `/healthz`
//! and gives no state beyond liveness; detailed readiness and metrics bind to
//! `WEALD_RELAY_OBSERVABILITY_LISTEN`, loopback by default."
//!
//! That split is the whole design of this module. It exists so the same image
//! digest is usable by a self-hoster without publishing storage, usage or
//! security-state metadata to the internet. A single `/readyz` on the public
//! listener would tell any passer-by how much storage a workspace uses, whether
//! access-set enforcement is on, and whether the build is behind a security
//! release. Each of those is a gift to somebody choosing a target.
//!
//! The direction is also fixed: the control plane **polls** these, and the relay
//! never initiates (`specs/backend/contracts/decisions/ADR-0007-one-way-polling.md`).
//! Nothing here makes an outbound request.

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::config::{Config, WriteMode};
use crate::db::Database;
use crate::storage::Store;

/// What a dependency check found. Serialised as an object rather than a boolean so
/// the reason travels with the answer: an operator reading `/readyz` needs to know
/// which of the two dependencies is down and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DependencyState {
    pub ok: bool,
    /// Absent when `ok`. Never a credential: `/readyz` output goes in a support
    /// ticket, and the connection URL's password would go with it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl DependencyState {
    pub fn up() -> Self {
        Self {
            ok: true,
            detail: None,
        }
    }

    pub fn down(detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            detail: Some(crate::logging::scrub(&detail.into())),
        }
    }
}

/// The result of the release check. `server.md` distinguishes two things a client
/// must render differently: a digest that does not match its source tag is an
/// alarm, and a digest that is merely older than the latest release is a chore.
/// Rendering the second as the first is how a security banner gets trained into
/// background noise, so the two are separate states here rather than one boolean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ReleaseState {
    /// `WEALD_RELAY_RELEASE_CHECK=off`, for air-gapped installs.
    Disabled,
    /// On, and no check has completed yet. Distinct from `current`: a relay that
    /// has not checked is not a relay that is up to date.
    Unknown,
    Current,
    Behind {
        latest: String,
    },
    /// The feed could not be read. Also not `current`.
    Unreachable {
        detail: String,
    },
}

/// The private readiness document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Readiness {
    pub build: String,
    pub version: String,
    pub database: DependencyState,
    pub storage: DependencyState,
    /// The field step 3's artifact must contain. `enforce` or `off`, and a relay
    /// running `off` says so here because a customer should not have to read their
    /// operator's environment file to learn it.
    pub access_set: &'static str,
    /// `none` or `mls`. Under `none` the client surfaces an explicit "this relay
    /// accepts unencrypted envelopes" state, so the setting has to be reported
    /// rather than left to an operator's memory.
    pub min_enc: &'static str,
    pub write_mode: &'static str,
    /// Present only under `read_only`, and never content-derived: a client is told
    /// why durable writes are refused without being told anything about the data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_mode_reason: Option<&'static str>,
    /// Groups whose retention control chain is contested. Group ids only, which are
    /// opaque.
    pub frozen_groups: Vec<String>,
    pub release: ReleaseState,
    /// The push posture: `off`, `configured` or `unreachable`.
    ///
    /// Reported for the reason `access_set` and `calls` are, and with one extra
    /// consequence stated in `specs/backend/relay/push.md` section 5: `unreachable`
    /// is **not** un-ready. A relay whose ringer is down still accepts, stores and
    /// serves, and taking a whole deployment out of a load balancer for a best-effort
    /// side channel would be a self-inflicted outage.
    pub push: &'static str,
    /// The call posture: `on` or `off`, reported for the reason `access_set` and
    /// `min_enc` are. A customer whose calls do not connect should be able to see
    /// that this relay does not carry them, rather than reading their operator's
    /// environment file or concluding the network is broken.
    pub calls: &'static str,
    /// The four operator counters the call path produces. Capacity, never
    /// identity: not one of them is per call, per group or per principal, because
    /// a labelled count here would be exactly the metadata `crate::hub` refuses to
    /// hold. `specs/backend/relay/calls.md`.
    pub call_stats: CallStats,
    /// What the Postgres pool is doing. The signal a hosted resize is driven by,
    /// and the one an operator sizing their own instance needs.
    pub db_pool: PoolStats,
    /// Whether the relay would accept a durable write right now. The one-line
    /// answer, so a poller does not have to reimplement the conjunction.
    pub ready: bool,
}

/// The Postgres pool, as three numbers.
///
/// Reported because the pool ceiling is the relay's hardest capacity limit and
/// the least visible one. `specs/backend/cloud/provisioning.md` promises resize
/// is metric-driven, and a database resize needs a metric about the database:
/// CPU on the relay's own container says nothing about a pool that is fully
/// checked out, and the symptom of an undersized pool is an `acquire_timeout`
/// that looks like a relay defect from every other vantage point.
///
/// Capacity, never identity: no group, no principal, no query. Three integers
/// about this process's own connections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PoolStats {
    /// The ceiling, from `WEALD_RELAY_DB_POOL_SIZE`.
    pub size: u32,
    /// Connections the pool holds right now, busy or idle.
    pub connections: u32,
    /// Of those, the ones checked out to a query at this instant.
    ///
    /// Equal to `size` is the state that matters: every further caller is waiting
    /// on `acquire_timeout`, and a relay that sits there is one whose database is
    /// too small or whose pool is, which are different fixes with the same
    /// symptom.
    pub in_use: u32,
}

/// What an operator can see about calls, and the whole of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallStats {
    /// Calls open on this process right now.
    pub open: u64,
    /// Media frames dropped because a recipient's queue was full, since start.
    ///
    /// The capacity signal the shed rule is observable through. A relay shedding
    /// audio is one whose subscribers cannot keep up, and an operator needs to see
    /// that; the affected client is deliberately not told, because the next frame
    /// is 20 ms away and a downgrade would be a lie about its durable log.
    pub media_shed: u64,
    /// Media frames refused because the sender was not in the call it named.
    pub media_denied: u64,
    /// Calls refused because one connection already held its share of the call
    /// table, since start.
    ///
    /// Beside `open` for the reason `connections_closed_handshake_deadline` sits
    /// beside `connections_refused`: a call table at its ceiling is answered by
    /// raising the ceiling, and one connection holding a quarter of it is answered
    /// at the edge. Non-zero with `open` nowhere near the ceiling is a client loop
    /// regenerating its call id, or somebody parking on the table.
    pub calls_share_refused: u64,
    /// Client sockets open now, and how many have been refused at the cap since
    /// start.
    pub connections: u64,
    pub connections_refused: u64,
    /// Connections closed because they never authenticated inside
    /// `WEALD_RELAY_HANDSHAKE_TIMEOUT_MS`, since start.
    ///
    /// Beside `connections_refused` rather than folded into it, because the two
    /// say opposite things about the same relay. A rising `connections_refused`
    /// is a relay at its ceiling, which an operator answers by raising the
    /// ceiling or adding an instance. A rising
    /// `connections_closed_handshake_deadline` against a connection count that is
    /// nowhere near the ceiling is somebody parking on the connection table, which
    /// an operator answers at the edge and never by raising anything. Without the
    /// counter both look identical from outside: connections that ended, which is
    /// also what a crash looks like.
    pub connections_closed_handshake_deadline: u64,
    /// Outbound frames refused at the wire cap and answered with a close. See
    /// `RelayState::oversized_outbound_frames`; any non-zero value is a relay
    /// bug an operator should report, never client behaviour.
    pub oversized_outbound_frames: u64,
    /// Connections closed because an authenticated peer went silent for
    /// `WEALD_RELAY_IDLE_TIMEOUT_MS` and then did not answer the liveness ping,
    /// since start.
    ///
    /// Expected to be non-zero on any real deployment: laptops close and mobile
    /// networks drop connections without a FIN, and this is the count of sockets
    /// reclaimed from peers that had already gone. It is a fleet-health signal
    /// rather than an alarm, and it is what distinguishes that ordinary attrition
    /// from the deliberate case the counter above records.
    pub connections_closed_idle_deadline: u64,
}

/// Everything the readiness document needs, gathered once per request.
///
/// Gathered per request and not cached. `/readyz` reports reachability, and a
/// cached answer would report a database that went away five minutes ago as
/// healthy, which is worse than not reporting at all because somebody would act
/// on it.
#[derive(Debug)]
pub struct RelayState {
    pub config: Config,
    pub database: Option<Database>,
    pub storage: Option<Arc<Store>>,
    pub build: crate::BuildInfo,
    /// The clock, injected. `specs/backend/build/testing.md` forbids a wall-clock
    /// read inside anything under test, and every expiry the relay owns is
    /// evaluated against its own observed time, so there is exactly one place that
    /// reads it and everything else is a function of what it returned.
    pub clock: Clock,
    /// Set by the release-check timer. Read here, never written here: this module
    /// makes no outbound request.
    pub release: std::sync::RwLock<ReleaseState>,
    /// Who is subscribed to what, for the live push path
    /// (`specs/backend/relay/wire.md`, the sync section). Group ids and connection
    /// handles only: see `crate::hub` for why nothing else may go in it.
    pub hub: crate::hub::Hub,
    /// Signs the local presigned-URL tokens `media::http` issues when storage is
    /// the filesystem backend. `environments.md` runs the filesystem backend only
    /// in `local`, where there is no real object storage to presign a request
    /// against, so the relay stands in for one over its own public listener; this
    /// is the process secret that makes those tokens unforgeable. Unused, and
    /// never read, when storage is S3-compatible.
    pub media_presign_secret: [u8; 32],
    /// The per-device download budget: 50 requests/minute, 5 GB/day
    /// (`specs/backend/relay/media.md`, "Bandwidth"), process-local and shared by
    /// every connection this relay serves.
    pub media_rate: crate::media::RateLimiter,
    /// The per-device inbound budget on `SEND` (`crate::send_budget`), process-local
    /// and shared by every connection this relay serves. Beside `media_rate`
    /// rather than inside it, because they bound different paths with different
    /// windows and merging them would have made one limiter answer two questions.
    pub send_budget: crate::send_budget::SendBudget,
    /// The calls this process is carrying, and the only place call state lives.
    ///
    /// Beside the hub rather than inside it, because the hub's map is group to
    /// connection and a call is a narrower thing: two to five of a group's
    /// subscribers, for a few minutes. Merging them would have made the hub's one
    /// invariant (it holds a group id and a connection handle and nothing else)
    /// harder to state.
    pub calls: crate::calls::CallRegistry,
    /// How many client sockets are open, against
    /// `WEALD_RELAY_MAX_CONNECTIONS`.
    ///
    /// An `AtomicUsize` and not a semaphore: the cap is checked and incremented at
    /// the upgrade and decremented when the reader loop ends, and there is no
    /// caller that should ever wait for a slot. A relay at its ceiling refuses now
    /// rather than holding a request open until somebody else leaves.
    pub connections: std::sync::atomic::AtomicUsize,
    /// Pre-authentication connection counts by a process-local, keyed hash of the
    /// transport source. The address never leaves this map as plaintext and every
    /// entry is removed as soon as its socket authenticates or closes.
    /// `tokio::sync::Mutex` rather than `std::sync::Mutex`, for the reason
    /// `hub.rs` gives: the std lock poisons on a panic, and this lock guards
    /// whether a socket may be opened at all, so a single poisoning panic would
    /// refuse every future connection for the life of the process while
    /// `/healthz` kept answering. A lock with no poisoning has no recovery arm
    /// to leave uncovered.
    unauthenticated_connections_by_source: tokio::sync::Mutex<HashMap<[u8; 32], usize>>,
    /// Key for `unauthenticated_connections_by_source`, generated at startup and
    /// deliberately not shared with the invite source-hash salt or any persisted
    /// data.
    unauthenticated_connection_source_key: [u8; 32],
    /// How many connections were refused because the cap was reached. An operator
    /// counter with no label: capacity, never identity.
    pub connections_refused: std::sync::atomic::AtomicU64,
    /// Connections closed on the handshake deadline, and on the idle deadline.
    ///
    /// Counters with no label, exactly like `connections_refused`: capacity and
    /// liveness, never identity. A per-source breakdown would be the address the
    /// invite path goes out of its way to hash before it reaches a table, kept in
    /// memory and served on an operator surface, so there is a number and no map.
    pub handshake_deadline_closes: std::sync::atomic::AtomicU64,
    pub idle_deadline_closes: std::sync::atomic::AtomicU64,
    /// Outbound frames the relay built over `MAX_FRAME_BYTES` and refused to
    /// write. Every conforming peer rejects such a frame by the same symmetric
    /// gate the relay applies inbound, so writing one is a silent wedge; the
    /// writer drops it, closes the connection with a real error, and counts it
    /// here so the failure is attributable. Any non-zero value is a relay bug.
    pub oversized_outbound_frames: std::sync::atomic::AtomicU64,
    /// The wake path: the bounded queue, the settings and the counters
    /// (`crate::push`). Present whether push is on or off, because a relay with push
    /// off still has to answer a `Query` with `enabled: false` and still has to say
    /// `off` on `/readyz`, and an `Option` here would have put a "no push path
    /// configured" arm on every one of those call sites.
    pub push: crate::push::Push,
    /// The five-per-hour-per-principal registration ceiling. Process-local, shared by
    /// every connection this relay serves, and keyed by entry hash so a device that
    /// reconnects does not get a fresh allowance.
    pub push_rate: crate::push::store::RateLimiter,
}

impl RelayState {
    pub fn new(config: Config, database: Option<Database>, storage: Option<Arc<Store>>) -> Self {
        let release = if config.release_check {
            ReleaseState::Unknown
        } else {
            ReleaseState::Disabled
        };
        // Read before `config` is moved into the struct. `None` is only reachable
        // with calls off, where the registry is never consulted, and zero is then
        // the honest ceiling rather than a number nobody chose.
        let max_concurrent_calls =
            usize::try_from(config.max_concurrent_calls.unwrap_or(0)).unwrap_or(usize::MAX);
        // Built before `config` is moved, for the reason the call ceiling is read
        // first: this reads six of its fields and the struct owns it afterwards.
        let push = crate::push::Push::from_config(&config);
        // Built before `config` moves, for the reason `push` is: it reads two of
        // its fields and the struct owns it afterwards.
        let send_budget = crate::send_budget::budget_from(&config);
        Self {
            config,
            database,
            storage,
            build: crate::BuildInfo::current(),
            clock: Clock::System,
            release: std::sync::RwLock::new(release),
            hub: crate::hub::Hub::new(),
            media_presign_secret: random_secret(),
            media_rate: crate::media::default_rate_limiter(),
            send_budget,
            calls: crate::calls::CallRegistry::new(max_concurrent_calls),
            connections: std::sync::atomic::AtomicUsize::new(0),
            unauthenticated_connections_by_source: tokio::sync::Mutex::new(HashMap::new()),
            unauthenticated_connection_source_key: random_secret(),
            connections_refused: std::sync::atomic::AtomicU64::new(0),
            handshake_deadline_closes: std::sync::atomic::AtomicU64::new(0),
            idle_deadline_closes: std::sync::atomic::AtomicU64::new(0),
            oversized_outbound_frames: std::sync::atomic::AtomicU64::new(0),
            push,
            push_rate: crate::push::store::RateLimiter::new(),
        }
    }

    /// Take one connection slot, or refuse.
    ///
    /// The check and the increment are one `fetch_update`, so two sockets arriving
    /// in the same instant cannot both be told there was room for the last slot.
    /// That is the whole reason this is not a read followed by an add.
    pub async fn admit_connection(&self, source: Option<&str>) -> bool {
        use std::sync::atomic::Ordering;

        let Some(ceiling) = self.connection_ceiling() else {
            self.connections.fetch_add(1, Ordering::Relaxed);
            return true;
        };
        // A source may occupy at most one quarter of a finite connection table
        // before it authenticates. This leaves at least three quarters for other
        // sources while an attacker continuously replaces handshake-expired
        // sockets. The share is a pre-authentication control only: it is released
        // on `AUTH_ACK`, so a NAT cannot cap its own authenticated users.
        let source_ceiling = (ceiling / 4).max(1);
        let source = self.connection_source(source);
        let mut sources = self.unauthenticated_connections_by_source.lock().await;
        if sources.get(&source).copied().unwrap_or(0) >= source_ceiling {
            self.connections_refused.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let taken = self
            .connections
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |open| {
                (open < ceiling).then_some(open + 1)
            });
        if taken.is_err() {
            self.connections_refused.fetch_add(1, Ordering::Relaxed);
        } else {
            *sources.entry(source).or_insert(0) += 1;
        }
        taken.is_ok()
    }

    /// Release the temporary pre-authentication source share after `AUTH_ACK` or
    /// when a socket ends before it can authenticate.
    pub async fn release_unauthenticated_connection(&self, source: Option<&str>) {
        let Some(_) = self.connection_ceiling() else {
            return;
        };
        let source = self.connection_source(source);
        let mut sources = self.unauthenticated_connections_by_source.lock().await;
        let Some(count) = sources.get_mut(&source) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            sources.remove(&source);
        }
    }

    fn connection_ceiling(&self) -> Option<usize> {
        match self.config.max_connections {
            crate::config::Limit::Unlimited => None,
            crate::config::Limit::Of(value) => Some(usize::try_from(value).unwrap_or(usize::MAX)),
        }
    }

    fn connection_source(&self, source: Option<&str>) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.unauthenticated_connection_source_key);
        hasher.update(source.unwrap_or("unknown").as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Give one connection slot back. Called exactly once per successful
    /// ``admit_connection``, when the reader loop ends however it ends.
    pub fn release_connection(&self) {
        use std::sync::atomic::Ordering;

        // Saturating rather than wrapping. A decrement below zero would be a
        // pairing bug, and wrapping to `usize::MAX` would turn it into a relay
        // that refuses every future connection.
        let _ = self
            .connections
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |open| {
                Some(open.saturating_sub(1))
            });
    }

    /// Record that a connection was closed because a deadline elapsed.
    ///
    /// One function rather than two public counters bumped at the call site, so
    /// `crate::deadline::Expiry` is the only thing that decides which number
    /// moves and a new deadline cannot be added without deciding where it is
    /// counted.
    pub fn record_deadline(&self, expiry: crate::deadline::Expiry) {
        use std::sync::atomic::Ordering;

        match expiry {
            crate::deadline::Expiry::Handshake => &self.handshake_deadline_closes,
            crate::deadline::Expiry::Idle => &self.idle_deadline_closes,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    /// How many connections each deadline has closed. For `/readyz` and the tests.
    pub fn deadline_closes(&self, expiry: crate::deadline::Expiry) -> u64 {
        use std::sync::atomic::Ordering;

        match expiry {
            crate::deadline::Expiry::Handshake => &self.handshake_deadline_closes,
            crate::deadline::Expiry::Idle => &self.idle_deadline_closes,
        }
        .load(Ordering::Relaxed)
    }

    /// Sockets open right now. For `/readyz` and the tests.
    pub fn open_connections(&self) -> usize {
        self.connections.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Milliseconds since the epoch, from whichever clock this state carries.
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// Probe both dependencies and assemble the document.
    pub async fn readiness(&self) -> Readiness {
        let database = match &self.database {
            None => DependencyState::down("no database configured"),
            Some(db) => match db.probe().await {
                Ok(()) => DependencyState::up(),
                Err(error) => DependencyState::down(error.to_string()),
            },
        };
        let storage = match &self.storage {
            None => DependencyState::down("no storage configured"),
            Some(store) => match store.probe().await {
                Ok(()) => DependencyState::up(),
                Err(error) => DependencyState::down(error.to_string()),
            },
        };
        let frozen_groups = self.frozen_groups().await;
        let release = self
            .release
            .read()
            .map(|guard| guard.clone())
            // A poisoned lock means the release-check timer panicked. The honest
            // answer is that the state is unknown, not that it is current.
            .unwrap_or(ReleaseState::Unknown);

        // Readiness is about accepting durable writes, so `read_only` is not ready
        // even with both dependencies up. A load balancer using this to decide
        // whether to send traffic should stop sending writes to a relay in
        // maintenance mode.
        let ready = database.ok
            && storage.ok
            && matches!(self.config.write_mode, WriteMode::Full)
            && frozen_groups.is_empty();

        Readiness {
            build: self.build.line(),
            version: self.build.version.to_string(),
            database,
            storage,
            access_set: self.config.access_set_label(),
            min_enc: self.config.min_enc_label(),
            write_mode: match self.config.write_mode {
                WriteMode::Full => "full",
                WriteMode::ReadOnly => "read_only",
            },
            write_mode_reason: match self.config.write_mode {
                WriteMode::Full => None,
                WriteMode::ReadOnly => Some("service_read_only"),
            },
            frozen_groups,
            release,
            push: self.push.health().as_str(),
            calls: self.config.calls_label(),
            call_stats: CallStats {
                open: self.calls.open_calls().await as u64,
                media_shed: self.calls.shed(),
                media_denied: self.calls.denied(),
                calls_share_refused: self.calls.share_refused(),
                connections: self.open_connections() as u64,
                connections_refused: self
                    .connections_refused
                    .load(std::sync::atomic::Ordering::Relaxed),
                connections_closed_handshake_deadline: self
                    .deadline_closes(crate::deadline::Expiry::Handshake),
                oversized_outbound_frames: self
                    .oversized_outbound_frames
                    .load(std::sync::atomic::Ordering::Relaxed),
                connections_closed_idle_deadline: self
                    .deadline_closes(crate::deadline::Expiry::Idle),
            },
            db_pool: self.pool_stats(),
            ready,
        }
    }

    /// The pool's three numbers, or zeroes where there is no pool. Zeroes rather
    /// than an absent field: the document shape does not change with the
    /// configuration, so a poller has one shape to parse.
    fn pool_stats(&self) -> PoolStats {
        let size = self.config.db_pool_size;
        match &self.database {
            None => PoolStats {
                size,
                connections: 0,
                in_use: 0,
            },
            Some(db) => {
                let pool = db.pool();
                // `size` is already a `u32`; `num_idle` is a `usize`.
                let connections = pool.size();
                let idle = u32::try_from(pool.num_idle()).unwrap_or(u32::MAX);
                PoolStats {
                    size,
                    connections,
                    in_use: connections.saturating_sub(idle),
                }
            }
        }
    }

    /// Groups with a contested retention control chain. Empty until step 10 gives
    /// something the power to freeze one; the field exists now because `/readyz`
    /// is specified to report it and a poller that learned the field later would
    /// have to learn a new document shape.
    async fn frozen_groups(&self) -> Vec<String> {
        let Some(db) = &self.database else {
            return Vec::new();
        };
        match sqlx::query_scalar::<_, Vec<u8>>(
            "select group_id from relay_group where frozen_reason is not null order by group_id",
        )
        .fetch_all(db.pool())
        .await
        {
            // Through `group_for_log` rather than `hex_prefix` directly, so the
            // sensitivity rule (`Sensitivity::Correlatable` is debug-only) is the
            // thing that admits the value here too: the document these prefixes
            // appear in is operator-only (`readyz` gates it on the bearer), which
            // is the same audience the debug level is.
            Ok(rows) => rows
                .iter()
                .filter_map(|group| crate::logging::group_for_log(group, tracing::Level::DEBUG))
                .collect(),
            // A database that cannot answer is already reported by the `database`
            // field. Reporting an empty frozen list on top of that is honest: the
            // relay does not know of any frozen group, because it cannot ask.
            Err(_) => Vec::new(),
        }
    }
}

/// Where the relay's idea of now comes from.
///
/// One type with three arms rather than a trait: the system clock, a fixed instant
/// for static decisions, and an explicitly shared manual clock for deterministic
/// tests of long-lived connections. Keeping time injected makes receipt-time
/// decisions testable without sleeps or the host clock.
#[derive(Debug, Clone)]
pub enum Clock {
    System,
    /// A fixed instant, for a test that has to control an expiry or a skew.
    Fixed(u64),
    /// A manually advanced instant shared with a deterministic test fixture.
    Manual(Arc<AtomicU64>),
}

impl Clock {
    pub fn now_ms(&self) -> u64 {
        match self {
            Self::System => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                // A clock before 1970 is a machine whose time is unusable. Zero is
                // the honest answer and every expiry then reads as not yet due,
                // which fails closed rather than expiring everything at once.
                .map_or(0, |elapsed| elapsed.as_millis() as u64),
            Self::Fixed(value) => *value,
            Self::Manual(value) => value.load(Ordering::Relaxed),
        }
    }
}

/// Thirty-two bytes nobody can predict, for ``RelayState::media_presign_secret``.
/// A failure to obtain operating-system entropy is fatal, matching
/// `session::challenge_secret`: continuing with a predictable secret would
/// silently remove the protection it provides.
fn random_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).expect("the operating system must provide randomness");
    secret
}

/// The public listener: liveness, and the socket clients talk on.
///
/// Liveness means the process is running and can answer. It deliberately does not
/// probe the database: a relay whose database is down is still alive, and a
/// `/healthz` that failed then would make an orchestrator restart a process that
/// has nothing wrong with it while the actual fault is elsewhere.
pub fn public_router(state: Arc<RelayState>) -> Router {
    let router = Router::new()
        .route("/healthz", get(healthz))
        .route("/relay", get(relay_socket))
        .route("/join/:token", get(join_page))
        .merge(crate::media::http::routes());
    let router = mount_handoff(router, &state);
    // `/admitted` on the public listener as well, for exactly the reason the
    // handoff route moved: it is asked cross-region by a control plane that cannot
    // resolve the private name, and `renderAdmittedPrincipals` answers 1 rather
    // than a count when it cannot ask. Still mounted only where the operator token
    // exists, still checked by the same constant-time comparison, and still
    // reporting a number and nothing else.
    let router = match state.config.operator_token.clone() {
        Some(token) => router
            .route(
                "/admitted",
                get(admitted).layer(axum::Extension(OperatorToken(token.clone()))),
            )
            .route(
                "/gc/restore-marker",
                post(set_restore_marker)
                    .delete(clear_restore_marker)
                    .layer(axum::Extension(OperatorToken(token))),
            ),
        None => router,
    };
    router.with_state(state)
}

/// Mount `GET /handoff/<derived>`, or do not.
///
/// Mounted only where both a handoff public key and an operator token are set,
/// which is the hosted shape and only the hosted shape. A self-hoster has no
/// control plane, nothing that would ever call this, and no token to authenticate
/// it with, so the honest answer to a request for it there is 404 rather than a
/// route that exists and refuses everything. This is the same conditional-mount
/// rule `/admitted` follows and for the same reason: a misread variable name means
/// the route is absent and the provisioner fails loudly, rather than present and
/// open.
///
/// ## Why the public listener
///
/// `server.md` originally pinned this to the private observability listener, on the
/// argument that a ciphertext is safer on a port the internet cannot reach. That was
/// right about the port and wrong about the topology. The private listener is
/// per-region provider-private networking, and the control plane does not run in
/// every region it provisions into, so `renderHandoffBlob` cannot reach it and reads
/// unreachable as absent: `POST /instances/:id/bootstrap` then answers
/// `instance_not_operable` for ever and the customer's relay, up and certificated,
/// is destroyed and refunded at the deadline. A blob nobody can fetch is not a
/// safer blob, it is a broken product.
///
/// Moving it to the public listener costs nothing the design was relying on. What is
/// served is a ciphertext openable only by a key held in another system, the path is
/// derived from that key rather than from anything guessable, and the request must
/// still carry the operator bearer. The private listener was never the security
/// boundary; `operator_authorized` was, and it still is.
fn mount_handoff(
    router: Router<Arc<RelayState>>,
    state: &Arc<RelayState>,
) -> Router<Arc<RelayState>> {
    let (Some(configured), Some(token)) = (
        state.config.bootstrap_handoff_pubkey.as_deref(),
        state.config.operator_token.clone(),
    ) else {
        return router;
    };
    let Ok(key) = crate::invite::handoff::parse_public_key(configured) else {
        // An unusable key is already fatal to the mint (`serve::bootstrap`), so this
        // relay has no genesis and nothing to serve. Refusing to derive a path from
        // a value that is not a key keeps the two decisions consistent rather than
        // mounting a route that could only ever 404.
        return router;
    };
    router.route(
        &crate::invite::handoff::handoff_path(&key),
        get(handoff).layer(axum::Extension(OperatorToken(token))),
    )
}

/// `GET /handoff/<derived>`: the sealed bootstrap handoff, or 404.
///
/// Reading does not consume. The control plane polls this while it waits for a relay
/// to finish coming up, and a read that spent the invite would destroy it before the
/// buyer ever saw it; redemption remains the one-time operation and it happens over
/// the socket, not here.
///
/// 404 before anything has been sealed, which is the state between a relay accepting
/// connections and its first boot completing the mint, and also the permanent state
/// of a relay whose mint failed. The control plane treats both as "not operable yet"
/// and retries, which is correct for the first and is resolved by a restart against
/// an empty database for the second.
async fn handoff(
    State(state): State<Arc<RelayState>>,
    axum::Extension(OperatorToken(expected)): axum::Extension<OperatorToken>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if !operator_authorized(&expected, &headers) {
        return (StatusCode::UNAUTHORIZED, "operator token required\n").into_response();
    }
    let Some(database) = state.database.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no database\n").into_response();
    };
    let workspace = crate::serve::bootstrap_workspace(&state.config.hostname);
    match crate::invite::handoff::read(database.pool(), &workspace).await {
        Ok(Some(sealed)) => (StatusCode::OK, axum::Json(sealed)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no sealed handoff\n").into_response(),
        // 503 rather than 404 when the database could not answer. The caller reads
        // 404 as "nothing was ever sealed", which for an instance that did seal one
        // is a wrong answer rather than an unavailable one, and the difference is
        // whether it retries or gives up on a relay that is fine.
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "no database\n").into_response(),
    }
}

/// The invite landing page, at the path the first-run banner prints.
///
/// Routed on the public listener because the whole point of the printed link is
/// that somebody who is not the operator can open it. The relay used to print a
/// URL it did not serve, so every invite ended on a 404.
///
/// The token is not read, not looked up and not interpolated: the response is
/// byte-identical for every token, including tokens that never existed. A page
/// that varied would tell anyone who could fetch it which tokens are live, which
/// is the oracle the flat response exists to close. `invite::delivery` carries the
/// longer argument.
async fn join_page() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        crate::invite::delivery::landing_page(),
    )
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

/// Headroom over `MAX_FRAME_BYTES` for the transport's own message ceiling.
///
/// The WebSocket layer reassembles a whole message before the relay sees it, so the
/// allocation bound has to live on the transport rather than on the length check in
/// `ws::handle_message`: that check runs after the bytes exist. A small allowance
/// keeps a maximum-size frame deliverable while anything materially larger is
/// refused by tungstenite before it is buffered.
const WS_MESSAGE_ALLOWANCE: usize = 4096;

/// The largest message and the largest fragment the transport will assemble.
pub const WS_MAX_MESSAGE_BYTES: usize = crate::frame::MAX_FRAME_BYTES + WS_MESSAGE_ALLOWANCE;

/// Why a request's client address could not be established.
///
/// One variant, because there is one way to get this wrong that is not a
/// programming error: the operator declared proxies that did not append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardedError {
    /// Fewer forwarding entries than declared hops. Ambiguous, so refused.
    ChainTooShort,
}

/// The address the pre-authentication budgets should charge, given how many
/// reverse proxies the operator declared.
///
/// Pure, and separated from the handler so the spoofing cases are testable
/// without a socket. Two rules, and the second only exists because of the first:
///
/// - `hops == 0` means the relay is reached directly, so the transport peer is
///   the client and `X-Forwarded-For` is not read at all. A direct client that
///   sends the header gets exactly the bucket its real address earns, which is
///   what stops a header from being a way to pick your own quota.
/// - `hops == n > 0` means `n` proxies this operator runs each appended one
///   entry on the way in: the innermost appended the address it saw (the
///   client, or the next proxy out), so the client is at index `len - n`. A
///   chain with fewer than `n` entries did not come through the declared path
///   and is refused rather than guessed at. Note the innermost proxy appends
///   the client, not itself, so a single declared hop behind the Compose
///   bundle's Caddy sees a one-entry chain and that entry is the client.
///
/// Counting from the right is the whole security property. The leftmost entry is
/// attacker-controlled in every deployment, because the first proxy appends what
/// it saw without deleting what the client claimed.
pub fn client_source(
    hops: u64,
    headers: &axum::http::HeaderMap,
    peer: Option<std::net::SocketAddr>,
) -> Result<Option<String>, ForwardedError> {
    if hops == 0 {
        return Ok(peer.map(|address| address.ip().to_string()));
    }
    // Every value of the header, in order, then every comma-separated element
    // inside each value: a chain crossing several proxies may arrive as one
    // header or as several, and the two are the same chain.
    //
    // `X-Forwarded-For` only. RFC 7239 `Forwarded` is the standardised spelling
    // and no proxy in any deployment this relay supports emits it, so reading it
    // would be a second parser covering nothing, with its own quoted-string and
    // `for=` obfuscation rules to get wrong.
    let chain: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|element| !element.is_empty())
        .collect();
    let hops = hops as usize;
    // Each declared proxy appended exactly one entry, so a well formed chain has
    // at least `hops` of them and the client is the first of that suffix.
    if chain.len() < hops {
        return Err(ForwardedError::ChainTooShort);
    }
    Ok(Some(chain[chain.len() - hops].to_string()))
}

/// The socket the client actually talks on.
///
/// On the public listener beside `/healthz`, because it is the customer-facing
/// surface: `/readyz` is private and a WebSocket is not.
async fn relay_socket(
    ws: axum::extract::WebSocketUpgrade,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: axum::http::HeaderMap,
    State(state): State<Arc<RelayState>>,
) -> axum::response::Response {
    // The client's address, for the redeem path's per-source budget and for
    // nothing else. It is hashed with the workspace salt before it reaches any
    // table (`invite::reserve::source_hash`), so what the relay stores is a value
    // it cannot turn back into an address. `None` when the router was mounted
    // without connection info, which is every unit test: the budget then falls
    // back to the one the joiner cannot forge, which is its own device.
    //
    // Which address counts as the client's is a deployment fact, not a transport
    // fact: behind the Compose bundle's Caddy, or behind any provider edge that
    // terminates TLS, the transport peer is the proxy and every public client
    // shares it. `client_source` reads that fact off
    // `WEALD_RELAY_TRUSTED_PROXY_HOPS`.
    let source = match client_source(
        state.config.trusted_proxy_hops,
        &headers,
        peer.map(|axum::extract::ConnectInfo(address)| address),
    ) {
        Ok(source) => source,
        // A declared proxy chain that is not there. Refusing is the point: the
        // alternative is falling back to the transport peer, which is the shared
        // bucket this key exists to stop, or to the leftmost header entry, which
        // is a value the client wrote.
        Err(ForwardedError::ChainTooShort) => {
            return (StatusCode::BAD_REQUEST, "forwarded chain is not trusted\n").into_response();
        }
    };
    // The cap, before the upgrade rather than after it.
    //
    // `operations.md` recorded the absence of this as a known gap: the per
    // connection send queue is bounded in bytes, and nothing bounded the number of
    // connections, so instance memory was the budget times however many clients
    // chose to connect. Refusing here costs the peer one HTTP response and costs
    // this process nothing; refusing after the upgrade would mean allocating the
    // queues the cap exists to bound.
    //
    // 503 with `Retry-After`, which is the transport's own way of saying what
    // `quota` says in a frame. There is no frame to say it in: the socket does not
    // exist yet.
    if !state.admit_connection(source.as_deref()).await {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(axum::http::header::RETRY_AFTER, "5")],
            "at capacity\n",
        )
            .into_response();
    }
    // A connection can outlive any one clock tick. `serve_connection` asks the
    // relay clock for each received message so an accepted envelope records its
    // receipt time, while session rules still receive an injected value.
    // The slot is released by `serve_connection` itself, on every path out of it,
    // rather than here: `on_upgrade` hands the future to the runtime and returns,
    // so anything written after this line would run while the connection was still
    // open. A slot leaked once per connection would be a relay that stops
    // accepting after `WEALD_RELAY_MAX_CONNECTIONS` clients have ever visited.
    //
    // `on_failed_upgrade` is the other path out. axum spawns the callback above
    // only when the upgrade completes; a peer that sends a well-formed upgrade
    // request and resets the TCP connection before the 101 lands never reaches
    // `serve_connection`, and the default failed-upgrade handler is a no-op. The
    // slot and the pre-authentication source share taken above would then be held
    // forever, so `WEALD_RELAY_MAX_CONNECTIONS` aborted upgrades took the relay
    // offline with no authentication and no payload. The two handlers are mutually
    // exclusive by construction, so the release runs exactly once per admission.
    //
    // The transport's own size ceiling is set here because tungstenite reassembles
    // an entire message before axum yields it: the `MAX_FRAME_BYTES` check in
    // `ws::handle_message` runs only after the allocation it would refuse. Without
    // this bound an unauthenticated peer could hold 64 MiB (the axum default) per
    // connection on the read side, eight times the send-queue byte budget the
    // capacity story is sized against.
    let failed_state = Arc::clone(&state);
    let failed_source = source.clone();
    ws.max_message_size(WS_MAX_MESSAGE_BYTES)
        .max_frame_size(WS_MAX_MESSAGE_BYTES)
        .on_failed_upgrade(move |_error| {
            // The callback is synchronous and the source-share release now takes
            // an async lock, so the release is handed to the runtime. Ordering
            // does not matter here: both releases are idempotent decrements and
            // nothing observes them together.
            tokio::spawn(async move {
                failed_state
                    .release_unauthenticated_connection(failed_source.as_deref())
                    .await;
                failed_state.release_connection();
            });
        })
        .on_upgrade(move |socket| crate::ws::serve_connection(socket, state, source))
}

/// The private listener. Detailed readiness, bound to loopback by default.
///
/// `/admitted` is mounted only where `WEALD_RELAY_OPERATOR_TOKEN` is set, which
/// is the hosted shape. Two reasons it is conditional rather than always there
/// and always checked:
///
/// - A route that exists but refuses everything is a route a self-hoster has to
///   reason about. There is no control plane in that deployment and nothing that
///   would ever call this, so the honest answer to a request for it is 404.
/// - Mounting only where the credential to authenticate it exists is the pattern
///   the control plane already uses for its own webhook routes, and it is what
///   stops an unauthenticated operator surface appearing by omission. A misread
///   variable name means the route is absent and the provisioner fails loudly,
///   rather than present and open.
///
/// The listener itself is loopback by default and the hosted tier exposes it over
/// provider-private networking. That is a network boundary, and the token is here
/// because a network boundary is not an authentication boundary: every other
/// service in a provider environment can reach this port.
pub fn private_router(state: Arc<RelayState>) -> Router {
    let router = Router::new()
        .route("/readyz", get(readyz))
        .route("/healthz", get(healthz));
    // The token is carried into the handler rather than read back out of the
    // configuration there. Both would work, but reading it again inside the
    // handler means the handler has a branch for "mounted with no token", which
    // this function has just made impossible: dead code on the one path where a
    // wrong answer hands out bootstrap authority, and dead code cannot be tested.
    let router = match state.config.operator_token.clone() {
        Some(token) => router
            .route(
                "/admitted",
                get(admitted).layer(axum::Extension(OperatorToken(token.clone()))),
            )
            .route(
                "/gc/restore-marker",
                post(set_restore_marker)
                    .delete(clear_restore_marker)
                    .layer(axum::Extension(OperatorToken(token))),
            ),
        None => router,
    };
    router.with_state(state)
}

/// The operator bearer this relay was configured with, carried to the one handler
/// that checks it. Present by construction: the route is mounted with it or not
/// mounted at all.
#[derive(Clone)]
struct OperatorToken(String);

/// What `/admitted` answers. One field, and the field is a number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Admitted {
    pub admitted: i64,
}

/// Whether this request carried the operator bearer.
///
/// Compared in constant time. The token is a fixed string presented on every
/// poll, so a comparison that returned early would leak its length and then its
/// bytes to anything that can reach the port, which on a provider network is
/// more than just us.
fn operator_authorized(expected: &str, headers: &axum::http::HeaderMap) -> bool {
    let Some(offered) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    let expected = expected.as_bytes();
    let offered = offered.as_bytes();
    if expected.len() != offered.len() {
        return false;
    }
    expected
        .iter()
        .zip(offered)
        .fold(0u8, |differences, (a, b)| differences | (a ^ b))
        == 0
}

/// `GET /admitted`: how many principals this relay has admitted.
///
/// 503 rather than 0 when the database is unreachable. The caller branches on
/// zero to decide whether a one-time bootstrap invite may still be claimed, and
/// answering 0 for "I could not look" would hand out bootstrap authority for a
/// workspace that may already have an admin. An unavailable answer is a retry;
/// a wrong answer is the trust-root race in `specs/backend/cloud/provisioning.md`.
async fn admitted(
    State(state): State<Arc<RelayState>>,
    axum::Extension(OperatorToken(expected)): axum::Extension<OperatorToken>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if !operator_authorized(&expected, &headers) {
        return (StatusCode::UNAUTHORIZED, "operator token required\n").into_response();
    }
    let Some(database) = state.database.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no database\n").into_response();
    };
    match crate::access::store::admitted_principals(database.pool()).await {
        Ok(admitted) => (StatusCode::OK, Json(Admitted { admitted })).into_response(),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            crate::logging::scrub(&error.to_string()),
        )
            .into_response(),
    }
}

/// What `POST /gc/restore-marker` answers, and what `DELETE` answers when it has
/// cleared one. One field, and the field is how many collector passes are still
/// suppressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RestoreMarker {
    pub passes_remaining: i32,
}

/// How many passes to suppress, when the caller names a number.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RestoreMarkerRequest {
    pub passes: Option<i32>,
}

/// `POST /gc/restore-marker`: suppress the storage-listing sweep for the next few
/// collector passes, because this relay's database has just been restored.
///
/// This is the operator half of the restore path in
/// `specs/backend/cloud/backup-dr.md`. The database half of a restore leaves the
/// relay holding rows older than its own bucket, so every object uploaded since the
/// recovery point looks unreferenced to `media::gc`; the caller that completed the
/// restore posts this before the relay is let back into service, and the collector
/// counts it down. Whoever restores writes it: the control plane's restore job for a
/// hosted instance, the operator running the runbook for a self-hosted one.
///
/// Idempotent, and a second post replaces rather than adds: two restores in a week
/// should leave the second one's full protection.
async fn set_restore_marker(
    State(state): State<Arc<RelayState>>,
    axum::Extension(OperatorToken(expected)): axum::Extension<OperatorToken>,
    headers: axum::http::HeaderMap,
    request: Option<Json<RestoreMarkerRequest>>,
) -> axum::response::Response {
    if !operator_authorized(&expected, &headers) {
        return (StatusCode::UNAUTHORIZED, "operator token required\n").into_response();
    }
    let Some(database) = state.database.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no database\n").into_response();
    };
    let passes = request
        .and_then(|Json(body)| body.passes)
        .unwrap_or(crate::media::restore::DEFAULT_SUPPRESSED_PASSES);
    if passes <= 0 {
        return (
            StatusCode::BAD_REQUEST,
            "passes must be positive; DELETE clears the marker\n",
        )
            .into_response();
    }
    match crate::media::restore::set(database.pool(), passes, "database restore").await {
        Ok(passes_remaining) => {
            (StatusCode::OK, Json(RestoreMarker { passes_remaining })).into_response()
        }
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            crate::logging::scrub(&error.to_string()),
        )
            .into_response(),
    }
}

/// `DELETE /gc/restore-marker`: the restore is settled, let the sweep run again.
///
/// The marker clears itself once its passes are spent, so this exists for the
/// operator who finished sooner and does not want the reconcile switched off for
/// days it no longer needs.
async fn clear_restore_marker(
    State(state): State<Arc<RelayState>>,
    axum::Extension(OperatorToken(expected)): axum::Extension<OperatorToken>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if !operator_authorized(&expected, &headers) {
        return (StatusCode::UNAUTHORIZED, "operator token required\n").into_response();
    }
    let Some(database) = state.database.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no database\n").into_response();
    };
    match crate::media::restore::clear(database.pool()).await {
        Ok(()) => (
            StatusCode::OK,
            Json(RestoreMarker {
                passes_remaining: 0,
            }),
        )
            .into_response(),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            crate::logging::scrub(&error.to_string()),
        )
            .into_response(),
    }
}

/// The unauthenticated `/readyz` body: a verdict, and nothing else.
///
/// Two fields saying the same thing, on purpose. `ready` is the field's name in the
/// full document, and `ok` is what the control plane's body sniff looks for to tell
/// the relay's own 503 apart from a provider edge answering for a host it cannot
/// route to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ReadyVerdict {
    pub ok: bool,
    pub ready: bool,
}

async fn readyz(
    State(state): State<Arc<RelayState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let readiness = state.readiness().await;
    // 503 when not ready, so a poller that only reads the status code is not
    // misled, and 200 when it is.
    let code = if readiness.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    // The detailed document sits behind the operator bearer, exactly like
    // `/admitted` and for the rationale written on `private_router`: the private
    // listener is a network boundary and a network boundary is not an
    // authentication boundary, because every co-tenant service in a provider
    // environment can reach this port. The full document carries `frozen_groups`
    // (group id prefixes, the correlation handles the public/private split exists
    // to withhold), refusal counters, pool saturation and security posture; a
    // caller without the bearer gets the one thing readiness owes an
    // orchestrator, which is the verdict.
    let authorized = state
        .config
        .operator_token
        .as_deref()
        .is_some_and(|expected| operator_authorized(expected, &headers));
    if authorized {
        (code, Json(readiness)).into_response()
    } else {
        (
            code,
            Json(ReadyVerdict {
                ok: readiness.ready,
                ready: readiness.ready,
            }),
        )
            .into_response()
    }
}
