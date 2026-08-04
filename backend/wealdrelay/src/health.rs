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

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

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
    /// Whether the relay would accept a durable write right now. The one-line
    /// answer, so a poller does not have to reimplement the conjunction.
    pub ready: bool,
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
    /// Client sockets open now, and how many have been refused at the cap since
    /// start.
    pub connections: u64,
    pub connections_refused: u64,
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
    /// How many connections were refused because the cap was reached. An operator
    /// counter with no label: capacity, never identity.
    pub connections_refused: std::sync::atomic::AtomicU64,
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
            calls: crate::calls::CallRegistry::new(max_concurrent_calls),
            connections: std::sync::atomic::AtomicUsize::new(0),
            connections_refused: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Take one connection slot, or refuse.
    ///
    /// The check and the increment are one `fetch_update`, so two sockets arriving
    /// in the same instant cannot both be told there was room for the last slot.
    /// That is the whole reason this is not a read followed by an add.
    pub fn admit_connection(&self) -> bool {
        use std::sync::atomic::Ordering;

        let ceiling = match self.config.max_connections {
            crate::config::Limit::Unlimited => {
                return {
                    self.connections.fetch_add(1, Ordering::Relaxed);
                    true
                }
            }
            crate::config::Limit::Of(value) => usize::try_from(value).unwrap_or(usize::MAX),
        };
        let taken = self
            .connections
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |open| {
                (open < ceiling).then_some(open + 1)
            });
        if taken.is_err() {
            self.connections_refused.fetch_add(1, Ordering::Relaxed);
        }
        taken.is_ok()
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
            calls: self.config.calls_label(),
            call_stats: CallStats {
                open: self.calls.open_calls().await as u64,
                media_shed: self.calls.shed(),
                media_denied: self.calls.denied(),
                connections: self.open_connections() as u64,
                connections_refused: self
                    .connections_refused
                    .load(std::sync::atomic::Ordering::Relaxed),
            },
            ready,
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
            Ok(rows) => rows
                .iter()
                .map(|group| crate::logging::hex_prefix(group))
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
    Router::new()
        .route("/healthz", get(healthz))
        .route("/relay", get(relay_socket))
        .route("/join/:token", get(join_page))
        .merge(crate::media::http::routes())
        .with_state(state)
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

/// The socket the client actually talks on.
///
/// On the public listener beside `/healthz`, because it is the customer-facing
/// surface: `/readyz` is private and a WebSocket is not.
async fn relay_socket(
    ws: axum::extract::WebSocketUpgrade,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    State(state): State<Arc<RelayState>>,
) -> axum::response::Response {
    // The peer's address, for the redeem path's per-source budget and for nothing
    // else. It is hashed with the workspace salt before it reaches any table
    // (`invite::reserve::source_hash`), so what the relay stores is a value it
    // cannot turn back into an address. `None` when the router was mounted without
    // connection info, which is every unit test: the budget then falls back to the
    // one the joiner cannot forge, which is its own device.
    let source = peer.map(|axum::extract::ConnectInfo(address)| address.ip().to_string());
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
    if !state.admit_connection() {
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
    ws.on_upgrade(move |socket| crate::ws::serve_connection(socket, state, source))
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
        Some(token) => router.route(
            "/admitted",
            get(admitted).layer(axum::Extension(OperatorToken(token))),
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

async fn readyz(State(state): State<Arc<RelayState>>) -> impl IntoResponse {
    let readiness = state.readiness().await;
    // 503 when not ready, so a poller that only reads the status code is not
    // misled, and 200 with the document when it is. The document is served in both
    // cases: a caller debugging a 503 needs to know which field caused it.
    let code = if readiness.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(readiness))
}
