// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Configuration, from environment variables with an optional `relay.toml`.
//!
//! The surface is `specs/backend/relay/server.md`, "Configuration surface", and
//! it is deliberately small: three required variables and a set of optionals
//! whose defaults work. Everything here is that list and nothing else.
//!
//! Three rules from the spec shape this module, and each of them is a test below
//! rather than a comment:
//!
//! - **A missing required variable exits non-zero and names the variable.** A
//!   relay that started with a default database URL would be a relay writing
//!   somewhere its operator did not choose.
//! - **An unrecognised value is refused, never coerced.** `WEALD_RELAY_TLS=of`
//!   is not `off`. Silently reading a typo as a permissive default is how a
//!   deployment ends up in a posture nobody chose, and two of these values
//!   decide security posture.
//! - **The relay has no dependency on any commercial-layer vendor.** There is no
//!   key here that names anything in `specs/backend/cloud/`, and adding one
//!   would be a trust boundary change because the hosted binary must be the
//!   audited binary.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// Every key the relay reads. Named once, so the error messages, the
/// `relay.toml` parser and the tests cannot drift apart.
pub mod keys {
    pub const HOSTNAME: &str = "WEALD_RELAY_HOSTNAME";
    pub const DATABASE_URL: &str = "WEALD_RELAY_DATABASE_URL";
    /// How many Postgres backends this process holds open at once.
    ///
    /// A memory budget on the database rather than on the relay, and on a small
    /// instance a hard ceiling too: providers cap connections per plan, and a
    /// pool above the cap fails `acquire_timeout` under load rather than
    /// degrading. Defaults to `crate::db::DEFAULT_POOL_SIZE`, which is sized for
    /// the smallest plan the hosted tier sells; an operator on a larger database
    /// raises it deliberately.
    pub const DB_POOL_SIZE: &str = "WEALD_RELAY_DB_POOL_SIZE";
    pub const STORAGE_URL: &str = "WEALD_RELAY_STORAGE_URL";
    pub const REDIS_URL: &str = "WEALD_RELAY_REDIS_URL";
    pub const LISTEN: &str = "WEALD_RELAY_LISTEN";
    pub const OBSERVABILITY_LISTEN: &str = "WEALD_RELAY_OBSERVABILITY_LISTEN";
    pub const TLS: &str = "WEALD_RELAY_TLS";
    pub const MAX_STORAGE_GB: &str = "WEALD_RELAY_MAX_STORAGE_GB";
    /// The per-workspace ceiling on the envelope log, in decimal GB.
    ///
    /// `MAX_STORAGE_GB` bounds media alone and `RETENTION_DAYS` is a warning
    /// threshold rather than a deletion, so before this variable existed one
    /// workspace could fill a relay's Postgres while inside every limit the relay
    /// enforced (`specs/backend/cloud/instance-sizing.md`). Unlimited by default,
    /// which is the self-hoster's posture: an operator who owns the disk decides
    /// what to do with it. The hosted provisioner always sets it.
    ///
    /// A gigabyte is 10^9 bytes here, the same as `MAX_STORAGE_GB` and the same
    /// as `pricing.ts BYTES_PER_GB`, because the number a customer is sold and
    /// the number the relay enforces have to be one number.
    pub const MAX_LOG_GB: &str = "WEALD_RELAY_MAX_LOG_GB";
    pub const RETENTION_DAYS: &str = "WEALD_RELAY_RETENTION_DAYS";
    pub const ACCESS_SET: &str = "WEALD_RELAY_ACCESS_SET";
    pub const MIN_ENC: &str = "WEALD_RELAY_MIN_ENC";
    pub const SMTP_URL: &str = "WEALD_RELAY_SMTP_URL";
    pub const WRITE_MODE: &str = "WEALD_RELAY_WRITE_MODE";
    pub const RELEASE_CHECK: &str = "WEALD_RELAY_RELEASE_CHECK";
    pub const METRICS_GROUP_LABELS: &str = "WEALD_RELAY_METRICS_GROUP_LABELS";
    pub const BOOTSTRAP_HANDOFF_PUBKEY: &str = "WEALD_RELAY_BOOTSTRAP_HANDOFF_PUBKEY";
    /// Whether the ephemeral path is served at all.
    ///
    /// It exists because presence is the one thing this relay carries that a
    /// self-hoster may reasonably not want to carry: a beat every 20 seconds per
    /// connected device is traffic an operator did not ask for, and `off` is a
    /// posture rather than a failure. A version 2 client told `off` reports presence
    /// unavailable, which is the same thing it reports against a version 1 relay.
    pub const LIVE: &str = "WEALD_RELAY_LIVE";
    /// How a beat reaches the other instances of a multi-instance deployment.
    ///
    /// It exists because single-process fanout is correct only in a single-process
    /// deployment, and a two-instance deployment on `process` would show every
    /// member half the room with nothing anywhere reporting a fault. The relay
    /// refuses to start in that combination rather than serving a half room.
    pub const LIVE_FANOUT: &str = "WEALD_RELAY_LIVE_FANOUT";
    /// Whether voice calls are carried at all.
    ///
    /// `off` by default, unlike `WEALD_RELAY_LIVE`, and the difference is
    /// deliberate. Presence is the ordinary shape of the app and costs a beat
    /// every twenty seconds. A call is a sustained stream an operator has to have
    /// sized for, so it is opt-in: an instance carries calls because somebody
    /// decided it would, and that decision is the same act as setting
    /// `WEALD_RELAY_MAX_CONCURRENT_CALLS` (`specs/backend/relay/calls.md`).
    pub const CALLS: &str = "WEALD_RELAY_CALLS";
    /// How many calls one instance may carry at once.
    ///
    /// Required when `WEALD_RELAY_CALLS=on` and refused as meaningless when it is
    /// off. There is no default and there deliberately never will be: call
    /// capacity is a sizing decision about one instance's bandwidth, and a relay
    /// that guessed one would be a relay whose ceiling nobody chose and whose
    /// operator discovers it under load.
    pub const MAX_CONCURRENT_CALLS: &str = "WEALD_RELAY_MAX_CONCURRENT_CALLS";
    /// How many client sockets may be open at once.
    ///
    /// `specs/backend/relay/operations.md` recorded the absence of this as a known
    /// gap: "nothing caps concurrent connections, so instance memory is still the
    /// budget times however many connect". Calls make the gap matter sooner,
    /// because a connection carrying a call holds its queue full rather than
    /// nearly empty, so the cap ships with them.
    pub const MAX_CONNECTIONS: &str = "WEALD_RELAY_MAX_CONNECTIONS";
    /// How long a connection may sit between the WebSocket upgrade and
    /// `AUTH_ACK`, in milliseconds.
    ///
    /// The cap above bounds how many sockets may be open and bounded nothing
    /// about how long an unauthenticated one may hold its slot, which made the
    /// cap itself the attack: `WEALD_RELAY_MAX_CONNECTIONS` sockets that send no
    /// bytes at all lock every real device out of a customer's relay for the cost
    /// of one file descriptor each. `crate::deadline` carries the argument and
    /// the default.
    pub const HANDSHAKE_TIMEOUT_MS: &str = "WEALD_RELAY_HANDSHAKE_TIMEOUT_MS";
    /// How long an authenticated connection may be silent before the relay asks
    /// whether its peer is still there, in milliseconds.
    ///
    /// Long by design, and not an abuse control: see `crate::deadline`. The
    /// answer is an application-level liveness exchange rather than a TCP
    /// keepalive, so a quiet peer and a wedged one are distinguishable.
    pub const IDLE_TIMEOUT_MS: &str = "WEALD_RELAY_IDLE_TIMEOUT_MS";
    /// How many `SEND` frames one device may write per minute.
    ///
    /// The envelope path had no budget at all until `crate::send_budget`: an admitted
    /// device could drive the database at line rate, and every other workspace on
    /// the instance would feel it. Raisable per instance, as
    /// `specs/backend/relay/wire.md` says the ingress limits are, and never per
    /// group, so it cannot be used to single a workspace out.
    pub const SEND_FRAMES_PER_MINUTE: &str = "WEALD_RELAY_SEND_FRAMES_PER_MINUTE";
    /// How many `SEND` bytes one device may write per minute.
    ///
    /// The other half of the same budget. Two variables rather than one, because
    /// they answer different questions about an instance: the frame count is
    /// about database write capacity and the byte count is about bandwidth and
    /// storage, and an operator who raises one usually does not mean the other.
    pub const SEND_BYTES_PER_MINUTE: &str = "WEALD_RELAY_SEND_BYTES_PER_MINUTE";
    /// The bearer a control plane presents on the operator routes.
    ///
    /// `specs/backend/cloud/api.md` requires the relay to report how many
    /// principals it has admitted, and `provisioning.md` requires the sealed
    /// bootstrap handoff to be retrievable "over the provider-private path". Both
    /// are on the observability listener, which is loopback by default and, on the
    /// hosted tier, is exposed over provider-private networking rather than to the
    /// internet (`specs/backend/relay/server.md`).
    ///
    /// Provider-private is a network boundary, and a network boundary is not an
    /// authentication boundary: on a shared provider network every other service in
    /// the environment can reach this port. So the operator routes are mounted only
    /// where a token exists to check them against, exactly as the control plane
    /// mounts its own webhook routes only where a signing secret exists. Absent
    /// means the routes are not there at all, which is the self-host shape: a
    /// self-hoster has no control plane and reads the invite off stdout.
    pub const OPERATOR_TOKEN: &str = "WEALD_RELAY_OPERATOR_TOKEN";
    /// Whether the relay has an outbound wake leg at all.
    ///
    /// `off` by default, and off is a supported deployment rather than a degraded
    /// one: the relay then has no outbound leg, devices are told push is unavailable
    /// and never register, and notifications stay local and full-content exactly as
    /// `specs/backend/relay/notifications.md` version 1 describes them. A
    /// self-hoster on a private network keeps this forever.
    pub const PUSH: &str = "WEALD_RELAY_PUSH";
    /// Where a wake is POSTed. Required if and only if push is on.
    ///
    /// No default, ever, for the same reason `WEALD_RELAY_MAX_CONCURRENT_CALLS` has
    /// none: a wake destination is a trust boundary, and a relay that inherited one
    /// silently would be a relay whose users' devices are being woken by a party
    /// their operator never chose.
    pub const PUSH_URL: &str = "WEALD_RELAY_PUSH_URL";
    /// The bearer the ringer checks, when it is configured with one.
    ///
    /// Optional, because authority to wake a device is possession of the handle and
    /// the handle is a capability the device minted. Never printed by
    /// `--check-config` and never logged.
    pub const PUSH_TOKEN: &str = "WEALD_RELAY_PUSH_TOKEN";
    /// What `Capability` states, when it differs from the wake url.
    ///
    /// Defaults to `PUSH_URL` with its `/v1/wake` path replaced by the ringer's own
    /// `/v1/handles` path, because that is where the reference ringer serves
    /// registration. A replacement and not an append: `PUSH_URL` is a whole route.
    /// The relay states it rather
    /// than letting the device guess, since guessing ours would mean a self-hoster's
    /// users silently registering with a ringer their operator did not choose.
    pub const PUSH_REGISTER_URL: &str = "WEALD_RELAY_PUSH_REGISTER_URL";
    /// The coalescing window in milliseconds. Zero is legal and means no coalescing.
    pub const PUSH_COALESCE_MS: &str = "WEALD_RELAY_PUSH_COALESCE_MS";
    /// The bound on the wake queue. A bound, not a target.
    pub const PUSH_QUEUE: &str = "WEALD_RELAY_PUSH_QUEUE";
    /// How long between collector passes, in milliseconds. Positive: zero would be
    /// a task that scans Postgres without pause, which is not a posture anyone
    /// wants, and the way to turn collection off is to not run a relay.
    pub const JANITOR_INTERVAL_MS: &str = "WEALD_RELAY_JANITOR_INTERVAL_MS";
    /// The age floor under the storage-listing sweep, in seconds. An unreferenced
    /// object younger than this is never deleted, because "no reservation row" is
    /// also what every object uploaded after a restore point looks like once the
    /// database has been rolled back to it. Set by the control plane against the
    /// backup cadence it actually runs; 48 hours without it, against a stated
    /// 12-hour recovery-point objective. Zero is legal and means no floor.
    pub const GC_MIN_OBJECT_AGE_SECONDS: &str = "WEALD_RELAY_GC_MIN_OBJECT_AGE_SECONDS";
    /// How many reverse proxies the relay sits behind, each of which appends the
    /// address it received the request from to `X-Forwarded-For`.
    ///
    /// Zero by default, and zero means the transport peer is the client and every
    /// forwarding header is ignored: a relay reached directly must never let a
    /// client name its own address, because both the pre-authentication
    /// connection bucket and the invite-code cooldown key on that value
    /// (`crate::health::client_source`). Set it to the number of hops the
    /// deployment actually has, which is `1` behind the Compose bundle's Caddy
    /// and `1` behind a provider edge that terminates TLS. Without it every
    /// client behind the proxy shares one bucket, so one attacker, or ordinary
    /// concurrent onboarding, caps and cools down every unrelated user.
    ///
    /// Counted from the right, never the left: the leftmost entries are whatever
    /// the client sent and the rightmost `n` were appended by proxies this
    /// operator declared. A chain too short to have come through that many
    /// declared proxies is refused rather than guessed at, because guessing is
    /// exactly the spoof the count exists to close.
    pub const TRUSTED_PROXY_HOPS: &str = "WEALD_RELAY_TRUSTED_PROXY_HOPS";
    /// Which deployment this is. `self_host` by default; `hosted` refuses the
    /// settings `specs/backend/relay/server.md` says the hosted tier forbids.
    /// Configuration, never a compile-time branch: both profiles are in every
    /// build and the digest is the same either way (`crate::profile`).
    pub const PROFILE: &str = "WEALD_RELAY_PROFILE";

    /// Every key, for the `relay.toml` reader: a file naming something outside
    /// this list is refused rather than ignored, because a typo in a config file
    /// that silently does nothing is the same failure as a typo in a variable.
    pub const ALL: &[&str] = &[
        HOSTNAME,
        DATABASE_URL,
        DB_POOL_SIZE,
        STORAGE_URL,
        REDIS_URL,
        LISTEN,
        OBSERVABILITY_LISTEN,
        TLS,
        MAX_STORAGE_GB,
        MAX_LOG_GB,
        RETENTION_DAYS,
        ACCESS_SET,
        MIN_ENC,
        LIVE,
        LIVE_FANOUT,
        CALLS,
        MAX_CONCURRENT_CALLS,
        MAX_CONNECTIONS,
        HANDSHAKE_TIMEOUT_MS,
        IDLE_TIMEOUT_MS,
        SEND_FRAMES_PER_MINUTE,
        SEND_BYTES_PER_MINUTE,
        SMTP_URL,
        WRITE_MODE,
        RELEASE_CHECK,
        METRICS_GROUP_LABELS,
        BOOTSTRAP_HANDOFF_PUBKEY,
        OPERATOR_TOKEN,
        PROFILE,
        PUSH,
        PUSH_URL,
        PUSH_TOKEN,
        PUSH_REGISTER_URL,
        PUSH_COALESCE_MS,
        PUSH_QUEUE,
        JANITOR_INTERVAL_MS,
        GC_MIN_OBJECT_AGE_SECONDS,
        TRUSTED_PROXY_HOPS,
    ];
}

/// How `AUTH` is checked. `specs/backend/relay/server.md`: `enforce` means the
/// published access set decides, so revoking a device disconnects it. `off`
/// means any well-formed key may open a socket, which is appropriate only for a
/// relay with no public ingress.
///
/// `off` is disclosed on `/readyz`, because a customer should not have to read
/// their operator's environment file to learn it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessSetMode {
    Enforce,
    Off,
}

/// The encryption floor the relay accepts. `specs/backend/relay/wire.md`: `mls`
/// rejects every `enc: 0` envelope with `denied/plaintext_refused` and is the
/// only permitted value on the hosted tier; `none` accepts both and is available
/// to self-hosters during their own rollout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinEncryption {
    None,
    Mls,
}

/// TLS termination. `off` is bounded: the client refuses a plaintext socket
/// unless the host resolves to loopback, which is step 4's test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    Acme,
    File,
    Off,
}

/// Whether the ephemeral path (`LIVE`) is served.
///
/// `off` refuses every beat with `reject/protocol_unsupported` and is what a
/// self-hoster who does not want to carry presence traffic sets. A client told
/// `off` reports presence unavailable, which is the same thing it reports against
/// a version 1 relay: the one thing it must never do is render everybody offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveMode {
    On,
    Off,
}

/// How a beat reaches subscribers held by another process.
///
/// `specs/backend/relay/presence.md`: single-process fanout with a startup
/// refusal, rather than a Redis dependency this release does not take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveFanout {
    /// In-process channels. Correct in a single-process deployment and in no
    /// other, which is why the combination below is refused rather than warned
    /// about.
    Process,
    /// A shared fanout endpoint. Declared, and refused at startup by this build,
    /// because a setting the binary accepts and does not honour is worse than one
    /// it refuses: an operator would read the value back and believe presence
    /// crossed their instances.
    Shared(String),
}

/// Whether the call path (`CALL` and `MEDIA`) is served.
///
/// `off` refuses both frames with `reject/protocol_unsupported`, which is what a
/// version 3 client reads as calls being unavailable on this relay: the same
/// thing it reads from a version 2 relay, and a different thing from a call that
/// failed. `off` is the default, because carrying a sustained media stream is a
/// posture an operator adopts rather than one they inherit from an upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallMode {
    On,
    Off,
}

/// Whether the relay has an outbound wake leg.
///
/// `off` is the default and is a posture rather than a failure: a relay with no
/// ringer answers `denied/push_not_configured` to a `Register` and `enabled: false`
/// to a `Query`, and a client reads both as an instruction to hold no registration
/// and raise no expectation of push (`specs/backend/relay/push.md` section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushMode {
    On,
    Off,
}

/// A vendor-neutral local maintenance mode. `read_only` rejects new durable
/// writes while leaving reconciliation and export available. It does not contact
/// or name a billing system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    Full,
    ReadOnly,
}

/// Where blobs go. Both arms are behind one contract suite
/// (`crate::storage`), so the fake is not a hand-written approximation of the
/// real one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageTarget {
    /// `file:///var/lib/wealdrelay/blobs`
    Filesystem(PathBuf),
    /// `s3://bucket`, optionally with a key prefix.
    S3 { bucket: String, prefix: String },
}

/// A limit that may legitimately be absent. Spelled out rather than reusing
/// `Option<u64>` so `unlimited` reads as a decision at every use site: the spec's
/// default for both storage and retention is genuinely unlimited, and a zero
/// would be a very different setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Unlimited,
    Of(u64),
}

/// The whole configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub hostname: String,
    pub database_url: String,
    pub storage: StorageTarget,
    pub redis_url: Option<String>,
    pub listen: String,
    pub observability_listen: String,
    pub tls: TlsMode,
    /// The Postgres pool ceiling. See `keys::DB_POOL_SIZE`.
    pub db_pool_size: u32,
    pub max_storage_gb: Limit,
    /// The envelope log's per-workspace ceiling. See `keys::MAX_LOG_GB`.
    pub max_log_gb: Limit,
    pub retention_days: Limit,
    pub access_set: AccessSetMode,
    pub min_encryption: MinEncryption,
    pub live: LiveMode,
    pub live_fanout: LiveFanout,
    pub calls: CallMode,
    /// The concurrent-call ceiling. `None` exactly when calls are off, which is
    /// the one combination `enforce_calls` permits: a number is required whenever
    /// the feature is on, so nothing downstream has a default to fall back to.
    pub max_concurrent_calls: Option<u64>,
    pub max_connections: Limit,
    /// Upgrade to `AUTH_ACK`, in milliseconds. Never zero: `positive` refuses it,
    /// because a zero handshake deadline is a relay that refuses every client and
    /// is not a posture anybody can mean.
    pub handshake_timeout_ms: u64,
    /// Silence on an authenticated connection before the liveness ping, in
    /// milliseconds. Never zero, for the same reason.
    pub idle_timeout_ms: u64,
    /// The per-device inbound budget on `SEND`, in frames and in bytes per
    /// minute (`crate::send_budget`). Never zero, for the reason the deadlines are
    /// never zero: zero is not a smaller limit, it is a relay that refuses every
    /// write.
    pub send_frames_per_minute: u64,
    pub send_bytes_per_minute: u64,
    pub smtp_url: Option<String>,
    pub write_mode: WriteMode,
    pub release_check: bool,
    pub metrics_group_labels: bool,
    pub bootstrap_handoff_pubkey: Option<String>,
    /// The operator bearer, or `None` where the operator routes are not mounted.
    pub operator_token: Option<String>,
    pub profile: crate::profile::Profile,
    pub push: PushMode,
    /// Where a wake is POSTed. `Some` exactly when push is on, which
    /// `enforce_push` guarantees in both directions: on without a url does not
    /// start, and off with one does not either.
    pub push_url: Option<String>,
    pub push_token: Option<String>,
    /// What `Capability` states, when the operator set it explicitly. `None` means
    /// "derive it from the wake url", which `crate::push::Settings` does once.
    pub push_register_url: Option<String>,
    pub push_coalesce_ms: u64,
    pub push_queue: u64,
    /// How long the collector waits between passes. Never zero: `positive` refuses
    /// it, for the reason on `keys::JANITOR_INTERVAL_MS`.
    pub janitor_interval_ms: u64,
    /// How old an unreferenced object must be before the storage-listing sweep may
    /// delete it. See `keys::GC_MIN_OBJECT_AGE_SECONDS`.
    pub gc_min_object_age_seconds: u64,
    /// Declared reverse-proxy hops in front of this relay. Zero means direct, and
    /// zero ignores forwarding headers entirely. See `keys::TRUSTED_PROXY_HOPS`.
    pub trusted_proxy_hops: u64,
}

/// Why a configuration was refused.
///
/// Every variant names the key, because the operator's next action is to edit
/// that key and an error that does not name it makes them guess.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("{key} is required and is not set")]
    Missing { key: &'static str },
    #[error("{key} is set to an empty value; unset it instead of setting it to nothing")]
    Empty { key: &'static str },
    #[error("{key}={value} is not one of: {allowed}")]
    NotAllowed {
        key: &'static str,
        value: String,
        allowed: &'static str,
    },
    #[error("{key}={value} is not a number")]
    NotANumber { key: &'static str, value: String },
    #[error("{key}={value} must be a postgres:// or postgresql:// url")]
    NotAPostgresUrl { key: &'static str, value: String },
    #[error("{key}={value} must be file:// or s3://")]
    NotAStorageUrl { key: &'static str, value: String },
    #[error("{key}={value} must be host:port")]
    NotAnAddress { key: &'static str, value: String },
    #[error("relay.toml at {path} could not be read: {reason}")]
    UnreadableFile { path: String, reason: String },
    #[error("relay.toml at {path} is not valid TOML: {reason}")]
    MalformedFile { path: String, reason: String },
    #[error("relay.toml at {path} sets {key}, which is not a relay configuration key")]
    UnknownFileKey { path: String, key: String },
    #[error(
        "relay.toml at {path} sets {key} to a table or an array; every value must be a scalar"
    )]
    NonScalarFileValue { path: String, key: String },
    /// `process` fanout in a deployment that has declared more than one instance.
    ///
    /// Fatal rather than a warning, and this is the whole reason the setting
    /// exists. Two relay processes each fanning out in process would show every
    /// member exactly the half of the room that happens to share their socket, with
    /// nothing anywhere reporting a fault. A relay that will not start is a page a
    /// human reads; a half room is one nobody ever sees.
    #[error(
        "{key}=process is refused because {declared} declares more than one instance; \
         set {key} to a shared fanout url or set WEALD_RELAY_LIVE=off"
    )]
    LiveFanoutSingleProcess {
        key: &'static str,
        declared: &'static str,
    },
    /// A shared fanout url on a build that does not implement one.
    #[error("{key}={value} names a shared fanout, which this build does not implement")]
    LiveFanoutUnavailable { key: &'static str, value: String },
    /// A TLS mode on a build that terminates no TLS.
    ///
    /// Same principle as `LiveFanoutUnavailable`, and for a louder reason: a
    /// setting the binary accepts and does not honour is worse than one it
    /// refuses, and here the unhonoured setting is the one an operator reads as
    /// "this socket is encrypted". Nothing in this crate wraps the listener, so
    /// `acme` and `file` would bind the public address in cleartext while
    /// `--check-config` printed the mode back as confirmation.
    #[error(
        "{key}={value} asks this build to terminate TLS, which it does not implement: \
         terminate TLS at a reverse proxy and set {key}=off"
    )]
    TlsUnavailable {
        key: &'static str,
        value: &'static str,
    },
    /// Calls turned on without the ceiling that sizes them.
    ///
    /// Fatal at startup and never defaulted. A relay that invented a number would
    /// be a relay whose call capacity nobody chose, and the operator would meet it
    /// as a refusal during a call rather than as a line in their configuration.
    #[error("{key} is required when {because}=on and has no default: set it to the number of simultaneous calls this instance is sized for")]
    CallsCeilingMissing {
        key: &'static str,
        because: &'static str,
    },
    /// The ceiling set on an instance that does not carry calls.
    ///
    /// Refused rather than ignored, for the reason an empty value is refused: a
    /// setting the binary accepts and does not honour is one an operator reads
    /// back and believes.
    #[error("{key} is set but {because}=off, so it would do nothing; turn calls on or unset it")]
    CallsCeilingUnused {
        key: &'static str,
        because: &'static str,
    },
    /// `WEALD_RELAY_CALLS=on` in a deployment that has declared more than one
    /// instance.
    ///
    /// The same refusal `LIVE` gets and for a sharper reason. Call routing is
    /// process-local, so two instances would put the two halves of a call on
    /// different processes and the call would connect and then be silent. Chat
    /// degrades to reconciliation across a process boundary; a call has no
    /// reconciliation to degrade to.
    #[error(
        "{key}=on is refused because {declared} declares more than one instance and call routing \
         is process local; unset {declared} or set {key}=off"
    )]
    CallsSingleProcess {
        key: &'static str,
        declared: &'static str,
    },
    /// A zero ceiling, for either cap. Refused rather than read as "none": a
    /// relay that may carry no calls is one with `WEALD_RELAY_CALLS=off`, and a
    /// relay that may hold no connections is not a relay.
    #[error("{key}=0 is not a limit; use off or unlimited to say what you mean")]
    ZeroLimit { key: &'static str },
    /// Push on with nowhere to send a wake.
    ///
    /// Fatal and never defaulted, for the reason the call ceiling is never
    /// defaulted: this is a trust boundary, and an operator who meant to point at
    /// their own ringer must not silently inherit somebody else's.
    #[error(
        "{key} is required when {because}=on and has no default: a wake destination is a trust \
         boundary and inheriting one silently is the mistake this refusal exists to prevent"
    )]
    PushUrlMissing {
        key: &'static str,
        because: &'static str,
    },
    /// A `PUSH_*` variable set on a relay with push off.
    ///
    /// Refused rather than ignored. A configured-and-ignored outbound destination
    /// reads as working and is not, which is exactly the class of mistake
    /// `--check-config` exists to surface.
    #[error("{key} is set but {because}=off, so it would do nothing; turn push on or unset it")]
    PushSettingUnused {
        key: &'static str,
        because: &'static str,
    },
    /// A wake or registration url that is not `https` and not loopback.
    ///
    /// `push.md` section 5 exempts the `local` and `ci` profiles, and the exemption
    /// is spelled here as loopback because that is the part of it this binary can
    /// check: the relay has no notion of a build profile, and those two profiles are
    /// exactly the deployments whose ringer is a listener on 127.0.0.1 reaching no
    /// vendor at all. Anything else is a wake destination on the open internet, and
    /// a handle in cleartext there is a wake capability anybody on the path can use.
    #[error(
        "{key}={value} must be https, or http against loopback for a local harness ringer; \
         a plaintext wake url on any other host puts a wake capability on the wire"
    )]
    PushUrlNotSecure { key: &'static str, value: String },
    /// A setting the hosted profile forbids. Fatal at startup: a relay that
    /// logged about a forbidden setting and served anyway would be a relay whose
    /// posture nobody chose (`crate::profile`).
    #[error("{key} is refused on WEALD_RELAY_PROFILE=hosted: {reason}")]
    RefusedOnHostedProfile {
        key: &'static str,
        reason: &'static str,
    },
}

impl ConfigError {
    /// The key this failure is about, when it has one. Used by the startup path
    /// to guarantee the message names it.
    pub fn key(&self) -> Option<&str> {
        match self {
            Self::Missing { key }
            | Self::Empty { key }
            | Self::NotAllowed { key, .. }
            | Self::NotANumber { key, .. }
            | Self::NotAPostgresUrl { key, .. }
            | Self::NotAStorageUrl { key, .. }
            | Self::NotAnAddress { key, .. }
            | Self::RefusedOnHostedProfile { key, .. }
            | Self::LiveFanoutSingleProcess { key, .. }
            | Self::LiveFanoutUnavailable { key, .. }
            | Self::TlsUnavailable { key, .. }
            | Self::CallsCeilingMissing { key, .. }
            | Self::CallsCeilingUnused { key, .. }
            | Self::CallsSingleProcess { key, .. }
            | Self::PushUrlMissing { key, .. }
            | Self::PushSettingUnused { key, .. }
            | Self::PushUrlNotSecure { key, .. }
            | Self::ZeroLimit { key } => Some(key),
            Self::UnknownFileKey { key, .. } | Self::NonScalarFileValue { key, .. } => Some(key),
            Self::UnreadableFile { .. } | Self::MalformedFile { .. } => None,
        }
    }
}

/// Where a value came from. Reported by `relay --check-config` so an operator
/// can see which of two places is winning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Environment,
    File,
    Default,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Environment => write!(f, "environment"),
            Self::File => write!(f, "relay.toml"),
            Self::Default => write!(f, "default"),
        }
    }
}

/// The two places a value can come from, resolved.
///
/// The environment wins over the file. That order is the one every deployment
/// path in `server.md` depends on: the compose bundle ships a file and the
/// one-click templates set variables, and a template that could not override the
/// bundled file would be unable to set the hostname.
#[derive(Debug, Clone, Default)]
pub struct Values {
    environment: BTreeMap<String, String>,
    file: BTreeMap<String, String>,
}

impl Values {
    /// Read from a real process environment, keeping only the relay's own keys so
    /// nothing else on the machine can affect the result.
    pub fn from_env() -> Self {
        let mut environment = BTreeMap::new();
        for key in keys::ALL {
            if let Ok(value) = std::env::var(key) {
                environment.insert((*key).to_string(), value);
            }
        }
        Self {
            environment,
            file: BTreeMap::new(),
        }
    }

    /// For tests and for `--check-config` over a hypothetical environment.
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            environment: pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
            file: BTreeMap::new(),
        }
    }

    /// Merge an optional `relay.toml`. A file that is not there is not an error:
    /// the file is optional and the variables alone are a complete configuration.
    pub fn with_file(mut self, path: Option<&Path>) -> Result<Self, ConfigError> {
        let Some(path) = path else { return Ok(self) };
        if !path.exists() {
            return Ok(self);
        }
        let text = std::fs::read_to_string(path).map_err(|error| ConfigError::UnreadableFile {
            path: path.display().to_string(),
            reason: error.to_string(),
        })?;
        self.file = parse_toml(&text, path)?;
        Ok(self)
    }

    fn get(&self, key: &'static str) -> Option<(&str, Source)> {
        if let Some(value) = self.environment.get(key) {
            return Some((value.as_str(), Source::Environment));
        }
        self.file
            .get(key)
            .map(|value| (value.as_str(), Source::File))
    }

    /// Which source a key resolved from, or `Default` when neither set it.
    pub fn source_of(&self, key: &'static str) -> Source {
        self.get(key).map_or(Source::Default, |(_, source)| source)
    }
}

/// Read a `relay.toml` into the same flat key space the environment uses.
///
/// Two shapes are accepted for one reason each. Flat `WEALD_RELAY_HOSTNAME =
/// "..."` keys are what an operator copying their environment file into TOML will
/// write. Lowercase unprefixed keys under a `[relay]` table are what the compose
/// bundle ships, because repeating the prefix on every line of a file that is
/// already only about the relay is noise. Anything else is refused: a config file
/// key that silently does nothing is the same failure as a mistyped variable.
fn parse_toml(text: &str, path: &Path) -> Result<BTreeMap<String, String>, ConfigError> {
    // Parsed straight into a `Table` rather than into a `Value` and then matched.
    // A TOML document is always a table at its root, so a match would carry an arm
    // no input can reach, and an arm no input can reach is a coverage exclusion
    // wearing a different hat.
    let table: toml::Table = toml::from_str(text).map_err(|error| ConfigError::MalformedFile {
        path: path.display().to_string(),
        reason: error.message().to_string(),
    })?;

    let mut out = BTreeMap::new();
    for (key, value) in table {
        if key == "relay" {
            let toml::Value::Table(inner) = value else {
                return Err(ConfigError::NonScalarFileValue {
                    path: path.display().to_string(),
                    key,
                });
            };
            for (short, value) in inner {
                let full = format!("WEALD_RELAY_{}", short.to_uppercase());
                insert_file_value(&mut out, full, value, path)?;
            }
            continue;
        }
        insert_file_value(&mut out, key, value, path)?;
    }
    Ok(out)
}

fn insert_file_value(
    out: &mut BTreeMap<String, String>,
    key: String,
    value: toml::Value,
    path: &Path,
) -> Result<(), ConfigError> {
    if !keys::ALL.contains(&key.as_str()) {
        return Err(ConfigError::UnknownFileKey {
            path: path.display().to_string(),
            key,
        });
    }
    let rendered = match value {
        toml::Value::String(s) => s,
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        _ => {
            return Err(ConfigError::NonScalarFileValue {
                path: path.display().to_string(),
                key,
            })
        }
    };
    out.insert(key, rendered);
    Ok(())
}

impl Config {
    /// The label `/readyz` and the startup log use. One place, so the document and
    /// the log line cannot disagree about what the relay is enforcing.
    pub fn access_set_label(&self) -> &'static str {
        match self.access_set {
            AccessSetMode::Enforce => "enforce",
            AccessSetMode::Off => "off",
        }
    }

    /// The label `/readyz` and the startup log use for the ephemeral path.
    pub fn live_label(&self) -> &'static str {
        match self.live {
            LiveMode::On => "on",
            LiveMode::Off => "off",
        }
    }

    /// Refuse the one combination that would serve half a room.
    ///
    /// A `WEALD_RELAY_REDIS_URL` is how `specs/backend/relay/server.md` says a
    /// deployment declares that it runs more than one process: the table lists it
    /// as "omit for single-process installs". So the declaration already exists and
    /// this reads it rather than adding a second way to say the same thing.
    ///
    /// Skipped when the ephemeral path is off, because there is then no beat to
    /// fail to cross an instance boundary.
    /// Refuse a TLS mode nothing in the binary implements.
    ///
    /// `serve::bind` binds bare `TcpListener`s and `serve::run` hands them to
    /// `axum::serve` unwrapped; there is no acceptor and no certificate loader in
    /// this crate. Until there is, the only honest answer to `acme` or `file` is
    /// to refuse to start, so the operator meets the gap at startup rather than
    /// as plaintext frames on the public address.
    fn enforce_tls(&self) -> Result<(), ConfigError> {
        let value = match self.tls {
            TlsMode::Acme => "acme",
            TlsMode::File => "file",
            TlsMode::Off => return Ok(()),
        };
        Err(ConfigError::TlsUnavailable {
            key: keys::TLS,
            value,
        })
    }

    fn enforce_live_fanout(&self) -> Result<(), ConfigError> {
        if let LiveFanout::Shared(value) = &self.live_fanout {
            return Err(ConfigError::LiveFanoutUnavailable {
                key: keys::LIVE_FANOUT,
                value: value.clone(),
            });
        }
        if matches!(self.live, LiveMode::Off) || self.redis_url.is_none() {
            return Ok(());
        }
        Err(ConfigError::LiveFanoutSingleProcess {
            key: keys::LIVE_FANOUT,
            declared: keys::REDIS_URL,
        })
    }

    /// The label `/readyz` and the startup log use for the call path.
    pub fn calls_label(&self) -> &'static str {
        match self.calls {
            CallMode::On => "on",
            CallMode::Off => "off",
        }
    }

    /// The three rules that make the call configuration answerable rather than
    /// guessed: a ceiling exists exactly when calls do, and calls are refused in a
    /// deployment that has declared a second process.
    ///
    /// All three are startup refusals rather than warnings. A relay that will not
    /// start is a page a human reads; a call that connects and is silent is a bug
    /// report six months later.
    fn enforce_calls(&self) -> Result<(), ConfigError> {
        match (self.calls, self.max_concurrent_calls) {
            (CallMode::On, None) => {
                return Err(ConfigError::CallsCeilingMissing {
                    key: keys::MAX_CONCURRENT_CALLS,
                    because: keys::CALLS,
                })
            }
            (CallMode::Off, Some(_)) => {
                return Err(ConfigError::CallsCeilingUnused {
                    key: keys::MAX_CONCURRENT_CALLS,
                    because: keys::CALLS,
                })
            }
            (CallMode::On, Some(_)) | (CallMode::Off, None) => {}
        }
        if matches!(self.calls, CallMode::On) && self.redis_url.is_some() {
            return Err(ConfigError::CallsSingleProcess {
                key: keys::CALLS,
                declared: keys::REDIS_URL,
            });
        }
        Ok(())
    }

    /// The label `/readyz`, the startup log and `--check-config` use for push.
    pub fn push_label(&self) -> &'static str {
        match self.push {
            PushMode::On => "on",
            PushMode::Off => "off",
        }
    }

    /// The four rules that make the push configuration answerable rather than
    /// guessed, all four fatal at startup (`specs/backend/relay/push.md` section 5).
    ///
    /// Fatal rather than warned about, for the reason the call rules are: a relay
    /// that will not start is a page a human reads, and a relay that quietly holds a
    /// wake destination nobody chose is a privacy failure nobody sees.
    fn enforce_push(&self) -> Result<(), ConfigError> {
        match (self.push, self.push_url.as_deref()) {
            (PushMode::On, None) => {
                return Err(ConfigError::PushUrlMissing {
                    key: keys::PUSH_URL,
                    because: keys::PUSH,
                })
            }
            (PushMode::Off, Some(_)) => {
                return Err(ConfigError::PushSettingUnused {
                    key: keys::PUSH_URL,
                    because: keys::PUSH,
                })
            }
            (PushMode::On, Some(_)) | (PushMode::Off, None) => {}
        }
        // The other three, in the order an operator is most likely to have set them.
        // Each is refused rather than ignored: a variable the binary accepts and does
        // not honour is one an operator reads back and believes.
        if matches!(self.push, PushMode::Off) {
            for (key, set) in [
                (keys::PUSH_TOKEN, self.push_token.is_some()),
                (keys::PUSH_REGISTER_URL, self.push_register_url.is_some()),
                (
                    keys::PUSH_COALESCE_MS,
                    self.push_coalesce_ms != crate::push::DEFAULT_COALESCE_MS,
                ),
                (
                    keys::PUSH_QUEUE,
                    self.push_queue != crate::push::DEFAULT_QUEUE,
                ),
            ] {
                if set {
                    return Err(ConfigError::PushSettingUnused {
                        key,
                        because: keys::PUSH,
                    });
                }
            }
            return Ok(());
        }
        for (key, url) in [
            (keys::PUSH_URL, self.push_url.as_deref()),
            (keys::PUSH_REGISTER_URL, self.push_register_url.as_deref()),
        ] {
            if let Some(url) = url {
                if !is_secure_push_url(url) {
                    return Err(ConfigError::PushUrlNotSecure {
                        key,
                        value: url.to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    pub fn min_enc_label(&self) -> &'static str {
        match self.min_encryption {
            MinEncryption::None => "none",
            MinEncryption::Mls => "mls",
        }
    }

    /// Defaults, for every optional key. Named here so the table in
    /// `server.md` has exactly one counterpart in code.
    pub const DEFAULT_LISTEN: &'static str = "0.0.0.0:8443";
    pub const DEFAULT_OBSERVABILITY_LISTEN: &'static str = "127.0.0.1:9090";

    /// Resolve a configuration, or refuse with a message naming the key.
    pub fn resolve(values: &Values) -> Result<Self, ConfigError> {
        let hostname = required(values, keys::HOSTNAME)?.to_string();
        let database_url = postgres_url(values, keys::DATABASE_URL)?;
        let storage = storage_target(values, keys::STORAGE_URL)?;

        let resolved = Self {
            hostname,
            database_url,
            storage,
            redis_url: optional(values, keys::REDIS_URL)?.map(str::to_string),
            listen: address(values, keys::LISTEN, Self::DEFAULT_LISTEN)?,
            observability_listen: address(
                values,
                keys::OBSERVABILITY_LISTEN,
                Self::DEFAULT_OBSERVABILITY_LISTEN,
            )?,
            tls: one_of(
                values,
                keys::TLS,
                TlsMode::Off,
                "acme, file, off",
                &[
                    ("acme", TlsMode::Acme),
                    ("file", TlsMode::File),
                    ("off", TlsMode::Off),
                ],
            )?,
            max_storage_gb: capacity(values, keys::MAX_STORAGE_GB)?,
            max_log_gb: capacity(values, keys::MAX_LOG_GB)?,
            retention_days: limit(values, keys::RETENTION_DAYS)?,
            // `enforce` in every environment including local, so nobody ever
            // develops against the permissive path and discovers the difference
            // in staging (specs/backend/build/environments.md).
            access_set: one_of(
                values,
                keys::ACCESS_SET,
                AccessSetMode::Enforce,
                "enforce, off",
                &[
                    ("enforce", AccessSetMode::Enforce),
                    ("off", AccessSetMode::Off),
                ],
            )?,
            // The default is `none` because the migration in
            // specs/backend/relay/migration.md has phases where envelopes are
            // signed and not encrypted, and a default of `mls` would make a
            // self-hoster's Phase 2 impossible. The hosted tier pins `mls` and
            // does not make it configurable, which is a property of that
            // deployment rather than of this default.
            min_encryption: one_of(
                values,
                keys::MIN_ENC,
                MinEncryption::None,
                "none, mls",
                &[("none", MinEncryption::None), ("mls", MinEncryption::Mls)],
            )?,
            // `on` by default, because the product's presence surfaces are the
            // ordinary shape of the app and an operator who wants them off says so.
            live: one_of(
                values,
                keys::LIVE,
                LiveMode::On,
                "on, off",
                &[("on", LiveMode::On), ("off", LiveMode::Off)],
            )?,
            live_fanout: live_fanout(values, keys::LIVE_FANOUT)?,
            // `off` by default, unlike `live`. See `keys::CALLS`.
            calls: one_of(
                values,
                keys::CALLS,
                CallMode::Off,
                "on, off",
                &[("on", CallMode::On), ("off", CallMode::Off)],
            )?,
            max_concurrent_calls: positive(values, keys::MAX_CONCURRENT_CALLS)?,
            // A number rather than `Unlimited` by default, which is the whole
            // point of closing the gap: the previous behaviour was unlimited and
            // it is the behaviour being replaced. Two hundred and fifty six
            // sockets against an 8 MiB per-connection queue budget is two
            // gigabytes at the absolute ceiling, which is a bound a modest
            // instance survives; an operator with more memory says so.
            max_connections: connection_limit(values, keys::MAX_CONNECTIONS)?,
            // `positive` rather than `count`, so `0` is refused at startup rather
            // than resolved into a relay that closes every connection the instant
            // it is opened. It is the same refusal `WEALD_RELAY_MAX_CONNECTIONS=0`
            // gets and for the same reason: zero is not a smaller limit, it is a
            // service that does not run.
            handshake_timeout_ms: positive(values, keys::HANDSHAKE_TIMEOUT_MS)?
                .unwrap_or(crate::deadline::DEFAULT_HANDSHAKE_TIMEOUT_MS),
            idle_timeout_ms: positive(values, keys::IDLE_TIMEOUT_MS)?
                .unwrap_or(crate::deadline::DEFAULT_IDLE_TIMEOUT_MS),
            // `positive` for the deadlines' reason: a zero here is a relay that
            // answers `quota` to every `SEND` any device ever makes, which is not
            // a posture anybody means, so it is refused at startup rather than
            // discovered when a workspace goes silent.
            send_frames_per_minute: positive(values, keys::SEND_FRAMES_PER_MINUTE)?
                .unwrap_or(crate::send_budget::DEFAULT_SEND_FRAMES_PER_MINUTE),
            send_bytes_per_minute: positive(values, keys::SEND_BYTES_PER_MINUTE)?
                .unwrap_or(crate::send_budget::DEFAULT_SEND_BYTES_PER_MINUTE),
            db_pool_size: pool_size(values, keys::DB_POOL_SIZE)?,
            smtp_url: optional(values, keys::SMTP_URL)?.map(str::to_string),
            write_mode: one_of(
                values,
                keys::WRITE_MODE,
                WriteMode::Full,
                "full, read_only",
                &[
                    ("full", WriteMode::Full),
                    ("read_only", WriteMode::ReadOnly),
                ],
            )?,
            release_check: on_off(values, keys::RELEASE_CHECK, true)?,
            metrics_group_labels: on_off(values, keys::METRICS_GROUP_LABELS, false)?,
            bootstrap_handoff_pubkey: optional(values, keys::BOOTSTRAP_HANDOFF_PUBKEY)?
                .map(str::to_string),
            operator_token: optional(values, keys::OPERATOR_TOKEN)?.map(str::to_string),
            profile: one_of(
                values,
                keys::PROFILE,
                crate::profile::Profile::SelfHost,
                crate::profile::Profile::ALLOWED,
                crate::profile::Profile::TABLE,
            )?,
            // `off` by default, like `calls` and unlike `live`. Push is the only
            // component of this system that talks to a party outside the operator's
            // control, so it is a posture an operator adopts rather than one they
            // inherit from an upgrade (`specs/backend/relay/push.md` section 5).
            push: one_of(
                values,
                keys::PUSH,
                PushMode::Off,
                "on, off",
                &[("on", PushMode::On), ("off", PushMode::Off)],
            )?,
            push_url: optional(values, keys::PUSH_URL)?.map(str::to_string),
            push_token: optional(values, keys::PUSH_TOKEN)?.map(str::to_string),
            push_register_url: optional(values, keys::PUSH_REGISTER_URL)?.map(str::to_string),
            // Zero is legal here and means no coalescing, so this is not `positive`:
            // a relay whose operator wants every wake sent as it arrives is a
            // deployment, not a mistake.
            push_coalesce_ms: count(
                values,
                keys::PUSH_COALESCE_MS,
                crate::push::DEFAULT_COALESCE_MS,
            )?,
            push_queue: positive(values, keys::PUSH_QUEUE)?.unwrap_or(crate::push::DEFAULT_QUEUE),
            janitor_interval_ms: positive(values, keys::JANITOR_INTERVAL_MS)?
                .unwrap_or(crate::janitor::DEFAULT_INTERVAL_MS),
            // `count` rather than `positive`: zero is a meaningful setting here and
            // means no floor at all, which is the self-hoster who keeps no backups
            // and wants a planted object collected on the next pass.
            gc_min_object_age_seconds: count(
                values,
                keys::GC_MIN_OBJECT_AGE_SECONDS,
                crate::media::gc::DEFAULT_MIN_OBJECT_AGE_SECONDS,
            )?,
            // `count` with a zero default rather than `positive`: zero is the
            // meaningful value here, not a refused one. It says the relay is
            // reached directly, which is what a developer running it on a laptop
            // has, and it is the only setting under which a forwarding header is
            // safe to ignore rather than trust.
            trusted_proxy_hops: count(values, keys::TRUSTED_PROXY_HOPS, 0)?,
        };
        resolved.enforce_tls()?;
        resolved.enforce_live_fanout()?;
        resolved.enforce_calls()?;
        resolved.enforce_push()?;
        // Last, because the hosted rules are about the resolved values rather
        // than about the strings, and a rule that ran mid-resolution would have
        // to be re-stated for every source a value can come from.
        crate::profile::enforce(&resolved)?;
        Ok(resolved)
    }
}

/// `process`, or anything else read as a shared fanout endpoint.
///
/// Not `one_of`, because the second arm is an open-ended value rather than a
/// member of a closed set, and `one_of`'s error would have listed a url as if it
/// were a keyword.
fn live_fanout(values: &Values, key: &'static str) -> Result<LiveFanout, ConfigError> {
    match optional(values, key)? {
        None | Some("process") => Ok(LiveFanout::Process),
        Some(value) => Ok(LiveFanout::Shared(value.to_string())),
    }
}

fn optional<'a>(values: &'a Values, key: &'static str) -> Result<Option<&'a str>, ConfigError> {
    match values.get(key) {
        None => Ok(None),
        // An empty value is refused rather than read as absent. `FOO=` in a
        // compose file is almost always a variable somebody meant to fill in,
        // and treating it as unset would start the relay in a posture nobody
        // chose.
        Some((value, _)) if value.trim().is_empty() => Err(ConfigError::Empty { key }),
        Some((value, _)) => Ok(Some(value)),
    }
}

fn required<'a>(values: &'a Values, key: &'static str) -> Result<&'a str, ConfigError> {
    optional(values, key)?.ok_or(ConfigError::Missing { key })
}

fn postgres_url(values: &Values, key: &'static str) -> Result<String, ConfigError> {
    let value = required(values, key)?;
    let parsed = url::Url::parse(value).map_err(|_| ConfigError::NotAPostgresUrl {
        key,
        value: value.to_string(),
    })?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql") {
        return Err(ConfigError::NotAPostgresUrl {
            key,
            value: value.to_string(),
        });
    }
    Ok(value.to_string())
}

fn storage_target(values: &Values, key: &'static str) -> Result<StorageTarget, ConfigError> {
    let value = required(values, key)?;
    let parsed = url::Url::parse(value).map_err(|_| ConfigError::NotAStorageUrl {
        key,
        value: value.to_string(),
    })?;
    match parsed.scheme() {
        "file" => {
            let path = parsed
                .to_file_path()
                .map_err(|()| ConfigError::NotAStorageUrl {
                    key,
                    value: value.to_string(),
                })?;
            Ok(StorageTarget::Filesystem(path))
        }
        "s3" => {
            let bucket = parsed.host_str().unwrap_or_default();
            if bucket.is_empty() {
                return Err(ConfigError::NotAStorageUrl {
                    key,
                    value: value.to_string(),
                });
            }
            Ok(StorageTarget::S3 {
                bucket: bucket.to_string(),
                prefix: parsed.path().trim_matches('/').to_string(),
            })
        }
        _ => Err(ConfigError::NotAStorageUrl {
            key,
            value: value.to_string(),
        }),
    }
}

fn address(
    values: &Values,
    key: &'static str,
    default: &'static str,
) -> Result<String, ConfigError> {
    let Some(value) = optional(values, key)? else {
        return Ok(default.to_string());
    };
    // Split from the right, so an IPv6 literal in brackets survives.
    let (host, port) = value.rsplit_once(':').ok_or(ConfigError::NotAnAddress {
        key,
        value: value.to_string(),
    })?;
    if host.is_empty() || port.parse::<u16>().is_err() {
        return Err(ConfigError::NotAnAddress {
            key,
            value: value.to_string(),
        });
    }
    Ok(value.to_string())
}

/// A capacity ceiling, where zero is refused rather than obeyed.
///
/// The same reasoning as ``positive`` and ``connection_limit``: zero is not a
/// smaller ceiling, it is a relay that starts, passes health, reports ready and
/// then answers `quota` to every write. A provisioner template that renders an
/// unset variable as `0` must fail at boot naming the variable, not silently at
/// the first `SEND`. `unlimited` remains the only way to say no ceiling.
fn capacity(values: &Values, key: &'static str) -> Result<Limit, ConfigError> {
    match limit(values, key)? {
        Limit::Of(0) => Err(ConfigError::ZeroLimit { key }),
        other => Ok(other),
    }
}

fn limit(values: &Values, key: &'static str) -> Result<Limit, ConfigError> {
    let Some(value) = optional(values, key)? else {
        return Ok(Limit::Unlimited);
    };
    if value.eq_ignore_ascii_case("unlimited") {
        return Ok(Limit::Unlimited);
    }
    value
        .parse::<u64>()
        .map(Limit::Of)
        .map_err(|_| ConfigError::NotANumber {
            key,
            value: value.to_string(),
        })
}

/// An optional count that must be at least one when it is there.
///
/// Separate from ``limit`` because there is no `unlimited` here: an unbounded
/// number of simultaneous calls is the sizing decision this key exists to refuse.
fn positive(values: &Values, key: &'static str) -> Result<Option<u64>, ConfigError> {
    let Some(value) = optional(values, key)? else {
        return Ok(None);
    };
    let parsed = value.parse::<u64>().map_err(|_| ConfigError::NotANumber {
        key,
        value: value.to_string(),
    })?;
    if parsed == 0 {
        return Err(ConfigError::ZeroLimit { key });
    }
    Ok(Some(parsed))
}

/// A plain count with a default, where zero is a legal value that means something.
///
/// Separate from ``positive`` because zero is the whole point at the one key that
/// uses this: `WEALD_RELAY_PUSH_COALESCE_MS=0` is "send every wake as it arrives",
/// which is a posture rather than the absent limit ``positive`` exists to refuse.
fn count(values: &Values, key: &'static str, default: u64) -> Result<u64, ConfigError> {
    let Some(value) = optional(values, key)? else {
        return Ok(default);
    };
    value.parse::<u64>().map_err(|_| ConfigError::NotANumber {
        key,
        value: value.to_string(),
    })
}

/// Whether a wake destination may be used as written.
///
/// The rule itself is `crate::push::is_acceptable_register_url`, and it lives there
/// because the `WAKE` codec applies the same one: a relay that refused a url at
/// startup and encoded one on the wire would be two rules with one name. Here it is
/// wrapped only to refuse the empty string, which is a legal `Capability` field
/// meaning "no ringer" and is not a legal wake destination.
fn is_secure_push_url(value: &str) -> bool {
    !value.is_empty() && crate::push::is_acceptable_register_url(value)
}

/// The socket cap: a number, or `unlimited` for the behaviour this key replaced.
fn connection_limit(values: &Values, key: &'static str) -> Result<Limit, ConfigError> {
    /// Sized against ``crate::ws::SEND_QUEUE_BYTE_BUDGET``: this many connections
    /// each at their absolute queue ceiling is two gibibytes, which is the point
    /// beyond which a modest instance is killed rather than degraded.
    const DEFAULT: u64 = 256;

    let Some(value) = optional(values, key)? else {
        return Ok(Limit::Of(DEFAULT));
    };
    if value.eq_ignore_ascii_case("unlimited") {
        return Ok(Limit::Unlimited);
    }
    let parsed = value.parse::<u64>().map_err(|_| ConfigError::NotANumber {
        key,
        value: value.to_string(),
    })?;
    if parsed == 0 {
        return Err(ConfigError::ZeroLimit { key });
    }
    Ok(Limit::Of(parsed))
}

/// The Postgres pool ceiling: a positive integer, defaulting to the relay's own
/// sizing. Unlike `connection_limit` there is no `unlimited`, because an
/// unbounded pool against a database with a per-plan connection cap is not a
/// choice an operator can mean.
fn pool_size(values: &Values, key: &'static str) -> Result<u32, ConfigError> {
    let Some(value) = optional(values, key)? else {
        return Ok(crate::db::DEFAULT_POOL_SIZE);
    };
    let parsed = value.parse::<u32>().map_err(|_| ConfigError::NotANumber {
        key,
        value: value.to_string(),
    })?;
    if parsed == 0 {
        return Err(ConfigError::ZeroLimit { key });
    }
    Ok(parsed)
}

fn one_of<T: Copy>(
    values: &Values,
    key: &'static str,
    default: T,
    allowed: &'static str,
    table: &[(&str, T)],
) -> Result<T, ConfigError> {
    let Some(value) = optional(values, key)? else {
        return Ok(default);
    };
    table
        .iter()
        .find(|(name, _)| *name == value)
        .map(|(_, parsed)| *parsed)
        .ok_or(ConfigError::NotAllowed {
            key,
            value: value.to_string(),
            allowed,
        })
}

fn on_off(values: &Values, key: &'static str, default: bool) -> Result<bool, ConfigError> {
    one_of(
        values,
        key,
        default,
        "on, off",
        &[("on", true), ("off", false)],
    )
}
