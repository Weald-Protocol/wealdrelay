// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Push wake: how a relay rings a device that is not holding a socket.
//!
//! `specs/backend/relay/push.md` is the normative half and this module is its
//! implementation. The one sentence that decides the shape of everything here is
//! section 1's: the relay holds no APNs key, no token and no Apple relationship,
//! because a self-hosted relay is Apache 2.0 source a stranger rebuilds and the app
//! it talks to is our App Store build under our bundle identifiers. A key is minted
//! against a bundle identifier, so a self-hoster cannot mint ours and we cannot ship
//! ours inside published source.
//!
//! So the component that talks to Apple is separated, published as its own contract
//! (`specs/backend/relay/ringer.md`), and addressed by URL. What the relay knows is
//! a handle and a category. What it sends is a POST. Authority to wake a device is
//! possession of the handle, which is a capability the device minted and handed out,
//! and that is what makes this legal under `server.md`: no account, no licence, no
//! credential we issue, and therefore no dependency on a commercial layer.
//!
//! ## The three absences, and where each one is enforced
//!
//! Section 2 makes three absences load-bearing, and each is a mechanism here rather
//! than a rule in a document:
//!
//! - **A handle never reaches a log line, at any level.** ``crate::frame::WakeBody``
//!   has a hand-written `Debug` that prints the form and redacts the fields, this
//!   module's own types do the same, `crate::logging::SENSITIVE_KEYS` carries
//!   `handle`, and no call site formats one.
//! - **A handle is never returned by the `ACCESS` state query.** That query carries
//!   two facts (`crate::access::encode_state`) and this module adds nothing to it.
//! - **A handle is never derived from anything.** Nothing here computes one. It
//!   arrives on a `WAKE` frame, is stored verbatim, and is compared for equality.
//!
//! ## Never on the latency path of a `SEND`
//!
//! The write commits first, always. The wake is dispatched from a detached task
//! (`dispatch::after_commit`), the queue is bounded, and the worker is the only
//! thing that ever waits on the network. The requirement is stated as a test rather
//! than as prose: a ringer that accepts a connection and then hangs for thirty
//! seconds adds no measurable latency to `SEND` on the same process, and
//! `tests/push_adversarial.rs` proves it.
//!
//! ## A note for the release
//!
//! The outbound leg uses `hyper`, `hyper-util`, `hyper-rustls` and
//! `http-body-util`, all of which were already in this tree transitively under
//! `axum` and the AWS SDK. The public mirror's `Cargo.toml` is owned there and is
//! applied by hand in the commit that bumps the version, per
//! `specs/backend/build/relay-publication.md`.

pub mod dispatch;
pub mod queue;
pub mod ringer;
pub mod store;
pub mod worker;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::{Mutex, Notify};

use crate::config::{Config, PushMode};
use crate::frame::WakeBody;

/// How many bytes a handle is, exactly.
///
/// Sixteen, from `specs/backend/relay/ringer.md`: enough that guessing one is not a
/// strategy, short enough that a wake request is a few hundred bytes. Fixed rather
/// than bounded, because a variable-length capability would let two encodings name
/// one device.
pub const HANDLE_BYTES: usize = 16;

/// The longest `register_url` the relay will state or accept.
///
/// 512 bytes, which `push.md` section 3 fixes and which the client enforces on its
/// own side. Both halves check it, because a client that trusted the relay's bound
/// would be a client with no bound at all.
pub const MAX_REGISTER_URL_BYTES: usize = 512;

/// The most registrations one principal may make in an hour.
///
/// Five. Rotation is weekly by design, so five is generous, and the ceiling exists
/// because a registration is a database write and a device with a retry loop must
/// not be one.
pub const REGISTRATIONS_PER_HOUR: u32 = 5;

/// The window the rate ceiling is measured over, in milliseconds.
pub const RATE_WINDOW_MS: u64 = 60 * 60 * 1000;

/// The bound on the wake queue, when the operator has not said otherwise.
///
/// A bound and not a target. Push is best effort by construction: the client's
/// reconciliation path is what makes a lost wake survivable, and a queue that grew
/// would trade a lost notification for an exhausted relay.
pub const DEFAULT_QUEUE: u64 = 1024;

/// The coalescing window, when the operator has not said otherwise.
///
/// Two seconds, so a burst of twenty envelopes is one wake. Zero is legal and means
/// no coalescing at all.
pub const DEFAULT_COALESCE_MS: u64 = 2000;

/// The deadline on one outbound wake. Two seconds, from `push.md` section 4.
///
/// A deadline and not a retry budget. Past it the wake is counted and dropped,
/// because the alternative is a queue that grows behind a ringer that is not
/// answering, and a relay that runs out of memory has failed at its actual job.
pub const WAKE_DEADLINE_MS: u64 = 2000;

/// The path the ringer serves registration on, appended to the wake URL when
/// `WEALD_RELAY_PUSH_REGISTER_URL` is not set. `ringer.md` route 1.
pub const RINGER_REGISTER_PATH: &str = "/v1/handles";

/// What a wake says, and the whole of what it says.
///
/// A closed enum of three values the relay can determine without reading
/// ciphertext. No counts, no sizes, no group, no epoch, no sequence, no sender, no
/// channel, and no timestamp beyond the fact of the request itself. There is
/// nowhere in this type for anything more, which is the point of it being a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// An envelope accepted for a group this principal is admitted to.
    Message = 1,
    /// A `CALL` frame of kind `offer` routed to this principal.
    Call = 2,
    /// A `HANDSHAKE` message accepted for a group this principal is in.
    Handshake = 4,
}

impl Category {
    /// The bit this category occupies in a registration's mask.
    pub fn bit(self) -> u8 {
        self as u8
    }

    /// The wire name, which is the only form the ringer accepts (`ringer.md`
    /// route 3). Stable strings, because the ringer branches on them.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Call => "call",
            Self::Handshake => "handshake",
        }
    }

    /// Whether a device that registered `mask` wants to be woken for this.
    ///
    /// A masked-out wake is not sent, rather than sent and ignored by the device.
    /// The difference is what the ringer learns: a wake it never receives is a fact
    /// it never holds.
    pub fn admitted_by(self, mask: u8) -> bool {
        mask & self.bit() != 0
    }

    /// Whether this category jumps the coalescing window.
    ///
    /// Only `call`. A ring that arrives two seconds late is a missed call, and a
    /// message notification that arrives two seconds late is a message
    /// notification.
    pub fn is_urgent(self) -> bool {
        matches!(self, Self::Call)
    }

    /// Every category, so a test can walk them rather than remember them.
    pub const ALL: &'static [Self] = &[Self::Message, Self::Call, Self::Handshake];
}

/// Every bit this version defines, as a mask. `1 | 2 | 4`.
pub const ALL_CATEGORIES: u8 = 0b0000_0111;

/// Whether a registration's bitmask is one this version can honour.
///
/// At least one bit, and no bit above 4. Zero is refused rather than read as "wake
/// me for nothing", because a device that wants no wakes sends `Clear` and a zero
/// mask is a client bug; an undefined bit is a client from a version this relay
/// does not speak, and silently masking it off would store a registration whose
/// meaning the two ends disagree about.
pub fn is_valid_mask(mask: u8) -> bool {
    mask != 0 && mask & !ALL_CATEGORIES == 0
}

/// Whether a url may be stated to a device as its ringer, or used as a wake
/// destination.
///
/// `https` anywhere, or `http` against loopback. One rule in one place, used by the
/// startup refusal in `crate::config` and by the `WAKE` codec, because a relay that
/// refused a url at startup and encoded one on the wire would be two rules with one
/// name. The loopback arm is the code-checkable form of `push.md` section 5's
/// exemption for the `local` and `ci` profiles: this binary has no notion of a build
/// profile, and what is true of those two is that their ringer is a listener on
/// 127.0.0.1 which reaches no vendor at all.
///
/// The empty string is acceptable and means "no ringer", which is what a relay with
/// push off states in a `Capability` and what a client reads as an instruction to
/// hold no registration.
pub fn is_acceptable_register_url(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let Ok(parsed) = url::Url::parse(value) else {
        return false;
    };
    match parsed.scheme() {
        "https" => true,
        "http" => matches!(
            parsed.host_str(),
            Some("127.0.0.1" | "localhost" | "::1" | "[::1]")
        ),
        _ => false,
    }
}

/// The resolved push configuration, as the rest of the relay reads it.
///
/// Built once from `Config` so nothing downstream re-derives a URL or a default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Where a wake is POSTed. `None` exactly when push is off, which
    /// `Config::enforce_push` guarantees.
    pub wake_url: Option<String>,
    /// The bearer, when the ringer is configured with one. Never logged and never
    /// printed by `--check-config`; see ``crate::describe_config``.
    pub token: Option<String>,
    /// What `Capability` states. Defaulted from the wake url and the ringer's own
    /// registration path rather than guessed by the client.
    pub register_url: String,
    pub coalesce_ms: u64,
    pub queue_bound: usize,
}

impl Settings {
    /// Read the six variables into the shape this module uses.
    ///
    /// The refusals are `Config`'s, not this function's: a configuration that
    /// reached here is one the relay has already agreed to start with, so there is
    /// no failure arm to write and none to leave untested.
    pub fn from_config(config: &Config) -> Self {
        let wake_url = match config.push {
            PushMode::On => config.push_url.clone(),
            PushMode::Off => None,
        };
        let register_url = config
            .push_register_url
            .clone()
            .or_else(|| {
                wake_url
                    .as_deref()
                    .map(|url| format!("{}{RINGER_REGISTER_PATH}", url.trim_end_matches('/')))
            })
            .unwrap_or_default();
        Self {
            wake_url,
            token: config.push_token.clone(),
            register_url,
            coalesce_ms: config.push_coalesce_ms,
            queue_bound: usize::try_from(config.push_queue).unwrap_or(usize::MAX),
        }
    }

    pub fn enabled(&self) -> bool {
        self.wake_url.is_some()
    }
}

/// What `/readyz` reports about push. Three states, and the third is not un-ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// `WEALD_RELAY_PUSH=off`. A supported deployment and the default.
    Off,
    /// On, and the ringer has not refused anything.
    Configured,
    /// On, and the last wake did not reach the ringer.
    ///
    /// Deliberately not un-ready. A relay whose ringer is down still accepts,
    /// stores and serves, and taking a whole deployment out of a load balancer for a
    /// best-effort side channel would be the wrong trade by a wide margin.
    Unreachable,
}

impl Health {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Configured => "configured",
            Self::Unreachable => "unreachable",
        }
    }
}

/// The wake path's whole state: the queue, the settings and four counters.
///
/// Counters and never labels. `push.md` section 4 says a full queue "increments a
/// counter with no content-derived label", and that applies to all four of these:
/// not one is per handle, per workspace, per group or per principal, because a
/// labelled count here would be exactly the metadata the rest of this design spends
/// its budget keeping out.
#[derive(Debug)]
pub struct Push {
    pub settings: Settings,
    queue: Mutex<queue::Queue>,
    /// Woken when something is enqueued, so the worker sleeps rather than polls.
    wake: Notify,
    sent: AtomicU64,
    dropped: AtomicU64,
    failed: AtomicU64,
    /// How many times a ringer's `429` has paused the worker. An operator counter,
    /// and the only observable difference between a ringer that is rate limiting and
    /// one that is merely slow.
    pauses: AtomicU64,
    /// Whether the last outbound attempt reached the ringer. Seeded true, because
    /// a relay that has not tried yet has not failed.
    reachable: std::sync::atomic::AtomicBool,
}

impl Push {
    pub fn new(settings: Settings) -> Self {
        let bound = settings.queue_bound;
        Self {
            settings,
            queue: Mutex::new(queue::Queue::new(bound)),
            wake: Notify::new(),
            sent: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            pauses: AtomicU64::new(0),
            reachable: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// From a configuration, which is how ``crate::health::RelayState`` builds one.
    pub fn from_config(config: &Config) -> Self {
        Self::new(Settings::from_config(config))
    }

    pub fn enabled(&self) -> bool {
        self.settings.enabled()
    }

    /// The answer to a `Query`, which is the whole of forms 5 and 6.
    pub fn capability(&self) -> WakeBody {
        WakeBody::Capability {
            enabled: self.enabled(),
            register_url: self.settings.register_url.clone(),
        }
    }

    /// Put one wake on the queue, coalescing it against what is already there.
    ///
    /// Returns whether anything was added, which is what a test asserts on and what
    /// the drop counter is derived from. Never blocks on anything but the queue's own
    /// mutex, whose critical section is a map lookup.
    pub async fn enqueue(&self, handle: Vec<u8>, category: Category, now_ms: u64) -> queue::Admit {
        let admitted = {
            let mut queue = self.queue.lock().await;
            queue.admit(handle, category, now_ms, self.settings.coalesce_ms)
        };
        if matches!(admitted, queue::Admit::Dropped) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        // Notified even for a coalesced wake. The worker's next deadline may have
        // moved forward (a `call` supersedes a pending `message` and is due now), and
        // a notification the worker does not need costs it one loop iteration.
        self.wake.notify_one();
        admitted
    }

    /// Wait until there is plausibly something to do.
    ///
    /// Either an enqueue notified, or the earliest deadline in the queue has passed.
    /// A timeout rather than a poll, because the ordinary state of this worker is
    /// nothing to do at all.
    pub async fn wait_for_work(&self, now_ms: u64) {
        let sleep_for = {
            let queue = self.queue.lock().await;
            queue.next_deadline().map(|due| due.saturating_sub(now_ms))
        };
        match sleep_for {
            Some(delay) => {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(delay),
                    self.wake.notified(),
                )
                .await;
            }
            None => self.wake.notified().await,
        }
    }

    /// Everything whose window has closed, in the order it became due.
    pub async fn take_due(&self, now_ms: u64) -> Vec<(Vec<u8>, Category)> {
        self.queue.lock().await.take_due(now_ms)
    }

    /// How many wakes are waiting for their window to close.
    pub async fn queued(&self) -> usize {
        self.queue.lock().await.len()
    }

    /// Record the outcome of one outbound attempt.
    pub fn record(&self, outcome: ringer::Outcome) {
        match outcome {
            ringer::Outcome::Accepted => {
                self.sent.fetch_add(1, Ordering::Relaxed);
                self.reachable.store(true, Ordering::Relaxed);
            }
            // The ringer answered, so it is reachable. What it said is a fact about
            // one handle rather than about the deployment.
            ringer::Outcome::Unknown | ringer::Outcome::Refused => {
                self.failed.fetch_add(1, Ordering::Relaxed);
                self.reachable.store(true, Ordering::Relaxed);
            }
            ringer::Outcome::Paused { .. } => {
                self.reachable.store(true, Ordering::Relaxed);
            }
            ringer::Outcome::Unreachable => {
                self.failed.fetch_add(1, Ordering::Relaxed);
                self.reachable.store(false, Ordering::Relaxed);
            }
        }
    }

    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    /// Wakes dropped because the queue was at its bound.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Wakes the ringer did not accept, for any reason.
    pub fn failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }

    /// Note that a ringer told this worker to wait.
    pub fn note_pause(&self) {
        self.pauses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn pauses(&self) -> u64 {
        self.pauses.load(Ordering::Relaxed)
    }

    /// What `/readyz` prints.
    pub fn health(&self) -> Health {
        if !self.enabled() {
            return Health::Off;
        }
        if self.reachable.load(Ordering::Relaxed) {
            Health::Configured
        } else {
            Health::Unreachable
        }
    }
}

/// Start the coalescing worker for a relay whose push path is on.
///
/// Returns the join handle, or `None` when push is off and there is nothing to run.
/// Called by `serve::run` and by any test that needs the outbound leg; a relay that
/// never starts it still queues, which is what makes the queue's own behaviour
/// testable without a listener.
pub fn spawn(state: &Arc<crate::health::RelayState>) -> Option<tokio::task::JoinHandle<()>> {
    if !state.push.enabled() {
        return None;
    }
    let state = Arc::clone(state);
    Some(tokio::spawn(worker::run(state)))
}
