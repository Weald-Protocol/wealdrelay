// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The per-device inbound budget on `SEND`.
//!
//! `media::RateLimiter` bounds what one device may pull down the blob path and
//! `push::store::RateLimiter` bounds how often one principal may register a wake
//! handle, but until this module existed the envelope path had no budget at all:
//! `Work::Accept` ran a decode, an authorization read and a Postgres transaction
//! for every `SEND` a connection cared to write. An admitted device, including
//! one whose credential a member leaked, could therefore drive the database at
//! line rate with 1 MiB frames, and every other workspace on the instance would
//! feel it. `specs/backend/relay/wire.md` has carried the number for this budget
//! since the first draft of its Limits table; a limit the spec claims and the
//! code does not enforce is worse than no limit, because it is protection
//! somebody is relying on.
//!
//! Not to be confused with `crate::log_budget`, which bounds how much envelope
//! log one *workspace* may keep. That is a question about storage over the life
//! of a workspace; this is a question about how fast one *device* may spend this
//! process's write capacity in the next minute. Different subject, different
//! window, different answer on the wire.
//!
//! ## The shape is `media::RateLimiter`'s, deliberately
//!
//! Process-local, in memory, keyed by device, counted in fixed windows. That is
//! the shape the blob budget already uses and the shape `push::store` reached for
//! when it needed the same thing, and there is no reason for a third idea. The
//! reasoning transfers whole: the ceiling exists so one device cannot spend this
//! process's write capacity, which is a property of this process's load rather
//! than a fact worth a table and a collector of its own, and a fixed window is
//! what a single process-local counter can enforce without a shared clock
//! service.
//!
//! Keyed by device key rather than by connection, for the reason `push::store`
//! gives: a per-connection budget is a budget a flooding client clears by
//! reconnecting, which is the hole rather than the fix.
//!
//! ## One method, unlike the blob budget
//!
//! `media::RateLimiter` charges its two limits at two moments and so has two
//! methods: the request count is charged before the object is looked up and the
//! byte budget after, because until the object has been found there is no size to
//! charge. `SEND` has no such gap. The frame is in hand, so its length is known
//! before any work at all begins, and both limits can be decided together.
//!
//! Deciding them together is what makes the charge atomic: both are checked
//! before either is committed, so a frame refused on bytes has not silently spent
//! a frame of the count. A partial charge would let an attacker exhaust the frame
//! budget with frames that were never admitted.
//!
//! ## Charged before the transaction, or it protects nothing
//!
//! `ws::serve_work`'s `Work::Accept` arm charges this budget as its first act,
//! ahead of the envelope decode, ahead of the group authorization read and
//! therefore ahead of the transaction `accept::accept` opens. A budget charged
//! after the database has already done the work is a budget that measures the
//! damage rather than preventing it.
//!
//! Charging ahead of the decode also means a malformed envelope is charged, which
//! is correct: the relay spent the bytes and the parse either way, and a budget a
//! client could avoid by sending rubbish would be a budget that rewards rubbish.
//!
//! ## Refused, not disconnected
//!
//! The answer is an error frame on a socket that stays up, in the `quota` class,
//! carrying the interval to wait. A well-behaved client that is merely fast is
//! the ordinary case here, not the adversarial one: `RelayConnection.drain` on
//! macOS writes its whole outbox in one pass with no pacing, so any backlog flush
//! is a burst by construction. Closing the socket would turn that into a
//! reconnect storm and would take down the client's reads (`SUB`, `RECON`,
//! `PUSH`) over a limit that is only about its writes. `quota` is the class whose
//! published client behaviour is exactly right: wait the named interval, then
//! come back.

use crate::frame::{ErrorCode, FrameError};

/// The window both limits are counted over. One minute, which is the interval
/// `specs/backend/relay/wire.md`'s Limits table already states its envelope
/// allowance in.
pub const SEND_WINDOW_MS: u64 = 60_000;

/// Frames per device per window.
///
/// Ten times the `600` the Limits table carried before this module enforced
/// anything, and the difference is a measurement rather than a loosening. `600`
/// was written against a steady interactive stream: a person typing, an agent
/// committing. The traffic that actually arrives on this path at the start of a
/// session is a backlog flush, and `Sources/Sync/RelayConnection.swift` performs
/// it without pacing of any kind. `drain()` walks the outbox and hands every
/// unacknowledged envelope to the socket in a single pass, awaiting the write and
/// not the acknowledgement, and `offerUnnumbered` fills that outbox, once per
/// group per session, with every local record the relay has never numbered. So
/// the burst a real cold start presents is the size of the local unnumbered set,
/// delivered as fast as the socket will take it, and a budget sized for the
/// steady state would meet it in the first second.
///
/// At a hundred frames a second this admits, inside one window, every ordinary
/// cold start named in `specs/backend/relay/search.md`: a joining device offers
/// nothing at all, because it has no unnumbered records yet, and a device
/// returning from an extended offline period offers only what its own member
/// authored while away. The one case that does exceed a window is a full history
/// migration of the 40,000-envelope workspace `search.md` sizes its largest
/// fixture at. That case is paced rather than failed: seven windows of backoff
/// against the twenty-minute backfill gate `search.md` already publishes, with
/// the socket up and reads flowing throughout.
pub const DEFAULT_SEND_FRAMES_PER_MINUTE: u64 = 6_000;

/// Bytes per device per window.
///
/// The 64 MiB figure `wire.md` already states for workspace ingress, applied per
/// device, because the attack this budget exists to stop is one device rather
/// than one workspace. Against the 1 MiB `ct` ceiling it admits sixty-four
/// maximum-size frames in a window and refuses a device writing 1 MiB frames at
/// line rate, which is the whole objection.
///
/// It is deliberately far above the frame budget at realistic record sizes. A
/// `.weald` record is a few kilobytes, so six thousand of them is single-digit
/// mebibytes and the frame count is what a legitimate client meets first. That
/// ordering matters: the frame budget is the one whose refusal a normal client
/// can reach, and it is the one whose interval is short.
pub const DEFAULT_SEND_BYTES_PER_MINUTE: u64 = 64 * 1024 * 1024;

/// How many devices' counters are held before stale ones are swept.
///
/// A bound on the budget's own memory, in the spirit of `calls`'
/// `MAX_TRACKED_STREAMS`. It is belt and braces rather than the primary defence:
/// only a device the access set admits can reach `SEND` at all, so the map is
/// already bounded by the roster, and the sweep exists so that a workspace which
/// rotates device keys for a year does not accumulate a year of them in memory.
///
/// The sweep drops only entries whose window has already turned over, so a real
/// roster larger than this bound is not evicted mid-window and does not lose its
/// counters. That is the honest trade: this bounds churn, not membership.
pub const MAX_TRACKED_DEVICES: usize = 4_096;

/// Why a `SEND` was refused by the budget.
///
/// A `Result` error rather than a verdict enum with an `Allowed` arm, for the
/// reason `calls::MediaRefusal` gives: with `Allowed` in the set every function
/// mapping a verdict to a code needs an arm for the case that has no code, and
/// that arm is unreachable from the only caller that checks first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendRefusal {
    /// Over the frame allowance for this window.
    FrameRate,
    /// Over the byte allowance for this window.
    ByteRate,
}

impl SendRefusal {
    /// The code the client is answered with.
    ///
    /// `quota/rate_limited` for both, which is the code this taxonomy already has
    /// for "a per-principal limit, with an interval, retry after it" and the one
    /// `ws::close_on_deadline` reaches for on the same grounds. Not
    /// `group_ingress_limited`: that code belongs to the admission-blind
    /// per-group abuse budget `wire.md` describes, which is a different limit
    /// about a different subject, and spending it here would leave that one
    /// without a code of its own.
    ///
    /// One code for two causes on purpose, exactly as `calls` uses one for three.
    /// A client's correct response to both is identical, two codes would be two
    /// things for a client to branch on that it must treat the same, and the
    /// interval already says how long to wait.
    pub fn code(self) -> ErrorCode {
        match self {
            Self::FrameRate | Self::ByteRate => ErrorCode::RateLimited,
        }
    }

    /// Seconds before the refused frame could succeed.
    ///
    /// The width of the window for both, because both are counted over the same
    /// window. A fixed window means the true wait is somewhere between zero and a
    /// full window and the relay does not tell the client which, deliberately:
    /// naming the exact millisecond the bucket turns over would synchronise every
    /// refused client onto the same instant, which is a thundering herd the
    /// budget itself built.
    pub fn retry_after(self) -> u32 {
        (SEND_WINDOW_MS / 1_000).max(1) as u32
    }

    /// The limit the answer names, so a client can surface the lever it hit
    /// rather than the one it did not. Never content-derived.
    ///
    /// The limit rather than the interval, which is where `frame.rs` says a limit
    /// goes and where `session.rs` already puts the groups-per-connection
    /// ceiling; the interval travels in `retry_after`, which is the field
    /// `operations.md` defines for it and the field `RelayBackoff.honouring`
    /// reads on the client. Putting an interval in `detail` as well would be two
    /// spellings of one fact and a second thing to keep in step.
    pub fn detail(self, budget: &SendBudget) -> u64 {
        match self {
            Self::FrameRate => budget.frames_per_window,
            Self::ByteRate => budget.bytes_per_window,
        }
    }

    /// The whole refusal, as it goes on the wire.
    pub fn to_frame_error(self, budget: &SendBudget) -> FrameError {
        FrameError::new(self.code())
            .retry_after(self.retry_after())
            .detail(self.detail(budget).to_be_bytes())
    }
}

/// One device's counters for the window they were last touched in.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct DeviceUsage {
    window: u64,
    frames: u64,
    bytes: u64,
}

/// The per-device inbound budget on `SEND`.
#[derive(Debug)]
pub struct SendBudget {
    /// A `tokio::sync::Mutex` for the reason `media::RateLimiter` gives for using
    /// one: a `std::sync::Mutex` poisons on a panic, and the recovery arm that
    /// would then be needed is an arm nothing can reach, because nothing inside
    /// this critical section can panic.
    devices: tokio::sync::Mutex<std::collections::HashMap<Vec<u8>, DeviceUsage>>,
    pub frames_per_window: u64,
    pub bytes_per_window: u64,
}

impl Default for SendBudget {
    fn default() -> Self {
        Self::new(
            DEFAULT_SEND_FRAMES_PER_MINUTE,
            DEFAULT_SEND_BYTES_PER_MINUTE,
        )
    }
}

impl SendBudget {
    pub fn new(frames_per_window: u64, bytes_per_window: u64) -> Self {
        Self {
            devices: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            frames_per_window,
            bytes_per_window,
        }
    }

    /// Charge one `SEND` of `bytes` against `device`, or say why it may not be.
    ///
    /// Both limits are checked before either is committed, so a refusal charges
    /// nothing at all. The frame limit is checked first, so a device that is over
    /// both is told about the one it will meet again first.
    ///
    /// ## A backwards clock begins a new window
    ///
    /// `health::Clock::System` reads `SystemTime`, which is a wall clock and steps
    /// backwards whenever NTP corrects one. Dividing into fixed buckets handles
    /// that on its own: a corrected clock lands in a different bucket, the
    /// counters reset, and the window simply starts again. That costs an attacker
    /// nothing they did not already have, because no client can move the relay's
    /// clock, and it costs a legitimate device nothing at all. The alternative,
    /// asking whether enough time has passed, answers "no" across such a step and
    /// would freeze a device's counters at whatever they held, refusing every
    /// write until the clock climbed back: a routine one-second correction turning
    /// into up to a minute of a workspace being unable to send.
    pub async fn charge(&self, device: &[u8], bytes: u64, now_ms: u64) -> Result<(), SendRefusal> {
        let window = now_ms / SEND_WINDOW_MS;
        let mut devices = self.devices.lock().await;
        sweep(&mut devices, window);
        let usage = devices.entry(device.to_vec()).or_default();
        if usage.window != window {
            *usage = DeviceUsage {
                window,
                frames: 0,
                bytes: 0,
            };
        }
        // Both decided before either is committed. `saturating_add` rather than a
        // checked add because the honest answer at the ceiling of a `u64` is "over
        // the limit", and a limit is always far below it.
        let frames = usage.frames.saturating_add(1);
        let spent = usage.bytes.saturating_add(bytes);
        if frames > self.frames_per_window {
            return Err(SendRefusal::FrameRate);
        }
        if spent > self.bytes_per_window {
            return Err(SendRefusal::ByteRate);
        }
        usage.frames = frames;
        usage.bytes = spent;
        Ok(())
    }

    /// What `device` has spent in the window containing `now_ms`, for tests and
    /// for nothing else. Never a wire surface: it is a fact about one device.
    #[doc(hidden)]
    pub async fn spent(&self, device: &[u8], now_ms: u64) -> (u64, u64) {
        let window = now_ms / SEND_WINDOW_MS;
        let devices = self.devices.lock().await;
        match devices.get(device) {
            Some(usage) if usage.window == window => (usage.frames, usage.bytes),
            _ => (0, 0),
        }
    }

    /// How many devices are currently tracked. Capacity, never identity.
    #[doc(hidden)]
    pub async fn tracked(&self) -> usize {
        self.devices.lock().await.len()
    }
}

/// Drop counters belonging to a window that has already turned over, once the map
/// is larger than the bound.
///
/// Only past windows, so a roster larger than `MAX_TRACKED_DEVICES` keeps every
/// live counter and the budget stays correct; the sweep bounds churn rather than
/// membership. Only above the bound, so the ordinary path is a hash lookup and
/// not a walk.
fn sweep(devices: &mut std::collections::HashMap<Vec<u8>, DeviceUsage>, window: u64) {
    if devices.len() <= MAX_TRACKED_DEVICES {
        return;
    }
    devices.retain(|_, usage| usage.window == window);
}

/// The relay's default posture, from configuration.
pub fn budget_from(config: &crate::config::Config) -> SendBudget {
    SendBudget::new(config.send_frames_per_minute, config.send_bytes_per_minute)
}
