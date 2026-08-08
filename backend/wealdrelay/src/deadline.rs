// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The two deadlines a connection lives under, as arithmetic rather than as a
//! socket.
//!
//! A connection slot is taken at the WebSocket upgrade (`health::relay_socket`)
//! and given back when the reader loop ends (`ws::serve_connection`). Until this
//! module existed, nothing bounded the time between those two events for a peer
//! that simply said nothing: an unauthenticated attacker could open
//! `WEALD_RELAY_MAX_CONNECTIONS` sockets, send no bytes at all, and hold every
//! slot on a customer's relay for the cost of one file descriptor each. The cap
//! bounded memory and bounded nothing about availability.
//!
//! So there are two deadlines, and they are different deadlines because they
//! answer different questions.
//!
//! - **The handshake deadline** runs from the upgrade to `AUTH_ACK`. A peer that
//!   has not authenticated is a stranger holding a slot, and there is no legitimate
//!   client that needs minutes to send `CONNECT` and answer a challenge: the work
//!   is one signature. It is short for the same reason the invite attempt budget
//!   is small, which is that the honest path does not need the room and the
//!   dishonest one is entirely built out of it.
//! - **The idle deadline** runs on an authenticated connection, and it is
//!   deliberately long. A quiet workspace is the ordinary case and a relay that
//!   dropped a member's socket for being quiet would be a relay that reconnects
//!   everybody all day, which costs a handshake and a replay each time.
//!
//! ## Why the idle deadline is not TCP's job
//!
//! `specs/backend/relay/transport-security.md`: a socket that is open is not a
//! peer that is there. TCP will hold a connection open indefinitely without a
//! keepalive, the keepalive default is measured in hours, and it is a property of
//! the host's network stack rather than of this relay, so a deadline built on it
//! would mean something different on every deployment. Worse, TCP answers the
//! wrong question. The kernel's peer is the kernel on the other side, and it will
//! keep acknowledging segments for a process that has stopped reading, so an
//! idle timer that trusted it could not tell a quiet client from a wedged one.
//!
//! The exchange is therefore application level: when the idle interval elapses
//! the relay sends a WebSocket ping and waits ``LIVENESS_PROBE_WINDOW`` for
//! anything at all to come back. A live client's transport answers a ping without
//! its application being involved, so a quiet member costs one frame every idle
//! interval and stays connected; a client that has stopped reading never
//! produces the pong and is closed. The distinction between slow and gone is the
//! same one the replay drain makes in `ws::queue_all_awaiting`, made here for a
//! connection that is sending nothing rather than for one that is receiving too
//! slowly.
//!
//! ## Time in, decisions out
//!
//! Nothing here reads a clock. `specs/backend/build/testing.md` forbids a
//! wall-clock read inside anything under test, and a deadline whose only test was
//! "sleep and see" would be a slow test that proved a sleep. The caller supplies
//! monotonic milliseconds (in `ws::serve_connection`, elapsed time from a
//! `tokio::time::Instant` taken at the upgrade, which is monotonic and which
//! `tokio::time::pause` can advance without waiting) and this module returns what
//! to do about them. It is deliberately *not* the injected `health::Clock`: that
//! one is wall time, it is what an accepted envelope's receipt is recorded
//! against, and suites pin it to a fixed instant, which would freeze every
//! deadline in the process.

use std::time::Duration;

/// How long the relay waits for an answer to a liveness ping before closing.
///
/// A constant rather than a third variable. The two configured durations are the
/// two policy decisions an operator can reasonably hold an opinion about; this is
/// the width of a round trip, and an operator who tuned it would be tuning their
/// network rather than their relay. Ten seconds is generous by three orders of
/// magnitude against a WebSocket round trip and is the same figure
/// ``ws::REPLAY_DRAIN_TIMEOUT`` uses for the same kind of judgement.
pub const LIVENESS_PROBE_WINDOW: Duration = Duration::from_secs(10);

/// `WEALD_RELAY_HANDSHAKE_TIMEOUT_MS` when the operator sets nothing.
///
/// Ten seconds. `CONNECT`, a challenge, one Ed25519 signature and `AUTH`: a
/// second is plenty on a bad mobile link, and ten is what is left after being
/// generous about a cold TLS session and a client that was swapped out mid
/// handshake. Long enough that no real client has ever needed more, short enough
/// that holding the whole connection table costs an attacker a new TCP
/// connection every ten seconds rather than one connection forever.
pub const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 10_000;

/// `WEALD_RELAY_IDLE_TIMEOUT_MS` when the operator sets nothing.
///
/// Five minutes, and long on purpose. This is not an abuse control: an
/// authenticated peer is in the access set, it is counted against the seat it
/// holds, and the abuse budgets in `specs/backend/relay/wire.md` are what bound
/// what it can do. It is a reaper for connections whose peer has gone without
/// saying so, which is the ordinary end of a laptop lid closing on a mobile
/// network, and the cost of being wrong is a reconnect and a replay. Five
/// minutes means a wedged client is reclaimed inside a support call rather than
/// at the next restart, without reconnecting a quiet office every minute.
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 300_000;

/// Which deadline ended a connection.
///
/// Two variants rather than one, and they are counted separately on the health
/// surface, because an operator seeing connections end needs to tell an attacker
/// parked on the connection table from a fleet of clients whose network is
/// dropping them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    /// Upgraded, never authenticated, out of time.
    Handshake,
    /// Authenticated, said nothing for the idle interval, and did not answer the
    /// liveness ping that followed.
    Idle,
}

impl Expiry {
    /// The stable word for a log line and for the health document.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Handshake => "handshake_deadline",
            Self::Idle => "idle_deadline",
        }
    }
}

/// What the connection loop should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// Nothing is due. Wait this long for an inbound message, then ask again.
    ///
    /// A duration rather than an instant, so the caller passes it straight to
    /// `tokio::time::timeout` and there is one place that subtracts.
    Wait(Duration),
    /// The idle interval elapsed on an authenticated connection. Send the
    /// liveness ping, record it with ``probed``, and wait this long for anything
    /// to come back.
    Probe(Duration),
    /// Out of time. Close, and count it.
    Expired(Expiry),
}

/// One connection's deadlines, and where it currently stands against them.
///
/// Owned by the connection loop and touched from nowhere else, so it is a plain
/// struct with no synchronisation: there is exactly one task per connection that
/// reads its socket.
#[derive(Debug, Clone)]
pub struct Deadlines {
    handshake: Duration,
    idle: Duration,
    probe: Duration,
    /// When the socket was upgraded, in the caller's monotonic milliseconds.
    opened_ms: u64,
    /// The last time anything at all arrived from the peer. A ping, a pong, a
    /// close and a frame all count: the question this deadline asks is whether
    /// the peer is there, and every one of those is evidence that it is.
    last_seen_ms: u64,
    /// When the outstanding liveness ping was sent, if one is outstanding.
    probed_at_ms: Option<u64>,
    /// Whether `AUTH_ACK` has been sent. The handshake deadline applies before
    /// this and the idle deadline after it; there is no window where both apply
    /// and none where neither does.
    authenticated: bool,
}

impl Deadlines {
    /// The deadlines this relay was configured with, starting now.
    pub fn new(config: &crate::config::Config, now_ms: u64) -> Self {
        Self::from_parts(
            Duration::from_millis(config.handshake_timeout_ms),
            Duration::from_millis(config.idle_timeout_ms),
            now_ms,
        )
    }

    /// The same, from two durations, for the tests that are about the arithmetic
    /// rather than about the configuration.
    pub fn from_parts(handshake: Duration, idle: Duration, now_ms: u64) -> Self {
        Self {
            handshake,
            idle,
            // Clamped so a deliberately tiny idle interval cannot produce a probe
            // window longer than the interval it guards, which would mean a
            // connection whose deadline could never be reached.
            probe: LIVENESS_PROBE_WINDOW.min(idle),
            opened_ms: now_ms,
            last_seen_ms: now_ms,
            probed_at_ms: None,
            authenticated: false,
        }
    }

    /// `AUTH_ACK` has been sent. The handshake deadline stops applying and the
    /// idle deadline starts, from now rather than from the upgrade.
    ///
    /// Idempotent, because the caller checks the session state after every
    /// message rather than trying to notice the one message that changed it, and
    /// a second call that restarted the idle interval would let an authenticated
    /// peer hold a connection open by sending frames the session ignores.
    pub fn authenticated(&mut self, now_ms: u64) {
        if self.authenticated {
            return;
        }
        self.authenticated = true;
        self.last_seen_ms = now_ms;
        self.probed_at_ms = None;
    }

    /// Something arrived from the peer.
    ///
    /// Clears any outstanding probe: the ping was asking whether the peer was
    /// there and the answer is that it is, whatever shape the answer took.
    pub fn saw_message(&mut self, now_ms: u64) {
        self.last_seen_ms = now_ms;
        self.probed_at_ms = None;
    }

    /// A liveness ping has been queued. The probe window runs from here.
    pub fn probed(&mut self, now_ms: u64) {
        self.probed_at_ms = Some(now_ms);
    }

    /// Whether a liveness ping is outstanding. For the tests and for a caller
    /// that wants to avoid queueing a second one.
    pub fn probing(&self) -> bool {
        self.probed_at_ms.is_some()
    }

    /// What to do, given the time now.
    ///
    /// Total: every branch returns, and the three arms are the three states a
    /// connection can be in. `saturating_sub` throughout, so a caller that hands
    /// back a `now_ms` behind a recorded one (which monotonic time forbids, but
    /// which an arithmetic slip could produce) gets a deadline that is due rather
    /// than one that wrapped into the far future.
    pub fn next(&self, now_ms: u64) -> Next {
        if !self.authenticated {
            return match remaining(self.opened_ms, self.handshake, now_ms) {
                None => Next::Expired(Expiry::Handshake),
                Some(left) => Next::Wait(left),
            };
        }
        if let Some(probed_at) = self.probed_at_ms {
            return match remaining(probed_at, self.probe, now_ms) {
                None => Next::Expired(Expiry::Idle),
                Some(left) => Next::Wait(left),
            };
        }
        match remaining(self.last_seen_ms, self.idle, now_ms) {
            // The interval elapsed and nothing has been asked yet, so the peer is
            // asked before it is judged. This is the whole difference between a
            // quiet client and a gone one.
            None => Next::Probe(self.probe),
            Some(left) => Next::Wait(left),
        }
    }
}

/// How long is left of `window` that started at `since`, or `None` if it has
/// elapsed.
fn remaining(since_ms: u64, window: Duration, now_ms: u64) -> Option<Duration> {
    let elapsed = Duration::from_millis(now_ms.saturating_sub(since_ms));
    let left = window.saturating_sub(elapsed);
    // Zero is elapsed rather than "wait for no time", because returning
    // `Wait(0)` would spin the connection loop.
    (!left.is_zero()).then_some(left)
}
