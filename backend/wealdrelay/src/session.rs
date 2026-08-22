// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The session state machine, and every rule about what may be sent when.
//!
//! Deliberately separated from the socket. This module decides, and
//! `src/ws.rs` moves bytes: the whole of `CONNECT`, `AUTH`, subscribe and the
//! error classes is reachable from a unit test without a network, and the socket
//! layer is then thin enough that its own tests are about framing rather than
//! about protocol rules.
//!
//! ## The order is enforced, not assumed
//!
//! `specs/backend/relay/wire.md` names the frames but a state machine is what
//! makes the order real. A relay that answered `SEND` before `AUTH` would be a
//! relay any unauthenticated peer could write through, and reading the frame
//! handler top to bottom is not a proof that it cannot happen. So a frame arriving
//! in the wrong state is refused by ``Session::handle`` before it reaches anything
//! that touches state, and the test for it walks every frame against every state.
//!
//! ## Clock skew
//!
//! `CONNECT` carries the client's clock and `CONNECT_ACK` carries the relay's, so
//! skew is detected at the start of a session rather than discovered on the first
//! write. The relay evaluates every expiry it owns against its own observed time
//! (`specs/backend/relay/operations.md`), so a skewed client is told and not
//! trusted: the answer is a warning to the client, never an adjustment to the
//! relay's clock.

use crate::config::{CallMode, Config, LiveMode, WriteMode};
use crate::frame::{
    ErrorCode, Frame, FrameError, KeysBody, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION,
};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    OnceLock,
};

/// The next connection identity in this relay process.
///
/// It is deliberately separate from time: many connections can legitimately
/// arrive in one millisecond, and a replay-resistant challenge must distinguish
/// them anyway. `Relaxed` is sufficient because uniqueness, not an ordering
/// relationship with any other state, is the invariant.
static NEXT_CONNECTION_NONCE: AtomicU64 = AtomicU64::new(0);

/// A process-local secret makes the otherwise observable connection counter
/// unusable for predicting a challenge. Failure to obtain operating-system
/// entropy is fatal: continuing with a predictable authentication challenge
/// would silently remove the protection this value provides.
static CHALLENGE_SECRET: OnceLock<[u8; 32]> = OnceLock::new();

/// How far apart the two clocks may be before the relay says so.
///
/// Five minutes. Chosen against what the number is for rather than as a round
/// figure: the client uses it to decide whether its own invite-expiry arithmetic
/// can be trusted, and invites live for 24 hours, so five minutes is far inside
/// the tolerance of every decision that depends on it while still catching the
/// misconfigured container whose clock is an hour out.
pub const CLOCK_SKEW_LIMIT_MS: u64 = 5 * 60 * 1000;

/// The bound on a connection's unacknowledged send queue.
///
/// `operations.md`: per-connection queues are bounded, and a full receive queue
/// stops reading the socket so backpressure travels through TCP rather than the
/// relay accepting and discarding. A subscriber that cannot keep up is downgraded
/// to reconciliation and told so, because a dropped envelope is a hole in an
/// author chain and therefore a security alarm on somebody else's screen.
pub const SEND_QUEUE_BOUND: usize = 256;

/// How many groups one connection may subscribe to.
pub const MAX_GROUPS_PER_CONNECTION: usize = 256;

/// The largest sealed ``LiveBody`` the relay will carry.
///
/// Four KiB. A beat is a signed struct rather than a payload
/// (`specs/backend/relay/presence.md`), so a larger one is a client using the
/// ephemeral path for something durable.
pub const MAX_LIVE_BYTES: usize = 4096;

/// `LIVE` frames one connection may send per minute.
///
/// Budgeted separately from the 600-envelope allowance, so presence can never
/// starve a durable write, and refused on the frame only: the connection stays up
/// and the next beat is 20 seconds away.
///
/// 900 rather than 60 because live cursors ride this path
/// (`specs/multiplayer-cursors.md`): a moving pointer publishes 10 coalesced
/// samples a second, which a 60 per minute budget refuses outright. The property
/// that mattered is unchanged, because it was never the number: the allowance is
/// still separate from the envelope allowance, so an ephemeral stream can only
/// spend its own and can never starve a durable write.
pub const LIVE_FRAMES_PER_MINUTE: u32 = 900;

/// `KEYS` frames one connection may send per minute. A roster prefetch is a
/// startup burst rather than a stream.
pub const KEYS_FRAMES_PER_MINUTE: u32 = 30;

/// `JOIN` frames one connection may send per minute.
///
/// The only pre-authentication frame, so the only budget that bounds a peer which
/// has proved nothing. Every redemption costs at least a cooldown query and a salt
/// read before `code::verify` is reached (`invite/reserve.rs`), so an unbudgeted
/// `JOIN` is unauthenticated database amplification inside the handshake deadline.
/// Well above a real client, which sends one and waits for the reservation, and far
/// below a pipelined flood.
pub const JOIN_FRAMES_PER_MINUTE: u32 = 20;

/// `HANDSHAKE` frames one connection may send per minute.
///
/// The most expensive durable write in the protocol per frame: each one takes
/// `relay_group ... for update`, inserts a row up to the 512 KiB handshake ceiling
/// into a log nothing compacts, and fans the whole message out to every subscriber.
/// So an unbudgeted `HANDSHAKE` is one admitted device serialising every real
/// committer in the group behind a row lock while growing a log the relay has no
/// operation to shrink. Set well above a real client, which publishes one message
/// per commit it makes and bursts only when a bulk membership change commits once
/// per group, and far below a peer pipelining maximum-size frames at line rate.
pub const HANDSHAKE_FRAMES_PER_MINUTE: u32 = 120;

/// `ACCESS` frames one connection may send per minute.
///
/// Judging a publication hashes every authorizer and recovery principal and reads
/// the prior set before the signature is even looked at, so an unbudgeted `ACCESS`
/// is a shape check a peer can repeat at socket speed. Set far above real use, one
/// frame per membership change, and far below a pipelining peer.
pub const ACCESS_FRAMES_PER_MINUTE: u32 = 30;

/// `WRAP` frames one connection may send per minute.
///
/// A wrap is a durable write: one row per recovery key, inserted before the
/// signature work behind it is ever questioned, so an unbudgeted `WRAP` is one
/// admitted device growing a table nothing compacts at line rate. Same shape as
/// `ACCESS`: far above real use, one frame per rotation, far below a pipelining
/// peer.
pub const WRAP_FRAMES_PER_MINUTE: u32 = 30;

/// `INVITE` frames one connection may send per minute.
///
/// Invite administration inserts and revokes rows and reads the invite record
/// first, so an unbudgeted `INVITE` is free database work for any admitted
/// device. Same allowance as its sibling durable-write frames.
pub const INVITE_FRAMES_PER_MINUTE: u32 = 30;

/// `SUB` frames one connection may send per minute.
///
/// Above `MAX_GROUPS_PER_CONNECTION`, deliberately and with room to spare: a cold
/// start subscribes every group it holds, so a ceiling at or below 256 would turn
/// the largest legitimate workspace's first minute into a rate limit. What it
/// refuses is the other shape, a loop re-subscribing one group, where every frame
/// costs an `authorize_group` query plus a replay of the group's log from
/// `from_seq`.
pub const SUB_FRAMES_PER_MINUTE: u32 = 300;

/// `RECON` frames one connection may send per minute.
///
/// The most expensive frame in the protocol per byte: each round runs
/// `log::items`, `log::envelopes_for` and `reopen_omitted` over up to the whole
/// window. It still cannot be as tight as `LIVE`, because reconciliation is
/// iterative by design and a client catching a large group up drives many rounds,
/// each cut to what the outbound queue will take (`sync.rs`). Ten a second is far
/// above a request-and-response client that holds one round outstanding per group
/// and far below a peer beating on a timer.
pub const RECON_FRAMES_PER_MINUTE: u32 = 600;

/// The window every per-connection frame budget is counted over.
pub const FRAME_BUDGET_WINDOW_MS: u64 = 60_000;

/// The most key packages a `KEYS::Fetch` may ask for at once. Higher is
/// enumeration (`specs/backend/relay/private-messaging.md`).
pub const MAX_KEY_PACKAGE_FETCH: u8 = 8;

/// A fixed-window frame budget for one connection.
///
/// Deliberately not a token bucket. What is being bounded is a client that beats
/// on a timer, so a window that resets is both sufficient and exactly what the
/// limits table states; a bucket would need a refill rate nothing in the spec
/// names.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct FrameBudget {
    window_started_ms: u64,
    spent: u32,
}

impl FrameBudget {
    /// Charge one frame. `false` means the budget is exhausted for this window.
    ///
    /// A window that started in the future is a new window. `health::Clock::System`
    /// is a wall clock, so an ordinary NTP correction moves `now_ms` backwards, and
    /// a comparison that only asked whether enough time had passed would answer
    /// "no" for as long as the step lasted plus the whole window after it. That
    /// would turn a one second clock correction into a minute of refusals on a
    /// connection doing nothing wrong, which is a fixed window failing open in the
    /// one direction it must not.
    fn charge(&mut self, now_ms: u64, allowance: u32) -> bool {
        if now_ms < self.window_started_ms
            || now_ms.saturating_sub(self.window_started_ms) >= FRAME_BUDGET_WINDOW_MS
        {
            self.window_started_ms = now_ms;
            self.spent = 0;
        }
        if self.spent >= allowance {
            return false;
        }
        self.spent += 1;
        true
    }
}

/// Where a session is. A `CONNECT` before anything, then a challenge, then a
/// signature, then it may work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Nothing received yet.
    Fresh,
    /// `CONNECT` accepted, challenge issued, waiting for `AUTH`.
    Challenged,
    /// Authenticated. The only state in which content frames are served.
    Ready,
    /// Authenticated into a workspace that has no access set yet.
    ///
    /// The bootstrap hole, made narrow rather than left open. A workspace's genesis
    /// set is signed by its trust root and published over a socket, so the first
    /// connection a workspace ever takes has no set to be checked against. Refusing
    /// it would make a workspace unreachable forever; admitting it to everything
    /// would make the access set optional, which is the hole step 6 exists to close.
    /// So the session is admitted to exactly one frame, `ACCESS`, until a set exists.
    /// `SEND`, `SUB` and `RECON` are refused with the same code a stranger gets.
    Bootstrapping,
    /// Closed, by `BYE` or by an error that ends the connection.
    Closed,
}

/// What the session decided to do about one frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reaction {
    /// Send these frames back, in order.
    Reply(Vec<Frame>),
    /// Send these, then close. A `version` failure aborts the connection rather
    /// than continuing (`operations.md`), and a `BYE` is a clean close.
    ReplyAndClose(Vec<Frame>),
    /// The frame needs work this module does not do: a database write, a
    /// subscription, a reconciliation. The socket layer performs it and feeds the
    /// answer back. Keeping I/O out of the state machine is what makes every rule
    /// above testable without one.
    Defer(Work),
}

/// Work the socket layer performs on the session's behalf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Work {
    /// Verify this device key and admit it, or close the socket.
    ///
    /// Three things, in this order, and the order is the security property: the
    /// signature is checked against the challenge **this connection** issued, then
    /// the key is tested against the workspace's access set, then its key packages
    /// are counted. Carrying the challenge in the work item rather than re-reading
    /// it later is what stops a signature captured from one session being replayed
    /// into another.
    Authenticate {
        device_key: Vec<u8>,
        signature: Vec<u8>,
        challenge: Vec<u8>,
    },
    /// Accept one envelope.
    Accept { envelope: Vec<u8> },
    /// Subscribe and backfill from this cursor.
    Subscribe { group: Vec<u8>, from_seq: u64 },
    /// A negentropy round trip, which arrives in step 5.
    Reconcile { group: Vec<u8>, payload: Vec<u8> },
    /// An access-set rotation, accepted transactionally in step 6.
    RotateAccessSet { body: Vec<u8> },
    /// A blob ticket, which arrives in step 9.
    BlobTicket { payload: Vec<u8> },
    /// One signed `drop_before` compaction instruction (step 10).
    DropBefore { payload: Vec<u8> },
    /// One recovery wrap, stored under its blinded tag (step 8).
    PublishWrap { body: Vec<u8> },
    /// One step of an invite redemption (step 8).
    Redeem { body: Vec<u8> },
    /// One invite administration request: issue, list, revoke, or the authority
    /// question. `Ready` only, unlike ``Work::Redeem``: this is the privileged half
    /// of the invite surface and its whole gate is that the session authenticated.
    AdministerInvite { body: Vec<u8> },
    /// One MLS handshake message, stored in order and fanned out (step 8).
    PublishHandshake { group: Vec<u8>, message: Vec<u8> },
    /// One ephemeral beat, fanned out to a group's version 2 subscribers and then
    /// forgotten (step 30). Nothing is stored, so there is no answer to the
    /// publisher and no sequence number to assign.
    PublishLive {
        group: Vec<u8>,
        epoch: u64,
        ct: Vec<u8>,
    },
    /// One key-package publication or fetch (step 33).
    KeyPackages { body: KeysBody },
    /// One push-wake registration, clear or query (step 37).
    ///
    /// Deferred exactly like ``Work::KeyPackages``: the state machine decides that the
    /// session may ask, and everything that needs the database or the configuration
    /// is decided by `ws::wake_registration`.
    WakeRegistration { body: crate::frame::WakeBody },
    /// One call signalling frame: access-set checked, applied to the call
    /// registry, then fanned out to the group's version 3 subscribers and
    /// forgotten (step 35). Nothing is stored and the publisher is not answered.
    PublishCall {
        /// Narrowed to its fixed width here rather than at the socket. The codec
        /// already fixes it at sixteen bytes, so the conversion cannot fail on a
        /// decoded frame; doing it in this layer means the one place it *can*
        /// fail (a hand-built `Frame`, which is possible because `Frame` is
        /// public) is the one place that answers it, and the socket layer carries
        /// no arm that nothing can reach.
        call_id: [u8; crate::calls::CALL_ID_BYTES],
        group: Vec<u8>,
        epoch: u64,
        kind: crate::calls::CallKind,
        body: Vec<u8>,
    },
    /// One media frame, routed at the participants of a call this connection was
    /// already admitted to (step 36).
    ///
    /// No group on the work item, because there is none on the frame and there is
    /// deliberately none to look up: the group was checked when the `CALL` that
    /// opened this call id was accepted, and repeating the check here would put a
    /// database read on a path carrying fifty frames a second.
    PublishMedia {
        call_id: [u8; crate::calls::CALL_ID_BYTES],
        stream: [u8; crate::calls::STREAM_BYTES],
        seq: u64,
        ct: Vec<u8>,
    },
}

/// One connection's protocol state.
#[derive(Debug)]
pub struct Session {
    state: State,
    /// Unique for this relay process. Included in every challenge derivation so
    /// a signature from one socket cannot authenticate another socket opened in
    /// the same clock tick for the same requested groups.
    connection_nonce: u64,
    /// The challenge this session issued, empty when there is none. Held so `AUTH`
    /// is verified against the bytes this connection sent and not against anything a
    /// peer supplies, which is what stops a signature captured from one session being
    /// replayed into another.
    ///
    /// Empty rather than `Option`, because `State::Challenged` already carries the
    /// fact that one was issued. An `Option` here needed an absent arm in the `AUTH`
    /// path that no sequence of frames could reach, and an unreachable arm in the
    /// authentication path is worse than a spare allocation: it cannot be tested, so
    /// nobody knows what it does.
    challenge: Vec<u8>,
    /// Groups the client asked for in `CONNECT`. Advisory: `wire.md` says the
    /// relay serves any group in the workspace to any device in the access set,
    /// because proving group membership to the relay would leak the membership
    /// graph.
    requested: Vec<Vec<u8>>,
    /// The relay-owned workspace that admitted this connection.  A CONNECT may
    /// mention several groups, but authentication is for exactly one workspace;
    /// later operations must be constrained to it rather than treating the
    /// requested list as a blanket capability.
    authorized_workspace: Option<String>,
    subscribed: Vec<Vec<u8>>,
    /// Milliseconds the client's clock is ahead of the relay's, if they differ
    /// enough to matter.
    skew_ms: Option<i64>,
    min_enc: u8,
    /// The peer's address, when the transport supplied one. See ``set_source``.
    source: Option<String>,
    /// The device key this session authenticated with, kept for the one query that
    /// needs to re-establish which workspace a founding device belongs to. Never
    /// used as a membership fact: membership is re-read from the tables every time.
    device_key: Option<Vec<u8>>,
    write_mode: WriteMode,
    /// What this relay reports as its running build, and the two settings a
    /// customer needs to judge it by (`specs/backend/relay/verification.md`).
    /// Read from the configuration once, so a session states what the process
    /// was actually started with rather than what the environment says now.
    build_digest: Vec<u8>,
    access_set_enforced: bool,
    refuses_plaintext: bool,
    /// The version this session settled on: `min(offered, PROTOCOL_VERSION)`.
    ///
    /// Held because fanout filters on it. A version 1 subscriber is never sent a
    /// `LIVE`, and the only place that fact can be known is the connection that
    /// negotiated it.
    negotiated_version: u16,
    /// Whether the ephemeral path is on at all, from `WEALD_RELAY_LIVE`.
    live: LiveMode,
    live_budget: FrameBudget,
    keys_budget: FrameBudget,
    /// `HANDSHAKE` frames per minute, budgeted separately from `SEND`'s device
    /// allowance because the two share no counter: `send_budget::charge` runs in
    /// the `Work::Accept` arm only, so nothing bounded this path at all.
    handshake_budget: FrameBudget,
    /// `ACCESS` frames per minute. Nothing bounded this path at all before it
    /// existed: the arm deferred the rotation with no charge.
    access_budget: FrameBudget,
    /// `WRAP` frames per minute, the same story as `access_budget`: a durable
    /// write per frame that no counter bounded.
    wrap_budget: FrameBudget,
    /// `INVITE` frames per minute, for the same reason: inserts and revokes
    /// behind an unbudgeted frame are free work for an admitted device.
    invite_budget: FrameBudget,
    /// `SUB` and `RECON` frames per minute, each budgeted separately from the
    /// others and from each other. They are the two largest amplifiers on the
    /// socket, a small frame against a query plus a replay, so an unbudgeted one
    /// lets one admitted device starve every other member of the workspace.
    sub_budget: FrameBudget,
    recon_budget: FrameBudget,
    /// `JOIN` frames per minute. The only budget charged before authentication,
    /// and the only one an unauthenticated peer can spend.
    join_budget: FrameBudget,
    /// Whether the call path is on at all, from `WEALD_RELAY_CALLS`.
    calls: CallMode,
    /// `CALL` signalling frames per minute, budgeted separately from `LIVE`,
    /// `KEYS` and the envelope allowance for the same reason those are separate
    /// from each other: no one path may starve another.
    call_budget: FrameBudget,
    /// The media budget: frames per stream per second and bytes per minute.
    /// `crate::calls::MediaBudget` rather than a `FrameBudget`, because a media
    /// limit is two limits over two windows and one of them is per stream.
    media_budget: crate::calls::MediaBudget,
}

impl Session {
    pub fn new(config: &Config) -> Self {
        Self {
            state: State::Fresh,
            connection_nonce: NEXT_CONNECTION_NONCE.fetch_add(1, Ordering::Relaxed),
            challenge: Vec::new(),
            requested: Vec::new(),
            authorized_workspace: None,
            subscribed: Vec::new(),
            skew_ms: None,
            min_enc: crate::accept::floor_byte(config.min_encryption),
            write_mode: config.write_mode,
            source: None,
            device_key: None,
            build_digest: crate::RunningDigest::resolve().line().into_bytes(),
            access_set_enforced: matches!(config.access_set, crate::config::AccessSetMode::Enforce),
            refuses_plaintext: matches!(config.min_encryption, crate::config::MinEncryption::Mls),
            // Until `CONNECT` is answered there is no selection. The floor rather
            // than the ceiling, so a session that somehow reached fanout without a
            // handshake would be treated as the oldest client rather than the
            // newest.
            negotiated_version: MIN_PROTOCOL_VERSION,
            live: config.live,
            live_budget: FrameBudget::default(),
            keys_budget: FrameBudget::default(),
            handshake_budget: FrameBudget::default(),
            access_budget: FrameBudget::default(),
            wrap_budget: FrameBudget::default(),
            invite_budget: FrameBudget::default(),
            sub_budget: FrameBudget::default(),
            recon_budget: FrameBudget::default(),
            join_budget: FrameBudget::default(),
            calls: config.calls,
            call_budget: FrameBudget::default(),
            media_budget: crate::calls::MediaBudget::default(),
        }
    }

    /// Where this connection came from, for the redeem budget and nothing else.
    ///
    /// `None` on a connection whose router carried no connection info, which is
    /// every unit test and any deployment behind a proxy that does not pass one. The
    /// redeem path then falls back to a source the joiner cannot forge either way,
    /// which is its own device key: the budget is per `(token, source, device)`, so
    /// losing the source narrows it rather than opening it.
    pub fn set_source(&mut self, source: Option<String>) {
        self.source = source;
    }

    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Remember which device key authenticated, and answer it.
    ///
    /// Deliberately not a membership claim. The only reader asks the database again
    /// with it, because a session that answered from memory would be a relay serving
    /// a workspace's salt to a device that has since been revoked from it.
    pub fn bind_device(&mut self, device_key: Vec<u8>) {
        self.device_key = Some(device_key);
    }

    pub fn device_key(&self) -> Option<&[u8]> {
        self.device_key.as_deref()
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn skew_ms(&self) -> Option<i64> {
        self.skew_ms
    }

    pub fn subscribed(&self) -> &[Vec<u8>] {
        &self.subscribed
    }

    /// Forget a group this connection never actually subscribed to.
    ///
    /// The `SUB` arm records the group before the work is deferred, because the group
    /// limit is a property of the frames a connection has sent and has to be decided
    /// without a database round trip. Authorization happens afterwards, in
    /// `ws::perform`, and a refused `SUB` creates no subscription: no hub entry, no
    /// acknowledgement, nothing. Left recorded, those refusals still counted against
    /// `MAX_GROUPS_PER_CONNECTION`, so 256 `SUB`s for group ids that do not exist put a
    /// connection holding zero subscriptions permanently at its ceiling, and the next
    /// `SUB` for a real group was answered `quota/rate_limited`. An honest client that
    /// subscribed to a group a moment before its row existed reached the same wall by
    /// accident.
    ///
    /// Called only from the refusal path, so a successful subscription is still counted
    /// exactly once and the limit still holds.
    pub fn forget_subscription(&mut self, group: &[u8]) {
        self.subscribed.retain(|held| held.as_slice() != group);
    }

    pub fn requested(&self) -> &[Vec<u8>] {
        &self.requested
    }

    /// Bind a successfully authenticated (or bootstrapping) connection to the
    /// workspace that the relay resolved during admission.
    pub fn bind_workspace(&mut self, workspace: String) {
        self.authorized_workspace = Some(workspace);
    }

    /// The only workspace this ready session may operate in.
    /// True while the operator has quiesced this instance for writes.
    fn refuses_writes(&self) -> bool {
        matches!(self.write_mode, WriteMode::ReadOnly)
    }

    /// The answer every durable-write frame owes in `read_only`, or `None` when
    /// the instance is taking writes. Answered from the session rather than
    /// deferred, so a quiesced relay does no database round trip per refusal and
    /// the reads the mode exists to keep serving are untouched.
    fn read_only_refusal(&self) -> Option<Reaction> {
        self.refuses_writes().then(|| {
            Reaction::Reply(vec![Frame::Error(FrameError::new(
                ErrorCode::ServiceReadOnly,
            ))])
        })
    }

    pub fn authorized_workspace(&self) -> Option<&str> {
        self.authorized_workspace.as_deref()
    }

    /// The protocol version this session settled on. Read by the fanout filter.
    pub fn negotiated_version(&self) -> u16 {
        self.negotiated_version
    }

    /// Decide about one frame.
    ///
    /// The match is on the state and the frame together: one table, so what may be
    /// sent when is in one place and a new frame cannot be added without deciding
    /// it. Every arm that touches state is an arm the table has already permitted,
    /// which is what makes the ordering rule a property of this function rather
    /// than of the guards inside it.
    ///
    /// `now_ms` is injected because `testing.md` forbids a wall-clock read inside
    /// anything under test, and because the clock-skew rule is only checkable if
    /// the test controls both clocks.
    /// The one answer both call frames give when the operator has turned the path
    /// off, or `None` when it is on.
    ///
    /// A version answer rather than a denial, exactly as `LIVE` gives: the frame
    /// is well formed and the client's correct response is to stop sending it and
    /// report calls unavailable, not to retry against a relay that will never say
    /// yes. Written once because two copies of it would be two things to keep in
    /// step.
    fn calls_unavailable(&self) -> Option<Reaction> {
        matches!(self.calls, CallMode::Off).then(|| {
            Reaction::Reply(vec![Frame::Error(FrameError::new(
                ErrorCode::ProtocolUnsupported,
            ))])
        })
    }

    pub fn handle(&mut self, frame: Frame, now_ms: u64) -> Reaction {
        match (self.state, frame) {
            (
                State::Fresh,
                Frame::Connect {
                    version,
                    groups,
                    sent_at,
                },
            ) => {
                // One field, which is the client's maximum offer, and the
                // selection is the lower of the two ceilings. Refused only when the
                // offer is below this build's floor, which is a client this relay
                // genuinely cannot serve; a client offering more than this build
                // speaks is served at this build's maximum and told so in
                // `CONNECT_ACK`.
                if version < MIN_PROTOCOL_VERSION {
                    // Aborts the connection. `operations.md`: a version failure
                    // never silently continues.
                    self.state = State::Closed;
                    return Reaction::ReplyAndClose(vec![Frame::Error(
                        FrameError::new(ErrorCode::ProtocolUnsupported)
                            .detail(PROTOCOL_VERSION.to_be_bytes()),
                    )]);
                }
                self.negotiated_version = version.min(PROTOCOL_VERSION);
                if groups.len() > MAX_GROUPS_PER_CONNECTION {
                    self.state = State::Closed;
                    return Reaction::ReplyAndClose(vec![Frame::Error(
                        FrameError::new(ErrorCode::RateLimited)
                            .detail((MAX_GROUPS_PER_CONNECTION as u64).to_be_bytes()),
                    )]);
                }
                self.requested = groups;
                self.skew_ms = skew(sent_at, now_ms);
                // The connection nonce makes otherwise identical handshakes
                // distinct; the process secret makes their challenges
                // unpredictable. Both properties are required for AUTH replay
                // resistance, not merely a timestamp that can collide.
                let challenge = challenge_bytes(now_ms, &self.requested, self.connection_nonce);
                self.challenge = challenge.clone();
                self.state = State::Challenged;
                Reaction::Reply(vec![
                    Frame::ConnectAck {
                        version: self.negotiated_version,
                        server_time: now_ms,
                        min_enc: self.min_enc,
                    },
                    Frame::AuthChallenge { challenge },
                ])
            }
            (
                State::Challenged,
                Frame::Auth {
                    device_key,
                    signature,
                },
            ) => {
                // Taken rather than cloned, so a second `AUTH` on this connection has
                // nothing to verify against even if the frame table ever stopped
                // refusing one. `State::Challenged` is reached only by issuing a
                // challenge, so what is taken here is never empty.
                let challenge = std::mem::take(&mut self.challenge);
                Reaction::Defer(Work::Authenticate {
                    device_key,
                    signature,
                    challenge,
                })
            }
            (State::Ready, Frame::Send { envelope }) => {
                if self.refuses_writes() {
                    // Answered here rather than deferred, so a relay in
                    // maintenance does not do a database round trip per refused
                    // write. `SUB`, `RECON` and export keep working, which is the
                    // whole point of the mode.
                    return Reaction::Reply(vec![Frame::Error(FrameError::new(
                        ErrorCode::ServiceReadOnly,
                    ))]);
                }
                Reaction::Defer(Work::Accept { envelope })
            }
            (State::Ready, Frame::Sub { group, from_seq }) => {
                if self.subscribed.len() >= MAX_GROUPS_PER_CONNECTION
                    && !self.subscribed.contains(&group)
                {
                    return Reaction::Reply(vec![Frame::Error(
                        FrameError::new(ErrorCode::RateLimited)
                            .detail((MAX_GROUPS_PER_CONNECTION as u64).to_be_bytes()),
                    )]);
                }
                // Charged before the subscription is recorded, so a refused frame
                // changes no session state and reaches no database: the whole point
                // of budgeting the frame is that the work behind it never starts.
                if !self.sub_budget.charge(now_ms, SUB_FRAMES_PER_MINUTE) {
                    return Reaction::Reply(vec![Frame::Error(
                        FrameError::new(ErrorCode::RateLimited)
                            .retry_after(60)
                            .detail(u64::from(SUB_FRAMES_PER_MINUTE).to_be_bytes()),
                    )]);
                }
                if !self.subscribed.contains(&group) {
                    self.subscribed.push(group.clone());
                }
                Reaction::Defer(Work::Subscribe { group, from_seq })
            }
            (State::Ready, Frame::Recon { group, payload }) => {
                if !self.recon_budget.charge(now_ms, RECON_FRAMES_PER_MINUTE) {
                    return Reaction::Reply(vec![Frame::Error(
                        FrameError::new(ErrorCode::RateLimited)
                            .retry_after(60)
                            .detail(u64::from(RECON_FRAMES_PER_MINUTE).to_be_bytes()),
                    )]);
                }
                Reaction::Defer(Work::Reconcile { group, payload })
            }
            // The one frame a bootstrapping session may send, and the reason that
            // state exists.
            (State::Ready | State::Bootstrapping, Frame::Access { body }) => {
                // An access-set rotation is a durable write, so `read_only` owes it
                // the same refusal `SEND` gets (WEALD-L158). Answered before the
                // budget is charged: a refused frame must cost the caller nothing
                // and reach no database.
                if let Some(refusal) = self.read_only_refusal() {
                    return refusal;
                }
                // Charged before the work is deferred, like every sibling arm: the
                // judgement hashes every principal and reads the prior set, so an
                // unbudgeted `ACCESS` is one admitted device pipelining maximal
                // rosters at line rate against a shared runtime.
                if !self.access_budget.charge(now_ms, ACCESS_FRAMES_PER_MINUTE) {
                    return Reaction::Reply(vec![Frame::Error(
                        FrameError::new(ErrorCode::RateLimited)
                            .retry_after(60)
                            .detail(u64::from(ACCESS_FRAMES_PER_MINUTE).to_be_bytes()),
                    )]);
                }
                Reaction::Defer(Work::RotateAccessSet { body })
            }
            // Ready only, unlike `ACCESS`. A bootstrapping session has no group
            // whose epoch secret could have derived a tag, so a wrap from one is
            // a client that is wrong about the protocol rather than a case to
            // allow for.
            (State::Ready, Frame::Wrap { body }) => {
                // A recovery wrap is a durable write (WEALD-L158).
                if let Some(refusal) = self.read_only_refusal() {
                    return refusal;
                }
                // Charged before the work is deferred, like every sibling arm: a
                // wrap inserts a row per recovery key, so an unbudgeted frame is
                // one admitted device growing that table at line rate
                // (WEALD-L217).
                if !self.wrap_budget.charge(now_ms, WRAP_FRAMES_PER_MINUTE) {
                    return Reaction::Reply(vec![Frame::Error(
                        FrameError::new(ErrorCode::RateLimited)
                            .retry_after(60)
                            .detail(u64::from(WRAP_FRAMES_PER_MINUTE).to_be_bytes()),
                    )]);
                }
                Reaction::Defer(Work::PublishWrap { body })
            }
            // Before authentication, deliberately, and it is the only frame that is.
            // A device redeeming an invite has no membership yet by definition: it is
            // asking for the reservation that will let it authenticate at all
            // (`specs/backend/relay/invites.md`, step 4). Refusing it until after
            // `AUTH` would make the first device of a workspace unable to join the
            // workspace it is founding.
            //
            // What stops that being a hole: the frame carries a token and a
            // one-time code, the relay Argon2-verifies the code, five wrong ones
            // cool the tuple down, and every refusal is the same generic answer. A
            // caller with no token learns nothing it did not already have.
            (
                State::Fresh | State::Challenged | State::Ready | State::Bootstrapping,
                Frame::Join { body },
            ) => {
                // Charged before the work is deferred, so a refused frame reaches no
                // database at all. This is the one budget that bounds a peer which
                // has authenticated nothing, and refusing the frame rather than the
                // connection keeps a person mistyping a code on the socket they are
                // already on.
                if !self.join_budget.charge(now_ms, JOIN_FRAMES_PER_MINUTE) {
                    return Reaction::Reply(vec![Frame::Error(
                        FrameError::new(ErrorCode::RateLimited)
                            .retry_after(60)
                            .detail(u64::from(JOIN_FRAMES_PER_MINUTE).to_be_bytes()),
                    )]);
                }
                Reaction::Defer(Work::Redeem { body })
            }
            // Ready only, like every other group-addressed frame: a handshake
            // message belongs to a group, and a bootstrapping session has no
            // workspace claim to check a group against.
            // `Ready` and nothing else, deliberately narrower than `JOIN` above.
            // A bootstrapping session has no access set to be an authorizer of, so
            // there is no state in which admitting this frame there could answer
            // anything but "no", and a refusal is clearer than a frame accepted into
            // a path that cannot serve it.
            (State::Ready, Frame::Invite { body }) => {
                // Invite administration inserts and revokes rows (WEALD-L158).
                if let Some(refusal) = self.read_only_refusal() {
                    return refusal;
                }
                // Charged before the work is deferred, like every sibling arm: the
                // administration path reads the invite record and writes rows, so
                // an unbudgeted frame is free database work for an admitted device
                // (WEALD-L217).
                if !self.invite_budget.charge(now_ms, INVITE_FRAMES_PER_MINUTE) {
                    return Reaction::Reply(vec![Frame::Error(
                        FrameError::new(ErrorCode::RateLimited)
                            .retry_after(60)
                            .detail(u64::from(INVITE_FRAMES_PER_MINUTE).to_be_bytes()),
                    )]);
                }
                Reaction::Defer(Work::AdministerInvite { body })
            }
            (State::Ready, Frame::Handshake { group, message, .. }) => {
                // A handshake commit appends a row (WEALD-L158), so the mode that
                // quiesces the instance refuses it too.
                if let Some(refusal) = self.read_only_refusal() {
                    return refusal;
                }
                // Charged before the work is deferred, so a refused frame reaches
                // no database: it takes no row lock, appends no row and fans nothing
                // out, which is the whole point of budgeting the frame rather than
                // the write behind it. Refused on the frame only, like every other
                // frame budget: the connection stays up and the client retries after
                // the window.
                if !self
                    .handshake_budget
                    .charge(now_ms, HANDSHAKE_FRAMES_PER_MINUTE)
                {
                    return Reaction::Reply(vec![Frame::Error(
                        FrameError::new(ErrorCode::RateLimited)
                            .retry_after(60)
                            .detail(u64::from(HANDSHAKE_FRAMES_PER_MINUTE).to_be_bytes()),
                    )]);
                }
                Reaction::Defer(Work::PublishHandshake { group, message })
            }
            // Ready only. There is no pre-auth case: `JOIN` remains the one frame
            // a session may send before it has authenticated, and a beat from an
            // unauthenticated peer is a peer claiming presence in a workspace it has
            // not proved it belongs to.
            (State::Ready, Frame::Live { group, epoch, ct }) => {
                if matches!(self.live, LiveMode::Off) {
                    // The operator turned the ephemeral path off. A version answer
                    // rather than a denial: the frame is well formed and the client's
                    // correct response is to stop sending it, not to retry.
                    return Reaction::Reply(vec![Frame::Error(FrameError::new(
                        ErrorCode::ProtocolUnsupported,
                    ))]);
                }
                if ct.len() > MAX_LIVE_BYTES {
                    return Reaction::Reply(vec![Frame::Error(
                        FrameError::new(ErrorCode::EnvelopeTooLarge)
                            .detail((MAX_LIVE_BYTES as u64).to_be_bytes()),
                    )]);
                }
                if !self.live_budget.charge(now_ms, LIVE_FRAMES_PER_MINUTE) {
                    // The frame only. The connection stays up and durable traffic
                    // is unaffected, which is the whole point of budgeting presence
                    // separately.
                    return Reaction::Reply(vec![Frame::Error(
                        FrameError::new(ErrorCode::RateLimited)
                            .retry_after(60)
                            .detail(u64::from(LIVE_FRAMES_PER_MINUTE).to_be_bytes()),
                    )]);
                }
                Reaction::Defer(Work::PublishLive { group, epoch, ct })
            }
            // Ready only, like every other authenticated frame. A key package is
            // stored against the authenticated device key, so a session that has not
            // authenticated has no shelf to publish onto.
            (State::Ready, Frame::Keys(body)) => {
                // The relay-to-client forms are refused on the way in. A client
                // sending one is a client that is wrong about the protocol, and the
                // catch-all's answer is the right one.
                if !matches!(body, KeysBody::Publish { .. } | KeysBody::Fetch { .. }) {
                    self.state = State::Closed;
                    return Reaction::ReplyAndClose(vec![Frame::Error(FrameError::new(
                        ErrorCode::MalformedHeader,
                    ))]);
                }
                // Publishing key packages inserts rows; a fetch only reads and
                // takes off the shelf, so the mode leaves it alone (WEALD-L158).
                if matches!(body, KeysBody::Publish { .. }) {
                    if let Some(refusal) = self.read_only_refusal() {
                        return refusal;
                    }
                }
                if let KeysBody::Fetch { count, .. } = &body {
                    if *count == 0 || *count > MAX_KEY_PACKAGE_FETCH {
                        return Reaction::Reply(vec![Frame::Error(
                            FrameError::new(ErrorCode::EnvelopeTooLarge)
                                .detail(u64::from(MAX_KEY_PACKAGE_FETCH).to_be_bytes()),
                        )]);
                    }
                }
                if !self.keys_budget.charge(now_ms, KEYS_FRAMES_PER_MINUTE) {
                    return Reaction::Reply(vec![Frame::Error(
                        FrameError::new(ErrorCode::RateLimited)
                            .retry_after(60)
                            .detail(u64::from(KEYS_FRAMES_PER_MINUTE).to_be_bytes()),
                    )]);
                }
                Reaction::Defer(Work::KeyPackages { body })
            }
            // `Ready` only, like every frame except `JOIN`. A registration is a
            // statement about an admitted principal, and the relay learns which
            // principal from the authenticated session rather than from a field, so a
            // session that has not authenticated has nothing to register against.
            (State::Ready, Frame::Wake(body)) => {
                // The relay-to-client forms are refused on the way in, exactly as
                // `KEYS` refuses its own. A client sending one is a client that is
                // wrong about the protocol, and the catch-all's answer is the right
                // one.
                if !matches!(
                    body,
                    crate::frame::WakeBody::Register { .. }
                        | crate::frame::WakeBody::Clear
                        | crate::frame::WakeBody::Query
                ) {
                    self.state = State::Closed;
                    return Reaction::ReplyAndClose(vec![Frame::Error(FrameError::new(
                        ErrorCode::MalformedHeader,
                    ))]);
                }
                // An expiry outside the storable window, judged against the relay's
                // own observed time. Here rather than in the codec because the codec
                // has no clock, and `reject` rather than `denied` because a
                // registration already expired, or so far ahead that the janitor sweep
                // could never reap it, is permanently wrong as sent: the client's fix
                // is to ask the ringer for a live handle, never to resend this one
                // (`specs/backend/relay/push.md` sections 3 and 4). One bound, shared
                // with the writing path in `ws.rs`, so the two cannot drift.
                if let crate::frame::WakeBody::Register { expires_at, .. } = &body {
                    if !crate::push::expiry_in_bounds(*expires_at, now_ms) {
                        return Reaction::Reply(vec![Frame::Error(FrameError::new(
                            ErrorCode::PushHandleMalformed,
                        ))]);
                    }
                }
                Reaction::Defer(Work::WakeRegistration { body })
            }
            // `Ready` only, like every other group-addressed frame. A call frame
            // names a group and claims a place in a conversation inside it, which
            // is a stronger claim than a beat, not a weaker one: a bootstrapping
            // session has no group it has been admitted to and so has nobody to
            // call.
            (
                State::Ready,
                Frame::Call {
                    call_id,
                    group,
                    epoch,
                    kind,
                    body,
                },
            ) => {
                if let Some(refusal) = self.calls_unavailable() {
                    return refusal;
                }
                // The kind is read before anything else is charged, because an
                // unrecognised kind is a client that is wrong about the protocol
                // rather than one that is over a limit, and charging a budget for a
                // frame that was never going to be routed would let a peer spend
                // somebody's allowance with garbage.
                let Some(kind) = crate::calls::CallKind::from_u8(kind) else {
                    return Reaction::Reply(vec![Frame::Error(FrameError::new(
                        ErrorCode::MalformedHeader,
                    ))]);
                };
                // Fixed width by the codec, so this cannot fail on a decoded
                // frame. It is a refusal rather than an unwrap because `Frame` is
                // public and a caller constructing one by hand is a caller this
                // must not panic for, and it lives here so the socket layer has no
                // copy of it that no sequence of bytes could reach.
                let Ok(call_id) = <[u8; crate::calls::CALL_ID_BYTES]>::try_from(call_id.as_slice())
                else {
                    return Reaction::Reply(vec![Frame::Error(FrameError::new(
                        ErrorCode::MalformedHeader,
                    ))]);
                };
                if body.len() > crate::calls::MAX_CALL_BODY_BYTES {
                    return Reaction::Reply(vec![Frame::Error(
                        FrameError::new(ErrorCode::EnvelopeTooLarge)
                            .detail((crate::calls::MAX_CALL_BODY_BYTES as u64).to_be_bytes()),
                    )]);
                }
                if !self
                    .call_budget
                    .charge(now_ms, crate::calls::CALL_FRAMES_PER_MINUTE)
                {
                    // The frame only. Signalling being refused must not take down
                    // a call that is already running on the same socket.
                    return Reaction::Reply(vec![Frame::Error(
                        FrameError::new(ErrorCode::RateLimited)
                            .retry_after(60)
                            .detail(u64::from(crate::calls::CALL_FRAMES_PER_MINUTE).to_be_bytes()),
                    )]);
                }
                Reaction::Defer(Work::PublishCall {
                    call_id,
                    group,
                    epoch,
                    kind,
                    body,
                })
            }
            // `Ready` only, and unlike every other frame here it names no group.
            // The group was checked when this connection was admitted to the call,
            // which is the whole design: see ``Work::PublishMedia``.
            (
                State::Ready,
                Frame::Media {
                    call_id,
                    stream,
                    seq,
                    ct,
                },
            ) => {
                if let Some(refusal) = self.calls_unavailable() {
                    return refusal;
                }
                if ct.len() > crate::calls::MAX_MEDIA_CT_BYTES {
                    // Refused on the declared length, before the payload is copied
                    // anywhere or charged against anything. The frame's bytes were
                    // already read off the socket under `MAX_FRAME_BYTES`; what is
                    // avoided here is every allocation after that.
                    return Reaction::Reply(vec![Frame::Error(
                        FrameError::new(ErrorCode::EnvelopeTooLarge)
                            .detail((crate::calls::MAX_MEDIA_CT_BYTES as u64).to_be_bytes()),
                    )]);
                }
                // Both ids are fixed width by the codec, so these conversions
                // cannot fail on a decoded frame. They are written as a refusal
                // rather than an unwrap because `Frame` is a public type and a
                // caller constructing one by hand is a caller this must not panic
                // for, and the narrowed values are what the work item carries, so
                // the socket layer has nothing left to convert.
                let (Ok(call_id), Ok(stream)) = (
                    <[u8; crate::calls::CALL_ID_BYTES]>::try_from(call_id.as_slice()),
                    <[u8; crate::calls::STREAM_BYTES]>::try_from(stream.as_slice()),
                ) else {
                    return Reaction::Reply(vec![Frame::Error(FrameError::new(
                        ErrorCode::MalformedHeader,
                    ))]);
                };
                if let Err(refusal) = self
                    .media_budget
                    .charge(now_ms, &call_id, &stream, ct.len())
                {
                    // Refused either way. What `should_report` decides is whether
                    // to say so, and it says so at most once a second: answering
                    // every frame of a flood is an amplifier, and the answers would
                    // fill the flooder's own bounded outbound queue and turn a rate
                    // limit into a disconnect.
                    return Reaction::Reply(if self.media_budget.should_report(now_ms) {
                        vec![Frame::Error(
                            FrameError::new(refusal.code())
                                .retry_after(refusal.retry_after())
                                .detail(refusal.detail().to_be_bytes()),
                        )]
                    } else {
                        Vec::new()
                    });
                }
                Reaction::Defer(Work::PublishMedia {
                    call_id,
                    stream,
                    seq,
                    ct,
                })
            }
            (State::Ready, Frame::Blob { payload }) => {
                Reaction::Defer(Work::BlobTicket { payload })
            }
            // Ready only, like every other group-addressed frame. A compaction
            // instruction names a group, and the group has to be checked against a
            // workspace this session has actually authenticated into.
            (State::Ready, Frame::Drop { payload }) => {
                Reaction::Defer(Work::DropBefore { payload })
            }
            // `BYE` is accepted in any live state: a client that changes its mind
            // between `CONNECT` and `AUTH` should be able to leave cleanly rather
            // than dropping a socket.
            (
                State::Fresh | State::Challenged | State::Ready | State::Bootstrapping,
                Frame::Bye { .. },
            ) => {
                self.state = State::Closed;
                Reaction::ReplyAndClose(vec![Frame::Bye { reason: Vec::new() }])
            }
            // Everything the table did not name: a frame in a state that does not
            // accept it, anything at all in a closed session, and the
            // relay-to-client frames a client does not send. One answer for all of
            // them, named as a malformed header rather than invented as a new
            // class: the registry is closed, and a frame in the wrong state is a
            // client that is wrong about the protocol, which is what `reject`
            // means.
            _ => {
                self.state = State::Closed;
                Reaction::ReplyAndClose(vec![Frame::Error(FrameError::new(
                    ErrorCode::MalformedHeader,
                ))])
            }
        }
    }

    /// The challenge this session issued, for the caller that verifies `AUTH`.
    pub fn challenge(&self) -> Option<&[u8]> {
        if self.challenge.is_empty() {
            return None;
        }
        Some(&self.challenge)
    }

    /// Record that authentication succeeded.
    pub fn authenticated(&mut self, key_packages_remaining: u32) -> Frame {
        self.state = State::Ready;
        // The challenge is spent. A second `AUTH` on one connection cannot reuse
        // it, and the frame table refuses a second `AUTH` anyway, so this is the
        // belt as well as the braces.
        self.challenge.clear();
        self.auth_ack(key_packages_remaining)
    }

    /// Authenticated into a workspace with no access set. See ``State/Bootstrapping``.
    pub fn bootstrapping(&mut self, key_packages_remaining: u32) -> Frame {
        self.state = State::Bootstrapping;
        self.challenge.clear();
        self.auth_ack(key_packages_remaining)
    }

    /// The one place `AUTH_ACK` is built, so the ordinary path and the
    /// bootstrapping path cannot come to report different things about the same
    /// relay.
    fn auth_ack(&self, key_packages_remaining: u32) -> Frame {
        Frame::AuthAck {
            key_packages_remaining,
            write_mode: match self.write_mode {
                WriteMode::Full => 0,
                WriteMode::ReadOnly => 1,
            },
            build_digest: self.build_digest.clone(),
            access_set: u8::from(self.access_set_enforced),
            min_enc: u8::from(self.refuses_plaintext),
        }
    }

    /// Record that authentication failed. The connection ends: a peer that cannot
    /// prove a key has nothing else to say, and leaving the socket open would let
    /// it keep guessing.
    /// Returns the frames to send on the way out rather than a `Reaction`: this
    /// always closes, and a caller that had to match on a `Reaction` would need arms
    /// for outcomes this cannot produce.
    pub fn rejected(&mut self, code: ErrorCode) -> Vec<Frame> {
        self.state = State::Closed;
        vec![Frame::Error(FrameError::new(code))]
    }
}

/// How far the client's clock is from the relay's, or `None` if it is close
/// enough not to mention.
fn skew(client_ms: u64, relay_ms: u64) -> Option<i64> {
    let difference = i64::try_from(client_ms)
        .unwrap_or(i64::MAX)
        .saturating_sub(i64::try_from(relay_ms).unwrap_or(i64::MAX));
    (difference.unsigned_abs() > CLOCK_SKEW_LIMIT_MS).then_some(difference)
}

/// Challenge bytes for one session.
///
/// BLAKE3 over a label, a process secret, the connection identity, the relay's
/// clock and requested groups. The counter guarantees distinct derivation inputs
/// for each live process session; the OS-random process secret prevents a peer
/// from predicting the resulting challenge.
fn challenge_bytes(now_ms: u64, groups: &[Vec<u8>], connection_nonce: u64) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"weald relay challenge v1");
    hasher.update(challenge_secret());
    hasher.update(&connection_nonce.to_be_bytes());
    hasher.update(&now_ms.to_be_bytes());
    for group in groups {
        hasher.update(group);
    }
    hasher.finalize().as_bytes().to_vec()
}

fn challenge_secret() -> &'static [u8; 32] {
    CHALLENGE_SECRET.get_or_init(|| {
        let mut secret = [0; 32];
        getrandom::fill(&mut secret)
            .expect("operating-system entropy is required for relay AUTH challenges");
        secret
    })
}
