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

use crate::config::{Config, WriteMode};
use crate::frame::{ErrorCode, Frame, FrameError, PROTOCOL_VERSION};
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
    /// One MLS handshake message, stored in order and fanned out (step 8).
    PublishHandshake { group: Vec<u8>, message: Vec<u8> },
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

    pub fn requested(&self) -> &[Vec<u8>] {
        &self.requested
    }

    /// Bind a successfully authenticated (or bootstrapping) connection to the
    /// workspace that the relay resolved during admission.
    pub fn bind_workspace(&mut self, workspace: String) {
        self.authorized_workspace = Some(workspace);
    }

    /// The only workspace this ready session may operate in.
    pub fn authorized_workspace(&self) -> Option<&str> {
        self.authorized_workspace.as_deref()
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
                if version != PROTOCOL_VERSION {
                    // Aborts the connection. `operations.md`: a version failure
                    // never silently continues.
                    self.state = State::Closed;
                    return Reaction::ReplyAndClose(vec![Frame::Error(
                        FrameError::new(ErrorCode::ProtocolUnsupported)
                            .detail(PROTOCOL_VERSION.to_be_bytes()),
                    )]);
                }
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
                        version: PROTOCOL_VERSION,
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
                if matches!(self.write_mode, WriteMode::ReadOnly) {
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
                if !self.subscribed.contains(&group) {
                    self.subscribed.push(group.clone());
                }
                Reaction::Defer(Work::Subscribe { group, from_seq })
            }
            (State::Ready, Frame::Recon { group, payload }) => {
                Reaction::Defer(Work::Reconcile { group, payload })
            }
            // The one frame a bootstrapping session may send, and the reason that
            // state exists.
            (State::Ready | State::Bootstrapping, Frame::Access { body }) => {
                Reaction::Defer(Work::RotateAccessSet { body })
            }
            // Ready only, unlike `ACCESS`. A bootstrapping session has no group
            // whose epoch secret could have derived a tag, so a wrap from one is
            // a client that is wrong about the protocol rather than a case to
            // allow for.
            (State::Ready, Frame::Wrap { body }) => Reaction::Defer(Work::PublishWrap { body }),
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
            ) => Reaction::Defer(Work::Redeem { body }),
            // Ready only, like every other group-addressed frame: a handshake
            // message belongs to a group, and a bootstrapping session has no
            // workspace claim to check a group against.
            (State::Ready, Frame::Handshake { group, message, .. }) => {
                Reaction::Defer(Work::PublishHandshake { group, message })
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
