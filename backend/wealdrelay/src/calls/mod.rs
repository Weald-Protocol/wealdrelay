// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Voice calls: the signalling frame, the media frame, and the routing table
//! that joins them.
//!
//! `specs/peer-calls.md` is the design and `specs/backend/relay/calls.md` is the
//! relay half of it. Two frames, `CALL` (tag 23) and `MEDIA` (tag 24), both
//! ephemeral in the sense `presence.md` already established for `LIVE`: never
//! sequenced, never stored, never reconciled, never attested, and the only frames
//! this relay may shed on its own initiative.
//!
//! ## Why a registry exists at all, when presence needed none
//!
//! A beat is addressed to a group and the group is on the frame, so `LIVE` needs
//! no state: `authorize_group` answers, the hub fans out, and the relay forgets.
//! Media cannot work that way for two reasons.
//!
//! The first is cost. `authorize_group` is a Postgres read, and a two-party call
//! is a hundred frames a second. Putting a database round trip on each of them
//! would put the database in the media path, which
//! `specs/peer-calls.md` section 3 forbids in the same breath as the `seq`
//! counter and for the same reason.
//!
//! The second is fanout width. A group is a workspace room and a call is two to
//! five people in it. Fanning media at the group would multiply egress by every
//! subscribed device that is not on the call and hand each of them a stream they
//! did not ask for.
//!
//! So `CALL` is the checkpoint and `MEDIA` is the cheap path behind it. A `CALL`
//! frame is access-set checked exactly as a `SEND` is, at a signalling rate of
//! two a second, and admission to a call is what it buys. `MEDIA` then costs one
//! map lookup and a memcpy per recipient, with no database, no hash and no
//! sequence number anywhere on the path.
//!
//! ## What this module is not allowed to know
//!
//! A call id, the group it belongs to, and connection handles. Nothing else.
//! `body` on a `CALL` and `ct` on a `MEDIA` are sealed, and there is nowhere in
//! these types to put them. No counter or log line here carries a call id, a
//! group, a principal or anything derived from either payload, which is the rule
//! `hub.rs` and `health.rs` already hold to.
//!
//! ## One process, and the honest statement of it
//!
//! The table is process-local, like the hub. Two relay processes sharing one
//! Postgres do **not** share it, so a call whose two participants land on
//! different processes does not connect. That is not papered over: it is the same
//! constraint `LIVE` has, it is enforced by the same startup refusal
//! (`config::LiveFanout`, which a call deployment must satisfy too), and it is the
//! first thing in this codebase that would genuinely need the Redis that
//! `WEALD_RELAY_REDIS_URL` declares and no code uses. `calls.md` records it as a
//! known bound rather than as a defect, because chat degrades to reconciliation
//! across processes and a call has no reconciliation to degrade to.

pub mod socket;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::Mutex;

use crate::frame::{ErrorCode, Frame};
use crate::hub::ConnectionId;
use crate::ws::{try_queue, OutboundSender, Queued};

/// Bytes in a call id. Client-chosen and opaque: the relay compares it and never
/// derives anything from it.
pub const CALL_ID_BYTES: usize = 16;

/// Bytes in a stream id. Four, because it is also the first half of the client's
/// AES-GCM nonce (`specs/peer-calls.md`, media encryption), so the wire width and
/// the nonce width are one number rather than two that could drift.
pub const STREAM_BYTES: usize = 4;

/// The largest `MEDIA.ct` the relay will carry.
///
/// 1500 bytes, from the limits table in `specs/peer-calls.md` section 3. Sized at
/// one Ethernet MTU rather than at the codec's frame size: 20 ms of AAC-ELD at
/// 32 kbps is about 80 bytes, so the ceiling is four hundred times the working
/// payload and exists to bound an attacker rather than to fit a codec.
pub const MAX_MEDIA_CT_BYTES: usize = 1500;

/// The largest `CALL.body` the relay will carry.
///
/// Four KiB, the same ceiling `LIVE` uses and for the same reason: a signalling
/// body is a small sealed struct, and a larger one is a client using an ephemeral
/// frame to move something durable.
pub const MAX_CALL_BODY_BYTES: usize = 4096;

/// `MEDIA` frames one stream may send per second.
///
/// Sixty against a codec that produces fifty, so a client that jitters a frame
/// across a window boundary is not punished for it, and a client at ten times the
/// rate is.
pub const MEDIA_FRAMES_PER_STREAM_PER_SECOND: u32 = 60;

/// The window the per-stream frame budget is counted over.
pub const MEDIA_STREAM_WINDOW_MS: u64 = 1_000;

/// `MEDIA` bytes one connection may send per minute.
///
/// One MiB. A 24 kbps stream is about 190 KiB a minute including overhead, so
/// this admits one stream comfortably and refuses a connection trying to push a
/// file through the media path.
pub const MEDIA_BYTES_PER_MINUTE: u64 = 1024 * 1024;

/// `CALL` frames one connection may send per minute.
///
/// A hundred and twenty. Signalling is a handful of frames per call plus
/// candidates later, so this is generous for a human and narrow for a loop.
pub const CALL_FRAMES_PER_MINUTE: u32 = 120;

/// People in one call.
///
/// Five. Egress grows as n(n-1) with relayed fanout, so five is where the
/// quadratic term stops being free (`specs/peer-calls.md` section 3), and the
/// cap is enforced here rather than only stated in a UI.
pub const MAX_PARTICIPANTS_PER_CALL: usize = 5;

/// How many distinct streams one connection's budget tracks at once.
///
/// A bound on the budget's own memory, so a client cannot make the relay hold a
/// window per invented stream id. Well above one call's worth: five participants
/// is five streams, and a client that legitimately exceeds this is not on a call.
pub const MAX_TRACKED_STREAMS: usize = 32;

/// The protocol version at which both call frames exist.
///
/// Fanout filters on it exactly as presence filters on 2, so a version 2 client
/// is never sent a frame its build cannot name and keeps working unchanged.
pub const CALL_PROTOCOL_VERSION: u16 = 3;

/// The cleartext `kind` on a `CALL` frame.
///
/// The one field of either frame the relay interprets, and it is deliberately a
/// closed enum of four small numbers. It has to be readable, because the relay
/// decides call membership from it and membership is what makes `MEDIA` cheap;
/// everything about *what* is being offered or answered is in the sealed `body`.
///
/// An unrecognised kind is refused rather than forwarded. A relay that forwarded
/// one would be a relay whose routing semantics a future client could change
/// without a version bump, which is the thing a fixed frame set exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CallKind {
    /// Start a call, or re-offer into one. The sender joins.
    Offer = 1,
    /// Accept an offer. The sender joins.
    Answer = 2,
    /// Refuse an offer. The sender does not join, and leaves if it had.
    Decline = 3,
    /// Leave. The sender leaves, and the call is forgotten when the last
    /// participant does.
    Bye = 4,
}

impl CallKind {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Offer,
            2 => Self::Answer,
            3 => Self::Decline,
            4 => Self::Bye,
            _ => return None,
        })
    }

    /// Whether this kind puts the sender in the call.
    pub fn joins(self) -> bool {
        matches!(self, Self::Offer | Self::Answer)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offer => "offer",
            Self::Answer => "answer",
            Self::Decline => "decline",
            Self::Bye => "bye",
        }
    }

    /// Every kind, so a test walks the set rather than remembering it.
    pub const ALL: &'static [Self] = &[Self::Offer, Self::Answer, Self::Decline, Self::Bye];
}

/// One connection's media budget: frames per stream per second, and bytes per
/// minute across all of them.
///
/// Fixed windows rather than token buckets, matching `session::FrameBudget`: what
/// is being bounded is a client sending on a 20 ms timer, so a window that resets
/// is both sufficient and exactly what the limits table states.
#[derive(Debug, Default, Clone)]
pub struct MediaBudget {
    /// `(call_id, stream, window_started_ms, spent)`. A vector rather than a map
    /// because it holds at most ``MAX_TRACKED_STREAMS`` entries and a linear scan
    /// of thirty-two is cheaper than hashing a twenty-byte key fifty times a
    /// second.
    streams: Vec<([u8; CALL_ID_BYTES], [u8; STREAM_BYTES], u64, u32)>,
    bytes_window_started_ms: u64,
    bytes_spent: u64,
    /// When this connection was last told it was over a media limit, or `None` if
    /// it never has been. See ``MediaBudget::refusal_to_report``.
    last_reported_ms: Option<u64>,
}

/// Why a media frame was refused by the budget.
///
/// An error type rather than a verdict enum with an `Allowed` arm, and the
/// difference is not cosmetic: with `Allowed` in the set, every function that
/// mapped a verdict to a code needed an arm for the case that has no code, and
/// that arm was unreachable from the one caller that checks first. `Result` puts
/// the distinction in the type, so there is no such arm to leave uncovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaRefusal {
    /// Over ``MEDIA_FRAMES_PER_STREAM_PER_SECOND`` on this stream.
    StreamRate,
    /// Over ``MEDIA_BYTES_PER_MINUTE`` for this connection.
    ByteRate,
    /// More than ``MAX_TRACKED_STREAMS`` distinct streams inside one window.
    TooManyStreams,
}

impl MediaRefusal {
    /// The code the client is answered with.
    ///
    /// Every one of them is `quota/group_ingress_limited`, which is the code
    /// `frame.rs` has carried since step 2 with nothing referring to it. A limit
    /// the spec claims and the code does not enforce is worse than no limit,
    /// because it is protection somebody is relying on.
    ///
    /// One code for three causes on purpose. A client's correct response to all
    /// three is identical (slow down, and `retry_after` says how long), and three
    /// codes would be three things for a client to branch on that it must treat
    /// the same, plus three ways for an observer to learn which limit a peer hit.
    pub fn code(self) -> ErrorCode {
        match self {
            Self::StreamRate | Self::ByteRate | Self::TooManyStreams => {
                ErrorCode::GroupIngressLimited
            }
        }
    }

    /// Seconds before the refused frame could succeed.
    ///
    /// One code for three causes, but not one interval: the windows are a second
    /// and a minute wide, and a client told to come back in a second against a byte
    /// window that resets in fifty-nine is a client that will be refused fifty-nine
    /// more times. That is the flood the single answer per window exists to
    /// prevent, arriving by the front door.
    ///
    /// This leaks nothing the sender did not already know. The argument against
    /// three codes is that three codes are three things an *observer* learns about
    /// a peer; this answer goes only to the connection that sent the frame, and it
    /// knows how many bytes it just sent.
    pub fn retry_after(self) -> u32 {
        match self {
            // Both are counted over ``MEDIA_STREAM_WINDOW_MS``.
            Self::StreamRate | Self::TooManyStreams => {
                (MEDIA_STREAM_WINDOW_MS / 1_000).max(1) as u32
            }
            Self::ByteRate => 60,
        }
    }

    /// The limit the answer names, so a client surfaces the lever it hit rather
    /// than the one it did not. Never content-derived.
    pub fn detail(self) -> u64 {
        match self {
            Self::StreamRate => u64::from(MEDIA_FRAMES_PER_STREAM_PER_SECOND),
            Self::ByteRate => MEDIA_BYTES_PER_MINUTE,
            Self::TooManyStreams => MAX_TRACKED_STREAMS as u64,
        }
    }
}

impl MediaBudget {
    /// Charge one frame of `bytes` on one stream.
    ///
    /// ## Why both windows treat a backwards clock as a new window
    ///
    /// `health::Clock::System` reads `SystemTime`, which is a wall clock and steps
    /// backwards whenever NTP corrects one. Asking only whether enough time has
    /// passed answers "no" across such a step, so both windows would freeze at
    /// whatever they held: the byte window would refuse every frame until the clock
    /// climbed back past its start plus a minute, and the stream table would prune
    /// nothing, so a connection that had touched ``MAX_TRACKED_STREAMS`` ids would
    /// answer `TooManyStreams` to every new stream for just as long.
    ///
    /// Both are a routine one second correction turning into up to a minute of
    /// silence on a live call, which is the failure mode a fixed window exists to
    /// avoid rather than to cause. A window whose start is in the future is
    /// therefore not a window at all, and the honest reading is to begin a new one:
    /// it costs an attacker nothing they did not already have, because a client
    /// cannot move the relay's clock, and it costs a legitimate call nothing at all.
    pub fn charge(
        &mut self,
        now_ms: u64,
        call_id: &[u8; CALL_ID_BYTES],
        stream: &[u8; STREAM_BYTES],
        bytes: usize,
    ) -> Result<(), MediaRefusal> {
        if now_ms < self.bytes_window_started_ms
            || now_ms.saturating_sub(self.bytes_window_started_ms) >= 60_000
        {
            self.bytes_window_started_ms = now_ms;
            self.bytes_spent = 0;
        }
        let next = self.bytes_spent.saturating_add(bytes as u64);
        if next > MEDIA_BYTES_PER_MINUTE {
            return Err(MediaRefusal::ByteRate);
        }

        // Expired windows are dropped rather than reset in place, so a client that
        // rotates stream ids cannot accumulate entries: the vector holds only
        // streams that were active inside the last second. An entry stamped after
        // `now_ms` is expired too, for the reason above: it is the residue of a
        // clock that has since been corrected backwards, and keeping it would hold a
        // seat in a table with a fixed number of them.
        self.streams.retain(|(_, _, started, _)| {
            *started <= now_ms && now_ms.saturating_sub(*started) < MEDIA_STREAM_WINDOW_MS
        });
        match self
            .streams
            .iter_mut()
            .find(|(id, s, _, _)| id == call_id && s == stream)
        {
            Some((_, _, _, spent)) => {
                if *spent >= MEDIA_FRAMES_PER_STREAM_PER_SECOND {
                    return Err(MediaRefusal::StreamRate);
                }
                *spent += 1;
            }
            None => {
                if self.streams.len() >= MAX_TRACKED_STREAMS {
                    return Err(MediaRefusal::TooManyStreams);
                }
                self.streams.push((*call_id, *stream, now_ms, 1));
            }
        }
        self.bytes_spent = next;
        Ok(())
    }

    /// How many stream windows this budget is holding.
    ///
    /// The bound on the budget's own memory, exposed so a test can assert it
    /// directly rather than inferring it from a refusal. A refusal proves the check
    /// fired; only the count proves the table did not grow, and those are different
    /// claims: a `TooManyStreams` answer returned from a vector that had already
    /// pushed the entry would satisfy the first and violate the second.
    pub fn tracked_streams(&self) -> usize {
        self.streams.len()
    }

    /// Whether to tell the sender about a refusal that has already happened.
    ///
    /// At most one refusal per window, and this is not a nicety. A stream at ten
    /// times its rate is 600 frames a second, and answering each one turns a flood
    /// into two floods: the same amplification an open resolver has. Worse, the
    /// answers are queued on the flooder's own outbound queue, which is bounded, so
    /// a relay that answered every frame would fill that queue and drop the
    /// connection, turning a rate limit into a disconnect.
    ///
    /// One answer per second is everything a client needs. It learns it is over the
    /// limit, and `retry_after` tells it when to try again; the next 599 answers
    /// would tell it the same thing.
    ///
    /// The silence is not a dropped guarantee. Nothing was accepted: the frame was
    /// refused either way, and what is being economised is the complaint rather
    /// than the enforcement.
    pub fn should_report(&mut self, now_ms: u64) -> bool {
        let fresh = match self.last_reported_ms {
            None => true,
            // Backwards is fresh, for the reason `charge` gives: a report stamped
            // after `now_ms` is the residue of a corrected clock, and treating it as
            // recent would silence the one answer a client needs to slow down.
            Some(last) => now_ms < last || now_ms.saturating_sub(last) >= MEDIA_STREAM_WINDOW_MS,
        };
        if fresh {
            self.last_reported_ms = Some(now_ms);
        }
        fresh
    }
}

/// One call in flight on this process.
#[derive(Debug)]
struct Call {
    /// The group the call belongs to, recorded when the call was opened and never
    /// changed. Every later frame for this call id is checked against it, which is
    /// what makes a call id collision a refusal rather than a bridge between two
    /// rooms.
    group: Vec<u8>,
    participants: Vec<(ConnectionId, OutboundSender)>,
}

/// Why a `CALL` could not be admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinRefusal {
    /// This call id is already open against a different group. The sender is
    /// either confused or is trying to reach a room it was not admitted to
    /// through a call it was.
    GroupMismatch,
    /// The process is already carrying its configured number of calls.
    TooManyCalls,
    /// This call already holds ``MAX_PARTICIPANTS_PER_CALL``.
    CallFull,
}

impl JoinRefusal {
    pub fn code(self) -> ErrorCode {
        match self {
            // Denied rather than quota: the frame names a group this session is
            // not entitled to reach through this call id, which is the same class
            // of answer `authorize_group` gives.
            Self::GroupMismatch => ErrorCode::WriterNotInAccessSet,
            Self::TooManyCalls | Self::CallFull => ErrorCode::RateLimited,
        }
    }

    /// The limit the answer names, so a client surfaces the lever rather than
    /// guessing at one. Never content-derived.
    pub fn detail(self, max_calls: usize) -> u64 {
        match self {
            Self::GroupMismatch => 0,
            Self::TooManyCalls => max_calls as u64,
            Self::CallFull => MAX_PARTICIPANTS_PER_CALL as u64,
        }
    }
}

/// The calls this process is carrying.
#[derive(Debug)]
pub struct CallRegistry {
    calls: Mutex<HashMap<[u8; CALL_ID_BYTES], Call>>,
    /// How many calls may be open at once, from
    /// `WEALD_RELAY_MAX_CONCURRENT_CALLS`. A required variable rather than a
    /// default, because an instance's call capacity is a sizing decision its
    /// operator makes and a relay that guessed one would be a relay whose limit
    /// nobody chose.
    max_concurrent: usize,
    /// Media frames dropped because a recipient's queue was full.
    ///
    /// The counter the shed rule is observable through. No label, on purpose: a
    /// per-call or per-group count would be exactly the metadata `hub.rs` refuses
    /// to hold, and an operator needs the capacity signal rather than the identity.
    shed: AtomicU64,
    /// Media frames refused because the sender was not in the call it named.
    denied: AtomicU64,
}

impl CallRegistry {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            calls: Mutex::new(HashMap::new()),
            max_concurrent,
            shed: AtomicU64::new(0),
            denied: AtomicU64::new(0),
        }
    }

    /// How many calls are open. For `/readyz` and the tests; never per group and
    /// never exported to a client.
    pub async fn open_calls(&self) -> usize {
        self.calls.lock().await.len()
    }

    /// How many media frames this process has shed under load.
    pub fn shed(&self) -> u64 {
        self.shed.load(Ordering::Relaxed)
    }

    /// How many media frames this process has refused as unadmitted.
    pub fn denied(&self) -> u64 {
        self.denied.load(Ordering::Relaxed)
    }

    /// The configured ceiling, so a refusal can name it.
    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// Admit a connection to a call, opening it if this is the first frame.
    ///
    /// `group` has already been checked against the session's access set by the
    /// caller. What is decided here is whether the *call id* is one this session
    /// may use, which is a different question: an id already open against another
    /// group is refused even though both groups may be admitted, because a call is
    /// a conversation inside one room.
    pub async fn join(
        &self,
        call_id: &[u8; CALL_ID_BYTES],
        group: &[u8],
        connection: ConnectionId,
        sender: OutboundSender,
    ) -> Result<(), JoinRefusal> {
        let mut calls = self.calls.lock().await;
        match calls.get_mut(call_id) {
            Some(call) => {
                if call.group != group {
                    return Err(JoinRefusal::GroupMismatch);
                }
                if call
                    .participants
                    .iter()
                    .any(|(existing, _)| *existing == connection)
                {
                    // Idempotent. A re-offer from somebody already in the call is a
                    // normal thing for a client to send and must not consume a seat.
                    return Ok(());
                }
                if call.participants.len() >= MAX_PARTICIPANTS_PER_CALL {
                    return Err(JoinRefusal::CallFull);
                }
                call.participants.push((connection, sender));
                Ok(())
            }
            None => {
                if calls.len() >= self.max_concurrent {
                    return Err(JoinRefusal::TooManyCalls);
                }
                calls.insert(
                    *call_id,
                    Call {
                        group: group.to_vec(),
                        participants: vec![(connection, sender)],
                    },
                );
                Ok(())
            }
        }
    }

    /// Take one connection out of one call, forgetting the call when it empties.
    pub async fn leave(&self, call_id: &[u8; CALL_ID_BYTES], connection: ConnectionId) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(call_id) {
            call.participants
                .retain(|(existing, _)| *existing != connection);
            if call.participants.is_empty() {
                calls.remove(call_id);
            }
        }
    }

    /// Take one connection out of every call it is in.
    ///
    /// Called when a socket ends, including when it ends badly. A registry that
    /// leaked a participant per dropped connection would fan media at senders
    /// nobody is reading, fifty times a second, for the life of the process.
    pub async fn forget(&self, connection: ConnectionId) {
        let mut calls = self.calls.lock().await;
        for call in calls.values_mut() {
            call.participants
                .retain(|(existing, _)| *existing != connection);
        }
        calls.retain(|_, call| !call.participants.is_empty());
    }

    /// The group a call belongs to, if this process is carrying it.
    pub async fn group_of(&self, call_id: &[u8; CALL_ID_BYTES]) -> Option<Vec<u8>> {
        self.calls
            .lock()
            .await
            .get(call_id)
            .map(|call| call.group.clone())
    }

    /// Whether one connection is in one call.
    pub async fn holds(&self, call_id: &[u8; CALL_ID_BYTES], connection: ConnectionId) -> bool {
        self.calls.lock().await.get(call_id).is_some_and(|call| {
            call.participants
                .iter()
                .any(|(existing, _)| *existing == connection)
        })
    }

    /// Fan one media frame at the other participants of its call.
    ///
    /// `Err` means the sender is not in the call it named, which is the refusal
    /// that makes `MEDIA` safe without a database read: a connection can only
    /// reach a call it was admitted to by a `CALL` frame that *was* access-set
    /// checked.
    ///
    /// A full queue sheds this frame and nothing else. It is never a downgrade,
    /// because a downgrade is a claim about durable state and there is no
    /// reconciliation for audio; it is never a close, because one late packet is
    /// not a reason to drop a call. `specs/peer-calls.md` section 3.
    pub async fn route(
        &self,
        call_id: &[u8; CALL_ID_BYTES],
        from: ConnectionId,
        frame: &Frame,
    ) -> Result<Routed, ErrorCode> {
        let mut gone = Vec::new();
        let mut routed = Routed::default();
        {
            let mut calls = self.calls.lock().await;
            let Some(call) = calls.get_mut(call_id) else {
                self.denied.fetch_add(1, Ordering::Relaxed);
                return Err(ErrorCode::WriterNotInAccessSet);
            };
            if !call
                .participants
                .iter()
                .any(|(existing, _)| *existing == from)
            {
                self.denied.fetch_add(1, Ordering::Relaxed);
                return Err(ErrorCode::WriterNotInAccessSet);
            }
            for (id, sender) in call.participants.iter() {
                if *id == from {
                    continue;
                }
                match try_queue(sender, frame.clone()) {
                    Queued::Sent => routed.sent += 1,
                    Queued::Full => {
                        self.shed.fetch_add(1, Ordering::Relaxed);
                        routed.shed += 1;
                    }
                    Queued::Closed => {
                        routed.gone += 1;
                        gone.push(*id);
                    }
                }
            }
            // The sender is never in `gone`: it is skipped by the loop above, and
            // it was confirmed to be a participant before the loop ran. So the
            // list cannot empty here, and there is deliberately no arm removing
            // the call: an arm no sequence of events can reach is worse than a
            // missing one, because it cannot be tested and reads as handled.
            //
            // A call whose last participant has gone is removed by `forget`, on
            // the path that actually produces that state: the reader loop ending.
            call.participants.retain(|(id, _)| !gone.contains(id));
        }
        Ok(routed)
    }
}

/// What one media fanout did. Counts only: no ids, no group, nothing derived from
/// the payload.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Routed {
    pub sent: usize,
    pub shed: usize,
    pub gone: usize,
}
