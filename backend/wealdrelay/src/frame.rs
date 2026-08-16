// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The frame set, and the one error taxonomy every frame uses.
//!
//! `specs/backend/relay/wire.md` names the frames and
//! `specs/backend/relay/operations.md` names the six error classes. Both are
//! reproduced here as types rather than as strings, because the point of the
//! taxonomy is that a client branches on a code: a client matching on a message
//! is a client that breaks when somebody improves the wording.
//!
//! ## Deterministic CBOR again, and for the same reason
//!
//! A frame is a two item array: a tag, then the frame's own fields as a nested
//! array. Not a map, because a map has a key order to get wrong and the envelope
//! inside `SEND` is content addressed, so a frame encoder with any freedom in it
//! would produce two encodings of one message and a relay would store both.
//!
//! ## What is deliberately absent
//!
//! No `kind`, no channel, no author, nothing derived from the ciphertext. The
//! relay routes on `group` and nothing else, so those are the only fields a frame
//! carries about content, and there is nowhere in this module for anything more.

use crate::cbor::{self, CborError, Reader};

/// The highest protocol version this build speaks.
///
/// `CONNECT` carries one field, which is the client's maximum offer, and the
/// relay selects `min(offered, PROTOCOL_VERSION)`. An offer below
/// ``MIN_PROTOCOL_VERSION`` is answered with `version/protocol_unsupported`
/// carrying this number, and the connection ends: `operations.md` says a version
/// failure aborts the connection and never silently continues.
///
/// Version 2 adds two frames (``FrameTag::Live`` and ``FrameTag::Keys``) and one
/// envelope kind, and changes no envelope. Version 3 adds two more
/// (``FrameTag::Call`` and ``FrameTag::Media``) and changes neither an envelope
/// nor an existing frame. A client of any earlier version keeps working and
/// simply never receives a frame it does not know.
///
/// Version 4 adds exactly one frame, ``FrameTag::Wake``, and changes no envelope,
/// no envelope kind and no existing frame. It is a version bump rather than an
/// additive change because `../contracts/governance.md`'s mechanical test is about
/// disagreement rather than about damage: a version 3 relay and a version 4 client
/// cannot agree on what tag 25 means, so the number that decides it has to move
/// (`specs/backend/relay/push.md`). A version 3 client keeps working, never sends
/// a `WAKE`, and therefore never receives a push, which is the same posture as a
/// relay with push switched off.
pub const PROTOCOL_VERSION: u16 = 4;

/// The lowest protocol version this build will still serve.
///
/// The other half of the range. A build constant on both sides rather than a
/// second field on `CONNECT`, because the shape of `CONNECT` is on the wire and
/// changing it is the one thing a version negotiation must not require
/// (`specs/backend/relay/wire.md`, versioning).
pub const MIN_PROTOCOL_VERSION: u16 = 1;

/// The six classes from `operations.md`. Not extensible without a protocol
/// version bump, which is why this is an enum and not a string, and why `Limit`
/// arrives here in the same version as ``FrameTag::Wake`` rather than on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// Transient. Backoff with jitter, resend verbatim, never renumber an author
    /// chain link.
    Retry,
    /// Permanently wrong as sent. Do not retry.
    Reject,
    /// Well formed, not permitted now. Re-read the state named in the error.
    Denied,
    /// Over a limit. Retry after the named interval, or surface the lever that
    /// clears it.
    Quota,
    /// Unsupported or below the client's floor. Abort the connection.
    Version,
    /// Over a per-principal ceiling on a write the client can simply stop making.
    /// Retry after the named interval, on the frame only: the connection stays up
    /// and durable traffic is unaffected.
    ///
    /// Distinct from `Quota` in who is over the line and in what clears it. A
    /// `quota` is the workspace's and clears by a lever an operator or an admin
    /// pulls; a `limit` is one principal's own rate and clears by that principal
    /// waiting. Folding the two together would tell a device to go and find an
    /// administrator when all it had to do was stop.
    Limit,
}

impl ErrorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Retry => "retry",
            Self::Reject => "reject",
            Self::Denied => "denied",
            Self::Quota => "quota",
            Self::Version => "version",
            Self::Limit => "limit",
        }
    }

    /// Whether a client should send the same bytes again after a wait.
    ///
    /// Only `retry`, `quota` and `limit`, and they are different waits: `retry`
    /// is backoff with jitter, `quota` and `limit` are the interval the error
    /// names. `denied` is deliberately not retryable, because retrying blind
    /// against a state that changed is how a client hammers a relay that has
    /// already told it no. Kept in step with `RETRYABLE` in
    /// `scripts/error-class-matrix.py`.
    pub fn is_retryable(self) -> bool {
        matches!(self, Self::Retry | Self::Quota | Self::Limit)
    }
}

/// Every code the relay may emit, from
/// `specs/backend/contracts/registries/error-codes.md`. The registry is closed:
/// nothing outside it may invent a code, and `scripts/spec-check.sh` fails on one
/// that appears in source without a row there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    // retry
    Backpressure,
    LockTimeout,
    Failover,
    /// No database on the wake-registration path. Fails closed like every other
    /// admission path: a relay that cannot write a registration must not answer as
    /// though it had, because the client would then believe it holds a wake
    /// capability it does not (`specs/backend/relay/push.md` section 3).
    PushBackpressure,
    // reject
    MalformedHeader,
    NoncanonicalCbor,
    HashMismatch,
    EnvelopeTooLarge,
    UnknownRequiredField,
    /// A `WAKE` registration the relay will never accept as sent: a handle that is
    /// not exactly sixteen bytes, a `categories` bitmask that is zero or sets an
    /// undefined bit, an `expires_at` already in the past, or a `register_url` a
    /// client would refuse. A reject and not a denial, because none of those becomes
    /// acceptable if the operator changes a variable: the bytes are wrong.
    PushHandleMalformed,
    // denied
    PlaintextRefused,
    WriterNotInAccessSet,
    GroupUnknown,
    ServiceReadOnly,
    GroupFrozen,
    /// A `Register` sent to a relay with `WEALD_RELAY_PUSH=off`.
    ///
    /// Denied rather than rejected, and the distinction is the client's next move.
    /// The frame is well formed and the answer would change if the operator changed
    /// one variable, so the correct response is to re-read the state by sending
    /// `Query` and to hold no registration meanwhile, never to resend the same
    /// `Register` against a relay that has said no.
    PushNotConfigured,
    /// A recovery wrap that does not advance its slot's epoch. Denied rather
    /// than rejected: the bytes are well formed and would have been accepted one
    /// epoch ago, which is exactly the replay the monotonicity rule refuses
    /// (`specs/backend/relay/groups.md`). A client's correct response is to
    /// re-derive the current epoch's wrap, never to resend this one.
    WrapNotNewer,
    // quota
    StorageExhausted,
    /// The workspace's envelope log is at `WEALD_RELAY_MAX_LOG_GB`.
    ///
    /// Distinct from `storage_exhausted`, which is the media bucket, because the
    /// two have different levers and a client that could not tell them apart
    /// would offer the wrong one. Media clears by deleting a file; the envelope
    /// log clears only by a signed `drop_before` behind an accepted checkpoint,
    /// or by a larger plan. The relay never compacts to make room on its own:
    /// `specs/backend/relay/lifecycle.md` says it "never drops an envelope on its
    /// own initiative", and a budget that deleted history to accept a write would
    /// be exactly that, done under load and without a signature.
    ///
    /// Carries the limit rather than an interval, because waiting does not clear
    /// it. `operations.md` allows a `quota` error to name either.
    LogBudgetExhausted,
    RateLimited,
    SeatsExhausted,
    GroupIngressLimited,
    /// More than ``crate::push::REGISTRATIONS_PER_HOUR`` registrations from one
    /// principal in an hour.
    ///
    /// `limit`, the class protocol version 4 added alongside this frame. It was
    /// briefly `quota` here on the reasoning that the class set was closed at five
    /// and `quota` was the nearest fit, and that was wrong in the direction that
    /// costs the most: the registry, `push.md`, the wire vectors and
    /// `scripts/error-class-matrix.py` all say `limit`, so the wire carried a class
    /// no published document named for this code. A client branches on the class
    /// before the code, which is exactly why adding one is a breaking change and
    /// why it rides this version bump.
    PushRegistrationRate,
    // version
    ProtocolUnsupported,
    BelowClientFloor,
}

impl ErrorCode {
    /// The class this code belongs to. One place, because a code whose class
    /// differed between two call sites would make the client's branch wrong at
    /// one of them.
    pub fn class(self) -> ErrorClass {
        match self {
            Self::Backpressure | Self::LockTimeout | Self::Failover | Self::PushBackpressure => {
                ErrorClass::Retry
            }
            Self::MalformedHeader
            | Self::NoncanonicalCbor
            | Self::HashMismatch
            | Self::EnvelopeTooLarge
            | Self::UnknownRequiredField
            | Self::PushHandleMalformed => ErrorClass::Reject,
            Self::PlaintextRefused
            | Self::WriterNotInAccessSet
            | Self::GroupUnknown
            | Self::ServiceReadOnly
            | Self::GroupFrozen
            | Self::WrapNotNewer
            | Self::PushNotConfigured => ErrorClass::Denied,
            Self::StorageExhausted
            | Self::LogBudgetExhausted
            | Self::RateLimited
            | Self::SeatsExhausted
            | Self::GroupIngressLimited => ErrorClass::Quota,
            Self::PushRegistrationRate => ErrorClass::Limit,
            Self::ProtocolUnsupported | Self::BelowClientFloor => ErrorClass::Version,
        }
    }

    /// The stable string a client matches on, without its class prefix.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Backpressure => "backpressure",
            Self::LockTimeout => "lock_timeout",
            Self::Failover => "failover",
            Self::PushBackpressure => "push_backpressure",
            Self::MalformedHeader => "malformed_header",
            Self::NoncanonicalCbor => "noncanonical_cbor",
            Self::HashMismatch => "hash_mismatch",
            Self::EnvelopeTooLarge => "envelope_too_large",
            Self::UnknownRequiredField => "unknown_required_field",
            Self::PushHandleMalformed => "push_handle_malformed",
            Self::PlaintextRefused => "plaintext_refused",
            Self::WriterNotInAccessSet => "writer_not_in_access_set",
            Self::GroupUnknown => "group_unknown",
            Self::ServiceReadOnly => "service_read_only",
            Self::GroupFrozen => "group_frozen",
            Self::PushNotConfigured => "push_not_configured",
            Self::WrapNotNewer => "wrap_not_newer",
            Self::StorageExhausted => "storage_exhausted",
            Self::LogBudgetExhausted => "log_budget_exhausted",
            Self::RateLimited => "rate_limited",
            Self::SeatsExhausted => "seats_exhausted",
            Self::GroupIngressLimited => "group_ingress_limited",
            Self::PushRegistrationRate => "push_registration_rate",
            Self::ProtocolUnsupported => "protocol_unsupported",
            Self::BelowClientFloor => "below_client_floor",
        }
    }

    /// `class/code`, the form the registry lists and the client logs.
    pub fn qualified(self) -> String {
        format!("{}/{}", self.class().as_str(), self.as_str())
    }

    /// Every code, so a test can walk the registry rather than remember it.
    pub const ALL: &'static [Self] = &[
        Self::Backpressure,
        Self::LockTimeout,
        Self::Failover,
        Self::PushBackpressure,
        Self::MalformedHeader,
        Self::NoncanonicalCbor,
        Self::HashMismatch,
        Self::EnvelopeTooLarge,
        Self::UnknownRequiredField,
        Self::PushHandleMalformed,
        Self::PlaintextRefused,
        Self::WriterNotInAccessSet,
        Self::GroupUnknown,
        Self::ServiceReadOnly,
        Self::GroupFrozen,
        Self::PushNotConfigured,
        Self::WrapNotNewer,
        Self::StorageExhausted,
        Self::LogBudgetExhausted,
        Self::RateLimited,
        Self::SeatsExhausted,
        Self::GroupIngressLimited,
        Self::PushRegistrationRate,
        Self::ProtocolUnsupported,
        Self::BelowClientFloor,
    ];
}

/// One error, as it goes on the wire.
///
/// `detail` carries the state hash or the limit where the class calls for one:
/// `operations.md` says every error carries the class, a stable code, and where
/// relevant the current state hash so the client can rebase rather than guess. It
/// is never content derived, and the type has no field that could hold content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameError {
    pub code: ErrorCode,
    /// Seconds to wait, for the classes that name an interval.
    pub retry_after: Option<u32>,
    /// A state hash, a limit, or a non-content reason code.
    pub detail: Option<Vec<u8>>,
}

impl FrameError {
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            retry_after: None,
            detail: None,
        }
    }

    pub fn retry_after(mut self, seconds: u32) -> Self {
        self.retry_after = Some(seconds);
        self
    }

    pub fn detail(mut self, detail: impl Into<Vec<u8>>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn class(&self) -> ErrorClass {
        self.code.class()
    }
}

/// The frame tags. Fixed numbers, because the tag is on the wire and renumbering
/// one would silently reinterpret every frame of that kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FrameTag {
    Connect = 1,
    ConnectAck = 2,
    AuthChallenge = 3,
    Auth = 4,
    AuthAck = 5,
    Access = 6,
    Sub = 7,
    SubAck = 8,
    Recon = 9,
    Push = 10,
    Send = 11,
    SendAck = 12,
    Blob = 13,
    Bye = 14,
    Error = 15,
    /// One `recovery.wrap`, client to relay.
    ///
    /// A frame of its own rather than an event kind carried in an envelope, and
    /// the reason is the one thing this whole layer is for: the kind lives inside
    /// `ct`, and under `enc: 1` the relay cannot read `ct`. `wire.md` lists
    /// `recovery.wrap` at `0x0061` and says the relay stores it "under a
    /// per-epoch blinded tag", which is an instruction the relay cannot carry out
    /// on bytes it cannot open. So the record reaches the relay here, where the
    /// tag and the epoch are visible and the sealed payload is not. Recorded in
    /// `specs/backend/relay/wire.md` in the same change.
    Wrap = 16,
    /// One MLS handshake message, either direction.
    ///
    /// A frame rather than an event kind for the same reason `WRAP` is one: the
    /// relay has to index and order these, and under `enc: 1` it cannot read an
    /// envelope's kind. It also cannot be an envelope on its own terms, because an
    /// envelope's `ct` is an encrypted `Payload` and a handshake message is the
    /// object that establishes the key such a payload is encrypted under.
    Handshake = 17,
    /// One step of an invite redemption, either direction.
    ///
    /// The only frame a client may send before it has authenticated, because a
    /// device redeeming an invite has no membership to authenticate with yet: it is
    /// asking for the reservation that lets it authenticate at all
    /// (`specs/backend/relay/invites.md`).
    Join = 18,
    /// One signed `drop_before` instruction, or the relay's answer to one.
    ///
    /// A frame of its own rather than a `BLOB` request, because compaction is
    /// about the envelope log rather than about an object in a bucket: it is the
    /// one instruction that removes text the relay is holding
    /// (`specs/backend/relay/lifecycle.md`). It shares the retention chain with
    /// media and shares nothing else.
    Drop = 19,
    /// One invite administration request, or the relay's answer to one.
    ///
    /// Separate from ``FrameTag::Join`` and deliberately so. `JOIN` is the one frame
    /// a client may send before it has authenticated, because a device redeeming an
    /// invite has no membership yet. Issuing, listing and revoking are the opposite:
    /// authenticated, privileged, and refused outright on a session that has not
    /// completed `AUTH`. Folding them into `JOIN` would have put a privileged
    /// operation on the one path that by construction has no session behind it, which
    /// is a gate nobody would ever be sure was closed.
    ///
    /// `specs/backend/relay/invites.md`, "Admin controls".
    Invite = 20,
    /// One ephemeral beat: presence or typing. Never stored, never sequenced.
    ///
    /// A frame rather than event kind `0x00F0`, which is retired to reserved
    /// forever. Under `enc: 1` the kind lives inside `ct`, so a relay told to drop
    /// one kind and keep every other cannot tell them apart, which is the same hole
    /// `WRAP` and `HANDSHAKE` were pulled out of the envelope to close
    /// (`specs/backend/relay/presence.md`).
    Live = 21,
    /// Publish or fetch MLS key packages.
    ///
    /// A frame rather than a kind because key packages are cleartext by
    /// construction, since they bootstrap encryption, and the relay has to index
    /// them by device key to serve a fetch at all
    /// (`specs/backend/relay/private-messaging.md`).
    Keys = 22,
    /// One call signalling frame: offer, answer, decline or bye.
    ///
    /// A frame rather than an event kind, for the third time and for the reason
    /// `WRAP`, `HANDSHAKE` and `LIVE` are frames: the relay has to act on this,
    /// and under `enc: 1` it cannot read anything inside `ct`. What it acts on is
    /// the cleartext `kind`, which decides call membership, and membership is what
    /// lets `MEDIA` be routed without a database read
    /// (`specs/backend/relay/calls.md`).
    Call = 23,
    /// One encrypted audio frame.
    ///
    /// Separate from ``FrameTag::Call`` and deliberately so. Signalling is rare,
    /// access-set checked and carries a group; media is fifty frames a second,
    /// carries no group at all and is routed on the call the sender was already
    /// admitted to. Folding them into one tag would have put the expensive check
    /// on the cheap path.
    Media = 24,
    /// One push-wake registration, either direction.
    ///
    /// Named `WAKE` and not `PUSH`, and the reason is a reader six months from now
    /// rather than taste: tag 10 has been ``FrameTag::Push``, the relay-to-client
    /// envelope delivery frame, since version 1. Tags are permanent, so the word
    /// `PUSH` is permanently spoken for, and using it a second time for the
    /// unrelated business of waking a sleeping device would be a defect waiting for
    /// somebody to grep.
    ///
    /// The frame carries no device identifier at all. A registration is a statement
    /// about the authenticated principal, and the relay learns which principal from
    /// the session rather than from a field, which is what stops one device
    /// registering a wake capability against another (`specs/backend/relay/push.md`
    /// section 3).
    Wake = 25,
}

impl FrameTag {
    pub fn from_u16(value: u16) -> Option<Self> {
        Some(match value {
            1 => Self::Connect,
            2 => Self::ConnectAck,
            3 => Self::AuthChallenge,
            4 => Self::Auth,
            5 => Self::AuthAck,
            6 => Self::Access,
            7 => Self::Sub,
            8 => Self::SubAck,
            9 => Self::Recon,
            10 => Self::Push,
            11 => Self::Send,
            12 => Self::SendAck,
            13 => Self::Blob,
            14 => Self::Bye,
            15 => Self::Error,
            16 => Self::Wrap,
            17 => Self::Handshake,
            18 => Self::Join,
            19 => Self::Drop,
            20 => Self::Invite,
            21 => Self::Live,
            22 => Self::Keys,
            23 => Self::Call,
            24 => Self::Media,
            25 => Self::Wake,
            _ => return None,
        })
    }

    pub const ALL: &'static [Self] = &[
        Self::Connect,
        Self::ConnectAck,
        Self::AuthChallenge,
        Self::Auth,
        Self::AuthAck,
        Self::Access,
        Self::Sub,
        Self::SubAck,
        Self::Recon,
        Self::Push,
        Self::Send,
        Self::SendAck,
        Self::Blob,
        Self::Bye,
        Self::Error,
        Self::Wrap,
        Self::Handshake,
        Self::Join,
        Self::Drop,
        Self::Invite,
        Self::Live,
        Self::Keys,
        Self::Call,
        Self::Media,
        Self::Wake,
    ];
}

/// The largest frame the relay will read.
///
/// One MiB of `ct` plus the envelope header plus frame framing. Sized from the
/// envelope ceiling rather than chosen: a bound smaller than a legal envelope
/// would reject writes the rest of the system considers valid, and a much larger
/// one would let an attacker make the relay allocate before it has checked
/// anything.
pub const MAX_FRAME_BYTES: usize = (1 << 20) + 4096;

/// The largest `WAKE` frame the relay will read.
///
/// One kibibyte, which `specs/backend/relay/push.md` section 3 fixes. Every field
/// is fixed and small: sixteen bytes of handle, one byte of mask, two integers and
/// a url bounded at 512 bytes. A frame near this bound is already implausible and a
/// frame over it is a peer spending the relay's read budget on a question whose
/// answer cannot depend on the bytes past here.
pub const MAX_WAKE_BYTES: usize = 1024;

/// Why a frame could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameDecodeError {
    #[error("frame is {0} bytes, over the {MAX_FRAME_BYTES} byte limit")]
    TooLarge(usize),
    #[error("frame is not canonical CBOR: {0}")]
    Cbor(#[from] CborError),
    #[error("frame tag {0} is not one this version speaks")]
    UnknownTag(u16),
    #[error("frame carries protocol version {0}, this build speaks {PROTOCOL_VERSION}")]
    UnsupportedVersion(u16),
    #[error("frame field {field} is not what the frame set says it is")]
    BadField { field: &'static str },
    /// A `WAKE` field that is wrong in a way the push registry has its own code
    /// for. Separate from ``BadField`` so the client is told
    /// `reject/push_handle_malformed` and knows the registration was refused, rather
    /// than `reject/malformed_header`, which reads as a framing bug and would send a
    /// client looking at its encoder. The field name is `&'static str` and never the
    /// value: a variant carrying the handle would put it in every error message.
    #[error("WAKE field {field} is not what the frame set says it is")]
    BadWakeField { field: &'static str },
    /// A `WAKE` frame over its own kilobyte ceiling, which is far below
    /// ``MAX_FRAME_BYTES``. Its own variant because its own bound: every field is
    /// fixed and small, so a large one is not a big registration but a peer making
    /// the relay read a megabyte to answer a sixteen byte question. Answered with the
    /// code every other over-size frame is answered with, because that is what it is.
    #[error("WAKE frame is {0} bytes, over the {MAX_WAKE_BYTES} byte limit")]
    TooLargeWake(usize),
}

impl FrameDecodeError {
    /// The code this failure is answered with. Every decode failure has one,
    /// because a client that gets a closed socket and no frame cannot tell a
    /// protocol error from a network one.
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::TooLarge(_) => ErrorCode::EnvelopeTooLarge,
            Self::Cbor(_) => ErrorCode::NoncanonicalCbor,
            Self::UnknownTag(_) | Self::BadField { .. } => ErrorCode::MalformedHeader,
            Self::BadWakeField { .. } => ErrorCode::PushHandleMalformed,
            Self::TooLargeWake(_) => ErrorCode::EnvelopeTooLarge,
            Self::UnsupportedVersion(_) => ErrorCode::ProtocolUnsupported,
        }
    }
}

/// Split a `WAKE` codec failure into "the wrong shape" and "not canonical".
///
/// Every other frame answers both with `reject/noncanonical_cbor`, through
/// ``FrameDecodeError::code``, and that is a shared mapping across twenty five tags
/// which this change is not going to move. `WAKE` is the first frame with a
/// hand-computed vector corpus that distinguishes the two
/// (`specs/backend/contracts/wire/vectors/push-frames.json`), and the distinction is
/// worth having where it exists: a map where an array belongs is a peer that
/// disagrees about the frame's shape, which is `malformed_header`, while an
/// indefinite length or a non-shortest integer is a peer whose encoder is not
/// deterministic, which is `noncanonical_cbor` and names the rule it broke.
fn wake_shape(error: CborError, field: &'static str) -> FrameDecodeError {
    match error {
        // The canonicity rules, which are about the encoding rather than the frame.
        CborError::NonCanonicalInteger
        | CborError::ReservedAdditionalInfo(_)
        | CborError::TrailingBytes(_) => FrameDecodeError::Cbor(error),
        // Everything else is a field that is not what the frame set says it is.
        _ => FrameDecodeError::BadField { field },
    }
}

/// A frame, in the shapes this step needs.
///
/// `BLOB` and `RECON` are named in the tag set and carried through the codec as
/// opaque payloads: their contents are `specs/backend/relay/media.md` and the
/// negentropy round trip, which arrive in steps 9 and 5. A tag that existed with
/// no wire shape would be a frame a peer could send that this build could not
/// even name back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Client hello: the version it speaks and the groups it wants.
    Connect {
        version: u16,
        /// Group ids the client intends to subscribe to. Advisory: the relay
        /// serves any group in the workspace to any device in the access set.
        groups: Vec<Vec<u8>>,
        /// The client's own clock in milliseconds, so skew is detected at the
        /// start rather than discovered on the first `SEND`.
        sent_at: u64,
    },
    ConnectAck {
        version: u16,
        /// The relay's own clock, for the same reason.
        server_time: u64,
        /// What the relay will accept. A client that would be refused learns it
        /// here rather than on its first write.
        min_enc: u8,
    },
    /// Relay to client: bytes to sign.
    AuthChallenge {
        challenge: Vec<u8>,
    },
    /// Client to relay: the device key and its signature over the challenge.
    Auth {
        device_key: Vec<u8>,
        signature: Vec<u8>,
    },
    AuthAck {
        /// Unused key packages this device has left, so a client tops up before
        /// it runs out rather than after.
        key_packages_remaining: u32,
        /// Whether durable writes are being accepted right now.
        write_mode: u8,
        /// What build this relay is running
        /// (`specs/backend/relay/verification.md` proof 1). UTF-8, either
        /// `sha256:<hex>` for a published image or `exe-blake3:<hex>` for a
        /// binary that hashed itself. See `crate::RunningDigest`.
        ///
        /// On this frame and not on `CONNECT_ACK` on purpose. `health.rs`
        /// explains why the public listener says nothing beyond liveness: a
        /// passer-by learning whether a relay is behind a security release, or
        /// running with access-set enforcement off, is a gift to somebody
        /// choosing a target. After AUTH the peer is an admitted device of this
        /// workspace, and telling that device is the entire point of the
        /// encryption panel.
        build_digest: Vec<u8>,
        /// `1` when the access set is enforced, `0` when it is off. A relay
        /// running `off` is materially weaker and the customer should not have
        /// to read their operator's environment file to find out.
        access_set: u8,
        /// `1` when the relay refuses plaintext envelopes, `0` when it accepts
        /// them.
        min_enc: u8,
    },
    /// A signed access-set rotation, accepted transactionally.
    Access {
        body: Vec<u8>,
    },
    Sub {
        group: Vec<u8>,
        /// Where to start. A cursor only.
        from_seq: u64,
    },
    SubAck {
        group: Vec<u8>,
        head_seq: u64,
    },
    Recon {
        group: Vec<u8>,
        payload: Vec<u8>,
    },
    /// One envelope, relay to client.
    Push {
        envelope: Vec<u8>,
    },
    /// One envelope, client to relay.
    Send {
        envelope: Vec<u8>,
    },
    /// The assigned sequence number, or the existing one for a duplicate.
    SendAck {
        hash: Vec<u8>,
        seq: u64,
    },
    Blob {
        payload: Vec<u8>,
    },
    /// One `drop_before` instruction (`lifecycle::wire::DropBefore`) client to
    /// relay, and the relay's `lifecycle::wire::Response` coming back.
    Drop {
        payload: Vec<u8>,
    },
    Bye {
        reason: Vec<u8>,
    },
    Error(FrameError),
    /// One recovery wrap, encoded as `recovery::RecoveryWrap`.
    ///
    /// Client to relay when it carries a body, relay to client as the
    /// acknowledgement, which echoes the tag that was stored. Same shape as
    /// `Access` and for the same reason: a control record the relay validates and
    /// indexes, answered with enough for the publisher to know which slot moved.
    Wrap {
        body: Vec<u8>,
    },
    /// One MLS handshake message for a group.
    ///
    /// Client to relay to publish it; relay to client to acknowledge it and to
    /// deliver somebody else's. `seq` is the relay-assigned position in the group's
    /// handshake order, zero and ignored on the way in. Unlike an envelope's `seq`
    /// this one is load-bearing: a commit for epoch N+1 applied before the commit
    /// for epoch N cannot be processed at all, so the order is the product.
    Handshake {
        group: Vec<u8>,
        seq: u64,
        message: Vec<u8>,
    },
    /// One redemption step, encoded as `invite::redeem::Request` on the way in and
    /// `invite::redeem::Response` on the way back.
    ///
    /// One frame rather than three, because the three steps are one conversation and
    /// a client that could reach step two without step one is a client that reached
    /// it without a code.
    Join {
        body: Vec<u8>,
    },
    /// One invite administration request or answer, encoded as
    /// `invite::admin::Request` on the way in and `invite::admin::Response` on the way
    /// back.
    Invite {
        body: Vec<u8>,
    },
    /// One ephemeral beat for a group, the same shape in both directions.
    ///
    /// `ct` is a sealed ``LiveBody``: a signed presence or typing claim, opaque to
    /// the relay exactly like an envelope's payload. Nothing about it is durable.
    /// It is never given a sequence number, never stored, never returned by a
    /// `RECON` round, never attested and never named in a `drop_before` manifest.
    Live {
        group: Vec<u8>,
        epoch: u64,
        ct: Vec<u8>,
    },
    /// One key-package publication or fetch, or the relay's answer to one.
    ///
    /// Five forms in one frame, discriminated by the leading `form` byte, because
    /// they are one conversation about one shelf and a client that could reach a
    /// fetch without the publish half is a client with a different frame set.
    Keys(KeysBody),
    /// One call signalling frame, the same shape in both directions.
    ///
    /// `kind` is the only field of either call frame the relay reads beside the
    /// routing ids: a small closed enum (``crate::calls::CallKind``) that decides
    /// whether the sender is joining or leaving. `body` is sealed under the
    /// group's MLS exporter and is opaque exactly like an envelope's payload.
    /// Nothing about it is durable: no sequence number, no row, no `RECON`, no
    /// attestation, no `drop_before` manifest entry.
    Call {
        call_id: Vec<u8>,
        group: Vec<u8>,
        epoch: u64,
        kind: u8,
        body: Vec<u8>,
    },
    /// One encrypted audio frame, the same shape in both directions.
    ///
    /// No group, deliberately. The group was checked when this connection was
    /// admitted to `call_id` by a `CALL` frame, and repeating the check here would
    /// put a Postgres read on a path that carries fifty frames a second per
    /// stream (`specs/peer-calls.md` section 3).
    ///
    /// `seq` is the sender's own per-stream counter, copied and never
    /// interpreted. It is emphatically **not** the per-group `seq` in
    /// `accept.rs`: that one is an `UPDATE ... RETURNING` inside a transaction,
    /// and routing audio through it would serialise every writer in the group
    /// behind the call. Out of order is reordered by the receiver's jitter
    /// buffer, late is dropped, missing is concealed.
    Media {
        call_id: Vec<u8>,
        stream: Vec<u8>,
        seq: u64,
        ct: Vec<u8>,
    },
    /// One push-wake conversation, in either direction.
    ///
    /// Six forms in one frame, the shape `KEYS` already uses, because they are one
    /// conversation about one row: a client that could clear a registration it had no
    /// way to make would be a client with a different frame set
    /// (`specs/backend/relay/push.md` section 3).
    Wake(WakeBody),
}

/// The `WAKE` forms. `specs/backend/relay/push.md`.
///
/// No `Debug` derive that could print a handle: see the hand-written implementation
/// below. The handle is the one field in this crate that is a capability to reach a
/// human's device, and the negative proof the gate runs is that it never reaches a
/// log line at any level, including inside an error.
#[derive(Clone, PartialEq, Eq)]
pub enum WakeBody {
    /// Client to relay: store this against me, in this workspace.
    Register {
        /// Sixteen random bytes the ringer minted to this device. Opaque here and
        /// never derived from anything the relay holds.
        handle: Vec<u8>,
        /// The bitmask from ``crate::push::Category``. At least one bit, no bit
        /// above 4.
        categories: u8,
        /// The ringer's stated expiry, in milliseconds since the epoch.
        expires_at: u64,
    },
    /// Relay to client: stored, and this is when the relay will forget it.
    Registered { expires_at: u64 },
    /// Client to relay: forget my registration in this workspace.
    Clear,
    /// Relay to client: forgotten. A `Clear` with no row is also this, because the
    /// client's desired state has been reached either way and a distinguishable
    /// answer would tell a caller whether a row existed.
    Cleared,
    /// Client to relay: where do I register, if anywhere?
    Query,
    /// Relay to client: push is on or off here, and this is the ringer.
    ///
    /// The form that makes a self-hosted deployment work with a shipped client and
    /// no client-side configuration. The device must not guess a ringer, because
    /// guessing ours would mean a self-hoster's users registering with a party their
    /// operator did not choose, so the relay states it.
    Capability { enabled: bool, register_url: String },
}

impl WakeBody {
    /// The leading discriminant on the wire. Fixed numbers for the same reason a
    /// frame tag is fixed.
    pub fn form(&self) -> u8 {
        match self {
            Self::Register { .. } => 1,
            Self::Registered { .. } => 2,
            Self::Clear => 3,
            Self::Cleared => 4,
            Self::Query => 5,
            Self::Capability { .. } => 6,
        }
    }

    /// What holding this body costs, in bytes, for the queue budget.
    ///
    /// Every form is small and fixed except the url, which is bounded by
    /// ``MAX_REGISTER_URL_BYTES``. Counted anyway, for the reason ``KeysBody``
    /// counts its packages: the allowance in ``Frame::queued_bytes`` is a fixed
    /// header estimate, and a field that can be half a kilobyte is not a header.
    pub fn queued_bytes(&self) -> usize {
        match self {
            Self::Register { handle, .. } => handle.len(),
            Self::Capability { register_url, .. } => register_url.len(),
            Self::Registered { .. } | Self::Clear | Self::Cleared | Self::Query => 0,
        }
    }
}

/// Hand written, so a handle cannot reach a log through a derived `Debug`.
///
/// `specs/backend/relay/push.md` section 2 makes three absences load-bearing and
/// this is the mechanism behind the first of them. A derived implementation would
/// print the bytes anywhere a frame is formatted, including inside a panic message
/// or a `tracing` field, and "nobody formats a frame" is a rule a reviewer enforces
/// rather than the compiler. The form is printed because the form is not a secret
/// and an operator debugging a registration needs to know which one arrived.
impl std::fmt::Debug for WakeBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Register { .. } => "Register",
            Self::Registered { .. } => "Registered",
            Self::Clear => "Clear",
            Self::Cleared => "Cleared",
            Self::Query => "Query",
            Self::Capability { .. } => "Capability",
        };
        write!(f, "WakeBody::{name}({})", crate::logging::REDACTED)
    }
}

/// The `KEYS` forms. `specs/backend/relay/private-messaging.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysBody {
    /// Client to relay: store these against the authenticated device key.
    Publish { packages: Vec<Vec<u8>> },
    /// Relay to client: how many are on the shelf now.
    Published { remaining: u32 },
    /// Client to relay: hand me at most `count` packages for this device.
    Fetch { device: Vec<u8>, count: u8 },
    /// Relay to client: here they are, and they are gone from the shelf.
    Bundles { packages: Vec<Vec<u8>> },
    /// Relay to client: the shelf is empty. Not an error. The correct client
    /// behaviour is to wait for the peer to top up rather than to retry.
    None,
}

impl KeysBody {
    /// The leading discriminant on the wire. Fixed numbers for the same reason a
    /// frame tag is fixed.
    pub fn form(&self) -> u8 {
        match self {
            Self::Publish { .. } => 1,
            Self::Published { .. } => 2,
            Self::Fetch { .. } => 3,
            Self::Bundles { .. } => 4,
            Self::None => 5,
        }
    }

    /// What holding this body costs, in bytes, for the queue budget.
    pub fn queued_bytes(&self) -> usize {
        match self {
            Self::Publish { packages } | Self::Bundles { packages } => {
                packages.iter().map(Vec::len).sum()
            }
            Self::Published { .. } | Self::Fetch { .. } | Self::None => 0,
        }
    }
}

impl Frame {
    pub fn tag(&self) -> FrameTag {
        match self {
            Self::Connect { .. } => FrameTag::Connect,
            Self::ConnectAck { .. } => FrameTag::ConnectAck,
            Self::AuthChallenge { .. } => FrameTag::AuthChallenge,
            Self::Auth { .. } => FrameTag::Auth,
            Self::AuthAck { .. } => FrameTag::AuthAck,
            Self::Access { .. } => FrameTag::Access,
            Self::Wrap { .. } => FrameTag::Wrap,
            Self::Handshake { .. } => FrameTag::Handshake,
            Self::Join { .. } => FrameTag::Join,
            Self::Invite { .. } => FrameTag::Invite,
            Self::Sub { .. } => FrameTag::Sub,
            Self::SubAck { .. } => FrameTag::SubAck,
            Self::Recon { .. } => FrameTag::Recon,
            Self::Push { .. } => FrameTag::Push,
            Self::Send { .. } => FrameTag::Send,
            Self::SendAck { .. } => FrameTag::SendAck,
            Self::Blob { .. } => FrameTag::Blob,
            Self::Drop { .. } => FrameTag::Drop,
            Self::Bye { .. } => FrameTag::Bye,
            Self::Live { .. } => FrameTag::Live,
            Self::Keys(_) => FrameTag::Keys,
            Self::Call { .. } => FrameTag::Call,
            Self::Media { .. } => FrameTag::Media,
            Self::Wake(_) => FrameTag::Wake,
            Self::Error(_) => FrameTag::Error,
        }
    }

    /// What holding this frame in a send queue costs, in bytes.
    ///
    /// The variable-length payload plus a fixed allowance for the header and the
    /// small fields, which is what the queue's byte budget is accounted in
    /// (`ws::SEND_QUEUE_BYTE_BUDGET`). Deliberately not `encode().len()`: the writer
    /// encodes the frame when it sends it, and encoding every frame a second time to
    /// measure it would put the cost being bounded back into the accounting.
    ///
    /// An estimate is enough because the budget is a resource limit rather than a
    /// protocol field. Nothing on the wire depends on it, and the frames that can
    /// actually exhaust it (`Push`, `Handshake`, `Blob`, `Send`) are dominated by one
    /// payload each, so the estimate is within a few dozen bytes of the truth exactly
    /// where being right matters.
    pub fn queued_bytes(&self) -> usize {
        /// Tag, array headers, and the handful of integers and 32-byte ids a frame
        /// carries beside its payload. Generous on purpose: over-counting spends
        /// budget, under-counting spends memory.
        const OVERHEAD: usize = 256;

        let payload = match self {
            Self::Push { envelope } => envelope.len(),
            Self::Send { envelope } => envelope.len(),
            Self::Handshake { message, .. } => message.len(),
            Self::Recon { payload, .. } => payload.len(),
            Self::Access { body }
            | Self::Wrap { body }
            | Self::Join { body }
            | Self::Invite { body } => body.len(),
            Self::Blob { payload } => payload.len(),
            Self::Connect { groups, .. } => groups.iter().map(Vec::len).sum(),
            Self::Live { ct, .. } => ct.len(),
            Self::Call { body, .. } => body.len(),
            Self::Media { ct, .. } => ct.len(),
            Self::Keys(body) => body.queued_bytes(),
            Self::Wake(body) => body.queued_bytes(),
            // Everything else is headers and integers, covered by the allowance.
            _ => 0,
        };
        payload + OVERHEAD
    }

    /// Deterministic CBOR: `[tag, [fields...]]`.
    pub fn encode(&self) -> Vec<u8> {
        let body = match self {
            Self::Connect {
                version,
                groups,
                sent_at,
            } => cbor::array(&[
                cbor::uint(u64::from(*version)),
                cbor::array(&groups.iter().map(|g| cbor::bytes(g)).collect::<Vec<_>>()),
                cbor::uint(*sent_at),
            ]),
            Self::ConnectAck {
                version,
                server_time,
                min_enc,
            } => cbor::array(&[
                cbor::uint(u64::from(*version)),
                cbor::uint(*server_time),
                cbor::uint(u64::from(*min_enc)),
            ]),
            Self::AuthChallenge { challenge } => cbor::array(&[cbor::bytes(challenge)]),
            Self::Auth {
                device_key,
                signature,
            } => cbor::array(&[cbor::bytes(device_key), cbor::bytes(signature)]),
            Self::AuthAck {
                key_packages_remaining,
                write_mode,
                build_digest,
                access_set,
                min_enc,
            } => cbor::array(&[
                cbor::uint(u64::from(*key_packages_remaining)),
                cbor::uint(u64::from(*write_mode)),
                cbor::bytes(build_digest),
                cbor::uint(u64::from(*access_set)),
                cbor::uint(u64::from(*min_enc)),
            ]),
            Self::Access { body } => cbor::array(&[cbor::bytes(body)]),
            Self::Wrap { body } => cbor::array(&[cbor::bytes(body)]),
            Self::Handshake {
                group,
                seq,
                message,
            } => cbor::array(&[cbor::bytes(group), cbor::uint(*seq), cbor::bytes(message)]),
            Self::Join { body } => cbor::array(&[cbor::bytes(body)]),
            Self::Invite { body } => cbor::array(&[cbor::bytes(body)]),
            Self::Sub { group, from_seq } => {
                cbor::array(&[cbor::bytes(group), cbor::uint(*from_seq)])
            }
            Self::SubAck { group, head_seq } => {
                cbor::array(&[cbor::bytes(group), cbor::uint(*head_seq)])
            }
            Self::Recon { group, payload } => {
                cbor::array(&[cbor::bytes(group), cbor::bytes(payload)])
            }
            Self::Push { envelope } => cbor::array(&[cbor::bytes(envelope)]),
            Self::Send { envelope } => cbor::array(&[cbor::bytes(envelope)]),
            Self::SendAck { hash, seq } => cbor::array(&[cbor::bytes(hash), cbor::uint(*seq)]),
            Self::Blob { payload } => cbor::array(&[cbor::bytes(payload)]),
            Self::Drop { payload } => cbor::array(&[cbor::bytes(payload)]),
            Self::Bye { reason } => cbor::array(&[cbor::bytes(reason)]),
            Self::Live { group, epoch, ct } => {
                cbor::array(&[cbor::bytes(group), cbor::uint(*epoch), cbor::bytes(ct)])
            }
            Self::Call {
                call_id,
                group,
                epoch,
                kind,
                body,
            } => cbor::array(&[
                cbor::bytes(call_id),
                cbor::bytes(group),
                cbor::uint(*epoch),
                cbor::uint(u64::from(*kind)),
                cbor::bytes(body),
            ]),
            Self::Media {
                call_id,
                stream,
                seq,
                ct,
            } => cbor::array(&[
                cbor::bytes(call_id),
                cbor::bytes(stream),
                cbor::uint(*seq),
                cbor::bytes(ct),
            ]),
            Self::Keys(body) => {
                let fields = match body {
                    KeysBody::Publish { packages } | KeysBody::Bundles { packages } => {
                        cbor::array(&packages.iter().map(|p| cbor::bytes(p)).collect::<Vec<_>>())
                    }
                    KeysBody::Published { remaining } => {
                        cbor::array(&[cbor::uint(u64::from(*remaining))])
                    }
                    KeysBody::Fetch { device, count } => {
                        cbor::array(&[cbor::bytes(device), cbor::uint(u64::from(*count))])
                    }
                    KeysBody::None => cbor::array(&[]),
                };
                cbor::array(&[cbor::uint(u64::from(body.form())), fields])
            }
            Self::Wake(body) => {
                let fields = match body {
                    WakeBody::Register {
                        handle,
                        categories,
                        expires_at,
                    } => cbor::array(&[
                        cbor::bytes(handle),
                        cbor::uint(u64::from(*categories)),
                        cbor::uint(*expires_at),
                    ]),
                    WakeBody::Registered { expires_at } => cbor::array(&[cbor::uint(*expires_at)]),
                    WakeBody::Clear | WakeBody::Cleared | WakeBody::Query => cbor::array(&[]),
                    WakeBody::Capability {
                        enabled,
                        register_url,
                    } => cbor::array(&[cbor::boolean(*enabled), cbor::text(register_url)]),
                };
                cbor::array(&[cbor::uint(u64::from(body.form())), fields])
            }
            Self::Error(error) => cbor::array(&[
                cbor::bytes(error.code.class().as_str().as_bytes()),
                cbor::bytes(error.code.as_str().as_bytes()),
                cbor::uint(u64::from(error.retry_after.unwrap_or(0))),
                cbor::bytes(error.detail.as_deref().unwrap_or_default()),
            ]),
        };
        cbor::array(&[cbor::uint(u64::from(self.tag() as u16)), body])
    }

    /// Read a frame, or say precisely why not.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameDecodeError> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(FrameDecodeError::TooLarge(bytes.len()));
        }
        let mut reader = Reader::new(bytes);
        reader.array(2)?;
        let raw_tag = reader.uint()?;
        let tag = u16::try_from(raw_tag)
            .ok()
            .and_then(FrameTag::from_u16)
            .ok_or(FrameDecodeError::UnknownTag(
                u16::try_from(raw_tag).unwrap_or(u16::MAX),
            ))?;

        let frame = match tag {
            FrameTag::Connect => {
                reader.array(3)?;
                let version = reader.u16()?;
                // A floor and no ceiling. The field is the client's maximum offer,
                // not an assertion about this build, so a client that speaks more
                // than this relay does has to reach the session to be clamped and
                // told what it got: `Session::handle` owns that rule and is the one
                // place it is stated. Refusing the offer here instead made the
                // clamp unreachable and hard-broke every future client release
                // against every deployed relay, which is the failure one-field
                // negotiation exists to prevent. Below the floor is different: that
                // is a client this build genuinely cannot serve.
                if version < MIN_PROTOCOL_VERSION {
                    return Err(FrameDecodeError::UnsupportedVersion(version));
                }
                let count = reader.array_header()?;
                let mut groups = Vec::new();
                for _ in 0..count {
                    groups.push(reader.bytes_of(32)?);
                }
                Self::Connect {
                    version,
                    groups,
                    sent_at: reader.uint()?,
                }
            }
            FrameTag::ConnectAck => {
                reader.array(3)?;
                let version = reader.u16()?;
                // Admits a selection below the local maximum on purpose: that is
                // exactly a version 2 client learning it is talking to a version 1
                // relay, which it reports as presence unavailable rather than
                // treating as a failure.
                if !(MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&version) {
                    return Err(FrameDecodeError::UnsupportedVersion(version));
                }
                Self::ConnectAck {
                    version,
                    server_time: reader.uint()?,
                    min_enc: reader.u8()?,
                }
            }
            FrameTag::AuthChallenge => {
                reader.array(1)?;
                Self::AuthChallenge {
                    challenge: reader.bytes()?,
                }
            }
            FrameTag::Auth => {
                reader.array(2)?;
                Self::Auth {
                    device_key: reader.bytes_of(32)?,
                    signature: reader.bytes_of(64)?,
                }
            }
            FrameTag::AuthAck => {
                reader.array(5)?;
                Self::AuthAck {
                    key_packages_remaining: reader.u32()?,
                    write_mode: reader.u8()?,
                    build_digest: reader.bytes()?,
                    access_set: reader.u8()?,
                    min_enc: reader.u8()?,
                }
            }
            FrameTag::Access => {
                reader.array(1)?;
                Self::Access {
                    body: reader.bytes()?,
                }
            }
            FrameTag::Wrap => {
                reader.array(1)?;
                Self::Wrap {
                    body: reader.bytes()?,
                }
            }
            FrameTag::Join => {
                reader.array(1)?;
                Self::Join {
                    body: reader.bytes()?,
                }
            }
            FrameTag::Invite => {
                reader.array(1)?;
                Self::Invite {
                    body: reader.bytes()?,
                }
            }
            FrameTag::Handshake => {
                reader.array(3)?;
                Self::Handshake {
                    group: reader.bytes_of(32)?,
                    seq: reader.uint()?,
                    message: reader.bytes()?,
                }
            }
            FrameTag::Sub => {
                reader.array(2)?;
                Self::Sub {
                    group: reader.bytes_of(32)?,
                    from_seq: reader.uint()?,
                }
            }
            FrameTag::SubAck => {
                reader.array(2)?;
                Self::SubAck {
                    group: reader.bytes_of(32)?,
                    head_seq: reader.uint()?,
                }
            }
            FrameTag::Recon => {
                reader.array(2)?;
                Self::Recon {
                    group: reader.bytes_of(32)?,
                    payload: reader.bytes()?,
                }
            }
            FrameTag::Push => {
                reader.array(1)?;
                Self::Push {
                    envelope: reader.bytes()?,
                }
            }
            FrameTag::Send => {
                reader.array(1)?;
                Self::Send {
                    envelope: reader.bytes()?,
                }
            }
            FrameTag::SendAck => {
                reader.array(2)?;
                Self::SendAck {
                    hash: reader.bytes_of(32)?,
                    seq: reader.uint()?,
                }
            }
            FrameTag::Blob => {
                reader.array(1)?;
                Self::Blob {
                    payload: reader.bytes()?,
                }
            }
            FrameTag::Drop => {
                reader.array(1)?;
                Self::Drop {
                    payload: reader.bytes()?,
                }
            }
            FrameTag::Bye => {
                reader.array(1)?;
                Self::Bye {
                    reason: reader.bytes()?,
                }
            }
            FrameTag::Live => {
                reader.array(3)?;
                Self::Live {
                    group: reader.bytes_of(32)?,
                    epoch: reader.uint()?,
                    ct: reader.bytes()?,
                }
            }
            FrameTag::Call => {
                reader.array(5)?;
                Self::Call {
                    call_id: reader.bytes_of(crate::calls::CALL_ID_BYTES)?,
                    group: reader.bytes_of(32)?,
                    epoch: reader.uint()?,
                    kind: reader.u8()?,
                    body: reader.bytes()?,
                }
            }
            FrameTag::Media => {
                reader.array(4)?;
                Self::Media {
                    call_id: reader.bytes_of(crate::calls::CALL_ID_BYTES)?,
                    stream: reader.bytes_of(crate::calls::STREAM_BYTES)?,
                    seq: reader.uint()?,
                    ct: reader.bytes()?,
                }
            }
            FrameTag::Keys => {
                reader.array(2)?;
                let form = reader.u8()?;
                let body = match form {
                    1 | 4 => {
                        let count = reader.array_header()?;
                        let mut packages = Vec::new();
                        for _ in 0..count {
                            packages.push(reader.bytes()?);
                        }
                        if form == 1 {
                            KeysBody::Publish { packages }
                        } else {
                            KeysBody::Bundles { packages }
                        }
                    }
                    2 => {
                        reader.array(1)?;
                        KeysBody::Published {
                            remaining: reader.u32()?,
                        }
                    }
                    3 => {
                        reader.array(2)?;
                        KeysBody::Fetch {
                            device: reader.bytes_of(32)?,
                            count: reader.u8()?,
                        }
                    }
                    5 => {
                        reader.array(0)?;
                        KeysBody::None
                    }
                    _ => return Err(FrameDecodeError::BadField { field: "form" }),
                };
                Self::Keys(body)
            }
            FrameTag::Wake => {
                if bytes.len() > MAX_WAKE_BYTES {
                    return Err(FrameDecodeError::TooLargeWake(bytes.len()));
                }
                reader.array(2).map_err(|e| wake_shape(e, "wake"))?;
                let form = reader.u8().map_err(|e| wake_shape(e, "form"))?;
                let body = match form {
                    1 => {
                        reader.array(3).map_err(|e| wake_shape(e, "register"))?;
                        // Read as a variable-length byte string and measured here,
                        // rather than as a fixed sixteen through `bytes_of`. The
                        // difference is the code the client is told: a wrong-length
                        // handle is `reject/push_handle_malformed`, which names the
                        // field that was wrong, where the codec's own length refusal
                        // would surface as a framing complaint and send a client
                        // looking at its encoder.
                        let handle = reader.bytes().map_err(|e| wake_shape(e, "handle"))?;
                        if handle.len() != crate::push::HANDLE_BYTES {
                            return Err(FrameDecodeError::BadWakeField { field: "handle" });
                        }
                        let categories = reader.u8().map_err(|e| wake_shape(e, "categories"))?;
                        if !crate::push::is_valid_mask(categories) {
                            return Err(FrameDecodeError::BadWakeField {
                                field: "categories",
                            });
                        }
                        WakeBody::Register {
                            handle,
                            categories,
                            expires_at: reader.uint().map_err(|e| wake_shape(e, "expires_at"))?,
                        }
                    }
                    2 => {
                        reader.array(1).map_err(|e| wake_shape(e, "registered"))?;
                        WakeBody::Registered {
                            expires_at: reader.uint().map_err(|e| wake_shape(e, "expires_at"))?,
                        }
                    }
                    3..=5 => {
                        reader.array(0).map_err(|e| wake_shape(e, "fields"))?;
                        match form {
                            3 => WakeBody::Clear,
                            4 => WakeBody::Cleared,
                            // The remaining arm, and the only one left: the outer
                            // match admits exactly these three numbers here.
                            _ => WakeBody::Query,
                        }
                    }
                    6 => {
                        reader.array(2).map_err(|e| wake_shape(e, "capability"))?;
                        let enabled = reader.boolean().map_err(|e| wake_shape(e, "enabled"))?;
                        let register_url =
                            reader.text().map_err(|e| wake_shape(e, "register_url"))?;
                        // Length in bytes and not in characters, because the bound is
                        // on the wire rather than on the display: `tstr .size (0..512)`
                        // is a byte count, and a client refusing at 512 characters
                        // would refuse a url this relay considers legal. The scheme is
                        // checked by the same rule the configuration applies, so a url
                        // a client would refuse is one this codec refuses too rather
                        // than one the relay states and the device silently ignores.
                        if register_url.len() > crate::push::MAX_REGISTER_URL_BYTES
                            || !crate::push::is_acceptable_register_url(&register_url)
                        {
                            return Err(FrameDecodeError::BadWakeField {
                                field: "register_url",
                            });
                        }
                        WakeBody::Capability {
                            enabled,
                            register_url,
                        }
                    }
                    // Not one of the six. `BadField` and not `BadWakeField`, because
                    // this is a peer that disagrees about the frame set rather than
                    // one whose registration is wrong, which is the same answer
                    // `KEYS` gives an unknown form of its own.
                    _ => return Err(FrameDecodeError::BadField { field: "form" }),
                };
                Self::Wake(body)
            }
            FrameTag::Error => {
                reader.array(4)?;
                let class = reader.bytes()?;
                let code = reader.bytes()?;
                let retry_after = reader.u32()?;
                let detail = reader.bytes()?;
                let code = ErrorCode::ALL
                    .iter()
                    .copied()
                    .find(|candidate| {
                        candidate.as_str().as_bytes() == code.as_slice()
                            && candidate.class().as_str().as_bytes() == class.as_slice()
                    })
                    .ok_or(FrameDecodeError::BadField { field: "code" })?;
                Self::Error(FrameError {
                    code,
                    retry_after: (retry_after > 0).then_some(retry_after),
                    detail: (!detail.is_empty()).then_some(detail),
                })
            }
        };
        reader.finish()?;
        Ok(frame)
    }
}
