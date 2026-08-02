// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The frame set, and the one error taxonomy every frame uses.
//!
//! `specs/backend/relay/wire.md` names the frames and
//! `specs/backend/relay/operations.md` names the five error classes. Both are
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

/// The protocol version this build speaks.
///
/// One value. A client that offers something else is answered with
/// `version/protocol_unsupported` carrying this range, and the connection ends:
/// `operations.md` says a version failure aborts the connection and never
/// silently continues.
pub const PROTOCOL_VERSION: u16 = 1;

/// The five classes from `operations.md`. Not extensible without a protocol
/// version bump, which is why this is an enum and not a string.
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
}

impl ErrorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Retry => "retry",
            Self::Reject => "reject",
            Self::Denied => "denied",
            Self::Quota => "quota",
            Self::Version => "version",
        }
    }

    /// Whether a client should send the same bytes again after a wait.
    ///
    /// Only `retry` and `quota`, and they are different waits: `retry` is
    /// backoff with jitter, `quota` is the interval the error names. `denied` is
    /// deliberately not retryable, because retrying blind against a state that
    /// changed is how a client hammers a relay that has already told it no.
    pub fn is_retryable(self) -> bool {
        matches!(self, Self::Retry | Self::Quota)
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
    // reject
    MalformedHeader,
    NoncanonicalCbor,
    HashMismatch,
    EnvelopeTooLarge,
    UnknownRequiredField,
    // denied
    PlaintextRefused,
    WriterNotInAccessSet,
    GroupUnknown,
    ServiceReadOnly,
    GroupFrozen,
    /// A recovery wrap that does not advance its slot's epoch. Denied rather
    /// than rejected: the bytes are well formed and would have been accepted one
    /// epoch ago, which is exactly the replay the monotonicity rule refuses
    /// (`specs/backend/relay/groups.md`). A client's correct response is to
    /// re-derive the current epoch's wrap, never to resend this one.
    WrapNotNewer,
    // quota
    StorageExhausted,
    RateLimited,
    SeatsExhausted,
    GroupIngressLimited,
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
            Self::Backpressure | Self::LockTimeout | Self::Failover => ErrorClass::Retry,
            Self::MalformedHeader
            | Self::NoncanonicalCbor
            | Self::HashMismatch
            | Self::EnvelopeTooLarge
            | Self::UnknownRequiredField => ErrorClass::Reject,
            Self::PlaintextRefused
            | Self::WriterNotInAccessSet
            | Self::GroupUnknown
            | Self::ServiceReadOnly
            | Self::GroupFrozen
            | Self::WrapNotNewer => ErrorClass::Denied,
            Self::StorageExhausted
            | Self::RateLimited
            | Self::SeatsExhausted
            | Self::GroupIngressLimited => ErrorClass::Quota,
            Self::ProtocolUnsupported | Self::BelowClientFloor => ErrorClass::Version,
        }
    }

    /// The stable string a client matches on, without its class prefix.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Backpressure => "backpressure",
            Self::LockTimeout => "lock_timeout",
            Self::Failover => "failover",
            Self::MalformedHeader => "malformed_header",
            Self::NoncanonicalCbor => "noncanonical_cbor",
            Self::HashMismatch => "hash_mismatch",
            Self::EnvelopeTooLarge => "envelope_too_large",
            Self::UnknownRequiredField => "unknown_required_field",
            Self::PlaintextRefused => "plaintext_refused",
            Self::WriterNotInAccessSet => "writer_not_in_access_set",
            Self::GroupUnknown => "group_unknown",
            Self::ServiceReadOnly => "service_read_only",
            Self::GroupFrozen => "group_frozen",
            Self::WrapNotNewer => "wrap_not_newer",
            Self::StorageExhausted => "storage_exhausted",
            Self::RateLimited => "rate_limited",
            Self::SeatsExhausted => "seats_exhausted",
            Self::GroupIngressLimited => "group_ingress_limited",
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
        Self::MalformedHeader,
        Self::NoncanonicalCbor,
        Self::HashMismatch,
        Self::EnvelopeTooLarge,
        Self::UnknownRequiredField,
        Self::PlaintextRefused,
        Self::WriterNotInAccessSet,
        Self::GroupUnknown,
        Self::ServiceReadOnly,
        Self::GroupFrozen,
        Self::WrapNotNewer,
        Self::StorageExhausted,
        Self::RateLimited,
        Self::SeatsExhausted,
        Self::GroupIngressLimited,
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
            Self::UnsupportedVersion(_) => ErrorCode::ProtocolUnsupported,
        }
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
            Self::Sub { .. } => FrameTag::Sub,
            Self::SubAck { .. } => FrameTag::SubAck,
            Self::Recon { .. } => FrameTag::Recon,
            Self::Push { .. } => FrameTag::Push,
            Self::Send { .. } => FrameTag::Send,
            Self::SendAck { .. } => FrameTag::SendAck,
            Self::Blob { .. } => FrameTag::Blob,
            Self::Drop { .. } => FrameTag::Drop,
            Self::Bye { .. } => FrameTag::Bye,
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
            Self::Access { body } | Self::Wrap { body } | Self::Join { body } => body.len(),
            Self::Blob { payload } => payload.len(),
            Self::Connect { groups, .. } => groups.iter().map(Vec::len).sum(),
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
                if version != PROTOCOL_VERSION {
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
                if version != PROTOCOL_VERSION {
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
