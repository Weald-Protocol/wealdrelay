// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The redemption conversation, as it goes on the wire.
//!
//! `specs/backend/relay/invites.md` steps 4 to 7: reserve a seat with the token and
//! the one-time code, fetch the sealed bundles for each scope, and commit each scope
//! as the joiner enters it. Three requests, one frame, one order.
//!
//! ## Why this is a frame and not an event kind
//!
//! Everything else a client sends is inside a group it already belongs to. A joiner
//! belongs to nothing: it is asking for the reservation that lets it authenticate at
//! all. So this is the one frame the relay accepts before `AUTH`, and every other
//! defence is arranged around that fact rather than around a session.
//!
//! ## What the relay learns, and what it refuses to say
//!
//! It learns that somebody presented a token and a code. It does not say which of
//! "no such token", "wrong code", "no seats left", "revoked", "expired" or "cooled
//! down" it was: `invite::UNAVAILABLE` is the one answer to all of them, because an
//! endpoint that distinguished them is an endpoint that confirms a token exists. The
//! rule is `invites.md`'s and it is enforced here rather than in the caller, so
//! there is one place a future arm could break it.

use crate::cbor::{self, CborError, Reader};

/// A joiner's step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Take a seat, with the code the second channel carried.
    ///
    /// `device` is the joining device's public key. The hash the relay stores is
    /// computed here from the workspace salt, not supplied: a client that chose its
    /// own entry hash could reserve a seat against somebody else's device.
    Reserve {
        token: Vec<u8>,
        code: String,
        nonce: Vec<u8>,
        device: Vec<u8>,
    },
    /// The sealed `GroupInfo` bundles for one scope of a reserved invite.
    Bundles { token: Vec<u8>, group: Vec<u8> },
    /// The record itself, so a joiner can verify the issuer's signature and learn
    /// which scopes the invite carries.
    ///
    /// `invites.md` step 5 requires both, and until this step existed neither was
    /// possible: a client had no way to fetch the record, so it could not check that
    /// the invite chained to the workspace trust root rather than to whoever holds the
    /// relay, and it could not know which groups to ask for bundles of. It was
    /// guessing, which for a joiner that knows nothing about the workspace means it
    /// could not proceed at all.
    ///
    /// Answered with the bytes the issuer signed, byte for byte, never re-encoded, so
    /// the signature is checked over the issuer's encoder and not over the relay's.
    /// Not gated on a reservation and deliberately not: the record is public to
    /// whoever holds the token, it contains no code, no secret and nothing but
    /// ciphertext nobody without the fragment can open, and gating it would mean
    /// spending a code attempt to find out an invite is malformed.
    Record { token: Vec<u8> },
    /// This scope is entered. The last one consumes the seat.
    Commit {
        token: Vec<u8>,
        nonce: Vec<u8>,
        device: Vec<u8>,
        group: Vec<u8>,
    },
}

/// What the relay answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// A seat is held until this time, in relay milliseconds.
    Reserved { expires_at_ms: i64 },
    /// The retained candidates for the scope, newest first, opaque.
    Bundles(Vec<super::EncBundle>),
    /// The receipt for a scope commit, which is a hash of what it is a receipt for.
    Committed { receipt: Vec<u8> },
    /// The stored record, exactly as its issuer signed it. Empty for a token that
    /// does not exist, which is the same answer as for one that does and was revoked:
    /// this path stays uninformative about which tokens are real.
    Record { body: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RedeemError {
    #[error("redeem request is malformed: {0}")]
    Malformed(String),
    #[error("redeem step {0} is not one this relay knows")]
    UnknownStep(u64),
}

impl From<CborError> for RedeemError {
    fn from(error: CborError) -> Self {
        Self::Malformed(error.to_string())
    }
}

impl RedeemError {
    /// Every refusal on this path is the same generic answer, including this one.
    ///
    /// A malformed request could honestly be `reject/malformed_header`, and saying so
    /// would tell a prober that its bytes reached a relay that understood them. The
    /// endpoint is uninformative on purpose (`invites.md`), so it stays uninformative
    /// about its own decoder too.
    pub fn code(&self) -> crate::frame::ErrorCode {
        super::UNAVAILABLE
    }
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Reserve {
                token,
                code,
                nonce,
                device,
            } => cbor::array(&[
                cbor::uint(0),
                cbor::bytes(token),
                cbor::bytes(code.as_bytes()),
                cbor::bytes(nonce),
                cbor::bytes(device),
            ]),
            Self::Bundles { token, group } => {
                cbor::array(&[cbor::uint(1), cbor::bytes(token), cbor::bytes(group)])
            }
            Self::Record { token } => cbor::array(&[cbor::uint(3), cbor::bytes(token)]),
            Self::Commit {
                token,
                nonce,
                device,
                group,
            } => cbor::array(&[
                cbor::uint(2),
                cbor::bytes(token),
                cbor::bytes(nonce),
                cbor::bytes(device),
                cbor::bytes(group),
            ]),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RedeemError> {
        let mut reader = Reader::new(bytes);
        let fields = reader.array_header()?;
        let step = reader.uint()?;
        let request = match (step, fields) {
            (0, 5) => Self::Reserve {
                token: reader.bytes()?,
                // UTF-8 inside a byte string, because this wire has no text type
                // (`crate::cbor`). A code that is not UTF-8 is not a code anybody
                // typed, and it is refused as malformed rather than lossily decoded.
                code: String::from_utf8(reader.bytes()?)
                    .map_err(|_| RedeemError::Malformed("code is not utf-8".into()))?,
                nonce: reader.bytes()?,
                device: reader.bytes()?,
            },
            (1, 3) => Self::Bundles {
                token: reader.bytes()?,
                group: reader.bytes()?,
            },
            (2, 5) => Self::Commit {
                token: reader.bytes()?,
                nonce: reader.bytes()?,
                device: reader.bytes()?,
                group: reader.bytes()?,
            },
            (3, 2) => Self::Record {
                token: reader.bytes()?,
            },
            (0..=3, count) => {
                return Err(RedeemError::Malformed(format!(
                    "step {step} takes a different number of fields than {count}"
                )))
            }
            _ => return Err(RedeemError::UnknownStep(step)),
        };
        reader.finish()?;
        Ok(request)
    }
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Reserved { expires_at_ms } => cbor::array(&[
                cbor::uint(0),
                cbor::uint(u64::try_from(*expires_at_ms).unwrap_or_default()),
            ]),
            Self::Bundles(bundles) => cbor::array(&[
                cbor::uint(1),
                cbor::array(
                    &bundles
                        .iter()
                        .map(|bundle| {
                            cbor::array(&[
                                cbor::bytes(&bundle.group),
                                cbor::uint(bundle.epoch),
                                cbor::bytes(&bundle.ct),
                            ])
                        })
                        .collect::<Vec<_>>(),
                ),
            ]),
            Self::Committed { receipt } => cbor::array(&[cbor::uint(2), cbor::bytes(receipt)]),
            Self::Record { body } => cbor::array(&[cbor::uint(3), cbor::bytes(body)]),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RedeemError> {
        let mut reader = Reader::new(bytes);
        reader.array(2)?;
        let kind = reader.uint()?;
        let response = match kind {
            0 => Self::Reserved {
                expires_at_ms: i64::try_from(reader.uint()?)
                    .map_err(|_| RedeemError::Malformed("expiry is out of range".into()))?,
            },
            1 => {
                let count = reader.array_header()?;
                if count > super::MAX_SCOPES {
                    return Err(RedeemError::Malformed(format!(
                        "{count} bundles is past the {} scope bound",
                        super::MAX_SCOPES
                    )));
                }
                let mut bundles = Vec::with_capacity(count);
                for _ in 0..count {
                    reader.array(3)?;
                    bundles.push(super::EncBundle {
                        group: reader.bytes()?,
                        epoch: reader.uint()?,
                        ct: reader.bytes()?,
                    });
                }
                Self::Bundles(bundles)
            }
            2 => Self::Committed {
                receipt: reader.bytes()?,
            },
            3 => Self::Record {
                body: reader.bytes()?,
            },
            other => return Err(RedeemError::UnknownStep(other)),
        };
        reader.finish()?;
        Ok(response)
    }
}
