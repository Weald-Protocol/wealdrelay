// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The envelope, and every check the relay makes on accept.
//!
//! This is the trust boundary. `backend/build-coverage-exclusions.md` names
//! `backend/wealdrelay/src/envelope/**` as a path where no coverage exclusion is
//! ever permitted and `scripts/backend-coverage.sh --exclusion-grep` fails on one,
//! because envelope validation is what makes a forged author chain fail.
//!
//! The client's half is `Sources/Sync/Envelope.swift`. The two compute the same
//! content address over the same canonical encoding, and step 4's gate compares
//! them against the same vectors, because "the relay recomputes the hash on
//! accept" is only a real check if both sides mean the same function by it.
//!
//! ## What the relay can check, and what it deliberately cannot
//!
//! It checks: the protocol version, `enc` against its configured floor, that the
//! group exists, that `hash` is `BLAKE3(v, enc, group, epoch, ct)`, and that `ct`
//! is under the size limit. That is the whole list.
//!
//! It does not check the author. `wire.md` is explicit: the encrypted `author` is
//! deliberately not used, because agents are authored by delegated keys and proxy
//! through their issuing device, and the relay cannot inspect the author without
//! breaking the content boundary. Authorship is checked by every receiving client,
//! against a signature the relay cannot produce and cannot verify.

use crate::cbor::{self, CborError, Reader};
use crate::config::MinEncryption;
use crate::frame::ErrorCode;

/// The protocol version this build accepts.
pub const VERSION: u8 = 1;

/// `[32]byte`, from the wire format.
pub const GROUP_BYTES: usize = 32;
pub const HASH_BYTES: usize = 32;

/// The `ct` ceiling, which `reject/envelope_too_large` carries.
pub const MAX_CIPHERTEXT_BYTES: usize = 1 << 20;

/// How the body is protected. `0` is signed plaintext, which
/// `specs/backend/relay/migration.md` Phases 1 and 2 use and which the hosted tier
/// never accepts. `1` is MLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    None = 0,
    Mls = 1,
}

impl Encryption {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Mls),
            _ => None,
        }
    }
}

/// The eight-field envelope. The only unit the relay stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub v: u8,
    pub enc: Encryption,
    pub group: Vec<u8>,
    pub epoch: u64,
    /// Relay-assigned on accept. Zero as it arrives. A sync cursor only.
    pub seq: u64,
    /// Relay receipt time in milliseconds. Zero as it arrives.
    pub ts: u64,
    pub hash: Vec<u8>,
    pub ct: Vec<u8>,
}

/// `BLAKE3(v, enc, group, epoch, ct)`, canonically encoded in that order.
///
/// Deliberately excluding `seq` and `ts`: the relay assigns them, so an address
/// covering them would change when the relay touched it and a retry would not
/// deduplicate. This is the function `Sources/Sync/Envelope.swift` computes, over
/// the same bytes.
pub fn content_hash(v: u8, enc: Encryption, group: &[u8], epoch: u64, ct: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&cbor::uint(u64::from(v)));
    hasher.update(&cbor::uint(enc as u64));
    hasher.update(&cbor::bytes(group));
    hasher.update(&cbor::uint(epoch));
    hasher.update(&cbor::bytes(ct));
    hasher.finalize().as_bytes().to_vec()
}

/// Why an envelope was refused, in the terms the error registry uses.
///
/// Every variant maps to a code, because a `SEND` that failed without one would
/// leave a client unable to tell "do not retry this" from "try again in a minute",
/// and `wire.md` requires that a retry is always safe.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    #[error("envelope is not canonical CBOR: {0}")]
    Cbor(#[from] CborError),
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown enc value {0}")]
    UnknownEncryption(u8),
    #[error("denied/plaintext_refused: this relay requires MLS")]
    PlaintextRefused,
    #[error("content address does not match the envelope's own fields")]
    HashMismatch,
    #[error("ct is {0} bytes, over the limit")]
    CiphertextTooLarge(usize),
}

impl EnvelopeError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Cbor(_) => ErrorCode::NoncanonicalCbor,
            Self::UnsupportedVersion(_) => ErrorCode::ProtocolUnsupported,
            Self::UnknownEncryption(_) => ErrorCode::MalformedHeader,
            Self::PlaintextRefused => ErrorCode::PlaintextRefused,
            Self::HashMismatch => ErrorCode::HashMismatch,
            Self::CiphertextTooLarge(_) => ErrorCode::EnvelopeTooLarge,
        }
    }
}

impl Envelope {
    /// Deterministic CBOR: an eight-item array in the spec's field order.
    pub fn encode(&self) -> Vec<u8> {
        cbor::array(&[
            cbor::uint(u64::from(self.v)),
            cbor::uint(self.enc as u64),
            cbor::bytes(&self.group),
            cbor::uint(self.epoch),
            cbor::uint(self.seq),
            cbor::uint(self.ts),
            cbor::bytes(&self.hash),
            cbor::bytes(&self.ct),
        ])
    }

    /// Decode without validating. Separate calls, so a receiver can report which
    /// check failed rather than one undifferentiated refusal.
    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let mut reader = Reader::new(bytes);
        reader.array(8)?;
        let v = reader.u8()?;
        let raw_enc = reader.u8()?;
        let enc = Encryption::from_u8(raw_enc).ok_or(EnvelopeError::UnknownEncryption(raw_enc))?;
        let group = reader.bytes_of(GROUP_BYTES)?;
        let epoch = reader.uint()?;
        let seq = reader.uint()?;
        let ts = reader.uint()?;
        let hash = reader.bytes_of(HASH_BYTES)?;
        let ct = reader.bytes()?;
        reader.finish()?;
        Ok(Self {
            v,
            enc,
            group,
            epoch,
            seq,
            ts,
            hash,
            ct,
        })
    }

    /// The address this envelope's own fields imply, whatever `hash` says.
    pub fn computed_hash(&self) -> Vec<u8> {
        content_hash(self.v, self.enc, &self.group, self.epoch, &self.ct)
    }

    /// Every check the relay makes that does not need database state.
    ///
    /// Group existence and the access set are checked by the accept path, because
    /// both are state this function cannot see. Everything here is a property of
    /// the bytes alone, which is what lets it run before any database work: a
    /// forged envelope costs the relay one hash and no transaction.
    pub fn validate(&self, floor: MinEncryption) -> Result<(), EnvelopeError> {
        if self.v != VERSION {
            return Err(EnvelopeError::UnsupportedVersion(self.v));
        }
        if matches!(floor, MinEncryption::Mls) && matches!(self.enc, Encryption::None) {
            return Err(EnvelopeError::PlaintextRefused);
        }
        if self.ct.len() > MAX_CIPHERTEXT_BYTES {
            return Err(EnvelopeError::CiphertextTooLarge(self.ct.len()));
        }
        // Last, because it is the only check that costs a hash over the whole
        // ciphertext. A peer sending a two megabyte envelope with a wrong version
        // is refused before the relay reads all of it.
        if self.computed_hash() != self.hash {
            return Err(EnvelopeError::HashMismatch);
        }
        Ok(())
    }
}
