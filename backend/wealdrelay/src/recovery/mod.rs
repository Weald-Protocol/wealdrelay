// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Recovery wraps: what a committer publishes, and what the relay may conclude.
//!
//! `specs/backend/relay/groups.md`, "Recovery access without a leaf in every
//! group". A recovery key is not an MLS leaf outside the workspace root, so for
//! every other group the committer seals that group's current epoch secret **and**
//! its current `GroupInfo` to each entitled recovery public key and publishes the
//! result as `recovery.wrap` (wire kind `0x0061`).
//!
//! ## What this module cannot do
//!
//! It cannot open a wrap and it cannot name whose wrap it is. `ct` is sealed to a
//! recovery key that exists only on a person's paper phrase and their devices, and
//! the index is `tag`, which is
//! `BLAKE3(export(weald wraptag v1) || recovery_pubkey)` and therefore derived from
//! the group's own epoch secret. Two consequences the relay depends on:
//!
//! - A tag rotates wholesale on every commit, so a slot is a per-epoch pseudonym
//!   and not an identity.
//! - The same person's wraps in two different groups carry unrelated tags, so the
//!   set of slots per group cannot be joined into a membership graph. That is the
//!   property `scripts/prove-blind.py` measures directly, by reading every wrap in
//!   the database and refusing any value that recurs across two groups.
//!
//! What the relay does learn is a count per group, which `groups.md` states plainly
//! is already implied by the size of a commit.
//!
//! ## Two halves, deliberately separated
//!
//! Everything here is pure: the decode, the bounds, and the replacement rule. The
//! transactions are in `recovery::store`. Same split as `access` and `invite`, and
//! for the same reason: a rule that can only be reached through a socket and a
//! Postgres round trip is a rule nobody covers.

pub mod store;

use crate::cbor::{self, CborError, Reader};

/// Group ids, tags and hashes are all 32 bytes on this wire.
pub const GROUP_BYTES: usize = 32;
pub const TAG_BYTES: usize = 32;

/// A bound on one sealed wrap.
///
/// A wrap carries an epoch secret, which is small and fixed, plus a `GroupInfo`,
/// which is a ratchet tree and grows with the group. Sized well past a realistic
/// group at the stated posture of 3 to 30 people, and bounded so that a member
/// cannot use the wrap table as storage. The same reasoning and the same order of
/// magnitude as `invite::MAX_BUNDLE_BYTES`, which bounds the same payload arriving
/// by the other path.
pub const MAX_WRAP_BYTES: usize = 256 * 1024;

/// How long the superseded slot outlives its replacement.
///
/// `groups.md`: "The relay retains the prior wrap slot for 30 days after
/// activation; only then may it discard it." That overlap is the availability
/// guarantee for the two-phase cross-group handoff, so it is a constant here and
/// not a deployment knob: a relay that shortened it would silently narrow the
/// window a recovery has to land in.
pub const PRIOR_RETENTION_DAYS: i64 = 30;

/// One `recovery.wrap`, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryWrap {
    pub group: Vec<u8>,
    pub epoch: u64,
    /// `BLAKE3(export(weald wraptag v1) || recovery_pubkey)`. Opaque to the relay
    /// by construction: it is derived from a secret the relay does not hold.
    pub tag: Vec<u8>,
    /// Sealed `{ epoch_secret, group_info }`. Opaque.
    pub ct: Vec<u8>,
}

/// Why a wrap was refused.
///
/// Every arm is a property of the bytes, checkable without any key and without any
/// database. A wrap that fails one of these was never a wrap, so it is refused
/// before it can occupy a slot.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WrapError {
    #[error("recovery wrap: malformed: {0}")]
    Malformed(String),
    #[error("recovery wrap: group id is {0} bytes, expected {GROUP_BYTES}")]
    GroupWidth(usize),
    #[error("recovery wrap: tag is {0} bytes, expected {TAG_BYTES}")]
    TagWidth(usize),
    #[error("recovery wrap: ciphertext is empty")]
    Empty,
    #[error("recovery wrap: ciphertext is {0} bytes, over the {MAX_WRAP_BYTES} byte bound")]
    TooLarge(usize),
    /// A slot may only move forward. See ``RecoveryWrap::check_replacement``.
    #[error("recovery wrap: epoch {offered} does not advance the stored epoch {stored}")]
    NotNewer { stored: u64, offered: u64 },
}

impl WrapError {
    /// The wire code a client is told, which is one decision and therefore lives
    /// in one place.
    ///
    /// A stale wrap is `denied`: the bytes are well formed and would have been
    /// accepted an epoch ago, so the client's correct response is to re-derive the
    /// current wrap rather than to resend this one. Everything else here is a
    /// property of the bytes, which is `reject`: resending them will fail again.
    pub fn code(&self) -> crate::frame::ErrorCode {
        use crate::frame::ErrorCode;
        match self {
            Self::NotNewer { .. } => ErrorCode::WrapNotNewer,
            Self::TooLarge(_) => ErrorCode::EnvelopeTooLarge,
            Self::Malformed(_) | Self::GroupWidth(_) | Self::TagWidth(_) | Self::Empty => {
                ErrorCode::MalformedHeader
            }
        }
    }
}

impl From<CborError> for WrapError {
    fn from(error: CborError) -> Self {
        Self::Malformed(error.to_string())
    }
}

impl RecoveryWrap {
    /// Canonical encoding: `[group, epoch, tag, ct]`.
    ///
    /// The field order is the order `groups.md` states the struct in, and the
    /// framing is the deterministic CBOR every other digest and record on this wire
    /// uses (`crate::cbor`).
    pub fn encode(&self) -> Vec<u8> {
        cbor::array(&[
            cbor::bytes(&self.group),
            cbor::uint(self.epoch),
            cbor::bytes(&self.tag),
            cbor::bytes(&self.ct),
        ])
    }

    /// Decode and check every bound, in that order.
    ///
    /// Bounds before storage, always: the width checks are what stop a client
    /// writing a row the schema's own constraints would reject at the far end of a
    /// transaction, and the size check is what stops one allocating megabytes on
    /// the relay before anything has been validated.
    pub fn decode(bytes: &[u8]) -> Result<Self, WrapError> {
        let mut reader = Reader::new(bytes);
        reader.array(4)?;
        let group = reader.bytes()?;
        let epoch = reader.uint()?;
        let tag = reader.bytes()?;
        let ct = reader.bytes()?;
        reader.finish()?;
        let wrap = Self {
            group,
            epoch,
            tag,
            ct,
        };
        wrap.check()?;
        Ok(wrap)
    }

    /// The bounds, separately from the decode, so a locally constructed wrap is
    /// held to the same rules as a decoded one.
    pub fn check(&self) -> Result<(), WrapError> {
        if self.group.len() != GROUP_BYTES {
            return Err(WrapError::GroupWidth(self.group.len()));
        }
        if self.tag.len() != TAG_BYTES {
            return Err(WrapError::TagWidth(self.tag.len()));
        }
        if self.ct.is_empty() {
            return Err(WrapError::Empty);
        }
        if self.ct.len() > MAX_WRAP_BYTES {
            return Err(WrapError::TooLarge(self.ct.len()));
        }
        Ok(())
    }

    /// May this wrap replace what is already in its slot?
    ///
    /// Only forward. A slot that could be rewritten at the same epoch, or at an
    /// older one, is a slot an attacker who captured any past wrap can restore, and
    /// a recovery that then read it would rejoin at a dead epoch holding a secret
    /// the group has already ratcheted away from. The relay cannot verify the seal,
    /// so monotonicity is the entire defence available to it and it is not optional.
    ///
    /// Note the asymmetry with `access`: this is not a quorum decision and not a
    /// signature check. It is the one comparison the relay can make honestly.
    pub fn check_replacement(stored: u64, offered: u64) -> Result<(), WrapError> {
        if offered > stored {
            Ok(())
        } else {
            Err(WrapError::NotNewer { stored, offered })
        }
    }
}
