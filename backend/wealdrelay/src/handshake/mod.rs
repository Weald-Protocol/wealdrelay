// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! MLS handshake messages: what a member publishes, and what the relay may do
//! with it.
//!
//! `specs/backend/relay/groups.md` puts key packages, Welcomes and the commits
//! that advance an epoch in the relay's hands as bytes it stores and forwards and
//! cannot open. This module is the relay's half of that: a bound, a content
//! address, and an order.
//!
//! ## Why this is not an envelope
//!
//! An envelope's `ct` under `enc: 1` is an encrypted `Payload`
//! (`specs/backend/relay/wire.md`). An MLS handshake message is not one: it is the
//! object that establishes the key an envelope is encrypted under, so a member who
//! has not processed it cannot decrypt anything published after it. Two
//! consequences settle the design:
//!
//! - Handshake messages are **order dependent** in a way envelopes are not. A
//!   commit for epoch N+1 applied before the commit for epoch N is not a message
//!   out of order, it is a message that cannot be processed at all. So the relay
//!   assigns a dense per-group sequence here, unlike `relay_envelope.seq`, which
//!   `wire.md` calls a sync cursor and nothing above layer 2 reads.
//! - Carrying them as `enc: 0` envelopes would put signed plaintext control records
//!   in every group's log on a relay that is behaving perfectly, and would make the
//!   encryption claim untestable: "every stored envelope is encrypted" has to be
//!   true or it is not a claim.
//!
//! ## What the relay learns
//!
//! That a group exists, that somebody is committing to it, and how large the
//! messages are. It cannot read one and holds no key that could. The count and the
//! sizes are the same facts the envelope log already exposes.

pub mod store;

/// Group ids are 32 bytes on this wire, and so is a content address.
pub const GROUP_BYTES: usize = 32;
pub const HASH_BYTES: usize = 32;

/// The largest handshake message the relay will store.
///
/// A commit carries path secrets for the ratchet tree, so it grows with the group,
/// and a `Welcome` carries the tree itself. Sized well past a realistic group at
/// the stated posture of 3 to 30 people and bounded so that the table cannot be
/// used as storage. The same order of magnitude as `invite::MAX_BUNDLE_BYTES`,
/// which bounds a `GroupInfo` arriving by the other path.
pub const MAX_MESSAGE_BYTES: usize = 512 * 1024;

/// One handshake message, as the relay holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub group: Vec<u8>,
    /// Opaque. One serialised MLS message.
    pub message: Vec<u8>,
}

/// Why a handshake message was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandshakeError {
    #[error("handshake: group id is {0} bytes, expected {GROUP_BYTES}")]
    GroupWidth(usize),
    #[error("handshake: the message is empty")]
    Empty,
    #[error("handshake: the message is {0} bytes, over the {MAX_MESSAGE_BYTES} byte bound")]
    TooLarge(usize),
}

impl HandshakeError {
    /// The wire code a client is told, decided in one place.
    ///
    /// All three are `reject`: every one is a property of the bytes, so resending
    /// them will fail again. A size problem is told apart from a shape problem
    /// because a client fixes them differently.
    pub fn code(&self) -> crate::frame::ErrorCode {
        use crate::frame::ErrorCode;
        match self {
            Self::TooLarge(_) => ErrorCode::EnvelopeTooLarge,
            Self::GroupWidth(_) | Self::Empty => ErrorCode::MalformedHeader,
        }
    }
}

impl Handshake {
    /// The bounds. Checked before anything is allocated or stored.
    pub fn check(&self) -> Result<(), HandshakeError> {
        if self.group.len() != GROUP_BYTES {
            return Err(HandshakeError::GroupWidth(self.group.len()));
        }
        if self.message.is_empty() {
            return Err(HandshakeError::Empty);
        }
        if self.message.len() > MAX_MESSAGE_BYTES {
            return Err(HandshakeError::TooLarge(self.message.len()));
        }
        Ok(())
    }

    /// `BLAKE3(group || message)`. The content address, and the deduplication key.
    ///
    /// Over the group as well as the message, for the same reason envelope hashes
    /// are never deduplicated across groups: an identical message in two groups is
    /// two facts, and collapsing them would let one group's history depend on
    /// another's.
    pub fn hash(&self) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.group);
        hasher.update(&self.message);
        hasher.finalize().as_bytes().to_vec()
    }
}
