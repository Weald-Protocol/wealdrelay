// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The `DROP` request and response: text compaction's one instruction.
//!
//! `specs/backend/relay/lifecycle.md`. A `drop_before` names a group, the
//! checkpoint that anchors it, the barrier below which envelopes may go, and
//! every snapshot the checkpoint requires. It is signed with the group's
//! epoch-derived retention signing key, the same key the media chain uses, and it
//! is bound to a threshold-authorized `RetentionPolicy` or `RetentionDestruction`
//! which is what actually permits deletion. The signature proves a member asked;
//! the authorization proves the group agreed. Neither alone is enough, for
//! exactly the reason `media.md` gives about manifests: every current member
//! holds the verifier, including the one on their way out.
//!
//! Canonical CBOR, arrays in declaration order, the same shape as every other
//! record on this wire (`media::wire`). `signing_bytes` is the canonical encoding
//! of every field except the signature, which is what the signer signs and what
//! the relay recomputes from the record it decoded.

use crate::access::{HASH_BYTES, SIG_BYTES};
use crate::cbor::{self, CborError, Reader};

/// A bound on the snapshot list, for the same reason `media::wire::MAX_LIST`
/// exists: refuse the count before the allocation.
pub const MAX_SNAPSHOTS: usize = 4096;

/// Why a lifecycle record could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LifecycleWireError {
    #[error("lifecycle record is not canonical CBOR: {0}")]
    Encoding(#[from] CborError),
    #[error("a snapshot list longer than {MAX_SNAPSHOTS}")]
    TooManyEntries,
    #[error("unknown lifecycle message tag {0}")]
    UnknownTag(u64),
}

const TAG_DROP_BEFORE: u64 = 1;

const RTAG_DROPPED: u64 = 1;
const RTAG_REFUSED: u64 = 2;

/// One signed compaction instruction.
///
/// **There is no barrier field, and that is deliberate.** An earlier version had
/// the client name the sequence number to drop below, which it cannot know: `seq`
/// is assigned by the relay on accept and is not in any answer the client holds.
/// A client that guessed either dropped nothing or, far worse, named a barrier
/// above the checkpoint it anchored to and asked for history the checkpoint does
/// not replace. The relay already requires the checkpoint envelope to be present
/// before it deletes anything, so it knows that envelope's own `seq`, and the
/// barrier is that number. Deriving it makes the dangerous instruction
/// unrepresentable rather than merely refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropBefore {
    pub group: Vec<u8>,
    /// The hash of the envelope carrying the `checkpoint` payload.
    pub manifest_hash: Vec<u8>,
    /// Every snapshot envelope the checkpoint names. The relay refuses the whole
    /// instruction unless it holds all of them, because a checkpoint whose
    /// snapshots are missing is a barrier with nothing behind it.
    pub snapshots: Vec<Vec<u8>>,
    /// The retention epoch whose verifier signed this.
    pub epoch: u64,
    /// The authorized `RetentionPolicy` version this drop runs under, or `None`
    /// when it runs under a one-off `RetentionDestruction` instead.
    pub policy_version: Option<u64>,
    /// The `RetentionDestruction` this drop runs under, by `target_digest`, or
    /// `None` when it runs under a policy.
    pub destruction_digest: Option<Vec<u8>>,
    pub sig: Vec<u8>,
}

impl DropBefore {
    pub fn signing_bytes(&self) -> Vec<u8> {
        cbor::array(&[
            cbor::bytes(&self.group),
            cbor::bytes(&self.manifest_hash),
            encode_hashes(&self.snapshots),
            cbor::uint(self.epoch),
            match self.policy_version {
                Some(version) => cbor::bytes(&version.to_be_bytes()),
                None => cbor::NULL.to_vec(),
            },
            match &self.destruction_digest {
                Some(digest) => cbor::bytes(digest),
                None => cbor::NULL.to_vec(),
            },
        ])
    }

    pub fn encode(&self) -> Vec<u8> {
        cbor::array(&[cbor::uint(TAG_DROP_BEFORE), self.encoded_body()])
    }

    fn encoded_body(&self) -> Vec<u8> {
        cbor::array(&[
            cbor::bytes(&self.group),
            cbor::bytes(&self.manifest_hash),
            encode_hashes(&self.snapshots),
            cbor::uint(self.epoch),
            match self.policy_version {
                Some(version) => cbor::bytes(&version.to_be_bytes()),
                None => cbor::NULL.to_vec(),
            },
            match &self.destruction_digest {
                Some(digest) => cbor::bytes(digest),
                None => cbor::NULL.to_vec(),
            },
            cbor::bytes(&self.sig),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, LifecycleWireError> {
        let mut reader = Reader::new(bytes);
        reader.array(2)?;
        let tag = reader.uint()?;
        if tag != TAG_DROP_BEFORE {
            return Err(LifecycleWireError::UnknownTag(tag));
        }
        let record = Self::decode_body(&mut reader)?;
        reader.finish()?;
        Ok(record)
    }

    fn decode_body(reader: &mut Reader<'_>) -> Result<Self, LifecycleWireError> {
        reader.array(7)?;
        let group = reader.bytes_of(HASH_BYTES)?;
        let manifest_hash = reader.bytes_of(HASH_BYTES)?;
        let snapshots = read_hashes(reader)?;
        let epoch = reader.uint()?;
        let policy_version = reader
            .optional_bytes()?
            .map(|bytes| {
                let array: [u8; 8] = bytes
                    .try_into()
                    .map_err(|_| LifecycleWireError::TooManyEntries)?;
                Ok::<u64, LifecycleWireError>(u64::from_be_bytes(array))
            })
            .transpose()?;
        let destruction_digest = reader.optional_bytes()?;
        let sig = reader.bytes_of(SIG_BYTES)?;
        Ok(Self {
            group,
            manifest_hash,
            snapshots,
            epoch,
            policy_version,
            destruction_digest,
            sig,
        })
    }
}

/// What the relay answers a `DROP` with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// The instruction was verified and run. The numbers are the artifact: what
    /// went, how many bytes it was, and what the checkpoint kept.
    Dropped { deleted: u64, bytes: u64, kept: u64 },
    /// The instruction was refused, and this is why in one machine-readable
    /// word. A refusal is never a partial run: nothing is deleted before every
    /// check has passed.
    Refused { reason: String },
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Dropped {
                deleted,
                bytes,
                kept,
            } => cbor::array(&[
                cbor::uint(RTAG_DROPPED),
                cbor::array(&[cbor::uint(*deleted), cbor::uint(*bytes), cbor::uint(*kept)]),
            ]),
            Self::Refused { reason } => cbor::array(&[
                cbor::uint(RTAG_REFUSED),
                cbor::array(&[cbor::bytes(reason.as_bytes())]),
            ]),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, LifecycleWireError> {
        let mut reader = Reader::new(bytes);
        reader.array(2)?;
        let tag = reader.uint()?;
        let response = match tag {
            RTAG_DROPPED => {
                reader.array(3)?;
                let deleted = reader.uint()?;
                let bytes = reader.uint()?;
                let kept = reader.uint()?;
                Self::Dropped {
                    deleted,
                    bytes,
                    kept,
                }
            }
            RTAG_REFUSED => {
                reader.array(1)?;
                let reason = reader.bytes()?;
                Self::Refused {
                    reason: String::from_utf8_lossy(&reason).into_owned(),
                }
            }
            other => return Err(LifecycleWireError::UnknownTag(other)),
        };
        reader.finish()?;
        Ok(response)
    }
}

fn encode_hashes(items: &[Vec<u8>]) -> Vec<u8> {
    cbor::array(
        &items
            .iter()
            .map(|item| cbor::bytes(item))
            .collect::<Vec<_>>(),
    )
}

fn read_hashes(reader: &mut Reader<'_>) -> Result<Vec<Vec<u8>>, LifecycleWireError> {
    let count = reader.array_header()?;
    if count > MAX_SNAPSHOTS {
        return Err(LifecycleWireError::TooManyEntries);
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(reader.bytes_of(HASH_BYTES)?);
    }
    Ok(items)
}
