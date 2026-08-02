// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Range-based set reconciliation, and the `RECON` payload it travels in.
//!
//! `specs/backend/relay/wire.md`: "Negentropy over the per-group sequence space.
//! A reconnecting client and the relay exchange fingerprints over sequence
//! ranges, recursing only into ranges that differ, converging in O(diff) round
//! trips rather than O(history)." This module is that exchange, and
//! `reconcile.rs` beside it is the two roles: the relay answering, and the client
//! driving.
//!
//! ## What an item is, and why `seq` is allowed to be the key
//!
//! An item is one envelope, as `(seq, id)`, where `id` is the content address the
//! relay already stores and `seq` is the relay-assigned cursor. Using `seq` as the
//! ordering key looks like it contradicts `wire.md`'s rule that causality never
//! comes from `seq`, and it does not: this space is a *search index over a set*,
//! not an order. Nothing here or above it concludes that an item with a lower
//! `seq` happened first. Ordering stays in the Automerge change graph inside the
//! ciphertext, which this module cannot read and never consults.
//!
//! Gaps are legal, because `accept.rs` leaves them whenever a transaction rolls
//! back. Ranges are half-open over the *value* space rather than over positions,
//! so a gap costs nothing.
//!
//! ## Dual transport is why the id is the identity
//!
//! `specs/backend/relay/migration.md`: during Phases 2 and 3 both transports are
//! live, and "an envelope arriving by both paths deduplicates without
//! coordination" because the hash is a content address. A client therefore holds
//! two kinds of envelope: ones with a relay `seq`, which take part in the exchange
//! below, and ones that arrived by git and have no `seq` at all, which the client
//! simply `SEND`s. A duplicate `SEND` is answered with the existing `seq`
//! (`wire.md`), so that path is free and needs no protocol of its own.
//!
//! ## The payload shape
//!
//! `wire.md` names the `RECON` frame and leaves its bytes to this step, so they
//! are fixed here, in the same deterministic CBOR subset as every other frame
//! (`crate::cbor`). One encoding per message, because the client's half is a
//! separate implementation in `Sources/Sync` and the two are held to shared
//! vectors rather than to each other's good intentions.
//!
//! ```text
//! Message = [version: uint, ranges: [Range]]
//! Range   = [upper: uint, mode: uint, payload]
//!   mode 0  skip         payload = null      settled, nothing to do
//!   mode 1  fingerprint  payload = bytes(32) BLAKE3 over the items in the range
//!   mode 2  idlist       payload = [bytes(32)] every id in the range, ascending
//! ```
//!
//! Ranges cover the whole space with no holes: the first starts at zero, each
//! covers `[previous upper, upper)`, and the last ends at ``INFINITY``. A message
//! that does not cover the space is refused rather than interpreted, because a
//! partial cover would silently exclude envelopes from reconciliation and the
//! symptom would be one member missing messages nobody else is missing.

use crate::cbor::{self, CborError, Reader};

/// The payload version. Separate from `PROTOCOL_VERSION`: the frame set and the
/// reconciliation payload can move independently, and a client that speaks frame
/// version 1 with a reconciliation payload this build does not know is a client to
/// refuse precisely, not vaguely.
pub const RECON_VERSION: u64 = 1;

/// The open end of the last range. `u64::MAX` rather than a real head, so a
/// message stays valid while the relay accepts writes underneath it: a cover that
/// ended at the head observed a moment ago would exclude everything accepted
/// since.
pub const INFINITY: u64 = u64::MAX;

/// How many items a range may hold before the answer is fingerprints instead of
/// ids.
///
/// Sixteen. An id is 32 bytes, so a full id list is 512 bytes plus framing, which
/// is smaller than the extra round trip that splitting instead would cost. Above
/// it, splitting wins: eight fingerprints are 256 bytes and divide the differing
/// region by eight.
pub const IDLIST_LIMIT: usize = 16;

/// How many sub-ranges a differing range splits into.
///
/// Eight, so the recursion is base-8 rather than binary: a corpus of a hundred
/// thousand envelopes with one difference is three round trips rather than
/// seventeen, for 256 bytes a round.
pub const SPLIT_FACTOR: usize = 8;

/// The most ranges one message may carry.
///
/// A bound rather than a guideline: a peer that sent a million ranges would make
/// the relay do a million index scans for one frame, and the frame size limit
/// alone does not stop that because a skip range is three bytes.
pub const MAX_RANGES: usize = 1024;

/// The most ids one range may carry. Larger than ``IDLIST_LIMIT`` because a peer
/// is permitted to be more generous than this build would be, but bounded for the
/// reason above.
pub const MAX_IDS_PER_RANGE: usize = 4096;

/// One envelope, as reconciliation sees it: a cursor and a content address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Item {
    pub seq: u64,
    pub id: Id,
}

/// A content address. `[u8; 32]` rather than `Vec<u8>` because every id in this
/// module comes from `relay_envelope.hash`, which the schema constrains to 32
/// bytes, and a variable-width id would make the fingerprint's preimage
/// ambiguous.
pub type Id = [u8; 32];

/// What one range says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Settled. Either the fingerprints matched or the diff has been dealt with.
    Skip,
    /// A fingerprint over the sender's items in this range.
    Fingerprint(Id),
    /// Every id the sender holds in this range, ascending.
    IdList(Vec<Id>),
}

impl Mode {
    fn tag(&self) -> u64 {
        match self {
            Self::Skip => 0,
            Self::Fingerprint(_) => 1,
            Self::IdList(_) => 2,
        }
    }
}

/// One range of the sequence space, `[lower, upper)`, where `lower` is the
/// previous range's `upper` or zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    pub upper: u64,
    pub mode: Mode,
}

impl Range {
    pub fn new(upper: u64, mode: Mode) -> Self {
        Self { upper, mode }
    }
}

/// One reconciliation message: a cover of the sequence space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub ranges: Vec<Range>,
}

/// Why a reconciliation payload was refused.
///
/// Separate from ``CborError`` where the failure is about this format rather than
/// about CBOR, because the two map onto different wire codes: bad CBOR is
/// `reject/noncanonical_cbor` and a malformed cover is `reject/malformed_header`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReconError {
    #[error("payload is not canonical CBOR: {0}")]
    Cbor(#[from] CborError),
    #[error("payload carries reconciliation version {0}, this build speaks {RECON_VERSION}")]
    UnsupportedVersion(u64),
    #[error("payload carries {0} ranges, over the {MAX_RANGES} range limit")]
    TooManyRanges(usize),
    #[error("a range carries {0} ids, over the {MAX_IDS_PER_RANGE} id limit")]
    TooManyIds(usize),
    #[error("range mode {0} is not one this version speaks")]
    UnknownMode(u64),
    #[error("range upper bounds are not strictly ascending")]
    UnorderedRanges,
    #[error("the last range does not reach the open end, so the cover has a hole")]
    IncompleteCover,
    #[error("ids within a range are not strictly ascending")]
    UnorderedIds,
    #[error("payload carries no ranges at all")]
    Empty,
}

impl ReconError {
    /// The wire code a peer is answered with.
    pub fn code(&self) -> crate::frame::ErrorCode {
        match self {
            Self::Cbor(_) => crate::frame::ErrorCode::NoncanonicalCbor,
            _ => crate::frame::ErrorCode::MalformedHeader,
        }
    }
}

impl Message {
    /// A message whose every range is settled. What a converged side sends, and
    /// what a peer reads as "we are done".
    pub fn settled() -> Self {
        Self {
            ranges: vec![Range::new(INFINITY, Mode::Skip)],
        }
    }

    /// Whether every range is settled.
    pub fn is_settled(&self) -> bool {
        self.ranges.iter().all(|range| range.mode == Mode::Skip)
    }

    pub fn encode(&self) -> Vec<u8> {
        let ranges: Vec<Vec<u8>> = self
            .ranges
            .iter()
            .map(|range| {
                let payload = match &range.mode {
                    Mode::Skip => cbor::NULL.to_vec(),
                    Mode::Fingerprint(fingerprint) => cbor::bytes(fingerprint),
                    Mode::IdList(ids) => {
                        let items: Vec<Vec<u8>> = ids.iter().map(|id| cbor::bytes(id)).collect();
                        cbor::array(&items)
                    }
                };
                cbor::array(&[
                    cbor::uint(range.upper),
                    cbor::uint(range.mode.tag()),
                    payload,
                ])
            })
            .collect();
        cbor::array(&[cbor::uint(RECON_VERSION), cbor::array(&ranges)])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ReconError> {
        let mut reader = Reader::new(bytes);
        reader.array(2)?;
        let version = reader.uint()?;
        if version != RECON_VERSION {
            return Err(ReconError::UnsupportedVersion(version));
        }
        let count = reader.array_header()?;
        if count == 0 {
            return Err(ReconError::Empty);
        }
        if count > MAX_RANGES {
            return Err(ReconError::TooManyRanges(count));
        }
        let mut ranges = Vec::with_capacity(count);
        let mut previous: Option<u64> = None;
        for _ in 0..count {
            let range = decode_range(&mut reader)?;
            // Strictly ascending, so an empty range cannot be sent twice and two
            // peers cannot disagree about which of two identical bounds covers an
            // item.
            if previous.is_some_and(|previous| range.upper <= previous) {
                return Err(ReconError::UnorderedRanges);
            }
            previous = Some(range.upper);
            ranges.push(range);
        }
        // Checked after the loop rather than inside it: the hole this catches is a
        // property of the last range, and a cover that stopped short would
        // otherwise be read as "everything above this is settled".
        if previous != Some(INFINITY) {
            return Err(ReconError::IncompleteCover);
        }
        reader.finish()?;
        Ok(Self { ranges })
    }

    /// The ranges as `(lower, upper, mode)`, which is how both roles read them.
    pub fn spans(&self) -> Vec<(u64, u64, &Mode)> {
        let mut lower = 0u64;
        let mut out = Vec::with_capacity(self.ranges.len());
        for range in &self.ranges {
            out.push((lower, range.upper, &range.mode));
            lower = range.upper;
        }
        out
    }
}

fn decode_range(reader: &mut Reader<'_>) -> Result<Range, ReconError> {
    reader.array(3)?;
    let upper = reader.uint()?;
    let tag = reader.uint()?;
    let mode = match tag {
        0 => {
            // `optional_bytes` is the only reader that accepts `null`, and a skip
            // range carrying bytes instead is a peer sending a payload for a mode
            // that has none.
            match reader.optional_bytes()? {
                None => Mode::Skip,
                Some(_) => {
                    return Err(ReconError::Cbor(CborError::TypeMismatch {
                        expected: "null",
                    }))
                }
            }
        }
        1 => Mode::Fingerprint(fixed(reader.bytes_of(32)?)),
        2 => {
            let count = reader.array_header()?;
            if count > MAX_IDS_PER_RANGE {
                return Err(ReconError::TooManyIds(count));
            }
            let mut ids: Vec<Id> = Vec::with_capacity(count);
            for _ in 0..count {
                let id = fixed(reader.bytes_of(32)?);
                // Ascending and unique, so one set has one encoding. Without this
                // a peer could send the same id twice and two implementations
                // would disagree about the fingerprint of what they hold.
                if ids.last().is_some_and(|last| &id <= last) {
                    return Err(ReconError::UnorderedIds);
                }
                ids.push(id);
            }
            Mode::IdList(ids)
        }
        other => return Err(ReconError::UnknownMode(other)),
    };
    Ok(Range { upper, mode })
}

/// A content address from a slice of database bytes.
///
/// Any slice, saturating: `relay_envelope.hash` is constrained to 32 bytes by the
/// schema, so a shorter one cannot be stored, and a fallible conversion here would
/// add an arm reachable only from a corrupted database.
pub fn id_from_slice(bytes: &[u8]) -> Id {
    let mut out = [0u8; 32];
    for (slot, byte) in out.iter_mut().zip(bytes) {
        *slot = *byte;
    }
    out
}

/// A 32 byte vector as an array.
///
/// Infallible by construction: every caller has just come through
/// `Reader::bytes_of(32)`, which refuses any other length. Written as a fold
/// rather than `try_into().unwrap()` so there is no panic arm for the coverage
/// floor to have to reach.
fn fixed(bytes: Vec<u8>) -> Id {
    let mut out = [0u8; 32];
    for (slot, byte) in out.iter_mut().zip(bytes) {
        *slot = byte;
    }
    out
}

/// The fingerprint over a set of items.
///
/// BLAKE3 over a domain label, the count, and each item's `seq` and `id`. The
/// count is inside the preimage because a fingerprint over concatenated ids alone
/// would let two different sets collide trivially by construction, and the label
/// is there because every other hash in this system has one and an unlabelled hash
/// is one somebody can replay into a different position later.
///
/// `seq` is included as well as `id`: an envelope the relay renumbered would
/// otherwise fingerprint identically, and a renumbering is exactly the kind of
/// server-side rewrite the client is entitled to notice.
pub fn fingerprint(items: &[Item]) -> Id {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"weald negentropy fingerprint v1");
    hasher.update(&(items.len() as u64).to_be_bytes());
    for item in items {
        hasher.update(&item.seq.to_be_bytes());
        hasher.update(&item.id);
    }
    *hasher.finalize().as_bytes()
}

/// The items inside `[lower, upper)`, given a slice sorted by `seq`.
///
/// Binary search rather than a scan, because the relay does this once per range
/// per round and a linear scan would make a thousand-range message quadratic.
pub fn items_in(items: &[Item], lower: u64, upper: u64) -> &[Item] {
    let start = items.partition_point(|item| item.seq < lower);
    let end = items.partition_point(|item| item.seq < upper);
    &items[start..end]
}

/// Every id in a slice of items, ascending, deduplicated.
///
/// Sorted by id rather than by `seq` because that is the order the wire format
/// fixes for an id list, and deduplicated because two groups may hold the same
/// content address at two sequence numbers only if the relay renumbered, in which
/// case sending it twice would break the encoding rule rather than reporting the
/// renumbering. The renumbering is caught by the fingerprint, which includes
/// `seq`.
pub fn ids_of(items: &[Item]) -> Vec<Id> {
    let mut ids: Vec<Id> = items.iter().map(|item| item.id).collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

mod reconcile;
pub use reconcile::{advance, initiate, respond, ClientStep, Response};
