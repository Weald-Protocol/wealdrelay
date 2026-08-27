// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The object a `HANDSHAKE` frame's payload actually is.
//!
//! `specs/backend/relay/wire.md` calls a `HANDSHAKE` payload "one MLS handshake
//! message", and read literally that is what this file used not to exist for.
//! The shipping client does not put a bare MLS message on that frame: every
//! member publishes and reads `Sources/Sync/GroupSession.swift`'s
//! `HandshakeRecord`, a two-element deterministic CBOR array of a kind tag and a
//! byte string, because a group carries three other things on the same ordered
//! per-group stream that are not MLS messages at all: a sealed `GroupInfo` for an
//! entitled joiner, a joiner's signed claim beside the commit it belongs to, and
//! the `open` group's sealed history.
//!
//! Any Rust participant in a real workspace group therefore has to speak that
//! framing, and `weald-agent-gateway` did not. It handed the frame's payload
//! straight to OpenMLS, which is correct against a publisher that also writes
//! bare messages and correct against nothing a person's Mac has ever sent: a
//! Welcome from a real member arrives CBOR-wrapped and does not parse as a
//! Welcome, so the gateway is never welcomed, and every later commit is dropped
//! for the same reason. Nothing caught it because the only publisher it had ever
//! been tested against was another Rust process writing bare bytes, which is two
//! halves of one implementation agreeing with each other.
//!
//! The tags are the Swift enum's, and they are wire values: `mls` is 0,
//! `standing` is 1, `claim` is 2 and `history` is 3. Note that the tag order is
//! not the declaration order over there, which is exactly why they are written
//! out here rather than derived from one.

use crate::agent_cbor::{self as cbor, CborError, Reader};

/// The kind tags, as they travel.
pub const TAG_MLS: u64 = 0;
pub const TAG_STANDING: u64 = 1;
pub const TAG_CLAIM: u64 = 2;
pub const TAG_HISTORY: u64 = 3;

/// One record on a group's handshake stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeRecord {
    /// One MLS message, for every member to process.
    Mls(Vec<u8>),
    /// A `GroupInfo` sealed under the enrolment key, for an entitled joiner.
    Standing(Vec<u8>),
    /// A joiner's signed claim, beside the commit it belongs to.
    Claim(Vec<u8>),
    /// The `open` group's sealed per-epoch history.
    History(Vec<u8>),
    /// A kind this build does not know.
    ///
    /// Kept rather than refused, because `wire.md` says an unknown kind is stored
    /// and ignored, and a participant that treated one as a protocol error would
    /// disconnect itself the first time a newer client published something.
    Unknown { tag: u64, payload: Vec<u8> },
}

impl HandshakeRecord {
    /// The MLS message this record carries, if it carries one.
    ///
    /// `None` for every other kind, and that is the whole point of the type: a
    /// sealed `GroupInfo` handed to OpenMLS is not an error to report, it is
    /// somebody else's record on a stream this participant shares.
    pub fn mls_message(&self) -> Option<&[u8]> {
        match self {
            HandshakeRecord::Mls(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn tag(&self) -> u64 {
        match self {
            HandshakeRecord::Mls(_) => TAG_MLS,
            HandshakeRecord::Standing(_) => TAG_STANDING,
            HandshakeRecord::Claim(_) => TAG_CLAIM,
            HandshakeRecord::History(_) => TAG_HISTORY,
            HandshakeRecord::Unknown { tag, .. } => *tag,
        }
    }

    fn payload(&self) -> &[u8] {
        match self {
            HandshakeRecord::Mls(bytes)
            | HandshakeRecord::Standing(bytes)
            | HandshakeRecord::Claim(bytes)
            | HandshakeRecord::History(bytes)
            | HandshakeRecord::Unknown { payload: bytes, .. } => bytes,
        }
    }

    /// Deterministic CBOR, byte for byte what `HandshakeRecord.encoded` writes.
    pub fn encode(&self) -> Vec<u8> {
        cbor::array(&[cbor::uint(self.tag()), cbor::bytes(self.payload())])
    }

    /// Read one record. Refuses anything that is not the two-element array the
    /// framing is, so a bare MLS message is a decode failure rather than being
    /// mistaken for a record whose first byte happens to look like a small int.
    pub fn decode(bytes: &[u8]) -> Result<Self, CborError> {
        let mut reader = Reader::new(bytes);
        let count = reader.array_count()?;
        if count != 2 {
            return Err(CborError::WrongArrayCount {
                expected: 2,
                got: count,
            });
        }
        let tag = reader.uint()?;
        let payload = reader.bytes()?;
        reader.require_end()?;
        Ok(match tag {
            TAG_MLS => HandshakeRecord::Mls(payload),
            TAG_STANDING => HandshakeRecord::Standing(payload),
            TAG_CLAIM => HandshakeRecord::Claim(payload),
            TAG_HISTORY => HandshakeRecord::History(payload),
            other => HandshakeRecord::Unknown {
                tag: other,
                payload,
            },
        })
    }
}

/// One MLS message, framed for the wire. The only thing a participant that is not
/// the workspace's own client ever needs to publish.
pub fn mls(message: &[u8]) -> Vec<u8> {
    HandshakeRecord::Mls(message.to_vec()).encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_round_trips_through_its_own_framing() {
        for record in [
            HandshakeRecord::Mls(b"a commit".to_vec()),
            HandshakeRecord::Standing(b"a sealed group info".to_vec()),
            HandshakeRecord::Claim(b"a signed claim".to_vec()),
            HandshakeRecord::History(b"sealed epochs".to_vec()),
            HandshakeRecord::Unknown {
                tag: 9,
                payload: b"a newer client".to_vec(),
            },
        ] {
            let encoded = record.encode();
            assert_eq!(HandshakeRecord::decode(&encoded), Ok(record.clone()));
            assert_eq!(
                HandshakeRecord::decode(&encoded).unwrap().tag(),
                record.tag()
            );
        }
    }

    /// The framing, pinned to bytes rather than to itself. A round trip proves
    /// this file agrees with this file; these are the bytes the Swift encoder
    /// writes for the same record, and they are what the two implementations
    /// have to agree on.
    #[test]
    fn the_encoding_is_the_two_element_array_the_client_writes() {
        // CBOR: 0x82 (array of 2), 0x00 (uint 0), 0x43 (bytes of 3) "abc".
        assert_eq!(mls(b"abc"), vec![0x82, 0x00, 0x43, b'a', b'b', b'c']);
        assert_eq!(
            HandshakeRecord::History(vec![]).encode(),
            vec![0x82, 0x03, 0x40]
        );
    }

    /// Only `Mls` is an MLS message. A participant that fed the others to OpenMLS
    /// would be handing it a sealed `GroupInfo` and reporting the refusal.
    #[test]
    fn only_the_mls_kind_offers_a_message() {
        assert_eq!(
            HandshakeRecord::Mls(b"m".to_vec()).mls_message(),
            Some(&b"m"[..])
        );
        assert_eq!(HandshakeRecord::Standing(b"g".to_vec()).mls_message(), None);
        assert_eq!(HandshakeRecord::Claim(b"c".to_vec()).mls_message(), None);
        assert_eq!(HandshakeRecord::History(b"h".to_vec()).mls_message(), None);
        assert_eq!(
            HandshakeRecord::Unknown {
                tag: 7,
                payload: b"u".to_vec()
            }
            .mls_message(),
            None
        );
    }

    /// A bare MLS message is not a record, and saying so is what stops a lenient
    /// decoder from becoming a second framing nobody chose.
    #[test]
    fn a_bare_message_is_refused_rather_than_guessed_at() {
        assert!(HandshakeRecord::decode(b"a raw welcome").is_err());
        assert!(HandshakeRecord::decode(&[]).is_err());
        // An array of the right shape with a trailing byte is not the framing.
        assert!(HandshakeRecord::decode(&[0x82, 0x00, 0x41, b'x', 0x00]).is_err());
        // Three elements is not the framing either.
        assert!(HandshakeRecord::decode(&[0x83, 0x00, 0x40, 0x40]).is_err());
        // The payload has to be a byte string.
        assert!(HandshakeRecord::decode(&[0x82, 0x00, 0x00]).is_err());
    }
}
