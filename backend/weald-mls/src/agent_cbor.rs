// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The deterministic CBOR subset the agent payloads travel in, as Rust reads it.
//!
//! # The mirror, and why it is written twice
//!
//! `Sources/WealdRelayNetworking/DeterministicCBOR.swift` and its agent extension
//! are the same subset in Swift. This is not shared code and it is not generated
//! from it. `specs/agents/networked/protocol.md` requires every rule to be enforced
//! by both codecs against one corpus, and a shared implementation would satisfy the
//! letter of that while defeating its purpose: a single misreading of RFC 8949
//! would then be true on both sides and the corpus would agree with itself.
//!
//! So the rules are written from the spec a second time, and the corpus in
//! `Tests/Fixtures/agents/` is laid down by a third implementation
//! (`scripts/agents-vectors.py`) that consults neither. Three readings that agree
//! on every byte is a claim worth making. Two halves of one reading is not.
//!
//! # The subset
//!
//! Unsigned integers, byte strings, text strings, arrays, and maps with unsigned
//! integer keys. Nothing else, and every omission is deliberate: a floating point
//! number, an indefinite length, a tag or a negative integer is a place two
//! encoders could differ, and a payload signature stops meaning anything the moment
//! they do.
//!
//! Three rules carry the determinism, and each is a refusal rather than a
//! normalisation:
//!
//! - **Shortest-form heads.** `0x18 0x01` is one, and so is `0x01`. Accepting both
//!   gives one card two encodings and therefore two `cardHash` values, so the long
//!   form of a small number is a decode error.
//! - **Strictly ascending map keys.** RFC 8949's canonical form sorts them; merely
//!   *tolerating* an unsorted map accepts a second encoding of one card. Out of
//!   order and duplicated are the same defect and share one error.
//! - **Closed schemas.** An unknown key is refused, never skipped. A codec that
//!   ignores what it does not understand will one day ignore a field somebody added
//!   on purpose, and for `agent.card` that field is how a system prompt reaches
//!   every member of a workspace.

use std::fmt;

/// Why a decode refused, and the closed reason code it maps to.
///
/// The reason codes are the cross-language contract:
/// `Tests/Fixtures/agents/manifest.json` names one per rejected vector and both
/// codecs must produce it. "Both refused it" would otherwise be satisfied by two
/// codecs refusing the same bytes for unrelated reasons, which is not agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborError {
    /// The item claimed more bytes than the message carries.
    Truncated,
    /// Bytes remain after the last field the schema names.
    Trailing(usize),
    /// A head that is not in its shortest form.
    NonCanonicalInteger,
    /// A major type this subset does not carry.
    UnsupportedMajor(u8),
    /// Additional info 28 to 30, which RFC 8949 reserves.
    ReservedAdditionalInfo(u8),
    /// A simple value other than the one the envelope codec carries.
    UnsupportedSimple(u64),
    /// The item at the cursor is not the major type the slot names.
    TypeMismatch(&'static str),
    /// A fixed-width byte string of the wrong width.
    WrongLength { expected: usize, got: usize },
    /// A fixed-count array of the wrong count.
    WrongArrayCount { expected: usize, got: usize },
    /// A text string whose bytes are not UTF-8. Refused rather than replaced with
    /// U+FFFD: a lossy decode gives two inputs one value, and the card hash would
    /// then cover something the signer never wrote.
    InvalidUtf8,
    /// A map key that does not follow the one before it.
    MapKeysNotAscending { previous: u64, next: u64 },
    /// A key outside the closed schema.
    UnknownKey(u64),
    /// A schema slot the decode required and the map did not carry.
    MissingKey(u64),
    /// An item nested deeper than any legitimate payload. The structural skip
    /// used to recurse one stack frame per level with no ceiling, so a member's
    /// signed body chose its own recursion depth and overflowed the stack
    /// (WEALD-L257).
    TooDeep,
}

impl CborError {
    /// The closed reason code, matching `AgentCodecReason` in Swift.
    pub fn reason(&self) -> &'static str {
        match self {
            CborError::Truncated => "codec.truncated",
            CborError::Trailing(_) => "codec.trailing",
            CborError::NonCanonicalInteger => "codec.noncanonical.int",
            CborError::UnsupportedMajor(_) => "codec.major.unsupported",
            CborError::ReservedAdditionalInfo(_) => "codec.additionalinfo.reserved",
            CborError::UnsupportedSimple(_) => "codec.simple.unsupported",
            CborError::TypeMismatch(_) => "codec.type.mismatch",
            CborError::WrongLength { .. } => "codec.length.wrong",
            CborError::WrongArrayCount { .. } => "codec.arraycount.wrong",
            CborError::InvalidUtf8 => "codec.utf8.invalid",
            CborError::MapKeysNotAscending { .. } => "codec.mapkeys.order",
            CborError::UnknownKey(_) => "codec.key.unknown",
            CborError::MissingKey(_) => "codec.key.missing",
            CborError::TooDeep => "codec.depth",
        }
    }
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CborError::Truncated => write!(f, "CBOR ended inside an item"),
            CborError::Trailing(n) => write!(f, "{n} bytes remain after the last field"),
            CborError::NonCanonicalInteger => {
                write!(f, "CBOR integer is not in its shortest form")
            }
            CborError::UnsupportedMajor(m) => {
                write!(f, "CBOR major type {m} is not carried by this format")
            }
            CborError::ReservedAdditionalInfo(a) => {
                write!(f, "CBOR additional info {a} is reserved")
            }
            CborError::UnsupportedSimple(v) => {
                write!(f, "CBOR simple value {v} is not carried by this format")
            }
            CborError::TypeMismatch(expected) => write!(f, "CBOR item is not a {expected}"),
            CborError::WrongLength { expected, got } => {
                write!(f, "CBOR byte string is {got} bytes, expected {expected}")
            }
            CborError::WrongArrayCount { expected, got } => {
                write!(f, "CBOR array holds {got} items, expected {expected}")
            }
            CborError::InvalidUtf8 => write!(f, "CBOR text string is not valid UTF-8"),
            CborError::MapKeysNotAscending { previous, next } => write!(
                f,
                "CBOR map key {next} does not follow {previous} in ascending order"
            ),
            CborError::UnknownKey(k) => {
                write!(f, "CBOR map carries key {k}, which is outside the schema")
            }
            CborError::MissingKey(k) => write!(f, "CBOR map is missing required key {k}"),
            CborError::TooDeep => write!(
                f,
                "CBOR item nests deeper than the {} levels this codec walks",
                Reader::MAX_SKIP_DEPTH
            ),
        }
    }
}

impl std::error::Error for CborError {}

pub type Result<T> = std::result::Result<T, CborError>;

// ------------------------------------------------------------------- encoding

/// One head in shortest form. Major type in the top three bits, argument below.
fn head(major: u8, value: u64) -> Vec<u8> {
    let tag = major << 5;
    if value < 24 {
        return vec![tag | value as u8];
    }
    if value <= u8::MAX as u64 {
        return vec![tag | 24, value as u8];
    }
    if value <= u16::MAX as u64 {
        let mut out = vec![tag | 25];
        out.extend_from_slice(&(value as u16).to_be_bytes());
        return out;
    }
    if value <= u32::MAX as u64 {
        let mut out = vec![tag | 26];
        out.extend_from_slice(&(value as u32).to_be_bytes());
        return out;
    }
    let mut out = vec![tag | 27];
    out.extend_from_slice(&value.to_be_bytes());
    out
}

pub fn uint(value: u64) -> Vec<u8> {
    head(0, value)
}

pub fn bytes(value: &[u8]) -> Vec<u8> {
    let mut out = head(2, value.len() as u64);
    out.extend_from_slice(value);
    out
}

pub fn text(value: &str) -> Vec<u8> {
    let mut out = head(3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
    out
}

/// An array of already-encoded items.
pub fn array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = head(4, items.len() as u64);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// A map of already-encoded values under unsigned integer keys.
///
/// Sorted here rather than trusted from the caller, for the same reason the Swift
/// encoder sorts: "the caller passed them in order" is the invariant that rots. A
/// duplicate key is a programming error rather than a wire condition, so it panics
/// instead of returning an error. Two values in one schema slot must never reach
/// the wire, where which one wins would be answered differently by two
/// implementations.
pub fn map(pairs: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut sorted: Vec<&(u64, Vec<u8>)> = pairs.iter().collect();
    sorted.sort_by_key(|p| p.0);
    for window in sorted.windows(2) {
        assert!(
            window[0].0 != window[1].0,
            "duplicate CBOR map key {}: two values in one schema slot",
            window[0].0
        );
    }
    let mut out = head(5, sorted.len() as u64);
    for (key, value) in sorted {
        out.extend_from_slice(&uint(*key));
        out.extend_from_slice(value);
    }
    out
}

// ------------------------------------------------------------------- decoding

/// A cursor over one message.
pub struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, offset: 0 }
    }

    /// One head, with the shortest-form rule. The single place both the major type
    /// and the canonical-integer refusal are decided, so no reader can forget
    /// either.
    fn head(&self) -> Result<(u8, u64, usize)> {
        let start = self.offset;
        let initial = *self.data.get(start).ok_or(CborError::Truncated)?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        if info < 24 {
            return Ok((major, u64::from(info), start + 1));
        }
        if info >= 28 {
            return Err(CborError::ReservedAdditionalInfo(info));
        }
        let width = 1usize << (info - 24);
        if start + width >= self.data.len() {
            return Err(CborError::Truncated);
        }
        let mut value: u64 = 0;
        for i in 0..width {
            value = (value << 8) | u64::from(self.data[start + 1 + i]);
        }
        let minimum: u64 = match width {
            1 => 24,
            2 => u64::from(u8::MAX) + 1,
            4 => u64::from(u16::MAX) + 1,
            _ => u64::from(u32::MAX) + 1,
        };
        if value < minimum {
            return Err(CborError::NonCanonicalInteger);
        }
        Ok((major, value, start + 1 + width))
    }

    /// The argument of a head of a given major type, with the length sanity check
    /// that keeps an announced count from becoming an allocation.
    fn counted(&mut self, major: u8, name: &'static str) -> Result<u64> {
        let (found, argument, next) = self.head()?;
        if found != major {
            return Err(CborError::TypeMismatch(name));
        }
        // One item is at least one byte, so the bytes that remain are a sound upper
        // bound on any announced count. Checking it here is what stops a nine byte
        // message from asking for a gigabyte.
        if argument > (self.data.len() - next) as u64 {
            return Err(CborError::Truncated);
        }
        self.offset = next;
        Ok(argument)
    }

    pub fn uint(&mut self) -> Result<u64> {
        let (major, value, next) = self.head()?;
        if major != 0 {
            return Err(CborError::TypeMismatch("unsigned integer"));
        }
        self.offset = next;
        Ok(value)
    }

    pub fn bytes(&mut self) -> Result<Vec<u8>> {
        let length = self.counted(2, "byte string")? as usize;
        let start = self.offset;
        self.offset = start + length;
        Ok(self.data[start..self.offset].to_vec())
    }

    /// A byte string of a stated width. An `agentID` that is not 32 bytes is not an
    /// `agentID`, and accepting one would make the fixed widths in `protocol.md`
    /// documentation rather than rules.
    pub fn bytes_exact(&mut self, expected: usize) -> Result<Vec<u8>> {
        let value = self.bytes()?;
        if value.len() != expected {
            return Err(CborError::WrongLength {
                expected,
                got: value.len(),
            });
        }
        Ok(value)
    }

    pub fn text(&mut self) -> Result<String> {
        let length = self.counted(3, "text string")? as usize;
        let start = self.offset;
        self.offset = start + length;
        String::from_utf8(self.data[start..self.offset].to_vec())
            .map_err(|_| CborError::InvalidUtf8)
    }

    pub fn array_count(&mut self) -> Result<usize> {
        Ok(self.counted(4, "array")? as usize)
    }

    pub fn map_count(&mut self) -> Result<usize> {
        Ok(self.counted(5, "map")? as usize)
    }

    pub fn at_end(&self) -> bool {
        self.offset == self.data.len()
    }

    pub fn require_end(&self) -> Result<()> {
        if self.at_end() {
            Ok(())
        } else {
            Err(CborError::Trailing(self.data.len() - self.offset))
        }
    }

    /// Walk one whole item of any type this subset carries.
    ///
    /// The depth budget is the whole point (WEALD-L257): every array and map
    /// level used to cost one stack frame with no ceiling, and one byte of input
    /// (`0x81`, a single-item array) bought one level, so a body well inside the
    /// 1 MiB frame ceiling could exhaust any stack this process runs on. The cap
    /// is far above anything the agent schemas produce — a card or invoke is one
    /// map of scalars, byte strings and one shallow list — and far below what a
    /// stack survives. It matches `CBOR.Reader.maxSkipDepth` in Swift, because
    /// the reason vocabulary is the cross-language contract and both codecs must
    /// refuse the same bytes with the same word.
    pub const MAX_SKIP_DEPTH: usize = 32;

    fn skip_item(&mut self) -> Result<()> {
        self.skip_item_bounded(0)
    }

    fn skip_item_bounded(&mut self, depth: usize) -> Result<()> {
        if depth > Self::MAX_SKIP_DEPTH {
            return Err(CborError::TooDeep);
        }
        let (major, argument, next) = self.head()?;
        match major {
            0 => {
                self.offset = next;
            }
            2 | 3 => {
                if argument > (self.data.len() - next) as u64 {
                    return Err(CborError::Truncated);
                }
                self.offset = next + argument as usize;
            }
            4 => {
                self.offset = next;
                for _ in 0..argument {
                    self.skip_item_bounded(depth + 1)?;
                }
            }
            5 => {
                self.offset = next;
                for _ in 0..argument {
                    self.skip_item_bounded(depth + 1)?;
                    self.skip_item_bounded(depth + 1)?;
                }
            }
            7 => {
                if argument != 22 {
                    return Err(CborError::UnsupportedSimple(argument));
                }
                self.offset = next;
            }
            other => return Err(CborError::UnsupportedMajor(other)),
        }
        Ok(())
    }

    /// One whole item at the cursor, as its encoded bytes.
    ///
    /// Skipping by structure rather than by length is what keeps the strictness: a
    /// nested item that does not decode fails here, rather than being copied out as
    /// opaque bytes and never looked at again.
    pub fn raw_value(&mut self) -> Result<Vec<u8>> {
        let start = self.offset;
        self.skip_item()?;
        Ok(self.data[start..self.offset].to_vec())
    }

    /// A whole map read into schema slots, refusing any key the schema does not
    /// name and any key out of ascending order.
    ///
    /// This is the function `protocol.md`'s "walk every key and fail on anything
    /// outside the schema" is written against, and the reason `agent.card` encodes
    /// as a map at all: position cannot be walked that way, because an extra field
    /// is indistinguishable from a longer array.
    pub fn schema_map(&mut self, schema: &[u64]) -> Result<Vec<(u64, Vec<u8>)>> {
        let pairs = self.map_count()?;
        let mut out: Vec<(u64, Vec<u8>)> = Vec::with_capacity(pairs);
        let mut previous: Option<u64> = None;
        for _ in 0..pairs {
            let key = self.uint()?;
            if let Some(previous) = previous {
                if key <= previous {
                    return Err(CborError::MapKeysNotAscending {
                        previous,
                        next: key,
                    });
                }
            }
            previous = Some(key);
            if !schema.contains(&key) {
                return Err(CborError::UnknownKey(key));
            }
            out.push((key, self.raw_value()?));
        }
        Ok(out)
    }
}

/// One slot out of a decoded schema map, if the map carried it.
///
/// Separate from `slot` because `org` is the one schema slot whose absence is legal,
/// and expressing that as `match slot(..) { Err(MissingKey) => None, Err(other) =>
/// .. }` left an arm nothing could reach: `slot` returns no other error. An
/// unreachable arm is not a safety net, it is a line no test can cover and a reader
/// has to work out is dead.
pub fn optional_slot(slots: &[(u64, Vec<u8>)], key: u64) -> Option<&[u8]> {
    slots
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.as_slice())
}

/// One slot out of a decoded schema map, or `MissingKey`.
pub fn slot(slots: &[(u64, Vec<u8>)], key: u64) -> Result<&[u8]> {
    optional_slot(slots, key).ok_or(CborError::MissingKey(key))
}

/// Read one whole item out of a slot and assert nothing follows it.
///
/// The `require_end` is not decoration. A slot's bytes came out of `raw_value`,
/// which walked exactly one item, so trailing bytes inside a slot are impossible
/// today; asserting it anyway means a future reader that returns a slice by length
/// rather than by structure cannot silently start admitting them.
pub fn in_slot<T, F>(slots: &[(u64, Vec<u8>)], key: u64, read: F) -> Result<T>
where
    F: FnOnce(&mut Reader<'_>) -> Result<T>,
{
    let raw = slot(slots, key)?;
    let mut reader = Reader::new(raw);
    let value = read(&mut reader)?;
    reader.require_end()?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --------------------------------------------------------------- encoding

    #[test]
    fn heads_use_the_shortest_form_at_every_width() {
        assert_eq!(uint(0), vec![0x00]);
        assert_eq!(uint(23), vec![0x17]);
        assert_eq!(uint(24), vec![0x18, 0x18]);
        assert_eq!(uint(255), vec![0x18, 0xff]);
        assert_eq!(uint(256), vec![0x19, 0x01, 0x00]);
        assert_eq!(uint(65_535), vec![0x19, 0xff, 0xff]);
        assert_eq!(uint(65_536), vec![0x1a, 0x00, 0x01, 0x00, 0x00]);
        assert_eq!(uint(u32::MAX as u64), vec![0x1a, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            uint(u32::MAX as u64 + 1),
            vec![0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn byte_text_array_and_map_encode() {
        assert_eq!(bytes(&[1, 2, 3]), vec![0x43, 1, 2, 3]);
        assert_eq!(text("hi"), vec![0x62, b'h', b'i']);
        assert_eq!(array(&[uint(1), uint(2)]), vec![0x82, 0x01, 0x02]);
        assert_eq!(
            map(&[(2, uint(9)), (1, uint(8))]),
            vec![0xa2, 0x01, 0x08, 0x02, 0x09]
        );
        assert_eq!(array(&[]), vec![0x80]);
        assert_eq!(map(&[]), vec![0xa0]);
    }

    #[test]
    fn a_long_text_uses_a_wider_head() {
        let long = "n".repeat(300);
        let encoded = text(&long);
        assert_eq!(encoded[0], 0x79);
        assert_eq!(encoded.len(), 3 + 300);
    }

    /// The duplicate-key guard, caught rather than declared with `#[should_panic]`.
    ///
    /// Two reasons. It asserts the message, which `#[should_panic(expected:)]` only
    /// substring-matches and which is what a person debugging actually reads. And a
    /// test function that panics never reaches its own closing brace, so llvm-cov
    /// records that line as uncovered and the 100 percent floor becomes unreachable
    /// for a reason that has nothing to do with the code under test.
    #[test]
    fn a_duplicate_key_is_a_programming_error() {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let caught = std::panic::catch_unwind(|| map(&[(1, uint(1)), (1, uint(2))]));
        std::panic::set_hook(previous);

        let payload = caught.expect_err("a duplicate key must not encode");
        let message = payload
            .downcast_ref::<String>()
            .expect("the guard panics with a formatted message");
        assert!(
            message.contains("duplicate CBOR map key 1"),
            "the guard must name the slot: {message}"
        );
    }

    // --------------------------------------------------------------- decoding

    #[test]
    fn round_trips() {
        let mut r = Reader::new(&[0x18, 0x2a]);
        assert_eq!(r.uint().unwrap(), 42);
        assert!(r.at_end());

        let encoded = bytes(&[7, 7, 7]);
        assert_eq!(Reader::new(&encoded).bytes().unwrap(), vec![7, 7, 7]);

        let encoded = text("Résearcher 🜛");
        assert_eq!(Reader::new(&encoded).text().unwrap(), "Résearcher 🜛");

        let encoded = array(&[uint(1), uint(2), uint(3)]);
        let mut r = Reader::new(&encoded);
        assert_eq!(r.array_count().unwrap(), 3);
        assert_eq!(
            (r.uint().unwrap(), r.uint().unwrap(), r.uint().unwrap()),
            (1, 2, 3)
        );
        r.require_end().unwrap();
    }

    #[test]
    fn bytes_exact_holds_the_width() {
        let encoded = bytes(&[0u8; 32]);
        assert_eq!(Reader::new(&encoded).bytes_exact(32).unwrap().len(), 32);
        assert_eq!(
            Reader::new(&encoded).bytes_exact(16).unwrap_err(),
            CborError::WrongLength {
                expected: 16,
                got: 32
            }
        );
    }

    #[test]
    fn every_structural_refusal_fires() {
        // Truncated: an empty message, and a head that promises bytes it lacks.
        assert_eq!(Reader::new(&[]).uint().unwrap_err(), CborError::Truncated);
        assert_eq!(
            Reader::new(&[0x19, 0x01]).uint().unwrap_err(),
            CborError::Truncated
        );
        assert_eq!(
            Reader::new(&[0x43, 1, 2]).bytes().unwrap_err(),
            CborError::Truncated
        );
        // Non-canonical: 1 in a one-byte argument, at each width.
        for head in [
            vec![0x18, 0x01],
            vec![0x19, 0x00, 0x01],
            vec![0x1a, 0x00, 0x00, 0x00, 0x01],
            vec![0x1b, 0, 0, 0, 0, 0, 0, 0, 1],
        ] {
            assert_eq!(
                Reader::new(&head).uint().unwrap_err(),
                CborError::NonCanonicalInteger
            );
        }
        // Reserved additional info.
        assert_eq!(
            Reader::new(&[0x1c]).uint().unwrap_err(),
            CborError::ReservedAdditionalInfo(28)
        );
        // Type mismatches, one per reader.
        assert_eq!(
            Reader::new(&text("x")).uint().unwrap_err(),
            CborError::TypeMismatch("unsigned integer")
        );
        assert_eq!(
            Reader::new(&uint(1)).bytes().unwrap_err(),
            CborError::TypeMismatch("byte string")
        );
        assert_eq!(
            Reader::new(&uint(1)).text().unwrap_err(),
            CborError::TypeMismatch("text string")
        );
        assert_eq!(
            Reader::new(&uint(1)).array_count().unwrap_err(),
            CborError::TypeMismatch("array")
        );
        assert_eq!(
            Reader::new(&uint(1)).map_count().unwrap_err(),
            CborError::TypeMismatch("map")
        );
        // Invalid UTF-8 in a text string.
        assert_eq!(
            Reader::new(&[0x62, 0xff, 0xfe]).text().unwrap_err(),
            CborError::InvalidUtf8
        );
        // Trailing bytes.
        let mut r = Reader::new(&[0x01, 0x02]);
        r.uint().unwrap();
        assert_eq!(r.require_end().unwrap_err(), CborError::Trailing(1));
    }

    /// An announced count larger than the message is refused before anything is
    /// allocated for it. The bug this prevents is a nine byte message that asks for
    /// four gigabytes.
    #[test]
    fn an_announced_count_larger_than_the_message_is_refused() {
        assert_eq!(
            Reader::new(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
                .array_count()
                .unwrap_err(),
            CborError::Truncated
        );
    }

    #[test]
    fn skip_item_walks_every_type_this_subset_carries() {
        let nested = map(&[
            (1, uint(1)),
            (2, bytes(&[9])),
            (3, text("x")),
            (4, array(&[uint(1), map(&[(1, uint(1))])])),
            (5, vec![0xf6]),
        ]);
        let mut r = Reader::new(&nested);
        assert_eq!(r.raw_value().unwrap(), nested);
        r.require_end().unwrap();
    }

    /// A depth bomb under a valid schema key is refused with the depth reason
    /// before any type check runs, at a nesting no stack could have survived
    /// (WEALD-L257). One byte per level means 100_000 levels fits inside the
    /// relay's 1 MiB frame ceiling, which is exactly how a member's signed body
    /// used to choose its own recursion depth.
    #[test]
    fn a_depth_bomb_is_refused_not_walked() {
        let levels = 100_000;
        let mut bomb = Vec::with_capacity(levels + 1);
        bomb.extend(std::iter::repeat_n(0x81, levels - 1));
        bomb.push(0x80);
        let encoded = map(&[(11, bomb)]);
        let mut reader = Reader::new(&encoded);
        assert_eq!(
            reader.schema_map(&[11]).unwrap_err().reason(),
            "codec.depth"
        );
    }

    /// The honest boundary: nesting at the cap decodes. A cap that refused
    /// legitimate structure would be its own outage.
    #[test]
    fn nesting_at_the_cap_still_decodes() {
        let mut honest = array(&[uint(1)]);
        for _ in 1..Reader::MAX_SKIP_DEPTH {
            honest = array(&[honest]);
        }
        let encoded = map(&[(11, honest)]);
        let slots = Reader::new(&encoded).schema_map(&[11]).unwrap();
        assert_eq!(slots.len(), 1);
    }

    #[test]
    fn skip_item_refuses_what_the_subset_does_not_carry() {
        // Major type 1, a negative integer.
        assert_eq!(
            Reader::new(&[0x20]).raw_value().unwrap_err(),
            CborError::UnsupportedMajor(1)
        );
        // Major type 6, a tag.
        assert_eq!(
            Reader::new(&[0xc0]).raw_value().unwrap_err(),
            CborError::UnsupportedMajor(6)
        );
        // Major 7 other than the one simple value carried: `true`.
        assert_eq!(
            Reader::new(&[0xf5]).raw_value().unwrap_err(),
            CborError::UnsupportedSimple(21)
        );
        // A byte string inside a skip whose length runs past the end.
        assert_eq!(
            Reader::new(&[0x43, 1]).raw_value().unwrap_err(),
            CborError::Truncated
        );
        // A nested item that does not decode fails rather than being copied out.
        let mut bad = map(&[(1, uint(1))]);
        bad.pop();
        bad.push(0x20);
        assert_eq!(
            Reader::new(&bad).raw_value().unwrap_err(),
            CborError::UnsupportedMajor(1)
        );
    }

    // ------------------------------------------------------------ schema maps

    const SCHEMA: [u64; 3] = [1, 2, 3];

    #[test]
    fn a_schema_map_reads_its_slots() {
        let encoded = map(&[(1, uint(7)), (3, text("x"))]);
        let slots = Reader::new(&encoded).schema_map(&SCHEMA).unwrap();
        assert_eq!(slots.len(), 2);
        // One closure, used for both the hit and the miss. Two separate closure
        // literals would leave the second one never called, because `in_slot`
        // returns `MissingKey` before it reads anything, and an uncalled closure is
        // an uncovered function this file's floor cannot afford.
        let read_uint = |r: &mut Reader<'_>| r.uint();
        assert_eq!(in_slot(&slots, 1, read_uint).unwrap(), 7);
        assert_eq!(in_slot(&slots, 3, |r| r.text()).unwrap(), "x");
        assert_eq!(
            in_slot(&slots, 2, read_uint).unwrap_err(),
            CborError::MissingKey(2)
        );
        assert_eq!(slot(&slots, 2).unwrap_err(), CborError::MissingKey(2));
    }

    #[test]
    fn an_empty_schema_map_is_legal_and_carries_nothing() {
        let slots = Reader::new(&map(&[])).schema_map(&SCHEMA).unwrap();
        assert!(slots.is_empty());
    }

    #[test]
    fn a_key_outside_the_schema_is_refused() {
        let encoded = map(&[(1, uint(1)), (9, uint(1))]);
        assert_eq!(
            Reader::new(&encoded).schema_map(&SCHEMA).unwrap_err(),
            CborError::UnknownKey(9)
        );
    }

    #[test]
    fn keys_out_of_order_or_repeated_are_refused() {
        // Hand-laid, because `map` sorts and dedupes by construction.
        let descending = [0xa2, 0x02, 0x01, 0x01, 0x01];
        assert_eq!(
            Reader::new(&descending).schema_map(&SCHEMA).unwrap_err(),
            CborError::MapKeysNotAscending {
                previous: 2,
                next: 1
            }
        );
        let duplicated = [0xa2, 0x01, 0x01, 0x01, 0x01];
        assert_eq!(
            Reader::new(&duplicated).schema_map(&SCHEMA).unwrap_err(),
            CborError::MapKeysNotAscending {
                previous: 1,
                next: 1
            }
        );
    }

    #[test]
    fn a_slot_carrying_trailing_bytes_is_refused() {
        // `raw_value` cannot produce one, so it is built by hand: the assertion is
        // about `in_slot`, not about the reader that fed it.
        let slots = vec![(1u64, vec![0x01, 0x02])];
        assert_eq!(
            in_slot(&slots, 1, |r| r.uint()).unwrap_err(),
            CborError::Trailing(1)
        );
    }

    // ---------------------------------------------------------------- reasons

    /// Every error names a reason and says what went wrong. The reason strings are
    /// the cross-language contract, so a typo here is a corpus row that can never
    /// pass in one language.
    #[test]
    fn every_error_has_a_reason_and_a_message() {
        let all = [
            CborError::Truncated,
            CborError::Trailing(1),
            CborError::NonCanonicalInteger,
            CborError::UnsupportedMajor(1),
            CborError::ReservedAdditionalInfo(28),
            CborError::UnsupportedSimple(21),
            CborError::TypeMismatch("map"),
            CborError::WrongLength {
                expected: 1,
                got: 2,
            },
            CborError::WrongArrayCount {
                expected: 1,
                got: 2,
            },
            CborError::InvalidUtf8,
            CborError::MapKeysNotAscending {
                previous: 1,
                next: 1,
            },
            CborError::UnknownKey(1),
            CborError::MissingKey(1),
        ];
        for error in all {
            assert!(error.reason().starts_with("codec."));
            assert!(!error.to_string().is_empty());
            // `Debug` and `Error` are both derived and both used in failure output.
            assert!(!format!("{error:?}").is_empty());
            assert!(std::error::Error::source(&error).is_none());
        }
    }
}
