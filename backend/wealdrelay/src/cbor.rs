// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Deterministic CBOR, the relay's half.
//!
//! The client's half is `Sources/Sync/DeterministicCBOR.swift` and the two have
//! to agree byte for byte, because the envelope's `hash` is a content address the
//! relay recomputes on accept: two encoders that differ by one byte produce two
//! addresses for one message and dedupe stops working.
//!
//! So this is the same deliberately tiny subset, refusing the same things:
//! unsigned integers in shortest form, definite-length byte strings and arrays,
//! and `null`. No maps, no text strings, no tags, no floats, no indefinite
//! lengths, no negative integers. Each of those is either unused by the wire
//! format or a place where two encoders could differ, and
//! `specs/backend/contracts/registries/error-codes.md` has a
//! `reject/noncanonical_cbor` code precisely so a peer that sends one is told
//! which rule it broke.
//!
//! A struct is an array of its fields in declaration order. Position carries the
//! field identity, so there are no keys to sort and no canonical-map rule to get
//! wrong.

/// Major types, in the high three bits of the initial byte.
const MAJOR_UINT: u8 = 0;
const MAJOR_BYTES: u8 = 2;
/// Text, and the one field that carries it.
///
/// The subset above says "no text strings", and that stayed true for every frame
/// up to version 3 because every string on the wire was an opaque identifier and a
/// byte string is the honest type for one. `WAKE`'s `register_url` is the
/// exception, and it is an exception on purpose rather than an erosion: it is a URL
/// a human pastes into an operator's configuration and a client parses as a URL, so
/// the CDDL in `specs/backend/contracts/wire/` states it as `tstr` and this decoder
/// has to agree byte for byte with that (`specs/backend/relay/push.md` section 3).
///
/// Determinism is unaffected, which is what made this admissible: a text string is
/// a byte string with a different major and the same length rule, so there is still
/// exactly one encoding of any value. The reader below refuses invalid UTF-8 rather
/// than replacing it, because a lossy conversion would give two inputs one decoded
/// value and that is precisely the property the whole module exists to protect.
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_SIMPLE: u8 = 7;

/// `null`. Major 7, value 22.
pub const NULL: &[u8] = &[0xf6];

/// A major type and an argument, in the shortest form that holds it.
///
/// This is the whole determinism rule: 23 encodes in the initial byte, 300
/// encodes in two following bytes and never in four, and there is exactly one
/// encoding of any value.
fn head(major: u8, value: u64) -> Vec<u8> {
    let tag = major << 5;
    if value < 24 {
        return vec![tag | u8::try_from(value).unwrap_or_default()];
    }
    if value <= u64::from(u8::MAX) {
        return vec![tag | 24, u8::try_from(value).unwrap_or_default()];
    }
    if value <= u64::from(u16::MAX) {
        let mut out = vec![tag | 25];
        out.extend_from_slice(&u16::try_from(value).unwrap_or_default().to_be_bytes());
        return out;
    }
    if value <= u64::from(u32::MAX) {
        let mut out = vec![tag | 26];
        out.extend_from_slice(&u32::try_from(value).unwrap_or_default().to_be_bytes());
        return out;
    }
    let mut out = vec![tag | 27];
    out.extend_from_slice(&value.to_be_bytes());
    out
}

pub fn uint(value: u64) -> Vec<u8> {
    head(MAJOR_UINT, value)
}

pub fn bytes(value: &[u8]) -> Vec<u8> {
    let mut out = head(MAJOR_BYTES, value.len() as u64);
    out.extend_from_slice(value);
    out
}

/// `false` and `true`. Major 7, values 20 and 21.
///
/// Here for the same reason ``MAJOR_TEXT`` is, and with the same narrowness: one
/// field on one frame (`WAKE`'s `Capability.enabled`) is a boolean in the CDDL,
/// because "push is on here" is a two-state fact and a client branching on
/// `uint == 1` would be a client that has to decide what `2` means. There is
/// exactly one encoding of each value, so nothing about determinism changes.
pub const FALSE: &[u8] = &[0xf4];
pub const TRUE: &[u8] = &[0xf5];

pub fn boolean(value: bool) -> Vec<u8> {
    if value {
        TRUE.to_vec()
    } else {
        FALSE.to_vec()
    }
}

/// One text string. See ``MAJOR_TEXT`` for why the subset carries one at all.
pub fn text(value: &str) -> Vec<u8> {
    let mut out = head(MAJOR_TEXT, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
    out
}

pub fn array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = head(MAJOR_ARRAY, items.len() as u64);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// A byte string, or `null` when absent. The shape of an optional field.
pub fn optional_bytes(value: Option<&[u8]>) -> Vec<u8> {
    match value {
        Some(value) => bytes(value),
        None => NULL.to_vec(),
    }
}

/// Why a decode refused. Every variant is reachable from a wire byte a hostile
/// peer can send, so every variant has a test.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CborError {
    #[error("input ended inside an item")]
    Truncated,
    #[error("major type {0} is not carried by the wire format")]
    UnsupportedMajor(u8),
    #[error("integer is not in its shortest form")]
    NonCanonicalInteger,
    #[error("additional info {0} is reserved or indefinite")]
    ReservedAdditionalInfo(u8),
    #[error("simple value {0} is not carried by the wire format")]
    UnsupportedSimple(u8),
    #[error("item is not a {expected}")]
    TypeMismatch { expected: &'static str },
    #[error("byte string is {got} bytes, expected {expected}")]
    WrongLength { expected: usize, got: usize },
    #[error("array holds {got} items, expected {expected}")]
    WrongArrayCount { expected: usize, got: usize },
    #[error("integer {0} does not fit the field")]
    OutOfRange(u64),
    #[error("{0} bytes remain after the last field")]
    TrailingBytes(usize),
    /// A text string whose bytes are not UTF-8. Refused rather than replaced: a
    /// lossy conversion would map two different inputs onto one decoded value,
    /// which is the same determinism hole as a non-canonical integer.
    #[error("text string is not valid UTF-8")]
    InvalidUtf8,
}

/// A cursor over encoded bytes.
///
/// Every read either advances past one whole item or fails and leaves the cursor
/// where it was, so a caller that catches can report the offset. That property is
/// load-bearing for the frame decoder, which reads fields in order and has to be
/// able to say which field was wrong.
pub struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn is_at_end(&self) -> bool {
        self.offset == self.data.len()
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }

    /// Refuse anything left over. Trailing garbage is not a valid message: it
    /// would let two byte strings decode to one value, which is the same hole as
    /// a non-canonical integer.
    pub fn finish(&self) -> Result<(), CborError> {
        if self.is_at_end() {
            Ok(())
        } else {
            Err(CborError::TrailingBytes(self.remaining()))
        }
    }

    fn byte_at(&self, index: usize) -> Result<u8, CborError> {
        self.data.get(index).copied().ok_or(CborError::Truncated)
    }

    /// Read one head: its major type and its argument, canonicity enforced.
    fn read_head(&mut self) -> Result<(u8, u64), CborError> {
        let initial = self.byte_at(self.offset)?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        if info < 24 {
            self.offset += 1;
            return Ok((major, u64::from(info)));
        }
        if info >= 28 {
            return Err(CborError::ReservedAdditionalInfo(info));
        }
        let width = 1usize << (info - 24);
        let mut value: u64 = 0;
        for index in 0..width {
            value = (value << 8) | u64::from(self.byte_at(self.offset + 1 + index)?);
        }
        // Canonicity: the value must not have fitted in a shorter form.
        let minimum = match width {
            1 => 24,
            2 => u64::from(u8::MAX) + 1,
            4 => u64::from(u16::MAX) + 1,
            _ => u64::from(u32::MAX) + 1,
        };
        if value < minimum {
            return Err(CborError::NonCanonicalInteger);
        }
        self.offset += 1 + width;
        Ok((major, value))
    }

    /// One rejection for a head that is not the expected major type.
    ///
    /// A major this subset does not carry at all is named separately from one
    /// that is carried but in the wrong position, because the two are different
    /// bugs: the first is a peer speaking a wider CBOR than the protocol, the
    /// second is a peer sending the fields out of order.
    fn mismatch(major: u8, expected: &'static str) -> CborError {
        if matches!(major, MAJOR_UINT | MAJOR_BYTES | MAJOR_ARRAY | MAJOR_SIMPLE) {
            CborError::TypeMismatch { expected }
        } else {
            CborError::UnsupportedMajor(major)
        }
    }

    pub fn uint(&mut self) -> Result<u64, CborError> {
        let start = self.offset;
        let (major, argument) = self.read_head()?;
        if major != MAJOR_UINT {
            self.offset = start;
            return Err(Self::mismatch(major, "unsigned integer"));
        }
        Ok(argument)
    }

    pub fn u8(&mut self) -> Result<u8, CborError> {
        let value = self.uint()?;
        u8::try_from(value).map_err(|_| CborError::OutOfRange(value))
    }

    pub fn u16(&mut self) -> Result<u16, CborError> {
        let value = self.uint()?;
        u16::try_from(value).map_err(|_| CborError::OutOfRange(value))
    }

    pub fn u32(&mut self) -> Result<u32, CborError> {
        let value = self.uint()?;
        u32::try_from(value).map_err(|_| CborError::OutOfRange(value))
    }

    pub fn bytes(&mut self) -> Result<Vec<u8>, CborError> {
        let start = self.offset;
        let (major, argument) = self.read_head()?;
        if major != MAJOR_BYTES {
            self.offset = start;
            return Err(Self::mismatch(major, "byte string"));
        }
        // Compared in `u64` and converted afterwards. A fallible conversion here
        // would carry an arm no 64-bit target can reach, and an unreachable arm is
        // a coverage exclusion wearing a different hat. The bound is the same
        // either way: a length longer than the bytes that remain is truncation.
        if argument > self.remaining() as u64 {
            self.offset = start;
            return Err(CborError::Truncated);
        }
        let length = argument as usize;
        let slice = self.data[self.offset..self.offset + length].to_vec();
        self.offset += length;
        Ok(slice)
    }

    /// A byte string of an exact width. The `[32]byte` and `[64]byte` fields are
    /// fixed, and a short `group` would otherwise decode fine and then hash to
    /// something no relay recognises.
    pub fn bytes_of(&mut self, count: usize) -> Result<Vec<u8>, CborError> {
        let start = self.offset;
        let value = self.bytes()?;
        if value.len() != count {
            self.offset = start;
            return Err(CborError::WrongLength {
                expected: count,
                got: value.len(),
            });
        }
        Ok(value)
    }

    /// One boolean, and nothing that merely looks like one.
    ///
    /// An integer here is a type mismatch rather than a truthy value, because a
    /// decoder that accepted `1` for `true` would be a decoder with an opinion about
    /// `2`, and two peers whose opinions differ is the drift this module exists to
    /// prevent.
    pub fn boolean(&mut self) -> Result<bool, CborError> {
        let start = self.offset;
        let (major, argument) = self.read_head()?;
        if major != MAJOR_SIMPLE {
            self.offset = start;
            return Err(Self::mismatch(major, "boolean"));
        }
        match argument {
            20 => Ok(false),
            21 => Ok(true),
            other => {
                self.offset = start;
                Err(CborError::UnsupportedSimple(
                    u8::try_from(other).unwrap_or(u8::MAX),
                ))
            }
        }
    }

    /// One text string, UTF-8 checked.
    ///
    /// The length rule and the truncation refusal are ``bytes``'s, copied rather
    /// than shared because sharing them would mean reading a text string as a byte
    /// string first and a caller could then get the bytes out of a field the wire
    /// format says is text.
    pub fn text(&mut self) -> Result<String, CborError> {
        let start = self.offset;
        let (major, argument) = self.read_head()?;
        if major != MAJOR_TEXT {
            self.offset = start;
            return Err(Self::mismatch(major, "text string"));
        }
        if argument > self.remaining() as u64 {
            self.offset = start;
            return Err(CborError::Truncated);
        }
        let length = argument as usize;
        let decoded = std::str::from_utf8(&self.data[self.offset..self.offset + length])
            .map(str::to_string)
            .map_err(|_| CborError::InvalidUtf8);
        match decoded {
            Ok(value) => {
                self.offset += length;
                Ok(value)
            }
            Err(error) => {
                self.offset = start;
                Err(error)
            }
        }
    }

    /// A byte string, or `null` for absence.
    pub fn optional_bytes(&mut self) -> Result<Option<Vec<u8>>, CborError> {
        let initial = self.byte_at(self.offset)?;
        if initial >> 5 != MAJOR_SIMPLE {
            return self.bytes().map(Some);
        }
        let start = self.offset;
        let (_, argument) = self.read_head()?;
        if argument != 22 {
            self.offset = start;
            return Err(CborError::UnsupportedSimple(
                u8::try_from(argument).unwrap_or(u8::MAX),
            ));
        }
        Ok(None)
    }

    /// Is the next item `null`?
    ///
    /// Consumes it when it is and leaves the reader untouched when it is not, so a
    /// caller can spell "an optional structure" the way ``optional_bytes`` spells an
    /// optional byte string. Needed by `access::AccessSet`, whose optional field is a
    /// nested array rather than a byte string.
    pub fn optional_is_null(&mut self) -> Result<bool, CborError> {
        let initial = self.byte_at(self.offset)?;
        if initial >> 5 != MAJOR_SIMPLE {
            return Ok(false);
        }
        let start = self.offset;
        let (_, argument) = self.read_head()?;
        if argument != 22 {
            self.offset = start;
            return Err(CborError::UnsupportedSimple(
                u8::try_from(argument).unwrap_or(u8::MAX),
            ));
        }
        Ok(true)
    }

    /// An array header of any length, returning the item count.
    pub fn array_header(&mut self) -> Result<usize, CborError> {
        let start = self.offset;
        let (major, argument) = self.read_head()?;
        if major != MAJOR_ARRAY {
            self.offset = start;
            return Err(Self::mismatch(major, "array"));
        }
        // Compared in `u64`, for the reason `bytes` gives. An item count larger
        // than the bytes that remain cannot be satisfied, and refusing it here is
        // what stops a hostile peer making the relay allocate for a length it
        // never intends to send.
        if argument > self.remaining() as u64 {
            self.offset = start;
            return Err(CborError::Truncated);
        }
        Ok(argument as usize)
    }

    /// An array header of an exact item count.
    pub fn array(&mut self, count: usize) -> Result<(), CborError> {
        let start = self.offset;
        let got = self.array_header()?;
        if got != count {
            self.offset = start;
            return Err(CborError::WrongArrayCount {
                expected: count,
                got,
            });
        }
        Ok(())
    }
}
