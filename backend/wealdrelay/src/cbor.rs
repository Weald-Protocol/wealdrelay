// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Deterministic CBOR, the relay's half.
//!
//! The client has a Swift implementation of the same encoding, and the two have
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
