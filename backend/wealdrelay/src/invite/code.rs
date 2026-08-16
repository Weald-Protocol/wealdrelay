// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The one-time code: 12 characters of Crockford Base32, hashed with Argon2id.
//!
//! `specs/backend/relay/invites.md`, "Two-channel delivery". The link goes to
//! email. The code does not. An attacker with mailbox access has the link and
//! cannot join; an attacker who somehow has the code has nothing without the link.
//!
//! ## Why 12 Crockford symbols
//!
//! 12 symbols at 5 bits is 60 bits, grouped `ABCD-EFGH-JKLM` so it is comfortable
//! to paste into a Slack thread or read aloud. Crockford's alphabet is the reason
//! reading it aloud works: `I`, `L`, `O` and `U` are not symbols, and the first
//! three are accepted on input as `1`, `1` and `0`, so a human who transcribes the
//! shape of a character rather than the character still gets in. `U` is excluded and
//! is **not** remapped, because it is excluded from the alphabet on purpose and
//! silently accepting it would make two different strings decode to one code.
//!
//! ## Why Argon2id and why the token is the salt
//!
//! The relay must rate-limit attempts without learning the code, so it holds a hash.
//! A fast hash of a 60-bit value is a hash an attacker with the record can brute
//! force offline, so the hash is memory-hard. The salt is the token, which is
//! already the lookup key: it is unique per invite, so one precomputed table cannot
//! attack two invites, and it needs no second column and no second thing to
//! round-trip through the signature.

use argon2::{Algorithm, Argon2, Params, Version};

use super::HASH_BYTES;

/// Crockford's alphabet, in value order. No `I`, `L`, `O` or `U`.
pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Symbols in a code.
pub const CODE_SYMBOLS: usize = 12;

/// Bits of entropy in a code. 12 symbols at 5 bits.
pub const CODE_BITS: u32 = 60;

/// Symbols per group in the displayed form, `ABCD-EFGH-JKLM`.
pub const GROUP_SYMBOLS: usize = 4;

/// Failed attempts from one token and source pair before that pair cools down.
///
/// The pair deliberately excludes the joiner's device: the device is an arbitrary
/// byte string supplied pre-authentication, so a key that included it was a key the
/// guesser chose, and the five-guess bound was unbounded from one address.
pub const MAX_FAILURES: i32 = 5;

/// Failed attempts against one token, across every source, before the whole token
/// cools down. This is what bounds a distributed guesser: sources are cheap in
/// aggregate even though each one is not attacker-chosen, and the 60-bit code's
/// guarantee has to hold against all of them together.
pub const MAX_TOKEN_FAILURES: i64 = 25;

/// How long a cooled-down pair or token stays cooled down, in seconds.
pub const COOLDOWN_SECONDS: i64 = 15 * 60;

/// Argon2id parameters.
///
/// 19 MiB, two passes, one lane: the OWASP second-choice profile, chosen over the
/// 46 MiB first choice because the relay verifies these on a request path and must
/// not be turned into its own memory-exhaustion lever by an attacker who can send
/// wrong codes. The rate limit above is what makes the smaller profile sufficient:
/// an online attacker gets five guesses per tuple per fifteen minutes against 60
/// bits, and an offline attacker who has the record is facing 2^60 memory-hard
/// evaluations.
pub const MEMORY_KIB: u32 = 19 * 1024;
pub const ITERATIONS: u32 = 2;
pub const LANES: u32 = 1;

/// Why a code could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodeError {
    #[error("a code is {CODE_SYMBOLS} symbols, this one is {0}")]
    WrongLength(usize),
    #[error("{0} is not a Crockford Base32 symbol")]
    NotASymbol(char),
    #[error("the code hash could not be computed: {0}")]
    Hash(String),
}

/// A one-time code, normalised.
///
/// Held as the 60-bit value rather than as text, so two spellings of one code are
/// one value and there is no place for a comparison against a formatting difference
/// to hide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Code(u64);

impl Code {
    /// A fresh code, straight from the operating system.
    pub fn random() -> Self {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).expect("the operating system must provide randomness");
        Self::from_bits(u64::from_be_bytes(bytes))
    }

    /// The low 60 bits of a value, as a code. The high four are dropped, which is
    /// what makes any `u64` a legal input and keeps the constructor total.
    pub fn from_bits(value: u64) -> Self {
        Self(value & ((1u64 << CODE_BITS) - 1))
    }

    pub fn bits(self) -> u64 {
        self.0
    }

    /// The 12 symbols, ungrouped. What is hashed.
    pub fn symbols(self) -> String {
        let mut out = String::with_capacity(CODE_SYMBOLS);
        for index in (0..CODE_SYMBOLS).rev() {
            let shift = 5 * index;
            let value = (self.0 >> shift) & 0x1f;
            out.push(char::from(ALPHABET[value as usize]));
        }
        out
    }

    /// `ABCD-EFGH-JKLM`. What the admin's client displays and the admin pastes.
    pub fn grouped(self) -> String {
        let symbols = self.symbols();
        symbols
            .as_bytes()
            .chunks(GROUP_SYMBOLS)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Read a code a human typed.
    ///
    /// Case is ignored, hyphens and spaces are ignored, and Crockford's confusable
    /// remappings are applied, because the code exists to be read aloud and
    /// retyped. Everything else is refused: a code that silently accepted an
    /// unknown character would be a code with two spellings.
    pub fn parse(input: &str) -> Result<Self, CodeError> {
        let mut value: u64 = 0;
        let mut symbols = 0usize;
        for character in input.chars() {
            if character == '-' || character == ' ' {
                continue;
            }
            let symbol = normalise(character)?;
            symbols += 1;
            if symbols > CODE_SYMBOLS {
                return Err(CodeError::WrongLength(symbols));
            }
            value = (value << 5) | u64::from(symbol);
        }
        if symbols != CODE_SYMBOLS {
            return Err(CodeError::WrongLength(symbols));
        }
        Ok(Self(value))
    }
}

/// One character to its 5-bit value, with Crockford's remappings.
fn normalise(character: char) -> Result<u8, CodeError> {
    let upper = character.to_ascii_uppercase();
    let upper = match upper {
        // Crockford: these are read as digits, so a human who transcribed the shape
        // rather than the character still gets in.
        'I' | 'L' => '1',
        'O' => '0',
        other => other,
    };
    // `U` is not in the alphabet and is deliberately not remapped: it is excluded on
    // purpose, and accepting it would give one code two spellings.
    match ALPHABET.iter().position(|symbol| *symbol == upper as u8) {
        Some(index) => Ok(index as u8),
        None => Err(CodeError::NotASymbol(character)),
    }
}

/// Argon2id of a code, salted with the invite token.
///
/// The token is 16 bytes, comfortably past Argon2's 8-byte salt floor, and it is
/// already the lookup key, so the hash needs no second column and the signature
/// needs no second field.
pub fn hash(code: Code, token: &[u8]) -> Result<[u8; HASH_BYTES], CodeError> {
    hash_with(MEMORY_KIB, code, token)
}

/// The same, for a token of the width this system's tokens actually are.
///
/// Argon2 refuses in exactly two places: a memory cost below the algorithm's floor,
/// and a salt shorter than eight bytes. Here the cost is ``MEMORY_KIB`` and the salt
/// is a ``TOKEN_BYTES``-wide array, so both are settled at compile time and there is
/// no failure for a caller to handle. The fallible form stays for callers holding a
/// slice whose width they cannot promise.
pub fn hash_token(code: Code, token: &[u8; super::TOKEN_BYTES]) -> [u8; HASH_BYTES] {
    hash_with(MEMORY_KIB, code, token)
        .expect("Argon2id refuses only a sub-floor memory cost or a salt under 8 bytes")
}

/// The same, with the memory cost passed in.
///
/// Split out so both of Argon2's refusals are reachable from a test without a mock:
/// a memory cost below the algorithm's floor refuses at ``Params::new``, and a salt
/// shorter than eight bytes refuses at the hash itself. Production has exactly one
/// caller and it passes ``MEMORY_KIB``.
pub fn hash_with(memory_kib: u32, code: Code, token: &[u8]) -> Result<[u8; HASH_BYTES], CodeError> {
    let params = Params::new(memory_kib, ITERATIONS, LANES, Some(HASH_BYTES))
        .map_err(|error| CodeError::Hash(error.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; HASH_BYTES];
    argon
        .hash_password_into(code.symbols().as_bytes(), token, &mut out)
        .map_err(|error| CodeError::Hash(error.to_string()))?;
    Ok(out)
}

/// Whether a presented code matches a stored hash, in constant time.
///
/// Every wrong-shaped input answers false rather than propagating a type: a salt
/// Argon2 refuses and a stored hash of the wrong width are the same answer to the
/// only question this function asks, and two failure paths for one answer is two
/// paths for a caller to get wrong. That flatness is also what invites.md requires
/// of the redeem surface, which must not distinguish "this relay could not compute"
/// from "you typed it wrong".
pub fn verify(code: Code, token: &[u8], stored: &[u8]) -> bool {
    let Ok(computed) = hash(code, token) else {
        return false;
    };
    stored.len() == HASH_BYTES && constant_time_eq(&computed, stored)
}

/// Equality without an early exit.
fn constant_time_eq(left: &[u8; HASH_BYTES], right: &[u8]) -> bool {
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}
