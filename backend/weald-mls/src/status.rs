// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! What every function across the boundary answers with.
//!
//! `specs/backend/relay/mls-binding.md`: "Every entry point is wrapped in
//! `catch_unwind` and returns a typed error." Typed means this enum: a closed set of
//! `i32` codes the Swift side switches over exhaustively, with no string parsing and no
//! `errno`.
//!
//! The set is deliberately small and coarse. A caller's only decisions are whether the
//! call can be retried, whether the message should be dropped, and whether the group is
//! unusable, so the codes answer those and nothing finer. Anything finer would be a
//! detail of OpenMLS's error taxonomy crossing a boundary whose whole purpose is to be
//! narrow, and it would be a promise about an upstream crate's error names.

use core::fmt;

/// The status of one call.
///
/// `repr(i32)` and explicit discriminants, because these numbers are the ABI: a value
/// that shifted when a variant was inserted would silently change what Swift believes
/// happened.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The call did what it was asked.
    Ok = 0,
    /// A pointer was null, a length was impossible, or bytes that had to be UTF-8 were
    /// not. The caller has a bug; retrying will not help.
    InvalidArgument = 1,
    /// The handle is not one this library issued, or has already been freed.
    InvalidHandle = 2,
    /// The handle was used from a thread other than the one it was created on. Handles
    /// are thread-confined by contract (`mls-binding.md`), and this is the contract
    /// being enforced rather than assumed.
    WrongThread = 3,
    /// The MLS protocol refused: a message from the wrong epoch, a member who is not in
    /// the group, a signature that does not verify. The group is still usable.
    Protocol = 4,
    /// Bytes that did not decode as the MLS structure they were presented as. The
    /// message is dropped; this is the ordinary answer to hostile input.
    Malformed = 5,
    /// The state store could not be read or written. Nothing was changed, and the caller
    /// should treat the operation as not having happened.
    Storage = 6,
    /// A panic was caught at the boundary. The library is in an unknown state for this
    /// handle and the caller must free it. Reported rather than unwound, because an
    /// unwind into Swift is undefined behaviour.
    Panicked = 7,
}

impl Status {
    /// The name a log line uses. Not `Display` on purpose: this is a stable label for
    /// an operator, not a sentence for a person.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::InvalidArgument => "invalid_argument",
            Self::InvalidHandle => "invalid_handle",
            Self::WrongThread => "wrong_thread",
            Self::Protocol => "protocol",
            Self::Malformed => "malformed",
            Self::Storage => "storage",
            Self::Panicked => "panicked",
        }
    }

    /// Every code, so a test can assert the mapping is total and Swift can assert it
    /// knows all of them.
    pub const ALL: [Status; 8] = [
        Status::Ok,
        Status::InvalidArgument,
        Status::InvalidHandle,
        Status::WrongThread,
        Status::Protocol,
        Status::Malformed,
        Status::Storage,
        Status::Panicked,
    ];
}

/// What went wrong, inside Rust, before it becomes a ``Status``.
///
/// Carries a message for the log and never for the caller's control flow. The message
/// is deliberately not returned across the boundary: a string out is an allocation to
/// free and a place for key material to end up by accident, and the code is what the
/// caller acts on.
#[derive(Debug)]
pub enum Error {
    InvalidArgument(String),
    InvalidHandle,
    WrongThread,
    Protocol(String),
    Malformed(String),
    Storage(String),
}

impl Error {
    pub fn status(&self) -> Status {
        match self {
            Self::InvalidArgument(_) => Status::InvalidArgument,
            Self::InvalidHandle => Status::InvalidHandle,
            Self::WrongThread => Status::WrongThread,
            Self::Protocol(_) => Status::Protocol,
            Self::Malformed(_) => Status::Malformed,
            Self::Storage(_) => Status::Storage,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(why) => write!(f, "invalid argument: {why}"),
            Self::InvalidHandle => write!(f, "not a live handle"),
            Self::WrongThread => write!(f, "handle used from another thread"),
            Self::Protocol(why) => write!(f, "protocol: {why}"),
            Self::Malformed(why) => write!(f, "malformed: {why}"),
            Self::Storage(why) => write!(f, "storage: {why}"),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// The ABI generation this library implements.
///
/// # Safety
/// None required. No pointers cross and nothing is allocated.
#[no_mangle]
pub extern "C" fn weald_mls_status_label(status: i32) -> *const core::ffi::c_char {
    // A label for a code, so a crash report carries a word rather than a number.
    // Static strings, so there is nothing to free.
    const LABELS: [&str; 9] = [
        "ok\0",
        "invalid_argument\0",
        "invalid_handle\0",
        "wrong_thread\0",
        "protocol\0",
        "malformed\0",
        "storage\0",
        "panicked\0",
        "unknown\0",
    ];
    let index = match usize::try_from(status) {
        Ok(index) if index < LABELS.len() - 1 => index,
        // Anything this build does not know, including a negative number, is named as
        // unknown rather than indexed with. A caller reading a code from a newer
        // library is the case this exists for.
        _ => LABELS.len() - 1,
    };
    LABELS[index].as_ptr().cast()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_status_has_a_distinct_code_and_label() {
        let mut codes: Vec<i32> = Status::ALL.iter().map(|s| *s as i32).collect();
        let mut labels: Vec<&str> = Status::ALL.iter().map(|s| s.label()).collect();
        let count = codes.len();
        codes.sort_unstable();
        codes.dedup();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(codes.len(), count, "two statuses share a code");
        assert_eq!(labels.len(), count, "two statuses share a label");
        // The codes are the ABI. Pinned here so an inserted variant that shifted them
        // fails this test rather than a customer's client.
        assert_eq!(codes, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn every_error_maps_to_the_status_a_caller_acts_on() {
        let cases = [
            (
                Error::InvalidArgument("null".into()),
                Status::InvalidArgument,
            ),
            (Error::InvalidHandle, Status::InvalidHandle),
            (Error::WrongThread, Status::WrongThread),
            (Error::Protocol("wrong epoch".into()), Status::Protocol),
            (Error::Malformed("not a commit".into()), Status::Malformed),
            (Error::Storage("disk".into()), Status::Storage),
        ];
        for (error, status) in cases {
            assert_eq!(error.status(), status);
            // Every error says what happened, for the log and not for the caller.
            assert!(!error.to_string().is_empty());
            assert!(format!("{error:?}").len() > 2);
        }
    }

    #[test]
    fn a_label_is_answered_for_every_code_and_for_codes_this_build_does_not_know() {
        for status in Status::ALL {
            let ptr = weald_mls_status_label(status as i32);
            // Safety: the function's contract is a static NUL-terminated string.
            let label = unsafe { core::ffi::CStr::from_ptr(ptr) };
            assert_eq!(label.to_str().expect("ascii"), status.label());
        }
        for unknown in [-1, 8, 9, i32::MAX, i32::MIN] {
            let ptr = weald_mls_status_label(unknown);
            let label = unsafe { core::ffi::CStr::from_ptr(ptr) };
            assert_eq!(label.to_str().expect("ascii"), "unknown");
        }
    }
}
