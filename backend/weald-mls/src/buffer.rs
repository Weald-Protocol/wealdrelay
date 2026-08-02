// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Bytes out, owned by the caller, freed by an explicit call.
//!
//! `specs/backend/relay/mls-binding.md`: "Buffers in, owned buffers out, freed by an
//! explicit call. No callbacks from Rust into Swift." And: "Secrets are zeroed on free."
//!
//! Both rules are this file. A buffer is three words the caller can read and one call it
//! must make, and the free path overwrites the bytes before releasing them, because the
//! things that come out of here are exporter secrets, plaintexts and welcome messages.
//!
//! ## Why not let Swift allocate
//!
//! The alternative shape, where Swift passes a buffer and a length and Rust fills it,
//! needs either a two-call protocol (ask the size, then ask again) or a truncation rule.
//! The first doubles every entry point; the second is a place a message is silently cut
//! in half. Owned-out with an explicit free is one call and one rule.

use zeroize::Zeroize;

/// Bytes crossing out of Rust.
///
/// `repr(C)` and three plain words: the pointer, the length the caller may read, and the
/// capacity the free path needs in order to hand the allocation back exactly as it was
/// taken. Capacity is carried rather than recomputed because `Vec`'s allocation is
/// described by both numbers, and reconstructing it with the wrong one is undefined
/// behaviour rather than a leak.
#[repr(C)]
#[derive(Debug)]
pub struct Buffer {
    pub bytes: *mut u8,
    pub len: usize,
    pub capacity: usize,
}

impl Buffer {
    /// An empty buffer. What every out-parameter holds before a call, and what a failed
    /// call leaves behind: a caller that frees it is doing nothing, which is what makes
    /// the error paths safe to write.
    pub const fn empty() -> Self {
        Self {
            bytes: core::ptr::null_mut(),
            len: 0,
            capacity: 0,
        }
    }

    /// Take ownership of `bytes` and hand it out.
    pub fn owning(bytes: Vec<u8>) -> Self {
        // `into_raw_parts` is still unstable, so this is the stable spelling of it: read
        // the three numbers, then forget the vector so its destructor does not run.
        let mut bytes = core::mem::ManuallyDrop::new(bytes);
        Self {
            bytes: bytes.as_mut_ptr(),
            len: bytes.len(),
            capacity: bytes.capacity(),
        }
    }

    /// Is this the empty buffer? Used by the tests and by ``free``.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_null()
    }

    /// The bytes, as a slice, without giving up ownership.
    ///
    /// For a caller that wants to read a buffer before freeing it, which on the Swift
    /// side is every caller: the ownership rule is that the buffer is freed by an explicit
    /// call, so there has to be a way to read it that is not the free.
    ///
    /// # Safety
    /// `self` must be a live buffer this library produced and not yet freed.
    pub unsafe fn as_slice(&self) -> &[u8] {
        if self.is_empty() {
            return &[];
        }
        // Safety: `owning` produced the pointer and length from one `Vec<u8>` and nothing
        // has changed them, which is what `from_raw_parts` requires.
        unsafe { core::slice::from_raw_parts(self.bytes, self.len) }
    }

    /// Overwrite the bytes in place, leaving the allocation alive.
    ///
    /// Separated from ``free`` so the rule is observable. Asserting zeroization after a
    /// deallocation means reading freed memory, which is undefined behaviour and, worse,
    /// wrong: the allocator writes its own free-list bookkeeping into the first words, so
    /// such a test fails for a reason that has nothing to do with whether the secret was
    /// erased. Here the erasure is checked while the buffer is still ours.
    ///
    /// # Safety
    /// `self` must be a live buffer this library produced.
    pub unsafe fn wipe(&mut self) {
        if self.is_empty() {
            return;
        }
        // Safety: `owning` produced these three numbers from one `Vec<u8>` and nothing
        // has changed them, which is what `from_raw_parts_mut` requires.
        let bytes = unsafe { core::slice::from_raw_parts_mut(self.bytes, self.len) };
        bytes.zeroize();
    }

    /// Zero the bytes and release the allocation.
    ///
    /// Idempotent against the empty buffer so every failure path can hand one back
    /// without the caller needing to know whether a call got far enough to allocate.
    ///
    /// # Safety
    /// `self` must be a buffer this library produced and not yet freed.
    pub unsafe fn free(&mut self) {
        if self.is_empty() {
            return;
        }
        // Zeroed before the allocator can hand the pages to anything else. This is the
        // rule from the spec, and it applies to every buffer rather than only to the
        // exporter's output: a plaintext is as much a secret as a key, and a rule with
        // an exception is a rule somebody has to remember.
        // Safety: the buffer is live, by this function's own contract.
        unsafe { self.wipe() };
        // Safety: the pointer, length and capacity are the ones `owning` took from a
        // `Vec<u8>`, unchanged, which is exactly what `from_raw_parts` requires.
        let owned = unsafe { Vec::from_raw_parts(self.bytes, self.len, self.capacity) };
        drop(owned);
        *self = Self::empty();
    }
}

/// Free a buffer this library produced.
///
/// The one deallocation entry point. Null-safe and double-free-safe in the only sense
/// that is achievable across a C ABI: freeing the empty buffer is a no-op, and freeing
/// through this function leaves the struct empty, so a caller that frees the same struct
/// twice does nothing the second time.
///
/// # Safety
/// `buffer` must be null, or point to a buffer this library produced and did not already
/// free through this function.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_buffer_free(buffer: *mut Buffer) {
    if buffer.is_null() {
        return;
    }
    // Safety: the caller's contract is that this points to one of our buffers.
    unsafe { (*buffer).free() };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_owned_buffer_carries_the_bytes_it_was_given() {
        let mut buffer = Buffer::owning(vec![1, 2, 3, 4]);
        assert_eq!(buffer.len, 4);
        assert!(!buffer.is_empty());
        // Safety: the buffer is live and owns four bytes.
        let seen = unsafe { core::slice::from_raw_parts(buffer.bytes, buffer.len) };
        assert_eq!(seen, &[1, 2, 3, 4]);
        unsafe { buffer.free() };
        assert!(buffer.is_empty());
        assert_eq!(buffer.len, 0);
        assert_eq!(buffer.capacity, 0);
    }

    #[test]
    fn an_empty_buffer_is_safe_to_free_and_stays_empty() {
        let mut buffer = Buffer::empty();
        assert!(buffer.is_empty());
        unsafe { buffer.free() };
        unsafe { buffer.free() };
        assert!(buffer.is_empty());
    }

    #[test]
    fn the_bytes_are_erased_before_the_allocation_goes_back() {
        // The spec's "secrets are zeroed on free", checked while the buffer is still
        // ours. `free` is `wipe` plus the deallocation, so proving `wipe` erases and that
        // `free` calls it is the whole rule; reading the pointer afterwards would be
        // reading freed memory and would fail on the allocator's own bookkeeping rather
        // than on the secret.
        let mut buffer = Buffer::owning(vec![0xAB; 64]);
        unsafe { buffer.wipe() };
        // Safety: the buffer is still live; only its contents were overwritten.
        let after = unsafe { core::slice::from_raw_parts(buffer.bytes, buffer.len) };
        assert!(
            after.iter().all(|byte| *byte == 0),
            "wipe left the secret in place: {after:?}"
        );
        unsafe { buffer.free() };
        assert!(buffer.is_empty());

        // And wiping the empty buffer is a no-op rather than a null dereference, which
        // is what every failure path relies on.
        let mut nothing = Buffer::empty();
        unsafe { nothing.wipe() };
        assert!(nothing.is_empty());
    }

    #[test]
    fn the_c_entry_point_is_null_safe_and_frees_what_it_is_given() {
        // Null: the case a caller reaches by freeing an out-parameter it never passed.
        unsafe { weald_mls_buffer_free(core::ptr::null_mut()) };

        let mut buffer = Buffer::owning(vec![7; 8]);
        unsafe { weald_mls_buffer_free(&mut buffer) };
        assert!(buffer.is_empty());
        // Again, because a caller that cannot free twice safely is a caller that leaks
        // on every error path.
        unsafe { weald_mls_buffer_free(&mut buffer) };
        assert!(buffer.is_empty());
    }

    #[test]
    fn reading_the_empty_buffer_as_a_slice_gives_nothing_rather_than_a_null_dereference() {
        // Every failure path hands back the empty buffer, so the first thing a Swift
        // caller does with it is read it. `as_slice` has to answer that with an empty
        // slice: `from_raw_parts` on a null pointer is undefined behaviour even for a
        // length of zero, which is why the check is in front of it rather than left to
        // the caller remembering to test `is_empty` first.
        let empty = Buffer::empty();
        // Safety: the empty buffer is a live buffer this library produced.
        let seen = unsafe { empty.as_slice() };
        assert!(seen.is_empty());

        // And the same call on a live buffer really does hand back its bytes, so the
        // check above is a special case rather than the only case.
        let mut buffer = Buffer::owning(vec![5, 6, 7]);
        // Safety: live, owning three bytes.
        assert_eq!(unsafe { buffer.as_slice() }, &[5, 6, 7]);
        unsafe { buffer.free() };
        // Freed, so empty again, and reading it is the no-op above rather than a read of
        // memory the allocator has taken back.
        // Safety: the buffer is the empty buffer now.
        assert!(unsafe { buffer.as_slice() }.is_empty());
    }

    #[test]
    fn a_zero_length_vector_still_round_trips() {
        // An empty MLS message is a legitimate outcome: a commit with no proposals
        // produces no welcome. The buffer for it is not the null buffer, because the
        // caller has to be able to tell "nothing to send" from "the call failed".
        let mut buffer = Buffer::owning(Vec::new());
        assert_eq!(buffer.len, 0);
        unsafe { buffer.free() };
        assert!(buffer.is_empty());
    }
}
