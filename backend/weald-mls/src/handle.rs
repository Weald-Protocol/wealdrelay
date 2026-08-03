// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Opaque, thread-confined handles.
//!
//! `specs/backend/relay/mls-binding.md`: "Handles are opaque and thread-confined. One
//! group handle is used from one actor. Concurrency lives in Swift, not in the FFI."
//!
//! Swift's half of that is a non-`Sendable` wrapper, which the compiler checks. This is
//! the other half, and it exists because a compiler check on one side of a C ABI is a
//! convention on the other: `dlsym` and an `@_silgen_name` declaration reach these
//! functions with no wrapper in the way at all. So the handle records the thread it was
//! created on and refuses anybody else, and the refusal is a typed status rather than a
//! data race.
//!
//! ## Why not a mutex
//!
//! Because the rule is not "one call at a time", it is "one owner". OpenMLS group state
//! plus a SQLite connection under a mutex would be *safe* and would still be wrong: two
//! actors interleaving commits on one group produce an epoch sequence neither of them
//! expects, and the crash-consistency rule in the spec (one transaction per processed
//! message, covering MLS state and document state together) is a claim about a single
//! owner advancing the group. A refusal makes the mistake visible in a test; a mutex
//! hides it until a customer sees a fork.

use std::thread::ThreadId;

use crate::status::{Error, Result};

/// A live handle's tag, so a pointer that is not one of ours is refused rather than
/// dereferenced.
///
/// Not a security measure: a caller who can pass an arbitrary pointer can do worse. It is
/// a diagnostic, and what it soundly catches is a live pointer that is not one of ours,
/// which would otherwise be a wild read inside OpenMLS.
const MAGIC: u64 = 0x5745_414C_4D4C_5300; // "WEALMLS\0"

/// What a magic becomes once the handle is freed.
///
/// **This does not make use-after-free safe, and an earlier version of this comment
/// claimed it did.** Reading the tag requires dereferencing the pointer, and once
/// ``consume`` has handed the `Box` back to the allocator there is no defined dereference
/// of it, whatever bytes happen to still be there. `miri` says exactly that, and the
/// finding is recorded in `build-evidence/step-07/miri.txt` and in the deleted test at the
/// bottom of this file.
///
/// It is kept because stamping it costs one store and does turn the common mistake, a
/// Swift `deinit` that runs twice, into a status often enough to be worth having. It is
/// not relied on. The property that actually keeps use-after-free out of the product is
/// that the Swift wrapper owns the handle, frees it once, and never lets the pointer
/// escape, which the compiler checks.
const FREED: u64 = 0xDEAD_0000_DEAD_0000;

/// One owned thing behind an opaque pointer.
///
/// Generic over the payload so the handle rules are written once and tested without
/// OpenMLS: `Handle<Session>` is what the ABI hands out, and the tests in this file use
/// `Handle<i32>` to exercise every refusal without building a group.
pub struct Handle<T> {
    magic: u64,
    owner: ThreadId,
    value: T,
}

impl<T> Handle<T> {
    /// Wrap `value` and give the caller a pointer to it.
    ///
    /// The box is leaked deliberately: ownership has crossed to the caller, and the only
    /// way back is ``consume``.
    pub fn into_raw(value: T) -> *mut Handle<T> {
        Box::into_raw(Box::new(Handle {
            magic: MAGIC,
            owner: std::thread::current().id(),
            value,
        }))
    }

    /// Borrow the payload, checking that this is a live handle owned by this thread.
    ///
    /// # Safety
    /// `raw` must be null, or a pointer this library produced through ``into_raw``.
    pub unsafe fn borrow<'a>(raw: *mut Handle<T>) -> Result<&'a mut T> {
        // Safety: forwarded to `check`, which does the null and tag validation before
        // anything is read out of the payload.
        let handle = unsafe { Self::check(raw)? };
        Ok(&mut handle.value)
    }

    /// Take the handle back and return its payload, so it can be dropped in Rust.
    ///
    /// # Safety
    /// As ``borrow``. The pointer must not be used again afterwards.
    pub unsafe fn consume(raw: *mut Handle<T>) -> Result<T> {
        // Safety: forwarded.
        let handle = unsafe { Self::check(raw)? };
        // Marked dead before the box is reclaimed, so a second free through the same
        // pointer is refused rather than freeing an allocation twice. That is a
        // best-effort guard: the allocator may have reused the memory, and nothing here
        // can make a genuine double free safe. What it does buy is that the ordinary
        // mistake, a Swift `deinit` that runs twice, is a status and not a crash.
        handle.magic = FREED;
        // Safety: the pointer came from `Box::into_raw` in `into_raw` and has not been
        // reclaimed, because the magic was still `MAGIC` a line ago.
        let owned = unsafe { Box::from_raw(raw) };
        Ok(owned.value)
    }

    /// The null, tag and thread checks, in the order that reads no memory it has not yet
    /// validated.
    ///
    /// # Safety
    /// As ``borrow``.
    unsafe fn check<'a>(raw: *mut Handle<T>) -> Result<&'a mut Handle<T>> {
        if raw.is_null() {
            return Err(Error::InvalidHandle);
        }
        // Safety: not null, and the caller's contract is that it is one of ours.
        let handle = unsafe { &mut *raw };
        if handle.magic != MAGIC {
            return Err(Error::InvalidHandle);
        }
        if handle.owner != std::thread::current().id() {
            return Err(Error::WrongThread);
        }
        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::Status;

    #[test]
    fn a_handle_hands_back_the_value_it_was_given() {
        let raw = Handle::into_raw(41);
        // Safety: `raw` is live and this is its owning thread.
        let value = unsafe { Handle::borrow(raw) }.expect("a live handle");
        *value += 1;
        let taken = unsafe { Handle::consume(raw) }.expect("a live handle");
        assert_eq!(taken, 42);
    }

    #[test]
    fn null_is_not_a_handle() {
        let error = unsafe { Handle::<i32>::borrow(core::ptr::null_mut()) }.expect_err("refused");
        assert_eq!(error.status(), Status::InvalidHandle);
        let error = unsafe { Handle::<i32>::consume(core::ptr::null_mut()) }.expect_err("refused");
        assert_eq!(error.status(), Status::InvalidHandle);
    }

    #[test]
    fn a_pointer_that_is_not_ours_is_refused_rather_than_read() {
        // A live allocation of the right size and alignment with the wrong contents,
        // which is what a pointer from another library looks like.
        let mut impostor = Handle {
            magic: 0,
            owner: std::thread::current().id(),
            value: 7_i32,
        };
        let raw: *mut Handle<i32> = &mut impostor;
        let error = unsafe { Handle::borrow(raw) }.expect_err("refused");
        assert_eq!(error.status(), Status::InvalidHandle);
    }

    // There was a test here called `a_freed_handle_is_refused_on_the_second_use`, and it
    // is deleted rather than skipped. It asserted that calling `borrow` on a pointer that
    // `consume` had already reclaimed answers `InvalidHandle`, and it passed.
    //
    // It passed by performing undefined behaviour. `miri` says so in one line, recorded in
    // `build-evidence/step-07/miri.txt`:
    //
    //     error: Undefined Behavior: constructing invalid value of type
    //     &mut handle::Handle<i32>: encountered a dangling reference (use-after-free)
    //        --> src/handle.rs:104:31
    //
    // and the `ffi.rs` suite found the same thing independently from the other side: the
    // freed allocation had been reused, so the magic read back as valid and the thread id
    // did not, and the call answered `WrongThread`. Two methods, one finding.
    //
    // The `FREED` tag cannot be made sound. Reading it requires dereferencing the pointer,
    // and after the `Box` goes back to the allocator there is no dereference of it that is
    // defined, whatever value happens to be in those bytes. A test that performs UB and
    // passes is worse than no test: it is written down as evidence for a property the
    // program does not have.
    //
    // So the tag stays, documented as what it is, a diagnostic that turns the common
    // mistake into a status often enough to be worth its two lines, and the claim that it
    // is a defence is withdrawn. What actually keeps use-after-free out of this product is
    // one level up: the Swift wrapper owns each handle, frees it exactly once in `deinit`,
    // and never exposes the pointer, which is a property the compiler checks rather than
    // one a runtime tag hopes for. `Sources/MLS/MLSSession.swift` is where that is
    // enforced and `Tests/MLSBindingTests.swift` is where it is asserted.
    //
    // The two soundly-testable refusals, a null pointer and a live pointer that is not
    // ours, are covered by the two tests above this comment.

    #[test]
    fn another_thread_is_refused_and_the_handle_survives_it() {
        let raw = Handle::into_raw(5_i32);
        // A raw pointer is not `Send`, which is the whole point: the address is moved
        // across as a number, exactly the way a caller that ignored the rule would.
        let address = raw as usize;
        let status = std::thread::spawn(move || {
            let elsewhere = address as *mut Handle<i32>;
            // Safety: a live handle owned by another thread, which is the case under test.
            unsafe { Handle::borrow(elsewhere) }
                .map(|_| Status::Ok)
                .unwrap_or_else(|error| error.status())
        })
        .join()
        .expect("the thread ran");
        assert_eq!(status, Status::WrongThread);

        // Refused, and not damaged: the owner can still use it. A guard that poisoned
        // the handle would turn one caller's mistake into a lost group.
        let value = unsafe { Handle::borrow(raw) }.expect("still ours");
        assert_eq!(*value, 5);

        // And freeing from the wrong thread is refused too, so the payload is not
        // dropped on a thread that does not own it.
        let status = std::thread::spawn(move || {
            let elsewhere = address as *mut Handle<i32>;
            unsafe { Handle::consume(elsewhere) }
                .map(|_| Status::Ok)
                .unwrap_or_else(|error| error.status())
        })
        .join()
        .expect("the thread ran");
        assert_eq!(status, Status::WrongThread);
        let taken = unsafe { Handle::consume(raw) }.expect("still ours");
        assert_eq!(taken, 5);
    }
}
