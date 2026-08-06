// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The Weald MLS binding.
//!
//! Step 0 establishes the build root, the toolchain pin and the coverage gate.
//! The twelve-function seam in `specs/backend/relay/mls-binding.md` lands in
//! step 7 and nothing here anticipates it.
//!
//! What exists now is the one thing the client needs before any MLS function
//! does: a way to check that the XCFramework it linked against is the one this
//! source produced. `specs/backend/build/environments.md` pins this component
//! by checksum, and a checksum is only useful next to a version the running
//! process can be asked for.
//!
//! This crate has no test double in any environment. See
//! `specs/backend/build/local-harness.md`.

pub mod agent_card;
pub mod agent_cbor;
pub mod agent_corpus;
pub mod agent_invoke;
pub mod agent_lifecycle;
pub mod agent_vectors;
pub mod boundary;
pub mod buffer;
pub mod ffi;
pub mod handle;
pub mod recovery;
pub mod session;
pub mod status;
pub mod store;

/// The ABI generation. Bumped only when the shape of the seam changes, never
/// for an implementation change, because the client compares this against the
/// value it was compiled for and refuses a mismatch.
pub const ABI_VERSION: u32 = 0;

/// Crate version as a NUL-terminated C string, so the client can log the exact
/// build without a marshalling step that could itself be wrong.
const VERSION_C: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

/// The ABI generation this library implements.
///
/// # Safety
/// None required. No pointers cross, nothing is allocated, and there is no
/// state to confine to a thread.
#[no_mangle]
pub extern "C" fn weald_mls_abi_version() -> u32 {
    ABI_VERSION
}

/// A pointer to a static, NUL-terminated build version. The caller does not own
/// it and must not free it. Static lifetime is the whole reason this returns a
/// borrowed pointer rather than an owned buffer: the ownership rules in
/// `mls-binding.md` apply to key material and message buffers, and adding a
/// free call for a compile-time constant would be a free call to get wrong.
///
/// # Safety
/// The returned pointer is valid for the lifetime of the process and points to
/// a NUL-terminated ASCII string.
#[no_mangle]
pub extern "C" fn weald_mls_version() -> *const core::ffi::c_char {
    VERSION_C.as_ptr().cast()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_version_is_the_declared_generation() {
        assert_eq!(weald_mls_abi_version(), ABI_VERSION);
    }

    #[test]
    fn version_is_nul_terminated_and_matches_the_package() {
        let ptr = weald_mls_version();
        // Safety: the contract of `weald_mls_version` is exactly this.
        let s = unsafe { core::ffi::CStr::from_ptr(ptr) };
        assert_eq!(s.to_str().expect("ascii"), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn version_pointer_is_stable_across_calls() {
        assert_eq!(weald_mls_version(), weald_mls_version());
    }
}
