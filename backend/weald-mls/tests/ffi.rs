// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The seam through real pointers, which is the only way Swift will ever reach it.
//!
//! `backend/weald-mls/tests/session.rs` drives the Rust API, and it drives it hard. This
//! file exists because that suite cannot see the layer Swift actually calls. Everything
//! between a `GroupHandle` and a `Session` is marshalling, and marshalling is where the
//! mistakes in a hand-written C ABI live: an out-parameter written on a failure path, a
//! length read before a null check, a handle borrowed after it was freed. None of those
//! are reachable from a test that holds a `&mut Session`.
//!
//! What is proven here, from `specs/backend/build/phases-relay.md` step 7:
//!
//! - "Negative: a panic deliberately raised inside the boundary returns a typed error and
//!   does not unwind into Swift."
//! - The ownership rule in `specs/backend/relay/mls-binding.md`: "Buffers in, owned
//!   buffers out, freed by an explicit call."
//! - "Handles are opaque and thread-confined", enforced rather than documented.
//! - The four recovery-wrap functions the seam grew in this step, which are the only ones
//!   that can return an epoch secret and therefore the ones whose refusals matter most.
//!
//! Every case here is real OpenMLS against a real SQLite database, and every pointer is a
//! real pointer. There is no test double in this crate, in any environment.

use std::ffi::CString;

use weald_mls::buffer::{weald_mls_buffer_free, Buffer};
use weald_mls::ffi::*;
use weald_mls::status::Status;

/// A NUL-terminated `:memory:`, which is what every case here opens.
fn memory() -> CString {
    CString::new(":memory:").expect("no interior nul")
}

/// The status code a call answered with, named rather than compared as a number.
fn status(code: i32) -> Status {
    Status::ALL
        .into_iter()
        .find(|s| *s as i32 == code)
        .unwrap_or_else(|| panic!("a code this build does not know: {code}"))
}

/// Open a device handle, which every other call needs.
fn open_device(identity: &[u8]) -> DeviceHandle {
    let database = memory();
    let mut handle: DeviceHandle = core::ptr::null_mut();
    // Safety: the pointers are live for the call and `handle` is writable.
    let code = unsafe {
        weald_mls_device_open(
            database.as_ptr(),
            identity.as_ptr(),
            identity.len(),
            &mut handle,
        )
    };
    assert_eq!(status(code), Status::Ok);
    assert!(!handle.is_null());
    handle
}

/// Take an owned buffer's bytes and free it, which is the caller's half of the ownership
/// contract.
///
/// Written as one helper so no case in this file can forget the free. A leak here would
/// not fail a test, which is exactly why it is not left to each case to remember.
fn take(buffer: &mut Buffer) -> Vec<u8> {
    // Safety: the buffer was written by a call that answered `Ok`.
    let bytes = unsafe { buffer.as_slice() }.to_vec();
    // Safety: owned by us, freed exactly once.
    unsafe { weald_mls_buffer_free(buffer) };
    bytes
}

/// A group of one, as a handle.
fn create_group(device: DeviceHandle, group: &[u8]) -> GroupHandle {
    let mut handle: GroupHandle = core::ptr::null_mut();
    // Safety: `device` is live and from this thread, `group` is readable, `handle` is
    // writable.
    let code = unsafe { weald_mls_create_group(device, group.as_ptr(), group.len(), &mut handle) };
    assert_eq!(status(code), Status::Ok);
    handle
}

const GROUP: &[u8] = b"weald-ffi-group";

#[test]
fn the_whole_invite_path_works_through_the_c_abi_and_every_buffer_is_freed() {
    // The ordinary product path, end to end, but every value crossing as a pointer. If
    // the Rust API works and this does not, the bug is in the marshalling, which is the
    // whole reason this file is separate from `session.rs`.
    let ada = open_device(b"ada");
    let bo = open_device(b"bo");
    let group = create_group(ada, GROUP);

    let mut package = Buffer::empty();
    // Safety: `bo` is live, `package` is writable.
    assert_eq!(
        status(unsafe { weald_mls_key_package(bo, &mut package) }),
        Status::Ok
    );
    let package_bytes = take(&mut package);
    assert!(!package_bytes.is_empty());

    let mut commit = Buffer::empty();
    let mut welcome = Buffer::empty();
    // Safety: all four pointers are live and writable as required.
    assert_eq!(
        status(unsafe {
            weald_mls_add(
                group,
                package_bytes.as_ptr(),
                package_bytes.len(),
                &mut commit,
                &mut welcome,
            )
        }),
        Status::Ok
    );
    let commit_bytes = take(&mut commit);
    let welcome_bytes = take(&mut welcome);
    // Two distinct messages. A seam that returned the welcome to the group would be
    // sending the joiner's key material to everybody.
    assert_ne!(commit_bytes, welcome_bytes);

    let mut epoch = 0u64;
    // Safety: `group` is live, `epoch` is writable.
    assert_eq!(
        status(unsafe { weald_mls_merge_pending(group, &mut epoch) }),
        Status::Ok
    );
    assert_eq!(epoch, 1, "the epoch moves when the commit is merged");

    // The other half of the ordering rule, over the same seam: a commit the relay refuses
    // is dropped rather than merged, and the epoch stays where the group's is. Built and
    // cleared here so the C caller has the same escape the Rust one does.
    let mut refused = Buffer::empty();
    // Safety: `group` is live, `refused` is writable.
    assert_eq!(
        status(unsafe { weald_mls_commit_pending(group, &mut refused) }),
        Status::Ok
    );
    let _ = take(&mut refused);
    let mut cleared = 0u64;
    // Safety: `group` is live, `cleared` is writable.
    assert_eq!(
        status(unsafe { weald_mls_clear_pending_commit(group, &mut cleared) }),
        Status::Ok
    );
    assert_eq!(cleared, 1, "a dropped commit leaves the epoch where it was");

    let mut joined: GroupHandle = core::ptr::null_mut();
    // Safety: `bo` is live, the welcome is readable, `joined` is writable.
    assert_eq!(
        status(unsafe {
            weald_mls_join_welcome(bo, welcome_bytes.as_ptr(), welcome_bytes.len(), &mut joined)
        }),
        Status::Ok
    );

    // A message across, through `encrypt` and `process`, checking the flat `ProcessedOut`
    // the ABI uses instead of a tagged union.
    let plaintext = b"hello over the boundary";
    let mut ciphertext = Buffer::empty();
    // Safety: live handle, readable input, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_encrypt(group, plaintext.as_ptr(), plaintext.len(), &mut ciphertext)
        }),
        Status::Ok
    );
    let ciphertext_bytes = take(&mut ciphertext);
    // The plaintext is not in the ciphertext, asserted at the boundary because this is the
    // buffer that actually reaches the relay.
    assert!(!ciphertext_bytes
        .windows(plaintext.len())
        .any(|w| w == plaintext));

    let mut out = ProcessedOut::zeroed();
    // Safety: live handle, readable input, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_process(
                joined,
                ciphertext_bytes.as_ptr(),
                ciphertext_bytes.len(),
                &mut out,
            )
        }),
        Status::Ok
    );
    assert_eq!(out.kind, ProcessedKind::Application as u8);
    assert_eq!(out.sender, 0);
    assert_eq!(take(&mut out.plaintext), plaintext.to_vec());

    // Freed explicitly, both of them, which is the contract.
    // Safety: live handles, freed exactly once each.
    unsafe {
        assert_eq!(status(weald_mls_free(joined)), Status::Ok);
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(bo)), Status::Ok);
    }
}

#[test]
fn a_null_handle_is_refused_and_a_freed_one_is_only_best_effort() {
    // This test was first written to assert that a freed handle answers `InvalidHandle`,
    // and it failed with `WrongThread`. The assertion was wrong, not the library, and the
    // reason is worth writing down because it is the kind of thing a green suite hides.
    //
    // `Handle::consume` stamps `FREED` over the magic and then hands the box back to the
    // allocator. Calling through that pointer afterwards is a read of freed memory, which
    // is undefined behaviour no tag can rescue: the allocator is free to have reused those
    // bytes, and here it had, so the magic read back as valid and the thread id did not.
    // `handle.rs` says as much in its own words: the tag is "a diagnostic", "best-effort",
    // and "nothing here can make a genuine double free safe".
    //
    // So what is asserted is what is actually true. The null case is sound and is the one
    // that happens in practice, because a Swift optional unwraps to null when a call
    // earlier in the chain failed. The use-after-free case is deliberately not asserted,
    // because a test that performs undefined behaviour and passes is not evidence of
    // anything. What keeps that bug out is the Swift wrapper owning the handle and freeing
    // it in `deinit` exactly once, which is a compile-time property of the wrapper rather
    // than a runtime property of this library.
    let mut out = Buffer::empty();
    // Safety: null is checked before anything is dereferenced.
    let code = unsafe { weald_mls_group_info(core::ptr::null_mut(), &mut out) };
    assert_eq!(status(code), Status::InvalidHandle);

    let mut package = Buffer::empty();
    // Safety: as above, on the device half of the seam.
    let code = unsafe { weald_mls_key_package(core::ptr::null_mut(), &mut package) };
    assert_eq!(status(code), Status::InvalidHandle);

    // Freeing null is a no-op rather than a crash, which is what lets a Swift `deinit`
    // run on a value whose initialiser failed.
    // Safety: null is explicitly handled.
    unsafe {
        assert_eq!(
            status(weald_mls_free(core::ptr::null_mut())),
            Status::InvalidHandle
        );
        assert_eq!(
            status(weald_mls_device_free(core::ptr::null_mut())),
            Status::InvalidHandle
        );
    }

    // And a live handle still works, so none of the above left anything behind.
    let ada = open_device(b"ada");
    let group = create_group(ada, GROUP);
    let mut out = Buffer::empty();
    // Safety: live handle from this thread.
    assert_eq!(
        status(unsafe { weald_mls_group_info(group, &mut out) }),
        Status::Ok
    );
    let _ = take(&mut out);
    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
    }
}

#[test]
fn a_handle_used_from_a_second_thread_is_refused_and_the_group_survives_it() {
    // `mls-binding.md`: "Handles are opaque and thread-confined. One group handle is used
    // from one actor." Enforced here rather than documented, and the second half of the
    // assertion is the one that matters: the handle must still work afterwards. Poisoning
    // it would turn one caller's mistake into a lost group.
    let ada = open_device(b"ada");
    let group = create_group(ada, GROUP);

    let raw = group as usize;
    let code = std::thread::spawn(move || {
        let handle = raw as GroupHandle;
        let mut out = Buffer::empty();
        // Safety: deliberately the wrong thread. The tag check happens before any state is
        // touched, which is what makes this defined rather than a data race.
        unsafe { weald_mls_group_info(handle, &mut out) }
    })
    .join()
    .expect("the thread did not panic, because the guard caught nothing to catch");
    assert_eq!(status(code), Status::WrongThread);

    // Still usable from its own thread.
    let mut out = Buffer::empty();
    // Safety: the owning thread.
    assert_eq!(
        status(unsafe { weald_mls_group_info(group, &mut out) }),
        Status::Ok
    );
    assert!(!take(&mut out).is_empty());

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
    }
}

#[test]
fn a_panic_raised_inside_the_boundary_becomes_a_status_and_does_not_unwind_into_swift() {
    // The negative the gate names by hand. A panic that crossed this boundary would be
    // undefined behaviour, and `mls-binding.md` says it "would happen first in the least
    // tested path", so the guard is tested directly rather than only relied upon.
    //
    // `weald_mls_panic_for_test` exists only under `cfg(test)` and the test profile. It is
    // not in the shipped library, which is checked by the symbol assertion in the
    // XCFramework step of this gate.
    // Safety: the function takes nothing and returns a status.
    let code = unsafe { weald_mls_panic_for_test(0) };
    assert_eq!(status(code), Status::Panicked);

    // A panic carrying a non-string payload, because a guard that only handled `&str`
    // would let this one through and that is the one that would reach Swift.
    // Safety: as above.
    let code = unsafe { weald_mls_panic_for_test(1) };
    assert_eq!(status(code), Status::Panicked);

    // The process is still alive and the library still works, which is the whole claim:
    // `Panicked` means this handle is unusable, not that the library is.
    let ada = open_device(b"ada");
    let group = create_group(ada, GROUP);
    let mut out = Buffer::empty();
    // Safety: live handle.
    assert_eq!(
        status(unsafe { weald_mls_group_info(group, &mut out) }),
        Status::Ok
    );
    let _ = take(&mut out);
    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
    }
}

#[test]
fn every_null_and_empty_input_on_the_seam_is_a_typed_refusal() {
    // The caller-bug cases, at the boundary, because a null reaching a `from_raw_parts`
    // is undefined behaviour and the check has to be in front of it rather than behind.
    let ada = open_device(b"ada");
    let group = create_group(ada, GROUP);
    let database = memory();

    let mut handle: DeviceHandle = core::ptr::null_mut();
    // A null database path.
    // Safety: null is explicitly handled by `text`.
    assert_eq!(
        status(unsafe {
            weald_mls_device_open(core::ptr::null(), b"ada".as_ptr(), 3, &mut handle)
        }),
        Status::InvalidArgument
    );
    // A null identity with a non-zero length, which is the dangerous shape.
    // Safety: null with a length is explicitly refused by `slice`.
    assert_eq!(
        status(unsafe {
            weald_mls_device_open(database.as_ptr(), core::ptr::null(), 3, &mut handle)
        }),
        Status::InvalidArgument
    );
    // An empty identity, which decodes fine and means nothing.
    // Safety: readable, empty.
    assert_eq!(
        status(unsafe { weald_mls_device_open(database.as_ptr(), b"".as_ptr(), 0, &mut handle) }),
        Status::InvalidArgument
    );

    // A null out-parameter on a function that has something to hand back. Refused rather
    // than written through, because writing through it is the crash.
    // Safety: null out is explicitly refused by `put`.
    assert_eq!(
        status(unsafe { weald_mls_group_info(group, core::ptr::null_mut()) }),
        Status::InvalidArgument
    );

    // An empty group id, and a null message to the function that eats untrusted bytes.
    let mut out: GroupHandle = core::ptr::null_mut();
    // Safety: readable, empty.
    assert_eq!(
        status(unsafe { weald_mls_create_group(ada, b"".as_ptr(), 0, &mut out) }),
        Status::InvalidArgument
    );
    let mut processed = ProcessedOut::zeroed();
    // Safety: null with a length is refused before any read.
    assert_eq!(
        status(unsafe { weald_mls_process(group, core::ptr::null(), 4, &mut processed) }),
        Status::InvalidArgument
    );

    // Hostile bytes are `Malformed`, not `InvalidArgument`, because the caller did nothing
    // wrong. The distinction is what lets Swift drop a message without telling a person
    // their client is broken.
    let junk = [0xffu8; 16];
    // Safety: readable.
    assert_eq!(
        status(unsafe { weald_mls_process(group, junk.as_ptr(), junk.len(), &mut processed) }),
        Status::Malformed
    );

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
    }
}

#[test]
fn a_wrap_is_sealed_and_opened_across_the_boundary_and_the_secret_never_crosses_unsealed() {
    // The four functions the seam grew in this step. The reason they are below the
    // boundary at all is that sealing above it would mean handing Swift a raw epoch
    // secret, so the assertion that matters is what the sealed record does and does not
    // contain.
    let ada = open_device(b"ada");
    let group = create_group(ada, GROUP);
    let database = memory();
    let seed = b"ada's twelve recovery words";

    let mut public = Buffer::empty();
    // Safety: live pointers, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_recovery_public(database.as_ptr(), seed.as_ptr(), seed.len(), &mut public)
        }),
        Status::Ok
    );
    let public_bytes = take(&mut public);
    assert!(!public_bytes.is_empty());

    let mut tag = Buffer::empty();
    // Safety: live handle, readable key, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_wrap_tag(group, public_bytes.as_ptr(), public_bytes.len(), &mut tag)
        }),
        Status::Ok
    );
    let tag_bytes = take(&mut tag);
    assert_eq!(tag_bytes.len(), 32);

    let mut wrap = Buffer::empty();
    // Safety: live handle, readable inputs, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_seal_wrap(
                group,
                GROUP.as_ptr(),
                GROUP.len(),
                public_bytes.as_ptr(),
                public_bytes.len(),
                &mut wrap,
            )
        }),
        Status::Ok
    );
    let wrap_bytes = take(&mut wrap);

    // The recovery public key is the stable per-user identifier the blinded tag exists to
    // hide, so it must not appear in the record the relay stores. This is the same claim
    // `weald-stack prove-blind` makes against the real wrap table, made here against the
    // bytes that actually leave the boundary.
    assert!(!wrap_bytes
        .windows(public_bytes.len())
        .any(|w| w == public_bytes));

    let mut secret = Buffer::empty();
    let mut group_info = Buffer::empty();
    // Safety: live pointers, both outs writable.
    assert_eq!(
        status(unsafe {
            weald_mls_open_wrap(
                database.as_ptr(),
                seed.as_ptr(),
                seed.len(),
                wrap_bytes.as_ptr(),
                wrap_bytes.len(),
                &mut secret,
                &mut group_info,
            )
        }),
        Status::Ok
    );
    let secret_bytes = take(&mut secret);
    let group_info_bytes = take(&mut group_info);
    assert_eq!(secret_bytes.len(), 32);
    // Both halves, because a wrap carrying only the secret could read a group and never
    // rejoin it, which made every closed group unreachable after a recovery.
    assert!(!group_info_bytes.is_empty());
    // The secret was never in the sealed record in the clear.
    assert!(!wrap_bytes
        .windows(secret_bytes.len())
        .any(|w| w == secret_bytes));

    // The wrong seed opens nothing, which is the whole point of the seal.
    let wrong = b"somebody else's words entirely";
    let mut secret = Buffer::empty();
    let mut group_info = Buffer::empty();
    // Safety: as above.
    assert_eq!(
        status(unsafe {
            weald_mls_open_wrap(
                database.as_ptr(),
                wrong.as_ptr(),
                wrong.len(),
                wrap_bytes.as_ptr(),
                wrap_bytes.len(),
                &mut secret,
                &mut group_info,
            )
        }),
        Status::Protocol
    );

    // And a wrap that is not a wrap is `Malformed`, the ordinary answer to a damaged row.
    let junk = b"{}";
    // Safety: as above.
    assert_eq!(
        status(unsafe {
            weald_mls_open_wrap(
                database.as_ptr(),
                seed.as_ptr(),
                seed.len(),
                junk.as_ptr(),
                junk.len(),
                &mut secret,
                &mut group_info,
            )
        }),
        Status::Malformed
    );

    // An empty recovery key on either recovery function is a caller bug, not a protocol
    // failure.
    let mut out = Buffer::empty();
    // Safety: readable, empty.
    assert_eq!(
        status(unsafe { weald_mls_wrap_tag(group, b"".as_ptr(), 0, &mut out) }),
        Status::InvalidArgument
    );

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
    }
}

#[test]
fn the_remaining_seam_functions_answer_through_pointers_too() {
    // The rest of the eighteen, so no function on the seam is reachable only from the
    // Rust API. A function that was never called through its own ABI is a function whose
    // marshalling has never run.
    let ada = open_device(b"ada");
    let bo = open_device(b"bo");
    let group = create_group(ada, GROUP);

    // `epoch` writes two out-parameters, one of them owned.
    let mut epoch = 0u64;
    let mut authenticator = Buffer::empty();
    // Safety: live handle, both outs writable.
    assert_eq!(
        status(unsafe { weald_mls_epoch(group, &mut epoch, &mut authenticator) }),
        Status::Ok
    );
    assert_eq!(epoch, 0);
    assert!(!take(&mut authenticator).is_empty());

    // `export`, the one function that has always returned key material.
    let label = CString::new("weald/ffi").expect("no nul");
    let mut secret = Buffer::empty();
    // Safety: live handle, live label, writable out.
    assert_eq!(
        status(unsafe { weald_mls_export(group, label.as_ptr(), 32, &mut secret) }),
        Status::Ok
    );
    assert_eq!(take(&mut secret).len(), 32);
    // The bound, because the length arrives from the other side of a C ABI and an
    // exporter asked for four gigabytes is a denial of service with extra steps.
    let mut secret = Buffer::empty();
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_export(group, label.as_ptr(), 1 << 30, &mut secret) }),
        Status::InvalidArgument
    );

    // `propose_add` and `commit_pending`, the two-step path for a proposer who is not the
    // committer.
    let mut package = Buffer::empty();
    // Safety: live handle, writable out.
    assert_eq!(
        status(unsafe { weald_mls_key_package(bo, &mut package) }),
        Status::Ok
    );
    let package_bytes = take(&mut package);
    let mut proposal = Buffer::empty();
    // Safety: live handle, readable input, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_propose_add(
                group,
                package_bytes.as_ptr(),
                package_bytes.len(),
                &mut proposal,
            )
        }),
        Status::Ok
    );
    let _ = take(&mut proposal);
    let mut commit = Buffer::empty();
    // Safety: live handle, writable out.
    assert_eq!(
        status(unsafe { weald_mls_commit_pending(group, &mut commit) }),
        Status::Ok
    );
    let _ = take(&mut commit);
    let mut epoch = 0u64;
    // Safety: live handle, writable out.
    assert_eq!(
        status(unsafe { weald_mls_merge_pending(group, &mut epoch) }),
        Status::Ok
    );
    assert_eq!(epoch, 1);

    // `members`, which hands out a list rather than one value.
    let mut members = Buffer::empty();
    let mut count = 0usize;
    // Safety: live handle, both outs writable.
    assert_eq!(
        status(unsafe { weald_mls_members(group, &mut members, &mut count) }),
        Status::Ok
    );
    let member_bytes = take(&mut members);
    // Two members, four bytes each, little-endian, which is the shape Swift decodes. The
    // count is handed out separately so the caller does not have to divide by a stride it
    // was told about in a doc comment.
    assert_eq!(count, 2);
    assert_eq!(member_bytes.len(), 8);

    // `member_identities`, the same list with the credential at each leaf. Records are
    // leaf, length, bytes, and the buffer must end exactly on the last one: a decoder
    // that trusted the count and ran off the end is the failure this shape prevents
    // (WEALD-L335).
    let mut named = Buffer::empty();
    let mut named_count = 0usize;
    // Safety: live handle, both outs writable.
    assert_eq!(
        status(unsafe { weald_mls_member_identities(group, &mut named, &mut named_count) }),
        Status::Ok
    );
    let named_bytes = take(&mut named);
    assert_eq!(named_count, 2);
    let mut cursor = 0usize;
    let mut decoded: Vec<(u32, Vec<u8>)> = Vec::new();
    for _ in 0..named_count {
        assert!(named_bytes.len() - cursor >= 8);
        let leaf = u32::from_le_bytes(named_bytes[cursor..cursor + 4].try_into().unwrap());
        let length =
            u32::from_le_bytes(named_bytes[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;
        assert!(named_bytes.len() - cursor >= length);
        decoded.push((leaf, named_bytes[cursor..cursor + length].to_vec()));
        cursor += length;
    }
    assert_eq!(
        cursor,
        named_bytes.len(),
        "the buffer ends on a record boundary"
    );
    assert_eq!(decoded[0], (0u32, b"ada".to_vec()));
    assert_eq!(decoded[1], (1u32, b"bo".to_vec()));
    // The leaves agree with the leaf-only call, which is the seam's own consistency.
    assert_eq!(
        decoded.iter().map(|pair| pair.0).collect::<Vec<u32>>(),
        member_bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>()
    );

    // `remove`, then `decrypt` refusing a commit, then `join_external` from a group info.
    let leaves = [1u32];
    let mut commit = Buffer::empty();
    // Safety: live handle, readable input, writable out.
    assert_eq!(
        status(unsafe { weald_mls_remove(group, leaves.as_ptr(), leaves.len(), &mut commit,) }),
        Status::Ok
    );
    let _ = take(&mut commit);
    let mut epoch = 0u64;
    // Safety: live handle.
    assert_eq!(
        status(unsafe { weald_mls_merge_pending(group, &mut epoch) }),
        Status::Ok
    );

    let mut info = Buffer::empty();
    // Safety: live handle, writable out.
    assert_eq!(
        status(unsafe { weald_mls_group_info(group, &mut info) }),
        Status::Ok
    );
    let info_bytes = take(&mut info);
    let cy = open_device(b"cy");
    let mut joined: GroupHandle = core::ptr::null_mut();
    let mut join_commit = Buffer::empty();
    // Safety: live device, readable input, both outs writable.
    assert_eq!(
        status(unsafe {
            weald_mls_join_external(
                cy,
                info_bytes.as_ptr(),
                info_bytes.len(),
                &mut joined,
                &mut join_commit,
            )
        }),
        Status::Ok
    );
    let _ = take(&mut join_commit);

    // The escape for a join the relay refuses, over the same seam: the group goes out of
    // the store while the handle stays valid to be freed the ordinary way.
    // Safety: `joined` is live.
    assert_eq!(status(unsafe { weald_mls_abandon(joined) }), Status::Ok);

    // `decrypt` refuses a message that is not an application message, rather than quietly
    // advancing an epoch inside a function called decrypt.
    let mut plaintext = Buffer::empty();
    let mut sender = 0u32;
    // Safety: live handle, readable input, both outs writable.
    assert_eq!(
        status(unsafe {
            weald_mls_decrypt(
                group,
                info_bytes.as_ptr(),
                info_bytes.len(),
                &mut plaintext,
                &mut sender,
            )
        }),
        Status::Malformed
    );

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(joined)), Status::Ok);
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(bo)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(cy)), Status::Ok);
    }
}

/// Open a device against a database on disk, which is the only kind a group outlives.
///
/// Every other case in this file opens `:memory:`. Reopening cannot be stated that way:
/// an in-memory store is gone with the handle that held it, so a restart has nothing to
/// find.
fn open_device_at(path: &std::path::Path, identity: &[u8]) -> DeviceHandle {
    let database = CString::new(path.to_str().expect("utf-8 path")).expect("no interior nul");
    let mut handle: DeviceHandle = core::ptr::null_mut();
    // Safety: the pointers are live for the call and `handle` is writable.
    let code = unsafe {
        weald_mls_device_open(
            database.as_ptr(),
            identity.as_ptr(),
            identity.len(),
            &mut handle,
        )
    };
    assert_eq!(status(code), Status::Ok);
    handle
}

/// A restart, through the C ABI: the group comes back and it is the same group.
///
/// `session.rs` proves the reopen at the Rust layer. This exists because Swift never
/// reaches that layer: it calls `weald_mls_open_group` and gets back an opaque
/// `GroupHandle` through an out-parameter, and the marshalling in between is where a
/// hand-written C ABI goes wrong. The epoch and the authenticator are read back through
/// the ABI too, so what is compared is what a caller could actually observe.
#[test]
fn a_group_reopens_through_the_c_abi_and_is_the_same_group_it_was() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join("ada.sqlite");

    // First launch: Ada creates the group and adds Bo, so the state that has to survive
    // is a two-member group at epoch 1.
    let ada = open_device_at(&path, b"ada");
    let bo = open_device(b"bo");
    let group = create_group(ada, GROUP);

    let mut package = Buffer::empty();
    // Safety: `bo` is live, `package` is writable.
    assert_eq!(
        status(unsafe { weald_mls_key_package(bo, &mut package) }),
        Status::Ok
    );
    let package_bytes = take(&mut package);

    let mut commit = Buffer::empty();
    let mut welcome = Buffer::empty();
    // Safety: all four pointers are live and writable as required.
    assert_eq!(
        status(unsafe {
            weald_mls_add(
                group,
                package_bytes.as_ptr(),
                package_bytes.len(),
                &mut commit,
                &mut welcome,
            )
        }),
        Status::Ok
    );
    let _ = take(&mut commit);
    let welcome_bytes = take(&mut welcome);

    let mut epoch = 0u64;
    // Safety: `group` is live, `epoch` is writable.
    assert_eq!(
        status(unsafe { weald_mls_merge_pending(group, &mut epoch) }),
        Status::Ok
    );
    assert_eq!(epoch, 1);

    let mut authenticator = Buffer::empty();
    // Safety: live handle, both out-parameters writable.
    assert_eq!(
        status(unsafe { weald_mls_epoch(group, core::ptr::null_mut(), &mut authenticator) }),
        Status::Ok
    );
    let authenticator_before = take(&mut authenticator);

    let mut joined: GroupHandle = core::ptr::null_mut();
    // Safety: `bo` is live, the welcome is readable, `joined` is writable.
    assert_eq!(
        status(unsafe {
            weald_mls_join_welcome(bo, welcome_bytes.as_ptr(), welcome_bytes.len(), &mut joined)
        }),
        Status::Ok
    );

    // The restart. Both of Ada's handles go, which is what leaving the process does.
    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
    }

    let ada = open_device_at(&path, b"ada");
    let mut reopened: GroupHandle = core::ptr::null_mut();
    // Safety: `ada` is live, `GROUP` is readable, `reopened` is writable.
    assert_eq!(
        status(unsafe { weald_mls_open_group(ada, GROUP.as_ptr(), GROUP.len(), &mut reopened) }),
        Status::Ok
    );
    assert!(
        !reopened.is_null(),
        "an ok status with a null handle would mean the group was not found"
    );

    let mut epoch_after = 0u64;
    let mut authenticator = Buffer::empty();
    // Safety: live handle, both out-parameters writable.
    assert_eq!(
        status(unsafe { weald_mls_epoch(reopened, &mut epoch_after, &mut authenticator) }),
        Status::Ok
    );
    assert_eq!(epoch_after, 1);
    // The out-of-band check, across the restart and across the boundary. Everything else
    // could hold for a second group created under the same id; this could not.
    assert_eq!(take(&mut authenticator), authenticator_before);

    // And the reopened handle is usable, not just well-formed: Bo reads what it writes.
    let plaintext = b"back after a restart, over the boundary";
    let mut ciphertext = Buffer::empty();
    // Safety: live handle, readable input, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_encrypt(
                reopened,
                plaintext.as_ptr(),
                plaintext.len(),
                &mut ciphertext,
            )
        }),
        Status::Ok
    );
    let ciphertext_bytes = take(&mut ciphertext);

    let mut out = ProcessedOut::zeroed();
    // Safety: live handle, readable input, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_process(
                joined,
                ciphertext_bytes.as_ptr(),
                ciphertext_bytes.len(),
                &mut out,
            )
        }),
        Status::Ok
    );
    assert_eq!(out.kind, ProcessedKind::Application as u8);
    assert_eq!(out.sender, 0);
    assert_eq!(take(&mut out.plaintext), plaintext.to_vec());

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(reopened)), Status::Ok);
        assert_eq!(status(weald_mls_free(joined)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(bo)), Status::Ok);
    }
}

/// A group this device is not in answers ok with a null handle, which is the contract.
///
/// Stated as its own case because it is the one place in this seam where `Ok` and a null
/// out-parameter is a correct answer rather than a bug. A caller that checked only the
/// status would dereference null, so the shape is asserted here the way the header
/// documents it.
#[test]
fn a_group_this_device_is_not_in_answers_ok_with_a_null_handle() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let ada = open_device_at(&dir.path().join("ada.sqlite"), b"ada");
    let group = create_group(ada, GROUP);

    let missing = b"a-group-ada-was-never-in";
    let mut handle: GroupHandle = core::ptr::null_mut();
    // Safety: `ada` is live, the id is readable, `handle` is writable.
    assert_eq!(
        status(unsafe { weald_mls_open_group(ada, missing.as_ptr(), missing.len(), &mut handle) }),
        Status::Ok
    );
    assert!(
        handle.is_null(),
        "not being in a group is an ordinary answer and must not invent a session"
    );

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
    }
}
