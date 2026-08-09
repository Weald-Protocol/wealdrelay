// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The edges of the seam: the shapes `tests/ffi.rs` reaches for once and the ones it never
//! reaches at all.
//!
//! `tests/ffi.rs` drives the ordinary product path through real pointers. This file drives
//! the two things that path cannot: the answers `weald_mls_process` gives for a message
//! that is not an application message, and the out-parameter contract itself.
//!
//! `specs/backend/relay/mls-binding.md` states that contract in one sentence: "Buffers in,
//! owned buffers out, freed by an explicit call." Two rules fall out of it and neither is
//! visible from a test that always passes a real pointer:
//!
//! - A required out-parameter that is null is a typed refusal, taken before anything is
//!   created or consumed. A seam that created a group and then failed to hand it back
//!   would leak the group and, worse, would leave the caller a member of something it does
//!   not know it joined.
//! - An optional out-parameter that is null is an ordinary success. Swift passes null for
//!   the epoch it does not care about, and a library that refused that would push a
//!   throwaway variable into every call site.
//!
//! Every pointer here is a real pointer and every case is real OpenMLS against a real
//! SQLite database, as in `tests/ffi.rs`. There is no test double in this crate.

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

/// One device's key package, as bytes the caller owns.
fn key_package(device: DeviceHandle) -> Vec<u8> {
    let mut package = Buffer::empty();
    // Safety: `device` is live and from this thread, `package` is writable.
    let code = unsafe { weald_mls_key_package(device, &mut package) };
    assert_eq!(status(code), Status::Ok);
    let bytes = take(&mut package);
    assert!(!bytes.is_empty());
    bytes
}

/// The epoch a group is at, read through the seam.
fn epoch_of(group: GroupHandle) -> u64 {
    let mut epoch = u64::MAX;
    // Safety: `group` is live and from this thread, `epoch` is writable.
    let code = unsafe { weald_mls_epoch(group, &mut epoch, core::ptr::null_mut()) };
    assert_eq!(status(code), Status::Ok);
    epoch
}

/// A group of two: ada holding it and bo joined from the welcome.
///
/// Written once because three cases below need a second member to send to, and a member
/// added by hand in each of them would be three chances to get the merge order wrong.
fn group_of_two(ada: DeviceHandle, bo: DeviceHandle) -> (GroupHandle, GroupHandle) {
    let group = create_group(ada, GROUP);
    let package = key_package(bo);
    let mut commit = Buffer::empty();
    let mut welcome = Buffer::empty();
    // Safety: live handle, readable input, both outs writable.
    let code = unsafe {
        weald_mls_add(
            group,
            package.as_ptr(),
            package.len(),
            &mut commit,
            &mut welcome,
        )
    };
    assert_eq!(status(code), Status::Ok);
    let _ = take(&mut commit);
    let welcome_bytes = take(&mut welcome);
    // Safety: live handle, the epoch is not wanted here.
    assert_eq!(
        status(unsafe { weald_mls_merge_pending(group, core::ptr::null_mut()) }),
        Status::Ok
    );

    let mut joined: GroupHandle = core::ptr::null_mut();
    // Safety: live device, readable welcome, writable out.
    let code = unsafe {
        weald_mls_join_welcome(bo, welcome_bytes.as_ptr(), welcome_bytes.len(), &mut joined)
    };
    assert_eq!(status(code), Status::Ok);
    assert!(!joined.is_null());
    (group, joined)
}

const GROUP: &[u8] = b"weald-ffi-edges";

#[test]
fn a_commit_reaches_the_caller_as_a_commit_carrying_the_epoch_it_moved_to() {
    // `ProcessedOut` is flat rather than a tagged union, for the reason `ffi.rs` gives:
    // a tag across a C ABI is a place to get the tag wrong. So the tag has to be checked
    // for every kind through the ABI, and this is the commit kind. The epoch is the field
    // that matters: a client that merged a commit and was told epoch zero would republish
    // its wraps at the wrong epoch, which is the one mistake `groups.md` cannot recover
    // from.
    let ada = open_device(b"ada");
    let bo = open_device(b"bo");
    let cy = open_device(b"cy");
    let (group, joined) = group_of_two(ada, bo);
    assert_eq!(epoch_of(joined), 1);

    // Ada adds a third member. That commit is what bo has to process.
    let package = key_package(cy);
    let mut commit = Buffer::empty();
    let mut welcome = Buffer::empty();
    // Safety: live handle, readable input, both outs writable.
    assert_eq!(
        status(unsafe {
            weald_mls_add(
                group,
                package.as_ptr(),
                package.len(),
                &mut commit,
                &mut welcome,
            )
        }),
        Status::Ok
    );
    let commit_bytes = take(&mut commit);
    let _ = take(&mut welcome);

    let mut out = ProcessedOut::zeroed();
    // Safety: live handle, readable input, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_process(joined, commit_bytes.as_ptr(), commit_bytes.len(), &mut out)
        }),
        Status::Ok
    );
    assert_eq!(out.kind, ProcessedKind::Commit as u8);
    // The epoch after the merge, not the epoch before it, and not zero.
    assert_eq!(out.epoch, 2);
    assert_eq!(out.epoch, epoch_of(joined));
    // A commit has no plaintext and no meaningful sender leaf. Both are stated rather
    // than left to whatever the last call happened to leave in the struct, because Swift
    // reads all three fields and only the tag tells it which one to believe.
    assert_eq!(out.sender, 0);
    assert!(
        out.plaintext.is_empty(),
        "a commit must not hand out a buffer the caller then has to free"
    );
    // Freeing it anyway is a no-op, which is what lets Swift free unconditionally.
    // Safety: the empty buffer, freed through the one entry point.
    unsafe { weald_mls_buffer_free(&mut out.plaintext) };

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(joined)), Status::Ok);
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(bo)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(cy)), Status::Ok);
    }
}

#[test]
fn a_proposal_reaches_the_caller_as_a_proposal_and_moves_nothing() {
    // The third kind, and the one whose whole meaning is that nothing happened yet:
    // `session.rs` stores it as pending and returns `Processed::Proposal`. A seam that
    // reported it as a commit would have every other member believing the epoch moved
    // when it did not, and their next message would be rejected by everybody.
    let ada = open_device(b"ada");
    let bo = open_device(b"bo");
    let cy = open_device(b"cy");
    let (group, joined) = group_of_two(ada, bo);

    let package = key_package(cy);
    let mut proposal = Buffer::empty();
    // Safety: live handle, readable input, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_propose_add(group, package.as_ptr(), package.len(), &mut proposal)
        }),
        Status::Ok
    );
    let proposal_bytes = take(&mut proposal);

    let before = epoch_of(joined);
    let mut out = ProcessedOut::zeroed();
    // Safety: live handle, readable input, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_process(
                joined,
                proposal_bytes.as_ptr(),
                proposal_bytes.len(),
                &mut out,
            )
        }),
        Status::Ok
    );
    assert_eq!(out.kind, ProcessedKind::Proposal as u8);
    assert_eq!(out.epoch, 0, "a proposal reports no epoch");
    assert_eq!(out.sender, 0);
    assert!(out.plaintext.is_empty());
    // Safety: the empty buffer, freed through the one entry point.
    unsafe { weald_mls_buffer_free(&mut out.plaintext) };

    // And the receiver really did not move: the proposal is pending, not applied.
    assert_eq!(epoch_of(joined), before);
    let mut members = Buffer::empty();
    let mut count = 0usize;
    // Safety: live handle, both outs writable.
    assert_eq!(
        status(unsafe { weald_mls_members(joined, &mut members, &mut count) }),
        Status::Ok
    );
    let _ = take(&mut members);
    assert_eq!(count, 2, "the proposed member is not in the group yet");

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(joined)), Status::Ok);
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(bo)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(cy)), Status::Ok);
    }
}

#[test]
fn a_null_out_handle_is_refused_before_anything_is_created_or_consumed() {
    // The four functions that hand back a handle check their out-parameter first, before
    // the device is borrowed and before MLS state moves. That ordering is the assertion:
    // `weald_mls_create_group` that built the group and then found nowhere to put it would
    // leak it, and `weald_mls_join_welcome` that consumed the welcome would leave the
    // caller unable to retry with the same bytes. So each refusal is followed by the same
    // call done properly, which is what proves nothing was spent on the failed attempt.
    let ada = open_device(b"ada");
    let bo = open_device(b"bo");
    let database = memory();

    // `weald_mls_device_open`, whose out-parameter is the only thing it produces.
    // Safety: null out is checked before anything is dereferenced.
    assert_eq!(
        status(unsafe {
            weald_mls_device_open(
                database.as_ptr(),
                b"dee".as_ptr(),
                3,
                core::ptr::null_mut::<DeviceHandle>(),
            )
        }),
        Status::InvalidArgument
    );

    // `weald_mls_create_group`.
    // Safety: as above.
    assert_eq!(
        status(unsafe {
            weald_mls_create_group(
                ada,
                GROUP.as_ptr(),
                GROUP.len(),
                core::ptr::null_mut::<GroupHandle>(),
            )
        }),
        Status::InvalidArgument
    );
    // The device is untouched by that, so the same call with somewhere to put the answer
    // still works.
    let group = create_group(ada, GROUP);

    // `weald_mls_open_group`. The one whose ordinary answer can itself be a null handle,
    // which is why a null out-parameter has to be refused rather than treated as "the
    // caller did not want the group": those two are indistinguishable after the fact.
    // Safety: null out is checked before the device is borrowed or the id is read.
    assert_eq!(
        status(unsafe {
            weald_mls_open_group(
                ada,
                GROUP.as_ptr(),
                GROUP.len(),
                core::ptr::null_mut::<GroupHandle>(),
            )
        }),
        Status::InvalidArgument
    );

    // `weald_mls_join_welcome`. A welcome is minted for real, offered to a null out, and
    // then used, because a welcome that was consumed by the refused call would fail here.
    let package = key_package(bo);
    let mut commit = Buffer::empty();
    let mut welcome = Buffer::empty();
    // Safety: live handle, readable input, both outs writable.
    assert_eq!(
        status(unsafe {
            weald_mls_add(
                group,
                package.as_ptr(),
                package.len(),
                &mut commit,
                &mut welcome,
            )
        }),
        Status::Ok
    );
    let _ = take(&mut commit);
    let welcome_bytes = take(&mut welcome);
    // Safety: null out is refused before the welcome is read.
    assert_eq!(
        status(unsafe {
            weald_mls_join_welcome(
                bo,
                welcome_bytes.as_ptr(),
                welcome_bytes.len(),
                core::ptr::null_mut::<GroupHandle>(),
            )
        }),
        Status::InvalidArgument
    );
    // Safety: live handle, the epoch is not wanted here.
    assert_eq!(
        status(unsafe { weald_mls_merge_pending(group, core::ptr::null_mut()) }),
        Status::Ok
    );
    let mut joined: GroupHandle = core::ptr::null_mut();
    // Safety: the same welcome, this time with somewhere to put the group.
    assert_eq!(
        status(unsafe {
            weald_mls_join_welcome(bo, welcome_bytes.as_ptr(), welcome_bytes.len(), &mut joined)
        }),
        Status::Ok
    );
    assert!(!joined.is_null());

    // `weald_mls_join_external`, the one with two out-parameters. The commit buffer is
    // the observable half: it must still be empty afterwards, because the refusal happens
    // before the external commit is produced. A caller left holding a commit for a group
    // it does not have a handle to could publish an epoch change nobody can follow.
    let mut info = Buffer::empty();
    // Safety: live handle, writable out.
    assert_eq!(
        status(unsafe { weald_mls_group_info(group, &mut info) }),
        Status::Ok
    );
    let info_bytes = take(&mut info);
    let cy = open_device(b"cy");
    let mut join_commit = Buffer::empty();
    // Safety: null handle-out, real buffer-out.
    assert_eq!(
        status(unsafe {
            weald_mls_join_external(
                cy,
                info_bytes.as_ptr(),
                info_bytes.len(),
                core::ptr::null_mut::<GroupHandle>(),
                &mut join_commit,
            )
        }),
        Status::InvalidArgument
    );
    assert!(
        join_commit.is_empty(),
        "a refused external join must not leave a commit behind"
    );

    // `weald_mls_process`, whose out-parameter is a struct rather than a handle, and whose
    // input is the untrusted one. Null out, real message: refused without the message
    // being processed, which the epoch shows.
    let plaintext = b"a message nobody will read";
    let mut ciphertext = Buffer::empty();
    // Safety: live handle, readable input, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_encrypt(group, plaintext.as_ptr(), plaintext.len(), &mut ciphertext)
        }),
        Status::Ok
    );
    let ciphertext_bytes = take(&mut ciphertext);
    let before = epoch_of(joined);
    // Safety: null out is refused before the handle is borrowed.
    assert_eq!(
        status(unsafe {
            weald_mls_process(
                joined,
                ciphertext_bytes.as_ptr(),
                ciphertext_bytes.len(),
                core::ptr::null_mut::<ProcessedOut>(),
            )
        }),
        Status::InvalidArgument
    );
    assert_eq!(epoch_of(joined), before);
    // The same message still decrypts, so the refused call consumed nothing.
    let mut out = ProcessedOut::zeroed();
    // Safety: as above, with somewhere to put the answer.
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
    assert_eq!(take(&mut out.plaintext), plaintext.to_vec());

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(joined)), Status::Ok);
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(bo)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(cy)), Status::Ok);
    }
}

#[test]
fn a_null_array_or_a_null_buffer_out_is_refused_and_writes_nothing() {
    // The two remaining null shapes on the seam. `weald_mls_remove` takes an array of leaf
    // indices rather than bytes, so it has its own null check rather than `boundary`'s,
    // and a check written twice is a check that can be forgotten once. `weald_mls_decrypt`
    // is the case where the refusal has to reach past a second out-parameter: it must not
    // report a sender for a plaintext it had nowhere to put.
    let ada = open_device(b"ada");
    let bo = open_device(b"bo");
    let (group, joined) = group_of_two(ada, bo);

    let mut out = Buffer::empty();
    // Safety: null with a length is refused before `from_raw_parts` sees it.
    assert_eq!(
        status(unsafe { weald_mls_remove(group, core::ptr::null(), 1, &mut out) }),
        Status::InvalidArgument
    );
    assert!(
        out.is_empty(),
        "a refused remove must not hand out a commit"
    );
    // A null array with no elements is refused too: this seam takes "no leaves" as a
    // caller bug rather than as an empty removal, and the answer must not depend on the
    // length beside the null.
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_remove(group, core::ptr::null(), 0, &mut out) }),
        Status::InvalidArgument
    );
    assert!(out.is_empty());
    assert_eq!(epoch_of(group), 1, "nothing was committed");

    // `weald_mls_decrypt` with a real ciphertext, a null plaintext-out and a real
    // sender-out. The sentinel below is what makes this an assertion rather than a hope:
    // if the success arm ran it would overwrite it with a leaf index.
    let plaintext = b"nowhere to put this";
    let mut ciphertext = Buffer::empty();
    // Safety: live handle, readable input, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_encrypt(group, plaintext.as_ptr(), plaintext.len(), &mut ciphertext)
        }),
        Status::Ok
    );
    let ciphertext_bytes = take(&mut ciphertext);
    let mut sender = u32::MAX - 7;
    // Safety: null buffer-out is refused by `put`; `sender` is writable.
    assert_eq!(
        status(unsafe {
            weald_mls_decrypt(
                joined,
                ciphertext_bytes.as_ptr(),
                ciphertext_bytes.len(),
                core::ptr::null_mut::<Buffer>(),
                &mut sender,
            )
        }),
        Status::InvalidArgument
    );
    assert_eq!(
        sender,
        u32::MAX - 7,
        "a failed decrypt must not write the sender out-parameter"
    );

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(joined)), Status::Ok);
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(bo)), Status::Ok);
    }
}

#[test]
fn a_decrypt_hands_back_the_plaintext_and_the_sender_leaf_that_produced_it() {
    // `weald_mls_decrypt` is the narrow door: `mls-binding.md` has it refuse anything that
    // is not an application message, and `tests/ffi.rs` proves the refusal. This is the
    // other half, the success, and the sender leaf is the field that matters. Swift
    // attributes a message to a member by that number, so a decrypt that returned the
    // plaintext with the wrong leaf would put one person's words under another's name.
    let ada = open_device(b"ada");
    let bo = open_device(b"bo");
    let (group, joined) = group_of_two(ada, bo);

    let plaintext = b"ada speaking, on leaf zero";
    let mut ciphertext = Buffer::empty();
    // Safety: live handle, readable input, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_encrypt(group, plaintext.as_ptr(), plaintext.len(), &mut ciphertext)
        }),
        Status::Ok
    );
    let ciphertext_bytes = take(&mut ciphertext);

    let mut out = Buffer::empty();
    let mut sender = u32::MAX;
    // Safety: live handle, readable input, both outs writable.
    assert_eq!(
        status(unsafe {
            weald_mls_decrypt(
                joined,
                ciphertext_bytes.as_ptr(),
                ciphertext_bytes.len(),
                &mut out,
                &mut sender,
            )
        }),
        Status::Ok
    );
    assert_eq!(take(&mut out), plaintext.to_vec());
    assert_eq!(sender, 0, "ada is the group's first leaf");

    // The same call with no interest in the sender. Null there is a success, not a
    // refusal: Swift passes null when it is decrypting a message it already attributed,
    // and a library that refused would force a throwaway variable into every call site.
    let mut ciphertext = Buffer::empty();
    // Safety: live handle, readable input, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_encrypt(group, plaintext.as_ptr(), plaintext.len(), &mut ciphertext)
        }),
        Status::Ok
    );
    let ciphertext_bytes = take(&mut ciphertext);
    let mut out = Buffer::empty();
    // Safety: live handle, readable input, buffer-out writable, sender deliberately null.
    assert_eq!(
        status(unsafe {
            weald_mls_decrypt(
                joined,
                ciphertext_bytes.as_ptr(),
                ciphertext_bytes.len(),
                &mut out,
                core::ptr::null_mut::<u32>(),
            )
        }),
        Status::Ok
    );
    assert_eq!(take(&mut out), plaintext.to_vec());

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(joined)), Status::Ok);
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(bo)), Status::Ok);
    }
}

#[test]
fn an_optional_out_parameter_left_null_is_an_ordinary_success() {
    // Four functions take an out-parameter the caller may not want: the epoch from
    // `merge_pending`, either half of `epoch`, and the count from `members`. Null there
    // means "do not tell me", and the call must otherwise do exactly what it does with a
    // pointer. Both directions of each check are exercised, because a check written as
    // `if !p.is_null()` that was accidentally inverted would still pass a suite that only
    // ever passed one of the two.
    let ada = open_device(b"ada");
    let bo = open_device(b"bo");
    let group = create_group(ada, GROUP);

    let package = key_package(bo);
    let mut commit = Buffer::empty();
    let mut welcome = Buffer::empty();
    // Safety: live handle, readable input, both outs writable.
    assert_eq!(
        status(unsafe {
            weald_mls_add(
                group,
                package.as_ptr(),
                package.len(),
                &mut commit,
                &mut welcome,
            )
        }),
        Status::Ok
    );
    let _ = take(&mut commit);
    let _ = take(&mut welcome);

    // The merge, with nowhere to report the epoch. It still happened, which the following
    // read proves.
    // Safety: live handle, null out is explicitly permitted.
    assert_eq!(
        status(unsafe { weald_mls_merge_pending(group, core::ptr::null_mut::<u64>()) }),
        Status::Ok
    );

    // And the clear, with nowhere to report the epoch. Nothing is pending by now, which
    // is deliberately not an error: a failure path that had to know how far it got would
    // be a failure path with a second bug in it.
    // Safety: live handle, null out is explicitly permitted.
    assert_eq!(
        status(unsafe { weald_mls_clear_pending_commit(group, core::ptr::null_mut::<u64>()) }),
        Status::Ok
    );

    // `epoch` with both halves null: nothing to write, still a success, and the group is
    // unharmed by being asked for something it was not allowed to answer.
    // Safety: live handle, both outs deliberately null.
    assert_eq!(
        status(unsafe {
            weald_mls_epoch(
                group,
                core::ptr::null_mut::<u64>(),
                core::ptr::null_mut::<Buffer>(),
            )
        }),
        Status::Ok
    );
    // The authenticator alone, which is the shape a client uses when it already knows the
    // epoch and only wants something to compare.
    let mut authenticator = Buffer::empty();
    // Safety: live handle, epoch deliberately null, buffer-out writable.
    assert_eq!(
        status(unsafe { weald_mls_epoch(group, core::ptr::null_mut::<u64>(), &mut authenticator) }),
        Status::Ok
    );
    assert!(!take(&mut authenticator).is_empty());
    // And the epoch alone, which is the read every other case here uses. One, because the
    // merge above did happen.
    assert_eq!(epoch_of(group), 1);

    // `members` with no count. The buffer still carries the leaves, four little-endian
    // bytes each, which is the stride Swift decodes: the count is a convenience, not the
    // only way to know how many there are.
    let mut members = Buffer::empty();
    // Safety: live handle, buffer-out writable, count deliberately null.
    assert_eq!(
        status(unsafe { weald_mls_members(group, &mut members, core::ptr::null_mut::<usize>()) }),
        Status::Ok
    );
    let member_bytes = take(&mut members);
    assert_eq!(member_bytes.len(), 8);
    assert_eq!(
        member_bytes,
        vec![0, 0, 0, 0, 1, 0, 0, 0],
        "two leaves, zero and one, little-endian"
    );

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(bo)), Status::Ok);
    }
}

#[test]
fn the_status_a_never_written_out_parameter_reports_is_the_one_a_success_returns() {
    // `weald_mls_status_ok` exists so Swift can initialise a status variable without
    // hardcoding a number this crate owns. That is only useful if it is the same number a
    // successful call actually returns, so it is compared against one rather than against
    // a literal: a constant that drifted from the enum would be worse than no constant,
    // because every call site would look initialised and be wrong.
    let ok = weald_mls_status_ok();
    assert_eq!(status(ok), Status::Ok);

    let ada = open_device(b"ada");
    let group = create_group(ada, GROUP);
    let mut info = Buffer::empty();
    // Safety: live handle, writable out.
    let code = unsafe { weald_mls_group_info(group, &mut info) };
    assert_eq!(code, ok);
    assert!(!take(&mut info).is_empty());

    // And it is not the code a refusal returns, which is the other half of being useful.
    // Safety: null out is refused.
    let refused = unsafe { weald_mls_group_info(group, core::ptr::null_mut::<Buffer>()) };
    assert_ne!(refused, ok);

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
    }
}

#[test]
fn every_function_that_takes_a_handle_refuses_a_null_one_before_it_reads_anything_else() {
    // `mls-binding.md`: "Handles are opaque and thread-confined." The null case is the one
    // that actually happens, because a Swift optional unwraps to null when a call earlier
    // in the chain failed, and the next call in the sequence runs anyway. Every function on
    // the seam is checked, not a sample of them: the check is one line per function and a
    // function that lost it would fault inside `Handle::borrow` rather than answer.
    //
    // Every out-parameter here carries a sentinel, so each case asserts the second half of
    // the rule as well: a refused call writes nothing at all.
    let ada = open_device(b"ada");
    let package = key_package(ada);
    let label = CString::new("weald/ffi").expect("no nul");
    let null_device: DeviceHandle = core::ptr::null_mut();
    let null_group: GroupHandle = core::ptr::null_mut();

    // The three that produce a group from a device.
    let mut handle: GroupHandle = core::ptr::null_mut();
    // Safety: a null handle is refused by `Handle::borrow` before it is dereferenced.
    assert_eq!(
        status(unsafe {
            weald_mls_open_group(null_device, GROUP.as_ptr(), GROUP.len(), &mut handle)
        }),
        Status::InvalidHandle
    );
    // A null handle here means the group was not found, and a refused call must not be
    // readable as that. The status is what separates them, and it is asserted above.
    assert!(handle.is_null());
    // Safety: a null handle is refused by `Handle::borrow` before it is dereferenced.
    assert_eq!(
        status(unsafe {
            weald_mls_create_group(null_device, GROUP.as_ptr(), GROUP.len(), &mut handle)
        }),
        Status::InvalidHandle
    );
    assert!(handle.is_null());
    // Safety: as above.
    assert_eq!(
        status(unsafe {
            weald_mls_join_welcome(null_device, package.as_ptr(), package.len(), &mut handle)
        }),
        Status::InvalidHandle
    );
    assert!(handle.is_null());
    let mut commit = Buffer::empty();
    // Safety: as above, with the second out-parameter that has to stay untouched.
    assert_eq!(
        status(unsafe {
            weald_mls_join_external(
                null_device,
                package.as_ptr(),
                package.len(),
                &mut handle,
                &mut commit,
            )
        }),
        Status::InvalidHandle
    );
    assert!(handle.is_null());
    assert!(commit.is_empty());

    // The membership half.
    let mut welcome = Buffer::empty();
    // Safety: null group handle, real inputs and outs.
    assert_eq!(
        status(unsafe {
            weald_mls_add(
                null_group,
                package.as_ptr(),
                package.len(),
                &mut commit,
                &mut welcome,
            )
        }),
        Status::InvalidHandle
    );
    assert!(commit.is_empty() && welcome.is_empty());
    // Safety: as above.
    assert_eq!(
        status(unsafe {
            weald_mls_propose_add(null_group, package.as_ptr(), package.len(), &mut commit)
        }),
        Status::InvalidHandle
    );
    assert!(commit.is_empty());
    let leaves = [1u32];
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_remove(null_group, leaves.as_ptr(), 1, &mut commit) }),
        Status::InvalidHandle
    );
    assert!(commit.is_empty());
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_commit_pending(null_group, &mut commit) }),
        Status::InvalidHandle
    );
    assert!(commit.is_empty());
    let mut epoch = 77u64;
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_merge_pending(null_group, &mut epoch) }),
        Status::InvalidHandle
    );
    assert_eq!(epoch, 77, "a refused merge must not report an epoch");
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_clear_pending_commit(null_group, &mut epoch) }),
        Status::InvalidHandle
    );
    assert_eq!(epoch, 77, "a refused clear must not report an epoch either");
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_abandon(null_group) }),
        Status::InvalidHandle
    );

    // The message half.
    let mut processed = ProcessedOut::zeroed();
    // Safety: as above.
    assert_eq!(
        status(unsafe {
            weald_mls_process(null_group, package.as_ptr(), package.len(), &mut processed)
        }),
        Status::InvalidHandle
    );
    assert!(processed.plaintext.is_empty());
    // Safety: as above.
    assert_eq!(
        status(unsafe {
            weald_mls_encrypt(null_group, package.as_ptr(), package.len(), &mut commit)
        }),
        Status::InvalidHandle
    );
    assert!(commit.is_empty());
    let mut sender = 5u32;
    // Safety: as above.
    assert_eq!(
        status(unsafe {
            weald_mls_decrypt(
                null_group,
                package.as_ptr(),
                package.len(),
                &mut commit,
                &mut sender,
            )
        }),
        Status::InvalidHandle
    );
    assert!(commit.is_empty());
    assert_eq!(sender, 5);

    // The state half, including the exporter, which is the one that returns key material
    // and therefore the one whose handle check matters most.
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_export(null_group, label.as_ptr(), 32, &mut commit) }),
        Status::InvalidHandle
    );
    assert!(commit.is_empty());
    let mut authenticator = Buffer::empty();
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_epoch(null_group, &mut epoch, &mut authenticator) }),
        Status::InvalidHandle
    );
    assert_eq!(epoch, 77);
    assert!(authenticator.is_empty());
    let mut count = 9usize;
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_members(null_group, &mut commit, &mut count) }),
        Status::InvalidHandle
    );
    assert!(commit.is_empty());
    assert_eq!(count, 9);

    // The recovery wraps, which are the two that could hand out an epoch secret.
    // Safety: as above.
    assert_eq!(
        status(unsafe {
            weald_mls_wrap_tag(null_group, package.as_ptr(), package.len(), &mut commit)
        }),
        Status::InvalidHandle
    );
    assert!(commit.is_empty());
    // Safety: as above.
    assert_eq!(
        status(unsafe {
            weald_mls_seal_wrap(
                null_group,
                GROUP.as_ptr(),
                GROUP.len(),
                package.as_ptr(),
                package.len(),
                &mut commit,
            )
        }),
        Status::InvalidHandle
    );
    assert!(commit.is_empty());

    // Safety: live, freed once.
    unsafe { assert_eq!(status(weald_mls_device_free(ada)), Status::Ok) };
}

#[test]
fn every_input_pointer_on_the_seam_is_checked_before_it_is_read() {
    // The other half of `boundary`'s job. A null pointer with a non-zero length reaching
    // `core::slice::from_raw_parts` is undefined behaviour, so the check has to be in front
    // of every one of them rather than behind the first. This walks the whole seam, one
    // null per input, because the checks are written per call site and a missing one is
    // invisible until the day the caller's optional is empty.
    let ada = open_device(b"ada");
    let group = create_group(ada, GROUP);
    let database = memory();
    let seed = b"ada's twelve recovery words";
    let mut out = Buffer::empty();
    let mut handle: GroupHandle = core::ptr::null_mut();

    // The two joins, which read bytes that came off the wire.
    // Safety: null with a length is refused by `boundary::slice` before any read.
    assert_eq!(
        status(unsafe { weald_mls_join_welcome(ada, core::ptr::null(), 9, &mut handle) }),
        Status::InvalidArgument
    );
    assert!(handle.is_null());
    let mut commit = Buffer::empty();
    // Safety: as above.
    assert_eq!(
        status(unsafe {
            weald_mls_join_external(ada, core::ptr::null(), 9, &mut handle, &mut commit)
        }),
        Status::InvalidArgument
    );
    assert!(handle.is_null() && commit.is_empty());

    // The group id `open_group` is asked to look up, which is a caller-supplied slice
    // like any other and is read before the store is consulted.
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_open_group(ada, core::ptr::null(), 9, &mut handle) }),
        Status::InvalidArgument
    );
    assert!(handle.is_null());
    // A zero length is refused too, on the same rule `create_group` follows: an empty id
    // is a caller that lost track of what it was asking for, not a group nobody has.
    // Safety: readable pointer, zero length, writable out.
    assert_eq!(
        status(unsafe { weald_mls_open_group(ada, GROUP.as_ptr(), 0, &mut handle) }),
        Status::InvalidArgument
    );
    assert!(handle.is_null());

    // The two that read a key package.
    let mut welcome = Buffer::empty();
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_add(group, core::ptr::null(), 9, &mut commit, &mut welcome) }),
        Status::InvalidArgument
    );
    assert!(commit.is_empty() && welcome.is_empty());
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_propose_add(group, core::ptr::null(), 9, &mut out) }),
        Status::InvalidArgument
    );
    assert!(out.is_empty());

    // The message functions. `encrypt` is the one input on the seam that is allowed to be
    // empty, because a zero-length application message is a legitimate thing to send, so
    // both answers are asserted here rather than only the refusal.
    // Safety: null with a length is refused; null with no length is "nothing".
    assert_eq!(
        status(unsafe { weald_mls_encrypt(group, core::ptr::null(), 9, &mut out) }),
        Status::InvalidArgument
    );
    assert!(out.is_empty());
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_encrypt(group, core::ptr::null(), 0, &mut out) }),
        Status::Ok
    );
    assert!(
        !take(&mut out).is_empty(),
        "an empty plaintext still produces a real ciphertext"
    );
    let mut sender = 3u32;
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_decrypt(group, core::ptr::null(), 9, &mut out, &mut sender) }),
        Status::InvalidArgument
    );
    assert!(out.is_empty());
    assert_eq!(sender, 3);

    // The exporter's label, which is a C string rather than a byte range.
    // Safety: null is refused by `boundary::text`.
    assert_eq!(
        status(unsafe { weald_mls_export(group, core::ptr::null(), 32, &mut out) }),
        Status::InvalidArgument
    );
    assert!(out.is_empty());

    // The recovery wraps, both of whose inputs are refused by name.
    // Safety: as above.
    assert_eq!(
        status(unsafe {
            weald_mls_seal_wrap(
                group,
                core::ptr::null(),
                9,
                seed.as_ptr(),
                seed.len(),
                &mut out,
            )
        }),
        Status::InvalidArgument
    );
    assert!(out.is_empty());
    // Safety: as above.
    assert_eq!(
        status(unsafe {
            weald_mls_seal_wrap(
                group,
                GROUP.as_ptr(),
                GROUP.len(),
                core::ptr::null(),
                9,
                &mut out,
            )
        }),
        Status::InvalidArgument
    );
    assert!(out.is_empty());

    // The two functions that take a database path instead of a handle, because the device
    // calling them may not have a group yet.
    // Safety: null path is refused by `boundary::text`.
    assert_eq!(
        status(unsafe {
            weald_mls_recovery_public(core::ptr::null(), seed.as_ptr(), seed.len(), &mut out)
        }),
        Status::InvalidArgument
    );
    assert!(out.is_empty());
    // Safety: null seed with a length.
    assert_eq!(
        status(unsafe {
            weald_mls_recovery_public(database.as_ptr(), core::ptr::null(), 9, &mut out)
        }),
        Status::InvalidArgument
    );
    assert!(out.is_empty());

    let mut secret = Buffer::empty();
    let mut group_info = Buffer::empty();
    // Safety: null path.
    assert_eq!(
        status(unsafe {
            weald_mls_open_wrap(
                core::ptr::null(),
                seed.as_ptr(),
                seed.len(),
                b"{}".as_ptr(),
                2,
                &mut secret,
                &mut group_info,
            )
        }),
        Status::InvalidArgument
    );
    // Safety: null seed with a length.
    assert_eq!(
        status(unsafe {
            weald_mls_open_wrap(
                database.as_ptr(),
                core::ptr::null(),
                9,
                b"{}".as_ptr(),
                2,
                &mut secret,
                &mut group_info,
            )
        }),
        Status::InvalidArgument
    );
    // Safety: null wrap with a length.
    assert_eq!(
        status(unsafe {
            weald_mls_open_wrap(
                database.as_ptr(),
                seed.as_ptr(),
                seed.len(),
                core::ptr::null(),
                9,
                &mut secret,
                &mut group_info,
            )
        }),
        Status::InvalidArgument
    );
    assert!(
        secret.is_empty() && group_info.is_empty(),
        "no refusal on the recovery path may hand out an epoch secret"
    );

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
    }
}

#[test]
fn what_mls_itself_refuses_comes_back_as_a_status_rather_than_as_a_half_done_call() {
    // The inputs that are well formed as pointers and wrong as MLS. These are the cases
    // where the failure comes from `session`, and what is proved here is the marshalling
    // around it: the status reaches the caller, and the out-parameter is left as it was so
    // a Swift caller that checks the code before the buffer is never reading a stale value.
    let ada = open_device(b"ada");
    let bo = open_device(b"bo");
    let group = create_group(ada, GROUP);
    let mut out = Buffer::empty();

    // A group id this device already has. `Protocol`, not `InvalidArgument`: the caller's
    // pointers were fine and MLS is the one saying no.
    let mut second: GroupHandle = core::ptr::null_mut();
    // Safety: live device, readable id, writable out.
    assert_eq!(
        status(unsafe { weald_mls_create_group(ada, GROUP.as_ptr(), GROUP.len(), &mut second) }),
        Status::Protocol
    );
    assert!(
        second.is_null(),
        "a refused create must not hand back a handle"
    );

    // Bytes that are a valid MLS message of the wrong kind, offered to both joins. A key
    // package is not a welcome and is not a group info, and saying so is what keeps a
    // misrouted message from being half-applied.
    let package = key_package(bo);
    // Safety: live device, readable input, writable out.
    assert_eq!(
        status(unsafe { weald_mls_join_welcome(bo, package.as_ptr(), package.len(), &mut second) }),
        Status::Malformed
    );
    assert!(second.is_null());
    let mut commit = Buffer::empty();
    // Safety: as above.
    assert_eq!(
        status(unsafe {
            weald_mls_join_external(
                bo,
                package.as_ptr(),
                package.len(),
                &mut second,
                &mut commit,
            )
        }),
        Status::Malformed
    );
    assert!(second.is_null() && commit.is_empty());

    // And bytes that are not a key package, offered to the two functions that consume one.
    let junk = [0x7fu8; 24];
    let mut welcome = Buffer::empty();
    // Safety: readable input, both outs writable.
    assert_eq!(
        status(unsafe {
            weald_mls_add(group, junk.as_ptr(), junk.len(), &mut commit, &mut welcome)
        }),
        Status::Malformed
    );
    assert!(commit.is_empty() && welcome.is_empty());
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_propose_add(group, junk.as_ptr(), junk.len(), &mut out) }),
        Status::Malformed
    );
    assert!(out.is_empty());

    // A leaf that is not in the tree. The group is still at its own epoch afterwards,
    // which is the assertion that matters: a removal that failed halfway would leave this
    // device unable to talk to anybody.
    let missing = [99u32];
    // Safety: live handle, readable array, writable out.
    assert_eq!(
        status(unsafe { weald_mls_remove(group, missing.as_ptr(), 1, &mut out) }),
        Status::Protocol
    );
    assert!(out.is_empty());
    assert_eq!(epoch_of(group), 0);

    // A second commit while one is already pending. MLS allows exactly one, and the seam
    // has to pass that refusal through rather than produce a commit the group will reject.
    let package = key_package(bo);
    // Safety: live handle, readable input, writable out.
    assert_eq!(
        status(unsafe { weald_mls_propose_add(group, package.as_ptr(), package.len(), &mut out) }),
        Status::Ok
    );
    let _ = take(&mut out);
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_commit_pending(group, &mut out) }),
        Status::Ok
    );
    let _ = take(&mut out);
    // Safety: as above, with a commit already pending.
    assert_eq!(
        status(unsafe { weald_mls_commit_pending(group, &mut out) }),
        Status::Protocol
    );
    assert!(out.is_empty(), "the second commit produced nothing");

    // A database path that cannot exist, on all three functions that take one. `Storage`
    // rather than `InvalidArgument`, because the path was a string and the filesystem is
    // what refused.
    let impossible = CString::new("/dev/null/not-a-directory/device.sqlite").expect("no nul");
    let mut device: DeviceHandle = core::ptr::null_mut();
    // Safety: readable path, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_device_open(impossible.as_ptr(), b"dee".as_ptr(), 3, &mut device)
        }),
        Status::Storage
    );
    assert!(device.is_null());
    let seed = b"dee's twelve recovery words";
    // Safety: as above.
    assert_eq!(
        status(unsafe {
            weald_mls_recovery_public(impossible.as_ptr(), seed.as_ptr(), seed.len(), &mut out)
        }),
        Status::Storage
    );
    assert!(out.is_empty());

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(bo)), Status::Ok);
    }
}

#[test]
fn a_device_that_was_evicted_can_no_longer_produce_anything_for_the_group() {
    // Eviction is the state every function on the group half has to survive being called
    // in, because the member being removed finds out by processing the commit that removes
    // it: the call that leaves it evicted is a success, and every call after it is not.
    // The one that matters is `weald_mls_wrap_tag`, which exports a group secret. A tag
    // derived from a group this device has been thrown out of would be published to the
    // relay under a slot nobody can open.
    let ada = open_device(b"ada");
    let bo = open_device(b"bo");
    let (group, joined) = group_of_two(ada, bo);

    let leaves = [1u32];
    let mut commit = Buffer::empty();
    // Safety: live handle, readable array, writable out.
    assert_eq!(
        status(unsafe { weald_mls_remove(group, leaves.as_ptr(), 1, &mut commit) }),
        Status::Ok
    );
    let commit_bytes = take(&mut commit);
    // Safety: live handle, epoch not wanted.
    assert_eq!(
        status(unsafe { weald_mls_merge_pending(group, core::ptr::null_mut()) }),
        Status::Ok
    );

    // Bo learns of it the only way a removed member can: by processing the commit.
    let mut processed = ProcessedOut::zeroed();
    // Safety: live handle, readable input, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_process(
                joined,
                commit_bytes.as_ptr(),
                commit_bytes.len(),
                &mut processed,
            )
        }),
        Status::Ok
    );
    assert_eq!(processed.kind, ProcessedKind::Commit as u8);
    assert_eq!(processed.epoch, 2);
    // Safety: the empty buffer, freed through the one entry point.
    unsafe { weald_mls_buffer_free(&mut processed.plaintext) };

    // Everything that would speak for the group now refuses, and hands back nothing.
    let mut out = Buffer::empty();
    // Safety: live handle, readable input, writable out.
    assert_eq!(
        status(unsafe { weald_mls_encrypt(joined, b"still here?".as_ptr(), 11, &mut out) }),
        Status::Protocol
    );
    assert!(out.is_empty());
    let public = [0x11u8; 32];
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_wrap_tag(joined, public.as_ptr(), public.len(), &mut out) }),
        Status::Protocol
    );
    assert!(
        out.is_empty(),
        "an evicted member must not publish a wrap tag"
    );
    let package = key_package(ada);
    let mut welcome = Buffer::empty();
    // Safety: as above.
    assert_eq!(
        status(unsafe {
            weald_mls_add(
                joined,
                package.as_ptr(),
                package.len(),
                &mut out,
                &mut welcome,
            )
        }),
        Status::Protocol
    );
    assert!(out.is_empty() && welcome.is_empty());

    // The group ada still holds is unaffected by any of it.
    assert_eq!(epoch_of(group), 2);

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(joined)), Status::Ok);
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(bo)), Status::Ok);
    }
}

#[test]
fn an_out_parameter_that_cannot_be_written_fails_the_call_and_writes_no_other_one() {
    // The functions with two out-parameters write them in a deliberate order, and `ffi.rs`
    // says why at each one: the commit before the group handle, the group info before the
    // epoch secret. This is the case that ordering exists for. A null second parameter
    // must fail the whole call and leave the first alone, because the alternative is a
    // caller holding half an answer with a status that says it holds none.
    let ada = open_device(b"ada");
    let bo = open_device(b"bo");
    let group = create_group(ada, GROUP);

    // `weald_mls_join_external` with nowhere to put the commit. The handle stays null:
    // a joiner that got its group but not its commit would be a member of a group nobody
    // else knows it is in, which is the exact situation the comment in `ffi.rs` describes.
    let mut info = Buffer::empty();
    // Safety: live handle, writable out.
    assert_eq!(
        status(unsafe { weald_mls_group_info(group, &mut info) }),
        Status::Ok
    );
    let info_bytes = take(&mut info);
    let mut joined: GroupHandle = core::ptr::null_mut();
    // Safety: live device, readable input, handle-out writable, commit-out deliberately
    // null.
    assert_eq!(
        status(unsafe {
            weald_mls_join_external(
                bo,
                info_bytes.as_ptr(),
                info_bytes.len(),
                &mut joined,
                core::ptr::null_mut::<Buffer>(),
            )
        }),
        Status::InvalidArgument
    );
    assert!(
        joined.is_null(),
        "no handle may be handed out when the commit could not be"
    );

    // `weald_mls_add` with nowhere to put the commit. The welcome, which is written
    // second, must not be produced either: a welcome delivered for a commit that was
    // never published invites somebody into an epoch the group never reached.
    let package = key_package(bo);
    let mut welcome = Buffer::empty();
    // Safety: live handle, readable input, commit-out deliberately null.
    assert_eq!(
        status(unsafe {
            weald_mls_add(
                group,
                package.as_ptr(),
                package.len(),
                core::ptr::null_mut::<Buffer>(),
                &mut welcome,
            )
        }),
        Status::InvalidArgument
    );
    assert!(
        welcome.is_empty(),
        "the second out-parameter must be untouched when the first could not be written"
    );

    // `weald_mls_members`, where the count is written by the success arm and the buffer by
    // the body. A null buffer fails the call, so the count must never arrive: a caller
    // told there are two members with nothing to read them from would index into a null.
    let mut count = 42usize;
    // Safety: live handle, buffer-out deliberately null, count writable.
    assert_eq!(
        status(unsafe { weald_mls_members(group, core::ptr::null_mut::<Buffer>(), &mut count) }),
        Status::InvalidArgument
    );
    assert_eq!(count, 42, "a refused call must not report a count");

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(bo)), Status::Ok);
    }
}

#[test]
fn a_recovery_wrap_refuses_every_way_it_can_be_asked_for_wrongly() {
    // The recovery path, which is the only one that can produce an epoch secret, so its
    // refusals are the ones with something to lose. `tests/ffi.rs` proves the happy path
    // and the wrong-seed refusal; these are the rest of the ways the call can fail, and
    // in every one of them the assertion is the same: no secret came out.
    let ada = open_device(b"ada");
    let group = create_group(ada, GROUP);
    let database = memory();
    let seed = b"ada's twelve recovery words";

    let mut public = Buffer::empty();
    // Safety: readable inputs, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_recovery_public(database.as_ptr(), seed.as_ptr(), seed.len(), &mut public)
        }),
        Status::Ok
    );
    let public_bytes = take(&mut public);

    // A recovery key that is not a key. The seal is HPKE to that public key, so bytes of
    // the wrong shape fail in the crypto rather than in the marshalling, and the caller
    // is told `Protocol` rather than handed an unopenable record.
    let mut out = Buffer::empty();
    // Safety: live handle, readable inputs, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_seal_wrap(
                group,
                GROUP.as_ptr(),
                GROUP.len(),
                b"nope".as_ptr(),
                4,
                &mut out,
            )
        }),
        Status::Protocol
    );
    assert!(out.is_empty());

    // A real wrap, so the remaining failures are about the call rather than the record.
    // Safety: live handle, readable inputs, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_seal_wrap(
                group,
                GROUP.as_ptr(),
                GROUP.len(),
                public_bytes.as_ptr(),
                public_bytes.len(),
                &mut out,
            )
        }),
        Status::Ok
    );
    let wrap_bytes = take(&mut out);

    // Opening it against a database that cannot be opened. The wrap parsed, the seed was
    // there, and the store is what failed: `Storage`, and nothing written.
    let impossible = CString::new("/dev/null/not-a-directory/recovery.sqlite").expect("no nul");
    let mut secret = Buffer::empty();
    let mut group_info = Buffer::empty();
    // Safety: readable inputs, both outs writable.
    assert_eq!(
        status(unsafe {
            weald_mls_open_wrap(
                impossible.as_ptr(),
                seed.as_ptr(),
                seed.len(),
                wrap_bytes.as_ptr(),
                wrap_bytes.len(),
                &mut secret,
                &mut group_info,
            )
        }),
        Status::Storage
    );
    assert!(secret.is_empty() && group_info.is_empty());

    // And opening it with the right seed but nowhere to put the group info. `ffi.rs`
    // writes the group info first precisely so this case cannot hand out the secret: a
    // recovering client that received an epoch secret and no way back into the group
    // would be able to read the traffic it captured and never rejoin, which is the shape
    // `groups.md` calls out as the worst outcome of the whole mechanism.
    // Safety: readable inputs, secret-out writable, group-info-out deliberately null.
    assert_eq!(
        status(unsafe {
            weald_mls_open_wrap(
                database.as_ptr(),
                seed.as_ptr(),
                seed.len(),
                wrap_bytes.as_ptr(),
                wrap_bytes.len(),
                &mut secret,
                core::ptr::null_mut::<Buffer>(),
            )
        }),
        Status::InvalidArgument
    );
    assert!(
        secret.is_empty(),
        "the epoch secret must not be written when the group info could not be"
    );

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
    }
}

#[test]
fn a_database_another_writer_is_holding_is_a_typed_failure_rather_than_a_wait_or_a_crash() {
    // The storage failure a desktop app actually meets: two processes, or a stale copy of
    // the app, with the same workspace database open. `mls-binding.md` puts OpenMLS's
    // state in SQLite, and a key package is a write, so a call that needs the write lock
    // while somebody else holds it has to come back as a status rather than block the
    // caller's actor or unwind through the seam.
    //
    // The lock is taken through this crate's own `Provider`, which is the same connection
    // type and the same file the device is using. That is not a test double: it is a
    // second real writer, which is exactly the situation being described.
    let dir = std::env::temp_dir().join(format!("weald-mls-ffi-edges-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a temp directory");
    let path = dir.join("device.sqlite");
    let path_text = path.to_str().expect("utf-8 path").to_string();
    let database = CString::new(path_text.clone()).expect("no interior nul");

    let mut device: DeviceHandle = core::ptr::null_mut();
    // Safety: readable path, readable identity, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_device_open(database.as_ptr(), b"ada".as_ptr(), 3, &mut device)
        }),
        Status::Ok
    );

    let other = weald_mls::store::Provider::open(&path_text).expect("a second writer");
    other
        .connection()
        .execute("begin exclusive", [])
        .expect("the write lock");

    let mut package = Buffer::empty();
    // Safety: live handle, writable out. The storage underneath is locked, which is what
    // this case is about.
    assert_eq!(
        status(unsafe { weald_mls_key_package(device, &mut package) }),
        Status::Protocol
    );
    assert!(
        package.is_empty(),
        "a key package that could not be stored must not be published"
    );

    // Released, and the same call works, so the failure was the lock and not the device.
    other
        .connection()
        .execute("commit", [])
        .expect("the write lock, released");
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_key_package(device, &mut package) }),
        Status::Ok
    );
    assert!(!take(&mut package).is_empty());

    // Safety: live, freed once.
    unsafe { assert_eq!(status(weald_mls_device_free(device)), Status::Ok) };
    drop(other);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A group whose members carry credentials too large to serialise refuses to hand out a
/// group info, through the C ABI, and writes nothing.
///
/// The identity is the caller's bytes and this seam does not bound them: Swift hands
/// `weald_mls_device_open` a pointer and a length, and the credential built from them ends
/// up in the ratchet tree, which ends up in every group info. `mls-binding.md` caps a
/// message at `wire.md`'s one mebibyte envelope, so a large enough identity makes the
/// group info unpublishable, and this is the path where that is discovered.
///
/// What is proved is that the failure is a typed status rather than a panic or a truncated
/// record, and that the out-parameter is untouched. A group info silently cut to the
/// ceiling would be a joiner's external commit built against half a tree.
#[test]
fn a_group_info_that_cannot_be_serialised_is_a_typed_refusal_that_writes_no_buffer() {
    // Over one mebibyte once the credential is in the tree.
    let huge = open_device(&vec![b'a'; 1_200_000]);
    let group = create_group(huge, GROUP);

    let mut out = Buffer::empty();
    // Safety: live handle from this thread, writable out.
    assert_eq!(
        status(unsafe { weald_mls_group_info(group, &mut out) }),
        Status::InvalidArgument
    );
    assert!(
        out.is_empty(),
        "a group info that could not be serialised must not be handed out"
    );

    // The handle is still usable for everything that does not need a group info, so what
    // refused was the record and not the session.
    let mut epoch = 0u64;
    // Safety: live handle, writable out.
    assert_eq!(
        status(unsafe { weald_mls_epoch(group, &mut epoch, core::ptr::null_mut()) }),
        Status::Ok
    );
    assert_eq!(
        epoch, 0,
        "the group is still at the epoch it was created in"
    );

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(huge)), Status::Ok);
    }
}

/// An empty recovery seed is refused by both functions that take one, and neither writes
/// anything.
///
/// The seed is the recovery phrase of `specs/backend/relay/auth.md`, and an empty one is
/// what a caller passes when the field it read was blank. HPKE would happily derive a key
/// pair from zero bytes, and that key pair would be the same one on every device in the
/// world, so the refusal is a product rule rather than a limit of the crypto. It is stated
/// once, in `recovery::RecoveryKey::derive`, and this is the proof that it survives the
/// trip across the C ABI rather than being masked by a pointer check on the way in.
#[test]
fn an_empty_recovery_seed_is_refused_by_both_functions_that_take_one() {
    let database = memory();
    let empty: [u8; 0] = [];

    let mut public = Buffer::empty();
    // Safety: readable path, a real pointer with a zero length, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_recovery_public(database.as_ptr(), empty.as_ptr(), 0, &mut public)
        }),
        Status::InvalidArgument
    );
    assert!(
        public.is_empty(),
        "no recovery public key may come back from an empty seed"
    );

    // Null and zero is the other spelling of the same thing, and it must answer the same.
    // Safety: null with a zero length is the documented way to pass nothing.
    assert_eq!(
        status(unsafe {
            weald_mls_recovery_public(database.as_ptr(), core::ptr::null(), 0, &mut public)
        }),
        Status::InvalidArgument
    );
    assert!(public.is_empty());

    // A real seed, and a real wrap, so the open below fails on the seed and nothing else.
    // Safety: readable inputs, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_recovery_public(
                database.as_ptr(),
                b"ada's twelve recovery words".as_ptr(),
                27,
                &mut public,
            )
        }),
        Status::Ok
    );
    let public_bytes = take(&mut public);

    let ada = open_device(b"ada");
    let group = create_group(ada, GROUP);
    let mut out = Buffer::empty();
    // Safety: live handle, readable inputs, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_seal_wrap(
                group,
                GROUP.as_ptr(),
                GROUP.len(),
                public_bytes.as_ptr(),
                public_bytes.len(),
                &mut out,
            )
        }),
        Status::Ok
    );
    let wrap_bytes = take(&mut out);

    let mut secret = Buffer::empty();
    let mut group_info = Buffer::empty();
    // Safety: readable inputs, an empty seed, both outs writable.
    assert_eq!(
        status(unsafe {
            weald_mls_open_wrap(
                database.as_ptr(),
                empty.as_ptr(),
                0,
                wrap_bytes.as_ptr(),
                wrap_bytes.len(),
                &mut secret,
                &mut group_info,
            )
        }),
        Status::InvalidArgument
    );
    assert!(
        secret.is_empty() && group_info.is_empty(),
        "an empty seed must not open a wrap"
    );

    // Safety: live, freed once each.
    unsafe {
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(ada)), Status::Ok);
    }
}

/// The guard's success arm reports `Ok` at the same call site whose panics report
/// `Panicked`.
///
/// `tests/ffi.rs` proves the half of `specs/backend/relay/mls-binding.md`'s rule that says
/// "every entry point is wrapped in `catch_unwind` and returns a typed error". This is the
/// other half, and without it the first half is nearly worthless: a guard that answered
/// `Panicked` unconditionally, or one that swallowed the body's return value, would pass
/// every panic case and be useless as a boundary. Proving both through one injector means
/// the success path proved here is the same code the panic cases did not take, rather than
/// a second closure written only for the test.
///
/// The injector stays out of the shipped library. This changes nothing about that: it is
/// still behind `test-hooks`, and the XCFramework step of the gate still asserts the symbol
/// is absent.
#[test]
fn the_panic_injector_reports_ok_when_its_body_returns_which_is_the_guard_s_other_half() {
    // A negative payload is the documented "return without panicking" input.
    // Safety: the function takes a value and returns a status.
    assert_eq!(status(unsafe { weald_mls_panic_for_test(-1) }), Status::Ok);
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_panic_for_test(i32::MIN) }),
        Status::Ok
    );

    // And the two panicking inputs at the same call site still report `Panicked`, so the
    // `Ok` above is a distinction the guard draws rather than the only answer it gives.
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_panic_for_test(0) }),
        Status::Panicked
    );
    // Safety: as above.
    assert_eq!(
        status(unsafe { weald_mls_panic_for_test(1) }),
        Status::Panicked
    );
}

/// A store that cannot answer comes back as a status, with no handle written.
///
/// The other half of `weald_mls_open_group`'s contract, and the one that decides whether a
/// client can tell two very different situations apart. `Ok` with a null handle means "you
/// are not in this group", which is ordinary. A store that failed has to be neither that
/// nor a panic: a client that read a corrupt database as "not in the group" would conclude
/// it had been removed from a workspace it is still a member of, and would go and rejoin as
/// a new leaf instead of repairing the file.
///
/// `session_edges.rs` makes the same claim at the Rust layer. This one is about the seam:
/// the error has to travel out through `guard` as a status and the out-parameter has to be
/// left exactly as the caller set it, because Swift reads the handle when the status is ok
/// and would otherwise be reading a stale value it had initialised itself.
#[test]
fn a_group_whose_stored_state_will_not_load_is_a_status_and_writes_no_handle() {
    let dir = std::env::temp_dir().join(format!("weald-mls-open-group-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a temp directory");
    let path = dir.join("ada.sqlite");
    let _ = std::fs::remove_file(&path);
    let path_text = path.to_str().expect("utf-8 path").to_string();
    let database = CString::new(path_text.clone()).expect("no interior nul");

    let mut device: DeviceHandle = core::ptr::null_mut();
    // Safety: readable path, readable identity, writable out.
    assert_eq!(
        status(unsafe {
            weald_mls_device_open(database.as_ptr(), b"ada".as_ptr(), 3, &mut device)
        }),
        Status::Ok
    );
    let group = create_group(device, GROUP);
    // Safety: live, freed once each. The restart is what makes the reopen a real one.
    unsafe {
        assert_eq!(status(weald_mls_free(group)), Status::Ok);
        assert_eq!(status(weald_mls_device_free(device)), Status::Ok);
    }

    // A second real connection to the same file, which is the same storage the device
    // itself uses. Nothing here stands in for anything.
    let other = weald_mls::store::Provider::open(&path_text).expect("a second connection");
    let overwritten = other
        .connection()
        .execute(
            "update openmls_group_data set group_data = randomblob(64) \
             where data_type = 'tree'",
            [],
        )
        .expect("the row is overwritten");
    assert_eq!(
        overwritten, 1,
        "the group's tree row has to exist for this case to be about corruption"
    );

    let mut device: DeviceHandle = core::ptr::null_mut();
    // Safety: as above.
    assert_eq!(
        status(unsafe {
            weald_mls_device_open(database.as_ptr(), b"ada".as_ptr(), 3, &mut device)
        }),
        Status::Ok
    );

    // The sentinel is not null, so "no handle written" is a claim about this call rather
    // than about the value happening to start out null.
    let sentinel = 0xdead_beef_usize as GroupHandle;
    let mut handle: GroupHandle = sentinel;
    // Safety: live device, readable id, writable out. The stored tree is the broken part.
    assert_eq!(
        status(unsafe { weald_mls_open_group(device, GROUP.as_ptr(), GROUP.len(), &mut handle) }),
        Status::Storage
    );
    assert_eq!(
        handle, sentinel,
        "a refused open must not write the out-parameter at all"
    );

    // Safety: live, freed once.
    unsafe {
        assert_eq!(status(weald_mls_device_free(device)), Status::Ok);
    }
    let _ = std::fs::remove_file(&path);
}
