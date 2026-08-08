// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The seam itself: the functions Swift calls.
//!
//! `specs/backend/relay/mls-binding.md` lists them and this file is exactly that list,
//! fourteen functions with the two corrections the spec now records. Every one of them is
//! the same four lines of shape:
//!
//! 1. `guard`, so no panic reaches Swift.
//! 2. read the inputs through `boundary`, so a null or a bad length is a typed refusal.
//! 3. one call into `session`, which is where the MLS actually happens.
//! 4. hand the result out as an owned ``Buffer`` the caller frees.
//!
//! There is deliberately no logic here. A decision taken in this file would be a decision
//! taken in the one place that cannot be tested without a pointer, and the property suites
//! drive `session` directly.

use crate::boundary::{guard, required_slice, slice, text};
use crate::buffer::Buffer;
use crate::handle::Handle;
use crate::session::{Config, Device, Processed, Session};
use crate::status::{Error, Result, Status};

/// A device handle: one database, one identity, the groups it belongs to.
pub type DeviceHandle = *mut Handle<Device>;
/// A group handle.
pub type GroupHandle = *mut Handle<Session>;

/// What `process` produced, as three plain fields.
///
/// `repr(C)` and flat, because a tagged union across a C ABI is a place to get the tag
/// wrong. `kind` says which of the other two mean anything.
#[repr(C)]
#[derive(Debug)]
pub struct ProcessedOut {
    /// 0 application, 1 commit, 2 proposal. Named by ``ProcessedKind``.
    pub kind: u8,
    /// The sender's leaf, for an application message. `u32::MAX` for a sender outside the
    /// tree.
    pub sender: u32,
    /// The epoch after a commit was merged. Zero for the other kinds.
    pub epoch: u64,
    /// The plaintext, for an application message. Empty otherwise.
    pub plaintext: Buffer,
}

/// The values `ProcessedOut::kind` takes.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessedKind {
    Application = 0,
    Commit = 1,
    Proposal = 2,
}

impl ProcessedOut {
    /// What a caller initialises its out-parameter to before a call.
    ///
    /// Public because Swift needs to construct one, and because a caller that invented
    /// its own zero value would be guessing at the `kind` a never-written struct carries.
    pub fn zeroed() -> Self {
        Self::empty()
    }

    fn empty() -> Self {
        Self {
            kind: ProcessedKind::Proposal as u8,
            sender: 0,
            epoch: 0,
            plaintext: Buffer::empty(),
        }
    }

    fn from(processed: Processed) -> Self {
        match processed {
            Processed::Application { plaintext, sender } => Self {
                kind: ProcessedKind::Application as u8,
                sender,
                epoch: 0,
                plaintext: Buffer::owning(plaintext),
            },
            Processed::Commit { epoch } => Self {
                kind: ProcessedKind::Commit as u8,
                sender: 0,
                epoch,
                plaintext: Buffer::empty(),
            },
            Processed::Proposal => Self::empty(),
        }
    }
}

/// Read a config from its two C fields.
///
/// # Safety
/// Both pointers must satisfy ``boundary::text`` and ``boundary::required_slice``.
unsafe fn config(
    database: *const core::ffi::c_char,
    identity: *const u8,
    identity_len: usize,
) -> Result<Config> {
    // Safety: forwarded to the two readers, which do the null and encoding checks.
    let database = unsafe { text(database, "database")? };
    let identity = unsafe { required_slice(identity, identity_len, "identity")? };
    Ok(Config {
        database: database.to_string(),
        identity: identity.to_vec(),
    })
}

/// Write `bytes` into an out-parameter the caller owns, refusing a null out-parameter.
///
/// # Safety
/// `out` must be null or point to a writable ``Buffer``.
unsafe fn put(out: *mut Buffer, bytes: Vec<u8>) -> Result<()> {
    if out.is_null() {
        return Err(Error::InvalidArgument("out buffer is null".into()));
    }
    // Safety: not null, and the caller's contract is that it is writable.
    unsafe { *out = Buffer::owning(bytes) };
    Ok(())
}

/// Refuse a missing required result before touching MLS state.
fn required_out(out: *mut Buffer, name: &str) -> Result<()> {
    if out.is_null() {
        return Err(Error::InvalidArgument(format!("{name} is null")));
    }
    Ok(())
}

// MARK: The device

/// Open a device: its database, its identity, its signing key.
///
/// # Safety
/// `database` is a NUL-terminated path, `identity` is `identity_len` readable bytes, and
/// `out` is a writable pointer that receives the handle. The handle must be freed with
/// ``weald_mls_device_free`` from the same thread.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_device_open(
    database: *const core::ffi::c_char,
    identity: *const u8,
    identity_len: usize,
    out: *mut DeviceHandle,
) -> i32 {
    guard(
        |handle| {
            // Safety: checked non-null inside the body before the value was produced.
            unsafe { *out = handle }
        },
        || {
            if out.is_null() {
                return Err(Error::InvalidArgument("out handle is null".into()));
            }
            // Safety: forwarded.
            let config = unsafe { config(database, identity, identity_len)? };
            let device = Device::open(&config)?;
            Ok(Handle::into_raw(device))
        },
    ) as i32
}

/// Free a device handle.
///
/// # Safety
/// `handle` must be null or a live device handle from this thread.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_device_free(handle: DeviceHandle) -> i32 {
    guard(
        |_| {},
        || {
            // Safety: the caller's contract.
            let device = unsafe { Handle::consume(handle)? };
            drop(device);
            Ok(())
        },
    ) as i32
}

/// A key package for this device, for somebody else to add.
///
/// # Safety
/// `handle` is a live device handle from this thread and `out` is writable.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_key_package(handle: DeviceHandle, out: *mut Buffer) -> i32 {
    guard(
        |_| {},
        || {
            required_out(out, "out")?;
            // Safety: the caller's contract.
            let device = unsafe { Handle::borrow(handle)? };
            let bytes = device.key_package()?;
            // Safety: forwarded to `put`, which refuses a null.
            unsafe { put(out, bytes) }
        },
    ) as i32
}

// MARK: Creating and joining

/// Create a group with this device as its only member.
///
/// # Safety
/// As ``weald_mls_device_open`` for the handle, plus `group_id` is `group_id_len` readable
/// bytes and `out` receives a group handle to be freed with ``weald_mls_free``.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_create_group(
    handle: DeviceHandle,
    group_id: *const u8,
    group_id_len: usize,
    out: *mut GroupHandle,
) -> i32 {
    guard(
        // Safety: `out` was checked non-null before the value existed.
        |group| unsafe { *out = group },
        || {
            if out.is_null() {
                return Err(Error::InvalidArgument("out handle is null".into()));
            }
            // Safety: the caller's contract.
            let device = unsafe { Handle::borrow(handle)? };
            // Safety: forwarded.
            let group_id = unsafe { required_slice(group_id, group_id_len, "group_id")? };
            let session = device.create_group(group_id)?;
            Ok(Handle::into_raw(session))
        },
    ) as i32
}

/// Reopen a group this device is already a member of.
///
/// Writes a null handle and answers ok when the group is not in this device's store,
/// which is the ordinary answer to "have I got this one" and not a failure. A caller
/// must therefore check the handle rather than only the status.
///
/// # Safety
/// As ``weald_mls_create_group``.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_open_group(
    handle: DeviceHandle,
    group_id: *const u8,
    group_id_len: usize,
    out: *mut GroupHandle,
) -> i32 {
    guard(
        // Safety: `out` was checked non-null before the value existed.
        |group| unsafe { *out = group },
        || {
            if out.is_null() {
                return Err(Error::InvalidArgument("out handle is null".into()));
            }
            // Safety: the caller's contract.
            let device = unsafe { Handle::borrow(handle)? };
            // Safety: forwarded.
            let group_id = unsafe { required_slice(group_id, group_id_len, "group_id")? };
            match device.open_group(group_id)? {
                Some(session) => Ok(Handle::into_raw(session)),
                None => Ok(std::ptr::null_mut()),
            }
        },
    ) as i32
}

/// Join a group from a welcome.
///
/// # Safety
/// As ``weald_mls_create_group``, with `welcome` in place of the group id.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_join_welcome(
    handle: DeviceHandle,
    welcome: *const u8,
    welcome_len: usize,
    out: *mut GroupHandle,
) -> i32 {
    guard(
        // Safety: as above.
        |group| unsafe { *out = group },
        || {
            if out.is_null() {
                return Err(Error::InvalidArgument("out handle is null".into()));
            }
            // Safety: the caller's contract.
            let device = unsafe { Handle::borrow(handle)? };
            // Safety: forwarded.
            let welcome = unsafe { required_slice(welcome, welcome_len, "welcome")? };
            let session = device.join_welcome(welcome)?;
            Ok(Handle::into_raw(session))
        },
    ) as i32
}

/// Join a group by external commit, from a group info.
///
/// Two out-parameters, because the caller has to publish the commit: a joiner that kept it
/// is a member of a group nobody else knows it is in.
///
/// # Safety
/// As ``weald_mls_join_welcome``, plus `commit_out` is a writable ``Buffer``.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_join_external(
    handle: DeviceHandle,
    group_info: *const u8,
    group_info_len: usize,
    out: *mut GroupHandle,
    commit_out: *mut Buffer,
) -> i32 {
    guard(
        // Safety: as above.
        |group| unsafe { *out = group },
        || {
            if out.is_null() {
                return Err(Error::InvalidArgument("out handle is null".into()));
            }
            required_out(commit_out, "commit_out")?;
            // Safety: the caller's contract.
            let device = unsafe { Handle::borrow(handle)? };
            // Safety: forwarded.
            let info = unsafe { required_slice(group_info, group_info_len, "group_info")? };
            let (session, commit) = device.join_external(info)?;
            // The commit goes out first: if the out-parameter is null this call has to fail
            // before a handle is created, or the caller would hold a group whose commit
            // nobody can publish.
            // Safety: forwarded.
            unsafe { put(commit_out, commit)? };
            Ok(Handle::into_raw(session))
        },
    ) as i32
}

// MARK: Membership

/// Add a member. Produces the commit for the group and the welcome for the joiner.
///
/// # Safety
/// `handle` is a live group handle from this thread; `key_package` is readable; both out
/// parameters are writable ``Buffer``s.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_add(
    handle: GroupHandle,
    key_package: *const u8,
    key_package_len: usize,
    commit_out: *mut Buffer,
    welcome_out: *mut Buffer,
) -> i32 {
    guard(
        |_| {},
        || {
            required_out(commit_out, "commit_out")?;
            required_out(welcome_out, "welcome_out")?;
            // Safety: the caller's contract.
            let session = unsafe { Handle::borrow(handle)? };
            // Safety: forwarded.
            let package = unsafe { required_slice(key_package, key_package_len, "key_package")? };
            let (commit, welcome) = session.add(package)?;
            // Safety: forwarded.
            unsafe { put(commit_out, commit)? };
            // Safety: forwarded.
            unsafe { put(welcome_out, welcome) }
        },
    ) as i32
}

/// Propose an add without committing it.
///
/// # Safety
/// As ``weald_mls_add``, with one out-parameter.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_propose_add(
    handle: GroupHandle,
    key_package: *const u8,
    key_package_len: usize,
    out: *mut Buffer,
) -> i32 {
    guard(
        |_| {},
        || {
            required_out(out, "out")?;
            // Safety: the caller's contract.
            let session = unsafe { Handle::borrow(handle)? };
            // Safety: forwarded.
            let package = unsafe { required_slice(key_package, key_package_len, "key_package")? };
            let proposal = session.propose_add(package)?;
            // Safety: forwarded.
            unsafe { put(out, proposal) }
        },
    ) as i32
}

/// Remove members by leaf index.
///
/// # Safety
/// `leaves` points to `leaves_len` readable `u32`s and `out` is writable.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_remove(
    handle: GroupHandle,
    leaves: *const u32,
    leaves_len: usize,
    out: *mut Buffer,
) -> i32 {
    guard(
        |_| {},
        || {
            required_out(out, "out")?;
            // Safety: the caller's contract.
            let session = unsafe { Handle::borrow(handle)? };
            if leaves.is_null() {
                return Err(Error::InvalidArgument("leaves is null".into()));
            }
            // Safety: the caller's contract, and the null case is refused above.
            let leaves = unsafe { core::slice::from_raw_parts(leaves, leaves_len) };
            let commit = session.remove(leaves)?;
            // Safety: forwarded.
            unsafe { put(out, commit) }
        },
    ) as i32
}

/// Commit the proposals that are pending.
///
/// # Safety
/// As ``weald_mls_remove``, without the leaves.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_commit_pending(handle: GroupHandle, out: *mut Buffer) -> i32 {
    guard(
        |_| {},
        || {
            required_out(out, "out")?;
            // Safety: the caller's contract.
            let session = unsafe { Handle::borrow(handle)? };
            let commit = session.commit_pending()?;
            // Safety: forwarded.
            unsafe { put(out, commit) }
        },
    ) as i32
}

/// Merge this device's own pending commit, once the relay has accepted it.
///
/// # Safety
/// `epoch_out` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_merge_pending(handle: GroupHandle, epoch_out: *mut u64) -> i32 {
    guard(
        |epoch| {
            if !epoch_out.is_null() {
                // Safety: checked non-null.
                unsafe { *epoch_out = epoch }
            }
        },
        || {
            // Safety: the caller's contract.
            let session = unsafe { Handle::borrow(handle)? };
            session.merge_pending()
        },
    ) as i32
}

// MARK: Messages

/// Process one message from the group.
///
/// # Safety
/// `message` is readable and `out` is a writable ``ProcessedOut``. The plaintext buffer
/// inside it must be freed with ``crate::buffer::weald_mls_buffer_free``.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_process(
    handle: GroupHandle,
    message: *const u8,
    message_len: usize,
    out: *mut ProcessedOut,
) -> i32 {
    guard(
        |processed| {
            // Safety: `out` was checked non-null before the value existed.
            unsafe { *out = processed }
        },
        || {
            if out.is_null() {
                return Err(Error::InvalidArgument("out is null".into()));
            }
            // Safety: the caller's contract.
            let session = unsafe { Handle::borrow(handle)? };
            // Safety: forwarded.
            let message = unsafe { required_slice(message, message_len, "message")? };
            Ok(ProcessedOut::from(session.process(message)?))
        },
    ) as i32
}

/// Encrypt an application message for the group.
///
/// # Safety
/// `plaintext` is readable and `out` is writable. An empty plaintext is permitted: a
/// zero-length application message is a legitimate thing to send.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_encrypt(
    handle: GroupHandle,
    plaintext: *const u8,
    plaintext_len: usize,
    out: *mut Buffer,
) -> i32 {
    guard(
        |_| {},
        || {
            required_out(out, "out")?;
            // Safety: the caller's contract.
            let session = unsafe { Handle::borrow(handle)? };
            // Safety: forwarded.
            let plaintext = unsafe { slice(plaintext, plaintext_len, "plaintext")? };
            let ciphertext = session.encrypt(plaintext)?;
            // Safety: forwarded.
            unsafe { put(out, ciphertext) }
        },
    ) as i32
}

/// Decrypt an application message, refusing anything else.
///
/// # Safety
/// `ciphertext` is readable, `out` is a writable ``Buffer``, `sender_out` is null or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_decrypt(
    handle: GroupHandle,
    ciphertext: *const u8,
    ciphertext_len: usize,
    out: *mut Buffer,
    sender_out: *mut u32,
) -> i32 {
    guard(
        |sender| {
            if !sender_out.is_null() {
                // Safety: checked non-null.
                unsafe { *sender_out = sender }
            }
        },
        || {
            required_out(out, "out")?;
            // Safety: the caller's contract.
            let session = unsafe { Handle::borrow(handle)? };
            // Safety: forwarded.
            let ciphertext = unsafe { required_slice(ciphertext, ciphertext_len, "ciphertext")? };
            let (plaintext, sender) = session.decrypt(ciphertext)?;
            // Safety: forwarded.
            unsafe { put(out, plaintext)? };
            Ok(sender)
        },
    ) as i32
}

// MARK: Exports and state

/// The exporter: the only function that returns key material.
///
/// # Safety
/// `label` is a NUL-terminated string and `out` is writable.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_export(
    handle: GroupHandle,
    label: *const core::ffi::c_char,
    length: usize,
    out: *mut Buffer,
) -> i32 {
    guard(
        |_| {},
        || {
            // Safety: the caller's contract.
            let session = unsafe { Handle::borrow(handle)? };
            // Safety: forwarded.
            let label = unsafe { text(label, "label")? };
            let secret = session.export(label, length)?;
            // Safety: forwarded.
            unsafe { put(out, secret) }
        },
    ) as i32
}

/// A group info a joiner can external-commit against.
///
/// # Safety
/// `out` is writable.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_group_info(handle: GroupHandle, out: *mut Buffer) -> i32 {
    guard(
        |_| {},
        || {
            // Safety: the caller's contract.
            let session = unsafe { Handle::borrow(handle)? };
            let info = session.group_info()?;
            // Safety: forwarded.
            unsafe { put(out, info) }
        },
    ) as i32
}

/// The epoch and its authenticator.
///
/// # Safety
/// `epoch_out` is null or writable; `authenticator_out` is null or a writable ``Buffer``.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_epoch(
    handle: GroupHandle,
    epoch_out: *mut u64,
    authenticator_out: *mut Buffer,
) -> i32 {
    guard(
        |(epoch, authenticator): (u64, Vec<u8>)| {
            if !epoch_out.is_null() {
                // Safety: checked non-null.
                unsafe { *epoch_out = epoch }
            }
            if !authenticator_out.is_null() {
                // Safety: checked non-null.
                unsafe { *authenticator_out = Buffer::owning(authenticator) }
            }
        },
        || {
            // Safety: the caller's contract.
            let session = unsafe { Handle::borrow(handle)? };
            Ok((session.epoch(), session.epoch_authenticator()))
        },
    ) as i32
}

/// The leaf indices currently in the group, as `u32`s in a buffer.
///
/// # Safety
/// `out` is a writable ``Buffer``. Its bytes are `count` little-endian `u32`s.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_members(
    handle: GroupHandle,
    out: *mut Buffer,
    count_out: *mut usize,
) -> i32 {
    guard(
        |count| {
            if !count_out.is_null() {
                // Safety: checked non-null.
                unsafe { *count_out = count }
            }
        },
        || {
            // Safety: the caller's contract.
            let session = unsafe { Handle::borrow(handle)? };
            let leaves = session.members();
            let mut bytes = Vec::with_capacity(leaves.len() * 4);
            for leaf in &leaves {
                bytes.extend_from_slice(&leaf.to_le_bytes());
            }
            // Safety: forwarded.
            unsafe { put(out, bytes)? };
            Ok(leaves.len())
        },
    ) as i32
}

/// Free a group handle.
///
/// # Safety
/// `handle` must be null or a live group handle from this thread.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_free(handle: GroupHandle) -> i32 {
    guard(
        |_| {},
        || {
            // Safety: the caller's contract.
            let session = unsafe { Handle::consume(handle)? };
            drop(session);
            Ok(())
        },
    ) as i32
}

// MARK: Recovery wraps

/// The blinded slot one recovery key occupies in this group at this epoch.
///
/// Below the boundary for the reason `specs/backend/relay/mls-binding.md` now records:
/// the tag is `BLAKE3(export(weald wraptag v1) || recovery_pubkey)`, so deriving it above
/// the boundary would mean handing Swift an exported group secret in the clear.
///
/// # Safety
/// `recovery_public` is `recovery_public_len` readable bytes and `out` is writable.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_wrap_tag(
    handle: GroupHandle,
    recovery_public: *const u8,
    recovery_public_len: usize,
    out: *mut Buffer,
) -> i32 {
    guard(
        |_| {},
        || {
            // Safety: the caller's contract.
            let session = unsafe { Handle::borrow(handle)? };
            // Safety: forwarded.
            let public = unsafe { required_slice(recovery_public, recovery_public_len, "key")? };
            let tag = session.wrap_tag(public)?;
            // Safety: forwarded.
            unsafe { put(out, tag.to_vec()) }
        },
    ) as i32
}

/// Seal a `recovery.wrap` for one recovery key at this group's current epoch.
///
/// The epoch secret never crosses: it is exported, sealed and zeroed inside. What comes
/// out is the JSON record `specs/backend/relay/groups.md` defines, which is the thing the
/// client publishes to the relay.
///
/// # Safety
/// `group` and `recovery_public` are readable byte ranges of the stated lengths, and
/// `out` is writable.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_seal_wrap(
    handle: GroupHandle,
    group: *const u8,
    group_len: usize,
    recovery_public: *const u8,
    recovery_public_len: usize,
    out: *mut Buffer,
) -> i32 {
    guard(
        |_| {},
        || {
            // Safety: the caller's contract.
            let session = unsafe { Handle::borrow(handle)? };
            // Safety: forwarded.
            let group = unsafe { required_slice(group, group_len, "group")? };
            // Safety: forwarded.
            let public = unsafe { required_slice(recovery_public, recovery_public_len, "key")? };
            let wrap = session.seal_wrap(group, public)?;
            // `expect` rather than a mapped error: a `Wrap` is a byte vector, a `u64`, a
            // `[u8; 32]` and another byte vector, serialised into a `Vec<u8>`. `serde_json`
            // fails only on a map key that is not a string, a `Serialize` impl that raises
            // its own error, or an exhausted writer, and this shape has none of the three.
            // The inverse, in ``weald_mls_open_wrap`` below, stays an error: that one parses
            // bytes the relay handed back.
            let bytes = serde_json::to_vec(&wrap).expect("a wrap of byte vectors serialises");
            // Safety: forwarded.
            unsafe { put(out, bytes) }
        },
    ) as i32
}

/// The recovery public key for a seed, so a client can publish it without holding the
/// private half in its own memory.
///
/// Takes a database path rather than a handle, because the caller doing this may have no
/// group yet: it is a device being enrolled, or one being recovered.
///
/// # Safety
/// `database` is NUL-terminated, `seed` is `seed_len` readable bytes, `out` is writable.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_recovery_public(
    database: *const core::ffi::c_char,
    seed: *const u8,
    seed_len: usize,
    out: *mut Buffer,
) -> i32 {
    guard(
        |_| {},
        || {
            // Safety: forwarded.
            let database = unsafe { text(database, "database")? };
            // `slice` rather than `required_slice`, so an empty seed reaches the rule that
            // owns it. "A recovery seed is not allowed to be empty" is a statement about
            // recovery keys, not about this pointer, and it is written once in
            // ``recovery::RecoveryKey::derive``. Checking it here as well would leave that
            // rule with no caller that could ever reach it, which is how a rule stops being
            // tested. A null pointer with a non-zero length is still refused here.
            // Safety: forwarded.
            let seed = unsafe { slice(seed, seed_len, "seed")? };
            let provider = crate::store::Provider::open(database)?;
            let key = crate::recovery::RecoveryKey::derive(&provider, seed)?;
            let public = key.public().to_vec();
            // Safety: forwarded.
            unsafe { put(out, public) }
        },
    ) as i32
}

/// Open a wrap with a recovery seed, on a device that has nothing else.
///
/// The one function that returns an epoch secret, and it returns it only to a caller that
/// supplied the seed that unseals it. That is the whole situation the mechanism exists
/// for: a replacement device holding a recovery phrase and a pile of opaque wraps.
///
/// # Safety
/// Every pointer is a readable range of its stated length, and both out-parameters are
/// writable.
#[no_mangle]
pub unsafe extern "C" fn weald_mls_open_wrap(
    database: *const core::ffi::c_char,
    seed: *const u8,
    seed_len: usize,
    wrap: *const u8,
    wrap_len: usize,
    secret_out: *mut Buffer,
    group_info_out: *mut Buffer,
) -> i32 {
    guard(
        |_| {},
        || {
            // Safety: forwarded.
            let database = unsafe { text(database, "database")? };
            // `slice` rather than `required_slice`, for the reason
            // ``weald_mls_recovery_public`` gives: the empty-seed rule belongs to
            // ``recovery::RecoveryKey::derive`` and is reachable only if this does not
            // pre-empt it.
            // Safety: forwarded.
            let seed = unsafe { slice(seed, seed_len, "seed")? };
            // Safety: forwarded.
            let wrap = unsafe { required_slice(wrap, wrap_len, "wrap")? };
            let wrap: crate::recovery::Wrap = serde_json::from_slice(wrap)
                .map_err(|error| Error::Malformed(error.to_string()))?;
            let provider = crate::store::Provider::open(database)?;
            let key = crate::recovery::RecoveryKey::derive(&provider, seed)?;
            let opened = crate::recovery::open_wrap(&provider, &key, &wrap)?;
            // The group info first, so a failure to write the second out-parameter cannot
            // leave the caller holding the secret with no way back in.
            // Safety: forwarded.
            unsafe { put(group_info_out, opened.group_info.clone())? };
            // Safety: forwarded.
            unsafe { put(secret_out, opened.epoch_secret.clone()) }
        },
    ) as i32
}

/// Raise a panic inside the guard, so the guard can be proven rather than trusted.
///
/// `specs/backend/build/phases-relay.md` step 7 names this as a negative: "a panic
/// deliberately raised inside the boundary returns a typed error and does not unwind into
/// Swift." There is no way to prove that without a panic to catch, and no honest way to
/// get one out of a correct implementation, so this exists to supply it.
///
/// Behind the `test-hooks` feature, which is off by default and is never enabled for the
/// XCFramework. The symbol's absence from the shipped library is asserted by the build
/// step of this gate, because a panic injector reachable from a customer's process would
/// be a denial of service with a friendly name.
///
/// `payload` chooses what happens: 0 panics with a string, a positive value panics with a
/// non-string, and a negative value does not panic at all and reports `Ok`. The first two
/// are both here because a guard that only handled `&str` would let the second one
/// through, and that is the one that would reach Swift.
///
/// The third is here because the guard's success arm is part of what is being proven. The
/// claim in `mls-binding.md` is not only that a panic becomes a status; it is that a panic
/// becomes a status *and an ordinary return still becomes `Ok`*. A `catch_unwind` that
/// swallowed everything would satisfy the first half and be useless. Proving the second
/// half at the same call site, through the same C ABI, is what makes the pair meaningful,
/// and it costs one comparison in a function that is not in the shipped library.
///
/// # Safety
/// None required. Nothing is dereferenced and nothing is allocated for the caller.
#[cfg(feature = "test-hooks")]
#[no_mangle]
pub unsafe extern "C" fn weald_mls_panic_for_test(payload: i32) -> i32 {
    guard(
        |_: ()| {},
        || {
            if payload < 0 {
                // The success arm of the same guard, reached without a panic.
                return Ok(());
            }
            if payload == 0 {
                panic!("a deliberate panic, with a string payload");
            }
            // A payload that is not a string and not a `String`, which is the case a
            // guard written against `downcast_ref::<&str>` would miss.
            std::panic::panic_any(payload);
        },
    ) as i32
}

/// The status a call would report for an out-parameter that was never written.
///
/// Exists so Swift can initialise its own out-parameters to something meaningful without
/// duplicating the numbers. Not part of the seam's twelve; a constant with a function
/// around it, for the same reason ``weald_mls_status_label`` is one.
#[no_mangle]
pub extern "C" fn weald_mls_status_ok() -> i32 {
    Status::Ok as i32
}
