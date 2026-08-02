// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Arbitrary bytes into the one function that eats bytes from an untrusted network.
//!
//! `specs/backend/relay/mls-binding.md`: "Fuzzing of `weald_mls_process` with malformed
//! and hostile messages, since it is the one function that consumes bytes from an
//! untrusted network."
//!
//! Three properties, and they are the three the boundary rules in that spec promise:
//!
//! 1. It never panics. A panic here would be caught by `catch_unwind` at the C ABI and
//!    reported as `Status::Panicked`, but a caught panic is still a bug: it means the
//!    library reached a state it did not expect while holding a group's keys, and the
//!    spec's own words are "it would happen first in the least tested path".
//! 2. It always answers with a typed ``Status``. Nothing is returned that a Swift `switch`
//!    could fail to handle.
//! 3. The group survives. Hostile input is dropped, not absorbed: the epoch does not move
//!    and the session can still encrypt afterwards. A fuzz target that only checked for
//!    the absence of a crash would pass while the library quietly poisoned a group.
//!
//! `Session::process` is what `weald_mls_process` marshals to. Driving it here rather than
//! through the pointer is the same choice `src/session.rs` explains: everything that can be
//! tested without a pointer is, and the pointer layer is covered by the buffer and handle
//! tests that `miri` runs.

#![no_main]

use std::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use weald_mls::session::{Config, Device, Session};
use weald_mls::status::Status;

// The group under test, built once per process.
//
// Reused rather than rebuilt per input, for two reasons. A key generation per case would
// make the fuzzer measure X25519 rather than the parser, and reusing it is the stronger
// property anyway: every input in a run is fed to a group that has already survived every
// input before it, so a case that corrupts state fails on the case after it.
//
// In-memory storage, because a fuzzer that wrote a SQLite file per case would be fuzzing
// the disk. It is the same storage provider and the same SQL.
thread_local! {
    static SESSION: RefCell<Session> = RefCell::new(open());
}

fn open() -> Session {
    let device = Device::open(&Config {
        database: ":memory:".to_string(),
        identity: b"fuzz".to_vec(),
    })
    .expect("a device");
    device.create_group(b"weald-fuzz-group").expect("a group")
}

fuzz_target!(|data: &[u8]| {
    SESSION.with(|cell| {
        let mut session = cell.borrow_mut();
        let epoch_before = session.epoch();

        match session.process(data) {
            // A well-formed message this group accepts. Vanishingly unlikely from random
            // bytes and not an error if it happens: the point is that the answer is typed.
            Ok(_) => {}
            Err(error) => {
                let status = error.status();
                // The closed set, asserted rather than assumed. A status outside it would
                // be a number Swift's exhaustive switch has no arm for.
                assert!(
                    matches!(
                        status,
                        Status::Malformed
                            | Status::Protocol
                            | Status::InvalidArgument
                            | Status::Storage
                    ),
                    "process answered with {status:?}, which is not an answer this \
                     function is allowed to give"
                );
            }
        }

        // The epoch cannot move on input from a stranger. Moving it would mean random
        // bytes had advanced this group past the rest of the group, which is the exact
        // failure the crash suite exists to prevent, arriving over the network instead.
        assert_eq!(
            session.epoch(),
            epoch_before,
            "arbitrary bytes advanced the epoch"
        );
        // And the group is still usable. Hostile input is dropped, not absorbed.
        assert!(
            session.encrypt(b"still working").is_ok(),
            "the group stopped working after refusing an input"
        );
    });
});
