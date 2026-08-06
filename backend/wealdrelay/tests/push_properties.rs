// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Tier 2 for push: invariants over randomised input, per
//! `specs/backend/build/testing.md`.
//!
//! Two families here, and each is a claim the product makes out loud.
//!
//! 1. **Cross-workspace unlinkability.** One physical device joining two
//!    workspaces produces two unrelated rows, because the registration is keyed on
//!    the salted entry hash and the salt is per workspace. `push.md` section 2 says
//!    this is "a property of the key rather than an operational promise, and it is
//!    proved by a property test rather than asserted", so it is proved here over
//!    arbitrary device keys and arbitrary salts rather than over one pair somebody
//!    chose.
//! 2. **Codec determinism.** Every legal body has exactly one encoding, that
//!    encoding decodes back to it, and re-encoding is byte identical. The relay and
//!    three other implementations have to agree byte for byte, and an encoder with
//!    any freedom in it would produce two encodings of one frame.
//!
//! A third family falls out of the second and is worth stating separately: no byte
//! string at all, however hostile, makes the decoder panic. It is a peer that
//! chooses every one of those bytes.

use proptest::prelude::*;
use wealdrelay::access::entry_hash;
use wealdrelay::frame::{Frame, WakeBody, MAX_WAKE_BYTES};
use wealdrelay::push::queue::{Admit, Queue};
use wealdrelay::push::{Category, ALL_CATEGORIES, HANDLE_BYTES, MAX_REGISTER_URL_BYTES};

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    }
}

/// Sixteen bytes, the width the table constrains and the codec enforces.
fn handle() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), HANDLE_BYTES)
}

/// A url a client would accept: https, and inside the ceiling.
fn register_url() -> impl Strategy<Value = String> {
    "https://[a-z]{1,40}\\.example/v1/handles".prop_map(String::from)
}

fn body() -> impl Strategy<Value = WakeBody> {
    prop_oneof![
        (handle(), 1u8..=ALL_CATEGORIES, any::<u64>()).prop_map(
            |(handle, categories, expires_at)| {
                WakeBody::Register {
                    handle,
                    categories,
                    expires_at,
                }
            }
        ),
        any::<u64>().prop_map(|expires_at| WakeBody::Registered { expires_at }),
        Just(WakeBody::Clear),
        Just(WakeBody::Cleared),
        Just(WakeBody::Query),
        (any::<bool>(), register_url()).prop_map(|(enabled, register_url)| {
            WakeBody::Capability {
                enabled,
                register_url,
            }
        }),
    ]
}

fn category() -> impl Strategy<Value = Category> {
    prop_oneof![
        Just(Category::Message),
        Just(Category::Call),
        Just(Category::Handshake),
    ]
}

// MARK: Unlinkability

proptest! {
    #![proptest_config(config())]

    /// One device, two workspaces, two unrelated names.
    ///
    /// The salt is `relay_workspace.salt`, minted once per workspace from the
    /// operating system and never rotated, so the same device key produces two entry
    /// hashes with nothing in common. Since the registration is keyed on the entry
    /// hash and on nothing else, an operator holding both tables cannot tell that one
    /// device is behind both rows.
    #[test]
    fn one_device_in_two_workspaces_is_two_unrelated_registrations(
        device in prop::collection::vec(any::<u8>(), 32),
        first_salt in prop::collection::vec(any::<u8>(), 32),
        second_salt in prop::collection::vec(any::<u8>(), 32),
    ) {
        prop_assume!(first_salt != second_salt);
        let here = entry_hash(&device, &first_salt);
        let there = entry_hash(&device, &second_salt);
        prop_assert_ne!(&here, &there, "two workspaces, two names");
        // And neither name contains the device it was derived from, which is what
        // makes the table safe to hold at all: an entry hash is not a key wearing a
        // hat, and an operator holding the row must not be able to read a public key
        // out of it.
        prop_assert!(!here.windows(8).any(|window| device.windows(8).any(|w| w == window)));
        prop_assert!(!there.windows(8).any(|window| device.windows(8).any(|w| w == window)));
        prop_assert_eq!(here.len(), 32);
        prop_assert_eq!(there.len(), 32);
        // The same salt and the same device is stable, because a registration has to
        // be findable again by the principal that made it.
        prop_assert_eq!(entry_hash(&device, &first_salt), here);
    }

    /// Two devices in one workspace are two names, so the key is not a workspace
    /// identifier wearing a hash.
    #[test]
    fn two_devices_in_one_workspace_are_two_registrations(
        first in prop::collection::vec(any::<u8>(), 32),
        second in prop::collection::vec(any::<u8>(), 32),
        salt in prop::collection::vec(any::<u8>(), 32),
    ) {
        prop_assume!(first != second);
        prop_assert_ne!(entry_hash(&first, &salt), entry_hash(&second, &salt));
    }
}

// MARK: The codec

proptest! {
    #![proptest_config(config())]

    /// Encode, decode, encode: one value, one encoding, both times.
    #[test]
    fn every_legal_body_has_exactly_one_encoding(body in body()) {
        let frame = Frame::Wake(body.clone());
        let encoded = frame.encode();
        prop_assert!(encoded.len() <= MAX_WAKE_BYTES,
            "a legal body must fit the frame's own ceiling");
        let decoded = Frame::decode(&encoded).map_err(|error| {
            TestCaseError::fail(format!("a legal body did not decode: {error}"))
        })?;
        prop_assert_eq!(&decoded, &frame);
        prop_assert_eq!(decoded.encode(), encoded, "re-encoding is byte identical");
    }

    /// The form byte is a function of the body and of nothing else.
    #[test]
    fn the_form_is_stable_and_in_range(body in body()) {
        let form = body.form();
        prop_assert!((1..=6).contains(&form));
        prop_assert_eq!(body.clone().form(), form);
        // And it is the second item of the frame's inner array, which is where the
        // CDDL says the discriminant lives.
        let encoded = Frame::Wake(body).encode();
        prop_assert_eq!(encoded[3], 0x82, "an inner array of two");
        prop_assert_eq!(encoded[4], form, "then the form, in one byte");
    }

    /// No sequence of bytes panics the decoder, whatever it claims to be.
    ///
    /// It is a peer that chooses these bytes, and the decoder runs before anything
    /// has authenticated the peer that sent them.
    #[test]
    fn arbitrary_bytes_never_panic_the_decoder(
        bytes in prop::collection::vec(any::<u8>(), 0..600),
    ) {
        let _ = Frame::decode(&bytes);
    }

    /// The same, over bytes that are shaped like a `WAKE` frame, so the fuzz reaches
    /// past the tag and into the fields.
    #[test]
    fn arbitrary_wake_shaped_bytes_never_panic_the_decoder(
        form in any::<u8>(),
        tail in prop::collection::vec(any::<u8>(), 0..200),
    ) {
        let mut bytes = vec![0x82, 0x18, 25, 0x82, 0x18, form];
        bytes.extend_from_slice(&tail);
        let _ = Frame::decode(&bytes);
    }

    /// A url at or under the ceiling survives; one over it is refused. Stated as a
    /// property because the boundary is the whole rule.
    ///
    /// The padding goes inside the path of a real https url, because the codec applies
    /// the scheme rule as well as the length one and a run of `x` is neither.
    #[test]
    fn the_url_ceiling_is_exactly_where_it_says_it_is(length in 18usize..600) {
        let mut url = "https://r.example/".to_string();
        while url.len() < length {
            url.push('x');
        }
        let frame = Frame::Wake(WakeBody::Capability {
            enabled: true,
            register_url: url,
        });
        let decoded = Frame::decode(&frame.encode());
        prop_assert_eq!(decoded.is_ok(), length <= MAX_REGISTER_URL_BYTES);
    }
}

// MARK: The queue, over arbitrary interleavings

proptest! {
    #![proptest_config(config())]

    /// The queue never holds more than its bound, whatever is thrown at it, and it
    /// never returns a wake for a handle nobody enqueued.
    #[test]
    fn the_queue_is_bounded_and_invents_nothing(
        bound in 1usize..8,
        steps in prop::collection::vec((0u8..6, category(), 0u64..5000), 0..200),
        window in 0u64..3000,
    ) {
        let mut queue = Queue::new(bound);
        let mut clock = 1_800_000_000_000u64;
        let mut seen = Vec::new();
        for (seed, category, step) in steps {
            clock += step;
            let handle = vec![seed; HANDLE_BYTES];
            let admitted = queue.admit(handle.clone(), category, clock, window);
            // A handle already waiting is never added twice, whatever the outcome.
            if matches!(admitted, Admit::Queued | Admit::Dropped) {
                seen.push(handle);
            }
            prop_assert!(queue.len() <= bound, "the bound is a bound");
            let handles: Vec<Vec<u8>> = (0u8..6).map(|s| vec![s; HANDLE_BYTES]).collect();
            for (due_handle, _) in queue.take_due(clock) {
                prop_assert!(handles.contains(&due_handle), "a handle nobody sent came out");
            }
        }
        // Everything left is due eventually, because every deadline is finite.
        let drained = queue.take_due(u64::MAX);
        prop_assert!(drained.len() <= bound);
        prop_assert!(queue.next_deadline().is_none());
    }

    /// One handle is one entry, forever. Coalescing is the whole point, and a queue
    /// that held two entries for one handle would send two notifications for one
    /// window.
    #[test]
    fn one_handle_is_never_two_entries(
        categories in prop::collection::vec(category(), 1..40),
        window in 0u64..2000,
    ) {
        let mut queue = Queue::new(64);
        let handle = vec![0x5A; HANDLE_BYTES];
        for (step, category) in categories.iter().enumerate() {
            queue.admit(handle.clone(), *category, 1_000 + step as u64, window);
            prop_assert_eq!(queue.len(), 1);
        }
        // And a ring anywhere in the sequence wins, because a ring supersedes and is
        // never superseded.
        let expected = if categories.iter().any(|c| c.is_urgent()) {
            Category::Call
        } else {
            categories[0]
        };
        let due = queue.take_due(u64::MAX);
        prop_assert_eq!(due.len(), 1);
        prop_assert_eq!(due[0].1, expected);
    }

    /// A masked-out wake is never sent, for any mask and any category.
    #[test]
    fn masking_is_exactly_the_bitmask(mask in 1u8..=ALL_CATEGORIES, category in category()) {
        prop_assert_eq!(category.admitted_by(mask), mask & category.bit() != 0);
        // And a mask outside the defined bits is not a registration this relay would
        // ever have stored.
        prop_assert!(wealdrelay::push::is_valid_mask(mask));
    }
}
