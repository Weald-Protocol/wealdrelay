// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The relay checked against the client, on the access set.
//!
//! Step 6 adds a third piece of shared wire format. The digest is what the chain links
//! on and what an authorizer signs, so if the two encoders differ by one byte then
//! every publication a client makes is unverifiable at the relay, and the failure
//! surfaces as `denied/writer_not_in_access_set` on a set that is entirely valid.
//!
//! The vectors in `specs/backend/contracts/wire/vectors/access-set.json` are generated
//! by the **client's** code, by `scripts/fixture-log.sh --access-vectors`, which
//! compiles `Sources/Sync`. This suite asserts the relay reproduces them, decoder and
//! digest both. A Rust test asserting against a Rust-generated value would prove that
//! Rust is self-consistent, which is not the claim.
//!
//! `scripts/backend-gate.sh 6` regenerates the file from Swift and fails on any
//! difference, so a change to either encoder is caught by the side that did not change.

use std::path::PathBuf;

use wealdrelay::access::{entry_hash, quorum_message, AccessSet, MAX_ENTRIES};

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../specs/backend/contracts/wire/vectors/access-set.json")
}

fn hex_to_bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn vectors() -> serde_json::Value {
    let text = std::fs::read_to_string(vectors_path()).expect(
        "specs/backend/contracts/wire/vectors/access-set.json is missing. \
         Generate it with scripts/fixture-log.sh --access-vectors.",
    );
    serde_json::from_str(&text).expect("the vectors are JSON")
}

#[test]
fn the_relay_decodes_what_the_client_encodes_and_agrees_about_the_digest() {
    let vectors = vectors();
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(!cases.is_empty(), "the corpus is empty");
    for case in cases {
        let name = case["name"].as_str().expect("a name");
        let encoded = hex_to_bytes(case["encoded"].as_str().expect("encoded"));

        let set = AccessSet::decode(&encoded)
            .unwrap_or_else(|error| panic!("{name}: the relay cannot decode it: {error}"));

        // The digest, which is the value the whole chain rests on.
        assert_eq!(
            to_hex(&set.digest()),
            case["digest"].as_str().expect("digest"),
            "{name}: the two implementations disagree about the digest"
        );

        // And the whole encoding round trips, so the relay's encoder is checked against
        // the client's rather than only its hasher. A relay that decoded correctly and
        // re-encoded differently would break the stored body, which is what makes a
        // publication checkable by anyone reading the table.
        assert_eq!(
            to_hex(&set.encode()),
            case["encoded"].as_str().expect("encoded"),
            "{name}: the relay re-encodes it differently"
        );

        // The field counts, so a case that decoded into the wrong shape is caught here
        // rather than by an assertion about bytes nobody can read.
        assert_eq!(
            set.version,
            case["version"].as_u64().expect("version"),
            "{name}"
        );
        assert_eq!(
            set.entries.len() as u64,
            case["entries"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            set.authorizers.len() as u64,
            case["authorizers"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            set.recovery.len() as u64,
            case["recovery"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            set.pending.len() as u64,
            case["pending"].as_u64().unwrap(),
            "{name}"
        );
        match case["quorum_threshold"].as_u64() {
            Some(threshold) => assert_eq!(
                set.quorum
                    .as_ref()
                    .map(|quorum| u64::from(quorum.threshold)),
                Some(threshold),
                "{name}"
            ),
            None => assert!(set.quorum.is_none(), "{name}: an unexpected quorum"),
        }
    }
}

#[test]
fn the_two_implementations_agree_about_the_entry_hash_and_the_quorum_message() {
    // The other two shared functions. The entry hash is what `AUTH` compares, so a
    // disagreement locks every member out of a workspace; the quorum message is what a
    // confirmation signs, so a disagreement makes recovery unconfirmable.
    let vectors = vectors();
    let salt = hex_to_bytes(vectors["entry_hash_salt"].as_str().expect("salt"));
    let example = &vectors["entry_hash_example"];
    assert_eq!(
        to_hex(&entry_hash(
            &hex_to_bytes(example["pubkey"].as_str().unwrap()),
            &salt
        )),
        example["hash"].as_str().unwrap(),
        "the two implementations disagree about the entry hash"
    );

    let quorum = &vectors["quorum_message_example"];
    assert_eq!(
        to_hex(&quorum_message(
            &hex_to_bytes(quorum["digest"].as_str().unwrap()),
            &hex_to_bytes(quorum["replacement_entry"].as_str().unwrap()),
        )),
        quorum["message"].as_str().unwrap(),
        "the two implementations disagree about what a confirmation signs"
    );

    // And the bound, which both sides enforce before allocating.
    assert_eq!(
        vectors["max_entries"].as_u64().unwrap() as usize,
        MAX_ENTRIES,
        "the two implementations disagree about the list bound"
    );
}
