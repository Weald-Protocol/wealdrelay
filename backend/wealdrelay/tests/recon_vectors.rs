// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The relay against the client's own reconciliation vectors.
//!
//! `specs/backend/contracts/wire/vectors/recon.json` is generated from the client's
//! implementation, by a generator that lives outside this repository, and is checked
//! in here as the fixed contract the relay is held to. So the expected values in it
//! come from the client, and this suite is the relay reproducing them.
//!
//! That direction matters and is the same argument `tests/vectors.rs` makes about the
//! content address: a Rust test asserting against a Rust-generated value proves the
//! relay agrees with itself. What has to be true is that two independent
//! implementations of one wire format and one set of rules agree, and the only way to
//! check it is for each to be measured against the other's output.
//!
//! Three things are pinned per case: the fingerprint over a set of items, the encoded
//! opening message, and, where the case has one, the answer to a peer's round together
//! with the ids that would move in each direction.

use std::collections::BTreeMap;

use wealdrelay::negentropy::{advance, fingerprint, initiate, Id, Item, Message};

const VECTORS: &str = include_str!("../../../specs/backend/contracts/wire/vectors/recon.json");

/// The ids in the vectors are synthetic and readable: the big-endian sequence number
/// in the first eight bytes, zeros after it.
fn id(seed: u64) -> Id {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&seed.to_be_bytes());
    out
}

fn items(seqs: &[u64]) -> Vec<Item> {
    let mut items: Vec<Item> = seqs
        .iter()
        .map(|seq| Item {
            seq: *seq,
            id: id(*seq),
        })
        .collect();
    items.sort();
    items
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|index| {
            u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex in the vectors")
        })
        .collect()
}

/// The vectors, parsed without a JSON dependency the relay does not otherwise need.
///
/// `serde_json` is already a dependency, so this uses it: a hand-rolled parser here
/// would be a second thing to get wrong in a file whose whole job is to be exact.
fn cases() -> Vec<BTreeMap<String, serde_json::Value>> {
    let document: serde_json::Value = serde_json::from_str(VECTORS).expect("the vectors parse");
    assert_eq!(
        document["recon_version"].as_u64(),
        Some(wealdrelay::negentropy::RECON_VERSION),
        "the client and the relay disagree about the payload version"
    );
    assert_eq!(
        document["idlist_limit"].as_u64(),
        Some(wealdrelay::negentropy::IDLIST_LIMIT as u64),
        "the client and the relay disagree about the id list limit"
    );
    assert_eq!(
        document["split_factor"].as_u64(),
        Some(wealdrelay::negentropy::SPLIT_FACTOR as u64),
        "the client and the relay disagree about the split factor"
    );
    document["cases"]
        .as_array()
        .expect("cases is an array")
        .iter()
        .map(|case| {
            case.as_object()
                .expect("a case is an object")
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .collect()
}

fn seqs(value: &serde_json::Value) -> Vec<u64> {
    value
        .as_array()
        .expect("a sequence list")
        .iter()
        .map(|entry| entry.as_u64().expect("a sequence number"))
        .collect()
}

#[test]
fn the_vectors_are_not_empty_and_name_themselves() {
    // A corpus that silently emptied would make every assertion below vacuous.
    let cases = cases();
    assert!(cases.len() >= 10, "the vector corpus has shrunk");
    for case in &cases {
        assert!(case["name"].as_str().is_some_and(|name| !name.is_empty()));
    }
}

#[test]
fn the_relay_computes_the_clients_fingerprints() {
    for case in cases() {
        let held = items(&seqs(&case["held"]));
        let expected = case["fingerprint"].as_str().expect("a fingerprint");
        assert_eq!(
            hex(&fingerprint(&held)),
            expected,
            "fingerprint disagreement on case {:?}",
            case["name"]
        );
    }
}

#[test]
fn the_relay_encodes_the_clients_opening_message_byte_for_byte() {
    for case in cases() {
        let held = items(&seqs(&case["held"]));
        let expected = case["opening"].as_str().expect("an opening message");
        let opening = initiate(&held);
        assert_eq!(
            hex(&opening.encode()),
            expected,
            "opening message disagreement on case {:?}",
            case["name"]
        );
        // And the relay reads its own encoding of the client's message back to the
        // same value, so the disagreement cannot be hiding in the decoder.
        assert_eq!(
            Message::decode(&unhex(expected)).expect("the client's message decodes"),
            opening
        );
    }
}

#[test]
fn the_relay_answers_a_round_the_way_the_client_does() {
    // The client's `advance` and the relay's are separate implementations of the same
    // rules, and the rules are where a subtle disagreement would live: a side that
    // settled a range the other did not would leave one member missing envelopes
    // nobody else is missing.
    let mut answered = 0;
    for case in cases() {
        let Some(answering) = case.get("answering") else {
            continue;
        };
        answered += 1;
        let held = items(&seqs(&case["held"]));
        let peer = items(&seqs(answering));
        let incoming = initiate(&peer);
        assert_eq!(
            hex(&incoming.encode()),
            case["incoming"].as_str().expect("the incoming message"),
            "the peer's message differs on case {:?}",
            case["name"]
        );

        let step = advance(&held, &incoming);
        match (&step.reply, &case["reply"]) {
            (Some(reply), expected) => assert_eq!(
                hex(&reply.encode()),
                expected.as_str().expect("a reply"),
                "reply disagreement on case {:?}",
                case["name"]
            ),
            (None, expected) => assert!(
                expected.is_null(),
                "the relay had nothing to say and the client did, on case {:?}",
                case["name"]
            ),
        }

        let expected_want: Vec<String> = case["want"]
            .as_array()
            .expect("want")
            .iter()
            .map(|entry| entry.as_str().expect("an id").to_string())
            .collect();
        let expected_send: Vec<String> = case["send"]
            .as_array()
            .expect("send")
            .iter()
            .map(|entry| entry.as_str().expect("an id").to_string())
            .collect();
        assert_eq!(
            step.want.iter().map(|id| hex(id)).collect::<Vec<_>>(),
            expected_want,
            "want disagreement on case {:?}",
            case["name"]
        );
        assert_eq!(
            step.send.iter().map(|id| hex(id)).collect::<Vec<_>>(),
            expected_send,
            "send disagreement on case {:?}",
            case["name"]
        );
    }
    assert!(answered >= 4, "the answering cases have gone missing");
}
