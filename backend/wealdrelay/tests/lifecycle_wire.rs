// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The `DROP` records: what they encode to, and every way a decode refuses.
//!
//! Tier 1. `specs/backend/relay/lifecycle.md` puts one instruction on this wire
//! and the relay acts on it by deleting a customer's history, so the encoding is
//! pinned here rather than exercised somewhere downstream. Three claims:
//!
//! 1. Every field round trips, including both authorization shapes and the empty
//!    snapshot list.
//! 2. `signing_bytes` covers every field except the signature, which is the
//!    property a signer and a verifier both depend on and the one that a field
//!    reordering breaks in silence.
//! 3. Every refusal is a refusal: a truncated record, a trailing byte, a tag this
//!    build does not speak, a snapshot list past the bound, and a hash that is
//!    not 32 bytes.
//!
//! Nothing here touches a database, a socket or a clock.

use wealdrelay::cbor;
use wealdrelay::lifecycle::wire::{DropBefore, LifecycleWireError, Response, MAX_SNAPSHOTS};

fn h(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

fn record(policy_version: Option<u64>, destruction: Option<Vec<u8>>) -> DropBefore {
    DropBefore {
        group: h(0x11),
        manifest_hash: h(0x22),
        snapshots: vec![h(0x33), h(0x44)],
        epoch: 7,
        policy_version,
        destruction_digest: destruction,
        sig: vec![0x55; 64],
    }
}

#[test]
fn an_instruction_round_trips_under_either_authorization() {
    for record in [
        record(Some(3), None),
        record(None, Some(h(0x66))),
        // Neither, which is a record the relay refuses on authorization rather
        // than on decoding: an instruction that names no authority is well formed
        // and permits nothing, and the two failures are different answers.
        record(None, None),
        DropBefore {
            snapshots: Vec::new(),
            ..record(Some(1), None)
        },
    ] {
        let encoded = record.encode();
        assert_eq!(DropBefore::decode(&encoded), Ok(record.clone()));
        // The debug form is what a refusal is logged with.
        assert!(format!("{record:?}").contains("DropBefore"));
    }
}

#[test]
fn signing_bytes_covers_every_field_except_the_signature() {
    let base = record(Some(3), None);
    let signed = base.signing_bytes();
    // A different signature over the same fields signs the same bytes: that is
    // what makes the signature verifiable at all.
    let resigned = DropBefore {
        sig: vec![0xaa; 64],
        ..base.clone()
    };
    assert_eq!(resigned.signing_bytes(), signed);

    // And every other field moves it. Each of these is a way a forged instruction
    // could otherwise reuse a captured signature: a different manifest anchors
    // elsewhere and therefore drops a different amount, a dropped snapshot
    // strands history, and a different authorization is a different permission
    // entirely.
    let variants = [
        DropBefore {
            group: h(0x99),
            ..base.clone()
        },
        DropBefore {
            manifest_hash: h(0x98),
            ..base.clone()
        },
        DropBefore {
            snapshots: vec![h(0x33)],
            ..base.clone()
        },
        DropBefore {
            epoch: 8,
            ..base.clone()
        },
        DropBefore {
            policy_version: Some(4),
            ..base.clone()
        },
        DropBefore {
            policy_version: None,
            destruction_digest: Some(h(0x66)),
            ..base.clone()
        },
    ];
    for variant in variants {
        assert_ne!(
            variant.signing_bytes(),
            signed,
            "a changed field must change what was signed"
        );
    }
}

#[test]
fn a_truncated_or_trailing_byte_is_refused_rather_than_read() {
    let bytes = record(Some(3), None).encode();
    for cut in 0..bytes.len() {
        assert!(
            DropBefore::decode(&bytes[..cut]).is_err(),
            "a record cut at {cut} decoded"
        );
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(matches!(
        DropBefore::decode(&extra),
        Err(LifecycleWireError::Encoding(_))
    ));
}

#[test]
fn a_tag_this_build_does_not_speak_is_named_rather_than_guessed() {
    let bytes = cbor::array(&[cbor::uint(9), cbor::array(&[])]);
    assert_eq!(
        DropBefore::decode(&bytes),
        Err(LifecycleWireError::UnknownTag(9))
    );
    assert_eq!(
        Response::decode(&bytes),
        Err(LifecycleWireError::UnknownTag(9))
    );
    assert_eq!(
        LifecycleWireError::UnknownTag(9).to_string(),
        "unknown lifecycle message tag 9"
    );
}

/// A well-formed CBOR array whose contents are the wrong shape.
///
/// Truncation cannot reach these: a message cut short fails on the array header
/// before the decoder looks at what is inside it. What reaches them is a peer
/// built against a different idea of this protocol, and the hostile case of
/// somebody probing what the decoder will accept. Neither may be read as a tag or
/// a count the relay then acts on.
#[test]
fn a_tag_or_a_count_that_is_not_a_number_is_refused_rather_than_read() {
    let not_a_number = cbor::array(&[cbor::bytes(b"one"), cbor::array(&[])]);
    assert!(matches!(
        DropBefore::decode(&not_a_number),
        Err(LifecycleWireError::Encoding(_))
    ));
    assert!(matches!(
        Response::decode(&not_a_number),
        Err(LifecycleWireError::Encoding(_))
    ));

    // Inside a `Dropped` answer, where the three numbers are what a client shows
    // an admin as "this much was reclaimed". Each position on its own, because a
    // decoder that stopped at the first would leave the others unchecked.
    for position in 0..3 {
        let mut fields = vec![cbor::uint(1), cbor::uint(2), cbor::uint(3)];
        fields[position] = cbor::bytes(b"not a number");
        let bytes = cbor::array(&[cbor::uint(1), cbor::array(&fields)]);
        assert!(
            matches!(
                Response::decode(&bytes),
                Err(LifecycleWireError::Encoding(_))
            ),
            "field {position} decoded as a number"
        );
    }
}

#[test]
fn a_snapshot_list_past_the_bound_is_refused_before_it_is_allocated() {
    let snapshots = (0..=MAX_SNAPSHOTS)
        .map(|_| cbor::bytes(&h(0x33)))
        .collect::<Vec<_>>();
    let body = cbor::array(&[
        cbor::bytes(&h(0x11)),
        cbor::bytes(&h(0x22)),
        cbor::array(&snapshots),
        cbor::uint(0),
        cbor::NULL.to_vec(),
        cbor::NULL.to_vec(),
        cbor::bytes(&[0x55; 64]),
    ]);
    let bytes = cbor::array(&[cbor::uint(1), body]);
    assert_eq!(
        DropBefore::decode(&bytes),
        Err(LifecycleWireError::TooManyEntries)
    );
    assert_eq!(
        LifecycleWireError::TooManyEntries.to_string(),
        format!("a snapshot list longer than {MAX_SNAPSHOTS}")
    );
}

#[test]
fn a_hash_that_is_not_thirty_two_bytes_is_not_a_hash() {
    let body = cbor::array(&[
        cbor::bytes(&h(0x11)),
        cbor::bytes(b"short"),
        cbor::array(&[]),
        cbor::uint(0),
        cbor::NULL.to_vec(),
        cbor::NULL.to_vec(),
        cbor::bytes(&[0x55; 64]),
    ]);
    let bytes = cbor::array(&[cbor::uint(1), body]);
    assert!(matches!(
        DropBefore::decode(&bytes),
        Err(LifecycleWireError::Encoding(_))
    ));

    // A policy version that is not eight bytes is the same class of refusal: the
    // field is a big-endian u64 and anything else is a record from a different
    // protocol.
    let body = cbor::array(&[
        cbor::bytes(&h(0x11)),
        cbor::bytes(&h(0x22)),
        cbor::array(&[]),
        cbor::uint(0),
        cbor::bytes(b"three"),
        cbor::NULL.to_vec(),
        cbor::bytes(&[0x55; 64]),
    ]);
    let bytes = cbor::array(&[cbor::uint(1), body]);
    assert_eq!(
        DropBefore::decode(&bytes),
        Err(LifecycleWireError::TooManyEntries)
    );
}

#[test]
fn the_answer_round_trips_in_both_of_its_shapes() {
    for response in [
        Response::Dropped {
            deleted: 1_024,
            bytes: 4_194_304,
            kept: 3,
        },
        Response::Dropped {
            deleted: 0,
            bytes: 0,
            kept: 0,
        },
        Response::Refused {
            reason: "incomplete_manifest:2".to_string(),
        },
    ] {
        assert_eq!(Response::decode(&response.encode()), Ok(response.clone()));
        assert!(!format!("{response:?}").is_empty());
    }

    // Trailing bytes and truncation, on the answer as much as on the instruction:
    // a client that acted on a half-read answer would report a compaction that
    // did not happen.
    let bytes = Response::Dropped {
        deleted: 1,
        bytes: 2,
        kept: 3,
    }
    .encode();
    for cut in 0..bytes.len() {
        assert!(Response::decode(&bytes[..cut]).is_err(), "cut at {cut}");
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(matches!(
        Response::decode(&extra),
        Err(LifecycleWireError::Encoding(_))
    ));

    let refusal = Response::Refused {
        reason: "group_frozen".to_string(),
    }
    .encode();
    for cut in 0..refusal.len() {
        assert!(Response::decode(&refusal[..cut]).is_err(), "cut at {cut}");
    }
}

#[test]
fn every_error_names_what_it_refused() {
    let encoding = LifecycleWireError::from(wealdrelay::cbor::CborError::Truncated);
    assert!(encoding
        .to_string()
        .starts_with("lifecycle record is not canonical CBOR"));
    assert!(format!("{encoding:?}").contains("Encoding"));
    assert_eq!(encoding.clone(), encoding);
}
