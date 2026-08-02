// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The recovery-wrap rules that need neither a socket nor a database.
//!
//! The encoding, every bound, and the one comparison the relay is able to make
//! honestly about a record it cannot open. Out here rather than in a `mod tests`
//! inside the crate, for the same reason `tests/access_unit.rs` is: an in-crate
//! test module is compiled into the measured library, so its own assertion arms
//! land in the coverage report as unexecuted regions and the floor stops measuring
//! the thing it exists to measure.

use wealdrelay::cbor;
use wealdrelay::recovery::{RecoveryWrap, WrapError, GROUP_BYTES, MAX_WRAP_BYTES, TAG_BYTES};

fn wrap() -> RecoveryWrap {
    RecoveryWrap {
        group: vec![7; GROUP_BYTES],
        epoch: 4,
        tag: vec![9; TAG_BYTES],
        ct: vec![1, 2, 3],
    }
}

#[track_caller]
fn malformed(bytes: &[u8], what: &str) {
    let outcome = RecoveryWrap::decode(bytes);
    let is_malformed = matches!(outcome, Err(WrapError::Malformed(_)));
    assert!(is_malformed, "{what}: expected malformed, got {outcome:?}");
}

#[test]
fn a_wrap_round_trips_through_its_canonical_encoding() {
    let original = wrap();
    let decoded = RecoveryWrap::decode(&original.encode()).expect("decodes");
    assert_eq!(decoded, original);
    // Deterministic: the decode of an encode re-encodes to the same bytes, so one
    // wrap has one encoding and a tag derived over it is stable.
    assert_eq!(decoded.encode(), original.encode());
}

#[test]
fn every_width_is_checked_and_the_error_says_which_one() {
    let mut bad = wrap();
    bad.group = vec![7; 31];
    assert_eq!(bad.check(), Err(WrapError::GroupWidth(31)));

    let mut bad = wrap();
    bad.tag = vec![9; 33];
    assert_eq!(bad.check(), Err(WrapError::TagWidth(33)));

    let mut bad = wrap();
    bad.ct = Vec::new();
    assert_eq!(bad.check(), Err(WrapError::Empty));

    let mut bad = wrap();
    bad.ct = vec![0; MAX_WRAP_BYTES + 1];
    assert_eq!(bad.check(), Err(WrapError::TooLarge(MAX_WRAP_BYTES + 1)));

    assert_eq!(wrap().check(), Ok(()));
}

#[test]
fn a_bound_is_enforced_on_decode_and_not_only_on_a_built_value() {
    let oversized = RecoveryWrap {
        ct: vec![0; MAX_WRAP_BYTES + 1],
        ..wrap()
    };
    assert_eq!(
        RecoveryWrap::decode(&oversized.encode()),
        Err(WrapError::TooLarge(MAX_WRAP_BYTES + 1))
    );
    let narrow = RecoveryWrap {
        tag: vec![9; 4],
        ..wrap()
    };
    assert_eq!(
        RecoveryWrap::decode(&narrow.encode()),
        Err(WrapError::TagWidth(4))
    );
    let wide_group = RecoveryWrap {
        group: vec![7; 8],
        ..wrap()
    };
    assert_eq!(
        RecoveryWrap::decode(&wide_group.encode()),
        Err(WrapError::GroupWidth(8))
    );
    let empty = RecoveryWrap {
        ct: Vec::new(),
        ..wrap()
    };
    assert_eq!(RecoveryWrap::decode(&empty.encode()), Err(WrapError::Empty));
}

#[test]
fn a_record_that_is_not_four_framed_fields_is_malformed_at_every_position() {
    let encoded = wrap().encode();
    malformed(&encoded[..encoded.len() - 1], "truncated");

    let mut trailing = encoded.clone();
    trailing.push(0x00);
    malformed(&trailing, "trailing bytes");

    malformed(&[], "empty");
    malformed(&[0x00], "not an array");

    // Each field, in turn, given the wrong CBOR major type. Done one position at a
    // time rather than once, because a decoder that read the fields in a different
    // order would still pass a single case and would be reading somebody else's
    // bytes as a tag.
    let group = cbor::bytes(&[7; GROUP_BYTES]);
    let epoch = cbor::uint(4);
    let tag = cbor::bytes(&[9; TAG_BYTES]);
    let ct = cbor::bytes(&[1, 2, 3]);
    let uint = cbor::uint(1);
    let bytes = cbor::bytes(&[1]);

    malformed(
        &cbor::array(&[uint.clone(), epoch.clone(), tag.clone(), ct.clone()]),
        "group as an integer",
    );
    malformed(
        &cbor::array(&[group.clone(), bytes.clone(), tag.clone(), ct.clone()]),
        "epoch as a byte string",
    );
    malformed(
        &cbor::array(&[group.clone(), epoch.clone(), uint.clone(), ct.clone()]),
        "tag as an integer",
    );
    malformed(
        &cbor::array(&[group.clone(), epoch.clone(), tag.clone(), uint]),
        "ct as an integer",
    );

    // Arity, both directions.
    malformed(
        &cbor::array(&[group.clone(), epoch.clone(), tag.clone()]),
        "three fields",
    );
    malformed(&cbor::array(&[group, epoch, tag, ct, bytes]), "five fields");
}

#[test]
fn a_slot_only_moves_forward() {
    assert_eq!(RecoveryWrap::check_replacement(4, 5), Ok(()));
    assert_eq!(
        RecoveryWrap::check_replacement(4, 4),
        Err(WrapError::NotNewer {
            stored: 4,
            offered: 4
        })
    );
    assert_eq!(
        RecoveryWrap::check_replacement(4, 3),
        Err(WrapError::NotNewer {
            stored: 4,
            offered: 3
        })
    );
    // The boundary at zero: a first wrap is written by the empty-slot path, so
    // epoch 0 replacing epoch 0 is still a refusal rather than a special case.
    assert_eq!(
        RecoveryWrap::check_replacement(0, 0),
        Err(WrapError::NotNewer {
            stored: 0,
            offered: 0
        })
    );
    assert_eq!(RecoveryWrap::check_replacement(0, 1), Ok(()));
}

#[test]
fn every_refusal_prints_itself_and_names_the_number_that_failed() {
    assert!(WrapError::GroupWidth(31).to_string().contains("31"));
    assert!(WrapError::TagWidth(33).to_string().contains("33"));
    assert!(WrapError::Empty.to_string().contains("empty"));
    assert!(WrapError::TooLarge(9).to_string().contains('9'));
    assert!(WrapError::NotNewer {
        stored: 4,
        offered: 3
    }
    .to_string()
    .contains("does not advance"));
    assert!(WrapError::Malformed("why".into())
        .to_string()
        .contains("why"));

    // Debug and Clone are used by the store's error type and by every test
    // harness message above, so they are exercised rather than merely derived.
    let error = WrapError::Empty;
    assert_eq!(format!("{:?}", error.clone()), format!("{error:?}"));
    assert_eq!(error, WrapError::Empty);
    assert_ne!(error, WrapError::TooLarge(1));
}

#[test]
fn every_refusal_maps_to_the_wire_code_a_client_branches_on() {
    use wealdrelay::frame::ErrorCode;

    // Walked variant by variant rather than spot-checked, because this mapping is
    // the whole of what a client sees and a wrong arm would tell a correct client
    // to stop retrying, or a stale one to retry for ever.
    assert_eq!(
        WrapError::NotNewer {
            stored: 2,
            offered: 1
        }
        .code(),
        ErrorCode::WrapNotNewer
    );
    assert_eq!(
        WrapError::TooLarge(MAX_WRAP_BYTES + 1).code(),
        ErrorCode::EnvelopeTooLarge
    );
    for shape in [
        WrapError::Malformed("truncated".into()),
        WrapError::GroupWidth(31),
        WrapError::TagWidth(31),
        WrapError::Empty,
    ] {
        assert_eq!(shape.code(), ErrorCode::MalformedHeader, "{shape}");
    }

    // And the classes, which are what a client actually branches on first. A stale
    // wrap is `denied`, meaning re-read the state and act; a malformed one is
    // `reject`, meaning these bytes will never be accepted.
    assert_eq!(
        WrapError::NotNewer {
            stored: 2,
            offered: 1
        }
        .code()
        .qualified(),
        "denied/wrap_not_newer"
    );
    assert_eq!(
        WrapError::Empty.code().qualified(),
        "reject/malformed_header"
    );
}

#[test]
fn the_constants_are_the_numbers_the_spec_states() {
    // Read off `groups.md` rather than off the source: a retention window that
    // drifted would narrow the overlap a recovery lands in, silently.
    assert_eq!(wealdrelay::recovery::PRIOR_RETENTION_DAYS, 30);
    assert_eq!(GROUP_BYTES, 32);
    assert_eq!(TAG_BYTES, 32);
}
