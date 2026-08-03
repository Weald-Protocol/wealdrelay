// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Deterministic CBOR, checked against the client's half byte for byte.
//!
//! The Swift side is `Tests/DeterministicCBORTests.swift` over
//! `Sources/Sync/DeterministicCBOR.swift`, and the vectors below are the same
//! vectors, deliberately. The envelope's `hash` is a content address the relay
//! recomputes on accept, so the only thing that makes dedupe work is that two
//! independent encoders produce identical bytes. A test that only round tripped
//! inside Rust would pass with an encoder that agreed with nothing, so every
//! assertion here names the exact bytes rather than comparing an encode to a
//! decode.
//!
//! The second half of the file is the refusals. Every one of them is a byte
//! sequence a hostile peer can send, and each has its own error because
//! `specs/backend/contracts/registries/error-codes.md` carries
//! `reject/noncanonical_cbor` precisely so a peer is told which rule it broke.

use proptest::prelude::*;
use wealdrelay::cbor::{self, CborError, Reader};

/// The ten integers RFC 8949 appendix A uses to pin the width boundaries: the
/// last value that fits each encoding and the first that does not.
const BOUNDARIES: [u64; 10] = [
    0,
    23,
    24,
    255,
    256,
    65535,
    65536,
    4_294_967_295,
    4_294_967_296,
    u64::MAX,
];

// MARK: Canonical integer widths

#[test]
fn an_integer_encodes_in_the_shortest_form_that_holds_it_at_every_boundary() {
    // These are the bytes `CBOR.uint` produces in the Swift client, asserted
    // here as literals so a change on either side shows up as a failure rather
    // than as two encoders quietly drifting apart.
    assert_eq!(cbor::uint(0), vec![0x00]);
    assert_eq!(cbor::uint(23), vec![0x17]);
    assert_eq!(cbor::uint(24), vec![0x18, 0x18]);
    assert_eq!(cbor::uint(255), vec![0x18, 0xff]);
    assert_eq!(cbor::uint(256), vec![0x19, 0x01, 0x00]);
    assert_eq!(cbor::uint(65535), vec![0x19, 0xff, 0xff]);
    assert_eq!(cbor::uint(65536), vec![0x1a, 0x00, 0x01, 0x00, 0x00]);
    assert_eq!(
        cbor::uint(4_294_967_295),
        vec![0x1a, 0xff, 0xff, 0xff, 0xff]
    );
    assert_eq!(
        cbor::uint(4_294_967_296),
        vec![0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        cbor::uint(u64::MAX),
        vec![0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
}

#[test]
fn every_width_round_trips_through_the_reader() {
    // The decoder has to accept exactly what the encoder produces at each
    // boundary, and has to be at the end afterwards: a reader that stopped one
    // byte short would leave trailing bytes on a message that was in fact whole.
    for value in BOUNDARIES {
        let encoded = cbor::uint(value);
        let mut reader = Reader::new(&encoded);
        assert_eq!(reader.uint().expect("a canonical integer decodes"), value);
        assert!(reader.is_at_end());
        assert_eq!(reader.remaining(), 0);
        reader.finish().expect("nothing is left over");
    }
}

#[test]
fn a_byte_string_and_an_array_carry_their_length_in_the_same_canonical_form() {
    // Containers reuse the integer head, so the same shortest-form rule governs
    // a length. These are the Swift client's container vectors.
    assert_eq!(cbor::bytes(&[]), vec![0x40]);
    assert_eq!(cbor::bytes(&[1, 2, 3]), vec![0x43, 1, 2, 3]);
    assert_eq!(cbor::array(&[]), vec![0x80]);
    assert_eq!(
        cbor::array(&[cbor::uint(1), cbor::uint(2)]),
        vec![0x82, 0x01, 0x02]
    );

    // 24 items crosses into the one-byte argument, which is the boundary a
    // hand-rolled encoder gets wrong.
    let items: Vec<Vec<u8>> = (0..24u64).map(cbor::uint).collect();
    assert_eq!(&cbor::array(&items)[..2], &[0x98, 0x18]);

    let encoded = cbor::bytes(&[9, 9]);
    let mut reader = Reader::new(&encoded);
    assert_eq!(reader.bytes().expect("a byte string decodes"), vec![9, 9]);
    reader.finish().expect("nothing is left over");
}

#[test]
fn an_absent_optional_is_null_and_a_present_one_is_a_byte_string() {
    // Absence is `null` and not a zero-length byte string, because a reader that
    // could not tell the two apart would turn an unset field into a set-but-empty
    // one on the way back.
    assert_eq!(cbor::optional_bytes(None), cbor::NULL.to_vec());
    assert_eq!(cbor::optional_bytes(Some(&[7])), vec![0x41, 7]);

    let absent = cbor::optional_bytes(None);
    let mut reader = Reader::new(&absent);
    assert_eq!(reader.optional_bytes().expect("null decodes"), None);
    reader.finish().expect("null is one whole item");

    let present = cbor::optional_bytes(Some(&[7]));
    let mut reader = Reader::new(&present);
    assert_eq!(
        reader.optional_bytes().expect("a byte string decodes"),
        Some(vec![7])
    );
    reader.finish().expect("the byte string is one whole item");
}

// MARK: What the reader refuses

#[test]
fn a_non_canonical_integer_is_refused_at_every_width() {
    // 24 encoded in one following byte is canonical; 23 encoded that way is not,
    // and accepting it would give one value two encodings, at which point there
    // is no content address. All four widths, because the minimum is chosen by a
    // match on the width and one wrong arm would only show at that width.
    let cases: [&[u8]; 4] = [
        &[0x18, 0x17],                               // 23 in one byte
        &[0x19, 0x00, 0xff],                         // 255 in two
        &[0x1a, 0x00, 0x00, 0xff, 0xff],             // 65535 in four
        &[0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff], // 2^32-1 in eight
    ];
    for bytes in cases {
        let mut reader = Reader::new(bytes);
        assert_eq!(reader.uint(), Err(CborError::NonCanonicalInteger));
        // The cursor is untouched, so a caller reports the field that failed.
        assert_eq!(reader.offset(), 0);
    }
}

#[test]
fn reserved_and_indefinite_additional_info_is_refused() {
    // 28, 29 and 30 are reserved and 31 is the indefinite-length marker. An
    // indefinite length is the clearest case of one value with many encodings,
    // which is exactly what a content address cannot survive.
    for info in 28u8..=31 {
        let bytes = [info];
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.uint(), Err(CborError::ReservedAdditionalInfo(info)));
        assert_eq!(reader.offset(), 0);
    }
}

#[test]
fn input_that_ends_inside_an_item_is_truncated_not_empty() {
    // Three separate places the input can stop: before the head, inside the
    // argument, and inside a byte string's payload. They are separate code paths
    // and a peer can arrange any of them, so each is asserted.
    let mut head = Reader::new(&[]);
    assert_eq!(head.uint(), Err(CborError::Truncated));

    let mut argument = Reader::new(&[0x19, 0x01]);
    assert_eq!(argument.uint(), Err(CborError::Truncated));
    assert_eq!(argument.offset(), 0);

    let mut payload = Reader::new(&[0x43, 1, 2]);
    assert_eq!(payload.bytes(), Err(CborError::Truncated));
    assert_eq!(payload.offset(), 0);
}

#[test]
fn a_major_type_the_wire_format_does_not_carry_is_named_as_such() {
    // 1 negative, 3 text, 5 map, 6 tag. None appears in the wire format, and a
    // peer sending one is speaking a wider CBOR than the protocol rather than
    // sending this protocol's fields in the wrong order.
    for major in [1u8, 3, 5, 6] {
        let bytes = [major << 5];
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.uint(), Err(CborError::UnsupportedMajor(major)));
        assert_eq!(reader.offset(), 0);
    }
}

#[test]
fn a_carried_major_type_in_the_wrong_position_is_a_type_mismatch() {
    // The other half of the same decision: a major this subset does carry, but
    // not where the caller is. That is a peer sending the fields out of order,
    // which is a different bug from a peer speaking a wider CBOR, so it gets a
    // different error.
    let bytes_item = cbor::bytes(&[1]);
    let mut wanted_int = Reader::new(&bytes_item);
    assert_eq!(
        wanted_int.uint(),
        Err(CborError::TypeMismatch {
            expected: "unsigned integer"
        })
    );
    assert_eq!(wanted_int.offset(), 0);

    let int_item = cbor::uint(1);
    let mut wanted_bytes = Reader::new(&int_item);
    assert_eq!(
        wanted_bytes.bytes(),
        Err(CborError::TypeMismatch {
            expected: "byte string"
        })
    );
    assert_eq!(wanted_bytes.offset(), 0);

    let mut wanted_array = Reader::new(&int_item);
    assert_eq!(
        wanted_array.array_header(),
        Err(CborError::TypeMismatch { expected: "array" })
    );
    assert_eq!(wanted_array.offset(), 0);

    // And the unsupported-major arm has to be reachable from the byte-string and
    // array readers too, not only from the integer reader: each names its own
    // expectation and one of them could have been written to fall through.
    let mut map_for_bytes = Reader::new(&[5 << 5]);
    assert_eq!(map_for_bytes.bytes(), Err(CborError::UnsupportedMajor(5)));
    let mut tag_for_array = Reader::new(&[6 << 5]);
    assert_eq!(
        tag_for_array.array_header(),
        Err(CborError::UnsupportedMajor(6))
    );
    // A fixed-width read and a counted array read reach the same rejection
    // through their own wrappers.
    let mut tag_for_fixed = Reader::new(&[6 << 5]);
    assert_eq!(
        tag_for_fixed.bytes_of(32),
        Err(CborError::UnsupportedMajor(6))
    );
    let mut tag_for_counted = Reader::new(&[6 << 5]);
    assert_eq!(
        tag_for_counted.array(2),
        Err(CborError::UnsupportedMajor(6))
    );
}

#[test]
fn a_value_too_wide_for_its_field_is_refused_rather_than_truncated() {
    // A silently truncated `version` or `min_enc` would be a field the peer set
    // to one thing and this build read as another. Each narrowing reader is
    // offered the first value that does not fit it, and the last that does.
    let too_wide_for_u8 = cbor::uint(256);
    assert_eq!(
        Reader::new(&too_wide_for_u8).u8(),
        Err(CborError::OutOfRange(256))
    );
    let too_wide_for_u16 = cbor::uint(65536);
    assert_eq!(
        Reader::new(&too_wide_for_u16).u16(),
        Err(CborError::OutOfRange(65536))
    );
    let too_wide_for_u32 = cbor::uint(4_294_967_296);
    assert_eq!(
        Reader::new(&too_wide_for_u32).u32(),
        Err(CborError::OutOfRange(4_294_967_296))
    );

    let widest_u8 = cbor::uint(255);
    assert_eq!(Reader::new(&widest_u8).u8(), Ok(255));
    let widest_u16 = cbor::uint(65535);
    assert_eq!(Reader::new(&widest_u16).u16(), Ok(65535));
    let widest_u32 = cbor::uint(4_294_967_295);
    assert_eq!(Reader::new(&widest_u32).u32(), Ok(4_294_967_295));

    // The narrowing readers also inherit the type check, so asking for one of
    // them where a byte string sits is a mismatch and not a range failure. All
    // three, because each wraps the integer reader itself and one of them could
    // have been written to swallow the failure and return a default.
    let bytes_item = cbor::bytes(&[1]);
    let mismatch = CborError::TypeMismatch {
        expected: "unsigned integer",
    };
    assert_eq!(Reader::new(&bytes_item).u8(), Err(mismatch.clone()));
    assert_eq!(Reader::new(&bytes_item).u16(), Err(mismatch.clone()));
    assert_eq!(Reader::new(&bytes_item).u32(), Err(mismatch));
}

#[test]
fn a_fixed_width_byte_string_of_the_wrong_length_is_refused() {
    // `group`, `hash` and a device key are fixed widths. A short one would decode
    // fine and then address something no relay has ever stored, so the length is
    // checked here rather than discovered at lookup time.
    let short = cbor::bytes(&[1u8; 31]);
    let mut reader = Reader::new(&short);
    assert_eq!(
        reader.bytes_of(32),
        Err(CborError::WrongLength {
            expected: 32,
            got: 31
        })
    );
    assert_eq!(reader.offset(), 0);

    let exact = cbor::bytes(&[1u8; 32]);
    assert_eq!(Reader::new(&exact).bytes_of(32).map(|v| v.len()), Ok(32));
}

#[test]
fn an_array_of_the_wrong_item_count_is_refused() {
    // The struct shape is the item count: a frame body with the wrong number of
    // fields is a different frame, not this one with a field missing.
    let one_item = cbor::array(&[cbor::uint(1)]);
    let mut reader = Reader::new(&one_item);
    assert_eq!(
        reader.array(8),
        Err(CborError::WrongArrayCount {
            expected: 8,
            got: 1
        })
    );
    assert_eq!(reader.offset(), 0);
    // And the exact count is accepted, leaving the cursor on the first item.
    assert_eq!(reader.array(1), Ok(()));
    assert_eq!(reader.offset(), 1);
}

#[test]
fn an_array_header_longer_than_the_input_is_refused_before_allocating() {
    // The check exists because the item count is attacker-chosen and a decoder
    // that sized a Vec from it would let two bytes on the wire ask for gigabytes
    // of memory. Nothing that large can be present in the bytes that remain, so a
    // count over the remaining length is truncation and is refused before any
    // per-item work happens.
    let mut absurd = Reader::new(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    assert_eq!(absurd.array_header(), Err(CborError::Truncated));
    assert_eq!(absurd.offset(), 0);

    // The same refusal at a plausible size: a header claiming 255 items with no
    // items behind it.
    let mut overclaimed = Reader::new(&[0x98, 0xff]);
    assert_eq!(overclaimed.array_header(), Err(CborError::Truncated));
    assert_eq!(overclaimed.offset(), 0);

    // A header whose count is within the remaining bytes is accepted, which is
    // what keeps the bound a bound rather than a refusal of legal input.
    let honest = cbor::array(&[cbor::uint(1), cbor::uint(2)]);
    let mut reader = Reader::new(&honest);
    assert_eq!(reader.array_header(), Ok(2));
}

#[test]
fn a_simple_value_other_than_null_is_refused_where_an_optional_is_expected() {
    // `false` is major 7, value 20. Legal CBOR, not in this wire format, and
    // accepting it would make an absent field ambiguous.
    let mut reader = Reader::new(&[0xf4]);
    assert_eq!(
        reader.optional_bytes(),
        Err(CborError::UnsupportedSimple(20))
    );
    assert_eq!(reader.offset(), 0);

    // A simple value with a wide argument still names itself rather than
    // wrapping around to a small number, so the message cannot be mistaken for a
    // different simple value.
    let mut wide = Reader::new(&[0xfb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(
        wide.optional_bytes(),
        Err(CborError::UnsupportedSimple(u8::MAX))
    );
    assert_eq!(wide.offset(), 0);

    // An empty input asked for an optional is truncation, not absence: there is
    // no byte there to be a `null`.
    let mut empty = Reader::new(&[]);
    assert_eq!(empty.optional_bytes(), Err(CborError::Truncated));

    // A simple-major head that is itself malformed is refused as the malformed
    // head it is, rather than being read as an unsupported simple value: 0xff is
    // major 7 with the indefinite-length marker, and 0xf8 is major 7 with a
    // following byte that is not there.
    let mut indefinite = Reader::new(&[0xff]);
    assert_eq!(
        indefinite.optional_bytes(),
        Err(CborError::ReservedAdditionalInfo(31))
    );
    let mut cut_argument = Reader::new(&[0xf8]);
    assert_eq!(cut_argument.optional_bytes(), Err(CborError::Truncated));
}

#[test]
fn bytes_after_the_last_field_are_refused_so_one_value_has_one_encoding() {
    // Trailing garbage would let two byte strings decode to one value, which is
    // the same hole as a non-canonical integer and the same loss of the content
    // address.
    let mut trailing = cbor::uint(1);
    trailing.push(0x02);
    let mut reader = Reader::new(&trailing);
    assert_eq!(reader.uint(), Ok(1));
    assert!(!reader.is_at_end());
    assert_eq!(reader.remaining(), 1);
    assert_eq!(reader.finish(), Err(CborError::TrailingBytes(1)));
}

// MARK: The cursor property

#[test]
fn a_failed_read_leaves_the_cursor_where_it_was() {
    // Load-bearing for the frame decoder: it reads fields in order and has to be
    // able to say which field was wrong. A reader that consumed part of an item
    // before failing would leave the cursor in the middle of the wire format, and
    // every field after it would be reported at the wrong place.
    let encoded = cbor::array(&[cbor::uint(7), cbor::bytes(&[1])]);
    let mut reader = Reader::new(&encoded);
    reader.array(2).expect("the header is a two item array");
    let after_header = reader.offset();

    // Every reader that can fail, offered something it must refuse, at the same
    // offset, and each one leaves the cursor exactly where it found it.
    assert!(reader.bytes().is_err());
    assert_eq!(reader.offset(), after_header);
    assert!(reader.bytes_of(32).is_err());
    assert_eq!(reader.offset(), after_header);
    assert!(reader.array_header().is_err());
    assert_eq!(reader.offset(), after_header);
    assert!(reader.array(2).is_err());
    assert_eq!(reader.offset(), after_header);
    assert!(reader.optional_bytes().is_err());
    assert_eq!(reader.offset(), after_header);

    // The integer is still readable afterwards, which is the point: a failed
    // probe costs nothing.
    assert_eq!(reader.uint(), Ok(7));
    let after_int = reader.offset();

    assert_eq!(
        reader.bytes_of(4),
        Err(CborError::WrongLength {
            expected: 4,
            got: 1
        })
    );
    assert_eq!(reader.offset(), after_int);
    assert!(reader.uint().is_err());
    assert_eq!(reader.offset(), after_int);
    // The failed fixed-width read did not consume the byte string either.
    assert_eq!(reader.bytes(), Ok(vec![1]));
    reader.finish().expect("the array is fully consumed");
}

#[test]
fn a_narrowing_read_that_overflows_has_still_consumed_its_item() {
    // The one deliberate exception to the rule above, and it is the same on the
    // Swift side (`uint8()` there also commits the successful `uint()` before it
    // checks the width). The item was whole and was read; only the field it was
    // being read into was too narrow, so the caller reports a field that does not
    // fit rather than a field it could not find.
    let encoded = cbor::uint(256);
    let mut reader = Reader::new(&encoded);
    assert_eq!(reader.u8(), Err(CborError::OutOfRange(256)));
    assert_eq!(reader.offset(), encoded.len());
    assert!(reader.is_at_end());
}

#[test]
fn every_decode_failure_has_a_message_that_names_what_was_wrong() {
    // These strings reach an operator log and, through `reject/noncanonical_cbor`,
    // a peer. An empty or duplicated one is a message that cannot tell two
    // different wire mistakes apart.
    let all = [
        CborError::Truncated,
        CborError::UnsupportedMajor(5),
        CborError::NonCanonicalInteger,
        CborError::ReservedAdditionalInfo(31),
        CborError::UnsupportedSimple(20),
        CborError::TypeMismatch { expected: "array" },
        CborError::WrongLength {
            expected: 32,
            got: 4,
        },
        CborError::WrongArrayCount {
            expected: 8,
            got: 2,
        },
        CborError::OutOfRange(300),
        CborError::TrailingBytes(3),
    ];
    let messages: Vec<String> = all.iter().map(ToString::to_string).collect();
    assert!(messages.iter().all(|message| !message.is_empty()));
    let unique: std::collections::BTreeSet<&String> = messages.iter().collect();
    assert_eq!(unique.len(), messages.len());
}

// MARK: Over arbitrary bytes

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2000),
        ..ProptestConfig::default()
    })]

    /// Decoding attacker-supplied bytes never panics, never loops, and whatever
    /// does decode re-encodes to exactly the bytes it came from.
    ///
    /// The first half is the safety claim: these bytes arrive from the network
    /// before anything about the peer is known. The second half is the
    /// canonicity claim, and it is the one that makes the content address work:
    /// if any accepted encoding differed from what this encoder produces, that
    /// message would have two hashes.
    #[test]
    fn decoding_arbitrary_bytes_is_total_and_canonical(
        data in prop::collection::vec(any::<u8>(), 0..64)
    ) {
        let mut reader = Reader::new(&data);
        // Bounded by the input length because every successful read consumes at
        // least one byte, which is asserted below. A read that consumed nothing
        // would spin here, so the bound is the loop check rather than a guess.
        for _ in 0..=data.len() {
            if reader.is_at_end() {
                break;
            }
            let start = reader.offset();

            // Each reader is tried on the same offset. A failure must leave the
            // cursor alone, so the next attempt sees the identical bytes.
            let mut probe = Reader::new(&data[start..]);
            if let Ok(value) = probe.uint() {
                let reencoded = cbor::uint(value);
                prop_assert_eq!(&data[start..start + probe.offset()], reencoded.as_slice());
            }
            let mut probe = Reader::new(&data[start..]);
            if let Ok(value) = probe.bytes() {
                let reencoded = cbor::bytes(&value);
                prop_assert_eq!(&data[start..start + probe.offset()], reencoded.as_slice());
            }
            let mut probe = Reader::new(&data[start..]);
            if let Ok(value) = probe.optional_bytes() {
                let reencoded = cbor::optional_bytes(value.as_deref());
                prop_assert_eq!(&data[start..start + probe.offset()], reencoded.as_slice());
            }

            // Then advance by whichever item is actually there, so the walk
            // covers the whole input rather than stalling on the first field.
            let advanced =
                reader.uint().is_ok() || reader.bytes().is_ok() || reader.array_header().is_ok();
            if !advanced {
                // Nothing decodes here, so the cursor must not have moved.
                prop_assert_eq!(reader.offset(), start);
                break;
            }
            prop_assert!(reader.offset() > start);
        }
    }
}
