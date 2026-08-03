// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The envelope, and every check the relay makes on it, with no database.
//!
//! `specs/backend/relay/wire.md` fixes the eight fields, their order, and the
//! function that addresses them. `backend/build-coverage-exclusions.md` names
//! `backend/wealdrelay/src/envelope/**` as a path where no coverage exclusion is
//! ever permitted, so every refusal below is reached by real bytes rather than
//! asserted about in a comment.
//!
//! Nothing here touches Postgres. Everything the envelope refuses is a property
//! of the bytes alone, which is exactly what lets `accept` run these checks
//! before it opens a transaction: a forged envelope costs the relay one hash and
//! no database work.

use wealdrelay::cbor::{self, CborError};
use wealdrelay::config::MinEncryption;
use wealdrelay::envelope::{
    content_hash, Encryption, Envelope, EnvelopeError, GROUP_BYTES, HASH_BYTES,
    MAX_CIPHERTEXT_BYTES, VERSION,
};
use wealdrelay::frame::ErrorCode;

// MARK: Helpers

/// A well-formed envelope whose `hash` is the address its own fields imply.
fn well_formed() -> Envelope {
    let group = vec![0x11u8; GROUP_BYTES];
    let ct = b"opaque ciphertext".to_vec();
    Envelope {
        v: VERSION,
        enc: Encryption::None,
        group: group.clone(),
        epoch: 7,
        // Relay-assigned, and zero as an envelope arrives.
        seq: 0,
        ts: 0,
        hash: content_hash(VERSION, Encryption::None, &group, 7, &ct),
        ct,
    }
}

/// An eight-item array built from raw field encodings, so a single field can be
/// made wrong without disturbing the seven around it. This is what a hostile peer
/// has: the ability to put any bytes in any position.
fn eight(fields: [Vec<u8>; 8]) -> Vec<u8> {
    cbor::array(&fields)
}

/// The eight fields of a well-formed envelope, as separate encodings.
fn fields() -> [Vec<u8>; 8] {
    let envelope = well_formed();
    [
        cbor::uint(u64::from(envelope.v)),
        cbor::uint(envelope.enc as u64),
        cbor::bytes(&envelope.group),
        cbor::uint(envelope.epoch),
        cbor::uint(envelope.seq),
        cbor::uint(envelope.ts),
        cbor::bytes(&envelope.hash),
        cbor::bytes(&envelope.ct),
    ]
}

/// The eight fields with one of them replaced.
fn fields_with(index: usize, replacement: Vec<u8>) -> Vec<u8> {
    let mut all = fields();
    all[index] = replacement;
    eight(all)
}

// MARK: The round trip

#[test]
fn an_envelope_survives_encode_and_decode_unchanged() {
    // The encoder and the decoder are the two halves of one wire format, and a
    // round trip that lost a field would mean the relay stored something other
    // than what the client sent. `seq` and `ts` are carried non-zero here as well,
    // because the relay writes them back into the envelope it serves to readers
    // and a decoder that dropped them would silently reset every cursor.
    let mut envelope = well_formed();
    envelope.seq = 4_294_967_296;
    envelope.ts = 1_700_000_000_000;
    let encoded = envelope.encode();
    assert_eq!(Envelope::decode(&encoded).expect("decodes"), envelope);
    // Deterministic: the same envelope encodes to the same bytes every time, which
    // is what makes the content address reproducible on the other side.
    assert_eq!(envelope.encode(), encoded);
    // And the encoding really is the eight-item array in the spec's field order,
    // rather than something that merely round trips through this crate.
    assert_eq!(
        encoded,
        eight([
            cbor::uint(u64::from(envelope.v)),
            cbor::uint(envelope.enc as u64),
            cbor::bytes(&envelope.group),
            cbor::uint(envelope.epoch),
            cbor::uint(envelope.seq),
            cbor::uint(envelope.ts),
            cbor::bytes(&envelope.hash),
            cbor::bytes(&envelope.ct),
        ])
    );
}

#[test]
fn every_encryption_byte_the_wire_format_carries_round_trips_and_nothing_else_does() {
    // `wire.md`: 0 is signed plaintext, 1 is MLS, and there is no third value. An
    // `enc` the relay did not recognise but stored would be an envelope no reader
    // could ever open.
    assert_eq!(Encryption::from_u8(0), Some(Encryption::None));
    assert_eq!(Encryption::from_u8(1), Some(Encryption::Mls));
    assert_eq!(Encryption::from_u8(2), None);
    assert_eq!(Encryption::from_u8(u8::MAX), None);
    assert_eq!(Encryption::None as u64, 0);
    assert_eq!(Encryption::Mls as u64, 1);
    // Copy and comparable, because the accept path passes it by value into the
    // hash function and into a bind parameter.
    let enc = Encryption::Mls;
    let copied = enc;
    assert_eq!(enc, copied);
    assert!(format!("{enc:?}").contains("Mls"));

    let mut envelope = well_formed();
    envelope.enc = Encryption::Mls;
    envelope.hash = envelope.computed_hash();
    assert_eq!(Envelope::decode(&envelope.encode()).unwrap(), envelope);
}

#[test]
fn an_envelope_is_debuggable_clonable_and_comparable() {
    // The accept path clones and compares envelopes, and every error message in
    // the suite prints one. A type that could not be printed would make every
    // failure below say nothing.
    let envelope = well_formed();
    let clone = envelope.clone();
    assert_eq!(envelope, clone);
    let mut different = envelope.clone();
    different.epoch += 1;
    assert_ne!(envelope, different);
    assert!(format!("{envelope:?}").contains("epoch"));
}

// MARK: Decode, one refusal per field a hostile peer controls

#[test]
fn a_decode_refuses_anything_that_is_not_an_eight_item_array() {
    // Position carries field identity in this format, so the item count is the
    // frame around every other check. Seven items would silently shift `ct` into
    // the `hash` slot.
    assert_eq!(
        Envelope::decode(&cbor::uint(1)),
        Err(EnvelopeError::Cbor(CborError::TypeMismatch {
            expected: "array"
        }))
    );
    let seven = cbor::array(&fields()[..7]);
    assert_eq!(
        Envelope::decode(&seven),
        Err(EnvelopeError::Cbor(CborError::WrongArrayCount {
            expected: 8,
            got: 7
        }))
    );
    // Nothing at all, which is what a truncated read hands the decoder.
    assert_eq!(
        Envelope::decode(&[]),
        Err(EnvelopeError::Cbor(CborError::Truncated))
    );
}

#[test]
fn a_decode_refuses_a_version_that_is_not_a_byte_sized_unsigned_integer() {
    // `v` is `uint8` on the wire. A version of 300 is not a version this build
    // could ever support, and reading it as a truncated byte would make an
    // unsupported peer look supported.
    assert_eq!(
        Envelope::decode(&fields_with(0, cbor::uint(300))),
        Err(EnvelopeError::Cbor(CborError::OutOfRange(300)))
    );
    assert_eq!(
        Envelope::decode(&fields_with(0, cbor::bytes(b"1"))),
        Err(EnvelopeError::Cbor(CborError::TypeMismatch {
            expected: "unsigned integer"
        }))
    );
}

#[test]
fn a_decode_refuses_an_enc_it_does_not_understand() {
    // Named separately from a malformed `enc`, because the two are different
    // faults: 2 is a peer speaking a wider protocol, a byte string is a peer
    // sending the fields out of order.
    assert_eq!(
        Envelope::decode(&fields_with(1, cbor::uint(2))),
        Err(EnvelopeError::UnknownEncryption(2))
    );
    assert_eq!(
        Envelope::decode(&fields_with(1, cbor::uint(999))),
        Err(EnvelopeError::Cbor(CborError::OutOfRange(999)))
    );
    assert_eq!(
        Envelope::decode(&fields_with(1, cbor::bytes(b"mls"))),
        Err(EnvelopeError::Cbor(CborError::TypeMismatch {
            expected: "unsigned integer"
        }))
    );
}

#[test]
fn a_decode_refuses_a_group_id_of_the_wrong_width() {
    // `[32]byte`. A short group would decode fine and then address a group no
    // relay has ever heard of, which is a refusal at the wrong layer and with the
    // wrong code.
    assert_eq!(
        Envelope::decode(&fields_with(2, cbor::bytes(&[0x11u8; GROUP_BYTES - 1]))),
        Err(EnvelopeError::Cbor(CborError::WrongLength {
            expected: GROUP_BYTES,
            got: GROUP_BYTES - 1
        }))
    );
    assert_eq!(
        Envelope::decode(&fields_with(2, cbor::uint(0))),
        Err(EnvelopeError::Cbor(CborError::TypeMismatch {
            expected: "byte string"
        }))
    );
}

#[test]
fn a_decode_refuses_a_malformed_epoch_seq_or_ts() {
    // Three unsigned integers in three positions. Each is read separately so the
    // refusal names the field that was wrong, and each is proven here rather than
    // one standing in for the other two.
    for index in [3usize, 4, 5] {
        assert_eq!(
            Envelope::decode(&fields_with(index, cbor::bytes(b"nope"))),
            Err(EnvelopeError::Cbor(CborError::TypeMismatch {
                expected: "unsigned integer"
            })),
            "field {index} must be refused as a non-integer"
        );
    }
}

#[test]
fn a_decode_refuses_a_hash_of_the_wrong_width() {
    // The content address is `[32]byte` and is compared byte for byte against a
    // recomputation. A 16-byte hash is not a hash that failed to match, it is a
    // header the relay cannot even attempt the comparison on.
    assert_eq!(
        Envelope::decode(&fields_with(6, cbor::bytes(&[0u8; 16]))),
        Err(EnvelopeError::Cbor(CborError::WrongLength {
            expected: HASH_BYTES,
            got: 16
        }))
    );
    assert_eq!(
        Envelope::decode(&fields_with(6, cbor::uint(0))),
        Err(EnvelopeError::Cbor(CborError::TypeMismatch {
            expected: "byte string"
        }))
    );
}

#[test]
fn a_decode_refuses_a_ct_that_is_not_a_byte_string() {
    // `ct` is the only variable-length field, and it is the last one. Anything
    // else in that slot is a peer that has miscounted its own encoding.
    assert_eq!(
        Envelope::decode(&fields_with(7, cbor::uint(4))),
        Err(EnvelopeError::Cbor(CborError::TypeMismatch {
            expected: "byte string"
        }))
    );
    // An empty `ct` is not malformed. Whether it is meaningful is a question for a
    // client with the key, and the relay is not that.
    let mut envelope = well_formed();
    envelope.ct = Vec::new();
    envelope.hash = envelope.computed_hash();
    assert_eq!(Envelope::decode(&envelope.encode()).unwrap(), envelope);
}

#[test]
fn a_decode_refuses_bytes_left_over_after_the_last_field() {
    // Trailing garbage would let two byte strings decode to one envelope, and two
    // encodings of one value is the same hole as a non-canonical integer: the
    // content address stops being an address.
    let mut encoded = well_formed().encode();
    encoded.push(0x00);
    assert_eq!(
        Envelope::decode(&encoded),
        Err(EnvelopeError::Cbor(CborError::TrailingBytes(1)))
    );
}

// MARK: The content address

#[test]
fn the_content_address_changes_when_any_of_its_five_inputs_changes() {
    // `BLAKE3(v, enc, group, epoch, ct)`. Each input is proven to be inside the
    // address, because one that was not would let two different envelopes share an
    // address and the second would be silently discarded as a duplicate.
    let base = well_formed();
    let address = base.computed_hash();
    assert_eq!(address.len(), HASH_BYTES);

    let mut version = base.clone();
    version.v = VERSION + 1;
    assert_ne!(version.computed_hash(), address, "v is not in the address");

    let mut enc = base.clone();
    enc.enc = Encryption::Mls;
    assert_ne!(enc.computed_hash(), address, "enc is not in the address");

    let mut group = base.clone();
    group.group[0] ^= 0xff;
    assert_ne!(
        group.computed_hash(),
        address,
        "group is not in the address"
    );

    let mut epoch = base.clone();
    epoch.epoch += 1;
    assert_ne!(
        epoch.computed_hash(),
        address,
        "epoch is not in the address"
    );

    let mut ct = base.clone();
    ct.ct.push(0x00);
    assert_ne!(ct.computed_hash(), address, "ct is not in the address");

    // And the free function and the method agree, because the client computes the
    // former and the relay checks the latter.
    assert_eq!(
        content_hash(base.v, base.enc, &base.group, base.epoch, &base.ct),
        address
    );
}

#[test]
fn the_content_address_does_not_change_when_seq_or_ts_change() {
    // This is why `seq` and `ts` are excluded. The relay assigns both, so an
    // address covering them would change the moment the relay touched the
    // envelope, and a client retrying after a dropped connection would send a
    // different address and be stored twice. `operations.md` turns on a retry
    // deduplicating, and this is the property that makes it possible.
    let base = well_formed();
    let address = base.computed_hash();
    let mut assigned = base.clone();
    assigned.seq = 42;
    assigned.ts = 1_700_000_000_000;
    assert_eq!(assigned.computed_hash(), address);
    // The `hash` field itself is not in the address either, so a peer cannot
    // change the address by lying about it. It is only ever compared against.
    let mut lying = base.clone();
    lying.hash = vec![0xaa; HASH_BYTES];
    assert_eq!(lying.computed_hash(), address);
}

// MARK: Validate

#[test]
fn a_well_formed_envelope_passes_under_both_floors() {
    // `enc` 1 satisfies a relay configured for either floor, which is what lets an
    // MLS client talk to a relay that has not yet raised its own.
    let mut envelope = well_formed();
    envelope
        .validate(MinEncryption::None)
        .expect("plaintext under no floor");
    envelope.enc = Encryption::Mls;
    envelope.hash = envelope.computed_hash();
    envelope
        .validate(MinEncryption::None)
        .expect("mls under no floor");
    envelope
        .validate(MinEncryption::Mls)
        .expect("mls under an mls floor");
}

#[test]
fn validate_refuses_a_protocol_version_this_build_does_not_speak() {
    // First check and cheapest: a peer sending a two megabyte envelope with a
    // version this relay never supported is refused before the relay reads all of
    // it, let alone hashes it.
    let mut envelope = well_formed();
    envelope.v = VERSION + 1;
    assert_eq!(
        envelope.validate(MinEncryption::None),
        Err(EnvelopeError::UnsupportedVersion(2))
    );
    // And a version of zero is no more acceptable than a version from the future.
    envelope.v = 0;
    assert_eq!(
        envelope.validate(MinEncryption::None),
        Err(EnvelopeError::UnsupportedVersion(0))
    );
}

#[test]
fn validate_refuses_plaintext_on_a_relay_that_requires_mls() {
    // `migration.md` Phases 1 and 2 carry `enc` 0 and the hosted tier never
    // accepts it. The floor is the one line of configuration that decides which of
    // those a relay is, and a relay that took plaintext anyway would be selling a
    // guarantee it does not have.
    let envelope = well_formed();
    assert_eq!(envelope.enc, Encryption::None);
    assert_eq!(
        envelope.validate(MinEncryption::Mls),
        Err(EnvelopeError::PlaintextRefused)
    );
}

#[test]
fn validate_refuses_a_ciphertext_over_the_limit_before_it_hashes_it() {
    // The size check comes before the hash for a reason that matters under load: a
    // hostile peer must not be able to make the relay hash more than the ceiling
    // however many envelopes it sends. The envelope here has a wrong hash as well,
    // and the size is what is reported, which is the observable form of that
    // ordering.
    let mut envelope = well_formed();
    envelope.ct = vec![0u8; MAX_CIPHERTEXT_BYTES + 1];
    assert_eq!(
        envelope.validate(MinEncryption::None),
        Err(EnvelopeError::CiphertextTooLarge(MAX_CIPHERTEXT_BYTES + 1))
    );
    // Exactly at the limit is accepted: the ceiling is inclusive, and an
    // off-by-one here would refuse a message a conforming client is entitled to
    // send.
    envelope.ct = vec![0u8; MAX_CIPHERTEXT_BYTES];
    envelope.hash = envelope.computed_hash();
    envelope
        .validate(MinEncryption::None)
        .expect("the limit itself is legal");
}

#[test]
fn validate_refuses_an_envelope_whose_hash_is_not_its_own_address() {
    // The check that makes the relay's storage content addressed at all. Without
    // it a peer could claim any address for any bytes, and dedupe would collapse
    // two different messages into one.
    let mut envelope = well_formed();
    envelope.hash = vec![0u8; HASH_BYTES];
    assert_eq!(
        envelope.validate(MinEncryption::None),
        Err(EnvelopeError::HashMismatch)
    );
    // A single flipped bit is as refused as a hash of zeroes.
    envelope.hash = envelope.computed_hash();
    envelope.hash[31] ^= 0x01;
    assert_eq!(
        envelope.validate(MinEncryption::None),
        Err(EnvelopeError::HashMismatch)
    );
    // And an envelope whose fields changed after it was addressed is caught by the
    // same check, which is the case an on-path attacker actually produces.
    let mut tampered = well_formed();
    tampered.ct = b"different ciphertext".to_vec();
    assert_eq!(
        tampered.validate(MinEncryption::None),
        Err(EnvelopeError::HashMismatch)
    );
}

// MARK: The error registry

#[test]
fn every_envelope_error_carries_the_code_the_registry_names_for_it() {
    // A `SEND` that failed without a code leaves a client unable to tell "do not
    // retry this" from "try again in a minute", and `wire.md` requires that a
    // retry is always safe. Each mapping is asserted separately because each one
    // is a different instruction to the client.
    let cases = [
        (
            EnvelopeError::Cbor(CborError::Truncated),
            ErrorCode::NoncanonicalCbor,
        ),
        (
            EnvelopeError::UnsupportedVersion(2),
            ErrorCode::ProtocolUnsupported,
        ),
        (
            EnvelopeError::UnknownEncryption(9),
            ErrorCode::MalformedHeader,
        ),
        (EnvelopeError::PlaintextRefused, ErrorCode::PlaintextRefused),
        (EnvelopeError::HashMismatch, ErrorCode::HashMismatch),
        (
            EnvelopeError::CiphertextTooLarge(1),
            ErrorCode::EnvelopeTooLarge,
        ),
    ];
    for (error, code) in &cases {
        assert_eq!(error.code(), *code, "{error:?}");
        // Every message says something, and none of them is the empty string a
        // caller would log as a blank line.
        assert!(!error.to_string().is_empty(), "{error:?}");
    }
    // Six variants, six codes, all distinct. A collision would mean two different
    // faults telling a client the same thing.
    let mut codes: Vec<&str> = cases.iter().map(|(_, code)| code.as_str()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), cases.len());

    // The messages name the offending value, because "unsupported version" without
    // the number is not something an operator can act on.
    assert!(EnvelopeError::UnsupportedVersion(2)
        .to_string()
        .contains('2'));
    assert!(EnvelopeError::UnknownEncryption(9)
        .to_string()
        .contains('9'));
    assert!(EnvelopeError::CiphertextTooLarge(1_048_577)
        .to_string()
        .contains("1048577"));
    assert!(EnvelopeError::Cbor(CborError::Truncated)
        .to_string()
        .contains("input ended inside an item"));

    // Clonable and comparable, because the accept path wraps one in `AcceptError`
    // and the suites above compare them.
    let error = EnvelopeError::HashMismatch;
    assert_eq!(error.clone(), error);
    assert!(format!("{error:?}").contains("HashMismatch"));
}

#[test]
fn a_cbor_failure_converts_into_an_envelope_failure() {
    // The `From` impl is what lets `decode` use `?` on a reader error, and a
    // conversion that lost the underlying fault would leave every malformed
    // envelope reported as the same undifferentiated refusal.
    let converted: EnvelopeError = CborError::TrailingBytes(3).into();
    assert_eq!(converted, EnvelopeError::Cbor(CborError::TrailingBytes(3)));
    assert_eq!(converted.code(), ErrorCode::NoncanonicalCbor);
}
