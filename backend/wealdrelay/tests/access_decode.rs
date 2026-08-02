// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `AccessSet::decode` as a total function: every byte string is either one set or
//! one refusal, and never a panic or a half-built set.
//!
//! `tests/access.rs` names the malformed encodings a real client could plausibly
//! send. This file makes the stronger claim the trust boundary needs: the decoder
//! runs before any signature has been checked, on bytes a stranger chose, so the
//! interesting input is not the plausible one. Two properties cover it. Every prefix
//! of a valid encoding is refused, which walks the truncation point through every
//! field in order. And every field, at every depth, is refused when the byte that
//! declares its type declares the wrong one, which is the check that stops a decoder
//! from reading a map where a hash belongs and calling the result membership.
//!
//! Separate from `tests/access.rs` because that file is already long, and the two
//! properties here are generated rather than enumerated.

use ed25519_dalek::{Signer as _, SigningKey};
use wealdrelay::access::{
    AccessError, AccessSet, QuorumSignature, RecoveryQuorum, HASH_BYTES, KEY_BYTES, SIG_BYTES,
};
use wealdrelay::cbor;

const SALT: &[u8] = b"salt for the decoder totality tests";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pk(signer: &SigningKey) -> Vec<u8> {
    signer.verifying_key().to_bytes().to_vec()
}

fn sorted(mut items: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    items.sort();
    items.dedup();
    items
}

/// A set with something in every list, so a truncation point exists inside each one.
/// A list the fixture left empty is a field whose element path no prefix can reach.
fn plain() -> AccessSet {
    let authorizer = key(1);
    let recovery = key(0x3f);
    let member = key(2);
    let entries = sorted(
        [&authorizer, &recovery, &member]
            .iter()
            .map(|signer| wealdrelay::access::entry_hash(&pk(signer), SALT))
            .collect(),
    );
    let mut set = AccessSet {
        workspace: vec![0x77; HASH_BYTES],
        version: 4,
        prev_hash: vec![0x11; HASH_BYTES],
        issued_at: 1,
        entries: entries.clone(),
        authorizers: vec![pk(&authorizer)],
        recovery: vec![pk(&recovery)],
        quorum: None,
        // Non-empty, so the `pending` list has an element boundary of its own.
        pending: vec![entries[0].clone()],
        signer: vec![0u8; KEY_BYTES],
        sig: vec![0u8; SIG_BYTES],
    };
    set.signer = pk(&authorizer);
    set.sig = authorizer.sign(&set.digest_input()).to_bytes().to_vec();
    set
}

/// The same set carrying a registered quorum and one confirmation.
///
/// The quorum arms of the decoder are only reachable through a set that has one, and
/// the signature arms only through a quorum that carries a signature: with the field
/// spelled `null` the decoder returns before ever reading a threshold.
fn with_quorum() -> AccessSet {
    let mut set = plain();
    set.quorum = Some(RecoveryQuorum {
        threshold: 2,
        keys: sorted(vec![pk(&key(0x81)), pk(&key(0x82))]),
        sigs: vec![QuorumSignature {
            key: pk(&key(0x81)),
            sig: key(0x81).sign(b"a confirmation").to_bytes().to_vec(),
        }],
    });
    let authorizer = key(1);
    set.sig = authorizer.sign(&set.digest_input()).to_bytes().to_vec();
    set
}

/// A CBOR item of a major type no field of an access set accepts.
///
/// A map header. The fields are byte strings, unsigned integers, arrays, and the one
/// simple value `null`; a map is none of those, at any position, so substituting it
/// tests the type check itself rather than a length or a range.
fn a_map_where_a_field_belongs() -> Vec<u8> {
    vec![0xa0]
}

#[test]
fn every_prefix_of_a_valid_encoding_is_refused_rather_than_half_decoded() {
    for set in [plain(), with_quorum()] {
        let whole = set.encode();
        assert_eq!(
            AccessSet::decode(&whole).expect("the fixture decodes"),
            set,
            "the fixture this property truncates must itself be valid"
        );
        for length in 0..whole.len() {
            let error = AccessSet::decode(&whole[..length])
                .expect_err("a truncated set is not a set at any length");
            // One class for all of them. A body that stops early is wrong about its
            // own bytes, so the answer is `reject`: resending the same prefix cannot
            // become a longer one, and a relay that answered `denied` would tell the
            // client to go and refetch a head that was never the problem.
            assert!(
                matches!(error, AccessError::Encoding(_)),
                "prefix of {length} bytes was refused as {error:?} rather than as bad encoding"
            );
        }
    }
}

#[test]
fn every_top_level_field_is_refused_when_it_declares_the_wrong_type() {
    let set = with_quorum();
    let fields = top_level_fields(&set);
    assert_eq!(fields.len(), 11, "the wire is eleven positional fields");
    assert_eq!(
        cbor::array(&fields),
        set.encode(),
        "this table must be the encoder's own field order, or it proves nothing"
    );
    for position in 0..fields.len() {
        let mut bad = fields.clone();
        bad[position] = a_map_where_a_field_belongs();
        let error = AccessSet::decode(&cbor::array(&bad))
            .expect_err("a field of the wrong type is not a field");
        assert!(
            matches!(error, AccessError::Encoding(_)),
            "field {position} of the wrong type was refused as {error:?}"
        );
    }
}

#[test]
fn every_field_inside_the_quorum_is_refused_when_it_declares_the_wrong_type() {
    let set = with_quorum();
    let quorum = set.quorum.clone().expect("the fixture registers a quorum");

    // The quorum's own three fields: the threshold, the keys, and the signatures.
    let inner = vec![
        cbor::uint(u64::from(quorum.threshold)),
        list_of(&quorum.keys),
        cbor::array(&[signature_pair(&quorum.sigs[0])]),
    ];
    for position in 0..inner.len() {
        let mut bad = inner.clone();
        bad[position] = a_map_where_a_field_belongs();
        expect_encoding_refusal(&set, cbor::array(&bad), &format!("quorum field {position}"));
    }
    // The quorum itself, spelled as a two-element array. A decoder that read the
    // fields it wanted and ignored the declared arity would accept a shape whose
    // remaining bytes belong to the next field.
    expect_encoding_refusal(&set, cbor::array(&inner[..2]), "a two-field quorum");

    // One signature is a pair. Wrong at the pair, wrong at the key, wrong at the
    // signature: three separate reads, each of which has to refuse on its own.
    let pair = vec![
        cbor::bytes(&quorum.sigs[0].key),
        cbor::bytes(&quorum.sigs[0].sig),
    ];
    let quorum_with = |signatures: Vec<Vec<u8>>| {
        cbor::array(&[
            cbor::uint(u64::from(quorum.threshold)),
            list_of(&quorum.keys),
            cbor::array(&signatures),
        ])
    };
    expect_encoding_refusal(
        &set,
        quorum_with(vec![a_map_where_a_field_belongs()]),
        "a signature that is not a pair",
    );
    for position in 0..pair.len() {
        let mut bad = pair.clone();
        bad[position] = a_map_where_a_field_belongs();
        expect_encoding_refusal(
            &set,
            quorum_with(vec![cbor::array(&bad)]),
            &format!("signature half {position}"),
        );
    }
}

#[test]
fn a_list_element_that_is_not_a_hash_is_refused_on_the_element() {
    // The count said one element and the element is a map. The bound on the count is
    // covered in `tests/access.rs`; what is covered here is the read of an element
    // the count promised, which is a separate refusal inside the loop.
    let set = with_quorum();
    let mut fields = top_level_fields(&set);
    fields[4] = cbor::array(&[a_map_where_a_field_belongs()]);
    let error = AccessSet::decode(&cbor::array(&fields)).expect_err("must refuse");
    assert!(
        matches!(error, AccessError::Encoding(_)),
        "an entry that is not a hash was refused as {error:?}"
    );
}

// MARK: Field tables

/// The eleven positional fields, as the encoder writes them.
fn top_level_fields(set: &AccessSet) -> Vec<Vec<u8>> {
    vec![
        cbor::bytes(&set.workspace),
        cbor::uint(set.version),
        cbor::bytes(&set.prev_hash),
        cbor::uint(set.issued_at),
        list_of(&set.entries),
        list_of(&set.authorizers),
        list_of(&set.recovery),
        match &set.quorum {
            Some(quorum) => cbor::array(&[
                cbor::uint(u64::from(quorum.threshold)),
                list_of(&quorum.keys),
                cbor::array(
                    &quorum
                        .sigs
                        .iter()
                        .map(signature_pair)
                        .collect::<Vec<Vec<u8>>>(),
                ),
            ]),
            None => cbor::optional_bytes(None),
        },
        list_of(&set.pending),
        cbor::bytes(&set.signer),
        cbor::bytes(&set.sig),
    ]
}

fn list_of(items: &[Vec<u8>]) -> Vec<u8> {
    cbor::array(
        &items
            .iter()
            .map(|item| cbor::bytes(item))
            .collect::<Vec<_>>(),
    )
}

fn signature_pair(signature: &QuorumSignature) -> Vec<u8> {
    cbor::array(&[cbor::bytes(&signature.key), cbor::bytes(&signature.sig)])
}

/// Substitute one quorum encoding into an otherwise valid set and require a refusal.
fn expect_encoding_refusal(set: &AccessSet, quorum: Vec<u8>, what: &str) {
    let mut fields = top_level_fields(set);
    fields[7] = quorum;
    let error = AccessSet::decode(&cbor::array(&fields)).expect_err("must refuse");
    assert!(
        matches!(error, AccessError::Encoding(_)),
        "{what} was refused as {error:?} rather than as bad encoding"
    );
}
