// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The media wire: the four public retention records, and the `BLOB` bodies.
//!
//! Tier 1. `specs/backend/relay/media.md` says the control records "live beside
//! envelopes, not inside `ct`, and use canonical CBOR", which makes this file the
//! place that pins the encoding rather than a place that exercises it. Every
//! record is asserted three ways:
//!
//! 1. It round trips.
//! 2. Its `signing_bytes` is a strict prefix of its `encode`, with the signature
//!    fields and nothing else removed. That is the property a signer and a
//!    verifier both depend on, and it is the one a field reordering breaks
//!    silently.
//! 3. Every way a decode can refuse is refused, naming the reason.
//!
//! Nothing here touches a database, a socket or a clock.

use wealdrelay::cbor::{self, CborError};
use wealdrelay::media::wire::{
    MediaWireError, Request, Response, RetentionControl, RetentionDestruction, RetentionManifest,
    RetentionPolicy, Signature, MAX_LIST,
};

fn h(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

fn sig(seed: u8) -> Vec<u8> {
    vec![seed; 64]
}

fn signature(seed: u8) -> Signature {
    Signature {
        key: h(seed),
        sig: sig(seed),
    }
}

fn control(prev: Option<Vec<u8>>) -> RetentionControl {
    RetentionControl {
        group: h(0x11),
        epoch: 7,
        verifier: h(0x22),
        prev_control_hash: prev,
        sig: sig(0x33),
    }
}

fn manifest(prev: Option<Vec<u8>>) -> RetentionManifest {
    RetentionManifest {
        group: h(0x11),
        epoch: 7,
        sequence: 3,
        prev_manifest_hash: prev,
        blobs: vec![h(0xa1), h(0xa2)],
        sig: sig(0x44),
    }
}

fn policy() -> RetentionPolicy {
    RetentionPolicy {
        group: h(0x11),
        version: 2,
        media_after_days: 45,
        text_after_days: 90,
        not_before: 1_700_000_000,
        authorizers: vec![h(0x51), h(0x52)],
        signatures: vec![signature(0x61), signature(0x62)],
    }
}

fn destruction(policy_version: Option<u64>) -> RetentionDestruction {
    RetentionDestruction {
        group: h(0x11),
        kind: b"blob".to_vec(),
        target_digest: h(0x71),
        policy_version,
        not_before: 1_700_000_000,
        authorizers: vec![h(0x51)],
        signatures: vec![signature(0x61)],
    }
}

// MARK: The four records

#[test]
fn a_control_round_trips_with_and_without_a_predecessor() {
    for record in [control(None), control(Some(h(0x99)))] {
        let encoded = record.encode();
        assert_eq!(RetentionControl::decode(&encoded), Ok(record.clone()));
        // The signature is the last field and nothing else moved: signing bytes
        // are the encoding with the signature removed and the array header one
        // shorter, so a prefix comparison would be wrong and this is the
        // assertion that actually holds.
        assert!(encoded.ends_with(&cbor::bytes(&record.sig)));
        assert_eq!(
            record.signing_bytes().len() + cbor::bytes(&record.sig).len(),
            encoded.len()
        );
        // The digest names the whole record, signature included, because a later
        // control's `prev_control_hash` has to pin which control it followed and
        // not merely what that control said.
        assert_eq!(record.digest(), blake3::hash(&encoded).as_bytes().to_vec());
        assert_eq!(record.digest().len(), 32);
    }
    assert_ne!(control(None).digest(), control(Some(h(0x99))).digest());
}

#[test]
fn a_manifest_round_trips_and_its_digest_covers_its_blob_list() {
    for record in [manifest(None), manifest(Some(h(0x98)))] {
        let encoded = record.encode();
        assert_eq!(RetentionManifest::decode(&encoded), Ok(record.clone()));
        assert_eq!(record.digest(), blake3::hash(&encoded).as_bytes().to_vec());
        assert_eq!(
            record.signing_bytes().len() + cbor::bytes(&record.sig).len(),
            encoded.len()
        );
    }
    let mut reordered = manifest(None);
    reordered.blobs.reverse();
    assert_ne!(
        manifest(None).digest(),
        reordered.digest(),
        "the blob list is signed in order, so a reordering is a different manifest"
    );
    let empty = RetentionManifest {
        blobs: Vec::new(),
        ..manifest(None)
    };
    assert_eq!(RetentionManifest::decode(&empty.encode()), Ok(empty));
}

#[test]
fn a_policy_round_trips_and_refuses_an_empty_authorizer_list() {
    let record = policy();
    assert_eq!(
        RetentionPolicy::decode(&record.encode()),
        Ok(record.clone())
    );
    assert!(record.signing_bytes().len() < record.encode().len());

    // `authorizers` is what the relay checks a signer against, so a record that
    // named nobody would be a record nobody could be checked against.
    let empty = RetentionPolicy {
        authorizers: Vec::new(),
        ..policy()
    };
    assert_eq!(
        RetentionPolicy::decode(&empty.encode()),
        Err(MediaWireError::EmptyList)
    );

    // No signatures at all is a shape the wire admits: it is a proposal nobody
    // has approved, and refusing it here would hide it behind a decode error
    // rather than behind the authorization check that is meant to catch it.
    let unsigned = RetentionPolicy {
        signatures: Vec::new(),
        ..policy()
    };
    assert_eq!(RetentionPolicy::decode(&unsigned.encode()), Ok(unsigned));
}

#[test]
fn a_destruction_round_trips_with_and_without_a_policy_version() {
    for record in [destruction(None), destruction(Some(9))] {
        assert_eq!(
            RetentionDestruction::decode(&record.encode()),
            Ok(record.clone())
        );
        assert!(record.signing_bytes().len() < record.encode().len());
    }
    assert_ne!(
        destruction(None).signing_bytes(),
        destruction(Some(9)).signing_bytes()
    );

    let empty = RetentionDestruction {
        authorizers: Vec::new(),
        ..destruction(None)
    };
    assert_eq!(
        RetentionDestruction::decode(&empty.encode()),
        Err(MediaWireError::EmptyList)
    );
}

/// `policy_version` is carried as eight big-endian bytes, so a record naming a
/// version of some other width is not a version this relay can read. It is
/// refused rather than truncated, because silently reading the first eight bytes
/// of a longer field would make two different records decode to the same policy.
#[test]
fn a_destruction_with_a_mis_sized_policy_version_is_refused() {
    let bytes = cbor::array(&[
        cbor::bytes(&h(0x11)),
        cbor::bytes(b"blob"),
        cbor::bytes(&h(0x71)),
        cbor::bytes(&[0u8; 4]),
        cbor::uint(5),
        cbor::array(&[cbor::bytes(&h(0x51))]),
        cbor::array(&[]),
    ]);
    assert_eq!(
        RetentionDestruction::decode(&bytes),
        Err(MediaWireError::TooManyEntries)
    );
}

// MARK: The bounds

/// `MAX_LIST` is refused before the allocation, the same rule `access::MAX_ENTRIES`
/// follows: a length prefix is attacker-supplied and reserving against it is the
/// allocation an attacker was asking for.
#[test]
fn a_list_longer_than_the_bound_is_refused_before_it_is_allocated() {
    let too_many: Vec<Vec<u8>> = (0..=MAX_LIST).map(|_| cbor::bytes(&h(1))).collect();
    let manifest_bytes = cbor::array(&[
        cbor::bytes(&h(0x11)),
        cbor::uint(1),
        cbor::uint(1),
        cbor::optional_bytes(None),
        cbor::array(&too_many),
        cbor::bytes(&sig(1)),
    ]);
    assert_eq!(
        RetentionManifest::decode(&manifest_bytes),
        Err(MediaWireError::TooManyEntries)
    );

    let many_signatures: Vec<Vec<u8>> = (0..=MAX_LIST)
        .map(|_| cbor::array(&[cbor::bytes(&h(1)), cbor::bytes(&sig(1))]))
        .collect();
    let policy_bytes = cbor::array(&[
        cbor::bytes(&h(0x11)),
        cbor::uint(1),
        cbor::uint(30),
        cbor::uint(30),
        cbor::uint(0),
        cbor::array(&[cbor::bytes(&h(0x51))]),
        cbor::array(&many_signatures),
    ]);
    assert_eq!(
        RetentionPolicy::decode(&policy_bytes),
        Err(MediaWireError::TooManyEntries)
    );

    let complete_bytes = cbor::array(&[
        cbor::uint(4),
        cbor::array(&[
            cbor::bytes(&[0u8; 16]),
            cbor::array(
                &(0..=MAX_LIST)
                    .map(|_| cbor::array(&[cbor::uint(1), cbor::bytes(b"e")]))
                    .collect::<Vec<_>>(),
            ),
        ]),
    ]);
    assert_eq!(
        Request::decode(&complete_bytes),
        Err(MediaWireError::TooManyEntries)
    );
}

/// Trailing bytes are not ignored. A decoder that stopped at the end of the
/// structure it expected would accept two different byte strings as the same
/// record, and every one of these records is signed over its bytes.
#[test]
fn every_record_refuses_a_trailing_byte() {
    let mut control_bytes = control(None).encode();
    control_bytes.push(0);
    assert!(matches!(
        RetentionControl::decode(&control_bytes),
        Err(MediaWireError::Encoding(_))
    ));

    let mut manifest_bytes = manifest(None).encode();
    manifest_bytes.push(0);
    assert!(matches!(
        RetentionManifest::decode(&manifest_bytes),
        Err(MediaWireError::Encoding(_))
    ));

    let mut policy_bytes = policy().encode();
    policy_bytes.push(0);
    assert!(matches!(
        RetentionPolicy::decode(&policy_bytes),
        Err(MediaWireError::Encoding(_))
    ));

    let mut destruction_bytes = destruction(None).encode();
    destruction_bytes.push(0);
    assert!(matches!(
        RetentionDestruction::decode(&destruction_bytes),
        Err(MediaWireError::Encoding(_))
    ));

    for request in requests() {
        let mut bytes = request.encode();
        bytes.push(0);
        assert!(
            matches!(Request::decode(&bytes), Err(MediaWireError::Encoding(_))),
            "a trailing byte was accepted after {request:?}"
        );
    }
    for response in responses() {
        let mut bytes = response.encode();
        bytes.push(0);
        assert!(
            matches!(Response::decode(&bytes), Err(MediaWireError::Encoding(_))),
            "a trailing byte was accepted after {response:?}"
        );
    }
}

/// Truncation at every offset. The assertion is not which error comes back, it
/// is that none of them panics and none of them succeeds, which is the property
/// a hand-written decoder over attacker bytes has to hold everywhere.
#[test]
fn no_truncation_of_any_record_ever_decodes_or_panics() {
    let bodies: Vec<Vec<u8>> = requests()
        .iter()
        .map(Request::encode)
        .chain(responses().iter().map(Response::encode))
        .chain([
            control(Some(h(1))).encode(),
            manifest(Some(h(1))).encode(),
            policy().encode(),
            destruction(Some(1)).encode(),
        ])
        .collect();
    for body in bodies {
        for cut in 0..body.len() {
            let head = &body[..cut];
            assert!(Request::decode(head).is_err() || cut == body.len());
            assert!(Response::decode(head).is_err() || cut == body.len());
            assert!(RetentionControl::decode(head).is_err());
            assert!(RetentionManifest::decode(head).is_err());
            assert!(RetentionPolicy::decode(head).is_err());
            assert!(RetentionDestruction::decode(head).is_err());
        }
    }
}

// MARK: Requests and responses

fn requests() -> Vec<Request> {
    vec![
        Request::Put {
            workspace: b"ws-step4".to_vec(),
            group: h(0x11),
            hash: h(0xa1),
            ciphertext_len: 1024,
        },
        Request::Get {
            workspace: b"ws-step4".to_vec(),
            group: h(0x11),
            hash: h(0xa1),
        },
        Request::MultipartPart {
            session_id: vec![7u8; 16],
            part_number: 3,
            expected_len: 64 * 1024 * 1024,
        },
        Request::MultipartComplete {
            session_id: vec![7u8; 16],
            parts: vec![(1, b"etag-one".to_vec()), (2, b"etag-two".to_vec())],
        },
        Request::MultipartComplete {
            session_id: vec![7u8; 16],
            parts: Vec::new(),
        },
        Request::MultipartAbort {
            session_id: vec![7u8; 16],
        },
        Request::RetentionControl(control(None)),
        Request::RetentionControl(control(Some(h(9)))),
        Request::RetentionManifest(manifest(None)),
        Request::RetentionManifest(manifest(Some(h(9)))),
        Request::RetentionPolicy(policy()),
        Request::RetentionDestruction(destruction(None)),
        Request::RetentionDestruction(destruction(Some(4))),
    ]
}

fn responses() -> Vec<Response> {
    vec![
        Response::Upload {
            url: "http://127.0.0.1:1/blob/a/b/c?exp=1&sig=ff".to_string(),
            expires_in: 900,
        },
        Response::Exists,
        Response::Multipart {
            session_id: vec![7u8; 16],
            part_size: 64 * 1024 * 1024,
            expires_in: 900,
        },
        Response::Download {
            url: "http://127.0.0.1:1/blob/a/b/c?exp=1&sig=ff".to_string(),
            expires_in: 900,
        },
        Response::NotFound,
        Response::MultipartPartUpload {
            url: "http://127.0.0.1:1/blob-part/aa/1?exp=1&sig=ff".to_string(),
            expires_in: 900,
        },
        Response::MultipartCompleted,
        Response::MultipartAborted,
        Response::RetentionAck { digest: h(0x77) },
    ]
}

#[test]
fn every_request_and_response_round_trips() {
    for request in requests() {
        assert_eq!(
            Request::decode(&request.encode()),
            Ok(request.clone()),
            "{request:?} did not round trip"
        );
    }
    for response in responses() {
        assert_eq!(
            Response::decode(&response.encode()),
            Ok(response.clone()),
            "{response:?} did not round trip"
        );
    }
}

/// A tag this build does not know is refused by number, not ignored. A relay
/// that skipped an unknown request would answer nothing to a client that thought
/// it had asked something.
#[test]
fn an_unknown_tag_is_refused_by_number() {
    let request = cbor::array(&[cbor::uint(99), cbor::array(&[])]);
    assert_eq!(
        Request::decode(&request),
        Err(MediaWireError::UnknownTag(99))
    );
    let response = cbor::array(&[cbor::uint(0), cbor::array(&[])]);
    assert_eq!(
        Response::decode(&response),
        Err(MediaWireError::UnknownTag(0))
    );
}

/// A tag that is not a number at all, and a part number that is not one either.
///
/// Truncation cannot reach these: a message cut short fails on the array header
/// before the decoder ever looks at what is inside it. What reaches them is a peer
/// that sends a well-formed CBOR array whose contents are the wrong shape, which is
/// the ordinary case of a client built against a different idea of this protocol,
/// and the hostile case of somebody probing what the decoder will accept. Neither
/// may be read as a tag or a part number the relay then acts on.
#[test]
fn a_tag_or_a_part_number_that_is_not_a_number_is_refused_rather_than_read() {
    let not_a_number = cbor::array(&[cbor::bytes(b"one"), cbor::array(&[])]);
    assert!(matches!(
        Request::decode(&not_a_number),
        Err(MediaWireError::Encoding(_))
    ));
    assert!(matches!(
        Response::decode(&not_a_number),
        Err(MediaWireError::Encoding(_))
    ));

    // Inside a `MULTIPART COMPLETE`, where the part numbers name the parts the
    // relay is about to assemble in order. A number no part can have must stop the
    // decode rather than be truncated into one that some part does have.
    let oversized_part = cbor::array(&[
        cbor::uint(4),
        cbor::array(&[
            cbor::bytes(&[0u8; 16]),
            cbor::array(&[cbor::array(&[
                cbor::uint(u64::MAX),
                cbor::bytes(b"an-etag"),
            ])]),
        ]),
    ]);
    assert!(matches!(
        Request::decode(&oversized_part),
        Err(MediaWireError::Encoding(_))
    ));
}

/// Every error this module can report says what went wrong, because the relay
/// logs the reason and an operator reading "invalid" learns nothing.
#[test]
fn every_error_names_what_it_refused() {
    assert_eq!(
        MediaWireError::TooManyEntries.to_string(),
        format!("a list in the record is longer than {MAX_LIST}")
    );
    assert_eq!(
        MediaWireError::EmptyList.to_string(),
        "an empty list where one entry is required"
    );
    assert_eq!(
        MediaWireError::UnknownTag(42).to_string(),
        "unknown media message tag 42"
    );
    let encoding = MediaWireError::from(CborError::Truncated);
    assert!(encoding
        .to_string()
        .starts_with("media record is not canonical CBOR"));
    assert!(format!("{encoding:?}").contains("Encoding"));
    assert_eq!(encoding.clone(), encoding);
}

/// The retention position question and its answer (WEALD-L355).
///
/// Both directions round trip, and the answer's "no chain at all" case is
/// distinguishable from "chain at epoch zero", which is the distinction the
/// client has to make before deciding whether to publish a genesis control.
#[test]
fn the_retention_position_round_trips_in_both_directions() {
    let request = Request::RetentionPosition { group: h(0x41) };
    assert_eq!(Request::decode(&request.encode()).unwrap(), request);

    let answered = Response::RetentionPosition {
        control_epoch: 7,
        control_digest: Some(h(0x42)),
        next_sequence: 9,
        prev_manifest_hash: Some(h(0x43)),
        blobs: vec![h(0x44), h(0x45)],
    };
    assert_eq!(Response::decode(&answered.encode()).unwrap(), answered);

    let empty = Response::RetentionPosition {
        control_epoch: 0,
        control_digest: None,
        next_sequence: 1,
        prev_manifest_hash: None,
        blobs: Vec::new(),
    };
    assert_eq!(Response::decode(&empty.encode()).unwrap(), empty);
    assert_ne!(empty.encode(), answered.encode());
}

/// A position answer naming more blobs than the wire allows is refused rather
/// than allocated for, the same bound every list on this wire is held to.
#[test]
fn a_position_answer_over_the_list_bound_is_refused() {
    let flood = Response::RetentionPosition {
        control_epoch: 0,
        control_digest: Some(h(0x42)),
        next_sequence: 1,
        prev_manifest_hash: None,
        blobs: (0..=MAX_LIST).map(|_| h(0x44)).collect(),
    };
    assert!(matches!(
        Response::decode(&flood.encode()),
        Err(MediaWireError::TooManyEntries)
    ));
}

/// The quota question and its answer (WEALD-L401).
///
/// The nullable limit is the whole subtlety: unlimited and a ceiling of zero are
/// opposite answers, and a client that read them as the same one would either warn
/// a self-hoster about a limit they do not have or promise room to a workspace
/// allowed none.
#[test]
fn the_quota_read_round_trips_in_both_directions() {
    let request = Request::Quota { group: h(0x51) };
    assert_eq!(Request::decode(&request.encode()).unwrap(), request);

    let limited = Response::Quota {
        stored_bytes: 400_000_000,
        reserved_bytes: 50_000_000,
        limit_bytes: Some(1_000_000_000),
    };
    assert_eq!(Response::decode(&limited.encode()).unwrap(), limited);

    let unlimited = Response::Quota {
        stored_bytes: 400_000_000,
        reserved_bytes: 50_000_000,
        limit_bytes: None,
    };
    assert_eq!(Response::decode(&unlimited.encode()).unwrap(), unlimited);

    let none_allowed = Response::Quota {
        stored_bytes: 0,
        reserved_bytes: 0,
        limit_bytes: Some(0),
    };
    assert_eq!(
        Response::decode(&none_allowed.encode()).unwrap(),
        none_allowed
    );
    assert_ne!(unlimited.encode(), limited.encode());
    assert_ne!(
        Response::Quota {
            stored_bytes: 0,
            reserved_bytes: 0,
            limit_bytes: None,
        }
        .encode(),
        none_allowed.encode(),
        "unlimited and a ceiling of zero must not share an encoding"
    );

    // The widest values the fields can carry, so a saturating read on either side
    // is caught rather than silently reporting the wrong headroom.
    let wide = Response::Quota {
        stored_bytes: u64::MAX,
        reserved_bytes: u64::MAX,
        limit_bytes: Some(u64::MAX),
    };
    assert_eq!(Response::decode(&wide.encode()).unwrap(), wide);
}
