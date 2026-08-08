// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The frame set and the error taxonomy, checked against the specs rather than
//! against the source.
//!
//! Two claims are being defended here. The first is that every frame this build
//! can send is a frame it can read back, which is what makes the codec a codec
//! rather than two functions that happen to compile. The second is that the
//! error taxonomy on the wire is the one
//! `specs/backend/contracts/registries/error-codes.md` publishes: a client
//! branches on a class and then on a code, so a code that drifted into another
//! class would silently change what every client does about it. That is why the
//! class assertions below read the registry file instead of restating what
//! `frame.rs` already says.

use std::collections::{BTreeMap, BTreeSet};

use wealdrelay::cbor;
use wealdrelay::frame::{
    ErrorClass, ErrorCode, Frame, FrameDecodeError, FrameError, FrameTag, KeysBody, WakeBody,
    MAX_FRAME_BYTES, PROTOCOL_VERSION,
};

/// A 32 byte field: a group id, a device key, a content hash.
fn wide(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

/// A 64 byte field: an Ed25519 signature.
fn signature(seed: u8) -> Vec<u8> {
    vec![seed; 64]
}

/// One frame of every variant, as a table.
///
/// A table rather than a test per frame so that a variant added without a case
/// here is visible: the coverage assertion below compares the tags this table
/// produces against `FrameTag::ALL` and names the ones missing.
fn every_variant() -> Vec<Frame> {
    vec![
        Frame::Connect {
            version: PROTOCOL_VERSION,
            groups: vec![wide(1), wide(2)],
            sent_at: 1_700_000_000_000,
        },
        // The same frame with no groups, because the group loop having a zero
        // case is the difference between "subscribes to nothing yet" and a
        // decoder that requires at least one.
        Frame::Connect {
            version: PROTOCOL_VERSION,
            groups: Vec::new(),
            sent_at: 0,
        },
        Frame::ConnectAck {
            version: PROTOCOL_VERSION,
            server_time: 1_700_000_000_001,
            min_enc: 1,
        },
        Frame::AuthChallenge {
            challenge: vec![0xab; 48],
        },
        Frame::Auth {
            device_key: wide(3),
            signature: signature(4),
        },
        Frame::AuthAck {
            key_packages_remaining: 97,
            write_mode: 0,
            build_digest: b"sha256:0123456789abcdef".to_vec(),
            access_set: 1,
            min_enc: 1,
        },
        Frame::Access { body: vec![9; 128] },
        // Client to relay, carrying an encoded `RecoveryWrap`, and relay to client
        // carrying only the tag it stored. Both directions, because the frame is
        // used in both and the acknowledgement's body is much shorter than the
        // publication's.
        Frame::Wrap { body: vec![7; 200] },
        Frame::Wrap { body: vec![7; 32] },
        // Both directions again: client to relay with `seq` zero and unread, relay
        // to client carrying the position the group's order gave it.
        Frame::Handshake {
            group: wide(9),
            seq: 0,
            message: vec![3; 512],
        },
        Frame::Join { body: vec![5; 96] },
        // Both directions, same shape, like `HANDSHAKE`. The empty body case is
        // deliberate: a beat whose sealed struct happened to be short must decode
        // rather than being read as a truncated frame.
        Frame::Live {
            group: wide(11),
            epoch: 4,
            ct: vec![2; 96],
        },
        Frame::Live {
            group: wide(11),
            epoch: u64::MAX,
            ct: vec![1],
        },
        // All five `KEYS` forms. The relay-to-client ones round trip here even
        // though `session.rs` refuses them on the way in: this suite is about the
        // codec, and a form the relay could send and not read back would be a form
        // no test could ever check.
        Frame::Keys(KeysBody::Publish {
            packages: vec![vec![1; 64], vec![2; 64]],
        }),
        Frame::Keys(KeysBody::Publish {
            packages: Vec::new(),
        }),
        Frame::Keys(KeysBody::Published { remaining: 97 }),
        Frame::Keys(KeysBody::Fetch {
            device: wide(12),
            count: 8,
        }),
        Frame::Keys(KeysBody::Bundles {
            packages: vec![vec![3; 64]],
        }),
        Frame::Keys(KeysBody::None),
        // Every signalling kind, because the number is on the wire and it is the
        // one field of either call frame the relay interprets.
        Frame::Call {
            call_id: vec![0xC1; 16],
            group: wide(11),
            epoch: 7,
            kind: 1,
            body: vec![0xDE, 0xAD],
        },
        Frame::Call {
            call_id: vec![0xC2; 16],
            group: wide(12),
            epoch: u64::MAX,
            kind: 4,
            // A zero-length body is legal: an offer whose whole content is the
            // kind is a frame the relay must carry unchanged.
            body: Vec::new(),
        },
        Frame::Media {
            call_id: vec![0xC3; 16],
            stream: vec![0, 0, 0, 1],
            seq: 0,
            ct: vec![0x41; 80],
        },
        Frame::Media {
            // An all-zero call id is not reserved and is not special-cased: the
            // relay compares call ids and derives nothing from them.
            call_id: vec![0; 16],
            stream: vec![0xFF; 4],
            // The counter never wraps inside an epoch by construction, but the
            // codec has to carry the width regardless: a saturating read on
            // either side would silently reorder a stream.
            seq: u64::MAX,
            ct: Vec::new(),
        },
        // Every `WAKE` form, because the leading discriminant is on the wire and
        // the tag-set assertion below is what noticed this frame had no case here
        // at all: tag 25 shipped in protocol version 4 and round-tripped nowhere.
        Frame::Wake(WakeBody::Register {
            handle: vec![0xA7; 16],
            categories: 0b0000_0001,
            expires_at: 1_700_000_000_000,
        }),
        Frame::Wake(WakeBody::Register {
            // Every defined bit at once (message, call, handshake), and the
            // furthest expiry a u64 can name.
            // Both are legal and neither is special-cased.
            handle: vec![0; 16],
            categories: 0b0000_0111,
            expires_at: u64::MAX,
        }),
        Frame::Wake(WakeBody::Registered {
            expires_at: 1_700_000_086_400,
        }),
        Frame::Wake(WakeBody::Clear),
        Frame::Wake(WakeBody::Cleared),
        Frame::Wake(WakeBody::Query),
        Frame::Wake(WakeBody::Capability {
            enabled: true,
            register_url: "https://ringer.weald.team/register".to_string(),
        }),
        Frame::Wake(WakeBody::Capability {
            // Off, and with no url to go to, which is the shape a self-hoster who
            // has not chosen a ringer answers with.
            enabled: false,
            register_url: String::new(),
        }),
        Frame::Invite { body: vec![6; 64] },
        Frame::Handshake {
            group: wide(9),
            seq: u64::MAX,
            message: vec![4],
        },
        Frame::Sub {
            group: wide(5),
            from_seq: 0,
        },
        Frame::SubAck {
            group: wide(6),
            head_seq: u64::MAX,
        },
        Frame::Recon {
            group: wide(7),
            payload: vec![1, 2, 3],
        },
        Frame::Push {
            envelope: vec![0x10; 300],
        },
        Frame::Send {
            envelope: vec![0x11; 300],
        },
        Frame::SendAck {
            hash: wide(8),
            seq: 42,
        },
        Frame::Blob {
            payload: vec![0x12; 64],
        },
        // Both directions, like `WRAP`: the instruction going up and the relay's
        // count coming back are the same frame with different bodies.
        Frame::Drop {
            payload: vec![0x34; 96],
        },
        Frame::Drop {
            payload: vec![0x34; 8],
        },
        Frame::Bye {
            reason: b"going away".to_vec(),
        },
        Frame::Error(
            FrameError::new(ErrorCode::RateLimited)
                .retry_after(30)
                .detail(wide(9)),
        ),
        // The same frame with both optional fields absent, because absence is
        // carried as a zero and an empty string on the wire and has to come back
        // as absence.
        Frame::Error(FrameError::new(ErrorCode::GroupUnknown)),
    ]
}

/// The class column of table A in `error-codes.md`, read from the file.
///
/// Read rather than transcribed so that this test asserts the published
/// contract. A row edited in the registry and not in `frame.rs` fails here,
/// which is the direction the failure has to point: the registry is the
/// authority and the enum is the implementation of it.
fn registry_classes() -> BTreeMap<String, String> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/backend/contracts/registries/error-codes.md"
    );
    let text = std::fs::read_to_string(path).expect("the error code registry is checked in");
    let mut rows = BTreeMap::new();
    for line in text.lines() {
        let mut cells = line.split('|').map(str::trim);
        // The leading empty cell before the first pipe, then the code, then the
        // class. Anything that is not a table row falls out on the parse below.
        if cells.next() != Some("") {
            continue;
        }
        let (Some(code), Some(class)) = (cells.next(), cells.next()) else {
            continue;
        };
        let Some(qualified) = code.strip_prefix('`').and_then(|c| c.strip_suffix('`')) else {
            continue;
        };
        let Some((class_prefix, bare)) = qualified.split_once('/') else {
            continue;
        };
        if class_prefix != class {
            panic!("registry row `{qualified}` is filed under class `{class}`");
        }
        rows.insert(bare.to_string(), class.to_string());
    }
    assert!(
        rows.len() >= 19,
        "the registry parse found only {} relay codes, so the table format changed",
        rows.len()
    );
    rows
}

// MARK: The frame set

#[test]
fn every_frame_variant_round_trips_and_the_table_covers_the_tag_set() {
    // The round trip is the codec's whole contract: what this build writes, this
    // build reads back identically. The coverage check underneath is what stops
    // that claim from quietly shrinking when a variant is added.
    let mut covered = BTreeSet::new();
    for frame in every_variant() {
        let encoded = frame.encode();
        let decoded = Frame::decode(&encoded).expect("a frame this build wrote decodes");
        assert_eq!(decoded, frame, "round trip changed the frame");
        assert_eq!(decoded.tag(), frame.tag());
        // Encoding is deterministic, so the second pass over the decoded frame
        // has to produce the identical bytes. Anything else would give one frame
        // two encodings.
        assert_eq!(decoded.encode(), encoded);
        covered.insert(frame.tag() as u16);
    }
    let expected: BTreeSet<u16> = FrameTag::ALL.iter().map(|tag| *tag as u16).collect();
    assert_eq!(
        covered, expected,
        "a frame variant has no case in every_variant()"
    );
}

#[test]
fn a_frame_is_a_tag_and_a_body_and_nothing_else() {
    // The outer shape is fixed by `wire.md`: a two item array of the tag and the
    // body. Asserted on bytes because the shape is what a client's decoder is
    // written against, and a third item would break every one of them.
    let frame = Frame::Bye {
        reason: b"bye".to_vec(),
    };
    let expected = cbor::array(&[
        cbor::uint(u64::from(FrameTag::Bye as u16)),
        cbor::array(&[cbor::bytes(b"bye")]),
    ]);
    assert_eq!(frame.encode(), expected);
}

#[test]
fn from_u16_accepts_exactly_the_tags_the_build_speaks() {
    // The tag is a wire number, so the accepted set has to be exactly the
    // declared set: one number more and this build would name a frame it cannot
    // read, one less and it would refuse a frame it can.
    for tag in FrameTag::ALL {
        assert_eq!(FrameTag::from_u16(*tag as u16), Some(*tag));
    }
    let known: BTreeSet<u16> = FrameTag::ALL.iter().map(|tag| *tag as u16).collect();
    for value in 0u16..=512 {
        assert_eq!(FrameTag::from_u16(value).is_some(), known.contains(&value));
    }
    // The two ends, called out because 0 is what an all-zero buffer looks like
    // and 65535 is what a truncated or sign-flipped one looks like.
    assert_eq!(FrameTag::from_u16(0), None);
    assert_eq!(FrameTag::from_u16(u16::MAX), None);
}

// MARK: The error taxonomy

#[test]
fn every_error_code_has_the_class_the_registry_gives_it() {
    // Code by code against `error-codes.md`, because the class is what a client
    // branches on before it has ever heard of the code. A code that moved from
    // `denied` to `retry` would turn "stop and re-read the state" into "send it
    // again", which is the failure this test exists to prevent.
    let registry = registry_classes();
    let mut unregistered = Vec::new();
    for code in ErrorCode::ALL {
        match registry.get(code.as_str()) {
            Some(class) => assert_eq!(
                code.class().as_str(),
                class,
                "`{}` is `{class}` in the registry",
                code.as_str()
            ),
            None => unregistered.push(code.as_str()),
        }
    }
    // Every code this build can emit has a row. The registry is closed and
    // `scripts/spec-check.sh` walks it rather than the source, so a code the relay
    // can emit and the registry does not list is a code invisible to the check
    // that exists to catch exactly that. `group_ingress_limited` was in that state
    // until step 4 added its row, which is why the assertion is on emptiness
    // rather than on a list of known gaps: a known gap is a gap somebody has
    // stopped noticing.
    assert!(
        unregistered.is_empty(),
        "these codes have no row in the registry: {unregistered:?}"
    );

    // The other direction: registry rows this build does not implement yet. The
    // invite codes belong to enrollment, which is a later step. Anything else
    // appearing here is a code the relay can be asked about and cannot name.
    let implemented: BTreeSet<&str> = ErrorCode::ALL.iter().map(|code| code.as_str()).collect();
    let missing: Vec<&String> = registry
        .keys()
        .filter(|code| !implemented.contains(code.as_str()))
        .collect();
    assert_eq!(
        missing,
        vec!["invite_code_invalid", "invite_expired", "invite_seat_spent"]
    );
}

#[test]
fn every_code_string_is_unique_and_qualifies_as_class_slash_code() {
    // `qualified()` is the form the registry lists and the client logs, so it has
    // to be the class and the code with one slash between them. Uniqueness is the
    // property that makes a code worth matching on at all: two codes with one
    // string would be two situations a client could not tell apart.
    let mut seen = BTreeSet::new();
    for code in ErrorCode::ALL {
        assert!(!code.as_str().is_empty());
        assert!(
            seen.insert(code.as_str()),
            "duplicate code {}",
            code.as_str()
        );
        assert_eq!(
            code.qualified(),
            format!("{}/{}", code.class().as_str(), code.as_str())
        );
    }
    assert_eq!(seen.len(), ErrorCode::ALL.len());

    // The class names themselves are on the wire too, and are the five
    // `operations.md` defines.
    let classes: Vec<&str> = [
        ErrorClass::Retry,
        ErrorClass::Reject,
        ErrorClass::Denied,
        ErrorClass::Quota,
        ErrorClass::Version,
    ]
    .iter()
    .map(|class| class.as_str())
    .collect();
    assert_eq!(
        classes,
        vec!["retry", "reject", "denied", "quota", "version"]
    );
}

#[test]
fn only_retry_quota_and_limit_are_retryable() {
    // Three classes and no others. `limit` joined `retry` and `quota` with
    // protocol version 4: it is one principal's own rate on a write it can stop
    // making, so the same bytes after the named interval are exactly the right
    // move. `denied` is deliberately excluded: it means well formed but not
    // permitted now, and retrying blind against a state that changed is how a
    // client hammers a relay that has already told it no. The remedy for `denied`
    // is to re-read the state the error names. `reject` is permanently wrong as
    // sent and `version` aborts the connection.
    assert!(ErrorClass::Retry.is_retryable());
    assert!(ErrorClass::Quota.is_retryable());
    assert!(ErrorClass::Limit.is_retryable());
    assert!(!ErrorClass::Denied.is_retryable());
    assert!(!ErrorClass::Reject.is_retryable());
    assert!(!ErrorClass::Version.is_retryable());

    for code in ErrorCode::ALL {
        let expected = matches!(
            code.class(),
            ErrorClass::Retry | ErrorClass::Quota | ErrorClass::Limit
        );
        assert_eq!(
            code.class().is_retryable(),
            expected,
            "{} would be retried",
            code.qualified()
        );
    }
}

#[test]
fn an_error_carries_its_class_and_only_the_fields_it_was_given() {
    // The builder is how the relay constructs an error, so the default has to be
    // "no interval, no detail": a `retry_after` that defaulted to a number would
    // be the relay inventing a wait it never measured.
    let bare = FrameError::new(ErrorCode::Backpressure);
    assert_eq!(bare.class(), ErrorClass::Retry);
    assert_eq!(bare.retry_after, None);
    assert_eq!(bare.detail, None);

    let full = FrameError::new(ErrorCode::StorageExhausted)
        .retry_after(60)
        .detail(b"limit=10gb".to_vec());
    assert_eq!(full.class(), ErrorClass::Quota);
    assert_eq!(full.retry_after, Some(60));
    assert_eq!(full.detail.as_deref(), Some(b"limit=10gb".as_slice()));
}

#[test]
fn an_error_frame_round_trips_absence_as_absence() {
    // On the wire the two optional fields are a zero and an empty byte string,
    // so the risk is that a decoder hands back `Some(0)` and `Some(vec![])` and
    // a client renders "retry after 0 seconds" for an error that named no
    // interval at all. Absent has to come back absent.
    let absent = Frame::Error(FrameError::new(ErrorCode::GroupFrozen));
    let decoded = Frame::decode(&absent.encode()).expect("the frame decodes");
    let Frame::Error(error) = decoded else {
        panic!("an error frame decoded as something else");
    };
    assert_eq!(error.code, ErrorCode::GroupFrozen);
    assert_eq!(error.retry_after, None);
    assert_eq!(error.detail, None);

    let present = Frame::Error(
        FrameError::new(ErrorCode::RateLimited)
            .retry_after(15)
            .detail(vec![7, 7]),
    );
    let decoded = Frame::decode(&present.encode()).expect("the frame decodes");
    let Frame::Error(error) = decoded else {
        panic!("an error frame decoded as something else");
    };
    assert_eq!(error.code, ErrorCode::RateLimited);
    assert_eq!(error.retry_after, Some(15));
    assert_eq!(error.detail, Some(vec![7, 7]));

    // Every code survives the round trip, which is what makes the code the thing
    // a client may branch on rather than the message.
    for code in ErrorCode::ALL {
        let frame = Frame::Error(FrameError::new(*code));
        assert_eq!(Frame::decode(&frame.encode()).expect("decodes"), frame);
    }
}

// MARK: Refusals

#[test]
fn a_frame_over_the_size_limit_is_refused_before_it_is_parsed() {
    // The bytes below are both oversized and malformed: 0xff is the reserved
    // additional-info byte, so any parse of them fails with a CBOR error. The
    // size error is therefore proof that nothing was parsed, which is the point
    // of the limit: an attacker must not be able to make the relay allocate or
    // walk a buffer it has already decided is too big.
    let oversized = vec![0xffu8; MAX_FRAME_BYTES + 1];
    assert_eq!(
        Frame::decode(&oversized),
        Err(FrameDecodeError::TooLarge(MAX_FRAME_BYTES + 1))
    );

    // Exactly at the limit is not over it, and fails for its content instead.
    let at_limit = vec![0xffu8; MAX_FRAME_BYTES];
    assert!(matches!(
        Frame::decode(&at_limit),
        Err(FrameDecodeError::Cbor(_))
    ));
}

#[test]
fn a_tag_this_build_does_not_speak_is_named_by_its_number() {
    // The number is in the error so an operator can tell a newer client from a
    // corrupt frame. Both a plausible unknown tag and one too wide for the tag
    // field, because the second reaches a different arm.
    let unknown = cbor::array(&[cbor::uint(99), cbor::array(&[])]);
    assert_eq!(
        Frame::decode(&unknown),
        Err(FrameDecodeError::UnknownTag(99))
    );
    assert_eq!(
        Frame::decode(&unknown).unwrap_err().code(),
        ErrorCode::MalformedHeader
    );

    // A tag that does not fit `u16` at all is still reported rather than
    // silently truncated into a tag this build does speak.
    let too_wide = cbor::array(&[cbor::uint(70_000), cbor::array(&[])]);
    assert_eq!(
        Frame::decode(&too_wide),
        Err(FrameDecodeError::UnknownTag(u16::MAX))
    );
}

#[test]
fn a_protocol_version_this_build_does_not_speak_aborts_the_frame() {
    // `operations.md` says a version failure aborts the connection and never
    // silently continues, so it has to be its own error and its own code rather
    // than a bad field. Both directions of the handshake carry a version, so both
    // are checked.
    let client_hello = Frame::Connect {
        version: PROTOCOL_VERSION + 1,
        groups: Vec::new(),
        sent_at: 0,
    };
    assert_eq!(
        Frame::decode(&client_hello.encode()),
        Err(FrameDecodeError::UnsupportedVersion(PROTOCOL_VERSION + 1))
    );

    let relay_hello = Frame::ConnectAck {
        version: 0,
        server_time: 1,
        min_enc: 0,
    };
    assert_eq!(
        Frame::decode(&relay_hello.encode()),
        Err(FrameDecodeError::UnsupportedVersion(0))
    );
    assert_eq!(
        Frame::decode(&relay_hello.encode()).unwrap_err().code(),
        ErrorCode::ProtocolUnsupported
    );
}

#[test]
fn a_field_of_the_wrong_shape_is_refused_where_it_sits() {
    // Each of these is a frame whose outer shape is right and whose fields are
    // not, which is the case a decoder is most likely to wave through.
    let bad_group = cbor::array(&[
        cbor::uint(u64::from(FrameTag::Sub as u16)),
        cbor::array(&[cbor::bytes(&[1, 2, 3]), cbor::uint(0)]),
    ]);
    let error = Frame::decode(&bad_group).expect_err("a short group is refused");
    assert!(matches!(error, FrameDecodeError::Cbor(_)));
    assert_eq!(error.code(), ErrorCode::NoncanonicalCbor);

    // A body with the wrong number of fields is a different frame, not this one.
    let short_body = cbor::array(&[
        cbor::uint(u64::from(FrameTag::Auth as u16)),
        cbor::array(&[cbor::bytes(&[1u8; 32])]),
    ]);
    assert!(matches!(
        Frame::decode(&short_body),
        Err(FrameDecodeError::Cbor(_))
    ));

    // A non-canonical integer anywhere in the frame, which is the case the
    // `reject/noncanonical_cbor` code exists for: 1 written in a following byte
    // rather than in the initial byte.
    let non_canonical = [0x82, 0x18, 0x0e, 0x81, 0x41, 0x00];
    assert!(matches!(
        Frame::decode(&non_canonical),
        Err(FrameDecodeError::Cbor(_))
    ));

    // Trailing bytes after a complete frame. Two frames concatenated must not
    // decode as one, or a peer could hide a frame behind another.
    let mut concatenated = Frame::Bye {
        reason: b"a".to_vec(),
    }
    .encode();
    concatenated.extend_from_slice(
        &Frame::Bye {
            reason: b"b".to_vec(),
        }
        .encode(),
    );
    assert!(matches!(
        Frame::decode(&concatenated),
        Err(FrameDecodeError::Cbor(_))
    ));
}

#[test]
fn an_error_frame_naming_a_code_outside_the_registry_is_a_bad_field() {
    // The registry is closed, so a code nobody registered is a malformed frame
    // and not a code this build passes through. A client that saw an unregistered
    // code would have no branch for it.
    let invented = cbor::array(&[
        cbor::uint(u64::from(FrameTag::Error as u16)),
        cbor::array(&[
            cbor::bytes(b"retry"),
            cbor::bytes(b"the_sun_exploded"),
            cbor::uint(0),
            cbor::bytes(&[]),
        ]),
    ]);
    assert_eq!(
        Frame::decode(&invented),
        Err(FrameDecodeError::BadField { field: "code" })
    );

    // A real code filed under the wrong class is refused for the same reason:
    // the pair is the identity, and accepting a mismatched pair would let a peer
    // move a code into a class whose client behaviour it was never given.
    let wrong_class = cbor::array(&[
        cbor::uint(u64::from(FrameTag::Error as u16)),
        cbor::array(&[
            cbor::bytes(b"retry"),
            cbor::bytes(b"group_frozen"),
            cbor::uint(0),
            cbor::bytes(&[]),
        ]),
    ]);
    assert_eq!(
        Frame::decode(&wrong_class),
        Err(FrameDecodeError::BadField { field: "code" })
    );
}

#[test]
fn a_narrow_header_field_that_does_not_fit_is_refused_rather_than_wrapped() {
    // The three fields this build reads into something narrower than a `u64`:
    // the two version fields and the key package count. A decoder that truncated
    // instead of refusing would read version 65537 as version 1 and answer a
    // client that speaks a protocol this build has never seen. The version check
    // itself cannot catch that, because by then the value has already been made
    // to fit.
    let version_is_not_a_number = cbor::array(&[
        cbor::uint(u64::from(FrameTag::Connect as u16)),
        cbor::array(&[cbor::bytes(b"one"), cbor::array(&[]), cbor::uint(0)]),
    ]);
    let error = Frame::decode(&version_is_not_a_number).expect_err("refused");
    assert!(matches!(error, FrameDecodeError::Cbor(_)));
    assert_eq!(error.code(), ErrorCode::NoncanonicalCbor);

    let version_too_wide = cbor::array(&[
        cbor::uint(u64::from(FrameTag::ConnectAck as u16)),
        cbor::array(&[cbor::uint(70_000), cbor::uint(1), cbor::uint(0)]),
    ]);
    assert!(matches!(
        Frame::decode(&version_too_wide),
        Err(FrameDecodeError::Cbor(_))
    ));

    // `AuthAck` carries five fields as of the build-identity change: the count,
    // the write mode, the digest, the access-set mode and the minimum
    // encryption. The two narrow numbers are asserted separately, and the array
    // is the full five in both cases on purpose. A short array is refused by the
    // length check before any field is read, so a two-element frame here would
    // pass this test while proving nothing about the field it names.
    let count_too_wide = cbor::array(&[
        cbor::uint(u64::from(FrameTag::AuthAck as u16)),
        cbor::array(&[
            cbor::uint(4_294_967_296),
            cbor::uint(0),
            cbor::bytes(b"sha256:0"),
            cbor::uint(1),
            cbor::uint(1),
        ]),
    ]);
    assert!(matches!(
        Frame::decode(&count_too_wide),
        Err(FrameDecodeError::Cbor(_))
    ));

    let write_mode_too_wide = cbor::array(&[
        cbor::uint(u64::from(FrameTag::AuthAck as u16)),
        cbor::array(&[
            cbor::uint(97),
            cbor::uint(256),
            cbor::bytes(b"sha256:0"),
            cbor::uint(1),
            cbor::uint(1),
        ]),
    ]);
    assert!(matches!(
        Frame::decode(&write_mode_too_wide),
        Err(FrameDecodeError::Cbor(_))
    ));
}

#[test]
fn every_decode_failure_maps_to_the_code_the_relay_answers_with() {
    // A client that got a closed socket and no frame could not tell a protocol
    // error from a network one, so every decode failure has a code. The mapping
    // is asserted per variant, and then again through a frame that actually
    // produces each one, so a variant that is unreachable in practice would show
    // as a missing case rather than as a passing table.
    let mapping = [
        (FrameDecodeError::TooLarge(1), ErrorCode::EnvelopeTooLarge),
        (
            FrameDecodeError::Cbor(wealdrelay::cbor::CborError::NonCanonicalInteger),
            ErrorCode::NoncanonicalCbor,
        ),
        (FrameDecodeError::UnknownTag(99), ErrorCode::MalformedHeader),
        (
            FrameDecodeError::BadField { field: "code" },
            ErrorCode::MalformedHeader,
        ),
        (
            FrameDecodeError::UnsupportedVersion(2),
            ErrorCode::ProtocolUnsupported,
        ),
    ];
    for (error, code) in &mapping {
        assert_eq!(error.code(), *code);
        // The code the relay answers with must itself be a registered code, or
        // the answer to a malformed frame would be an unregistered error.
        assert!(ErrorCode::ALL.contains(code));
    }

    // The messages reach an operator log, so none may be empty and no two may be
    // the same: two different wire mistakes that read identically are two
    // mistakes nobody can tell apart at three in the morning.
    let messages: Vec<String> = mapping.iter().map(|(error, _)| error.to_string()).collect();
    assert!(messages.iter().all(|message| !message.is_empty()));
    let unique: BTreeSet<&String> = messages.iter().collect();
    assert_eq!(unique.len(), messages.len());

    // And each one produced by a real frame rather than constructed by hand.
    let produced: Vec<FrameDecodeError> = vec![
        Frame::decode(&vec![0u8; MAX_FRAME_BYTES + 1]).unwrap_err(),
        Frame::decode(&[0x18, 0x01]).unwrap_err(),
        Frame::decode(&cbor::array(&[cbor::uint(99), cbor::array(&[])])).unwrap_err(),
        Frame::decode(&cbor::array(&[
            cbor::uint(u64::from(FrameTag::Error as u16)),
            cbor::array(&[
                cbor::bytes(b"retry"),
                cbor::bytes(b"nope"),
                cbor::uint(0),
                cbor::bytes(&[]),
            ]),
        ]))
        .unwrap_err(),
        Frame::decode(
            &Frame::Connect {
                version: 7,
                groups: Vec::new(),
                sent_at: 0,
            }
            .encode(),
        )
        .unwrap_err(),
    ];
    let produced_codes: Vec<ErrorCode> = produced.iter().map(FrameDecodeError::code).collect();
    assert_eq!(
        produced_codes,
        vec![
            ErrorCode::EnvelopeTooLarge,
            ErrorCode::NoncanonicalCbor,
            ErrorCode::MalformedHeader,
            ErrorCode::MalformedHeader,
            ErrorCode::ProtocolUnsupported,
        ]
    );
}

#[test]
fn an_empty_or_truncated_frame_is_refused_rather_than_read_as_a_default() {
    // The degenerate inputs a network hands a server first: nothing at all, and
    // half of something. Neither may decode into a frame with zeroed fields.
    assert!(matches!(Frame::decode(&[]), Err(FrameDecodeError::Cbor(_))));
    // Every variant, cut at every byte. A frame is read field by field, so this
    // exercises the failure path of every field of every frame: the property is
    // that a partial frame is always an error and never a frame whose later
    // fields defaulted to zero, an empty group set, or an unlimited sequence
    // number. Those defaults would be a peer's message silently rewritten.
    for frame in every_variant() {
        let whole = frame.encode();
        for cut in 0..whole.len() {
            assert!(
                Frame::decode(&whole[..cut]).is_err(),
                "{:?} cut at {cut} bytes decoded",
                frame.tag()
            );
        }
    }
}

#[test]
fn a_frames_queue_cost_is_its_payload_plus_a_header_allowance() {
    // What `ws::SEND_QUEUE_BYTE_BUDGET` is accounted in. Deliberately an estimate
    // rather than `encode().len()`, since encoding every frame twice to measure it
    // would add the cost the budget exists to bound. So what is held here is the
    // property the budget needs: it tracks the payload, it is never zero, and it is
    // close enough to the encoded size to be a memory bound.
    let payload = vec![0u8; 4096];
    let carriers = [
        Frame::Push {
            envelope: payload.clone(),
        },
        Frame::Send {
            envelope: payload.clone(),
        },
        Frame::Handshake {
            group: vec![0x11; 32],
            seq: 3,
            message: payload.clone(),
        },
        Frame::Recon {
            group: vec![0x11; 32],
            payload: payload.clone(),
        },
        Frame::Access {
            body: payload.clone(),
        },
        Frame::Wrap {
            body: payload.clone(),
        },
        Frame::Join {
            body: payload.clone(),
        },
        Frame::Blob {
            payload: payload.clone(),
        },
        Frame::Connect {
            version: 1,
            groups: vec![vec![0x11; 32], vec![0x22; 32]],
            sent_at: 0,
        },
    ];
    for frame in carriers {
        let cost = frame.queued_bytes();
        let encoded = frame.encode().len();
        assert!(
            cost >= encoded,
            "{:?} is {encoded} encoded but costs only {cost}",
            frame.tag()
        );
        assert!(
            cost < encoded + 1024,
            "{:?} costs {cost} against {encoded} encoded, which is not an estimate",
            frame.tag()
        );
    }

    // A frame with no payload still costs something: a queue that admitted an
    // unlimited number of free frames would not be bounded in bytes at all.
    let bare = Frame::SubAck {
        group: vec![0x11; 32],
        head_seq: 9,
    };
    assert!(bare.queued_bytes() >= bare.encode().len());
}
