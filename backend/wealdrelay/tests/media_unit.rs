// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Media, without a database, a bucket or a socket: the key shapes, the local
//! presign token, and the constants `specs/backend/relay/media.md` fixes.
//!
//! Tier 1. Everything here is a pure function, and each one is the kind that is
//! wrong in exactly one direction: a key builder that admits a separator is a path
//! traversal, and a token verifier that ignores an expiry is a presigned URL that
//! never stops working.

use wealdrelay::media::{
    self, BLOB_MAX_BYTES, MULTIPART_PART_SIZE, PRESIGN_TTL_SECONDS, SINGLE_PART_MAX_BYTES,
};

// MARK: The numbers media.md fixes

/// Read back as numbers rather than trusted as names. `media.md` says "Above 64
/// MB the relay issues a multipart upload session", the blob ceiling is 2 GiB,
/// and a presigned URL is "valid for 15 minutes"; a constant that drifted from
/// one of those sentences would change the product without changing a test.
#[test]
fn the_constants_are_the_ones_the_spec_names() {
    assert_eq!(SINGLE_PART_MAX_BYTES, 64 * 1024 * 1024);
    assert_eq!(MULTIPART_PART_SIZE, 64 * 1024 * 1024);
    assert_eq!(BLOB_MAX_BYTES, 2 * 1024 * 1024 * 1024);
    assert_eq!(PRESIGN_TTL_SECONDS, 900);
    assert_eq!(media::gc::UNCLAIMED_GRACE_SECONDS, 24 * 60 * 60);
    assert_eq!(media::gc::MEDIA_GRACE_FLOOR_DAYS, 30);
    const {
        assert!(
            BLOB_MAX_BYTES > SINGLE_PART_MAX_BYTES,
            "a blob at the ceiling has to be reachable through the multipart path"
        );
    }
}

/// The relay's default posture, `media.md`'s "50 blob requests per minute, 5 GB
/// per device per day".
#[test]
fn the_default_download_budget_is_the_published_one() {
    let limiter = media::default_rate_limiter();
    assert_eq!(limiter.requests_per_minute, 50);
    assert_eq!(limiter.bytes_per_day, 5 * 1_000_000_000);
    assert!(format!("{limiter:?}").contains("RateLimiter"));

    // "both raisable per instance": the constructor is the lever, so an operator
    // raising one does not have to be given a different type.
    let raised = media::RateLimiter::new(500, 50 * 1024 * 1024 * 1024);
    assert_eq!(raised.requests_per_minute, 500);
    assert_eq!(raised.bytes_per_day, 50 * 1024 * 1024 * 1024);
    assert_eq!(media::RateLimiter::default().requests_per_minute, 0);
}

// MARK: Key shapes

#[test]
fn hex_is_lower_case_and_fixed_width() {
    assert_eq!(media::hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    assert_eq!(media::hex(&[]), "");
    assert_eq!(media::hex(&[0xde; 32]).len(), 64);
}

/// A part key is `_multipart/<session>/part-<n>`. `_multipart` cannot collide
/// with a real workspace id, which is always `ws:<hostname>`, and the whole key
/// is rejected rather than sanitised when a component could escape the key space.
#[test]
fn a_part_key_is_built_only_from_components_that_cannot_escape() {
    let key = media::part_key("aabb", "7").expect("a well formed part key");
    assert_eq!(key.path(), "_multipart/aabb/part-7");

    // Every refusal `BlobKey::new` makes, reached through this builder: an empty
    // session, a separator in either direction, and a parent-directory alias
    // smuggled in through the part label.
    assert!(media::part_key("", "1").is_none());
    assert!(media::part_key("../etc", "1").is_none());
    assert!(media::part_key("a/b", "1").is_none());
    assert!(media::part_key("a\\b", "1").is_none());
    assert!(media::part_key(".", "1").is_none());
    assert!(media::part_key("aabb", "../1").is_none());
    assert!(media::part_key("aabb", "1/2").is_none());
}

// MARK: The local presigned-URL token
//
// Reachable only when storage is the filesystem backend, which is a local
// development configuration and never a deployed one. It stands in for
// AWS SigV4 on a laptop, so it has to hold the two properties SigV4 holds: a
// token for one object cannot be replayed against another, and an expired token
// is refused whatever its signature.

const SECRET: [u8; 32] = [0x5a; 32];
const OTHER_SECRET: [u8; 32] = [0x5b; 32];

fn token(sig: String, exp: u64) -> media::http::Token {
    media::http::Token { exp, sig }
}

#[test]
fn a_token_verifies_only_against_the_inputs_it_was_signed_over() {
    let signature = media::http::sign(&SECRET, "GET", "ws/group/hash", 1_000);
    assert_eq!(signature.len(), 64, "a BLAKE3 digest in hex");
    assert!(media::http::verify(
        &SECRET,
        "GET",
        "ws/group/hash",
        &token(signature.clone(), 1_000),
        999
    ));
    // Exactly at the expiry is still valid: the token is good "until" its second,
    // which is what a client refreshing on the boundary depends on.
    assert!(media::http::verify(
        &SECRET,
        "GET",
        "ws/group/hash",
        &token(signature.clone(), 1_000),
        1_000
    ));
    // One second later it is not, before the signature is even looked at.
    assert!(!media::http::verify(
        &SECRET,
        "GET",
        "ws/group/hash",
        &token(signature.clone(), 1_000),
        1_001
    ));
    // A GET token is not a PUT token. Without this, a leaked download URL would
    // be an upload URL for the same object.
    assert!(!media::http::verify(
        &SECRET,
        "PUT",
        "ws/group/hash",
        &token(signature.clone(), 1_000),
        999
    ));
    // Nor is it a token for the neighbouring object.
    assert!(!media::http::verify(
        &SECRET,
        "GET",
        "ws/group/other",
        &token(signature.clone(), 1_000),
        999
    ));
    // Nor for a different expiry, which is the field a holder can edit freely.
    assert!(!media::http::verify(
        &SECRET,
        "GET",
        "ws/group/hash",
        &token(signature.clone(), 2_000),
        999
    ));
    // Nor under another relay's process secret.
    assert!(!media::http::verify(
        &OTHER_SECRET,
        "GET",
        "ws/group/hash",
        &token(signature.clone(), 1_000),
        999
    ));
    // Nor with the signature rewritten.
    assert!(!media::http::verify(
        &SECRET,
        "GET",
        "ws/group/hash",
        &token("f".repeat(64), 1_000),
        999
    ));

    let parsed = token(signature, 1_000);
    assert!(format!("{parsed:?}").contains("Token"));
    assert_eq!(parsed.clone().sig.len(), 64);
}

#[test]
fn two_methods_over_one_key_never_produce_the_same_token() {
    let get = media::http::sign(&SECRET, "GET", "ws/group/hash", 5);
    let put = media::http::sign(&SECRET, "PUT", "ws/group/hash", 5);
    assert_ne!(get, put);
    // And the separator is real: "GET" over "x/y/z" must not collide with "GE"
    // over "Tx/y/z", which is the shape of every length-extension mistake a
    // concatenated MAC input makes.
    assert_ne!(
        media::http::sign(&SECRET, "GET", "x/y/z", 5),
        media::http::sign(&SECRET, "GE", "Tx/y/z", 5)
    );
}

/// A stored control record and an incoming one are the same record only when all
/// three of the fields that identify it agree.
///
/// The truth table matters rather than the happy case. `apply_control` answers a
/// match with a silent acceptance and a mismatch by freezing the group's garbage
/// collection until a member resolves it, so an over-eager match would let a second
/// claim quietly replace the record that decides who governs a group's retention,
/// and an over-eager mismatch would freeze a workspace every time a client retried
/// after a dropped socket.
#[test]
fn a_control_matches_only_when_every_field_that_identifies_it_agrees() {
    let record = wealdrelay::media::wire::RetentionControl {
        group: vec![0x01; 32],
        epoch: 1,
        verifier: vec![0x02; 32],
        prev_control_hash: Some(vec![0x03; 32]),
        sig: vec![0x04; 64],
    };
    let same = |verifier: &[u8], prev: Option<&[u8]>, sig: &[u8]| {
        wealdrelay::media::retention::is_the_same_control(verifier, prev, sig, &record)
    };

    assert!(
        same(&record.verifier, Some(&[0x03; 32]), &record.sig),
        "the identical record is the same record"
    );
    assert!(
        !same(&[0xff; 32], Some(&[0x03; 32]), &record.sig),
        "a different verifier is a different record"
    );
    assert!(
        !same(&record.verifier, Some(&[0xff; 32]), &record.sig),
        "the same verifier down a different chain is a different record"
    );
    assert!(
        !same(&record.verifier, None, &record.sig),
        "a record naming no predecessor is a different record"
    );
    // The one that is unreachable through `apply_control` and is the reason this
    // is a function: `access::verify` is not the strict verifier, so a malleated
    // signature over identical fields can verify while differing byte for byte.
    //
    // This is also the case a client must never produce by accident. CryptoKit
    // randomises Ed25519, so a client that re-signed a record it had already
    // published would land here and freeze its own group; the client therefore
    // stores the signed record and retransmits those exact bytes. A record that
    // reaches this branch is one nobody honest wrote.
    assert!(
        !same(&record.verifier, Some(&[0x03; 32]), &[0xff; 64]),
        "a second signature over the same fields is a different record"
    );
}

/// A stored policy and an incoming one are the same policy only when every term
/// they express agrees.
///
/// The two answers are opposite and both are wrong in the other's place. Read as
/// the same, a genuine tightening would be accepted quietly and never applied, so
/// a workspace would believe it had shortened its retention and would not have.
/// Read as different, an ordinary retransmission is refused as a version error,
/// which is what happens whenever a client publishes a policy and is then refused
/// further down the same exchange: it republishes on its next attempt, and an
/// operator reading `malformed_header` goes looking for a malformed record that
/// does not exist.
///
/// Compared on the terms rather than on the signatures, unlike the control chain.
/// Nothing is chained to a policy by digest, so two signings of one policy are the
/// same permission and there is no hash for them to disagree about.
#[test]
fn a_policy_matches_only_when_every_term_it_expresses_agrees() {
    let active = wealdrelay::media::retention::ActivePolicy {
        version: 2,
        media_after_days: 180,
        text_after_days: 0,
        not_before_secs: 1_800_000_000,
    };
    let record = wealdrelay::media::wire::RetentionPolicy {
        group: vec![0x01; 32],
        version: 2,
        media_after_days: 180,
        text_after_days: 0,
        not_before: 1_800_000_000,
        authorizers: vec![vec![0x02; 32]],
        signatures: Vec::new(),
    };
    assert!(
        active.is_the_same_policy(&record),
        "the identical policy is the same policy"
    );

    // Every term, one at a time. A version is a different policy in the chain; a
    // media window is the retention rule itself; a text window is the other half
    // of it; and a `not_before` is when the whole thing becomes permission, which
    // is the field a solo owner's seven-day floor is measured against.
    for (what, changed) in [
        (
            "a later version",
            wealdrelay::media::wire::RetentionPolicy {
                version: 3,
                ..record.clone()
            },
        ),
        (
            "a different media window",
            wealdrelay::media::wire::RetentionPolicy {
                media_after_days: 365,
                ..record.clone()
            },
        ),
        (
            "a different text window",
            wealdrelay::media::wire::RetentionPolicy {
                text_after_days: 30,
                ..record.clone()
            },
        ),
        (
            "a different not_before",
            wealdrelay::media::wire::RetentionPolicy {
                not_before: 1_800_000_001,
                ..record.clone()
            },
        ),
    ] {
        assert!(
            !active.is_the_same_policy(&changed),
            "{what} is a different policy"
        );
    }

    // The signatures are not part of it, which is the difference from
    // `is_the_same_control` and is deliberate.
    let resigned = wealdrelay::media::wire::RetentionPolicy {
        signatures: vec![wealdrelay::media::wire::Signature {
            key: vec![0x02; 32],
            sig: vec![0x03; 64],
        }],
        ..record.clone()
    };
    assert!(
        active.is_the_same_policy(&resigned),
        "a second signing of one policy is the same permission"
    );
}
