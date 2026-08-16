// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The access set's rules, as rules: no database, no socket, no relay.
//!
//! Step 6 from `specs/backend/build/phases-relay.md`, tracing to
//! `specs/backend/relay/wire.md`. Everything `access::judge` decides is decided from
//! four arguments and returns a verdict, so every branch of every rule is reachable
//! from a table of inputs. The half that needs Postgres is in `tests/access_store.rs`
//! and the half that needs sockets is in `tests/access_socket.rs`.
//!
//! Why the split is worth the three files: the rules are the part with the security
//! content, and a rule that could only be reached by standing up a relay and walking
//! a handshake is a rule nobody covers all of. Twenty error variants are twenty
//! cases here and would be twenty integration tests there.

use ed25519_dalek::{Signer as _, SigningKey};
use wealdrelay::access::{
    self, judge, quorum_message, AccessError, AccessSet, Prior, Probation, QuorumSignature,
    RecoveryQuorum, SignedAs, MAX_ENTRIES,
};
use wealdrelay::frame::ErrorCode;

// MARK: Building sets

/// A fixed salt. Fixed rather than random so a failure reproduces and so the entry
/// hashes in a failure message are the same on every machine.
const SALT: &[u8] = b"salt for the pure access-set tests";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pk(signer: &SigningKey) -> Vec<u8> {
    signer.verifying_key().to_bytes().to_vec()
}

fn hash_of(signer: &SigningKey) -> Vec<u8> {
    access::entry_hash(&pk(signer), SALT)
}

fn sorted(mut items: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    items.sort();
    items.dedup();
    items
}

/// A set whose entries cover every principal it names, which is the invariant
/// `principals_are_entries` checks and the one every valid set satisfies.
fn build(
    version: u64,
    prev_hash: Vec<u8>,
    members: &[&SigningKey],
    authorizers: &[&SigningKey],
    recovery: &[&SigningKey],
) -> AccessSet {
    let mut entries: Vec<Vec<u8>> = members.iter().map(|k| hash_of(k)).collect();
    entries.extend(authorizers.iter().map(|k| hash_of(k)));
    entries.extend(recovery.iter().map(|k| hash_of(k)));
    AccessSet {
        workspace: vec![0x77; 32],
        version,
        prev_hash,
        issued_at: 1,
        entries: sorted(entries),
        authorizers: sorted(authorizers.iter().map(|k| pk(k)).collect()),
        recovery: sorted(recovery.iter().map(|k| pk(k)).collect()),
        quorum: None,
        pending: Vec::new(),
        signer: vec![0u8; 32],
        sig: vec![0u8; 64],
    }
}

fn sign(mut set: AccessSet, signer: &SigningKey) -> AccessSet {
    set.signer = pk(signer);
    set.sig = signer.sign(&set.digest_input()).to_bytes().to_vec();
    set
}

/// The prior state a published set becomes once it is accepted.
fn prior_of(set: &AccessSet) -> Prior {
    Prior {
        workspace: set.workspace.clone(),
        version: set.version,
        digest: set.digest().to_vec(),
        entries: set.entries.clone(),
        authorizers: set.authorizers.clone(),
        recovery: set.recovery.clone(),
        // The stored quorum never carries signatures: they confirm one transition
        // and are not part of the state that transition produced.
        quorum: set.quorum.as_ref().map(|quorum| RecoveryQuorum {
            threshold: quorum.threshold,
            keys: quorum.keys.clone(),
            sigs: Vec::new(),
        }),
    }
}

/// The genesis every case in this file starts from: one device, which is the sole
/// authorizer, and one recovery principal.
fn genesis() -> AccessSet {
    sign(
        build(0, vec![0u8; 32], &[], &[&key(1)], &[&key(0x3f)]),
        &key(1),
    )
}

fn judged(
    candidate: &AccessSet,
    prior: &Prior,
) -> Result<(SignedAs, access::Effects), AccessError> {
    judge(candidate, Some(prior), SALT, &[], false)
}

// MARK: Encoding

#[test]
fn a_set_round_trips_through_its_own_encoding() {
    let set = genesis();
    let bytes = set.encode();
    assert_eq!(AccessSet::decode(&bytes).unwrap(), set);
    // And the digest is over the encoding without the signature, so signing does not
    // change the identity of the thing signed.
    let mut unsigned = set.clone();
    unsigned.sig = vec![0xff; 64];
    assert_eq!(unsigned.digest(), set.digest());
}

#[test]
fn a_set_with_a_quorum_round_trips_and_carries_its_signatures() {
    let mut set = genesis();
    set.quorum = Some(RecoveryQuorum {
        threshold: 2,
        keys: sorted(vec![pk(&key(0x81)), pk(&key(0x82))]),
        sigs: vec![QuorumSignature {
            key: pk(&key(0x81)),
            sig: key(0x81).sign(b"anything").to_bytes().to_vec(),
        }],
    });
    let set = sign(set, &key(1));
    let decoded = AccessSet::decode(&set.encode()).unwrap();
    assert_eq!(decoded, set);
    // The digest omits the signatures, which is what stops a confirmation from
    // being a signature over the object containing it.
    let mut without = set.clone();
    without.quorum.as_mut().unwrap().sigs.clear();
    assert_eq!(without.digest(), set.digest());
}

#[test]
fn every_malformed_encoding_is_refused_on_its_own_ground() {
    // An empty body, a short array, a wrong-width hash, and trailing bytes. Each is
    // a `reject` rather than a `denied`, because resending the same bytes cannot
    // help.
    for bad in [
        Vec::new(),
        wealdrelay::cbor::array(&[wealdrelay::cbor::uint(1)]),
        {
            let mut set = genesis();
            set.workspace = vec![0x77; 31];
            set.encode()
        },
        {
            let mut bytes = genesis().encode();
            bytes.push(0x00);
            bytes
        },
        // A simple value that is not `null` where the optional quorum goes. `false`
        // and a float share the major type with `null`, and a decoder that treated
        // any simple value as absence would accept a set with a quorum field nobody
        // wrote.
        replace_quorum_null(&[0xf4]),
        replace_quorum_null(&[0xfa, 0x00, 0x00, 0x00, 0x00]),
    ] {
        let error = AccessSet::decode(&bad).expect_err("must refuse");
        assert!(
            matches!(error, AccessError::Encoding(_)),
            "expected an encoding refusal, got {error:?}"
        );
        assert_eq!(error.code(), ErrorCode::MalformedHeader);
    }
}

#[test]
fn a_list_longer_than_the_bound_is_refused_on_the_count() {
    // Refused before the allocation, so a publication naming a million entries costs
    // the relay a count rather than a megabyte.
    let mut set = genesis();
    set.entries = (0..=MAX_ENTRIES)
        .map(|index| {
            let mut entry = vec![0u8; 32];
            entry[..8].copy_from_slice(&(index as u64).to_be_bytes());
            entry
        })
        .collect();
    let error = AccessSet::decode(&set.encode()).expect_err("must refuse");
    assert!(matches!(error, AccessError::TooManyEntries("list")));

    // The same bound on the quorum's signature list, which is a separate list with
    // its own count.
    let mut set = genesis();
    set.quorum = Some(RecoveryQuorum {
        threshold: 1,
        keys: vec![pk(&key(0x81))],
        sigs: (0..=MAX_ENTRIES)
            .map(|_| QuorumSignature {
                key: pk(&key(0x81)),
                sig: vec![0u8; 64],
            })
            .collect(),
    });
    let error = AccessSet::decode(&set.encode()).expect_err("must refuse");
    assert!(matches!(
        error,
        AccessError::TooManyEntries("quorum signatures")
    ));
}

/// The same bytes as a genesis set, with the `null` in the quorum slot replaced.
///
/// Found by position rather than by re-encoding, because the point is to produce
/// bytes the encoder would never emit.
fn replace_quorum_null(with: &[u8]) -> Vec<u8> {
    let bytes = genesis().encode();
    let at = bytes
        .iter()
        .position(|byte| *byte == 0xf6)
        .expect("the encoded set carries a null quorum");
    let mut out = bytes[..at].to_vec();
    out.extend_from_slice(with);
    out.extend_from_slice(&bytes[at + 1..]);
    out
}

// MARK: Shape

#[test]
fn an_empty_required_list_is_refused_and_pending_may_be_empty() {
    for (name, mutate) in [
        (
            "entries",
            (|set: &mut AccessSet| set.entries.clear()) as fn(&mut AccessSet),
        ),
        ("authorizers", |set: &mut AccessSet| set.authorizers.clear()),
        ("recovery", |set: &mut AccessSet| set.recovery.clear()),
    ] {
        let mut set = genesis();
        mutate(&mut set);
        assert_eq!(
            set.check_shape().expect_err("must refuse"),
            AccessError::EmptyList(name)
        );
    }
    // Pending is the one list that may be empty: an ordinary publication pins
    // nothing.
    assert!(genesis().check_shape().is_ok());
}

#[test]
fn an_unsorted_or_repeated_list_is_refused() {
    let mut set = genesis();
    set.entries = vec![vec![0x02; 32], vec![0x01; 32]];
    assert_eq!(
        set.check_shape().expect_err("must refuse"),
        AccessError::Unsorted("entries")
    );
    let mut set = genesis();
    set.entries = vec![vec![0x01; 32], vec![0x01; 32]];
    assert_eq!(
        set.check_shape().expect_err("must refuse"),
        AccessError::Unsorted("entries")
    );
}

#[test]
fn a_list_over_the_bound_is_refused_by_the_shape_check_too() {
    // `check_shape` bounds the lists as well as the decoder, because a set can be
    // constructed in process as well as decoded from a frame.
    let mut set = genesis();
    set.pending = (0..=MAX_ENTRIES).map(|_| vec![0x01; 32]).collect();
    assert_eq!(
        set.check_shape().expect_err("must refuse"),
        AccessError::TooManyEntries("pending")
    );
}

#[test]
fn a_malformed_quorum_is_refused_as_a_quorum_and_not_as_a_list() {
    // The distinction matters to an operator reading the log: "the quorum is
    // malformed" names the field they configured.
    let mut set = genesis();
    set.quorum = Some(RecoveryQuorum {
        threshold: 1,
        keys: Vec::new(),
        sigs: Vec::new(),
    });
    assert_eq!(
        set.check_shape().expect_err("must refuse"),
        AccessError::Quorum("keys must be unique, sorted and non-empty")
    );

    for threshold in [0u8, 3u8] {
        let mut set = genesis();
        set.quorum = Some(RecoveryQuorum {
            threshold,
            keys: sorted(vec![pk(&key(0x81)), pk(&key(0x82))]),
            sigs: Vec::new(),
        });
        assert_eq!(
            set.check_shape().expect_err("must refuse"),
            AccessError::Quorum("threshold must be between 1 and the key count")
        );
    }

    // And a well-formed one passes, so the check is not simply refusing quorums.
    let mut set = genesis();
    set.quorum = Some(RecoveryQuorum {
        threshold: 2,
        keys: sorted(vec![pk(&key(0x81)), pk(&key(0x82))]),
        sigs: Vec::new(),
    });
    assert!(set.check_shape().is_ok());
}

#[test]
fn a_principal_that_is_not_an_entry_is_refused() {
    // The one liveness invariant the relay can verify without the roster: an
    // authorizer who cannot connect cannot use the authority the set grants them.
    let mut set = genesis();
    set.authorizers = sorted(vec![pk(&key(1)), pk(&key(9))]);
    assert_eq!(
        set.principals_are_entries(SALT).expect_err("must refuse"),
        AccessError::PrincipalNotAnEntry
    );
    assert!(genesis().principals_are_entries(SALT).is_ok());
}

// MARK: Signatures

#[test]
fn a_signature_verifies_only_over_the_bytes_that_were_signed() {
    let set = genesis();
    assert!(set.signature_verifies());
    // One byte of the signed content changed, and the signature no longer stands.
    let mut tampered = set.clone();
    tampered.issued_at += 1;
    assert!(!tampered.signature_verifies());
    // A signature by the wrong key over the right bytes.
    let mut wrong = set.clone();
    wrong.sig = key(2).sign(&set.digest_input()).to_bytes().to_vec();
    assert!(!wrong.signature_verifies());
}

#[test]
fn every_wrong_shaped_input_to_verify_is_one_answer_and_not_a_type() {
    let signer = key(1);
    let message = b"a message";
    let signature = signer.sign(message).to_bytes().to_vec();
    assert!(access::verify(&pk(&signer), message, &signature));
    // A short key, a short signature, a key that is not a point on the curve, and a
    // valid signature over other bytes.
    assert!(!access::verify(&[0u8; 31], message, &signature));
    assert!(!access::verify(&pk(&signer), message, &[0u8; 63]));
    // Thirty-two bytes that are not a point on the curve at all. `0x02` repeated is
    // one such encoding, which is a different refusal from a well-formed key with a
    // wrong signature and is answered the same way on purpose.
    assert!(!access::verify(&[0x02; 32], message, &signature));
    assert!(!access::verify(&pk(&signer), b"other bytes", &signature));
}

#[test]
fn a_quorum_confirms_only_with_distinct_configured_keys_over_this_transition() {
    let configured = RecoveryQuorum {
        threshold: 2,
        keys: sorted(vec![pk(&key(0x81)), pk(&key(0x82))]),
        sigs: Vec::new(),
    };
    let replacement = hash_of(&key(7));
    let base = genesis();

    // No quorum carried at all.
    assert!(!base.quorum_confirms(&configured, &replacement));

    let confirm = |signers: Vec<(u8, &[u8])>| {
        let mut set = base.clone();
        let digest = {
            let mut probe = base.clone();
            probe.quorum = Some(RecoveryQuorum {
                threshold: configured.threshold,
                keys: configured.keys.clone(),
                sigs: Vec::new(),
            });
            probe.digest()
        };
        let message = quorum_message(&digest, &replacement);
        set.quorum = Some(RecoveryQuorum {
            threshold: configured.threshold,
            keys: configured.keys.clone(),
            sigs: signers
                .into_iter()
                .map(|(seed, over)| QuorumSignature {
                    key: pk(&key(seed)),
                    sig: key(seed)
                        .sign(if over.is_empty() { &message } else { over })
                        .to_bytes()
                        .to_vec(),
                })
                .collect(),
        });
        set.quorum_confirms(&configured, &replacement)
    };

    // An empty signature list.
    let mut empty = base.clone();
    empty.quorum = Some(RecoveryQuorum {
        threshold: configured.threshold,
        keys: configured.keys.clone(),
        sigs: Vec::new(),
    });
    assert!(!empty.quorum_confirms(&configured, &replacement));

    // One key is not two, whatever it signs.
    assert!(!confirm(vec![(0x81, b"")]));
    // The same key twice is still one key: `m` copies of one signature is not a
    // quorum, and this is the case a naive count would accept.
    assert!(!confirm(vec![(0x81, b""), (0x81, b"")]));
    // A key nobody configured does not count.
    assert!(!confirm(vec![(0x81, b""), (0x99, b"")]));
    // A signature over something other than this transition does not count.
    assert!(!confirm(vec![(0x81, b""), (0x82, b"another transition")]));
    // Two distinct configured keys over this transition do.
    assert!(confirm(vec![(0x81, b""), (0x82, b"")]));
}

// MARK: Genesis

#[test]
fn a_genesis_set_is_accepted_and_names_itself() {
    let (signed_as, effects) = judge(&genesis(), None, SALT, &[], false).unwrap();
    assert_eq!(signed_as, SignedAs::Authorizer);
    assert_eq!(signed_as.label(), "authorizer");
    assert!(effects.removed.is_empty());
    assert!(effects.opens_probation.is_none());
    assert!(effects.clears_probation.is_empty());
}

#[test]
fn every_way_a_genesis_set_can_be_wrong_is_refused_on_its_own_ground() {
    let cases: Vec<(AccessSet, AccessError)> = vec![
        (
            {
                let mut set = genesis();
                set.version = 1;
                sign(set, &key(1))
            },
            AccessError::VersionNotNext {
                expected: 0,
                got: 1,
            },
        ),
        (
            {
                let mut set = genesis();
                set.prev_hash = vec![0x01; 32];
                sign(set, &key(1))
            },
            AccessError::PrevHashMismatch,
        ),
        (
            // Signed by a key the set does not name as an authorizer, which at
            // genesis is the only membership test there is.
            {
                let set = build(0, vec![0u8; 32], &[&key(2)], &[&key(1)], &[&key(0x3f)]);
                sign(set, &key(2))
            },
            AccessError::SignerNotPermitted,
        ),
        (
            {
                let mut set = genesis();
                set.sig = vec![0u8; 64];
                set
            },
            AccessError::BadSignature,
        ),
        (
            {
                let mut set = genesis();
                set.pending = vec![hash_of(&key(0x3f))];
                sign(set, &key(1))
            },
            AccessError::RotationShape("name pending entries"),
        ),
    ];
    for (candidate, expected) in cases {
        assert_eq!(
            judge(&candidate, None, SALT, &[], false).expect_err("must refuse"),
            expected
        );
    }
}

// MARK: The chain

#[test]
fn a_publication_must_follow_the_accepted_head() {
    let prior = prior_of(&genesis());
    for (version, expected) in [(0u64, 1u64), (2, 1), (u64::MAX, 1)] {
        let candidate = sign(
            build(
                version,
                prior.digest.clone(),
                &[],
                &[&key(1)],
                &[&key(0x3f)],
            ),
            &key(1),
        );
        assert_eq!(
            judged(&candidate, &prior).expect_err("must refuse"),
            AccessError::VersionNotNext {
                expected,
                got: version
            }
        );
    }
    let candidate = sign(
        build(1, vec![0x11; 32], &[], &[&key(1)], &[&key(0x3f)]),
        &key(1),
    );
    assert_eq!(
        judged(&candidate, &prior).expect_err("must refuse"),
        AccessError::PrevHashMismatch
    );
}

/// A well formed, correctly chained, correctly signed successor that names
/// another workspace is refused. Without this the same authorizer key in two
/// workspaces on one relay could move a set from one chain into the other.
#[test]
fn a_correctly_chained_set_naming_another_workspace_is_refused() {
    let prior = prior_of(&genesis());
    let mut candidate = build(1, prior.digest.clone(), &[], &[&key(1)], &[&key(0x3f)]);
    candidate.workspace = vec![0x88; 32];
    let candidate = sign(candidate, &key(1));
    assert_eq!(
        judged(&candidate, &prior).expect_err("must refuse"),
        AccessError::WorkspaceMismatch
    );
}

#[test]
fn only_a_prior_authorizer_or_recovery_principal_may_publish() {
    let prior = prior_of(&genesis());
    let candidate = sign(
        build(
            1,
            prior.digest.clone(),
            &[&key(5)],
            &[&key(1)],
            &[&key(0x3f)],
        ),
        &key(5),
    );
    assert_eq!(
        judged(&candidate, &prior).expect_err("must refuse"),
        AccessError::SignerNotPermitted
    );
    assert_eq!(
        AccessError::SignerNotPermitted.code(),
        ErrorCode::WriterNotInAccessSet
    );

    // A permitted signer whose signature does not stand is refused on the signature
    // and not on the membership, because the two are different remedies.
    let mut candidate = build(
        1,
        prior.digest.clone(),
        &[&key(5)],
        &[&key(1)],
        &[&key(0x3f)],
    );
    candidate.signer = pk(&key(1));
    candidate.sig = vec![0u8; 64];
    assert_eq!(
        judged(&candidate, &prior).expect_err("must refuse"),
        AccessError::BadSignature
    );
    assert_eq!(
        AccessError::BadSignature.code(),
        ErrorCode::NoncanonicalCbor
    );
}

// MARK: Ordinary publications

#[test]
fn an_ordinary_publication_adds_and_removes_and_reports_what_it_removed() {
    let first = genesis();
    let prior = prior_of(&first);
    // Add a second device.
    let second = sign(
        build(
            1,
            prior.digest.clone(),
            &[&key(5)],
            &[&key(1)],
            &[&key(0x3f)],
        ),
        &key(1),
    );
    let (signed_as, effects) = judged(&second, &prior).unwrap();
    assert_eq!(signed_as, SignedAs::Authorizer);
    assert!(effects.removed.is_empty());

    // Then remove it, and the removal is reported so its sockets can be closed.
    let prior = prior_of(&second);
    let third = sign(
        build(2, prior.digest.clone(), &[], &[&key(1)], &[&key(0x3f)]),
        &key(1),
    );
    let (_, effects) = judged(&third, &prior).unwrap();
    assert_eq!(effects.removed, vec![hash_of(&key(5))]);
}

#[test]
fn a_publication_that_would_strand_the_workspace_is_refused() {
    let prior = prior_of(&genesis());
    // No prior authorizer remains.
    let candidate = sign(
        build(1, prior.digest.clone(), &[], &[&key(6)], &[&key(0x3f)]),
        &key(1),
    );
    assert_eq!(
        judged(&candidate, &prior).expect_err("must refuse"),
        AccessError::WouldStrandAuthority("authorizer")
    );

    // No prior recovery principal remains.
    let candidate = sign(
        build(1, prior.digest.clone(), &[], &[&key(1)], &[&key(0x4f)]),
        &key(1),
    );
    assert_eq!(
        judged(&candidate, &prior).expect_err("must refuse"),
        AccessError::WouldStrandAuthority("recovery principal")
    );
}

#[test]
fn an_ordinary_publication_may_not_pin_removals() {
    // Pinned removals are the recovery rotation's mechanism. An authorizer removing
    // a device does it by publishing a set without that entry, so a `pending` list
    // here would be a second way to express one thing.
    let prior = prior_of(&genesis());
    let mut candidate = build(1, prior.digest.clone(), &[], &[&key(1)], &[&key(0x3f)]);
    candidate.pending = vec![hash_of(&key(9))];
    let candidate = sign(candidate, &key(1));
    assert_eq!(
        judged(&candidate, &prior).expect_err("must refuse"),
        AccessError::RotationShape("name pending entries")
    );
}

// MARK: The recovery rotation

/// The rotation every case here starts from: `0x3f` is replaced by `0x4f`, and the
/// replacement device `7` becomes an entry and an authorizer.
fn rotation(prior: &Prior, pending: Vec<Vec<u8>>) -> AccessSet {
    let mut set = build(
        prior.version + 1,
        prior.digest.clone(),
        &[],
        &[&key(1), &key(7)],
        &[&key(0x4f)],
    );
    // Every prior authorizer stays, and every prior recovery principal except the
    // one rotating: a rotation that dropped somebody else's phrase is a different
    // transition and its own test.
    set.authorizers = sorted(
        prior
            .authorizers
            .iter()
            .cloned()
            .chain([pk(&key(7))])
            .collect(),
    );
    set.recovery = sorted(
        prior
            .recovery
            .iter()
            .filter(|principal| *principal != &pk(&key(0x3f)))
            .cloned()
            .chain([pk(&key(0x4f))])
            .collect(),
    );
    set.quorum = prior.quorum.clone();
    // The prior members other than the rotating recovery principal stay.
    set.entries = sorted(
        prior
            .entries
            .iter()
            .filter(|entry| *entry != &hash_of(&key(0x3f)))
            .cloned()
            .chain([hash_of(&key(7)), hash_of(&key(0x4f))])
            .collect(),
    );
    set.pending = sorted(pending);
    sign(set, &key(0x3f))
}

#[test]
fn a_recovery_rotation_is_accepted_and_opens_a_probation() {
    let prior = prior_of(&genesis());
    let (signed_as, effects) = judged(&rotation(&prior, Vec::new()), &prior).unwrap();
    assert_eq!(signed_as, SignedAs::Recovery);
    assert_eq!(signed_as.label(), "recovery");
    let probation = effects.opens_probation.expect("a probation opens");
    assert_eq!(probation.device, pk(&key(7)));
    assert_eq!(probation.introduced_at, 1);
    assert!(probation.pending.is_empty());
    // The rotating principal's own entry leaves with it, and nothing else.
    assert_eq!(effects.removed, vec![hash_of(&key(0x3f))]);
}

#[test]
fn a_rotation_inside_the_window_is_refused_however_well_formed_it_is() {
    let prior = prior_of(&genesis());
    assert_eq!(
        judge(&rotation(&prior, Vec::new()), Some(&prior), SALT, &[], true)
            .expect_err("must refuse"),
        AccessError::RotationRateLimited
    );
}

#[test]
fn every_way_a_rotation_can_be_the_wrong_shape_is_refused() {
    let base = genesis();
    let prior = prior_of(&base);
    let digest = prior.digest.clone();

    // Adds two entries rather than one.
    let mut two = rotation(&prior, Vec::new());
    two.entries = sorted(
        two.entries
            .iter()
            .cloned()
            .chain([hash_of(&key(8))])
            .collect(),
    );
    let two = sign(two, &key(0x3f));
    assert_eq!(
        judged(&two, &prior).expect_err("must refuse"),
        AccessError::RotationShape(
            "add exactly the replacement device and the successor recovery key"
        )
    );

    // Keeps its own recovery key: a phrase is one-shot, so reusing it is refused
    // even when everything else about the transition is right.
    let mut kept = build(
        1,
        digest.clone(),
        &[],
        &[&key(1), &key(7)],
        &[&key(0x3f), &key(0x4f)],
    );
    kept.entries = sorted(
        prior
            .entries
            .iter()
            .cloned()
            .chain([hash_of(&key(7)), hash_of(&key(0x4f))])
            .collect(),
    );
    let kept = sign(kept, &key(0x3f));
    assert_eq!(
        judged(&kept, &prior).expect_err("must refuse"),
        AccessError::RotationShape("rotate the signer's own recovery key")
    );

    // Names no successor recovery key.
    let mut none = build(1, digest.clone(), &[], &[&key(1), &key(7)], &[&key(0x3f)]);
    none.recovery = Vec::new();
    none.entries = sorted(
        prior
            .entries
            .iter()
            .cloned()
            .chain([hash_of(&key(7))])
            .collect(),
    );
    let none = sign(none, &key(0x3f));
    // An empty recovery list is refused by the shape check before the rotation rules
    // are reached, which is the order that keeps a malformed list from being hashed.
    assert_eq!(
        judged(&none, &prior).expect_err("must refuse"),
        AccessError::EmptyList("recovery")
    );

    // Names two successors.
    let mut two_successors = build(
        1,
        digest.clone(),
        &[],
        &[&key(1), &key(7)],
        &[&key(0x4f), &key(0x5f)],
    );
    two_successors.entries = sorted(
        prior
            .entries
            .iter()
            .filter(|entry| *entry != &hash_of(&key(0x3f)))
            .cloned()
            .chain([hash_of(&key(7)), hash_of(&key(0x4f)), hash_of(&key(0x5f))])
            .collect(),
    );
    let two_successors = sign(two_successors, &key(0x3f));
    assert_eq!(
        judged(&two_successors, &prior).expect_err("must refuse"),
        AccessError::RotationShape("replace its own recovery key with exactly one successor")
    );

    // Drops another principal's recovery key as well as its own.
    let with_two_recovery = sign(
        build(0, vec![0u8; 32], &[], &[&key(1)], &[&key(0x3f), &key(0x5f)]),
        &key(1),
    );
    let prior_two = prior_of(&with_two_recovery);
    let mut drops_other = build(
        1,
        prior_two.digest.clone(),
        &[],
        &[&key(1), &key(7)],
        &[&key(0x4f)],
    );
    drops_other.entries = sorted(
        prior_two
            .entries
            .iter()
            .filter(|entry| *entry != &hash_of(&key(0x3f)))
            .cloned()
            .chain([hash_of(&key(7)), hash_of(&key(0x4f))])
            .collect(),
    );
    let drops_other = sign(drops_other, &key(0x3f));
    assert_eq!(
        judged(&drops_other, &prior_two).expect_err("must refuse"),
        AccessError::RotationShape("replace its own recovery key and no other")
    );

    // Removes an entry besides its own.
    let with_member = sign(
        build(0, vec![0u8; 32], &[&key(5)], &[&key(1)], &[&key(0x3f)]),
        &key(1),
    );
    let prior_member = prior_of(&with_member);
    let mut removes_more = rotation(&prior_member, Vec::new());
    removes_more.entries = sorted(
        removes_more
            .entries
            .iter()
            .filter(|entry| *entry != &hash_of(&key(5)))
            .cloned()
            .collect(),
    );
    let removes_more = sign(removes_more, &key(0x3f));
    assert_eq!(
        judged(&removes_more, &prior_member).expect_err("must refuse"),
        AccessError::RotationShape("remove nothing but its own entry")
    );

    // Adds no authorizer at all.
    let mut no_authorizer = rotation(&prior, Vec::new());
    no_authorizer.authorizers = sorted(vec![pk(&key(1))]);
    let no_authorizer = sign(no_authorizer, &key(0x3f));
    assert_eq!(
        judged(&no_authorizer, &prior).expect_err("must refuse"),
        AccessError::RotationShape("add exactly the replacement device as an authorizer")
    );

    // Adds a different device as the authorizer than the one it added as an entry,
    // which is how a rotation would smuggle in a second principal.
    let mut mismatched = build(1, digest.clone(), &[], &[&key(1), &key(8)], &[&key(0x4f)]);
    mismatched.entries = sorted(
        prior
            .entries
            .iter()
            .filter(|entry| *entry != &hash_of(&key(0x3f)))
            .cloned()
            .chain([hash_of(&key(7)), hash_of(&key(0x4f))])
            .collect(),
    );
    // `8` is an authorizer without being an entry, so the entry check speaks first.
    let mismatched = sign(mismatched, &key(0x3f));
    assert_eq!(
        judged(&mismatched, &prior).expect_err("must refuse"),
        AccessError::PrincipalNotAnEntry
    );

    // The same, with the mismatched authorizer also present as an entry: now the
    // rotation rule is the one that refuses it.
    let mut smuggled = build(1, digest.clone(), &[], &[&key(1), &key(8)], &[&key(0x4f)]);
    smuggled.entries = sorted(
        prior
            .entries
            .iter()
            .filter(|entry| *entry != &hash_of(&key(0x3f)))
            .cloned()
            .chain([hash_of(&key(8)), hash_of(&key(0x4f))])
            .collect(),
    );
    let smuggled = sign(smuggled, &key(0x3f));
    assert!(judged(&smuggled, &prior).is_ok());

    // Removes a prior authorizer.
    let two_authorizers = sign(
        build(0, vec![0u8; 32], &[], &[&key(1), &key(2)], &[&key(0x3f)]),
        &key(1),
    );
    let prior_two_auth = prior_of(&two_authorizers);
    let mut drops_authorizer = build(
        1,
        prior_two_auth.digest.clone(),
        &[],
        &[&key(1), &key(7)],
        &[&key(0x4f)],
    );
    drops_authorizer.entries = sorted(
        prior_two_auth
            .entries
            .iter()
            .filter(|entry| *entry != &hash_of(&key(0x3f)))
            .cloned()
            .chain([hash_of(&key(7)), hash_of(&key(0x4f))])
            .collect(),
    );
    let drops_authorizer = sign(drops_authorizer, &key(0x3f));
    assert_eq!(
        judged(&drops_authorizer, &prior_two_auth).expect_err("must refuse"),
        AccessError::RotationShape("remove no authorizer")
    );
}

#[test]
fn a_rotation_may_pin_only_prior_entries_and_never_an_authorizer() {
    let with_member = sign(
        build(0, vec![0u8; 32], &[&key(5)], &[&key(1)], &[&key(0x3f)]),
        &key(1),
    );
    let prior = prior_of(&with_member);

    // An entry the prior set never carried.
    let stranger = rotation(&prior, vec![hash_of(&key(0x20))]);
    assert_eq!(
        judged(&stranger, &prior).expect_err("must refuse"),
        AccessError::RotationShape("pin only entries the prior set carried")
    );

    // Somebody else's admin. The lost-device set a user chose on the recovery screen
    // cannot include an authorizer, which is what stops a stolen phrase from
    // becoming a takeover.
    let admin = rotation(&prior, vec![hash_of(&key(1))]);
    assert_eq!(
        judged(&admin, &prior).expect_err("must refuse"),
        AccessError::RotationShape("pin no prior authorizer")
    );

    // An ordinary member's entry is allowed, and is carried into the probation.
    let ordinary = rotation(&prior, vec![hash_of(&key(5))]);
    let (_, effects) = judged(&ordinary, &prior).unwrap();
    assert_eq!(
        effects.opens_probation.unwrap().pending,
        vec![hash_of(&key(5))]
    );
}

// MARK: Probation

/// The state after a rotation: `7` is a probationary authorizer licensed to remove
/// `5`, and `1` is the authorizer that predates it.
fn after_rotation() -> (AccessSet, Prior, Vec<Probation>) {
    let genesis = sign(
        build(0, vec![0u8; 32], &[&key(5)], &[&key(1)], &[&key(0x3f)]),
        &key(1),
    );
    let prior = prior_of(&genesis);
    let rotated = rotation(&prior, vec![hash_of(&key(5))]);
    let (_, effects) = judged(&rotated, &prior).unwrap();
    let probation = effects.opens_probation.clone().unwrap();
    (rotated.clone(), prior_of(&rotated), vec![probation])
}

#[test]
fn a_probationary_authorizer_may_remove_only_what_its_rotation_pinned() {
    let (_, prior, probations) = after_rotation();

    // The pinned entry, which is the device the user said they lost.
    let mut allowed = build(
        2,
        prior.digest.clone(),
        &[],
        &[&key(1), &key(7)],
        &[&key(0x4f)],
    );
    allowed.entries = sorted(
        prior
            .entries
            .iter()
            .filter(|entry| *entry != &hash_of(&key(5)))
            .cloned()
            .collect(),
    );
    let allowed = sign(allowed, &key(7));
    let (_, effects) = judge(&allowed, Some(&prior), SALT, &probations, false).unwrap();
    assert_eq!(effects.removed, vec![hash_of(&key(5))]);
    // And it does not clear its own probation by publishing.
    assert!(effects.clears_probation.is_empty());

    // Anything else, and it is refused. This is the case a timer would have allowed.
    let mut overreach = build(2, prior.digest.clone(), &[], &[&key(7)], &[&key(0x4f)]);
    overreach.entries = sorted(
        prior
            .entries
            .iter()
            .filter(|entry| *entry != &hash_of(&key(1)))
            .cloned()
            .collect(),
    );
    let overreach = sign(overreach, &key(7));
    assert_eq!(
        judge(&overreach, Some(&prior), SALT, &probations, false).expect_err("must refuse"),
        AccessError::ProbationExceeded,
        "a probationary device removing the authorizer that predates it is refused on \
         its licence, not on liveness: `1` is still an authorizer of the candidate set \
         from the relay's point of view only if it carries it, and it does not"
    );

    // Removing an entry that is neither pinned nor an authorizer is refused on the
    // probation rather than on liveness.
    let with_bystander = {
        let mut set = build(
            2,
            prior.digest.clone(),
            &[],
            &[&key(1), &key(7)],
            &[&key(0x4f)],
        );
        set.entries = sorted(
            prior
                .entries
                .iter()
                .cloned()
                .chain([hash_of(&key(0x11))])
                .collect(),
        );
        sign(set, &key(1))
    };
    let prior_with_bystander = prior_of(&with_bystander);
    let mut removes_bystander = build(
        3,
        prior_with_bystander.digest.clone(),
        &[],
        &[&key(1), &key(7)],
        &[&key(0x4f)],
    );
    removes_bystander.entries = sorted(
        prior_with_bystander
            .entries
            .iter()
            .filter(|entry| *entry != &hash_of(&key(0x11)))
            .cloned()
            .collect(),
    );
    let removes_bystander = sign(removes_bystander, &key(7));
    assert_eq!(
        judge(
            &removes_bystander,
            Some(&prior_with_bystander),
            SALT,
            &probations,
            false
        )
        .expect_err("must refuse"),
        AccessError::ProbationExceeded
    );
}

/// WEALD-296. Dropping an authorizer from the authorizer list while keeping its
/// entry leaves `removed` empty, so the entry-based probation licence is
/// vacuously satisfied and the liveness guard is met by the probationary device
/// itself. That path made a stolen recovery phrase a permanent takeover.
#[test]
fn a_probationary_authorizer_may_not_shed_an_authority_that_predates_it() {
    let (_, prior, probations) = after_rotation();

    // Every entry carried, so nothing is removed; only the authorizer list shrinks
    // to the probationary device alone.
    let mut self_only = build(2, prior.digest.clone(), &[], &[&key(7)], &[&key(0x4f)]);
    self_only.entries = sorted(prior.entries.clone());
    let self_only = sign(self_only, &key(7));
    assert_eq!(
        judge(&self_only, Some(&prior), SALT, &probations, false).expect_err("must refuse"),
        AccessError::ProbationExceeded,
        "a probationary signer that keeps every entry but names only itself as an \
         authorizer would leave no key able to clear the probation, ever"
    );

    // And the honest shape, carrying both, still passes: the new rule refuses
    // shedding, not publishing.
    let carries = sign(
        build(
            2,
            prior.digest.clone(),
            &[],
            &[&key(1), &key(7)],
            &[&key(0x4f)],
        ),
        &key(7),
    );
    judge(&carries, Some(&prior), SALT, &probations, false).expect("carrying both is permitted");
}

/// WEALD-311. The two-hop escape, and the reason it worked: probation restricted
/// removals, so a probationary device could freely *add* an authorizer, and the
/// clearing loop treats any signer absent from `probations` as one that predates
/// every rotation. R adds R2, R2 publishes carrying R's entry, R is cleared, and a
/// stolen recovery phrase is again a permanent takeover. It needs no secret beyond
/// the phrase probation exists to contain.
///
/// The fix refuses hop one, which is what makes the clearing loop's assumption
/// true rather than patching the loop: no authorizer can come into existence while
/// a probation is open.
#[test]
fn a_probationary_authorizer_may_not_add_a_second_authorizer() {
    let (_, prior, probations) = after_rotation();

    // Hop one. Nothing is removed and every prior authorizer is carried, so both
    // existing probation rules are vacuously satisfied; only the authorizer list
    // grows, by a key of the probationary device's own choosing.
    let recruits = sign(
        build(
            2,
            prior.digest.clone(),
            &[],
            &[&key(1), &key(7), &key(9)],
            &[&key(0x4f)],
        ),
        &key(7),
    );
    assert_eq!(
        judge(&recruits, Some(&prior), SALT, &probations, false).expect_err("must refuse"),
        AccessError::ProbationExceeded,
        "a probationary signer that can name a new authorizer can have that \
         authorizer clear its probation on the next version"
    );

    // The rule is about authority, not about publishing. An ordinary member added
    // by the same signer in the same shape is still permitted, because a member's
    // entry can never clear anything.
    let adds_member = sign(
        build(
            2,
            prior.digest.clone(),
            // `key(5)` is carried so this transition removes nothing at all: the
            // point being made is about the addition, and the rotation pinned
            // `key(5)`'s entry, so dropping it would be permitted and would make
            // `removed` non-empty for a reason that has nothing to do with the rule
            // under test.
            &[&key(5), &key(0x11)],
            &[&key(1), &key(7)],
            &[&key(0x4f)],
        ),
        &key(7),
    );
    let (_, effects) = judge(&adds_member, Some(&prior), SALT, &probations, false)
        .expect("adding a member is fine");
    assert!(effects.removed.is_empty());
    assert!(
        effects.clears_probation.is_empty(),
        "and it still does not clear its own probation"
    );

    // A non-probationary authorizer adding one is untouched by the rule: the
    // restriction is on the probationary signer, not on the set.
    let by_predecessor = sign(
        build(
            2,
            prior.digest.clone(),
            &[],
            &[&key(1), &key(7), &key(9)],
            &[&key(0x4f)],
        ),
        &key(1),
    );
    judge(&by_predecessor, Some(&prior), SALT, &probations, false)
        .expect("an authorizer that predates the probation may still grow the set");
}

#[test]
fn a_pre_existing_authorizer_clears_a_probation_by_carrying_the_device() {
    let (_, prior, probations) = after_rotation();
    let carried = sign(
        build(
            2,
            prior.digest.clone(),
            &[],
            &[&key(1), &key(7)],
            &[&key(0x4f)],
        ),
        &key(1),
    );
    let (_, effects) = judge(&carried, Some(&prior), SALT, &probations, false).unwrap();
    assert_eq!(effects.clears_probation, vec![pk(&key(7))]);

    // A publication that does not carry the probationary device clears nothing: it
    // removed it instead, which is the other outcome and not a confirmation.
    let mut dropped = build(2, prior.digest.clone(), &[], &[&key(1)], &[&key(0x4f)]);
    dropped.entries = sorted(
        prior
            .entries
            .iter()
            .filter(|entry| *entry != &hash_of(&key(7)))
            .cloned()
            .collect(),
    );
    let dropped = sign(dropped, &key(1));
    let (_, effects) = judge(&dropped, Some(&prior), SALT, &probations, false).unwrap();
    assert!(effects.clears_probation.is_empty());
    assert_eq!(effects.removed, vec![hash_of(&key(7))]);
}

#[test]
fn a_probationary_authorizer_clears_another_only_with_a_quorum() {
    // Two rotations, so the signer is itself probationary. Without this rule one
    // stolen phrase could introduce two devices that confirm each other.
    let genesis = {
        let mut set = build(
            0,
            vec![0u8; 32],
            &[&key(5)],
            &[&key(1)],
            &[&key(0x3f), &key(0x6f)],
        );
        set.quorum = Some(RecoveryQuorum {
            threshold: 1,
            keys: sorted(vec![pk(&key(0x81))]),
            sigs: Vec::new(),
        });
        sign(set, &key(1))
    };
    let prior = prior_of(&genesis);
    let first = rotation(&prior, Vec::new());
    let (_, effects) = judged(&first, &prior).unwrap();
    let seven = effects.opens_probation.unwrap();

    // The second rotation, by the other recovery principal, introducing device `9`.
    let prior = prior_of(&first);
    let mut second = build(
        2,
        prior.digest.clone(),
        &[],
        &[&key(1), &key(7), &key(9)],
        &[&key(0x4f), &key(0x7f)],
    );
    second.quorum = prior.quorum.clone();
    second.entries = sorted(
        prior
            .entries
            .iter()
            .filter(|entry| *entry != &hash_of(&key(0x6f)))
            .cloned()
            .chain([hash_of(&key(9)), hash_of(&key(0x7f))])
            .collect(),
    );
    let second = sign(second, &key(0x6f));
    let (_, effects) = judge(
        &second,
        Some(&prior),
        SALT,
        std::slice::from_ref(&seven),
        false,
    )
    .unwrap();
    let nine = effects.opens_probation.unwrap();
    assert!(effects.clears_probation.is_empty());

    // Now `9`, itself probationary, publishes a set carrying `7`. Without a quorum
    // confirmation it clears nothing.
    let prior = prior_of(&second);
    let probations = vec![seven, nine];
    let plain = {
        let mut set = build(
            3,
            prior.digest.clone(),
            &[],
            &[&key(1), &key(7), &key(9)],
            &[&key(0x7f)],
        );
        set.quorum = prior.quorum.clone();
        set.entries = prior.entries.clone();
        sign(set, &key(9))
    };
    let (_, effects) = judge(&plain, Some(&prior), SALT, &probations, false).unwrap();
    assert!(effects.clears_probation.is_empty());

    // With one valid signature by the configured quorum key over `7`'s entry, it
    // does.
    let confirmed = {
        let mut set = build(
            3,
            prior.digest.clone(),
            &[],
            &[&key(1), &key(7), &key(9)],
            &[&key(0x7f)],
        );
        set.entries = prior.entries.clone();
        set.quorum = Some(RecoveryQuorum {
            threshold: 1,
            keys: sorted(vec![pk(&key(0x81))]),
            sigs: Vec::new(),
        });
        // The signer is part of the digest, so it is set before the digest is taken.
        // Getting this the other way round produces a confirmation over a set that
        // was never published, which is exactly what the domain separator is for.
        set.signer = pk(&key(9));
        let digest = set.digest();
        let message = quorum_message(&digest, &hash_of(&key(7)));
        set.quorum.as_mut().unwrap().sigs = vec![QuorumSignature {
            key: pk(&key(0x81)),
            sig: key(0x81).sign(&message).to_bytes().to_vec(),
        }];
        sign(set, &key(9))
    };
    let (_, effects) = judge(&confirmed, Some(&prior), SALT, &probations, false).unwrap();
    assert_eq!(effects.clears_probation, vec![pk(&key(7))]);
}

#[test]
fn a_probationary_authorizer_with_no_quorum_registered_clears_nothing() {
    // The branch where the workspace never registered a quorum: there is no way for
    // one probationary device to confirm another, and time is not a way.
    let (_, prior, probations) = after_rotation();
    let mut second_probation = probations.clone();
    second_probation.push(Probation {
        device: pk(&key(9)),
        introduced_at: 1,
        pending: Vec::new(),
    });
    let mut carried = build(
        2,
        prior.digest.clone(),
        &[],
        &[&key(1), &key(7)],
        &[&key(0x4f)],
    );
    carried.entries = sorted(
        prior
            .entries
            .iter()
            .cloned()
            .chain([hash_of(&key(9))])
            .collect(),
    );
    let carried = sign(carried, &key(7));
    let (_, effects) = judge(&carried, Some(&prior), SALT, &second_probation, false).unwrap();
    assert!(
        effects.clears_probation.is_empty(),
        "no quorum is registered, so nothing confirms"
    );
}

// MARK: The property

#[test]
fn no_sequence_of_ordinary_publications_ever_strands_a_workspace() {
    // The property the two liveness invariants exist for, over a randomised sequence:
    // whatever an authorizer publishes, an accepted set always leaves at least one
    // prior authorizer and one prior recovery principal in place, so the workspace
    // can always publish again.
    let mut random = 0x5eed_u64;
    let mut next = move || {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        random
    };
    let mut current = genesis();
    let mut accepted = 0usize;
    let mut refused = 0usize;
    for _ in 0..200u64 {
        let prior = prior_of(&current);
        // A candidate built from a random subset of a pool of devices, sometimes
        // keeping the incumbent authorizer and sometimes not.
        let pool: Vec<SigningKey> = (0x10..0x16).map(key).collect();
        let mut members: Vec<&SigningKey> = Vec::new();
        for (index, device) in pool.iter().enumerate() {
            if next() >> (index % 8) & 1 == 1 {
                members.push(device);
            }
        }
        let keep_authorizer = next() % 3 != 0;
        let keep_recovery = next() % 3 != 0;
        let authorizers: Vec<SigningKey> = if keep_authorizer {
            vec![key(1)]
        } else {
            vec![pool[0].clone()]
        };
        let recovery: Vec<SigningKey> = if keep_recovery {
            vec![key(0x3f)]
        } else {
            vec![pool[1].clone()]
        };
        let candidate = sign(
            build(
                prior.version + 1,
                prior.digest.clone(),
                &members,
                &authorizers.iter().collect::<Vec<_>>(),
                &recovery.iter().collect::<Vec<_>>(),
            ),
            &key(1),
        );
        match judged(&candidate, &prior) {
            Ok(_) => {
                assert!(
                    candidate.authorizers.contains(&pk(&key(1))),
                    "an accepted set stranded the authorizer"
                );
                assert!(
                    candidate.recovery.contains(&pk(&key(0x3f))),
                    "an accepted set stranded the recovery principal"
                );
                current = candidate;
                accepted += 1;
            }
            Err(error) => {
                assert!(
                    matches!(error, AccessError::WouldStrandAuthority(_)),
                    "refused for the wrong reason: {error:?}"
                );
                refused += 1;
            }
        }
    }
    // Both outcomes actually happened, or the property proved nothing.
    assert!(
        accepted > 0 && refused > 0,
        "{accepted} accepted, {refused} refused"
    );
}
