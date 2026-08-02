// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The invite record's rules, without a database.
//!
//! Negative first, because the negatives are the point: an invite missing its
//! workspace root is rejected, a tampered signature is rejected, an expired invite
//! is rejected, and a scopeless record cannot exempt itself from the mandatory-root
//! rule by claiming to be the bootstrap invite.
//!
//! Nothing here is mocked. The signatures are real Ed25519 over the real canonical
//! encoding, and every refusal is reached by sending bytes a hostile issuer could
//! actually send.

use ed25519_dalek::{Signer as _, SigningKey};
use wealdrelay::cbor::{self, CborError};
use wealdrelay::frame::{ErrorClass, ErrorCode};
use wealdrelay::invite::{
    self, EncBundle, Invite, InviteError, MAX_BUNDLE_BYTES, MAX_CAPS, MAX_SCOPES, MAX_USES,
};

const NOW: u64 = 1_700_000_000_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn group(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

/// One well-formed invite: the workspace root in scope, one bundle for it, signed.
fn valid(issuer: &SigningKey) -> Invite {
    let root = group(0x11);
    let mut invite = Invite {
        token: vec![0xab; 16],
        workspace: root.clone(),
        issuer: issuer.verifying_key().to_bytes().to_vec(),
        issued_at: NOW,
        expires: NOW + invite::DEFAULT_EXPIRY_MS,
        uses: invite::DEFAULT_USES,
        code_hash: vec![0x22; 32],
        scopes: vec![root.clone()],
        caps: vec![b"chat.read".to_vec(), b"chat.write".to_vec()],
        update_pub: vec![0x33; 32],
        bundles: vec![EncBundle {
            group: root,
            epoch: 7,
            ct: b"sealed group info".to_vec(),
        }],
        sig: vec![0u8; 64],
    };
    resign(&mut invite, issuer);
    invite
}

fn resign(invite: &mut Invite, issuer: &SigningKey) {
    invite.sig = issuer.sign(&invite.digest_input()).to_bytes().to_vec();
}

// MARK: The negatives

#[test]
fn an_invite_missing_its_workspace_root_is_rejected() {
    // The rule the scope picker may hide but cannot remove. A record scoping two
    // channels and not the root would leave a joiner unable to enter the
    // roster-bearing group at all, because the root has no parent and so cannot be
    // reached by self-join.
    let issuer = key(1);
    let mut invite = valid(&issuer);
    invite.scopes = vec![group(0x44)];
    invite.bundles = vec![EncBundle {
        group: group(0x44),
        epoch: 1,
        ct: b"x".to_vec(),
    }];
    resign(&mut invite, &issuer);

    assert_eq!(
        invite::judge(&invite, false, NOW),
        Err(InviteError::MissingWorkspaceRoot)
    );
    assert_eq!(
        invite.check_mandatory_root(false),
        Err(InviteError::MissingWorkspaceRoot)
    );
    // Even the bootstrap exemption does not save it: the exemption is for a record
    // with no scopes at all, not for one that scopes the wrong thing.
    assert_eq!(
        invite.check_mandatory_root(true),
        Err(InviteError::MissingWorkspaceRoot)
    );
}

#[test]
fn a_scopeless_record_cannot_exempt_itself() {
    // The bootstrap answer comes from the relay's own genesis row, never from the
    // record. A record that could claim the exemption by carrying no scopes would be
    // the mandatory-root rule's own bypass.
    let issuer = key(2);
    let mut invite = valid(&issuer);
    invite.scopes.clear();
    invite.bundles.clear();
    invite.caps = vec![b"admin".to_vec()];
    resign(&mut invite, &issuer);

    assert!(invite.is_bootstrap_shaped());
    assert_eq!(
        invite::judge(&invite, false, NOW),
        Err(InviteError::ScopelessAndNotBootstrap)
    );
    assert_eq!(invite::judge(&invite, true, NOW), Ok(()));
}

#[test]
fn the_bootstrap_invite_carries_admin_and_only_admin() {
    let issuer = key(3);
    let mut invite = valid(&issuer);
    invite.scopes.clear();
    invite.bundles.clear();

    for caps in [
        Vec::new(),
        vec![b"chat.read".to_vec()],
        vec![b"admin".to_vec(), b"chat.read".to_vec()],
    ] {
        invite.caps = caps;
        invite.caps.sort();
        resign(&mut invite, &issuer);
        assert_eq!(
            invite::judge(&invite, true, NOW),
            Err(InviteError::BootstrapCapsWrong)
        );
    }
}

#[test]
fn a_tampered_signature_is_refused() {
    let issuer = key(4);
    let invite = valid(&issuer);
    assert!(invite.signature_verifies());

    // One flipped bit in the signature.
    let mut flipped = invite.clone();
    flipped.sig[0] ^= 1;
    assert!(!flipped.signature_verifies());
    assert_eq!(
        invite::judge(&flipped, false, NOW),
        Err(InviteError::BadSignature)
    );

    // One changed field under an otherwise valid signature, which is the attack the
    // digest exists to stop: extending the expiry of somebody else's invite.
    let mut extended = invite.clone();
    extended.expires += 1;
    assert_eq!(
        invite::judge(&extended, false, NOW),
        Err(InviteError::BadSignature)
    );

    // A different signer's signature over the same bytes.
    let mut impostor = invite.clone();
    resign(&mut impostor, &key(5));
    assert_eq!(
        invite::judge(&impostor, false, NOW),
        Err(InviteError::BadSignature)
    );
}

#[test]
fn an_expired_invite_is_refused() {
    let issuer = key(6);
    let invite = valid(&issuer);
    assert_eq!(invite::judge(&invite, false, invite.expires - 1), Ok(()));
    // The boundary is inclusive: an invite is dead at its expiry, not after it.
    assert_eq!(
        invite::judge(&invite, false, invite.expires),
        Err(InviteError::Expired)
    );
    assert_eq!(
        invite::judge(&invite, false, invite.expires + 1),
        Err(InviteError::Expired)
    );
}

#[test]
fn shape_is_checked_before_the_signature() {
    // A malformed list must not make the relay hash a megabyte, so a record that is
    // both malformed and unsigned is answered on its shape.
    let issuer = key(7);
    let mut invite = valid(&issuer);
    invite.uses = 0;
    invite.sig = vec![0u8; 64];
    assert_eq!(
        invite::judge(&invite, false, NOW),
        Err(InviteError::UsesOutOfRange)
    );
}

// MARK: Shape

#[test]
fn uses_is_between_one_and_the_seat_ceiling() {
    let issuer = key(8);
    let mut invite = valid(&issuer);
    for bad in [0, MAX_USES + 1] {
        invite.uses = bad;
        assert_eq!(invite.check_shape(), Err(InviteError::UsesOutOfRange));
    }
    for good in [1, MAX_USES] {
        invite.uses = good;
        assert_eq!(invite.check_shape(), Ok(()));
    }
}

#[test]
fn expires_must_be_after_issued_at() {
    let issuer = key(9);
    let mut invite = valid(&issuer);
    invite.expires = invite.issued_at;
    assert_eq!(invite.check_shape(), Err(InviteError::ExpiryNotAfterIssue));
    invite.expires = invite.issued_at - 1;
    assert_eq!(invite.check_shape(), Err(InviteError::ExpiryNotAfterIssue));
}

#[test]
fn lists_are_sorted_deduplicated_and_bounded() {
    let issuer = key(10);
    let mut invite = valid(&issuer);

    invite.scopes = vec![group(0x22), group(0x11)];
    invite.bundles = invite
        .scopes
        .iter()
        .map(|scope| EncBundle {
            group: scope.clone(),
            epoch: 0,
            ct: b"x".to_vec(),
        })
        .collect();
    assert_eq!(invite.check_shape(), Err(InviteError::UnsortedScopes));

    invite.scopes = vec![group(0x11), group(0x11)];
    assert_eq!(invite.check_shape(), Err(InviteError::UnsortedScopes));

    invite.scopes = (0..=MAX_SCOPES).map(|i| vec![i as u8; 32]).collect();
    assert_eq!(invite.check_shape(), Err(InviteError::TooManyScopes));

    let mut invite = valid(&issuer);
    invite.caps = vec![b"chat.write".to_vec(), b"chat.read".to_vec()];
    assert_eq!(invite.check_shape(), Err(InviteError::UnsortedCaps));
    invite.caps = vec![b"chat.read".to_vec(); MAX_CAPS + 1];
    assert_eq!(invite.check_shape(), Err(InviteError::TooManyCaps));
}

#[test]
fn the_capability_vocabulary_is_closed() {
    let issuer = key(11);
    let mut invite = valid(&issuer);

    for capability in invite::CAPABILITIES {
        invite.caps = vec![capability.as_bytes().to_vec()];
        assert_eq!(invite.check_shape(), Ok(()), "{capability}");
    }

    invite.caps = vec![b"ticket.transition:todo->doing".to_vec()];
    assert_eq!(invite.check_shape(), Ok(()));

    for bad in [
        "ticket.transition:",
        "ticket.transition:->doing",
        "ticket.transition:todo->",
        "ticket.transition:todo",
        "chat.admin",
        "",
    ] {
        invite.caps = vec![bad.as_bytes().to_vec()];
        assert_eq!(
            invite.check_shape(),
            Err(InviteError::UnknownCapability(bad.to_string())),
            "{bad}"
        );
    }

    // A capability that is not text at all is named by its bytes, because the
    // message has to say which entry was wrong and there is nothing else to say.
    invite.caps = vec![vec![0xff, 0xfe]];
    assert_eq!(
        invite.check_shape(),
        Err(InviteError::UnknownCapability("fffe".to_string()))
    );
}

#[test]
fn there_is_exactly_one_bundle_per_scope_in_scope_order() {
    let issuer = key(12);
    let root = group(0x11);
    let second = group(0x22);

    let mut invite = valid(&issuer);
    invite.scopes = vec![root.clone(), second.clone()];
    invite.bundles = vec![EncBundle {
        group: root.clone(),
        epoch: 0,
        ct: b"x".to_vec(),
    }];
    assert_eq!(invite.check_shape(), Err(InviteError::BundleMismatch));

    invite.bundles = vec![
        EncBundle {
            group: second.clone(),
            epoch: 0,
            ct: b"x".to_vec(),
        },
        EncBundle {
            group: root.clone(),
            epoch: 0,
            ct: b"x".to_vec(),
        },
    ];
    assert_eq!(invite.check_shape(), Err(InviteError::BundleMismatch));

    invite.bundles = vec![
        EncBundle {
            group: root.clone(),
            epoch: 0,
            ct: Vec::new(),
        },
        EncBundle {
            group: second.clone(),
            epoch: 0,
            ct: b"x".to_vec(),
        },
    ];
    assert_eq!(invite.check_shape(), Err(InviteError::BundleEmpty));

    invite.bundles[0].ct = vec![0u8; MAX_BUNDLE_BYTES + 1];
    assert_eq!(invite.check_shape(), Err(InviteError::BundleTooLarge));

    invite.bundles[0].ct = vec![0u8; MAX_BUNDLE_BYTES];
    assert_eq!(invite.check_shape(), Ok(()));
}

// MARK: Encoding

#[test]
fn encode_and_decode_round_trip() {
    let issuer = key(13);
    let invite = valid(&issuer);
    let bytes = invite.encode();
    assert_eq!(Invite::decode(&bytes), Ok(invite.clone()));
    // The signed bytes are the encoding with `sig` removed, and nothing else.
    assert!(bytes.len() > invite.digest_input().len());
    assert_eq!(invite.digest(), invite.digest());
    assert_ne!(invite.digest().to_vec(), vec![0u8; 32]);
}

#[test]
fn a_record_the_relay_re_encodes_verifies_the_same() {
    // Load-bearing for `store::fetch`, which serves the stored bytes rather than a
    // re-encoding. If these ever differ the relay is asking a client to trust the
    // relay's encoder instead of the issuer's signature.
    let issuer = key(14);
    let invite = valid(&issuer);
    let decoded = Invite::decode(&invite.encode()).unwrap();
    assert_eq!(decoded.encode(), invite.encode());
    assert!(decoded.signature_verifies());
}

#[test]
fn a_truncated_or_trailing_record_is_refused() {
    let issuer = key(15);
    let bytes = valid(&issuer).encode();

    assert_eq!(
        Invite::decode(&bytes[..bytes.len() - 1]),
        Err(InviteError::Encoding(CborError::Truncated))
    );

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        Invite::decode(&trailing),
        Err(InviteError::Encoding(CborError::TrailingBytes(1)))
    );

    assert_eq!(
        Invite::decode(&cbor::array(&[cbor::uint(1)])),
        Err(InviteError::Encoding(CborError::WrongArrayCount {
            expected: 12,
            got: 1
        }))
    );
}

#[test]
fn a_field_of_the_wrong_width_is_refused() {
    // The fixed-width fields are fixed for a reason: a short `workspace` would decode
    // fine and then name a group no relay recognises.
    let issuer = key(16);
    let mut invite = valid(&issuer);
    invite.token = vec![0xab; 15];
    assert_eq!(
        Invite::decode(&invite.encode()),
        Err(InviteError::Encoding(CborError::WrongLength {
            expected: 16,
            got: 15
        }))
    );
}

#[test]
fn the_decoder_bounds_every_list_before_allocating() {
    let issuer = key(17);
    let invite = valid(&issuer);
    let head = |list: Vec<u8>, caps: Vec<u8>, bundles: Vec<u8>| {
        cbor::array(&[
            cbor::bytes(&invite.token),
            cbor::bytes(&invite.workspace),
            cbor::bytes(&invite.issuer),
            cbor::uint(invite.issued_at),
            cbor::uint(invite.expires),
            cbor::uint(u64::from(invite.uses)),
            cbor::bytes(&invite.code_hash),
            list,
            caps,
            cbor::bytes(&invite.update_pub),
            bundles,
            cbor::bytes(&invite.sig),
        ])
    };
    let one_scope = cbor::array(&[cbor::bytes(&invite.workspace)]);
    let one_cap = cbor::array(&[cbor::bytes(b"admin")]);
    let one_bundle = cbor::array(&[cbor::array(&[
        cbor::bytes(&invite.workspace),
        cbor::uint(0),
        cbor::bytes(b"x"),
    ])]);

    let many_scopes = cbor::array(&vec![cbor::bytes(&invite.workspace); MAX_SCOPES + 1]);
    assert_eq!(
        Invite::decode(&head(many_scopes, one_cap.clone(), one_bundle.clone())),
        Err(InviteError::TooManyScopes)
    );

    let many_caps = cbor::array(&vec![cbor::bytes(b"admin"); MAX_CAPS + 1]);
    assert_eq!(
        Invite::decode(&head(one_scope.clone(), many_caps, one_bundle.clone())),
        Err(InviteError::TooManyCaps)
    );

    let many_bundles = cbor::array(&vec![
        cbor::array(&[
            cbor::bytes(&invite.workspace),
            cbor::uint(0),
            cbor::bytes(b"x"),
        ]);
        MAX_SCOPES + 1
    ]);
    assert_eq!(
        Invite::decode(&head(one_scope.clone(), one_cap.clone(), many_bundles)),
        Err(InviteError::TooManyScopes)
    );

    let huge = cbor::array(&[cbor::array(&[
        cbor::bytes(&invite.workspace),
        cbor::uint(0),
        cbor::bytes(&vec![0u8; MAX_BUNDLE_BYTES + 1]),
    ])]);
    assert_eq!(
        Invite::decode(&head(one_scope, one_cap, huge)),
        Err(InviteError::BundleTooLarge)
    );
}

// MARK: The answers

#[test]
fn every_refusal_maps_to_a_code_in_the_closed_registry() {
    let cases = [
        InviteError::Encoding(CborError::Truncated),
        InviteError::TooManyScopes,
        InviteError::TooManyCaps,
        InviteError::UnsortedScopes,
        InviteError::UnsortedCaps,
        InviteError::UnknownCapability("x".to_string()),
        InviteError::UsesOutOfRange,
        InviteError::ExpiryNotAfterIssue,
        InviteError::BundleMismatch,
        InviteError::BundleTooLarge,
        InviteError::BundleEmpty,
        InviteError::MissingWorkspaceRoot,
        InviteError::ScopelessAndNotBootstrap,
        InviteError::BootstrapCapsWrong,
        InviteError::BadSignature,
        InviteError::Expired,
    ];
    for case in cases {
        let code = case.code();
        assert!(ErrorCode::ALL.contains(&code), "{case}");
        // Every one of them is permanent as sent or permanent as authorized. None of
        // them tells a member to try the same bytes again.
        assert!(!code.class().is_retryable(), "{case}");
        assert!(!case.to_string().is_empty());
    }
}

#[test]
fn the_joiner_is_told_one_thing_and_it_names_no_state() {
    // invites.md: no capacity, redeemed, revoked, expired, cooled down and
    // nonexistent are one response. `quota/seats_exhausted` carries no interval,
    // because an interval would be the oracle the flat answer exists to remove.
    assert_eq!(invite::UNAVAILABLE, ErrorCode::SeatsExhausted);
    assert_eq!(invite::UNAVAILABLE.class(), ErrorClass::Quota);
    let error = wealdrelay::frame::FrameError::new(invite::UNAVAILABLE);
    assert_eq!(error.retry_after, None);
    assert_eq!(error.detail, None);
}

#[test]
fn the_defaults_are_the_ones_the_spec_names() {
    assert_eq!(invite::DEFAULT_USES, 1);
    assert_eq!(invite::DEFAULT_EXPIRY_MS, 7 * 24 * 60 * 60 * 1000);
    assert_eq!(invite::BOOTSTRAP_EXPIRY_MS, 24 * 60 * 60 * 1000);
    assert_eq!(invite::TOKEN_BYTES, 16);
    assert_eq!(invite::NONCE_BYTES, 16);
    assert_eq!(invite::KEY_BYTES, 32);
    assert_eq!(invite::SIG_BYTES, 64);
    assert_eq!(invite::MAX_USES, 64);
    assert!(invite::TRANSITION_PREFIX.ends_with(':'));
}

// MARK: Every field position, given the wrong bytes

/// The twelve fields of the record, in the order `decode` reads them.
///
/// A decoder that read them in a different order would still pass a single
/// malformed case, and would be interpreting somebody else's bytes as a token or a
/// code hash. So each position is corrupted in turn and each must be refused.
fn fields(invite: &Invite) -> Vec<Vec<u8>> {
    vec![
        cbor::bytes(&invite.token),
        cbor::bytes(&invite.workspace),
        cbor::bytes(&invite.issuer),
        cbor::uint(invite.issued_at),
        cbor::uint(invite.expires),
        cbor::uint(u64::from(invite.uses)),
        cbor::bytes(&invite.code_hash),
        cbor::array(
            &invite
                .scopes
                .iter()
                .map(|s| cbor::bytes(s))
                .collect::<Vec<_>>(),
        ),
        cbor::array(
            &invite
                .caps
                .iter()
                .map(|c| cbor::bytes(c))
                .collect::<Vec<_>>(),
        ),
        cbor::bytes(&invite.update_pub),
        cbor::array(
            &invite
                .bundles
                .iter()
                .map(|b| {
                    cbor::array(&[
                        cbor::bytes(&b.group),
                        cbor::uint(b.epoch),
                        cbor::bytes(&b.ct),
                    ])
                })
                .collect::<Vec<_>>(),
        ),
        cbor::bytes(&invite.sig),
    ]
}

#[track_caller]
fn refuses(bytes: &[u8], what: &str) {
    let outcome = Invite::decode(bytes);
    let refused = matches!(outcome, Err(InviteError::Encoding(_)));
    assert!(
        refused,
        "{what}: expected an encoding refusal, got {outcome:?}"
    );
}

#[test]
fn the_field_order_is_load_bearing_and_every_position_is_checked() {
    let issuer = key(9);
    let invite = valid(&issuer);
    assert_eq!(Invite::decode(&invite.encode()).expect("decodes"), invite);

    let original = fields(&invite);
    assert_eq!(original.len(), 12);
    // Round trip through the hand-built field list, so a mistake in this test's own
    // encoder would fail here rather than by making every case below pass.
    assert_eq!(
        Invite::decode(&cbor::array(&original)).expect("decodes"),
        invite
    );

    // A byte string where the reader wants an unsigned integer, and an integer
    // where it wants a byte string. One or the other applies at every position.
    for position in 0..original.len() {
        let mut broken = original.clone();
        broken[position] = match position {
            3..=5 => cbor::bytes(&[1]),
            _ => cbor::uint(1),
        };
        refuses(
            &cbor::array(&broken),
            &format!("position {position} with the wrong major type"),
        );
    }

    // The fixed-width fields, one byte short. `bytes_of` is what enforces these and
    // a record that decoded a 31-byte key would be a record with a key nobody can
    // verify against.
    for (position, width) in [
        (0usize, 16usize),
        (1, 32),
        (2, 32),
        (6, 32),
        (9, 32),
        (11, 64),
    ] {
        let mut broken = original.clone();
        broken[position] = cbor::bytes(&vec![0u8; width - 1]);
        refuses(
            &cbor::array(&broken),
            &format!("position {position} one byte short"),
        );
    }

    // Arity, both directions, and trailing bytes after a complete record.
    refuses(&cbor::array(&original[..11]), "eleven fields");
    let mut extra = original.clone();
    extra.push(cbor::uint(0));
    refuses(&cbor::array(&extra), "thirteen fields");
    let mut trailing = cbor::array(&original);
    trailing.push(0x00);
    refuses(&trailing, "trailing bytes");

    // The three lists, each given a member of the wrong shape. Scopes and bundle
    // groups are fixed width; a cap is a variable-length byte string, so the wrong
    // shape there is an integer.
    let mut bad_scope = original.clone();
    bad_scope[7] = cbor::array(&[cbor::bytes(&[0u8; 31])]);
    refuses(&cbor::array(&bad_scope), "a 31-byte scope");
    let mut bad_cap = original.clone();
    bad_cap[8] = cbor::array(&[cbor::uint(1)]);
    refuses(&cbor::array(&bad_cap), "a cap that is not a byte string");
    let mut bad_bundle = original.clone();
    bad_bundle[10] = cbor::array(&[cbor::array(&[
        cbor::bytes(&[0u8; 31]),
        cbor::uint(1),
        cbor::bytes(b"ct"),
    ])]);
    refuses(&cbor::array(&bad_bundle), "a 31-byte bundle group");
    let mut short_bundle = original.clone();
    short_bundle[10] = cbor::array(&[cbor::array(&[cbor::bytes(&[0u8; 32]), cbor::uint(1)])]);
    refuses(&cbor::array(&short_bundle), "a two-field bundle");
    let mut bad_bundle_epoch = original.clone();
    bad_bundle_epoch[10] = cbor::array(&[cbor::array(&[
        cbor::bytes(&[0u8; 32]),
        cbor::bytes(b"not an epoch"),
        cbor::bytes(b"ct"),
    ])]);
    refuses(
        &cbor::array(&bad_bundle_epoch),
        "a bundle epoch that is not a number",
    );
    let mut bad_bundle_ct = original.clone();
    bad_bundle_ct[10] = cbor::array(&[cbor::array(&[
        cbor::bytes(&[0u8; 32]),
        cbor::uint(1),
        cbor::uint(7),
    ])]);
    refuses(
        &cbor::array(&bad_bundle_ct),
        "a bundle ciphertext that is not a byte string",
    );

    // And the one field with a range rather than a width: `uses` is a `u8` on the
    // wire, so a value past 255 is refused by the reader before the seat rules ever
    // see it.
    let mut wide_uses = original;
    wide_uses[5] = cbor::uint(u64::from(u16::MAX));
    refuses(&cbor::array(&wide_uses), "uses wider than a byte");
}
