// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The one-time code, and who is allowed to send invite mail.
//!
//! Both are pure, and both are the sort of thing that looks obviously right and is
//! not: a Base32 alphabet with the wrong exclusions makes a code that cannot be read
//! aloud, and a mail decision that reads the deployment profile makes a binary that
//! is not the audited binary.

use wealdrelay::invite::code::{self, Code, CodeError};
use wealdrelay::invite::delivery::{self, Delivery};

#[test]
fn a_code_is_twelve_crockford_symbols_grouped_in_fours() {
    let code = Code::from_bits(0);
    assert_eq!(code.symbols(), "000000000000");
    assert_eq!(code.grouped(), "0000-0000-0000");

    let full = Code::from_bits(u64::MAX);
    assert_eq!(full.symbols(), "ZZZZZZZZZZZZ");
    assert_eq!(full.grouped(), "ZZZZ-ZZZZ-ZZZZ");
    // The high four bits of a u64 are dropped, which is what makes any value a legal
    // code and keeps the constructor total.
    assert_eq!(full.bits(), (1u64 << code::CODE_BITS) - 1);

    assert_eq!(code::ALPHABET.len(), 32);
    assert_eq!(code::CODE_SYMBOLS * 5, code::CODE_BITS as usize);
    assert_eq!(code::GROUP_SYMBOLS, 4);
}

#[test]
fn the_alphabet_excludes_every_confusable_letter() {
    // Crockford: no I, no L, no O, no U. The first three are confusable with digits
    // and the fourth is excluded on purpose.
    for excluded in *b"ILOU" {
        assert!(!code::ALPHABET.contains(&excluded), "{}", excluded as char);
    }
}

#[test]
fn a_code_round_trips_through_the_form_a_human_types() {
    for bits in [0u64, 1, 0x0f0f0f0f0f0f0f, (1u64 << 60) - 1, 42] {
        let code = Code::from_bits(bits);
        assert_eq!(Code::parse(&code.symbols()), Ok(code));
        assert_eq!(Code::parse(&code.grouped()), Ok(code));
        assert_eq!(Code::parse(&code.symbols().to_lowercase()), Ok(code));
        assert_eq!(Code::parse(&code.grouped().replace('-', " ")), Ok(code));
    }
}

#[test]
fn crockfords_remappings_are_applied_on_input_and_u_is_not() {
    // A human who transcribed the shape of a character rather than the character
    // still gets in.
    let expected = Code::parse("110000000000").unwrap();
    for spelling in [
        "I10000000000",
        "l10000000000",
        "L10000000000",
        "1I0000000000",
    ] {
        assert_eq!(
            Code::parse(spelling).map(|code| code.bits()),
            Ok(expected.bits()),
            "{spelling}"
        );
    }
    assert_eq!(Code::parse("O00000000000"), Code::parse("000000000000"));

    // `U` is excluded from the alphabet on purpose and is not remapped: accepting it
    // would give one code two spellings.
    assert_eq!(Code::parse("U00000000000"), Err(CodeError::NotASymbol('U')));
    assert_eq!(Code::parse("u00000000000"), Err(CodeError::NotASymbol('u')));
}

#[test]
fn a_code_of_the_wrong_length_or_with_a_stray_character_is_refused() {
    assert_eq!(Code::parse(""), Err(CodeError::WrongLength(0)));
    assert_eq!(
        Code::parse("0000-0000-000"),
        Err(CodeError::WrongLength(11))
    );
    assert_eq!(
        Code::parse("0000-0000-00000"),
        Err(CodeError::WrongLength(13))
    );
    assert_eq!(
        Code::parse("0000_0000_0000"),
        Err(CodeError::NotASymbol('_'))
    );
    assert_eq!(
        Code::parse("0000-0000-000!"),
        Err(CodeError::NotASymbol('!'))
    );
    for error in [
        CodeError::WrongLength(3),
        CodeError::NotASymbol('!'),
        CodeError::Hash("x".to_string()),
    ] {
        assert!(!error.to_string().is_empty());
    }
}

#[test]
fn a_random_code_is_well_formed() {
    let a = Code::random();
    let b = Code::random();
    assert_eq!(Code::parse(&a.grouped()), Ok(a));
    assert_eq!(a.symbols().len(), code::CODE_SYMBOLS);
    // Two draws from 60 bits colliding would be a randomness failure, not a flake.
    assert_ne!(a, b);
}

#[test]
fn the_hash_is_argon2id_salted_with_the_token() {
    let token = vec![0x11; 16];
    let other = vec![0x22; 16];
    let code = Code::from_bits(12345);

    let hash = code::hash(code, &token).unwrap();
    assert_eq!(hash.len(), 32);
    // Deterministic for one code and one token.
    assert_eq!(code::hash(code, &token).unwrap(), hash);
    // Salted: the same code under a different token is a different hash, so one
    // precomputed table cannot attack two invites.
    assert_ne!(code::hash(code, &other).unwrap(), hash);
    // And a different code under the same token is different too.
    assert_ne!(code::hash(Code::from_bits(12346), &token).unwrap(), hash);

    assert!(code::verify(code, &token, &hash));
    assert!(!code::verify(Code::from_bits(12346), &token, &hash));
    assert!(!code::verify(code, &other, &hash));
}

#[test]
fn verify_answers_false_rather_than_erroring_on_anything_misshapen() {
    let token = vec![0x11; 16];
    let code = Code::from_bits(7);
    let hash = code::hash(code, &token).unwrap();

    // A salt Argon2 refuses.
    assert!(!code::verify(code, &[0u8; 4], &hash));
    // A stored hash of the wrong width.
    assert!(!code::verify(code, &token, &hash[..31]));
    assert!(!code::verify(code, &token, &[]));
}

#[test]
fn both_of_argon2s_refusals_are_reachable_and_neither_panics() {
    let token = vec![0x11; 16];
    let code = Code::from_bits(7);
    // Below the algorithm's memory floor.
    let refused = code::hash_with(1, code, &token);
    assert!(matches!(refused, Err(CodeError::Hash(_))));
    // Below the eight-byte salt floor.
    let short = code::hash(code, &[0u8; 4]);
    assert!(matches!(short, Err(CodeError::Hash(_))));
}

#[test]
fn the_rate_limit_constants_are_the_ones_the_spec_names() {
    // Five wrong attempts, fifteen minutes, per token, source and device tuple.
    assert_eq!(code::MAX_FAILURES, 5);
    assert_eq!(code::COOLDOWN_SECONDS, 15 * 60);
    assert_eq!(code::ITERATIONS, 2);
    assert_eq!(code::LANES, 1);
    assert_eq!(code::MEMORY_KIB, 19 * 1024);
}

// MARK: Mail

#[test]
fn the_relay_never_claims_it_will_send_the_mail() {
    // The negative for WEALD-L072. `Delivery::RelaySends` and the `relay_sends` label
    // are gone, because no SMTP client was ever written behind them: a relay that
    // reported it would send and then did not is worse than one that says plainly that
    // delivery is the admin's client. `decide` takes no argument now, so there is no
    // configuration that can move it.
    assert_eq!(delivery::decide(), Delivery::CopyLink);
    assert_eq!(Delivery::CopyLink.label(), "copy_link");
}

#[test]
fn a_hosted_relay_still_refuses_an_smtp_url() {
    // Unchanged by the arm's removal, and worth keeping for that reason: the variable is
    // still in the registry and still accepted on a self-host profile, so the refusal on
    // hosted is the thing that stops a hosted relay from ever holding an invitee address.
    // The refusal lives in `profile::enforce` rather than here, because a module that
    // branched on its own environment is what
    // `specs/backend/build/environments.md` forbids.
    use wealdrelay::config::{keys, Config, Values};
    let values = Values::from_pairs([
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@localhost/weald_relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
        (keys::PROFILE, "hosted"),
        (keys::ACCESS_SET, "enforce"),
        (keys::MIN_ENC, "mls"),
        (keys::SMTP_URL, "smtp://localhost:1025"),
    ]);
    let error =
        Config::resolve(&values).expect_err("a hosted relay may not hold invitee addresses");
    assert!(error.to_string().contains(keys::SMTP_URL));
    assert!(error.to_string().contains("invitee email addresses"));
}

#[test]
fn the_landing_page_says_nothing_the_relay_does_not_know() {
    let page = delivery::landing_page();
    assert!(page.contains("You've been invited to a Weald workspace"));
    // It cannot name the workspace, the inviter, or the token, because the relay does
    // not hold the first two and echoing the third would confirm which tokens exist.
    assert!(!page.contains("workspace name"));
    assert!(page.contains("weald://join/"));
    assert!(page.contains("location.hash"));
    // The same bytes for every token, including tokens that do not exist.
    assert_eq!(page, delivery::landing_page());
}

/// A fragment eaten in transit gets a specific message, not silence.
///
/// The hosted page at `backend/weald-web/src/workspace-invite.tsx` already diagnosed
/// this; the relay-served page did not, so which of the two pages an invitee landed
/// on decided whether they were told why nothing worked. See WEALD-L079.
#[test]
fn the_landing_page_names_a_missing_fragment() {
    let page = delivery::landing_page();
    assert!(
        page.contains("id=\"missing-secret\""),
        "the page has nowhere to put the missing-fragment message"
    );
    assert!(
        page.contains("missing the part after the"),
        "the message must name the fragment, not just say something went wrong"
    );
    // Hidden until the browser knows there is no fragment: the server never sees one,
    // so a page that showed this unconditionally would accuse every good link.
    assert!(page.contains("hidden"));
    assert!(page.contains("location.hash === ''"));
    // And the dead link is withheld rather than offered, because a `weald://` URL
    // without the secret is a link macOS answers with an error sheet.
    assert!(page.contains("removeAttribute('href')"));
}
