// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Tiers 1 and 2 for the envelope log's byte budget: the accounting itself,
//! without a database.
//!
//! `wealdrelay::log_budget` is deliberately made of small total functions so that
//! the arithmetic which decides whether a customer's write is refused can be
//! checked exhaustively here, and the database suite next door can be about the
//! things only a database can prove. What is proven in this file:
//!
//! - The unit is 10^9, the same one `pricing.ts BYTES_PER_GB` uses.
//!   `specs/backend/cloud/instance-sizing.md` records what having two of these
//!   cost the last time, so it is asserted rather than assumed.
//! - Unlimited never refuses anything.
//! - The comparison is on the total after the write, so reaching the budget
//!   exactly is accepted and passing it is not.
//! - Nothing overflows, including at `i64::MAX`, where a wrapping add would read
//!   as "plenty of room" at exactly the moment there is none.

use proptest::prelude::*;
use wealdrelay::config::{keys, Config, Limit, Values};
use wealdrelay::log_budget::{charge_of, limit_bytes, limit_detail, over_budget, BYTES_PER_GB};

fn config_with(value: Option<&str>) -> Config {
    let mut pairs = vec![
        (keys::HOSTNAME, "localhost".to_string()),
        (
            keys::DATABASE_URL,
            "postgres://weald@127.0.0.1/weald".to_string(),
        ),
        (
            keys::STORAGE_URL,
            "file:///tmp/weald-log-budget".to_string(),
        ),
        (keys::RELEASE_CHECK, "off".to_string()),
    ];
    if let Some(value) = value {
        pairs.push((keys::MAX_LOG_GB, value.to_string()));
    }
    Config::resolve(&Values::from_pairs(pairs)).expect("the configuration resolves")
}

#[test]
fn a_gigabyte_is_a_decimal_gigabyte() {
    assert_eq!(BYTES_PER_GB, 1_000_000_000);
}

#[test]
fn unset_is_unlimited_and_unlimited_is_no_ceiling() {
    let config = config_with(None);
    assert_eq!(config.max_log_gb, Limit::Unlimited);
    assert_eq!(limit_bytes(&config), None);
    // The self-hoster's posture: an operator who owns the disk is never told by
    // this relay what to do with it.
    assert!(!over_budget(i64::MAX, i64::MAX, None));
}

#[test]
fn the_configured_number_is_the_enforced_number() {
    // 25, the Team tier's figure, is the case that matters: the number on the
    // pricing page and the number the relay refuses at have to be one number.
    let config = config_with(Some("25"));
    assert_eq!(config.max_log_gb, Limit::Of(25));
    assert_eq!(limit_bytes(&config), Some(25_000_000_000));
}

#[test]
fn unlimited_is_spelled_out_rather_than_guessed() {
    let config = config_with(Some("unlimited"));
    assert_eq!(limit_bytes(&config), None);
}

#[test]
fn a_charge_is_the_ciphertext_and_nothing_else() {
    assert_eq!(charge_of(&[]), 0);
    assert_eq!(charge_of(&[0u8; 1024]), 1024);
}

#[test]
fn reaching_the_budget_is_accepted_and_passing_it_is_not() {
    // The boundary, stated three times because it is the whole behaviour: one
    // byte under, exactly on, one byte over.
    assert!(!over_budget(90, 9, Some(100)));
    assert!(!over_budget(90, 10, Some(100)));
    assert!(over_budget(90, 11, Some(100)));
}

#[test]
fn an_empty_workspace_with_a_zero_budget_cannot_write() {
    // A zero is a posture an operator can set and it means what it says. Nothing
    // in the relay coerces it to unlimited, which is the silent failure the
    // configuration layer refuses everywhere else.
    assert!(over_budget(0, 1, Some(0)));
    assert!(!over_budget(0, 0, Some(0)));
}

#[test]
fn the_limit_travels_as_eight_big_endian_bytes() {
    assert_eq!(limit_detail(1), vec![0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(limit_detail(25_000_000_000).len(), 8);
    assert_eq!(
        i64::from_be_bytes(limit_detail(25_000_000_000).try_into().unwrap()),
        25_000_000_000
    );
}

fn cases() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(cases())]

    /// Never panics, whatever the three numbers are, including at the extremes
    /// where a wrapping add would answer the opposite of the truth.
    #[test]
    fn the_decision_is_total(
        used in any::<i64>(),
        charge in any::<i64>(),
        limit in any::<i64>(),
    ) {
        let _ = over_budget(used, charge, Some(limit));
        let _ = over_budget(used, charge, None);
    }

    /// Unlimited is unconditional. No combination of numbers refuses a write on
    /// a relay whose operator set no ceiling.
    #[test]
    fn unlimited_never_refuses(used in any::<i64>(), charge in any::<i64>()) {
        prop_assert!(!over_budget(used, charge, None));
    }

    /// Monotone in what is already stored: a workspace that holds more is never
    /// treated as holding less. This is the property a counter has to have for
    /// the refusal to be stable, and it is what a wrapping add breaks first.
    #[test]
    fn more_stored_is_never_more_room(
        low in 0i64..i64::MAX,
        extra in 0i64..1_000_000_000i64,
        charge in 0i64..1_048_576i64,
        limit in 0i64..i64::MAX,
    ) {
        let high = low.saturating_add(extra);
        if over_budget(low, charge, Some(limit)) {
            prop_assert!(over_budget(high, charge, Some(limit)));
        }
    }

    /// Monotone in the charge, for the same reason: a larger envelope is never
    /// easier to accept than a smaller one.
    #[test]
    fn a_bigger_envelope_is_never_cheaper(
        used in 0i64..i64::MAX,
        small in 0i64..1_048_576i64,
        extra in 0i64..1_048_576i64,
        limit in 0i64..i64::MAX,
    ) {
        let big = small.saturating_add(extra);
        if over_budget(used, small, Some(limit)) {
            prop_assert!(over_budget(used, big, Some(limit)));
        }
    }

    /// The exact boundary, over the whole range: a write that lands the total on
    /// the limit is inside it, and one byte more is outside it. Stated as a
    /// property rather than as three examples because the off-by-one here is a
    /// customer's message being refused.
    #[test]
    fn the_boundary_is_the_total_after_the_write(
        limit in 0i64..1_000_000_000_000i64,
        charge in 0i64..1_048_576i64,
    ) {
        prop_assume!(charge <= limit);
        let exactly = limit - charge;
        prop_assert!(!over_budget(exactly, charge, Some(limit)));
        prop_assert!(over_budget(exactly + 1, charge, Some(limit)));
    }

    /// A charge is the ciphertext's length, for any ciphertext the relay would
    /// accept, and it is never negative.
    #[test]
    fn a_charge_is_a_length(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        prop_assert_eq!(charge_of(&bytes), bytes.len() as i64);
        prop_assert!(charge_of(&bytes) >= 0);
    }

    /// The limit survives the wire in both directions.
    #[test]
    fn the_detail_round_trips(limit in any::<i64>()) {
        let encoded = limit_detail(limit);
        prop_assert_eq!(encoded.len(), 8);
        prop_assert_eq!(i64::from_be_bytes(encoded.try_into().unwrap()), limit);
    }

    /// Every configurable ceiling resolves to a decimal multiple, and a larger
    /// tier is never a smaller number of bytes.
    #[test]
    fn configured_gigabytes_are_decimal(gb in 0u64..1_000_000u64) {
        let config = config_with(Some(&gb.to_string()));
        prop_assert_eq!(limit_bytes(&config), Some(gb as i64 * BYTES_PER_GB));
    }
}
