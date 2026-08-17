// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Tier 2. Invariants over randomised input, per
//! `specs/backend/build/testing.md`. The seed is printed by proptest on
//! failure and is recorded in the ledger when one is found.

use proptest::prelude::*;
use wealdrelay::config::{keys, Values};
use wealdrelay::{run, startup, Invocation, Startup};

/// Case count comes from the environment so ci can run reduced counts on push
/// and full counts on a pull request, per `specs/backend/build/testing.md`, and
/// so the number lives in one place rather than in every suite.
fn config() -> ProptestConfig {
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
    #![proptest_config(config())]

    /// Parsing never panics and never hangs, whatever argv holds. argv is
    /// attacker-adjacent on a self-hosted relay: it comes from a unit file
    /// somebody else wrote.
    #[test]
    fn parsing_is_total(args in prop::collection::vec(".*", 0..6)) {
        let parsed = Invocation::parse(args.iter());
        // Every outcome is one of the four, and the unknown arm always
        // carries the argument it rejected so the message can name it.
        match parsed {
            Invocation::Unknown(ref a) => prop_assert_eq!(a, &args[0]),
            Invocation::Serve => prop_assert!(args.is_empty()),
            Invocation::CheckConfig => prop_assert_eq!(args[0].as_str(), "--check-config"),
            Invocation::Version | Invocation::Help => {
                prop_assert!(matches!(args[0].as_str(), "--version" | "-V" | "--help" | "-h"));
            }
            // The one subcommand with arguments of its own. Either it read an
            // `--out` or it refused with a message; it never guesses a path.
            Invocation::Backup(_) | Invocation::BackupUsage(_) => {
                prop_assert_eq!(args[0].as_str(), "backup");
            }
            // The other half of `backup`, and the same shape: it either read a
            // `--from` or it refused with a message naming what was wrong, and
            // it never guesses a source.
            Invocation::Restore(_) | Invocation::RestoreUsage(_) => {
                prop_assert_eq!(args[0].as_str(), "restore");
            }
        }
    }

    /// Only the arguments this build documents exit zero from `run`. Anything
    /// else is a usage error, never a silent success, because a relay that
    /// ignores a flag it does not understand is a relay running a configuration
    /// its operator does not have.
    ///
    /// `--check-config` and the empty invocation are excluded because `run` is a
    /// function of argv alone and both of those need a resolved configuration:
    /// they go through `startup`, which the property below covers.
    #[test]
    fn only_documented_flags_succeed(args in prop::collection::vec(".*", 0..6)) {
        let out = run(args.iter());
        let documented = matches!(
            args.first().map(String::as_str),
            Some("--version") | Some("-V") | Some("--help") | Some("-h")
        );
        prop_assert_eq!(out.code == 0, documented);
        prop_assert_eq!(out.stdout.is_empty(), !documented);
    }

    /// `startup` never serves without a complete configuration, whatever argv
    /// and the environment hold. This is the property behind the negative proof:
    /// a relay that started on a partial configuration would be writing
    /// somewhere its operator did not choose.
    #[test]
    fn startup_never_serves_without_a_complete_configuration(
        args in prop::collection::vec(".*", 0..3),
        hostname in prop::option::of("[a-z.]{1,20}"),
        database in prop::option::of("[a-z:/@.]{1,30}"),
        storage in prop::option::of("[a-z:/]{1,30}"),
    ) {
        let mut pairs: Vec<(String, String)> = Vec::new();
        if let Some(value) = &hostname {
            pairs.push((keys::HOSTNAME.to_string(), value.clone()));
        }
        if let Some(value) = &database {
            pairs.push((keys::DATABASE_URL.to_string(), value.clone()));
        }
        if let Some(value) = &storage {
            pairs.push((keys::STORAGE_URL.to_string(), value.clone()));
        }
        let values = Values::from_pairs(pairs);
        match startup(args.iter(), &values) {
            Startup::Serve(_) => {
                // Serving requires all three, and requires the two urls to have
                // parsed. Anything less must have printed instead.
                prop_assert!(args.is_empty());
                prop_assert!(hostname.is_some() && database.is_some() && storage.is_some());
            }
            Startup::Print(outcome) => {
                // Every refusal names something. An empty message would leave the
                // operator with an exit code and no next action.
                prop_assert!(!outcome.stdout.is_empty() || !outcome.stderr.is_empty());
            }
            Startup::Backup { .. } => {
                // Same configuration bar as serving: a backup reads the database
                // and the store, so it cannot be reached on a partial one either.
                prop_assert_eq!(args.first().map(String::as_str), Some("backup"));
                prop_assert!(hostname.is_some() && database.is_some() && storage.is_some());
            }
            Startup::Restore { .. } => {
                // A restore writes the database and the store, so it clears the
                // same bar for the same reason.
                prop_assert_eq!(args.first().map(String::as_str), Some("restore"));
                prop_assert!(hostname.is_some() && database.is_some() && storage.is_some());
            }
        }
    }

    /// The first argument decides, so trailing noise can never turn a usage
    /// error into a success.
    #[test]
    fn the_first_argument_decides(
        head in prop::sample::select(vec!["--version", "-V", "--help", "-h", "--nope", ""]),
        tail in prop::collection::vec(".*", 0..4),
    ) {
        let mut args = vec![head.to_string()];
        args.extend(tail);
        prop_assert_eq!(Invocation::parse(args.iter()), Invocation::parse([head]));
    }
}
