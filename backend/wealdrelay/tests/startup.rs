// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `startup`: argv plus the environment, resolved into an action.
//!
//! `src/main.rs` is a shell over this, so every branch a real operator can reach
//! is reachable here without a process. The process suites exist as well, because
//! a `main` nobody runs is where an argument handling mistake hides, but the
//! branches themselves are decided here.

use wealdrelay::config::{keys, Config, Source, Values};
use wealdrelay::{describe_config, run, startup, BuildInfo, Invocation, Outcome, Startup, USAGE};

fn complete() -> Values {
    Values::from_pairs([
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald:secret@db/relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
    ])
}

fn printed(startup: Startup) -> Outcome {
    match startup {
        Startup::Print(outcome) => outcome,
        Startup::Serve(_) => panic!("expected a printed outcome, got a serve"),
    }
}

#[test]
fn a_complete_configuration_and_no_arguments_serves() {
    match startup(Vec::<String>::new(), &complete()) {
        Startup::Serve(config) => {
            assert_eq!(config.hostname, "relay.acme.com");
            assert_eq!(config.listen, Config::DEFAULT_LISTEN);
        }
        Startup::Print(outcome) => panic!("expected a serve, got {outcome:?}"),
    }
}

#[test]
fn an_incomplete_configuration_prints_and_names_the_key_rather_than_serving() {
    // The negative proof, at the level that decides it. Every arm below must name
    // a variable, because the operator's next action is to edit one.
    for missing in [keys::HOSTNAME, keys::DATABASE_URL, keys::STORAGE_URL] {
        let mut pairs: Vec<(&str, &str)> = vec![
            (keys::HOSTNAME, "relay.acme.com"),
            (keys::DATABASE_URL, "postgres://weald@db/relay"),
            (keys::STORAGE_URL, "file:///blobs"),
        ];
        pairs.retain(|(key, _)| *key != missing);
        let outcome = printed(startup(Vec::<String>::new(), &Values::from_pairs(pairs)));
        assert_eq!(outcome.code, wealdrelay::EXIT_CONFIG);
        assert!(outcome.stdout.is_empty());
        assert!(outcome.stderr.contains(missing), "{}", outcome.stderr);
        assert!(
            outcome.stderr.starts_with("wealdrelay:"),
            "{}",
            outcome.stderr
        );
    }
}

#[test]
fn the_argv_only_invocations_do_not_consult_the_configuration() {
    // `--version` on a machine with no configuration at all must still answer.
    // Anything else would mean an operator could not ask what they were running
    // until they had finished configuring it.
    let empty = Values::from_pairs(Vec::<(&str, &str)>::new());
    let version = printed(startup(["--version"], &empty));
    assert_eq!(version.code, 0);
    assert_eq!(version.stdout, BuildInfo::current().line());

    let help = printed(startup(["--help"], &empty));
    assert_eq!(help.code, 0);
    assert_eq!(help.stdout, USAGE);

    let unknown = printed(startup(["--nope"], &empty));
    assert_eq!(unknown.code, 64);
    assert!(unknown.stderr.contains("--nope"));
    assert!(unknown.stderr.contains("usage: wealdrelay"));
}

#[test]
fn check_config_prints_the_resolved_configuration_and_exits_zero() {
    let outcome = printed(startup(["--check-config"], &complete()));
    assert_eq!(outcome.code, 0);
    assert!(outcome.stderr.is_empty());
    assert!(outcome.stdout.contains("relay.acme.com"));
    // Never the password. This output goes into support tickets.
    assert!(!outcome.stdout.contains("secret"), "{}", outcome.stdout);
}

#[test]
fn check_config_refuses_what_serving_refuses() {
    let outcome = printed(startup(
        ["--check-config"],
        &Values::from_pairs(Vec::<(&str, &str)>::new()),
    ));
    assert_eq!(outcome.code, wealdrelay::EXIT_CONFIG);
    assert!(outcome.stderr.contains(keys::HOSTNAME));
}

#[test]
fn the_description_names_every_key_with_its_source() {
    // Every key, not only the ones that were set. An operator debugging a value
    // they did not set needs to see that it took the default.
    let values = Values::from_pairs([
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald:secret@db/relay"),
        (keys::STORAGE_URL, "s3://blobs/prefix"),
        (keys::REDIS_URL, "redis://cache:6379"),
        (keys::SMTP_URL, "smtp://mail:1025"),
        (keys::BOOTSTRAP_HANDOFF_PUBKEY, "abc"),
        (keys::TLS, "acme"),
        (keys::MAX_STORAGE_GB, "50"),
        (keys::RETENTION_DAYS, "unlimited"),
        (keys::WRITE_MODE, "read_only"),
        (keys::RELEASE_CHECK, "off"),
        (keys::METRICS_GROUP_LABELS, "on"),
    ]);
    let config = Config::resolve(&values).unwrap();
    let text = describe_config(&config, &values);

    for key in keys::ALL {
        assert!(text.contains(key), "{key} is missing from the description");
    }
    assert!(text.contains("s3://blobs/prefix"));
    assert!(text.contains("read_only"));
    assert!(text.contains("unlimited"));
    assert!(text.contains("50"));
    // The three URLs that can carry a credential are named, not printed.
    assert_eq!(text.matches("[set, not printed]").count(), 3, "{text}");
    assert!(text.contains("[set]"), "{text}");
    assert!(!text.contains("secret"), "{text}");
    assert!(!text.contains("redis://cache"), "{text}");
    // On and off render as the words the configuration accepts, so an operator can
    // copy a line back into their environment file.
    assert!(text.contains("off"));
    assert!(text.contains("on"));
    assert_eq!(values.source_of(keys::TLS), Source::Environment);
}

#[test]
fn the_description_of_an_unset_optional_says_what_the_relay_will_do() {
    // "unset" alone would leave an operator wondering what that means for Redis.
    let config = Config::resolve(&complete()).unwrap();
    let text = describe_config(&config, &complete());
    assert!(text.contains("unset, single-process mode"), "{text}");
    assert!(text.contains("file:///var/lib/wealdrelay/blobs"), "{text}");
    // An s3 target with no prefix renders without a trailing slash.
    let values = Values::from_pairs([
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@db/relay"),
        (keys::STORAGE_URL, "s3://plain-bucket"),
    ]);
    let text = describe_config(&Config::resolve(&values).unwrap(), &values);
    assert!(text.contains("s3://plain-bucket"), "{text}");
    assert!(!text.contains("s3://plain-bucket/"), "{text}");
}

#[test]
fn run_and_startup_agree_about_the_argv_only_invocations() {
    // `run` exists because the property suite and the older tests use it. If the
    // two ever disagreed, one of them would be testing a path the binary does not
    // take.
    let empty = Values::from_pairs(Vec::<(&str, &str)>::new());
    for args in [vec!["--version"], vec!["--help"], vec!["--nope"]] {
        let direct = run(args.iter());
        let through = printed(startup(args.iter(), &empty));
        assert_eq!(direct, through, "{args:?}");
    }
}

#[test]
fn the_startup_action_is_debuggable() {
    // It is formatted into a panic message by the tests above and by anybody
    // debugging a start, so an unformattable action would be a dead end.
    let action = startup(Vec::<String>::new(), &complete());
    assert!(format!("{action:?}").contains("Serve"));
    assert!(format!("{:?}", Invocation::CheckConfig).contains("CheckConfig"));
}
