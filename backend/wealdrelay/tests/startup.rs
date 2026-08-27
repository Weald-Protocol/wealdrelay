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
        Startup::Backup { .. } => panic!("expected a printed outcome, got a backup"),
        Startup::Restore { .. } => panic!("expected a printed outcome, got a restore"),
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
        Startup::Backup { request, .. } => {
            panic!("expected a serve, got a backup to {:?}", request.out)
        }
        Startup::Restore { request, .. } => {
            panic!("expected a serve, got a restore from {:?}", request.from)
        }
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
    // The identity line, then the protocol range the build serves: the number a
    // `push=unsupported` turns on, printed by the binary rather than inferred from
    // the digest it was created at (WEALD-L339).
    assert_eq!(version.stdout, BuildInfo::current().version_report());
    assert!(version.stdout.starts_with(&BuildInfo::current().line()));
    assert_eq!(
        version.stdout.lines().nth(1),
        Some(BuildInfo::current().protocol_line().as_str())
    );

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
        // Set explicitly, so the key still comes from the environment for the
        // source assertion below, but `off`: `Config::enforce_tls` refuses both
        // `acme` and `file` outright because the relay terminates TLS nowhere
        // yet, so `resolve` could never return the config this test describes.
        (keys::TLS, "off"),
        (keys::MAX_STORAGE_GB, "50"),
        (keys::RETENTION_DAYS, "unlimited"),
        (keys::WRITE_MODE, "read_only"),
        (keys::RELEASE_CHECK, "off"),
        (keys::METRICS_GROUP_LABELS, "on"),
        // With a Redis url set, which is how a deployment declares a second
        // instance, the ephemeral path has to be off or the configuration is
        // refused. See `two_instances_with_process_fanout_refuse_to_start`.
        (keys::LIVE, "off"),
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
    // The URLs that can carry a credential are named, not printed. Two here rather than
    // three: the SMTP url is still withheld, and now says it configures nothing, because
    // this relay has no SMTP client. See `invite::delivery` and WEALD-L072.
    assert_eq!(text.matches("[set, not printed]").count(), 2, "{text}");
    assert!(
        text.contains("[set, and unused: this relay sends no mail]"),
        "{text}"
    );
    assert!(!text.contains("smtp://mail:1025"), "{text}");
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

#[test]
fn two_instances_with_process_fanout_refuse_to_start() {
    // The refusal that keeps a multi-instance deployment from showing half a room.
    // Two relay processes each fanning out in process would show every member
    // exactly the half that happens to share their socket, with nothing anywhere
    // reporting a fault. A relay that will not start is a page a human reads; a
    // half room is one nobody ever sees.
    //
    // Asserted at startup rather than at fanout, because by the time a beat is
    // being fanned out the deployment is already live and the operator has already
    // been told everything is fine.
    let mut pairs: Vec<(&str, &str)> = vec![
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald:secret@db/relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
        (keys::REDIS_URL, "redis://cache:6379"),
    ];
    let outcome = printed(startup(
        Vec::<String>::new(),
        &Values::from_pairs(pairs.clone()),
    ));
    assert_eq!(outcome.code, wealdrelay::EXIT_CONFIG);
    assert!(
        outcome.stderr.contains(keys::LIVE_FANOUT),
        "{}",
        outcome.stderr
    );
    assert!(
        outcome.stderr.contains(keys::REDIS_URL),
        "{}",
        outcome.stderr
    );

    // And the escape hatch starts, because with no beats there is nothing to fail
    // to cross an instance boundary. Presence then reports unavailable, which is
    // honest, rather than showing half a room, which is not.
    pairs.push((keys::LIVE, "off"));
    match startup(Vec::<String>::new(), &Values::from_pairs(pairs)) {
        Startup::Serve(config) => assert_eq!(config.live_label(), "off"),
        Startup::Print(outcome) => panic!("expected a serve, got {outcome:?}"),
        Startup::Backup { request, .. } => {
            panic!("expected a serve, got a backup to {:?}", request.out)
        }
        Startup::Restore { request, .. } => {
            panic!("expected a serve, got a restore from {:?}", request.from)
        }
    }
}

#[test]
fn push_on_with_no_destination_refuses_to_start_and_names_the_variable() {
    // The startup half of `push.md` section 5's first refusal, at the level that
    // decides it. The operator's next action is to set one variable, so the message
    // has to name it.
    let mut pairs: Vec<(&str, &str)> = vec![
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald:secret@db/relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
        (keys::PUSH, "on"),
    ];
    let outcome = printed(startup(
        Vec::<String>::new(),
        &Values::from_pairs(pairs.clone()),
    ));
    assert_eq!(outcome.code, wealdrelay::EXIT_CONFIG);
    assert!(
        outcome.stderr.contains(keys::PUSH_URL),
        "{}",
        outcome.stderr
    );
    assert!(outcome.stdout.is_empty());

    // With a destination it serves, and the wake path is on.
    pairs.push((keys::PUSH_URL, "https://ringer.weald.team/v1/wake"));
    match startup(Vec::<String>::new(), &Values::from_pairs(pairs.clone())) {
        Startup::Serve(config) => assert_eq!(config.push_label(), "on"),
        Startup::Print(outcome) => panic!("expected a serve, got {outcome:?}"),
        Startup::Backup { request, .. } => {
            panic!("expected a serve, got a backup to {:?}", request.out)
        }
        Startup::Restore { request, .. } => {
            panic!("expected a serve, got a restore from {:?}", request.from)
        }
    }

    // And a plaintext destination on a real host does not start, because a handle in
    // cleartext is a wake capability anybody on the path can use.
    pairs.retain(|(key, _)| *key != keys::PUSH_URL);
    pairs.push((keys::PUSH_URL, "http://ringer.weald.team/v1/wake"));
    let outcome = printed(startup(Vec::<String>::new(), &Values::from_pairs(pairs)));
    assert_eq!(outcome.code, wealdrelay::EXIT_CONFIG);
    assert!(
        outcome.stderr.contains(keys::PUSH_URL),
        "{}",
        outcome.stderr
    );
}

#[test]
fn a_push_setting_with_push_off_refuses_to_start() {
    // A configured-and-ignored outbound destination reads as working and is not.
    let outcome = printed(startup(
        Vec::<String>::new(),
        &Values::from_pairs([
            (keys::HOSTNAME, "relay.acme.com"),
            (keys::DATABASE_URL, "postgres://weald:secret@db/relay"),
            (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
            (keys::PUSH_TOKEN, "a-bearer-nobody-will-ever-present"),
        ]),
    ));
    assert_eq!(outcome.code, wealdrelay::EXIT_CONFIG);
    assert!(
        outcome.stderr.contains(keys::PUSH_TOKEN),
        "{}",
        outcome.stderr
    );
    assert!(
        !outcome.stderr.contains("a-bearer-nobody-will-ever-present"),
        "the refusal named the secret it was refusing: {}",
        outcome.stderr
    );
}

#[test]
fn check_config_prints_the_wake_destination_and_never_the_bearer() {
    // The one value on this surface an operator most needs to read back is which
    // party is being handed their users' wake handles, so the url is printed. The
    // bearer is a shared secret and `--check-config` output is the first thing
    // anybody pastes into a support ticket, so it is `[set]` and nothing else.
    let values = Values::from_pairs([
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@db/relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
        (keys::PUSH, "on"),
        (keys::PUSH_URL, "https://ringer.weald.team/v1/wake"),
        (keys::PUSH_TOKEN, "sk-a-secret-nobody-should-paste"),
        (keys::PUSH_COALESCE_MS, "500"),
        (keys::PUSH_QUEUE, "64"),
    ]);
    let config = Config::resolve(&values).expect("the push configuration resolves");
    let text = describe_config(&config, &values);

    assert!(text.contains("https://ringer.weald.team/v1/wake"), "{text}");
    assert!(
        !text.contains("sk-a-secret-nobody-should-paste"),
        "the bearer was printed: {text}"
    );
    assert!(text.contains("500"), "{text}");
    assert!(text.contains("64"), "{text}");
    // The registration url is resolved rather than echoed, so an operator sees what
    // their devices are actually told rather than an empty column.
    assert!(
        text.contains("https://ringer.weald.team/v1/handles"),
        "{text}"
    );
    for key in [
        keys::PUSH,
        keys::PUSH_URL,
        keys::PUSH_TOKEN,
        keys::PUSH_REGISTER_URL,
        keys::PUSH_COALESCE_MS,
        keys::PUSH_QUEUE,
    ] {
        assert!(text.contains(key), "{key} is missing from the description");
    }

    // And with push off, the two url lines say what the relay will do rather than
    // leaving an operator to guess what an empty column means.
    let text = describe_config(&Config::resolve(&complete()).unwrap(), &complete());
    assert_eq!(text.matches("unset, push off").count(), 2, "{text}");
}
