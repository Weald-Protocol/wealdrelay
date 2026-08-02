// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The hosted profile refuses what `specs/backend/relay/server.md` says it must.
//!
//! Step 13's negative proof is one line of that spec: `SMTP_URL` set on a
//! hosted-profile build is refused at startup. The other three refusals are here
//! for the same reason: they are the settings the spec says are not
//! customer-configurable on the hosted tier, and a rule that is only written down
//! is a rule that will be configured around.
//!
//! Every case goes through `startup`, not through `profile::enforce` alone,
//! because the claim is about a relay refusing to start rather than about a
//! function returning an error. `startup` is the whole of `main` as a pure
//! function, so a `Startup::Print` with `EXIT_CONFIG` here is the same outcome as
//! a process exiting 78.

use wealdrelay::config::{Config, ConfigError, Values};
use wealdrelay::profile::{enforce, Profile};
use wealdrelay::{startup, Startup, EXIT_CONFIG};

/// The three required variables and nothing else, plus whatever the case adds.
fn values(extra: &[(&str, &str)]) -> Values {
    let mut pairs: Vec<(String, String)> = vec![
        ("WEALD_RELAY_HOSTNAME".into(), "relay.acme.com".into()),
        (
            "WEALD_RELAY_DATABASE_URL".into(),
            "postgres://relay@localhost/relay".into(),
        ),
        ("WEALD_RELAY_STORAGE_URL".into(), "s3://blobs".into()),
    ];
    for (key, value) in extra {
        pairs.push(((*key).to_string(), (*value).to_string()));
    }
    Values::from_pairs(pairs)
}

fn resolve(extra: &[(&str, &str)]) -> Result<Config, ConfigError> {
    Config::resolve(&values(extra))
}

/// The message a refused startup writes to stderr, or a panic naming what
/// happened instead. A test that accepted a successful start here would be
/// asserting the opposite of the thing under test.
fn refusal(extra: &[(&str, &str)]) -> String {
    match startup(Vec::<String>::new(), &values(extra)) {
        Startup::Print(outcome) => {
            assert_eq!(
                outcome.code, EXIT_CONFIG,
                "a refused configuration must exit EX_CONFIG so an init system \
                 can tell it apart from a crash"
            );
            assert!(outcome.stdout.is_empty());
            outcome.stderr
        }
        Startup::Serve(_) => panic!("this configuration was supposed to be refused"),
    }
}

#[test]
fn the_default_profile_is_self_host() {
    let config = resolve(&[]).expect("the three required variables are a complete configuration");
    assert_eq!(config.profile, Profile::SelfHost);
}

#[test]
fn both_profiles_parse_and_an_unknown_one_is_named_back() {
    assert_eq!(
        resolve(&[("WEALD_RELAY_PROFILE", "self_host")])
            .unwrap()
            .profile,
        Profile::SelfHost
    );
    assert_eq!(
        resolve(&[
            ("WEALD_RELAY_PROFILE", "hosted"),
            ("WEALD_RELAY_MIN_ENC", "mls"),
        ])
        .unwrap()
        .profile,
        Profile::Hosted
    );
    // Not coerced. `Hosted` is not `hosted`, and reading a typo as a permissive
    // value is how a deployment ends up in a posture nobody chose.
    let error = resolve(&[("WEALD_RELAY_PROFILE", "Hosted")]).unwrap_err();
    assert_eq!(error.key(), Some("WEALD_RELAY_PROFILE"));
    assert!(error.to_string().contains("self_host, hosted"));
}

// --- the negative proof, four settings --------------------------------------

#[test]
fn smtp_url_on_a_hosted_profile_is_refused_at_startup() {
    let message = refusal(&[
        ("WEALD_RELAY_PROFILE", "hosted"),
        ("WEALD_RELAY_SMTP_URL", "smtp://mail.acme.com:587"),
    ]);
    assert!(message.contains("WEALD_RELAY_SMTP_URL"), "{message}");
    assert!(message.contains("hosted"), "{message}");
    // The reason, not just the refusal. An operator who is told no and not told
    // why will try the next flag that looks similar.
    assert!(message.contains("invitee email addresses"), "{message}");
}

#[test]
fn the_same_smtp_url_is_accepted_on_a_self_host_profile() {
    // The mirror image of the case above, and the reason this is a profile
    // rather than a deletion: self-hosters may send invite mail.
    let config = resolve(&[("WEALD_RELAY_SMTP_URL", "smtp://mail.acme.com:587")])
        .expect("smtp is self-host only, not forbidden");
    assert_eq!(config.smtp_url.as_deref(), Some("smtp://mail.acme.com:587"));
    assert_eq!(config.profile, Profile::SelfHost);
}

#[test]
fn access_set_off_on_a_hosted_profile_is_refused() {
    let message = refusal(&[
        ("WEALD_RELAY_PROFILE", "hosted"),
        ("WEALD_RELAY_ACCESS_SET", "off"),
    ]);
    assert!(message.contains("WEALD_RELAY_ACCESS_SET"), "{message}");
    assert!(message.contains("customer-configurable"), "{message}");
}

#[test]
fn a_hosted_profile_that_does_not_pin_mls_is_refused() {
    let message = refusal(&[
        ("WEALD_RELAY_PROFILE", "hosted"),
        ("WEALD_RELAY_MIN_ENC", "none"),
        ("WEALD_RELAY_ACCESS_SET", "enforce"),
    ]);
    assert!(message.contains("WEALD_RELAY_MIN_ENC"), "{message}");
    assert!(message.contains("pins mls"), "{message}");
}

#[test]
fn per_group_metric_labels_on_a_hosted_profile_are_refused() {
    let message = refusal(&[
        ("WEALD_RELAY_PROFILE", "hosted"),
        ("WEALD_RELAY_MIN_ENC", "mls"),
        ("WEALD_RELAY_METRICS_GROUP_LABELS", "on"),
    ]);
    assert!(
        message.contains("WEALD_RELAY_METRICS_GROUP_LABELS"),
        "{message}"
    );
    assert!(message.contains("not offered"), "{message}");
}

#[test]
fn a_hosted_profile_that_obeys_every_rule_starts() {
    // The positive case matters as much as the four refusals: a rule set that
    // refused everything would pass every negative test and ship nothing.
    let config = resolve(&[
        ("WEALD_RELAY_PROFILE", "hosted"),
        ("WEALD_RELAY_MIN_ENC", "mls"),
        ("WEALD_RELAY_ACCESS_SET", "enforce"),
    ])
    .expect("a compliant hosted configuration must start");
    assert_eq!(config.profile, Profile::Hosted);
    assert!(enforce(&config).is_ok());
    assert!(matches!(
        startup(
            Vec::<String>::new(),
            &values(&[
                ("WEALD_RELAY_PROFILE", "hosted"),
                ("WEALD_RELAY_MIN_ENC", "mls"),
            ])
        ),
        Startup::Serve(_)
    ));
}

#[test]
fn a_self_host_profile_may_set_every_one_of_the_four() {
    // None of these four settings is forbidden in itself. They are forbidden on
    // one deployment, which is what makes this a profile and not a validation
    // rule.
    let config = resolve(&[
        ("WEALD_RELAY_PROFILE", "self_host"),
        ("WEALD_RELAY_SMTP_URL", "smtp://mail.acme.com:587"),
        ("WEALD_RELAY_ACCESS_SET", "off"),
        ("WEALD_RELAY_MIN_ENC", "none"),
        ("WEALD_RELAY_METRICS_GROUP_LABELS", "on"),
    ])
    .expect("a self-hoster owns all four of these decisions");
    assert!(enforce(&config).is_ok());
}

// --- the surfaces that report it --------------------------------------------

#[test]
fn check_config_prints_the_profile_and_where_it_came_from() {
    let values = values(&[
        ("WEALD_RELAY_PROFILE", "hosted"),
        ("WEALD_RELAY_MIN_ENC", "mls"),
    ]);
    match startup(["--check-config"], &values) {
        Startup::Print(outcome) => {
            assert_eq!(outcome.code, 0);
            assert!(
                outcome.stdout.contains("WEALD_RELAY_PROFILE"),
                "{}",
                outcome.stdout
            );
            assert!(outcome.stdout.contains("hosted"), "{}", outcome.stdout);
            assert!(outcome.stdout.contains("environment"), "{}", outcome.stdout);
        }
        Startup::Serve(_) => panic!("--check-config never serves"),
    }
}

#[test]
fn check_config_reports_the_refusal_rather_than_the_configuration() {
    // The thing an operator runs when a relay will not start has to tell them
    // the same thing the relay told them, or they will conclude the
    // configuration is fine.
    match startup(
        ["--check-config"],
        &values(&[
            ("WEALD_RELAY_PROFILE", "hosted"),
            ("WEALD_RELAY_SMTP_URL", "smtp://mail.acme.com:587"),
        ]),
    ) {
        Startup::Print(outcome) => {
            assert_eq!(outcome.code, EXIT_CONFIG);
            assert!(outcome.stderr.contains("WEALD_RELAY_SMTP_URL"));
        }
        Startup::Serve(_) => panic!("--check-config never serves"),
    }
}

#[test]
fn the_profile_can_come_from_relay_toml_too() {
    // The compose bundle ships a file and the one-click templates set variables.
    // A profile that could only be set one way would be unusable on one of them.
    let directory = tempfile::tempdir().expect("a temp dir");
    let path = directory.path().join("relay.toml");
    std::fs::write(
        &path,
        "[relay]\nprofile = \"hosted\"\nmin_enc = \"mls\"\nsmtp_url = \"smtp://x:1\"\n",
    )
    .expect("write relay.toml");
    let values = values(&[]).with_file(Some(&path)).expect("read relay.toml");
    let error = Config::resolve(&values).expect_err("the file's smtp_url must be refused too");
    assert_eq!(error.key(), Some("WEALD_RELAY_SMTP_URL"));
}

#[test]
fn the_refusal_error_names_its_key_and_prints_its_reason() {
    let error = ConfigError::RefusedOnHostedProfile {
        key: "WEALD_RELAY_SMTP_URL",
        reason: "because the spec says so",
    };
    assert_eq!(error.key(), Some("WEALD_RELAY_SMTP_URL"));
    let rendered = error.to_string();
    assert!(
        rendered.contains("WEALD_RELAY_PROFILE=hosted"),
        "{rendered}"
    );
    assert!(rendered.contains("because the spec says so"), "{rendered}");
    assert_eq!(error.clone(), error);
    assert!(format!("{error:?}").contains("RefusedOnHostedProfile"));
}
