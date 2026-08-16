// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Configuration parsing, including every invalid combination.
//!
//! Step 3's unit gate is "config parsing, including every invalid combination, at
//! the floor" (`specs/backend/build/phases-relay.md`). "Every invalid combination"
//! is read literally here: every key that has a closed set of values is offered a
//! value outside it, every key that is a number is offered something that is not,
//! and both required-but-missing and set-but-empty are separate cases because they
//! are separate operator mistakes.

use wealdrelay::config::{
    keys, AccessSetMode, CallMode, Config, ConfigError, Limit, LiveFanout, LiveMode, MinEncryption,
    PushMode, Source, StorageTarget, TlsMode, Values, WriteMode,
};

/// The three required keys, valid, and nothing else. Every test starts here and
/// changes one thing, so a failure names one variable.
fn minimal() -> Vec<(&'static str, &'static str)> {
    vec![
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@localhost/weald_relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
    ]
}

fn with(key: &'static str, value: &'static str) -> Values {
    let mut pairs = minimal();
    pairs.retain(|(existing, _)| *existing != key);
    pairs.push((key, value));
    Values::from_pairs(pairs)
}

fn resolve(key: &'static str, value: &'static str) -> Result<Config, ConfigError> {
    Config::resolve(&with(key, value))
}

/// Resolve with several keys set at once, for the rules that are about a
/// combination rather than a single value.
fn resolve_with(pairs: &[(&'static str, &'static str)]) -> Result<Config, ConfigError> {
    let mut values = minimal();
    for (key, value) in pairs {
        values.retain(|(existing, _)| existing != key);
        values.push((key, value));
    }
    Config::resolve(&Values::from_pairs(values))
}

// MARK: The defaults

#[test]
fn the_three_required_keys_are_a_complete_configuration() {
    // The claim in `server.md` is that a minimum viable deployment is the binary,
    // Postgres and a disk. If anything else were required, that claim would be
    // false and this test would say so.
    let config = Config::resolve(&Values::from_pairs(minimal())).expect("minimal config resolves");
    assert_eq!(config.hostname, "relay.acme.com");
    assert_eq!(
        config.storage,
        StorageTarget::Filesystem("/var/lib/wealdrelay/blobs".into())
    );
    assert_eq!(config.listen, Config::DEFAULT_LISTEN);
    assert_eq!(
        config.observability_listen,
        Config::DEFAULT_OBSERVABILITY_LISTEN
    );
    assert_eq!(config.tls, TlsMode::Off);
    assert_eq!(config.max_storage_gb, Limit::Unlimited);
    assert_eq!(config.retention_days, Limit::Unlimited);
    assert_eq!(config.write_mode, WriteMode::Full);
    assert!(config.redis_url.is_none());
    assert!(config.smtp_url.is_none());
    assert!(config.bootstrap_handoff_pubkey.is_none());
}

#[test]
fn access_set_defaults_to_enforce_and_the_release_check_defaults_to_on() {
    // `enforce` by default is load-bearing: `environments.md` puts it at `enforce`
    // in every environment including local, so nobody develops against the
    // permissive path and discovers the difference in staging.
    let config = Config::resolve(&Values::from_pairs(minimal())).unwrap();
    assert_eq!(config.access_set, AccessSetMode::Enforce);
    assert!(config.release_check);
    // Per-group metric labels default off, and are never on in the hosted tier.
    assert!(!config.metrics_group_labels);
}

#[test]
fn the_encryption_floor_defaults_to_none_so_a_self_hosted_rollout_is_possible() {
    // `migration.md` has phases where envelopes are signed and not encrypted. A
    // default of `mls` would make a self-hoster's Phase 2 impossible. The hosted
    // tier pins `mls`, which is a property of that deployment.
    let config = Config::resolve(&Values::from_pairs(minimal())).unwrap();
    assert_eq!(config.min_encryption, MinEncryption::None);
    assert_eq!(config.min_enc_label(), "none");
    assert_eq!(
        resolve(keys::MIN_ENC, "mls").unwrap().min_enc_label(),
        "mls"
    );
}

// MARK: Missing and empty

#[test]
fn every_required_key_is_named_when_it_is_missing() {
    // The negative proof for step 3, at the unit level: an operator whose relay
    // will not start must be told which variable to fix.
    for required in [keys::HOSTNAME, keys::DATABASE_URL, keys::STORAGE_URL] {
        let mut pairs = minimal();
        pairs.retain(|(key, _)| *key != required);
        let error = Config::resolve(&Values::from_pairs(pairs)).expect_err("must refuse");
        assert_eq!(error, ConfigError::Missing { key: required });
        assert!(
            error.to_string().contains(required),
            "the message must name {required}, got: {error}"
        );
        assert_eq!(error.key(), Some(required));
    }
}

#[test]
fn a_key_set_to_nothing_is_refused_rather_than_read_as_unset() {
    // `FOO=` in a compose file is almost always a variable somebody meant to fill
    // in. Reading it as absent would start the relay in a posture nobody chose,
    // and for `STORAGE_URL` it would mean silently choosing a directory.
    for key in [
        keys::HOSTNAME,
        keys::DATABASE_URL,
        keys::STORAGE_URL,
        keys::REDIS_URL,
        keys::LISTEN,
        keys::TLS,
        keys::ACCESS_SET,
        keys::SMTP_URL,
    ] {
        let error = resolve(key, "   ").expect_err("an empty value must be refused");
        assert_eq!(error, ConfigError::Empty { key });
        assert!(error.to_string().contains(key));
    }
}

// MARK: Every closed set

#[test]
fn a_value_outside_a_closed_set_is_refused_and_the_allowed_values_are_listed() {
    // Refused and never coerced. `WEALD_RELAY_TLS=of` is not `off`: two of these
    // keys decide security posture, and reading a typo as a permissive default is
    // how a deployment ends up somewhere nobody chose.
    let cases: &[(&'static str, &'static str, &'static str)] = &[
        (keys::TLS, "of", "acme, file, off"),
        (keys::ACCESS_SET, "enforced", "enforce, off"),
        (keys::ACCESS_SET, "ENFORCE", "enforce, off"),
        (keys::MIN_ENC, "MLS", "none, mls"),
        (keys::MIN_ENC, "plaintext", "none, mls"),
        (keys::WRITE_MODE, "readonly", "full, read_only"),
        (keys::WRITE_MODE, "read-only", "full, read_only"),
        (keys::RELEASE_CHECK, "true", "on, off"),
        (keys::METRICS_GROUP_LABELS, "yes", "on, off"),
    ];
    for (key, value, allowed) in cases {
        let error = resolve(key, value).expect_err("must refuse");
        assert_eq!(
            error,
            ConfigError::NotAllowed {
                key,
                value: (*value).to_string(),
                allowed,
            }
        );
        let message = error.to_string();
        assert!(message.contains(key), "{message}");
        assert!(message.contains(allowed), "{message}");
    }
}

#[test]
fn every_permitted_value_of_every_closed_set_is_accepted() {
    // The other half: a spec value this build refuses would be a deployment path
    // that cannot be configured.
    // `acme` and `file` parse into their variants but are refused later by
    // `enforce_tls`, because nothing in this build wraps the listener. Parsing is
    // asserted here; the refusal is asserted in
    // `a_tls_mode_is_refused_because_nothing_in_this_build_wraps_the_listener`.
    assert_eq!(resolve(keys::TLS, "off").unwrap().tls, TlsMode::Off);
    assert_eq!(
        resolve(keys::ACCESS_SET, "off").unwrap().access_set,
        AccessSetMode::Off
    );
    assert_eq!(
        resolve(keys::ACCESS_SET, "enforce")
            .unwrap()
            .access_set_label(),
        "enforce"
    );
    assert_eq!(
        resolve(keys::ACCESS_SET, "off").unwrap().access_set_label(),
        "off"
    );
    assert_eq!(
        resolve(keys::WRITE_MODE, "read_only").unwrap().write_mode,
        WriteMode::ReadOnly
    );
    assert_eq!(
        resolve(keys::WRITE_MODE, "full").unwrap().write_mode,
        WriteMode::Full
    );
    assert!(!resolve(keys::RELEASE_CHECK, "off").unwrap().release_check);
    assert!(resolve(keys::RELEASE_CHECK, "on").unwrap().release_check);
    assert!(
        resolve(keys::METRICS_GROUP_LABELS, "on")
            .unwrap()
            .metrics_group_labels
    );
}

// MARK: URLs

#[test]
fn a_database_url_that_is_not_postgres_is_refused() {
    for value in [
        "mysql://host/db",
        "http://host/db",
        "postgres",
        "not a url at all",
        "/var/lib/postgres",
    ] {
        let error = resolve(keys::DATABASE_URL, value).expect_err("must refuse");
        assert!(
            matches!(error, ConfigError::NotAPostgresUrl { .. }),
            "{error}"
        );
        assert!(error.to_string().contains(keys::DATABASE_URL));
    }
    // Both spellings the driver accepts.
    for value in [
        "postgres://weald:secret@localhost:5432/weald_relay",
        "postgresql://weald@localhost/weald_relay?sslmode=require",
    ] {
        assert_eq!(
            resolve(keys::DATABASE_URL, value).unwrap().database_url,
            value
        );
    }
}

#[test]
fn a_storage_url_must_be_file_or_s3() {
    for value in [
        "redis://host",
        "https://bucket.example.com",
        "bucket",
        "s3://",
    ] {
        let error = resolve(keys::STORAGE_URL, value).expect_err("must refuse");
        assert!(
            matches!(error, ConfigError::NotAStorageUrl { .. }),
            "{error}"
        );
        assert!(error.to_string().contains(keys::STORAGE_URL));
    }
}

#[test]
fn an_s3_url_carries_its_bucket_and_optional_prefix() {
    // The prefix matters: a self-hoster sharing one bucket between staging and
    // production needs the two to land in different key spaces, and a prefix that
    // was silently dropped would mix them.
    assert_eq!(
        resolve(keys::STORAGE_URL, "s3://weald-blobs")
            .unwrap()
            .storage,
        StorageTarget::S3 {
            bucket: "weald-blobs".to_string(),
            prefix: String::new(),
        }
    );
    assert_eq!(
        resolve(keys::STORAGE_URL, "s3://weald-blobs/staging/")
            .unwrap()
            .storage,
        StorageTarget::S3 {
            bucket: "weald-blobs".to_string(),
            prefix: "staging".to_string(),
        }
    );
}

#[test]
fn a_file_url_must_name_an_absolute_path() {
    // `file://blobs` is a URL with `blobs` as its host and no path, which is not a
    // directory. Accepting it would put the relay's storage somewhere unrelated to
    // what the operator wrote.
    let error = resolve(keys::STORAGE_URL, "file://blobs").expect_err("must refuse");
    assert!(
        matches!(error, ConfigError::NotAStorageUrl { .. }),
        "{error}"
    );
}

// MARK: Addresses and numbers

#[test]
fn a_listen_address_must_be_host_and_port() {
    for key in [keys::LISTEN, keys::OBSERVABILITY_LISTEN] {
        for value in [
            "8443",
            "0.0.0.0",
            "0.0.0.0:notaport",
            "0.0.0.0:99999",
            ":8443",
        ] {
            let error = resolve(key, value).expect_err("must refuse");
            assert_eq!(
                error,
                ConfigError::NotAnAddress {
                    key,
                    value: value.to_string()
                }
            );
            assert!(error.to_string().contains(key));
        }
    }
    // IPv6 in brackets survives, which is why the split is from the right.
    assert_eq!(
        resolve(keys::LISTEN, "[::1]:8443").unwrap().listen,
        "[::1]:8443"
    );
    assert_eq!(
        resolve(keys::OBSERVABILITY_LISTEN, "127.0.0.1:9090")
            .unwrap()
            .observability_listen,
        "127.0.0.1:9090"
    );
}

/// A capacity of zero is a relay that boots, reports ready and then refuses every
/// write with a quota error the operator never asked for. Refused at boot naming
/// the variable, while `unlimited` still means no ceiling.
#[test]
fn a_zero_capacity_is_refused_at_boot_rather_than_starving_every_write() {
    for key in [keys::MAX_STORAGE_GB, keys::MAX_LOG_GB] {
        let error = resolve(key, "0").expect_err("zero is refused");
        assert_eq!(error, ConfigError::ZeroLimit { key });
        assert_eq!(error.key(), Some(key));
        assert!(resolve(key, "unlimited").is_ok());
    }
    assert_eq!(
        resolve(keys::MAX_LOG_GB, "unlimited").unwrap().max_log_gb,
        Limit::Unlimited
    );
    assert_eq!(
        resolve(keys::MAX_STORAGE_GB, "unlimited")
            .unwrap()
            .max_storage_gb,
        Limit::Unlimited
    );
}

#[test]
fn a_limit_is_a_number_or_the_word_unlimited() {
    for key in [keys::MAX_STORAGE_GB, keys::RETENTION_DAYS] {
        assert_eq!(
            resolve(key, "unlimited").unwrap().hostname,
            "relay.acme.com"
        );
        for value in ["lots", "-1", "7.5", "7 days"] {
            let error = resolve(key, value).expect_err("must refuse");
            assert_eq!(
                error,
                ConfigError::NotANumber {
                    key,
                    value: value.to_string()
                }
            );
        }
    }
    assert_eq!(
        resolve(keys::RETENTION_DAYS, "7").unwrap().retention_days,
        Limit::Of(7)
    );
    assert_eq!(
        resolve(keys::MAX_STORAGE_GB, "1").unwrap().max_storage_gb,
        Limit::Of(1)
    );
    assert_eq!(
        resolve(keys::MAX_STORAGE_GB, "UNLIMITED")
            .unwrap()
            .max_storage_gb,
        Limit::Unlimited
    );
}

// MARK: Optional passthroughs

#[test]
fn the_optional_urls_are_carried_verbatim() {
    // With the ephemeral path off, because a Redis url is how `server.md` says a
    // deployment declares more than one instance and `process` fanout is refused in
    // that combination. The setting under test here is the passthrough, not the
    // refusal, which has its own test below.
    assert_eq!(
        resolve_with(&[
            (keys::REDIS_URL, "redis://localhost:6379"),
            (keys::LIVE, "off"),
        ])
        .unwrap()
        .redis_url
        .as_deref(),
        Some("redis://localhost:6379")
    );
    assert_eq!(
        resolve(keys::SMTP_URL, "smtp://localhost:1025")
            .unwrap()
            .smtp_url
            .as_deref(),
        Some("smtp://localhost:1025")
    );
    assert_eq!(
        resolve(keys::BOOTSTRAP_HANDOFF_PUBKEY, "abc123")
            .unwrap()
            .bootstrap_handoff_pubkey
            .as_deref(),
        Some("abc123")
    );
}

// MARK: relay.toml

#[test]
fn a_missing_relay_toml_is_not_an_error() {
    // The file is optional and the variables alone are a complete configuration.
    let values = Values::from_pairs(minimal())
        .with_file(Some(std::path::Path::new("/nonexistent/relay.toml")))
        .expect("an absent file is not a failure");
    assert!(Config::resolve(&values).is_ok());
    // Passing no path at all is the same.
    let values = Values::from_pairs(minimal()).with_file(None).unwrap();
    assert!(Config::resolve(&values).is_ok());
}

#[test]
fn relay_toml_supplies_values_and_the_environment_wins() {
    // The order is load-bearing: the compose bundle ships a file and the one-click
    // templates set variables, so a template that could not override the bundled
    // file would be unable to set the hostname.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("relay.toml");
    std::fs::write(
        &file,
        r#"
WEALD_RELAY_HOSTNAME = "from-file.example.com"
WEALD_RELAY_DATABASE_URL = "postgres://weald@file/relay"
WEALD_RELAY_STORAGE_URL = "file:///from/file"
WEALD_RELAY_RETENTION_DAYS = 7
WEALD_RELAY_RELEASE_CHECK = "off"
"#,
    )
    .unwrap();

    // File alone.
    let values = Values::from_pairs(Vec::<(&str, &str)>::new())
        .with_file(Some(&file))
        .unwrap();
    let config = Config::resolve(&values).unwrap();
    assert_eq!(config.hostname, "from-file.example.com");
    assert_eq!(config.retention_days, Limit::Of(7));
    assert!(!config.release_check);
    assert_eq!(values.source_of(keys::HOSTNAME), Source::File);
    assert_eq!(values.source_of(keys::LISTEN), Source::Default);

    // Environment over file.
    let values = Values::from_pairs([(keys::HOSTNAME, "from-env.example.com")])
        .with_file(Some(&file))
        .unwrap();
    let config = Config::resolve(&values).unwrap();
    assert_eq!(config.hostname, "from-env.example.com");
    assert_eq!(values.source_of(keys::HOSTNAME), Source::Environment);
    assert_eq!(values.source_of(keys::DATABASE_URL), Source::File);
}

#[test]
fn a_relay_table_may_use_short_lowercase_keys() {
    // What the compose bundle ships: repeating the prefix on every line of a file
    // that is only about the relay is noise.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("relay.toml");
    std::fs::write(
        &file,
        r#"
[relay]
hostname = "short.example.com"
database_url = "postgres://weald@short/relay"
storage_url = "file:///short"
access_set = "off"
"#,
    )
    .unwrap();
    let values = Values::from_pairs(Vec::<(&str, &str)>::new())
        .with_file(Some(&file))
        .unwrap();
    let config = Config::resolve(&values).unwrap();
    assert_eq!(config.hostname, "short.example.com");
    assert_eq!(config.access_set, AccessSetMode::Off);
}

#[test]
fn a_relay_toml_naming_something_that_is_not_a_relay_key_is_refused() {
    // A config file key that silently does nothing is the same failure as a
    // mistyped variable, and harder to notice because it looks deliberate.
    let dir = tempfile::tempdir().unwrap();
    for (body, expected_key) in [
        ("WEALD_RELAY_HOSTNMAE = \"typo\"\n", "WEALD_RELAY_HOSTNMAE"),
        ("[relay]\nhostnmae = \"typo\"\n", "WEALD_RELAY_HOSTNMAE"),
        ("STRIPE_KEY = \"nope\"\n", "STRIPE_KEY"),
    ] {
        let file = dir.path().join(format!("relay-{expected_key}.toml"));
        std::fs::write(&file, body).unwrap();
        let error = Values::from_pairs(Vec::<(&str, &str)>::new())
            .with_file(Some(&file))
            .expect_err("must refuse");
        match &error {
            ConfigError::UnknownFileKey { key, path } => {
                assert_eq!(key, expected_key);
                assert!(path.contains("relay-"));
            }
            other => panic!("expected an unknown key, got {other}"),
        }
        assert_eq!(error.key(), Some(expected_key));
    }
}

#[test]
fn a_relay_toml_that_is_not_valid_toml_is_refused_with_the_parser_message() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("relay.toml");
    std::fs::write(&file, "this is not = = toml\n").unwrap();
    let error = Values::from_pairs(Vec::<(&str, &str)>::new())
        .with_file(Some(&file))
        .expect_err("must refuse");
    assert!(
        matches!(error, ConfigError::MalformedFile { .. }),
        "{error}"
    );
    assert!(error.key().is_none());
}

#[test]
fn a_relay_toml_value_that_is_not_a_scalar_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    for (body, expected) in [
        (
            "WEALD_RELAY_HOSTNAME = [\"a\", \"b\"]\n",
            "WEALD_RELAY_HOSTNAME",
        ),
        ("[relay]\nhostname = { a = 1 }\n", "WEALD_RELAY_HOSTNAME"),
        ("[relay.hostname]\na = 1\n", "WEALD_RELAY_HOSTNAME"),
    ] {
        let file = dir
            .path()
            .join(format!("relay-scalar-{}.toml", expected.len()));
        std::fs::write(&file, body).unwrap();
        let error = Values::from_pairs(Vec::<(&str, &str)>::new())
            .with_file(Some(&file))
            .expect_err("must refuse");
        assert!(
            matches!(error, ConfigError::NonScalarFileValue { .. }),
            "{body} gave {error}"
        );
        assert_eq!(error.key(), Some(expected));
    }
}

#[test]
fn a_relay_key_that_is_not_a_table_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("relay.toml");
    std::fs::write(&file, "relay = \"nope\"\n").unwrap();
    let error = Values::from_pairs(Vec::<(&str, &str)>::new())
        .with_file(Some(&file))
        .expect_err("must refuse");
    assert!(
        matches!(&error, ConfigError::NonScalarFileValue { key, .. } if key == "relay"),
        "{error}"
    );
}

#[test]
fn a_relay_toml_that_cannot_be_read_is_refused_rather_than_ignored() {
    // A file that is there and unreadable is a permissions problem the operator
    // needs told about. Ignoring it would start the relay on the defaults the file
    // was there to override.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("relay.toml");
    std::fs::write(&file, "WEALD_RELAY_HOSTNAME = \"x\"\n").unwrap();
    let mut permissions = std::fs::metadata(&file).unwrap().permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        permissions.set_mode(0o000);
    }
    std::fs::set_permissions(&file, permissions).unwrap();
    let error = Values::from_pairs(Vec::<(&str, &str)>::new()).with_file(Some(&file));
    // Running as root would read it anyway, and that is a property of the machine
    // rather than of the code, so both outcomes are accepted and only the failure
    // shape is asserted.
    if let Err(error) = error {
        assert!(
            matches!(error, ConfigError::UnreadableFile { .. }),
            "{error}"
        );
        assert!(error.key().is_none());
    }
}

// MARK: The environment reader

#[test]
fn from_env_reads_only_the_relays_own_keys() {
    // Nothing else on the machine can affect the result. A relay that read a
    // loosely named variable would be configurable by accident.
    // Safety: single-threaded within this test, and the keys are relay-specific.
    unsafe {
        std::env::set_var(keys::HOSTNAME, "from-real-env.example.com");
        std::env::set_var("UNRELATED_VARIABLE", "ignored");
    }
    let values = Values::from_env();
    assert_eq!(values.source_of(keys::HOSTNAME), Source::Environment);
    assert_eq!(values.source_of(keys::LISTEN), Source::Default);
    unsafe {
        std::env::remove_var(keys::HOSTNAME);
        std::env::remove_var("UNRELATED_VARIABLE");
    }
}

// MARK: Shapes

#[test]
fn the_key_list_is_complete_and_has_no_duplicates() {
    // `keys::ALL` is what the `relay.toml` reader validates against, so a key that
    // is read but missing from the list would be refused in a file and accepted in
    // a variable.
    let mut sorted = keys::ALL.to_vec();
    sorted.sort_unstable();
    let mut deduped = sorted.clone();
    deduped.dedup();
    assert_eq!(sorted, deduped, "keys::ALL has a duplicate");
    // 17 since relay step 13 added WEALD_RELAY_PROFILE, the key that lets the
    // binary be told which deployment it is and refuse what that deployment
    // forbids (backend/wealdrelay/src/profile.rs). 18 since
    // WEALD_RELAY_OPERATOR_TOKEN, the bearer the control plane presents on the
    // operator routes: provider-private networking is a network boundary and not
    // an authentication one, so the routes that report the admitted count are
    // mounted only where there is a credential to check them against. 20 since
    // relay step 30 added WEALD_RELAY_LIVE and WEALD_RELAY_LIVE_FANOUT, the
    // ephemeral path's on switch and the setting whose only job is to refuse a
    // multi-instance deployment that would show every member half the room. 23
    // since step 35 added WEALD_RELAY_CALLS, WEALD_RELAY_MAX_CONCURRENT_CALLS and
    // WEALD_RELAY_MAX_CONNECTIONS: the call path's on switch, the ceiling that
    // sizes it and has no default on purpose, and the socket cap that
    // `specs/backend/relay/operations.md` had recorded as a known gap. 24 with
    // WEALD_RELAY_DB_POOL_SIZE, the Postgres pool ceiling an operator on a larger
    // plan raises. 30 since step 37 added the six push variables: the on switch, the
    // wake destination that has no default because it is a trust boundary, the
    // optional bearer, the registration url a device is told rather than left to
    // guess, the coalescing window and the queue bound.
    // 35 with WEALD_RELAY_SEND_FRAMES_PER_MINUTE and
    // WEALD_RELAY_SEND_BYTES_PER_MINUTE, the two halves of the per-device inbound
    // budget on the envelope path. That path had no budget at all: media
    // rate-limits per device and push rate-limits registration, but a `SEND` ran
    // straight into a decode, an authorization read and a Postgres transaction,
    // so any admitted device could drive the database at line rate with 1 MiB
    // frames (`crate::send_budget`, `specs/backend/relay/wire.md`).
    // 37 with WEALD_RELAY_JANITOR_INTERVAL_MS and
    // WEALD_RELAY_GC_MIN_OBJECT_AGE_SECONDS, the two the background janitor reads:
    // how often it wakes, and how old an unreferenced object must be before it is
    // collected. The age floor is the one that matters, because an object is
    // written before the envelope that references it, so a sweep with no floor
    // would collect a blob that was seconds away from being pointed at
    // (`src/janitor.rs`).
    assert_eq!(keys::ALL.len(), 38);
    assert!(keys::ALL.iter().all(|key| key.starts_with("WEALD_RELAY_")));
}

// MARK: The ephemeral path

#[test]
fn the_ephemeral_path_is_on_by_default_and_fans_out_in_process() {
    let config = Config::resolve(&Values::from_pairs(minimal())).expect("minimal config resolves");
    assert_eq!(config.live, LiveMode::On);
    assert_eq!(config.live_fanout, LiveFanout::Process);
    assert_eq!(config.live_label(), "on");
}

#[test]
fn the_ephemeral_path_can_be_turned_off() {
    let config = resolve(keys::LIVE, "off").expect("off resolves");
    assert_eq!(config.live, LiveMode::Off);
    assert_eq!(config.live_label(), "off");
}

#[test]
fn an_unknown_live_value_is_refused_by_name() {
    let error = resolve(keys::LIVE, "sometimes").expect_err("refused");
    assert_eq!(error.key(), Some(keys::LIVE));
}

#[test]
fn process_fanout_is_refused_in_a_multi_instance_deployment() {
    // The whole reason the setting exists. Two relay processes each fanning out in
    // process would show every member exactly the half of the room that happens to
    // share their socket, with nothing anywhere reporting a fault. A relay that
    // will not start is a page a human reads; a half room is one nobody sees.
    let error = resolve_with(&[(keys::REDIS_URL, "redis://localhost:6379")])
        .expect_err("process fanout with a declared second instance is refused");
    assert!(matches!(error, ConfigError::LiveFanoutSingleProcess { .. }));
    assert_eq!(error.key(), Some(keys::LIVE_FANOUT));
    assert!(error.to_string().contains(keys::REDIS_URL));
}

#[test]
fn a_multi_instance_deployment_may_turn_the_ephemeral_path_off_instead() {
    // The escape hatch, and it is the honest one: with no beats there is nothing to
    // fail to cross an instance boundary, so the deployment starts and presence
    // reports unavailable rather than showing half a room.
    let config = resolve_with(&[
        (keys::REDIS_URL, "redis://localhost:6379"),
        (keys::LIVE, "off"),
    ])
    .expect("live off resolves alongside a second instance");
    assert_eq!(config.live, LiveMode::Off);
}

#[test]
fn a_shared_fanout_url_is_refused_because_this_build_does_not_implement_one() {
    // A setting the binary accepts and does not honour is worse than one it
    // refuses: an operator would read the value back and believe presence crossed
    // their instances.
    let error =
        resolve(keys::LIVE_FANOUT, "redis://localhost:6379").expect_err("shared fanout refused");
    assert!(matches!(error, ConfigError::LiveFanoutUnavailable { .. }));
    assert_eq!(error.key(), Some(keys::LIVE_FANOUT));
}

#[test]
fn a_tls_mode_is_refused_because_nothing_in_this_build_wraps_the_listener() {
    // `serve::bind` binds bare TcpListeners and `serve::run` hands them to
    // `axum::serve` unwrapped, so accepting either mode would have bound the
    // public address in cleartext while `--check-config` printed the mode back
    // as confirmation that it had not.
    for mode in ["acme", "file"] {
        let error = resolve(keys::TLS, mode).expect_err("tls mode refused");
        assert!(matches!(error, ConfigError::TlsUnavailable { .. }));
        assert_eq!(error.key(), Some(keys::TLS));
    }
    let config = resolve(keys::TLS, "off").expect("tls off resolves");
    assert_eq!(config.tls, TlsMode::Off);
}

#[test]
fn no_configuration_key_names_a_commercial_layer_vendor() {
    // `server.md`: a pull request adding a key that points at something in
    // specs/backend/cloud/ is a trust boundary change, because it would mean the
    // hosted binary differs from the audited binary. Asserted rather than reviewed.
    for forbidden in [
        "CLERK", "STRIPE", "RENDER", "CLOUD", "CONTROL", "LICENSE", "BILLING", "ACCOUNT",
    ] {
        assert!(
            !keys::ALL.iter().any(|key| key.contains(forbidden)),
            "{forbidden} appears in the relay's configuration surface"
        );
    }
}

#[test]
fn a_source_renders_as_the_place_an_operator_would_look() {
    assert_eq!(Source::Environment.to_string(), "environment");
    assert_eq!(Source::File.to_string(), "relay.toml");
    assert_eq!(Source::Default.to_string(), "default");
}

#[test]
fn the_error_type_is_comparable_and_debuggable() {
    // Both are load-bearing: the tests above compare errors, and the startup path
    // formats one into a message.
    let a = ConfigError::Missing {
        key: keys::HOSTNAME,
    };
    assert_eq!(a.clone(), a);
    assert!(format!("{a:?}").contains("Missing"));
    assert!(ConfigError::UnreadableFile {
        path: "/tmp/relay.toml".into(),
        reason: "denied".into()
    }
    .to_string()
    .contains("/tmp/relay.toml"));
    assert!(ConfigError::MalformedFile {
        path: "/tmp/relay.toml".into(),
        reason: "bad".into()
    }
    .to_string()
    .contains("bad"));
}

#[test]
fn the_configuration_is_comparable_and_debuggable() {
    let config = Config::resolve(&Values::from_pairs(minimal())).unwrap();
    assert_eq!(config.clone(), config);
    assert!(format!("{config:?}").contains("relay.acme.com"));
    assert!(format!("{:?}", Values::default()).contains("Values"));
    assert!(format!("{:?}", Limit::Unlimited).contains("Unlimited"));
    assert!(format!("{:?}", TlsMode::Acme).contains("Acme"));
    assert!(format!("{:?}", MinEncryption::Mls).contains("Mls"));
    assert!(format!("{:?}", WriteMode::ReadOnly).contains("ReadOnly"));
    assert!(format!("{:?}", AccessSetMode::Off).contains("Off"));
    assert!(format!("{:?}", Source::File).contains("File"));
}

// MARK: Every error names its key

#[test]
fn every_error_variant_names_the_key_an_operator_must_edit_or_says_it_has_none() {
    // The startup path formats the message and the operator's next action is to
    // edit the key it names. A variant that forgot to report its key would send
    // somebody looking through sixteen variables by hand, and the failure would be
    // invisible until the day somebody misconfigured that one key. Every variant is
    // listed here, so adding one without deciding what it reports does not compile
    // past this test's match.
    let cases: Vec<(ConfigError, Option<&str>)> = vec![
        (
            ConfigError::Missing {
                key: keys::HOSTNAME,
            },
            Some(keys::HOSTNAME),
        ),
        (
            ConfigError::Empty {
                key: keys::REDIS_URL,
            },
            Some(keys::REDIS_URL),
        ),
        (
            ConfigError::NotAllowed {
                key: keys::TLS,
                value: "of".into(),
                allowed: "acme, file, off",
            },
            Some(keys::TLS),
        ),
        (
            ConfigError::NotANumber {
                key: keys::MAX_STORAGE_GB,
                value: "lots".into(),
            },
            Some(keys::MAX_STORAGE_GB),
        ),
        (
            ConfigError::NotAPostgresUrl {
                key: keys::DATABASE_URL,
                value: "mysql://host/db".into(),
            },
            Some(keys::DATABASE_URL),
        ),
        (
            ConfigError::NotAStorageUrl {
                key: keys::STORAGE_URL,
                value: "gs://bucket".into(),
            },
            Some(keys::STORAGE_URL),
        ),
        (
            ConfigError::NotAnAddress {
                key: keys::LISTEN,
                value: "8443".into(),
            },
            Some(keys::LISTEN),
        ),
        (
            ConfigError::UnknownFileKey {
                path: "/etc/relay.toml".into(),
                key: "WEALD_RELAY_NOPE".into(),
            },
            Some("WEALD_RELAY_NOPE"),
        ),
        (
            ConfigError::NonScalarFileValue {
                path: "/etc/relay.toml".into(),
                key: "WEALD_RELAY_HOSTNAME".into(),
            },
            Some("WEALD_RELAY_HOSTNAME"),
        ),
        // The two that are about the file rather than about a key. They report
        // none, because naming a key an operator did not write would be a wrong
        // instruction rather than a missing one.
        (
            ConfigError::UnreadableFile {
                path: "/etc/relay.toml".into(),
                reason: "permission denied".into(),
            },
            None,
        ),
        (
            ConfigError::MalformedFile {
                path: "/etc/relay.toml".into(),
                reason: "expected an equals sign".into(),
            },
            None,
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.key(), expected, "{error}");
        match expected {
            // The rendered message has to carry the key too. `key()` being right
            // while the text drops it would still leave the operator guessing.
            Some(key) => assert!(error.to_string().contains(key), "{error}"),
            None => assert!(error.to_string().contains("relay.toml"), "{error}"),
        }
    }
}

#[test]
fn a_relay_toml_may_write_a_boolean_or_an_integer_as_itself() {
    // An operator writing TOML writes `true` and `30`, not `"true"` and `"30"`,
    // because that is what TOML is for. The reader renders both into the same flat
    // string space the environment uses, so the value means the same thing however
    // it was spelled. Refusing a real TOML boolean would make the bundled file and
    // the documented variables disagree about the same setting.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("relay.toml");
    std::fs::write(
        &file,
        "WEALD_RELAY_HOSTNAME = \"relay.acme.com\"\n\
         WEALD_RELAY_DATABASE_URL = \"postgres://weald@localhost/weald_relay\"\n\
         WEALD_RELAY_STORAGE_URL = \"file:///var/lib/wealdrelay/blobs\"\n\
         WEALD_RELAY_RELEASE_CHECK = true\n\
         WEALD_RELAY_RETENTION_DAYS = 30\n",
    )
    .unwrap();
    let error = Values::from_pairs(Vec::<(&str, &str)>::new())
        .with_file(Some(&file))
        .expect("the file parses")
        .pipe_resolve()
        .expect_err("a boolean is rendered as its own text and is not one of on or off");
    // `true` is not `on`. The closed set is `on, off` and the reader does not
    // invent a synonym, because a value silently read as something adjacent is how
    // a deployment ends up in a posture nobody chose.
    assert_eq!(
        error,
        ConfigError::NotAllowed {
            key: keys::RELEASE_CHECK,
            value: "true".into(),
            allowed: "on, off",
        }
    );

    // The same file with the boolean spelled the way the key accepts, to show the
    // integer beside it resolves rather than merely parsing.
    std::fs::write(
        &file,
        "WEALD_RELAY_HOSTNAME = \"relay.acme.com\"\n\
         WEALD_RELAY_DATABASE_URL = \"postgres://weald@localhost/weald_relay\"\n\
         WEALD_RELAY_STORAGE_URL = \"file:///var/lib/wealdrelay/blobs\"\n\
         WEALD_RELAY_RELEASE_CHECK = \"off\"\n\
         WEALD_RELAY_METRICS_GROUP_LABELS = \"on\"\n\
         WEALD_RELAY_RETENTION_DAYS = 30\n\
         WEALD_RELAY_MAX_STORAGE_GB = 512\n",
    )
    .unwrap();
    let config = Values::from_pairs(Vec::<(&str, &str)>::new())
        .with_file(Some(&file))
        .expect("the file parses")
        .pipe_resolve()
        .expect("the file alone is a complete configuration");
    assert_eq!(config.retention_days, Limit::Of(30));
    assert_eq!(config.max_storage_gb, Limit::Of(512));
    assert!(!config.release_check);
    assert!(config.metrics_group_labels);
}

/// `Config::resolve` takes a reference, and these tests build the `Values` in an
/// expression. Named rather than repeated so each case above reads as one thought.
trait PipeResolve {
    fn pipe_resolve(&self) -> Result<Config, ConfigError>;
}

impl PipeResolve for Values {
    fn pipe_resolve(&self) -> Result<Config, ConfigError> {
        Config::resolve(self)
    }
}

#[test]
fn an_optional_key_set_to_nothing_is_refused_wherever_it_appears() {
    // `FOO=` in a compose file is almost always a variable somebody meant to fill
    // in. Treating it as unset would start the relay with no handoff key, or with
    // no limit, in both cases silently. Each of these reaches the empty check
    // through a different reader, so one of them being written to fall back to a
    // default rather than to refuse would show here and nowhere else.
    for key in [
        keys::BOOTSTRAP_HANDOFF_PUBKEY,
        keys::MAX_STORAGE_GB,
        keys::RETENTION_DAYS,
    ] {
        let error = resolve(key, "").expect_err("an empty value is refused");
        assert_eq!(error, ConfigError::Empty { key });
        assert_eq!(error.key(), Some(key));
    }
    // And whitespace is nothing, because a quoted blank in a compose file is the
    // same mistake wearing a space.
    assert_eq!(
        resolve(keys::BOOTSTRAP_HANDOFF_PUBKEY, "   ").expect_err("blank is empty"),
        ConfigError::Empty {
            key: keys::BOOTSTRAP_HANDOFF_PUBKEY
        }
    );
}

/// The operator token never appears in `check-config` output.
///
/// It is a shared secret, not a public key, and `check-config` output is the
/// first thing anybody pastes into a support ticket. The neighbouring handoff
/// value is a public key and is still reported as `[set]` rather than printed,
/// so the rule here is the one the file already follows: a configured secret is
/// reported as configured and never as itself.
#[test]
fn the_operator_token_is_reported_as_set_and_never_printed() {
    let secret = "operator-token-value-0123456789";
    let resolved = Config::resolve(&Values::from_pairs([
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@localhost/weald_relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
        (keys::OPERATOR_TOKEN, secret),
    ]))
    .expect("the configuration resolves");
    assert_eq!(resolved.operator_token.as_deref(), Some(secret));

    let empty: [(&str, &str); 0] = [];
    let printed = wealdrelay::describe_config(&resolved, &Values::from_pairs(empty));
    assert!(
        !printed.contains(secret),
        "check-config printed the operator token: {printed}"
    );
    assert!(
        printed.contains(keys::OPERATOR_TOKEN),
        "check-config did not mention the operator token at all: {printed}"
    );
}

// MARK: The call path

/// Calls on, with the ceiling the on switch requires. Two keys rather than one
/// because that pairing is itself a rule, tested on its own below.
fn calls_on(pairs: &[(&'static str, &'static str)]) -> Result<Config, ConfigError> {
    let mut values = vec![(keys::CALLS, "on"), (keys::MAX_CONCURRENT_CALLS, "3")];
    values.extend_from_slice(pairs);
    resolve_with(&values)
}

#[test]
fn the_call_path_is_off_by_default_and_carries_no_ceiling() {
    // Off, unlike the ephemeral path, and the asymmetry is the decision. A beat
    // every twenty seconds is the ordinary shape of the app; a sustained media
    // stream is capacity an operator has to have sized for, so it is opted into.
    let config = Config::resolve(&Values::from_pairs(minimal())).expect("minimal config resolves");
    assert_eq!(config.calls, CallMode::Off);
    assert_eq!(config.calls_label(), "off");
    assert_eq!(config.max_concurrent_calls, None);
}

#[test]
fn calls_on_with_a_ceiling_resolves() {
    let config = calls_on(&[]).expect("calls on with a ceiling resolves");
    assert_eq!(config.calls, CallMode::On);
    assert_eq!(config.calls_label(), "on");
    assert_eq!(config.max_concurrent_calls, Some(3));
}

#[test]
fn calls_on_without_a_ceiling_refuses_to_start_and_names_the_key() {
    // The variable with no default, and the reason there will never be one: call
    // capacity is a sizing decision about one instance's bandwidth, and a relay
    // that guessed would be a relay whose ceiling nobody chose and whose operator
    // meets it as a refusal during a call.
    let error = resolve(keys::CALLS, "on").expect_err("a ceiling is required");
    assert!(matches!(error, ConfigError::CallsCeilingMissing { .. }));
    assert_eq!(error.key(), Some(keys::MAX_CONCURRENT_CALLS));
    assert!(error.to_string().contains(keys::CALLS));
}

#[test]
fn a_ceiling_without_calls_is_refused_rather_than_ignored() {
    // For the reason an empty value is refused: a setting the binary accepts and
    // does not honour is one an operator reads back and believes.
    let error =
        resolve(keys::MAX_CONCURRENT_CALLS, "3").expect_err("a ceiling with calls off is refused");
    assert!(matches!(error, ConfigError::CallsCeilingUnused { .. }));
    assert_eq!(error.key(), Some(keys::MAX_CONCURRENT_CALLS));
}

#[test]
fn a_zero_ceiling_is_refused_because_it_is_not_a_limit() {
    let error = resolve_with(&[(keys::CALLS, "on"), (keys::MAX_CONCURRENT_CALLS, "0")])
        .expect_err("zero is refused");
    assert!(matches!(error, ConfigError::ZeroLimit { .. }));
    assert_eq!(error.key(), Some(keys::MAX_CONCURRENT_CALLS));
}

#[test]
fn a_ceiling_that_is_not_a_number_is_refused_by_name() {
    let error = resolve_with(&[(keys::CALLS, "on"), (keys::MAX_CONCURRENT_CALLS, "lots")])
        .expect_err("refused");
    assert!(matches!(error, ConfigError::NotANumber { .. }));
    assert_eq!(error.key(), Some(keys::MAX_CONCURRENT_CALLS));
}

#[test]
fn an_unknown_calls_value_is_refused_by_name() {
    let error = resolve(keys::CALLS, "sometimes").expect_err("refused");
    assert!(matches!(error, ConfigError::NotAllowed { .. }));
    assert_eq!(error.key(), Some(keys::CALLS));
}

#[test]
fn calls_are_refused_in_a_multi_instance_deployment() {
    // Sharper than the presence refusal it copies. Two instances would put the two
    // halves of a call on different processes, so the call would connect and then
    // be silent: chat degrades to reconciliation across that boundary and a call
    // has no reconciliation to degrade to.
    // Presence turned off, so the refusal under test is the call one rather than
    // the beat one: both rules read the same declaration and presence resolves
    // first, so leaving it on would prove `LiveFanoutSingleProcess` twice.
    let error = calls_on(&[
        (keys::REDIS_URL, "redis://localhost:6379"),
        (keys::LIVE, "off"),
    ])
    .expect_err("calls with a declared second instance are refused");
    assert!(matches!(error, ConfigError::CallsSingleProcess { .. }));
    assert_eq!(error.key(), Some(keys::CALLS));
    assert!(error.to_string().contains(keys::REDIS_URL));
}

#[test]
fn a_multi_instance_deployment_may_leave_calls_off() {
    let config = resolve_with(&[
        (keys::REDIS_URL, "redis://localhost:6379"),
        (keys::LIVE, "off"),
    ])
    .expect("calls off resolves alongside a second instance");
    assert_eq!(config.calls, CallMode::Off);
}

// MARK: The connection cap

#[test]
fn the_connection_cap_defaults_to_a_number_rather_than_to_unlimited() {
    // The gap being closed. `specs/backend/relay/operations.md` recorded that
    // nothing capped concurrent connections, so instance memory was the per
    // connection queue budget times however many clients chose to connect. A
    // default of `unlimited` would have been the old behaviour under a new name.
    let config = Config::resolve(&Values::from_pairs(minimal())).expect("minimal config resolves");
    assert_eq!(config.max_connections, Limit::Of(256));
}

#[test]
fn the_connection_cap_can_be_raised_or_removed_deliberately() {
    assert_eq!(
        resolve(keys::MAX_CONNECTIONS, "4096")
            .expect("a number resolves")
            .max_connections,
        Limit::Of(4096)
    );
    // `unlimited` is still expressible, because an operator who has sized their
    // instance and means it should be able to say so.
    assert_eq!(
        resolve(keys::MAX_CONNECTIONS, "unlimited")
            .expect("unlimited resolves")
            .max_connections,
        Limit::Unlimited
    );
}

#[test]
fn a_zero_or_unparseable_connection_cap_is_refused_by_name() {
    let zero = resolve(keys::MAX_CONNECTIONS, "0").expect_err("zero is not a limit");
    assert!(matches!(zero, ConfigError::ZeroLimit { .. }));
    assert_eq!(zero.key(), Some(keys::MAX_CONNECTIONS));
    let words = resolve(keys::MAX_CONNECTIONS, "many").expect_err("refused");
    assert!(matches!(words, ConfigError::NotANumber { .. }));
    assert_eq!(words.key(), Some(keys::MAX_CONNECTIONS));
}

// MARK: Push

#[test]
fn push_is_off_by_default_and_carries_no_destination() {
    // Off, like calls and unlike presence, and the asymmetry is the decision: push is
    // the only component of this system that talks to a party outside the operator's
    // control, so it is a posture an operator adopts rather than one they inherit from
    // an upgrade (`specs/backend/relay/push.md` section 5).
    let config = Config::resolve(&Values::from_pairs(minimal())).expect("minimal config resolves");
    assert_eq!(config.push, PushMode::Off);
    assert_eq!(config.push_label(), "off");
    assert_eq!(config.push_url, None);
    assert_eq!(config.push_token, None);
    assert_eq!(config.push_register_url, None);
    assert_eq!(
        config.push_coalesce_ms,
        wealdrelay::push::DEFAULT_COALESCE_MS
    );
    assert_eq!(config.push_queue, wealdrelay::push::DEFAULT_QUEUE);
}

#[test]
fn push_on_with_a_destination_resolves_and_carries_every_default() {
    let config = resolve_with(&[
        (keys::PUSH, "on"),
        (keys::PUSH_URL, "https://ringer.example/v1/wake"),
    ])
    .expect("push on with a url resolves");
    assert_eq!(config.push, PushMode::On);
    assert_eq!(config.push_label(), "on");
    assert_eq!(
        config.push_url.as_deref(),
        Some("https://ringer.example/v1/wake")
    );
    assert_eq!(config.push_coalesce_ms, 2000);
    assert_eq!(config.push_queue, 1024);
}

#[test]
fn push_on_without_a_destination_refuses_to_start_and_names_the_key() {
    // The variable with no default, and the reason there will never be one: a wake
    // destination is a trust boundary, and a relay that inherited one silently would
    // be waking its users' devices through a party its operator never chose.
    let error = resolve(keys::PUSH, "on").expect_err("a destination is required");
    assert!(matches!(error, ConfigError::PushUrlMissing { .. }));
    assert_eq!(error.key(), Some(keys::PUSH_URL));
    assert!(error.to_string().contains(keys::PUSH));
    assert!(error.to_string().contains("trust boundary"));
}

#[test]
fn any_push_setting_with_push_off_is_refused_rather_than_ignored() {
    // A configured-and-ignored outbound destination reads as working and is not,
    // which is exactly the class of mistake `--check-config` exists to surface. All
    // five of the other keys, because an operator who set one of them meant push to
    // be on and needs to be told it is not.
    for (key, value) in [
        (keys::PUSH_URL, "https://ringer.example/v1/wake"),
        (keys::PUSH_TOKEN, "a-bearer"),
        (keys::PUSH_REGISTER_URL, "https://ringer.example/v1/handles"),
        (keys::PUSH_COALESCE_MS, "500"),
        (keys::PUSH_QUEUE, "64"),
    ] {
        let error = resolve(key, value).expect_err("a push setting with push off is refused");
        assert!(
            matches!(error, ConfigError::PushSettingUnused { .. }),
            "{key} was accepted with push off"
        );
        assert_eq!(error.key(), Some(key));
        assert!(error.to_string().contains(keys::PUSH));
    }
}

#[test]
fn a_push_setting_left_at_its_default_is_not_read_as_set() {
    // The other half of the rule above, and it matters because the two numeric keys
    // are read as values rather than as options: an operator who writes the default
    // out explicitly is saying nothing, and a relay that refused to start over it
    // would be refusing over a no-op.
    let config = resolve_with(&[(keys::PUSH_COALESCE_MS, "2000"), (keys::PUSH_QUEUE, "1024")])
        .expect("the defaults, written out, are still the defaults");
    assert_eq!(config.push, PushMode::Off);
}

#[test]
fn a_plaintext_wake_destination_is_refused_unless_it_is_loopback() {
    // `push.md` section 5 exempts `local` and `ci`, which reach no vendor at all, and
    // the exemption is spelled as loopback because that is the part of it this binary
    // can check: those two profiles run a ringer on 127.0.0.1 and nothing else does.
    for (key, other) in [
        (keys::PUSH_URL, None),
        (
            keys::PUSH_REGISTER_URL,
            Some((keys::PUSH_URL, "https://ringer.example/v1/wake")),
        ),
    ] {
        for value in [
            "http://ringer.example/v1/wake",
            "ftp://ringer.example/v1/wake",
            "not a url at all",
        ] {
            let mut pairs = vec![(keys::PUSH, "on"), (key, value)];
            if let Some(extra) = other {
                pairs.push(extra);
            } else {
                pairs.push((keys::PUSH_URL, value));
            }
            let error = resolve_with(&pairs).expect_err("a plaintext destination is refused");
            assert!(
                matches!(error, ConfigError::PushUrlNotSecure { .. }),
                "{value} was accepted for {key}"
            );
            assert!(error.to_string().contains("https"));
        }
    }
    // And loopback in every spelling starts, because that is the local harness.
    for url in [
        "http://127.0.0.1:9099/v1/wake",
        "http://localhost:9099/v1/wake",
    ] {
        let config = resolve_with(&[(keys::PUSH, "on"), (keys::PUSH_URL, url)])
            .expect("a loopback ringer is legal");
        assert_eq!(config.push_url.as_deref(), Some(url));
    }
}

#[test]
fn a_zero_queue_is_refused_because_it_is_not_a_bound() {
    let error = resolve_with(&[
        (keys::PUSH, "on"),
        (keys::PUSH_URL, "https://ringer.example/v1/wake"),
        (keys::PUSH_QUEUE, "0"),
    ])
    .expect_err("zero is refused");
    assert!(matches!(error, ConfigError::ZeroLimit { .. }));
    assert_eq!(error.key(), Some(keys::PUSH_QUEUE));
}

#[test]
fn a_zero_coalescing_window_is_legal_because_it_means_something() {
    // Unlike the queue bound. An operator who wants every wake sent as it arrives is
    // describing a deployment rather than making a mistake.
    let config = resolve_with(&[
        (keys::PUSH, "on"),
        (keys::PUSH_URL, "https://ringer.example/v1/wake"),
        (keys::PUSH_COALESCE_MS, "0"),
    ])
    .expect("zero is a window");
    assert_eq!(config.push_coalesce_ms, 0);
}

#[test]
fn a_push_number_that_is_not_a_number_is_refused_by_name() {
    for key in [keys::PUSH_COALESCE_MS, keys::PUSH_QUEUE] {
        let error = resolve_with(&[
            (keys::PUSH, "on"),
            (keys::PUSH_URL, "https://ringer.example/v1/wake"),
            (key, "soon"),
        ])
        .expect_err("a word is not a number");
        assert!(matches!(error, ConfigError::NotANumber { .. }));
        assert_eq!(error.key(), Some(key));
    }
}

#[test]
fn push_takes_only_on_or_off() {
    let error = resolve(keys::PUSH, "maybe").expect_err("a third value is refused");
    assert!(matches!(error, ConfigError::NotAllowed { .. }));
    assert_eq!(error.key(), Some(keys::PUSH));
    assert!(error.to_string().contains("on, off"));
}

#[test]
fn the_hosted_profile_refuses_a_loopback_ringer() {
    // The profile-forbidden refusal. A hosted relay's ringer is a service on the
    // internet, so a plaintext wake destination here is either a harness
    // configuration copied by accident or a host on a shared provider network, and
    // both put a wake capability on the wire in cleartext.
    for key in [keys::PUSH_URL, keys::PUSH_REGISTER_URL] {
        let mut pairs = vec![
            (keys::PROFILE, "hosted"),
            (keys::PUSH, "on"),
            (keys::PUSH_URL, "https://ringer.example/v1/wake"),
            (keys::MIN_ENC, "mls"),
        ];
        pairs.retain(|(existing, _)| *existing != key || key == keys::PUSH_URL);
        if key == keys::PUSH_URL {
            pairs.retain(|(existing, _)| *existing != keys::PUSH_URL);
            pairs.push((keys::PUSH_URL, "http://127.0.0.1:9099/v1/wake"));
        } else {
            pairs.push((key, "http://127.0.0.1:9099/v1/handles"));
        }
        let error = resolve_with(&pairs).expect_err("the hosted profile forbids this");
        assert!(
            matches!(error, ConfigError::RefusedOnHostedProfile { .. }),
            "{key} was accepted on the hosted profile"
        );
        assert_eq!(error.key(), Some(key));
        assert!(error.to_string().contains("cleartext"));
    }
    // And an https ringer is exactly what the hosted tier is for, so it starts.
    let config = resolve_with(&[
        (keys::PROFILE, "hosted"),
        (keys::MIN_ENC, "mls"),
        (keys::PUSH, "on"),
        (keys::PUSH_URL, "https://ringer.weald.team/v1/wake"),
    ])
    .expect("a hosted relay with a real ringer starts");
    assert_eq!(config.push, PushMode::On);
}

// MARK: The environment we actually ship

/// The self-host Compose bundle's relay environment has to resolve.
///
/// It did not. `docker-compose.yml` set `WEALD_RELAY_REDIS_URL` for a redis
/// service and never set `WEALD_RELAY_LIVE`, which defaults on, and
/// `enforce_live_fanout` refuses exactly that pair: the download exited 78 on
/// first boot and no self-hoster ever reached a running relay. Nothing in this
/// crate's tests read the deploy directory, so every config test passed while
/// the one configuration a customer actually receives could not start.
///
/// This parses the shipped file rather than restating it, so a future edit that
/// reintroduces an illegal combination fails here instead of in somebody's
/// terminal. See WEALD-468.
#[test]
fn the_shipped_compose_environment_resolves() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/deploy/compose/docker-compose.yml"
    );
    let text = std::fs::read_to_string(path).expect("the compose bundle is part of the repo");

    // The relay service's `environment:` block, which is the last one in the file
    // that carries WEALD_RELAY_ keys alongside the database url.
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "environment:" {
            inside = trimmed.starts_with("environment:") && line.starts_with("    ");
            continue;
        }
        if inside && !line.starts_with("      ") {
            inside = false;
        }
        if !inside || trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        let Some((key, value)) = trimmed.split_once(": ") else {
            continue;
        };
        if !key.starts_with("WEALD_RELAY_") {
            continue;
        }
        // Compose interpolation is not this test's business; substitute the
        // documented defaults so the values are the shapes the relay parses.
        let value = value.trim().trim_matches('"');
        let value = match value {
            v if v.contains("${WEALD_RELAY_HOSTNAME") => "relay.acme.com".to_string(),
            v if v.contains("${POSTGRES_PASSWORD") => {
                "postgres://wealdrelay:pw@postgres:5432/wealdrelay".to_string()
            }
            v if v.contains("${MINIO_BUCKET") => "s3://weald-blobs".to_string(),
            v if v.contains("unlimited") => "unlimited".to_string(),
            v => v.to_string(),
        };
        pairs.push((key.to_string(), value));
    }

    assert!(
        pairs.iter().any(|(k, _)| k == keys::HOSTNAME),
        "parsed no relay environment out of the compose file: {pairs:?}"
    );
    let borrowed: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let config = Config::resolve(&Values::from_pairs(borrowed))
        .expect("the shipped compose environment must start a relay");

    // And the two values the bundle exists to get right: TLS is terminated by the
    // Caddy in front, and the relay is told how many proxies that is, so its
    // per-source bucket keys on the client and not on the Caddy container.
    assert_eq!(config.tls, TlsMode::Off);
    assert_eq!(config.trusted_proxy_hops, 1);
}
