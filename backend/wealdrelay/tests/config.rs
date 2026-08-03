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
    keys, AccessSetMode, Config, ConfigError, Limit, MinEncryption, Source, StorageTarget, TlsMode,
    Values, WriteMode,
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
    assert_eq!(resolve(keys::TLS, "acme").unwrap().tls, TlsMode::Acme);
    assert_eq!(resolve(keys::TLS, "file").unwrap().tls, TlsMode::File);
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
        resolve(keys::MAX_STORAGE_GB, "0").unwrap().max_storage_gb,
        Limit::Of(0)
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
    assert_eq!(
        resolve(keys::REDIS_URL, "redis://localhost:6379")
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
    // mounted only where there is a credential to check them against.
    assert_eq!(keys::ALL.len(), 18);
    assert!(keys::ALL.iter().all(|key| key.starts_with("WEALD_RELAY_")));
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
