// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The Weald blind relay.
//!
//! Step 0 established the build root, the toolchain pin and the coverage gate.
//! Step 3 adds the skeleton: configuration, the Postgres schema, the object
//! storage abstraction, the two health surfaces and the logging layer
//! (`specs/backend/build/phases-relay.md`).
//!
//! The wire protocol is deliberately not here. A relay that could accept an
//! envelope before its storage contract was proven would have no way to show
//! that the storage contract holds, which is the whole of step 3's gate.
//!
//! `BuildInfo` below is the identity the relay must be able to report about
//! itself, because `specs/backend/relay/verification.md` proof 1 turns on a
//! client comparing the running relay against a published release.

pub mod accept;
pub mod access;
pub mod calls;
pub mod cbor;
pub mod config;
pub mod db;
pub mod envelope;
pub mod frame;
pub mod handshake;
pub mod health;
pub mod hub;
pub mod invite;
pub mod keys;
pub mod lifecycle;
pub mod log;
pub mod logging;
pub mod media;
pub mod negentropy;
pub mod profile;
pub mod recovery;
pub mod serve;
pub mod session;
pub mod storage;
pub mod sync;
pub mod ws;

/// Identity of this build, reported by `wealdrelay --version` and, from step 3,
/// by `/readyz`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildInfo {
    pub name: &'static str,
    pub version: &'static str,
}

/// What this relay reports as the build it is running.
///
/// `specs/backend/relay/verification.md` proof 1 turns on a client comparing
/// this against the published `/releases` feed, and the same spec is explicit
/// about what the comparison is worth: "A modified relay can lie about a
/// self-reported digest. The product must not claim otherwise." So this detects
/// deployment drift and operator mistakes, which are the common failures, and
/// claims nothing about a compelled host.
///
/// Two forms, and they are deliberately not interchangeable.
///
/// - `sha256:<64 hex>` is the published image manifest digest, baked in at image
///   build time from the same value step 13's reproducible build agreed on. Only
///   this form is ever compared against a release.
/// - `exe-blake3:<64 hex>` is this process hashing its own executable, used when
///   nothing baked a digest in. It is a true statement about the running binary
///   and it is labelled so it can never be mistaken for an image digest and
///   compared against one: a self-hash that happened to be formatted like an
///   image digest would silently read as "no matching release" forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunningDigest {
    /// The published image digest, from `WEALD_RELAY_IMAGE_DIGEST`.
    Image(String),
    /// This binary, hashed by this process.
    Executable(String),
    /// Neither was available: no digest was baked in and the executable could
    /// not be read. Reported as itself rather than as an empty string, because
    /// a client showing a blank digest looks like a client that failed to ask.
    Unknown,
}

impl RunningDigest {
    /// The environment key an image build bakes the published digest into.
    pub const IMAGE_KEY: &'static str = "WEALD_RELAY_IMAGE_DIGEST";

    /// What this process is running, resolved once at startup.
    pub fn resolve() -> Self {
        Self::resolve_with(
            std::env::var(Self::IMAGE_KEY).ok(),
            std::env::current_exe().ok(),
        )
    }

    /// The resolution itself, over its two inputs, so every outcome including
    /// the unreadable executable is reachable from a test.
    pub fn resolve_with(baked: Option<String>, exe: Option<std::path::PathBuf>) -> Self {
        if let Some(baked) = baked {
            let trimmed = baked.trim().to_string();
            if !trimmed.is_empty() {
                return Self::Image(trimmed);
            }
        }
        match exe.and_then(|path| std::fs::read(path).ok()) {
            Some(bytes) => Self::Executable(blake3::hash(&bytes).to_hex().to_string()),
            None => Self::Unknown,
        }
    }

    /// The one string the client is shown and the health endpoint reports.
    pub fn line(&self) -> String {
        match self {
            Self::Image(digest) => digest.clone(),
            Self::Executable(hex) => format!("exe-blake3:{hex}"),
            Self::Unknown => "unknown".to_string(),
        }
    }

    /// True only for the form a published release can be compared against.
    pub fn is_comparable(&self) -> bool {
        matches!(self, Self::Image(_))
    }
}

impl BuildInfo {
    /// The identity compiled into this binary.
    pub const fn current() -> Self {
        Self {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    /// One line, stable in shape, because step 13 diffs it across independent
    /// builds and a formatting change would read as a reproducibility failure.
    pub fn line(&self) -> String {
        format!("{} {}", self.name, self.version)
    }
}

/// What the process was asked to do. Parsed from argv so that `main` holds no
/// branching of its own and every outcome is reachable from a unit test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    /// Print the build identity and exit zero.
    Version,
    /// Print usage and exit zero.
    Help,
    /// Run the relay.
    Serve,
    /// Resolve the configuration, print it with the source of every value, and
    /// exit without opening a socket. The thing an operator runs when a relay
    /// will not start and they want to know which of two places set a value.
    CheckConfig,
    /// An argument this build does not understand, carried so the message can
    /// name it.
    Unknown(String),
}

impl Invocation {
    pub fn parse<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        // Only the first argument decides. A relay that skipped past an
        // argument it did not understand would be a relay running a
        // configuration its operator does not have, so anything unrecognised
        // stops here and is named back to them.
        match args.into_iter().next() {
            None => Self::Serve,
            Some(arg) => match arg.as_ref() {
                "--version" | "-V" => Self::Version,
                "--help" | "-h" => Self::Help,
                "--check-config" => Self::CheckConfig,
                other => Self::Unknown(other.to_string()),
            },
        }
    }
}

/// Usage text. Kept beside the parser so the two cannot drift.
pub const USAGE: &str = "\
usage: wealdrelay [--version] [--help] [--check-config]

  --version, -V   print the build identity
  --help, -h      print this message
  --check-config  resolve the configuration, print where each value came from,
                  and exit without opening a socket

With no arguments the relay serves. Configuration is by environment variable,
with an optional relay.toml beside the binary; see
specs/backend/relay/server.md.";

/// Exit code for a configuration that cannot be used. `EX_CONFIG` from
/// `sysexits.h`, so an init system or a compose healthcheck can tell a
/// misconfiguration apart from a crash.
pub const EXIT_CONFIG: i32 = 78;

/// Exit code for a dependency that is not there at startup. `EX_UNAVAILABLE`.
pub const EXIT_UNAVAILABLE: i32 = 69;

/// Outcome of a run: what to write where, and the exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
}

/// The whole of `main`, as a pure function, so the binary is one unbranching
/// call and the coverage floor is paid by unit tests rather than by running a
/// process.
pub fn run<I, S>(args: I) -> Outcome
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    run_invocation(Invocation::parse(args))
}

/// What the process should do, once argv and the configuration have both been
/// read.
///
/// Split from ``run`` because serving is not a pure function of argv: it needs a
/// resolved configuration, and a configuration failure has to be reportable with
/// the same shape as a bad argument. `main` is then one match with no logic of its
/// own, which is what keeps every branch here reachable from a unit test.
#[derive(Debug)]
pub enum Startup {
    /// Write this and exit with this code.
    Print(Outcome),
    /// Serve with this configuration.
    Serve(Box<config::Config>),
}

/// Resolve argv and the environment into an action.
///
/// A missing or unusable configuration value returns `Print` with a non-zero code
/// and a message **naming the key**, which is step 3's negative proof: an operator
/// whose relay will not start must be told which variable to fix rather than left
/// to guess.
pub fn startup<I, S>(args: I, values: &config::Values) -> Startup
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let invocation = Invocation::parse(args);
    match invocation {
        Invocation::Version | Invocation::Help | Invocation::Unknown(_) => {
            Startup::Print(run_invocation(invocation))
        }
        Invocation::CheckConfig => match config::Config::resolve(values) {
            Ok(resolved) => Startup::Print(Outcome {
                stdout: describe_config(&resolved, values),
                stderr: String::new(),
                code: 0,
            }),
            Err(error) => Startup::Print(config_failure(&error)),
        },
        Invocation::Serve => match config::Config::resolve(values) {
            Ok(resolved) => Startup::Serve(Box::new(resolved)),
            Err(error) => Startup::Print(config_failure(&error)),
        },
    }
}

fn config_failure(error: &config::ConfigError) -> Outcome {
    Outcome {
        stdout: String::new(),
        stderr: format!("wealdrelay: {error}"),
        code: EXIT_CONFIG,
    }
}

/// The resolved configuration, one key per line, with where each value came from.
///
/// Values that could be credentials are named and not printed. The database URL
/// carries a password, and an operator pasting `--check-config` output into an
/// issue should not be pasting that with it.
pub fn describe_config(resolved: &config::Config, values: &config::Values) -> String {
    use config::keys;
    let mut lines = Vec::new();
    let mut row = |key: &'static str, value: String| {
        lines.push(format!("{key:<38} {value:<34} {}", values.source_of(key)));
    };
    row(keys::HOSTNAME, resolved.hostname.clone());
    row(keys::DATABASE_URL, "[set, not printed]".to_string());
    row(keys::STORAGE_URL, describe_storage(&resolved.storage));
    row(
        keys::REDIS_URL,
        match resolved.redis_url {
            Some(_) => "[set, not printed]".to_string(),
            None => "unset, single-process mode".to_string(),
        },
    );
    row(keys::LISTEN, resolved.listen.clone());
    row(
        keys::OBSERVABILITY_LISTEN,
        resolved.observability_listen.clone(),
    );
    row(keys::TLS, format!("{:?}", resolved.tls).to_lowercase());
    row(
        keys::MAX_STORAGE_GB,
        describe_limit(resolved.max_storage_gb),
    );
    row(
        keys::RETENTION_DAYS,
        describe_limit(resolved.retention_days),
    );
    row(
        keys::ACCESS_SET,
        format!("{:?}", resolved.access_set).to_lowercase(),
    );
    row(
        keys::MIN_ENC,
        format!("{:?}", resolved.min_encryption).to_lowercase(),
    );
    row(keys::LIVE, resolved.live_label().to_string());
    row(
        keys::LIVE_FANOUT,
        match &resolved.live_fanout {
            config::LiveFanout::Process => "process".to_string(),
            // Named, not printed: a shared fanout endpoint can carry a credential
            // in its url exactly as the database and cache urls can.
            config::LiveFanout::Shared(_) => "[set, not printed]".to_string(),
        },
    );
    row(keys::CALLS, resolved.calls_label().to_string());
    row(
        keys::MAX_CONCURRENT_CALLS,
        match resolved.max_concurrent_calls {
            Some(limit) => limit.to_string(),
            // Only reachable with calls off, which `Config::enforce_calls`
            // guarantees: a relay carrying calls without a ceiling does not start.
            // Saying so here rather than printing an empty column means an operator
            // reading this back sees why the number is absent.
            None => "unset, calls off".to_string(),
        },
    );
    row(
        keys::MAX_CONNECTIONS,
        describe_limit(resolved.max_connections),
    );
    row(
        keys::SMTP_URL,
        match resolved.smtp_url {
            // Said out loud rather than left as "[set]". This relay has no SMTP client,
            // so an operator who configured mail and read a bare "set" would reasonably
            // conclude invites were being sent. Delivery is the admin's own mail client;
            // see `invite::delivery`.
            Some(_) => "[set, and unused: this relay sends no mail]".to_string(),
            None => "unset".to_string(),
        },
    );
    row(
        keys::WRITE_MODE,
        match resolved.write_mode {
            config::WriteMode::Full => "full".to_string(),
            config::WriteMode::ReadOnly => "read_only".to_string(),
        },
    );
    row(keys::PROFILE, resolved.profile.label().to_string());
    row(keys::RELEASE_CHECK, on_off(resolved.release_check));
    row(
        keys::METRICS_GROUP_LABELS,
        on_off(resolved.metrics_group_labels),
    );
    row(
        keys::BOOTSTRAP_HANDOFF_PUBKEY,
        match resolved.bootstrap_handoff_pubkey {
            Some(_) => "[set]".to_string(),
            None => "unset".to_string(),
        },
    );
    // Set or unset, never the value. This one is a shared secret rather than a
    // public key, and `check-config` output is the first thing anybody pastes
    // into a support ticket.
    row(
        keys::OPERATOR_TOKEN,
        match resolved.operator_token {
            Some(_) => "[set]".to_string(),
            None => "unset".to_string(),
        },
    );
    lines.join("\n")
}

fn on_off(value: bool) -> String {
    if value {
        "on".to_string()
    } else {
        "off".to_string()
    }
}

fn describe_limit(limit: config::Limit) -> String {
    match limit {
        config::Limit::Unlimited => "unlimited".to_string(),
        config::Limit::Of(value) => value.to_string(),
    }
}

fn describe_storage(target: &config::StorageTarget) -> String {
    match target {
        config::StorageTarget::Filesystem(path) => format!("file://{}", path.display()),
        config::StorageTarget::S3 { bucket, prefix } if prefix.is_empty() => {
            format!("s3://{bucket}")
        }
        config::StorageTarget::S3 { bucket, prefix } => format!("s3://{bucket}/{prefix}"),
    }
}

/// The print-only arms of ``run``, factored out so ``startup`` can reuse them
/// without re-parsing argv.
fn run_invocation(invocation: Invocation) -> Outcome {
    match invocation {
        Invocation::Version => Outcome {
            stdout: BuildInfo::current().line(),
            stderr: String::new(),
            code: 0,
        },
        Invocation::Help => Outcome {
            stdout: USAGE.to_string(),
            stderr: String::new(),
            code: 0,
        },
        Invocation::Unknown(arg) => Outcome {
            stdout: String::new(),
            stderr: format!("wealdrelay: unrecognised argument: {arg}\n{USAGE}"),
            code: 64,
        },
        Invocation::Serve | Invocation::CheckConfig => Outcome {
            stdout: String::new(),
            stderr: "wealdrelay: this invocation needs a resolved configuration".to_string(),
            code: EXIT_CONFIG,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_info_names_this_crate() {
        let info = BuildInfo::current();
        assert_eq!(info.name, "wealdrelay");
        assert_eq!(info.line(), format!("wealdrelay {}", info.version));
    }

    #[test]
    fn build_info_is_copy_and_comparable() {
        let a = BuildInfo::current();
        let b = a;
        assert_eq!(a, b);
        assert!(format!("{a:?}").contains("wealdrelay"));
    }

    #[test]
    fn no_arguments_means_serve() {
        assert_eq!(Invocation::parse(Vec::<String>::new()), Invocation::Serve);
    }

    #[test]
    fn version_flags_both_forms() {
        assert_eq!(Invocation::parse(["--version"]), Invocation::Version);
        assert_eq!(Invocation::parse(["-V"]), Invocation::Version);
    }

    #[test]
    fn help_flags_both_forms() {
        assert_eq!(Invocation::parse(["--help"]), Invocation::Help);
        assert_eq!(Invocation::parse(["-h"]), Invocation::Help);
    }

    #[test]
    fn an_unknown_argument_is_carried_so_the_message_can_name_it() {
        assert_eq!(
            Invocation::parse(["--smtp-url"]),
            Invocation::Unknown("--smtp-url".to_string())
        );
        assert!(format!("{:?}", Invocation::parse(["--x"])).contains("Unknown"));
    }

    #[test]
    fn version_run_prints_the_identity_and_exits_zero() {
        let out = run(["--version"]);
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, BuildInfo::current().line());
        assert!(out.stderr.is_empty());
    }

    #[test]
    fn help_run_prints_usage_and_exits_zero() {
        let out = run(["--help"]);
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, USAGE);
        assert!(out.stderr.is_empty());
    }

    #[test]
    fn run_refuses_the_invocations_that_need_a_configuration() {
        // `run` is argv only. Serving and checking a configuration both need one
        // resolved, so they go through `startup`, and reaching them here is a
        // caller error rather than an outcome.
        for out in [run(Vec::<String>::new()), run(["--check-config"])] {
            assert_eq!(out.code, EXIT_CONFIG);
            assert!(out.stdout.is_empty());
            assert!(out.stderr.contains("resolved configuration"));
        }
    }

    #[test]
    fn an_unrecognised_argument_exits_sixty_four_and_names_the_argument() {
        let out = run(["--nope"]);
        assert_eq!(out.code, 64);
        assert!(out.stderr.contains("--nope"));
        assert!(out.stderr.contains("usage: wealdrelay"));
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn outcome_is_comparable_and_printable() {
        let a = run(["--version"]);
        assert_eq!(a.clone(), a);
        assert!(format!("{a:?}").contains("stdout"));
    }
}
