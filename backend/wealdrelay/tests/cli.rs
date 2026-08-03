// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Executes the built binary. This is what covers `src/main.rs`: unit tests
//! cannot reach a `main`, and a `main` nobody runs is where an argument
//! handling mistake hides.
//!
//! It is also where the configuration negative proof is made against a real
//! process: a missing required variable exits non-zero with a message naming the
//! variable. An operator whose relay will not start reads that message and nothing
//! else, so the test that guarantees it has to run the process rather than the
//! function.

use std::process::Command;

/// Variables the coverage run needs the child to keep.
///
/// `env_clear` is deliberate: a variable set on the developer's machine must not
/// make a test pass that would fail in ci. But clearing everything also clears
/// `LLVM_PROFILE_FILE`, and then the child writes no profile and `src/main.rs`
/// reports as uncovered, which would be a coverage hole created by the test that
/// exists to close it.
fn keep_instrumentation(command: &mut Command) {
    for key in [
        "PATH",
        "HOME",
        "LLVM_PROFILE_FILE",
        "CARGO_LLVM_COV",
        "CARGO_LLVM_COV_TARGET_DIR",
    ] {
        if let Ok(value) = std::env::var(key) {
            command.env(key, value);
        }
    }
}

/// Run with an environment containing only what is passed, so a variable set on
/// the developer's machine cannot make a test pass that would fail in ci.
fn run_with(args: &[&str], env: &[(&str, &str)]) -> (String, String, i32) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wealdrelay"));
    command.args(args).env_clear();
    // `PATH` and `HOME` survive because clearing them makes the dynamic loader and
    // the AWS credential chain behave differently from any real deployment, and
    // neither is a relay configuration key.
    keep_instrumentation(&mut command);
    for (key, value) in env {
        command.env(key, value);
    }
    // A directory with no `relay.toml` in it, so the optional file cannot supply a
    // value this test believes is absent.
    let scratch = std::env::temp_dir().join(format!("weald-cli-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&scratch);
    command.current_dir(&scratch);

    let out = command
        .output()
        .expect("the binary under test must be executable");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status
            .code()
            .expect("the process must exit rather than be signalled"),
    )
}

fn run(args: &[&str]) -> (String, String, i32) {
    run_with(args, &[])
}

/// A configuration that resolves but names nothing that answers, so
/// `--check-config` can be exercised without a database.
fn valid_env() -> Vec<(&'static str, &'static str)> {
    vec![
        ("WEALD_RELAY_HOSTNAME", "relay.example.com"),
        (
            "WEALD_RELAY_DATABASE_URL",
            "postgres://weald:hunter2@127.0.0.1:1/nothing",
        ),
        ("WEALD_RELAY_STORAGE_URL", "s3://weald-blobs/staging"),
        ("WEALD_RELAY_ACCESS_SET", "off"),
        ("WEALD_RELAY_RETENTION_DAYS", "7"),
    ]
}

#[test]
fn version_goes_to_stdout_with_a_zero_exit() {
    let (stdout, stderr, code) = run(&["--version"]);
    assert_eq!(code, 0);
    assert!(stdout.starts_with("wealdrelay "), "stdout was {stdout:?}");
    // No log line before the answer: the subscriber is installed only on the
    // serving path, because a JSON log line here would break every script that
    // parses this output.
    assert!(stderr.is_empty(), "stderr was {stderr:?}");
    assert!(
        !stdout.contains('{'),
        "stdout carried a log line: {stdout:?}"
    );
}

#[test]
fn help_goes_to_stdout_with_a_zero_exit() {
    let (stdout, stderr, code) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("usage: wealdrelay"));
    assert!(stdout.contains("--check-config"));
    assert!(stderr.is_empty());
}

#[test]
fn serving_without_a_configuration_exits_non_zero_and_names_the_missing_variable() {
    // The configuration negative proof, at the process boundary. The exit code is
    // `EX_CONFIG` so an init system or a compose healthcheck can tell a
    // misconfiguration apart from a crash.
    let (stdout, stderr, code) = run(&[]);
    assert_eq!(code, 78, "stderr was {stderr:?}");
    assert!(stdout.is_empty(), "stdout was {stdout:?}");
    assert!(
        stderr.contains("WEALD_RELAY_HOSTNAME"),
        "the message must name the variable, got {stderr:?}"
    );
}

#[test]
fn each_required_variable_is_named_in_turn_as_it_is_supplied() {
    // Supplying them one at a time walks the operator's actual experience: fix the
    // variable the message named, run again, be told the next one. A relay that
    // named only the first missing variable forever would send them round a loop.
    let (_, stderr, code) = run_with(&[], &[("WEALD_RELAY_HOSTNAME", "relay.example.com")]);
    assert_eq!(code, 78);
    assert!(stderr.contains("WEALD_RELAY_DATABASE_URL"), "{stderr}");

    let (_, stderr, code) = run_with(
        &[],
        &[
            ("WEALD_RELAY_HOSTNAME", "relay.example.com"),
            (
                "WEALD_RELAY_DATABASE_URL",
                "postgres://weald@localhost/relay",
            ),
        ],
    );
    assert_eq!(code, 78);
    assert!(stderr.contains("WEALD_RELAY_STORAGE_URL"), "{stderr}");
}

#[test]
fn an_invalid_value_is_named_along_with_what_was_allowed() {
    let mut env = valid_env();
    env.push(("WEALD_RELAY_TLS", "of"));
    let (_, stderr, code) = run_with(&[], &env);
    assert_eq!(code, 78);
    assert!(stderr.contains("WEALD_RELAY_TLS"), "{stderr}");
    assert!(stderr.contains("acme, file, off"), "{stderr}");
}

#[test]
fn check_config_prints_every_value_with_its_source_and_no_credential() {
    // What an operator runs when a relay will not start and they want to know which
    // of two places set a value. It must not print the database password: this
    // output goes into support tickets.
    let (stdout, stderr, code) = run_with(&["--check-config"], &valid_env());
    assert_eq!(code, 0, "stderr was {stderr:?}");
    assert!(stdout.contains("WEALD_RELAY_HOSTNAME"), "{stdout}");
    assert!(stdout.contains("relay.example.com"), "{stdout}");
    // Where each value came from.
    assert!(stdout.contains("environment"), "{stdout}");
    assert!(stdout.contains("default"), "{stdout}");
    // The storage URL is printed because it is not a credential, and the database
    // URL is not because it carries one.
    assert!(stdout.contains("s3://weald-blobs/staging"), "{stdout}");
    assert!(
        !stdout.contains("hunter2"),
        "the password was printed: {stdout}"
    );
    assert!(stdout.contains("[set, not printed]"), "{stdout}");
    // Security posture is visible, since the point is to answer "what is this relay
    // actually enforcing".
    assert!(stdout.contains("off"), "{stdout}");
    assert!(stdout.contains('7'), "{stdout}");
}

#[test]
fn check_config_refuses_the_same_configurations_serving_refuses() {
    // Otherwise an operator could get a clean `--check-config` and a relay that
    // will not start, which is worse than no check at all.
    let (stdout, stderr, code) = run_with(&["--check-config"], &[]);
    assert_eq!(code, 78);
    assert!(stdout.is_empty());
    assert!(stderr.contains("WEALD_RELAY_HOSTNAME"), "{stderr}");
}

#[test]
fn an_unrecognised_argument_exits_sixty_four_and_names_it() {
    let (stdout, stderr, code) = run(&["--not-a-flag"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty());
    assert!(stderr.contains("--not-a-flag"));
    // And prints usage, so the operator does not have to ask twice.
    assert!(stderr.contains("usage: wealdrelay"));
}

#[test]
fn a_relay_toml_in_the_working_directory_is_read() {
    // The compose bundle ships one, so the binary has to find it without being told.
    let scratch = std::env::temp_dir().join(format!("weald-cli-toml-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    std::fs::write(
        scratch.join("relay.toml"),
        "[relay]\nhostname = \"from-the-file.example.com\"\n\
         database_url = \"postgres://weald@localhost/relay\"\n\
         storage_url = \"file:///tmp/weald-blobs\"\n",
    )
    .unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_wealdrelay"));
    keep_instrumentation(&mut command);
    let out = command
        .arg("--check-config")
        .current_dir(&scratch)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("from-the-file.example.com"), "{stdout}");
    assert!(stdout.contains("relay.toml"), "{stdout}");
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn a_malformed_relay_toml_stops_the_process_and_names_the_file() {
    let scratch = std::env::temp_dir().join(format!("weald-cli-bad-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    std::fs::write(scratch.join("relay.toml"), "SOME_VENDOR_KEY = \"nope\"\n").unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_wealdrelay"));
    keep_instrumentation(&mut command);
    let out = command.current_dir(&scratch).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(78), "{stderr}");
    assert!(stderr.contains("SOME_VENDOR_KEY"), "{stderr}");
    assert!(stderr.contains("relay.toml"), "{stderr}");
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn a_dependency_that_does_not_answer_exits_unavailable_rather_than_config() {
    // The distinction matters to whoever is holding the pager: `EX_CONFIG` means
    // edit a variable, `EX_UNAVAILABLE` means the thing the variable names is down.
    let (stdout, stderr, code) = run_with(&[], &valid_env());
    assert_eq!(code, 69, "stderr was {stderr:?}");
    assert!(stdout.is_empty());
    // And it does not print the password on the way out.
    assert!(!stderr.contains("hunter2"), "{stderr}");
}

#[test]
#[cfg(unix)]
fn a_process_that_cannot_build_a_runtime_says_so_and_exits_unavailable() {
    // The runtime is built in `main` and nowhere else, because it needs a real
    // process. It can fail, and the two ways it does in practice are a machine out
    // of file descriptors and a machine out of thread slots, both of which happen
    // to a busy host running many containers rather than to a broken relay.
    //
    // The operator has to be told which of the three startup stages failed. A relay
    // that panicked here would leave a backtrace where a message should be, and one
    // that exited `EX_CONFIG` would send somebody to edit a variable that is
    // perfectly correct. The descriptor limit is lowered for the child alone, so
    // this proves the arm without needing the host to be in trouble.
    use std::os::unix::process::CommandExt as _;

    let scratch = std::env::temp_dir().join(format!("weald-cli-nofd-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_wealdrelay"));
    command.current_dir(&scratch).env_clear();
    keep_instrumentation(&mut command);
    for (key, value) in valid_env() {
        command.env(key, value);
    }
    // Four: the three standard streams and one to spare, which is enough for the
    // loader and for the profile the coverage run writes, and not enough for the
    // reactor the runtime has to open.
    const DESCRIPTORS: u64 = 4;
    // Safety: the closure runs between fork and exec in the child and calls only
    // `setrlimit`, which is async-signal-safe. Nothing here touches this process.
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: DESCRIPTORS,
                rlim_max: DESCRIPTORS,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }

    let out = command
        .output()
        .expect("the binary under test must be executable");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(69),
        "a host that cannot give the process a runtime is unavailable and not \
         misconfigured: {stderr}"
    );
    assert!(
        stderr.contains("cannot start the runtime"),
        "the message has to name the stage that failed: {stderr}"
    );
    // And it is a message rather than a panic, because the operator reads this and
    // nothing else.
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(out.stdout.is_empty(), "nothing goes to stdout on a failure");

    let _ = std::fs::remove_dir_all(&scratch);
}
