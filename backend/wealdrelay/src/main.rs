// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Thin shell over the library. Every decision lives there so it is unit
//! testable; this file moves bytes to the real streams, starts the runtime when
//! the invocation asks for one, and sets the exit code.
//!
//! Two things happen here and nowhere else, because both need a real process:
//! installing the logging subscriber, and building the tokio runtime. Everything
//! else is `wealdrelay::startup`, which is a pure function of argv and the
//! environment and is covered by unit tests.

use std::io::Write as _;

use wealdrelay::config::Values;
use wealdrelay::{startup, Startup};

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // `relay.toml` beside the working directory, which is what the compose bundle
    // ships. Optional: the three required variables alone are a complete
    // configuration.
    let values = match Values::from_env().with_file(Some(std::path::Path::new("relay.toml"))) {
        Ok(values) => values,
        Err(error) => return report("", &format!("wealdrelay: {error}"), wealdrelay::EXIT_CONFIG),
    };

    match startup(args, &values) {
        Startup::Print(outcome) => report(&outcome.stdout, &outcome.stderr, outcome.code),
        Startup::Serve(config) => {
            // The subscriber is installed only on the serving path. `--version`
            // writing a JSON log line before its answer would break every script
            // that parses it.
            let _ = wealdrelay::logging::install("info");
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(error) => {
                    return report(
                        "",
                        &format!("wealdrelay: cannot start the runtime: {error}"),
                        wealdrelay::EXIT_UNAVAILABLE,
                    )
                }
            };
            match runtime.block_on(wealdrelay::serve::serve(*config)) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(error) => report("", &format!("wealdrelay: {error}"), error.exit_code()),
            }
        }
    }
}

fn report(stdout: &str, stderr: &str, code: i32) -> std::process::ExitCode {
    if !stdout.is_empty() {
        // A closed pipe is not an error worth an exit code here; the caller hung
        // up. Writing is best effort and the result is deliberately dropped so
        // this line carries no untestable failure branch.
        let _ = writeln!(std::io::stdout().lock(), "{stdout}");
    }
    if !stderr.is_empty() {
        let _ = writeln!(std::io::stderr().lock(), "{stderr}");
    }
    std::process::ExitCode::from(code as u8)
}
