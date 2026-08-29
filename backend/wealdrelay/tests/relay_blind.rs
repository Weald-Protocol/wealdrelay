// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The org addendum's relay-unchanged assertion, as a property rather than a diff.
//!
//! `specs/agents/networked/phases-org.md:482-497` records why this is not a
//! commit-range diff of `backend/wealdrelay/src/` and `migrations/`: this is a
//! monorepo, the relay is under active development by other programmes, and
//! across the networked-agents range it legitimately gained media, bootstrap
//! handoff, deadline and budget code. A range diff cannot separate this track's
//! changes from theirs, so a red there would say nothing and would be switched
//! off within a week.
//!
//! What the diff was a proxy for is asserted here, three ways, and each of the
//! three holds for every future commit rather than only for the one the gate
//! happened to run on:
//!
//! 1. the relay's source names no agent concept in code,
//! 2. the relay links none of this track's three crates, so it could not call
//!    one by mistake,
//! 3. the working tree that brought the reply path touches no relay source file
//!    and no relay migration.
//!
//! Driven by `scripts/weald-stack agent-ship-gate` as the `relay unchanged` row
//! of the step 17 transcript.

use std::path::{Path, PathBuf};
use std::process::Command;

fn relay_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_root() -> PathBuf {
    // backend/wealdrelay -> backend -> root
    relay_dir()
        .parent()
        .and_then(Path::parent)
        .expect("the relay crate lives two levels under the repository root")
        .to_path_buf()
}

/// Every `.rs` file under a directory, sorted so a failure names the same file
/// on every machine.
fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let entries = std::fs::read_dir(&next)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", next.display()));
        for entry in entries {
            let path = entry.expect("a readable directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    assert!(
        !out.is_empty(),
        "no relay sources found under {}",
        dir.display()
    );
    out
}

/// The source with its comments removed.
///
/// Comments are stripped rather than searched because all three of the relay's
/// current mentions of the word are prose about who writes into a workspace
/// (`send_budget.rs`, `accept.rs`, `envelope/mod.rs`), and prose is not a
/// dependency. What the assertion is about is whether the relay's *code* names
/// the concept: an identifier, a frame kind, a column, a match arm.
fn code_only(src: &str) -> String {
    let bytes: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    let mut block_depth = 0usize;
    let mut in_line_comment = false;
    while i < bytes.len() {
        let c = bytes[i];
        let next = bytes.get(i + 1).copied();
        if in_line_comment {
            if c == '\n' {
                in_line_comment = false;
                out.push('\n');
            }
            i += 1;
            continue;
        }
        if block_depth > 0 {
            if c == '/' && next == Some('*') {
                block_depth += 1;
                i += 2;
                continue;
            }
            if c == '*' && next == Some('/') {
                block_depth -= 1;
                i += 2;
                continue;
            }
            if c == '\n' {
                out.push('\n');
            }
            i += 1;
            continue;
        }
        if c == '/' && next == Some('/') {
            in_line_comment = true;
            i += 2;
            continue;
        }
        if c == '/' && next == Some('*') {
            block_depth += 1;
            i += 2;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// The vocabulary this track introduced. A relay that named any of these in code
/// would be a relay that had learned what an agent is.
///
/// A correction made while writing this, recorded rather than applied quietly:
/// the first draft also listed bare `invocation` and `invoke`. Both are already
/// the relay's own words for something else entirely, `Invocation` being how
/// `src/lib.rs` models its argv (`--version`, `--help`, `serve`, `backup`), and
/// a check that reds on the relay's command-line parser is a check nobody keeps.
/// The discriminating token is `agent`; the compounds are listed beside it so a
/// failure names the exact frame kind that leaked rather than only the word.
const AGENT_VOCABULARY: &[&str] = &[
    "agent",
    "agent.card",
    "agent.invoke",
    "agent.lifecycle",
    "agent.lease",
    "agent.status",
];

#[test]
fn the_relay_source_names_no_agent_concept_in_code() {
    let mut offences: Vec<String> = Vec::new();
    for path in rust_sources(&relay_dir().join("src")) {
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let code = code_only(&text);
        for (n, line) in code.lines().enumerate() {
            let lowered = line.to_ascii_lowercase();
            for needle in AGENT_VOCABULARY {
                if lowered.contains(needle) {
                    offences.push(format!(
                        "{}:{}: names {:?} in code: {}",
                        path.display(),
                        n + 1,
                        needle,
                        line.trim()
                    ));
                }
            }
        }
    }
    assert!(
        offences.is_empty(),
        "the relay's code names an agent concept, so it is no longer blind to one:\n{}",
        offences.join("\n")
    );
}

/// The three crates the networked-agents track built above the relay.
const TRACK_CRATES: &[&str] = &["weald-agent-gateway", "weald-agent-worker", "weald-llm"];

#[test]
fn the_relay_links_none_of_the_track_crates() {
    let manifest =
        std::fs::read_to_string(relay_dir().join("Cargo.toml")).expect("the relay has a manifest");
    for crate_name in TRACK_CRATES {
        assert!(
            !manifest.contains(crate_name),
            "backend/wealdrelay/Cargo.toml names {crate_name}; the relay could call it"
        );
        // The underscored spelling is what a `use` would read, and a path
        // dependency renamed in the manifest would still show up here.
        let underscored = crate_name.replace('-', "_");
        for path in rust_sources(&relay_dir().join("src")) {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            let code = code_only(&text);
            assert!(
                !code.contains(&underscored),
                "{} names {underscored}; the relay could call it",
                path.display()
            );
        }
    }
}

#[test]
fn the_working_tree_touches_no_relay_source_or_migration() {
    let root = repo_root();
    let out = Command::new("git")
        .arg("-C")
        .arg(&root)
        .args([
            "status",
            "--porcelain",
            "--",
            "backend/wealdrelay/src",
            "backend/wealdrelay/migrations",
        ])
        .output()
        .expect("git is on PATH inside the repository");
    assert!(
        out.status.success(),
        "git status failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let dirty = String::from_utf8_lossy(&out.stdout);
    let dirty = dirty.trim();
    assert!(
        dirty.is_empty(),
        "the working tree changes relay source or migrations:\n{dirty}"
    );
}

#[test]
fn the_comment_stripper_keeps_code_and_drops_prose() {
    // The stripper is what makes check one honest, so it is pinned rather than
    // trusted: a line comment, a doc comment, a nested block comment and a real
    // line of code that happens to sit after one.
    let src = "//! agents are authored by delegated keys\n\
               let a = 1; // agent\n\
               /* agent /* still agent */ agent */ let b = 2;\n\
               let agent = 3;\n";
    let code = code_only(src);
    assert!(!code.contains("agents are authored"));
    assert!(code.contains("let a = 1;"));
    assert!(code.contains("let b = 2;"));
    assert!(code.contains("let agent = 3;"));
    // And the line count survives, so an offence reports the line a reader sees.
    assert_eq!(code.lines().count(), 4);
}
