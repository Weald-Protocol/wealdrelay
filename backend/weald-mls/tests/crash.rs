// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Kill the process at every boundary in the one transaction, and prove nothing tore.
//!
//! The obligation: kill the process between the MLS state write and the document write at
//! every injection point, assert recovery on the next launch, and leave no epoch the app
//! disagrees with.
//!
//! `specs/backend/relay/mls-binding.md`, "State storage", says why: "processing a commit
//! advances the epoch, and if the app crashes between advancing the MLS state and
//! recording the envelopes decrypted under it, the group is in a state the rest of the app
//! disagrees with. One transaction per processed message, covering both, is the entire
//! mitigation and it is not optional."
//!
//! And the same section's second half, quoting `wire.md`: kill the process "between
//! reserving a link and sending it", and the restarted client must resend "the identical
//! envelope rather than reissuing the counter over different content. A crash must never
//! produce a chain fork, because a chain fork is a security alarm on everybody else's
//! screen."
//!
//! The kill is a real one. `harness/crash-victim.rs` calls `std::process::abort`, this
//! file asserts the child died by signal, and a child that exited cleanly at a point that
//! asked for a crash fails the case rather than passing it. A test that killed itself with
//! `panic!` would be measuring Rust's unwinding: a rusqlite transaction rolls itself back
//! on drop, so the invariant would hold for a reason that has nothing to do with SQLite.
//!
//! The database is file-backed here, unlike every other suite in this crate. `:memory:`
//! would leave nothing to recover, which is the whole subject.

use std::path::{Path, PathBuf};
use std::process::Command;

use openmls::group::{GroupId, MlsGroup};
use openmls_traits::OpenMlsProvider as _;
use weald_mls::session::{Config, Device};
use weald_mls::store::Provider;

/// The group the victim works in. Must match the constant in `harness/crash-victim.rs`,
/// which is the process that loads it.
const GROUP: &[u8] = b"weald-crash-group";

/// The epoch the group is at before the commit under test is processed.
const EPOCH_BEFORE: u64 = 1;
/// The epoch it reaches once the commit is merged. The whole invariant is that this value
/// and the document side move together or not at all.
const EPOCH_AFTER: u64 = 2;

const DOC_ID: &str = "doc-1";
const BODY: &str = "the line the commit's epoch protects";
/// What a restarted client would send if it were free to reissue the counter over new
/// content. It must never appear on the wire.
const TEMPTING_BODY: &str = "different content under the same link";

// MARK: Driving the victim

/// The path to the built `crash-victim` binary.
///
/// Derived from this test binary's own location rather than from `cargo run`, because
/// `cargo run` inside a test would take the build lock the test runner already holds.
fn victim() -> PathBuf {
    let mut path = std::env::current_exe().expect("this test binary's path");
    path.pop(); // the deps directory
    path.pop(); // the profile directory
    path.push("crash-victim");
    assert!(
        path.exists(),
        "crash-victim is not built at {}. It is a bin target of this crate and \
         `cargo test` builds it; if this fires, the [[bin]] entry is missing.",
        path.display()
    );
    path
}

/// Every injection point, asked of the victim rather than listed here.
///
/// This is the point of the `points` subcommand: the matrix iterates what the sequence
/// actually contains, so a new boundary added to the victim is covered on the next run.
/// A list duplicated in the test would be a list that silently stopped matching.
fn injection_points() -> Vec<String> {
    let output = Command::new(victim())
        .arg("points")
        .output()
        .expect("the victim runs");
    assert!(output.status.success(), "the victim can list its points");
    serde_json::from_slice(&output.stdout).expect("a JSON list of names")
}

/// What the child did.
struct Death {
    signal: Option<i32>,
    code: Option<i32>,
}

impl Death {
    fn by_signal(&self) -> bool {
        self.signal.is_some()
    }
}

fn run_victim(args: &[&str], crash_at: &str) -> Death {
    use std::os::unix::process::ExitStatusExt as _;
    let status = Command::new(victim())
        .args(args)
        .env("WEALD_MLS_CRASH_AT", crash_at)
        .status()
        .expect("the victim runs");
    Death {
        signal: status.signal(),
        code: status.code(),
    }
}

// MARK: Setting up a group that has something to process

/// A group at epoch 1 in a file-backed database, plus the commit that would take it to 2.
///
/// Ada is the device under test. Bo joins her group, then Bo commits an add of Cy: a
/// commit Ada has not seen, produced by somebody else, which is exactly the message whose
/// processing the spec says must be transactional.
fn stage(dir: &Path) -> (PathBuf, PathBuf) {
    let database = dir.join("ada.sqlite");
    let database_path = database.to_str().expect("utf-8 path").to_string();

    let ada_device = Device::open(&Config {
        database: database_path.clone(),
        identity: b"ada".to_vec(),
    })
    .expect("ada's device");
    let mut ada = ada_device.create_group(GROUP).expect("a group");

    let bo_device = Device::open(&Config {
        database: ":memory:".into(),
        identity: b"bo".to_vec(),
    })
    .expect("bo's device");
    let (_, welcome) = ada
        .add(&bo_device.key_package().expect("a key package"))
        .expect("an add");
    assert_eq!(ada.merge_pending().expect("merged"), EPOCH_BEFORE);
    let mut bo = bo_device.join_welcome(&welcome).expect("bo joined");

    let cy_device = Device::open(&Config {
        database: ":memory:".into(),
        identity: b"cy".to_vec(),
    })
    .expect("cy's device");
    let (commit, _) = bo
        .add(&cy_device.key_package().expect("a key package"))
        .expect("bo commits an add");

    let message = dir.join("commit.mls");
    std::fs::write(&message, &commit).expect("the commit is written");

    // Everything is dropped before the victim runs, so the file is not held open by this
    // process. A second connection would still work, but the test would then be proving
    // something about SQLite's locking rather than about the crash.
    drop(bo);
    drop(ada);
    drop(bo_device);
    drop(cy_device);
    drop(ada_device);

    (database, message)
}

// MARK: Reading the wreckage

/// What the database says after the child died, read in this process.
#[derive(Debug)]
struct Recovered {
    mls_epoch: Option<u64>,
    app_epoch: Option<i64>,
    documents: i64,
    chain_links: i64,
    unsent_links: i64,
    /// The envelope bytes reserved for link 1, if a link was ever reserved.
    reserved: Option<Vec<u8>>,
}

/// Reopen the database the way a relaunched app does and read both sides.
///
/// In-process and through the crate's own `Provider`, because the claim is about what the
/// next launch sees, and the next launch opens this file with this code.
fn recover(database: &Path) -> Recovered {
    let provider = Provider::open(database.to_str().expect("utf-8 path")).expect("reopened");
    let mls_epoch = MlsGroup::load(provider.storage(), &GroupId::from_slice(GROUP))
        .expect("the group loads")
        .map(|group| group.epoch().as_u64());

    let connection = provider.connection();
    let table_missing =
        |sql: &str| -> i64 { connection.query_row(sql, [], |r| r.get(0)).unwrap_or(0) };
    Recovered {
        mls_epoch,
        app_epoch: connection
            .query_row(
                "select epoch from weald_epoch where group_id = ?1",
                rusqlite::params![GROUP],
                |row| row.get(0),
            )
            .ok(),
        documents: table_missing("select count(*) from weald_document"),
        chain_links: table_missing("select count(*) from weald_chain"),
        unsent_links: table_missing("select count(*) from weald_chain where sent = 0"),
        reserved: connection
            .query_row(
                "select envelope from weald_chain where link = 1",
                [],
                |row| row.get(0),
            )
            .ok(),
    }
}

/// Everything that was actually put on the wire, in order of link.
fn outbox(dir: &Path) -> Vec<Vec<u8>> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    files.sort();
    files
        .iter()
        .map(|path| std::fs::read(path).expect("an envelope"))
        .collect()
}

// MARK: The matrix

/// One row of the crash matrix, which is also the artifact the gate collects.
#[derive(serde::Serialize)]
struct Row {
    injection_point: String,
    died_by_signal: bool,
    signal: Option<i32>,
    exit_code: Option<i32>,
    mls_epoch: Option<u64>,
    app_epoch: Option<i64>,
    documents: i64,
    chain_links: i64,
    committed: bool,
    resent_identical_envelope: bool,
    chain_forked: bool,
    verdict: &'static str,
}

#[test]
fn every_injection_point_leaves_the_epoch_and_the_documents_agreeing() {
    let points = injection_points();
    // The list has to contain the boundaries the spec names by name. Asserted rather than
    // assumed, because a victim that quietly stopped offering "after_mls_state_write" would
    // still produce a green matrix that proved nothing about the sharp edge.
    for required in [
        "before_begin",
        "after_begin",
        "after_mls_state_write",
        "after_chain_reservation",
        "after_document_write",
        "before_commit",
        "after_commit",
    ] {
        assert!(
            points.iter().any(|p| p == required),
            "the victim has no injection point called {required}"
        );
    }

    let mut rows: Vec<Row> = Vec::new();
    for point in &points {
        rows.push(one_injection_point(point));
    }

    // Both outcomes must actually occur across the matrix, or the invariant would be
    // satisfiable by a victim that never commits anything.
    assert!(
        rows.iter().any(|row| row.committed),
        "no injection point ever reached a committed state, so nothing was proved"
    );
    assert!(
        rows.iter().any(|row| !row.committed),
        "no injection point ever rolled back, so nothing was proved"
    );

    if std::env::var("WEALD_MLS_EVIDENCE").as_deref() == Ok("1") {
        write_evidence(&rows);
    }
}

/// One case: stage a group, kill the victim at `point`, and read both sides back.
fn one_injection_point(point: &str) -> Row {
    let dir = tempfile::tempdir().expect("a temp dir");
    let (database, message) = stage(dir.path());
    let out = dir.path().join("outbox");

    let death = run_victim(
        &[
            "process",
            database.to_str().expect("utf-8"),
            message.to_str().expect("utf-8"),
            DOC_ID,
            BODY,
            out.to_str().expect("utf-8"),
        ],
        point,
    );

    if point == "none" {
        // The control. It must complete, or every other row would be a comparison against
        // a sequence that never worked.
        assert!(
            !death.by_signal() && death.code == Some(0),
            "the control run did not complete: {:?}/{:?}",
            death.signal,
            death.code
        );
    } else {
        // A clean exit at a point that asked for a crash is not a crash, and accepting one
        // would turn every row of this matrix into a test of a process that ran to
        // completion. `abort` raises SIGABRT and the child must die by it.
        assert!(
            death.by_signal(),
            "the victim exited cleanly at {point} (code {:?}) instead of dying by signal",
            death.code
        );
    }

    let state = recover(&database);
    let committed = state.mls_epoch == Some(EPOCH_AFTER);

    // THE INVARIANT. Either the commit and the envelopes it decrypted are both there, or
    // neither is. A row that broke this is a group at an epoch the rest of the app
    // disagrees with, which is the failure `mls-binding.md` calls not optional to prevent.
    if committed {
        assert_eq!(
            state.documents, 1,
            "at {point} the epoch advanced to {EPOCH_AFTER} and the document it decrypted \
             is missing: the group is ahead of the app"
        );
        assert_eq!(
            state.app_epoch,
            Some(i64::try_from(EPOCH_AFTER).expect("small")),
            "at {point} the group is at {EPOCH_AFTER} and the app recorded {:?}",
            state.app_epoch
        );
        assert_eq!(
            state.chain_links, 1,
            "at {point} the epoch advanced without a reserved link, so the envelope it \
             produced has no place in the author chain"
        );
    } else {
        assert_eq!(
            state.mls_epoch,
            Some(EPOCH_BEFORE),
            "at {point} the group is neither at the old epoch nor the new one"
        );
        assert_eq!(
            state.documents, 0,
            "at {point} a document was recorded under an epoch the group never reached"
        );
        assert_eq!(
            state.chain_links, 0,
            "at {point} a link was reserved by a transaction that rolled back, which \
             would leave the counter ahead of the chain"
        );
        assert_eq!(
            state.app_epoch, None,
            "at {point} the app recorded an epoch the group never reached"
        );
    }

    // The author-chain half. Restart, hand the restarted client different content, and
    // watch what it puts on the wire.
    let before = outbox(&out);
    let resume = Command::new(victim())
        .args([
            "resume",
            database.to_str().expect("utf-8"),
            out.to_str().expect("utf-8"),
            TEMPTING_BODY,
        ])
        .output()
        .expect("the restarted client runs");
    assert!(
        resume.status.success(),
        "the restarted client failed at {point}: {}",
        String::from_utf8_lossy(&resume.stderr)
    );
    let after = outbox(&out);

    let expected = state.reserved.clone().unwrap_or_default();
    let mut resent_identical = true;
    let mut forked = false;
    for envelope in &after {
        let text = String::from_utf8_lossy(envelope);
        // A fork is the counter reissued over content it did not commit to. It is detected
        // by content and not by count, because a resend of identical bytes is not a fork
        // and must be allowed: that is precisely what a crash between reserve and send
        // requires the client to do.
        if text.contains(TEMPTING_BODY) {
            forked = true;
        }
        if !expected.is_empty() && !text.contains(BODY) {
            resent_identical = false;
        }
    }
    assert!(
        !forked,
        "at {point} the restarted client reissued link 1 over different content. That is a \
         chain fork, which is a security alarm on every other member's screen."
    );
    assert!(
        resent_identical,
        "at {point} the restarted client sent an envelope that is not the one it reserved"
    );
    if state.chain_links == 1 {
        // Exactly one link, still. A restart that allocated a second link for the same
        // work would burn a counter value nobody can account for, and the next real send
        // would land on a number the group has already seen skipped.
        let recovered_after = recover(&database);
        assert_eq!(
            recovered_after.chain_links, 1,
            "at {point} the restart reserved a second link for work already reserved"
        );
        assert_eq!(
            recovered_after.unsent_links, 0,
            "at {point} the restart left a reserved link unsent, so it is lost"
        );
        assert_eq!(
            recovered_after.reserved.as_deref(),
            expected.as_slice().into(),
            "at {point} the reserved envelope changed across the restart"
        );
        // And it did reach the wire, either before the crash or on the restart.
        assert!(
            !after.is_empty(),
            "at {point} a reserved link was never sent, before or after the restart"
        );
        assert!(
            after.len() >= before.len(),
            "at {point} the restart removed something from the wire"
        );
    } else {
        assert!(
            after.is_empty(),
            "at {point} nothing was reserved and yet something was sent"
        );
    }

    let final_state = recover(&database);
    Row {
        injection_point: point.to_string(),
        died_by_signal: death.by_signal(),
        signal: death.signal,
        exit_code: death.code,
        mls_epoch: final_state.mls_epoch,
        app_epoch: final_state.app_epoch,
        documents: final_state.documents,
        chain_links: final_state.chain_links,
        committed,
        resent_identical_envelope: resent_identical,
        chain_forked: forked,
        verdict: "consistent",
    }
}

/// The recorded artifact for this suite: the crash matrix.
///
/// Written only under `WEALD_MLS_EVIDENCE=1`, so an ordinary `cargo test` does not write
/// into the tree. The gate sets it.
fn write_evidence(rows: &[Row]) {
    // `WEALD_GATE_EVIDENCE_DIR` is where the gate that asked for this is looking, and a
    // gate run can redirect a whole sweep's evidence elsewhere. A matrix written to the
    // checked-in path while the gate read the redirected directory was the shape that made
    // this suite fail on a clean checkout and pass locally against the copy an earlier run
    // had committed. The checked-in path stays the default.
    let root = match std::env::var("WEALD_GATE_EVIDENCE_DIR") {
        Ok(dir) if !dir.is_empty() => std::path::PathBuf::from(dir),
        _ => Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("the repository root")
            .join("build-evidence")
            .join("step-07"),
    };
    std::fs::create_dir_all(&root).expect("the evidence directory");
    let document = serde_json::json!({
        "spec": "specs/backend/relay/mls-binding.md#state-storage",
        "gate": "mls binding, crash consistency",
        "invariant":
            "either the merged commit and the envelopes decrypted under it are both \
             durable, or neither is; and a restart resends the identical reserved \
             envelope rather than reissuing the counter over different content",
        "injection_points": rows.len(),
        "rows": rows,
    });
    std::fs::write(
        root.join("crash-matrix.json"),
        serde_json::to_string_pretty(&document).expect("serialised") + "\n",
    )
    .expect("the crash matrix is written");
}
