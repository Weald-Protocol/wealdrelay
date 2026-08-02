// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Every way the crash victim can be told to do something it must refuse.
//!
//! `tests/crash.rs` proves the invariant across the sequence's happy path and its ten
//! injection points. This file is the other half of the same claim: that the process which
//! carries the invariant reports what it cannot do instead of doing part of it.
//!
//! `specs/backend/relay/mls-binding.md`, "State storage": "processing a commit advances
//! the epoch, and if the app crashes between advancing the MLS state and recording the
//! envelopes decrypted under it, the group is in a state the rest of the app disagrees
//! with. One transaction per processed message, covering both, is the entire mitigation
//! and it is not optional."
//!
//! A refusal is that mitigation seen from the other side. Every case below drives the real
//! binary with hostile input, asserts the exit code, asserts that stderr names the actual
//! reason rather than failing anonymously, and where the sequence had already started,
//! asserts that the database came back to the epoch it was at. A run that reported an
//! error and left half a transaction behind would satisfy an exit-code assertion and break
//! the property the spec calls not optional, so the state is read back in every case that
//! got far enough to have any.
//!
//! The same section's second half, quoting `wire.md`, is why the author-chain failures are
//! here too: a restart must resend "the identical envelope rather than reissuing the
//! counter over different content", and a restart that cannot resend has to say so rather
//! than report success over a link that is still sitting unsent.
//!
//! The binary is the one `cargo test` built, found from this test binary's own location,
//! for the reason `tests/crash.rs` gives: `cargo run` inside a test would take the build
//! lock the test runner already holds.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use openmls::group::{GroupId, MlsGroup};
use openmls_traits::OpenMlsProvider as _;
use weald_mls::session::{Config, Device};
use weald_mls::store::Provider;

/// The group the victim works in. Must match the constant in `src/bin/crash-victim.rs`.
const GROUP: &[u8] = b"weald-crash-group";

/// The epoch the staged group is at before the commit under test is processed.
const EPOCH_BEFORE: u64 = 1;
/// The epoch it reaches once that commit is merged.
const EPOCH_AFTER: u64 = 2;

const DOC_ID: &str = "doc-1";
const BODY: &str = "the line the commit's epoch protects";
const TEMPTING_BODY: &str = "different content under the same link";

// MARK: Driving the victim

/// The path to the built `crash-victim` binary.
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

/// Run the victim to completion with no injection point set.
fn run(args: &[&str]) -> Output {
    Command::new(victim())
        .args(args)
        .env("WEALD_MLS_CRASH_AT", "")
        .output()
        .expect("the victim runs")
}

/// Run the victim with an injection point set, and return what it printed.
fn run_crashing(args: &[&str], crash_at: &str) -> Output {
    Command::new(victim())
        .args(args)
        .env("WEALD_MLS_CRASH_AT", crash_at)
        .output()
        .expect("the victim runs")
}

/// What the process said about why it stopped.
fn complaint(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Assert the run refused, with the exit code a refusal uses and a reason that names the
/// thing that went wrong.
///
/// Both halves matter. An exit code alone would pass for a process that refused for a
/// reason nobody can act on, and this binary's whole job is to be legible after the fact.
fn refused(output: &Output, reason: &str) {
    let said = complaint(output);
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected a refusal about {reason:?}, got {:?} with stderr {said:?}",
        output.status
    );
    assert!(
        said.contains(reason),
        "the refusal did not name {reason:?}. stderr was {said:?}"
    );
}

// MARK: Staging

/// A group at epoch 1 in a file-backed database, plus the commit that would take it to 2,
/// an application message from the same sender, and a key package.
///
/// The same staging `tests/crash.rs` uses, with two extra messages so the cases about
/// "this is not the kind of message the sequence handles" have something real to be about.
/// Every one of them is produced by a real device through the real seam: a hand-built
/// message would be testing this file's idea of MLS rather than OpenMLS's.
struct Staged {
    database: PathBuf,
    commit: PathBuf,
    application: PathBuf,
    key_package: PathBuf,
}

fn stage(dir: &Path) -> Staged {
    let database = dir.join("ada.sqlite");
    let database_path = database.to_str().expect("utf-8 path").to_string();

    let ada_device = Device::open(&Config {
        database: database_path,
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

    // An ordinary application message at the epoch ada is sitting at. It decrypts, so the
    // victim gets all the way to asking what kind of message it is.
    let application = dir.join("application.mls");
    std::fs::write(
        &application,
        bo.encrypt(b"an ordinary line of text").expect("encrypted"),
    )
    .expect("the application message is written");

    let cy_device = Device::open(&Config {
        database: ":memory:".into(),
        identity: b"cy".to_vec(),
    })
    .expect("cy's device");
    let (commit_bytes, _) = bo
        .add(&cy_device.key_package().expect("a key package"))
        .expect("bo commits an add");
    let commit = dir.join("commit.mls");
    std::fs::write(&commit, &commit_bytes).expect("the commit is written");

    let key_package = dir.join("key-package.mls");
    std::fs::write(
        &key_package,
        cy_device.key_package().expect("a key package"),
    )
    .expect("the key package is written");

    drop(bo);
    drop(ada);
    drop(bo_device);
    drop(cy_device);
    drop(ada_device);

    Staged {
        database,
        commit,
        application,
        key_package,
    }
}

impl Staged {
    fn db(&self) -> &str {
        self.database.to_str().expect("utf-8")
    }
}

// MARK: Reading the database back

/// What the next launch would see: the group's epoch, and the app's two tables.
#[derive(Debug, PartialEq, Eq)]
struct State {
    mls_epoch: Option<u64>,
    documents: i64,
    chain_links: i64,
}

fn state(database: &Path) -> State {
    let provider = Provider::open(database.to_str().expect("utf-8 path")).expect("reopened");
    let mls_epoch = MlsGroup::load(provider.storage(), &GroupId::from_slice(GROUP))
        .expect("the group loads")
        .map(|group| group.epoch().as_u64());
    let connection = provider.connection();
    let counted = |sql: &str| -> i64 { connection.query_row(sql, [], |r| r.get(0)).unwrap_or(0) };
    State {
        mls_epoch,
        documents: counted("select count(*) from weald_document"),
        chain_links: counted("select count(*) from weald_chain"),
    }
}

/// Run one statement batch against the staged database, as a foreign or damaged database
/// would already contain it.
///
/// A plain connection rather than a `Provider`, because what is being installed is a
/// schema the provider would never write. That is the point: the victim has to survive
/// opening a database it did not create.
fn sabotage(database: &Path, sql: &str) {
    let connection =
        rusqlite::Connection::open(database).expect("the staged database opens for sabotage");
    connection.execute_batch(sql).expect("the sabotage applies");
}

/// The shape `migrate` would have created, so a trigger can be hung off it.
const REAL_CHAIN: &str = "create table weald_chain ( \
     link integer primary key, \
     envelope blob not null, \
     sent integer not null default 0 \
   );";

// MARK: The modes themselves

/// A mode this binary does not have is refused by name, and nothing is opened.
///
/// `specs/backend/relay/mls-binding.md` makes the victim the process that carries the
/// one-transaction rule, and a process that silently did nothing for an argument it did
/// not understand would make a mistyped gate script look like a passing gate.
#[test]
fn a_mode_the_victim_does_not_have_is_refused_by_name_rather_than_ignored() {
    let output = run(&["fly"]);
    refused(&output, "unknown mode");
    // The mode is quoted back, so a script with a typo can see its own typo.
    assert!(complaint(&output).contains("\"fly\""));

    // And no arguments at all is the same refusal, not a success. A bare invocation that
    // exited zero would be a gate script that ran nothing and reported a pass.
    let bare = run(&[]);
    refused(&bare, "unknown mode");
    assert!(complaint(&bare).contains("\"\""));
}

/// `points` is the list the crash matrix iterates, and it is the one thing this binary
/// does without touching a database.
///
/// Asserted here as well as used in `tests/crash.rs` so that the contract between the two,
/// a JSON array on stdout and a zero exit, is stated somewhere as a claim.
#[test]
fn the_points_subcommand_prints_the_injection_points_as_json_and_touches_nothing() {
    let output = run(&["points"]);
    assert_eq!(output.status.code(), Some(0));
    let points: Vec<String> = serde_json::from_slice(&output.stdout).expect("a JSON list");
    assert!(points.contains(&"none".to_string()));
    assert!(points.contains(&"after_mls_state_write".to_string()));
    assert!(complaint(&output).is_empty(), "it said nothing on stderr");
}

/// Too few arguments prints the usage and creates no database.
///
/// The victim's `Provider::open` creates the file and its parent directory, so a run that
/// got past argument parsing leaves a database behind. Asserting the file does not exist
/// is what proves the refusal happened before anything was opened.
#[test]
fn processing_with_the_wrong_arguments_prints_the_usage_and_creates_no_database() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let database = dir.path().join("never.sqlite");
    let output = run(&["process", database.to_str().expect("utf-8")]);
    refused(&output, "crash-victim process <db> <message-file>");
    assert!(
        !database.exists(),
        "a run that never parsed its arguments still created a database"
    );
}

/// A message file that is not there is named, and the database is still not opened.
///
/// The order matters and is asserted rather than assumed: the message is read before the
/// database is opened, so a missing file cannot leave a half-created workspace behind.
#[test]
fn a_message_file_that_cannot_be_read_is_named_and_no_database_is_created() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let database = dir.path().join("never.sqlite");
    let missing = dir.path().join("not-here.mls");
    let output = run(&[
        "process",
        database.to_str().expect("utf-8"),
        missing.to_str().expect("utf-8"),
        DOC_ID,
        BODY,
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&output, "cannot read");
    assert!(complaint(&output).contains("not-here.mls"));
    assert!(!database.exists(), "the database was created anyway");
}

/// A database path that cannot be opened is a refusal, not a panic.
///
/// A directory where a file has to be. `store::Provider` turns that into a `Storage`
/// error, and the victim's job is to print it with the path attached.
#[test]
fn a_database_that_cannot_be_opened_is_named_in_both_modes() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let occupied = dir.path().join("a-directory");
    std::fs::create_dir(&occupied).expect("a directory in the way");
    let message = dir.path().join("message.mls");
    std::fs::write(&message, b"anything at all").expect("a message file");

    let processing = run(&[
        "process",
        occupied.to_str().expect("utf-8"),
        message.to_str().expect("utf-8"),
        DOC_ID,
        BODY,
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&processing, "cannot open");

    // The relaunch has the same failure and must report it the same way, because the
    // relaunch is the half a person actually runs after a crash.
    let resuming = run(&[
        "resume",
        occupied.to_str().expect("utf-8"),
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&resuming, "cannot open");
}

/// A database where the app's own table name is taken by something that is not a table
/// fails the migration by name, in both modes.
///
/// `migrate` runs outside the transaction under test on purpose, and this is the failure
/// that makes that decision visible: the schema never came up, so the sequence must not
/// start at all rather than begin a transaction it cannot use.
#[test]
fn a_schema_the_migration_cannot_create_is_reported_in_both_modes() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let staged = stage(dir.path());
    // An index wearing the name the migration wants for a table. `create table if not
    // exists` does not treat that as "already there", it refuses.
    sabotage(
        &staged.database,
        "create index weald_chain on openmls_group_data(group_id);",
    );

    let processing = run(&[
        "process",
        staged.db(),
        staged.commit.to_str().expect("utf-8"),
        DOC_ID,
        BODY,
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&processing, "cannot migrate");

    let resuming = run(&[
        "resume",
        staged.db(),
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&resuming, "cannot migrate");

    // Nothing was processed, so the group is where it was.
    assert_eq!(state(&staged.database).mls_epoch, Some(EPOCH_BEFORE));
}

/// A database with no group in it is reported, not treated as an empty group.
///
/// The relaunch path has the opposite answer for the same input, and that difference is
/// the point of asserting them together. `process` has nothing to process a commit
/// against and refuses. `resume` reports a null epoch and exits zero, because a device
/// that has not joined anything yet is a device with nothing to resend, not an error.
#[test]
fn a_database_with_no_group_refuses_to_process_and_still_resumes() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let staged = stage(dir.path());
    let empty = dir.path().join("empty.sqlite");
    // A real provider database, migrated, with no group in it: what a device looks like
    // before it has joined anything.
    drop(Provider::open(empty.to_str().expect("utf-8")).expect("an empty provider"));

    let processing = run(&[
        "process",
        empty.to_str().expect("utf-8"),
        staged.commit.to_str().expect("utf-8"),
        DOC_ID,
        BODY,
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&processing, "no group in");

    let resuming = run(&[
        "resume",
        empty.to_str().expect("utf-8"),
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    assert_eq!(resuming.status.code(), Some(0));
    let report: serde_json::Value =
        serde_json::from_slice(&resuming.stdout).expect("a JSON report");
    assert!(
        report["mls_epoch"].is_null(),
        "a device with no group reported an epoch: {report}"
    );
    assert_eq!(report["chain_links"], 0);
    assert_eq!(report["resent"].as_array().expect("a list").len(), 0);
}

/// A group whose stored state is damaged is reported as unloadable, not as absent.
///
/// The distinction is the whole reason `MlsGroup::load` has three outcomes. A damaged row
/// read as "no group" would make a relaunch quietly abandon a group the person is still a
/// member of, which is the same class of loss as an epoch the app disagrees with.
#[test]
fn a_group_whose_stored_state_is_damaged_is_unloadable_rather_than_absent() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let staged = stage(dir.path());
    // One row of the group's persisted tree, replaced with bytes that are not the codec's.
    sabotage(
        &staged.database,
        "update openmls_group_data set group_data = cast('not the codec''s json' as blob) \
         where data_type = 'tree';",
    );

    let processing = run(&[
        "process",
        staged.db(),
        staged.commit.to_str().expect("utf-8"),
        DOC_ID,
        BODY,
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&processing, "cannot load the group");

    let resuming = run(&[
        "resume",
        staged.db(),
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&resuming, "cannot load the group");
}

// MARK: Messages the sequence must refuse

/// Bytes that are not an MLS message are refused before the group is touched.
#[test]
fn bytes_that_are_not_an_mls_message_are_refused_and_change_nothing() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let staged = stage(dir.path());
    let garbage = dir.path().join("garbage.mls");
    std::fs::write(&garbage, b"\xff\xff\xff not an mls message at all").expect("written");

    let output = run(&[
        "process",
        staged.db(),
        garbage.to_str().expect("utf-8"),
        DOC_ID,
        BODY,
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&output, "malformed message");
    assert_eq!(
        state(&staged.database),
        State {
            mls_epoch: Some(EPOCH_BEFORE),
            documents: 0,
            chain_links: 0
        }
    );
}

/// A key package is an MLS message and is still not something a group can process.
///
/// It deserialises, so the refusal has to come from `try_into_protocol_message` rather
/// than from the parser. A binding that fed it to the group anyway would be handing
/// OpenMLS a message it has no epoch for.
#[test]
fn an_mls_message_that_is_not_a_protocol_message_is_refused_as_one() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let staged = stage(dir.path());

    let output = run(&[
        "process",
        staged.db(),
        staged.key_package.to_str().expect("utf-8"),
        DOC_ID,
        BODY,
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&output, "not a protocol message");
    assert_eq!(state(&staged.database).mls_epoch, Some(EPOCH_BEFORE));
}

/// A commit the group has already merged is refused, and the epoch does not move twice.
///
/// This is the case a retry after a crash actually produces: the transaction committed,
/// the acknowledgement was lost, and the same commit arrives again. The group is past it,
/// OpenMLS refuses it, and the app's two tables are exactly as the first run left them.
#[test]
fn a_commit_the_group_has_already_merged_is_refused_and_the_epoch_does_not_move_twice() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let staged = stage(dir.path());
    let outbox = dir.path().join("outbox");
    let args = [
        "process",
        staged.db(),
        staged.commit.to_str().expect("utf-8"),
        DOC_ID,
        BODY,
        outbox.to_str().expect("utf-8"),
    ];

    let first = run(&args);
    assert_eq!(first.status.code(), Some(0), "{}", complaint(&first));
    let after_first = state(&staged.database);
    assert_eq!(after_first.mls_epoch, Some(EPOCH_AFTER));

    let again = run(&args);
    refused(&again, "refused");
    assert_eq!(
        state(&staged.database),
        after_first,
        "a refused replay changed the database"
    );
}

/// An application message decrypts and is still not a commit, and is refused as one.
///
/// The sequence's next step after `process_message` is `merge_staged_commit`, and the
/// content check in front of it is what keeps a plain message from reaching it. The
/// refusal happens inside the transaction, so this case is also the proof that a refusal
/// after the transaction opened leaves nothing behind.
#[test]
fn an_application_message_is_not_a_commit_and_is_refused_inside_the_transaction() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let staged = stage(dir.path());

    let output = run(&[
        "process",
        staged.db(),
        staged.application.to_str().expect("utf-8"),
        DOC_ID,
        BODY,
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&output, "must be a commit");
    assert_eq!(
        state(&staged.database),
        State {
            mls_epoch: Some(EPOCH_BEFORE),
            documents: 0,
            chain_links: 0
        }
    );
}

// MARK: Failures inside the transaction

/// A merge the storage refuses is reported, and the group stays where it was.
///
/// `process_message` stages a commit and writes nothing; `merge_staged_commit` is the line
/// that advances the epoch and persists it. Making OpenMLS's own group-state write fail is
/// the only way to sit exactly between the two, and it is the case `mls-binding.md` is
/// least willing to get wrong: a group whose merge half-landed is a group at an epoch
/// nobody else agrees with. The reopened group has to be at the old epoch, still able to
/// load, with nothing recorded against the new one.
#[test]
fn a_merge_the_storage_refuses_is_reported_and_leaves_the_group_at_the_old_epoch() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let staged = stage(dir.path());
    // The row the merge writes and the staging never touches.
    sabotage(
        &staged.database,
        "create trigger openmls_secrets_frozen before insert on openmls_group_data \
         when new.data_type = 'group_epoch_secrets' \
         begin select raise(abort, 'the group state cannot be written'); end;",
    );

    let output = run(&[
        "process",
        staged.db(),
        staged.commit.to_str().expect("utf-8"),
        DOC_ID,
        BODY,
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&output, "cannot merge");
    assert_eq!(
        state(&staged.database),
        State {
            mls_epoch: Some(EPOCH_BEFORE),
            documents: 0,
            chain_links: 0
        }
    );
}

/// A chain table the sequence cannot read stops it before the epoch is recorded anywhere,
/// and the merged commit goes back with it.
///
/// This is the sharpest of these cases. The MLS state write has already happened when the
/// chain is read, so a refusal here is a refusal after the epoch advanced in memory. The
/// assertion that the reopened group is still at the old epoch is the one-transaction rule
/// holding on an ordinary error rather than on a kill.
#[test]
fn a_chain_the_sequence_cannot_read_rolls_the_merged_commit_back_with_it() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let staged = stage(dir.path());
    // A chain table with no link column. `create table if not exists` leaves it alone.
    sabotage(
        &staged.database,
        "create table weald_chain (envelope blob not null, sent integer not null default 0);",
    );

    let output = run(&[
        "process",
        staged.db(),
        staged.commit.to_str().expect("utf-8"),
        DOC_ID,
        BODY,
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&output, "cannot read the chain");
    assert_eq!(
        state(&staged.database),
        State {
            mls_epoch: Some(EPOCH_BEFORE),
            documents: 0,
            chain_links: 0
        }
    );
}

/// A link that cannot be reserved takes the merged commit back with it too.
///
/// `wire.md`, quoted in `mls-binding.md`: reserve, then send. A sequence that merged a
/// commit and then failed to reserve the link for the envelope it produced must not keep
/// the merge, or the next run reserves a link for work the group already did.
#[test]
fn a_link_that_cannot_be_reserved_rolls_the_merged_commit_back() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let staged = stage(dir.path());
    // A chain table with a link but nowhere to put the envelope.
    sabotage(
        &staged.database,
        "create table weald_chain (link integer primary key, sent integer not null default 0);",
    );

    let output = run(&[
        "process",
        staged.db(),
        staged.commit.to_str().expect("utf-8"),
        DOC_ID,
        BODY,
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&output, "cannot reserve a link");
    assert_eq!(state(&staged.database).mls_epoch, Some(EPOCH_BEFORE));
}

/// A document that cannot be written takes the epoch back with it.
///
/// The exact pairing `mls-binding.md` names: the epoch advanced and the envelope it
/// decrypted could not be recorded. The mitigation is that neither survives.
#[test]
fn a_document_that_cannot_be_written_takes_the_epoch_back_with_it() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let staged = stage(dir.path());
    // A document table with only its key: the insert of a body and an epoch cannot land.
    sabotage(
        &staged.database,
        "create table weald_document (id text primary key);",
    );

    let output = run(&[
        "process",
        staged.db(),
        staged.commit.to_str().expect("utf-8"),
        DOC_ID,
        BODY,
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&output, "cannot write the document");
    let after = state(&staged.database);
    assert_eq!(after.mls_epoch, Some(EPOCH_BEFORE));
    assert_eq!(
        after.chain_links, 0,
        "the link reserved by the failed run outlived it"
    );
}

/// An epoch the app cannot record is the same failure, and rolls back the same way.
#[test]
fn an_epoch_the_app_cannot_record_rolls_the_whole_message_back() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let staged = stage(dir.path());
    sabotage(
        &staged.database,
        "create table weald_epoch (group_id blob primary key);",
    );

    let output = run(&[
        "process",
        staged.db(),
        staged.commit.to_str().expect("utf-8"),
        DOC_ID,
        BODY,
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&output, "cannot record the epoch");
    assert_eq!(
        state(&staged.database),
        State {
            mls_epoch: Some(EPOCH_BEFORE),
            documents: 0,
            chain_links: 0
        }
    );
}

/// A commit that the database refuses at the last moment discards every write in it.
///
/// A deferred foreign key is the one way to make SQLite accept every statement in a
/// transaction and then refuse the transaction, which is exactly the shape of a failure
/// arriving after the sequence believed it was done. Every write, including the MLS state
/// write, goes back: the group is at the old epoch, with no document and no link.
#[test]
fn a_transaction_the_database_refuses_at_commit_time_discards_every_write_in_it() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let staged = stage(dir.path());
    sabotage(
        &staged.database,
        "create table weald_document_epochs (epoch integer primary key); \
         create table weald_document ( \
           id text primary key, \
           body blob not null, \
           epoch integer not null \
             references weald_document_epochs(epoch) deferrable initially deferred \
         );",
    );

    let output = run(&[
        "process",
        staged.db(),
        staged.commit.to_str().expect("utf-8"),
        DOC_ID,
        BODY,
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&output, "cannot commit");
    assert_eq!(
        state(&staged.database),
        State {
            mls_epoch: Some(EPOCH_BEFORE),
            documents: 0,
            chain_links: 0
        }
    );
}

/// An outbox that is a file rather than a directory is named before anything is sent.
///
/// The wire is outside the database, and a wire that cannot be written to is not a
/// transaction failure. The run has already committed by the time it sends, so what is
/// asserted here is that the reason is printed by name and that the committed state is
/// still whole: the epoch, the document and the reserved link all survive, and the link
/// is left unsent for the relaunch to resend.
#[test]
fn an_outbox_that_is_not_a_directory_is_named_and_the_committed_state_survives() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let staged = stage(dir.path());
    let outbox = dir.path().join("outbox");
    std::fs::write(&outbox, b"a file where the outbox should be").expect("a file in the way");

    let output = run(&[
        "process",
        staged.db(),
        staged.commit.to_str().expect("utf-8"),
        DOC_ID,
        BODY,
        outbox.to_str().expect("utf-8"),
    ]);
    assert!(
        !output.status.success(),
        "sending into a file reported success"
    );
    let said = complaint(&output);
    assert!(
        said.contains("cannot create"),
        "the outbox problem was not named: {said:?}"
    );
    // Committed before the send was attempted, and still whole.
    assert_eq!(
        state(&staged.database),
        State {
            mls_epoch: Some(EPOCH_AFTER),
            documents: 1,
            chain_links: 1
        }
    );
}

/// A chain row that cannot be marked sent is reported rather than counted as sent.
///
/// `wire.md`'s ordering is send, then mark. This is the failure of the second half: the
/// bytes reached the wire and the database would not record it. The refusal is what keeps
/// the run from reporting success over a link the next launch has no way to know about,
/// and the row stays unsent so the relaunch resends the identical envelope.
#[test]
fn a_chain_row_that_cannot_be_marked_sent_is_reported_and_left_unsent() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let staged = stage(dir.path());
    let outbox = dir.path().join("outbox");
    sabotage(
        &staged.database,
        &format!(
            "{REAL_CHAIN} create trigger weald_chain_frozen before update on weald_chain \
             begin select raise(abort, 'this chain row cannot be updated'); end;"
        ),
    );

    let output = run(&[
        "process",
        staged.db(),
        staged.commit.to_str().expect("utf-8"),
        DOC_ID,
        BODY,
        outbox.to_str().expect("utf-8"),
    ]);
    refused(&output, "cannot send");
    // The transaction had already committed, so the merge and the reservation are durable
    // and the link is the one thing left outstanding.
    let after = state(&staged.database);
    assert_eq!(after.mls_epoch, Some(EPOCH_AFTER));
    assert_eq!(after.chain_links, 1);
    let sent: i64 = rusqlite::Connection::open(&staged.database)
        .expect("reopened")
        .query_row("select sent from weald_chain where link = 1", [], |row| {
            row.get(0)
        })
        .expect("the reserved row");
    assert_eq!(
        sent, 0,
        "a link that could not be marked sent was recorded as sent"
    );
}

// MARK: The relaunch

/// The relaunch refuses its own bad arguments and creates nothing.
#[test]
fn resuming_with_the_wrong_arguments_prints_the_usage_and_creates_no_database() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let database = dir.path().join("never.sqlite");
    let output = run(&["resume", database.to_str().expect("utf-8")]);
    refused(&output, "crash-victim resume <db> <outbox>");
    assert!(!database.exists(), "the relaunch created a database anyway");
}

/// A relaunch whose chain it cannot read refuses instead of reporting an empty chain.
///
/// An empty answer here is the dangerous one. A relaunch that could not read the chain and
/// said "nothing to resend" would drop every reserved link on the floor silently, which is
/// the loss `wire.md`'s reserve-then-send ordering exists to prevent.
#[test]
fn a_relaunch_that_cannot_read_the_chain_refuses_rather_than_resending_nothing() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let staged = stage(dir.path());
    sabotage(
        &staged.database,
        "create table weald_chain (envelope blob not null, sent integer not null default 0);",
    );

    let output = run(&[
        "resume",
        staged.db(),
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&output, "cannot read the chain");
}

/// A reserved row that cannot be read back as an envelope is refused, not skipped.
///
/// The row is there and its envelope is not bytes. Skipping it would be the same silent
/// loss as failing to read the chain at all, and it would be worse for being invisible:
/// the report would say the chain has a link and claim nothing needed resending.
#[test]
fn a_reserved_row_whose_envelope_is_not_bytes_is_refused_rather_than_skipped() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let staged = stage(dir.path());
    sabotage(
        &staged.database,
        &format!(
            "{REAL_CHAIN} insert into weald_chain (link, envelope, sent) \
             values (1, 'text where an envelope should be', 0);"
        ),
    );

    let output = run(&[
        "resume",
        staged.db(),
        dir.path().join("outbox").to_str().expect("utf-8"),
    ]);
    refused(&output, "cannot read the chain");
}

/// A relaunch that cannot resend a reserved link says which link it is.
///
/// The state this starts from is the real one: the process was killed after the commit and
/// before the send, so link 1 is reserved and unsent. The relaunch then cannot mark it
/// sent, and the thing that must not happen is a silent zero exit that leaves the link
/// unsent forever while every later link goes out ahead of it.
#[test]
fn a_relaunch_that_cannot_resend_a_reserved_link_names_the_link() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let staged = stage(dir.path());
    let outbox = dir.path().join("outbox");

    // Killed after the commit, before the send: exactly the reserved-but-unsent state.
    let death = run_crashing(
        &[
            "process",
            staged.db(),
            staged.commit.to_str().expect("utf-8"),
            DOC_ID,
            BODY,
            outbox.to_str().expect("utf-8"),
        ],
        "after_commit",
    );
    assert!(
        death.status.code().is_none(),
        "the victim did not die by signal at after_commit"
    );
    let after_crash = state(&staged.database);
    assert_eq!(after_crash.mls_epoch, Some(EPOCH_AFTER));
    assert_eq!(after_crash.chain_links, 1);

    sabotage(
        &staged.database,
        "create trigger weald_chain_frozen before update on weald_chain \
         begin select raise(abort, 'this chain row cannot be updated'); end;",
    );

    let output = run(&[
        "resume",
        staged.db(),
        outbox.to_str().expect("utf-8"),
        TEMPTING_BODY,
    ]);
    refused(&output, "cannot resend link 1");
    // And what it did put on the wire before failing is the envelope it reserved, not the
    // content it was handed. A failed resend is still not a licence to fork the chain.
    let wire =
        std::fs::read(outbox.join("link-1.envelope")).expect("the envelope reached the wire");
    let text = String::from_utf8_lossy(&wire);
    assert!(
        text.contains(BODY),
        "the resent envelope was not the reserved one"
    );
    assert!(
        !text.contains(TEMPTING_BODY),
        "the failed relaunch reissued link 1 over different content, which is a chain fork"
    );
}
