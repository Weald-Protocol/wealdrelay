// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! A process that does the real thing and then dies in the middle of it.
//!
//! `specs/backend/relay/mls-binding.md`, "State storage": "processing a commit advances
//! the epoch, and if the app crashes between advancing the MLS state and recording the
//! envelopes decrypted under it, the group is in a state the rest of the app disagrees
//! with. One transaction per processed message, covering both, is the entire mitigation
//! and it is not optional."
//!
//! A crash test cannot be written with `panic!`, because a panic runs destructors and a
//! rusqlite `Transaction` rolls itself back on drop: the test would be measuring Rust's
//! unwinding rather than SQLite's recovery. So this is a separate process that calls
//! `std::process::abort` at a named point. The kill is a real, uncatchable SIGABRT with no
//! destructor, no flush and no atexit hook, which is the only thing a power cut resembles.
//!
//! It is a binary rather than a test because that is what makes the kill real. It is not
//! library code and nothing links it.
//!
//! Two halves, because the spec's crash gate names two:
//!
//! - The MLS half. Process a commit, advance the epoch, record the document it decrypted
//!   and the epoch the app now believes in, all inside one transaction.
//! - The author-chain half (`specs/backend/relay/wire.md`, quoted in `mls-binding.md`):
//!   reserve a link, send it, and never let a crash between the two produce a fork. The
//!   reservation is a row in the same database and the same transaction, holding the exact
//!   bytes this device intends to send, so a restarted client resends those bytes rather
//!   than reissuing the counter over different content.
//!
//! ## Why this drives OpenMLS rather than ``weald_mls::session::Session``
//!
//! The seam has no function that reopens a group that is already in the store. `Device`
//! can create a group, join one by welcome and join one by external commit, and every one
//! of those makes new state. A relaunched client has none of those three things: it has a
//! database and a group id. So the reopen is done here with `MlsGroup::load` against the
//! crate's own public `Provider`, which is the identical storage OpenMLS wrote through,
//! and the sequence below is byte for byte what `Session::process` does. The missing
//! function is reported as a real gap in the seam rather than papered over here.

use std::io::Write as _;

use openmls::group::{GroupId, MlsGroup};
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::{MlsMessageIn, ProcessedMessageContent, ProtocolMessage};
use openmls_traits::OpenMlsProvider as _;

use weald_mls::store::Provider;

/// Every point in the sequence where the process can die.
///
/// Exported through the `points` subcommand, and the test matrix iterates what this prints
/// rather than a list of its own. That is the whole reason it is a subcommand: a new
/// injection point added here is covered by the matrix on the next run, and a point that
/// existed only in the test would be a point nobody had proved anything about.
///
/// The order is the order of the sequence in ``run_process``.
const CRASH_POINTS: &[&str] = &[
    // The control. No abort, so the matrix has a row that proves the sequence completes.
    "none",
    "before_begin",
    "after_begin",
    "after_process_message",
    "after_mls_state_write",
    "after_chain_reservation",
    "after_document_write",
    "before_commit",
    "after_commit",
    "after_send",
];

/// The group every run of this binary works in. A constant rather than an argument,
/// because the point under test is the transaction and not the group id.
const GROUP: &[u8] = b"weald-crash-group";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("");
    let code = match mode {
        "points" => {
            println!(
                "{}",
                serde_json::to_string(CRASH_POINTS).expect("a list of names serialises")
            );
            0
        }
        "process" => run_process(&args),
        "resume" => run_resume(&args),
        other => {
            eprintln!("crash-victim: unknown mode {other:?}");
            2
        }
    };
    std::process::exit(code);
}

/// Abort here if this is the named point.
///
/// `abort` and not `panic`, and not `exit` either. `exit` runs atexit handlers and flushes
/// stdio, and an uncommitted SQLite transaction that got a clean shutdown is not evidence
/// about a crash. The child's exit is asserted to be a signal death for the same reason.
fn crash_at(point: &str) {
    let requested = std::env::var("WEALD_MLS_CRASH_AT").unwrap_or_default();
    if requested == point {
        // Flushed first, so a run that is being debugged says where it died. The flush is
        // of this process's own log and touches nothing in the database.
        let _ = std::io::stderr().flush();
        std::process::abort();
    }
}

/// The tables the app owns, beside OpenMLS's own, in the same database.
///
/// Created outside the transaction under test on purpose: schema creation is first-run
/// work, and a `create table` inside the measured transaction would be one more write
/// whose rollback could be mistaken for the property being proved.
fn migrate(provider: &Provider) -> rusqlite::Result<()> {
    provider.connection().execute_batch(
        "create table if not exists weald_document ( \
           id text primary key, \
           body blob not null, \
           epoch integer not null \
         ); \
         create table if not exists weald_chain ( \
           link integer primary key, \
           envelope blob not null, \
           sent integer not null default 0 \
         ); \
         create table if not exists weald_epoch ( \
           group_id blob primary key, \
           epoch integer not null \
         );",
    )
}

/// The bytes this device intends to put on the wire for one link.
///
/// Derived from the link number and the body so that a caller who reissued the counter
/// over different content would produce visibly different bytes. That is the fork the
/// spec calls "a security alarm on everybody else's screen", and it is only detectable in
/// a test if the envelope actually commits to its content.
fn envelope(link: i64, doc_id: &str, body: &str) -> Vec<u8> {
    format!("weald/v1;link={link};doc={doc_id};body={body}").into_bytes()
}

/// The full sequence, with a named boundary between every pair of writes.
///
/// `crash-victim process <db> <message-file> <doc-id> <body> <outbox>`
fn run_process(args: &[String]) -> i32 {
    let (db, message_file, doc_id, body, outbox) = match args.get(2..7) {
        Some([db, message_file, doc_id, body, outbox]) => (db, message_file, doc_id, body, outbox),
        _ => {
            eprintln!("crash-victim process <db> <message-file> <doc-id> <body> <outbox>");
            return 2;
        }
    };

    let message = match std::fs::read(message_file) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("crash-victim: cannot read {message_file}: {error}");
            return 2;
        }
    };

    let provider = match Provider::open(db) {
        Ok(provider) => provider,
        Err(error) => {
            eprintln!("crash-victim: cannot open {db}: {error}");
            return 2;
        }
    };
    if let Err(error) = migrate(&provider) {
        eprintln!("crash-victim: cannot migrate: {error}");
        return 2;
    }

    let group_id = GroupId::from_slice(GROUP);
    let mut group = match MlsGroup::load(provider.storage(), &group_id) {
        Ok(Some(group)) => group,
        Ok(None) => {
            eprintln!("crash-victim: no group in {db}");
            return 2;
        }
        Err(error) => {
            eprintln!("crash-victim: cannot load the group: {error}");
            return 2;
        }
    };

    // Everything above is setup that a relaunched client does anyway. The measured
    // sequence starts here.
    crash_at("before_begin");

    let transaction = match provider.connection().unchecked_transaction() {
        Ok(transaction) => transaction,
        Err(error) => {
            eprintln!("crash-victim: cannot begin: {error}");
            return 2;
        }
    };
    crash_at("after_begin");

    // Deserialise and process. Nothing is written yet: `process_message` stages a commit
    // and leaves the group where it was.
    let incoming = match MlsMessageIn::tls_deserialize_exact(&message) {
        Ok(incoming) => incoming,
        Err(error) => {
            eprintln!("crash-victim: malformed message: {error}");
            return 2;
        }
    };
    let protocol: ProtocolMessage = match incoming.try_into_protocol_message() {
        Ok(protocol) => protocol,
        Err(error) => {
            eprintln!("crash-victim: not a protocol message: {error}");
            return 2;
        }
    };
    let processed = match group.process_message(&provider, protocol) {
        Ok(processed) => processed,
        Err(error) => {
            eprintln!("crash-victim: refused: {error}");
            return 2;
        }
    };
    crash_at("after_process_message");

    // The MLS state write. The epoch advances here and it advances *inside* the
    // transaction, which is the entire mitigation the spec refuses to make optional.
    let staged = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => staged,
        _ => {
            eprintln!("crash-victim: the message under test must be a commit");
            return 2;
        }
    };
    if let Err(error) = group.merge_staged_commit(&provider, *staged) {
        eprintln!("crash-victim: cannot merge: {error}");
        return 2;
    }
    let epoch = group.epoch().as_u64();
    crash_at("after_mls_state_write");

    // The author chain half. The link is reserved and the exact bytes to be sent are
    // reserved with it, in this transaction, before anything is sent. Reserve, send, then
    // advance: the same ordering `wire.md` uses and `mls-binding.md` repeats.
    let link: i64 = match transaction.query_row(
        "select coalesce(max(link), 0) + 1 from weald_chain",
        [],
        |row| row.get(0),
    ) {
        Ok(link) => link,
        Err(error) => {
            eprintln!("crash-victim: cannot read the chain: {error}");
            return 2;
        }
    };
    let bytes = envelope(link, doc_id, body);
    if let Err(error) = transaction.execute(
        "insert into weald_chain (link, envelope, sent) values (?1, ?2, 0)",
        rusqlite::params![link, bytes],
    ) {
        eprintln!("crash-victim: cannot reserve a link: {error}");
        return 2;
    }
    crash_at("after_chain_reservation");

    // The document write: the envelope decrypted under the epoch that just advanced. A
    // crash between the two writes is the case the whole spec paragraph is about.
    if let Err(error) = transaction.execute(
        "insert into weald_document (id, body, epoch) values (?1, ?2, ?3)",
        rusqlite::params![doc_id, body.as_bytes(), i64::try_from(epoch).unwrap_or(-1)],
    ) {
        eprintln!("crash-victim: cannot write the document: {error}");
        return 2;
    }
    crash_at("after_document_write");

    // The app's own record of the epoch. This is the value that "an epoch the app
    // disagrees with" is about: if it can ever differ from the group's, the invariant is
    // broken and every reader downstream is reading under the wrong key.
    if let Err(error) = transaction.execute(
        "insert or replace into weald_epoch (group_id, epoch) values (?1, ?2)",
        rusqlite::params![GROUP, i64::try_from(epoch).unwrap_or(-1)],
    ) {
        eprintln!("crash-victim: cannot record the epoch: {error}");
        return 2;
    }
    crash_at("before_commit");

    if let Err(error) = transaction.commit() {
        eprintln!("crash-victim: cannot commit: {error}");
        return 2;
    }
    crash_at("after_commit");

    // Sending is deliberately outside the transaction, because it is outside the database.
    // A crash here is the "reserved but not sent" case, and the restart has to resend
    // these exact bytes.
    if let Err(error) = send(&provider, outbox, link, &bytes) {
        eprintln!("crash-victim: cannot send: {error}");
        return 2;
    }
    crash_at("after_send");

    0
}

/// Put one reserved link on the wire and mark it sent.
///
/// The "wire" is a file in a directory the test reads. Marking sent afterwards rather than
/// before is the only order that cannot lose a link: a crash between the two resends, and
/// a resend of identical bytes is not a fork.
fn send(provider: &Provider, outbox: &str, link: i64, bytes: &[u8]) -> rusqlite::Result<()> {
    if let Err(error) = std::fs::create_dir_all(outbox) {
        eprintln!("crash-victim: cannot create {outbox}: {error}");
    }
    let path = std::path::Path::new(outbox).join(format!("link-{link}.envelope"));
    // Appended, not truncated, so a second send of the same link is visible to the test
    // as two writes rather than hidden by an overwrite.
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("an outbox file");
    file.write_all(bytes).expect("the envelope");
    file.flush().expect("flushed");
    provider
        .connection()
        .execute("update weald_chain set sent = 1 where link = ?1", [link])?;
    Ok(())
}

/// The relaunch: report what survived, and resend anything reserved but not sent.
///
/// `crash-victim resume <db> <outbox> <different-body>`
///
/// The third argument exists to make the security property testable. It is content this
/// process would have sent if it were free to reissue the counter over something new, and
/// the correct behaviour is to ignore it completely and resend what was reserved.
fn run_resume(args: &[String]) -> i32 {
    let (db, outbox) = match args.get(2..4) {
        Some([db, outbox]) => (db, outbox),
        _ => {
            eprintln!("crash-victim resume <db> <outbox> <different-body>");
            return 2;
        }
    };
    let _tempting_new_content = args.get(4);

    let provider = match Provider::open(db) {
        Ok(provider) => provider,
        Err(error) => {
            eprintln!("crash-victim: cannot open {db}: {error}");
            return 2;
        }
    };
    if let Err(error) = migrate(&provider) {
        eprintln!("crash-victim: cannot migrate: {error}");
        return 2;
    }

    let group_id = GroupId::from_slice(GROUP);
    let mls_epoch = match MlsGroup::load(provider.storage(), &group_id) {
        Ok(Some(group)) => Some(group.epoch().as_u64()),
        Ok(None) => None,
        Err(error) => {
            eprintln!("crash-victim: cannot load the group: {error}");
            return 2;
        }
    };

    // Resend before reporting, so the report describes the state a peer would see.
    let unsent: Vec<(i64, Vec<u8>)> = {
        let mut statement = match provider
            .connection()
            .prepare("select link, envelope from weald_chain where sent = 0 order by link")
        {
            Ok(statement) => statement,
            Err(error) => {
                eprintln!("crash-victim: cannot read the chain: {error}");
                return 2;
            }
        };
        // Collected through the `Result`, not around it. An earlier version of this line
        // read `filter_map(Result::ok)`, which dropped any row it could not read and then
        // reported the surviving rows as the whole of what needed resending. A reserved
        // link that was silently skipped is a link nobody ever sends, which is the loss
        // `wire.md`'s reserve-then-send ordering exists to prevent, and it would have been
        // invisible: the report would say the chain has a link and that nothing needed
        // resending. A row that cannot be read is now the same refusal as a chain that
        // cannot be read at all.
        match statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .and_then(|rows| rows.collect::<rusqlite::Result<Vec<(i64, Vec<u8>)>>>())
        {
            Ok(rows) => rows,
            Err(error) => {
                eprintln!("crash-victim: cannot read the chain: {error}");
                return 2;
            }
        }
    };
    for (link, bytes) in &unsent {
        if let Err(error) = send(&provider, outbox, *link, bytes) {
            eprintln!("crash-victim: cannot resend link {link}: {error}");
            return 2;
        }
    }

    let report = serde_json::json!({
        "mls_epoch": mls_epoch,
        "app_epoch": scalar(&provider, "select epoch from weald_epoch where group_id = ?1"),
        "documents": count(&provider, "select count(*) from weald_document"),
        "chain_links": count(&provider, "select count(*) from weald_chain"),
        "max_link": scalar_no_args(&provider, "select coalesce(max(link), 0) from weald_chain"),
        "resent": unsent
            .iter()
            .map(|(link, bytes)| {
                serde_json::json!({
                    "link": link,
                    "envelope": String::from_utf8_lossy(bytes),
                })
            })
            .collect::<Vec<_>>(),
    });
    println!("{report}");
    0
}

fn count(provider: &Provider, sql: &str) -> i64 {
    provider
        .connection()
        .query_row(sql, [], |row| row.get(0))
        .unwrap_or(-1)
}

fn scalar_no_args(provider: &Provider, sql: &str) -> Option<i64> {
    provider
        .connection()
        .query_row(sql, [], |row| row.get(0))
        .ok()
}

fn scalar(provider: &Provider, sql: &str) -> Option<i64> {
    provider
        .connection()
        .query_row(sql, rusqlite::params![GROUP], |row| row.get(0))
        .ok()
}
