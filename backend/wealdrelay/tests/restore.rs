// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `wealdrelay restore --from <path|s3://bucket/key>` against a real database
//! and a real store.
//!
//! The same shape as `tests/backup.rs`, and for a stronger version of the same
//! reason: this is the command a customer reaches for after losing data, and a
//! restore proven against a stub database is a restore proven against nothing.
//! The round trip below writes rows and a blob, captures, writes *more* rows,
//! restores, and then asserts both directions: what the capture held is back and
//! what was written after it is gone. A restore that only proved the first would
//! pass while doing nothing at all, which is exactly the failure that made this
//! command necessary (WEALD-L234).

mod support;

use wealdrelay::backup::{self, Destination};
use wealdrelay::db::Database;
use wealdrelay::restore::{self, Request};

/// A local-path restore, which is what most of this suite asks for.
fn from(path: &std::path::Path) -> Request {
    Request {
        from: Destination::Local(path.to_path_buf()),
        receipt: None,
    }
}

/// A tarball of exactly these members, with a manifest the caller controls.
///
/// Hand built rather than produced by `backup::write_archive`, because every
/// negative below is a disagreement *between* the manifest and the members, and
/// the writer's whole job is to make those two agree.
fn tarball(manifest: &[u8], members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut append = |name: &str, bytes: &[u8]| {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, name, bytes)
            .expect("append");
    };
    append(backup::MANIFEST_NAME, manifest);
    for (name, bytes) in members {
        append(name, bytes);
    }
    builder.into_inner().expect("finish the tarball")
}

/// A manifest naming exactly these members, at their real sizes and digests.
fn manifest_for(members: &[(&str, &[u8])]) -> Vec<u8> {
    let entries: Vec<serde_json::Value> = members
        .iter()
        .map(|(name, bytes)| {
            serde_json::json!({
                "name": name,
                "bytes": bytes.len(),
                "blake3": backup::Entry::new(*name, bytes.to_vec()).digest(),
            })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "manifest_version": 1,
        "hash": "blake3",
        "schema_version": "0001_x",
        "migrations": ["0001_x"],
        "entries": entries,
    }))
    .expect("a manifest")
}

const ONE_TABLE: &[u8] = b"copy public.\"relay_group\" from stdin;\n\\.\n";

// ---------------------------------------------------------------- round trip

#[tokio::test]
async fn a_capture_restored_returns_what_it_held_and_not_what_came_after() {
    let scratch = support::Scratch::new("restore_round_trip").await;
    let blobs = tempfile::tempdir().expect("a blob root");
    let out = tempfile::tempdir().expect("an output directory");
    let config = support::config_for(&scratch, blobs.path());

    let db = Database::connect(&scratch.url).await.expect("connect");
    db.migrate().await.expect("migrate");

    let workspace = "ws-restore";
    let before = [1u8; 32];
    let before_hex: String = before.iter().map(|b| format!("{b:02x}")).collect();
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(before.as_slice())
        .bind(workspace)
        .execute(db.pool())
        .await
        .expect("seed the row the capture holds");

    let ciphertext = b"opaque ciphertext, never decrypted by a restore".to_vec();
    let store = wealdrelay::storage::open(&config.storage)
        .await
        .expect("open the store");
    let key = wealdrelay::storage::BlobKey::new(workspace, &before_hex, "deadbeef")
        .expect("a well formed key");
    store.put(&key, &ciphertext).await.expect("store a blob");

    let capture = out.path().join("capture.tar.gz");
    backup::run(
        &config,
        &backup::Request {
            out: Destination::Local(capture.clone()),
            database_only: false,
        },
    )
    .await
    .expect("the capture runs");

    // Written after the capture, so the restore has to remove it. This is the
    // half a restore that did nothing would still have passed.
    let after = [2u8; 32];
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(after.as_slice())
        .bind(workspace)
        .execute(db.pool())
        .await
        .expect("seed the row the capture does not hold");
    // And the blob is deleted, so the restore has to put it back.
    store.delete(&key).await.expect("delete the blob");

    let report = restore::run(&config, &from(&capture))
        .await
        .expect("the restore runs");
    assert!(report.tables > 0);
    assert_eq!(report.blobs, 1);

    let groups: Vec<(Vec<u8>,)> = sqlx::query_as("select group_id from relay_group order by 1")
        .fetch_all(db.pool())
        .await
        .expect("read the groups back");
    assert_eq!(
        groups.into_iter().map(|row| row.0).collect::<Vec<_>>(),
        vec![before.to_vec()],
        "the capture's row is back and the row written after it is gone"
    );
    assert_eq!(
        store.get(&key).await.expect("the blob is back"),
        ciphertext,
        "the bytes are the bytes, unchanged and never decrypted"
    );

    // The storage sweep is suppressed, because the relay's view of what is
    // referenced has just changed underneath it.
    let marker = wealdrelay::media::restore::remaining(db.pool())
        .await
        .expect("read the marker");
    assert!(marker.is_some(), "a restore sets the collector's marker");
}

#[tokio::test]
async fn a_receipt_is_written_only_after_the_load_succeeds() {
    let scratch = support::Scratch::new("restore_receipt").await;
    let blobs = tempfile::tempdir().expect("a blob root");
    let out = tempfile::tempdir().expect("an output directory");
    let config = support::config_for(&scratch, blobs.path());
    let db = Database::connect(&scratch.url).await.expect("connect");
    db.migrate().await.expect("migrate");

    let capture = out.path().join("capture.tar");
    backup::run(
        &config,
        &backup::Request {
            out: Destination::Local(capture.clone()),
            database_only: true,
        },
    )
    .await
    .expect("the capture runs");

    let receipt = out.path().join("receipt.json");
    restore::run(
        &config,
        &Request {
            from: Destination::Local(capture.clone()),
            receipt: Some(Destination::Local(receipt.clone())),
        },
    )
    .await
    .expect("the restore runs");
    let written: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt).expect("the receipt exists"))
            .expect("the receipt is json");
    assert_eq!(written["restored_from"], capture.display().to_string());
    assert!(written["tables"].as_u64().expect("a table count") > 0);
}

#[tokio::test]
async fn a_capture_from_another_schema_is_refused_and_nothing_is_deleted() {
    let scratch = support::Scratch::new("restore_schema").await;
    let blobs = tempfile::tempdir().expect("a blob root");
    let out = tempfile::tempdir().expect("an output directory");
    let config = support::config_for(&scratch, blobs.path());
    let db = Database::connect(&scratch.url).await.expect("connect");
    db.migrate().await.expect("migrate");
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind([9u8; 32].as_slice())
        .bind("ws-schema")
        .execute(db.pool())
        .await
        .expect("seed a row");

    // A well formed capture of a schema this relay is not at. The `COPY` blocks
    // are column ordered for the schema they were dumped from, so loading them
    // across a migration would put values in columns that have moved, and the
    // failure would be silent.
    let members: &[(&str, &[u8])] = &[("database/relay_group.copy", ONE_TABLE)];
    let path = out.path().join("foreign.tar");
    std::fs::write(&path, tarball(&manifest_for(members), members)).expect("write");

    let error = restore::run(&config, &from(&path))
        .await
        .expect_err("a foreign schema is refused");
    assert!(
        error
            .to_string()
            .contains("restoring across a schema change"),
        "{error}"
    );
    assert_eq!(error.exit_code(), restore::EXIT_DATAERR);
    let count: (i64,) = sqlx::query_as("select count(*) from relay_group")
        .fetch_one(db.pool())
        .await
        .expect("count");
    assert_eq!(count.0, 1, "the refusal deleted nothing");
}

#[tokio::test]
async fn an_unreachable_database_is_a_retryable_failure() {
    let scratch = support::Scratch::new("restore_unreachable").await;
    let blobs = tempfile::tempdir().expect("a blob root");
    let out = tempfile::tempdir().expect("an output directory");
    let mut config = support::config_for(&scratch, blobs.path());
    let db = Database::connect(&scratch.url).await.expect("connect");
    db.migrate().await.expect("migrate");
    let capture = out.path().join("capture.tar");
    backup::run(
        &config,
        &backup::Request {
            out: Destination::Local(capture.clone()),
            database_only: true,
        },
    )
    .await
    .expect("the capture runs");

    config.database_url = "postgres://nobody@127.0.0.1:1/none".to_string();
    let error = restore::run(&config, &from(&capture))
        .await
        .expect_err("an unreachable database fails");
    assert_eq!(error.exit_code(), wealdrelay::EXIT_UNAVAILABLE);
}

#[tokio::test]
async fn a_capture_that_is_not_there_names_what_was_asked_for() {
    let scratch = support::Scratch::new("restore_absent").await;
    let blobs = tempfile::tempdir().expect("a blob root");
    let config = support::config_for(&scratch, blobs.path());
    let error = restore::run(
        &config,
        &from(std::path::Path::new("/nonexistent/capture.tar")),
    )
    .await
    .expect_err("an absent capture fails");
    assert!(
        error.to_string().contains("/nonexistent/capture.tar"),
        "{error}"
    );
    assert_eq!(error.exit_code(), restore::EXIT_DATAERR);
}

// ------------------------------------------------------- reading the artifact

#[test]
fn a_flipped_byte_is_refused_rather_than_loaded() {
    let good: &[(&str, &[u8])] = &[("database/relay_group.copy", ONE_TABLE)];
    let tampered: &[(&str, &[u8])] = &[(
        "database/relay_group.copy",
        b"copy public.\"relay_group\" from stdin;\n\\.\n ",
    )];
    let error = restore::read_archive(&tarball(&manifest_for(good), tampered))
        .expect_err("a member that disagrees with its manifest is refused");
    assert!(error.to_string().contains("relay_group"), "{error}");
}

#[test]
fn a_member_the_manifest_does_not_name_is_refused() {
    let named: &[(&str, &[u8])] = &[("database/relay_group.copy", ONE_TABLE)];
    let carried: &[(&str, &[u8])] = &[
        ("database/relay_group.copy", ONE_TABLE),
        ("database/extra.copy", ONE_TABLE),
    ];
    let error = restore::read_archive(&tarball(&manifest_for(named), carried))
        .expect_err("an unnamed member is refused");
    assert!(error.to_string().contains("not in its manifest"), "{error}");
}

#[test]
fn a_name_the_manifest_carries_and_the_tarball_does_not_is_refused() {
    let named: &[(&str, &[u8])] = &[
        ("database/relay_group.copy", ONE_TABLE),
        ("database/missing.copy", ONE_TABLE),
    ];
    let carried: &[(&str, &[u8])] = &[("database/relay_group.copy", ONE_TABLE)];
    let error = restore::read_archive(&tarball(&manifest_for(named), carried))
        .expect_err("an incomplete capture is refused");
    assert!(error.to_string().contains("does not carry it"), "{error}");
}

#[test]
fn a_capture_with_no_manifest_is_refused() {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(ONE_TABLE.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "database/relay_group.copy", ONE_TABLE)
        .expect("append");
    let error = restore::read_archive(&builder.into_inner().expect("tar"))
        .expect_err("a capture that cannot be checked is refused");
    assert!(error.to_string().contains("manifest.json"), "{error}");
}

#[test]
fn a_manifest_shape_this_build_does_not_read_is_refused() {
    let members: &[(&str, &[u8])] = &[("database/relay_group.copy", ONE_TABLE)];
    let manifest = serde_json::to_vec(&serde_json::json!({
        "manifest_version": 99,
        "hash": "blake3",
        "entries": [],
    }))
    .expect("a manifest");
    let error = restore::read_archive(&tarball(&manifest, members))
        .expect_err("an unknown manifest version is refused");
    assert!(error.to_string().contains("version 99"), "{error}");
}

#[test]
fn a_digest_this_relay_does_not_check_is_refused() {
    let members: &[(&str, &[u8])] = &[("database/relay_group.copy", ONE_TABLE)];
    let manifest = serde_json::to_vec(&serde_json::json!({
        "manifest_version": 1,
        "hash": "sha256",
        "entries": [],
    }))
    .expect("a manifest");
    let error = restore::read_archive(&tarball(&manifest, members))
        .expect_err("a hash this relay does not compute is refused");
    assert!(error.to_string().contains("blake3"), "{error}");
}

#[test]
fn a_gzipped_capture_reads_exactly_as_a_plain_one_does() {
    let members: &[(&str, &[u8])] = &[("database/relay_group.copy", ONE_TABLE)];
    let plain = tarball(&manifest_for(members), members);
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, &plain).expect("compress");
    let gzipped = encoder.finish().expect("finish");
    assert_eq!(
        restore::read_archive(&plain).expect("plain"),
        restore::read_archive(&gzipped).expect("gzipped")
    );
}

#[test]
fn bytes_that_are_not_a_tarball_are_refused() {
    let error = restore::read_archive(b"not a tarball at all").expect_err("junk is refused");
    assert!(!error.to_string().is_empty());
}

// ------------------------------------------------------------------ planning

fn archive_of(members: &[(&str, &[u8])]) -> restore::Archive {
    restore::read_archive(&tarball(&manifest_for(members), members)).expect("a readable archive")
}

#[test]
fn the_migrations_table_is_carried_and_never_loaded_back() {
    let members: &[(&str, &[u8])] = &[
        ("database/relay_group.copy", ONE_TABLE),
        ("database/_sqlx_migrations.copy", ONE_TABLE),
    ];
    let plan = restore::plan(&archive_of(members)).expect("a plan");
    assert_eq!(
        plan.tables
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        vec!["relay_group"],
        "this database's own migration record is what the compatibility check read"
    );
}

#[test]
fn a_capture_with_no_tables_is_not_a_capture_of_a_relay() {
    let members: &[(&str, &[u8])] = &[("blobs/ws/aa/bb", b"bytes")];
    let error = restore::plan(&archive_of(members)).expect_err("refused");
    assert!(error.to_string().contains("no tables"), "{error}");
}

#[test]
fn a_member_that_is_neither_a_table_nor_a_blob_is_refused() {
    let members: &[(&str, &[u8])] = &[
        ("database/relay_group.copy", ONE_TABLE),
        ("notes.txt", b"x"),
    ];
    let error = restore::plan(&archive_of(members)).expect_err("refused");
    assert!(
        error.to_string().contains("neither a table nor a blob"),
        "{error}"
    );
}

#[test]
fn a_table_name_that_is_not_a_table_name_is_refused() {
    // The name is about to be interpolated into a `truncate` and a `copy`. The
    // refusal is the thing that makes that safe, so it is asserted rather than
    // reasoned about.
    let members: &[(&str, &[u8])] =
        &[("database/relay_group\"; drop schema public.copy", ONE_TABLE)];
    let error = restore::plan(&archive_of(members)).expect_err("refused");
    assert!(error.to_string().contains("unexpected name"), "{error}");
}

#[test]
fn a_file_under_database_that_is_not_a_copy_is_refused() {
    let members: &[(&str, &[u8])] = &[("database/relay_group.sql", ONE_TABLE)];
    let error = restore::plan(&archive_of(members)).expect_err("refused");
    assert!(error.to_string().contains("not a .copy file"), "{error}");
}

#[test]
fn a_blob_path_the_store_would_refuse_is_refused_here_too() {
    // Every blob name goes through `BlobKey::new`, the same validator every
    // writer in the relay uses, so a capture cannot name a path that is not a
    // blob path. (`..` is not reachable at all: the tar writer refuses to put
    // one in an archive, so a capture carrying one cannot be built.)
    let members: &[(&str, &[u8])] = &[
        ("database/relay_group.copy", ONE_TABLE),
        ("blobs/ws/gr\\up/hash", b"x"),
    ];
    let error = restore::plan(&archive_of(members)).expect_err("refused");
    assert!(!error.to_string().is_empty());
}

#[test]
fn a_blob_that_is_not_workspace_group_hash_is_refused() {
    let members: &[(&str, &[u8])] = &[
        ("database/relay_group.copy", ONE_TABLE),
        ("blobs/ws/group", b"x"),
    ];
    let error = restore::plan(&archive_of(members)).expect_err("refused");
    assert!(error.to_string().contains("blobs/<workspace>"), "{error}");
}

#[test]
fn compatibility_is_the_whole_migration_list_in_order() {
    let members: &[(&str, &[u8])] = &[("database/relay_group.copy", ONE_TABLE)];
    let archive = archive_of(members);
    restore::compatible(&archive.manifest, &["0001_x".to_string()]).expect("the same schema");
    // One extra applied migration is a database whose columns have moved.
    restore::compatible(
        &archive.manifest,
        &["0001_x".to_string(), "0002_y".to_string()],
    )
    .expect_err("a longer list is not this list");
    restore::compatible(&archive.manifest, &[]).expect_err("no migrations is not this list");
}

#[test]
fn the_copy_envelope_is_removed_and_the_rows_are_not() {
    assert_eq!(
        restore::strip_copy_envelope(b"copy public.\"t\" from stdin;\na\tb\n\\.\n"),
        b"a\tb\n".to_vec()
    );
    // A block with no envelope is its own body, so a caller cannot lose a row by
    // stripping twice.
    assert_eq!(restore::strip_copy_envelope(b"a\tb\n"), b"a\tb\n".to_vec());
    assert_eq!(restore::strip_copy_envelope(b""), Vec::<u8>::new());
}

// ------------------------------------------------------------------ the flags

#[test]
fn from_parsing_accepts_both_spellings_and_refuses_the_rest() {
    assert_eq!(
        restore::parse_args(["--from", "/tmp/a.tar"]).expect("parses"),
        Request {
            from: Destination::Local("/tmp/a.tar".into()),
            receipt: None
        }
    );
    assert_eq!(
        restore::parse_args(["--from=/tmp/a.tar"]).expect("parses"),
        Request {
            from: Destination::Local("/tmp/a.tar".into()),
            receipt: None
        }
    );
    assert_eq!(
        restore::parse_args([
            "--from",
            "s3://bucket/exports/a.tar.gz",
            "--receipt",
            "s3://bucket/restores/a.json"
        ])
        .expect("parses"),
        Request {
            from: Destination::S3 {
                bucket: "bucket".to_string(),
                key: "exports/a.tar.gz".to_string()
            },
            receipt: Some(Destination::S3 {
                bucket: "bucket".to_string(),
                key: "restores/a.json".to_string()
            }),
        }
    );
    for bad in [
        vec!["--from"],
        vec!["--from", "/a", "--from", "/b"],
        vec!["--receipt", "/a", "--receipt", "/b"],
        vec!["--receipt"],
        vec!["--receipt", "/a"],
        vec!["--out", "/a"],
        vec![],
        vec!["--from="],
        vec!["--receipt=", "--from", "/a"],
        vec!["--from", "s3://"],
    ] {
        let message = restore::parse_args(bad.clone()).expect_err("refused");
        assert!(
            message.starts_with("restore:"),
            "{bad:?} produced {message}"
        );
    }
}

#[test]
fn the_binary_refuses_a_restore_it_cannot_read() {
    let outcome = wealdrelay::run(["restore"]);
    assert_eq!(outcome.code, 64);
    assert!(outcome.stderr.contains("--from"), "{}", outcome.stderr);
    // The usage the operator is shown names the subcommand they just ran.
    assert!(outcome.stderr.contains("wealdrelay restore"));
}
