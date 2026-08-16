// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `wealdrelay backup --out <path>` against a real database and a real store.
//!
//! Not a unit test with a fake: the artifact this produces is the one a customer
//! restores from and the one `render-operations.ts` uploads, and an archiver
//! proven against a stub database is an archiver proven against nothing. The
//! scratch Postgres is the harness Postgres, the store is the filesystem backend
//! the contract suite already holds, and the assertions open the tarball with an
//! independent reader rather than with the writer that produced it.

mod support;

use std::collections::BTreeMap;
use std::io::Read as _;

use wealdrelay::backup;
use wealdrelay::backup::{Destination, Request};
use wealdrelay::db::Database;

/// Every member of a tarball, by name, decompressing when the path says to.
fn read_archive(path: &std::path::Path) -> BTreeMap<String, Vec<u8>> {
    let file = std::fs::File::open(path).expect("the backup exists");
    let name = path.to_string_lossy().to_string();
    let reader: Box<dyn std::io::Read> = if name.ends_with(".gz") || name.ends_with(".tgz") {
        Box::new(flate2::read::GzDecoder::new(file))
    } else {
        Box::new(file)
    };
    let mut archive = tar::Archive::new(reader);
    let mut members = BTreeMap::new();
    for entry in archive.entries().expect("the tarball has entries") {
        let mut entry = entry.expect("every entry reads");
        let name = entry
            .path()
            .expect("every entry has a path")
            .to_string_lossy()
            .to_string();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).expect("every entry reads");
        members.insert(name, bytes);
    }
    members
}

/// A plain local-path request, which is what most of this suite asks for.
fn to(path: &std::path::Path) -> Request {
    Request {
        out: Destination::Local(path.to_path_buf()),
        database_only: false,
    }
}

/// The relay's own digest, through the type that carries it, so the test cannot
/// disagree with the manifest by using a different hash.
fn blake3_hex(bytes: &[u8]) -> String {
    backup::Entry::new("digest", bytes.to_vec()).digest()
}

/// The whole subcommand, end to end: a migrated database with a group in it, a
/// blob on disk, and one gzipped tarball that names both and whose digests hold.
#[tokio::test]
async fn backup_writes_a_tarball_the_manifest_describes() {
    let scratch = support::Scratch::new("backup_artifact").await;
    let blobs = tempfile::tempdir().expect("a blob root");
    let out = tempfile::tempdir().expect("an output directory");
    let config = support::config_for(&scratch, blobs.path());

    let db = Database::connect(&scratch.url).await.expect("connect");
    db.migrate().await.expect("migrate");

    let workspace = "ws-backup";
    let group = [7u8; 32];
    let group_hex: String = group.iter().map(|b| format!("{b:02x}")).collect();
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(group.as_slice())
        .bind(workspace)
        .execute(db.pool())
        .await
        .expect("seed a group");

    // Ciphertext as far as this command is concerned: bytes it stores and hands
    // back without ever looking inside, which is the property the artifact has to
    // preserve.
    let ciphertext = b"opaque ciphertext, never decrypted by the backup".to_vec();
    let store = wealdrelay::storage::open(&config.storage)
        .await
        .expect("open the store");
    let key = wealdrelay::storage::BlobKey::new(workspace, &group_hex, "deadbeef")
        .expect("a well formed key");
    store.put(&key, &ciphertext).await.expect("store a blob");

    let target = out.path().join("export.tar.gz");
    let bytes = backup::run(&config, &to(&target))
        .await
        .expect("the backup runs");
    assert!(bytes > 0, "the artifact is not empty");
    assert_eq!(
        bytes,
        std::fs::metadata(&target)
            .expect("the artifact exists")
            .len()
    );

    let members = read_archive(&target);
    let manifest: serde_json::Value = serde_json::from_slice(
        members
            .get(backup::MANIFEST_NAME)
            .expect("the manifest is in the tarball"),
    )
    .expect("the manifest is json");

    assert_eq!(manifest["manifest_version"], 1);
    assert_eq!(manifest["relay"], "wealdrelay");
    assert_eq!(manifest["relay_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(manifest["hash"], "blake3");
    // The signing decision, asserted rather than left implicit: if a relay
    // identity key ever exists, this line is what fails and sends the next reader
    // to `src/backup.rs`.
    assert!(manifest["signature"].is_null());
    let schema_version = manifest["schema_version"]
        .as_str()
        .expect("a schema version")
        .to_string();
    let applied = db.applied_migrations().await.expect("read migrations");
    assert_eq!(&schema_version, applied.last().expect("one migration ran"));
    assert_eq!(
        manifest["migrations"]
            .as_array()
            .expect("the migration list")
            .len(),
        applied.len()
    );

    // Every name the manifest gives is in the tarball, at the size and digest it
    // claims, and nothing is in the tarball the manifest does not name.
    let named = manifest["entries"].as_array().expect("entries").clone();
    assert!(!named.is_empty());
    for entry in &named {
        let name = entry["name"].as_str().expect("a name");
        let bytes = members
            .get(name)
            .unwrap_or_else(|| panic!("the manifest names {name} and the tarball holds it"));
        assert_eq!(
            entry["bytes"].as_u64().expect("a size"),
            bytes.len() as u64,
            "{name} is the size the manifest claims"
        );
        assert_eq!(
            entry["blake3"].as_str().expect("a digest"),
            blake3_hex(bytes),
            "{name} verifies against its digest"
        );
    }
    let mut in_manifest: Vec<String> = named
        .iter()
        .map(|entry| entry["name"].as_str().expect("a name").to_string())
        .collect();
    in_manifest.push(backup::MANIFEST_NAME.to_string());
    in_manifest.sort();
    let mut in_archive: Vec<String> = members.keys().cloned().collect();
    in_archive.sort();
    assert_eq!(
        in_manifest, in_archive,
        "the manifest names the whole tarball"
    );

    // The blob is byte for byte, unencrypted-by-us and undecrypted-by-us.
    let blob_name = format!("blobs/{workspace}/{group_hex}/deadbeef");
    assert_eq!(
        members.get(&blob_name).expect("the blob is in the tarball"),
        &ciphertext
    );

    // The database dump is a loadable COPY block that actually holds the row.
    let dump = String::from_utf8(
        members
            .get("database/relay_group.copy")
            .expect("the group table is dumped")
            .clone(),
    )
    .expect("the dump is text");
    assert!(dump.starts_with("copy public.\"relay_group\" from stdin;\n"));
    assert!(dump.contains(workspace), "the dumped row is really there");
    assert!(dump.ends_with("\\.\n"));

    scratch.drop_database().await;
}

/// A plain `.tar` is a plain tar, because a self-hoster who named one should not
/// get gzip bytes under that name.
#[tokio::test]
async fn an_uncompressed_name_produces_an_uncompressed_tar() {
    let scratch = support::Scratch::new("backup_plain_tar").await;
    let blobs = tempfile::tempdir().expect("a blob root");
    let out = tempfile::tempdir().expect("an output directory");
    let config = support::config_for(&scratch, blobs.path());
    Database::connect(&scratch.url)
        .await
        .expect("connect")
        .migrate()
        .await
        .expect("migrate");

    let target = out.path().join("export.tar");
    backup::run(&config, &to(&target))
        .await
        .expect("the backup runs");
    let bytes = std::fs::read(&target).expect("read it back");
    // ustar magic at offset 257 of the first header. A gzip stream starts 1f 8b
    // and has no such thing.
    assert_eq!(&bytes[257..262], b"ustar", "this is a raw tar");
    assert!(read_archive(&target).contains_key(backup::MANIFEST_NAME));

    scratch.drop_database().await;
}

/// The negative proof: an `--out` under a directory that does not exist fails
/// with a message naming the path, a non-zero exit code, and no panic. Checked
/// before the database is opened, so the operator hears about their typo rather
/// than about a connection.
#[tokio::test]
async fn a_bad_out_path_fails_cleanly() {
    let scratch = support::Scratch::new("backup_bad_out").await;
    let blobs = tempfile::tempdir().expect("a blob root");
    let out = tempfile::tempdir().expect("an output directory");
    let config = support::config_for(&scratch, blobs.path());

    let target = out.path().join("no-such-directory").join("export.tar.gz");
    let error = backup::run(&config, &to(&target))
        .await
        .expect_err("a path with no directory cannot be written");
    assert!(matches!(error, backup::BackupError::Output { .. }));
    assert_eq!(error.exit_code(), backup::EXIT_CANTCREAT);
    assert!(
        error.to_string().contains("no-such-directory"),
        "the message names the path: {error}"
    );
    assert!(!target.exists());

    scratch.drop_database().await;
}

/// A database that is not there is a different failure with a different code, so
/// a scheduler can tell "retry later" from "your argument is wrong".
#[tokio::test]
async fn an_unreachable_database_is_a_retryable_failure() {
    let scratch = support::Scratch::new("backup_no_db").await;
    let blobs = tempfile::tempdir().expect("a blob root");
    let out = tempfile::tempdir().expect("an output directory");
    let config = support::config_for(&scratch, blobs.path());
    // Never created, so the connection is refused by a real Postgres rather than
    // by a fake.
    scratch.drop_database().await;

    let error = backup::run(&config, &to(&out.path().join("export.tar.gz")))
        .await
        .expect_err("no database, no backup");
    assert!(matches!(error, backup::BackupError::Database(_)));
    assert_eq!(error.exit_code(), wealdrelay::EXIT_UNAVAILABLE);
}

/// The same failure through the real process, because `main` is where an exit
/// code is actually set and a subcommand nobody runs is where an argument
/// mistake hides.
#[test]
fn the_binary_refuses_a_backup_it_cannot_write() {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_wealdrelay"));
    let output = command
        .args(["backup", "--out", "/no-such-root-directory/export.tar.gz"])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .output()
        .expect("the binary runs");
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("wealdrelay:"), "stderr says why: {stderr}");
}

/// A missing `--out` is a usage error naming the flag, not a panic and not a
/// backup written somewhere the operator did not ask for.
#[test]
fn the_binary_refuses_a_backup_with_no_out() {
    for args in [
        vec!["backup"],
        vec!["backup", "--out"],
        vec!["backup", "--elsewhere", "/tmp/x"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_wealdrelay"))
            .args(&args)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .output()
            .expect("the binary runs");
        assert_eq!(output.status.code(), Some(64), "{args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("backup:"), "{args:?} says why: {stderr}");
    }
}

/// A tampered member is caught by the manifest, which is the whole point of
/// carrying digests in an artifact nobody signs.
#[test]
fn a_flipped_byte_breaks_its_digest() {
    let entry = backup::Entry::new("blobs/a/b/c", b"ciphertext".to_vec());
    let digest = entry.digest();
    let tampered = backup::Entry::new("blobs/a/b/c", b"Ciphertext".to_vec());
    assert_ne!(digest, tampered.digest());
    assert_eq!(digest, blake3_hex(b"ciphertext"));
}

/// `--out=<path>` and `--out <path>` mean the same thing, and everything else is
/// refused by name.
#[test]
fn out_parsing_accepts_both_spellings_and_refuses_the_rest() {
    assert_eq!(
        backup::parse_args(["--out", "/tmp/a.tar.gz"]).expect("a path"),
        to(std::path::Path::new("/tmp/a.tar.gz"))
    );
    assert_eq!(
        backup::parse_args(["--out=/tmp/a.tar.gz"]).expect("a path"),
        to(std::path::Path::new("/tmp/a.tar.gz"))
    );
    assert!(backup::parse_args(Vec::<String>::new()).is_err());
    assert!(backup::parse_args(["--out"]).is_err());
    assert!(backup::parse_args(["--out", ""]).is_err());
    assert!(backup::parse_args(["--out", "/a", "--out", "/b"]).is_err());
    assert!(backup::parse_args(["--nope"]).is_err());
}

/// `--out s3://bucket/key` is read as an upload, not as a path, and a URL that
/// names no bucket or no key is refused rather than turned into a file called
/// `s3:`.
#[test]
fn an_s3_out_is_parsed_as_an_upload() {
    let request = backup::parse_args(["--out", "s3://weald-inst-1/exports/a.tar.gz"])
        .expect("an s3 destination");
    assert_eq!(
        request.out,
        Destination::S3 {
            bucket: "weald-inst-1".to_string(),
            key: "exports/a.tar.gz".to_string(),
        }
    );
    assert!(!request.database_only);
    assert_eq!(request.out.describe(), "s3://weald-inst-1/exports/a.tar.gz");

    // The scheme is the only thing that routes. Everything else stays a path,
    // including a relative one and one that merely mentions s3.
    assert_eq!(
        backup::parse_args(["--out", "./s3/export.tar"])
            .expect("a path")
            .out,
        Destination::Local(std::path::PathBuf::from("./s3/export.tar"))
    );
    assert!(backup::parse_args(["--out", "s3://"]).is_err());
    assert!(backup::parse_args(["--out", "s3://bucket"]).is_err());
    assert!(backup::parse_args(["--out", "s3://bucket/"]).is_err());
    assert!(backup::parse_args(["--out", "s3:///key"]).is_err());
}

/// `--database-only` is off unless asked for, and given twice is a usage error
/// like every other repeated flag here.
#[test]
fn database_only_is_opt_in() {
    let request =
        backup::parse_args(["--out", "/tmp/a.tar.gz", "--database-only"]).expect("a request");
    assert!(request.database_only);
    assert!(
        backup::parse_args(["--database-only", "--out=/tmp/a.tar.gz"])
            .expect("order does not matter")
            .database_only
    );
    assert!(backup::parse_args(["--out", "/tmp/a", "--database-only", "--database-only"]).is_err());
}

/// With `--database-only` the tarball holds the database and the manifest and no
/// blob, while the same relay without the flag holds the blob. Both asserted in
/// one test against one seeded blob, because the thing being proven is the
/// difference between them.
#[tokio::test]
async fn database_only_leaves_the_blobs_out() {
    let scratch = support::Scratch::new("backup_database_only").await;
    let blobs = tempfile::tempdir().expect("a blob root");
    let out = tempfile::tempdir().expect("an output directory");
    let config = support::config_for(&scratch, blobs.path());

    let db = Database::connect(&scratch.url).await.expect("connect");
    db.migrate().await.expect("migrate");
    let workspace = "ws-dbonly";
    let group = [9u8; 32];
    let group_hex: String = group.iter().map(|b| format!("{b:02x}")).collect();
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(group.as_slice())
        .bind(workspace)
        .execute(db.pool())
        .await
        .expect("seed a group");
    let store = wealdrelay::storage::open(&config.storage)
        .await
        .expect("open the store");
    let key = wealdrelay::storage::BlobKey::new(workspace, &group_hex, "deadbeef")
        .expect("a well formed key");
    store.put(&key, b"opaque").await.expect("store a blob");
    let blob_name = format!("blobs/{workspace}/{group_hex}/deadbeef");

    let full = out.path().join("full.tar.gz");
    backup::run(&config, &to(&full)).await.expect("full backup");
    assert!(
        read_archive(&full).contains_key(&blob_name),
        "the unflagged backup is unchanged and still carries every blob"
    );

    let slim = out.path().join("slim.tar.gz");
    backup::run(
        &config,
        &Request {
            out: Destination::Local(slim.clone()),
            database_only: true,
        },
    )
    .await
    .expect("database-only backup");
    let members = read_archive(&slim);
    assert!(!members.contains_key(&blob_name), "no blob is carried");
    assert!(members
        .keys()
        .all(|name| name == backup::MANIFEST_NAME || name.starts_with("database/")));
    assert!(members.contains_key("database/relay_group.copy"));
    let manifest: serde_json::Value =
        serde_json::from_slice(&members[backup::MANIFEST_NAME]).expect("json");
    let named = manifest["entries"].as_array().expect("entries");
    assert!(!named.is_empty());
    assert!(
        named.iter().all(|entry| entry["name"]
            .as_str()
            .expect("a name")
            .starts_with("database/")),
        "the manifest names the database and nothing else: {named:?}"
    );

    scratch.drop_database().await;
}

/// The negative proof for the upload arm, through the real binary: a bucket that
/// cannot be reached exits non-zero, says so on stderr, and leaves no staged
/// tarball behind in the temporary directory.
///
/// No fake S3 server: this tree has never had one, and inventing one would prove
/// the fake rather than the client. What is real here is the refusal path, which
/// is the part an operator meets at three in the morning.
#[tokio::test]
async fn a_refused_upload_fails_and_leaves_no_temporary_file() {
    let scratch = support::Scratch::new("backup_s3_refused").await;
    let blobs = tempfile::tempdir().expect("a blob root");
    let temp = tempfile::tempdir().expect("a private temporary directory");
    Database::connect(&scratch.url)
        .await
        .expect("connect")
        .migrate()
        .await
        .expect("migrate");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_wealdrelay"))
        .args([
            "backup",
            "--out",
            "s3://weald-no-such-bucket/exports/a.tar.gz",
            "--database-only",
        ])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("TMPDIR", temp.path())
        .env("WEALD_RELAY_HOSTNAME", "localhost")
        .env("WEALD_RELAY_DATABASE_URL", &scratch.url)
        .env(
            "WEALD_RELAY_STORAGE_URL",
            format!("file://{}", blobs.path().display()),
        )
        .env("WEALD_RELAY_RELEASE_CHECK", "off")
        // A port nothing listens on, so the credentials are real enough to sign
        // with and the request is refused by the network rather than by a mock.
        .env("AWS_ENDPOINT_URL_S3", "http://127.0.0.1:1")
        .env("AWS_REGION", "auto")
        .env("AWS_ACCESS_KEY_ID", "not-a-real-key")
        .env("AWS_SECRET_ACCESS_KEY", "not-a-real-secret")
        .output()
        .expect("the binary runs");

    assert_ne!(
        output.status.code(),
        Some(0),
        "a refused upload is a failure"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot upload the backup to s3://weald-no-such-bucket/exports/a.tar.gz"),
        "stderr names the target: {stderr}"
    );
    let left: Vec<String> = std::fs::read_dir(temp.path())
        .expect("read the temporary directory")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        left.is_empty(),
        "no staged artifact is left behind: {left:?}"
    );

    scratch.drop_database().await;
}
