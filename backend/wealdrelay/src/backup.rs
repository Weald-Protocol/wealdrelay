// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `wealdrelay backup --out <path>`: the portable export artifact.
//!
//! `specs/backend/cloud/backup-dr.md` ("Export is a separate artifact") fixes
//! what this produces and, more importantly, what it must not produce. The
//! tarball "contains the encrypted relay database and encrypted blobs exactly as
//! a self-hosted backup does, plus a signed manifest; it has no dependency on a
//! Weald key or a hosted-only restore path". So:
//!
//! - **Nothing here decrypts and nothing here encrypts.** Every row the relay
//!   holds is already envelope ciphertext and every blob is already sealed by the
//!   client. Adding a second layer would be adding a key, and a key is exactly
//!   the dependency the spec forbids. The hosted control plane wraps this
//!   artifact for its own retained copy (`backups/envelope.ts`); that is its
//!   business and happens above this command.
//! - **One artifact, two callers.** A self-hoster runs this by hand and the
//!   hosted export worker runs the same command, which is what makes the export
//!   portable by construction rather than by promise
//!   (`render-operations.ts:196-220` waits for the object it writes).
//!
//! ## What is in the tarball
//!
//! - `database/<table>.copy` per table, in name order: a `COPY ... FROM stdin`
//!   header, Postgres text-format rows, and the `\.` terminator. Restorable by
//!   piping into `psql` against a database the relay has migrated, which is why
//!   the schema is not dumped as DDL: the migrations are embedded in the binary
//!   (`db.rs`), so the restore path is "run the relay once, then load the data",
//!   and a DDL dump in the tarball would be a second source of truth for a schema
//!   that already has one.
//! - `blobs/<workspace>/<group>/<hash>` per object, byte for byte.
//! - `manifest.json`: every entry with its BLAKE3 digest, the relay version, and
//!   the schema version.
//!
//! ## The manifest is not signed, and that is recorded rather than papered over
//!
//! There is no relay-held signing key to sign it with. The only Ed25519 private
//! key this relay ever generates is the per-workspace bootstrap genesis key, and
//! `invite/genesis.rs:408` nulls `relay_genesis.secret_key` on redemption: it is
//! a one-time bootstrap secret, deliberately destroyed, and it is not a relay
//! identity. Signing an export with a workspace's dead bootstrap key would be
//! inventing a key ceremony this programme has not specified, so the manifest
//! carries `"signature": null` with the reason in `"signature_note"`, and the
//! digests carry the integrity. When a relay identity key exists, this is the one
//! place that has to change.
//!
//! ## The hash is BLAKE3
//!
//! Not a choice made here: `storage.rs` is content addressed on BLAKE3 and the
//! envelope content address is BLAKE3 (`Cargo.toml`), so the manifest uses the
//! hash the relay already depends on rather than introducing a second one.

use std::path::{Path, PathBuf};

use futures_util::TryStreamExt as _;

/// The manifest file name inside the tarball. Fixed, because a restore tool
/// looks for exactly this.
pub const MANIFEST_NAME: &str = "manifest.json";

/// Manifest shape version. Bumped when the fields change meaning, so a reader
/// can refuse an artifact it does not understand instead of guessing.
pub const MANIFEST_VERSION: u32 = 1;

/// `EX_CANTCREAT` from `sysexits.h`: the output path cannot be written.
pub const EXIT_CANTCREAT: i32 = 73;

/// Why a backup failed.
///
/// Typed and separated by cause, because the three have different operator
/// responses: a bad `--out` is the operator's own argument, an unreachable
/// database or store is the environment, and those get different exit codes so a
/// scheduler can tell "you asked for the impossible" from "try again later".
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("cannot read the database: {0}")]
    Database(String),
    #[error("cannot read object storage: {0}")]
    Storage(String),
    #[error("cannot write the backup to {path}: {reason}")]
    Output { path: String, reason: String },
    /// The tarball was built but the object store refused it. Separate from
    /// `Output` because the artifact was fine and the operator's argument was
    /// fine: the bucket, the credentials or the network was not, which is the
    /// same class of thing as an unreachable store and gets the same retryable
    /// exit code.
    #[error("cannot upload the backup to {target}: {reason}")]
    Upload { target: String, reason: String },
}

impl BackupError {
    /// The process exit code for this failure.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Database(_) | Self::Storage(_) | Self::Upload { .. } => crate::EXIT_UNAVAILABLE,
            Self::Output { .. } => EXIT_CANTCREAT,
        }
    }
}

/// Where the artifact goes.
///
/// A local path is what a self-hoster asks for. An `s3://bucket/key` URL exists
/// for one reason (`specs/backend/cloud/backup-dr.md` capture path): the hosted
/// control plane cannot reach an instance's Postgres across regions, so the
/// capture runs as a job inside the instance's own region and puts the tarball in
/// the instance's own bucket, where the control plane fetches it over HTTPS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    Local(PathBuf),
    /// A bucket and a full object key. The configured storage prefix is not
    /// applied: the operator named the whole key.
    S3 {
        bucket: String,
        key: String,
    },
}

impl Destination {
    /// Read one `--out` value. `s3://` routes to an upload; everything else is a
    /// path, including anything with no scheme at all.
    pub fn parse(value: &str) -> Result<Self, String> {
        if value.is_empty() {
            return Err("backup: --out needs a path".to_string());
        }
        let lowered = value.to_ascii_lowercase();
        if !lowered.starts_with("s3://") {
            return Ok(Self::Local(PathBuf::from(value)));
        }
        let rest = &value["s3://".len()..];
        let (bucket, key) = match rest.split_once('/') {
            Some((bucket, key)) => (bucket, key),
            None => (rest, ""),
        };
        if bucket.is_empty() {
            return Err(format!("backup: {value} names no bucket"));
        }
        if key.is_empty() {
            return Err(format!("backup: {value} names no object key"));
        }
        Ok(Self::S3 {
            bucket: bucket.to_string(),
            key: key.to_string(),
        })
    }

    /// What the operator is told the artifact was written to.
    pub fn describe(&self) -> String {
        match self {
            Self::Local(path) => path.display().to_string(),
            Self::S3 { bucket, key } => format!("s3://{bucket}/{key}"),
        }
    }

    /// The name the compression decision is made from, so an `s3://` key ending
    /// `.tar.gz` gets gzip exactly as a local path of that name does.
    fn artifact_name(&self) -> String {
        let whole = match self {
            Self::Local(path) => path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("backup")
                .to_string(),
            Self::S3 { key, .. } => key.rsplit('/').next().unwrap_or("backup").to_string(),
        };
        if whole.is_empty() {
            "backup".to_string()
        } else {
            whole
        }
    }
}

/// One parsed `backup` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub out: Destination,
    /// Skip the blobs and archive only the database and the manifest.
    ///
    /// The hosted capture path uses this: blobs are content addressed in R2,
    /// which the control plane can already read directly and across regions, so
    /// it copies and deduplicates them itself. Carrying every blob in every
    /// twice-daily capture would re-copy the whole bucket and then throw the copy
    /// away. The unflagged backup keeps every blob, because that one is the
    /// self-host and export artifact and has to be restorable on its own.
    pub database_only: bool,
}

/// One member of the tarball, held in memory with its digest.
///
/// In memory rather than streamed, deliberately and with a limit in mind: the
/// caller assembles entries one at a time and hands them to the writer, so the
/// peak is one blob plus one table rather than the whole archive. A relay whose
/// single largest object does not fit in memory is a relay whose media path
/// already did not fit, because `media::MULTIPART_PART_SIZE` is read the same
/// way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub bytes: Vec<u8>,
}

impl Entry {
    pub fn new(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            bytes,
        }
    }

    /// The content address of this member, in the relay's own hash.
    pub fn digest(&self) -> String {
        blake3::hash(&self.bytes).to_hex().to_string()
    }
}

/// What the relay knows about itself at the moment of the backup, and what a
/// restorer needs to know before opening the data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// The last applied migration, which is the schema the `COPY` files are for.
    pub schema_version: String,
    /// Every applied migration, in order. The schema version alone cannot show a
    /// database that skipped one.
    pub migrations: Vec<String>,
}

/// Build the manifest for a set of entries.
///
/// Pure, so the manifest can be asserted without a database: the whole reason
/// the collection step and the archive step are separate functions.
pub fn manifest(entries: &[Entry], provenance: &Provenance) -> Vec<u8> {
    let members: Vec<serde_json::Value> = entries
        .iter()
        .map(|entry| {
            serde_json::json!({
                "name": entry.name,
                "bytes": entry.bytes.len(),
                "blake3": entry.digest(),
            })
        })
        .collect();
    let document = serde_json::json!({
        "manifest_version": MANIFEST_VERSION,
        "relay": crate::BuildInfo::current().name,
        "relay_version": crate::BuildInfo::current().version,
        "schema_version": provenance.schema_version,
        "migrations": provenance.migrations,
        "hash": "blake3",
        // Stated, not omitted. An absent field reads as an oversight; a null with
        // a reason reads as the decision it is. See the module note.
        "signature": serde_json::Value::Null,
        "signature_note":
            "unsigned: this relay holds no long-lived signing key. Integrity is the \
             per-entry BLAKE3 digests. See src/backup.rs.",
        "entries": members,
    });
    let mut bytes = serde_json::to_vec_pretty(&document).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

/// Write `entries` plus the manifest to `path` as a tarball.
///
/// Gzipped when the path ends `.gz` or `.tgz`, plain tar otherwise, because the
/// hosted export object is `exports/<backupId>.tar.gz`
/// (`render-operations.ts:208`) and a self-hoster naming a `.tar` should not
/// silently get compressed bytes.
///
/// Written to a temporary file beside the target and renamed, for the reason
/// `storage.rs` gives for the same construction: a reader, and the export worker
/// is one, sees the whole artifact or no artifact, never a truncated tarball it
/// would then upload.
pub fn write_archive(
    path: &Path,
    entries: &[Entry],
    provenance: &Provenance,
) -> Result<u64, BackupError> {
    let display = path.display().to_string();
    let fail = |reason: String| BackupError::Output {
        path: display.clone(),
        reason,
    };
    if path.file_name().is_none() {
        return Err(fail("that is a directory, not a file".to_string()));
    }
    let directory = path.parent().unwrap_or(Path::new("."));
    let directory = if directory.as_os_str().is_empty() {
        Path::new(".")
    } else {
        directory
    };
    if !directory.is_dir() {
        return Err(fail(format!("no directory at {}", directory.display())));
    }

    let manifest = Entry::new(MANIFEST_NAME, manifest(entries, provenance));
    let temporary = directory.join(format!(
        ".{}.partial",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("backup")
    ));
    let build = || -> std::io::Result<()> {
        let file = std::fs::File::create(&temporary)?;
        // The manifest goes first so a streaming reader can learn what it is
        // about to be handed before it is handed any of it.
        if compressed(path) {
            let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
                file,
                flate2::Compression::default(),
            ));
            append(&mut builder, &manifest)?;
            for entry in entries {
                append(&mut builder, entry)?;
            }
            builder.into_inner()?.finish()?.sync_all()
        } else {
            let mut builder = tar::Builder::new(file);
            append(&mut builder, &manifest)?;
            for entry in entries {
                append(&mut builder, entry)?;
            }
            builder.into_inner()?.sync_all()
        }
    };
    if let Err(error) = build() {
        let _ = std::fs::remove_file(&temporary);
        return Err(fail(error.to_string()));
    }
    let bytes = match std::fs::metadata(&temporary) {
        Ok(metadata) => metadata.len(),
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            return Err(fail(error.to_string()));
        }
    };
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(fail(error.to_string()));
    }
    Ok(bytes)
}

fn compressed(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.ends_with(".gz") || name.ends_with(".tgz")
}

fn append<W: std::io::Write>(builder: &mut tar::Builder<W>, entry: &Entry) -> std::io::Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(entry.bytes.len() as u64);
    header.set_mode(0o644);
    // Zero, not now(). Two backups of an unchanged relay should differ only where
    // the data differs, and a wall clock in every member header would make every
    // archive a different archive.
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder.append_data(&mut header, &entry.name, entry.bytes.as_slice())
}

/// Read everything the relay holds: the database, then the blobs.
///
/// Order matters and is the pessimistic one. The database is read first, so the
/// blob list comes from the same read as the rows that reference it; a blob
/// written after the row snapshot is a blob nothing in the artifact points at,
/// which is inert, while a row referencing a blob taken before it existed would
/// be a dangling reference in a restore.
/// `storage` is `None` for a database-only capture, which is the flag rather
/// than a second function: the blob loop is the only difference and a `None`
/// store cannot accidentally be read.
pub async fn collect(
    db: &crate::db::Database,
    storage: Option<&crate::storage::Store>,
) -> Result<(Vec<Entry>, Provenance), BackupError> {
    let migrations = db
        .applied_migrations()
        .await
        .map_err(|error| BackupError::Database(error.to_string()))?;
    let provenance = Provenance {
        schema_version: migrations
            .last()
            .cloned()
            // A database with no applied migration is a database the relay has
            // never started against. Named rather than left empty, because
            // "schema_version": "" in a restore tool's hands is a silent wrong
            // answer.
            .unwrap_or_else(|| "none".to_string()),
        migrations,
    };

    let mut entries = Vec::new();
    let tables = db
        .tables()
        .await
        .map_err(|error| BackupError::Database(error.to_string()))?;
    for table in &tables {
        let dump = dump_table(db, table).await?;
        entries.push(Entry::new(format!("database/{table}.copy"), dump));
    }

    let Some(storage) = storage else {
        return Ok((entries, provenance));
    };

    for (workspace, group) in blob_groups(db).await? {
        let names = storage
            .list(&workspace, &group)
            .await
            .map_err(|error| BackupError::Storage(error.to_string()))?;
        for name in names {
            let Ok(key) = crate::storage::BlobKey::new(&workspace, &group, &name) else {
                // Unreachable through the relay's own writers, which construct
                // every key through the same constructor. Skipped rather than
                // failed, because a stray file in a blob directory must not stop
                // an operator taking a backup of everything else.
                continue;
            };
            let bytes = storage
                .get(&key)
                .await
                .map_err(|error| BackupError::Storage(error.to_string()))?;
            entries.push(Entry::new(format!("blobs/{}", key.path()), bytes));
        }
    }
    Ok((entries, provenance))
}

/// Every `(workspace, group)` pair that can hold blobs, from the group table
/// rather than from the store.
///
/// From the database because the store cannot be enumerated without one: the
/// contract's `list` is per workspace and group by design
/// (`storage.rs`, no cross-group dedupe), and a backend-wide listing is not
/// something the S3 arm is allowed to do.
async fn blob_groups(db: &crate::db::Database) -> Result<Vec<(String, String)>, BackupError> {
    let rows: Vec<(String, Vec<u8>)> =
        sqlx::query_as("select workspace_id, group_id from relay_group order by 1, 2")
            .fetch_all(db.pool())
            .await
            .map_err(|error| BackupError::Database(error.to_string()))?;
    Ok(rows
        .into_iter()
        .map(|(workspace, group)| (workspace, crate::media::hex(&group)))
        .collect())
}

/// One table as a `psql`-loadable `COPY` block.
async fn dump_table(db: &crate::db::Database, table: &str) -> Result<Vec<u8>, BackupError> {
    // Identifier quoting rather than interpolation hygiene by hope: the name came
    // from `information_schema`, so it cannot contain a quote, but the query is
    // built by format and this is the line that makes that safe to read.
    if !table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(BackupError::Database(format!(
            "refusing to dump a table with an unexpected name: {table:?}"
        )));
    }
    let mut out = format!("copy public.\"{table}\" from stdin;\n").into_bytes();
    let mut stream = sqlx::postgres::PgPoolCopyExt::copy_out_raw(
        db.pool(),
        &format!("copy public.\"{table}\" to stdout"),
    )
    .await
    .map_err(|error| BackupError::Database(error.to_string()))?;
    while let Some(chunk) = stream
        .try_next()
        .await
        .map_err(|error| BackupError::Database(error.to_string()))?
    {
        out.extend_from_slice(&chunk);
    }
    out.extend_from_slice(b"\\.\n");
    Ok(out)
}

/// The whole subcommand: open the database and the store, read them, write the
/// tarball. Returns the artifact size, which is what the operator is told.
pub async fn run(config: &crate::config::Config, request: &Request) -> Result<u64, BackupError> {
    // The output location is checked before a connection is opened. An operator
    // who mistyped a path should be told so in a second rather than after the
    // relay has read a database it is going to throw away.
    if let Destination::Local(out) = &request.out {
        if let Some(parent) = out.parent() {
            let parent = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            if !parent.is_dir() {
                return Err(BackupError::Output {
                    path: out.display().to_string(),
                    reason: format!("no directory at {}", parent.display()),
                });
            }
        }
    }
    let db = crate::db::Database::connect_with_pool_size(&config.database_url, 1)
        .await
        .map_err(|error| BackupError::Database(error.to_string()))?;
    // Opened only when it is going to be read. A database-only capture that
    // probed the bucket would fail for a reason that has nothing to do with what
    // it was asked to produce.
    let storage = if request.database_only {
        None
    } else {
        Some(
            crate::storage::open(&config.storage)
                .await
                .map_err(|error| BackupError::Storage(error.to_string()))?,
        )
    };
    let (entries, provenance) = collect(&db, storage.as_ref()).await?;
    match &request.out {
        Destination::Local(out) => write_archive(out, &entries, &provenance),
        Destination::S3 { bucket, key } => {
            upload_archive(bucket, key, &request.out, &entries, &provenance).await
        }
    }
}

/// Build the tarball in a temporary directory, then put it in the bucket.
///
/// Built first and uploaded second, deliberately: a failed build must never
/// leave a half-written object under the key the control plane is about to
/// fetch. The temporary directory is removed on every path out, success or
/// failure, so a machine running this twice a day does not fill its disk with
/// abandoned archives.
async fn upload_archive(
    bucket: &str,
    key: &str,
    destination: &Destination,
    entries: &[Entry],
    provenance: &Provenance,
) -> Result<u64, BackupError> {
    let target = destination.describe();
    let scratch = std::env::temp_dir().join(format!(
        "wealdrelay-backup-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&scratch).map_err(|error| BackupError::Output {
        path: scratch.display().to_string(),
        reason: error.to_string(),
    })?;
    let staged = scratch.join(destination.artifact_name());
    let built = write_archive(&staged, entries, provenance);
    let result = match built {
        Ok(bytes) => crate::storage::put_object_file(bucket, key, &staged)
            .await
            .map(|()| bytes)
            .map_err(|error| BackupError::Upload {
                target: target.clone(),
                reason: error.to_string(),
            }),
        Err(error) => Err(error),
    };
    // Best effort and dropped: the caller is being told why the backup failed,
    // and replacing that with why a temporary directory would not delete would
    // lose the useful half.
    let _ = std::fs::remove_dir_all(&scratch);
    result
}

/// The `backup` half of argument parsing, kept beside the command rather than in
/// `lib.rs`, so the flag and what reads it live together.
///
/// Accepts `--out <path>` and `--out=<path>`. Anything else is an error naming
/// what was wrong, because a backup that silently wrote somewhere the operator
/// did not ask for is worse than one that refused.
pub fn parse_args<I, S>(rest: I) -> Result<Request, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out: Option<String> = None;
    let mut database_only = false;
    let mut args = rest.into_iter().peekable();
    while let Some(arg) = args.next() {
        let arg = arg.as_ref().to_string();
        if arg == "--database-only" {
            if database_only {
                return Err("backup: --database-only given twice".to_string());
            }
            database_only = true;
        } else if let Some(value) = arg.strip_prefix("--out=") {
            if out.is_some() {
                return Err("backup: --out given twice".to_string());
            }
            out = Some(value.to_string());
        } else if arg == "--out" {
            if out.is_some() {
                return Err("backup: --out given twice".to_string());
            }
            match args.next() {
                Some(value) => out = Some(value.as_ref().to_string()),
                None => return Err("backup: --out needs a path".to_string()),
            }
        } else {
            return Err(format!("backup: unknown argument {arg}"));
        }
    }
    match out {
        Some(path) if !path.is_empty() => Ok(Request {
            out: Destination::parse(&path)?,
            database_only,
        }),
        Some(_) => Err("backup: --out needs a path".to_string()),
        None => Err("backup: --out <path> is required".to_string()),
    }
}
