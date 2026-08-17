// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `wealdrelay restore --from <path|s3://bucket/key>`: the inverse of `backup`.
//!
//! `specs/backend/cloud/backup-dr.md` makes the portable tarball the capture on
//! the packed substrate, because the mechanism that document used to name for
//! the fast half cannot exist: Hetzner has no volume snapshot, and the image its
//! API does offer is an image of a whole box carrying up to sixteen customers'
//! cells (WEALD-L240). A capture with no restore is a promise nobody can call
//! in, so this is the other half and it reads exactly what `backup` wrote.
//!
//! ## What it does, in order, and why the order is the whole of it
//!
//! 1. **Read the artifact whole before touching anything.** Local path or
//!    `s3://bucket/key`, gunzipped when it is gzipped, every member checked
//!    against the manifest's BLAKE3 digest. A truncated or altered tarball is
//!    refused here, before a single row has been deleted.
//! 2. **Refuse a schema this binary did not write.** The archive carries the
//!    migrations that were applied when it was taken, and the `COPY` files are
//!    column-ordered for exactly that schema. Loading them into a different one
//!    is how a restore silently puts values in the wrong columns, so an archive
//!    whose migration list is not this database's migration list is refused with
//!    both lists named.
//! 3. **Replace, inside one transaction.** The tables the archive carries are
//!    truncated and re-loaded together, so a failure part way through leaves the
//!    database as it was rather than half of one capture and half of another.
//! 4. **Blobs after the rows.** `backup` reads the database first so that no row
//!    can reference a blob the artifact does not carry; writing the blobs last
//!    keeps that ordering true at the far end too, and a blob written twice is a
//!    blob written once because the store is content addressed.
//! 5. **Suppress the storage sweep.** The collector deletes objects it finds
//!    unreferenced, and immediately after a restore the relay's view of what is
//!    referenced has just changed underneath it, so this sets the same marker
//!    `POST /gc/restore-marker` sets (`media::restore`).
//!
//! ## What it deliberately does not do
//!
//! It does not migrate, because the schema has to match already. It does not
//! decrypt: every row and every blob is ciphertext on both sides of the trip,
//! and adding a key here would be adding the dependency `backup` refuses. And it
//! never deletes a table the archive does not carry, because an archive is a
//! capture of a relay and not an assertion about one.

use std::path::Path;

use crate::backup::{Destination, Entry, MANIFEST_NAME, MANIFEST_VERSION};

/// The table that records which migrations ran.
///
/// Carried in the archive, because `backup` dumps every table in the public
/// schema, and never loaded back: this database's own migration record is what
/// step 2 checked the archive against, and overwriting it with the archive's
/// copy would erase the evidence that the check passed.
const MIGRATIONS_TABLE: &str = "_sqlx_migrations";

/// How many collector passes a restore suppresses. The same default the HTTP
/// marker uses, because it is the same event.
const SUPPRESSED_PASSES: i32 = crate::media::restore::DEFAULT_SUPPRESSED_PASSES;

/// Why a restore failed.
///
/// Split the way `BackupError` is split, and for the same reason: an operator
/// naming an artifact that is not there has a different next action from one
/// whose database is unreachable. `Artifact` is the class this file adds, and it
/// is the one that must never be retried: a tarball that failed its digests will
/// fail them again.
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    #[error("cannot read the database: {0}")]
    Database(String),
    #[error("cannot read object storage: {0}")]
    Storage(String),
    #[error("cannot read the capture at {at}: {reason}")]
    Source { at: String, reason: String },
    #[error("{0}")]
    Artifact(String),
    /// The archive was readable and this relay is the wrong relay to load it
    /// into. Separate from `Artifact` because nothing is wrong with the capture.
    #[error("{0}")]
    Incompatible(String),
}

impl RestoreError {
    /// The process exit code for this failure.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Database(_) | Self::Storage(_) => crate::EXIT_UNAVAILABLE,
            // The operator asked for something that cannot be done as asked, and
            // asking again changes nothing. `EX_DATAERR`.
            Self::Source { .. } | Self::Artifact(_) | Self::Incompatible(_) => EXIT_DATAERR,
        }
    }
}

/// `EX_DATAERR` from `sysexits.h`: the input was wrong, not the environment.
pub const EXIT_DATAERR: i32 = 65;

/// One parsed `restore` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Where the capture is read from. The same two forms `backup --out` writes
    /// to, parsed by the same code, so a path one accepts the other accepts.
    pub from: Destination,
    /// Where to write a receipt once the load has succeeded, if anywhere.
    ///
    /// This is how a caller that cannot watch the process learns that the
    /// restore finished, and the packed substrate is exactly that caller: the
    /// control plane writes a restore request into a box's manifest and never
    /// speaks to the box again (`bin-packed-provisioner.md`, "How a cell is
    /// started"), so the only signal available is one the cell itself writes
    /// into the customer's own bucket. Written **after** the transaction
    /// commits and after the blobs are back, so a receipt that exists is a
    /// restore that happened.
    pub receipt: Option<Destination>,
}

/// What the archive says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveManifest {
    pub manifest_version: u32,
    pub schema_version: String,
    pub migrations: Vec<String>,
}

/// A read, verified archive: its manifest and its members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Archive {
    pub manifest: ArchiveManifest,
    pub entries: Vec<Entry>,
}

/// What a load will do, derived from an archive and nothing else.
///
/// Pure, and separated from the loading for the reason the backup's collection
/// is separated from its writing: every refusal below is then assertable without
/// a database, and the two dangerous operations (a truncate and a blob write)
/// are decided by a function with no connection in its hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadPlan {
    /// `(table, COPY block)`, in the order they are truncated and loaded.
    pub tables: Vec<(String, Vec<u8>)>,
    /// `(workspace/group/hash, bytes)`.
    pub blobs: Vec<(String, Vec<u8>)>,
}

/// Read a capture's bytes into a verified archive.
///
/// Every member is checked against the manifest before anything is returned, and
/// a member the manifest does not name is a refusal rather than a skip: the
/// manifest is the artifact's own account of itself, and a tarball carrying a
/// file that account does not mention is not the artifact it claims to be.
pub fn read_archive(bytes: &[u8]) -> Result<Archive, RestoreError> {
    let plain = if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        std::io::copy(
            &mut flate2::read::GzDecoder::new(bytes),
            &mut std::io::Cursor::new(&mut out),
        )
        .map_err(|error| {
            RestoreError::Artifact(format!("the capture will not decompress: {error}"))
        })?;
        out
    } else {
        bytes.to_vec()
    };
    let mut archive = tar::Archive::new(std::io::Cursor::new(&plain));
    let mut members: Vec<Entry> = Vec::new();
    let mut manifest_bytes: Option<Vec<u8>> = None;
    let iterator = archive.entries().map_err(|error| {
        RestoreError::Artifact(format!("the capture is not a tarball: {error}"))
    })?;
    for member in iterator {
        let mut member = member.map_err(|error| {
            RestoreError::Artifact(format!("the capture is truncated: {error}"))
        })?;
        let name = member
            .path()
            .map_err(|error| {
                RestoreError::Artifact(format!("a member has no readable name: {error}"))
            })?
            .to_string_lossy()
            .to_string();
        let mut body = Vec::new();
        std::io::Read::read_to_end(&mut member, &mut body)
            .map_err(|error| RestoreError::Artifact(format!("cannot read {name}: {error}")))?;
        if name == MANIFEST_NAME {
            manifest_bytes = Some(body);
        } else {
            members.push(Entry::new(name, body));
        }
    }
    let Some(manifest_bytes) = manifest_bytes else {
        return Err(RestoreError::Artifact(format!(
            "the capture carries no {MANIFEST_NAME}, so nothing in it can be checked"
        )));
    };
    let manifest = parse_manifest(&manifest_bytes)?;
    verify(&manifest_bytes, &members)?;
    Ok(Archive {
        manifest,
        entries: members,
    })
}

/// The manifest, read strictly: a shape this build does not understand is
/// refused rather than read past.
fn parse_manifest(bytes: &[u8]) -> Result<ArchiveManifest, RestoreError> {
    let document: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| RestoreError::Artifact(format!("the manifest is not JSON: {error}")))?;
    let version = document
        .get("manifest_version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default() as u32;
    if version != MANIFEST_VERSION {
        return Err(RestoreError::Artifact(format!(
            "the capture's manifest is version {version} and this relay reads version \
             {MANIFEST_VERSION}"
        )));
    }
    let hash = document
        .get("hash")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if hash != "blake3" {
        return Err(RestoreError::Artifact(format!(
            "the capture's digests are {hash:?} and this relay checks blake3"
        )));
    }
    Ok(ArchiveManifest {
        manifest_version: version,
        schema_version: document
            .get("schema_version")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        migrations: document
            .get("migrations")
            .and_then(serde_json::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// Every member, against the manifest's own record of it.
///
/// Both directions. A member whose digest disagrees is a corrupted capture, and
/// a member the manifest never named is an altered one; a name the manifest
/// carries and the tarball does not is an incomplete one. None of the three is
/// something to load half of.
fn verify(manifest_bytes: &[u8], members: &[Entry]) -> Result<(), RestoreError> {
    let document: serde_json::Value = serde_json::from_slice(manifest_bytes)
        .map_err(|error| RestoreError::Artifact(format!("the manifest is not JSON: {error}")))?;
    let listed = document
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut expected: std::collections::BTreeMap<String, (u64, String)> =
        std::collections::BTreeMap::new();
    for value in &listed {
        let name = value
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let bytes = value
            .get("bytes")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default();
        let digest = value
            .get("blake3")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if name.is_empty() || digest.is_empty() {
            return Err(RestoreError::Artifact(
                "the manifest lists an entry with no name or no digest".to_string(),
            ));
        }
        expected.insert(name.to_string(), (bytes, digest.to_string()));
    }
    for member in members {
        let Some((bytes, digest)) = expected.remove(&member.name) else {
            return Err(RestoreError::Artifact(format!(
                "{} is in the capture and not in its manifest",
                member.name
            )));
        };
        if member.bytes.len() as u64 != bytes {
            return Err(RestoreError::Artifact(format!(
                "{} is {} bytes and its manifest says {bytes}",
                member.name,
                member.bytes.len()
            )));
        }
        if member.digest() != digest {
            return Err(RestoreError::Artifact(format!(
                "{} does not match its manifest digest",
                member.name
            )));
        }
    }
    if let Some((name, _)) = expected.into_iter().next() {
        return Err(RestoreError::Artifact(format!(
            "the manifest names {name} and the capture does not carry it"
        )));
    }
    Ok(())
}

/// What loading this archive would do.
///
/// The migrations table is dropped here rather than at the far end, so the one
/// table this must never overwrite is excluded by a function a test can call.
pub fn plan(archive: &Archive) -> Result<LoadPlan, RestoreError> {
    let mut tables = Vec::new();
    let mut blobs = Vec::new();
    for entry in &archive.entries {
        if let Some(rest) = entry.name.strip_prefix("database/") {
            let Some(table) = rest.strip_suffix(".copy") else {
                return Err(RestoreError::Artifact(format!(
                    "{} is under database/ and is not a .copy file",
                    entry.name
                )));
            };
            // The same charset `backup::dump_table` refuses to dump outside of.
            // The name is about to be interpolated into a `truncate` and a
            // `copy`, and this is the line that makes that safe to read.
            if table.is_empty() || !table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(RestoreError::Artifact(format!(
                    "refusing to load a table with an unexpected name: {table:?}"
                )));
            }
            if table == MIGRATIONS_TABLE {
                continue;
            }
            tables.push((table.to_string(), entry.bytes.clone()));
        } else if let Some(rest) = entry.name.strip_prefix("blobs/") {
            let parts: Vec<&str> = rest.split('/').collect();
            let [workspace, group, hash] = parts.as_slice() else {
                return Err(RestoreError::Artifact(format!(
                    "{} is not blobs/<workspace>/<group>/<hash>",
                    entry.name
                )));
            };
            // Constructed rather than trusted: `BlobKey::new` is the same
            // validator every writer in the relay goes through, so a capture
            // cannot name a path that escapes the store.
            crate::storage::BlobKey::new(*workspace, *group, *hash)
                .map_err(|error| RestoreError::Artifact(format!("{}: {error}", entry.name)))?;
            blobs.push((rest.to_string(), entry.bytes.clone()));
        } else {
            return Err(RestoreError::Artifact(format!(
                "{} is neither a table nor a blob",
                entry.name
            )));
        }
    }
    if tables.is_empty() {
        return Err(RestoreError::Artifact(
            "the capture carries no tables, so it is not a capture of a relay's database"
                .to_string(),
        ));
    }
    // Deterministic, so two runs of one archive issue the same statements in the
    // same order and a failure is reproducible.
    tables.sort_by(|a, b| a.0.cmp(&b.0));
    blobs.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(LoadPlan { tables, blobs })
}

/// Whether an archive may be loaded into a database with these migrations.
///
/// Equality, in order, and not "the archive's last migration is present". A
/// `COPY` block is column-ordered for the schema it was dumped from, so a
/// database that has one extra migration applied is a database whose columns
/// have moved, and the failure that produces is silent: values land in the wrong
/// columns and every row is readable nonsense.
pub fn compatible(archive: &ArchiveManifest, applied: &[String]) -> Result<(), RestoreError> {
    if archive.migrations == applied {
        return Ok(());
    }
    Err(RestoreError::Incompatible(format!(
        "the capture was taken at schema {} ({} migration(s)) and this relay is at {} ({} \
         migration(s)); restoring across a schema change would load rows into columns that have \
         moved",
        archive.schema_version,
        archive.migrations.len(),
        applied.last().map(String::as_str).unwrap_or("none"),
        applied.len(),
    )))
}

/// What a completed restore is reported as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub tables: usize,
    pub blobs: usize,
}

/// The whole subcommand: read the capture, check it, replace the data.
pub async fn run(
    config: &crate::config::Config,
    request: &Request,
) -> Result<Report, RestoreError> {
    let bytes = read_source(&request.from).await?;
    let archive = read_archive(&bytes)?;
    let plan = plan(&archive)?;

    let db = crate::db::Database::connect_with_pool_size(&config.database_url, 1)
        .await
        .map_err(|error| RestoreError::Database(error.to_string()))?;
    let applied = db
        .applied_migrations()
        .await
        .map_err(|error| RestoreError::Database(error.to_string()))?;
    compatible(&archive.manifest, &applied)?;

    // The store is opened before the transaction, so a capture with blobs and an
    // unreachable bucket refuses without having emptied a single table.
    let storage = if plan.blobs.is_empty() {
        None
    } else {
        Some(
            crate::storage::open(&config.storage)
                .await
                .map_err(|error| RestoreError::Storage(error.to_string()))?,
        )
    };

    load_tables(&db, &plan).await?;

    if let Some(storage) = storage {
        for (path, body) in &plan.blobs {
            let parts: Vec<&str> = path.split('/').collect();
            let [workspace, group, hash] = parts.as_slice() else {
                continue;
            };
            let key = crate::storage::BlobKey::new(*workspace, *group, *hash)
                .map_err(|error| RestoreError::Storage(error.to_string()))?;
            storage
                .put(&key, body)
                .await
                .map_err(|error| RestoreError::Storage(error.to_string()))?;
        }
    }

    // The rows the collector counts as references have just been replaced, so
    // the next few sweeps are suppressed exactly as they are after the operator
    // half of a restore (`media::restore`, `health.rs` set_restore_marker).
    crate::media::restore::set(db.pool(), SUPPRESSED_PASSES, "database restore")
        .await
        .map_err(|error| RestoreError::Database(error.to_string()))?;

    let report = Report {
        tables: plan.tables.len(),
        blobs: plan.blobs.len(),
    };
    if let Some(receipt) = &request.receipt {
        write_receipt(receipt, &request.from, report).await?;
    }
    Ok(report)
}

/// The receipt, written last.
///
/// A small JSON document rather than an empty object, because the one thing a
/// reader wants to know beyond "it happened" is which capture it was: a bucket
/// holding two receipts must not be ambiguous about which restore each names.
pub fn receipt_document(from: &Destination, report: Report) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "restored_from": from.describe(),
        "tables": report.tables,
        "blobs": report.blobs,
        "relay_version": crate::BuildInfo::current().version,
    }))
    .unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

async fn write_receipt(
    receipt: &Destination,
    from: &Destination,
    report: Report,
) -> Result<(), RestoreError> {
    let body = receipt_document(from, report);
    let target = receipt.describe();
    match receipt {
        Destination::Local(path) => {
            std::fs::write(path, &body).map_err(|error| RestoreError::Source {
                at: target,
                reason: error.to_string(),
            })
        }
        Destination::S3 { bucket, key } => {
            // Staged on disk because the only upload the relay has takes a path
            // (`storage::put_object_file`, and `backup` stages its tarball the
            // same way). Removed on both paths out.
            let scratch =
                std::env::temp_dir().join(format!("wealdrelay-receipt-{}", std::process::id()));
            std::fs::write(&scratch, &body).map_err(|error| RestoreError::Source {
                at: target.clone(),
                reason: error.to_string(),
            })?;
            let put = crate::storage::put_object_file(bucket, key, &scratch).await;
            let _ = std::fs::remove_file(&scratch);
            put.map_err(|error| RestoreError::Storage(format!("{target}: {error}")))
        }
    }
}

/// Truncate and re-load every table in the plan, in one transaction.
///
/// `session_replication_role = replica` for the duration, because the tables are
/// loaded one at a time and a foreign key checked mid-load would refuse a row
/// whose parent table has not been loaded yet. The constraints are back on at
/// commit: this is a session setting inside a transaction, not a schema change,
/// and a rollback leaves both the data and the setting as they were.
async fn load_tables(db: &crate::db::Database, plan: &LoadPlan) -> Result<(), RestoreError> {
    let fail = |error: sqlx::Error| RestoreError::Database(error.to_string());
    let mut transaction = db.pool().begin().await.map_err(fail)?;
    sqlx::query("set local session_replication_role = replica")
        .execute(&mut *transaction)
        .await
        .map_err(fail)?;
    let list = plan
        .tables
        .iter()
        .map(|(table, _)| format!("public.\"{table}\""))
        .collect::<Vec<_>>()
        .join(", ");
    sqlx::query(&format!("truncate table {list} restart identity"))
        .execute(&mut *transaction)
        .await
        .map_err(fail)?;
    for (table, body) in &plan.tables {
        let mut sink = transaction
            .copy_in_raw(&format!("copy public.\"{table}\" from stdin"))
            .await
            .map_err(fail)?;
        // The block already carries its own `copy ... from stdin;` header and
        // its `\.` terminator, which is what makes the artifact loadable by
        // `psql` with no tool of ours. The header is dropped here because the
        // statement above is the header, and the terminator is dropped because
        // `finish` is the terminator.
        let payload = strip_copy_envelope(body);
        sink.send(payload).await.map_err(fail)?;
        sink.finish().await.map_err(fail)?;
    }
    transaction.commit().await.map_err(fail)?;
    Ok(())
}

/// A `COPY` block with its `copy ... from stdin;` line and trailing `\.` removed.
///
/// Pure and separate, because it is the one piece of parsing between an artifact
/// and a `COPY` stream and getting it wrong loads a literal SQL line as a row.
pub fn strip_copy_envelope(block: &[u8]) -> Vec<u8> {
    let mut body: &[u8] = block;
    if let Some(position) = body.iter().position(|byte| *byte == b'\n') {
        let first = &body[..position];
        if first.starts_with(b"copy ") {
            body = &body[position + 1..];
        }
    }
    for terminator in [b"\\.\n".as_slice(), b"\\.".as_slice()] {
        if body.ends_with(terminator) {
            body = &body[..body.len() - terminator.len()];
            break;
        }
    }
    body.to_vec()
}

/// The capture's bytes, from a path or from a bucket.
async fn read_source(from: &Destination) -> Result<Vec<u8>, RestoreError> {
    let source = from.describe();
    match from {
        Destination::Local(path) => read_local(path).map_err(|reason| RestoreError::Source {
            at: source.clone(),
            reason,
        }),
        Destination::S3 { bucket, key } => crate::storage::get_object_bytes(bucket, key)
            .await
            .map_err(|error| RestoreError::Source {
                at: source.clone(),
                reason: error.to_string(),
            }),
    }
}

fn read_local(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|error| error.to_string())
}

/// The `restore` half of argument parsing, beside the command for the reason
/// `backup::parse_args` is: the flag and what reads it live together.
pub fn parse_args<I, S>(rest: I) -> Result<Request, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut from: Option<String> = None;
    let mut receipt: Option<String> = None;
    let mut args = rest.into_iter();
    while let Some(arg) = args.next() {
        let arg = arg.as_ref().to_string();
        if let Some(value) = arg.strip_prefix("--receipt=") {
            if receipt.is_some() {
                return Err("restore: --receipt given twice".to_string());
            }
            receipt = Some(value.to_string());
        } else if arg == "--receipt" {
            if receipt.is_some() {
                return Err("restore: --receipt given twice".to_string());
            }
            match args.next() {
                Some(value) => receipt = Some(value.as_ref().to_string()),
                None => return Err("restore: --receipt needs a path".to_string()),
            }
        } else if let Some(value) = arg.strip_prefix("--from=") {
            if from.is_some() {
                return Err("restore: --from given twice".to_string());
            }
            from = Some(value.to_string());
        } else if arg == "--from" {
            if from.is_some() {
                return Err("restore: --from given twice".to_string());
            }
            match args.next() {
                Some(value) => from = Some(value.as_ref().to_string()),
                None => return Err("restore: --from needs a path".to_string()),
            }
        } else {
            return Err(format!("restore: unknown argument {arg}"));
        }
    }
    let renamed = |message: String| {
        // `Destination::parse` names itself `backup:` because that is its first
        // caller. The operator ran `restore`.
        message.replacen("backup:", "restore:", 1)
    };
    let receipt = match receipt {
        None => None,
        Some(value) if value.is_empty() => {
            return Err("restore: --receipt needs a path".to_string())
        }
        Some(value) => Some(Destination::parse(&value).map_err(renamed)?),
    };
    match from {
        Some(path) if !path.is_empty() => Ok(Request {
            from: Destination::parse(&path).map_err(renamed)?,
            receipt,
        }),
        Some(_) => Err("restore: --from needs a path".to_string()),
        None => Err("restore: --from <path> is required".to_string()),
    }
}
