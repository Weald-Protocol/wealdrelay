// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Object storage, filesystem and S3, behind one contract.
//!
//! `specs/backend/build/environments.md` states the rule this module exists to
//! satisfy: "Where a fake exists in this programme, a shared contract suite
//! exists beside it. Where one does not, the fake is not permitted." The
//! filesystem backend is not a hand-written approximation of S3; it is a
//! `BlobStore` implementation held to the same assertions, and any behaviour it
//! has that the real one does not is a bug in it and fails the contract run.
//!
//! ## The key layout is not a detail
//!
//! `specs/backend/relay/media.md`: the object key is
//! `workspace/group/ciphertext-hash`, and hashes are **never deduplicated across
//! groups or workspaces**. Two groups uploading identical ciphertext get two
//! objects. That is not a missed optimisation: cross-group dedupe would let one
//! group's membership prove what another group holds, which is a content
//! inference the relay is not supposed to be able to make.
//!
//! ## Never a partial write
//!
//! Step 3's negative proof is that a storage backend outage produces a typed
//! error and never a partial write. For the filesystem backend that is concrete:
//! bytes go to a temporary file in the same directory and are renamed into place,
//! so a reader either sees the whole object or no object. A backend that streamed
//! into the final path would leave a truncated blob that `exists` would then
//! answer for, and the relay would hand a client a presigned URL to half a file.

use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Where one blob lives. Constructed rather than formatted at call sites, so the
/// no-cross-group-dedupe rule is a property of the type instead of a convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobKey {
    pub workspace: String,
    pub group: String,
    pub hash: String,
}

impl BlobKey {
    /// Refuse a component that could escape the key space or collide with the
    /// separator. Every component is opaque to the relay, so the only thing that
    /// can be checked is shape, and shape is exactly what a path traversal
    /// exploits.
    pub fn new(
        workspace: impl Into<String>,
        group: impl Into<String>,
        hash: impl Into<String>,
    ) -> Result<Self, StorageError> {
        let key = Self {
            workspace: workspace.into(),
            group: group.into(),
            hash: hash.into(),
        };
        for component in [&key.workspace, &key.group, &key.hash] {
            // `.` as well as `..`. Both are path aliases, and the two backends
            // disagree about a bare `.`: real S3 accepts `ws/grp/.` as an ordinary
            // key while a filesystem can never create that file, so a key the
            // contract admits would work on one backend and not the other.
            if component.is_empty()
                || component == "."
                || component.contains('/')
                || component.contains('\\')
                || component.contains("..")
            {
                return Err(StorageError::InvalidKey {
                    component: component.clone(),
                });
            }
        }
        Ok(key)
    }

    /// `workspace/group/ciphertext-hash`.
    pub fn path(&self) -> String {
        format!("{}/{}/{}", self.workspace, self.group, self.hash)
    }
}

/// Why a storage operation failed.
///
/// Typed, because step 3's negative proof requires that a backend outage produces
/// a typed error rather than a panic or a partial write, and because the caller
/// has to map these onto the error classes in
/// `specs/backend/contracts/registries/error-codes.md`: an outage is `retry`,
/// a full disk is `quota`, and a malformed key is `reject`.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("blob key component {component:?} is empty or contains a path separator")]
    InvalidKey { component: String },
    #[error("no blob at {key}")]
    NotFound { key: String },
    #[error("storage backend is unreachable: {reason}")]
    Unreachable { reason: String },
    #[error("storage backend refused the write: {reason}")]
    WriteFailed { reason: String },
    #[error("storage backend refused the read: {reason}")]
    ReadFailed { reason: String },
}

impl StorageError {
    /// Whether a caller should retry. An outage is transient; a malformed key and
    /// a missing object are not.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Unreachable { .. })
    }
}

/// What a backend reports about one object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobInfo {
    pub len: u64,
}

/// The contract. Both backends implement exactly this, and the contract suite in
/// `tests/storage_contract.rs` runs the same assertions against both.
///
/// Deliberately narrow. Presigned URLs, multipart sessions and quota reservations
/// are `media.md` concerns that arrive with step 9; adding them now would be
/// adding a surface no test could exercise end to end.
/// Every method returns an explicit `impl Future + Send` rather than being an
/// `async fn`, and the trait is not object safe.
///
/// That is a toolchain decision recorded rather than absorbed. The obvious
/// spelling is `#[async_trait]` plus `Box<dyn BlobStore>`, and it was what this
/// module had first. On the pinned nightly, a trait carrying that macro makes
/// `llvm-cov report` segfault under branch instrumentation: a fifteen line trait
/// and one impl reproduce it with nothing else in the crate. The choice was
/// between a proc macro and the ability to measure the relay against the coverage
/// floor at all, so the macro went. `Sources/../build-coverage-exclusions.md` has
/// the full note.
///
/// The explicit `+ Send` matters and is not decoration: without it the returned
/// futures are not `Send`, and nothing holding a store could be spawned onto the
/// multi-threaded runtime.
pub trait BlobStore: Send + Sync + std::fmt::Debug {
    /// Store bytes at `key`, atomically. Overwriting an existing object with
    /// identical bytes is a no-op from a reader's point of view, which is what
    /// makes a retry after a dropped upload free.
    fn put(
        &self,
        key: &BlobKey,
        bytes: &[u8],
    ) -> impl std::future::Future<Output = Result<(), StorageError>> + Send;

    /// Read an object back, or `NotFound`.
    fn get(
        &self,
        key: &BlobKey,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, StorageError>> + Send;

    /// Whether the object is there, and how large. `exists` is what the relay
    /// answers instead of issuing a second upload URL for bytes it already holds.
    fn head(
        &self,
        key: &BlobKey,
    ) -> impl std::future::Future<Output = Result<Option<BlobInfo>, StorageError>> + Send;

    /// Remove an object. Removing one that is not there is not an error: garbage
    /// collection runs against a list that may be stale by the time it acts.
    fn delete(
        &self,
        key: &BlobKey,
    ) -> impl std::future::Future<Output = Result<(), StorageError>> + Send;

    /// Every key under one workspace and group, sorted. Used by the
    /// unreferenced-blob collector.
    fn list(
        &self,
        workspace: &str,
        group: &str,
    ) -> impl std::future::Future<Output = Result<Vec<String>, StorageError>> + Send;

    /// Concatenate `parts`, in the order given, into one object at `target`, and
    /// answer how many bytes it holds.
    ///
    /// This is how a multipart upload is finalized (`media::handle` and
    /// `specs/backend/relay/media.md`), and it is on the contract rather than in
    /// the media module for a reason found by measurement: the obvious
    /// implementation, reading every part and writing one object, cannot carry
    /// the size the spec requires. A single `PutObject` of 2 GiB against the
    /// object store this programme ships with fails after about two minutes with
    /// a dispatch failure, reproducibly, while 2,000,000,000 bytes succeeds in
    /// forty-three seconds. It would also mean the relay holding a whole
    /// attachment in memory twice, which is a denial of service as much as it is
    /// a correctness problem.
    ///
    /// So assembly belongs to the backend, which is the only layer that can do it
    /// without moving the bytes: the S3 arm issues one `UploadPartCopy` per part
    /// and the object is built inside the bucket, and the filesystem arm streams
    /// part into target through a bounded buffer.
    ///
    /// **Every part but the last must be at least 5 MiB.** That is S3's own
    /// multipart rule and it is stated on the contract rather than hidden in one
    /// implementation, because a caller that broke it would get a working
    /// filesystem backend and a refusing bucket. `media::MULTIPART_PART_SIZE` is
    /// 64 MiB, so the one caller satisfies it by construction.
    ///
    /// A missing part is `NotFound`, and nothing is written. An empty `parts` is
    /// `InvalidKey`: there is no such thing as an object assembled from nothing,
    /// and answering `Ok(0)` would let a client finalize an upload it never made.
    fn assemble(
        &self,
        parts: &[BlobKey],
        target: &BlobKey,
    ) -> impl std::future::Future<Output = Result<u64, StorageError>> + Send;

    /// Whether the backend is reachable right now. `/readyz` reports this, so it
    /// has to be a real round trip rather than a cached flag: an operator reading
    /// "storage ok" wants to know about the bucket, not about a boolean set at
    /// startup.
    fn probe(&self) -> impl std::future::Future<Output = Result<(), StorageError>> + Send;

    /// For logs and `/readyz`. Never a credential: this string is printed.
    fn describe(&self) -> String;
}

/// The filesystem backend. The whole of a single-node install's storage, and the
/// default in `local` (`specs/backend/build/environments.md`).
#[derive(Debug, Clone)]
pub struct FilesystemStore {
    root: PathBuf,
}

impl FilesystemStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn object_path(&self, key: &BlobKey) -> PathBuf {
        self.root
            .join(&key.workspace)
            .join(&key.group)
            .join(&key.hash)
    }

    fn group_path(&self, workspace: &str, group: &str) -> PathBuf {
        self.root.join(workspace).join(group)
    }
}

impl BlobStore for FilesystemStore {
    async fn put(&self, key: &BlobKey, bytes: &[u8]) -> Result<(), StorageError> {
        let target = self.object_path(key);
        let directory = target.parent().unwrap_or(&self.root);
        std::fs::create_dir_all(directory).map_err(|error| StorageError::WriteFailed {
            reason: error.to_string(),
        })?;

        // Temporary file in the same directory, then rename. Same directory
        // because rename across filesystems is not atomic, and atomicity is the
        // property being bought: a reader sees the whole object or no object,
        // never a truncated one that `head` would then answer for.
        let temporary = directory.join(format!(".{}.partial", key.hash));
        let write = || -> std::io::Result<()> {
            let mut file = std::fs::File::create(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()
        };
        if let Err(error) = write() {
            let _ = std::fs::remove_file(&temporary);
            return Err(StorageError::WriteFailed {
                reason: error.to_string(),
            });
        }
        if let Err(error) = std::fs::rename(&temporary, &target) {
            let _ = std::fs::remove_file(&temporary);
            return Err(StorageError::WriteFailed {
                reason: error.to_string(),
            });
        }
        Ok(())
    }

    async fn get(&self, key: &BlobKey) -> Result<Vec<u8>, StorageError> {
        let target = self.object_path(key);
        match std::fs::read(&target) {
            Ok(bytes) => Ok(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(StorageError::NotFound { key: key.path() })
            }
            Err(error) => Err(StorageError::ReadFailed {
                reason: error.to_string(),
            }),
        }
    }

    async fn head(&self, key: &BlobKey) -> Result<Option<BlobInfo>, StorageError> {
        match std::fs::metadata(self.object_path(key)) {
            Ok(metadata) => Ok(Some(BlobInfo {
                len: metadata.len(),
            })),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StorageError::ReadFailed {
                reason: error.to_string(),
            }),
        }
    }

    async fn delete(&self, key: &BlobKey) -> Result<(), StorageError> {
        match std::fs::remove_file(self.object_path(key)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(StorageError::WriteFailed {
                reason: error.to_string(),
            }),
        }
    }

    async fn list(&self, workspace: &str, group: &str) -> Result<Vec<String>, StorageError> {
        let directory = self.group_path(workspace, group);
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            // A group nobody has uploaded into is empty, not missing.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(StorageError::ReadFailed {
                    reason: error.to_string(),
                })
            }
        };
        object_names(entries)
    }

    async fn assemble(&self, parts: &[BlobKey], target: &BlobKey) -> Result<u64, StorageError> {
        if parts.is_empty() {
            return Err(StorageError::InvalidKey {
                component: "an object cannot be assembled from no parts".to_string(),
            });
        }
        let destination = self.object_path(target);
        let directory = destination.parent().unwrap_or(&self.root);
        std::fs::create_dir_all(directory).map_err(|error| StorageError::WriteFailed {
            reason: error.to_string(),
        })?;
        // The same temporary-then-rename shape `put` uses, and for the same
        // reason: a reader sees the whole object or no object. The parts are
        // streamed through a one-megabyte buffer rather than read whole, so
        // assembling a 2 GiB object costs a megabyte of memory.
        let temporary = directory.join(format!(".{}.assembling", target.hash));
        let mut written = 0u64;
        let outcome = (|| -> std::io::Result<u64> {
            let mut out = std::fs::File::create(&temporary)?;
            let mut buffer = vec![0u8; 1 << 20];
            for part in parts {
                let mut input = std::fs::File::open(self.object_path(part))?;
                loop {
                    let read = std::io::Read::read(&mut input, &mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    out.write_all(&buffer[..read])?;
                    written += read as u64;
                }
            }
            out.sync_all()?;
            Ok(written)
        })();
        let total = match outcome {
            Ok(total) => total,
            Err(error) => {
                let _ = std::fs::remove_file(&temporary);
                return Err(if error.kind() == std::io::ErrorKind::NotFound {
                    StorageError::NotFound { key: target.path() }
                } else {
                    StorageError::WriteFailed {
                        reason: error.to_string(),
                    }
                });
            }
        };
        if let Err(error) = std::fs::rename(&temporary, &destination) {
            let _ = std::fs::remove_file(&temporary);
            return Err(StorageError::WriteFailed {
                reason: error.to_string(),
            });
        }
        Ok(total)
    }

    async fn probe(&self) -> Result<(), StorageError> {
        // Reachability for a filesystem means the root is there and writable, and
        // the only honest way to know the second is to write. The probe object is
        // outside the `workspace/group/hash` space, so it can never be mistaken
        // for a blob or collected as one.
        std::fs::create_dir_all(&self.root).map_err(|error| StorageError::Unreachable {
            reason: error.to_string(),
        })?;
        // Named for this process, not `.readyz`. Two relays sharing one blob
        // directory is an ordinary deployment (a rolling deploy is exactly that),
        // and with one shared name they race: one writes the file, the other
        // removes it, and the first's remove fails with "no such file" and reports
        // its storage unreachable. A relay that refused to start because another
        // relay was starting is a deploy that fails half the time.
        //
        // Found by three processes starting at once in
        // `tests/multiprocess.rs`, which is the only place that interleaving is
        // exercised, and only after an unrelated change made all three reach this
        // line at the same instant.
        let probe = self.root.join(format!(".readyz.{}", std::process::id()));
        std::fs::write(&probe, b"ok").map_err(|error| StorageError::Unreachable {
            reason: error.to_string(),
        })?;
        // The write is the answer. Removing the probe is tidying, and a failure to
        // tidy is not a storage backend that cannot be reached: the write succeeded,
        // which is the whole question, and what is left behind is one empty
        // per-process file outside the `workspace/group/hash` space that the next
        // probe overwrites. Reporting the backend unreachable because a file could
        // not be deleted would take an instance down for the tidiest possible reason.
        let _ = std::fs::remove_file(&probe);
        Ok(())
    }

    fn describe(&self) -> String {
        format!("file://{}", self.root.display())
    }
}

/// The two backends, as a closed set.
///
/// Dynamic dispatch is not available: ``BlobStore`` returns `impl Future` and is
/// therefore not object safe, for the toolchain reason recorded on the trait. An
/// enum is the honest replacement rather than a workaround, because the set really
/// is closed: `server.md` names a filesystem path and an S3-compatible bucket and
/// nothing else, and a third backend would be a change to that document before it
/// was a change to this type.
#[derive(Debug)]
pub enum Store {
    Filesystem(FilesystemStore),
    S3(S3Store),
}

impl Store {
    pub async fn put(&self, key: &BlobKey, bytes: &[u8]) -> Result<(), StorageError> {
        match self {
            Self::Filesystem(store) => store.put(key, bytes).await,
            Self::S3(store) => store.put(key, bytes).await,
        }
    }

    pub async fn get(&self, key: &BlobKey) -> Result<Vec<u8>, StorageError> {
        match self {
            Self::Filesystem(store) => store.get(key).await,
            Self::S3(store) => store.get(key).await,
        }
    }

    pub async fn head(&self, key: &BlobKey) -> Result<Option<BlobInfo>, StorageError> {
        match self {
            Self::Filesystem(store) => store.head(key).await,
            Self::S3(store) => store.head(key).await,
        }
    }

    pub async fn delete(&self, key: &BlobKey) -> Result<(), StorageError> {
        match self {
            Self::Filesystem(store) => store.delete(key).await,
            Self::S3(store) => store.delete(key).await,
        }
    }

    pub async fn list(&self, workspace: &str, group: &str) -> Result<Vec<String>, StorageError> {
        match self {
            Self::Filesystem(store) => store.list(workspace, group).await,
            Self::S3(store) => store.list(workspace, group).await,
        }
    }

    pub async fn assemble(&self, parts: &[BlobKey], target: &BlobKey) -> Result<u64, StorageError> {
        match self {
            Self::Filesystem(store) => store.assemble(parts, target).await,
            Self::S3(store) => store.assemble(parts, target).await,
        }
    }

    pub async fn probe(&self) -> Result<(), StorageError> {
        match self {
            Self::Filesystem(store) => store.probe().await,
            Self::S3(store) => store.probe().await,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Filesystem(store) => store.describe(),
            Self::S3(store) => store.describe(),
        }
    }
}

/// Resolve the configured target into a store.
///
/// The S3 arm lands with the async client it needs; until then a configuration
/// naming `s3://` is refused at startup rather than accepted and discovered to be
/// unimplemented on the first upload. See `S3Store`.
pub async fn open(target: &crate::config::StorageTarget) -> Result<Store, StorageError> {
    match target {
        crate::config::StorageTarget::Filesystem(path) => {
            let store = Store::Filesystem(FilesystemStore::new(path.clone()));
            store.probe().await?;
            Ok(store)
        }
        crate::config::StorageTarget::S3 { bucket, prefix } => {
            let store = Store::S3(S3Store::connect(bucket.clone(), prefix.clone()).await);
            store.probe().await?;
            Ok(store)
        }
    }
}

/// Every object name in a directory listing, sorted, or the first read failure.
///
/// Written over the iterator rather than inside ``FilesystemStore::list`` for the
/// same reason ``object_name`` is written over one item: a `read_dir` iterator
/// yielding an error mid-iteration needs a detached volume or a fault-injecting
/// filesystem to provoke, and neither is available to a hermetic test. Taking the
/// iterator means the whole failure path, propagation included, is reachable with
/// a synthesized `io::Error` and is tested rather than asserted.
pub fn object_names(
    entries: impl Iterator<Item = std::io::Result<std::fs::DirEntry>>,
) -> Result<Vec<String>, StorageError> {
    let mut out = Vec::new();
    for entry in entries {
        if let Some(name) = object_name(entry)? {
            out.push(name);
        }
    }
    // Sorted here rather than by the caller, because both backends promise a
    // sorted listing and `read_dir` order is whatever the filesystem felt like.
    out.sort();
    Ok(out)
}

/// One directory entry, as an object name, or `None` if it is not one.
///
/// Split out of ``FilesystemStore::list`` rather than written inline for a reason
/// the coverage floor forces and that turns out to be the right shape anyway: a
/// `read_dir` iterator yielding an error mid-iteration needs a detached volume or a
/// fault-injecting filesystem to provoke, and neither is available to a hermetic
/// test. As a function taking the iterator's own item type it is reachable with a
/// synthesized `io::Error`, so the failure path is tested rather than asserted.
pub fn object_name(
    entry: std::io::Result<std::fs::DirEntry>,
) -> Result<Option<String>, StorageError> {
    let entry = entry.map_err(|error| StorageError::ReadFailed {
        reason: error.to_string(),
    })?;
    let name = entry.file_name().to_string_lossy().to_string();
    // A partial file is not an object. It is the temporary half of a put that was
    // interrupted, and listing it would let the collector delete an upload that is
    // still in flight.
    if name.starts_with('.') {
        return Ok(None);
    }
    Ok(Some(name))
}

/// Whether a path is inside a directory, after both are canonicalised. Used by
/// the contract suite; here rather than in the test so both backends can be held
/// to it.
pub fn is_within(root: &Path, candidate: &Path) -> bool {
    match (root.canonicalize(), candidate.canonicalize()) {
        (Ok(root), Ok(candidate)) => candidate.starts_with(root),
        _ => false,
    }
}

mod s3;
pub use s3::S3Store;
