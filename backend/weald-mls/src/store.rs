// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The provider: OpenMLS's crypto, randomness and storage, assembled for one workspace.
//!
//! `specs/backend/relay/mls-binding.md` requires this database to be encrypted at rest
//! with a Keychain key bound to the device. That is NOT true of this file today: what is
//! opened below is a plain SQLite database, with no SQLCipher and no key pragma, so the
//! MLS signing key and all group ratchet state are readable by anything that can read
//! the file. Do not describe this store as encrypted at rest anywhere — in a comment, a
//! spec, or a published claim — until encryption actually lands.
//!
//! The trait implementation itself is `openmls_sqlite_storage`, maintained by the OpenMLS
//! project. That is a deliberate choice and the same one the spec makes about OpenMLS: the
//! place where this design can refuse to be novel, it refuses. Hand-writing forty trait
//! methods over `rusqlite` would have put the group's persistence in the least reviewed
//! code in the tree.
//!
//! What is ours is the assembly: which file, which serialisation, the migration on first
//! use, and the pragmas that make a crash leave a readable database rather than a
//! truncated one.

use std::path::Path;
use std::rc::Rc;

use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;

use crate::status::{Error, Result};

/// How OpenMLS values are serialised into SQLite.
///
/// JSON, and the reason is auditability rather than size. A stored group is the thing an
/// incident investigation reads, and a self-describing encoding is one an investigator can
/// read with `sqlite3` and `jq` at three in the morning. The database is a plain file
/// today (see the module header), so this encoding IS carrying confidentiality it should
/// not have to; that is one more reason encryption at rest has to land, not a property
/// to rely on.
#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> core::result::Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(
        slice: &[u8],
    ) -> core::result::Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

/// The storage half of the provider, over one shared SQLite connection.
///
/// `Rc` rather than an owned connection, because the connection has two users: OpenMLS
/// through this trait implementation, and the caller's own document writes. The spec's
/// crash rule is "one transaction per processed message" covering both, and two
/// connections cannot be in one transaction however carefully they are sequenced. The
/// `Rc` is never sent anywhere: a handle is thread-confined (`handle.rs`), which is what
/// makes a non-atomic refcount the right one.
pub type Storage = SqliteStorageProvider<JsonCodec, Rc<Connection>>;

/// The same provider over a borrowed connection, used once to run the migrations.
///
/// A separate type only because `run_migrations` needs `BorrowMut` and an `Rc` cannot
/// give it. Nothing else uses this shape.
type Migrating<'a> = SqliteStorageProvider<JsonCodec, &'a mut Connection>;

/// Everything OpenMLS asks a host for.
pub struct Provider {
    crypto: RustCrypto,
    storage: Storage,
    /// The same connection the storage provider writes through, for the transaction that
    /// has to cover the caller's document state as well.
    connection: Rc<Connection>,
}

impl core::fmt::Debug for Provider {
    /// Named and nothing more. Neither OpenMLS's crypto provider nor the storage provider
    /// is `Debug`, and a provider that printed its contents would be a provider printing
    /// key material into whatever formatted it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Provider")
    }
}

impl Provider {
    /// Open or create the database at `path` and run the storage migrations.
    ///
    /// `:memory:` is accepted and is what the property suites use: ten thousand cases
    /// against a file would be measuring the disk. It is not a test double of the storage
    /// provider, which is the thing the spec forbids faking; it is the same provider and
    /// the same SQL against a database that does not outlive the case.
    pub fn open(path: &str) -> Result<Self> {
        // One `map_err` over both ways of getting a connection, because there is one
        // answer for both: a caller handed a path this process cannot open learns that the
        // storage refused, and which of the two calls refused is in the message rather
        // than in the type.
        let connection = if path == ":memory:" {
            Connection::open_in_memory()
        } else {
            // A missing parent directory is the ordinary first-run case for a workspace
            // container, and creating it here keeps the caller from having to know where
            // this library wants to live.
            if let Some(parent) = Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .map_err(|error| Error::Storage(error.to_string()))?;
                }
            }
            Connection::open(path)
        }
        .map_err(|error| Error::Storage(error.to_string()))?;

        // Write-ahead logging and a full synchronous setting, because the crash-injection
        // gate in `mls-binding.md` is exactly the case these decide. `synchronous=FULL`
        // costs a flush per transaction and buys the property the spec asks for: a commit
        // that returned has reached the disk, so a process killed immediately afterwards
        // comes back to a database that agrees with the message it just processed.
        //
        // Set in one loop rather than three statements, because the three share a failure
        // and the failure is the interesting part: SQLite opens a connection lazily, so
        // whichever pragma runs first is the statement that discovers a file that is not a
        // database or a database this process may not write. Naming the pragma in the
        // error is what tells a reader of the log which one that was.
        for (pragma, value) in [
            ("journal_mode", "WAL"),
            ("synchronous", "FULL"),
            ("foreign_keys", "ON"),
        ] {
            connection
                .pragma_update(None, pragma, value)
                .map_err(|error| Error::Storage(format!("pragma {pragma}: {error}")))?;
        }

        let mut connection = connection;
        Migrating::new(&mut connection)
            .run_migrations()
            .map_err(|error| Error::Storage(error.to_string()))?;
        let connection = Rc::new(connection);
        Ok(Self {
            crypto: RustCrypto::default(),
            storage: Storage::new(Rc::clone(&connection)),
            connection,
        })
    }

    /// The connection, for the transaction that spans MLS state and document state.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = Storage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_in_memory_provider_comes_up_migrated() {
        let provider = Provider::open(":memory:").expect("a provider");
        // The migration ran, so the storage tables exist. Asked of the database rather
        // than assumed, because a provider whose migrations silently did nothing fails
        // later, inside OpenMLS, with an error about a missing row.
        let count: i64 = provider
            .connection()
            .query_row(
                "select count(*) from sqlite_master where type = 'table' \
                 and name = 'openmls_sqlite_storage_migrations'",
                [],
                |row| row.get(0),
            )
            .expect("the migration table");
        assert_eq!(count, 1);
    }

    #[test]
    fn a_file_provider_creates_its_directory_and_survives_a_reopen() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir
            .path()
            .join("workspace")
            .join("mls.sqlite")
            .to_str()
            .expect("utf-8 path")
            .to_string();

        let provider = Provider::open(&path).expect("a provider");
        // WAL survives a reopen and is what the crash tests rely on, so it is asserted
        // rather than trusted: a database that silently stayed in rollback-journal mode
        // would still pass every functional test and lose the last transaction on a kill.
        let mode: String = provider
            .connection()
            .query_row("pragma journal_mode", [], |row| row.get(0))
            .expect("a journal mode");
        assert_eq!(mode.to_lowercase(), "wal");
        drop(provider);

        // Reopened: the migration is idempotent, which is what makes a relaunch cheap.
        let again = Provider::open(&path).expect("a reopened provider");
        let count: i64 = again
            .connection()
            .query_row(
                "select count(*) from openmls_sqlite_storage_migrations",
                [],
                |row| row.get(0),
            )
            .expect("a migration count");
        assert!(count >= 1);
    }

    /// Every pragma the crash gate depends on is really in effect on the connection the
    /// caller gets back.
    ///
    /// `mls-binding.md` asks for a database that survives a kill mid-transaction, and the
    /// three settings that decide it are set here rather than by SQLite's defaults: two of
    /// the three defaults are the wrong ones (`synchronous` is `NORMAL`, `foreign_keys` is
    /// off). They are asked of the connection rather than assumed from the fact that the
    /// statements returned without error, because a pragma name SQLite does not recognise
    /// is silently accepted and does nothing, and a provider that had quietly set nothing
    /// would pass every functional test in this crate and lose the last transaction on a
    /// kill.
    #[test]
    fn every_pragma_the_crash_gate_depends_on_is_in_effect_on_the_connection() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("pragmas.sqlite");
        let provider = Provider::open(path.to_str().expect("utf-8")).expect("a provider");

        let journal: String = provider
            .connection()
            .query_row("pragma journal_mode", [], |row| row.get(0))
            .expect("a journal mode");
        assert_eq!(journal.to_lowercase(), "wal");

        // 2 is `FULL`. Asserted as the number SQLite reports rather than the word this
        // code passes in, so the assertion is about the setting and not about the string.
        let synchronous: i64 = provider
            .connection()
            .query_row("pragma synchronous", [], |row| row.get(0))
            .expect("a synchronous setting");
        assert_eq!(synchronous, 2);

        let foreign_keys: i64 = provider
            .connection()
            .query_row("pragma foreign_keys", [], |row| row.get(0))
            .expect("a foreign keys setting");
        assert_eq!(foreign_keys, 1);
    }

    #[test]
    fn a_path_that_cannot_be_opened_is_a_storage_error_and_not_a_panic() {
        // A directory where a file has to be. The one failure a caller can actually
        // cause, and it must arrive as a status: the app's answer is to tell the person
        // their workspace container is wrong, not to crash.
        let dir = tempfile::tempdir().expect("a temp dir");
        let error = Provider::open(dir.path().to_str().expect("utf-8")).expect_err("refused");
        assert_eq!(error.status(), crate::status::Status::Storage);

        // And a path whose parent cannot be created, because a file is in the way.
        let file = dir.path().join("occupied");
        std::fs::write(&file, b"not a directory").expect("write");
        let blocked = file.join("mls.sqlite");
        let error = Provider::open(blocked.to_str().expect("utf-8")).expect_err("refused");
        assert_eq!(error.status(), crate::status::Status::Storage);
    }

    /// The provider prints its name and nothing else.
    ///
    /// A security property rather than a cosmetic one. `Provider` owns the SQLite
    /// connection that holds every signature key, every epoch secret and every key
    /// package private half this device has. A `Debug` that walked those fields would put
    /// key material into any log line, panic message or `assert_eq!` failure that ever
    /// formatted a provider, and `specs/backend/relay/mls-binding.md` scopes this crate as
    /// the place key material lives and does not leave. So the output is asserted to be
    /// exactly the type name, and asserted not to contain what a walked provider would
    /// have shown.
    #[test]
    fn the_debug_of_a_provider_names_the_type_and_prints_no_key_material() {
        let provider = Provider::open(":memory:").expect("a provider");
        let printed = format!("{provider:?}");
        assert_eq!(printed, "Provider");
        for leaked in ["crypto", "storage", "connection", "sqlite", "key"] {
            assert!(
                !printed.to_lowercase().contains(leaked),
                "the provider's Debug named {leaked}: {printed}"
            );
        }
        // And the same inside a container, which is the shape a `Debug` derive on a
        // caller's own type would produce.
        assert_eq!(format!("{:?}", Some(&provider)), "Some(Provider)");
    }

    /// A path with no directory component at all is opened as given.
    ///
    /// The database path arrives from Swift across a C ABI, so it is not guaranteed to
    /// look like a workspace container path. `/` has no parent and no name; there is
    /// nothing to create and nothing to open, and the answer has to be a status rather
    /// than a panic or a directory creation attempt at the root of the volume.
    #[test]
    fn a_path_with_no_parent_directory_is_refused_without_trying_to_create_one() {
        let error = Provider::open("/").expect_err("refused");
        assert_eq!(error.status(), crate::status::Status::Storage);
    }

    /// A file that is not a database is a storage error, named at the pragma that found
    /// it.
    ///
    /// SQLite opens a connection lazily, so a corrupt or unrelated file at the workspace
    /// path is not discovered by `Connection::open`: the first statement finds it. That
    /// first statement here is the `journal_mode` pragma the crash gate depends on, and a
    /// caller has to learn about it as a storage status rather than as a working provider
    /// that fails later inside OpenMLS.
    #[test]
    fn a_file_that_is_not_a_database_is_refused_when_the_pragmas_are_set() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("not-a-database.sqlite");
        std::fs::write(&path, b"this is not an sqlite file, it is a note").expect("write");
        let error = Provider::open(path.to_str().expect("utf-8")).expect_err("refused");
        assert_eq!(error.status(), crate::status::Status::Storage);
        assert!(
            error.to_string().contains("not a database"),
            "the error should name what sqlite found: {error}"
        );
    }

    /// A database whose tables collide with the storage migrations is refused.
    ///
    /// The workspace database is shared: `mls-binding.md` puts the search index in the
    /// same file, so somebody else's table can be in the way. The migration is where that
    /// is discovered, and it must arrive as a storage status. A provider that returned
    /// successfully from a half-run migration would hand OpenMLS a schema neither side
    /// agreed on.
    #[test]
    fn a_database_that_collides_with_the_storage_migrations_is_refused() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("occupied.sqlite");
        {
            let connection = Connection::open(&path).expect("a connection");
            // The name the second migration creates unconditionally.
            connection
                .execute("create table openmls_group_data_new (mine integer)", [])
                .expect("a colliding table");
        }
        let error = Provider::open(path.to_str().expect("utf-8")).expect_err("refused");
        assert_eq!(error.status(), crate::status::Status::Storage);
    }

    #[test]
    fn the_codec_round_trips_and_reports_what_it_cannot_read() {
        let bytes = JsonCodec::to_vec(&vec![1_u8, 2, 3]).expect("serialised");
        let back: Vec<u8> = JsonCodec::from_slice(&bytes).expect("deserialised");
        assert_eq!(back, vec![1, 2, 3]);
        // Not JSON at all: the shape a corrupted row has, and an error rather than a
        // panic is what lets the caller report a damaged database.
        let error = JsonCodec::from_slice::<Vec<u8>>(b"\xff\xfe").expect_err("refused");
        assert!(!error.to_string().is_empty());
    }
}
