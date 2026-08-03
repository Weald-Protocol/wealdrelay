// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Postgres: the pool, the migrations, and the reachability probe.
//!
//! The schema itself is SQL, under `migrations/`, embedded into the binary by
//! `sqlx::migrate!`. Embedded rather than shipped alongside because
//! `specs/backend/relay/server.md` promises one statically linked binary with no
//! runtime dependencies: a relay that needed its migration files on disk would
//! have a second artifact to deploy and a way to be half-upgraded.
//!
//! ## What the relay stores, and what it deliberately does not
//!
//! `server.md` names four things: the envelope log, group heads, key packages and
//! quotas. Two absences in the schema are decisions rather than omissions:
//!
//! - **No `prev` column on envelopes.** `specs/backend/relay/wire.md` removes the
//!   relay-maintained head chain: it made every concurrent write a compare-and-swap
//!   against one per-group head, and it did not deliver the tamper evidence it was
//!   credited with, because a chain the relay alone constructs is a chain the relay
//!   alone can fork. Ordering and tamper evidence live inside the ciphertext.
//! - **No column derived from content.** `ct` is opaque. There is no `kind`, no
//!   channel, no author: `kind` and `author` are inside the ciphertext, and the
//!   relay could not populate them without breaking the one claim the product
//!   makes. A schema that had somewhere to put them would be a schema inviting
//!   somebody to.
//!
//! `seq` is assigned here and is a sync cursor only. Gaps in it are legal: a
//! rolled-back transaction leaves one, and reconciliation runs over the space that
//! exists rather than over a dense range.

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::{Acquire as _, ConnectOptions, PgPool, Row};

/// The migrations, embedded.
///
/// `include_str!` and a hand-written runner rather than `sqlx::migrate!`. Two
/// reasons, and the first is the one that decided it:
///
/// - **`sqlx::migrate!` crashes `llvm-cov`.** The macro's generated coverage
///   mapping segfaults the report step on this toolchain, which would have meant
///   the relay could not be measured against the coverage floor at all. A tool
///   crash is not a reason to lower a floor, and it is not a reason to skip a
///   migration runner either, so the runner is written here where it is ordinary
///   code with ordinary tests.
/// - The runner is then **covered code rather than macro output**, which matters
///   for a component whose failure mode is a half-applied schema.
///
/// Embedded either way, because `server.md` promises one statically linked binary
/// with no runtime dependencies: a relay that needed its migration files on disk
/// would have a second artifact to deploy and a way to be half-upgraded.
const MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_relay_schema",
        include_str!("../migrations/0001_relay_schema.sql"),
    ),
    (
        "0002_access_set",
        include_str!("../migrations/0002_access_set.sql"),
    ),
    (
        "0003_invites",
        include_str!("../migrations/0003_invites.sql"),
    ),
    (
        "0004_recovery_wrap",
        include_str!("../migrations/0004_recovery_wrap.sql"),
    ),
    (
        "0005_handshake",
        include_str!("../migrations/0005_handshake.sql"),
    ),
    ("0006_media", include_str!("../migrations/0006_media.sql")),
    (
        "0007_lifecycle",
        include_str!("../migrations/0007_lifecycle.sql"),
    ),
];

/// The ledger of what has been applied. Created before anything else, and by the
/// same `create table if not exists` shape every migration uses, so a database
/// that already has it is not a failure.
const LEDGER_TABLE: &str = "create table if not exists relay_migration (\
     name text primary key, \
     fingerprint text not null, \
     applied_at timestamptz not null default now())";

/// A fixed advisory lock id for the migration section. Arbitrary and permanent:
/// changing it would let an old process and a new one migrate at once.
///
/// Public so the integration suite can take the same lock from another session
/// rather than copying the number, because a test holding a different lock would
/// prove nothing while still passing.
pub const MIGRATION_LOCK: i64 = 0x7765_616c_6431;

/// A cheap fingerprint over a migration's text, to notice an applied migration
/// that has since been edited.
///
/// FNV-1a, and deliberately not a cryptographic hash. What this detects is an
/// accident: somebody editing a migration that has already run somewhere. A
/// hostile edit is not in scope, because anybody who can change the migration text
/// in the binary can change this function beside it.
fn fingerprint(sql: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in sql.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("fnv1a:{hash:016x}")
}

/// Why the database layer refused.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("database url is not usable: {reason}")]
    BadUrl { reason: String },
    #[error("database is unreachable: {reason}")]
    Unreachable { reason: String },
    #[error("migrations failed: {reason}")]
    Migration { reason: String },
    #[error("query failed: {reason}")]
    Query { reason: String },
}

/// The pool, plus what it took to open it.
#[derive(Debug, Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    /// Connect, without migrating. Separate calls because "the database is
    /// reachable" and "the schema is current" are different failures with
    /// different operator responses, and `/readyz` reports the first.
    pub async fn connect(url: &str) -> Result<Self, DbError> {
        let mut options: sqlx::postgres::PgConnectOptions =
            url.parse().map_err(|error: sqlx::Error| DbError::BadUrl {
                reason: error.to_string(),
            })?;
        // Statement logging off. `specs/backend/relay/operations.md` allows group
        // ids at debug level and forbids envelope bytes at any level, and a driver
        // logging its own bind parameters would put `ct` in the log with no
        // scrubber in the path.
        options = options.disable_statement_logging();
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await
            .map_err(|error| DbError::Unreachable {
                reason: error.to_string(),
            })?;
        Ok(Self { pool })
    }

    /// For a caller that already holds a pool, including the integration suite.
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Run every migration that has not run.
    ///
    /// Idempotent, and safe to run on every start: `server.md` says first run
    /// migrates the schema, and an upgrade is rolling, so a process starting
    /// against a database a newer process already migrated must find nothing to do
    /// rather than fail. Two processes starting at once are serialised by a
    /// Postgres advisory lock, because a rolling deploy does exactly that and two
    /// concurrent `create table` statements would leave one process crash-looping.
    pub async fn migrate(&self) -> Result<(), DbError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|error| DbError::Unreachable {
                reason: error.to_string(),
            })?;

        // A fixed advisory lock id, held for the length of the session rather than
        // the transaction, so it also covers the ledger table's own creation.
        sqlx::query("select pg_advisory_lock($1)")
            .bind(MIGRATION_LOCK)
            .execute(&mut *connection)
            .await
            .map_err(|error| DbError::Migration {
                reason: format!("cannot take the migration lock: {error}"),
            })?;

        let result = Self::apply_all(&mut connection).await;

        // Released whatever happened: a process that failed to migrate and kept the
        // lock would block every other process on the deploy, turning one failure
        // into an outage.
        let _ = sqlx::query("select pg_advisory_unlock($1)")
            .bind(MIGRATION_LOCK)
            .execute(&mut *connection)
            .await;
        result
    }

    async fn apply_all(connection: &mut sqlx::PgConnection) -> Result<(), DbError> {
        sqlx::raw_sql(LEDGER_TABLE)
            .execute(&mut *connection)
            .await
            .map_err(|error| DbError::Migration {
                reason: format!("cannot create the migration ledger: {error}"),
            })?;

        for (name, sql) in MIGRATIONS {
            let digest = fingerprint(sql);
            let recorded: Option<String> =
                sqlx::query_scalar("select fingerprint from relay_migration where name = $1")
                    .bind(name)
                    .fetch_optional(&mut *connection)
                    .await
                    .map_err(|error| DbError::Migration {
                        reason: format!("cannot read the migration ledger: {error}"),
                    })?;

            match recorded {
                Some(recorded) if recorded == digest => continue,
                Some(recorded) => {
                    // An applied migration whose text has changed. Refused rather
                    // than re-run: re-running it would fail on the objects it
                    // already created, and ignoring it would leave the schema and
                    // the source disagreeing with nobody the wiser.
                    return Err(DbError::Migration {
                        reason: format!(
                            "migration {name} has already been applied with a \
                             different text (recorded {recorded}, this build has \
                             {digest}). Add a new migration rather than editing an \
                             applied one."
                        ),
                    });
                }
                None => {}
            }

            // One transaction per migration, so a failure part way through leaves
            // the schema as it was rather than half applied. The ledger row is
            // written inside it, which is what makes the pair atomic.
            let mut transaction = connection
                .begin()
                .await
                .map_err(|error| DbError::Migration {
                    reason: format!("cannot begin {name}: {error}"),
                })?;
            sqlx::raw_sql(sql)
                .execute(&mut *transaction)
                .await
                .map_err(|error| DbError::Migration {
                    reason: format!("{name} failed: {error}"),
                })?;
            sqlx::query("insert into relay_migration (name, fingerprint) values ($1, $2)")
                .bind(name)
                .bind(&digest)
                .execute(&mut *transaction)
                .await
                .map_err(|error| DbError::Migration {
                    reason: format!("cannot record {name}: {error}"),
                })?;
            transaction
                .commit()
                .await
                .map_err(|error| DbError::Migration {
                    reason: format!("cannot commit {name}: {error}"),
                })?;
        }
        Ok(())
    }

    /// Which migrations this database has applied, in order. Read by the
    /// integration suite and by the evidence bundle.
    pub async fn applied_migrations(&self) -> Result<Vec<String>, DbError> {
        let rows = sqlx::query("select name from relay_migration order by name")
            .fetch_all(&self.pool)
            .await
            .map_err(|error| DbError::Query {
                reason: error.to_string(),
            })?;
        Ok(rows
            .iter()
            .map(|row| row.get::<String, _>("name"))
            .collect())
    }

    /// A real round trip. `/readyz` reports database reachability, and a cached
    /// boolean would report a database that went away five minutes ago as healthy.
    pub async fn probe(&self) -> Result<(), DbError> {
        sqlx::query("select 1")
            .fetch_one(&self.pool)
            .await
            .map(|_| ())
            .map_err(|error| DbError::Unreachable {
                reason: error.to_string(),
            })
    }

    /// Every table the schema defines, in name order. A schema dump is recorded
    /// as evidence that the migrations landed, and this produces it from the
    /// running database rather than from the migration files, so the dump records
    /// what was actually applied.
    pub async fn tables(&self) -> Result<Vec<String>, DbError> {
        let rows = sqlx::query(
            "select table_name from information_schema.tables \
             where table_schema = 'public' order by table_name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| DbError::Query {
            reason: error.to_string(),
        })?;
        Ok(rows
            .iter()
            .map(|row| row.get::<String, _>("table_name"))
            .collect())
    }

    /// Column names and types for one table, for the same dump.
    pub async fn columns(&self, table: &str) -> Result<Vec<(String, String)>, DbError> {
        let rows = sqlx::query(
            "select column_name, data_type from information_schema.columns \
             where table_schema = 'public' and table_name = $1 order by ordinal_position",
        )
        .bind(table)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| DbError::Query {
            reason: error.to_string(),
        })?;
        Ok(rows
            .iter()
            .map(|row| {
                (
                    row.get::<String, _>("column_name"),
                    row.get::<String, _>("data_type"),
                )
            })
            .collect())
    }
}
