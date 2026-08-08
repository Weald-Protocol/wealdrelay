// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Step 3's integration proof, against real dependencies.
//!
//! `specs/backend/build/phases-relay.md`: "the binary against real Postgres and
//! real MinIO, migrations from zero, `/readyz` truthful, restart with state
//! intact". Every one of those words is load-bearing and none of them is
//! satisfiable with a mock, so nothing here is mocked.
//!
//! The dependencies come from the local harness (`scripts/weald-stack up`). If
//! they are not there these tests **fail** rather than skip. A skipped integration
//! proof that reports success is the exact failure mode this programme exists to
//! prevent: `specs/backend/build/testing.md` puts real Postgres and real object
//! storage in tier 3 and says "no mock of anything the customer runs".
//!
//! Each test gets its own database, created and dropped here, because
//! `testing.md` requires that no test share a port or a database name with
//! another.

use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use sqlx::{Connection, Executor as _, PgConnection, Row};

use wealdrelay::config::{keys, Config, StorageTarget, Values};

use wealdrelay::serve;

/// Where the harness puts Postgres. The port is the harness's default and is
/// overridable by the same variable the harness uses, so a machine already running
/// something on 54032 configures both in one place.
fn postgres_port() -> String {
    std::env::var("WEALD_STACK_PG_PORT").unwrap_or_else(|_| "54032".to_string())
}

fn minio_port() -> String {
    std::env::var("WEALD_STACK_MINIO_PORT").unwrap_or_else(|_| "54090".to_string())
}

fn admin_url() -> String {
    format!(
        "postgres://weald:weald@127.0.0.1:{}/weald_relay",
        postgres_port()
    )
}

/// Fail with the command that fixes it, rather than skipping.
fn require_reachable(port: &str, what: &str) {
    let address: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .expect("a valid address");
    if TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_err() {
        panic!(
            "{what} is not reachable on 127.0.0.1:{port}. This is an integration test and it \
             does not skip: run `scripts/weald-stack up` and try again."
        );
    }
}

/// A database of its own, named after the test, dropped when the guard falls.
struct Scratch {
    name: String,
    url: String,
}

impl Scratch {
    async fn new(label: &str) -> Self {
        require_reachable(&postgres_port(), "Postgres");
        // The name carries the pid as well as the label, so two runs of the suite
        // on one machine do not collide and a leftover database from a killed run
        // does not block the next one.
        let name = format!("weald_step3_{label}_{}", std::process::id());
        let mut admin = PgConnection::connect(&admin_url())
            .await
            .expect("connect to the harness Postgres");
        // Dropped first: a previous run killed mid-test leaves one behind, and a
        // suite that failed on that would be a suite nobody could rerun.
        admin
            .execute(format!("drop database if exists {name}").as_str())
            .await
            .expect("drop any leftover scratch database");
        admin
            .execute(format!("create database {name}").as_str())
            .await
            .expect("create the scratch database");
        let url = format!(
            "postgres://weald:weald@127.0.0.1:{}/{name}",
            postgres_port()
        );
        Self { name, url }
    }

    async fn drop_database(&self) {
        let Ok(mut admin) = PgConnection::connect(&admin_url()).await else {
            return;
        };
        let _ = admin
            .execute(format!("drop database if exists {} with (force)", self.name).as_str())
            .await;
    }
}

/// A configuration pointing at the scratch database, a scratch blob directory and
/// two ephemeral ports.
fn config_for(scratch: &Scratch, blobs: &std::path::Path) -> Config {
    Config::resolve(&Values::from_pairs([
        (keys::HOSTNAME, "localhost".to_string()),
        (keys::DATABASE_URL, scratch.url.clone()),
        (keys::STORAGE_URL, format!("file://{}", blobs.display())),
        // Port zero: the operating system assigns, so no test shares a port with
        // another. `testing.md` requires exactly this.
        (keys::LISTEN, "127.0.0.1:0".to_string()),
        (keys::OBSERVABILITY_LISTEN, "127.0.0.1:0".to_string()),
        // The one thing every environment agrees on, including local.
        (keys::ACCESS_SET, "enforce".to_string()),
        // Off, so no test makes an outbound request to the release feed.
        (keys::RELEASE_CHECK, "off".to_string()),
    ]))
    .expect("the integration configuration resolves")
}

// MARK: Migrations from zero

#[tokio::test]
async fn migrations_run_from_zero_and_create_the_four_things_the_relay_stores() {
    // "Migrations from zero" means against an empty database, not against one a
    // previous run left in some state. That is why this test creates its own.
    let scratch = Scratch::new("migrate").await;
    let blobs = tempfile::tempdir().unwrap();
    let state = serve::prepare(config_for(&scratch, blobs.path()))
        .await
        .expect("prepare against a real Postgres and a real directory");

    let database = state.database.as_ref().expect("a database");
    let tables = database.tables().await.expect("read the schema back");
    // `server.md` names four things the relay stores: the envelope log, group
    // heads, key packages and quotas. Each has a table, and the assertion is on the
    // schema the database actually holds rather than on the migration text, so a
    // migration that failed half way cannot pass this.
    for expected in [
        "relay_envelope",
        "relay_group",
        "relay_key_package",
        "relay_quota",
        "relay_blob_reservation",
    ] {
        assert!(
            tables.iter().any(|table| table == expected),
            "{expected} is missing from {tables:?}"
        );
    }

    // The envelope table holds the eight header fields and `ct`, and nothing
    // derived from content. A column named after anything inside the ciphertext
    // would be a place for somebody to put it.
    let columns = database
        .columns("relay_envelope")
        .await
        .expect("read the envelope columns");
    let names: Vec<&str> = columns.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        names,
        vec!["group_id", "hash", "v", "enc", "epoch", "seq", "ts", "ct"],
        "the envelope table is not the wire header plus ct"
    );
    for forbidden in ["kind", "author", "channel", "body", "sender", "text"] {
        assert!(
            !names.contains(&forbidden),
            "relay_envelope has a {forbidden} column, which the relay cannot populate"
        );
    }

    scratch.drop_database().await;
}

#[tokio::test]
async fn migrating_twice_is_a_no_op_so_a_rolling_upgrade_works() {
    // `server.md` says upgrades are rolling and migrations are forward-compatible
    // for one minor version, so an old process and a new one run against the same
    // database during a deploy. A migration that failed when it had already run
    // would make the second process crash-loop through the whole deploy.
    let scratch = Scratch::new("twice").await;
    let blobs = tempfile::tempdir().unwrap();
    let config = config_for(&scratch, blobs.path());
    serve::prepare(config.clone()).await.expect("first start");
    serve::prepare(config).await.expect("second start");
    scratch.drop_database().await;
}

#[tokio::test]
async fn an_applied_migration_that_has_since_been_edited_is_refused() {
    // The failure this guards against is a schema and a source that disagree with
    // nobody the wiser. Re-running an edited migration would fail on the objects it
    // already created; ignoring it would leave the two apart. Refusing names the
    // migration and says what to do instead.
    let scratch = Scratch::new("edited").await;
    let blobs = tempfile::tempdir().unwrap();
    let state = serve::prepare(config_for(&scratch, blobs.path()))
        .await
        .unwrap();
    let database = state.database.as_ref().unwrap();
    assert_eq!(
        database.applied_migrations().await.unwrap(),
        vec![
            "0001_relay_schema".to_string(),
            "0002_access_set".to_string(),
            "0003_invites".to_string(),
            "0004_recovery_wrap".to_string(),
            "0005_handshake".to_string(),
            "0006_media".to_string(),
            "0007_lifecycle".to_string(),
            "0008_envelope_read_path".to_string(),
            "0009_push".to_string(),
            "0010_envelope_budget".to_string()
        ]
    );

    // Rewrite the recorded fingerprint, which is what an edit to the file would
    // look like from the database's point of view.
    sqlx::query("update relay_migration set fingerprint = $1 where name = $2")
        .bind("fnv1a:0000000000000000")
        .bind("0001_relay_schema")
        .execute(database.pool())
        .await
        .unwrap();

    let error = database.migrate().await.expect_err("must refuse");
    let message = error.to_string();
    assert!(message.contains("0001_relay_schema"), "{message}");
    assert!(message.contains("already been applied"), "{message}");
    assert!(message.contains("Add a new migration"), "{message}");

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_migration_that_cannot_run_leaves_the_schema_as_it_was() {
    // One transaction per migration. A failure part way through must not leave half
    // a schema, because the next start would then see a ledger with no row and a
    // database with some of the objects, and would fail forever.
    let scratch = Scratch::new("halfway").await;
    let blobs = tempfile::tempdir().unwrap();
    let state = serve::prepare(config_for(&scratch, blobs.path()))
        .await
        .unwrap();
    let database = state.database.as_ref().unwrap();

    // Forget that the migration ran, and leave a table with the right name and the
    // wrong shape in its way. Every statement in the migration is `if not exists`,
    // which is what makes a rolling upgrade safe, so the only way to make one fail
    // is an object that already exists and does not match: the `create table if not
    // exists relay_group` becomes a no-op and the index on `workspace_id` then has
    // no such column to build on.
    sqlx::query("delete from relay_migration")
        .execute(database.pool())
        .await
        .unwrap();
    // Everything that references `relay_group` goes first, or the drop below is
    // refused by the foreign keys rather than by the thing this test is about.
    for dependent in [
        "relay_envelope",
        "relay_recovery_wrap",
        "relay_recovery_wrap_prior",
        "relay_handshake",
        "relay_retention_control",
        "relay_retention_control_conflict",
        "relay_retention_manifest",
        "relay_retention_manifest_rejected",
        "relay_retention_policy",
        "relay_retention_destruction",
        "relay_checkpoint_anchor",
        "relay_checkpoint",
    ] {
        sqlx::query(&format!("drop table {dependent}"))
            .execute(database.pool())
            .await
            .unwrap();
    }
    sqlx::query("drop table relay_group")
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query("create table relay_group (unrelated int)")
        .execute(database.pool())
        .await
        .unwrap();

    let error = database.migrate().await.expect_err("must refuse");
    assert!(error.to_string().contains("0001_relay_schema"), "{error}");
    // The ledger did not record a migration that did not finish.
    assert!(database.applied_migrations().await.unwrap().is_empty());

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_migration_against_a_closed_pool_reports_the_database_as_unreachable() {
    let scratch = Scratch::new("closedpool").await;
    let blobs = tempfile::tempdir().unwrap();
    let state = serve::prepare(config_for(&scratch, blobs.path()))
        .await
        .unwrap();
    let database = state.database.as_ref().unwrap();
    database.pool().close().await;
    let error = database.migrate().await.expect_err("must refuse");
    assert!(
        matches!(error, wealdrelay::db::DbError::Unreachable { .. }),
        "{error}"
    );
    // And the reader surfaces the same failure rather than an empty list.
    assert!(database.applied_migrations().await.is_err());
    assert!(database.tables().await.is_err());
    assert!(database.columns("relay_group").await.is_err());
    scratch.drop_database().await;
}

// MARK: The schema's own rules

#[tokio::test]
async fn the_schema_refuses_an_envelope_that_the_wire_format_would_refuse() {
    // The constraints are not decoration. A relay whose database accepted a
    // 33-byte group id or a two-megabyte `ct` would accept, at the storage layer,
    // things the accept path is specified to reject, and the two would drift.
    let scratch = Scratch::new("constraints").await;
    let blobs = tempfile::tempdir().unwrap();
    let state = serve::prepare(config_for(&scratch, blobs.path()))
        .await
        .unwrap();
    let pool = state.database.as_ref().unwrap().pool();

    let group = vec![7u8; 32];
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(&group)
        .bind("ws-1")
        .execute(pool)
        .await
        .expect("a 32-byte group id is accepted");

    // A group id of the wrong width.
    let wrong_width =
        sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
            .bind(vec![7u8; 31])
            .bind("ws-1")
            .execute(pool)
            .await;
    assert!(wrong_width.is_err(), "a 31-byte group id must be refused");

    let insert = "insert into relay_envelope \
                  (group_id, hash, v, enc, epoch, seq, ts, ct) \
                  values ($1, $2, $3, $4, $5, $6, $7, $8)";

    // The happy path first, so the failures below are about the constraint under
    // test and not about the statement.
    sqlx::query(insert)
        .bind(&group)
        .bind(vec![1u8; 32])
        .bind(1i16)
        .bind(0i16)
        .bind(0i64)
        .bind(1i64)
        .bind(1_700_000_000_000i64)
        .bind(vec![9u8; 16])
        .execute(pool)
        .await
        .expect("a well-formed envelope row is accepted");

    // An unknown protocol version, an unknown `enc`, an oversize `ct` and a
    // short hash. Each is a reject class in the error registry, and each is
    // refused here as well so the two layers cannot disagree.
    /// One rejected row: the label, the protocol version, the `enc`, the hash,
    /// the ciphertext and the sequence number.
    type RejectCase = (&'static str, i16, i16, Vec<u8>, Vec<u8>, i64);
    let cases: Vec<RejectCase> = vec![
        ("version", 2, 0, vec![2u8; 32], vec![1u8; 8], 2),
        ("enc", 1, 2, vec![3u8; 32], vec![1u8; 8], 3),
        ("hash width", 1, 0, vec![4u8; 16], vec![1u8; 8], 4),
        (
            "ct size",
            1,
            0,
            vec![5u8; 32],
            vec![0u8; 1024 * 1024 + 1],
            5,
        ),
    ];
    for (label, v, enc, hash, ct, seq) in cases {
        let result = sqlx::query(insert)
            .bind(&group)
            .bind(&hash)
            .bind(v)
            .bind(enc)
            .bind(0i64)
            .bind(seq)
            .bind(1_700_000_000_000i64)
            .bind(&ct)
            .execute(pool)
            .await;
        assert!(result.is_err(), "the schema must refuse a bad {label}");
    }

    // The content address deduplicates a retry: the same hash in the same group is
    // one row, and that is what lets the accept path answer a resend with the
    // existing `seq` instead of an error.
    let duplicate = sqlx::query(insert)
        .bind(&group)
        .bind(vec![1u8; 32])
        .bind(1i16)
        .bind(0i16)
        .bind(0i64)
        .bind(99i64)
        .bind(1_700_000_000_000i64)
        .bind(vec![9u8; 16])
        .execute(pool)
        .await;
    assert!(
        duplicate.is_err(),
        "the same hash in one group must be one row"
    );

    // The same hash in a *different* group is a different row, because hashes are
    // never deduplicated across groups.
    let other_group = vec![8u8; 32];
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(&other_group)
        .bind("ws-2")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(insert)
        .bind(&other_group)
        .bind(vec![1u8; 32])
        .bind(1i16)
        .bind(0i16)
        .bind(0i64)
        .bind(1i64)
        .bind(1_700_000_000_000i64)
        .bind(vec![9u8; 16])
        .execute(pool)
        .await
        .expect("the same hash in another group is another row");

    scratch.drop_database().await;
}

#[tokio::test]
async fn the_per_group_counter_hands_out_sequence_numbers_without_touching_other_groups() {
    // `operations.md`: sequence assignment is a single UPDATE ... RETURNING against
    // a per-group counter row inside the same transaction as the insert, so the
    // lock is per group and unrelated groups never contend. This asserts the shape
    // the accept path in step 4 will use, against the real database, before there
    // is an accept path to get it wrong.
    let scratch = Scratch::new("counter").await;
    let blobs = tempfile::tempdir().unwrap();
    let state = serve::prepare(config_for(&scratch, blobs.path()))
        .await
        .unwrap();
    let pool = state.database.as_ref().unwrap().pool();

    for (index, workspace) in ["ws-a", "ws-b"].iter().enumerate() {
        sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
            .bind(vec![index as u8 + 1; 32])
            .bind(workspace)
            .execute(pool)
            .await
            .unwrap();
    }

    let claim = "update relay_group set next_seq = next_seq + 1 \
                 where group_id = $1 returning next_seq - 1 as seq";
    for expected in 1..=3i64 {
        let row = sqlx::query(claim)
            .bind(vec![1u8; 32])
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(row.get::<i64, _>("seq"), expected);
    }
    // The other group is untouched, which is the whole point of the row being per
    // group.
    let row = sqlx::query(claim)
        .bind(vec![2u8; 32])
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(row.get::<i64, _>("seq"), 1);

    scratch.drop_database().await;
}

// MARK: /readyz is truthful

#[tokio::test]
async fn readyz_reports_both_dependencies_and_the_security_posture() {
    let scratch = Scratch::new("readyz").await;
    let blobs = tempfile::tempdir().unwrap();
    let state = serve::prepare(config_for(&scratch, blobs.path()))
        .await
        .unwrap();
    let readiness = state.readiness().await;

    assert!(readiness.database.ok, "{:?}", readiness.database);
    assert!(readiness.storage.ok, "{:?}", readiness.storage);
    assert!(readiness.ready);
    // The field step 3's artifact must contain.
    assert_eq!(readiness.access_set, "enforce");
    assert_eq!(readiness.min_enc, "none");
    assert_eq!(readiness.write_mode, "full");
    assert!(readiness.write_mode_reason.is_none());
    assert!(readiness.frozen_groups.is_empty());
    assert!(readiness.build.starts_with("wealdrelay "));
    // The release check is off in this configuration, and `disabled` is reported
    // rather than `current`: a relay that has not checked is not up to date.
    assert_eq!(
        serde_json::to_value(&readiness.release).unwrap()["state"],
        serde_json::json!("disabled")
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn readyz_tells_the_truth_when_the_database_goes_away() {
    // Truthful is the word in the gate, and this is the case that makes it mean
    // something. A cached answer would report a database that went away five
    // minutes ago as healthy, and somebody would act on it.
    let scratch = Scratch::new("dbgone").await;
    let blobs = tempfile::tempdir().unwrap();
    let state = serve::prepare(config_for(&scratch, blobs.path()))
        .await
        .unwrap();
    assert!(state.readiness().await.database.ok);

    // Close every connection in the pool and drop the database out from under it.
    state.database.as_ref().unwrap().pool().close().await;
    let readiness = state.readiness().await;
    assert!(!readiness.database.ok, "a closed pool must not report ok");
    assert!(!readiness.ready);
    let detail = readiness.database.detail.expect("a reason");
    assert!(!detail.is_empty());
    // Whatever the driver said, it does not carry the password out of the URL.
    assert!(
        !detail.contains("weald:weald"),
        "the readiness detail leaked a credential: {detail}"
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn readyz_tells_the_truth_when_storage_goes_away() {
    let scratch = Scratch::new("blobsgone").await;
    let blobs = tempfile::tempdir().unwrap();
    let path = blobs.path().join("nested");
    std::fs::create_dir_all(&path).unwrap();
    let state = serve::prepare(config_for(&scratch, &path)).await.unwrap();
    assert!(state.readiness().await.storage.ok);

    // Take the directory away and make its parent unwritable, so the probe cannot
    // simply recreate it. This is the filesystem equivalent of a bucket that has
    // stopped answering.
    std::fs::remove_dir_all(&path).unwrap();
    let mut permissions = std::fs::metadata(blobs.path()).unwrap().permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        permissions.set_mode(0o500);
    }
    std::fs::set_permissions(blobs.path(), permissions).unwrap();

    let readiness = state.readiness().await;
    // Running as root would recreate it, and that is a property of the machine
    // rather than of the code, so the assertion is on the pair: either storage is
    // down and the relay is not ready, or the probe genuinely succeeded.
    if !readiness.storage.ok {
        assert!(!readiness.ready);
        assert!(readiness.storage.detail.is_some());
    }

    let mut permissions = std::fs::metadata(blobs.path()).unwrap().permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        permissions.set_mode(0o700);
    }
    std::fs::set_permissions(blobs.path(), permissions).unwrap();
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_relay_running_access_set_off_says_so_on_readyz() {
    // `server.md`: a relay running `off` says so in `/readyz` output, because a
    // customer should not have to read their operator's environment file to learn
    // it. This is the ci suite that flips the value, and its whole purpose is to
    // assert the document reports the difference.
    let scratch = Scratch::new("accessoff").await;
    let blobs = tempfile::tempdir().unwrap();
    let mut config = config_for(&scratch, blobs.path());
    config.access_set = wealdrelay::config::AccessSetMode::Off;
    config.min_encryption = wealdrelay::config::MinEncryption::Mls;
    config.write_mode = wealdrelay::config::WriteMode::ReadOnly;
    let state = serve::prepare(config).await.unwrap();
    let readiness = state.readiness().await;

    assert_eq!(readiness.access_set, "off");
    assert_eq!(readiness.min_enc, "mls");
    assert_eq!(readiness.write_mode, "read_only");
    // The reason code is non-content, and it is the registry's own code.
    assert_eq!(readiness.write_mode_reason, Some("service_read_only"));
    // Read-only is not ready: a load balancer using this to decide where to send
    // writes should stop sending them here.
    assert!(!readiness.ready);
    assert!(readiness.database.ok && readiness.storage.ok);

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_frozen_group_is_named_on_readyz_and_stops_readiness() {
    // `media.md`: a group whose retention control chain has a contested successor
    // is reported as frozen on `/readyz`. Nothing can freeze a group until step 10,
    // so the column is set directly here: the point is that the document reports
    // it, and a poller that learned the field later would have to learn a new
    // document shape.
    let scratch = Scratch::new("frozen").await;
    let blobs = tempfile::tempdir().unwrap();
    let state = serve::prepare(config_for(&scratch, blobs.path()))
        .await
        .unwrap();
    let pool = state.database.as_ref().unwrap().pool();
    let group = vec![0xabu8; 32];
    sqlx::query(
        "insert into relay_group (group_id, workspace_id, frozen_reason) values ($1, $2, $3)",
    )
    .bind(&group)
    .bind("ws-frozen")
    .bind("contested retention successor")
    .execute(pool)
    .await
    .unwrap();

    let readiness = state.readiness().await;
    assert_eq!(readiness.frozen_groups.len(), 1);
    // Opaque, and a prefix rather than the whole id: enough to correlate, and the
    // same prefix length the client's alarms use.
    assert_eq!(
        readiness.frozen_groups[0],
        "ababababababab".get(..12).unwrap()
    );
    assert!(!readiness.ready);

    scratch.drop_database().await;
}

// MARK: Restart with state intact

#[tokio::test]
async fn a_restart_finds_its_state_intact() {
    // The gate's words. What makes this a real test rather than a tautology is that
    // the second start runs the migrations again and must neither fail nor lose the
    // row the first one wrote.
    let scratch = Scratch::new("restart").await;
    let blobs = tempfile::tempdir().unwrap();
    let config = config_for(&scratch, blobs.path());

    let first = serve::prepare(config.clone()).await.unwrap();
    let pool = first.database.as_ref().unwrap().pool();
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(vec![0x5au8; 32])
        .bind("ws-restart")
        .execute(pool)
        .await
        .unwrap();
    // A blob too, because storage is half the state and a restart that lost the
    // directory would be as broken as one that lost the row.
    let store = first.storage.as_ref().unwrap();
    let key = wealdrelay::storage::BlobKey::new("ws-restart", "group-1", "hash-1").unwrap();
    store.put(&key, b"ciphertext").await.unwrap();
    drop(first);

    let second = serve::prepare(config).await.unwrap();
    let count: i64 = sqlx::query_scalar("select count(*) from relay_group")
        .fetch_one(second.database.as_ref().unwrap().pool())
        .await
        .unwrap();
    assert_eq!(count, 1, "the restart lost the group row");
    assert_eq!(
        second.storage.as_ref().unwrap().get(&key).await.unwrap(),
        b"ciphertext"
    );
    assert!(second.readiness().await.ready);

    scratch.drop_database().await;
}

// MARK: The two listeners, over real sockets

#[tokio::test]
async fn the_public_listener_serves_liveness_and_nothing_else() {
    // The split is the design: a single `/readyz` on the public listener would tell
    // any passer-by whether access-set enforcement is on and whether the build is
    // behind a security release.
    let scratch = Scratch::new("listeners").await;
    let blobs = tempfile::tempdir().unwrap();
    let state = Arc::new(
        serve::prepare(config_for(&scratch, blobs.path()))
            .await
            .unwrap(),
    );
    let (public, private) = serve::bind(&state).await.unwrap();
    let public_address = public.local_addr().unwrap();
    let private_address = private.local_addr().unwrap();

    let (stop, wait) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(serve::run(Arc::clone(&state), public, private, async {
        let _ = wait.await;
    }));

    // Public: liveness, and no readiness.
    let body = get(&format!("http://{public_address}/healthz")).await;
    assert_eq!(body.0, 200);
    assert_eq!(body.1.trim(), "ok");
    let (status, body) = get(&format!("http://{public_address}/readyz")).await;
    assert_eq!(status, 404, "the public listener must not serve /readyz");
    assert!(!body.contains("access_set"));

    // Private: the whole document.
    let (status, body) = get(&format!("http://{private_address}/readyz")).await;
    assert_eq!(status, 200, "{body}");
    let document: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(document["access_set"], "enforce");
    assert_eq!(document["ready"], true);
    assert_eq!(document["database"]["ok"], true);
    assert_eq!(document["storage"]["ok"], true);
    // The private listener answers liveness too, so a poller behind provider-private
    // networking does not need to reach the public one.
    assert_eq!(
        get(&format!("http://{private_address}/healthz")).await.0,
        200
    );

    let _ = stop.send(());
    served.await.unwrap();

    // And the sockets are closed once it has stopped.
    assert!(
        tokio::net::TcpStream::connect(public_address)
            .await
            .is_err()
            || tokio::net::TcpStream::connect(public_address)
                .await
                .is_err(),
        "the public listener is still accepting after shutdown"
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn readyz_answers_503_when_the_relay_is_not_ready() {
    // A poller that only reads the status code must not be misled, and a caller
    // debugging the 503 needs the document, so both happen.
    let scratch = Scratch::new("notready").await;
    let blobs = tempfile::tempdir().unwrap();
    let mut config = config_for(&scratch, blobs.path());
    config.write_mode = wealdrelay::config::WriteMode::ReadOnly;
    let state = Arc::new(serve::prepare(config).await.unwrap());
    let (public, private) = serve::bind(&state).await.unwrap();
    let private_address = private.local_addr().unwrap();
    let (stop, wait) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(serve::run(Arc::clone(&state), public, private, async {
        let _ = wait.await;
    }));

    let (status, body) = get(&format!("http://{private_address}/readyz")).await;
    assert_eq!(status, 503);
    let document: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(document["ready"], false);
    assert_eq!(document["write_mode"], "read_only");

    let _ = stop.send(());
    served.await.unwrap();
    scratch.drop_database().await;
}

#[tokio::test]
async fn binding_a_port_already_in_use_is_a_typed_failure_naming_the_address() {
    // An operator who has something else on 8443 needs told which address failed,
    // not a panic.
    let scratch = Scratch::new("bindfail").await;
    let blobs = tempfile::tempdir().unwrap();
    let squatter = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let taken = squatter.local_addr().unwrap().to_string();

    let mut config = config_for(&scratch, blobs.path());
    config.listen = taken.clone();
    let state = Arc::new(serve::prepare(config).await.unwrap());
    let error = serve::bind(&state).await.expect_err("must refuse");
    assert!(error.to_string().contains(&taken), "{error}");
    assert_eq!(error.exit_code(), wealdrelay::EXIT_UNAVAILABLE);

    // And the same for the private listener, which is a separate call site.
    let mut config = config_for(&scratch, blobs.path());
    config.observability_listen = taken.clone();
    let state = Arc::new(serve::prepare(config).await.unwrap());
    let error = serve::bind(&state).await.expect_err("must refuse");
    assert!(error.to_string().contains(&taken), "{error}");

    scratch.drop_database().await;
}

// MARK: Startup failures

#[tokio::test]
async fn a_database_that_is_not_there_stops_the_process_with_a_typed_error() {
    // `EX_UNAVAILABLE` and not `EX_CONFIG`: the configuration was valid and the
    // thing it named did not answer. An init system can tell the two apart.
    let blobs = tempfile::tempdir().unwrap();
    let config = Config::resolve(&Values::from_pairs([
        (keys::HOSTNAME, "localhost".to_string()),
        (
            keys::DATABASE_URL,
            "postgres://weald:weald@127.0.0.1:1/nothing_here".to_string(),
        ),
        (
            keys::STORAGE_URL,
            format!("file://{}", blobs.path().display()),
        ),
    ]))
    .unwrap();
    let error = serve::prepare(config).await.expect_err("must refuse");
    assert_eq!(error.exit_code(), wealdrelay::EXIT_UNAVAILABLE);
    assert!(
        !error.to_string().contains("weald:weald"),
        "the startup error leaked a credential: {error}"
    );
}

#[tokio::test]
async fn a_storage_path_that_cannot_be_created_stops_the_process() {
    let scratch = Scratch::new("badstorage").await;
    let mut config = config_for(&scratch, std::path::Path::new("/dev/null/blobs"));
    config.storage = StorageTarget::Filesystem("/dev/null/blobs".into());
    let error = serve::prepare(config).await.expect_err("must refuse");
    assert_eq!(error.exit_code(), wealdrelay::EXIT_UNAVAILABLE);
    scratch.drop_database().await;
}

#[tokio::test]
async fn an_unusable_database_url_is_reported_before_a_connection_is_attempted() {
    // The configuration layer refuses a URL that is not Postgres, so reaching this
    // needs a URL that parses as Postgres and is not usable by the driver.
    let error = wealdrelay::db::Database::connect("postgres://[not a host]/db")
        .await
        .expect_err("must refuse");
    assert!(
        matches!(error, wealdrelay::db::DbError::BadUrl { .. }),
        "{error}"
    );
}

// MARK: MinIO, the other real dependency

#[tokio::test]
async fn the_relay_starts_against_real_minio() {
    // The gate says real MinIO, so one start goes all the way through the S3
    // backend rather than the filesystem one. The contract suite covers the
    // operations; this covers `prepare` choosing and probing the S3 arm.
    require_reachable(&minio_port(), "MinIO");
    let scratch = Scratch::new("minio").await;
    let bucket = format!("weald-step3-{}", std::process::id());
    create_bucket(&bucket).await;

    let mut config = config_for(&scratch, tempfile::tempdir().unwrap().path());
    config.storage = StorageTarget::S3 {
        bucket: bucket.clone(),
        prefix: String::new(),
    };
    // The SDK reads these, which is how MinIO is reached without a Weald-specific
    // credential key: the difference between environments is configuration.
    // Safety: this test process sets them for itself before the client is built.
    unsafe {
        std::env::set_var("AWS_ACCESS_KEY_ID", "weald");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "weald-local-only");
        std::env::set_var("AWS_REGION", "us-east-1");
        std::env::set_var(
            "AWS_ENDPOINT_URL_S3",
            format!("http://127.0.0.1:{}", minio_port()),
        );
    }

    let state = serve::prepare(config).await.expect("start against MinIO");
    let readiness = state.readiness().await;
    assert!(readiness.storage.ok, "{:?}", readiness.storage);
    assert!(readiness.ready);
    assert_eq!(
        state.storage.as_ref().unwrap().describe(),
        format!("s3://{bucket}")
    );

    delete_bucket(&bucket).await;
    scratch.drop_database().await;
}

// MARK: Helpers

/// A minimal HTTP GET. Written here rather than pulled in as a dependency because
/// the whole need is one request against loopback, and a client crate would be a
/// dependency the relay does not otherwise have.
/// A GET carrying an `Authorization: Bearer`, for the operator routes.
async fn get_with_bearer(url: &str, token: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let without_scheme = url.strip_prefix("http://").expect("an http url");
    let (authority, path) = without_scheme.split_once('/').expect("a path");
    let mut stream = tokio::net::TcpStream::connect(authority)
        .await
        .expect("connect to the relay");
    let request = format!(
        "GET /{path} HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {token}\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

async fn get(url: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let without_scheme = url.strip_prefix("http://").expect("an http url");
    let (authority, path) = without_scheme.split_once('/').expect("a path");
    let mut stream = tokio::net::TcpStream::connect(authority)
        .await
        .expect("connect to the relay");
    let request = format!("GET /{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = text.split_once("\r\n\r\n").map_or("", |(_, body)| body);
    (status, body.to_string())
}

async fn minio_client() -> aws_sdk_s3::Client {
    let credentials = aws_credential_types::Credentials::new(
        "weald",
        "weald-local-only",
        None,
        None,
        "weald-step3-tests",
    );
    let config = aws_sdk_s3::Config::builder()
        .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .endpoint_url(format!("http://127.0.0.1:{}", minio_port()))
        .credentials_provider(credentials)
        .force_path_style(true)
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

async fn create_bucket(bucket: &str) {
    let client = minio_client().await;
    let _ = client.create_bucket().bucket(bucket).send().await;
}

async fn delete_bucket(bucket: &str) {
    let client = minio_client().await;
    if let Ok(listed) = client.list_objects_v2().bucket(bucket).send().await {
        for object in listed.contents() {
            if let Some(key) = object.key() {
                let _ = client.delete_object().bucket(bucket).key(key).send().await;
            }
        }
    }
    let _ = client.delete_bucket().bucket(bucket).send().await;
}

// MARK: A connection that dies part way through a migration
//
// `migrate` reports six different failures, and each one tells the operator
// something different: a lock it could not take means another process is
// migrating, a ledger it could not create means the role cannot write to the
// schema, a transaction it could not commit means the migration did not happen.
// Collapsing them into one message would leave whoever is holding the pager
// guessing, so each is a separate arm and each is proven here.
//
// A real database does not fail on demand at a chosen statement, so these drive it
// through a proxy that severs the connection the moment a named statement goes
// past. That is not a mock of Postgres: the database and the driver are both real,
// and what is simulated is the network between them going away, which is the
// failure these arms exist for.

/// A TCP proxy in front of the harness Postgres that cuts the connection dead the
/// moment the client sends a statement containing `marker`.
///
/// The bytes are forwarded verbatim in both directions until the marker appears,
/// so everything before it really happened against the real server. Returns the
/// port to point a connection at.
async fn postgres_that_dies_at(marker: &'static [u8]) -> u16 {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    require_reachable(&postgres_port(), "Postgres");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback proxy");
    let port = listener.local_addr().expect("local address").port();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let upstream = format!("127.0.0.1:{}", postgres_port());
                let Ok(server) = tokio::net::TcpStream::connect(upstream).await else {
                    return;
                };
                let (mut from_client, mut to_client) = client.into_split();
                let (mut from_server, mut to_server) = server.into_split();
                let forward = async move {
                    // Everything the client has sent so far, so a marker split
                    // across two reads is still seen.
                    let mut sent: Vec<u8> = Vec::new();
                    let mut buffer = vec![0_u8; 8192];
                    loop {
                        let Ok(read) = from_client.read(&mut buffer).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        sent.extend_from_slice(&buffer[..read]);
                        if sent.windows(marker.len()).any(|window| window == marker) {
                            // Dropped without forwarding, which from the driver's
                            // side is the connection going away mid-statement.
                            return;
                        }
                        if to_server.write_all(&buffer[..read]).await.is_err() {
                            return;
                        }
                    }
                };
                let back = async move {
                    let _ = tokio::io::copy(&mut from_server, &mut to_client).await;
                };
                tokio::select! {
                    () = forward => {},
                    () = back => {},
                }
            });
        }
    });
    port
}

/// The scratch database, reached through a proxy that will sever the connection.
/// `sslmode` is disabled so the statements are visible to the proxy: a session the
/// proxy could not read would be a proxy that never cut anything and a test that
/// passed for the wrong reason.
async fn severing_url(scratch: &Scratch, marker: &'static [u8]) -> String {
    let port = postgres_that_dies_at(marker).await;
    format!(
        "postgres://weald:weald@127.0.0.1:{port}/{}?sslmode=disable",
        scratch.name
    )
}

#[tokio::test]
async fn a_pool_the_caller_already_holds_can_be_wrapped_and_used() {
    // The relay opens its own pool, but the integration suite and anything
    // embedding the library hand one in. A wrapper that did not actually use the
    // pool it was given would connect somewhere else, and every test written
    // against it would be a test of a different database.
    let scratch = Scratch::new("frompool").await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&scratch.url)
        .await
        .expect("connect a pool to the scratch database");
    let database = wealdrelay::db::Database::from_pool(pool.clone());

    database
        .migrate()
        .await
        .expect("migrate through the wrapped pool");
    database
        .probe()
        .await
        .expect("the wrapped pool is reachable");
    assert_eq!(
        database.applied_migrations().await.unwrap(),
        vec![
            "0001_relay_schema".to_string(),
            "0002_access_set".to_string(),
            "0003_invites".to_string(),
            "0004_recovery_wrap".to_string(),
            "0005_handshake".to_string(),
            "0006_media".to_string(),
            "0007_lifecycle".to_string(),
            "0008_envelope_read_path".to_string(),
            "0009_push".to_string(),
            "0010_envelope_budget".to_string()
        ]
    );
    // The same pool, and not a copy of the configuration that opened another one.
    assert!(!database.pool().is_closed());
    pool.close().await;
    assert!(database.pool().is_closed());

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_migration_that_cannot_take_the_lock_says_so_and_does_not_run_anyway() {
    // The lock is what makes a rolling deploy safe. A process that could not take
    // it must stop, because carrying on would be two processes running `create
    // table` at once, which is the crash loop the lock exists to prevent. The
    // message names the lock rather than the migration, because the operator's
    // question is which other process is holding it.
    let scratch = Scratch::new("nolock").await;
    let url = severing_url(&scratch, b"pg_advisory_lock").await;
    let database = wealdrelay::db::Database::connect(&url)
        .await
        .expect("the proxy carries a healthy connection until the lock is asked for");

    let error = database.migrate().await.expect_err("must refuse");
    assert!(
        matches!(error, wealdrelay::db::DbError::Migration { .. }),
        "a lock that could not be taken is a migration failure, not a query failure: {error}"
    );
    assert!(
        error.to_string().contains("cannot take the migration lock"),
        "{error}"
    );
    // And nothing was applied, because nothing ran.
    let checker = wealdrelay::db::Database::connect(&scratch.url)
        .await
        .unwrap();
    assert!(
        !checker
            .tables()
            .await
            .unwrap()
            .contains(&"relay_envelope".to_string()),
        "a migration that never took the lock must not have created anything"
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_ledger_that_cannot_be_created_stops_the_migration_before_any_schema_runs() {
    // The ledger is created first and by the same `if not exists` shape every
    // migration uses. If it cannot be created, the relay does not know what has
    // already run, and running the migrations blind is how a half-upgraded schema
    // happens.
    let scratch = Scratch::new("noledger").await;
    let url = severing_url(&scratch, b"create table if not exists relay_migration").await;
    let database = wealdrelay::db::Database::connect(&url).await.unwrap();

    let error = database.migrate().await.expect_err("must refuse");
    assert!(
        error
            .to_string()
            .contains("cannot create the migration ledger"),
        "{error}"
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_ledger_that_cannot_be_read_is_refused_rather_than_treated_as_empty() {
    // A ledger the relay cannot read is not a ledger with nothing in it. Reading
    // the failure as "nothing has been applied" would re-run every migration
    // against a database that already has the schema, and the operator would see
    // the second failure rather than the first.
    //
    // The shape here is what an operator collides with in practice: something else
    // in the database already owns the name `relay_migration`. The `if not exists`
    // create is then a no-op and the read is what fails, which is exactly the
    // ordering this arm has to survive.
    let scratch = Scratch::new("badledger").await;
    let mut connection = PgConnection::connect(&scratch.url).await.unwrap();
    connection
        .execute("create table relay_migration (wrong int)")
        .await
        .expect("put a table of the same name and the wrong shape in the way");

    let database = wealdrelay::db::Database::connect(&scratch.url)
        .await
        .unwrap();
    let error = database.migrate().await.expect_err("must refuse");
    assert!(
        error
            .to_string()
            .contains("cannot read the migration ledger"),
        "{error}"
    );

    // And the startup path surfaces it rather than binding a listener over it. A
    // relay that answered `/healthz` with a schema it could not account for would
    // be told by an orchestrator that it was fine.
    let blobs = tempfile::tempdir().unwrap();
    let failure = serve::prepare(config_for(&scratch, blobs.path()))
        .await
        .expect_err("startup must refuse");
    assert!(
        failure
            .to_string()
            .contains("cannot read the migration ledger"),
        "{failure}"
    );
    // A dependency that will not answer is `EX_UNAVAILABLE`, not `EX_CONFIG`: the
    // configuration was valid and the thing it named is in a state the relay
    // cannot work with.
    assert_eq!(failure.exit_code(), 69);

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_transaction_that_cannot_be_opened_names_the_migration_it_was_for() {
    // One transaction per migration is what makes a failure part way through leave
    // the schema as it was. A transaction that never opened has to be reported as
    // such rather than letting the statements run outside one, because outside one
    // a failure half way leaves half a schema and a ledger with no row in it.
    let scratch = Scratch::new("nobegin").await;
    let url = severing_url(&scratch, b"BEGIN").await;
    let database = wealdrelay::db::Database::connect(&url).await.unwrap();

    let error = database.migrate().await.expect_err("must refuse");
    let message = error.to_string();
    assert!(message.contains("cannot begin"), "{message}");
    assert!(message.contains("0001_relay_schema"), "{message}");

    // Nothing was applied. The transaction is what the ledger row rides in, so a
    // migration that could not open one cannot have recorded itself.
    let checker = wealdrelay::db::Database::connect(&scratch.url)
        .await
        .unwrap();
    assert!(checker.applied_migrations().await.unwrap().is_empty());

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_transaction_that_cannot_be_committed_is_reported_and_not_assumed() {
    // The last thing that can go wrong, and the most dangerous one to get wrong: a
    // commit that failed and was read as success would leave the process believing
    // the schema is current when the database rolled the whole thing back. The next
    // query against the missing table would be the first anybody heard of it.
    let scratch = Scratch::new("nocommit").await;
    let url = severing_url(&scratch, b"COMMIT").await;
    let database = wealdrelay::db::Database::connect(&url).await.unwrap();

    let error = database.migrate().await.expect_err("must refuse");
    let message = error.to_string();
    assert!(message.contains("cannot commit"), "{message}");
    assert!(message.contains("0001_relay_schema"), "{message}");

    // The server rolled the transaction back when the connection went away, so the
    // database is as it was and the next start has a clean run at it.
    let checker = wealdrelay::db::Database::connect(&scratch.url)
        .await
        .unwrap();
    assert!(
        checker.applied_migrations().await.unwrap().is_empty(),
        "a commit that did not happen must not leave a ledger row behind"
    );
    assert!(
        !checker
            .tables()
            .await
            .unwrap()
            .contains(&"relay_envelope".to_string()),
        "the schema went back with the transaction, so nothing it created survives"
    );
    checker
        .migrate()
        .await
        .expect("a clean connection completes the migration");
    assert_eq!(
        checker.applied_migrations().await.unwrap(),
        vec![
            "0001_relay_schema".to_string(),
            "0002_access_set".to_string(),
            "0003_invites".to_string(),
            "0004_recovery_wrap".to_string(),
            "0005_handshake".to_string(),
            "0006_media".to_string(),
            "0007_lifecycle".to_string(),
            "0008_envelope_read_path".to_string(),
            "0009_push".to_string(),
            "0010_envelope_budget".to_string()
        ]
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn the_migration_lock_is_the_one_the_relay_actually_takes() {
    // The lock id is fixed and permanent: changing it would let an old process and
    // a new one migrate at once, which is the thing it exists to prevent. Held from
    // another session here, so the number in the source is proven to be the number
    // on the wire rather than copied into the test and drifted.
    let scratch = Scratch::new("locknum").await;
    let mut holder = PgConnection::connect(&scratch.url).await.unwrap();
    sqlx::query("select pg_advisory_lock($1)")
        .bind(wealdrelay::db::MIGRATION_LOCK)
        .execute(&mut holder)
        .await
        .expect("take the lock from another session");

    // A second session asking for the same lock without waiting is refused, which
    // is what makes the id load-bearing.
    let mut other = PgConnection::connect(&scratch.url).await.unwrap();
    let taken: bool = sqlx::query_scalar("select pg_try_advisory_lock($1)")
        .bind(wealdrelay::db::MIGRATION_LOCK)
        .fetch_one(&mut other)
        .await
        .unwrap();
    assert!(!taken, "the relay's lock id has to be the one being held");

    drop(holder);
    drop(other);
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_migration_that_cannot_record_itself_is_a_failure_and_not_a_silent_success() {
    // The ledger row is written inside the migration's own transaction, and that
    // pairing is what makes "has this run" answerable at all. A relay that applied
    // the schema and could not record it, and reported success anyway, would run
    // the same migration again on the next start and fail on the objects it had
    // already created, forever.
    let scratch = Scratch::new("norecord").await;
    let url = severing_url(&scratch, b"insert into relay_migration").await;
    let database = wealdrelay::db::Database::connect(&url).await.unwrap();

    let error = database.migrate().await.expect_err("must refuse");
    let message = error.to_string();
    assert!(message.contains("cannot record"), "{message}");
    assert!(message.contains("0001_relay_schema"), "{message}");

    // The transaction carried the schema as well as the row, so neither survived
    // and the next start has a clean run at it.
    let checker = wealdrelay::db::Database::connect(&scratch.url)
        .await
        .unwrap();
    assert!(checker.applied_migrations().await.unwrap().is_empty());
    assert!(!checker
        .tables()
        .await
        .unwrap()
        .contains(&"relay_envelope".to_string()));

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_relay_with_no_storage_still_answers_liveness_and_refuses_readiness() {
    // `RelayState` carries storage as an option, and every reader of it has to say
    // something honest when it is absent. Liveness is still true: the process is
    // running and can answer, and a `/healthz` that failed here would make an
    // orchestrator restart a process with nothing wrong with it. Readiness is not:
    // a relay that cannot store a blob cannot take a durable write, and the startup
    // line has to say `none` rather than name a backend that is not there.
    let scratch = Scratch::new("nostore").await;
    let blobs = tempfile::tempdir().unwrap();
    let prepared = serve::prepare(config_for(&scratch, blobs.path()))
        .await
        .unwrap();
    let state = Arc::new(wealdrelay::health::RelayState::new(
        prepared.config.clone(),
        prepared.database.clone(),
        None,
    ));
    let (public, private) = serve::bind(&state).await.unwrap();
    let public_address = public.local_addr().unwrap();
    let private_address = private.local_addr().unwrap();

    let (stop, wait) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(serve::run(Arc::clone(&state), public, private, async {
        let _ = wait.await;
    }));

    assert_eq!(
        get(&format!("http://{public_address}/healthz")).await.0,
        200
    );
    let (status, body) = get(&format!("http://{private_address}/readyz")).await;
    assert_eq!(status, 503, "{body}");
    let document: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(document["ready"], false);
    assert_eq!(document["storage"]["ok"], false);
    assert_eq!(document["storage"]["detail"], "no storage configured");
    // The database is real and is reported as such, so the operator can see which
    // of the two is the problem.
    assert_eq!(document["database"]["ok"], true);

    let _ = stop.send(());
    served
        .await
        .expect("serving ends when the shutdown future completes");
    scratch.drop_database().await;
}

// MARK: First run

/// What a fresh relay does before it serves anything.
///
/// `specs/backend/relay/server.md`, "Bootstrap": first run migrates the schema and
/// generates a single-use genesis key, then prints the enrollment URL a self-hoster
/// pins. Three states, and the third is the one worth having: a relay whose genesis
/// table it cannot reach still serves, because a workspace enrolled last year does
/// not stop working because a table needed only for enrolment is missing. The
/// alternative would let one unreachable table take down an instance that had no
/// need of it.
#[tokio::test]
async fn first_run_mints_a_genesis_key_and_a_second_start_does_not() {
    let scratch = Scratch::new("bootstrap").await;
    let blobs = tempfile::tempdir().unwrap();
    let config = config_for(&scratch, blobs.path());

    let state = serve::prepare(config.clone()).await.expect("first start");
    let database = state.database.as_ref().expect("a database");
    let workspace = serve::bootstrap_workspace(&config.hostname);
    let minted: i64 =
        sqlx::query_scalar("select count(*) from relay_genesis where workspace_id = $1")
            .bind(&workspace)
            .fetch_one(database.pool())
            .await
            .expect("count");
    assert_eq!(minted, 1, "first run did not mint a genesis key");

    // The invite behind it, which is what the printed link redeems.
    let invites: i64 = sqlx::query_scalar(
        "select count(*) from relay_invite where bootstrap and workspace_id = $1",
    )
    .bind(&workspace)
    .fetch_one(database.pool())
    .await
    .expect("count");
    assert_eq!(invites, 1);

    // A restart mints nothing. A relay that minted a second bootstrap invite every
    // time it was restarted would hand out a fresh admin credential on every deploy.
    serve::bootstrap(database, &config).await;
    let after: i64 =
        sqlx::query_scalar("select count(*) from relay_genesis where workspace_id = $1")
            .bind(&workspace)
            .fetch_one(database.pool())
            .await
            .expect("count");
    assert_eq!(after, 1, "a restart minted a second genesis key");

    // And a relay that cannot reach the table still comes up. Reported, not fatal.
    sqlx::query("alter table relay_genesis rename to weald_parked")
        .execute(database.pool())
        .await
        .expect("park the table");
    serve::bootstrap(database, &config).await;
    sqlx::query("alter table weald_parked rename to relay_genesis")
        .execute(database.pool())
        .await
        .expect("restore the table");

    scratch.drop_database().await;
}

#[tokio::test]
async fn the_bootstrap_workspace_is_derived_from_the_relays_own_hostname() {
    // One relay serves one instance, so its hostname is the identity its genesis key
    // belongs to. Derived rather than configured, which is what makes a restart with
    // the same configuration bootstrap the same workspace rather than a second one.
    assert_eq!(
        serve::bootstrap_workspace("relay.acme.com"),
        "ws:relay.acme.com"
    );
    assert_ne!(
        serve::bootstrap_workspace("relay.acme.com"),
        serve::bootstrap_workspace("relay.other.com")
    );
}

// MARK: The operator surface

/// `GET /admitted`, the count the control plane branches on, over a real socket
/// against a real database.
///
/// `specs/backend/cloud/api.md` requires this route and
/// `weald-cloud/src/provisioner/render-operations.ts` already calls it. It did not
/// exist: the relay served `/healthz` and `/readyz` and nothing else, so every
/// hosted bootstrap availability check and every reprovision decision would have
/// read a 404 against a real relay.
///
/// Four things are asserted together because they are one contract: the route is
/// on the private listener and not the public one, it refuses a request with no
/// bearer and one with the wrong bearer, it answers the right shape with the right
/// one, and the number it reports is the number the store reports.
#[tokio::test]
async fn the_operator_route_answers_the_admitted_count_and_refuses_everyone_else() {
    let scratch = Scratch::new("admitted_route").await;
    let blobs = tempfile::tempdir().unwrap();
    let mut config = config_for(&scratch, blobs.path());
    config.operator_token = Some("operator-token-value-0123456789".to_string());
    let state = Arc::new(serve::prepare(config).await.unwrap());
    let (public, private) = serve::bind(&state).await.unwrap();
    let public_address = public.local_addr().unwrap();
    let private_address = private.local_addr().unwrap();

    let (stop, wait) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(serve::run(Arc::clone(&state), public, private, async {
        let _ = wait.await;
    }));

    // Not on the public listener. The roster size is not a fact for the internet:
    // `server.md` keeps the public listener to liveness and nothing else.
    let (status, _) = get(&format!("http://{public_address}/admitted")).await;
    assert_eq!(status, 404, "the public listener served the admitted count");

    // Provider-private is a network boundary, not an authentication boundary.
    let (status, _) = get(&format!("http://{private_address}/admitted")).await;
    assert_eq!(status, 401, "an unauthenticated caller read the count");
    let (status, _) = get_with_bearer(
        &format!("http://{private_address}/admitted"),
        "operator-token-value-0123456780",
    )
    .await;
    assert_eq!(
        status, 401,
        "a wrong token of the right length was accepted"
    );

    // The real answer, and it is zero: nothing has been admitted.
    let (status, body) = get_with_bearer(
        &format!("http://{private_address}/admitted"),
        "operator-token-value-0123456789",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let document: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(document["admitted"], 0);
    // A count, and nothing else about the roster (`api.md`).
    assert_eq!(
        document.as_object().map(|fields| fields.len()),
        Some(1),
        "the admitted document carried more than the count: {body}"
    );

    let _ = stop.send(());
    let _ = served.await;
    scratch.drop_database().await;
}

/// Without a token the route is absent, which is the self-host shape.
///
/// A self-hoster has no control plane and nothing that would ever call this, so
/// 404 is the honest answer. Mounting it always and refusing always would leave a
/// surface to reason about that nobody in that deployment can use, and a variable
/// name misread in the hosted one would then leave it mounted and open rather than
/// absent and loud.
#[tokio::test]
async fn a_relay_with_no_operator_token_does_not_serve_the_route_at_all() {
    let scratch = Scratch::new("admitted_selfhost").await;
    let blobs = tempfile::tempdir().unwrap();
    let config = config_for(&scratch, blobs.path());
    assert!(config.operator_token.is_none(), "the default is no token");
    let state = Arc::new(serve::prepare(config).await.unwrap());
    let (public, private) = serve::bind(&state).await.unwrap();
    let private_address = private.local_addr().unwrap();

    let (stop, wait) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(serve::run(Arc::clone(&state), public, private, async {
        let _ = wait.await;
    }));

    let (status, _) = get(&format!("http://{private_address}/admitted")).await;
    assert_eq!(status, 404, "an unauthenticable route was mounted anyway");
    // Readiness is unaffected: it is not an operator route.
    let (status, _) = get(&format!("http://{private_address}/readyz")).await;
    assert_eq!(status, 200);

    let _ = stop.send(());
    let _ = served.await;
    scratch.drop_database().await;
}
