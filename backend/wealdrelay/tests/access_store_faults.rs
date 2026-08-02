// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! What the access store answers when the database cannot answer it.
//!
//! `tests/access_store.rs` proves the store right when Postgres works. This file
//! proves it right when Postgres does not, which is the half with the security
//! content: every query behind the access check has a failure path, and the only
//! correct answer on that path is `StoreError::Database`. A relay that could not
//! look must say "come back". It must never guess, never answer `Refused` (which
//! would evict a member the relay simply failed to read), never answer `Admitted`
//! (which would admit a stranger the relay simply failed to look up), never report a
//! publication as accepted when a row of it did not land, and never panic.
//!
//! Nothing here is a mock or a test double. The trust boundary has none, and one
//! here would be a proof about a fake. Every fault is a real state of a real
//! Postgres in a database of this test's own: a dropped table, a dropped column, a
//! trigger that swallows or refuses a write, a deferred constraint that fires at
//! commit, a nulled column, a shadowed built-in. Faults are injected one query at a
//! time, because a function whose first query fails never reaches its second, and
//! "the store handles database errors" proven on the first query is nothing said
//! about the fourth.
//!
//! The injection helpers live here rather than in `tests/support` because no other
//! suite injects faults: they are this file's vocabulary, not shared harness.

mod support;

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer as _, SigningKey};
use sqlx::PgPool;
use wealdrelay::access::store::{self, StoreError};
use wealdrelay::access::{AccessSet, QuorumSignature, RecoveryQuorum};
use wealdrelay::health::{Clock, RelayState};

use support::{config_for, Running, Scratch};

const WORKSPACE: &str = "ws-access";

// MARK: The same fixtures the working suite uses

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pk(signer: &SigningKey) -> Vec<u8> {
    signer.verifying_key().to_bytes().to_vec()
}

fn sorted(mut items: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    items.sort();
    items.dedup();
    items
}

async fn prepared(label: &str) -> (Scratch, tempfile::TempDir, Arc<RelayState>) {
    let scratch = Scratch::new(label).await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(1)).await;
    let state = Arc::clone(&relay.state);
    relay.shutdown().await;
    (scratch, blobs, state)
}

fn pool_of(state: &Arc<RelayState>) -> &PgPool {
    state.database.as_ref().expect("a database").pool()
}

fn build(
    salt: &[u8],
    version: u64,
    prev_hash: Vec<u8>,
    members: &[&SigningKey],
    authorizers: &[&SigningKey],
    recovery: &[&SigningKey],
) -> AccessSet {
    let hash = |signer: &SigningKey| wealdrelay::access::entry_hash(&pk(signer), salt);
    let mut entries: Vec<Vec<u8>> = members.iter().map(|k| hash(k)).collect();
    entries.extend(authorizers.iter().map(|k| hash(k)));
    entries.extend(recovery.iter().map(|k| hash(k)));
    AccessSet {
        workspace: vec![0x77; 32],
        version,
        prev_hash,
        issued_at: 1,
        entries: sorted(entries),
        authorizers: sorted(authorizers.iter().map(|k| pk(k)).collect()),
        recovery: sorted(recovery.iter().map(|k| pk(k)).collect()),
        quorum: None,
        pending: Vec::new(),
        signer: vec![0u8; 32],
        sig: vec![0u8; 64],
    }
}

fn sign(mut set: AccessSet, signer: &SigningKey) -> AccessSet {
    set.signer = pk(signer);
    set.sig = signer.sign(&set.digest_input()).to_bytes().to_vec();
    set
}

async fn publish(pool: &PgPool, set: &AccessSet) -> Result<store::Accepted, StoreError> {
    store::publish(pool, WORKSPACE, set, &set.encode()).await
}

/// The genesis most of these tests start from: one member, one authorizer, one
/// recovery principal.
fn genesis_over(salt: &[u8]) -> AccessSet {
    sign(
        build(
            salt,
            0,
            vec![0u8; 32],
            &[&key(5)],
            &[&key(1)],
            &[&key(0x3f)],
        ),
        &key(1),
    )
}

// MARK: Injecting faults

/// Run one statement of injected database state, and insist that it landed.
///
/// An injection that silently failed would leave a test that proves the happy path
/// twice, which is worse than no test: it would report the fault path as covered.
async fn inject(pool: &PgPool, statement: &str) {
    if let Err(error) = sqlx::query(statement).execute(pool).await {
        panic!("the injected database state must land: {statement}: {error}");
    }
}

/// A trigger function that refuses whatever write it is attached to.
async fn refusing_function(pool: &PgPool) {
    inject(
        pool,
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected: this write cannot land'; end $$",
    )
    .await;
}

/// Refuse one statement class against one table, leaving reads of it alone.
///
/// Statement level rather than row level, because an `update` that matches no row
/// fires no row trigger and the store has updates that legitimately match none.
async fn refuse_statements(pool: &PgPool, table: &str, event: &str) {
    refusing_function(pool).await;
    inject(
        pool,
        &format!(
            "create trigger weald_injected_{event} before {event} on {table} \
             for each statement execute function weald_injected_refusal()"
        ),
    )
    .await;
}

async fn stop_refusing(pool: &PgPool, table: &str, event: &str) {
    inject(
        pool,
        &format!("drop trigger weald_injected_{event} on {table}"),
    )
    .await;
}

/// A group this relay knows, so `workspace_of` resolves and the callers that take
/// groups rather than a workspace can be reached at all.
async fn seed_group(pool: &PgPool, byte: u8) -> Vec<u8> {
    let group = vec![byte; 32];
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, $2)")
        .bind(&group)
        .bind(WORKSPACE)
        .execute(pool)
        .await
        .expect("a group row");
    group
}

/// The one correct answer on every fault path.
///
/// Named as a claim rather than a matcher: the store may not answer a verdict it
/// could not read, and the difference between `Database` and any verdict is the
/// difference between "come back" and a guess about membership.
#[track_caller]
fn is_told_to_come_back<T: std::fmt::Debug>(outcome: Result<T, StoreError>, what: &str) {
    match outcome {
        Err(StoreError::Database(_)) => {}
        other => panic!(
            "{what}: a relay that could not look must answer come back, and answered {other:?}"
        ),
    }
}

// MARK: The salt

#[tokio::test]
async fn a_relay_that_cannot_read_the_workspace_table_tells_every_caller_to_come_back() {
    // The salt is the first read of every access question, because an entry hash
    // cannot be computed without it. So a workspace table the relay cannot reach is
    // the one fault that reaches every entry point, and every one of them has to
    // answer the same way.
    let (scratch, _blobs, state) = prepared("no_workspace_table").await;
    let pool = pool_of(&state);
    let group = seed_group(pool, 0x01).await;
    let stranger = pk(&key(9));
    let candidate = genesis_over(&[0u8; 32]);

    inject(pool, "drop table relay_workspace cascade").await;

    is_told_to_come_back(store::salt(pool, WORKSPACE).await, "salt");
    is_told_to_come_back(store::current(pool, WORKSPACE).await, "current");
    is_told_to_come_back(store::admits(pool, WORKSPACE, &stranger).await, "admits");
    is_told_to_come_back(
        store::admission(pool, std::slice::from_ref(&group), &stranger).await,
        "admission",
    );
    is_told_to_come_back(
        store::state_for(pool, std::slice::from_ref(&group)).await,
        "state_for",
    );
    is_told_to_come_back(publish(pool, &candidate).await, "publish");
    is_told_to_come_back(
        store::publish_for(pool, &[group], &candidate, &candidate.encode()).await,
        "publish_for",
    );
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_workspace_row_that_does_not_land_is_not_answered_with_an_invented_salt() {
    // The salt insert is `on conflict do nothing` plus a re-read rather than a
    // check-then-insert, so that two connections publishing a genesis set at the same
    // moment agree about the salt. This is the state where that re-read finds
    // nothing: a trigger swallows the row, the insert reports success, and the select
    // that follows has no row to return. The relay must not fall back to the value it
    // generated in memory, because a salt nobody stored is a salt that changes on the
    // next call and an entry hash chain that can never be recomputed.
    let (scratch, _blobs, state) = prepared("swallowed_workspace").await;
    let pool = pool_of(&state);
    inject(
        pool,
        "create or replace function weald_injected_swallow() returns trigger \
         language plpgsql as $$ begin return null; end $$",
    )
    .await;
    inject(
        pool,
        "create trigger weald_injected_swallow before insert on relay_workspace \
         for each row execute function weald_injected_swallow()",
    )
    .await;

    is_told_to_come_back(store::salt(pool, WORKSPACE).await, "salt");
    // Counted for this workspace rather than for the table. A relay bootstraps its
    // own workspace at startup now (`serve::bootstrap`), so the table is not empty on
    // a database a relay has been started against, and a count over all of it would
    // be measuring that instead of this.
    let rows: i64 =
        sqlx::query_scalar("select count(*) from relay_workspace where workspace_id = $1")
            .bind(WORKSPACE)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        rows, 0,
        "the swallowing trigger must have swallowed the row"
    );
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_workspace_row_with_no_salt_is_a_fault_rather_than_an_empty_salt() {
    // A salt that decoded as nothing would hash every device key to the same entry,
    // which is the one failure that turns the access set into a set that admits
    // anybody. So a column the relay cannot read as 32 bytes is a fault and not a
    // value.
    let (scratch, _blobs, state) = prepared("null_salt").await;
    let pool = pool_of(&state);
    inject(
        pool,
        "alter table relay_workspace alter column salt drop not null",
    )
    .await;
    sqlx::query("insert into relay_workspace (workspace_id, salt) values ($1, null)")
        .bind(WORKSPACE)
        .execute(pool)
        .await
        .expect("a workspace row with no salt");

    is_told_to_come_back(store::salt(pool, WORKSPACE).await, "salt");
    is_told_to_come_back(store::current(pool, WORKSPACE).await, "current");
    scratch.drop_database().await;
}

// MARK: The prior state, one query at a time

#[tokio::test]
async fn a_relay_blind_to_any_one_table_behind_the_prior_set_refuses_to_judge() {
    // Five queries answer "what is the prior state": the head of the chain, its
    // entries, its principals, its quorum, and the open probations. Each is taken
    // away in turn, latest first, so that every one of them is the query that fails
    // while the ones before it succeed. A publication judged against a prior state
    // the relay only partly read would be judged against a set with members missing,
    // which is how a removed device gets readmitted and how a live one gets evicted.
    let (scratch, _blobs, state) = prepared("blind_prior").await;
    let pool = pool_of(&state);
    let group = seed_group(pool, 0x02).await;
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    let stranger = pk(&key(9));
    let mut genesis = genesis_over(&salt);
    genesis.quorum = Some(RecoveryQuorum {
        threshold: 1,
        keys: vec![pk(&key(0x81))],
        sigs: vec![QuorumSignature {
            key: pk(&key(0x81)),
            sig: vec![0u8; 64],
        }],
    });
    let genesis = sign(genesis, &key(1));
    publish(pool, &genesis).await.unwrap();
    // The whole prior state reads back before anything is taken away, so each
    // refusal below is the injected query and not a set that was never there.
    assert!(store::current(pool, WORKSPACE)
        .await
        .unwrap()
        .prior
        .is_some());

    inject(pool, "drop table relay_access_probation cascade").await;
    is_told_to_come_back(store::current(pool, WORKSPACE).await, "no probation table");

    inject(pool, "drop table relay_access_quorum cascade").await;
    is_told_to_come_back(store::current(pool, WORKSPACE).await, "no quorum table");

    inject(pool, "drop table relay_access_principal cascade").await;
    is_told_to_come_back(store::current(pool, WORKSPACE).await, "no principal table");
    // The same missing table reached through the two callers that read the prior set
    // for themselves. `admission` reads it only after the admission checks have said
    // no, to tell "this workspace has no set yet" from "your key is not in it"; a
    // relay that could not tell them apart must not pick one.
    is_told_to_come_back(
        store::admission(pool, std::slice::from_ref(&group), &stranger).await,
        "admission with no principal table",
    );
    is_told_to_come_back(
        store::state_for(pool, std::slice::from_ref(&group)).await,
        "state_for with no principal table",
    );

    inject(pool, "drop table relay_access_entry cascade").await;
    is_told_to_come_back(store::current(pool, WORKSPACE).await, "no entry table");
    is_told_to_come_back(
        store::admits(pool, WORKSPACE, &stranger).await,
        "admits with no entry table",
    );
    is_told_to_come_back(
        store::admission(pool, std::slice::from_ref(&group), &stranger).await,
        "admission with no entry table",
    );

    inject(pool, "drop table relay_access_set cascade").await;
    is_told_to_come_back(store::current(pool, WORKSPACE).await, "no chain table");
    is_told_to_come_back(publish(pool, &genesis).await, "publish with no chain table");
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_chain_row_with_a_null_where_a_value_belongs_is_a_fault_and_not_a_prior_set() {
    // The columns behind the prior state are `not null` in the schema, and the reader
    // has no branch for a null because no row can carry one. That is the right shape
    // only if the reader refuses the row it cannot read rather than defaulting it: a
    // version read as zero would rewind the chain, an entry read as empty would drop
    // a member, and a role read as nothing would silently file an authorizer as a
    // quorum key. This is that schema half-dismantled, one column at a time.
    let (scratch, _blobs, state) = prepared("null_chain").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    assert_eq!(salt.len(), 32);

    for statement in [
        "alter table relay_access_set drop constraint relay_access_set_pkey cascade",
        "alter table relay_access_set alter column version drop not null",
        "alter table relay_access_set alter column digest drop not null",
        "alter table relay_access_entry drop constraint relay_access_entry_pkey",
        "alter table relay_access_entry alter column entry_hash drop not null",
        "alter table relay_access_principal drop constraint relay_access_principal_pkey",
        "alter table relay_access_principal alter column role drop not null",
        "alter table relay_access_principal alter column pubkey drop not null",
        "alter table relay_access_quorum drop constraint relay_access_quorum_pkey",
        "alter table relay_access_quorum alter column threshold drop not null",
    ] {
        inject(pool, statement).await;
    }

    // A head the reader can read, so the nulls below are reached one at a time.
    inject(
        pool,
        "insert into relay_access_set \
         (workspace_id, version, digest, prev_hash, issued_at, signer, signed_as, body) \
         values ('ws-access', 7, repeat('a', 32)::bytea, repeat('b', 32)::bytea, 1, \
                 repeat('c', 32)::bytea, 'authorizer', ''::bytea)",
    )
    .await;
    assert!(store::current(pool, WORKSPACE)
        .await
        .unwrap()
        .prior
        .is_some());

    inject(
        pool,
        "insert into relay_access_entry (workspace_id, version, entry_hash) \
         values ('ws-access', 7, null)",
    )
    .await;
    is_told_to_come_back(store::current(pool, WORKSPACE).await, "a null entry hash");
    inject(pool, "delete from relay_access_entry").await;

    inject(
        pool,
        "insert into relay_access_principal (workspace_id, version, role, pubkey) \
         values ('ws-access', 7, null, repeat('d', 32)::bytea)",
    )
    .await;
    is_told_to_come_back(store::current(pool, WORKSPACE).await, "a null role");
    inject(pool, "delete from relay_access_principal").await;

    inject(
        pool,
        "insert into relay_access_principal (workspace_id, version, role, pubkey) \
         values ('ws-access', 7, 'authorizer', null)",
    )
    .await;
    is_told_to_come_back(store::current(pool, WORKSPACE).await, "a null pubkey");
    inject(pool, "delete from relay_access_principal").await;

    inject(
        pool,
        "insert into relay_access_quorum (workspace_id, version, threshold) \
         values ('ws-access', 7, null)",
    )
    .await;
    is_told_to_come_back(store::current(pool, WORKSPACE).await, "a null threshold");
    inject(pool, "delete from relay_access_quorum").await;

    // The head row's own two columns, last, because a head the reader refuses hides
    // every query after it. A higher version first, then a null version: the head is
    // read `order by version desc`, and a null sorts ahead of every number there.
    inject(
        pool,
        "insert into relay_access_set \
         (workspace_id, version, digest, prev_hash, issued_at, signer, signed_as, body) \
         values ('ws-access', 8, null, repeat('b', 32)::bytea, 1, \
                 repeat('c', 32)::bytea, 'authorizer', ''::bytea)",
    )
    .await;
    is_told_to_come_back(store::current(pool, WORKSPACE).await, "a null digest");

    inject(
        pool,
        "insert into relay_access_set \
         (workspace_id, version, digest, prev_hash, issued_at, signer, signed_as, body) \
         values ('ws-access', null, repeat('e', 32)::bytea, repeat('b', 32)::bytea, 1, \
                 repeat('c', 32)::bytea, 'authorizer', ''::bytea)",
    )
    .await;
    is_told_to_come_back(store::current(pool, WORKSPACE).await, "a null version");
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_probation_row_with_a_null_where_a_value_belongs_is_a_fault_and_not_a_probation() {
    // A probation is a licence to remove named entries. Read as a row with a missing
    // device, a missing version or a missing pinned list, it would be a licence with
    // no holder or a licence with no bound, and the safe reading of a row the relay
    // cannot read is not a narrower licence: it is no answer at all.
    let (scratch, _blobs, state) = prepared("null_probation").await;
    let pool = pool_of(&state);
    store::salt(pool, WORKSPACE).await.unwrap();
    for statement in [
        "alter table relay_access_probation drop constraint relay_access_probation_pkey",
        "alter table relay_access_probation alter column device drop not null",
        "alter table relay_access_probation alter column introduced_at drop not null",
        "alter table relay_access_probation alter column pending drop not null",
    ] {
        inject(pool, statement).await;
    }

    for (column, values) in [
        (
            "introduced_at",
            "repeat('d', 32)::bytea, null, '{}'::bytea[]",
        ),
        ("device", "null, 1, '{}'::bytea[]"),
        ("pending", "repeat('d', 32)::bytea, 1, null"),
    ] {
        inject(
            pool,
            &format!(
                "insert into relay_access_probation (workspace_id, device, introduced_at, pending) \
                 values ('ws-access', {values})"
            ),
        )
        .await;
        is_told_to_come_back(
            store::current(pool, WORKSPACE).await,
            &format!("a probation with a null {column}"),
        );
        inject(pool, "delete from relay_access_probation").await;
    }
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_group_row_with_no_workspace_is_a_fault_and_not_an_unknown_group() {
    // `UnknownGroup` is a verdict: it tells the caller this relay serves no workspace
    // for the group the connection named. A row that exists but cannot be read is not
    // that, and answering `UnknownGroup` would close a member's socket over a column
    // the relay failed to decode.
    let (scratch, _blobs, state) = prepared("null_group_workspace").await;
    let pool = pool_of(&state);
    inject(
        pool,
        "alter table relay_group alter column workspace_id drop not null",
    )
    .await;
    let group = vec![0x03; 32];
    sqlx::query("insert into relay_group (group_id, workspace_id) values ($1, null)")
        .bind(&group)
        .execute(pool)
        .await
        .expect("a group row with no workspace");

    is_told_to_come_back(store::workspace_of(pool, &group).await, "workspace_of");
    is_told_to_come_back(
        store::admission(pool, std::slice::from_ref(&group), &pk(&key(9))).await,
        "admission",
    );
    is_told_to_come_back(store::state_for(pool, &[group]).await, "state_for");
    scratch.drop_database().await;
}

// MARK: The rate limit

#[tokio::test]
async fn a_relay_that_cannot_read_the_rotation_log_refuses_the_rotation_rather_than_allowing_it() {
    // The window is the whole of the rate limit: at most one recovery rotation per
    // principal per 24 hours. A relay that could not read the log has no way to know
    // whether this is the first rotation or the fiftieth, and the answer that fails
    // safe is to refuse the publication, not to assume the log was empty.
    let (scratch, _blobs, state) = prepared("blind_rotation_log").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    let genesis = genesis_over(&salt);
    publish(pool, &genesis).await.unwrap();
    let rotation = sign(
        build(
            &salt,
            1,
            genesis.digest().to_vec(),
            &[&key(5)],
            &[&key(1), &key(7)],
            &[&key(0x4f)],
        ),
        &key(0x3f),
    );

    inject(pool, "drop table relay_recovery_rotation cascade").await;
    is_told_to_come_back(
        store::rotated_recently(pool, WORKSPACE, &pk(&key(0x3f))).await,
        "rotated_recently",
    );
    is_told_to_come_back(publish(pool, &rotation).await, "a rotation");
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_rotation_count_the_relay_cannot_read_as_a_number_is_a_fault_and_not_a_zero() {
    // The same window, failing the other way: the query runs and answers with
    // something the relay cannot read as a count. Injected by shadowing `count` in a
    // search path that names `pg_catalog` last, which is a real and famously
    // destructive operator setting rather than a stub of one. Zero would be the
    // dangerous default here, because zero means "has not rotated" and would hand a
    // recovery principal an unlimited supply of rotations.
    let scratch = Scratch::new("shadowed_count").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(1)).await;
    let migrated = Arc::clone(&relay.state);
    let pool = pool_of(&migrated);
    inject(pool, "create schema weald_injected").await;
    inject(
        pool,
        "create function weald_injected.not_a_number(text) returns text \
         language sql immutable as $$ select 'not a number' $$",
    )
    .await;
    inject(
        pool,
        "create aggregate weald_injected.count(*) \
         (sfunc = weald_injected.not_a_number, stype = text, initcond = 'x')",
    )
    .await;
    inject(
        pool,
        &format!(
            "alter database {} set search_path = weald_injected, public, pg_catalog",
            scratch.name
        ),
    )
    .await;
    relay.shutdown().await;

    // A pool opened after the setting, so its connections carry it. The database is
    // the migrated one above; only the search path is new.
    let shadowed = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&scratch.url)
        .await
        .expect("a pool against the shadowed search path");
    // The shadow has to be the fault the store actually meets. If the query failed
    // instead, this test would prove the query path a second time and say nothing
    // about the read of the answer, so the injected state is checked first: the
    // count runs, and it answers with a type no count can be read from.
    let answered: String =
        sqlx::query_scalar("select pg_typeof(count(*))::text from relay_recovery_rotation")
            .fetch_one(&shadowed)
            .await
            .expect("the shadowed count still runs");
    assert_eq!(answered, "text", "the shadowed count is not in the path");
    is_told_to_come_back(
        store::rotated_recently(&shadowed, WORKSPACE, &pk(&key(0x3f))).await,
        "rotated_recently",
    );
    shadowed.close().await;
    scratch.drop_database().await;
}

// MARK: The publication transaction

#[tokio::test]
async fn a_publication_that_cannot_write_any_one_of_its_rows_is_refused_whole() {
    // The publication is one transaction and six kinds of row: the chain entry, the
    // salted entries, the authorizers and recovery keys, the quorum's keys, and the
    // quorum's threshold. Each write is broken in turn, latest first, so each is the
    // one that fails after the earlier ones have already succeeded inside the
    // transaction. The answer must be `Database` and the transaction must leave
    // nothing: a set reported as accepted whose entries did not land is a set that
    // admits nobody, and one whose principals did not land is a set nobody can
    // rotate ever again.
    let (scratch, _blobs, state) = prepared("half_written").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    let mut with_quorum = genesis_over(&salt);
    with_quorum.quorum = Some(RecoveryQuorum {
        threshold: 1,
        keys: vec![pk(&key(0x81))],
        sigs: vec![QuorumSignature {
            key: pk(&key(0x81)),
            sig: vec![0u8; 64],
        }],
    });
    let with_quorum = sign(with_quorum, &key(1));
    let plain = genesis_over(&salt);

    // The threshold row, last of the six.
    inject(pool, "drop table relay_access_quorum cascade").await;
    is_told_to_come_back(publish(pool, &with_quorum).await, "no quorum table");
    assert_nothing_was_published(pool).await;

    // The quorum's keys, which share a table and a statement with the authorizers:
    // separated by a constraint that admits the two roles and refuses the third, so
    // the authorizer rows land and the quorum row does not.
    inject(
        pool,
        "alter table relay_access_principal \
         drop constraint relay_access_principal_role_known",
    )
    .await;
    inject(
        pool,
        "alter table relay_access_principal add constraint relay_access_principal_role_known \
         check (role in ('authorizer', 'recovery'))",
    )
    .await;
    is_told_to_come_back(publish(pool, &with_quorum).await, "no quorum principals");
    assert_nothing_was_published(pool).await;

    inject(pool, "drop table relay_access_principal cascade").await;
    is_told_to_come_back(publish(pool, &plain).await, "no principal table");
    assert_nothing_was_published(pool).await;

    inject(pool, "drop table relay_access_entry cascade").await;
    is_told_to_come_back(publish(pool, &plain).await, "no entry table");

    // The chain row itself. A dropped column rather than a dropped table, because the
    // read that judges the publication needs the table to still be there.
    inject(pool, "alter table relay_access_set drop column body").await;
    is_told_to_come_back(publish(pool, &plain).await, "no body column");
    scratch.drop_database().await;
}

/// Nothing of a refused publication survives. Read from the chain table directly
/// rather than through the store, because the store is the thing under test.
async fn assert_nothing_was_published(pool: &PgPool) {
    let rows: i64 = sqlx::query_scalar("select count(*) from relay_access_set")
        .fetch_one(pool)
        .await
        .expect("the chain table reads");
    assert_eq!(rows, 0, "a refused publication left a version behind");
}

#[tokio::test]
async fn a_rotation_whose_rate_limit_or_probation_cannot_be_recorded_is_refused_whole() {
    // Two writes only a recovery rotation makes: the row that spends the 24 hour
    // window, and the probation that bounds what the replacement device may remove
    // until somebody confirms it. Neither may be skipped. A rotation accepted
    // without its window row is an unlimited rotation, and one accepted without its
    // probation row is an unconfirmed device with an authorizer's full powers.
    let (scratch, _blobs, state) = prepared("unrecorded_rotation").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    let genesis = genesis_over(&salt);
    publish(pool, &genesis).await.unwrap();
    let rotation = sign(
        build(
            &salt,
            1,
            genesis.digest().to_vec(),
            &[&key(5)],
            &[&key(1), &key(7)],
            &[&key(0x4f)],
        ),
        &key(0x3f),
    );

    refuse_statements(pool, "relay_recovery_rotation", "insert").await;
    is_told_to_come_back(publish(pool, &rotation).await, "an unrecordable window");
    stop_refusing(pool, "relay_recovery_rotation", "insert").await;

    refuse_statements(pool, "relay_access_probation", "insert").await;
    is_told_to_come_back(publish(pool, &rotation).await, "an unrecordable probation");
    stop_refusing(pool, "relay_access_probation", "insert").await;

    // Neither attempt left a version, a window row or a probation behind, and the
    // rotation still holds once the database will take it.
    let versions: i64 = sqlx::query_scalar("select count(*) from relay_access_set")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(versions, 1, "a refused rotation left a version behind");
    let windows: i64 = sqlx::query_scalar("select count(*) from relay_recovery_rotation")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(windows, 0, "a refused rotation spent the window anyway");
    assert!(publish(pool, &rotation)
        .await
        .unwrap()
        .opened_probation
        .is_some());
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_confirmation_that_cannot_clear_the_probation_it_confirms_is_refused_whole() {
    // Clearing is the point of the confirmation. A confirmation reported as accepted
    // whose clearing update did not land would leave the replacement device on
    // probation forever, with the set that was meant to free it already published and
    // unrepeatable.
    let (scratch, _blobs, state) = prepared("uncleared_probation").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    let genesis = genesis_over(&salt);
    publish(pool, &genesis).await.unwrap();
    let rotation = sign(
        build(
            &salt,
            1,
            genesis.digest().to_vec(),
            &[&key(5)],
            &[&key(1), &key(7)],
            &[&key(0x4f)],
        ),
        &key(0x3f),
    );
    publish(pool, &rotation).await.unwrap();
    let confirm = sign(
        build(
            &salt,
            2,
            rotation.digest().to_vec(),
            &[&key(5)],
            &[&key(1), &key(7)],
            &[&key(0x4f)],
        ),
        &key(1),
    );

    refuse_statements(pool, "relay_access_probation", "update").await;
    is_told_to_come_back(publish(pool, &confirm).await, "an unclearable probation");
    stop_refusing(pool, "relay_access_probation", "update").await;

    // The probation is still open and the confirmation is still publishable, which is
    // the whole claim: the transaction rolled back rather than half applying.
    assert_eq!(
        store::current(pool, WORKSPACE)
            .await
            .unwrap()
            .probations
            .len(),
        1
    );
    assert_eq!(
        publish(pool, &confirm).await.unwrap().cleared_probation,
        vec![pk(&key(7))]
    );
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_publication_that_cannot_settle_the_provisional_grants_is_refused_whole() {
    // Both halves of the implicit-void rule are writes inside the publication: the
    // mark that says an accepted set carried this joiner's hash, and the void that
    // says a later set dropped it. A publication accepted without the mark would void
    // a joiner's grant on the next publication for something it never did. One
    // accepted without the void would leave a removed principal connecting under a
    // grant that should have died with them, which is the offboarding hole the whole
    // access set exists to close.
    let (scratch, _blobs, state) = prepared("unsettled_grants").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    let genesis = genesis_over(&salt);

    refuse_statements(pool, "relay_provisional_grant", "update").await;
    is_told_to_come_back(publish(pool, &genesis).await, "an unmarkable grant");
    stop_refusing(pool, "relay_provisional_grant", "update").await;
    assert_nothing_was_published(pool).await;

    // The second update, reached only once the first has run: a grant this set does
    // not carry, already marked as seen by an earlier one, is the row the void
    // statement matches. A row trigger on that statement alone, because the first
    // update matches nothing here and a row trigger never fires on a statement that
    // matched no row.
    let departed = wealdrelay::access::entry_hash(&pk(&key(9)), &salt);
    store::grant(pool, WORKSPACE, &departed, 4_000_000_000_000)
        .await
        .unwrap();
    inject(
        pool,
        "update relay_provisional_grant set seen_version = 0 where seen_version is null",
    )
    .await;
    refusing_function(pool).await;
    inject(
        pool,
        "create trigger weald_injected_void before update on relay_provisional_grant \
         for each row when (new.voided_reason = 'superseded') \
         execute function weald_injected_refusal()",
    )
    .await;
    is_told_to_come_back(publish(pool, &genesis).await, "an unvoidable grant");
    assert_nothing_was_published(pool).await;
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_publication_that_cannot_commit_is_refused_rather_than_reported_as_accepted() {
    // Every statement succeeds and the commit does not, which is what a deferred
    // constraint does and what a database at the end of its disk does. The version
    // number and digest the caller would have echoed to the publisher, and the
    // sockets the caller would have closed on the strength of it, all hang on this
    // being an error rather than an `Accepted`.
    let (scratch, _blobs, state) = prepared("failed_commit").await;
    let pool = pool_of(&state);
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    let genesis = genesis_over(&salt);

    refusing_function(pool).await;
    inject(
        pool,
        "create constraint trigger weald_injected_commit after insert on relay_access_set \
         deferrable initially deferred for each row execute function weald_injected_refusal()",
    )
    .await;
    is_told_to_come_back(publish(pool, &genesis).await, "a commit that fails");
    inject(
        pool,
        "drop trigger weald_injected_commit on relay_access_set",
    )
    .await;
    assert_nothing_was_published(pool).await;
    assert!(store::current(pool, WORKSPACE)
        .await
        .unwrap()
        .prior
        .is_none());
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_publication_that_cannot_open_a_transaction_at_all_is_refused_before_it_writes() {
    // The judging reads succeed and the transaction cannot be opened, which is what a
    // relay shutting down looks like from inside a publication that arrived a moment
    // too early. Arranged by closing the pool while the last of those reads is still
    // in flight: a set-returning function behind the probation table makes that read
    // slow enough to be a place rather than an instant, so the close lands after the
    // last read and before the first write.
    let (scratch, _blobs, state) = prepared("no_transaction").await;
    let pool = pool_of(&state).clone();
    let salt = store::salt(&pool, WORKSPACE).await.unwrap();
    let genesis = genesis_over(&salt);
    inject(
        &pool,
        "alter table relay_access_probation rename to relay_access_probation_rows",
    )
    .await;
    inject(
        &pool,
        "create function weald_injected_slow_probations() \
         returns setof relay_access_probation_rows language plpgsql as $$ \
         begin perform pg_sleep(2); return query select * from relay_access_probation_rows; end $$",
    )
    .await;
    inject(
        &pool,
        "create view relay_access_probation as select * from weald_injected_slow_probations()",
    )
    .await;

    let closing = {
        let pool = pool.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            pool.close().await;
        })
    };
    is_told_to_come_back(publish(&pool, &genesis).await, "a pool that closed");
    closing.await.unwrap();
    scratch.drop_database().await;
}

// MARK: What AUTH asks

#[tokio::test]
async fn a_relay_that_cannot_read_the_provisional_grants_does_not_answer_refused() {
    // `Refused` is the answer that closes a joiner's socket, and a joiner is admitted
    // by a grant and by nothing else: their hash is in no accepted set yet, by
    // definition. So a grant table the relay cannot read is exactly the state where
    // answering the verdict it has so far, which is `Refused`, would lock out every
    // legitimate joiner in the workspace.
    let (scratch, _blobs, state) = prepared("blind_grants").await;
    let pool = pool_of(&state);
    let group = seed_group(pool, 0x04).await;
    let salt = store::salt(pool, WORKSPACE).await.unwrap();
    publish(pool, &genesis_over(&salt)).await.unwrap();
    let joiner = pk(&key(9));
    let hash = wealdrelay::access::entry_hash(&joiner, &salt);

    inject(pool, "drop table relay_provisional_grant cascade").await;
    is_told_to_come_back(store::admits(pool, WORKSPACE, &joiner).await, "admits");
    is_told_to_come_back(store::admission(pool, &[group], &joiner).await, "admission");
    is_told_to_come_back(
        store::grant(pool, WORKSPACE, &hash, 4_000_000_000_000).await,
        "grant",
    );
    is_told_to_come_back(
        store::revoke_grant(pool, WORKSPACE, &hash).await,
        "revoke_grant",
    );
    scratch.drop_database().await;
}
