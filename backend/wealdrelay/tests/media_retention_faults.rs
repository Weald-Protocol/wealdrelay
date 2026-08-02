// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! What the retention store answers when the database cannot answer it.
//!
//! `tests/media_retention.rs` proves the control chain, the manifest chain and the
//! threshold right when Postgres works. This file proves them right when Postgres
//! does not, and that half carries the deletion risk, because every statement
//! behind a retention decision has a failure path and only one answer on it is
//! safe: `StoreError::Database`.
//!
//! The stakes are the ones `specs/backend/relay/media.md` states rather than
//! generic ones. A manifest reported as accepted whose row did not land is a claim
//! nobody can find later, and the blob it claimed reads as unclaimed. A conflict
//! that could not be recorded, or a freeze that could not be written, is a
//! successor race the relay believes it settled: the removed member's forged branch
//! becomes the group's retention authority and the cleanup job keeps running. A
//! rejection that could not be stored must not be reported as a rejection quietly
//! filed, because `media.md` keeps rejected manifests "as evidence". And a read
//! that failed must never read as an empty chain, an unfrozen group, or no active
//! policy: "I could not find out" treated as "nothing objects" is exactly how a
//! database blip deletes somebody's attachments.
//!
//! Nothing here is a mock. Every fault is a real state of a real Postgres in a
//! database of this test's own: a dropped table, a dropped column, a trigger that
//! refuses a write, a nulled column, a retyped one. Faults are injected one
//! statement at a time, because a function whose first statement fails never
//! reaches its third, and "the store handles database errors" proven on the first
//! statement is nothing said about the fourth.

mod support;

use std::sync::Arc;

use sqlx::PgPool;
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::media::retention::{self, ControlOutcome, StoreError};

use support::{
    blob_hash, config_for, device_from, make_group_in, signed_control, signed_manifest,
    verifier_key, Running, Scratch,
};

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

/// A workspace with one authorizer, and one group inside it.
async fn workspace_with(state: &Arc<RelayState>, workspace: &str, byte: u8) -> Vec<u8> {
    let devices = [device_from(0x71)];
    make_group_in(state, workspace, byte, &devices, &devices).await
}

/// A second pool, opened after an injected schema change.
///
/// Retyping a column invalidates Postgres's cached plan for a statement already
/// prepared on a connection, and the failure then arrives from the query rather
/// than from the decode of its answer. A connection that has never seen the old
/// shape prepares against the new one, which is how a retyped column reaches the
/// reader as the decode failure it is meant to be.
async fn fresh_pool(scratch: &Scratch) -> PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&scratch.url)
        .await
        .expect("a pool against the injected schema")
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
/// fires no row trigger and this store has updates that legitimately match none.
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

/// Always paired with `refuse_statements`. A trigger left installed is not this
/// test's fault any more, it is the next case's, and that is a bug that reads as a
/// pass.
async fn stop_refusing(pool: &PgPool, table: &str, event: &str) {
    inject(
        pool,
        &format!("drop trigger weald_injected_{event} on {table}"),
    )
    .await;
}

/// The one correct answer on every fault path.
///
/// Named as a claim rather than as a matcher: the relay may not answer a verdict
/// it could not read, and the distance between `Database` and any verdict here is
/// the distance between "come back" and a deletion nobody authorized.
#[track_caller]
fn is_told_to_come_back<T>(outcome: Result<T, StoreError>, what: &str) {
    match outcome {
        Err(StoreError::Database(_)) => {}
        Ok(_) => panic!(
            "{what}: a relay that could not read the retention state must answer come back, \
             and answered as though it had read it"
        ),
    }
}

// MARK: The control chain

#[tokio::test]
async fn a_prior_epoch_the_relay_cannot_read_is_never_a_chain_that_authorizes() {
    // Every non-genesis control is authorized by the prior epoch's verifier and by
    // nothing else. A relay that cannot read the prior epoch has no authority to
    // check the new control against, and the two wrong answers are symmetrical:
    // treating the unreadable prior as absent would refuse a legitimate rotation
    // forever, and treating the record as self-authorizing would let anybody who
    // can reach the socket install themselves as the group's retention authority.
    let (scratch, _blobs, state) = prepared("retentionfault_no_prior").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-noprior", 0x61).await;
    let epoch0 = verifier_key(0x21);
    let epoch1 = verifier_key(0x22);
    let rotation = signed_control(&group, 1, &epoch1, Some(blob_hash(9)), &epoch0);

    inject(pool, "drop table relay_retention_control cascade").await;
    is_told_to_come_back(
        retention::apply_control(pool, &rotation).await,
        "a rotation with no readable prior epoch",
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_control_that_cannot_be_written_is_not_reported_as_accepted() {
    // `Accepted` is what tells a client its group has a retention authority for
    // this epoch. Returned over a row that did not land, the next epoch's rotation
    // would find no predecessor and the chain would be broken at a link the client
    // was told was there.
    let (scratch, _blobs, state) = prepared("retentionfault_unwritable").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-unwritable", 0x62).await;
    let epoch0 = verifier_key(0x21);
    let genesis = signed_control(&group, 0, &epoch0, None, &epoch0);

    refuse_statements(pool, "relay_retention_control", "insert").await;
    is_told_to_come_back(
        retention::apply_control(pool, &genesis).await,
        "a control the database will not take",
    );
    stop_refusing(pool, "relay_retention_control", "insert").await;

    let rows: i64 = sqlx::query_scalar("select count(*) from relay_retention_control")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(rows, 0, "a refused control was stored anyway");
    // And the same record still lands once the database will take it, which is what
    // makes the failure a transient refusal rather than a poisoned chain.
    assert_eq!(
        retention::apply_control(pool, &genesis).await.unwrap(),
        ControlOutcome::Accepted
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_successor_race_the_relay_cannot_record_or_freeze_is_never_reported_as_settled() {
    // The negative proof the step 9 gate names, failing at the database rather than
    // at the protocol. A second, differently signed control for a settled epoch
    // "is not rejected and forgotten": it is stored as evidence and it freezes the
    // group. Neither half may be reported as done when it did not happen. A
    // conflict that vanished is a removed member's forged branch with no trace, and
    // a freeze that did not land is a garbage collector that keeps running through
    // a race `media.md` says must stop it.
    let (scratch, _blobs, state) = prepared("retentionfault_race").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-race", 0x63).await;
    let settled = verifier_key(0x21);
    let rival = verifier_key(0x31);
    retention::apply_control(pool, &signed_control(&group, 0, &settled, None, &settled))
        .await
        .unwrap();
    let forged = signed_control(&group, 0, &rival, None, &rival);

    // The evidence row first, because a conflict that cannot be recorded must not
    // go on to freeze: the freeze without the evidence is an alarm with nothing
    // behind it for the member who has to resolve it.
    refuse_statements(pool, "relay_retention_control_conflict", "insert").await;
    is_told_to_come_back(
        retention::apply_control(pool, &forged).await,
        "a conflict the database will not record",
    );
    assert!(
        !retention::is_frozen(pool, &group).await.unwrap(),
        "a conflict that was never recorded froze the group anyway"
    );
    stop_refusing(pool, "relay_retention_control_conflict", "insert").await;

    // The freeze itself. The evidence lands and the freeze cannot, which must not
    // read as `ConflictFroze`.
    refuse_statements(pool, "relay_group", "update").await;
    is_told_to_come_back(
        retention::apply_control(pool, &forged).await,
        "a freeze the database will not write",
    );
    assert!(
        !retention::is_frozen(pool, &group).await.unwrap(),
        "a freeze that was refused is not a freeze"
    );

    // Only a client clears a freeze, and a clear that could not be written must not
    // be reported as one either: the client would stop asking and the group would
    // stay frozen with nobody left to notice.
    is_told_to_come_back(
        retention::clear_freeze(pool, &group).await,
        "a freeze the database will not clear",
    );
    stop_refusing(pool, "relay_group", "update").await;

    // With the database willing, the race settles the way `media.md` requires.
    assert_eq!(
        retention::apply_control(pool, &forged).await.unwrap(),
        ControlOutcome::ConflictFroze
    );
    assert!(retention::is_frozen(pool, &group).await.unwrap());

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_control_row_the_relay_cannot_read_is_not_a_verifier_it_may_use() {
    // The three columns behind a stored control are the whole of the prior epoch's
    // authority: the verifier the next control must be signed by, the predecessor it
    // must name, and the signature the digest is computed over. Every one of them is
    // `not null` in the schema and the reader has no branch for a null, which is the
    // right shape only if a row it cannot read is refused rather than defaulted. A
    // verifier read as empty would verify nothing, and a signature read as empty
    // would change the digest the successor has to name.
    let (scratch, _blobs, state) = prepared("retentionfault_null_control").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-nullctl", 0x64).await;
    let epoch1 = verifier_key(0x22);
    let rotation = signed_control(&group, 1, &epoch1, Some(blob_hash(9)), &verifier_key(0x21));

    for statement in [
        "alter table relay_retention_control \
         drop constraint relay_retention_control_verifier_is_32_bytes",
        "alter table relay_retention_control alter column verifier drop not null",
        "alter table relay_retention_control alter column sig drop not null",
    ] {
        inject(pool, statement).await;
    }

    let seed = |verifier: &str, prev: &str, sig: &str| {
        format!(
            "insert into relay_retention_control \
             (group_id, epoch, verifier, prev_control_hash, sig, signer_note) \
             values (decode(repeat('64', 32), 'hex'), 0, {verifier}, {prev}, {sig}, 'genesis')"
        )
    };
    inject(pool, &seed("null", "null", "decode('00', 'hex')")).await;
    is_told_to_come_back(
        retention::apply_control(pool, &rotation).await,
        "a prior epoch with no verifier",
    );
    inject(pool, "delete from relay_retention_control").await;

    inject(
        pool,
        &seed("decode(repeat('11', 32), 'hex')", "null", "null"),
    )
    .await;
    is_told_to_come_back(
        retention::apply_control(pool, &rotation).await,
        "a prior epoch with no signature",
    );
    inject(pool, "delete from relay_retention_control").await;

    // The predecessor is nullable by design, so a null says "genesis" rather than
    // "unreadable". The unreadable case for this column is a value that is not
    // bytes at all, which is what a schema drifted under a running relay looks
    // like, and it must not read as the genesis it resembles. A value rather than a
    // null on purpose: a null needs no decoding and would prove nothing about the
    // column's type.
    inject(
        pool,
        &seed(
            "decode(repeat('11', 32), 'hex')",
            "decode('aabb', 'hex')",
            "decode('00', 'hex')",
        ),
    )
    .await;
    inject(
        pool,
        "alter table relay_retention_control alter column prev_control_hash type text \
         using encode(prev_control_hash, 'hex')",
    )
    .await;
    let fresh = fresh_pool(&scratch).await;
    is_told_to_come_back(
        retention::apply_control(&fresh, &rotation).await,
        "a prior epoch whose predecessor is not bytes",
    );
    fresh.close().await;

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_freeze_flag_the_relay_cannot_read_is_not_an_unfrozen_group() {
    // `is_frozen` gates every collection decision for a group. False is the
    // dangerous default: it means "carry on deleting", and a group is frozen
    // precisely when the relay has evidence that two parties disagree about who
    // governs its retention.
    let (scratch, _blobs, state) = prepared("retentionfault_frozen_read").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-frozenread", 0x65).await;
    assert!(!retention::is_frozen(pool, &group).await.unwrap());

    // A reason first, then a column that cannot hold one. A null needs no decoding
    // and would read as "not frozen" honestly; the fault is a frozen group whose
    // reason the relay cannot read at all.
    inject(pool, "update relay_group set frozen_reason = 'injected'").await;
    inject(
        pool,
        "alter table relay_group alter column frozen_reason type bigint using 7::bigint",
    )
    .await;
    let fresh = fresh_pool(&scratch).await;
    is_told_to_come_back(
        retention::is_frozen(&fresh, &group).await,
        "a freeze reason that is not a reason",
    );
    fresh.close().await;

    scratch.drop_database().await;
}

// MARK: The manifest chain

#[tokio::test]
async fn a_manifest_whose_rejection_cannot_be_stored_is_never_quietly_dropped() {
    // `media.md` keeps a rejected manifest "as evidence but never uses it for
    // deletion". Every one of the four ways a manifest is refused writes that
    // evidence, and each is reached only once the ones before it have passed: no
    // control for the epoch, a signature that does not verify, a sequence that does
    // not advance by one, and a predecessor that does not match. A relay that
    // answered `Invalid` while its evidence row was refused would be discarding the
    // only record that a member's client is producing manifests nobody can verify.
    let (scratch, _blobs, state) = prepared("retentionfault_rejection").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-reject", 0x66).await;
    let epoch0 = verifier_key(0x21);
    let stranger = verifier_key(0x41);

    refuse_statements(pool, "relay_retention_manifest_rejected", "insert").await;

    // 1. No control for the epoch the manifest names.
    let orphan = signed_manifest(&group, 0, 1, None, vec![blob_hash(1)], &epoch0);
    is_told_to_come_back(
        retention::apply_manifest(pool, "ws-reject", &orphan).await,
        "a manifest with no control for its epoch",
    );

    stop_refusing(pool, "relay_retention_manifest_rejected", "insert").await;
    retention::apply_control(pool, &signed_control(&group, 0, &epoch0, None, &epoch0))
        .await
        .unwrap();
    refuse_statements(pool, "relay_retention_manifest_rejected", "insert").await;

    // 2. A signature that does not verify against the epoch's verifier.
    let forged = signed_manifest(&group, 0, 1, None, vec![blob_hash(1)], &stranger);
    is_told_to_come_back(
        retention::apply_manifest(pool, "ws-reject", &forged).await,
        "a manifest signed by nobody the epoch names",
    );

    // 3. A sequence that does not advance by exactly one.
    let skipped = signed_manifest(&group, 0, 7, None, vec![blob_hash(1)], &epoch0);
    is_told_to_come_back(
        retention::apply_manifest(pool, "ws-reject", &skipped).await,
        "a manifest whose sequence skips",
    );

    // 4. A predecessor that does not match the latest manifest, which needs a
    // latest manifest to disagree with, so the first one is accepted with the
    // rejection trigger lifted.
    stop_refusing(pool, "relay_retention_manifest_rejected", "insert").await;
    let first = signed_manifest(&group, 0, 1, None, vec![blob_hash(1)], &epoch0);
    retention::apply_manifest(pool, "ws-reject", &first)
        .await
        .unwrap();
    refuse_statements(pool, "relay_retention_manifest_rejected", "insert").await;
    let branched = signed_manifest(
        &group,
        0,
        2,
        Some(blob_hash(0xee)),
        vec![blob_hash(1)],
        &epoch0,
    );
    is_told_to_come_back(
        retention::apply_manifest(pool, "ws-reject", &branched).await,
        "a manifest that names a predecessor the chain does not have",
    );
    stop_refusing(pool, "relay_retention_manifest_rejected", "insert").await;

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_manifest_chain_the_relay_cannot_read_is_not_an_empty_chain() {
    // The latest manifest decides both what sequence comes next and what digest the
    // next manifest must name. Read as absent when it is only unreadable, the relay
    // would accept a manifest at sequence 1 that forks the chain from its start,
    // and `gc::eligible` reads the latest manifest to decide omission: a fork is a
    // manifest that omits everything the real chain claims.
    let (scratch, _blobs, state) = prepared("retentionfault_no_chain").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-nochain", 0x67).await;
    let epoch0 = verifier_key(0x21);
    retention::apply_control(pool, &signed_control(&group, 0, &epoch0, None, &epoch0))
        .await
        .unwrap();
    let manifest = signed_manifest(&group, 0, 1, None, vec![blob_hash(1)], &epoch0);

    inject(
        pool,
        "alter table relay_retention_manifest drop column digest",
    )
    .await;
    is_told_to_come_back(
        retention::latest_manifest(pool, &group).await,
        "latest_manifest",
    );
    is_told_to_come_back(
        retention::apply_manifest(pool, "ws-nochain", &manifest).await,
        "a manifest judged against a chain nobody could read",
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_manifest_that_cannot_be_written_is_not_reported_as_an_accepted_claim() {
    // `Accepted` carries the digest the next manifest must name, and accepting a
    // manifest is the one moment a blob's bytes move from reserved to stored. A
    // manifest reported as accepted whose row did not land would hand a client a
    // digest no chain contains, and, worse, would read afterwards as a manifest
    // that omits every hash it named: `gc::eligible`'s omission test is over the
    // latest stored manifest, so a claim that did not land is indistinguishable
    // from a claim that was withdrawn.
    let (scratch, _blobs, state) = prepared("retentionfault_unwritable_manifest").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-nomanifest", 0x68).await;
    let epoch0 = verifier_key(0x21);
    retention::apply_control(pool, &signed_control(&group, 0, &epoch0, None, &epoch0))
        .await
        .unwrap();
    let manifest = signed_manifest(&group, 0, 1, None, vec![blob_hash(1)], &epoch0);

    refuse_statements(pool, "relay_retention_manifest", "insert").await;
    is_told_to_come_back(
        retention::apply_manifest(pool, "ws-nomanifest", &manifest).await,
        "a manifest the database will not take",
    );
    stop_refusing(pool, "relay_retention_manifest", "insert").await;

    assert!(
        retention::latest_manifest(pool, &group)
            .await
            .unwrap()
            .is_none(),
        "a refused manifest became the latest one"
    );
    // Nothing was claimed either, which is the accounting half of the same claim: a
    // manifest that did not land must not have moved a byte.
    let rows: i64 = sqlx::query_scalar(
        "select count(*) from relay_blob_reservation where finalized_at is not null",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(rows, 0, "a refused manifest claimed a blob anyway");

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_manifest_row_the_relay_cannot_read_is_not_the_latest_manifest() {
    // The three columns the chain head is made of. A sequence read as zero would
    // let the next manifest re-use sequence 1, a digest read as empty would let it
    // name an empty predecessor, and a blob list read as empty is the omission that
    // `media.md`'s deletion rule acts on: it would mark every blob in the group as
    // dropped by the latest manifest.
    let (scratch, _blobs, state) = prepared("retentionfault_null_manifest").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-nullmanifest", 0x69).await;

    for statement in [
        "alter table relay_retention_manifest \
         drop constraint relay_retention_manifest_pkey cascade",
        "alter table relay_retention_manifest \
         drop constraint relay_retention_manifest_sequence_positive",
        "alter table relay_retention_manifest alter column sequence drop not null",
        "alter table relay_retention_manifest alter column digest drop not null",
        "alter table relay_retention_manifest alter column blobs drop not null",
    ] {
        inject(pool, statement).await;
    }

    let seed = |sequence: &str, digest: &str, blobs: &str| {
        format!(
            "insert into relay_retention_manifest \
             (group_id, sequence, epoch, prev_manifest_hash, blobs, sig, digest) \
             values (decode(repeat('69', 32), 'hex'), {sequence}, 0, null, {blobs}, \
                     decode('00', 'hex'), {digest})"
        )
    };
    for (what, sequence, digest, blobs) in [
        (
            "no sequence",
            "null",
            "decode('aa', 'hex')",
            "'{}'::bytea[]",
        ),
        ("no digest", "1", "null", "'{}'::bytea[]"),
        ("no blob list", "1", "decode('aa', 'hex')", "null"),
    ] {
        inject(pool, &seed(sequence, digest, blobs)).await;
        is_told_to_come_back(
            retention::latest_manifest(pool, &group).await,
            &format!("a manifest with {what}"),
        );
        inject(pool, "delete from relay_retention_manifest").await;
    }

    scratch.drop_database().await;
}

// MARK: What authorizes a deletion

#[tokio::test]
async fn a_policy_row_the_relay_cannot_read_is_not_an_active_policy() {
    // The active policy is one of the two halves that permit a deletion at all. Its
    // three columns each fail dangerously if defaulted: a version read as zero would
    // let a superseded policy be re-applied, a window read as zero would delete
    // media the moment it was claimed, and a `not_before` read as zero would make
    // every destructive action due immediately, which is the seven-day grace the
    // spec gives a group to cancel one.
    let (scratch, _blobs, state) = prepared("retentionfault_null_policy").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-nullpolicy", 0x6a).await;

    for statement in [
        "alter table relay_retention_policy drop constraint relay_retention_policy_pkey cascade",
        "alter table relay_retention_policy \
         drop constraint relay_retention_policy_version_positive",
        "alter table relay_retention_policy \
         drop constraint relay_retention_policy_media_after_floor",
        "alter table relay_retention_policy alter column version drop not null",
        "alter table relay_retention_policy alter column media_after_days drop not null",
        "alter table relay_retention_policy alter column not_before drop not null",
    ] {
        inject(pool, statement).await;
    }

    let seed = |version: &str, days: &str, not_before: &str| {
        format!(
            "insert into relay_retention_policy \
             (group_id, version, media_after_days, text_after_days, not_before, \
              authorizers, signatures) \
             values (decode(repeat('6a', 32), 'hex'), {version}, {days}, 30, {not_before}, \
                     '{{}}'::bytea[], '[]'::jsonb)"
        )
    };
    for (what, version, days, not_before) in [
        ("no version", "null", "30", "now()"),
        ("no media window", "1", "null", "now()"),
        ("no not_before", "1", "30", "null"),
    ] {
        inject(pool, &seed(version, days, not_before)).await;
        is_told_to_come_back(
            retention::active_policy(pool, &group).await,
            &format!("a policy with {what}"),
        );
        inject(pool, "delete from relay_retention_policy").await;
    }

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_destruction_row_the_relay_cannot_read_is_not_a_destruction_that_is_due() {
    // A destruction record's `not_before` is the whole of its timing, and
    // `media.md` gives every destructive action a seven-day window in which it can
    // still be cancelled. Read as zero, the record would be due the instant it was
    // filed, which turns a cancellable request into an executed one.
    let (scratch, _blobs, state) = prepared("retentionfault_null_destruction").await;
    let pool = pool_of(&state);
    let group = workspace_with(&state, "ws-nulldestruction", 0x6b).await;

    inject(
        pool,
        "alter table relay_retention_destruction alter column not_before drop not null",
    )
    .await;
    inject(
        pool,
        "insert into relay_retention_destruction \
         (group_id, kind, target_digest, policy_version, not_before, authorizers, signatures) \
         values (decode(repeat('6b', 32), 'hex'), 'blob', decode('aa', 'hex'), null, null, \
                 '{}'::bytea[], '[]'::jsonb)",
    )
    .await;

    is_told_to_come_back(
        retention::active_destruction(pool, &group, "blob", &[0xaa]).await,
        "a destruction with no not_before",
    );

    scratch.drop_database().await;
}
