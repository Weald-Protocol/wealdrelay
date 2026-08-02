// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! What text compaction answers when the database cannot answer it, and what the
//! frame layer answers when the session cannot be trusted with the question.
//!
//! Tier 4. `tests/lifecycle_drop.rs` proves the verdicts right when Postgres
//! works. This file proves the one answer that is safe when it does not: a relay
//! that could not look never says "refused" and never says "dropped". Both would
//! be claims about a customer's history that the relay is in no position to make,
//! and the second is the one that ends with somebody's records gone.
//!
//! Every fault is a real state of a real Postgres: a dropped table, a retyped
//! column, a trigger that refuses a write, a closed pool. Injected one statement
//! at a time, because a function whose first read fails never reaches its fourth,
//! and "the drop path handles database errors" proven on the first read says
//! nothing about the last.

mod support;

use std::sync::Arc;

use sqlx::PgPool;
use wealdrelay::frame::{ErrorCode, Frame};
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::lifecycle::{self, store as lifecycle_store, wire};
use wealdrelay::media::retention;
use wealdrelay::session::Session;

use support::{
    config_for, device_from, envelope_for, make_group_in, signed_control, signed_drop,
    signed_policy, verifier_key, Running, Scratch,
};

const NOW_MS: u64 = 1_800_000_000_000;
const NOW_SECS: u64 = NOW_MS / 1000;
const WS: &str = "ws-lifecycle-faults";

struct Harness {
    scratch: Scratch,
    _blobs: tempfile::TempDir,
    state: Arc<RelayState>,
    group: Vec<u8>,
    manifest: Vec<u8>,
    barrier: u64,
}

impl Harness {
    /// A group with a chain, a due policy and a log with a checkpoint on top:
    /// everything an instruction needs, so the only thing a test changes is which
    /// read fails.
    async fn new(label: &str) -> Self {
        let scratch = Scratch::new(label).await;
        let blobs = tempfile::tempdir().unwrap();
        let config = config_for(&scratch, blobs.path());
        let relay = Running::start(config.clone(), Clock::Fixed(NOW_MS)).await;
        let state = Arc::clone(&relay.state);
        relay.shutdown().await;
        let group = make_group_in(
            &state,
            WS,
            0x51,
            &[device_from(0x71), device_from(0x72)],
            &[device_from(0x71), device_from(0x72)],
        )
        .await;
        let pool = state.database.as_ref().expect("a database").pool();
        let key = verifier_key(0x51);
        retention::apply_control(pool, &signed_control(&group, 0, &key, None, &key))
            .await
            .expect("the control lands");
        let policy = signed_policy(
            &group,
            1,
            180,
            NOW_SECS - 1,
            &[device_from(0x71), device_from(0x72)],
        );
        retention::insert_policy(pool, &policy, "[]")
            .await
            .expect("the policy lands");

        let mut manifest = Vec::new();
        for index in 0..3u32 {
            let envelope = envelope_for(&group, format!("fault record {index}").as_bytes());
            wealdrelay::accept::accept(pool, &config, &envelope, NOW_MS)
                .await
                .expect("accepted");
            manifest = envelope.hash.clone();
        }
        let barrier: i64 =
            sqlx::query_scalar("select seq from relay_envelope where group_id = $1 and hash = $2")
                .bind(&group)
                .bind(&manifest)
                .fetch_one(pool)
                .await
                .expect("the checkpoint's seq");

        Self {
            scratch,
            _blobs: blobs,
            state,
            group,
            manifest,
            barrier: barrier as u64,
        }
    }

    fn pool(&self) -> &PgPool {
        self.state.database.as_ref().expect("a database").pool()
    }

    fn instruction(&self) -> wire::DropBefore {
        signed_drop(
            &self.group,
            &self.manifest,
            Vec::new(),
            0,
            Some(1),
            None,
            &verifier_key(0x51),
        )
    }

    async fn finish(self) {
        self.scratch.drop_database().await;
    }
}

async fn inject(pool: &PgPool, statement: &str) {
    if let Err(error) = sqlx::query(statement).execute(pool).await {
        panic!("the injected database state must land: {statement}: {error}");
    }
}

/// A pool that has never seen the old schema, so a retyped column arrives as the
/// decode failure it is meant to be rather than as a stale cached plan.
async fn fresh_pool(scratch: &Scratch) -> PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&scratch.url)
        .await
        .expect("a pool against the injected schema")
}

/// The one correct answer on every fault path.
#[track_caller]
fn cannot_look<T>(outcome: Result<T, retention::StoreError>) {
    match outcome {
        Err(retention::StoreError::Database(_)) => {}
        Ok(_) => panic!(
            "a relay that could not read its own chain must not answer about a customer's history"
        ),
    }
}

// MARK: Every read on the way to a deletion

#[tokio::test]
async fn a_freeze_check_that_cannot_be_read_stops_the_compaction() {
    // The first read, and the one whose failure is most dangerous to guess at: a
    // relay that could not tell whether a group is frozen must not decide that it
    // is not. The frozen state exists because a removed member may have captured
    // the chain, and "I could not check" read as "not frozen" is exactly the
    // deletion the freeze was invented to stop.
    let harness = Harness::new("lifecycle_fault_freeze").await;
    inject(
        harness.pool(),
        "alter table relay_group rename column frozen_reason to weald_injected_gone",
    )
    .await;
    let fresh = fresh_pool(&harness.scratch).await;
    cannot_look(lifecycle::drop_before(&fresh, WS, &harness.instruction(), NOW_SECS).await);
    fresh.close().await;
    harness.finish().await;
}

#[tokio::test]
async fn a_chain_that_cannot_be_read_stops_the_compaction() {
    // Two reads of the control chain: the newest epoch, and that epoch's verifier.
    // Each is injected on its own, because the second is never reached while the
    // first is failing and a single test would leave it unproven.
    let harness = Harness::new("lifecycle_fault_chain").await;

    inject(
        harness.pool(),
        "alter table relay_retention_control rename column epoch to weald_injected_epoch",
    )
    .await;
    let fresh = fresh_pool(&harness.scratch).await;
    cannot_look(lifecycle::drop_before(&fresh, WS, &harness.instruction(), NOW_SECS).await);
    fresh.close().await;
    inject(
        harness.pool(),
        "alter table relay_retention_control rename column weald_injected_epoch to epoch",
    )
    .await;

    // The epoch and the verifier are read out of one row, so each column is
    // retyped on its own: a reader that could not decode either must not answer
    // about the chain, and a decode nobody has run is not a handled failure.
    inject(
        harness.pool(),
        "alter table relay_retention_control \
         drop constraint relay_retention_control_epoch_not_negative",
    )
    .await;
    inject(
        harness.pool(),
        "alter table relay_retention_control alter column epoch type text using epoch::text",
    )
    .await;
    let fresh = fresh_pool(&harness.scratch).await;
    cannot_look(lifecycle::drop_before(&fresh, WS, &harness.instruction(), NOW_SECS).await);
    fresh.close().await;
    inject(
        harness.pool(),
        "alter table relay_retention_control alter column epoch type bigint using epoch::bigint",
    )
    .await;
    inject(
        harness.pool(),
        "alter table relay_retention_control \
         add constraint relay_retention_control_epoch_not_negative check (epoch >= 0)",
    )
    .await;

    // And the verifier beside it.
    inject(
        harness.pool(),
        "alter table relay_retention_control \
         drop constraint relay_retention_control_verifier_is_32_bytes",
    )
    .await;
    inject(
        harness.pool(),
        "alter table relay_retention_control alter column verifier type text \
         using encode(verifier, 'hex')",
    )
    .await;
    let fresh = fresh_pool(&harness.scratch).await;
    cannot_look(lifecycle::drop_before(&fresh, WS, &harness.instruction(), NOW_SECS).await);
    fresh.close().await;

    harness.finish().await;
}

#[tokio::test]
async fn an_authorization_that_cannot_be_read_stops_the_compaction() {
    // Both authorization paths, because they are two statements against two
    // tables and a compaction can arrive under either. A policy the relay cannot
    // read is not an absent policy, and an unreadable destruction record is not a
    // cancelled one.
    let harness = Harness::new("lifecycle_fault_authorization").await;

    inject(
        harness.pool(),
        "alter table relay_retention_policy \
         drop constraint if exists relay_retention_policy_version_positive",
    )
    .await;
    inject(
        harness.pool(),
        "alter table relay_retention_policy alter column version type text using version::text",
    )
    .await;
    let fresh = fresh_pool(&harness.scratch).await;
    cannot_look(lifecycle::drop_before(&fresh, WS, &harness.instruction(), NOW_SECS).await);
    fresh.close().await;

    let digest = vec![0x9a; 32];
    let destruction = signed_drop(
        &harness.group,
        &harness.manifest,
        Vec::new(),
        0,
        None,
        Some(digest),
        &verifier_key(0x51),
    );
    inject(
        harness.pool(),
        "alter table relay_retention_destruction rename column not_before to weald_injected_when",
    )
    .await;
    let fresh = fresh_pool(&harness.scratch).await;
    cannot_look(lifecycle::drop_before(&fresh, WS, &destruction, NOW_SECS).await);
    fresh.close().await;

    // The policy's other window, which is read beside the one above and would
    // otherwise be a decode nobody had run. A policy read with half its terms is
    // not a policy: the text window is what a text compaction is measured
    // against, and a relay that could not read it must not act on the rest.
    //
    // The version column goes back first. It was retyped at the top of this test
    // and `active_policy` reads it before anything else, so leaving it broken
    // would mean this injection was never reached and the decode below never ran:
    // a fault that lands behind an earlier fault is a fault nobody has tested.
    inject(
        harness.pool(),
        "alter table relay_retention_policy alter column version type bigint \
         using version::bigint",
    )
    .await;
    inject(
        harness.pool(),
        "alter table relay_retention_policy alter column text_after_days type text \
         using text_after_days::text",
    )
    .await;
    let fresh = fresh_pool(&harness.scratch).await;
    // The policy path, not the destruction path: a destruction-authorized drop
    // never reads a policy and would prove nothing about this column.
    cannot_look(lifecycle::drop_before(&fresh, WS, &harness.instruction(), NOW_SECS).await);
    fresh.close().await;

    harness.finish().await;
}

#[tokio::test]
async fn a_manifest_check_that_cannot_be_read_stops_the_compaction() {
    // The completeness check is the last thing between an authorized instruction
    // and a delete. A read failure here read as "nothing missing" would drop
    // history under a checkpoint nobody confirmed the relay was holding.
    let harness = Harness::new("lifecycle_fault_manifest").await;
    inject(
        harness.pool(),
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected'; end $$",
    )
    .await;
    // A rule that makes the presence check fail rather than answer. Postgres
    // evaluates a `select` against a view, so the view is what fails.
    inject(
        harness.pool(),
        "create or replace function weald_injected_boom() returns boolean \
         language plpgsql as $$ begin raise exception 'injected: this read cannot answer'; end $$",
    )
    .await;
    inject(
        harness.pool(),
        "alter table relay_envelope rename to weald_injected_envelopes",
    )
    .await;
    inject(
        harness.pool(),
        "create view relay_envelope as select group_id, hash, v, enc, epoch, seq, ts, ct \
         from weald_injected_envelopes where weald_injected_boom()",
    )
    .await;
    let fresh = fresh_pool(&harness.scratch).await;
    cannot_look(lifecycle::drop_before(&fresh, WS, &harness.instruction(), NOW_SECS).await);
    fresh.close().await;
    harness.finish().await;
}

#[tokio::test]
async fn a_deletion_that_cannot_commit_is_never_reported_as_a_deletion() {
    // The write half. A drop reported as done that did not commit is a client
    // that moves its verification floor above a checkpoint the relay never
    // anchored, and every envelope beneath it is then history nobody will check.
    let harness = Harness::new("lifecycle_fault_delete").await;
    inject(
        harness.pool(),
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected: this write cannot land'; end $$",
    )
    .await;
    inject(
        harness.pool(),
        "create trigger weald_injected_insert before insert on relay_checkpoint \
         for each statement execute function weald_injected_refusal()",
    )
    .await;
    cannot_look(lifecycle::drop_before(harness.pool(), WS, &harness.instruction(), NOW_SECS).await);
    // And nothing went: the transaction that could not record the anchor did not
    // delete either.
    let left: i64 = sqlx::query_scalar("select count(*) from relay_envelope where group_id = $1")
        .bind(&harness.group)
        .fetch_one(harness.pool())
        .await
        .unwrap();
    assert_eq!(left, 3);
    harness.finish().await;
}

#[tokio::test]
async fn the_run_log_and_the_anchor_list_report_a_read_they_could_not_make() {
    // Both operator-facing reads. An empty run log means "this group has never
    // been compacted", which is a different claim from "I could not look", and an
    // empty anchor list read as truth would let a caller believe nothing is
    // pinned.
    let harness = Harness::new("lifecycle_fault_reads").await;
    inject(
        harness.pool(),
        "alter table relay_drop_run rename column deleted_count to weald_injected_count",
    )
    .await;
    inject(
        harness.pool(),
        "alter table relay_checkpoint_anchor rename column hash to weald_injected_hash",
    )
    .await;
    let fresh = fresh_pool(&harness.scratch).await;
    assert!(lifecycle_store::runs(&fresh, &harness.group).await.is_err());
    assert!(lifecycle_store::anchors(&fresh, &harness.group)
        .await
        .is_err());
    assert!(
        lifecycle_store::missing_envelopes(&fresh, &harness.group, &[vec![0x11; 32]])
            .await
            .is_ok()
    );
    fresh.close().await;

    // A closed pool, which is what a dead database looks like to every one of
    // these calls at once.
    let closed = fresh_pool(&harness.scratch).await;
    closed.close().await;
    assert!(lifecycle_store::runs(&closed, &harness.group)
        .await
        .is_err());
    assert!(lifecycle_store::anchors(&closed, &harness.group)
        .await
        .is_err());
    assert!(
        lifecycle_store::missing_envelopes(&closed, &harness.group, &[vec![0x11; 32]])
            .await
            .is_err()
    );
    assert!(lifecycle_store::drop_before(
        &closed,
        &harness.group,
        &harness.manifest,
        harness.barrier,
        0,
        &[]
    )
    .await
    .is_err());
    // The error says which layer could not answer, because an operator reading a
    // log needs to know whether it was the media store or this one.
    let error = lifecycle_store::runs(&closed, &harness.group)
        .await
        .expect_err("a closed pool answers nothing");
    assert!(error.to_string().starts_with("lifecycle store:"), "{error}");
    assert!(format!("{error:?}").contains("Database"));

    harness.finish().await;
}

// MARK: The frame layer, above the decision

#[tokio::test]
async fn a_relay_with_no_database_tells_the_client_to_come_back() {
    let scratch = Scratch::new("lifecycle_fault_nodb").await;
    let blobs = tempfile::tempdir().unwrap();
    let state = Arc::new(RelayState::new(
        config_for(&scratch, blobs.path()),
        None,
        None,
    ));
    let mut session = Session::new(&state.config);
    session.bind_workspace(WS.to_string());
    session.bind_device(vec![1u8; 32]);
    let record = signed_drop(
        &[0x51; 32],
        &[0x52; 32],
        Vec::new(),
        0,
        Some(1),
        None,
        &verifier_key(0x51),
    );
    match lifecycle::handle(&state, &session, record.encode()).await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::Backpressure),
        other => panic!("expected backpressure, got {other:?}"),
    }
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_session_with_no_workspace_may_not_compact_anything() {
    // A session that has not authenticated has no workspace to check a group
    // against, so there is no question to answer: the instruction is refused
    // before the chain is read.
    let harness = Harness::new("lifecycle_fault_nosession").await;
    let session = Session::new(&harness.state.config);
    match lifecycle::handle(&harness.state, &session, harness.instruction().encode()).await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("expected a refusal, got {other:?}"),
    }
    harness.finish().await;
}

#[tokio::test]
async fn a_workspace_lookup_that_fails_is_backpressure_rather_than_a_refusal() {
    // "Which workspace owns this group" is a read like any other, and a relay
    // that could not make it must not answer "not yours": the client would take a
    // permanent refusal for a transient outage and stop retrying.
    let harness = Harness::new("lifecycle_fault_lookup").await;
    let mut session = Session::new(&harness.state.config);
    session.bind_workspace(WS.to_string());
    session.bind_device(device_from(0x71).verifying_key().to_bytes().to_vec());
    let instruction = harness.instruction();

    inject(
        harness.pool(),
        "alter table relay_group rename column workspace_id to weald_injected_workspace",
    )
    .await;
    let fresh = fresh_pool(&harness.scratch).await;
    let state = Arc::new(RelayState::new(
        harness.state.config.clone(),
        Some(wealdrelay::db::Database::from_pool(fresh.clone())),
        None,
    ));
    match lifecycle::handle(&state, &session, instruction.encode()).await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::Backpressure),
        other => panic!("expected backpressure, got {other:?}"),
    }
    fresh.close().await;
    inject(
        harness.pool(),
        "alter table relay_group rename column weald_injected_workspace to workspace_id",
    )
    .await;

    // And a decision the relay could not make, for the same reason: the chain
    // read fails after the group has been authorized, and the answer is still
    // come back rather than a verdict.
    inject(
        harness.pool(),
        "alter table relay_retention_control rename column epoch to weald_injected_epoch",
    )
    .await;
    let fresh = fresh_pool(&harness.scratch).await;
    let state = Arc::new(RelayState::new(
        harness.state.config.clone(),
        Some(wealdrelay::db::Database::from_pool(fresh.clone())),
        None,
    ));
    match lifecycle::handle(&state, &session, instruction.encode()).await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::Backpressure),
        other => panic!("expected backpressure, got {other:?}"),
    }
    fresh.close().await;

    harness.finish().await;
}

#[tokio::test]
async fn every_statement_inside_a_drop_reports_the_one_that_failed() {
    // A drop is five statements in one transaction, and a test that failed only
    // the first would leave the other four unproven: each is injected on its own
    // database, one at a time, and the answer has to be the same every time.
    // Reported rather than guessed at, because the alternative to "I could not
    // do this" here is a client told its history was compacted when it was not.
    for (label, statements) in [
        (
            "the anchor list",
            vec![
                "create trigger weald_injected_anchor before insert on relay_checkpoint_anchor \
                 for each statement execute function weald_injected_refusal()",
            ],
        ),
        (
            "the surviving count",
            vec!["alter table relay_envelope rename column seq to weald_injected_seq"],
        ),
        (
            "the byte count",
            vec!["alter table relay_envelope rename column ct to weald_injected_ct"],
        ),
        (
            "the deletion",
            vec![
                "create trigger weald_injected_delete before delete on relay_envelope \
                 for each statement execute function weald_injected_refusal()",
            ],
        ),
        (
            "the run log",
            vec![
                "create trigger weald_injected_run before insert on relay_drop_run \
                 for each statement execute function weald_injected_refusal()",
            ],
        ),
        (
            "the commit",
            // A deferred constraint, which is the one failure that arrives at
            // `commit` rather than at a statement: every statement in the
            // transaction succeeded and the transaction still did not happen. A
            // relay that reported the outcome it computed before committing would
            // tell a client its history was compacted by a transaction Postgres
            // rolled back.
            vec![
                "alter table relay_drop_run add constraint weald_injected_one_per_group \
                 unique (group_id) deferrable initially deferred",
                "insert into relay_drop_run \
                 (group_id, manifest_hash, barrier_seq, deleted_count, deleted_bytes, kept_count) \
                 values (decode(repeat('51', 32), 'hex'), decode(repeat('52', 32), 'hex'), 1, 0, 0, 0)",
            ],
        ),
    ] {
        let harness = Harness::new(&format!(
            "lifecycle_fault_stmt_{}",
            label.replace(' ', "_")
        ))
        .await;
        inject(
            harness.pool(),
            "create or replace function weald_injected_refusal() returns trigger \
             language plpgsql as $$ begin raise exception 'injected: this write cannot land'; end $$",
        )
        .await;
        for statement in statements {
            inject(harness.pool(), statement).await;
        }
        let outcome = lifecycle_store::drop_before(
            harness.pool(),
            &harness.group,
            &harness.manifest,
            harness.barrier,
            0,
            &[],
        )
        .await;
        assert!(outcome.is_err(), "{label}: a failed statement was reported as a compaction");
        harness.finish().await;
    }
}

#[tokio::test]
async fn a_run_log_row_the_relay_cannot_read_is_never_a_number_it_reports() {
    // Every column of the run log, one at a time. An operator reads these to
    // decide whether compaction is working, and a column read as zero would say
    // "nothing was ever reclaimed" about a workspace that has been compacting
    // for months.
    let harness = Harness::new("lifecycle_fault_runrows").await;
    lifecycle_store::drop_before(
        harness.pool(),
        &harness.group,
        &harness.manifest,
        harness.barrier,
        0,
        &[],
    )
    .await
    .expect("one compaction to read back");

    for column in [
        "barrier_seq",
        "deleted_count",
        "deleted_bytes",
        "kept_count",
        "manifest_hash",
    ] {
        let scratch = Scratch::new(&format!("lifecycle_fault_run_{column}")).await;
        let blobs = tempfile::tempdir().unwrap();
        let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(NOW_MS)).await;
        let pool = relay.state.database.as_ref().unwrap().pool().clone();
        relay.shutdown().await;
        inject(
            &pool,
            "alter table relay_drop_run drop constraint relay_drop_run_counts_not_negative",
        )
        .await;
        inject(
            &pool,
            "insert into relay_drop_run \
             (group_id, manifest_hash, barrier_seq, deleted_count, deleted_bytes, kept_count) \
             values (decode(repeat('51', 32), 'hex'), decode(repeat('52', 32), 'hex'), 1, 1, 1, 1)",
        )
        .await;
        let retype = if column == "manifest_hash" {
            format!(
                "alter table relay_drop_run alter column {column} type text \
                 using encode({column}, 'hex')"
            )
        } else {
            format!(
                "alter table relay_drop_run alter column {column} type text using {column}::text"
            )
        };
        inject(&pool, &retype).await;
        let fresh = fresh_pool(&scratch).await;
        assert!(
            lifecycle_store::runs(&fresh, &[0x51; 32]).await.is_err(),
            "a run log whose {column} cannot be read must not be reported"
        );
        fresh.close().await;
        pool.close().await;
        scratch.drop_database().await;
    }

    harness.finish().await;
}

#[tokio::test]
async fn an_anchor_the_relay_cannot_read_is_never_an_empty_anchor_list() {
    // The anchor list decides what a drop keeps. Read as empty because a column
    // could not be decoded, the next barrier would sweep the snapshots every
    // earlier checkpoint depends on.
    let harness = Harness::new("lifecycle_fault_anchor_read").await;
    lifecycle_store::drop_before(
        harness.pool(),
        &harness.group,
        &harness.manifest,
        harness.barrier,
        0,
        &[],
    )
    .await
    .expect("one compaction, so there is an anchor to read");
    inject(
        harness.pool(),
        "alter table relay_checkpoint_anchor \
         drop constraint relay_checkpoint_anchor_hash_is_32_bytes",
    )
    .await;
    inject(
        harness.pool(),
        "alter table relay_checkpoint_anchor alter column hash type text using encode(hash, 'hex')",
    )
    .await;
    let fresh = fresh_pool(&harness.scratch).await;
    assert!(lifecycle_store::anchors(&fresh, &harness.group)
        .await
        .is_err());
    fresh.close().await;
    harness.finish().await;
}

#[tokio::test]
async fn a_store_failure_reaches_the_caller_as_an_outage_and_not_a_verdict() {
    // The seam between the decision and the write. `lifecycle::drop_before` runs
    // every check itself and then hands off; a store failure on the far side of
    // that hand-off must come back as "I could not", because the alternative is a
    // client told its history was compacted by a transaction that rolled back.
    let harness = Harness::new("lifecycle_fault_handoff").await;
    inject(
        harness.pool(),
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected: this write cannot land'; end $$",
    )
    .await;
    inject(
        harness.pool(),
        "create trigger weald_injected_checkpoint before insert on relay_checkpoint \
         for each statement execute function weald_injected_refusal()",
    )
    .await;
    cannot_look(lifecycle::drop_before(harness.pool(), WS, &harness.instruction(), NOW_SECS).await);
    harness.finish().await;
}

#[tokio::test]
async fn a_barrier_the_relay_cannot_read_is_never_read_as_zero() {
    // The barrier is the checkpoint envelope's own `seq`, and the relay derives
    // it rather than taking it from the instruction. A read that failed and was
    // treated as zero would drop nothing, which is the harmless direction, but it
    // would also write a run-log row saying a compaction happened. The answer has
    // to be that it could not look.
    let harness = Harness::new("lifecycle_fault_barrier").await;
    inject(
        harness.pool(),
        "alter table relay_envelope rename column seq to weald_injected_seq",
    )
    .await;
    let fresh = fresh_pool(&harness.scratch).await;
    assert!(
        lifecycle_store::seq_of(&fresh, &harness.group, &harness.manifest)
            .await
            .is_err(),
        "a barrier the relay cannot read must not answer a number"
    );
    // And through the entry point, because that is where the answer is decided:
    // the completeness check above it reads no `seq` and still succeeds, so this
    // is the one read that fails and the verdict has to be an outage.
    cannot_look(lifecycle::drop_before(&fresh, WS, &harness.instruction(), NOW_SECS).await);
    // And an envelope it simply does not hold is a different answer: no row, no
    // error. The caller has already refused that case as an incomplete manifest.
    inject(
        harness.pool(),
        "alter table relay_envelope rename column weald_injected_seq to seq",
    )
    .await;
    assert_eq!(
        lifecycle_store::seq_of(harness.pool(), &harness.group, &[0xee; 32])
            .await
            .expect("the read works"),
        None
    );
    fresh.close().await;
    harness.finish().await;
}
