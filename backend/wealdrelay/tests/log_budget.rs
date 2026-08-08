// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Tiers 3 and 4 for the envelope log's byte budget, against a real Postgres.
//!
//! Nothing here is mocked. Every envelope is written through `accept::accept`,
//! the path a `SEND` frame takes; the counter is the one the triggers in
//! `migrations/0010_envelope_budget.sql` maintain; and the compaction at the end
//! is the real signed `drop_before` the client sends. What is being proven is
//! which writes a real database accepts when a workspace is at its ceiling, and
//! that is not a claim a fake can carry.
//!
//! The four claims, from `specs/backend/relay/lifecycle.md` and
//! `specs/backend/relay/operations.md`:
//!
//! - A workspace can be filled to its budget exactly, and the envelope that
//!   lands on the limit is accepted. The budget is a ceiling, not a margin.
//! - The next write is refused with `quota/log_budget_exhausted` carrying the
//!   limit, and the refusal is a whole answer: the row is not there, the client
//!   was not acknowledged, and nothing was dropped silently. A dropped envelope
//!   would be a hole in an author chain.
//! - Compaction is the lever the refusal names, and it works: a signed
//!   `drop_before` behind an accepted checkpoint frees bytes and the workspace
//!   writes again. The relay never does this on its own initiative.
//! - The budget is per workspace. A workspace at its ceiling does not refuse
//!   anybody else's writes, and no workspace's bytes are ever charged to another.

mod support;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sqlx::PgPool;
use wealdrelay::accept::{accept, AcceptError};
use wealdrelay::config::{keys, Config, Values};
use wealdrelay::envelope::MAX_CIPHERTEXT_BYTES;
use wealdrelay::frame::{ErrorClass, ErrorCode};
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::lifecycle::{self, wire};
use wealdrelay::log_budget;
use wealdrelay::media::retention;

use support::{
    device_from, envelope_for, make_group_in, record_evidence, signed_control, signed_drop,
    signed_policy, verifier_key, Running, Scratch,
};

const NOW_MS: u64 = 1_800_000_000_000;
const NOW_SECS: u64 = NOW_MS / 1000;

/// One decimal gigabyte, which is what `WEALD_RELAY_MAX_LOG_GB=1` means.
const BUDGET: i64 = 1_000_000_000;

const FIRST: &str = "ws-budget-first";
const SECOND: &str = "ws-budget-second";

/// The integration configuration with a ceiling on the envelope log.
///
/// A local builder rather than a flag on `support::config_for`, for the reason
/// `config_for_calls` gives: every suite that is not about this budget should be
/// running against the default posture, which is unlimited, and a shared helper
/// that quietly set a ceiling would mean thirty suites exercising a refusal none
/// of them is testing.
fn config_with_budget(scratch: &Scratch, blobs: &std::path::Path, gb: u64) -> Config {
    Config::resolve(&Values::from_pairs([
        (keys::HOSTNAME, "localhost".to_string()),
        (keys::DATABASE_URL, scratch.url.clone()),
        (keys::STORAGE_URL, format!("file://{}", blobs.display())),
        (keys::LISTEN, "127.0.0.1:0".to_string()),
        (keys::OBSERVABILITY_LISTEN, "127.0.0.1:0".to_string()),
        (keys::RELEASE_CHECK, "off".to_string()),
        (keys::MAX_LOG_GB, gb.to_string()),
    ]))
    .expect("the budget configuration resolves")
}

struct Harness {
    scratch: Scratch,
    _blobs: tempfile::TempDir,
    state: Arc<RelayState>,
    config: Config,
    written: AtomicU64,
}

impl Harness {
    async fn new(label: &str) -> Self {
        let scratch = Scratch::new(label).await;
        let blobs = tempfile::tempdir().unwrap();
        let config = config_with_budget(&scratch, blobs.path(), 1);
        let relay = Running::start(config.clone(), Clock::Fixed(NOW_MS)).await;
        let state = Arc::clone(&relay.state);
        relay.shutdown().await;
        Self {
            scratch,
            _blobs: blobs,
            state,
            config,
            written: AtomicU64::new(0),
        }
    }

    fn pool(&self) -> &PgPool {
        self.state.database.as_ref().expect("a database").pool()
    }

    async fn group(&self, workspace: &str, byte: u8) -> Vec<u8> {
        make_group_in(
            &self.state,
            workspace,
            byte,
            &[device_from(0x71), device_from(0x72)],
            &[device_from(0x71), device_from(0x72)],
        )
        .await
    }

    /// A body of exactly `size` bytes that no other body in this harness equals.
    ///
    /// The uniqueness is load-bearing rather than tidy: a hash is a content
    /// address, so two identical bodies are one envelope stored once, and a fill
    /// loop that repeated itself would charge the budget nothing while believing
    /// it had written a gigabyte.
    fn body(&self, size: usize) -> Vec<u8> {
        let index = self.written.fetch_add(1, Ordering::Relaxed);
        let mut body = format!("{index:016x}").into_bytes();
        body.resize(size.max(body.len()), 0xAB);
        body.truncate(size.max(1));
        body
    }

    /// Write one envelope of `size` bytes and answer with its hash.
    async fn write(&self, group: &[u8], size: usize) -> Result<Vec<u8>, AcceptError> {
        let envelope = envelope_for(group, &self.body(size));
        accept(self.pool(), &self.config, &envelope, NOW_MS).await?;
        Ok(envelope.hash)
    }

    async fn used(&self, workspace: &str) -> i64 {
        log_budget::used_bytes(self.pool(), workspace)
            .await
            .expect("the counter reads")
    }

    async fn summed(&self, workspace: &str) -> i64 {
        log_budget::summed_bytes(self.pool(), workspace)
            .await
            .expect("the sum reads")
    }

    /// Fill a workspace to exactly its budget, in envelopes no larger than the
    /// protocol's own ciphertext ceiling.
    ///
    /// Driven by the counter rather than by arithmetic the test does for itself,
    /// so it lands on the limit whatever else the workspace already holds. That
    /// also means the loop is a check of the counter: if the counter did not
    /// track the writes, this would not terminate.
    async fn fill_to_budget(&self, workspace: &str, group: &[u8]) -> usize {
        let mut written = 0usize;
        loop {
            let room = BUDGET - self.used(workspace).await;
            assert!(room >= 0, "the fill overshot the budget");
            if room == 0 {
                return written;
            }
            let size = room.min(MAX_CIPHERTEXT_BYTES as i64) as usize;
            self.write(group, size)
                .await
                .expect("a write inside the budget is accepted");
            written += 1;
        }
    }

    /// The retention chain at epoch zero, which is what a `drop_before` is signed
    /// under. Copied in shape from `lifecycle_drop.rs`, because compaction here
    /// has to be the real thing or the lever is not the one a customer has.
    async fn chain(&self, group: &[u8]) {
        let key = verifier_key(0x51);
        let record = signed_control(group, 0, &key, None, &key);
        assert_eq!(
            retention::apply_control(self.pool(), &record)
                .await
                .expect("the control lands"),
            retention::ControlOutcome::Accepted
        );
    }

    async fn policy(&self, workspace: &str, group: &[u8]) {
        let record = signed_policy(
            group,
            1,
            180,
            NOW_SECS - 1,
            &[device_from(0x71), device_from(0x72)],
        );
        let authorization = retention::authorize(
            self.pool(),
            workspace,
            &record.signing_bytes(),
            &record.signatures,
            record.not_before,
            NOW_SECS,
        )
        .await
        .expect("authorization is checkable");
        assert_eq!(authorization, retention::Authorization::Threshold);
        retention::insert_policy(self.pool(), &record, "[]")
            .await
            .expect("the policy lands");
    }

    async fn finish(self) {
        self.scratch.drop_database().await;
    }
}

fn instruction(group: &[u8], manifest: &[u8], snapshots: Vec<Vec<u8>>) -> wire::DropBefore {
    signed_drop(
        group,
        manifest,
        snapshots,
        0,
        Some(1),
        None,
        &verifier_key(0x51),
    )
}

// MARK: The budget itself

/// Fill one workspace to its budget against a real database, watch the next
/// write refused, and watch compaction clear it.
///
/// One test rather than three because the state each part needs is the state the
/// one before it produced, and a gigabyte of envelopes is not a fixture worth
/// building three times.
#[tokio::test]
async fn a_full_workspace_is_refused_and_compaction_is_the_lever() {
    let harness = Harness::new("log_budget_full").await;
    let group = harness.group(FIRST, 0x41).await;
    harness.chain(&group).await;
    harness.policy(FIRST, &group).await;

    // The history a checkpoint will later replace, then the checkpoint itself.
    // Written before the ceiling is reached, because a workspace at its budget
    // cannot write the very snapshot that would let it compact: that is the
    // deadlock the ordering here exists to avoid, and it is why the refusal names
    // compaction as a lever the client plans for rather than one it reaches for
    // at the last byte.
    let mut old = Vec::new();
    for _ in 0..100 {
        old.push(
            harness
                .write(&group, MAX_CIPHERTEXT_BYTES)
                .await
                .expect("early writes are accepted"),
        );
    }
    let snapshot = harness
        .write(&group, 4096)
        .await
        .expect("the snapshot is accepted");
    let manifest = harness
        .write(&group, 4096)
        .await
        .expect("the checkpoint is accepted");

    let written = harness.fill_to_budget(FIRST, &group).await;
    assert!(written > 0, "the fill wrote nothing");

    // The envelope that lands on the limit is accepted. A budget that refused it
    // would be a budget one megabyte smaller than the number the customer bought.
    assert_eq!(
        harness.used(FIRST).await,
        BUDGET,
        "the workspace did not land exactly on its budget"
    );
    assert_eq!(
        harness.used(FIRST).await,
        harness.summed(FIRST).await,
        "the counter and the rows disagree at the boundary"
    );

    // And the next byte is refused.
    let error = harness
        .write(&group, 1)
        .await
        .expect_err("a write past the budget was accepted");
    assert_eq!(
        error,
        AcceptError::LogBudgetExhausted { limit: BUDGET },
        "the refusal did not carry the configured limit"
    );

    let frame = error.to_frame();
    assert_eq!(frame.code, ErrorCode::LogBudgetExhausted);
    assert_eq!(
        frame.class(),
        ErrorClass::Quota,
        "the class a client branches on"
    );
    assert_eq!(
        frame
            .detail
            .clone()
            .map(|bytes| i64::from_be_bytes(bytes.try_into().expect("eight bytes of limit"))),
        Some(BUDGET),
        "the client is told the limit it is against"
    );
    assert_eq!(
        ErrorCode::LogBudgetExhausted.qualified(),
        "quota/log_budget_exhausted"
    );

    // The refusal is a whole answer. Nothing was stored, so the workspace is
    // still exactly at its budget rather than one envelope past it, and the
    // client's write is still the client's own to retry after it compacts.
    assert_eq!(
        harness.used(FIRST).await,
        BUDGET,
        "a refused write left bytes behind"
    );
    assert_eq!(harness.used(FIRST).await, harness.summed(FIRST).await);

    // Compaction: the lever the error names. The relay does none of this on its
    // own initiative, which is the boundary decision this budget was written
    // against (`specs/backend/relay/lifecycle.md`).
    let record = instruction(&group, &manifest, vec![snapshot.clone()]);
    let outcome = lifecycle::drop_before(harness.pool(), FIRST, &record, NOW_SECS)
        .await
        .expect("the relay could look")
        .expect("the instruction is accepted");
    assert_eq!(
        outcome.deleted as usize,
        old.len(),
        "compaction removed something other than the history below the barrier"
    );
    assert!(outcome.bytes > 0);

    let after = harness.used(FIRST).await;
    assert_eq!(
        after,
        BUDGET - outcome.bytes as i64,
        "the counter was not credited for what compaction removed"
    );
    assert_eq!(
        after,
        harness.summed(FIRST).await,
        "the counter and the rows disagree after a batch delete"
    );

    // And the workspace writes again, which is the whole point of naming a lever
    // rather than an interval.
    harness
        .write(&group, MAX_CIPHERTEXT_BYTES)
        .await
        .expect("a write after compaction is accepted");

    record_evidence(
        "step-04",
        "relay-log-budget.txt",
        &format!(
            "WEALD_RELAY_MAX_LOG_GB=1 ({BUDGET} bytes, decimal)\n\
             filled to the budget exactly: used={BUDGET} envelopes={written}\n\
             next write refused: {}\n\
             detail carried: limit={BUDGET} bytes, big-endian, no interval\n\
             compaction reclaimed: {} bytes across {} envelopes\n\
             counter after compaction: {after}, equal to the sum over the rows\n\
             write after compaction: accepted\n",
            ErrorCode::LogBudgetExhausted.qualified(),
            outcome.bytes,
            outcome.deleted,
        ),
    );

    harness.finish().await;
}

// MARK: The negative

/// One workspace at its ceiling refuses nobody else, and no workspace's bytes are
/// ever charged to another.
///
/// This is the failure that would matter most in production and would be
/// invisible in a single-tenant test: a budget keyed on anything other than the
/// group's own workspace would let one noisy customer silence every other
/// customer on the same relay, which is worse than the unbounded log this budget
/// replaced.
#[tokio::test]
async fn one_workspaces_writes_never_refuse_another() {
    let harness = Harness::new("log_budget_isolation").await;
    let full = harness.group(FIRST, 0x42).await;
    let quiet = harness.group(SECOND, 0x43).await;
    // A second group in the full workspace, because the budget is per workspace
    // and not per group: the ceiling has to follow the tenant across every
    // channel it owns, or a workspace routes around it by opening one more.
    let also_full = harness.group(FIRST, 0x44).await;

    harness.fill_to_budget(FIRST, &full).await;
    assert_eq!(harness.used(FIRST).await, BUDGET);

    // The other workspace has been charged nothing at all.
    assert_eq!(
        harness.used(SECOND).await,
        0,
        "another workspace's bytes were charged to this one"
    );

    // And writes normally, while the first workspace is at its ceiling.
    for _ in 0..8 {
        harness
            .write(&quiet, MAX_CIPHERTEXT_BYTES)
            .await
            .expect("a quiet workspace is refused by a full neighbour");
    }
    assert_eq!(
        harness.used(SECOND).await,
        8 * MAX_CIPHERTEXT_BYTES as i64,
        "the second workspace's counter is not its own bytes"
    );
    assert_eq!(harness.used(SECOND).await, harness.summed(SECOND).await);

    // The full workspace is still full, and still refused, on a group that has
    // never been written to.
    assert_eq!(
        harness.used(FIRST).await,
        BUDGET,
        "a neighbour's writes moved this workspace's counter"
    );
    let error = harness
        .write(&also_full, 1)
        .await
        .expect_err("a second group escaped the workspace's budget");
    assert_eq!(error, AcceptError::LogBudgetExhausted { limit: BUDGET });

    record_evidence(
        "step-04",
        "relay-log-budget-isolation.txt",
        &format!(
            "workspace {FIRST}: at budget ({BUDGET} bytes), refused on a second group\n\
             workspace {SECOND}: {} bytes, accepted throughout\n\
             neither counter moved for the other's writes\n",
            harness.used(SECOND).await,
        ),
    );

    harness.finish().await;
}

/// An unlimited relay is unchanged by any of this.
///
/// The self-hoster's posture is the default, and a budget that quietly applied
/// itself when nobody configured one would be this relay enforcing our pricing on
/// somebody who is not our customer.
#[tokio::test]
async fn an_unconfigured_relay_has_no_ceiling() {
    let scratch = Scratch::new("log_budget_unlimited").await;
    let blobs = tempfile::tempdir().unwrap();
    let config = support::config_for(&scratch, blobs.path());
    assert_eq!(log_budget::limit_bytes(&config), None);

    let relay = Running::start(config.clone(), Clock::Fixed(NOW_MS)).await;
    let state = Arc::clone(&relay.state);
    relay.shutdown().await;
    let pool = state.database.as_ref().expect("a database").pool();
    let group = make_group_in(
        &state,
        FIRST,
        0x45,
        &[device_from(0x71), device_from(0x72)],
        &[device_from(0x71), device_from(0x72)],
    )
    .await;

    for index in 0..16u64 {
        let envelope = envelope_for(&group, format!("unlimited {index}").as_bytes());
        accept(pool, &config, &envelope, NOW_MS)
            .await
            .expect("an unconfigured relay refuses nothing");
    }

    // The counter is still maintained, because the trigger is not conditional on
    // configuration: an operator who sets a ceiling later gets a true number
    // immediately rather than one that starts counting from the restart.
    assert_eq!(
        log_budget::used_bytes(pool, FIRST).await.unwrap(),
        log_budget::summed_bytes(pool, FIRST).await.unwrap()
    );
    assert!(log_budget::used_bytes(pool, FIRST).await.unwrap() > 0);

    scratch.drop_database().await;
}
