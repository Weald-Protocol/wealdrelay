// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `WEALD_RELAY_RETENTION_DAYS` is read by the binary, and what it does is warn.
//!
//! Before `retention_notice` existed the variable was parsed, validated and printed
//! back by `--check-config` while no code path in the crate read it (WEALD-L180), so
//! an operator who set 30 could not tell a relay holding nothing older than a month
//! from one holding two years of it. These tests fail against that tree: the pass
//! they call did not exist, and the count they assert on was never computed.
//!
//! What they must never prove is a deletion. `specs/backend/relay/lifecycle.md:293`
//! gives this variable the warning half of the three-way split, so the row is still
//! there afterwards and that is asserted, not incidental.
//!
//! Real Postgres, like every other suite that touches the envelope log.

mod support;

use std::sync::Arc;

use sqlx::PgPool;
use wealdrelay::config::{keys, Config, Limit, Values};
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::retention_notice::{cutoff_ms, overdue};

use support::{device_from, make_group_in, Running, Scratch};

const NOW: u64 = 1_800_000_000_000;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

fn config_with_retention(scratch: &Scratch, blobs: &std::path::Path, days: &str) -> Config {
    Config::resolve(&Values::from_pairs([
        (keys::HOSTNAME, "localhost".to_string()),
        (keys::DATABASE_URL, scratch.url.clone()),
        (keys::STORAGE_URL, format!("file://{}", blobs.display())),
        (keys::LISTEN, "127.0.0.1:0".to_string()),
        (keys::OBSERVABILITY_LISTEN, "127.0.0.1:0".to_string()),
        (keys::RELEASE_CHECK, "off".to_string()),
        (keys::RETENTION_DAYS, days.to_string()),
    ]))
    .expect("the retention configuration resolves")
}

struct Harness {
    scratch: Scratch,
    _blobs: tempfile::TempDir,
    state: Arc<RelayState>,
}

impl Harness {
    async fn new(label: &str, days: &str) -> Self {
        let scratch = Scratch::new(label).await;
        let blobs = tempfile::tempdir().unwrap();
        let relay = Running::start(
            config_with_retention(&scratch, blobs.path(), days),
            Clock::Fixed(NOW),
        )
        .await;
        let state = Arc::clone(&relay.state);
        relay.shutdown().await;
        Self {
            scratch,
            _blobs: blobs,
            state,
        }
    }

    fn pool(&self) -> &PgPool {
        self.state.database.as_ref().expect("a database").pool()
    }

    async fn finish(self) {
        self.scratch.drop_database().await;
    }
}

/// One envelope, at a receipt time the test chooses.
async fn envelope_at(pool: &PgPool, group: &[u8], seq: i64, byte: u8, ts_ms: u64) {
    sqlx::query(
        "insert into relay_envelope (group_id, hash, v, enc, epoch, seq, ts, ct) \
         values ($1, $2, 1, 0, 0, $3, $4, $5)",
    )
    .bind(group)
    .bind(vec![byte; 32])
    .bind(seq)
    .bind(ts_ms as i64)
    .bind(vec![byte; 16])
    .execute(pool)
    .await
    .expect("the test's own envelope inserts");
}

async fn envelope_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("select count(*)::bigint from relay_envelope")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The headline proof: an envelope past the window is counted, reported with its
/// age, and still there afterwards.
#[tokio::test]
async fn a_collector_pass_reports_what_is_past_the_window_and_deletes_none_of_it() {
    let harness = Harness::new("retention_notice_warns", "7").await;
    let pool = harness.pool();
    let group = make_group_in(
        &harness.state,
        "ws-ret1",
        0x41,
        &[device_from(0x61)],
        &[device_from(0x61)],
    )
    .await;

    envelope_at(pool, &group, 1, 0xa1, NOW - 30 * DAY_MS).await;
    envelope_at(pool, &group, 2, 0xa2, NOW - 9 * DAY_MS).await;
    envelope_at(pool, &group, 3, 0xa3, NOW - DAY_MS).await;

    let summary = wealdrelay::janitor::pass(&harness.state).await;

    assert_eq!(
        summary.retention_overdue.envelopes, 2,
        "both envelopes older than seven days are counted, the one-day-old one is not"
    );
    assert_eq!(summary.retention_overdue.workspaces, 1);
    assert_eq!(
        summary.retention_overdue.oldest_days, 30,
        "the operator is told how far past the window the oldest one is"
    );
    assert_eq!(
        envelope_count(pool).await,
        3,
        "retention warns; only a signed drop_before deletes (lifecycle.md:311-316)"
    );
    harness.finish().await;
}

/// The negative half: nothing past the window means nothing to say, and an
/// unlimited setting asks no question at all.
#[tokio::test]
async fn nothing_past_the_window_and_no_window_at_all_both_report_nothing() {
    let harness = Harness::new("retention_notice_quiet", "7").await;
    let pool = harness.pool();
    let group = make_group_in(
        &harness.state,
        "ws-ret2",
        0x42,
        &[device_from(0x62)],
        &[device_from(0x62)],
    )
    .await;
    envelope_at(pool, &group, 1, 0xb1, NOW - 2 * DAY_MS).await;

    let summary = wealdrelay::janitor::pass(&harness.state).await;
    assert!(summary.retention_overdue.is_empty());
    assert_eq!(summary.retention_overdue.oldest_days, 0);

    assert_eq!(
        overdue(pool, Limit::Unlimited, NOW).await,
        Default::default(),
        "an operator who set no threshold is asked no question"
    );
    assert_eq!(
        overdue(pool, Limit::Of(1), NOW).await.envelopes,
        1,
        "a tighter threshold sees the same row"
    );
    harness.finish().await;
}

/// A clock younger than the window reports nothing rather than wrapping into a
/// cutoff in the far future that would call every envelope overdue.
#[test]
fn the_cutoff_saturates_and_unlimited_has_none() {
    assert_eq!(cutoff_ms(Limit::Unlimited, NOW), None);
    assert_eq!(cutoff_ms(Limit::Of(1), NOW), Some(NOW - DAY_MS));
    assert_eq!(cutoff_ms(Limit::Of(10_000), 5_000), Some(0));
    assert_eq!(cutoff_ms(Limit::Of(u64::MAX), NOW), Some(0));
}
