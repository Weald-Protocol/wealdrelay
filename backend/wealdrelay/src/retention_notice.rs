// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The `WEALD_RELAY_RETENTION_DAYS` warning threshold, made real.
//!
//! `specs/backend/relay/lifecycle.md:293` settles what this variable is: "retention
//! **warns**, the budget **refuses**, and a signed `drop_before` behind an accepted
//! checkpoint is the only thing that **deletes**". So this module never deletes an
//! envelope, and it must not: `lifecycle.md:311-316` says the relay "never drops an
//! envelope on its own initiative, never expires by policy, and has no retention
//! configuration that acts without a signed instruction".
//!
//! What it does is close the drift the setting had before it existed. The value was
//! parsed, validated and printed back by `--check-config`, and no code path read it,
//! so an operator who set 30 read `30` out of the relay's own table and learned
//! nothing at all: not that history was deleted (it is not), and not that anything
//! was past the window either. `config.rs` calls that the worst case of all, "a
//! setting the binary accepts and does not honour".
//!
//! The pass is one aggregate query per relay, run from `janitor`, that reports how
//! many envelopes and how many workspaces sit older than the window, and how old the
//! oldest one is. That is the whole guarantee the variable makes, and it is now one
//! an operator can observe.
//!
//! ## Why the log line names no group
//!
//! Same rule as every other collector line (`janitor`): a per-group count would put
//! a group id in the log on every interval, which is the identifier `logging.rs`
//! scrubs. Workspace *count* rather than workspace ids, for the same reason.

use sqlx::{PgPool, Row};

use crate::config::Limit;

/// Milliseconds in a day, as the relay's `ts` column counts them.
const MS_PER_DAY: u64 = 24 * 60 * 60 * 1000;

/// What one warning pass found.
///
/// `Default` is the "nothing to say" case, which is also what an unlimited
/// retention setting and a failed query both produce: this pass never turns a
/// database hiccup into a false all-clear *and* never turns it into a fake alarm,
/// it just reports nothing and the next interval is the retry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct Overdue {
    /// Envelopes whose relay receipt time is older than the window.
    pub envelopes: u64,
    /// How many distinct workspaces those envelopes belong to.
    pub workspaces: u64,
    /// Age of the oldest such envelope, in whole days. Zero when `envelopes` is
    /// zero, and always at least the configured window otherwise.
    pub oldest_days: u64,
}

impl Overdue {
    /// Whether this pass has anything worth logging.
    pub fn is_empty(&self) -> bool {
        self.envelopes == 0
    }
}

/// The cutoff timestamp for a window, or `None` when the operator set no window.
///
/// Saturating, so a relay whose clock is younger than the window (a fresh test
/// clock, or a container started at epoch zero) reports nothing rather than
/// wrapping into a cutoff far in the future that would call every envelope
/// overdue.
pub fn cutoff_ms(retention_days: Limit, now_ms: u64) -> Option<u64> {
    match retention_days {
        Limit::Unlimited => None,
        Limit::Of(days) => Some(now_ms.saturating_sub(days.saturating_mul(MS_PER_DAY))),
    }
}

/// Count what is past the window. Never deletes.
pub async fn overdue(pool: &PgPool, retention_days: Limit, now_ms: u64) -> Overdue {
    let Some(cutoff) = cutoff_ms(retention_days, now_ms) else {
        return Overdue::default();
    };
    let row = sqlx::query(
        "select count(*)::bigint as envelopes, \
                count(distinct g.workspace_id)::bigint as workspaces, \
                coalesce(min(e.ts), 0)::bigint as oldest_ts \
         from relay_envelope e \
         join relay_group g on g.group_id = e.group_id \
         where e.ts < $1",
    )
    .bind(cutoff as i64)
    .fetch_one(pool)
    .await;
    let row = match row {
        Ok(row) => row,
        Err(error) => {
            tracing::warn!(
                error = %crate::logging::scrub(&error.to_string()),
                "could not measure the retention window"
            );
            return Overdue::default();
        }
    };
    let envelopes = row.try_get::<i64, _>("envelopes").unwrap_or(0).max(0) as u64;
    if envelopes == 0 {
        return Overdue::default();
    }
    let workspaces = row.try_get::<i64, _>("workspaces").unwrap_or(0).max(0) as u64;
    let oldest_ts = row.try_get::<i64, _>("oldest_ts").unwrap_or(0).max(0) as u64;
    Overdue {
        envelopes,
        workspaces,
        oldest_days: now_ms.saturating_sub(oldest_ts) / MS_PER_DAY,
    }
}
