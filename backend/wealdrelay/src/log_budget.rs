// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The per-workspace byte budget on the envelope log.
//!
//! `WEALD_RELAY_MAX_STORAGE_GB` bounds media and nothing else, and
//! `WEALD_RELAY_RETENTION_DAYS` is a warning threshold rather than a deletion
//! (`specs/backend/relay/lifecycle.md`), so it is a time bound that does nothing
//! at all inside its own window. Between them the envelope log had no ceiling:
//! one workspace could fill a relay's Postgres, on the store that costs twenty
//! times what the bucket costs, while sitting inside every limit the relay
//! enforced (`specs/backend/cloud/instance-sizing.md`).
//!
//! This module is the accounting half. The refusal is in `crate::accept`, the
//! counter is maintained by the triggers in `migrations/0010_envelope_budget.sql`,
//! and the workspace is resolved exactly the way `access::store::workspace_of`
//! resolves it: from `relay_group`, never from anything a client said.
//!
//! ## The boundary between the budget and retention
//!
//! **Reaching the budget refuses writes. It never compacts.** The two levers look
//! adjacent and are not the same kind of thing:
//!
//! - Compaction is client-driven, signed, and authorized by the group
//!   (`lifecycle.md`: the relay "cannot read content, therefore it cannot decide
//!   what is safe to drop"). A budget that compacted to make room would be the
//!   relay deleting history on its own initiative, under load, choosing the
//!   victim itself, without the checkpoint that makes the remainder verifiable.
//!   That is the exact failure `lifecycle.md` is written to prevent, and it would
//!   arrive at the worst moment: when a workspace is busy.
//! - A refusal is recoverable and a deletion is not. `lifecycle.md` already
//!   chooses that trade for the frozen case ("the failure mode is a storage bill,
//!   which is recoverable, rather than history a departing member arranged to have
//!   deleted, which is not"). The budget makes the same choice for the same
//!   reason.
//!
//! So the two meet without overlapping: retention *warns*, the budget *refuses*,
//! and compaction (a signed `drop_before` behind an accepted checkpoint) is the
//! only thing that deletes. The refusal names that lever, which is why it is
//! `quota/log_budget_exhausted` and not `quota/storage_exhausted`: a client shown
//! the media error would offer the wrong remedy.
//!
//! A dropped envelope is never an option here. Silently discarding a `SEND` the
//! relay acknowledged would leave a hole in an author chain that every receiving
//! client would detect and none could repair, so over budget is an error frame
//! and the client's write is still its own.

use sqlx::{PgPool, Row};

use crate::config::{Config, Limit};

/// A gigabyte, decimally.
///
/// The same constant `media::limit_bytes` uses and the same one `pricing.ts
/// BYTES_PER_GB` uses. `instance-sizing.md` records what it cost to have two of
/// these: the meter rated 1024^3 while the relay enforced 10^9, so the ceiling
/// fired 7.4 percent below the allowance it was supposed to be.
pub const BYTES_PER_GB: i64 = 1_000_000_000;

/// The configured ceiling in bytes, or `None` for unlimited.
///
/// Unlimited is the default and is the self-hoster's posture: an operator who
/// owns the disk decides what to do with it, and a relay that refused writes on a
/// machine with terabytes free would be enforcing our pricing on somebody who is
/// not our customer. The hosted provisioner always sets a number.
pub fn limit_bytes(config: &Config) -> Option<i64> {
    match config.max_log_gb {
        Limit::Unlimited => None,
        Limit::Of(gb) => Some((gb as i64).saturating_mul(BYTES_PER_GB)),
    }
}

/// What one envelope costs against the budget.
///
/// `ct` alone, which is what `relay_envelope`'s trigger counts and what
/// `instance-sizing.md` identifies as the only line that matters: the eight
/// header fields are about 135 bytes of dense heap row and the payload is out of
/// line already. Counting the headers too would make the number the relay
/// enforces differ from the number the meter bills, for a rounding error.
pub fn charge_of(ciphertext: &[u8]) -> i64 {
    ciphertext.len() as i64
}

/// Why a budget read could not answer.
#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    #[error("log budget: {0}")]
    Database(String),
}

fn db(error: sqlx::Error) -> BudgetError {
    BudgetError::Database(crate::logging::scrub(&error.to_string()))
}

/// What one workspace's envelope log currently occupies, in bytes.
///
/// Reads the counter, which the triggers keep equal to the sum. A workspace with
/// no row has written nothing and occupies nothing: the row is created by the
/// first insert rather than by a provisioning step, so there is no state a relay
/// can be in where a legitimate workspace is missing its accounting.
pub async fn used_bytes(pool: &PgPool, workspace: &str) -> Result<i64, BudgetError> {
    let row = sqlx::query("select used_bytes from relay_log_budget where workspace_id = $1")
        .bind(workspace)
        .fetch_optional(pool)
        .await
        .map_err(db)?;
    match row {
        Some(row) => row.try_get::<i64, _>("used_bytes").map_err(db),
        None => Ok(0),
    }
}

/// The same number computed the expensive way: the actual sum over the rows.
///
/// Not on any hot path, and deliberately not used by the accept path. It exists
/// so that "the counter equals the sum" is a claim a test can check after any
/// sequence of writes and compactions rather than a claim the triggers assert
/// about themselves, and so an operator with a suspicious counter has one query
/// that settles it.
pub async fn summed_bytes(pool: &PgPool, workspace: &str) -> Result<i64, BudgetError> {
    let sum: i64 = sqlx::query_scalar(
        "select coalesce(sum(octet_length(e.ct)), 0)::bigint \
         from relay_envelope e \
         join relay_group g on g.group_id = e.group_id \
         where g.workspace_id = $1",
    )
    .bind(workspace)
    .fetch_one(pool)
    .await
    .map_err(db)?;
    Ok(sum)
}

/// Would a workspace holding `used` bytes be over `limit` after writing `charge`?
///
/// One function so the accept path and every test mean the same thing by "over".
/// The comparison is on the total *after* the write, not before it, which is what
/// makes the last accepted envelope the one that reaches the budget rather than
/// the one that exceeds it: a budget checked before the write lets a workspace
/// finish one megabyte past its ceiling, and `ct` is capped at exactly one
/// megabyte, so that overshoot is not theoretical.
///
/// Saturating, because the sum of two `i64` byte counts is only unrepresentable
/// in a database nobody has, and an overflow that wrapped negative would read as
/// "plenty of room" at exactly the moment there is none.
pub fn over_budget(used: i64, charge: i64, limit: Option<i64>) -> bool {
    match limit {
        None => false,
        Some(limit) => used.saturating_add(charge) > limit,
    }
}

/// The limit as the error frame carries it: eight bytes, big-endian.
///
/// `operations.md` lets a `quota` error carry the limit, and the client renders
/// it. Big-endian and fixed width rather than a decimal string, because every
/// other non-content detail on this wire is a fixed-width integer and a client
/// parsing one field differently from the rest is a bug waiting for a locale.
pub fn limit_detail(limit: i64) -> Vec<u8> {
    limit.to_be_bytes().to_vec()
}
