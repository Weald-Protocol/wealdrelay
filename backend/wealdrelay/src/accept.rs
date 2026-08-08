// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The accept path: what happens to one `SEND`.
//!
//! `specs/backend/relay/operations.md` fixes the shape and the order, and both
//! are load-bearing:
//!
//! - **Duplicate `hash` is resolved before the counter is touched.** A retry
//!   after a dropped connection takes no lock at all and is answered with the
//!   original `seq`. That is what makes `wire.md`'s promise true: a client that
//!   retries is always safe, and never has to renumber an author chain link.
//! - **Sequence assignment is a single `UPDATE ... RETURNING` against a per-group
//!   counter row, inside the same transaction that inserts the envelope.** The
//!   lock is per group, so unrelated groups never contend, and thirty people and a
//!   dozen agents writing into one workspace do not queue behind each other.
//! - **Gaps in `seq` are legal.** A rolled-back transaction leaves one.
//!   Reconciliation runs over the space that exists rather than over a dense
//!   range, and nothing above layer 2 reads `seq` for correctness.
//!
//! - **The workspace's byte budget is checked after the insert and inside the
//!   same transaction.** `crate::log_budget` carries the argument for the order and
//!   for why reaching the budget refuses the write rather than compacting to make
//!   room. What matters here is that the refusal is an error frame: an envelope
//!   the relay dropped quietly would be a hole in an author chain, and the client
//!   would have been told its write succeeded.
//!
//! `seq` is a sync cursor and nothing more. Ordering lives in the Automerge change
//! graph and integrity lives in the author chain, both inside the ciphertext where
//! the relay cannot reach them.

use sqlx::{PgPool, Row};

use crate::config::{Config, MinEncryption, WriteMode};
use crate::envelope::{Envelope, EnvelopeError};
use crate::frame::{ErrorCode, FrameError};

/// What accepting one envelope did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accepted {
    /// Stored now, with this sequence number.
    Stored { seq: u64 },
    /// Already held. The sequence number is the one it was given the first time,
    /// so a client's cursor does not move backwards on a retry.
    Duplicate { seq: u64 },
}

impl Accepted {
    pub fn seq(self) -> u64 {
        match self {
            Self::Stored { seq } | Self::Duplicate { seq } => seq,
        }
    }
}

/// Why an envelope was not accepted. Every variant carries the code the client is
/// answered with, because a `SEND` that failed without one leaves a client unable
/// to tell "do not retry" from "try again shortly".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AcceptError {
    #[error("{0}")]
    Envelope(#[from] EnvelopeError),
    #[error("denied/group_unknown")]
    GroupUnknown,
    #[error("denied/group_frozen")]
    GroupFrozen,
    #[error("denied/service_read_only")]
    ReadOnly,
    /// The workspace's envelope log is at `WEALD_RELAY_MAX_LOG_GB`. Carries the
    /// limit in bytes, which is what the error frame shows the client.
    #[error("quota/log_budget_exhausted: {limit} bytes")]
    LogBudgetExhausted { limit: i64 },
    #[error("retry/backpressure: {0}")]
    Backpressure(String),
}

impl AcceptError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Envelope(error) => error.code(),
            Self::GroupUnknown => ErrorCode::GroupUnknown,
            Self::GroupFrozen => ErrorCode::GroupFrozen,
            Self::ReadOnly => ErrorCode::ServiceReadOnly,
            Self::LogBudgetExhausted { .. } => ErrorCode::LogBudgetExhausted,
            Self::Backpressure(_) => ErrorCode::Backpressure,
        }
    }

    /// The frame the client receives. `group_frozen` carries the state hash the
    /// registry says it carries; the others carry nothing content derived, because
    /// there is nothing here that is not opaque.
    ///
    /// The budget refusal carries its limit, which `operations.md` permits for
    /// the `quota` class and which a client needs in order to say anything useful:
    /// "over the limit" with no limit is a message a person cannot act on. It is a
    /// number an operator configured, so it is not content derived.
    pub fn to_frame(&self) -> FrameError {
        match self {
            Self::LogBudgetExhausted { limit } => {
                FrameError::new(self.code()).detail(crate::log_budget::limit_detail(*limit))
            }
            _ => FrameError::new(self.code()),
        }
    }
}

/// Accept one envelope into one group.
///
/// `now_ms` is injected rather than read from the clock. `testing.md` forbids a
/// wall-clock read inside anything under test, and the relay's own observed time
/// is the authority for every expiry it owns, so the caller that owns the clock
/// passes it in.
pub async fn accept(
    pool: &PgPool,
    config: &Config,
    envelope: &Envelope,
    now_ms: u64,
) -> Result<Accepted, AcceptError> {
    if matches!(config.write_mode, WriteMode::ReadOnly) {
        // Refused before any validation work: a relay in maintenance is not going
        // to store this whatever it says, and hashing a megabyte first would be
        // work done for an answer already decided.
        return Err(AcceptError::ReadOnly);
    }
    envelope.validate(config.min_encryption)?;

    // The duplicate check first, and outside any transaction. A retry is then a
    // single indexed read and takes no lock, which is the property that lets a
    // client resend verbatim without thinking about it.
    if let Some(seq) = existing_seq(pool, &envelope.group, &envelope.hash).await? {
        return Ok(Accepted::Duplicate { seq });
    }

    let mut transaction = pool.begin().await.map_err(backpressure)?;

    // The counter row and the group's state in one statement, and the row is
    // locked for the length of the transaction by the update itself. A separate
    // existence check would be a read the insert could then race.
    let claimed = sqlx::query(
        "update relay_group set next_seq = next_seq + 1 \
         where group_id = $1 returning next_seq - 1 as seq, frozen_reason, workspace_id",
    )
    .bind(&envelope.group)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(backpressure)?;

    let Some(row) = claimed else {
        return Err(AcceptError::GroupUnknown);
    };
    if row
        .try_get::<Option<String>, _>("frozen_reason")
        .map_err(backpressure)?
        .is_some()
    {
        // Rolled back rather than committed, which spends a sequence number on
        // nothing. That is deliberate and is why gaps are legal: the alternative is
        // reading the group's state before claiming a number, which is a race.
        return Err(AcceptError::GroupFrozen);
    }
    let seq: i64 = row.try_get("seq").map_err(backpressure)?;

    let inserted = sqlx::query(
        "insert into relay_envelope (group_id, hash, v, enc, epoch, seq, ts, ct) \
         values ($1, $2, $3, $4, $5, $6, $7, $8) on conflict do nothing",
    )
    .bind(&envelope.group)
    .bind(&envelope.hash)
    .bind(i16::from(envelope.v))
    .bind(envelope.enc as i16)
    .bind(envelope.epoch as i64)
    .bind(seq)
    .bind(now_ms as i64)
    .bind(&envelope.ct)
    .execute(&mut *transaction)
    .await
    .map_err(backpressure)?;

    if inserted.rows_affected() == 0 {
        // Another connection stored the same content address between the check
        // above and this insert. Not an error: the client is told the sequence
        // number the winner was given, which is the same answer it would have got a
        // moment earlier.
        transaction.rollback().await.map_err(backpressure)?;
        let seq = existing_seq(pool, &envelope.group, &envelope.hash)
            .await?
            // The row is there: `on conflict do nothing` fired on its primary key,
            // and the transaction that wrote it has committed by the time this
            // read runs. A missing row here would mean the winner rolled back
            // after conflicting, which cannot happen in one statement.
            .unwrap_or(seq as u64);
        return Ok(Accepted::Duplicate { seq });
    }

    // The budget, checked after the insert and inside the same transaction.
    //
    // Deliberately in that order, and it is the only order that is exact. The
    // counter is maintained by a trigger on this very insert
    // (`migrations/0010_envelope_budget.sql`), so reading it here reads the total
    // this envelope produced, and the row it updated is locked until this
    // transaction ends. Two writers racing for a workspace's last few bytes
    // therefore serialize on that row and the second one sees the first one's
    // bytes, which is the property a check-then-insert cannot have at any
    // isolation level Postgres offers by default.
    //
    // The cost of being exact is that an over-budget write does the insert work
    // and then rolls it back. That is the cheap side of the trade: the workspace
    // is at its ceiling, so the path is not hot, and the alternative is a
    // workspace that overshoots by one megabyte per concurrent writer.
    //
    // Skipped entirely when unlimited, which is the self-hoster's default: no
    // limit means no read, so nobody pays for a ceiling they did not set.
    if let Some(limit) = crate::log_budget::limit_bytes(config) {
        let workspace: String = row.try_get("workspace_id").map_err(backpressure)?;
        let used: i64 =
            sqlx::query_scalar("select used_bytes from relay_log_budget where workspace_id = $1")
                .bind(&workspace)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(backpressure)?
                // The trigger inserted the row as part of this transaction, so it is
                // there. Zero is the honest answer if it somehow is not, and it makes
                // this arm a refusal-free path rather than a failed `SEND`: an accounting
                // row that vanished must not cost a customer their write.
                .unwrap_or(0);
        // `used` already includes this envelope, so the comparison is against the
        // total after the write, and `charge` is zero here for that reason.
        if crate::log_budget::over_budget(used, 0, Some(limit)) {
            transaction.rollback().await.map_err(backpressure)?;
            return Err(AcceptError::LogBudgetExhausted { limit });
        }
    }

    transaction.commit().await.map_err(backpressure)?;
    Ok(Accepted::Stored { seq: seq as u64 })
}

async fn existing_seq(
    pool: &PgPool,
    group: &[u8],
    hash: &[u8],
) -> Result<Option<u64>, AcceptError> {
    let row = sqlx::query("select seq from relay_envelope where group_id = $1 and hash = $2")
        .bind(group)
        .bind(hash)
        .fetch_optional(pool)
        .await
        .map_err(backpressure)?;
    Ok(row
        .map(|row| row.try_get::<i64, _>("seq"))
        .transpose()
        .map_err(backpressure)?
        .map(|seq| seq as u64))
}

/// Every database failure on this path is `retry/backpressure`.
///
/// `operations.md`: `SEND` never returns `retry` for contention, only for
/// infrastructure, which is the property the absence of a head chain buys. A
/// database that is saturated or gone is infrastructure, and the client's correct
/// response is backoff and a verbatim resend.
fn backpressure(error: sqlx::Error) -> AcceptError {
    AcceptError::Backpressure(crate::logging::scrub(&error.to_string()))
}

/// The encryption floor as the relay reports it, for the `CONNECT` acknowledgement.
pub fn floor_byte(floor: MinEncryption) -> u8 {
    match floor {
        MinEncryption::None => 0,
        MinEncryption::Mls => 1,
    }
}
