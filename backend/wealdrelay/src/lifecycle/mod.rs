// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Text compaction: the `DROP` frame and everything it has to survive.
//!
//! `specs/backend/relay/lifecycle.md`. "The relay cannot read content, therefore
//! it cannot decide what is safe to drop, therefore compaction is client-driven."
//! Everything in this module is the enforcement half of a decision made
//! elsewhere: a client signs an instruction, the group authorizes it, and the
//! relay's job is to refuse every version of that instruction that is not
//! exactly what it claims to be.
//!
//! The five refusals, each of which is a real way a customer loses history:
//!
//! - **A frozen group.** A contested successor control freezes text compaction
//!   the way it freezes media collection (`media.md`). A removed member who
//!   forged a successor gets a storage bill for the group, never a deletion.
//! - **A stale epoch.** An instruction signed by an epoch the chain has moved
//!   past is the party removed at that rotation. The signature verifies; the
//!   authority is gone.
//! - **A signature that is not the epoch's verifier.** Anybody can compose CBOR.
//! - **No due authorization.** The verifier is evidence that a member asked. A
//!   threshold-authorized policy or destruction record is what makes it
//!   permission, and it has to be due, not merely present.
//! - **An incomplete manifest.** Every snapshot the checkpoint names has to be an
//!   envelope the relay is holding, before anything is deleted. A checkpoint
//!   whose snapshots are missing is a barrier with nothing behind it, and
//!   dropping under it is how history becomes unverifiable rather than compact.
//!
//! What is never here: a timer, a policy the relay applies on its own, or a
//! configuration that deletes. `WEALD_RELAY_RETENTION_DAYS` "sets a warning
//! threshold, not a deletion".

pub mod store;
pub mod wire;

use std::sync::Arc;

use crate::access;
use crate::frame::{ErrorCode, Frame, FrameError};
use crate::health::RelayState;
use crate::media::retention;
use crate::session::Session;

/// Why an instruction was refused, in the one word the client is told.
///
/// A refusal is a whole answer rather than a partial run: every check below
/// happens before the first delete, so a client that reads any of these knows
/// its history is exactly where it left it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    GroupFrozen,
    NoChain,
    StaleEpoch { latest: u64 },
    BadSignature,
    NoAuthorization,
    AuthorizationNotDue,
    IncompleteManifest { missing: usize },
}

impl Refusal {
    pub fn reason(&self) -> String {
        match self {
            Self::GroupFrozen => "group_frozen".to_string(),
            Self::NoChain => "no_retention_chain".to_string(),
            Self::StaleEpoch { latest } => format!("stale_epoch:{latest}"),
            Self::BadSignature => "bad_signature".to_string(),
            Self::NoAuthorization => "no_authorization".to_string(),
            Self::AuthorizationNotDue => "authorization_not_due".to_string(),
            Self::IncompleteManifest { missing } => format!("incomplete_manifest:{missing}"),
        }
    }
}

/// Handle one `DROP` frame's payload and answer with exactly one `Frame`.
///
/// The same shape as `media::handle`: authorize the group against the session's
/// workspace, do the work, answer once. The caller queues the answer, so a test
/// driving this directly sees the frame a socket would have carried.
pub async fn handle(state: &Arc<RelayState>, session: &Session, payload: Vec<u8>) -> Frame {
    let Ok(record) = wire::DropBefore::decode(&payload) else {
        return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
    };
    let Some(pool) = state.database.as_ref().map(|db| db.pool()) else {
        return Frame::Error(FrameError::new(ErrorCode::Backpressure));
    };
    let Some(workspace) = session.authorized_workspace() else {
        return Frame::Error(FrameError::new(ErrorCode::WriterNotInAccessSet));
    };
    match access::store::workspace_of(pool, &record.group).await {
        Ok(Some(found)) if found == workspace => {}
        Ok(Some(_)) => {
            return Frame::Error(FrameError::new(ErrorCode::WriterNotInAccessSet));
        }
        Ok(None) => return Frame::Error(FrameError::new(ErrorCode::GroupUnknown)),
        Err(_) => return Frame::Error(FrameError::new(ErrorCode::Backpressure)),
    }

    // The relay's own clock, not the host's. `testing.md` forbids a wall-clock
    // read inside anything under test, and every expiry the relay enforces is
    // against the clock it was given: a due date read from somewhere else would
    // be a different relay's opinion of now.
    match drop_before(pool, workspace, &record, state.now_ms() / 1000).await {
        Ok(Ok(outcome)) => Frame::Drop {
            payload: wire::Response::Dropped {
                deleted: outcome.deleted,
                bytes: outcome.bytes,
                kept: outcome.kept,
            }
            .encode(),
        },
        Ok(Err(refusal)) => Frame::Drop {
            payload: wire::Response::Refused {
                reason: refusal.reason(),
            }
            .encode(),
        },
        // A database that could not answer is never a refusal: a refusal is a
        // statement about the instruction, and the relay has not yet formed one.
        //
        // Logged, because the client is told only "come back" and an operator
        // reading that learns nothing. `media::handle_control` does the same for
        // the same reason: without it, a schema fault presents as a compaction
        // that quietly never happens.
        Err(error) => {
            tracing::warn!(error = %error, "lifecycle: drop_before failed");
            Frame::Error(FrameError::new(ErrorCode::Backpressure))
        }
    }
}

/// Verify, authorize and run one instruction.
///
/// `Ok(Err(refusal))` is a verdict about the instruction. `Err(_)` is the relay
/// being unable to look, which is a different answer and is never allowed to read
/// as either a deletion or a refusal.
pub async fn drop_before(
    pool: &sqlx::PgPool,
    workspace: &str,
    record: &wire::DropBefore,
    now: u64,
) -> Result<Result<store::DropOutcome, Refusal>, retention::StoreError> {
    if retention::is_frozen(pool, &record.group).await? {
        return Ok(Err(Refusal::GroupFrozen));
    }
    let Some((latest, verifier)) = retention::latest_control(pool, &record.group).await? else {
        return Ok(Err(Refusal::NoChain));
    };
    if record.epoch != latest {
        return Ok(Err(Refusal::StaleEpoch { latest }));
    }
    if !access::verify(&verifier, &record.signing_bytes(), &record.sig) {
        return Ok(Err(Refusal::BadSignature));
    }

    match authorization(pool, workspace, record, now).await? {
        Authorized::Yes => {}
        Authorized::Missing => return Ok(Err(Refusal::NoAuthorization)),
        Authorized::NotDue => return Ok(Err(Refusal::AuthorizationNotDue)),
    }

    // The manifest and every snapshot it names, checked together and before any
    // deletion, because the whole point of the barrier is that what is beneath it
    // is replaced rather than lost.
    let mut required = Vec::with_capacity(record.snapshots.len() + 1);
    required.push(record.manifest_hash.clone());
    required.extend(record.snapshots.iter().cloned());
    let missing = store::missing_envelopes(pool, &record.group, &required)
        .await
        .map_err(|error| retention::StoreError::Database(error.to_string()))?;
    if !missing.is_empty() {
        return Ok(Err(Refusal::IncompleteManifest {
            missing: missing.len(),
        }));
    }

    // The barrier is the checkpoint's own place in the log, read from the
    // envelope the check above just proved is there. Derived rather than taken
    // from the instruction: `seq` is the relay's numbering and a client that
    // named one would be guessing at a number that decides how much history goes.
    let barrier = store::seq_of(pool, &record.group, &record.manifest_hash)
        .await
        .map_err(|error| retention::StoreError::Database(error.to_string()))?
        .unwrap_or_default();

    let outcome = store::drop_before(
        pool,
        &record.group,
        &record.manifest_hash,
        barrier,
        record.epoch,
        &record.snapshots,
    )
    .await
    .map_err(|error| retention::StoreError::Database(error.to_string()))?;
    Ok(Ok(outcome))
}

enum Authorized {
    Yes,
    Missing,
    NotDue,
}

/// A policy version or a destruction record, and either way it has to be due.
///
/// "The steward ... issues the matching `drop_before` only for material older
/// than the group's already-authorized retention policy. It cannot turn a new
/// checkpoint into an unsupervised deletion authority."
async fn authorization(
    pool: &sqlx::PgPool,
    _workspace: &str,
    record: &wire::DropBefore,
    now: u64,
) -> Result<Authorized, retention::StoreError> {
    if let Some(version) = record.policy_version {
        let Some(policy) = retention::active_policy(pool, &record.group).await? else {
            return Ok(Authorized::Missing);
        };
        if policy.version != version {
            return Ok(Authorized::Missing);
        }
        return Ok(if now >= policy.not_before_secs {
            Authorized::Yes
        } else {
            Authorized::NotDue
        });
    }
    let Some(digest) = &record.destruction_digest else {
        return Ok(Authorized::Missing);
    };
    let Some(destruction) =
        retention::active_destruction(pool, &record.group, DESTRUCTION_KIND, digest).await?
    else {
        return Ok(Authorized::Missing);
    };
    Ok(if now >= destruction.not_before_secs {
        Authorized::Yes
    } else {
        Authorized::NotDue
    })
}

/// The `kind` a one-off compaction authorization carries, which is the string a
/// client puts in its `RetentionDestruction` when it wants to compact now rather
/// than wait for policy.
pub const DESTRUCTION_KIND: &str = "drop_before";
