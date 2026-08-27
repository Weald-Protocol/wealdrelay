// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The retention control chain: evidence, authorization, and the successor-race
//! freeze.
//!
//! `specs/backend/relay/media.md`. Two authorities, deliberately never merged
//! into one:
//!
//! - The epoch-derived **verifier** chain (`RetentionControl`, `RetentionManifest`)
//!   proves a current group member produced a complete view. The relay can check
//!   it without learning anything about membership, but it is evidence, not
//!   permission: "It cannot safely decide that the group intended to destroy
//!   data".
//! - A **threshold-authorized** record (`RetentionPolicy`, `RetentionDestruction`),
//!   checked against the workspace's access-set `authorizers`, is what actually
//!   permits deletion.
//!
//! A blob is only ever a garbage-collection candidate once both have said yes:
//! `gc::eligible` reads both halves and neither alone.

use sqlx::{PgPool, Row};

use super::wire::{RetentionControl, RetentionDestruction, RetentionManifest, RetentionPolicy};
use crate::access;

/// Why a store call could not answer.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("retention store: {0}")]
    Database(String),
}

fn db(error: sqlx::Error) -> StoreError {
    StoreError::Database(error.to_string())
}

/// What accepting a `RetentionControl` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlOutcome {
    /// The first, or an exact retransmission of the one already on file.
    Accepted,
    /// A second, differently signed control for an epoch already settled. The
    /// group is now frozen and this is stored purely as evidence.
    ConflictFroze,
    /// A second, differently signed control for a group already frozen by an
    /// earlier conflict at this epoch.
    ConflictAlreadyFrozen,
    Invalid(&'static str),
}

/// Verify and, if it holds, apply one `RetentionControl`.
///
/// Epoch 0 is the genesis case: `media.md` says it "is emitted by the group
/// creator with the first epoch's verifier", so its authority is the verifier
/// signing for itself. That self-signature is a possession proof and nothing
/// more, and WEALD-L183 is the record of what it is not: any party who can
/// reach this function can mint a keypair and sign for it, so on its own it
/// binds the record to a key rather than to the group. Two things bind it to
/// the group, and both are required.
///
/// The first is the caller's: `media::handle_control` admits the frame only
/// from a device the workspace's *current access set* names
/// (`access::store::Admission::InSet`), never from a provisional grant and
/// never from a device an offboarding commit dropped. The relay holds no
/// per-group roster by construction (`wire.md`: "the relay serves any group in
/// the workspace to any device in the access set, because proving group
/// membership to the relay would leak the membership graph"), so the access set
/// is the group's access set as far as this process can ever know.
///
/// The second is here: a genesis control is the chain's root and a root is
/// claimed once. A second, differently signed epoch-0 record is refused
/// outright and, crucially, does **not** freeze. Freezing on a genesis conflict
/// was a permanent denial of service any admitted device could trigger against
/// any group id in its workspace, one frame per group, and the freeze it set
/// disabled every retention policy, tombstone and sweep for that group. There
/// is no legitimate second genesis: unlike a successor race, where both
/// claimants proved possession of the prior epoch's verifier and the relay
/// genuinely cannot tell them apart, an epoch-0 claimant proved possession of
/// nothing the group ever asserted. The settled row stands and the impostor is
/// told the record is malformed.
///
/// Every later epoch must be signed by the *prior* epoch's verifier and must
/// name that control's digest, which is the chain `groups.md`'s epoch rotation
/// and this module's freeze rule both depend on. Those conflicts still freeze,
/// which is what `media.md`'s successor-race section asks for.
pub async fn apply_control(
    pool: &PgPool,
    record: &RetentionControl,
) -> Result<ControlOutcome, StoreError> {
    let signing_bytes = record.signing_bytes();
    let authority: Vec<u8> = if record.epoch == 0 {
        if record.prev_control_hash.is_some() {
            return Ok(ControlOutcome::Invalid(
                "genesis control names a predecessor",
            ));
        }
        record.verifier.clone()
    } else {
        let Some(prior) = control_at(pool, &record.group, record.epoch - 1).await? else {
            return Ok(ControlOutcome::Invalid("no control for the prior epoch"));
        };
        let Some(named) = &record.prev_control_hash else {
            return Ok(ControlOutcome::Invalid(
                "non-genesis control names no predecessor",
            ));
        };
        if named != &prior.digest {
            return Ok(ControlOutcome::Invalid(
                "prev_control_hash does not match the prior epoch's control",
            ));
        }
        prior.verifier
    };
    if !access::verify(&authority, &signing_bytes, &record.sig) {
        return Ok(ControlOutcome::Invalid("signature does not verify"));
    }

    if let Some(existing) = control_at(pool, &record.group, record.epoch).await? {
        if is_the_same_control(
            &existing.verifier,
            existing.prev_control_hash.as_deref(),
            &existing.sig,
            record,
        ) {
            return Ok(ControlOutcome::Accepted);
        }
        if record.epoch == 0 {
            return Ok(ControlOutcome::Invalid(
                "group already has a genesis control",
            ));
        }
        return record_conflict_and_freeze(pool, record).await;
    }

    // `on conflict do nothing` rather than the plain insert this used to be, because
    // the read above and this insert are not one atomic step: two distinct valid
    // successors can both pass the read seeing no row, and without this clause the
    // loser's insert would fail on the `(group_id, epoch)` primary key with a bare
    // database error, never reaching the freeze path that exists exactly for this
    // race. `returning group_id` tells the two callers apart: a row back means this
    // insert was the one that won.
    let inserted = sqlx::query(
        "insert into relay_retention_control \
         (group_id, epoch, verifier, prev_control_hash, sig, signer_note) \
         values ($1, $2, $3, $4, $5, $6) \
         on conflict (group_id, epoch) do nothing \
         returning group_id",
    )
    .bind(&record.group)
    .bind(record.epoch as i64)
    .bind(&record.verifier)
    .bind(record.prev_control_hash.as_deref())
    .bind(&record.sig)
    .bind(if record.epoch == 0 {
        "genesis"
    } else {
        "rotation"
    })
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    if inserted.is_some() {
        return Ok(ControlOutcome::Accepted);
    }

    // Lost the race: some other insert landed between the read above and this
    // statement. Re-read the row that actually won and judge this record against
    // it exactly as the pre-existing-row branch above does, so the loser of a race
    // is frozen and recorded rather than silently refused.
    let Some(winner) = control_at(pool, &record.group, record.epoch).await? else {
        return Err(StoreError::Database(
            "on conflict do nothing left no row to read back".to_string(),
        ));
    };
    if is_the_same_control(
        &winner.verifier,
        winner.prev_control_hash.as_deref(),
        &winner.sig,
        record,
    ) {
        return Ok(ControlOutcome::Accepted);
    }
    // Same rule as the pre-insert branch, for the same reason: losing a genesis
    // race to a different verifier is a refusal, not a freeze.
    if record.epoch == 0 {
        return Ok(ControlOutcome::Invalid(
            "group already has a genesis control",
        ));
    }
    record_conflict_and_freeze(pool, record).await
}

/// A genuine conflict for an epoch some other control already settled. Recorded
/// as evidence and never allowed to replace the settled row, which is what
/// "first valid wins" means in practice: the winner was decided by whichever
/// insert landed first, and nothing here reopens that.
async fn record_conflict_and_freeze(
    pool: &PgPool,
    record: &RetentionControl,
) -> Result<ControlOutcome, StoreError> {
    sqlx::query(
        "insert into relay_retention_control_conflict \
         (group_id, epoch, verifier, prev_control_hash, sig) values ($1, $2, $3, $4, $5)",
    )
    .bind(&record.group)
    .bind(record.epoch as i64)
    .bind(&record.verifier)
    .bind(record.prev_control_hash.as_deref())
    .bind(&record.sig)
    .execute(pool)
    .await
    .map_err(db)?;
    let already_frozen = freeze(pool, &record.group, "retention control conflict").await?;
    Ok(if already_frozen {
        ControlOutcome::ConflictAlreadyFrozen
    } else {
        ControlOutcome::ConflictFroze
    })
}

struct Control {
    verifier: Vec<u8>,
    prev_control_hash: Option<Vec<u8>>,
    sig: Vec<u8>,
    digest: Vec<u8>,
}

/// Whether a stored control record and an incoming one are the same record.
///
/// A retry has to be told apart from a conflict, because the answers are opposite:
/// a retry is accepted silently and a conflict freezes the group's garbage
/// collection until a member resolves it. Freezing on an ordinary reconnect would
/// be a bug with a customer-visible cost, and treating a genuine second claim as a
/// retry would be the far worse one.
///
/// Extracted from `apply_control` rather than left inline, and the reason is worth
/// recording because it is not tidiness. Two of these three comparisons cannot
/// disagree by the time `apply_control` reaches them: the predecessor was already
/// forced equal to the prior epoch's digest, and Ed25519 signing is deterministic,
/// so the same key over the same bytes cannot produce a second, different
/// signature. Inline, that made two branch edges unreachable through any input a
/// test could construct, and the choice was between deleting a real check and
/// excluding it from the coverage floor.
///
/// Neither was right, because the checks are not redundant. `access::verify` is not
/// the strict verifier, so a malleated signature over the same fields can verify
/// while differing byte for byte, and the roster row it would silently overwrite is
/// the one deciding who governs a group's retention. As a pure function the whole
/// truth table is reachable, so the defence is kept and it is proven.
///
/// **This comparison was briefly relaxed to ignore the signature, and that was
/// wrong.** The symptom was real: a client republishing its own control froze its
/// own group on the second launch, because CryptoKit randomises
/// `Curve25519.Signing` and Ed25519 is only deterministic in RFC 8032, not in
/// every implementation of it. But the relay was right and the client was wrong,
/// and relaxing this hid a worse bug rather than fixing one. A successor names its
/// predecessor by `digest`, and the digest covers the signature: a client that
/// re-signs its own genesis record computes a different digest, so the epoch-1
/// record it publishes names a predecessor the relay has never held and the chain
/// can never advance past epoch zero. The fix is that a client publishes the
/// record it published before, byte for byte
/// (`Sources/Sync/RetentionKeyStore.swift`), which makes a retransmission
/// identical and leaves this check free to catch the thing it is for.
pub fn is_the_same_control(
    existing_verifier: &[u8],
    existing_prev: Option<&[u8]>,
    existing_sig: &[u8],
    record: &RetentionControl,
) -> bool {
    existing_verifier == record.verifier
        && existing_prev == record.prev_control_hash.as_deref()
        && existing_sig == record.sig
}

/// The newest epoch of a group's retention chain, and the verifier that signs
/// for it.
///
/// Public because the chain has two consumers now: the media manifests here, and
/// text compaction in `crate::lifecycle`, which is signed with the same key for
/// the same reason (`specs/backend/relay/lifecycle.md`, "signed with the
/// relay-verifiable retention signing key"). One chain, one place it is read.
///
/// The two facts are answered together rather than by two calls, and that is not
/// tidiness: asked separately, the second call has a "no control at the epoch the
/// first one just reported" arm that no database state can produce, and an arm
/// nothing can reach is an arm nothing has checked. One statement, one answer,
/// and the caller's only question is whether the chain exists at all.
///
/// The transition check a `drop_before` is held to is then the caller's: an
/// instruction signed by an epoch older than this one is a member who was removed
/// at that rotation, which is precisely the party the successor rules exist to
/// keep away from deletion authority.
pub async fn latest_control(
    pool: &PgPool,
    group: &[u8],
) -> Result<Option<(u64, Vec<u8>)>, StoreError> {
    let row = sqlx::query(
        "select epoch, verifier from relay_retention_control \
         where group_id = $1 order by epoch desc limit 1",
    )
    .bind(group)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    let Some(row) = row else { return Ok(None) };
    let epoch: i64 = row.try_get("epoch").map_err(db)?;
    let verifier: Vec<u8> = row.try_get("verifier").map_err(db)?;
    Ok(Some((epoch as u64, verifier)))
}

async fn control_at(
    pool: &PgPool,
    group: &[u8],
    epoch: u64,
) -> Result<Option<Control>, StoreError> {
    let row = sqlx::query(
        "select verifier, prev_control_hash, sig from relay_retention_control \
         where group_id = $1 and epoch = $2",
    )
    .bind(group)
    .bind(epoch as i64)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    let Some(row) = row else { return Ok(None) };
    let verifier: Vec<u8> = row.try_get("verifier").map_err(db)?;
    let prev_control_hash: Option<Vec<u8>> = row.try_get("prev_control_hash").map_err(db)?;
    let sig: Vec<u8> = row.try_get("sig").map_err(db)?;
    let record = RetentionControl {
        group: group.to_vec(),
        epoch,
        verifier: verifier.clone(),
        prev_control_hash: prev_control_hash.clone(),
        sig: sig.clone(),
    };
    Ok(Some(Control {
        verifier,
        prev_control_hash,
        sig,
        digest: record.digest(),
    }))
}

/// Set a group's freeze reason if it is not already set. Returns whether it was
/// already frozen, so the caller can tell a fresh freeze from a repeat conflict.
async fn freeze(pool: &PgPool, group: &[u8], reason: &str) -> Result<bool, StoreError> {
    let row = sqlx::query(
        "update relay_group set frozen_reason = $2 where group_id = $1 and frozen_reason is null \
         returning group_id",
    )
    .bind(group)
    .bind(reason)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    Ok(row.is_none())
}

pub async fn is_frozen(pool: &PgPool, group: &[u8]) -> Result<bool, StoreError> {
    let row = sqlx::query("select frozen_reason from relay_group where group_id = $1")
        .bind(group)
        .fetch_optional(pool)
        .await
        .map_err(db)?;
    Ok(match row {
        Some(row) => row
            .try_get::<Option<String>, _>("frozen_reason")
            .map_err(db)?
            .is_some(),
        None => false,
    })
}

/// Only a client can clear a freeze (`media.md`): this is that one narrow
/// action, performed with no interpretation of the resolution's content beyond
/// "a member with the true epoch secret said so", which is a claim the relay
/// cannot verify and is not asked to.
pub async fn clear_freeze(pool: &PgPool, group: &[u8]) -> Result<(), StoreError> {
    sqlx::query("update relay_group set frozen_reason = null where group_id = $1")
        .bind(group)
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(())
}

/// What resolving one `RetentionResolution` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// The freeze is cleared. Also returned when the group was not frozen at
    /// all, since applying an already-applied resolution is not an error.
    Cleared,
    /// The signature does not verify against the verifier the record names.
    BadSignature,
    /// `verifier` is not one of the candidates on file for this `(group,
    /// epoch)` — neither the settled control nor a recorded conflict — so
    /// this is not a genuine resolution of *this* freeze.
    UnknownVerifier,
}

/// Apply one `RetentionResolution` (`media.md`'s "any member holding the true
/// epoch secret publishes a signed resolution naming which control is
/// genuine").
///
/// The resolution is self-signed by the verifier it names, exactly like a
/// genesis `RetentionControl`: the relay checks that the signature verifies
/// against `record.verifier`, and that `verifier` matches a candidate already
/// on record for this epoch (the winner in `relay_retention_control` or a
/// loser in `relay_retention_control_conflict`). That is all the relay is
/// positioned to check — it has no MLS state and cannot tell which candidate
/// is the group's true successor, only that the caller derives one of the
/// candidates it already saw asserted for this epoch, which is the same
/// "current member" proof a genesis control carries.
pub async fn resolve_freeze(
    pool: &PgPool,
    record: &super::wire::RetentionResolution,
) -> Result<ResolveOutcome, StoreError> {
    if !crate::access::verify(&record.verifier, &record.signing_bytes(), &record.sig) {
        return Ok(ResolveOutcome::BadSignature);
    }
    let known = if let Some(control) = control_at(pool, &record.group, record.epoch).await? {
        control.verifier == record.verifier
    } else {
        false
    } || sqlx::query(
        "select 1 from relay_retention_control_conflict \
         where group_id = $1 and epoch = $2 and verifier = $3 limit 1",
    )
    .bind(&record.group)
    .bind(record.epoch as i64)
    .bind(&record.verifier)
    .fetch_optional(pool)
    .await
    .map_err(db)?
    .is_some();
    if !known {
        return Ok(ResolveOutcome::UnknownVerifier);
    }
    clear_freeze(pool, &record.group).await?;
    Ok(ResolveOutcome::Cleared)
}

/// What accepting a `RetentionManifest` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestOutcome {
    Accepted { digest: Vec<u8> },
    Invalid(String),
}

/// Verify and, if it holds, apply one `RetentionManifest`, claiming every hash it
/// names.
///
/// `claim` is idempotent, so a manifest re-naming a hash an earlier manifest
/// already claimed costs nothing extra; a manifest that finally drops a
/// previously claimed hash is exactly the "omission" `media.md`'s deletion rule
/// reads, which `gc::eligible` checks by re-reading the latest manifest rather
/// than by anything recorded here.
/// The sequence a group's **first** manifest must name.
///
/// One, not zero. Named rather than written into the expression it is used in
/// because the client has to agree with it exactly and disagreed silently: a first
/// manifest numbered zero is refused, `handle_manifest` reports that as
/// `reject/malformed_header`, and two tickets (WEALD-L333, WEALD-L336) were then
/// spent on the header codec, which had always agreed.
/// `Sources/Sync/RetentionManifest.swift` is the other half.
pub const FIRST_MANIFEST_SEQUENCE: u64 = 1;

pub async fn apply_manifest(
    pool: &PgPool,
    workspace: &str,
    record: &RetentionManifest,
) -> Result<ManifestOutcome, StoreError> {
    let reject = |reason: &str| reason.to_string();
    // The transition check `latest_control` delegates to its callers, made here
    // for the same reason `lifecycle::drop_before` makes it: a manifest signed by
    // an older epoch is a member removed at that rotation, and an omission from
    // the newest manifest is what `gc::eligible` reads as permission to delete.
    let Some((latest_epoch, verifier)) = latest_control(pool, &record.group).await? else {
        let reason = reject("no retention control for this group");
        reject_manifest(pool, record, &reason).await?;
        return Ok(ManifestOutcome::Invalid(reason));
    };
    if record.epoch != latest_epoch {
        let reason = reject("manifest epoch is not the group's latest epoch");
        reject_manifest(pool, record, &reason).await?;
        return Ok(ManifestOutcome::Invalid(reason));
    }
    if !access::verify(&verifier, &record.signing_bytes(), &record.sig) {
        let reason = reject("signature does not verify against the epoch verifier");
        reject_manifest(pool, record, &reason).await?;
        return Ok(ManifestOutcome::Invalid(reason));
    }

    let latest = latest_manifest(pool, &record.group).await?;
    let expected_sequence = latest
        .as_ref()
        .map_or(FIRST_MANIFEST_SEQUENCE, |m| m.sequence + 1);
    if record.sequence != expected_sequence {
        let reason = reject("sequence does not advance by exactly one");
        reject_manifest(pool, record, &reason).await?;
        return Ok(ManifestOutcome::Invalid(reason));
    }
    let expected_prev = latest.as_ref().map(|m| m.digest.clone());
    if record.prev_manifest_hash != expected_prev {
        let reason = reject("prev_manifest_hash does not match the latest manifest");
        reject_manifest(pool, record, &reason).await?;
        return Ok(ManifestOutcome::Invalid(reason));
    }

    let digest = record.digest();
    // The manifest row and every claim it names, in one transaction. `media.md`
    // makes an accepted manifest the boundary after which a named blob is no longer
    // an unclaimed-upload candidate, so a manifest that is durable while one of its
    // claims is not is a named object the collector may still delete, and an exact
    // retry cannot repair it because the sequence check refuses the second attempt
    // (BR-040). Either the whole boundary moves or none of it does.
    let mut tx = pool.begin().await.map_err(db)?;
    sqlx::query(
        "insert into relay_retention_manifest \
         (group_id, sequence, epoch, prev_manifest_hash, blobs, sig, digest) \
         values ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&record.group)
    .bind(record.sequence as i64)
    .bind(record.epoch as i64)
    .bind(record.prev_manifest_hash.as_deref())
    .bind(&record.blobs)
    .bind(&record.sig)
    .bind(&digest)
    .execute(&mut *tx)
    .await
    .map_err(db)?;

    for hash in &record.blobs {
        super::store::claim_in(&mut tx, workspace, &record.group, hash)
            .await
            .map_err(|error| StoreError::Database(error.to_string()))?;
    }
    tx.commit().await.map_err(db)?;

    Ok(ManifestOutcome::Accepted { digest })
}

async fn reject_manifest(
    pool: &PgPool,
    record: &RetentionManifest,
    reason: &str,
) -> Result<(), StoreError> {
    sqlx::query(
        "insert into relay_retention_manifest_rejected (group_id, epoch, sequence, reason) \
         values ($1, $2, $3, $4)",
    )
    .bind(&record.group)
    .bind(record.epoch as i64)
    .bind(record.sequence as i64)
    .bind(reason)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(())
}

pub struct LatestManifest {
    pub sequence: u64,
    pub digest: Vec<u8>,
    pub blobs: Vec<Vec<u8>>,
}

/// Where a group's retention chain has got to, as the relay holds it.
///
/// The two chains are answered together for the reason `latest_control` answers
/// its two facts together: a client that asked separately would have to reason
/// about a control that rotated between the two calls, and the whole point of
/// this record is that the relay, not the client, is the authority on the
/// position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainPosition {
    /// The newest epoch a `RetentionControl` exists for, and its digest. `None`
    /// digest means the group has no control chain at all, which is the one case
    /// `control_epoch` says nothing.
    pub control_epoch: u64,
    pub control_digest: Option<Vec<u8>>,
    /// The sequence the next manifest must name.
    pub next_sequence: u64,
    /// The digest that next manifest must name as its predecessor.
    pub prev_manifest_hash: Option<Vec<u8>>,
    /// The claim set the latest manifest named, so a client can publish a superset
    /// rather than silently un-claiming blobs it never saw.
    pub blobs: Vec<Vec<u8>>,
}

/// Read a group's chain position.
///
/// This exists because `apply_manifest` refuses a manifest whose sequence does
/// not advance by exactly one, `handle_manifest` collapses that to
/// `reject/malformed_header`, and `RetentionManifestLog` derived the sequence
/// from purely local device state. A joiner therefore sent `sequence = 1`
/// forever and was refused forever (WEALD-L355). Nothing here is content: an
/// epoch, two digests, a counter, and the ciphertext hashes the same caller can
/// already read back with `Request::List`.
pub async fn position(pool: &PgPool, group: &[u8]) -> Result<ChainPosition, StoreError> {
    let control = latest_control(pool, group).await?;
    let control_digest = match &control {
        Some((epoch, _)) => control_at(pool, group, *epoch).await?.map(|c| c.digest),
        None => None,
    };
    let latest = latest_manifest(pool, group).await?;
    Ok(ChainPosition {
        control_epoch: control.map(|(epoch, _)| epoch).unwrap_or(0),
        control_digest,
        next_sequence: latest
            .as_ref()
            .map_or(FIRST_MANIFEST_SEQUENCE, |m| m.sequence + 1),
        prev_manifest_hash: latest.as_ref().map(|m| m.digest.clone()),
        blobs: latest.map(|m| m.blobs).unwrap_or_default(),
    })
}

pub async fn latest_manifest(
    pool: &PgPool,
    group: &[u8],
) -> Result<Option<LatestManifest>, StoreError> {
    let row = sqlx::query(
        "select sequence, digest, blobs from relay_retention_manifest \
         where group_id = $1 order by sequence desc limit 1",
    )
    .bind(group)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some(LatestManifest {
        sequence: {
            let value: i64 = row.try_get("sequence").map_err(db)?;
            value as u64
        },
        digest: row.try_get("digest").map_err(db)?,
        blobs: row.try_get("blobs").map_err(db)?,
    }))
}

/// The result of checking a threshold-authorized record's signatures against a
/// workspace's current access set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authorization {
    /// Two or more authorizers exist and two distinct ones signed.
    Threshold,
    /// Exactly one authorizer exists for the workspace, one signed, and
    /// `not_before` is at least seven days out. `media.md`: "every destructive
    /// action has a seven-day not_before and is cancellable ... until execution".
    SoleAuthorizerGraced,
    /// Not enough valid, distinct authorizer signatures for the workspace's
    /// current set.
    Insufficient,
    /// A lone authorizer signed but `not_before` is sooner than the seven-day
    /// floor a single signer requires.
    SoleAuthorizerTooSoon,
    /// The workspace has no authorizer at all to check against (a bootstrapping
    /// workspace, or one whose access set has not been read yet).
    NoAuthorizers,
}

/// Read by `media::authorization_error` too, so the wait it reports and the floor
/// enforced here are one number (WEALD-L315).
pub const SOLE_AUTHORIZER_FLOOR_SECS: u64 = 7 * 24 * 60 * 60;

/// Check a threshold record's signatures against the workspace's current
/// authorizers. `signing_bytes` is the canonical body every signer signed;
/// `signatures` and `not_before` come from the record itself.
pub async fn authorize(
    pool: &PgPool,
    workspace: &str,
    signing_bytes: &[u8],
    signatures: &[super::wire::Signature],
    not_before_secs: u64,
    now_secs: u64,
) -> Result<Authorization, StoreError> {
    let current = access::store::current(pool, workspace)
        .await
        .map_err(|error| StoreError::Database(error.to_string()))?;
    let Some(prior) = current.prior else {
        return Ok(Authorization::NoAuthorizers);
    };
    if prior.authorizers.is_empty() {
        return Ok(Authorization::NoAuthorizers);
    }

    let mut distinct: Vec<&[u8]> = Vec::new();
    for signature in signatures {
        if !prior.authorizers.iter().any(|key| key == &signature.key) {
            continue;
        }
        if !access::verify(&signature.key, signing_bytes, &signature.sig) {
            continue;
        }
        if !distinct.contains(&signature.key.as_slice()) {
            distinct.push(&signature.key);
        }
    }

    if prior.authorizers.len() >= 2 {
        return Ok(if distinct.len() >= 2 {
            Authorization::Threshold
        } else {
            Authorization::Insufficient
        });
    }

    if distinct.is_empty() {
        return Ok(Authorization::Insufficient);
    }
    // A single authorizer's action must be at least seven days out from the
    // relay's own receipt of it (`now_secs`), never from whatever the record
    // itself claims: a client that backdated `not_before` would otherwise buy
    // itself an earlier execution than a solo owner is allowed.
    let floor = now_secs.saturating_add(SOLE_AUTHORIZER_FLOOR_SECS);
    if not_before_secs < floor {
        return Ok(Authorization::SoleAuthorizerTooSoon);
    }
    Ok(Authorization::SoleAuthorizerGraced)
}

/// Apply a `RetentionPolicy`, once its authorization has already been checked by
/// the caller (`media::authorize_and_store_policy`), inserting it as the new
/// active version for its group.
pub async fn insert_policy(
    pool: &PgPool,
    record: &RetentionPolicy,
    signatures_json: &str,
) -> Result<(), StoreError> {
    sqlx::query(
        "insert into relay_retention_policy \
         (group_id, version, media_after_days, text_after_days, not_before, authorizers, signatures) \
         values ($1, $2, $3, $4, to_timestamp($5), $6, $7::jsonb)",
    )
    .bind(&record.group)
    .bind(record.version as i64)
    .bind(record.media_after_days as i32)
    .bind(record.text_after_days as i32)
    .bind(record.not_before as f64)
    .bind(&record.authorizers)
    .bind(signatures_json)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(())
}

pub struct ActivePolicy {
    pub version: u64,
    pub media_after_days: u32,
    pub text_after_days: u32,
    pub not_before_secs: u64,
}

impl ActivePolicy {
    /// Is `record` the policy already on file, rather than a new one?
    ///
    /// A retransmission has to be told apart from a tightening, because the
    /// answers are opposite: a retry is accepted quietly and a new policy must
    /// name the next version. Without this, an ordinary retry (a client that
    /// republishes because its first attempt was refused downstream, which is
    /// exactly what a two-step compaction does) is refused as a version error,
    /// and the operator sees `malformed_header` for a record that is correct.
    ///
    /// Compared on the terms rather than on the signatures, for the reason
    /// `is_the_same_control` is compared on the bytes and this is not: nothing is
    /// chained to a policy by digest, so two signings of one policy are the same
    /// permission and there is no hash for them to disagree about.
    pub fn is_the_same_policy(&self, record: &RetentionPolicy) -> bool {
        self.version == record.version
            && self.media_after_days == record.media_after_days
            && self.text_after_days == record.text_after_days
            && self.not_before_secs == record.not_before
    }
}

pub async fn active_policy(
    pool: &PgPool,
    group: &[u8],
) -> Result<Option<ActivePolicy>, StoreError> {
    let row = sqlx::query(
        "select version, media_after_days, text_after_days, \
                extract(epoch from not_before)::bigint as not_before \
         from relay_retention_policy where group_id = $1 and cancelled_at is null \
         order by version desc limit 1",
    )
    .bind(group)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some(ActivePolicy {
        version: {
            let v: i64 = row.try_get("version").map_err(db)?;
            v as u64
        },
        media_after_days: {
            let v: i32 = row.try_get("media_after_days").map_err(db)?;
            v as u32
        },
        text_after_days: {
            let v: i32 = row.try_get("text_after_days").map_err(db)?;
            v as u32
        },
        not_before_secs: {
            let v: i64 = row.try_get("not_before").map_err(db)?;
            v as u64
        },
    }))
}

/// Apply a `RetentionDestruction`, once authorization is checked. Idempotent on
/// `(group, kind, target_digest)`.
pub async fn insert_destruction(
    pool: &PgPool,
    record: &RetentionDestruction,
    signatures_json: &str,
) -> Result<bool, StoreError> {
    let result = sqlx::query(
        "insert into relay_retention_destruction \
         (group_id, kind, target_digest, policy_version, not_before, authorizers, signatures) \
         values ($1, $2, $3, $4, to_timestamp($5), $6, $7::jsonb) \
         on conflict (group_id, kind, target_digest) do nothing",
    )
    .bind(&record.group)
    .bind(String::from_utf8_lossy(&record.kind).into_owned())
    .bind(&record.target_digest)
    .bind(record.policy_version.map(|v| v as i64))
    .bind(record.not_before as f64)
    .bind(&record.authorizers)
    .bind(signatures_json)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(result.rows_affected() > 0)
}

pub struct Destruction {
    pub not_before_secs: u64,
}

pub async fn active_destruction(
    pool: &PgPool,
    group: &[u8],
    kind: &str,
    target_digest: &[u8],
) -> Result<Option<Destruction>, StoreError> {
    let row = sqlx::query(
        "select extract(epoch from not_before)::bigint as not_before from relay_retention_destruction \
         where group_id = $1 and kind = $2 and target_digest = $3 and cancelled_at is null",
    )
    .bind(group)
    .bind(kind)
    .bind(target_digest)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some(Destruction {
        not_before_secs: {
            let v: i64 = row.try_get("not_before").map_err(db)?;
            v as u64
        },
    }))
}
