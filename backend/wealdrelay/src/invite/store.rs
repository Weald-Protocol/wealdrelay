// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Invites against Postgres: the record, its bundles, and their end.
//!
//! Every rule lives in the parent module and none of them live here. What is here
//! is the transaction boundary. The split is the same one `access::store` makes
//! against `access`, and for the same reason: a rule reachable only through a
//! database round trip is a rule nobody covers.
//!
//! The reservation half, which is where seats are actually spent, is in
//! `invite::reserve`.
//!
//! ## What this module cannot do
//!
//! It cannot read a bundle. `ct` appears in exactly two statements, one that writes
//! it and one that selects it to serve it back, and there is no key anywhere in this
//! crate that could open one. That is checkable rather than asserted: grep this file
//! for `ct` and both hits are transport.

use sqlx::{PgPool, Row};

use super::{code, EncBundle, Invite, InviteError};

/// Newest candidates retained per `(token, group)`.
///
/// invites.md, "GroupInfo freshness": the relay cannot verify group membership, so
/// it treats an update as an availability hint rather than as truth. Retaining three
/// is what stops a bogus high-epoch upload from masking the last valid update, and
/// the invitee accepts only an MLS-valid GroupInfo for the invited group, so it can
/// find the real one among them.
pub const RETAINED_BUNDLES: i64 = 3;

/// Why a database call could not answer.
///
/// Separate from ``InviteError``: one is a client that published something wrong,
/// the other is a relay that could not look. Conflating them would tell a correct
/// client to stop retrying.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("invite store: {0}")]
    Database(String),
    #[error("{0}")]
    Refused(#[from] InviteError),
    #[error("invite code: {0}")]
    Code(#[from] code::CodeError),
}

impl StoreError {
    /// The wire code a joiner is told, decided in one place.
    ///
    /// A relay that could not look answers `retry`, because the invite may be
    /// perfectly good and the client's correct move is to come back. Everything else
    /// is the one generic refusal `invites.md` requires of this path: an endpoint
    /// reachable without authentication must not say which of "no such token",
    /// "wrong code", "no seats", "revoked" or "expired" it was.
    pub fn code(&self) -> crate::frame::ErrorCode {
        match self {
            Self::Database(_) => crate::frame::ErrorCode::Backpressure,
            Self::Refused(_) | Self::Code(_) => super::UNAVAILABLE,
        }
    }
}

pub(super) fn db(error: sqlx::Error) -> StoreError {
    StoreError::Database(crate::logging::scrub(&error.to_string()))
}

/// Where an invite is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Live,
    Revoked,
    Spent,
}

impl State {
    pub fn label(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Revoked => "revoked",
            Self::Spent => "spent",
        }
    }

    /// Read a stored label.
    ///
    /// An unknown label answers `Revoked` rather than erroring: the column is
    /// constrained to the three, so the arm is only reachable by a row this schema
    /// forbids, and the safe reading of a row nobody can explain is "not usable".
    pub fn from_label(label: &str) -> Self {
        match label {
            "live" => Self::Live,
            "spent" => Self::Spent,
            _ => Self::Revoked,
        }
    }
}

/// One stored invite, as the relay holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub invite: Invite,
    /// The bytes the issuer signed, byte for byte. Served rather than re-encoded,
    /// so a client verifies the issuer's signature over the issuer's bytes and not
    /// over the relay's encoder.
    pub body: Vec<u8>,
    pub state: State,
    pub remaining: i16,
    pub bootstrap: bool,
    pub workspace_id: String,
}

/// Store a record a member issued.
///
/// `bootstrap` is false and cannot be otherwise: the only scopeless invite in the
/// system is the one the relay writes for itself in `invite::genesis`, and a client
/// path that could ask for the exemption would be the mandatory-root rule's own
/// bypass. This is the relay half of "the relay rejects an otherwise-valid invite
/// record that omits its declared workspace root".
pub async fn create(
    pool: &PgPool,
    workspace_id: &str,
    invite: &Invite,
    now_ms: i64,
) -> Result<(), StoreError> {
    insert(pool, workspace_id, invite, false, now_ms).await
}

/// The insert itself, with the bootstrap exemption available to this crate only.
pub(super) async fn insert(
    pool: &PgPool,
    workspace_id: &str,
    invite: &Invite,
    bootstrap: bool,
    now_ms: i64,
) -> Result<(), StoreError> {
    // The transaction is opened before anything else touches the database, so a
    // relay that cannot open one says so before it has written a workspace row for a
    // record it is then going to fail to store.
    let mut tx = pool.begin().await.map_err(db)?;
    insert_within(&mut tx, pool, workspace_id, invite, bootstrap, now_ms).await?;
    tx.commit().await.map_err(db)?;
    Ok(())
}

/// The same insert, inside a transaction the caller owns.
///
/// `invite::genesis` needs this: minting a workspace's bootstrap invite writes an
/// invite record and a `relay_genesis` row, and those two have to land together.
/// They did not before, and the failure was not theoretical: with the genesis row
/// refused, the invite still committed, `read` still found no genesis, and the next
/// call minted a second bootstrap invite while the first stayed live. Two live
/// single-use bootstrap invites for one workspace, one of them untracked, is the
/// opposite of what "the single-use genesis key" means.
pub(super) async fn insert_within(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool: &PgPool,
    workspace_id: &str,
    invite: &Invite,
    bootstrap: bool,
    now_ms: i64,
) -> Result<(), StoreError> {
    super::judge(invite, bootstrap, now_ms.max(0) as u64)?;
    // Ensures the workspace row the foreign keys need, and is the same call the
    // access set makes for the same reason.
    crate::access::store::salt(pool, workspace_id)
        .await
        .map_err(|error| StoreError::Database(error.to_string()))?;

    sqlx::query(
        "insert into relay_invite \
         (token, workspace_id, workspace, issuer, expires_at, uses, remaining, \
          code_hash, update_pub, state, bootstrap, body) \
         values ($1, $2, $3, $4, to_timestamp($5::double precision / 1000), \
                 $6, $6, $7, $8, 'live', $9, $10)",
    )
    .bind(&invite.token)
    .bind(workspace_id)
    .bind(&invite.workspace)
    .bind(&invite.issuer)
    .bind(i64::try_from(invite.expires).unwrap_or(i64::MAX))
    .bind(i16::from(invite.uses))
    .bind(&invite.code_hash)
    .bind(&invite.update_pub)
    .bind(bootstrap)
    .bind(invite.encode())
    .execute(&mut **tx)
    .await
    .map_err(db)?;

    for (position, scope) in invite.scopes.iter().enumerate() {
        sqlx::query(
            "insert into relay_invite_scope (token, group_id, position) values ($1, $2, $3)",
        )
        .bind(&invite.token)
        .bind(scope)
        .bind(i16::try_from(position).unwrap_or(i16::MAX))
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    }

    for bundle in &invite.bundles {
        sqlx::query(
            "insert into relay_invite_bundle (token, group_id, epoch, ct) \
             values ($1, $2, $3, $4)",
        )
        .bind(&invite.token)
        .bind(&bundle.group)
        .bind(i64::try_from(bundle.epoch).unwrap_or(i64::MAX))
        .bind(&bundle.ct)
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    }

    Ok(())
}

/// One record by token, whatever state it is in.
///
/// The caller decides what to do about the state, because the two callers want
/// different things: the redeem path answers `UNAVAILABLE` for anything but `Live`,
/// and the admin's live list wants to show why an invite is gone.
pub async fn fetch(pool: &PgPool, token: &[u8]) -> Result<Option<Record>, StoreError> {
    let row = sqlx::query(
        "select body, state, remaining, bootstrap, workspace_id \
         from relay_invite where token = $1",
    )
    .bind(token)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let body: Vec<u8> = row.get("body");
    let invite = Invite::decode(&body)?;
    Ok(Some(Record {
        invite,
        body,
        state: State::from_label(row.get::<String, _>("state").as_str()),
        remaining: row.get("remaining"),
        bootstrap: row.get("bootstrap"),
        workspace_id: row.get("workspace_id"),
    }))
}

/// Every live invite for a workspace, for the admin's live list.
pub async fn live_tokens(pool: &PgPool, workspace_id: &str) -> Result<Vec<Vec<u8>>, StoreError> {
    let rows = sqlx::query(
        "select token from relay_invite where workspace_id = $1 and state = 'live' \
         order by created_at asc, token asc",
    )
    .bind(workspace_id)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    Ok(rows
        .iter()
        .map(|row| row.get::<Vec<u8>, _>("token"))
        .collect())
}

/// Revoke an invite: tombstone first, then delete the redeemable record.
///
/// The order is the whole point. `specs/backend/relay/wire.md` requires the durable,
/// opaque tombstone to be written **before** the ciphertext is removed, so an invite
/// can vanish from the admin's live list without deleting the state required to
/// enforce its revocation. The tombstone retains the token, the terminal state, the
/// expiry and the device hashes needed to find grants, and nothing else: no link
/// secret, no code, no code hash, no name, no scope ciphertext.
pub async fn revoke(pool: &PgPool, token: &[u8]) -> Result<bool, StoreError> {
    terminate(pool, token, "revoked").await
}

/// The same transition, for an invite that ended by being fully spent.
pub async fn mark_spent(pool: &PgPool, token: &[u8]) -> Result<bool, StoreError> {
    terminate(pool, token, "spent").await
}

async fn terminate(pool: &PgPool, token: &[u8], terminal: &str) -> Result<bool, StoreError> {
    let mut tx = pool.begin().await.map_err(db)?;
    let row = sqlx::query(
        "select workspace_id, expires_at from relay_invite where token = $1 for update",
    )
    .bind(token)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?;
    let Some(row) = row else {
        // Dropped rather than rolled back explicitly. `sqlx` rolls a transaction
        // back when it falls out of scope, so an explicit call here would add a
        // failure path that only fires when the rollback itself fails, which is a
        // state no test can stage and no reader can act on.
        return Ok(false);
    };
    let workspace_id: String = row.get("workspace_id");

    let hashes: Vec<Vec<u8>> =
        sqlx::query("select distinct device_hash from relay_invite_reservation where token = $1")
            .bind(token)
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?
            .iter()
            .map(|row| row.get::<Vec<u8>, _>("device_hash"))
            .collect();

    sqlx::query(
        "insert into relay_invite_tombstone \
         (token, workspace_id, terminal, expires_at, device_hashes) \
         select $1, $2, $3, expires_at, $4 from relay_invite where token = $1 \
         on conflict (token) do update set terminal = excluded.terminal, \
             device_hashes = excluded.device_hashes",
    )
    .bind(token)
    .bind(&workspace_id)
    .bind(terminal)
    .bind(&hashes)
    .execute(&mut *tx)
    .await
    .map_err(db)?;

    // The redeemable ciphertext goes; the reservations and their scope commits go
    // with it by cascade, because a reservation against a record that no longer
    // exists cannot be completed and keeping it would only make the seat
    // unaccountable. The tombstone above is what survives, and it is what the grant
    // rules read.
    sqlx::query("update relay_invite set state = $2 where token = $1")
        .bind(token)
        .bind(terminal)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    sqlx::query("delete from relay_invite_bundle where token = $1")
        .bind(token)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    tx.commit().await.map_err(db)?;

    // Explicit rule, wire.md: revoking an invite voids every grant derived from it
    // immediately and closes matching open connections.
    for hash in &hashes {
        crate::access::store::revoke_grant(pool, &workspace_id, hash)
            .await
            .map_err(|error| StoreError::Database(error.to_string()))?;
    }
    Ok(true)
}

/// The device hashes a tombstone remembers, so a grant can be found after the
/// redeemable record is gone.
pub async fn tombstoned_hashes(
    pool: &PgPool,
    token: &[u8],
) -> Result<Option<Vec<Vec<u8>>>, StoreError> {
    let row = sqlx::query("select device_hashes from relay_invite_tombstone where token = $1")
        .bind(token)
        .fetch_optional(pool)
        .await
        .map_err(db)?;
    Ok(row.map(|row| row.get::<Vec<Vec<u8>>, _>("device_hashes")))
}

/// Seal a fresh `GroupInfo` to an invite's `update_pub`.
///
/// The relay accepts this from an authenticated current access-set principal and
/// never decrypts it, and it cannot verify that the uploader is in the group. So it
/// keeps the newest ``RETAINED_BUNDLES`` candidates per `(token, group)` and lets the
/// invitee choose: a bogus high-epoch upload cannot mask the last valid update
/// because the last valid update is still there.
///
/// An upload for a group the invite does not scope is refused, because a record has
/// no authority to carry material for a group it does not name.
pub async fn refresh_bundle(
    pool: &PgPool,
    token: &[u8],
    bundle: &EncBundle,
) -> Result<bool, StoreError> {
    if bundle.ct.is_empty() || bundle.ct.len() > super::MAX_BUNDLE_BYTES {
        return Ok(false);
    }
    let scoped = sqlx::query(
        "select 1 as present from relay_invite_scope s join relay_invite i using (token) \
         where s.token = $1 and s.group_id = $2 and i.state = 'live'",
    )
    .bind(token)
    .bind(&bundle.group)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    if scoped.is_none() {
        return Ok(false);
    }

    // Two statements and deliberately not a transaction. The retention is a hint
    // rather than an invariant: a relay that stored the candidate and died before
    // pruning holds four candidates instead of three, which costs a row and changes
    // nothing a joiner can observe. A transaction here would buy that nothing at the
    // price of a failure path with no correct handling.
    sqlx::query(
        "insert into relay_invite_bundle (token, group_id, epoch, ct) values ($1, $2, $3, $4) \
         on conflict (token, group_id, epoch) do update \
         set ct = excluded.ct, uploaded_at = now()",
    )
    .bind(token)
    .bind(&bundle.group)
    .bind(i64::try_from(bundle.epoch).unwrap_or(i64::MAX))
    .bind(&bundle.ct)
    .execute(pool)
    .await
    .map_err(db)?;
    sqlx::query(
        "delete from relay_invite_bundle where token = $1 and group_id = $2 \
         and (uploaded_at, epoch) not in ( \
             select uploaded_at, epoch from relay_invite_bundle \
             where token = $1 and group_id = $2 \
             order by uploaded_at desc, epoch desc limit $3)",
    )
    .bind(token)
    .bind(&bundle.group)
    .bind(RETAINED_BUNDLES)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(true)
}

/// The retained candidates for one scope, newest first.
///
/// Opaque bytes out. The relay has served them; it has not looked at them.
pub async fn bundles_for(
    pool: &PgPool,
    token: &[u8],
    group: &[u8],
) -> Result<Vec<EncBundle>, StoreError> {
    let rows = sqlx::query(
        "select group_id, epoch, ct from relay_invite_bundle \
         where token = $1 and group_id = $2 order by uploaded_at desc, epoch desc",
    )
    .bind(token)
    .bind(group)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    Ok(rows
        .iter()
        .map(|row| EncBundle {
            group: row.get("group_id"),
            epoch: u64::try_from(row.get::<i64, _>("epoch")).unwrap_or_default(),
            ct: row.get("ct"),
        })
        .collect())
}
