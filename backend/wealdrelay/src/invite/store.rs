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

/// Newest *refreshed* candidates retained per `(token, group)`.
///
/// invites.md, "GroupInfo freshness": the relay cannot verify group membership, so
/// it treats an update as an availability hint rather than as truth. The invitee
/// accepts only an MLS-valid GroupInfo for the invited group, so it can find the
/// real one among the retained candidates.
///
/// Retaining N newest is not on its own what stops a bogus upload from masking the
/// last valid one: N+1 bogus uploads at distinct epochs evict every older row.
/// What stops it is the pinned row, the candidate carried in the signed invite
/// record, which pruning never touches (WEALD-338). This constant bounds only the
/// unpinned rows, so a scope holds at most `RETAINED_BUNDLES + 1`.
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

/// The same mapping, for the sibling modules that run their own queries.
///
/// `invite::admin` reads a summary view this module has no other reason to expose, and
/// a second private copy of this conversion would be a second place for a database
/// error to be reported as something else.
pub fn db_error(error: sqlx::Error) -> StoreError {
    db(error)
}

/// Whether a token belongs to this workspace.
///
/// Answered before any write on the admin path, so an authorizer of one workspace
/// cannot revoke another workspace's invite by presenting its token. `false` for a
/// token that does not exist at all, which is the same answer and deliberately so.
pub async fn belongs_to(
    pool: &PgPool,
    token: &[u8],
    workspace_id: &str,
) -> Result<bool, StoreError> {
    let row = sqlx::query("select 1 from relay_invite where token = $1 and workspace_id = $2")
        .bind(token)
        .bind(workspace_id)
        .fetch_optional(pool)
        .await
        .map_err(db)?;
    Ok(row.is_some())
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
    insert_within(&mut tx, workspace_id, invite, bootstrap, now_ms).await?;
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
    workspace_id: &str,
    invite: &Invite,
    bootstrap: bool,
    now_ms: i64,
) -> Result<(), StoreError> {
    super::judge(invite, bootstrap, now_ms.max(0) as u64)?;
    // Ensures the workspace row the foreign keys need, and is the same call the
    // access set makes for the same reason. On the caller's transaction, never on
    // the pool: a second checkout while this transaction holds the first is how
    // issuance starved every authenticated session of connections. The parameter
    // is gone rather than merely unused, so the shape cannot come back.
    crate::access::store::salt_within(&mut *tx, workspace_id)
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
            // `issued`: this row came in on the signed record over the authenticated
            // issue path, so it is the one candidate pruning may never evict.
            "insert into relay_invite_bundle (token, group_id, epoch, ct, issued) \
             values ($1, $2, $3, $4, true)",
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
    let Some((workspace_id, hashes)) = terminate_in(&mut tx, token, terminal).await? else {
        return Ok(false);
    };

    // Explicit rule, wire.md: revoking an invite voids every grant derived from it
    // immediately and closes matching open connections. Inside the same transaction
    // as the state change (WEALD-L153): a failure on the second of three hashes used
    // to commit the terminal state and then report `Backpressure`, leaving the invite
    // gone from every admin surface while the remaining devices kept live grants.
    for hash in &hashes {
        crate::access::store::revoke_grant_in(&mut tx, &workspace_id, hash)
            .await
            .map_err(|error| StoreError::Database(error.to_string()))?;
    }
    tx.commit().await.map_err(db)?;
    Ok(true)
}

/// End an invite as `spent` inside a transaction the caller already holds, and
/// delete the sealed `GroupInfo` it was still serving (WEALD-L188).
///
/// Deliberately lighter than `terminate`. Exhaustion is not revocation: the devices
/// that redeemed the seats keep the grants they earned, so no grant is voided; and
/// no tombstone is written, because a tombstone is the record that makes a
/// revocation stick and writing one here would refuse the duplicate `Commit` retry
/// of the very reservation that spent the last seat. What ends is the invite's
/// ability to admit anyone else, and with it the retained ciphertext, which is the
/// only thing a former joiner holding the link and its URL fragment could still
/// open. Taking the caller's transaction is the point: the last seat being spent and
/// the invite ending are one fact, and a second transaction would leave a window in
/// which a fully-redeemed invite still served its bundles.
pub(crate) async fn spend_in(
    tx: &mut sqlx::PgConnection,
    token: &[u8],
) -> Result<bool, StoreError> {
    let changed =
        sqlx::query("update relay_invite set state = 'spent' where token = $1 and state = 'live'")
            .bind(token)
            .execute(&mut *tx)
            .await
            .map_err(db)?
            .rows_affected();
    if changed == 0 {
        return Ok(false);
    }
    sqlx::query("delete from relay_invite_bundle where token = $1")
        .bind(token)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    Ok(true)
}

/// End every live invite whose stated expiry has passed.
///
/// The janitor's caller. An expiry that only a reader enforces leaves the sealed
/// bundles on disk forever, so the sweep runs the same transition exhaustion runs:
/// an invite that simply ran out of time does not retract the memberships it already
/// granted, and it does not need a tombstone to stay unredeemable, because every
/// redeeming path already refuses a state that is not `live`.
pub async fn sweep_expired(pool: &PgPool, now_ms: i64) -> Result<u64, StoreError> {
    let tokens: Vec<Vec<u8>> = sqlx::query(
        "select token from relay_invite \
         where state = 'live' \
           and expires_at <= to_timestamp($1::double precision / 1000.0) \
         order by token asc",
    )
    .bind(now_ms as f64)
    .fetch_all(pool)
    .await
    .map_err(db)?
    .iter()
    .map(|row| row.get::<Vec<u8>, _>("token"))
    .collect();

    let mut ended = 0u64;
    for token in &tokens {
        let mut tx = pool.begin().await.map_err(db)?;
        if spend_in(&mut tx, token).await? {
            tx.commit().await.map_err(db)?;
            ended += 1;
        }
    }
    Ok(ended)
}

/// The revocation transition itself: tombstone, state, reservations, ciphertext.
/// Grants are the caller's business, because revocation voids them and exhaustion
/// (`spend_in`) does not.
async fn terminate_in(
    tx: &mut sqlx::PgConnection,
    token: &[u8],
    terminal: &str,
) -> Result<Option<(String, Vec<Vec<u8>>)>, StoreError> {
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
        return Ok(None);
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

    // This is an update, not a delete, so `on delete cascade` never fires: a live
    // reservation survives the state change unless released explicitly here. The
    // tombstone above is what survives, and it is what the grant rules read.
    sqlx::query("update relay_invite set state = $2 where token = $1")
        .bind(token)
        .bind(terminal)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    sqlx::query(
        "update relay_invite_reservation set released_at = now() \
         where token = $1 and consumed_at is null and released_at is null",
    )
    .bind(token)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    sqlx::query("delete from relay_invite_bundle where token = $1")
        .bind(token)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    Ok(Some((workspace_id, hashes)))
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
/// keeps the newest ``RETAINED_BUNDLES`` refreshed candidates per `(token, group)`
/// and lets the invitee choose.
///
/// The candidate sealed into the signed invite record is pinned and never pruned or
/// overwritten by this path, because retaining N opaque newest values cannot prove
/// one of them is valid: N+1 bogus uploads at distinct epochs would otherwise evict
/// the last valid candidate and park every outstanding invite (WEALD-338). With the
/// pin, the worst a flood achieves is that the joiner falls back to the seal the
/// issuer gave it.
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
        // The `where` on the conflict update is the same pin seen from the other
        // side: an upload that collides with the issued row's epoch must not be able
        // to replace its ciphertext, which would evict the valid candidate by
        // overwrite rather than by pruning. The statement still reports success,
        // because a refusal here would tell an uploader which epoch the issuer
        // sealed, and there is nothing the honest uploader would do differently.
        "insert into relay_invite_bundle (token, group_id, epoch, ct) values ($1, $2, $3, $4) \
         on conflict (token, group_id, epoch) do update \
         set ct = excluded.ct, uploaded_at = now() \
         where relay_invite_bundle.issued = false",
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
         and issued = false \
         and (uploaded_at, epoch) not in ( \
             select uploaded_at, epoch from relay_invite_bundle \
             where token = $1 and group_id = $2 and issued = false \
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
/// The state gate is this function's own, not the caller's (WEALD-L188). `JOIN` is
/// pre-authentication by design, so anyone holding a leaked link can ask; a
/// revoked, spent or expired invite therefore has to answer nothing here even if
/// the transition that should have deleted these rows was missed. Empty rather than
/// an error, so the path stays as uninformative about which tokens are real as the
/// `Record` arm above it.
pub async fn bundles_for(
    pool: &PgPool,
    token: &[u8],
    group: &[u8],
    now_ms: i64,
) -> Result<Vec<EncBundle>, StoreError> {
    let rows = sqlx::query(
        "select b.group_id, b.epoch, b.ct from relay_invite_bundle b \
         join relay_invite i on i.token = b.token \
         where b.token = $1 and b.group_id = $2 \
           and i.state = 'live' \
           and i.expires_at > to_timestamp($3::double precision / 1000.0) \
         order by b.uploaded_at desc, b.epoch desc",
    )
    .bind(token)
    .bind(group)
    .bind(now_ms as f64)
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
