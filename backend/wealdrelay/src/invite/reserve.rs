// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Reservations: where a seat is actually spent, and where a wrong code is
//! answered.
//!
//! `specs/backend/relay/invites.md`, step 4 of the join flow. Before spending a
//! seat the client generates its device key, collects a display name, and generates
//! and confirms the recovery phrase. Those are local-only: abandoning that screen
//! sends nothing here and costs no invitation capacity. Only afterwards does it
//! submit the token, the code, a random join nonce and its device hash, and only
//! then is a seat taken.
//!
//! ## One answer, always
//!
//! Every refusal in this module is ``Verdict::Unavailable``. Nonexistent, expired,
//! revoked, spent, out of capacity and cooled down are one response, because an
//! endpoint that distinguished them would be an oracle for which tokens ever
//! existed. The reasons are recorded on the relay side, where an operator can read
//! them; they are never told to the caller.
//!
//! ## What five wrong codes do, and what they do not do
//!
//! Five failures from one `(token, source, device)` tuple cool that tuple down for
//! fifteen minutes. They do not burn the invite, they do not touch capacity, and
//! they do not affect the other seats behind a shared invite: one person
//! fat-fingering a code cannot lock out the nine colleagues invited alongside them.
//! The issuer's connected client is told the attempt volume and is never told a
//! source address, because the relay hashes the source with the workspace salt and
//! has nothing else to tell.

use sqlx::{PgPool, Row};

use super::code::{self, Code};
use super::store::{db, State, StoreError};

/// How long an unconsumed reservation holds its seat.
///
/// Ten minutes covers the network join after local setup, not the time to read or
/// store a recovery phrase. A join parked on a stale `GroupInfo` extends once, to
/// the invite's own expiry, which is what stops the parked-join path from expiring
/// the seat it is waiting on.
pub const RESERVATION_SECONDS: i64 = 10 * 60;

/// What a reserve attempt produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A seat is held for this nonce and device hash until this time.
    Reserved { expires_at_ms: i64 },
    /// The one answer to everything else.
    Unavailable,
}

/// How many wrong codes an issuer is being told about.
///
/// Volume and nothing else. No address, no hash of an address, no device: the
/// notification exists so an admin can decide to revoke, and an admin who could read
/// a source IP out of it would be reading it out of the blind half of the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptVolume {
    pub failures: i64,
    /// Distinct tuples that have failed at least once, so "one person mistyping" and
    /// "a thousand hosts guessing" are different numbers.
    pub tuples: i64,
}

/// A salted hash of whatever identifies the requester's source.
///
/// The relay must be able to count attempts per source and must not be able to name
/// one. Salted with the workspace salt, which is the same salt the access set uses
/// and which is already relay-held, so this adds no new secret and no new column.
pub fn source_hash(source: &str, salt: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(source.as_bytes());
    hasher.update(salt);
    hasher.finalize().as_bytes().to_vec()
}

/// Take one unit of remaining capacity, if everything about the request is right.
///
/// The whole of the linearization point for `uses` is the one `update ... where
/// remaining > 0 ... returning` below: a check-then-decrement would let two devices
/// both believe they had won the last seat.
pub async fn reserve(
    pool: &PgPool,
    token: &[u8],
    typed_code: &str,
    nonce: &[u8],
    device_hash: &[u8],
    source: &[u8],
    now_ms: i64,
) -> Result<Verdict, StoreError> {
    if cooled_down(pool, token, source, device_hash, now_ms).await? {
        return Ok(Verdict::Unavailable);
    }
    let Some(record) = super::store::fetch(pool, token).await? else {
        return Ok(Verdict::Unavailable);
    };
    if record.state != State::Live || now_ms.max(0) as u64 >= record.invite.expires {
        return Ok(Verdict::Unavailable);
    }

    let Ok(parsed) = Code::parse(typed_code) else {
        record_failure(pool, token, source, device_hash, now_ms).await?;
        return Ok(Verdict::Unavailable);
    };
    if !code::verify(parsed, token, &record.invite.code_hash) {
        record_failure(pool, token, source, device_hash, now_ms).await?;
        return Ok(Verdict::Unavailable);
    }

    // Idempotent for the same nonce, and only for the same nonce: a live
    // reservation is returned as it stands rather than taking a second seat.
    if let Some(existing) = live_reservation(pool, token, nonce, now_ms).await? {
        return Ok(Verdict::Reserved {
            expires_at_ms: existing,
        });
    }

    let expires_at_ms = (now_ms + RESERVATION_SECONDS * 1000)
        .min(i64::try_from(record.invite.expires).unwrap_or(i64::MAX));

    // One statement, so it is one transaction and there is no window between taking
    // the seat and recording who holds it. The `where remaining > 0` inside the
    // update is the linearization point: a check-then-decrement would let two devices
    // both believe they had won the last seat, and a second statement to insert the
    // reservation would let a crash spend a seat nobody holds.
    let taken = sqlx::query(
        "with taken as ( \
             update relay_invite set remaining = remaining - 1 \
             where token = $1 and state = 'live' and remaining > 0 \
               and expires_at > to_timestamp($5::double precision / 1000) \
             returning token) \
         insert into relay_invite_reservation (token, join_nonce, device_hash, expires_at) \
         select $1, $2, $3, to_timestamp($4::double precision / 1000) from taken \
         returning join_nonce",
    )
    .bind(token)
    .bind(nonce)
    .bind(device_hash)
    .bind(expires_at_ms)
    .bind(now_ms)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    if taken.is_none() {
        return Ok(Verdict::Unavailable);
    }

    // The reservation is a connection credential from this moment: the joiner has to
    // be able to open a socket to perform its external commit, and no access set
    // names it yet.
    crate::access::store::grant(pool, &record.workspace_id, device_hash, expires_at_ms)
        .await
        .map_err(|error| StoreError::Database(error.to_string()))?;
    Ok(Verdict::Reserved { expires_at_ms })
}

/// Extend a parked join, once, to the invite's own expiry.
///
/// The relay verifies nothing about the client's claim that local setup finished and
/// does not need to: the extension consumes the seat it already holds, is bound to
/// the same nonce and device hash, and can never outlive the invite. Without it the
/// parked-join path expires the seat it is waiting on, and a joiner who did
/// everything asked of them finds a burnt invite and a recovery phrase for a
/// workspace they never entered.
pub async fn extend(pool: &PgPool, token: &[u8], nonce: &[u8]) -> Result<bool, StoreError> {
    let done = sqlx::query(
        "update relay_invite_reservation r set expires_at = i.expires_at, extended = true \
         from relay_invite i where i.token = r.token and r.token = $1 and r.join_nonce = $2 \
           and r.extended = false and r.consumed_at is null and r.released_at is null",
    )
    .bind(token)
    .bind(nonce)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(done.rows_affected() > 0)
}

/// Record one accepted scope commit, and consume the seat on the last one.
///
/// The relay accepts an external commit only when the reservation is live, the
/// committing device hash matches, and the group is one of the reserved scopes. A
/// duplicate retry returns the original receipt rather than a second one, because a
/// client that lost the answer must be able to ask again without spending anything.
pub async fn scope_commit(
    pool: &PgPool,
    token: &[u8],
    nonce: &[u8],
    device_hash: &[u8],
    group: &[u8],
    now_ms: i64,
) -> Result<Option<Vec<u8>>, StoreError> {
    let row = sqlx::query(
        "select r.device_hash, r.consumed_at is not null as consumed, \
                (extract(epoch from r.expires_at) * 1000)::double precision as expires_ms, \
                (select count(*) from relay_invite_scope s where s.token = r.token) as scopes, \
                i.workspace_id, \
                (extract(epoch from i.expires_at) * 1000)::double precision as invite_expires_ms \
         from relay_invite_reservation r join relay_invite i on i.token = r.token \
         where r.token = $1 and r.join_nonce = $2 and r.released_at is null",
    )
    .bind(token)
    .bind(nonce)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.get::<Vec<u8>, _>("device_hash") != device_hash {
        return Ok(None);
    }
    let consumed: bool = row.get("consumed");
    let expires_ms: f64 = row.get("expires_ms");
    if !consumed && now_ms as f64 >= expires_ms {
        return Ok(None);
    }
    let scoped = sqlx::query(
        "select 1 as present from relay_invite_scope where token = $1 and group_id = $2",
    )
    .bind(token)
    .bind(group)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    if scoped.is_none() {
        return Ok(None);
    }

    let receipt = receipt_for(token, nonce, group);
    sqlx::query(
        "insert into relay_invite_scope_commit (token, join_nonce, group_id, receipt) \
         values ($1, $2, $3, $4) on conflict (token, join_nonce, group_id) do nothing",
    )
    .bind(token)
    .bind(nonce)
    .bind(group)
    .bind(&receipt)
    .execute(pool)
    .await
    .map_err(db)?;

    let committed: i64 = sqlx::query(
        "select count(*) as done from relay_invite_scope_commit where token = $1 and join_nonce = $2",
    )
    .bind(token)
    .bind(nonce)
    .fetch_one(pool)
    .await
    .map_err(db)?
    .get("done");
    let scopes: i64 = row.get("scopes");
    if !consumed && committed >= scopes {
        consume(
            pool,
            token,
            nonce,
            device_hash,
            row.get("workspace_id"),
            row.get::<f64, _>("invite_expires_ms") as i64,
        )
        .await?;
    }
    Ok(Some(receipt))
}

/// The final scope commit: spend the seat, promote the grant.
///
/// One transaction, so a second device cannot race a seat that has already been
/// spent. Promotion rather than a second grant: the just-enrolled device stays
/// connected while it waits for the durable access-set publication, and no other
/// device can inherit the seat.
/// The workspace and the invite expiry are passed in rather than read again. The
/// caller already holds both from the row it judged the commit against, and a second
/// read would have had a "the row went away between two statements" arm that only a
/// race could reach, which is an arm no test can take honestly.
async fn consume(
    pool: &PgPool,
    token: &[u8],
    nonce: &[u8],
    device_hash: &[u8],
    workspace_id: String,
    invite_expires_ms: i64,
) -> Result<(), StoreError> {
    sqlx::query(
        "update relay_invite_reservation set consumed_at = now() \
         where token = $1 and join_nonce = $2 and consumed_at is null",
    )
    .bind(token)
    .bind(nonce)
    .execute(pool)
    .await
    .map_err(db)?;
    crate::access::store::grant(pool, &workspace_id, device_hash, invite_expires_ms)
        .await
        .map_err(|error| StoreError::Database(error.to_string()))?;
    Ok(())
}

/// A receipt is a hash of what it is a receipt for, so it is stable across retries
/// and carries nothing else.
fn receipt_for(token: &[u8], nonce: &[u8], group: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"weald invite scope-commit v1");
    hasher.update(token);
    hasher.update(nonce);
    hasher.update(group);
    hasher.finalize().as_bytes().to_vec()
}

/// Return the seats of reservations that ran out.
///
/// Capacity is decremented on reserve and returned on expiry, so an abandoned setup
/// frees a seat after ten minutes rather than burning one of ten invitations
/// permanently.
pub async fn release_expired(pool: &PgPool, now_ms: i64) -> Result<u64, StoreError> {
    // One statement again, and for the same reason: releasing a reservation and
    // returning its seat are two halves of one fact. `count(*)` per token rather than
    // a join, because two reservations of one invite expiring together must return
    // two seats and a plain join would return one.
    let rows = sqlx::query(
        "with released as ( \
             update relay_invite_reservation set released_at = now() \
             where consumed_at is null and released_at is null \
               and expires_at <= to_timestamp($1::double precision / 1000) \
             returning token), \
         counted as (select token, count(*) as freed from released group by token) \
         update relay_invite i set remaining = least(i.remaining + c.freed, i.uses) \
         from counted c where i.token = c.token returning c.freed",
    )
    .bind(now_ms)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    Ok(rows
        .iter()
        .map(|row| u64::try_from(row.get::<i64, _>("freed")).unwrap_or_default())
        .sum())
}

/// The expiry of a live reservation for this nonce, if there is one.
async fn live_reservation(
    pool: &PgPool,
    token: &[u8],
    nonce: &[u8],
    now_ms: i64,
) -> Result<Option<i64>, StoreError> {
    let row = sqlx::query(
        "select (extract(epoch from expires_at) * 1000)::double precision as expires_ms \
         from relay_invite_reservation \
         where token = $1 and join_nonce = $2 and released_at is null \
           and expires_at > to_timestamp($3::double precision / 1000)",
    )
    .bind(token)
    .bind(nonce)
    .bind(now_ms)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    Ok(row.map(|row| row.get::<f64, _>("expires_ms") as i64))
}

/// Whether this tuple is inside its fifteen-minute cooldown.
async fn cooled_down(
    pool: &PgPool,
    token: &[u8],
    source: &[u8],
    device_hash: &[u8],
    now_ms: i64,
) -> Result<bool, StoreError> {
    let row = sqlx::query(
        "select 1 as present from relay_invite_attempt \
         where token = $1 and source_hash = $2 and device_hash = $3 \
           and cooldown_until > to_timestamp($4::double precision / 1000)",
    )
    .bind(token)
    .bind(source)
    .bind(device_hash)
    .bind(now_ms)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    Ok(row.is_some())
}

/// Count one wrong code against one tuple, and cool that tuple down at five.
async fn record_failure(
    pool: &PgPool,
    token: &[u8],
    source: &[u8],
    device_hash: &[u8],
    now_ms: i64,
) -> Result<(), StoreError> {
    sqlx::query(
        "insert into relay_invite_attempt (token, source_hash, device_hash, failures) \
         values ($1, $2, $3, 1) \
         on conflict (token, source_hash, device_hash) do update \
         set failures = relay_invite_attempt.failures + 1, \
             cooldown_until = case when relay_invite_attempt.failures + 1 >= $4 \
                 then to_timestamp($5::double precision / 1000) + make_interval(secs => $6::double precision) \
                 else relay_invite_attempt.cooldown_until end",
    )
    .bind(token)
    .bind(source)
    .bind(device_hash)
    .bind(code::MAX_FAILURES)
    .bind(now_ms)
    .bind(code::COOLDOWN_SECONDS as f64)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(())
}

/// What the issuer's client is told: how much, never by whom.
pub async fn attempt_volume(pool: &PgPool, token: &[u8]) -> Result<AttemptVolume, StoreError> {
    let row = sqlx::query(
        "select coalesce(sum(failures), 0)::bigint as failures, count(*)::bigint as tuples \
         from relay_invite_attempt where token = $1 and failures > 0",
    )
    .bind(token)
    .fetch_one(pool)
    .await
    .map_err(db)?;
    Ok(AttemptVolume {
        failures: row.get("failures"),
        tuples: row.get("tuples"),
    })
}
