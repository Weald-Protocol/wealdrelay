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
//! Five failures from one `(token, source)` pair cool that pair down for fifteen
//! minutes, and twenty-five failures against one token from any mix of sources
//! cool the whole token down. The key deliberately carries no device: the device
//! value is an arbitrary byte string the joiner supplies before authenticating, so
//! a key that included it was a key the guesser chose, and the five-guess bound
//! against the 60-bit code was unbounded from a single address. The failures do
//! not burn the invite, they do not touch capacity, and colleagues joining from
//! their own addresses are untouched. The issuer's connected client is told the
//! attempt volume and is never told a source address, because the relay hashes the
//! source with the workspace salt and has nothing else to tell.

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
    // Before the record fetch and long before `code::verify`: a cooled-down pair
    // or token never reaches Argon2id, so the guess loop cannot double as a
    // memory and CPU exhaustion lever.
    if cooled_down(pool, token, source, now_ms).await? {
        return Ok(Verdict::Unavailable);
    }
    let Some(record) = super::store::fetch(pool, token).await? else {
        return Ok(Verdict::Unavailable);
    };
    if record.state != State::Live || now_ms.max(0) as u64 >= record.invite.expires {
        return Ok(Verdict::Unavailable);
    }

    // Charge the attempt slot before the code is parsed or hashed, not after it
    // fails. The read above is a fast path and nothing more: two connections from
    // one source can both pass it, and a check-then-charge budget bounds nothing
    // against a burst that arrives inside the width of one Argon2id call. The
    // charge below is the linearization point, for the same reason the seat
    // decrement is: one statement takes the slot, so N simultaneous wrong codes
    // from one source take N distinct slots and only the configured number of them
    // reach the verifier. WEALD-336.
    if !claim_attempt(pool, token, source, now_ms).await? {
        return Ok(Verdict::Unavailable);
    }

    let Ok(parsed) = Code::parse(typed_code) else {
        return Ok(Verdict::Unavailable);
    };
    if !code::verify(parsed, token, &record.invite.code_hash) {
        return Ok(Verdict::Unavailable);
    }
    // The code was right, so the slot was not a guess: give it back. Without the
    // refund the budget counts honest joins, and five colleagues behind one office
    // address would cool down the pair that just admitted them. A refund is safe
    // to hand out here and nowhere else, because reaching this line requires the
    // 60-bit code.
    refund_attempt(pool, token, source).await?;

    // A device whose grant was voided (revoked, superseded, expired) is refused
    // before it can spend a seat. Voiding is terminal, so redeeming again would take
    // a use of the invite and end with a credential that admits nothing.
    if crate::access::store::grant_is_voided(pool, &record.workspace_id, device_hash)
        .await
        .map_err(|error| StoreError::Database(error.to_string()))?
    {
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

    // One statement, so there is no window between taking the seat and recording who
    // holds it. The `where remaining > 0` inside the update is the linearization
    // point: a check-then-decrement would let two devices both believe they had won
    // the last seat, and a second statement to insert the reservation would let a
    // crash spend a seat nobody holds.
    //
    // That argument stopped one statement short, so the statement runs inside an
    // explicit transaction with the grant below rather than autocommitting alone
    // (WEALD-342). The provisional grant is what lets the joiner open a socket at
    // all, so a seat taken without one is precisely the seat nobody holds that the
    // paragraph above refuses to allow. Both writes are this database, so the atom
    // costs nothing but the transaction.
    let mut tx = pool.begin().await.map_err(db)?;
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
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?;
    if taken.is_none() {
        // Nothing was written, so the rollback gives nothing back. Explicit anyway:
        // an early return that left the transaction to its `Drop` would be one more
        // place for a later edit to leak a held connection.
        tx.rollback().await.map_err(db)?;
        return Ok(Verdict::Unavailable);
    }

    // The reservation is a connection credential from this moment: the joiner has to
    // be able to open a socket to perform its external commit, and no access set
    // names it yet.
    // A device whose grant was already voided (revoked, superseded, expired) does not
    // get a live one back by redeeming again: `grant` refuses to clear a void, and a
    // reservation whose credential is dead would strand the joiner on a socket it
    // cannot open.
    //
    // Inside the transaction that took the seat, so the two outcomes a caller can
    // see are the two honest ones: a seat spent and a credential to use it, or
    // neither. A refused grant (the device was voided between the read above and
    // here) and a database error both roll the seat back, so a client that retries
    // is not charged for the attempt that could never have worked, and the invite's
    // `uses` cannot be drained by a device that is refused every time.
    let granted = match crate::access::store::grant(
        &mut *tx,
        &record.workspace_id,
        device_hash,
        expires_at_ms,
    )
    .await
    {
        Ok(granted) => granted,
        Err(error) => {
            tx.rollback().await.map_err(db)?;
            return Err(StoreError::Database(error.to_string()));
        }
    };
    if !granted {
        tx.rollback().await.map_err(db)?;
        return Ok(Verdict::Unavailable);
    }
    tx.commit().await.map_err(db)?;
    Ok(Verdict::Reserved { expires_at_ms })
}

/// Extend a parked join, once, to the invite's own expiry.
///
/// Only while the invite is live. Without that filter this was the lever that made a
/// revoked-but-in-flight join worth waiting for: it widens a ten minute reservation
/// to the invite's whole expiry, so a parked joiner could sit for days and then
/// commit. Revocation now ends the extension as well as the commit. WEALD-345.
///
/// The relay verifies nothing about the client's claim that local setup finished and
/// does not need to: the extension consumes the seat it already holds, is bound to
/// the same nonce and device hash, and can never outlive the invite. Without it the
/// parked-join path expires the seat it is waiting on, and a joiner who did
/// everything asked of them finds a burnt invite and a recovery phrase for a
/// workspace they never entered.
/// Both halves move or neither does. The seat and the credential are two rows and
/// extending only the first is the bug this function was written to prevent
/// happening in a different place: `store::reserve` gave the device a provisional
/// grant expiring with the ten minute reservation, and widening the reservation
/// alone left the joiner holding a seat it could no longer authenticate to use,
/// because admission reads the grant's own expiry (`access::store::admits`). The
/// joiner did everything asked of them and was refused at AUTH with a live seat.
/// WEALD-475.
pub async fn extend(pool: &PgPool, token: &[u8], nonce: &[u8]) -> Result<bool, StoreError> {
    let mut tx = pool.begin().await.map_err(db)?;
    let done = sqlx::query(
        "update relay_invite_reservation r set expires_at = i.expires_at, extended = true \
         from relay_invite i where i.token = r.token and r.token = $1 and r.join_nonce = $2 \
           and r.extended = false and r.consumed_at is null and r.released_at is null \
           and i.state = 'live'",
    )
    .bind(token)
    .bind(nonce)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    if done.rows_affected() == 0 {
        tx.rollback().await.map_err(db)?;
        return Ok(false);
    }
    // The credential, to the same instant and never past it: `i.expires_at` is the
    // invite's own expiry, which is the ceiling the doc comment above promises. The
    // void guard is the same one `access::store::grant` carries and for the same
    // reason: an extension must not be the lever that undoes a revocation, and a
    // device voided between the reservation and here stays voided with its seat
    // widened and its credential dead, which is the refusal we want.
    sqlx::query(
        "update relay_provisional_grant g set expires_at = i.expires_at \
         from relay_invite i, relay_invite_reservation r \
         where r.token = $1 and r.join_nonce = $2 and i.token = r.token \
           and g.workspace_id = i.workspace_id and g.device_hash = r.device_hash \
           and g.voided_at is null",
    )
    .bind(token)
    .bind(nonce)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok(true)
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
                exists (select 1 from relay_invite_tombstone t where t.token = r.token) \
                    as tombstoned, \
                (extract(epoch from i.expires_at) * 1000)::double precision as invite_expires_ms \
         from relay_invite_reservation r join relay_invite i on i.token = r.token \
         where r.token = $1 and r.join_nonce = $2 and r.released_at is null \
           and (i.state = 'live' \
                or (i.state = 'spent' and r.consumed_at is not null))",
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

    // Revocation has to reach a join that is already in flight. `terminate` leaves
    // the reservation in place and marks the invite, so the state filter above is
    // the first half; the tombstone is the second, because it is the record that
    // survives and it is what the grant rules read. Both are checked on every
    // commit rather than once at reserve time, since the admin's revocation lands
    // between two frames of the same join.
    if row.get::<bool, _>("tombstoned") {
        return Ok(None);
    }

    // The invite's own expiry, enforced rather than merely selected. Without this a
    // reservation taken a minute before expiry could be committed indefinitely, and
    // the grant it ends in would be dated from an invite that is long dead.
    let invite_expires_ms: f64 = row.get("invite_expires_ms");
    if now_ms as f64 >= invite_expires_ms {
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
    let mut tx = pool.begin().await.map_err(db)?;
    sqlx::query(
        "update relay_invite_reservation set consumed_at = now() \
         where token = $1 and join_nonce = $2 and consumed_at is null",
    )
    .bind(token)
    .bind(nonce)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    // A void survives this. If revocation reached the grant while the join was in
    // flight, the seat is still spent (the reservation was real and the group work
    // was done) but the credential stays dead: the last frame of a join must not be
    // able to undo the admin's decision.
    //
    // Inside the transaction that spends the seat, as `reserve` does: a grant that
    // failed after the consume landed left the seat spent and the joiner holding
    // only the ten minute reservation credential, with the retry refused because
    // `consumed_at` was already set (WEALD-382).
    if let Err(error) =
        crate::access::store::grant(&mut *tx, &workspace_id, device_hash, invite_expires_ms).await
    {
        tx.rollback().await.map_err(db)?;
        return Err(StoreError::Database(error.to_string()));
    }

    // The last seat and the end of the invite are one fact, so they land in one
    // transaction (WEALD-L188). `remaining` is zero only when no seat is left to
    // sell, and the reservation test covers the seats that are held but not yet
    // spent: an invite with a live reservation outstanding is not exhausted, it is
    // mid-join. Ending it here is what deletes the retained sealed `GroupInfo`,
    // which otherwise outlives every possible redemption of the token.
    let exhausted: bool = sqlx::query(
        "select i.remaining = 0 and not exists ( \
             select 1 from relay_invite_reservation r \
             where r.token = $1 and r.consumed_at is null and r.released_at is null \
         ) as exhausted \
         from relay_invite i where i.token = $1 and i.state = 'live' for update",
    )
    .bind(token)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?
    .map(|row| row.get::<bool, _>("exhausted"))
    .unwrap_or(false);
    if exhausted {
        crate::invite::store::spend_in(&mut tx, token).await?;
    }

    tx.commit().await.map_err(db)?;
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

/// Whether this pair, or the whole token, is inside its fifteen-minute cooldown.
///
/// Two bounds in one read. The pair bound is the per-address one; the token-wide
/// sum is what holds against a guesser spread over many addresses, because sources
/// are cheap in aggregate even though no single one is attacker-chosen. The sum
/// counts only rows still inside their window: `sweep_attempts` removes the rest,
/// so a token that has been quiet for a cooldown interval starts from zero.
async fn cooled_down(
    pool: &PgPool,
    token: &[u8],
    source: &[u8],
    now_ms: i64,
) -> Result<bool, StoreError> {
    let row = sqlx::query(
        "select 1 as present from relay_invite_attempt \
         where token = $1 and source_hash = $2 \
           and cooldown_until > to_timestamp($3::double precision / 1000) \
         union all \
         select 1 as present from relay_invite_attempt \
         where token = $1 \
           and (window_started > to_timestamp($3::double precision / 1000) - make_interval(secs => $5::double precision) \
                or cooldown_until > to_timestamp($3::double precision / 1000)) \
         group by token having coalesce(sum(failures), 0) >= $4 \
         limit 1",
    )
    .bind(token)
    .bind(source)
    .bind(now_ms)
    .bind(code::MAX_TOKEN_FAILURES)
    .bind(code::COOLDOWN_SECONDS as f64)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    Ok(row.is_some())
}

/// Take one attempt slot against one pair before the code is verified, and say
/// whether the caller may proceed to Argon2id.
///
/// Charging first is what makes the budget real. The `on conflict do update` is one
/// statement, so it takes the row lock: concurrent attempts against one pair
/// serialize on it and each one sees its own incremented count, where a preceding
/// read would have let all of them see the same count below the ceiling. The update
/// is skipped when the pair is already cooled down, which does two things at once:
/// it refuses the attempt (no row comes back), and it stops a cooled guesser from
/// inflating the token-wide sum, which would otherwise let one address cool a whole
/// invite down for everybody.
///
/// The token-wide sum is read in the same statement and bounds the spread-out
/// guesser. It sums the other sources and adds this charge, because the row this
/// statement just wrote is not in the snapshot the subquery reads. Simultaneous
/// first attempts from many distinct sources can still each be admitted against a
/// sum that is a moment stale; what holds unconditionally is the per-pair ceiling,
/// and a source address is not free to mint.
///
/// The sweep runs first, in the same call, so the table is bounded by writes to it
/// rather than by a timer somebody has to remember: a row whose cooldown has
/// passed and whose window is stale says nothing the next decision needs, and rows
/// per token are then at most the distinct recent sources, each of which paid for
/// its row with a real connection.
async fn claim_attempt(
    pool: &PgPool,
    token: &[u8],
    source: &[u8],
    now_ms: i64,
) -> Result<bool, StoreError> {
    sweep_attempts(pool, token, now_ms).await?;
    let row = sqlx::query(
        "with charged as ( \
             insert into relay_invite_attempt (token, source_hash, failures, window_started) \
             values ($1, $2, 1, to_timestamp($4::double precision / 1000)) \
             on conflict (token, source_hash) do update \
             set failures = relay_invite_attempt.failures + 1, \
                 cooldown_until = case when relay_invite_attempt.failures + 1 >= $3 \
                     then to_timestamp($4::double precision / 1000) + make_interval(secs => $5::double precision) \
                     else relay_invite_attempt.cooldown_until end \
             where relay_invite_attempt.cooldown_until is null \
                or relay_invite_attempt.cooldown_until <= to_timestamp($4::double precision / 1000) \
             returning failures) \
         select charged.failures as failures, \
                (charged.failures + (select coalesce(sum(a.failures), 0) from relay_invite_attempt a \
                  where a.token = $1 and a.source_hash <> $2 \
                    and (a.window_started > to_timestamp($4::double precision / 1000) - make_interval(secs => $5::double precision) \
                         or a.cooldown_until > to_timestamp($4::double precision / 1000))))::bigint as total \
           from charged",
    )
    .bind(token)
    .bind(source)
    .bind(code::MAX_FAILURES)
    .bind(now_ms)
    .bind(code::COOLDOWN_SECONDS as f64)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    // No row means the pair was already cooled down and nothing was charged.
    let Some(row) = row else {
        return Ok(false);
    };
    // The slot that reaches the ceiling is spent, not refused: five wrong codes are
    // five verifications, and the sixth is what the cooldown answers. The sum is
    // read after the charge, so the same rule applies to the token-wide ceiling.
    Ok(row.get::<i32, _>("failures") <= code::MAX_FAILURES
        && row.get::<i64, _>("total") <= code::MAX_TOKEN_FAILURES)
}

/// Give back the slot a correct code took.
///
/// Only reachable past `code::verify`, so it cannot be used to reset a budget
/// without the code the budget protects. Clearing the cooldown when the count falls
/// back under the ceiling matters for the pair whose last slot was the one that
/// succeeded: the joiner who typed it correctly must not leave the office address
/// cooled down behind them.
async fn refund_attempt(pool: &PgPool, token: &[u8], source: &[u8]) -> Result<(), StoreError> {
    sqlx::query(
        "update relay_invite_attempt \
         set failures = greatest(failures - 1, 0), \
             cooldown_until = case when greatest(failures - 1, 0) >= $3 \
                 then cooldown_until else null end \
         where token = $1 and source_hash = $2",
    )
    .bind(token)
    .bind(source)
    .bind(code::MAX_FAILURES)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(())
}

/// Remove attempt rows that no longer inform any decision: the cooldown, if one
/// was ever set, has passed, and the window is older than a cooldown interval.
/// Both the per-pair check and the token-wide sum then read only live rows.
async fn sweep_attempts(pool: &PgPool, token: &[u8], now_ms: i64) -> Result<(), StoreError> {
    sqlx::query(
        "delete from relay_invite_attempt \
         where token = $1 \
           and (cooldown_until is null or cooldown_until <= to_timestamp($2::double precision / 1000)) \
           and window_started <= to_timestamp($2::double precision / 1000) - make_interval(secs => $3::double precision)",
    )
    .bind(token)
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
