// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The genesis key, the bootstrap invite, and log entry zero.
//!
//! `specs/backend/relay/invites.md`, "Bootstrap is an invite". The first device
//! enrolling into an empty workspace uses the same primitive as everyone else: no
//! separate bootstrap token type, no separate expiry rule, no separate reissue
//! endpoint, and no second code path to audit.
//!
//! Every other invite is signed by a device holding `admit`, and validation is "the
//! issuer signature chains to the workspace trust root". At bootstrap there is no
//! trust root and no device, so the relay signs. That means the relay briefly holds
//! a key that can mint an admin authorization, and on the hosted tier that relay is
//! ours. It is bounded in four ways and all four are release blocking:
//!
//! 1. **Generated on first run, for one purpose.** A fresh Ed25519 keypair, used to
//!    sign exactly one invite record and nothing else, ever. Not a service identity,
//!    not the TLS key, and it signs no other frame in the protocol.
//! 2. **Destroyed on redemption**, in the same transaction that records the trust
//!    root. There is no configuration flag and no support command that restores it.
//! 3. **Fingerprint printed and pinned**, at first run, and recorded by the
//!    enrolling client as the workspace's genesis anchor.
//! 4. **Genesis is the first transparency log entry, not an untracked event.** An
//!    earlier draft said bootstrap consumption was recorded in the membership
//!    transparency log, which was vacuous: at bootstrap the log did not exist yet,
//!    because the trust root creates it. So the log begins at genesis, entry zero,
//!    and there is no unlogged prefix.
//!
//! ## What consumption is
//!
//! Every other invite retires its reservation on the final scope commit. A bootstrap
//! invite has no scopes, so that rule names nothing, and left there the most
//! security-critical seat in the product would have no defined moment of consumption
//! and the genesis key no defined moment of death.
//!
//! Consumption is therefore the **acceptance of the genesis access set**: the first
//! valid `ACCESS` publication whose sole authorizer is the reserving device. It is
//! the right event because it is the first thing a trust root does that the relay
//! can verify unaided, it is signed by the device the reservation was bound to, and
//! it is the artifact that makes the workspace reachable at all.
//!
//! ## One spec disagreement, recorded
//!
//! invites.md calls that publication "the first valid `ACCESS` frame at `version`
//! 1". The genesis publication is version **0** everywhere else in the system:
//! `specs/backend/relay/wire.md` writes `prev_hash` as "zero at genesis" and
//! `access::judge` has required `version == 0` with an all-zero `prev_hash` since
//! step 6, which is green and shipped. "Version 1" reads as "the first version"
//! rather than as a second publication, so the rule implemented here is "the first
//! accepted set", and invites.md is corrected rather than the four things that
//! already agree.

use sqlx::{PgPool, Postgres, Row, Transaction};

use super::code::Code;
use super::store::StoreError;
use super::{EncBundle, Invite, BOOTSTRAP_EXPIRY_MS, HASH_BYTES, TOKEN_BYTES};
use crate::access::AccessSet;
use crate::cbor;

/// The label entry zero carries.
pub const GENESIS_KIND: &str = "genesis";

/// What a first run produced, for the operator's stdout and nowhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstRun {
    pub public_key: Vec<u8>,
    pub fingerprint: Vec<u8>,
    pub token: Vec<u8>,
    /// The one-time code. Held only long enough to print it: it is not stored, and
    /// what the relay keeps is the Argon2id hash inside the signed record.
    pub code: Code,
}

/// The state of a relay's genesis key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ensured {
    /// Minted just now.
    Minted(FirstRun),
    /// Already there. `redeemed` is the answer to "can this relay mint a second
    /// bootstrap invite", and it is permanently no once it is true.
    Existing {
        fingerprint: Vec<u8>,
        token: Vec<u8>,
        redeemed: bool,
    },
}

/// Which workspace a device holding a live genesis reservation is founding.
///
/// The first `ACCESS` a workspace ever receives arrives before any group exists,
/// because groups are created by the trust root after it is admitted. So the
/// ordinary resolution, which reads the workspace off a group the connection named,
/// has nothing to read. This is the other way in and it is deliberately narrow: a
/// device is answered a workspace only when it holds the live, unconsumed
/// reservation on that workspace's bootstrap invite, which is one device per
/// workspace and only until the seat is spent.
///
/// The comparison is done here rather than in SQL because the stored value is
/// salted per workspace (`access::entry_hash`), so the hash to look for depends on
/// the row it is being compared against.
pub async fn founding_workspace(
    pool: &PgPool,
    authorizer: &[u8],
) -> Result<Option<String>, StoreError> {
    let rows = sqlx::query(
        "select g.workspace_id, w.salt, r.device_hash \
         from relay_genesis g \
         join relay_invite_reservation r on r.token = g.token \
         join relay_workspace w on w.workspace_id = g.workspace_id \
         where g.secret_key is not null and r.consumed_at is null and r.released_at is null \
           and r.expires_at > now()",
    )
    .fetch_all(pool)
    .await
    .map_err(super::store::db)?;
    for row in rows {
        let salt: Vec<u8> = row.get("salt");
        let device_hash: Vec<u8> = row.get("device_hash");
        if crate::access::entry_hash(authorizer, &salt) == device_hash {
            return Ok(Some(row.get("workspace_id")));
        }
    }
    Ok(None)
}

/// BLAKE3 of the genesis public key. What goes to stdout and what a client pins.
pub fn fingerprint(public_key: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"weald genesis v1");
    hasher.update(public_key);
    hasher.finalize().as_bytes().to_vec()
}

/// Lower-case hex, for the printed forms.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// What a self-hoster reads on their terminal at first run.
///
/// The link and the code both, because for a self-hoster the genesis key never
/// leaves their machine and the two-channel split protects them against nothing they
/// do not already control. On the hosted tier the two halves go to different places
/// and neither of them is here.
///
/// The link carries no `#<secret>` fragment, and that is not an omission. A fragment
/// exists to hand a joiner the private half of `update_pub` so it can open the
/// sealed bundles; a bootstrap invite has no scopes and therefore no bundles, so
/// there is nothing to seal and nothing to open. The relay consequently never
/// derives, holds or prints a private encryption key for an invite, which is a
/// stronger statement than "it deletes one afterwards".
pub fn banner(hostname: &str, run: &FirstRun) -> String {
    format!(
        "weald: this workspace has no members yet.\n\
         weald:   invite link  https://{hostname}/join/{token}\n\
         weald:   invite code  {code}\n\
         weald:   genesis key  {fingerprint}\n\
         weald: the code is not in the link on purpose. The genesis key signs this\n\
         weald: one record and is destroyed when it is redeemed.",
        token = hex(&run.token),
        code = run.code.grouped(),
        fingerprint = hex(&run.fingerprint),
    )
}

/// What a self-hoster reads on every later start while the workspace is still
/// empty.
///
/// The link only. The code is not in it because the code is not recoverable: the
/// relay stores an Argon2id hash of it and never the value, so there is nothing to
/// reprint. Saying that plainly is the point of this banner. An operator who lost
/// the first-run output would otherwise go looking for a reissue command, and
/// there is deliberately none: reissuing a bootstrap invite would create a second
/// route to trust root, which is the attack
/// `specs/backend/contracts/threat-model/bootstrap-handoff.md` control B6 exists
/// to close.
///
/// Reprinting the link is safe in a way reprinting the code would not be. The link
/// half enrolls nobody on its own, and it is already in the hands of whoever asked
/// for it.
pub fn reminder(hostname: &str, token: &[u8], fingerprint: &[u8]) -> String {
    format!(
        "weald: this workspace still has no members.\n\
         weald:   invite link  https://{hostname}/join/{token}\n\
         weald:   genesis key  {fingerprint}\n\
         weald: the one-time code cannot be reprinted. The relay keeps only its\n\
         weald: hash, and there is no reissue: a second bootstrap invite would be a\n\
         weald: second route to trust root. If the code is lost, start this relay\n\
         weald: again against an empty database.",
        token = hex(token),
        fingerprint = hex(fingerprint),
    )
}

/// What an operator reads on a hosted relay's first run.
///
/// The fingerprint and nothing else, which is the whole of `server.md`'s "prints
/// only those non-secret fingerprints". A fingerprint is a public key's fingerprint:
/// publishing it grants nobody anything and its entire purpose is to be compared out
/// of band, so it is the one value that belongs in a log an operator can read.
///
/// The link and the code are both absent, and absent for different reasons. The link
/// half is claimed once by the buyer's browser and the code half is mailed to their
/// verified address; a copy on this relay's stdout would be a third copy, in a place
/// neither of them chose, held by the party the two-channel split exists to exclude.
pub fn sealed_banner(hostname: &str, fingerprint: &[u8]) -> String {
    format!(
        "weald: this workspace has no members yet.\n\
         weald:   relay        {hostname}\n\
         weald:   genesis key  {fingerprint}\n\
         weald: the enrollment link and the one-time code were sealed to the\n\
         weald: handoff key and are not printed here. They reach the buyer through\n\
         weald: the dashboard and their verified email, on purpose.",
        fingerprint = hex(fingerprint),
    )
}

/// Mint the bootstrap invite if this relay has never had one, otherwise say so.
///
/// Idempotent, and idempotent in the direction that matters: a relay that has been
/// enrolled cannot mint a second bootstrap invite, and a relay restarted before
/// enrolment gets the same record back rather than a second one.
pub async fn ensure(pool: &PgPool, workspace_id: &str, now_ms: i64) -> Result<Ensured, StoreError> {
    // Two passes at most, and the second only happens when somebody else won the
    // mint. A rolling deploy starts two processes against one database
    // (`specs/backend/relay/server.md`), both read no genesis, and both try; the
    // loser goes round once and reads the winner's key. It cannot loop further,
    // because the second pass either reads a row or refuses: a relay that kept
    // retrying against a database that swallows its writes would spin for ever
    // rather than say what was wrong.
    //
    // Written as a loop rather than as a re-read at the conflict, so there is one
    // `read` in this function and one failure path through it. Two would have been
    // one arm nobody can reach: a read that works on the way in and fails a
    // millisecond later is not a state a test can stage.
    let mut attempted = false;
    loop {
        // The transaction is opened first, before anything else touches the
        // database. Everything below either lands together or does not land: an
        // invite record with no `relay_genesis` row is a live single-use bootstrap
        // invite that `read` cannot see, so the next call would mint a second one and
        // the workspace would have two. Opening it first also means a relay that
        // cannot begin a transaction says so before it has written a workspace row
        // for a genesis it is then going to fail to mint.
        let mut tx = pool.begin().await.map_err(super::store::db)?;
        // Both of these run on `tx`, never on `pool`. Each pool call made here
        // checked out another connection while this transaction held one, so a
        // handful of concurrent mints could hold every connection in the pool and
        // wait on each other for the next, starving `AUTH` and `SEND` of the pool
        // they share. It also makes the workspace row atomic with the genesis it
        // is being written for.
        crate::access::store::salt_within(&mut tx, workspace_id)
            .await
            .map_err(|error| StoreError::Database(error.to_string()))?;
        if let Some(existing) = read(&mut *tx, workspace_id).await? {
            return Ok(existing);
        }
        if attempted {
            // The second pass found no row after losing the first. Something removed
            // it between the insert and this read, and there is no honest verdict to
            // give: not a mint this relay made, and not a key it can name.
            return Err(StoreError::Database("genesis vanished mid-mint".into()));
        }

        let secret = random_bytes::<32>();
        let signing = ed25519_dalek::SigningKey::from_bytes(&secret);
        let public_key = signing.verifying_key().to_bytes().to_vec();
        let token = random_bytes::<TOKEN_BYTES>();
        let code = Code::random();
        let code_hash = super::code::hash_token(code, &token).to_vec();

        let expires = (now_ms.max(0) as u64) + BOOTSTRAP_EXPIRY_MS;
        let mut invite = Invite {
            token: token.to_vec(),
            // The workspace root group does not exist yet: there are no groups. The
            // field carries the workspace id the relay will use, and the
            // mandatory-root rule is satisfied by the bootstrap exemption rather than
            // by this value.
            workspace: workspace_hash(workspace_id),
            issuer: public_key.clone(),
            issued_at: now_ms.max(0) as u64,
            expires,
            uses: 1,
            code_hash,
            scopes: Vec::new(),
            caps: vec![b"admin".to_vec()],
            // No scopes means no bundles, so nothing is sealed to this key and no
            // private half exists anywhere. Random rather than derived, so there is
            // no derivation for anyone to claim the relay could have kept.
            update_pub: random_bytes::<32>().to_vec(),
            bundles: Vec::<EncBundle>::new(),
            sig: vec![0u8; super::SIG_BYTES],
        };
        invite.sig = sign(&signing, &invite.digest_input());

        super::store::insert_within(&mut tx, workspace_id, &invite, true, now_ms).await?;
        let print = fingerprint(&public_key);
        let inserted = sqlx::query(
            "insert into relay_genesis \
             (workspace_id, public_key, secret_key, fingerprint, token) \
             values ($1, $2, $3, $4, $5) on conflict (workspace_id) do nothing",
        )
        .bind(workspace_id)
        .bind(&public_key)
        .bind(secret.as_slice())
        .bind(&print)
        .bind(token)
        // `on conflict do nothing` rather than a plain insert: the loser of the race
        // above must not report a failure, because the workspace has exactly one
        // genesis key and that is the invariant.
        .execute(&mut *tx)
        .await
        .map_err(super::store::db)?;
        if inserted.rows_affected() == 0 {
            // Dropped rather than committed, which rolls this process's invite back
            // along with the genesis row it could not write. Leaving the invite would
            // put a second live bootstrap invite in the table for a workspace that
            // already has one.
            drop(tx);
            attempted = true;
            continue;
        }
        tx.commit().await.map_err(super::store::db)?;

        return Ok(Ensured::Minted(FirstRun {
            public_key,
            fingerprint: print,
            token: token.to_vec(),
            code,
        }));
    }
}

/// Executor-generic so the mint loop can run it on its own open transaction. Read
/// on the pool while that transaction is held, it checked out a second connection
/// and made issuance compete with `AUTH` and `SEND` for the pool.
async fn read<'a, E>(executor: E, workspace_id: &str) -> Result<Option<Ensured>, StoreError>
where
    E: sqlx::Executor<'a, Database = Postgres>,
{
    let row = sqlx::query(
        "select fingerprint, token, secret_key is null as redeemed \
         from relay_genesis where workspace_id = $1",
    )
    .bind(workspace_id)
    .fetch_optional(executor)
    .await
    .map_err(super::store::db)?;
    Ok(row.map(|row| Ensured::Existing {
        fingerprint: row.get("fingerprint"),
        token: row.get("token"),
        redeemed: row.get("redeemed"),
    }))
}

/// Accept the genesis access set, and end the genesis key with it.
///
/// Called from inside `access::store::publish`'s transaction, because invites.md
/// requires one transaction: "the relay accepts that set, retires the reservation,
/// marks the invite spent, and zeroes the genesis private key". Two transactions
/// would leave a window in which the trust root exists and the key that could mint a
/// rival one still does.
///
/// Answers `false` for every publication that is not this one, including every
/// publication after it. A redeemed genesis key is refused: the row has no secret
/// half to find, so there is nothing to retire a second time.
pub(crate) async fn consume_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: &str,
    candidate: &AccessSet,
    salt: &[u8],
) -> Result<bool, sqlx::Error> {
    // Only the first accepted set. See the module note: invites.md says "version 1"
    // and means the first version, which is 0 in the encoding every other part of
    // the system already agrees on.
    if candidate.version != 0 {
        return Ok(false);
    }
    // "whose sole authorizer is the reserving device". Sole, so a genesis set naming
    // two authorizers does not consume anything: the reservation was bound to one
    // device hash and a set that names a second is not the artifact this rule
    // describes.
    if candidate.authorizers.len() != 1 {
        return Ok(false);
    }
    let row = sqlx::query(
        "select g.token, r.join_nonce, r.device_hash from relay_genesis g \
         join relay_invite_reservation r on r.token = g.token \
         where g.workspace_id = $1 and g.secret_key is not null \
           and r.consumed_at is null and r.released_at is null \
         for update of g, r",
    )
    .bind(workspace_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let device_hash: Vec<u8> = row.get("device_hash");
    if crate::access::entry_hash(&candidate.authorizers[0], salt) != device_hash {
        return Ok(false);
    }
    let token: Vec<u8> = row.get("token");
    let nonce: Vec<u8> = row.get("join_nonce");

    sqlx::query(
        "update relay_invite_reservation set consumed_at = now() \
         where token = $1 and join_nonce = $2",
    )
    .bind(&token)
    .bind(&nonce)
    .execute(&mut **tx)
    .await?;
    sqlx::query("update relay_invite set state = 'spent', remaining = 0 where token = $1")
        .bind(&token)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "update relay_genesis set secret_key = null, redeemed_at = now() \
         where workspace_id = $1",
    )
    .bind(workspace_id)
    .execute(&mut **tx)
    .await?;
    // The sealed handoff describes this invite, and this invite is now spent, so the
    // ciphertexts go in the same transaction that retires the key.
    super::handoff::forget_in_tx(tx, workspace_id).await?;

    let public_key: Vec<u8> =
        sqlx::query("select public_key from relay_genesis where workspace_id = $1")
            .bind(workspace_id)
            .fetch_one(&mut **tx)
            .await?
            .get("public_key");
    let body = entry_zero_body(&public_key, &candidate.authorizers[0], &device_hash);
    let prev_hash = vec![0u8; HASH_BYTES];
    let entry_hash = chain(&prev_hash, &body);
    sqlx::query(
        "insert into relay_transparency_log \
         (workspace_id, seq, kind, body, prev_hash, entry_hash) \
         values ($1, 0, $2, $3, $4, $5)",
    )
    .bind(workspace_id)
    .bind(GENESIS_KIND)
    .bind(&body)
    .bind(&prev_hash)
    .bind(&entry_hash)
    .execute(&mut **tx)
    .await?;
    Ok(true)
}

/// Entry zero: the genesis key, its fingerprint, and the trust root it admitted.
///
/// The device hash is carried alongside the trust root's key because the hash is
/// what the reservation was bound to, and an auditor checking "the key that signed
/// the first set is the device the seat was held for" needs both halves in the
/// entry rather than in two tables.
pub fn entry_zero_body(genesis_public: &[u8], trust_root: &[u8], device_hash: &[u8]) -> Vec<u8> {
    cbor::array(&[
        cbor::bytes(genesis_public),
        cbor::bytes(&fingerprint(genesis_public)),
        cbor::bytes(trust_root),
        cbor::bytes(device_hash),
    ])
}

/// BLAKE3 over the previous entry hash and this entry's body. The log is a chain,
/// so an entry cannot be replaced without replacing everything after it.
pub fn chain(prev_hash: &[u8], body: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prev_hash);
    hasher.update(body);
    hasher.finalize().as_bytes().to_vec()
}

/// One transparency log entry, as it is read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub seq: u64,
    pub kind: String,
    pub body: Vec<u8>,
    pub prev_hash: Vec<u8>,
    pub entry_hash: Vec<u8>,
}

/// The whole log for a workspace, ascending. Entry zero is genesis or the log is
/// empty; there is no third state, because the trust root creates the log.
pub async fn log(pool: &PgPool, workspace_id: &str) -> Result<Vec<LogEntry>, StoreError> {
    let rows = sqlx::query(
        "select seq, kind, body, prev_hash, entry_hash from relay_transparency_log \
         where workspace_id = $1 order by seq asc",
    )
    .bind(workspace_id)
    .fetch_all(pool)
    .await
    .map_err(super::store::db)?;
    Ok(rows
        .iter()
        .map(|row| LogEntry {
            seq: u64::try_from(row.get::<i64, _>("seq")).unwrap_or_default(),
            kind: row.get("kind"),
            body: row.get("body"),
            prev_hash: row.get("prev_hash"),
            entry_hash: row.get("entry_hash"),
        })
        .collect())
}

/// Whether the chain in a read-back log holds.
pub fn log_verifies(entries: &[LogEntry]) -> bool {
    let mut previous = vec![0u8; HASH_BYTES];
    for (index, entry) in entries.iter().enumerate() {
        if entry.seq != index as u64 || entry.prev_hash != previous {
            return false;
        }
        if entry.entry_hash != chain(&entry.prev_hash, &entry.body) {
            return false;
        }
        previous = entry.entry_hash.clone();
    }
    true
}

/// The workspace id as the 32 bytes the record's `workspace` field carries.
fn workspace_hash(workspace_id: &str) -> Vec<u8> {
    blake3::hash(workspace_id.as_bytes()).as_bytes().to_vec()
}

fn sign(signing: &ed25519_dalek::SigningKey, message: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    signing.sign(message).to_bytes().to_vec()
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("the operating system must provide randomness");
    bytes
}
