// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Genesis: the one key the relay owns, and the log entry that outlives it.
//!
//! The negative leads. A redeemed genesis key is refused, permanently and by every
//! route: the relay cannot mint a second bootstrap invite, the spent token cannot be
//! reserved again, and there is no configuration flag or support call in this suite
//! or in the codebase that puts the private half back.
//!
//! Nothing here is mocked. The keypair is real, the signature over the bootstrap
//! record is real, the access set that consumes it is a real publication through the
//! real `access::store::publish`, and the log is read back out of Postgres and
//! re-hashed.

mod support;

use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey};
use sqlx::{PgPool, Row as _};
use wealdrelay::access::store as access_store;
use wealdrelay::access::{entry_hash, AccessSet};
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::invite::genesis::{self, Ensured};
use wealdrelay::invite::reserve::{self, Verdict};
use wealdrelay::invite::store::{self, State};
use wealdrelay::invite::{self, Invite};

use support::{config_for, Running, Scratch};

const WORKSPACE: &str = "ws-genesis";
const NOW: i64 = 1_700_000_000_000;
const NOW_U: u64 = 1_700_000_000_000;

async fn prepared(label: &str) -> (Scratch, tempfile::TempDir, Arc<RelayState>) {
    let scratch = Scratch::new(label).await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(1)).await;
    let state = Arc::clone(&relay.state);
    relay.shutdown().await;
    (scratch, blobs, state)
}

fn pool_of(state: &Arc<RelayState>) -> &PgPool {
    state.database.as_ref().expect("a database").pool()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pk(signer: &SigningKey) -> Vec<u8> {
    signer.verifying_key().to_bytes().to_vec()
}

fn sorted(mut items: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    items.sort();
    items.dedup();
    items
}

/// The genesis access set: version 0, all-zero `prev_hash`, its own sole
/// authorizer. `wire.md` and `access::judge` have agreed on this shape since step 6.
fn genesis_set(salt: &[u8], trust_root: &SigningKey, recovery: &SigningKey) -> AccessSet {
    let mut set = AccessSet {
        workspace: vec![0x77; 32],
        version: 0,
        prev_hash: vec![0u8; 32],
        issued_at: 1,
        entries: sorted(vec![
            entry_hash(&pk(trust_root), salt),
            entry_hash(&pk(recovery), salt),
        ]),
        authorizers: vec![pk(trust_root)],
        recovery: vec![pk(recovery)],
        quorum: None,
        pending: Vec::new(),
        signer: pk(trust_root),
        sig: vec![0u8; 64],
    };
    set.sig = trust_root.sign(&set.digest_input()).to_bytes().to_vec();
    set
}

async fn secret_is_present(pool: &PgPool) -> bool {
    sqlx::query("select secret_key is not null as held from relay_genesis where workspace_id = $1")
        .bind(WORKSPACE)
        .fetch_one(pool)
        .await
        .unwrap()
        .get("held")
}

// MARK: First run

#[tokio::test]
async fn a_first_run_mints_exactly_one_bootstrap_invite() {
    let (scratch, _blobs, state) = prepared("mint").await;
    let pool = pool_of(&state);

    let Ensured::Minted(run) = genesis::ensure(pool, WORKSPACE, NOW).await.unwrap() else {
        panic!("a fresh relay mints");
    };
    assert_eq!(run.fingerprint, genesis::fingerprint(&run.public_key));
    assert_eq!(run.token.len(), invite::TOKEN_BYTES);

    // The record is an ordinary invite in every way but the exemption: no scopes,
    // one seat, `admin` and only `admin`, and twenty-four hours rather than seven
    // days, because the buyer may not have installed the app yet.
    let stored = store::fetch(pool, &run.token).await.unwrap().unwrap();
    assert!(stored.bootstrap);
    assert!(stored.invite.scopes.is_empty());
    assert!(stored.invite.bundles.is_empty());
    assert_eq!(stored.invite.caps, vec![b"admin".to_vec()]);
    assert_eq!(stored.invite.uses, 1);
    assert_eq!(
        stored.invite.expires - stored.invite.issued_at,
        invite::BOOTSTRAP_EXPIRY_MS
    );
    // Signed by the genesis key and by nothing else.
    assert_eq!(stored.invite.issuer, run.public_key);
    assert!(stored.invite.signature_verifies());
    assert_eq!(invite::judge(&stored.invite, true, NOW_U), Ok(()));
    // And it is still refused by the ordinary rule, which is the exemption's whole
    // shape: bootstrap is a fact about the relay, not a claim in the record.
    assert!(invite::judge(&stored.invite, false, NOW_U).is_err());

    // A restart before enrolment gets the same record back rather than a second one.
    let again = genesis::ensure(pool, WORKSPACE, NOW).await.unwrap();
    assert_eq!(
        again,
        Ensured::Existing {
            fingerprint: run.fingerprint.clone(),
            token: run.token.clone(),
            redeemed: false,
        }
    );
    // Counted for this workspace. The relay bootstraps its own workspace at startup
    // (`serve::bootstrap`), so a count of every bootstrap invite in the database
    // would be counting that one too and would say nothing about this one.
    let count: i64 =
        sqlx::query("select count(*) as n from relay_invite where bootstrap and workspace_id = $1")
            .bind(WORKSPACE)
            .fetch_one(pool)
            .await
            .unwrap()
            .get("n");
    assert_eq!(count, 1);

    // What the operator reads. Both halves, because for a self-hoster the key never
    // leaves their machine.
    let banner = genesis::banner("relay.acme.com", &run);
    assert!(banner.contains(&genesis::hex(&run.token)));
    assert!(banner.contains(&run.code.grouped()));
    assert!(banner.contains(&genesis::hex(&run.fingerprint)));
    // No fragment: a bootstrap invite has no scopes, so nothing is sealed and there
    // is no private encryption key for the relay to hold or print.
    assert!(!banner.contains('#'));
    scratch.drop_database().await;
}

// MARK: Consumption

#[tokio::test]
async fn accepting_the_genesis_access_set_consumes_the_seat_and_ends_the_key() {
    let (scratch, _blobs, state) = prepared("consume").await;
    let pool = pool_of(&state);
    let Ensured::Minted(run) = genesis::ensure(pool, WORKSPACE, NOW).await.unwrap() else {
        panic!("mints");
    };
    let salt = access_store::salt(pool, WORKSPACE).await.unwrap();
    let trust_root = key(0x21);
    let device_hash = entry_hash(&pk(&trust_root), &salt);

    // The buyer completes local setup and reserves the one seat.
    assert!(matches!(
        reserve::reserve(
            pool,
            &run.token,
            &run.code.grouped(),
            &[0x01; 16],
            &device_hash,
            &[0x02; 32],
            NOW
        )
        .await
        .unwrap(),
        Verdict::Reserved { .. }
    ));
    assert!(secret_is_present(pool).await);
    assert!(genesis::log(pool, WORKSPACE).await.unwrap().is_empty());

    // And publishes the genesis access set, which is the first thing a trust root
    // does that the relay can verify unaided.
    let set = genesis_set(&salt, &trust_root, &key(0x3f));
    access_store::publish(pool, WORKSPACE, &set, &set.encode())
        .await
        .unwrap();

    // One transaction did all four things.
    assert!(!secret_is_present(pool).await);
    let spent = store::fetch(pool, &run.token).await.unwrap().unwrap();
    assert_eq!(spent.state, State::Spent);
    assert_eq!(spent.remaining, 0);
    let consumed: bool = sqlx::query(
        "select consumed_at is not null as done from relay_invite_reservation where token = $1",
    )
    .bind(&run.token)
    .fetch_one(pool)
    .await
    .unwrap()
    .get("done");
    assert!(consumed);

    // And the log begins with genesis, which is what makes "was this workspace
    // founded by the device I think founded it" a question with an answer forever.
    let log = genesis::log(pool, WORKSPACE).await.unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].seq, 0);
    assert_eq!(log[0].kind, genesis::GENESIS_KIND);
    assert_eq!(log[0].prev_hash, vec![0u8; 32]);
    assert_eq!(
        log[0].body,
        genesis::entry_zero_body(&run.public_key, &pk(&trust_root), &device_hash)
    );
    assert!(genesis::log_verifies(&log));
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_redeemed_genesis_key_is_refused() {
    let (scratch, _blobs, state) = prepared("redeemed").await;
    let pool = pool_of(&state);
    let Ensured::Minted(run) = genesis::ensure(pool, WORKSPACE, NOW).await.unwrap() else {
        panic!("mints");
    };
    let salt = access_store::salt(pool, WORKSPACE).await.unwrap();
    let trust_root = key(0x22);
    let device_hash = entry_hash(&pk(&trust_root), &salt);
    reserve::reserve(
        pool,
        &run.token,
        &run.code.grouped(),
        &[0x01; 16],
        &device_hash,
        &[0x02; 32],
        NOW,
    )
    .await
    .unwrap();
    let set = genesis_set(&salt, &trust_root, &key(0x3f));
    access_store::publish(pool, WORKSPACE, &set, &set.encode())
        .await
        .unwrap();

    // No second bootstrap invite at any price. `ensure` says redeemed and mints
    // nothing, now and on every restart from here.
    for _ in 0..2 {
        assert_eq!(
            genesis::ensure(pool, WORKSPACE, NOW + 1).await.unwrap(),
            Ensured::Existing {
                fingerprint: run.fingerprint.clone(),
                token: run.token.clone(),
                redeemed: true,
            }
        );
    }
    // Counted for this workspace. The relay bootstraps its own workspace at startup
    // (`serve::bootstrap`), so a count of every bootstrap invite in the database
    // would be counting that one too and would say nothing about this one.
    let count: i64 =
        sqlx::query("select count(*) as n from relay_invite where bootstrap and workspace_id = $1")
            .bind(WORKSPACE)
            .fetch_one(pool)
            .await
            .unwrap()
            .get("n");
    assert_eq!(count, 1);

    // The spent token cannot be reserved again, with the right code and everything.
    assert_eq!(
        reserve::reserve(
            pool,
            &run.token,
            &run.code.grouped(),
            &[0x03; 16],
            &entry_hash(&pk(&key(0x23)), &salt),
            &[0x02; 32],
            NOW
        )
        .await
        .unwrap(),
        Verdict::Unavailable
    );

    // And the private half is gone from the row rather than merely marked. There is
    // nothing left to sign a second record with.
    let secret: Option<Vec<u8>> =
        sqlx::query("select secret_key from relay_genesis where workspace_id = $1")
            .bind(WORKSPACE)
            .fetch_one(pool)
            .await
            .unwrap()
            .get("secret_key");
    assert!(secret.is_none());

    // A later publication cannot write a second entry zero: the log stays one entry
    // long and still verifies.
    let second = {
        let prior = access_store::current(pool, WORKSPACE)
            .await
            .unwrap()
            .prior
            .unwrap();
        let mut set = genesis_set(&salt, &trust_root, &key(0x3f));
        set.version = 1;
        set.prev_hash = prior.digest;
        set.sig = trust_root.sign(&set.digest_input()).to_bytes().to_vec();
        set
    };
    access_store::publish(pool, WORKSPACE, &second, &second.encode())
        .await
        .unwrap();
    let log = genesis::log(pool, WORKSPACE).await.unwrap();
    assert_eq!(log.len(), 1);
    assert!(genesis::log_verifies(&log));
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_set_that_is_not_the_reserving_devices_consumes_nothing() {
    let (scratch, _blobs, state) = prepared("wrong_root").await;
    let pool = pool_of(&state);
    let Ensured::Minted(run) = genesis::ensure(pool, WORKSPACE, NOW).await.unwrap() else {
        panic!("mints");
    };
    let salt = access_store::salt(pool, WORKSPACE).await.unwrap();
    let reserving = key(0x31);
    reserve::reserve(
        pool,
        &run.token,
        &run.code.grouped(),
        &[0x01; 16],
        &entry_hash(&pk(&reserving), &salt),
        &[0x02; 32],
        NOW,
    )
    .await
    .unwrap();

    // Somebody else races a genesis publication. It is a valid access set, so it is
    // accepted as one; it is not the artifact that consumes the bootstrap seat,
    // because the reservation was bound to a different device hash.
    let impostor = key(0x32);
    let set = genesis_set(&salt, &impostor, &key(0x3f));
    access_store::publish(pool, WORKSPACE, &set, &set.encode())
        .await
        .unwrap();

    assert!(secret_is_present(pool).await);
    assert_eq!(
        store::fetch(pool, &run.token).await.unwrap().unwrap().state,
        State::Live
    );
    assert!(genesis::log(pool, WORKSPACE).await.unwrap().is_empty());
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_set_naming_two_authorizers_consumes_nothing() {
    let (scratch, _blobs, state) = prepared("two_auth").await;
    let pool = pool_of(&state);
    let Ensured::Minted(run) = genesis::ensure(pool, WORKSPACE, NOW).await.unwrap() else {
        panic!("mints");
    };
    let salt = access_store::salt(pool, WORKSPACE).await.unwrap();
    let trust_root = key(0x41);
    let second = key(0x42);
    reserve::reserve(
        pool,
        &run.token,
        &run.code.grouped(),
        &[0x01; 16],
        &entry_hash(&pk(&trust_root), &salt),
        &[0x02; 32],
        NOW,
    )
    .await
    .unwrap();

    // "whose sole authorizer is the reserving device". A set naming a second
    // authorizer is not that artifact, so the seat and the key both survive it.
    let mut set = genesis_set(&salt, &trust_root, &key(0x3f));
    set.entries = sorted([set.entries.clone(), vec![entry_hash(&pk(&second), &salt)]].concat());
    set.authorizers = sorted(vec![pk(&trust_root), pk(&second)]);
    set.sig = trust_root.sign(&set.digest_input()).to_bytes().to_vec();
    access_store::publish(pool, WORKSPACE, &set, &set.encode())
        .await
        .unwrap();

    assert!(secret_is_present(pool).await);
    assert!(genesis::log(pool, WORKSPACE).await.unwrap().is_empty());
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_publication_in_a_workspace_with_no_genesis_row_is_ordinary() {
    // Every workspace that was not bootstrapped through this relay, which is every
    // workspace in the step 6 suite, publishes exactly as it did before.
    let (scratch, _blobs, state) = prepared("no_genesis").await;
    let pool = pool_of(&state);
    let salt = access_store::salt(pool, WORKSPACE).await.unwrap();
    let trust_root = key(0x51);
    let set = genesis_set(&salt, &trust_root, &key(0x3f));
    let accepted = access_store::publish(pool, WORKSPACE, &set, &set.encode())
        .await
        .unwrap();
    assert_eq!(accepted.version, 0);
    assert!(genesis::log(pool, WORKSPACE).await.unwrap().is_empty());
    scratch.drop_database().await;
}

// MARK: The log

#[test]
fn the_log_is_a_chain_and_a_broken_one_is_visible() {
    let genesis_public = vec![0x61; 32];
    let trust_root = vec![0x62; 32];
    let device_hash = vec![0x63; 32];
    let body = genesis::entry_zero_body(&genesis_public, &trust_root, &device_hash);
    let prev = vec![0u8; 32];
    let entry = genesis::LogEntry {
        seq: 0,
        kind: genesis::GENESIS_KIND.to_string(),
        body: body.clone(),
        prev_hash: prev.clone(),
        entry_hash: genesis::chain(&prev, &body),
    };
    assert!(genesis::log_verifies(std::slice::from_ref(&entry)));
    // An empty log verifies: a workspace before its trust root has no entries, and
    // the log is created by the trust root rather than before it.
    assert!(genesis::log_verifies(&[]));

    // Every way to break the chain is visible.
    let mut wrong_seq = entry.clone();
    wrong_seq.seq = 1;
    assert!(!genesis::log_verifies(&[wrong_seq]));

    let mut wrong_prev = entry.clone();
    wrong_prev.prev_hash = vec![9u8; 32];
    assert!(!genesis::log_verifies(&[wrong_prev]));

    let mut tampered = entry.clone();
    tampered.body = genesis::entry_zero_body(&genesis_public, &[0xff; 32], &device_hash);
    assert!(!genesis::log_verifies(&[tampered]));

    // A second entry has to name the first.
    let second = genesis::LogEntry {
        seq: 1,
        kind: "join".to_string(),
        body: vec![1, 2, 3],
        prev_hash: entry.entry_hash.clone(),
        entry_hash: genesis::chain(&entry.entry_hash, &[1, 2, 3]),
    };
    assert!(genesis::log_verifies(&[entry.clone(), second.clone()]));
    let mut orphan = second;
    orphan.prev_hash = vec![0u8; 32];
    orphan.entry_hash = genesis::chain(&orphan.prev_hash, &orphan.body);
    assert!(!genesis::log_verifies(&[entry, orphan]));
}

#[test]
fn the_fingerprint_is_domain_separated_and_printable() {
    let a = genesis::fingerprint(&[0x11; 32]);
    let b = genesis::fingerprint(&[0x12; 32]);
    assert_eq!(a.len(), 32);
    assert_ne!(a, b);
    // Not a bare hash of the key: a genesis fingerprint and any other BLAKE3 of the
    // same bytes must not be the same string in an operator's terminal.
    assert_ne!(a, blake3::hash(&[0x11; 32]).as_bytes().to_vec());
    assert_eq!(genesis::hex(&[0x0a, 0xff]), "0aff");
}

#[test]
fn a_bootstrap_record_is_still_an_invite() {
    // No separate bootstrap token type, so the decoder that reads every other record
    // reads this one.
    let signing = key(0x71);
    let mut record = Invite {
        token: vec![0xaa; 16],
        workspace: vec![0xbb; 32],
        issuer: pk(&signing),
        issued_at: NOW as u64,
        expires: NOW as u64 + invite::BOOTSTRAP_EXPIRY_MS,
        uses: 1,
        code_hash: vec![0xcc; 32],
        scopes: Vec::new(),
        caps: vec![b"admin".to_vec()],
        update_pub: vec![0xdd; 32],
        bundles: Vec::new(),
        sig: vec![0u8; 64],
    };
    record.sig = signing.sign(&record.digest_input()).to_bytes().to_vec();
    assert_eq!(Invite::decode(&record.encode()), Ok(record.clone()));
    assert!(record.is_bootstrap_shaped());
    assert_eq!(invite::judge(&record, true, NOW_U), Ok(()));
}

// MARK: What consumption does when the database refuses part of it

/// Consumption is four writes inside the access-set publication's own transaction:
/// the reservation is marked used, the invite is spent, the private half of the
/// genesis key is destroyed, and entry zero of the transparency log is written.
///
/// They are one transaction on purpose. A partial consumption is the worst state
/// this system can be in: a genesis key destroyed with no log entry leaves a
/// workspace whose founding cannot be verified by anybody, ever, and a log entry
/// with the key still live leaves a second founding possible. So each write is
/// refused in turn and the whole publication must fail with nothing changed.
#[tokio::test]
async fn a_consumption_that_cannot_finish_changes_nothing_at_all() {
    for (table, event) in [
        ("relay_invite_reservation", "update"),
        ("relay_invite", "update"),
        ("relay_genesis", "update"),
        ("relay_transparency_log", "insert"),
    ] {
        let label = format!("consume_{table}_{event}");
        let (scratch, _blobs, state) = prepared(&label).await;
        let pool = pool_of(&state);
        let Ensured::Minted(run) = genesis::ensure(pool, WORKSPACE, NOW).await.unwrap() else {
            panic!("mints");
        };
        let salt = access_store::salt(pool, WORKSPACE).await.unwrap();
        let trust_root = key(0x21);
        let device_hash = entry_hash(&pk(&trust_root), &salt);
        reserve::reserve(
            pool,
            &run.token,
            &run.code.grouped(),
            &[0x01; 16],
            &device_hash,
            &[0x02; 32],
            NOW,
        )
        .await
        .unwrap();

        sqlx::query(
            "create or replace function weald_injected_refusal() returns trigger \
             language plpgsql as $$ begin raise exception 'injected'; end $$",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(&format!(
            "create trigger weald_injected before {event} on {table} \
             for each statement execute function weald_injected_refusal()"
        ))
        .execute(pool)
        .await
        .unwrap();

        let set = genesis_set(&salt, &trust_root, &key(0x3f));
        let outcome = access_store::publish(pool, WORKSPACE, &set, &set.encode()).await;
        assert!(
            outcome.is_err(),
            "{label}: a publication that could not consume genesis reported success"
        );

        sqlx::query(&format!("drop trigger weald_injected on {table}"))
            .execute(pool)
            .await
            .unwrap();

        // Nothing moved. The key is still live, the invite is still live, and the
        // log is still empty, so the founding can still happen exactly once.
        assert!(
            secret_is_present(pool).await,
            "{label}: the key was destroyed"
        );
        assert_eq!(
            store::fetch(pool, &run.token).await.unwrap().unwrap().state,
            State::Live,
            "{label}: the invite was spent"
        );
        assert!(
            genesis::log(pool, WORKSPACE).await.unwrap().is_empty(),
            "{label}: the log was written"
        );

        // And the real publication still works afterwards, so the refusal was a
        // refusal and not damage.
        access_store::publish(pool, WORKSPACE, &set, &set.encode())
            .await
            .expect("the retry succeeds");
        assert!(!secret_is_present(pool).await);
        assert_eq!(genesis::log(pool, WORKSPACE).await.unwrap().len(), 1);

        scratch.drop_database().await;
    }
}

/// The two reads inside consumption, which a refusing trigger cannot reach.
///
/// Triggers do not fire on `select`, so a read that fails needs a column that is
/// not there. Each of these is renamed rather than dropped, and put back afterwards,
/// so the fault is narrow: exactly one statement stops working and everything
/// around it is untouched.
#[tokio::test]
async fn a_consumption_that_cannot_read_what_it_needs_changes_nothing_either() {
    for column in ["secret_key", "public_key"] {
        let label = format!("consume_read_{column}");
        let (scratch, _blobs, state) = prepared(&label).await;
        let pool = pool_of(&state);
        let Ensured::Minted(run) = genesis::ensure(pool, WORKSPACE, NOW).await.unwrap() else {
            panic!("mints");
        };
        let salt = access_store::salt(pool, WORKSPACE).await.unwrap();
        let trust_root = key(0x21);
        let device_hash = entry_hash(&pk(&trust_root), &salt);
        reserve::reserve(
            pool,
            &run.token,
            &run.code.grouped(),
            &[0x01; 16],
            &device_hash,
            &[0x02; 32],
            NOW,
        )
        .await
        .unwrap();

        sqlx::query(&format!(
            "alter table relay_genesis rename column {column} to weald_parked_column"
        ))
        .execute(pool)
        .await
        .unwrap();

        let set = genesis_set(&salt, &trust_root, &key(0x3f));
        let outcome = access_store::publish(pool, WORKSPACE, &set, &set.encode()).await;
        assert!(
            outcome.is_err(),
            "{label}: a publication that could not read genesis reported success"
        );

        sqlx::query(&format!(
            "alter table relay_genesis rename column weald_parked_column to {column}"
        ))
        .execute(pool)
        .await
        .unwrap();

        assert!(
            secret_is_present(pool).await,
            "{label}: the key was destroyed"
        );
        assert!(
            genesis::log(pool, WORKSPACE).await.unwrap().is_empty(),
            "{label}: the log was written"
        );
        access_store::publish(pool, WORKSPACE, &set, &set.encode())
            .await
            .expect("the retry succeeds");
        assert_eq!(genesis::log(pool, WORKSPACE).await.unwrap().len(), 1);

        scratch.drop_database().await;
    }
}

/// Two processes minting at once, with the interleaving Postgres itself enforces.
///
/// A rolling deploy starts a second relay against the same database before the
/// first has finished (`specs/backend/relay/server.md`), so both read no genesis
/// and both mint one. The loser must not report a failure and must not leave its
/// invite behind: the workspace has exactly one genesis key and exactly one
/// bootstrap invite, and which process wrote them is not a fact anybody needs.
///
/// No trigger and no advisory lock. The winner opens a transaction and inserts the
/// row without committing, which makes the primary key held but not visible; the
/// loser reads no genesis, mints, and blocks on that key inside its own insert,
/// which is what Postgres does to a second writer. Committing the winner releases
/// it into exactly the state a real second process wakes into.
#[tokio::test]
async fn a_second_process_that_loses_the_mint_answers_with_the_winners_key() {
    let (scratch, _blobs, state) = prepared("genesis_race").await;
    let pool = pool_of(&state);

    let other = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&scratch.url)
        .await
        .expect("a second connection, which is what the other process is");
    // The workspace row first, which the genesis row's foreign key needs and which
    // `access::store::salt` writes on any relay's first touch of a workspace.
    sqlx::query(
        "insert into relay_workspace (workspace_id, salt) values ($1, decode(repeat('ee',32),'hex')) \
         on conflict (workspace_id) do nothing",
    )
    .bind(WORKSPACE)
    .execute(&other)
    .await
    .expect("the workspace row");

    let mut winner = other.begin().await.expect("the winner's transaction");
    // The invite the genesis row points at, because a genesis key without its
    // bootstrap invite is a foreign key violation and, more to the point, is not a
    // state any relay can produce.
    sqlx::query(
        "insert into relay_invite (token, workspace_id, workspace, issuer, expires_at, uses, \
                                   remaining, code_hash, update_pub, state, bootstrap, body) \
         values (decode(repeat('dd',16),'hex'), $1, decode(repeat('11',32),'hex'), \
                 decode(repeat('22',32),'hex'), now() + interval '1 day', 1, 1, \
                 decode(repeat('33',32),'hex'), decode(repeat('44',32),'hex'), 'live', true, \
                 decode('00','hex'))",
    )
    .bind(WORKSPACE)
    .execute(&mut *winner)
    .await
    .expect("the winner's bootstrap invite");
    sqlx::query(
        "insert into relay_genesis (workspace_id, public_key, secret_key, fingerprint, token) \
         values ($1, decode(repeat('aa',32),'hex'), decode(repeat('bb',32),'hex'), \
                 decode(repeat('cc',32),'hex'), decode(repeat('dd',16),'hex'))",
    )
    .bind(WORKSPACE)
    .execute(&mut *winner)
    .await
    .expect("the winner takes the key, uncommitted");

    let loser_pool = pool.clone();
    let loser = tokio::spawn(async move { genesis::ensure(&loser_pool, WORKSPACE, NOW).await });
    // Long enough for the loser to read, mint and reach its own insert, where
    // Postgres blocks it on the uncommitted key. Not a synchronisation primitive:
    // if it were short the loser would win instead, and the assertion below would
    // say so rather than pass quietly.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    winner.commit().await.expect("the winner commits");

    match loser.await.expect("the loser finishes").expect("no error") {
        Ensured::Existing {
            fingerprint,
            redeemed,
            ..
        } => {
            assert_eq!(
                fingerprint,
                vec![0xcc; 32],
                "the loser answered with its own key"
            );
            assert!(!redeemed);
        }
        other => panic!("the loser reported {other:?}"),
    }

    // And it left nothing behind. A bootstrap invite with no genesis row of its own
    // is a live single-use invite nobody can account for.
    let invites: i64 = sqlx::query_scalar(
        "select count(*) from relay_invite where bootstrap and workspace_id = $1",
    )
    .bind(WORKSPACE)
    .fetch_one(pool)
    .await
    .unwrap();
    // One bootstrap invite for this workspace, and it is the winner's.
    assert_eq!(
        invites, 1,
        "the loser's invite survived beside the winner's"
    );
    let token: Vec<u8> =
        sqlx::query_scalar("select token from relay_invite where bootstrap and workspace_id = $1")
            .bind(WORKSPACE)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        token,
        vec![0xdd; 16],
        "the surviving invite is the winner's"
    );

    scratch.drop_database().await;
}

/// The two ways the loser's re-read can go wrong, which are not the same answer.
///
/// After an insert that affected nothing, `ensure` asks the table who won. If the
/// answer is "nobody", something removed the row between the insert and the read and
/// there is no honest verdict to give: the relay says so rather than reporting a
/// mint it did not make or an existing key it cannot name. If the read itself
/// cannot run, that is a database that could not answer, and it is reported as one.
#[tokio::test]
async fn a_mint_that_lands_nowhere_says_so_rather_than_inventing_a_verdict() {
    let (scratch, _blobs, state) = prepared("genesis_vanished").await;
    let pool = pool_of(&state);

    // An insert that succeeds and stores nothing. Unreachable through this crate,
    // which is the point: the arm exists for a state nobody can produce on purpose,
    // and an arm nobody can reach is an arm nobody has checked.
    sqlx::query(
        "create or replace function weald_injected_vanish() returns trigger \
         language plpgsql as $$ begin return null; end $$",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "create trigger weald_injected_vanish before insert on relay_genesis \
         for each row execute function weald_injected_vanish()",
    )
    .execute(pool)
    .await
    .unwrap();

    let outcome = genesis::ensure(pool, WORKSPACE, NOW).await;
    match outcome {
        Err(store::StoreError::Database(reason)) => assert!(
            reason.contains("vanished"),
            "the relay reported {reason} rather than saying the row is not there"
        ),
        other => panic!("expected a database refusal, got {other:?}"),
    }

    // And the read failing is a different answer with the same shape: the column the
    // read needs is gone, so the relay could not look rather than looked and found
    // nothing.
    sqlx::query("alter table relay_genesis rename column secret_key to weald_parked")
        .execute(pool)
        .await
        .unwrap();
    assert!(
        matches!(
            genesis::ensure(pool, WORKSPACE, NOW).await,
            Err(store::StoreError::Database(_))
        ),
        "a relay that could not read must say come back"
    );
    sqlx::query("alter table relay_genesis rename column weald_parked to secret_key")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("drop trigger weald_injected_vanish on relay_genesis")
        .execute(pool)
        .await
        .unwrap();

    scratch.drop_database().await;
}

/// The workspace a founding device belongs to, resolved from its reservation.
///
/// The first `ACCESS` a workspace ever receives arrives before any group exists,
/// because groups are made by the trust root and the trust root is admitted by that
/// publication. So there is nothing to resolve the workspace from except the seat
/// the device is holding, and this is the only path that does it.
///
/// Narrow on purpose, and the negatives say how narrow: a device with no
/// reservation is nobody, and a device whose seat has been consumed is no longer
/// founding anything.
#[tokio::test]
async fn a_founding_device_is_resolved_by_its_reservation_and_only_while_it_holds_one() {
    let (scratch, _blobs, state) = prepared("genesis_founding").await;
    let pool = pool_of(&state);
    // The wall clock throughout, because a reservation's liveness is read against
    // the database's `now()`. This suite's fixed clock is in 2023, so an invite
    // minted with it is expired before it is reserved and the seat is refused.
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let Ensured::Minted(run) = genesis::ensure(pool, WORKSPACE, wall).await.unwrap() else {
        panic!("mints");
    };
    let salt = access_store::salt(pool, WORKSPACE).await.unwrap();
    let trust_root = key(0x21);
    let device_hash = entry_hash(&pk(&trust_root), &salt);

    // Before the reservation, nobody.
    assert_eq!(
        genesis::founding_workspace(pool, &pk(&trust_root))
            .await
            .unwrap(),
        None
    );

    assert!(matches!(
        reserve::reserve(
            pool,
            &run.token,
            &run.code.grouped(),
            &[0x01; 16],
            &device_hash,
            &[0x02; 32],
            wall,
        )
        .await
        .unwrap(),
        Verdict::Reserved { .. }
    ));

    // Holding the seat, it is founding this workspace.
    assert_eq!(
        genesis::founding_workspace(pool, &pk(&trust_root))
            .await
            .unwrap()
            .as_deref(),
        Some(WORKSPACE)
    );
    // And nobody else is, however many devices ask.
    assert_eq!(
        genesis::founding_workspace(pool, &pk(&key(0x99)))
            .await
            .unwrap(),
        None
    );

    // Consumed, and it is over: the workspace has a trust root and this path closes
    // behind it.
    let set = genesis_set(&salt, &trust_root, &key(0x3f));
    access_store::publish(pool, WORKSPACE, &set, &set.encode())
        .await
        .unwrap();
    assert_eq!(
        genesis::founding_workspace(pool, &pk(&trust_root))
            .await
            .unwrap(),
        None,
        "a spent seat still names a founder"
    );

    scratch.drop_database().await;
}
