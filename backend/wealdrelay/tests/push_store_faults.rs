// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! What the push path answers when the database cannot answer it.
//!
//! The stakes are smaller than the handshake store's and the rule is the same: fail
//! closed. A relay that answered `Registered` to a write that did not land would
//! leave a client believing it holds a wake capability it does not, and the client's
//! only symptom would be notifications that never arrive, weeks later, with nothing
//! anywhere reporting a fault. So every failure is `retry/push_backpressure`, which
//! is a client instruction to come back rather than a state it can act on.
//!
//! Nothing here is mocked. The faults are real states of a real Postgres, one
//! statement at a time, exactly as the other fault suites produce them.

mod support;

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use sqlx::PgPool;
use wealdrelay::frame::{ErrorCode, Frame, WakeBody};
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::push::store;
use wealdrelay::push::{Category, ALL_CATEGORIES};
use wealdrelay::session::Session;

use support::{
    config_for_push, default_device, entry_hash_of, make_group, wake_expiry, wake_handle, Client,
    Running, Scratch,
};

const CLOCK: u64 = 1_700_000_000_000;
const WORKSPACE: &str = "ws-step4";
const RINGER: &str = "https://ringer.invalid/v1/wake";

async fn prepared(label: &str, group_byte: u8) -> (Scratch, tempfile::TempDir, Running, Vec<u8>) {
    let scratch = Scratch::new(label).await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), RINGER, 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, group_byte).await;
    (scratch, blobs, relay, group)
}

fn pool_of(state: &Arc<RelayState>) -> &PgPool {
    state.database.as_ref().expect("a database").pool()
}

async fn inject(pool: &PgPool, statement: &str) {
    if let Err(error) = sqlx::query(statement).execute(pool).await {
        panic!("the injected database state must land: {statement}: {error}");
    }
}

#[track_caller]
fn is_told_to_come_back<T: std::fmt::Debug>(outcome: Result<T, store::StoreError>, what: &str) {
    match outcome {
        Err(store::StoreError::Database(_)) => {}
        other => panic!(
            "{what}: a relay that could not reach its table must answer come back, and answered \
             {other:?}"
        ),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_store_call_answers_come_back_when_the_table_is_not_there() {
    let (scratch, _blobs, relay, group) = prepared("pushfault_no_table", 0x70).await;
    let pool = pool_of(&relay.state);
    let entry = entry_hash_of(pool, WORKSPACE, &default_device()).await;

    inject(pool, "alter table relay_push_handle rename to weald_parked").await;
    is_told_to_come_back(
        store::register(
            pool,
            WORKSPACE,
            &entry,
            &wake_handle(1),
            ALL_CATEGORIES,
            wake_expiry(CLOCK),
        )
        .await,
        "register with no table",
    );
    is_told_to_come_back(store::clear(pool, WORKSPACE, &entry).await, "clear");
    is_told_to_come_back(store::find(pool, WORKSPACE, &entry).await, "find");
    is_told_to_come_back(
        store::wakeable_for_group(pool, &group, Category::Message, CLOCK).await,
        "the wake lookup",
    );
    is_told_to_come_back(
        store::delete_by_handle(pool, &wake_handle(1)).await,
        "delete by handle",
    );
    is_told_to_come_back(store::sweep_expired(pool, CLOCK).await, "the sweep");
    inject(pool, "alter table weald_parked rename to relay_push_handle").await;

    // And the access set's join, which the wake lookup also needs.
    inject(
        pool,
        "alter table relay_access_entry rename to weald_parked",
    )
    .await;
    is_told_to_come_back(
        store::wakeable_for_group(pool, &group, Category::Message, CLOCK).await,
        "the wake lookup with no access entries",
    );
    inject(
        pool,
        "alter table weald_parked rename to relay_access_entry",
    )
    .await;

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_registration_that_cannot_be_written_is_never_reported_as_stored() {
    // The wire half of the same rule. `retry/push_backpressure`, and the socket stays
    // up: the client's correct response is to send the same registration again later,
    // which is free.
    let (scratch, _blobs, relay, group) = prepared("pushfault_register_wire", 0x71).await;
    let pool = pool_of(&relay.state);

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    inject(pool, "alter table relay_push_handle rename to weald_parked").await;
    ada.send_frame(&Frame::Wake(WakeBody::Register {
        handle: wake_handle(2),
        categories: ALL_CATEGORIES,
        expires_at: wake_expiry(CLOCK),
    }))
    .await;
    match ada.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::PushBackpressure);
            assert_eq!(error.code.qualified(), "retry/push_backpressure");
            assert!(
                error.code.class().is_retryable(),
                "the client is told to come back, which is the whole point of the class"
            );
        }
        other => panic!("expected backpressure, got {other:?}"),
    }
    // A `Clear` is the same answer, for the same reason: a client told `Cleared`
    // would stop expecting wakes it may still receive.
    ada.send_frame(&Frame::Wake(WakeBody::Clear)).await;
    match ada.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::PushBackpressure),
        other => panic!("expected backpressure, got {other:?}"),
    }
    inject(pool, "alter table weald_parked rename to relay_push_handle").await;

    // And when the table comes back, so does the registration path, on the same
    // socket: the failure was transient and was reported as transient.
    ada.send_frame(&Frame::Wake(WakeBody::Register {
        handle: wake_handle(3),
        categories: ALL_CATEGORIES,
        expires_at: wake_expiry(CLOCK),
    }))
    .await;
    assert!(matches!(
        ada.recv_frame().await,
        Frame::Wake(WakeBody::Registered { .. })
    ));

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_query_is_answered_even_with_no_database_at_all() {
    // The one form that does not fail closed, and deliberately. `Query` is how a
    // client learns whether to register at all, so a relay whose Postgres is
    // unreachable must still be able to say "push is on here, and this is the ringer":
    // the alternative is a client that reads an outage as push being unavailable and
    // holds no registration afterwards.
    let (scratch, _blobs, relay, _group) = prepared("pushfault_query", 0x72).await;
    let mut state = wealdrelay::health::RelayState::new(relay.state.config.clone(), None, None);
    state.clock = Clock::Fixed(CLOCK);
    let state = Arc::new(state);
    let session = Session::new(&state.config);

    let answer = wealdrelay::ws::wake_answer(&state, &session, WakeBody::Query, CLOCK).await;
    assert_eq!(
        answer,
        Frame::Wake(WakeBody::Capability {
            enabled: true,
            // The wake path is trimmed before the registration path goes on
            // (`push::default_register_url`), so the answer is the ringer's
            // origin plus `/v1/handles`. Appending to `RINGER` whole asserted
            // `/v1/wake/v1/handles`, a path no ringer serves.
            register_url: format!(
                "{}{}",
                RINGER.trim_end_matches(wealdrelay::push::RINGER_WAKE_PATH),
                wealdrelay::push::RINGER_REGISTER_PATH
            ),
        })
    );

    // Everything else on a relay with no database is `retry/push_backpressure`.
    for body in [
        WakeBody::Register {
            handle: wake_handle(4),
            categories: ALL_CATEGORIES,
            expires_at: wake_expiry(CLOCK),
        },
        WakeBody::Clear,
    ] {
        match wealdrelay::ws::wake_answer(&state, &session, body, CLOCK).await {
            Frame::Error(error) => assert_eq!(error.code, ErrorCode::PushBackpressure),
            other => panic!("expected backpressure, got {other:?}"),
        }
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_that_cannot_resolve_a_salt_registers_nobody() {
    // The salt is how a principal is named, so a relay that cannot read one cannot
    // know whose registration this would be. Backpressure rather than a guess.
    let (scratch, _blobs, relay, group) = prepared("pushfault_salt", 0x73).await;
    let pool = pool_of(&relay.state);

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    inject(pool, "alter table relay_workspace rename to weald_parked").await;
    ada.send_frame(&Frame::Wake(WakeBody::Register {
        handle: wake_handle(5),
        categories: ALL_CATEGORIES,
        expires_at: wake_expiry(CLOCK),
    }))
    .await;
    match ada.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::PushBackpressure),
        other => panic!("expected backpressure, got {other:?}"),
    }
    inject(pool, "alter table weald_parked rename to relay_workspace").await;

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wake_dispatch_with_no_database_queues_nothing_rather_than_guessing() {
    // A relay that cannot answer who is admitted must not wake anybody: a wake sent
    // to a guess is a wake sent to the wrong device. Silence is the honest answer, and
    // `/readyz` is already reporting why.
    let (scratch, _blobs, relay, group) = prepared("pushfault_dispatch", 0x74).await;
    let mut state = wealdrelay::health::RelayState::new(relay.state.config.clone(), None, None);
    state.clock = Clock::Fixed(CLOCK);
    let state = Arc::new(state);

    wealdrelay::push::dispatch::wake_group(&state, &group, Category::Message).await;
    assert_eq!(state.push.queued().await, 0);
    assert_eq!(state.push.dropped(), 0);

    // And with a database whose table has gone, the same: the read failed, so nothing
    // is enqueued and nothing is invented.
    let pool = pool_of(&relay.state);
    inject(pool, "alter table relay_push_handle rename to weald_parked").await;
    wealdrelay::push::dispatch::wake_group(&relay.state, &group, Category::Message).await;
    assert_eq!(relay.state.push.queued().await, 0);
    inject(pool, "alter table weald_parked rename to relay_push_handle").await;

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_relay_to_client_forms_are_refused_at_the_handler_as_well_as_at_the_session() {
    // `session.rs` closes the connection on one of these, so nothing on the wire
    // reaches the handler with a reply form. The arm exists because the type is one
    // enum in both directions, and it gives the same answer the session table gives so
    // that the two cannot disagree; this drives it directly to prove that.
    let (scratch, _blobs, relay, _group) = prepared("pushfault_reply_forms", 0x75).await;
    // A session that is past every earlier refusal, so the arm under test is the one
    // that answers. Built by binding what `AUTH` binds rather than by reaching into
    // the type, which is the same thing the socket layer does after it admits a
    // device.
    let mut session = Session::new(&relay.state.config);
    session.bind_workspace(WORKSPACE.to_string());
    let device: SigningKey = default_device();
    session.bind_device(device.verifying_key().to_bytes().to_vec());
    for body in [
        WakeBody::Registered { expires_at: 0 },
        WakeBody::Cleared,
        WakeBody::Capability {
            enabled: true,
            register_url: String::new(),
        },
    ] {
        match wealdrelay::ws::wake_answer(&relay.state, &session, body, CLOCK).await {
            Frame::Error(error) => assert_eq!(error.code, ErrorCode::MalformedHeader),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_with_no_workspace_claim_registers_nothing() {
    // Reachable with `WEALD_RELAY_ACCESS_SET=off`, the one mode that admits a session
    // with no workspace claim. A registration belongs to a workspace, so the answer is
    // the one a stranger gets rather than a row against nobody.
    let scratch = Scratch::new("pushfault_no_workspace").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        support::config_with(
            &scratch,
            blobs.path(),
            [
                (wealdrelay::config::keys::PUSH, "on".to_string()),
                (wealdrelay::config::keys::PUSH_URL, RINGER.to_string()),
                (wealdrelay::config::keys::ACCESS_SET, "off".to_string()),
            ],
        ),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x76).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&Frame::Wake(WakeBody::Register {
        handle: wake_handle(6),
        categories: ALL_CATEGORIES,
        expires_at: wake_expiry(CLOCK),
    }))
    .await;
    match ada.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("expected the refusal a stranger gets, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}
