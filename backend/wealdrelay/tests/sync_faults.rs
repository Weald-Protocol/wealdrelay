// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! What a subscriber and a reconciling peer are told when the log cannot be read.
//!
//! `tests/reconcile.rs` and `tests/ws.rs` prove the sync paths right when Postgres
//! works. These are the arms they cannot reach: a relay whose envelope log is
//! there for the access check and gone for the read.
//!
//! The distinction being proven is `retry` rather than `reject`. A client whose
//! backfill failed must come back, because its own state is fine and the relay's
//! is not. A client told `reject` would treat its subscription as permanently
//! wrong and stop asking, which turns a minute of database trouble into a
//! workspace that silently stops converging.
//!
//! Nothing is mocked: the fault is the real envelope table renamed out from under
//! a running relay, which is the same shape as a failed failover or a migration
//! half applied.

mod support;

use wealdrelay::frame::{ErrorCode, Frame};
use wealdrelay::health::Clock;
use wealdrelay::negentropy::initiate;

use support::{config_for, make_group, Client, Running, Scratch};

const CLOCK: u64 = 1_700_000_000_000;

#[tokio::test(flavor = "multi_thread")]
async fn a_backfill_that_cannot_be_read_is_a_retry_and_not_a_rejection() {
    let scratch = Scratch::new("syncfault_sub").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0xC1).await;
    let pool = relay.state.database.as_ref().expect("a database").pool();

    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], CLOCK).await;

    // The access check reads `relay_group`, which is still there; the backfill
    // reads `relay_envelope`, which is not. So the session is authorized and the
    // read fails, which is the exact ordering this arm exists for.
    sqlx::query("alter table relay_envelope rename to parked_away")
        .execute(pool)
        .await
        .expect("park the envelope table");

    client
        .send_frame(&Frame::Sub {
            group: group.clone(),
            from_seq: 0,
        })
        .await;
    // WEALD-299. No acknowledgement at all, because the head this one would name
    // comes from the same unreadable table. A `SUB_ACK` whose `head_seq` fell back
    // to zero would resolve to the client's own cursor and tell it there is
    // nothing left to fetch, which is the one answer it acts on and never revisits.
    // Refusing costs a retry; acknowledging costs the envelopes.
    match client.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::Backpressure);
            assert_eq!(error.code.qualified(), "retry/backpressure");
        }
        other => panic!("expected backpressure, got {other:?}"),
    }

    sqlx::query("alter table parked_away rename to relay_envelope")
        .execute(pool)
        .await
        .expect("restore the envelope table");
    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reconciliation_that_cannot_read_the_log_is_a_retry_and_not_a_rejection() {
    let scratch = Scratch::new("syncfault_recon").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0xC2).await;
    let pool = relay.state.database.as_ref().expect("a database").pool();

    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], CLOCK).await;

    sqlx::query("alter table relay_envelope rename to parked_away")
        .execute(pool)
        .await
        .expect("park the envelope table");

    // A well formed opening round. The payload decodes, so the refusal below is
    // about the relay's read and not about the client's bytes, which is the
    // difference the two error classes carry.
    client
        .send_frame(&Frame::Recon {
            group: group.clone(),
            payload: initiate(&[]).encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::Backpressure),
        other => panic!("expected backpressure, got {other:?}"),
    }

    // Restored, and the same client reconciles: the session survived a `retry`,
    // which is what makes the class meaningful.
    sqlx::query("alter table parked_away rename to relay_envelope")
        .execute(pool)
        .await
        .expect("restore the envelope table");
    client
        .send_frame(&Frame::Recon {
            group: group.clone(),
            payload: initiate(&[]).encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Recon {
            group: answered, ..
        } => assert_eq!(answered, group),
        other => panic!("expected a Recon answer, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_head_that_cannot_be_read_refuses_the_subscription_with_no_suback() {
    // The negative proof WEALD-299 asks for. The two tests above park the table
    // after the handshake, by which point the head statement is already prepared
    // and Postgres keeps serving the cached plan by OID, so they exercise the
    // failed backfill and never the failed head read. Here the pool itself is
    // closed, so the very first statement `sync::subscribe` runs, the head read,
    // fails, and the claim under test is that no `SUB_ACK` naming a head this
    // relay did not read is ever emitted: the client is told `retry/backpressure`
    // and nothing else. An ack at the client's own cursor would tell it it is
    // caught up, permanently, over a transient fault.
    use wealdrelay::db::Database;
    use wealdrelay::health::RelayState;
    use wealdrelay::ws::{outbound_channel, Outbound};

    let scratch = Scratch::new("syncfault_head").await;
    let blobs = tempfile::tempdir().unwrap();
    let config = config_for(&scratch, blobs.path());
    let database = Database::connect(&scratch.url).await.expect("a database");
    database.pool().close().await;
    let state = std::sync::Arc::new(RelayState::new(config, Some(database), None));

    let (sender, mut receiver) = outbound_channel();
    let group = vec![0xC3; 32];
    assert!(
        wealdrelay::sync::subscribe(
            &sender,
            &state,
            1,
            group.clone(),
            42,
            wealdrelay::frame::PROTOCOL_VERSION,
        )
        .await,
        "a refused subscription keeps the connection"
    );
    match receiver.try_recv() {
        Ok(Outbound::Frame(Frame::Error(error))) => {
            assert_eq!(error.code, ErrorCode::Backpressure);
        }
        other => panic!("expected backpressure and no SubAck, got {other:?}"),
    }
    assert!(
        receiver.try_recv().is_err(),
        "nothing follows the refusal, and above all no SubAck"
    );
    assert_eq!(
        state.hub.subscribers(&group).await,
        0,
        "a refused subscription is not registered for fanout"
    );

    scratch.drop_database().await;
}
