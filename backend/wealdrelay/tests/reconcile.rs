// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Reconciliation and the live path, over real sockets against real Postgres.
//!
//! The integration and negative proofs for reconciliation. The client half of the
//! exchange is driven by `wealdrelay::negentropy::advance`, which is the Rust peer
//! of the client's own implementation of the same protocol: the two are held to the
//! shared vectors in `specs/backend/contracts/wire/vectors/recon.json` rather than
//! to each other, so this suite proving the round trip does not also excuse the
//! client half.
//!
//! What is proven here:
//!
//! - Two clients with disjoint sets converge over `RECON`, and the number of round
//!   trips is recorded rather than assumed.
//! - A client that has been away catches up, both by cursor backfill and by
//!   reconciliation.
//! - A relay serving a forked history is detected by the client.
//! - A relay killed mid-reconcile leaves the next round able to complete.
//! - A malformed reconciliation payload is refused with a code, and the session
//!   survives it.

mod support;

use std::collections::BTreeSet;

use sqlx::Executor as _;
use wealdrelay::envelope::{content_hash, Encryption, Envelope};
use wealdrelay::frame::{ErrorCode, Frame};
use wealdrelay::health::Clock;
use wealdrelay::negentropy::{advance, id_from_slice, initiate, Id, Item, Message};

use support::{config_for, envelope_for, make_group, Client, Running, Scratch};

const CLOCK: u64 = 1_700_000_000_000;

/// What one side of the exchange holds, as the client's own store.
#[derive(Debug, Default)]
struct Local {
    items: Vec<Item>,
    envelopes: Vec<Envelope>,
}

impl Local {
    /// Apply a pushed envelope, verifying it against its own content address first.
    ///
    /// The verification is the client's half of the trust boundary and it is not
    /// optional: the relay is the one party that can serve a history nobody signed
    /// for, and a client that stored what it was handed without recomputing the
    /// address would have no way to notice. See
    /// ``a_relay_serving_a_forked_history_is_detected``.
    fn apply(&mut self, envelope: Envelope) -> Result<(), &'static str> {
        if envelope.computed_hash() != envelope.hash {
            return Err("the relay served an envelope whose content address is wrong");
        }
        if self.items.iter().any(|item| item.id == id_of(&envelope)) {
            return Ok(());
        }
        self.items.push(Item {
            seq: envelope.seq,
            id: id_of(&envelope),
        });
        self.items.sort();
        self.envelopes.push(envelope);
        Ok(())
    }

    fn ids(&self) -> BTreeSet<Id> {
        self.items.iter().map(|item| item.id).collect()
    }
}

fn id_of(envelope: &Envelope) -> Id {
    id_from_slice(&envelope.hash)
}

/// Drive one reconciliation exchange to completion, returning the round count.
///
/// The client applies pushes as they arrive and `SEND`s what the relay lacks,
/// applying each acknowledgement's assigned sequence number before answering, which
/// is the order `src/negentropy/reconcile.rs` documents.
async fn reconcile_to_convergence(
    client: &mut Client,
    local: &mut Local,
    group: &[u8],
    pending: &[Envelope],
    bound: usize,
) -> usize {
    let mut message = initiate(&local.items);
    let mut rounds = 0usize;

    loop {
        rounds += 1;
        assert!(
            rounds <= bound,
            "the exchange did not converge in {bound} rounds"
        );
        client
            .send_frame(&Frame::Recon {
                group: group.to_vec(),
                payload: message.encode(),
            })
            .await;

        // Pushes first, then the answering `RECON`. The relay owes that order and
        // this loop depends on it: the next round is computed against what the
        // client holds.
        let reply = loop {
            match client.recv_frame().await {
                Frame::Push { envelope } => {
                    let decoded = Envelope::decode(&envelope).expect("a pushed envelope decodes");
                    local
                        .apply(decoded)
                        .expect("the relay served a sound envelope");
                }
                Frame::Recon { payload, .. } => {
                    break Message::decode(&payload).expect("the relay's answer decodes")
                }
                other => panic!("expected a push or an answer, got {other:?}"),
            }
        };

        let mut step = advance(&local.items, &reply);
        if !step.send.is_empty() {
            for id in &step.send {
                let envelope = pending
                    .iter()
                    .find(|envelope| id_of(envelope) == *id)
                    .expect("the client sends what it holds")
                    .clone();
                client
                    .send_frame(&Frame::Send {
                        envelope: envelope.encode(),
                    })
                    .await;
                let seq = match client.recv_frame().await {
                    Frame::SendAck { seq, .. } => seq,
                    other => panic!("expected a SendAck, got {other:?}"),
                };
                // The assigned number is applied before the answer is computed.
                local.items.retain(|item| item.id != *id);
                let mut numbered = envelope;
                numbered.seq = seq;
                local.envelopes.retain(|held| id_of(held) != *id);
                local.apply(numbered).expect("our own envelope is sound");
            }
            step = advance(&local.items, &reply);
        }

        match step.reply {
            None => return rounds,
            Some(next) => message = next,
        }
    }
}

/// Publish `count` envelopes through one client, returning them.
async fn publish(client: &mut Client, group: &[u8], bodies: &[&[u8]]) -> Vec<Envelope> {
    let mut out = Vec::new();
    for body in bodies {
        let envelope = envelope_for(group, body);
        client
            .send_frame(&Frame::Send {
                envelope: envelope.encode(),
            })
            .await;
        let seq = match client.recv_frame().await {
            Frame::SendAck { seq, .. } => seq,
            other => panic!("expected a SendAck, got {other:?}"),
        };
        let mut stored = envelope;
        stored.seq = seq;
        out.push(stored);
    }
    out
}

// MARK: The integration proofs

#[tokio::test(flavor = "multi_thread")]
async fn two_clients_with_disjoint_sets_converge_over_recon() {
    // The relay holds what one client wrote; the other holds envelopes the relay has
    // never seen. This is the dual-transport case: a member on git wrote things the
    // relay does not have, and a member on the relay wrote things that member does
    // not have.
    let scratch = Scratch::new("disjoint").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x51).await;

    let mut writer = Client::connect(relay.address).await;
    writer.handshake(vec![group.clone()], CLOCK).await;
    let on_relay = publish(
        &mut writer,
        &group,
        &[b"relay-one", b"relay-two", b"relay-three"],
    )
    .await;

    // The second client holds three envelopes of its own, which reached it by git.
    let mut reader = Client::connect(relay.address).await;
    reader.handshake(vec![group.clone()], CLOCK).await;
    let mut local = Local::default();
    let mut pending = Vec::new();
    for body in [b"git-one".as_slice(), b"git-two", b"git-three"] {
        let envelope = envelope_for(&group, body);
        pending.push(envelope.clone());
        // A git-delivered envelope has no relay sequence number. It goes into the
        // client's own store at zero and is placed in the reconciliation space only
        // once the relay numbers it.
        local.apply(envelope).expect("our own envelope is sound");
    }

    let rounds = reconcile_to_convergence(&mut reader, &mut local, &group, &pending, 12).await;

    // Everything, both directions.
    let mut expected: BTreeSet<Id> = on_relay.iter().map(id_of).collect();
    expected.extend(pending.iter().map(id_of));
    assert_eq!(local.ids(), expected);

    // And the relay holds all six.
    let stored: i64 = sqlx::query_scalar("select count(*) from relay_envelope where group_id = $1")
        .bind(&group)
        .fetch_one(relay.state.database.as_ref().unwrap().pool())
        .await
        .unwrap();
    assert_eq!(stored, 6);

    // Recorded rather than assumed: the round count against corpus size is the
    // deliverable this suite owes, so it is written out rather than inferred.
    support::record_recon_rounds("disjoint 3 by 3", 6, rounds);

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_offline_for_a_day_catches_up() {
    // Two hundred envelopes land while one client is away. It comes back, subscribes
    // from the cursor it remembers, and reconciles what the cursor cannot express.
    let scratch = Scratch::new("offline").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x52).await;

    let mut writer = Client::connect(relay.address).await;
    writer.handshake(vec![group.clone()], CLOCK).await;

    // The returning client saw the first ten before it went away.
    let mut local = Local::default();
    let bodies: Vec<Vec<u8>> = (0..200u16)
        .map(|index| index.to_be_bytes().to_vec())
        .collect();
    let refs: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
    let all = publish(&mut writer, &group, &refs).await;
    for envelope in all.iter().take(10) {
        local.apply(envelope.clone()).expect("sound");
    }

    let mut returning = Client::connect(relay.address).await;
    returning.handshake(vec![group.clone()], CLOCK).await;
    let pending: Vec<Envelope> = Vec::new();
    let rounds = reconcile_to_convergence(&mut returning, &mut local, &group, &pending, 12).await;

    assert_eq!(local.ids().len(), 200);
    assert_eq!(local.ids(), all.iter().map(id_of).collect());
    support::record_recon_rounds("one day behind, 190 of 200 missing", 200, rounds);

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cursor_subscription_backfills_and_then_stays_live() {
    // The other half of catching up: `SUB` from a remembered cursor, then the live
    // path. The acknowledgement carries the head, the backfill follows it, and an
    // envelope accepted afterwards arrives without another round trip.
    let scratch = Scratch::new("backfill").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x53).await;

    let mut writer = Client::connect(relay.address).await;
    writer.handshake(vec![group.clone()], CLOCK).await;
    publish(&mut writer, &group, &[b"one", b"two", b"three", b"four"]).await;

    let mut reader = Client::connect(relay.address).await;
    reader.handshake(vec![group.clone()], CLOCK).await;
    reader
        .send_frame(&Frame::Sub {
            group: group.clone(),
            from_seq: 3,
        })
        .await;
    match reader.recv_frame().await {
        Frame::SubAck { head_seq, .. } => assert_eq!(head_seq, 4),
        other => panic!("expected a SubAck, got {other:?}"),
    }
    // From the cursor, not from the start: two of the four.
    for expected in [3u64, 4] {
        match reader.recv_frame().await {
            Frame::Push { envelope } => {
                assert_eq!(Envelope::decode(&envelope).unwrap().seq, expected);
            }
            other => panic!("expected a backfill push, got {other:?}"),
        }
    }

    // Live from here.
    publish(&mut writer, &group, &[b"five"]).await;
    match reader.recv_frame().await {
        Frame::Push { envelope } => {
            let decoded = Envelope::decode(&envelope).unwrap();
            assert_eq!(decoded.seq, 5);
            assert_eq!(decoded.ct, b"five".to_vec());
        }
        other => panic!("expected a live push, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_missing_more_than_the_send_queue_converges_without_disconnect() {
    // BR-005 regression.  The old path made 257 PUSH frames plus the answering
    // RECON frame in one synchronous queue run.  The 256-slot channel then
    // rejected the response and the socket closed.  Use 257 exactly: one more
    // than the transport bound is the minimized counterexample, and the fixed
    // body values make this reproduction deterministic.
    let scratch = Scratch::new("recon-over-queue").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x58).await;

    let mut writer = Client::connect(relay.address).await;
    writer.handshake(vec![group.clone()], CLOCK).await;
    let bodies: Vec<Vec<u8>> = (0u16..257)
        .map(|index| index.to_be_bytes().to_vec())
        .collect();
    let refs: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
    let all = publish(&mut writer, &group, &refs).await;

    let mut reader = Client::connect(relay.address).await;
    reader.handshake(vec![group.clone()], CLOCK).await;
    let mut local = Local::default();
    let rounds = reconcile_to_convergence(&mut reader, &mut local, &group, &[], 12).await;

    assert_eq!(local.ids(), all.iter().map(id_of).collect());
    assert!(
        rounds >= 2,
        "the fixture must cross the queue-bound continuation"
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_subscription_larger_than_the_send_queue_can_finish_by_reconciliation() {
    // `SUB_ACK` consumes one queue slot, so this exercises the companion path:
    // bounded cursor backfill followed by the ordinary reconciliation protocol.
    let scratch = Scratch::new("sub-over-queue").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x59).await;

    let mut writer = Client::connect(relay.address).await;
    writer.handshake(vec![group.clone()], CLOCK).await;
    let bodies: Vec<Vec<u8>> = (0u16..257)
        .map(|index| index.to_be_bytes().to_vec())
        .collect();
    let refs: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
    let all = publish(&mut writer, &group, &refs).await;

    let mut reader = Client::connect(relay.address).await;
    reader.handshake(vec![group.clone()], CLOCK).await;
    reader
        .send_frame(&Frame::Sub {
            group: group.clone(),
            from_seq: 0,
        })
        .await;
    let head = match reader.recv_frame().await {
        Frame::SubAck { head_seq, .. } => head_seq,
        other => panic!("expected a subscription acknowledgement, got {other:?}"),
    };
    assert_eq!(head, 257);
    let mut local = Local::default();
    for _ in 0..wealdrelay::session::SEND_QUEUE_BOUND - 1 {
        let Frame::Push { envelope } = reader.recv_frame().await else {
            panic!("expected the bounded cursor backfill");
        };
        local.apply(Envelope::decode(&envelope).unwrap()).unwrap();
    }

    let rounds = reconcile_to_convergence(&mut reader, &mut local, &group, &[], 12).await;
    assert_eq!(local.ids(), all.iter().map(id_of).collect());
    assert!(rounds >= 1);

    relay.shutdown().await;
    scratch.drop_database().await;
}

// MARK: The negative proofs

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_serving_a_forked_history_is_detected() {
    // The relay is the one party that can serve a history nobody signed for. Here it
    // does: a row is written straight into the log whose `hash` does not address its
    // own `ct`, which is what a forked or tampered history looks like from a client's
    // side. The client recomputes the address on receipt and refuses it.
    //
    // Written by SQL rather than through `SEND`, deliberately: the accept path
    // refuses this envelope, so the only way to make the relay serve one is to
    // arrange it behind the accept path, which is exactly the threat model. A
    // hostile or compromised operator has that access and a client cannot assume
    // otherwise.
    let scratch = Scratch::new("forked").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x54).await;
    let pool = relay.state.database.as_ref().unwrap().pool();

    // First prove the front door is shut: the accept path refuses it.
    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], CLOCK).await;
    let honest = envelope_for(&group, b"honest");
    let mut forged = honest.clone();
    forged.ct = b"tampered".to_vec();
    client
        .send_frame(&Frame::Send {
            envelope: forged.encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::HashMismatch),
        other => panic!("expected reject/hash_mismatch, got {other:?}"),
    }

    // Now the back door: the operator writes it directly.
    sqlx::query(
        "insert into relay_envelope (group_id, hash, v, enc, epoch, seq, ts, ct) \
         values ($1, $2, 1, 0, 0, 1, $3, $4)",
    )
    .bind(&group)
    .bind(&honest.hash)
    .bind(CLOCK as i64)
    .bind(b"tampered".to_vec())
    .execute(pool)
    .await
    .expect("the operator can write what they like");

    // The client reconciles and is served the forgery.
    let mut local = Local::default();
    client
        .send_frame(&Frame::Recon {
            group: group.clone(),
            payload: initiate(&local.items).encode(),
        })
        .await;
    let mut detected = false;
    loop {
        match client.recv_frame().await {
            Frame::Push { envelope } => {
                let decoded = Envelope::decode(&envelope).expect("it decodes; that is the point");
                // Decoding succeeds. The check that fails is the content address,
                // which is the check the relay cannot forge without the ciphertext
                // it does not have.
                assert!(local.apply(decoded).is_err());
                detected = true;
            }
            Frame::Recon { .. } => break,
            other => panic!("unexpected frame {other:?}"),
        }
    }
    assert!(
        detected,
        "the relay served the forgery and the client saw it"
    );
    assert!(local.ids().is_empty(), "nothing forged was stored");

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_killed_mid_reconcile_lets_the_next_round_complete() {
    // The relay goes away between two rounds of one exchange. Nothing is stranded:
    // the client reconnects and reconciliation resumes from what each side holds,
    // because a round carries no server-side session state. That is the property
    // being proven, and it is why reconciliation is stateless by design.
    let scratch = Scratch::new("killed").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x55).await;

    let mut writer = Client::connect(relay.address).await;
    writer.handshake(vec![group.clone()], CLOCK).await;
    let bodies: Vec<Vec<u8>> = (0..200u16)
        .map(|index| index.to_be_bytes().to_vec())
        .collect();
    let refs: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
    let all = publish(&mut writer, &group, &refs).await;

    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], CLOCK).await;
    let mut local = Local::default();
    // The client already holds half. That matters: an exchange whose first round can
    // be answered in one go would prove nothing about being interrupted, because
    // there would be no second round to complete. With a large overlapping set the
    // opening message is fingerprints and the exchange genuinely takes several
    // rounds.
    for envelope in all.iter().take(100) {
        local.apply(envelope.clone()).expect("sound");
    }

    // One round, then the relay is killed.
    client
        .send_frame(&Frame::Recon {
            group: group.clone(),
            payload: initiate(&local.items).encode(),
        })
        .await;
    loop {
        match client.recv_frame().await {
            Frame::Push { envelope } => {
                local
                    .apply(Envelope::decode(&envelope).unwrap())
                    .expect("sound");
            }
            Frame::Recon { .. } => break,
            other => panic!("unexpected frame {other:?}"),
        }
    }
    assert!(
        local.ids().len() < all.len(),
        "the first round finished the corpus, so there is no interruption to prove"
    );

    relay.shutdown().await;

    // A new process on the same database, which is what a restart is.
    let restarted = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let mut resumed = Client::connect(restarted.address).await;
    resumed.handshake(vec![group.clone()], CLOCK).await;
    let pending: Vec<Envelope> = Vec::new();
    reconcile_to_convergence(&mut resumed, &mut local, &group, &pending, 12).await;
    assert_eq!(local.ids(), all.iter().map(id_of).collect());

    restarted.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_reconciliation_payload_is_refused_and_the_session_survives() {
    let scratch = Scratch::new("malformed").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x56).await;
    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], CLOCK).await;

    // Not CBOR at all.
    client
        .send_frame(&Frame::Recon {
            group: group.clone(),
            payload: vec![0xff, 0xff],
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::NoncanonicalCbor),
        other => panic!("expected reject/noncanonical_cbor, got {other:?}"),
    }

    // Canonical CBOR, but a cover with a hole in it, which is the failure that would
    // otherwise silently exclude envelopes from reconciliation.
    let holed = wealdrelay::cbor::array(&[
        wealdrelay::cbor::uint(1),
        wealdrelay::cbor::array(&[wealdrelay::cbor::array(&[
            wealdrelay::cbor::uint(10),
            wealdrelay::cbor::uint(0),
            wealdrelay::cbor::NULL.to_vec(),
        ])]),
    ]);
    client
        .send_frame(&Frame::Recon {
            group: group.clone(),
            payload: holed,
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::MalformedHeader),
        other => panic!("expected reject/malformed_header, got {other:?}"),
    }

    // The session survives both, so a client with a bad reconciliation
    // implementation can still write and still subscribe.
    let envelope = envelope_for(&group, b"still working");
    client
        .send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::SendAck { seq, .. } => assert_eq!(seq, 1),
        other => panic!("expected a SendAck, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_group_is_refused_before_reconciliation() {
    // A session is authorized for one relay-resolved workspace, never for an
    // arbitrary group identifier.  `authorize_group` must reject an unknown target
    // before reconciliation reads its history; treating it as an empty group would
    // weaken the workspace boundary established by CONNECT/AUTH.
    let scratch = Scratch::new("unknowngroup").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let known = make_group(&relay.state, 0x57).await;
    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![known.clone()], CLOCK).await;

    let unknown = vec![0x99u8; 32];
    client
        .send_frame(&Frame::Recon {
            group: unknown.clone(),
            payload: initiate(&[]).encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::GroupUnknown),
        other => panic!("expected denied/group_unknown before reconciliation, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_database_that_goes_away_mid_session_answers_retry_rather_than_closing() {
    // The read side's only interesting failure. `retry/backpressure` and an open
    // socket, because the client's correct response is backoff and a verbatim
    // resend, and a closed socket with no frame would be indistinguishable from a
    // network fault.
    let scratch = Scratch::new("dbgone").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x58).await;
    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], CLOCK).await;

    // The database is dropped from under the running relay, which is what an
    // operator's mistake or a failover looks like.
    let mut admin = sqlx::postgres::PgConnection::connect(&support::admin_url())
        .await
        .expect("connect as admin");
    admin
        .execute(format!("drop database if exists {} with (force)", scratch.name).as_str())
        .await
        .expect("drop it under the relay");

    client
        .send_frame(&Frame::Recon {
            group: group.clone(),
            payload: initiate(&[]).encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::Backpressure);
            assert!(error.code.class().is_retryable());
        }
        other => panic!("expected retry/backpressure, got {other:?}"),
    }

    // SUB also reports the outage rather than closing.  The workspace lookup now
    // happens before its acknowledgement, so there is no stale head to report.
    client
        .send_frame(&Frame::Sub {
            group: group.clone(),
            from_seq: 0,
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::Backpressure),
        other => panic!("expected retry/backpressure, got {other:?}"),
    }

    relay.shutdown().await;
}

use sqlx::Connection as _;

/// A group with a hash that is not 32 bytes cannot exist, so this suite never has to
/// reason about a short id. Asserted here rather than assumed, because
/// `id_from_slice` saturates and a schema that allowed a short hash would make that
/// saturation reachable with two different envelopes hashing to one id.
#[tokio::test]
async fn the_schema_refuses_a_hash_that_is_not_thirty_two_bytes() {
    let scratch = Scratch::new("hashwidth").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x59).await;
    let result = sqlx::query(
        "insert into relay_envelope (group_id, hash, v, enc, epoch, seq, ts, ct) \
         values ($1, $2, 1, 0, 0, 1, 0, $3)",
    )
    .bind(&group)
    .bind(vec![0u8; 8])
    .bind(vec![1u8, 2, 3])
    .execute(relay.state.database.as_ref().unwrap().pool())
    .await;
    assert!(
        result.is_err(),
        "a short hash must be refused by the schema"
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

/// One envelope, built the way the suite builds them, so the helper is exercised
/// even in a run where every other test is filtered out.
#[test]
fn an_envelope_addresses_its_own_contents() {
    let group = vec![0x60u8; 32];
    let envelope = envelope_for(&group, b"body");
    assert_eq!(
        envelope.hash,
        content_hash(1, Encryption::None, &group, 0, b"body")
    );
}

/// A client that already holds part of a group's history, catching up across the
/// queue bound.
///
/// The two tests above cross the bound from an empty client, which produces one
/// span: every omitted id falls inside it, so the loop that reopens a range as a
/// fingerprint takes the same arm on every pass. A client partway through a
/// catch-up is the ordinary case and the harder one. Its opening message carries
/// several ranges, the overflow touches only some of them, and the arms that
/// decide *which* ranges reopen finally get to be wrong.
///
/// That distinction is the whole correctness of the bounded push. Reopening a
/// range that had nothing omitted costs a round the client did not need; failing
/// to reopen one that did is the stranding this code was written to prevent, and
/// the difference between them is invisible from a single-span fixture.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_holding_part_of_a_group_catches_up_across_the_queue_bound() {
    let scratch = Scratch::new("partial-over-queue").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x5a).await;

    let mut writer = Client::connect(relay.address).await;
    writer.handshake(vec![group.clone()], CLOCK).await;
    // Comfortably over the bound, so the overflow is real rather than marginal.
    let bodies: Vec<Vec<u8>> = (0u16..400)
        .map(|index| index.to_be_bytes().to_vec())
        .collect();
    let refs: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
    let all = publish(&mut writer, &group, &refs).await;

    // The reader starts holding a scattered subset rather than a prefix: a
    // client that has been receiving live pushes while offline for some of them
    // has gaps in the middle, and a subset chosen by stride puts a held item in
    // every part of the id space, which is what makes the ranges split.
    let mut local = Local::default();
    for envelope in all.iter().step_by(3) {
        local
            .apply(envelope.clone())
            .expect("a locally held envelope");
    }
    let held = local.ids().len();
    assert!(held > 1, "the fixture must start with history of its own");

    let mut reader = Client::connect(relay.address).await;
    reader.handshake(vec![group.clone()], CLOCK).await;
    let rounds = reconcile_to_convergence(&mut reader, &mut local, &group, &[], 16).await;

    assert_eq!(
        local.ids(),
        all.iter().map(id_of).collect(),
        "a partly caught-up client must still converge on the whole group"
    );
    assert!(
        rounds >= 2,
        "the fixture must cross the queue-bound continuation"
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_group_of_large_envelopes_converges_across_the_byte_budget() {
    // The companion to the two tests above, which cross the frame bound with small
    // envelopes. This one crosses the byte bound with few envelopes, and it is the
    // proof that the bound `ws::SEND_QUEUE_BYTE_BUDGET` introduced did not quietly
    // turn a memory limit into a disconnect: a batch built to the frame count alone
    // would be refused by the queue and end the connection, which is what the
    // handshake replay used to do from the other direction.
    //
    // Thirty-two envelopes of 512 KiB is 16 MiB against a 7 MiB allowance, so the
    // response cannot be one round and the ranges holding the remainder have to come
    // back open.
    let scratch = Scratch::new("recon-over-bytes").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x5c).await;

    let mut writer = Client::connect(relay.address).await;
    writer.handshake(vec![group.clone()], CLOCK).await;
    let bodies: Vec<Vec<u8>> = (0u16..32)
        .map(|index| {
            let mut body = vec![0u8; 512 * 1024];
            body[..2].copy_from_slice(&index.to_be_bytes());
            body
        })
        .collect();
    let refs: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
    let all = publish(&mut writer, &group, &refs).await;

    let mut reader = Client::connect(relay.address).await;
    reader.handshake(vec![group.clone()], CLOCK).await;
    let mut local = Local::default();
    let rounds = reconcile_to_convergence(&mut reader, &mut local, &group, &[], 12).await;

    assert_eq!(
        local.ids(),
        all.iter().map(id_of).collect(),
        "every envelope arrived, whatever it took"
    );
    assert!(
        rounds >= 2,
        "the fixture must cross the byte allowance, took {rounds} round"
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}
