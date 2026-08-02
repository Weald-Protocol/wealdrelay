// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `DROP` over a real socket, and every answer the frame layer can give.
//!
//! Tier 3 and tier 5. `tests/lifecycle_drop.rs` proves the decision right;
//! this file proves the instruction reaches it over a WebSocket a client speaks
//! and that the answer comes back on the same frame. The three refusals below the
//! decision live here too, because they are answers about the *session* rather
//! than about the instruction: a group in another workspace, a group the relay
//! has never heard of, and a payload that is not a record at all.

mod support;

use std::sync::Arc;

use sqlx::PgPool;
use wealdrelay::frame::{ErrorCode, Frame};
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::lifecycle::wire::{DropBefore, Response};
use wealdrelay::media::retention;

use support::{
    config_for, default_device, device_from, envelope_for, make_group_in, signed_control,
    signed_drop, signed_policy, verifier_key, Client, Running, Scratch,
};

const NOW_MS: u64 = 1_800_000_000_000;
const NOW_SECS: u64 = NOW_MS / 1000;
const WS: &str = "ws-lifecycle-socket";

fn pool_of(state: &Arc<RelayState>) -> &PgPool {
    state.database.as_ref().expect("a database").pool()
}

#[track_caller]
fn drop_answer(frame: &Frame) -> Response {
    match frame {
        Frame::Drop { payload } => Response::decode(payload).expect("a lifecycle response"),
        other => panic!("expected a DROP answer, got {other:?}"),
    }
}

async fn ask(client: &mut Client, record: &DropBefore) -> Frame {
    client
        .send_frame(&Frame::Drop {
            payload: record.encode(),
        })
        .await;
    client.recv_frame().await
}

/// A group, a chain, a due policy, and a log with a checkpoint at the top: the
/// state a steward's compaction runs against.
async fn prepared(label: &str) -> (Scratch, tempfile::TempDir, Running, Vec<u8>, Vec<u8>, u64) {
    let scratch = Scratch::new(label).await;
    let blobs = tempfile::tempdir().unwrap();
    let config = config_for(&scratch, blobs.path());
    let running = Running::start(config.clone(), Clock::Fixed(NOW_MS)).await;
    let group = make_group_in(
        &running.state,
        WS,
        0x62,
        &[default_device(), device_from(0x32)],
        &[default_device(), device_from(0x32)],
    )
    .await;

    let key = verifier_key(0x51);
    retention::apply_control(
        pool_of(&running.state),
        &signed_control(&group, 0, &key, None, &key),
    )
    .await
    .expect("the control lands");
    let policy = signed_policy(
        &group,
        1,
        180,
        NOW_SECS - 1,
        &[default_device(), device_from(0x32)],
    );
    retention::insert_policy(pool_of(&running.state), &policy, "[]")
        .await
        .expect("the policy lands");

    let mut manifest = Vec::new();
    for index in 0..4u32 {
        let envelope = envelope_for(&group, format!("socket record {index}").as_bytes());
        wealdrelay::accept::accept(pool_of(&running.state), &config, &envelope, NOW_MS)
            .await
            .expect("accepted");
        manifest = envelope.hash.clone();
    }
    let barrier: i64 =
        sqlx::query_scalar("select seq from relay_envelope where group_id = $1 and hash = $2")
            .bind(&group)
            .bind(&manifest)
            .fetch_one(pool_of(&running.state))
            .await
            .expect("the checkpoint's own seq");

    (scratch, blobs, running, group, manifest, barrier as u64)
}

#[tokio::test]
async fn an_instruction_travels_over_the_socket_and_the_count_comes_back() {
    let (scratch, _blobs, running, group, manifest, _barrier) = prepared("socket_drop").await;
    let mut client = Client::connect(running.address).await;
    client.handshake(vec![group.clone()], NOW_MS).await;

    let record = signed_drop(
        &group,
        &manifest,
        Vec::new(),
        0,
        Some(1),
        None,
        &verifier_key(0x51),
    );
    let answer = drop_answer(&ask(&mut client, &record).await);
    assert_eq!(
        answer,
        Response::Dropped {
            deleted: 3,
            bytes: 45,
            kept: 0
        }
    );

    // A second, identical instruction is not a second deletion: everything below
    // the barrier is already gone, and the answer says so rather than failing.
    let answer = drop_answer(&ask(&mut client, &record).await);
    assert_eq!(
        answer,
        Response::Dropped {
            deleted: 0,
            bytes: 0,
            kept: 0
        }
    );

    // The remaining log is the checkpoint and nothing beneath it.
    let left: i64 = sqlx::query_scalar("select count(*) from relay_envelope where group_id = $1")
        .bind(&group)
        .fetch_one(pool_of(&running.state))
        .await
        .expect("count the log");
    assert_eq!(left, 1);

    running.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_refusal_comes_back_on_the_same_frame_rather_than_as_an_error() {
    // A refusal is a verdict about the instruction, so it is an answer and not a
    // protocol error: the client stays connected and knows exactly what to fix.
    let (scratch, _blobs, running, group, manifest, _barrier) = prepared("socket_refusal").await;
    let mut client = Client::connect(running.address).await;
    client.handshake(vec![group.clone()], NOW_MS).await;

    let forged = signed_drop(
        &group,
        &manifest,
        Vec::new(),
        0,
        Some(1),
        None,
        &verifier_key(0x7e),
    );
    assert_eq!(
        drop_answer(&ask(&mut client, &forged).await),
        Response::Refused {
            reason: "bad_signature".to_string()
        }
    );

    // Still connected, and the next instruction is answered normally.
    let good = signed_drop(
        &group,
        &manifest,
        Vec::new(),
        0,
        Some(1),
        None,
        &verifier_key(0x51),
    );
    assert!(matches!(
        drop_answer(&ask(&mut client, &good).await),
        Response::Dropped { .. }
    ));

    running.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_payload_that_is_not_an_instruction_is_a_protocol_error() {
    let (scratch, _blobs, running, group, _manifest, _barrier) = prepared("socket_malformed").await;
    let mut client = Client::connect(running.address).await;
    client.handshake(vec![group.clone()], NOW_MS).await;

    client
        .send_frame(&Frame::Drop {
            payload: vec![0xff, 0xff, 0xff],
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::MalformedHeader),
        other => panic!("expected a protocol error, got {other:?}"),
    }

    running.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_group_outside_this_session_is_refused_before_the_instruction_is_read() {
    // The same rule `SEND`, `SUB` and `BLOB` follow: a group named in a frame has
    // to belong to the workspace this session authenticated into. A relay that
    // checked the signature first would let anybody with a valid instruction for
    // their own group point it at somebody else's.
    let (scratch, _blobs, running, group, manifest, _barrier) = prepared("socket_foreign").await;

    // A second workspace with a group of its own.
    let other = make_group_in(
        &running.state,
        "ws-somebody-else",
        0x63,
        &[device_from(0x41)],
        &[device_from(0x41)],
    )
    .await;

    let mut client = Client::connect(running.address).await;
    client.handshake(vec![group.clone()], NOW_MS).await;

    let record = signed_drop(
        &other,
        &manifest,
        Vec::new(),
        0,
        Some(1),
        None,
        &verifier_key(0x51),
    );
    match ask(&mut client, &record).await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("expected a refusal, got {other:?}"),
    }

    // And a group nobody has provisioned at all.
    let unknown = signed_drop(
        &[0x77; 32],
        &manifest,
        Vec::new(),
        0,
        Some(1),
        None,
        &verifier_key(0x51),
    );
    match ask(&mut client, &unknown).await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::GroupUnknown),
        other => panic!("expected a refusal, got {other:?}"),
    }

    running.shutdown().await;
    scratch.drop_database().await;
}
