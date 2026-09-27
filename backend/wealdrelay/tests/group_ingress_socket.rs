// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The admission-blind per-group `SEND` budget over a real socket (WEALD-L1090).
//!
//! `wire.md` holds a principal to 8 MiB a minute into one group. Before this,
//! nine 1 MB frames into one group were all stored and fanned out.

mod support;

use wealdrelay::frame::{ErrorClass, ErrorCode, Frame};
use wealdrelay::group_ingress::{
    GroupIngressBudget, IngressRefusal, DEFAULT_PRINCIPAL_GROUP_BYTES_PER_MINUTE,
    GROUP_INGRESS_WINDOW_MS,
};
use wealdrelay::health::Clock;

use support::{config_for, default_device, envelope_for, make_group, Client, Running, Scratch};

const CLOCK: u64 = 1_700_000_000_000;
const BODY: usize = 1_000_000;

async fn stored(state: &std::sync::Arc<wealdrelay::health::RelayState>, group: &[u8]) -> i64 {
    let pool = state.database.as_ref().expect("a database").pool();
    let (count,): (i64,) =
        sqlx::query_as("select count(*) from relay_envelope where group_id = $1")
            .bind(group)
            .fetch_one(pool)
            .await
            .expect("count envelopes");
    count
}

#[tokio::test]
async fn the_ninth_megabyte_into_one_group_is_refused_and_another_group_still_takes_it() {
    let scratch = Scratch::new("group-ingress-flood").await;
    let blobs = tempfile::tempdir().expect("a blob directory");
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let first = make_group(&relay.state, 0x61).await;
    let second = make_group(&relay.state, 0x62).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake_as(
        &default_device(),
        vec![first.clone(), second.clone()],
        CLOCK,
    )
    .await;

    for index in 0..8u8 {
        let envelope = envelope_for(&first, &vec![index; BODY]);
        ada.send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
        match ada.recv_frame().await {
            Frame::SendAck { hash, .. } => assert_eq!(hash, envelope.hash),
            other => panic!("frame {index} inside the budget was refused: {other:?}"),
        }
    }
    let over = envelope_for(&first, &vec![0xee; BODY]);
    ada.send_frame(&Frame::Send {
        envelope: over.encode(),
    })
    .await;
    let error = match ada.recv_frame().await {
        Frame::Error(error) => error,
        other => panic!("expected group_ingress_limited, got {other:?}"),
    };
    assert_eq!(error.code, ErrorCode::GroupIngressLimited);
    assert_eq!(error.code.class(), ErrorClass::Quota);
    assert_eq!(
        error.retry_after,
        Some((GROUP_INGRESS_WINDOW_MS / 1_000) as u32)
    );
    assert_eq!(
        error.detail,
        Some(
            DEFAULT_PRINCIPAL_GROUP_BYTES_PER_MINUTE
                .to_be_bytes()
                .to_vec()
        )
    );
    assert_eq!(
        stored(&relay.state, &first).await,
        8,
        "the refused frame was stored"
    );

    let elsewhere = envelope_for(&second, &vec![0x11; BODY]);
    ada.send_frame(&Frame::Send {
        envelope: elsewhere.encode(),
    })
    .await;
    match ada.recv_frame().await {
        Frame::SendAck { hash, .. } => assert_eq!(hash, elsewhere.hash),
        other => panic!("a second group was refused: {other:?}"),
    }
    assert_eq!(relay.state.group_ingress.refused(), 1);
}

#[tokio::test]
async fn the_workspace_ceiling_holds_across_groups_and_a_refusal_charges_nothing() {
    let budget = GroupIngressBudget::new(10, 25);
    let now = CLOCK;
    assert_eq!(budget.charge(b"a", b"g1", "ws", 10, now).await, Ok(()));
    assert_eq!(
        budget.charge(b"a", b"g1", "ws", 1, now).await,
        Err(IngressRefusal::PrincipalGroup)
    );
    assert_eq!(budget.charge(b"a", b"g2", "ws", 10, now).await, Ok(()));
    assert_eq!(
        budget.charge(b"b", b"g3", "ws", 10, now).await,
        Err(IngressRefusal::Workspace)
    );
    // The refusal above charged nothing, so five bytes still fit the workspace.
    assert_eq!(budget.charge(b"b", b"g3", "ws", 5, now).await, Ok(()));
    // Another workspace is its own ceiling, and a new window starts again.
    assert_eq!(budget.charge(b"c", b"g4", "other", 10, now).await, Ok(()));
    assert_eq!(
        budget
            .charge(b"a", b"g1", "ws", 10, now + GROUP_INGRESS_WINDOW_MS)
            .await,
        Ok(())
    );
    assert_eq!(budget.refused(), 2);
}
