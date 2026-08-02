// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Handshake messages against real Postgres: the order, the resend, the replay.
//!
//! The order is the whole product of this table. Envelopes converge in any order,
//! because reconciliation is over a set; handshake messages do not, because a
//! commit for epoch N+1 cannot be processed before the commit for epoch N. So the
//! claims worth proving are about sequence:
//!
//! - Two messages never take the same number, including under concurrency.
//! - The numbers are dense from zero, so a replaying client can tell a message it
//!   has not seen from one that does not exist.
//! - A resend after a dropped connection gets the number it already had rather than
//!   a second place in the order, which is the same promise `SEND` makes.
//!
//! Nothing here is mocked, and nothing here reads a message: the relay stores and
//! forwards these and holds no key that could open one.

mod support;

use std::sync::Arc;

use sqlx::PgPool;
use wealdrelay::handshake::store::{self, Appended, StoreError};
use wealdrelay::handshake::{Handshake, HandshakeError, MAX_MESSAGE_BYTES};
use wealdrelay::health::{Clock, RelayState};

use support::{config_for, make_group, Running, Scratch};

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

fn message(group: &[u8], body: &[u8]) -> Handshake {
    Handshake {
        group: group.to_vec(),
        message: body.to_vec(),
    }
}

#[tokio::test]
async fn the_order_is_dense_from_zero_and_replays_in_the_order_it_was_written() {
    let (scratch, _blobs, state) = prepared("handshake_order").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x11).await;

    for (index, body) in [b"create".as_slice(), b"add", b"commit"].iter().enumerate() {
        assert_eq!(
            store::append(pool, &message(&group, body))
                .await
                .expect("append"),
            Appended::Stored(index as u64),
            "the sequence is dense from zero"
        );
    }
    assert_eq!(store::head(pool, &group).await.expect("head"), 3);

    let replayed = store::since(pool, &group, 0).await.expect("replay");
    assert_eq!(
        replayed
            .iter()
            .map(|stored| (stored.seq, stored.message.clone()))
            .collect::<Vec<_>>(),
        vec![
            (0, b"create".to_vec()),
            (1, b"add".to_vec()),
            (2, b"commit".to_vec()),
        ]
    );

    // A partial replay, which is what a reconnecting client asks for.
    let tail = store::since(pool, &group, 2).await.expect("replay");
    assert_eq!(tail.len(), 1);
    assert_eq!(tail[0].seq, 2);
    // And past the end is empty rather than an error: a client whose cursor is
    // current has nothing to apply, which is the ordinary case on every reconnect.
    assert!(store::since(pool, &group, 3)
        .await
        .expect("replay")
        .is_empty());

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_resend_takes_the_number_it_already_had() {
    let (scratch, _blobs, state) = prepared("handshake_resend").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x12).await;

    let commit = message(&group, b"the same commit");
    assert_eq!(
        store::append(pool, &commit).await.expect("first"),
        Appended::Stored(0)
    );
    // The realistic case: the acknowledgement was lost, so the client sends the
    // identical bytes again. A second place in the order would make every other
    // member apply the same commit twice, and MLS refuses the second, which would
    // strand the group at an epoch nobody can advance.
    assert_eq!(
        store::append(pool, &commit).await.expect("resend"),
        Appended::Duplicate(0)
    );
    assert_eq!(store::head(pool, &group).await.expect("head"), 1);
    assert_eq!(
        store::since(pool, &group, 0).await.expect("replay").len(),
        1
    );

    // A different message still takes the next number.
    assert_eq!(
        store::append(pool, &message(&group, b"a different commit"))
            .await
            .expect("next"),
        Appended::Stored(1)
    );
    assert_eq!(Appended::Stored(1).seq(), 1);
    assert_eq!(Appended::Duplicate(4).seq(), 4);

    scratch.drop_database().await;
}

#[tokio::test]
async fn the_same_bytes_in_two_groups_are_two_messages() {
    let (scratch, _blobs, state) = prepared("handshake_two_groups").await;
    let pool = pool_of(&state);
    let first = make_group(&state, 0x13).await;
    let second = make_group(&state, 0x14).await;

    // Content addresses are never shared across groups, for the same reason
    // envelope hashes are not: an identical message in two groups is two facts, and
    // collapsing them would make one group's history depend on another's.
    let body = b"identical bytes";
    assert_eq!(
        store::append(pool, &message(&first, body))
            .await
            .expect("first group"),
        Appended::Stored(0)
    );
    assert_eq!(
        store::append(pool, &message(&second, body))
            .await
            .expect("second group"),
        Appended::Stored(0)
    );
    assert_eq!(
        store::since(pool, &first, 0).await.expect("replay").len(),
        1
    );
    assert_eq!(
        store::since(pool, &second, 0).await.expect("replay").len(),
        1
    );
    assert_ne!(
        message(&first, body).hash(),
        message(&second, body).hash(),
        "the content address does not separate the groups"
    );

    scratch.drop_database().await;
}

#[tokio::test]
async fn two_committers_at_once_never_take_the_same_number() {
    let (scratch, _blobs, state) = prepared("handshake_race").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x15).await;

    // The failure this guards against is not theoretical: `max(seq) + 1` computed
    // outside a lock hands the same number to both, and the loser's insert fails on
    // the primary key. Every member replaying the log would then be missing one of
    // the two commits, which is a group that has forked.
    let first = message(&group, b"committer one");
    let second = message(&group, b"committer two");
    let (a, b) = tokio::join!(store::append(pool, &first), store::append(pool, &second));
    let a = a.expect("one");
    let b = b.expect("two");
    assert_ne!(a.seq(), b.seq(), "two committers took the same number");
    assert_eq!(
        [a.seq(), b.seq()].iter().copied().min(),
        Some(0),
        "the order still starts at zero"
    );
    assert_eq!(store::head(pool, &group).await.expect("head"), 2);

    let replayed = store::since(pool, &group, 0).await.expect("replay");
    assert_eq!(replayed.len(), 2);
    assert_eq!(replayed[0].seq, 0);
    assert_eq!(replayed[1].seq, 1);

    scratch.drop_database().await;
}

#[tokio::test]
async fn a_message_the_bounds_refuse_never_reaches_the_table() {
    let (scratch, _blobs, state) = prepared("handshake_bounds").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x16).await;

    let mut narrow = message(&group, b"ok");
    narrow.group = vec![0x16; 31];
    assert!(matches!(
        store::append(pool, &narrow).await,
        Err(StoreError::Refused(HandshakeError::GroupWidth(31)))
    ));

    assert!(matches!(
        store::append(pool, &message(&group, b"")).await,
        Err(StoreError::Refused(HandshakeError::Empty))
    ));

    let huge = message(&group, &vec![0u8; MAX_MESSAGE_BYTES + 1]);
    assert!(matches!(
        store::append(pool, &huge).await,
        Err(StoreError::Refused(HandshakeError::TooLarge(_)))
    ));

    // A group the relay has never carried traffic for. It does not learn that a
    // group exists from a handshake message any more than it does from a wrap.
    assert!(matches!(
        store::append(pool, &message(&[0xAA; 32], b"ok")).await,
        Err(StoreError::Database(_))
    ));

    assert_eq!(store::head(pool, &group).await.expect("head"), 0);
    assert!(store::since(pool, &group, 0)
        .await
        .expect("replay")
        .is_empty());

    scratch.drop_database().await;
}

#[tokio::test]
async fn every_refusal_prints_itself_and_carries_the_wire_code_a_client_branches_on() {
    use wealdrelay::frame::ErrorCode;

    assert_eq!(
        HandshakeError::TooLarge(1).code(),
        ErrorCode::EnvelopeTooLarge
    );
    assert_eq!(
        HandshakeError::GroupWidth(31).code(),
        ErrorCode::MalformedHeader
    );
    assert_eq!(HandshakeError::Empty.code(), ErrorCode::MalformedHeader);
    // All three are `reject`: each is a property of the bytes, so resending them
    // will fail again and a client must not.
    for error in [
        HandshakeError::TooLarge(1),
        HandshakeError::GroupWidth(31),
        HandshakeError::Empty,
    ] {
        assert_eq!(error.code().class().as_str(), "reject", "{error}");
        assert!(!error.to_string().is_empty());
        assert_eq!(format!("{:?}", error.clone()), format!("{error:?}"));
    }
    assert!(HandshakeError::GroupWidth(31).to_string().contains("31"));
    assert!(HandshakeError::Empty.to_string().contains("empty"));
    assert!(HandshakeError::TooLarge(9).to_string().contains('9'));
    assert_eq!(HandshakeError::Empty, HandshakeError::Empty);
    assert_ne!(HandshakeError::Empty, HandshakeError::TooLarge(1));

    let handshake = Handshake {
        group: vec![1; 32],
        message: vec![2],
    };
    assert_eq!(handshake.check(), Ok(()));
    assert_eq!(handshake.hash().len(), 32);
    assert_eq!(format!("{:?}", handshake.clone()), format!("{handshake:?}"));
}
