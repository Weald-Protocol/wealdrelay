// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `WAKE` over real sockets against real Postgres.
//!
//! What a client can actually do with the frame, and what it cannot. Every relay
//! here is `serve::prepare` on an ephemeral port with the harness Postgres behind
//! it, and every client is the hand-rolled WebSocket in `support`: nothing about the
//! registration path is exercised through the relay's own encoder talking to itself.
//!
//! The relays with push on point at `https://ringer.invalid/v1/wake`, which resolves
//! to nothing. That is deliberate for this suite: registration must not depend on the
//! ringer being reachable, and a suite that needed a listener to prove a `Register`
//! would have been a suite that could not tell the two apart. The outbound leg has
//! its own suite (`push_adversarial.rs`) with a real listener.

mod support;

use wealdrelay::frame::{ErrorCode, Frame, WakeBody, PROTOCOL_VERSION};
use wealdrelay::health::Clock;
use wealdrelay::push::{Category, ALL_CATEGORIES, REGISTRATIONS_PER_HOUR};

use support::{
    config_for, config_for_push, default_device, entry_hash_of, make_group, make_group_in,
    other_device, wake_expiry, wake_handle, Client, Running, Scratch,
};

const CLOCK: u64 = 1_700_000_000_000;
/// A url that is well formed, https, and resolves to nothing. See the module note.
const UNREACHABLE_RINGER: &str = "https://ringer.invalid/v1/wake";

fn register(seed: u8, categories: u8) -> Frame {
    Frame::Wake(WakeBody::Register {
        handle: wake_handle(seed),
        categories,
        expires_at: wake_expiry(CLOCK),
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_registers_and_the_relay_states_when_it_will_forget() {
    let scratch = Scratch::new("push_socket_register").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), UNREACHABLE_RINGER, 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x50).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&register(0xA1, ALL_CATEGORIES)).await;
    assert_eq!(
        ada.recv_frame().await,
        Frame::Wake(WakeBody::Registered {
            expires_at: wake_expiry(CLOCK)
        }),
        "the relay states the expiry it will honour, which is the ringer's own"
    );

    // And the row is there, against the salted entry hash and against nothing else.
    let pool = relay.state.database.as_ref().unwrap().pool();
    let entry = entry_hash_of(pool, "ws-step4", &default_device()).await;
    let stored = wealdrelay::push::store::find(pool, "ws-step4", &entry)
        .await
        .expect("the store answers")
        .expect("a row");
    assert_eq!(stored.0, wake_handle(0xA1));
    assert_eq!(stored.1, ALL_CATEGORIES);

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn re_registering_replaces_rather_than_accumulates() {
    // One live registration per device per workspace. A device that rotated weekly
    // for a year holds one row, not fifty two, which is what the primary key is for.
    let scratch = Scratch::new("push_socket_rotate").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), UNREACHABLE_RINGER, 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x51).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&register(0xB1, ALL_CATEGORIES)).await;
    assert!(matches!(
        ada.recv_frame().await,
        Frame::Wake(WakeBody::Registered { .. })
    ));
    ada.send_frame(&register(0xB2, Category::Call.bit())).await;
    assert!(matches!(
        ada.recv_frame().await,
        Frame::Wake(WakeBody::Registered { .. })
    ));

    let pool = relay.state.database.as_ref().unwrap().pool();
    let entry = entry_hash_of(pool, "ws-step4", &default_device()).await;
    let stored = wealdrelay::push::store::find(pool, "ws-step4", &entry)
        .await
        .expect("the store answers")
        .expect("a row");
    assert_eq!(
        stored.0,
        wake_handle(0xB2),
        "the new handle replaced the old"
    );
    assert_eq!(stored.1, Category::Call.bit());
    let rows: i64 = sqlx::query_scalar("select count(*) from relay_push_handle")
        .fetch_one(pool)
        .await
        .expect("count the rows");
    assert_eq!(rows, 1, "the rotation left no orphan");

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn clear_forgets_the_registration_and_a_clear_with_no_row_is_the_same_answer() {
    // A distinguishable answer would turn `Clear` into an oracle for whether a
    // principal had registered, which is a membership fact the relay does not hand
    // out to whoever opened a socket.
    let scratch = Scratch::new("push_socket_clear").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), UNREACHABLE_RINGER, 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x52).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;

    // No row at all: still `Cleared`.
    ada.send_frame(&Frame::Wake(WakeBody::Clear)).await;
    assert_eq!(ada.recv_frame().await, Frame::Wake(WakeBody::Cleared));

    ada.send_frame(&register(0xC1, ALL_CATEGORIES)).await;
    let _ = ada.recv_frame().await;
    ada.send_frame(&Frame::Wake(WakeBody::Clear)).await;
    assert_eq!(ada.recv_frame().await, Frame::Wake(WakeBody::Cleared));

    let pool = relay.state.database.as_ref().unwrap().pool();
    let entry = entry_hash_of(pool, "ws-step4", &default_device()).await;
    assert!(wealdrelay::push::store::find(pool, "ws-step4", &entry)
        .await
        .expect("the store answers")
        .is_none());

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_query_on_a_push_off_relay_says_so_and_names_no_ringer() {
    // The default posture. A client reads `enabled: false` as an instruction to hold
    // no registration and raise no expectation of push, which is the same thing it
    // does against a version 3 relay.
    let scratch = Scratch::new("push_socket_query_off").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x53).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&Frame::Wake(WakeBody::Query)).await;
    assert_eq!(
        ada.recv_frame().await,
        Frame::Wake(WakeBody::Capability {
            enabled: false,
            register_url: String::new(),
        })
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_query_on_a_push_on_relay_names_the_ringer_the_operator_chose() {
    // Forms 5 and 6 are what make a self-hosted deployment work with a shipped client
    // and no client-side configuration: the device does not guess a ringer, because
    // guessing ours would mean a self-hoster's users registering with a party their
    // operator did not choose.
    let scratch = Scratch::new("push_socket_query_on").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), UNREACHABLE_RINGER, 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x54).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&Frame::Wake(WakeBody::Query)).await;
    match ada.recv_frame().await {
        Frame::Wake(WakeBody::Capability {
            enabled,
            register_url,
        }) => {
            assert!(enabled);
            // The wake path is substituted, not appended: the configured
            // `WEALD_RELAY_PUSH_URL` is a whole `/v1/wake` route, and appending gave
            // every device a 404 to register against.
            assert_eq!(register_url, "https://ringer.invalid/v1/handles");
            assert!(
                register_url.starts_with("https://"),
                "a client refuses anything else"
            );
            assert!(register_url.len() <= wealdrelay::push::MAX_REGISTER_URL_BYTES);
        }
        other => panic!("expected a capability, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_register_on_a_push_off_relay_is_denied_rather_than_rejected() {
    // Denied, because the frame is well formed and the answer would change if the
    // operator changed one variable. The client's correct response is `Query`.
    let scratch = Scratch::new("push_socket_denied").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x55).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&register(0xD1, ALL_CATEGORIES)).await;
    match ada.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::PushNotConfigured);
            assert_eq!(error.code.qualified(), "denied/push_not_configured");
        }
        other => panic!("expected a denial, got {other:?}"),
    }

    // Nothing was written, and the socket is still up: a denial is not a disconnect.
    let pool = relay.state.database.as_ref().unwrap().pool();
    let rows: i64 = sqlx::query_scalar("select count(*) from relay_push_handle")
        .fetch_one(pool)
        .await
        .expect("count the rows");
    assert_eq!(rows, 0);
    ada.send_frame(&Frame::Wake(WakeBody::Query)).await;
    assert!(matches!(
        ada.recv_frame().await,
        Frame::Wake(WakeBody::Capability { .. })
    ));

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sixth_registration_in_an_hour_is_refused_and_the_socket_survives() {
    // Rotation is weekly by design, so five is generous. The ceiling exists because a
    // registration is a write and a device with a loop must not be one.
    let scratch = Scratch::new("push_socket_rate").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), UNREACHABLE_RINGER, 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x56).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    for seed in 0..REGISTRATIONS_PER_HOUR {
        ada.send_frame(&register(
            u8::try_from(0xE0 + seed).expect("a byte"),
            ALL_CATEGORIES,
        ))
        .await;
        assert!(matches!(
            ada.recv_frame().await,
            Frame::Wake(WakeBody::Registered { .. })
        ));
    }
    ada.send_frame(&register(0xEF, ALL_CATEGORIES)).await;
    match ada.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::PushRegistrationRate);
            assert_eq!(error.retry_after, Some(3600));
            assert_eq!(
                error.detail,
                Some(u64::from(REGISTRATIONS_PER_HOUR).to_be_bytes().to_vec()),
                "the ceiling is named, so a client can back off against it"
            );
        }
        other => panic!("expected a quota refusal, got {other:?}"),
    }

    // The frame only. Durable traffic is unaffected, exactly as it is by a spent
    // presence or key budget.
    let envelope = support::envelope_for(&group, b"still writing");
    ada.send_frame(&Frame::Send {
        envelope: envelope.encode(),
    })
    .await;
    assert!(matches!(ada.recv_frame().await, Frame::SendAck { .. }));

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reconnect_does_not_hand_a_device_a_fresh_allowance() {
    // Per principal, not per connection. A per-connection budget would be a ceiling a
    // device clears by reconnecting, which is no ceiling.
    let scratch = Scratch::new("push_socket_rate_reconnect").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), UNREACHABLE_RINGER, 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x57).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    for seed in 0..REGISTRATIONS_PER_HOUR {
        ada.send_frame(&register(
            u8::try_from(0x60 + seed).expect("a byte"),
            ALL_CATEGORIES,
        ))
        .await;
        let _ = ada.recv_frame().await;
    }

    let mut again = Client::connect(relay.address).await;
    again.handshake(vec![group.clone()], CLOCK).await;
    again.send_frame(&register(0x6F, ALL_CATEGORIES)).await;
    match again.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::PushRegistrationRate),
        other => panic!("expected the same refusal on a new socket, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_in_another_workspace_cannot_claim_a_registered_handle() {
    // The unique index, from the wire. A second principal claiming a handle already
    // registered is the only way one device could steal another's wakes, and the
    // answer is the same whether the other claimant is in this workspace or not, so
    // it is not an oracle for who else has registered.
    let scratch = Scratch::new("push_socket_cross_workspace").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), UNREACHABLE_RINGER, 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let ada_key = default_device();
    let bo_key = other_device();
    let first = make_group_in(
        &relay.state,
        "ws-a",
        0x58,
        std::slice::from_ref(&ada_key),
        std::slice::from_ref(&ada_key),
    )
    .await;
    let second = make_group_in(
        &relay.state,
        "ws-b",
        0x59,
        std::slice::from_ref(&bo_key),
        std::slice::from_ref(&bo_key),
    )
    .await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake_as(&ada_key, vec![first], CLOCK).await;
    ada.send_frame(&register(0x77, ALL_CATEGORIES)).await;
    assert!(matches!(
        ada.recv_frame().await,
        Frame::Wake(WakeBody::Registered { .. })
    ));

    let mut bo = Client::connect(relay.address).await;
    bo.handshake_as(&bo_key, vec![second], CLOCK).await;
    bo.send_frame(&register(0x77, ALL_CATEGORIES)).await;
    match bo.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::PushHandleMalformed),
        other => panic!("expected the claim to be refused, got {other:?}"),
    }

    // And the first device still holds it.
    let pool = relay.state.database.as_ref().unwrap().pool();
    let entry = entry_hash_of(pool, "ws-a", &ada_key).await;
    assert_eq!(
        wealdrelay::push::store::find(pool, "ws-a", &entry)
            .await
            .expect("the store answers")
            .expect("a row")
            .0,
        wake_handle(0x77)
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expiry_already_in_the_past_is_rejected_against_the_relays_own_clock() {
    // The codec has no clock, so this is the session's judgement, and it is a reject
    // rather than a denial: a registration that expired before it arrived is
    // permanently wrong as sent and the fix is a live handle from the ringer.
    let scratch = Scratch::new("push_socket_expired").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), UNREACHABLE_RINGER, 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x5A).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    ada.send_frame(&Frame::Wake(WakeBody::Register {
        handle: wake_handle(0x88),
        categories: ALL_CATEGORIES,
        expires_at: CLOCK - 1,
    }))
    .await;
    match ada.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::PushHandleMalformed),
        other => panic!("expected a reject, got {other:?}"),
    }
    // Exactly now is also past: an expiry the relay has already reached is one it
    // would forget in the same instant it stored it.
    ada.send_frame(&Frame::Wake(WakeBody::Register {
        handle: wake_handle(0x89),
        categories: ALL_CATEGORIES,
        expires_at: CLOCK,
    }))
    .await;
    match ada.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::PushHandleMalformed),
        other => panic!("expected a reject, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_to_client_form_sent_upward_closes_the_connection() {
    let scratch = Scratch::new("push_socket_wrong_form").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), UNREACHABLE_RINGER, 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x5B).await;

    for body in [
        WakeBody::Registered { expires_at: 0 },
        WakeBody::Cleared,
        WakeBody::Capability {
            enabled: true,
            register_url: String::new(),
        },
    ] {
        let mut ada = Client::connect(relay.address).await;
        ada.handshake(vec![group.clone()], CLOCK).await;
        ada.send_frame(&Frame::Wake(body)).await;
        match ada.recv_frame().await {
            Frame::Error(error) => assert_eq!(error.code, ErrorCode::MalformedHeader),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(ada.recv().await.is_none(), "and the connection ends");
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wake_before_auth_is_refused_like_every_frame_except_join() {
    let scratch = Scratch::new("push_socket_pre_auth").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), UNREACHABLE_RINGER, 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x5C).await;

    let mut stranger = Client::connect(relay.address).await;
    stranger
        .handshake_to_challenge(vec![group.clone()], CLOCK)
        .await;
    stranger.send_frame(&register(0x99, ALL_CATEGORIES)).await;
    match stranger.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::MalformedHeader),
        other => panic!("expected a refusal, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_version_three_client_is_served_at_three_and_never_receives_a_wake() {
    // The compatibility claim, from the client's side. It offers 3, the relay selects
    // 3, and the frame version 4 added is one it never sees. A client that never sends
    // a `WAKE` never registers, so it never receives a push, which is the same posture
    // as a relay with push off.
    let scratch = Scratch::new("push_socket_version_three").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), UNREACHABLE_RINGER, 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x5D).await;

    let mut older = Client::connect(relay.address).await;
    older
        .handshake_as_version(&default_device(), vec![group.clone()], CLOCK, 3)
        .await;

    // It still writes, subscribes and is acknowledged: nothing about version 4 took
    // anything away from it.
    older
        .send_frame(&Frame::Sub {
            group: group.clone(),
            from_seq: 0,
        })
        .await;
    assert!(matches!(older.recv_frame().await, Frame::SubAck { .. }));

    // And a fully-versioned peer writing into the same group produces a `PUSH` for it
    // and never a `WAKE`.
    let mut ada = Client::connect(relay.address).await;
    ada.handshake_as(&other_device(), vec![group.clone()], CLOCK)
        .await;
    let envelope = support::envelope_for(&group, b"a message");
    ada.send_frame(&Frame::Send {
        envelope: envelope.encode(),
    })
    .await;
    assert!(matches!(ada.recv_frame().await, Frame::SendAck { .. }));
    match older.recv_frame().await {
        Frame::Push { .. } => {}
        other => panic!("a version 3 client is still pushed envelopes, got {other:?}"),
    }
    assert_eq!(PROTOCOL_VERSION, 4, "and this build speaks four");

    relay.shutdown().await;
    scratch.drop_database().await;
}
