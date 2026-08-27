// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The bytes the relay puts on the wire to the ringer, character for character.
//!
//! Every push suite downstream of this one answers "what did the relay mean": which
//! handle, which category, which decision after which answer. Those assertions are
//! made against substrings of a body, and a substring cannot see a contract
//! violation that arrives as an extra header, a second field or a differently
//! spelled request line — which is precisely the class of bug `ringer.md` route 3
//! exists to make impossible. The ringer refuses an unknown field rather than
//! tolerating it *because* silently ignoring one is how a group identifier
//! eventually arrives in a payload, so the relay's side of that bargain has to be
//! pinned the same way: against the recorded HTTP conversation, not against a Rust
//! type that could drift in step with a regression.
//!
//! The far end here is `support::RecordingRinger` in raw mode: a real TCP listener
//! speaking real HTTP/1.1, keeping the head as well as the body. Everything on the
//! relay's side of the wire is the shipping path — real client registration over a
//! real socket, a real envelope publish, the real worker and its pooled hyper
//! client.

mod support;

use serde_json::Value;
use wealdrelay::config::keys;
use wealdrelay::frame::{Frame, WakeBody};
use wealdrelay::health::Clock;
use wealdrelay::push::ALL_CATEGORIES;

use support::{
    config_for_push, config_with, entry_hash_of, make_group, other_device, wake_expiry,
    wake_handle, Client, RecordingRinger, Running, Scratch,
};

const CLOCK: u64 = 1_700_000_000_000;
const WORKSPACE: &str = "ws-step4";

/// What one journey produced, hex-encoded where a test wants to grep for it.
struct Journey {
    scratch: Scratch,
    ringer: RecordingRinger,
    relay: Running,
    /// Every request as it arrived, request line and headers and body.
    raw: Vec<String>,
    /// The group the message was published into, and the sleeping device's entry
    /// hash: the two identifiers the relay knows and must never send.
    group_hex: String,
    sleeper_hex: String,
}

/// One sleeping device registered through the shipping socket path, one publish
/// from a peer, and the single wake that must follow.
///
/// Both suites below need this same journey, and the journey is not what either of
/// them asserts: it is the rig the assertion is read off. `extra` carries any
/// additional configuration, which is how the bearer suite turns the credential on
/// without this rig knowing a credential exists.
async fn one_wake_from_a_sleeping_device(
    label: &str,
    extra: Vec<(&'static str, String)>,
) -> Journey {
    let scratch = Scratch::new(label).await;
    let blobs = tempfile::tempdir().unwrap();
    let ringer = RecordingRinger::accepting().await;
    let config = if extra.is_empty() {
        config_for_push(&scratch, blobs.path(), &ringer.url(), 0)
    } else {
        let base = [
            (keys::PUSH, "on".to_string()),
            (keys::PUSH_URL, ringer.url()),
            (keys::PUSH_COALESCE_MS, "0".to_string()),
        ];
        config_with(&scratch, blobs.path(), base.into_iter().chain(extra))
    };
    let relay = Running::start(config, Clock::Fixed(CLOCK)).await;

    let group = make_group(&relay.state, 0x60).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let sleeper_entry = entry_hash_of(pool, WORKSPACE, &other_device()).await;

    // Bo's Mac registers over the wire, exactly as `CompanionPushWiring` does on a
    // live session, and then goes away.
    let mut bo = Client::connect(relay.address).await;
    bo.handshake_as(&other_device(), vec![group.clone()], CLOCK)
        .await;
    bo.send_frame(&Frame::Wake(WakeBody::Register {
        handle: wake_handle(0x5B),
        categories: ALL_CATEGORIES,
        expires_at: wake_expiry(CLOCK),
    }))
    .await;
    assert!(matches!(
        bo.recv_frame().await,
        Frame::Wake(WakeBody::Registered { .. })
    ));
    drop(bo);
    support::wait_until_disconnected(&relay.state, &sleeper_entry).await;

    let worker = wealdrelay::push::spawn(&relay.state).expect("a worker");

    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![group.clone()], CLOCK).await;
    let envelope = support::envelope_for(&group, b"a message");
    ada.send_frame(&Frame::Send {
        envelope: envelope.encode(),
    })
    .await;
    assert!(matches!(ada.recv_frame().await, Frame::SendAck { .. }));

    let seen = ringer.wait_for(1).await;
    assert_eq!(seen.len(), 1, "one sleeping peer, one wake");
    let raw = ringer.raw_requests().await;
    worker.abort();

    Journey {
        scratch,
        ringer,
        relay,
        raw,
        group_hex: group.iter().map(|byte| format!("{byte:02x}")).collect(),
        sleeper_hex: sleeper_entry
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_wake_post_is_exactly_route_three_and_names_nothing_else() {
    let journey = one_wake_from_a_sleeping_device("push_ringer_wire_plain", vec![]).await;

    assert_eq!(journey.raw.len(), 1, "one publish, one HTTP conversation");
    let conversation = &journey.raw[0];

    // The request line names method and path and nothing else. The path is the
    // configured url's, origin-form, because that is what an HTTP client puts on
    // the wire and what a ringer behind either an operator's proxy prefix or a
    // bare port has to agree to serve.
    let (head, body) = match conversation.split_once("\r\n\r\n") {
        Some(parts) => parts,
        None => panic!("the recorded conversation had no head/body separator"),
    };
    let mut lines = head.lines();
    assert_eq!(
        lines.next(),
        Some("POST /v1/wake HTTP/1.1"),
        "route 3 is a POST to the configured path, and nothing else"
    );

    let lower = head.to_ascii_lowercase();
    assert!(
        lower.contains("content-type: application/json\r\n"),
        "the body declares itself json"
    );
    assert!(
        !lower.contains("authorization:"),
        "no bearer was configured, so none may be sent; a credential the operator \
         never chose must not appear because a default invented one"
    );
    let stated_length: usize = lower
        .split("content-length:")
        .nth(1)
        .and_then(|rest| rest.split("\r\n").next())
        .and_then(|value| value.trim().parse().ok())
        .expect("a body carried on the wire states its length");
    assert_eq!(stated_length, body.len(), "the stated length is the body");

    // The body carries exactly two fields. An extra tolerated field is the hole
    // `ringer.md` section 2 refuses at the far end; the near end does not get to
    // rely on that refusal as its own backstop.
    let json: Value = serde_json::from_str(body).expect("the body parses as json");
    let object = json.as_object().expect("the body is a json object");
    assert_eq!(
        object.keys().count(),
        2,
        "two fields, no more: got {object:?}"
    );
    assert!(object.contains_key("handle") && object.contains_key("category"));

    // The handle travels as lowercase hex of all sixteen bytes, which is the form
    // the ringer mints and resolves; truncated or uppercased it would 404, and the
    // row would be deleted for being dead when it is alive.
    let handle = object["handle"].as_str().expect("handle is a string");
    assert_eq!(handle.len(), 32, "sixteen bytes as hex");
    assert!(
        handle
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "lowercase hex, got {handle}"
    );
    let expected: String = wake_handle(0x5B)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(handle, expected);

    assert_eq!(object["category"], "message");

    // What the relay knows and must never send: the group id and the principals'
    // entry hashes. None are fields of route 3, and none may arrive as an accident
    // of serialization either, which is why this reads the whole conversation and
    // not only the parsed fields.
    assert!(
        !conversation.contains(&journey.group_hex),
        "the group id reached the ringer"
    );
    assert!(
        !conversation.contains(&journey.sleeper_hex),
        "the sleeping device's entry hash reached the ringer"
    );

    journey.ringer.stop();
    journey.relay.shutdown().await;
    journey.scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_configured_bearer_rides_the_header_and_appears_nowhere_else() {
    // Deliberately not a plausible secret: something greppable, so a leak into a
    // body, a query string or a second header cannot hide behind resemblance to
    // the surrounding traffic.
    const TOKEN: &str = "wake-bearer-9c27-operator";
    let journey = one_wake_from_a_sleeping_device(
        "push_ringer_wire_bearer",
        vec![(keys::PUSH_TOKEN, TOKEN.to_string())],
    )
    .await;

    assert_eq!(journey.raw.len(), 1);
    let conversation = &journey.raw[0];
    let (head, body) = match conversation.split_once("\r\n\r\n") {
        Some(parts) => parts,
        None => panic!("the recorded conversation had no head/body separator"),
    };

    let lower = head.to_ascii_lowercase();
    assert!(
        lower.contains(&format!("authorization: bearer {TOKEN}\r\n")),
        "the credential rides the Authorization header as a bearer"
    );
    assert_eq!(
        lower.matches("authorization:").count(),
        1,
        "exactly one authorization header"
    );
    // And nowhere else: not in the body, whose two fields are fixed, and not
    // spelled out a second time anywhere on the wire.
    assert!(
        !body.contains(TOKEN),
        "the bearer leaked into the body, which the ringer would refuse and worse, read"
    );
    assert_eq!(conversation.matches(TOKEN).count(), 1);

    journey.ringer.stop();
    journey.relay.shutdown().await;
    journey.scratch.drop_database().await;
}
