// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! One direct message wakes the other person's phone, and only theirs.
//!
//! `specs/direct-messages.md` puts a dm in its own group, derived from the two
//! handles, carrying ordinary `chatEntry` envelopes. That derivation is the client's
//! and the relay never learns it: to this crate a dm group is a group id like any
//! other. What is *not* like any other group is who declared it. A dm group is
//! created by whoever writes into it first (`access::store::ensure_groups` from the
//! opening), so the recipient's phone has typically never named it, is not subscribed
//! to it, and in the first-message case has not yet joined the MLS group at all.
//!
//! So the property worth a suite of its own is that the wake does not depend on any
//! of that. Membership for the wake path is the workspace's newest access set
//! (`push::store::wakeable_for_group`), which the recipient is in from enrolment. A
//! relay that had keyed wakes on the subscriber list instead would pass every test in
//! `push_adversarial.rs` and silently never ring a phone for the first direct message
//! anybody sent it, which is the case a person reports as "push is broken".

mod support;

use wealdrelay::frame::{Frame, WakeBody};
use wealdrelay::health::Clock;
use wealdrelay::push::ALL_CATEGORIES;

use support::{
    config_for_push, entry_hash_of, make_group, other_device, wake_expiry, wake_handle, Client,
    RecordingRinger, Running, Scratch,
};

const CLOCK: u64 = 1_700_000_000_000;
const WORKSPACE: &str = "ws-step4";

#[tokio::test(flavor = "multi_thread")]
async fn a_direct_message_wakes_the_peer_who_never_named_the_group() {
    let scratch = Scratch::new("push_direct_message").await;
    let blobs = tempfile::tempdir().unwrap();
    let ringer = RecordingRinger::accepting().await;
    let relay = Running::start(
        config_for_push(&scratch, blobs.path(), &ringer.url(), 0),
        Clock::Fixed(CLOCK),
    )
    .await;
    // The workspace root group, which is the only group Bo's phone ever declares, and
    // the dm group, which only Ada names.
    let root = make_group(&relay.state, 0x50).await;
    let dm = make_group(&relay.state, 0x51).await;
    let pool = relay.state.database.as_ref().unwrap().pool();
    let bo_entry = entry_hash_of(pool, WORKSPACE, &other_device()).await;

    // Bo's phone registers over the wire, exactly as `CompanionPushWiring` does on a
    // live session, and then goes away. Registered against the workspace and never
    // against a group: there is no field on `WAKE` that could hold one.
    let mut bo = Client::connect(relay.address).await;
    bo.handshake_as(&other_device(), vec![root.clone()], CLOCK)
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
    support::wait_until_disconnected(&relay.state, &bo_entry).await;

    let worker = wealdrelay::push::spawn(&relay.state).expect("a worker");

    // Ada opens the conversation and writes the first line into it.
    let mut ada = Client::connect(relay.address).await;
    ada.handshake(vec![root, dm.clone()], CLOCK).await;
    let envelope = support::envelope_for(&dm, b"a direct message");
    ada.send_frame(&Frame::Send {
        envelope: envelope.encode(),
    })
    .await;
    assert!(matches!(ada.recv_frame().await, Frame::SendAck { .. }));

    let seen = ringer.wait_for(1).await;
    assert_eq!(seen.len(), 1, "one sleeping peer, one wake");
    let bo_hex: String = wake_handle(0x5B)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert!(
        seen[0].contains(&bo_hex),
        "the wake did not name the peer's handle"
    );
    // The category a phone renders as a message rather than as a ring, and the whole
    // body: no group, no sequence, no size, no sender.
    assert!(seen[0].contains("\"category\":\"message\""));
    let dm_hex: String = dm.iter().map(|byte| format!("{byte:02x}")).collect();
    assert!(
        !seen[0].contains(&dm_hex),
        "the dm group id reached the ringer"
    );

    worker.abort();
    ringer.stop();
    relay.shutdown().await;
    scratch.drop_database().await;
}
