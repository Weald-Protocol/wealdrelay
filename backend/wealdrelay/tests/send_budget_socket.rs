// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The `SEND` budget over a real socket, against a real relay and real Postgres.
//!
//! `send_budget_unit.rs` proves the arithmetic. What it cannot prove is that the
//! arithmetic is wired to the envelope path at all, and the wiring is the whole
//! of the defect this closes: before it, `Work::Accept` ran a decode, an
//! authorization read and a Postgres transaction for every `SEND` a connection
//! cared to write, so an admitted device could drive the database at line rate.
//! A budget that exists in a module and is never charged is exactly the
//! protection somebody relies on and does not have.
//!
//! Four claims, and each is a sentence from `specs/backend/relay/wire.md` or
//! `specs/backend/relay/operations.md` turned into a socket exchange.
//!
//! 1. A flooding device is refused, with `quota/rate_limited`, an interval and
//!    the limit it met.
//! 2. A second device on the same relay, in the same group, in the same window,
//!    is completely unaffected. This is what "per device" means, and it is the
//!    claim a per-connection budget would fail.
//! 3. The refused connection stays up and keeps working, including for reads.
//!    `operations.md` is explicit that this refusal is not the deadline close.
//! 4. The negative: an ordinary cold-start sync of a large workspace, at the
//!    shipped defaults, is never refused. A budget a legitimate cold start trips
//!    is a bug that presents as a network fault, so it is proved not to.
//!
//! The dependencies are the local harness's, and if they are not there these
//! tests fail rather than skip, for the reason `specs/backend/build/testing.md`
//! gives: a skipped integration proof that reports success is the failure mode
//! the programme exists to prevent. Nothing here is mocked, and in particular the
//! budget is not: `Running::start` builds it from the resolved configuration
//! exactly as the shipped binary does.

mod support;

use wealdrelay::config::keys;
use wealdrelay::frame::{ErrorClass, ErrorCode, Frame};
use wealdrelay::health::Clock;
use wealdrelay::send_budget::{DEFAULT_SEND_FRAMES_PER_MINUTE, SEND_WINDOW_MS};

use support::{
    config_with, default_device, envelope_for, make_group, other_device, Client, Running, Scratch,
};

/// A fixed clock, so every frame a test sends lands in one window and the suite
/// is a statement about the budget rather than about how fast the machine is.
const CLOCK: u64 = 1_700_000_000_000;

/// The allowance the refusal tests run against. Small enough that meeting it is a
/// handful of frames rather than six thousand, which is the one liberty taken
/// here: the numbers are configuration, so a suite that used the shipped default
/// would be a suite nobody runs. Everything else is the shipped path.
const FEW_FRAMES: u64 = 5;

/// Read one frame and require it to be a `SendAck`.
async fn expect_ack(client: &mut Client, expected: &[u8]) -> u64 {
    match client.recv_frame().await {
        Frame::SendAck { hash, seq } => {
            assert_eq!(hash, expected, "the ack names another envelope");
            seq
        }
        other => panic!("expected a SendAck, got {other:?}"),
    }
}

// MARK: The flood, and the neighbour who does not notice it

/// A device over its frame allowance is refused; a second device is not; and the
/// refused socket is still a working socket afterwards.
#[tokio::test]
async fn a_flooding_device_is_refused_while_its_neighbour_is_unaffected() {
    let scratch = Scratch::new("send-budget-flood").await;
    let blobs = tempfile::tempdir().expect("a blob directory");
    let relay = Running::start(
        config_with(
            &scratch,
            blobs.path(),
            [(keys::SEND_FRAMES_PER_MINUTE, FEW_FRAMES.to_string())],
        ),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x51).await;

    let mut ada = Client::connect(relay.address).await;
    let mut bo = Client::connect(relay.address).await;
    ada.handshake_as(&default_device(), vec![group.clone()], CLOCK)
        .await;
    bo.handshake_as(&other_device(), vec![group.clone()], CLOCK)
        .await;

    // Ada spends her whole allowance, and every frame of it is accepted. The
    // budget must not refuse anything inside the limit, which is the half of a
    // rate limiter that is easy to get wrong in the safe-looking direction.
    let mut transcript = String::new();
    transcript.push_str("# The SEND budget over a socket\n\n");
    transcript.push_str(&format!(
        "relay: WEALD_RELAY_SEND_FRAMES_PER_MINUTE={FEW_FRAMES}, bytes at the default\n"
    ));
    transcript.push_str("ada and bo are two devices in one access set, one group, one window\n\n");
    for index in 0..FEW_FRAMES {
        let envelope = envelope_for(&group, &[index as u8; 32]);
        ada.send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
        let seq = expect_ack(&mut ada, &envelope.hash).await;
        transcript.push_str(&format!(
            "ada  SEND #{}  -> SEND_ACK seq={seq}\n",
            index + 1
        ));
    }

    // One more, and it is refused rather than served.
    let over = envelope_for(&group, b"one too many");
    ada.send_frame(&Frame::Send {
        envelope: over.encode(),
    })
    .await;
    let error = match ada.recv_frame().await {
        Frame::Error(error) => error,
        other => panic!("expected the budget to refuse, got {other:?}"),
    };
    assert_eq!(error.code, ErrorCode::RateLimited);
    assert_eq!(
        error.code.class(),
        ErrorClass::Quota,
        "the class a client branches on"
    );
    assert_eq!(
        error.retry_after,
        Some((SEND_WINDOW_MS / 1_000) as u32),
        "the interval belongs in retry_after"
    );
    assert_eq!(
        error.detail,
        Some(FEW_FRAMES.to_be_bytes().to_vec()),
        "the refusal names the limit that was met"
    );
    transcript.push_str(&format!(
        "ada  SEND #{}  -> ERROR {}/{} retry_after={}s detail={FEW_FRAMES}\n",
        FEW_FRAMES + 1,
        error.code.class().as_str(),
        error.code.as_str(),
        error.retry_after.unwrap_or_default()
    ));

    // The envelope was refused before the transaction, so it is not in the log.
    // Without this the suite would pass against a relay that charged the budget
    // after writing, which is the version that protects nothing.
    let pool = relay
        .state
        .database
        .as_ref()
        .expect("a database")
        .pool()
        .clone();
    let stored: i64 =
        sqlx::query_scalar("select count(*) from relay_envelope where group_id = $1 and hash = $2")
            .bind(&group)
            .bind(&over.hash)
            .fetch_one(&pool)
            .await
            .expect("count the refused envelope");
    assert_eq!(stored, 0, "a refused envelope reached the database");
    transcript.push_str("db   the refused envelope is absent: charged before the transaction\n");

    // Bo, in the same group, in the same window, on the same relay, is untouched.
    // A per-connection or per-group budget would fail here, and so would a
    // per-process one.
    let bos = envelope_for(&group, b"bo is fine");
    bo.send_frame(&Frame::Send {
        envelope: bos.encode(),
    })
    .await;
    let bo_seq = expect_ack(&mut bo, &bos.hash).await;
    transcript.push_str(&format!(
        "bo   SEND #1  -> SEND_ACK seq={bo_seq}  (a second device is unaffected)\n"
    ));

    // And Ada's socket is still a socket. `operations.md` requires the refusal to
    // leave reads working, because the limit was only ever about her writes.
    ada.send_frame(&Frame::Sub {
        group: group.clone(),
        from_seq: 0,
    })
    .await;
    match ada.recv_frame().await {
        Frame::SubAck { group: g, head_seq } => {
            assert_eq!(g, group);
            assert!(head_seq >= FEW_FRAMES, "the accepted writes are in the log");
            transcript.push_str(&format!(
                "ada  SUB       -> SUB_ACK head_seq={head_seq}  (refused, not disconnected)\n"
            ));
        }
        other => panic!("expected a SubAck on a socket that should still be up, got {other:?}"),
    }

    support::record_evidence("alpha-03", "send-budget-transcript.txt", &transcript);
    relay.shutdown().await;
}

/// The byte half, over a socket. Same shape, and it is a separate test because a
/// single budget that only ever bound on frames would pass the one above while
/// leaving the 1 MiB frame at line rate exactly where it was.
#[tokio::test]
async fn a_device_over_the_byte_allowance_is_refused_naming_the_byte_limit() {
    const FEW_BYTES: u64 = 4_096;
    let scratch = Scratch::new("send-budget-bytes").await;
    let blobs = tempfile::tempdir().expect("a blob directory");
    let relay = Running::start(
        config_with(
            &scratch,
            blobs.path(),
            [(keys::SEND_BYTES_PER_MINUTE, FEW_BYTES.to_string())],
        ),
        Clock::Fixed(CLOCK),
    )
    .await;
    let group = make_group(&relay.state, 0x52).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake_as(&default_device(), vec![group.clone()], CLOCK)
        .await;

    // Frames far below the frame allowance, so whatever refuses is the byte
    // budget and nothing else.
    let mut refused = None;
    for index in 0..8u8 {
        let envelope = envelope_for(&group, &vec![index; 1_024]);
        ada.send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
        match ada.recv_frame().await {
            Frame::SendAck { .. } => {}
            Frame::Error(error) => {
                refused = Some((index, error));
                break;
            }
            other => panic!("expected an ack or a refusal, got {other:?}"),
        }
    }
    let (at, error) = refused.expect("eight kibibytes of envelopes against a four kibibyte budget");
    assert!(at > 0, "the first envelope of a window must be admitted");
    assert_eq!(error.code, ErrorCode::RateLimited);
    assert_eq!(
        error.detail,
        Some(FEW_BYTES.to_be_bytes().to_vec()),
        "the byte refusal names the byte limit, not the frame one"
    );
    relay.shutdown().await;
}

// MARK: The negative. A real cold start is never refused.

/// An ordinary cold-start sync of a large workspace, at the shipped defaults, is
/// answered entirely with acknowledgements.
///
/// The behaviour this is sized against is written down in
/// `specs/backend/relay/wire.md` under "Sizing the `SEND` budget", and it is the
/// reason the default is not the `600` the Limits table used to carry.
/// `RelayConnection.drain` writes the whole outbox in one pass, awaiting the
/// write and not the acknowledgement, and `offerUnnumbered` fills that outbox
/// once per group per session with every record the relay has never numbered. So
/// the traffic is a burst, and this test is a burst: the frames go out
/// pipelined, in batches, exactly as a client that is not waiting for anything
/// produces them.
///
/// The count is a working proxy for a large workspace's session backlog rather
/// than the whole 40,000-envelope fixture, because a thousand real Postgres
/// transactions is already a slow test and the sizing headroom above it is
/// asserted in `send_budget_unit.rs` against the arithmetic, where six thousand
/// costs nothing. What this test adds is that the number is enforced by a running
/// relay rather than by a constant.
#[tokio::test]
async fn a_cold_start_sync_of_a_large_workspace_is_never_refused() {
    /// A record a workspace actually produces: a couple of kilobytes, not the
    /// 1 MiB ceiling.
    const RECORD_BYTES: usize = 2 * 1024;
    /// The backlog. Pipelined in batches so the client is never waiting on a
    /// round trip it did not have to wait for, and so neither side's queue is
    /// asked to hold the whole burst at once.
    const BACKLOG: usize = 1_000;
    const BATCH: usize = 100;

    let scratch = Scratch::new("send-budget-cold-start").await;
    let blobs = tempfile::tempdir().expect("a blob directory");
    // The shipped defaults, deliberately: this test is about the number an
    // operator gets without choosing one.
    let relay = Running::start(config_with(&scratch, blobs.path(), []), Clock::Fixed(CLOCK)).await;
    assert_eq!(
        relay.state.send_budget.frames_per_window, DEFAULT_SEND_FRAMES_PER_MINUTE,
        "the shipped default is what is under test"
    );
    let group = make_group(&relay.state, 0x53).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake_as(&default_device(), vec![group.clone()], CLOCK)
        .await;

    let mut acknowledged = 0usize;
    let mut offered = 0usize;
    while offered < BACKLOG {
        let count = BATCH.min(BACKLOG - offered);
        let mut hashes = Vec::with_capacity(count);
        for index in 0..count {
            let body = body_for(offered + index, RECORD_BYTES);
            let envelope = envelope_for(&group, &body);
            hashes.push(envelope.hash.clone());
            ada.send_frame(&Frame::Send {
                envelope: envelope.encode(),
            })
            .await;
        }
        for hash in hashes {
            match ada.recv_frame().await {
                Frame::SendAck { hash: acked, .. } => {
                    assert_eq!(
                        acked, hash,
                        "acks come back in the order the sends went out"
                    );
                    acknowledged += 1;
                }
                Frame::Error(error) => panic!(
                    "a normal cold start was refused after {acknowledged} envelopes: {}/{}",
                    error.code.class().as_str(),
                    error.code.as_str()
                ),
                other => panic!("expected a SendAck, got {other:?}"),
            }
        }
        offered += count;
    }
    assert_eq!(acknowledged, BACKLOG);

    // And the budget agrees it carried the whole burst, with room left. Asserted
    // rather than inferred from the absence of an error, so that a budget which
    // had silently stopped charging would fail here instead of passing.
    let device = default_device().verifying_key().to_bytes().to_vec();
    let (frames, bytes) = relay.state.send_budget.spent(&device, CLOCK).await;
    assert_eq!(frames, BACKLOG as u64, "every send was charged");
    assert!(frames < relay.state.send_budget.frames_per_window);
    assert!(bytes < relay.state.send_budget.bytes_per_window);

    let headroom = relay.state.send_budget.frames_per_window - frames;
    support::record_evidence(
        "alpha-03",
        "cold-start-not-refused.txt",
        &format!(
            "A cold-start sync of a large workspace, at the shipped defaults.\n\n\
             frames offered      {BACKLOG}\n\
             frames acknowledged {acknowledged}\n\
             frames refused      0\n\
             record size         {RECORD_BYTES} bytes\n\
             pipelined in        batches of {BATCH}, no wait between sends\n\n\
             charged against the budget: {frames} frames, {bytes} bytes\n\
             budget:                     {} frames, {} bytes per minute\n\
             headroom:                   {headroom} frames in the same window\n",
            relay.state.send_budget.frames_per_window, relay.state.send_budget.bytes_per_window,
        ),
    );
    relay.shutdown().await;
}

/// A distinct body per record, so every envelope has a distinct content hash and
/// none of them is answered as a duplicate. A cold start offers distinct records;
/// a test that accidentally offered one record a thousand times would be proving
/// the deduplication path instead.
fn body_for(index: usize, len: usize) -> Vec<u8> {
    let mut body = index.to_be_bytes().to_vec();
    body.resize(len, 0x5a);
    body
}

// MARK: The recovery. The window rolls and the device publishes again.

/// A device refused by the frame budget publishes again once the window turns
/// over, on the same socket, with no reconnection.
///
/// WEALD-L924. The tests above pin the refusal; none of them pinned what happens
/// next, and what a live 0.1.42 cell was observed doing after a burst was
/// `messageAfter=no`: both ends reported `connected=yes` and the workspace could
/// not publish again. "Refused with `quota/rate_limited` on a socket that stays
/// up" (`wire.md:929`) is two promises, and only the first of them had a proof.
///
/// The clock is manual rather than fixed, so the window turning over is an
/// instruction rather than a sleep: a test that waited a real minute for a real
/// window would be a test nobody runs.
#[tokio::test]
async fn a_refused_device_publishes_again_once_the_window_rolls() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    let scratch = Scratch::new("send-budget-recovery").await;
    let blobs = tempfile::tempdir().expect("a blob directory");
    let clock = Arc::new(AtomicU64::new(CLOCK));
    let relay = Running::start(
        config_with(
            &scratch,
            blobs.path(),
            [(keys::SEND_FRAMES_PER_MINUTE, FEW_FRAMES.to_string())],
        ),
        Clock::Manual(Arc::clone(&clock)),
    )
    .await;
    let group = make_group(&relay.state, 0x53).await;

    let mut ada = Client::connect(relay.address).await;
    ada.handshake_as(&default_device(), vec![group.clone()], CLOCK)
        .await;

    for index in 0..FEW_FRAMES {
        let envelope = envelope_for(&group, &[index as u8; 32]);
        ada.send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
        expect_ack(&mut ada, &envelope.hash).await;
    }

    // The refusal, and the code a client branches on. Pinned here as well as
    // above, because this test is the one that says what the code is worth: a
    // client told `quota/rate_limited` waits `retry_after` and tries again, and
    // the assertion below is that doing so works.
    let over = envelope_for(&group, b"one too many");
    ada.send_frame(&Frame::Send {
        envelope: over.encode(),
    })
    .await;
    let error = match ada.recv_frame().await {
        Frame::Error(error) => error,
        other => panic!("expected the budget to refuse, got {other:?}"),
    };
    assert_eq!(error.code, ErrorCode::RateLimited);
    assert_eq!(error.code.class(), ErrorClass::Quota);
    let wait = error.retry_after.expect("the refusal names an interval");

    // Exactly the interval the relay named, and not a millisecond more: a
    // recovery that needed longer than the wait it advertised would be the same
    // defect wearing a smaller number.
    clock.fetch_add(u64::from(wait) * 1_000, Ordering::Relaxed);

    let after = envelope_for(&group, b"after the window rolled");
    ada.send_frame(&Frame::Send {
        envelope: after.encode(),
    })
    .await;
    let seq = expect_ack(&mut ada, &after.hash).await;
    assert!(seq > 0, "the recovered write is in the log");

    // And it is durable, rather than merely acknowledged.
    let pool = relay
        .state
        .database
        .as_ref()
        .expect("a database")
        .pool()
        .clone();
    let stored: i64 =
        sqlx::query_scalar("select count(*) from relay_envelope where group_id = $1 and hash = $2")
            .bind(&group)
            .bind(&after.hash)
            .fetch_one(&pool)
            .await
            .expect("count the recovered envelope");
    assert_eq!(stored, 1, "the write after the window is not in the log");

    relay.shutdown().await;
}
