// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The per-device inbound budget on `SEND`: tier 1 and tier 2.
//!
//! `send_budget_socket.rs` proves the budget is wired to the envelope path and
//! that a flooding device is answered on a real socket while its neighbour is
//! not. This file proves the budget itself is right, which is a different claim
//! and the one the wiring is only worth anything on top of: that the two limits
//! bind where they should, that a refusal charges nothing, that a window turns
//! over, that devices do not share an allowance, and that no sequence of charges
//! at any clock, including a clock that runs backwards, ever admits more than the
//! configured budget inside one window.
//!
//! The arithmetic is deliberately reachable without a database, a socket or a
//! relay: `SendBudget` takes a `now_ms` rather than reading a clock, which is what
//! `specs/backend/build/testing.md` requires of anything under test, and it is
//! why the window-boundary and backwards-clock cases below can be stated as facts
//! rather than as timing races.

use proptest::prelude::*;
use wealdrelay::frame::{ErrorClass, ErrorCode};
use wealdrelay::send_budget::{
    SendBudget, SendRefusal, DEFAULT_SEND_BYTES_PER_MINUTE, DEFAULT_SEND_FRAMES_PER_MINUTE,
    MAX_TRACKED_DEVICES, SEND_WINDOW_MS,
};

/// A round number well inside a window, so a test that charges a few frames does
/// not accidentally cross a boundary it did not mean to.
const NOW: u64 = 1_800_000_000_000;

fn device(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

// MARK: Tier 1, the two limits

#[tokio::test]
async fn frames_are_admitted_up_to_the_limit_and_refused_after_it() {
    let budget = SendBudget::new(3, 1_000_000);
    for _ in 0..3 {
        assert_eq!(budget.charge(&device(1), 10, NOW).await, Ok(()));
    }
    assert_eq!(
        budget.charge(&device(1), 10, NOW).await,
        Err(SendRefusal::FrameRate)
    );
}

#[tokio::test]
async fn bytes_are_admitted_up_to_the_limit_and_refused_after_it() {
    let budget = SendBudget::new(1_000, 100);
    assert_eq!(budget.charge(&device(1), 60, NOW).await, Ok(()));
    assert_eq!(budget.charge(&device(1), 40, NOW).await, Ok(()));
    // Exactly at the limit is admitted; the next byte is not.
    assert_eq!(
        budget.charge(&device(1), 1, NOW).await,
        Err(SendRefusal::ByteRate)
    );
}

/// The case the whole module exists for, stated as one test: a device writing
/// maximum-size envelopes meets the byte budget long before the frame budget.
///
/// This is the "1 MiB frames at line rate" objection. At the shipped defaults it
/// takes sixty-four of them, and the sixty-fifth is refused while the frame count
/// has barely moved.
#[tokio::test]
async fn maximum_size_frames_meet_the_byte_budget_first() {
    let budget = SendBudget::default();
    let mib = 1024 * 1024;
    for _ in 0..64 {
        assert_eq!(budget.charge(&device(1), mib, NOW).await, Ok(()));
    }
    assert_eq!(
        budget.charge(&device(1), mib, NOW).await,
        Err(SendRefusal::ByteRate)
    );
    let (frames, bytes) = budget.spent(&device(1), NOW).await;
    assert_eq!(frames, 64, "the frame budget is nowhere near met");
    assert_eq!(bytes, DEFAULT_SEND_BYTES_PER_MINUTE);
}

/// And the mirror of it: a device writing realistic records meets the frame
/// budget first, which is the limit whose refusal a legitimate client can reach.
///
/// The ordering is a design claim in `specs/backend/relay/wire.md` under "Sizing
/// the SEND budget", not an accident of two numbers, so it is asserted.
#[tokio::test]
async fn realistic_records_meet_the_frame_budget_first() {
    let budget = SendBudget::default();
    let record = 2 * 1024;
    for _ in 0..DEFAULT_SEND_FRAMES_PER_MINUTE {
        assert_eq!(budget.charge(&device(1), record, NOW).await, Ok(()));
    }
    assert_eq!(
        budget.charge(&device(1), record, NOW).await,
        Err(SendRefusal::FrameRate)
    );
    let (_, bytes) = budget.spent(&device(1), NOW).await;
    assert!(
        bytes < DEFAULT_SEND_BYTES_PER_MINUTE / 4,
        "a full window of realistic records is nowhere near the byte budget, was {bytes}"
    );
}

/// A refusal charges nothing at all.
///
/// The reason this is a test and not a comment: with a non-atomic charge, a
/// device refused on bytes would still have spent a frame of the count, so a peer
/// could exhaust the frame budget with frames that were never admitted, and the
/// budget would refuse traffic it had never carried.
#[tokio::test]
async fn a_refusal_charges_nothing() {
    let budget = SendBudget::new(10, 100);
    assert_eq!(budget.charge(&device(1), 100, NOW).await, Ok(()));
    let before = budget.spent(&device(1), NOW).await;
    for _ in 0..5 {
        assert_eq!(
            budget.charge(&device(1), 1, NOW).await,
            Err(SendRefusal::ByteRate)
        );
    }
    assert_eq!(
        budget.spent(&device(1), NOW).await,
        before,
        "five refusals moved a counter"
    );
}

/// Over both limits at once is reported as the frame limit, because that is the
/// one the client will meet again first.
#[tokio::test]
async fn over_both_limits_reports_the_frame_limit() {
    let budget = SendBudget::new(1, 10);
    assert_eq!(budget.charge(&device(1), 10, NOW).await, Ok(()));
    assert_eq!(
        budget.charge(&device(1), 1_000, NOW).await,
        Err(SendRefusal::FrameRate)
    );
}

// MARK: Tier 1, windows

#[tokio::test]
async fn the_next_window_is_a_fresh_allowance() {
    let budget = SendBudget::new(1, 1_000);
    assert_eq!(budget.charge(&device(1), 1, NOW).await, Ok(()));
    assert_eq!(
        budget.charge(&device(1), 1, NOW).await,
        Err(SendRefusal::FrameRate)
    );
    assert_eq!(
        budget.charge(&device(1), 1, NOW + SEND_WINDOW_MS).await,
        Ok(())
    );
}

/// Inside a window is one allowance, however the milliseconds fall.
#[tokio::test]
async fn the_whole_window_shares_one_allowance() {
    let budget = SendBudget::new(2, 1_000);
    let start = (NOW / SEND_WINDOW_MS) * SEND_WINDOW_MS;
    assert_eq!(budget.charge(&device(1), 1, start).await, Ok(()));
    assert_eq!(
        budget
            .charge(&device(1), 1, start + SEND_WINDOW_MS - 1)
            .await,
        Ok(())
    );
    assert_eq!(
        budget.charge(&device(1), 1, start + 1).await,
        Err(SendRefusal::FrameRate)
    );
}

/// A clock that steps backwards begins a new window rather than freezing the old
/// one.
///
/// NTP corrects a wall clock backwards routinely. The alternative reading, "not
/// enough time has passed", would answer no across such a step and hold a
/// device's counters wherever they were, so a one second correction would become
/// up to a minute of a workspace unable to write. That is a worse failure than
/// the allowance an attacker cannot cause, because a client cannot move the
/// relay's clock.
#[tokio::test]
async fn a_backwards_clock_begins_a_new_window() {
    let budget = SendBudget::new(1, 1_000);
    assert_eq!(budget.charge(&device(1), 1, NOW).await, Ok(()));
    assert_eq!(
        budget.charge(&device(1), 1, NOW).await,
        Err(SendRefusal::FrameRate)
    );
    assert_eq!(
        budget.charge(&device(1), 1, NOW - SEND_WINDOW_MS).await,
        Ok(())
    );
}

// MARK: Tier 1, whose allowance it is

/// Two devices do not share an allowance. The neighbour claim, at the unit level.
#[tokio::test]
async fn devices_do_not_share_an_allowance() {
    let budget = SendBudget::new(1, 1_000);
    assert_eq!(budget.charge(&device(1), 1, NOW).await, Ok(()));
    assert_eq!(
        budget.charge(&device(1), 1, NOW).await,
        Err(SendRefusal::FrameRate)
    );
    assert_eq!(budget.charge(&device(2), 1, NOW).await, Ok(()));
}

/// The sweep drops counters from windows that have turned over, and keeps live
/// ones.
///
/// The second half is the half that matters: a sweep that evicted a live counter
/// would hand a flooding device a fresh allowance for the price of filling a
/// hash map, which is the bound arriving as the bypass.
#[tokio::test]
async fn the_sweep_drops_stale_counters_and_keeps_live_ones() {
    let budget = SendBudget::new(1, 1_000);
    for seed in 0..=MAX_TRACKED_DEVICES {
        let key = (seed as u64).to_be_bytes().to_vec();
        assert_eq!(budget.charge(&key, 1, NOW).await, Ok(()));
    }
    assert!(budget.tracked().await > MAX_TRACKED_DEVICES);
    // One charge in the next window, which is the call that sweeps.
    let later = NOW + SEND_WINDOW_MS;
    assert_eq!(budget.charge(&device(200), 1, later).await, Ok(()));
    assert_eq!(
        budget.tracked().await,
        1,
        "every counter from the previous window should be gone"
    );

    // And now the half that must not happen: fill the map again inside one
    // window, and check that a device already at its limit in that same window is
    // still at its limit.
    let flooder = device(201);
    assert_eq!(budget.charge(&flooder, 1, later).await, Ok(()));
    for seed in 0..=MAX_TRACKED_DEVICES {
        let key = (seed as u64).to_be_bytes().to_vec();
        let _ = budget.charge(&key, 1, later).await;
    }
    assert_eq!(
        budget.charge(&flooder, 1, later).await,
        Err(SendRefusal::FrameRate),
        "the sweep handed a flooding device a fresh allowance"
    );
}

// MARK: Tier 1, what the refusal says on the wire

#[tokio::test]
async fn both_refusals_are_quota_rate_limited() {
    for refusal in [SendRefusal::FrameRate, SendRefusal::ByteRate] {
        assert_eq!(refusal.code(), ErrorCode::RateLimited);
        assert_eq!(
            refusal.code().class(),
            ErrorClass::Quota,
            "the class the client branches on"
        );
        assert!(
            refusal.code().class().is_retryable(),
            "a client must know to come back"
        );
    }
}

/// The interval is in `retry_after` and the limit is in `detail`, which is the
/// division `frame.rs` defines and the client reads. A test rather than a
/// comment, because swapping them would be invisible until a client waited the
/// wrong length of time.
#[tokio::test]
async fn the_refusal_carries_the_interval_and_the_limit() {
    let budget = SendBudget::new(7, 999);

    let frames = SendRefusal::FrameRate.to_frame_error(&budget);
    assert_eq!(frames.retry_after, Some((SEND_WINDOW_MS / 1_000) as u32));
    assert_eq!(frames.detail, Some(7u64.to_be_bytes().to_vec()));

    let bytes = SendRefusal::ByteRate.to_frame_error(&budget);
    assert_eq!(bytes.retry_after, Some((SEND_WINDOW_MS / 1_000) as u32));
    assert_eq!(
        bytes.detail,
        Some(999u64.to_be_bytes().to_vec()),
        "the byte refusal names the byte limit, not the frame one"
    );
}

/// The refusal survives a round trip on the wire, interval and limit intact.
#[tokio::test]
async fn the_refusal_round_trips_as_a_frame() {
    use wealdrelay::frame::Frame;
    let budget = SendBudget::default();
    for refusal in [SendRefusal::FrameRate, SendRefusal::ByteRate] {
        let frame = Frame::Error(refusal.to_frame_error(&budget));
        let decoded = Frame::decode(&frame.encode()).expect("a refusal decodes");
        assert_eq!(decoded, frame);
    }
}

// MARK: Tier 2, invariants over randomised charges

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    }
}

/// One charge, as a property test generates it: a device, a size, and a moment.
#[derive(Debug, Clone)]
struct Charge {
    device: u8,
    bytes: u64,
    now_ms: u64,
}

fn charges() -> impl Strategy<Value = Vec<Charge>> {
    prop::collection::vec(
        (0u8..4, 0u64..4_096, any::<u64>()).prop_map(|(device, bytes, now_ms)| Charge {
            device,
            bytes,
            now_ms,
        }),
        1..200,
    )
}

/// Drive one async body to completion on a current-thread runtime.
///
/// `proptest!` bodies are synchronous, and `#[tokio::test]` cannot be applied to
/// one, so each case builds its own runtime. That is cheap for a current-thread
/// runtime with no I/O driver, and it keeps every case independent: nothing here
/// shares a budget, a task or a clock with the case before it.
fn run<F>(body: F) -> Result<(), TestCaseError>
where
    F: std::future::Future<Output = Result<(), TestCaseError>>,
{
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime")
        .block_on(body)
}

proptest! {
    #![proptest_config(config())]

    /// The invariant the budget exists to hold: whatever sequence of charges
    /// arrives, at whatever moments, no device is ever admitted past either
    /// limit inside one window.
    ///
    /// Stated over the accounting rather than over the return values, because a
    /// limiter that refused correctly but counted wrongly would pass a test that
    /// only read its answers and would then refuse a device that had spent
    /// nothing.
    #[test]
    fn no_window_ever_exceeds_either_limit(charges in charges()) {
        run(async move {
            let frames_limit = 5u64;
            let bytes_limit = 4_096u64;
            let budget = SendBudget::new(frames_limit, bytes_limit);
            for charge in &charges {
                let device = vec![charge.device; 32];
                let _ = budget.charge(&device, charge.bytes, charge.now_ms).await;
                let (frames, bytes) = budget.spent(&device, charge.now_ms).await;
                prop_assert!(frames <= frames_limit, "{frames} frames admitted");
                prop_assert!(bytes <= bytes_limit, "{bytes} bytes admitted");
            }
            Ok(())
        })?;
    }
}

proptest! {
    #![proptest_config(config())]

    /// Admitting a charge always moves both counters by exactly what was charged,
    /// and refusing one never moves either.
    ///
    /// This is the atomicity claim generalised: `a_refusal_charges_nothing`
    /// proves it for one hand-picked sequence, and this proves there is no
    /// sequence for which it fails.
    #[test]
    fn a_charge_is_all_or_nothing(charges in charges()) {
        run(async move {
            let budget = SendBudget::new(5, 4_096);
            for charge in &charges {
                let device = vec![charge.device; 32];
                let before = budget.spent(&device, charge.now_ms).await;
                let outcome = budget.charge(&device, charge.bytes, charge.now_ms).await;
                let after = budget.spent(&device, charge.now_ms).await;
                match outcome {
                    Ok(()) => {
                        prop_assert_eq!(after.0, before.0 + 1);
                        prop_assert_eq!(after.1, before.1 + charge.bytes);
                    }
                    Err(_) => prop_assert_eq!(after, before),
                }
            }
            Ok(())
        })?;
    }
}

proptest! {
    #![proptest_config(config())]

    /// One device's traffic never changes what another device is allowed.
    ///
    /// The neighbour claim, over arbitrary interleavings rather than the one the
    /// socket suite drives. A limiter that keyed its map wrongly, or whose sweep
    /// was too eager, would fail here long before anybody noticed on a relay.
    #[test]
    fn one_device_cannot_spend_anothers_allowance(charges in charges(), noise in charges()) {
        run(async move {
            let alone = SendBudget::new(5, 4_096);
            let crowded = SendBudget::new(5, 4_096);
            let watched = vec![0xABu8; 32];
            for (charge, other) in charges.iter().zip(noise.iter()) {
                let quiet = alone.charge(&watched, charge.bytes, charge.now_ms).await;
                // The same charge against a budget that is also carrying a second
                // device's traffic at the same moments.
                let neighbour = vec![other.device; 32];
                let _ = crowded.charge(&neighbour, other.bytes, charge.now_ms).await;
                let busy = crowded.charge(&watched, charge.bytes, charge.now_ms).await;
                prop_assert_eq!(quiet, busy);
            }
            Ok(())
        })?;
    }
}

proptest! {
    #![proptest_config(config())]

    /// No charge, at any clock value, ever panics or wraps.
    ///
    /// `now_ms` is generated across the whole `u64` range on purpose: it stands in
    /// for a clock that has been set to anything at all, including values that
    /// make the window index overflow arithmetic a careless implementation would
    /// have written.
    #[test]
    fn any_clock_and_any_size_is_answered_rather_than_panicking(
        bytes in any::<u64>(),
        now_ms in any::<u64>(),
    ) {
        run(async move {
            let budget = SendBudget::default();
            // Whatever the answer, there is one, and the counters stay inside the
            // limits afterwards.
            let _ = budget.charge(&[7u8; 32], bytes, now_ms).await;
            let (frames, spent) = budget.spent(&[7u8; 32], now_ms).await;
            prop_assert!(frames <= DEFAULT_SEND_FRAMES_PER_MINUTE);
            prop_assert!(spent <= DEFAULT_SEND_BYTES_PER_MINUTE);
            Ok(())
        })?;
    }
}
