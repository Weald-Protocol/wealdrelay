// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Tier 2 for the call path: invariants over randomised input, per
//! `specs/backend/build/testing.md`.
//!
//! `calls_unit.rs` states the individual rules and each of its tests names one.
//! What it cannot state is what holds across an arbitrary sequence of them, and
//! that is the whole subject here. The two pieces of state on the media path, the
//! per-connection ``MediaBudget`` and the process-wide ``CallRegistry``, are both
//! mutable, both driven entirely by a peer, and both consulted fifty times a
//! second per stream. A rule that holds for one frame and fails for the ten
//! thousandth is a rule that fails in production and nowhere else.
//!
//! Three families here, and each is a claim an operator would make out loud.
//!
//! 1. **The budget is total.** No sequence of frames, widths, stream ids or clock
//!    readings panics it, and none makes its own memory grow past
//!    ``MAX_TRACKED_STREAMS``. It is a peer that chooses every one of those
//!    inputs.
//! 2. **The budget is a ceiling on egress.** Over any run, accepted frames per
//!    stream and accepted bytes per connection stay under the stated rate, with
//!    the one window of slack a fixed window has by construction. This is the
//!    number a relay is sized against.
//! 3. **The registry is exactly its model.** Against a straightforward map of
//!    what should be open, a randomised interleaving of join, leave, forget and
//!    route agrees on every call, every participant and every refusal, and the
//!    structural invariants (never past the instance ceiling, never past the
//!    participant cap, never an empty call left behind, never a frame to its own
//!    sender) hold after every single step.
//!
//! The clock deserves its own line, because it is where this file found a
//! defect. `health::Clock::System` is `SystemTime`, a wall clock, so `now_ms`
//! moves backwards whenever NTP corrects the machine. Every window here is
//! therefore driven with backwards steps mixed into the forward ones, and the
//! property is that a correction costs a well-behaved connection nothing.

use std::collections::HashMap;

use proptest::prelude::*;
use wealdrelay::calls::{
    CallKind, CallRegistry, JoinRefusal, MediaBudget, MediaRefusal, CALL_ID_BYTES,
    MAX_PARTICIPANTS_PER_CALL, MAX_TRACKED_STREAMS, MEDIA_BYTES_PER_MINUTE,
    MEDIA_FRAMES_PER_STREAM_PER_SECOND, MEDIA_STREAM_WINDOW_MS, STREAM_BYTES,
};
use wealdrelay::frame::{ErrorCode, Frame};
use wealdrelay::hub::ConnectionId;
use wealdrelay::ws::{outbound_channel, Outbound, OutboundReceiver, OutboundSender};

/// A wall-clock reading in the range a running relay actually holds, so the
/// arithmetic under test is exercised at the magnitude it runs at rather than
/// near zero, where an underflow bug hides behind a saturating subtraction.
const NOW: u64 = 1_800_000_000_000;

/// The byte window's width. Not exported by the crate because nothing outside it
/// needs to name it; restated here so the property can reason about it, and
/// pinned by ``the_two_windows_are_the_widths_the_limits_table_states`` below so
/// this copy cannot drift from the one being tested.
const BYTE_WINDOW_MS: u64 = 60_000;

fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

// MARK: The budget

/// One step of a randomised media stream: how far the clock moved, which call and
/// stream the frame named, and how big it was.
///
/// The clock delta is signed, which is the point. A relay reads a wall clock, and
/// a wall clock moves backwards.
#[derive(Debug, Clone, Copy)]
struct Step {
    delta_ms: i64,
    call: u8,
    stream: u8,
    bytes: usize,
}

fn steps() -> impl Strategy<Value = Vec<Step>> {
    prop::collection::vec(
        (
            // Forward mostly, because that is what a clock does, with backwards
            // steps frequent enough that a run of a few hundred contains many.
            prop_oneof![
                7 => 0i64..40,
                2 => 0i64..2_000,
                1 => -5_000i64..0,
            ],
            // A small id space on purpose: collisions between calls and streams
            // are where the budget's keying is either right or wrong, and a wide
            // space would make them vanishingly rare.
            0u8..6,
            0u8..40,
            // Zero is legal (a frame that is all header), and the ceiling is
            // exercised by `calls_unit`; what matters here is the mix.
            0usize..1_600,
        )
            .prop_map(|(delta_ms, call, stream, bytes)| Step {
                delta_ms,
                call,
                stream,
                bytes,
            }),
        1..400,
    )
}

fn call_of(seed: u8) -> [u8; CALL_ID_BYTES] {
    [seed; CALL_ID_BYTES]
}

fn stream_of(seed: u8) -> [u8; STREAM_BYTES] {
    [seed, 0, 0, seed]
}

proptest! {
    #![proptest_config(config())]

    /// Charging is total, and the budget's own memory is bounded whatever a peer
    /// does to it.
    ///
    /// Both halves matter and they are different claims. Totality says no input
    /// panics: the widths are attacker-chosen and the arithmetic is saturating, so
    /// this is the property that an overflow was not merely made unlikely.
    /// Boundedness says the table cannot be grown: a client rotating stream ids at
    /// fifty a second for an hour is a hundred and eighty thousand ids, and a
    /// relay that remembered a window for each of them would have been handed an
    /// allocator by the peer.
    #[test]
    fn the_budget_is_total_and_its_table_is_bounded(steps in steps()) {
        let mut budget = MediaBudget::default();
        let mut clock = NOW;
        for step in steps {
            clock = clock.saturating_add_signed(step.delta_ms);
            // The result is deliberately ignored: what is asserted is that there
            // is one, for every input, rather than a panic or a hang.
            let _ = budget.charge(clock, &call_of(step.call), &stream_of(step.stream), step.bytes);
            prop_assert!(
                budget.tracked_streams() <= MAX_TRACKED_STREAMS,
                "the stream table grew to {} against a ceiling of {MAX_TRACKED_STREAMS}",
                budget.tracked_streams()
            );
        }
    }

    /// A refused frame costs nothing.
    ///
    /// The ordering inside `charge` is byte budget, then stream budget, then
    /// commit, and the commit has to be the last thing: a frame refused for its
    /// rate that still spent its bytes would let a flooder exhaust a connection's
    /// minute with frames the relay never carried, which is a peer turning a rate
    /// limit into a denial of service against itself and, on a shared budget,
    /// against its own call.
    ///
    /// Asserted by keeping the clock still, so no window can roll over and hide the
    /// difference, and comparing what the budget accepted against what a plain sum
    /// of the accepted frames says it should have.
    #[test]
    fn a_refused_frame_spends_nothing(
        sizes in prop::collection::vec(1usize..1_500, 1..400),
        which in prop::collection::vec(0u8..3, 1..400),
    ) {
        let mut budget = MediaBudget::default();
        let mut accepted_bytes = 0u64;
        let mut accepted_frames: HashMap<u8, u32> = HashMap::new();
        for (index, bytes) in sizes.iter().enumerate() {
            let stream = which[index % which.len()];
            match budget.charge(NOW, &call_of(1), &stream_of(stream), *bytes) {
                Ok(()) => {
                    accepted_bytes += *bytes as u64;
                    *accepted_frames.entry(stream).or_default() += 1;
                }
                // A refusal is a refusal: nothing was carried, so nothing may have
                // been charged. The next accepted frame proves it, because the
                // running total below is computed only from acceptances.
                Err(MediaRefusal::ByteRate) => {
                    prop_assert!(accepted_bytes + *bytes as u64 > MEDIA_BYTES_PER_MINUTE);
                }
                Err(MediaRefusal::StreamRate) => {
                    prop_assert_eq!(
                        accepted_frames.get(&stream).copied().unwrap_or_default(),
                        MEDIA_FRAMES_PER_STREAM_PER_SECOND
                    );
                }
                Err(MediaRefusal::TooManyStreams) => {
                    // Unreachable with three stream ids, and asserted rather than
                    // ignored so that a keying bug that invented streams would be
                    // caught here rather than passing quietly.
                    prop_assert!(false, "three stream ids cannot exhaust {MAX_TRACKED_STREAMS}");
                }
            }
            prop_assert!(accepted_bytes <= MEDIA_BYTES_PER_MINUTE);
        }
    }

    /// The budget is a ceiling on egress, over a whole run rather than over one
    /// window.
    ///
    /// This is the number an instance is sized against, so it is asserted as an
    /// operator would state it: across a run of any length, one stream cannot have
    /// been carried faster than its rate and one connection cannot have been
    /// carried faster than its byte rate, allowing exactly the one window of slack
    /// a fixed window has by construction and no more. A leak that only appeared
    /// after the tenth window would be invisible to a single-window test and is
    /// visible here.
    ///
    /// The clock is monotone in this property on purpose. Backwards steps are the
    /// subject of the next one, and mixing them in here would make the bound above
    /// unstatable rather than merely harder to state.
    #[test]
    fn accepted_traffic_stays_under_the_stated_rate(steps in steps()) {
        let mut budget = MediaBudget::default();
        let mut clock = NOW;
        let mut accepted_bytes = 0u64;
        let mut per_stream: HashMap<(u8, u8), u64> = HashMap::new();
        for step in &steps {
            // Forward only, and never zero, so elapsed time is well defined.
            clock = clock.saturating_add(step.delta_ms.unsigned_abs());
            if budget
                .charge(clock, &call_of(step.call), &stream_of(step.stream), step.bytes)
                .is_ok()
            {
                accepted_bytes += step.bytes as u64;
                *per_stream.entry((step.call, step.stream)).or_default() += 1;
            }
        }
        let elapsed = clock - NOW;
        // One extra window on each bound, which is the fixed window's slack: a
        // stream may spend the tail of one window and the head of the next.
        let byte_ceiling =
            MEDIA_BYTES_PER_MINUTE.saturating_mul(elapsed / BYTE_WINDOW_MS + 2);
        prop_assert!(
            accepted_bytes <= byte_ceiling,
            "{accepted_bytes} bytes carried in {elapsed} ms, over a ceiling of {byte_ceiling}"
        );
        let frame_ceiling = u64::from(MEDIA_FRAMES_PER_STREAM_PER_SECOND)
            .saturating_mul(elapsed / MEDIA_STREAM_WINDOW_MS + 2);
        for ((call, stream), carried) in per_stream {
            prop_assert!(
                carried <= frame_ceiling,
                "stream {stream} of call {call} carried {carried} frames in {elapsed} ms, \
                 over a ceiling of {frame_ceiling}"
            );
        }
    }

    /// A backwards clock costs a well-behaved connection nothing.
    ///
    /// This property found a real defect. `Clock::System` is `SystemTime`, so an
    /// ordinary NTP correction moves `now_ms` backwards by a second or so. Both
    /// windows used to ask only whether enough time had passed, which answers "no"
    /// across a backwards step, so the byte window froze at whatever it had spent
    /// and the stream table stopped pruning. A one second correction became up to
    /// a minute of `quota` refusals on a live call, and a connection that had
    /// touched ``MAX_TRACKED_STREAMS`` ids answered `TooManyStreams` to every new
    /// stream for just as long. Audio, on a call already in progress, for a
    /// connection that did nothing wrong.
    ///
    /// The claim asserted is the one that matters to a person on a call: a window
    /// whose start is in the future is a new window, for any size of correction,
    /// so a connection at a legitimate rate is carried across one. That is a
    /// bounded thing to give away, because a peer cannot move the relay's clock:
    /// the only party that can is the operator's own time daemon.
    ///
    /// A forward jump needs no property. Time passing is what a fixed window is
    /// already built for, and the run above drives it constantly.
    #[test]
    fn a_backwards_clock_starts_a_window_rather_than_freezing_one(
        jump in 1u64..600_000,
    ) {
        // The stream table. Every seat taken inside one window, then the clock is
        // corrected backwards: every entry is now stamped in the future, and a
        // table that pruned on elapsed time alone would hold all thirty-two of
        // them and refuse every new stream until the clock caught up.
        let mut table = MediaBudget::default();
        for id in 0..MAX_TRACKED_STREAMS {
            prop_assert_eq!(table.charge(NOW, &call_of(1), &stream_of(id as u8), 700), Ok(()));
        }
        prop_assert_eq!(
            table.charge(NOW, &call_of(1), &stream_of(200), 700),
            Err(MediaRefusal::TooManyStreams)
        );
        let corrected = NOW - jump;
        prop_assert_eq!(
            table.charge(corrected, &call_of(1), &stream_of(200), 700),
            Ok(()),
            );
        prop_assert!(table.tracked_streams() <= MAX_TRACKED_STREAMS);

        // The byte window, the same way. The allowance is spent, the clock is
        // corrected backwards, and the frame after it is carried rather than
        // refused for a minute the connection has not had.
        let mut bytes = MediaBudget::default();
        let mut spent = 0u64;
        let mut id = 0u8;
        while spent + 1_024 <= MEDIA_BYTES_PER_MINUTE {
            prop_assert_eq!(bytes.charge(NOW, &call_of(1), &stream_of(id), 1_024), Ok(()));
            spent += 1_024;
            // Thirty-two frames a stream, well under the per-stream rate, so this
            // exhausts the byte budget and nothing else.
            id = (id + 1) % (MAX_TRACKED_STREAMS as u8);
        }
        prop_assert_eq!(
            bytes.charge(NOW, &call_of(1), &stream_of(id), 1_024),
            Err(MediaRefusal::ByteRate)
        );
        prop_assert_eq!(bytes.charge(corrected, &call_of(1), &stream_of(id), 1_024), Ok(()));
    }

    /// A refusal is reported at most once per window, and a corrected clock does
    /// not silence the report.
    ///
    /// The rate limit on the complaint is what stops a refused flood becoming an
    /// amplifier, so its bound is asserted directly: over a monotone run, the
    /// number of reports never exceeds the number of windows the run spans. The
    /// second half is the same clock defect from the other side: a report stamped
    /// after `now_ms` must not suppress the next one, because the answer carrying
    /// `retry_after` is the only thing telling a client to slow down.
    #[test]
    fn a_flood_is_answered_no_more_than_once_a_window(
        deltas in prop::collection::vec(0u64..1_500, 1..300),
    ) {
        let mut budget = MediaBudget::default();
        let mut clock = NOW;
        let mut reports = 0u64;
        for delta in &deltas {
            clock += delta;
            if budget.should_report(clock) {
                reports += 1;
            }
        }
        let windows = (clock - NOW) / MEDIA_STREAM_WINDOW_MS + 1;
        prop_assert!(
            reports <= windows,
            "{reports} answers across {windows} windows"
        );
        // And backwards, where a stale stamp must not win.
        let mut corrected = MediaBudget::default();
        prop_assert!(corrected.should_report(NOW));
        prop_assert!(!corrected.should_report(NOW + 1));
        prop_assert!(corrected.should_report(NOW - 1));
    }
}

/// The widths this file reasons about are the widths the crate enforces.
///
/// The byte window is not a public constant, so the property above restates it,
/// and a restated number is a number that can drift. This pins it: sixty
/// thousand milliseconds of traffic at the cap is carried and the next frame is
/// not, which is only true if both files mean the same minute.
#[test]
fn the_two_windows_are_the_widths_the_limits_table_states() {
    let mut budget = MediaBudget::default();
    let call = call_of(1);
    // The whole byte allowance, spent in one instant across enough streams that no
    // per-stream rate is touched: thirty-two streams at thirty-two frames each is
    // half the per-stream allowance and all of the connection's minute.
    let mut spent = 0u64;
    let mut id = 0u8;
    while spent + 1_024 <= MEDIA_BYTES_PER_MINUTE {
        assert_eq!(budget.charge(NOW, &call, &stream_of(id), 1_024), Ok(()));
        spent += 1_024;
        id = (id + 1) % (MAX_TRACKED_STREAMS as u8);
    }
    // The last millisecond of the minute is still the same minute.
    assert_eq!(
        budget.charge(NOW + BYTE_WINDOW_MS - 1, &call, &stream_of(id), 1_024),
        Err(MediaRefusal::ByteRate),
        "the byte window is narrower than {BYTE_WINDOW_MS} ms"
    );
    // And the millisecond after it is the next one.
    assert_eq!(
        budget.charge(NOW + BYTE_WINDOW_MS, &call, &stream_of(id), 1_024),
        Ok(()),
        "the byte window is wider than {BYTE_WINDOW_MS} ms"
    );

    // The stream window, the same shape: the allowance inside one second, refused
    // at the end of it, carried at the start of the next.
    let mut stream_budget = MediaBudget::default();
    let one = stream_of(1);
    for _ in 0..MEDIA_FRAMES_PER_STREAM_PER_SECOND {
        assert_eq!(stream_budget.charge(NOW, &call, &one, 1), Ok(()));
    }
    assert_eq!(
        stream_budget.charge(NOW + MEDIA_STREAM_WINDOW_MS - 1, &call, &one, 1),
        Err(MediaRefusal::StreamRate),
        "the stream window is narrower than {MEDIA_STREAM_WINDOW_MS} ms"
    );
    assert_eq!(
        stream_budget.charge(NOW + MEDIA_STREAM_WINDOW_MS, &call, &one, 1),
        Ok(()),
        "the stream window is wider than {MEDIA_STREAM_WINDOW_MS} ms"
    );
}

// MARK: The registry

/// One step against the registry.
#[derive(Debug, Clone, Copy)]
enum Op {
    /// A `CALL` of a joining kind: `offer` or `answer`.
    Join {
        call: u8,
        group: u8,
        connection: ConnectionId,
    },
    /// A `CALL` of a leaving kind: `decline` or `bye`.
    Leave { call: u8, connection: ConnectionId },
    /// A reader loop ending, however it ended.
    Forget { connection: ConnectionId },
    /// One `MEDIA` frame.
    Route { call: u8, connection: ConnectionId },
}

/// How many connections the model drives. Larger than one call's participant cap
/// so that `CallFull` is reachable, and small enough that the same connection
/// lands in several calls, which is the case a per-connection cleanup either
/// handles or leaks.
const CONNECTIONS: u64 = 8;

/// How many call ids, and how many groups. Two groups against three call ids is
/// what makes `GroupMismatch` a case the sequence actually reaches rather than a
/// branch nothing walks.
const CALLS: u8 = 3;
const GROUPS: u8 = 2;

/// The ceiling the property runs the registry at. Below ``CALLS`` on purpose, so
/// `TooManyCalls` is reachable too.
const MAX_CONCURRENT: usize = 2;

fn ops() -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec(
        prop_oneof![
            // Weighted towards joins and routes, which is the shape of a call: a
            // handful of signalling frames and then audio.
            3 => (0u8..CALLS, 0u8..GROUPS, 0u64..CONNECTIONS)
                .prop_map(|(call, group, connection)| Op::Join { call, group, connection }),
            1 => (0u8..CALLS, 0u64..CONNECTIONS)
                .prop_map(|(call, connection)| Op::Leave { call, connection }),
            1 => (0u64..CONNECTIONS).prop_map(|connection| Op::Forget { connection }),
            4 => (0u8..CALLS, 0u64..CONNECTIONS)
                .prop_map(|(call, connection)| Op::Route { call, connection }),
        ],
        1..200,
    )
}

/// What the registry should hold: for each open call, its group and its
/// participants in join order.
///
/// Deliberately a plain map with the rules written out longhand rather than a
/// clever one. A model that shared an implementation detail with the thing it
/// models would agree with it about the bug as well as about the behaviour.
#[derive(Default)]
struct Model {
    calls: HashMap<u8, (u8, Vec<ConnectionId>)>,
}

impl Model {
    fn join(&mut self, call: u8, group: u8, connection: ConnectionId) -> Result<(), JoinRefusal> {
        match self.calls.get_mut(&call) {
            Some((existing, participants)) => {
                if *existing != group {
                    return Err(JoinRefusal::GroupMismatch);
                }
                if participants.contains(&connection) {
                    return Ok(());
                }
                if participants.len() >= MAX_PARTICIPANTS_PER_CALL {
                    return Err(JoinRefusal::CallFull);
                }
                participants.push(connection);
                Ok(())
            }
            None => {
                if self.calls.len() >= MAX_CONCURRENT {
                    return Err(JoinRefusal::TooManyCalls);
                }
                // The second ceiling, and the model has to carry it or the two
                // disagree on every trace where one connection opens more than
                // its share. `CallRegistry::share` is a quarter of the table and
                // never less than one: a finite table with no per-source share is
                // a table one source takes, and on the hosted tier that process
                // carries many workspaces, so one socket could refuse every other
                // customer's calls (WEALD-340). Written out longhand here, like
                // every other rule in this model, rather than calling the
                // registry's own `share`: a model that borrowed the
                // implementation would agree with it about a bug too.
                let share = (MAX_CONCURRENT / 4).max(1);
                let held = self
                    .calls
                    .values()
                    .filter(|(_, participants)| participants.contains(&connection))
                    .count();
                if held >= share {
                    // The same refusal the table ceiling gives, deliberately: the
                    // client's next move is identical and a distinct code would
                    // tell an attacker which of the two ceilings it found.
                    return Err(JoinRefusal::TooManyCalls);
                }
                self.calls.insert(call, (group, vec![connection]));
                Ok(())
            }
        }
    }

    fn leave(&mut self, call: u8, connection: ConnectionId) {
        if let Some((_, participants)) = self.calls.get_mut(&call) {
            participants.retain(|held| *held != connection);
            if participants.is_empty() {
                self.calls.remove(&call);
            }
        }
    }

    fn forget(&mut self, connection: ConnectionId) {
        for (_, participants) in self.calls.values_mut() {
            participants.retain(|held| *held != connection);
        }
        self.calls
            .retain(|_, (_, participants)| !participants.is_empty());
    }

    fn members(&self, call: u8) -> &[ConnectionId] {
        self.calls
            .get(&call)
            .map_or(&[][..], |(_, participants)| participants.as_slice())
    }
}

/// The eight connections, their channels held open for the whole run so that a
/// `Closed` never happens by accident. `calls_unit` covers the dropped-receiver
/// case deliberately; here it would be noise that made the routed counts
/// unpredictable.
struct Peers {
    senders: Vec<OutboundSender>,
    receivers: Vec<OutboundReceiver>,
}

impl Peers {
    fn new() -> Self {
        let mut senders = Vec::new();
        let mut receivers = Vec::new();
        for _ in 0..CONNECTIONS {
            let (sender, receiver) = outbound_channel();
            senders.push(sender);
            receivers.push(receiver);
        }
        Self { senders, receivers }
    }

    /// Empty every queue, so the bounded channel never fills and turns a `Sent`
    /// into a `Full` for a reason that has nothing to do with the property.
    fn drain(&mut self) -> Vec<usize> {
        self.receivers
            .iter_mut()
            .map(|receiver| {
                let mut taken = 0;
                while let Ok(Outbound::Frame(_)) = receiver.try_recv() {
                    taken += 1;
                }
                taken
            })
            .collect()
    }
}

fn media_frame(call: u8) -> Frame {
    Frame::Media {
        call_id: call_of(call).to_vec(),
        stream: stream_of(1).to_vec(),
        seq: 1,
        ct: vec![7; 80],
    }
}

proptest! {
    #![proptest_config(config())]

    /// The registry agrees with a plain model of it after every step, and the
    /// structural invariants hold at every step rather than at the end.
    ///
    /// Four operations interleaved arbitrarily, which is the real ordering: a
    /// socket can die mid-offer, a `bye` can arrive after the peer already left,
    /// and a media frame can arrive for a call that was torn down between the
    /// client sending it and the relay reading it. Every one of those is a real
    /// sequence and none of them is a special case in the code, so the property is
    /// that none of them needs to be.
    ///
    /// The refusal is compared, not merely the fact of one. `GroupMismatch`
    /// answers `denied` and the other two answer `quota`, and `operations.md` has
    /// a client treat those oppositely: one is not retryable and the other is a
    /// backoff. A registry that refused correctly and classified wrongly would
    /// have clients retrying a denial forever.
    #[test]
    fn the_registry_is_exactly_its_model(ops in ops()) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        runtime.block_on(async {
            let registry = CallRegistry::new(MAX_CONCURRENT);
            let mut model = Model::default();
            let mut peers = Peers::new();
            let mut denied_seen = 0u64;

            for op in ops {
                match op {
                    Op::Join { call, group, connection } => {
                        let expected = model.join(call, group, connection);
                        let actual = registry
                            .join(
                                &call_of(call),
                                &[group; 32],
                                connection,
                                peers.senders[connection as usize].clone(),
                            )
                            .await;
                        prop_assert_eq!(
                            actual,
                            expected,
                            "join({}, {}, {}) disagreed with the model", call, group, connection
                        );
                    }
                    Op::Leave { call, connection } => {
                        model.leave(call, connection);
                        registry.leave(&call_of(call), connection).await;
                    }
                    Op::Forget { connection } => {
                        model.forget(connection);
                        registry.forget(connection).await;
                    }
                    Op::Route { call, connection } => {
                        let members = model.members(call);
                        let admitted = members.contains(&connection);
                        let routed = registry
                            .route(&call_of(call), connection, &media_frame(call))
                            .await;
                        if admitted {
                            let routed = routed.expect("an admitted sender is routed");
                            // Everybody else, and nobody else. The sender never
                            // receives its own audio, which is the property that
                            // makes a loop impossible rather than merely unlikely.
                            prop_assert_eq!(routed.sent, members.len() - 1);
                            prop_assert_eq!(routed.shed, 0);
                            prop_assert_eq!(routed.gone, 0);
                            let taken = peers.drain();
                            for (index, count) in taken.iter().enumerate() {
                                let expected = usize::from(
                                    members.contains(&(index as u64)) && index as u64 != connection,
                                );
                                prop_assert_eq!(
                                    *count,
                                    expected,
                                    "connection {} received {} frames of call {}", index, count, call
                                );
                            }
                        } else {
                            // A claim on a conversation this connection was never
                            // admitted to, answered as exactly that and counted.
                            prop_assert_eq!(routed, Err(ErrorCode::WriterNotInAccessSet));
                            denied_seen += 1;
                            prop_assert_eq!(registry.denied(), denied_seen);
                            // Nothing reached anybody.
                            prop_assert!(peers.drain().iter().all(|count| *count == 0));
                        }
                    }
                }

                // The invariants, after every single step.
                let open = registry.open_calls().await;
                prop_assert_eq!(open, model.calls.len());
                prop_assert!(
                    open <= MAX_CONCURRENT,
                    "{open} calls open against a ceiling of {MAX_CONCURRENT}"
                );
                for (call, (group, participants)) in &model.calls {
                    // No empty call is ever left behind. An empty one still holding
                    // its id is a seat under the instance ceiling that nobody can
                    // use and nothing will ever free.
                    prop_assert!(!participants.is_empty());
                    prop_assert!(participants.len() <= MAX_PARTICIPANTS_PER_CALL);
                    prop_assert_eq!(
                        registry.group_of(&call_of(*call)).await,
                        Some(vec![*group; 32])
                    );
                    for connection in 0..CONNECTIONS {
                        prop_assert_eq!(
                            registry.holds(&call_of(*call), connection).await,
                            participants.contains(&connection),
                            "membership of {} in call {} disagreed", connection, call
                        );
                    }
                }
                // And nothing is held for a call the model closed.
                for call in 0..CALLS {
                    if !model.calls.contains_key(&call) {
                        prop_assert_eq!(registry.group_of(&call_of(call)).await, None);
                    }
                }
                // Nothing was shed: every receiver is drained every step, so a shed
                // here would be a bounded queue filling for a reason the property
                // does not model.
                prop_assert_eq!(registry.shed(), 0);
            }

            // Every socket ending empties the process, which is the claim that a
            // relay carrying calls for a month is carrying no dead ones.
            for connection in 0..CONNECTIONS {
                registry.forget(connection).await;
            }
            prop_assert_eq!(registry.open_calls().await, 0);
            Ok(())
        })?;
    }

    /// The kind byte is a closed set, whatever a peer puts in it.
    ///
    /// One line of the frame is cleartext and the relay routes on it, so the
    /// exhaustive statement is worth having: exactly four numbers are readable as a
    /// kind, exactly two of them join, and every other byte is refused rather than
    /// forwarded.
    #[test]
    fn only_the_four_documented_kinds_are_readable(byte in any::<u8>()) {
        match CallKind::from_u8(byte) {
            Some(kind) => {
                prop_assert!((1..=4).contains(&byte));
                prop_assert_eq!(kind as u8, byte);
                prop_assert_eq!(kind.joins(), byte == 1 || byte == 2);
                prop_assert!(CallKind::ALL.contains(&kind));
            }
            None => prop_assert!(!(1..=4).contains(&byte)),
        }
    }
}
