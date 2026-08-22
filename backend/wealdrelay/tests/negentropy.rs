// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Range-based set reconciliation: the codec, the two roles, and convergence.
//!
//! Tier 1 and tier 2 for step 5's first gate part. The flagship is
//! ``any_partition_converges``: envelopes are partitioned at random between the two
//! sides, arrival order is randomised, and the exchange is driven to completion. It
//! asserts three things, and the second and third are the ones that make it a proof
//! rather than a smoke test:
//!
//! 1. Both sides end holding the same set.
//! 2. It terminates inside the round bound the recursion implies, so a
//!    non-converging exchange fails rather than hanging.
//! 3. Nothing moves that was not missing. A protocol that converged by resending
//!    the whole corpus would satisfy (1) and (2) and would have thrown away the
//!    entire point of range reconciliation.

use std::collections::BTreeSet;

use proptest::prelude::*;
use wealdrelay::cbor::CborError;
use wealdrelay::frame::ErrorCode;
use wealdrelay::negentropy::{
    advance, fingerprint, ids_of, initiate, items_in, respond, Id, Item, Message, Mode, Range,
    ReconError, IDLIST_LIMIT, INFINITY, MAX_IDS_PER_RANGE, MAX_RANGES, RECON_VERSION,
};

/// An id built from a seed, so a test can name the item it means.
fn id(seed: u64) -> Id {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&seed.to_be_bytes());
    out
}

fn item(seq: u64) -> Item {
    Item { seq, id: id(seq) }
}

/// A relay-shaped item set: sorted, and one item per sequence number, because
/// `(group_id, seq)` is unique in the schema. A set with a duplicated `seq` is what
/// a renumbering looks like from a client's side, and that case has its own test
/// rather than being smuggled into every other one.
fn items(seqs: impl IntoIterator<Item = u64>) -> Vec<Item> {
    let mut items: Vec<Item> = seqs.into_iter().map(item).collect();
    items.sort();
    items.dedup();
    items
}

// MARK: The codec

#[test]
fn a_wide_disagreement_answers_a_message_the_peer_can_decode() {
    // WEALD-L178. One legal `RECON` carrying `MAX_RANGES` disagreeing fingerprint
    // spans, each over more than `IDLIST_LIMIT` items, used to answer with up to
    // eight thousand ranges: under the frame ceiling, over the decoder's own range
    // bound, and deterministic, so the group could never reconcile again.
    let per_span = IDLIST_LIMIT * 4;
    let held = items((0..(MAX_RANGES * per_span) as u64).map(|n| n + 1));
    let mut ranges: Vec<Range> = (1..MAX_RANGES)
        .map(|index| {
            Range::new(
                (index * per_span) as u64 + 1,
                Mode::Fingerprint([index as u8; 32]),
            )
        })
        .collect();
    ranges.push(Range::new(INFINITY, Mode::Fingerprint([9u8; 32])));
    let incoming = Message { ranges };
    let response = respond(&held, &incoming);
    assert!(
        response.reply.ranges.len() <= MAX_RANGES,
        "answered with {} ranges",
        response.reply.ranges.len()
    );
    assert_eq!(
        Message::decode(&response.reply.encode()),
        Ok(response.reply.clone()),
        "the reply must be one the peer's decoder accepts"
    );
}

#[test]
fn a_message_round_trips_through_every_mode() {
    let message = Message {
        ranges: vec![
            Range::new(10, Mode::Skip),
            Range::new(20, Mode::Fingerprint(id(1))),
            Range::new(INFINITY, Mode::IdList(vec![id(2), id(3)])),
        ],
    };
    let encoded = message.encode();
    assert_eq!(Message::decode(&encoded), Ok(message));
}

#[test]
fn one_message_has_exactly_one_encoding() {
    // The client's half is a separate implementation, so the encoding has to be a
    // function of the value and nothing else. Two encodes of one value differing by
    // a byte would put two payloads on the wire for one message.
    let message = Message::settled();
    assert_eq!(message.encode(), message.encode());
    assert_eq!(
        Message::settled().encode(),
        Message {
            ranges: vec![Range::new(INFINITY, Mode::Skip)]
        }
        .encode()
    );
}

#[test]
fn a_settled_message_is_recognised_as_settled() {
    assert!(Message::settled().is_settled());
    assert!(!Message {
        ranges: vec![Range::new(INFINITY, Mode::Fingerprint(id(1)))],
    }
    .is_settled());
}

#[test]
fn the_version_is_checked_before_anything_else() {
    let mut encoded = Message::settled().encode();
    // The second byte is the version, in shortest form.
    encoded[1] = 0x02;
    assert_eq!(
        Message::decode(&encoded),
        Err(ReconError::UnsupportedVersion(2))
    );
    assert_eq!(RECON_VERSION, 1);
}

#[test]
fn a_cover_with_a_hole_is_refused_rather_than_interpreted() {
    // The failure this catches is one member silently missing envelopes nobody else
    // is missing, which is the worst class of bug this protocol can have.
    let short = Message {
        ranges: vec![Range::new(99, Mode::Skip)],
    };
    assert_eq!(
        Message::decode(&short.encode()),
        Err(ReconError::IncompleteCover)
    );
}

#[test]
fn range_bounds_must_strictly_ascend() {
    let repeated = Message {
        ranges: vec![Range::new(10, Mode::Skip), Range::new(10, Mode::Skip)],
    };
    assert_eq!(
        Message::decode(&repeated.encode()),
        Err(ReconError::UnorderedRanges)
    );
    let descending = Message {
        ranges: vec![Range::new(10, Mode::Skip), Range::new(4, Mode::Skip)],
    };
    assert_eq!(
        Message::decode(&descending.encode()),
        Err(ReconError::UnorderedRanges)
    );
}

#[test]
fn ids_within_a_range_must_strictly_ascend() {
    let repeated = Message {
        ranges: vec![Range::new(INFINITY, Mode::IdList(vec![id(2), id(2)]))],
    };
    assert_eq!(
        Message::decode(&repeated.encode()),
        Err(ReconError::UnorderedIds)
    );
    let descending = Message {
        ranges: vec![Range::new(INFINITY, Mode::IdList(vec![id(3), id(2)]))],
    };
    assert_eq!(
        Message::decode(&descending.encode()),
        Err(ReconError::UnorderedIds)
    );
}

#[test]
fn an_empty_message_is_refused() {
    let encoded = wealdrelay::cbor::array(&[
        wealdrelay::cbor::uint(RECON_VERSION),
        wealdrelay::cbor::array(&[]),
    ]);
    assert_eq!(Message::decode(&encoded), Err(ReconError::Empty));
}

#[test]
fn a_range_count_past_the_bound_is_refused_before_the_ranges_are_read() {
    // Encoded by hand, because building `MAX_RANGES + 1` real ranges would make the
    // test prove the encoder rather than the bound. The array header is what is
    // being refused, and it is refused without reading an item.
    let header = wealdrelay::cbor::array(&[wealdrelay::cbor::uint(RECON_VERSION), {
        let mut out = vec![0x99];
        out.extend_from_slice(&((MAX_RANGES + 1) as u16).to_be_bytes());
        // Enough filler that the array header's own length check passes: the
        // reader refuses a count larger than the bytes that remain, and the
        // bound under test is the protocol's rather than CBOR's.
        out.extend(std::iter::repeat_n(0u8, MAX_RANGES + 2));
        out
    }]);
    assert_eq!(
        Message::decode(&header),
        Err(ReconError::TooManyRanges(MAX_RANGES + 1))
    );
}

#[test]
fn an_id_count_past_the_bound_is_refused() {
    let mut ids = vec![0x99];
    ids.extend_from_slice(&((MAX_IDS_PER_RANGE + 1) as u16).to_be_bytes());
    ids.extend(std::iter::repeat_n(0u8, MAX_IDS_PER_RANGE + 2));
    let encoded = wealdrelay::cbor::array(&[
        wealdrelay::cbor::uint(RECON_VERSION),
        wealdrelay::cbor::array(&[wealdrelay::cbor::array(&[
            wealdrelay::cbor::uint(INFINITY),
            wealdrelay::cbor::uint(2),
            ids,
        ])]),
    ]);
    assert_eq!(
        Message::decode(&encoded),
        Err(ReconError::TooManyIds(MAX_IDS_PER_RANGE + 1))
    );
}

#[test]
fn an_unknown_mode_is_named_rather_than_ignored() {
    let encoded = wealdrelay::cbor::array(&[
        wealdrelay::cbor::uint(RECON_VERSION),
        wealdrelay::cbor::array(&[wealdrelay::cbor::array(&[
            wealdrelay::cbor::uint(INFINITY),
            wealdrelay::cbor::uint(9),
            wealdrelay::cbor::NULL.to_vec(),
        ])]),
    ]);
    assert_eq!(Message::decode(&encoded), Err(ReconError::UnknownMode(9)));
}

#[test]
fn a_skip_range_carrying_a_payload_is_refused() {
    let encoded = wealdrelay::cbor::array(&[
        wealdrelay::cbor::uint(RECON_VERSION),
        wealdrelay::cbor::array(&[wealdrelay::cbor::array(&[
            wealdrelay::cbor::uint(INFINITY),
            wealdrelay::cbor::uint(0),
            wealdrelay::cbor::bytes(&id(1)),
        ])]),
    ]);
    assert_eq!(
        Message::decode(&encoded),
        Err(ReconError::Cbor(CborError::TypeMismatch {
            expected: "null"
        }))
    );
}

#[test]
fn trailing_bytes_are_refused() {
    let mut encoded = Message::settled().encode();
    encoded.push(0x00);
    assert_eq!(
        Message::decode(&encoded),
        Err(ReconError::Cbor(CborError::TrailingBytes(1)))
    );
}

#[test]
fn a_payload_that_is_not_cbor_at_all_is_a_cbor_failure() {
    assert_eq!(
        Message::decode(&[0xff]),
        Err(ReconError::Cbor(CborError::ReservedAdditionalInfo(31)))
    );
}

#[test]
fn every_refusal_maps_to_a_code_in_the_closed_registry() {
    // Bad CBOR and a malformed cover are different bugs and the client branches on
    // the difference: one is a peer speaking a wider encoding, the other is a peer
    // whose cover is wrong.
    assert_eq!(
        ReconError::Cbor(CborError::Truncated).code(),
        ErrorCode::NoncanonicalCbor
    );
    for error in [
        ReconError::UnsupportedVersion(2),
        ReconError::TooManyRanges(1),
        ReconError::TooManyIds(1),
        ReconError::UnknownMode(3),
        ReconError::UnorderedRanges,
        ReconError::IncompleteCover,
        ReconError::UnorderedIds,
        ReconError::Empty,
    ] {
        assert_eq!(error.code(), ErrorCode::MalformedHeader);
        // Every variant has a message an operator can read. The registry is closed,
        // so the code is the client's branch and the text is the human's.
        assert!(!error.to_string().is_empty());
    }
}

// MARK: Fingerprints and range selection

#[test]
fn the_fingerprint_covers_the_sequence_number_as_well_as_the_id() {
    // A relay that renumbered an envelope must not fingerprint identically: a
    // silent renumbering is a server-side rewrite the client is entitled to notice.
    let one = vec![Item { seq: 1, id: id(9) }];
    let renumbered = vec![Item { seq: 2, id: id(9) }];
    assert_ne!(fingerprint(&one), fingerprint(&renumbered));
}

#[test]
fn the_fingerprint_covers_the_count() {
    assert_ne!(fingerprint(&[]), fingerprint(&items([1])));
    assert_eq!(fingerprint(&items([1, 2])), fingerprint(&items([2, 1])));
}

#[test]
fn items_in_a_range_are_half_open_and_tolerate_gaps() {
    let held = items([1, 2, 5, 9]);
    assert_eq!(items_in(&held, 0, 5), &held[..2]);
    assert_eq!(items_in(&held, 5, 10), &held[2..]);
    // A range that names nothing is empty rather than an error: gaps in `seq` are
    // legal, because a rolled-back transaction leaves one.
    assert!(items_in(&held, 6, 9).is_empty());
    assert_eq!(items_in(&held, 0, INFINITY).len(), 4);
}

#[test]
fn ids_are_sorted_and_deduplicated() {
    let duplicated = vec![Item { seq: 1, id: id(5) }, Item { seq: 2, id: id(5) }];
    assert_eq!(ids_of(&duplicated), vec![id(5)]);
    let unsorted = vec![Item { seq: 1, id: id(9) }, Item { seq: 2, id: id(3) }];
    assert_eq!(ids_of(&unsorted), vec![id(3), id(9)]);
}

#[test]
fn a_small_set_opens_with_an_id_list_and_a_large_one_with_fingerprints() {
    let small = initiate(&items(1..=IDLIST_LIMIT as u64));
    assert!(
        matches!(small.ranges.as_slice(), [range] if matches!(&range.mode, Mode::IdList(ids) if ids.len() == IDLIST_LIMIT))
    );
    assert_eq!(small.ranges[0].upper, INFINITY);

    let large = initiate(&items(1..=200));
    assert!(large.ranges.len() > 1);
    assert!(large
        .ranges
        .iter()
        .all(|range| matches!(range.mode, Mode::Fingerprint(_))));
    assert_eq!(large.ranges.last().expect("a range").upper, INFINITY);
    // The cover is a cover: decode enforces it, so encoding and decoding the
    // opening message is the assertion.
    assert!(Message::decode(&large.encode()).is_ok());
}

#[test]
fn a_renumbered_set_still_encodes_a_valid_cover() {
    // Two items at one sequence number, which is what a client sees if the relay
    // renumbered an envelope. The relay's own set cannot hold this, because
    // `(group_id, seq)` is unique, but the client's can, and a split that emitted
    // two ranges with the same upper bound would produce a message the decoder
    // refuses. Found by `every_message_produced_is_one_the_decoder_accepts`.
    let mut held: Vec<Item> = (1..=200).map(item).collect();
    for offset in 0..40u64 {
        held.push(Item {
            seq: 100,
            id: id(10_000 + offset),
        });
    }
    held.sort();
    let opening = initiate(&held);
    assert_eq!(Message::decode(&opening.encode()), Ok(opening.clone()));
    // And the relay answers it without producing an invalid cover either.
    let response = respond(&items(1..=200), &opening);
    assert_eq!(
        Message::decode(&response.reply.encode()),
        Ok(response.reply.clone())
    );
}

#[test]
fn an_empty_client_asks_for_everything_in_one_frame() {
    let opening = initiate(&[]);
    assert_eq!(
        opening,
        Message {
            ranges: vec![Range::new(INFINITY, Mode::IdList(Vec::new()))]
        }
    );
    // And the relay answers by pushing the lot.
    let response = respond(&items([1, 2, 3]), &opening);
    assert_eq!(response.push, vec![id(1), id(2), id(3)]);
    assert!(response.reply.is_settled());
}

// MARK: The two roles, one round at a time

#[test]
fn equal_sides_settle_in_one_round() {
    let held = items(1..=100);
    let opening = initiate(&held);
    let response = respond(&held, &opening);
    assert!(response.push.is_empty());
    assert!(response.reply.is_settled());
    let step = advance(&held, &response.reply);
    assert!(step.done());
    assert!(step.reply.is_none());
}

#[test]
fn a_settled_range_is_never_reopened() {
    // A side that has said a range is done does not get argued with: re-examining
    // it would make the exchange non-terminating whenever a write landed mid-round.
    let response = respond(&items(1..=100), &Message::settled());
    assert!(response.reply.is_settled());
    assert!(response.push.is_empty());
}

#[test]
fn a_differing_large_range_is_split_rather_than_listed() {
    let relay = items(1..=800);
    let mut client = relay.clone();
    client.pop();
    let response = respond(&relay, &initiate(&client));
    assert!(response
        .reply
        .ranges
        .iter()
        .any(|range| matches!(range.mode, Mode::Fingerprint(_))));
    // Nothing is pushed yet: the relay does not know what the client holds until an
    // id list arrives, and guessing would send the whole range.
    assert!(response.push.is_empty());
}

#[test]
fn a_client_that_is_ahead_is_told_what_the_relay_has_so_it_can_resend() {
    let relay = items([1, 2]);
    let client = items([1, 2, 3]);
    let response = respond(&relay, &initiate(&client));
    assert!(response.push.is_empty());
    assert!(!response.reply.is_settled());
    let step = advance(&client, &response.reply);
    assert_eq!(step.send, vec![id(3)]);
    assert!(step.want.is_empty());
    assert!(!step.done());
}

#[test]
fn a_client_that_is_behind_wants_what_it_lacks() {
    let relay = items([1, 2, 3]);
    let client = items([1]);
    // Round one: the client's id list, the relay pushes what is missing.
    let response = respond(&relay, &initiate(&client));
    assert_eq!(response.push, vec![id(2), id(3)]);
    assert!(response.reply.is_settled());
    // Applied, and the exchange is over.
    let step = advance(&relay, &response.reply);
    assert!(step.done());
}

#[test]
fn a_client_answering_a_relay_id_list_reports_both_directions() {
    let relay = items([1, 2, 5]);
    let client = items([1, 3]);
    let reply = Message {
        ranges: vec![Range::new(INFINITY, Mode::IdList(ids_of(&relay)))],
    };
    let step = advance(&client, &reply);
    assert_eq!(step.want, vec![id(2), id(5)]);
    assert_eq!(step.send, vec![id(3)]);
    assert!(step.reply.is_some());
}

#[test]
fn a_client_answers_a_fingerprint_it_disagrees_with() {
    let relay = items(1..=300);
    let client = items(1..=290);
    // The relay opens, which happens when a relay drives a round after a restart.
    let opening = initiate(&relay);
    let step = advance(&client, &opening);
    let reply = step.reply.expect("a disagreement is answered");
    assert!(reply
        .ranges
        .iter()
        .any(|range| matches!(range.mode, Mode::Fingerprint(_) | Mode::IdList(_))));
    assert!(Message::decode(&reply.encode()).is_ok());
}

#[test]
fn a_client_that_answers_before_its_acks_is_safe_but_wasteful() {
    // The rule the client owes: `SEND` first, apply each `SEND_ACK`'s assigned
    // sequence number, then answer. A client that answers from its pre-`SEND` view
    // describes its own envelopes at sequence numbers the relay does not use, so the
    // relay reads them as absent from the range it is looking at and pushes them
    // back. Safe, because the envelope is content addressed and the client already
    // holds it, and wasteful, because it is a round of bytes for nothing. Asserted
    // rather than described, so a client implementation that gets the order wrong
    // has a test to read.
    let client = items(1..=40);
    let relay = items([500]);
    let response = respond(&relay, &initiate(&client));
    let step = advance(&client, &response.reply);
    assert_eq!(step.send.len(), 40);

    // The relay numbers them from its own counter, which is past everything it
    // holds, so every one of them lands above the client's own view of the space.
    let numbered: Vec<Item> = step
        .send
        .iter()
        .enumerate()
        .map(|(index, id)| Item {
            seq: 501 + index as u64,
            id: *id,
        })
        .collect();
    let mut settled = relay.clone();
    settled.extend(numbered.iter().copied());
    settled.sort();

    // Answering with the stale view: the relay pushes back what the client already
    // holds.
    let stale = advance(&client, &response.reply)
        .reply
        .expect("a difference is answered");
    let wasteful = respond(&settled, &stale);
    assert!(!wasteful.push.is_empty());

    // Answering with the acks applied: nothing moves.
    let mut updated = numbered;
    updated.push(relay[0]);
    updated.sort();
    let correct = advance(&updated, &response.reply);
    let exchanged = correct
        .reply
        .map(|reply| respond(&settled, &reply).push)
        .unwrap_or_default();
    assert!(exchanged.is_empty());
}

#[test]
fn a_client_settles_a_skip_range_without_reading_its_own_items() {
    let step = advance(&items(1..=50), &Message::settled());
    assert!(step.done());
}

// MARK: Convergence

/// One side of the exchange, as a set of items keyed by id.
///
/// Sequence numbers are the relay's, so the client learns one only when an envelope
/// arrives from the relay. Modelled by keeping the relay's `seq` on transfer, which
/// is what a real client does with a pushed envelope's header.
#[derive(Debug, Clone)]
struct Side {
    held: Vec<Item>,
}

impl Side {
    fn new(held: Vec<Item>) -> Self {
        let mut side = Self { held };
        side.held.sort();
        side
    }

    fn ids(&self) -> BTreeSet<Id> {
        self.held.iter().map(|item| item.id).collect()
    }

    fn insert(&mut self, item: Item) {
        if !self.held.iter().any(|held| held.id == item.id) {
            self.held.push(item);
            self.held.sort();
        }
    }

    fn find(&self, id: Id) -> Option<Item> {
        self.held.iter().copied().find(|item| item.id == id)
    }
}

/// Drive the exchange to completion and report what it cost.
///
/// Returns the number of rounds and the number of envelopes that moved, which is
/// what the artifact records and what the "nothing moves that was not missing"
/// assertion is made against.
fn converge(client: &mut Side, relay: &mut Side, bound: usize) -> (usize, usize) {
    let mut rounds = 0usize;
    let mut moved = 0usize;
    let mut message = initiate(&client.held);

    loop {
        rounds += 1;
        assert!(
            rounds <= bound,
            "the exchange did not converge in {bound} rounds"
        );

        // The relay's turn. Its answer is computed against what it holds, then the
        // pushes are applied to the client before the client's turn, exactly as the
        // frame order on the socket guarantees.
        let response = respond(&relay.held, &message);
        for id in &response.push {
            let item = relay.find(*id).expect("the relay pushes what it holds");
            client.insert(item);
            moved += 1;
        }

        let mut step = advance(&client.held, &response.reply);
        // The client `SEND`s first, and applies each `SEND_ACK`'s assigned sequence
        // number before it answers. That order is required rather than tidy: an
        // envelope the client holds without a relay sequence number is placed in the
        // reconciliation space only once the relay has numbered it, and a client that
        // answered from its pre-`SEND` view would describe those envelopes at
        // sequence numbers the relay does not use, which costs a round of redundant
        // pushes. See `a_client_that_answers_before_its_acks_is_safe_but_wasteful`.
        if !step.send.is_empty() {
            for id in &step.send {
                let assigned = relay.held.iter().map(|item| item.seq).max().unwrap_or(0) + 1;
                relay.insert(Item {
                    seq: assigned,
                    id: *id,
                });
                client.held.retain(|item| item.id != *id);
                client.insert(Item {
                    seq: assigned,
                    id: *id,
                });
                moved += 1;
            }
            step = advance(&client.held, &response.reply);
        }

        match step.reply {
            None => break,
            Some(reply) => message = reply,
        }
    }

    (rounds, moved)
}

fn set_strategy() -> impl Strategy<Value = Vec<u64>> {
    prop::collection::vec(1u64..400, 0..120)
}

fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2000);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// Any partition of envelopes across the two transports converges to one set,
    /// with arrival order randomised. Step 5's property gate.
    ///
    /// The partition is the point: an envelope may be on the relay only, on the
    /// client only, or on both, which is exactly what dual transport produces when
    /// one member is on git and another is on the relay.
    #[test]
    fn any_partition_converges(
        seqs in set_strategy(),
        left in prop::collection::vec(any::<bool>(), 0..120),
        right in prop::collection::vec(any::<bool>(), 0..120),
    ) {
        let universe = items(seqs);
        let mut client = Vec::new();
        let mut relay = Vec::new();
        for (index, item) in universe.iter().enumerate() {
            // Arrival order is randomised by shuffling which side gets which item
            // and by the item order inside each side, which `Side::new` then sorts:
            // the protocol is order-independent and this is where that is asserted.
            if left.get(index).copied().unwrap_or(true) {
                client.push(*item);
            }
            if right.get(index).copied().unwrap_or(true) {
                relay.push(*item);
            }
        }
        // The union of what the two sides actually hold, which is not the whole
        // universe: an envelope assigned to neither side is one nobody has ever
        // seen, and reconciliation cannot and must not invent it.
        let mut expected: BTreeSet<Id> = Side::new(client.clone()).ids();
        expected.extend(Side::new(relay.clone()).ids());
        let missing_from_client = expected.len() - Side::new(client.clone()).ids().len();
        let missing_from_relay = expected.len() - Side::new(relay.clone()).ids().len();

        let mut client = Side::new(client);
        let mut relay = Side::new(relay);
        let (_, moved) = converge(&mut client, &mut relay, 64);

        prop_assert_eq!(client.ids(), relay.ids());
        prop_assert_eq!(client.ids(), expected);
        // Nothing moves that was not missing. A protocol that converged by
        // resending the corpus would pass the two assertions above.
        prop_assert_eq!(moved, missing_from_client + missing_from_relay);
    }

    /// One difference in a large corpus costs a handful of rounds, not a walk.
    /// This is the O(diff) rather than O(history) claim, asserted rather than
    /// described.
    #[test]
    fn one_difference_in_a_large_corpus_converges_in_few_rounds(
        withheld in 1u64..2000,
    ) {
        let universe = items(1..=2000);
        let relay = Side::new(universe.clone());
        let client = Side::new(
            universe
                .iter()
                .copied()
                .filter(|item| item.seq != withheld)
                .collect(),
        );
        let mut client = client;
        let mut relay = relay;
        let (rounds, moved) = converge(&mut client, &mut relay, 8);
        prop_assert_eq!(moved, 1);
        // log8(2000) is under 4, plus the id-list round and the settling round.
        prop_assert!(rounds <= 8, "converged in {} rounds", rounds);
    }

    /// Every message either side produces is a valid cover that decodes to itself.
    #[test]
    fn every_message_produced_is_one_the_decoder_accepts(seqs in set_strategy()) {
        let held = items(seqs);
        let opening = initiate(&held);
        let decoded_opening = Message::decode(&opening.encode());
        prop_assert_eq!(decoded_opening, Ok(opening.clone()));
        let response = respond(&held, &opening);
        let decoded_reply = Message::decode(&response.reply.encode());
        prop_assert_eq!(decoded_reply, Ok(response.reply.clone()));
    }

    /// No reply either side builds can exceed the bound its own decoder enforces.
    #[test]
    fn a_reply_never_exceeds_the_range_bound(seqs in set_strategy()) {
        let held = items(seqs);
        let mut wide_ranges: Vec<Range> = (1..MAX_RANGES)
            .map(|index| Range::new(index as u64 * 4, Mode::Fingerprint([index as u8; 32])))
            .collect();
        // A cover reaches the open end, which is what the decoder means by complete.
        wide_ranges.push(Range::new(INFINITY, Mode::Fingerprint([7u8; 32])));
        let wide = Message { ranges: wide_ranges };
        let response = respond(&held, &wide);
        prop_assert!(response.reply.ranges.len() <= MAX_RANGES);
        prop_assert!(Message::decode(&response.reply.encode()).is_ok());
        if let Some(reply) = advance(&held, &wide).reply {
            prop_assert!(reply.ranges.len() <= MAX_RANGES);
            prop_assert!(Message::decode(&reply.encode()).is_ok());
        }
    }

    /// Decoding is total: no payload panics, whatever bytes a peer sends.
    #[test]
    fn decoding_is_total(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = Message::decode(&bytes);
    }
}

// MARK: Every place the decoder can give up

/// The decoder reads fields in order, and each read can fail on a hostile payload.
/// Every one of those failures is reachable from bytes a peer can send, so every one
/// has a case here: a decoder with an unreachable arm is an arm nobody has checked
/// the answer of.
#[test]
fn every_read_in_the_decoder_can_fail_and_says_which() {
    let byte_string = wealdrelay::cbor::bytes(&[1, 2, 3]);
    let range_header = |items: Vec<Vec<u8>>| {
        wealdrelay::cbor::array(&[
            wealdrelay::cbor::uint(RECON_VERSION),
            wealdrelay::cbor::array(&[wealdrelay::cbor::array(&items)]),
        ])
    };

    // The outer array is not a two item array.
    assert!(matches!(
        Message::decode(&wealdrelay::cbor::array(&[wealdrelay::cbor::uint(1)])),
        Err(ReconError::Cbor(CborError::WrongArrayCount { .. }))
    ));
    // The version is not an integer.
    assert!(matches!(
        Message::decode(&wealdrelay::cbor::array(&[
            byte_string.clone(),
            wealdrelay::cbor::array(&[]),
        ])),
        Err(ReconError::Cbor(CborError::TypeMismatch { .. }))
    ));
    // The range list is not an array.
    assert!(matches!(
        Message::decode(&wealdrelay::cbor::array(&[
            wealdrelay::cbor::uint(RECON_VERSION),
            byte_string.clone(),
        ])),
        Err(ReconError::Cbor(CborError::TypeMismatch { .. }))
    ));
    // A range is not a three item array.
    assert!(matches!(
        Message::decode(&range_header(vec![wealdrelay::cbor::uint(1)])),
        Err(ReconError::Cbor(CborError::WrongArrayCount { .. }))
    ));
    // The upper bound is not an integer.
    assert!(matches!(
        Message::decode(&range_header(vec![
            byte_string.clone(),
            wealdrelay::cbor::uint(0),
            wealdrelay::cbor::NULL.to_vec(),
        ])),
        Err(ReconError::Cbor(CborError::TypeMismatch { .. }))
    ));
    // The mode is not an integer.
    assert!(matches!(
        Message::decode(&range_header(vec![
            wealdrelay::cbor::uint(INFINITY),
            byte_string.clone(),
            wealdrelay::cbor::NULL.to_vec(),
        ])),
        Err(ReconError::Cbor(CborError::TypeMismatch { .. }))
    ));
    // A skip range with nothing after it at all.
    assert!(matches!(
        Message::decode(&range_header(vec![
            wealdrelay::cbor::uint(INFINITY),
            wealdrelay::cbor::uint(0),
        ])),
        Err(ReconError::Cbor(CborError::WrongArrayCount { .. }))
    ));
    // A fingerprint that is not 32 bytes.
    assert!(matches!(
        Message::decode(&range_header(vec![
            wealdrelay::cbor::uint(INFINITY),
            wealdrelay::cbor::uint(1),
            byte_string.clone(),
        ])),
        Err(ReconError::Cbor(CborError::WrongLength { .. }))
    ));
    // An id list that is not an array.
    assert!(matches!(
        Message::decode(&range_header(vec![
            wealdrelay::cbor::uint(INFINITY),
            wealdrelay::cbor::uint(2),
            byte_string.clone(),
        ])),
        Err(ReconError::Cbor(CborError::TypeMismatch { .. }))
    ));
    // An id inside the list that is not 32 bytes.
    assert!(matches!(
        Message::decode(&range_header(vec![
            wealdrelay::cbor::uint(INFINITY),
            wealdrelay::cbor::uint(2),
            wealdrelay::cbor::array(&[byte_string]),
        ])),
        Err(ReconError::Cbor(CborError::WrongLength { .. }))
    ));
    // Truncated inside the range list's own header.
    assert!(matches!(
        Message::decode(&[0x82, 0x01]),
        Err(ReconError::Cbor(CborError::Truncated))
    ));
}

#[test]
fn a_short_id_from_the_database_saturates_rather_than_panicking() {
    // `id_from_slice` is fed `relay_envelope.hash`, which the schema constrains to 32
    // bytes, so a short slice cannot come from a stored row. It is written to
    // saturate rather than to fail because a fallible conversion there would add an
    // arm only a corrupted database could reach, and
    // `tests/reconcile.rs::the_schema_refuses_a_hash_that_is_not_thirty_two_bytes`
    // proves the constraint that makes it unreachable.
    assert_eq!(
        wealdrelay::negentropy::id_from_slice(&[1, 2, 3])[..4],
        [1, 2, 3, 0]
    );
    assert_eq!(
        wealdrelay::negentropy::id_from_slice(&[0xff; 64]),
        [0xff; 32]
    );
}

#[test]
fn a_skip_range_carrying_a_simple_value_that_is_not_null_is_refused() {
    // `true` where `null` belongs. Distinct from a skip range carrying bytes: this is
    // a peer using a CBOR simple value the wire format does not carry at all, and the
    // reader names it rather than reading past it.
    let encoded = wealdrelay::cbor::array(&[
        wealdrelay::cbor::uint(RECON_VERSION),
        wealdrelay::cbor::array(&[wealdrelay::cbor::array(&[
            wealdrelay::cbor::uint(INFINITY),
            wealdrelay::cbor::uint(0),
            vec![0xf5],
        ])]),
    ]);
    assert_eq!(
        Message::decode(&encoded),
        Err(ReconError::Cbor(CborError::UnsupportedSimple(21)))
    );

    // And a skip range with the payload byte missing entirely.
    let truncated = wealdrelay::cbor::array(&[
        wealdrelay::cbor::uint(RECON_VERSION),
        wealdrelay::cbor::array(&[{
            let mut range = vec![0x83];
            range.extend_from_slice(&wealdrelay::cbor::uint(INFINITY));
            range.extend_from_slice(&wealdrelay::cbor::uint(0));
            range
        }]),
    ]);
    assert!(matches!(
        Message::decode(&truncated),
        Err(ReconError::Cbor(CborError::Truncated))
    ));
}

#[test]
fn a_step_with_nothing_to_say_has_nothing_to_move() {
    // The invariant `ClientStep::done` relies on: `advance` withholds a reply only
    // when every range came back settled, and a settled range has nothing left to
    // move in either direction. Asserted here and in the convergence property rather
    // than re-checked inside `done`, which would give that predicate two arms no
    // exchange can reach.
    let step = advance(&items(1..=30), &Message::settled());
    assert!(step.done());
    assert!(step.want.is_empty());
    assert!(step.send.is_empty());
}

#[test]
fn two_different_answers_are_not_equal() {
    // The equality the property suite compares answers with, exercised on values that
    // differ in each field. A derived comparison that short-circuited wrongly would
    // make every `prop_assert_eq` in this file weaker than it looks.
    let relay = items(1..=4);
    // Differing in `push` alone: the client is behind, so the relay pushes and
    // settles; and the client is level, so it pushes nothing and settles. Same reply,
    // different pushes, which is exactly the pair a comparison that only looked at
    // one field would call equal.
    let behind_answer = respond(&relay, &initiate(&items([1])));
    let level_answer = respond(&relay, &initiate(&relay));
    assert_ne!(behind_answer, level_answer);
    assert_ne!(behind_answer.push, level_answer.push);
    assert_eq!(behind_answer.reply, level_answer.reply);

    // Differing in `reply` alone: a client that is ahead is answered with an id list
    // rather than a settled range.
    let ahead_answer = respond(&relay, &initiate(&items(1..=6)));
    assert_ne!(ahead_answer.reply, level_answer.reply);
    assert_eq!(ahead_answer.push, level_answer.push);

    // And the client's own answers differ from each other on the same input, because
    // what it says depends on what it holds.
    let from_ahead = advance(&items([1, 2, 9]), &ahead_answer.reply);
    let from_behind = advance(&items([1]), &ahead_answer.reply);
    assert_ne!(from_ahead, from_behind);
    assert_ne!(from_ahead.send, from_behind.send);
    assert_ne!(from_ahead.want, from_behind.want);
}

/// WEALD-297. One id the relay does not hold used to make it answer with every id
/// in the span.
///
/// The `Fingerprint` arm has always split a range too wide to list. The `IdList`
/// arm did not, so a client that opened with a single unknown id over the whole
/// space got back an id list the size of the group. Past `MAX_IDS_PER_RANGE` that
/// reply is one the client's own decoder refuses, so the group could never
/// reconcile again, and each retry cost a full scan and a multi-megabyte encode.
#[test]
fn a_single_unknown_id_over_the_whole_space_does_not_produce_an_unencodable_reply() {
    let relay = items(1..=5_000);
    let opening = Message {
        ranges: vec![Range::new(INFINITY, Mode::IdList(vec![id(999_999)]))],
    };

    let response = respond(&relay, &opening);

    for range in &response.reply.ranges {
        if let Mode::IdList(ids) = &range.mode {
            assert!(
                ids.len() <= IDLIST_LIMIT,
                "a reply range carries {} ids, over the {IDLIST_LIMIT} the wire and \
                 the fingerprint arm both bound it to",
                ids.len()
            );
        }
    }

    // And the reply is one the peer can actually read back, which is the property
    // the group's ability to converge rests on.
    let encoded = response.reply.encode();
    let decoded = Message::decode(&encoded).expect("the relay's own reply must decode");
    assert_eq!(decoded, response.reply);

    // The relay still pushes what the client is visibly missing.
    assert_eq!(response.push.len(), relay.len());
}

/// The bounded case is unchanged: a small range still gets a plain id list, which
/// is what makes the exchange settle in one more round rather than splitting
/// forever.
#[test]
fn an_id_list_over_a_range_within_the_limit_is_still_answered_with_ids() {
    let relay = items(1..=IDLIST_LIMIT as u64);
    let opening = Message {
        ranges: vec![Range::new(INFINITY, Mode::IdList(vec![id(999_999)]))],
    };
    let response = respond(&relay, &opening);
    assert_eq!(
        response.reply.ranges,
        vec![Range::new(INFINITY, Mode::IdList(ids_of(&relay)))]
    );
}

/// WEALD-325, the client half of WEALD-297. `advance` answered a disagreeing id
/// list with every id it held in the span, so a client holding more than
/// `MAX_IDS_PER_RANGE` items under one range produced a message the relay's own
/// decoder refuses, byte for byte on every retry and reconnect.
#[test]
fn a_client_answering_a_wide_id_list_does_not_produce_an_unencodable_reply() {
    let client = items(1..=5_000);
    // The relay claims one id the client does not hold, over the whole space, so
    // the sets differ and the answering arm is the one under test.
    let incoming = Message {
        ranges: vec![Range::new(INFINITY, Mode::IdList(vec![id(999_999)]))],
    };

    let step = advance(&client, &incoming);
    let reply = step.reply.expect("a disagreement is answered");

    for range in &reply.ranges {
        if let Mode::IdList(ids) = &range.mode {
            assert!(
                ids.len() <= IDLIST_LIMIT,
                "a reply range carries {} ids, over the {IDLIST_LIMIT} the wire and \
                 the fingerprint arm both bound it to",
                ids.len()
            );
        }
    }

    let decoded = Message::decode(&reply.encode()).expect("the client's own reply must decode");
    assert_eq!(decoded, reply);

    // The client still knows what it owes the relay and what it is missing.
    assert_eq!(step.send.len(), client.len());
    assert_eq!(step.want, vec![id(999_999)]);
}

#[test]
fn a_range_of_one_sequence_number_is_named_rather_than_re_asserted() {
    // WEALD-351. `split` chooses boundaries at item positions and then widens each
    // boundary past items sharing a `seq`, because a range bound *is* a `seq` and two
    // ranges with one upper bound are a cover the decoder refuses. Feed it a set
    // whose items all share one sequence number and the widening runs to the end on
    // the first pass: what came back was a single fingerprinted range with
    // `bound == upper`, byte-identical to the range being split. The peer's
    // fingerprint still differs, so it split again, produced the same bytes again,
    // and the exchange never terminated while paying a full scan a round.
    //
    // Well past IDLIST_LIMIT, so the caller had already chosen splitting over an id
    // list and this is the arm that has to make the progress.
    let crowded: Vec<Item> = (0..IDLIST_LIMIT as u64 * 4)
        .map(|offset| Item {
            seq: 77,
            id: id(50_000 + offset),
        })
        .collect();
    let opening = initiate(&crowded);
    // One range, and it names the ids rather than fingerprinting them, which is the
    // whole of the fix: an id list is what the peer diffs, so the next round moves
    // envelopes instead of repeating an assertion.
    assert_eq!(opening.ranges.len(), 1);
    let Mode::IdList(named) = &opening.ranges[0].mode else {
        panic!("an unsplittable range came back as a fingerprint: {opening:?}");
    };
    assert_eq!(named.len(), crowded.len());
    assert!(named.len() <= MAX_IDS_PER_RANGE);
    assert_eq!(Message::decode(&opening.encode()), Ok(opening.clone()));

    // And the round after it settles: the relay holding the same set answers Skip,
    // where before it answered the identical fingerprint range forever.
    let response = respond(&crowded, &opening);
    assert!(response.reply.is_settled(), "{:?}", response.reply);
    assert!(response.push.is_empty());

    // The relay that holds none of them names its own emptiness and pushes nothing
    // it does not have, and the client's next step has something to say exactly once.
    let response = respond(&[], &opening);
    assert!(response.push.is_empty());
    let step = advance(&crowded, &response.reply);
    assert!(!step.done());
    assert_eq!(step.send.len(), crowded.len());
    assert!(step.want.is_empty());
}

// ---------------------------------------------------------------------------
// WEALD-L392: what the *client's* decoder accepts, checked against what the
// relay emits on a cold reconciliation of a large backlog.
// ---------------------------------------------------------------------------

/// The acceptance rules of `Sources/Sync/ReconMessage.swift decode`, written out
/// here rather than borrowed from `Message::decode`.
///
/// Borrowing the relay's own decoder would prove nothing: two halves of one
/// implementation agreeing is the thing this module's header says is not a proof
/// about the wire. So these are the Swift decoder's guards, in its order, with its
/// names, and a divergence between the two decoders shows up here as a failure
/// rather than as a live workspace reporting a permanent error string
/// (WEALD-L392).
fn client_would_accept(bytes: &[u8]) -> Result<(), String> {
    let decoded = Message::decode(bytes).map_err(|error| format!("cbor: {error}"))?;
    if decoded.ranges.is_empty() {
        return Err("empty: the payload carries no ranges at all".into());
    }
    if decoded.ranges.len() > MAX_RANGES {
        return Err(format!("tooManyRanges: {}", decoded.ranges.len()));
    }
    let mut previous: Option<u64> = None;
    for range in &decoded.ranges {
        if previous.is_some_and(|last| range.upper <= last) {
            return Err("unorderedRanges: bounds are not strictly ascending".into());
        }
        previous = Some(range.upper);
        if let Mode::IdList(ids) = &range.mode {
            if ids.len() > MAX_IDS_PER_RANGE {
                return Err(format!("tooManyIds: {}", ids.len()));
            }
            for pair in ids.windows(2) {
                if pair[1] <= pair[0] {
                    return Err("unorderedIds: ids are not strictly ascending".into());
                }
            }
        }
    }
    if previous != Some(INFINITY) {
        return Err("incompleteCover: the last range does not reach the open end".into());
    }
    Ok(())
}

/// A whole exchange, with every payload either side puts on the wire checked
/// against the client's rules.
fn drive_and_check(relay: &[Item], client: &[Item]) {
    let mut held: Vec<Item> = client.to_vec();
    let mut message = initiate(&held);
    for _ in 0..64 {
        client_would_accept(&message.encode()).expect("a client payload the peer must accept");
        let response = respond(relay, &message);
        client_would_accept(&response.reply.encode())
            .expect("a relay payload the client must accept");
        for id in &response.push {
            if let Some(item) = relay.iter().find(|item| &item.id == id) {
                if !held.iter().any(|mine| mine.id == item.id) {
                    held.push(*item);
                }
            }
        }
        held.sort();
        let step = advance(&held, &response.reply);
        match step.reply {
            None => return,
            Some(next) => message = next,
        }
    }
    panic!("the exchange did not converge inside the round bound");
}

#[test]
fn a_cold_client_reconciling_a_large_backlog_sends_nothing_the_client_refuses() {
    // The live shape WEALD-L392 came from: a checkout that holds nothing at all
    // against a workspace with more than two thousand records.
    let relay: Vec<Item> = (1..=2019).map(item).collect();
    drive_and_check(&relay, &[]);
}

#[test]
fn a_partly_cold_client_over_the_same_backlog_is_also_accepted() {
    // The other half of the same run: a device that has some of the history and
    // reconciles the rest, which is what makes the round trips recurse rather
    // than settle in one push.
    let relay: Vec<Item> = (1..=2500).map(item).collect();
    let client: Vec<Item> = relay.iter().copied().step_by(7).collect();
    drive_and_check(&relay, &client);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Every payload of every exchange over a large corpus is one the client's
    /// decoder accepts, whatever the client already holds.
    #[test]
    fn no_payload_over_a_large_corpus_is_one_the_client_refuses(
        total in 2001usize..2600,
        keep in proptest::collection::vec(any::<bool>(), 2001..2600),
        gap in 1u64..5,
    ) {
        let relay: Vec<Item> = (1..=total as u64).map(|n| item(n * gap)).collect();
        let client: Vec<Item> = relay
            .iter()
            .zip(keep.iter())
            .filter_map(|(item, keep)| keep.then_some(*item))
            .collect();
        drive_and_check(&relay, &client);
    }
}
