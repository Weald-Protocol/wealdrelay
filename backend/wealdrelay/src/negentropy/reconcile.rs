// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The two roles: the relay answering a round, and the client driving one.
//!
//! Both are pure functions over a sorted item slice and one message. No database,
//! no socket, no clock. That is what makes the convergence property in
//! `tests/negentropy.rs` a property test rather than an integration test: the same
//! code the relay runs is driven ten thousand times against randomised set
//! partitions and randomised arrival order, which is the gate step 5 asks for.
//!
//! ## The round, end to end
//!
//! 1. The client sends fingerprints over a cover of the sequence space
//!    (``initiate``).
//! 2. The relay compares each range against its own items (``respond``). Equal
//!    fingerprints come back settled. A differing range comes back as an id list
//!    if it is small, and as sub-fingerprints if it is not, so the recursion is
//!    O(diff) rather than O(history).
//! 3. The client diffs an id list against what it holds (``advance``). Ids the
//!    relay has and it does not are wanted; ids it has and the relay does not are
//!    sent. It answers with its own id list, which is what tells the relay to push.
//! 4. The relay, receiving an id list, pushes the envelopes the client is missing
//!    and settles the range.
//!
//! The client `SEND`s its extra envelopes **before** the answering `RECON` on the
//! same socket, so by the time the relay diffs the id list the writes have already
//! landed. Frames on one WebSocket are ordered, so that is a guarantee rather than
//! a hope.
//!
//! ## Termination
//!
//! Every round either settles a range or divides it by ``SPLIT_FACTOR``, and a
//! range holding one item cannot be divided further, so the exchange terminates in
//! at most `log8(n) + 2` rounds. ``ClientStep::done`` is the client's own view of
//! it: every range settled and nothing left to move. A relay that kept sending
//! differing fingerprints for a range that cannot shrink would be caught by the
//! round bound in the property suite rather than by trust.

use std::collections::BTreeSet;

use super::{
    fingerprint, ids_of, items_in, Id, Item, Message, Mode, Range, IDLIST_LIMIT, INFINITY,
    SPLIT_FACTOR,
};

/// What the relay decided about one round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The answering message.
    pub reply: Message,
    /// Envelopes the client is missing, to be pushed. Ascending, deduplicated: the
    /// caller turns each into a `PUSH` frame and a stable order makes the resulting
    /// frame sequence reproducible in the evidence bundle.
    pub push: Vec<Id>,
}

/// What the client decided about one round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientStep {
    /// The next message, or `None` when there is nothing left to say.
    pub reply: Option<Message>,
    /// Ids the relay holds and the client does not. Informational: they arrive as
    /// `PUSH` frames once the relay sees the answering id list. Carried out
    /// explicitly so a client can report "17 behind" rather than a spinner.
    pub want: Vec<Id>,
    /// Ids the client holds and the relay does not. The client `SEND`s these.
    pub send: Vec<Id>,
}

impl ClientStep {
    /// Whether the exchange is over.
    ///
    /// Having nothing to say is the whole of it: ``advance`` withholds a reply only
    /// when every range came back settled, and a settled range is one with nothing
    /// left to move in either direction. So a step with no reply also has an empty
    /// `want` and an empty `send`, and that is asserted as an invariant by
    /// `tests/negentropy.rs::a_step_with_nothing_to_say_has_nothing_to_move` rather
    /// than re-checked here: a predicate that tested all three would have two arms
    /// no exchange can reach, and an unreachable arm is a coverage exclusion wearing
    /// a different hat.
    pub fn done(&self) -> bool {
        self.reply.is_none()
    }
}

/// The client's opening message: a cover of the sequence space over what it holds.
///
/// A small set goes out as an id list rather than as a fingerprint, which saves a
/// round trip in the common case of a client that has been away for an hour. An
/// empty set is one range with an empty id list, which tells the relay "I have
/// nothing, push everything" in one frame.
pub fn initiate(items: &[Item]) -> Message {
    if items.len() <= IDLIST_LIMIT {
        return Message {
            ranges: vec![Range::new(INFINITY, Mode::IdList(ids_of(items)))],
        };
    }
    Message {
        ranges: split(items, INFINITY),
    }
}

/// Divide a set of items into at most ``SPLIT_FACTOR`` fingerprinted ranges, the
/// last of which ends at `upper`.
///
/// Boundaries are chosen at item positions rather than by dividing the numeric
/// space, so a corpus whose sequence numbers are sparse in one region and dense in
/// another still splits into equal-sized buckets. Dividing the space instead is the
/// obvious implementation and it degrades to a linear scan on exactly the history
/// that has had a compaction run over it.
fn split(items: &[Item], upper: u64) -> Vec<Range> {
    let bucket = items.len().div_ceil(SPLIT_FACTOR).max(1);
    let mut ranges = Vec::new();
    let mut index = 0usize;
    while index < items.len() {
        let mut end = (index + bucket).min(items.len());
        // Items sharing a sequence number stay in one range. A range boundary is a
        // `seq`, so splitting between two items with the same one would produce two
        // ranges with the same upper bound, which the decoder refuses as a cover
        // whose bounds do not ascend. The relay's own set cannot contain a
        // duplicate, because `(group_id, seq)` is unique in the schema, but a
        // client's can: a relay that renumbered an envelope hands it a second item
        // at a sequence number it already holds, and that is a case to reconcile
        // rather than to encode into an invalid message. The property suite found
        // this, which is what it is for.
        while end < items.len() && items[end].seq == items[end - 1].seq {
            end += 1;
        }
        let chunk = &items[index..end];
        // The bound is the next item's `seq`, so the range is half-open and the
        // next range starts exactly where this one stops. The final chunk takes
        // `upper` so the cover reaches the open end.
        let bound = if end == items.len() {
            upper
        } else {
            items[end].seq
        };
        ranges.push(Range::new(bound, Mode::Fingerprint(fingerprint(chunk))));
        index = end;
    }
    ranges
}

/// The relay's answer to one round.
///
/// `local` is every item the relay holds for the group, sorted by `seq`.
pub fn respond(local: &[Item], incoming: &Message) -> Response {
    let mut ranges = Vec::new();
    let mut push: BTreeSet<Id> = BTreeSet::new();

    for (lower, upper, mode) in incoming.spans() {
        let mine = items_in(local, lower, upper);
        match mode {
            // Already settled by the peer. Answered in kind rather than
            // re-examined: a side that has said a range is done does not get to be
            // argued with, and re-fingerprinting it would make the exchange
            // non-terminating whenever a write landed mid-round.
            Mode::Skip => ranges.push(Range::new(upper, Mode::Skip)),
            Mode::Fingerprint(theirs) => {
                let ours = fingerprint(mine);
                if &ours == theirs {
                    ranges.push(Range::new(upper, Mode::Skip));
                } else if mine.len() <= IDLIST_LIMIT {
                    ranges.push(Range::new(upper, Mode::IdList(ids_of(mine))));
                } else {
                    ranges.extend(split(mine, upper));
                }
            }
            Mode::IdList(theirs) => {
                let theirs: BTreeSet<Id> = theirs.iter().copied().collect();
                let ours = ids_of(mine);
                for id in &ours {
                    if !theirs.contains(id) {
                        push.insert(*id);
                    }
                }
                // Settled only when the client holds nothing the relay does not.
                // Otherwise the client is told what the relay has, so it can see
                // which of its own ids never arrived and resend them.
                let ours_set: BTreeSet<Id> = ours.iter().copied().collect();
                if theirs.is_subset(&ours_set) {
                    ranges.push(Range::new(upper, Mode::Skip));
                } else {
                    ranges.push(Range::new(upper, Mode::IdList(ours)));
                }
            }
        }
    }

    Response {
        reply: Message { ranges },
        push: push.into_iter().collect(),
    }
}

/// The client's answer to one round.
///
/// `local` is every item the client holds for the group **including** anything
/// pushed since the last round, sorted by `seq`. Feeding a stale set is the one way
/// to make the exchange loop, so the caller applies pushes before calling.
pub fn advance(local: &[Item], incoming: &Message) -> ClientStep {
    let mut ranges = Vec::new();
    let mut want: BTreeSet<Id> = BTreeSet::new();
    let mut send: BTreeSet<Id> = BTreeSet::new();
    let mut anything_to_say = false;

    for (lower, upper, mode) in incoming.spans() {
        let mine = items_in(local, lower, upper);
        match mode {
            Mode::Skip => ranges.push(Range::new(upper, Mode::Skip)),
            Mode::Fingerprint(theirs) => {
                let ours = fingerprint(mine);
                if &ours == theirs {
                    ranges.push(Range::new(upper, Mode::Skip));
                } else if mine.len() <= IDLIST_LIMIT {
                    anything_to_say = true;
                    ranges.push(Range::new(upper, Mode::IdList(ids_of(mine))));
                } else {
                    anything_to_say = true;
                    ranges.extend(split(mine, upper));
                }
            }
            Mode::IdList(theirs) => {
                let ours = ids_of(mine);
                let ours_set: BTreeSet<Id> = ours.iter().copied().collect();
                for id in theirs {
                    if !ours_set.contains(id) {
                        want.insert(*id);
                    }
                }
                let theirs_set: BTreeSet<Id> = theirs.iter().copied().collect();
                for id in &ours {
                    if !theirs_set.contains(id) {
                        send.insert(*id);
                    }
                }
                if ours_set == theirs_set {
                    ranges.push(Range::new(upper, Mode::Skip));
                } else {
                    // The answering id list is what makes the relay push what this
                    // client is missing, so it goes out even when the only
                    // difference is in the client's favour.
                    anything_to_say = true;
                    ranges.push(Range::new(upper, Mode::IdList(ours)));
                }
            }
        }
    }

    ClientStep {
        reply: anything_to_say.then_some(Message { ranges }),
        want: want.into_iter().collect(),
        send: send.into_iter().collect(),
    }
}
