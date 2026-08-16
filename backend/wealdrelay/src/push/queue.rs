// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The bounded wake queue and the coalescing state machine.
//!
//! Pure, and deliberately so: no clock, no network, no database, no lock. Every
//! rule in `specs/backend/relay/push.md` section 4 about *which* wakes are sent is
//! decided here, so all of them are reachable from an in-process test with a
//! hand-advanced `now_ms` and none of them needs a listener to prove.
//!
//! ## The four rules, and why each is a rule
//!
//! - **One wake per handle per window.** A burst of twenty envelopes into a busy
//!   group is one notification on the device, because twenty is not more informative
//!   than one and the ringer learning twenty timings rather than one is a metadata
//!   leak for no benefit.
//! - **`call` is exempt.** A ring that arrives two seconds late is a missed call.
//! - **A `call` supersedes a pending `message` for the same handle.** The device is
//!   about to be woken with something strictly more urgent, and sending both would
//!   put two notifications on a Lock Screen for one event.
//! - **A `message` for a handle with a pending `call` is redundant.** The same fact
//!   from the other direction, and it is dropped rather than queued behind.
//!
//! ## The bound is a bound
//!
//! At the ceiling the **oldest** entry goes, not the newest. A wake is a hint that
//! something happened, and the newest hint is the one whose notification is still
//! worth delivering; shedding the newest would make a relay under load stop waking
//! anybody while still holding a full queue.

use std::collections::VecDeque;

use super::Category;

/// What admitting one wake did to the queue.
///
/// Five outcomes rather than a boolean, because the operator counter and the tests
/// both need to tell "coalesced into an existing window" from "dropped at the
/// bound", and a boolean would have made those the same answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Added, with a window of its own.
    Queued,
    /// Folded into a window that was already open for this handle.
    Coalesced,
    /// A `call` took over a pending `message` for this handle and is due now.
    Superseded,
    /// A `message` behind a pending `call` for this handle. Not sent.
    Redundant,
    /// Added, and the oldest waiting wake was discarded to make room.
    Dropped,
}

/// One waiting wake.
///
/// No `Debug` that prints the handle, for the reason `WakeBody` has none: this
/// struct is inside a queue inside the relay state, and a state dump that formatted
/// it would put a live wake capability in whatever was reading.
#[derive(Clone, PartialEq, Eq)]
struct Entry {
    handle: Vec<u8>,
    category: Category,
    /// When this wake leaves the queue. `now` for an urgent one, `now + window`
    /// otherwise.
    due_at: u64,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The category and the deadline are operational; the handle is not.
        f.debug_struct("Entry")
            .field("handle", &crate::logging::NeverLogged)
            .field("category", &self.category)
            .field("due_at", &self.due_at)
            .finish()
    }
}

/// The queue itself.
#[derive(Debug)]
pub struct Queue {
    bound: usize,
    entries: VecDeque<Entry>,
}

impl Queue {
    /// A queue with room for `bound` waiting wakes.
    ///
    /// Clamped to at least one, so a queue that cannot hold anything is not
    /// representable. `Config` refuses a zero bound on the way in, and clamping here
    /// means this type has no state in which `admit` would have to answer for a
    /// capacity nobody chose.
    pub fn new(bound: usize) -> Self {
        Self {
            bound: bound.max(1),
            entries: VecDeque::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn bound(&self) -> usize {
        self.bound
    }

    /// Apply the four rules to one incoming wake.
    pub fn admit(
        &mut self,
        handle: Vec<u8>,
        category: Category,
        now_ms: u64,
        coalesce_ms: u64,
    ) -> Admit {
        if let Some(existing) = self.entries.iter_mut().find(|entry| entry.handle == handle) {
            if existing.category.is_urgent() {
                // A ring is already waiting for this device. Anything else about the
                // same device is redundant, including a second ring: one wake and one
                // ring are the same notification.
                return if category.is_urgent() {
                    Admit::Coalesced
                } else {
                    Admit::Redundant
                };
            }
            if category.is_urgent() {
                existing.category = category;
                existing.due_at = now_ms;
                return Admit::Superseded;
            }
            // Two non-urgent categories inside one window. The first one's category
            // is kept rather than merged, because the wire carries one category per
            // wake and a device woken for a message it turns out was a handshake
            // reconciles either way: the payload says nothing beyond the category and
            // the client's next act is to read the log.
            return Admit::Coalesced;
        }

        let due_at = if category.is_urgent() {
            now_ms
        } else {
            now_ms.saturating_add(coalesce_ms)
        };
        let entry = Entry {
            handle,
            category,
            due_at,
        };
        if self.entries.len() >= self.bound {
            // Shed the oldest non-urgent entry. A ring waiting for a device is the one
            // wake that cannot be regenerated by the client reading its log, so a flood
            // of ordinary envelopes must never evict it.
            if let Some(index) = self
                .entries
                .iter()
                .position(|existing| !existing.category.is_urgent())
            {
                self.entries.remove(index);
                self.entries.push_back(entry);
                return Admit::Dropped;
            }
            // Every waiting entry is urgent. An ordinary wake yields to them; another
            // ring sheds the oldest ring.
            if !entry.category.is_urgent() {
                return Admit::Dropped;
            }
            self.entries.pop_front();
            self.entries.push_back(entry);
            return Admit::Dropped;
        }
        self.entries.push_back(entry);
        Admit::Queued
    }

    /// The earliest moment the worker has something to do, if anything.
    pub fn next_deadline(&self) -> Option<u64> {
        self.entries.iter().map(|entry| entry.due_at).min()
    }

    /// Take everything whose window has closed, oldest first.
    ///
    /// Insertion order among equally due entries, which is the order the bursts
    /// arrived in. Nothing downstream depends on it, and a stable order means a
    /// recorded test vector of a batch is reproducible.
    pub fn take_due(&mut self, now_ms: u64) -> Vec<(Vec<u8>, Category)> {
        let mut due = Vec::new();
        let mut kept = VecDeque::with_capacity(self.entries.len());
        for entry in std::mem::take(&mut self.entries) {
            if entry.due_at <= now_ms {
                due.push((entry.handle, entry.category));
            } else {
                kept.push_back(entry);
            }
        }
        self.entries = kept;
        due
    }
}
