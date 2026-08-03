// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The live path: who is subscribed to what, and the fanout onto them.
//!
//! `specs/backend/relay/wire.md`: "after reconciliation the client holds an open
//! subscription and the relay pushes envelopes as they are accepted. No polling.
//! This is the entire `latency` 2-to-5 move." This module is the registry that
//! makes that sentence true, and it is deliberately the whole of it: one map from
//! group id to the connections that asked for it.
//!
//! ## What it is not allowed to know
//!
//! A group id and a connection handle. Nothing else. No device key, no principal,
//! no count per author, nothing derived from `ct`. The relay serves any group in
//! the workspace to any device in the access set precisely so that this map cannot
//! become a membership graph (`wire.md`, the access set section), and a field here
//! naming who is subscribed to which group would be exactly the membership signal
//! the product claims the operator does not have.
//!
//! ## Backpressure, not dropping
//!
//! Fanout uses ``crate::ws::try_queue``, so a subscriber whose queue is full is
//! **downgraded and told**, never silently skipped: `operations.md` requires that a
//! dropped envelope is impossible, because a hole in an author chain is a security
//! alarm on somebody else's screen. The downgrade frame tells the client it is now
//! responsible for catching up by reconciliation, which is the mechanism step 5
//! adds and which is why the downgrade only becomes honest in this step.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::Mutex;

use crate::frame::Frame;
use crate::ws::{downgrade_frame, try_queue, OutboundSender, Queued};

/// One connection's identity inside the hub. Opaque and per process: it exists so
/// a connection does not receive its own writes back, and so a disconnect can
/// remove exactly one entry.
pub type ConnectionId = u64;

/// One authenticated socket belonging to a principal: the connection to skip or
/// close, and the channel revocation has to reach.
type PrincipalConnection = (ConnectionId, OutboundSender);

/// What fanout did to one subscriber, which is what the caller logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Queued for delivery.
    Sent,
    /// Queue full: the subscriber was downgraded to reconciliation and told so.
    Downgraded,
    /// The connection has gone. Its entry is removed.
    Gone,
}

/// The subscriber registry.
#[derive(Debug, Default)]
pub struct Hub {
    /// Group id to subscribers.
    ///
    /// `tokio::sync::Mutex` rather than `std::sync::Mutex`, for one reason: the std
    /// lock poisons on a panic, and the recovery arm that would then be needed is a
    /// line no test can reach honestly, because nothing inside a critical section
    /// here can panic. A lock with no poisoning has no arm to leave uncovered. The
    /// critical sections are a map lookup and a `try_send`, both non-blocking, so
    /// nothing is held across an await inside them.
    groups: Mutex<HashMap<Vec<u8>, Vec<Subscriber>>>,
    next_id: AtomicU64,
    /// How many subscribers have been downgraded to reconciliation because their
    /// queue was full. An operator counter with no content-derived label, which is
    /// what `operations.md` asks for: a relay shedding to reconciliation under load
    /// is a capacity signal, and one that only told the affected client would leave
    /// the operator unable to see it at all.
    downgrades: AtomicU64,
    /// Which live connections belong to which principal, by salted entry hash.
    ///
    /// The one thing in this registry that is about a device rather than a group,
    /// and it is here because revocation has to reach a socket. `wire.md`: "an
    /// `ACCESS` frame that drops an entry causes the relay to close that device's
    /// open connections immediately". Without this map the relay could refuse the
    /// next connection and would leave the current one running until the client
    /// chose to close it, which is offboarding that does not offboard.
    ///
    /// A hash and never a key, so this holds no more about a principal than
    /// `relay_access_entry` does. A connection that has not authenticated is absent.
    principals: Mutex<HashMap<Vec<u8>, Vec<PrincipalConnection>>>,
}

#[derive(Debug)]
struct Subscriber {
    id: ConnectionId,
    sender: OutboundSender,
    /// Set when this subscriber's queue was full and the downgrade frame could not
    /// be queued either, which is the normal case: the queue is full precisely when
    /// there is no room for anything.
    ///
    /// Kept rather than dropped, because `operations.md` requires that a downgraded
    /// subscriber is *told* it must reconcile. The frame goes out ahead of the next
    /// envelope this subscriber can accept, so the client learns before it is given
    /// anything it might otherwise mistake for a complete live stream.
    downgrade_owed: bool,
}

impl Hub {
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh connection id.
    pub fn connect(&self) -> ConnectionId {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Register interest in a group. Idempotent per connection: a client that
    /// re-subscribes after a downgrade must not end up receiving every envelope
    /// twice.
    pub async fn subscribe(&self, group: &[u8], id: ConnectionId, sender: OutboundSender) {
        let mut groups = self.lock().await;
        let subscribers = groups.entry(group.to_vec()).or_default();
        if subscribers.iter().any(|subscriber| subscriber.id == id) {
            return;
        }
        subscribers.push(Subscriber {
            id,
            sender,
            downgrade_owed: false,
        });
    }

    /// Record that a connection authenticated as one principal.
    ///
    /// Called once per connection, after `AUTH` succeeds. Idempotent, because a
    /// second call for one connection would leave a stale sender behind after the
    /// first close.
    pub async fn identify(&self, entry_hash: &[u8], id: ConnectionId, sender: OutboundSender) {
        let mut principals = self.principals.lock().await;
        let connections = principals.entry(entry_hash.to_vec()).or_default();
        if connections.iter().any(|(existing, _)| *existing == id) {
            return;
        }
        connections.push((id, sender));
    }

    /// Close every open connection held by one principal, now.
    ///
    /// Returns how many were closed, which is what the disconnect timing in step 6's
    /// evidence is measured from. A connection that has already gone counts as
    /// closed: the outcome the caller asked for is that it is not connected.
    pub async fn evict(&self, entry_hash: &[u8]) -> usize {
        let taken = {
            let mut principals = self.principals.lock().await;
            principals.remove(entry_hash).unwrap_or_default()
        };
        let count = taken.len();
        for (id, sender) in taken {
            // Best effort, deliberately. A sender whose receiver has gone is a
            // connection that is already closed, and treating that as a failure
            // would make revocation look unreliable when it had already succeeded.
            let _ = sender.close().await;
            self.disconnect(id).await;
        }
        count
    }

    /// How many live connections one principal holds. For `/readyz` and the tests.
    pub async fn connections_for(&self, entry_hash: &[u8]) -> usize {
        self.principals
            .lock()
            .await
            .get(entry_hash)
            .map_or(0, Vec::len)
    }

    /// Drop every subscription a connection holds. Called when its socket ends,
    /// including when it ends badly: a hub that leaked an entry per dropped
    /// connection would fan out to senders nobody is reading, once per accepted
    /// envelope, forever.
    pub async fn disconnect(&self, id: ConnectionId) {
        {
            let mut groups = self.lock().await;
            for subscribers in groups.values_mut() {
                subscribers.retain(|subscriber| subscriber.id != id);
            }
            // Empty groups are removed rather than left as empty vectors, so a relay
            // that has served a million groups does not hold a million keys.
            groups.retain(|_, subscribers| !subscribers.is_empty());
        }
        let mut principals = self.principals.lock().await;
        for connections in principals.values_mut() {
            connections.retain(|(existing, _)| *existing != id);
        }
        principals.retain(|_, connections| !connections.is_empty());
    }

    /// How many connections are subscribed to a group. For `/readyz` counts and
    /// for the tests; never per-device and never exported per group to a client.
    pub async fn subscribers(&self, group: &[u8]) -> usize {
        self.lock().await.get(group).map_or(0, Vec::len)
    }

    /// How many downgrades this process has performed.
    pub fn downgrades(&self) -> u64 {
        self.downgrades.load(Ordering::Relaxed)
    }

    /// Push one envelope to every subscriber except its writer.
    ///
    /// The writer is excluded because it already has the envelope and has been
    /// answered with a `SEND_ACK` carrying the sequence number; pushing it back
    /// would double every local write.
    /// Fan one envelope out, as a `PUSH`.
    pub async fn fanout(
        &self,
        group: &[u8],
        envelope: &[u8],
        except: ConnectionId,
    ) -> Vec<(ConnectionId, Delivery)> {
        self.fanout_frame(
            group,
            &Frame::Push {
                envelope: envelope.to_vec(),
            },
            except,
        )
        .await
    }

    /// Fan one frame out to a group's subscribers.
    ///
    /// Generalised in step 8, when MLS handshake messages became a frame of their
    /// own: they are fanned out on exactly the same terms as envelopes, including
    /// the downgrade owed to a subscriber whose queue is full, and duplicating that
    /// logic for a second frame is how the two would drift apart.
    pub async fn fanout_frame(
        &self,
        group: &[u8],
        frame: &Frame,
        except: ConnectionId,
    ) -> Vec<(ConnectionId, Delivery)> {
        let mut outcomes = Vec::new();
        let mut gone = Vec::new();
        {
            let mut groups = self.lock().await;
            let Some(subscribers) = groups.get_mut(group) else {
                return outcomes;
            };
            for subscriber in subscribers.iter_mut() {
                if subscriber.id == except {
                    continue;
                }
                // A downgrade owed from an earlier round goes out first, ahead of
                // anything this subscriber might otherwise read as a complete live
                // stream. Only once it has been queued is the subscriber live again.
                if subscriber.downgrade_owed {
                    match try_queue(&subscriber.sender, downgrade_frame(group)) {
                        Queued::Sent => subscriber.downgrade_owed = false,
                        Queued::Full => {
                            outcomes.push((subscriber.id, Delivery::Downgraded));
                            continue;
                        }
                        Queued::Closed => {
                            gone.push(subscriber.id);
                            outcomes.push((subscriber.id, Delivery::Gone));
                            continue;
                        }
                    }
                }
                let delivery = match try_queue(&subscriber.sender, frame.clone()) {
                    Queued::Sent => Delivery::Sent,
                    Queued::Full => {
                        // Told, not dropped. The queue is full, so the frame that
                        // says so cannot go out now either; it is owed and goes out
                        // ahead of the next envelope this subscriber can take. What
                        // must never happen is a silently discarded envelope, and
                        // nothing here discards one: the sender keeps everything it
                        // accepted, and the client is told to reconcile for the rest.
                        //
                        // Reached only when nothing was owed already: a subscriber
                        // that still owes a downgrade took the early exit above, so
                        // the counter moves once per downgrade rather than once per
                        // envelope refused while one is outstanding.
                        subscriber.downgrade_owed = true;
                        self.downgrades.fetch_add(1, Ordering::Relaxed);
                        Delivery::Downgraded
                    }
                    Queued::Closed => {
                        gone.push(subscriber.id);
                        Delivery::Gone
                    }
                };
                outcomes.push((subscriber.id, delivery));
            }
        }
        // Outside the lock above, because `disconnect` takes it. A closed sender is
        // a connection whose reader loop has not yet run its own cleanup, and
        // leaving it would make the next fanout do the same work again.
        for id in gone {
            self.disconnect(id).await;
        }
        outcomes
    }

    /// The lock. Infallible, because a `tokio::sync::Mutex` does not poison.
    async fn lock(&self) -> tokio::sync::MutexGuard<'_, HashMap<Vec<u8>, Vec<Subscriber>>> {
        self.groups.lock().await
    }
}
