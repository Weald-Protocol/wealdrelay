// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Key packages: the one shelf the relay keeps in the clear.
//!
//! `specs/backend/relay/private-messaging.md`. A device publishes MLS key
//! packages so that somebody who wants to open a private conversation with it can
//! add it to a group without the two of them ever being online together. The relay
//! holds them, hands them out one at a time, and deletes what it hands out.
//!
//! ## Why this is a frame and not an event kind
//!
//! Two reasons, and both are structural rather than convenient. A key package is
//! cleartext by construction, because it is the object that bootstraps encryption
//! and there is no earlier key to seal it under. And the relay has to index it by
//! device key to serve a fetch at all, which is a lookup it cannot perform on an
//! envelope whose kind lives inside `ct` under `enc: 1`. Both facts point the same
//! way: this belongs on the wire where the relay can see it, and it must not be
//! mistaken for content.
//!
//! ## What the relay learns, stated plainly
//!
//! That a device published key packages, and that some other device in the same
//! workspace fetched one. That is a correlation the relay genuinely has and the
//! product does not pretend otherwise: `specs/privacy-posture.md` carries it, and
//! the client's mitigation is to prefetch the whole roster on first use rather
//! than at conversation-open time, so a fetch does not time-correlate with the
//! intent to talk to a particular person.
//!
//! ## One-time by construction
//!
//! A package served twice would hand two different dm groups the same joiner leaf
//! key, which is the one failure this shelf exists to prevent. So a fetch consumes
//! in the same statement that selects, under `for update skip locked`, and the
//! property test asserts across arbitrary interleavings that no package is ever
//! served twice.

pub mod store;

use std::sync::Arc;

use crate::frame::{ErrorCode, Frame, FrameError, KeysBody};
use crate::health::RelayState;
use crate::session::Session;

/// The most packages one device may have outstanding.
///
/// A hundred, which `specs/backend/relay/wire.md` already states. Over the cap is
/// refused rather than evicting the oldest: a silent discard would leave a
/// publisher believing it had a shelf, and the first person who tried to add it to
/// a conversation would get an unaddable member with no error anywhere.
pub const MAX_OUTSTANDING: i64 = 100;

/// How long a published package is good for. Ninety days, matching the column
/// comment in `migrations/0001_relay_schema.sql`.
pub const LIFETIME_DAYS: i64 = 90;

/// Serve one `KEYS` frame.
///
/// The session is `Ready` and its budget has already been charged by
/// `session.rs`; what is decided here is everything that needs the database.
pub async fn handle(state: &Arc<RelayState>, session: &Session, body: KeysBody) -> Frame {
    let Some(database) = &state.database else {
        return Frame::Error(FrameError::new(ErrorCode::Backpressure));
    };
    let Some(workspace) = session.authorized_workspace() else {
        // The same refusal a stranger gets. Reachable with
        // `WEALD_RELAY_ACCESS_SET=off`, the one mode that admits a session with no
        // workspace claim, and a shelf belongs to a workspace.
        return Frame::Error(FrameError::new(ErrorCode::WriterNotInAccessSet));
    };
    let Some(device_key) = session.device_key() else {
        return Frame::Error(FrameError::new(ErrorCode::WriterNotInAccessSet));
    };
    let pool = database.pool();

    match body {
        KeysBody::Publish { packages } => {
            match store::publish(pool, workspace, device_key, &packages).await {
                Ok(store::Published::Stored { remaining }) => {
                    Frame::Keys(KeysBody::Published { remaining })
                }
                // Over the cap. `quota`, because the lever that clears it is time
                // and consumption rather than a change to the request.
                Ok(store::Published::OverCap) => Frame::Error(
                    FrameError::new(ErrorCode::SeatsExhausted)
                        .detail((MAX_OUTSTANDING as u64).to_be_bytes()),
                ),
                Err(_) => Frame::Error(FrameError::new(ErrorCode::Backpressure)),
            }
        }
        KeysBody::Fetch { device, count } => {
            // Both devices in the access set of the same workspace, checked
            // against the target rather than only the requester. Without it any
            // admitted device could enumerate a shelf belonging to a workspace it
            // is not in, which is a membership oracle as well as a theft of
            // one-time keys.
            match crate::access::store::admits(pool, workspace, &device).await {
                Ok(crate::access::store::Admission::Refused) => {
                    return Frame::Error(FrameError::new(ErrorCode::WriterNotInAccessSet))
                }
                Ok(_) => {}
                Err(_) => return Frame::Error(FrameError::new(ErrorCode::Backpressure)),
            }
            match store::fetch(pool, workspace, &device, count).await {
                // An empty shelf is not an error. The correct client behaviour is
                // to wait for the peer to top up rather than to retry, and an error
                // would invite exactly the retry loop that drains a shelf.
                Ok(packages) if packages.is_empty() => Frame::Keys(KeysBody::None),
                Ok(packages) => Frame::Keys(KeysBody::Bundles { packages }),
                Err(_) => Frame::Error(FrameError::new(ErrorCode::Backpressure)),
            }
        }
        // `session.rs` refuses the relay-to-client forms before they reach here,
        // and closes the connection when one arrives. This arm exists because the
        // type is one enum in both directions; it is the same answer the session
        // table gives, so the two cannot disagree.
        KeysBody::Published { .. } | KeysBody::Bundles { .. } | KeysBody::None => {
            Frame::Error(FrameError::new(ErrorCode::MalformedHeader))
        }
    }
}
