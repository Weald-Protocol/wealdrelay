// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Which address the pre-authentication budgets charge, as a pure function.
//!
//! Both of the relay's unauthenticated defences key on one value: the
//! per-source connection bucket in `health::admit_connection` and the invite
//! code's per-source cooldown in `invite::reserve`. Before
//! `WEALD_RELAY_TRUSTED_PROXY_HOPS` that value was always the transport peer,
//! which behind the Compose bundle's Caddy, or behind any provider edge that
//! terminates TLS, is the proxy: every public client shared one bucket, so one
//! attacker (or a normal morning of concurrent onboarding) capped and cooled
//! down every unrelated user, while the attacker's real address isolated it from
//! nothing.
//!
//! The negative half matters more than the positive half. A relay reached
//! directly must ignore the header completely, because a client that can name
//! its own source can mint itself unlimited buckets, which is a strictly worse
//! failure than the shared one this key exists to fix.
//!
//! Nothing here reads a clock or opens a socket, per
//! `specs/backend/build/testing.md`.

use axum::http::HeaderMap;
use wealdrelay::health::{client_source, ForwardedError};

fn peer(address: &str) -> Option<std::net::SocketAddr> {
    Some(address.parse().expect("test address parses"))
}

fn headers(values: &[&str]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for value in values {
        map.append(
            "x-forwarded-for",
            value.parse().expect("test header value parses"),
        );
    }
    map
}

/// Direct: the peer is the client, whatever the client says about itself.
#[test]
fn no_hops_uses_the_transport_peer() {
    let source = client_source(0, &HeaderMap::new(), peer("203.0.113.7:44321"))
        .expect("a direct request is never refused");
    assert_eq!(source.as_deref(), Some("203.0.113.7"));
}

/// The spoof the counting rule exists to close. A direct client sends a header
/// naming somebody else; the relay charges the address it actually saw.
#[test]
fn a_direct_client_cannot_name_its_own_source() {
    let source = client_source(
        0,
        &headers(&["198.51.100.1, 10.0.0.9"]),
        peer("203.0.113.7:44321"),
    )
    .expect("a direct request is never refused");
    assert_eq!(source.as_deref(), Some("203.0.113.7"));
}

/// One declared proxy: the proxy appends the address it saw, so a one-entry
/// chain is the client. This is every honest request through the shipped
/// Compose bundle's Caddy.
#[test]
fn one_hop_reads_the_entry_the_proxy_appended() {
    let source = client_source(1, &headers(&["203.0.113.7"]), peer("172.18.0.4:9000"))
        .expect("a well formed chain is accepted");
    assert_eq!(source.as_deref(), Some("203.0.113.7"));
}

/// The property the ticket asks for: two clients behind one proxy occupy two
/// buckets, where before they shared the proxy's.
#[test]
fn two_clients_behind_one_proxy_get_distinct_sources() {
    let proxy = peer("172.18.0.4:9000");
    let first = client_source(1, &headers(&["203.0.113.7"]), proxy).expect("accepted");
    let second = client_source(1, &headers(&["203.0.113.8"]), proxy).expect("accepted");
    assert_ne!(first, second);
}

/// A client behind a declared proxy prepending a forged entry moves itself left,
/// not right: the relay still counts from the end, so the forgery is ignored and
/// the client's real appended address is charged.
#[test]
fn a_forged_prefix_behind_a_proxy_is_ignored() {
    let source = client_source(
        1,
        &headers(&["198.51.100.1, 203.0.113.7"]),
        peer("172.18.0.4:9000"),
    )
    .expect("accepted");
    assert_eq!(source.as_deref(), Some("203.0.113.7"));
}

/// A chain split across repeated headers is one chain, because proxies differ in
/// whether they append to the existing value or add another header.
#[test]
fn repeated_headers_are_one_chain() {
    let source = client_source(
        3,
        &headers(&["203.0.113.7", "192.0.2.5, 192.0.2.6"]),
        peer("172.18.0.4:9000"),
    )
    .expect("accepted");
    assert_eq!(source.as_deref(), Some("203.0.113.7"));
}

/// Declared hops that did not append. Ambiguous, so refused: falling back to the
/// peer would restore the shared bucket and falling back to the leftmost entry
/// would trust a value the client wrote.
#[test]
fn a_chain_shorter_than_the_declared_hops_is_refused() {
    assert_eq!(
        client_source(2, &headers(&["203.0.113.7"]), peer("172.18.0.4:9000")),
        Err(ForwardedError::ChainTooShort)
    );
}

/// The same refusal with no header at all, which is what a client reaching a
/// proxied relay directly (bypassing the edge) produces.
#[test]
fn a_missing_chain_behind_a_declared_proxy_is_refused() {
    assert_eq!(
        client_source(1, &HeaderMap::new(), peer("203.0.113.7:44321")),
        Err(ForwardedError::ChainTooShort)
    );
}

/// No connection info, which is how the router is mounted in unit tests: the
/// budget falls back to the device identity, so `None` has to survive.
#[test]
fn no_peer_and_no_hops_is_no_source() {
    assert_eq!(
        client_source(0, &HeaderMap::new(), None).expect("accepted"),
        None
    );
}
