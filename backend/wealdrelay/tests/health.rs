// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The readiness document, held to its shape without a database in sight.
//!
//! `/readyz` is a contract with two readers who cannot ask a follow-up question:
//! a load balancer reading the status code, and a person reading the body out of a
//! support ticket. Both are covered by `specs/backend/relay/server.md`, and the
//! parts of that contract which do not need a real Postgres are pinned here rather
//! than in the integration suite, so a change to the document shape fails in a
//! test that runs in milliseconds on a laptop with no harness up.
//!
//! The integration suite proves the same document is truthful against real
//! dependencies. This file proves it is truthful when there are none.

use std::sync::Arc;

use wealdrelay::config::{keys, Config, Values};
use wealdrelay::health::{DependencyState, Readiness, RelayState, ReleaseState};

/// A configuration that resolves without touching anything. The database URL is
/// well formed and is never dialled, because every test here builds the state with
/// no database at all.
fn config(extra: &[(&'static str, &'static str)]) -> Config {
    let mut pairs = vec![
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@localhost/weald_relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
    ];
    for (key, value) in extra {
        pairs.retain(|(existing, _)| existing != key);
        pairs.push((key, value));
    }
    Config::resolve(&Values::from_pairs(pairs)).expect("the configuration resolves")
}

#[test]
fn a_relay_with_the_release_check_on_starts_at_unknown_and_not_at_current() {
    // A relay that has not checked is not a relay that is up to date. Starting at
    // `current` would mean every relay reported itself current for the window
    // between boot and the first check, which is exactly the window a client
    // deciding whether to trust a build would ask about.
    let state = RelayState::new(config(&[(keys::RELEASE_CHECK, "on")]), None, None);
    assert_eq!(
        *state
            .release
            .read()
            .expect("the release lock is not poisoned"),
        ReleaseState::Unknown
    );

    // And `off` is a different answer again: an air-gapped install has not failed
    // to check, it has been told not to.
    let disabled = RelayState::new(config(&[(keys::RELEASE_CHECK, "off")]), None, None);
    assert_eq!(
        *disabled
            .release
            .read()
            .expect("the release lock is not poisoned"),
        ReleaseState::Disabled
    );
}

#[tokio::test]
async fn a_relay_with_neither_dependency_reports_both_down_and_is_not_ready() {
    // The failure this guards against is a `/readyz` that reports `ok` because it
    // had nothing to ask. A relay with no database configured cannot accept a
    // durable write, and saying so is the whole job of this document.
    let state = RelayState::new(config(&[(keys::RELEASE_CHECK, "off")]), None, None);
    let readiness = state.readiness().await;

    assert!(
        !readiness.database.ok,
        "no database is not a healthy database"
    );
    assert_eq!(
        readiness.database.detail.as_deref(),
        Some("no database configured")
    );
    assert!(!readiness.storage.ok, "no storage is not healthy storage");
    assert_eq!(
        readiness.storage.detail.as_deref(),
        Some("no storage configured")
    );
    assert!(!readiness.ready);
    // Empty rather than unknown. The relay does not know of a frozen group because
    // it has nowhere to ask, and inventing one would be worse than saying none.
    assert!(readiness.frozen_groups.is_empty());
    assert_eq!(readiness.release, ReleaseState::Disabled);
    assert_eq!(readiness.access_set, "enforce");
    assert_eq!(readiness.min_enc, "none");
    assert_eq!(readiness.write_mode, "full");
    assert!(!readiness.build.is_empty());
    assert!(!readiness.version.is_empty());
}

#[tokio::test]
async fn the_reason_for_refusing_writes_is_present_only_when_writes_are_refused() {
    // A client under `read_only` is told why durable writes are refused, and a
    // client under `full` is told nothing, because a field that is always there
    // with an empty value is a field somebody renders as a banner on a healthy
    // relay. The reason is a fixed token and never content-derived.
    let full = RelayState::new(config(&[(keys::RELEASE_CHECK, "off")]), None, None)
        .readiness()
        .await;
    assert_eq!(full.write_mode, "full");
    assert_eq!(full.write_mode_reason, None);
    let rendered = serde_json::to_value(&full).expect("the document serialises");
    assert!(
        rendered.get("write_mode_reason").is_none(),
        "an absent reason is absent from the json and not a null: {rendered}"
    );

    let read_only = RelayState::new(
        config(&[
            (keys::RELEASE_CHECK, "off"),
            (keys::WRITE_MODE, "read_only"),
        ]),
        None,
        None,
    )
    .readiness()
    .await;
    assert_eq!(read_only.write_mode, "read_only");
    assert_eq!(read_only.write_mode_reason, Some("service_read_only"));
    let rendered = serde_json::to_value(&read_only).expect("the document serialises");
    assert_eq!(
        rendered.get("write_mode_reason").and_then(|v| v.as_str()),
        Some("service_read_only")
    );
}

#[test]
fn every_release_state_serialises_with_the_tag_a_client_switches_on() {
    // The client renders a mismatched digest as an alarm and a merely older one as
    // a chore, and it picks between them on this tag. A state that serialised
    // without it, or that collapsed two states into one string, would either train
    // a security banner into background noise or raise one that is not warranted.
    let cases = [
        (ReleaseState::Disabled, "disabled"),
        (ReleaseState::Unknown, "unknown"),
        (ReleaseState::Current, "current"),
        (
            ReleaseState::Behind {
                latest: "0.9.0".into(),
            },
            "behind",
        ),
        (
            ReleaseState::Unreachable {
                detail: "the feed did not answer".into(),
            },
            "unreachable",
        ),
    ];
    for (state, tag) in cases {
        let rendered = serde_json::to_value(&state).expect("a release state serialises");
        assert_eq!(
            rendered.get("state").and_then(|v| v.as_str()),
            Some(tag),
            "{rendered}"
        );
        // The payload travels with the tag rather than being folded into it, so a
        // client can show the version it should move to without parsing prose.
        match &state {
            ReleaseState::Behind { latest } => assert_eq!(
                rendered.get("latest").and_then(|v| v.as_str()),
                Some(latest.as_str())
            ),
            ReleaseState::Unreachable { detail } => assert_eq!(
                rendered.get("detail").and_then(|v| v.as_str()),
                Some(detail.as_str())
            ),
            _ => assert_eq!(
                rendered.as_object().map(serde_json::Map::len),
                Some(1),
                "a state with no payload carries nothing but its tag"
            ),
        }
        assert!(format!("{state:?}")
            .to_lowercase()
            .contains(tag.trim_end_matches('e')));
        assert_eq!(state.clone(), state);
    }
}

#[test]
fn a_dependency_detail_is_scrubbed_before_it_is_ever_rendered() {
    // `/readyz` output goes into a support ticket. The connection URL reaches this
    // field through a driver error message, and the password goes with it unless
    // the scrubber is in the path here rather than at the log sink.
    let down = DependencyState::down(
        "connecting to postgres://weald:hunter2thisisalongpassword@db:5432/relay failed",
    );
    assert!(!down.ok);
    let detail = down.detail.clone().expect("a failure carries a reason");
    assert!(
        !detail.contains("hunter2thisisalongpassword"),
        "the password survived into the readiness document: {detail}"
    );
    assert!(
        detail.contains("weald"),
        "the role is not the credential: {detail}"
    );

    let up = DependencyState::up();
    assert!(up.ok);
    assert_eq!(up.detail, None);
    let rendered = serde_json::to_value(&up).expect("a dependency state serialises");
    assert!(
        rendered.get("detail").is_none(),
        "a healthy dependency has no reason field at all: {rendered}"
    );
}

#[test]
fn the_readiness_document_is_comparable_and_debuggable() {
    // Both are load-bearing: the tests above compare states, and a failure in the
    // integration suite prints the whole document.
    let state = Arc::new(RelayState::new(
        config(&[(keys::RELEASE_CHECK, "off")]),
        None,
        None,
    ));
    assert!(format!("{state:?}").contains("relay.acme.com"));
    let readiness: Readiness = futures_lite_block_on(state.readiness());
    assert_eq!(readiness.clone(), readiness);
    assert!(format!("{readiness:?}").contains("no database configured"));
}

/// A one-poll block-on, so the test above does not need a runtime attribute for a
/// future that never yields. Written here rather than pulled in as a dependency,
/// because a test helper is not a reason to add a crate to the relay's tree.
fn futures_lite_block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime")
        .block_on(future)
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime")
        .block_on(future)
}

/// One request against a router, without binding a port.
fn answer(router: axum::Router, path: &str) -> axum::http::StatusCode {
    block_on(async {
        use tower::ServiceExt as _;
        router
            .oneshot(
                axum::http::Request::builder()
                    .uri(path)
                    .body(axum::body::Body::empty())
                    .expect("a request"),
            )
            .await
            .expect("the router answers")
            .status()
    })
}

#[test]
fn the_invite_link_the_relay_prints_is_a_route_the_relay_serves() {
    // The first-run banner prints `https://<hostname>/join/<token>`. For a while
    // the landing page existed as a function and the router did not mention it, so
    // every printed invite led to a 404 and the only caller of `landing_page` was a
    // test. This asserts the two agree: the path in the banner is a path the public
    // router answers.
    let state = Arc::new(RelayState::new(
        config(&[(keys::RELEASE_CHECK, "off")]),
        None,
        None,
    ));
    let banner = wealdrelay::invite::genesis::banner(
        &state.config.hostname,
        &wealdrelay::invite::genesis::FirstRun {
            public_key: vec![1; 32],
            fingerprint: vec![2; 32],
            token: vec![3; 16],
            code: wealdrelay::invite::code::Code::from_bits(0x0123_4567_89ab_cdef),
        },
    );
    let printed = banner
        .lines()
        .find_map(|line| line.split_once("https://"))
        .map(|(_, rest)| rest.trim().to_string())
        .expect("the banner prints a link");
    let path = printed
        .split_once('/')
        .map(|(_, rest)| format!("/{rest}"))
        .expect("the link carries a path");

    assert_eq!(
        answer(wealdrelay::health::public_router(Arc::clone(&state)), &path),
        axum::http::StatusCode::OK,
        "the printed invite path {path} must be served, not 404"
    );
}

/// The landing page names no client the relay cannot deliver.
///
/// It used to link `/download`, which is a route on the marketing site and not on
/// a relay: every self-hosted invite offered the joiner a 404. The page is served
/// by whoever runs the relay, so it can name the protocol and must not promise a
/// binary.
#[test]
fn the_landing_page_does_not_offer_a_download_the_relay_cannot_serve() {
    let page = wealdrelay::invite::delivery::landing_page();
    assert!(
        !page.contains("href=\"/download\""),
        "the landing page links a path no relay serves"
    );
    assert!(
        page.contains("weald://join/") || page.contains("weald://"),
        "the landing page must still hand the invite to a client"
    );
}
