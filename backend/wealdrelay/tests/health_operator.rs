// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `GET /admitted`, the one operator route, and the bearer in front of it.
//!
//! The route landed with the control plane's provisioning path and had no test at
//! all, which step 20's coverage assertion is what found. It is worth more than an
//! ordinary route: `specs/backend/cloud/provisioning.md` has the control plane
//! branch on the answer to decide whether a one-time bootstrap invite may still be
//! claimed, so a wrong answer here hands bootstrap authority to a second device in
//! a workspace that already has an admin. That is the trust-root race, and the
//! three things that prevent it are all asserted here:
//!
//! - It answers only to the operator bearer, compared in constant time. Anything
//!   else is 401, including a token of the right length and the wrong bytes.
//! - It answers 503, never 0, when it could not look. Zero is the value the caller
//!   treats as "nobody has enrolled yet"; a relay that could not read its own
//!   database has not learned that.
//! - It is not mounted at all where no bearer is configured, which is the
//!   self-hosted shape: a route that exists and refuses everything is a route a
//!   self-hoster has to reason about, and there is no control plane there to call
//!   it.
//!
//! Every fault is a real state of a real Postgres, per `testing.md`: the count is
//! read against rows a real publication wrote, and the unreadable case is a table
//! that is really gone.

mod support;

use std::sync::Arc;

use wealdrelay::config::{keys, Config, Values};
use wealdrelay::health::{Clock, RelayState};

use support::{Running, Scratch};

const TOKEN: &str = "operator-bearer-for-the-admitted-route";

/// The integration configuration plus an operator bearer.
fn config_with_operator(scratch: &Scratch, blobs: &std::path::Path) -> Config {
    Config::resolve(&Values::from_pairs([
        (keys::HOSTNAME, "localhost".to_string()),
        (keys::DATABASE_URL, scratch.url.clone()),
        (keys::STORAGE_URL, format!("file://{}", blobs.display())),
        (keys::LISTEN, "127.0.0.1:0".to_string()),
        (keys::OBSERVABILITY_LISTEN, "127.0.0.1:0".to_string()),
        (keys::RELEASE_CHECK, "off".to_string()),
        (keys::OPERATOR_TOKEN, TOKEN.to_string()),
    ]))
    .expect("the operator configuration resolves")
}

/// A configuration with no database dialled and no bearer, for the two cases that
/// need neither.
fn bare(extra: &[(&'static str, &'static str)]) -> Config {
    let mut pairs = vec![
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@localhost/weald_relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
        (keys::RELEASE_CHECK, "off"),
    ];
    for (key, value) in extra {
        pairs.retain(|(existing, _)| existing != key);
        pairs.push((key, value));
    }
    Config::resolve(&Values::from_pairs(pairs)).expect("the configuration resolves")
}

/// One request against the private router, without binding a port.
async fn ask(
    state: &Arc<RelayState>,
    authorization: Option<&str>,
) -> (axum::http::StatusCode, String) {
    ask_at(state, "/admitted", authorization).await
}

/// The same, at a path of the caller's choosing.
async fn ask_at(
    state: &Arc<RelayState>,
    uri: &str,
    authorization: Option<&str>,
) -> (axum::http::StatusCode, String) {
    use tower::ServiceExt as _;
    let mut request = axum::http::Request::builder().uri(uri);
    if let Some(value) = authorization {
        request = request.header(axum::http::header::AUTHORIZATION, value);
    }
    let response = wealdrelay::health::private_router(Arc::clone(state))
        .oneshot(request.body(axum::body::Body::empty()).expect("a request"))
        .await
        .expect("the router answers");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("a body");
    (status, String::from_utf8_lossy(&body).to_string())
}

// MARK: The bearer

#[tokio::test]
async fn the_route_is_absent_where_no_operator_bearer_is_configured() {
    // The self-hosted shape. Not 401: there is no control plane in that deployment
    // and nothing that would ever call this, so the honest answer is that the
    // route does not exist.
    let state = Arc::new(RelayState::new(bare(&[]), None, None));
    let (status, _) = ask(&state, Some(&format!("Bearer {TOKEN}"))).await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn every_wrong_bearer_is_refused_and_none_of_them_reaches_the_database() {
    // No database on this state at all, so a request that got past the bearer check
    // would answer 503 rather than 401 and this test would see the difference.
    let state = Arc::new(RelayState::new(
        bare(&[(keys::OPERATOR_TOKEN, TOKEN)]),
        None,
        None,
    ));

    let wrong_bytes: String = {
        // The same length, one byte different. The comparison is constant time
        // precisely so length is the only thing a caller can learn, and a test that
        // only sent short tokens would pass against a comparison that returned on
        // the first differing byte.
        let mut bytes = TOKEN.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x20;
        String::from_utf8(bytes).expect("still utf8")
    };
    for offered in [
        None,
        Some(String::new()),
        Some(TOKEN.to_string()),               // no scheme
        Some(format!("Basic {TOKEN}")),        // the wrong scheme
        Some(format!("bearer {TOKEN}")),       // the scheme is case sensitive here
        Some("Bearer ".to_string()),           // empty
        Some(format!("Bearer {TOKEN}x")),      // longer
        Some(format!("Bearer {wrong_bytes}")), // same length, wrong bytes
    ] {
        let (status, body) = ask(&state, offered.as_deref()).await;
        assert_eq!(
            status,
            axum::http::StatusCode::UNAUTHORIZED,
            "{offered:?} was not refused"
        );
        assert!(body.contains("operator token required"), "{body}");
    }
}

#[tokio::test]
async fn a_relay_with_the_bearer_and_no_database_answers_unavailable_and_not_zero() {
    // The distinction the whole route exists for. Zero means "nobody has enrolled,
    // the bootstrap invite may still be claimed"; this relay does not know that.
    let state = Arc::new(RelayState::new(
        bare(&[(keys::OPERATOR_TOKEN, TOKEN)]),
        None,
        None,
    ));
    let (status, body) = ask(&state, Some(&format!("Bearer {TOKEN}"))).await;
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("no database"), "{body}");
    assert!(
        !body.contains('0'),
        "an unavailable answer carried a count: {body}"
    );
}

// MARK: `/readyz` and what each caller is allowed to see (WEALD-295)

#[tokio::test(flavor = "multi_thread")]
async fn an_unauthenticated_readyz_carries_the_verdict_and_nothing_derived_from_a_group() {
    use sqlx::Executor as _;

    let scratch = Scratch::new("readyz_bare").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_with_operator(&scratch, blobs.path()),
        Clock::Fixed(1),
    )
    .await;
    let pool = relay
        .state
        .database
        .as_ref()
        .expect("a database")
        .pool()
        .clone();

    // A frozen group, which is the one value on the full document that is derived
    // from a group id and is exactly what the unauthenticated body must not carry.
    // The workspace is minted the way the access path mints one.
    let group: Vec<u8> = vec![0xab; 32];
    wealdrelay::access::store::salt(&pool, "ws-readyz")
        .await
        .expect("mint the workspace");
    pool.execute(
        sqlx::query(
            "insert into relay_group (group_id, workspace_id, frozen_reason) \
             values ($1, 'ws-readyz', 'contested')",
        )
        .bind(&group),
    )
    .await
    .expect("freeze a group");
    let prefix = &wealdrelay::logging::hex_prefix(&group);

    // Unauthenticated: the verdict, truthfully 503 (a frozen group is not ready),
    // and no value derived from a group id anywhere in the body.
    let (status, body) = ask_at(&relay.state, "/readyz", None).await;
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !body.contains(prefix) && !body.contains("frozen"),
        "the unauthenticated body leaked a group handle: {body}"
    );
    let verdict: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(verdict["ready"], false);
    assert_eq!(verdict["ok"], false);
    assert_eq!(
        verdict.as_object().map(|fields| fields.len()),
        Some(2),
        "the unauthenticated verdict grew a field: {body}"
    );

    // A wrong bearer is the same caller as no bearer.
    let (_, wrong) = ask_at(&relay.state, "/readyz", Some("Bearer nope")).await;
    assert!(!wrong.contains(prefix), "{wrong}");

    // The operator sees the document the control plane polls, frozen group named.
    let (status, body) = ask_at(&relay.state, "/readyz", Some(&format!("Bearer {TOKEN}"))).await;
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        body.contains(prefix),
        "the operator document lost the frozen group: {body}"
    );
    let document: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(document["access_set"], "enforce");

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_relay_with_no_operator_bearer_serves_only_the_verdict_to_anybody() {
    // The self-hosted shape: with no bearer configured there is no caller the
    // detailed document can be authenticated for, so nobody gets it, whatever
    // they put in the header.
    let state = Arc::new(RelayState::new(bare(&[]), None, None));
    let (status, body) = ask_at(&state, "/readyz", Some("Bearer anything")).await;
    // No database and no storage on this state: honestly not ready.
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let verdict: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(verdict["ready"], false);
    assert!(
        verdict.get("database").is_none() && verdict.get("frozen_groups").is_none(),
        "the verdict carried detail: {body}"
    );
}

// MARK: The count itself

#[tokio::test(flavor = "multi_thread")]
async fn the_count_is_the_entries_of_every_workspace_s_latest_set() {
    use ed25519_dalek::{Signer as _, SigningKey};
    use wealdrelay::access::{entry_hash, store, AccessSet};

    let scratch = Scratch::new("health_operator_count").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_with_operator(&scratch, blobs.path()),
        Clock::Fixed(1),
    )
    .await;
    let pool = relay
        .state
        .database
        .as_ref()
        .expect("a database")
        .pool()
        .clone();

    // Nobody yet. A fresh relay's honest answer, and the one the control plane
    // treats as "the bootstrap invite is still claimable".
    let (status, body) = ask(&relay.state, Some(&format!("Bearer {TOKEN}"))).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body, r#"{"admitted":0}"#);

    // One workspace with two devices in its genesis set, published the way a real
    // trust root publishes it.
    let root = SigningKey::from_bytes(&[0x51; 32]);
    let recovery = SigningKey::from_bytes(&[0x52; 32]);
    let workspace = "ws-admitted-count";
    // `salt` mints the workspace row on first ask, which is how every other path
    // here reaches a workspace that has never been seen.
    let salt = store::salt(&pool, workspace).await.expect("a salt");
    let mut set = AccessSet {
        workspace: vec![0x60; 32],
        version: 0,
        prev_hash: vec![0u8; 32],
        issued_at: 1,
        entries: {
            let mut entries = vec![
                entry_hash(&root.verifying_key().to_bytes(), &salt),
                entry_hash(&recovery.verifying_key().to_bytes(), &salt),
            ];
            entries.sort();
            entries
        },
        authorizers: vec![root.verifying_key().to_bytes().to_vec()],
        recovery: vec![recovery.verifying_key().to_bytes().to_vec()],
        quorum: None,
        pending: Vec::new(),
        signer: root.verifying_key().to_bytes().to_vec(),
        sig: vec![0u8; 64],
    };
    set.sig = root.sign(&set.digest_input()).to_bytes().to_vec();
    store::publish(&pool, workspace, &set, &set.encode())
        .await
        .expect("the genesis set is accepted");

    let (status, body) = ask(&relay.state, Some(&format!("Bearer {TOKEN}"))).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(
        body, r#"{"admitted":2}"#,
        "the count is the entries of the latest set"
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_that_cannot_read_its_own_tables_answers_unavailable_without_leaking_the_error() {
    use sqlx::Executor as _;

    let scratch = Scratch::new("health_operator_unreadable").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(
        config_with_operator(&scratch, blobs.path()),
        Clock::Fixed(1),
    )
    .await;
    let pool = relay
        .state
        .database
        .as_ref()
        .expect("a database")
        .pool()
        .clone();

    // A real fault, not a mock: the table the count reads is really gone.
    pool.execute("drop table relay_access_entry cascade")
        .await
        .expect("the table is dropped");

    let (status, body) = ask(&relay.state, Some(&format!("Bearer {TOKEN}"))).await;
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    // Scrubbed, because this body reaches a provider-side caller and an unscrubbed
    // sqlx error carries the connection string.
    assert!(
        !body.contains("postgres://") && !body.contains(&scratch.name),
        "the error named the database: {body}"
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}
