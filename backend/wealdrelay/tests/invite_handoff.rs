// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The sealed bootstrap handoff: the relay's half of the two-channel enrollment.
//!
//! `specs/backend/relay/server.md` pins the format and the path here rather than
//! leaving them to the implementation, because two independent programs have to
//! agree on them byte for byte and a disagreement is only discovered when a
//! customer's one bootstrap invite has been spent on it. So this suite asserts
//! against `specs/backend/contracts/wire/vectors/bootstrap-handoff.json`, which the
//! control plane's half is checked against too, rather than against the relay's own
//! output.
//!
//! What is proven here:
//!
//! - The construction. The blob layout, the derived path, and the refusal of a
//!   configured value that is not a 32-byte key.
//! - The boot branch. With a handoff key the relay prints no code and no link and
//!   seals both halves; without one it prints all three and seals nothing.
//! - The route. Mounted only where both a handoff key and an operator bearer are
//!   configured, refused without the bearer, 404 before anything is sealed, and
//!   non-consuming: reading it twice returns the same blob, because redemption is
//!   the one-time operation and it happens over the socket.

mod support;

use std::sync::Arc;

use wealdrelay::config::{keys, Config, Values};
use wealdrelay::health::RelayState;
use wealdrelay::invite::handoff;

use support::Scratch;

/// A handoff keypair from the conformance vectors, so the private half is known and
/// the blob this relay produces can actually be opened rather than merely inspected.
const HANDOFF_PUBLIC: &str = "e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM=";
const HANDOFF_PRIVATE: &str = "ERERERERERERERERERERERERERERERERERERERERERE=";
const TOKEN: &str = "operator-bearer-for-the-handoff-route";

fn config(scratch: &Scratch, blobs: &std::path::Path, sealed: bool, operator: bool) -> Config {
    let mut pairs = vec![
        (keys::HOSTNAME, "relay.acme.test".to_string()),
        (keys::DATABASE_URL, scratch.url.clone()),
        (keys::STORAGE_URL, format!("file://{}", blobs.display())),
        (keys::LISTEN, "127.0.0.1:0".to_string()),
        (keys::OBSERVABILITY_LISTEN, "127.0.0.1:0".to_string()),
        (keys::RELEASE_CHECK, "off".to_string()),
    ];
    if sealed {
        pairs.push((keys::BOOTSTRAP_HANDOFF_PUBKEY, HANDOFF_PUBLIC.to_string()));
    }
    if operator {
        pairs.push((keys::OPERATOR_TOKEN, TOKEN.to_string()));
    }
    Config::resolve(&Values::from_pairs(pairs)).expect("the configuration resolves")
}

/// One request against the public router, without binding a port.
async fn ask(
    state: &Arc<RelayState>,
    path: &str,
    authorization: Option<&str>,
) -> (axum::http::StatusCode, String) {
    use tower::ServiceExt as _;
    let mut request = axum::http::Request::builder().uri(path);
    if let Some(value) = authorization {
        request = request.header(axum::http::header::AUTHORIZATION, value);
    }
    let response = wealdrelay::health::public_router(Arc::clone(state))
        .oneshot(request.body(axum::body::Body::empty()).expect("a request"))
        .await
        .expect("the router answers");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("a body");
    (status, String::from_utf8_lossy(&body).to_string())
}

/// The vectors both implementations are checked against.
///
/// Read from the repository rather than copied in, because the point of the file is
/// that neither implementation is the other's oracle: the control plane's suite reads
/// the same bytes, and a copy here would be a fourth thing to keep in step.
fn vectors() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../specs/backend/contracts/wire/vectors/bootstrap-handoff.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("the vectors are readable"))
        .expect("the vectors are json")
}

fn key(text: &str) -> [u8; 32] {
    handoff::parse_public_key(text).expect("a 32 byte key")
}

// MARK: The construction

#[test]
fn the_path_is_derived_from_the_key_and_carries_no_padding() {
    let public = key(HANDOFF_PUBLIC);
    let path = handoff::handoff_path(&public);
    assert!(path.starts_with("/handoff/"), "{path}");
    // base64url without padding, because the value sits in a URL path segment and
    // `=` there is legal and needlessly escaped by half the clients that fetch it.
    assert!(!path.contains('='), "{path}");
    // The URL-safe alphabet, checked on the segment rather than on the whole path:
    // the prefix has a `/` in it by construction and testing the whole string would
    // have been an assertion that could never hold.
    let segment = path.strip_prefix("/handoff/").expect("the prefix");
    assert!(
        segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "{segment}"
    );
    // Derived from the key rather than from the workspace: a path containing a
    // hostname would be a guessable url for a ciphertext.
    assert_ne!(path, handoff::handoff_path(&[0u8; 32]));
}

#[test]
fn a_configured_value_that_is_not_a_key_is_refused_rather_than_padded() {
    for value in ["", "not base64!!", "AAAA", &"A".repeat(100)] {
        assert!(
            handoff::parse_public_key(value).is_err(),
            "{value:?} was accepted as a key"
        );
    }
}

#[test]
fn every_conformance_vector_seals_to_exactly_its_recorded_bytes() {
    // Byte for byte, against the file the control plane is checked against too. This
    // is the assertion that makes the two implementations agree on something other
    // than each other, which matters because a disagreement is only discovered when
    // a customer's one bootstrap invite has been spent on it.
    let vectors = vectors();
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(!cases.is_empty(), "the vectors file is empty");
    for case in cases {
        let id = case["id"].as_str().expect("an id");
        let public = key(case["handoff_public_key"].as_str().expect("a public key"));
        let ephemeral = key(case["ephemeral_private_key"]
            .as_str()
            .expect("an ephemeral key"));
        let plaintext = case["plaintext"].as_str().expect("a plaintext");
        let sealed =
            handoff::seal_with_ephemeral(&public, &ephemeral, plaintext.as_bytes()).expect("seal");
        assert_eq!(sealed, case["blob"].as_str().expect("a blob"), "case {id}");

        // And the other direction, so a wrong-but-self-consistent key schedule is
        // caught rather than agreed with.
        let private = key(case["handoff_private_key"].as_str().expect("a private key"));
        assert_eq!(
            String::from_utf8(handoff::open(&private, &public, &sealed).expect("open"))
                .expect("utf8"),
            plaintext,
            "case {id}"
        );
    }
}

#[test]
fn a_sealed_blob_opens_to_its_plaintext_and_is_never_the_plaintext() {
    let public = key(HANDOFF_PUBLIC);
    let plaintext = "https://relay.acme.test/join/0011223344556677889900aabbccddee";
    let blob = handoff::seal(&public, plaintext.as_bytes()).expect("seal");
    // Control B3: what leaves the relay is ciphertext. A test that only checked the
    // round trip would pass against an implementation that base64'd the link.
    assert!(!blob.contains("/join/"), "{blob}");
    // A fresh ephemeral pair per call, which is what makes the zero nonce safe.
    assert_ne!(
        blob,
        handoff::seal(&public, plaintext.as_bytes()).expect("seal")
    );
    assert_eq!(
        String::from_utf8(handoff::open(&key(HANDOFF_PRIVATE), &public, &blob).expect("open"))
            .expect("utf8"),
        plaintext
    );
}

#[test]
fn a_blob_sealed_to_one_key_does_not_open_under_another() {
    // `info` binds the ciphertext to the key it was sealed to, so a blob lifted from
    // one instance and served for another fails to open rather than decrypting into
    // somebody else's invite.
    let other = key("4NDwbOM3PhZLBl+aZKGWJm1JW8QoWHmVJBJPRz0uMHM=");
    let blob = handoff::seal(&other, b"someone else's link").expect("seal");
    assert!(handoff::open(&key(HANDOFF_PRIVATE), &key(HANDOFF_PUBLIC), &blob).is_err());
}

// MARK: The boot branch

#[tokio::test]
async fn with_a_handoff_key_the_relay_seals_both_halves_and_prints_neither() {
    let scratch = Scratch::new("handoff_with_a_handoff_key").await;
    let blobs = tempfile::tempdir().expect("a blob directory");
    let config = config(&scratch, blobs.path(), true, true);
    let state = wealdrelay::serve::prepare(config.clone())
        .await
        .expect("the relay prepares");
    let database = state.database.as_ref().expect("a database");
    let workspace = wealdrelay::serve::bootstrap_workspace(&config.hostname);

    let sealed = wealdrelay::invite::handoff::read(database.pool(), &workspace)
        .await
        .expect("the read succeeds")
        .expect("a sealed handoff exists");

    // The link half opens to this relay's own enrollment URL.
    let link = String::from_utf8(
        handoff::open(&key(HANDOFF_PRIVATE), &key(HANDOFF_PUBLIC), &sealed.blob).expect("open"),
    )
    .expect("utf8");
    assert!(link.starts_with("https://relay.acme.test/join/"), "{link}");

    // The code half opens to the grouped form, which is what a human is asked to
    // type and what `cloud/email.md` puts in the mail. A blob with no `sealed_code`
    // beside it is refused by the control plane, because a workspace whose code was
    // never sealed is one nobody can ever enroll into.
    let code = String::from_utf8(
        handoff::open(
            &key(HANDOFF_PRIVATE),
            &key(HANDOFF_PUBLIC),
            &sealed.sealed_code,
        )
        .expect("open"),
    )
    .expect("utf8");
    assert_eq!(
        code.len(),
        14,
        "twelve symbols in three dashed groups: {code}"
    );
    assert_eq!(code.matches('-').count(), 2, "{code}");
    assert_eq!(code, code.to_uppercase(), "{code}");

    // The fingerprint travels with the blob because `cloud/api.md` returns the two
    // together: two separate reads would be two chances to answer about two keys.
    assert_eq!(sealed.genesis_fingerprint.len(), 64);
    assert!(sealed
        .genesis_fingerprint
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert_ne!(sealed.blob, sealed.sealed_code);
}

#[tokio::test]
async fn without_a_handoff_key_nothing_is_sealed_and_every_derived_path_is_absent() {
    let scratch = Scratch::new("handoff_without_a_handoff_key").await;
    let blobs = tempfile::tempdir().expect("a blob directory");
    let config = config(&scratch, blobs.path(), false, true);
    let state = Arc::new(
        wealdrelay::serve::prepare(config.clone())
            .await
            .expect("the relay prepares"),
    );
    let database = state.database.as_ref().expect("a database");
    let workspace = wealdrelay::serve::bootstrap_workspace(&config.hostname);

    // The self-host path: the invite is on the operator's own terminal, and there is
    // nothing to seal it to.
    assert!(
        wealdrelay::invite::handoff::read(database.pool(), &workspace)
            .await
            .expect("the read succeeds")
            .is_none()
    );

    let (status, _) = ask(
        &state,
        &handoff::handoff_path(&key(HANDOFF_PUBLIC)),
        Some(&format!("Bearer {TOKEN}")),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}

// MARK: The route

#[tokio::test]
async fn the_route_answers_the_bearer_and_nothing_else_and_does_not_consume() {
    let scratch = Scratch::new("handoff_route_answers").await;
    let blobs = tempfile::tempdir().expect("a blob directory");
    let config = config(&scratch, blobs.path(), true, true);
    let state = Arc::new(
        wealdrelay::serve::prepare(config)
            .await
            .expect("the relay prepares"),
    );
    let public = key(HANDOFF_PUBLIC);
    let path = handoff::handoff_path(&public);

    // The same refusals `/admitted` makes, because it is the same comparison.
    for offered in [
        None,
        Some(TOKEN.to_string()),
        Some(format!("Basic {TOKEN}")),
        Some(format!("Bearer {TOKEN}x")),
    ] {
        let (status, _) = ask(&state, &path, offered.as_deref()).await;
        assert_eq!(
            status,
            axum::http::StatusCode::UNAUTHORIZED,
            "{offered:?} was not refused"
        );
    }

    // Reading does not consume. The control plane polls this while it waits for a
    // relay to come up, so a read that spent the invite would destroy it before the
    // buyer ever saw it.
    let bearer = format!("Bearer {TOKEN}");
    let (first_status, first) = ask(&state, &path, Some(&bearer)).await;
    let (second_status, second) = ask(&state, &path, Some(&bearer)).await;
    assert_eq!(first_status, axum::http::StatusCode::OK);
    assert_eq!(second_status, axum::http::StatusCode::OK);
    assert_eq!(first, second);

    // The exact three fields `render-operations.ts renderHandoffBlob` parses. A
    // response missing any of them is refused there, so the names are the wire.
    let body: serde_json::Value = serde_json::from_str(&first).expect("json");
    for field in ["blob", "sealed_code", "genesis_fingerprint"] {
        assert!(
            body.get(field)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|v| !v.is_empty()),
            "{field} missing from {first}"
        );
    }
    // And nothing else. A fourth field here would be a relay volunteering something
    // about a workspace it is supposed to be blind to.
    assert_eq!(body.as_object().expect("an object").len(), 3, "{first}");
    assert!(
        !first.contains("/join/"),
        "the link half travelled in clear"
    );
}

#[tokio::test]
async fn the_route_is_absent_without_an_operator_bearer_even_with_a_handoff_key() {
    // Both credentials or neither. A route mounted with a sealing key and no bearer
    // would be an unauthenticated operator surface appearing by omission, which is
    // the failure the conditional mount exists to make impossible.
    let scratch = Scratch::new("handoff_route_absent").await;
    let blobs = tempfile::tempdir().expect("a blob directory");
    let state = Arc::new(
        wealdrelay::serve::prepare(config(&scratch, blobs.path(), true, false))
            .await
            .expect("the relay prepares"),
    );
    let (status, _) = ask(&state, &handoff::handoff_path(&key(HANDOFF_PUBLIC)), None).await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}
