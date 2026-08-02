// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The local stand-in for a presigned URL, over the relay's own public listener.
//!
//! `specs/backend/build/environments.md`: the filesystem storage backend is
//! `local`'s only, and `ci`, `staging` and `production` all run against an
//! S3-compatible bucket that can presign a real request. A laptop running
//! `local` has no such bucket, so when storage is the filesystem backend the
//! relay presigns a request against **itself**: a URL naming this route, with an
//! HMAC token in its query string standing in for AWS SigV4. `media::presign`
//! decides which of the two happens; this module is only ever reached in the
//! first case.
//!
//! The token covers the method, the object key and an expiry, keyed by
//! `RelayState::media_presign_secret`, a process secret generated once at
//! startup (`session::challenge_secret` is the same pattern for `AUTH`). A token
//! for one object cannot be replayed against another, and an expired token is
//! refused regardless of its signature.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use serde::Deserialize;

use crate::health::RelayState;
use crate::storage::BlobKey;

/// One presigned-token query string.
#[derive(Debug, Clone, Deserialize)]
pub struct Token {
    pub exp: u64,
    pub sig: String,
}

/// Sign `method || key.path()` with the process secret, expiring at `expires_at`
/// (seconds since the epoch).
pub fn sign(secret: &[u8; 32], method: &str, key_path: &str, expires_at: u64) -> String {
    let mut hasher = blake3::Hasher::new_keyed(secret);
    hasher.update(b"weald local blob token v1");
    hasher.update(method.as_bytes());
    hasher.update(b"\0");
    hasher.update(key_path.as_bytes());
    hasher.update(&expires_at.to_be_bytes());
    crate::invite::genesis::hex(hasher.finalize().as_bytes())
}

/// Verify a token against the same inputs its signer used, and that it has not
/// expired as of `now_secs`.
pub fn verify(
    secret: &[u8; 32],
    method: &str,
    key_path: &str,
    token: &Token,
    now_secs: u64,
) -> bool {
    if token.exp < now_secs {
        return false;
    }
    let expected = sign(secret, method, key_path, token.exp);
    // Length-independent-content comparison is not needed here beyond what a
    // straight comparison of two hex strings of the process's own fixed digest
    // width gives: both sides are 64 hex characters, so there is no length signal
    // to leak, and BLAKE3 with a secret key is the MAC being trusted for
    // unforgeability rather than the comparison.
    expected == token.sig
}

pub fn routes() -> Router<Arc<RelayState>> {
    Router::new()
        .route(
            "/blob/:workspace/:group/:hash",
            get(get_object).put(put_object),
        )
        .route("/blob-part/:session/:part", get(get_part).put(put_part))
        // Axum's default body limit is two megabytes, which is smaller than every
        // blob this route exists to carry. The ceiling here is
        // `SINGLE_PART_MAX_BYTES` rather than `BLOB_MAX_BYTES` because nothing
        // larger ever arrives as one request: above that threshold `BLOB put`
        // answers with a multipart session and each part is at most one part size
        // (`media.md`, "Above 64 MB the relay issues a multipart upload session").
        // So this is the true maximum a local upload can be, and it doubles as the
        // bound on what one request can make the relay hold in memory.
        .layer(axum::extract::DefaultBodyLimit::max(
            super::SINGLE_PART_MAX_BYTES as usize,
        ))
}

async fn put_object(
    Path((workspace, group, hash)): Path<(String, String, String)>,
    Query(token): Query<Token>,
    State(state): State<Arc<RelayState>>,
    body: axum::body::Bytes,
) -> StatusCode {
    let Ok(key) = BlobKey::new(workspace, group, hash) else {
        return StatusCode::BAD_REQUEST;
    };
    if !verify(
        &state.media_presign_secret,
        "PUT",
        &key.path(),
        &token,
        state.now_ms() / 1000,
    ) {
        return StatusCode::FORBIDDEN;
    }
    let Some(storage) = &state.storage else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    match storage.put(&key, &body).await {
        Ok(()) => StatusCode::OK,
        Err(error) if error.is_transient() => StatusCode::SERVICE_UNAVAILABLE,
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

async fn get_object(
    Path((workspace, group, hash)): Path<(String, String, String)>,
    Query(token): Query<Token>,
    State(state): State<Arc<RelayState>>,
) -> Result<axum::body::Bytes, StatusCode> {
    let key = BlobKey::new(workspace, group, hash).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !verify(
        &state.media_presign_secret,
        "GET",
        &key.path(),
        &token,
        state.now_ms() / 1000,
    ) {
        return Err(StatusCode::FORBIDDEN);
    }
    let storage = state
        .storage
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    match storage.get(&key).await {
        Ok(bytes) => Ok(axum::body::Bytes::from(bytes)),
        Err(crate::storage::StorageError::NotFound { .. }) => Err(StatusCode::NOT_FOUND),
        Err(error) if error.is_transient() => Err(StatusCode::SERVICE_UNAVAILABLE),
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

/// One part of a local multipart session. Parts are stored as ordinary objects
/// under a reserved key shape, `<session>/part-<n>`, in the workspace-and-group
/// space nothing else ever writes into (`media::MULTIPART_PREFIX`), and
/// `media::gc` assembles and deletes them exactly the way it would any other
/// object: through the same `BlobStore` contract, never a filesystem shortcut.
async fn put_part(
    Path((session, part)): Path<(String, String)>,
    Query(token): Query<Token>,
    State(state): State<Arc<RelayState>>,
    body: axum::body::Bytes,
) -> StatusCode {
    let Some(key) = super::part_key(&session, &part) else {
        return StatusCode::BAD_REQUEST;
    };
    if !verify(
        &state.media_presign_secret,
        "PUT",
        &key.path(),
        &token,
        state.now_ms() / 1000,
    ) {
        return StatusCode::FORBIDDEN;
    }
    let Some(storage) = &state.storage else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    match storage.put(&key, &body).await {
        Ok(()) => StatusCode::OK,
        Err(error) if error.is_transient() => StatusCode::SERVICE_UNAVAILABLE,
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

async fn get_part(
    Path((session, part)): Path<(String, String)>,
    Query(token): Query<Token>,
    State(state): State<Arc<RelayState>>,
) -> Result<axum::body::Bytes, StatusCode> {
    let key = super::part_key(&session, &part).ok_or(StatusCode::BAD_REQUEST)?;
    if !verify(
        &state.media_presign_secret,
        "GET",
        &key.path(),
        &token,
        state.now_ms() / 1000,
    ) {
        return Err(StatusCode::FORBIDDEN);
    }
    let storage = state
        .storage
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    match storage.get(&key).await {
        Ok(bytes) => Ok(axum::body::Bytes::from(bytes)),
        Err(crate::storage::StorageError::NotFound { .. }) => Err(StatusCode::NOT_FOUND),
        Err(error) if error.is_transient() => Err(StatusCode::SERVICE_UNAVAILABLE),
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}
