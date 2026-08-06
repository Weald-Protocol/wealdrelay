// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The outbound leg: one POST to the ringer, and what its answer means.
//!
//! `specs/backend/relay/ringer.md` route 3 is the whole contract this speaks:
//! `POST {url}` with `{ handle, category }` and nothing else, answered `202`, `404`
//! or `429`. The request carries no other field, because the ringer refuses one and
//! because silently tolerating an extra field is how a group identifier eventually
//! arrives in a payload.
//!
//! ## What this may never do
//!
//! Retry into a queue that can grow. A non-2xx answer is counted and dropped. `429`
//! pauses the worker for the interval the ringer named, which is a pause rather than
//! a queue: the wakes that arrive during it are coalesced by
//! ``crate::push::queue::Queue`` and shed at its bound, both of which are bounded.
//! `404` deletes the row, because the ringer has told us the device is gone and
//! keeping the row would be keeping a dead capability.
//!
//! ## Why the bearer is optional
//!
//! Authority to wake a device is possession of the handle, which the device minted
//! and handed out, so a ringer configured without a credential serving any caller is
//! correct and deliberate (`ringer.md` route 3). The bearer exists for an operator
//! who wants their ringer to answer only their relay, and it is never logged: it is
//! set on the request and nowhere else, and `--check-config` prints `[set]`.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

/// What the ringer said, in the four shapes the caller acts on differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// `2xx`. The wake is on its way to Apple, or was dropped there, and either way
    /// the relay's part is done.
    Accepted,
    /// `404`. The ringer does not know this handle, so the row is deleted.
    Unknown,
    /// `429`, with the interval to hold off for. Pauses this worker; nothing is
    /// requeued.
    Paused { seconds: u64 },
    /// Any other answer. Counted and dropped: the ringer is reachable and said no,
    /// and a relay that retried would be a relay amplifying somebody else's fault.
    Refused,
    /// No answer at all inside the deadline: connection refused, DNS, TLS, or a
    /// ringer that accepted the connection and then said nothing. The one outcome
    /// that makes `/readyz` report `unreachable`, which is deliberately still ready.
    Unreachable,
}

/// A pooled HTTP client for the wake path.
///
/// One client for the process, built once, because the point of HTTP/2 here is a
/// pooled connection: a wake is a few hundred bytes and a fresh TLS handshake per
/// wake would cost more than everything else on this path put together.
#[derive(Clone)]
pub struct Ringer {
    client: Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
}

/// No `Debug` that could print the client's internals, and one that says so.
impl std::fmt::Debug for Ringer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ringer")
    }
}

impl Default for Ringer {
    fn default() -> Self {
        Self::new()
    }
}

impl Ringer {
    pub fn new() -> Self {
        // The provider is named rather than taken from the process default. Two are
        // reachable in this dependency graph and `ClientConfig::builder()` panics
        // when it cannot choose, which would be a panic on the wake path of a relay
        // that started perfectly. `expect` is on a configuration that cannot vary at
        // runtime: safe default protocol versions against the ring provider, which
        // is the pair rustls itself ships.
        let tls = hyper_rustls::HttpsConnectorBuilder::new()
            .with_provider_and_webpki_roots(rustls::crypto::ring::default_provider())
            .expect("rustls accepts its own safe defaults over the ring provider")
            // `https_or_http` rather than `https_only`, because `local` and `ci`
            // point at a loopback ringer over plaintext and reach no vendor at all.
            // Every other deployment is refused a plaintext url at startup by
            // `Config::enforce_push`, which is where that rule belongs: a connector
            // that refused it here would refuse it after the relay had already
            // started and told the operator it was configured.
            .https_or_http()
            .enable_all_versions()
            .build();
        Self {
            client: Client::builder(TokioExecutor::new()).build(tls),
        }
    }

    /// Ring one handle, once, inside the deadline.
    ///
    /// The handle is hex encoded, which is the form `ringer.md` mints and accepts. It
    /// is never logged here or anywhere below: the request body is built and moved
    /// into the client, and no error path formats it.
    pub async fn wake(
        &self,
        url: &str,
        token: Option<&str>,
        handle: &[u8],
        category: super::Category,
    ) -> Outcome {
        let body = format!(
            "{{\"handle\":\"{}\",\"category\":\"{}\"}}",
            hex(handle),
            category.as_str()
        );
        let mut request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(url)
            .header(hyper::header::CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            request = request.header(hyper::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let Ok(request) = request.body(Full::new(Bytes::from(body))) else {
            // A url the builder cannot parse. Refused rather than retried, and
            // reachable only from a caller passing something `Config` did not
            // validate, which is why it is an outcome rather than a panic.
            return Outcome::Refused;
        };

        let sent = tokio::time::timeout(
            Duration::from_millis(super::WAKE_DEADLINE_MS),
            self.client.request(request),
        )
        .await;
        let response = match sent {
            Ok(Ok(response)) => response,
            // A ringer that hangs and a ringer that is not there are the same fact
            // from the relay's side: no answer. Both are `unreachable`, and neither
            // is allowed to hold anything up, which is what the deadline is for.
            Ok(Err(_)) | Err(_) => return Outcome::Unreachable,
        };
        let status = response.status();
        let retry_after = response
            .headers()
            .get(hyper::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok());
        // Drained rather than dropped, so the pooled connection is reusable for the
        // next wake instead of being torn down with a body still on it.
        let _ = response.into_body().collect().await;

        if status.is_success() {
            return Outcome::Accepted;
        }
        match status.as_u16() {
            404 => Outcome::Unknown,
            429 => Outcome::Paused {
                // A ringer that answered `429` without an interval is still telling
                // the relay to stop, so a default stands in rather than the pause
                // being skipped. One coalescing window is the smallest pause that
                // means anything.
                seconds: retry_after.unwrap_or(1),
            },
            _ => Outcome::Refused,
        }
    }
}

/// Lowercase hex, for the one field the wake request carries.
///
/// Written here rather than reusing `logging::hex_prefix`, which truncates to twelve
/// characters on purpose: that function exists to make a value safe for a log, and
/// this one has to be complete for the ringer to resolve it. Two functions, so
/// neither can be used for the other's job by accident.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The process-wide client, built on first use.
///
/// A `OnceLock` rather than a field on `RelayState`, because building it needs no
/// configuration and every relay that has push on wants exactly one. A relay with
/// push off never touches it and therefore never builds a TLS configuration it has
/// no use for.
static SHARED: std::sync::OnceLock<Arc<Ringer>> = std::sync::OnceLock::new();

pub fn shared() -> Arc<Ringer> {
    Arc::clone(SHARED.get_or_init(|| Arc::new(Ringer::new())))
}
