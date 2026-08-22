// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Every answer `media::handle` can give to a `BLOB` frame.
//!
//! Tier 3 and tier 4. `media::handle` is the whole media surface: `ws.rs` decodes
//! one frame, hands the payload here, and queues whatever comes back. So this
//! file drives that function directly against a real Postgres and a real object
//! store, and `tests/media_socket.rs` proves the same exchange over a real
//! WebSocket. Splitting it that way is deliberate: the socket suite proves the
//! frame reaches the handler, and this one proves the handler is right about
//! every case, including the ones that need the database or the bucket to be
//! broken in a specific way.
//!
//! Faults are real states of real dependencies, never injected error values: a
//! renamed table is what a half-applied migration looks like, a trigger that
//! raises is what a constraint violation looks like, an `S3Store` with no bucket
//! is what a misconfigured relay looks like, and a port nothing listens on is
//! what an outage looks like.

mod support;

use std::sync::Arc;
use std::time::Duration;

use aws_sdk_s3::config::retry::RetryConfig;
use aws_sdk_s3::config::timeout::TimeoutConfig;
use sqlx::PgPool;
use wealdrelay::config::keys;
use wealdrelay::frame::{ErrorCode, Frame};
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::media::wire::{Request, Response};
use wealdrelay::media::{self, retention, store, RateLimiter};
use wealdrelay::session::Session;
use wealdrelay::storage::{BlobKey, FilesystemStore, S3Store, Store};

use support::{
    blob_hash, config_with, device_from, make_group_in, signed_control, signed_destruction,
    signed_manifest, signed_policy, verifier_key, Running, Scratch,
};

const NOW: u64 = 1_800_000_000_000;
const DAY: u64 = 24 * 60 * 60;
const WS: &str = "ws-media";

struct Harness {
    scratch: Scratch,
    _blobs: tempfile::TempDir,
    state: Arc<RelayState>,
    rate: RateLimiter,
}

impl Harness {
    async fn new(label: &str) -> Self {
        Self::with(label, [], |_| {}).await
    }

    async fn with(
        label: &str,
        extra: impl IntoIterator<Item = (&'static str, String)>,
        mutate: impl FnOnce(&mut RelayState),
    ) -> Self {
        let scratch = Scratch::new(label).await;
        let blobs = tempfile::tempdir().unwrap();
        let config = config_with(&scratch, blobs.path(), extra);
        let relay = Running::start_with(config, Clock::Fixed(NOW), mutate).await;
        let state = Arc::clone(&relay.state);
        relay.shutdown().await;
        Self {
            scratch,
            _blobs: blobs,
            state,
            rate: media::default_rate_limiter(),
        }
    }

    fn pool(&self) -> &PgPool {
        self.state.database.as_ref().expect("a database").pool()
    }

    fn storage(&self) -> &Store {
        self.state.storage.as_ref().expect("a store")
    }

    /// A group in `WS`, whose access set names `authorizers`, with `device` in it.
    async fn group(&self, byte: u8, authorizers: &[ed25519_dalek::SigningKey]) -> Vec<u8> {
        let devices: Vec<ed25519_dalek::SigningKey> = authorizers.to_vec();
        make_group_in(&self.state, WS, byte, &devices, authorizers).await
    }

    fn session(&self) -> Session {
        let mut session = Session::new(&self.state.config);
        session.bind_workspace(WS.to_string());
        session.bind_device(device_from(0x71).verifying_key().to_bytes().to_vec());
        session
    }

    async fn ask(&self, session: &Session, request: &Request) -> Frame {
        media::handle(&self.state, session, request.encode(), &self.rate).await
    }

    async fn ask_with(&self, session: &Session, rate: &RateLimiter, request: &Request) -> Frame {
        media::handle(&self.state, session, request.encode(), rate).await
    }

    async fn finish(self) {
        self.scratch.drop_database().await;
    }
}

#[track_caller]
fn error_code(frame: &Frame) -> ErrorCode {
    match frame {
        Frame::Error(error) => error.code,
        other => panic!("expected an error frame, got {other:?}"),
    }
}

#[track_caller]
fn response(frame: &Frame) -> Response {
    match frame {
        Frame::Blob { payload } => Response::decode(payload).expect("a media response"),
        other => panic!("expected a BLOB answer, got {other:?}"),
    }
}

fn put(group: &[u8], hash: &[u8], len: u64) -> Request {
    Request::Put {
        workspace: WS.as_bytes().to_vec(),
        group: group.to_vec(),
        hash: hash.to_vec(),
        ciphertext_len: len,
    }
}

fn get(group: &[u8], hash: &[u8]) -> Request {
    Request::Get {
        workspace: WS.as_bytes().to_vec(),
        group: group.to_vec(),
        hash: hash.to_vec(),
    }
}

fn key(workspace: &str, group: &[u8], hash: &[u8]) -> BlobKey {
    BlobKey::new(workspace, media::hex(group), media::hex(hash)).expect("a well formed key")
}

/// A real `S3Store` with no bucket name: presigning fails terminally on it while
/// nothing about it is faked. That is what a relay configured with an empty
/// `WEALD_RELAY_STORAGE_URL` bucket would do, and it is the only way to reach the
/// refusal `presigned` reports without breaking the network.
async fn bucketless_store() -> Store {
    Store::S3(S3Store::with_client(
        minio_client(true).await,
        String::new(),
        String::new(),
    ))
}

/// A real `S3Store` against a port nothing is listening on.
async fn unreachable_store() -> Store {
    Store::S3(S3Store::with_client(
        minio_client(false).await,
        "weald-blobs".to_string(),
        String::new(),
    ))
}

async fn minio_client(reachable: bool) -> aws_sdk_s3::Client {
    let credentials = aws_credential_types::Credentials::new(
        "weald",
        "weald-local-only",
        None,
        None,
        "weald-media-frames",
    );
    let endpoint = if reachable {
        "http://127.0.0.1:54090"
    } else {
        "http://127.0.0.1:1"
    };
    let loaded = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-east-1"))
        .endpoint_url(endpoint)
        .credentials_provider(credentials)
        .load()
        .await;
    let config = aws_sdk_s3::config::Builder::from(&loaded)
        .force_path_style(true)
        .retry_config(RetryConfig::disabled())
        .timeout_config(
            TimeoutConfig::builder()
                .operation_attempt_timeout(Duration::from_secs(2))
                .build(),
        )
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

async fn inject(pool: &PgPool, statement: &str) {
    sqlx::query(statement)
        .execute(pool)
        .await
        .unwrap_or_else(|error| panic!("the injected state must land: {statement}: {error}"));
}

/// A trigger that refuses whatever write it is attached to, the same technique
/// `tests/recovery_store_faults.rs` uses.
async fn refuse_inserts(pool: &PgPool, table: &str) {
    inject(
        pool,
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected: this write cannot land'; end $$",
    )
    .await;
    inject(
        pool,
        &format!(
            "create trigger weald_injected_insert_{table} before insert on {table} \
             for each statement execute function weald_injected_refusal()"
        ),
    )
    .await;
}

// MARK: The frame layer

#[tokio::test]
async fn a_payload_that_is_not_a_media_record_is_refused_before_anything_else() {
    let harness = Harness::new("frames_malformed").await;
    let session = harness.session();
    assert_eq!(
        error_code(&media::handle(&harness.state, &session, vec![0xff, 0xff], &harness.rate).await),
        ErrorCode::MalformedHeader
    );
    harness.finish().await;
}

/// A relay with no database cannot answer a single media question, and says so
/// as backpressure rather than as a refusal: the client should come back, not
/// give up.
#[tokio::test]
async fn a_relay_with_no_database_tells_the_client_to_come_back() {
    let scratch = Scratch::new("frames_nodb").await;
    let blobs = tempfile::tempdir().unwrap();
    let config = config_with(&scratch, blobs.path(), []);
    let state = Arc::new(RelayState::new(config, None, None));
    let mut session = Session::new(&state.config);
    session.bind_workspace(WS.to_string());
    session.bind_device(vec![1u8; 32]);
    let rate = media::default_rate_limiter();
    let frame = media::handle(
        &state,
        &session,
        put(&blob_hash(1), &blob_hash(2), 10).encode(),
        &rate,
    )
    .await;
    assert_eq!(error_code(&frame), ErrorCode::Backpressure);
    scratch.drop_database().await;
}

// MARK: BLOB put

#[tokio::test]
async fn a_put_is_answered_with_a_presigned_url_and_a_retry_is_free() {
    let harness = Harness::new("frames_put").await;
    let group = harness.group(0x41, &[device_from(0x71)]).await;
    let session = harness.session();
    let hash = blob_hash(0xa1);

    let answer = harness.ask(&session, &put(&group, &hash, 1024)).await;
    match response(&answer) {
        Response::Upload { url, expires_in } => {
            assert_eq!(expires_in, media::PRESIGN_TTL_SECONDS);
            assert!(
                url.contains(&media::hex(&hash)),
                "the URL names the object: {url}"
            );
            assert!(
                url.contains("sig="),
                "the local presign carries its token: {url}"
            );
        }
        other => panic!("expected an upload URL, got {other:?}"),
    }
    assert_eq!(
        store::usage(harness.pool(), WS)
            .await
            .unwrap()
            .reserved_bytes,
        1024
    );

    // The client uploads. Now the same `put` is `exists`, which is what makes a
    // retry after a dropped upload free.
    harness
        .storage()
        .put(&key(WS, &group, &hash), &vec![7u8; 1024])
        .await
        .unwrap();
    assert_eq!(
        response(&harness.ask(&session, &put(&group, &hash, 1024)).await),
        Response::Exists
    );

    harness.finish().await;
}

#[tokio::test]
async fn a_put_the_relay_cannot_serve_is_refused_by_the_reason_it_cannot() {
    let harness = Harness::new("frames_put_bad").await;
    let group = harness.group(0x42, &[device_from(0x71)]).await;
    let session = harness.session();

    // A blob of no bytes, and a blob past the 2 GiB ceiling.
    for length in [0, media::BLOB_MAX_BYTES + 1] {
        assert_eq!(
            error_code(
                &harness
                    .ask(&session, &put(&group, &blob_hash(1), length))
                    .await
            ),
            ErrorCode::EnvelopeTooLarge
        );
    }
    // Exactly at the ceiling is inside it.
    assert!(matches!(
        response(
            &harness
                .ask(&session, &put(&group, &blob_hash(2), media::BLOB_MAX_BYTES))
                .await
        ),
        Response::Multipart { .. }
    ));

    // A group this relay has never heard of.
    assert_eq!(
        error_code(
            &harness
                .ask(&session, &put(&blob_hash(0xcc), &blob_hash(1), 10))
                .await
        ),
        ErrorCode::GroupUnknown
    );

    // A group in another workspace. The session's own workspace is the only one
    // it may operate in, which is the rule `ws::authorize_group` enforces for
    // every other group-addressed frame.
    let elsewhere = make_group_in(
        &harness.state,
        "ws-other",
        0x43,
        &[device_from(0x71)],
        &[device_from(0x71)],
    )
    .await;
    assert_eq!(
        error_code(
            &harness
                .ask(&session, &put(&elsewhere, &blob_hash(1), 10))
                .await
        ),
        ErrorCode::WriterNotInAccessSet
    );

    // A session that has not been bound to a workspace at all.
    let anonymous = Session::new(&harness.state.config);
    assert_eq!(
        error_code(
            &harness
                .ask(&anonymous, &put(&group, &blob_hash(1), 10))
                .await
        ),
        ErrorCode::WriterNotInAccessSet
    );

    harness.finish().await;
}

#[tokio::test]
async fn a_workspace_out_of_storage_is_told_so_and_text_still_flows() {
    // One gigabyte, which is what `WEALD_RELAY_MAX_STORAGE_GB` means here.
    let harness = Harness::with(
        "frames_quota",
        [(keys::MAX_STORAGE_GB, "1".to_string())],
        |_| {},
    )
    .await;
    let group = harness.group(0x44, &[device_from(0x71)]).await;
    let session = harness.session();

    assert!(matches!(
        response(
            &harness
                .ask(&session, &put(&group, &blob_hash(1), 900_000_000))
                .await
        ),
        Response::Multipart { .. }
    ));

    // The boundary. `media.md`: over quota "returns a structured rejection the
    // client renders as 'this workspace is out of storage'". It is a named error
    // code and not a silence, and no reservation is taken for it.
    let refused = harness
        .ask(&session, &put(&group, &blob_hash(2), 200_000_000))
        .await;
    assert_eq!(error_code(&refused), ErrorCode::StorageExhausted);
    match &refused {
        Frame::Error(error) => assert_eq!(error.code.as_str(), "storage_exhausted"),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        store::usage(harness.pool(), WS)
            .await
            .unwrap()
            .reserved_bytes,
        900_000_000,
        "a refused upload takes no quota"
    );

    // "Text envelopes are never rejected for quota." The relay's own quota rows
    // are read by `BLOB put` and by nothing else, so a workspace with no bytes
    // left still accepts every envelope; `tests/media_socket.rs` proves the same
    // thing over a live socket, where a `SEND` is acknowledged while a `BLOB put`
    // in the same connection is refused.
    let usage = store::usage(harness.pool(), WS).await.unwrap();
    assert_eq!(usage.limit_bytes, Some(1_000_000_000));

    harness.finish().await;
}

/// The quota read answers the real row, before an upload is refused (WEALD-L401).
///
/// `relay_quota` was read inside `reserve` and `claim` and reported on no frame at
/// all, so the only way to learn a workspace's ceiling was to hit it: reaching a
/// 25 GB one on a hosted relay cost two hours and forty minutes of real uploading.
/// This asserts the three numbers a files view needs to warn first, against a
/// reservation and a claim that really happened, and it asserts them from the
/// handler rather than from `store::usage`: a read that authorized nothing, or that
/// reported the wrong side of the sum, would still agree with the store.
#[tokio::test]
async fn the_quota_read_reports_the_workspace_s_real_stored_limit_and_remaining() {
    let harness = Harness::with(
        "frames_quota_read",
        [(keys::MAX_STORAGE_GB, "1".to_string())],
        |_| {},
    )
    .await;
    let group = harness.group(0x4b, &[device_from(0x71)]).await;
    let session = harness.session();

    let quota = |frame: &Frame| match response(frame) {
        Response::Quota {
            stored_bytes,
            reserved_bytes,
            limit_bytes,
        } => (stored_bytes, reserved_bytes, limit_bytes),
        other => panic!("expected a quota answer, got {other:?}"),
    };

    // A workspace that has stored nothing still knows its ceiling. Before this the
    // row did not exist yet, and a read of a missing row answers "no limit", which
    // is the one wrong answer a warning could be built on.
    let empty = harness
        .ask(
            &session,
            &Request::Quota {
                group: group.clone(),
            },
        )
        .await;
    assert_eq!(quota(&empty), (0, 0, Some(1_000_000_000)));

    // One reservation in flight. `reserved_bytes` is on the wire because the
    // ceiling is enforced against the sum: a client shown only `stored_bytes` here
    // would promise 1 GB of room that is already spoken for.
    let hash = blob_hash(0x4c);
    assert!(matches!(
        response(
            &harness
                .ask(&session, &put(&group, &hash, 400_000_000))
                .await
        ),
        Response::Multipart { .. }
    ));
    let reserved = harness
        .ask(
            &session,
            &Request::Quota {
                group: group.clone(),
            },
        )
        .await;
    assert_eq!(quota(&reserved), (0, 400_000_000, Some(1_000_000_000)));

    // And the same bytes once they are claimed rather than reserved: the total the
    // ceiling is measured against has not moved, which is what a person reading
    // "600 MB left" is entitled to.
    assert!(store::claim(harness.pool(), WS, &group, &hash)
        .await
        .unwrap());
    let claimed = harness
        .ask(
            &session,
            &Request::Quota {
                group: group.clone(),
            },
        )
        .await;
    assert_eq!(quota(&claimed), (400_000_000, 0, Some(1_000_000_000)));

    // Another workspace's group is refused, exactly as a listing of it would be:
    // the quota read authorizes through `authorize_group` and reports a number that
    // belongs to whoever owns the group.
    let mut stranger = Session::new(&harness.state.config);
    stranger.bind_workspace("ws-somebody-else".to_string());
    stranger.bind_device(device_from(0x72).verifying_key().to_bytes().to_vec());
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &stranger,
                    &Request::Quota {
                        group: group.clone()
                    }
                )
                .await
        ),
        ErrorCode::WriterNotInAccessSet
    );

    harness.finish().await;
}

/// The read costs one request against the same budget a listing does.
///
/// A poll-shaped question that was free is a poll-shaped question a client will
/// make on every keystroke, and the media wire's whole rate story is per device.
#[tokio::test]
async fn the_quota_read_is_charged_against_the_device_s_request_budget() {
    let harness = Harness::new("frames_quota_rate").await;
    let group = harness.group(0x4e, &[device_from(0x71)]).await;
    let session = harness.session();
    let rate = RateLimiter::new(1, 60_000);

    assert!(matches!(
        response(
            &harness
                .ask_with(
                    &session,
                    &rate,
                    &Request::Quota {
                        group: group.clone()
                    }
                )
                .await
        ),
        Response::Quota { .. }
    ));
    assert_eq!(
        error_code(
            &harness
                .ask_with(
                    &session,
                    &rate,
                    &Request::Quota {
                        group: group.clone()
                    }
                )
                .await
        ),
        ErrorCode::RateLimited
    );

    harness.finish().await;
}

#[tokio::test]
async fn an_unlimited_relay_puts_no_ceiling_on_a_workspace() {
    let harness = Harness::with(
        "frames_unlimited",
        [(keys::MAX_STORAGE_GB, "unlimited".to_string())],
        |_| {},
    )
    .await;
    let group = harness.group(0x45, &[device_from(0x71)]).await;
    let session = harness.session();
    for seed in 0..3u8 {
        assert!(matches!(
            response(
                &harness
                    .ask(
                        &session,
                        &put(&group, &blob_hash(0x50 + seed), media::BLOB_MAX_BYTES)
                    )
                    .await
            ),
            Response::Multipart { .. }
        ));
    }
    assert_eq!(
        store::usage(harness.pool(), WS).await.unwrap().limit_bytes,
        None
    );
    harness.finish().await;
}

#[tokio::test]
async fn a_put_whose_workspace_cannot_be_a_key_is_refused_rather_than_guessed_at() {
    let harness = Harness::new("frames_put_badkey").await;
    let group = harness.group(0x46, &[device_from(0x71)]).await;
    inject(
        harness.pool(),
        "update relay_group set workspace_id = 'bad/ws' where group_id = decode('4646464646464646464646464646464646464646464646464646464646464646', 'hex')",
    )
    .await;
    let mut session = Session::new(&harness.state.config);
    session.bind_workspace("bad/ws".to_string());
    session.bind_device(device_from(0x71).verifying_key().to_bytes().to_vec());

    assert_eq!(
        error_code(&harness.ask(&session, &put(&group, &blob_hash(1), 10)).await),
        ErrorCode::MalformedHeader
    );
    assert_eq!(
        error_code(&harness.ask(&session, &get(&group, &blob_hash(1))).await),
        ErrorCode::MalformedHeader
    );

    harness.finish().await;
}

#[tokio::test]
async fn a_relay_with_no_object_store_cannot_take_an_upload() {
    let harness = Harness::with("frames_nostore", [], |state| state.storage = None).await;
    let group = harness.group(0x47, &[device_from(0x71)]).await;
    let session = harness.session();
    assert_eq!(
        error_code(&harness.ask(&session, &put(&group, &blob_hash(1), 10)).await),
        ErrorCode::Backpressure
    );
    assert_eq!(
        error_code(&harness.ask(&session, &get(&group, &blob_hash(1))).await),
        ErrorCode::Backpressure
    );
    harness.finish().await;
}

/// A relay whose store cannot presign has not refused the upload: the
/// reservation is taken and the object is still welcome, so the client is told
/// to come back rather than that its blob is unacceptable.
#[tokio::test]
async fn a_relay_that_cannot_presign_says_come_back_rather_than_no() {
    let harness = Harness::new("frames_nopresign").await;
    let group = harness.group(0x49, &[device_from(0x71)]).await;
    let session = harness.session();
    let hash = blob_hash(0xb0);
    let rate = media::default_rate_limiter();

    let broken = swap_storage(&harness.state, Some(bucketless_store().await));
    assert_eq!(
        error_code(&media::handle(&broken, &session, put(&group, &hash, 32).encode(), &rate).await),
        ErrorCode::Backpressure
    );
    // The reservation was taken before the URL was attempted, so a retry once the
    // store is healthy again is the same reservation rather than a second one.
    assert_eq!(
        store::usage(harness.pool(), WS)
            .await
            .unwrap()
            .reserved_bytes,
        32
    );
    assert!(matches!(
        response(&harness.ask(&session, &put(&group, &hash, 32)).await),
        Response::Upload { .. }
    ));
    assert_eq!(
        store::usage(harness.pool(), WS)
            .await
            .unwrap()
            .reserved_bytes,
        32
    );

    harness.finish().await;
}

// MARK: BLOB get

#[tokio::test]
async fn a_get_is_a_presigned_url_or_a_plain_not_found() {
    let harness = Harness::new("frames_get").await;
    let group = harness.group(0x4a, &[device_from(0x71)]).await;
    let session = harness.session();
    let hash = blob_hash(0xb1);

    // Nothing there yet. `media.md`: "a presigned GET URL, 15 minutes, or 404."
    assert_eq!(
        response(&harness.ask(&session, &get(&group, &hash)).await),
        Response::NotFound
    );

    harness
        .storage()
        .put(&key(WS, &group, &hash), b"ciphertext")
        .await
        .unwrap();
    match response(&harness.ask(&session, &get(&group, &hash)).await) {
        Response::Download { url, expires_in } => {
            assert_eq!(expires_in, media::PRESIGN_TTL_SECONDS);
            assert!(url.contains(&media::hex(&hash)));
        }
        other => panic!("expected a download URL, got {other:?}"),
    }

    // A session that authenticated as nobody has no device to budget against.
    let mut deviceless = Session::new(&harness.state.config);
    deviceless.bind_workspace(WS.to_string());
    assert_eq!(
        error_code(&harness.ask(&deviceless, &get(&group, &hash)).await),
        ErrorCode::WriterNotInAccessSet
    );

    // A group in another workspace, and one that does not exist.
    assert_eq!(
        error_code(&harness.ask(&session, &get(&blob_hash(0xcd), &hash)).await),
        ErrorCode::GroupUnknown
    );

    harness.finish().await;
}

/// `media.md`, "Bandwidth": "50 blob requests per minute, 5 GB per device per
/// day, both raisable per instance". Both limits are proven here, each against a
/// limiter configured to the boundary so the test is about the rule and not about
/// how long it takes to make fifty requests.
#[tokio::test]
async fn the_download_budget_holds_in_both_of_its_dimensions() {
    let harness = Harness::new("frames_rate").await;
    let group = harness.group(0x4b, &[device_from(0x71)]).await;
    let session = harness.session();
    let hash = blob_hash(0xb2);
    harness
        .storage()
        .put(&key(WS, &group, &hash), b"0123456789")
        .await
        .unwrap();

    // Three requests a minute, and plenty of bytes.
    let per_minute = RateLimiter::new(3, 1_000_000);
    for _ in 0..3 {
        assert!(matches!(
            response(
                &harness
                    .ask_with(&session, &per_minute, &get(&group, &hash))
                    .await
            ),
            Response::Download { .. }
        ));
    }
    let refused = harness
        .ask_with(&session, &per_minute, &get(&group, &hash))
        .await;
    assert_eq!(error_code(&refused), ErrorCode::RateLimited);
    match &refused {
        Frame::Error(error) => assert_eq!(error.retry_after, Some(60)),
        other => panic!("{other:?}"),
    }

    // Plenty of requests, and a daily budget of twenty-five bytes against a
    // ten-byte object: the third download is the one that does not fit.
    let per_day = RateLimiter::new(1_000, 25);
    for _ in 0..2 {
        assert!(matches!(
            response(
                &harness
                    .ask_with(&session, &per_day, &get(&group, &hash))
                    .await
            ),
            Response::Download { .. }
        ));
    }
    assert_eq!(
        error_code(
            &harness
                .ask_with(&session, &per_day, &get(&group, &hash))
                .await
        ),
        ErrorCode::RateLimited,
        "the daily budget is charged against the object's real size"
    );

    // Both windows are fixed and both turn over: a relay whose clock has moved on
    // by two days starts both counts again for the same device.
    let tomorrow = swap_clock(&harness.state, NOW + 2 * DAY * 1000);
    let rate_frame =
        media::handle(&tomorrow, &session, get(&group, &hash).encode(), &per_day).await;
    assert!(
        matches!(response(&rate_frame), Response::Download { .. }),
        "the budget a device spent yesterday is not the budget it has today"
    );
    assert!(matches!(
        response(
            &media::handle(
                &tomorrow,
                &session,
                get(&group, &hash).encode(),
                &per_minute
            )
            .await
        ),
        Response::Download { .. }
    ));

    harness.finish().await;
}

/// "An object storage outage renders media temporarily unavailable and never
/// deleted." This is the first half of that sentence, at the frame layer: a
/// download against an unreachable bucket is backpressure, never a `404`, because
/// a client told `404` renders "deleted or expired" for a blob that is still
/// there.
#[tokio::test]
async fn a_get_against_an_unreachable_bucket_is_backpressure_and_never_a_404() {
    let harness = Harness::new("frames_get_outage").await;
    let group = harness.group(0x4d, &[device_from(0x71)]).await;
    let session = harness.session();
    let hash = blob_hash(0xb3);
    harness
        .storage()
        .put(&key(WS, &group, &hash), b"still here")
        .await
        .unwrap();

    let down = swap_storage(&harness.state, Some(unreachable_store().await));
    let rate = media::default_rate_limiter();
    assert_eq!(
        error_code(&media::handle(&down, &session, get(&group, &hash).encode(), &rate).await),
        ErrorCode::Backpressure
    );

    // A store that answers and says no is a different thing: the bucket was
    // reached and it does not have the object, which is a `404`.
    let refusing = swap_storage(&harness.state, Some(bucketless_store().await));
    assert_eq!(
        response(&media::handle(&refusing, &session, get(&group, &hash).encode(), &rate).await),
        Response::NotFound
    );

    // And the object is untouched by either answer.
    assert!(harness
        .storage()
        .head(&key(WS, &group, &hash))
        .await
        .unwrap()
        .is_some());

    harness.finish().await;
}

// MARK: What the database being broken looks like from here

#[tokio::test]
async fn every_write_the_relay_cannot_land_is_answered_as_backpressure() {
    let harness = Harness::new("frames_db_faults").await;
    let group = harness.group(0x4e, &[device_from(0x71)]).await;
    let session = harness.session();
    let pool = harness.pool();

    // The quota row itself cannot be written.
    refuse_inserts(pool, "relay_quota").await;
    assert_eq!(
        error_code(&harness.ask(&session, &put(&group, &blob_hash(1), 10)).await),
        ErrorCode::Backpressure
    );
    inject(
        pool,
        "drop trigger weald_injected_insert_relay_quota on relay_quota",
    )
    .await;

    // The quota row lands and the reservation does not.
    refuse_inserts(pool, "relay_blob_reservation").await;
    assert_eq!(
        error_code(&harness.ask(&session, &put(&group, &blob_hash(1), 10)).await),
        ErrorCode::Backpressure
    );
    inject(
        pool,
        "drop trigger weald_injected_insert_relay_blob_reservation on relay_blob_reservation",
    )
    .await;

    // The reservation lands and the multipart session does not.
    refuse_inserts(pool, "relay_blob_multipart").await;
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &session,
                    &put(&group, &blob_hash(2), media::SINGLE_PART_MAX_BYTES + 1)
                )
                .await
        ),
        ErrorCode::Backpressure
    );
    inject(
        pool,
        "drop trigger weald_injected_insert_relay_blob_multipart on relay_blob_multipart",
    )
    .await;

    // And the group lookup itself failing is backpressure rather than "unknown
    // group", because a relay that cannot look must not answer as though it did.
    inject(pool, "alter table relay_group rename to relay_group_moved").await;
    assert_eq!(
        error_code(&harness.ask(&session, &put(&group, &blob_hash(3), 10)).await),
        ErrorCode::Backpressure
    );
    inject(pool, "alter table relay_group_moved rename to relay_group").await;

    harness.finish().await;
}

// MARK: The retention records, over the frame layer

#[tokio::test]
async fn the_retention_chain_is_driven_entirely_through_blob_frames() {
    let harness = Harness::new("frames_retention").await;
    let ada = device_from(0x71);
    let group = harness.group(0x50, std::slice::from_ref(&ada)).await;
    let session = harness.session();
    let epoch = verifier_key(0x21);

    // The control.
    let genesis = signed_control(&group, 0, &epoch, None, &epoch);
    match response(
        &harness
            .ask(&session, &Request::RetentionControl(genesis.clone()))
            .await,
    ) {
        Response::RetentionAck { digest } => assert_eq!(digest, genesis.digest()),
        other => panic!("expected an ack, got {other:?}"),
    }

    // A control that does not verify.
    let bad = signed_control(&group, 0, &epoch, Some(blob_hash(1)), &epoch);
    assert_eq!(
        error_code(&harness.ask(&session, &Request::RetentionControl(bad)).await),
        ErrorCode::MalformedHeader
    );

    // A reservation, so the manifest has something to claim.
    let hash = blob_hash(0xc1);
    assert!(matches!(
        response(&harness.ask(&session, &put(&group, &hash, 64)).await),
        Response::Upload { .. }
    ));

    let manifest = signed_manifest(&group, 0, 1, None, vec![hash.clone()], &epoch);
    match response(
        &harness
            .ask(&session, &Request::RetentionManifest(manifest.clone()))
            .await,
    ) {
        Response::RetentionAck { digest } => assert_eq!(digest, manifest.digest()),
        other => panic!("expected an ack, got {other:?}"),
    }
    assert_eq!(
        store::usage(harness.pool(), WS).await.unwrap().stored_bytes,
        64
    );

    // A manifest that does not verify.
    let forged = signed_manifest(
        &group,
        0,
        2,
        Some(manifest.digest()),
        vec![],
        &verifier_key(0xee),
    );
    assert_eq!(
        error_code(
            &harness
                .ask(&session, &Request::RetentionManifest(forged))
                .await
        ),
        ErrorCode::MalformedHeader
    );

    // A policy. One authorizer, so the seven-day solo grace applies.
    let policy = signed_policy(
        &group,
        1,
        30,
        NOW / 1000 + 8 * DAY,
        std::slice::from_ref(&ada),
    );
    assert!(matches!(
        response(
            &harness
                .ask(&session, &Request::RetentionPolicy(policy))
                .await
        ),
        Response::RetentionAck { .. }
    ));
    assert_eq!(
        retention::active_policy(harness.pool(), &group)
            .await
            .unwrap()
            .unwrap()
            .version,
        1
    );

    // A destruction, idempotent on its target.
    let destruction = signed_destruction(
        &group,
        "blob",
        &hash,
        NOW / 1000 + 8 * DAY,
        std::slice::from_ref(&ada),
    );
    for _ in 0..2 {
        assert!(matches!(
            response(
                &harness
                    .ask(
                        &session,
                        &Request::RetentionDestruction(destruction.clone())
                    )
                    .await
            ),
            Response::RetentionAck { .. }
        ));
    }
    assert!(
        retention::active_destruction(harness.pool(), &group, "blob", &hash)
            .await
            .unwrap()
            .is_some()
    );

    // Every one of the four refuses a group the session may not speak for.
    let anonymous = Session::new(&harness.state.config);
    for request in [
        Request::RetentionControl(signed_control(&group, 1, &epoch, None, &epoch)),
        Request::RetentionManifest(signed_manifest(&group, 0, 9, None, vec![], &epoch)),
        Request::RetentionPolicy(signed_policy(&group, 9, 30, 0, std::slice::from_ref(&ada))),
        Request::RetentionDestruction(signed_destruction(
            &group,
            "blob",
            &hash,
            0,
            std::slice::from_ref(&ada),
        )),
    ] {
        assert_eq!(
            error_code(&harness.ask(&anonymous, &request).await),
            ErrorCode::WriterNotInAccessSet
        );
    }

    harness.finish().await;
}

/// WEALD-308. The claim is where declared bytes become charged bytes, so it is
/// where an under-declared upload has to be caught: reserve one byte, write a
/// megabyte, and without the measurement the workspace is charged one byte for
/// it forever while `WEALD_RELAY_MAX_STORAGE_GB` never binds.
#[tokio::test]
async fn a_manifest_claiming_an_object_larger_than_it_declared_is_refused() {
    let harness = Harness::new("frames_underdeclared").await;
    let ada = device_from(0x71);
    let group = harness.group(0x58, std::slice::from_ref(&ada)).await;
    let session = harness.session();
    let epoch = verifier_key(0x22);
    assert!(matches!(
        response(
            &harness
                .ask(
                    &session,
                    &Request::RetentionControl(signed_control(&group, 0, &epoch, None, &epoch))
                )
                .await
        ),
        Response::RetentionAck { .. }
    ));

    let hash = blob_hash(0xc2);
    assert!(matches!(
        response(&harness.ask(&session, &put(&group, &hash, 1)).await),
        Response::Upload { .. }
    ));
    // The client uploads a megabyte against its one byte reservation.
    harness
        .storage()
        .put(&key(WS, &group, &hash), &vec![7u8; 1_000_000])
        .await
        .unwrap();

    let manifest = signed_manifest(&group, 0, 1, None, vec![hash.clone()], &epoch);
    assert_eq!(
        error_code(
            &harness
                .ask(&session, &Request::RetentionManifest(manifest.clone()))
                .await
        ),
        ErrorCode::HashMismatch
    );
    let usage = store::usage(harness.pool(), WS).await.unwrap();
    assert_eq!(
        usage.stored_bytes, 0,
        "a refused claim charges nothing to stored bytes"
    );
    assert_eq!(
        usage.reserved_bytes, 1,
        "and leaves the reservation exactly as it was, for the sweep to release"
    );

    // An honest object of the declared size is claimed as it always was, and the
    // manifest sequence is undisturbed by the refusal above.
    let honest = blob_hash(0xc3);
    assert!(matches!(
        response(&harness.ask(&session, &put(&group, &honest, 64)).await),
        Response::Upload { .. }
    ));
    harness
        .storage()
        .put(&key(WS, &group, &honest), &[9u8; 64])
        .await
        .unwrap();
    assert!(matches!(
        response(
            &harness
                .ask(
                    &session,
                    &Request::RetentionManifest(signed_manifest(
                        &group,
                        0,
                        1,
                        None,
                        vec![honest.clone()],
                        &epoch
                    ))
                )
                .await
        ),
        Response::RetentionAck { .. }
    ));
    assert_eq!(
        store::usage(harness.pool(), WS).await.unwrap().stored_bytes,
        64
    );

    harness.finish().await;
}

/// The freeze, over the wire: a conflicting control is answered `group_frozen`
/// rather than accepted, and the group stops garbage-collecting until a client
/// resolves it.
#[tokio::test]
async fn a_conflicting_control_is_answered_group_frozen() {
    let harness = Harness::new("frames_freeze").await;
    let group = harness.group(0x51, &[device_from(0x71)]).await;
    let session = harness.session();
    let epoch = verifier_key(0x21);

    let genesis = signed_control(&group, 0, &epoch, None, &epoch);
    harness
        .ask(&session, &Request::RetentionControl(genesis.clone()))
        .await;
    // Epoch one is where the freeze lives. WEALD-L183: a second *genesis* is
    // refused rather than frozen on, because any admitted device could mint one
    // for any group id in the workspace and a freeze it could set was a
    // permanent, unclearable stop on that group's retention.
    let rotated = signed_control(
        &group,
        1,
        &verifier_key(0x22),
        Some(genesis.digest()),
        &epoch,
    );
    harness
        .ask(&session, &Request::RetentionControl(rotated))
        .await;
    let forged = signed_control(
        &group,
        1,
        &verifier_key(0xee),
        Some(genesis.digest()),
        &epoch,
    );
    assert_eq!(
        error_code(
            &harness
                .ask(&session, &Request::RetentionControl(forged.clone()))
                .await
        ),
        ErrorCode::GroupFrozen
    );
    // A second one finds it already frozen, and is answered the same way.
    assert_eq!(
        error_code(
            &harness
                .ask(&session, &Request::RetentionControl(forged))
                .await
        ),
        ErrorCode::GroupFrozen
    );
    assert!(retention::is_frozen(harness.pool(), &group).await.unwrap());

    harness.finish().await;
}

/// WEALD-L183, the wire half: a genesis control roots a group's retention chain,
/// so the device publishing it must be named by the workspace's current access
/// set. Reaching the workspace is not enough, and a provisional grant is not
/// enough. The self-signature proves possession of a key the publisher made a
/// moment ago and nothing about the group.
#[tokio::test]
async fn a_genesis_control_from_a_device_outside_the_access_set_is_refused() {
    let harness = Harness::new("frames_genesis_binding").await;
    let group = harness.group(0x52, &[device_from(0x71)]).await;
    let epoch = verifier_key(0x21);

    // A session for a device the access set does not name, holding the same
    // workspace authorization the socket grants.
    let mut stranger = Session::new(&harness.state.config);
    stranger.bind_workspace(WS.to_string());
    stranger.bind_device(device_from(0xcc).verifying_key().to_bytes().to_vec());

    assert_eq!(
        error_code(
            &harness
                .ask(
                    &stranger,
                    &Request::RetentionControl(signed_control(&group, 0, &epoch, None, &epoch)),
                )
                .await
        ),
        ErrorCode::WriterNotInAccessSet
    );
    assert!(retention::latest_control(harness.pool(), &group)
        .await
        .unwrap()
        .is_none());
    assert!(!retention::is_frozen(harness.pool(), &group).await.unwrap());

    // The member's own genesis still lands.
    let session = harness.session();
    assert!(matches!(
        harness
            .ask(
                &session,
                &Request::RetentionControl(signed_control(&group, 0, &epoch, None, &epoch)),
            )
            .await,
        Frame::Blob { .. }
    ));

    harness.finish().await;
}

/// A policy or destruction the access set does not authorize is refused, and the
/// 30-day floor cannot be shortened by any version of any policy.
#[tokio::test]
async fn a_policy_is_refused_unless_it_is_authorized_and_at_or_above_the_floor() {
    let harness = Harness::new("frames_policy_rules").await;
    let ada = device_from(0x71);
    let bo = device_from(0x72);
    let group = harness.group(0x52, &[ada.clone(), bo.clone()]).await;
    let session = harness.session();

    // Under the floor. "The existing 30-day grace period remains a floor; a
    // policy can lengthen it but never shorten it."
    let short = signed_policy(
        &group,
        1,
        29,
        NOW / 1000 + 8 * DAY,
        &[ada.clone(), bo.clone()],
    );
    assert_eq!(
        error_code(
            &harness
                .ask(&session, &Request::RetentionPolicy(short))
                .await
        ),
        ErrorCode::MalformedHeader
    );

    // A first policy has to be version one.
    let misversioned = signed_policy(
        &group,
        4,
        30,
        NOW / 1000 + 8 * DAY,
        &[ada.clone(), bo.clone()],
    );
    assert_eq!(
        error_code(
            &harness
                .ask(&session, &Request::RetentionPolicy(misversioned))
                .await
        ),
        ErrorCode::MalformedHeader
    );

    // Two authorizers, one signature: not enough, whatever the window.
    let half = signed_policy(
        &group,
        1,
        30,
        NOW / 1000 + 400 * DAY,
        std::slice::from_ref(&ada),
    );
    assert_eq!(
        error_code(&harness.ask(&session, &Request::RetentionPolicy(half)).await),
        ErrorCode::WriterNotInAccessSet
    );

    // Both of them: accepted.
    let good = signed_policy(
        &group,
        1,
        60,
        NOW / 1000 + 8 * DAY,
        &[ada.clone(), bo.clone()],
    );
    assert!(matches!(
        response(&harness.ask(&session, &Request::RetentionPolicy(good)).await),
        Response::RetentionAck { .. }
    ));

    // A second policy has to advance the version by exactly one, and may not
    // shorten the window it replaces.
    let skipped = signed_policy(
        &group,
        3,
        90,
        NOW / 1000 + 8 * DAY,
        &[ada.clone(), bo.clone()],
    );
    assert_eq!(
        error_code(
            &harness
                .ask(&session, &Request::RetentionPolicy(skipped))
                .await
        ),
        ErrorCode::MalformedHeader
    );
    let shortened = signed_policy(
        &group,
        2,
        45,
        NOW / 1000 + 8 * DAY,
        &[ada.clone(), bo.clone()],
    );
    assert_eq!(
        error_code(
            &harness
                .ask(&session, &Request::RetentionPolicy(shortened))
                .await
        ),
        ErrorCode::MalformedHeader,
        "tightening a policy may not shorten an already-scheduled grace window"
    );
    let lengthened = signed_policy(
        &group,
        2,
        120,
        NOW / 1000 + 8 * DAY,
        &[ada.clone(), bo.clone()],
    );
    assert!(matches!(
        response(
            &harness
                .ask(&session, &Request::RetentionPolicy(lengthened.clone()))
                .await
        ),
        Response::RetentionAck { .. }
    ));

    // The same policy again is the same policy, not a version error. A client
    // that publishes a policy and is then refused further down the same exchange
    // republishes on its next attempt, which is ordinary rather than suspicious,
    // and answering it with `malformed_header` sends an operator looking for a
    // malformed record that does not exist. Signed again on the way, because
    // Ed25519 is randomised in the client this relay serves and the retry
    // therefore carries different signature bytes over identical terms.
    let resigned = signed_policy(
        &group,
        2,
        120,
        NOW / 1000 + 8 * DAY,
        &[ada.clone(), bo.clone()],
    );
    assert!(
        matches!(
            response(
                &harness
                    .ask(&session, &Request::RetentionPolicy(resigned))
                    .await
            ),
            Response::RetentionAck { .. }
        ),
        "a retransmission of the active policy is not a version error"
    );
    // And it did not become the next version: the chain is still at two, so a
    // genuine third policy is still version three.
    let third = signed_policy(
        &group,
        3,
        150,
        NOW / 1000 + 8 * DAY,
        &[ada.clone(), bo.clone()],
    );
    assert!(matches!(
        response(
            &harness
                .ask(&session, &Request::RetentionPolicy(third))
                .await
        ),
        Response::RetentionAck { .. }
    ));

    // The same threshold governs a one-off destruction.
    let solo = signed_destruction(
        &group,
        "blob",
        &blob_hash(1),
        NOW / 1000 + 400 * DAY,
        std::slice::from_ref(&ada),
    );
    assert_eq!(
        error_code(
            &harness
                .ask(&session, &Request::RetentionDestruction(solo))
                .await
        ),
        ErrorCode::WriterNotInAccessSet
    );
    let quorate = signed_destruction(
        &group,
        "blob",
        &blob_hash(1),
        NOW / 1000 + 8 * DAY,
        &[ada, bo],
    );
    assert!(matches!(
        response(
            &harness
                .ask(&session, &Request::RetentionDestruction(quorate))
                .await
        ),
        Response::RetentionAck { .. }
    ));

    harness.finish().await;
}

#[tokio::test]
async fn a_retention_record_the_relay_cannot_store_is_backpressure() {
    let harness = Harness::new("frames_retention_faults").await;
    let ada = device_from(0x71);
    let group = harness.group(0x53, std::slice::from_ref(&ada)).await;
    let session = harness.session();
    let pool = harness.pool();
    let epoch = verifier_key(0x21);

    inject(
        pool,
        "alter table relay_retention_control rename to rrc_moved",
    )
    .await;
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &session,
                    &Request::RetentionControl(signed_control(&group, 0, &epoch, None, &epoch))
                )
                .await
        ),
        ErrorCode::Backpressure
    );
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &session,
                    &Request::RetentionManifest(signed_manifest(
                        &group,
                        0,
                        1,
                        None,
                        vec![],
                        &epoch
                    ))
                )
                .await
        ),
        ErrorCode::Backpressure
    );
    inject(
        pool,
        "alter table rrc_moved rename to relay_retention_control",
    )
    .await;

    // The authorization check itself failing.
    inject(pool, "alter table relay_access_set rename to ras_moved").await;
    let policy = signed_policy(
        &group,
        1,
        30,
        NOW / 1000 + 8 * DAY,
        std::slice::from_ref(&ada),
    );
    assert_eq!(
        error_code(
            &harness
                .ask(&session, &Request::RetentionPolicy(policy.clone()))
                .await
        ),
        ErrorCode::Backpressure
    );
    let destruction = signed_destruction(
        &group,
        "blob",
        &blob_hash(1),
        NOW / 1000 + 8 * DAY,
        std::slice::from_ref(&ada),
    );
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &session,
                    &Request::RetentionDestruction(destruction.clone())
                )
                .await
        ),
        ErrorCode::Backpressure
    );
    inject(pool, "alter table ras_moved rename to relay_access_set").await;

    // The check passing and the write failing.
    refuse_inserts(pool, "relay_retention_policy").await;
    assert_eq!(
        error_code(
            &harness
                .ask(&session, &Request::RetentionPolicy(policy))
                .await
        ),
        ErrorCode::Backpressure
    );
    refuse_inserts(pool, "relay_retention_destruction").await;
    assert_eq!(
        error_code(
            &harness
                .ask(&session, &Request::RetentionDestruction(destruction))
                .await
        ),
        ErrorCode::Backpressure
    );

    harness.finish().await;
}

// MARK: Multipart

#[tokio::test]
async fn a_multipart_session_runs_from_open_to_finalized_over_frames() {
    let harness = Harness::new("frames_multipart").await;
    let group = harness.group(0x54, &[device_from(0x71)]).await;
    let session = harness.session();
    let hash = blob_hash(0xd1);
    let total = media::SINGLE_PART_MAX_BYTES + 16;

    let session_id = match response(&harness.ask(&session, &put(&group, &hash, total)).await) {
        Response::Multipart {
            session_id,
            part_size,
            expires_in,
        } => {
            assert_eq!(part_size, media::MULTIPART_PART_SIZE);
            assert_eq!(expires_in, media::PRESIGN_TTL_SECONDS);
            session_id
        }
        other => panic!("expected a multipart session, got {other:?}"),
    };

    // Two parts. Each one gets its own presigned URL with its own refreshable
    // window, which is what makes a 2 GiB upload survive a reconnect.
    let lengths = [media::MULTIPART_PART_SIZE, 16];
    for (index, length) in lengths.iter().enumerate() {
        let number = index as u32 + 1;
        let ask = Request::MultipartPart {
            session_id: session_id.clone(),
            part_number: number,
            expected_len: *length,
        };
        match response(&harness.ask(&session, &ask).await) {
            Response::MultipartPartUpload { url, expires_in } => {
                assert_eq!(expires_in, media::PRESIGN_TTL_SECONDS);
                assert!(url.contains(&format!("part-{number}")), "{url}");
            }
            other => panic!("expected a part URL, got {other:?}"),
        }
        // A refresh of the same part is the same part, not a second one.
        assert!(matches!(
            response(&harness.ask(&session, &ask).await),
            Response::MultipartPartUpload { .. }
        ));
        // And its length is immutable once issued.
        assert_eq!(
            error_code(
                &harness
                    .ask(
                        &session,
                        &Request::MultipartPart {
                            session_id: session_id.clone(),
                            part_number: number,
                            expected_len: length + 1,
                        }
                    )
                    .await
            ),
            ErrorCode::MalformedHeader
        );
    }

    // The client uploads both parts through the presigned URLs; here they are
    // written through the same store the URLs point at.
    let uuid = uuid::Uuid::from_slice(&session_id).unwrap();
    for (index, length) in lengths.iter().enumerate() {
        let number = index + 1;
        let part = BlobKey::new(
            "_multipart",
            uuid.simple().to_string(),
            format!("part-{number}"),
        )
        .unwrap();
        harness
            .storage()
            .put(&part, &vec![index as u8; *length as usize])
            .await
            .unwrap();
    }

    let complete = Request::MultipartComplete {
        session_id: session_id.clone(),
        parts: vec![(2, b"etag-two".to_vec()), (1, b"etag-one".to_vec())],
    };
    assert_eq!(
        response(&harness.ask(&session, &complete).await),
        Response::MultipartCompleted
    );

    // The object is assembled in part order, whatever order the client listed
    // them in, and the parts are gone.
    let assembled = harness
        .storage()
        .get(&key(WS, &group, &hash))
        .await
        .unwrap();
    assert_eq!(assembled.len() as u64, total);
    assert_eq!(assembled[0], 0);
    assert_eq!(assembled[assembled.len() - 1], 1);
    assert!(harness
        .storage()
        .list("_multipart", &uuid.simple().to_string())
        .await
        .unwrap()
        .is_empty());

    // Exactly once. A second COMPLETE is answered the same way the first was and
    // does not reassemble anything: the parts it would need are already gone.
    assert_eq!(
        response(&harness.ask(&session, &complete).await),
        Response::MultipartCompleted
    );
    let completions: i64 = sqlx::query_scalar(
        "select count(*) from relay_blob_multipart where session_id = $1 and completed_at is not null",
    )
    .bind(uuid)
    .fetch_one(harness.pool())
    .await
    .unwrap();
    assert_eq!(completions, 1);
    assert_eq!(
        store::usage(harness.pool(), WS)
            .await
            .unwrap()
            .reserved_bytes,
        total as i64,
        "finalizing the transfer does not finalize the reservation: only a manifest claim does"
    );

    // WEALD-L148. An abort after a successful completion is refused. The
    // reservation is still unfinalized at this point, so releasing it would hand
    // back quota for bytes that are in the bucket and, because the GC's known set
    // is built from reservation rows, would make the assembled object
    // unreferenced and sweepable at once.
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &session,
                    &Request::MultipartAbort {
                        session_id: session_id.clone()
                    }
                )
                .await
        ),
        ErrorCode::MalformedHeader
    );
    assert_eq!(
        store::usage(harness.pool(), WS)
            .await
            .unwrap()
            .reserved_bytes,
        total as i64,
        "an abort after completion must not release the reservation"
    );
    let reservations: i64 = sqlx::query_scalar(
        "select count(*) from relay_blob_reservation where workspace_id = $1 and blob_hash = $2",
    )
    .bind(WS)
    .bind(hash.as_slice())
    .fetch_one(harness.pool())
    .await
    .unwrap();
    assert_eq!(reservations, 1, "the reservation row survives the abort");
    assert_eq!(
        harness
            .storage()
            .get(&key(WS, &group, &hash))
            .await
            .unwrap()
            .len() as u64,
        total,
        "and the assembled object is still there"
    );

    // And a part cannot be added to a session that is already finished.
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &session,
                    &Request::MultipartPart {
                        session_id: session_id.clone(),
                        part_number: 3,
                        expected_len: 8,
                    }
                )
                .await
        ),
        ErrorCode::MalformedHeader
    );

    harness.finish().await;
}

#[tokio::test]
async fn an_aborted_session_gives_its_quota_back_and_accepts_nothing_further() {
    let harness = Harness::new("frames_multipart_abort").await;
    let group = harness.group(0x55, &[device_from(0x71)]).await;
    let session = harness.session();
    let total = media::SINGLE_PART_MAX_BYTES + 1;

    let session_id = match response(
        &harness
            .ask(&session, &put(&group, &blob_hash(0xd2), total))
            .await,
    ) {
        Response::Multipart { session_id, .. } => session_id,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        store::usage(harness.pool(), WS)
            .await
            .unwrap()
            .reserved_bytes,
        total as i64
    );

    assert_eq!(
        response(
            &harness
                .ask(
                    &session,
                    &Request::MultipartAbort {
                        session_id: session_id.clone()
                    }
                )
                .await
        ),
        Response::MultipartAborted
    );
    assert_eq!(
        store::usage(harness.pool(), WS)
            .await
            .unwrap()
            .reserved_bytes,
        0,
        "an aborted session releases the bytes it was holding"
    );

    // Nothing further is accepted for it.
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &session,
                    &Request::MultipartPart {
                        session_id: session_id.clone(),
                        part_number: 1,
                        expected_len: 8,
                    }
                )
                .await
        ),
        ErrorCode::MalformedHeader
    );
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &session,
                    &Request::MultipartComplete {
                        session_id: session_id.clone(),
                        parts: vec![],
                    }
                )
                .await
        ),
        ErrorCode::MalformedHeader
    );

    harness.finish().await;
}

/// WEALD-293. Four ways one multipart session used to be free storage: a part
/// number past the session's own part count, a part longer than the part size,
/// a completion listing a part twice or listing one that was never issued, and
/// an abort that returned the quota while leaving every part object in the
/// bucket.
#[tokio::test]
async fn a_multipart_session_owns_a_bounded_set_of_parts_and_takes_them_with_it() {
    let harness = Harness::new("frames_multipart_bounds").await;
    let group = harness.group(0x56, &[device_from(0x71)]).await;
    let session = harness.session();
    let total = media::SINGLE_PART_MAX_BYTES + 16;

    let session_id = match response(
        &harness
            .ask(&session, &put(&group, &blob_hash(0xd3), total))
            .await,
    ) {
        Response::Multipart { session_id, .. } => session_id,
        other => panic!("{other:?}"),
    };
    let uuid = uuid::Uuid::from_slice(&session_id).unwrap();
    let part = |number: u32, expected_len: u64| Request::MultipartPart {
        session_id: session_id.clone(),
        part_number: number,
        expected_len,
    };

    // The session covers two parts, so the third is not a part of it, and
    // neither is anything a `u32` can hold. Refused as too large rather than as
    // malformed: the frame is well formed, the number is out of range.
    assert_eq!(
        error_code(&harness.ask(&session, &part(3, 16)).await),
        ErrorCode::EnvelopeTooLarge
    );
    assert_eq!(
        error_code(&harness.ask(&session, &part(u32::MAX, 16)).await),
        ErrorCode::EnvelopeTooLarge
    );
    // Nor can one in-range part be longer than the part size the session was
    // opened with.
    assert_eq!(
        error_code(
            &harness
                .ask(&session, &part(1, media::MULTIPART_PART_SIZE + 1))
                .await
        ),
        ErrorCode::EnvelopeTooLarge
    );
    // None of the three left a row behind, so none of them can be completed
    // against later.
    assert_eq!(
        store::recorded_parts(harness.pool(), uuid).await.unwrap(),
        Vec::<i32>::new()
    );

    // Two real parts, uploaded through the store the presigned URLs point at.
    let lengths = [media::MULTIPART_PART_SIZE, 16];
    for (index, length) in lengths.iter().enumerate() {
        let number = index as u32 + 1;
        assert!(matches!(
            response(&harness.ask(&session, &part(number, *length)).await),
            Response::MultipartPartUpload { .. }
        ));
        harness
            .storage()
            .put(
                &media::part_key_for(uuid, number as i32),
                &vec![index as u8; *length as usize],
            )
            .await
            .unwrap();
    }

    // A completion that names part 1 twice would assemble it twice and still add
    // up to the reserved total, and a completion naming a part never issued
    // names an object of some other session.
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &session,
                    &Request::MultipartComplete {
                        session_id: session_id.clone(),
                        parts: vec![(1, b"a".to_vec()), (1, b"b".to_vec())],
                    }
                )
                .await
        ),
        ErrorCode::MalformedHeader
    );
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &session,
                    &Request::MultipartComplete {
                        session_id: session_id.clone(),
                        parts: vec![(1, b"a".to_vec()), (9, b"b".to_vec())],
                    }
                )
                .await
        ),
        ErrorCode::MalformedHeader
    );

    // The abort returns the bytes and takes the part objects with it, so the
    // quota and the bucket agree afterwards.
    assert_eq!(
        response(
            &harness
                .ask(
                    &session,
                    &Request::MultipartAbort {
                        session_id: session_id.clone()
                    }
                )
                .await
        ),
        Response::MultipartAborted
    );
    assert_eq!(
        store::usage(harness.pool(), WS)
            .await
            .unwrap()
            .reserved_bytes,
        0
    );
    assert!(
        harness
            .storage()
            .list("_multipart", &uuid.simple().to_string())
            .await
            .unwrap()
            .is_empty(),
        "an abort that frees the quota must not leave the parts in the bucket"
    );
    // And a second abort is the same answer, against nothing left to delete.
    assert_eq!(
        response(
            &harness
                .ask(&session, &Request::MultipartAbort { session_id })
                .await
        ),
        Response::MultipartAborted
    );

    harness.finish().await;
}

/// WEALD-293. Every other blob frame is charged against the per-device budget;
/// an uncharged `MULTIPART part` is a free loop that mints one presigned 64 MiB
/// upload URL per iteration.
#[tokio::test]
async fn a_multipart_part_is_charged_against_the_request_budget() {
    let harness = Harness::new("frames_multipart_rate").await;
    let group = harness.group(0x57, &[device_from(0x71)]).await;
    let session = harness.session();
    let total = media::SINGLE_PART_MAX_BYTES + 16;

    let session_id = match response(
        &harness
            .ask(&session, &put(&group, &blob_hash(0xd4), total))
            .await,
    ) {
        Response::Multipart { session_id, .. } => session_id,
        other => panic!("{other:?}"),
    };
    let ask = Request::MultipartPart {
        session_id,
        part_number: 1,
        expected_len: 16,
    };
    let rate = RateLimiter::new(1, 5_000_000_000);
    assert!(matches!(
        response(&harness.ask_with(&session, &rate, &ask).await),
        Response::MultipartPartUpload { .. }
    ));
    assert_eq!(
        error_code(&harness.ask_with(&session, &rate, &ask).await),
        ErrorCode::RateLimited
    );

    harness.finish().await;
}

#[tokio::test]
async fn every_way_a_multipart_frame_can_name_nothing_is_refused() {
    let harness = Harness::new("frames_multipart_bad").await;
    let group = harness.group(0x56, &[device_from(0x71)]).await;
    let session = harness.session();

    // A session id that is not a uuid, and one that names no session.
    for id in [vec![1u8; 4], uuid::Uuid::nil().as_bytes().to_vec()] {
        for request in [
            Request::MultipartPart {
                session_id: id.clone(),
                part_number: 1,
                expected_len: 8,
            },
            Request::MultipartComplete {
                session_id: id.clone(),
                parts: vec![],
            },
            Request::MultipartAbort {
                session_id: id.clone(),
            },
        ] {
            assert_eq!(
                error_code(&harness.ask(&session, &request).await),
                ErrorCode::MalformedHeader
            );
        }
    }

    let session_id = match response(
        &harness
            .ask(
                &session,
                &put(&group, &blob_hash(0xd3), media::SINGLE_PART_MAX_BYTES + 8),
            )
            .await,
    ) {
        Response::Multipart { session_id, .. } => session_id,
        other => panic!("{other:?}"),
    };

    // Part zero, and a part of no bytes. Part numbers start at one and a part
    // that carries nothing is not a part.
    for (number, length) in [(0u32, 8u64), (1, 0)] {
        assert_eq!(
            error_code(
                &harness
                    .ask(
                        &session,
                        &Request::MultipartPart {
                            session_id: session_id.clone(),
                            part_number: number,
                            expected_len: length,
                        }
                    )
                    .await
            ),
            ErrorCode::MalformedHeader
        );
    }

    // A session belonging to a group the caller may not speak for.
    let anonymous = Session::new(&harness.state.config);
    for request in [
        Request::MultipartPart {
            session_id: session_id.clone(),
            part_number: 1,
            expected_len: 8,
        },
        Request::MultipartComplete {
            session_id: session_id.clone(),
            parts: vec![],
        },
        Request::MultipartAbort {
            session_id: session_id.clone(),
        },
    ] {
        assert_eq!(
            error_code(&harness.ask(&anonymous, &request).await),
            ErrorCode::WriterNotInAccessSet
        );
    }

    // A COMPLETE naming parts that were never uploaded.
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &session,
                    &Request::MultipartComplete {
                        session_id: session_id.clone(),
                        parts: vec![(1, b"etag".to_vec())],
                    }
                )
                .await
        ),
        ErrorCode::MalformedHeader
    );

    // A COMPLETE whose parts do not add up to what was reserved. The relay's own
    // accounting is the reservation's byte total, never the sum of what the
    // client says it uploaded.
    // The part is asked for before it is written, which is what a client does and
    // what this test was missing.
    //
    // `MultipartComplete` refuses any part number the relay did not record
    // (`media/mod.rs`: `recorded_parts`), and it refuses it before it heads a
    // single object. Writing bytes straight into storage therefore never reached
    // the byte-total check this assertion is about; it hit the earlier refusal
    // and answered `MalformedHeader`, so the accounting rule the comment below
    // describes has never actually been exercised. Asking for the part URL is
    // what records it.
    let uuid = uuid::Uuid::from_slice(&session_id).unwrap();
    assert!(matches!(
        response(
            &harness
                .ask(
                    &session,
                    &Request::MultipartPart {
                        session_id: session_id.clone(),
                        part_number: 1,
                        expected_len: 8,
                    }
                )
                .await
        ),
        Response::MultipartPartUpload { .. }
    ));
    let part = BlobKey::new("_multipart", uuid.simple().to_string(), "part-1").unwrap();
    harness.storage().put(&part, b"short").await.unwrap();
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &session,
                    &Request::MultipartComplete {
                        session_id: session_id.clone(),
                        parts: vec![(1, b"etag".to_vec())],
                    }
                )
                .await
        ),
        ErrorCode::HashMismatch
    );

    harness.finish().await;
}

#[tokio::test]
async fn a_multipart_frame_the_relay_cannot_serve_is_backpressure() {
    let harness = Harness::new("frames_multipart_faults").await;
    let group = harness.group(0x57, &[device_from(0x71)]).await;
    let session = harness.session();
    let pool = harness.pool();
    let total = media::SINGLE_PART_MAX_BYTES + 8;

    // `part_size` is taken from the reservation rather than discarded, because it
    // is the ceiling a part URL is checked against (`media/mod.rs`: an
    // `expected_len` above it is `EnvelopeTooLarge`). This asked for a part as
    // large as the whole upload, so it was refused on the size before it reached
    // the injected fault below and the fault it exists to prove never ran.
    let (session_id, part_size) = match response(
        &harness
            .ask(&session, &put(&group, &blob_hash(0xd4), total))
            .await,
    ) {
        Response::Multipart {
            session_id,
            part_size,
            ..
        } => (session_id, part_size),
        other => panic!("{other:?}"),
    };
    let uuid = uuid::Uuid::from_slice(&session_id).unwrap();

    // The part row cannot be written.
    refuse_inserts(pool, "relay_blob_multipart_part").await;
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &session,
                    &Request::MultipartPart {
                        session_id: session_id.clone(),
                        part_number: 1,
                        expected_len: part_size,
                    }
                )
                .await
        ),
        ErrorCode::Backpressure
    );
    inject(
        pool,
        "drop trigger weald_injected_insert_relay_blob_multipart_part on relay_blob_multipart_part",
    )
    .await;

    // The parts are there and the completion cannot be recorded.
    let part = BlobKey::new("_multipart", uuid.simple().to_string(), "part-1").unwrap();
    harness
        .storage()
        .put(&part, &vec![0u8; total as usize])
        .await
        .unwrap();
    inject(pool, "alter table relay_blob_multipart rename to rbm_moved").await;
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &session,
                    &Request::MultipartComplete {
                        session_id: session_id.clone(),
                        parts: vec![(1, b"etag".to_vec())],
                    }
                )
                .await
        ),
        ErrorCode::MalformedHeader,
        "a session that cannot be read is a session that does not exist"
    );
    inject(pool, "alter table rbm_moved rename to relay_blob_multipart").await;

    harness.finish().await;
}

/// The store side of multipart: a relay with no store, an unreachable one, and
/// one that refuses the assembled write.
#[tokio::test]
async fn a_multipart_completion_against_broken_storage_never_reports_success() {
    let scratch = Scratch::new("frames_multipart_storage").await;
    let blobs = tempfile::tempdir().unwrap();
    let config = config_with(&scratch, blobs.path(), []);

    // A relay with a store, to open the session and write the part.
    let relay = Running::start(config.clone(), Clock::Fixed(NOW)).await;
    let state = Arc::clone(&relay.state);
    relay.shutdown().await;
    let group = make_group_in(&state, WS, 0x58, &[device_from(0x71)], &[device_from(0x71)]).await;
    let mut session = Session::new(&state.config);
    session.bind_workspace(WS.to_string());
    session.bind_device(device_from(0x71).verifying_key().to_bytes().to_vec());
    let rate = media::default_rate_limiter();
    let total = media::SINGLE_PART_MAX_BYTES + 8;

    let opened = media::handle(
        &state,
        &session,
        put(&group, &blob_hash(0xd5), total).encode(),
        &rate,
    )
    .await;
    let (session_id, part_size) = match response(&opened) {
        Response::Multipart {
            session_id,
            part_size,
            ..
        } => (session_id, part_size),
        other => panic!("expected a multipart session, got {other:?}"),
    };
    let uuid = uuid::Uuid::from_slice(&session_id).unwrap();
    // Part 1 is asked for against the healthy store before the stores below are
    // swapped out. `MultipartComplete` refuses a part number the relay never
    // recorded (`media/mod.rs`: `recorded_parts`) before it reads a single
    // object, so writing the bytes straight into the bucket answered
    // `MalformedHeader` and none of the storage faults this test exists to prove
    // were ever reached.
    assert!(matches!(
        response(
            &media::handle(
                &state,
                &session,
                Request::MultipartPart {
                    session_id: session_id.clone(),
                    part_number: 1,
                    expected_len: part_size,
                }
                .encode(),
                &rate,
            )
            .await
        ),
        Response::MultipartPartUpload { .. }
    ));
    let part = BlobKey::new("_multipart", uuid.simple().to_string(), "part-1").unwrap();
    state
        .storage
        .as_ref()
        .unwrap()
        .put(&part, &vec![0u8; total as usize])
        .await
        .unwrap();

    let complete = Request::MultipartComplete {
        session_id: session_id.clone(),
        parts: vec![(1, b"etag".to_vec())],
    };
    let ask_part = Request::MultipartPart {
        session_id: session_id.clone(),
        part_number: 2,
        expected_len: 8,
    };

    // No store at all. The part URL cannot be presigned and the assembly cannot
    // be read, and both are backpressure rather than a refusal.
    let stateless = swap_storage(&state, None);
    assert_eq!(
        error_code(&media::handle(&stateless, &session, ask_part.encode(), &rate).await),
        ErrorCode::Backpressure
    );
    assert_eq!(
        error_code(&media::handle(&stateless, &session, complete.encode(), &rate).await),
        ErrorCode::Backpressure
    );

    // A store that cannot be presigned against.
    let unpresignable = swap_storage(&state, Some(bucketless_store().await));
    assert_eq!(
        error_code(&media::handle(&unpresignable, &session, ask_part.encode(), &rate).await),
        ErrorCode::Backpressure
    );

    // A store that cannot be reached. The parts are unreadable, so nothing is
    // assembled and nothing is marked complete.
    let down = swap_storage(&state, Some(unreachable_store().await));
    assert_eq!(
        error_code(&media::handle(&down, &session, complete.encode(), &rate).await),
        ErrorCode::Backpressure
    );

    // A store that can be read and cannot be written: the parts assemble and the
    // object refuses to land, which must never be reported as a completion.
    let readonly = tempfile::tempdir().unwrap();
    let readonly_store = Store::Filesystem(FilesystemStore::new(readonly.path().to_path_buf()));
    readonly_store
        .put(&part, &vec![0u8; total as usize])
        .await
        .unwrap();
    set_mode(readonly.path(), 0o500);
    let refusing = swap_storage(&state, Some(readonly_store));
    assert_eq!(
        error_code(&media::handle(&refusing, &session, complete.encode(), &rate).await),
        ErrorCode::Backpressure
    );
    set_mode(readonly.path(), 0o700);

    // And with the real store back, it completes.
    assert_eq!(
        response(&media::handle(&state, &session, complete.encode(), &rate).await),
        Response::MultipartCompleted
    );

    scratch.drop_database().await;
}

/// The same relay state with a different store behind it. `RelayState` owns its
/// database pool, so this shares it rather than opening a second one: the point
/// is to vary the store and nothing else.
fn swap_storage(state: &Arc<RelayState>, storage: Option<Store>) -> Arc<RelayState> {
    let mut copy = RelayState::new(
        state.config.clone(),
        state.database.clone(),
        storage.map(Arc::new),
    );
    copy.clock = Clock::Fixed(NOW);
    Arc::new(copy)
}

fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("the test owns this directory");
}

/// The same relay state with its clock moved on, for the fixed windows the
/// download budget is measured in.
fn swap_clock(state: &Arc<RelayState>, now_ms: u64) -> Arc<RelayState> {
    let mut copy = RelayState::new(
        state.config.clone(),
        state.database.clone(),
        state.storage.clone(),
    );
    copy.clock = Clock::Fixed(now_ms);
    Arc::new(copy)
}

/// Every way a finalization can be refused after the session was legitimately
/// opened, each one for its own reason.
///
/// `media.md` puts the relay's own accounting ahead of anything the client says:
/// "a completed upload is finalized exactly once before the reservation becomes
/// stored usage". These are the four refusals on the way to that, and none of them
/// may be reported as a completion, because a completion is what turns a
/// reservation into billed storage and tells the client its attachment is safe.
#[tokio::test]
async fn a_finalization_is_refused_for_each_reason_it_can_be() {
    let harness = Harness::new("frames_multipart_refusals").await;
    let group = harness.group(0x55, &[device_from(0x71)]).await;
    let session = harness.session();
    let total = media::SINGLE_PART_MAX_BYTES + 16;

    // Open a session, so each case below starts from one that would otherwise
    // finalize. Written as a closure returning a future rather than an `async`
    // block that captures, so the four cases can each call it.
    async fn open(
        harness: &Harness,
        session: &Session,
        group: &[u8],
        total: u64,
        hash: Vec<u8>,
    ) -> (Vec<u8>, uuid::Uuid) {
        let opened = harness.ask(session, &put(group, &hash, total)).await;
        let session_id = match response(&opened) {
            Response::Multipart { session_id, .. } => session_id,
            other => panic!("expected a multipart session, got {other:?}"),
        };
        let uuid = uuid::Uuid::from_slice(&session_id).unwrap();
        (session_id, uuid)
    }

    // 1. An aborted session. `media.md`: "Stale multipart sessions are aborted and
    //    their reservations released", and a client that comes back afterwards
    //    holding a session id must be told no rather than handed a completion for
    //    an upload whose bytes were already released.
    let (session_id, uuid) = open(&harness, &session, &group, total, blob_hash(0xe1)).await;
    store::abort_multipart(harness.pool(), uuid)
        .await
        .expect("the session aborts");
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &session,
                    &Request::MultipartComplete {
                        session_id: session_id.clone(),
                        parts: vec![(1, b"etag".to_vec())],
                    }
                )
                .await
        ),
        ErrorCode::MalformedHeader,
        "an aborted session cannot be finalized"
    );

    // 2. A part that is present and unreadable. Distinct from a part that is
    //    absent, which is the `Ok(None)` case above, and distinct from a backend
    //    that is down, which is transient and must invite a retry. This one is the
    //    bucket answering with something that is not a blob, and a retry will not
    //    help, so it is a refusal.
    let (session_id, uuid) = open(&harness, &session, &group, total, blob_hash(0xe2)).await;
    let unreadable = tempfile::tempdir().unwrap();
    let unreadable_store = Store::Filesystem(FilesystemStore::new(unreadable.path().to_path_buf()));
    let part = BlobKey::new("_multipart", uuid.simple().to_string(), "part-1").unwrap();
    unreadable_store
        .put(&part, &vec![0u8; total as usize])
        .await
        .unwrap();
    // The part is there and its directory refuses to be traversed, so the stat
    // fails with a permission error rather than a missing file. Chosen after a
    // directory-in-place-of-a-part turned out to stat perfectly well and produce a
    // size mismatch instead, which is a different branch and a different answer.
    let enclosing = unreadable
        .path()
        .join("_multipart")
        .join(uuid.simple().to_string());
    set_mode(&enclosing, 0o000);
    let obstructed = swap_storage(&harness.state, Some(unreadable_store));
    let refused = error_code(
        &media::handle(
            &obstructed,
            &session,
            Request::MultipartComplete {
                session_id: session_id.clone(),
                parts: vec![(1, b"etag".to_vec())],
            }
            .encode(),
            &harness.rate,
        )
        .await,
    );
    set_mode(&enclosing, 0o700);
    assert_eq!(
        refused,
        ErrorCode::MalformedHeader,
        "a part that cannot be read is not a retry"
    );

    // 3. Parts that do not add up to what was reserved. The relay measures rather
    //    than believing the client, so a set that is short is a hash mismatch and
    //    never a completion: the reservation is the number the customer is billed
    //    for and the object would be wrong anyway.
    let (session_id, uuid) = open(&harness, &session, &group, total, blob_hash(0xe3)).await;
    // The part is asked for before it is written. `MultipartComplete` refuses a
    // part number the relay never recorded, and refuses it before it heads a
    // single object (`media/mod.rs`: `recorded_parts`), so writing bytes straight
    // into the bucket answered `MalformedHeader` and the byte accounting this
    // case exists for was never reached.
    assert!(matches!(
        response(
            &harness
                .ask(
                    &session,
                    &Request::MultipartPart {
                        session_id: session_id.clone(),
                        part_number: 1,
                        expected_len: 8,
                    }
                )
                .await
        ),
        Response::MultipartPartUpload { .. }
    ));
    let part = BlobKey::new("_multipart", uuid.simple().to_string(), "part-1").unwrap();
    harness
        .storage()
        .put(&part, &vec![0u8; (total - 1) as usize])
        .await
        .unwrap();
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &session,
                    &Request::MultipartComplete {
                        session_id: session_id.clone(),
                        parts: vec![(1, b"etag".to_vec())],
                    }
                )
                .await
        ),
        ErrorCode::HashMismatch,
        "a short set of parts is refused against the reservation"
    );

    // A part request against a session that is no longer open. Aborted here; the
    // completed case is the exactly-once path above, which answers rather than
    // refuses. An aborted session has already had its reservation released, so
    // issuing a part URL for it would be issuing a URL against bytes nobody is
    // accounting for.
    let (aborted_id, aborted_uuid) = open(&harness, &session, &group, total, blob_hash(0xe7)).await;
    store::abort_multipart(harness.pool(), aborted_uuid)
        .await
        .expect("the session aborts");
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &session,
                    &Request::MultipartPart {
                        session_id: aborted_id,
                        part_number: 1,
                        expected_len: 16,
                    }
                )
                .await
        ),
        ErrorCode::MalformedHeader,
        "an aborted session issues no more part URLs"
    );

    // 4. The object assembles and the session cannot be marked complete. The
    //    dangerous one: the bytes are now in the bucket, so answering "done" would
    //    leave a session that is finalized in storage and open in the database, and
    //    the next sweep would release a reservation for an object that exists.
    //    Backpressure, so the client asks again and the exactly-once path answers.
    let (session_id, uuid) = open(&harness, &session, &group, total, blob_hash(0xe4)).await;
    // Two parts, recorded and then written, because this case has to get all the
    // way through assembly to reach the failure it injects.
    //
    // `total` is one byte-count larger than a single part may carry
    // (`MULTIPART_PART_SIZE`), so it was never coverable by the one part this
    // wrote: the part URL was refused `EnvelopeTooLarge`, and before that the
    // unrecorded part number was refused `MalformedHeader`. Either way the relay
    // never assembled anything and the "object landed, session did not" state
    // this case is named for could not arise.
    let split = [
        (1u32, media::MULTIPART_PART_SIZE),
        (2, total - media::MULTIPART_PART_SIZE),
    ];
    for (number, length) in split {
        assert!(matches!(
            response(
                &harness
                    .ask(
                        &session,
                        &Request::MultipartPart {
                            session_id: session_id.clone(),
                            part_number: number,
                            expected_len: length,
                        }
                    )
                    .await
            ),
            Response::MultipartPartUpload { .. }
        ));
        let part = BlobKey::new(
            "_multipart",
            uuid.simple().to_string(),
            format!("part-{number}"),
        )
        .unwrap();
        harness
            .storage()
            .put(&part, &vec![0u8; length as usize])
            .await
            .unwrap();
    }
    inject(
        harness.pool(),
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected: this write cannot land'; end $$",
    )
    .await;
    inject(
        harness.pool(),
        "create trigger weald_injected_complete before update on relay_blob_multipart \
         for each statement execute function weald_injected_refusal()",
    )
    .await;
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &session,
                    &Request::MultipartComplete {
                        session_id: session_id.clone(),
                        parts: vec![(1, b"etag".to_vec()), (2, b"etag".to_vec())],
                    }
                )
                .await
        ),
        ErrorCode::Backpressure,
        "an object that landed and a session that did not is a retry, never a completion"
    );

    // A part number and a length of zero, which are the two shapes of a part
    // request that cannot mean anything. Parts are one-based, so part zero is not
    // a part, and a zero-length part would reserve nothing and assemble nothing.
    // Refused before a URL is issued, because a presigned URL for a part that
    // cannot exist is a URL that can only be misused.
    let (session_id, _) = open(&harness, &session, &group, total, blob_hash(0xe6)).await;
    for (part_number, expected_len) in [(0u32, 16u64), (1, 0)] {
        assert_eq!(
            error_code(
                &harness
                    .ask(
                        &session,
                        &Request::MultipartPart {
                            session_id: session_id.clone(),
                            part_number,
                            expected_len,
                        }
                    )
                    .await
            ),
            ErrorCode::MalformedHeader,
            "part {part_number} of length {expected_len} is not a part"
        );
    }

    // 5. A workspace that cannot be an object key, discovered at finalization. The
    //    parts are all present and add up, so this is the last check before the
    //    object would be written, and it has to refuse rather than construct a key
    //    by guessing at what the workspace meant. Same injection as
    //    `a_put_whose_workspace_cannot_be_a_key_is_refused_rather_than_guessed_at`,
    //    applied after the session was legitimately opened.
    let (session_id, uuid) = open(&harness, &session, &group, total, blob_hash(0xe5)).await;
    let part = BlobKey::new("_multipart", uuid.simple().to_string(), "part-1").unwrap();
    harness
        .storage()
        .put(&part, &vec![0u8; total as usize])
        .await
        .unwrap();
    inject(
        harness.pool(),
        "drop trigger weald_injected_complete on relay_blob_multipart",
    )
    .await;
    inject(
        harness.pool(),
        "update relay_group set workspace_id = 'bad/ws' where group_id = decode('5555555555555555555555555555555555555555555555555555555555555555', 'hex')",
    )
    .await;
    let mut renamed = Session::new(&harness.state.config);
    renamed.bind_workspace("bad/ws".to_string());
    renamed.bind_device(device_from(0x71).verifying_key().to_bytes().to_vec());
    assert_eq!(
        error_code(
            &harness
                .ask(
                    &renamed,
                    &Request::MultipartComplete {
                        session_id: session_id.clone(),
                        parts: vec![(1, b"etag".to_vec())],
                    }
                )
                .await
        ),
        ErrorCode::MalformedHeader,
        "a workspace that cannot be a key is refused at finalization too"
    );

    harness.finish().await;
}

// MARK: BLOB list at scale (WEALD-L399)

/// A hash that is distinct per index, so a thousand of them are a thousand
/// objects rather than one written a thousand times.
fn indexed_hash(index: u16) -> Vec<u8> {
    let mut hash = vec![0u8; 32];
    hash[0] = (index >> 8) as u8;
    hash[1] = (index & 0xff) as u8;
    hash
}

/// A listing of a thousand objects is built from the relay's own reservation
/// rows, in one query, and never from one `head` per object.
///
/// The regression this holds shut is WEALD-L399: `handle_list` used to head every
/// key before it encoded a reply, so a group holding a few hundred objects took
/// longer than the client's exchange window and the files view answered "the
/// relay did not answer the listing" at every size above that. The assertion is
/// therefore both halves: every object is named with its charged length, and the
/// whole answer arrives well inside the window a person is waiting on.
#[tokio::test]
async fn a_listing_of_a_thousand_objects_is_answered_from_the_reservation_rows() {
    let harness = Harness::with("frames_list_scale", [], |_| {}).await;
    let group = harness.group(0x4c, &[device_from(0x71)]).await;
    let session = harness.session();
    let pool = harness.pool();
    let store = harness.storage();

    const COUNT: u16 = 1000;
    const BYTES: i64 = 4096;
    for index in 0..COUNT {
        let hash = indexed_hash(index);
        store
            .put(&key(WS, &group, &hash), &vec![7u8; BYTES as usize])
            .await
            .expect("the object is written");
        store::ensure_quota_row(pool, WS, None)
            .await
            .expect("a quota row");
        store::reserve(
            pool,
            WS,
            &group,
            &hash,
            BYTES,
            false,
            i64::from(media::PRESIGN_TTL_SECONDS),
        )
        .await
        .expect("a reservation");
    }

    let started = std::time::Instant::now();
    let frame = harness
        .ask(
            &session,
            &Request::List {
                workspace: WS.as_bytes().to_vec(),
                group: group.clone(),
            },
        )
        .await;
    let elapsed = started.elapsed();

    match response(&frame) {
        Response::Listing { entries } => {
            assert_eq!(entries.len(), COUNT as usize);
            assert!(
                entries.iter().all(|(_, len)| *len == BYTES as u64),
                "every entry carries the length the reservation was charged for"
            );
        }
        other => panic!("expected a listing, got {other:?}"),
    }
    assert!(
        elapsed < Duration::from_secs(5),
        "a thousand-object listing took {elapsed:?}, which is a per-object head loop"
    );
    harness.finish().await;
}

// MARK: A joiner's upload (WEALD-L400)

/// A second device's small upload is stored, and its manifest claim accepted, on
/// exactly the terms the founder's is.
///
/// WEALD-L400: against a live cell the founder's 4 KB `media-put` stored while a
/// joined second workspace's identical put came back `reject/malformed_header`
/// twice. `media.md:25-58` gives every group member the same upload path, and
/// mp.14 and mp.15 had only ever been driven from the founder side, so nothing
/// covered this direction. The joiner here holds no genesis key and never will,
/// which is the whole difference between the two devices: it reads the chain
/// position the relay reports, signs at the epoch that position names with the
/// key every member of that epoch derives, and extends the chain by one.
#[tokio::test]
async fn a_joiners_manifest_claim_is_accepted_on_the_founders_terms() {
    let harness = Harness::new("frames_joiner_claim").await;
    let founder_device = device_from(0x71);
    let joiner_device = device_from(0x72);
    let group = harness
        .group(0x52, &[founder_device.clone(), joiner_device.clone()])
        .await;
    let genesis_key = verifier_key(0x21);
    let rotated_key = verifier_key(0x22);

    let mut founder = harness.session();
    founder.bind_device(founder_device.verifying_key().to_bytes().to_vec());
    // The joiner is the same workspace and a different device, which is what a
    // second Mac admitted to the access set is.
    let mut joiner = harness.session();
    joiner.bind_device(joiner_device.verifying_key().to_bytes().to_vec());

    // The founder's chain: genesis, then one rotation, which is the epoch the
    // joiner arrived at and the only retention key it holds.
    let genesis = signed_control(&group, 0, &genesis_key, None, &genesis_key);
    assert!(matches!(
        response(
            &harness
                .ask(&founder, &Request::RetentionControl(genesis.clone()))
                .await
        ),
        Response::RetentionAck { .. }
    ));
    let rotated = signed_control(
        &group,
        1,
        &rotated_key,
        Some(genesis.digest()),
        &genesis_key,
    );
    assert!(matches!(
        response(
            &harness
                .ask(&founder, &Request::RetentionControl(rotated))
                .await
        ),
        Response::RetentionAck { .. }
    ));

    // The founder's own 4 KB upload and claim, so the chain is already past its
    // first manifest when the joiner arrives.
    let founder_hash = blob_hash(0xf1);
    assert!(matches!(
        response(
            &harness
                .ask(&founder, &put(&group, &founder_hash, 4096))
                .await
        ),
        Response::Upload { .. }
    ));
    let first = signed_manifest(&group, 1, 1, None, vec![founder_hash.clone()], &rotated_key);
    assert!(matches!(
        response(
            &harness
                .ask(&founder, &Request::RetentionManifest(first.clone()))
                .await
        ),
        Response::RetentionAck { .. }
    ));

    // The joiner's identical put.
    let joiner_hash = blob_hash(0x1a);
    assert!(matches!(
        response(&harness.ask(&joiner, &put(&group, &joiner_hash, 4096)).await),
        Response::Upload { .. }
    ));

    // The position it builds its claim from, which is the whole of what a joiner
    // knows about a chain it did not start.
    let position = match response(
        &harness
            .ask(
                &joiner,
                &Request::RetentionPosition {
                    group: group.clone(),
                },
            )
            .await,
    ) {
        Response::RetentionPosition {
            control_epoch,
            next_sequence,
            prev_manifest_hash,
            blobs,
            ..
        } => (control_epoch, next_sequence, prev_manifest_hash, blobs),
        other => panic!("expected a chain position, got {other:?}"),
    };
    let (control_epoch, next_sequence, prev_manifest_hash, mut blobs) = position;
    assert_eq!(control_epoch, 1);
    assert_eq!(next_sequence, 2);
    assert_eq!(prev_manifest_hash, Some(first.digest()));
    // The union, never a replacement: a joiner that published only what it can
    // see would un-claim the founder's attachment.
    blobs.push(joiner_hash.clone());

    let claim = signed_manifest(
        &group,
        control_epoch,
        next_sequence,
        prev_manifest_hash,
        blobs,
        &rotated_key,
    );
    match response(
        &harness
            .ask(&joiner, &Request::RetentionManifest(claim.clone()))
            .await,
    ) {
        Response::RetentionAck { digest } => assert_eq!(digest, claim.digest()),
        other => panic!("a joiner's manifest claim was refused: {other:?}"),
    }
    // Both objects are charged, which is the founder's fetchable file and the
    // joiner's, not one at the cost of the other.
    assert_eq!(
        store::usage(harness.pool(), WS).await.unwrap().stored_bytes,
        8192
    );
    harness.finish().await;
}
