// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Media blobs: upload, download, quota, multipart, and the retention chain.
//!
//! `specs/backend/relay/media.md`. The whole surface arrives over `Frame::Blob {
//! payload }`, decoded by `wire::Request`/`wire::Response` the way
//! `invite::redeem` decodes `Frame::Join`. `handle` is this module's one entry
//! point from the socket layer, mirroring `ws.rs`'s `redeem`, `publish_wrap` and
//! `rotate_access_set`: it authorizes the group against the session's workspace,
//! does the work, and answers with exactly one `Frame`.
//!
//! ## How a multipart upload is actually finalized
//!
//! The relay does not hand the client an S3 multipart upload id. Each part is an
//! ordinary object under a reserved key space (`part_key`), with its own
//! presigned URL and its own refreshable window, so both storage backends carry a
//! part the same way and the contract suite that already proves whole-object
//! behaviour proves this too.
//!
//! Assembly is the backend's job, through `storage::BlobStore::assemble`. The
//! first version of this module read every part into memory, concatenated them
//! and wrote one object; that is recorded here rather than quietly replaced,
//! because it failed at exactly the size `media.md` requires. A single
//! `PutObject` of 2 GiB against MinIO fails reproducibly after about two minutes
//! with a dispatch failure, while 2,000,000,000 bytes succeeds in forty-three
//! seconds, and either way the relay would hold a whole attachment in its heap
//! twice. The S3 arm now issues one `UploadPartCopy` per part and the object is
//! built inside the bucket; the filesystem arm streams part into target through a
//! bounded buffer. The relay's memory cost for a 2 GiB upload is a megabyte.
//!
//! Completion is exactly once: a second `COMPLETE` for a session already marked
//! complete is answered the same way the first was, without reassembling
//! anything.

pub mod gc;
pub mod http;
pub mod restore;
pub mod retention;
pub mod store;
pub mod wire;

use std::sync::Arc;
use std::time::Duration;

use crate::access;
use crate::frame::{ErrorCode, Frame, FrameError};
use crate::health::RelayState;
use crate::session::Session;
use crate::storage::{BlobKey, StorageError, Store};

/// Above this, a `PUT` becomes a multipart session. `media.md`: "Above 64 MB the
/// relay issues a multipart upload session instead."
pub const SINGLE_PART_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// The fixed part size this build uses for every multipart session.
pub const MULTIPART_PART_SIZE: u64 = 64 * 1024 * 1024;
/// `wire.md`'s blob ceiling, and `relay_blob_reservation_within_blob_limit`'s.
pub const BLOB_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// `media.md`: "a presigned PUT URL valid for 15 minutes", refreshable per part.
pub const PRESIGN_TTL_SECONDS: u32 = 15 * 60;

/// Lower-case hex. Object-key components must be shell- and path-safe, and the
/// wire carries raw 32-byte group ids and hashes, so every storage key in this
/// module is built from the hex form rather than the raw bytes.
pub fn hex(bytes: &[u8]) -> String {
    crate::invite::genesis::hex(bytes)
}

/// The key one multipart part is stored under: `_multipart/<session>/part-<n>`.
/// `_multipart` can never collide with a real workspace id, which is always
/// `ws:<hostname>` (`serve::bootstrap_workspace`).
pub fn part_key(session_hex: &str, part_label: &str) -> Option<BlobKey> {
    BlobKey::new("_multipart", session_hex, format!("part-{part_label}")).ok()
}

/// The same key, for a session this relay itself opened.
///
/// Infallible by construction, and that is the point of it existing beside
/// ``part_key``: a session id is a uuid and a part number is digits, so neither
/// component can carry a separator and there is no refusal for a caller to
/// handle. ``part_key`` is the fallible form and `media::http` is its only
/// caller, because there the components come off a URL somebody else wrote.
fn own_part_key(session: uuid::Uuid, part_number: u32) -> BlobKey {
    BlobKey::new(
        "_multipart",
        session.simple().to_string(),
        format!("part-{part_number}"),
    )
    .expect("a uuid and a part number are always well formed key components")
}

/// ``own_part_key`` for callers outside this module, notably the janitor, which
/// deletes a stale session's part objects and has only the session id and the
/// part numbers the database recorded.
pub fn part_key_for(session: uuid::Uuid, part_number: i32) -> BlobKey {
    own_part_key(session, part_number as u32)
}

fn object_key(workspace: &str, group: &[u8], hash: &[u8]) -> Result<BlobKey, StorageError> {
    BlobKey::new(workspace, hex(group), hex(hash))
}

/// A presigned URL for `key`, from whichever backend is configured.
///
/// The S3 arm is a real presigned request (`storage::s3::S3Store::presign_put`).
/// The filesystem arm, reachable only in `local`
/// (`specs/backend/build/environments.md`: the filesystem backend is `local`'s
/// only), presigns against the relay's own `/blob` route
/// (`media::http`) instead, because there is no real bucket on a laptop to
/// presign a request against.
async fn presign(
    state: &RelayState,
    key: &BlobKey,
    method: &str,
    ttl: Duration,
    content_length: Option<i64>,
) -> Result<String, StorageError> {
    let store = state
        .storage
        .as_ref()
        .ok_or_else(|| StorageError::Unreachable {
            reason: "no storage configured".to_string(),
        })?;
    match store.as_ref() {
        Store::S3(s3) => match method {
            // The write is bound to the length the quota was charged for; the read
            // is not bound to anything, because it stores nothing.
            "PUT" => s3.presign_put(key, ttl, content_length).await,
            _ => s3.presign_get(key, ttl).await,
        },
        Store::Filesystem(_) => {
            let expires_at = state.now_ms() / 1000 + ttl.as_secs();
            let sig = http::sign(&state.media_presign_secret, method, &key.path(), expires_at);
            let scheme_host = format!("http://{}", state.config.listen);
            Ok(format!(
                "{scheme_host}/blob/{}/{}/{}?exp={expires_at}&sig={sig}",
                key.workspace, key.group, key.hash
            ))
        }
    }
}

/// One presigned URL, as the `Frame` the client gets back.
///
/// The three callers (`BLOB put`, `BLOB get`, and one multipart part) differ
/// only in the method and in which response carries the URL, so the refusal is
/// written once. A relay that cannot presign has not failed the request
/// permanently: the object and the reservation are both still there, so the
/// answer is `Backpressure` and the client retries.
async fn presigned(
    state: &Arc<RelayState>,
    key: &BlobKey,
    method: &str,
    content_length: Option<i64>,
    carry: impl FnOnce(String) -> wire::Response,
) -> Frame {
    match presign(
        state,
        key,
        method,
        Duration::from_secs(u64::from(PRESIGN_TTL_SECONDS)),
        content_length,
    )
    .await
    {
        Ok(url) => Frame::Blob {
            payload: carry(url).encode(),
        },
        Err(error) => {
            tracing::warn!(error = %error, method, "media: could not presign");
            Frame::Error(FrameError::new(ErrorCode::Backpressure))
        }
    }
}

/// A per-device download budget. `media.md`: "50 blob requests per minute, 5 GB
/// per device per day, both raisable per instance." Both are fixed windows
/// rather than sliding ones: a fixed window is what a single process-local
/// counter can enforce without a shared clock service, and the numbers are
/// generous enough that a window edge is not a product concern.
///
/// The two limits are charged at different moments and so are two methods
/// rather than one. The request count is charged before the relay looks the
/// object up, so a client cannot probe for hashes for free; the byte budget is
/// charged after, because until the object has been found there is no size to
/// charge and a budget charged at zero is a budget that never binds.
#[derive(Debug, Default)]
struct DeviceUsage {
    minute_bucket: u64,
    minute_count: u32,
    day_bucket: u64,
    day_bytes: u64,
}

#[derive(Debug, Default)]
pub struct RateLimiter {
    /// A `tokio::sync::Mutex` for the reason `hub::Hub` gives for using one: a
    /// `std::sync::Mutex` poisons on a panic, and the recovery arm that would
    /// then be needed is an arm nothing can reach, because nothing inside this
    /// critical section can panic. A lock that does not poison has no such arm.
    devices: tokio::sync::Mutex<std::collections::HashMap<Vec<u8>, DeviceUsage>>,
    pub requests_per_minute: u32,
    pub bytes_per_day: u64,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32, bytes_per_day: u64) -> Self {
        Self {
            devices: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            requests_per_minute,
            bytes_per_day,
        }
    }

    /// Whether `device` may make one more blob request in this minute. Charges
    /// the request when it may.
    pub async fn allow_request(&self, device: &[u8], now_ms: u64) -> bool {
        let mut guard = self.devices.lock().await;
        let usage = rolled(&mut guard, device, now_ms);
        if usage.minute_count >= self.requests_per_minute {
            return false;
        }
        usage.minute_count += 1;
        true
    }

    /// Whether `bytes` more fit inside `device`'s budget for this day. Charges
    /// them when they do.
    pub async fn allow_bytes(&self, device: &[u8], bytes: u64, now_ms: u64) -> bool {
        let mut guard = self.devices.lock().await;
        let usage = rolled(&mut guard, device, now_ms);
        if usage.day_bytes.saturating_add(bytes) > self.bytes_per_day {
            return false;
        }
        usage.day_bytes = usage.day_bytes.saturating_add(bytes);
        true
    }
}

/// One device's counters, with any window that has since turned over reset.
fn rolled<'a>(
    devices: &'a mut std::collections::HashMap<Vec<u8>, DeviceUsage>,
    device: &[u8],
    now_ms: u64,
) -> &'a mut DeviceUsage {
    let minute = now_ms / 60_000;
    let day = now_ms / 86_400_000;
    let usage = devices.entry(device.to_vec()).or_default();
    if usage.minute_bucket != minute {
        usage.minute_bucket = minute;
        usage.minute_count = 0;
    }
    if usage.day_bucket != day {
        usage.day_bucket = day;
        usage.day_bytes = 0;
    }
    usage
}

/// The relay's default posture: 50 requests/minute, 5 GB/day.
pub fn default_rate_limiter() -> RateLimiter {
    RateLimiter::new(50, 5 * 1_000_000_000)
}

/// Handle one `BLOB` frame's payload, and answer with exactly one `Frame`.
///
/// Public so `ws.rs`'s `Work::BlobTicket` arm can call it directly; the shape
/// matches `ws::redeem` and `ws::publish_wrap`, which take the same four
/// arguments and return the same `bool`. This function does not itself queue the
/// answer onto the socket: the caller does, so both the socket path and a test
/// driving this function directly see the same `Frame`.
pub async fn handle(
    state: &Arc<RelayState>,
    session: &Session,
    payload: Vec<u8>,
    rate: &RateLimiter,
) -> Frame {
    let request = match wire::Request::decode(&payload) {
        Ok(request) => request,
        Err(_) => return Frame::Error(FrameError::new(ErrorCode::MalformedHeader)),
    };
    let Some(pool) = state.database.as_ref().map(|db| db.pool()) else {
        return Frame::Error(FrameError::new(ErrorCode::Backpressure));
    };

    match request {
        wire::Request::Put {
            group,
            hash,
            ciphertext_len,
            ..
        } => handle_put(state, session, pool, &group, &hash, ciphertext_len).await,
        wire::Request::Get { group, hash, .. } => {
            handle_get(state, session, pool, &group, &hash, rate).await
        }
        wire::Request::MultipartPart {
            session_id,
            part_number,
            expected_len,
        } => {
            handle_multipart_part(
                state,
                session,
                pool,
                &session_id,
                part_number,
                expected_len,
                rate,
            )
            .await
        }
        wire::Request::MultipartComplete { session_id, parts } => {
            handle_multipart_complete(state, session, pool, &session_id, &parts).await
        }
        wire::Request::MultipartAbort { session_id } => {
            handle_multipart_abort(state, session, pool, &session_id).await
        }
        wire::Request::List { group, .. } => handle_list(state, session, pool, &group, rate).await,
        wire::Request::RetentionControl(record) => handle_control(session, pool, &record).await,
        wire::Request::RetentionManifest(record) => {
            handle_manifest(state, session, pool, &record).await
        }
        wire::Request::RetentionPolicy(record) => {
            handle_policy(state, session, pool, &record).await
        }
        wire::Request::RetentionDestruction(record) => {
            handle_destruction(state, session, pool, &record).await
        }
    }
}

/// The group named in a request must belong to the session's own workspace, the
/// same rule `ws::authorize_group` enforces for `SEND`, `SUB` and `RECON`.
async fn authorize_group(
    pool: &sqlx::PgPool,
    session: &Session,
    group: &[u8],
) -> Result<String, ErrorCode> {
    let Some(workspace) = session.authorized_workspace() else {
        return Err(ErrorCode::WriterNotInAccessSet);
    };
    match access::store::workspace_of(pool, group).await {
        Ok(Some(found)) if found == workspace => Ok(workspace.to_string()),
        Ok(Some(_)) => Err(ErrorCode::WriterNotInAccessSet),
        Ok(None) => Err(ErrorCode::GroupUnknown),
        Err(_) => Err(ErrorCode::Backpressure),
    }
}

async fn handle_put(
    state: &Arc<RelayState>,
    session: &Session,
    pool: &sqlx::PgPool,
    group: &[u8],
    hash: &[u8],
    ciphertext_len: u64,
) -> Frame {
    let workspace = match authorize_group(pool, session, group).await {
        Ok(workspace) => workspace,
        Err(code) => return Frame::Error(FrameError::new(code)),
    };
    if ciphertext_len == 0 || ciphertext_len > BLOB_MAX_BYTES {
        return Frame::Error(FrameError::new(ErrorCode::EnvelopeTooLarge));
    }
    let Ok(key) = object_key(&workspace, group, hash) else {
        return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
    };
    let Some(store) = &state.storage else {
        return Frame::Error(FrameError::new(ErrorCode::Backpressure));
    };
    let already_stored = matches!(store.head(&key).await, Ok(Some(_)));

    if let Err(error) = store::ensure_quota_row(pool, &workspace, limit_bytes(state)).await {
        tracing::warn!(error = %error, "media: could not ensure quota row");
        return Frame::Error(FrameError::new(ErrorCode::Backpressure));
    }

    let reservation = match store::reserve(
        pool,
        &workspace,
        group,
        hash,
        ciphertext_len as i64,
        already_stored,
        i64::from(PRESIGN_TTL_SECONDS),
    )
    .await
    {
        Ok(reservation) => reservation,
        Err(error) => {
            tracing::warn!(error = %error, "media: reservation failed");
            return Frame::Error(FrameError::new(ErrorCode::Backpressure));
        }
    };

    match reservation {
        store::Reserved::AlreadyStored => Frame::Blob {
            payload: wire::Response::Exists.encode(),
        },
        store::Reserved::OverQuota => Frame::Error(FrameError::new(ErrorCode::StorageExhausted)),
        store::Reserved::Active { reservation_id } => {
            if ciphertext_len > SINGLE_PART_MAX_BYTES {
                match store::create_multipart(
                    pool,
                    reservation_id,
                    "",
                    MULTIPART_PART_SIZE as i64,
                    i64::from(PRESIGN_TTL_SECONDS),
                )
                .await
                {
                    Ok(session_id) => Frame::Blob {
                        payload: wire::Response::Multipart {
                            session_id: session_id.as_bytes().to_vec(),
                            part_size: MULTIPART_PART_SIZE,
                            expires_in: PRESIGN_TTL_SECONDS,
                        }
                        .encode(),
                    },
                    Err(error) => {
                        tracing::warn!(error = %error, "media: could not open a multipart session");
                        Frame::Error(FrameError::new(ErrorCode::Backpressure))
                    }
                }
            } else {
                // Bound to exactly the length the reservation was charged for. The
                // client declared it, the quota was moved for it, and now the
                // object store will not take anything else.
                presigned(state, &key, "PUT", Some(ciphertext_len as i64), |url| {
                    wire::Response::Upload {
                        url,
                        expires_in: PRESIGN_TTL_SECONDS,
                    }
                })
                .await
            }
        }
    }
}

fn limit_bytes(state: &RelayState) -> Option<i64> {
    match state.config.max_storage_gb {
        crate::config::Limit::Unlimited => None,
        crate::config::Limit::Of(gb) => Some((gb as i64).saturating_mul(1_000_000_000)),
    }
}

async fn handle_get(
    state: &Arc<RelayState>,
    session: &Session,
    pool: &sqlx::PgPool,
    group: &[u8],
    hash: &[u8],
    rate: &RateLimiter,
) -> Frame {
    let workspace = match authorize_group(pool, session, group).await {
        Ok(workspace) => workspace,
        Err(code) => return Frame::Error(FrameError::new(code)),
    };
    let Some(device) = session.device_key() else {
        return Frame::Error(FrameError::new(ErrorCode::WriterNotInAccessSet));
    };
    // The request count is charged first, before the relay looks anything up, so
    // a caller cannot use `BLOB get` to probe for which hashes exist for free.
    if !rate.allow_request(device, state.now_ms()).await {
        return Frame::Error(FrameError::new(ErrorCode::RateLimited).retry_after(60));
    }
    let Ok(key) = object_key(&workspace, group, hash) else {
        return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
    };
    let Some(store) = &state.storage else {
        return Frame::Error(FrameError::new(ErrorCode::Backpressure));
    };
    let length = match store.head(&key).await {
        Ok(Some(info)) => info.len,
        Ok(None) => {
            return Frame::Blob {
                payload: wire::Response::NotFound.encode(),
            }
        }
        Err(error) if error.is_transient() => {
            return Frame::Error(FrameError::new(ErrorCode::Backpressure))
        }
        Err(_) => {
            return Frame::Blob {
                payload: wire::Response::NotFound.encode(),
            }
        }
    };
    // The daily budget is charged against the object's real size, which is the
    // number `media.md`'s "5 GB per device per day" is about. That size is
    // knowable only once the object has been found, which is why it is charged
    // here: a budget charged at zero bytes per request is a budget that never
    // binds at all.
    if !rate.allow_bytes(device, length, state.now_ms()).await {
        return Frame::Error(FrameError::new(ErrorCode::RateLimited).retry_after(60));
    }
    presigned(state, &key, "GET", None, |url| wire::Response::Download {
        url,
        expires_in: PRESIGN_TTL_SECONDS,
    })
    .await
}

/// Answer `BLOB list` with what the bucket holds for one group.
///
/// Authorized exactly like `BLOB get`, through ``authorize_group``, so a device
/// can only ever enumerate a group of its own workspace, and charged one request
/// against the same limiter for the same reason: a free listing is a free probe
/// for which objects exist.
///
/// The daily byte budget is deliberately not charged. A listing moves hashes and
/// lengths, not objects, and charging the sum of the sizes would make opening the
/// files view cost the same as downloading everything in it.
///
/// A `head` that fails for one object reports that object as zero length rather
/// than failing the listing: the file is there, and a view that showed nothing
/// because one size was unreadable would be the less true answer.
async fn handle_list(
    state: &Arc<RelayState>,
    session: &Session,
    pool: &sqlx::PgPool,
    group: &[u8],
    rate: &RateLimiter,
) -> Frame {
    let workspace = match authorize_group(pool, session, group).await {
        Ok(workspace) => workspace,
        Err(code) => return Frame::Error(FrameError::new(code)),
    };
    let Some(device) = session.device_key() else {
        return Frame::Error(FrameError::new(ErrorCode::WriterNotInAccessSet));
    };
    if !rate.allow_request(device, state.now_ms()).await {
        return Frame::Error(FrameError::new(ErrorCode::RateLimited).retry_after(60));
    }
    let Some(store) = &state.storage else {
        return Frame::Error(FrameError::new(ErrorCode::Backpressure));
    };
    let names = match store.list(&workspace, &hex(group)).await {
        Ok(names) => names,
        Err(error) if error.is_transient() => {
            return Frame::Error(FrameError::new(ErrorCode::Backpressure))
        }
        Err(_) => return Frame::Error(FrameError::new(ErrorCode::Backpressure)),
    };
    let mut entries = Vec::with_capacity(names.len());
    for name in names {
        let Ok(hash) = hex_bytes(&name) else { continue };
        let Ok(key) = object_key(&workspace, group, &hash) else {
            continue;
        };
        let len = match store.head(&key).await {
            Ok(Some(info)) => info.len,
            _ => 0,
        };
        entries.push((hash, len));
    }
    Frame::Blob {
        payload: wire::Response::Listing { entries }.encode(),
    }
}

/// The inverse of ``hex``, for the object names a listing comes back as.
fn hex_bytes(text: &str) -> Result<Vec<u8>, ()> {
    if !text.len().is_multiple_of(2) {
        return Err(());
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).map_err(|_| ()))
        .collect()
}

fn parse_session_id(bytes: &[u8]) -> Option<uuid::Uuid> {
    uuid::Uuid::from_slice(bytes).ok()
}

/// How many parts one session can have: `ceil(total_bytes / part_size)`.
///
/// `None` when the session's own numbers are unusable (a non-positive part size
/// or total), which the caller refuses rather than treating as unbounded.
fn session_part_count(multipart: &store::MultipartSession) -> Option<u64> {
    if multipart.part_size <= 0 || multipart.total_bytes <= 0 {
        return None;
    }
    let part_size = multipart.part_size as u64;
    Some((multipart.total_bytes as u64).div_ceil(part_size))
}

async fn handle_multipart_part(
    state: &Arc<RelayState>,
    session: &Session,
    pool: &sqlx::PgPool,
    session_id: &[u8],
    part_number: u32,
    expected_len: u64,
    rate: &RateLimiter,
) -> Frame {
    let Some(session_uuid) = parse_session_id(session_id) else {
        return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
    };
    let Some(device) = session.device_key() else {
        return Frame::Error(FrameError::new(ErrorCode::WriterNotInAccessSet));
    };
    // Charged before anything is looked up, for the reason `handle_get` is: an
    // uncharged part request is a free session probe, and uncharged it is also a
    // free loop that mints one presigned 64 MiB upload URL per iteration.
    if !rate.allow_request(device, state.now_ms()).await {
        return Frame::Error(FrameError::new(ErrorCode::RateLimited).retry_after(60));
    }
    let Ok(Some(multipart)) = store::find_multipart(pool, session_uuid).await else {
        return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
    };
    if authorize_group(pool, session, &multipart.group)
        .await
        .is_err()
    {
        return Frame::Error(FrameError::new(ErrorCode::WriterNotInAccessSet));
    }
    if multipart.completed || multipart.aborted || part_number == 0 || expected_len == 0 {
        return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
    }
    // A session covers exactly the bytes its reservation was charged for, so it
    // has exactly this many parts. Without the bound, any `u32` is a valid part
    // number and one reservation mints four billion upload URLs, none of which
    // the quota has heard of.
    let Some(max_parts) = session_part_count(&multipart) else {
        return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
    };
    if u64::from(part_number) > max_parts {
        return Frame::Error(FrameError::new(ErrorCode::EnvelopeTooLarge));
    }
    if let Ok(Some(existing)) = store::expected_len_of(pool, session_uuid, part_number as i32).await
    {
        // Checked before the length bound below, because a part already issued
        // is answered by its immutability rule whatever the client now claims.
        if existing as u64 != expected_len {
            return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
        }
    } else if expected_len > multipart.part_size as u64 {
        return Frame::Error(FrameError::new(ErrorCode::EnvelopeTooLarge));
    } else if let Err(error) =
        store::record_part(pool, session_uuid, part_number as i32, expected_len as i64).await
    {
        tracing::warn!(error = %error, "media: could not record a multipart part");
        return Frame::Error(FrameError::new(ErrorCode::Backpressure));
    }

    // The part is bound to the length recorded for it, which is the same number
    // the completion path adds up. A part URL that took any body would let one
    // recorded part number carry a whole upload.
    presigned(
        state,
        &own_part_key(session_uuid, part_number),
        "PUT",
        Some(expected_len as i64),
        |url| wire::Response::MultipartPartUpload {
            url,
            expires_in: PRESIGN_TTL_SECONDS,
        },
    )
    .await
}

async fn handle_multipart_complete(
    state: &Arc<RelayState>,
    session: &Session,
    pool: &sqlx::PgPool,
    session_id: &[u8],
    parts: &[(u32, Vec<u8>)],
) -> Frame {
    let Some(session_uuid) = parse_session_id(session_id) else {
        return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
    };
    let Ok(Some(multipart)) = store::find_multipart(pool, session_uuid).await else {
        return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
    };
    let workspace = match authorize_group(pool, session, &multipart.group).await {
        Ok(workspace) => workspace,
        Err(code) => return Frame::Error(FrameError::new(code)),
    };
    if multipart.aborted {
        return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
    }
    if multipart.completed {
        // Exactly-once finalization: a second COMPLETE for a session that is
        // already done is answered the same way the first one was, not refused.
        return Frame::Blob {
            payload: wire::Response::MultipartCompleted.encode(),
        };
    }
    let Some(store) = &state.storage else {
        return Frame::Error(FrameError::new(ErrorCode::Backpressure));
    };
    // The submitted list is the client's, so it is reconciled against the parts
    // this relay actually issued before a single key is built from it. A repeated
    // part number would otherwise be assembled twice and still add up to the
    // reserved total, and a number never issued names an object of somebody
    // else's session.
    let Ok(recorded) = store::recorded_parts(pool, session_uuid).await else {
        return Frame::Error(FrameError::new(ErrorCode::Backpressure));
    };
    let mut ordered = parts.to_vec();
    ordered.sort_by_key(|(number, _)| *number);
    if ordered.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
    }
    if ordered
        .iter()
        .any(|(number, _)| !recorded.contains(&(*number as i32)))
    {
        return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
    }
    let keys: Vec<BlobKey> = ordered
        .iter()
        .map(|(number, _etag)| own_part_key(session_uuid, *number))
        .collect();

    // The parts are measured before anything is assembled, because the relay's
    // own accounting is the reservation's byte total and never the sum of what
    // the client says it uploaded (`media.md`). A part that is not there, or a
    // set that does not add up to what was reserved, is refused here rather than
    // after an object has been written.
    let mut measured = 0i64;
    for key in &keys {
        match store.head(key).await {
            Ok(Some(info)) => measured += info.len as i64,
            Ok(None) => return Frame::Error(FrameError::new(ErrorCode::MalformedHeader)),
            Err(error) if error.is_transient() => {
                return Frame::Error(FrameError::new(ErrorCode::Backpressure))
            }
            Err(_) => return Frame::Error(FrameError::new(ErrorCode::MalformedHeader)),
        }
    }
    if measured != multipart.total_bytes {
        return Frame::Error(FrameError::new(ErrorCode::HashMismatch));
    }
    let Ok(final_key) = object_key(&workspace, &multipart.group, &multipart.hash) else {
        return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
    };
    // The bytes never pass through this process: `assemble` is on the storage
    // contract precisely so a 2 GiB attachment is built inside the bucket rather
    // than in the relay's heap. See `storage::BlobStore::assemble`.
    if let Err(error) = store.assemble(&keys, &final_key).await {
        tracing::warn!(error = %error, "media: could not assemble a multipart upload");
        return Frame::Error(FrameError::new(ErrorCode::Backpressure));
    }
    // Completion is recorded before the parts are cleaned up, and the order is the
    // whole point. `Backpressure` tells the client to retry, and a retry re-enters
    // above and heads the parts: with the parts already deleted and `completed_at`
    // never written, every retry heads an object that is gone, answers
    // `MalformedHeader`, and the exactly-once short circuit never engages. The
    // session would be stranded forever with its final object sitting in the bucket.
    // Recording first makes the retry hit that short circuit and receive the same
    // `MultipartCompleted` the first call would have, which is what exactly-once
    // means. Nothing is lost by the swap: `assemble` has already succeeded, so the
    // final object exists, and the parts are dead weight rather than state.
    if let Err(error) = store::complete_multipart(pool, session_uuid).await {
        tracing::warn!(error = %error, "media: could not mark a multipart session complete");
        return Frame::Error(FrameError::new(ErrorCode::Backpressure));
    }
    // A part that will not delete is an orphan, not a failure of this call: the
    // client's object is assembled and its session is finalized. Counted and logged
    // rather than discarded with `let _`, because a silent orphan is storage nobody
    // is looking for. No key or part number is logged; the count is the signal.
    let mut orphaned = 0u32;
    for key in &keys {
        if store.delete(key).await.is_err() {
            orphaned += 1;
        }
    }
    if orphaned > 0 {
        tracing::warn!(
            orphaned,
            "media: multipart parts survived completion and were not deleted"
        );
    }
    Frame::Blob {
        payload: wire::Response::MultipartCompleted.encode(),
    }
}

async fn handle_multipart_abort(
    state: &Arc<RelayState>,
    session: &Session,
    pool: &sqlx::PgPool,
    session_id: &[u8],
) -> Frame {
    let Some(session_uuid) = parse_session_id(session_id) else {
        return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
    };
    let Ok(Some(multipart)) = store::find_multipart(pool, session_uuid).await else {
        // The lookup inner-joins the reservation and the first abort deleted
        // that row (`store::release`), so an already-aborted session lands here
        // and never reaches the repeated-abort branch below, which was
        // unreachable for exactly this reason. `specs/backend/relay/media.md`
        // requires the same `MultipartAborted` the first abort gave. The group
        // went with the reservation, so there is nothing left to authorize
        // against; the session id is the 128 random bits handed to whoever
        // opened it, and this says nothing to anyone who cannot produce one.
        if matches!(
            store::multipart_is_aborted(pool, session_uuid).await,
            Ok(true)
        ) {
            return Frame::Blob {
                payload: wire::Response::MultipartAborted.encode(),
            };
        }
        return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
    };
    let workspace = match authorize_group(pool, session, &multipart.group).await {
        Ok(workspace) => workspace,
        Err(code) => return Frame::Error(FrameError::new(code)),
    };
    // A completed session has an assembled object in the bucket and an
    // unfinalized reservation row, because finalization happens at manifest
    // claim. Releasing it would return the quota for bytes that are still
    // stored, and, worse, `gc::sweep_unreferenced_storage` builds its known set
    // from reservation rows, so the object the client was told was stored would
    // be swept immediately. An abort after a completion is a client error, not a
    // reversal.
    if multipart.completed {
        return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
    }
    // A repeated abort is answered the same way the first one was, and does not
    // run the release a second time.
    if multipart.aborted {
        return Frame::Blob {
            payload: wire::Response::MultipartAborted.encode(),
        };
    }
    // The parts are deleted before the reservation is released, because the
    // release is what makes the bytes free: an abort that returned the quota and
    // left the parts in the bucket is a loop for unbounded unaccounted storage.
    // Deleting an object that is not there is not an error on either backend, so
    // a repeated abort is idempotent.
    if let Some(store) = &state.storage {
        if let Ok(parts) = store::recorded_parts(pool, session_uuid).await {
            for part_number in parts {
                let _ = store
                    .delete(&own_part_key(session_uuid, part_number as u32))
                    .await;
            }
        }
    }
    let _ = store::abort_multipart(pool, session_uuid).await;
    let _ = store::release(pool, &workspace, multipart.reservation_id).await;
    Frame::Blob {
        payload: wire::Response::MultipartAborted.encode(),
    }
}

async fn handle_control(
    session: &Session,
    pool: &sqlx::PgPool,
    record: &wire::RetentionControl,
) -> Frame {
    if authorize_group(pool, session, &record.group).await.is_err() {
        return Frame::Error(FrameError::new(ErrorCode::WriterNotInAccessSet));
    }
    match retention::apply_control(pool, record).await {
        Ok(retention::ControlOutcome::Accepted) => Frame::Blob {
            payload: wire::Response::RetentionAck {
                digest: record.digest(),
            }
            .encode(),
        },
        Ok(
            retention::ControlOutcome::ConflictFroze
            | retention::ControlOutcome::ConflictAlreadyFrozen,
        ) => Frame::Error(FrameError::new(ErrorCode::GroupFrozen)),
        Ok(retention::ControlOutcome::Invalid(_)) => {
            Frame::Error(FrameError::new(ErrorCode::MalformedHeader))
        }
        Err(error) => {
            tracing::warn!(error = %error, "media: retention control store failed");
            Frame::Error(FrameError::new(ErrorCode::Backpressure))
        }
    }
}

async fn handle_manifest(
    state: &Arc<RelayState>,
    session: &Session,
    pool: &sqlx::PgPool,
    record: &wire::RetentionManifest,
) -> Frame {
    let workspace = match authorize_group(pool, session, &record.group).await {
        Ok(workspace) => workspace,
        Err(code) => return Frame::Error(FrameError::new(code)),
    };
    // The manifest claim is what turns reserved bytes into stored bytes, so it is
    // the last moment the relay can compare what the client declared against what
    // it actually wrote. Without this the declaration is the accounting: reserve
    // one byte, PUT sixty-four megabytes, claim it, and the workspace is charged
    // one byte forever while the bucket holds the rest. Measured here rather than
    // inside `retention::apply_manifest` because the object store is the socket
    // layer's to reach; the retention module takes a pool and nothing else.
    if let Some(store) = &state.storage {
        for hash in &record.blobs {
            let Ok(Some(reservation)) =
                store::find_active_reservation(pool, &workspace, &record.group, hash).await
            else {
                continue;
            };
            // An already finalized reservation was charged by an earlier manifest,
            // and re-naming a hash is ordinary: nothing further is booked for it.
            if reservation.finalized {
                continue;
            }
            let Ok(key) = object_key(&workspace, &record.group, hash) else {
                continue;
            };
            match store.head(&key).await {
                // Longer than declared is the under-declaration this refuses. A
                // shorter object is the client's own loss, charged at what it
                // asked for, and refusing it would fail an honest early flush.
                Ok(Some(info)) if info.len > reservation.bytes as u64 => {
                    return Frame::Error(FrameError::new(ErrorCode::HashMismatch))
                }
                Err(error) if error.is_transient() => {
                    return Frame::Error(FrameError::new(ErrorCode::Backpressure))
                }
                _ => {}
            }
        }
    }
    match retention::apply_manifest(pool, &workspace, record).await {
        Ok(retention::ManifestOutcome::Accepted { digest }) => Frame::Blob {
            payload: wire::Response::RetentionAck { digest }.encode(),
        },
        Ok(retention::ManifestOutcome::Invalid(_)) => {
            Frame::Error(FrameError::new(ErrorCode::MalformedHeader))
        }
        Err(error) => {
            tracing::warn!(error = %error, "media: retention manifest store failed");
            Frame::Error(FrameError::new(ErrorCode::Backpressure))
        }
    }
}

async fn handle_policy(
    state: &Arc<RelayState>,
    session: &Session,
    pool: &sqlx::PgPool,
    record: &wire::RetentionPolicy,
) -> Frame {
    let workspace = match authorize_group(pool, session, &record.group).await {
        Ok(workspace) => workspace,
        Err(code) => return Frame::Error(FrameError::new(code)),
    };
    if record.media_after_days < gc::MEDIA_GRACE_FLOOR_DAYS {
        return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
    }
    if let Ok(Some(previous)) = retention::active_policy(pool, &record.group).await {
        // The same policy arriving twice is not a version error. A client that
        // publishes a policy and is then refused further down the same exchange
        // republishes on its next attempt, which is ordinary rather than
        // suspicious, and answering that with `malformed_header` sends an
        // operator looking for a malformed record that does not exist.
        if previous.is_the_same_policy(record) {
            return Frame::Blob {
                payload: wire::Response::RetentionAck {
                    digest: blake3::hash(&record.signing_bytes()).as_bytes().to_vec(),
                }
                .encode(),
            };
        }
        if record.version != previous.version + 1
            || record.media_after_days < previous.media_after_days
        {
            return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
        }
    } else if record.version != 1 {
        return Frame::Error(FrameError::new(ErrorCode::MalformedHeader));
    }
    let now_secs = state.now_ms() / 1000;
    let outcome = match retention::authorize(
        pool,
        &workspace,
        &record.signing_bytes(),
        &record.signatures,
        record.not_before,
        now_secs,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::warn!(error = %error, "media: policy authorization check failed");
            return Frame::Error(FrameError::new(ErrorCode::Backpressure));
        }
    };
    match outcome {
        retention::Authorization::Threshold | retention::Authorization::SoleAuthorizerGraced => {
            match retention::insert_policy(pool, record, &signatures_json(&record.signatures)).await
            {
                Ok(()) => Frame::Blob {
                    payload: wire::Response::RetentionAck {
                        digest: blake3::hash(&record.signing_bytes()).as_bytes().to_vec(),
                    }
                    .encode(),
                },
                Err(error) => {
                    tracing::warn!(error = %error, "media: policy store failed");
                    Frame::Error(FrameError::new(ErrorCode::Backpressure))
                }
            }
        }
        _ => Frame::Error(FrameError::new(ErrorCode::WriterNotInAccessSet)),
    }
}

async fn handle_destruction(
    state: &Arc<RelayState>,
    session: &Session,
    pool: &sqlx::PgPool,
    record: &wire::RetentionDestruction,
) -> Frame {
    let workspace = match authorize_group(pool, session, &record.group).await {
        Ok(workspace) => workspace,
        Err(code) => return Frame::Error(FrameError::new(code)),
    };
    let now_secs = state.now_ms() / 1000;
    let outcome = match retention::authorize(
        pool,
        &workspace,
        &record.signing_bytes(),
        &record.signatures,
        record.not_before,
        now_secs,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::warn!(error = %error, "media: destruction authorization check failed");
            return Frame::Error(FrameError::new(ErrorCode::Backpressure));
        }
    };
    match outcome {
        retention::Authorization::Threshold | retention::Authorization::SoleAuthorizerGraced => {
            match retention::insert_destruction(pool, record, &signatures_json(&record.signatures))
                .await
            {
                Ok(_) => Frame::Blob {
                    payload: wire::Response::RetentionAck {
                        digest: blake3::hash(&record.signing_bytes()).as_bytes().to_vec(),
                    }
                    .encode(),
                },
                Err(error) => {
                    tracing::warn!(error = %error, "media: destruction store failed");
                    Frame::Error(FrameError::new(ErrorCode::Backpressure))
                }
            }
        }
        _ => Frame::Error(FrameError::new(ErrorCode::WriterNotInAccessSet)),
    }
}

fn signatures_json(signatures: &[wire::Signature]) -> String {
    let entries: Vec<String> = signatures
        .iter()
        .map(|entry| {
            format!(
                "{{\"key\":\"{}\",\"sig\":\"{}\"}}",
                hex(&entry.key),
                hex(&entry.sig)
            )
        })
        .collect();
    format!("[{}]", entries.join(","))
}
