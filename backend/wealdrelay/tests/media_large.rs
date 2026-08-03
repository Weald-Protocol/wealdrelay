// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Two gibibytes of fixture media, through MinIO, over a connection that drops
//! halfway.
//!
//! Tier 5, and the integration half of step 9's gate: "2 GB of fixture media
//! round trips". `specs/backend/relay/media.md` is explicit about why this test
//! is the shape it is: "A 2 GiB video over a hotel connection has to survive a
//! reconnect or the feature does not work." So the client here does not merely
//! upload a large object; it loses its socket mid-transfer, reconnects, resumes
//! from the part it had reached, and finishes.
//!
//! Nothing is faked. The bucket is a real bucket in the MinIO
//! `backend/compose/weald-stack.yml` runs, the URLs are real AWS SigV4 presigned
//! requests produced by `S3Store::presign_put`, the transfer is real HTTP to
//! MinIO with no Weald code in the path, and the object is read back out and
//! hashed. The relay is the same `serve::run` every other integration suite
//! starts, with the harness bucket installed as its store.
//!
//! Three claims, in the order they matter:
//!
//! 1. The whole 2 GiB round trips, byte for byte, verified by hash.
//! 2. A reconnect mid-transfer costs nothing: part numbers and expected lengths
//!    are immutable, the window is refreshable, and the parts already uploaded
//!    are still there.
//! 3. Finalization is exactly once. A second `COMPLETE` is answered the same way
//!    the first was, does not reassemble, and does not double-count a byte.

mod support;

use std::net::TcpStream as SyncTcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use wealdrelay::frame::Frame;
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::media::wire::{Request, Response};
use wealdrelay::media::{self, store};
use wealdrelay::storage::{BlobKey, S3Store, Store};

use support::{
    config_with, default_device, make_group_in, signed_control, signed_manifest, verifier_key,
    Client, Running, Scratch,
};

const MINIO_ENDPOINT: &str = "http://127.0.0.1:54090";
const MINIO_ACCESS_KEY: &str = "weald";
const MINIO_SECRET_KEY: &str = "weald-local-only";
const MINIO_REGION: &str = "us-east-1";
const WS: &str = "ws-media-large";
const NOW: u64 = 1_800_000_000_000;

/// The gate says 2 GB. This is 2 GiB, which is larger, and is also exactly
/// `media::BLOB_MAX_BYTES`: the ceiling the wire format allows, so the largest
/// blob this relay will ever be asked to carry is the one being carried here.
const TOTAL: u64 = media::BLOB_MAX_BYTES;

fn part_count() -> u32 {
    TOTAL.div_ceil(media::MULTIPART_PART_SIZE) as u32
}

/// The ciphertext of part `number`, generated rather than stored: two gibibytes
/// of fixture on disk would be two gibibytes in the repository. Deterministic, so
/// a mismatch names a part and an offset rather than a random seed.
fn part_bytes(number: u32) -> Vec<u8> {
    let start = u64::from(number - 1) * media::MULTIPART_PART_SIZE;
    let length = (TOTAL - start).min(media::MULTIPART_PART_SIZE) as usize;
    let mut bytes = vec![0u8; length];
    for (offset, byte) in bytes.iter_mut().enumerate() {
        *byte = ((start + offset as u64) % 251) as u8;
    }
    bytes
}

fn require_minio() {
    let address = "127.0.0.1:54090".parse().expect("a literal address");
    if SyncTcpStream::connect_timeout(&address, Duration::from_secs(2)).is_err() {
        panic!(
            "MinIO is not answering on {MINIO_ENDPOINT}. This is the integration tier and it does \
             not skip: run `scripts/weald-stack up` and try again."
        );
    }
}

async fn minio() -> aws_sdk_s3::Client {
    let credentials = aws_credential_types::Credentials::new(
        MINIO_ACCESS_KEY,
        MINIO_SECRET_KEY,
        None,
        None,
        "weald-media-large",
    );
    let loaded = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(MINIO_REGION))
        .endpoint_url(MINIO_ENDPOINT)
        .credentials_provider(credentials)
        .load()
        .await;
    aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::config::Builder::from(&loaded)
            .force_path_style(true)
            // Two gibibytes over loopback is not fast, and the SDK's default
            // per-attempt ceiling is not written for it.
            .timeout_config(
                aws_sdk_s3::config::timeout::TimeoutConfig::builder()
                    .operation_attempt_timeout(Duration::from_secs(600))
                    .build(),
            )
            .build(),
    )
}

async fn empty_and_delete(client: &aws_sdk_s3::Client, bucket: &str) {
    let mut continuation: Option<String> = None;
    loop {
        let mut request = client.list_objects_v2().bucket(bucket);
        if let Some(token) = continuation.take() {
            request = request.continuation_token(token);
        }
        let Ok(page) = request.send().await else {
            return;
        };
        for object in page.contents() {
            if let Some(key) = object.key() {
                let _ = client.delete_object().bucket(bucket).key(key).send().await;
            }
        }
        match page.next_continuation_token() {
            Some(token) if page.is_truncated().unwrap_or(false) => {
                continuation = Some(token.to_string())
            }
            _ => break,
        }
    }
    let _ = client.delete_bucket().bucket(bucket).send().await;
}

/// One HTTP request against whatever host a presigned URL names, with the body
/// streamed out of a slice and the answer's body counted rather than kept.
///
/// The relay is not in this path and neither is any Weald code: the point of a
/// presigned URL is that the client talks to the bucket directly, so anything
/// else here would be testing a different arrangement than the one that ships.
async fn presigned_put(url: &str, body: &[u8]) -> u16 {
    let (authority, path) = split_url(url);
    let mut stream = tokio::net::TcpStream::connect(&authority)
        .await
        .expect("connect to the bucket");
    let head = format!(
        "PUT {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.expect("send head");
    stream.write_all(body).await.expect("send body");
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer).await;
    status_of(&answer)
}

/// A presigned GET, hashed as it arrives. Two gibibytes are never held in the
/// test's memory at once: what is being proven is that the bytes are the same
/// bytes, and a hash is how that is checked.
async fn presigned_get_hash(url: &str) -> (u16, u64, [u8; 32]) {
    let (authority, path) = split_url(url);
    let mut stream = tokio::net::TcpStream::connect(&authority)
        .await
        .expect("connect to the bucket");
    let head = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).await.expect("send head");

    let mut buffer = vec![0u8; 1 << 20];
    let mut pending: Vec<u8> = Vec::new();
    let mut hasher = blake3::Hasher::new();
    let mut status = 0u16;
    let mut counted = 0u64;
    let mut in_body = false;
    loop {
        let read = stream.read(&mut buffer).await.expect("read the answer");
        if read == 0 {
            break;
        }
        if in_body {
            hasher.update(&buffer[..read]);
            counted += read as u64;
            continue;
        }
        pending.extend_from_slice(&buffer[..read]);
        if let Some(split) = pending.windows(4).position(|window| window == b"\r\n\r\n") {
            status = status_of(&pending);
            let body = &pending[split + 4..];
            hasher.update(body);
            counted += body.len() as u64;
            in_body = true;
            pending.clear();
        }
    }
    (status, counted, *hasher.finalize().as_bytes())
}

fn split_url(url: &str) -> (String, String) {
    let without_scheme = url.strip_prefix("http://").expect("an http url");
    let (authority, path) = without_scheme.split_once('/').expect("a path");
    (authority.to_string(), format!("/{path}"))
}

fn status_of(response: &[u8]) -> u16 {
    String::from_utf8_lossy(&response[..response.len().min(64)])
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

#[track_caller]
fn blob_answer(frame: &Frame) -> Response {
    match frame {
        Frame::Blob { payload } => Response::decode(payload).expect("a media response"),
        other => panic!("expected a BLOB answer, got {other:?}"),
    }
}

async fn ask(client: &mut Client, request: &Request) -> Frame {
    client
        .send_frame(&Frame::Blob {
            payload: request.encode(),
        })
        .await;
    client.recv_frame().await
}

async fn connect(address: std::net::SocketAddr, group: &[u8]) -> Client {
    let mut client = Client::connect(address).await;
    client.handshake(vec![group.to_vec()], NOW).await;
    client
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_gibibytes_round_trip_through_a_reconnect_and_finalize_exactly_once() {
    require_minio();
    let client = minio().await;
    let bucket = format!("weald-media-large-{}", std::process::id());
    empty_and_delete(&client, &bucket).await;
    client
        .create_bucket()
        .bucket(&bucket)
        .send()
        .await
        .expect("MinIO is up but refused a new bucket");

    let scratch = Scratch::new("media_large").await;
    let blobs = tempfile::tempdir().unwrap();
    let config = config_with(&scratch, blobs.path(), []);
    let store = Store::S3(S3Store::with_client(
        client.clone(),
        bucket.clone(),
        String::new(),
    ));
    let running = Running::start_with(config, Clock::Fixed(NOW), move |state: &mut RelayState| {
        state.storage = Some(Arc::new(store));
    })
    .await;
    let group = make_group_in(
        &running.state,
        WS,
        0x71,
        &[default_device()],
        &[default_device()],
    )
    .await;

    // The whole object's hash, computed the way a client computes it: over the
    // ciphertext it is about to send, part by part, before any of it is uploaded.
    let mut whole = blake3::Hasher::new();
    for number in 1..=part_count() {
        whole.update(&part_bytes(number));
    }
    let hash = whole.finalize().as_bytes().to_vec();

    let epoch = verifier_key(0x21);
    let mut socket = connect(running.address, &group).await;
    assert!(matches!(
        blob_answer(
            &ask(
                &mut socket,
                &Request::RetentionControl(signed_control(&group, 0, &epoch, None, &epoch))
            )
            .await
        ),
        Response::RetentionAck { .. }
    ));

    // `BLOB put` at the ceiling: above 64 MB the answer is a multipart session
    // rather than one URL.
    let started = Instant::now();
    let session_id = match blob_answer(
        &ask(
            &mut socket,
            &Request::Put {
                workspace: WS.as_bytes().to_vec(),
                group: group.clone(),
                hash: hash.clone(),
                ciphertext_len: TOTAL,
            },
        )
        .await,
    ) {
        Response::Multipart {
            session_id,
            part_size,
            expires_in,
        } => {
            assert_eq!(part_size, media::MULTIPART_PART_SIZE);
            assert_eq!(expires_in, media::PRESIGN_TTL_SECONDS);
            session_id
        }
        other => panic!("expected a multipart session for {TOTAL} bytes, got {other:?}"),
    };
    assert_eq!(
        store::usage(running.state.database.as_ref().unwrap().pool(), WS)
            .await
            .unwrap()
            .reserved_bytes,
        TOTAL as i64,
        "the whole object is reserved before a single byte is issued a URL"
    );

    // The hotel connection. Half the parts, then the socket goes away.
    let halfway = part_count() / 2;
    for number in 1..=halfway {
        upload_part(&mut socket, &session_id, number).await;
    }
    drop(socket);

    // The reconnect. A new socket, a new handshake, and the session is still
    // there: part numbers, expected lengths and the reservation id are immutable,
    // so the client resumes rather than starting again.
    let mut socket = connect(running.address, &group).await;
    let already = blob_answer(
        &ask(
            &mut socket,
            &Request::MultipartPart {
                session_id: session_id.clone(),
                part_number: halfway,
                expected_len: part_bytes(halfway).len() as u64,
            },
        )
        .await,
    );
    assert!(
        matches!(already, Response::MultipartPartUpload { .. }),
        "a resumed client must be able to refresh the window on a part it already sent"
    );
    // And the same part with a different length is refused: the length is part of
    // what was agreed when the number was issued.
    assert!(matches!(
        ask(
            &mut socket,
            &Request::MultipartPart {
                session_id: session_id.clone(),
                part_number: halfway,
                expected_len: 17,
            }
        )
        .await,
        Frame::Error(_)
    ));

    for number in (halfway + 1)..=part_count() {
        upload_part(&mut socket, &session_id, number).await;
    }
    let uploaded = started.elapsed();

    // Finalize. The parts are listed out of order on purpose: the relay assembles
    // by part number, never by the order the client happened to name them in.
    let mut parts: Vec<(u32, Vec<u8>)> = (1..=part_count())
        .map(|number| (number, format!("etag-{number}").into_bytes()))
        .collect();
    parts.reverse();
    let complete = Request::MultipartComplete {
        session_id: session_id.clone(),
        parts,
    };
    let assembling = Instant::now();
    assert_eq!(
        blob_answer(&ask(&mut socket, &complete).await),
        Response::MultipartCompleted
    );
    let assembled_in = assembling.elapsed();

    // Exactly once. A second COMPLETE is answered the same way and reassembles
    // nothing: the parts it would need are already deleted, so a relay that tried
    // would fail rather than silently rewrite the object.
    assert_eq!(
        blob_answer(&ask(&mut socket, &complete).await),
        Response::MultipartCompleted
    );
    let pool = running.state.database.as_ref().unwrap().pool();
    let completions: i64 = sqlx::query_scalar(
        "select count(*) from relay_blob_multipart \
         where session_id = $1 and completed_at is not null",
    )
    .bind(uuid::Uuid::from_slice(&session_id).unwrap())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(completions, 1, "one session, finalized once");
    assert_eq!(
        store::usage(pool, WS).await.unwrap().reserved_bytes,
        TOTAL as i64,
        "finalizing the transfer must not double-count the reservation"
    );

    // The parts are gone from the bucket and the object is there, whole.
    let uuid = uuid::Uuid::from_slice(&session_id).unwrap();
    let leftover = running
        .state
        .storage
        .as_ref()
        .unwrap()
        .list("_multipart", &uuid.simple().to_string())
        .await
        .unwrap();
    assert!(
        leftover.is_empty(),
        "the parts are cleaned up: {leftover:?}"
    );
    let info = running
        .state
        .storage
        .as_ref()
        .unwrap()
        .head(&BlobKey::new(WS, media::hex(&group), media::hex(&hash)).unwrap())
        .await
        .unwrap()
        .expect("the assembled object is in the bucket");
    assert_eq!(info.len, TOTAL);

    // The manifest, which is what turns the reservation into stored bytes.
    let manifest = signed_manifest(&group, 0, 1, None, vec![hash.clone()], &epoch);
    assert!(matches!(
        blob_answer(&ask(&mut socket, &Request::RetentionManifest(manifest)).await),
        Response::RetentionAck { .. }
    ));
    let usage = store::usage(pool, WS).await.unwrap();
    assert_eq!(usage.stored_bytes, TOTAL as i64);
    assert_eq!(usage.reserved_bytes, 0);

    // And down again, through a presigned GET straight from the bucket, hashed as
    // it arrives. This is the round trip the gate asks for and it is checked by
    // content, not by length.
    let download = blob_answer(
        &ask(
            &mut socket,
            &Request::Get {
                workspace: WS.as_bytes().to_vec(),
                group: group.clone(),
                hash: hash.clone(),
            },
        )
        .await,
    );
    let url = match download {
        Response::Download { url, .. } => url,
        other => panic!("expected a download URL, got {other:?}"),
    };
    let reading = Instant::now();
    let (status, counted, digest) = presigned_get_hash(&url).await;
    let read_in = reading.elapsed();
    assert_eq!(status, 200);
    assert_eq!(counted, TOTAL, "the whole object came back");
    assert_eq!(
        digest.to_vec(),
        hash,
        "the ciphertext that came back is the ciphertext that went up"
    );

    // Written down rather than only asserted: `testing.md` asks for the timings
    // beside the verdict, because a round trip that finished suspiciously fast is
    // a round trip that did not happen.
    record_timing(
        TOTAL,
        part_count(),
        uploaded,
        assembled_in,
        read_in,
        &bucket,
    );

    running.shutdown().await;
    scratch.drop_database().await;
    empty_and_delete(&client, &bucket).await;
}

async fn upload_part(socket: &mut Client, session_id: &[u8], number: u32) {
    let bytes = part_bytes(number);
    let url = match blob_answer(
        &ask(
            socket,
            &Request::MultipartPart {
                session_id: session_id.to_vec(),
                part_number: number,
                expected_len: bytes.len() as u64,
            },
        )
        .await,
    ) {
        Response::MultipartPartUpload { url, .. } => url,
        other => panic!("expected a part URL for part {number}, got {other:?}"),
    };
    let status = presigned_put(&url, &bytes).await;
    assert_eq!(status, 200, "part {number} was refused by the bucket");
}

/// The step 9 artifact's share of this run, written where the gate collects it.
fn record_timing(
    total: u64,
    parts: u32,
    uploaded: Duration,
    assembled: Duration,
    read: Duration,
    bucket: &str,
) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let directory = root.join("target").join("step-09");
    let _ = std::fs::create_dir_all(&directory);
    let _ = std::fs::write(
        directory.join("large-round-trip.txt"),
        format!(
            "bytes            {total}\n\
             parts            {parts} of {} bytes\n\
             bucket           {bucket} (MinIO, {MINIO_ENDPOINT})\n\
             upload           {:.1}s across a reconnect at part {}\n\
             assemble         {:.1}s\n\
             download+verify  {:.1}s\n\
             verified         blake3 of the downloaded ciphertext equals the uploaded hash\n",
            media::MULTIPART_PART_SIZE,
            uploaded.as_secs_f64(),
            parts / 2,
            assembled.as_secs_f64(),
            read.as_secs_f64(),
        ),
    );
}
