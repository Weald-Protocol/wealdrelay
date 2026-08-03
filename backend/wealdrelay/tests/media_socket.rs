// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Media over a real socket, and a real upload through a presigned URL.
//!
//! Tier 3 and tier 5. `tests/media_frames.rs` proves `media::handle` right about
//! every case; this file proves the frame gets there and the answer comes back
//! over a WebSocket a client actually speaks, and then takes the URL the relay
//! issued and does the transfer over HTTP the way a client does.
//!
//! The round trip here is the whole `media.md` "Upload" and "Download" sequence
//! end to end: `BLOB put`, a real PUT of ciphertext, a retention manifest that
//! claims the hash, `BLOB get`, and a real GET that returns the same bytes. On
//! the local profile the presigned URL points at the relay's own `/blob` route,
//! which `environments.md` makes the filesystem backend's stand-in for AWS SigV4,
//! so this file is also the only place that route is exercised as a route.

mod support;

use std::sync::Arc;

use sqlx::PgPool;
use wealdrelay::config::keys;
use wealdrelay::frame::{ErrorCode, Frame};
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::media::wire::{Request, Response};
use wealdrelay::media::{self, store};
use wealdrelay::storage::{BlobKey, S3Store, Store};

use support::{
    blob_hash, config_with, default_device, device_from, envelope_for, http_request, make_group_in,
    path_of, seed_access_set_with_authorizers, signed_control, signed_manifest, verifier_key,
    Client, Running, Scratch,
};

const NOW: u64 = 1_800_000_000_000;
const WS: &str = "ws-media-socket";

/// The device every client here connects as. It has to be the one the access set
/// names, and the retention records are signed by the same key so one workspace
/// serves both halves of the exchange.
fn ada() -> ed25519_dalek::SigningKey {
    default_device()
}

async fn relay(
    label: &str,
    extra: impl IntoIterator<Item = (&'static str, String)>,
) -> (Scratch, tempfile::TempDir, Running) {
    let scratch = Scratch::new(label).await;
    let blobs = tempfile::tempdir().unwrap();
    let config = config_with(&scratch, blobs.path(), extra);
    let running = Running::start(config, Clock::Fixed(NOW)).await;
    (scratch, blobs, running)
}

async fn group_in(state: &Arc<RelayState>, byte: u8) -> Vec<u8> {
    make_group_in(state, WS, byte, &[ada(), device_from(0x32)], &[ada()]).await
}

fn pool_of(state: &Arc<RelayState>) -> &PgPool {
    state.database.as_ref().expect("a database").pool()
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

/// One blob, all the way there and all the way back, over the wire the customer's
/// client speaks.
#[tokio::test]
async fn a_blob_goes_up_through_a_presigned_url_and_comes_back_down_through_another() {
    let (scratch, _blobs, running) = relay("socket_roundtrip", []).await;
    let group = group_in(&running.state, 0x61).await;
    let epoch = verifier_key(0x21);
    let ciphertext: Vec<u8> = (0..4096u32).map(|index| (index % 251) as u8).collect();
    let hash = blake3::hash(&ciphertext).as_bytes().to_vec();

    let mut client = Client::connect(running.address).await;
    client.handshake(vec![group.clone()], NOW).await;

    // The control record first: a manifest is only accepted under a verifier the
    // relay has already been given, which is what makes the chain a chain.
    let genesis = signed_control(&group, 0, &epoch, None, &epoch);
    assert!(matches!(
        blob_answer(&ask(&mut client, &Request::RetentionControl(genesis)).await),
        Response::RetentionAck { .. }
    ));

    // `BLOB put`, and the presigned URL that comes back.
    let upload = ask(
        &mut client,
        &Request::Put {
            workspace: WS.as_bytes().to_vec(),
            group: group.clone(),
            hash: hash.clone(),
            ciphertext_len: ciphertext.len() as u64,
        },
    )
    .await;
    let url = match blob_answer(&upload) {
        Response::Upload { url, expires_in } => {
            assert_eq!(expires_in, media::PRESIGN_TTL_SECONDS);
            url
        }
        other => panic!("expected an upload URL, got {other:?}"),
    };

    // The transfer itself, which never touches the WebSocket.
    let (status, _) = http_request(running.address, "PUT", &path_of(&url), &ciphertext).await;
    assert_eq!(status, 200, "the presigned PUT is accepted");

    // Now the manifest, which is what moves the bytes from reserved to stored.
    let manifest = signed_manifest(&group, 0, 1, None, vec![hash.clone()], &epoch);
    assert!(matches!(
        blob_answer(&ask(&mut client, &Request::RetentionManifest(manifest)).await),
        Response::RetentionAck { .. }
    ));
    let usage = store::usage(pool_of(&running.state), WS).await.unwrap();
    assert_eq!(usage.stored_bytes, ciphertext.len() as i64);
    assert_eq!(usage.reserved_bytes, 0);

    // A second `put` for the same object is `exists`: the retry after a dropped
    // upload is free.
    assert_eq!(
        blob_answer(
            &ask(
                &mut client,
                &Request::Put {
                    workspace: WS.as_bytes().to_vec(),
                    group: group.clone(),
                    hash: hash.clone(),
                    ciphertext_len: ciphertext.len() as u64,
                }
            )
            .await
        ),
        Response::Exists
    );

    // And down again, on a second connection, the way a second device would.
    let mut reader = Client::connect(running.address).await;
    reader
        .handshake_as(&device_from(0x32), vec![group.clone()], NOW)
        .await;
    let download = ask(
        &mut reader,
        &Request::Get {
            workspace: WS.as_bytes().to_vec(),
            group: group.clone(),
            hash: hash.clone(),
        },
    )
    .await;
    let url = match blob_answer(&download) {
        Response::Download { url, .. } => url,
        other => panic!("expected a download URL, got {other:?}"),
    };
    let (status, body) = http_request(running.address, "GET", &path_of(&url), &[]).await;
    assert_eq!(status, 200);
    assert_eq!(body, ciphertext, "the ciphertext survives the round trip");
    assert_eq!(
        blake3::hash(&body).as_bytes().to_vec(),
        hash,
        "and the client's hash check passes on what came back"
    );

    // A blob nobody uploaded is a plain not-found, not an error.
    assert_eq!(
        blob_answer(
            &ask(
                &mut reader,
                &Request::Get {
                    workspace: WS.as_bytes().to_vec(),
                    group: group.clone(),
                    hash: blob_hash(0xee),
                }
            )
            .await
        ),
        Response::NotFound
    );

    running.shutdown().await;
    scratch.drop_database().await;
}

/// `media.md`: "Text envelopes are never rejected for quota. Blocking someone
/// from sending a message because a colleague uploaded a video is a worse failure
/// than a slightly over-quota bill."
///
/// Proven on one connection, in one breath: the `BLOB put` is refused with the
/// structured rejection the client renders as "this workspace is out of storage",
/// and the `SEND` that follows it on the same socket is acknowledged.
#[tokio::test]
async fn a_workspace_out_of_storage_still_sends_text() {
    let (scratch, _blobs, running) =
        relay("socket_quota", [(keys::MAX_STORAGE_GB, "1".to_string())]).await;
    let group = group_in(&running.state, 0x62).await;
    let mut client = Client::connect(running.address).await;
    client.handshake(vec![group.clone()], NOW).await;

    // Fill the plan.
    assert!(matches!(
        blob_answer(
            &ask(
                &mut client,
                &Request::Put {
                    workspace: WS.as_bytes().to_vec(),
                    group: group.clone(),
                    hash: blob_hash(0xa1),
                    ciphertext_len: 999_000_000,
                }
            )
            .await
        ),
        Response::Multipart { .. }
    ));

    // The boundary.
    let refused = ask(
        &mut client,
        &Request::Put {
            workspace: WS.as_bytes().to_vec(),
            group: group.clone(),
            hash: blob_hash(0xa2),
            ciphertext_len: 2_000_000,
        },
    )
    .await;
    match &refused {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::StorageExhausted);
            assert_eq!(error.code.as_str(), "storage_exhausted");
        }
        other => panic!("expected a structured rejection, got {other:?}"),
    }

    // The same socket, the same instant, an envelope.
    let envelope = envelope_for(&group, b"a message, while the bucket is full");
    client
        .send_frame(&Frame::Send {
            envelope: envelope.encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::SendAck { hash, seq } => {
            assert_eq!(hash, envelope.hash);
            assert_eq!(seq, 1);
        }
        other => panic!("text must never be rejected for quota, and got {other:?}"),
    }

    // And the socket is still usable for media afterwards: an upload that fits is
    // still accepted, so the refusal was about the blob and not about the client.
    assert!(matches!(
        blob_answer(
            &ask(
                &mut client,
                &Request::Put {
                    workspace: WS.as_bytes().to_vec(),
                    group: group.clone(),
                    hash: blob_hash(0xa3),
                    ciphertext_len: 500_000,
                }
            )
            .await
        ),
        Response::Upload { .. }
    ));

    running.shutdown().await;
    scratch.drop_database().await;
}

// MARK: The local presigned-URL route
//
// Reachable only on the filesystem backend, which `environments.md` runs in
// `local` alone. It stands in for AWS SigV4 there, so it has to refuse everything
// SigV4 refuses: a key that could escape the key space, a token for another
// object, an expired token, and a token nobody signed.

#[tokio::test]
async fn the_local_presign_route_refuses_everything_a_real_presigner_would() {
    let (scratch, _blobs, running) = relay("socket_presign", []).await;
    let group = group_in(&running.state, 0x63).await;
    let hash = blob_hash(0xb1);
    let mut client = Client::connect(running.address).await;
    client.handshake(vec![group.clone()], NOW).await;

    let upload = ask(
        &mut client,
        &Request::Put {
            workspace: WS.as_bytes().to_vec(),
            group: group.clone(),
            hash: hash.clone(),
            ciphertext_len: 8,
        },
    )
    .await;
    let url = match blob_answer(&upload) {
        Response::Upload { url, .. } => url,
        other => panic!("{other:?}"),
    };
    let path = path_of(&url);

    // No token at all: axum cannot even extract one, so the request never reaches
    // the handler.
    let bare = path.split('?').next().unwrap().to_string();
    let (status, _) = http_request(running.address, "PUT", &bare, b"12345678").await;
    assert_eq!(status, 400);

    // A token whose signature has been rewritten.
    let forged = path.replace("sig=", "sig=0");
    let (status, _) = http_request(running.address, "PUT", &forged, b"12345678").await;
    assert_eq!(status, 403);
    let (status, _) = http_request(running.address, "GET", &forged, &[]).await;
    assert_eq!(status, 403);

    // A token for this object, replayed against the one next to it. The key is
    // part of what was signed, so it does not travel.
    let neighbour = path.replace(&media::hex(&hash), &media::hex(&blob_hash(0xb2)));
    let (status, _) = http_request(running.address, "PUT", &neighbour, b"12345678").await;
    assert_eq!(status, 403);

    // An expired token. The expiry is in the query string and is signed, so
    // moving it forward invalidates it; moving the relay's clock past it is the
    // case that matters, and it is refused before the signature is checked.
    let expired = media::http::sign(
        &running.state.media_presign_secret,
        "PUT",
        &format!("{WS}/{}/{}", media::hex(&group), media::hex(&hash)),
        NOW / 1000 - 1,
    );
    let (status, _) = http_request(
        running.address,
        "PUT",
        &format!(
            "/blob/{WS}/{}/{}?exp={}&sig={expired}",
            media::hex(&group),
            media::hex(&hash),
            NOW / 1000 - 1
        ),
        b"12345678",
    )
    .await;
    assert_eq!(status, 403);

    // A key component that could escape the key space, on both routes.
    let (status, _) = http_request(
        running.address,
        "PUT",
        "/blob/%2E/g/h?exp=99999999999&sig=00",
        b"x",
    )
    .await;
    assert_eq!(status, 400);
    let (status, _) = http_request(
        running.address,
        "GET",
        "/blob/%2E/g/h?exp=99999999999&sig=00",
        &[],
    )
    .await;
    assert_eq!(status, 400);
    let (status, _) = http_request(
        running.address,
        "PUT",
        "/blob-part/%2E/1?exp=99999999999&sig=00",
        b"x",
    )
    .await;
    assert_eq!(status, 400);
    let (status, _) = http_request(
        running.address,
        "GET",
        "/blob-part/%2E/1?exp=99999999999&sig=00",
        &[],
    )
    .await;
    assert_eq!(status, 400);

    // The real token works, and the object it wrote reads back.
    let (status, _) = http_request(running.address, "PUT", &path, b"12345678").await;
    assert_eq!(status, 200);
    let download = ask(
        &mut client,
        &Request::Get {
            workspace: WS.as_bytes().to_vec(),
            group: group.clone(),
            hash: hash.clone(),
        },
    )
    .await;
    let get_url = match blob_answer(&download) {
        Response::Download { url, .. } => url,
        other => panic!("{other:?}"),
    };
    let (status, body) = http_request(running.address, "GET", &path_of(&get_url), &[]).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"12345678");

    // A GET token for an object that is not there is a 404, not a 403: the token
    // was good and the object is gone, and a client has to be able to tell those
    // apart to render "deleted or expired".
    let missing = media::hex(&blob_hash(0xb3));
    let key_path = format!("{WS}/{}/{missing}", media::hex(&group));
    let expires = NOW / 1000 + 900;
    let token = media::http::sign(
        &running.state.media_presign_secret,
        "GET",
        &key_path,
        expires,
    );
    let (status, _) = http_request(
        running.address,
        "GET",
        &format!("/blob/{key_path}?exp={expires}&sig={token}"),
        &[],
    )
    .await;
    assert_eq!(status, 404);

    running.shutdown().await;
    scratch.drop_database().await;
}

/// The part routes, which the multipart path uses and nothing else does.
#[tokio::test]
async fn a_multipart_part_travels_through_its_own_presigned_route() {
    let (scratch, _blobs, running) = relay("socket_part", []).await;
    let group = group_in(&running.state, 0x64).await;
    let mut client = Client::connect(running.address).await;
    client.handshake(vec![group.clone()], NOW).await;

    // Two parts, the second one short, so the assembled object is not a multiple
    // of the part size.
    let first: Vec<u8> = vec![0xa5; media::MULTIPART_PART_SIZE as usize];
    let second: Vec<u8> = vec![0x5a; 32];
    let total = (first.len() + second.len()) as u64;
    let hash = blake3::hash(&[first.clone(), second.clone()].concat())
        .as_bytes()
        .to_vec();

    let session_id = match blob_answer(
        &ask(
            &mut client,
            &Request::Put {
                workspace: WS.as_bytes().to_vec(),
                group: group.clone(),
                hash: hash.clone(),
                ciphertext_len: total,
            },
        )
        .await,
    ) {
        Response::Multipart {
            session_id,
            part_size,
            ..
        } => {
            assert_eq!(part_size, media::MULTIPART_PART_SIZE);
            session_id
        }
        other => panic!("expected a multipart session, got {other:?}"),
    };

    for (number, bytes) in [(1u32, &first), (2, &second)] {
        let url = match blob_answer(
            &ask(
                &mut client,
                &Request::MultipartPart {
                    session_id: session_id.clone(),
                    part_number: number,
                    expected_len: bytes.len() as u64,
                },
            )
            .await,
        ) {
            Response::MultipartPartUpload { url, .. } => url,
            other => panic!("{other:?}"),
        };
        // A forged token on the part route is refused the same way it is on the
        // object route.
        let (status, _) = http_request(
            running.address,
            "PUT",
            &path_of(&url).replace("sig=", "sig=0"),
            bytes,
        )
        .await;
        assert_eq!(status, 403);
        let (status, _) = http_request(running.address, "PUT", &path_of(&url), bytes).await;
        assert_eq!(status, 200);

        // And the part reads back through its own GET token, which is what a
        // resumed client uses to check what it already sent.
        let uuid = uuid::Uuid::from_slice(&session_id).unwrap();
        let part_path = format!("_multipart/{}/part-{number}", uuid.simple());
        let expires = NOW / 1000 + 900;
        let token = media::http::sign(
            &running.state.media_presign_secret,
            "GET",
            &part_path,
            expires,
        );
        let (status, body) = http_request(
            running.address,
            "GET",
            &format!(
                "/blob-part/{}/{number}?exp={expires}&sig={token}",
                uuid.simple()
            ),
            &[],
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(body.len(), bytes.len());
        let (status, _) = http_request(
            running.address,
            "GET",
            &format!("/blob-part/{}/{number}?exp={expires}&sig=00", uuid.simple()),
            &[],
        )
        .await;
        assert_eq!(status, 403);
    }

    // A part nobody uploaded is a 404 on the part route too.
    let uuid = uuid::Uuid::from_slice(&session_id).unwrap();
    let expires = NOW / 1000 + 900;
    let token = media::http::sign(
        &running.state.media_presign_secret,
        "GET",
        &format!("_multipart/{}/part-9", uuid.simple()),
        expires,
    );
    let (status, _) = http_request(
        running.address,
        "GET",
        &format!("/blob-part/{}/9?exp={expires}&sig={token}", uuid.simple()),
        &[],
    )
    .await;
    assert_eq!(status, 404);

    assert_eq!(
        blob_answer(
            &ask(
                &mut client,
                &Request::MultipartComplete {
                    session_id: session_id.clone(),
                    parts: vec![(1, b"e1".to_vec()), (2, b"e2".to_vec())],
                }
            )
            .await
        ),
        Response::MultipartCompleted
    );

    let stored = running
        .state
        .storage
        .as_ref()
        .unwrap()
        .get(&BlobKey::new(WS, media::hex(&group), media::hex(&hash)).unwrap())
        .await
        .unwrap();
    assert_eq!(stored.len() as u64, total);
    assert_eq!(
        blake3::hash(&stored).as_bytes().to_vec(),
        hash,
        "the assembled object is exactly what the client hashed"
    );

    running.shutdown().await;
    scratch.drop_database().await;
}

/// The two answers the route gives when the relay itself, rather than the token,
/// is the problem: no store configured at all, and a store that cannot be
/// reached.
#[tokio::test]
async fn the_local_presign_route_reports_a_broken_store_rather_than_a_bad_request() {
    let scratch = Scratch::new("socket_presign_broken").await;
    let blobs = tempfile::tempdir().unwrap();
    let config = config_with(&scratch, blobs.path(), []);

    // No store at all.
    let running = Running::start_with(config.clone(), Clock::Fixed(NOW), |state| {
        state.storage = None
    })
    .await;
    let expires = NOW / 1000 + 900;
    for (method, route, key_path) in [
        ("PUT", format!("/blob/{WS}/aa/bb"), format!("{WS}/aa/bb")),
        ("GET", format!("/blob/{WS}/aa/bb"), format!("{WS}/aa/bb")),
        (
            "PUT",
            "/blob-part/aa/1".to_string(),
            "_multipart/aa/part-1".to_string(),
        ),
        (
            "GET",
            "/blob-part/aa/1".to_string(),
            "_multipart/aa/part-1".to_string(),
        ),
    ] {
        let token = media::http::sign(
            &running.state.media_presign_secret,
            method,
            &key_path,
            expires,
        );
        let (status, _) = http_request(
            running.address,
            method,
            &format!("{route}?exp={expires}&sig={token}"),
            if method == "PUT" {
                b"x".as_slice()
            } else {
                &[]
            },
        )
        .await;
        assert_eq!(status, 503, "{method} {route} with no store configured");
    }
    running.shutdown().await;

    // A store that cannot be reached: the same 503, from the other direction.
    let unreachable = unreachable_store().await;
    let running = Running::start_with(config.clone(), Clock::Fixed(NOW), move |state| {
        state.storage = Some(Arc::new(unreachable))
    })
    .await;
    for (method, route, key_path) in [
        ("PUT", format!("/blob/{WS}/aa/bb"), format!("{WS}/aa/bb")),
        ("GET", format!("/blob/{WS}/aa/bb"), format!("{WS}/aa/bb")),
        (
            "PUT",
            "/blob-part/aa/1".to_string(),
            "_multipart/aa/part-1".to_string(),
        ),
        (
            "GET",
            "/blob-part/aa/1".to_string(),
            "_multipart/aa/part-1".to_string(),
        ),
    ] {
        let token = media::http::sign(
            &running.state.media_presign_secret,
            method,
            &key_path,
            expires,
        );
        let (status, _) = http_request(
            running.address,
            method,
            &format!("{route}?exp={expires}&sig={token}"),
            if method == "PUT" {
                b"x".as_slice()
            } else {
                &[]
            },
        )
        .await;
        assert_eq!(status, 503, "{method} {route} against an unreachable store");
    }
    running.shutdown().await;

    // A store that answers and refuses: a bad request rather than a retry, on
    // both methods and both routes.
    let bucketless = bucketless_store().await;
    let running = Running::start_with(config, Clock::Fixed(NOW), move |state| {
        state.storage = Some(Arc::new(bucketless))
    })
    .await;
    for (method, route, key_path) in [
        ("PUT", format!("/blob/{WS}/aa/bb"), format!("{WS}/aa/bb")),
        ("GET", format!("/blob/{WS}/aa/bb"), format!("{WS}/aa/bb")),
        (
            "PUT",
            "/blob-part/aa/1".to_string(),
            "_multipart/aa/part-1".to_string(),
        ),
        (
            "GET",
            "/blob-part/aa/1".to_string(),
            "_multipart/aa/part-1".to_string(),
        ),
    ] {
        let token = media::http::sign(
            &running.state.media_presign_secret,
            method,
            &key_path,
            expires,
        );
        let (status, _) = http_request(
            running.address,
            method,
            &format!("{route}?exp={expires}&sig={token}"),
            if method == "PUT" {
                b"x".as_slice()
            } else {
                &[]
            },
        )
        .await;
        assert_eq!(status, 400, "{method} {route} against a store that refuses");
    }
    running.shutdown().await;

    scratch.drop_database().await;
}

async fn minio_client(reachable: bool) -> aws_sdk_s3::Client {
    let credentials = aws_credential_types::Credentials::new(
        "weald",
        "weald-local-only",
        None,
        None,
        "weald-media-socket",
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
        .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
        .timeout_config(
            aws_sdk_s3::config::timeout::TimeoutConfig::builder()
                .operation_attempt_timeout(std::time::Duration::from_secs(2))
                .build(),
        )
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

async fn unreachable_store() -> Store {
    Store::S3(S3Store::with_client(
        minio_client(false).await,
        "weald-blobs".to_string(),
        String::new(),
    ))
}

async fn bucketless_store() -> Store {
    Store::S3(S3Store::with_client(
        minio_client(true).await,
        String::new(),
        String::new(),
    ))
}

/// Keeps the unused-import checker honest about the helper this file shares with
/// the rest of the suite.
#[allow(dead_code)]
async fn _seed(state: &Arc<RelayState>) {
    seed_access_set_with_authorizers(state, WS, &[ada()], &[ada()]).await;
}

/// The part route refuses a forged token and accepts a signed one.
///
/// Written directly against the route rather than through a whole multipart
/// session, because a session-shaped test proves the session and leaves it
/// ambiguous which handler answered. `media.md` gives every part the same
/// fifteen-minute signed window as a whole object, so the two answers that matter
/// are the refusal and the acceptance, and they are asserted here as themselves.
#[tokio::test]
async fn the_part_route_refuses_a_forged_token_and_stores_a_signed_one() {
    let (scratch, _blobs, running) = relay("socket_part_route", []).await;
    let session = uuid::Uuid::new_v4();
    let expires = NOW / 1000 + 900;
    let key_path = format!("_multipart/{}/part-7", session.simple());
    let token = media::http::sign(
        &running.state.media_presign_secret,
        "PUT",
        &key_path,
        expires,
    );
    let route = format!("/blob-part/{}/7", session.simple());

    let (status, _) = http_request(
        running.address,
        "PUT",
        &format!("{route}?exp={expires}&sig=0{token}"),
        b"a part",
    )
    .await;
    assert_eq!(status, 403, "a forged signature is refused");

    let (status, _) = http_request(
        running.address,
        "PUT",
        &format!("{route}?exp={expires}&sig={token}"),
        b"a part",
    )
    .await;
    assert_eq!(status, 200, "a signed part is stored");

    running.shutdown().await;
    scratch.drop_database().await;
}
