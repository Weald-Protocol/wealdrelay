// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The media lifecycle artifact, produced by a real run rather than described.
//!
//! What has to be shown is the GC run log and the storage accounting against the
//! quota. A run log is only evidence if something actually ran, so this file drives
//! the whole media lifecycle against the harness Postgres and the harness MinIO and
//! leaves the rows behind to be read out with `psql`.
//!
//! The database is named rather than scratch, and is deliberately **not** dropped
//! at the end: the artifact is read out of the running stack's own Postgres, the
//! same way the transparency-log artifact is, and a database that disappeared with
//! the test would leave nothing to read. It is recreated from empty on every run,
//! so it never accumulates.
//!
//! What the run contains, and why each part is in it:
//!
//! - Four blobs uploaded and claimed by a manifest, so `relay_quota.stored_bytes`
//!   has something to account for.
//! - One later manifest omitting two of them, and a threshold-authorized policy,
//!   so the retention collector has a real verdict to reach on each.
//! - One object planted directly in the bucket with no reservation, so the
//!   storage-listing sweep has something to find.
//! - One reservation aged past the 24-hour grace with no claim, so the
//!   unclaimed-upload collector has something to find.
//!
//! Every number the artifact prints is therefore a number some mechanism reached
//! on its own, and the assertions below are what make the artifact worth reading:
//! a run log full of zeroes would pass a file-is-not-empty check and prove
//! nothing.

mod support;

use std::sync::Arc;

use sqlx::{Connection, Executor as _, PgConnection, PgPool};
use wealdrelay::config::{keys, Config, Values};
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::media::{gc, retention, store};
use wealdrelay::storage::{BlobKey, S3Store, Store};

use support::{
    blob_hash, device_from, make_group_in, postgres_port, signed_control, signed_manifest,
    signed_policy, verifier_key, Running,
};

/// Fixed, so whoever reads the artifact out afterwards knows where to look.
const DATABASE: &str = "weald_step09_evidence";
const BUCKET: &str = "weald-step09-evidence";
const WS: &str = "ws-step09";
const NOW: u64 = 1_800_000_000_000;

fn admin_url() -> String {
    format!(
        "postgres://weald:weald@127.0.0.1:{}/weald_relay",
        postgres_port()
    )
}

async fn fresh_database() -> String {
    let mut admin = PgConnection::connect(&admin_url()).await.expect(
        "Postgres is not reachable. This is an integration test and it does not skip: \
         run `scripts/weald-stack up`.",
    );
    admin
        .execute(format!("drop database if exists {DATABASE} with (force)").as_str())
        .await
        .expect("drop the previous evidence database");
    admin
        .execute(format!("create database {DATABASE}").as_str())
        .await
        .expect("create the evidence database");
    format!(
        "postgres://weald:weald@127.0.0.1:{}/{DATABASE}",
        postgres_port()
    )
}

async fn minio() -> aws_sdk_s3::Client {
    let credentials = aws_credential_types::Credentials::new(
        "weald",
        "weald-local-only",
        None,
        None,
        "weald-step09-evidence",
    );
    let loaded = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-east-1"))
        .endpoint_url("http://127.0.0.1:54090")
        .credentials_provider(credentials)
        .load()
        .await;
    aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::config::Builder::from(&loaded)
            .force_path_style(true)
            .build(),
    )
}

async fn empty_bucket(client: &aws_sdk_s3::Client) {
    let Ok(page) = client.list_objects_v2().bucket(BUCKET).send().await else {
        let _ = client.create_bucket().bucket(BUCKET).send().await;
        return;
    };
    for object in page.contents() {
        if let Some(key) = object.key() {
            let _ = client.delete_object().bucket(BUCKET).key(key).send().await;
        }
    }
}

fn key(group: &[u8], hash: &[u8]) -> BlobKey {
    BlobKey::new(
        WS,
        wealdrelay::media::hex(group),
        wealdrelay::media::hex(hash),
    )
    .expect("a well formed key")
}

#[tokio::test]
async fn the_gc_run_log_and_the_storage_accounting_are_left_behind_for_the_gate() {
    let url = fresh_database().await;
    let unused = tempfile::tempdir().unwrap();
    let s3 = minio().await;
    let _ = s3.create_bucket().bucket(BUCKET).send().await;
    empty_bucket(&s3).await;

    let config = Config::resolve(&Values::from_pairs([
        (keys::HOSTNAME, "localhost".to_string()),
        (keys::DATABASE_URL, url),
        // The configured backend is a scratch directory and the store installed
        // below is the harness MinIO. `serve::prepare` opens whatever the
        // configuration names from the ambient AWS chain, which on a laptop has no
        // region; the bucket this run actually uses is handed in with its client
        // already built, exactly as `tests/media_large.rs` does.
        (
            keys::STORAGE_URL,
            format!("file://{}", unused.path().display()),
        ),
        (keys::LISTEN, "127.0.0.1:0".to_string()),
        (keys::OBSERVABILITY_LISTEN, "127.0.0.1:0".to_string()),
        (keys::RELEASE_CHECK, "off".to_string()),
        (keys::MAX_STORAGE_GB, "1".to_string()),
    ]))
    .expect("the evidence configuration resolves");
    let store = Store::S3(S3Store::with_client(
        s3.clone(),
        BUCKET.to_string(),
        String::new(),
    ));
    let relay = Running::start_with(config, Clock::Fixed(NOW), move |state: &mut RelayState| {
        state.storage = Some(Arc::new(store));
    })
    .await;
    let state = Arc::clone(&relay.state);
    relay.shutdown().await;
    let pool: &PgPool = state.database.as_ref().expect("a database").pool();
    let storage = state.storage.as_ref().expect("a store");

    let ada = device_from(0x71);
    let group = make_group_in(
        &state,
        WS,
        0x91,
        std::slice::from_ref(&ada),
        std::slice::from_ref(&ada),
    )
    .await;
    let epoch = verifier_key(0x21);
    retention::apply_control(pool, &signed_control(&group, 0, &epoch, None, &epoch))
        .await
        .expect("the genesis control");
    store::ensure_quota_row(pool, WS, Some(1_000_000_000))
        .await
        .unwrap();

    // Four blobs, uploaded and claimed.
    let sizes = [4_096usize, 8_192, 16_384, 32_768];
    let hashes: Vec<Vec<u8>> = (0..4).map(|index| blob_hash(0xa0 + index as u8)).collect();
    for (index, hash) in hashes.iter().enumerate() {
        store::reserve(pool, WS, &group, hash, sizes[index] as i64, false, 900)
            .await
            .unwrap();
        storage
            .put(&key(&group, hash), &vec![index as u8; sizes[index]])
            .await
            .unwrap();
    }
    let first = signed_manifest(&group, 0, 1, None, hashes.clone(), &epoch);
    retention::apply_manifest(pool, WS, &first)
        .await
        .expect("the first manifest");
    let total: i64 = sizes.iter().map(|size| *size as i64).sum();
    assert_eq!(store::usage(pool, WS).await.unwrap().stored_bytes, total);

    // An interrupted upload nobody ever claimed, aged past the 24-hour grace.
    let orphan = blob_hash(0xb0);
    store::reserve(pool, WS, &group, &orphan, 2_048, false, 900)
        .await
        .unwrap();
    storage
        .put(&key(&group, &orphan), &vec![9u8; 2_048])
        .await
        .unwrap();
    sqlx::query(
        "update relay_blob_reservation set created_at = now() - interval '25 hours' \
         where blob_hash = $1",
    )
    .bind(&orphan)
    .execute(pool)
    .await
    .unwrap();

    // An object placed straight into the bucket, with no reservation behind it.
    let planted = blob_hash(0xc0);
    storage
        .put(&key(&group, &planted), b"planted with bucket credentials")
        .await
        .unwrap();
    // And one under a key shape the relay's own key space cannot express, which a
    // directory upload into the bucket produces. It is skipped rather than
    // deleted, because a key the relay cannot name is a key it must not act on.
    s3.put_object()
        .bucket(BUCKET)
        .key(format!(
            "{WS}/{}/nested/object",
            wealdrelay::media::hex(&group)
        ))
        .body(aws_sdk_s3::primitives::ByteStream::from_static(b"nested"))
        .send()
        .await
        .unwrap();

    // Two of the four are dropped by a later manifest, and a policy authorizes
    // the collection once the 30-day floor has passed.
    let second = signed_manifest(
        &group,
        0,
        2,
        Some(first.digest()),
        hashes[..2].to_vec(),
        &epoch,
    );
    retention::apply_manifest(pool, WS, &second)
        .await
        .expect("the second manifest");
    let policy = signed_policy(&group, 1, 30, NOW / 1000 - 1, &[ada]);
    retention::insert_policy(pool, &policy, "[]").await.unwrap();
    sqlx::query(
        "update relay_blob_reservation set finalized_at = now() - interval '40 days' \
         where finalized_at is not null",
    )
    .execute(pool)
    .await
    .unwrap();

    // All three mechanisms, in the order the relay runs them.
    let unclaimed = gc::sweep_unclaimed(pool, storage, WS, NOW).await;
    assert_eq!(unclaimed.examined, 1);
    assert_eq!(unclaimed.deleted, 1);
    assert_eq!(unclaimed.deleted_bytes, 2_048);

    let unreferenced = gc::sweep_unreferenced_storage(pool, storage, WS, &group, NOW).await;
    assert!(
        unreferenced.deleted >= 1,
        "the planted object has to be collected: {unreferenced:?}"
    );
    assert!(storage
        .head(&key(&group, &planted))
        .await
        .unwrap()
        .is_none());

    let retention_pass = gc::sweep_retention(pool, storage, WS, &group, NOW).await;
    assert_eq!(retention_pass.examined, 4);
    assert_eq!(retention_pass.deleted, 2, "the two the manifest dropped");
    assert_eq!(retention_pass.deleted_bytes, (sizes[2] + sizes[3]) as i64);

    // The two the manifest still names are still there, object and accounting
    // both. This is the line the artifact is really about: the storage accounting
    // agrees with the bucket.
    for hash in &hashes[..2] {
        assert!(storage.head(&key(&group, hash)).await.unwrap().is_some());
    }
    let usage = store::usage(pool, WS).await.unwrap();
    assert_eq!(usage.stored_bytes, (sizes[0] + sizes[1]) as i64);
    assert_eq!(usage.reserved_bytes, 0);
    assert_eq!(usage.limit_bytes, Some(1_000_000_000));

    // Three runs, one per mechanism, each with a non-zero examined count.
    let runs: i64 = sqlx::query_scalar("select count(*) from relay_gc_run")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(runs, 3);

    // The database is left in place on purpose: the gate reads it.
}
