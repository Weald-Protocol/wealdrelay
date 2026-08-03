// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! One storage contract, run against both backends.
//!
//! The rule this file exists to satisfy: where a fake exists in this programme, a
//! shared contract suite exists beside it, and where one does not, the fake is not
//! permitted. So the assertions below are written exactly once, over one type
//! parameter, and two `#[tokio::test]` entry points run the whole set: one over a
//! `FilesystemStore` in a temporary directory, one over an `S3Store` talking to
//! the MinIO the local harness runs. A filesystem backend held to its own private
//! set of assertions would be free to drift from the real one, and the drift would
//! be discovered in production rather than here.
//!
//! The parameter is a local trait rather than `BlobStore` itself. `BlobStore`
//! methods return `impl Future` since the `async_trait` macro left this module, so
//! no trait object can be formed, and the `Store` enum that `storage::open`
//! returns dispatches with inherent methods rather than by implementing the
//! trait. One local trait, forwarded by a macro, puts all three behind the single
//! parameter the shared-contract rule asks for, and each entry point runs the set
//! a second time through `Store` so a dispatcher forwarding one method to the
//! wrong backend cannot hide.
//!
//! The S3 half never skips. If MinIO is not reachable the test panics with the
//! command to bring it up, because a skipped integration proof reports success
//! for a thing that was never checked, and that is the exact failure mode the
//! build programme is arranged to prevent.
//!
//! A small number of assertions are inherently local: a permission bit, a
//! temporary filename, a path-containment helper. Those live in a separate
//! section further down, each with the reason it cannot be asserted against a
//! remote object store.

use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use aws_sdk_s3::config::retry::RetryConfig;
use aws_sdk_s3::config::timeout::TimeoutConfig;
use aws_sdk_s3::Client;
use wealdrelay::config::StorageTarget;
use wealdrelay::storage::{self, BlobInfo, BlobKey, FilesystemStore, S3Store, StorageError, Store};

/// The MinIO the local harness runs, from `backend/compose/weald-stack.yml`.
/// Hard-coded rather than read from the environment: a contract run that silently
/// pointed somewhere else would prove nothing about the deployment being built.
const MINIO_ENDPOINT: &str = "http://127.0.0.1:54090";
const MINIO_ACCESS_KEY: &str = "weald";
const MINIO_SECRET_KEY: &str = "weald-local-only";
const MINIO_REGION: &str = "us-east-1";

/// A few hundred KiB, deterministic, so a mismatch names a byte rather than a
/// random seed.
fn large_payload() -> Vec<u8> {
    (0..320 * 1024).map(|index| (index % 251) as u8).collect()
}

fn key(workspace: &str, group: &str, hash: &str) -> BlobKey {
    BlobKey::new(workspace, group, hash).expect("the test's own keys are well formed")
}

// MARK: One parameter over both backends

/// What the contract is written against. Every method forwards to the backend
/// unchanged; the trait exists only so the assertions can be written once and
/// applied to a `FilesystemStore`, an `S3Store` and the `Store` enum that
/// `storage::open` returns.
trait UnderTest {
    async fn put(&self, key: &BlobKey, bytes: &[u8]) -> Result<(), StorageError>;
    async fn get(&self, key: &BlobKey) -> Result<Vec<u8>, StorageError>;
    async fn head(&self, key: &BlobKey) -> Result<Option<BlobInfo>, StorageError>;
    async fn delete(&self, key: &BlobKey) -> Result<(), StorageError>;
    async fn list(&self, workspace: &str, group: &str) -> Result<Vec<String>, StorageError>;
    async fn assemble(&self, parts: &[BlobKey], target: &BlobKey) -> Result<u64, StorageError>;
    async fn probe(&self) -> Result<(), StorageError>;
    fn describe(&self) -> String;
}

/// Written as a macro rather than as a blanket implementation over `BlobStore`,
/// because `Store` deliberately does not implement `BlobStore` and a blanket
/// implementation would leave no way to include it. `BlobStore` is named in full
/// rather than imported, so that every unqualified call in this file resolves to
/// the trait above and there is no second way to reach a backend.
macro_rules! backend_under_test {
    ($store:ty) => {
        impl UnderTest for $store {
            async fn put(&self, key: &BlobKey, bytes: &[u8]) -> Result<(), StorageError> {
                <$store as wealdrelay::storage::BlobStore>::put(self, key, bytes).await
            }
            async fn get(&self, key: &BlobKey) -> Result<Vec<u8>, StorageError> {
                <$store as wealdrelay::storage::BlobStore>::get(self, key).await
            }
            async fn head(&self, key: &BlobKey) -> Result<Option<BlobInfo>, StorageError> {
                <$store as wealdrelay::storage::BlobStore>::head(self, key).await
            }
            async fn delete(&self, key: &BlobKey) -> Result<(), StorageError> {
                <$store as wealdrelay::storage::BlobStore>::delete(self, key).await
            }
            async fn list(
                &self,
                workspace: &str,
                group: &str,
            ) -> Result<Vec<String>, StorageError> {
                <$store as wealdrelay::storage::BlobStore>::list(self, workspace, group).await
            }
            async fn assemble(
                &self,
                parts: &[BlobKey],
                target: &BlobKey,
            ) -> Result<u64, StorageError> {
                <$store as wealdrelay::storage::BlobStore>::assemble(self, parts, target).await
            }
            async fn probe(&self) -> Result<(), StorageError> {
                <$store as wealdrelay::storage::BlobStore>::probe(self).await
            }
            fn describe(&self) -> String {
                <$store as wealdrelay::storage::BlobStore>::describe(self)
            }
        }
    };
}

backend_under_test!(FilesystemStore);
backend_under_test!(S3Store);

/// The enum `storage::open` returns, forwarded to its own inherent methods. It is
/// held to the contract as well, because a dispatcher that sent `head` to the
/// filesystem arm while everything else went to the bucket would pass every
/// assertion made against the two backends directly.
impl UnderTest for Store {
    async fn put(&self, key: &BlobKey, bytes: &[u8]) -> Result<(), StorageError> {
        Store::put(self, key, bytes).await
    }
    async fn get(&self, key: &BlobKey) -> Result<Vec<u8>, StorageError> {
        Store::get(self, key).await
    }
    async fn head(&self, key: &BlobKey) -> Result<Option<BlobInfo>, StorageError> {
        Store::head(self, key).await
    }
    async fn delete(&self, key: &BlobKey) -> Result<(), StorageError> {
        Store::delete(self, key).await
    }
    async fn list(&self, workspace: &str, group: &str) -> Result<Vec<String>, StorageError> {
        Store::list(self, workspace, group).await
    }
    async fn assemble(&self, parts: &[BlobKey], target: &BlobKey) -> Result<u64, StorageError> {
        Store::assemble(self, parts, target).await
    }
    async fn probe(&self) -> Result<(), StorageError> {
        Store::probe(self).await
    }
    fn describe(&self) -> String {
        Store::describe(self)
    }
}

// MARK: The contract

/// Everything both backends must do, in one place. `description` is the exact
/// string `describe` has to produce for this store, which is the only part of the
/// contract whose expected value differs between a directory and a bucket.
async fn run_the_contract(store: &impl UnderTest, description: &str) {
    put_then_get_returns_the_identical_bytes(store).await;
    a_repeated_put_is_invisible_and_a_changed_put_replaces(store).await;
    head_is_none_when_absent_and_a_length_when_present(store).await;
    get_of_an_absent_key_is_not_found(store).await;
    delete_removes_and_deleting_nothing_succeeds(store).await;
    list_is_scoped_to_one_workspace_and_group_and_sorted(store).await;
    list_of_an_empty_group_is_an_empty_vec(store).await;
    probe_succeeds_when_the_backend_is_reachable(store).await;
    describe_is_a_url_and_never_a_credential(store, description).await;
    an_empty_and_a_large_payload_both_round_trip(store).await;
    unusual_but_legal_key_components_survive(store).await;
    assemble_concatenates_its_parts_in_order(store).await;
    assemble_refuses_a_missing_part_and_an_empty_list(store).await;
}

/// The finalization of a multipart upload, on the contract because
/// `media::handle` is the only caller and both backends have to build the same
/// object out of the same parts. `specs/backend/relay/media.md`: "a completed
/// upload is finalized exactly once before the reservation becomes stored usage".
///
/// The part size here is 5 MiB and not five bytes, and that is the contract
/// rather than a detail of one backend: every part but the last must be at least
/// 5 MiB, which is S3's own multipart rule, and a suite that used tiny parts
/// would pass against a directory and fail against every bucket in production.
async fn assemble_concatenates_its_parts_in_order(store: &impl UnderTest) {
    const PART: usize = 5 * 1024 * 1024;
    let first = key("ws-assemble", "grp", "part-1");
    let second = key("ws-assemble", "grp", "part-2");
    let tail = key("ws-assemble", "grp", "part-3");
    store
        .put(&first, &vec![0xa1u8; PART])
        .await
        .expect("part 1");
    store
        .put(&second, &vec![0xa2u8; PART])
        .await
        .expect("part 2");
    store
        .put(&tail, b"tail")
        .await
        .expect("the short last part");

    let target = key("ws-assemble", "grp", "whole");
    let total = store
        .assemble(&[first.clone(), second.clone(), tail.clone()], &target)
        .await
        .expect("assemble");
    assert_eq!(total as usize, PART * 2 + 4);
    let whole = store.get(&target).await.expect("read the assembled object");
    assert_eq!(whole.len(), PART * 2 + 4);
    assert_eq!(whole[0], 0xa1);
    assert_eq!(whole[PART - 1], 0xa1);
    assert_eq!(whole[PART], 0xa2);
    assert_eq!(&whole[PART * 2..], b"tail");
    assert_eq!(
        store
            .head(&target)
            .await
            .expect("head")
            .expect("present")
            .len as usize,
        PART * 2 + 4
    );

    // The parts are untouched by the assembly: it is the caller that decides when
    // they may go, because until it has recorded the completion they are the only
    // copy of what the client uploaded.
    assert!(store.head(&first).await.expect("head").is_some());

    // One part is a legal assembly, and the 5 MiB rule does not apply to a last
    // part, so the only part may be any size.
    let single = key("ws-assemble", "grp", "single");
    assert_eq!(
        store
            .assemble(std::slice::from_ref(&tail), &single)
            .await
            .expect("one part"),
        4
    );
    assert_eq!(store.get(&single).await.expect("get"), b"tail");

    for object in [first, second, tail, target, single] {
        store.delete(&object).await.expect("clean up");
    }
}

/// The two refusals. A missing part is a client finalizing an upload it did not
/// finish, and assembling from nothing would let it finalize one it never made:
/// both have to be refused rather than answered with an empty object, because the
/// caller turns a success here into stored usage a customer is billed for.
async fn assemble_refuses_a_missing_part_and_an_empty_list(store: &impl UnderTest) {
    let target = key("ws-assemble-bad", "grp", "whole");
    let present = key("ws-assemble-bad", "grp", "part-1");
    store
        .put(&present, &vec![7u8; 5 * 1024 * 1024])
        .await
        .expect("the one part that is there");
    let absent = key("ws-assemble-bad", "grp", "part-2");

    assert!(matches!(
        store.assemble(&[], &target).await,
        Err(StorageError::InvalidKey { .. })
    ));
    assert!(
        store.head(&target).await.expect("head").is_none(),
        "an assembly that was refused must leave no object behind"
    );

    match store.assemble(&[present.clone(), absent], &target).await {
        Err(StorageError::NotFound { .. }) => {}
        other => panic!("a missing part must be NotFound, and was {other:?}"),
    }
    assert!(
        store.head(&target).await.expect("head").is_none(),
        "a failed assembly leaves no partial object"
    );

    store.delete(&present).await.expect("clean up");
}

/// The whole point of the abstraction. An upload the relay accepted has to come
/// back byte for byte, because the bytes are ciphertext and a single flipped bit
/// is an envelope no member can open and no operator can diagnose.
async fn put_then_get_returns_the_identical_bytes(store: &impl UnderTest) {
    let blob = key("ws-roundtrip", "grp", "hash-a");
    store.put(&blob, b"ciphertext").await.expect("put");
    assert_eq!(store.get(&blob).await.expect("get"), b"ciphertext");
}

/// A dropped upload is retried by the client, and the retry has to be free. The
/// second put of identical bytes must leave a reader unable to tell it happened,
/// and a put of different bytes at the same key must replace rather than append
/// or refuse, because the relay never merges object bodies.
async fn a_repeated_put_is_invisible_and_a_changed_put_replaces(store: &impl UnderTest) {
    let blob = key("ws-repeat", "grp", "hash-b");
    store.put(&blob, b"first").await.expect("first put");
    store.put(&blob, b"first").await.expect("identical put");
    assert_eq!(store.get(&blob).await.expect("get"), b"first");
    assert_eq!(
        store.head(&blob).await.expect("head").expect("present").len,
        5
    );
    assert_eq!(
        store.list("ws-repeat", "grp").await.expect("list"),
        vec!["hash-b".to_string()],
        "an identical put must not produce a second object"
    );

    store.put(&blob, b"replacement").await.expect("changed put");
    assert_eq!(store.get(&blob).await.expect("get"), b"replacement");
    assert_eq!(
        store.head(&blob).await.expect("head").expect("present").len,
        11
    );
    assert_eq!(
        store.list("ws-repeat", "grp").await.expect("list"),
        vec!["hash-b".to_string()]
    );
}

/// `head` is what the relay consults instead of issuing a second upload URL for
/// bytes it already holds, so absence has to be an answer rather than a failure,
/// and the length has to be the real one rather than whatever the client claimed.
async fn head_is_none_when_absent_and_a_length_when_present(store: &impl UnderTest) {
    let blob = key("ws-head", "grp", "hash-c");
    assert!(store
        .head(&blob)
        .await
        .expect("head of an absent key")
        .is_none());
    store.put(&blob, b"0123456789").await.expect("put");
    let info = store.head(&blob).await.expect("head").expect("present");
    assert_eq!(info.len, 10);
    // `BlobInfo` is compared and printed by callers, so both are part of the
    // contract rather than incidental derives.
    assert_eq!(info, BlobInfo { len: 10 });
    assert!(format!("{info:?}").contains("10"));
}

/// A read of something that is not there is `NotFound` and never an empty body,
/// because an empty body would be handed to a client as a valid envelope. The
/// message names the key so an operator can find it in the bucket.
async fn get_of_an_absent_key_is_not_found(store: &impl UnderTest) {
    let blob = key("ws-missing", "grp", "hash-d");
    let error = store.get(&blob).await.expect_err("must not invent bytes");
    match &error {
        StorageError::NotFound { key } => assert_eq!(key, "ws-missing/grp/hash-d"),
        other => panic!("expected NotFound, got {other}"),
    }
    assert!(
        !error.is_transient(),
        "a missing object is not worth retrying"
    );
}

/// Garbage collection runs against a list that may already be stale by the time
/// it acts, so deleting a key another collector removed a moment ago has to
/// succeed. A backend that failed there would turn a harmless race into an
/// operator page.
async fn delete_removes_and_deleting_nothing_succeeds(store: &impl UnderTest) {
    let blob = key("ws-delete", "grp", "hash-e");
    store.put(&blob, b"transient").await.expect("put");
    store.delete(&blob).await.expect("delete");
    assert!(store.head(&blob).await.expect("head").is_none());
    store
        .delete(&blob)
        .await
        .expect("deleting an absent key succeeds");
    assert!(store
        .list("ws-delete", "grp")
        .await
        .expect("list")
        .is_empty());
}

/// `list` feeds the unreferenced-blob collector, so leaking a neighbouring
/// group's keys into an answer would let the collector delete another group's
/// objects. The identical-hash case is the rule from
/// `specs/backend/relay/media.md`: hashes are never deduplicated across groups or
/// workspaces, because cross-group dedupe would let one group's membership prove
/// what another group holds.
async fn list_is_scoped_to_one_workspace_and_group_and_sorted(store: &impl UnderTest) {
    let shared = "hash-shared";
    for (workspace, group, hash) in [
        ("ws-list-one", "grp-a", "hash-zebra"),
        ("ws-list-one", "grp-a", "hash-apple"),
        ("ws-list-one", "grp-a", "hash-mango"),
        ("ws-list-one", "grp-a", shared),
        ("ws-list-one", "grp-b", shared),
        ("ws-list-two", "grp-a", shared),
    ] {
        store
            .put(&key(workspace, group, hash), workspace.as_bytes())
            .await
            .expect("put");
    }

    assert_eq!(
        store.list("ws-list-one", "grp-a").await.expect("list"),
        vec![
            "hash-apple".to_string(),
            "hash-mango".to_string(),
            "hash-shared".to_string(),
            "hash-zebra".to_string(),
        ],
        "sorted, and only this workspace and group"
    );
    assert_eq!(
        store.list("ws-list-one", "grp-b").await.expect("list"),
        vec![shared.to_string()]
    );
    assert_eq!(
        store.list("ws-list-two", "grp-a").await.expect("list"),
        vec![shared.to_string()]
    );

    // Three separate objects for one hash, and deleting one leaves the others
    // untouched. If any backend deduplicated, this is where it would show.
    store
        .delete(&key("ws-list-one", "grp-a", shared))
        .await
        .expect("delete one of the three");
    assert!(store
        .head(&key("ws-list-one", "grp-a", shared))
        .await
        .expect("head")
        .is_none());
    for (workspace, group) in [("ws-list-one", "grp-b"), ("ws-list-two", "grp-a")] {
        let info = store
            .head(&key(workspace, group, shared))
            .await
            .expect("head")
            .expect("the other copies are independent objects");
        assert_eq!(info.len, workspace.len() as u64);
    }
}

/// A group nobody has uploaded into is empty, not missing. The collector walks
/// every group it knows about, and an error for the ordinary case of a group with
/// no media would stop the walk at the first quiet group.
async fn list_of_an_empty_group_is_an_empty_vec(store: &impl UnderTest) {
    assert!(store
        .list("ws-never-used", "grp-never-used")
        .await
        .expect("an empty group is not an error")
        .is_empty());
}

/// `/readyz` reports this, so it has to be a real round trip. Against a store
/// that is up it simply has to succeed, twice, because a probe that consumed
/// something on the first call would report a healthy backend as sick on the
/// second.
async fn probe_succeeds_when_the_backend_is_reachable(store: &impl UnderTest) {
    store.probe().await.expect("the backend under test is up");
    store.probe().await.expect("probing twice is still fine");
}

/// This string is printed into logs and served from `/readyz`, so it is the one
/// piece of storage configuration an attacker reading a log gets for free. It
/// carries the URL form and never a secret.
async fn describe_is_a_url_and_never_a_credential(store: &impl UnderTest, expected: &str) {
    let described = store.describe();
    assert_eq!(described, expected);
    assert!(
        described.starts_with("file://") || described.starts_with("s3://"),
        "describe must be a URL, got {described}"
    );
    for secret in [MINIO_SECRET_KEY, MINIO_ACCESS_KEY, "password", "token"] {
        assert!(
            !described.contains(secret),
            "describe leaked {secret}: {described}"
        );
    }
}

/// Both ends of the size range. Zero bytes is a legal ciphertext body and must not
/// be confused with absence, and a few hundred KiB is an ordinary attachment that
/// has to survive whatever buffering the backend does in between.
async fn an_empty_and_a_large_payload_both_round_trip(store: &impl UnderTest) {
    let empty = key("ws-sizes", "grp", "hash-empty");
    store.put(&empty, b"").await.expect("put an empty object");
    assert_eq!(store.get(&empty).await.expect("get"), Vec::<u8>::new());
    assert_eq!(
        store
            .head(&empty)
            .await
            .expect("head")
            .expect("present")
            .len,
        0,
        "an empty object is present with length zero, not absent"
    );

    let big = key("ws-sizes", "grp", "hash-large");
    let payload = large_payload();
    store.put(&big, &payload).await.expect("put a large object");
    assert_eq!(store.get(&big).await.expect("get"), payload);
    assert_eq!(
        store.head(&big).await.expect("head").expect("present").len,
        payload.len() as u64
    );
    assert_eq!(
        store.list("ws-sizes", "grp").await.expect("list"),
        vec!["hash-empty".to_string(), "hash-large".to_string()]
    );
}

/// Every component is opaque to the relay, so anything `BlobKey::new` accepts has
/// to work identically on both backends. A character that a bucket encodes and a
/// directory does not would mean an object the relay wrote and cannot read back.
async fn unusual_but_legal_key_components_survive(store: &impl UnderTest) {
    let components = [
        "space in the middle",
        "unicode-ünïcode-名前",
        "plus+and=equals",
        "tilde~and-dash_and.dot",
        "percent%20literal",
        "parens(and)brackets[1]",
        "quote'single",
        "at@sign,comma;semicolon",
        "UPPER-and-lower-0123456789",
    ];
    for (index, component) in components.iter().enumerate() {
        let blob = key("ws unusual", &format!("grp-{index}"), component);
        let payload = component.as_bytes();
        store.put(&blob, payload).await.expect("put");
        assert_eq!(store.get(&blob).await.expect("get"), payload);
        assert_eq!(
            store.head(&blob).await.expect("head").expect("present").len,
            payload.len() as u64
        );
        assert_eq!(
            store
                .list("ws unusual", &format!("grp-{index}"))
                .await
                .expect("list"),
            vec![(*component).to_string()],
            "the listed name must be the component that was written"
        );
        store.delete(&blob).await.expect("delete");
    }
}

// MARK: The two backends

#[tokio::test]
async fn the_filesystem_backend_satisfies_the_storage_contract() {
    let root = tempfile::tempdir().expect("temp dir");
    let store = FilesystemStore::new(root.path());
    run_the_contract(&store, &format!("file://{}", root.path().display())).await;
    // `FilesystemStore` is cloned into the request path, and printed when the
    // startup summary explains where blobs are going.
    let clone = store.clone();
    assert_eq!(UnderTest::describe(&clone), UnderTest::describe(&store));
    assert!(format!("{store:?}").contains("FilesystemStore"));

    // And the same set again through the enum the rest of the relay is handed,
    // in a directory of its own so the second run starts from nothing.
    let wrapped_root = tempfile::tempdir().expect("temp dir");
    let wrapped = Store::Filesystem(FilesystemStore::new(wrapped_root.path()));
    run_the_contract(
        &wrapped,
        &format!("file://{}", wrapped_root.path().display()),
    )
    .await;
    assert!(format!("{wrapped:?}").contains("Filesystem"));
}

#[tokio::test]
async fn the_s3_backend_satisfies_the_storage_contract() {
    require_minio();
    // Both prefix forms, because a self-hoster sharing one bucket between staging
    // and production sets a prefix and a single-tenant one does not, and the two
    // build different object keys.
    let bucket = TestBucket::create("root").await;
    let store = S3Store::with_client(bucket.client.clone(), bucket.name.clone(), String::new());
    run_the_contract(&store, &format!("s3://{}", bucket.name)).await;
    bucket.destroy().await;

    let bucket = TestBucket::create("prefixed").await;
    let store = S3Store::with_client(
        bucket.client.clone(),
        bucket.name.clone(),
        "staging".to_string(),
    );
    run_the_contract(&store, &format!("s3://{}/staging", bucket.name)).await;
    // The prefix is real: the objects are under it, and a store without the prefix
    // sees nothing, which is what keeps two deployments in one bucket apart.
    let unprefixed =
        S3Store::with_client(bucket.client.clone(), bucket.name.clone(), String::new());
    assert!(UnderTest::list(&unprefixed, "ws-sizes", "grp")
        .await
        .expect("list")
        .is_empty());
    assert!(format!("{store:?}").contains("S3Store"));
    bucket.destroy().await;

    // And once more through the enum, under a prefix of its own.
    let bucket = TestBucket::create("wrapped").await;
    let wrapped = Store::S3(S3Store::with_client(
        bucket.client.clone(),
        bucket.name.clone(),
        "wrapped".to_string(),
    ));
    run_the_contract(&wrapped, &format!("s3://{}/wrapped", bucket.name)).await;
    assert!(format!("{wrapped:?}").contains("S3"));
    bucket.destroy().await;
}

// MARK: The filesystem alone
//
// What follows cannot be asserted against a bucket. A temporary partial file, a
// directory permission bit, a canonicalised path and a `StorageTarget` pointing at
// a directory are all properties of a local filesystem; S3 has no equivalent to
// hold to the same assertion, and inventing one would be inventing a fake.

/// The storage negative proof, at the level where it is observable: a reader never
/// sees a partial object. The filesystem backend buys that with a temporary file
/// and a rename, so the temporary name must never appear in a listing and the
/// object must be whole the moment it appears at all.
#[tokio::test]
async fn no_partial_object_is_ever_visible() {
    let root = tempfile::tempdir().expect("temp dir");
    let store = FilesystemStore::new(root.path());
    let blob = key("ws", "grp", "hash-partial");
    let payload = large_payload();
    store.put(&blob, &payload).await.expect("put");

    let listed = store.list("ws", "grp").await.expect("list");
    assert_eq!(listed, vec!["hash-partial".to_string()]);
    assert!(
        !listed
            .iter()
            .any(|name| name.contains("partial") && name.starts_with('.')),
        "a temporary name must never be listed: {listed:?}"
    );
    // And the temporary itself is gone from the directory, not merely hidden from
    // the listing.
    let temporary = root
        .path()
        .join("ws")
        .join("grp")
        .join(".hash-partial.partial");
    assert!(!temporary.exists(), "the temporary file outlived the put");
    assert_eq!(store.get(&blob).await.expect("get").len(), payload.len());

    // A temporary left behind by a process that died mid-put is hidden from the
    // collector rather than deleted as an unreferenced blob.
    std::fs::write(&temporary, b"half").expect("simulate an interrupted put");
    assert_eq!(
        store.list("ws", "grp").await.expect("list"),
        vec!["hash-partial".to_string()]
    );
}

/// Shape is the only thing the relay can check about an opaque component, and
/// shape is exactly what a path traversal exploits. A component with a separator
/// in it would write outside the group directory on one backend and create a
/// nested key on the other, so it is refused before either can happen.
#[test]
fn blob_key_refuses_a_component_that_could_escape_the_key_space() {
    assert_eq!(key("ws", "grp", "hash").path(), "ws/grp/hash");
    let ok = key("ws", "grp", "hash");
    assert_eq!(ok.clone(), ok);
    assert!(format!("{ok:?}").contains("hash"));

    // `.` is in the list as well as `..`. Both are path aliases, and the two
    // backends disagree about a bare `.`: real S3 accepts `ws/grp/.` as an ordinary
    // key while a filesystem can never create that file, so a key the contract
    // admitted would work on one backend and not on the other.
    for bad in ["", ".", "a/b", "a\\b", "..", "../etc", "a..b"] {
        for position in 0..3 {
            let mut parts = ["ws", "grp", "hash"];
            parts[position] = bad;
            let error = BlobKey::new(parts[0], parts[1], parts[2])
                .expect_err("must refuse a component that is empty or holds a separator");
            match &error {
                StorageError::InvalidKey { component } => assert_eq!(component, bad),
                other => panic!("expected InvalidKey for {bad:?}, got {other}"),
            }
            assert!(!error.is_transient());
            assert!(error.to_string().contains("path separator"));
        }
    }
}

/// The caller turns this into an error class: an outage is `retry`, everything
/// else is `reject` or `quota`
/// (`specs/backend/contracts/registries/error-codes.md`). A write failure marked
/// transient would have a client re-uploading against a full disk forever.
#[test]
fn only_an_outage_is_transient() {
    assert!(StorageError::Unreachable {
        reason: "connection refused".into()
    }
    .is_transient());
    for terminal in [
        StorageError::InvalidKey {
            component: "a/b".into(),
        },
        StorageError::NotFound {
            key: "a/b/c".into(),
        },
        StorageError::WriteFailed {
            reason: "no space".into(),
        },
        StorageError::ReadFailed {
            reason: "denied".into(),
        },
    ] {
        assert!(!terminal.is_transient(), "{terminal} must not be retried");
        assert!(!format!("{terminal:?}").is_empty());
    }
}

/// Path containment, canonicalised on both sides. A candidate that does not exist
/// is not inside anything, because a check that answered from the textual path
/// would accept a symlink that had not been resolved yet.
#[test]
fn is_within_is_true_only_for_a_path_actually_inside_the_root() {
    let root = tempfile::tempdir().expect("temp dir");
    let elsewhere = tempfile::tempdir().expect("temp dir");
    let inside = root.path().join("ws");
    std::fs::create_dir_all(&inside).expect("create");
    let file = inside.join("hash");
    std::fs::write(&file, b"x").expect("write");

    assert!(storage::is_within(root.path(), &inside));
    assert!(storage::is_within(root.path(), &file));
    assert!(storage::is_within(root.path(), root.path()));
    assert!(!storage::is_within(root.path(), elsewhere.path()));
    assert!(!storage::is_within(
        root.path(),
        &root.path().join("does-not-exist")
    ));
    assert!(!storage::is_within(
        Path::new("/does/not/exist/either"),
        &file
    ));
    // A traversal that resolves back out of the root is outside it, which is the
    // case the canonicalisation is there for.
    assert!(!storage::is_within(&inside, &inside.join("..")));
}

/// `open` is the startup path. It creates the directory rather than requiring the
/// operator to, and it probes, so a relay that starts has already proven it can
/// write where it was told to.
#[tokio::test]
async fn open_on_a_filesystem_target_creates_the_directory_and_probes_it() {
    let root = tempfile::tempdir().expect("temp dir");
    let blobs = root.path().join("nested").join("blobs");
    let target = StorageTarget::Filesystem(blobs.clone());
    let store = storage::open(&target).await.expect("open");
    assert!(
        blobs.is_dir(),
        "open must create the directory it was given"
    );
    assert_eq!(store.describe(), format!("file://{}", blobs.display()));
    // The probe object never survives into the key space it would otherwise be
    // collected from.
    assert!(!blobs.join(".readyz").exists());
    let blob = key("ws", "grp", "hash");
    store
        .put(&blob, b"through the trait object")
        .await
        .expect("put");
    assert_eq!(
        store.get(&blob).await.expect("get"),
        b"through the trait object"
    );
}

/// A configuration naming a directory the relay cannot create is refused at
/// startup with a typed error rather than a panic, because the operator needs the
/// reason and the supervisor needs an exit code rather than a backtrace.
#[tokio::test]
async fn open_on_an_impossible_filesystem_target_returns_a_typed_error() {
    let root = tempfile::tempdir().expect("temp dir");
    let file = root.path().join("not-a-directory");
    std::fs::write(&file, b"x").expect("write");
    let target = StorageTarget::Filesystem(file.join("blobs"));
    let error = storage::open(&target)
        .await
        .expect_err("a directory under a regular file cannot be created");
    assert!(
        matches!(error, StorageError::Unreachable { .. }),
        "expected an outage, got {error}"
    );
    assert!(error.is_transient());
}

/// The other half of the negative proof: every filesystem failure the backend can
/// meet is a typed error, and a failed put leaves nothing half-written behind.
/// These use permission bits and directories in place of files, which is why they
/// are here rather than in the shared contract.
#[tokio::test]
async fn every_filesystem_failure_is_a_typed_error_and_never_a_partial_object() {
    let root = tempfile::tempdir().expect("temp dir");
    let store = FilesystemStore::new(root.path());

    // A group directory that cannot be written to fails the put at the temporary
    // file, before anything is visible at the object's own name.
    let unwritable = root.path().join("ws-ro").join("grp");
    std::fs::create_dir_all(&unwritable).expect("create");
    set_mode(&unwritable, 0o500);
    let blob = key("ws-ro", "grp", "hash");
    let error = store.put(&blob, b"x").await.expect_err("put must fail");
    assert!(
        matches!(error, StorageError::WriteFailed { .. }),
        "expected a write failure, got {error}"
    );
    set_mode(&unwritable, 0o700);
    assert!(store.list("ws-ro", "grp").await.expect("list").is_empty());

    // A rename onto a non-empty directory fails, and the temporary is cleaned up
    // rather than left for the collector to trip over.
    let occupied = root.path().join("ws-dir").join("grp").join("hash");
    std::fs::create_dir_all(&occupied).expect("create");
    std::fs::write(occupied.join("inner"), b"x").expect("write");
    let blob = key("ws-dir", "grp", "hash");
    let error = store.put(&blob, b"x").await.expect_err("put must fail");
    assert!(
        matches!(error, StorageError::WriteFailed { .. }),
        "expected a write failure, got {error}"
    );
    assert!(!root
        .path()
        .join("ws-dir")
        .join("grp")
        .join(".hash.partial")
        .exists());

    // Reading, heading and deleting something that is not a readable file are read
    // and write failures rather than `NotFound`, because an operator told "no blob
    // there" would go looking for a missing upload instead of a broken disk.
    let error = store.get(&blob).await.expect_err("get must fail");
    assert!(
        matches!(error, StorageError::ReadFailed { .. }),
        "expected a read failure, got {error}"
    );
    let error = store.delete(&blob).await.expect_err("delete must fail");
    assert!(
        matches!(error, StorageError::WriteFailed { .. }),
        "expected a write failure, got {error}"
    );

    // A component whose parent is a regular file is not "absent": the path cannot
    // exist at all, and that is a different thing to tell the operator.
    std::fs::write(root.path().join("ws-file"), b"x").expect("write");
    let blocked = key("ws-file", "grp", "hash");
    let error = store.head(&blocked).await.expect_err("head must fail");
    assert!(
        matches!(error, StorageError::ReadFailed { .. }),
        "expected a read failure, got {error}"
    );
    let error = store
        .list("ws-file", "grp")
        .await
        .expect_err("list must fail");
    assert!(
        matches!(error, StorageError::ReadFailed { .. }),
        "expected a read failure, got {error}"
    );
    // The group directory cannot even be created, which is the first thing a put
    // does and the earliest point at which it can refuse.
    let error = store.put(&blocked, b"x").await.expect_err("put must fail");
    assert!(
        matches!(error, StorageError::WriteFailed { .. }),
        "expected a write failure, got {error}"
    );
    assert!(!error.is_transient());
}

/// A write that fails part way through, rather than at the moment the temporary
/// file is opened. A named pipe standing where the temporary belongs accepts the
/// open, takes some of the bytes and then loses its reader, which is as close as a
/// test can get to a disk that fills up half way through an upload. The object
/// must not appear, because a half-written blob is exactly what the rename is
/// there to prevent.
#[tokio::test]
async fn a_write_that_fails_part_way_through_leaves_no_object_behind() {
    let root = tempfile::tempdir().expect("temp dir");
    let store = FilesystemStore::new(root.path());
    let directory = root.path().join("ws-pipe").join("grp");
    std::fs::create_dir_all(&directory).expect("create");
    let temporary = directory.join(".hash.partial");
    let made = std::process::Command::new("mkfifo")
        .arg(&temporary)
        .status()
        .expect("mkfifo");
    assert!(made.success(), "mkfifo failed");

    // A reader that takes a little and leaves. The write blocks once the pipe
    // buffer is full, and fails the moment the far end is gone.
    let reading = temporary.clone();
    let reader = std::thread::spawn(move || {
        use std::io::Read as _;
        let mut pipe = std::fs::File::open(&reading).expect("open the pipe for reading");
        let mut scratch = [0_u8; 4096];
        let _ = pipe.read(&mut scratch);
    });

    let blob = key("ws-pipe", "grp", "hash");
    let error = store
        .put(&blob, &vec![7_u8; 8 * 1024 * 1024])
        .await
        .expect_err("a write that loses its far end must fail");
    reader.join().expect("the reader thread");
    assert!(
        matches!(error, StorageError::WriteFailed { .. }),
        "expected a write failure, got {error}"
    );
    assert!(
        store.head(&blob).await.expect("head").is_none(),
        "a failed put must leave no object"
    );
    assert!(
        store.list("ws-pipe", "grp").await.expect("list").is_empty(),
        "a failed put must leave nothing for the collector either"
    );
}

/// The probe is the honest kind: it writes and removes. Each of the three ways
/// that can fail has to surface as an outage, because `/readyz` turning green over
/// a directory the relay cannot write to is worse than no probe at all.
#[tokio::test]
async fn a_probe_that_cannot_write_or_clean_up_reports_an_outage() {
    let root = tempfile::tempdir().expect("temp dir");

    // The root cannot be created at all.
    let file = root.path().join("regular-file");
    std::fs::write(&file, b"x").expect("write");
    let error = FilesystemStore::new(file.join("blobs"))
        .probe()
        .await
        .expect_err("probe must fail");
    assert!(matches!(error, StorageError::Unreachable { .. }), "{error}");

    // The root exists and cannot be written to.
    let unwritable = root.path().join("unwritable");
    std::fs::create_dir_all(&unwritable).expect("create");
    set_mode(&unwritable, 0o500);
    let error = FilesystemStore::new(&unwritable)
        .probe()
        .await
        .expect_err("probe must fail");
    assert!(matches!(error, StorageError::Unreachable { .. }), "{error}");
    set_mode(&unwritable, 0o700);

    // The probe object can be written and not removed: the file is writable, the
    // directory holding it is not, which is exactly the state a half-configured
    // volume mount produces.
    let sticky = root.path().join("no-unlink");
    std::fs::create_dir_all(&sticky).expect("create");
    std::fs::write(sticky.join(".readyz"), b"stale").expect("write");
    set_mode(&sticky, 0o500);
    let error = FilesystemStore::new(&sticky)
        .probe()
        .await
        .expect_err("probe must fail when it cannot clean up after itself");
    assert!(matches!(error, StorageError::Unreachable { .. }), "{error}");
    set_mode(&sticky, 0o700);
}

/// The three ways the filesystem assembly can fail with every part present and
/// readable, which are the three the shared contract cannot reach: a missing part
/// is a contract assertion, and these are about the object being written.
///
/// The temporary file is the whole of the "a reader sees the whole object or no
/// object" guarantee, so each of these must come back as a refusal and leave the
/// destination absent. Reported as a success, the relay would mark a multipart
/// upload complete, charge the workspace for it, and hand out a key with nothing
/// behind it. The one thing worse would be a partial object under the real key,
/// which is what the temporary-then-rename shape exists to prevent, so that is
/// asserted after every case.
///
/// The causes are contrived and the states are not. A path that is a directory is
/// a leftover from a crashed assembly of the same object. A pipe is a path that is
/// not the regular file the store assumed, and the write into one whose reader has
/// gone is `EPIPE`, which is what a network filesystem does when a mount goes away
/// mid-write. A device that will not flush is the one case where every byte is
/// accepted and none of them is durable, which is the failure the flush is there
/// to catch.
#[tokio::test]
async fn an_assembly_that_cannot_write_its_temporary_object_is_refused_and_leaves_nothing() {
    let root = tempfile::tempdir().expect("temp dir");
    let store = Store::Filesystem(FilesystemStore::new(root.path()));
    let part = BlobKey::new("ws-assembly", "grp", "part-1").expect("key");
    let target = BlobKey::new("ws-assembly", "grp", "whole").expect("key");
    // Larger than a pipe will hold, so the write below has to block rather than
    // disappearing into a buffer and succeeding.
    store
        .put(&part, &vec![7_u8; 2 << 20])
        .await
        .expect("the part lands");
    let directory = root.path().join("ws-assembly").join("grp");
    let temporary = directory.join(".whole.assembling");
    let destination = directory.join("whole");

    let refused = |what: &str, outcome: Result<u64, StorageError>| {
        match outcome {
            Err(StorageError::WriteFailed { .. }) => {}
            other => panic!("{what}: expected a write failure, got {other:?}"),
        }
        assert!(
            !destination.exists(),
            "{what}: a refused assembly left an object under the real key"
        );
    };

    // 1. The temporary path cannot be opened for writing at all.
    std::fs::create_dir_all(&temporary).expect("a directory in the way");
    refused(
        "a temporary path that is a directory",
        store.assemble(std::slice::from_ref(&part), &target).await,
    );
    std::fs::remove_dir_all(&temporary).expect("clear the way");

    // 2. The write itself is refused partway through. The reader opens, which is
    // what lets the assembly's own open finish, and then goes away, which is what
    // turns the next write into an error.
    nix_mkfifo(&temporary);
    let reading = std::thread::spawn({
        let path = temporary.clone();
        move || {
            let handle = std::fs::File::open(&path).expect("open the pipe to read");
            std::thread::sleep(Duration::from_millis(300));
            drop(handle);
        }
    });
    refused(
        "a temporary object whose reader goes away",
        store.assemble(std::slice::from_ref(&part), &target).await,
    );
    reading.join().expect("the reader finishes");
    let _ = std::fs::remove_file(&temporary);

    // 3. Every byte is accepted and none of them can be flushed. A write the
    // filesystem took and cannot make durable is not a written object, and
    // answering with a byte count here would report an attachment as stored that
    // nothing would survive a power cut with.
    std::os::unix::fs::symlink("/dev/null", &temporary).expect("a device in the way");
    refused(
        "a temporary object that cannot be flushed",
        store.assemble(std::slice::from_ref(&part), &target).await,
    );
    let _ = std::fs::remove_file(&temporary);

    // With the way clear, the same assembly succeeds, so each refusal above was
    // the injected state and not an assembly that could never have worked.
    assert_eq!(
        store
            .assemble(std::slice::from_ref(&part), &target)
            .await
            .expect("assemble"),
        2 << 20
    );
}

/// `mkfifo` through libc, which is already a dev-dependency for the signal in
/// `tests/process.rs`. There is no `std` for it.
fn nix_mkfifo(path: &Path) {
    let raw = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("a path");
    let made = unsafe { libc::mkfifo(raw.as_ptr(), 0o600) };
    assert_eq!(made, 0, "mkfifo {}", path.display());
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = std::fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(mode);
    std::fs::set_permissions(path, permissions).expect("set permissions");
}

// MARK: S3 alone
//
// The same reasoning in reverse. A credential that is wrong, an endpoint that is
// dead, a server that answers with something that is not S3 and a listing that
// needs a second page are all properties of talking to a remote service over HTTP,
// and the filesystem backend has nothing to hold to the same assertion.

/// Fail loudly, never skip. A skipped integration test reports success for
/// something nobody checked, which is the failure mode the whole build programme
/// is arranged around.
fn require_minio() {
    let address = "127.0.0.1:54090".parse().expect("a literal address");
    if TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_err() {
        panic!(
            "MinIO is not answering on {MINIO_ENDPOINT}. This is the integration tier and it does \
             not skip: run `scripts/weald-stack up` and try again."
        );
    }
}

/// A client for MinIO. Built from the SDK's own defaults so it has an HTTP client
/// and a sleep implementation, then overridden with the harness endpoint,
/// path-style addressing and static credentials, which is exactly what an operator
/// pointing the relay at a non-AWS gateway configures.
async fn client_for(endpoint: &str, access: &str, secret: &str, patient: bool) -> Client {
    let credentials = aws_credential_types::Credentials::new(
        access.to_string(),
        secret.to_string(),
        None,
        None,
        "weald-storage-contract",
    );
    let loaded = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(MINIO_REGION))
        .endpoint_url(endpoint)
        .credentials_provider(credentials)
        .load()
        .await;
    let mut builder = aws_sdk_s3::config::Builder::from(&loaded).force_path_style(true);
    if !patient {
        // No retries and a short ceiling, so a test about an unreachable backend
        // finishes in the time an unreachable backend takes to notice.
        builder = builder
            .retry_config(RetryConfig::disabled())
            .timeout_config(
                TimeoutConfig::builder()
                    .operation_attempt_timeout(Duration::from_secs(3))
                    .build(),
            );
    }
    Client::from_conf(builder.build())
}

/// A bucket of its own per test, named for the run, removed at the end. Sharing
/// one would make a listing assertion depend on what another test had uploaded.
struct TestBucket {
    client: Client,
    name: String,
}

impl TestBucket {
    async fn create(label: &str) -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_nanos();
        let name = format!("contract-{label}-{stamp}");
        let client = client_for(MINIO_ENDPOINT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, true).await;
        client
            .create_bucket()
            .bucket(&name)
            .send()
            .await
            .expect("MinIO is up but refused a new bucket");
        Self { client, name }
    }

    async fn destroy(self) {
        let mut continuation: Option<String> = None;
        loop {
            let mut request = self.client.list_objects_v2().bucket(&self.name);
            if let Some(token) = continuation.take() {
                request = request.continuation_token(token);
            }
            let page = request.send().await.expect("list for cleanup");
            for object in page.contents() {
                if let Some(key) = object.key() {
                    self.client
                        .delete_object()
                        .bucket(&self.name)
                        .key(key)
                        .send()
                        .await
                        .expect("delete for cleanup");
                }
            }
            match page.next_continuation_token() {
                Some(token) if page.is_truncated().unwrap_or(false) => {
                    continuation = Some(token.to_string())
                }
                _ => break,
            }
        }
        self.client
            .delete_bucket()
            .bucket(&self.name)
            .send()
            .await
            .expect("delete the test bucket");
    }
}

/// A backend that is not answering produces `Unreachable`, which is the one error
/// the caller retries. Every operation has to agree about that, because a put that
/// reported a dead endpoint as a permanent write failure would lose an upload the
/// client could have retried in a second.
#[tokio::test]
async fn an_unreachable_endpoint_is_transient_on_every_operation() {
    // Port 1 on the loopback interface has nothing listening and refuses
    // immediately, so this is an outage rather than a timeout.
    let client = client_for(
        "http://127.0.0.1:1",
        MINIO_ACCESS_KEY,
        MINIO_SECRET_KEY,
        false,
    )
    .await;
    let store = S3Store::with_client(client, "weald-nowhere".to_string(), String::new());
    let blob = key("ws", "grp", "hash");

    for error in [
        store.put(&blob, b"x").await.expect_err("put"),
        store.get(&blob).await.expect_err("get"),
        store.head(&blob).await.expect_err("head"),
        store.delete(&blob).await.expect_err("delete"),
        store.list("ws", "grp").await.expect_err("list"),
        // Assembly reaches the bucket three ways (open, copy, complete) and the
        // first of them is the one an outage stops, so this is the arm that has
        // to stay transient: a multipart completion that reported a terminal
        // failure would let a client believe its upload was rejected rather than
        // delayed.
        store
            .assemble(&[key("ws", "grp", "part-1")], &blob)
            .await
            .expect_err("assemble"),
        store.probe().await.expect_err("probe"),
    ] {
        assert!(
            error.is_transient(),
            "an unreachable bucket must be retryable, got {error}"
        );
    }
}

/// A credential the bucket refuses is terminal, not transient. Retrying a
/// signature failure would hammer the provider and never succeed, and the write
/// half has to come back as a write failure so the caller maps it onto `reject`
/// rather than `retry`.
#[tokio::test]
async fn a_refused_credential_is_a_terminal_failure_and_not_a_missing_object() {
    require_minio();
    let bucket = TestBucket::create("denied").await;
    let blob = key("ws", "grp", "hash");
    let good = S3Store::with_client(bucket.client.clone(), bucket.name.clone(), String::new());
    good.put(&blob, b"present").await.expect("put");

    let wrong = client_for(MINIO_ENDPOINT, MINIO_ACCESS_KEY, "not-the-secret", false).await;
    let store = S3Store::with_client(wrong, bucket.name.clone(), String::new());
    for error in [
        store.get(&blob).await.expect_err("get"),
        store.head(&blob).await.expect_err("head"),
        store.delete(&blob).await.expect_err("delete"),
        store.list("ws", "grp").await.expect_err("list"),
    ] {
        assert!(
            !error.is_transient(),
            "a refused signature must not be retried, got {error}"
        );
        assert!(
            !matches!(error, StorageError::NotFound { .. }),
            "a refused read is not an absent object: {error}"
        );
    }
    let error = store.put(&blob, b"x").await.expect_err("put");
    assert!(
        matches!(error, StorageError::WriteFailed { .. }),
        "a refused put is a write failure, got {error}"
    );
    // And the object is still there, so the refused write changed nothing.
    assert_eq!(good.get(&blob).await.expect("get"), b"present");
    bucket.destroy().await;
}

/// A listing longer than one page. The unreferenced-blob collector deletes what a
/// listing did not mention, so a list that stopped silently at the first thousand
/// keys would delete every blob after it.
#[tokio::test]
async fn a_listing_longer_than_one_page_is_followed_to_the_end() {
    require_minio();
    let bucket = TestBucket::create("paged").await;
    let store = S3Store::with_client(bucket.client.clone(), bucket.name.clone(), String::new());
    // One more than the default page size of a thousand.
    let total = 1001;
    let mut pending = Vec::new();
    for index in 0..total {
        let store = S3Store::with_client(bucket.client.clone(), bucket.name.clone(), String::new());
        pending.push(tokio::spawn(async move {
            let blob = key("ws-paged", "grp", &format!("hash-{index:05}"));
            store.put(&blob, b"").await.expect("put");
        }));
        if pending.len() == 32 {
            for task in pending.drain(..) {
                task.await.expect("upload task");
            }
        }
    }
    for task in pending.drain(..) {
        task.await.expect("upload task");
    }

    let listed = store.list("ws-paged", "grp").await.expect("list");
    assert_eq!(listed.len(), total, "every page has to be followed");
    assert_eq!(listed.first().map(String::as_str), Some("hash-00000"));
    assert_eq!(listed.last().map(String::as_str), Some("hash-01000"));
    bucket.destroy().await;
}

/// A listener on the loopback interface that answers every request with one
/// canned reply, or with nothing at all. Standing in for a misconfigured endpoint
/// that reaches something which is not S3, which no real MinIO can be made to do
/// while it is healthy.
async fn a_server_that_is_not_s3(reply: Option<Vec<u8>>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback listener");
    let endpoint = format!("http://{}", listener.local_addr().expect("local address"));
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let reply = reply.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                let mut scratch = [0_u8; 4096];
                let _ = socket.read(&mut scratch).await;
                match reply {
                    Some(bytes) => {
                        let bytes = &bytes[..];
                        let _ = socket.write_all(bytes).await;
                        let _ = socket.flush().await;
                    }
                    // Accepted and never answered, which is what a hung backend
                    // looks like from the client side.
                    None => {
                        let _ = socket.readable().await;
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                }
            });
        }
    });
    endpoint
}

/// A listing whose body is well-formed HTTP and not a listing. The relay has to
/// turn that into a typed read failure naming the operation, rather than a panic
/// in the deserialiser, because the operator who pointed `s3://` at their own web
/// server needs a message they can act on.
#[tokio::test]
async fn a_response_that_is_not_an_s3_listing_is_a_typed_error() {
    let endpoint = a_server_that_is_not_s3(Some(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: 88\r\n\r\n\
          <?xml version=\"1.0\"?><ListBucketResult><Contents><Size>a lot</Size>\
          </Contents></ListBucketResult>"
            .to_vec(),
    ))
    .await;
    let client = client_for(&endpoint, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, false).await;
    let store = S3Store::with_client(client, "not-a-bucket".to_string(), String::new());
    let error = store
        .list("ws", "grp")
        .await
        .expect_err("a listing that cannot be parsed is a failure");
    assert!(
        matches!(error, StorageError::ReadFailed { .. }),
        "expected a read failure, got {error}"
    );
    assert!(
        !error.is_transient(),
        "a server answering nonsense will answer the same nonsense next time: {error}"
    );
    assert!(
        error.to_string().contains("list ws/grp/"),
        "the message has to name the operation: {error}"
    );
}

/// A body shorter than the length its headers promised. The object exists as far
/// as the response line is concerned, so this is the one failure that happens
/// after a successful `GetObject`, and handing the truncated prefix to a client as
/// an envelope would be the remote equivalent of reading a partial write.
#[tokio::test]
async fn a_truncated_body_is_a_read_failure_and_never_a_short_object() {
    let endpoint = a_server_that_is_not_s3(Some(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\nonly these bytes arrive".to_vec(),
    ))
    .await;
    let client = client_for(&endpoint, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, false).await;
    let store = S3Store::with_client(client, "not-a-bucket".to_string(), String::new());
    let error = store
        .get(&key("ws", "grp", "hash"))
        .await
        .expect_err("a body that stopped early is not an object");
    match &error {
        StorageError::ReadFailed { reason } => {
            assert!(reason.contains("ws/grp/hash"), "{reason}")
        }
        other => panic!("expected a read failure, got {other}"),
    }
}

/// A backend that accepts the connection and never answers. Distinct from a
/// refused connection and identical in what the caller must do about it: the
/// request never reached the bucket, so it is retryable.
#[tokio::test]
async fn a_backend_that_never_answers_times_out_and_is_transient() {
    let endpoint = a_server_that_is_not_s3(None).await;
    let credentials = aws_credential_types::Credentials::new(
        MINIO_ACCESS_KEY,
        MINIO_SECRET_KEY,
        None,
        None,
        "weald-storage-contract",
    );
    let loaded = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(MINIO_REGION))
        .endpoint_url(&endpoint)
        .credentials_provider(credentials)
        .load()
        .await;
    let client = Client::from_conf(
        aws_sdk_s3::config::Builder::from(&loaded)
            .force_path_style(true)
            .retry_config(RetryConfig::disabled())
            .timeout_config(
                TimeoutConfig::builder()
                    .operation_timeout(Duration::from_millis(250))
                    .build(),
            )
            .build(),
    );
    let store = S3Store::with_client(client, "not-a-bucket".to_string(), String::new());
    let blob = key("ws", "grp", "hash");

    // Every operation, not just one. A timeout is classified where the request was
    // made, so an operation that mapped it somewhere else would be a retryable
    // failure the caller rejected, and it would only ever show up as a lost upload.
    for (what, error) in [
        ("put", store.put(&blob, b"x").await.expect_err("put")),
        ("get", store.get(&blob).await.expect_err("get")),
        ("head", store.head(&blob).await.expect_err("head")),
        ("delete", store.delete(&blob).await.expect_err("delete")),
        ("list", store.list("ws", "grp").await.expect_err("list")),
    ] {
        assert!(
            error.is_transient(),
            "a timeout is the definition of worth retrying, {what} gave {error}"
        );
        assert!(error.to_string().contains("timed out"), "{what}: {error}");
    }
    // `probe` reports the same outage in its own words, because it is asking about
    // the bucket rather than about an object and the operator reading `/readyz`
    // needs to see which of the two failed.
    let error = store.probe().await.expect_err("probe");
    assert!(error.is_transient(), "{error}");
    assert!(error.to_string().contains("head bucket"), "{error}");
}

/// A request the SDK will not even build. The relay never constructs one on
/// purpose, but the arm exists so a future caller passing an impossible bucket
/// gets a typed error rather than an unwrap somewhere in the SDK.
#[tokio::test]
async fn a_request_that_cannot_be_constructed_is_a_typed_error() {
    let client = client_for(MINIO_ENDPOINT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, false).await;
    let store = S3Store::with_client(client, String::new(), String::new());
    let blob = key("ws", "grp", "hash");
    let error = store
        .put(&blob, b"x")
        .await
        .expect_err("an empty bucket name is not a request");
    assert!(
        matches!(error, StorageError::WriteFailed { .. }),
        "expected a write failure, got {error}"
    );
    // The read half of the surface, all of it. Each operation builds its own
    // request, so an arm that panicked instead of returning would be one call away
    // from a relay that aborts rather than answers.
    for (what, error) in [
        ("get", store.get(&blob).await.expect_err("get")),
        ("head", store.head(&blob).await.expect_err("head")),
        ("delete", store.delete(&blob).await.expect_err("delete")),
        ("list", store.list("ws", "grp").await.expect_err("list")),
    ] {
        assert!(
            matches!(error, StorageError::ReadFailed { .. }),
            "expected a read failure from {what}, got {error}"
        );
        // And it is terminal. A request the SDK will not build will never build,
        // so retrying it would spin forever against a bucket name that is wrong.
        assert!(!error.is_transient(), "{what}: {error}");
    }
    // `probe` again says it in its own words, and marks it transient, because a
    // bucket it cannot ask about is reported to `/readyz` as an outage rather than
    // as a claim about the object space.
    let error = store.probe().await.expect_err("probe");
    assert!(
        matches!(error, StorageError::Unreachable { .. }),
        "expected an outage, got {error}"
    );
}

/// A key with nothing after the last separator. Other tools write these as folder
/// markers, and a relay that reported one as a blob would hand the collector a
/// name that is not a hash and cannot be deleted by key.
#[tokio::test]
async fn a_folder_marker_is_not_reported_as_a_blob() {
    require_minio();
    let bucket = TestBucket::create("marker").await;
    let store = S3Store::with_client(bucket.client.clone(), bucket.name.clone(), String::new());
    store
        .put(&key("ws-marker", "grp", "hash"), b"real")
        .await
        .expect("put");
    bucket
        .client
        .put_object()
        .bucket(&bucket.name)
        .key("ws-marker/grp/")
        .body(aws_sdk_s3::primitives::ByteStream::from_static(b""))
        .send()
        .await
        .expect("write a folder marker the way another tool would");

    assert_eq!(
        store.list("ws-marker", "grp").await.expect("list"),
        vec!["hash".to_string()],
        "the marker is not a blob and must not be listed"
    );
    bucket.destroy().await;
}

/// A listing that says there is more and does not say where to continue from. No
/// correct server does this, and a relay that trusted the flag alone would loop on
/// the same page forever with the collector waiting on it.
#[tokio::test]
async fn a_listing_that_claims_more_without_saying_where_stops() {
    let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
        <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
        <Name>bucket</Name><Prefix>ws/grp/</Prefix><KeyCount>1</KeyCount>\
        <MaxKeys>1000</MaxKeys><IsTruncated>true</IsTruncated>\
        <Contents><Key>ws/grp/hash</Key><Size>4</Size></Contents>\
        </ListBucketResult>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let endpoint = a_server_that_is_not_s3(Some(response.into_bytes())).await;
    let client = client_for(&endpoint, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, false).await;
    let store = S3Store::with_client(client, "bucket".to_string(), String::new());
    assert_eq!(
        store.list("ws", "grp").await.expect("list"),
        vec!["hash".to_string()],
        "the page that was returned is kept, and the walk stops"
    );
}

/// The startup path for a bucket, end to end: `open` on an `s3://` target builds
/// its own client from the ambient AWS configuration, probes the bucket and hands
/// back a working store. This is the only test that touches process environment,
/// because that chain is the whole point of it.
#[tokio::test]
async fn open_on_an_s3_target_probes_the_bucket_from_the_ambient_configuration() {
    require_minio();
    let bucket = TestBucket::create("ambient").await;
    // Safety: the AWS variables are not read by any other test in this binary, and
    // every other client here sets its endpoint and credentials explicitly.
    std::env::set_var("AWS_ENDPOINT_URL_S3", MINIO_ENDPOINT);
    std::env::set_var("AWS_ENDPOINT_URL", MINIO_ENDPOINT);
    std::env::set_var("AWS_ACCESS_KEY_ID", MINIO_ACCESS_KEY);
    std::env::set_var("AWS_SECRET_ACCESS_KEY", MINIO_SECRET_KEY);
    std::env::set_var("AWS_REGION", MINIO_REGION);

    let target = StorageTarget::S3 {
        bucket: bucket.name.clone(),
        prefix: "opened".to_string(),
    };
    let store = storage::open(&target).await.expect("open an s3 target");
    assert_eq!(store.describe(), format!("s3://{}/opened", bucket.name));
    let blob = key("ws", "grp", "hash");
    store.put(&blob, b"through open").await.expect("put");
    assert_eq!(store.get(&blob).await.expect("get"), b"through open");

    // A bucket that is not there fails the probe rather than being discovered on
    // the first upload.
    let missing = StorageTarget::S3 {
        bucket: format!("{}-absent", bucket.name),
        prefix: String::new(),
    };
    let error = storage::open(&missing)
        .await
        .expect_err("a bucket the relay cannot see must fail at startup");
    assert!(
        matches!(error, StorageError::Unreachable { .. }),
        "expected an outage, got {error}"
    );

    std::env::remove_var("AWS_ENDPOINT_URL_S3");
    std::env::remove_var("AWS_ENDPOINT_URL");
    std::env::remove_var("AWS_ACCESS_KEY_ID");
    std::env::remove_var("AWS_SECRET_ACCESS_KEY");
    std::env::remove_var("AWS_REGION");
    bucket.destroy().await;
}

// MARK: The directory listing, entry by entry
//
// `read_dir` yielding an error part way through a listing needs a volume that
// detaches under the process or a fault-injecting filesystem, and neither is
// available to a hermetic test. The reader is therefore written as two functions
// over the iterator's own item type, which is what makes the failure path
// reachable with a synthesized error rather than argued about in a comment.

/// The error `read_dir` hands back when a directory it has already opened stops
/// answering. Synthesized, because the real thing needs hardware to misbehave.
fn a_read_that_failed() -> std::io::Result<std::fs::DirEntry> {
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "the volume stopped answering part way through the listing",
    ))
}

/// One real directory holding one real object and one partial file, so the two
/// arms that keep an entry and drop one are exercised against entries the
/// operating system produced rather than ones the test invented.
fn a_directory_with_an_object_and_a_partial() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("a temporary directory");
    std::fs::write(dir.path().join("aa11"), b"an object").expect("write the object");
    std::fs::write(dir.path().join(".aa11.part"), b"half an upload")
        .expect("write the partial file");
    dir
}

#[test]
fn a_listing_that_fails_part_way_through_is_a_read_failure_and_never_a_short_list() {
    // The failure this guards against is a listing that swallowed an error and
    // returned the entries it had managed to read. The unreferenced-blob collector
    // runs off this list, and a short list means it deletes objects it never saw.
    let error = storage::object_name(a_read_that_failed())
        .expect_err("an entry that could not be read is not an absent entry");
    assert!(
        matches!(error, StorageError::ReadFailed { .. }),
        "expected a read failure, got {error}"
    );
    assert!(
        error.to_string().contains("stopped answering"),
        "the reason the operating system gave has to survive: {error}"
    );
    // A read failure is not transient. Retrying a directory that cannot be read
    // would spin rather than surface the fault.
    assert!(!error.is_transient(), "{error}");

    // And the same error inside a real listing stops the whole listing rather than
    // being skipped over.
    let dir = a_directory_with_an_object_and_a_partial();
    let entries = std::fs::read_dir(dir.path()).expect("read the directory");
    let error = storage::object_names(entries.chain(std::iter::once(a_read_that_failed())))
        .expect_err("one unreadable entry fails the listing");
    assert!(
        matches!(error, StorageError::ReadFailed { .. }),
        "expected a read failure, got {error}"
    );

    // The same reader over the same shape of listing with nothing wrong with it,
    // so the failure above is a property of the unreadable entry and not of the
    // reader refusing anything it is handed.
    let other = a_directory_with_an_object_and_a_partial();
    let extra = std::fs::read_dir(other.path())
        .expect("read the second directory")
        .find(|entry| {
            entry
                .as_ref()
                .is_ok_and(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
        })
        .expect("the second directory holds an object");
    let entries = std::fs::read_dir(dir.path()).expect("read the directory");
    assert_eq!(
        storage::object_names(entries.chain(std::iter::once(extra)))
            .expect("a listing with nothing wrong with it"),
        vec!["aa11".to_string(), "aa11".to_string()],
        "the reader keeps every object it is given and sorts them"
    );
}

#[test]
fn a_partial_upload_is_not_an_object_and_a_real_one_is() {
    // A dot-prefixed file is the temporary half of a put that is still in flight.
    // Listing it would hand the collector a name that is not a hash, and deleting
    // by that name would destroy an upload that had not finished.
    let dir = a_directory_with_an_object_and_a_partial();
    let mut kept = Vec::new();
    let mut skipped = 0;
    for entry in std::fs::read_dir(dir.path()).expect("read the directory") {
        match storage::object_name(entry).expect("a readable entry") {
            Some(name) => kept.push(name),
            None => skipped += 1,
        }
    }
    assert_eq!(kept, vec!["aa11".to_string()]);
    assert_eq!(skipped, 1, "the partial file is dropped and not listed");

    // The same directory through the whole reader, which also sorts: both backends
    // promise a sorted listing and `read_dir` order is whatever the filesystem
    // felt like that day.
    let entries = std::fs::read_dir(dir.path()).expect("read the directory");
    assert_eq!(
        storage::object_names(entries).expect("a readable directory"),
        vec!["aa11".to_string()]
    );
}

/// A listing whose keys are not under the prefix that was asked for. No correct
/// server does this, and the relay drops them rather than reporting them as blobs
/// in this group, because a name that is not in the group is a name the collector
/// would delete out of somebody else's.
#[tokio::test]
async fn a_listing_carrying_a_key_outside_the_prefix_drops_it() {
    let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
        <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
        <Name>bucket</Name><Prefix>ws/grp/</Prefix><KeyCount>3</KeyCount>\
        <MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>\
        <Contents><Key>ws/grp/hash</Key><Size>4</Size></Contents>\
        <Contents><Key>somewhere/else/hash</Key><Size>4</Size></Contents>\
        <Contents><Key>ws/grp/</Key><Size>0</Size></Contents>\
        </ListBucketResult>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let endpoint = a_server_that_is_not_s3(Some(response.into_bytes())).await;
    let client = client_for(&endpoint, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, false).await;
    let store = S3Store::with_client(client, "bucket".to_string(), String::new());
    assert_eq!(
        store.list("ws", "grp").await.expect("list"),
        vec!["hash".to_string()],
        "only the key actually under the prefix is a blob in this group"
    );
}

// MARK: Presigned URLs and the assembly failures
//
// `media.md` puts the transfer itself outside the WebSocket: the relay answers
// `BLOB put` and `BLOB get` with a presigned URL and never carries the bytes. The
// happy paths below run against MinIO because a signature is only worth asserting
// against something that verifies it, and the refusals run against a server that
// is not S3 because a bucket cannot be asked to fail on demand.

/// A presigned PUT and GET are issued, name the object, and carry an expiry.
///
/// Asserted as URL structure rather than by fetching: what the relay owes the
/// client is a signed URL for the right key, and whether MinIO honours it is
/// already proven by the round trip in `tests/media_socket.rs`.
#[tokio::test]
async fn a_presigned_url_is_issued_for_both_directions_and_names_its_object() {
    require_minio();
    let bucket = TestBucket::create("presign").await;
    let store = S3Store::with_client(bucket.client.clone(), bucket.name.clone(), String::new());
    let key = BlobKey::new("ws-presign", "grp", "hash").expect("key");

    let put = store
        .presign_put(&key, Duration::from_secs(900))
        .await
        .expect("a presigned put");
    let get = store
        .presign_get(&key, Duration::from_secs(900))
        .await
        .expect("a presigned get");

    for url in [&put, &get] {
        assert!(
            url.contains("ws-presign/grp/hash"),
            "names the object: {url}"
        );
        // The signature and its lifetime, both of which are what makes the URL
        // usable by a client holding no credential of ours.
        assert!(url.contains("X-Amz-Signature="), "is signed: {url}");
        assert!(url.contains("X-Amz-Expires=900"), "expires: {url}");
    }
    assert_ne!(
        put, get,
        "the two directions are signed for their own method"
    );

    // The prefix a shared bucket is deployed under reaches the signed key too,
    // or a staging relay would hand out URLs into production's objects.
    let prefixed = S3Store::with_client(
        bucket.client.clone(),
        bucket.name.clone(),
        "staging".to_string(),
    );
    assert!(prefixed
        .presign_put(&key, Duration::from_secs(900))
        .await
        .expect("a prefixed presigned put")
        .contains("staging/ws-presign/grp/hash"));

    bucket.destroy().await;
}

/// A lifetime S3 will not sign is refused as a typed error, in both directions.
///
/// Seven days is the ceiling the signature format itself imposes. The relay only
/// ever asks for fifteen minutes (`PRESIGN_TTL_SECONDS`), so this is a guard on a
/// caller that gets it wrong rather than a path the product takes, and it has to
/// be an error rather than a panic because it is reachable from configuration.
#[tokio::test]
async fn a_lifetime_longer_than_s3_will_sign_is_refused_rather_than_panicking() {
    require_minio();
    let bucket = TestBucket::create("presign-ttl").await;
    let store = S3Store::with_client(bucket.client.clone(), bucket.name.clone(), String::new());
    let key = BlobKey::new("ws-presign", "grp", "hash").expect("key");
    let beyond = Duration::from_secs(8 * 24 * 60 * 60);

    match store.presign_put(&key, beyond).await {
        Err(StorageError::WriteFailed { reason }) => {
            assert!(reason.contains("presigning config"), "{reason}")
        }
        other => panic!("expected a typed refusal, got {other:?}"),
    }
    match store.presign_get(&key, beyond).await {
        Err(StorageError::ReadFailed { reason }) => {
            assert!(reason.contains("presigning config"), "{reason}")
        }
        other => panic!("expected a typed refusal, got {other:?}"),
    }

    bucket.destroy().await;
}

/// A credential source that cannot answer is a typed refusal, in both directions.
///
/// Worth stating why this is the failure being injected rather than an unreachable
/// endpoint, because the obvious test is the wrong one and was written first.
/// Presigning performs no request: it is a signature computed locally, and a
/// backend that never answers produces a perfectly good URL for a bucket that
/// happens to be down. What the operation genuinely needs is a credential, so a
/// provider that fails is the only thing that reaches the error arm.
///
/// It is a real deployment state rather than a contrivance: an instance holding an
/// expired role, or pointed at an instance-metadata endpoint it cannot reach, is
/// exactly this. The relay must answer `BLOB put` with a refusal it can classify
/// instead of panicking inside a request handler.
#[tokio::test]
async fn presigning_without_a_usable_credential_is_a_typed_refusal() {
    #[derive(Debug)]
    struct NoCredentials;
    impl aws_credential_types::provider::ProvideCredentials for NoCredentials {
        fn provide_credentials<'a>(
            &'a self,
        ) -> aws_credential_types::provider::future::ProvideCredentials<'a>
        where
            Self: 'a,
        {
            aws_credential_types::provider::future::ProvideCredentials::ready(Err(
                aws_credential_types::provider::error::CredentialsError::not_loaded(
                    "the harness withheld a credential on purpose",
                ),
            ))
        }
    }

    let loaded = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(MINIO_REGION))
        .endpoint_url(MINIO_ENDPOINT)
        .credentials_provider(NoCredentials)
        .load()
        .await;
    let client = Client::from_conf(
        aws_sdk_s3::config::Builder::from(&loaded)
            .force_path_style(true)
            .build(),
    );
    let store = S3Store::with_client(client, "bucket".to_string(), String::new());
    let key = BlobKey::new("ws", "grp", "hash").expect("key");

    for outcome in [
        store.presign_put(&key, Duration::from_secs(900)).await,
        store.presign_get(&key, Duration::from_secs(900)).await,
    ] {
        match outcome {
            // Retryable, and that is the SDK's classification rather than ours: it
            // reports an unanswerable credential provider as a dispatch failure, so
            // it arrives here as `Unreachable`. Recorded as the expected answer
            // rather than corrected, because it is also the better one. A role
            // mid-refresh and an instance-metadata endpoint that flaps both clear on
            // their own, and the alternative classification would tell a client its
            // upload was malformed, which would be false and which a client would
            // act on by discarding a blob it should have retried.
            Err(error) => assert!(
                error.is_transient(),
                "a credential that cannot be loaded is retryable, got {error:?}"
            ),
            Ok(url) => panic!("expected a refusal without a credential, got {url}"),
        }
    }
}

/// A bucket that opens no upload is refused rather than assembled into nothing.
///
/// `CreateMultipartUpload` answering 200 with no `UploadId` is not something MinIO
/// does; it is what a proxy or a gateway in front of a bucket can do, and without
/// this branch the relay would go on to copy parts into an upload that does not
/// exist and report a finalized object that was never written.
#[tokio::test]
async fn a_bucket_that_opens_no_upload_refuses_the_assembly() {
    let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
        <InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
        <Bucket>bucket</Bucket><Key>ws/grp/whole</Key>\
        </InitiateMultipartUploadResult>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let endpoint = a_server_that_is_not_s3(Some(response.into_bytes())).await;
    let client = client_for(&endpoint, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, false).await;
    let store = S3Store::with_client(client, "bucket".to_string(), String::new());
    let part = BlobKey::new("ws", "grp", "part-1").expect("key");
    let target = BlobKey::new("ws", "grp", "whole").expect("key");

    match store.assemble(&[part], &target).await {
        Err(StorageError::WriteFailed { reason }) => {
            assert!(reason.contains("opened no upload"), "{reason}")
        }
        other => panic!("expected the assembly to refuse, got {other:?}"),
    }
}

/// Assembly fails without leaving a partial object, for a reason that is not a
/// missing part, and for a destination that cannot be renamed onto.
///
/// Filesystem-only, deliberately. Both branches are about `io::Error` kinds that a
/// bucket has no equivalent for, and the contract suite already holds both backends
/// to the missing-part case. What is asserted here is the property that makes
/// `assemble` safe to retry: whatever goes wrong, the temporary file is removed and
/// no half-built object is left where a reader or the collector could find it.
#[tokio::test]
async fn a_failed_assembly_leaves_no_partial_object_behind() {
    let root = tempfile::tempdir().expect("temp dir");
    let store = FilesystemStore::new(root.path());
    let target = BlobKey::new("ws-partial", "grp", "whole").expect("key");

    // A part that is a directory rather than a file. It opens, and then refuses to
    // be read, which is an error that is not `NotFound` and must therefore arrive as
    // a write failure rather than as "that part was never uploaded".
    let unreadable = BlobKey::new("ws-partial", "grp", "part-1").expect("key");
    std::fs::create_dir_all(root.path().join("ws-partial/grp/part-1")).expect("a directory part");
    match storage::BlobStore::assemble(&store, &[unreadable], &target).await {
        Err(StorageError::WriteFailed { .. }) => {}
        other => panic!("expected a write failure for an unreadable part, got {other:?}"),
    }
    assert!(
        no_temporary_survives(&root.path().join("ws-partial/grp")),
        "the half-written object was left behind"
    );

    // And a destination that cannot be renamed onto: a non-empty directory sitting
    // where the finished object belongs. Contrived as a filesystem state, and the
    // shape of a real one: an operator who restored a backup into the blob root.
    let blocked = BlobKey::new("ws-blocked", "grp", "whole").expect("key");
    let part = BlobKey::new("ws-blocked", "grp", "part-1").expect("key");
    storage::BlobStore::put(&store, &part, b"a real part")
        .await
        .expect("a part to assemble");
    std::fs::create_dir_all(root.path().join("ws-blocked/grp/whole/occupied"))
        .expect("an occupied destination");
    match storage::BlobStore::assemble(&store, &[part], &blocked).await {
        Err(StorageError::WriteFailed { .. }) => {}
        other => panic!("expected a write failure for a blocked destination, got {other:?}"),
    }
    assert!(
        no_temporary_survives(&root.path().join("ws-blocked/grp")),
        "the half-written object was left behind"
    );
}

/// Whether the directory holds no `.assembling` or `.partial` leftover.
fn no_temporary_survives(directory: &Path) -> bool {
    std::fs::read_dir(directory)
        .expect("the group directory")
        .filter_map(Result::ok)
        .all(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            !name.ends_with(".assembling") && !name.ends_with(".partial")
        })
}

/// Which step of a multipart assembly the fake bucket refuses at.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FailAt {
    /// The copy never gets an answer: the connection closes under it.
    CopyDispatch,
    /// The copy is answered with something that is not a copy result.
    CopyGarbage,
    /// The completion never gets an answer.
    CompleteDispatch,
    /// The completion is answered with an S3 error.
    CompleteService,
    /// The copy is refused because the part is not there.
    CopyMissing,
    /// The copy succeeds and the part is gone by the time it is measured.
    PartVanishes,
    /// The copy is refused by a gateway that words a missing object differently.
    CopyNotFound,
    /// The copy succeeds and the bucket stops answering before the part can be
    /// measured. The length is what the relay charges the workspace for, so a
    /// measurement that never came back must not be read as a length.
    MeasureDispatch,
}

/// A bucket that answers the assembly sequence and refuses at one named step.
///
/// `a_server_that_is_not_s3` replies the same bytes to everything, which is enough
/// for a single call and not enough here: `assemble` is three different requests in
/// order, and the branches worth proving are the ones where the first two succeed
/// and the third does not. Anything less cannot reach them, because a bucket that
/// fails the first request never reaches the third.
///
/// It answers by looking at the request line, which is exactly how S3 distinguishes
/// these operations: `?uploads` opens, `?partNumber=` copies, `?uploadId=` without
/// a part number completes.
async fn a_bucket_that_fails_at(step: FailAt) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback listener");
    let endpoint = format!("http://{}", listener.local_addr().expect("local address"));
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                let mut scratch = vec![0_u8; 16 * 1024];
                let read = socket.read(&mut scratch).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&scratch[..read]).to_string();
                let line = request.lines().next().unwrap_or_default().to_string();

                let opening = line.contains("?uploads");
                let copying = line.contains("partNumber=");
                let completing = !opening && !copying && line.contains("uploadId=");
                let measuring = line.starts_with("HEAD ");

                // A part that is not there, in the two places `assemble` can find
                // that out: when it copies, and when it measures what it copied.
                if (copying && (step == FailAt::CopyMissing || step == FailAt::CopyNotFound))
                    || (measuring && step == FailAt::PartVanishes)
                {
                    // S3 says NoSuchKey; some compatible gateways say NotFound.
                    // The relay treats both as the same thing, and a test that
                    // only ever sent the first would leave the second untried.
                    let code = if step == FailAt::CopyNotFound {
                        "NotFound"
                    } else {
                        "NoSuchKey"
                    };
                    let body = format!(
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                         <Error><Code>{code}</Code><Message>gone</Message></Error>"
                    );
                    let response = format!(
                        "HTTP/1.1 404 Not Found\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.flush().await;
                    return;
                }
                // The measurement that gets no answer at all, which is the same
                // outage as `CopyDispatch` arriving one request later.
                if measuring && step == FailAt::MeasureDispatch {
                    return;
                }
                // Measuring a part that is still there: a length and nothing else.
                if measuring {
                    let _ = socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5242880\r\n\r\n")
                        .await;
                    let _ = socket.flush().await;
                    return;
                }

                // The refusals that are a silence. Dropping the socket without a
                // reply is what a bucket behind a failing load balancer does, and
                // it is the only way to reach the transient arm of a step that is
                // not the first one.
                if (copying && step == FailAt::CopyDispatch)
                    || (completing && step == FailAt::CompleteDispatch)
                {
                    return;
                }

                let body = if opening {
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                     <Bucket>bucket</Bucket><Key>ws/grp/whole</Key><UploadId>an-upload</UploadId>\
                     </InitiateMultipartUploadResult>"
                        .to_string()
                } else if copying && step == FailAt::CopyGarbage {
                    // A well-formed document that is not a copy result. The SDK
                    // cannot parse an ETag out of it, which is a refusal that is
                    // not a missing part and must therefore be a write failure.
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><NotACopyResult/>".to_string()
                } else if copying {
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <CopyPartResult><ETag>\"an-etag\"</ETag></CopyPartResult>"
                        .to_string()
                } else if completing && step == FailAt::CompleteService {
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <Error><Code>InternalError</Code><Message>injected</Message></Error>"
                        .to_string()
                } else {
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <CompleteMultipartUploadResult><ETag>\"an-etag\"</ETag>\
                     </CompleteMultipartUploadResult>"
                        .to_string()
                };
                let status = if completing && step == FailAt::CompleteService {
                    "500 Internal Server Error"
                } else {
                    "200 OK"
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    endpoint
}

/// Assembly refuses at every step it can, and says which kind of refusal it was.
///
/// The distinction being proven is the one `media::handle` acts on: a transient
/// failure invites the client to try the finalization again, and a terminal one
/// must not, because retrying it forever would leave a client believing its
/// attachment is still on its way up.
#[tokio::test]
async fn an_assembly_that_fails_late_is_classified_by_how_it_failed() {
    let parts = vec![BlobKey::new("ws", "grp", "part-1").expect("key")];
    let target = BlobKey::new("ws", "grp", "whole").expect("key");

    for (step, transient, label) in [
        (FailAt::CopyDispatch, true, "a copy that never answers"),
        (FailAt::CopyGarbage, false, "a copy answered with nonsense"),
        (
            FailAt::CompleteDispatch,
            true,
            "a completion that never answers",
        ),
        (
            FailAt::CompleteService,
            false,
            "a completion the bucket refuses",
        ),
        // Both of these are the caller finalizing an upload it never finished,
        // which `media.md` treats as a refusal rather than an outage: retrying it
        // will not make a part that was never uploaded appear.
        (FailAt::CopyMissing, false, "a part that was never uploaded"),
        (
            FailAt::CopyNotFound,
            false,
            "a gateway wording a missing part as NotFound",
        ),
        (
            FailAt::PartVanishes,
            false,
            "a part that is gone by the time it is measured",
        ),
        (
            FailAt::MeasureDispatch,
            true,
            "a measurement that never answers",
        ),
    ] {
        let endpoint = a_bucket_that_fails_at(step).await;
        let client = client_for(&endpoint, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, false).await;
        let store = S3Store::with_client(client, "bucket".to_string(), String::new());
        match store.assemble(&parts, &target).await {
            Ok(total) => panic!("{label}: expected a refusal, assembled {total} bytes"),
            Err(error) => assert_eq!(
                error.is_transient(),
                transient,
                "{label}: classified wrong, got {error:?}"
            ),
        }
    }
}
