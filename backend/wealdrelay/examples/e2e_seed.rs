// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Seed one workspace and one group so a foreign client can be admitted.
//!
//! A development helper for `scripts/android-call-e2e.sh` and nothing else. The
//! Android harness drives a relay in a separate operating-system process, so
//! there is no `RelayState` to reach through the way `tests/support` does, and
//! the two things a call needs before any socket opens are a published genesis
//! access set naming the harness devices and a `relay_group` row that ties the
//! call's group id to that workspace. Both are exactly what an enrolment would
//! write, published through `access::store::publish` rather than inserted, so
//! the same judgement a real publication gets is the judgement this gets.
//!
//!     cargo run -p wealdrelay --example e2e_seed -- \
//!       --database-url postgres://... --workspace ws-call-e2e \
//!       --group <64 hex> --seed <64 hex> --seed <64 hex>
//!
//! Idempotent on the group row, because the script drops and recreates the
//! database on every run but a rerun against a live one must not fail on a
//! duplicate key.

use ed25519_dalek::{Signer, SigningKey};
use sqlx::postgres::PgPoolOptions;
use wealdrelay::access::AccessSet;

fn hex32(text: &str, what: &str) -> [u8; 32] {
    let bytes = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .unwrap_or_else(|_| panic!("{what} is hexadecimal"));
    <[u8; 32]>::try_from(bytes.as_slice()).unwrap_or_else(|_| panic!("{what} is 32 bytes"))
}

#[tokio::main]
async fn main() {
    let mut database_url: Option<String> = None;
    let mut workspace: Option<String> = None;
    let mut group: Option<[u8; 32]> = None;
    let mut seeds: Vec<SigningKey> = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        let mut value = || args.next().expect("that flag takes a value");
        match argument.as_str() {
            "--database-url" => database_url = Some(value()),
            "--workspace" => workspace = Some(value()),
            "--group" => group = Some(hex32(&value(), "a group id")),
            "--seed" => seeds.push(SigningKey::from_bytes(&hex32(&value(), "a device seed"))),
            other => panic!("unknown argument {other}"),
        }
    }

    let database_url = database_url.expect("--database-url");
    let workspace = workspace.expect("--workspace");
    let group = group.expect("--group");
    assert!(!seeds.is_empty(), "at least one --seed");

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("the harness database is reachable");

    // The genesis set, published exactly as `tests/support::seed_access_set_directly`
    // does. The first device signs it, because a genesis set has no prior
    // authorizers and its own signer is what bootstraps authority.
    let salt = wealdrelay::access::store::salt(&pool, &workspace)
        .await
        .expect("a workspace salt");
    let signer = seeds.first().expect("at least one device").clone();
    let mut entries: Vec<Vec<u8>> = seeds
        .iter()
        .map(|device| wealdrelay::access::entry_hash(&device.verifying_key().to_bytes(), &salt))
        .collect();
    // The recovery principal every set must have. The same fixed key the Rust
    // suites use, because nothing here ever recovers anything and a set with an
    // empty recovery list is refused by `wire.md`.
    let recovery = SigningKey::from_bytes(&[0x3f; 32]);
    entries.push(wealdrelay::access::entry_hash(
        &recovery.verifying_key().to_bytes(),
        &salt,
    ));
    entries.sort();
    entries.dedup();

    let mut set = AccessSet {
        workspace: vec![0u8; 32],
        version: 0,
        prev_hash: vec![0u8; 32],
        issued_at: 0,
        entries,
        authorizers: vec![signer.verifying_key().to_bytes().to_vec()],
        recovery: vec![recovery.verifying_key().to_bytes().to_vec()],
        quorum: None,
        pending: Vec::new(),
        signer: signer.verifying_key().to_bytes().to_vec(),
        sig: vec![0u8; 64],
    };
    set.sig = Signer::sign(&signer, &set.digest_input())
        .to_bytes()
        .to_vec();
    let body = set.encode();
    if wealdrelay::access::store::current(&pool, &workspace)
        .await
        .expect("read the current access set")
        .prior
        .is_none()
    {
        wealdrelay::access::store::publish(&pool, &workspace, &set, &body)
            .await
            .expect("the genesis access set is accepted");
    }

    sqlx::query(
        "insert into relay_group (group_id, workspace_id) values ($1, $2) \
         on conflict (group_id) do nothing",
    )
    .bind(group.to_vec())
    .bind(&workspace)
    .execute(&pool)
    .await
    .expect("create the group");

    println!("seeded");
}
