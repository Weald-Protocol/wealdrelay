// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `WRAP` over a real socket: what the relay accepts, refuses, and learns.
//!
//! Step 8's proof that recovery wraps reach the relay by a path that works when the
//! encryption claim is true. The pure rules are in `src/recovery`, the transaction
//! is `tests/recovery_store.rs`; what only a relay can prove is here.
//!
//! Three things a socket can show and a store cannot:
//!
//! - A replayed wrap is answered `denied/wrap_not_newer` on the wire, not merely
//!   refused inside a function.
//! - A device outside the group's access set cannot write into that group's wrap
//!   table, so the blinded slots are not a public bulletin board.
//! - After a full exchange, the relay's own tables hold ciphertext and opaque tags
//!   and nothing that names a person. That is asserted by reading the database
//!   back, which is the same instrument `prove-blind` uses at a larger scale.

mod support;

use sqlx::Row as _;
use wealdrelay::frame::{ErrorCode, Frame};
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::recovery::RecoveryWrap;

use support::{config_for, make_group, Client, Running, Scratch};
use wealdrelay::config::{keys, Config, Values};

const CLOCK: u64 = 1_700_000_000_000;

fn wrap(group: &[u8], tag: u8, epoch: u64, ct: &[u8]) -> RecoveryWrap {
    RecoveryWrap {
        group: group.to_vec(),
        epoch,
        tag: vec![tag; 32],
        ct: ct.to_vec(),
    }
}

async fn tag_rows(state: &std::sync::Arc<RelayState>) -> Vec<(Vec<u8>, Vec<u8>, i64)> {
    sqlx::query("select group_id, tag, epoch from relay_recovery_wrap order by group_id, tag")
        .fetch_all(state.database.as_ref().expect("a database").pool())
        .await
        .expect("read the wrap table")
        .into_iter()
        .map(|row| {
            (
                row.get::<Vec<u8>, _>("group_id"),
                row.get::<Vec<u8>, _>("tag"),
                row.get::<i64, _>("epoch"),
            )
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrap_is_stored_under_its_tag_and_a_replay_is_denied_on_the_wire() {
    let scratch = Scratch::new("wrap_socket").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x31).await;

    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], CLOCK).await;

    let first = wrap(&group, 0x77, 3, b"sealed to a recovery key");
    client
        .send_frame(&Frame::Wrap {
            body: first.encode(),
        })
        .await;
    match client.recv_frame().await {
        // The acknowledgement is the tag and not the ciphertext. A relay that
        // echoed `ct` back would be repeating a value it has no reason to hold in
        // two places.
        Frame::Wrap { body } => assert_eq!(body, first.tag),
        other => panic!("expected a Wrap answer, got {other:?}"),
    }

    let second = wrap(&group, 0x77, 4, b"the next epoch");
    client
        .send_frame(&Frame::Wrap {
            body: second.encode(),
        })
        .await;
    assert!(matches!(client.recv_frame().await, Frame::Wrap { .. }));

    // The replay, over the wire, with the exact bytes that were accepted a moment
    // ago. This is the negative the whole slot rule exists for.
    client
        .send_frame(&Frame::Wrap {
            body: first.encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WrapNotNewer),
        other => panic!("expected wrap_not_newer, got {other:?}"),
    }
    // Denied, not fatal: the session stays open, because a client that offered a
    // stale wrap is behind rather than broken, and its next act is to derive the
    // current one.
    client
        .send_frame(&Frame::Wrap {
            body: wrap(&group, 0x77, 5, b"caught up").encode(),
        })
        .await;
    assert!(matches!(client.recv_frame().await, Frame::Wrap { .. }));

    let rows = tag_rows(&relay.state).await;
    assert_eq!(rows.len(), 1, "one slot, whatever the traffic");
    assert_eq!(rows[0].2, 5);

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_wrap_is_refused_before_it_reaches_the_table() {
    let scratch = Scratch::new("wrap_malformed").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x41).await;

    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], CLOCK).await;

    client.send_frame(&Frame::Wrap { body: vec![0xff] }).await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::MalformedHeader),
        other => panic!("expected malformed_header, got {other:?}"),
    }

    let mut narrow = wrap(&group, 0x11, 1, b"ct");
    narrow.tag = vec![0x11; 8];
    client
        .send_frame(&Frame::Wrap {
            body: narrow.encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::MalformedHeader),
        other => panic!("expected malformed_header, got {other:?}"),
    }

    // An oversized wrap is answered as a size problem rather than as a shape
    // problem, because those are different defects and a client fixes them
    // differently.
    let mut huge = wrap(&group, 0x12, 1, b"ct");
    huge.ct = vec![0; wealdrelay::recovery::MAX_WRAP_BYTES + 1];
    client
        .send_frame(&Frame::Wrap {
            body: huge.encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::EnvelopeTooLarge),
        other => panic!("expected envelope_too_large, got {other:?}"),
    }

    assert!(tag_rows(&relay.state).await.is_empty());
    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_outside_the_group_cannot_write_into_its_wrap_table() {
    let scratch = Scratch::new("wrap_stranger").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x51).await;

    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], CLOCK).await;

    // A group in a workspace this session did not authenticate against. The wrap
    // is perfectly well formed; the writer simply has no business in that group,
    // and the relay's answer is the same one a `RECON` for it would get.
    let elsewhere = vec![0xEE; 32];
    client
        .send_frame(&Frame::Wrap {
            body: wrap(&elsewhere, 0x99, 1, b"ct").encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert!(
            matches!(
                error.code,
                ErrorCode::GroupUnknown | ErrorCode::WriterNotInAccessSet
            ),
            "expected a denial, got {:?}",
            error.code
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(tag_rows(&relay.state).await.is_empty());

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn what_the_relay_holds_after_two_groups_have_published_is_slots_and_ciphertext() {
    let scratch = Scratch::new("wrap_blind").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let first = make_group(&relay.state, 0x61).await;
    let second = make_group(&relay.state, 0x62).await;

    let mut client = Client::connect(relay.address).await;
    client
        .handshake(vec![first.clone(), second.clone()], CLOCK)
        .await;

    // One person, entitled to both groups. In the clear-indexed design this
    // replaces, both rows would have carried that person's recovery public key and
    // a join on it would have said "these two groups share a member". Here the two
    // tags are derived from two different epoch secrets, so they are unrelated
    // values and the join returns nothing.
    for (group, tag) in [(&first, 0xA0u8), (&second, 0xB0)] {
        client
            .send_frame(&Frame::Wrap {
                body: wrap(group, tag, 1, b"sealed to one person's recovery key").encode(),
            })
            .await;
        assert!(matches!(client.recv_frame().await, Frame::Wrap { .. }));
    }

    let rows = tag_rows(&relay.state).await;
    assert_eq!(rows.len(), 2);
    let tags: Vec<&Vec<u8>> = rows.iter().map(|(_, tag, _)| tag).collect();
    assert_ne!(tags[0], tags[1], "the same value indexed both groups");

    // The cross-group join, run as a query rather than asserted in prose. This is
    // the same measurement `scripts/prove-blind.py` makes over the whole database.
    let shared: i64 = sqlx::query_scalar(
        "select count(*) from (select tag from relay_recovery_wrap \
         group by tag having count(distinct group_id) > 1) as shared",
    )
    .fetch_one(relay.state.database.as_ref().expect("a database").pool())
    .await
    .expect("join the wrap table against itself");
    assert_eq!(shared, 0, "a tag correlates two groups");

    // And the relay knows nothing else. The table has four columns and none of
    // them is a key, a name or an address, which is checked against the catalogue
    // rather than against the migration file, so a column added later is caught.
    let columns: Vec<String> = sqlx::query_scalar(
        "select column_name from information_schema.columns \
         where table_schema='public' and table_name='relay_recovery_wrap' order by column_name",
    )
    .fetch_all(relay.state.database.as_ref().expect("a database").pool())
    .await
    .expect("read the catalogue");
    assert_eq!(
        columns,
        vec!["ct", "epoch", "group_id", "tag", "updated_at"],
        "the wrap table grew a column"
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrap_before_authentication_is_a_wrong_state_frame() {
    let scratch = Scratch::new("wrap_early").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x71).await;

    // Connected, not authenticated. A wrap here is a client that is wrong about
    // the protocol, and the session ends on it exactly as any other wrong-state
    // frame does.
    let mut client = Client::connect(relay.address).await;
    client
        .send_frame(&Frame::Connect {
            version: wealdrelay::frame::PROTOCOL_VERSION,
            groups: vec![group.clone()],
            sent_at: CLOCK,
        })
        .await;
    let _ = client.recv_frame().await;
    let _ = client.recv_frame().await;
    client
        .send_frame(&Frame::Wrap {
            body: wrap(&group, 0x01, 1, b"ct").encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::MalformedHeader),
        other => panic!("expected malformed_header, got {other:?}"),
    }
    assert!(
        client.recv().await.is_none(),
        "a frame the state does not accept must end the session"
    );

    assert!(tag_rows(&relay.state).await.is_empty());
    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_that_cannot_write_the_wrap_tells_the_client_to_retry() {
    let scratch = Scratch::new("wrap_backpressure").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0x91).await;

    // A database that answers everything except this write. The client is mid
    // publication and the correct answer is `retry/backpressure` with the socket
    // still open: the wrap is fine, the relay is not, and a `reject` here would
    // make a correct client discard a wrap that has to exist for its epoch.
    let pool = relay.state.database.as_ref().expect("a database").pool();
    sqlx::query(
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected'; end $$",
    )
    .execute(pool)
    .await
    .expect("the injected function lands");
    sqlx::query(
        "create trigger weald_injected_insert before insert on relay_recovery_wrap \
         for each statement execute function weald_injected_refusal()",
    )
    .execute(pool)
    .await
    .expect("the injected trigger lands");

    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], CLOCK).await;
    client
        .send_frame(&Frame::Wrap {
            body: wrap(&group, 0x51, 1, b"ct").encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => {
            assert_eq!(error.code, ErrorCode::Backpressure);
            assert_eq!(error.code.qualified(), "retry/backpressure");
        }
        other => panic!("expected backpressure, got {other:?}"),
    }

    // The socket is still usable, which is the difference between retry and
    // reject: the client waits and resends the same bytes.
    sqlx::query("drop trigger weald_injected_insert on relay_recovery_wrap")
        .execute(pool)
        .await
        .expect("stop refusing");
    client
        .send_frame(&Frame::Wrap {
            body: wrap(&group, 0x51, 1, b"ct").encode(),
        })
        .await;
    assert!(matches!(client.recv_frame().await, Frame::Wrap { .. }));

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_with_no_workspace_claim_may_not_reach_a_group_at_all() {
    // `WEALD_RELAY_ACCESS_SET=off` is the one ci diagnostic mode where a device is
    // admitted without a workspace being established, and `environments.md` allows
    // it so that `/readyz` can report the difference. A session in that state
    // carries no workspace, so no group can be shown to belong to it, and every
    // group-addressed frame is refused rather than admitted by default. Without
    // this test that arm is unreachable code nobody has run.
    let scratch = Scratch::new("wrap_no_workspace").await;
    let blobs = tempfile::tempdir().unwrap();
    let config = Config::resolve(&Values::from_pairs([
        (keys::HOSTNAME, "localhost".to_string()),
        (keys::DATABASE_URL, scratch.url.clone()),
        (
            keys::STORAGE_URL,
            format!("file://{}", blobs.path().display()),
        ),
        (keys::LISTEN, "127.0.0.1:0".to_string()),
        (keys::OBSERVABILITY_LISTEN, "127.0.0.1:0".to_string()),
        (keys::RELEASE_CHECK, "off".to_string()),
        (keys::ACCESS_SET, "off".to_string()),
    ]))
    .expect("the access-set-off configuration resolves");
    let relay = Running::start(config, Clock::Fixed(CLOCK)).await;
    let group = make_group(&relay.state, 0xA1).await;

    let mut client = Client::connect(relay.address).await;
    client.handshake(vec![group.clone()], CLOCK).await;
    client
        .send_frame(&Frame::Wrap {
            body: wrap(&group, 0x61, 1, b"ct").encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("expected writer_not_in_access_set, got {other:?}"),
    }
    assert!(tag_rows(&relay.state).await.is_empty());

    relay.shutdown().await;
    scratch.drop_database().await;
}
