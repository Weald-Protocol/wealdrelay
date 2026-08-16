// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Recovery wraps against real Postgres: the slot, its predecessor, and the sweep.
//!
//! Nothing here is mocked. The database is the harness Postgres from
//! `scripts/weald-stack`, the schema is the migration the binary embeds, and every
//! claim about what the relay can and cannot learn is measured by reading the table
//! back rather than by reading the code that wrote it.
//!
//! The negatives lead, because they are what the mechanism is for:
//!
//! - A replayed wrap cannot restore a dead epoch into a live slot.
//! - A tag cannot appear in two groups, which is the cross-group correlation handle
//!   the blinding exists to refuse. That one is enforced by the schema, so it is
//!   proven by asking the database to break its own rule and watching it refuse.
//! - A prior slot stops answering the moment its window closes, before any sweep
//!   has run, so retention is a promise about availability and not about deletion
//!   timing.

mod support;

use std::sync::Arc;

use sqlx::{PgPool, Row as _};
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::recovery::store::{self, Published, StoreError};
use wealdrelay::recovery::{RecoveryWrap, WrapError, MAX_WRAP_BYTES, PRIOR_RETENTION_DAYS};

use support::{config_for, make_group, Running, Scratch};

async fn prepared(label: &str) -> (Scratch, tempfile::TempDir, Arc<RelayState>) {
    let scratch = Scratch::new(label).await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(1)).await;
    let state = Arc::clone(&relay.state);
    relay.shutdown().await;
    (scratch, blobs, state)
}

fn pool_of(state: &Arc<RelayState>) -> &PgPool {
    state.database.as_ref().expect("a database").pool()
}

fn wrap(group: &[u8], tag: u8, epoch: u64, ct: &[u8]) -> RecoveryWrap {
    RecoveryWrap {
        group: group.to_vec(),
        epoch,
        tag: vec![tag; 32],
        ct: ct.to_vec(),
    }
}

#[tokio::test]
async fn a_replayed_wrap_cannot_put_a_dead_epoch_back_into_a_live_slot() {
    let (scratch, _blobs, state) = prepared("recovery_replay").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x41).await;

    let old = wrap(&group, 0xA1, 4, b"epoch four");
    assert_eq!(
        store::publish(pool, &old).await.expect("first publish"),
        Published::Created
    );
    let new = wrap(&group, 0xA1, 5, b"epoch five");
    assert_eq!(
        store::publish(pool, &new).await.expect("replacement"),
        Published::Replaced { superseded: 4 }
    );

    // The replay. Byte for byte what a member legitimately published one epoch
    // ago, which is the realistic shape of this attack: the wrap was public, the
    // relay stored it, and anyone who saw it can offer it again.
    let refused = store::publish(pool, &old).await;
    assert!(
        matches!(
            refused,
            Err(StoreError::Refused(WrapError::NotNewer {
                stored: 5,
                offered: 4
            }))
        ),
        "a replay was accepted: {refused:?}"
    );
    // Same epoch, different ciphertext, is refused by the same rule. Without this
    // arm an attacker who could not roll the epoch back could still overwrite the
    // current slot with a value nobody can open.
    let sideways = wrap(&group, 0xA1, 5, b"not the real wrap");
    assert!(matches!(
        store::publish(pool, &sideways).await,
        Err(StoreError::Refused(WrapError::NotNewer { .. }))
    ));

    let current = store::current(pool, &group, &[0xA1; 32])
        .await
        .expect("read")
        .expect("a wrap");
    assert_eq!(current.epoch, 5);
    assert_eq!(current.ct, b"epoch five".to_vec());
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_refused_wrap_leaves_both_slots_exactly_as_it_found_them() {
    let (scratch, _blobs, state) = prepared("recovery_refused_no_write").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x51).await;
    let tag = vec![0xB2; 32];

    store::publish(pool, &wrap(&group, 0xB2, 2, b"two"))
        .await
        .expect("create");
    store::publish(pool, &wrap(&group, 0xB2, 3, b"three"))
        .await
        .expect("replace");

    // The refusal has to be a whole refusal. `publish` writes the superseded value
    // into the prior slot before it overwrites the current one, so a refused
    // replacement that had already reached that write would move the prior slot
    // without moving the current one, and a recovery reading the overlap window
    // would be handed a wrap it cannot open. Nothing here asserts the refusal
    // itself; the two tests above do that. This asserts that neither table moved.
    let refused = store::publish(pool, &wrap(&group, 0xB2, 3, b"sideways")).await;
    assert!(matches!(refused, Err(StoreError::Refused(_))));
    let older = store::publish(pool, &wrap(&group, 0xB2, 1, b"one")).await;
    assert!(matches!(older, Err(StoreError::Refused(_))));

    let current = store::current(pool, &group, &tag)
        .await
        .expect("read")
        .expect("a wrap");
    assert_eq!(current.epoch, 3);
    assert_eq!(current.ct, b"three".to_vec());
    let prior = store::prior(pool, &group, &tag)
        .await
        .expect("read prior")
        .expect("the superseded wrap");
    assert_eq!(prior.epoch, 2, "a refused publish moved the prior slot");
    assert_eq!(prior.ct, b"two".to_vec());
    let count: i64 = sqlx::query_scalar("select count(*) from relay_recovery_wrap_prior")
        .fetch_one(pool)
        .await
        .expect("count");
    assert_eq!(count, 1, "a refused publish added a prior row");
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_tag_cannot_be_shared_by_two_groups() {
    let (scratch, _blobs, state) = prepared("recovery_cross_group").await;
    let pool = pool_of(&state);
    let first = make_group(&state, 0x51).await;
    let second = make_group(&state, 0x52).await;

    store::publish(pool, &wrap(&first, 0xB2, 1, b"one"))
        .await
        .expect("first group");

    // The same tag in a second group is the one row that would make the relay's
    // wrap table a membership graph: the tag would be a value common to two
    // groups, and joining on it would say those groups share a person. The schema
    // refuses it, so the refusal survives any code path that forgets to check.
    let refused = store::publish(pool, &wrap(&second, 0xB2, 1, b"two")).await;
    assert!(
        matches!(refused, Err(StoreError::Database(_))),
        "a tag was shared across two groups: {refused:?}"
    );

    // And the refusal is the constraint's, not a coincidence of ordering: the
    // second group can hold its own distinct tag perfectly well.
    store::publish(pool, &wrap(&second, 0xB3, 1, b"two"))
        .await
        .expect("a distinct tag in the second group");

    let rows = sqlx::query("select encode(tag,'hex') as tag, count(distinct group_id) as groups from relay_recovery_wrap group by tag")
        .fetch_all(pool)
        .await
        .expect("read every wrap");
    for row in rows {
        let groups: i64 = row.get("groups");
        let tag: String = row.get("tag");
        assert_eq!(groups, 1, "tag {tag} appears in more than one group");
    }
    scratch.drop_database().await;
}

#[tokio::test]
async fn the_superseded_slot_survives_its_replacement_and_then_stops_answering() {
    let (scratch, _blobs, state) = prepared("recovery_prior").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x61).await;
    let tag = vec![0xC4; 32];

    store::publish(pool, &wrap(&group, 0xC4, 7, b"seven"))
        .await
        .expect("create");
    assert_eq!(
        store::prior(pool, &group, &tag).await.expect("read prior"),
        None,
        "a slot with no history has no prior"
    );

    store::publish(pool, &wrap(&group, 0xC4, 8, b"eight"))
        .await
        .expect("replace");
    let prior = store::prior(pool, &group, &tag)
        .await
        .expect("read prior")
        .expect("the superseded wrap");
    assert_eq!(prior.epoch, 7);
    assert_eq!(prior.ct, b"seven".to_vec());

    // The window, read off the row rather than assumed: the retention promise is a
    // number in `groups.md` and a row that expired a day early would break a
    // recovery that arrived on day 29.
    let days: f64 = sqlx::query_scalar(
        "select (extract(epoch from (expires_at - superseded_at)) / 86400)::float8 \
         from relay_recovery_wrap_prior where group_id = $1 and tag = $2",
    )
    .bind(&group)
    .bind(&tag)
    .fetch_one(pool)
    .await
    .expect("read the window");
    assert!(
        (days - PRIOR_RETENTION_DAYS as f64).abs() < 0.01,
        "the prior slot is retained for {days} days, not {PRIOR_RETENTION_DAYS}"
    );

    // Age it past the window. A reader must stop serving it immediately, before
    // any sweep has run, or the sweep's schedule becomes observable as the real
    // retention period.
    sqlx::query("update relay_recovery_wrap_prior set expires_at = now() - interval '1 second' where group_id = $1 and tag = $2")
        .bind(&group)
        .bind(&tag)
        .execute(pool)
        .await
        .expect("age the prior slot");
    assert_eq!(
        store::prior(pool, &group, &tag).await.expect("read prior"),
        None,
        "an expired prior slot was served"
    );

    assert_eq!(store::sweep_prior(pool).await.expect("sweep"), 1);
    assert_eq!(
        store::sweep_prior(pool).await.expect("sweep again"),
        0,
        "the sweep is idempotent"
    );
    // The current slot is untouched by the sweep, which is the whole point of the
    // two tables.
    assert_eq!(
        store::current(pool, &group, &tag)
            .await
            .expect("read")
            .expect("a wrap")
            .epoch,
        8
    );
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_third_wrap_replaces_the_prior_slot_rather_than_accumulating() {
    let (scratch, _blobs, state) = prepared("recovery_prior_replaced").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x71).await;
    let tag = vec![0xD5; 32];

    for (epoch, ct) in [(1u64, b"one".as_slice()), (2, b"two"), (3, b"three")] {
        store::publish(pool, &wrap(&group, 0xD5, epoch, ct))
            .await
            .expect("publish");
    }

    // One prior, not two. The overlap `groups.md` promises is one slot deep: a
    // table that accumulated every past wrap would be a growing archive of
    // ciphertext the relay has no reason to keep, and would widen the window a
    // stolen recovery key can reach back through.
    let count: i64 = sqlx::query_scalar("select count(*) from relay_recovery_wrap_prior")
        .fetch_one(pool)
        .await
        .expect("count");
    assert_eq!(count, 1);
    let prior = store::prior(pool, &group, &tag)
        .await
        .expect("read")
        .expect("a prior");
    assert_eq!(
        prior.epoch, 2,
        "the prior slot holds the wrap just replaced"
    );
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_group_reads_back_every_slot_it_holds_and_nothing_from_another_group() {
    let (scratch, _blobs, state) = prepared("recovery_for_group").await;
    let pool = pool_of(&state);
    let first = make_group(&state, 0x81).await;
    let second = make_group(&state, 0x82).await;

    for tag in [0xE1u8, 0xE2, 0xE3] {
        store::publish(pool, &wrap(&first, tag, 1, b"first"))
            .await
            .expect("publish");
    }
    store::publish(pool, &wrap(&second, 0xE9, 1, b"second"))
        .await
        .expect("publish");

    let held = store::for_group(pool, &first).await.expect("read");
    assert_eq!(held.len(), 3);
    assert_eq!(
        held.iter().map(|w| w.tag[0]).collect::<Vec<_>>(),
        vec![0xE1, 0xE2, 0xE3],
        "slots come back in tag order"
    );
    assert!(held.iter().all(|w| w.group == first));
    assert_eq!(
        store::for_group(pool, &second).await.expect("read").len(),
        1
    );

    // An empty slot answers empty rather than erroring: a group with no recovery
    // principal entitled to it is ordinary, not a fault.
    assert!(store::for_group(pool, &[0x99; 32])
        .await
        .expect("read")
        .is_empty());
    assert_eq!(
        store::current(pool, &first, &[0x00; 32])
            .await
            .expect("read"),
        None
    );
    scratch.drop_database().await;
}

#[tokio::test]
async fn removal_forgets_both_slots_and_forgetting_nothing_is_not_an_error() {
    let (scratch, _blobs, state) = prepared("recovery_forget").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0x91).await;

    store::publish(pool, &wrap(&group, 0xF1, 1, b"one"))
        .await
        .expect("publish");
    store::publish(pool, &wrap(&group, 0xF1, 2, b"two"))
        .await
        .expect("replace");
    store::publish(pool, &wrap(&group, 0xF2, 1, b"other"))
        .await
        .expect("publish");

    // lifecycle.md step 4: removing a person deletes every wrap sealed to their
    // recovery key. Both slots go, because a prior slot left behind would keep
    // answering for the length of the retention window, which is a removed member
    // holding read access for thirty days.
    assert_eq!(
        store::forget(pool, &group, &[vec![0xF1; 32]])
            .await
            .expect("forget"),
        2,
        "the current and prior slots both went"
    );
    assert_eq!(
        store::current(pool, &group, &[0xF1; 32])
            .await
            .expect("read"),
        None
    );
    assert_eq!(
        store::prior(pool, &group, &[0xF1; 32]).await.expect("read"),
        None
    );
    // The other principal's slot is untouched.
    assert!(store::current(pool, &group, &[0xF2; 32])
        .await
        .expect("read")
        .is_some());

    assert_eq!(store::forget(pool, &group, &[]).await.expect("nothing"), 0);
    assert_eq!(
        store::forget(pool, &group, &[vec![0x01; 32]])
            .await
            .expect("unknown tag"),
        0
    );
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_malformed_wrap_never_reaches_the_table() {
    let (scratch, _blobs, state) = prepared("recovery_malformed").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0xA9).await;

    let mut narrow = wrap(&group, 0x11, 1, b"ct");
    narrow.tag = vec![0x11; 31];
    assert!(matches!(
        store::publish(pool, &narrow).await,
        Err(StoreError::Refused(WrapError::TagWidth(31)))
    ));

    let mut empty = wrap(&group, 0x12, 1, b"ct");
    empty.ct = Vec::new();
    assert!(matches!(
        store::publish(pool, &empty).await,
        Err(StoreError::Refused(WrapError::Empty))
    ));

    let mut huge = wrap(&group, 0x13, 1, b"ct");
    huge.ct = vec![0; MAX_WRAP_BYTES + 1];
    assert!(matches!(
        store::publish(pool, &huge).await,
        Err(StoreError::Refused(WrapError::TooLarge(_)))
    ));

    let mut wrong_group = wrap(&group, 0x14, 1, b"ct");
    wrong_group.group = vec![0x00; 31];
    assert!(matches!(
        store::publish(pool, &wrong_group).await,
        Err(StoreError::Refused(WrapError::GroupWidth(31)))
    ));

    // A wrap for a group the relay has never carried traffic for. The relay does
    // not learn that a group exists from a wrap, so this is a database refusal and
    // not an insert.
    let unknown = wrap(&[0xBB; 32], 0x15, 1, b"ct");
    assert!(matches!(
        store::publish(pool, &unknown).await,
        Err(StoreError::Database(_))
    ));

    // An epoch past what Postgres can hold. Refused before the bind rather than
    // panicking on the cast.
    let overflow = wrap(&group, 0x16, u64::MAX, b"ct");
    assert!(matches!(
        store::publish(pool, &overflow).await,
        Err(StoreError::Database(_))
    ));

    let count: i64 = sqlx::query_scalar("select count(*) from relay_recovery_wrap")
        .fetch_one(pool)
        .await
        .expect("count");
    assert_eq!(count, 0, "a refused wrap reached the table");
    scratch.drop_database().await;
}

#[tokio::test]
async fn two_publishers_racing_one_slot_leave_it_holding_the_newer_epoch() {
    let (scratch, _blobs, state) = prepared("recovery_race").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0xB9).await;
    store::publish(pool, &wrap(&group, 0x21, 1, b"one"))
        .await
        .expect("seed");

    // Both committers read epoch 1 and both decide to publish. Only one may win,
    // and the loser must be told the same thing a replay is told rather than
    // quietly overwriting the winner.
    let first = wrap(&group, 0x21, 2, b"two");
    let second = wrap(&group, 0x21, 2, b"also two");
    let (a, b) = tokio::join!(store::publish(pool, &first), store::publish(pool, &second));
    let winners = [&a, &b].iter().filter(|r| r.is_ok()).count();
    assert_eq!(winners, 1, "both publishers won: {a:?} {b:?}");
    let loser = if a.is_err() { a } else { b };
    assert!(matches!(
        loser,
        Err(StoreError::Refused(WrapError::NotNewer { .. }))
    ));

    let current = store::current(pool, &group, &[0x21; 32])
        .await
        .expect("read")
        .expect("a wrap");
    assert_eq!(current.epoch, 2);
    // Exactly one prior, holding the value that really was current before.
    let prior = store::prior(pool, &group, &[0x21; 32])
        .await
        .expect("read")
        .expect("a prior");
    assert_eq!(prior.epoch, 1);
    assert_eq!(prior.ct, b"one".to_vec());
    scratch.drop_database().await;
}

#[tokio::test]
async fn the_store_error_says_which_half_failed_and_carries_no_secret() {
    let (scratch, _blobs, state) = prepared("recovery_errors").await;
    let pool = pool_of(&state);
    let group = make_group(&state, 0xC9).await;
    store::publish(pool, &wrap(&group, 0x31, 9, b"nine"))
        .await
        .expect("seed");

    let refusal = store::publish(pool, &wrap(&group, 0x31, 8, b"eight"))
        .await
        .expect_err("a refusal");
    let message = refusal.to_string();
    assert!(message.contains("does not advance"), "{message}");
    assert!(
        !message.contains("nine"),
        "the error quoted ciphertext: {message}"
    );
    assert!(format!("{refusal:?}").contains("NotNewer"));

    let database = store::publish(pool, &wrap(&[0xCC; 32], 0x32, 1, b"ct"))
        .await
        .expect_err("a database refusal");
    assert!(
        database.to_string().starts_with("recovery wrap store:"),
        "{database}"
    );
    scratch.drop_database().await;
}
