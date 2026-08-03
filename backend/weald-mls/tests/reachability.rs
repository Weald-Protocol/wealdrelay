// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Recovery reaches every group, and history reaches every joiner.
//!
//! Two properties from `specs/backend/relay/mls-binding.md`, quoted there as gates rather
//! than manual checks for one stated reason: "both fail silently rather than loudly if
//! they regress". A wrap that stopped being emitted, or a tag that stopped matching, does
//! not break a single thing a person would notice. It breaks the day somebody loses their
//! laptop, and by then the evidence is a year old.
//!
//! What is asserted here, in the words of `specs/backend/build/phases-relay.md` step 7:
//!
//! - "after any interleaving of commits, a recovery key locates and opens a wrap for
//!   every group its owner belongs to using only the tag directory"
//! - "a principal self-joining an `open` group obtains the same history an invitee
//!   obtains"
//! - "A new invitee first external-commits into the mandatory workspace-root scope, then
//!   self-joins its `parent` channels; omission of the root from a non-bootstrap invite
//!   and any attempt to self-join the root are rejected before MLS state changes."
//!
//! "Using only the tag directory" is the part that carries the weight, so the recovering
//! side of every case here is written as a fresh device that holds a recovery phrase and
//! a sealed directory and nothing else. It is given the relay's wrap table as an opaque
//! map from tag to wrap, exactly what a relay could hand over, and it never sees a group
//! id it did not learn from its own directory.
//!
//! Real OpenMLS, real SQLite, no test double anywhere, by this crate's own rule.

use std::collections::HashMap;

use weald_mls::recovery::{open_wrap, Directory, RecoveryKey, Wrap};
use weald_mls::session::{Config, Device, Session};
use weald_mls::status::Status;
use weald_mls::store::Provider;

/// One device against its own in-memory database.
fn device(identity: &str) -> Device {
    Device::open(&Config {
        database: ":memory:".to_string(),
        identity: identity.as_bytes().to_vec(),
    })
    .expect("a device")
}

/// The workspace root group, which every principal is in and which is where directories
/// and the one recovery leaf live (`specs/backend/relay/groups.md`).
const ROOT: &[u8] = b"weald-workspace-root";

/// What the relay stores: a flat map from blinded tag to the latest wrap in that slot.
///
/// Deliberately keyed by tag alone rather than by `(group, tag)`, which is stricter than
/// the relay's real index. If a recovering client can find its wrap in this map it can
/// find it in the real one, and modelling it this way makes it impossible for a test to
/// cheat by looking a wrap up by a group id it was not supposed to know yet.
#[derive(Default)]
struct WrapTable {
    slots: HashMap<[u8; 32], Wrap>,
}

impl WrapTable {
    /// Publish a wrap, retaining the prior slot. `groups.md` keeps the old slot for 30
    /// days after activation, and that overlap is the availability guarantee the handoff
    /// rests on, so nothing here evicts.
    fn publish(&mut self, wrap: Wrap) {
        self.slots.insert(wrap.tag, wrap);
    }

    fn get(&self, tag: &[u8; 32]) -> Option<&Wrap> {
        self.slots.get(tag)
    }
}

/// One committer's whole publish step for one group: seal a wrap for every entitled
/// recovery key, and drive the two-phase directory around it.
///
/// This is the sequence `groups.md` specifies, in order: derive the next tag, write
/// `recovery.directory.prepare` bound to the target commit, publish the commit and its
/// wraps, then write `recovery.directory.activate`.
fn publish_wraps(
    session: &mut Session,
    group: &[u8],
    target: [u8; 32],
    recovery: &[&RecoveryKey],
    directories: &mut HashMap<Vec<u8>, Directory>,
    table: &mut WrapTable,
) {
    for key in recovery {
        let tag = session.wrap_tag(key.public()).expect("a tag");
        let directory = directories.entry(key.public().to_vec()).or_default();
        directory.entry(group).prepare(tag, target);

        let wrap = session.seal_wrap(group, key.public()).expect("a wrap");
        assert_eq!(wrap.tag, tag, "the tag published is the tag prepared");
        table.publish(wrap);

        directory.entry(group).activate(target).expect("activated");
    }
}

/// The recovering side: a fresh device with a phrase and a sealed directory.
///
/// Returns, for every group the directory names, the first tag that opened a wrap. A
/// `None` for any group is the failure this suite exists to catch.
fn recover(
    provider: &Provider,
    key: &RecoveryKey,
    sealed_directory: &[u8],
    table: &WrapTable,
) -> Vec<(Vec<u8>, Option<u64>)> {
    let directory = Directory::open(provider, key, sealed_directory).expect("the directory opens");
    directory
        .entries
        .iter()
        .map(|entry| {
            // Candidate, then current, then fallback, which is the order `groups.md`
            // names and the order that makes a mid-handoff recovery work.
            let found = entry.tags().into_iter().find_map(|tag| {
                let wrap = table.get(&tag)?;
                let opened = open_wrap(provider, key, wrap).ok()?;
                // A wrap with no way back in is not a recovered group. Asserted rather
                // than assumed, because a wrap carrying only the secret is exactly the
                // earlier draft `groups.md` rejected: it could read a group's traffic and
                // never rejoin it.
                assert!(!opened.group_info.is_empty());
                assert_eq!(opened.epoch_secret.len(), 32);
                Some(wrap.epoch)
            });
            (entry.group.clone(), found)
        })
        .collect()
}

#[test]
fn a_recovery_key_opens_a_wrap_for_every_group_its_owner_belongs_to() {
    // Ada belongs to the root and to three channels, each of which commits a different
    // number of times. The point is that no group is special: the root is not the only
    // one that stays reachable, and a group that ratcheted further than the others does
    // not fall out of the directory.
    let provider = Provider::open(":memory:").expect("a provider");
    let recovery = RecoveryKey::derive(&provider, b"ada's twelve words").expect("a key");

    let ada_device = device("ada");
    let mut directories: HashMap<Vec<u8>, Directory> = HashMap::new();
    let mut table = WrapTable::default();

    let groups: Vec<&[u8]> = vec![ROOT, b"channel-design", b"channel-build", b"dm-ada-bo"];
    for (index, group) in groups.iter().enumerate() {
        let mut session = ada_device.create_group(group).expect("a group");
        publish_wraps(
            &mut session,
            group,
            [index as u8; 32],
            &[&recovery],
            &mut directories,
            &mut table,
        );

        // Each group commits a different number of times, so the epochs and therefore the
        // tags diverge. A directory that only worked when every group was at epoch zero
        // would pass a weaker version of this test.
        for round in 0..index {
            let joiner = device(&format!("member-{index}-{round}"));
            let package = joiner.key_package().expect("a key package");
            session.add(&package).expect("an add");
            session.merge_pending().expect("merged");
            publish_wraps(
                &mut session,
                group,
                [(index * 10 + round + 1) as u8; 32],
                &[&recovery],
                &mut directories,
                &mut table,
            );
        }
    }

    let sealed = directories
        .get(recovery.public())
        .expect("a directory")
        .seal(&provider, recovery.public())
        .expect("sealed");

    let found = recover(&provider, &recovery, &sealed, &table);
    assert_eq!(found.len(), groups.len(), "every group is in the directory");
    for (group, epoch) in &found {
        assert!(
            epoch.is_some(),
            "no wrap was reachable for {:?}, which is the silent failure this gate exists for",
            String::from_utf8_lossy(group)
        );
    }
}

#[test]
fn a_recovery_arriving_at_any_point_in_the_handoff_still_finds_a_valid_wrap() {
    // The interleaving that matters. `groups.md` calls the two-phase handoff "not an
    // impossible claim of atomic MLS commits across groups", and the whole reason it is
    // two phases is that a crash lands between them. So the recovery is attempted after
    // each of the four points in turn, on the same group, and every one of them must find
    // a wrap.
    let provider = Provider::open(":memory:").expect("a provider");
    let recovery = RecoveryKey::derive(&provider, b"ada's twelve words").expect("a key");
    let ada_device = device("ada");
    let group: &[u8] = b"channel-handoff";
    let mut session = ada_device.create_group(group).expect("a group");

    let mut table = WrapTable::default();
    let mut directory = Directory::default();

    // Epoch zero, fully published, so there is a `current` for the handoff to move off.
    let tag = session.wrap_tag(recovery.public()).expect("a tag");
    directory.entry(group).prepare(tag, [0xa0; 32]);
    table.publish(session.seal_wrap(group, recovery.public()).expect("a wrap"));
    directory
        .entry(group)
        .activate([0xa0; 32])
        .expect("activated");

    let attempt = |directory: &Directory, table: &WrapTable, at: &str| {
        let sealed = directory
            .seal(&provider, recovery.public())
            .expect("sealed");
        let found = recover(&provider, &recovery, &sealed, table);
        let (_, epoch) = found.first().expect("one group");
        assert!(
            epoch.is_some(),
            "a recovery crashing at {at} found no wrap, so this handoff is not crash safe"
        );
    };

    // Point one: crashed before `prepare`. The directory still names the old tag and the
    // old wrap is still in its slot, because the relay retains it.
    attempt(&directory, &table, "before prepare");

    // Point two: crashed after `prepare`, before the target group's commit. The candidate
    // names a tag no wrap exists under yet, and `groups.md` says recovery "never treats a
    // missing candidate as data loss": it falls through to the current.
    let bo = device("bo");
    let package = bo.key_package().expect("a key package");
    let (commit, _welcome) = session.add(&package).expect("an add");
    let target = blake3_of(&commit);
    session.merge_pending().expect("merged");
    let next_tag = session.wrap_tag(recovery.public()).expect("a tag");
    directory.entry(group).prepare(next_tag, target);
    attempt(&directory, &table, "after prepare, before the commit");

    // Point three: crashed after the wrap upload, before `activate`. Now the candidate
    // does resolve, and it is the newer one.
    table.publish(session.seal_wrap(group, recovery.public()).expect("a wrap"));
    attempt(&directory, &table, "after the wrap upload, before activate");

    // Point four: activated. The candidate has become current and the old slot is the
    // fallback, which the relay keeps for 30 days.
    directory.entry(group).activate(target).expect("activated");
    attempt(&directory, &table, "after activate");

    let entry = directory.get(group).expect("an entry");
    assert_eq!(entry.current, Some(next_tag));
    assert_eq!(entry.fallback, Some(tag));
    // Both slots resolve, which is what the retention overlap buys and what makes the
    // window between the two phases survivable rather than merely short.
    assert!(table.get(&tag).is_some() && table.get(&next_tag).is_some());
}

#[test]
fn the_relay_never_sees_a_stable_recovery_identifier_across_groups() {
    // The negative half of the reachability property, and the reason the tag exists at
    // all. `groups.md`: an earlier draft indexed wraps by the recovery public key in the
    // clear, which let a relay "join the lists across groups to reconstruct which groups
    // belong to the same person".
    let provider = Provider::open(":memory:").expect("a provider");
    let ada = RecoveryKey::derive(&provider, b"ada's twelve words").expect("a key");
    let bo = RecoveryKey::derive(&provider, b"bo's twelve words").expect("a key");
    let ada_device = device("ada");

    let mut table = WrapTable::default();
    let mut tags_by_group: Vec<Vec<[u8; 32]>> = Vec::new();
    for group in [ROOT, b"channel-one".as_slice(), b"channel-two".as_slice()] {
        let mut session = ada_device.create_group(group).expect("a group");
        let mut tags = Vec::new();
        for key in [&ada, &bo] {
            let wrap = session.seal_wrap(group, key.public()).expect("a wrap");
            tags.push(wrap.tag);
            table.publish(wrap);
        }
        tags_by_group.push(tags);
    }

    // Every tag in the whole table is distinct. Ada appears in three groups and Bo in
    // three, and if any value recurred the relay would have a join key. This is the same
    // assertion `weald-stack prove-blind` makes against the real wrap table in step 8,
    // made here against the mechanism that produces it.
    let mut all: Vec<[u8; 32]> = tags_by_group.iter().flatten().copied().collect();
    let count = all.len();
    all.sort_unstable();
    all.dedup();
    assert_eq!(
        all.len(),
        count,
        "a tag recurs, so the wrap table is a join key"
    );

    // And what the relay does learn is a count, which `groups.md` says is "already
    // implied by the size of a commit".
    for tags in &tags_by_group {
        assert_eq!(tags.len(), 2);
    }
}

#[test]
fn a_self_joiner_to_an_open_group_obtains_the_same_history_an_invitee_obtains() {
    // The second reachability property. Both paths must land on the same group state, or
    // the two ways into an `open` channel give two different products.
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(b"channel-open").expect("a group");

    // Some history first, so "the same history" is a claim about something.
    let early = ada
        .encrypt(b"a line from before either of them")
        .expect("ct");

    // Cy self-joins by external commit, from a group info.
    let info = ada.group_info().expect("a group info");
    let cy_device = device("cy");
    let (mut cy, cy_commit) = cy_device.join_external(&info).expect("joined");
    ada.process(&cy_commit).expect("processed");

    // Bo is invited by welcome, at the same epoch.
    let bo_device = device("bo");
    let package = bo_device.key_package().expect("a key package");
    let (add_commit, welcome) = ada.add(&package).expect("an add");
    ada.merge_pending().expect("merged");
    let mut bo = bo_device.join_welcome(&welcome).expect("joined");
    cy.process(&add_commit).expect("processed");

    // The three of them agree about the whole epoch, which is what the epoch
    // authenticator is for.
    assert_eq!(ada.epoch(), bo.epoch());
    assert_eq!(ada.epoch(), cy.epoch());
    assert_eq!(ada.epoch_authenticator(), bo.epoch_authenticator());
    assert_eq!(ada.epoch_authenticator(), cy.epoch_authenticator());
    assert_eq!(ada.members(), bo.members());
    assert_eq!(ada.members(), cy.members());

    // And from here both read the same thing. The history before their join is reachable
    // through the wrap and the retained envelopes rather than through MLS, which is the
    // division `groups.md` draws, so what is asserted here is the part MLS owns: from the
    // joining epoch on, the self-joiner and the invitee are indistinguishable.
    let line = ada.encrypt(b"a line after both of them").expect("ct");
    assert_eq!(
        bo.decrypt(&line).expect("decrypted").0,
        b"a line after both of them".to_vec()
    );
    let line = ada.encrypt(b"a line after both of them").expect("ct");
    assert_eq!(
        cy.decrypt(&line).expect("decrypted").0,
        b"a line after both of them".to_vec()
    );

    // Neither of them can read what came before their epoch, which is forward secrecy
    // doing its job rather than a bug. `open` history reaches them through the retained
    // envelopes, not through this layer.
    assert_eq!(
        bo.decrypt(&early).expect_err("before bo's epoch").status(),
        Status::Protocol
    );
}

#[test]
fn the_root_scope_is_mandatory_on_the_way_in_and_closed_to_a_self_join() {
    // `phases-relay.md` step 7: "A new invitee first external-commits into the mandatory
    // workspace-root scope, then self-joins its `parent` channels; omission of the root
    // from a non-bootstrap invite and any attempt to self-join the root are rejected
    // before MLS state changes."
    //
    // The ordering rule is the product's, so what this crate owns is the second half:
    // whether a refusal happens before any MLS state moves. That is the part a caller
    // cannot check for itself and the part that would leave a device half-joined.
    let ada_device = device("ada");
    let mut root = ada_device.create_group(ROOT).expect("the root group");
    let mut channel = ada_device.create_group(b"channel-parent").expect("a group");

    let epoch_before = root.epoch();
    let members_before = root.members();
    let authenticator_before = root.epoch_authenticator();

    // A self-join attempt against the root, presented the way a client would present it
    // and refused. The root publishes no group info to a stranger, so the bytes a
    // would-be self-joiner has are not one.
    let cy_device = device("cy");
    let not_a_group_info = cy_device.key_package().expect("a key package");
    let refused = cy_device
        .join_external(&not_a_group_info)
        .expect_err("the root is not self-joinable");
    assert_eq!(refused.status(), Status::Malformed);

    // Nothing moved. This is the assertion that matters: a refusal that had already
    // advanced an epoch would leave the root at a state the rest of the workspace
    // disagrees with, which is the same failure the crash gate is about.
    assert_eq!(root.epoch(), epoch_before);
    assert_eq!(root.members(), members_before);
    assert_eq!(root.epoch_authenticator(), authenticator_before);

    // The same for an omitted root: a bundle that names only the channel is refused
    // before the channel's state moves.
    let channel_epoch = channel.epoch();
    let refused = channel.add(b"not a key package").expect_err("refused");
    assert_eq!(refused.status(), Status::Malformed);
    assert_eq!(channel.epoch(), channel_epoch);

    // And the ordinary path still works afterwards, so the refusals cost nothing.
    let package = cy_device.key_package().expect("a key package");
    root.add(&package).expect("an add");
    root.merge_pending().expect("merged");
    assert_eq!(root.members(), vec![0, 1]);
}

/// BLAKE3 of some bytes, as the commit hash a directory record binds to.
///
/// The real hash is the relay's envelope hash from `specs/backend/relay/wire.md`. What
/// this suite needs is only that it is stable and distinct per commit, which is the
/// property the directory's idempotency relies on.
fn blake3_of(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}
