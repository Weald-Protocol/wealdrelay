// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The group, end to end, through the session layer.
//!
//! `specs/backend/relay/mls-binding.md` step 7's first obligation: the twelve-function
//! seam does what the product needs, which is a group two people can talk in, a third
//! person who can join, and a fourth who is removed and can no longer read.
//!
//! Every case here is real OpenMLS against a real SQLite database. There is no test
//! double anywhere in this crate, in any environment, by the spec's own rule.

use weald_mls::session::{Config, Device, Processed};
use weald_mls::status::Status;

/// One device's configuration. In-memory storage, because ten thousand property cases
/// against a file would be measuring the disk rather than the protocol. It is the same
/// storage provider and the same SQL either way.
fn config(identity: &str) -> Config {
    Config {
        database: ":memory:".to_string(),
        identity: identity.as_bytes().to_vec(),
    }
}

/// One device, opened against its own in-memory database.
fn device(identity: &str) -> Device {
    Device::open(&config(identity)).expect("a device")
}

const GROUP: &[u8] = b"weald-test-group";

#[test]
fn a_group_of_one_can_be_created_and_talks_to_itself() {
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");
    assert_eq!(ada.epoch(), 0);
    assert_eq!(ada.members(), vec![0]);
    assert_eq!(ada.own_leaf(), 0);
    assert_eq!(ada.identity(), b"ada".to_vec());

    // A message to a group of one is still a message: it is encrypted under the epoch's
    // key and the sender cannot read its own ciphertext back, which is the property that
    // makes the log at the relay opaque even to the author's own device replaying it.
    let ciphertext = ada.encrypt(b"the first line").expect("ciphertext");
    assert!(!ciphertext
        .windows(14)
        .any(|window| window == b"the first line"));
    let refused = ada.decrypt(&ciphertext).expect_err("own message");
    assert_eq!(refused.status(), Status::Protocol);
}

#[test]
fn two_devices_converge_and_read_each_other() {
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");

    // Bo publishes a key package, Ada adds it, Bo joins by the welcome. The ordinary
    // invite path, and the one the twelve-function seam could not express until
    // `key_package` and `join_welcome` were added to it.
    let bo_device = device("bo");
    let key_package = bo_device.key_package().expect("a key package");
    let (commit, welcome) = ada.add(&key_package).expect("an add");
    assert_eq!(ada.epoch(), 0, "the epoch moves when the commit is merged");
    let epoch = ada.merge_pending().expect("merged");
    assert_eq!(epoch, 1);
    assert_eq!(ada.members(), vec![0, 1]);
    // The commit is for the group and the welcome is for the joiner. Two messages, and a
    // caller that sent the welcome to the group would be sending Bo's key material to
    // everybody.
    assert_ne!(commit, welcome);

    let mut bo = bo_device.join_welcome(&welcome).expect("joined");
    assert_eq!(bo.epoch(), 1);
    assert_eq!(bo.members(), vec![0, 1]);
    // The same group state, checked the way two members check it out of band.
    assert_eq!(bo.epoch_authenticator(), ada.epoch_authenticator());

    let ciphertext = ada.encrypt(b"hello bo").expect("ciphertext");
    let (plaintext, sender) = bo.decrypt(&ciphertext).expect("decrypted");
    assert_eq!(plaintext, b"hello bo".to_vec());
    assert_eq!(sender, 0);

    let answer = bo.encrypt(b"hello ada").expect("ciphertext");
    let (plaintext, sender) = ada.decrypt(&answer).expect("decrypted");
    assert_eq!(plaintext, b"hello ada".to_vec());
    assert_eq!(sender, 1);
}

#[test]
fn a_removed_device_cannot_read_anything_after_the_removing_epoch() {
    // The negative property the whole product rests on, at its smallest.
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");
    let bo_device = device("bo");
    let key_package = bo_device.key_package().expect("a key package");
    let (_, welcome) = ada.add(&key_package).expect("an add");
    ada.merge_pending().expect("merged");
    let mut bo = bo_device.join_welcome(&welcome).expect("joined");

    // Before: Bo reads.
    let before = ada.encrypt(b"before the removal").expect("ciphertext");
    assert_eq!(
        bo.decrypt(&before).expect("decrypted").0,
        b"before the removal".to_vec()
    );

    // Ada removes Bo. Bo processes the commit that removes him, which is how he learns.
    let commit = ada.remove(&[1]).expect("a removal");
    ada.merge_pending().expect("merged");
    assert_eq!(ada.members(), vec![0]);
    let processed = bo.process(&commit).expect("processed");
    assert!(matches!(processed, Processed::Commit { .. }));

    // After: the epoch moved and Bo has no key for it.
    let after = ada.encrypt(b"after the removal").expect("ciphertext");
    let refused = bo.decrypt(&after).expect_err("removed");
    assert_eq!(refused.status(), Status::Protocol);

    // And Bo cannot write into the group either: a removed member's message is refused
    // rather than quietly ignored, so a device that thinks it is still a member finds out.
    let attempt = bo.encrypt(b"still here").err().map(|error| error.status());
    if let Some(status) = attempt {
        assert_eq!(status, Status::Protocol);
    } else {
        // OpenMLS lets a removed member produce a message it cannot deliver. What must
        // never happen is Ada accepting it.
        let stale = bo.encrypt(b"still here").expect("bytes");
        let refused = ada.decrypt(&stale).expect_err("from a removed member");
        assert_eq!(refused.status(), Status::Protocol);
    }
}

#[test]
fn a_third_device_self_joins_by_external_commit_and_sees_what_follows() {
    // The `open` group path in `specs/backend/relay/groups.md`: nobody invites Cy, Cy
    // joins from the group info and tells the group afterwards.
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");
    let group_info = ada.group_info().expect("a group info");

    let cy_device = device("cy");
    let (mut cy, commit) = cy_device.join_external(&group_info).expect("joined");
    assert_eq!(cy.epoch(), 1, "an external commit is its own epoch");

    // Ada processes Cy's commit and they are in the same epoch.
    let processed = ada.process(&commit).expect("processed");
    assert!(matches!(processed, Processed::Commit { epoch: 1 }));
    assert_eq!(ada.members(), vec![0, 1]);
    assert_eq!(ada.epoch_authenticator(), cy.epoch_authenticator());

    // And the history from here is shared, which is what "the same history an invitee
    // obtains" means for the epochs after the join.
    let line = ada.encrypt(b"after cy joined").expect("ciphertext");
    assert_eq!(
        cy.decrypt(&line).expect("decrypted").0,
        b"after cy joined".to_vec()
    );
}

#[test]
fn the_exporter_is_the_only_way_key_material_leaves_and_it_is_bounded() {
    let ada_device = device("ada");
    let ada = ada_device.create_group(GROUP).expect("a group");
    let secret = ada.export("weald/test", 32).expect("a secret");
    assert_eq!(secret.len(), 32);
    // Deterministic for one epoch and label, which is what makes it usable as a key
    // derivation input on both sides.
    assert_eq!(ada.export("weald/test", 32).expect("again"), secret);
    // A different label is a different secret, or the label would be decoration.
    assert_ne!(ada.export("weald/other", 32).expect("other"), secret);

    // Zero and enormous are both refused, because the length arrives from the other side
    // of a C ABI.
    assert_eq!(
        ada.export("weald/test", 0).expect_err("refused").status(),
        Status::InvalidArgument
    );
    assert_eq!(
        ada.export("weald/test", 1025)
            .expect_err("refused")
            .status(),
        Status::InvalidArgument
    );
}

#[test]
fn malformed_input_is_refused_by_name_rather_than_by_panic() {
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");
    // The function that eats bytes from the network. Hostile input is `Malformed` and the
    // group stays usable, which is the property the fuzz target extends to random bytes.
    for bytes in [
        vec![],
        vec![0x00],
        vec![0xff; 16],
        b"not a tls encoded message at all".to_vec(),
    ] {
        let error = ada.process(&bytes).expect_err("refused");
        assert_eq!(error.status(), Status::Malformed, "for {bytes:?}");
    }

    // A well-formed message of the wrong kind is refused on its kind, not on its bytes.
    let bo_device = device("bo");
    let key_package = bo_device.key_package().expect("a key package");
    let error = ada.process(&key_package).expect_err("refused");
    assert_eq!(error.status(), Status::Malformed);

    // And the same for the specific consumers.
    let error = ada.add(&[0xff; 8]).expect_err("refused");
    assert_eq!(error.status(), Status::Malformed);
    let error = bo_device.join_welcome(&key_package).expect_err("refused");
    assert_eq!(error.status(), Status::Malformed);
    let error = bo_device.join_external(&key_package).expect_err("refused");
    assert_eq!(error.status(), Status::Malformed);

    // The group survived every one of them.
    assert_eq!(ada.epoch(), 0);
    assert!(!ada
        .encrypt(b"still working")
        .expect("ciphertext")
        .is_empty());
}

#[test]
fn an_empty_identity_and_an_empty_removal_are_refused() {
    let error = Device::open(&Config {
        database: ":memory:".into(),
        identity: Vec::new(),
    })
    .expect_err("refused");
    assert_eq!(error.status(), Status::InvalidArgument);

    // And a group with no id, which is the same class of caller mistake.
    let error = device("ada").create_group(&[]).expect_err("refused");
    assert_eq!(error.status(), Status::InvalidArgument);

    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");
    let error = ada.remove(&[]).expect_err("refused");
    assert_eq!(error.status(), Status::InvalidArgument);
}

#[test]
fn a_proposal_waits_for_a_commit_and_the_commit_carries_it() {
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");
    let bo_device = device("bo");
    let key_package = bo_device.key_package().expect("a key package");
    let (_, welcome) = ada.add(&key_package).expect("an add");
    ada.merge_pending().expect("merged");
    let mut bo = bo_device.join_welcome(&welcome).expect("joined");

    // Cy is proposed by Bo and committed by Ada, which is the two-step path a client uses
    // when the proposer is not the committer.
    let cy_device = device("cy");
    let cy_package = cy_device.key_package().expect("a key package");
    let proposal = bo.propose_add(&cy_package).expect("a proposal");
    assert!(matches!(
        ada.process(&proposal).expect("processed"),
        Processed::Proposal
    ));
    let commit = ada.commit_pending().expect("a commit");
    ada.merge_pending().expect("merged");
    assert_eq!(ada.members(), vec![0, 1, 2]);
    // Bo learns from the commit rather than from the proposal he made.
    assert!(matches!(
        bo.process(&commit).expect("processed"),
        Processed::Commit { epoch: 2 }
    ));
    assert_eq!(bo.members(), vec![0, 1, 2]);
}

/// One device against a database on disk.
///
/// Every other case in this file uses `:memory:`, which is the right default: ten
/// thousand property cases against a file would be measuring the disk. Reopening is the
/// one obligation that cannot be stated that way, because a group in memory cannot
/// survive the process that created it by definition.
fn file_config(dir: &std::path::Path, identity: &str) -> Config {
    Config {
        database: dir
            .join(format!("{identity}.sqlite"))
            .to_str()
            .expect("utf-8 path")
            .to_string(),
        identity: identity.as_bytes().to_vec(),
    }
}

/// A restart gets the group back, and gets the same group rather than a second one.
///
/// The obligation `open_group` exists for. Before it, the only ways to hold a group were
/// to create it or to join it, so a client that restarted would either create a second
/// group under the same id, forking the workspace, or external-commit itself in again on
/// every launch, growing the ratchet tree without bound. Both are worse than an error,
/// which is why the identity of the reopened group is asserted here and not just its
/// presence.
#[test]
fn a_group_this_device_is_already_in_reopens_after_a_restart() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let ada_config = file_config(dir.path(), "ada");

    // First launch. Ada creates the group and invites Bo, so what has to survive is a
    // real two-member group at epoch 1 and not a group of one.
    let bo_device = device("bo");
    let key_package = bo_device.key_package().expect("a key package");
    let (authenticator, welcome) = {
        let ada_device = Device::open(&ada_config).expect("a device");
        let mut ada = ada_device.create_group(GROUP).expect("a group");
        let (_commit, welcome) = ada.add(&key_package).expect("an add");
        assert_eq!(ada.merge_pending().expect("merged"), 1);
        (ada.epoch_authenticator(), welcome)
    };
    let mut bo = bo_device.join_welcome(&welcome).expect("joined");

    // Second launch: a new `Device` over the same database, which is what a restart is.
    let ada_device = Device::open(&ada_config).expect("the device, reopened");
    let mut ada = ada_device
        .open_group(GROUP)
        .expect("the store answered")
        .expect("the group is in this device's store");

    assert_eq!(ada.epoch(), 1);
    assert_eq!(ada.members(), vec![0, 1]);
    assert_eq!(ada.own_leaf(), 0);
    assert_eq!(ada.identity(), b"ada".to_vec());
    // The check two members make out of band. If the restart had produced a different
    // group under the same id, everything above could still hold and this could not.
    assert_eq!(ada.epoch_authenticator(), authenticator);

    // And it still works, which is the whole point of getting it back: Bo reads what the
    // reopened session writes, under key material that came off the disk.
    let ciphertext = ada.encrypt(b"back after a restart").expect("ciphertext");
    let (plaintext, sender) = bo.decrypt(&ciphertext).expect("decrypted");
    assert_eq!(plaintext, b"back after a restart".to_vec());
    assert_eq!(sender, 0);
}

/// "Have I got this one" answered no, which is an ordinary answer and not a failure.
///
/// A client asks this on every launch for every workspace it knows about, including the
/// ones it has been removed from and the ones it has not joined yet. Returning an error
/// would make the ordinary case indistinguishable from a broken database.
#[test]
fn a_group_this_device_is_not_in_is_an_ordinary_none_rather_than_an_error() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let ada_device = Device::open(&file_config(dir.path(), "ada")).expect("a device");
    // A group this device really is in, so the negative below is about the group asked
    // for and not about a store that holds nothing at all.
    ada_device.create_group(GROUP).expect("a group");

    assert!(ada_device
        .open_group(b"a-group-ada-was-never-in")
        .expect("the store answered")
        .is_none());
}

/// A refused commit is dropped, and the membership change can be built again.
///
/// The obligation `clear_pending_commit` exists for, and the reason a caller can honestly
/// wait for the relay before merging. Without it a device whose write was refused holds a
/// commit it can neither merge, because the group never saw it, nor replace, because a
/// second commit is refused while one is pending: the group is stuck one write short of
/// the epoch everybody else is at, forever.
#[test]
fn a_pending_commit_can_be_dropped_and_the_change_rebuilt() {
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");
    let bo_device = device("bo");
    let key_package = bo_device.key_package().expect("a key package");

    // The write is refused, so nothing merges. The epoch is the group's, and Bo is not a
    // member here any more than he is anywhere else.
    let (refused, _) = ada.add(&key_package).expect("an add");
    assert_eq!(ada.clear_pending_commit().expect("cleared"), 0);
    assert_eq!(ada.epoch(), 0);
    assert_eq!(ada.members(), vec![0]);

    // Idempotent: a failure path that had to know how far it got would be a failure path
    // with a second bug in it.
    assert_eq!(ada.clear_pending_commit().expect("cleared again"), 0);

    // And the change is retryable, which is the whole point. The second commit is a real
    // one and not the refused bytes replayed.
    let (commit, welcome) = ada.add(&key_package).expect("a second add");
    assert_ne!(commit, refused);
    assert_eq!(ada.merge_pending().expect("merged"), 1);
    assert_eq!(ada.members(), vec![0, 1]);
    let bo = bo_device.join_welcome(&welcome).expect("joined");
    assert_eq!(bo.epoch_authenticator(), ada.epoch_authenticator());
}

/// An external join nobody accepted can be abandoned, and the device rejoins cleanly.
///
/// `join_external` writes the group through the store before its commit has been anywhere.
/// Without a way to delete it, a device whose commit the relay refused finds that group on
/// its next launch, takes the resume path rather than the join path, and can never
/// republish the only thing that would have made it a member (BR-027). This is that way
/// out, over a real database, because the whole failure is about what survives a restart.
#[test]
fn an_unaccepted_external_join_can_be_abandoned_and_tried_again() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let cy_config = file_config(dir.path(), "cy");
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");

    // The refused join. Cy holds a group at epoch 1 that Ada has never heard of.
    {
        let cy_device = Device::open(&cy_config).expect("a device");
        let (cy, _refused) = cy_device
            .join_external(&ada.group_info().expect("a group info"))
            .expect("joined");
        assert_eq!(cy.epoch(), 1);
        let mut cy = cy;
        cy.abandon().expect("abandoned");
    }

    // A restart. The group is not in the store, so the client takes the join path again
    // rather than resuming a membership no other member has.
    let cy_device = Device::open(&cy_config).expect("the device, reopened");
    assert!(cy_device
        .open_group(GROUP)
        .expect("the store answered")
        .is_none());

    // And the second attempt is a real join: Ada accepts the commit and they converge.
    let (mut cy, commit) = cy_device
        .join_external(&ada.group_info().expect("a group info"))
        .expect("joined");
    assert!(matches!(
        ada.process(&commit).expect("processed"),
        Processed::Commit { epoch: 1 }
    ));
    assert_eq!(ada.members(), vec![0, 1]);
    assert_eq!(ada.epoch_authenticator(), cy.epoch_authenticator());
    let line = ada.encrypt(b"after cy rejoined").expect("ciphertext");
    assert_eq!(
        cy.decrypt(&line).expect("decrypted").0,
        b"after cy rejoined".to_vec()
    );
}
