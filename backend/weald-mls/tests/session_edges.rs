// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The edges of the session seam: what it refuses, what it prints, and what it exports.
//!
//! `tests/session.rs` proves the ordinary path in `specs/backend/relay/mls-binding.md`:
//! a group two people talk in, a third who joins, a fourth who is removed. This file is
//! the other half of the same obligation, the cases a client reaches when something is
//! wrong or when the caller asks for something the seam has to say no to. Every one of
//! them is a claim about behaviour a person could observe, not a call for its own sake.
//!
//! Real OpenMLS against a real SQLite database, like everything else in this crate.

use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::RatchetTreeIn;

use weald_mls::session::{Config, Device, Processed};
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

const GROUP: &[u8] = b"weald-edge-group";

/// A session and a device print their own name and nothing that is inside them.
///
/// A security property, not a cosmetic one. `Session` holds a signing key, a credential
/// and OpenMLS group state; `Device` holds the same signing key and the provider that has
/// every secret this device owns. `Debug` is the one trait that gets called by accident:
/// a `derive(Debug)` on a caller's struct, a failing `assert_eq!`, a `log::debug!`, a
/// panic message crossing into a crash report. `mls-binding.md` scopes this crate as the
/// place key material lives and does not leave, so the formatted output is asserted to
/// carry the two facts an operator needs and none of the material.
#[test]
fn a_session_and_a_device_print_their_name_and_never_their_key_material() {
    let ada_device = device("ada");
    let ada = ada_device.create_group(GROUP).expect("a group");

    let printed = format!("{ada:?}");
    assert!(printed.starts_with("Session {"), "{printed}");
    assert!(printed.contains("epoch: 0"), "{printed}");
    assert!(printed.contains("leaf: 0"), "{printed}");
    // `finish_non_exhaustive` is the whole design: the fields that are not epoch and leaf
    // are secret, and the output says so rather than showing them.
    assert!(printed.contains(".."), "{printed}");

    let device_printed = format!("{ada_device:?}");
    assert_eq!(device_printed, "Device { .. }");

    // Nothing that a walked struct would have shown is in either string. The signature
    // key is checked as its own rendering and as raw bytes, because a `Debug` that
    // printed a byte slice and one that printed a hex string are the same leak.
    let key = ada_device.signature_key();
    let as_debug = format!("{key:?}");
    let as_hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    for output in [&printed, &device_printed] {
        assert!(!output.contains(&as_debug), "the key's bytes: {output}");
        assert!(!output.contains(&as_hex), "the key in hex: {output}");
        for field in ["signer", "credential", "provider", "group"] {
            assert!(!output.contains(field), "the field {field}: {output}");
        }
        // And not the identity either, which is a device key by `identity.md` and not
        // something a log line should carry on its own.
        assert!(!output.contains("ada"), "the identity: {output}");
    }
}

/// A well-formed MLS message that is not a key package is refused on its kind.
///
/// A key package arrives from the relay, which means it arrives from whoever asked the
/// relay to hold one. Bytes that decode cleanly as some other MLS structure are the
/// interesting case: the decoder is happy, so the only thing standing between a group and
/// a message on the wrong path is this check. It has to name the kind rather than the
/// bytes, so an operator reading the log knows the sender sent the wrong thing rather
/// than a corrupted thing.
#[test]
fn a_well_formed_message_that_is_not_a_key_package_is_refused_on_its_kind() {
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");
    let bo_device = device("bo");
    let package = bo_device.key_package().expect("a key package");
    let (commit, welcome) = ada.add(&package).expect("an add");
    ada.merge_pending().expect("merged");
    let group_info = ada.group_info().expect("a group info");
    let application = ada.encrypt(b"an ordinary line").expect("ciphertext");

    for (name, bytes) in [
        ("a commit", &commit),
        ("a welcome", &welcome),
        ("a group info", &group_info),
        ("an application message", &application),
    ] {
        let error = ada.add(bytes).expect_err("refused");
        assert_eq!(error.status(), Status::Malformed, "for {name}");
        assert!(
            error.to_string().contains("not a key package"),
            "for {name}, the error has to name the kind: {error}"
        );
        // The same check guards the propose path, which is a second caller of the same
        // reader and would otherwise be a second place to forget it.
        let error = ada.propose_add(bytes).expect_err("refused");
        assert_eq!(error.status(), Status::Malformed, "for {name}");
    }

    // The group is untouched by any of them.
    assert_eq!(ada.members(), vec![0, 1]);
    assert_eq!(ada.epoch(), 1);
}

/// `decrypt` refuses a commit and a proposal by name rather than handling them quietly.
///
/// The two functions differ in what the caller has to do next. An application message is
/// content to project; a commit changes the group and has to be recorded in the same
/// transaction as the documents it affects. A caller that received a commit on the
/// decrypt path has been handed a message on the wrong path by its own transport code,
/// and the seam says so.
#[test]
fn decrypt_refuses_a_commit_and_a_proposal_by_name() {
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");
    let bo_device = device("bo");
    let package = bo_device.key_package().expect("a key package");
    let (_, welcome) = ada.add(&package).expect("an add");
    ada.merge_pending().expect("merged");
    let mut bo = bo_device.join_welcome(&welcome).expect("joined");

    // A commit, on the decrypt path.
    let cy_device = device("cy");
    let cy_package = cy_device.key_package().expect("a key package");
    let (commit, _) = ada.add(&cy_package).expect("an add");
    ada.merge_pending().expect("merged");
    let error = bo.decrypt(&commit).expect_err("refused");
    assert_eq!(error.status(), Status::Protocol);
    assert!(
        error.to_string().contains("not an application message"),
        "the error has to name why: {error}"
    );

    // The refusal did not cost Bo the group: the two are still in the same epoch and Bo
    // still reads what Ada writes. A refusal on the wrong path is a message to the
    // caller, not a broken session.
    assert_eq!(bo.epoch(), ada.epoch());
    assert_eq!(bo.epoch_authenticator(), ada.epoch_authenticator());
    let line = ada.encrypt(b"after the refusal").expect("ciphertext");
    assert_eq!(
        bo.decrypt(&line).expect("decrypted").0,
        b"after the refusal".to_vec()
    );

    // A proposal, on the same path. Proposed by Ada so that Bo is the one receiving it,
    // and last because a group with a proposal pending will not encrypt anything.
    let dee_device = device("dee");
    let dee_package = dee_device.key_package().expect("a key package");
    let proposal = ada.propose_add(&dee_package).expect("a proposal");
    let error = bo.decrypt(&proposal).expect_err("refused");
    assert_eq!(error.status(), Status::Protocol);
    assert!(
        error.to_string().contains("not an application message"),
        "the error has to name why: {error}"
    );

    // And the proposal really is pending on Bo's side rather than lost: the commit Ada
    // makes for it is one Bo can apply, and the two agree afterwards.
    let commit = ada.commit_pending().expect("a commit");
    ada.merge_pending().expect("merged");
    assert!(matches!(
        bo.process(&commit).expect("processed"),
        Processed::Commit { .. }
    ));
    assert_eq!(bo.members(), ada.members());
    assert_eq!(bo.epoch_authenticator(), ada.epoch_authenticator());
}

/// The ratchet tree export is a tree, and every member at an epoch exports the same one.
///
/// The out-of-band copy of what the ratchet tree extension normally carries in the group
/// info. Two claims are worth making about it and both are properties a joiner depends
/// on: the bytes really are a TLS-encoded ratchet tree (a joiner handed anything else
/// cannot build the group), and two members at the same epoch produce identical bytes (a
/// joiner given one member's copy would otherwise reach a different tree from the rest of
/// the group). And it moves when the tree moves, or it would be answering about a group
/// that no longer exists.
#[test]
fn the_ratchet_tree_export_is_a_tree_and_every_member_exports_the_same_one() {
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");
    let alone = ada.ratchet_tree().expect("a ratchet tree");
    assert!(RatchetTreeIn::tls_deserialize_exact(&alone).is_ok());

    let bo_device = device("bo");
    let package = bo_device.key_package().expect("a key package");
    let (_, welcome) = ada.add(&package).expect("an add");
    ada.merge_pending().expect("merged");
    let bo = bo_device.join_welcome(&welcome).expect("joined");

    let from_ada = ada.ratchet_tree().expect("a ratchet tree");
    let from_bo = bo.ratchet_tree().expect("a ratchet tree");
    assert_eq!(from_ada, from_bo, "two members, one tree");
    RatchetTreeIn::tls_deserialize_exact(&from_ada).expect("a ratchet tree decodes");

    // The tree grew, so the export changed. A constant would have passed every assertion
    // above.
    assert_ne!(from_ada, alone);
}

/// A message over the wire ceiling is refused, and the error names the size.
///
/// `wire.md` puts a one mebibyte ceiling on an envelope. Serialising a message past it
/// produces bytes the relay will refuse, so the refusal happens here, where the reason is
/// still known: the caller learns its payload is too large rather than learning that some
/// server said no. The number is in the message because the caller's next move is to
/// split the payload, and it cannot without knowing by how much.
#[test]
fn a_message_over_the_wire_ceiling_is_refused_and_the_error_names_the_size() {
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");

    // Comfortably under, to fix that the ceiling is the thing being tested and not the
    // encryption of a large payload.
    let ordinary = ada.encrypt(&vec![7u8; 4096]).expect("ciphertext");
    assert!(ordinary.len() < (1 << 20));

    let oversized = vec![7u8; (1 << 20) + 4096];
    let error = ada.encrypt(&oversized).expect_err("refused");
    assert_eq!(error.status(), Status::InvalidArgument);
    let message = error.to_string();
    assert!(
        message.contains("1048576"),
        "the ceiling has to be in the message: {message}"
    );
    assert!(
        message.contains(&format!("{}", oversized.len())) || message.contains("bytes, over"),
        "the size has to be in the message: {message}"
    );

    // The group is still usable: a payload the caller has to split is not a broken group.
    assert_eq!(ada.epoch(), 0);
    assert!(!ada
        .encrypt(b"a smaller line")
        .expect("ciphertext")
        .is_empty());
}

/// One database cannot hold the same group twice.
///
/// The group id comes from the product layer, and two calls with the same one is a caller
/// bug with a real consequence: the second group would overwrite the first's state in the
/// shared store, and the device would lose the epoch secrets of a group it is still a
/// member of. Refusing is the only safe answer, and it has to be a status rather than a
/// silent replacement.
#[test]
fn one_database_cannot_hold_the_same_group_twice() {
    let ada_device = device("ada");
    let first = ada_device.create_group(GROUP).expect("a group");
    let error = ada_device.create_group(GROUP).expect_err("refused");
    assert_eq!(error.status(), Status::Protocol);

    // The first group is still the one in the store, at the epoch it was at.
    assert_eq!(first.epoch(), 0);
    assert_eq!(first.members(), vec![0]);

    // A different id in the same database is fine, because a device belongs to several
    // groups through one file.
    let other = ada_device.create_group(b"a-second-group").expect("a group");
    assert_ne!(other.epoch_authenticator(), first.epoch_authenticator());
}

/// Every path that would produce a second commit is refused while one is pending.
///
/// `merge_pending` is deliberately separate from producing a commit: the caller merges
/// when the relay has accepted the write. That leaves a window, and in it this device
/// holds a commit the group has not seen. A second commit built in that window would be
/// built on an epoch that may never exist, and whichever of the two the relay accepted,
/// the other would be unusable. So all four of the functions that commit or propose
/// refuse, rather than one of them.
#[test]
fn every_path_that_commits_is_refused_while_a_commit_is_pending() {
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");

    let bo_device = device("bo");
    let bo_package = bo_device.key_package().expect("a key package");
    let cy_device = device("cy");
    let cy_package = cy_device.key_package().expect("a key package");

    let (_, welcome) = ada.add(&bo_package).expect("an add");

    let error = ada.add(&cy_package).expect_err("refused");
    assert_eq!(error.status(), Status::Protocol);
    let error = ada.remove(&[0]).expect_err("refused");
    assert_eq!(error.status(), Status::Protocol);
    let error = ada.propose_add(&cy_package).expect_err("refused");
    assert_eq!(error.status(), Status::Protocol);
    let error = ada.commit_pending().expect_err("refused");
    assert_eq!(error.status(), Status::Protocol);

    // Nothing about the pending commit was disturbed by four refusals: merging it still
    // produces the epoch it always would have, and the welcome that was made with it
    // still admits Bo.
    assert_eq!(ada.merge_pending().expect("merged"), 1);
    assert_eq!(ada.members(), vec![0, 1]);
    let bo = bo_device.join_welcome(&welcome).expect("joined");
    assert_eq!(bo.epoch_authenticator(), ada.epoch_authenticator());
}

/// An evicted member can neither merge nor export, and the group info it can still
/// produce admits nobody.
///
/// The negative property `tests/session.rs` proves for reading, extended to everything
/// else the seam offers. A removed device that could still export a secret would be a
/// removed device that could still derive a key the group is using. `group_info` is the
/// one call OpenMLS still answers after an eviction, so what is proved about it is the
/// thing that actually matters: the group refuses the external commit built from it, so a
/// removed device cannot invite anybody into a group it is not in.
#[test]
fn an_evicted_member_can_neither_merge_nor_export_and_its_group_info_admits_nobody() {
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");
    let bo_device = device("bo");
    let package = bo_device.key_package().expect("a key package");
    let (_, welcome) = ada.add(&package).expect("an add");
    ada.merge_pending().expect("merged");
    let mut bo = bo_device.join_welcome(&welcome).expect("joined");

    // Before the removal, all three answer.
    assert_eq!(bo.export("weald/test", 32).expect("a secret").len(), 32);
    assert!(!bo.group_info().expect("a group info").is_empty());

    let commit = ada.remove(&[1]).expect("a removal");
    ada.merge_pending().expect("merged");
    assert!(matches!(
        bo.process(&commit).expect("processed"),
        Processed::Commit { .. }
    ));

    let error = bo.merge_pending().expect_err("evicted");
    assert_eq!(error.status(), Status::Protocol);
    let error = bo.export("weald/test", 32).expect_err("evicted");
    assert_eq!(error.status(), Status::Protocol);

    // The stale group info is still producible, and it is worthless: Cy can build an
    // external commit from it and the group will not take it, because it names an epoch
    // the group has left.
    let stale = bo.group_info().expect("a stale group info");
    let cy_device = device("cy");
    match cy_device.join_external(&stale) {
        Err(error) => assert_eq!(error.status(), Status::Protocol),
        Ok((_, commit)) => {
            let error = ada.process(&commit).expect_err("refused");
            assert_eq!(error.status(), Status::Protocol);
            assert_eq!(ada.members(), vec![0], "nobody was admitted");
        }
    }

    // And Ada, who is still in the group, can still do both.
    assert_eq!(ada.export("weald/test", 32).expect("a secret").len(), 32);
    assert!(!ada.group_info().expect("a group info").is_empty());
}

/// An external commit whose joiner cannot fit in an envelope is refused, and nothing about
/// the group it was aimed at moves.
///
/// The self-join path of an `open` group (`specs/backend/relay/groups.md`) produces a
/// commit the joiner has to publish, and that commit carries the joiner's own leaf node,
/// which carries its identity. The identity arrives from Swift across the C ABI, so its
/// size is a caller's input, and a commit past `wire.md`'s one mebibyte ceiling is one the
/// relay will refuse. The joiner has to learn that here, where the reason is still known,
/// rather than by publishing bytes and being told no by a server: a device that thinks it
/// joined a group nobody admitted it to is the worst of the three outcomes.
#[test]
fn an_external_commit_over_the_wire_ceiling_is_refused_before_it_is_published() {
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");
    let group_info = ada.group_info().expect("a group info");

    let huge = Device::open(&Config {
        database: ":memory:".to_string(),
        identity: vec![b'h'; 2 << 20],
    })
    .expect("a device");
    let error = huge.join_external(&group_info).expect_err("refused");
    assert_eq!(error.status(), Status::InvalidArgument);
    let message = error.to_string();
    assert!(
        message.contains("1048576"),
        "the ceiling has to be in the message: {message}"
    );

    // Ada's group is exactly where it was: a refusal on the joiner's side is not something
    // the group ever hears about.
    assert_eq!(ada.members(), vec![0]);
    assert_eq!(ada.epoch(), 0);

    // And an ordinary joiner still gets in through the same group info, so the refusal was
    // about the size and not about the path.
    let cy_device = device("cy");
    let (cy, commit) = cy_device
        .join_external(&group_info)
        .expect("an external join");
    assert!(matches!(
        ada.process(&commit).expect("processed"),
        Processed::Commit { .. }
    ));
    assert_eq!(ada.members(), vec![0, 1]);
    assert_eq!(cy.epoch_authenticator(), ada.epoch_authenticator());
}

/// A workspace database that has become read-only refuses to merge a commit, rather than
/// advancing an epoch it cannot persist.
///
/// The crash rule in `specs/backend/relay/mls-binding.md` is that the epoch on disk and the
/// epoch in memory agree. A read-only database is the ordinary way that can be threatened
/// without a crash: a workspace container on a volume that was remounted, a file whose
/// permissions changed, a restore in progress. Reads keep working, so the message is
/// processed and verified, and only the write that advances the epoch fails. A binding
/// that swallowed that failure would leave this device an epoch ahead of its own database
/// and unable to decrypt anything the group sends after a relaunch.
///
/// The commit here is an external join, which is the one commit RFC 9420 frames as a
/// public message. That is what makes the case sharp: processing it writes nothing on its
/// own, so the only write in the call is the merge, and the failure is unambiguously the
/// one being tested.
#[test]
fn a_read_only_database_refuses_to_merge_a_commit_rather_than_advancing_without_it() {
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");
    let group_info = ada.group_info().expect("a group info");
    let cy_device = device("cy");
    let (_cy, commit) = cy_device
        .join_external(&group_info)
        .expect("an external join");

    ada.provider()
        .connection()
        .execute("pragma query_only = 1", [])
        .expect("a read-only database");

    let error = ada.process(&commit).expect_err("refused");
    assert_eq!(error.status(), Status::Protocol);
    assert!(
        error.to_string().contains("storage"),
        "the error has to say the storage refused: {error}"
    );

    // Nothing moved. The device is still at the epoch its database is at, which is the
    // whole property: a merge that cannot be written is a merge that did not happen.
    assert_eq!(ada.epoch(), 0);
    assert_eq!(ada.members(), vec![0]);

    // And when the database is writable again the same commit applies, so the refusal was
    // a report about the storage rather than a rejection of the message.
    ada.provider()
        .connection()
        .execute("pragma query_only = 0", [])
        .expect("a writable database");
    assert!(matches!(
        ada.process(&commit).expect("processed"),
        Processed::Commit { .. }
    ));
    assert_eq!(ada.epoch(), 1);
    assert_eq!(ada.members(), vec![0, 1]);
}

/// A database path with no directory component is opened beside the process.
///
/// The path arrives from Swift across a C ABI and is not guaranteed to be absolute. A
/// single name has no parent to create, and the provider has to notice that rather than
/// ask the filesystem to create a directory called nothing, which is an error on every
/// platform this ships to.
///
/// This is the one case in this file that depends on the process's working directory, so
/// it is the only one: every other test here uses an in-memory database or an absolute
/// temporary path, and integration test binaries are separate processes, so the change
/// cannot reach another suite.
#[test]
fn a_database_path_with_no_directory_component_is_opened_beside_the_process() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let previous = std::env::current_dir().expect("a working directory");
    std::env::set_current_dir(dir.path()).expect("a working directory");
    let opened = Provider::open("weald-edge-relative.sqlite");
    std::env::set_current_dir(&previous).expect("the working directory back");

    let provider = opened.expect("a provider");
    // Migrated, so this is a real provider and not merely a file that got created.
    let count: i64 = provider
        .connection()
        .query_row(
            "select count(*) from openmls_sqlite_storage_migrations",
            [],
            |row| row.get(0),
        )
        .expect("a migration count");
    assert!(count >= 1);
    drop(provider);
    assert!(
        dir.path().join("weald-edge-relative.sqlite").exists(),
        "the database is beside the process, not somewhere invented for it"
    );
}

/// Reopening a group with no id is refused before the store is touched.
///
/// The same rule `create_group` follows. An empty group id is not a group nobody has, it
/// is a caller that lost track of what it was asking for, and answering `None` would tell
/// that caller "you are not in it" rather than "you asked wrongly".
#[test]
fn opening_a_group_with_an_empty_id_is_refused_rather_than_answered_none() {
    let ada_device = device("ada");
    let refused = ada_device.open_group(b"").expect_err("an empty group id");
    assert_eq!(refused.status(), Status::InvalidArgument);
}

/// A group row the disk corrupted is a typed failure, not a panic and not a silent no.
///
/// The one storage failure a client cannot prevent: the bytes that came back are not the
/// bytes that went out. It has to be distinguishable from "you are not in this group",
/// because a client that read a corrupt store as `None` would conclude it had been
/// removed from a workspace it is still a member of, and the repair for those two is not
/// the same. Written through a second real connection to the same file, which is the same
/// storage the device itself uses; there is no double here.
#[test]
fn a_group_row_the_disk_corrupted_is_a_typed_storage_failure_rather_than_a_silent_no() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let database = dir
        .path()
        .join("ada.sqlite")
        .to_str()
        .expect("utf-8 path")
        .to_string();
    let config = Config {
        database: database.clone(),
        identity: b"ada".to_vec(),
    };

    {
        let ada_device = Device::open(&config).expect("a device");
        ada_device.create_group(GROUP).expect("a group");
    }

    let other = Provider::open(&database).expect("a second connection");
    let overwritten = other
        .connection()
        .execute(
            "update openmls_group_data set group_data = randomblob(64) \
             where data_type = 'tree'",
            [],
        )
        .expect("the row is overwritten");
    assert_eq!(
        overwritten, 1,
        "the group's tree row has to exist for this case to be about corruption"
    );

    let ada_device = Device::open(&config).expect("the device, reopened");
    let refused = ada_device
        .open_group(GROUP)
        .expect_err("a tree that will not deserialise");
    assert_eq!(refused.status(), Status::Storage);
}
