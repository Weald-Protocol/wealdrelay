// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Two clients that do not speak quite the same dialect, in one group.
//!
//! `specs/backend/relay/mls-binding.md`, "Testing": "Cross-version tests. An old client
//! and a new client in one group, since forward compatibility is claimed in
//! `specs/backend/relay/wire.md` and claimed compatibility that is never tested is a
//! rumour." `specs/backend/build/phases-relay.md` step 7 lists it as a gate item.
//!
//! # What this file proves
//!
//! Compatibility in MLS is negotiated by two things and only two: the protocol version in
//! the message frame, and the capability set a leaf advertises. So those are what is
//! tested here, through the seam, against real OpenMLS and real SQLite.
//!
//! - A key package produced by the ordinary path advertises nothing beyond the floor
//!   every RFC 9420 implementation has to support: MLS 1.0, the basic credential, no leaf
//!   extension and no proposal type of its own. That is the property that makes an older
//!   peer able to accept our leaf at all, and it is asserted rather than assumed because
//!   it is a property of a default in a dependency, which is the kind of thing that
//!   changes in a minor version without anybody noticing.
//! - A device that advertises only the minimum capability set joins a group created by
//!   the ordinary path, reads it, writes to it, and commits into it, and both members
//!   converge on the same epoch authenticator. That is the old client and the new client
//!   in one group.
//! - A leaf that carries an extension this build has never heard of is carried, not
//!   rejected, and the group goes on working around it. That is what forward
//!   compatibility means in MLS and it is the direction most likely to be broken by
//!   accident, because nothing in day-to-day development ever exercises it.
//! - A key package that carries an extension its own leaf never claimed to support is
//!   refused with a typed `Status::Protocol`, and a message that claims a protocol
//!   version this build does not speak is refused with a typed `Status::Malformed`.
//!   Neither panics, and the group is still usable afterwards. That is the other half:
//!   a claim this build cannot honour is declined by name, not by crashing the component
//!   that holds every key.
//!
//! # What this file does NOT prove
//!
//! It does not run two builds of this crate against each other. There is one version of
//! `weald-mls` in the tree, so there is no older binary to link, and a test that claimed
//! otherwise would be claiming something the repository cannot currently support. In
//! particular it says nothing about:
//!
//! - a change in how this crate marshals a message across the C ABI, since both sides
//!   here are the same `ffi.rs`,
//! - a change in the SQLite storage schema, since both sides here run the same migrations,
//! - a change in the OpenMLS version itself, since both sides here link the same 0.8.1.
//!
//! To become a two-binary test it would need: the previous released crate published or
//! vendored at a pinned revision, a second test target that links it, and a harness that
//! passes byte buffers between the two rather than calling both through one `use`. That
//! is a build-system change rather than a test change, and it belongs with the
//! XCFramework work in `specs/backend/build/environments.md`, which is where the pinned
//! checksums for previous builds would come from. Until then the honest claim is the one
//! above: compatibility is proved at the protocol-version and capability level, which is
//! the level MLS actually negotiates at, and not at the level of two compiled artefacts.

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::{
    BasicCredential, Capabilities, CredentialType, CredentialWithKey, Extension, ExtensionType,
    Extensions, KeyPackage, KeyPackageBundle, LeafNode, MlsMessageBodyIn, MlsMessageIn,
    MlsMessageOut, ProtocolVersion, UnknownExtension, VerifiableCiphersuite,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider as _;

use weald_mls::session::{Config, Device, Processed, CIPHERSUITE};
use weald_mls::status::Status;

const GROUP: &[u8] = b"weald-cross-version-group";

/// An extension type no version of anything has defined. It stands in for whatever a
/// client two releases from now will legitimately want to put in its leaf.
const FROM_THE_FUTURE: u16 = 0xf00d;

/// One device, opened against its own in-memory database.
fn device(identity: &str) -> Device {
    Device::open(&Config {
        database: ":memory:".to_string(),
        identity: identity.as_bytes().to_vec(),
    })
    .expect("a device")
}

/// A key package for `device`, advertising exactly the capabilities and leaf extensions
/// given, minted into that device's own store.
///
/// `Device::key_package` takes no arguments on purpose: this build has one ciphersuite and
/// one capability set, and a seam that let a caller choose would be a seam that let a
/// caller choose wrong. So describing a peer with a different capability set means
/// building the key package here, from the same provider and the same signing key the
/// device already has, so that `Device::join_welcome` can still find the private half.
/// Nothing is faked: the signer is read back out of the device's real SQLite store, and
/// the key package is a real one that a real relay would accept.
fn key_package_advertising(
    device: &Device,
    capabilities: Capabilities,
    leaf_extensions: Extensions<LeafNode>,
    key_package_extensions: Extensions<KeyPackage>,
) -> Vec<u8> {
    let signer = SignatureKeyPair::read(
        device.provider().storage(),
        &device.signature_key(),
        CIPHERSUITE.signature_algorithm(),
    )
    .expect("the device's own signing key");
    let credential = CredentialWithKey {
        credential: BasicCredential::new(device.identity()).into(),
        signature_key: device.signature_key().into(),
    };
    let bundle: KeyPackageBundle = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .leaf_node_extensions(leaf_extensions)
        .key_package_extensions(key_package_extensions)
        .build(CIPHERSUITE, device.provider(), &signer, credential)
        .expect("a key package");
    MlsMessageOut::from(bundle.key_package().clone())
        .tls_serialize_detached()
        .expect("serialised")
}

/// The capability set of a leaf, read back out of serialised key package bytes.
///
/// Read from the wire form rather than from the builder that made it, because what an
/// older peer sees is the bytes, and a test that inspected the local object would be
/// testing the object rather than the message.
fn capabilities_on_the_wire(key_package: &[u8]) -> Capabilities {
    let message = MlsMessageIn::tls_deserialize_exact(key_package).expect("a message");
    let MlsMessageBodyIn::KeyPackage(package) = message.extract() else {
        panic!("not a key package");
    };
    let package: KeyPackage = package
        .validate(
            weald_mls::store::Provider::open(":memory:")
                .expect("a provider")
                .crypto(),
            ProtocolVersion::Mls10,
        )
        .expect("a valid key package");
    package.leaf_node().capabilities().clone()
}

#[test]
fn a_key_package_from_this_build_advertises_nothing_beyond_the_floor_of_rfc_9420() {
    let capabilities =
        capabilities_on_the_wire(&device("new").key_package().expect("a key package"));

    // One protocol version. A leaf that advertised a second one would be a leaf claiming
    // this build can speak something it has never been run against.
    assert_eq!(capabilities.versions(), [ProtocolVersion::Mls10]);
    // No leaf extension and no proposal type of our own. These two are the ones that make
    // a peer refuse a leaf it cannot support, so a build that started advertising one
    // would silently become incompatible with every older client, and this is where that
    // shows up.
    assert!(
        capabilities.extensions().is_empty(),
        "this build advertises a leaf extension an older client would have to support: {:?}",
        capabilities.extensions()
    );
    assert!(
        capabilities.proposals().is_empty(),
        "this build advertises a proposal type an older client would have to support: {:?}",
        capabilities.proposals()
    );
    // The basic credential, which is the one RFC 9420 makes mandatory and the one
    // `specs/backend/relay/identity.md` builds a device key on.
    assert!(capabilities.credentials().contains(&CredentialType::Basic));
    // And the ciphersuite the group actually runs on is among the ones the leaf claims,
    // or the leaf could not be added to its own group.
    assert!(capabilities
        .ciphersuites()
        .contains(&VerifiableCiphersuite::from(CIPHERSUITE)));
}

#[test]
fn an_old_client_that_advertises_only_the_minimum_capability_set_joins_talks_and_commits() {
    // The new client: the ordinary path, whatever this build's defaults are.
    let new_device = device("new");
    let mut new = new_device.create_group(GROUP).expect("a group");

    // The old client: one protocol version, one ciphersuite, one credential type, and not
    // a single extension or proposal type beyond the base protocol. This is the narrowest
    // leaf RFC 9420 permits, and therefore the worst case an older release could present.
    let old_device = device("old");
    let minimum = Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[CIPHERSUITE]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    );
    let key_package = key_package_advertising(
        &old_device,
        minimum,
        Extensions::<LeafNode>::default(),
        Extensions::<KeyPackage>::default(),
    );
    let advertised = capabilities_on_the_wire(&key_package);
    assert_eq!(advertised.versions(), [ProtocolVersion::Mls10]);
    assert_eq!(advertised.ciphersuites().len(), 1);
    assert!(advertised.extensions().is_empty());

    // The new client adds it. If this build had grown a required capability, this is the
    // call that would fail, and it would fail for every older client in the field at once.
    let (_, welcome) = new.add(&key_package).expect("the old client is addable");
    new.merge_pending().expect("merged");
    let mut old = old_device
        .join_welcome(&welcome)
        .expect("the old client joins");
    assert_eq!(old.epoch(), new.epoch());
    assert_eq!(old.epoch_authenticator(), new.epoch_authenticator());

    // They read each other, in both directions.
    let ciphertext = new.encrypt(b"from the new client").expect("ciphertext");
    assert_eq!(
        old.decrypt(&ciphertext).expect("decrypted").0,
        b"from the new client".to_vec()
    );
    let answer = old.encrypt(b"from the old client").expect("ciphertext");
    assert_eq!(
        new.decrypt(&answer).expect("decrypted").0,
        b"from the old client".to_vec()
    );

    // And the old client commits, which is the direction that actually breaks first when
    // compatibility is broken: reading is tolerant, but a commit rewrites the tree and
    // every member has to accept the leaf it writes.
    let commit = old.commit_pending().expect("a commit from the old client");
    assert!(matches!(
        new.process(&commit).expect("processed"),
        Processed::Commit { .. }
    ));
    old.merge_pending().expect("merged");
    assert_eq!(old.epoch_authenticator(), new.epoch_authenticator());

    // The new client commits back, and the old client, which advertises support for
    // nothing optional at all, must still be able to accept it.
    let third = device("third");
    let (commit, _) = new
        .add(&third.key_package().expect("a key package"))
        .expect("an add");
    assert!(matches!(
        old.process(&commit).expect("processed"),
        Processed::Commit { .. }
    ));
    new.merge_pending().expect("merged");
    assert_eq!(old.epoch_authenticator(), new.epoch_authenticator());
    assert_eq!(old.members(), new.members());
}

/// The leaf extensions a client from the future would carry: one type nobody here has
/// heard of, declared in its own capabilities, exactly as RFC 9420 requires of a leaf.
fn a_leaf_from_the_future() -> Extensions<LeafNode> {
    Extensions::<LeafNode>::single(Extension::Unknown(
        FROM_THE_FUTURE,
        UnknownExtension(b"whatever this turns out to mean".to_vec()),
    ))
    .expect("one extension")
}

#[test]
fn a_leaf_extension_this_build_has_never_heard_of_is_carried_rather_than_rejected() {
    // This test asserted the opposite when it was first written, and the assertion was
    // wrong about MLS rather than about this crate, so it was corrected rather than
    // softened. RFC 9420 requires a leaf's extensions to be listed in that leaf's own
    // capabilities; it does not require every other member to understand them. OpenMLS
    // enforces exactly that (`treesync/node/leaf_node.rs`, `validate_locally`) and checks
    // support across the group only for extensions in the *group context* and in
    // `required_capabilities`. Which is the whole point: if an unknown leaf extension were
    // rejected, no client could ever ship a new one without every peer upgrading first,
    // and forward compatibility would be impossible rather than merely untested.
    let old_device = device("old");
    let mut old = old_device.create_group(GROUP).expect("a group");

    let future_device = device("future");
    let key_package = key_package_advertising(
        &future_device,
        Capabilities::new(
            None,
            None,
            Some(&[ExtensionType::Unknown(FROM_THE_FUTURE)]),
            None,
            None,
        ),
        a_leaf_from_the_future(),
        Extensions::<KeyPackage>::default(),
    );

    let (_, welcome) = old
        .add(&key_package)
        .expect("a leaf from the future is addable");
    old.merge_pending().expect("merged");
    let mut future = future_device.join_welcome(&welcome).expect("joined");

    // And the group works, in both directions, with a leaf in the tree that this build
    // cannot interpret. That is the claim `wire.md` makes about forward compatibility,
    // asserted rather than assumed.
    assert_eq!(old.epoch_authenticator(), future.epoch_authenticator());
    let ciphertext = old.encrypt(b"from the older client").expect("ciphertext");
    assert_eq!(
        future.decrypt(&ciphertext).expect("decrypted").0,
        b"from the older client".to_vec()
    );
    let answer = future
        .encrypt(b"from the newer client")
        .expect("ciphertext");
    assert_eq!(
        old.decrypt(&answer).expect("decrypted").0,
        b"from the newer client".to_vec()
    );

    // Including a commit written by the older client, which rewrites the tree around a
    // leaf it does not understand and must leave it intact.
    let commit = old.commit_pending().expect("a commit");
    assert!(matches!(
        future.process(&commit).expect("processed"),
        Processed::Commit { .. }
    ));
    old.merge_pending().expect("merged");
    assert_eq!(old.epoch_authenticator(), future.epoch_authenticator());
}

#[test]
fn a_key_package_carrying_an_extension_its_own_leaf_does_not_support_is_refused_by_name() {
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");
    let epoch_before = ada.epoch();

    // The same unknown extension, but this time in the key package's own extensions with
    // a leaf that never claimed to support it. That is a self-inconsistent key package,
    // which is what a garbled or maliciously assembled forward-compatibility claim looks
    // like on the wire, and RFC 9420 requires it to be rejected.
    let future_device = device("future");
    let key_package = key_package_advertising(
        &future_device,
        Capabilities::default(),
        Extensions::<LeafNode>::default(),
        Extensions::<KeyPackage>::single(Extension::Unknown(
            FROM_THE_FUTURE,
            UnknownExtension(b"a claim the leaf never made".to_vec()),
        ))
        .expect("one extension"),
    );

    // Refused, by name. The thing being asserted is not that MLS says no, it is that our
    // seam turns that no into a typed `Protocol` status the Swift side can switch on,
    // rather than into a panic unwinding across a C ABI, which `mls-binding.md` calls
    // undefined behaviour. `Protocol` and not `Malformed`, because the bytes decoded
    // perfectly well: what failed was validation of what they said.
    let refused = ada
        .add(&key_package)
        .expect_err("a key package that contradicts itself");
    assert_eq!(refused.status(), Status::Protocol);

    // And the group is exactly where it was. A refused add that had already moved the
    // epoch would leave this device unable to talk to anybody, which is a worse failure
    // than the one it was refusing.
    assert_eq!(ada.epoch(), epoch_before);
    let bo_device = device("bo");
    let (_, welcome) = ada
        .add(&bo_device.key_package().expect("a key package"))
        .expect("an ordinary add still works");
    ada.merge_pending().expect("merged");
    let mut bo = bo_device.join_welcome(&welcome).expect("joined");
    let ciphertext = ada.encrypt(b"still usable").expect("ciphertext");
    assert_eq!(
        bo.decrypt(&ciphertext).expect("decrypted").0,
        b"still usable".to_vec()
    );
}

#[test]
fn a_message_that_claims_a_protocol_version_this_build_does_not_speak_is_refused_by_name() {
    let ada_device = device("ada");
    let mut ada = ada_device.create_group(GROUP).expect("a group");
    let bo_device = device("bo");
    let bo_package = bo_device.key_package().expect("a key package");
    let (_, welcome) = ada.add(&bo_package).expect("an add");
    ada.merge_pending().expect("merged");
    let mut bo = bo_device.join_welcome(&welcome).expect("joined");

    // Every MLSMessage on the wire starts with a two-byte protocol version. Bumping it is
    // the smallest possible thing a future release could do to a message, and it is what
    // a client one version ahead of this one would send if the version were ever bumped.
    let mut from_the_future = bo.encrypt(b"sent by a newer client").expect("ciphertext");
    from_the_future[0] = 0x00;
    from_the_future[1] = 0x02;

    // `Malformed` rather than `Protocol`, and the distinction is real rather than
    // incidental: the version is checked while the frame is being decoded, before anything
    // in it is treated as belonging to this group, so the honest answer is that the bytes
    // were not a message this build can read. `Protocol` would say the group refused it,
    // which is a different thing and would send a caller looking in the wrong place.
    let refused = ada
        .process(&from_the_future)
        .expect_err("a version this build does not speak");
    assert_eq!(refused.status(), Status::Malformed);

    // The same for a key package, which is the other structure that arrives from a peer
    // whose version we do not control.
    let mut package_from_the_future = bo_device.key_package().expect("a key package");
    package_from_the_future[0] = 0x00;
    package_from_the_future[1] = 0x02;
    let refused = ada
        .add(&package_from_the_future)
        .expect_err("a version this build does not speak");
    assert_eq!(refused.status(), Status::Malformed);

    // And the group is untouched by either. This is the half of forward compatibility that
    // matters operationally: one member on a newer release must not be able to stop
    // everybody else from talking, whether by accident or on purpose.
    let ciphertext = ada.encrypt(b"still talking").expect("ciphertext");
    assert_eq!(
        bo.decrypt(&ciphertext).expect("decrypted").0,
        b"still talking".to_vec()
    );
    let answer = bo.encrypt(b"still listening").expect("ciphertext");
    assert_eq!(
        ada.decrypt(&answer).expect("decrypted").0,
        b"still listening".to_vec()
    );
}
