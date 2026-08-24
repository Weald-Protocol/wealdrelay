// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! One group, one identity, one owner: the operations the ABI marshals to.
//!
//! Written as a Rust API rather than inside the `extern "C"` functions, for the reason
//! `specs/backend/relay/mls-binding.md` gives for keeping the seam at twelve functions:
//! everything that can be tested without a pointer should be. The FFI layer in `ffi.rs`
//! is then only marshalling, and the property suites in `tests/` drive this.
//!
//! Nothing here decides anything about the product. There is no envelope, no author
//! chain, no certificate and no retention rule: those are Swift's, and a decision that
//! leaked down here would be a product rule inside the component the audit scopes as
//! crypto.

use openmls::group::{MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, StagedWelcome};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize};
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, KeyPackage, KeyPackageBundle, LeafNodeIndex,
    MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProcessedMessageContent, ProtocolMessage,
    ProtocolVersion, RatchetTreeIn, Sender, SenderRatchetConfiguration,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider as _;

use rusqlite::OptionalExtension as _;
use std::rc::Rc;

use crate::status::{Error, Result};
use crate::store::Provider;

/// The one ciphersuite this build speaks.
///
/// `specs/backend/relay/mls-binding.md`: "No custom ciphersuite." One value, chosen from
/// RFC 9420's mandatory-to-implement set, so two clients cannot negotiate their way into
/// a combination nobody tested. A second ciphersuite is a protocol version change and
/// arrives through `wire.md`'s version negotiation, not through a config field.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// What a group is created or joined with.
#[derive(Debug, Clone)]
pub struct Config {
    /// Where the state lives. `:memory:` for the property suites.
    pub database: String,
    /// The credential identity: which principal this device signs as. Opaque bytes to
    /// this crate, and a device key to `specs/backend/relay/identity.md`.
    pub identity: Vec<u8>,
}

/// One device in one workspace: its provider, its identity, and its signing key.
///
/// The unit the storage is really about. A device belongs to several groups (a workspace
/// root, a channel, a ticket board) and all of them persist through one database and sign
/// with one identity key, so the provider and the signer live here and a ``Session``
/// borrows them.
///
/// The signing key is created on first use and **read back afterwards**. That is not an
/// optimisation: a device that minted a new key every time it opened its database would
/// have a new MLS identity on every launch, its own leaf would stop verifying, and the
/// group would see a member it cannot authenticate. The key lives in the provider's
/// storage, which is the encrypted database, and never crosses the boundary.
pub struct Device {
    provider: Rc<Provider>,
    credential: CredentialWithKey,
    signer: SignatureKeyPair,
}

impl Device {
    /// Open the database and load or create this identity's signing key.
    pub fn open(config: &Config) -> Result<Self> {
        if config.identity.is_empty() {
            return Err(Error::InvalidArgument("identity is empty".into()));
        }
        let provider = Rc::new(Provider::open(&config.database)?);
        let signer = load_or_create_signer(&provider, &config.identity)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(config.identity.clone()).into(),
            signature_key: signer.public().into(),
        };
        Ok(Self {
            provider,
            credential,
            signer,
        })
    }

    /// The provider, for the caller's own transaction across MLS and document state.
    pub fn provider(&self) -> &Provider {
        &self.provider
    }

    /// The identity this device signs as.
    pub fn identity(&self) -> Vec<u8> {
        self.credential.credential.serialized_content().to_vec()
    }

    /// The public signature key, which is what a peer's leaf carries.
    pub fn signature_key(&self) -> Vec<u8> {
        self.signer.public().to_vec()
    }

    /// Publish a key package, so somebody else can add this device to a group.
    ///
    /// The thirteenth function, and the reason it exists is written down in
    /// `specs/backend/relay/mls-binding.md`: the seam as first specified could consume a
    /// key package in `add` and could never produce one, so no device could be invited to
    /// anything. The private half stays in the provider's storage; what comes out is the
    /// public key package the relay already holds a count of (`wire.md`,
    /// `key_packages_remaining`).
    pub fn key_package(&self) -> Result<Vec<u8>> {
        let bundle: KeyPackageBundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                self.provider.as_ref(),
                &self.signer,
                self.credential.clone(),
            )
            .map_err(|error| Error::Protocol(error.to_string()))?;
        // Through the same ceiling every other outgoing message goes through, and for the
        // same reason: a key package is published to the relay in an envelope, so one over
        // `wire.md`'s ceiling is one no relay will hold and no joiner will ever see. The
        // identity in it is a caller's bytes from across the C ABI, which is the only way
        // a key package gets anywhere near a mebibyte, and telling that caller its
        // identity is too large is better than handing it bytes the transport refuses.
        serialize(&MlsMessageOut::from(bundle.key_package().clone()))
    }

    /// Create a group with this device as its only member.
    pub fn create_group(&self, group_id: &[u8]) -> Result<Session> {
        if group_id.is_empty() {
            return Err(Error::InvalidArgument("group id is empty".into()));
        }
        let create_config = MlsGroupCreateConfig::builder()
            // The tree travels in the group info, so a joiner that arrives by external
            // commit can build the same tree without asking anybody for it. Without this
            // the self-join path in `groups.md` needs an out-of-band ratchet tree, which
            // is a second thing to keep consistent.
            .use_ratchet_tree_extension(true)
            .ciphersuite(CIPHERSUITE)
            .build();
        let group = MlsGroup::new_with_group_id(
            self.provider.as_ref(),
            &self.signer,
            &create_config,
            openmls::group::GroupId::from_slice(group_id),
            self.credential.clone(),
        )
        .map_err(|error| Error::Protocol(error.to_string()))?;
        self.session(group)
    }

    /// Reopen a group this device is already a member of.
    ///
    /// The sixteenth function, and it is the one a client cannot live without. MLS
    /// state is durable: it is in this device's own database, written by every
    /// commit. Before this existed the only ways to hold a group were to create it
    /// or to join it, so a client that restarted could not get back to a group it
    /// was already in. It would either create a second group under the same id, or
    /// external-commit itself in again as a new leaf on every launch, and both are
    /// worse than an error: the first forks the workspace and the second grows the
    /// ratchet tree without bound.
    ///
    /// Answers `None` rather than an error when the group is not in the store,
    /// because "have I got this one" is a question a client asks on every launch and
    /// the negative answer is ordinary.
    pub fn open_group(&self, group_id: &[u8]) -> Result<Option<Session>> {
        if group_id.is_empty() {
            return Err(Error::InvalidArgument("group id is empty".into()));
        }
        let id = openmls::group::GroupId::from_slice(group_id);
        let group = MlsGroup::load(self.provider.storage(), &id)
            .map_err(|error| Error::Storage(error.to_string()))?;
        match group {
            Some(group) => self.session(group).map(Some),
            None => Ok(None),
        }
    }

    /// Join by welcome, which is the ordinary invite path.
    ///
    /// The fourteenth function, and the same reasoning: `add` produces a welcome for the
    /// joiner and the seam had no way to consume one. `join_external` covers the self-join
    /// of an `open` group and cannot stand in for it, because an invitee to a closed group
    /// never sees a group info.
    pub fn join_welcome(&self, welcome: &[u8]) -> Result<Session> {
        let message = decode(welcome)?;
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(Error::Malformed("not a welcome".into())),
        };
        let staged =
            StagedWelcome::new_from_welcome(self.provider.as_ref(), &join_config(), welcome, None)
                .map_err(|error| Error::Protocol(error.to_string()))?;
        let group = staged
            .into_group(self.provider.as_ref())
            .map_err(|error| Error::Protocol(error.to_string()))?;
        self.session(group)
    }

    /// Join by external commit, from a group info. The self-join path for an `open` group.
    ///
    /// Returns the commit the caller has to publish: until the group accepts it, this
    /// device is a member of a group nobody else knows it is in.
    pub fn join_external(&self, group_info: &[u8]) -> Result<(Session, Vec<u8>)> {
        let message = decode(group_info)?;
        let verifiable = match message.extract() {
            MlsMessageBodyIn::GroupInfo(info) => info,
            _ => return Err(Error::Malformed("not a group info".into())),
        };
        let (group, bundle) = MlsGroup::external_commit_builder()
            .build_group(self.provider.as_ref(), verifiable, self.credential.clone())
            .map_err(|error| Error::Protocol(error.to_string()))?
            // Infallible here, and the argument is exact rather than hopeful.
            // `load_psks` walks two proposal lists and touches storage only for a
            // `PreSharedKey` proposal it finds in one of them. The first list is the
            // builder's own proposals, and this crate adds none: `external_commit_builder`
            // is used bare. The second is the proposal store of the group being built,
            // which `build_group` creates empty a few lines earlier and nothing can reach
            // between there and here. So the loop body never runs, no storage call is
            // made, and the only value this can produce is an empty set of PSKs. A
            // `map_err` here would be an arm no test could ever reach, which is a worse
            // thing to ship than a stated invariant.
            .load_psks(self.provider.storage())
            .expect("an external commit this crate builds carries no pre-shared key proposal")
            .build(
                self.provider.rand(),
                self.provider.crypto(),
                &self.signer,
                // Every leaf already in the tree is acceptable to this device: the question
                // the callback answers is whether to trust the credentials in the group,
                // and that decision belongs to the access set and the roster one layer up
                // (`specs/backend/relay/identity.md`). A crypto layer inventing a second
                // membership policy would be a second place to disagree.
                |_| true,
            )
            .map_err(|error| Error::Protocol(error.to_string()))?
            .finalize(self.provider.as_ref())
            .map_err(|error| Error::Protocol(error.to_string()))?;
        let commit = bundle.into_commit();
        // Already merged, and not by this function. `finalize` above sets the group's
        // pending commit and merges it itself before it returns, so the group handed back
        // is already at the new epoch and its state is `Operational`. This function used
        // to merge again here; the second merge was a no-op that OpenMLS answers from the
        // `Operational` arm without touching storage, so it could not fail and could not
        // do anything either. It is gone rather than left as an unreachable error arm.
        // The property it was there for is the one that matters and it still holds: a
        // caller gets back a session it can use immediately, without having to process its
        // own commit first, which is what `tests/session.rs` asserts about the epoch of a
        // freshly external-joined session.
        let session = self.session(group)?;
        let bytes = serialize(&commit)?;
        Ok((session, bytes))
    }

    /// A session over one group, with its own read of the signing key.
    ///
    /// The key is read back out of the store rather than copied from this device, because
    /// `SignatureKeyPair` is deliberately neither `Clone` nor readable-in-parts outside
    /// upstream's test feature. That is the right call for a private key, and reading it
    /// from the encrypted store is the access path this crate already relies on.
    fn session(&self, group: MlsGroup) -> Result<Session> {
        let signer = SignatureKeyPair::read(
            self.provider.storage(),
            self.signer.public(),
            CIPHERSUITE.signature_algorithm(),
        )
        .ok_or_else(|| Error::Storage("this device's signing key is not in its store".into()))?;
        Ok(Session {
            provider: Rc::clone(&self.provider),
            signer,
            credential: self.credential.clone(),
            group,
        })
    }
}

/// One group, as one device sees it.
///
/// `Debug` names it and nothing more, for the reason ``store::Provider``'s does: the
/// fields are a signing key, a credential and OpenMLS group state, and a type that printed
/// them would be a type that leaks key material into whatever formatted it. Named at all
/// because a test asserting `expect_err` on a function that returns one needs it.
pub struct Session {
    provider: Rc<Provider>,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    group: MlsGroup,
}

/// What processing one message produced.
///
/// A flat, closed set, because the caller's decision tree is flat: either there is
/// plaintext to project, or the epoch moved, or a proposal is waiting for a commit.
#[derive(Debug, PartialEq, Eq)]
pub enum Processed {
    /// An application message, with the leaf that sent it.
    Application { plaintext: Vec<u8>, sender: u32 },
    /// A commit that has been merged. The epoch has moved.
    Commit { epoch: u64 },
    /// A proposal, now pending. Nothing has changed until it is committed.
    Proposal,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("epoch", &self.epoch())
            .field("leaf", &self.own_leaf())
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Device").finish_non_exhaustive()
    }
}

impl Session {
    // MARK: Membership

    /// One key package, from bytes, validated.
    ///
    /// Validated rather than trusted, because a key package arrives from the relay: the
    /// signature, the lifetime and the protocol version are all checked before this device
    /// commits a stranger into its group.
    fn read_key_package(&self, bytes: &[u8]) -> Result<KeyPackage> {
        let message = decode(bytes)?;
        match message.extract() {
            MlsMessageBodyIn::KeyPackage(package) => package
                .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|error| Error::Protocol(error.to_string())),
            _ => Err(Error::Malformed("not a key package".into())),
        }
    }

    /// Add a member, returning the commit for the group and the welcome for the joiner.
    pub fn add(&mut self, key_package: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let key_package = self.read_key_package(key_package)?;
        let (commit, welcome, _) = self
            .group
            .add_members(self.provider.as_ref(), &self.signer, &[key_package])
            .map_err(|error| Error::Protocol(error.to_string()))?;
        Ok((serialize(&commit)?, serialize(&welcome)?))
    }

    /// Remove members by leaf index, returning the commit.
    pub fn remove(&mut self, leaves: &[u32]) -> Result<Vec<u8>> {
        if leaves.is_empty() {
            return Err(Error::InvalidArgument("no leaf to remove".into()));
        }
        let indices: Vec<LeafNodeIndex> = leaves.iter().copied().map(LeafNodeIndex::new).collect();
        let (commit, _, _) = self
            .group
            .remove_members(self.provider.as_ref(), &self.signer, &indices)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        serialize(&commit)
    }

    /// Propose an add without committing it, for the case where the proposer is not the
    /// committer.
    ///
    /// A separate function from ``add`` because the two are different acts with different
    /// authority: `groups.md` lets a member propose and requires an admin to commit, and a
    /// caller that could only add-and-commit would have to hold admin rights to invite
    /// anybody.
    pub fn propose_add(&mut self, key_package: &[u8]) -> Result<Vec<u8>> {
        let key_package = self.read_key_package(key_package)?;
        let (proposal, _) = self
            .group
            .propose_add_member(self.provider.as_ref(), &self.signer, &key_package)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        serialize(&proposal)
    }

    /// Commit whatever proposals are pending, returning the commit.
    pub fn commit_pending(&mut self) -> Result<Vec<u8>> {
        let (commit, _, _) = self
            .group
            .commit_to_pending_proposals(self.provider.as_ref(), &self.signer)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        serialize(&commit)
    }

    /// Merge this device's own pending commit, after the relay has accepted it.
    ///
    /// Separate from producing the commit on purpose. A commit that was merged before the
    /// relay accepted it would leave this device an epoch ahead of everybody else, unable
    /// to decrypt what the group is still sending and unable to explain why. So the
    /// caller merges when the write is durable, which is the same ordering rule
    /// `wire.md` uses for the author chain.
    pub fn merge_pending(&mut self) -> Result<u64> {
        self.group
            .merge_pending_commit(self.provider.as_ref())
            .map_err(|error| Error::Protocol(error.to_string()))?;
        Ok(self.epoch())
    }

    /// Drop this device's own pending commit, after the relay refused it.
    ///
    /// The other half of ``merge_pending``, and the reason a caller can honestly wait for
    /// acceptance before advancing. Without it a refused commit is stuck: it cannot be
    /// merged, because the group never saw it, and it cannot be rebuilt, because OpenMLS
    /// refuses a second commit while one is pending. Clearing it returns the group to the
    /// epoch the rest of the group is still at, with the original proposals gone, so the
    /// caller rebuilds the membership change from scratch and publishes again.
    ///
    /// Idempotent on purpose: clearing when nothing is pending is not an error, because a
    /// failure path that has to know whether it got as far as producing a commit is a
    /// failure path with a second bug in it.
    pub fn clear_pending_commit(&mut self) -> Result<u64> {
        self.group
            .clear_pending_commit(self.provider.storage())
            .map_err(|error| Error::Storage(error.to_string()))?;
        Ok(self.epoch())
    }

    /// Delete this group from the device's store, leaving no trace of it.
    ///
    /// The escape for a join nobody accepted. ``Device::join_external`` writes the group
    /// through the provider before its commit has been anywhere, so a device whose
    /// external commit the relay refused finds that group again on its next launch, takes
    /// the resume path rather than the join path, and can never republish the commit that
    /// would have made it a member. Abandoning the group puts the device back where it
    /// was: not in the group, free to external-join again from a fresh group info.
    ///
    /// The session stays alive and is freed the ordinary way. What is deleted is the
    /// persisted state: a caller that went on using this handle would be operating on a
    /// group held only in memory, which is why every caller drops it immediately.
    pub fn abandon(&mut self) -> Result<()> {
        self.group
            .delete(self.provider.storage())
            .map_err(|error| Error::Storage(error.to_string()))
    }

    // MARK: Messages

    /// Process one message from the group: a commit, a proposal, or an application
    /// message.
    pub fn process(&mut self, message: &[u8]) -> Result<Processed> {
        let incoming = decode(message)?;
        let protocol: ProtocolMessage = incoming
            .try_into_protocol_message()
            .map_err(|error| Error::Malformed(error.to_string()))?;
        let processed = self
            .group
            .process_message(self.provider.as_ref(), protocol)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        let sender = match processed.sender() {
            Sender::Member(leaf) => leaf.u32(),
            // A message from outside the tree: an external join's commit, or an external
            // proposal. The leaf is meaningless for those and the caller is told so with
            // a sentinel rather than with a second shape, because the only caller that
            // cares is the one projecting an application message and those are always
            // from a member.
            _ => u32::MAX,
        };
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application) => {
                Ok(Processed::Application {
                    plaintext: application.into_bytes(),
                    sender,
                })
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                self.group
                    .merge_staged_commit(self.provider.as_ref(), *staged)
                    .map_err(|error| Error::Protocol(error.to_string()))?;
                Ok(Processed::Commit {
                    epoch: self.epoch(),
                })
            }
            ProcessedMessageContent::ProposalMessage(proposal) => {
                self.group
                    .store_pending_proposal(self.provider.storage(), *proposal)
                    .map_err(|error| Error::Storage(error.to_string()))?;
                Ok(Processed::Proposal)
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                self.group
                    .store_pending_proposal(self.provider.storage(), *proposal)
                    .map_err(|error| Error::Storage(error.to_string()))?;
                Ok(Processed::Proposal)
            }
        }
    }

    /// Encrypt an application message for the group.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let message = self
            .group
            .create_message(self.provider.as_ref(), &self.signer, plaintext)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        serialize(&message)
    }

    /// Decrypt an application message, refusing anything that is not one.
    ///
    /// A separate function from ``process`` because the caller's handling is different: a
    /// commit changes the group and has to be recorded in the same transaction as the
    /// documents it affects, while an application message is content. A caller that
    /// received a commit here has been handed a message on the wrong path, and saying so
    /// is better than quietly advancing an epoch inside a function called decrypt.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<(Vec<u8>, u32)> {
        match self.process(ciphertext)? {
            Processed::Application { plaintext, sender } => Ok((plaintext, sender)),
            Processed::Commit { .. } | Processed::Proposal => {
                Err(Error::Protocol("not an application message".into()))
            }
        }
    }

    // MARK: Exports

    /// The exporter, which is the only way key material leaves this crate.
    pub fn export(&self, label: &str, length: usize) -> Result<Vec<u8>> {
        if length == 0 {
            return Err(Error::InvalidArgument("export length is zero".into()));
        }
        // A ceiling, because the length is a number from the other side of a C ABI and an
        // exporter asked for four gigabytes would be a denial of service with extra
        // steps. Every use in this product is a key or a nonce.
        const MAX: usize = 1024;
        if length > MAX {
            return Err(Error::InvalidArgument(format!(
                "export length {length} is over {MAX}"
            )));
        }
        self.group
            .export_secret(self.provider.crypto(), label, &[], length)
            .map_err(|error| Error::Protocol(error.to_string()))
    }

    /// A group info a joiner can external-commit against.
    pub fn group_info(&mut self) -> Result<Vec<u8>> {
        let info = self
            .group
            .export_group_info(self.provider.crypto(), &self.signer, true)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        serialize(&info)
    }

    /// The current epoch.
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// The epoch authenticator: what two members compare to know they hold the same group
    /// state at this epoch.
    ///
    /// The seam in `mls-binding.md` calls this the tree hash. Corrected to the epoch
    /// authenticator, for two reasons and both are written down here rather than left as a
    /// silent substitution. OpenMLS exposes `MlsGroup::tree_hash` only behind its
    /// `test-utils` feature, and a shipping library that turned on another crate's test
    /// feature would be shipping code upstream does not treat as API. And the authenticator
    /// is the value RFC 9420 designed for exactly this comparison: it covers the whole
    /// epoch's state rather than the ratchet tree alone, so two members who agree on it
    /// agree about more than two who agree on a tree hash.
    pub fn epoch_authenticator(&self) -> Vec<u8> {
        self.group.epoch_authenticator().as_slice().to_vec()
    }

    /// This device's own leaf index.
    pub fn own_leaf(&self) -> u32 {
        self.group.own_leaf_index().u32()
    }

    /// The leaf indices currently in the group, sorted.
    pub fn members(&self) -> Vec<u32> {
        let mut leaves: Vec<u32> = self
            .group
            .members()
            .map(|member| member.index.u32())
            .collect();
        leaves.sort_unstable();
        leaves
    }

    /// The leaf indices currently in the group with the credential at each one,
    /// sorted by leaf.
    ///
    /// `members()` throws the credential away, and every caller above had to guess
    /// which principal a leaf belonged to from a signed side channel: a claim it
    /// published about itself, a replayed handshake log, or, at the very bottom,
    /// counting leaves and inferring the odd one out. A device admitted by an
    /// external commit publishes no `Add` on the admin's side, so none of those had
    /// anything to read and a removal stopped at `epochsRotated` for ever
    /// (WEALD-L335). The group's own ratchet tree has known this the whole time.
    ///
    /// The credential bytes are the same value ``identity`` returns for self, so a
    /// caller compares them directly against the principal it means to remove.
    pub fn member_identities(&self) -> Vec<(u32, Vec<u8>)> {
        let mut pairs: Vec<(u32, Vec<u8>)> = self
            .group
            .members()
            .map(|member| {
                (
                    member.index.u32(),
                    member.credential.serialized_content().to_vec(),
                )
            })
            .collect();
        pairs.sort_unstable_by_key(|pair| pair.0);
        pairs
    }

    /// The ratchet tree, for a joiner that needs it out of band.
    pub fn ratchet_tree(&self) -> Result<Vec<u8>> {
        // Through the same ceiling as every other outgoing message, because this one
        // travels the same way: a joiner that needs the tree out of band receives it in an
        // envelope, so a tree over `wire.md`'s ceiling is a tree that cannot be delivered.
        serialize(&RatchetTreeIn::from(self.group.export_ratchet_tree()))
    }

    /// The identity this session signs as, for a test that has to tell two sessions apart.
    pub fn identity(&self) -> Vec<u8> {
        self.credential.credential.serialized_content().to_vec()
    }

    /// The provider, for the caller's own transaction across MLS and document state.
    pub fn provider(&self) -> &Provider {
        &self.provider
    }
}

/// The join configuration, shared by both join paths.
///
/// The out-of-order tolerance is OpenMLS's default. It is a deliberate non-decision: the
/// relay numbers envelopes and the client reconciles them (`wire.md`), so messages arrive
/// in order far more often than in a peer-to-peer deployment, and a wider window would
/// only widen the state a receiver keeps.
fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .sender_ratchet_configuration(SenderRatchetConfiguration::default())
        .build()
}

/// The signing key for one identity: read back if this database has one, created and
/// stored if it does not.
///
/// The public half is derived from the identity deterministically so it can be found
/// again: OpenMLS's storage is keyed by public key, and a device reopening its database
/// has the identity bytes and nothing else. So the mapping lives in a table of ours,
/// beside OpenMLS's own, in the same database and the same transaction domain.
fn load_or_create_signer(provider: &Provider, identity: &[u8]) -> Result<SignatureKeyPair> {
    provider
        .connection()
        .execute(
            "create table if not exists weald_identity ( \
               identity blob primary key, \
               signature_key blob not null \
             )",
            [],
        )
        .map_err(|error| Error::Storage(error.to_string()))?;
    let existing: Option<Vec<u8>> = provider
        .connection()
        .query_row(
            "select signature_key from weald_identity where identity = ?1",
            [identity],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| Error::Storage(error.to_string()))?;

    if let Some(public) = existing {
        // Read back, and a miss here is a damaged database rather than a first run: the
        // mapping row says this identity has a key and the key store disagrees.
        return SignatureKeyPair::read(
            provider.storage(),
            &public,
            CIPHERSUITE.signature_algorithm(),
        )
        .ok_or_else(|| {
            Error::Storage(
                "the identity table names a signing key the key store does not have".into(),
            )
        });
    }

    // Infallible for the one signature scheme this build has, and the argument is about
    // upstream's code rather than about luck. `SignatureKeyPair::new` matches on the
    // scheme it is given: it returns `Err(UnsupportedSignatureScheme)` for anything that
    // is not P-256 or Ed25519, and for those two it returns `Ok` unconditionally, because
    // the generators it calls take no fallible step (`ed25519_dalek::SigningKey::generate`
    // panics rather than returning on a randomness failure, which is upstream's decision
    // and not this crate's to convert). The scheme here is not a parameter: it is
    // `CIPHERSUITE.signature_algorithm()`, and `CIPHERSUITE` is the one constant at the
    // top of this file, whose signature algorithm is Ed25519. There is no input, no
    // configuration and no wire data anywhere near this call, so the error arm it used to
    // carry was one no test and no attacker could reach.
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
        .expect("the crate's one ciphersuite signs with Ed25519, which is always supported");
    signer
        .store(provider.storage())
        .map_err(|error| Error::Storage(error.to_string()))?;
    provider
        .connection()
        .execute(
            "insert into weald_identity (identity, signature_key) values (?1, ?2)",
            rusqlite::params![identity, signer.public()],
        )
        .map_err(|error| Error::Storage(error.to_string()))?;
    Ok(signer)
}

/// Deserialise one incoming MLS message, treating a panic in the decoder as malformed
/// input.
///
/// The `catch_unwind` is here because of a real finding, and it is worth writing down
/// rather than leaving as an unexplained wrapper. `tls_codec` 0.4.2 carries a
/// `debug_assert!(len_len_log <= MAX_LEN_LEN_LOG)` in `calculate_length`, reachable from
/// the length prefix of any variable-length vector, which is to say reachable from the
/// first two bits of a message an attacker chose. Upstream guards it with
/// `if !cfg!(fuzzing)`, which silences their fuzzer without removing the assert, so the
/// panic is known and still live for everybody else.
///
/// That produced two problems, and the second is the one that matters:
///
/// 1. In a debug build, `process` on hostile bytes panicked instead of answering
///    `Malformed`. The boundary guard caught it, so nothing unwound into Swift, but the
///    caller was told `Panicked`, which means "this handle is unusable, free it". An
///    attacker who can send one malformed byte should not be able to make a client tear
///    down a group.
/// 2. Debug and release disagreed. `debug_assert!` compiles out with assertions off, so
///    the shipped XCFramework returned `Malformed` and every test ran the other path. A
///    suite that never executes production's code path is a suite that proves less than
///    it claims, and this is exactly the divergence `specs/backend/build/README.md`
///    refuses between environments.
///
/// Catching it here makes the two agree, and the mapping is honest rather than a
/// convenience: a panic raised by a pure decoder, on bytes it was asked to decode, is
/// that decoder saying the bytes are not what they claimed to be. There is no state to
/// corrupt, because nothing has been written yet. A panic anywhere past this point still
/// reaches the boundary guard and is still reported as `Panicked`, which is the correct
/// answer there, because past this point there is state.
fn decode(bytes: &[u8]) -> Result<MlsMessageIn> {
    let parsed = std::panic::catch_unwind(|| MlsMessageIn::tls_deserialize_exact(bytes));
    match parsed {
        Ok(Ok(message)) => Ok(message),
        Ok(Err(error)) => Err(Error::Malformed(error.to_string())),
        Err(_) => Err(Error::Malformed(
            "the tls decoder panicked on this input".into(),
        )),
    }
}

/// One outgoing message as bytes.
///
/// Length-checked before serialisation, because `tls_serialize_detached` on a message
/// larger than the wire format's own bound would produce bytes no peer can read, and a
/// caller that sent them would get a refusal from the relay rather than from here.
///
/// Generic over what is being sent rather than written three times. Everything this crate
/// hands out leaves in an envelope: a commit, a welcome, a group info, a key package, a
/// ratchet tree. They are different TLS structures and the same wire, so they get the same
/// ceiling and the same refusal, and there is one place to change when `wire.md`'s ceiling
/// changes.
fn serialize<M: Serialize>(message: &M) -> Result<Vec<u8>> {
    let size = message.tls_serialized_len();
    // One mebibyte, which is `wire.md`'s envelope ceiling. A message over it is a message
    // the transport will refuse, so refusing it here names the real reason.
    const MAX: usize = 1 << 20;
    if size > MAX {
        return Err(Error::InvalidArgument(format!(
            "message is {size} bytes, over the {MAX} byte ceiling"
        )));
    }
    // Infallible past the check above, and the argument is about `tls_codec` rather than
    // about optimism. `tls_serialize_detached` writes into a `Vec<u8>`, whose `io::Write`
    // never fails, so the only error it can produce is `tls_codec`'s own
    // `InvalidVectorLength`, raised when a variable-length vector is asked to encode more
    // than the format's bound of 2^30 - 1 bytes. A structure whose total serialised
    // length is at most 2^20 cannot contain a vector of 2^30, and `tls_serialized_len` is
    // that total, computed by the same derived implementation that does the writing. So
    // the ceiling check above is what rules the error out, and past it there is nothing
    // left to report.
    Ok(message
        .tls_serialize_detached()
        .expect("a structure under the wire ceiling has no vector over the tls length bound"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::Status;
    use openmls::prelude::{GroupEpoch, GroupId, JoinProposal};

    /// One device against its own in-memory database, which is the same storage provider
    /// and the same SQL a file gets.
    fn device(identity: &str) -> Device {
        Device::open(&Config {
            database: ":memory:".to_string(),
            identity: identity.as_bytes().to_vec(),
        })
        .expect("a device")
    }

    /// One device against a database at `path`, for the cases that are about what is on
    /// disk when the device is opened a second time.
    fn device_at(path: &std::path::Path, identity: &str) -> Result<Device> {
        Device::open(&Config {
            database: path.to_str().expect("utf-8 path").to_string(),
            identity: identity.as_bytes().to_vec(),
        })
    }

    const GROUP: &[u8] = b"weald-session-unit";

    /// A device whose identity is `size` bytes long, for the cases about the wire ceiling.
    ///
    /// The identity is the one field of a key package a caller controls the size of, and
    /// it arrives from Swift across the C ABI, so a large one is a caller's input rather
    /// than an invented shape.
    fn a_device_with_an_identity_of(size: usize) -> Device {
        Device::open(&Config {
            database: ":memory:".to_string(),
            identity: vec![b'i'; size],
        })
        .expect("a device")
    }

    /// This device's key package without the wire ceiling in the way.
    ///
    /// The same three calls ``Device::key_package`` makes, minus the ceiling, because the
    /// case being built is a key package that arrives from a peer whose build did not
    /// apply one. A relay hands over what it was given, so a member has to be able to
    /// survive being handed one of these.
    fn an_unchecked_key_package(device: &Device) -> Vec<u8> {
        let bundle: KeyPackageBundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                device.provider.as_ref(),
                &device.signer,
                device.credential.clone(),
            )
            .expect("a key package");
        MlsMessageOut::from(bundle.key_package().clone())
            .tls_serialize_detached()
            .expect("bytes")
    }

    /// Replace the private half of this device's stored signing key with bytes that are
    /// still a well-formed stored key pair and are not an Ed25519 private key.
    ///
    /// What a partially restored or bit-rotted workspace database looks like from the
    /// inside. The row is still there, the public half still matches the identity table,
    /// and every read succeeds; only signing fails. That is the case a device cannot
    /// detect by looking, which is why the seam has to answer it as a status.
    fn damage_the_private_half_of_the_stored_signing_key(provider: &Provider) {
        let stored: Vec<u8> = provider
            .connection()
            .query_row(
                "select signature_key from openmls_signature_keys",
                [],
                |row| row.get(0),
            )
            .expect("a stored signing key");
        let mut key: serde_json::Value = serde_json::from_slice(&stored).expect("stored as json");
        key["private"] = serde_json::json!([0, 1, 2]);
        let damaged = serde_json::to_vec(&key).expect("json");
        let updated = provider
            .connection()
            .execute(
                "update openmls_signature_keys set signature_key = ?1",
                rusqlite::params![damaged],
            )
            .expect("an update");
        assert_eq!(updated, 1, "there was exactly one signing key to damage");
    }

    /// A welcome whose epoch keys have nowhere to go is refused at the join.
    ///
    /// The welcome path has two halves and they fail differently. Staging reads this
    /// device's key package and decrypts the group secrets; turning the staged welcome
    /// into a group is the first thing that writes, and the first thing it writes is the
    /// epoch key pairs. A device that returned a session from a join it could not persist
    /// would be in the group until it relaunched and then silently not, which is the
    /// failure `specs/backend/relay/mls-binding.md` puts the whole storage provider under.
    /// The table is dropped after the migration has recorded that it ran, which is what a
    /// partial restore of a workspace container looks like.
    #[test]
    fn a_welcome_whose_epoch_keys_have_nowhere_to_go_is_refused_when_the_group_is_built() {
        let ada_device = device("ada");
        let mut ada = ada_device.create_group(GROUP).expect("a group");
        let bo_device = device("bo");
        let package = bo_device.key_package().expect("a key package");
        let (_, welcome) = ada.add(&package).expect("an add");
        ada.merge_pending().expect("merged");

        // Only the epoch key pairs: staging the welcome does not touch this table, so this
        // is the write that fails and not an earlier one.
        bo_device
            .provider()
            .connection()
            .execute("drop table openmls_epoch_keys_pairs", [])
            .expect("a drop");
        let error = bo_device.join_welcome(&welcome).expect_err("refused");
        assert_eq!(error.status(), Status::Protocol);
        // OpenMLS wraps a storage failure from this call in its own welcome error, which
        // is as much detail as the seam can honestly pass on, so what is asserted is that
        // the caller learns it was the storage that refused rather than the peer.
        assert!(
            error.to_string().contains("storage"),
            "the error has to say the storage refused: {error}"
        );

        // Ada, whose database is intact, is unaffected: the failed join is the joiner's
        // problem and not a group-wide one.
        assert_eq!(ada.members(), vec![0, 1]);
    }

    /// A session whose stored signing key is damaged cannot export a group info, and says
    /// so rather than publishing something unsigned.
    ///
    /// ``Device::session`` reads the signing key back out of the store for every group, so
    /// a key that reads but does not sign produces a session that looks healthy until it
    /// is asked to sign. A group info is signed by the exporter and is the thing a joiner
    /// external-commits against (`specs/backend/relay/groups.md`), so a failure here has
    /// to reach the caller as a status: the alternative is a device that keeps offering a
    /// join path nobody can complete.
    #[test]
    fn a_session_whose_stored_signing_key_is_damaged_cannot_export_a_group_info() {
        let ada_device = device("ada");
        let mut ada = ada_device.create_group(GROUP).expect("a group");
        let bo_device = device("bo");
        let package = bo_device.key_package().expect("a key package");
        let (_, welcome) = ada.add(&package).expect("an add");
        ada.merge_pending().expect("merged");

        // Damaged after the key package was published and before the session is opened,
        // which is the order a restore produces: the group the device is being invited to
        // is older than the damage.
        damage_the_private_half_of_the_stored_signing_key(bo_device.provider());
        let mut bo = bo_device.join_welcome(&welcome).expect("joined");

        let error = bo.group_info().expect_err("refused");
        assert_eq!(error.status(), Status::Protocol);
        assert!(
            error.to_string().to_lowercase().contains("sign"),
            "the error has to name the signing failure: {error}"
        );

        // Everything that does not need the private half still works, which is what makes
        // this the hard case: the device can read the group it can no longer speak in.
        assert_eq!(bo.members(), vec![0, 1]);
        assert_eq!(bo.epoch_authenticator(), ada.epoch_authenticator());
        let line = ada.encrypt(b"still readable").expect("ciphertext");
        assert_eq!(
            bo.decrypt(&line).expect("decrypted").0,
            b"still readable".to_vec()
        );
    }

    /// A device whose stored signing key is damaged cannot build an external commit.
    ///
    /// The other half of the same damage, on the join path that signs before it has a
    /// session at all: an external commit is signed by the joiner, so the failure is
    /// inside OpenMLS's commit builder rather than at an export. It reaches the caller as
    /// a protocol status, and the device it happened to is still able to open its own
    /// database, which is why the failure has to be reported rather than assumed away by
    /// a device that came up successfully.
    #[test]
    fn a_device_whose_stored_signing_key_is_damaged_cannot_build_an_external_commit() {
        let ada_device = device("ada");
        let mut ada = ada_device.create_group(GROUP).expect("a group");
        let group_info = ada.group_info().expect("a group info");

        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("damaged-signer.sqlite");
        let cy_device = device_at(&path, "cy").expect("a device");
        damage_the_private_half_of_the_stored_signing_key(cy_device.provider());
        drop(cy_device);

        // Reopened, so the damaged key is the one this device signs with rather than one
        // it merely has on disk.
        let cy_device = device_at(&path, "cy").expect("a reopened device");
        let error = cy_device.join_external(&group_info).expect_err("refused");
        assert_eq!(error.status(), Status::Protocol);

        // Nobody joined: Ada's group is where it was.
        assert_eq!(ada.members(), vec![0]);
        assert_eq!(ada.epoch(), 0);
    }

    /// An external join cannot open a session over a group whose device lost its signing
    /// key.
    ///
    /// The same read-back ``Device::session`` does on every path, on the path that reaches
    /// it last: the external commit is built and the group is written before the session
    /// is asked for. A session handed back without a signer would be a handle that fails
    /// at the first message, inside OpenMLS, with an error about a key rather than about a
    /// database, and the device would already have published a commit for a group it
    /// cannot use.
    #[test]
    fn an_external_join_cannot_open_a_session_when_the_key_store_lost_the_signing_key() {
        let ada_device = device("ada");
        let mut ada = ada_device.create_group(GROUP).expect("a group");
        let group_info = ada.group_info().expect("a group info");

        let cy_device = device("cy");
        let removed = cy_device
            .provider()
            .connection()
            .execute("delete from openmls_signature_keys", [])
            .expect("a delete");
        assert_eq!(removed, 1, "there was exactly one signing key to lose");

        let error = cy_device.join_external(&group_info).expect_err("refused");
        assert_eq!(error.status(), Status::Storage);
        assert!(
            error
                .to_string()
                .contains("signing key is not in its store"),
            "the error has to name what is missing: {error}"
        );
    }

    /// Both halves of what an add produces are held to the wire ceiling.
    ///
    /// `add` returns a commit for the group and a welcome for the joiner, and either one
    /// can be the one that is too large: the commit carries the joiner's key package, and
    /// the welcome carries a group info with the whole ratchet tree in it. `wire.md` puts
    /// both in an envelope with a one mebibyte ceiling, so a caller that was handed either
    /// would get a refusal from the relay instead of from here, with no way to tell which
    /// of the two was the problem. The key package in the first case is minted without
    /// this build's own ceiling, because it stands for one that arrived from a peer whose
    /// build did not apply one.
    #[test]
    fn a_commit_and_a_welcome_are_both_held_to_the_wire_ceiling_by_add() {
        // The commit: the joiner's key package is over the ceiling on its own.
        let ada_device = device("ada");
        let mut ada = ada_device.create_group(GROUP).expect("a group");
        let huge = a_device_with_an_identity_of((1 << 20) + 4096);
        let package = an_unchecked_key_package(&huge);
        assert!(package.len() > (1 << 20), "the case needs an oversized one");
        let error = ada.add(&package).expect_err("refused");
        assert_eq!(error.status(), Status::InvalidArgument);
        assert!(
            error.to_string().contains("1048576"),
            "the ceiling has to be in the message: {error}"
        );

        // The welcome: two members whose identities are each well under the ceiling, and a
        // ratchet tree carrying both of them that is not.
        let ada_device = device("ada");
        let mut ada = ada_device.create_group(GROUP).expect("a group");
        let bo = a_device_with_an_identity_of(700_000);
        let first = bo.key_package().expect("a key package");
        assert!(first.len() < (1 << 20));
        ada.add(&first).expect("an add under the ceiling");
        ada.merge_pending().expect("merged");

        let cy = a_device_with_an_identity_of(700_000);
        let second = cy.key_package().expect("a key package");
        let error = ada.add(&second).expect_err("refused");
        assert_eq!(error.status(), Status::InvalidArgument);
        assert!(
            error.to_string().contains("1048576"),
            "the ceiling has to be in the message: {error}"
        );
    }

    /// A name collision that `if not exists` cannot absorb is a storage error at the
    /// create.
    ///
    /// The workspace database is shared with the search index by `mls-binding.md`, so
    /// something else can already own the name `weald_identity`. SQLite keeps tables,
    /// views, indexes and triggers in one namespace but `create table if not exists` only
    /// forgives a table, so an index by that name is a hard error at the first statement
    /// ``load_or_create_signer`` runs. That is the one statement of the three whose
    /// failure a device cannot recover from by trying the next one, and it has to arrive
    /// as a status rather than as an unwrap on a shared file.
    #[test]
    fn a_name_collision_that_if_not_exists_cannot_absorb_is_refused_at_the_create() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("indexed.sqlite");
        {
            let connection = rusqlite::Connection::open(&path).expect("a connection");
            connection
                .execute("create table somebody_elses (identity blob)", [])
                .expect("a table");
            connection
                .execute(
                    "create index weald_identity on somebody_elses (identity)",
                    [],
                )
                .expect("an index");
        }

        let error = device_at(&path, "ada").expect_err("refused");
        assert_eq!(error.status(), Status::Storage);
        assert!(
            error.to_string().contains("index"),
            "the error has to name what owns the name: {error}"
        );
    }

    /// Ada alone, and Bo joined by the ordinary welcome path. The shape most of the cases
    /// below need before they can damage something.
    fn a_pair() -> (Device, Session, Device, Session) {
        let ada_device = device("ada");
        let mut ada = ada_device.create_group(GROUP).expect("a group");
        let bo_device = device("bo");
        let package = bo_device.key_package().expect("a key package");
        let (_, welcome) = ada.add(&package).expect("an add");
        ada.merge_pending().expect("merged");
        let bo = bo_device.join_welcome(&welcome).expect("joined");
        (ada_device, ada, bo_device, bo)
    }

    /// An external join proposal is queued and the commit that follows carries the joiner.
    ///
    /// The fourth arm of ``Session::process``, and the one a member reaches without ever
    /// having produced it: `specs/backend/relay/groups.md`'s `open` group lets a device
    /// ask to be added instead of joining by external commit, and the relay hands that
    /// proposal to every member. RFC 9420 gives it its own sender kind, so OpenMLS gives
    /// it its own processed content, and a binding that only handled the three ordinary
    /// arms would refuse a message the protocol says is well formed.
    ///
    /// Built here rather than in `tests/` because a join proposal is signed by the joiner
    /// and a ``Device``'s signing key deliberately never leaves this module.
    #[test]
    fn an_external_join_proposal_is_queued_and_the_commit_that_follows_adds_the_joiner() {
        let ada_device = device("ada");
        let mut ada = ada_device.create_group(GROUP).expect("a group");

        let bo_device = device("bo");
        let bytes = bo_device.key_package().expect("a key package");
        let package = ada.read_key_package(&bytes).expect("a valid key package");
        let proposal = JoinProposal::new::<crate::store::Storage>(
            package,
            GroupId::from_slice(GROUP),
            GroupEpoch::from(ada.epoch()),
            &bo_device.signer,
        )
        .expect("an external join proposal");
        let proposal = proposal.tls_serialize_detached().expect("bytes");

        // Queued, not applied: nothing about the group has changed yet, which is the whole
        // point of a proposal arriving from outside the tree.
        assert_eq!(
            ada.process(&proposal).expect("processed"),
            Processed::Proposal
        );
        assert_eq!(ada.members(), vec![0]);
        assert_eq!(ada.epoch(), 0);

        // And the commit a member makes afterwards really carries it: Bo is in the tree.
        ada.commit_pending().expect("a commit");
        ada.merge_pending().expect("merged");
        assert_eq!(ada.members(), vec![0, 1]);
        assert_eq!(ada.epoch(), 1);
    }

    /// A device reopening its database reads its signing key back rather than minting a
    /// second one.
    ///
    /// The property ``Device``'s own documentation is about, asserted against a real file
    /// rather than assumed: a device that made a new key on every launch would present a
    /// new MLS identity to a group that already knows its leaf, and every peer would see a
    /// member it cannot authenticate. Two identities in one database keep their own keys,
    /// because a workspace container holds one file and `identity.md` puts more than one
    /// device key in it over a device's life.
    #[test]
    fn a_reopened_device_reads_its_signing_key_back_rather_than_minting_a_second_one() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("device.sqlite");

        let first = device_at(&path, "ada").expect("a device");
        let key = first.signature_key();
        drop(first);

        let again = device_at(&path, "ada").expect("a reopened device");
        assert_eq!(again.signature_key(), key, "the same device, the same leaf");
        assert_eq!(again.identity(), b"ada".to_vec());

        // A different identity in the same file is a different key, or the mapping table
        // would be answering the wrong question.
        let other = device_at(&path, "bo").expect("a second identity");
        assert_ne!(other.signature_key(), key);
    }

    /// An identity row that names a signing key the key store does not have is a damaged
    /// database, and it is reported as one.
    ///
    /// Two tables have to agree: ours maps an identity to a public key, OpenMLS's holds
    /// the private half. A device that answered "first run" when the second table came
    /// back empty would silently mint a new identity for a device that already has a leaf
    /// in a group, which is the failure `Device`'s documentation exists to prevent. So the
    /// disagreement is a storage error that names both sides, and the row is destroyed
    /// here with real SQL against the same database, because that is what a truncated
    /// file or a partial restore looks like.
    #[test]
    fn an_identity_naming_a_signing_key_the_store_does_not_have_is_a_damaged_database() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("damaged.sqlite");

        let first = device_at(&path, "ada").expect("a device");
        let removed = first
            .provider()
            .connection()
            .execute("delete from openmls_signature_keys", [])
            .expect("a delete");
        assert_eq!(removed, 1, "there was exactly one signing key to lose");
        drop(first);

        let error = device_at(&path, "ada").expect_err("refused");
        assert_eq!(error.status(), Status::Storage);
        assert!(
            error.to_string().contains("key store does not have"),
            "the error has to name the disagreement: {error}"
        );

        // And it is the damaged case rather than the first-run case wearing its clothes:
        // the mapping row this build wrote is still on disk, still naming a key.
        let connection = rusqlite::Connection::open(&path).expect("a connection");
        let rows: i64 = connection
            .query_row("select count(*) from weald_identity", [], |row| row.get(0))
            .expect("a count");
        assert_eq!(rows, 1);
    }

    /// A session cannot be opened over a group whose device lost its signing key.
    ///
    /// ``Device::session`` reads the key back out of the store for every group rather than
    /// copying it, so the same damaged database shows up a second time, on a different
    /// path, and has to be a status there too. A group handed back without a signer would
    /// be a handle that fails at the first commit, inside OpenMLS, with an error about a
    /// key rather than about a database.
    #[test]
    fn a_group_cannot_be_opened_when_the_key_store_lost_this_devices_signing_key() {
        let ada_device = device("ada");
        ada_device
            .provider()
            .connection()
            .execute("delete from openmls_signature_keys", [])
            .expect("a delete");
        let error = ada_device.create_group(GROUP).expect_err("refused");
        assert_eq!(error.status(), Status::Storage);
        assert!(
            error
                .to_string()
                .contains("signing key is not in its store"),
            "the error has to name what is missing: {error}"
        );
    }

    /// An identity table that is not the one this build wrote is a storage error at every
    /// step, rather than a panic or a silent second identity.
    ///
    /// The workspace database is shared with the search index by `mls-binding.md`, so a
    /// name collision is a real state a device can be handed: an older build, a partial
    /// restore, or somebody else's table. Each of the three statements
    /// ``load_or_create_signer`` runs can be the one that finds it, and all three have to
    /// arrive as `Storage` rather than as an unwrap.
    #[test]
    fn an_identity_table_this_build_did_not_write_is_a_storage_error_at_every_step() {
        let dir = tempfile::tempdir().expect("a temp dir");

        // A view by that name: the create cannot even run.
        let occupied = dir.path().join("view.sqlite");
        {
            let connection = rusqlite::Connection::open(&occupied).expect("a connection");
            connection
                .execute("create view weald_identity as select 1 as identity", [])
                .expect("a view");
        }
        let error = device_at(&occupied, "ada").expect_err("refused");
        assert_eq!(error.status(), Status::Storage);

        // A table by that name without the column the read needs.
        let narrow = dir.path().join("narrow.sqlite");
        {
            let connection = rusqlite::Connection::open(&narrow).expect("a connection");
            connection
                .execute(
                    "create table weald_identity (identity blob primary key)",
                    [],
                )
                .expect("a table");
        }
        let error = device_at(&narrow, "ada").expect_err("refused");
        assert_eq!(error.status(), Status::Storage);

        // A table by that name that the write cannot satisfy.
        let strict = dir.path().join("strict.sqlite");
        {
            let connection = rusqlite::Connection::open(&strict).expect("a connection");
            connection
                .execute(
                    "create table weald_identity ( \
                       identity blob primary key, \
                       signature_key blob not null, \
                       written_by text not null \
                     )",
                    [],
                )
                .expect("a table");
        }
        let error = device_at(&strict, "ada").expect_err("refused");
        assert_eq!(error.status(), Status::Storage);

        // And a database that cannot be opened at all is refused by `Device::open` before
        // any of that, so the caller is never handed a device over nothing.
        let error = device_at(dir.path(), "ada").expect_err("refused");
        assert_eq!(error.status(), Status::Storage);
    }

    /// A device whose key tables are gone cannot publish a key package, and says so.
    ///
    /// `key_package` writes the private half into the store before it hands the public
    /// half out. A store that cannot take it must fail here, because the alternative is
    /// publishing a key package whose private half nobody has: a joiner would encrypt a
    /// welcome to it and this device could never open it, and the failure would surface
    /// as an unexplained join refusal on somebody else's machine.
    #[test]
    fn a_device_whose_key_tables_are_gone_cannot_publish_a_key_package() {
        let ada_device = device("ada");
        ada_device
            .provider()
            .connection()
            .execute("drop table openmls_key_packages", [])
            .expect("a drop");
        let error = ada_device.key_package().expect_err("refused");
        assert_eq!(error.status(), Status::Protocol);
    }

    /// A key store that lost its table between two launches refuses the second one.
    ///
    /// The migration records that it has run, so a table dropped afterwards is not
    /// recreated: this is what a partial restore of a workspace container looks like from
    /// the inside. The device must refuse rather than come up with a signing key it cannot
    /// persist, because a key that is only in memory is a key the next launch will not
    /// have.
    #[test]
    fn a_key_store_that_lost_its_table_between_launches_refuses_to_create_a_signer() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("lost-table.sqlite");

        let first = device_at(&path, "ada").expect("a device");
        first
            .provider()
            .connection()
            .execute("drop table openmls_signature_keys", [])
            .expect("a drop");
        drop(first);

        // A second identity, so this is the create path rather than the read-back path.
        let error = device_at(&path, "bo").expect_err("refused");
        assert_eq!(error.status(), Status::Storage);
    }

    /// A storage failure while a proposal is being queued is reported, and the group is
    /// still usable afterwards.
    ///
    /// `store_pending_proposal` is the one write `process` makes on the proposal paths,
    /// and both of them (a member's proposal and an outsider's join proposal) have to
    /// answer `Storage` rather than claim the proposal is pending. A caller told the
    /// proposal was stored would commit to a proposal set the database does not have, and
    /// the commit would not match what any other member built.
    #[test]
    fn a_storage_failure_while_queueing_a_proposal_is_reported_rather_than_claimed_stored() {
        let (_ada_device, mut ada, bo_device, mut bo) = a_pair();

        let cy_device = device("cy");
        let cy_package = cy_device.key_package().expect("a key package");
        let proposal = ada.propose_add(&cy_package).expect("a proposal");

        bo.provider()
            .connection()
            .execute("drop table openmls_proposals", [])
            .expect("a drop");
        let error = bo.process(&proposal).expect_err("refused");
        assert_eq!(error.status(), Status::Storage);
        // Nothing was applied, so the two sides still agree about the group.
        assert_eq!(bo.epoch(), ada.epoch());
        assert_eq!(bo.epoch_authenticator(), ada.epoch_authenticator());

        // And the same for a proposal that arrives from outside the tree.
        let dee_device = device("dee");
        let bytes = dee_device.key_package().expect("a key package");
        let package = ada.read_key_package(&bytes).expect("a valid key package");
        let join = JoinProposal::new::<crate::store::Storage>(
            package,
            GroupId::from_slice(GROUP),
            GroupEpoch::from(bo.epoch()),
            &dee_device.signer,
        )
        .expect("an external join proposal")
        .tls_serialize_detached()
        .expect("bytes");
        let error = bo.process(&join).expect_err("refused");
        assert_eq!(error.status(), Status::Storage);

        // Bo's session is still a session: a refused write is not a poisoned handle.
        assert_eq!(bo.members(), vec![0, 1]);
        drop(bo_device);
    }

    /// A storage failure while a commit is being merged is reported rather than swallowed.
    ///
    /// `merge_staged_commit` writes the new group state before anything else, and the
    /// crash rule in `mls-binding.md` is that the epoch on disk and the epoch in memory
    /// agree. A merge that failed to write and returned success would leave this device an
    /// epoch ahead of its own database, which is the exact divergence the crash-injection
    /// gate exists to rule out.
    #[test]
    fn a_storage_failure_while_merging_a_commit_is_reported() {
        let (_ada_device, mut ada, _bo_device, mut bo) = a_pair();

        let cy_device = device("cy");
        let cy_package = cy_device.key_package().expect("a key package");
        let (commit, _) = ada.add(&cy_package).expect("an add");
        ada.merge_pending().expect("merged");

        bo.provider()
            .connection()
            .execute("drop table openmls_group_data", [])
            .expect("a drop");
        let error = bo.process(&commit).expect_err("refused");
        // Reported, and the reason survives into the message a log line will carry:
        // OpenMLS wraps the storage failure in its own merge error, so the status this
        // crate can honestly give is `Protocol`, and the table that went missing is named
        // in the text rather than lost.
        assert_eq!(error.status(), Status::Protocol);
        assert!(
            error.to_string().contains("openmls_group_data"),
            "the error has to name what failed: {error}"
        );
    }

    /// A storage failure on either join path is reported rather than producing a group
    /// this device cannot persist.
    ///
    /// Both joins end in a write: the welcome path stages a group and then commits it to
    /// storage, and the external-commit path finalises one and merges its own commit. A
    /// join that returned a session it could not store would be a device that is in a
    /// group until it is relaunched, and then silently is not.
    #[test]
    fn a_storage_failure_on_either_join_path_is_reported() {
        let ada_device = device("ada");
        let mut ada = ada_device.create_group(GROUP).expect("a group");

        let bo_device = device("bo");
        let package = bo_device.key_package().expect("a key package");
        let (_, welcome) = ada.add(&package).expect("an add");
        ada.merge_pending().expect("merged");
        bo_device
            .provider()
            .connection()
            .execute("drop table openmls_group_data", [])
            .expect("a drop");
        let error = bo_device.join_welcome(&welcome).expect_err("refused");
        assert_eq!(error.status(), Status::Protocol);

        // The self-join of an `open` group, damaged the same way.
        let group_info = ada.group_info().expect("a group info");
        let cy_device = device("cy");
        cy_device
            .provider()
            .connection()
            .execute("drop table openmls_own_leaf_nodes", [])
            .expect("a drop");
        let error = cy_device.join_external(&group_info).expect_err("refused");
        assert_eq!(error.status(), Status::Protocol);

        // Ada, who never touched a damaged database, is unaffected by either.
        assert_eq!(ada.members(), vec![0, 1]);
        assert!(!ada.encrypt(b"still here").expect("ciphertext").is_empty());
    }

    /// The byte that used to panic, pinned forever.
    ///
    /// `tls_codec` 0.4.2 reads the top two bits of a length prefix as a log-scale length
    /// and `debug_assert!`s that the result is in range, so `0xC0` and above reach an
    /// assertion rather than a return. Found by the seed corpus in `tests/fuzz_corpus.rs`,
    /// which is what a fuzz corpus is for, and fixed in ``decode``.
    ///
    /// Kept as a named case rather than left to the corpus because the corpus is a set of
    /// files somebody could prune. This is the one input whose behaviour is a claim about
    /// the product: an attacker who can send one byte cannot make a client tear down a
    /// group.
    #[test]
    fn the_length_prefix_that_panicked_the_tls_decoder_is_answered_as_malformed() {
        for first in [0xc0u8, 0xd0, 0xe0, 0xff] {
            for tail in [vec![], vec![0x00], vec![0xff; 8]] {
                let mut bytes = vec![first];
                bytes.extend_from_slice(&tail);
                let error = decode(&bytes).expect_err("refused");
                assert_eq!(
                    error.status(),
                    Status::Malformed,
                    "for a message beginning {first:#04x}"
                );
            }
        }
    }

    /// And the ordinary refusals still arrive as refusals rather than as caught panics,
    /// so the guard above has not swallowed the decoder's real error path.
    #[test]
    fn ordinary_malformed_input_is_still_refused_by_the_decoder_itself() {
        for bytes in [
            vec![],
            vec![0x00],
            vec![0x01, 0x02, 0x03],
            b"not a tls encoded message at all".to_vec(),
        ] {
            let error = decode(&bytes).expect_err("refused");
            assert_eq!(error.status(), Status::Malformed, "for {bytes:?}");
            // The decoder's own message, not the panic path's, which is how a reader of a
            // log can tell the two apart.
            assert!(
                !error.to_string().contains("panicked"),
                "for {bytes:?}, this took the panic path and should not have"
            );
        }
    }
}
