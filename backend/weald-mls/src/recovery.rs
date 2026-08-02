// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Recovery wraps, blinded tags and the two-phase tag directory.
//!
//! `specs/backend/relay/groups.md`, "Recovery access without a leaf in every group".
//! Exactly one recovery leaf exists per user, in the workspace root group. For every
//! other group the committer emits a `recovery.wrap` sealed to each entitled recovery
//! public key, and the relay stores only the latest wrap per `(group, tag)`.
//!
//! **Why this is in the crate rather than in Swift.** Every other product decision in
//! this design lives above the boundary, and this one looks like it belongs there too: a
//! wrap is a record with a retention rule and a health check. It is here because of what
//! it is made of. A wrap carries the group's exported epoch secret, and the seam's rule
//! in `specs/backend/relay/mls-binding.md` is that "the exporter is the only way to get
//! key material out" and that no function returns a raw epoch secret. Sealing the wrap
//! in Swift would mean exporting the epoch secret to Swift in the clear, which is
//! exactly the thing that rule forbids, and it would put the group's most sensitive
//! value in the layer the third-party audit does not scope as crypto. So the secret is
//! exported, sealed and zeroed without ever crossing the boundary, and what crosses is
//! the sealed ciphertext. Recorded as a correction in `mls-binding.md` in this step.
//!
//! What is still Swift's: which principals are entitled, when a wrap is re-emitted, the
//! 30-day retention of the prior slot, the weekly health check, and every schedule. This
//! module answers "seal this, derive that tag, open this" and decides nothing.

use blake3::Hasher;
use openmls_traits::crypto::OpenMlsCrypto as _;
use openmls_traits::types::{HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType};
use openmls_traits::OpenMlsProvider as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

use crate::session::Session;
use crate::status::{Error, Result};
use crate::store::Provider;

/// The HPKE configuration a wrap is sealed under.
///
/// The same primitives as the one ciphersuite this build speaks
/// (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`), and pinned here rather than derived
/// from the ciphersuite so a future second ciphersuite cannot silently change the format
/// of a record that has to be readable years after it was written. A wrap outlives the
/// epoch that made it: it is what a person recovers an account with.
const HPKE: HpkeConfig = HpkeConfig(
    HpkeKemType::DhKem25519,
    HpkeKdfType::HkdfSha256,
    HpkeAeadType::AesGcm128,
);

/// The exporter label the blinded tag is derived from.
///
/// `groups.md` writes the tag as `BLAKE3(export(weald wraptag v1) || recovery_pubkey)`.
/// The label is versioned in its own text because a change to it is a change to every
/// tag in every group at once, and a recovering client has to be able to say which rule
/// a tag it is looking at was made under.
const TAG_LABEL: &str = "weald wraptag v1";

/// The exporter label the wrapped epoch secret is derived from.
///
/// A different label from the tag's, and that separation is the point rather than
/// bookkeeping. The tag is published to the relay in the clear and the secret is the
/// thing the wrap protects, so deriving both from one exporter output would publish a
/// value computed from the same material the ciphertext hides.
const SECRET_LABEL: &str = "weald recovery v1";

/// How many bytes of exporter output a wrap carries as its epoch secret.
const SECRET_LEN: usize = 32;

/// A recovery keypair, as this crate handles it.
///
/// Derived from a seed rather than generated, because the seed is the recovery phrase in
/// `specs/backend/relay/auth.md` and the whole point of a recovery phrase is that the
/// same words produce the same key on a device that has nothing else. Generation would
/// make the key unrecoverable, which is the one thing it must not be.
///
/// No `Debug`, for the reason `store::Provider` has none: a type that printed this would
/// print a private key into whatever formatted it.
pub struct RecoveryKey {
    private: Vec<u8>,
    public: Vec<u8>,
}

impl core::fmt::Debug for RecoveryKey {
    /// Named, and the public half only. `Debug` exists at all because a test asserting
    /// `expect_err` on a function returning one needs it, and the private half is left
    /// out for the reason the type has no derive: a formatter is the easiest place in a
    /// program for a private key to end up in a log.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveryKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Opened {
    /// The lengths and nothing else. An opened wrap is a decrypted epoch secret, so a
    /// type that printed its contents would print the group's keys into whatever
    /// formatted it, which is the failure this crate's other `Debug` impls also avoid.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Opened")
            .field("epoch_secret_len", &self.epoch_secret.len())
            .field("group_info_len", &self.group_info.len())
            .finish()
    }
}

impl Drop for RecoveryKey {
    /// Zeroed on drop, which is the "secrets are zeroed on free" rule in
    /// `mls-binding.md` applied to the longest-lived secret in the product.
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

impl RecoveryKey {
    /// Derive the recovery keypair for one seed.
    ///
    /// Deterministic: the same seed gives the same key on any device, forever. That is
    /// asserted in the suite rather than assumed, because a derivation that drifted would
    /// not fail here. It would fail on the one day somebody needs it, having already lost
    /// the account it was protecting.
    pub fn derive(provider: &Provider, seed: &[u8]) -> Result<Self> {
        if seed.is_empty() {
            return Err(Error::InvalidArgument("recovery seed is empty".into()));
        }
        // `expect` rather than a mapped error, and the reason is that the error cannot
        // happen for the ciphersuite `HPKE` pins. DHKEM(X25519, HKDF-SHA256) derives a
        // key pair with one labelled HKDF extract, one labelled HKDF expand to 32 bytes,
        // and one clamped scalar multiplication. None of those three inspects the input
        // or can reject it, and there is no rejection sampling loop (the loop in
        // `hpke-rs` exists for the NIST curves, whose scalars have to land below the
        // group order; X25519's do not). So every byte string is a usable seed and the
        // only refusal on this path is the empty-seed rule above, which is ours rather
        // than the KEM's. An arm that can never run is an untested arm, and this is the
        // function a person's whole account hangs off.
        let pair = provider
            .crypto()
            .derive_hpke_keypair(HPKE, seed)
            .expect("DHKEM(X25519, HKDF-SHA256) derives a key pair from any non-empty seed");
        Ok(Self {
            // `HpkePrivateKey` derefs to the bytes. Spelled through the deref rather than
            // `as_ref`, which is ambiguous here because the type implements several.
            private: (*pair.private).to_vec(),
            public: pair.public,
        })
    }

    /// The public half, which is what a committer seals to and what a tag is bound to.
    pub fn public(&self) -> &[u8] {
        &self.public
    }
}

/// One `recovery.wrap` record, as `groups.md` defines it.
///
/// `group` and `epoch` are in the clear because the relay indexes by them and already
/// knows both. `tag` is the blinded slot. `ct` is everything else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wrap {
    pub group: Vec<u8>,
    pub epoch: u64,
    pub tag: [u8; 32],
    pub ct: Vec<u8>,
}

/// What a wrap carries, once opened.
///
/// Both halves, and the second one is not optional. `groups.md`: "`epoch_secret` is what
/// lets a recovery key read. `group_info` is what lets it get back in." An earlier draft
/// carried only the secret, and a recovery key with no leaf and no group info could
/// decrypt a group's traffic and never rejoin it, which made every closed group
/// permanently unreachable after a recovery.
pub struct Opened {
    pub epoch_secret: Vec<u8>,
    pub group_info: Vec<u8>,
}

impl Drop for Opened {
    fn drop(&mut self) {
        self.epoch_secret.zeroize();
    }
}

/// The sealed payload, as bytes, before it becomes `ct`.
#[derive(Serialize, Deserialize)]
struct Payload {
    epoch_secret: Vec<u8>,
    group_info: Vec<u8>,
}

impl Drop for Payload {
    /// Zeroed on drop, so the exported epoch secret is not left in a freed allocation on
    /// any path out of ``Session::seal_wrap``. The explicit zeroing there still happens,
    /// and happens earlier, but it only covers the path where the seal succeeded. This
    /// covers the ones where it did not.
    fn drop(&mut self) {
        self.epoch_secret.zeroize();
    }
}

impl Session {
    /// The blinded slot this recovery key occupies in this group at this epoch.
    ///
    /// `BLAKE3(export(weald wraptag v1) || recovery_pubkey)`, exactly as written in
    /// `groups.md`. Derived from the group's own epoch secret, so it is unlinkable across
    /// groups and rotates on every commit. That is the whole mitigation: an earlier draft
    /// indexed wraps by the recovery public key in the clear, which handed the relay a
    /// per-group list of stable user identifiers it could join across groups to
    /// reconstruct the workspace's group membership graph.
    pub fn wrap_tag(&self, recovery_public: &[u8]) -> Result<[u8; 32]> {
        if recovery_public.is_empty() {
            return Err(Error::InvalidArgument("recovery key is empty".into()));
        }
        let mut exported = self.export(TAG_LABEL, 32)?;
        let mut hasher = Hasher::new();
        hasher.update(&exported);
        hasher.update(recovery_public);
        let tag = *hasher.finalize().as_bytes();
        // The exporter output is key material and its only job was to be hashed. Zeroed
        // rather than dropped, so it does not sit in a freed allocation.
        exported.zeroize();
        Ok(tag)
    }

    /// Seal a wrap for one recovery key at this group's current epoch.
    ///
    /// The epoch secret never leaves this function in the clear. It is exported, placed
    /// in the payload, sealed, and the payload's copy is zeroed before return.
    /// The order of the three fallible steps is deliberate and is written down because it
    /// is not obvious. The group info comes first because it is the only one that says
    /// nothing about the caller's recovery key, then the epoch secret, then the tag. Every
    /// one of the three can fail on its own: the group info on a group whose members carry
    /// credentials too large to serialise inside `wire.md`'s envelope ceiling, the export
    /// on a group this device has been evicted from, and the tag on a recovery key that is
    /// not there. Once the secret has been exported ``Payload``'s `Drop` is what zeroes it
    /// if a later step refuses.
    pub fn seal_wrap(&mut self, group: &[u8], recovery_public: &[u8]) -> Result<Wrap> {
        let mut payload = Payload {
            // Field order is evaluation order, and the group info is fetched first so a
            // group that cannot produce one refuses before an epoch secret exists at all.
            group_info: self.group_info()?,
            epoch_secret: self.export(SECRET_LABEL, SECRET_LEN)?,
        };
        let tag = self.wrap_tag(recovery_public)?;
        // `expect` rather than a mapped error: `Payload` is two `Vec<u8>` and nothing
        // else, and `serde_json` fails to serialise only on a map key that is not a
        // string, on a `Serialize` impl that returns an error of its own, or on an
        // exhausted writer. A derived impl over two byte vectors into a `Vec<u8>` has
        // none of the three, so the arm could never have run.
        let mut plaintext =
            serde_json::to_vec(&payload).expect("a payload of two byte vectors always serialises");
        payload.epoch_secret.zeroize();

        // The tag is the associated data, not just the index. Binding it into the AEAD is
        // what stops a relay moving a valid ciphertext into another slot: a wrap opened
        // out of the slot it was sealed for fails to authenticate rather than decrypting
        // into a group the recovering client was never in.
        let sealed = self
            .provider()
            .crypto()
            .hpke_seal(HPKE, recovery_public, group, &tag, &plaintext)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        plaintext.zeroize();

        Ok(Wrap {
            group: group.to_vec(),
            epoch: self.epoch(),
            tag,
            ct: encode_ciphertext(&sealed),
        })
    }
}

/// Open a wrap with the recovery private key.
///
/// A free function rather than a method on ``Session``, because the caller doing this has
/// no session: it is a fresh device holding a recovery phrase and a pile of wraps, which
/// is the entire situation the mechanism exists for.
pub fn open_wrap(provider: &Provider, key: &RecoveryKey, wrap: &Wrap) -> Result<Opened> {
    let ciphertext = decode_ciphertext(&wrap.ct)?;
    let plaintext = provider
        .crypto()
        .hpke_open(HPKE, &ciphertext, &key.private, &wrap.group, &wrap.tag)
        // `Protocol` rather than `Malformed`: the bytes decoded, and what failed was the
        // authentication. A caller trying its candidate, current and fallback tags in
        // turn treats this as "not this one" and moves on, which is the recovery path in
        // `groups.md` working as designed rather than an error to show a person.
        .map_err(|error| Error::Protocol(error.to_string()))?;
    // Still an error and still tested. The plaintext here came off the relay: authenticating
    // says the bytes were sealed to this key under this tag, and says nothing at all about
    // whether they are a payload.
    let mut payload: Payload =
        serde_json::from_slice(&plaintext).map_err(|error| Error::Malformed(error.to_string()))?;
    Ok(Opened {
        // Moved out by hand because ``Payload`` has a `Drop`. What is left behind is an
        // empty vector, and the secret's one remaining copy is the one in ``Opened``,
        // which zeroes it in turn.
        epoch_secret: core::mem::take(&mut payload.epoch_secret),
        group_info: core::mem::take(&mut payload.group_info),
    })
}

/// One group's entry in a recovery principal's tag directory.
///
/// Three tags, and each answers a different question during a recovery. `current` is the
/// tag the last activated commit published under. `candidate` is the tag the next commit
/// will publish under, written before that commit is published. `fallback` is the
/// previous `current`, retained so a recovery that arrives during a handoff still finds a
/// slot. `groups.md`: recovery "tries the directory's candidate, current and fallback
/// tags, accepts only a wrap whose MLS `GroupInfo` validates at the stated epoch, and
/// never treats a missing candidate as data loss."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub group: Vec<u8>,
    pub current: Option<[u8; 32]>,
    pub candidate: Option<[u8; 32]>,
    pub fallback: Option<[u8; 32]>,
    /// The commit this entry's candidate is bound to, so a `prepare` and its `activate`
    /// are idempotent on `(group, target_commit_hash)` as `groups.md` requires.
    pub target: Option<[u8; 32]>,
    /// The last target this entry actually activated.
    ///
    /// Kept rather than cleared, and the reason is worth writing down because the first
    /// version of this type did clear it. Without it a retried activate and an activate
    /// for a commit nobody ever prepared are the same call: both arrive with no pending
    /// target. Answering `Ok` to both makes the idempotency the crash path needs, and
    /// gives up the refusal that stops `current` moving to a tag no wrap was published
    /// under. Answering `Err` to both makes the refusal work and turns the ordinary
    /// crash-then-retry into a hard failure. One extra field buys both.
    pub activated: Option<[u8; 32]>,
}

impl DirectoryEntry {
    /// A group with no wrap published yet.
    pub fn new(group: &[u8]) -> Self {
        Self {
            group: group.to_vec(),
            current: None,
            candidate: None,
            fallback: None,
            target: None,
            activated: None,
        }
    }

    /// Phase one: record the tag the next commit will publish under, bound to that
    /// commit.
    ///
    /// Idempotent on the target. Preparing the same commit twice is the ordinary
    /// consequence of a crash and a retry, and it must not rotate `fallback` a second
    /// time: doing so would discard the slot a concurrent recovery is reading from.
    pub fn prepare(&mut self, candidate: [u8; 32], target: [u8; 32]) {
        if self.target == Some(target) {
            return;
        }
        self.candidate = Some(candidate);
        self.target = Some(target);
    }

    /// Phase two: the commit was accepted, so the candidate becomes current and the old
    /// current is retained as the fallback.
    ///
    /// Idempotent, and refuses an activate for a target this entry never prepared. A
    /// directory that accepted an unprepared activate would move `current` to a tag no
    /// wrap was ever published under, which is silent, total loss of the account this
    /// mechanism exists to save.
    pub fn activate(&mut self, target: [u8; 32]) -> Result<()> {
        if self.target != Some(target) {
            // The retry after a crash between the write and its acknowledgement. Named by
            // the target that was actually activated, so it cannot be confused with the
            // case below.
            if self.activated == Some(target) {
                return Ok(());
            }
            return Err(Error::Protocol(
                "activate for a target this directory never prepared".into(),
            ));
        }
        let Some(candidate) = self.candidate.take() else {
            return Ok(());
        };
        self.fallback = self.current;
        self.current = Some(candidate);
        self.target = None;
        self.activated = Some(target);
        Ok(())
    }

    /// Every tag worth trying, in the order `groups.md` names: candidate, current,
    /// fallback.
    ///
    /// Ordered rather than a set, because the order is the availability guarantee. A
    /// recovery arriving mid-handoff finds the candidate first, and one arriving after a
    /// crash that never activated finds the current.
    pub fn tags(&self) -> Vec<[u8; 32]> {
        [self.candidate, self.current, self.fallback]
            .into_iter()
            .flatten()
            .collect()
    }
}

/// A recovery principal's whole directory: every group it is entitled to, and the tags.
///
/// Sealed to the recovery key inside the workspace root group, which is what keeps the
/// relay from seeing a stable recovery identifier or the group membership graph. The
/// sealing is the same HPKE as a wrap's, so there is one format to review rather than
/// two.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Directory {
    pub entries: Vec<DirectoryEntry>,
}

impl Directory {
    /// The entry for one group, created if this is the first wrap for it.
    pub fn entry(&mut self, group: &[u8]) -> &mut DirectoryEntry {
        if let Some(index) = self.entries.iter().position(|e| e.group == group) {
            return &mut self.entries[index];
        }
        self.entries.push(DirectoryEntry::new(group));
        self.entries.last_mut().expect("just pushed")
    }

    /// The entry for one group, if there is one.
    pub fn get(&self, group: &[u8]) -> Option<&DirectoryEntry> {
        self.entries.iter().find(|e| e.group == group)
    }

    /// Seal the directory to a recovery key.
    pub fn seal(&self, provider: &Provider, recovery_public: &[u8]) -> Result<Vec<u8>> {
        // `expect` for the reason ``Session::seal_wrap``'s does: a directory is a vector
        // of records of byte vectors and fixed-size arrays, serialised into a `Vec<u8>`,
        // which is not a shape `serde_json` has a way to refuse.
        let plaintext = serde_json::to_vec(self).expect("a directory of byte vectors serialises");
        let sealed = provider
            .crypto()
            .hpke_seal(HPKE, recovery_public, DIRECTORY_INFO, &[], &plaintext)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        Ok(encode_ciphertext(&sealed))
    }

    /// Open a directory with the recovery private key.
    pub fn open(provider: &Provider, key: &RecoveryKey, bytes: &[u8]) -> Result<Self> {
        let ciphertext = decode_ciphertext(bytes)?;
        let plaintext = provider
            .crypto()
            .hpke_open(HPKE, &ciphertext, &key.private, DIRECTORY_INFO, &[])
            .map_err(|error| Error::Protocol(error.to_string()))?;
        // As in ``open_wrap``: authenticating proves who sealed these bytes, not what they
        // are, and a directory is read on the one device that has nothing else to check it
        // against. So this stays an error and is tested rather than assumed.
        serde_json::from_slice(&plaintext).map_err(|error| Error::Malformed(error.to_string()))
    }
}

/// The HPKE info string a directory is sealed under.
///
/// Different from a wrap's, which is the group id, so a ciphertext cannot be moved
/// between the two roles even by somebody holding both.
const DIRECTORY_INFO: &[u8] = b"weald recovery directory v1";

/// An HPKE ciphertext as bytes.
///
/// JSON, matching `store::JsonCodec` and for the same reason: a wrap is what an incident
/// investigation reads, and a self-describing encoding is one an investigator can read
/// at three in the morning. The confidentiality is in the AEAD, not in the framing.
///
/// Infallible, and that is a claim rather than an oversight. What is encoded is a pair of
/// byte vectors into a `Vec<u8>`, and `serde_json` reports failure only for a map key that
/// is not a string, a `Serialize` impl that raises an error of its own, or a writer that
/// ran out. A tuple of two `Vec<u8>` written into a growable vector has none of the three.
/// The inverse below stays fallible, because its input is bytes off the relay.
fn encode_ciphertext(sealed: &HpkeCiphertext) -> Vec<u8> {
    let pair = (
        sealed.kem_output.as_slice().to_vec(),
        sealed.ciphertext.as_slice().to_vec(),
    );
    serde_json::to_vec(&pair).expect("a pair of byte vectors always serialises")
}

/// The inverse, refusing anything that is not one.
fn decode_ciphertext(bytes: &[u8]) -> Result<HpkeCiphertext> {
    let (kem_output, ciphertext): (Vec<u8>, Vec<u8>) =
        serde_json::from_slice(bytes).map_err(|error| Error::Malformed(error.to_string()))?;
    Ok(HpkeCiphertext {
        kem_output: kem_output.into(),
        ciphertext: ciphertext.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Config, Device};

    fn device(identity: &str) -> Device {
        Device::open(&Config {
            database: ":memory:".into(),
            identity: identity.as_bytes().to_vec(),
        })
        .expect("a device")
    }

    const GROUP: &[u8] = b"weald-recovery-group";

    #[test]
    fn a_recovery_key_is_the_same_key_every_time_the_same_seed_is_used() {
        let provider = Provider::open(":memory:").expect("a provider");
        let first = RecoveryKey::derive(&provider, b"correct horse battery staple")
            .expect("a recovery key");
        let again = RecoveryKey::derive(&provider, b"correct horse battery staple")
            .expect("a recovery key");
        // The property the recovery phrase rests on. If this drifted it would not fail
        // here, it would fail on the one day somebody needs it.
        assert_eq!(first.public(), again.public());

        let other = RecoveryKey::derive(&provider, b"a different phrase entirely").expect("a key");
        assert_ne!(first.public(), other.public());

        let refused = RecoveryKey::derive(&provider, b"").expect_err("refused");
        assert_eq!(refused.status(), crate::status::Status::InvalidArgument);
    }

    #[test]
    fn a_wrap_round_trips_and_carries_both_the_secret_and_the_way_back_in() {
        let ada_device = device("ada");
        let mut ada = ada_device.create_group(GROUP).expect("a group");
        let provider = Provider::open(":memory:").expect("a provider");
        let key = RecoveryKey::derive(&provider, b"ada's recovery phrase").expect("a key");

        let wrap = ada.seal_wrap(GROUP, key.public()).expect("a wrap");
        assert_eq!(wrap.epoch, ada.epoch());
        assert_eq!(wrap.group, GROUP.to_vec());

        let opened = open_wrap(&provider, &key, &wrap).expect("opened");
        assert_eq!(opened.epoch_secret.len(), SECRET_LEN);
        // Both halves. The group info is what lets a recovery key rejoin rather than only
        // read, and a wrap carrying only the secret made every closed group permanently
        // unreachable after a recovery.
        assert!(!opened.group_info.is_empty());
        assert_eq!(
            opened.epoch_secret,
            ada.export(SECRET_LABEL, SECRET_LEN).expect("the secret")
        );
    }

    #[test]
    fn the_sealed_wrap_shows_the_relay_nothing_it_should_not_have() {
        let ada_device = device("ada");
        let mut ada = ada_device.create_group(GROUP).expect("a group");
        let provider = Provider::open(":memory:").expect("a provider");
        let key = RecoveryKey::derive(&provider, b"ada's recovery phrase").expect("a key");
        let wrap = ada.seal_wrap(GROUP, key.public()).expect("a wrap");

        // The recovery public key is the stable per-user identifier the tag exists to
        // hide. It must not appear anywhere in the stored record, in the tag or in the
        // ciphertext, or the blinding was decoration.
        let public = key.public();
        assert!(!wrap.tag.windows(public.len().min(32)).any(|w| w == public));
        assert!(!wrap.ct.windows(public.len()).any(|window| window == public));

        // And the secret itself is not in the record.
        let secret = ada.export(SECRET_LABEL, SECRET_LEN).expect("the secret");
        assert!(!wrap.ct.windows(secret.len()).any(|window| window == secret));
    }

    #[test]
    fn a_tag_is_unlinkable_across_groups_and_rotates_on_every_commit() {
        let provider = Provider::open(":memory:").expect("a provider");
        let key = RecoveryKey::derive(&provider, b"one person, one recovery key").expect("a key");

        // The same recovery key in two groups. If these matched, the relay could join the
        // two slot lists and learn that one person is in both groups, which is the
        // membership graph `wire.md` claims it never sees.
        let ada_device = device("ada");
        let first = ada_device.create_group(b"group-one").expect("a group");
        let second = ada_device.create_group(b"group-two").expect("a group");
        let one = first.wrap_tag(key.public()).expect("a tag");
        let two = second.wrap_tag(key.public()).expect("a tag");
        assert_ne!(one, two);

        // And the same group across a commit. The tag is derived from the epoch secret,
        // so it changes wholesale when the epoch does.
        let mut ada = first;
        let bo_device = device("bo");
        let package = bo_device.key_package().expect("a key package");
        ada.add(&package).expect("an add");
        ada.merge_pending().expect("merged");
        let after = ada.wrap_tag(key.public()).expect("a tag");
        assert_ne!(one, after);

        // Two different recovery keys in one group are different slots, or one wrap would
        // overwrite another.
        let other = RecoveryKey::derive(&provider, b"somebody else").expect("a key");
        assert_ne!(ada.wrap_tag(other.public()).expect("a tag"), after);

        let refused = ada.wrap_tag(&[]).expect_err("refused");
        assert_eq!(refused.status(), crate::status::Status::InvalidArgument);
    }

    #[test]
    fn a_wrap_cannot_be_opened_by_the_wrong_key_or_moved_into_another_slot() {
        let ada_device = device("ada");
        let mut ada = ada_device.create_group(GROUP).expect("a group");
        let provider = Provider::open(":memory:").expect("a provider");
        let key = RecoveryKey::derive(&provider, b"the right phrase").expect("a key");
        let wrong = RecoveryKey::derive(&provider, b"the wrong phrase").expect("a key");
        let wrap = ada.seal_wrap(GROUP, key.public()).expect("a wrap");

        assert_eq!(
            open_wrap(&provider, &wrong, &wrap)
                .expect_err("refused")
                .status(),
            crate::status::Status::Protocol
        );

        // The tag is the associated data, so a relay that moved this ciphertext into
        // another slot produces a wrap that fails to authenticate rather than one that
        // decrypts into a group its reader was never in.
        let mut moved = wrap.clone();
        moved.tag = [0x11; 32];
        assert_eq!(
            open_wrap(&provider, &key, &moved)
                .expect_err("refused")
                .status(),
            crate::status::Status::Protocol
        );

        // And the group id is the info string, so the same ciphertext under another
        // group is refused too.
        let mut relabelled = wrap.clone();
        relabelled.group = b"some-other-group".to_vec();
        assert_eq!(
            open_wrap(&provider, &key, &relabelled)
                .expect_err("refused")
                .status(),
            crate::status::Status::Protocol
        );

        // Bytes that are not a ciphertext at all are `Malformed`, which is the ordinary
        // answer to a damaged row.
        let mut damaged = wrap.clone();
        damaged.ct = b"not a sealed thing".to_vec();
        assert_eq!(
            open_wrap(&provider, &key, &damaged)
                .expect_err("refused")
                .status(),
            crate::status::Status::Malformed
        );
    }

    #[test]
    fn the_directory_hands_off_in_two_phases_and_a_crash_at_either_one_is_survivable() {
        let mut entry = DirectoryEntry::new(GROUP);
        assert!(entry.tags().is_empty());

        // First commit: prepare, then activate. Between them the candidate is what a
        // recovery would try, and that is the availability guarantee rather than a
        // convenience.
        entry.prepare([1; 32], [0xaa; 32]);
        assert_eq!(entry.tags(), vec![[1; 32]]);
        entry.activate([0xaa; 32]).expect("activated");
        assert_eq!(entry.tags(), vec![[1; 32]]);
        assert_eq!(entry.current, Some([1; 32]));

        // Second commit: mid-handoff, all three tags are live and the order is candidate,
        // current, fallback.
        entry.prepare([2; 32], [0xbb; 32]);
        assert_eq!(entry.tags(), vec![[2; 32], [1; 32]]);
        entry.activate([0xbb; 32]).expect("activated");
        assert_eq!(entry.tags(), vec![[2; 32], [1; 32]]);
        assert_eq!(entry.fallback, Some([1; 32]));

        // A crash between prepare and activate, then a retry of the prepare. Idempotent
        // on the target, and it must not rotate the fallback a second time: doing so
        // would discard the slot a concurrent recovery is reading from.
        entry.prepare([3; 32], [0xcc; 32]);
        let before = entry.clone();
        entry.prepare([3; 32], [0xcc; 32]);
        assert_eq!(entry, before);

        // A crash between activate and the acknowledgement, then a retry. Also
        // idempotent, and it does not move current a second time.
        entry.activate([0xcc; 32]).expect("activated");
        let after = entry.clone();
        entry.activate([0xcc; 32]).expect("already activated");
        assert_eq!(entry, after);

        // An activate for a target nobody prepared is refused. A directory that accepted
        // one would move current to a tag no wrap was ever published under, which is
        // silent, total loss of the account this whole mechanism exists to save.
        assert_eq!(
            entry.activate([0xff; 32]).expect_err("refused").status(),
            crate::status::Status::Protocol
        );
    }

    #[test]
    fn formatting_a_recovery_key_or_an_opened_wrap_prints_no_key_material() {
        let ada_device = device("ada");
        let mut ada = ada_device.create_group(GROUP).expect("a group");
        let provider = Provider::open(":memory:").expect("a provider");
        let key = RecoveryKey::derive(&provider, b"ada's recovery phrase").expect("a key");
        let wrap = ada.seal_wrap(GROUP, key.public()).expect("a wrap");
        let opened = open_wrap(&provider, &key, &wrap).expect("opened");

        // A formatter is the easiest place in a program for a secret to end up in a log,
        // and both of these types hold one: the recovery key is the longest-lived secret
        // in the product, and an opened wrap is a decrypted epoch secret. `Debug` exists
        // on them because tests calling `expect_err` need it, so what it prints is a
        // security property and not a convenience.
        let printed_key = format!("{key:?}");
        let printed_wrap = format!("{opened:?}");

        // Named, so a person reading a log can tell what was formatted.
        assert!(printed_key.starts_with("RecoveryKey"));
        assert!(printed_wrap.starts_with("Opened"));

        // The private half is not in it, in the rendering `Debug` would have used and
        // byte by byte. The field is reachable from this module, so this is asserted
        // against the real secret rather than against a copy of it.
        assert!(!printed_key.contains(&format!("{:?}", key.private)));
        for run in key.private.windows(4) {
            // Four consecutive bytes of the private key, rendered the way a formatter
            // would render them. Single bytes would collide with the public half by
            // chance; a run of four is the key itself.
            let rendered = format!("{}, {}, {}, {}", run[0], run[1], run[2], run[3]);
            assert!(
                !printed_key.contains(&rendered),
                "part of the private key appears in {printed_key}"
            );
        }
        // The public half is what a committer seals to and what a tag is bound to, so it
        // is the one part that is safe to print, and it is printed.
        assert!(printed_key.contains(&format!("{:?}", key.public)));

        // The opened wrap says how long its two halves are and nothing about what is in
        // them. `mls-binding.md`: "the exporter is the only way to get key material out",
        // and a `Debug` impl is not the exporter.
        assert!(!printed_wrap.contains(&format!("{:?}", opened.epoch_secret)));
        assert!(printed_wrap.contains(&format!("epoch_secret_len: {}", SECRET_LEN)));
        assert!(printed_wrap.contains(&format!("group_info_len: {}", opened.group_info.len())));
        let secret = ada.export(SECRET_LABEL, SECRET_LEN).expect("the secret");
        assert!(!printed_wrap
            .as_bytes()
            .windows(secret.len())
            .any(|window| window == secret));
    }

    #[test]
    fn an_activate_for_a_prepared_target_with_no_candidate_left_moves_nothing() {
        // A directory entry that came back from the relay with its candidate missing: the
        // record says a commit was prepared and does not say which tag it was prepared
        // under. It is not a state this type's own methods can produce, and it is exactly
        // what a truncated or partially written stored record looks like.
        let mut entry = DirectoryEntry::new(GROUP);
        entry.prepare([7; 32], [0xdd; 32]);
        let mut record = serde_json::to_value(&entry).expect("serialised");
        record["candidate"] = serde_json::Value::Null;
        let mut damaged: DirectoryEntry = serde_json::from_value(record).expect("deserialised");

        // Accepted rather than refused, because refusing would turn a damaged record into
        // a permanent hard failure on the ordinary crash-then-retry path.
        damaged.activate([0xdd; 32]).expect("accepted");

        // And nothing moved. This is the property that matters: `current` must never come
        // to hold a tag no wrap was ever published under, which is silent, total loss of
        // the account the whole mechanism exists to save. With no candidate there is no
        // tag to move to, so the entry is left alone and a recovery keeps finding whatever
        // slot it was already finding.
        assert_eq!(damaged.current, None);
        assert_eq!(damaged.fallback, None);
        assert!(damaged.tags().is_empty());
    }

    #[test]
    fn a_directory_seals_to_its_recovery_key_and_names_every_group_its_owner_is_in() {
        let provider = Provider::open(":memory:").expect("a provider");
        let key = RecoveryKey::derive(&provider, b"ada's recovery phrase").expect("a key");
        let wrong = RecoveryKey::derive(&provider, b"not ada").expect("a key");

        let mut directory = Directory::default();
        directory.entry(b"group-one").prepare([1; 32], [0xaa; 32]);
        directory
            .entry(b"group-one")
            .activate([0xaa; 32])
            .expect("activated");
        directory.entry(b"group-two").prepare([2; 32], [0xbb; 32]);
        // Asking for the same group twice is the same entry, or a second commit would
        // start a second directory line for one group.
        assert_eq!(directory.entries.len(), 2);

        let sealed = directory.seal(&provider, key.public()).expect("sealed");
        let opened = Directory::open(&provider, &key, &sealed).expect("opened");
        assert_eq!(opened, directory);
        assert_eq!(
            opened.get(b"group-one").expect("an entry").tags(),
            vec![[1; 32]]
        );
        assert!(opened.get(b"group-three").is_none());

        // Sealed to one principal, so another recovery key learns nothing, which is what
        // keeps the relay from seeing the group membership graph.
        assert_eq!(
            Directory::open(&provider, &wrong, &sealed)
                .expect_err("refused")
                .status(),
            crate::status::Status::Protocol
        );

        // A directory ciphertext cannot be presented as a wrap, because the info string
        // is different for the two roles.
        let as_wrap = Wrap {
            group: b"group-one".to_vec(),
            epoch: 0,
            tag: [1; 32],
            ct: sealed.clone(),
        };
        assert_eq!(
            open_wrap(&provider, &key, &as_wrap)
                .expect_err("refused")
                .status(),
            crate::status::Status::Protocol
        );

        assert_eq!(
            Directory::open(&provider, &key, b"not sealed at all")
                .expect_err("refused")
                .status(),
            crate::status::Status::Malformed
        );
    }

    /// A group whose members carry credentials too large for `wire.md`'s envelope ceiling
    /// cannot produce a group info, and so cannot seal a wrap.
    ///
    /// The identity is a caller's bytes, arriving through `weald_mls_device_open`, and
    /// nothing above this crate bounds it. A wrap carries a `GroupInfo` (`groups.md`:
    /// "`group_info` is what lets it get back in"), the group info carries the ratchet
    /// tree, and the ratchet tree carries every member's credential, so a large enough
    /// identity makes the record unpublishable. `specs/backend/relay/mls-binding.md` puts
    /// the ceiling at `wire.md`'s envelope size for exactly this reason: refusing here
    /// names the real cause, where letting it through would produce a wrap the transport
    /// drops and a recovery that silently finds nothing.
    ///
    /// The property proved is that the refusal is typed and total: `InvalidArgument`
    /// naming the ceiling, no wrap, and the tag still derivable, which is what makes this
    /// a failure of the record rather than of the group.
    #[test]
    fn a_group_whose_info_is_over_the_envelope_ceiling_refuses_to_seal_a_wrap() {
        // Over the one mebibyte `serialize` enforces, once the credential is in the tree.
        let oversized = Device::open(&Config {
            database: ":memory:".into(),
            identity: vec![b'a'; 1_200_000],
        })
        .expect("a device");
        let mut group = oversized.create_group(GROUP).expect("a group");
        let provider = Provider::open(":memory:").expect("a provider");
        let key = RecoveryKey::derive(&provider, b"ada's recovery phrase").expect("a key");

        // The tag still derives, so what follows is the group info and nothing else.
        group.wrap_tag(key.public()).expect("a tag");

        let refused = group.seal_wrap(GROUP, key.public()).expect_err("refused");
        assert_eq!(refused.status(), crate::status::Status::InvalidArgument);
        assert!(
            refused
                .to_string()
                .contains("over the 1048576 byte ceiling"),
            "the refusal must name the ceiling, not just fail: {refused}"
        );
    }

    /// A device evicted from a group cannot seal a wrap for it, and says so as `Protocol`.
    ///
    /// The order inside ``Session::seal_wrap`` is what this pins down. A removed member
    /// learns it was removed by processing the commit that removed it, so the call that
    /// evicts it succeeds and every call after it must not. A wrap sealed after eviction
    /// would be published into a slot derived from an epoch secret the group has already
    /// left, which a recovery would find and fail to use.
    #[test]
    fn an_evicted_device_cannot_seal_a_wrap_for_the_group_it_was_thrown_out_of() {
        let ada_device = device("ada");
        let bo_device = device("bo");
        let mut ada = ada_device.create_group(GROUP).expect("a group");
        let package = bo_device.key_package().expect("a key package");
        let (_commit, welcome) = ada.add(&package).expect("an add");
        ada.merge_pending().expect("merged");
        let mut bo = bo_device.join_welcome(&welcome).expect("joined");

        let commit = ada.remove(&[1]).expect("a removal");
        ada.merge_pending().expect("merged");
        bo.process(&commit)
            .expect("bo learns of it by processing it");

        let provider = Provider::open(":memory:").expect("a provider");
        let key = RecoveryKey::derive(&provider, b"bo's recovery phrase").expect("a key");
        let refused = bo.seal_wrap(GROUP, key.public()).expect_err("refused");
        assert_eq!(refused.status(), crate::status::Status::Protocol);
        assert!(
            refused.to_string().contains("after being evicted"),
            "the refusal must name the eviction: {refused}"
        );

        // And the group info alone still works, which is what makes the export above the
        // thing that refused rather than the whole session being unusable.
        bo.group_info().expect("a group info");
    }

    /// A ciphertext that authenticates but does not contain a payload is refused as
    /// malformed rather than opened.
    ///
    /// This is the hostile case the sealing side cannot rule out. `groups.md` has a
    /// recovering device fetch wraps from the relay by tag and try them, so the bytes
    /// arriving at ``open_wrap`` are the relay's. Anyone able to seal to the recovery
    /// public key, which is published, can produce a ciphertext that decrypts perfectly
    /// under the right group id and tag and contains anything at all. Authentication says
    /// who sealed it, not what it is, and the assertion here is that the difference is
    /// noticed: `Malformed`, naming the parse, and no ``Opened``.
    #[test]
    fn a_wrap_that_decrypts_to_something_that_is_not_a_payload_is_refused_as_malformed() {
        let provider = Provider::open(":memory:").expect("a provider");
        let key = RecoveryKey::derive(&provider, b"ada's recovery phrase").expect("a key");
        let tag = [0x5a_u8; 32];

        // Sealed through the provider directly, under the same info and associated data a
        // real wrap uses, which is exactly what a relay or anyone holding the published
        // recovery public key could produce.
        let sealed = provider
            .crypto()
            .hpke_seal(HPKE, key.public(), GROUP, &tag, b"not a payload at all")
            .expect("sealed");
        let forged = Wrap {
            group: GROUP.to_vec(),
            epoch: 7,
            tag,
            ct: encode_ciphertext(&sealed),
        };

        let refused = open_wrap(&provider, &key, &forged).expect_err("refused");
        assert_eq!(refused.status(), crate::status::Status::Malformed);
        assert!(
            refused.to_string().contains("expected ident"),
            "the refusal must name the parse that failed: {refused}"
        );

        // The same bytes shaped as JSON but as the wrong JSON, so the refusal is not just
        // "these bytes are not JSON". A record with the fields missing is the shape a
        // truncated or renamed payload would have.
        let sealed = provider
            .crypto()
            .hpke_seal(HPKE, key.public(), GROUP, &tag, br#"{"epoch_secret":[]}"#)
            .expect("sealed");
        let truncated = Wrap {
            ct: encode_ciphertext(&sealed),
            ..forged
        };
        let refused = open_wrap(&provider, &key, &truncated).expect_err("refused");
        assert_eq!(refused.status(), crate::status::Status::Malformed);
        assert!(
            refused.to_string().contains("group_info"),
            "the refusal must name the field that was missing: {refused}"
        );
    }

    /// Sealing a wrap for a recovery key that is not there is refused, and the epoch
    /// secret it had already exported does not survive the refusal.
    ///
    /// ``Session::seal_wrap`` exports the group's epoch secret before it derives the tag,
    /// so this is the one path where the function holds key material and then fails. The
    /// refusal itself is the ordinary one, `InvalidArgument` for a missing argument, and
    /// what is worth proving alongside it is that the group is unchanged afterwards: an
    /// epoch that had moved, or a wrap that came back anyway, would mean a caller could
    /// disturb a group by passing nothing.
    #[test]
    fn sealing_a_wrap_for_a_recovery_key_that_is_not_there_is_refused_and_changes_nothing() {
        let ada_device = device("ada");
        let mut ada = ada_device.create_group(GROUP).expect("a group");
        let before = ada.epoch_authenticator();

        let refused = ada.seal_wrap(GROUP, &[]).expect_err("refused");
        assert_eq!(refused.status(), crate::status::Status::InvalidArgument);
        assert!(
            refused.to_string().contains("recovery key is empty"),
            "the refusal must name what was missing: {refused}"
        );

        // Nothing moved, and the same group still seals for a key that is there.
        assert_eq!(ada.epoch_authenticator(), before);
        let provider = Provider::open(":memory:").expect("a provider");
        let key = RecoveryKey::derive(&provider, b"ada's recovery phrase").expect("a key");
        let wrap = ada.seal_wrap(GROUP, key.public()).expect("a wrap");
        open_wrap(&provider, &key, &wrap).expect("opened");
    }

    /// A directory ciphertext that authenticates but does not contain a directory is
    /// refused as malformed.
    ///
    /// The same argument as the wrap case above, on the record that names every group its
    /// owner is in. A directory is read on the one device that has nothing else to check
    /// it against, so "it decrypted" must not be allowed to stand in for "it is a
    /// directory".
    #[test]
    fn a_directory_that_decrypts_to_something_that_is_not_a_directory_is_refused() {
        let provider = Provider::open(":memory:").expect("a provider");
        let key = RecoveryKey::derive(&provider, b"ada's recovery phrase").expect("a key");

        let sealed = provider
            .crypto()
            .hpke_seal(HPKE, key.public(), DIRECTORY_INFO, &[], b"[not a directory")
            .expect("sealed");
        let refused =
            Directory::open(&provider, &key, &encode_ciphertext(&sealed)).expect_err("refused");
        assert_eq!(refused.status(), crate::status::Status::Malformed);
        assert!(
            refused.to_string().contains("expected ident"),
            "the refusal must name the parse that failed: {refused}"
        );
    }

    /// Sealing a directory to bytes that are not a recovery public key fails in the
    /// crypto rather than producing a record nobody can open.
    ///
    /// The public key comes from whatever the client believes is entitled, so a wrong
    /// length, or a valid length that is not a valid X25519 point, are both real inputs.
    /// The one that matters is the second: thirty-two zero bytes is a low-order point, and
    /// a Diffie-Hellman against it yields an all-zero shared secret. An implementation
    /// that accepted it would emit a directory encrypted under a key an attacker also
    /// holds. The assertion is that every one of these is refused as `Protocol` and that
    /// nothing comes back.
    #[test]
    fn a_directory_cannot_be_sealed_to_bytes_that_are_not_a_recovery_public_key() {
        let provider = Provider::open(":memory:").expect("a provider");
        let directory = Directory::default();

        for public in [
            Vec::new(),
            vec![0x11; 1],
            vec![0x11; 31],
            vec![0x11; 33],
            // Thirty-two bytes and the right length, and still not a usable key.
            vec![0x00; 32],
        ] {
            let length = public.len();
            let refused = directory
                .seal(&provider, &public)
                .expect_err("a directory sealed to a non-key must be refused");
            assert_eq!(
                refused.status(),
                crate::status::Status::Protocol,
                "for a {length}-byte key"
            );
            assert!(
                refused.to_string().contains("CryptoLibraryError"),
                "the refusal must come from the crypto: {refused}"
            );
        }

        // And a real key still works, so what was refused was the key and not the call.
        let key = RecoveryKey::derive(&provider, b"a real recovery phrase").expect("a key");
        assert!(!directory
            .seal(&provider, key.public())
            .expect("sealed")
            .is_empty());
    }
}
