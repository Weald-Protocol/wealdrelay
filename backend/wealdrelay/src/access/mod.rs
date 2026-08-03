// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The access set: the one piece of derived membership data the relay holds.
//!
//! This module carries a 100 percent coverage floor and no coverage-exclusion
//! attribute is permitted anywhere in it. That is because this module decides who
//! may open a socket, and every branch that decides it has to be a branch a test
//! has actually taken.
//!
//! ## What it is for
//!
//! An earlier draft had `AUTH` prove possession of "a roster device key", which the
//! relay cannot check: the roster is encrypted to the workspace group. That left
//! connection auth unable to tell a member from a stranger and unable to ever cut
//! off a revoked device. A person removed on Friday could open a socket on Monday
//! and pull every group's ciphertext.
//!
//! So the relay gets a set of salted principal hashes, the device keys allowed to
//! rotate that set, and the recovery principals allowed one narrow transition. It
//! learns how many principals a workspace has, when that number changes, and which
//! presented keys may rotate access. It learns nothing about content, about which
//! groups a principal reads, or about who belongs to which group.
//!
//! ## Two halves, deliberately separated
//!
//! Everything in this file is pure: decoding, the digest, signature verification,
//! and the whole of the transition rules. `access::store` holds the one database
//! transaction that applies an accepted transition. The split is the same one
//! `session.rs` makes against `ws.rs`, and for the same reason: the rules are the
//! part worth testing exhaustively, and a rule that could only be reached through a
//! socket and a Postgres round trip is a rule nobody covers.
//!
//! ## Encoding
//!
//! Definite-length arrays with positional fields, which is what every other
//! structure on this wire uses (`envelope::Envelope`, `frame::Frame`, and their
//! Swift counterparts). `specs/backend/contracts/wire/wire.cddl` writes `AccessSet`
//! as an integer-keyed map; the implementation has always used arrays and the
//! CDDL is corrected rather than the four structures that already ship. The
//! correction is recorded in `specs/backend/contracts/wire/vectors/README.md`.

pub mod store;

use crate::cbor::{self, CborError, Reader};

/// A principal key, an entry hash, a digest. All 32 bytes on this wire.
pub const KEY_BYTES: usize = 32;
pub const HASH_BYTES: usize = 32;
pub const SIG_BYTES: usize = 64;

/// The domain separator a quorum signature covers, so a confirmation cannot be
/// replayed as anything else.
pub const QUORUM_CONFIRM_LABEL: &[u8] = b"weald recovery-confirm v1";

/// A bound on every list in a published set.
///
/// Not a policy about workspace size; a bound on what one frame may make the relay
/// allocate before any signature has been checked. A publication naming a million
/// entries is refused on the count rather than after the allocation.
pub const MAX_ENTRIES: usize = 4096;

/// How a signer was acting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedAs {
    /// A member of the prior set's `authorizers`.
    Authorizer,
    /// A member of the prior set's `recovery`, taking the one narrow transition.
    Recovery,
}

impl SignedAs {
    pub fn label(self) -> &'static str {
        match self {
            Self::Authorizer => "authorizer",
            Self::Recovery => "recovery",
        }
    }
}

/// A quorum signature over one proposed transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumSignature {
    pub key: Vec<u8>,
    pub sig: Vec<u8>,
}

/// Confirm-only external keys. Never entries, never authorizers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecoveryQuorum {
    pub threshold: u8,
    pub keys: Vec<Vec<u8>>,
    pub sigs: Vec<QuorumSignature>,
}

/// One published access set, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessSet {
    pub workspace: Vec<u8>,
    pub version: u64,
    pub prev_hash: Vec<u8>,
    pub issued_at: u64,
    pub entries: Vec<Vec<u8>>,
    pub authorizers: Vec<Vec<u8>>,
    pub recovery: Vec<Vec<u8>>,
    pub quorum: Option<RecoveryQuorum>,
    pub pending: Vec<Vec<u8>>,
    pub signer: Vec<u8>,
    pub sig: Vec<u8>,
}

/// Why a publication was refused.
///
/// One variant per rule, because "rejected" with no reason is a rule an operator
/// cannot act on and a rule a test cannot distinguish from the next one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AccessError {
    #[error("the access set is not canonical CBOR: {0}")]
    Encoding(#[from] CborError),
    #[error("a list in the access set is empty and may not be")]
    EmptyList(&'static str),
    #[error("a list in the access set is longer than {MAX_ENTRIES}")]
    TooManyEntries(&'static str),
    #[error("a list in the access set is not sorted and deduplicated")]
    Unsorted(&'static str),
    #[error("version {got} does not follow {expected}")]
    VersionNotNext { expected: u64, got: u64 },
    #[error("prev_hash names a set this relay has not accepted")]
    PrevHashMismatch,
    #[error("the signer is in neither the prior authorizers nor the prior recovery keys")]
    SignerNotPermitted,
    #[error("the signature does not verify over the set digest")]
    BadSignature,
    #[error("an authorizer or recovery key is not itself an entry")]
    PrincipalNotAnEntry,
    #[error("an ordinary publication may not remove the last {0}")]
    WouldStrandAuthority(&'static str),
    #[error("a recovery rotation may only {0}")]
    RotationShape(&'static str),
    #[error("this recovery principal already rotated within the last 24 hours")]
    RotationRateLimited,
    #[error("a probationary authorizer may only remove entries pinned by its rotation")]
    ProbationExceeded,
    #[error("the recovery quorum is malformed: {0}")]
    Quorum(&'static str),
    #[error("the workspace in the set is not the workspace of this connection")]
    WorkspaceMismatch,
}

impl AccessError {
    /// The wire code a client is answered with.
    ///
    /// Two classes and no more. A publication that is wrong about the chain is
    /// `denied`, because it may become right once the client fetches the current
    /// head and reissues; a publication that is wrong about its own bytes is
    /// `reject`, because resending them cannot help.
    pub fn code(&self) -> crate::frame::ErrorCode {
        use crate::frame::ErrorCode;
        match self {
            Self::Encoding(_)
            | Self::EmptyList(_)
            | Self::TooManyEntries(_)
            | Self::Unsorted(_)
            | Self::Quorum(_) => ErrorCode::MalformedHeader,
            Self::BadSignature => ErrorCode::NoncanonicalCbor,
            _ => ErrorCode::WriterNotInAccessSet,
        }
    }
}

impl AccessSet {
    /// Decode a published set.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccessError> {
        let mut reader = Reader::new(bytes);
        reader.array(11)?;
        let workspace = reader.bytes_of(HASH_BYTES)?;
        let version = reader.uint()?;
        let prev_hash = reader.bytes_of(HASH_BYTES)?;
        let issued_at = reader.uint()?;
        let entries = read_list(&mut reader, HASH_BYTES)?;
        let authorizers = read_list(&mut reader, KEY_BYTES)?;
        let recovery = read_list(&mut reader, KEY_BYTES)?;
        let quorum = read_quorum(&mut reader)?;
        let pending = read_list(&mut reader, HASH_BYTES)?;
        let signer = reader.bytes_of(KEY_BYTES)?;
        let sig = reader.bytes_of(SIG_BYTES)?;
        reader.finish()?;
        Ok(Self {
            workspace,
            version,
            prev_hash,
            issued_at,
            entries,
            authorizers,
            recovery,
            quorum,
            pending,
            signer,
            sig,
        })
    }

    /// The bytes an authorizer signs.
    ///
    /// The canonical encoding with `sig` and the quorum signatures omitted. That
    /// explicit omission is what stops the quorum proof from becoming a recursive
    /// "signature over the object containing this signature", while binding a
    /// confirmation to exactly one proposed transition.
    pub fn digest_input(&self) -> Vec<u8> {
        let quorum = self
            .quorum
            .as_ref()
            .map(|quorum| encode_quorum(quorum, false))
            .unwrap_or_else(|| cbor::optional_bytes(None));
        cbor::array(&[
            cbor::bytes(&self.workspace),
            cbor::uint(self.version),
            cbor::bytes(&self.prev_hash),
            cbor::uint(self.issued_at),
            encode_list(&self.entries),
            encode_list(&self.authorizers),
            encode_list(&self.recovery),
            quorum,
            encode_list(&self.pending),
            cbor::bytes(&self.signer),
        ])
    }

    /// BLAKE3 over ``digest_input``. The set's identity in the chain.
    pub fn digest(&self) -> [u8; HASH_BYTES] {
        *blake3::hash(&self.digest_input()).as_bytes()
    }

    /// Re-encode, whole. Round trips with ``decode``.
    pub fn encode(&self) -> Vec<u8> {
        let quorum = self
            .quorum
            .as_ref()
            .map(|quorum| encode_quorum(quorum, true))
            .unwrap_or_else(|| cbor::optional_bytes(None));
        cbor::array(&[
            cbor::bytes(&self.workspace),
            cbor::uint(self.version),
            cbor::bytes(&self.prev_hash),
            cbor::uint(self.issued_at),
            encode_list(&self.entries),
            encode_list(&self.authorizers),
            encode_list(&self.recovery),
            quorum,
            encode_list(&self.pending),
            cbor::bytes(&self.signer),
            cbor::bytes(&self.sig),
        ])
    }

    /// The shape checks that need no prior set: sizes, sorting, and the invariants
    /// a genesis publication must already satisfy.
    pub fn check_shape(&self) -> Result<(), AccessError> {
        check_list("entries", &self.entries, false)?;
        check_list("authorizers", &self.authorizers, false)?;
        check_list("recovery", &self.recovery, false)?;
        check_list("pending", &self.pending, true)?;
        if let Some(quorum) = &self.quorum {
            check_list("quorum", &quorum.keys, false)
                .map_err(|_| AccessError::Quorum("keys must be unique, sorted and non-empty"))?;
            if quorum.threshold == 0 || quorum.threshold as usize > quorum.keys.len() {
                return Err(AccessError::Quorum(
                    "threshold must be between 1 and the key count",
                ));
            }
        }
        Ok(())
    }

    /// Whether every authorizer and recovery key hashes to an entry.
    ///
    /// The relay can check this because it holds the salt, and it is the one
    /// liveness invariant it can verify without seeing the roster: an authorizer
    /// who is not a member is an authorizer who cannot connect to use the authority
    /// the set grants them.
    pub fn principals_are_entries(&self, salt: &[u8]) -> Result<(), AccessError> {
        for key in self.authorizers.iter().chain(self.recovery.iter()) {
            if !self
                .entries
                .iter()
                .any(|entry| entry == &entry_hash(key, salt))
            {
                return Err(AccessError::PrincipalNotAnEntry);
            }
        }
        Ok(())
    }

    /// Verify the signer's signature over the digest.
    pub fn signature_verifies(&self) -> bool {
        verify(&self.signer, &self.digest_input(), &self.sig)
    }

    /// Does the quorum confirm this transition for `replacement`?
    ///
    /// `m` distinct valid signatures by configured keys over
    /// `BLAKE3(label || set_digest || replacement_entry)`. Distinct is enforced,
    /// because `m` copies of one signature is one key pretending to be a quorum.
    pub fn quorum_confirms(&self, configured: &RecoveryQuorum, replacement: &[u8]) -> bool {
        let Some(carried) = &self.quorum else {
            return false;
        };
        if carried.sigs.is_empty() {
            return false;
        }
        let message = quorum_message(&self.digest(), replacement);
        let mut seen: Vec<&Vec<u8>> = Vec::new();
        for signature in &carried.sigs {
            if !configured.keys.contains(&signature.key) {
                continue;
            }
            if seen.contains(&&signature.key) {
                continue;
            }
            if verify(&signature.key, &message, &signature.sig) {
                seen.push(&signature.key);
            }
        }
        seen.len() >= configured.threshold as usize
    }
}

/// `BLAKE3(pubkey || workspace_salt)`, the only form of a principal the relay
/// stores as an entry.
pub fn entry_hash(pubkey: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(pubkey);
    hasher.update(salt);
    hasher.finalize().as_bytes().to_vec()
}

/// The answer to the state query: `[salt, [version, digest]]`, or a null head before
/// genesis.
///
/// Here rather than in `ws` so the client's decoder has one definition to mirror, the
/// way `AccessSet::encode` and the client's Swift decoder mirror each other. The
/// head is a nested array rather than two fields so that its absence is one null: a
/// version of zero is a real version and must not read as "no set".
pub fn encode_state(state: &store::State) -> Vec<u8> {
    let head = match &state.head {
        Some((version, digest)) => cbor::array(&[cbor::uint(*version), cbor::bytes(digest)]),
        None => cbor::NULL.to_vec(),
    };
    cbor::array(&[cbor::bytes(&state.salt), head])
}

/// What a quorum key signs to confirm one transition.
pub fn quorum_message(digest: &[u8], replacement_entry: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(QUORUM_CONFIRM_LABEL);
    hasher.update(digest);
    hasher.update(replacement_entry);
    hasher.finalize().as_bytes().to_vec()
}

/// One Ed25519 check, in one place.
///
/// Every wrong-shaped input answers false rather than propagating a type from the
/// signature crate: a 31-byte key and a bad signature are the same answer to the
/// only question this module asks, and two error paths for one answer is two paths
/// for a caller to get wrong.
pub fn verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Ok(key_bytes): Result<[u8; KEY_BYTES], _> = pubkey.try_into() else {
        return false;
    };
    let Ok(sig_bytes): Result<[u8; SIG_BYTES], _> = signature.try_into() else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    key.verify(message, &Signature::from_bytes(&sig_bytes))
        .is_ok()
}

// MARK: The transition rules

/// The prior state a transition is judged against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prior {
    pub version: u64,
    pub digest: Vec<u8>,
    pub entries: Vec<Vec<u8>>,
    pub authorizers: Vec<Vec<u8>>,
    pub recovery: Vec<Vec<u8>>,
    pub quorum: Option<RecoveryQuorum>,
}

/// A probationary authorizer and what it may remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probation {
    pub device: Vec<u8>,
    /// The version whose rotation introduced it.
    pub introduced_at: u64,
    pub pending: Vec<Vec<u8>>,
}

/// What accepting a transition does beyond storing it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Effects {
    /// A probation to open, when this was a recovery rotation.
    pub opens_probation: Option<Probation>,
    /// Devices whose probation this publication clears.
    pub clears_probation: Vec<Vec<u8>>,
    /// Entries the prior set carried and this one does not. Their sockets close.
    pub removed: Vec<Vec<u8>>,
}

/// Judge one publication against the prior state.
///
/// Everything the relay can decide without the roster, in one function, so the
/// order of the checks is visible in one place. The order matters: shape before
/// signature, because a malformed list should not make the relay hash a megabyte;
/// signature before semantics, because a set nobody signed has no meaning to
/// reason about.
pub fn judge(
    candidate: &AccessSet,
    prior: Option<&Prior>,
    salt: &[u8],
    probations: &[Probation],
    recovery_rotated_recently: bool,
) -> Result<(SignedAs, Effects), AccessError> {
    candidate.check_shape()?;
    candidate.principals_are_entries(salt)?;

    let Some(prior) = prior else {
        // Genesis. Signed by the trust root, which is its own sole authorizer, so
        // there is no prior list to be a member of and the set must name itself.
        if candidate.version != 0 {
            return Err(AccessError::VersionNotNext {
                expected: 0,
                got: candidate.version,
            });
        }
        if candidate.prev_hash != vec![0u8; HASH_BYTES] {
            return Err(AccessError::PrevHashMismatch);
        }
        if !candidate.authorizers.contains(&candidate.signer) {
            return Err(AccessError::SignerNotPermitted);
        }
        if !candidate.signature_verifies() {
            return Err(AccessError::BadSignature);
        }
        if !candidate.pending.is_empty() {
            return Err(AccessError::RotationShape("name pending entries"));
        }
        return Ok((SignedAs::Authorizer, Effects::default()));
    };

    if candidate.version != prior.version + 1 {
        return Err(AccessError::VersionNotNext {
            expected: prior.version + 1,
            got: candidate.version,
        });
    }
    if candidate.prev_hash != prior.digest {
        return Err(AccessError::PrevHashMismatch);
    }

    let as_authorizer = prior.authorizers.contains(&candidate.signer);
    let as_recovery = prior.recovery.contains(&candidate.signer);
    if !as_authorizer && !as_recovery {
        return Err(AccessError::SignerNotPermitted);
    }
    if !candidate.signature_verifies() {
        return Err(AccessError::BadSignature);
    }

    let removed: Vec<Vec<u8>> = prior
        .entries
        .iter()
        .filter(|entry| !candidate.entries.contains(entry))
        .cloned()
        .collect();

    if as_authorizer {
        return judge_ordinary(candidate, prior, salt, probations, removed);
    }
    judge_rotation(candidate, prior, salt, removed, recovery_rotated_recently)
}

/// An ordinary publication by a prior authorizer.
fn judge_ordinary(
    candidate: &AccessSet,
    prior: &Prior,
    salt: &[u8],
    probations: &[Probation],
    removed: Vec<Vec<u8>>,
) -> Result<(SignedAs, Effects), AccessError> {
    // The two liveness invariants the relay can verify without the roster. It is
    // deliberately narrower than "an admin remains", which only the encrypted
    // roster verifier can decide: this prevents an invalid or compromised client
    // from bricking connection-authority rotation, without pretending the relay
    // knows who is an admin.
    if !prior
        .authorizers
        .iter()
        .any(|key| candidate.authorizers.contains(key))
    {
        return Err(AccessError::WouldStrandAuthority("authorizer"));
    }
    if !prior
        .recovery
        .iter()
        .any(|key| candidate.recovery.contains(key))
    {
        return Err(AccessError::WouldStrandAuthority("recovery principal"));
    }
    if !candidate.pending.is_empty() {
        return Err(AccessError::RotationShape("name pending entries"));
    }

    // Probation. A device introduced by a recovery rotation may remove only what
    // its rotation pinned, and only until somebody who predates it says otherwise.
    if let Some(probation) = probations.iter().find(|p| p.device == candidate.signer) {
        if !removed
            .iter()
            .all(|entry| probation.pending.contains(entry))
        {
            return Err(AccessError::ProbationExceeded);
        }
    }

    // Who this publication clears. A publication by an authorizer that predates a
    // probation and that carries the probationary device clears it; so does one
    // carrying enough quorum signatures over that device's entry. Never a timer:
    // time cannot tell the owner who lost a laptop from somebody who copied a
    // phrase, so a timed promotion turns a theft into a delayed takeover.
    let mut clears = Vec::new();
    for probation in probations {
        if probation.device == candidate.signer {
            continue;
        }
        let entry = entry_hash(&probation.device, salt);
        if !candidate.entries.contains(&entry) {
            continue;
        }
        // A prior authorizer that is not itself probationary predates every
        // rotation by definition: a device introduced by one is recorded in
        // `probations` until it is cleared, and this signer is not there.
        if !probations
            .iter()
            .any(|other| other.device == candidate.signer)
        {
            clears.push(probation.device.clone());
            continue;
        }
        if let Some(configured) = &prior.quorum {
            if candidate.quorum_confirms(configured, &entry) {
                clears.push(probation.device.clone());
            }
        }
    }

    Ok((
        SignedAs::Authorizer,
        Effects {
            opens_probation: None,
            clears_probation: clears,
            removed,
        },
    ))
}

/// The one narrow transition a recovery principal may take.
fn judge_rotation(
    candidate: &AccessSet,
    prior: &Prior,
    salt: &[u8],
    removed: Vec<Vec<u8>>,
    rotated_recently: bool,
) -> Result<(SignedAs, Effects), AccessError> {
    if rotated_recently {
        return Err(AccessError::RotationRateLimited);
    }

    // Replaces the signer's own recovery entry with exactly one successor. The
    // rotate-on-use rule: a phrase is one-shot.
    if candidate.recovery.contains(&candidate.signer) {
        return Err(AccessError::RotationShape(
            "rotate the signer's own recovery key",
        ));
    }
    let new_recovery: Vec<&Vec<u8>> = candidate
        .recovery
        .iter()
        .filter(|key| !prior.recovery.contains(*key))
        .collect();
    if new_recovery.len() != 1 {
        return Err(AccessError::RotationShape(
            "replace its own recovery key with exactly one successor",
        ));
    }
    let dropped_recovery: Vec<&Vec<u8>> = prior
        .recovery
        .iter()
        .filter(|key| !candidate.recovery.contains(*key))
        .collect();
    if dropped_recovery != vec![&candidate.signer] {
        return Err(AccessError::RotationShape(
            "replace its own recovery key and no other",
        ));
    }

    // Adds exactly the replacement device and the successor recovery key, and
    // nothing else.
    //
    // Two hashes rather than the one `wire.md` counts, and the difference is not a
    // loosening. The prose says "adds exactly one entry, the replacement device" and
    // separately requires every recovery key to hash to an entry, so a rotation that
    // added only the device could not name a successor phrase at all and the
    // transition the whole rule exists for would be unpublishable. The successor's
    // entry arrives in place of the signer's, which leaves in the same publication:
    // the count of entries a rotation may add beyond that swap is still exactly one.
    // The plan file records the correction.
    let successor = new_recovery[0].clone();
    let added: Vec<Vec<u8>> = candidate
        .entries
        .iter()
        .filter(|entry| !prior.entries.contains(entry))
        .cloned()
        .collect();
    let mut permitted = vec![entry_hash(&successor, salt)];

    // Removes nothing else. The signer's own recovery entry leaves with it, and
    // nothing besides.
    let signer_entry = entry_hash(&candidate.signer, salt);
    if !removed.iter().all(|entry| entry == &signer_entry) {
        return Err(AccessError::RotationShape(
            "remove nothing but its own entry",
        ));
    }

    // Adds the replacement device to authorizers, and removes no authorizer.
    let added_authorizers: Vec<&Vec<u8>> = candidate
        .authorizers
        .iter()
        .filter(|key| !prior.authorizers.contains(*key))
        .collect();
    if added_authorizers.len() != 1 {
        return Err(AccessError::RotationShape(
            "add exactly the replacement device as an authorizer",
        ));
    }
    let replacement = added_authorizers[0].clone();
    permitted.push(entry_hash(&replacement, salt));
    permitted.sort();
    permitted.dedup();
    let mut added_sorted = added.clone();
    added_sorted.sort();
    added_sorted.dedup();
    if added_sorted != permitted {
        return Err(AccessError::RotationShape(
            "add exactly the replacement device and the successor recovery key",
        ));
    }
    if !prior
        .authorizers
        .iter()
        .all(|key| candidate.authorizers.contains(key))
    {
        return Err(AccessError::RotationShape("remove no authorizer"));
    }

    // The pinned removals. Every one must be an entry the prior set carried, and
    // none of them may be a prior authorizer: the lost-device set a user chose on
    // the recovery screen cannot include somebody else's admin.
    for entry in &candidate.pending {
        if !prior.entries.contains(entry) {
            return Err(AccessError::RotationShape(
                "pin only entries the prior set carried",
            ));
        }
        if prior
            .authorizers
            .iter()
            .any(|key| &entry_hash(key, salt) == entry)
        {
            return Err(AccessError::RotationShape("pin no prior authorizer"));
        }
    }

    Ok((
        SignedAs::Recovery,
        Effects {
            opens_probation: Some(Probation {
                device: replacement,
                introduced_at: candidate.version,
                pending: candidate.pending.clone(),
            }),
            clears_probation: Vec::new(),
            removed,
        },
    ))
}

// MARK: Encoding helpers

fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let encoded: Vec<Vec<u8>> = items.iter().map(|item| cbor::bytes(item)).collect();
    cbor::array(&encoded)
}

fn encode_quorum(quorum: &RecoveryQuorum, with_signatures: bool) -> Vec<u8> {
    let signatures = if with_signatures {
        let encoded: Vec<Vec<u8>> = quorum
            .sigs
            .iter()
            .map(|signature| {
                cbor::array(&[cbor::bytes(&signature.key), cbor::bytes(&signature.sig)])
            })
            .collect();
        cbor::array(&encoded)
    } else {
        cbor::array(&[])
    };
    cbor::array(&[
        cbor::uint(u64::from(quorum.threshold)),
        encode_list(&quorum.keys),
        signatures,
    ])
}

fn read_list(reader: &mut Reader<'_>, width: usize) -> Result<Vec<Vec<u8>>, AccessError> {
    let count = reader.array_header()?;
    if count > MAX_ENTRIES {
        return Err(AccessError::TooManyEntries("list"));
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(reader.bytes_of(width)?);
    }
    Ok(items)
}

/// The quorum, or its absence.
///
/// Absent is a CBOR null rather than an empty array, matching
/// ``cbor::optional_bytes``: an empty quorum and no quorum are different states and
/// a wire that spelled them the same way would make "registered with zero keys"
/// unrepresentable.
fn read_quorum(reader: &mut Reader<'_>) -> Result<Option<RecoveryQuorum>, AccessError> {
    if reader.optional_is_null()? {
        return Ok(None);
    }
    reader.array(3)?;
    let threshold = reader.u8()?;
    let keys = read_list(reader, KEY_BYTES)?;
    let count = reader.array_header()?;
    if count > MAX_ENTRIES {
        return Err(AccessError::TooManyEntries("quorum signatures"));
    }
    let mut sigs = Vec::with_capacity(count);
    for _ in 0..count {
        reader.array(2)?;
        sigs.push(QuorumSignature {
            key: reader.bytes_of(KEY_BYTES)?,
            sig: reader.bytes_of(SIG_BYTES)?,
        });
    }
    Ok(Some(RecoveryQuorum {
        threshold,
        keys,
        sigs,
    }))
}

/// Non-empty, bounded, sorted and deduplicated.
///
/// Sorted is not cosmetic. The digest covers the list in order, so an unsorted list
/// would let one logical set have many valid signatures, and the chain would no
/// longer name one state per version.
fn check_list(
    name: &'static str,
    items: &[Vec<u8>],
    may_be_empty: bool,
) -> Result<(), AccessError> {
    if items.is_empty() && !may_be_empty {
        return Err(AccessError::EmptyList(name));
    }
    if items.len() > MAX_ENTRIES {
        return Err(AccessError::TooManyEntries(name));
    }
    for pair in items.windows(2) {
        if pair[0] >= pair[1] {
            return Err(AccessError::Unsorted(name));
        }
    }
    Ok(())
}
