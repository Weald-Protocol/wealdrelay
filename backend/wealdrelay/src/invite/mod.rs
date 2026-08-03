// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The invite record: what an admit-holding device signs, and what the relay is
//! allowed to conclude from it.
//!
//! `specs/backend/relay/invites.md`. An invite is three things bundled: an
//! authorization naming what the bearer may join and until when, a renewable
//! encrypted `GroupInfo` per group in scope, and a one-time code delivered over a
//! different channel from the link.
//!
//! ## What is deliberately not here
//!
//! There is no decryption in this module and there is nowhere for one to go. The
//! relay stores `update_pub` and it stores `EncBundle::ct`, and it has no private
//! key for either. The 32-byte invite secret that derives the matching private half
//! travels in a URL fragment, which browsers do not send to servers and which the
//! deep link hands straight to the client. That is the property the whole design
//! turns on: any current member can refresh a bundle by sealing a fresh `GroupInfo`
//! to a public key, while neither the relay nor a removed member can open one.
//!
//! ## The mandatory root
//!
//! Every invite other than the empty-workspace bootstrap invite must include the
//! workspace root group in `scopes`. The root has no parent and so cannot use the
//! self-join mechanism; its per-invite `GroupInfo` is what lets a new device enter
//! the roster-bearing group at all. ``Invite::check_mandatory_root`` is the relay's
//! half of that rule and the client's Swift implementation is the other, because
//! invites.md requires both: the relay rejects a record that omits its declared
//! workspace root, and clients reject one before presenting it to the joiner.
//!
//! ## Two halves, deliberately separated
//!
//! Everything in this file is pure. `invite::store` holds the transactions, and
//! `invite::genesis` holds the one key the relay itself owns. The split is the same
//! one `access` makes for the same reason: the rules are the part worth testing
//! exhaustively, and a rule reachable only through a socket and a Postgres round
//! trip is a rule nobody covers.

pub mod code;
pub mod delivery;
pub mod genesis;
pub mod redeem;
pub mod reserve;
pub mod store;

use crate::cbor::{self, CborError, Reader};

/// The lookup key, and the Argon2id salt for the code.
pub const TOKEN_BYTES: usize = 16;
/// A join nonce is the same width as a token, for the same reason: it is a random
/// identifier and nothing else.
pub const NONCE_BYTES: usize = 16;
pub const KEY_BYTES: usize = 32;
pub const HASH_BYTES: usize = 32;
pub const SIG_BYTES: usize = 64;

/// Seven days, in milliseconds. The default life of an invite.
///
/// Short because an external commit means a stolen invite is exploitable for its
/// lifetime without an admin being online to notice (invites.md, "Validation, and
/// its honest limit").
pub const DEFAULT_EXPIRY_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Twenty-four hours, in milliseconds. The life of the bootstrap invite.
///
/// Longer than an ordinary invite rather than shorter, because the buyer may not
/// have installed the app yet and there is nothing of value in an empty workspace
/// to protect with a tight window. The provisioning configuration names the same
/// twenty-four hours, so the two agree.
pub const BOOTSTRAP_EXPIRY_MS: u64 = 24 * 60 * 60 * 1000;

/// The default seat count.
pub const DEFAULT_USES: u8 = 1;

/// 64 seats per invite record (invites.md, "Rate limits").
pub const MAX_USES: u8 = 64;

/// A bound on the scope list.
///
/// Not a policy about workspace size; a bound on what one record may make the relay
/// allocate before any signature has been checked.
pub const MAX_SCOPES: usize = 256;

/// A bound on the capability list, for the same reason.
pub const MAX_CAPS: usize = 64;

/// The largest sealed bundle the relay will store for one scope.
///
/// A `GroupInfo` plus, for an `open` group, that group's history key. Sized well
/// past a realistic ratchet tree so a legitimate large group is never refused, and
/// bounded so a token holder cannot use the bundle table as storage.
pub const MAX_BUNDLE_BYTES: usize = 256 * 1024;

/// The capability vocabulary from `specs/backend/relay/identity.md`, as the wire
/// carries it: UTF-8 bytes inside a CBOR byte string, because this wire has no text
/// string type (`crate::cbor`).
pub const CAPABILITIES: &[&str] = &[
    "chat.read",
    "chat.write",
    "ticket.read",
    "ticket.write",
    "ticket.create",
    "git.patch.propose",
    "media.write",
    "admit",
    "roster.revoke",
    "admin",
];

/// The one capability that takes an argument: `ticket.transition:<from>-><to>`.
pub const TRANSITION_PREFIX: &str = "ticket.transition:";

/// A `GroupInfo` sealed to one invite's `update_pub`, and for an `open` group that
/// group's history key alongside it.
///
/// The history key is what makes an `open` scope arrive populated, and it is the
/// same key a self-joiner unwraps from `history.publish` under the parent enrolment
/// key. One mechanism, two deliveries, so an invited member and a member who joined
/// the channel by itself see the same room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncBundle {
    pub group: Vec<u8>,
    pub epoch: u64,
    /// Opaque. Nothing in this crate opens it and nothing in this crate holds a key
    /// that could.
    pub ct: Vec<u8>,
}

/// One invite record, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub token: Vec<u8>,
    /// The workspace root group id.
    pub workspace: Vec<u8>,
    /// The admitting device's public key.
    pub issuer: Vec<u8>,
    pub issued_at: u64,
    pub expires: u64,
    pub uses: u8,
    /// Argon2id of the one-time code, salted with `token`.
    pub code_hash: Vec<u8>,
    pub scopes: Vec<Vec<u8>>,
    pub caps: Vec<Vec<u8>>,
    /// X25519 public key derived from the URL secret.
    pub update_pub: Vec<u8>,
    pub bundles: Vec<EncBundle>,
    pub sig: Vec<u8>,
}

/// Why a record was refused.
///
/// One variant per rule. "Rejected" with no reason is a rule an operator cannot act
/// on and a rule a test cannot tell apart from the next one. These are the reasons
/// the relay records; what a joiner is *told* is `Unavailable` and nothing more,
/// because invites.md requires the redeem surface to be uninformative about which
/// of expired, revoked, spent, cooled down or nonexistent it was.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InviteError {
    #[error("the invite is not canonical CBOR: {0}")]
    Encoding(#[from] CborError),
    #[error("the scope list is longer than {MAX_SCOPES}")]
    TooManyScopes,
    #[error("the capability list is longer than {MAX_CAPS}")]
    TooManyCaps,
    #[error("the scope list is not sorted and deduplicated")]
    UnsortedScopes,
    #[error("the capability list is not sorted and deduplicated")]
    UnsortedCaps,
    #[error("capability {0} is not in the vocabulary")]
    UnknownCapability(String),
    #[error("uses must be between 1 and {MAX_USES}")]
    UsesOutOfRange,
    #[error("expires is not after issued_at")]
    ExpiryNotAfterIssue,
    #[error("there must be exactly one bundle per scope, in scope order")]
    BundleMismatch,
    #[error("a sealed bundle is larger than {MAX_BUNDLE_BYTES} bytes")]
    BundleTooLarge,
    #[error("a sealed bundle is empty")]
    BundleEmpty,
    #[error("the invite omits its declared workspace root group")]
    MissingWorkspaceRoot,
    #[error("only the empty-workspace bootstrap invite may carry no scopes")]
    ScopelessAndNotBootstrap,
    #[error("the bootstrap invite must carry admin and only admin")]
    BootstrapCapsWrong,
    #[error("the signature does not verify over the record")]
    BadSignature,
    #[error("the invite expired")]
    Expired,
}

impl InviteError {
    /// The wire code a member publishing or refreshing an invite is answered with.
    ///
    /// The redeem path never uses this: a joiner gets ``UNAVAILABLE`` whatever went
    /// wrong. This is for the authenticated member who uploaded a record, who is
    /// entitled to know which rule they broke, and it uses only codes already in
    /// the closed registry (`specs/backend/contracts/registries/error-codes.md`).
    pub fn code(&self) -> crate::frame::ErrorCode {
        use crate::frame::ErrorCode;
        match self {
            Self::Encoding(_) => ErrorCode::NoncanonicalCbor,
            Self::BadSignature => ErrorCode::NoncanonicalCbor,
            Self::TooManyScopes
            | Self::TooManyCaps
            | Self::UnsortedScopes
            | Self::UnsortedCaps
            | Self::UnknownCapability(_)
            | Self::UsesOutOfRange
            | Self::ExpiryNotAfterIssue
            | Self::BundleMismatch
            | Self::BundleTooLarge
            | Self::BundleEmpty
            | Self::BootstrapCapsWrong => ErrorCode::MalformedHeader,
            Self::MissingWorkspaceRoot | Self::ScopelessAndNotBootstrap | Self::Expired => {
                ErrorCode::WriterNotInAccessSet
            }
        }
    }
}

/// The one answer a joiner ever gets when a redemption does not proceed.
///
/// invites.md: "A request arriving with no capacity left, or against a redeemed,
/// revoked, expired or nonexistent token, receives the same generic unavailable
/// response, so the endpoint stays uninformative about which of those it was." A
/// cooldown answers the same way, which is what stops the endpoint from confirming
/// that a token exists by telling an attacker they are being throttled on it.
///
/// `quota/seats_exhausted` carries no `retry_after`, deliberately: an interval would
/// be the oracle the flat answer exists to remove.
pub const UNAVAILABLE: crate::frame::ErrorCode = crate::frame::ErrorCode::SeatsExhausted;

impl Invite {
    /// Decode a record.
    pub fn decode(bytes: &[u8]) -> Result<Self, InviteError> {
        let mut reader = Reader::new(bytes);
        reader.array(12)?;
        let token = reader.bytes_of(TOKEN_BYTES)?;
        let workspace = reader.bytes_of(HASH_BYTES)?;
        let issuer = reader.bytes_of(KEY_BYTES)?;
        let issued_at = reader.uint()?;
        let expires = reader.uint()?;
        let uses = reader.u8()?;
        let code_hash = reader.bytes_of(HASH_BYTES)?;
        let scopes = read_group_list(&mut reader)?;
        let caps = read_cap_list(&mut reader)?;
        let update_pub = reader.bytes_of(KEY_BYTES)?;
        let bundles = read_bundles(&mut reader)?;
        let sig = reader.bytes_of(SIG_BYTES)?;
        reader.finish()?;
        Ok(Self {
            token,
            workspace,
            issuer,
            issued_at,
            expires,
            uses,
            code_hash,
            scopes,
            caps,
            update_pub,
            bundles,
            sig,
        })
    }

    /// The bytes the issuer signs: the canonical encoding with `sig` omitted.
    pub fn digest_input(&self) -> Vec<u8> {
        cbor::array(&[
            cbor::bytes(&self.token),
            cbor::bytes(&self.workspace),
            cbor::bytes(&self.issuer),
            cbor::uint(self.issued_at),
            cbor::uint(self.expires),
            cbor::uint(u64::from(self.uses)),
            cbor::bytes(&self.code_hash),
            encode_list(&self.scopes),
            encode_list(&self.caps),
            cbor::bytes(&self.update_pub),
            encode_bundles(&self.bundles),
        ])
    }

    /// Re-encode, whole. Round trips with ``decode``.
    pub fn encode(&self) -> Vec<u8> {
        let mut items: Vec<Vec<u8>> = vec![
            cbor::bytes(&self.token),
            cbor::bytes(&self.workspace),
            cbor::bytes(&self.issuer),
            cbor::uint(self.issued_at),
            cbor::uint(self.expires),
            cbor::uint(u64::from(self.uses)),
            cbor::bytes(&self.code_hash),
            encode_list(&self.scopes),
            encode_list(&self.caps),
            cbor::bytes(&self.update_pub),
            encode_bundles(&self.bundles),
        ];
        items.push(cbor::bytes(&self.sig));
        cbor::array(&items)
    }

    /// BLAKE3 over ``digest_input``. The record's identity.
    pub fn digest(&self) -> [u8; HASH_BYTES] {
        *blake3::hash(&self.digest_input()).as_bytes()
    }

    /// Whether this record claims to be the empty-workspace bootstrap invite.
    ///
    /// Shape only: a scopeless record. Whether it is *the* bootstrap invite is a
    /// question about the relay's own genesis row, and `invite::genesis` answers it.
    pub fn is_bootstrap_shaped(&self) -> bool {
        self.scopes.is_empty()
    }

    /// Sizes, sorting, and the invariants that need no relay state.
    pub fn check_shape(&self) -> Result<(), InviteError> {
        if self.scopes.len() > MAX_SCOPES {
            return Err(InviteError::TooManyScopes);
        }
        if self.caps.len() > MAX_CAPS {
            return Err(InviteError::TooManyCaps);
        }
        if !is_sorted_unique(&self.scopes) {
            return Err(InviteError::UnsortedScopes);
        }
        if !is_sorted_unique(&self.caps) {
            return Err(InviteError::UnsortedCaps);
        }
        for cap in &self.caps {
            check_capability(cap)?;
        }
        if self.uses == 0 || self.uses > MAX_USES {
            return Err(InviteError::UsesOutOfRange);
        }
        if self.expires <= self.issued_at {
            return Err(InviteError::ExpiryNotAfterIssue);
        }
        self.check_bundles()
    }

    /// Exactly one bundle per scope, in scope order, each sealed and bounded.
    ///
    /// Order rather than a lookup, because two bundles for one group would let an
    /// uploader decide which one a joiner reads by ordering alone, and a bundle for
    /// a group not in scope is material the record has no authority to carry.
    fn check_bundles(&self) -> Result<(), InviteError> {
        if self.bundles.len() != self.scopes.len() {
            return Err(InviteError::BundleMismatch);
        }
        for (bundle, scope) in self.bundles.iter().zip(self.scopes.iter()) {
            if &bundle.group != scope {
                return Err(InviteError::BundleMismatch);
            }
            if bundle.ct.is_empty() {
                return Err(InviteError::BundleEmpty);
            }
            if bundle.ct.len() > MAX_BUNDLE_BYTES {
                return Err(InviteError::BundleTooLarge);
            }
        }
        Ok(())
    }

    /// The mandatory-root rule.
    ///
    /// `bootstrap` is the relay's own answer to "is this the empty-workspace
    /// bootstrap invite", never the record's claim about itself: a record that could
    /// exempt itself from the rule by carrying no scopes would be the rule's own
    /// bypass. A scopeless record that is not the bootstrap invite is refused, and
    /// the bootstrap invite must carry `admin` and only `admin`.
    pub fn check_mandatory_root(&self, bootstrap: bool) -> Result<(), InviteError> {
        if self.scopes.is_empty() {
            if !bootstrap {
                return Err(InviteError::ScopelessAndNotBootstrap);
            }
            if self.caps.len() != 1 || self.caps[0] != b"admin" {
                return Err(InviteError::BootstrapCapsWrong);
            }
            return Ok(());
        }
        if !self.scopes.contains(&self.workspace) {
            return Err(InviteError::MissingWorkspaceRoot);
        }
        Ok(())
    }

    /// Verify the issuer's signature over the record.
    pub fn signature_verifies(&self) -> bool {
        crate::access::verify(&self.issuer, &self.digest_input(), &self.sig)
    }
}

/// Judge one record, in the order the checks have to happen.
///
/// Shape before signature, because a malformed list should not make the relay hash a
/// megabyte. Signature before semantics, because a record nobody signed has no
/// meaning to reason about. The mandatory root and the expiry last, because both are
/// statements about a record that is already known to be authentic.
///
/// `now_ms` is the relay's clock and never the record's `issued_at`: an expiry
/// evaluated against a client-supplied time is not an expiry.
pub fn judge(invite: &Invite, bootstrap: bool, now_ms: u64) -> Result<(), InviteError> {
    invite.check_shape()?;
    if !invite.signature_verifies() {
        return Err(InviteError::BadSignature);
    }
    invite.check_mandatory_root(bootstrap)?;
    if now_ms >= invite.expires {
        return Err(InviteError::Expired);
    }
    Ok(())
}

fn is_sorted_unique(items: &[Vec<u8>]) -> bool {
    items.windows(2).all(|pair| pair[0] < pair[1])
}

/// A capability is one of the fixed names, or the one form that takes an argument.
fn check_capability(cap: &[u8]) -> Result<(), InviteError> {
    let Ok(text) = std::str::from_utf8(cap) else {
        return Err(InviteError::UnknownCapability(hex(cap)));
    };
    if CAPABILITIES.contains(&text) {
        return Ok(());
    }
    if let Some(argument) = text.strip_prefix(TRANSITION_PREFIX) {
        // `<from>-><to>`, both non-empty. An empty side would name a transition
        // with no end, which is a capability that grants nothing and would still
        // have to be carried forever.
        if let Some((from, to)) = argument.split_once("->") {
            if !from.is_empty() && !to.is_empty() {
                return Ok(());
            }
        }
    }
    Err(InviteError::UnknownCapability(text.to_string()))
}

/// Lower-case hex, for naming a capability that is not text at all.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let encoded: Vec<Vec<u8>> = items.iter().map(|item| cbor::bytes(item)).collect();
    cbor::array(&encoded)
}

fn encode_bundles(bundles: &[EncBundle]) -> Vec<u8> {
    let encoded: Vec<Vec<u8>> = bundles
        .iter()
        .map(|bundle| {
            cbor::array(&[
                cbor::bytes(&bundle.group),
                cbor::uint(bundle.epoch),
                cbor::bytes(&bundle.ct),
            ])
        })
        .collect();
    cbor::array(&encoded)
}

fn read_group_list(reader: &mut Reader<'_>) -> Result<Vec<Vec<u8>>, InviteError> {
    let count = reader.array_header()?;
    if count > MAX_SCOPES {
        return Err(InviteError::TooManyScopes);
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(reader.bytes_of(HASH_BYTES)?);
    }
    Ok(items)
}

fn read_cap_list(reader: &mut Reader<'_>) -> Result<Vec<Vec<u8>>, InviteError> {
    let count = reader.array_header()?;
    if count > MAX_CAPS {
        return Err(InviteError::TooManyCaps);
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(reader.bytes()?);
    }
    Ok(items)
}

fn read_bundles(reader: &mut Reader<'_>) -> Result<Vec<EncBundle>, InviteError> {
    let count = reader.array_header()?;
    if count > MAX_SCOPES {
        return Err(InviteError::TooManyScopes);
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        reader.array(3)?;
        let group = reader.bytes_of(HASH_BYTES)?;
        let epoch = reader.uint()?;
        let ct = reader.bytes()?;
        if ct.len() > MAX_BUNDLE_BYTES {
            return Err(InviteError::BundleTooLarge);
        }
        items.push(EncBundle { group, epoch, ct });
    }
    Ok(items)
}
