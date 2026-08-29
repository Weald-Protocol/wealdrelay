// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `agent.card`, as Rust reads it.
//!
//! The mirror of `Sources/Sync/Agents/AgentCard.swift` and
//! `AgentCardCodec.swift`, written from `specs/agents/networked/protocol.md` rather
//! than translated from them, for the reason `agent_cbor` explains: two halves of
//! one reading agree with each other no matter what either gets wrong.
//!
//! # Check order is part of the protocol
//!
//! Every rejected vector in `Tests/Fixtures/agents/` carries exactly one defect and
//! names the one reason it must produce. That is only a well-formed requirement if
//! both codecs check in the same sequence, because a card whose aliases are
//! unsorted is also a card whose stored `cardHash` was computed over unsorted
//! aliases, and a codec that compared the hash first would refuse it for the wrong
//! reason. So the order below is normative and is stated in `protocol.md`:
//!
//! 1. The schema map: ascending keys, no unknown key, nothing trailing.
//! 2. `hostKind`, then `availability`, against their closed vocabularies.
//! 3. `aliases`: canonical order, non-empty, lowercased.
//! 4. `capabilities`: canonical order, then the closed vocabulary.
//! 5. `scopes`, at their fixed width.
//! 6. The `org` block, and its presence against `hostKind`.
//! 7. The remaining fixed-width and scalar slots.
//! 8. `cardHash`, recomputed and compared.
//! 9. `sig`, verified under `ownerPrincipal`. Only in `decode_verified`.
//!
//! Nine is separate from one through eight on purpose. Decoding answers "are these
//! bytes a card"; verification answers "did the principal it names write it". A
//! client may show an unverifiable card as unverified, but nothing is ever
//! projected without `decode_verified`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::agent_cbor::{self as cbor, CborError, Reader};

/// `AGENT_PROTOCOL_VERSION`.
pub const PROTOCOL_VERSION: u64 = 2;

pub const AGENT_ID_WIDTH: usize = 32;
pub const CARD_HASH_WIDTH: usize = 32;
pub const SCOPE_WIDTH: usize = 32;
pub const ORG_ID_WIDTH: usize = 32;

/// The closed set of schema slots. Numbers are permanent: a retired slot is never
/// reused, because a card signed under the old meaning would still verify under the
/// new one.
pub mod key {
    pub const V: u64 = 1;
    pub const AGENT_ID: u64 = 2;
    pub const HOST_KIND: u64 = 3;
    pub const OWNER_PRINCIPAL: u64 = 4;
    pub const DISPLAY_NAME: u64 = 5;
    pub const ALIASES: u64 = 6;
    pub const SCOPES: u64 = 7;
    pub const CAPABILITIES: u64 = 8;
    pub const AVAILABILITY: u64 = 9;
    pub const PROFILE_VERSION: u64 = 10;
    pub const CARD_HASH: u64 = 11;
    pub const ISSUED_AT: u64 = 12;
    pub const EXPIRES_AT: u64 = 13;
    pub const ORG: u64 = 14;
    pub const SIG: u64 = 15;
    pub const CODE: u64 = 16;

    /// The decoder's allow-list. Every key, and nothing else.
    pub const SCHEMA: [u64; 16] = [
        V,
        AGENT_ID,
        HOST_KIND,
        OWNER_PRINCIPAL,
        DISPLAY_NAME,
        ALIASES,
        SCOPES,
        CAPABILITIES,
        AVAILABILITY,
        PROFILE_VERSION,
        CARD_HASH,
        ISSUED_AT,
        EXPIRES_AT,
        ORG,
        SIG,
        CODE,
    ];
}

/// Version 1 is exactly these three. There is no administrative capability and
/// there is no wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    /// The only capability that produces content.
    ChatReply,
    ReadChannel,
    ReadTicket,
    CodePullRequest,
    /// Weald CI: a client inside the customer's own pipeline reporting a run as
    /// an agent. It writes no branch, so `ci-module.md` refuses a card that also
    /// carries `CodePullRequest` rather than trusting a policy to hold later.
    CiReport,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::ChatReply => "chat.reply",
            Capability::ReadChannel => "read.channel",
            Capability::ReadTicket => "read.ticket",
            Capability::CodePullRequest => "code.pullrequest",
            Capability::CiReport => "ci.report",
        }
    }

    /// `pub` because `agent_invoke` carries one capability out of the same closed
    /// vocabulary. One parser, not two: a second copy is a second place for the
    /// vocabulary to open.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "chat.reply" => Some(Capability::ChatReply),
            "read.channel" => Some(Capability::ReadChannel),
            "read.ticket" => Some(Capability::ReadTicket),
            "code.pullrequest" => Some(Capability::CodePullRequest),
            "ci.report" => Some(Capability::CiReport),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    User,
    Organization,
}

impl HostKind {
    fn raw(self) -> u64 {
        match self {
            HostKind::User => 0,
            HostKind::Organization => 1,
        }
    }

    fn parse(raw: u64) -> Option<Self> {
        match raw {
            0 => Some(HostKind::User),
            1 => Some(HostKind::Organization),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    Online,
    Offline,
    Suspended,
}

impl Availability {
    fn raw(self) -> u64 {
        match self {
            Availability::Online => 0,
            Availability::Offline => 1,
            Availability::Suspended => 2,
        }
    }

    fn parse(raw: u64) -> Option<Self> {
        match raw {
            0 => Some(Availability::Online),
            1 => Some(Availability::Offline),
            2 => Some(Availability::Suspended),
            _ => None,
        }
    }
}

/// Present only when `host_kind` is `Organization`, and required then. Both halves
/// of that are decode errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Org {
    pub org_id: Vec<u8>,
    pub gateway_region: String,
    pub provider: String,
    pub model: String,
    pub retention_policy: String,
    pub cost_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRepository {
    pub repository_id: u64,
    pub repo_ref: String,
    pub base_branch: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestPolicy {
    pub argv: Vec<String>,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    pub repos: Vec<CodeRepository>,
    pub installation_id: u64,
    pub test: Option<TestPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCard {
    pub v: u64,
    pub agent_id: Vec<u8>,
    pub host_kind: HostKind,
    pub owner_principal: Vec<u8>,
    pub display_name: String,
    pub aliases: Vec<String>,
    pub scopes: Vec<Vec<u8>>,
    pub capabilities: Vec<Capability>,
    pub availability: Availability,
    pub profile_version: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub org: Option<Org>,
    pub code: Option<Code>,
    pub sig: Vec<u8>,
}

/// Why a card was refused. The CBOR layer's refusals pass through unchanged so a
/// caller has one error type and one reason vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardError {
    Cbor(CborError),
    UnknownCapability(String),
    UnknownHostKind(u64),
    UnknownAvailability(u64),
    /// An organization card with no `org` block, or a user card carrying one.
    OrgBlockMismatch {
        host_kind: HostKind,
        present: bool,
    },
    CardHashMismatch {
        stored: Vec<u8>,
        computed: Vec<u8>,
    },
    /// `aliases` or `capabilities` out of order, or repeating.
    ListNotCanonical(&'static str),
    EmptyAlias,
    AliasNotLowercased(String),
    CodeBlockMismatch,
    /// A card carrying both `ci.report` and `code.pullrequest`. A CI client is
    /// admitted only because it is never a second Git writer, and this makes that
    /// unrepresentable in bytes rather than enforced by a policy somewhere later.
    CapabilityExclusive,
    CodeRepositoriesInvalid,
    RepositoryRefInvalid(String),
    BranchInvalid(String),
    TestPolicyInvalid,
    /// `sig` does not verify under `owner_principal`, or `owner_principal` is not a
    /// key at all.
    SignatureInvalid,
}

impl From<CborError> for CardError {
    fn from(error: CborError) -> Self {
        CardError::Cbor(error)
    }
}

impl CardError {
    /// The closed reason code, matching `AgentCodecReason` in Swift and the
    /// `reason` column of the shared corpus manifest.
    pub fn reason(&self) -> &'static str {
        match self {
            CardError::Cbor(inner) => inner.reason(),
            CardError::UnknownCapability(_) => "codec.capability.unknown",
            CardError::UnknownHostKind(_) => "codec.hostkind.unknown",
            CardError::UnknownAvailability(_) => "codec.availability.unknown",
            CardError::OrgBlockMismatch { .. } => "codec.org.mismatch",
            CardError::CardHashMismatch { .. } => "codec.cardhash.mismatch",
            CardError::ListNotCanonical(_) => "codec.list.order",
            CardError::EmptyAlias => "codec.alias.empty",
            CardError::AliasNotLowercased(_) => "codec.alias.case",
            CardError::CodeBlockMismatch => "codec.code.mismatch",
            CardError::CapabilityExclusive => "codec.capability.exclusive",
            CardError::CodeRepositoriesInvalid => "codec.code.repos",
            CardError::RepositoryRefInvalid(_) => "codec.repo.ref",
            CardError::BranchInvalid(_) => "codec.branch.ref",
            CardError::TestPolicyInvalid => "codec.test.policy",
            CardError::SignatureInvalid => "codec.signature.invalid",
        }
    }
}

impl std::fmt::Display for CardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CardError::Cbor(inner) => write!(f, "{inner}"),
            CardError::UnknownCapability(value) => {
                write!(
                    f,
                    "'{value}' is not a version 1 capability. The vocabulary is closed."
                )
            }
            CardError::UnknownHostKind(raw) => {
                write!(f, "host kind {raw} is not user or organization")
            }
            CardError::UnknownAvailability(raw) => {
                write!(f, "availability {raw} is not online, offline or suspended")
            }
            CardError::OrgBlockMismatch { host_kind, present } => {
                if *host_kind == HostKind::Organization {
                    write!(f, "an organization card must carry an org block")
                } else {
                    write!(
                        f,
                        "a user card must not carry an org block (present: {present})"
                    )
                }
            }
            CardError::CardHashMismatch { stored, computed } => write!(
                f,
                "cardHash {} does not cover this card (computed {})",
                hex4(stored),
                hex4(computed)
            ),
            CardError::ListNotCanonical(field) => {
                write!(f, "{field} is not in canonical order, or repeats an entry")
            }
            CardError::EmptyAlias => write!(f, "an empty alias would match every bare mention"),
            CardError::AliasNotLowercased(alias) => write!(
                f,
                "alias '{alias}' is not lowercased; mentions resolve case-insensitively"
            ),
            CardError::CodeBlockMismatch => write!(
                f,
                "code block must be present exactly with code.pullrequest"
            ),
            CardError::CapabilityExclusive => write!(
                f,
                "ci.report and code.pullrequest cannot appear on one card"
            ),
            CardError::CodeRepositoriesInvalid => write!(
                f,
                "code repositories must contain 1...100 unique ids and refs in id order"
            ),
            CardError::RepositoryRefInvalid(value) => {
                write!(f, "repository ref '{value}' is not canonical owner/name")
            }
            CardError::BranchInvalid(value) => {
                write!(f, "base branch '{value}' is not a valid Git ref")
            }
            CardError::TestPolicyInvalid => {
                write!(f, "direct-exec test policy is outside its closed bounds")
            }
            CardError::SignatureInvalid => write!(
                f,
                "the card's signature does not verify under its own ownerPrincipal"
            ),
        }
    }
}

impl std::error::Error for CardError {}

fn hex4(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

pub type Result<T> = std::result::Result<T, CardError>;

// ------------------------------------------------------------------- encoding

/// The bytes `cardHash` covers and `sig` signs: every field except those two.
///
/// One function for both, because a signature over one set of bytes and a hash over
/// another would let a card whose hash matches carry a signature that does not.
pub fn signing_input(card: &AgentCard) -> Vec<u8> {
    cbor::map(&body_pairs(card))
}

/// BLAKE3 over `signing_input`, 32 bytes. The same digest the envelope's content
/// address uses, so there is one hash function in the protocol rather than two.
pub fn card_hash(card: &AgentCard) -> Vec<u8> {
    blake3::hash(&signing_input(card)).as_bytes().to_vec()
}

/// The full card, including `cardHash` and `sig`.
pub fn encode(card: &AgentCard) -> Vec<u8> {
    let mut pairs = body_pairs(card);
    pairs.push((key::CARD_HASH, cbor::bytes(&card_hash(card))));
    pairs.push((key::SIG, cbor::bytes(&card.sig)));
    cbor::map(&pairs)
}

fn body_pairs(card: &AgentCard) -> Vec<(u64, Vec<u8>)> {
    let mut pairs = vec![
        (key::V, cbor::uint(card.v)),
        (key::AGENT_ID, cbor::bytes(&card.agent_id)),
        (key::HOST_KIND, cbor::uint(card.host_kind.raw())),
        (key::OWNER_PRINCIPAL, cbor::bytes(&card.owner_principal)),
        (key::DISPLAY_NAME, cbor::text(&card.display_name)),
        (
            key::ALIASES,
            cbor::array(
                &card
                    .aliases
                    .iter()
                    .map(|a| cbor::text(a))
                    .collect::<Vec<_>>(),
            ),
        ),
        (
            key::SCOPES,
            cbor::array(
                &card
                    .scopes
                    .iter()
                    .map(|s| cbor::bytes(s))
                    .collect::<Vec<_>>(),
            ),
        ),
        (
            key::CAPABILITIES,
            cbor::array(
                &card
                    .capabilities
                    .iter()
                    .map(|c| cbor::text(c.as_str()))
                    .collect::<Vec<_>>(),
            ),
        ),
        (key::AVAILABILITY, cbor::uint(card.availability.raw())),
        (key::PROFILE_VERSION, cbor::uint(card.profile_version)),
        (key::ISSUED_AT, cbor::uint(card.issued_at)),
        (key::EXPIRES_AT, cbor::uint(card.expires_at)),
    ];
    if let Some(org) = &card.org {
        // Positional, because the org block's fields are fixed and it is not what
        // the schema walk defends: a leak would have to add a key to `SCHEMA`, which
        // is where the walk looks.
        pairs.push((
            key::ORG,
            cbor::array(&[
                cbor::bytes(&org.org_id),
                cbor::text(&org.gateway_region),
                cbor::text(&org.provider),
                cbor::text(&org.model),
                cbor::text(&org.retention_policy),
                cbor::text(&org.cost_policy),
            ]),
        ));
    }
    if let Some(code) = &card.code {
        pairs.push((key::CODE, encode_code(code)));
    }
    pairs
}

fn encode_code(code: &Code) -> Vec<u8> {
    let repos = code
        .repos
        .iter()
        .map(|repo| {
            let mut fields = vec![cbor::uint(repo.repository_id), cbor::text(&repo.repo_ref)];
            if let Some(branch) = &repo.base_branch {
                fields.push(cbor::text(branch));
            }
            cbor::array(&fields)
        })
        .collect::<Vec<_>>();
    let mut fields = vec![cbor::array(&repos), cbor::uint(code.installation_id)];
    if let Some(test) = &code.test {
        fields.push(cbor::array(&[
            cbor::array(
                &test
                    .argv
                    .iter()
                    .map(|arg| cbor::text(arg))
                    .collect::<Vec<_>>(),
            ),
            cbor::uint(test.timeout_seconds),
        ]));
    }
    cbor::array(&fields)
}

// ------------------------------------------------------------------- decoding

/// Structure only. See the module comment on why this does not verify.
pub fn decode(data: &[u8]) -> Result<AgentCard> {
    let mut reader = Reader::new(data);
    let slots = reader.schema_map(&key::SCHEMA)?;
    reader.require_end()?;

    let host_kind_raw = cbor::in_slot(&slots, key::HOST_KIND, |r| r.uint())?;
    let host_kind =
        HostKind::parse(host_kind_raw).ok_or(CardError::UnknownHostKind(host_kind_raw))?;

    let availability_raw = cbor::in_slot(&slots, key::AVAILABILITY, |r| r.uint())?;
    let availability = Availability::parse(availability_raw)
        .ok_or(CardError::UnknownAvailability(availability_raw))?;

    let aliases = text_list(&slots, key::ALIASES)?;
    require_canonical(&aliases, "aliases")?;
    for alias in &aliases {
        if alias.is_empty() {
            return Err(CardError::EmptyAlias);
        }
        if *alias != alias.to_lowercase() {
            return Err(CardError::AliasNotLowercased(alias.clone()));
        }
    }

    let capability_strings = text_list(&slots, key::CAPABILITIES)?;
    require_canonical(&capability_strings, "capabilities")?;
    let mut capabilities = Vec::with_capacity(capability_strings.len());
    for raw in &capability_strings {
        capabilities
            .push(Capability::parse(raw).ok_or_else(|| CardError::UnknownCapability(raw.clone()))?);
    }

    let scopes = cbor::in_slot(&slots, key::SCOPES, |r| {
        let count = r.array_count()?;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(r.bytes_exact(SCOPE_WIDTH)?);
        }
        Ok(out)
    })?;

    // `optional_slot`, because `org` is the one slot whose absence is legal and
    // matching on `slot`'s error left an arm nothing could reach.
    let org = cbor::optional_slot(&slots, key::ORG)
        .map(decode_org)
        .transpose()?;
    if (host_kind == HostKind::Organization) != org.is_some() {
        return Err(CardError::OrgBlockMismatch {
            host_kind,
            present: org.is_some(),
        });
    }
    let code = cbor::optional_slot(&slots, key::CODE)
        .map(decode_code)
        .transpose()?;
    if capabilities.contains(&Capability::CiReport)
        && capabilities.contains(&Capability::CodePullRequest)
    {
        return Err(CardError::CapabilityExclusive);
    }
    let has_code_capability = capabilities.contains(&Capability::CodePullRequest);
    if has_code_capability != code.is_some() {
        return Err(CardError::CodeBlockMismatch);
    }

    let card = AgentCard {
        v: cbor::in_slot(&slots, key::V, |r| r.uint())?,
        agent_id: cbor::in_slot(&slots, key::AGENT_ID, |r| r.bytes_exact(AGENT_ID_WIDTH))?,
        host_kind,
        owner_principal: cbor::in_slot(&slots, key::OWNER_PRINCIPAL, |r| r.bytes())?,
        display_name: cbor::in_slot(&slots, key::DISPLAY_NAME, |r| r.text())?,
        aliases,
        scopes,
        capabilities,
        availability,
        profile_version: cbor::in_slot(&slots, key::PROFILE_VERSION, |r| r.uint())?,
        issued_at: cbor::in_slot(&slots, key::ISSUED_AT, |r| r.uint())?,
        expires_at: cbor::in_slot(&slots, key::EXPIRES_AT, |r| r.uint())?,
        org,
        code,
        sig: cbor::in_slot(&slots, key::SIG, |r| r.bytes())?,
    };

    // Recomputed rather than trusted. A stored `cardHash` a peer chose is a
    // constant, and every later step keys a card's identity on it.
    let stored = cbor::in_slot(&slots, key::CARD_HASH, |r| r.bytes_exact(CARD_HASH_WIDTH))?;
    let computed = card_hash(&card);
    if stored != computed {
        return Err(CardError::CardHashMismatch { stored, computed });
    }
    Ok(card)
}

fn decode_code(data: &[u8]) -> Result<Code> {
    let mut r = Reader::new(data);
    let count = r.array_count()?;
    if count != 2 && count != 3 {
        return Err(CborError::WrongArrayCount {
            expected: 2,
            got: count,
        }
        .into());
    }
    let repo_count = r.array_count()?;
    if !(1..=100).contains(&repo_count) {
        return Err(CardError::CodeRepositoriesInvalid);
    }
    let mut repos = Vec::with_capacity(repo_count);
    for _ in 0..repo_count {
        let fields = r.array_count()?;
        if fields != 2 && fields != 3 {
            return Err(CborError::WrongArrayCount {
                expected: 2,
                got: fields,
            }
            .into());
        }
        let repository_id = r.uint()?;
        let repo_ref = r.text()?;
        if !valid_repo_ref(&repo_ref) {
            return Err(CardError::RepositoryRefInvalid(repo_ref));
        }
        let base_branch = if fields == 3 { Some(r.text()?) } else { None };
        if let Some(branch) = &base_branch {
            if !valid_branch(branch) {
                return Err(CardError::BranchInvalid(branch.clone()));
            }
        }
        repos.push(CodeRepository {
            repository_id,
            repo_ref,
            base_branch,
        });
    }
    if !repos
        .windows(2)
        .all(|w| w[0].repository_id < w[1].repository_id)
    {
        return Err(CardError::CodeRepositoriesInvalid);
    }
    let mut refs = std::collections::HashSet::new();
    if !repos
        .iter()
        .all(|repo| refs.insert(repo.repo_ref.to_ascii_lowercase()))
    {
        return Err(CardError::CodeRepositoriesInvalid);
    }
    let installation_id = r.uint()?;
    let test = if count == 3 {
        let fields = r.array_count()?;
        if fields != 2 {
            return Err(CborError::WrongArrayCount {
                expected: 2,
                got: fields,
            }
            .into());
        }
        let argc = r.array_count()?;
        if !(1..=32).contains(&argc) {
            return Err(CardError::TestPolicyInvalid);
        }
        let mut argv = Vec::with_capacity(argc);
        for _ in 0..argc {
            let arg = r.text()?;
            if arg.is_empty() || arg.len() > 1024 {
                return Err(CardError::TestPolicyInvalid);
            }
            argv.push(arg);
        }
        let timeout_seconds = r.uint()?;
        if !(1..=900).contains(&timeout_seconds) {
            return Err(CardError::TestPolicyInvalid);
        }
        Some(TestPolicy {
            argv,
            timeout_seconds,
        })
    } else {
        None
    };
    r.require_end()?;
    Ok(Code {
        repos,
        installation_id,
        test,
    })
}

fn valid_repo_ref(value: &str) -> bool {
    if !value.is_ascii() {
        return false;
    }
    let mut parts = value.split('/');
    let owner = parts.next().unwrap_or_default();
    let repo = parts.next().unwrap_or_default();
    parts.next().is_none()
        && !owner.is_empty()
        && owner.len() <= 39
        && !repo.is_empty()
        && owner
            .bytes()
            .enumerate()
            .all(|(i, b)| b.is_ascii_alphanumeric() || (i > 0 && matches!(b, b'.' | b'_' | b'-')))
        && repo
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn valid_branch(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with(['/', '.', '-'])
        && !value.ends_with(['/', '.'])
        && !["..", "@{", "//", "\\", " ", "~", "^", ":", "?", "*", "["]
            .iter()
            .any(|bad| value.contains(bad))
        && value.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// `sig` verifies under `owner_principal` over `signing_input`.
pub fn verify(card: &AgentCard) -> Result<()> {
    let principal: [u8; 32] = card
        .owner_principal
        .as_slice()
        .try_into()
        .map_err(|_| CardError::SignatureInvalid)?;
    let signature: [u8; 64] = card
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| CardError::SignatureInvalid)?;
    let key = VerifyingKey::from_bytes(&principal).map_err(|_| CardError::SignatureInvalid)?;
    key.verify(&signing_input(card), &Signature::from_bytes(&signature))
        .map_err(|_| CardError::SignatureInvalid)
}

/// Decode and verify. The only entry point a projection may use.
pub fn decode_verified(data: &[u8]) -> Result<AgentCard> {
    let card = decode(data)?;
    verify(&card)?;
    Ok(card)
}

fn text_list(slots: &[(u64, Vec<u8>)], key: u64) -> Result<Vec<String>> {
    Ok(cbor::in_slot(slots, key, |r| {
        let count = r.array_count()?;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(r.text()?);
        }
        Ok(out)
    })?)
}

fn decode_org(data: &[u8]) -> Result<Org> {
    let mut r = Reader::new(data);
    let count = r.array_count()?;
    if count != 6 {
        return Err(CborError::WrongArrayCount {
            expected: 6,
            got: count,
        }
        .into());
    }
    let org = Org {
        org_id: r.bytes_exact(ORG_ID_WIDTH)?,
        gateway_region: r.text()?,
        provider: r.text()?,
        model: r.text()?,
        retention_policy: r.text()?,
        cost_policy: r.text()?,
    };
    r.require_end()?;
    Ok(org)
}

/// Strictly ascending: sorted, and no repeats.
///
/// Both halves matter for the same reason the map keys ascend. `["b", "a"]` and
/// `["a", "b"]` name the same agent, and if both encode there are two `cardHash`
/// values for one card. A repeat is the degenerate case of the same problem.
fn require_canonical(values: &[String], field: &'static str) -> Result<()> {
    if values.windows(2).all(|w| w[0] < w[1]) {
        Ok(())
    } else {
        Err(CardError::ListNotCanonical(field))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// The same two fixed seeds `scripts/agents-vectors.py` uses, so a card built
    /// here and a card built there are the same card.
    fn owner_key() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    fn stranger_key() -> SigningKey {
        SigningKey::from_bytes(&[0x22; 32])
    }

    fn org_block() -> Org {
        Org {
            org_id: vec![0x33; 32],
            gateway_region: "us-east".into(),
            provider: "anthropic".into(),
            model: "claude-sonnet-4-6".into(),
            retention_policy: "none".into(),
            cost_policy: "metered".into(),
        }
    }

    fn unsigned(host_kind: HostKind, org: Option<Org>) -> AgentCard {
        AgentCard {
            v: PROTOCOL_VERSION,
            agent_id: vec![0xa1; 32],
            host_kind,
            owner_principal: owner_key().verifying_key().to_bytes().to_vec(),
            display_name: "Researcher".into(),
            aliases: vec!["researcher.p1".into()],
            scopes: vec![vec![0x5c; 32]],
            capabilities: vec![Capability::ChatReply, Capability::ReadChannel],
            availability: Availability::Online,
            profile_version: 1,
            issued_at: 1_760_000_000,
            expires_at: 1_790_000_000,
            org,
            code: None,
            sig: vec![],
        }
    }

    fn signed(mut card: AgentCard, key: &SigningKey) -> AgentCard {
        card.owner_principal = key.verifying_key().to_bytes().to_vec();
        card.sig = key.sign(&signing_input(&card)).to_bytes().to_vec();
        card
    }

    fn user_card() -> AgentCard {
        signed(unsigned(HostKind::User, None), &owner_key())
    }

    /// Re-lay an encoded card's pairs, so a test can corrupt one slot without
    /// rebuilding the whole encoding by hand.
    fn slots_of(data: &[u8]) -> Vec<(u64, Vec<u8>)> {
        Reader::new(data).schema_map(&key::SCHEMA).unwrap()
    }

    #[test]
    fn agent_coding_error_messages_and_malformed_nested_arrays_are_covered() {
        for error in [
            CardError::CodeBlockMismatch,
            CardError::CodeRepositoriesInvalid,
            CardError::RepositoryRefInvalid("bad ref".into()),
            CardError::BranchInvalid("bad branch".into()),
            CardError::TestPolicyInvalid,
        ] {
            assert!(!error.to_string().is_empty());
        }
        assert!(matches!(
            decode_code(&cbor::array(&[cbor::array(&[])])),
            Err(CardError::Cbor(CborError::WrongArrayCount { got: 1, .. }))
        ));
        assert!(matches!(
            decode_code(&cbor::array(&[
                cbor::array(&[cbor::array(&[cbor::uint(1)])]),
                cbor::uint(1),
            ])),
            Err(CardError::Cbor(CborError::WrongArrayCount { got: 1, .. }))
        ));
        assert!(matches!(
            decode_code(&cbor::array(&[
                cbor::array(&[cbor::array(&[cbor::uint(1), cbor::text("owner/repo"),])]),
                cbor::uint(1),
                cbor::array(&[cbor::array(&[cbor::text("test")])]),
            ])),
            Err(CardError::Cbor(CborError::WrongArrayCount { got: 1, .. }))
        ));
        assert!(!valid_repo_ref("é/repo"));
    }

    // ------------------------------------------------------------ round trips

    #[test]
    fn a_user_card_round_trips() {
        let card = user_card();
        let encoded = encode(&card);
        let decoded = decode_verified(&encoded).unwrap();
        assert_eq!(decoded, card);
        assert_eq!(encode(&decoded), encoded);
    }

    #[test]
    fn an_organization_card_round_trips() {
        let card = signed(
            unsigned(HostKind::Organization, Some(org_block())),
            &owner_key(),
        );
        let decoded = decode_verified(&encode(&card)).unwrap();
        assert_eq!(decoded.org, Some(org_block()));
        assert_eq!(decoded, card);
    }

    #[test]
    fn empty_lists_round_trip() {
        let mut card = unsigned(HostKind::User, None);
        card.aliases.clear();
        card.scopes.clear();
        card.capabilities.clear();
        let card = signed(card, &owner_key());
        assert_eq!(decode_verified(&encode(&card)).unwrap(), card);
    }

    #[test]
    fn every_vocabulary_value_round_trips() {
        for availability in [
            Availability::Online,
            Availability::Offline,
            Availability::Suspended,
        ] {
            let mut card = unsigned(HostKind::User, None);
            card.availability = availability;
            card.capabilities = vec![
                Capability::ChatReply,
                Capability::ReadChannel,
                Capability::ReadTicket,
            ];
            let card = signed(card, &owner_key());
            let decoded = decode_verified(&encode(&card)).unwrap();
            assert_eq!(decoded.availability, availability);
            assert_eq!(decoded.capabilities.len(), 3);
        }
        for host_kind in [HostKind::User, HostKind::Organization] {
            assert_eq!(HostKind::parse(host_kind.raw()), Some(host_kind));
        }
        for capability in [
            Capability::ChatReply,
            Capability::ReadChannel,
            Capability::ReadTicket,
        ] {
            assert_eq!(Capability::parse(capability.as_str()), Some(capability));
        }
    }

    #[test]
    fn encoding_is_stable_and_ascending() {
        let card = user_card();
        assert_eq!(encode(&card), encode(&card));
        let keys: Vec<u64> = slots_of(&encode(&card)).iter().map(|(k, _)| *k).collect();
        assert!(keys.windows(2).all(|w| w[0] < w[1]));
        // Every slot but the two optional blocks.
        assert_eq!(keys.len(), key::SCHEMA.len() - 2);
        assert!(!keys.contains(&key::ORG));
    }

    #[test]
    fn card_hash_covers_the_card_and_not_the_signature() {
        let card = user_card();
        let mut tampered = card.clone();
        tampered.sig = vec![0; 64];
        assert_eq!(card_hash(&card), card_hash(&tampered));
        assert_eq!(card_hash(&card).len(), CARD_HASH_WIDTH);

        // And every covered field moves it.
        let mut moved = card.clone();
        moved.display_name = "Other".into();
        assert_ne!(card_hash(&card), card_hash(&moved));
        let mut moved = card.clone();
        moved.profile_version += 1;
        assert_ne!(card_hash(&card), card_hash(&moved));
        let mut moved = card.clone();
        moved.org = Some(org_block());
        assert_ne!(card_hash(&card), card_hash(&moved));
    }

    // ------------------------------------------------------------- signatures

    #[test]
    fn a_card_signed_by_a_stranger_does_not_verify() {
        let mut forged = user_card();
        // The forgery: keep the genuine owner in the card, sign with another key.
        forged.sig = stranger_key()
            .sign(&signing_input(&forged))
            .to_bytes()
            .to_vec();
        // Structurally perfect, which is what makes the signature check
        // load-bearing rather than redundant.
        assert!(decode(&encode(&forged)).is_ok());
        assert_eq!(
            decode_verified(&encode(&forged)).unwrap_err(),
            CardError::SignatureInvalid
        );
    }

    #[test]
    fn an_owner_principal_that_is_not_a_key_is_refused_as_unsigned() {
        let mut card = user_card();
        card.owner_principal = vec![0x00; 31];
        assert_eq!(verify(&card).unwrap_err(), CardError::SignatureInvalid);

        // The right width and still not a point on the curve.
        let mut card = user_card();
        card.owner_principal = vec![0xff; 32];
        assert_eq!(verify(&card).unwrap_err(), CardError::SignatureInvalid);

        // A signature of the wrong width.
        let mut card = user_card();
        card.sig = vec![0x00; 63];
        assert_eq!(verify(&card).unwrap_err(), CardError::SignatureInvalid);
    }

    // ---------------------------------------------------------------- refusals

    #[test]
    fn a_key_outside_the_schema_is_refused() {
        let mut pairs = slots_of(&encode(&user_card()));
        pairs.push((17, cbor::text("a system prompt")));
        assert_eq!(
            decode(&cbor::map(&pairs)).unwrap_err(),
            CardError::Cbor(CborError::UnknownKey(17))
        );
    }

    #[test]
    fn a_missing_slot_is_refused() {
        for missing in key::SCHEMA {
            let pairs: Vec<(u64, Vec<u8>)> = slots_of(&encode(&user_card()))
                .into_iter()
                .filter(|(k, _)| *k != missing)
                .collect();
            // `org` is the one slot a user card does not carry, so removing it is a
            // no-op rather than a refusal.
            if missing == key::ORG || missing == key::CODE {
                assert!(decode(&cbor::map(&pairs)).is_ok());
                continue;
            }
            assert_eq!(
                decode(&cbor::map(&pairs)).unwrap_err(),
                CardError::Cbor(CborError::MissingKey(missing)),
                "removing slot {missing} was not refused as a missing key"
            );
        }
    }

    #[test]
    fn trailing_and_truncated_bytes_are_refused() {
        let mut encoded = encode(&user_card());
        encoded.push(0x00);
        assert_eq!(
            decode(&encoded).unwrap_err(),
            CardError::Cbor(CborError::Trailing(1))
        );

        let encoded = encode(&user_card());
        assert_eq!(
            decode(&encoded[..encoded.len() - 3]).unwrap_err(),
            CardError::Cbor(CborError::Truncated)
        );
    }

    #[test]
    fn an_unknown_vocabulary_value_is_refused() {
        let replace = |k: u64, value: Vec<u8>| {
            let pairs: Vec<(u64, Vec<u8>)> = slots_of(&encode(&user_card()))
                .into_iter()
                .map(|(key, existing)| (key, if key == k { value.clone() } else { existing }))
                .collect();
            decode(&cbor::map(&pairs)).unwrap_err()
        };
        assert_eq!(
            replace(key::HOST_KIND, cbor::uint(2)),
            CardError::UnknownHostKind(2)
        );
        assert_eq!(
            replace(key::AVAILABILITY, cbor::uint(3)),
            CardError::UnknownAvailability(3)
        );
        assert_eq!(
            replace(key::CAPABILITIES, cbor::array(&[cbor::text("admin.all")])),
            CardError::UnknownCapability("admin.all".into())
        );
        assert_eq!(
            replace(key::AGENT_ID, cbor::bytes(&[0xa1; 31])),
            CardError::Cbor(CborError::WrongLength {
                expected: 32,
                got: 31
            })
        );
        assert_eq!(
            replace(key::SCOPES, cbor::array(&[cbor::bytes(&[0x5c; 31])])),
            CardError::Cbor(CborError::WrongLength {
                expected: 32,
                got: 31
            })
        );
        assert_eq!(
            replace(key::DISPLAY_NAME, cbor::uint(1)),
            CardError::Cbor(CborError::TypeMismatch("text string"))
        );
    }

    #[test]
    fn a_forged_card_hash_is_refused() {
        let pairs: Vec<(u64, Vec<u8>)> = slots_of(&encode(&user_card()))
            .into_iter()
            .map(|(k, v)| {
                if k == key::CARD_HASH {
                    (k, cbor::bytes(&[0xee; 32]))
                } else {
                    (k, v)
                }
            })
            .collect();
        let error = decode(&cbor::map(&pairs)).unwrap_err();
        assert!(matches!(error, CardError::CardHashMismatch { .. }));
        assert_eq!(error.reason(), "codec.cardhash.mismatch");
    }

    /// The lists are checked before the hash, which is why a vector carrying one
    /// unsorted list produces `codec.list.order` and not `codec.cardhash.mismatch`.
    /// Built through `encode` so the hash matches the malformed body, which is the
    /// only way the ordering rule is what fails.
    #[test]
    fn non_canonical_lists_are_refused_and_before_the_hash() {
        let mut card = unsigned(HostKind::User, None);
        card.aliases = vec!["rp1".into(), "researcher".into()];
        let card = signed(card, &owner_key());
        assert_eq!(
            decode(&encode(&card)).unwrap_err(),
            CardError::ListNotCanonical("aliases")
        );

        let mut card = unsigned(HostKind::User, None);
        card.aliases = vec!["researcher".into(), "researcher".into()];
        let card = signed(card, &owner_key());
        assert_eq!(
            decode(&encode(&card)).unwrap_err(),
            CardError::ListNotCanonical("aliases")
        );

        let mut card = unsigned(HostKind::User, None);
        card.capabilities = vec![Capability::ReadChannel, Capability::ChatReply];
        let card = signed(card, &owner_key());
        assert_eq!(
            decode(&encode(&card)).unwrap_err(),
            CardError::ListNotCanonical("capabilities")
        );
    }

    #[test]
    fn a_bad_alias_is_refused() {
        let mut card = unsigned(HostKind::User, None);
        card.aliases = vec![String::new()];
        let card = signed(card, &owner_key());
        assert_eq!(decode(&encode(&card)).unwrap_err(), CardError::EmptyAlias);

        let mut card = unsigned(HostKind::User, None);
        card.aliases = vec!["Researcher.P1".into()];
        let card = signed(card, &owner_key());
        assert_eq!(
            decode(&encode(&card)).unwrap_err(),
            CardError::AliasNotLowercased("Researcher.P1".into())
        );
    }

    #[test]
    fn the_org_block_must_match_the_host_kind() {
        let orgless = signed(unsigned(HostKind::Organization, None), &owner_key());
        assert_eq!(
            decode(&encode(&orgless)).unwrap_err(),
            CardError::OrgBlockMismatch {
                host_kind: HostKind::Organization,
                present: false
            }
        );

        let extra = signed(unsigned(HostKind::User, Some(org_block())), &owner_key());
        assert_eq!(
            decode(&encode(&extra)).unwrap_err(),
            CardError::OrgBlockMismatch {
                host_kind: HostKind::User,
                present: true
            }
        );
    }

    #[test]
    fn an_org_block_of_the_wrong_arity_is_refused() {
        let pairs: Vec<(u64, Vec<u8>)> = slots_of(&encode(&signed(
            unsigned(HostKind::Organization, Some(org_block())),
            &owner_key(),
        )))
        .into_iter()
        .map(|(k, v)| {
            if k == key::ORG {
                (
                    k,
                    cbor::array(&[cbor::bytes(&[0x33; 32]), cbor::text("us-east")]),
                )
            } else {
                (k, v)
            }
        })
        .collect();
        assert_eq!(
            decode(&cbor::map(&pairs)).unwrap_err(),
            CardError::Cbor(CborError::WrongArrayCount {
                expected: 6,
                got: 2
            })
        );
    }

    #[test]
    fn an_org_slot_that_is_not_an_array_is_refused() {
        let pairs: Vec<(u64, Vec<u8>)> = slots_of(&encode(&signed(
            unsigned(HostKind::Organization, Some(org_block())),
            &owner_key(),
        )))
        .into_iter()
        .map(|(k, v)| {
            if k == key::ORG {
                (k, cbor::uint(1))
            } else {
                (k, v)
            }
        })
        .collect();
        assert_eq!(
            decode(&cbor::map(&pairs)).unwrap_err(),
            CardError::Cbor(CborError::TypeMismatch("array"))
        );
    }

    #[test]
    fn an_org_block_with_trailing_bytes_is_refused() {
        let mut org = cbor::array(&[
            cbor::bytes(&[0x33; 32]),
            cbor::text("us-east"),
            cbor::text("anthropic"),
            cbor::text("claude-sonnet-4-6"),
            cbor::text("none"),
            cbor::text("metered"),
        ]);
        org.push(0x00);
        assert_eq!(
            decode_org(&org).unwrap_err(),
            CardError::Cbor(CborError::Trailing(1))
        );
    }

    // ----------------------------------------------------------------- reasons

    #[test]
    fn every_error_names_a_reason_and_says_what_went_wrong() {
        let all = [
            CardError::Cbor(CborError::Truncated),
            CardError::UnknownCapability("x".into()),
            CardError::UnknownHostKind(9),
            CardError::UnknownAvailability(9),
            CardError::OrgBlockMismatch {
                host_kind: HostKind::Organization,
                present: false,
            },
            CardError::OrgBlockMismatch {
                host_kind: HostKind::User,
                present: true,
            },
            CardError::CardHashMismatch {
                stored: vec![1, 2, 3, 4, 5],
                computed: vec![6, 7, 8, 9, 10],
            },
            CardError::ListNotCanonical("aliases"),
            CardError::EmptyAlias,
            CardError::AliasNotLowercased("A".into()),
            CardError::SignatureInvalid,
        ];
        for error in all {
            assert!(error.reason().starts_with("codec."));
            assert!(!error.to_string().is_empty());
            assert!(!format!("{error:?}").is_empty());
            assert!(std::error::Error::source(&error).is_none());
        }
        assert_eq!(hex4(&[0xde, 0xad, 0xbe, 0xef, 0x99]), "deadbeef");
    }

    #[test]
    fn an_unknown_capability_and_host_kind_parse_to_none() {
        assert_eq!(Capability::parse("admin.all"), None);
        assert_eq!(HostKind::parse(2), None);
        assert_eq!(Availability::parse(3), None);
    }
}
