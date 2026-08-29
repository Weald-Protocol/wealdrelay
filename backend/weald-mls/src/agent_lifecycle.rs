// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `agent.lifecycle` and `agent.lease`, as Rust reads them.
//!
//! The mirror of `Sources/Sync/Agents/AgentLifecycle.swift`, `AgentLease.swift` and
//! their two codecs, written from `specs/agents/networked/protocol.md` rather than
//! translated, for the reason `agent_cbor` states.
//!
//! # Three field-presence rules belong to the codec
//!
//! `reason` is required for `failed`, `declined` and `expired`; `result_message_id`
//! appears only on `completed`; `detail` is bounded. Each is a way a record can be
//! readable and meaningless: a failure nobody can be told anything about, a
//! completion whose content cannot be found, and an unbounded field where a provider
//! error arrives verbatim and takes a credential with it. Refused at decode, no
//! client renders it, including the one whose bug wrote it.
//!
//! # `requested` is not a state a host may write
//!
//! `protocol.md` says it is implied by the invoke event, so it is absent from the
//! enum rather than present and forbidden. A record carrying it is refused by the
//! closed vocabulary rather than by a rule somebody has to remember.
//!
//! # Epoch ordering is not here
//!
//! "A higher epoch supersedes" is a statement about two leases and a codec sees one.
//! The fold that owns it is `AgentLeaseFold` in Swift; this crate carries the codecs,
//! because the corpus is what both languages must agree on and the fold's proof is
//! two app instances rather than two codecs.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::agent_cbor::{self as cbor, CborError, Reader};

pub use crate::agent_card::PROTOCOL_VERSION;

pub const INVOCATION_ID_WIDTH: usize = 16;
pub const RESULT_MESSAGE_ID_WIDTH: usize = 16;
pub const AGENT_ID_WIDTH: usize = 32;

/// The `detail` bound, in UTF-8 bytes. Enforced by the codec: see the module comment.
pub const DETAIL_BYTE_LIMIT: usize = 512;

/// The closed lifecycle decline vocabulary from `protocol.md`.
///
/// Carried as strings rather than an enum, and deliberately: this crate has no need
/// to *interpret* a reason, only to refuse one that is not in the set, and a
/// twenty-six case enum whose only operation is set membership would be twenty-six
/// places for the set to drift from the Swift copy.
pub const LIFECYCLE_REASONS: [&str; 39] = [
    "version.unsupported",
    "profile.stale",
    "scope.notmember",
    "scope.unassigned",
    "delegation.missing",
    "delegation.expired",
    "capability.denied",
    "policy.remote.disabled",
    "budget.rate",
    "budget.cost",
    "tool.tier",
    "deadline.passed",
    "host.offline",
    "lease.notheld",
    "agent.revoked",
    "org.suspended",
    "org.quota",
    "provider.auth",
    "provider.ratelimited",
    "provider.overloaded",
    "provider.badrequest",
    "provider.context",
    "provider.filtered",
    "provider.model",
    "provider.transport",
    "provider.malformed",
    "repo.unbound",
    "branch.protected",
    "config.untrusted",
    "egress.refused",
    "budget.reached",
    "source.unsupported",
    "patch.invalid",
    "base.stale",
    "tests.failed",
    "github.auth",
    "github.ratelimited",
    "github.transport",
    "runner.unavailable",
];

pub mod key {
    pub const V: u64 = 1;
    pub const INVOCATION_ID: u64 = 2;
    pub const STATE: u64 = 3;
    pub const AT: u64 = 4;
    pub const HOST: u64 = 5;
    pub const REASON: u64 = 6;
    pub const DETAIL: u64 = 7;
    pub const RESULT_MESSAGE_ID: u64 = 8;
    pub const SIG: u64 = 9;
    pub const PHASE: u64 = 10;

    pub const SCHEMA: [u64; 10] = [
        V,
        INVOCATION_ID,
        STATE,
        AT,
        HOST,
        REASON,
        DETAIL,
        RESULT_MESSAGE_ID,
        SIG,
        PHASE,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Claiming,
    Checkout,
    Planning,
    Editing,
    Testing,
    Pushing,
}
impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claiming => "claiming",
            Self::Checkout => "checkout",
            Self::Planning => "planning",
            Self::Editing => "editing",
            Self::Testing => "testing",
            Self::Pushing => "pushing",
        }
    }
    /// The phase named by this string, or nothing.
    ///
    /// Public because the gateway reads a phase out of a control-plane column
    /// and must publish only a phase this vocabulary names: the alternative was
    /// a second copy of the six words in `weald-agent-gateway`, and a second
    /// copy is how a client comes to meet a phase it cannot decode.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "claiming" => Some(Self::Claiming),
            "checkout" => Some(Self::Checkout),
            "planning" => Some(Self::Planning),
            "editing" => Some(Self::Editing),
            "testing" => Some(Self::Testing),
            "pushing" => Some(Self::Pushing),
            _ => None,
        }
    }
}

pub mod lease_key {
    pub const V: u64 = 1;
    pub const AGENT_ID: u64 = 2;
    pub const HOLDER: u64 = 3;
    pub const EPOCH: u64 = 4;
    pub const ACQUIRED_AT: u64 = 5;
    pub const EXPIRES_AT: u64 = 6;
    pub const SIG: u64 = 7;

    pub const SCHEMA: [u64; 7] = [V, AGENT_ID, HOLDER, EPOCH, ACQUIRED_AT, EXPIRES_AT, SIG];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Accepted,
    Running,
    Completed,
    Failed,
    Declined,
    Expired,
    Cancelled,
}

impl State {
    pub fn raw(self) -> u64 {
        match self {
            State::Accepted => 1,
            State::Running => 2,
            State::Completed => 3,
            State::Failed => 4,
            State::Declined => 5,
            State::Expired => 6,
            State::Cancelled => 7,
        }
    }

    pub fn parse(raw: u64) -> Option<Self> {
        match raw {
            1 => Some(State::Accepted),
            2 => Some(State::Running),
            3 => Some(State::Completed),
            4 => Some(State::Failed),
            5 => Some(State::Declined),
            6 => Some(State::Expired),
            7 => Some(State::Cancelled),
            _ => None,
        }
    }

    pub fn is_terminal(self) -> bool {
        !matches!(self, State::Accepted | State::Running)
    }

    pub fn requires_reason(self) -> bool {
        matches!(self, State::Failed | State::Declined | State::Expired)
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            State::Accepted => "accepted",
            State::Running => "running",
            State::Completed => "completed",
            State::Failed => "failed",
            State::Declined => "declined",
            State::Expired => "expired",
            State::Cancelled => "cancelled",
        };
        f.write_str(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentLifecycle {
    pub v: u64,
    pub invocation_id: Vec<u8>,
    pub state: State,
    pub at: u64,
    pub host: Vec<u8>,
    pub reason: Option<String>,
    pub detail: Option<String>,
    pub result_message_id: Option<Vec<u8>>,
    pub phase: Option<Phase>,
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentLease {
    pub v: u64,
    pub agent_id: Vec<u8>,
    pub holder: Vec<u8>,
    pub epoch: u64,
    pub acquired_at: u64,
    pub expires_at: u64,
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    Cbor(CborError),
    UnknownState(u64),
    UnknownReason(String),
    ReasonMismatch {
        state: State,
        present: bool,
    },
    ResultMismatch {
        state: State,
        present: bool,
    },
    DetailTooLong(usize),
    UnknownPhase(String),
    PhaseMismatch {
        state: State,
        present: bool,
    },
    /// A lease whose `expires_at` is not after its `acquired_at`.
    EmptyWindow {
        acquired_at: u64,
        expires_at: u64,
    },
    SignatureInvalid,
}

impl From<CborError> for LifecycleError {
    fn from(error: CborError) -> Self {
        LifecycleError::Cbor(error)
    }
}

impl LifecycleError {
    pub fn reason(&self) -> &'static str {
        match self {
            LifecycleError::Cbor(inner) => inner.reason(),
            LifecycleError::UnknownState(_) => "codec.state.unknown",
            LifecycleError::UnknownReason(_) => "codec.reason.unknown",
            LifecycleError::ReasonMismatch { .. } => "codec.reason.mismatch",
            LifecycleError::ResultMismatch { .. } => "codec.result.mismatch",
            LifecycleError::DetailTooLong(_) => "codec.detail.toolong",
            LifecycleError::UnknownPhase(_) => "codec.phase.unknown",
            LifecycleError::PhaseMismatch { .. } => "codec.phase.mismatch",
            LifecycleError::EmptyWindow { .. } => "codec.lease.window",
            LifecycleError::SignatureInvalid => "codec.signature.invalid",
        }
    }
}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LifecycleError::Cbor(inner) => write!(f, "{inner}"),
            LifecycleError::UnknownState(raw) => {
                write!(f, "lifecycle state {raw} is not one a host may write")
            }
            LifecycleError::UnknownReason(raw) => {
                write!(
                    f,
                    "'{raw}' is not a lifecycle reason. The vocabulary is closed."
                )
            }
            LifecycleError::ReasonMismatch { state, present } => {
                if *present {
                    write!(f, "{state} carries a reason and must not")
                } else {
                    write!(f, "{state} requires a reason and carries none")
                }
            }
            LifecycleError::ResultMismatch { state, present } => {
                if *present {
                    write!(f, "{state} names a result message and only completed may")
                } else {
                    write!(f, "completed must name the message its content arrived as")
                }
            }
            LifecycleError::DetailTooLong(bytes) => {
                write!(
                    f,
                    "detail is {bytes} bytes and the bound is {DETAIL_BYTE_LIMIT}"
                )
            }
            LifecycleError::UnknownPhase(raw) => write!(f, "'{raw}' is not a lifecycle phase"),
            LifecycleError::PhaseMismatch { state, .. } => {
                write!(f, "{state} carries phase and only running may")
            }
            LifecycleError::EmptyWindow {
                acquired_at,
                expires_at,
            } => write!(
                f,
                "a lease from {acquired_at} to {expires_at} is held for no interval"
            ),
            LifecycleError::SignatureInvalid => {
                write!(
                    f,
                    "the record's signature does not verify under its own signer"
                )
            }
        }
    }
}

impl std::error::Error for LifecycleError {}

pub type Result<T> = std::result::Result<T, LifecycleError>;

// ------------------------------------------------------- agent.lifecycle codec

pub fn signing_input(record: &AgentLifecycle) -> Vec<u8> {
    cbor::map(&body_pairs(record))
}

pub fn encode(record: &AgentLifecycle) -> Vec<u8> {
    let mut pairs = body_pairs(record);
    pairs.push((key::SIG, cbor::bytes(&record.sig)));
    cbor::map(&pairs)
}

fn body_pairs(record: &AgentLifecycle) -> Vec<(u64, Vec<u8>)> {
    let mut pairs = vec![
        (key::V, cbor::uint(record.v)),
        (key::INVOCATION_ID, cbor::bytes(&record.invocation_id)),
        (key::STATE, cbor::uint(record.state.raw())),
        (key::AT, cbor::uint(record.at)),
        (key::HOST, cbor::bytes(&record.host)),
    ];
    if let Some(reason) = &record.reason {
        pairs.push((key::REASON, cbor::text(reason)));
    }
    if let Some(detail) = &record.detail {
        pairs.push((key::DETAIL, cbor::text(detail)));
    }
    if let Some(result) = &record.result_message_id {
        pairs.push((key::RESULT_MESSAGE_ID, cbor::bytes(result)));
    }
    if let Some(phase) = record.phase {
        pairs.push((key::PHASE, cbor::text(phase.as_str())));
    }
    pairs
}

pub fn decode(data: &[u8]) -> Result<AgentLifecycle> {
    let mut reader = Reader::new(data);
    let slots = reader.schema_map(&key::SCHEMA)?;
    reader.require_end()?;

    let state_raw = cbor::in_slot(&slots, key::STATE, |r| r.uint())?;
    let state = State::parse(state_raw).ok_or(LifecycleError::UnknownState(state_raw))?;

    let reason = match cbor::optional_slot(&slots, key::REASON) {
        Some(_) => {
            let raw = cbor::in_slot(&slots, key::REASON, |r| r.text())?;
            if !LIFECYCLE_REASONS.contains(&raw.as_str()) {
                return Err(LifecycleError::UnknownReason(raw));
            }
            Some(raw)
        }
        None => None,
    };
    if state.requires_reason() != reason.is_some() {
        return Err(LifecycleError::ReasonMismatch {
            state,
            present: reason.is_some(),
        });
    }
    if let Some(raw) = &reason {
        let legal = if raw == "repo.unbound" {
            state == State::Declined
        } else if matches!(
            raw.as_str(),
            "branch.protected"
                | "config.untrusted"
                | "egress.refused"
                | "budget.reached"
                | "source.unsupported"
                | "patch.invalid"
                | "base.stale"
                | "tests.failed"
                | "github.auth"
                | "github.ratelimited"
                | "github.transport"
                | "runner.unavailable"
        ) {
            state == State::Failed
        } else {
            state.requires_reason()
        };
        if !legal {
            return Err(LifecycleError::ReasonMismatch {
                state,
                present: true,
            });
        }
    }

    let phase = match cbor::optional_slot(&slots, key::PHASE) {
        Some(_) => {
            let raw = cbor::in_slot(&slots, key::PHASE, |r| r.text())?;
            Some(Phase::parse(&raw).ok_or(LifecycleError::UnknownPhase(raw))?)
        }
        None => None,
    };
    if phase.is_some() && state != State::Running {
        return Err(LifecycleError::PhaseMismatch {
            state,
            present: true,
        });
    }

    let detail = match cbor::optional_slot(&slots, key::DETAIL) {
        Some(_) => {
            let raw = cbor::in_slot(&slots, key::DETAIL, |r| r.text())?;
            if raw.len() > DETAIL_BYTE_LIMIT {
                return Err(LifecycleError::DetailTooLong(raw.len()));
            }
            Some(raw)
        }
        None => None,
    };

    let result_message_id = match cbor::optional_slot(&slots, key::RESULT_MESSAGE_ID) {
        Some(_) => Some(cbor::in_slot(&slots, key::RESULT_MESSAGE_ID, |r| {
            r.bytes_exact(RESULT_MESSAGE_ID_WIDTH)
        })?),
        None => None,
    };
    if (state == State::Completed) != result_message_id.is_some() {
        return Err(LifecycleError::ResultMismatch {
            state,
            present: result_message_id.is_some(),
        });
    }

    Ok(AgentLifecycle {
        v: cbor::in_slot(&slots, key::V, |r| r.uint())?,
        invocation_id: cbor::in_slot(&slots, key::INVOCATION_ID, |r| {
            r.bytes_exact(INVOCATION_ID_WIDTH)
        })?,
        state,
        at: cbor::in_slot(&slots, key::AT, |r| r.uint())?,
        host: cbor::in_slot(&slots, key::HOST, |r| r.bytes())?,
        reason,
        detail,
        result_message_id,
        phase,
        sig: cbor::in_slot(&slots, key::SIG, |r| r.bytes())?,
    })
}

pub fn verify(record: &AgentLifecycle) -> Result<()> {
    verify_under(&record.host, &record.sig, &signing_input(record))
}

pub fn decode_verified(data: &[u8]) -> Result<AgentLifecycle> {
    let record = decode(data)?;
    verify(&record)?;
    Ok(record)
}

// ------------------------------------------------------------ agent.lease codec

pub fn lease_signing_input(lease: &AgentLease) -> Vec<u8> {
    cbor::map(&lease_body_pairs(lease))
}

pub fn lease_encode(lease: &AgentLease) -> Vec<u8> {
    let mut pairs = lease_body_pairs(lease);
    pairs.push((lease_key::SIG, cbor::bytes(&lease.sig)));
    cbor::map(&pairs)
}

fn lease_body_pairs(lease: &AgentLease) -> Vec<(u64, Vec<u8>)> {
    vec![
        (lease_key::V, cbor::uint(lease.v)),
        (lease_key::AGENT_ID, cbor::bytes(&lease.agent_id)),
        (lease_key::HOLDER, cbor::bytes(&lease.holder)),
        (lease_key::EPOCH, cbor::uint(lease.epoch)),
        (lease_key::ACQUIRED_AT, cbor::uint(lease.acquired_at)),
        (lease_key::EXPIRES_AT, cbor::uint(lease.expires_at)),
    ]
}

pub fn lease_decode(data: &[u8]) -> Result<AgentLease> {
    let mut reader = Reader::new(data);
    let slots = reader.schema_map(&lease_key::SCHEMA)?;
    reader.require_end()?;

    let acquired_at = cbor::in_slot(&slots, lease_key::ACQUIRED_AT, |r| r.uint())?;
    let expires_at = cbor::in_slot(&slots, lease_key::EXPIRES_AT, |r| r.uint())?;
    if expires_at <= acquired_at {
        return Err(LifecycleError::EmptyWindow {
            acquired_at,
            expires_at,
        });
    }
    Ok(AgentLease {
        v: cbor::in_slot(&slots, lease_key::V, |r| r.uint())?,
        agent_id: cbor::in_slot(&slots, lease_key::AGENT_ID, |r| {
            r.bytes_exact(AGENT_ID_WIDTH)
        })?,
        holder: cbor::in_slot(&slots, lease_key::HOLDER, |r| r.bytes())?,
        epoch: cbor::in_slot(&slots, lease_key::EPOCH, |r| r.uint())?,
        acquired_at,
        expires_at,
        sig: cbor::in_slot(&slots, lease_key::SIG, |r| r.bytes())?,
    })
}

pub fn lease_verify(lease: &AgentLease) -> Result<()> {
    verify_under(&lease.holder, &lease.sig, &lease_signing_input(lease))
}

pub fn lease_decode_verified(data: &[u8]) -> Result<AgentLease> {
    let lease = lease_decode(data)?;
    lease_verify(&lease)?;
    Ok(lease)
}

/// One signature check for both payloads.
///
/// Shared because the rule is identical and stating it twice is how one copy grows a
/// length check the other does not have. A principal that is not a key and a signature
/// of the wrong length are both `SignatureInvalid`: there is no useful difference
/// between two ways of being unsigned, and a corpus row must not be able to assert one.
fn verify_under(principal: &[u8], sig: &[u8], message: &[u8]) -> Result<()> {
    let principal: [u8; 32] = principal
        .try_into()
        .map_err(|_| LifecycleError::SignatureInvalid)?;
    let signature: [u8; 64] = sig
        .try_into()
        .map_err(|_| LifecycleError::SignatureInvalid)?;
    let key = VerifyingKey::from_bytes(&principal).map_err(|_| LifecycleError::SignatureInvalid)?;
    key.verify(message, &Signature::from_bytes(&signature))
        .map_err(|_| LifecycleError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn host_key() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    fn other_key() -> SigningKey {
        SigningKey::from_bytes(&[0x22; 32])
    }

    fn unsigned(state: State) -> AgentLifecycle {
        AgentLifecycle {
            v: PROTOCOL_VERSION,
            invocation_id: vec![0x1a; 16],
            state,
            at: 1_800_000_000,
            host: host_key().verifying_key().to_bytes().to_vec(),
            reason: if state.requires_reason() {
                Some("budget.rate".into())
            } else {
                None
            },
            detail: None,
            result_message_id: if state == State::Completed {
                Some(vec![0x33; 16])
            } else {
                None
            },
            phase: None,
            sig: vec![],
        }
    }

    fn signed(mut record: AgentLifecycle, key: &SigningKey) -> AgentLifecycle {
        record.host = key.verifying_key().to_bytes().to_vec();
        record.sig = key.sign(&signing_input(&record)).to_bytes().to_vec();
        record
    }

    fn record(state: State) -> AgentLifecycle {
        signed(unsigned(state), &host_key())
    }

    fn slots_of(data: &[u8]) -> Vec<(u64, Vec<u8>)> {
        Reader::new(data).schema_map(&key::SCHEMA).unwrap()
    }

    #[test]
    fn agent_phase_errors_and_illegal_coding_reasons_are_covered() {
        assert!(LifecycleError::UnknownPhase("unknown".into())
            .to_string()
            .contains("unknown"));
        assert!(LifecycleError::PhaseMismatch {
            state: State::Accepted,
            present: true,
        }
        .to_string()
        .contains("accepted"));

        let mut illegal = unsigned(State::Declined);
        illegal.reason = Some("branch.protected".into());
        let bytes = encode(&signed(illegal, &host_key()));
        assert!(matches!(
            decode(&bytes),
            Err(LifecycleError::ReasonMismatch {
                state: State::Declined,
                present: true,
            })
        ));
    }

    fn unsigned_lease() -> AgentLease {
        AgentLease {
            v: PROTOCOL_VERSION,
            agent_id: vec![0xa1; 32],
            holder: host_key().verifying_key().to_bytes().to_vec(),
            epoch: 3,
            acquired_at: 1_800_000_000,
            expires_at: 1_800_000_600,
            sig: vec![],
        }
    }

    fn lease() -> AgentLease {
        let mut lease = unsigned_lease();
        lease.sig = host_key()
            .sign(&lease_signing_input(&lease))
            .to_bytes()
            .to_vec();
        lease
    }

    // ------------------------------------------------------------ round trips

    #[test]
    fn agent_lifecycle_every_state_round_trips() {
        for state in [
            State::Accepted,
            State::Running,
            State::Completed,
            State::Failed,
            State::Declined,
            State::Expired,
            State::Cancelled,
        ] {
            let original = record(state);
            let encoded = encode(&original);
            assert_eq!(decode_verified(&encoded).unwrap(), original);
            assert_eq!(encode(&decode(&encoded).unwrap()), encoded);
            assert_eq!(
                state.is_terminal(),
                !matches!(state, State::Accepted | State::Running)
            );
            assert!(!format!("{state}").is_empty());
            assert_eq!(State::parse(state.raw()), Some(state));
        }
    }

    #[test]
    fn agent_lifecycle_carries_a_bounded_detail() {
        let mut original = unsigned(State::Failed);
        original.detail = Some("x".repeat(DETAIL_BYTE_LIMIT));
        let original = signed(original, &host_key());
        assert_eq!(decode_verified(&encode(&original)).unwrap(), original);

        let mut over = unsigned(State::Failed);
        over.detail = Some("x".repeat(DETAIL_BYTE_LIMIT + 1));
        let over = signed(over, &host_key());
        assert_eq!(
            decode(&encode(&over)).unwrap_err(),
            LifecycleError::DetailTooLong(DETAIL_BYTE_LIMIT + 1)
        );
    }

    #[test]
    fn agent_lifecycle_refuses_an_unknown_state() {
        let mut slots = slots_of(&encode(&record(State::Accepted)));
        for slot in slots.iter_mut() {
            if slot.0 == key::STATE {
                slot.1 = cbor::uint(8);
            }
        }
        assert_eq!(
            decode(&cbor::map(&slots)).unwrap_err(),
            LifecycleError::UnknownState(8)
        );
    }

    /// `requested` is not a state a host may write, so state 0 is as unknown as 8.
    #[test]
    fn agent_lifecycle_refuses_requested_as_a_written_state() {
        let mut slots = slots_of(&encode(&record(State::Accepted)));
        for slot in slots.iter_mut() {
            if slot.0 == key::STATE {
                slot.1 = cbor::uint(0);
            }
        }
        assert_eq!(
            decode(&cbor::map(&slots)).unwrap_err().reason(),
            "codec.state.unknown"
        );
    }

    #[test]
    fn agent_lifecycle_refuses_an_unknown_reason() {
        let mut original = unsigned(State::Failed);
        original.reason = Some("provider.exploded".into());
        let original = signed(original, &host_key());
        assert_eq!(
            decode(&encode(&original)).unwrap_err(),
            LifecycleError::UnknownReason("provider.exploded".into())
        );
    }

    #[test]
    fn agent_lifecycle_requires_a_reason_where_the_state_does() {
        for state in [State::Failed, State::Declined, State::Expired] {
            let mut original = unsigned(state);
            original.reason = None;
            let original = signed(original, &host_key());
            assert_eq!(
                decode(&encode(&original)).unwrap_err(),
                LifecycleError::ReasonMismatch {
                    state,
                    present: false
                }
            );
        }
        for state in [State::Accepted, State::Running, State::Cancelled] {
            let mut original = unsigned(state);
            original.reason = Some("budget.rate".into());
            let original = signed(original, &host_key());
            assert_eq!(
                decode(&encode(&original)).unwrap_err(),
                LifecycleError::ReasonMismatch {
                    state,
                    present: true
                }
            );
        }
    }

    #[test]
    fn agent_lifecycle_permits_a_result_only_on_completed() {
        let mut missing = unsigned(State::Completed);
        missing.result_message_id = None;
        let missing = signed(missing, &host_key());
        assert_eq!(
            decode(&encode(&missing)).unwrap_err(),
            LifecycleError::ResultMismatch {
                state: State::Completed,
                present: false
            }
        );

        let mut extra = unsigned(State::Running);
        extra.result_message_id = Some(vec![0x33; 16]);
        let extra = signed(extra, &host_key());
        assert_eq!(
            decode(&encode(&extra)).unwrap_err(),
            LifecycleError::ResultMismatch {
                state: State::Running,
                present: true
            }
        );
    }

    #[test]
    fn agent_lifecycle_refuses_a_wrong_width_result_id() {
        let mut original = unsigned(State::Completed);
        original.result_message_id = Some(vec![0x33; 15]);
        let original = signed(original, &host_key());
        assert_eq!(
            decode(&encode(&original)).unwrap_err().reason(),
            "codec.length.wrong"
        );
    }

    #[test]
    fn agent_lifecycle_refuses_a_record_mutated_after_signing() {
        let mut original = record(State::Accepted);
        original.at += 1;
        assert_eq!(
            decode_verified(&encode(&original)).unwrap_err(),
            LifecycleError::SignatureInvalid
        );
        assert!(decode(&encode(&original)).is_ok());
    }

    #[test]
    fn agent_lifecycle_refuses_a_record_signed_by_another_host() {
        let mut original = record(State::Accepted);
        original.sig = other_key()
            .sign(&signing_input(&original))
            .to_bytes()
            .to_vec();
        assert_eq!(
            verify(&original).unwrap_err(),
            LifecycleError::SignatureInvalid
        );
    }

    #[test]
    fn agent_lifecycle_refuses_structural_defects() {
        let encoded = encode(&record(State::Accepted));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(decode(&trailing).unwrap_err().reason(), "codec.trailing");

        let mut extra = slots_of(&encoded);
        extra.push((11, cbor::uint(1)));
        assert_eq!(
            decode(&cbor::map(&extra)).unwrap_err().reason(),
            "codec.key.unknown"
        );

        let missing: Vec<(u64, Vec<u8>)> = slots_of(&encoded)
            .into_iter()
            .filter(|(k, _)| *k != key::AT)
            .collect();
        assert_eq!(
            decode(&cbor::map(&missing)).unwrap_err(),
            LifecycleError::Cbor(CborError::MissingKey(key::AT))
        );

        let mut wide = slots_of(&encoded);
        for slot in wide.iter_mut() {
            if slot.0 == key::INVOCATION_ID {
                slot.1 = cbor::bytes(&[0x1a; 15]);
            }
        }
        assert_eq!(
            decode(&cbor::map(&wide)).unwrap_err().reason(),
            "codec.length.wrong"
        );
    }

    #[test]
    fn agent_lifecycle_error_display_and_reason_cover_every_case() {
        let cases = [
            LifecycleError::Cbor(CborError::Trailing(1)),
            LifecycleError::UnknownState(8),
            LifecycleError::UnknownReason("nope".into()),
            LifecycleError::ReasonMismatch {
                state: State::Failed,
                present: false,
            },
            LifecycleError::ReasonMismatch {
                state: State::Failed,
                present: true,
            },
            LifecycleError::ResultMismatch {
                state: State::Completed,
                present: false,
            },
            LifecycleError::ResultMismatch {
                state: State::Completed,
                present: true,
            },
            LifecycleError::DetailTooLong(9),
            LifecycleError::EmptyWindow {
                acquired_at: 2,
                expires_at: 1,
            },
            LifecycleError::SignatureInvalid,
        ];
        for error in cases {
            assert!(!format!("{error}").is_empty());
            assert!(error.reason().starts_with("codec."));
        }
        assert_eq!(
            LifecycleError::from(CborError::MissingKey(1)).reason(),
            "codec.key.missing"
        );
    }

    // ----------------------------------------------------------------- lease

    #[test]
    fn agent_lease_round_trips() {
        let original = lease();
        let encoded = lease_encode(&original);
        assert_eq!(lease_decode_verified(&encoded).unwrap(), original);
        assert_eq!(lease_encode(&lease_decode(&encoded).unwrap()), encoded);
    }

    #[test]
    fn agent_lease_refuses_an_empty_or_inverted_window() {
        for (acquired, expires) in [(1_800_000_000u64, 1_800_000_000u64), (2, 1)] {
            let mut original = unsigned_lease();
            original.acquired_at = acquired;
            original.expires_at = expires;
            original.sig = host_key()
                .sign(&lease_signing_input(&original))
                .to_bytes()
                .to_vec();
            assert_eq!(
                lease_decode(&lease_encode(&original)).unwrap_err(),
                LifecycleError::EmptyWindow {
                    acquired_at: acquired,
                    expires_at: expires,
                }
            );
        }
    }

    #[test]
    fn agent_lease_refuses_a_claim_mutated_after_signing() {
        let mut original = lease();
        original.epoch += 1;
        assert_eq!(
            lease_decode_verified(&lease_encode(&original)).unwrap_err(),
            LifecycleError::SignatureInvalid
        );
        assert!(lease_decode(&lease_encode(&original)).is_ok());
    }

    #[test]
    fn agent_lease_refuses_a_holder_that_is_not_a_key() {
        let mut original = lease();
        original.holder = vec![0xff; 32];
        assert_eq!(
            lease_verify(&original).unwrap_err(),
            LifecycleError::SignatureInvalid
        );
        original.holder = vec![0x00; 31];
        assert_eq!(
            lease_verify(&original).unwrap_err(),
            LifecycleError::SignatureInvalid
        );
        let mut short_sig = lease();
        short_sig.sig = vec![0x00; 63];
        assert_eq!(
            lease_verify(&short_sig).unwrap_err(),
            LifecycleError::SignatureInvalid
        );
    }

    #[test]
    fn agent_lease_refuses_structural_defects() {
        let encoded = lease_encode(&lease());
        let slots = |data: &[u8]| Reader::new(data).schema_map(&lease_key::SCHEMA).unwrap();

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            lease_decode(&trailing).unwrap_err().reason(),
            "codec.trailing"
        );

        let mut extra = slots(&encoded);
        extra.push((8, cbor::uint(1)));
        assert_eq!(
            lease_decode(&cbor::map(&extra)).unwrap_err().reason(),
            "codec.key.unknown"
        );

        let missing: Vec<(u64, Vec<u8>)> = slots(&encoded)
            .into_iter()
            .filter(|(k, _)| *k != lease_key::EPOCH)
            .collect();
        assert_eq!(
            lease_decode(&cbor::map(&missing)).unwrap_err(),
            LifecycleError::Cbor(CborError::MissingKey(lease_key::EPOCH))
        );

        let mut wide = slots(&encoded);
        for slot in wide.iter_mut() {
            if slot.0 == lease_key::AGENT_ID {
                slot.1 = cbor::bytes(&[0xa1; 31]);
            }
        }
        assert_eq!(
            lease_decode(&cbor::map(&wide)).unwrap_err().reason(),
            "codec.length.wrong"
        );
    }

    /// The vocabulary this crate refuses against is the one Swift declares.
    ///
    /// Thirty-nine reasons, and the count is the guard: a reason added on one side and
    /// not the other would let a record decode in one language and not in the other,
    /// which is the divergence the whole corpus exists to prevent.
    #[test]
    fn agent_lifecycle_reason_vocabulary_is_closed_and_complete() {
        assert_eq!(LIFECYCLE_REASONS.len(), 39);
        assert!(LIFECYCLE_REASONS.contains(&"deadline.passed"));
        assert!(LIFECYCLE_REASONS.contains(&"provider.malformed"));
        assert!(LIFECYCLE_REASONS.contains(&"runner.unavailable"));
        assert!(!LIFECYCLE_REASONS.iter().any(|r| r.starts_with("codec.")));
        let mut sorted = LIFECYCLE_REASONS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            LIFECYCLE_REASONS.len(),
            "a reason is repeated"
        );
    }
}
