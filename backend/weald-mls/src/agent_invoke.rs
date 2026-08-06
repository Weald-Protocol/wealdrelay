// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! `agent.invoke`, as Rust reads it.
//!
//! The mirror of `Sources/Sync/Agents/AgentInvoke.swift`,
//! `AgentInvokeCodec.swift` and `AgentInvokeAdmission.swift`, written from
//! `specs/agents/networked/protocol.md` rather than translated from them, for the
//! reason `agent_cbor` states: two halves of one reading agree with each other no
//! matter what either gets wrong.
//!
//! # Two differences from `agent_card`, both deliberate
//!
//! **No second derived slot.** `signing_input` excludes `sig` and nothing else.
//! There is no `invoke_hash`, because nothing refers to an invoke by hash:
//! `invocation_id` is the identity every lifecycle record folds on, it is chosen by
//! the requester, and it is covered by the signature.
//!
//! **Two optional slots.** `thread_ref` and `ticket_ref` are absent rather than
//! null when unset. A null placeholder would be a second encoding of one invoke and
//! therefore a second set of bytes for one signature to cover.
//!
//! # Decode is not admission
//!
//! A cross-workspace `scope`, a passed `deadline` and a `v` above this host's are
//! all well-formed invokes. They decode here and are refused by `admission_refusal`
//! with a reason from the *lifecycle* vocabulary, not a `codec.` one. The shared
//! corpus carries the distinction as its `stage` column, because an implementation
//! that could not tell "these bytes are not an invoke" from "this invoke arrived
//! too late" would still have to render the second to a person.
//!
//! # Check order is part of the protocol
//!
//! 1. The schema map: ascending keys, no unknown key, nothing trailing.
//! 2. `capability`, against the closed vocabulary.
//! 3. The fixed-width and scalar slots, then the two optional ones.
//! 4. `sig`, verified under `requester`. Only in `decode_verified`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::agent_card::Capability;
use crate::agent_cbor::{self as cbor, CborError, Reader};

/// `AGENT_PROTOCOL_VERSION`. One constant for all four payloads, re-exported from
/// `agent_card` rather than declared again: two copies would eventually disagree.
pub use crate::agent_card::PROTOCOL_VERSION;

pub const INVOCATION_ID_WIDTH: usize = 16;
pub const IDEMPOTENCY_KEY_WIDTH: usize = 32;
pub const TARGET_AGENT_ID_WIDTH: usize = 32;
pub const SOURCE_MESSAGE_ID_WIDTH: usize = 16;
pub const SCOPE_WIDTH: usize = 32;
pub const THREAD_REF_WIDTH: usize = 16;

/// The tolerance on the requester's clock, in seconds.
///
/// Five minutes, and not a number chosen here: `specs/backend/relay/operations.md`
/// already sets the skew an authenticated frame is admitted within, and an invoke
/// travels inside those frames. A second bound would mean an invoke the relay
/// accepted and the host called stale, a disagreement with no owner.
pub const SKEW_BOUND: u64 = 300;

/// The closed set of schema slots, in the field order `protocol.md` lists. Numbers
/// are permanent.
pub mod key {
    pub const V: u64 = 1;
    pub const INVOCATION_ID: u64 = 2;
    pub const IDEMPOTENCY_KEY: u64 = 3;
    pub const TARGET_AGENT_ID: u64 = 4;
    pub const EXPECTED_PROFILE_VERSION: u64 = 5;
    pub const SOURCE_MESSAGE_ID: u64 = 6;
    pub const SCOPE: u64 = 7;
    pub const THREAD_REF: u64 = 8;
    pub const TICKET_REF: u64 = 9;
    pub const REQUESTER: u64 = 10;
    pub const CAPABILITY: u64 = 11;
    pub const DEADLINE: u64 = 12;
    pub const SIG: u64 = 13;

    /// The decoder's allow-list. Every key, and nothing else.
    pub const SCHEMA: [u64; 13] = [
        V,
        INVOCATION_ID,
        IDEMPOTENCY_KEY,
        TARGET_AGENT_ID,
        EXPECTED_PROFILE_VERSION,
        SOURCE_MESSAGE_ID,
        SCOPE,
        THREAD_REF,
        TICKET_REF,
        REQUESTER,
        CAPABILITY,
        DEADLINE,
        SIG,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentInvoke {
    pub v: u64,
    pub invocation_id: Vec<u8>,
    pub idempotency_key: Vec<u8>,
    pub target_agent_id: Vec<u8>,
    pub expected_profile_version: u64,
    pub source_message_id: Vec<u8>,
    pub scope: Vec<u8>,
    pub thread_ref: Option<Vec<u8>>,
    pub ticket_ref: Option<String>,
    pub requester: Vec<u8>,
    pub capability: Capability,
    pub deadline: u64,
    pub sig: Vec<u8>,
}

/// Why an invoke's bytes were refused. Two cases beyond the CBOR layer's, which
/// pass through unchanged so a caller has one error type and one vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvokeError {
    Cbor(CborError),
    UnknownCapability(String),
    /// `sig` does not verify under `requester`, or `requester` is not a key at all.
    SignatureInvalid,
}

impl From<CborError> for InvokeError {
    fn from(error: CborError) -> Self {
        InvokeError::Cbor(error)
    }
}

impl InvokeError {
    /// The closed reason code, matching `AgentCodecReason` in Swift and the `reason`
    /// column of the shared corpus manifest.
    pub fn reason(&self) -> &'static str {
        match self {
            InvokeError::Cbor(inner) => inner.reason(),
            InvokeError::UnknownCapability(_) => "codec.capability.unknown",
            InvokeError::SignatureInvalid => "codec.signature.invalid",
        }
    }
}

impl std::fmt::Display for InvokeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvokeError::Cbor(inner) => write!(f, "{inner}"),
            InvokeError::UnknownCapability(value) => write!(
                f,
                "'{value}' is not a version 1 capability. The vocabulary is closed."
            ),
            InvokeError::SignatureInvalid => write!(
                f,
                "the invoke's signature does not verify under its own requester"
            ),
        }
    }
}

impl std::error::Error for InvokeError {}

pub type Result<T> = std::result::Result<T, InvokeError>;

// ------------------------------------------------------------------- encoding

/// The bytes `sig` covers: every slot except `sig`.
pub fn signing_input(invoke: &AgentInvoke) -> Vec<u8> {
    cbor::map(&body_pairs(invoke))
}

/// The full invoke, including `sig`.
pub fn encode(invoke: &AgentInvoke) -> Vec<u8> {
    let mut pairs = body_pairs(invoke);
    pairs.push((key::SIG, cbor::bytes(&invoke.sig)));
    cbor::map(&pairs)
}

fn body_pairs(invoke: &AgentInvoke) -> Vec<(u64, Vec<u8>)> {
    let mut pairs = vec![
        (key::V, cbor::uint(invoke.v)),
        (key::INVOCATION_ID, cbor::bytes(&invoke.invocation_id)),
        (key::IDEMPOTENCY_KEY, cbor::bytes(&invoke.idempotency_key)),
        (key::TARGET_AGENT_ID, cbor::bytes(&invoke.target_agent_id)),
        (
            key::EXPECTED_PROFILE_VERSION,
            cbor::uint(invoke.expected_profile_version),
        ),
        (
            key::SOURCE_MESSAGE_ID,
            cbor::bytes(&invoke.source_message_id),
        ),
        (key::SCOPE, cbor::bytes(&invoke.scope)),
    ];
    // Absent when unset, never a null placeholder. `cbor::map` sorts, so these do
    // not have to be pushed in key order.
    if let Some(thread_ref) = &invoke.thread_ref {
        pairs.push((key::THREAD_REF, cbor::bytes(thread_ref)));
    }
    if let Some(ticket_ref) = &invoke.ticket_ref {
        pairs.push((key::TICKET_REF, cbor::text(ticket_ref)));
    }
    pairs.push((key::REQUESTER, cbor::bytes(&invoke.requester)));
    pairs.push((key::CAPABILITY, cbor::text(invoke.capability.as_str())));
    pairs.push((key::DEADLINE, cbor::uint(invoke.deadline)));
    pairs
}

// ------------------------------------------------------------------- decoding

/// Structure only. See the module comment on why this does not verify.
pub fn decode(data: &[u8]) -> Result<AgentInvoke> {
    let mut reader = Reader::new(data);
    let slots = reader.schema_map(&key::SCHEMA)?;
    reader.require_end()?;

    let capability_raw = cbor::in_slot(&slots, key::CAPABILITY, |r| r.text())?;
    let capability =
        Capability::parse(&capability_raw).ok_or(InvokeError::UnknownCapability(capability_raw))?;

    let thread_ref = match cbor::optional_slot(&slots, key::THREAD_REF) {
        Some(_) => Some(cbor::in_slot(&slots, key::THREAD_REF, |r| {
            r.bytes_exact(THREAD_REF_WIDTH)
        })?),
        None => None,
    };
    let ticket_ref = match cbor::optional_slot(&slots, key::TICKET_REF) {
        Some(_) => Some(cbor::in_slot(&slots, key::TICKET_REF, |r| r.text())?),
        None => None,
    };

    Ok(AgentInvoke {
        v: cbor::in_slot(&slots, key::V, |r| r.uint())?,
        invocation_id: cbor::in_slot(&slots, key::INVOCATION_ID, |r| {
            r.bytes_exact(INVOCATION_ID_WIDTH)
        })?,
        idempotency_key: cbor::in_slot(&slots, key::IDEMPOTENCY_KEY, |r| {
            r.bytes_exact(IDEMPOTENCY_KEY_WIDTH)
        })?,
        target_agent_id: cbor::in_slot(&slots, key::TARGET_AGENT_ID, |r| {
            r.bytes_exact(TARGET_AGENT_ID_WIDTH)
        })?,
        expected_profile_version: cbor::in_slot(&slots, key::EXPECTED_PROFILE_VERSION, |r| {
            r.uint()
        })?,
        source_message_id: cbor::in_slot(&slots, key::SOURCE_MESSAGE_ID, |r| {
            r.bytes_exact(SOURCE_MESSAGE_ID_WIDTH)
        })?,
        scope: cbor::in_slot(&slots, key::SCOPE, |r| r.bytes_exact(SCOPE_WIDTH))?,
        thread_ref,
        ticket_ref,
        requester: cbor::in_slot(&slots, key::REQUESTER, |r| r.bytes())?,
        capability,
        deadline: cbor::in_slot(&slots, key::DEADLINE, |r| r.uint())?,
        sig: cbor::in_slot(&slots, key::SIG, |r| r.bytes())?,
    })
}

/// `sig` verifies under `requester` over `signing_input`.
pub fn verify(invoke: &AgentInvoke) -> Result<()> {
    let principal: [u8; 32] = invoke
        .requester
        .as_slice()
        .try_into()
        .map_err(|_| InvokeError::SignatureInvalid)?;
    let signature: [u8; 64] = invoke
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| InvokeError::SignatureInvalid)?;
    let key = VerifyingKey::from_bytes(&principal).map_err(|_| InvokeError::SignatureInvalid)?;
    key.verify(&signing_input(invoke), &Signature::from_bytes(&signature))
        .map_err(|_| InvokeError::SignatureInvalid)
}

/// Decode and verify. The only entry point admission or a projection may use.
pub fn decode_verified(data: &[u8]) -> Result<AgentInvoke> {
    let invoke = decode(data)?;
    verify(&invoke)?;
    Ok(invoke)
}

// ----------------------------------------------------------------- admission

/// Everything outside the invoke that the three pure checks read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionContext {
    /// The `group` of the envelope this invoke arrived in. Not taken from the
    /// invoke, which is the point: `scope` is a claim and this is the fact.
    pub envelope_group: Vec<u8>,
    /// Seconds since the epoch, on the host's clock.
    pub now: u64,
    /// This host's `AGENT_PROTOCOL_VERSION`, so a test can pose as an older host
    /// without editing the constant.
    pub protocol_version: u64,
}

/// The lifecycle reason this invoke is refused with, or `None` if the three checks
/// this layer owns pass.
///
/// `None` is not "accepted". `protocol.md`'s checks 1 and 3 through 5 need a local
/// agent store, a roster, a delegation certificate and a budget, all of which are
/// step 7's, and nothing here has looked at them.
///
/// Order is normative. Version first, because every check after it interprets fields
/// whose meaning a higher version may have changed. Then the envelope binding,
/// because until `scope` is known to be the group this arrived in there is no group
/// to be timely in. Then the deadline.
///
/// The binding refuses as `scope.notmember` rather than a code of its own: the invoke
/// asserts membership of a group whose roster this envelope establishes nothing
/// about, so the requester cannot be placed in `scope`. A dedicated code would also
/// leak back that the named group is one this host knows and is not the one they
/// wrote into, and a refusal distinguishing "not a member" from "not a member here"
/// is a probe.
pub fn admission_refusal(invoke: &AgentInvoke, context: &AdmissionContext) -> Option<&'static str> {
    if invoke.v > context.protocol_version {
        return Some("version.unsupported");
    }
    if invoke.scope != context.envelope_group {
        return Some("scope.notmember");
    }
    if deadline_has_passed(invoke.deadline, context.now) {
        return Some("deadline.passed");
    }
    None
}

/// `deadline` is behind `now` by more than the skew bound.
///
/// Subtraction rather than `deadline + SKEW_BOUND`, which overflows for a deadline
/// near `u64::MAX`. In release that would wrap and make the largest possible deadline
/// the most expired one; in debug it would panic on a field a peer chooses.
fn deadline_has_passed(deadline: u64, now: u64) -> bool {
    now > deadline && now - deadline > SKEW_BOUND
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// The same two fixed seeds `scripts/agents-vectors.py` uses, so an invoke built
    /// here and one built there are the same invoke.
    fn requester_key() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    fn stranger_key() -> SigningKey {
        SigningKey::from_bytes(&[0x22; 32])
    }

    fn scope_bytes() -> Vec<u8> {
        vec![0x5c; 32]
    }

    fn unsigned() -> AgentInvoke {
        AgentInvoke {
            v: PROTOCOL_VERSION,
            invocation_id: vec![0x1a; 16],
            idempotency_key: vec![0x1d; 32],
            target_agent_id: vec![0xa1; 32],
            expected_profile_version: 1,
            source_message_id: vec![0x11; 16],
            scope: scope_bytes(),
            thread_ref: None,
            ticket_ref: None,
            requester: requester_key().verifying_key().to_bytes().to_vec(),
            capability: Capability::ChatReply,
            deadline: 1_760_000_300,
            sig: vec![],
        }
    }

    fn signed(mut invoke: AgentInvoke, key: &SigningKey) -> AgentInvoke {
        invoke.requester = key.verifying_key().to_bytes().to_vec();
        invoke.sig = key.sign(&signing_input(&invoke)).to_bytes().to_vec();
        invoke
    }

    fn invoke() -> AgentInvoke {
        signed(unsigned(), &requester_key())
    }

    fn slots_of(data: &[u8]) -> Vec<(u64, Vec<u8>)> {
        Reader::new(data).schema_map(&key::SCHEMA).unwrap()
    }

    fn relay(slots: Vec<(u64, Vec<u8>)>) -> Vec<u8> {
        cbor::map(&slots)
    }

    // ------------------------------------------------------------ round trips

    #[test]
    fn agent_invoke_round_trips() {
        let original = invoke();
        let encoded = encode(&original);
        let decoded = decode_verified(&encoded).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(encode(&decoded), encoded);
    }

    #[test]
    fn agent_invoke_round_trips_with_both_optional_slots() {
        let mut original = unsigned();
        original.thread_ref = Some(vec![0x7e; 16]);
        original.ticket_ref = Some("WEALD-412".into());
        let original = signed(original, &requester_key());
        let decoded = decode_verified(&encode(&original)).unwrap();
        assert_eq!(decoded.thread_ref, Some(vec![0x7e; 16]));
        assert_eq!(decoded.ticket_ref.as_deref(), Some("WEALD-412"));
        assert_eq!(decoded, original);
    }

    #[test]
    fn agent_invoke_every_capability_round_trips() {
        for capability in [
            Capability::ChatReply,
            Capability::ReadChannel,
            Capability::ReadTicket,
        ] {
            let mut original = unsigned();
            original.capability = capability;
            let original = signed(original, &requester_key());
            assert_eq!(decode_verified(&encode(&original)).unwrap(), original);
        }
    }

    /// An absent optional is absent, not a null. A placeholder would be a second
    /// encoding of one invoke and therefore a second set of bytes for one signature.
    #[test]
    fn agent_invoke_omits_unset_optional_slots() {
        let encoded = encode(&invoke());
        let keys: Vec<u64> = slots_of(&encoded).iter().map(|(k, _)| *k).collect();
        assert!(!keys.contains(&key::THREAD_REF));
        assert!(!keys.contains(&key::TICKET_REF));
        assert_eq!(keys.len(), 11);
    }

    /// `signing_input` is the encoding minus `sig`, and nothing else. There is no
    /// hash slot to leave out, unlike a card.
    #[test]
    fn agent_invoke_signing_input_is_the_encoding_minus_sig() {
        let original = invoke();
        let signable = signing_input(&original);
        let keys: Vec<u64> = Reader::new(&signable)
            .schema_map(&key::SCHEMA)
            .unwrap()
            .iter()
            .map(|(k, _)| *k)
            .collect();
        assert!(!keys.contains(&key::SIG));
        assert_eq!(keys.len(), 10);
    }

    // -------------------------------------------------------------- refusals

    #[test]
    fn agent_invoke_refuses_an_unknown_capability() {
        let mut slots = slots_of(&encode(&invoke()));
        for slot in slots.iter_mut() {
            if slot.0 == key::CAPABILITY {
                slot.1 = cbor::text("admin.*");
            }
        }
        assert_eq!(
            decode(&relay(slots)).unwrap_err(),
            InvokeError::UnknownCapability("admin.*".into())
        );
    }

    #[test]
    fn agent_invoke_refuses_an_unknown_key() {
        let mut slots = slots_of(&encode(&invoke()));
        slots.push((14, cbor::text("a system prompt")));
        assert_eq!(
            decode(&relay(slots)).unwrap_err().reason(),
            "codec.key.unknown"
        );
    }

    #[test]
    fn agent_invoke_refuses_a_missing_key() {
        let slots: Vec<(u64, Vec<u8>)> = slots_of(&encode(&invoke()))
            .into_iter()
            .filter(|(k, _)| *k != key::SCOPE)
            .collect();
        assert_eq!(
            decode(&relay(slots)).unwrap_err(),
            InvokeError::Cbor(CborError::MissingKey(key::SCOPE))
        );
    }

    #[test]
    fn agent_invoke_refuses_a_wrong_width_invocation_id() {
        let mut slots = slots_of(&encode(&invoke()));
        for slot in slots.iter_mut() {
            if slot.0 == key::INVOCATION_ID {
                slot.1 = cbor::bytes(&[0x1a; 15]);
            }
        }
        assert_eq!(
            decode(&relay(slots)).unwrap_err().reason(),
            "codec.length.wrong"
        );
    }

    #[test]
    fn agent_invoke_refuses_a_wrong_width_thread_ref() {
        let mut original = unsigned();
        original.thread_ref = Some(vec![0x7e; 15]);
        let original = signed(original, &requester_key());
        assert_eq!(
            decode(&encode(&original)).unwrap_err().reason(),
            "codec.length.wrong"
        );
    }

    /// Every slot, one at a time, holding the wrong major type.
    ///
    /// A loop rather than thirteen tests, and it is not only brevity: what is being
    /// asserted is that *no* slot is read without its type being checked. A
    /// hand-written list would be a list somebody adds a field to without adding a
    /// row, and the new field would then be the one read loosely.
    #[test]
    fn agent_invoke_refuses_a_wrong_major_type_in_every_slot() {
        let numeric = [key::V, key::EXPECTED_PROFILE_VERSION, key::DEADLINE];
        for target in key::SCHEMA {
            // Whichever type the slot does not hold: a byte string where a number
            // belongs, and a number everywhere else.
            let wrong = if numeric.contains(&target) {
                cbor::bytes(&[0x00])
            } else {
                cbor::uint(1)
            };
            let mut slots = slots_of(&encode(&invoke()));
            match slots.iter_mut().find(|(k, _)| *k == target) {
                Some(slot) => slot.1 = wrong,
                // The two optional slots are absent from a minimal invoke, so they
                // are added rather than replaced.
                None => slots.push((target, wrong)),
            }
            assert_eq!(
                decode(&relay(slots)).unwrap_err().reason(),
                "codec.type.mismatch",
                "slot {target} was read without checking its type"
            );
        }
    }

    /// A `requester` that is 32 bytes and still not a point on the curve.
    ///
    /// Separate from the wrong-length case because it fails one step later, at
    /// decompression rather than at the length check, and a test that only ever
    /// handed over the wrong number of bytes would leave that step unproven.
    #[test]
    fn agent_invoke_refuses_a_requester_that_is_not_a_curve_point() {
        let mut original = invoke();
        original.requester = vec![0xff; 32];
        assert_eq!(
            verify(&original).unwrap_err(),
            InvokeError::SignatureInvalid
        );
    }

    #[test]
    fn agent_invoke_refuses_trailing_bytes() {
        let mut encoded = encode(&invoke());
        encoded.push(0x00);
        assert_eq!(decode(&encoded).unwrap_err().reason(), "codec.trailing");
    }

    #[test]
    fn agent_invoke_refuses_a_body_mutated_after_signing() {
        let mut original = invoke();
        original.deadline += 1;
        assert_eq!(
            decode_verified(&encode(&original)).unwrap_err(),
            InvokeError::SignatureInvalid
        );
        // Structure is untouched: only the signature is wrong, which is what makes
        // the mutation a signature test rather than an encoding one.
        assert!(decode(&encode(&original)).is_ok());
    }

    #[test]
    fn agent_invoke_refuses_a_stranger_s_signature() {
        let mut original = unsigned();
        original.requester = requester_key().verifying_key().to_bytes().to_vec();
        original.sig = stranger_key()
            .sign(&signing_input(&original))
            .to_bytes()
            .to_vec();
        assert_eq!(
            verify(&original).unwrap_err(),
            InvokeError::SignatureInvalid
        );
    }

    #[test]
    fn agent_invoke_refuses_a_requester_that_is_not_a_key() {
        let mut original = invoke();
        original.requester = vec![0x00; 31];
        assert_eq!(
            verify(&original).unwrap_err(),
            InvokeError::SignatureInvalid
        );
        original.requester = vec![0x00; 32];
        assert_eq!(
            verify(&original).unwrap_err(),
            InvokeError::SignatureInvalid
        );
    }

    #[test]
    fn agent_invoke_refuses_a_signature_of_the_wrong_length() {
        let mut original = invoke();
        original.sig = vec![0x00; 63];
        assert_eq!(
            verify(&original).unwrap_err(),
            InvokeError::SignatureInvalid
        );
    }

    #[test]
    fn agent_invoke_error_display_and_reason_cover_every_case() {
        for error in [
            InvokeError::Cbor(CborError::Trailing(1)),
            InvokeError::UnknownCapability("admin.*".into()),
            InvokeError::SignatureInvalid,
        ] {
            assert!(!format!("{error}").is_empty());
            assert!(error.reason().starts_with("codec."));
        }
        assert_eq!(
            InvokeError::from(CborError::MissingKey(1)).reason(),
            "codec.key.missing"
        );
    }

    // ------------------------------------------------------------ admission

    fn context(now: u64) -> AdmissionContext {
        AdmissionContext {
            envelope_group: scope_bytes(),
            now,
            protocol_version: PROTOCOL_VERSION,
        }
    }

    #[test]
    fn agent_invoke_admission_accepts_a_timely_invoke_in_its_own_group() {
        assert_eq!(admission_refusal(&invoke(), &context(1_760_000_000)), None);
    }

    #[test]
    fn agent_invoke_admission_refuses_a_higher_version() {
        let mut original = unsigned();
        original.v = PROTOCOL_VERSION + 1;
        let original = signed(original, &requester_key());
        assert_eq!(
            admission_refusal(&original, &context(1_760_000_000)),
            Some("version.unsupported")
        );
    }

    #[test]
    fn agent_invoke_admission_refuses_a_scope_that_is_not_the_carrying_group() {
        let mut ctx = context(1_760_000_000);
        ctx.envelope_group = vec![0x9f; 32];
        assert_eq!(admission_refusal(&invoke(), &ctx), Some("scope.notmember"));
    }

    /// Version is checked before the binding, so an invoke with both defects reports
    /// the version. Order is normative because the error identifies which check
    /// failed, and a reordering changes what a probing requester learns.
    #[test]
    fn agent_invoke_admission_reports_version_before_scope() {
        let mut original = unsigned();
        original.v = PROTOCOL_VERSION + 1;
        original.scope = vec![0x9f; 32];
        let original = signed(original, &requester_key());
        assert_eq!(
            admission_refusal(&original, &context(1_760_000_000)),
            Some("version.unsupported")
        );
    }

    #[test]
    fn agent_invoke_admission_tolerates_skew_up_to_the_bound_and_no_further() {
        let original = invoke();
        let deadline = original.deadline;
        // Exactly at the bound is tolerated; one second past it is not. Asserted at
        // the boundary rather than a round number, because an off-by-one here is a
        // whole class of invocation the product would silently drop.
        assert_eq!(
            admission_refusal(&original, &context(deadline + SKEW_BOUND)),
            None
        );
        assert_eq!(
            admission_refusal(&original, &context(deadline + SKEW_BOUND + 1)),
            Some("deadline.passed")
        );
        // A deadline in the future is never passed.
        assert_eq!(admission_refusal(&original, &context(deadline - 1)), None);
        assert_eq!(admission_refusal(&original, &context(deadline)), None);
    }

    /// A deadline near `u64::MAX` must not overflow into being expired.
    #[test]
    fn agent_invoke_admission_does_not_overflow_on_a_hostile_deadline() {
        let mut original = unsigned();
        original.deadline = u64::MAX;
        let original = signed(original, &requester_key());
        assert_eq!(admission_refusal(&original, &context(u64::MAX)), None);
        assert_eq!(admission_refusal(&original, &context(0)), None);
    }
}
