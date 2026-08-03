# Threat model: client to relay

The boundary the whole product exists to defend. The adversary is a fully
compromised relay operator with root on the host, the database and the object
store, who is also willing to lie.

## What crosses

Cleartext envelope header (`v`, `enc`, `group`, `epoch`, `seq`, `ts`, `hash`),
opaque `ct`, access-set public keys, connection source IP, and connection
timing. Nothing else.

## STRIDE

| # | Threat | Class | Control | Answer class | Proof |
| --- | --- | --- | --- | --- | --- |
| R1 | Operator reads message bodies | Information disclosure | MLS. Keys exist only on client devices. | 1. A key we do not hold. | `mls-binding.md` FFI suite; corpus `env-valid-mls-first-link`. |
| R2 | Operator is handed plaintext by a downgraded or misconfigured client | Information disclosure | `enc` is a header field the relay reads and enforces against `WEALD_RELAY_MIN_ENC`. Fixed to `mls` on the hosted profile and not configurable there. | 2. Property of the deployment. | `env-denied-plaintext-under-mls-floor`, plus a hosted-profile relay that refuses to start with `none`. |
| R3 | Operator claims `enc: 1` payloads are MLS when they are not | Spoofing | **Not defended by the header.** The confidentiality claim rests entirely on clients holding keys the relay does not. The field removes only the silent case. | 1, by construction. The header is not load-bearing for confidentiality. | Stated as a non-claim in `wire.md` and here, so nobody markets it as one. |
| R4 | Operator forges a message from a member | Spoofing | Sign-then-encrypt. Ed25519 inside `ct`. The relay cannot produce the inner signature. | 1. | Client-side verification on every receive. |
| R5 | Operator re-attributes a decrypted message | Spoofing | Author is inside the signature. A group member cannot re-attribute either. | 1. | |
| R6 | Operator drops or withholds an envelope from one client | Tampering | Dense per-author counter with `prev_self` linkage, both inside the signature and the encryption. A gap is visible to every receiver. | 1. | `chain-gap-no-reset-is-evidence`. |
| R7 | Operator shows a consistent but different subset of history to different clients | Tampering | `head.attest` every 15 minutes. Disagreement unresolved across two sync rounds raises a named split-view warning. | 3, and it is the weakest link in this table. | `attest-expected-set-comes-from-ratchet-tree`. |
| R8 | Operator withholds every attestation from the client it is lying to, producing silence rather than disagreement | Tampering | Liveness is checked as well as content. Expected attesters are the group's current device leaves read from the client's own ratchet tree, never from the relay. Zero peer attestations for 60 minutes with live traffic is a warning naming the relay. | 3. | `attest-total-silence-with-live-traffic`, `attest-device-silent-against-evidence`. |
| R9 | The split-view detector is trained into noise by ordinary traffic | Meta | Agents are never expected attesters and never unattested; their proxying device attests for them. Absence alone raises nothing. | 3. | The four silence-is-normal vectors. Removing any of them fails `spec-check.sh`. |
| R10 | An honest crash produces a forked author chain indistinguishable from an attack | Meta | Counter is reserved in the same local transaction as the MLS state write, before the send. Unacknowledged links are resent verbatim, never re-signed, never renumbered. Unrecoverable loss emits a signed `chain.reset`. | 3. | `chain-gap-with-reset-is-stated`, `chain-fork-same-ctr-different-content`. |
| R11 | Operator reorders history | Tampering | `seq` is a sync cursor only. Causality lives in the Automerge change graph; integrity in the author chain. Nothing above layer 2 reads `seq` for correctness. | 1. | `seq-gap-after-rollback-is-legal`. |
| R12 | Operator admits an unauthorized writer | Elevation of privilege | Signed `access.publish`, the only body the relay reads. Enforcement is a check the relay can make without reading anything. | 3. | `env-denied-writer-not-in-access-set`. |
| R13 | Removed member continues reading | Elevation of privilege | Removal and the epoch change that enforces it are one action. | 1. | Property tests over random membership churn interleaved with concurrent edits. |
| R14 | Operator learns the social graph from headers | Information disclosure | **Residual and acknowledged.** Group ids are opaque 32-byte values, but who connects, to which opaque group, when, and how much, is visible. Deployment on a private network removes it entirely. | Residual. | Stated in `overview.md`. Not claimed as solved. |
| R15 | Operator correlates a recovery principal's existence | Information disclosure | `recovery.wrap` is stored under a per-epoch blinded tag rather than under the recovery key. | 1. | `RecoveryWrapBody` in the CDDL. |
| R16 | Denial of service by an authenticated member | Denial of service | Per-IP connection limits, per-connection bounded queues, signature check before database work, hard cap on unauthenticated connection lifetime, storage and rate quotas. An attacker holding a key can consume bandwidth and quota and can read nothing. | 3. Sized for cost control, not confidentiality. | `quota/*` vectors. |
| R17 | Backpressure silently discards envelopes, creating a false tamper alarm | Denial of service | A full receive queue stops reading the socket, pushing back through TCP. Storage saturation returns `quota`, database saturation returns `retry`, never a silent accept. `0x00F0` is the only sheddable kind. | 3. | `env-valid-ephemeral-not-persisted`, `retry/backpressure`. |
| R18 | Operator forges timestamps to expire or extend credentials | Tampering | Every expiry is evaluated by a client against local time. Relay `ts` and the `AUTH` challenge timestamp are observed, never trusted. Skew past 5 minutes raises a warning and blocks issuance while permitting read, write and sync. Verification is skew-tolerant only in the safe direction. | 1 for verification, 3 for the warning. | `clock-skew-refuses-issuance-only`. |
| R19 | Content-address collision or encoder ambiguity | Tampering | Deterministic CBOR is a validation rule. Indefinite lengths, unsorted keys, non-shortest integers and floats are all rejected even when they decode identically. | 3. | The four `reject/noncanonical_cbor` vectors. |
| R20 | Repudiation of an action by a member | Repudiation | Signed payload plus dense counter. A member cannot deny an envelope it signed, and cannot silently remove one. | 1. | |

## What is deliberately not defended

- **Traffic analysis at the header level.** See R14.
- **A compromised client device.** Keys live there. A stolen unlocked laptop is
  a member, and the answer is offboarding plus an epoch advance, not cryptography.
- **A member who screenshots and leaks.** Out of scope for every system of this
  shape, and saying so is more honest than a control that suggests otherwise.
