# ADR-0002: No relay-maintained prev chain

- Status: accepted
- Date: 2026-06
- Source: `specs/backend/relay/wire.md`

## Context

An earlier draft required each envelope to name the relay's current head, giving
the relay a per-group hash chain and apparent tamper evidence.

## Decision

There is no relay-maintained `prev` chain. Ordering and tamper evidence move
inside the ciphertext, as a per-author dense counter (`ctr`) plus `prev_self`,
both covered by the inner signature and the encryption. `seq` is relay-assigned
and is a sync cursor only.

## Rationale

Two independent reasons, either sufficient.

**Contention.** A header chain makes every concurrent write a compare-and-swap
against a single per-group head. At the stated posture, thirty people and a
dozen agents writing continuously into one workspace root group, the design
would have spent most of its time losing races.

**It did not deliver what it was credited with.** A header chain the relay alone
constructs is a chain the relay alone can fork.

## Consequences

- Concurrent writers never contend, because each writes only its own chain.
- `SEND` never returns `retry` for contention, only for infrastructure. A
  `retry/lock_timeout` rate above noise is therefore a regression alarm rather
  than a capacity signal.
- Gaps in `seq` are legal and clients must tolerate them. Negentropy reconciles
  over the space that exists, not over a dense range.
- Detection now depends on clients comparing notes (`head.attest`), which is a
  weaker class of answer than cryptography and is why the attestation liveness
  rules and their silence-is-normal vectors exist.
- A client crash between signing and persisting the counter would produce a fork
  indistinguishable from an attack, so the counter is written ahead of the wire
  and `chain.reset` exists for unrecoverable loss.
