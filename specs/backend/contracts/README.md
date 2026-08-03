# Contracts

The machine-checkable half of the relay specification.

`../relay/` is prose: it carries the reasoning, the rejected alternatives and the
judgement calls, and it should stay prose. This directory carries the parts a
compiler, a linter or a fuzzer can hold us to.

**Where a contract artifact and a prose spec disagree, the artifact is correct
and the prose is a bug.** See `decisions/ADR-0008-artifacts-outrank-prose.md`.

## What is here

| Path | Artifact |
| --- | --- |
| `wire/wire.cddl` | The envelope, the payload, the event kinds and the transport frames as a CDDL schema. The authority on the frame set. |
| `wire/vectors/` | The conformance corpus. One vector per acceptance and per rejection class, plus the client-side chain vectors and the cases where silence is the correct behaviour. |
| `wire/recon.md` | The reconciliation protocol, with its own vectors in `wire/vectors/recon.json`. |
| `registries/error-codes.md` | Every stable error code a client may branch on. |
| `threat-model/` | STRIDE per trust boundary, each entry naming its control, its answer class and its proof. `relay-boundary.md` is the relay itself; `bootstrap-handoff.md` is the trust-root race. |
| `diagrams/` | Four mermaid diagrams: trust boundaries, envelope lifecycle, MLS group lifecycle, migration phases. |
| `decisions/` | The ADRs behind choices that are otherwise buried in prose. |
| `governance.md` | What is governed, the three change classes, how a breaking change happens, the emergency path, registry intake. The document that makes "protocol" a word we are entitled to. |

Two notes on scope, so that nothing here reads as missing.

**ADR numbers are not dense.** They are issued from one register covering the
whole system, and only the relay-relevant decisions ship here. A gap is a
decision about the macOS client or the hosted service, not a file that went
astray.

**The control plane's contracts are not in this repository**, because the control
plane is not in this repository. Its OpenAPI document, its audit-event registry,
its data classification table and its state machines govern a service that cannot
read anything anyway, and none of them is a dependency of a relay implementation.
What the relay is willing to tell it is specified here, in `../relay/server.md`
and `decisions/ADR-0007-one-way-polling.md`.

## Reading order

Someone new to the system, in this order, takes about an hour:

1. `../WEALD-PROTOCOL.md`. What the protocol is, end to end.
2. `diagrams/trust-boundaries.mmd`. What crosses each edge and in what form.
   This is also the diagram that goes in a security questionnaire response.
3. `threat-model/relay-boundary.md`. The three classes of answer, applied to the
   component you are about to run.
4. `decisions/`. Why the shape is the shape, including what was rejected.
5. `governance.md`. What may change, how much warning you get, how to object.
   Read this before depending on anything below it.
6. `wire/wire.cddl` and `wire/vectors/`, if you are implementing.

## The three answer classes

Every security property in this system is answered by one of exactly three
things, and the class matters more than the control:

1. **A key we do not hold.** Cannot be undone by a bug.
2. **A property of the deployment.** `WEALD_RELAY_MIN_ENC=mls` is not
   configurable on hosted, so a hosted operator cannot receive plaintext even by
   accident.
3. **A control we implement.** Weakest, because it is code. Every answer in this
   class must name its test.

A change that moves an answer from class 1 to class 3 is a downgrade even when it
adds code, and needs an ADR.

## Enforcement

```bash
./scripts/spec-check.sh
```

Five checks, the subset of the full gate that is meaningful in a public
repository and that an outside contributor can run:

1. Every relay error code has a conformance vector.
2. `wire.cddl` compiles. Skipped, loudly, without the `cddl` tool installed.
3. Every backtick-quoted spec reference resolves to a file that exists.
4. The licence boundary holds: every crate carries `LICENSE` and `NOTICE`, and
   every Rust source carries an SPDX header.
5. House style, per the project writing rules.

Adding an error code without a vector is a build failure rather than a review
comment. That is the point.

The rest of the gate, the coverage floors, the property suites, miri, the fuzz
budget and the client-side integration steps, runs in Weald's private build
repository, because most of it exercises surfaces that are not here. What can be
checked from outside is in `../relay/verification.md`, and it is deliberately the
part that does not require trusting us.

## What must never be added here

An endpoint, field or table that would let anything outside a workspace answer a
question about that workspace's membership or content. The relay's own answer to
"who is in this group" is a salted hash and a count, and that is the whole of it.
A proposal to add more is visibly a change to the trust boundary rather than a
migration.
