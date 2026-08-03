# Contracts

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only: the Clerk
> production instance, Stripe live mode, the production Render environment and
> Postgres, the production R2 bucket, the published relay digest. No dev tier,
> no test mode, no staging tier, and no agent creates one. `local` and `ci` are
> not an exception because they reach no vendor at all. A gate that cannot reach
> production configuration fails; it never degrades to a mock, a stub, a fake, a
> skip or a newly created dev or staging resource.

The machine-checkable half of the backend specification.

`relay/` and `cloud/` are prose: they carry the reasoning, the rejected
alternatives and the judgement calls, and they should stay prose. This directory
carries the parts a compiler, a linter or a fuzzer can hold us to.

**Where a contract artifact and a prose spec disagree, the artifact is correct
and the prose is a bug.** See `decisions/ADR-0008`.

## What is here

| Path | Artifact | Replaces prose in |
| --- | --- | --- |
| `api/openapi.yaml` | OpenAPI 3.1 for the control plane. Roles, step-up, rate limits and declared problem types are structured fields, not sentences. | `cloud/api.md`, `cloud/api-contract.md` |
| `wire/wire.cddl` | The envelope, the payload, the event kinds and the transport frames as a CDDL schema. | `relay/wire.md` |
| `wire/vectors/` | Declarative conformance corpus. One vector per acceptance and per rejection class, plus the client-side chain, attestation and clock vectors. | `relay/wire.md`, `relay/operations.md` |
| `registries/error-codes.md` | Every stable code in the system, both families. | scattered across nine specs |
| `registries/audit-events.md` | Every name written to `audit_events`. | `cloud/api.md`, `cloud/control-plane.md` |
| `registries/data-classification.md` | Field-level classification, retention, readership and subprocessor exposure. The table an enterprise review asks for by name. | `cloud/compliance.md` |
| `state-machines/` | Instance lifecycle, entitlement, domain. Transition tables plus explicit illegal transitions. | `cloud/service-lifecycle.md`, `cloud/billing.md`, `cloud/domain-lifecycle.md` |
| `diagrams/` | Nine mermaid diagrams. C4 context and container, trust boundaries, purchase, enrollment, envelope lifecycle, MLS groups, ERD, provisioning jobs, migration phases. | nothing. This was the gap. |
| `threat-model/` | STRIDE per trust boundary, each entry naming its control, its answer class and its proof artifact. | `relay/groups.md` had one embedded |
| `decisions/` | Eight ADRs for choices already made and previously buried in prose. | everywhere |
| `governance.md` | What is governed, the three change classes, how a breaking change happens, who decides, the emergency path, registry intake. The document that makes "protocol" a word we are entitled to. | nothing. This was the other gap. |

## Reading order

Someone new to the system, in this order, takes about an hour:

1. `diagrams/c4-context.mmd` and `c4-container.mmd`. What the pieces are.
2. `diagrams/trust-boundaries.mmd`. What crosses each edge and in what form.
   This is also the diagram that goes in a security questionnaire response.
3. `threat-model/README.md`. The three classes of answer.
4. `decisions/`. Why the shape is the shape, including what was rejected.
5. `governance.md`. What may change, how much warning you get, how to object.
   Read this before depending on anything below it.
6. The artifact for whatever you are about to build.

## The three answer classes

Every security property in this system is answered by one of exactly three
things, and the class matters more than the control:

1. **A key we do not hold.** Cannot be undone by a bug.
2. **A property of the deployment.** `WEALD_RELAY_MIN_ENC=mls` is not
   configurable on hosted, so a hosted operator cannot receive plaintext even by
   accident.
3. **A control we implement.** Weakest, because it is code. Every answer in this
   class must name its test.

A change that moves an answer from class 1 to class 3 is a downgrade even when
it adds code, and needs an ADR.

## Enforcement

```bash
./scripts/spec-check.sh
```

Nine checks, wired into the same gate the `backend-build` skill runs:

1. OpenAPI lints clean.
2. Every declared problem type is registered, and every registered type is
   reachable from at least one operation.
3. Every relay error code has a negative vector, and the four
   silence-is-normal vectors still exist.
4. CDDL compiles, and every event kind in `wire.md` appears in it.
5. Every mermaid diagram parses.
6. Every relative and backtick-quoted spec reference resolves.
7. No state machine has an undefined transition target or an unreachable state.
8. Every control plane schema field has a data-classification row.
9. No em dashes, per the project writing rules.

Adding an error code without a vector, or a column without a classification row,
is a build failure rather than a review comment. That is the point.

## What must never be added here

An endpoint, field or table that would let the control plane answer a question
about workspace membership or content. `registries/data-classification.md` lists
those as class `X`, present precisely so that a proposal to add one is visibly a
change to the trust boundary rather than a migration.
