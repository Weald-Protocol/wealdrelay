# ADR-0008: Where an artifact and the prose disagree, the artifact wins

- Status: accepted
- Date: 2026-06
- Source: `specs/backend/contracts/README.md`,
  `specs/backend/contracts/governance.md`

## Context

This system is specified twice. Prose carries the reasoning, the rejected
alternatives and the judgement calls. Contract artifacts, the CDDL schema, the
conformance vectors and the error registry, carry the same rules in a form a
compiler or a test runner can hold us to.

Two descriptions of one rule will eventually disagree. When that happens someone
has to know which one they are implementing against, and finding out by argument
is the failure this decision exists to prevent.

## Decision

The artifact is correct and the prose is the bug.

An implementation is conformant when it passes the vector corpus. Not when it
matches a paragraph. If `wire.md` and `wire.cddl` describe different frames,
`wire.cddl` describes the frames; the fix is a pull request against `wire.md`,
and it is a documentation fix rather than a protocol change.

The precedence is only ever artifact over prose. It does not run the other way,
and an artifact is not licensed to change because it is machine-checkable: both
are governed by `governance.md`, and a breaking change to a governed artifact
still takes its comment period.

## Rationale

An ambiguity in prose is discovered by two implementers reading it differently,
which is to say after both have shipped. An ambiguity in a vector corpus is
discovered by a test failing. Naming the checkable half authoritative is what
makes "conformant" a word with a procedure behind it rather than an opinion.

It also fixes the incentive. If prose were authoritative, keeping the artifact
current would be optional, and a stale schema is worse than no schema because
people trust it.

## Consequences

- Every relay error code has a negative vector, enforced by `scripts/spec-check.sh`
  rather than by review. A code nobody can produce a failing case for is a code
  no implementer can test against.
- A prose-only rule is not a rule yet. If it matters, it gets a vector or a
  schema line in the same change.
- A reported disagreement between a spec and a vector is a specification bug and
  we want it reported as one.
- Prose is still where the reasoning lives, and this decision is not licence to
  stop writing it down. An artifact says what; only prose says why, and why is
  what stops the next person undoing it.
