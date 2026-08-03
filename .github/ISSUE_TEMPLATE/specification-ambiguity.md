---
name: Specification ambiguity
about: A place in the specification where two implementers could reasonably disagree
labels: specification
---

An ambiguity in the specification is a bug in the specification. This is the
report we most want, and it does not need a patch attached.

**Where.** File and section, for example `specs/backend/relay/wire.md`, "Header
binding".

**The two readings.** What you took it to mean, and the other thing it could
mean. If you have already implemented one of them, say which.

**What the artifacts say.** `specs/backend/contracts/wire/wire.cddl` and the
vectors under `specs/backend/contracts/wire/vectors/` outrank the prose where
they disagree (ADR-0008). If they settle it, the fix is to the prose, and saying
so here saves a round trip. If they do not cover the case, that is the more
interesting report.

**What you expected the relay to do, and what it did**, if you got as far as
running one.
