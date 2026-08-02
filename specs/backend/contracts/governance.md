# Governance and change control

Until this file existed, "the Weald Protocol" meant "whatever our current wire
format happens to be". The difference between those two things is not the quality
of the specification. It is whether somebody who is not us can depend on it: know
what may change, know how much warning they get, know how to object, and know
what will still be true in two years. That is what this document supplies, and it
is the last of the two genuine gaps recorded in `PROTOCOL-READINESS.md`, the
other being the ciphersuite pin now written in `../relay/mls-binding.md`.

Scope: the protocol surface listed below. Not the macOS client, which is not
open source and carries no compatibility promise; not the control plane's
internal schema; not pricing, packaging or the hosted tier's operations.

## 1. What is governed

A change to any of these is a protocol change and follows this document.
Everything else is ordinary engineering.

| Surface | Artifact | Why it is here |
| --- | --- | --- |
| Envelope and frames | `wire/wire.cddl`, `../relay/wire.md` | Two implementations must agree byte for byte. |
| Version negotiation | `../relay/wire.md` | The mechanism every other change depends on. |
| Authentication | `../relay/auth.md` | A relay and a client must agree or nobody connects. |
| Cryptographic profile | `../relay/mls-binding.md`, `../WEALD-PROTOCOL.md` section 5 | Pinned, one value per parameter, no negotiation. |
| Error codes | `registries/error-codes.md` | Clients branch on these. |
| Conformance vectors | `wire/vectors/` | The definition of "conforming". |
| Event kinds and payloads | `wire/wire.cddl` | The envelope is closed; payload kinds are open, per section 3. |
| Relay configuration a client can observe | `../relay/server.md` | An operator's setting that changes client behaviour is protocol. |

Explicitly not governed: the relay's database schema (an implementation detail
of one implementation, documented for operators, free to change on any release),
log formats, metric names, the control plane's HTTP API (versioned separately by
`api/openapi.yaml`), and anything under `../build/`.

## 2. Versioning

One integer. Not semantic versioning, because there is exactly one axis that
matters to a peer: can we talk or not.

- The protocol version appears in `CONNECT`, as a minimum and a maximum, and is
  signed into the authentication challenge so a downgrade is detectable rather
  than silent. This is already specified in `../relay/wire.md` and is the
  foundation the rest of this section stands on.
- Version 1 is the current version.
- A version number is allocated only by the process in section 4, and never
  reused, never withdrawn once published, and never renumbered.
- Relay and client version ranges are independent. A relay advertises what it
  accepts; a client pins a floor. Neither may assume the other upgraded.
- There is no minor version and no patch version. A specification correction that
  does not change what bytes are legal is an editorial revision, dated, recorded
  in the revision log at the foot of the amended file, and not a version bump.

## 3. The three change classes

Every proposal is exactly one of these, and misclassifying one is the failure
mode this section exists to prevent.

**Editorial.** Wording, examples, corrections that do not change which byte
sequences are legal or what a conforming implementation does. Requires review by
one maintainer and a note in the amended file's revision log. Ships whenever.

**Compatible extension.** Adds something an old implementation can ignore
without becoming wrong. In practice this means exactly one thing: a new payload
kind. The envelope is closed and unknown envelope keys are rejected with
`reject/unknown_required_field`; payload kinds are open, which is the seam the
protocol deliberately left itself. A compatible extension requires: a CDDL
entry, at least one acceptance vector and one rejection vector, a statement of
what an implementation that does not understand the kind does with it, and
maintainer review. It does not bump the version.

**Breaking change.** Anything else, and the test is mechanical rather than a
matter of opinion: if a version N implementation and a changed implementation
can fail to interoperate for any input, it is breaking. Adding a required field,
removing or repurposing a field, changing an error code's class, tightening a
limit, changing any row of the pinned cryptographic profile, and changing the
handshake are all breaking. A breaking change bumps the version and runs the
full process in section 4.

Two rules that exist because they are the ones most likely to be argued around:

- Intent is irrelevant. A change that fixes a defect and breaks interoperability
  is a breaking change with a good reason, not a non-breaking change.
- Tightening is breaking. Rejecting input that was previously accepted breaks
  every peer that was sending it, including peers whose behaviour we consider
  wrong. Loosening is usually breaking too, because the peer on the other side
  is doing the rejecting.

## 4. How a breaking change happens

1. **Written proposal.** In `decisions/` as an ADR, per the existing convention.
   It names the problem, the change, what it breaks, what it costs an operator
   of a self-hosted relay, and the alternatives rejected. An ADR that does not
   name a rejected alternative is not finished.
2. **Public comment, minimum 30 days.** Published where the specification is
   published, dated, open to anyone. Comments are answered in public, in the ADR.
   The clock does not start until the full text is public.
3. **Decision, recorded.** Accepted, rejected or withdrawn, with reasoning, in
   the same ADR. A rejected proposal stays in the tree; the record of what was
   turned down and why is as much a part of the protocol's history as what was
   accepted.
4. **Version allocation and specification.** New version number, amended
   specification text, and CDDL.
5. **Vectors before code.** The conformance corpus carries the new version
   alongside the old before any implementation claims it. A version whose vectors
   do not exist yet is not a version.
6. **Cross-version proof.** The cross-version property suite in
   `../relay/mls-binding.md` must show an old and a new implementation in one
   group, and the negative proof must show the downgrade being detected.
7. **Deprecation calendar.** The old version runs through the stages in
   `../relay/mls-binding.md` before it is refused. Eighteen months from
   announcement to refusal, and no shortening except by section 6.

Steps 1 through 3 may be skipped only for the emergency path in section 6.
Steps 4 through 7 may never be skipped.

## 5. Who decides

Honesty first: today this is one company and, in practice, one maintainer. Saying
otherwise would be the kind of governance theatre that makes a protocol document
less trustworthy rather than more. What follows is what is actually true and what
is actually committed to.

**Today.** A single maintainer with published constraints. Weald decides. The constraints are real and are the
part that matters: every breaking change follows section 4 including the 30 day
public comment period; every decision including every rejection is published with
reasoning; and the deprecation calendar binds us the same way it binds anyone
else. A maintainer who can change the protocol silently is not governed by
anything, so the commitment is specifically to never do it silently.

**The trigger for changing this.** When there is a second independent
implementation of the relay or the client that is not ours and is in production
use, this section is replaced by a maintainers group including that
implementation's authors, with a documented process for adding and removing
maintainers, before the next breaking change ships. That trigger is written here
rather than left to goodwill so that the obligation survives us being busy.

**What a third party can rely on now, before any of that.** The Apache 2.0 grant
on the relay and the MLS binding, which does not depend on our continued good
behaviour. The published specification and vectors, which are enough to build an
independent implementation. The deprecation calendar. And the fork right: if this
governance fails, the licence is what lets someone else continue without us, and
that is deliberately the backstop rather than a promise we make about ourselves.

## 6. Emergency changes

Two situations, and only these two: a cryptographic break in a pinned primitive,
and a defect that lets a non-member read plaintext or impersonate a member.

- The public comment period is waived. Nothing else is.
- The change is the narrowest one that closes the hole. An emergency is not an
  occasion to also land the thing we wanted anyway.
- The deprecation calendar collapses to the shortest interval that gets a fixed
  implementation into users' hands, and applies only to the affected parameter.
- The reasoning is published at the time, not afterwards, and includes what was
  known when, and what the window of exposure was.
- Within 30 days the change goes through the full section 4 process
  retrospectively, and if that process would have reached a different answer, the
  emergency change is amended.
- Coordinated disclosure timing is the one thing that may delay publication of
  the reasoning, and it delays it by days, with the delay itself disclosed.

## 7. Registries

`registries/error-codes.md` and the event kind list in `wire/wire.cddl` are
registries, and registries need an intake rule or they become a graveyard.

- Codes and kinds are allocated by this process, never invented locally. This is
  already mechanically enforced: `scripts/spec-check.sh` fails if a code appears
  in a spec, in the OpenAPI document or in source and is not registered, and
  fails if a registered relay code has no negative vector.
- A code is never removed and never reused for a different meaning. A retired
  code is marked retired and keeps its row, because somewhere there is a client
  that still branches on it.
- Adding an error code within an existing class is a compatible extension.
  Adding a class, or moving a code between classes, is breaking, because clients
  branch on the class first.
- Vendor-specific or experimental codes are not permitted. There is no private
  range. A code that exists is in the registry.

## 8. What we will not do

The list is short and each entry is here because it is a thing protocols
routinely do to their implementers.

- No silent breaking change, and no change presented as a clarification that
  narrows what is legal.
- No version withdrawn or renumbered after publication.
- No private extension range, no vendor prefix, no "reserved for future use"
  field that turns out to be already in use by us.
- No negotiation of the cryptographic profile, and no configuration surface that
  amounts to one.
- No protocol feature that only the hosted relay implements. If a self-hosted
  relay cannot do it, it is not in the protocol, and this is checkable: the
  relay binary is the same binary with a different profile, per
  `../relay/server.md`.
- No deprecation faster than the calendar except under section 6, and no use of
  section 6 for anything but the two situations it names.

## Revision log

| Date | Change |
| --- | --- |
| 2026-08-02 | Created. First governance and change control document for the protocol. Closes the second of the two real gaps in `PROTOCOL-READINESS.md`, alongside the cryptographic pin in `../relay/mls-binding.md`. |
