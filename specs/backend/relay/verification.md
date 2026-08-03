# Relay: proving the encryption

The claim is that an operator cannot read content. An unverifiable claim is
marketing. This spec is the set of surfaces that let a customer, a security
reviewer or a journalist check it without taking our word for anything.

Design rule throughout: **proof is a UI surface, not a documentation page.** A
security write-up is read once by one person before purchase. A panel in the app
is seen by everyone, every week, and it is what turns a claim into something
users would notice breaking.

## The six proofs

Each answers a different question, and none of them substitutes for another.

| Question | Proof |
| --- | --- |
| Is the released relay artifact the published source? | Reproducible build plus signed release provenance. |
| Is the relay actually blind, or does the protocol leak? | Published threat model plus third-party audit. |
| Has someone been silently added to my group? | Safety numbers plus the membership transparency log. |
| Is the relay showing everyone the same history? | Author chains plus head attestation. |
| Was this workspace founded by the person I think? | Genesis entry at the head of the transparency log. |
| Is my content encrypted right now, in this channel? | Per-channel encryption state in the client. |

The middle two are new, and both close holes rather than adding polish. Without
head attestation, a relay could serve consistent but different histories to
different clients and no single client would notice
(`specs/backend/relay/wire.md`). Without a genesis entry, the most
security-critical moment in a workspace's life, the one where a hosted control
plane briefly handles an admin capability, sat outside the log entirely
(`specs/backend/relay/invites.md`).

## Proof 1: the released binary is the published source

Reproducible builds, published digests, and client-side release comparison as described in
`specs/backend/relay/server.md`. The part that makes it live rather than
ceremonial:

The client fetches `/releases` from the control plane (`specs/backend/hosted-service.md`),
reads the digest its relay reports, and compares. A mismatch is not a log line:
it is a banner naming the expected and reported digests, shown to every connected
user until acknowledged. This detects ordinary deployment drift and operator
mistakes.

It does **not** prove what a remote host is executing. A modified relay can lie
about a self-reported digest. The product must not claim otherwise. Hosted
instances therefore expose provider deployment metadata and signed image
provenance for independent operator audit; a cryptographic runtime proof would
require hardware-backed remote attestation and is not a v1 property. The MLS
content-confidentiality claim does not depend on this self-report, but any claim
about a compelled or modified server build must be limited to the evidence we
actually have.

Self-hosters get the same check against the public `/releases` feed, which is
unauthenticated for exactly this reason.

## Proof 2: the protocol is what we say it is

Threat model published verbatim from `specs/backend/relay/groups.md`, including
the parts that are unflattering: metadata is visible, a compromised member
device holds plaintext, content sent to a model provider has left the boundary,
and external-commit validation is detect-and-evict within one epoch rather than
gated up front.

Third-party audit of the MLS integration and envelope handling before general
availability, scope and firm named, report published whole rather than
summarised. `specs/backend/hosted-service.md` sequences this ahead of SOC 2,
because for this audience it is worth more and costs less.

## Proof 3: nobody was silently added

**Safety numbers.** Per group, derived from the ratchet tree, comparable out of
band. Already required by `specs/backend/relay/groups.md`. The UI addition: a
member who has been verified once carries a badge, and the badge clears if their
device set changes. Unverified members are visible as such in the member list
rather than being indistinguishable from verified ones.

For invited members this is mostly free, because the 12-character code in
`specs/backend/relay/invites.md` already binds the join to an out-of-band
channel. The invite flow marks the joiner verified on redemption, so the badge
reflects real evidence rather than a ceremony nobody performed.

**Membership transparency log.** Every epoch change hash-chained, verified for
continuity on sync, with a loud warning on a gap or a fork. Its first entry is
the genesis key and the trust root it admitted, so the chain has no unlogged
prefix. This is what catches a relay that adds a leaf and hopes nobody
recomputes the tree.

**Head attestation.** Every client publishes, every 15 minutes, the highest
signed counter it has seen from every author in every group it holds. Clients
compare. A relay withholding envelopes from one person, or serving a forked
history to two halves of a team, produces a disagreement that surfaces as a
split-view warning naming the relay and the authors involved
(`specs/backend/relay/wire.md`).

The panel reports agreement against the **expected** set of attesters, taken from
the group's device leaves in the ratchet tree, and names who has not been heard
from. Agent leaves are covered by the device that proxies them rather than
counted as silent members, because an agent holds no state to attest to
(`specs/backend/relay/wire.md`). Getting that wrong would put a permanent
warning on every workspace that uses agents, which is every workspace, and a
detector that is always red is a detector nobody reads. That distinction
is the difference between a working detector and a decorative one: a relay that
suppresses attestations rather than forging them produces silence, and a panel
reading "agreeing with 2 of 2" while eleven members go unmentioned would report
an attack as perfect health.

This is the proof that the relay's control over ordering and delivery is
bounded. Without it, "the relay cannot forge history" was true only in the sense
that it could not forge a signature, while still being free to decide who saw
what.

## Proof 4: this channel is encrypted, right now

The everyday surface, and the one most likely to be skipped in implementation
because it looks decorative. It is not.

**Channel header.** A lock state showing the history policy (`open` or
`closed`, per `specs/backend/relay/groups.md`) and the member count. One glance,
no settings dive.

**Encryption panel**, per workspace, reachable in two clicks:

- Relay hostname, running digest, and match state against `/releases`.
- Transparency log continuity: verified through epoch N, last checked at T,
  genesis verified against the fingerprint recorded at enrollment.
- Split-view state: agreeing with N of the M members expected to attest, the
  ones not heard from named, last compared at T.
- Access-set standing: whether any authorizer is currently probationary, which
  recovery principal introduced it, and the pre-existing authorizer whose
  approval is required (`specs/backend/relay/wire.md`). A workspace that has
  recently been recovered should be able to see it and resolve it directly.
- Any author chain reset declared in a group, naming the author and the date, so
  a stated gap reads as a stated gap and an unstated one keeps its alarm.
- Access set enforcement state, since a relay running with it off is materially
  weaker and the customer should not have to read their operator's environment
  file to find out (`specs/backend/relay/wire.md`).
- Member list with verification badges and device counts.
- History verification floor per group, since compaction means chains below a
  checkpoint are verified by signature rather than by replay
  (`specs/backend/relay/lifecycle.md`).
- Plain-language "what the relay can see" block, generated from the actual
  protocol rather than hand-written: envelope sizes, timing, group identifiers,
  connection metadata. Not a marketing paraphrase, and it updates if the
  protocol changes.
- A "what the relay cannot see" block naming message text, ticket text, media,
  channel names, display names and the roster.

**Agent context disclosure.** Required by `specs/backend/relay/groups.md` and it
belongs here too, because it is the largest real hole in the encryption story:
per agent, which model provider its context goes to. Content an agent sends to
an inference API has left the boundary, and a user who does not know that is
being misled by the lock icon three inches away.

## Verification runbook

Written as a runnable procedure, not prose. A reviewer with a terminal should be
able to work through it in under an hour. The operator-facing version, with the
commands and the counterpart each step has in the test suite, is
`specs/backend/relay/verification-runbook.md`.

1. Clone the relay source at the tag matching your running digest.
2. Run the reproducible build. Compare the resulting digest.
3. Confirm the release artifact's digest matches what your client displays and,
   for hosted, compare it with the provider deployment metadata.
4. Capture relay traffic. Confirm envelopes are opaque and that the fields the
   relay reads are only those in the header per `specs/backend/relay/wire.md`.
5. Dump the relay's Postgres. Confirm no plaintext content is present.
6. Compare safety numbers with a colleague on a second device.
7. Verify the transparency log chain from genesis, including that the genesis
   entry names the fingerprint your relay printed at first run.
8. On two clients, compare the head attestations for one group and confirm they
   agree, then block one client's attestations at the relay and confirm both
   raise a split-view warning within two rounds. Silence must alarm as loudly as
   contradiction, and this is the step that proves it does.
9. Confirm the relay reports access set enforcement, and that revoking a test
   device drops its connection within seconds. Repeat with a device that joined
   minutes earlier on a still-live invite, which is the case a provisional grant
   would otherwise have kept connected
   (`specs/backend/relay/wire.md`).
10. Dump the relay's recovery wrap table. Confirm that the index rotates every
    epoch and that no value in it recurs across two groups, which is what stops
    the wrap index being a membership graph
    (`specs/backend/relay/groups.md`).

If you only run one of these, run step 5. It is the one that convinces people:
`SELECT * FROM envelopes` against the relay's own database returns nothing but
blobs, and no amount of prose about encryption carries the same weight as seeing
that yourself.

## What we must never ship

Anything that would make these proofs false, listed so it is a checklist during
review rather than a judgement call:

- A server-side search index, in any form, including "encrypted search" schemes
  that leak access patterns without a much stronger analysis than we can do.
- A support tool that reads workspace content.
- A notification service that renders previews server-side.
- A hosted-only relay build. The hosted binary is the audited binary, always.
- Telemetry from the client carrying content-derived values.
- A key escrow, a recovery backdoor, or an operator-held group membership.

Any feature request that needs one of these is a request to change the trust
boundary and belongs in `specs/backend/relay/overview.md` as a product change,
argued in those words.
