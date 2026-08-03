# Relay: overview

Weald's second sync substrate. Git stays. This adds a blind relay alongside it so
that `.weald` state can sync in under a second, reach people without a clone, and
be readable only by the team that wrote it.

The claim this whole design exists to support: **an operator running the relay,
including us, cannot read message bodies, ticket text, or media.** Not "does
not". Cannot. If a change to any spec in this family weakens that claim, it is a
product change and gets written down in those words.

**Vocabulary, fixed across every spec in this family: one workspace is one
project.** A workspace owns one `.weald` directory, one roster, one recovery
phrase and one relay instance. There is no container above a project and no
scoped sub-project below one, so "workspace" and "project" name the same object
seen from the protocol side and the developer's side. A team with three projects
runs three workspaces (`specs/backend/relay/multi-workspace.md`).

Spec family:

| Spec | Covers |
| --- | --- |
| `specs/backend/relay/overview.md` | This document. Goals, layering, what we ship. |
| `specs/backend/relay/identity.md` | Device keys, principals, agent delegation certificates. |
| `specs/backend/relay/auth.md` | Signup, admin, mandatory recovery phrase, pairing, recovery. |
| `specs/backend/relay/invites.md` | Email invites, one-time codes, MLS external commits, admin controls. |
| `specs/backend/relay/groups.md` | MLS groups, epochs, membership, history policy. |
| `specs/backend/relay/channels.md` | Default channels, admission policy, self-join, pending adds. |
| `specs/backend/relay/wire.md` | Envelope format, event kinds, sync algorithm, transport. |
| `specs/backend/relay/server.md` | The self-host package. What the customer actually downloads. |
| `specs/backend/relay/deployment.md` | The four concrete paths to a running relay, including private-network. |
| `specs/backend/relay/operations.md` | Sequence assignment, frame errors, backpressure, denial of service, clocks, key packages. |
| `specs/backend/relay/mls-binding.md` | OpenMLS behind a fourteen-function Rust FFI. The highest-risk engineering here. |
| `specs/backend/relay/media.md` | Blob upload, download, quota and garbage collection. |
| `specs/backend/relay/search.md` | Client-side index and the cold-start budget. |
| `specs/backend/relay/agents.md` | How agents connect: through the local app, never their own MLS stack. |
| `specs/backend/relay/lifecycle.md` | Offboarding, key compromise, retention and compaction. |
| `specs/backend/relay/multi-workspace.md` | One workspace is one project. One client holding several, isolated keys. |
| `specs/backend/relay/notifications.md` | Local notifications now, APNs rules if it ever ships. |
| `specs/backend/relay/verification.md` | The proofs, as UI surfaces rather than a docs page. |
| `specs/backend/relay/migration.md` | Git-to-relay path, dual transport, rollback. |

Git alone is not enough for this workload, and the alternatives in the same
space (peer-to-peer code collaboration, capability-scoped stores, federated
messaging, signed event logs) were each scored against the eight dimensions
listed under "Rubric delta" below before this design was chosen.

## The problem

A shared workspace where humans and coding agents write to one log usually
solves durability and ordering, and then stores content the operator can read.
Signing an event proves who wrote it. It does not stop whoever runs the server
from filtering, threading and indexing the plaintext, which means the operator
is inside the trust boundary whether or not anyone intends them to be.
Self-hosting moves that boundary rather than removing it, and a team that has to
run its own infrastructure to get confidentiality is paying for the wrong thing.

The position here is that owning the server should not matter, because the
server is blind either way. That is not a feature bullet. It decides the
architecture, because a relay that cannot read content cannot index it, and
everything downstream of search has to move to the client.

## Posture

Teams of 3 to 30. The relay adds one group to the target that git alone
excluded, the member without a clone, which is the `reach` row in the rubric
below and the standing product risk.

Explicit non-goals:

- Federation between relays. One relay is authoritative per workspace.
- Public or discoverable content. Everything is in a group or it does not exist.
- Server-side search, server-side moderation, server-side anything that needs
  plaintext. These are unavailable by construction, not unimplemented.
- Replacing git. Git remains the archival tier and the offline path.

## Layering

Six layers. Each is replaceable without touching the ones above it.

```
5  Application     tickets, chat, presence, media references
4  State           Automerge CRDT documents, per ticket and per index
3  Encryption      MLS (RFC 9420) group per sync scope, one epoch key per group state
2  Envelope        signed, encrypted, ordered record; the only thing the relay stores
1  Transport       WebSocket over TLS, range-based set reconciliation
0  Identity        Ed25519 device keys, principals, delegation certificates
```

The relay implements layers 1 and 2 only. It sees an opaque blob, a group id, a
sequence number and a size. It does not hold a key that decrypts anything.

## The three properties that follow from that

**1. Content the operator cannot read.** MLS group per scope, keys negotiated
between clients, ciphertext at rest and in flight. Detail in
`specs/backend/relay/groups.md`.

**2. Scope smaller than the workspace.** A plaintext log scopes by server and by
channel membership, enforced server-side. We scope by which group holds the key, so a
contractor admitted to one channel is cryptographically excluded from the rest
rather than filtered out of them, and a contractor working on one project is
never in the other projects' rosters at all, because a workspace is exactly one
project (`specs/backend/relay/multi-workspace.md`). Removal is an MLS epoch change, which means
forward secrecy against a member who kept a copy of the ciphertext.

**3. Revocable, time-boxed agent authority.** The usual arrangement gives an
agent a keypair and membership, and nothing else. We give an agent a keypair plus a signed delegation certificate
naming its scopes, its permitted ticket transitions and an expiry, and expiry
evicts the agent's MLS leaf rather than only voiding its signature.

Stated precisely, because the earlier phrasing of this bullet overclaimed: a
leaked agent key is bounded in **write authority** by its capabilities and in
**time** by its expiry. During its validity window it can read everything in its
scope, because reading is holding an epoch key. That is still far better than a
permanent workspace-wide credential, and it is not the same as "bounded blast
radius" without qualification. Detail in `specs/backend/relay/identity.md` and
`specs/backend/relay/agents.md`.

## What we give up

Written here so it is not rediscovered in month four.

- **No server-side search.** Search is a local index built from decrypted state.
  Cold start on a new device means downloading and decrypting the group history
  before search works, staged so the app is useful in seconds and honest about
  what is still loading (`specs/backend/relay/search.md`).
- **No server-side notification content.** v1 notifications are local to the
  running client, so there is no push provider at all. If APNs ever ships, the
  payload is a wake hint and a rotating group alias, never a preview
  (`specs/backend/relay/notifications.md`).
- **Metadata is not hidden.** The relay learns group sizes, message sizes,
  timing, connection patterns, the number of principals in the workspace via the
  access-set authorizer keys, how often a group's epoch advances and therefore
  how often its membership changes, and which group claims which blob via
  retention manifests. It does not learn who is in a group: the one mechanism
  that would have told it, the per-group recovery wrap index, is blinded per
  epoch for that reason (`specs/backend/relay/groups.md`). Hiding the rest needs
  padding and cover traffic and is out of scope. Say this plainly in
  the marketing, because overclaiming here is how a privacy product dies.
- **Deletion in an `open`-history group is weaker than in a `closed` one.**
  Historical epoch secrets are deliberately re-wrappable for new joiners, so
  advancing the epoch does not retroactively lock old content away from members.
  The blob goes, the key does not (`specs/backend/relay/groups.md`).
- **Backfill for new members is a visible choice at invite time.** Two history
  policies, `open` and `closed`, in `specs/backend/relay/groups.md`.
- **Lost keys mean lost data.** Recovery is the mandatory 24-word phrase in
  `specs/backend/relay/auth.md`. There is no operator reset and there cannot be
  one.

## Rubric delta

Projected scores for the relay path against the eight dimensions this design was
evaluated on, each scored 0 to 5. The figure in brackets is what a purely
git-backed transport scores on the same dimension.

| Dimension | Relay | Why |
| --- | --- | --- |
| `latency` | 5 [2] | Push, not pull. Sub-second on an open connection. |
| `reach` | 4 [0] | Anyone the group admits, no clone needed. Not 5: still needs a Weald client to hold keys. |
| `durability` | 4 [5] | Every client holds a full decrypted copy, and git remains the archive. Not 5: a member who never syncs holds nothing. |
| `infra` | 3 [5] | One stateless binary plus Postgres and object storage. This is the cost. |
| `identity` | 5 [4] | Delegation chain rooted in a workspace roster, not trust-on-first-push. |
| `prunability` | 4 [1] | Real delete: drop the blob, rotate the epoch. Not 5: copies already decrypted by members cannot be recalled. |
| `offline` | 5 [5] | CRDT merge, no coordination needed to write. |
| `maturity` | 2 [5] | MLS is a finished RFC with a solid Rust implementation. Our composition of it is new code. |

`infra` at 3 and `maturity` at 2 are the honest price. The bet is that `reach`
0 to 4 and `identity` 4 to 5, plus a relay that cannot read what it carries, are
worth it, and that keeping git alive means the bet is reversible.

## Deliverable

What a customer downloads is specified in `specs/backend/relay/server.md`. Summary: a
single static Rust binary, a signed multi-arch container image, a one-file
Compose bundle, and one-click templates for Railway, Fly, Render
and DigitalOcean. Reproducible builds with published digests establish release
provenance; hosted runtime identity additionally relies on provider deployment
metadata, as bounded in `specs/backend/relay/verification.md`.
