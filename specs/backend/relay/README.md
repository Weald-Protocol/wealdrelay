# Relay specs

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only: the Clerk
> production instance, Stripe live mode, the production Render environment and
> Postgres, the production R2 bucket, the published relay digest. No dev tier,
> no test mode, no staging tier, and no agent creates one. `local` and `ci` are
> not an exception because they reach no vendor at all. A gate that cannot reach
> production configuration fails; it never degrades to a mock, a stub, a fake, a
> skip or a newly created dev or staging resource.

Design for Weald's second sync substrate: a blind relay that carries `.weald`
state end-to-end encrypted, alongside the existing git transport.

One workspace is one project throughout these specs: one `.weald` directory, one
roster, one recovery phrase, one relay. See `multi-workspace.md`.

Read in this order.

**Protocol.**

| Spec | Covers |
| --- | --- |
| `overview.md` | Goals, layering, competitive position, rubric delta, what we give up. |
| `identity.md` | Device keys, principals, roster, agent certificates, agent leaf lifecycle. |
| `auth.md` | Signup, admin, mandatory recovery phrase, pairing, recovery. |
| `invites.md` | Invites, one-time codes, external commits, the genesis key, admin controls. |
| `groups.md` | MLS groups, epochs, derived keys, history policy, deletion, threat model. |
| `channels.md` | Default channels, admission policy, self-join, pending adds, creation order. |
| `wire.md` | Envelope, author chains, head attestation, the access set, event kinds, sync, transport. |
| `mls-binding.md` | OpenMLS behind a twelve-function Rust FFI. Highest-risk engineering in the programme. |

**Running it.**

| Spec | Covers |
| --- | --- |
| `server.md` | The self-host package. What a customer downloads and runs. |
| `deployment.md` | The four paths to a running relay, including private-network with no public ingress. |
| `operations.md` | Running it under load and under attack: seq assignment across processes, frame error classes, backpressure, DoS bounds, clock skew, key package supply. |
| `test-harness.md` | Deterministic real-Postgres, raw-WebSocket, storage, and process-boundary test workflow. |
| `media.md` | Blob upload, download, quota, and how blobs are ever reclaimed. |
| `lifecycle.md` | Offboarding, key compromise, retention, compaction, ongoing health checks. |

**Living with it.**

| Spec | Covers |
| --- | --- |
| `search.md` | Client-side index and the cold-start budget, with gates. |
| `agents.md` | Agents proxy through the local app rather than holding their own MLS state. |
| `multi-workspace.md` | One workspace is one project. One client holding several, isolated keys and phrases. |
| `notifications.md` | Local notifications now, pre-decided APNs rules if it ever ships. |
| `verification.md` | The proofs, as UI surfaces rather than a docs page. |
| `migration.md` | Phased rollout from git, dual transport, rollback, risk register. |

Prerequisite reading, outside this folder: `specs/sync-substrate.md` for why git
was chosen and how the eight-dimension rubric works, `specs/chat.md` for the
current on-disk chat format, `specs/weald-data-tiers.md` for the durable and
live split, `specs/ticket-format.md` and `specs/ticket-write-contract.md` for
the round-trip guarantees the relay must not break.

Status: specification only. Nothing here is implemented. Phase 0 in
`migration.md` is the only part cleared to start.

Nothing in `specs/backend/cloud/` is a dependency of anything in this folder. The
relay has no client, credential or configuration key for Clerk, Stripe, Render or
the control plane, and the integration runs one way only: they poll us. A change
that breaks this makes the hosted binary differ from the audited binary, which is
a trust boundary change (`relay/server.md`).

The one-line claim the whole folder exists to support: an operator running the
relay, including us, cannot read message bodies, ticket text or media.

The bounds on that claim, stated in the same breath everywhere it appears:
metadata is visible, including the number of principals in a workspace; a
compromised member device holds plaintext; content an agent sends to a model
provider has left the boundary; deletion in an `open`-history group removes the
blob and not the key; and external-commit validation is detect-and-evict within
one epoch rather than gated up front.
