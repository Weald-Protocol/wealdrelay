# Relay specs

Design for Weald's second sync substrate: a blind relay that carries `.weald`
state end-to-end encrypted, alongside the existing git transport.

One workspace is one project throughout these specs: one `.weald` directory, one
roster, one recovery phrase, one relay. See `multi-workspace.md`.

**Conventions carried over from where these documents were written.** They are
development bookkeeping and none of them carries meaning for an implementer.

"Step N" refers to a gated step in Weald's private build ledger, which advances
only when its unit, property, integration and negative proofs are all recorded.
A sentence like "corrected in step 7" is dating a decision, not naming anything
you need. Similarly, `build-evidence/` paths point at recorded artifacts in that
repository, and citations of `specs/backend/build/*`, `specs/backend/cloud/*`,
`Sources/*`, `Tests/*` and the `scripts/backend-gate.sh` family name files in
the private monorepo that holds the macOS client and the build ledger. They are
provenance for a decision, not reading you are missing: where such a reference
matters to you, the claim it supports is restated in `verification.md` in terms
you can check yourself. Everything needed to implement, run and verify a relay
is in this repository.

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

Background cited but not shipped here: `specs/sync-substrate.md` for why git was
chosen and how the eight-dimension rubric works, `specs/chat.md` for the current
on-disk chat format, `specs/weald-data-tiers.md` for the durable and live split,
`specs/ticket-format.md` and `specs/ticket-write-contract.md` for the round-trip
guarantees the relay must not break. Those describe the client's on-disk formats
and live in the private client repository. Nothing in this folder depends on
reading them: the relay carries opaque payloads, and what it does with them is
specified in `wire.md`.

Status: pre-1.0, and implemented. The relay in `backend/wealdrelay` and the MLS
binding in `backend/weald-mls` are the running code these documents describe.
Where a document and the code disagree, `verification.md` says which proof
settles it.

Nothing in Weald's hosted service (`specs/backend/hosted-service.md`) is a
dependency of anything in this folder. The
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
