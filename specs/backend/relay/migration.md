# Relay: migration from git

How the relay lands without breaking the git path, and how to back out.

Governing rule: git is not being replaced. On the rubric in
`specs/backend/relay/overview.md` a git-backed transport scores 5 on
`durability`, `infra`, `offline` and `maturity`, and those four fives are the
existing bet. The relay is a second transport over the same event model, not a
rewrite.

## Sequencing

Five phases. Each is shippable and each leaves the product working if the next
one never happens.

**Phase 0: extract the transport seam.** Define `SyncTransport` with
publish, subscribe and reconcile, put the existing git behaviour behind it as
`GitTransport`, and change nothing else. No user-visible change. This is the
only phase that is unambiguously worth doing regardless of everything else in
this spec family.

**Phase 1: event model, git-backed.** Introduce the envelope and payload from
`specs/backend/relay/wire.md`, but with the relay's role played by files. Envelopes pack
into `.weald/log/<group>/<utc-day>.bin`, append-only, `merge=union` friendly.
Signing is already in place. Encryption is off in this phase. Existing JSONL
chat and the ticket files on disk remain the human-editable surface; the log is
derived. Still no server.

**Phase 2: relay as an accelerator.** Ship `wealdrelay`. Clients that can reach
it get sub-second sync; clients that cannot fall back to git and converge later.
Both transports carry identical envelopes, so a team can be split across them
during rollout without splitting its history. Encryption still off, so the
relay is readable at this stage and must be labelled as such in the client.

Readable at this stage means `enc: 0` envelopes against a relay running
`WEALD_RELAY_MIN_ENC=none` (`specs/backend/relay/wire.md`), which the client
reports in the encryption panel rather than leaving to an operator's memory.
**This phase never reaches a paying customer.** The hosted tier is fixed at
`mls` and cannot be configured otherwise, so a hosted workspace is encrypted
from its first envelope and the phase order here is a development sequence and
a self-host option, not a menu presented at checkout
(`specs/backend/hosted-service.md`). Shipping the hosted tier on
Phase 2 would have made the product's one claim false for everyone who bought
it.

**Phase 3: encryption on.** MLS groups per `specs/backend/relay/groups.md`. This is the
phase that makes the product claim true, and it is the one with real risk. Once
a group is encrypted, git can no longer serve as a readable archive for it, so
Phase 3 forces the question in Phase 4.

Phase 3 does not ship without all of: the property suite and fuzzing in
`specs/backend/relay/mls-binding.md` passing, including the author chain
crash-injection and the recovery and history reachability properties; the
cold-start gates in `specs/backend/relay/search.md` met on the fixture
workspace; compaction running per `specs/backend/relay/lifecycle.md`; and the
one-action removal flow implemented end to end, with a removal minutes after a
join proven to disconnect (`specs/backend/relay/wire.md`). Those four are what turn this from a working prototype
into something an enterprise can be sold, and each of them is the kind of work
that gets deferred to "after launch" and then never done.

The suite includes failure injection for the recovery tag-directory handoff,
checkpoint-manifest verification before `drop_before`, and the relay's
admission-blind group-ingress budgets. Those are release gates rather than
operational tuning: each protects a property the relay cannot recover after an
implementation shortcut.

It also includes the first-run tests that the second flow pass added: a parked
join outliving its reservation window without losing its seat, a provisional
grant that binds one reservation's device hash and no other, bootstrap
consumption landing atomically with genesis-key destruction, a 24-hour agent
soak raising no split-view warning, and a phrase-only recovery in a
quorum-registered workspace clearing probation on `m` signatures and on no
fewer. Each of those is a first-ten-minutes failure, which is the class users do
not report and do not return from.

It also includes adversarial authorization tests: a stolen recovery phrase must
remain probationary indefinitely without pre-existing-authorizer or quorum
approval; a
single current member's manifest omission or checkpoint must never delete media
or envelopes without the required retention authorization; and a cancelled or
not-yet-due authorization must leave every object intact. Hosted acceptance tests
claim the bootstrap handoff exactly once, restore an exported tarball without a
Weald-held backup key, and prove that detailed health and metrics are unreachable
from the public relay listener.

**Phase 4: git as the archive tier.** A designated device holds plaintext and
writes a decrypted, human-readable mirror into the repo on a schedule. Opt-in
per workspace, which is per project. This preserves the "a clone is a complete archive" property for
teams that want it, while making explicit that the property costs one machine
holding plaintext. Teams that decline get relay-only durability, which is every
member's local copy plus the operator's ciphertext.

## Dual transport

During Phases 2 and 3 both transports are live. Rules:

- Envelope hashes are content-addressed, so an envelope arriving by both paths
  deduplicates without coordination.
- The CRDT layer is order-independent, so it does not matter which path delivers
  first.
- The relay's `seq` is advisory when git is also in play. Causality comes from
  the Automerge change graph, never from `seq`. This is already required by
  `specs/backend/relay/wire.md` and dual transport is why.
- A client reports per project, and so per workspace, which transport is live, and the UI shows it. A
  user should never be guessing whether their teammate has seen something.

## Data migration

There is none, and that is deliberate.

Existing `.weald/chat` JSONL and the ticket files on disk are not converted. They
remain readable and remain the archive of everything written before the cutover.
New envelopes start at sequence 0 in a new log. A client renders both, sorted by
timestamp, with a visible boundary marker.

Rationale: converting history means re-signing content with keys that did not
sign it, which manufactures attribution that never existed. The same reasoning
that leaves legacy unsigned lines permanently unverified applies here.

## Rollback

Per phase.

- **Phases 0 to 2** roll back by switching the transport flag. Nothing was
  encrypted, everything is still in git, no data is stranded.
- **Phase 3 rollback is a decryption event**, not a config change. A group with
  a plaintext-holding member can export and re-emit to git; a group without one
  cannot be recovered by us and must not be, since that is the entire point.
  Before enabling encryption for a group the client requires acknowledgement of
  exactly this, in one sentence, with no dark pattern.
- **Phase 4** is additive and rolls back by turning the mirror off.

## Risk register

| Risk | Severity | Mitigation |
| --- | --- | --- |
| MLS plus CRDT history replay is subtly wrong and members silently lose data. | High | Property-based tests over random membership churn interleaved with concurrent edits, asserting convergence and that removed members cannot decrypt post-removal epochs. Specified as a gate in `specs/backend/relay/mls-binding.md`. Gate Phase 3 on it. |
| The Rust FFI holding every key is where the memory-safety bug lands. | High | Fourteen-function seam, no callbacks, no panics across the boundary, fuzzing on the one function that eats untrusted bytes, and audit scope that includes the binding (`specs/backend/relay/mls-binding.md`). |
| Cold-start decrypt and index makes a new device feel broken. | High | Four-phase staged index with published gates: skeleton under 5s, 30-day window under 60s, full backfill under 20 minutes on the fixture workspace (`specs/backend/relay/search.md`). |
| Relay storage grows without bound on a storage-priced plan. | High | Checkpoint-anchored compaction, automated by the epoch steward, with an admin-visible lever before the plan limit (`specs/backend/relay/lifecycle.md`). Gate the hosted tier on it. |
| Offboarding leaves a revoked person connected or their recovery phrase live. | High | One removal action performing all of roster, epochs, recovery wraps and access set, with a receipt (`specs/backend/relay/lifecycle.md`). |
| `infra` regression loses the zero-service selling point. | Medium | Git path stays fully supported and remains the default for new workspaces until Phase 4 lands. |
| Search quality drops when it moves client-side. | Medium | Local index built at decrypt time, not at query time. Benchmark against the existing client-side search latency before shipping. |
| We become the maintainers of a bespoke protocol. | Medium | Every layer that can be a standard is one: MLS, WebSocket, Automerge, Negentropy. The only novel part is the envelope, which is 8 fields. |
| Notification previews break on iOS. | Low | v1 has no push service at all, so this is deferred rather than mitigated. Rules for when it ships are pre-decided in `specs/backend/relay/notifications.md`. |
| A contractor's second workspace leaks key material into the first. | Medium | Per-workspace device keys, key stores and indexes, with no cross-workspace references anywhere (`specs/backend/relay/multi-workspace.md`). |
| A mechanism added for one purpose hands the relay membership metadata the product claims it cannot have. | High | The recovery wrap index was exactly this and is now blinded per epoch (`specs/backend/relay/groups.md`). The standing control is the review question in `specs/backend/hosted-service.md`: anything the relay stores per group is assumed to be a membership signal until shown otherwise, and the verification runbook has a step that checks it empirically rather than by reading the code. |
| A detector that only alarms on contradiction is defeated by suppression. | High | Head attestation now alarms on silence against an expected set as well as on disagreement, and the runbook tests it by blocking attestations rather than by forging one (`specs/backend/relay/wire.md`). |
| A recovery phrase becomes a way to take a workspace rather than to re-enter one. | High | The recovery rotation is additive, pins the removals it licenses, and the device it introduces remains probationary until a pre-existing authorizer confirms it; it never self-promotes on a timer (`specs/backend/relay/wire.md`). |
| An `open` channel entered by self-join is empty, contradicting its own lock state. | Medium | History travels as a group history key on both join paths, and its presence is on the weekly health check (`specs/backend/relay/channels.md`). |

## What gets a ticket

Phase 0 only, initially. The rest stays as specification until Phase 0 lands and
the seam is real, because sequencing work behind an interface that does not yet
exist is how a spec family turns into fiction.
