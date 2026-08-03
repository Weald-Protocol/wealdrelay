# Relay: groups and encryption

How content becomes unreadable to the operator. Layer 3 of the stack in
`specs/backend/relay/overview.md`.

## Choice of primitive

MLS, RFC 9420, via OpenMLS (Rust, audited, stable). Not a hand-rolled scheme,
not Signal's Double Ratchet extended to groups, not Nostr's NIP-04 or NIP-44
wrapping.

Reasons, in order of weight:

1. **Member removal is O(log n) and actually forward-secure.** Pairwise schemes
   require re-encrypting to every remaining member on every change. With agents
   joining and leaving on every session, membership churn is the common case
   here, not the rare one. MLS's ratchet tree is designed for exactly that.
2. **Post-compromise security.** A device compromised at epoch N loses access at
   epoch N+1 once it stops participating in commits. Given that agent keys live
   on developer laptops and in CI, assume compromise and design for recovery.
3. **It is a finished IETF standard with a real implementation.** The one place
   in this design where we can refuse to be novel, we refuse.

Prior art worth reading before changing anything here: Keyhive's causal-key
design solves a strictly harder problem and is pre-alpha. Marmot and NIP-EE are MLS carried over Nostr relays and are
the closest working reference for MLS on a dumb relay.

## Group topology

One MLS group per sync scope. A scope is the unit of "who can read this".

**A workspace is a project.** One workspace corresponds to exactly one Weald
project, meaning one `.weald` directory, and there is no group between the
workspace root and a channel. A team with three projects runs three workspaces
(`specs/backend/relay/multi-workspace.md`).

| Scope | Group | Typical members |
| --- | --- | --- |
| Workspace root | `ws:<workspace id>` | Every device and agent in the workspace. Carries the roster, tickets, board state and workspace documents. |
| Channel | `chan:<slug>` | Subset of the workspace. Carries one channel's messages. |
| Direct | `dm:<pair digest>` | Two users, meaning every device each of them holds. |

A DM is between **users, not devices**, because a user has no key of its own
(`specs/backend/relay/identity.md`) and a conversation that lived between two
laptops would fork the moment either person opened their second one. The id is
`BLAKE3(workspace id || "dm" || the two user ids, sorted)`, taken from the roster
rather than from any key, so it is stable across device pairing, device loss and
recovery. **Each of those four fields is length-framed**, with the same
deterministic CBOR framing every other digest in this design uses, and that was
specified rather than assumed: a bare concatenation of variable-length
fields is ambiguous, so user ids `ab` and `c` would hash to the same id as `a` and
`bc`, and a user id chosen for the purpose could land one pair's conversation in
the group of another pair. The fields, their order and the sort are unchanged. Every current device of both users is a leaf, and pairing a new device
adds it here like anywhere else.

The id is deterministic, so both ends compute the same one and both can try to
create it at once. That is resolved where every other authorization decision in
this design is resolved rather than by a new mechanism: the `GroupPolicy` for a
DM is a `RosterOperation` (`specs/backend/relay/identity.md`), which is linear
and base-headed, so exactly one creation is accepted. The loser does not error
and does not create a second group under the same id. It adopts the accepted
policy, joins the group that won, and re-sends the message the person had
already typed. Nobody sees anything except their message arriving.

Which of these groups exist by default, who is entitled to each, and how a
principal joins one created after they arrived, are specified in
`specs/backend/relay/channels.md`. This document owns the cryptography of a
group; that one owns its membership policy.

Nesting is by convention, not cryptography. A channel group does not derive from
the workspace root group, and holding the workspace key grants nothing about a
private channel. This is deliberate: it means a contractor admitted to one
channel is excluded from the rest by not holding a key, which is the property
that distinguishes this from server-enforced channel membership. The same
argument one level up is why a second project is a second workspace: separate
roots, separate rosters, no shared key material.

Cost: a device in twelve channels maintains twelve MLS states, plus one root per
workspace it belongs to. Measured state is roughly 4 KB plus 200 bytes per member
per group, so this is not a problem at the stated posture of 3 to 30 people. It
would be at 3000.

## Key packages and joining

Each device publishes MLS key packages to the relay, encrypted to nothing (they
are public by design) and rate-limited. A device admitting a new member fetches
a key package, issues an `Add` proposal plus `Commit`, and the relay fans out
the resulting `Welcome` message.

The relay stores and forwards key packages and Welcomes. It cannot derive a
group secret from either.

Key packages are consumed on use and refreshed on a schedule. A device that runs
out is unaddable until it comes online, which is an acceptable failure mode and
should surface in the UI as "waiting for that device to check in" rather than an
error.

### Derived keys, and why none of them are long-lived

Every symmetric key outside the MLS key schedule is derived from it with the RFC
9420 exporter, so that every one of them rotates automatically on every commit:

| Key | Exporter label | Used for |
| --- | --- | --- |
| Retention signing seed | `weald retain v1` | Ed25519 seed for public, relay-verifiable retention manifests and checkpoints. |
| Enrolment key | `weald enrol v1` | Wrapping a child group's `GroupInfo`, and its history key, for principals entitled to self-join it (`specs/backend/relay/channels.md`). |
| Wrap tag key | `weald wraptag v1` | Deriving the per-epoch blinded index under which the relay stores recovery wraps, so that a long-lived recovery key never appears in relay state. |
| History epoch secret | `weald history v1` | The per-epoch value an `open` group seals into `history.publish`, and the content key the envelope layer uses for that epoch. See "History policy" for why the list cannot hold raw MLS epoch secrets. |

An earlier draft used one GroupInfo publication key shared by every member of the
group being joined. A removed member could retain it, unwrap a current GroupInfo,
and external-commit back into the group they had just been removed from.

Two mechanisms replace it, and neither has that property.

For an invitee, who holds no epoch key of any group yet, GroupInfo is sealed to
the individual invite's update public key and refreshed by current members
(`specs/backend/relay/invites.md`).

For an existing workspace member self-joining an entitled group, GroupInfo is
wrapped under the enrolment key exported from the **parent** group's current
epoch secret, which for every channel is the workspace root group, the only
parent there is. Never the target group's own secret, which a joiner
by definition does not hold. The removed-member hole does not reappear because
removal rotates the parent epoch in the same batched pass that removes them
(`specs/backend/relay/lifecycle.md`), so the enrolment key they retain is dead
before they can spend it, and a principal removed from the workspace is outside
the roster that every client validates a self-join against.

The retention exporter output rotates on every commit. It is used only as an
Ed25519 seed; its public half is published in the signed retention-control chain
described in `specs/backend/relay/media.md`. The relay gets the verification key,
never the exporter output or an MLS secret.

## Epochs and the CRDT

Every membership change advances the epoch. Application messages are encrypted
under the current epoch's key schedule.

The interaction with Automerge (layer 4) is the sharp edge of this whole design,
so state it precisely:

- An Automerge change is encrypted as a single MLS application message. One
  change, one envelope. Do not batch across epochs.
- A document's full history is therefore a sequence of envelopes spanning many
  epochs. Replaying the document from scratch requires decrypting every one.
- A member who joins at epoch N can decrypt envelopes from epoch N forward. It
  cannot decrypt epochs 0 through N-1, by construction. That is the security
  property working, and it is also the reason new members see an empty board
  unless something is done about it.

### History policy

Two options, not three. An earlier draft had `forward-only`, `reseal-on-join`
and `shared-history`; the middle one required an online member holding plaintext
at join time, which reintroduced exactly the wait that MLS external commits
remove (`specs/backend/relay/invites.md`). A three-way policy matrix that nobody
can explain in one sentence is also a maintenance liability. Collapsed to:

**`open`.** Historical epoch secrets are available to every principal the group
admits, so a joiner reads everything written before they arrived. Default for
`ws:` and `chan:` groups. This is the weaker option and the UI says what it
does in plain words at invite time: "give them access to past messages in these
channels".

An `open` group therefore maintains a **history key**: one long-lived X25519
keypair, created with the group, under which the accumulating list of historical
epoch secrets is sealed and published as `history.publish`
(`specs/backend/relay/wire.md`). The history key itself is small, so it is the
only thing that has to be re-wrapped when the enrolment key rotates, and the
sealed history blob is rewritten only when the group gains an epoch.

**What is in that list, corrected.** An earlier version of this
paragraph said the list holds historical epoch secrets, meaning the MLS key
schedule's own. It cannot, and the correction is not cosmetic. No RFC 9420
implementation hands an epoch secret out, the exporter is the only way key
material leaves the key schedule, which is the rule `mls-binding.md` states and
the rest of this design relies on, and MLS defines no operation that re-imports a
past epoch's schedule into a group, so a recipient could do nothing with one if it
had it. What an `open` group accumulates is therefore one **exporter output per
epoch** under `weald history v1`: the content key the envelope layer uses for that
epoch, which is exactly what a joiner needs in order to read what was written
then, and which rotates on every commit like every other derived key. The recovery
wrap already carries the epoch's value this way below the boundary, under
`weald recovery v1`, so this is the existing shape rather than a new mechanism.
The consequence for the envelope layer is stated once, here: an `open` group's
application content is keyed so that holding that epoch's exporter output is
sufficient to read it, and a `closed` group's is not.

Two paths consume it and they are deliberately the same shape:

- An **invitee** receives the history key inside its invite bundle, sealed to the
  invite's `update_pub`, alongside the `GroupInfo`
  (`specs/backend/relay/invites.md`).
- A **self-joiner**, meaning an existing member entering an `everyone` or
  `parent` group, receives it wrapped under the parent-derived enrolment key,
  alongside the `GroupInfo` it is already unwrapping
  (`specs/backend/relay/channels.md`).

Without the second path an `open` group entered by self-join would present a
lock state promising history and contain none, which was true of every channel
created after a member joined. That is the most common way anybody encounters a
channel in a workspace more than a week old, so it was the default experience
rather than an edge case.

Retaining the history key is what `open` means, and a removed member keeps
whatever it already held. That is not a new weakness: re-wrappable history is the
definition of the policy, removal protects forward secrecy rather than backward,
and the deletion note below already says so. `closed` groups have no history key,
publish no `history.publish`, and cannot acquire either later, because the field
is immutable at creation.

**`closed`.** New members see nothing before they joined. Mandatory and
unchangeable for `dm:` groups. Default for any channel created as private.

Set at group creation, immutable afterwards, shown as a lock state in the
channel header so nobody has to open settings to know which one they are in.

The honest cost of `open` as a default: a leaked invite is a leak of history,
not just of future messages. Bounded by single-use, 7-day expiry, and the
two-channel code in `specs/backend/relay/invites.md`. The alternative default
puts every new hire in a set of empty rooms, which is the failure mode that
makes people stop using the product, so this is the right trade at the stated
posture.

### Recovery access without a leaf in every group

Recovery keys (`specs/backend/relay/auth.md`) are not MLS leaves in every group.
An earlier draft made them so, and the cost compounded badly: a thirty-person
workspace carried thirty leaves that never issue a commit, in every group,
roughly doubling tree size and permanently holding back how far the group
ratchets forward. A tree full of stale leaves is a group with degraded
post-compromise security for everyone in it, not just for the stale leaves.

Instead, exactly one recovery leaf exists, in the workspace root group, per
user. For every other group, the committer emits a `recovery.wrap` event sealed
to each recovery public key entitled to it. The relay stores only the latest wrap
per (group, tag), where the tag is defined below and is not the recovery key.

A wrap carries two things, and the second one is not optional:

```
RecoveryWrap {
  group:       [32]byte
  epoch:       u64
  tag:         [32]byte      // BLAKE3(export(weald wraptag v1) || recovery_pubkey)
  ct:          bytes         // sealed { epoch_secret, group_info } to that recovery key
}
```

#### Why the tag exists, and what it is worth

An earlier draft indexed wraps by the recovery public key in the clear. A
recovery key is long-lived, one per user, and appears in every group that user
belongs to, so that index was a per-group list of stable user identifiers. A
relay holding it could count the members of every group, and could join the
lists across groups to reconstruct which groups belong to the same person. That
is the workspace's group membership graph, handed over by a mechanism nobody
was looking at, while `specs/backend/relay/wire.md` claimed on the same page
that the relay learns nothing about group membership. The claim was the thing
that was wrong, not the page it was written on, so the mechanism changes.

`tag` is derived from the group's own epoch secret, so it is unlinkable across
groups and rotates on every commit. What the relay sees is a set of opaque slots
per group that changes wholesale each epoch. It still learns how many wraps a
group carries, which is a count and not an identity, and that count is already
implied by the size of a commit.

The recovering client can recompute a tag only for groups whose epoch secret it
has, which is the wrong way round during a recovery, since the secret is inside
the wrap. Each recovery principal therefore has a **tag directory**, sealed to
that recovery key inside the workspace-root group. It maps each entitled group
to its current tag and a bounded fallback tag.

This is a two-phase cross-group handoff, not an impossible claim of atomic MLS
commits across groups. Before a non-root group commit is published, its committer
derives the next epoch's tags and writes a root-group `recovery.directory.prepare`
record containing both the current and candidate tag, bound to the target commit
hash. It then publishes the target commit and its wraps, retaining the old and
new wrap slots. Finally it writes `recovery.directory.activate`. A crash at any
point is safe: recovery tries the directory's candidate, current and fallback
tags, accepts only a wrap whose MLS `GroupInfo` validates at the stated epoch,
and never treats a missing candidate as data loss. The relay retains the prior
wrap slot for 30 days after activation; only then may it discard it.

Directory records are idempotent on `(group, target_commit_hash)` and are
encrypted per recovery principal, so the relay still sees no stable recovery
identifier or group-membership graph. A weekly health check repairs a missing
prepare or activate record, but recovery never depends on that repair: the
overlap is the availability guarantee. An absent directory entry for a group the
roster says the user belongs to remains a health-check failure exactly as a
missing wrap is (`specs/backend/relay/lifecycle.md`). The directory is a
versioned root-group document, so a root-group checkpoint manifest must retain
its current snapshot; compaction may never turn recovery into a full-history
requirement.

**`epoch_secret` is what lets a recovery key read. `group_info` is what lets it
get back in.** An earlier draft carried only the secret, which does not work: an
exported epoch secret is not MLS membership, a recovery key with no leaf cannot
produce a valid commit, and so a recovered user could decrypt a group's traffic
and never rejoin it. For `open` groups the joining device could have scraped a
`GroupInfo` from the self-join path, but `closed` groups publish none, which made
every DM permanently unreachable after a recovery. That was silent, total data
loss on the one flow whose entire purpose is not losing data.

Carrying the current `GroupInfo` inside the wrap fixes it with no new mechanism
and no new cadence: the wrap is already re-emitted on every commit, so the
`GroupInfo` in it is current by the same rule that keeps the secret current. The
replacement device external-commits into every group using the `GroupInfo` from
that group's wrap, exactly as an invitee does with an invite bundle.

Validation is the same shape as every other external commit in this design.
Receiving clients accept the commit when its `authenticated_data` names a
recovery principal that is unrevoked in the roster, when the committing device is
the single replacement device named in that principal's live recovery transaction
(`specs/backend/relay/auth.md`), and when the wrap it used was the current one.
Anything else is evicted within one epoch and alerts admins. A recovery key can
therefore re-enter only the groups it already held wraps for, which are by
definition the groups its owner already belonged to. It cannot use recovery to
reach a group it was never in.

Properties this gets right:

- The active groups ratchet normally, with only live devices and agents as
  leaves.
- Recovery restores membership of every group, because a wrap exists per group
  per current epoch and carries the `GroupInfo` needed to rejoin it.
- Removing a person removes their wraps as well as their leaves, in the same
  commit, so a departing employee's written-down phrase stops working at the
  same instant their laptop does (`specs/backend/relay/lifecycle.md`).
- A wrap is one small envelope per recovery key per epoch. At the stated posture
  that is cheaper than the leaves it replaces.

The tradeoff, stated plainly and more narrowly than an earlier draft did.
Membership comes back in full. **History does not.** A wrap carries the current
epoch secret only, so:

- In an `open` group the recovered device reads everything, because historical
  epoch secrets are re-wrappable there by design and the rejoining device
  receives them the same way any joiner does.
- In a `closed` group the recovered device reads from the epoch its wrap named
  and no earlier. For DMs, which are `closed` by construction, that means
  recovery returns the conversation but not its history.

`specs/backend/relay/auth.md` previously said a `closed` group returns everything
written after the recovery key was added. That was wrong by a wide margin and is
corrected there. The recovery summary screen names, per group, the date history
resumes from, before the user runs a search and forms their own theory about what
happened.

### Deletion

The `prunability` 1-to-4 move in `specs/backend/relay/overview.md` comes from here.

A delete is two operations: the relay drops the blob, and the group advances the
epoch so that any cached ciphertext is orphaned from a live key. Both are needed;
either alone is theatre.

What is not recoverable: copies already decrypted by a member and sitting in
their local store. No protocol fixes that, and the marketing copy must not
imply otherwise.

Second thing the copy must not imply, because it is the sharper one: in an
`open`-history group, historical epoch secrets are deliberately re-wrappable for
new joiners, so advancing the epoch does not make old content unreadable to
anyone who is still a member or who joins later. Deletion in an `open` group
means the blob is gone from the relay and from every client that honours the
tombstone. It does not mean the old key stopped existing. `closed` groups get
the stronger property. The channel header lock state already distinguishes the
two, and any description of the deletion guarantee has to say which of the two
it is describing.

Retention and compaction are specified in `specs/backend/relay/lifecycle.md`,
because dropping envelopes has to stay compatible with author chains, with
`open`-history joins, and with a customer whose bill is a function of what the
relay still holds.

## Media

Media is encrypted client-side with a random per-blob AES-256-GCM key. The blob
goes to object storage addressed by the hash of the ciphertext. The key travels
inside the MLS-encrypted envelope that references it.

Consequence: object storage holds ciphertext with no accompanying key, so the
storage tier can be a third-party S3 bucket without extending the trust
boundary. Deduplication is by ciphertext hash, so identical files uploaded by
different groups do not dedupe. Accept that.

Transfer, quotas, and how blobs are ever reclaimed given that the relay cannot
read the envelopes that reference them, are in
`specs/backend/relay/media.md`.

## Threat model

**In scope.** A malicious or compelled relay operator, including us. A
compromised object store. A passive network observer. A revoked member. A leaked
agent key.

**Out of scope, stated plainly.** A compromised member device, which by
definition holds plaintext. Traffic analysis: the relay sees group ids, message
sizes, and timing, and correlating those with a known team is not hard. Malicious
model providers: if an agent sends channel content to an inference API, that
content has left the boundary, and no transport-level encryption closes that. The client
must show, per agent, which provider its context is going to, and that UI is a
requirement of this spec rather than a nicety.

## Verification

The claim needs to be checkable, not just asserted.

- **Safety numbers.** Per group, a short authentication string derived from the
  ratchet tree, comparable out of band. Detects a relay silently inserting a
  device.
- **Membership transparency.** Every epoch change is recorded in an append-only
  log with a hash chain. Clients verify continuity on sync and warn loudly on a
  gap or fork. A relay that adds a member has to do it visibly.
- **Reproducible relay builds.** See `specs/backend/relay/server.md`.
