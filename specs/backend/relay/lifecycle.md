# Relay: lifecycle, offboarding and retention

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only: the Clerk
> production instance, Stripe live mode, the production Render environment and
> Postgres, the production R2 bucket, the published relay digest. No dev tier,
> no test mode, no staging tier, and no agent creates one. `local` and `ci` are
> not an exception because they reach no vendor at all. A gate that cannot reach
> production configuration fails; it never degrades to a mock, a stub, a fake, a
> skip or a newly created dev or staging resource.

The operations that a workspace performs on itself over years rather than
minutes: removing a person, responding to a compromised key, and keeping the
relay's storage from growing without bound.

These were the largest gap in the first pass of this spec family. Every other
document described a workspace being created and joined. None described one
being maintained, and the omissions compounded: a departing employee kept a
working connection, their recovery phrase kept working, and the relay kept
storing every envelope ever written while billing the customer for it.

## Removing a person

The single most important flow in this document, because it is the one an
enterprise buyer will ask about first and the one that has three halves that
must not be allowed to drift apart.

**One action in the client.** An admin selects a person in the member list and
chooses Remove. There is no separate revoke-devices, revoke-agents,
revoke-recovery and republish-access-set sequence for a human to get wrong.

Behind that one action, in order, atomically from the user's point of view:

1. **Enumerate.** Every device owned by the user, every agent certificate they
   issued including sub-delegated chains, and their recovery principal.
2. **Roster.** Write `revoked_at` on all of them in one `roster.revoke` event.
3. **Epochs.** Issue a `Remove` commit in every group any of those principals
   belonged to, batched into one commit per group. This rotates the epoch
   secret, and with it the retention signing key
   (`specs/backend/relay/groups.md`), so the removed party cannot unwrap the next
   `GroupInfo` and cannot external commit back in.
4. **Recovery wraps.** Delete every `recovery.wrap` sealed to the removed user's
   recovery key, and drop that user from the tag directory. Wraps are indexed by
   a blinded per-epoch tag rather than by the recovery key
   (`specs/backend/relay/groups.md`), so the deletion names tags the removing
   client computes from its own MLS state, which is also why only a member can
   perform it. The epoch rotation in step 3 makes any wrap that survives the pass
   undecryptable anyway; the deletion is belt as well as braces, and both are
   cheap. Their phrase, written on a card in a drawer, stops being a way back in
   at the same moment their laptop does.
5. **Access set.** Publish a new access set without their entries, including
   their recovery principal in `recovery`, so a removed user cannot spend the
   constrained recovery rotation to put a device back on the relay
   (`specs/backend/relay/wire.md`). The relay closes their open connections
   within seconds and refuses new ones, so they stop being able to fetch even
   ciphertext they cannot read.

   **Provisional grants die here too.** A person removed days after joining may
   still have a live invite behind them, and a grant derived from that invite is
   a working connection credential. The removal revokes every invite record
   naming them, and the relay independently voids any grant for a hash that a
   previous accepted access set carried and this one does not. Two mechanisms
   rather than one, because the first depends on the client enumerating
   correctly and the second does not depend on the client at all. Without them,
   the fastest offboarding in the product, removing somebody in their first
   week, was the one that left them connected.
6. **Receipt.** Write a removal record to the membership transparency log and
   show the admin a summary: which groups were rotated, how many devices and
   agents were revoked, and the timestamp. Exportable, because this is the
   artifact an auditor asks for.

The client persists this as a durable `RemovalOperation` before step 1, with a
unique id, the authorization-operation head it was based on, the complete target
principal set, and a receipt for every group and relay-side access-set update.
Each step is idempotent; after a crash or reconnect the client resumes the same
operation, never starts a second removal against a newer roster by accident. If
the authorization head changed before the first MLS commit, the operation pauses
and shows the admin the intervening change for explicit reapproval. The receipt
is emitted only after every scoped group has rotated and the access-set
compare-and-swap has succeeded.

**What removal does not do**, stated in the confirmation dialog in one sentence
before the admin commits: it cannot reach content the person already decrypted
onto their own machine. Every honest system has this boundary. Pretending
otherwise in the UI is how a security claim becomes a lie in the one moment a
customer is paying closest attention.

The order above is load-bearing rather than incidental, because most groups are
self-join (`specs/backend/relay/channels.md`). Roster revocation lands first, so
every client rejects a self-join from the removed principal from that moment;
the epoch rotations then kill the enrolment keys it retained. Reversing the two
would leave a window in which a removed laptop rejoins every `everyone` group on
its next sync.

**Partial removal.** Removing someone from one channel rather than the whole
workspace runs the same sequence scoped to that channel's group. The access set
is unchanged, because they remain a member of the workspace. It requires the
channel to be `explicit`: a `parent` channel has no partial removal, because the
workspace roster is its entitlement and the person would rejoin. The client says
so in the scope picker at channel creation, which is the only moment the
choice can still be made cheaply (`specs/backend/relay/channels.md`).

Removing someone from one **project** is a full removal from that workspace,
because a workspace is one project. Somebody who works on two of a team's
projects is in two workspaces and is offboarded from each separately
(`specs/backend/relay/multi-workspace.md`).

### If the removed person is the last admin

Blocked, per `specs/backend/relay/auth.md`. The control is disabled with an
explanation rather than failing afterwards, and the fix offered inline is
"promote someone first", with the promote flow one click away.

## Key compromise

Distinct from removal, because the person stays and their key does not.

**A device is lost or stolen.** The user, from any other device of theirs,
chooses Revoke device. Same machinery as removal, scoped to one device. If they
have no other device, this is a recovery-phrase flow: recover onto a new device,
which revokes the old one as its last step
(`specs/backend/relay/auth.md`).

**An agent key leaks.** Revoke the certificate and evict the leaf, which the
epoch steward does automatically on the next pass
(`specs/backend/relay/identity.md`). The admin panel offers "revoke all
certificates issued by this device" as one action, because a compromised laptop
means every agent it delegated to is suspect.

**A recovery phrase leaks.** Rotate from settings. The old recovery principal is
revoked, a new phrase is generated and confirmed, and every group re-wraps to
the new key.

**The trust root's device is compromised.** The worst case, and it needs no
special mechanism: any other admin removes it like any other device. This is why
the client nags a solo admin to promote a second one, once, after the first
other person joins. Nagging twice would be dishonest about how much we can help
if they decline.

### Detection

Compromise you do not know about is the case that matters, so three surfaces
report it without anybody going looking:

- **Split-view warning** from head attestation, raised on disagreement and also
  on the silence that a withholding relay would produce instead of disagreement
  (`specs/backend/relay/wire.md`).
- **Recovery rotation or rejected access-set publication** by a probationary
  authorizer. The former is an actionable approval request and the latter is an
  attempted takeover; both notify every pre-existing admin naming the recovery
  principal spent.
- **Transparency log gap or fork** on sync (`specs/backend/relay/groups.md`).
- **Retention fork** when two successor controls exist for one epoch, which is
  the signature of a removed member trying to capture the deletion authority on
  their way out (`specs/backend/relay/media.md`).
- **Unexpected roster change** notification: any admission or revocation the
  local user did not perform raises a notification naming the acting device.
  Quiet by default is wrong here.

## Retention and compaction

The relay cannot read content, therefore it cannot decide what is safe to drop,
therefore compaction is client-driven. That is unavoidable. What is avoidable is
what an earlier draft left: no automation, so nothing ever pruned, on a product
priced by storage.

### Checkpoints

A client holding full history for a group periodically writes a `checkpoint`
payload. A checkpoint is a signed, complete replacement manifest, not an
assertion that some snapshot happens to exist:

```
Checkpoint {
  group, barrier: [{ author, ctr, hash }],
  index_snapshot_hash,
  documents: [{ document_id, snapshot_hash, automerge_heads }],
  manifest_hash, signer, sig
}
```

`documents` is the complete document inventory at the barrier, including every
daily chat shard; `index_snapshot_hash` is the snapshot that discovers that
inventory. The writer proves locally that each listed snapshot applies to the
named heads and captures all changes at or below the author barriers before it
signs. Receivers verify the signature, the index inventory, every referenced
snapshot hash and head, and reject a checkpoint that omits a known document or
has a snapshot above/below its claimed barrier. It is signed under the group's
epoch-derived retention signing key, so only a current member can write one.

A checkpoint is what makes dropping envelopes safe against the author chains in
`specs/backend/relay/wire.md`. Clients verify chain continuity **above** the
newest checkpoint they trust, and verify the checkpoint's signature rather than
replaying beneath it. Without this, compaction and tamper detection are
mutually exclusive, which is the trap here.

### Dropping

The steward may then send a `drop_before` instruction to the relay, signed with
the relay-verifiable retention signing key and bound to an active
threshold-authorized `RetentionPolicy` (`specs/backend/relay/media.md`), naming
a group and a checkpoint.

**The instruction does not name a barrier.** It names the checkpoint, and the
relay uses that checkpoint envelope's own sequence number as the barrier. A
client cannot know that number: `seq` is assigned by the relay on accept and is
in no answer a client holds, so a client naming one would be guessing at the
value that decides how much history goes. Too low drops nothing; too high asks
for history the checkpoint does not replace. The relay must already be holding
the checkpoint envelope before it deletes anything, so the number is in front of
it, and deriving it makes the dangerous instruction impossible to express rather
than merely refused. A one-off compact-now request instead carries a due
`RetentionDestruction` authorization. The instruction includes the checkpoint's
manifest hash and every required snapshot hash. The relay verifies the
retention-key transition chain, the authorization, and that all named snapshot
envelopes are present and retained before deleting anything below the barrier;
it keeps the checkpoint and its snapshots forever as the anchor. A relay rejects
a drop with an incomplete manifest or missing authorization rather than guessing
which envelopes are safe to lose.

A `drop_before` is subject to the same successor-race rules as a media manifest,
and a frozen retention chain freezes text compaction too. A group whose control
chain is contested stops dropping anything until a member resolves the conflict.
The failure mode is a storage bill, which is recoverable, rather than history a
departing member arranged to have deleted, which is not.

Automation, so this is not a chore anybody has to remember:

- The epoch steward emits a checkpoint per group every 512 changes or 7 days,
  whichever first, and issues the matching `drop_before` only for material older
  than the group's already-authorized retention policy. It cannot turn a new
  checkpoint into an unsupervised deletion authority.
- Default retention window is **unlimited for text and 180 days for media**,
  because media is what actually fills a disk and text is what people search.
  Both configurable per group by an admin, with the storage impact of the change
  shown as a number before it is applied.
- A workspace approaching its plan's storage limit gets one notification to
  admins with a one-click "compact now" that runs the pass immediately, and a
  clear statement of what will be deleted.

### Interaction with `open` history

Dropping envelopes below a checkpoint means a future joiner to an `open` group
reads history from the snapshot, not from the original changes. That is the
correct trade and it is invisible in the UI, because the snapshot carries the
same content. What is visible: a joiner cannot verify author chains beneath a
checkpoint they were not present for, and the member list shows exactly that,
as "history verified from <date>".

### What the relay never does

The relay never drops an envelope on its own initiative, never expires by
policy, and has no retention configuration that acts without a signed
instruction. `WEALD_RELAY_RETENTION_DAYS` sets a warning threshold, not a
deletion. An operator who could quietly delete a customer's history would be an
operator with a power the trust boundary says they do not have.

## Ongoing health

The client runs a weekly self-check per workspace and surfaces failures in the
encryption panel:

| Check | Failure means |
| --- | --- |
| Recovery wrap present, and carrying a current `GroupInfo`, for every group the user belongs to | Recovery would come back unable to rejoin that group at all, not merely short of history. Repaired on next commit. |
| Recovery tag directory has a valid current-or-fallback slot for every group the user belongs to | A cross-group commit may have stopped mid-handoff. The overlap makes recovery safe now; the next connected committer repairs the directory (`specs/backend/relay/groups.md`). |
| `history.publish` present and current for every `open` group the user is in | A self-joiner would enter a channel whose lock state promises history and find it empty (`specs/backend/relay/channels.md`). |
| Head attestations received from every member the client is also receiving envelopes from | A relay withholding attestations rather than forging them. Escalates to a split-view warning (`specs/backend/relay/wire.md`). |
| No unresolved probationary authorizer | A recovery rotation completed and needs explicit confirmation by a pre-existing authorizer. It never clears itself; the panel offers approve or reject. |
| No frozen retention chain | A contested successor control is blocking compaction and needs a member to resolve it. |
| Access set version fresher than 7 days | Admin devices have all been offline. Republished automatically on next admin connect. |
| No expired agent leaves outstanding | Eviction pass has not run. Steward takeover applies. |
| Transparency log continuous to head | Escalates to a split-view warning. |
| At least two admin devices, or a registered recovery quorum | A phrase-only recovery in this workspace would leave a device that can never clear probation and therefore can never remove anybody again (`specs/backend/relay/wire.md`). Actionable, with pair-a-device and register-a-quorum both one click away. Shown until resolved or explicitly dismissed once. |
| Storage against plan | Advisory until 80 percent, then actionable with compact-now. |

Each of these is a thing that silently degrades over months and none of them
would have been noticed by a user, which is the definition of the class of bug
that makes an infrastructure product lose trust in year two rather than week
one.
