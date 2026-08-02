# Relay: groups people actually get put in

`specs/backend/relay/groups.md` specifies MLS group cryptography. It does not say
which groups exist, who is in them, or how somebody gets added to a group created
after they joined the workspace. That gap is the whole "send your first message"
path, and left open it reintroduces the waiting-for-a-teammate state that
external commits were adopted to remove (`specs/backend/relay/invites.md`).

This spec closes it. Two rules carry the weight:

1. **Every workspace ships with default channels.** A workspace is one project
   (`specs/backend/relay/multi-workspace.md`), so this is one set of defaults per
   project. Nobody ever faces an empty sidebar and a "create a channel" button as
   their first act.
2. **Most groups are self-join.** Membership is derived from the roster, not
   granted by a human, and a member adds itself by external commit against a
   standing `GroupInfo`. No online teammate, no approval, no queue.

## Group policy

Every group carries a policy record, set at creation, stored in the roster
document, and signed as a `RosterOperation` (`specs/backend/relay/identity.md`)
because it is authorization state and must not merge last-writer-wins.

```
GroupPolicy {
  group:      [32]byte          // group id
  kind:       "ws" | "chan" | "dm"
  parent:     [32]byte | null   // the workspace root for a channel, null otherwise
  admission:  "everyone" | "parent" | "explicit"
  history:    "open" | "closed"
  default:    bool              // created automatically, undeletable
  created_by: [32]byte
  created_at: u64
}
```

`admission` is the field that removes the human from the loop.

| `admission` | Entitled set | How a principal gets in |
| --- | --- | --- |
| `everyone` | Every non-revoked **device** in the workspace roster, plus any **agent** named by a live delegation certificate scoped to this group | Devices self-join by external commit. Agents are added by the issuing device, never by self-join |
| `parent` | Every **device** already in the `parent` workspace root group, plus agents on the same terms | Same |
| `explicit` | Only principals named in the group's member list | Add commit by a current member |

`admission` is immutable after creation, exactly like `history`. Changing who is
entitled to a group is a new group, not an edit. The two fields together are the
lock state shown in the channel header, so the answer to "who can read this" is
one glance, never a settings panel.

Agents are deliberately excluded from the **derived** half of both admission
sets. A delegation certificate is scoped, whereas `everyone` and `parent` are
not; treating an agent as an ordinary self-joining member would silently grant
it every normal channel in the workspace. When a human approves an agent
session, the app issues one batched `Add` for exactly the groups named by the
certificate and records those leaves as explicit agent members. Renewal within
the same scope does not change membership or prompt again. Widening a scope is
one visible approval followed by the matching additions. Clients reject an agent
external commit to a derived-admission group even if that agent has a valid
roster entry. This keeps the normal human join path automatic while making the
agent's MLS read scope exactly match the scope shown in its approval sheet.

Being excluded from the derived set is not the same as having no way in, and an
earlier version of this page collapsed the two. `everyone` and `parent` listed
self-join as the *only* path, and the validation rule below required every
committing principal to be inside the entitled set, so an agent leaf added to
the workspace root group by its own issuing device, which is the path
`specs/backend/relay/agents.md` requires and the only way an agent reads
anything at all, failed validation on every receiving client and was evicted
within one epoch. The highest-volume writer in the system could not be admitted
to the group it writes to. The entitled set therefore includes certificate-named
agents explicitly, and the two ways in are distinguished by principal kind
rather than left to be inferred.

Legal combinations, and the only ones a client may create:

| `kind` | `admission` | `history` |
| --- | --- | --- |
| `ws` | `everyone` | `open` |
| `chan` | `parent` or `explicit` | `open` if `parent`, `closed` if `explicit` |
| `dm` | `explicit` | `closed` |

There is no project group, because the workspace root **is** the project: it
carries the roster, the tickets, the board state and the project documents.
Somebody who should not see the project at all is not in the workspace at all,
which is a cleaner boundary than a scoped subgroup and is the reason the
intermediate layer was removed.

An `explicit` channel is therefore **not** the contractor case and is not an
invite scope, which this page previously implied and which is not constructible.
`explicit` forces `history: closed` in the legal-combination table above, and
`closed` groups are never offered as invite scopes
(`specs/backend/relay/invites.md`), so "scoped at invite time" named a state the
scope picker cannot produce. `explicit` is the private-channel case for people
who are already in the workspace: a member is added to it by a current member,
after they arrive, and it is the only kind of channel anybody can be removed from
without being removed from the project. A genuine contractor gets their own
workspace, because a workspace is a project and that is the boundary that
actually holds.

## Default channels

Created by the client, automatically, in the same transaction as the thing they
belong to. Not a template, not a wizard step, not skippable.

**On workspace creation** (bootstrap, `specs/backend/relay/invites.md`), the
trust root creates:

| Group | Policy | Purpose |
| --- | --- | --- |
| `ws:<workspace>` | `everyone`, `open`, default | Roster, access set, tickets, board state, project documents. Not a chat surface. |
| `chan:ws/general` | `parent`, `open`, default | The everybody channel. Where a new joiner's first message lands. |
| `chan:ws/activity` | `parent`, `open`, default | Agent and CI output, ticket transitions, git status. Muted by default. |

Binding the local project to the workspace
(`specs/backend/hosted-service.md` step 7) creates no groups. The
workspace root already is the project group, so binding writes the `workspace`
field into `.weald` and flips the transport, and the default channels above are
the project's channels.

Nothing else is created automatically. Three surfaces per workspace is the
smallest set where the app is usable on arrival and the largest set that does not
read as clutter.

Default channels cannot be deleted or archived while their parent exists, because
a workspace whose only channel has been deleted has no place to put a first
message and no obvious repair. They can be muted, renamed and reordered.

`chan:ws/activity` exists so that agent chatter, which is the highest-volume
writer at this posture (`specs/backend/relay/agents.md`), has a home that is not
the channel humans read. Routing it into `general` by default is how a team turns
notifications off in week one.

## Self-join

The mechanism that makes `everyone` and `parent` groups work without anybody
being awake.

### Standing GroupInfo

Every self-join group publishes `groupinfo.publish` (kind `0x0060`,
`specs/backend/relay/wire.md`) on every commit, wrapped under the **enrolment
key** exported from its parent group's current epoch secret
(`specs/backend/relay/groups.md`). Parent means the workspace root group, which
is the only parent there is.

Never the target group's own secret. A principal joining `chan:ws/general` for
the first time holds no secret of that group, which is the exact reason the
earlier shared-publication-key design was both unusable here and unsafe: it was
retainable by a member the target group had just removed. Deriving from the
parent instead means the key a self-joiner uses is one the roster already
entitles it to, and removal from the workspace rotates that parent epoch in the
same pass that revokes the roster entry.

`parent` therefore chains exactly one level and no further. A channel's parent is
always the workspace root, and the root's entitlement is the workspace roster.
One level of derivation, no recursion, no group whose enrolment depends on a
group its joiner has not already entered. Collapsing the project layer into the
root is what removed the second level.

Distinct from the per-invite `update_pub` bundles in
`specs/backend/relay/invites.md`, and both are needed. An invitee is outside the
workspace and holds no epoch key at all, so it needs a bundle sealed to a key
only it holds, refreshed by whoever commits. An existing member already holds the
parent epoch secret, so it needs nothing per-principal and no member has to do
anything on its behalf. That difference is the whole reason self-join has no
teammate in the loop and invites do.

### The join

1. Client reads the roster, computes the set of groups it is entitled to and not
   yet a member of. Runs on every roster change, every connect, and after any
   invite redemption.
2. For each, fetches the latest `groupinfo.publish`, unwraps it with the
   publication key derived from the workspace or parent epoch secret. For an
   `open` group it fetches `history.publish` in the same round trip and unwraps
   the group's history key from it under the same enrolment key, which is what
   gives a self-joiner the history an invitee gets from a bundle
   (`specs/backend/relay/groups.md`).
3. Performs an external commit, embedding in `authenticated_data` its roster
   entry reference and the `GroupPolicy` hash it joined under.
4. Emits `recovery.wrap` for its own recovery key in the same commit, so recovery
   coverage is never behind membership (`specs/backend/relay/groups.md`).

Every receiving client validates the commit against the policy: the joiner is in
the roster, unrevoked, and inside the entitled set for that `admission`. A commit
that fails validation is evicted within one epoch and raises the same alert as a
forged invite (`specs/backend/relay/invites.md`). Detect-and-evict, one epoch,
same window and same honesty as every other external commit in this design.

An agent leaf is validated on the other path and against a different test: it
arrives as an `Add` inside a commit issued by a device, and receiving clients
check that the adding device issued a live, unexpired delegation certificate
naming that agent and that group (`specs/backend/relay/identity.md`). An agent
`Add` by a device that did not issue the certificate fails, and so does an agent
external commit to any group whatever. The epoch steward evicts the leaf when
the certificate expires, which is the same rule read from the other end.

### What this fixes

Sam joins Monday with `chan:ws/general` in the invite scopes. Dana creates
`chan:design` on Tuesday, a `parent` channel of the workspace Sam is in. Sam's
client sees the new `GroupPolicy` in the roster on next sync and joins itself,
whether or not Dana is still online, whether or not Sam is online at the time.
Nobody waits for anybody. Under the previous design this path had no owner at
all.

It also fixes the case that was quietly worse, because it is the common one.
`chan:design` usually exists **before** Sam arrives and is not in Sam's invite
scopes, since scopes name what an admin picked rather than every channel the
workspace contains. Self-join used to carry a `GroupInfo` and nothing else, so Sam
entered an `open` channel, saw a lock state promising past messages, and found an
empty room. In a workspace older than a week that was the default experience of
joining a channel rather than an edge case. The history key travels the same path
as the `GroupInfo` now, so an `open` group entered by self-join is populated on
arrival exactly as an invited one is, and the only groups that are ever empty for
a joiner are the ones whose policy says so.

## Explicit groups and the pending add

`explicit` groups are the only ones that need a member to act, and that is
correct: a private channel where anybody entitled can add themselves is not a
private channel.

1. A current member picks principals and issues one batched `Add` plus `Commit`.
2. If a target device has no key package left (`specs/backend/relay/groups.md`),
   the add is recorded as a **pending add** in the group policy record rather
   than failing. The adder's job is done and the UI says so.
3. Any current member's client completes outstanding pending adds on connect,
   which is the same self-healing pattern as invite bundle refresh.
4. The added principal is notified on arrival
   (`specs/backend/relay/notifications.md`).

The member list shows pending adds as "waiting for that device to check in" with
the date, so an add that cannot complete for a week is visible rather than
silently absent.

DMs are `explicit` by construction and follow this path: the first message to a
new counterparty creates the group and adds every device that person holds. Its
id is derived from the two user ids rather than from any key, and simultaneous
first messages resolve through the linear `RosterOperation` head rather than
producing two groups sharing one id, per `specs/backend/relay/groups.md`. The
losing client adopts the winning policy and re-sends. Neither person sees
anything other than their message arriving.

## Ordering at bootstrap and at join

Group creation and joining have a strict order, because the publication key for
each layer is derived from the layer above it.

**Bootstrap.** Workspace root group, then its access set
(`specs/backend/relay/wire.md`), then `chan:ws/general` and `chan:ws/activity`.
The trust root is the sole member of all three and issues the creating commits
itself.

**A partial bootstrap is resumed, not torn down.** An earlier version of this
rule said a workspace reaching `active` with fewer than three groups is a failed
provision and is destroyed. That is the wrong remedy and an expensive one: the
seat is consumed and the genesis private key is destroyed at acceptance of the
access set (`specs/backend/relay/invites.md`), which happens *before* the two
channel commits, so a client that crashes in that window has a valid workspace
it can finish and a bootstrap invite it can never use again. Teardown there
turns a resumable hiccup into a reprovision, a new workspace id and a support
conversation, on the buyer's first two minutes with the product.

The trust root is the sole member of both channels and needs no coordination to
create them, so creation is idempotent on the deterministic group ids and is
retried on every launch until it completes. The client treats a workspace
missing a default channel as incomplete setup, finishes it silently, and only
then reports the workspace ready. The completion check in
`specs/backend/hosted-service.md`, a visible `#general` and an enabled
Send button, is what gates "ready" and it is a check the client can satisfy by
acting rather than by giving up.

Teardown per `specs/backend/hosted-service.md` remains correct for the case
it was written for: a provision where no trust root was ever admitted, meaning
the genesis key is intact and nothing has been consumed.

**Join.** Every non-bootstrap invite includes the workspace root as a mandatory,
non-removable scope, even when the picker shows only chat channels. The joiner
first enters that root by external commit against its per-invite bundle. Then it
self-joins its `parent` channels. A root group has no parent, so it cannot be
self-joined: trying to derive the root enrolment key from the root's own epoch
secret would be circular and would strand a new joiner before their first
message. Each step's key material comes from the step before it, so this is a
dependency order rather than a preference.

A joiner therefore lands in `chan:ws/general` and every `parent` channel in its
invite scopes, populated with history, within the same seconds the join
completes. That is the first-message path and it involves no other human.

## Interaction with removal

`specs/backend/relay/lifecycle.md` removes a person from every group they belong
to in one batched pass. Self-join makes that pass load-bearing in a way it was
not before: a removed principal that is still in the roster would immediately
rejoin every `everyone` group. So the ordering in that spec is mandatory, not
incidental. The roster revocation lands **before** the epoch rotations, every
client validates self-joins against the roster, and the rotated publication key
means a removed principal cannot unwrap the next `GroupInfo` even if it ignores
its own roster state.

Partial removal, meaning removing someone from one channel rather than the
workspace, requires the channel to be `explicit`. A person cannot be removed from
a `parent` channel while remaining in the workspace, because they would rejoin on
their next sync. The client states this at channel creation, in the scope picker,
in one sentence: "anyone in this workspace can join this channel". A team that
needs to remove people from individual channels creates them `explicit`, and that
is a decision made once at creation rather than discovered during an offboarding.

Removing someone from one **project** is removing them from that workspace, which
is the ordinary path in `specs/backend/relay/lifecycle.md`. Because a workspace is
a project, a contractor working on one of three projects was never in the other
two rosters to begin with.

## Limits

| Limit | Value | Why |
| --- | --- | --- |
| Groups per workspace, meaning per project | 512 | Bounded client MLS state, roughly 4 KB plus 200 bytes per member each. |
| Self-join commits per principal per hour | 32 | A client loop cannot storm the epoch. |
| Pending adds per group | 64 | Beyond this the group is misconfigured, not unlucky. |
| Default channels | 3 per workspace, meaning 3 per project | Fixed. Not configurable. |
