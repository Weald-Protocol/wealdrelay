# Relay: accounts, authentication and recovery

There is no login. There is no password. There is no account record on the
relay. Authentication is possession of a device private key, and everything on
this page is the human-facing machinery around that fact.

This spec owns the flows. `specs/backend/relay/identity.md` owns the data structures
they produce (roster entries, delegation certificates) and
`specs/backend/relay/wire.md` owns the `AUTH` frame. Where they overlap, this document
is the authority on sequence and UI, those documents are the authority on
format.

## Two layers people conflate

**Connection auth.** On `CONNECT` the relay issues a challenge and the client
signs it with a device key (or, only for the recovery flow below, a recovery
key). The relay checks the signing key against the
published access set (`specs/backend/relay/wire.md`), which is the one piece of
derived membership data it holds. This grants a socket and a quota. It grants no
data, and it tells the relay nothing about which groups the device belongs to.

**Data access.** Gated entirely by holding MLS keys for a group
(`specs/backend/relay/groups.md`). The relay does not enforce it and cannot, because
enforcement requires knowing the membership graph, which is the knowledge the
whole design denies it. A non-member may subscribe to any group id and will
receive ciphertext it cannot read.

Consequence worth stating in security reviews: an attacker who completely
defeats connection auth gains the ability to consume bandwidth and to hoard
ciphertext they cannot read, and nothing else.

Consequence worth stating to buyers, which is different: because the access set
exists, removing someone actually disconnects them. Without it, connection auth
could not tell a member from a stranger and a revoked device would have kept
pulling ciphertext indefinitely. That was a real hole in an earlier draft and it
is closed in `specs/backend/relay/wire.md`.

## The first account is the admin

The first device enrolled in a workspace is the trust root and is permanently an
administrator. This is not a default that can be changed during setup and there
is no separate "make me an admin" step.

The trust root self-admits its own roster entry, creates the workspace root MLS
group, and holds the full capability set including `admit`, `roster.revoke` and
`admin`. Every later roster entry chains to it.

`admin` is a capability like any other in `specs/backend/relay/identity.md`, with three
rules specific to it:

1. Only a device holding `admin` may grant `admin`.
2. `admin` is never delegatable to an agent. Neither are `admit` or
   `roster.revoke`. An agent cannot expand the trust boundary it lives inside.
3. **A workspace must always have at least one non-revoked admin device.** The
   last admin cannot be revoked and cannot revoke itself. Transferring out means
   granting `admin` to another device first, which the client enforces by
   disabling the revoke control with an explanation rather than failing after
   the fact.

Rule 3 is what makes the trust root safe to hard-code. An organisation whose
founder leaves is not stuck, because the founder can promote before departing,
but nobody can accidentally orphan a workspace with one wrong tap.

## Recovery phrase is mandatory

Generated during first-device setup, before the workspace exists. Not skippable,
not deferrable to settings, no dismiss control.

- 24 words, BIP39 wordlist, 256 bits of entropy, generated on-device.
- Derives an Ed25519 **recovery keypair**, admitted to the roster as a principal
  of kind `recovery` owned by the creating user.
- The recovery key is an MLS leaf in the workspace root group. Every other group
  seals its current epoch secret to the recovery key as a `recovery.wrap` event
  on every commit (`specs/backend/relay/groups.md`), which keeps recovery current
  without filling every ratchet tree with leaves that never ratchet. A recovery
  key that drifts out of date is worse than none, because it produces a recovery
  that appears to succeed and returns an empty workspace, so the client treats a
  missing wrap for any group the user belongs to as a health warning and repairs
  it on next commit.
- The recovery principal holds `admin`. Recovering must be able to restore
  administration, or a solo user recovers into a workspace they cannot manage.
- Confirmation step: the user re-enters three words chosen at random by
  position. This is the only friction on the screen and it stays.
- The phrase is scoped to one workspace. A person in three workspaces holds
  three phrases, which is a real UX cost and is handled in
  `specs/backend/relay/multi-workspace.md`.

We never see the phrase, the words never leave the device, and there is no
escrow, no operator reset and no support-side override. Support cannot help and
the documentation says so in those words.

### The tradeoff, stated honestly

A recovery key never issues a normal commit, so it never ratchets forward and
does not get post-compromise security the way an active device does. A phrase that leaks
grants access from the moment of the leak until it is rotated. Confining the
leaf to the workspace root group and reaching every other group through wraps
means this weakness no longer degrades the ratchet properties of the groups
people actually work in, but it does not remove the weakness itself.

Two mitigations, both required:

- **Rotate on use.** After a successful recovery the phrase has been typed into
  a machine and is considered spent. The client immediately generates a new
  phrase, adds the new recovery key, removes the old leaf, and forces the same
  confirmation step. Recovery is not complete until this finishes.
- **Rotate on demand,** from settings, at any time, with the same flow.

### The one thing a phrase alone cannot restore

A phrase restores a user's work. It does not restore unrestricted
administration, because the device it introduces is probationary until a
pre-existing authorizer or a registered recovery quorum confirms it
(`specs/backend/relay/wire.md`). A workspace with a second admin never notices
this. A workspace with exactly one admin and no quorum has nobody who can ever
confirm, so a phrase-only recovery there leaves a device that can read, write
and drop its own lost devices but can never remove anyone again.

That is a real and permanent outcome, so it is a decision taken while things
are calm rather than a discovery made on the worst day:

- **At first-device setup, on the screen immediately after enrollment lands**,
  which is the first moment a roster exists to write to and therefore the
  earliest this can be asked at all, the client asks for one of two things and
  does not offer a third: pair a second
  admin device, or register a recovery quorum by entering `m` of `n` public
  keys, which a person can generate from another Weald install or hand to a
  co-founder. Skipping is allowed and is a single explicit screen that says
  what is being given up in one sentence: if you lose this laptop and this is
  still your only admin, your phrase brings your work back and does not bring
  back the ability to remove people.
- **The prompt returns once** when the first other person joins
  (`specs/backend/hosted-service.md`), and after that only through the
  weekly health check (`specs/backend/relay/lifecycle.md`), which lists it as
  an open item with a one-click fix rather than nagging.
- **A quorum key never reads anything.** It holds no epoch secret, no wrap and
  no roster write. Its entire power is confirming that a recovery was
  legitimate, which is what makes it safe to give to somebody you would not add
  to the workspace.

## Flow: first user, self-host

1. Operator stands up the relay per `specs/backend/relay/server.md`. On first
   run it generates a single-use **genesis key**, prints a bootstrap invite link,
   a 12-character code and the genesis key fingerprint, and destroys the genesis
   private key the moment the invite is redeemed. This is the same invite
   primitive as `specs/backend/relay/invites.md`, with no scopes and `admin` in
   its caps, so there is one enrollment path in the codebase rather than two.
   Expiry is 24 hours.
2. User opens the URL. It deep-links into the app via the `weald://` scheme.
3. App generates a device keypair in the Secure Enclave.
4. App asks for a display name. This is the only field collected. No email, no
   password, no username uniqueness check, because handles are per-workspace and
   come from the roster.
5. Recovery phrase generated, shown, confirmed.
6. Device self-admits as trust root and admin, creates the workspace root group,
   adds the recovery leaf.

Two screens. Faster than any email-and-password signup, and the recovery step is
the only reason it is two rather than one.

## Flow: first user, hosted

Identical from step 2 onward. The difference is upstream and is deliberately
quarantined.

1. `weald.team/start` signs the buyer into Clerk, creates or selects a **billing
   account**, then opens Stripe Checkout for payment. The account is not a
   workspace user identity.
2. We provision a relay instance. The bootstrap invite link renders on the
   post-checkout page; the 12-character code is emailed to the verified Clerk email
   of the owner who started Checkout, rather than a mutable invoice address.
   The split protects a forwarded link but is not an independent defense against
   a compromised control plane; the client hard-fail and genesis evidence carry
   that threat model. The link is valid for 24 hours, because the buyer has a
   notarized DMG to download first and a 15-minute window created the exact
   failure it was meant to prevent.
3. Everything after this is the self-host flow, including the client's hard
   check that it became the trust root
   (`specs/backend/hosted-service.md`).

The billing record knows an email address and an instance. It never learns a
device key, never joins a group, and never appears in the roster. We cannot
enumerate the humans in a workspace we host from the billing record alone.

## Flow: additional device for an existing user

Pairing, not a credential.

1. New device generates a keypair and displays a short authentication string.
2. An existing device of the same user scans or reads it and verifies.
3. Existing device signs a roster entry and issues MLS `Add` plus `Commit` for
   every group the user belongs to.
4. Epochs advance. New device receives the current epoch key.

Whether the new device can read history is the history policy question, answered
per group in `specs/backend/relay/groups.md` and not here.

## Flow: a new human joins

Full design in `specs/backend/relay/invites.md`. Summary, because it differs from what
this document originally specified:

1. An admin issues an invite. Their client uploads a signed authorization plus
   an encrypted `GroupInfo` per scope, and displays a 12-character code once.
2. The link goes by email. The code goes by whatever channel the admin already
   uses. Two channels, deliberately: an attacker holding the mailbox cannot
   join.
3. The joiner clicks, lands on a static page served by the relay itself, gets
   the app, and deep links in.
4. Device key, display name, recovery phrase. Mandatory, unchanged.
5. The client performs an **MLS external commit** (RFC 9420) into each scoped
   group. No existing member participates.

There is no waiting state and no approval queue. An earlier draft of this spec
required an online member to issue the `Add` and `Commit`, and produced an
unbounded "waiting for a teammate" state on a new user's first screen. External
commits remove it.

The tradeoff moves rather than disappearing: the joiner adds itself, so
validation is detect-and-evict within one epoch rather than gated up front. The
12-character code also replaces the forced post-join safety-number comparison this
document previously required, folding that verification into the one message the
admin was already sending. Both are covered in `specs/backend/relay/invites.md`.

## Flow: recovery

1. User selects "restore from recovery phrase" on a fresh install.
2. Enters 24 words. App derives the recovery key and connects to the relay,
   whose hostname is not in the phrase, is not derivable from it, and must come
   from somewhere else.

   Naming that somewhere else is load-bearing rather than an implementation
   detail, because the person most likely to need it is a solo owner whose only
   laptop is gone, which is also the person least likely to be holding the
   exported workspace card. Three sources, in the order the restore screen
   offers them: the hostname typed directly, if they know it; a previously
   exported workspace card or recovery card
   (`specs/backend/relay/multi-workspace.md`); or, on the hosted tier, the
   control-plane dashboard, which lists every instance on the billing account
   against a Clerk login that is recoverable by ordinary email means
   (`specs/backend/hosted-service.md`).

   The third source is why the hosted tier is not worse than self-host here, and
   it costs nothing against the trust model: an instance hostname is control
   plane data we already hold and have always held, it is public in DNS, and it
   grants nothing on its own. Knowing where a relay lives has never been the
   secret. The restore screen says which of the three the user is using, and the
   dashboard's instance list is labelled as the answer to "I lost the laptop"
   rather than left to be inferred from a billing page.
3. Recovery key decrypts the workspace root group, reads the roster, and
   enumerates group membership. That group's wrap also carries the **tag
   directory**, naming every group the user belongs to and the blinded tag its
   wrap is stored under, which is how a recovering device locates wraps that are
   deliberately not indexed by its recovery key
   (`specs/backend/relay/groups.md`). For every other group it fetches that
   group's latest `recovery.wrap`, which carries both the current epoch secret
   and the current `GroupInfo`. The second half is what
   makes rejoining possible: an epoch secret decrypts traffic but is not
   membership, and without a `GroupInfo` the replacement device could read a
   `closed` group forever and never be in it.
4. The client opens a **recovery transaction**, authenticated by the recovery
   key and bound to one freshly generated replacement device public key. The
   replacement device enters each group by external commit against the
   `GroupInfo` from that group's wrap, naming the recovery principal in
   `authenticated_data` so every other member can validate it. The only
   permitted writes are: add that device to the roster and required MLS groups;
   add and confirm a newly generated recovery key; revoke the spent recovery
   key; and, if selected by the user, revoke the lost-device set. The transaction
   is idempotent on its nonce and expires in ten minutes.

   **Which frames the connection permits, enumerated, because the earlier
   phrasing forbade the transaction's own traffic.** That phrasing said the relay
   permits "no `SUB`, normal `SEND`, invite, or delegation frames", while step 5
   requires the replacement device to external-commit into every recovered group
   and emit a `recovery.wrap` for each, all of which are `SEND`. Nothing defined
   what made a `SEND` normal, so the flow contradicted its own transport rule and
   an implementer had no way to resolve it in favour of anything.

   The connection is scoped by payload kind rather than by frame type, which is
   the distinction that was missing:

   - `AUTH` by the recovery key, then by the replacement device once (a) below
     has been accepted. Both keys are usable on the one connection, and the
     relay is told which is signing what.
   - `SUB` **is permitted**, restricted to the groups named in the recovery
     principal's tag directory. The replacement device cannot fetch the wraps it
     needs without it, and those are groups its owner already belonged to.
   - `SEND` is permitted, to those same groups. It carries the MLS external
     commits entering them, a `recovery.wrap` (`0x0061`) and
     `recovery.directory` (`0x0063`) per group, the `roster.update` and
     `roster.revoke` operations enumerated above, and the two `ACCESS`
     rotations in step 5.
   - Invite and delegation frames are refused outright, unchanged. A recovery
     key cannot bring a fourth party in or issue an agent certificate.

   **Where each half of that is actually enforced**, because the split is not
   obvious and assuming the relay does all of it is the mistake this rewrite
   exists to prevent. The relay enforces what it can see: the connection's group
   set, taken from the recovery transaction rather than from any ciphertext; the
   refusal of invite and delegation frames, which are their own frame types; and
   the shape of the recovery rotation, which is in the clear
   (`specs/backend/relay/wire.md`). It cannot enforce anything about payload
   kind, because `kind` lives inside `ct` and the relay has no key. A rule
   written as "the relay rejects a `chat.message` on this connection" would be
   unimplementable, and the earlier text was drifting toward exactly that.

   The rest is enforced by receiving clients, on the same detect-and-evict
   footing as every other external commit here: a device that is inside a live
   recovery transaction may author only the kinds listed above, and an
   application payload from it, a `chat.message`, a `doc.change`, a `media.ref`,
   is rendered as rejected and alerts admins. This is a smaller claim than
   relay-side enforcement and it is the true one. It also loses nothing that
   matters, because a recovery is authorized by a key that already holds read
   access to everything its wraps cover; the property being protected is
   attribution and the audit trail, not confidentiality.

   The connection closes when the transaction completes or expires, and the
   replacement device reconnects as an ordinary device.
5. The replacement device completes the MLS commits. The access set is then
   rotated in two publications, not one, because the replacement device starts
   outside `authorizers` and a recovery key must never hold general authority
   over it (`specs/backend/relay/wire.md`):

   a. A **recovery rotation**, signed by the recovery key. Additive only: it adds
      the replacement device as an entry and an authorizer, swaps the spent
      recovery principal for its successor, and pins the lost-device set the user
      selected on the previous screen as the only removals the replacement device
      will be licensed to make. It removes nothing itself. The relay enforces
      that shape, so a leaked phrase can never lock a workspace out.

   b. An **ordinary publication**, signed by the replacement device now that it
      is an authorizer, dropping exactly the pinned lost devices. This is the
      same authority path as any other revocation and appears as one.

   The replacement device is a **probationary** authorizer until an established,
   pre-existing authorizer publishes a set containing it
   (`specs/backend/relay/wire.md`). During probation it may remove only what was
   pinned in (a); it never self-promotes on a timer. This costs ordinary recovery
   nothing, because the pinned set is precisely what the user asked to remove.
   A phrase cannot distinguish its owner from a thief, so a phrase-only solo
   recovery restores the owner's work but not unrestricted administrative power;
   that requires a previously configured recovery quorum or another admin.

   The client verifies the resulting roster before the recovery connection
   closes. A recovery key is never allowed to leave an enduring administrative
   session behind, and the transaction is not complete until (b) lands. The
   client then presents any pre-existing admin with a one-tap, safety-number
   checked approval; it never presents timer expiry as approval.
6. Phrase rotation is therefore part of the transaction, not cleanup. Recovery
   is not complete until the new phrase is confirmed and the old recovery
   principal is absent from the access set.
7. The old device, if it ever reconnects, is revoked when the user selected that
   option; otherwise it is retained as an intentional, visible choice.

History availability after recovery follows each group's history policy and the
coverage of its wraps, and the honest statement is narrower than the one this
document previously made. Membership comes back in full. An `open` group returns
its history, because historical epoch secrets are re-wrappable there. A `closed`
group returns only what was written from the epoch its wrap named, **not**
everything since the recovery key was added, because a wrap carries one epoch
secret and is overwritten on every commit (`specs/backend/relay/groups.md`). For
DMs that means the conversation comes back and its history does not.

The recovery summary screen names, per group, the date history resumes from. Say
it there rather than letting someone discover it through an empty DM.

## Flow: a person leaves

Revoking every device, every agent certificate they issued, and their recovery
principal, then rotating epochs and republishing the access set, is one action
in the client and is specified end to end in
`specs/backend/relay/lifecycle.md`. It is not left to an admin to remember the
three separate halves.

## SSO

Not built, and worth knowing why before someone promises it. SAML and OIDC can
gate the transport layer only: an IdP can decide who may open a connection, and
cannot decide who may read, because reading requires keys the IdP does not hold.
Same for SCIM deprovisioning, where the actual removal is an MLS epoch change
issued by an admin device. Both are perimeter controls that buyers will assume
govern data access, so if they are ever built they ship with that sentence
attached.

## What is deliberately absent

No password reset, because no password. No email verification, because no email.
No "log in on a new machine", only pairing or recovery. No operator override, no
support-side account access, no admin panel on the relay. No global username
namespace. No session tokens with server-side revocation, because a connection
is authenticated per-connection by signature and revocation happens in the
roster.
