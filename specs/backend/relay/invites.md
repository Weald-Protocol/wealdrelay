# Relay: invites

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only: the Clerk
> production instance, Stripe live mode, the production Render environment and
> Postgres, the production R2 bucket, the published relay digest. No dev tier,
> no test mode, no staging tier, and no agent creates one. `local` and `ci` are
> not an exception because they reach no vendor at all. A gate that cannot reach
> production configuration fails; it never degrades to a mock, a stub, a fake, a
> skip or a newly created dev or staging resource.

An admin issues an invite, the person gets an email, clicks it, enters a code,
and is in. No teammate needs to be online, no approval queue, no waiting state.

This replaces the admission sequence sketched in `specs/backend/relay/auth.md`, which
required an online member to issue the MLS `Add` and `Commit` and therefore
produced an unbounded "waiting for a teammate's device" state. That state is
gone.

## The mechanism

MLS external commits, RFC 9420 section 12.4.3.2. A party outside a group can
commit itself in, provided it holds a recent `GroupInfo` carrying the
`external_pub` extension. No existing member participates.

The invite is therefore three things bundled together:

1. **An authorization**, signed by an admit-holding device, naming what the
   bearer may join and until when.
2. **A renewable encrypted `GroupInfo` per group in scope**, so the bearer can
   actually perform the external commit even if the group advances an epoch.
3. **A one-time code**, delivered separately from the link, binding the invite
   to a human rather than to an inbox.

For every invite other than the empty-workspace bootstrap invite, `scopes`
**must include the workspace root group**. The scope picker may hide that
mandatory entry, but it cannot remove it. The root has no parent and therefore
cannot use the self-join mechanism; its per-invite `GroupInfo` is what lets a
new device enter the roster-bearing group before it derives enrolment keys for
normal channels. The relay rejects an otherwise-valid invite record that omits
its declared workspace root, and clients reject one before presenting it to the
joiner.

The relay stores the ciphertext and serves it to anyone presenting the token. It
cannot decrypt any of it.

## Invite record

Created by the admin's client, uploaded to the relay, referenced by token.

```
Invite {
  token:      [16]byte     // random, URL-safe, the lookup key
  workspace:  [32]byte      // workspace root group id
  issuer:     [32]byte      // admitting device pubkey
  issued_at:  u64
  expires:    u64           // default 7 days
  uses:       u8            // default 1
  code_hash:  [32]byte      // Argon2id of the one-time code, salted with token
  scopes:     [GroupRef]    // which groups this admits to
  caps:       [Capability]  // what the joiner may do, per specs/backend/relay/identity.md
  update_pub: [32]byte      // X25519 public key derived from the URL secret
  bundles:    [EncBundle]   // one per scope
  sig:        [64]byte      // Ed25519 by issuer over all of the above
}

EncBundle {
  group:      [32]byte
  epoch:      u64
  ct:         bytes         // sealed to update_pub: GroupInfo, and for an
                            // `open` group the group's history key
}
```

The history key is what makes an `open` scope arrive populated, and it is the
same key a self-joiner unwraps from `history.publish` under the parent enrolment
key (`specs/backend/relay/groups.md`). One mechanism, two deliveries, so an
invited member and a member who joined the channel by itself see the same room.

The **invite secret** never reaches the relay. It is a 32-byte random value
carried in the URL fragment, which browsers do not transmit to servers and which
the deep link hands directly to the client. It deterministically derives the
private half matching `update_pub`; the relay holds only the public half and
ciphertext it cannot open. This lets any current member refresh an invite without
ever learning or retaining the URL secret.

## Two-channel delivery

The link goes to email. The code does not.

At invite creation the admin's client displays a one-time **12-character
Crockford Base32 code**, grouped `ABCD-EFGH-JKLM`, and the admin sends it over
whatever channel they already use, typically the Slack thread where they said
"I'm adding you". The email contains only the link. The grouping makes it
comfortable to paste or read aloud while the 60-bit value remains safe even
against distributed guessing.

This is what makes the invite something other than a bearer token in an inbox.
An attacker with mailbox access has the link and cannot join. An attacker who
somehow has the code has nothing without the link. It is also the replacement
for the forced safety-number comparison in `specs/backend/relay/auth.md`, which required
a second out-of-band interaction after joining; the code folds that verification
into the one message the admin was already going to send.

The code is Argon2id-hashed with the token as salt, so the relay can rate-limit
attempts without learning it. Five wrong attempts against one token from one
source impose a 15-minute cooldown for that token and source, and twenty-five
wrong attempts against one token across all sources cool the whole token down
for the same interval. The key deliberately carries no device value: the device
in a `Reserve` frame is an arbitrary byte string supplied pre-authentication, so
a key that included it would let a guesser mint a fresh allowance per attempt
(WEALD-287). A cooled-down attempt is refused before the Argon2id hash runs.

The attempt slot is charged before the code is parsed or hashed, not after the
hash fails, and is refunded once a correct code has been shown. Reading the
budget before the verifier and writing it after would let a burst of connections
from one address all read the same count below the ceiling and all run Argon2id,
which turns a five-guess budget into an unbounded CPU and memory amplifier; the
charge is a single statement on the `(token, source)` row, so simultaneous
attempts serialize on it and take distinct slots (WEALD-336). The charge is
skipped, and the attempt refused, when the pair is already cooled down, so a
cooled guesser cannot go on inflating the token-wide sum and cool an invite down
for everybody. The refund is what keeps the budget a guess budget: it is
reachable only past verification, so it cannot reset a ceiling without the
60-bit code it protects, and without it five colleagues behind one office
address would cool that address down by joining successfully.
Failures never burn the invite or other seats behind a shared invite, and
colleagues joining from their own addresses are unaffected by one address's
cooldown. The relay returns the same generic unavailable response during a
cooldown and notifies the issuer's connected client of suspicious attempt
volume without naming a source IP.

## The join flow

1. **Admin.** Picks people and scopes, clicks invite. Client generates the
   token, secret and code, encrypts a current `GroupInfo` per scope, signs the
   record, uploads it, and hands the mail merge to the relay. Displays the code.

2. **Email.** Plain, short, one link:
   `https://relay.acme.com/join/<token>#<secret>`.

   Who sends it depends on the tier, and the difference matters more than it
   looks. A **self-hosted** relay may send it via the operator's own SMTP
   settings, because the operator is the customer and an invitee address in
   their own mail server is not a disclosure to anyone. On the **hosted** tier
   relay-sent mail is off and cannot be enabled: the admin's client sends the
   invite through the admin's own mail client, or copies the link.

   The reason is narrow and worth stating. If our relay sent invite mail, we
   would hold the email addresses of people being invited into a workspace, in
   the data plane, which contradicts the claim in
   `specs/backend/cloud/overview.md` that we cannot tell which humans exist.
   No feature is worth putting a name list inside the blind half of the system.

   Either way, no admin is ever forced to configure mail to onboard someone.
   Copy-to-clipboard is always available and is the default on hosted.

3. **Web landing page**, served by the relay itself, static, no control plane
   involved so self-host works identically. It says an invite is waiting, offers
   the macOS download, and deep links to `weald://join/<token>#<secret>`. It
   cannot display the workspace name, the inviter's name, or anything else,
   because the relay does not know them. Say "You've been invited to a Weald
   workspace" and leave it.

**How these steps reach the relay.** Steps 4, 5 and 7 travel on the `JOIN` frame
(`specs/backend/relay/wire.md`), which is the one frame a client may send before it
has authenticated. That is not an exemption carved out for convenience: a device
redeeming an invite has no access-set membership and cannot have one, because the
reservation is what makes it admissible. Everything that would otherwise be a
session check is a property of the record instead, and the endpoint's single generic
answer is what keeps it from being an oracle.

Step 5's signature verification is **implemented on every client**, and the two
implementations answer identically: `InviteRedemption.fetchRecord` on macOS
(`Sources/Sync/InviteRedemption.swift`) and `InviteRedemption.fetchRecord` on
Android (`Android/app/src/main/java/team/weald/android/mls/InviteRedemption.kt`)
both refuse a record whose stored bytes do not decode, whose `token` is not the
token that was asked for, or whose issuer signature does not verify, and both
answer that refusal the same way they answer a token the relay does not hold:
with nothing. That sameness is deliberate. A client that told the two apart would
be an oracle for which tokens exist, reachable by anybody who can open a socket,
which is the property this whole endpoint is shaped around.

The scope list therefore comes from the record and never from the relay's own
answer. A relay can still shrink what it serves, which costs a joiner a channel it
would have entered, and it cannot widen it: a scope it invented has no bundle
anybody can open, and the commit for it is refused against the record's own scope
list.

4. **Local setup, then reserve.** Before spending an invite seat, the client
   generates its device key, collects a display name, and generates and confirms
   the recovery phrase. These are local-only actions: abandoning this screen
   sends nothing to the relay and costs no invitation capacity. Only after that
   confirmation does it submit the token, code, a random join nonce, and the
   new device public-key hash. The relay Argon2-verifies the code and atomically
   takes one unit of remaining capacity, recording
   `reserved(join_nonce, device_hash, expires_at)` against it. A reservation
   lasts ten minutes and is idempotent for the same nonce. This is the
   linearization point for `uses`.

   The provisional grant that lets the joiner open a socket is written inside
   that same transaction, so the seat and the credential to spend it are one
   atom. Either both exist or neither does. A grant that failed after the seat
   was taken produced the state this rule exists to forbid: capacity spent on a
   reservation nobody could use, with nothing to give it back (WEALD-342).

   Ten minutes covers only the network join after local setup, not the time to
   read or store a recovery phrase. A reservation is extended, once, to the
   invite's own expiry the moment the client reports that local setup completed
   and the join is blocked on something the joiner cannot influence, which in
   practice means a stale `GroupInfo`
   (see "GroupInfo freshness"). The relay verifies nothing about that claim and
   does not need to: the extension consumes the seat it already holds, is bound
   to the same nonce and device hash, and can never outlive the invite. Without
   this rule the parked-join path below expires the seat it is waiting on, and
   a joiner who did everything asked of them finds a burnt invite and a recovery
   phrase for a workspace they never entered.

   `uses` may exceed one, because bulk invites with a shared code are offered
   below, so reservations are a **bounded pool rather than a single slot**. The
   relay holds up to `uses` live reservations at once, each bound to its own
   nonce and device hash. Capacity is decremented on reserve and returned on
   expiry, so an abandoned setup frees a seat after ten minutes rather than
   burning one of ten invitations permanently. A request arriving with no
   capacity left, or against a redeemed, revoked, expired or nonexistent token,
   receives the same generic unavailable response, so the endpoint stays
   uninformative about which of those it was.

5. **Client.** Fetches the reserved record, verifies the issuer signature chains
   to the workspace trust root, and decrypts the current bundles with the private
   key derived from the URL secret.

6. **Join.** Performs an external commit against each scoped group, embedding
   the signed invite authorization in the commit's `authenticated_data`. Writes
   its own roster entry, which is valid because the invite signature chains to
   an admit-holding device. The same commit emits a `recovery.wrap` sealing each
   group's current epoch secret to the joiner's freshly generated recovery key,
   so recovery works from the first minute rather than from whenever an admin
   next happens to commit.

   The client half of that rule, made explicit 2026-08-09 (register BR-027): a
   scope entered by external commit is not a joined scope until the relay has
   numbered the commit that carries it. Until then the joining device folds
   nothing into its seal, writes no epoch secret to its group store, emits no
   recovery wrap and reports the scope as still waiting, because a device that
   recorded the join on its own word would be sealing to a group no other member
   has it in and would look healthy while being invisible.

   The relay accepts an external commit only when its invite reservation is live,
   the committing device hash matches the reservation, and the group is one of
   the reserved scopes. It records each accepted scope commit against the nonce;
   duplicate retries return the original receipt. The final required scope commit
   atomically consumes that reservation's seat, so a second device cannot race a
   seat that has already been spent. It also promotes the reservation-bound
   provisional grant to `pending_access_set` through the invite expiry. This is
   a state transition, not a second grant: the just-enrolled device stays
   connected while it waits for the durable access-set publication, but no other
   device can inherit the seat.

7. **Access set.** The joiner's commit is not enough on its own: the relay's
   access set is signed by an admit-holding device
   (`specs/backend/relay/wire.md`), and the joiner is not one. Until an admin's
   client publishes an updated set, a joiner connects under a **provisional
   grant** derived from its own reservation rather than from the invite record.
   The invite cannot name the joiner: it is written before that person has a
   device, and an admin who could name the key would have had to meet the
   device first, which is the coordination the whole flow exists to remove. What
   the relay has instead is the `device_hash` it recorded at reserve, which is
   the same hash the external commit had to match. That hash, and only that
   hash, is honoured as an access set entry of one: first for the reservation,
   then as `pending_access_set` through the invite expiry after the final scope
   commit. Any admin client publishes the real set within seconds of seeing the
   join, and the notification in the admin controls below is what triggers it.
   If no admin is online, the joiner keeps working for the life of the invite
   and the set catches up later.

   This is the one piece of the join flow that could have reintroduced a
   "waiting for a teammate" state, and it does not, because the provisional
   grant covers the gap.

   A grant is a real connection credential, so it has a defined end as well as a
   defined beginning (`specs/backend/relay/wire.md`). It dies with its invite,
   dies immediately if the invite is revoked or deleted, and dies the moment an
   accepted access set drops a hash that a previous accepted set carried. That
   last rule is what stops a removal from being undone by a forgotten invite: an
   admin who removes someone an hour after they joined ends their connection
   through the ordinary path, without anybody having to remember that an invite
   was still outstanding. The relay can evaluate all three without learning
   anything it did not already hold.

   Voiding is terminal, and that matters because revocation is aimed at exactly
   the party that drives the rest of a join. A grant that has been voided is
   never brought back by another `grant`: the upsert refuses to clear
   `voided_at`, so the final `Commit` of a join the admin already killed cannot
   re-arm the credential to the invite's original expiry. A device that has been
   revoked, superseded or expired needs a new invite, and redeeming again is
   refused before it can spend a seat. Every `Commit` also re-reads the invite's
   state, its tombstone and its expiry, because revocation lands between two
   frames of the same join and the reservation alone does not know about it.

8. **Self-join the rest.** The mandatory workspace-root scope is already
committed in step 6. Everything else the roster entitles the joiner to, meaning
the workspace default channels and every `parent` channel it is entitled to,
is entered by self-join immediately afterwards, in the dependency order in
`specs/backend/relay/channels.md`. This is also the path by which a member
enters any group created after they joined, so an invite going stale between
issue and redemption costs nothing.

9. **Done.** The joiner is reading and writing in `#general` within seconds of
    clicking the link. Nobody else had to be awake.

## GroupInfo freshness

An external commit needs a `GroupInfo` from the current epoch. Every commit
advances the epoch, so bundles go stale.

Rule: **any member issuing a commit must refresh every live invite for that
group**. For each outstanding invite record the member seals the new `GroupInfo`
to that invite's public `update_pub` and uploads an `InviteGroupInfoUpdate`
containing `(token, group, epoch, ct)`. The relay accepts an update only from an
authenticated current access-set principal and never decrypts it. Because it
cannot verify group membership, it treats the update as an availability hint:
it retains the newest three candidates per `(token, group)`, rate-limits writes,
and the invitee accepts only an MLS-valid GroupInfo for the invited group.

Retaining the newest three is not on its own what stops a bogus upload from
masking the last valid one, and this section used to claim that it was. Four
bogus uploads at four distinct epochs evict every older row, so an admitted
workspace principal could park every outstanding invite for a group without
revoking one. What stops it is a lineage the relay can authenticate indirectly:
**the candidate carried in the signed invite record is pinned**. It arrived over
the authenticated issue path inside a record the issuer signed, so pruning never
evicts it and a colliding refresh at its epoch never overwrites it. The worst a
flood achieves is that the joiner falls back to the seal the issuer gave it,
which is the state it would have been in had nobody refreshed at all. A scope
therefore holds at most four rows: three refreshed and one pinned. The inviter
may also cancel an invite; the relay then deletes all of its update records.

This is intentionally per-invite rather than a single group-wide publication
key. The group-wide key rotates on removal, but an outstanding invitee cannot
derive its replacement. A per-invite public encryption key lets any current
member refresh the bundle while a removed member cannot decrypt the new one.
At the stated limit (20 live creations per admin per hour, seven-day expiry), the
fanout is bounded and far cheaper than a join flow that sometimes cannot join.

If the required per-invite update has not arrived, which can happen when a
committing client dies between the commit and its refresh batch, the join does
not fail. It parks:

- The client completes device key, display name and recovery phrase as normal,
  so the human finishes setup and puts their laptop down.
- The reserved invite becomes a **pending join** held by the relay, on the
  extended reservation in step 4, so the seat survives as long as the invite
  does. A pending join is the one state that outlives the ten-minute window, and
  it is bound to the same device hash throughout, so nothing else can take the
  seat while it waits. Every member's client refreshes outstanding invite
  bundles on connect precisely so this resolves without anybody being asked to
  do anything.
- If the invite itself expires while a join is parked, the client says so
  plainly and offers to ask the admin for a new one, naming the reason. Setup
  is preserved: the device key, display name and confirmed phrase are reused
  against the replacement invite rather than regenerated, so a second attempt
  is one click and not a second recovery phrase.
- The moment an update lands, the external commit runs and the joiner is
  notified that they are in.

The user-visible string is "finishing up, you can close this" rather than "this
workspace needs a member to come online once". Nobody is ever left staring at a
screen waiting for a colleague, which was the failure mode external commits were
adopted to remove and which a hard failure here would have reintroduced through
the back door.

## Validation, and its honest limit

External commits mean the joiner adds itself. Existing members validate
afterwards, not before.

On receiving a commit carrying an invite authorization, every client checks that
the signature chains to a device holding `admit`, that the invite has not
expired, and that the claimed scopes match. A commit failing validation triggers
an immediate `Remove` proposal from the first member to notice, plus a loud
alert to admins naming the offending key.

This is detect-and-evict, not prevent. The window is one epoch. State it plainly
in the security page rather than implying admission is gated, because a reviewer
will read the RFC and find this themselves.

The exposure is bounded by the fact that forging an invite requires an
admit-holding device's private key, which is the same thing that gates the
prevent-first design. What external commits actually change is that a stolen
invite is exploitable for its lifetime without an admin being online to notice,
which is why expiry defaults to 7 days and single-use.

## Bootstrap is an invite

The first device enrolling into an empty workspace uses this same primitive.
There is no separate bootstrap token type, no separate expiry rule, no separate
reissue endpoint, and no second code path to audit.

A fresh relay, on first run, writes a self-issued `Invite` with no scopes (there
are no groups yet), `uses: 1`, and a `caps` list containing `admin`. Redeeming
it makes the redeemer the trust root, exactly as `specs/backend/relay/auth.md`
describes.

### What redemption means when there are no scopes

Every other invite retires its reservation on the final scope commit. A
bootstrap invite has no scopes, so that rule names nothing, and left there the
most security-critical seat in the product has no defined moment of
consumption and the genesis key has no defined moment of death.

Consumption is therefore the **acceptance of the genesis access set**: the
first valid `ACCESS` frame at `version` 1 whose sole authorizer is the
reserving device (`specs/backend/relay/wire.md`). It is the right event because
it is the first thing a trust root does that the relay can verify unaided, it
is signed by the device the reservation was bound to, and it is the artifact
that makes the workspace reachable at all. In one transaction the relay accepts
that set, retires the reservation, marks the invite spent, and zeroes the
genesis private key.

Everything before the reservation is abandonable and costs nothing. A buyer who
quits at the recovery phrase screen has not spent a seat and can click the same
link again inside its 24 hours, on a new nonce and a new device key. A buyer
who completes setup has a workspace whose first
log entry is genesis, and no second bootstrap exists at any price.

The client's trust-root check (`specs/backend/cloud/provisioning.md`) runs
against the accepted genesis set rather than against a roster it wrote itself,
so an interception is caught by the relay's own accepted state and not by the
client agreeing with itself.

### The genesis key

Every other invite is signed by a device holding `admit`, and validation is
"the issuer signature chains to the workspace trust root". At bootstrap there is
no trust root and no device, so the relay signs. That means the relay briefly
holds a key that can mint an admin authorization, and on the hosted tier that
relay is ours. Left unbounded it would be the single strongest argument against
the whole product, so it is bounded in four ways and all four are release
blocking.

1. **Generated on first run, for one purpose.** A fresh Ed25519 keypair, used to
   sign exactly one invite record and nothing else, ever. It is not a service
   identity, it is not the TLS key, and it signs no other frame in the protocol.
2. **Destroyed on redemption.** The private half is zeroed from memory and from
   disk in the same transaction that records the trust root. A relay that has
   been enrolled cannot mint a second bootstrap invite, and there is no
   configuration flag or support command that restores the ability. Reprovisioning
   means a new instance, which the customer initiates and which produces a
   visibly different workspace id.
3. **Fingerprint printed and pinned.** The fingerprint goes to relay stdout at
   first run and, on hosted, onto the post-checkout page beside the link. The
   enrolling client records it as the workspace's genesis anchor, and the
   transparency log's first entry is the genesis key plus the trust root it
   admitted. Every later client verifies that entry on first sync, so the
   question "was this workspace founded by the device I think founded it" has an
   answer forever.
4. **Genesis is the first transparency log entry, not an untracked event.** An
   earlier draft claimed the bootstrap consumption was recorded in the membership
   transparency log, which was vacuous: at bootstrap the log did not exist yet,
   because the trust root creates it. Now the log begins with genesis, so there is
   no unlogged prefix.

The reservation is what the relay checks, on every path. A connection that names
a group of a workspace with no access set yet is not thereby founding it: group
rows exist before genesis on every provisioned relay, so the workspace resolved
from a named group id is only admitted to the bootstrapping state when the
connecting device holds the live, unconsumed reservation on that workspace's own
bootstrap invite. Without that the answer is the ordinary refusal.

For self-hosters the genesis key never leaves their machine and this whole
section is a formality. For hosted it is the crux of the trust-root race in
`specs/backend/cloud/provisioning.md`, and it should be demoed rather than
described: a screen recording of the key being destroyed and the log entry being
written is worth more than the paragraph above.

### Delivery

The relay prints the link and the code to its own stdout for self-hosters, and
for the hosted tier the two halves are split across channels:

- **Link** on the post-checkout page, in the browser session that paid.
- **Code** emailed to the verified Clerk email of the owner who initiated
  Checkout, locked into that Checkout session. A mutable Stripe invoice address
  is never used for this security factor.

That split protects against an accidentally forwarded link and against a
browser-only or inbox-only compromise. It does **not** turn email delivery into
an independent control-plane security boundary: the service requesting delivery
handles the code. The hosted trust-root race is instead made visible by the
client's hard-fail and permanently attributable through the genesis entry; the
customer can replace the instance without a support ticket. This distinction is
deliberate because a reassuring but false "two independent compromises" claim
would be worse than naming the remaining risk.

Expiry for a bootstrap invite is 24 hours rather than 15 minutes, because the
buyer may not have installed the app yet and there is nothing of value in an
empty workspace to protect with a tight window. This removes the "token expired
while I was downloading" failure that the short-lived bootstrap token created.

## Admin controls

These are carried by `INVITE`, frame tag 20, which is separate from `JOIN` (tag 18)
and refused on any session that has not authenticated. `JOIN` is the one frame a
client may send before `AUTH`, because a device redeeming an invite has no
membership yet; issuing is the opposite, and folding the two together would put a
privileged operation on the one path that by construction has no session behind it.

The relay gates `INVITE` on the access set's `authorizers` list, not on the `admit`
capability. It cannot check the capability: capabilities live in the roster and the
roster is encrypted to the workspace group. `identity.md` makes the authority to
rotate the access set and the authority to admit the same power in practice, so the
authorizer list is the relay-visible form of it. The record's own signed `caps` list
is where the capability rule is really enforced, by every client that reads it.
Unlike the redeem path, answers here are specific: the caller is an authenticated
member who just uploaded a record, and telling them which rule they broke is safe.

The joiner's side gains one step on `JOIN`: `Record`, which serves the stored record
exactly as its issuer signed it. Step 5 below has always required a client to verify
that signature before presenting anything, and there was no verb for it, so a client
had to trust the relay for which scopes an invite covered and a joiner who knows
nothing about the workspace could not name a group to ask about at all. It is not
gated on a reservation: the record carries no code and no secret, and gating it would
mean spending a code attempt to discover an invite was malformed.

The client module above all of this is `specs/invite-module.md`.

- **Live invite list.** Outstanding invites, scopes, expiry, uses remaining,
  revocable individually. Revocation first writes the opaque enforcement
  tombstone defined in `specs/backend/relay/wire.md`, then deletes the
  redeemable record and its bundle updates. The invite vanishes from the live
  list and an unredeemed link dies immediately, while any already-issued
  provisional grant is still findable and closed immediately.
- **Notification on redemption.** Admin's client gets a notification naming the
  display name and the invite used (`specs/backend/relay/notifications.md`). Not
  approval, just visibility, since the joiner is already in. Receiving it also
  triggers the client to publish the updated access set, which converts the
  joiner's provisional grant into a durable one.
- **Bulk invite.** Paste a list of emails, one shared code or one code per
  person. One code per person by default; a shared code is a convenience for
  onboarding a whole team at once and is labelled as weaker.
- **Scope presets.** "Everything", meaning the whole workspace and so the whole
  project, or "one channel". There is no project-sized preset between them,
  because the workspace is the project. They map to the
  capability vocabulary in `specs/backend/relay/identity.md`.

## Rate limits

Per relay: 20 invite creations per admin per hour, 64 seats per invite record and
200 outstanding seats per workspace, 5 failed code attempts per token/source/
device tuple per 15 minutes, 100 join attempts per source IP per hour, and a
100-attempt per-token hourly abuse ceiling that cools down rather than revokes.
Redemption of an expired or revoked
token returns the same error as a nonexistent one, so the endpoint is not an
oracle for which tokens ever existed.

## What the joiner sees on arrival

Per the group's history policy in `specs/backend/relay/groups.md`, which is now
two values rather than three.

Groups set to `open`, the default for the workspace root and team channels, carry their
history key in the invite bundle alongside the `GroupInfo`, and that key opens
the published history of the group (`specs/backend/relay/groups.md`). The joiner
lands in a populated workspace with no member online and no waiting state, and so
does every `open` channel they enter by self-join afterwards, which is the larger
half of what a new member actually opens.

Groups set to `closed`, which is mandatory for DMs and the default for channels
created private, are simply not offered as invite scopes. There is no partial
state to explain and no empty-room failure mode to design around.

The scope picker therefore shows only `open` groups, and the confirmation line
says what the invite actually does: "Sam will be able to read past messages in
3 channels."
