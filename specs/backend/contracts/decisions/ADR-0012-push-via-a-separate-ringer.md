# ADR-0012: push goes through a separate ringer, addressed by URL

Status: accepted, 2026-08-04. Supersedes nothing. Recorded so it is not
relitigated.

**Published.** This ADR goes into `PUBLISHED_SPECS` in `scripts/relay-mirror.py`
along with `specs/backend/relay/push.md` and `specs/backend/relay/ringer.md`. The
decision is entirely about the protocol and the relay's dependency surface, and it
is the one a self-hoster most needs to be able to audit, because it is the reason
their relay can wake our App Store build without asking us for anything. There is
no pricing, vendor choice or purchase flow in it. `ADR-0006` is the contrasting
case and stays unpublished for exactly that reason.

**This ADR is also the trust-boundary review `specs/backend/relay/server.md`
requires.** That file says the relay has no dependency on any commercial-layer
vendor and that a pull request adding a configuration key pointing at something in
`specs/backend/cloud/` is a trust boundary change, because it would mean the hosted
binary differs from the audited binary and a self-hoster runs something we do not.
Push adds six keys, one of which is an outbound destination, so the review is owed
whether or not anybody asks for it. The finding is in the last section, and it is
the reason the destination is a URL an operator supplies rather than a name we
compile in.

## The decision

The component that talks to Apple is separated from the relay, published as its own
contract (`ringer.md`), and addressed by URL. The relay holds no APNs key, no
device token and no Apple relationship. It wakes a device by POSTing
`{handle, category}` to `WEALD_RELAY_PUSH_URL`, with `WEALD_RELAY_PUSH_TOKEN` as an
optional bearer, and it stores a sixteen-byte handle the ringer minted, which it
cannot resolve.

Authority to wake a device is **possession of the handle**, not an account, a
licence, a credential we issue or a relationship with us. A handle is a capability
the device minted at the ringer and handed out, so a party holding one is by
construction a party the device chose to hand it to. A ringer configured without a
bearer serves any caller, and that is deliberate rather than an oversight.

That single property is what makes the whole thing work: a self-hosted relay pushes
to our App Store build by pointing one variable at a ringer holding the key for
that bundle, which in practice is the one we run, and it needs nothing from us to do
it. No sign-up, no licence check, no callback, no account. An operator shipping a
fork under their own bundle identifier runs their own ringer with their own key,
changes the same one variable, and the protocol is unchanged, which is why the
ringer's contract is published rather than merely described.

## Why, on what the constraint actually is

The easy half is that a hosted relay could hold an APNs key. The hard half is the
one that decides the shape, and it is not a preference:

- The relay is Apache 2.0 software a stranger clones, rebuilds and digest-matches
  (`specs/backend/relay/verification.md`). A signing key cannot be inside it.
- An APNs key is minted against a bundle identifier. The apps are
  `com.dicyanin.weald.app` and `com.dicyanin.weald.companion`, which we own and a
  self-hoster does not, so a self-hoster cannot mint a key for the app their users
  actually run.

Both facts point the same way, so the answer is not a compromise between them. The
key has to live outside the published binary, in a component whose address is
configuration, and every other property of this design follows from that one move.

## Why, on what the relay ends up holding, which is the stronger half

A handle is sixteen random bytes, minted per device per workspace, opaque to the
relay and meaningless to anyone who cannot resolve it. It is never derived from the
token, the device key or the workspace, so a rotated handle is unrelated to the one
it replaced and two handles for one device do not look like two handles for one
device.

The row is keyed on `entry_hash`, the salted device hash, with the salt minted once
per workspace and never rotated, so the same device in two workspaces produces two
unrelated rows. Cross-workspace unlinkability is therefore a property of the key
rather than an operational promise, and it is proved by a property test.

Compare what the rejected shape would have held. A relay storing APNs tokens would
hold a durable, cross-installation, Apple-resolvable identifier beside a workspace
principal, which is a materially worse metadata position than
`specs/backend/relay/overview.md` discloses today, and it would be worse for a
self-hoster's users than for ours because there would be no reason for the tokens to
be in that database at all.

The ringer's side of the trade is honest and small: it learns that a handle was
woken at a time. It has no workspace column, no group column, no relay column and no
wake log, so it cannot answer which workspaces a device belongs to or which relay
woke a handle. That is strictly less than the relay already knows about the same
device's connection timing, and it is the irreducible minimum for a component whose
job is to place a call to Apple.

## The alternatives rejected, and why

**The relay holds an APNs key.** Rejected as impossible twice over, which is why it
is first: impossible in published source, because the key would be in the tree a
stranger clones, and impossible for a self-hoster, because they cannot mint one for
a bundle they do not own. A design that only works for the hosted relay is
forbidden outright by `../governance.md` section 8: if a self-hosted relay cannot do
it, it is not in the protocol. This alternative fails that test before any privacy
argument is needed.

**The handle rides on the access-set entry.** This is what an earlier draft
proposed, and `specs/push-notifications.md` carried it until this ADR, as an
optional `push_handle` field the device published with its entry. It is rejected on
a lifecycle mismatch that no amount of care fixes. An APNs token rotates on Apple's
schedule, which is to say unpredictably and often, and the handle rotates with it.
An access set is a signed, versioned, monotonic document rotated by an authorizer
holding `admit`, with each version naming the prior version's hash. Coupling a value
Apple's servers change to a document a human with a signing key rotates would mean
either a device cannot rotate its handle without an authorizer being present, or the
access set grows a mutable field outside its signature, and the second is worse than
the first: it would put an unsigned field in the one document whose whole purpose is
that every field is signed. There is a smaller point on top of it, which is that the
access set is readable by every admitted device, so the handle would have been too.
The frame exists because a registration is a statement one device makes about
itself, on its own schedule, and it deserved its own conversation rather than a
field on somebody else's record.

**The device triggers the wake, not the relay.** `specs/push-notifications.md`
section 8: a connected Mac notices an offline peer and asks the ringer directly,
signed with its own device key, and the relay gains no outbound leg at all. This is
genuinely the most conservative option and it is not rejected so much as held: it is
the fallback if this ADR fails review, and it stays written down rather than being
rediscovered under pressure. What it costs is reliability, because it only works
when at least one peer is awake, and the case push exists for is the one where
nobody is. A notification system that works when somebody is already watching is a
worse product than a locked phone that rings, and the privacy difference is smaller
than it looks: the ringer learns the same thing either way, and the party that
learns something new is a member of the workspace rather than the operator.

**A push field on `CONNECT_ACK` instead of forms 5 and 6.** Rejected in one
sentence, and it is the same sentence every time: changing the shape of the
handshake is the one thing a version negotiation must not require. A device asks
where to register with a frame, after it is `Ready`, or it does not ask.

## What we give up, stated honestly

Push is best effort and always will be. A full outbound queue drops the oldest wake
and increments a counter, a non-2xx from the ringer is counted and dropped, and
nothing is retried into a queue that could grow. The client's reconciliation path is
what makes that acceptable, and any sentence promising delivery would be false.

We also give up telling a user, from the server side, whether their push is working.
The relay cannot resolve a handle, so it cannot distinguish a device that has
uninstalled from one that is simply asleep, and it never asks. `readyz` reports
`off`, `configured` or `unreachable` about the ringer and says nothing about any
device. Unreachable is deliberately not un-ready: a relay whose ringer is down still
accepts, stores and serves, and taking a whole deployment down for a best-effort
side channel would be the wrong trade in the wrong direction.

And there is one more party in the disclosure table than there was. Apple Push
Notification service and the ringer both join it the day this ships, which is the
first time this product hands a routing signal to a third party. That is a real cost
and it is why push becomes a nineteenth surface in the `privacy-review` rotation
rather than getting one review and a tick.

## The trust-boundary finding

`server.md`'s rule is about a key pointing at something in `specs/backend/cloud/`,
and the finding is that this one does not, in a way that is checkable rather than
asserted:

- The value is a URL an operator supplies, with no default ever. Nothing about our
  hosted service is compiled into the binary, and a relay with `WEALD_RELAY_PUSH=off`
  has no outbound leg at all. Off is the default.
- No account, no licence, no tenancy and no callback. The ringer's routes have no
  account concept to attach a licence to, which is stated as a refusal in
  `ringer.md` section 6 so an implementation that grew one would fail its gate.
- The hosted binary is the audited binary with a different profile, which is the
  property `server.md` asks for. Push changes configuration and not code paths that
  only one deployment can reach.
- A relay refuses every `CLERK` variable and continues to. Workspace identity stays
  MLS and sealed handoffs, and a wake carries no identity at all.

The refusals are what make that hold rather than merely describe it: `PUSH=on` with
no `PUSH_URL` will not start, a non-`https` destination will not start outside
`local` and `ci`, and `PUSH=off` with any other `PUSH_*` variable set will not start,
because a configured-and-ignored outbound destination reads as working and is not.

## What would reopen this

Two things, and neither is a matter of taste.

If Apple ever offers a way for one key to wake another team's bundle, or for a
token to be resolvable by its holder without a key, the ringer's reason for existing
weakens and the separation should be re-argued rather than kept out of habit.

And if a ringer holding a bearer turns out to be how operators actually run it, then
the "possession of the handle is the authority" claim is true of the protocol and
false of the deployment, and the honest response is to say so in `ringer.md` rather
than to keep the sentence. What must never happen is the bearer becoming something
we issue per operator, because that is an account, and an account is a licence
waiting to be enforced against a self-hoster who owes us nothing.
