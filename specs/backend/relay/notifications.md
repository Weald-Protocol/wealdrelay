# Relay: notifications

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only: the Clerk
> production instance, Stripe live mode, the production Render environment and
> Postgres, the production R2 bucket, the published relay digest. No dev tier,
> no test mode, no staging tier, and no agent creates one. `local` and `ci` are
> not an exception because they reach no vendor at all. A gate that cannot reach
> production configuration fails; it never degrades to a mock, a stub, a fake, a
> skip or a newly created dev or staging resource.

`specs/backend/relay/overview.md` commits to push carrying a group id and a wake
hint, never a preview. That commitment implies a push service, a device token
registry and a new metadata surface, none of which appeared in the subprocessor
table or anywhere else. This closes that.

## Scope

This file was written when the client was macOS only, and it said in as many
words that there was no third-party push service at all. That sentence was true
until protocol version 4 and it is not any more, so it is corrected here rather
than left for a reader to trip over: `specs/backend/relay/push.md` is the
normative half, `specs/backend/relay/ringer.md` is the component at the other end
of it, and `specs/backend/contracts/decisions/ADR-0012-push-via-a-separate-ringer.md`
is the decision. The product design is `specs/push-notifications.md`.

What is still true, and is the more important half, is that **the local path
below is unchanged and is still the only thing that renders a notification.** A
wake carries a three-value category and nothing else; it is an instruction to go
and look, never a thing to display. Every notification a person reads is still
authored on their own machine from plaintext that was decrypted there.

Three deployments, and the first of them is the default:

- **No push.** `WEALD_RELAY_PUSH=off`. The relay has no outbound leg, devices are
  told so and never register, and this file's v1 section is the whole story. A
  self-hoster on a private network keeps this, and the subprocessor list does not
  grow for them.
- **A shared ringer.** The relay points at a ringer holding the APNs key for the
  app its users actually run. Apple and the ringer join the subprocessor table in
  `specs/backend/cloud/compliance.md` the day this ships.
- **Their own ringer.** An operator shipping a fork under their own bundle
  identifier runs their own with their own key and changes one URL.

## v1: local, and still the only thing that renders

The Weald app holds its relay connections while running, including in the
background. An envelope arrives, the app decrypts it, and if it matches a
notification rule the app raises a local macOS notification with full content,
because the content is already decrypted on the machine that is displaying it.

Properties:

- No device token registry. No push provider. Nothing to disclose.
- Full previews, because the rendering happens after local decryption.
- Works identically for self-hosters, with no dependency on our infrastructure.
  A self-hosted relay with no public ingress still notifies
  (`specs/backend/relay/deployment.md`).

Failure mode, stated because it is real: an app that is quit gets no
notifications, and the user sees them on next launch. The app defaults to
launch-at-login and says why, once.

## When APNs becomes necessary

An iOS client, or a macOS app that should notify while quit, needs Apple Push.
These rules were settled here before anything was built, so that they were not
decided under shipping pressure later. Four of the five held exactly as written.
The one that did not is recorded rather than quietly amended, because the whole
value of settling a rule early is being able to see what it was when it changes.

**Payload.** A wake hint and nothing that identifies anything. Never text, never
a display name, never a channel name, never a sender. The push payload must be
worthless to anyone who reads it, including Apple. Held, and tightened: what
crosses APNs is a three-value category and a dull placeholder body, and not even
the handle, because the device knows its own handle and telling Apple which one
was woken would put a stable identifier in the payload.

**No group id at all, rotating or otherwise.** This rule used to read "group ids
are pseudonymous", with a per-device rotating alias and a small relay-side alias
table that rotated weekly. It is superseded by `push.md`, and the replacement is
strictly stronger: there is no group in a wake, so there is no alias table, no
rotation schedule and no mapping to keep. The reasoning against the old rule is
worth keeping, because it is the shape of a mistake that recurs. A rotating alias
is only unlinkable if the rotation actually happens, which makes a privacy
property depend on a scheduled job continuing to run correctly for years, and it
still leaks the structural fact that two pushes to one device concern the same
conversation inside a rotation window. Sending no group avoids all of it, and the
device reconciles to find out what changed.

**Rendering.** A notification service extension wakes, fetches, decrypts with
keys from a shared Keychain access group, and rewrites the notification with real
content. If it cannot, the fallback is the placeholder and nothing else. It is
never a preview generated anywhere but on device. Held exactly.

**Disclosure.** Apple Push Notification service joins the subprocessor table the
day this ships, with the data column reading "opaque wake handles and a
three-value category, no content, no identifiers", and the ringer joins as the
party holding the handle-to-token mapping. `/security` gets the same sentence.
Adding a subprocessor quietly would be worse than the feature is worth. Held, and
push becomes a nineteenth surface in the `privacy-review` rotation on top, because
it is the first time this product hands a routing signal to a third party.

**Opt-out.** A workspace authorizer can disable push entirely for the workspace,
and an individual can disable it for themselves. Both are one toggle, and the
self-host docs note that disabling push removes the only component of the system
that talks to a party outside the operator's control. Held, with a third opt-out
underneath the two: an operator who never sets `WEALD_RELAY_PUSH=on` has no
outbound leg at all, which is the default and is not a degraded state.

## Notification rules

Client-side, because the relay cannot evaluate them.

Defaults chosen to not be noisy, since agent-driven workspaces generate far more
events than human ones:

| Event | Default |
| --- | --- |
| Direct message | Notify |
| Mention of the user | Notify |
| Reply in a thread the user is in | Notify |
| Ticket assigned to the user | Notify |
| Agent completed a task the user started | Notify |
| Any other agent write | Silent, badge only |
| Channel message with no mention | Silent, badge only |
| Roster change the user did not perform | Notify, always, not muteable |
| Split-view or transparency log warning | Notify, always, not muteable |

The last two are deliberately not muteable. A security signal a user has trained
themselves to dismiss is not a security signal, and these two fire approximately
never in a healthy workspace (`specs/backend/relay/lifecycle.md`).

## Digests

An agent finishing forty tickets overnight should produce one notification, not
forty. The client coalesces per workspace, meaning per project, per hour outside working hours and
renders a digest naming counts and the top few items. Working hours are a local
setting, not synced, because it is nobody else's business.
