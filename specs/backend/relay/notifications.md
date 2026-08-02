# Relay: notifications

`specs/backend/relay/overview.md` commits to push carrying a group id and a wake
hint, never a preview. That commitment implies a push service, a device token
registry and a new metadata surface, none of which appeared in the subprocessor
table or anywhere else. This closes that.

## Scope

The client is macOS only, so v1 is local notifications plus a background
connection, and there is no third-party push service at all.

That is worth stating as a decision rather than an accident, because it means
the subprocessor list in `specs/backend/hosted-service.md` does not grow, and
no external party learns when a workspace is active.

## v1: local, no push service

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
The rules below are settled now so that they are not decided under shipping
pressure later.

**Payload.** A wake hint and an opaque group id. Never text, never a display
name, never a channel name, never a sender. The push payload must be worthless
to anyone who reads it, including Apple.

**Group ids are pseudonymous.** The id in a push is a per-device rotating alias
of the real group id, so an observer correlating pushes over months cannot build
a stable map of a workspace's structure. The alias table lives on the client and
in a small relay-side mapping that rotates weekly.

**Rendering.** A notification service extension wakes, fetches the envelope,
decrypts with keys from a shared Keychain access group, and rewrites the
notification with real content. If it cannot, the fallback text is the app name
and nothing else. It is never a preview generated anywhere but on device.

**Disclosure.** Apple Push Notification service joins the subprocessor table the
day this ships, with the data column reading "opaque wake hints and rotating
group aliases, no content". `/security` gets the same sentence. Adding a
subprocessor quietly would be worse than the feature is worth.

**Opt-out.** A workspace admin can disable push entirely for the workspace, and
an individual can disable it for themselves. Both are one toggle, and the
self-host docs note that disabling push removes the only component of the system
that talks to a party outside the operator's control.

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
