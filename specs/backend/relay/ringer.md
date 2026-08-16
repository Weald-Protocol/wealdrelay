# The ringer: a published contract for waking a device

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only: the Clerk
> production instance, Stripe live mode, the production Render environment and
> Postgres, the production R2 bucket, the published relay digest. No dev tier,
> no test mode, no staging tier, and no agent creates one. `local` and `ci` are
> not an exception because they reach no vendor at all. A gate that cannot reach
> production configuration fails; it never degrades to a mock, a stub, a fake, a
> skip or a newly created dev or staging resource.

The ringer is the only component in this system that talks to Apple. It exists
because the relay must not: `push.md` section 1 has the argument, and this file
is the contract, published so that an operator running a fork under their own
bundle identifier can implement it, or run ours, or run neither.

It is three routes and one table. If an implementation is more than a few hundred
lines it is doing something this contract does not ask for.

## 1. What it knows

    handles
      handle        16 bytes, the primary key, minted here
      token         the APNs device token
      platform      ios | macos | android
      topic         the APNs topic, a bundle identifier, optionally with .voip
      expires_at    when this mapping is forgotten
      created_at

That is the whole schema, and the absences are the contract. There is no
workspace column, no group column, no relay column, no account, no user, no
principal, no device name, no last-seen, no wake log and no counter keyed by
anything but the handle. The ringer cannot answer "which workspaces does this
device belong to" because it has never been told, and it cannot answer "which
relay woke this handle" because it does not record the caller.

One aggregate is served from this table and named here so it is not mistaken for
a drift: `GET /v1/ops/push` on the control plane reports, per platform, how many
live rows exist, how many were created in the last day and how many expire within
the week, beside this process's wake outcomes counted per platform. Platform is
the only label any of it carries. Three integers about a platform reconstruct no
row, name no device and are not a last-seen, and without them an operator cannot
tell "Firebase is refusing us" from "everything is fine" while every Android phone
in the fleet has gone quiet. A count keyed by anything narrower than a platform
stays refused.

It learns that a handle was woken at a time. That is strictly less than the relay
already knows about the same device's connection timing, and it is the irreducible
minimum for a component whose job is to place a call to Apple.

## 2. Routes

### `POST /v1/handles`

The device registers. This is the only route a device calls, and it calls it
directly over HTTPS, never through the relay, because the whole point is that the
relay never sees a token.

    request   { token, platform, topic, prior_handle? }
    response  201 { handle, expires_at }

`handle` is lowercase hex of the 16 bytes. `expires_at` is an RFC3339 UTC string,
never a number: it is what the ringer emits and what every client parses, and the
type is part of the contract because a client that guessed the other one silently
failed every mint.

`token` is validated as hex of the platform's expected length and nothing else;
the ringer does not verify it with Apple at registration time, because a token
Apple rejects is discovered on first wake and handled there. `topic` must be one
of the ringer's configured topics, and a request naming any other is `403` with no
body, because a ringer holding one key must not be usable as an open relay to
another vendor's app.

`prior_handle`, when present and known, is deleted in the same transaction. That
makes rotation atomic: a device that rotates weekly holds exactly one handle at a
time and never leaves an orphan that would keep waking a device the user has
signed out of.

`handle` is sixteen bytes from a cryptographic source, hex encoded in the
response. It is never derived from the token, the topic or the time, so a party
holding two handles for one device cannot tell they are for one device, and a
rotated handle is unrelated to the one it replaced.

No authentication. A registration creates a capability to wake exactly the device
that asked for it, and there is nothing to protect: an attacker who forges a
registration has registered their own device. Rate limiting is by source, five
per minute, and the answer over the limit is `429` with `Retry-After`.

### `DELETE /v1/handles/{handle}`

The device signs out. `204` whether the handle existed or not, in constant time,
because a distinguishable answer would turn this route into an oracle for handle
existence.

### `POST /v1/wake`

The relay rings. This is the route `WEALD_RELAY_PUSH_URL` names.

    request   { handle, category }
    response  202 {} | 404 {} | 429 {}

`category` is one of `message`, `call`, `handshake`, and nothing else is accepted.
The request carries no other field, and a request carrying one is `400`, because
silently ignoring an extra field is how a group identifier eventually arrives in
a payload.

Authorization is possession of the handle. A `Bearer` credential is accepted and
checked if the ringer is configured with one, and a ringer configured without one
serves any caller, which is correct and deliberate: a handle is a capability the
device minted and handed out, so a caller holding one is a caller the device
chose. This is what lets a self-hosted relay push to our app without us
provisioning that operator anything, and it is why no route here has an account
concept to attach a licence to.

`404` for an unknown handle, in constant time and with no body, for the same
reason `DELETE` is constant time. A relay reads `404` as an instruction to delete
its row.

Per-handle rate limiting, thirty wakes per minute, answered `429` with
`Retry-After`. A relay coalesces already; this ceiling is for the relay that does
not.

### `GET /healthz`

`200 ok`. No dependency probe, because a ringer whose Apple connection is
temporarily unhealthy should still accept registrations.

## 3. Talking to Apple

HTTP/2 to `https://api.push.apple.com`, one pooled connection per topic, with a
`Bearer` JWT signed ES256 over the `.p8` key, `iss` the team identifier, `iat`
now, refreshed at forty minutes and never at request time. `node:http2` and
`node:crypto` do all of this, which is why the reference implementation takes no
dependency at all.

Headers per wake: `apns-topic` from the row, `apns-push-type` and `apns-priority`
from the category, and `apns-expiration` set so that a wake that could not be
delivered inside its useful lifetime is dropped by Apple rather than queued:

| Category | Push type | Priority | Expiration | Payload |
| --- | --- | --- | --- | --- |
| `message` | `alert` | 10 | 3600 | `mutable-content: 1`, a dull placeholder body, `weald: { category }` |
| `handshake` | `background` | 5 | 3600 | `content-available: 1`, `weald: { category }` |
| `call` (ios) | `voip` | 10 | 30 | `weald: { category }` on the `.voip` topic |
| `call` (macos) | `alert` | 10 | 30 | `interruption-level: time-sensitive`, placeholder body |

The placeholder is what the user sees if the device cannot do better, so it is
deliberately dull and says "New activity in Weald." with no count, because a
count is a metadata leak and would be wrong anyway. The `weald` dictionary
carries the category and nothing else. The handle is not in the payload: the
device knows its own handle and telling Apple which one was woken would put a
stable identifier in the one place this design has spent its whole budget keeping
it out of.

`410 Unregistered` from Apple deletes the row, immediately, in the same request.
`400 BadDeviceToken` does the same. Every other Apple failure is counted and
dropped, because a wake is best effort and a queue that grows is worse than a
wake that is lost.

## 4. Configuration

| Variable | Shape | Notes |
| --- | --- | --- |
| `WEALD_RINGER_APNS_KEY` | secret, PEM | The `.p8`, never logged, never echoed |
| `WEALD_RINGER_APNS_KEY_ID` | string | The key identifier |
| `WEALD_RINGER_APNS_TEAM` | string | The team identifier |
| `WEALD_RINGER_APNS_TOPICS` | comma list | The allowlist from route 1 |
| `WEALD_RINGER_TOKEN` | secret | Optional bearer for `/v1/wake` |
| `WEALD_RINGER_DATABASE_URL` | url | The handle table |

All six go into `../build/env-registry.json` in the same commit, on a new
`ringer` surface, because the gate fails in both directions.

## 5. Where it runs, and what it costs

APNs is free with the Apple Developer Program. A ringer must be always on,
because a service that spins down cannot ring, and per the no-upgrade rule it
does not get a new paid service: the reference deployment is an additional route
group on the existing always-on worker, so the marginal spend is zero. Publishing
the ringer as its own component and deploying it inside an existing process are
not in tension, because the contract is what is published, not the process
layout.

Throughput is negligible. A wake is a few hundred bytes on a pooled connection,
and the relay only sends one when a principal is not connected, so volume is
bounded by the number of offline devices with unread activity rather than by
message volume.

## 6. Refusals

An implementation of this contract is wrong, and the gate fails, if it: stores
any field not in section 1; logs a token, a handle or a JWT; returns a
distinguishable answer for a known and an unknown handle on `DELETE` or `/v1/wake`;
accepts a `topic` outside its allowlist; accepts an unknown field on `/v1/wake`;
retries a wake into an unbounded queue; or requires an account, a licence or a
credential we issue in order to accept a wake from a relay we do not run.
