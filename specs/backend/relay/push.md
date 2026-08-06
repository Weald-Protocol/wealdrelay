# Relay: push wake, protocol version 4

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only: the Clerk
> production instance, Stripe live mode, the production Render environment and
> Postgres, the production R2 bucket, the published relay digest. No dev tier,
> no test mode, no staging tier, and no agent creates one. `local` and `ci` are
> not an exception because they reach no vendor at all. A gate that cannot reach
> production configuration fails; it never degrades to a mock, a stub, a fake, a
> skip or a newly created dev or staging resource.

`specs/backend/relay/notifications.md` settled the payload rules for remote push
before anything was built, and `specs/push-notifications.md` is the product
design that follows from them. This file is the normative half: the frame, the
table, the wake path, the configuration, and the refusals. It is protocol, so it
is governed by `../contracts/governance.md` and published under
`PUBLISHED_SPECS`.

Push is a breaking-class change by the mechanical test in governance section 3,
because a version 3 relay and a version 4 client cannot agree on frame tag 25.
So it is a version bump: `PROTOCOL_VERSION` becomes 4, `MIN_PROTOCOL_VERSION`
stays 1, `CONNECT` keeps its single field as the client's maximum offer, and the
relay selects the lower of the two ceilings exactly as it has since version 1.
A version 3 client keeps working and simply never sends a `WAKE` frame, which
means it never receives a push, which is the same posture as a relay with push
switched off.

## 1. The question this design answers

A hosted relay could push by holding an APNs key, and that would be the easy
half. The hard half is the one that decides the shape: a self-hosted relay is
Apache 2.0 software a stranger clones, rebuilds and digest-matches, running under
an operator we have never met, and the app it is talking to is our App Store
build with our bundle identifiers, `com.dicyanin.weald.app` and
`com.dicyanin.weald.companion`. An APNs key is minted against a bundle
identifier. A self-hoster cannot mint one for a bundle they do not own, and we
cannot ship ours inside published source.

Both facts point the same way, so the answer is not a compromise. The component
that talks to Apple is separated from the relay, published as its own contract
(`ringer.md`), and addressed by URL. The relay holds no key, no token and no
Apple relationship. A self-hosted relay pushes to our app by pointing
`WEALD_RELAY_PUSH_URL` at a ringer that holds the key for that app, which in
practice is the one we run, and it needs nothing from us to do so: no account, no
licence, no credential, no registration. Authority to wake a device is the handle
itself, minted by the ringer to that device, and a party holding a handle is by
construction a party the device chose to hand it to. That is what makes this
legal under `server.md`, which forbids the relay any dependency on a
commercial-layer vendor, an account concept or a licence check. A URL and an
optional bearer are neither.

Three supported deployments, and none of them is degraded:

- **No push.** `WEALD_RELAY_PUSH=off`, which is the default. The relay has no
  outbound leg at all, devices are told push is unavailable and never register,
  and notifications stay as `notifications.md` version 1 describes them: local,
  full content, no third party. A self-hoster on a private network keeps this.
- **Shared ringer.** `WEALD_RELAY_PUSH_URL` points at a ringer holding the APNs
  key for the app the operator's users actually run. The ringer learns that a
  handle was woken at a time and nothing else: not the relay that called it, not
  the workspace, not the group, not the size, not the sender.
- **Own ringer.** An operator shipping a fork under their own bundle identifier
  runs their own ringer with their own key, changes one URL, and the protocol is
  unchanged. This is why the ringer contract is published rather than described.

## 2. What the relay stores, and what it refuses to store

An APNs device token is a durable, cross-installation, Apple-resolvable
identifier. The relay never holds one, never receives one, and has no field that
could hold one. What it holds is a **handle**: sixteen random bytes minted by the
ringer to one device for one workspace, opaque to the relay and meaningless to
anyone who cannot resolve it.

    relay_push_handle
      workspace_id  the workspace this registration belongs to
      entry_hash    the salted device hash from access/mod.rs, 32 bytes
      handle        16 bytes, unique
      categories    small bitmask, see section 4
      expires_at    the ringer's stated expiry, refused if already past
      updated_at    when this row was last written

Primary key `(workspace_id, entry_hash)`, so a device has at most one live
registration per workspace and re-registering replaces rather than accumulates.
`handle` carries its own unique index so a second principal cannot claim a handle
that is already registered, which is the only way one device could steal
another's wakes.

Keyed on `entry_hash` and not on the device key, for the reason
`relay_key_package.device_hash` is: the salt is `relay_workspace.salt`, minted
once per workspace and never rotated, so the same device in two workspaces
produces two unrelated rows. Cross-workspace unlinkability is therefore a
property of the key rather than an operational promise, and it is proved by a
property test rather than asserted.

Three absences are load-bearing and each one is a negative proof in the gate. A
handle never appears in a log line, at any level, including at `debug` and
including inside an error. A handle is never returned by the `ACCESS` state
query, which carries exactly two facts and does not grow a third. A handle is
never derived from anything: not from the token, not from the device key, not
from the workspace. It is random, from the ringer, and rotation produces a value
unrelated to the one before it.

Registrations are removed when the access-set entry that owns them is dropped,
in the same transaction, because a principal that is no longer admitted must not
keep a wake capability. They are also removed on `expires_at`, by the existing
GC pass rather than by a new one.

## 3. The `WAKE` frame, tag 25

Frame tag 25, the next free integer. Tags are permanent and 21 through 24 were
allocated to `LIVE`, `KEYS`, `CALL` and `MEDIA`; the frame is named `WAKE` and
not `PUSH` because tag 10 has been `PUSH`, the relay-to-client delivery frame,
since version 1, and reusing the word in a second place would be a defect
waiting for a reader.

`Ready` only, like every frame except `JOIN`. A registration is a statement
about an admitted principal, and the relay learns which principal from the
authenticated session rather than from a field, so the frame carries no device
identifier at all. One body enum with six forms, the shape `KEYS` already uses,
because these are one conversation about one row:

| Form | Direction | Fields | Meaning |
| --- | --- | --- | --- |
| 1 `Register` | client to relay | `handle`, `categories`, `expires_at` | Store this against me in this workspace |
| 2 `Registered` | relay to client | `expires_at` | Stored, and this is when the relay will forget it |
| 3 `Clear` | client to relay | none | Forget my registration in this workspace |
| 4 `Cleared` | relay to client | none | Forgotten, and a `Clear` with no row is also this |
| 5 `Query` | client to relay | none | Where do I register, if anywhere |
| 6 `Capability` | relay to client | `enabled`, `register_url` | Push is on or off here, and this is the ringer |

Form 5 and form 6 are the part that makes a self-hosted deployment work with a
shipped client and no client-side configuration. The device does not know which
ringer to register with, and it must not guess, because guessing ours would mean
a self-hoster's users silently register with a ringer their operator did not
choose. So the relay states it. The client refuses a `register_url` that is not
`https`, refuses one longer than 512 bytes, and treats `enabled: false` as an
instruction to hold no registration and raise no expectation of push. It is not
asked at `CONNECT_ACK` time, because adding a field to `CONNECT_ACK` is the one
thing a version negotiation must not require.

Sizes are fixed and small: `handle` is exactly 16 bytes, `categories` is a `u8`,
`expires_at` is milliseconds since the epoch, and a `WAKE` frame never exceeds
1 KiB. Anything else is `reject/push_handle_malformed`, which is a reject and not
a denial because a wrong-length handle is permanently wrong as sent.

Four error codes, registered in `../contracts/registries/error-codes.md` in the
same change, each with a negative vector in `../contracts/wire/vectors/manifest.json`:

- `reject/push_handle_malformed`, a handle of the wrong length, a `categories`
  bitmask with an undefined bit set, an `expires_at` already in the past, or a
  `register_url` a client would refuse.
- `denied/push_not_configured`, a `Register` sent to a relay with
  `WEALD_RELAY_PUSH=off`. Denied rather than rejected, because the frame is well
  formed and the answer would change if the operator changed one variable, and
  the client re-reads state by sending `Query`.
- `limit/push_registration_rate`, more than five registrations per principal per
  hour. Rotation is weekly by design, so five is generous, and the ceiling exists
  because a registration is a write and a device with a loop must not be one.
- `retry/push_backpressure`, no database. Fails closed like every other admission
  path.

## 4. Categories, and the wake path

A category is the entire content of a wake, and it is a closed enum of three
values the relay can determine without reading ciphertext:

| Bit | Category | Determined by |
| --- | --- | --- |
| 1 | `message` | An envelope accepted for a group this principal is admitted to |
| 2 | `call` | A `CALL` frame of kind `offer` routed to this principal |
| 4 | `handshake` | A `HANDSHAKE` message accepted for a group this principal is in |

No counts, no sizes, no group, no epoch, no sequence, no sender, no channel, no
timestamp beyond the fact of the request itself. A device registers the bitmask
it wants, the relay masks every wake against it, and a masked-out wake is not
sent rather than being sent and ignored.

The path, on the accept side of `accept.rs`, `handshake/store.rs` and
`calls/socket.rs`:

1. The write commits first. A wake is never on the critical path of a `SEND`,
   and a `SEND_ACK` is never delayed by one.
2. The relay asks `hub` which admitted principals of that group are connected
   now, and drops those. Push exists for a device that is not holding a socket;
   waking one that is would be a duplicate notification and a metadata leak for
   no benefit.
3. Remaining principals with a registration whose `categories` admits this
   category are enqueued as `(handle, category)` on a bounded queue, default
   1024 entries. A full queue drops the oldest and increments a counter with no
   content-derived label. Push is best effort by construction and the client's
   reconciliation path is what makes that acceptable.
4. A single worker coalesces per handle over a window, default two seconds, so a
   burst of twenty envelopes is one wake. `call` is exempt: a ring that arrives
   two seconds late is a missed call, so a `call` wake jumps the window and is
   sent immediately, and a `message` wake for a handle with a pending `call` is
   dropped as redundant.
5. The worker POSTs to `WEALD_RELAY_PUSH_URL` with a two-second deadline on a
   pooled HTTP/2 connection, with `WEALD_RELAY_PUSH_TOKEN` as a bearer if one is
   set. A non-2xx answer is counted and dropped, never retried into a queue that
   could grow, except `429` which pauses that worker for the stated interval.
   A `404` for a handle deletes the row, because the ringer has told us the
   device is gone and keeping the row would be keeping a dead capability.

The requirement that makes this safe to run is stated as a test rather than as
prose: a ringer that accepts a connection and then hangs for thirty seconds adds
no measurable latency to `SEND` on the same process. The gate proves it with a
listener that does exactly that.

## 5. Configuration

Six variables, all `surface: relay`, all added to
`../build/env-registry.json` in the same commit because the gate fails in both
directions.

| Variable | Shape | Default | Notes |
| --- | --- | --- | --- |
| `WEALD_RELAY_PUSH` | `on \| off` | `off` | Off is the default and a supported deployment |
| `WEALD_RELAY_PUSH_URL` | url | unset | Required if and only if push is on, no default ever |
| `WEALD_RELAY_PUSH_TOKEN` | secret | unset | Optional, because authority is the handle |
| `WEALD_RELAY_PUSH_REGISTER_URL` | url | unset | What `Capability` states, defaults to `PUSH_URL` with the ringer's `/v1/handles` path |
| `WEALD_RELAY_PUSH_COALESCE_MS` | uint | `2000` | Zero is legal and means no coalescing |
| `WEALD_RELAY_PUSH_QUEUE` | uint | `1024` | The bound, not a target |

Startup refusals, in `config.rs` beside the ones for `CALLS` and `LIVE_FANOUT`,
each exiting `EXIT_CONFIG`:

- `PUSH=on` with no `PUSH_URL`. There is no default, for the same reason
  `MAX_CONCURRENT_CALLS` has none: a wake destination is a trust boundary and
  inheriting one silently is the failure this refusal exists to prevent.
- `PUSH_URL` or `PUSH_REGISTER_URL` that is not `https`, unless the profile is
  `local` or `ci`, which reach no vendor at all.
- `PUSH=off` with any other `PUSH_*` variable set. A configured-and-ignored
  outbound destination reads as working and is not, which is the class of
  mistake `--check-config` exists to surface.
- A profile that forbids push, per `profile.rs`.

`--check-config` prints all six, with `PUSH_TOKEN` as `[set]` or `unset` and
never as its value, and `readyz` grows one field, `push`, reading `off`,
`configured` or `unreachable`. Unreachable is not un-ready: a relay whose ringer
is down still accepts, stores and serves, and saying otherwise would take a
whole deployment down for a best-effort side channel.

## 6. What this discloses, and to whom

Apple Push Notification service joins the subprocessor table in
`../cloud/compliance.md` the day this ships, with the data column reading
"opaque wake handles and a three-value category, no content, no identifiers", and
`/security` gets the same sentence. The ringer joins as the party holding the
handle-to-token mapping. Push becomes a nineteenth surface in the
`privacy-review` rotation, because it is the first time this product hands a
routing signal to a third party and that deserves a scheduled re-examination
rather than a one-time review.

A workspace authorizer can disable push for the workspace, and an individual can
disable it for themselves; both are one toggle, and the self-host documentation
notes that disabling push removes the only component of the system that talks to
a party outside the operator's control.

## 7. Build steps

Steps 37 to 41 in `../build/ledger.json`, under the four-part gate. Steps 35 and
36 are the call frames, so the numbering in `specs/push-notifications.md`
section 7 was corrected in the same commit that created this file, exactly as
step 35 corrected `specs/peer-calls.md` for the frame tags.

**Step 37. The handle.** Migration `0009_push.sql`, `src/push/store.rs`, the
frame, the version bump on all four implementations, the vectors, the error
codes. Negative proofs: a handle never reaches a log; a handle is absent from the
`ACCESS` state query; two workspaces hold unlinkable handles for one device; a
malformed handle is a reject; a `Register` on an unconfigured relay is a denial.

**Step 38. The ringer.** `ringer.md`, `backend/weald-ringer/`, the ES256 JWT,
HTTP/2 pooling, `410 Unregistered` deleting the mapping, per-handle rate
limiting. Negative proofs: a wake for an unknown handle is a no-op whose timing
reveals nothing; the store holds no field naming a workspace, a group or a relay;
a token is never logged and never returned by any route.

**Step 39. The wake path.** `src/push/ringer.rs`, presence-aware suppression,
coalescing, the bounded queue, the deadline, the counters. Negative proof: the
hanging ringer adds no measurable `SEND` latency.

**Step 40. Client registration and message push.** Registration on both
platforms, the macOS entitlement and provisioning-profile work, the placeholder
notification, then the notification service extension behind a flag that is off
by default until it has soaked. Integration proof is a real device receiving a
real push from the real ringer, because a simulator cannot receive one.

**Step 41. Call push.** PushKit and CallKit on iOS, a time-sensitive alert on
macOS, the Live Activity with its locally rendered timer. Proof: a call offered
from a Mac rings a locked phone, is answered from the Lock Screen, and audio
flows over tags 23 and 24. Negative proof: the payload, captured verbatim,
contains no name, no text and no group identifier.
