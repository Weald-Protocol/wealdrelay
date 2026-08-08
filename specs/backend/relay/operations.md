# Relay: running it under load and under attack

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only: the Clerk
> production instance, Stripe live mode, the production Render environment and
> Postgres, the production R2 bucket, the published relay digest. No dev tier,
> no test mode, no staging tier, and no agent creates one. `local` and `ci` are
> not an exception because they reach no vendor at all. A gate that cannot reach
> production configuration fails; it never degrades to a mock, a stub, a fake, a
> skip or a newly created dev or staging resource.

The parts of the relay that are not protocol and not packaging: what it does when
frames are malformed, when a client floods it, when two processes share a
workspace, when a clock is wrong, and what it promises about its own
availability.

None of this was written down, which is survivable for a prototype and not for a
thing an enterprise buys. Every gap below is one where the implementation would
otherwise have invented an answer per call site.

## Sequence assignment across processes

`seq` is per-group, monotonic, and assigned by the relay
(`specs/backend/relay/wire.md`). The Scale tier runs two relay processes against
one database, so assignment has to be correct without becoming the contention
point that the removed head chain was.

- Assignment is a single `UPDATE ... RETURNING` against a per-group counter row,
  inside the transaction that inserts the envelope. One statement, one row lock,
  held for the length of an insert.
- The lock is per group, so unrelated groups never contend, and the only workload
  that serialises is writes into the same group, which is bounded by the
  connection rate limit rather than by the number of processes.
- Duplicate `hash` is resolved before the counter is touched, so a retry after a
  dropped connection takes no lock at all and returns the original `seq`.
- Nothing above layer 2 reads `seq` for correctness, so a gap left by a rolled
  back transaction is legal and clients must tolerate one. Negentropy reconciles
  over the space that exists, not over a dense range.

Redis carries fanout only. A missed Redis message costs a subscriber its live
push and is repaired by reconciliation on the next round trip, so Redis is never
the source of truth for whether an envelope was accepted.

## Frame errors

One taxonomy, used by every frame, so a client can branch on a code rather than
on a string.

| Class | Meaning | Client behaviour |
| --- | --- | --- |
| `retry` | Transient. Backpressure, a lock timeout, a failover. | Exponential backoff with jitter, resend verbatim, never renumber an author chain link. |
| `reject` | Permanently wrong as sent. Malformed header, bad hash, oversized `ct`, unknown required field. | Do not retry. Surface as a defect, log locally, keep the payload. |
| `denied` | Well formed, not permitted now. Sender outside the access set, invite seat spent, group frozen. | Do not retry blind. Re-read the state named in the error and act. |
| `quota` | Over a limit. Storage, seats, rate. | Retry after the named interval, or surface the limit to the user with the lever that clears it. |
| `version` | Protocol version unsupported or below the client's pinned floor. | Abort the connection. Never silently continue (`specs/backend/relay/wire.md`). |

Every error carries the class, a stable code, and where relevant the current
state hash so the client can rebase rather than guess. `SEND` never returns
`retry` for contention, only for infrastructure, which is the property the
absence of a head chain buys.

## Backpressure

A relay under load slows down rather than dropping envelopes, because a dropped
envelope is a hole in an author chain and therefore a security alarm on somebody
else's screen.

- Per-connection send and receive queues are bounded. A full receive queue stops
  reading the socket, which pushes back through TCP, rather than accepting and
  discarding.
- The send queue is bounded **in both frames and bytes**, whichever is reached
  first: 256 frames and 8 MiB. The count alone is not a memory bound, because
  frames differ in size by three orders of magnitude (a `SubAck` against a `PUSH`
  carrying a 1 MiB envelope), and 256 of the largest is a quarter of a gigabyte on
  one connection. An empty queue accepts one frame of any size, so nothing becomes
  unsendable; a close costs nothing, so it always gets through.
- A response the relay builds is cut to fit that budget rather than built to the
  frame count and then refused. A reconciliation round short of what the client
  asked for leaves the affected ranges open as fingerprints so the client drives
  another round, which is the same mechanism the frame count already used.
- A run that **cannot** be shortened waits for room instead of failing. The MLS
  handshake replay is the case: its length is the group's epoch count rather than
  anything the client chose, and truncating it would leave a member unable to
  decrypt. It waits per frame, and the connection ends only if that wait is
  exhausted, which distinguishes a peer that is slow from a peer that has stopped
  reading.
- `0x00F0 ephemeral` is retired and never used; under `enc: 1` the kind lives
  inside `ct`, so a relay told to shed one kind and keep every other could never
  tell them apart. The frames the relay may shed are `LIVE`
  (`specs/backend/relay/presence.md`) and `CALL` and `MEDIA`
  (`specs/backend/relay/calls.md`), and they are shed rather than downgraded:
  a downgrade is a claim about durable state, and there is no reconciliation for
  a presence beat or for audio.
- A subscriber that cannot keep up with live push is downgraded to
  reconciliation, told so in a frame, and catches up by range fetch. Slow
  consumers degrade to polling instead of stalling the fanout for everyone.
- Storage and database saturation return `quota` and `retry` respectively, never
  a silent accept.
- A workspace at `WEALD_RELAY_MAX_LOG_GB` returns `quota/log_budget_exhausted` on
  `SEND`, carrying the limit and no interval, and stores nothing. The budget is
  per workspace and is charged from the group's own workspace row, so a workspace
  at its ceiling refuses nobody else's writes and no workspace's bytes are ever
  charged to another. The check is inside the accept transaction and after the
  insert, so the ceiling is exact under concurrent writers rather than
  overshootable by one envelope per writer. Reaching it never triggers
  compaction: `lifecycle.md` holds that decision and its reasons.

The per-connection budget bounds one slow client's blast radius, and since
protocol version 3 there is a process-wide ceiling behind it:
`WEALD_RELAY_MAX_CONNECTIONS`, 256 by default, which at the 8 MiB per-connection
queue is two gibibytes at the absolute worst case. It was recorded here as a gap
for several releases, in these words: "nothing caps concurrent connections, so
instance memory is still the budget times however many connect". Calls made the
gap matter sooner, because a connection carrying one holds its queue busy rather
than nearly empty, so the cap shipped with them.

A connection past the ceiling is refused **before** the WebSocket upgrade, with
HTTP 503 and `Retry-After`, because refusing after it would mean allocating the
queues the cap exists to bound. There is no frame to refuse it in: the socket
does not exist yet. `unlimited` remains expressible for an operator who has sized
their instance and means it; the default is a number rather than `unlimited`
precisely because a default of `unlimited` would have been the old behaviour under
a new name.

`/readyz` reports `call_stats.connections` and `call_stats.connections_refused`,
so an operator can see the ceiling binding rather than infer it from a support
ticket.

### Connection deadlines

A slot is taken at the upgrade and given back when the reader loop ends, so
until protocol version 4 the cap above bounded how many sockets could be open
and bounded nothing about how long one could stay open having said nothing.
That made the cap the attack rather than the control: an unauthenticated
stranger could take every slot on a customer's relay by opening sockets and
sending no bytes, at the cost of one file descriptor each. Two deadlines close
it.

| Deadline | Variable | Default | Bounds |
| --- | --- | --- | --- |
| Handshake | `WEALD_RELAY_HANDSHAKE_TIMEOUT_MS` | 10000 | Upgrade to `AUTH_ACK`. The honest path is one signature; nothing legitimate needs ten seconds. |
| Idle | `WEALD_RELAY_IDLE_TIMEOUT_MS` | 300000 | Silence on an authenticated connection, before the liveness exchange below. Long on purpose: a quiet workspace is the ordinary case. |

Both are refused at `0` by the rule that refuses `WEALD_RELAY_MAX_CONNECTIONS=0`,
and neither takes `unlimited`, because unlimited is precisely the behaviour being
replaced.

The idle deadline is enforced by an **application-level** exchange and not by
TCP. When the interval elapses the relay sends a WebSocket ping and waits ten
seconds for anything at all to come back; any inbound message, including a ping
or a close, resets the interval and cancels an outstanding probe. TCP is the
wrong instrument here for the same reason it is the wrong instrument in the
replay drain above: the kernel on the other side goes on acknowledging segments
for a process that has stopped reading, so a socket that looks alive is not a
peer that is there, and the whole point of both mechanisms is to tell a slow peer
from a gone one. The full argument is in `transport-security.md`.

A connection closed on either deadline is sent `quota/rate_limited` carrying
`retry-after` and then closed, which is the close path a refusal already takes:
a client never gets a dropped connection without a frame, because it cannot
otherwise tell a decision from a network failure.

`/readyz` reports `call_stats.connections_closed_handshake_deadline` and
`call_stats.connections_closed_idle_deadline` beside `connections_refused`. An
operator needs to tell a deadline from a crash, and needs to tell the two
deadlines apart: refusals rising means the ceiling is binding, handshake closes
rising against a low connection count means somebody is parked on the connection
table, and idle closes rising is ordinary attrition from laptops closing and
mobile networks dropping connections without a FIN. They are counts with no
labels, like every other number on this surface.

## Abuse and denial of service

The relay has three surfaces reachable without workspace membership, and each is
bounded independently:

| Surface | Bound |
| --- | --- |
| `/join/<token>` landing page and static assets | Cached, no database read, per-IP rate limited. |
| Invite reserve and code attempt | 5 attempts per token, 100 per source IP per hour, Argon2id cost tuned so guessing is expensive for the attacker and unnoticeable for the joiner (`specs/backend/relay/invites.md`). |
| `CONNECT` and `AUTH` | Per-IP connection rate limit, a signature check before any database work beyond the access-set lookup, and a hard cap on unauthenticated connection lifetime: `WEALD_RELAY_HANDSHAKE_TIMEOUT_MS`, ten seconds by default, under "Connection deadlines" above. That clause described an intention rather than an implementation until protocol version 4, which is how a socket that never authenticated could hold a connection slot for as long as it liked. |

Everything else requires a key in the access set. An attacker who holds one can
consume bandwidth and quota and can read nothing, which is stated in
`specs/backend/relay/auth.md` and is why the limits above are sized for cost
control rather than for confidentiality.

### The inbound budget on `SEND`

Consuming bandwidth and quota is not free, and the envelope path is where it is
cheapest for an attacker and most expensive for the relay: a `SEND` costs a
decode, an authorization read and a Postgres transaction. So every `SEND` is
charged against a per-device budget, in frames and in bytes, over a one minute
window: `WEALD_RELAY_SEND_FRAMES_PER_MINUTE` and
`WEALD_RELAY_SEND_BYTES_PER_MINUTE`, sized in the Limits table of
`specs/backend/relay/wire.md`. The charge happens before the decode and
therefore before the transaction opens, because a budget charged after the
database has already done the work measures the damage rather than preventing
it.

Keyed by the authenticated device key rather than by connection, so a flooding
client cannot clear its allowance by reconnecting, and process-local, so it
bounds this instance's load rather than claiming a cluster-wide guarantee.

A frame over either limit is answered `quota/rate_limited`, carrying
`retry-after` in seconds and the limit that was met in `detail`, **and the
socket stays up**. That is the difference between this refusal and the deadline
closes above, and it is deliberate. A client that is merely fast is the ordinary
case on this path rather than the adversarial one, because a client flushing a
backlog writes its whole outbox in one pass; closing the socket would turn an
ordinary cold start into a reconnect storm, and would stop that connection's
`SUB`, `RECON` and `PUSH` traffic over a limit that was only ever about its
writes. `quota` is the class whose published client behaviour is exactly right:
wait the named interval, then come back.

The interval travels in `retry-after` and never in `detail`, which carries the
limit. A client must not treat the interval as the exact moment the window turns
over; it is a fixed window and the true wait is somewhere inside it, stated as a
full window on purpose so that a refused fleet does not synchronise onto one
instant.

Because the refusal names no envelope, a client must make **every**
unacknowledged envelope sendable again when it receives one, not only the frame
it believes was refused. Re-offering an envelope that was in fact accepted is
free and safe: a duplicate `hash` is answered with the `seq` the original was
given, so no cursor moves backwards.

Hosted instances sit behind the provider's own edge protection. Self-hosters get
the same in-process limits and a documented recommendation, not a requirement,
since a relay on a private network has no exposure to protect
(`specs/backend/relay/deployment.md`).

## Clocks

Expiry has one authority per decision. The relay evaluates every state it owns
against its own observed UTC time: invite redemption and reservation expiry,
provisional-grant expiry, recovery-session expiry, upload reservations and
retention grace periods. A client cannot extend any of those by setting its
clock back. Clients evaluate credentials they must reject before a relay round
trip, notably delegation certificates, against both local time and observed
relay time. Probation is deliberately not an expiry; it requires explicit
confirmation by a pre-existing authorizer. This split prevents a user clock
from reviving a server-side credential while preserving offline verification
where it is actually possible.

- The relay's `ts` on every envelope and the timestamp in the `AUTH` challenge
  give every client a continuous reference without introducing a trusted time
  service. The relay is not trusted for this, it is merely observed.
- A client whose local clock differs from the relay's observed time by more than
  **5 minutes** raises a clock warning in the encryption panel, naming the skew.
- While outside the bound it refuses to **issue** certificates or invites, since
  signing an expiry it cannot compute correctly is how a 24-hour credential
  becomes a 24-day one. It continues to read, write and sync normally, because
  refusing to work would be a worse failure than a stale expiry check.
- Verification is skew-tolerant in the safe direction only: a credential is
  accepted while it is valid under both the local clock and the observed relay
  time, and rejected when either says it has expired.

## Key packages

A device that runs out of key packages cannot be added to a group and becomes a
pending add (`specs/backend/relay/channels.md`), which is a visible delay rather
than an error, but a device that runs out routinely turns every add into one.

- Each device maintains a target of **20 unused key packages** per workspace,
  topped up on connect and whenever the relay reports the count below half.
- The relay reports the connecting device's own unused count on `AUTH`. It is
  the device's own number, so this discloses nothing.
- The 100 outstanding cap in `specs/backend/relay/wire.md` remains an
  exhaustion bound rather than a target.
- Key packages expire after 90 days and expired ones are refused for adds, so a
  device offline for a quarter is added with a fresh package rather than one
  whose lifetime assumptions have lapsed.

## Availability and self-monitoring

`WEALD_RELAY_WRITE_MODE=read_only` is a local maintenance mode: durable `SEND`
returns `denied/service_read_only`, while `SUB`, `RECON`, backups and recovery
reads remain available. The state and a non-content reason code appear in
`AUTH` and `/readyz`; clients never guess it from a control-plane clock. The
relay has no billing client. Hosted orchestration of the setting is specified in
`cloud/service-lifecycle.md`.

- Public `/healthz` is liveness only. Detailed `/readyz` is private and reports
  database reachability, storage reachability, access-set enforcement state,
  any frozen retention chain, and whether the running build is behind the
  release feed (`specs/backend/relay/server.md`).
- Metrics are aggregate by default. Per-group labels are off unless
  `WEALD_RELAY_METRICS_GROUP_LABELS=on`, which exists for a self-hoster debugging
  their own instance and is never enabled on hosted, so that per-group counts are
  not merely unretained by the control plane but unavailable to it
  (`specs/backend/cloud/billing.md`).
- Structured logs carry group ids at debug level only and never carry envelope
  bytes, header or body, at any level.

The hosted SLO and its measurement live in
`specs/backend/cloud/compliance.md`. This document is what the binary does; that
one is what we promise about it.
