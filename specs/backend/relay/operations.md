# Relay: running it under load and under attack

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
- `ephemeral` (`0x00F0`) is the only kind that may be shed under pressure, which
  is why it is the only kind the relay is permitted to drop at all.
- A subscriber that cannot keep up with live push is downgraded to
  reconciliation, told so in a frame, and catches up by range fetch. Slow
  consumers degrade to polling instead of stalling the fanout for everyone.
- Storage and database saturation return `quota` and `retry` respectively, never
  a silent accept.

The per-connection budget bounds one slow client's blast radius. It is not yet a
process-wide ceiling: nothing caps concurrent connections, so instance memory is
still the budget times however many connect.

## Abuse and denial of service

The relay has three surfaces reachable without workspace membership, and each is
bounded independently:

| Surface | Bound |
| --- | --- |
| `/join/<token>` landing page and static assets | Cached, no database read, per-IP rate limited. |
| Invite reserve and code attempt | 5 attempts per token, 100 per source IP per hour, Argon2id cost tuned so guessing is expensive for the attacker and unnoticeable for the joiner (`specs/backend/relay/invites.md`). |
| `CONNECT` and `AUTH` | Per-IP connection rate limit, a signature check before any database work beyond the access-set lookup, and a hard cap on unauthenticated connection lifetime. |

Everything else requires a key in the access set. An attacker who holds one can
consume bandwidth and quota and can read nothing, which is stated in
`specs/backend/relay/auth.md` and is why the limits above are sized for cost
control rather than for confidentiality.

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
`specs/backend/hosted-service.md`.

- Public `/healthz` is liveness only. Detailed `/readyz` is private and reports
  database reachability, storage reachability, access-set enforcement state,
  any frozen retention chain, and whether the running build is behind the
  release feed (`specs/backend/relay/server.md`).
- Metrics are aggregate by default. Per-group labels are off unless
  `WEALD_RELAY_METRICS_GROUP_LABELS=on`, which exists for a self-hoster debugging
  their own instance and is never enabled on hosted, so that per-group counts are
  not merely unretained by the control plane but unavailable to it
  (`specs/backend/hosted-service.md`).
- Structured logs carry group ids at debug level only and never carry envelope
  bytes, header or body, at any level.

The hosted SLO and its measurement live in
`specs/backend/hosted-service.md`. This document is what the binary does; that
one is what we promise about it.
