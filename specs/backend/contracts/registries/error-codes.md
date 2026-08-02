# Registry: error codes

One registry for every stable code the system emits. Two families, deliberately
separate, because they cross different trust boundaries and are read by
different code.

Nothing outside this file may invent a code. `scripts/spec-check.sh` fails if a
code appears in a spec, in the OpenAPI document, or in source, and is not here;
and fails if a relay code here has no negative vector in
`../wire/vectors/manifest.json`.

## A. Relay frame errors

Emitted in `ErrorBody`. Class first, so a client branches on the class and only
then on the code. Classes are defined in `specs/backend/relay/operations.md` and
are not extensible without a protocol version bump.

| Class | Client behaviour |
| --- | --- |
| `retry` | Transient. Exponential backoff with jitter, resend verbatim, never renumber an author chain link. |
| `reject` | Permanently wrong as sent. Do not retry. Surface as a defect, log locally, keep the payload. |
| `denied` | Well formed, not permitted now. Do not retry blind. Re-read the named state and act. |
| `quota` | Over a limit. Retry after the named interval, or surface the limit with the lever that clears it. |
| `version` | Unsupported or below the pinned floor. Abort the connection. Never silently continue. |

| Code | Class | Emitted when | Carries |
| --- | --- | --- | --- |
| `retry/backpressure` | retry | Receive queue full or database saturated. Never a silent accept. | retry-after |
| `retry/lock_timeout` | retry | Per-group counter lock timed out. | retry-after |
| `retry/failover` | retry | Process or database failover in progress. | retry-after |
| `reject/malformed_header` | reject | Envelope decodes but a field has the wrong size or is empty. | |
| `reject/noncanonical_cbor` | reject | Indefinite length, unsorted keys, non-shortest integer, tag or float. | |
| `reject/hash_mismatch` | reject | `hash` is not BLAKE3 over `(v, enc, group, epoch, ct)`. | |
| `reject/envelope_too_large` | reject | `ct` exceeds the configured ceiling. | the ceiling |
| `reject/unknown_required_field` | reject | Unknown map key in the Envelope. Envelope is closed; payload kinds are open. | |
| `denied/plaintext_refused` | denied | `enc: 0` under `WEALD_RELAY_MIN_ENC=mls`. Always on hosted, where the setting is not configurable. | |
| `denied/writer_not_in_access_set` | denied | Authenticated session device absent from the current `ACCESS` set. | state hash |
| `denied/group_unknown` | denied | Group id not known to this relay. | |
| `denied/service_read_only` | denied | Durable `SEND` under `WEALD_RELAY_WRITE_MODE=read_only`. `SUB`, `RECON`, backups, export and recovery reads continue. | non-content reason code |
| `denied/invite_code_invalid` | denied | Wrong code half. Counts against the 5-per-token attempt budget. | attempts remaining |
| `denied/invite_seat_spent` | denied | Every seat on the invite is taken. | |
| `denied/invite_expired` | denied | Past the invite's expiry, evaluated against the client's own clock. | |
| `denied/wrap_not_newer` | denied | A `WRAP` frame whose epoch does not advance the stored wrap in that `(group, tag)` slot. The bytes are well formed and would have been accepted an epoch ago, which is the replay the monotonicity rule in `../../relay/groups.md` refuses. The client re-derives the current epoch's wrap; it never resends this one. | the stored epoch |
| `denied/group_frozen` | denied | Group frozen by a retention chain or an in-flight commit. | state hash |
| `quota/storage_exhausted` | quota | Instance storage limit reached. | retry-after, the limit |
| `quota/rate_limited` | quota | Per-IP or per-connection rate limit. | retry-after |
| `quota/seats_exhausted` | quota | Workspace seat limit. | the limit |
| `quota/group_ingress_limited` | quota | The admission-blind abuse budget in `../../relay/wire.md`: 8 MiB per principal per target group per minute, 64 MiB per workspace per minute, or 32 MiB of undelivered backlog. Charged before persistence. | retry-after, the limit |
| `version/protocol_unsupported` | version | `v` unsupported by this relay. | supported range |
| `version/below_client_floor` | version | Relay's version is below the client's pinned floor. | relay version |

`quota/group_ingress_limited` was added to this table in step 4. It was specified
in `../../relay/wire.md` and named in the protocol document, but had no row here,
which meant `scripts/spec-check.sh` could not see that it also had no negative
vector: a code invisible to the check that exists to close this gap. It is written
here with its class prefix, which the prose in `wire.md` omits.

Its vectors landed separately, and all three limits get one: the per-principal
per-group minute, the per-workspace minute, and the standing undelivered backlog.
Three more sit beside them and are the reason the set is worth reading. One holds
exactly at the per-principal boundary and must be accepted, because wire.md sizes
the budget so that eight maximum-size changes a minute stay above interactive use
and a guard that refuses *at* the limit is an outage rather than a cost control.
One asserts the charge lands before persistence, so a refused `SEND` leaves the
head, the seq and the storage footprint untouched and never takes the per-group
counter lock. One asserts a `BLOB` past the budget is still accepted, because
`wire.md` routes media off this path and the cheapest wrong implementation of the
whole guard is a single counter over all inbound bytes, which would pass every
other vector while breaking media upload for every paying customer.

Every error carries the class, the code, and where relevant the current state
hash so the client can rebase rather than guess. `SEND` never returns `retry`
for contention, only for infrastructure. That property is what the absence of a
relay-maintained head chain buys, and a `retry/lock_timeout` rate above noise is
therefore a regression alarm rather than a capacity signal.

## B. Control plane problem types

Not in this repository. The hosted service's HTTP API returns RFC 9457 Problem
Details, and its registry of `type` values belongs to that service rather than
to the relay protocol: no conformant client or relay ever produces or consumes
one. See `specs/backend/hosted-service.md` for the boundary.

Section A above is the complete error surface of the relay wire protocol, and
every code in it has a conformance vector in `../wire/vectors/`.
