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
| `limit` | Over a per-principal ceiling on a write the client can simply stop making. Retry after the named interval, on the frame only: the connection stays up and durable traffic is unaffected. |

`limit` arrived with protocol version 4 and is the only class this protocol has
ever added. Adding a class is a breaking change by the mechanical test in
`../governance.md` section 3, because clients branch on the class before the code,
so it rides the same version bump the `WAKE` frame does rather than arriving as a
clarification. It exists rather than being folded into `quota` because the two
mean different things to the person on the other end: `quota` is a workspace over
an allowance an operator or an invoice can raise, and it belongs in a sentence
naming the lever that clears it, while `limit` is one device's own behaviour and
the honest client response is to slow down and say nothing to anybody. Folding it
into `quota` would have put "you are over your plan" in front of a user whose
phone rotated a push handle in a loop.

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
| `denied/invite_code_invalid` | denied | Wrong code half. Counts against the 5-per-token attempt budget. Answered inside the `JOIN` body's own response rather than as a frame-level error, which is why this row and the two below it are absent from the Rust `ErrorCode` enum and present in the client's `RelayError.Code`: the relay does not emit them as `ERROR` frames, and a client that could not name a code it is shown would render it as an unknown error. | attempts remaining |
| `denied/invite_seat_spent` | denied | Every seat on the invite is taken. Carried by the `JOIN` response; see the note on `invite_code_invalid`. | |
| `denied/invite_expired` | denied | Past the invite's expiry, evaluated against the client's own clock. Carried by the `JOIN` response; see the note on `invite_code_invalid`. | |
| `denied/wrap_not_newer` | denied | A `WRAP` frame whose epoch does not advance the stored wrap in that `(group, tag)` slot. The bytes are well formed and would have been accepted an epoch ago, which is the replay the monotonicity rule in `../../relay/groups.md` refuses. The client re-derives the current epoch's wrap; it never resends this one. | the stored epoch |
| `denied/group_frozen` | denied | Group frozen by a retention chain or an in-flight commit. | state hash |
| `quota/storage_exhausted` | quota | Instance storage limit reached. | retry-after, the limit |
| `quota/rate_limited` | quota | Per-IP or per-connection rate limit. | retry-after |
| `quota/seats_exhausted` | quota | Workspace seat limit. | the limit |
| `quota/group_ingress_limited` | quota | Two things, both ingress aimed at one group. The admission-blind abuse budget in `../../relay/wire.md`: 8 MiB per principal per target group per minute, 64 MiB per workspace per minute, or 32 MiB of undelivered backlog, charged before persistence. And, since protocol version 3, the media budgets in `../../relay/calls.md`: 60 `MEDIA` frames per stream per second, 1 MiB per connection per minute, and 32 distinct streams tracked per connection. | retry-after, the limit |
| `version/protocol_unsupported` | version | `v` unsupported by this relay. | supported range |
| `version/below_client_floor` | version | Relay's version is below the client's pinned floor. | relay version |
| `reject/push_handle_malformed` | reject | A `WAKE` `Register` whose handle is not exactly 16 bytes, whose `categories` bitmask is empty or carries an undefined bit, or whose `expires_at` has already elapsed; and, in the other direction, a `Capability` whose `register_url` is not `https` or is longer than 512 bytes, which the client refuses rather than registering against. A reject and not a denial because every one of those is permanently wrong as sent, so resending would be wrong in the same way. | |
| `denied/push_not_configured` | denied | A well-formed `Register` sent to a relay with `WEALD_RELAY_PUSH=off`, which is the default and a supported deployment rather than a degraded one. Denied rather than rejected because the frame is correct and the answer would change if the operator changed one variable; the client re-reads state by sending `Query` and never by retrying the registration. | |
| `limit/push_registration_rate` | limit | More than five `WAKE` registrations per principal per hour. Rotation is weekly by design, so five is generous, and the ceiling exists because a registration is a write and a device with a loop must not be one. Refused on the frame only. | retry-after, the limit |
| `retry/push_backpressure` | retry | No database on a `WAKE` registration. Fails closed like every other admission path. Distinct from `retry/backpressure`, which is the relay's own receive queue, and distinct from the wake path's bounded outbound queue, which drops the oldest and increments a counter rather than answering anybody, because a wake has nobody to answer. | retry-after |

`quota/group_ingress_limited` was added to this table in step 4. It was specified
in `../../relay/wire.md` and named in the protocol document, but had no row here,
which meant `scripts/spec-check.sh` could not see that it also had no negative
vector: a code invisible to the check that exists to close this gap. It is written
here with its class prefix, which the prose in `wire.md` omits.

Until protocol version 3 it was a code with a row here, a paragraph in `wire.md`
and **no reference anywhere in `backend/wealdrelay/src/`**. That is the worse
half of the failure this table exists to catch: a code invisible to the check is a
gap somebody will find, and a code visible to the check but enforced nowhere is
protection somebody is relying on. The media limits in `../../relay/calls.md` are
where it starts being emitted, and `backend/wealdrelay/tests/calls_unit.rs` and
`tests/calls_socket.rs` assert this exact code rather than merely that an error
occurred.

One rule about it is specific to the media path and belongs here because it is
about what a client is told rather than about what is enforced: a connection over
a media limit is answered **at most once a second**. Every frame over the limit is
refused either way; what is economised is the complaint. Answering each frame of a
600-per-second flood is an amplifier, and the answers queue on the flooder's own
bounded outbound queue, so a relay that complained about each one would fill that
queue and turn a rate limit into a disconnect. A client learns the fact and reads
`retry-after`; the next 599 answers would say the same thing.

Its vectors landed separately, and all three of the original limits get one: the per-principal
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

RFC 9457 Problem Details. Every `type` is
`https://docs.weald.team/errors/<code>` and resolves to a real docs page.
`spec-check.sh` fails on a type declared in `../api/openapi.yaml` that is
missing here, and on a code here that no operation declares.

| Code | HTTP | Meaning | Retry guidance |
| --- | --- | --- | --- |
| `idempotency_key_reused` | 409 | Same key, different canonical request body. | Never. Use a new key. |
| `idempotency_key_required` | 400 | Mutation sent without `Idempotency-Key`. | After adding one. |
| `bootstrap_handoff_already_used` | 409 | The one-and-only handoff has been claimed. There is no reissue. | Never. The remedy is `POST /instances/:id/reprovision`. |
| `bootstrap_instance_enrolled` | 409 | The relay reports a non-zero admitted principal count. | Never. |
| `step_up_required` | 401 | No Clerk reauthentication within 15 minutes. | After step-up. |
| `step_up_expired` | 401 | Step-up older than 15 minutes at the time of the action. | After step-up. |
| `insufficient_role` | 403 | Caller is not an owner for an owner-only action. | Never for this actor. |
| `account_scope_violation` | 403 | Loaded resource does not belong to the session's `org_id`. Logged as a security event. | Never. |
| `csrf_token_invalid` | 403 | Browser mutation without a valid same-site CSRF token. | After reload. |
| `instance_not_found` | 404 | Unknown, or outside the caller's account. Deliberately indistinguishable. | Never. |
| `operation_not_found` | 404 | Unknown operation, or outside the caller's account. | Never. |
| `pending_intent_expired` | 409 | Checkout intent older than 24 hours. | Start a new checkout. |
| `pending_intent_conflict` | 409 | Account already has an unsettled intent for this region and tier. | After the first settles or expires. |
| `subscription_not_settled` | 409 | Checkout completed but settlement is not `paid` or `no_payment_required`. | Reconciled from Stripe. Poll the operation. |
| `region_immutable` | 409 | Region change attempted after creation. | Never. Requires backup, restore and a hostname change. |
| `instance_not_in_valid_state` | 409 | Action illegal for the instance's lifecycle state. | After the state changes. See `../state-machines/instance-lifecycle.md`. |
| `legal_hold_active` | 409 | Destruction, backup-key erasure or purge blocked by a hold. | After release. |
| `legal_hold_release_forbidden` | 403 | A legal-process hold cannot be released by the customer. | Never for this actor. |
| `domain_reserved_elsewhere` | 409 | Hostname is live, in grace, or detached within 30 days for another account. | After 30 days. |
| `domain_verification_failed` | 409 | TXT challenge absent or not exact. Re-checked immediately before attach. | After DNS propagates. |
| `domain_invalid` | 400 | Public suffix, IP literal, wildcard or a Weald-owned domain. | Never. |
| `domain_detach_failed` | 502 | Provider binding could not be confirmed gone. Blocks destruction and pages operations. Never silently skipped. | Automatic. |
| `export_window_closed` | 409 | Past the deadline in `service-lifecycle.md`. A backup is not an undeclared extension of the export window. | Never. |
| `reprovision_window_closed` | 409 | More than 7 days since creation. | Never. |
| `reprovision_confirmation_required` | 400 | Relay reports an admitted principal and the owner did not type the hostname. | After confirming. |
| `account_has_live_instances` | 409 | `DELETE /account` before every instance is destroyed. Deleting the login before cancelling the subscription strands a paying customer behind a door they cannot open. | After teardown. |
| `rate_limited` | 429 | 100/min general, 5/min on bootstrap, restore and destroy. | `Retry-After`. |
| `provider_unavailable` | 502 | Render or R2 failed. The operation retries. | Automatic. Poll the operation. |
| `internal_error` | 500 | Unclassified. Carries a request id and nothing else. | Automatic. |

No Problem Details response ever echoes a secret, a provider handle, a raw
webhook payload, bootstrap material, or any workspace data. `instance_not_found`
and `operation_not_found` are returned for both "does not exist" and "not
yours", because a distinguishable 403 is an account enumeration oracle.
