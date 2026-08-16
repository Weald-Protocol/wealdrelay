# Relay: voice calls

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only, no dev tier,
> no test mode, no staging tier. `local` and `ci` are not an exception because
> they reach no vendor at all. A gate that cannot reach production configuration
> fails; it never degrades to a mock, a stub, a fake or a skip.

Protocol version 3 adds two frames, `CALL` and `MEDIA`, and nothing else. They
carry a voice call between members of a group: the signalling that starts and
ends it, and the encrypted audio that runs between. This document is the whole of
the relay's half. `specs/peer-calls.md` is the design of record and covers the
client, the codec, the key schedule and the P2P upgrade that comes later.

## What the relay does and does not know

It reads three things: a call id, a group id, and a small cleartext `kind` on the
signalling frame. That is the complete list.

`CALL.body` and `MEDIA.ct` are opaque. The call key is derived from the MLS group
with the `weald call v1` exporter label and the relay holds no key, exactly as it
holds none for an envelope. No counter, metric or log line here carries a call
id, a group id, a principal or anything derived from either payload; that rule is
`src/hub.rs`'s and `src/health.rs`'s already and it applies unchanged.

Metadata is not hidden and `specs/backend/relay/overview.md` says to say so
plainly, so: an operator can see that a call is happening, how many are open,
how much traffic is moving and whether frames are being shed. They cannot see who
is on one, which group it belongs to, or a single byte of what is said.

## The frames

### `CALL`, frame tag 23

```
Call {
  call_id: [16]byte     // client-chosen, opaque, compared and never derived from
  group:   [32]byte     // group id, checked against the session's access set
  epoch:   u64          // MLS epoch, so a receiver can pick the key
  kind:    u8           // offer 1, answer 2, decline 3, bye 4
  body:    bytes        // sealed, opaque, <= 4 KiB
}
```

Client to relay and relay to client, the same shape in both directions, like
`LIVE` and `HANDSHAKE`.

`kind` is cleartext and it is the one field of either frame the relay interprets.
It has to be, and this is the same argument that made `LIVE` a frame: the relay
decides call membership from it, and membership is what lets `MEDIA` be routed
without a database read. Everything about *what* is being offered or answered is
in the sealed body.

The set is closed. A kind outside it is refused with
`reject/malformed_header` rather than forwarded, because a relay that forwarded
an unrecognised kind would be a relay whose routing semantics a future client
could change without a version bump. `candidate`, for the ICE exchange in the
P2P step, is a fifth number added under a version bump when that step lands.

The relay's whole behaviour on receipt:

1. Refuse unless the session is `Ready`. No bootstrapping case and no pre-auth
   case; `JOIN` remains the only pre-auth frame.
2. Refuse unless `kind` is in the set.
3. Refuse above 4 KiB with `reject/envelope_too_large`.
4. Charge the per-connection `CALL` budget below.
5. Refuse unless the group is known and the authenticated device is in its
   access set, by exactly the check `SEND` uses.
6. Refuse with `denied/writer_not_in_access_set` if `call_id` is already open on
   this process against a **different group**, whichever kind it is. Both halves
   matter and the leaving half is the less obvious one: leaving is applied to the
   call id and fanout is at the group named on the frame, so a `bye` naming a
   second room the sender happens to be admitted to would drop the sender from
   the call while telling the wrong room about it, and the people actually on the
   call would hold a participant the relay had already stopped routing to. A call
   is a conversation inside one room, and the id is bound to that room when the
   call opens.
7. Apply it to the call registry: `offer` and `answer` join, `decline` and `bye`
   leave. Leaving a call you were not in is not an error, and neither is leaving
   a call this process is not carrying: step 6 refuses a *mismatch*, not an
   absence.
8. Fan out to every other session subscribed to that group that negotiated
   version 3 or higher. Not to the sender.
9. Answer the sender with nothing at all.

An organization agent's gateway is an authenticated principal in the access set,
so an offer fanned out at the group reaches it like any other subscriber. It
answers `decline` within one second with a bounded reason, because code with no
arm for a frame ignores it and an ignored offer renders as a phone ringing
forever. Voice with a bot stays where it already works, on the local
human-to-model path in `Sources/Voice/Calls/`, which shares only the word "call"
with this subsystem. What a real agent participant would require is written down
in `specs/agents/networked/phases-live.md` and is not built.

Fanout is at the **group** rather than at the call, and that is deliberate: an
offer has to reach somebody who is not in the call yet, which is the entire point
of an offer. It is also why signalling is rate limited an order of magnitude
below media: a frame that reaches every subscribed device has to be rare.

### `MEDIA`, frame tag 24

```
Media {
  call_id: [16]byte     // the call this belongs to
  stream:  [4]byte      // per-call stream id, also the first half of the client's nonce
  seq:     u64          // the sender's own per-stream counter
  ct:      bytes        // AES-256-GCM frame, opaque, <= 1500 bytes
}
```

**No group field, deliberately.** The group was checked when this connection was
admitted to `call_id` by a `CALL` frame that *was* access-set checked, and
repeating the check here would put a Postgres read on a path carrying fifty
frames a second per stream. `specs/peer-calls.md` section 3 forbids that in the
same breath as the `seq` counter and for the same reason.

`seq` is the sender's counter, copied and never interpreted. It is emphatically
not the per-group `seq` in `src/accept.rs`: that one is an
`UPDATE ... RETURNING` inside a transaction, and routing audio through it would
serialise every writer in the group behind the call and add a database round trip
to every audio frame. The receiver's jitter buffer is the only reader: out of
order is reordered, late is dropped, missing is concealed.

The relay's whole behaviour on receipt:

1. Refuse unless the session is `Ready`.
2. Refuse above 1500 bytes with `reject/envelope_too_large`, on the declared
   length, before the payload is copied or charged anywhere.
3. Charge the media budget below. A refusal is reported at most once a second;
   see "Why a refused flood is answered once".
4. Look `call_id` up in the registry. A connection that is not a participant is
   refused with `denied/writer_not_in_access_set`, which is exactly what it is: a
   claim on a conversation this session was never admitted to.
5. Copy it to the other participants of that call. Not to the group, and not to
   the sender.
6. Answer the sender with nothing at all.

No database, no hash, no sequence number, no group lookup, anywhere on that path.

## Neither frame is ever persisted

Not to a table, not to a log line, not to a metric label. They are never given a
sequence number, never returned by a `RECON` round, never attested, and never
named in a `drop_before` manifest. They are the only two frames the relay may
shed under pressure, which is the property that makes them different in kind from
an envelope rather than merely different in size.

The negative proof is a zero-row delta against a real Postgres, measured over
every table the relay writes to, immediately before and immediately after a whole
call: `backend/wealdrelay/tests/calls_socket.rs` and
`build-evidence/step-35/call-transcript.txt`.

## The registry, and why one exists at all

A beat is addressed to a group and the group is on the frame, so `LIVE` needs no
state. Media cannot work that way, for two reasons.

Cost: `authorize_group` is a Postgres read and a two-party call is a hundred
frames a second. Fanout width: a group is a workspace room and a call is two to
five people in it, so fanning media at the group would multiply egress by every
subscribed device not on the call and hand each of them a stream it did not ask
for.

So `CALL` is the checkpoint and `MEDIA` is the cheap path behind it. The registry
holds, per open call, the group it belongs to and the connections in it. Nothing
else. A call id already open against a different group is refused even when both
groups are admitted for the sender, because a call is a conversation inside one
room; that is what makes a guessed or observed call id worthless.

## One process, stated plainly

The registry is process-local, like the hub. Two relay processes sharing one
Postgres do **not** share it, so a call whose participants land on different
processes does not connect.

This is not papered over and it is not new: fanout has always been process-local,
and `WEALD_RELAY_REDIS_URL` has always been the way a deployment declares a second
instance. What is new is that the consequence is worse for calls than for chat.
Chat degrades to reconciliation across a process boundary and loses nothing
durable. A call has no reconciliation to degrade to; it would connect and be
silent, which is the failure mode nobody reports because it looks like a bad
network.

So `WEALD_RELAY_CALLS=on` alongside a declared second instance is a **startup
refusal**, the same shape `WEALD_RELAY_LIVE_FANOUT` already has and for a sharper
reason. A relay that will not start is a page a human reads.

This is the first thing in this codebase that would genuinely require the Redis
that `WEALD_RELAY_REDIS_URL` declares and no code uses. It is recorded here as a
known bound of this release rather than as a defect, and it is what a
multi-instance operator must read before turning calls on.

## Shedding, not downgrading

Media is charged against the existing `SEND_QUEUE_BYTE_BUDGET` (8 MiB) and
`SEND_QUEUE_BOUND` (256 frames), not given a budget of its own, so a call cannot
starve chat.

On overflow the relay **sheds the media frame**. It does not downgrade the
subscriber to reconciliation, because a downgrade is a claim about durable state
and there is no reconciliation for audio, so telling a client to reconcile
because a packet was late would be a lie about its log. It does not close the
connection, because one late packet is not a reason to drop a call. It does not
tell the sender, because the next frame is 20 ms away and a per-frame answer
would double the traffic on exactly the connection that is already too slow.

The shed is visible to the operator and nowhere else: `call_stats.media_shed` on
`/readyz`, a bare count with no label.

## Why a refused flood is answered once

A stream at ten times its rate is 600 frames a second. Answering each refusal
turns one flood into two, which is the amplification an open resolver has, and
the answers are queued on the flooder's own bounded outbound queue, so a relay
that complained about every frame would fill that queue and drop the connection.
A rate limit that turns into a disconnect is a denial of service an attacker can
aim at somebody else's call.

So a connection is told it is over a media limit at most once a second. It learns
the fact and `retry_after` tells it when to come back; the next 599 answers would
say the same thing. Nothing about enforcement changes: every frame over the limit
is refused either way, and what is economised is the complaint.

## Limits

| limit | value | code when exceeded | `retry_after` | `detail` |
| --- | --- | --- | --- | --- |
| `MEDIA` frames per stream per second | 60 | `quota/group_ingress_limited` | 1 | 60 |
| `MEDIA` bytes per connection per minute | 1 MiB | `quota/group_ingress_limited` | 60 | 1048576 |
| distinct streams tracked per connection | 32 | `quota/group_ingress_limited` | 1 | 32 |
| max `MEDIA.ct` bytes | 1500 | `reject/envelope_too_large` | | 1500 |
| `CALL` frames per connection per minute | 120 | `quota/rate_limited` | 60 | 120 |
| max `CALL.body` bytes | 4096 | `reject/envelope_too_large` | | 4096 |
| participants per call | 5 | `quota/rate_limited` | 5 | 5 |
| concurrent calls per instance | `WEALD_RELAY_MAX_CONCURRENT_CALLS` | `quota/rate_limited` | 5 | the ceiling |
| calls opened per connection | a quarter of the ceiling, at least 1 | `quota/rate_limited` | 5 | the ceiling |
| concurrent connections per instance | `WEALD_RELAY_MAX_CONNECTIONS` | HTTP 503 with `Retry-After` | | |

The per-connection share exists because the instance ceiling is a finite table
shared by every workspace the process carries, and a finite table with no
per-source share is a table one source takes. A call is created by the first
`Offer` naming a fresh id and released only when its last participant leaves, so
before the share one admitted device sending fresh call ids inside its 120 frames
a minute held every slot for the life of its socket, and every other customer's
calls were refused (WEALD-340). The number and its reasoning are the connection
table's: at most a quarter, never less than one, released as calls end. It is
spent only on *opening* a call, so answering a call somebody else opened is never
refused by it, and the refusal reuses `quota/rate_limited` because the client's
correct next move is the same one and a distinct code would tell an attacker
which of the two ceilings it found. The operator's distinction is
`call_stats.calls_share_refused`, which is where it is actionable.

One code for the three media limits and three different intervals, which is not
an inconsistency. The code is what a client *branches* on and its correct
response to all three is identical, so three codes would be three things to treat
the same and three ways for an observer to learn which limit a peer hit. The
interval is an instruction to the sender about its own traffic: a client told to
come back in a second against a byte window that resets in fifty-nine would be
refused fifty-nine more times, which is the flood the once-a-second answer exists
to prevent, arriving by the front door. `detail` names the limit that was hit for
the same reason, and neither leaks anything the sender did not already know,
because both go only to the connection that sent the frame.

The two join refusals name an interval even though neither clears on a timer.
They used to name none, and that reads as tidier than it is. `quota` is defined
by `../contracts/registries/error-codes.md` as "retry after the named interval",
and a client is entitled to sort an answer it should act on from one it should
wait out: the Android client drops a non-terminal error carrying no interval, so
a call refused by a full instance or a full call rang out its whole forty-five
seconds and then said "no answer", which names the wrong cause to the one person
who could have acted on the right one. Five seconds, and it is a suggestion
rather than a window that provably clears, because both of these free up when
somebody hangs up. That is the right shape for this class anyway: the interval on
a fixed window is when the window resets, and the interval here is how long to
wait before asking again. `denied/writer_not_in_access_set` from a call id open
against another group names none, because it is not a quota and will be refused
identically forever.

`quota/group_ingress_limited` is the code `src/frame.rs` has carried since step 2
with nothing referring to it. A limit the spec claims and the code does not
enforce is worse than no limit, because it is protection somebody is relying on;
this is where it starts being enforced.

Sixty frames a second against a codec producing fifty, so a client that jitters a
frame across a window boundary is not punished and a client at ten times the rate
is. Five participants because relayed egress grows as n(n-1) and five is where
the quadratic term stops being free.

Every one of these windows is a fixed window over the relay's own observed time,
and that time is a wall clock: `health::Clock::System` reads `SystemTime`, so
`now_ms` steps backwards whenever NTP corrects the machine. **A window whose
start is in the future is a new window**, in both the byte counter and the
per-stream table, and an entry stamped after the current reading is expired
rather than kept.

This is a correctness rule and not a nicety. A window that asked only whether
enough time had elapsed answers "no" across a backwards step, so the byte counter
would freeze at whatever it had spent and the stream table would prune nothing:
an ordinary one second correction would refuse a live call's audio for up to a
minute, and a connection that had touched all 32 stream ids would answer
`quota/group_ingress_limited` to every new stream for just as long. It gives an
attacker nothing, because no peer can move the relay's clock; the only party who
can is the operator's own time daemon. The same rule applies to the per-connection
`CALL`, `LIVE` and `KEYS` budgets in `src/session.rs`, which share the window
type. Proved by `tests/calls_session.rs` and `tests/calls_properties.rs`, one
deterministic test and one property each side.

The connection cap closes a gap `specs/backend/relay/operations.md` had recorded
in words: "nothing caps concurrent connections, so instance memory is still the
budget times however many connect". It defaults to 256, which at the 8 MiB
per-connection queue ceiling is two gibibytes at the absolute worst case.
`unlimited` remains expressible for an operator who has sized their instance and
means it. Refusal happens **before** the WebSocket upgrade, because refusing
after it would mean allocating the queues the cap exists to bound.

## Nagle

The relay clears `TCP_NODELAY` on its public listening socket, and every accepted
socket inherits it. A 20 ms media frame is exactly the traffic Nagle was designed
to coalesce, and coalescing it is pure added latency with no bandwidth won,
because the frames are already the size they are going to be.

Inheritance is a platform property rather than a hope, and it is asserted rather
than assumed: `tests/calls_capacity.rs` sets the option through the relay's own
function, performs a real accept, and reads the option back off the accepted
socket, with a control socket beside it to prove the assertion is testing the
call. The observability listener is left alone; it carries request-response JSON,
which is what Nagle is good for.

The option is set on the listener rather than on each connection because
`axum::serve` in 0.7 takes the listener by value and never hands this crate the
accepted stream. Reaching it would mean a direct `hyper` dependency and a
hand-rolled accept loop, and `specs/peer-calls.md` section 4 spends the entire
dependency budget on having neither.

## Configuration

| variable | shape | default |
| --- | --- | --- |
| `WEALD_RELAY_CALLS` | `on` \| `off` | `off` |
| `WEALD_RELAY_MAX_CONCURRENT_CALLS` | a positive integer | none, and required when calls are on |
| `WEALD_RELAY_MAX_CONNECTIONS` | a positive integer \| `unlimited` | 256 |

Every one of them is in `specs/backend/build/env-registry.json`, which is the
single source of truth; the table above is a reading aid and the registry decides.

`off` by default, unlike `WEALD_RELAY_LIVE`, and the asymmetry is the decision. A
beat every twenty seconds is the ordinary shape of the app. A sustained media
stream is capacity an operator has to have sized for, so it is opted into, and
the act of opting in is the same act as stating the ceiling.

`WEALD_RELAY_MAX_CONCURRENT_CALLS` has no default and deliberately never will.
Call capacity is a sizing decision about one instance's bandwidth; a relay that
guessed would be a relay whose ceiling nobody chose and whose operator meets it as
a refusal during a call. Setting it with calls off is refused too, for the reason
an empty value is refused: a setting the binary accepts and does not honour is one
an operator reads back and believes.

A relay with calls off answers both frames with `version/protocol_unsupported`,
which a version 3 client reads as calls being unavailable on this relay: the same
thing it reads from a version 2 relay, and a different thing from a call that
failed. It is a posture, not a fault, and durable traffic on the same socket is
unaffected.

## Version negotiation

`PROTOCOL_VERSION` is 3 and `MIN_PROTOCOL_VERSION` stays 1. `CONNECT` keeps its
single field as the client's maximum offer and the relay selects the lower of the
two ceilings, so a version 1 or 2 client still decodes, still connects and simply
never receives a frame it does not know. Fanout filters on the negotiated version
at 3 for both call frames, exactly as it filters at 2 for `LIVE`.

## What an operator can see

On `/readyz`, on the private listener only:

- `calls`: `on` or `off`
- `call_stats.open`: calls open right now
- `call_stats.media_shed`: media frames dropped for a full queue, since start
- `call_stats.media_denied`: media frames refused as unadmitted, since start
- `call_stats.calls_share_refused`: calls refused because one connection already
  held its share of the table, since start
- `call_stats.connections` and `call_stats.connections_refused`

Capacity, never identity. Not one of them is per call, per group or per
principal, because a labelled count here would be exactly the metadata the hub
refuses to hold.

## How this is tested

Twelve suites, each at one layer, because a claim proved at the wrong layer is
not proved. Together they are the unit, property, integration, negative,
adversarial and load evidence step 35 and step 36 name.

| suite | layer | what it holds |
| --- | --- | --- |
| `tests/calls_unit.rs` | codec, budgets, registry | each rule, named one per test |
| `tests/calls_invariants.rs` | budgets and registry | each rule firing at the right number, not merely firing |
| `tests/calls_properties.rs` | budgets and registry | invariants over randomised sequences, plus a model of the registry |
| `tests/calls_session.rs` | session state machine | the order the six checks happen in, and what each refusal costs |
| `tests/calls_concurrency.rs` | registry, multi-threaded | seat races, disconnect storms, and no frame to a stranger |
| `tests/calls_socket.rs` | real socket, real Postgres | a whole call, and a zero-row delta over every table |
| `tests/calls_adversarial.rs` | hand-built hostile frames | a colliding call id, a lying length, a kind outside the set |
| `tests/calls_capacity.rs` | the two instance ceilings | connections and calls, and shedding under a wedged reader |
| `tests/call_vectors.rs` | codec, both sides | the relay's bytes against the client's, vector by vector |
| `tests/calls_load.rs` | throughput | 1, 10 and 50 concurrent calls, with latency percentiles |
| `tests/calls_soak.rs` | duration | a call running for a day without growth |
| `Tests/RelayFrameTests.swift` | the client codec | the same frames, from the other side |

The layering is deliberate. `calls_session.rs` exists because over a socket the
only visible difference between "refused for its kind" and "refused for its
budget" is the error code, so a relay that charged a budget before reading the
kind would answer identically to this one while letting a peer spend somebody
else's allowance with garbage; driving `Session::handle` directly is what makes
the remaining allowance measurable. `calls_concurrency.rs` exists because every
other suite drives the registry from one task, which is the one thing production
never does: a check-then-insert that was not one critical section would admit a
sixth participant on some runs and five on others.

## What is deliberately absent

No STUN, no ICE, no TURN, no SFU and no UDP listener. The relayed path is the
permanent floor and the P2P upgrade is a separate step
(`specs/peer-calls.md` section 5, step 37), which reuses these frames for
signalling and adds candidates as a new `kind`.

No push. A ring to a closed laptop has no delivery path in this release; the
relay is the only party that knows an offer was sent to an offline principal, so
it is the only party that could ever trigger the wake, and
`specs/push-notifications.md` sections 3 and 7 keep that door open rather than
walking through it here.

No recording, no transcoding, no mixing and no media storage. R2 is not involved
at any point, because media never touches storage.
