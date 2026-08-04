# Relay: presence and the ephemeral path

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only, no dev tier,
> no test mode, no staging tier. `local` and `ci` are not an exception because
> they reach no vendor at all. A gate that cannot reach production configuration
> fails; it never degrades to a mock, a stub, a fake or a skip.

Protocol version 2 adds one frame, `LIVE`, and nothing else. It carries the
messages that are true for a moment and worthless a minute later: presence,
typing, and later a read cursor. This document is the whole of that addition,
including what it deliberately does not do.

## The hole this closes

`specs/backend/relay/wire.md` has always listed kind `0x00F0 ephemeral` with the
sentence "Presence, typing, cursor. Not persisted by the relay", and the sentence
after it: "`0x00F0` is the only kind the relay is permitted to drop. It fans out
to currently-connected subscribers and is never written to Postgres."

That instruction cannot be carried out. Under `enc: 1` the kind lives inside
`ct`, and the relay cannot read `ct`. A relay told to drop one kind and persist
every other kind, on bytes whose kind it cannot see, has been given an
instruction with no implementation. `backend/wealdrelay/src/ws.rs` records the
same fact in a comment and adds that nothing writes one.

This is the third time the same shape has appeared. `WRAP` and `HANDSHAKE` are
frames rather than event kinds because the relay has to act on them (store one
under a blinded tag, order and fan out the other) and cannot act on what it
cannot read. Ephemeral traffic is the same case and gets the same answer: a
frame, where the routing decision is visible and the content is not.

So `0x00F0` is retired to reserved and never used. The kind number stays
permanently allocated, because kind numbers are permanent, and it points at this
document.

## `LIVE`, frame tag 21

```
Live {
  group:  [32]byte      // group id, opaque to the relay
  epoch:  u64           // MLS epoch, so a receiver can pick the key
  ct:     bytes         // MLS application message, opaque, <= 4 KiB
}
```

Client to relay and relay to client, the same shape in both directions, like
`HANDSHAKE`.

The relay's whole behaviour on receipt:

1. Refuse unless the session is `Ready`. There is no bootstrapping case and no
   pre-auth case; `JOIN` remains the only pre-auth frame.
2. Refuse unless the group is known and the authenticated device key is in the
   access set for it, by exactly the check `SEND` uses. A device that may not
   write to a group may not announce itself into it either.
3. Refuse above 4 KiB, with `Reject`/`EnvelopeTooLarge`.
4. Charge the per-connection `LIVE` budget below.
5. Fan out to every other session that is subscribed to that group and that
   negotiated version 2 or higher. Not to the sender.
6. Forget it.

No sequence number is assigned. No `SendAck` is returned. No row is written. It
never appears in a `RECON` round, never in a head attestation, never in a
checkpoint, and never in a `drop_before` manifest. A `LIVE` frame that arrives
while its group has no other connected subscriber is discarded, and that is the
normal case rather than an error.

Backpressure sheds `LIVE` first, before it touches any durable frame, and sheds
it silently. This is the whole reason it must be a frame: the shed decision is
made on a bounded queue by a relay that has to know it is allowed to drop this
one, and it cannot learn that from `ct`. A shed `LIVE` produces no error to
either side, because the next beat is twenty seconds away and a lost beat is
indistinguishable from a slow one.

### Version negotiation

`PROTOCOL_VERSION` becomes 2 in `backend/wealdrelay/src/frame.rs` and in
`Sources/WealdRelayNetworking/RelayFrame.swift`. `CONNECT` already offers a
version and `CONNECT_ACK` already selects one, and the selection is already
signed into the challenge so a network attacker cannot downgrade it.

A version 1 client connected to a version 2 relay never receives a `LIVE` frame
and never sends one, and sees the product it saw before: no presence. A version
2 client connected to a version 1 relay learns from `CONNECT_ACK` that the peer
selected 1, and reports presence as unavailable rather than as everyone offline.
Those two are different sentences on screen and the app says the true one.

An unknown frame tag remains `Reject`/`ProtocolUnsupported`, unchanged. Adding a
tag does not break a version 1 client because a version 1 client is never sent
one.

### What is inside `ct`

The relay never reads this. It is written here because both ends must agree, and
because a body defined in two codebases and no document is a body that diverges.

```
LiveBody {
  kind:     u8            // 1 presence, 2 typing, 5 agent status. 3 and 4 reserved for focus and read cursor
  member:   [32]byte      // the author's device key, as in EnvelopePayload.author
  state:    u8            // 1 active, 2 idle, 3 away, 4 busy (agent status only)
  channel:  bytes?        // channel slug, typing only, absent for presence
  agent:    [32]byte?     // agentID, agent status only, absent otherwise
  at:       u64           // the author's clock, milliseconds
  ttl:      u32           // seconds this claim is good for
  cert:     bytes?        // delegation certificate, same rules as identity.md
  sig:      [64]byte      // Ed25519 over the canonical body without sig
}
```

`kind 5` is an agent's availability, and it is a claim by the member hosting that
agent rather than a new kind of principal. For a user-hosted agent the author is
the owner's device key, because an agent holds no socket and no relay identity
per `specs/backend/relay/agents.md`. For an organization agent the author is the
gateway's own principal, which is in the access set in its own right, so the beat
is a signed claim by a member exactly like a human's. The relay asserts nothing
either way, and the refusal of relay-asserted presence below covers agents
without amendment.

Clients draw an agent's ring separately from a person's dot. They are two facts.
Availability written on an `agent.card` is stale by construction, and the
invariant that an offline host is a visible state rather than an indefinite
spinner cannot be met by a field in a document. See
`specs/agents/networked/phases-live.md`.

Deterministic CBOR, and the same signing discipline as `EnvelopePayload`: the
signature covers every field except itself, and the certificate chain is checked
by the rules in `specs/backend/relay/identity.md`.

Signed even though MLS already authenticates the sender, for the same reason
`EnvelopePayload` carries an `author` and a signature on top of MLS: MLS tells a
receiver which leaf sent this, and the product's identity is a device key. The
roster in `specs/presence.md` binds a device key to a person, so a presence
claim has to arrive as a device key or the join does not exist.

`ttl` is a claim by the sender about how long to believe it, and a receiver
clamps it to 120 seconds. An unclamped `ttl` is a member who can appear online
forever by sending one frame and closing the lid.

`at` is the sender's clock and is used only to discard a beat older than one
already held from the same device. It is never rendered as a timestamp, because
a wrong clock would render as a wrong "last seen".

## What the relay learns, stated plainly

The relay already knows, from `AUTH` and `SUB` and `SEND`, which device key is
connected, when it connected, which groups it subscribed to and when it wrote.
Presence does not hand it a new category of fact. It changes the resolution: a
device that has the app open and is typing nothing currently looks idle to the
relay, and with a twenty second beat it looks present. The relay's picture goes
from "wrote at these moments" to "was at the keyboard across this interval".

That is a real change and it belongs in `specs/privacy-posture.md` and in the
transparency panel rather than in a footnote here. It comes with a workspace
setting: beacons off, in which case that member is rendered from observed
traffic alone, which is honest, coarse and free.

The relay learns nothing about who is present in a **channel** beyond the group
id it already routes, and nothing at all about the state, the typing target or
the person. `state` is inside `ct`.

## Rejected

**Relay-asserted presence.** The relay holds a connection table already; it
could answer "who is subscribed to this group" and save the beacon entirely.
Rejected, and not on efficiency grounds. It would make the relay the authority on
a fact members render as trust: a hostile or compromised relay could report a
teammate as online, and a person deciding whether to say something sensitive in a
room would be deciding on the relay's word. Presence is a signed claim by a
member or it is not shown. This is the same rule as everything else here, where
the relay routes and never asserts.

**Server-side last seen.** Rejected: a blind relay that keeps a per-member
activity log has stopped being one. Last seen is derived on each client from the
last beat or envelope that client actually received, so it is local, it differs
slightly between members, and it disappears when they quit. Two members
disagreeing by a minute about when a third was last seen is correct behaviour,
not drift to be fixed.

**Presence over the durable log.** Rejected. Writing presence as envelopes would
put a permanent, reconciled, checkpointed record of every member's working hours
into the group history, which is the single worst artifact this product could
produce, and it would do it at a thousand times the volume of the content.

**Redis fanout now.** `specs/backend/relay/server.md` lists Redis as optional and
for exactly this. A single relay process fans out from its own hub with no
dependency. The plan does not add Redis, and it does add the gate: presence
across two relay processes is not correct until a shared fanout exists, so a
multi-process deployment is refused at startup while `LIVE` is enabled and no
fanout is configured, rather than quietly showing half the room.

## Limits

| Limit | Value | Why |
| --- | --- | --- |
| `LIVE` `ct` | 4 KiB | A beat is tens of bytes. The cap exists so the ephemeral path cannot be used as an unlogged bulk channel. |
| `LIVE` frames per connection per minute | 60 | One beat per group per twenty seconds across a handful of open channels, plus typing. Budgeted separately from the 600 envelope allowance so a chatty presence can never starve a durable write. |
| Beacon interval, client | 20 seconds | Below the 120 second ttl clamp with room for two lost beats. |
| `ttl` clamp, receiver | 120 seconds | A sender cannot claim to be present indefinitely. |

Exceeding the budget is `Quota`/`RateLimited` on the frame and nothing else: the
connection stays up and durable traffic is unaffected.

## Configuration

Two variables, added to `specs/backend/build/env-registry.json` in the commit
that reads them and not before, because the registry gate fails both ways.

- `WEALD_RELAY_LIVE` (`on` | `off`, default `on`): refuse every `LIVE` frame with
  `Reject`/`ProtocolUnsupported` when off. A self-hoster who wants no ephemeral
  path at all gets one switch.
- `WEALD_RELAY_LIVE_FANOUT` (`process` | a shared fanout url, default
  `process`): `process` is single-instance fanout and startup refuses it when the
  deployment declares more than one instance.

## Gate

Four parts, per `specs/backend/build/testing.md`.

- Unit and property at the coverage floor: frame round trip through canonical
  CBOR, refusal on each of the five refusal paths, the access-set check reusing
  the `SEND` path, budget accounting independent of the envelope budget, `ttl`
  clamping, and a property that no `LIVE` frame ever reaches storage (the
  storage layer is handed a recording double and must see zero calls).
- Integration against a real relay on real Postgres: two authenticated clients
  in one group, one beats, the other receives, the row count in every table is
  unchanged before and after, and a third client not in the access set receives
  nothing.
- Negative: a version 1 client is never sent a `LIVE`; an oversized body is
  refused; a device outside the access set is refused; a saturated send queue
  sheds `LIVE` and still delivers every durable envelope in order; two relay
  processes with `process` fanout refuse to start.
- Artifact: a packet-level transcript of one beat, the before and after table
  counts, and the shed count under a saturation run.
