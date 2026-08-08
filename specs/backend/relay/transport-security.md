# Transport security

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only: the Clerk
> production instance, Stripe live mode, the production Render environment and
> Postgres, the production R2 bucket, the published relay digest. No dev tier,
> no test mode, no staging tier, and no agent creates one. `local` and `ci` are
> not an exception because they reach no vendor at all. A gate that cannot reach
> production configuration fails; it never degrades to a mock, a stub, a fake, a
> skip or a newly created dev or staging resource.

What protects the relay socket itself, as distinct from what protects the
envelopes travelling over it.

The envelope layer is the one that matters most and it is specified elsewhere:
bodies are sealed under the group's per-epoch content key (`mls-binding.md`), so
a relay is blind to content whether or not any of this holds. This document is
about the layer below that, and about the two things the sealed layer does not
give you: metadata (who is connected, which groups they name, how much they
send, when) and the identity of the peer this client is authenticating to.

The threat model here is specific and it is not the usual one. Weald relays are
self-hostable and user-configurable. The host in `.weald/project.json` is
whatever the operator typed. So "the server we shipped a key for" does not exist,
and the interesting adversary is not only a network attacker but also a relay
operator, or anyone who can obtain a certificate for a relay's name.

## The scheme rule

`RelayEndpoint.validate` is the gate and it is a pure function.

- `wss` everywhere.
- `ws` only to a host that is *literally* loopback, and only outside a shipped
  build. Never to a resolved address: a name that resolves to loopback today
  resolves wherever its zone says tomorrow.
- A shipped build refuses plaintext outright, including to loopback, and ignores
  `WEALD_RELAY_URL` entirely so a variable in a customer's shell cannot aim their
  client anywhere.

App Transport Security is configured to agree rather than to compensate:
`NSAllowsArbitraryLoads` is false, with `NSAllowsLocalNetworking` for the dev
relay and nothing else. There is no per-domain exception.

## The TLS floor

`URLSessionRelaySocket` states the floor rather than inheriting it. ATS already
refuses worse than TLS 1.2 for a host it governs, but a floor that lives only in
a plist is one that a later exception silently lowers, and this is the connection
carrying the workspace.

The default floor is TLS 1.2. Not because 1.3 would be worse, but because a team
terminating TLS on a reverse proxy they do not control is a supported deployment,
and a client that refused them is a client they work around. `"tls": "1.3"` in a
workspace's relay config raises it, and a hosted relay sets it.

The session is `ephemeral` with cookie and credential storage explicitly cleared.

## Pinning

Ordinary pinning assumes the client ships knowing its server. This one does not.
So the pin is trust-on-first-use, with a stronger configured mode on top.

| Mode | When | Behaviour |
| --- | --- | --- |
| `tofu` | Default | First connection records the leaf's key; every later one must match. |
| `strict` | `"pin"` in the config, or a zone we operate | Only the named keys are accepted. Nothing is ever learned. |
| `system` | Loopback | System trust only. |

### Precedence

Four sources can have an opinion. `RelayPinStore.policy` resolves them in this
order, and the order is the whole design:

1. **A loopback host.** System trust only, and nothing is learned or stored.
2. **A zone we operate, with pins shipped, in a shipped build.** Strict, on the
   shipped keys. A workspace's own `pin` cannot loosen this.
3. **The workspace's `"pin"`.** Strict, on the configured keys.
4. **What was learned before**, or first use.

Rule 2 outranks rule 3 because a project file is writable by anything that can
write to the repository. Without it, "point them at my relay and pin my key"
would be two lines of JSON. Outside a shipped build the order of 2 and 3 is
reversed, which is how a staging key gets tested against a debug build.

### Zones we operate

`specs/backend/build/environments.md` puts every hosted relay under `weald.team`:
`<slug>.weald.team` for a customer's instance, `api.weald.team` for the control
plane. We hold that zone and its certificates, so for those hosts the client can
make the stronger claim: not "the same relay as yesterday" but "the key we
published". There is no first-use window, and a certificate mis-issued for
`weald.team` by any of the CAs in the system trust store does not get traffic.

`RelayKnownHosts.entries` carries them. Matching is on a label boundary, so
`notweald.team` and `weald.team.attacker.example` are not ours. Those hosts also
get a TLS 1.3 floor, since the reason the general default is 1.2 (a customer's
reverse proxy) does not apply to a terminator we run.

None of this touches a self-hosted relay. A customer's own host keeps
trust-on-first-use and their own configured pin.

**An entry with no pins yet is not a refusal.** It falls through to first use.
That is the state a zone is in between owning the name and shipping a digest,
and it must not be the state that takes the product down.

**Rotation.** `scripts/relay-pin.sh <host>` prints the `sha256/…` line for a live
host. The operational rule is that `entries` always carries the key in service
*and* the next one, published in a build *before* the rotation. A build that
ships only the key in service bricks every client the moment that key is
replaced, and those clients are on other people's Macs.

System trust is evaluated first and always. A pin narrows what is acceptable; it
never rescues an expired, revoked, or wrongly-named certificate.

The digest is over the DER `SubjectPublicKeyInfo` (RFC 7469), so renewing a
certificate with the same key pair keeps the pin valid. That is deliberate: a
relay behind a 90-day ACME certificate would otherwise warn four times a year and
teach its operator to click through. Where the key type is outside the table in
`RelaySPKI.headers`, the fallback pins the whole certificate under a distinct
`cert-sha256/` label, so the two can never be confused and the weaker case is
visible rather than silent.

Several pins may be held at once. A relay behind two terminators, or one
mid-rotation, legitimately presents either of two keys, and an operator forced to
pick one is an operator who deletes the pin.

Learning records the leaf only. Learning the chain would pin the CA, and a pin
that any certificate from a public CA satisfies is not a pin.

### Where pins live

`.weald/relay-pins.json`, keyed by `host:port`. Committed, on purpose: a teammate
cloning the repository inherits a key the team already verified, so their first
connection is checked rather than learned. A pin is a public-key digest, so there
is nothing in the file to keep secret, and a change to it is a reviewable diff.

Port is part of the key because two relays on one host are two relays.

A loopback host is never written to it. The file is committed, so a developer
running `wss://localhost` against a throwaway certificate would otherwise hand
`localhost:443` to every teammate and refuse the next developer whose local
certificate differs.

## Local builds

Nothing about pinning changes how a local relay behaves. Specifically:

- `ws://127.0.0.1:8787`, the documented dev path, has no TLS and reaches no
  pinning code at all. The socket is built without a delegate.
- `wss://` to a loopback host gets `system` mode: system trust is evaluated
  exactly as it was before any of this existed, so a certificate that worked
  still works and a self-signed one still fails, for the same reason and with the
  same message as before.
- Nothing is learned for a loopback host, so `.weald/relay-pins.json` stays out
  of a developer's diff.
- The TLS 1.3 floor applies to our zones, not to loopback.

A held pin is never overwritten by learning. Rotation is an explicit
`RelayPinStore.forget`, not a prompt attached to a failure: a person shown "trust
this new key?" while trying to work will say yes.

A corrupt store degrades to first-use, not to a client that cannot connect.

## The authentication challenge

`AUTH_CHALLENGE` is answered by signing the relay's bytes with the device's
Ed25519 key. That key is not only the relay's: it also signs chat lines
(`ChatSignature`), envelope payloads (`EnvelopePayload.signingInput`), access-set
revisions (`AccessSet.digestInput`), self-join claims and retention records.
None of those signing inputs carries a domain-separation label.

A relay that could choose the bytes to be signed could therefore choose what this
device appears to have said: hand it a canonical chat object as a "challenge" and
get back a signature that verifies as a message from that device. Because the
relay is not ours, that is a live path and not a theoretical one.

The current bound is a shape check. `session.rs::challenge_bytes` finalises a
BLAKE3 hash, so an honest challenge is exactly 32 bytes; every signing input
listed above is a CBOR array or JSON object and is longer. `RelayHandshake`
requires the exact length before the key is touched, which costs nothing on the
wire and removes every known collision by construction.

That is a bound, not a proof, and it should not be the end state.

**Open, for the next protocol version:** sign a domain-separated transcript,
`H("weald/relay-auth/v1" ‖ challenge)`, rather than the challenge. Both halves
have to move together, so it belongs to a `RelayFrame.protocolVersion` bump. The
same bump should add domain-separation labels to the other signing inputs above,
which would make the class of attack impossible rather than merely unreachable.

**Also open:** channel binding. The challenge is not tied to the TLS exporter, so
an attacker able to terminate TLS for a relay's name can relay a live handshake.
The envelope layer holds under that (bodies stay sealed), but metadata does not.
Binding the challenge to the exporter is the fix and it belongs to the same bump.

## Connection deadlines

An open socket is not a peer that is there, and until protocol version 4 the
relay treated the two as the same thing. A connection slot is taken at the
WebSocket upgrade and given back when the reader loop ends
(`operations.md`, "Backpressure"), and nothing bounded the time between those
two events. The consequence is worth stating plainly, because it turned a
capacity control into the attack: an unauthenticated stranger could open
`WEALD_RELAY_MAX_CONNECTIONS` sockets, send no bytes at all, and lock every real
device out of a customer's relay for the cost of one file descriptor each. The
cap bounded memory and bounded nothing about availability. The abuse table in
`operations.md` already claimed "a hard cap on unauthenticated connection
lifetime" against `CONNECT` and `AUTH`; these two deadlines are what makes that
sentence true.

| Deadline | Variable | Default | Runs from | Runs until |
| --- | --- | --- | --- | --- |
| Handshake | `WEALD_RELAY_HANDSHAKE_TIMEOUT_MS` | 10000 | The WebSocket upgrade | `AUTH_ACK` |
| Idle | `WEALD_RELAY_IDLE_TIMEOUT_MS` | 300000 | The last message from the peer | The liveness exchange below |

They are two deadlines rather than one because they answer different questions
about different peers. Before `AUTH_ACK` the peer is a stranger holding a slot,
and the honest path is one `CONNECT`, one challenge, one Ed25519 signature and
one `AUTH`: no real client needs ten seconds for that, and every second granted
beyond it is a second an attacker holds the connection table for free. After
`AUTH_ACK` the peer is in the access set, holding a seat, and bounded by the
abuse budgets in `wire.md`; a quiet workspace is then the ordinary case rather
than a suspicious one, so five minutes is a reaper for peers that have already
gone rather than a control on peers that are merely silent. Getting it wrong in
that direction costs a reconnect and a handshake replay for somebody who was
working fine, which is why the number is generous.

Both are configuration with a stated default, both are refused at `0` by the same
rule that refuses `WEALD_RELAY_MAX_CONNECTIONS=0`, and neither has an
`unlimited`. Zero is not a smaller deadline, it is a relay that closes every
connection it accepts. `unlimited` is absent because unlimited is the behaviour
being replaced, and offering it under a new name would let the gap above be
re-opened by one variable.

### Why liveness is not TCP's job

The idle deadline is enforced by an application-level exchange: when the interval
elapses the relay sends a WebSocket ping and waits ten seconds for **anything**
to come back, and only silence past that closes the connection. Any inbound
message resets the interval and cancels an outstanding probe, because the
question is whether the peer is present and a frame, a ping, a pong and a close
are each an answer to it.

TCP is not used for this, for two reasons and the second is the one that matters.
First, a TCP keepalive is a property of the host's network stack rather than of
this relay: it is off by default, its interval is measured in hours where it is
on, and a deadline built on it would mean something different on every
deployment a self-hoster chooses. Second, and structurally, TCP answers the wrong
question. The kernel's peer is the kernel on the other side, and it will go on
acknowledging segments for a process that has stopped reading, so a relay that
trusted the socket's liveness could not distinguish a client that is quiet from a
client that is wedged. That distinction is exactly what the deadline exists to
make, and it is the same one the replay drain makes from the other direction in
`operations.md`: a peer that is slow keeps its connection, a peer that is gone
does not.

A ping is used rather than a new frame because the WebSocket layer already
defines one, a conforming client's transport answers it without its application
being involved, and adding a protocol frame for it would mean a wire tag, a
registry row and a client release to say something the transport says already.
It costs a quiet connection one small frame every five minutes.

### What a closed connection is told, and what an operator sees

A connection closed on either deadline is sent `quota/rate_limited` with
`retry-after`, then closed. That is the same close path a refusal takes, and it
is deliberate: `operations.md` requires that a client never gets a dropped
connection without a frame, because it cannot otherwise tell a decision the relay
made from a network that failed. The class carries the client behaviour that is
actually correct here, which is to wait the named interval and reconnect.

The client is told one thing and the operator is told another, because they need
different facts. `/readyz` reports
`call_stats.connections_closed_handshake_deadline` and
`call_stats.connections_closed_idle_deadline` beside
`call_stats.connections_refused`. Three counters rather than one, because from
outside they are otherwise indistinguishable from each other and from a relay
that is crashing:

- `connections_refused` rising is a relay at its ceiling. The answer is a bigger
  ceiling or another instance.
- `connections_closed_handshake_deadline` rising while `connections` sits well
  below the ceiling is somebody parked on the connection table. The answer is at
  the edge, and it is never to raise anything.
- `connections_closed_idle_deadline` rising is ordinary attrition: laptops
  closing, mobile networks dropping connections without a FIN. It is non-zero on
  every real deployment and is a fleet-health signal rather than an alarm.

They are counts and nothing else. There is no per-source breakdown, for the
reason the invite path hashes a source address before it reaches a table: a map
from address to connection behaviour, held in memory and served on an operator
surface, is the metadata this design spends its effort not accumulating.

## What this does not protect

- **Metadata against the relay itself.** The relay sees connection times, group
  ids, sizes and rates. That is inherent to the design; `overview.md` says so.
- **A compromised device.** Pinning says which server; it says nothing about a
  key already stolen from a Mac.
- **Group identities.** Members verify each other with safety numbers
  (`SafetyNumber.swift`), which is a separate mechanism and the one that actually
  answers "am I talking to my teammate". Nothing on this page substitutes for it.
