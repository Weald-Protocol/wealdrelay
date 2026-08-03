# Transport security

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

Endpoint validation is the gate, and it has to be a pure function of the
configured URL, decided before a socket is opened.

- `wss` everywhere.
- `ws` only to a host that is *literally* loopback, and only outside a shipped
  build. Never to a resolved address: a name that resolves to loopback on one
  lookup resolves wherever its zone says on the next.
- A shipped build refuses plaintext outright, including to loopback, and ignores
  `WEALD_RELAY_URL` entirely so a variable in a customer's shell cannot aim their
  client anywhere.

App Transport Security is configured to agree rather than to compensate:
`NSAllowsArbitraryLoads` is false, with `NSAllowsLocalNetworking` for the dev
relay and nothing else. There is no per-domain exception.

## The TLS floor

The client states the floor in code rather than inheriting it. ATS already
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

Four sources can have an opinion. A client resolves them in this
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

### Zones the client's vendor operates

A managed offering typically holds one DNS zone and issues a subdomain per
customer instance under it. Where the party that builds the client is also the
party that holds the zone and its certificates, the client can make the stronger
claim for those hosts: not "the same relay as yesterday" but "the key we
published". There is no first-use window, and a certificate mis-issued for one
of those names by any of the CAs in the system trust store does not get traffic.

The client carries a table of such zones and their pins. Matching is on a label
boundary, so a zone `example.net` does not match `notexample.net` or
`example.net.attacker.example`. Those hosts also get a TLS 1.3 floor, since the
reason the general default is 1.2 (a customer's reverse proxy) does not apply to
a terminator the vendor runs.

None of this touches a self-hosted relay. A customer's own host keeps
trust-on-first-use and their own configured pin.

**An entry with no pins yet is not a refusal.** It falls through to first use.
That is the state a zone is in between owning the name and shipping a digest,
and it must not be the state that takes the product down.

**Rotation.** `scripts/relay-pin.sh <host>` prints the `sha256/…` line for a live
host. The operational rule is that the table always carries the key in service
*and* the next one, published in a build *before* the rotation. A build that
ships only the key in service bricks every client the moment that key is
replaced, and those clients are on other people's Macs.

System trust is evaluated first and always. A pin narrows what is acceptable; it
never rescues an expired, revoked, or wrongly-named certificate.

The digest is over the DER `SubjectPublicKeyInfo` (RFC 7469), so renewing a
certificate with the same key pair keeps the pin valid. That is deliberate: a
relay behind a 90-day ACME certificate would otherwise warn four times a year and
teach its operator to click through. Where the key type is one for which the
client holds no SPKI algorithm header, the fallback pins the whole certificate under a distinct
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

A held pin is never overwritten by learning. Rotation is an explicit, deliberate
act of forgetting the stored pin, never a prompt attached to a failure: a person
shown "trust this new key?" while trying to work will say yes.

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
listed above is a CBOR array or JSON object and is longer. A client must require
that exact length before the key is touched, which costs nothing on the
wire and removes every known collision by construction.

That is a bound, not a proof, and it should not be the end state.

**Open, for the next protocol version:** sign a domain-separated transcript,
`H("weald/relay-auth/v1" ‖ challenge)`, rather than the challenge. Both halves
have to move together, so it belongs to a protocol version bump. The
same bump should add domain-separation labels to the other signing inputs above,
which would make the class of attack impossible rather than merely unreachable.

**Also open:** channel binding. The challenge is not tied to the TLS exporter, so
an attacker able to terminate TLS for a relay's name can relay a live handshake.
The envelope layer holds under that (bodies stay sealed), but metadata does not.
Binding the challenge to the exporter is the fix and it belongs to the same bump.

## What this does not protect

- **Metadata against the relay itself.** The relay sees connection times, group
  ids, sizes and rates. That is inherent to the design; `overview.md` says so.
- **A compromised device.** Pinning says which server; it says nothing about a
  key already stolen from a Mac.
- **Group identities.** Members verify each other with safety numbers, which are
  a separate mechanism and the one that actually
  answers "am I talking to my teammate". Nothing on this page substitutes for it.
