# Peer voice calls

Status: the relay half is built. Target: relay **`v0.2.0`**, app `0.58`.

The relay half of this document (the two frames, the limits, the routing and the
transport decision) is implemented and gated as build steps 35 and 36. The client
half (steps 37 to 39 below) is not.

Two corrections to the original framing, made by building it rather than by
re-reading it, and both are recorded here rather than quietly applied.

**The version is `0.2.0`, not `1.1.0`.** The crates in
`backend/wealdrelay/Cargo.toml` and `backend/weald-mls/Cargo.toml` are `0.1.0`
and the published tag is `wealdrelay-v0.1.5`. A new wire capability under semver
is a minor bump, so the target is `wealdrelay-v0.2.0`. `1.0.0` is not for this
work: the protocol is not frozen and the launch gate is not closed.

**The frame tags are 23 and 24, not 21 and 22.** This document was written on
2026-06-09, when 21 and 22 were free. They were taken in the meantime by `LIVE`
and `KEYS` (`specs/backend/relay/presence.md`,
`specs/backend/relay/private-messaging.md`). Tag numbers are permanent, so the
call frames took the next two, and the step numbers moved with them: what section
5 calls steps 30 to 34 are steps 35 to 39 in
`specs/backend/build/ledger.json`, because 30 to 34 were also taken. Section 5
below is corrected in place; the paragraphs are marked where they moved.

A third correction, in section 3's limits table, was made by measuring: see
"What the measurement changed".

This document answers four questions: what the transport should be, why P2P is
second and not first, what it costs to run, and what the build steps are. It is
written against the stack as it exists on 2026-06-09, so every claim about the
current system carries the file that backs it.

## 1. What already exists, and what does not

The relay is one Rust process, axum 0.7 over `tokio`, one WebSocket endpoint at
`GET /relay`, binary deterministic-CBOR frames tagged 1 to 20
(`backend/wealdrelay/src/frame.rs`), Ed25519 challenge auth against a salted
access set (`src/session.rs`), per-group `seq` assigned inside the insert
transaction, fanout through an in-memory hub keyed by group id (`src/hub.rs`).
Every accepted `SEND` is written to Postgres. Send queues are bounded in both
frames (256) and bytes (8 MiB), and a subscriber that overflows is downgraded to
reconciliation and told so, never silently dropped.

Encryption is MLS (RFC 9420) through OpenMLS 0.8.1 behind a C ABI in
`backend/weald-mls/`, exposed to Swift as `Frameworks/WealdMLS.xcframework` and
driven by `Sources/MLS/MLSSession.swift`. The relay holds no key. Four exporter
labels already exist (`weald retain v1`, `weald enrol v1`, `weald wraptag v1`,
`weald history v1`), all rotating on every commit.

Three things matter for calls and are worth stating as facts rather than
assumptions.

The wire spec already reserves exactly one droppable, never-persisted event
kind: `0x00F0 ephemeral`, "Presence, typing, cursor" (`specs/backend/relay/wire.md`),
with a CDDL entry (`k-ephemeral = 240`) and a contract vector,
`env-valid-ephemeral-not-persisted`, that asserts a zero-row delta in Postgres.
**It is unimplemented on both sides.** `backend/wealdrelay/src/ws.rs` says so in
a comment, and `EnvelopeKind` in `Sources/Sync/EnvelopePayload.swift` has no case
for it.

That reservation as written is also unimplementable, and this is the single most
important design finding in this document. `kind` lives inside `Payload`, inside
`ct`. A blind relay cannot read `kind`, so under `enc: 1` it cannot know which
envelope to shed or refuse to persist. This is precisely the defect `wire.md`
already found for `recovery.wrap` and for MLS handshakes and already fixed the
same way, by promoting both out of the envelope and into their own frames.
`ACCESS` is not an event kind either. So ephemeral must be a frame, not a kind,
and the `0x00F0` reservation should be retired rather than implemented.

The app already has a complete call subsystem, 70 files and roughly 14.9k lines
in `Sources/Voice/`, but it is human-to-LLM-agent over HTTPS. There is no
WebRTC, Opus, RTP, SRTP or jitter buffer anywhere in `Sources/`, `specs/` or the
relay. What is reusable is substantial and should be reused rather than
paralleled: the single shared `AVAudioEngine` with input and output voice
processing, so echo cancellation actually works
(`Sources/Voice/Calls/CallAudioGraph.swift`, whose own header explains why a
second engine broke AEC); the pure transition table `AgentCall.applying(_:at:)`;
the ring panel `IncomingCallPresenter.swift`; the in-call tray `CallTrayView.swift`;
`MicrophoneAccess.swift`; and the call-grade session deadlines in
`CallNetwork.swift`. `Weald.entitlements` already carries
`com.apple.security.device.audio-input`, and the app is unsandboxed.

What does not exist and blocks a call outright: **the app does not know who is
online.** `AgentPresence` in `Sources/Core/LiveWorkspace.swift` is git-backed,
one file per writer on the `weald/live` orphan branch, with push-pull latency.
Head attestation (`Sources/Sync/HeadAttestation.swift`) runs on a fifteen minute
cadence. Rosters answer who *may* be called (`Sources/Sync/AccessSet.swift`,
`GroupAdmission.swift`); nothing answers who is reachable now. Presence is not a
nice-to-have here, it is step one.

Also absent: any APNs or remote push (`Sources/Sync/LocalNotifications.swift`
decides from already-decrypted plaintext only), so a ring to a closed laptop has
no delivery path and is out of scope for 1.1. And no STUN, TURN, coturn, SFU or
LiveKit anywhere, plus no Redis code at all despite `WEALD_RELAY_REDIS_URL`
being a required production variable.

## 2. Transport decision

**Relayed by default, encrypted end to end, P2P as an opportunistic upgrade in a
later release.** Not P2P first.

### Answer, in four sentences

As written this plan is not a P2P solution: steps 35 to 38 route every audio
frame through the relay over the existing WebSocket, and P2P appears only as the
separable step 39. We should keep it that way because the relayed path needs
zero new dependencies on either side, works on every network that already works
including the port-443-only ones, and has to exist permanently anyway as the
symmetric-NAT fallback that P2P would otherwise require TURN for. P2P is still
worth building afterwards, since it removes the quadratic egress term that caps
group calls at five and cuts latency, but it is an optimisation on a shipped
feature rather than a prerequisite for one. It also matters for
`specs/push-notifications.md` that the relay is in the media path: the relay is
the only party that knows a `CALL` offer was sent to an offline principal, so it
is the only party that can trigger the APNs wake without a peer inventing a
side channel, and under P2P the offer still travels as a tag 23 signalling frame
for exactly that reason.

The reasoning is about what the two designs cost in code we would have to own,
not about latency. A relayed path reuses a socket that is already open,
authenticated, access-set-checked and TLS-terminated by the platform. It adds no
Rust dependency, no new listener, no new port, no NAT traversal, no ICE state
machine, no TURN allocation protocol, and no second security boundary. It also
works on every network that already works, including the corporate networks
where a privacy tool is most likely to be deployed, because it is port 443.

P2P is genuinely better for latency and for our cost line, and it is worth
building, but honestly accounted it is ICE (RFC 8445) plus STUN plus a fallback
that has to exist anyway for symmetric NAT. That fallback is the relayed path.
So the relayed path is not a stepping stone we throw away; it is the permanent
floor, and P2P is a measured optimisation on top of a shipped feature. Building
it in that order means 1.1 ships and 1.2 makes it faster.

Rejecting WebRTC deserves a line of its own, because it is the obvious answer.
It would bring `libwebrtc` or a Rust stack (`webrtc-rs`, `str0m`) plus DTLS plus
SRTP plus Opus into a tree whose relay currently has twenty-two direct
dependencies, hand-writes its own canonical CBOR reader in 333 lines rather than
take a CBOR crate, and pins a reproducible distroless image whose digest three
independent builders must agree on. It would also introduce a second key
exchange, DTLS-SRTP, beside the MLS one we already have and already audit, which
is a worse security story, not a better one: the group we want to authenticate
is the MLS group, and DTLS certificate fingerprints would have to be bound back
into it anyway. Rejected on dependency budget and on crypto simplicity, and the
rejection should be recorded in `specs/backend/contracts/adr/` so it is not
relitigated.

### Is the relay production grade for voice, honestly

Yes for the load, no for the transport, and the first draft of this document
undersold the second half. Sections 3's cost analysis is right that the relay's
CPU and bandwidth cost per call is close to nothing, because media bypasses
BLAKE3, the per-group `seq` transaction and S3 entirely. That is a real result
and it means a Team instance can carry its workspace's calls without a plan
change. It is also not the thing that decides whether a call sounds good.

The thing that decides that is TCP. Every relayed frame in this plan rides the
existing WebSocket, which is TCP, and TCP does two things voice does not want: it
retransmits lost packets that are already too late to play, and it holds back
every subsequent packet until the lost one arrives (head-of-line blocking). On a
clean wired or good Wi-Fi network this is invisible and the calls will sound
fine. On a lossy network, a congested cafe, a train, a weak cellular link, it
degrades differently from how real voice stacks degrade: instead of a brief
concealed dropout, you get a stall and then a burst, and the jitter buffer must
either grow (latency climbs) or discard the burst (a longer gap than the loss
warranted). Every serious voice product runs UDP for exactly this reason, and
that is what step 39 actually buys. It is not primarily a cost or latency
optimisation, it is the fix for the failure mode above, and this document should
have said so in section 2.

So the accurate claim is: the relayed path is production grade for one-to-one
and small group calls among colleagues on decent networks, which is the real
usage of a developer tool, and it is honest to ship as v1.1 provided the UI shows
a connection quality indicator and does not promise more. It is not a general
purpose telephony product and should not be marketed as one until step 39 lands.
Two mitigations belong in step 35 rather than being deferred, and both shipped
there: disable Nagle on
the relay socket (`TCP_NODELAY`), since 20 ms frames are exactly the traffic
Nagle was designed to coalesce and coalescing them is pure added latency; and cap
the jitter buffer at the 200 ms ceiling already specified, dropping rather than
growing past it, so a bad network produces gaps instead of an ever-increasing
delay. Measure loss and round trip on the client, surface it, and let step 39's
artifact be a measured comparison rather than an assertion.

### Why not build step 39 first and only

The fair version of this question is: if P2P is better, why pay for a relayed
path at all? Three answers, and the third is the one that settles it.

First, most of what looks like "the relayed path" is not relay-specific. Steps 37
and 38 are the audio graph, the codec adapter, the jitter buffer, the AES-GCM
frame format, the call state machine and the ring UI, and step 39 reuses every
one of them unchanged because the media layer is deliberately transport-agnostic.
The only work unique to relaying is step 35: two frame tags, a routing table, and
the rate limits. That is the smallest step in the plan.
Skipping it saves very little, so the trade is not "half the work" versus "all
the work", it is "a small extra step" versus "no fallback".

Second, signalling needs the relay regardless. Two devices cannot exchange ICE
candidates without a mutually reachable, authenticated meeting point, and ours is
the relay, so tag 23 exists in either plan. A P2P-only build still ships relay
changes; it just ships them without the part that makes calls work when P2P
fails.

Third, and decisively: P2P does not always connect. Between symmetric NAT,
carrier-grade NAT on cellular, and corporate firewalls that permit only outbound
443, a meaningful minority of pairs cannot form a direct path at all, and
published WebRTC deployment data puts the share needing a relay in the high
single digits to low twenties depending on population (worth measuring for our
own users rather than taking on faith, and step 39's artifact should do that).
Whatever the exact number, it is not zero and it is concentrated in exactly the
networks a work tool encounters, so P2P-only means a visible fraction of calls
simply fail with nothing to fall back to. The standard fix for that is TURN,
which is a relay, so the choice was never relay or no relay; it was our relay,
reusing an open authenticated socket and zero new dependencies, or coturn, a new
always-on service, a new port range, a new credential scheme and a new operational
surface for self-hosters. Building the fallback first means shipping a feature
that always works and then making it faster. Building P2P first means shipping a
feature that usually works and then discovering the fallback under pressure,
which is the same work in a worse order.

### Media encryption

Derive a call key from the MLS group with a new exporter label, `weald call v1`,
alongside the four that exist. Per call, both sides compute

```
call_secret = MLS-Exporter("weald call v1", call_id, 32)
send_key    = HKDF(call_secret, info: "weald call send" || sender_principal)
```

so each direction has its own key and each participant's stream is decryptable
by every group member without a pairwise handshake. Frames are AES-256-GCM
(`CryptoKit` on the client, already used) with a 12-byte nonce of
`4-byte stream id || 8-byte monotonic frame counter`. The counter never repeats
inside an epoch, and a new epoch means a new `call_secret`, so nonce reuse is
structurally impossible rather than checked. Additional authenticated data is
the cleartext frame header, which binds sequence and timestamp the way
`Envelope.hdr` binds `(v, enc, group, epoch)`.

This adds zero cryptographic dependencies on either side and keeps the property
the product sells: the relay forwards opaque bytes and holds no key.

**One correction, made by building it on Android first.** The exporter form above
is not computable on a device that is not an MLS member, which is exactly the
case the phone companions exist to serve: a device holding a `BridgeRelayGrant`
holds the per-epoch secret and no group handle. So the shipped derivation takes
the per-epoch secret as the input keying material and puts the label, the group,
the epoch and the call id in the HKDF info. The security claim is unchanged,
because holding that secret already grants read of every message in the epoch, so
the call key reaches exactly the devices that could already read the room. The
Mac holds the same secret, so when step 37 lands it must derive the same way or
the two ends will connect and be silent. `specs/android-voice-calls.md` carries
the exact inputs.

### Codec

`kAudioFormatMPEG4AAC_ELD` through `AudioToolbox`'s `AudioConverter`. AAC-ELD is
in the OS on macOS 14 and iOS 17, is a genuine low-delay codec (roughly 15 ms
algorithmic delay at 48 kHz), and encodes speech acceptably at 24 to 32 kbps
mono. Opus is the better codec and every serious voice product uses it, and it
is also a new C dependency in a tree that would then have to vendor it, build it
for two Apple platforms, and account for it in the reproducible relay image if
the relay ever touched media (it does not, so the cost is client-only). Take the
OS codec for 1.1. If measured quality is not good enough, the decision to vendor
`libopus` is a small, contained, later one, because the codec sits behind one
protocol in `Sources/Voice/Peers/`.

Frame size 20 ms, so 50 packets per second per direction.

### Frames

Two new relay frame tags. Tag numbers are permanent, so **23 and 24**: this
section originally said 21 and 22, which were free when it was written and were
taken by `LIVE` and `KEYS` before this was built.

```
23  CALL    [call_id[16], group[32], epoch, kind, body]   signalling, ephemeral
24  MEDIA   [call_id[16], stream[4], seq, ct]             media, ephemeral
```

Both are `Ready`-only, both require the group to be admitted for the session,
both are fanned out to currently-subscribed connections and **never written to
Postgres**, and both are the only frames the relay may shed under pressure.
`kind` on `CALL` is a small cleartext enum (`offer` 1, `answer` 2, `decline` 3,
`bye` 4; `candidate` is 5 and arrives with the P2P step under its own version
bump) carrying an opaque encrypted `body`; the relay routes on `call_id` and
`group` and reads nothing else. The set is closed and an unrecognised kind is
refused rather than forwarded, because a relay that forwarded one would be a
relay whose routing semantics a future client could change without a version
bump. `MEDIA.ct` is the AES-GCM frame.

`CALL` is fanned out at the group and `MEDIA` at the call's participants, which
is why `MEDIA` carries no group at all: the group was checked when a `CALL`
admitted the connection to that call id, and repeating the check on a path
carrying fifty frames a second per stream would put a Postgres read into the
media path. `specs/backend/relay/calls.md` carries the built design.

Both need a byte-exact Swift twin in `Sources/WealdRelayNetworking/RelayFrame.swift`,
a CDDL entry in `specs/backend/contracts/wire/wire.cddl`, and vectors under
`specs/backend/contracts/wire/vectors/`, including a negative vector asserting a
zero-row Postgres delta for each, replacing `env-valid-ephemeral-not-persisted`.

Presence was going to ride on the signalling frame as its own `kind`. It does
not, and that is the one structural change between this design and what shipped:
presence became its own frame, `LIVE` on tag 21, in the release before this one,
because it needed to exist without calls existing. So the two frames here serve
ringing and media routing, and presence is `specs/backend/relay/presence.md`'s.
The cost of the split is one frame tag; the benefit is that the online dots
shipped a release early, which is what section 5 wanted from step 30 anyway.

### Ordering and loss

`MEDIA` must **not** go through the per-group `seq` counter in
`src/accept.rs`. That counter is a Postgres `UPDATE ... RETURNING` inside a
transaction, and putting 50 packets per second per stream through it would
serialise every writer in the group behind the call and add a database round
trip to every audio frame. `MEDIA.seq` is a per-stream client counter used only
by the receiver's jitter buffer. Out of order is reordered, late is dropped,
missing is concealed. This is the one place where the relay's normal "never drop
an envelope on its own initiative" invariant does not apply, which is exactly
why media is a distinct frame and not an envelope.

Jitter buffer: adaptive, 40 ms target, 200 ms ceiling, in
`Sources/Voice/Peers/`, pure Foundation so the Companion can compile it.

## 3. Server cost and slowdown

### Bandwidth

At 24 kbps mono plus a roughly 6% overhead for the GCM tag, frame header and
WebSocket framing, one direction is about 3.2 KB/s. A relayed two-party call is
two inbound streams and two outbound, so the relay moves about 12.8 KB/s, of
which egress is 6.4 KB/s.

| | per call-hour |
| --- | --- |
| relay egress | ~23 MB |
| relay ingress | ~23 MB |
| both directions | ~46 MB |

A five-person call is the same maths with fanout: n inbound streams, n(n-1)
outbound, so egress grows quadratically. At five participants that is 20
outbound streams, roughly 64 KB/s egress, 230 MB per call-hour. Cap group calls
at five in 1.1 and say so in the UI rather than discovering it in production.
This quadratic term is the honest reason a future SFU or P2P mesh matters, and
it should be stated in the tier spec.

Against Render's per-instance included bandwidth, a Team workspace would need
hundreds of call-hours a month before egress became a line item, and R2 is not
involved at all because media never touches storage. **Verify the current Render
included-bandwidth allowance and per-GB overage before publishing any number in
`specs/backend/cloud/billing.md`;** this document deliberately does not restate a
vendor price, and per `specs/backend/build/production-only.md` and the no-upgrade
rule, the answer if the floor is exceeded is a cheaper design, never a bigger
plan.

### CPU and memory

Per relayed media frame the relay does: read a bounded WebSocket message, parse
a two-item CBOR array, look up `call_id` in a map, check the group is admitted,
clone bytes into n bounded queues. No hashing (the envelope `hash` recomputation
does not apply, there is no envelope), no signature check, no Postgres, no S3.
That is on the order of a microsecond of work per frame per recipient.

A two-party call is 100 frames per second total. Existing traffic on the same
process is capped at 600 envelopes per connection per minute, which is 10 per
second, each of which does a BLAKE3 recomputation and a database transaction. So
one call costs less CPU than a single busy chat connection and touches no
database at all. Ten concurrent two-party calls on a Team instance is 1000
frames per second of map-lookup and memcpy work: sub-1% of a core, and the
number worth measuring rather than asserting.

Memory per call is the jitter of the send queues, bounded by the existing
`SEND_QUEUE_BYTE_BUDGET` accounting, so a few hundred KB per participant in the
worst case. **Media must be charged against that same 8 MiB budget**, not given
its own, so that a call cannot starve chat, and when it overflows the correct
behaviour is to shed media frames, not to downgrade the subscriber to
reconciliation, because there is no reconciliation for audio.

So: the honest answer to "how much will this slow the server down" is
essentially not at all in CPU terms, because the expensive parts of the existing
pipeline (BLAKE3, Postgres `seq`, S3) are all bypassed by construction. The real
resource is bandwidth, and the real risk is the uncapped-connections gap already
recorded in `specs/backend/relay/operations.md`: "nothing caps concurrent
connections, so instance memory is still the budget times however many connect."
Calls make that pre-existing gap matter sooner, so a concurrent-connection cap
and a concurrent-call cap shipped in the same step as the feature, and that
sentence in `operations.md` has been replaced by the cap that closes it.

### What the measurement changed

The CPU paragraph above ends "the number worth measuring rather than asserting",
so it was measured. `scripts/calls-load.sh` drives a real spawned relay against a
real Postgres at 1, 10 and 50 concurrent two-party calls and writes
`build-evidence/step-36/load-results.md`, which names the command that produced
it so a stranger can rerun it.

The prediction held and the numbers are in the artifact rather than here, because
a number copied into prose is a number that goes stale: the file is regenerated
by the run and this paragraph is not. What the measurement settled is the claim
this section could not make honestly on its own, that a media flood costs a
concurrent chat `SEND` nothing, which is
`build-evidence/step-36/flood-latency.txt`.

One thing the measurement did change: it exposed that answering every refused
frame of a flood is an amplifier, and that the answers queue on the flooder's own
bounded outbound queue, so a relay that complained about each one would fill that
queue and drop the connection. A rate limit that turns into a disconnect is a
denial of service an attacker can aim at somebody else's call. Media refusals are
therefore reported at most once a second; enforcement is unchanged and only the
complaint is economised. `specs/backend/relay/calls.md` carries the rule.

### New rate limits

Add to the limits table in `wire.md`, and unlike the 600-per-minute envelope
limit these must actually be implemented, not just written down (that one is
specified and absent: `ErrorCode::GroupIngressLimited` exists in `frame.rs` and
is referenced nowhere else):

| limit | value |
| --- | --- |
| `MEDIA` frames per stream per second | 60 |
| `MEDIA` bytes per connection per minute | 1 MiB |
| distinct streams tracked per connection | 32 |
| concurrent calls per instance | `WEALD_RELAY_MAX_CONCURRENT_CALLS` |
| participants per call | 5 |
| `CALL` signalling frames per connection per minute | 120 |
| max `CALL.body` bytes | 4096 |
| max `MEDIA.ct` bytes | 1500 |

Three rows changed while this was built, and the reasons are worth keeping.

"Per principal" became **per connection** throughout. The relay's identity for a
budget is the socket, because that is what it holds; a per-principal budget would
need a lookup on a path chosen for having none. The difference only matters to a
device with two sockets open, which is not a case any client produces.

"Concurrent calls per workspace, 3 (Team) and 10 (Scale)" became **per instance,
from `WEALD_RELAY_MAX_CONCURRENT_CALLS`, with no default**. Two reasons. A
per-tier number in the relay would put a commercial tier inside the blind relay,
which is exactly what `specs/backend/relay/overview.md` says never goes in there:
the relay does not know what anybody paid. And a default would be a capacity
number nobody chose; call capacity is a sizing decision about one instance's
bandwidth, so turning calls on and stating the ceiling are one act.

"Distinct streams tracked per connection, 32" is new, and it exists because
writing the budget exposed the hole: without it, a peer could make the relay hold
a rate-limit window per invented stream id, which is a slow allocation attack
down the path chosen for being cheap.

## 4. New dependencies

Relay: **zero new crates.** The frames are hand-written CBOR in the existing
`src/cbor.rs` style, the routing is a `HashMap` in the existing `src/hub.rs`
style, and there is no crypto because the relay holds no key.

Client: **zero new packages.** `AudioToolbox` and `AVFoundation` are in the SDK,
`CryptoKit` is already used, `Network.framework` covers 1.2's UDP, and the MLS
exporter label is one line in the existing FFI surface (`export` already exists;
no new FFI function is needed, which is worth stating because the FFI seam is
deliberately fourteen functions and adding a fifteenth would need its own
argument).

1.2 P2P adds STUN. Do not take a crate and do not run coturn: a STUN Binding
request and success response is a 20-byte header and one XOR-mapped-address
attribute, about 80 lines of Rust on a new UDP listener, and it is the entire
server side of server-reflexive candidate discovery. Symmetric NAT falls back to
the relayed path, which is why we never need TURN and never need to own an
allocation protocol.

## 5. Build steps

Gated as steps **35 to 39** in `specs/backend/build/ledger.json`, under the
existing
four-part gate (unit and property at 100% coverage, integration against real
dependencies, a negative proof, a recorded artifact) and the existing rule that a
step cannot advance while its predecessor is red. Note that steps 20, 25, 28 and
29 are `not_started` and 27 is `in_progress`, and the live ledger is stalled at
milestone 10 with no webhook event ever delivered and a broken production R2
token. **Calls should not start before the launch gate closes**; this plan is the
first upgrade after 1.0, not a detour around it.

**~~Step 30. Presence.~~ Done, and it moved.** Presence shipped a release early
as its own frame, `LIVE` on tag 21, rather than as a `kind` on the signalling
frame: it needed to exist without calls existing, which is what this step said it
wanted. It is build step 30 in the ledger, `specs/backend/relay/presence.md` is
the relay half and `specs/presence.md` the client half, and it retired the
`0x00F0` reservation on the way through, exactly as this section asked. The online
dots are in `ChatChannelCrewBar.swift`. Nothing is left of this step.

**Step 35. The call frames and the relayed path. Done.** Frame tags 23 and 24,
`kind` as the one cleartext routing field, the call registry that lets `MEDIA`
carry no group, per-stream and per-connection limits, media charged against the
existing 8 MiB byte budget, shed-not-downgrade under pressure, the
concurrent-connection cap, `ErrorCode::GroupIngressLimited` finally enforced, and
`TCP_NODELAY`. Negative proofs, each its own named test: a `MEDIA` frame for an
unadmitted group is denied; an oversized `ct` is rejected; a call frame before
`AUTH` is refused and closes the connection; a revoked device's live socket stops
receiving media the moment the `ACCESS` drop lands; a shed frame increments a
counter carrying no content-derived label; and a flood does not delay `SEND` on
the same process, measured rather than asserted. `specs/backend/relay/calls.md`.

**Step 36. The measurements. Done.** The throughput, latency, CPU and memory
numbers at 1, 10 and 50 concurrent calls, and the flood-versus-chat number, both
produced by a command a stranger can rerun. There was no throughput gate anywhere
in this repository before it. Split from step 35 rather than folded into it
because a measurement that only ever runs as part of a feature's own gate is a
measurement nobody runs again.

**Step 37. Client audio path.** `Sources/Voice/Peers/` for the pure types
(packet, jitter buffer, codec protocol, transition table, all Foundation-only so
`Companion/project.yml` can add one path entry the way it already does for five
`Sources/Sync` files). Extend `CallAudioGraph.swift`, do not build a second
`AVAudioEngine`. Call lifecycle as a pure `applying(_:at:)` table mirroring
`AgentCall`. Registry as a per-workspace hub in the `ChatHub` / `AgentCallCenter.shared`
shape, activated from `VoiceModule.activate`, never from `WealdApp.swift`.
Suppress `NSSupportsSuddenTermination` while a call is live. Reword
`NSMicrophoneUsageDescription` in `project.yml`, which is already inaccurate for
agent calls and would be wrong twice over for peer calls. Integration proof is
two real app instances against a real relay, which is the shape
`specs/agents/networked/ledger.json` already uses.

**Step 38. Ring, answer, and the encryption panel.** `IncomingCallPresenter`'s
`NSPanel` for the ring, `CallTrayView` for in-call, a call event written to the
chat log as a durable `chat.message` so a missed call survives (the call itself
leaves no trace by design, so the record has to be deliberate). The encryption
panel must state what the relay sees for a call: that a call happened, which
group, who was connected, for how long, and how many bytes. Metadata is not
hidden and `specs/backend/relay/overview.md` says to say so plainly, so say it
here too.

**Step 39. P2P upgrade.** STUN listener on the relay, ICE-lite candidate
exchange as `CALL` kinds, `NWConnection` UDP with the same GCM frame format so
the media layer is transport-agnostic, automatic fallback to tag 24 on
gathering failure or 2 s of silence, and a measured latency and cost comparison
recorded as the artifact. Separable, and 1.1 ships without it.

Cross-cutting, per the repository rules: `WEALD_RELAY_MAX_CONCURRENT_CALLS` and
any other new variable goes into `specs/backend/build/env-registry.json` in the
same commit, because the gate fails in both directions. This file and any new
relay spec must be added to `PUBLISHED_SPECS` in `scripts/relay-mirror.py` or
they are invisible to the public repository, and `--check` will report the
omission rather than decide it. The release order is unchanged: mirror with
`--write` into a fresh clone, hand-apply the version bump to both `Cargo.toml`
files there (there are no dependency changes to hand-apply, which is the point of
section 4), build and test in that tree, tag `wealdrelay-v0.2.0`, then confirm
no drift.

## 6. Was it realistic

Yes, and the estimate held. The audio stack, the call state machine, the ring UI,
the mic entitlement, the authenticated transport, the group key schedule and the
fanout hub all already existed. What was missing was presence, two frame tags, a
jitter buffer and a codec adapter. Presence shipped separately in the release
before this one, the two frame tags are steps 35 and 36, and the jitter buffer and
codec adapter are steps 37 and 38. Nothing was added to the dependency graph on
either side, which was the load-bearing claim: the relay's `Cargo.toml` is
unchanged, and section 4 said it would be.

### The sequencing note this section carried, and what happened to it

This section used to end: "Calls are the right first upgrade for 1.1 and the
wrong thing to build this week", because build steps 20, 25, 28 and 29 were
unstarted, live milestone 10 had never seen a webhook event and the production R2
token answered 403 on both buckets.

Most of that has moved. Build steps 27, 28 and 29 are done, 30 to 34 shipped the
presence and private-messaging work, and live milestones 0 to 13 are done
including the webhook. What is still open is build step 20 (the launch gate, in
progress), build step 25 (the app launch gate, unstarted, and waiting on 20), and
live milestones 14, 15 and 16.

So the sequencing advice is narrower than it was and it is still real: **the
relay half of calls is built**, and as of 2026-08-21 it is on by default
(`WEALD_RELAY_CALLS=on`, `calls/mod.rs DEFAULT_CONCURRENT_CALLS`), which supersedes
the line this paragraph carried while it was opt-in. The reason for the change is
the reason the opt-in was wrong in practice: no provisioner ever set the variable,
so every relay a customer bought answered `version/protocol_unsupported`
(`specs/launch-review-2026-08-11.md:36`), and a feature nobody can reach is an
absence rather than a posture. `off` is still available to an operator who wants
it. No client above the socket exists yet, and nothing about steps 35 and 36 touches the launch
gate's path. The client half, steps 37 to 39, is the part that should wait for
the launch gate, because that is the part a customer can see.
