# ADR-0011: voice calls do not use WebRTC

Status: accepted, 2026-08-04. Supersedes nothing. Recorded so it is not
relitigated.

**Published.** This ADR goes into `PUBLISHED_SPECS` in `scripts/relay-mirror.py`
along with `specs/peer-calls.md` and `specs/backend/relay/calls.md`. The decision
is entirely about the protocol and the relay's dependency surface, which is what
the public repository exists to let a stranger audit; there is no hosted-tier
pricing, vendor choice or purchase flow in it. `ADR-0006` is the contrasting
case, and it stays unpublished for exactly that reason.

## The decision

Relayed voice runs over the existing authenticated WebSocket as two new
deterministic-CBOR frames, `CALL` (23) and `MEDIA` (24), with media encrypted
end to end under a key exported from the MLS group. We do not take `libwebrtc`,
`webrtc-rs`, `str0m`, DTLS, SRTP or a bundled Opus.

## Why, on dependency budget

The relay has twenty-two direct dependencies. It hand-writes its own canonical
CBOR reader in 333 lines rather than take a CBOR crate, and it pins a
reproducible distroless image whose digest three independent builders must agree
on (`specs/backend/relay/verification.md`). Every dependency is a thing each of
those builders has to fetch and agree about.

A WebRTC stack is not one dependency. It is a media stack, a transport stack, a
congestion controller, a DTLS implementation, an SRTP implementation and a codec,
and on the Rust side it is a young one. Against that, the relayed path this
release ships added **zero** crates: the frames are hand-written CBOR in the
existing style, the routing is a `HashMap` in the existing hub style, and there
is no crypto in the relay at all because the relay holds no key.

## Why, on crypto simplicity, which is the stronger half

DTLS-SRTP is a second key exchange beside the MLS one we already have and already
audit. That is a worse security story, not a better one.

The group we want to authenticate is the MLS group. Under DTLS-SRTP the media
keys come from a certificate exchange between two endpoints, so the fingerprints
would have to be bound back into MLS anyway to mean anything about membership, and
we would then be maintaining two key schedules and the binding between them. What
we do instead is one line of existing machinery: a fifth exporter label,
`weald call v1`, beside the four that already rotate on every commit. Per-sender
keys are HKDF over the call secret, and the nonce is the 4-byte stream id plus an
8-byte counter, so nonce reuse is structurally impossible inside an epoch rather
than checked.

The relay's property is unchanged and that is the point: it forwards opaque bytes
and holds no key. A DTLS terminator would have been the first thing in this
system that could not honestly say that.

## What we give up, stated honestly

Congestion control, FEC, RTCP feedback and a mature jitter strategy, all of which
WebRTC has and we do not.

And UDP, which is the real cost. Every relayed frame rides TCP, which retransmits
packets that are already too late to play and holds back everything behind a lost
one. On a clean network this is invisible. On a lossy one it degrades differently
from how a real voice stack degrades: a stall and then a burst, rather than a
brief concealed dropout. `specs/peer-calls.md` section 2 says so plainly and the
UI is required to show a connection quality indicator rather than promise more.

Two mitigations ship with the frames: `TCP_NODELAY` on the relay's listener, so
20 ms frames are not coalesced by the thing Nagle was designed to coalesce; and a
jitter buffer capped at 200 ms on the client, dropping rather than growing past
it, so a bad network produces gaps instead of an ever-increasing delay.

## What would reopen this

The P2P step (`specs/peer-calls.md` step 37) adds a UDP path with about eighty
lines of STUN on a new listener and no TURN, because the relayed path is the
symmetric-NAT fallback that TURN would otherwise be. That is the fix for the
failure mode above, and it reuses the same GCM frame format, so the media layer
stays transport-agnostic.

If measured call quality on the relayed path is unacceptable **and** the P2P step
does not close it, the next thing to reconsider is the codec (vendoring
`libopus`, a small contained client-only decision) and not the transport stack.
Adopting WebRTC would mean accepting the second key exchange, and that trade does
not improve with time.
