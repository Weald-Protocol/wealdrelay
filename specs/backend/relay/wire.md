# Relay: wire protocol

The envelope, the event kinds, the sync algorithm and the transport. Layers 1,
2 and 4 of the stack in `specs/backend/relay/overview.md`.

Everything here is what the relay actually handles. If a field is not in the
envelope header, the relay does not know it exists.

## Envelope

The only unit the relay stores. Deterministic CBOR.

```
Envelope {
  v:        u8            // protocol version, currently 1
  enc:      u8            // 0 = none (Phase 2 only), 1 = MLS. See below.
  group:    [32]byte      // group id, opaque to the relay
  epoch:    u64           // MLS epoch, needed for routing to the right key
  seq:      u64           // per-group, assigned by the relay on accept. advisory
  ts:       u64           // relay receipt time, milliseconds. advisory only
  hash:     [32]byte      // BLAKE3 of the header binding below. content address
  ct:       bytes         // MLS application message. opaque.
}
```

The relay validates: version, `enc` against its configured floor, group exists,
`hash` is correct, `ct` is under the size limit, and the **authenticated device
session** is inside the access set below. The encrypted `author` is deliberately
not used for this check: agents are authored by delegated keys but proxy through
their issuing device, and the relay cannot inspect the author without breaking
the content boundary.

### The header binding

Two separate things, and conflating them produces a definition that eats itself.

**The content address.** `hash` is `BLAKE3(v, enc, group, epoch, ct)`,
canonically encoded in that order. It is what the relay recomputes on accept and
what deduplicates a retry. It deliberately excludes `seq` and `ts`, which the
relay assigns and which no client can know at signing time; those two are
advisory and are never trusted for anything.

**The signed binding.** The plaintext payload carries `hdr`, a copy of
`(v, enc, group, epoch)` as its first signed field. It cannot be the `hash`
above, because that hash covers `ct` and `ct` is the encryption of the payload,
so a payload committing to it would have to commit to its own ciphertext. `hdr`
carries the mutable header fields themselves, which is small, non-circular, and
exactly as strong for this purpose.

This closes a real gap rather than tidying one. An earlier draft left `enc`
outside both the content address and the signature, and described the payload
signature as covering "the payload plus the envelope header" in
`specs/backend/relay/identity.md` while defining it over the payload fields
alone here. The two readings are not equivalent and the weaker one is
exploitable: with `enc` unbound, a relay or a network attacker on a self-hosted
deployment running `WEALD_RELAY_MIN_ENC=none` during Phases 2 and 3 could
relabel a signed plaintext envelope as `enc: 1`, and every client's encryption
panel would report it as MLS ciphertext that merely failed to decrypt.
Relabelling in the other direction is equally cheap. Rehoming an envelope onto a
different `group` or `epoch` was unbound for the same reason.

A receiving client compares `hdr` against the header it actually received and
rejects the envelope on any mismatch, before it interprets the payload. The
relay is not asked to check this and could not: `hdr` is inside the ciphertext.

### `enc`, and why the relay reads it

`specs/backend/relay/migration.md` has a phase where envelopes are signed and
not encrypted, which is the right way to land a transport without betting the
product on the MLS work landing first. It is also, left implicit, a way for a
relay to be handed plaintext by a misconfigured or downgraded client while its
operator believes the opposite.

So the encryption state is a header field the relay reads and enforces against
`WEALD_RELAY_MIN_ENC`, rather than a property nobody can name:

- `WEALD_RELAY_MIN_ENC=mls` rejects every `enc: 0` envelope with a stable
  `denied/plaintext_refused`. **This is the only permitted value on the hosted
  tier and it is not configurable there**, so a hosted operator cannot receive
  plaintext even by accident, and the claim in
  `specs/backend/hosted-service.md` is a property of the deployment rather than
  a promise about client behaviour.
- `WEALD_RELAY_MIN_ENC=none` accepts both and is available to self-hosters
  during Phases 2 and 3 of their own rollout. The relay reports the setting on
  `/readyz`, and the client surfaces it in the encryption panel as an explicit
  "this relay accepts unencrypted envelopes" state
  (`specs/backend/relay/verification.md`).

This does not prove that an `enc: 1` payload is really MLS, and must not be
described as though it did. The confidentiality claim rests where it always
did, on clients holding keys the relay does not. What the field removes is the
silent case: a relay configured to demand ciphertext cannot be quietly fed
anything else, and a relay that accepts plaintext says so to every user
connected to it. It cannot validate
the signature inside `ct`, because it cannot decrypt it. That check happens on
every receiving client.

There is deliberately **no relay-maintained `prev` chain**. An earlier draft
required each envelope to name the relay's current head, which made every
concurrent write a compare-and-swap against a single per-group head. At the
stated posture, thirty people and a dozen agents write into one workspace root
group
continuously, so that design would have spent most of its time losing races. It
also did not deliver the tamper evidence it was credited with, because a header
chain the relay alone constructs is a chain the relay alone can fork.

Ordering and tamper evidence both move inside the ciphertext, where the relay
cannot reach them.

`seq` is relay-assigned and is a **sync cursor only**. Nothing above layer 2
reads it for correctness. Causality lives in the Automerge change graph, and
integrity lives in the author chain below.

## Plaintext payload

Inside `ct`, after MLS decryption. Also deterministic CBOR.

```
Payload {
  hdr:       Hdr          // (v, enc, group, epoch) copied from the envelope header
  kind:      u16
  author:    [32]byte     // principal pubkey
  cert:      Certificate? // delegation chain, present when author is an agent
  ctr:       u64          // per (author, group) monotonic counter, starts at 0
  prev_self: [32]byte     // hash of this author's previous envelope in this group
  sent_at:   u64          // author clock, milliseconds
  body:      bytes        // kind-specific
  sig:       [64]byte     // Ed25519 by author over all fields above
}
```

Sign-then-encrypt. A group member cannot re-attribute a decrypted message.

### The author chain

Each principal maintains one hash chain per group: `ctr` increments by exactly
one and `prev_self` names the hash of that author's own previous envelope. Both
are inside the signature and inside the encryption.

This is what makes withholding detectable. Concurrent writers never contend,
because each writes only its own chain. A relay that drops, reorders or
withholds an envelope from one client produces a gap in some author's counter,
and every receiving client checks for gaps as it applies events. The relay
cannot forge a link, because it cannot produce the inner signature, and it
cannot quietly skip one, because the counter is dense.

### Head attestation

An author chain proves nothing on its own if the relay shows a consistent but
different subset of history to different clients. Closing that requires clients
to compare notes, so they do.

Every client, on connect and then every 15 minutes while connected, emits a
`head.attest` payload naming, per group it holds, the highest `ctr` and matching
hash it has seen from every author including itself. Receiving clients compare
against their own view. A disagreement that does not resolve within two sync
rounds raises a **split-view warning** naming the relay and the disagreeing
authors, in the encryption panel described in
`specs/backend/relay/verification.md`.

This is cheap, roughly one small envelope per client per quarter hour, and it is
the difference between "the relay cannot forge history" and "the relay cannot
forge history without somebody's client saying so out loud".

#### Silence is also a signal

Comparing notes only detects a split view if the notes arrive. A relay that
withholds every `head.attest` from the client it is lying to produces silence
rather than disagreement, and a detector that alarms only on disagreement fails
open in exactly the case it exists for.

So attestation liveness is checked as well as attestation content, using the
group's own MLS ratchet tree as the expected set rather than anything the relay
supplies:

- **Expected attesters** for a group are its current **device** leaves, which
  every client reads from its own ratchet tree. The relay is not consulted and
  cannot shrink the set.
- **Agent leaves are never expected attesters, and are never unattested
  either.** An agent holds no MLS state and never opens a socket
  (`specs/backend/relay/agents.md`), so it cannot observe a history to attest
  to, while being the highest-volume writer in the system. Left in the expected
  set it would trip the absence-against-evidence rule below on every ordinary
  agent write, and a warning that fires on normal Tuesday traffic is a warning
  people learn to dismiss. Instead the **app that proxies an agent attests on
  its behalf**: a device includes, in its own `head.attest`, the highest `ctr`
  and hash it has seen for every agent whose key it holds, alongside its own.
  This is honest rather than convenient, because the proxying app is the
  component that actually saw those envelopes leave. An agent whose issuing
  device is offline is silent, which is the ordinary silence of a shut laptop
  and raises nothing.
- **An agent author with no proxying attester is a warning.** If envelopes
  arrive signed by an agent whose issuing device has attested in the same round
  without covering that agent, the pair contradict each other and the split-view
  warning names both. That is the case the naive rule was reaching for, and it
  is the only case where it means anything.
- **Absence alone is normal.** A member whose laptop is shut is silent, and that
  raises nothing.
- **Absence against evidence of presence is not.** Receiving application
  envelopes from a device author while receiving no attestation from that author
  across two consecutive rounds is a split-view warning naming that author, on
  the same surface and with the same wording as a disagreement. For an agent
  author the equivalent test is against its issuing device, per the proxy rule
  above.
- **Total silence with live traffic is not.** A group in which the client is
  receiving envelopes but has received zero peer attestations for 60 minutes
  raises the same warning naming the relay.

The client's encryption panel therefore reports agreement as a fraction of the
expected set, with the members it has not heard from named, rather than as
agreement with whoever happened to reply
(`specs/backend/relay/verification.md`).

#### Writing a chain link durably

A dense signed counter is tamper evidence only if an honest client can never
produce two different envelopes at the same `ctr`. A client that signs, sends,
and then crashes before persisting its counter would reissue `ctr` on restart
with different content, and every receiver would read that as a forked author
chain. The alarm would be indistinguishable from an attack and would fire on an
ordinary crash, which is how a security signal gets trained into noise.

So the counter is written ahead of the wire, not after it:

- The client reserves `(ctr, prev_self, hash)` in the same local transaction that
  records the signed payload, and only then sends. The MLS state write in
  `specs/backend/relay/mls-binding.md` is part of that same transaction.
- On restart, any reserved-but-unacknowledged link is resent verbatim. It is
  never re-signed and never renumbered. Duplicate `hash` is answered with the
  existing `seq`, so a resend is free.
- A client that discovers it cannot reproduce a reserved link, meaning local
  state was lost rather than merely interrupted, does not skip the counter and
  does not reuse it. It emits a signed `chain.reset` in the next payload it
  writes, naming the last link it can prove and the gap it is declaring. Every
  receiver renders the gap as unverified rather than as tampering, and the
  encryption panel shows it as a chain reset by that author at that date.

### Finding the counter without replaying the group

Reading the cursor is a fold over the author's own records, and it is on the
write path: `EnvelopeLogPublisher` writes one envelope per entry, so a twenty
line paste reads it twenty times. Folding the whole group each time made that
Theta(N squared) in decodes, SHA-256 validations, HKDF derivations and AEAD
opens.

The fold is kept instead of repeated. A conformant client caches the cursor
together with how
many bytes of each day file it has already consumed, persisted under
`.weald/log-cursor/` (ephemeral, per machine, never committed: another checkout
merged those files differently) and memoized in-process. Day files only grow, so
a later call resumes at the recorded offset by tailing the file from there.

Nothing about this may let a counter be reissued, so the saved position is
validated on every use and any mismatch costs one full replay, which is exactly
the old behaviour:

- Every remembered file must still exist and be at least as long as the bytes
  folded from it. Shorter or missing means somebody rewrote it.
- The resume offset must land on a record boundary, checked by requiring a
  newline immediately before it.
- The seal's epoch set for the group is fingerprinted (epoch numbers only, never
  key material). A client that has since learned a key for an older epoch can
  read records it previously skipped, and a fold taken without that key would be
  missing the author's own history.

None of those can produce a cursor *lower* than the truth, which is the only
direction that matters.

Reservations are deliberately not folded in. A reservation can be dropped as
corrupt, and a cursor that had already advanced past it would skip a counter with
no `chain.reset` to explain the gap. They are small and almost always absent, so
`EnvelopeWriter.cursor(group:)` reads them in full on every call and applies them
on top of the fold.

Separately, `EnvelopeContentKeyCache` memoizes the content key by
`(secret, group, epoch)`. The secret is part of the key because two seals can
hold different exporter output for the same group and epoch, and keying on the
pair alone would hand back a key derived from somebody else's secret.

Each of those cases is worth a test that asserts the cached result against a
cold, cacheless replay. The reference client has one per case.

A self-fork observed without a matching `chain.reset` remains what it always
was: evidence, surfaced loudly. The distinction between a crash and an attack is
made by the author, in signed form, before the fact rather than by a receiver
guessing after it.

Certificate verification rules are in `specs/backend/relay/identity.md`. A
payload whose chain fails is retained and rendered as rejected, never dropped.

## Event kinds

| Kind | Name | Body |
| --- | --- | --- |
| `0x0001` | `doc.change` | One Automerge change for the document named in the body header. |
| `0x0002` | `doc.snapshot` | Compacted Automerge `save()` output. Checkpointing, and the payload an `open`-history invite bundle points at. |
| `0x0010` | `chat.message` | Message text plus references. Structurally a `doc.change` on a channel doc, kept separate so chat can be tailed without loading the doc. |
| `0x0020` | `roster.update` | Roster document change. Workspace group only. |
| `0x0021` | `roster.revoke` | Revocation plus the epoch change that enforces it. |
| `0x0030` | `media.ref` | Ciphertext hash, per-blob key, mime, size, dimensions. |
| `0x0040` | `git.patch` | Patch bytes, base commit, target ticket. Proposal only, never applied by the receiver. |
| `0x0041` | `git.status` | CI or review status for a patch. |
| `0x0050` | `tombstone` | Target hash plus reason. Paired with an epoch advance. |
| `0x0060` | `groupinfo.publish` | Current-epoch `GroupInfo` for a self-join group, wrapped under the enrolment key exported from its parent group's epoch secret. Republished by any member that commits. Relay keeps only the latest per group. See `specs/backend/relay/channels.md`. |
| `0x0061` | `recovery.wrap` | This group's current epoch secret **and current `GroupInfo`**, sealed to a named recovery public key. The secret restores reading, the `GroupInfo` restores membership. One per recovery principal per epoch, stored by the relay under a per-epoch blinded tag rather than under the recovery key itself. See `specs/backend/relay/groups.md`. |
| `0x0062` | `history.publish` | For an `open` group only: the group's historical epoch secrets, sealed to the group's long-lived history key, plus that history key wrapped under the parent-derived enrolment key. What gives a self-joiner the history an invitee gets from a bundle. See `specs/backend/relay/channels.md`. |
| `0x0063` | `recovery.directory` | A prepare or activate record for one recovery principal's blinded wrap tags, encrypted to that recovery key in the workspace-root group. Carries current, candidate and fallback tags bound to a target group commit. See `specs/backend/relay/groups.md`. |
| `0x0070` | `head.attest` | Per-author highest `ctr` and hash, per group. Split-view detection. |
| `0x0072` | `chain.reset` | Signed declaration by an author that it lost local state, naming the last link it can prove and the counter it resumes at. Turns an honest gap into a stated one. See the author chain above. |
| `0x0071` | `checkpoint` | Signed complete snapshot manifest: author barriers, index snapshot and every document snapshot/head required to replace dropped history. Makes compaction chain-safe. See `specs/backend/relay/lifecycle.md`. |
| `0x0073` | `snapshot` | The replacement content a `checkpoint` names: a document snapshot, or the index snapshot that discovers the inventory. Referenced by envelope hash from the checkpoint and from the `drop_before` instruction, and kept forever by the relay as an anchor. Added in a later revision, because `lifecycle.md` requires the relay to verify "that all named snapshot envelopes are present and retained before deleting anything below the barrier", and this table had no kind for the envelopes that rule names. See `specs/backend/relay/lifecycle.md`. |
| `0x0080` | `media.retain` | Signed set of media ciphertext hashes this group still references. Input to blob GC. See `specs/backend/relay/media.md`. |
| `0x00F0` | `ephemeral` | Presence, typing, cursor. Not persisted by the relay. |

Kind numbers are permanent. Unknown kinds are stored and ignored, so an old
client does not lose data written by a new one.

`0x00F0` is the only kind the relay is permitted to drop. It fans out to
currently-connected subscribers and is never written to Postgres.

## Documents

Layer 4. Automerge, one document per logical object.

- One document per ticket. Where a client also keeps tickets as human-editable
  files on disk, round-trip safety with that on-disk format is preserved by
  treating the file as the materialized view and the document as the truth. A
  human editing the file produces a diff that is converted to Automerge changes
  on save. This is the same write contract a file-backed client already needs,
  with a different backing store.
- One index document per workspace, which is one per project, holding ticket
  ordering, groups and board state. It lives in the workspace root group
  (`specs/backend/relay/groups.md`).
- One document per channel per UTC day, mirroring the shard layout the git path
  already uses for chat, so that the two paths shard identically.

Why CRDT at all, when a git-backed chat log deliberately does not use one: the
objection was that Automerge files are not human-readable, and that is still
true. It does not apply here, because the relay path never writes Automerge to
disk in a place a human edits. The human-editable files stay JSONL and the
plain-text ticket format. The CRDT is the transport representation.

Checkpointing: after 512 changes or 256 KB, whichever first, a client with the
full history writes a `doc.snapshot` and clients may prune preceding changes
locally. Server-side pruning is a separate, signed operation, because dropping
envelopes interacts with author chains and with `open`-history joins. It is
specified in `specs/backend/relay/lifecycle.md` and is never something the relay
decides on its own.

## Sync

Range-based set reconciliation, the same algorithm family `iroh-docs` uses and
the right shape for a client that reconnects holding most of what it needs.

Negentropy over the per-group sequence space. A reconnecting client and the
relay exchange fingerprints over sequence ranges, recursing only into ranges
that differ, converging in O(diff) round trips rather than O(history). A client
offline for a week and a client offline for a year cost the same when nothing
changed.

Live path: after reconciliation the client holds an open subscription and the
relay pushes envelopes as they are accepted. No polling. This is the entire
`latency` 2-to-5 move.

## Transport

**WebSocket over TLS only for v1.** QUIC was in an earlier draft as the primary
transport with WebSocket as fallback. Dropped: it doubles the transport surface,
the NAT and middlebox handling, and the operator's firewall story, in exchange
for a head-of-line-blocking win that barely registers on a long-lived
subscription carrying small envelopes. One transport, port 443, works
everywhere, and the frame set below is transport-agnostic so QUIC can be added
later without touching anything above layer 1.

```
CONNECT   client hello, protocol version, requested groups
AUTH      challenge, then a signature by a device key over the challenge
ACCESS    signed cleartext access-set rotation, accepted transactionally
SUB       subscribe to groups, with a starting seq or a reconciliation request
RECON     negentropy round trip
PUSH      relay to client, one envelope
SEND      client to relay, one envelope, answered with an assigned seq or a reject
WRAP      client to relay, one recovery wrap, stored under its blinded tag
HANDSHAKE one MLS handshake message for a group, stored in order and fanned out
JOIN      one step of an invite redemption, before the joiner can authenticate
BLOB      media upload and download tickets, per specs/backend/relay/media.md
BYE       clean close
```

`WRAP` was added in a later revision, and the reason is a hole in the sentence
this document already contained. The event-kind table below says `recovery.wrap` is
"stored by the relay under a per-epoch blinded tag", and a kind lives inside
`Payload`, which lives inside `ct`. Under `enc: 1` the relay cannot read `ct`, so
that instruction was one the relay could not carry out on any deployment where the
encryption claim is true. Every other control record with the same shape is
already a frame for the same reason: `ACCESS` is not an event kind either.

So the record travels twice, deliberately, and the two copies are not redundant.
Members exchange `recovery.wrap` (`0x0061`) as an encrypted envelope, which is how
a client learns a wrap it is entitled to and how the record is signed and chained.
The relay's copy arrives as a `WRAP` frame carrying `RecoveryWrap` directly:
`group`, `epoch`, `tag` and the sealed `ct`. The relay sees the slot and the
ciphertext, and nothing else. It cannot open `ct`, it holds no recovery key, and
`tag` is derived from the group's own epoch secret rather than from any recovery
key, so what it stores is a set of opaque per-epoch slots per group.

`HANDSHAKE` was added at the same time for a reason with the same shape and a
sharper edge. A commit is what moves a group to its next epoch, and it has to reach every
member or the group forks. It cannot be an envelope: an envelope's `ct` under
`enc: 1` is an encrypted `Payload`, and a handshake message is the object that
establishes the key such a payload is encrypted under, so a member who has not
processed it cannot decrypt one. Carrying commits as `enc: 0` envelopes instead
would put signed plaintext control records in every group's log on a relay that is
behaving perfectly, and would make "every stored envelope is encrypted" false as a
matter of design rather than of failure.

The relay assigns each message a **dense per-group sequence**, and that sequence is
load-bearing in a way `relay_envelope.seq` deliberately is not. Envelopes converge
in any order because reconciliation is over a set. Handshake messages do not: a
commit for epoch N+1 applied before the commit for epoch N cannot be processed at
all. So two members committing at the same moment are serialised by the relay, and
a member replaying the log applies what it is given in the order it is given.

A subscriber receives **every** handshake message for the group, from zero, ahead
of any envelope in the same `SUB`. From zero rather than from a cursor, because MLS
state is built by applying all of them: a member joining at the latest epoch still
needs the commits that produced the earlier ones. Ahead of the envelopes, because
an envelope encrypted under an epoch the client has not reached is ciphertext it
would have to buffer and reprocess. A subscriber that cannot take its replay has
its connection ended rather than downgraded: a downgraded client is told to
reconcile, and there is no reconciliation for MLS state.

A resend after a dropped connection is answered with the sequence number the
message already has, exactly as a duplicate `SEND` is answered with its existing
`seq`. The relay stores and forwards these and can open none of them, which is the
same sentence `specs/backend/relay/groups.md` already writes about key packages and
Welcomes.

`JOIN` is the one frame a client may send before `AUTH`, and the reason is
structural rather than a concession. `AUTH` checks a device against the workspace's
access set; a device redeeming an invite is not in it, and cannot be, because what
it is asking for is the reservation that makes it admissible
(`specs/backend/relay/invites.md`, the reserve step). A relay that required authentication
first would make the first device of a workspace unable to join the workspace it is
founding.

Three steps travel on it: reserve a seat with the token and the one-time code, fetch
the sealed bundles for a scope, and commit a scope as the joiner enters it. What
stands in for a session is the record itself: the relay Argon2-verifies a code it
never learns, five wrong ones cool the tuple down, the budget is per source and per
token, and **every refusal is the same generic answer**, `quota/seats_exhausted`.
Not one code per reason. An endpoint reachable without authentication that
distinguished "no such token" from "wrong code" would confirm which tokens exist,
and that includes its own decoder: a malformed request is answered the same way.

The relay learns nothing it can act on beyond the seat. `ct` in the bundles it
serves back is sealed to the invite's `update_pub`, whose private half the joiner
derives from 32 bytes carried in a URL fragment that never reaches a server.

### The first publication of a workspace

A workspace's first `ACCESS` arrives before any group exists, because groups are
made by the trust root and the trust root is admitted by that publication. The
relay's ordinary resolution, which reads the workspace off a group the connection
named, has nothing to read.

So there is a second resolution and it is deliberately narrow: a device holding the
**live, unconsumed reservation** on a workspace's bootstrap invite is founding that
workspace. One device per workspace, only until the seat is spent, and re-read from
the tables on every request rather than remembered from the handshake, because a
session that answered from memory would be a relay serving one workspace's salt
after that workspace stopped being its. Both the state query and the publication use
it, and `genesis::consume` checks the same fact again before it destroys the key.

A `WRAP` is accepted only in `Ready`, only for a group the session's device is
admitted to, and only when its epoch strictly advances the stored wrap in that
slot. An equal or lower epoch is answered `denied/wrap_not_newer`: the relay
cannot verify a seal, so monotonicity is the whole of the defence it can offer
against a captured wrap being restored. The acknowledgement echoes the stored
`tag`, which tells the publisher which slot moved without repeating the
ciphertext. A tag may exist in exactly one group, enforced by a unique index, so
the cross-group join that would reconstruct a membership graph cannot be written
even by a client that tried.

`SEND` never fails for contention, only for size, quota, malformed header, or an
access set that no longer contains the authenticated session device. Duplicate `hash` is answered with
the existing `seq` rather than an error, so a client that retries after a
dropped connection is always safe.

Because the relay cannot establish MLS membership from opaque ciphertext, an
access-set principal could otherwise inject invalid ciphertext into any known
group id. `SEND` therefore also has an admission-blind abuse budget: 8 MiB per
authenticated principal per target group per minute, 64 MiB per workspace per
minute, and 32 MiB of not-yet-delivered envelope backlog per principal/group.
These are independent of the normal per-principal write limit and are charged
before persistence; media uses `BLOB`, not this path. Exceeding one returns a
stable retryable `group_ingress_limited` rejection and emits an operator metric
with no content-derived labels. The limits are deliberately low enough that a
known-but-nonmember group cannot be made expensive, while eight maximum-size
document changes per minute remains well above normal interactive use. Hosted
plans may raise them only as an instance-wide configuration, never per hidden
group. A future protocol version may replace this guard with a privacy-preserving
membership proof; v1 must not claim one.

`AUTH` proves the connecting party holds a key in the current **access set**. It
deliberately does not prove group membership, because proving that to the relay
would leak the membership graph. Within the access set, the relay serves any
group a connected device asks for, and non-members simply cannot decrypt. Rate
limiting and quota are per device.

## The access set

An earlier draft had `AUTH` prove possession of "a roster device key", which the
relay cannot check: the roster is encrypted to the workspace group. That left
connection auth unable to distinguish a member from a stranger, and unable to
ever cut off a revoked device. A person removed from the company on Friday could
still open a socket on Monday and pull every group's ciphertext, and the
membership transparency log they were removed from would say nothing about it,
because the relay never saw it.

So the relay gets exactly one piece of derived membership data, and no more.

```
AccessSet {
  workspace:  [32]byte      // workspace root group id
  version:    u64           // exactly previous version + 1
  prev_hash:  [32]byte      // hash of the accepted prior set; zero at genesis
  issued_at:  u64
  entries:    [[32]byte]    // BLAKE3(pubkey || workspace_salt), sorted
  authorizers:[[32]byte]    // device pubkeys allowed to rotate this set, sorted
  recovery:   [[32]byte]    // recovery pubkeys allowed the constrained rotation below, sorted
  recovery_quorum: RecoveryQuorum? // confirm-only external keys; never entries
  pending:    [[32]byte]    // recovery rotations only: the entries the replacement
                            // device is licensed to remove later. Empty otherwise.
  signer:     [32]byte      // a member of authorizers, or of recovery
  sig:        [64]byte
}

RecoveryQuorum {
  threshold: u8             // m; 1 <= m <= keys.len()
  keys:      [[32]byte]     // unique Ed25519 public keys, sorted
  sigs:      [[32]byte, [64]byte]? // only when confirming a probationary device
}
```

For this structure, the **set digest** is the canonical CBOR encoding of the
candidate `AccessSet` with both `sig` and `recovery_quorum.sigs` omitted. The
authorizer signs that digest. Each quorum signature signs
`BLAKE3("weald recovery-confirm v1" || set_digest || replacement_entry)`.
That explicit omission prevents the quorum proof from creating a recursive
"signature over the object containing this signature" definition, while binding
the confirmation to exactly one proposed access-set transition and replacement
device.

`authorizers` is the deliberately small, relay-visible mirror of the roster's
`admit` authority. It is necessary: a set of principal hashes alone lets the
relay prove that a signer is *a member*, but not that the signer is allowed to
add or remove members. The relay verifies a publication by checking all of the
following in one database transaction: `version` is exactly the previous version
plus one; `prev_hash` names the accepted previous set; `signer` was in the prior
set's `authorizers`; and `sig` verifies over canonical CBOR. It also enforces
the liveness invariants it can verify without seeing the roster: `entries`,
`authorizers`, and `recovery` are non-empty; every authorizer and recovery key
hashes to an entry; and an ordinary publication cannot remove the final prior
authorizer or final prior recovery principal. The encrypted roster-operation
verifier independently enforces the stronger semantic invariant that at least
one non-revoked admin device remains. The relay rule is intentionally narrower:
it prevents an invalid or compromised client from bricking connection-authority
rotation, while never pretending the relay can determine who is an admin.
A compare-and-swap failure returns the current set hash so the client replays
its roster operation against the current state rather than silently overwriting
a concurrent change.

### The recovery rotation

`authorizers` alone deadlocks the one flow that most needs to work. A user who
lost every device recovers onto a brand new pubkey that is in no prior
`authorizers` list, and their recovery key is not one either, so
`specs/backend/relay/auth.md` could complete the roster and MLS halves of a
recovery and then be unable to publish the access set that lets the replacement
device connect at all. For a solo admin that is a workspace bricked at the
transport layer while every key that governs it is intact.

So `recovery` names the recovery principals permitted one deliberately narrow
transition, and the relay enforces its shape rather than trusting its intent. A
publication whose `signer` is in the prior set's `recovery` is accepted only when
all of the following hold, on top of the ordinary version and `prev_hash` checks:

- It **adds exactly one** entry beyond the recovery swap: the replacement device.
  The successor recovery key's entry arrives in the same publication, in place of
  the signer's own entry, which leaves in it. Corrected from "adds exactly one
  entry" full stop, which contradicted the rule above that every recovery key
  hashes to an entry: read strictly, a rotation could not name a successor phrase
  and the one transition this section exists to permit would have been
  unpublishable.
- It **replaces the signer's own** recovery entry with exactly one successor, per
  the rotate-on-use rule in `specs/backend/relay/auth.md`.
- It adds that replacement device to `authorizers`.
- It **removes nothing else.** Not one other entry, not one other authorizer.
- It names in `pending` the entries the replacement device intends to remove
  afterwards, which is the lost-device set the user selected during recovery.
  The list may be empty and may not name any authorizer that predates this
  publication other than the user's own lost devices as chosen on that screen.
- At most one such rotation per recovery principal per 24 hours.

#### Probation, because additive-only is not enough on its own

Additive-only bounds the rotation and does not bound what the device it adds can
do one second later. A replacement device is an authorizer, and an authorizer may
publish an ordinary set that removes every other entry. Left there, a phrase
found in a drawer still locks a company out of its own relay; it just takes two
publications instead of one, and the second one looks routine.

So an authorizer introduced by a recovery rotation is **probationary**, and the
relay enforces the shape of what it may do:

- While probationary it may sign publications whose removals are a subset of the
  `pending` list pinned by the rotation that introduced it. Removing anything
  else is rejected, with the current set hash returned.
- Probation clears the moment any authorizer that predates the rotation publishes
  a set containing the replacement device. In a workspace with a second admin
  that is seconds and nobody notices it happened.
- **A pre-registered recovery quorum clears it too**, and without one a solo
  owner's probation is permanent, which is a bricked workspace rather than a
  safe one. The only pre-existing authorizer a one-admin workspace has is the
  device that was lost, so the rule above can never be satisfied: the
  replacement device could read, write and drop its own lost devices forever,
  and could never remove anybody again. That is not a conservative outcome, it
  is an unrecoverable one, and it lands on the single-founder case rather than
  on an exotic edge.

  So a workspace may register a **recovery quorum** at any time: a set of
  external Ed25519 public keys, `m` of `n`, held by people or devices outside
  the workspace, named in the access set and in the roster. A publication
  carrying `m` valid quorum signatures over the replacement device's entry
  clears probation exactly as a pre-existing authorizer would. The quorum holds
  no epoch key, no wrap and no read access whatsoever: it can confirm that a
  recovery was legitimate and can do nothing else, which is the narrowest power
  that solves this and the reason it is safe to hand to a co-founder, a lawyer
  or a second laptop in a drawer.

  Registering one is a `RosterOperation` like any other and requires `admin`.
  The clear `recovery_quorum` field above is the relay-verifiable mirror of that
  encrypted operation. The relay accepts a registration or change only from a
  prior authorizer, requires unique sorted keys and `1 <= m <= n`, and records
  it in the set chain. Changing it requires `admin` and notifies every admin
  device. A quorum key is never an authorizer and never appears in `entries`.
  To clear probation, the publication contains exactly `m` distinct valid
  signatures by configured quorum keys over the set digest and the
  replacement-device entry; those signatures authorize that confirmation only,
  not a roster or access-set change of their own.
- **Probation is therefore always resolvable, and the resolution is chosen
  before it is needed.** A workspace with a second admin resolves in seconds. A
  workspace with a quorum resolves at the speed of a phone call. A workspace
  with neither is told at setup exactly what it is choosing
  (`specs/backend/relay/auth.md`), and the weekly health check keeps saying so
  (`specs/backend/relay/lifecycle.md`).
- It **never clears on a timer.** Time cannot distinguish the owner who lost a
  laptop from somebody who copied a phrase, so a 72-hour promotion merely turns
  a theft into a delayed takeover. It clears only when a pre-existing
  authorizer publishes a set containing the replacement device.
- A solo owner is still unblocked for the work recovery exists to do: the
  replacement device may read and write the groups recovered for its user,
  rotate its phrase, and remove the explicitly pinned lost devices. It cannot
  admit, remove, or delegate authority for anybody else. There is no honest
  cryptographic way to make a phrase-only solo promotion safe, which is why the
  escape is a second admin or a quorum registered in advance rather than a rule
  that eventually gives up.
- Probation state is public, persistent, and actionable: it appears in the
  encryption panel and membership transparency log alongside the rotation that
  created it, and every pre-existing admin receives an approval or rejection
  action. It is never treated as a background warning that expires unnoticed.

The property this buys, stated at its real strength: a leaked phrase can add a
restricted device, read what its wraps already covered, and remove the devices
its owner had already marked lost. It cannot remove an admin, another recovery
principal, or itself from probation, and therefore cannot take a workspace away
from the people in it. Any attempt to try is a rejected publication and a
notification to every pre-existing admin.

Additive-only is the load-bearing constraint. A leaked recovery phrase already
grants read access to everything its wraps cover, so letting it add a device
grants an attacker nothing they did not already have. Letting it *remove* entries
would grant something genuinely new, the power to lock a company out of its own
relay with a phrase found in a drawer, and no recovery flow needs that power.
Revoking the lost devices is a second, ordinary publication signed by the
replacement device once it is an authorizer, which is the same authority path as
any other revocation and is visible as such.

Every recovery rotation is written to the membership transparency log and raises
an unexpected-roster-change notification to every admin device naming the
recovery principal used (`specs/backend/relay/lifecycle.md`). A phrase used by
somebody other than its owner is therefore loud, one-shot, and reversible by any
remaining admin, rather than silent.

Published in the clear as an `ACCESS` control frame by an authorizer on every
roster or authorizer change and at least every 7 days. The genesis set is signed
by the trust root at bootstrap and contains that device as its sole authorizer.
Clients verify that each access-set transition corresponds to a valid encrypted
roster transition; a set that does not is surfaced as a security warning and is
not treated as evidence that the roster changed. A compromised authorizer can
still abuse its real admission power; the access set must not create any extra
power beyond that.

The relay holds the workspace salt, because it has to hash the key presented at
`AUTH` to test membership. The salt therefore does not hide anything from the
relay, and is not there to. It exists so that a stolen access set is not
linkable against key material seen in any other workspace, in a backup, or in a
leak. Say it that way in the security page rather than implying more.

The salt is therefore **told to the client that asks for it**, because an entry is
`BLAKE3(pubkey || workspace_salt)` and a client that does not hold the salt cannot
compute one. Without this the genesis publication described above was unbuildable
by any real client, and the only thing that could produce a first set was a test
with a database connection. An `ACCESS` frame with an **empty body** is that
question, answered with an `ACCESS` frame carrying the canonical CBOR of

```
AccessState {
  salt: [32]byte
  head: [u64 version, [32]byte digest]?   // null before the genesis set
}
```

No encoding of an `AccessSet` is zero bytes long, so the query and a publication
cannot be confused for one another. It is accepted in the same two session states
`ACCESS` already is, `Ready` and the one-frame `Bootstrapping` state, and it is
answered `denied/group_unknown` for a connection naming no group this relay knows
and `retry/backpressure` by a relay that cannot read its own tables. A relay that
invented a salt would make every entry hash built against it permanently
unverifiable, which is why the honest answer to an outage here is "come back"
rather than a value.

The answer carries exactly the two facts a publisher needs to address its next
publication and no third. Not the entries, not the authorizers, not a count: those
are membership facts, and this question is answered to anybody who can open a
socket. `version` and `digest` are already echoed to a publisher on every accepted
rotation, so the query adds nothing that a member could not already learn.

What the relay learns from the access set: how many principals a workspace has,
when that number changes, and which presented device keys are allowed to rotate
connection access. It learns nothing from it about content, about which groups a
principal reads, or about who belongs to which group. The one place that
membership could have leaked out of a neighbouring mechanism, the per-group
recovery wrap index, is blinded per epoch for exactly this reason
(`specs/backend/relay/groups.md`), because an unblinded index would have handed
the relay the workspace's group membership graph while this page claimed
otherwise. This is a little more metadata than a count of hashes; it is the
minimum needed to make relay-side revocation authorization real rather than
trust-on-any-member.

### Provisional grants and how they end

A joiner connects under a provisional grant until an admin publishes a real set
(`specs/backend/relay/invites.md`). The grant names the `device_hash` recorded
on that joiner's invite **reservation**, not a hash carried in the invite
record, because an invite is written before its recipient owns a device. That
grant is a genuine connection credential, so it needs a defined death as well as
a defined birth, or removing a person who joined an hour ago would leave them
connected for the remaining life of their invite.

Three rules, and the relay can evaluate all of them without learning anything
new:

- **Bounded at birth.** A grant covers exactly one device hash and carries the
  invite's expiry when it is created. Before all required scope commits land it
  is backed by a live reservation; a parked reservation may extend once, never
  past that expiry. The final scope commit atomically consumes the reservation
  **but promotes the same grant to `pending_access_set` until that expiry**.
  Consumption must not erase the credential the completed join needs while it
  waits for an admin to publish the durable set. A grant is never renewable and
  cannot outlive its invite.

- **Explicit.** Revoking an invite writes a durable, opaque revocation tombstone
  before its redeemable ciphertext is removed. The tombstone retains only the
  token, terminal state, expiry and device hashes needed to find reservations
  and grants; it contains no link secret, code or code hash, name, scope
  ciphertext or content.
  It voids every grant derived from that invite immediately and closes matching
  open connections. Tombstones are retained through the latest possible grant
  expiry, then purged by the same server-time expiry worker. This is why an
  invite can disappear from the admin's live list without deleting the relay
  state required to enforce its revocation.
- **Implicit.** A grant is void once an accepted access set has contained the
  joiner's hash and a later accepted set does not. The relay keeps the set chain,
  so it can tell a set that never caught up with a new joiner, which must not
  void the grant, from one that deliberately dropped a principal it previously
  carried, which must.

The second rule is what makes the first safe to forget. An admin who removes
someone through any path at all ends their connection, whether or not anybody
remembered there was an invite.

What it buys, and this is the enterprise-grade part: revocation actually
disconnects. An `ACCESS` frame that drops an entry causes the relay to close
that device's open connections immediately and refuse new ones. Combined with
the MLS epoch change that removes their read access to future content, offboarding
becomes a single action with both halves enforced (`specs/backend/relay/lifecycle.md`).

The stale-set failure mode is bounded on purpose: if no admit-holding device has
published for 30 days the relay keeps serving the last valid set rather than
locking the workspace out. Availability beats freshness here, because the relay
is not the security boundary and never was.

Self-hosters with no public ingress may set `WEALD_RELAY_ACCESS_SET=off`, which
returns to the older any-key-may-connect behaviour. Documented as weaker, and
off is not the default.

## Limits

| Limit | Value | Why |
| --- | --- | --- |
| Envelope `ct` | 1 MiB | Larger content goes to media. |
| Media blob | 2 GiB | Object store practicalities. |
| Envelopes per connection per minute | 600 | Abuse control without impeding agents. Per connecting device key, which is the only identity the relay has. Per-agent budgets are enforced in the app, since the relay cannot see an author (`specs/backend/relay/agents.md`). |
| Groups per connection | 256 | Bounded server-side subscription state. |
| Key packages per device | 100 outstanding | Prevents exhaustion. |

## Versioning

`v` in the envelope header and an explicit range in `CONNECT`. A client offers
`min_version` and `max_version`; the relay selects the highest mutually supported
version and signs the selection into the connection challenge. The client aborts
if the selected version is below its minimum or differs from the pinned policy,
so a network attacker cannot silently downgrade a connection.

The relay accepts any envelope version it knows and stores unknown-kind payloads
verbatim. Breaking the envelope means a new version number, a published
compatibility matrix, and a period where the relay accepts both. Breaking a
payload requires a new `kind` or a versioned body schema; it does not involve the
relay at all, which is the point of the layering. Canonical-CBOR test vectors for
every supported header and frame are release artifacts, not implementation
details.
