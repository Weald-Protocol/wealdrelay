# Relay: identity

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only: the Clerk
> production instance, Stripe live mode, the production Render environment and
> Postgres, the production R2 bucket, the published relay digest. No dev tier,
> no test mode, no staging tier, and no agent creates one. `local` and `ci` are
> not an exception because they reach no vendor at all. A gate that cannot reach
> production configuration fails; it never degrades to a mock, a stub, a fake, a
> skip or a newly created dev or staging resource.

Who a principal is, how a device proves it, and how an agent gets bounded
authority. Layer 0 of the stack in `specs/backend/relay/overview.md`.

This replaces the trust-on-first-push root described in
`specs/sync-substrate.md`, which scored `identity` 4 because whoever can push to
`.weald/keys/` can publish a key under someone else's handle.

## Principals

Four kinds. All are Ed25519 keypairs and all are addressed by the 32-byte
public key. The flows that create them live in `specs/backend/relay/auth.md`.

**Device.** A physical machine belonging to one human. The private key is
generated on-device and never leaves it. On macOS the key lives in the Secure
Enclave when the hardware supports it and in the Keychain with
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` otherwise. There is no export, no
backup and no sync of a device key. Losing the device means revoking it.

**User.** A human, defined as the set of their devices. A user has no key of its
own. Its `user_id` is a 32-byte random value generated with the first device
and copied, unchanged, into every one of that human's roster entries. It is
encrypted roster data: the relay never receives it. It is an identifier for
ownership, pairing and stable DM derivation, not a credential and not a secret.
Losing every device does not make the value an authentication factor; recovery
restores it from the workspace roster. This matters: there is no long-lived
secret to steal that represents a person, only per-device secrets that can be
revoked individually.

**Agent.** A non-human principal: a Claude Code session, a goose run, a CI hook,
an MCP client. It has its own keypair and a delegation certificate. An agent is
never a device and never borrows a human's key, so every line an agent writes is
attributable to that agent and to the human who delegated it.

**Recovery.** A keypair derived from a user's 24-word recovery phrase, created
during first-device setup and never optional. It is an MLS leaf in the workspace
root group only; every other group reaches it through a `recovery.wrap` event,
carrying that group's current epoch secret and `GroupInfo`, rather than through a
leaf, so that active groups keep ratcheting cleanly
(`specs/backend/relay/groups.md`). Those wraps are indexed under a per-epoch
blinded tag rather than under the recovery key, so a recovery principal is not a
stable identifier the relay can follow from one group to the next. It holds `admin`. It is not a device: it never
participates in normal sync, writes normal application data, or delegates
authority. Its one exception is a narrowly-scoped recovery session: it may
authenticate, create one replacement device, rotate itself, and revoke the
lost-device set as one recovery transaction. It cannot use that session to
invite another person, edit a roster arbitrarily, or remain connected afterwards.
Full lifecycle and the exact transaction are in `specs/backend/relay/auth.md`.

## Roster

Each workspace has a roster: the signed set of principals and their standing.
The roster is itself an Automerge document synced through the relay like any
other, encrypted to the workspace root group.

A roster entry is:

```
{
  "pubkey":    "<32 bytes, base64url>",
  "kind":      "device" | "agent" | "recovery",
  "owner":     "<user id>",
  "label":     "Hunter's MacBook Pro",
  "added_at":  "<RFC3339>",
  "added_by":  "<pubkey of the admitting device>",
  "revoked_at": "<RFC3339 | null>"
}
```

Admission requires a signature from a device already holding the `admit`
capability. The first device in a workspace self-admits, becomes the trust root,
and is permanently an admin; every later entry chains to it. A workspace must
always retain at least one non-revoked admin, so the last one cannot be revoked
(`specs/backend/relay/auth.md`). That chain is what moves `identity` from
4 to 5: a malicious committer cannot fabricate an entry because there is no
file to write, only a chain to forge, and forging it requires a private key
nobody else holds.

### Authorization operations are not CRDT merges

The roster document is an Automerge materialized view, but a grant, revocation,
or capability change is a security operation and must not inherit Automerge's
last-writer-wins behaviour. Each such operation has a canonical signed form:

```
RosterOperation { id, base_head, kind, target, delta, signer, sig }
```

`base_head` is the hash of the currently accepted authorization-operation head.
Clients accept an operation only when its base is their current head and the
signer had the required capability in that head; the resulting operation hash
becomes the next head. The operation is carried in the MLS commit or workspace
payload that applies its effect, and its `id` makes retries idempotent. A
concurrent operation is retained as rejected evidence, never silently merged;
its initiator must fetch the new head and explicitly reissue it. This gives
security state a linear, auditable history while keeping ordinary roster display
fields and application documents CRDT-friendly.

Revocation writes `revoked_at`, triggers an MLS epoch change in every group the
principal belonged to (`specs/backend/relay/groups.md`), and publishes a new
access set so the relay drops the principal's connections
(`specs/backend/relay/wire.md`). All three halves are one action in the client
and the full sequence is in `specs/backend/relay/lifecycle.md`. Ciphertext
written after that epoch is unreadable to the revoked key, and the revoked key
can no longer fetch the ciphertext written before it.

## Device enrollment

Adding a second device is a pairing flow, not a password.

1. New device generates a keypair and displays a short authentication string
   derived from its public key plus a nonce.
2. Existing device scans or the user types the string.
3. Existing device verifies, signs a roster entry, and adds the new device to
   every MLS group the user belongs to as a new leaf.
4. Group epochs advance. New device receives the current epoch key and can
   decrypt from that point forward.

Whether it can decrypt what came before is the history policy question, handled
in `specs/backend/relay/groups.md`. Do not answer it here.

## Delegation certificates

The mechanism that makes agent authority bounded. A certificate is a signed
statement by a device that a named agent key may do specific things, in specific
places, until a specific time.

```
{
  "v":        1,
  "agent":    "<agent pubkey>",
  "issuer":   "<device pubkey>",
  "issued_at":"<RFC3339>",
  "expires":  "<RFC3339>",
  "scopes":   ["workspace", "channel:eng"],
  "caps":     ["chat.write", "ticket.read", "ticket.transition:todo->doing", "git.patch.propose"],
  "sig":      "<Ed25519 over the canonical encoding of the above>"
}
```

Rules:

- **Expiry is mandatory.** No certificate is issued without one. Default is 24
  hours for an interactive agent session, 7 days for a long-running bot.
- **Expiry is evaluated against a bounded clock.** A client checks a certificate
  against both local time and observed relay time, so a device with a wrong
  clock cannot honour a dead certificate. Server-owned expiries are instead
  enforced by the relay's clock. The skew bound, how a client detects that it
  is outside it, and what it refuses to do while it is, are in
  `specs/backend/relay/operations.md`.
- **Attenuation only.** An agent may sub-delegate to a child agent, but the
  child's scopes and caps must be a subset and its expiry no later. Chains are
  verified end to end on receipt.
- **Verification is client-side.** The relay cannot check a certificate, because
  the certificate is inside the encrypted envelope. Every receiving client
  verifies the chain before applying the event to local state. An event whose
  chain fails verification is stored and rendered as rejected, never silently
  dropped, so that tampering is visible rather than invisible.
- **Certificates are data.** They live in the roster document and sync like
  everything else, so revocation propagates through the same path as membership.
- **Expiry removes the leaf, not just the authority.** See below. A certificate
  that has expired while its MLS leaf is still in the group is a hole, not a
  bounded credential.

### Agent leaf lifecycle

The certificate bounds what an agent may **write**. On its own it does nothing
about what an agent may **read**, because reading is holding an epoch key, and
an expired agent whose leaf is still in the ratchet tree keeps receiving them.

So expiry is enforced in the tree as well:

- Every client, on sync, computes the set of agent leaves in each group whose
  certificate has expired or been revoked.
- The **epoch steward** for a group is the connected member device with the
  lowest pubkey, and it issues a batched `Remove` commit for that set. Any other
  member device takes over after a 60-second grace period if the steward does not
  act, so a sleeping laptop delays eviction rather than preventing it.
- Stewardship deliberately does not require `admit`. Evicting a leaf whose
  certificate has expired is not an admission decision: the expiry is signed by
  the issuer, every client computes the same set independently, and a commit
  removing anything else fails validation on arrival. Requiring `admit` would
  have meant that a workspace whose only admin was on holiday kept expired
  agents reading it, which is the failure this rule exists to prevent. Roster
  operations still require `admit`, and this is not one.
- Removals batch: one commit per group per eviction pass, not one per agent.
  With a dozen agents cycling daily certificates this is one or two commits a
  day per group, not dozens.
- If no member has been online to evict, an agent's own client refuses to use
  keys received after its certificate expired. That is honest defence in depth
  and nothing more, since the agent could lie, which is why the tree-side
  eviction is the real control.

Say the resulting property precisely, because the earlier phrasing overclaimed
it. A leaked agent key is bounded in **write authority** by its capabilities and
in **time** by its expiry. It is not bounded in read access during its validity
window: an agent scoped to the workspace can read that project, since a
workspace is one project (`specs/backend/relay/multi-workspace.md`), including
history because the workspace root group is `open`. A narrower grant is a channel
scope, not a sub-project. The client's agent panel states the read scope in those
words at issuance, next to the write scopes, because a human granting a 24-hour
certificate should know they are also granting a 24-hour read of everything in
scope.

### Capability vocabulary

Namespaced, dot-separated, with an optional argument after a colon. Initial set:

| Capability | Grants |
| --- | --- |
| `chat.read` | Decrypt and read channel messages in scope. |
| `chat.write` | Post messages. |
| `ticket.read` | Read ticket documents. |
| `ticket.write` | Edit ticket body and fields. |
| `ticket.create` | Create new tickets. |
| `ticket.transition:<from>-><to>` | Move a ticket between two named states. |
| `git.patch.propose` | Attach a patch to a ticket. Never applies it. |
| `media.write` | Upload encrypted blobs. |
| `admit` | Add principals to the roster. Devices only, never agents. |
| `roster.revoke` | Revoke a principal. Devices only. |
| `admin` | Grant and revoke `admin`. Held permanently by the first device enrolled. Devices and recovery keys only. |

`admin`, `admit` and `roster.revoke` are permanently undelegatable to agents. An agent
cannot expand the trust boundary it lives inside. This is enforced at
certificate issuance and again at verification.

## Signing

Every envelope is signed by the writing principal, before encryption, over a
canonical encoding of the plaintext payload. Sign-then-encrypt, so that a group
member cannot re-attribute a decrypted message to someone else.

The mutable envelope header fields travel inside that signature as the payload's
`hdr` field, so `enc`, `group` and `epoch` are bound by the same signature and a
relay cannot relabel an envelope it cannot decrypt. `specs/backend/relay/wire.md`
is the authority on the exact binding and on why it is a copy of those fields
rather than a hash of the header, which would be circular. Do not restate the
construction here; this page previously said "the payload plus the envelope
header" while that page said the payload alone, and the disagreement was the
bug.

Canonical encoding is deterministic CBOR. No JSON canonicalisation, because the
existing `.weald` chat signing already learned that lesson and the
round-trip-safety requirement in `CLAUDE.md` applies to files on disk, not to
the wire.

## Relationship to `.weald/keys`

The existing per-device Ed25519 keys committed under `.weald/keys/` stay valid
and stay in use for the git path. Same key material, two trust roots: the repo
for git-synced history, the roster for relay-synced history. A device
participating in both publishes the same public key to both.

Legacy unsigned lines remain unverified forever. There is no migration and there
cannot be one, per `specs/sync-substrate.md`.

## Open questions

- Whether a quorum should also be able to authorize a recovery, rather than only
  to confirm one. The confirm-only recovery quorum in
  `specs/backend/relay/wire.md` is required for general availability, because
  without it a one-admin workspace has no way out of probation. Letting a quorum
  additionally start a recovery, for a team that would rather not hold a phrase
  at all, is the larger version of the feature and is not scoped.
- Whether a hardware security key (FIDO2, resident credential) can act as a
  portable device identity for the browser client. Would materially improve
  `reach`. Not scoped.
