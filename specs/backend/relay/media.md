# Relay: media transfer

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only: the Clerk
> production instance, Stripe live mode, the production Render environment and
> Postgres, the production R2 bucket, the published relay digest. No dev tier,
> no test mode, no staging tier, and no agent creates one. `local` and `ci` are
> not an exception because they reach no vendor at all. A gate that cannot reach
> production configuration fails; it never degrades to a mock, a stub, a fake, a
> skip or a newly created dev or staging resource.

How an encrypted blob gets to object storage, back out again, and eventually
deleted. `specs/backend/relay/groups.md` specifies the cryptography. This
specifies the transfer, the quota, and the garbage collection, none of which
existed and all of which a storage-priced product needs before launch.

## The shape of the problem

The relay cannot read the envelopes that reference blobs, so it cannot know
which blobs are still referenced. Left alone, every screen recording anyone ever
pasted stays in the bucket forever, the customer's bill grows with it, and
neither the customer nor us can say why. That is the single most expensive
consequence of blindness and it needs a mechanism, not a note.

## Upload

Media never travels through the WebSocket. Envelopes stay small and the transfer
path stays boring.

1. Client encrypts the blob with a fresh AES-256-GCM key and a random 96-bit
   nonce, prepends the nonce to the stored ciphertext, and authenticates
   `weald-media-v1 || workspace id || group id || plaintext length` as associated
   data. It computes the ciphertext hash and sends `BLOB put` naming the workspace, target group,
   hash and ciphertext length. The object key is
   `workspace/group/ciphertext-hash`; hashes are never deduplicated across groups
   or workspaces.
2. Relay checks the size limit and atomically reserves the requested bytes from
   the workspace quota, then answers with either a presigned PUT URL valid for
   15 minutes, or `exists` for that same workspace/group/hash, which makes a
   retry after a dropped upload free. An expired or aborted reservation is
   released by a cleanup job.
3. Client PUTs the ciphertext directly to object storage.
4. Client publishes a signed **retention manifest** that includes the hash, then
   emits a `media.ref` payload inside the group, carrying the ciphertext hash,
   per-blob key, mime type, size and dimensions. The client retries this ordered
   pair until both receipts are durable. Only group members can read the ref and
   learn the key.

The blob is unreferenced between steps 3 and 4. An upload with no accepted
manifest claim is collected after 24 hours, which covers the client that crashed
mid-post. Once a manifest claim exists, the relay never deletes it merely because
the group has been quiet; deletion requires a later, valid manifest omission or
an explicit valid tombstone.

**Resumable for large files.** Above 64 MB the relay issues a multipart upload
session instead, with the same 15-minute refreshable window per part. Part
numbers, expected ciphertext lengths and the reservation id are immutable; a
completed upload is finalized exactly once before the reservation becomes stored
usage. Stale multipart sessions are aborted and their reservations released. A
2 GiB video over a hotel connection has to survive a reconnect or the feature
does not work.

## Download

1. Client sees a `media.ref` it does not hold and sends `BLOB get` with the
   workspace, group and ciphertext hash.
2. Relay answers with a presigned GET URL, 15 minutes, or `404`.
3. Client fetches, verifies the hash, decrypts with the key from the envelope.

Presigned URLs are per request and never cached server-side, so a leaked URL
grants 15 minutes of access to one ciphertext the holder still cannot decrypt.

**Bandwidth.** Downloads are not metered (`specs/backend/cloud/billing.md`), but
they are rate limited per device to prevent a compromised access-set entry from
being used to drain a bucket at our expense: 50 blob requests per minute, 5 GB
per device per day, both raisable per instance.

## Quota

Checked at `BLOB put`, before the presigned URL is issued, against the
instance's plan. Over quota returns a structured rejection the client renders as
"this workspace is out of storage" with the admin's contact and, for admins, a
link to the compaction pass in `specs/backend/relay/lifecycle.md`. It never
fails silently and never accepts an upload it will later delete.

Text envelopes are never rejected for quota. Blocking someone from sending a
message because a colleague uploaded a video is a worse failure than a slightly
over-quota bill, and text is a rounding error against media anyway.

## Garbage collection

Two mechanisms, because neither is sufficient alone.

**Retention manifests.** `media.retain` has two representations. Its encrypted
payload remains the audit record group members read. Alongside it the client
sends a clear `RetentionManifest` containing only `(group id, epoch, manifest
sequence, prior digest, blob hashes, current retention verification key,
signature)`. The signing key is the epoch-derived Ed25519 seed from
`specs/backend/relay/groups.md`; the relay receives only its public verification
key. The first manifest is anchored by the group creation record. Each later
manifest must advance the sequence, name the previous digest, and verify with
the previous epoch's published key; an epoch change publishes its next public
verification key under the previous key. This gives the relay enough authority
to store and apply a manifest without learning a media reference, filename, or
content key.

The public control records live beside envelopes, not inside `ct`, and use
canonical CBOR:

```
RetentionControl { group, epoch, verifier, prev_control_hash, sig }
RetentionManifest { group, epoch, sequence, prev_manifest_hash, blobs, sig }
RetentionPolicy { group, version, media_after_days, text_after_days,
                  not_before, authorizers, signatures }
RetentionDestruction { group, kind, target_digest, policy_version?,
                       not_before, authorizers, signatures }
```

The first `RetentionControl` is emitted by the group creator with the first
epoch's verifier. A subsequent control must be signed by the prior verifier and
introduce exactly one successor verifier; manifests must be signed by the
verifier for their named epoch. The relay validates this chain before accepting
a manifest or `drop_before` instruction. Clients independently derive the same
verifiers from their MLS state and warn if a public control record disagrees, so
the relay cannot turn a storage-control record into an unnoticed membership
decision.

**A manifest is evidence, not deletion authority.** The epoch-derived verifier
proves only that a current group member produced a complete retention view. It
cannot safely decide that the group intended to destroy data: every current
member holds that verifier, including a malicious insider. The relay therefore
requires a separate, clear `RetentionPolicy` or `RetentionDestruction` before it
deletes a claimed object. These records contain no filename, plaintext, member
list, or content key; `target_digest` is a hash of the public action body.

The relay verifies each signer against the current access-set `authorizers`, so
it can enforce authorization without seeing the encrypted roster:

- If the accepted set has two or more authorizers, two distinct authorizer
  signatures are required. One signer may propose; the second sees an explicit
  summary of the affected retention rule or deletion before approving.
- A genuinely single-authorizer workspace may use one signature, but every
  destructive action has a seven-day `not_before` and is cancellable by that
  authorizer until execution. The client labels this plainly as a solo-owner
  risk, never as equivalent to two-person approval.
- A `RetentionPolicy` is the smooth path for normal automation. An admin sets
  the group retention window once; the steward may later compact or garbage
  collect only material whose policy age has passed. Tightening a policy follows
  the same approval rule and may not shorten an already-scheduled grace window.
- A one-off `RetentionDestruction` is required for an explicit attachment
  deletion outside policy. It is idempotent on `(group, kind, target_digest)`;
  a cancellation is another threshold-authorized clear record and is possible
  until `not_before`.

The public retention verifier continues to protect chain continuity and detect
the removed-member successor race below. It grants no right to destroy data.

### The successor race, and why first-writer-wins is not enough

Signing a successor with the prior verifier is not, on its own, a control. The
member being removed by a commit held the prior epoch's verifier too, and can
sign a successor naming a verifier they invented. The relay cannot tell an
invented successor from a derived one, because the whole point is that it holds
no MLS secret. Left there, a removed member could capture the retention chain on
their way out and issue manifests omitting every blob, and the group's media
would be deleted at the end of the grace period by the relay's own correct
behaviour. Destroying a company's attachments on exit is the most damaging thing
a departing insider could be handed, so the chain gets three rules rather than
one.

1. **One successor per epoch, first valid wins.** The relay accepts at most one
   `RetentionControl` for a given `(group, epoch)`. Honest members publish theirs
   in the same batch as the commit that rotated the epoch, so under normal
   operation the legitimate record is already recorded before a removed party
   could send one.

2. **A conflicting successor freezes deletion.** A second, differently-signed
   control for the same `(group, epoch)` is not rejected and forgotten.

   Differently-signed means differently-signed, byte for byte, and that puts an
   obligation on the client rather than a caveat on the relay. A successor names
   its predecessor by digest and the digest covers the signature, so a client
   that re-signs a record it has already published computes a different digest
   and its next record names a predecessor no relay holds: the chain stops
   advancing. Ed25519 is deterministic in RFC 8032 and is not in every
   implementation of it (CryptoKit randomises `Curve25519.Signing`), so a client
   **stores the signed record it published** and retransmits those bytes rather
   than signing again. See `Sources/Sync/RetentionKeyStore.swift`. The relay
   stores it as evidence, refuses every retention-driven deletion for that group
   until the conflict clears, and reports the group as frozen on `/readyz` and in
   the client's encryption panel. Every member's client raises a
   retention-fork warning naming the epoch, alongside the split-view and
   transparency-log alarms it already renders
   (`specs/backend/relay/verification.md`).

3. **Only a client can clear a freeze.** Members derive the correct verifier for
   the epoch from their own MLS state, and any member holding the true epoch
   secret publishes a signed resolution naming which control is genuine. The
   relay applies it without being able to evaluate it, which is the correct
   division: the relay is the enforcement point for a decision it never makes.

The resulting property, stated at its real strength rather than a flattering one:
a removed member cannot cause deletion, because their forged branch freezes the
group instead of governing it. They can cause a **freeze**, meaning the group
stops garbage-collecting media until a member resolves it, and its storage grows
in the meantime. That is a nuisance and a visible alarm rather than data loss,
and trading availability of a cleanup job for the integrity of a customer's
attachments is not a close call.

Every group emits a manifest immediately before a new `media.ref`, after an
attachment deletion, and on the same schedule as checkpoints. The relay stores
the latest valid manifest per group and takes the union across groups as the
live set. A manifest that fails verification is retained as evidence but never
used for deletion.

A blob may be deleted only after it appeared in at least one valid manifest, is
absent from a later valid manifest for every group that previously claimed it,
and its threshold-authorized policy or destruction record is due. The existing
30-day grace period remains a floor; a policy can lengthen it but never shorten
it. The grace period matters: a group whose members were all on holiday must not
lose attachments because nobody published a newer set. An unclaimed interrupted
upload follows the separate 24-hour rule above. For policy evaluation the relay
uses its immutable receipt time for the blob's first accepted manifest claim,
not a client-supplied media timestamp, so a malicious client cannot backdate an
upload into immediate deletion.

**Explicit tombstones.** A user deleting an attachment writes a `tombstone`
naming the ciphertext hash, publishes a matching valid manifest omission, and
requests a `RetentionDestruction`. The UI hides the attachment immediately for
that client and labels it “pending secure deletion”; the relay makes it
unavailable only when the required approval and `not_before` have landed. It
then retains the object for the seven-day recovery window before physical
deletion. This is deliberately a little slower than a local delete: an active
insider must not be able to turn one click into irreversible server-side
destruction.

Deduplication is by ciphertext hash and identical plaintext encrypted twice
produces different ciphertext, so cross-group dedupe does not happen. A blob
referenced by two groups is therefore two objects, and each group's retention
set governs its own copy independently. This is slightly wasteful and it is the
correct trade: shared storage across groups would mean one group's deletion
could break another's attachment.

## What the relay learns

Blob sizes, upload and download timing, and which group's retention set names a
hash. This is the same metadata class already disclosed in
`specs/backend/cloud/overview.md` and it must be listed there explicitly rather
than folded into "envelope sizes", because a retention set makes the association
between a group and a blob visible to us in a way individual envelopes do not.

Naming that in `/security` costs us nothing and being caught omitting it would
cost a great deal.

## Client behaviour

- Thumbnails are generated client-side and stored as their own small blobs, so
  a board view does not download originals. There is no server-side image
  processing and there cannot be.
- Downloads are lazy by default and prefetch only for the active channel's most
  recent 20 references, which keeps a fresh device from pulling gigabytes on
  first sync (`specs/backend/relay/search.md` covers the same concern for text).
- A reference whose blob is gone renders as "deleted or expired" with the
  original filename and date, never as a broken image.
