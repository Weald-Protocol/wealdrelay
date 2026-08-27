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
   released by a cleanup job. The URL is **signed for exactly the declared
   ciphertext length**: `Content-Length` is part of the signature, so a request
   announcing any other length is not the request that was signed, and a body that
   disagrees with its own header is refused by the object store. Without that, the
   quota is advisory, because the relay charges the declared length and never
   re-measures the object: declare one byte, presign, and PUT the store's whole
   single-request ceiling. Each multipart part URL is bound the same way, to the
   length recorded for that part number.
3. Client PUTs the ciphertext directly to object storage, at exactly the length it
   declared.
4. Client publishes a signed **retention manifest** that includes the hash, then
   emits a `media.ref` payload inside the group, carrying the ciphertext hash,
   per-blob key, name, mime type, size and dimensions. The name is carried here
   because this is the only record in the system that can hold one: the bucket
   stores opaque objects under their content address, so a workspace that did not
   seal a name beside the hash could never show its own members anything but
   digests. Sealed, so the relay is no better off than before. The client retries this ordered
   pair until both receipts are durable. Only group members can read the ref and
   learn the key.

The claim in step 4 is where reserved bytes become stored bytes, so it is also
where the declaration is checked against reality. Before a manifest is applied,
the relay heads each object it names that still has an unfinalized reservation,
and refuses the whole manifest with `hash-mismatch` if the stored object is
longer than the bytes that reservation was charged for. Without that check the
declaration is the accounting: reserve one byte, PUT sixty-four megabytes, claim
it, and the workspace is charged one byte while the bucket holds the rest, so the
storage ceiling never binds. A shorter object is accepted and charged at the
declared length, because an honest client that compressed better than it
predicted should not be refused.

The blob is unreferenced between steps 3 and 4. An upload with no accepted
manifest claim is collected after 24 hours, which covers the client that crashed
mid-post. That window is `WEALD_RELAY_MEDIA_UNCLAIMED_GRACE_SECONDS`, whose
default is the promised 24 hours; an operator shortens it on a probe instance and
forces one collector pass with `POST /gc/sweep`
(`specs/backend/relay/janitor.md`), because a day is longer than any test against
a running relay can wait and a promise nothing can observe is not a proof. Once a manifest claim exists, the relay never deletes it merely because
the group has been quiet; deletion requires a later, valid manifest omission or
an explicit valid tombstone.

**Resumable for large files.** Above 64 MB the relay issues a multipart upload
session instead, with the same 15-minute refreshable window per part. Part
numbers, expected ciphertext lengths and the reservation id are immutable; a
completed upload is finalized exactly once before the reservation becomes stored
usage. A 2 GiB video over a hotel connection has to survive a reconnect or the
feature does not work.

A session owns exactly `ceil(total_bytes / part_size)` parts, and a part number
outside that range, or a part longer than the session's part size, is refused
with `envelope-too-large`. Each `MULTIPART part` is charged one request against
the same per-device budget `BLOB get` and `BLOB list` are charged against,
because an uncharged part request mints a presigned 64 MiB upload URL for free.
Completion reconciles the client's submitted part list against the parts the
relay recorded: a duplicate number, or a number never issued for that session, is
refused rather than assembled, so no part is written into the object twice.

Part objects are the relay's, not the workspace's: they live under the synthetic
`_multipart/<session>` key space, so no sweep that walks real workspaces can see
them. They are therefore deleted explicitly, on all three exits. Completion
deletes them after assembly, abort deletes them before releasing the reservation
(release is what makes the bytes free again, and returning quota while leaving
the parts in the bucket is unbounded unaccounted storage), and the janitor
deletes the recorded parts of every stale session it aborts. All three are
idempotent, because deleting an object that is not there is not an error on
either backend.

An abort is only a reversal of an unfinished session. A session that has already
completed is refused, because its reservation stays unfinalized until a manifest
claims the hash: releasing it there would return quota for bytes that are in the
bucket and drop the reservation row the collection rule reads to know the
assembled object is referenced. A session already aborted is answered with the
same `MultipartAborted` the first abort gave, and the release is not run twice.

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

## Listing

`BLOB list` names a workspace and a group and is answered with one entry per
stored object: the ciphertext hash and the stored byte length, and nothing else.
The relay never held a key, so it has no filename, mime type, author or
timestamp to report, and a listing that carried any of those would be the relay
claiming to know something about content it cannot read. A name, where the
client has one, comes from the workspace's own sealed `media.ref` records.

Authorized exactly like `BLOB get`, so a device can only ever enumerate a group
of its own workspace, and charged one request against the same limiter, because
a free listing is a free probe for which objects exist. The daily byte budget is
not charged: a listing moves hashes and lengths rather than objects. The list is
bounded by `MAX_LIST` on both sides.

The surface above it is `/specs/workspace-files.md`.

## Quota

Checked at `BLOB put`, before the presigned URL is issued, against the
instance's plan. Over quota returns a structured rejection the client renders as
"this workspace is out of storage" with the admin's contact and, for admins, a
link to the compaction pass in `specs/backend/relay/lifecycle.md`. It never
fails silently and never accepts an upload it will later delete.

Text envelopes are never rejected for quota. Blocking someone from sending a
message because a colleague uploaded a video is a worse failure than a slightly
over-quota bill, and text is a rounding error against media anyway.

**The ceiling is readable before it is hit.** The refusal above is raised at `BLOB
put` against the declared length and nowhere else, so a client used to learn the
plan existed only by being refused at it, after a person had already chosen a file
and the client had already sealed it. Reaching a real ceiling cost hours of real
uploading, which made the refusal unobservable anywhere not prepared to fill the
plan (WEALD-L401). A device already authorized for the group may therefore ask:

```
Request  Quota { group }
Response Quota { stored_bytes, reserved_bytes, limit_bytes }
```

`stored_bytes` is what claimed objects charge and `reserved_bytes` is what uploads
in flight hold, and both are answered because the ceiling is enforced against
their sum: a client shown only `stored_bytes` would promise room a concurrent
upload has already taken. `limit_bytes` is absent exactly when the relay was
configured with no ceiling at all, which is the self-hosted shape; a ceiling of
zero is a real limit and a different answer, so the field is nullable rather than
sentinel. Remaining headroom is the client's subtraction, saturating at zero,
because a lowered ceiling can leave a workspace already over it.

Authorized exactly as a listing is, by the group belonging to the session's own
workspace, and charged one request against the same per-device limiter, because a
free number is a free poll. It names no object, no filename and no member: three
integers a member of the same workspace could already total up from a listing. The
row is written with the instance's configured limit before it is read, the same
`ensure_quota_row` call `BLOB put` makes, so a workspace that has stored nothing
reports its ceiling rather than reporting none. A relay that does not know this
request answers an unknown-tag error frame and the client shows no warning rather
than failing anything; the upload it was going to warn about is still refused at
the relay if it should be.

**An operator can set a workspace's ceiling.** `POST /media/quota` on the operator
listeners, behind `WEALD_RELAY_OPERATOR_TOKEN` and mounted only where that bearer
exists, writes `relay_quota.limit_bytes` for one named workspace and nothing else:

```
POST /media/quota  {"workspace": "...", "limit_bytes": 4096}   # null is unlimited
200                {"workspace", "stored_bytes", "reserved_bytes", "limit_bytes"}
```

It exists so `quota/storage_exhausted` is an assertion instead of an argument: put
the ceiling one object away and the refusal a full workspace gets is driven in
seconds by the same code that raises it in production. It cannot delete an object,
cannot lower `stored_bytes` and takes no per-object target, so the worst it grants
an operator holding the bearer is refusing their own instance's next upload, which
is authority `WEALD_RELAY_MAX_STORAGE_GB` already gave them. A negative limit and
an empty workspace name are refused rather than written. Every other quota rule,
including the reservation arithmetic the ceiling is enforced against, stays with
the store.

**One object is charged once, and a missing object is not a charge.** A finalized
reservation is the relay's own record that it confirmed the object exists, so a
finalized row whose object is *not* in the store is a contradiction, and it is
reachable by ordinary means: the retention sweep removes the object before the row
on purpose, so a crash or a failed row delete leaves exactly that state, as does an
operator removing a bucket object. On the next `BLOB put` for the same triple the
relay retires every such stale row and returns its bytes to the workspace before
deciding whether the upload fits, so the re-upload is charged as a first upload
rather than a second helping for one object. What it must not do is answer
`exists`: the object is genuinely absent, and telling the client its upload is
unnecessary would turn a billing error into missing media. A row delete the sweep
could not perform is counted in the sweep's own note and logged, because an
uncollectable row holding a charge that nothing reclaims is the state an operator
has to be able to see.

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
introduce exactly one successor verifier; manifests must name the group's latest
epoch and be signed by that epoch's verifier. The relay validates this chain
before accepting a manifest or `drop_before` instruction, and a manifest naming a
superseded epoch is refused and recorded as evidence: the party still holding an
older epoch's key is the member the rotation removed, and an omission from the
latest manifest is what the collection rule reads as permission to delete. Clients independently derive the same
verifiers from their MLS state and warn if a public control record disagrees, so
the relay cannot turn a storage-control record into an unnoticed membership
decision.

**The relay states the chain position; the client does not guess it.** The
manifest chain is per group, but a client can only see its own device state, and
the two are not the same fact. A device that joined an existing group holds no
manifest of its own, so a client deriving `sequence` and `prev_manifest_hash`
from local state alone sends the first sequence into a group already past it,
which this section's own advance rule refuses. Because the client only records a
manifest it saw acknowledged, that refusal is permanent: the same refused record
is sent again for the life of the group (WEALD-L355). A client therefore asks:

```
Request  RetentionPosition { group }
Response RetentionPosition { control_epoch, control_digest, next_sequence,
                             prev_manifest_hash, blobs }
```

`control_digest` is absent exactly when the group has no `RetentionControl` at
all, which is the only case `control_epoch` carries no meaning; epoch zero with a
chain and no chain at all are opposite instructions to the client. `next_sequence`
is the sequence the next manifest must name, `prev_manifest_hash` the digest it
must name as its predecessor, and `blobs` the claim set the latest manifest
named. The answer names no content, no filename and no member: it is an epoch,
two digests, a counter, and ciphertext hashes the same caller can already read
back with a listing. It is authorized exactly as every other retention request
is, by the group belonging to the session's own workspace, and it is read only.

A relay that does not know this request answers with an error frame for an
unknown `BLOB` tag, and a client that gets one falls back to its own log rather
than failing the upload. That is the compatibility rule for this wire in both
directions: a peer that has never had to know a message must not be broken by
it, so neither the question nor the answer is ever required for a transfer to
succeed.

A client that publishes a manifest and is refused re-reads the position once and
republishes from it; a second refusal is a real refusal.

**The successor control may be published by any member who holds both keys.**
The genesis record needs the founder, because self-signing is the founder's
possession proof. Every later record needs the prior epoch's key and the prior
record's digest, and both are held by every member who lived through that
rotation, not only by the founder. A client that holds no key for epoch zero
therefore publishes its chain from the earliest epoch it can actually anchor:
the successor to the `control_epoch` the relay reported, when it holds the keys
for both. Before this, such a client published no control at all, so its
manifests named an epoch newer than the relay's latest control and were refused
under the epoch rule above.

**A manifest is the complete claim set, so it is published as a union.** Because
an omission is the only deletion signal the relay has, a device that cannot
replay every historical `media.ref` must not publish only what it can see: for a
joiner that is every attachment written before it arrived, and publishing that
set would silently un-claim the founder's attachments. A client therefore
publishes the union of what it can prove and the `blobs` the relay reported.
Dropping a claim is a `RetentionDestruction`, which is threshold-authorized and
deliberate, never an accident of what one device happened to have decrypted.

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

   The wire shape is `RetentionResolution { group, epoch, verifier, sig }`,
   `BLOB` tag 6 (request) / 6 (response `RetentionResolved`, tag 11 on both
   sides), self-signed by the verifier it names exactly like a genesis
   control. The relay accepts it once `verifier` matches a candidate already
   on file for `(group, epoch)`, either the settled `relay_retention_control` row or
   a `relay_retention_control_conflict` row, and then clears
   `relay_group.frozen_reason`. Until WEALD-L294, `clear_freeze` existed in
   `backend/wealdrelay/src/media/retention.rs` and nothing on the wire could
   ever call it: a frozen group had no client-reachable recovery at all. See
   `Sources/Sync/RetentionRecords.swift`'s `Resolution` and
   `Weald relay-client resolve-freeze --id EPOCH`.

   WEALD-L716 records what the recovery cost when the client read the wrong
   answer. A cleared freeze is `Response::RetentionResolved`, tag 11 and an empty
   body; a retention *control* is acknowledged with tag 9 and a digest. The Mac
   client accepted only tag 9, so a resolution that actually cleared the freeze
   exited non-zero saying the group was not resolved. The client now reads both
   tags, asks the relay for its settled epoch with `RetentionPosition` before
   signing anything, prints that epoch beside its own, and offers every epoch it
   holds a key for rather than only the newest: the relay accepts a resolution at
   any epoch it has a candidate control for, so a member that never held the
   conflicting controls can still resolve after one sync. A verifier the relay has
   no candidate for is refused `writer_not_in_access_set` with the detail
   `unknown_retention_verifier`, so an operator is not sent hunting a membership
   fault that does not exist.

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
