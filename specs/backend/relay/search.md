# Relay: client-side search and cold start

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only: the Clerk
> production instance, Stripe live mode, the production Render environment and
> Postgres, the production R2 bucket, the published relay digest. No dev tier,
> no test mode, no staging tier, and no agent creates one. `local` and `ci` are
> not an exception because they reach no vendor at all. A gate that cannot reach
> production configuration fails; it never degrades to a mock, a stub, a fake, a
> skip or a newly created dev or staging resource.

Search moves entirely to the client, because the relay cannot index what it
cannot read. `specs/backend/relay/migration.md` names cold-start decrypt-and-index
as a High risk with no design behind it. This is the design.

The user-facing stake: the first ten minutes on a new laptop decide whether
someone believes this product works. A search box that returns nothing while a
progress bar crawls is indistinguishable from a broken app.

## Index model

One local index per workspace, built at decrypt time rather than query time.

- SQLite with FTS5, one database per workspace, in Application Support,
  encrypted at rest with a key in the Keychain bound to the device.
- Written as envelopes are applied, in the same transaction that updates local
  document state, so the index cannot drift from the data. An index rebuild is
  always possible from local state and never requires the network.
- Indexed: message text, ticket title and body, channel names, the project name,
  author display names, attachment filenames.
- Not indexed and not stored: anything from a group the device does not hold
  keys for, which is nothing, because it cannot decrypt it in the first place.

Query latency target is the same as the current board search in
`specs/board-search.md`, and it is benchmarked against that before Phase 3
ships. Search getting slower is the most likely way users notice the migration
and dislike it.

## Cold start

A new device joining a two-year-old workspace has to fetch, decrypt and index a
lot. The design principle is that the app is **useful immediately and honest
about what is missing**, rather than complete-or-broken.

Four phases, all concurrent with normal use:

**1. Skeleton, target under 5 seconds.** Roster, channel list,
board indexes, open tickets. These are small documents and they are what the
first screen renders. The app is navigable here.

**2. Recent window, target under 60 seconds.** The last 30 days of every group
the user belongs to, newest first. Most work is recent, so this covers the
overwhelming majority of what someone actually looks for on day one.

**3. Backfill, background, hours if necessary.** Everything older, oldest-last,
throttled to stay out of the way of foreground sync and paused on battery below
20 percent. Snapshots first where they exist, because a `doc.snapshot` replaces
hundreds of changes and decrypting it is one operation
(`specs/backend/relay/wire.md`).

**4. Media, lazy forever.** Blobs are never part of cold start
(`specs/backend/relay/media.md`).

### Saying so in the UI

Search results during backfill carry a footer naming the indexed range: "showing
results from the last 30 days, still loading older history". Not a spinner, not
a percentage nobody can act on. A person who knows the search is partial will
wait; a person shown an empty result set concludes the message is gone.

The same line appears in the workspace switcher, so the state is visible without
running a query first.

## Making backfill cheap

Three things keep phase 3 from taking a week on a large workspace.

**Snapshot-first replay.** Clients write `doc.snapshot` every 512 changes, and a
cold device fetches the newest snapshot per document plus the changes above it,
rather than replaying from zero. This is the single largest lever and it is why
snapshotting is mandatory rather than an optimisation.

**Parallel decrypt.** MLS application messages within an epoch decrypt
independently, so decryption is a thread pool sized to performance cores, not a
serial loop. Ordering is applied afterwards by the CRDT layer, which does not
care about arrival order.

**Range fetch, not stream.** Negentropy reconciles the sequence space in
O(diff), and cold start asks for ranges newest-first rather than subscribing and
waiting. A cold device and a week-offline device use the same code path.

Target on the largest fixture workspace, measured before Phase 3 ships: skeleton
under 5 seconds, 30-day window under 60 seconds, full backfill of a 40,000
envelope workspace under 20 minutes on an M-series laptop. These are gates, not
aspirations, and the fixture is checked in.

## Recovery is a colder start

After a recovery-phrase restore, history availability follows each group's
policy and its `recovery.wrap` coverage (`specs/backend/relay/groups.md`). The
recovery summary screen names which groups came back partial, before the user
starts searching and forms their own theory about what happened.

## What we must never do to make this faster

Listed so it stays a checklist rather than a judgement call under deadline
pressure, and consistent with `specs/backend/relay/verification.md`:

- No server-side index, in any form.
- No encrypted-search scheme with access-pattern leakage we cannot analyse.
- No "search assist" that sends decrypted content to an inference API without
  the per-agent disclosure that governs every other model call.
- No sampling of query text into telemetry, including as a hashed value.

## How this is built, and the one place it departs from the paragraph above

Recorded here rather than in a commit message, because two of these are choices
a reader of the section above would not predict from it.

**The database is in memory and the bytes are what is encrypted.** The index
model says "SQLite with FTS5 ... encrypted at rest with a key in the Keychain
bound to the device", and the obvious reading is a SQLite file with page-level
encryption underneath it. This project has no SQLCipher and is not going to take
one, and the alternative is a hand-written encrypting VFS: a page cipher on the
path of every read, with its own crash-consistency story to prove. So the
database is opened as `:memory:`, and `Sources/Sync/SearchStore.swift` persists
it as `sqlite3_serialize` output sealed with AES-GCM, plus a journal of sealed
batches appended between snapshots so a minute of indexing is durable without
rewriting the whole image.

Three properties follow, and they are stronger than the original wording asked
for. Nothing plaintext reaches a disk at all, not a page and not a temp file,
because SQLite is never given a filename; the negative proof greps the real file
for terms that are certainly in the corpus. A crash mid-append leaves a torn
trailing record, and everything committed before it replays. And an unopenable
file costs a rebuild rather than data, which is only true because the index is
derived from local state.

What it costs, stated rather than buried: resident memory proportional to the
index, and a snapshot write proportional to the whole index rather than to the
change. The second is paid on a compaction ratio, not per write, so the interval
between snapshots grows as the index does.

**The key is device-bound and never wrapped for anybody.** One key per
workspace, `WorkspaceScope.searchPurpose`, `ThisDeviceOnly` so a Keychain
migration does not carry it to a new Mac. A second device rebuilds its own index
rather than being sent one, which is the same reason a recovery phrase restores
the workspace and not the cache over it.

**The recent window is anchored to the corpus, not to the wall clock.** "The
last 30 days" means thirty days back from the newest day the workspace holds. On
a live workspace the newest day is today and the two readings are identical. On
a workspace nobody has written to for a month, or on the fixture, a wall-clock
window would be empty, and phase two would be a measurement of nothing.

**Indexing is fed from local state as well as from the socket.** The spec says
the index is written "as envelopes are applied", and `EnvelopeProjection` does
that. It is not sufficient on its own: `GitTransport` lands chat and tickets by
pulling files, so a hook that only sat on the socket would leave a dual-transport
workspace missing everything that arrived the other way. Cold start therefore
reads `.weald/` rather than the envelope log, which also makes it the rebuild
path.

**Only the last typed term is a prefix.** `relay ref` matches "reference"; `rel
reference` does not match "relay reference". This is what a search box does, and
it is what `Sources/Core/BoardSearch.swift` does today, so a person moving onto
this index is not surprised by it.
