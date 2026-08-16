# Relay: the MLS binding

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only: the Clerk
> production instance, Stripe live mode, the production Render environment and
> Postgres, the production R2 bucket, the published relay digest. No dev tier,
> no test mode, no staging tier, and no agent creates one. `local` and `ci` are
> not an exception because they reach no vendor at all. A gate that cannot reach
> production configuration fails; it never degrades to a mock, a stub, a fake, a
> skip or a newly created dev or staging resource.

The highest-risk engineering in this programme, and until now the only piece
documented nowhere. The client is Swift on macOS; the mature MLS
implementations are Rust. Something has to bridge them, and doing that badly
would mean either a memory-safety bug in the component holding every key, or a
hand-rolled MLS, which
`specs/backend/relay/groups.md` explicitly refuses.

## Decision: OpenMLS behind a narrow Rust FFI

**OpenMLS**, not mls-rs. Both are credible. OpenMLS is audited, has the larger
independent user base, and its storage provider trait is a clean seam for
putting state where we want it. Revisit only with a specific reason written
down.

**A narrow, hand-written C ABI**, not a general binding generator. The surface
is small enough to specify completely, and every function that crosses it is a
place a mistake becomes a key-handling bug, so the surface stays small
deliberately.

## The seam

```
weald_mls_create_group(config)                 -> GroupHandle
weald_mls_join_external(group_info, auth)      -> GroupHandle, Commit
weald_mls_add(handle, key_package)             -> Commit, Welcome
weald_mls_remove(handle, [leaf])               -> Commit
weald_mls_commit_pending(handle)               -> Commit
weald_mls_process(handle, message)             -> ProcessedMessage
weald_mls_encrypt(handle, plaintext)           -> ct
weald_mls_decrypt(handle, ct)                  -> plaintext, sender
weald_mls_export(handle, label, len)           -> secret
weald_mls_group_info(handle)                   -> GroupInfo
weald_mls_epoch(handle)                        -> u64, tree_hash
weald_mls_free(handle)
```

Everything above them, including envelope construction, author chains,
certificates, retention and every product decision in this spec family, lives in
Swift. Everything below is OpenMLS unmodified.

**Corrected in step 7, from twelve functions to fourteen**, and to sixteen on
2026-08-09 by the two acceptance-ordering functions described below. The list above could
consume a key package in `add` and could never produce one, and could accept a
`Welcome` from nobody: `add` returns a welcome for the joiner and no function took
one. So the ordinary invite path in `specs/backend/relay/invites.md` was
unimplementable as written, and `wire.md`'s `key_packages_remaining` counted a
thing this seam could not make. `join_external` does not stand in for either: an
invitee to a closed group never sees a group info. The two additions are

```
weald_mls_key_package(config)                  -> KeyPackage
weald_mls_join_welcome(config, welcome)        -> GroupHandle
```

and they are reviewed as the security change the risk table asks for. Neither
widens what crosses the boundary in kind: `key_package` returns the public key
package the relay already stores a count of and keeps its private half in the
provider's storage, and `join_welcome` consumes bytes the same way `process`
does. The exporter is still the only function that returns key material.

Two further corrections of the same kind, both made in step 7 and both narrower
than they look:

- **`weald_mls_epoch` returns the epoch authenticator, not the tree hash.**
  OpenMLS exposes `MlsGroup::tree_hash` only behind its `test-utils` feature, and
  a shipped library that enabled another crate's test feature would be shipping
  code upstream does not treat as API. The epoch authenticator is what RFC 9420
  defines for exactly this comparison and covers more: two members who agree on
  it agree about the whole epoch's state rather than the ratchet tree alone.
- **Merging a commit is separate from producing one.** `add`, `remove` and
  `commit_pending` return a commit and leave it pending; a `merge_pending` call
  advances the epoch once the relay has accepted the write. Merging inside those
  functions would put this device an epoch ahead of a group that never received
  the commit, unable to read what the group is still sending and unable to say
  why. It is the same ordering rule `wire.md` uses for the author chain: reserve,
  send, then advance.

  The Swift side keeps that ordering as of 2026-08-09 (register BR-025).
  `GroupSession.commitPending` returns the commit unmerged and reports
  `awaitingAcceptance`; the caller publishes it, waits for the relay to number it,
  and only then calls `GroupSession.accepted()`, which merges and returns the
  standing `GroupInfo` and the history record for the epoch the merge created.
  Those two publications cannot be produced any earlier because both describe an
  epoch that does not exist until the merge, which is why the publish call is two
  phases and not one. A write the relay refused leaves the device at the epoch the
  rest of the group is at, and it publishes nothing describing an epoch nobody
  else reached.

  **Two more functions, added 2026-08-09, and they are what let every other path
  keep that ordering** (register BR-025 and BR-027):

```
weald_mls_clear_pending_commit(handle)         -> epoch
weald_mls_abandon(handle)
```

  `clear_pending_commit` drops a commit the relay refused. Without it a refused
  commit is stuck: it cannot be merged, because the group never saw it, and it
  cannot be replaced, because a second commit is refused while one is pending. So
  the agent-admission and steward paths could not defer their merge at all, since
  both read the added or evicted leaf out of merged state and had no way back if
  the write failed. They now build the commit, publish it, and record the leaf and
  the eviction window only on acceptance (`AgentAdmission.prepare` then `accepted`
  or `refused`; `EpochSteward.prepare` then `accepted` or `refused`), which is the
  same two-phase shape `commitPending` and `accepted()` already had.

  `abandon` deletes a group from this device's store. It exists for the one case
  where refusing to advance is not enough: `join_external` writes the group through
  the storage provider before its commit has been anywhere, so a device whose
  external commit was refused would find that group again on its next launch,
  resume it rather than rejoin, and never republish the only thing that would have
  made it a member. Abandoning returns the device to not being in the group, which
  is what every other member already believes, and the next pass joins again from
  the standing publication. Neither function widens what crosses the boundary: both
  take a handle and return a number or nothing, and no key material moves.

**A third correction, made in step 7: the recovery wrap is sealed below the boundary,
not above it.** `specs/backend/relay/groups.md` describes `recovery.wrap` as a record
the committer emits, and everything about it reads like a product concern: who is
entitled, when it is re-emitted, the 30-day retention of the prior slot, the weekly
health check. All of that is still Swift's. What cannot be is the sealing itself. A wrap
carries the group's exported epoch secret, and sealing it in Swift means handing Swift a
raw epoch secret in the clear, which is precisely what the rule below forbids and what
would put the group's most sensitive value in the layer the third-party audit does not
scope as crypto. So four more functions cross, and none of them widens what crosses in
kind:

```
weald_mls_wrap_tag(handle, recovery_pubkey)     -> tag
weald_mls_seal_wrap(handle, group, recovery_pubkey) -> Wrap
weald_mls_open_wrap(config, seed, wrap)         -> epoch_secret, group_info
weald_mls_recovery_public(config, seed)         -> recovery_pubkey
```

The exporter is still the only function that returns key material to a caller who did
not already hold the key that unseals it: `open_wrap` returns the secret only to a
process that supplied the recovery seed, which is the recovering device and nobody else.
The tag derivation is here for the same reason: it is
`BLAKE3(export(weald wraptag v1) || recovery_pubkey)`, so computing it above the boundary
would mean exporting that secret too.

**An open gap, found in step 8 and not closed there.** The seam list above writes
the self-join entry point as `join_external(group_info, auth)`, and the shipped C
ABI is `weald_mls_join_external(handle, group_info, len, out, commit_out)`: there
is no `auth` parameter, so nothing can be placed in the external commit's
`authenticated_data`. `specs/backend/relay/channels.md` requires a self-joiner to
embed its roster entry reference and the `GroupPolicy` hash it joined under, so
that every receiving client validates the commit against the roster it holds. Until
the parameter exists, that record travels beside the commit rather than inside it,
and is validated against the same two values; the difference is that a commit and
its claim are two objects an adversary could try to pair differently rather than
one signed object. Closing it is a change to an existing function rather than a new
one, so the seam stays at fourteen and step 7's count gate is unaffected, but it is
a change to the crypto boundary and is reviewed as one.

Rules that keep it safe:

- **No Swift-managed memory crosses the boundary.** Buffers in, owned buffers
  out, freed by an explicit call. No callbacks from Rust into Swift.
- **No panics cross the boundary.** Every entry point is wrapped in
  `catch_unwind` and returns a typed error. A panic that unwinds into Swift is
  undefined behaviour, and it would happen first in the least tested path.
- **Handles are opaque and thread-confined.** One group handle is used from one
  actor. Concurrency lives in Swift, not in the FFI.
- **A device's thread lives exactly as long as the device.** The executor's
  thread holds it weakly and re-takes the reference for one job at a time, so a
  released device releases its thread, its SQLite connection and its provider.
  Written down because the first version waited on its condition variable while
  holding the executor strongly, which is a wait that never ends: every device
  ever opened kept a thread for the life of the process, and the `deinit` that
  was supposed to stop it could not run. Corrected in step 8.
- **Secrets are zeroed on free**, and the exporter is the only way to get key
  material out. No function returns a raw epoch secret.

## State storage

OpenMLS's storage provider trait is implemented against SQLite, in the same
per-workspace database as the search index
(`specs/backend/relay/multi-workspace.md`), encrypted at rest with a Keychain
key bound to the device with
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.

Writes are transactional with the local document state. This is the sharp edge:
processing a commit advances the epoch, and if the app crashes between advancing
the MLS state and recording the envelopes decrypted under it, the group is in a
state the rest of the app disagrees with. One transaction per processed message,
covering both, is the entire mitigation and it is not optional.

## Build and distribution

- Static library, built into one XCFramework and vendored at a pinned revision
  with a checksum. Three platform slices, because an XCFramework slice is
  identified by platform and variant: macOS from `aarch64-apple-darwin` and
  `x86_64-apple-darwin`, iOS device from `aarch64-apple-ios`, iOS simulator from
  `aarch64-apple-ios-sim` and `x86_64-apple-ios`. The list is
  `scripts/build-mls-xcframework.sh` and it is not a loop over whatever is
  installed, because a build that quietly produced a single-arch framework would
  ship a client that does not run on half the fleet.
- The two iOS platforms are not a second binding. The iOS Companion redeems an
  invite and enters groups through this same seam and the same Swift wrapper
  (`specs/companion-invite-redemption.md`), the way Android reaches it through a
  JNI shim (`specs/android-mls.md`). Three clients, one crate.
- The simulator platform is in the list for the reason `x86_64` is in the
  Android list: without it the suites that prove this binding cannot run in CI
  at all.
- Built by CI from a pinned OpenMLS version and a pinned Rust toolchain, and the
  resulting checksum is published, because the client's whole claim rests on
  what this component does.
- The Rust build is reproducible for the same reason the relay's is
  (`specs/backend/relay/server.md`), even though the client is proprietary. An
  auditor should be able to verify the crypto layer without the app source.

## Testing

This is where the Phase 3 gate in `specs/backend/relay/migration.md` is actually
enforced, so the list is specific:

- **Property tests over membership churn.** Random interleavings of add, remove,
  update and concurrent application messages, asserting that every remaining
  member converges to the same document state, and that every removed member
  fails to decrypt everything after the removing epoch. Ten thousand cases in
  CI, a longer soak nightly.
- **RFC 9420 test vectors**, run against our binding rather than only against
  OpenMLS's own suite, so a mistake in our marshalling is caught.
- **Crash-injection around the transaction boundary above**, killing the process
  between MLS state write and document write, asserting recovery on next launch.
  The same suite covers the author chain counter in
  `specs/backend/relay/wire.md`, killing the process between reserving a link and
  sending it, and asserting that the restarted client resends the identical
  envelope rather than reissuing the counter over different content. A crash must
  never produce a chain fork, because a chain fork is a security alarm on
  everybody else's screen.
- **Recovery and history reachability.** Property tests asserting that after any
  interleaving of commits, a recovery key can locate and open a wrap for every
  group its owner belongs to using only the tag directory, and that a principal
  self-joining an `open` group obtains the same history an invitee to that group
  obtains. Both are correctness properties of the wrap and history mechanisms in
  `specs/backend/relay/groups.md`, and both fail silently rather than loudly if
  they regress, which is why they are gates rather than manual checks.
- **Cross-group recovery handoff tests**, crashing before and after each
  `recovery.directory.prepare`, target-group commit, wrap upload and
  `recovery.directory.activate`, then recovering from a fresh device. Every
  interleaving must find either the current or fallback valid wrap and must never
  require the relay to reveal a recovery identity.
- **Cross-version tests.** An old client and a new client in one group, since
  forward compatibility is claimed in `specs/backend/relay/wire.md` and claimed
  compatibility that is never tested is a rumour.
- **Fuzzing of `weald_mls_process`** with malformed and hostile messages, since
  it is the one function that consumes bytes from an untrusted network.

## Risks

| Risk | Mitigation |
| --- | --- |
| OpenMLS API churn across versions. | Pinned version, the twelve-function seam absorbs changes, upgrade is a deliberate task with the property suite as the gate. |
| The FFI becomes the place bugs live. | Keep it at twelve functions. Any proposal to widen it is reviewed as a security change. |
| Nobody on the team is a Rust engineer. | The binding is small and mostly marshalling, but the third-party audit in `specs/backend/relay/verification.md` is scoped to include it, and that audit is release-blocking. |
| Swift concurrency plus a non-Sendable handle. | **Corrected in step 7: an actor is not enough.** An actor serialises access and does not pin a thread, and Swift's cooperative pool moves one across suspensions (measured at five threads for one actor). The Rust side compares thread ids and shares a non-atomic `Rc` between a device and its sessions, so a hop is a refusal at best and a data race at worst. Confinement is supplied by a `SerialExecutor` over one dedicated thread, one per device and shared by its groups, in `Sources/MLS/MLSExecutor.swift`. The compiler still enforces that the pointer cannot escape. Evidence and the failing-without-the-fix proof: `build-evidence/step-07/confinement.md`. |
| iOS later needs the same binding in an extension. | The XCFramework already targets it, and the notification service extension case in `specs/backend/relay/notifications.md` is the reason to keep the state store shareable via a Keychain access group. |

## The pinned cryptographic profile

Normative. An implementation that differs anywhere in this section is not a Weald
protocol version 1 implementation, whatever else it does correctly. Everything
here was already pinned in code; until now it was pinned nowhere an implementer
could read, which is the difference between a wire format and a protocol.

### Values

| Parameter | Value | Where it is pinned in the reference implementation |
| --- | --- | --- |
| MLS protocol version | `mls10` (`0x0001`) | Validated on every key package, `backend/weald-mls/src/session.rs` |
| Ciphersuite | `0x0001`, `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` | `CIPHERSUITE`, `backend/weald-mls/src/session.rs` |
| HPKE KEM | `DHKEM(X25519, HKDF-SHA256)` | Implied by the ciphersuite, not separately selectable |
| HPKE KDF | `HKDF-SHA256` | Implied by the ciphersuite |
| HPKE AEAD | `AES-128-GCM` | Implied by the ciphersuite |
| Hash | `SHA-256` | Implied by the ciphersuite |
| Signature scheme | `Ed25519` | Implied by the ciphersuite, and the same scheme `identity.md` uses for device keys |
| Credential type | `basic` (`0x0001`), content is the device identity of `identity.md` | `BasicCredential`, `Device::open` |
| Weald-defined MLS extensions | None. The set is empty in version 1. | No extension is registered, proposed or accepted |
| Required capabilities | The RFC 9420 defaults for the pinned suite and credential type, nothing added | Key packages are built with no added capabilities |

Note the deliberate asymmetry with the rest of the profile in
`../WEALD-PROTOCOL.md`: AES-128-GCM here, AES-256-GCM for media. This is not an
oversight and not a weakening. `0x0001` is RFC 9420's mandatory-to-implement
suite, so it is the one suite every conforming MLS stack has, and a 128 bit AEAD
key derived from an X25519 exchange sits at the security level X25519 already
sets. Media is sealed outside MLS with its own key, where nothing constrains the
choice, so it takes the larger one.

### What this means for an implementer

- Send no ciphersuite list, read none, and offer no fallback. A key package, a
  welcome, a group info or a commit carrying any other suite, protocol version or
  credential type is rejected outright. It is not downgraded to, negotiated
  around, or logged and accepted.
- Rejection is a protocol error, not a crypto error. The relay never sees it,
  because the relay never sees MLS internals; the receiving client raises it.
- Do not treat the absence of a suite negotiation as room to add one privately.
  Two clients that agree bilaterally on a second suite have forked the protocol
  for every third member of the group.
- A group's epoch authenticator is the comparison value, per the correction
  above. Two members that agree on it agree about the epoch.

### How the pin changes

Only through `../contracts/governance.md`, and only as a protocol version bump
negotiated by `wire.md`. Concretely, a change to any row of the table above:

1. Is a breaking change by definition, whatever its intent, because a version 1
   implementation and the changed implementation cannot form a group.
2. Requires a new protocol version number, advertised in the version range in
   `CONNECT` and signed into the challenge, so that a downgrade is detectable
   rather than silent.
3. Requires the conformance vectors in `../contracts/wire/vectors/` to carry the
   new version alongside the old, and requires the cross-version property suite
   named under "Testing" above to cover a group containing both.
4. Requires the deprecation calendar below to have run before the old version is
   refused.

### Deprecation calendar

The calendar exists so that a device left in a drawer for a year is a support
question and not a data-loss event.

| Stage | Duration after the new version ships | Old version behaviour |
| --- | --- | --- |
| Announced | Published at the moment the new version ships | Fully supported. Nothing changes for anyone. |
| Preferred | Months 0 to 6 | New groups are created at the new version. Existing groups stay where they are. Both versions are accepted everywhere. |
| Migrating | Months 6 to 12 | Clients migrate existing groups on their next commit. Old version still accepted. Operators of self-hosted relays are notified at the start of this stage, not the end. |
| Sunset warning | Months 12 to 18 | Old version accepted, and every client that speaks it surfaces a dated warning naming the refusal date. |
| Refused | Month 18 onward | `version/protocol_unsupported`. Never earlier, and never without the four preceding stages having actually elapsed in public. |

Two exceptions, both narrow, both requiring the emergency path in
`../contracts/governance.md`: a cryptographic break in a pinned primitive, and a
defect that lets a non-member read plaintext. Either collapses the calendar to
the shortest interval that gets a fixed client into users' hands, the reasoning
is published at the time rather than afterwards, and the collapse applies only to
the affected parameter.

## What is not in scope

No custom ciphersuite, no modification to OpenMLS, no re-implementation of any
part of RFC 9420. The one place in this design where we can refuse to be novel,
we refuse, and this document exists to keep that refusal enforceable.
