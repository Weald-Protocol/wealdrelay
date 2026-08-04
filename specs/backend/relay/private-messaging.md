# Relay: private messaging

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only, no dev tier,
> no test mode, no staging tier. `local` and `ci` are not an exception because
> they reach no vendor at all. A gate that cannot reach production configuration
> fails; it never degrades to a mock, a stub, a fake or a skip.

Two members of a workspace, one MLS group nobody else is in, ordinary envelopes
inside it. Protocol version 2 adds one frame, `KEYS`, and one event kind,
`0x0022 dm.welcome`. Everything else already exists.

## What already exists

`specs/backend/relay/groups.md` gives the topology and `Sources/Sync/` implements
most of it already:

- `GroupKind.dm` is defined, `GroupAdmission` requires `explicit` admission and
  no parent for it, and `GroupPolicy` pairs it with `closed` history.
- `GroupIdentity.direct(_:_:workspace:)` derives the group id from BLAKE3 over
  length-framed CBOR of `[workspace, "dm", sorted[0], sorted[1]]`, with the
  length framing that `groups.md` records as a correction to an earlier bare
  concatenation.
- `MLSDevice.keyPackage()` produces key packages and `MLSGroup.add(keyPackage:)`
  produces a commit and a welcome, deliberately as two messages.
- `AuthAck` reports `key_packages_remaining`, and the relay counts rows in
  `relay_key_package`.

Three things are missing, and they are the whole of this document: nothing
publishes a key package, nothing fetches somebody else's, and a welcome has
nowhere to travel because the two devices share no group yet. `GroupIdentity.direct`
has zero call sites today for exactly that reason.

## `KEYS`, frame tag 22

The counter in `AuthAck` has no publisher. That is the hole.

```
Keys::Publish  { packages: Vec<bytes> }              -> Keys::Published { remaining: u32 }
Keys::Fetch    { device: [32]byte, count: u8 }        -> Keys::Bundles(Vec<bytes>) | Keys::None
```

Authenticated only, and refused before `AUTH` like every frame except `JOIN`.

`Publish` stores key packages against the authenticated device key, capped at the
100 outstanding per device that `wire.md` already states. Over the cap is
`Quota`/`SeatsExhausted` and the oldest are not evicted, because silently
discarding a key package a client believes is published produces a member who
cannot be added and no error anywhere.

`Fetch` hands out at most `count` packages for the named device and **deletes what
it hands out**. Key packages are one-time by construction and a relay that served
one twice would be handing two DM groups the same joiner leaf key. Refused with
`Denied`/`WriterNotInAccessSet` unless the requesting device and the target device
are both in the access set of the same workspace, so a stranger cannot enumerate
key material. An empty shelf answers `None` rather than an error, because the
correct client behaviour is to wait for the peer to come online and top up, not to
retry.

A frame rather than an envelope kind, and this one is not the usual reason. Key
packages are cleartext by construction: they are the object that bootstraps
encryption, so they cannot arrive encrypted under a key the recipient does not
have yet. The relay must also index them by device key to answer a fetch. Both
facts put them outside the envelope, where nothing is indexed and nothing is
readable.

The relay learns which device asked for which device's key package, which is a
metadata fact it cannot avoid holding if it is to hold key packages at all. That
is written down in `specs/privacy-posture.md` next to the mitigation, which is
that a client fetches on a schedule of its own choosing and prefetches for the
whole roster on first use rather than at the moment a person opens a
conversation, so the fetch does not time-correlate with the intent to talk.

## `0x0022 dm.welcome`

A welcome has to reach a device that shares no group with the sender. The only
group both are certainly in is the workspace root, so it travels there as an
ordinary envelope, encrypted to the root group like everything else.

```
DirectWelcome {
  tag:      [32]byte      // BLAKE3("weald dm welcome v1", key_package_ref)
  welcome:  bytes         // MLS Welcome
}
```

Two fields, and the omission is the design. The dm group id is **not** in the
record: the joiner learns it from inside the Welcome, which only the holder of the
referenced key package can open. Had the record named the group, every member of
the workspace root group could read the root log and learn which pair of people
had opened a conversation and when. They cannot learn it from a blinded tag they
cannot invert and a Welcome they cannot decrypt.

The relay learns nothing at all here: this is an envelope, `ct` is opaque, and
`dm.welcome` is a kind inside it. Other root members learn that somebody
published a welcome-shaped record, which is unavoidable in a shared log and is
the residual leak, stated rather than hidden.

Rejected: a dedicated per-pair delivery group for welcomes. It is the same
problem one level down, because creating that group needs a group. Rejected: a
relay-mediated mailbox addressed by device key, which would hand the relay the
social graph in cleartext and is the one thing this layer exists to prevent.

## The group

A DM group is `GroupKind.dm` and the existing policy rows already say what that
means. Restated here because a reader of this file should not have to derive it:

| Property | Value | Consequence |
| --- | --- | --- |
| Admission | `explicit` | No self-join. There is no standing `GroupInfo` and no `groupinfo.publish`, so a third device cannot external-commit its way in even holding the workspace root key. |
| History | `closed` | No `history.publish`. A second device of the same person added later sees messages from that point on and not before. |
| Parent | none | The workspace root key grants nothing here. An admin cannot read it. |
| Leaves | 2 principals, any number of their devices | Growing past two principals is a channel, and the app offers that instead rather than silently converting. |
| Recovery | none by default | No `recovery.wrap` is published for a dm group. |
| Agents | refused | `PrincipalKind.agent` is not admitted to a dm group. A delegated key that can read a private conversation is a private conversation with a third party in it. Talking to a bot without an audience is a real want and it gets its own group kind, `GroupKind.agentdm`, rather than an exception to this one: a different slug prefix, a different sidebar section, a header naming the owner or organization, and a disclosure sheet before creation. See `specs/agents/networked/phases-live.md`. This row does not soften when that lands, and the negative test asserting it stays in the gate. |

The recovery row is the load-bearing one. It means losing every device on both
sides loses the conversation, permanently, and no workspace administrator, no
recovery quorum and no operator can recover it. That is the promise the feature
makes, so the app states it in the conversation itself the first time a person
opens one, and `specs/direct-messages.md` owns that wording. A per-pair recovery
principal was considered and rejected: a recovery key that can open DMs is an
escrow key, and shipping one while calling the feature private would be a false
claim in the sense `specs/privacy-review` audits for.

Messages inside are ordinary envelopes of kind `chatEntry`, so the durable path,
reconciliation, head attestation, split-view detection, compaction and media all
work with no change. That is the argument for doing DMs as a group rather than as
a message type.

## Limits

| Limit | Value | Why |
| --- | --- | --- |
| Key packages per device | 100 outstanding | Already in `wire.md`. Now enforced on a publisher that exists. |
| `KEYS::Fetch` `count` | 8 | Enough for a peer's devices with headroom. Higher is enumeration. |
| `KEYS` frames per connection per minute | 30 | Prefetching a roster is a burst at startup, not a stream. |
| `dm.welcome` records per device per hour | 32 | The existing `selfJoinsPerPrincipalPerHour` shape, for the same reason: a member cannot spray welcomes. |
| dm groups per workspace per device | 512 | The existing `groupsPerWorkspace` bound applies unchanged; this is the per-device share of it. |

## Gate

- Unit and property at the coverage floor: `KEYS` round trip, one-time delivery
  proved by a property that no package is ever served twice across arbitrary
  interleavings, cap refusals, cross-workspace fetch refused, blinded tag
  derivation vectors, and a property that a `DirectWelcome` record never contains
  the dm group id in any encoding.
- Integration against a real relay on real Postgres and real MLS: device A
  publishes, device B fetches, A creates the dm group, A publishes the welcome to
  the root group, B opens it, both exchange a message, and a third member of the
  same workspace subscribed to the root group cannot decrypt either the welcome
  or any message and cannot name the group.
- Negative: a fetch by a device outside the workspace access set; a second fetch
  of the same package; an agent principal added to a dm group; a self-join
  attempted against a dm group; the same conversation opened concurrently from
  both sides, which must converge on one group id rather than two (the sorted
  derivation is what makes this true, and the test is what proves it).
- Artifact: the root-group log as a third member sees it, showing the welcome
  record as opaque, plus the two group ids derived independently on both sides
  matching byte for byte.
