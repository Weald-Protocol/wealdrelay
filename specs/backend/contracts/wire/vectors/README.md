# Wire conformance corpus

`manifest.json` is the source. Vectors are declarative rather than a directory
of opaque blobs, so a reviewer can read what a test asserts without a decoder.

## Shape

Every vector has an `id`, an `expect`, and one of:

| Field | Meaning |
| --- | --- |
| `fields` | The generator builds a canonical Envelope from these. `hash: "computed"` means the correct BLAKE3 over `(v, enc, group, epoch, ct)`. `ct: "fill:N"` is N bytes of a fixed pattern. Omitted fields take the corpus defaults. |
| `raw_cbor` | Hex, or a named malformer, when the point of the vector is an encoding the generator cannot produce because it is correct by construction. Named malformers live in the generator. |
| `session_device` | The device that completed `AUTH` for a relay-side `SEND` vector. It is distinct from the encrypted payload author, which the relay cannot read. |
| `replays` | Resend another vector's exact bytes, usually under a different `relay_config`. This is how the same envelope proves two opposite outcomes on two configurations. |
| `chain` / `attest` / `clock` | Client-side vectors. These never touch the relay. |
| `repeat` | Send the vector N times in one session and assert `expect` on the **last** one. Only meaningful for budgets, where the interesting behaviour is at a boundary rather than on a single frame: the ingress vectors use it to sit exactly at a limit and exactly one frame past it. A vector without `repeat` is sent once. |
| `frame` | The frame the vector exercises, when it is not `SEND`. Defaults to `SEND`. Present so that `BLOB` can be asserted as *not* charged against the `SEND` ingress budget, which is the property that separates a correct guard from one counter over all inbound bytes. |

`relay_config` pins the environment a vector runs under. A vector with a
`relay_config` runs against a relay started with exactly that configuration, and
a hosted-profile relay must refuse to start at all if a test tries to set
`WEALD_RELAY_MIN_ENC=none`.

## `expect` values

Relay-side values are the stable codes from `../../registries/error-codes.md`,
or `accept`. Client-side values are `client_accept`,
`client_split_view_warning`, `client_unverified_gap` and `client_clock_warning`.

## Why the positive-silence vectors exist

Four vectors assert that nothing happens: a shut laptop, a proxied agent, an
offline agent issuer, and a four-minute clock skew. They are load-bearing. A
split-view detector that fires on ordinary Tuesday traffic gets trained into
noise, at which point the real detection is worth nothing. Any change that
tightens the detector must keep these four silent, and `spec-check.sh` will not
let the corpus lose them.

## Coverage rule

`scripts/spec-check.sh` fails if any stable code in the frame-error registry has
no vector expecting it. Adding a new `denied/*` or `reject/*` code without a
negative vector is therefore a build failure, not a review comment.

## Determinism

The corpus is also the deterministic-encoding proof. Four vectors
(`indefinite-length-bstr`, `unsorted-map-keys`, `nonshortest-integer`,
`float-field`) decode to semantically identical envelopes and must all be
refused, because `hash` is a content address and a content address that depends
on the encoder is not one.
