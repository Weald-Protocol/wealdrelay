# The verification runbook, and what runs it for you

`specs/backend/relay/verification.md` publishes a ten step runbook written as a
runnable procedure rather than as prose, for a reviewer with a terminal and under
an hour.

A runbook nobody runs rots. Most steps below therefore have an automated
counterpart that runs in ci, so a change that would make a step fail is caught by
the build rather than by the next reviewer who tries it.

**A counterpart is not a substitute.** The reviewer's version of step 5 is
convincing precisely because they ran it themselves against their own relay. What
the counterpart guarantees is narrower and still worth having: that the procedure
still works, that the thing it checks is still true, and that nobody has to
discover otherwise while somebody else is watching.

**What you can run from this repository, and what you cannot.** Every `cargo`
command below runs against this source, and so does `scripts/weald-stack
prove-blind`. Four of the ten steps are properties of a client rather than of the
relay, and the reference client is a separate, proprietary product that is not in
this repository. Those rows say so rather than naming a suite you cannot run.
That asymmetry is the reason `verification.md` exists as its own document: what a
reviewer can check for themselves is deliberately the part that needs no test
suite of ours.

## The table

| # | Runbook step | Automated counterpart | Runs from here |
| --- | --- | --- | --- |
| 1 | Clone the relay source at the tag matching your running digest, run the reproducible build | `scripts/relay-reproduce.sh` builds from a clean context. The release workflow runs it on two independent runners, and a third time from a fresh clone of the tag | Yes |
| 2 | Compare the resulting digest against the published one | `scripts/repro-compare.py --selftest` proves the comparison refuses every way two builds can disagree, so a comparison that always passes cannot hide | Yes |
| 3 | Confirm the release artifact's digest matches what your client displays | Client side. The relay's half is that it reports the digest at all; comparing it against the signed release feed and surfacing a mismatch is required of a conformant client | No, client |
| 4 | Capture relay traffic, confirm envelopes are opaque and only header fields are read | `cargo test --test envelope` asserts the relay reads the header and never the ciphertext | Yes |
| 5 | Dump the relay's Postgres, confirm no plaintext content is present | `scripts/weald-stack prove-blind <sentinel>` dumps every table and greps the data directory for the phrase you sent | Yes |
| 6 | Compare safety numbers with a colleague on a second device | Client side. The relay holds no input to a safety number beyond the ratchet tree the group publishes for itself | No, client |
| 7 | Verify the transparency log chain from genesis, including the fingerprint your relay printed at first run | `cargo test --test invite_genesis` writes and reads a real genesis entry against a real Postgres. Verifying the chain from the other end is client side | Partly |
| 8 | On two clients compare head attestations, block one at the relay, confirm both warn within two rounds | The relay side is the suppressed-attestation scenario against a real relay. Raising the warning is client side | Partly |
| 9 | Confirm the relay reports access set enforcement, and that revoking a test device drops its connection within seconds | `cargo test --test access_socket`, which measures the disconnect timing and covers the device that joined minutes earlier on a still-live invite | Yes |
| 10 | Dump the recovery wrap table, confirm the index rotates every epoch and no value recurs across two groups | `cargo test --test recovery_store` asserts rotation and cross-group distinctness | Yes |

The integration tiers need the harness. `scripts/weald-stack up` brings up
Postgres, MinIO and Redis on loopback, and the suites fail rather than skip
without them.

## What this table is for

The failure mode a table like this actually has is a row quietly emptying out. A
step whose counterpart disappears should be visible as a gap, rather than
surviving as an entry that still reads fine and no longer describes anything.

The mapping is deliberately about existence and shape rather than about outcome.
Whether each counterpart passes is decided by running it, which `cargo test
--workspace` and the release workflow already do.
