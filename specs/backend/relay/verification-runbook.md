# The verification runbook, and what runs it for you

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only: the Clerk
> production instance, Stripe live mode, the production Render environment and
> Postgres, the production R2 bucket, the published relay digest. No dev tier,
> no test mode, no staging tier, and no agent creates one. `local` and `ci` are
> not an exception because they reach no vendor at all. A gate that cannot reach
> production configuration fails; it never degrades to a mock, a stub, a fake, a
> skip or a newly created dev or staging resource.

`specs/backend/relay/verification.md` publishes a ten-step runbook at
`/docs/verify`, "written as a runnable procedure, not prose", for a reviewer with
a terminal and under an hour.

A runbook nobody runs rots. Every step below therefore has an automated
counterpart that runs in ci, so a change that would make a step fail is caught by
the build rather than by the next reviewer who tries it. That is step 12's
integration gate, and this is the table it requires: ten rows, no blank ones.

**A counterpart is not a substitute.** The reviewer's version of step 5 is
convincing precisely because they ran it themselves against their own relay. What
the counterpart guarantees is narrower and still worth having: that the procedure
still works, that the thing it checks is still true, and that nobody has to
discover otherwise while a customer watches.

## The table

| # | Runbook step | Automated counterpart | Where it runs |
| --- | --- | --- | --- |
| 1 | Clone the relay source at the tag matching your running digest, run the reproducible build | `gate_13_reproducible` builds twice from a clean context and compares | `scripts/backend-gate.sh 13`, ci |
| 2 | Compare the resulting digest against the published one | `scripts/repro-compare.py --selftest` proves the comparison refuses every way two builds can disagree | `scripts/backend-gate.sh 13`, ci |
| 3 | Confirm the release artifact's digest matches what your client displays | `ReleaseComparisonTests` over all six verdicts, and `gate_12_digest_mismatch` deploys a deliberately wrong digest in `local` and reads the client's banner | `scripts/backend-gate.sh 12`, ci |
| 4 | Capture relay traffic, confirm envelopes are opaque and only header fields are read | `cargo test --test envelope` asserts the relay reads the header and never the ciphertext; `prove-blind.py` phase 2 confirms the traffic reached the relay at all | `scripts/backend-gate.sh 12`, ci |
| 5 | Dump the relay's Postgres, confirm no plaintext content is present | `scripts/weald-stack prove-blind` dumps every table and greps the data directory for sentinels | `scripts/backend-gate.sh 8`, ci |
| 6 | Compare safety numbers with a colleague on a second device | `SafetyNumberTests` proves a changed ratchet tree changes the number and that a stale epoch is not agreement | `scripts/backend-gate.sh 12`, ci |
| 7 | Verify the transparency log chain from genesis, including the fingerprint your relay printed at first run | `TransparencyLogTests` verifies the chain from the client side; `cargo test --test invite_genesis` writes and reads a real genesis entry against real Postgres | `scripts/backend-gate.sh 12`, ci |
| 8 | On two clients compare head attestations, block one at the relay, confirm both warn within two rounds | `SplitViewSuppressionTests` and the `suppressed-attestation` scenario against a real relay | `scripts/backend-gate.sh 6`, ci |
| 9 | Confirm the relay reports access set enforcement, and that revoking a test device drops its connection within seconds | `cargo test --test access_socket`, timed in `build-evidence/step-06/disconnect-timing.txt`, including the still-live-invite case | `scripts/backend-gate.sh 6`, ci |
| 10 | Dump the recovery wrap table, confirm the index rotates every epoch and no value recurs across two groups | `cargo test --test recovery_store` asserts rotation and cross-group distinctness | `scripts/backend-gate.sh 12`, ci |

## What the mapping is checked by

`scripts/verify-runbook-map.py` reads this file, refuses a row with a blank cell,
refuses a counterpart naming a test file or suite that does not exist, and emits
`build-evidence/step-12/runbook-map.json`. The gate runs it, so a row that
degrades into a promise fails the step rather than sitting here looking green.

The check is deliberately about existence and shape rather than about outcome.
Whether each counterpart passes is decided by running it, which the gates in the
right-hand column already do; what this stops is the failure mode a table like
this actually has, which is a row quietly emptying out.
