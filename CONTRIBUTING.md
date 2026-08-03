# Contributing

The most valuable contribution to this repository is not code. It is somebody
reading `specs/backend/relay/` and telling us where the argument does not hold,
or writing a second implementation and finding out where the specification is
ambiguous. An ambiguity in the specification is a bug in the specification, and
we would rather hear it as one.

Do not send a security issue as a pull request. `SECURITY.md`.

## Getting it running

```sh
git clone https://github.com/hunterh37/WealdRelay.git
cd WealdRelay
scripts/weald-stack up          # Postgres, MinIO and Redis, on loopback
cargo test --workspace --locked
scripts/weald-stack down
```

The toolchain is pinned in `rust-toolchain.toml` and rustup will fetch it. The
only build dependency beyond Rust is a C compiler, because `blake3` and `ring`
compile C. Docker, OrbStack, Colima or a plain Linux daemon all serve for the
harness.

**The integration tiers do not skip.** A suite that cannot reach Postgres or
MinIO fails and tells you to run `scripts/weald-stack up`. This is deliberate: a
skipped integration proof reports success for something nobody checked, which is
the failure mode the whole verification story exists to prevent. If Docker is
unavailable on your machine, say so in the pull request and we will run that tier
for you rather than have you weaken it.

Before opening a pull request, the same three commands CI runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
./scripts/spec-check.sh
```

`spec-check.sh` skips the CDDL compile unless you have the tool
(`cargo install cddl`). Everything else it checks is unconditional.

## What a change needs with it

**A behaviour change needs a test at the boundary the behaviour crosses.** Parsing
and state decisions get a unit test and a property test. A protocol rejection gets
an adversarial socket test that asserts the exact error frame. Anything touching
the database, storage or process lifecycle gets a real integration test against
the harness, not a mock. `specs/backend/relay/test-harness.md` is the long form,
including the shape a new integration scenario should take.

There are no mocks of anything a customer runs. Where a fake exists, a shared
contract suite runs against both it and the real thing, which is why
`tests/storage_contract.rs` is written once over a type parameter and executed
against both the filesystem and MinIO.

**A wire change needs the artifact, not just the prose.** Adding or changing a
frame, field, event kind or error code means updating `wire/wire.cddl` and adding
vectors under `specs/backend/contracts/wire/vectors/`, in the same commit. Where a
contract artifact and the prose disagree the artifact is correct
(`specs/backend/contracts/decisions/ADR-0008-artifacts-outrank-prose.md`), and
`spec-check.sh` fails an error code that has no negative vector.

Anything that changes what a conformant implementation must do is governed:
`specs/backend/contracts/governance.md` describes the three change classes and the
30 day comment period for a breaking one. Please open an issue before writing the
code for one of those; it is a conversation about compatibility rather than about
your diff.

## House style

The unusual part, and the part reviewers will ask about: **comments explain why,
not what.** Most modules in this repository carry a header explaining what the
design rejected and why the obvious alternative was worse. That is the standard
being maintained. A comment restating the line below it will be asked about; a
comment recording a decision, a measurement or a failure that shaped the code
will not.

Also: no em dashes anywhere (a period, comma, colon or parentheses instead), and
no emoji. `spec-check.sh` enforces the first over `specs/`.

Prefer a new file to growing one past about 500 lines.

## Some notes on reading the specifications

One convention comes from where these documents were written. A few test suites
write timing and evidence files under a `build-evidence/` directory, which is a
path in the private monorepo holding the reference client rather than anything in
this tree. Those are outputs, not reading you are missing: everything needed to
implement, run and verify a relay is in this repository, and
`specs/backend/relay/verification.md` restates in checkable terms any claim that
rests on evidence you cannot see.

## Licence

Apache 2.0. By opening a pull request you agree your contribution is licensed the
same way. There is no CLA.
