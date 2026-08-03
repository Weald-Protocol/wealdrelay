# Weald Relay

A blind store-and-forward relay. It holds your team's messages, tickets and
files, and it cannot read any of them.

Groups are MLS (RFC 9420). The relay sees ciphertext, sizes, timing and a salted
hash of who is allowed to fetch what. It does not see message contents, file
contents, channel names, ticket titles, or which human is which. That is not a
policy, it is what the binary in this repository does, and the whole point of
publishing it is that you can check.

```sh
git clone https://github.com/hunterh37/WealdRelay.git
cd WealdRelay
cargo build --release --locked -p wealdrelay
./target/release/wealdrelay --version
```

Minimum deployment is the binary, a Postgres database and a disk. S3 and Redis
are optional. There is no account to create, no license key, and no service of
ours to call: `backend/wealdrelay/deploy/README.md` has four paths, from a
provider one-click to a private network with no public ingress.

To run the tests, bring up the dependencies first. They are real, and the suites
fail rather than skip without them.

```sh
scripts/weald-stack up
cargo test --workspace --locked
scripts/weald-stack down
```

## Verify it

Reproducible builds are the reason this repository is public.

```sh
scripts/relay-reproduce.sh --out ./repro
```

Compare `repro/manifest.json`'s `platform_digests` against the digest in the
release notes. Two independent runners and a clean clone of the tag must all
produce the same bytes, and the release fails if they do not.
`specs/backend/relay/verification.md` is the full argument, including what each
proof does and does not establish.

## Read it

| Where | What |
|---|---|
| `specs/backend/relay/wire.md` | The frame set, header binding, author chain and limits |
| `specs/backend/contracts/wire/wire.cddl` | The same thing, formally, in CDDL |
| `specs/backend/contracts/wire/vectors/` | Conformance vectors: positive, negative, replay, and positive silence |
| `specs/backend/contracts/registries/error-codes.md` | Every stable error code |
| `specs/backend/relay/auth.md` | Device-key proof and the access set |
| `specs/backend/relay/server.md` | Configuration, health surfaces, operational requirements |
| `specs/backend/relay/verification.md` | What you can check, and how |

An implementation is conformant when it passes the vector corpus. If you are
writing one and something in the specification is ambiguous, that is a bug in
the specification and we would like to hear about it.

Two conventions in these documents come from the private monorepo the relay was
built in and mean nothing to an implementer: "step N" dates a decision against a
private build ledger, and citations of `specs/backend/build/*`,
`specs/backend/cloud/*`, `Sources/*` and `Tests/*` name files in the repository
holding the macOS client. They are provenance, not reading you are missing.
Everything needed to implement, run and verify a relay is here.

## Layout

```
backend/wealdrelay/     the relay: server, storage, migrations, deploy bundle
backend/weald-mls/      the MLS binding, a C ABI over OpenMLS
backend/compose/        the local test harness: Postgres, MinIO, Redis
specs/backend/relay/    the protocol and operational specifications
specs/backend/contracts/ formal wire schema, vectors, error registry
scripts/                the harness, the reproducible build, the spec checks
```

`CONTRIBUTING.md` is how to work on it. `SECURITY.md` is what to do instead of
opening an issue.

## License

Apache 2.0. Run it, modify it, fork it, sell a service on it. Each crate carries
its own `LICENSE` and `NOTICE`.

The Weald macOS client is a separate, proprietary product and is not in this
repository. The relay does not require it: the wire protocol is specified here
and any conformant client can speak to it.

## Status

Pre-1.0, and no independent implementation exists yet.

Settled: the wire format is versioned and negotiated (`CONNECT` carries
`min_version` and `max_version`, the relay selects the highest mutual version and
signs it into the challenge so a downgrade cannot be forced). The cryptographic
profile is pinned to a single ciphersuite with a stated deprecation calendar, in
`specs/backend/relay/mls-binding.md`. Changes are governed by
`specs/backend/contracts/governance.md`, including a 30 day public comment period
for anything breaking.

Not settled: nobody has written a second implementation, so "conformant" means
"passes our vectors" rather than "interoperates with someone else's relay". If
you are attempting one, tell us and we will treat your questions as
specification bugs.

## Security

`security@weald.team`. Please give us a chance to ship a fix before publishing.
