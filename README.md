<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/weald-mark-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset=".github/assets/weald-mark-light.svg">
  <img alt="Weald" src=".github/assets/weald-mark-light.svg" width="96" height="96">
</picture>

# Weald Relay

**A blind store-and-forward relay for team collaboration.**<br>
It holds your team's messages, tickets and files, and it cannot read any of them.

[![CI](https://github.com/Weald-Protocol/wealdrelay/actions/workflows/ci.yml/badge.svg)](https://github.com/Weald-Protocol/wealdrelay/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache_2.0-2563EB?style=flat-square&labelColor=0B0B0C)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.97.1-B7410E?style=flat-square&labelColor=0B0B0C)](rust-toolchain.toml)
[![Wire protocol](https://img.shields.io/badge/wire_protocol-v1-6B7280?style=flat-square&labelColor=0B0B0C)](specs/backend/relay/wire.md)
[![Release](https://img.shields.io/badge/release-v0.1.5-2563EB?style=flat-square&labelColor=0B0B0C)](https://github.com/Weald-Protocol/wealdrelay/releases/latest)
[![Image](https://img.shields.io/badge/image-ghcr.io_signed_digest-34D399?style=flat-square&labelColor=0B0B0C)](#install)
[![Status](https://img.shields.io/badge/status-production_ready-16A34A?style=flat-square&labelColor=0B0B0C)](#status)

[![MLS](https://img.shields.io/badge/groups-MLS_RFC_9420-34D399?style=flat-square&labelColor=0B0B0C)](specs/backend/relay/mls-binding.md)
[![Ciphersuite](https://img.shields.io/badge/ciphersuite-0x0001-34D399?style=flat-square&labelColor=0B0B0C)](specs/backend/relay/mls-binding.md)
[![KEM](https://img.shields.io/badge/HPKE_KEM-X25519_HKDF_SHA256-34D399?style=flat-square&labelColor=0B0B0C)](specs/backend/relay/mls-binding.md)
[![AEAD](https://img.shields.io/badge/AEAD-AES--128--GCM-34D399?style=flat-square&labelColor=0B0B0C)](specs/backend/relay/mls-binding.md)
[![Signatures](https://img.shields.io/badge/signatures-Ed25519-34D399?style=flat-square&labelColor=0B0B0C)](specs/backend/relay/auth.md)
[![Hash](https://img.shields.io/badge/hash-SHA--256-34D399?style=flat-square&labelColor=0B0B0C)](specs/backend/relay/mls-binding.md)
[![Transport](https://img.shields.io/badge/transport-TLS_1.3-34D399?style=flat-square&labelColor=0B0B0C)](specs/backend/relay/server.md)

[Install](#install) · [Quick start](#quick-start) · [Verify a build](#verify-a-build) · [Specification](#specification) · [Deploy](#deploy) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

</div>

---

## What this is

Groups are [MLS (RFC 9420)](https://www.rfc-editor.org/rfc/rfc9420.html). The relay
sees ciphertext, sizes, timing and a salted hash of who is allowed to fetch what. It
does not see message contents, file contents, channel names, ticket titles, or which
human is which.

That is not a policy. It is what the binary in this repository does, and the whole
point of publishing it is that you can check.

| | |
|---|---|
| **Blind by construction** | The server holds no key that decrypts anything. Access control runs on salted principal hashes, so the relay enforces who may fetch a blob without learning who they are. |
| **No vendor coupling** | The relay depends on no commercial service of ours. `grep -riE "clerk\|stripe" backend/wealdrelay/src` returns nothing, and a test asserts it stays that way. |
| **Reproducible** | Two independent runners and a clean clone of the tag must produce byte-identical output, or the release fails. |
| **Small surface** | One static binary, one Postgres database, one disk. S3 and Redis are optional. |
| **Specified, not described** | A formal CDDL grammar, a conformance vector corpus and a stable error registry, all in this repository. |

## Install

Released, signed and reproducible. `wealdrelay-v0.1.5` is the current release, and
it is the first published one.

Pin the digest, never the tag:

```
ghcr.io/weald-protocol/wealdrelay@sha256:1bdfb644d684ad8712a011bdb20df3943ca9edd03327dead54c063a15c0a5738
```

Two independent runners, of two different architectures, and a clean clone of the
tag each built that digest and agreed. The signature is keyless, so anyone can
check it without a key of ours:

```sh
cosign verify \
  --certificate-identity-regexp "^https://github.com/Weald-Protocol/wealdrelay/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/weald-protocol/wealdrelay@sha256:1bdfb644d684ad8712a011bdb20df3943ca9edd03327dead54c063a15c0a5738
```

For a whole stack rather than one image, the compose bundle fetches, verifies its
own SHA-256 and generates its passwords. It stops there: starting the service is
the operator's decision, not a piped script's.

```sh
curl -fsSL https://get.weald.team/relay | sh
```

Static binaries for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` and
`aarch64-apple-darwin` are attached to the release, each beside its `.sha256`.

## Quick start

Building from source stays first-class, and is the same code the release digest
came from.

```sh
git clone https://github.com/Weald-Protocol/wealdrelay.git
cd wealdrelay
cargo build --release --locked -p wealdrelay
./target/release/wealdrelay --version
```

There is no account to create, no license key, and no service of ours to call.

To run the tests, bring the dependencies up first. They are real, and the suites fail
rather than skip without them.

```sh
scripts/weald-stack up
cargo test --workspace --locked
scripts/weald-stack down
```

## Deploy

Minimum deployment is the binary, a Postgres database and a disk.
[`backend/wealdrelay/deploy/README.md`](backend/wealdrelay/deploy/README.md) covers four
paths, from a provider one-click to a private network with no public ingress at all.

| Path | Where it lives |
|---|---|
| Docker Compose, with Postgres, MinIO, Redis and Caddy | `backend/wealdrelay/deploy/compose/` |
| systemd, hardened unit | `backend/wealdrelay/deploy/systemd/` |
| Render, Fly, Railway, DigitalOcean, cloud-init | `backend/wealdrelay/deploy/templates/` |
| Tailscale, no public ingress | `backend/wealdrelay/deploy/README.md` |

`WEALD_RELAY_PROFILE` selects posture, not a build. Both profiles compile into every
binary and the digest is the same either way; `self_host` is the default everywhere,
including in our own hosted deployment.

> [!NOTE]
> The published image, its signed digest and the compose bundle are in
> [Install](#install). Building from source remains supported and produces the same
> digest.

## Verify a build

Reproducible builds are the reason this repository is public.

```sh
scripts/relay-reproduce.sh --out ./repro
```

Compare `repro/manifest.json`'s `platform_digests` against the digest published with the
release. The builder is pinned to `linux/arm64`, so the toolchain is a property of the
Dockerfile rather than of your machine; on an x86_64 host that means QEMU and a few
hours, and it is what makes two machines agree at all. [`specs/backend/relay/verification.md`](specs/backend/relay/verification.md) is
the full argument, including what each proof does and does not establish.

## Specification

An implementation is conformant when it passes the vector corpus. If you are writing one
and something in the specification is ambiguous, that is a bug in the specification and
we would like to hear about it.

| Document | What it covers |
|---|---|
| [`specs/backend/WEALD-PROTOCOL.md`](specs/backend/WEALD-PROTOCOL.md) | The normative protocol document |
| [`specs/backend/relay/wire.md`](specs/backend/relay/wire.md) | Frame set, header binding, author chain, limits, version negotiation |
| [`specs/backend/contracts/wire/wire.cddl`](specs/backend/contracts/wire/wire.cddl) | The same thing, formally, in CDDL |
| [`specs/backend/contracts/wire/vectors/`](specs/backend/contracts/wire/vectors/) | Conformance vectors: positive, negative, replay, positive silence |
| [`specs/backend/contracts/registries/error-codes.md`](specs/backend/contracts/registries/error-codes.md) | Every stable error code |
| [`specs/backend/relay/auth.md`](specs/backend/relay/auth.md) | Device-key proof and the access set |
| [`specs/backend/relay/mls-binding.md`](specs/backend/relay/mls-binding.md) | The pinned cryptographic profile and its deprecation calendar |
| [`specs/backend/relay/server.md`](specs/backend/relay/server.md) | Configuration, health surfaces, operational requirements |
| [`specs/backend/contracts/governance.md`](specs/backend/contracts/governance.md) | How the protocol changes, and how much warning that carries |
| [`specs/backend/contracts/threat-model/`](specs/backend/contracts/threat-model/) | What the relay boundary does and does not defend |

### Cryptographic profile

Pinned to one ciphersuite, deliberately. Full table and change process in
[`mls-binding.md`](specs/backend/relay/mls-binding.md).

```
ciphersuite   0x0001  MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
KEM           DHKEM(X25519, HKDF-SHA256)
AEAD          AES-128-GCM
hash          SHA-256
signatures    Ed25519
MLS version   mls10, basic credentials, empty Weald extension set
```

## Layout

```
backend/wealdrelay/        the relay: server, storage, migrations, deploy bundle
backend/weald-mls/         the MLS binding, a C ABI over OpenMLS
backend/compose/           the local test harness: Postgres, MinIO, Redis
specs/backend/relay/       protocol and operational specifications
specs/backend/contracts/   formal wire schema, vectors, error registry, governance
scripts/                   the harness, the reproducible build, the spec checks
```

One convention comes from the monorepo the relay was built in: a few test suites write
timing and evidence files under a `build-evidence/` directory that lives there rather
than here. Those are outputs, not reading you are missing. Everything needed to
implement, run and verify a relay is in this repository.

## Status

Production ready and running real traffic. Pre-1.0 in version number only: the wire
format is versioned and negotiated, the cryptographic profile is pinned, and breaking
changes carry a 30 day public comment period under
[`governance.md`](specs/backend/contracts/governance.md).

Settled: a downgrade cannot be forced (`CONNECT` carries `min_version` and
`max_version`, the relay selects the highest mutual version and signs it into the
challenge). The cryptographic profile is pinned to a single ciphersuite with a stated
deprecation calendar. `wealdrelay-v0.1.5` is published with a signed, reproducible
digest, so a binary can be checked against something rather than trusted.

Not settled: nobody has written a second implementation, so "conformant" means "passes
our vectors" rather than "interoperates with someone else's relay". If you are
attempting an implementation, tell us, and we will treat your questions as specification
bugs.

## The client

The Weald macOS client is a separate, proprietary product and is not in this repository.
The relay does not require it: the wire protocol is specified here and any conformant
client can speak to it.

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md) is how to work on it. Specification ambiguities,
conformance vector gaps and reproducibility failures are the most useful things you can
report.

## Security

Report privately to **security@weald.team** rather than opening an issue. Please give us
a chance to ship a fix before publishing. Details in [`SECURITY.md`](SECURITY.md).

## License

[Apache 2.0](LICENSE). Run it, modify it, fork it, sell a service on it. Each crate
carries its own `LICENSE` and `NOTICE`.
