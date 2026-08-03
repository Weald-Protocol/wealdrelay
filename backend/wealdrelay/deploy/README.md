# Running a Weald relay

Four ways. Pick the row that describes what you already have.
`specs/backend/relay/deployment.md`.

| You have | Take | Time |
| --- | --- | --- |
| A provider account and no patience | [Path 1, one-click template](#path-1-one-click-template) | 5 minutes |
| A VPS | [Path 2, compose](#path-2-compose-on-a-vps) | 10 minutes |
| Config management and a DBA | [Path 3, bare binary](#path-3-bare-binary-and-systemd) | 2 hours |
| A policy against public ingress | [Path 4, private network](#path-4-private-network-no-public-ingress) | 2 hours, mostly networking |

Every path produces the same database and the same bucket, so moving between
them is a `pg_dump` plus a copy of the bucket, restored elsewhere, then repoint
the client. That two-command form works today and is the one documented below.
A single `wealdrelay backup` command that wraps both is specified in
`specs/backend/relay/server.md` and is not implemented. Until it ships, the two
commands are the supported procedure, and no runbook should be written around
the single command. The workspace's identity is anchored to its genesis entry
rather than to a hostname, so changing hostname is a settings change and not a
new workspace.

The smallest useful configuration of this entire system is one person running a
relay on their own laptop for sub-second sync between their own devices, with no
server anywhere. That is `brew install weald-protocol/tap/wealdrelay`, and it is a
real deployment rather than a curiosity.

## Path 0: build it yourself

Every path below starts from an artifact we published. This one does not, and it
is the one that makes the others checkable: a relay you built from source is a
relay whose behaviour you can read.

**Status, and read this before you follow any command here.** Source is
published and building from it works today. Until the first signed release is
tagged there is no release page, so there are no binaries to download, no
`install.sh` to fetch, no compose bundle, no Homebrew tap, and the image
reference in `compose/docker-compose.yml` cannot be pulled. Paths 1, 2 and 4
therefore need an image you built yourself with `scripts/relay-reproduce.sh`,
set through `WEALD_RELAY_IMAGE`; path 3 needs the binary from the clone rather
than from a release. The configuration, operations and networking halves of this
guide are accurate and stable; the download-a-published-artifact half describes
artifacts that are not out yet. This notice comes down with the first published,
signed, digest-pinned release, and not before.

There is no `get.weald.team`, no install one-liner piped from a domain, and no
`latest` tag. Nothing in this directory asks you to trust one.

```sh
git clone https://github.com/Weald-Protocol/wealdrelay.git
cd wealdrelay
cargo build --release --locked -p wealdrelay
./target/release/wealdrelay --version
```

The toolchain is pinned in `rust-toolchain.toml` and `--locked` makes
`Cargo.lock` the contract, so a build that resolves a different dependency graph
fails rather than drifting. The only build dependency beyond the Rust toolchain
is a C compiler, because `blake3` and `ring` compile C.

To reproduce the published container image rather than a local binary, use
`scripts/relay-reproduce.sh --out ./repro`, then compare
`repro/manifest.json`'s `platform_digests` against the digest in the release
notes. That is proof 1 of `specs/backend/relay/verification.md`, and it is the
reason the relay is open source at all: a claim that the operator cannot read
your envelopes is worth exactly as much as your ability to check it.

## License

The relay (`backend/wealdrelay`) and its MLS binding (`backend/weald-mls`) are
Apache 2.0. You may run, modify, fork and redistribute them, commercially or
otherwise. You do not need an account with us, a license key, or any service we
operate: the relay has no dependency on any commercial-layer vendor, which is
enforced rather than promised (`specs/backend/relay/server.md`).

The macOS client is proprietary, is licensed separately, and is not in this
repository. The relay does not require it: the wire protocol is specified in
`specs/backend/relay/wire.md` and any conformant client can speak to it.

## Path 1: one-click template

`templates/`. Each template wires the provider's own managed Postgres and object
storage rather than running our containers for them, because a customer on
Railway wants Railway's Postgres backed up by Railway.

| Provider | File | Storage |
| --- | --- | --- |
| Render | `templates/render.yaml` | Persistent disk |
| Fly.io | `templates/fly.toml` | Tigris, S3-compatible |
| Railway | `templates/railway.json` | Volume |
| DigitalOcean App Platform | `templates/digitalocean-app.yaml` | Spaces |
| Any VPS | `templates/cloud-init.yaml` | Volume, via the compose bundle |

Each one provisions Postgres, wires the three required environment variables,
issues TLS on a provider subdomain, and runs first-boot migrations.
`WEALD_RELAY_ACCESS_SET=enforce` is set explicitly in every template and is
never weakened by one.

**The failure point on this path is human.** First boot prints a one-time
enrollment link and a one-time code into the provider's log view, which is the
only place a template-deploying user will look, and it is easy to close that
view before copying them.

Two mitigations and one hard edge. The link lives for 24 hours, and it is
reprinted on every start while the workspace still has no trust root, so a
restart gets it back. The code is never reprinted. The relay stores only its
Argon2id hash and so has nothing left to print, there is no reissue command, and
there will not be one: reissuing a bootstrap invite is forbidden by the threat
model, because a code that can be minted twice is a code an operator can mint
for themselves. An operator who loses the code before any device enrols has one
route forward, which is to drop the database and start again from empty. At that
point in the sequence the workspace holds nothing, which is what makes this
survivable.

## Path 2: compose on a VPS

`compose/`, and its own [README](compose/README.md). Postgres, MinIO, Redis and
Caddy in one file, one hostname to edit.

Two routes, and the compose README keeps them apart because mixing them is how
an operator ends up running an example password. Either download `install.sh`
from the release page for the tag you want and run it, which fetches the compose
bundle, checksums it and generates the two passwords into `.env`; or clone the
repository, work in `compose/` directly, and copy `.env.example` to `.env`
yourself, filling in the hostname and generating both passwords with
`openssl rand -base64 30`. Both passwords ship empty and compose refuses to
start on an empty one, so there is no path through the document that leaves a
placeholder in production.

The failures after that are both DNS: a hostname pointed at the wrong address,
or a certificate that cannot be issued because port 80 is closed. The bundle
names which one it is in words.

## Path 3: bare binary and systemd

`systemd/`. For a team with existing Postgres and existing configuration
management. A unit file, an environment file, a documented user and directory
layout.

The binary comes from the release, with its checksum published beside it. Verify
before you install it, because this is the path with no container digest doing
that for you:

```sh
tag=wealdrelay-v0.1.5
target=x86_64-unknown-linux-musl        # or aarch64-unknown-linux-musl
base=https://github.com/Weald-Protocol/wealdrelay/releases/download/$tag
curl -fLO "$base/wealdrelay-$target.tar.gz"
curl -fLO "$base/wealdrelay-$target.tar.gz.sha256"
sha256sum --check "wealdrelay-$target.tar.gz.sha256"
tar -xzf "wealdrelay-$target.tar.gz"
sudo install -m 0755 "wealdrelay-$target/wealdrelay" /usr/local/bin/wealdrelay
wealdrelay --version
```

Or build it yourself from Path 0, which is the same binary and one fewer thing to
trust.

TLS is yours to terminate on this path.

**Configure backups before you start the service.** The cron line is in
`systemd/wealdrelay.env.example` above the optional settings rather than below
them, deliberately: this is the path where backups get skipped.

## Path 4: private network, no public ingress

The relay binds to a Tailscale or WireGuard interface and is unreachable from
the internet. Clients reach it over the same network. No ACME, no public DNS
record, no exposure at all. `private-network/` holds a complete Tailscale
stack:

```sh
cd private-network
cp .env.example .env && $EDITOR .env
docker compose -f docker-compose.tailscale.yml up -d
```

That file is self-contained rather than an overlay on the compose bundle. The
relay here needs `network_mode: service:tailscale` and the bundle gives the same
service `networks: [weald]`; compose overlays merge keys and cannot remove them,
so an overlay produced a relay carrying both, which compose rejects before
starting anything. The comment at the top of the file says the same thing, so
nobody reintroduces the overlay.

Four consequences, and the docs state them together because taking one without
the others produces a broken install:

- **Certificates.** Tailscale's own TLS, or a private CA the client is told to
  trust explicitly. The client's digest and hostname pinning still applies.
- **Invites.** The landing page is reachable only inside the network, so a new
  joiner must be on the network first. Onboarding ordering becomes network
  first, workspace second, and the invite email says so.
- **`WEALD_RELAY_ACCESS_SET=off` is defensible here and only here**, because the
  network is doing the perimeter work the access set does elsewhere. It stays
  `enforce` by default from our side, and an operator who turns it off sees that
  reflected in every client's encryption panel.
- **Our support cannot reach it.** True of every self-host path, most visible
  here.

## The image reference, and what to update at release time

Every published image is `ghcr.io/weald-protocol/wealdrelay`, tagged
`wealdrelay-vX.Y.Z` and pinned by digest in the release notes. The release
workflow publishes no moving tag, deliberately: `latest` would let a customer's
relay change under them without a deploy they asked for, which is the thing the
whole verification story exists to prevent. Anything naming `latest` as a Weald
relay image tag is a bug. The supporting images in the compose files are a
different thing: those carry a tag and a digest, and the digest is what
resolves.

Six lines carry a version, each marked `RELEASE PIN` in its own file, and they
are updated together:

| File | Line |
| --- | --- |
| `compose/docker-compose.yml` | the `image:` default on the `relay` service |
| `private-network/docker-compose.tailscale.yml` | the `image:` default on the `relay` service |
| `templates/render.yaml` | `url:` under `image:` |
| `templates/fly.toml` | `image =` under `[build]` |
| `templates/digitalocean-app.yaml` | `tag:` under `image:` |
| `templates/cloud-init.yaml` | `RELAY_VERSION=` in the first-boot script |

Path 3 above also names a tag in its download commands, and the Homebrew formula
is rewritten wholesale from the release manifest by `scripts/release-homebrew.sh`
rather than edited by hand.

Operators do not have to touch any of these. Set `WEALD_RELAY_IMAGE` in `.env`
to the digest you verified from the release notes, on either compose path, and
that wins over the default.

## What your relay operator can do

Keep the service running, and stop keeping it running.

That is the complete list. There is no admin password, no operator account and
no web admin panel, because there is nothing an operator could usefully
administer. Workspace administration happens in the client, signed by a device
holding `admit`. A relay operator who is not a workspace member has exactly two
powers.
