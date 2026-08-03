# Running a Weald relay

Four ways. Pick the row that describes what you already have.
`specs/backend/relay/deployment.md`.

| You have | Take | Time |
| --- | --- | --- |
| A provider account and no patience | [Path 1, one-click template](#path-1-one-click-template) | 5 minutes |
| A VPS | [Path 2, compose](#path-2-compose-on-a-vps) | 10 minutes |
| Config management and a DBA | [Path 3, bare binary](#path-3-bare-binary-and-systemd) | An afternoon |
| A policy against public ingress | [Path 4, private network](#path-4-private-network-no-public-ingress) | An afternoon, mostly networking |

Every path produces the same database and the same bucket, so moving between
them is a `pg_dump` plus a copy of the bucket, restored elsewhere, then repoint
the client. That two-command form works today and is the one documented below.
A single `wealdrelay backup` command that wraps both is specified in
`specs/backend/relay/server.md` and is not implemented yet; until it ships, use
`pg_dump` and your bucket's own copy tool, and do not write a runbook around the
single command. The
workspace's identity is anchored to its genesis entry rather than to a hostname,
so changing hostname is a settings change and not a new workspace.

The smallest useful configuration of this entire system is one person running a
relay on their own laptop for sub-second sync between their own devices, with no
server anywhere. That is `brew install weald/tap/wealdrelay`, and it is a real
deployment rather than a curiosity.

## Path 0: build it yourself

Every path below starts from an artifact we published. This one does not, and it
is the one that makes the others checkable: a relay you built from source is a
relay whose behaviour you can read.

**Status, and read this before you follow any command here.** Source is
published and building from it works today. Until the first signed release is
tagged, the Homebrew tap does not exist, `get.weald.team` does not resolve, and
the image tag in `compose/docker-compose.yml` cannot be pulled, so paths 1, 2
and 4 need an image you built yourself with `scripts/relay-reproduce.sh`. The
configuration, operations and networking halves of this guide are accurate and
stable; the download-a-published-artifact half describes artifacts that are not
out yet. This notice comes down with the first published, signed, digest-pinned
release, and not before.

```sh
git clone https://github.com/hunterh37/WealdRelay.git
cd WealdRelay
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
enrollment URL into the provider's log view, which is the only place a
template-deploying user will look, and it is easy to close that view before
copying it. The mitigation is that the URL lives for 24 hours, and that
`wealdrelay bootstrap --reissue` will mint another one while the workspace still
has no trust root. Once a device has claimed it, reissue refuses, permanently.

## Path 2: compose on a VPS

`compose/`, and its own [README](compose/README.md). Three commands. Postgres,
MinIO, Redis and Caddy in one file, one hostname to edit.

The failures here are both DNS: a hostname pointed at the wrong address, or a
certificate that cannot be issued because port 80 is closed. The bundle names
which one it is in words.

## Path 3: bare binary and systemd

`systemd/`. For a team with existing Postgres and existing configuration
management. A unit file, an environment file, a documented user and directory
layout.

The binary comes from the release, with its checksum published beside it. Verify
before you install it, because this is the path with no container digest doing
that for you:

```sh
tag=wealdrelay-v0.1.0
target=x86_64-unknown-linux-musl        # or aarch64-unknown-linux-musl
base=https://github.com/hunterh37/WealdRelay/releases/download/$tag
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
record, no exposure at all. `private-network/` holds a Tailscale compose
overlay.

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

## What your relay operator can do

Keep the service running, and stop keeping it running.

That is the complete list. There is no admin password, no operator account and
no web admin panel, because there is nothing an operator could usefully
administer. Workspace administration happens in the client, signed by a device
holding `admit`. A relay operator who is not a workspace member has exactly two
powers.
