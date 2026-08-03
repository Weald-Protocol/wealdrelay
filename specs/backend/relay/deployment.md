# Relay: deployment paths

`specs/backend/relay/server.md` describes the artifact. This describes the four
concrete ways a customer ends up with one running, ordered by how many customers
will take each path, with the actual failure points named.

Design target throughout: ten minutes from decision to a working relay, with no
step that requires understanding MLS, and no step whose failure produces a
half-working workspace.

## Path 1: one-click provider template

The path most self-hosters take. Maintained templates for Railway, Fly.io,
Render and DigitalOcean App Platform, each wiring the provider's own managed
Postgres and object storage rather than running our containers for them.

What the template must do, since a template that leaves work behind is worse
than no template:

- Provision Postgres and a bucket, wire the three required environment
  variables, and issue TLS on a provider subdomain.
- Run first-boot migrations and print the bootstrap invite and genesis
  fingerprint into the provider's log view, which is the only place a
  template-deploying user will look.
- Set `WEALD_RELAY_ACCESS_SET=enforce`, which is the default and is never
  weakened by a template.

Failure point: the user closes the log view before copying the bootstrap invite.
Mitigation is the 24-hour expiry (`specs/backend/relay/invites.md`) plus
`wealdrelay bootstrap --reissue`, which works only while the workspace has no
trust root and refuses afterwards, permanently.

## Path 2: Compose on a VPS

Three commands, per `specs/backend/relay/server.md`. Postgres, MinIO, Redis and
Caddy in one file, one hostname to edit.

Failure points, all DNS: a hostname pointed at the wrong address, or a Caddy
certificate that cannot be issued because port 80 is closed. The bundle's health
check names exactly which of those it is, in words, rather than printing an ACME
stack trace.

## Path 3: bare binary with systemd

For teams with existing Postgres and existing configuration management. A unit
file, an environment file, a documented user and directory layout, and a note
that TLS is theirs to terminate.

This is the path where an operator is most likely to skip backups, so the docs
put backup configuration before the start command rather than after it.

## Path 4: private network, no public ingress

The path enterprises ask for and the reason it is a first-class deployment
rather than an open item.

The relay binds to a Tailscale or WireGuard interface and is unreachable from
the internet. Clients reach it over the same network. There is no ACME, no
public DNS record, and no exposure at all.

Consequences, all of which the docs must state together:

- **Certificates.** Tailscale's own TLS, or a private CA the client is told to
  trust explicitly. The client's digest and hostname pinning still applies.
- **Invites.** The landing page is reachable only inside the network, so a new
  joiner must be on the network first. The invite email says so, and onboarding
  ordering becomes network first, workspace second.
- **`WEALD_RELAY_ACCESS_SET=off` is defensible here** and only here, because the
  network is doing the perimeter work the access set does elsewhere. It remains
  off by default from our side; an operator choosing it sees it reflected in
  every client's encryption panel.
- **Our support cannot reach it**, which is true of every self-host path but is
  most visible here.
- **It is a self-contained compose file**, not an overlay on the public one.
  `backend/wealdrelay/deploy/private-network/docker-compose.tailscale.yml` brings
  up the whole stack itself and drops Caddy, because a relay behind a tailnet
  terminates TLS on the tailnet rather than through ACME. An overlay cannot work
  here: Compose merges rather than replaces, so the base file's `networks:` on
  the relay service would survive alongside this path's `network_mode:` and
  Compose refuses a service carrying both.

## The local case

A team running the relay on a Mac mini in a cupboard is a legitimate deployment
at this posture, served by `brew install hunterh37/tap/wealdrelay`. The client can
also run a relay locally for a solo user who wants sub-second sync across their
own devices with no server anywhere, which is the smallest useful configuration
of this entire system and is worth having in the docs as the first example
rather than a curiosity at the end.

## Choosing

The docs open with a four-row table, not prose: what you have, what to run, how
long it takes. Someone deciding between these has already read too much.

| You have | Take | Time |
| --- | --- | --- |
| A provider account and no patience | Path 1 | 5 minutes |
| A VPS | Path 2 | 10 minutes |
| Config management and a DBA | Path 3 | An afternoon |
| A policy against public ingress | Path 4 | An afternoon, mostly networking |

## Migration between paths

Every path produces the same database and bucket, so moving is
`wealdrelay backup`, restore elsewhere, repoint DNS or the client's relay
hostname. Clients reconcile from their own copies and repair any delta
(`specs/backend/relay/server.md`).

The one thing that does not move is the workspace's identity, which is anchored
to the genesis entry in the transparency log rather than to a hostname. Changing
hostname is a settings change, not a new workspace, and the client says so
rather than showing a scary unknown-relay warning to everyone at once.
