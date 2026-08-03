# The Weald relay, on your own VPS

A TLS-terminated relay in three commands. `specs/backend/relay/deployment.md`
path 2.

There are two routes and they do not mix. Pick one. The difference that matters
is where the two passwords come from: `install.sh` generates them, and by hand
you generate them yourself.

**Status.** Until the first signed release is tagged there is no release page to
download from and the image reference in `docker-compose.yml` cannot be pulled.
Route B works from a clone today if you build the image yourself with
`scripts/relay-reproduce.sh` and set `WEALD_RELAY_IMAGE` to what you built.
Everything else on this page is accurate now. This notice comes down with the
first published, signed, digest-pinned release.

## Route A: install.sh

`install.sh` is attached to every release. Download it from the release page for
the tag you want, https://github.com/Weald-Protocol/wealdrelay/releases, then:

```
sh install.sh
cd weald-relay && $EDITOR .env
docker compose up -d
```

`install.sh` fetches the compose bundle for the release, verifies its SHA-256,
copies `.env.example` to `.env` and fills in `POSTGRES_PASSWORD` and
`MINIO_ROOT_PASSWORD` with 40 random characters each. It does not start
anything: that decision is yours.

The `.env` edit is then one line, `WEALD_RELAY_HOSTNAME`. Everything else has a
working default.

**Do not run `cp .env.example .env` after `install.sh`.** That puts the empty
example passwords back over the generated ones, and compose will refuse to
start until you fill them in again.

## Route B: by hand, from a clone

No release needed, and nothing is downloaded that you have not read.

```
git clone https://github.com/Weald-Protocol/wealdrelay.git
cd wealdrelay/backend/wealdrelay/deploy/compose
cp .env.example .env
$EDITOR .env
docker compose up -d
```

On this route the `.env` edit is three lines, not one:

- `WEALD_RELAY_HOSTNAME`, your hostname.
- `POSTGRES_PASSWORD`, from `openssl rand -base64 30`.
- `MINIO_ROOT_PASSWORD`, from a second `openssl rand -base64 30`.

Both passwords ship empty. Compose refuses to start on an empty password and
names the variable, so there is no way to follow this route and end up running a
placeholder.

## Before you start

- A DNS A or AAAA record for your hostname, already pointing at this machine.
- Ports 80 and 443 open. Port 80 is not optional: it is how the certificate is
  issued.
- Docker with the compose plugin.

That is the whole list. The relay is blind, so there is no key to manage, no
secret to rotate, and no admin account to create.

## What comes up

| Service | What it is | Can you remove it |
| --- | --- | --- |
| `relay` | The relay. One process, no sidecars. | No. |
| `postgres` | Envelope log, group heads, key packages, quotas. | No. |
| `minio` | Encrypted media blobs, S3 API. | Yes: point `WEALD_RELAY_STORAGE_URL` at a directory instead. |
| `redis` | Fanout between relay processes, presence. | Yes for a single-process install: delete the service and unset `WEALD_RELAY_REDIS_URL`. |
| `caddy` | Automatic TLS. | Only if something else already terminates TLS for you. |

Only Caddy publishes a port. The relay is reachable from the internet through
Caddy and in no other way, and the private observability listener carrying
`/readyz` and `/metrics` is never proxied.

## First boot

The relay migrates the schema, generates a single-use genesis key and prints a
one-time enrollment URL:

```
docker compose logs relay
```

**Copy that URL and the one-time code printed with it.** The first device to
open the URL and enter the code becomes the workspace trust root, and the
genesis private key is destroyed in the same transaction. It expires in 24 hours
or on first use.

If you close the log before copying, read it again with the same command: the
log is still there. If the log itself is gone, restart the relay. While the
workspace is still unenrolled, every start reprints the enrollment link.

**The one-time code is not reprinted, ever.** The relay stores only its Argon2id
hash, so there is nothing left to print, and there is no reissue command and
never will be: reissuing a bootstrap invite is forbidden by the threat model. If
you lose the code before a device enrols, the only recovery is to start again
from an empty database:

```
docker compose down --volumes
docker compose up -d
```

That destroys the workspace. At this point in the sequence there is nothing in
it yet, which is why this is a recovery and not a disaster.

## When it does not work

The two failures are both DNS, and the bundle names which one it is rather than
printing an ACME stack trace.

```
docker compose logs caddy
```

- **"could not resolve"**: the hostname in `.env` has no record, or the record
  points somewhere else. Fix DNS, then `docker compose restart caddy`.
- **"connection refused on port 80"**: a firewall or another process holds
  port 80. ACME's HTTP challenge needs it.

To confirm the relay itself is alive independently of TLS:

```
docker compose exec caddy wget -qO- http://relay:8443/healthz
```

## Backup

Two things, and both hold ciphertext only, so a backup can go anywhere including
a provider you would not otherwise trust.

```
# 1. the database
docker compose exec -T postgres pg_dump -U wealdrelay -Fc wealdrelay > weald-db.dump

# 2. the bucket
docker compose run --rm --entrypoint sh minio-init -c \
  'mc alias set local http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" \
   && mc mirror local/"$BUCKET" /backup' -v "$PWD/weald-blobs:/backup"
```

Put both in cron. A single `wealdrelay backup` command that wraps both is
specified in `specs/backend/relay/server.md` and is **not implemented**. Until
it ships, the two commands above are the supported procedure, and no runbook
should be written around the single command.

Restore is the same two in reverse, against any other install, then repoint the
client. Clients hold a full
copy and reconcile the delta on next connect, so a restore from a slightly stale
backup self-heals.

## Upgrade

There is no moving tag to pull, deliberately: a relay that changed under its
operator without a deploy they asked for is the thing digest pinning exists to
prevent. An upgrade is an edit.

Set `WEALD_RELAY_IMAGE` in `.env` to the tag or digest of the release you are
moving to, then:

```
docker compose pull && docker compose up -d
```

Rolling is safe: schema migrations are forward-compatible for one minor version.

## What your relay operator can do

Keep the service running, and stop keeping it running. That is the complete
list. There is no admin password, no operator account and no web admin panel,
because there is nothing an operator could usefully administer. Workspace
administration happens in the client, signed by a device holding `admit`.
