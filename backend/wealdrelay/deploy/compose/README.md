# The Weald relay, on your own VPS

Three commands to a TLS-terminated relay. `specs/backend/relay/deployment.md`
path 2.

```
curl -fsSL https://get.weald.team/relay | sh
cd weald-relay && cp .env.example .env && $EDITOR .env
docker compose up -d
```

The `.env` edit is one line: `WEALD_RELAY_HOSTNAME`. Everything else has a
working default.

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

**Copy that URL.** The first device to open it becomes the workspace trust root
and the genesis private key is destroyed in the same transaction. It expires in
24 hours or on first use. If you close the log before copying it, and no device
has claimed it yet:

```
docker compose exec relay wealdrelay bootstrap --reissue
```

That works only while the workspace has no trust root, and refuses afterwards,
permanently.

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

Put both in cron. `wealdrelay backup`, the single command that wraps the two into
one tarball, is specified in `specs/backend/relay/server.md` and is **not shipped
yet**; it is an open item on relay step 13. The two commands above are the
supported procedure until it is.

Restore is the same two in reverse, against any other install, then repoint the
client. Clients hold a full
copy and reconcile the delta on next connect, so a restore from a slightly stale
backup self-heals.

## Upgrade

```
docker compose pull && docker compose up -d
```

Rolling is safe: schema migrations are forward-compatible for one minor version.

## What your relay operator can do

Keep the service running, and stop keeping it running. That is the complete
list. There is no admin password, no operator account and no web admin panel,
because there is nothing an operator could usefully administer. Workspace
administration happens in the client, signed by a device holding `admit`.
