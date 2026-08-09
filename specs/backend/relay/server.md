# Relay: the self-host package

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only: the Clerk
> production instance, Stripe live mode, the production Render environment and
> Postgres, the production R2 bucket, the published relay digest. No dev tier,
> no test mode, no staging tier, and no agent creates one. `local` and `ci` are
> not an exception because they reach no vendor at all. A gate that cannot reach
> production configuration fails; it never degrades to a mock, a stub, a fake, a
> skip or a newly created dev or staging resource.

What the customer actually downloads and runs. This is the answer to "what is
the final deliverable".

Design constraint that decides everything below: the relay is blind
(`specs/backend/relay/groups.md`), so it holds no key, needs no secret management, and
has no privileged operator mode. That makes it a genuinely boring service to
operate, and boring is the product here. A customer should be able to stand it
up in under ten minutes on infrastructure they already have, and should never
have to think about it again.

## The artifact

**One statically linked Rust binary: `wealdrelay`.**

- No runtime dependencies. No Node, no Python, no JVM.
- Targets: `aarch64-apple-darwin`, `x86_64-unknown-linux-musl`,
  `aarch64-unknown-linux-musl`, `x86_64-pc-windows-msvc`.
- Configuration by environment variables, with an optional `relay.toml`.
- Roughly 20 MB, single process, no sidecars.

Everything else on this page is packaging around that one binary.

## Dependencies the operator must provide

Three, all of them commodity, all of them things a hosting provider offers as a
managed add-on.

| Dependency | Purpose | Can it be omitted |
| --- | --- | --- |
| PostgreSQL 15+ | Envelope log, group heads, key packages, quotas. | No. |
| S3-compatible object storage | Encrypted media blobs. | Yes, falls back to a local filesystem path for single-node installs. |
| Redis 7+ | Fanout across multiple relay processes, presence, ephemeral kinds. | Yes, omit for single-process installs; the binary uses in-process channels instead. |

A minimum viable deployment is therefore `wealdrelay` plus Postgres plus a disk.
That runs comfortably for a 30-person team on the smallest instance every
provider sells.

Note what is absent: no Elasticsearch, no search cluster, no ML service, no
queue. There is no search index because the relay cannot read content. The
privacy property and the operational simplicity are the same property.

## Distribution channels

Shipped for every install path a customer might already be standing in.

**1. Container image.** `ghcr.io/weald-protocol/wealdrelay:<version>`, multi-arch amd64 and
arm64, distroless base, non-root, no shell. Signed with cosign, SBOM attached,
provenance attestation via SLSA level 3.

**2. Compose bundle.** One `docker-compose.yml`, one `.env.example`, one
`README.md`. Includes Postgres, MinIO, Redis and Caddy for automatic TLS.

```
curl -fsSL https://get.weald.team/relay | sh
cd weald-relay && cp .env.example .env && $EDITOR .env
docker compose up -d
```

Three commands to a TLS-terminated relay on a fresh VPS. The `.env` edit is one
line, the hostname. Everything else has a working default.

**3. One-click templates.** Maintained deploy buttons and templates for
Railway, Fly.io, Render, DigitalOcean App Platform, and a Hetzner or generic-VPS
cloud-init script. Each wires the provider's own managed Postgres and object
storage rather than running our containers for them, because a customer on
Railway wants Railway's Postgres backed up by Railway.

**4. Homebrew and a raw binary.** `brew install weald/tap/wealdrelay` for local
development and for a team that genuinely wants to run this on a Mac mini in a
cupboard, which at this posture is a legitimate deployment.

A Helm chart and Terraform modules are deliberately not in this list. Nobody at
a team of 3 to 30 is standing up Kubernetes for a 20 MB binary, and both are
cheap to add later if a specific deal asks.

## Configuration surface

Small on purpose. The full required set:

```
WEALD_RELAY_HOSTNAME       relay.acme.com
WEALD_RELAY_DATABASE_URL   postgres://...
WEALD_RELAY_STORAGE_URL    s3://bucket  |  file:///var/lib/wealdrelay/blobs
```

Optional, with defaults that work:

```
WEALD_RELAY_REDIS_URL          unset, single-process mode
WEALD_RELAY_LISTEN             0.0.0.0:8443
WEALD_RELAY_TLS                acme | file | off
WEALD_RELAY_MAX_STORAGE_GB     unlimited
WEALD_RELAY_RETENTION_DAYS     unlimited
WEALD_RELAY_ACCESS_SET         enforce | off      (default enforce)
WEALD_RELAY_SMTP_URL           unset, invites are copied by the admin instead
WEALD_RELAY_WRITE_MODE         full | read_only (default full)
WEALD_RELAY_BOOTSTRAP_HANDOFF_PUBKEY  unset, X25519 public key for a one-time sealed bootstrap handoff
WEALD_RELAY_OBSERVABILITY_LISTEN  127.0.0.1:9090 (private health and metrics listener)
```

Two of those decide security posture, so their semantics are pinned here rather
than left to the implementation:

**`WEALD_RELAY_ACCESS_SET`.** `enforce` means `AUTH` is checked against the
published access set (`specs/backend/relay/wire.md`), so revoking a device
disconnects it. `off` means any well-formed key may open a socket, which is
appropriate only for a relay with no public ingress, such as the Tailscale-only
deployment below. The hosted tier is always `enforce` and the value is not
customer-configurable there. A relay running `off` says so in `/readyz` output
and the client shows it in the encryption panel, because a customer should not
have to read their operator's environment file to learn this.

**`WEALD_RELAY_SMTP_URL`.** Self-host only. Configuring it lets the relay send
invite mail. It is unset by default and is refused outright on the hosted tier,
because our relay holding invitee email addresses would put a list of humans
inside the blind half of the system (`specs/backend/relay/invites.md`).

**`WEALD_RELAY_WRITE_MODE`.** A vendor-neutral local maintenance mode.
`read_only` rejects new durable writes while leaving reconciliation and export
available, and is exposed to authenticated clients with a non-content reason
code. It does not contact or name a billing system. Hosted lifecycle use,
atomic deployment and customer UX are specified in `cloud/service-lifecycle.md`.

**`WEALD_RELAY_BOOTSTRAP_HANDOFF_PUBKEY`.** Optional, short-lived X25519 public
key. On empty-workspace first run the relay seals the link half of its bootstrap
invite to this key, retains only the sealed blob until the invite expires, and
serves it at a rate-limited path derived from the public key. Reading that blob
does not consume it and reveals no plaintext without the corresponding private
key; redemption remains the one-time operation. It never stores the plaintext
link. This generic primitive has no cloud vendor dependency; its hosted use and
two-channel threat model are specified in
`cloud/provisioning.md`.

The format and the path are pinned here rather than left to the implementation,
because two independent programs have to agree on them byte for byte and a
disagreement is only discovered when a customer's one bootstrap invite is spent
on it. The control plane's half is
`backend/weald-cloud/src/provisioning/handoff.ts`; the relay's half is **not
built yet**, and this is what it must do.

    blob = ephemeral_public_key (32) || AES-256-GCM(key, nonce, plaintext) || tag (16)
    key   = HKDF-SHA256(ikm  = X25519(ephemeral_private, handoff_public),
                        salt = "weald-bootstrap-handoff-v1",
                        info = handoff_public_key,
                        len  = 32)
    nonce = 12 zero bytes
    path  = /handoff/<base64url(SHA-256(handoff_public_key))>

Four things about that, each of which is a decision rather than an accident. The
nonce is fixed and safe **here and only here**, because the key is derived from a
fresh ephemeral keypair per sealing and so encrypts exactly one message; a random
nonce would be equally safe and one more field for a second implementation to get
wrong. `info` binds the ciphertext to the key it was sealed to, so a blob lifted
from one instance and served for another fails to open rather than decrypting.
The path is derived from the key rather than from the workspace, because a path
containing a hostname would be a guessable url for a ciphertext. And the blob is
served on the **public listener behind the operator bearer**, mounted only where
both `WEALD_RELAY_BOOTSTRAP_HANDOFF_PUBKEY` and `WEALD_RELAY_OPERATOR_TOKEN` are
set, with the genesis fingerprint alongside it:

    GET /handoff/<derived>  ->  200 {"blob": "...", "sealed_code": "...",
                                     "genesis_fingerprint": "..."}
                                404 before anything has been sealed

An earlier draft of this section pinned the route to the private observability
listener, "never on the public one". That was right about the port and wrong about
the topology, and it is corrected here rather than quietly softened. The private
listener is per-region provider-private networking, and the control plane does not
run in every region it provisions into, so `renderHandoffBlob` could not reach it
and read unreachable as absent. The consequence reached a paying customer: `POST
/instances/:id/bootstrap` answered `instance_not_operable` however many times the
Reveal button was pressed, and the provisioning saga, which waited on the same
blob, destroyed and refunded relays that were up, certificated and answering on the
customer's own hostname. A blob nobody can fetch is not a safer blob.

Moving it costs nothing the design was relying on. What is served is a ciphertext
openable only by a private key held in another system and destroyed on first claim,
the path is derived from that key rather than from anything guessable, and the
request must still carry the operator bearer, compared in constant time by the same
function `/admitted` uses. The private listener was never the security boundary;
the bearer was, and it still is. `/admitted` is mounted on the public listener too,
for the same reason and under the same bearer, and both remain absent entirely on a
relay with no operator token, which is every self-hosted one.

The fingerprint travels with the blob because `cloud/api.md` returns the two
together and the client checks which genesis key signed the invite it is about to
redeem. Two separate reads would be two chances for a relay to answer about two
different keys.

`sealed_code` is the **code half**, sealed with the same function to the same key
and in the same format, carrying the 12 Crockford symbols in the grouped form
`Code::grouped` prints. Two ciphertexts rather than one, because the two halves
travel to two different places for two different reasons
(`cloud/provisioning.md`): the link half is claimed once by the buyer's browser
and the code half is mailed to their verified address, and a single blob would put
both in the same buffer in the endpoint that answers the browser. Sealing the code
rather than serving it in the clear is what keeps the relay's own guarantee intact:
it persists `Argon2id(code, salt=token)` and this ciphertext, and no recoverable
plaintext code. A relay that serves a blob with no `sealed_code` beside it is
refused, for the same reason one with no fingerprint is: a claim happens once, and
a workspace whose code was never sealed is one nobody can ever enroll into.

`specs/backend/contracts/wire/vectors/bootstrap-handoff.json` holds the
conformance vectors: three sealed blobs with their keys and plaintexts, including
an empty one and a long one. Both implementations are checked against those
bytes rather than against each other.

An earlier draft listed `WEALD_RELAY_OPEN_ENROLLMENT` with no semantics defined
anywhere. It is deleted rather than specified. Enrollment is invites, one path,
and a flag that silently widened it was the most dangerous undefined knob in the
configuration surface.

**The relay has no dependency on any commercial-layer vendor.** No Clerk, no
Stripe, no control plane client, no account concept, no license check, no
callback, and no configuration key naming any of them. The complete required
configuration is the three variables above. A pull request adding a fourth that
points at something in `specs/backend/cloud/` is a trust boundary change, because
it would mean the hosted binary differs from the audited binary and a self-hoster
runs something we do not.

### The relay's outbound configuration keys

The rule above is about a key pointing at something of ours. It is not a rule that
the relay may never reach outward, and the difference has to be written down or the
next person to need an outbound leg will either break the rule or abandon a feature
for the wrong reason. Every outbound destination the relay has is listed here, with
what it points at and what its absence means, and the list is exhaustive: a key not
on it does not exist.

| Key | Points at | Absent means |
| --- | --- | --- |
| `WEALD_RELAY_DATABASE_URL` | the relay's own Postgres | boot failure. Required |
| `WEALD_RELAY_STORAGE_URL` | the relay's own object store, ciphertext only | boot failure. Required |
| `WEALD_RELAY_REDIS_URL` | a declared second instance | one process, which is the ordinary shape |
| `WEALD_RELAY_PUSH_URL` | a ringer's wake route, chosen by the operator | no outbound wake leg. This is the default |
| `WEALD_RELAY_PUSH_REGISTER_URL` | a ringer's registration route, stated to clients | the wake url's host with the contract's registration path |

`WEALD_RELAY_SMTP_URL` is deliberately not in that table. It is refused in
production rather than merely unset, because relay-sent invite mail would put a
list of humans inside the blind half, and it is named here so that its absence from
the table reads as a decision rather than an oversight.

The two push keys arrived with protocol version 4 and are the first outbound
destination on this component that is not its own storage, so they got the review
this section demands: `../contracts/decisions/ADR-0012-push-via-a-separate-ringer.md`
is that review, and it is published. The finding, in short, is that the destination
is a URL the operator supplies with no default ever, that a relay with
`WEALD_RELAY_PUSH=off` has no outbound leg at all and that off is the default, that
the ringer's contract has no account concept to attach a licence to, and that the
hosted binary is still the audited binary with a different profile. A self-hosted
relay can point at our ringer and wake our App Store build without asking us for
anything, which is the property that would have been lost by any design where the
relay held the key.

The refusals are what hold that rather than describe it, and they are startup
refusals rather than runtime ones: `PUSH=on` with no `PUSH_URL` will not start,
a non-`https` destination will not start outside `local` and `ci`, and `PUSH=off`
with any other `PUSH_*` variable set will not start, because a
configured-and-ignored outbound destination reads as working and is not.

The direction of every integration is one-way: the control plane polls private
`/readyz` and `/metrics`, and the relay never initiates. The public listener
serves only `/healthz` and gives no state beyond liveness; detailed readiness and
metrics bind to `WEALD_RELAY_OBSERVABILITY_LISTEN`, loopback by default. Hosted
deployments expose that listener only over provider-private networking. This
keeps the same digest usable by self-hosters without publishing storage, usage,
or security-state metadata to the internet (`specs/backend/cloud/control-plane.md`).

There is no admin password, no operator account and no web admin panel, because
there is nothing an operator could usefully administer. Workspace administration
happens in the client, signed by a device holding `admit`
(`specs/backend/relay/identity.md`). A relay operator who is not a workspace member has
exactly two powers: keep the service running, and stop keeping it running.

Say that in the docs in those words. It is the strongest sentence we have.

## Operations

**Bootstrap.** First run migrates the schema and generates a single-use genesis
key. Without a handoff public key it prints a one-time enrollment URL containing
the relay hostname, genesis-key fingerprint and TLS-key fingerprint. With a
handoff public key it prints only those non-secret fingerprints and creates the
sealed handoff blob described above; this is the hosted path. The first device to
open the URL becomes the workspace trust root, and the genesis private key is
destroyed in the same transaction. The URL expires in **24 hours** or on first
use. Full rules, including why the genesis key is bounded the way it is, are in
`specs/backend/relay/invites.md`.

**Backup.** `pg_dump` plus the bucket. Ciphertext only, so a backup can go
anywhere, including a provider we would not otherwise trust. `wealdrelay backup`
wraps both into one tarball for the customer who does not want to think about it.

**Restore.** `wealdrelay restore <tarball>`. Clients reconcile automatically on
next connect and repair gaps from their own local copies, so a restore from a
slightly stale backup self-heals rather than losing the delta. This is a direct
benefit of every client holding a full copy.

**Upgrade.** Rolling. Schema migrations are forward-compatible for one minor
version, so an old process and a new process can run against the same database
during a deploy.

**Observability.** Prometheus metrics and detailed `/readyz` bind only to the
private observability listener; public `/healthz` is liveness only. Structured
JSON logs and OpenTelemetry traces remain available if an endpoint is
configured. Metrics exclude anything content-derived, which is automatic, since
the relay does not know channel names or anything else inside an envelope.

Per-group labels are a separate question and they are **off by default**.
`WEALD_RELAY_METRICS_GROUP_LABELS=on` breaks envelope counts and byte totals out
per group id, which is useful to a self-hoster debugging their own instance and
is never enabled on the hosted tier. With it off the endpoint exposes instance
totals only, so per-group counts are not merely something our control plane
declines to retain, they are something it is not offered
(`specs/backend/cloud/billing.md`). Full behaviour in
`specs/backend/relay/operations.md`.

**Health.** Public `/healthz` is liveness only. Private `/readyz` is readiness,
including database and storage reachability.

## Sizing

Measured against a synthetic 30-person workspace with 12 concurrent agents.

| Team size | Instance | Postgres | Storage growth |
| --- | --- | --- | --- |
| 3 to 10 | 1 vCPU, 512 MB | 1 GB | ~400 MB/month |
| 10 to 30 | 1 vCPU, 1 GB | 5 GB | ~2 GB/month |
| 30 to 100 | 2 vCPU, 2 GB, 2 replicas + Redis | 20 GB | ~8 GB/month |

Media dominates storage. Text is small but not negligible, and the earlier
figures on this table were optimistic because they ignored three things that are
real: one Automerge change is one envelope with its own MLS framing overhead,
`doc.snapshot` is additive rather than replacing what it compacts, and epoch
churn from agents produces invite-bundle refresh and `recovery.wrap` traffic on
every commit. The numbers above assume compaction is running per
`specs/backend/relay/lifecycle.md`. Without it, growth is monotonic and a
storage-priced plan turns into a bill the customer has no lever over, which is
why compaction is a launch requirement and not a later optimisation.

## Verifiability

The "we cannot read your data" claim is only worth something if it is checkable.
Four commitments, all of which are release-blocking:

1. **Reproducible builds.** The published container digest is byte-reproducible
   from the tagged source. A third party can rebuild and compare.
2. **Published digests.** Every release lists its image digest and binary
   SHA-256 in the repository and in the release notes, signed.
3. **Client-side release comparison.** The Weald client shows the relay's
   self-reported build digest and warns when it differs from the signed release
   feed. This detects drift but is not runtime attestation: a modified binary can
   lie about its own digest. Hosted deployments additionally retain provider
   deployment metadata and signed image provenance for independent audit.
4. **Third-party audit before general availability.** Of the MLS integration and
   the envelope handling specifically. Scope, firm and report published.

Point 3 is the one competitors will not copy, because it is only possible when
the server has no legitimate need for content access.

## Hosted offering

Same binary, same image, same digest as the self-host build. That is the whole
pitch: our hosted relay is the artifact customers can audit, running on
infrastructure they can leave at any time.

Migration off hosted is `wealdrelay backup` against our instance, restore
against theirs, repoint the client. No export format, no data liberation
feature, no negotiation, because there is nothing we hold that they do not.

Pricing sits on storage and retention rather than seats
(`specs/backend/cloud/billing.md`).

## Upgrades for self-hosters

Hosted instances are upgraded on a schedule the customer picks
(`specs/backend/cloud/provisioning.md`). Self-hosters had no equivalent signal,
which mattered because clients pin against the public `/releases` feed and would
warn about a digest mismatch the operator had no way to notice.

So the relay checks `/releases` itself, on a 24-hour timer, and reports the
result on `/readyz` and `/metrics`. A relay behind a security release surfaces in
the client as an **update available** notice naming the release and its
advisory, shown to admins only, with the upgrade command. No auto-upgrade and no
phone-home beyond an unauthenticated GET of a public feed, which is disclosed in
the docs and disableable with `WEALD_RELAY_RELEASE_CHECK=off` for air-gapped
installs.

The distinction the client draws matters: a digest that does not match its
source tag is an alarm, and a digest that is genuinely older than the latest
release is a chore. Rendering the second as the first is how a security banner
gets trained into background noise.

## Open items

- Browser client key custody. A browser cannot hold a device key the way the
  Mac app can. Options are a WASM client with an IndexedDB-held key plus a
  passkey unlock, or treating the browser as a view onto a paired desktop. This
  gates the `reach` score in `specs/backend/relay/overview.md` and is not yet decided.
- A Tailscale or WireGuard-only deployment mode for teams that want no public
  ingress. Now specified as a supported path in
  `specs/backend/relay/deployment.md`, and the only path where
  `WEALD_RELAY_ACCESS_SET=off` is a reasonable setting.
