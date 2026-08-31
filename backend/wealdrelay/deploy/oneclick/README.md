# One-click catalogues

`templates/` is for a provider whose platform runs the relay for you (Render,
Fly, Railway, DigitalOcean App Platform) and `compose/` is for a VPS you already
keep. This directory is the third thing: the artifact each **third-party app
catalogue** wants, so that a person who has never seen a compose file can install
a relay from a list of apps.

Every artifact here describes the same deployment as `compose/docker-compose.yml`
and pulls the same digest. A catalogue is a distribution channel, never a
different product.

Status per platform lives in `specs/backend/build/relay-oneclick.md` and its
ledger, which is not published: it names submission accounts and review state,
which is our business rather than the protocol's. What is published is this
directory, because the artifacts are the thing a stranger needs to run or fork.

## The two kinds of channel

**Approval-free.** The platform reads a compose file we host, so nobody has to
accept us into anything. This is where the effort goes first.

| Platform | Artifact | How a user starts it |
| --- | --- | --- |
| Hostinger VPS, Docker Manager | `hostinger/docker-compose.yml` | Paste the raw file URL into Docker Manager |
| Any VPS with cloud-init | `../templates/cloud-init.yaml` | Paste into the provider's user-data box at create time |
| Dokploy | `dokploy/` | Blueprint, or paste the compose file |
| CapRover | `caprover/one-click-app.yml` | One-click apps, custom repository or paste |
| Coolify | `coolify/wealdrelay.yaml` | Paste as a Docker Compose resource |

**Approval-gated.** The platform reviews a submission and builds a machine image
or merges a pull request. Each row here is a piece of work with somebody else's
timeline attached, so the artifact is checked in and the submission is tracked in
the build ledger rather than assumed.

| Platform | Artifact it wants | Gate |
| --- | --- | --- |
| DigitalOcean Marketplace | A Droplet snapshot built with Packer, passing `img_check.sh` | Vendor access, then review |
| Vultr Marketplace | App profile plus provisioning scripts plus a built image | Vendor account and QA |
| Akamai, formerly Linode | StackScript plus an Ansible playbook in a public repository | Pull request |
| Umbrel | `umbrel/` | Pull request, and the app must be usable from a browser after install |
| Coolify catalogue | `coolify/wealdrelay.yaml` | The upstream repository needs 1,000 GitHub stars |
| Hetzner Cloud apps | None | Closed. `github.com/hetznercloud/apps` takes bug fixes only |

Two rows are worth reading as refusals rather than as backlog. Hetzner's
catalogue is closed to new applications, so on Hetzner the artifact is
`cloud-init.yaml` and there is nothing to submit. Umbrel requires that an
installed app be operable from a browser, and this relay has no admin panel by
construction, so its enrollment URL has to reach the user some other way; the
Umbrel artifact here prints it into a place the Umbrel UI shows, and if that is
not accepted the honest answer is that Weald is not an Umbrel app.

## What every artifact must keep

- `WEALD_RELAY_ACCESS_SET=enforce`. No catalogue artifact weakens it.
- No published host port for the relay's `8443`, and never any port for the
  observability listener on `9090`. TLS terminates in front.
- The image is `ghcr.io/weald-protocol/wealdrelay`, by release tag or digest,
  never a moving tag, because none is published.
- Generated passwords, never example values, using whatever secret generator the
  platform provides.
- The one-time enrollment URL has to end up somewhere the platform's own UI
  shows, because the person installing from a catalogue will not open a shell.

`../../../scripts/relay-oneclick.py --check` asserts each of those against every
file in this directory, and fails if an artifact drifts from the compose bundle's
image or access-set value.
