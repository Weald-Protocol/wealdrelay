# The image-building catalogues

DigitalOcean Marketplace and Vultr Marketplace do not take a compose file. They
take a machine image, built by us, reviewed by them, and there is no artifact in
this directory for either yet. This page says what each wants so the work is a
morning rather than a discovery, and so nobody mistakes an absence for an
oversight.

Both build the same shape: a supported base image, Docker installed, the compose
bundle placed at `/opt/weald-relay`, a first-boot unit that generates the
passwords and asks for the hostname, and the vendor's own cleanup script run last
so no build-time credential or host key survives into the snapshot.

**DigitalOcean.** Vendor access first, by mail to their one-clicks team, then the
Vendor Portal. The artifact is a Droplet snapshot built with Packer using the
DigitalOcean builder. `github.com/digitalocean/marketplace-partners` carries the
template, `cleanup.sh` and `img_check.sh`; the submission fails unless
`img_check.sh` reports every test passed, warnings excepted. Build on their
smallest tier so the image works on all of them. Their vendor terms let them
reject a submission for any reason or none, and no review SLA is published.

**Vultr.** A vendor account and their publisher agreement, then an app profile,
provisioning scripts and a built image, reviewed by their QA.

Two things about a machine image are worse than a compose file, and both are
reasons this is second in the order rather than first. An image is a copy of the
relay frozen at build time, so every release needs a resubmission, where a
compose file pulls the digest we published this morning. And a snapshot is the
one artifact a reader cannot reproduce from source, which cuts against the whole
reason the relay is open source (`specs/backend/relay/verification.md`). So the
first-boot unit pulls the image by digest from GHCR rather than baking it into
the snapshot: the catalogue entry ages, the relay does not.

Hetzner is not on this page. `github.com/hetznercloud/apps` states it cannot
accept new applications, so on Hetzner the answer is `cloud-init.yaml` pasted
into the user-data box, and there is nothing to submit.
