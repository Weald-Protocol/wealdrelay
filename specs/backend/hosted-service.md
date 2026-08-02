# The hosted service, and why it is not in this repository

Weald operates a hosted relay as a commercial product. Its specifications cover
accounts, billing, provisioning, compliance and the control plane that runs it.
None of them are published, and none of them are here.

This file exists because the relay specifications refer to that service in a
dozen places, and a reference that resolves to nothing reads like something was
withheld. What was withheld is a commercial product's internals. What was not
withheld is anything you need in order to run this relay, implement against it,
or check what it does.

## The boundary

The relay has no dependency on any commercial-layer vendor. No Clerk, no Stripe,
no control plane client, no account concept, no license check, no callback, and
no configuration key naming any of them. This is enforced rather than promised:
the required configuration is three environment variables, and none of them
names a Weald service.

Integration with the hosted service runs one way. The control plane polls the
relay's private readiness and metrics endpoints. The relay never initiates a
connection to it, does not know it exists, and behaves identically whether it is
there or not.

`WEALD_RELAY_PROFILE` selects `self_host` (the default) or `hosted`. It is
configuration in one binary rather than a fork, and the `hosted` profile only
removes capabilities. The binary you build from this repository is the binary
Weald runs. That is the point: a claim that the operator cannot read your
envelopes is worth what your ability to check it is worth, and you cannot check
a binary you were not given the source to.

## What the references meant

Where a relay specification cites this file, it was originally citing one of the
hosted service's documents. The subject is always one of:

| Original subject | What it decides | Does the relay depend on it |
|---|---|---|
| Accounts and onboarding | How a customer signs up and reaches a first workspace | No |
| Billing | Plan tiers, storage caps, metering | No. The relay enforces limits from its own configuration |
| Provisioning | How a hosted instance is created and torn down | No. A self-hosted relay is provisioned by you |
| Control plane | The service that operates hosted instances | No. It polls; it is never called |
| Service lifecycle | Upgrade, suspend and delete for hosted instances | No |
| Compliance | Retention, deletion and audit obligations Weald carries as an operator | No. You carry your own, and the relay gives you the mechanisms |

In every case the hosted service is a caller, an operator or a customer of this
relay. It is never a dependency of it.

## If you are self-hosting

You can ignore this file entirely. `backend/wealdrelay/deploy/README.md` is the
runbook, `specs/backend/relay/server.md` is the configuration surface, and
`specs/backend/relay/verification.md` is how you check that the binary you are
running is the source you are reading.
