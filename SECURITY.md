# Security

## Reporting

`security@weald.team`. Please give us a chance to ship a fix before publishing.

Include what you did, what happened, and what you expected. A reproduction
against a relay you run yourself is ideal; `scripts/weald-stack up` gives you the
dependencies in about a minute. If encrypted mail is easier, say so in a first
message and we will send you a key.

We aim to acknowledge within three working days and to tell you our assessment,
including a disagreement, within ten. If a report is valid we will credit you in
the release notes unless you would rather we did not.

## What is in scope

The two crates in this repository, their wire protocol, and the deployment
material under `backend/wealdrelay/deploy/`. Concretely, we want to hear about:

- anything that lets the relay, or its operator, learn message contents, file
  contents, channel names, ticket titles, or which human a device belongs to;
- anything that lets a device read or write in a group it was never admitted to,
  or that survives revocation;
- anything that lets one workspace observe another;
- authentication bypasses on the device-key proof, and downgrade attacks on
  version negotiation;
- a way to make the relay accept a frame the CDDL schema and the vector corpus
  say it must reject, or reject one it must accept;
- memory unsafety anywhere, and in particular across the `weald-mls` C ABI;
- a build that does not reproduce, or a published digest that does not match its
  source.

**Cryptographic and protocol design objections are in scope even without an
exploit.** If the argument in `specs/backend/relay/` is wrong, that is the report
we most want.

## What is not

- Denial of service by volume against a relay you do not operate. The bounds are
  specified in `specs/backend/relay/operations.md`; a way to exceed them at
  trivial cost is in scope, load is not.
- Findings that require the operator's own database credentials or shell. An
  operator who holds the database holds ciphertext, and that is the design.
- The macOS client, which is not in this repository. Send those to the same
  address and we will route them.
- Automated scanner output with no analysis attached.

## What the relay is designed not to be able to do

Worth reading before reporting, because it decides whether something is a bug or
the architecture: `specs/backend/contracts/threat-model/relay-boundary.md` states
what the relay unavoidably sees (ciphertext, sizes, timing, and salted hashes of
who may fetch what) and what it must never see. Metadata in that first list is
documented rather than fixed, and `specs/backend/relay/verification.md` is honest
about which mitigations are bounded.

The single highest-risk edge in the system is the trust-root race at
provisioning, written up in
`specs/backend/contracts/threat-model/bootstrap-handoff.md` along with its
residual risk. If you can improve on those controls we would like to know.

## Supported versions

Pre-1.0. The most recent tagged release is the supported one, and there are no
backports yet. Every release is a signed, digest-pinned image whose build two
independent runners and a clean clone of the tag all agreed on; a security fix
ships the same way, so the thing you verify is the thing you run.

`specs/backend/contracts/governance.md` covers the emergency path, including how
a breaking change can skip the 30 day comment period when a vulnerability
requires it, and what we owe you when it does.
