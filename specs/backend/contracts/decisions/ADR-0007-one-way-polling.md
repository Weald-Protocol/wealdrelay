# ADR-0007: The control plane polls the relay. The relay never calls us.

- Status: accepted
- Date: 2026-06
- Source: `specs/backend/cloud/api.md`, `specs/backend/relay/operations.md`

## Decision

No webhooks from the relay. The control plane polls private `/readyz` and
`/metrics` over provider networking. The relay has no billing client and no
control-plane credential.

## Rationale

Keeping the direction one-way means the relay needs no credential for us and no
outbound configuration, which is what keeps the self-host and hosted binaries
**identical**. That identity is the audit story: the artifact a customer runs
themselves is the artifact we run for them.

## Consequences

- Hosted lifecycle transitions are orchestrated by changing a generic local
  config value (`WEALD_RELAY_WRITE_MODE`) through the provider deployment API,
  doing a rolling restart, waiting for `/readyz`, and only then committing the
  transition. The relay never learns why.
- The relay reports its mode and a non-content reason code on `/readyz` and in
  `AUTH`. The client renders that reason and directs the person to the
  dashboard; it never infers a deadline from local time and never needs a
  control-plane token.
- Self-hosters get the same maintenance mode with no billing semantics attached.
- Metrics on hosted are aggregate-only, so the control plane is never offered
  per-group counts rather than choosing not to retain them.
