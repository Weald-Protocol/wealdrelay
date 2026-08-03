# ADR-0007: The relay never calls out

- Status: accepted
- Date: 2026-06
- Source: `specs/backend/relay/server.md`, `backend/wealdrelay/src/health.rs`

## Context

A hosted fleet needs to know whether an instance is alive, whether its
dependencies are up, and whether it is behind a security release. The obvious
shape is a heartbeat: each relay posts its state to a central endpoint.

## Decision

The integration runs one way only. Something outside polls the relay's
observability listener; the relay never initiates a request to us. Its only
outbound connections are to its own Postgres, its own object store, and two
things the operator switches on for themselves: a release-version check, and the
operator's own SMTP server for invite mail. Neither is ours and neither carries
workspace state.

- The public listener serves `/healthz` and reports liveness and nothing else.
- Detailed readiness and metrics bind to a separate listener, loopback by
  default.
- The relay holds no client, credential, endpoint or configuration key for any
  commercial-layer vendor. There is nothing in the binary to point at a
  collector, because there is no collector setting.

## Rationale

**The self-hoster gets the audited binary, unmodified.** If the hosted build
phoned home and the self-host build did not, they would be two binaries, and the
reproducibility proof would cover the wrong one. One binary that never calls out
is the only version of this that keeps "the digest you verified is the digest we
run" true.

**A callback is a channel, and a channel is a way to leak.** An outbound request
carries timing, existence and whatever fields drift into it over the next two
years. The absence of the code path is a stronger guarantee than a review of what
the code path currently sends.

**Split listeners, because readiness is not public.** A single public `/readyz`
would tell a passer-by how much storage a workspace uses, whether access-set
enforcement is on, and whether the build is behind a security release. Each is a
gift to somebody choosing a target.

## Consequences

- Fleet monitoring is a polling job with network reach to the observability
  listener. Reaching a relay on a private network is the operator's problem, and
  is the honest consequence of a design where we cannot reach it either.
- An unreachable relay is indistinguishable from a relay that is down. There is
  no "last seen" telemetry to fall back on.
- Version-behind notices are the relay reading a release feed on a timer, which
  `WEALD_RELAY_RELEASE_CHECK=off` disables outright, and never us reading the
  relay. Readiness reports the check as disabled rather than as current, because
  "unknown" and "up to date" are different answers.
- Nothing in the relay's configuration surface can be pointed at us, which is
  checkable by grep rather than by trust.
