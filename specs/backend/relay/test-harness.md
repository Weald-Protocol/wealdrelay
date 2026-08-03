# Relay test harness

The relay harness proves behavior at the same boundaries customers operate:
real Postgres, a running relay, raw WebSockets, filesystem or MinIO storage,
and process lifecycle. It is not a mock wrapper around `src/`.

Use it for relay protocol, authorization, durability, reconciliation, and
availability regressions. Pure parsing and state decisions still belong in unit
or property tests. A release claim needs both when the behavior crosses a real
boundary.

## Entry points

```bash
scripts/weald-stack up          # Postgres, MinIO and Redis, on loopback
cargo test --workspace --locked
scripts/weald-stack down
```

`scripts/weald-stack status` says what is listening and whether it is ready, and
`scripts/weald-stack reset` drops the scratch databases a run killed with ctrl-c
leaves behind. Ports and credentials are fixed and public, in
`backend/compose/weald-stack.yml`, because every integration test hard-codes them:
a contract run that silently pointed at some other endpoint would prove nothing
about the deployment being built.

Weald's own development loop wraps these commands in a recorder that files each
run's output as gate evidence, in the private build repository. Nothing in the
tests depends on it; the commands above are the whole interface.

Start a material test cycle by reading the relevant wire contract, this document,
and the current diff.

## Harness contract

Use `backend/wealdrelay/tests/support/mod.rs` for every new relay integration
scenario. It provides:

- an isolated database per test (`Scratch`),
- a real `serve::run` relay bound to ephemeral listeners (`Running`),
- a fixed injectable relay clock (`Clock::Fixed`), and
- a raw WebSocket client (`Client`) with real masking, framing, and close
  behavior.

Use stable fixture bodies and name the count in the test. Do not use sleeps,
shared database names, shared ports, ambient time, or unseeded randomness. Test
cleanup must shut the relay down and drop its scratch database.

## Required test shape

1. Name the violated invariant and source contract in the test comment.
2. Build the minimized counterexample with fixed fixture data.
3. Drive the public wire path through `Client`, not a private function.
4. Assert the customer-visible result and the persisted result. For a refusal,
   assert its exact error frame and that no prohibited database row exists.
5. Add the companion tier:
   - parser or state invariant: unit plus property test;
   - protocol rejection: adversarial socket test;
   - storage/database/process boundary: real integration or crash proof;
   - customer flow: end-to-end scenario.

## Reconciliation and subscription scenarios

`RECON` sends `PUSH` frames before the reply. `SUB` sends `SUB_ACK` before its
backfill. A scenario must consume frames in that order.

The per-connection queue is `SEND_QUEUE_BOUND` (256). Any scenario that creates
a historical response larger than that must prove the client converges through
bounded continuation, not a connection close. The minimized regression fixture
is 257 envelopes:

- a new client with no items reconciles all 257 envelopes;
- a new client subscribes from cursor zero, receives a bounded backfill, then
  reconciles the remainder;
- the final local id set equals the relay's persisted set.

The reusable cases live in `backend/wealdrelay/tests/reconcile.rs`:

- `a_client_missing_more_than_the_send_queue_converges_without_disconnect`
- `a_subscription_larger_than_the_send_queue_can_finish_by_reconciliation`

## Running and recording proof

Start the local stack before a real-boundary run:

```bash
scripts/weald-stack up --budget 120
cargo test --package wealdrelay --test reconcile \
  a_client_missing_more_than_the_send_queue_converges_without_disconnect
cargo test --package wealdrelay --test reconcile \
  a_subscription_larger_than_the_send_queue_can_finish_by_reconciliation
```

Record the fixture count, the fixed clock, the command and the result alongside
the change. A scenario that changes access-set admission or any workspace-scoped
`SEND`, `SUB` or `RECON` path also needs the access suites
(`cargo test --package wealdrelay --test access_socket`), because those paths share
an admission decision and a regression in it shows up there first.

## Blocked environments

If `scripts/weald-stack up` reports that Docker or OrbStack is unavailable,
record the integration tier as blocked. A successful compile, unit test, or mock
does not substitute for the required real Postgres/socket proof.
