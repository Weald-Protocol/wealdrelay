# ADR-0001: One workspace is one project

- Status: accepted
- Date: 2026-06
- Source: `specs/backend/relay/multi-workspace.md`

## Context

A vocabulary question that decides a schema. Every collaboration product
eventually grows a container above the project or a scoped sub-project below it,
and each of those is a permission surface.

## Decision

One workspace is one project. A workspace owns one `.weald` directory, one
roster, one recovery phrase and one relay instance. There is no container above
a project and no scoped sub-project below one. "Workspace" and "project" name
the same object seen from the protocol side and the developer's side.

A team with three projects runs three workspaces, three instances and three
subscriptions.

## Consequences

- One relay instance per workspace. Not multi-tenant.
- Tenant isolation is enforced by the absence of keys rather than by our query
  scoping. A cross-tenant bug leaks ciphertext to someone who cannot read it.
- The smallest paid tier must cover a container plus a dedicated Postgres, which
  is why there is no free hosted tier.
- An agency or multi-project company is the normal shape rather than an edge
  case, so the dashboard lists instances by project name and checkout expects
  repeat purchases from the same account.

## Rejected

A shared multi-tenant relay. Cheaper, and the obvious thing to build. Rejected
because tenant isolation would then be a claim about our code, and "we correctly
scope every query by tenant id" is exactly the class of claim this product
exists to avoid making.
