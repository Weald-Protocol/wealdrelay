# Relay: multiple workspaces in one client

> **Production credentials only.** `specs/backend/build/production-only.md` is a
> standing rule and it outranks this file. Production vendors only: the Clerk
> production instance, Stripe live mode, the production Render environment and
> Postgres, the production R2 bucket, the published relay digest. No dev tier,
> no test mode, no staging tier, and no agent creates one. `local` and `ci` are
> not an exception because they reach no vendor at all. A gate that cannot reach
> production configuration fails; it never degrades to a mock, a stub, a fake, a
> skip or a newly created dev or staging resource.

**One workspace is one project.** That is the load-bearing rule of the whole
programme and every other spec under `specs/backend/` assumes it. A workspace has
one relay, one roster, one recovery phrase, one device keypair, and exactly one
`.weald` directory on disk. There is no container above a project and no
sub-project below one.

Weald watches every project on a developer's machine, so a developer with six
relay-backed projects has six workspaces. That is the normal case, not the
contractor edge case, and it is why this spec exists.

## Model

**Workspace** is the top-level object in the client, and it is the project. It
owns a relay hostname, a device keypair, a roster, a recovery phrase, its
tickets and board state (carried by the workspace root group,
`specs/backend/relay/groups.md`), its channels, and the one local project
directory bound to it.

**A project binds to exactly one workspace, and a workspace holds exactly one
project.** A `.weald` directory carries a `workspace` field naming the workspace
id and the relay hostname it syncs to. Unbound projects stay on the git
transport, which is the existing behaviour and remains the default
(`specs/backend/relay/migration.md`).

Binding one project to two workspaces is not supported and is refused with an
explanation rather than half-working. Two teams that both need a project either
share the one workspace or keep it on git. Binding a second project into an
existing workspace is refused the same way: the answer is a second workspace,
which costs one provision and one recovery phrase and buys complete key
separation.

**Why one to one.** A single team with three projects gets three rosters and
three bills, which is more setup than a nested model would need. What it buys is
worth more at this posture: the read boundary is the same object as the billing
object and the same object as the sync unit, so "who can see this project" has a
single answer with no scoped sub-group to reason about, one project cannot leak
into another through a mis-set channel policy, and a compromised relay for one
customer is a compromised relay for one project. The cost is repeated setup and a
switcher, and both are UI problems rather than protocol ones.

**Workspace resolution is a scan-time value, never a render-time one.**
`WorkspaceID.resolve` reads `.weald/project.json` and, for a project with no
`workspace` key (the default), forks `git remote get-url origin`. That is a
process spawn per project, so no SwiftUI `body` may call it: the settings
switcher resolves every watched project's workspace off the main actor, keyed on
`AppState.projectsGeneration`, and the render path reads the resolved map. A
changed `origin` or a newly written `workspace` key therefore appears after the
next scan, which is the same cadence every other project fact follows.

## Key isolation

This is the part that has to be right, because getting it wrong means one
customer's contractor leaks another customer's key material.

- **One device keypair per workspace.** Never shared. A device is
  `<device, workspace>`, and the same laptop appears as unrelated public keys in
  two rosters, which is correct: those two customers should not be able to tell
  they are working with the same person by comparing keys.
- **Separate Keychain items**, separate access groups, separate MLS state
  stores, separate SQLite search index per workspace
  (`specs/backend/relay/search.md`).
- **No cross-workspace references.** A ticket in one workspace cannot link to a
  document in another, and paste across workspaces is content only, never a
  reference that would leak an identifier.
- **Agent certificates are workspace-scoped**, which is to say project-scoped,
  since those are the same boundary. An agent delegated in one workspace has no
  standing in another, and the MCP server refuses a request whose target project
  is bound elsewhere
  (`specs/backend/relay/agents.md`).

## Recovery phrases

Three workspaces means three phrases, and there is no honest way around that:
each phrase derives a recovery key admitted to one roster, and a shared phrase
across workspaces would mean one leak compromises all of them.

What the client does to keep it manageable:

- The setup screen for a second workspace names the situation explicitly. "This
  is a separate project, so it needs its own recovery phrase" beats a user
  wondering why they are being asked again and typing the first one from memory.
- A **recovery card** export produces one card per workspace, naming that
  workspace, its relay hostname and its phrase, generated on device, never
  synced, never stored, offered at the moment of creating a second workspace.
  Printing several at once is one action, so the ergonomics of the earlier
  one-sheet design survive.

  It is deliberately not one sheet listing every workspace, which is what this
  page previously specified. That sheet contradicted the reason the phrases are
  separate in the first place, stated three paragraphs above: a shared phrase is
  rejected because one leak would compromise every workspace, and a single piece
  of paper carrying all three phrases reintroduces precisely that, with the
  contractor case, three phrases belonging to three different customers, as the
  worst instance. Separate cards can be stored separately, handed to different
  people, or left with different clients. The convenience being traded away is
  one stapler.
- Password manager export offers a per-workspace entry named for the workspace,
  so the manager's own search finds it later.

## Switching

- A workspace switcher in the sidebar, showing sync state and any health warning
  per workspace (`specs/backend/relay/lifecycle.md`). Because a workspace is a
  project, this is the project switcher, not a second piece of navigation stacked
  on top of one.
- Opening a project switches the active workspace automatically, because the
  binding says which one it is. Nobody should have to pick a workspace to open a
  ticket.
- Notifications are grouped by workspace and name it, since "Sam commented" is
  ambiguous across three clients and the ambiguity is the kind that gets
  confidential replies sent to the wrong company.
- Chat, board and search default to the active workspace and never merge results
  across workspaces, even for the user's own convenience. A unified search box
  would be a pleasant feature and a data-separation incident waiting to happen.

## Resource cost

Each workspace holds its own MLS state, its own index, and its own connection.
At the stated posture that is a few megabytes and one socket per workspace,
which is fine for the five to ten workspaces a developer with that many
relay-backed projects has. The client warns above twenty and does not attempt to
support two hundred. A machine watching fifty git-transport projects is
unaffected: only bound projects hold relay state.

## Departure

Leaving a workspace, as opposed to being removed from one, is a local action:
unbind the project, delete the local index and MLS state, and forget the
recovery phrase. The client asks once whether to keep a read-only local archive
of what was already decrypted, because a contractor's own record of their work
is a legitimate thing to want and pretending otherwise just means people take
screenshots.

The workspace's admins see the departure as a normal removal, and everything in
`specs/backend/relay/lifecycle.md` applies from their side.
