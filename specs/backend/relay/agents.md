# Relay: how agents actually connect

`specs/backend/relay/identity.md` says an agent is a principal with its own
keypair and an MLS leaf. It does not say what software holds that leaf, and the
answer decides how much MLS integration work exists
(`specs/backend/relay/mls-binding.md`), how many copies of the group secrets are
on a developer's disk, and what happens when a Claude Code session is killed with
control-C.

## Decision: agents proxy through the local Weald app

An agent does not speak the relay wire protocol, does not hold MLS state, and
does not open a socket. It talks to the local Weald app over the existing MCP
and HTTP server (`Sources/MCP/`), and the app performs every cryptographic
operation on its behalf.

The rejected alternative was giving each agent process its own MLS stack, which
would have meant shipping the Rust FFI layer into every agent runtime, and would
have put a full copy of every epoch secret in the scope of every agent process on
disk. A leaked agent key would then have been a leaked key **and** a leaked key
store.

What this preserves, which is the whole point of agent identity: the agent still
has its own keypair, and it still signs its own payloads. The app holds the MLS
state and performs the encryption, but the signature inside the envelope is made
by the agent's key, over content the agent produced. Attribution is unchanged.
Every line an agent writes is still attributable to that agent and to the human
who delegated it.

## Key custody

- The agent's private key lives in the Keychain, in an item owned by the Weald
  app, tagged with the agent id and the workspace.
- The agent process never sees it. Signing is a local call: the agent hands the
  app a payload, the app signs with the agent's key after checking the
  certificate permits that capability, and returns the result.
- Consequence worth naming: a compromised agent process cannot exfiltrate its
  own key, only use it, and only while the app is running and the certificate is
  valid. That is a materially better story than a key file in a dotfile
  directory, and it is the reason for the whole arrangement.

## Session lifecycle

1. **First run.** An agent connecting to the MCP server with no certificate
   triggers a single prompt in the app naming the agent, the workspace it is
   asking for and so the project, the scopes
   and the capabilities requested, and the read scope those grant
   (`specs/backend/relay/identity.md`). The human approves once.
2. **Certificate issued** by the human's device, default 24 hours interactive,
   7 days for a long-running bot.
   In the same user-approved operation, the app adds the agent leaf only to the
   certificate's named groups. Agents never self-join `everyone` or `parent`
   groups: those policies derive human device membership, not agent authority
   (`specs/backend/relay/channels.md`).
3. **Renewal is silent** within the same scope. Re-prompting a developer every
   morning trains them to click through, which is worse than the risk it
   pretends to manage.
4. **Widening scope always prompts.** An agent asking for a channel, or for a
   workspace, it was not granted is a new decision, not a renewal. Crossing into
   another project is always crossing into another workspace
   (`specs/backend/relay/multi-workspace.md`), so it can never happen silently.
5. **Expiry evicts the leaf**, per the epoch steward pass in
   `specs/backend/relay/identity.md`. An agent whose certificate lapsed mid-task
   gets a clean error and a re-prompt, not a silent write failure.

## Offline and app-not-running

An agent that starts while the Weald app is closed gets a clear failure naming
the app, and the app is launched if the user has allowed that. Queuing writes
from an agent without a live certificate check is refused: an offline write
queue that later replays under a certificate that has since been revoked is
exactly the hole the expiry rules exist to close.

The app itself being offline from the relay is different and is fine. Writes go
to local state and sync when the connection returns, which is the normal CRDT
path and needs nothing special for agents.

## What an agent may never do

Enforced at the MCP boundary as well as at certificate issuance, because defence
in depth here is cheap:

- Hold `admin`, `admit` or `roster.revoke`, per
  `specs/backend/relay/identity.md`.
- Issue a certificate that outlives or widens its own.
- Read a group outside its scopes, which is enforced by the app simply not
  decrypting for it.
- Reach a project bound to a different workspace
  (`specs/backend/relay/multi-workspace.md`).
- Send workspace content to a model provider without that provider appearing in
  the agent context disclosure required by
  `specs/backend/relay/verification.md`. This is the largest real hole in the
  encryption story and the app is the only component positioned to report it
  honestly, because it is the component the content passes through.

## Rate and cost

Agents write far more than humans, and the limit that contains that is enforced
in the app rather than at the relay. Say which is which, because an earlier
version of this section claimed relay enforcement that is not possible: the relay
authenticates a device key on the connection and the author of an envelope is
inside the ciphertext, so the relay cannot attribute a write to an agent and
cannot meter one. The per-connection limit in `specs/backend/relay/wire.md` is
therefore a ceiling on the app, not on any agent inside it.

The app holds every agent's key and performs every signature, so it is the only
component that can meter per agent, and it does: a per-agent envelope budget
enforced at the MCP boundary before signing, defaulting to a share of the
connection limit and adjustable per agent. One runaway agent hits its own budget
and returns a clean error to its caller rather than consuming the human's
throughput. The agent panel shows per-agent write volume against that budget,
which is also the cheapest early warning that a loop is stuck.

The honest bound: this is app-side accounting, so it constrains agents that go
through the app, which is all of them by construction
(`specs/backend/relay/agents.md` is the only sanctioned path and agents hold no
MLS state). A compromised app is outside it, and a compromised app already holds
plaintext.
