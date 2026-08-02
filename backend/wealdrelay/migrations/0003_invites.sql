-- Invites, one-time codes, reservations, and the genesis key.
--
-- specs/backend/relay/invites.md. The shape of these tables is the shape of the
-- claim: the relay holds a token, a public encryption key, an Argon2id hash of a
-- code it never sees, and ciphertext it cannot open. There is no column here for
-- an email address, a display name, a workspace name, or a plaintext code, and
-- there is nowhere for one to go.
--
-- On the hosted tier the same binary runs with `WEALD_RELAY_SMTP_URL` refused at
-- startup (src/profile.rs), so relay-sent invite mail is a configuration the
-- hosted deployment cannot hold rather than a branch this schema knows about.

-- The redeemable record, byte for byte as the issuer signed it.
--
-- `body` is the whole canonical encoding including the signature, because an
-- invite is evidence: a client re-verifies the issuer signature over bytes the
-- relay served, and a relay that re-encoded from columns would be asking the
-- client to trust the relay's encoder instead of the issuer's signature.
create table if not exists relay_invite (
    -- 16 random bytes, the lookup key and the Argon2id salt for the code.
    token         bytea       primary key,
    workspace_id  text        not null references relay_workspace (workspace_id) on delete restrict,
    -- The workspace root group id the record declares. Held out of `body` as a
    -- column so the mandatory-root rule is checkable by a query and not only by
    -- a decode.
    workspace     bytea       not null,
    issuer        bytea       not null,
    -- Relay time, milliseconds. Every expiry the relay enforces is evaluated
    -- against its own clock; the issuer's `issued_at` inside `body` is carried
    -- and never trusted.
    expires_at    timestamptz not null,
    -- Seats. `uses` is what the issuer signed; `remaining` is what is left after
    -- live reservations, and is the only thing the reserve path decrements.
    uses          smallint    not null,
    remaining     smallint    not null,
    -- Argon2id of the 12-character code, salted with `token`. The relay can
    -- rate-limit attempts against this without ever learning the code.
    code_hash     bytea       not null,
    -- The public half of the URL secret. The private half is derived by the
    -- joiner from 32 bytes carried in a URL fragment that never reaches here,
    -- which is what lets any current member refresh a bundle without learning it.
    update_pub    bytea       not null,
    -- 'live', 'revoked' or 'spent'. A redeemed genesis invite is 'spent' and
    -- there is no transition back.
    state         text        not null default 'live',
    -- True for the empty-workspace bootstrap invite, the one record permitted to
    -- carry no scopes. Set by the relay when it writes its own genesis invite,
    -- never by a client.
    bootstrap     boolean     not null default false,
    body          bytea       not null,
    created_at    timestamptz not null default now(),
    constraint relay_invite_token_is_16_bytes check (octet_length(token) = 16),
    constraint relay_invite_workspace_is_32_bytes check (octet_length(workspace) = 32),
    constraint relay_invite_issuer_is_32_bytes check (octet_length(issuer) = 32),
    constraint relay_invite_code_hash_is_32_bytes check (octet_length(code_hash) = 32),
    constraint relay_invite_update_pub_is_32_bytes check (octet_length(update_pub) = 32),
    constraint relay_invite_state_known check (state in ('live', 'revoked', 'spent')),
    -- 64 seats per invite record (invites.md, "Rate limits"). Constrained here so
    -- the reader has no arm for a row the writer could not have made.
    constraint relay_invite_uses_in_range check (uses >= 1 and uses <= 64),
    constraint relay_invite_remaining_in_range check (remaining >= 0 and remaining <= uses)
);

create index if not exists relay_invite_live_idx
    on relay_invite (workspace_id, expires_at) where state = 'live';

-- The groups an invite admits to, in the order the record lists them.
create table if not exists relay_invite_scope (
    token    bytea    not null references relay_invite (token) on delete cascade,
    group_id bytea    not null,
    position smallint not null,
    primary key (token, group_id),
    constraint relay_invite_scope_group_is_32_bytes check (octet_length(group_id) = 32),
    constraint relay_invite_scope_position_not_negative check (position >= 0)
);

-- The sealed GroupInfo per scope, and its refreshes.
--
-- The newest three candidates per (token, group) are retained, because the relay
-- cannot verify group membership and therefore treats an update as an
-- availability hint rather than as truth: a bogus high-epoch upload must not be
-- able to mask the last valid one. The invitee accepts only an MLS-valid
-- GroupInfo for the invited group, so three candidates is enough for it to find
-- the real one and few enough to bound the write amplification.
create table if not exists relay_invite_bundle (
    token       bytea       not null references relay_invite (token) on delete cascade,
    group_id    bytea       not null,
    epoch       bigint      not null,
    -- Sealed to `update_pub`. Opaque here in the strong sense: no query in this
    -- codebase reads it except to serve it back.
    ct          bytea       not null,
    uploaded_at timestamptz not null default now(),
    primary key (token, group_id, epoch),
    constraint relay_invite_bundle_group_is_32_bytes check (octet_length(group_id) = 32),
    constraint relay_invite_bundle_epoch_not_negative check (epoch >= 0)
);

create index if not exists relay_invite_bundle_recent_idx
    on relay_invite_bundle (token, group_id, uploaded_at desc);

-- One seat, taken. The linearization point for `uses`.
--
-- A bounded pool rather than a single slot, because `uses` may exceed one: the
-- relay holds up to `uses` live reservations at once, each bound to its own nonce
-- and device hash. Capacity is returned on expiry, so an abandoned setup frees a
-- seat rather than burning one permanently.
create table if not exists relay_invite_reservation (
    token       bytea       not null references relay_invite (token) on delete cascade,
    join_nonce  bytea       not null,
    device_hash bytea       not null,
    expires_at  timestamptz not null,
    -- A reservation may be extended once, to the invite's own expiry, when the
    -- join is parked on a stale GroupInfo. Never twice, and never past the
    -- invite.
    extended    boolean     not null default false,
    -- Set when the final required scope commit lands. A consumed reservation has
    -- spent its seat and cannot be raced.
    consumed_at timestamptz,
    -- Set when the ten-minute window passed with no consumption, at which point
    -- the seat went back to `remaining`.
    released_at timestamptz,
    created_at  timestamptz not null default now(),
    primary key (token, join_nonce),
    constraint relay_invite_reservation_nonce_is_16_bytes check (octet_length(join_nonce) = 16),
    constraint relay_invite_reservation_hash_is_32_bytes check (octet_length(device_hash) = 32)
);

create index if not exists relay_invite_reservation_live_idx
    on relay_invite_reservation (token, expires_at)
    where consumed_at is null and released_at is null;

-- Which scopes a reservation has already committed into, so a duplicate retry
-- returns the original receipt instead of a second one.
create table if not exists relay_invite_scope_commit (
    token       bytea       not null,
    join_nonce  bytea       not null,
    group_id    bytea       not null,
    receipt     bytea       not null,
    committed_at timestamptz not null default now(),
    primary key (token, join_nonce, group_id),
    foreign key (token, join_nonce)
        references relay_invite_reservation (token, join_nonce) on delete cascade,
    constraint relay_invite_scope_commit_group_is_32_bytes check (octet_length(group_id) = 32),
    constraint relay_invite_scope_commit_receipt_is_32_bytes check (octet_length(receipt) = 32)
);

-- Failed code attempts, per token, source and device.
--
-- The tuple is the point. Five wrong attempts cool down that tuple for fifteen
-- minutes and nothing else: the invite is not burnt, and the other seats behind a
-- shared invite are untouched, so one person fat-fingering a code cannot lock out
-- the nine colleagues invited alongside them.
--
-- `source` is a salted hash and not an address. The relay notifies the issuer
-- about attempt volume and must not be able to name an IP while doing it.
create table if not exists relay_invite_attempt (
    token          bytea       not null references relay_invite (token) on delete cascade,
    source_hash    bytea       not null,
    device_hash    bytea       not null,
    failures       integer     not null default 0,
    window_started timestamptz not null default now(),
    cooldown_until timestamptz,
    primary key (token, source_hash, device_hash),
    constraint relay_invite_attempt_source_is_32_bytes check (octet_length(source_hash) = 32),
    constraint relay_invite_attempt_device_is_32_bytes check (octet_length(device_hash) = 32),
    constraint relay_invite_attempt_failures_not_negative check (failures >= 0)
);

-- What survives a revocation.
--
-- wire.md, "Provisional grants and how they end": revocation writes a durable,
-- opaque tombstone before the redeemable ciphertext is deleted, so an invite can
-- vanish from the admin's live list without deleting the state required to
-- enforce its revocation. It retains only what finding reservations and grants
-- needs: no link secret, no code, no code hash, no name, no scope ciphertext.
create table if not exists relay_invite_tombstone (
    token        bytea       primary key,
    workspace_id text        not null references relay_workspace (workspace_id) on delete restrict,
    -- 'revoked' or 'spent'.
    terminal     text        not null,
    expires_at   timestamptz not null,
    device_hashes bytea[]    not null default '{}',
    written_at   timestamptz not null default now(),
    constraint relay_invite_tombstone_token_is_16_bytes check (octet_length(token) = 16),
    constraint relay_invite_tombstone_terminal_known check (terminal in ('revoked', 'spent'))
);

-- The genesis key: one keypair, one signature, one death.
--
-- The private half is nullable and is set to null in the same transaction that
-- accepts the genesis access set. There is no configuration flag and no support
-- command that puts it back; reprovisioning means a new instance with a visibly
-- different workspace id.
create table if not exists relay_genesis (
    workspace_id text        primary key references relay_workspace (workspace_id) on delete restrict,
    public_key   bytea       not null,
    -- Null once redeemed. The column is the whole audit story, so it is not
    -- dropped and not overwritten with zeroes-as-bytes: null is unambiguous and a
    -- row of zeroes is a key someone has to reason about.
    secret_key   bytea,
    -- BLAKE3 of the public key, printed to stdout at first run and pinned by the
    -- enrolling client.
    fingerprint  bytea       not null,
    token        bytea       not null references relay_invite (token) on delete restrict,
    created_at   timestamptz not null default now(),
    redeemed_at  timestamptz,
    constraint relay_genesis_public_is_32_bytes check (octet_length(public_key) = 32),
    constraint relay_genesis_secret_is_32_bytes check (secret_key is null or octet_length(secret_key) = 32),
    constraint relay_genesis_fingerprint_is_32_bytes check (octet_length(fingerprint) = 32)
);

-- The membership transparency log, beginning at genesis.
--
-- invites.md corrects an earlier framing that recorded bootstrap consumption
-- "in the transparency log" as though a log already existed. It did not: the
-- trust root creates it. So the log begins with genesis, entry zero, and there is
-- no unlogged prefix. Every later client verifies that entry on first sync, which
-- is what makes "was this workspace founded by the device I think founded it" a
-- question with an answer forever.
create table if not exists relay_transparency_log (
    workspace_id text        not null references relay_workspace (workspace_id) on delete restrict,
    seq          bigint      not null,
    kind         text        not null,
    -- Canonical CBOR. For entry zero: the genesis public key, its fingerprint,
    -- and the trust root it admitted.
    body         bytea       not null,
    -- BLAKE3 over (prev_hash || body), so the log is a chain and not a list.
    prev_hash    bytea       not null,
    entry_hash   bytea       not null,
    recorded_at  timestamptz not null default now(),
    primary key (workspace_id, seq),
    constraint relay_transparency_log_seq_not_negative check (seq >= 0),
    constraint relay_transparency_log_prev_is_32_bytes check (octet_length(prev_hash) = 32),
    constraint relay_transparency_log_entry_is_32_bytes check (octet_length(entry_hash) = 32),
    constraint relay_transparency_log_kind_known check (kind in ('genesis', 'join', 'revoke'))
);
