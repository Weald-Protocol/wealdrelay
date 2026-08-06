-- Push wake: the one row a relay holds so it can ring a device that is asleep.
--
-- specs/backend/relay/push.md section 2. The relay never holds an APNs device
-- token, never receives one, and has no column here that could hold one. What it
-- holds is a handle: sixteen random bytes minted by the ringer to one device for
-- one workspace, opaque to the relay and meaningless to anybody who cannot resolve
-- it. The party that can resolve it is the ringer (specs/backend/relay/ringer.md),
-- and it is a separate component precisely so that this table cannot become a
-- device registry.
--
-- Keyed on `entry_hash` and not on the device key, for the reason
-- relay_key_package.device_hash is: the salt is relay_workspace.salt, minted once
-- per workspace and never rotated, so the same physical device in two workspaces
-- produces two unrelated rows. Cross-workspace unlinkability is therefore a
-- property of the key rather than an operational promise, and it is proved by a
-- property test rather than asserted here.
--
-- Three absences are load-bearing, and none of them is an omission. There is no
-- token column, no platform column and no topic column, because those belong to
-- the ringer's table and a relay that held them would be the thing this whole
-- design exists to avoid. There is no counter, no last-woken and no wake log,
-- because a per-handle history is a routing signal about one human's device and
-- nothing in the relay needs it. And there is no column derived from content: a
-- category is decided from a frame the relay can already see, and it is carried on
-- the wire to the ringer rather than stored.
create table if not exists relay_push_handle (
    workspace_id text     not null,
    -- The salted device hash from access/mod.rs, which is the only name the relay
    -- has for a principal. `on delete cascade` is deliberately absent: the access
    -- set is versioned rather than mutated, so there is no row whose deletion a
    -- foreign key could follow. The registration is removed by
    -- push::store::delete_for_entries, inside the same transaction that accepts the
    -- set that dropped the entry, because a principal who is no longer admitted must
    -- not keep a wake capability.
    entry_hash   bytea    not null,
    -- Sixteen bytes from the ringer. Unique across the table and not merely within
    -- the workspace: the unique index below is the only thing that stops one device
    -- claiming a handle another device already registered, which is the single way
    -- one device could steal another's wakes.
    handle       bytea    not null,
    -- The bitmask from push::Category: 1 message, 2 call, 4 handshake. At least one
    -- bit and no undefined bit, which is what the range check says: 0 would be a
    -- registration that admits nothing and is a client mistake rather than a
    -- posture, and 8 or above is a category this version does not have.
    categories   smallint not null,
    -- The ringer's stated expiry. Refused on the way in if it is already past, and
    -- swept afterwards, so a handle for a device that has been signed out for a
    -- month is not a capability anybody still holds.
    expires_at   timestamptz not null,
    updated_at   timestamptz not null default now(),
    -- One live registration per device per workspace, so re-registering replaces
    -- rather than accumulates. A device that rotated its handle weekly for a year
    -- holds one row, not fifty two.
    primary key (workspace_id, entry_hash),
    constraint relay_push_handle_entry_is_32_bytes check (octet_length(entry_hash) = 32),
    constraint relay_push_handle_handle_is_16_bytes check (octet_length(handle) = 16),
    constraint relay_push_handle_categories_in_range check (categories between 1 and 7)
);

-- A second principal cannot claim a handle that is already registered. Enforced by
-- the database rather than by a read-then-write in the relay, because two devices
-- registering the same handle in the same instant is exactly the interleaving a
-- check-then-insert loses.
create unique index if not exists relay_push_handle_handle_unique
    on relay_push_handle (handle);

-- The wake lookup, which is the only read on the hot path: given a group, find the
-- live registrations of the principals that group's workspace admits. The join is
-- against relay_access_entry on (workspace_id, entry_hash), so the leading column
-- here matches the leading column there, and `expires_at` is included so an expired
-- row is skipped in the index rather than fetched and discarded.
create index if not exists relay_push_handle_workspace_idx
    on relay_push_handle (workspace_id, expires_at);
