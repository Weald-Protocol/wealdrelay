-- The relay's whole schema, from zero.
--
-- Four things, per specs/backend/relay/server.md: the envelope log, per-group
-- state, key packages, and quotas. Nothing here is derived from content, because
-- the relay cannot read content: there is no kind, no channel name, no author and
-- no timestamp the relay did not observe itself.
--
-- Column names are fixed here for the first time. No spec named them, and
-- specs/backend/build/testing.md asks for corrections to be recorded rather than
-- absorbed silently, so the step 3 evidence bundle carries the dump of this
-- schema as the record of that decision.

-- Groups exist before envelopes can be accepted into them: accept validates
-- "group exists" and answers denied/group_unknown otherwise
-- (specs/backend/contracts/registries/error-codes.md).
--
-- `next_seq` is the per-group counter the accept path advances with a single
-- UPDATE ... RETURNING inside the same transaction that inserts the envelope, so
-- the lock is per group and unrelated groups never contend
-- (specs/backend/relay/operations.md). It is deliberately not called `head`:
-- there is no relay-maintained head chain (specs/backend/relay/wire.md).
create table if not exists relay_group (
    -- The opaque 32 bytes from the envelope header. Opaque to the relay by
    -- construction: it is derived client-side and means nothing here.
    group_id      bytea       primary key,
    -- Which workspace the group belongs to, for quota accounting. Also opaque.
    workspace_id  text        not null,
    -- The next sequence number to hand out. Advisory: a sync cursor only.
    next_seq      bigint      not null default 1,
    -- Relay-observed, never client-supplied. Every expiry in the system is
    -- evaluated against the relay's own clock.
    created_at    timestamptz not null default now(),
    -- Set when a retention control chain is contested, which /readyz reports as a
    -- frozen group (specs/backend/relay/media.md).
    frozen_reason text,
    constraint relay_group_id_is_32_bytes check (octet_length(group_id) = 32),
    constraint relay_group_next_seq_positive check (next_seq >= 1)
);

create index if not exists relay_group_workspace_idx on relay_group (workspace_id);
-- Partial, because the frozen set is normally empty and /readyz reads it on every
-- poll.
create index if not exists relay_group_frozen_idx
    on relay_group (group_id) where frozen_reason is not null;

-- The envelope log. Exactly the eight header fields plus `ct`, and nothing else.
create table if not exists relay_envelope (
    group_id  bytea    not null references relay_group (group_id) on delete restrict,
    -- BLAKE3(v, enc, group, epoch, ct). The content address, recomputed on accept.
    -- Primary key with the group rather than alone: hashes are never deduplicated
    -- across groups, for the same reason blob keys are not
    -- (specs/backend/relay/media.md).
    hash      bytea    not null,
    v         smallint not null,
    -- 0 = signed plaintext, 1 = MLS. Read and enforced against
    -- WEALD_RELAY_MIN_ENC, so it is stored and queryable rather than validated and
    -- discarded (specs/backend/relay/wire.md).
    enc       smallint not null,
    epoch     bigint   not null,
    -- Relay-assigned on accept. Advisory. Gaps are legal: a rolled-back
    -- transaction leaves one and clients tolerate it.
    seq       bigint   not null,
    -- Relay receipt time in milliseconds. Advisory, and the relay's own clock.
    ts        bigint   not null,
    -- The opaque payload. C3 in the data classification: readable by nobody
    -- without a client key.
    ct        bytea    not null,
    primary key (group_id, hash),
    constraint relay_envelope_hash_is_32_bytes check (octet_length(hash) = 32),
    constraint relay_envelope_version_known check (v = 1),
    constraint relay_envelope_enc_known check (enc in (0, 1)),
    -- 1 MiB, the ceiling reject/envelope_too_large carries
    -- (specs/backend/relay/wire.md).
    constraint relay_envelope_ct_within_limit check (octet_length(ct) <= 1048576),
    constraint relay_envelope_seq_positive check (seq >= 1)
);

-- The reconciliation cursor: give me everything in this group after this seq.
create unique index if not exists relay_envelope_group_seq_idx
    on relay_envelope (group_id, seq);

-- MLS key packages. Public by design: a key package is encrypted to nothing, and
-- the relay stores and forwards them without being able to derive a group secret
-- (specs/backend/relay/groups.md).
create table if not exists relay_key_package (
    id           bigserial   primary key,
    workspace_id text        not null,
    -- The salted hash of the device key, which is what the relay holds rather than
    -- the key itself (specs/backend/relay/wire.md).
    device_hash  bytea       not null,
    package      bytea       not null,
    created_at   timestamptz not null default now(),
    -- Consumed on use, so an add cannot reuse one.
    consumed_at  timestamptz,
    -- 90 days from creation; an expired package is refused for adds
    -- (specs/backend/relay/operations.md).
    expires_at   timestamptz not null,
    constraint relay_key_package_device_hash_is_32_bytes check (octet_length(device_hash) = 32),
    constraint relay_key_package_expiry_after_creation check (expires_at > created_at)
);

-- The relay reports the connecting device's own unused count on AUTH, and a
-- device is capped at 100 outstanding, so this lookup is on the hot path.
create index if not exists relay_key_package_unused_idx
    on relay_key_package (workspace_id, device_hash)
    where consumed_at is null;

-- Storage accounting, per workspace. Reservations are taken before a presigned
-- upload URL is issued, so the relay never accepts an upload it will later delete
-- (specs/backend/relay/media.md).
create table if not exists relay_quota (
    workspace_id  text        primary key,
    -- Bytes actually stored, moved here only when an upload is finalized.
    stored_bytes  bigint      not null default 0,
    -- Bytes promised to uploads in flight. Released when a reservation expires or
    -- is aborted.
    reserved_bytes bigint     not null default 0,
    -- Null is unlimited, matching WEALD_RELAY_MAX_STORAGE_GB's default.
    limit_bytes   bigint,
    updated_at    timestamptz not null default now(),
    constraint relay_quota_stored_not_negative check (stored_bytes >= 0),
    constraint relay_quota_reserved_not_negative check (reserved_bytes >= 0)
);

-- One reservation per in-flight upload. Separate from relay_quota so an expired
-- reservation can be released by the cleanup job without touching the workspace
-- row's stored total.
create table if not exists relay_blob_reservation (
    reservation_id uuid        primary key,
    workspace_id   text        not null references relay_quota (workspace_id) on delete cascade,
    group_id       bytea       not null,
    -- The ciphertext hash the upload is for. The object key is
    -- workspace/group/ciphertext-hash and is never deduplicated across groups.
    blob_hash      bytea       not null,
    bytes          bigint      not null,
    created_at     timestamptz not null default now(),
    expires_at     timestamptz not null,
    finalized_at   timestamptz,
    constraint relay_blob_reservation_bytes_positive check (bytes > 0),
    -- 2 GiB, the blob ceiling (specs/backend/relay/wire.md).
    constraint relay_blob_reservation_within_blob_limit check (bytes <= 2147483648)
);

create unique index if not exists relay_blob_reservation_object_idx
    on relay_blob_reservation (workspace_id, group_id, blob_hash)
    where finalized_at is null;

create index if not exists relay_blob_reservation_expiry_idx
    on relay_blob_reservation (expires_at) where finalized_at is null;
