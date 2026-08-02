-- Media blobs: multipart sessions, and the retention control chain.
--
-- specs/backend/relay/media.md. `relay_quota` and `relay_blob_reservation`
-- already exist (migration 0001): a reservation is taken atomically before a
-- presigned upload URL is issued, and `relay_blob_reservation.finalized_at` is
-- repurposed here as exactly the moment the relay has independent confirmation an
-- object exists: the receipt time of the first valid retention manifest that
-- names it. That is deliberate and not a shortcut: `media.md` says policy
-- evaluation uses "its immutable receipt time for the blob's first accepted
-- manifest claim, not a client-supplied media timestamp", and re-using the column
-- the reservation already has means there is exactly one place a blob's lifecycle
-- clock is set.

-- Resumable multipart upload for blobs above 64 MiB. One session per reservation.
create table if not exists relay_blob_multipart (
    session_id     uuid        primary key,
    reservation_id uuid        not null references relay_blob_reservation (reservation_id) on delete cascade,
    -- The S3-side multipart upload id. Empty string for the filesystem backend,
    -- which assembles parts itself and has no such id.
    upload_id      text        not null default '',
    part_size      bigint      not null,
    created_at     timestamptz not null default now(),
    expires_at     timestamptz not null,
    completed_at   timestamptz,
    aborted_at     timestamptz,
    constraint relay_blob_multipart_part_size_positive check (part_size > 0)
);

create index if not exists relay_blob_multipart_expiry_idx
    on relay_blob_multipart (expires_at) where completed_at is null and aborted_at is null;

-- Part numbers are immutable once issued: `media.md` requires "part numbers,
-- expected ciphertext lengths and the reservation id are immutable". A second
-- request for the same part refreshes `issued_at`/`expected_len` in place rather
-- than creating a second row, which is what makes the 15-minute window
-- refreshable without changing which parts exist.
create table if not exists relay_blob_multipart_part (
    session_id   uuid        not null references relay_blob_multipart (session_id) on delete cascade,
    part_number  integer     not null,
    expected_len bigint      not null,
    issued_at    timestamptz not null default now(),
    -- Reported by the client at COMPLETE. Advisory: the relay's own accounting is
    -- the reservation's byte total, not the sum of client-reported part lengths.
    etag         text,
    primary key (session_id, part_number),
    constraint relay_blob_multipart_part_number_positive check (part_number >= 1),
    constraint relay_blob_multipart_part_len_positive check (expected_len > 0)
);

-- One control record per (group, epoch). The primary key is the first-writer-wins
-- rule from `media.md`'s successor-race section: the relay accepts at most one
-- `RetentionControl` for a given (group, epoch), so a second, differently signed
-- one cannot silently overwrite the first and has to go somewhere else, which is
-- `relay_retention_control_conflict` below.
create table if not exists relay_retention_control (
    group_id          bytea       not null references relay_group (group_id) on delete cascade,
    epoch             bigint      not null,
    verifier          bytea       not null,
    prev_control_hash bytea,
    sig               bytea       not null,
    signer_note       text        not null,
    received_at       timestamptz not null default now(),
    primary key (group_id, epoch),
    constraint relay_retention_control_epoch_not_negative check (epoch >= 0),
    constraint relay_retention_control_verifier_is_32_bytes check (octet_length(verifier) = 32)
);

-- The second, conflicting record for an (group, epoch) already settled. Stored as
-- evidence, never used to pick a winner: only a client-signed resolution clears
-- the freeze it causes.
create table if not exists relay_retention_control_conflict (
    id                bigserial   primary key,
    group_id          bytea       not null references relay_group (group_id) on delete cascade,
    epoch             bigint      not null,
    verifier          bytea       not null,
    prev_control_hash bytea,
    sig               bytea       not null,
    received_at       timestamptz not null default now()
);

create index if not exists relay_retention_control_conflict_group_idx
    on relay_retention_control_conflict (group_id, epoch);

-- Every accepted manifest, kept as a log so the sequence/prev-digest chain can be
-- verified against what came before it, not only against the latest row.
create table if not exists relay_retention_manifest (
    group_id          bytea       not null references relay_group (group_id) on delete cascade,
    sequence          bigint      not null,
    epoch             bigint      not null,
    prev_manifest_hash bytea,
    blobs             bytea[]     not null,
    sig               bytea       not null,
    digest            bytea       not null,
    received_at       timestamptz not null default now(),
    primary key (group_id, sequence),
    constraint relay_retention_manifest_sequence_positive check (sequence >= 1)
);

-- A manifest that failed verification. Retained as evidence per `media.md`
-- ("retained as evidence but never used for deletion"), never read by the
-- deletion path.
create table if not exists relay_retention_manifest_rejected (
    id          bigserial   primary key,
    group_id    bytea       not null references relay_group (group_id) on delete cascade,
    epoch       bigint,
    sequence    bigint,
    reason      text        not null,
    received_at timestamptz not null default now()
);

-- Retention policies: the smooth, repeatable path. `authorizers` and `signatures`
-- are stored so a later audit can see who authorized a widened or narrowed window
-- without the relay having interpreted anything content-derived: both are public
-- keys and signature bytes over the policy body.
create table if not exists relay_retention_policy (
    group_id        bytea       not null references relay_group (group_id) on delete cascade,
    version         bigint      not null,
    media_after_days integer    not null,
    text_after_days  integer    not null,
    not_before      timestamptz not null,
    authorizers     bytea[]     not null,
    signatures      jsonb       not null,
    created_at      timestamptz not null default now(),
    cancelled_at    timestamptz,
    primary key (group_id, version),
    constraint relay_retention_policy_version_positive check (version >= 1),
    constraint relay_retention_policy_media_after_floor check (media_after_days >= 30)
);

-- One-off destruction records. Idempotent on (group, kind, target_digest), as
-- `media.md` requires.
create table if not exists relay_retention_destruction (
    group_id       bytea       not null references relay_group (group_id) on delete cascade,
    kind           text        not null,
    target_digest  bytea       not null,
    policy_version bigint,
    not_before     timestamptz not null,
    authorizers    bytea[]     not null,
    signatures     jsonb       not null,
    created_at     timestamptz not null default now(),
    cancelled_at   timestamptz,
    executed_at    timestamptz,
    primary key (group_id, kind, target_digest)
);

-- The garbage collector's own run log, which is the artifact
-- `phases-relay.md` step 9 asks for: "the GC run log and the storage accounting
-- against the quota."
create table if not exists relay_gc_run (
    id             bigserial   primary key,
    started_at     timestamptz not null,
    finished_at    timestamptz not null,
    mechanism      text        not null,
    examined_count integer     not null default 0,
    deleted_count  integer     not null default 0,
    deleted_bytes  bigint      not null default 0,
    note           text
);
