-- Text compaction: checkpoints, the envelopes a checkpoint anchors, and the
-- record of every drop the relay has performed.
--
-- specs/backend/relay/lifecycle.md. The relay "never drops an envelope on its own
-- initiative, never expires by policy, and has no retention configuration that
-- acts without a signed instruction", so nothing here is a schedule. It is the
-- state a signed `drop_before` is checked against and the log of what one did.

-- One accepted checkpoint. The anchor a group's history is verified from once the
-- envelopes beneath it are gone, so it is never itself dropped.
create table if not exists relay_checkpoint (
    group_id       bytea       not null references relay_group (group_id) on delete restrict,
    -- The checkpoint's own manifest hash, which is the hash of the envelope
    -- carrying the `checkpoint` payload (wire.md, 0x0071).
    manifest_hash  bytea       not null,
    -- Everything below this sequence number is what the instruction proposes to
    -- drop. Advisory numbering like every other seq in this schema.
    barrier_seq    bigint      not null,
    -- The retention epoch whose verifier signed the instruction that landed it.
    epoch          bigint      not null,
    created_at     timestamptz not null default now(),
    primary key (group_id, manifest_hash),
    constraint relay_checkpoint_hash_is_32_bytes check (octet_length(manifest_hash) = 32),
    constraint relay_checkpoint_barrier_positive check (barrier_seq >= 1)
);

-- The envelopes a checkpoint names: its own manifest and every snapshot it lists.
-- Kept forever, by `lifecycle::drop_before` and by the media collectors alike,
-- because a checkpoint whose snapshots were collected is a group whose history
-- verifies from nothing at all.
create table if not exists relay_checkpoint_anchor (
    group_id      bytea not null,
    manifest_hash bytea not null,
    hash          bytea not null,
    primary key (group_id, manifest_hash, hash),
    constraint relay_checkpoint_anchor_hash_is_32_bytes check (octet_length(hash) = 32),
    foreign key (group_id, manifest_hash)
        references relay_checkpoint (group_id, manifest_hash) on delete cascade
);

-- Read on every drop, to decide which envelopes below the barrier survive it.
create index if not exists relay_checkpoint_anchor_group_hash_idx
    on relay_checkpoint_anchor (group_id, hash);

-- What each accepted instruction actually did. The artifact half of step 10's
-- gate: a compaction with no before-and-after is a claim rather than a number.
create table if not exists relay_drop_run (
    id             bigserial   primary key,
    group_id       bytea       not null,
    manifest_hash  bytea       not null,
    barrier_seq    bigint      not null,
    deleted_count  bigint      not null,
    deleted_bytes  bigint      not null,
    kept_count     bigint      not null,
    ran_at         timestamptz not null default now(),
    constraint relay_drop_run_counts_not_negative
        check (deleted_count >= 0 and deleted_bytes >= 0 and kept_count >= 0)
);

create index if not exists relay_drop_run_group_idx on relay_drop_run (group_id, ran_at desc);
