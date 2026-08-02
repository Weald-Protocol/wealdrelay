-- Recovery wraps, indexed by a blinded per-epoch tag.
--
-- specs/backend/relay/groups.md, "Recovery access without a leaf in every group".
-- Exactly one recovery leaf exists per user, in the workspace root group. For
-- every other group the committer emits a `recovery.wrap` sealed to each entitled
-- recovery public key, and the relay stores the latest wrap per (group, tag).
--
-- The shape of this table is the shape of the claim, so read the columns as the
-- claim rather than as storage:
--
--   * There is no recovery public key column, and there is nowhere for one to go.
--     An earlier draft indexed by the key in the clear, which handed the relay a
--     stable per-user identifier appearing in every group that user belongs to,
--     and therefore the workspace's group-membership graph by a join. `tag` is
--     BLAKE3(export(weald wraptag v1) || recovery_pubkey), derived from the
--     group's own epoch secret, so it is unlinkable across groups and rotates
--     wholesale on every commit.
--   * `ct` is sealed to a key this crate does not hold and cannot derive. It
--     appears in one statement that writes it and one that serves it back.
--   * A tag is unique to one group. The primary key says so and
--     `relay_recovery_wrap_tag_is_not_shared` says so again across groups,
--     because a tag recurring in two groups is exactly the correlation handle the
--     blinding exists to refuse, and a constraint is a better place to refuse it
--     than a code path somebody can forget to call.
create table if not exists relay_recovery_wrap (
    group_id     bytea       not null references relay_group (group_id) on delete cascade,
    -- The blinded slot. 32 bytes, per epoch, per recovery principal.
    tag          bytea       not null,
    -- The epoch whose secret and GroupInfo this wrap carries. Monotonic per slot:
    -- a wrap may only be replaced by one at a strictly greater epoch, which is
    -- enforced in `recovery::store` rather than here because it is a comparison
    -- against the existing row.
    epoch        bigint      not null,
    -- Sealed { epoch_secret, group_info } to the recovery key. Opaque.
    ct           bytea       not null,
    updated_at   timestamptz not null default now(),
    primary key (group_id, tag),
    constraint relay_recovery_wrap_group_is_32_bytes check (octet_length(group_id) = 32),
    constraint relay_recovery_wrap_tag_is_32_bytes check (octet_length(tag) = 32),
    constraint relay_recovery_wrap_epoch_not_negative check (epoch >= 0),
    constraint relay_recovery_wrap_ct_is_not_empty check (octet_length(ct) > 0)
);

-- A tag belongs to one group, forever. Without this a client that derived a tag
-- from the wrong group's secret, or a relay that accepted a replayed wrap under
-- another group's id, would write the one row that makes the cross-group
-- correlation `prove-blind` checks for true. The unique index is the enforcement;
-- the primary key above only makes (group, tag) unique, which is weaker.
create unique index if not exists relay_recovery_wrap_tag_is_not_shared
    on relay_recovery_wrap (tag);

-- The superseded slot, retained for 30 days after activation.
--
-- groups.md: recovery tries the directory's candidate, current and fallback tags,
-- and "the relay retains the prior wrap slot for 30 days after activation; only
-- then may it discard it". That overlap is the availability guarantee for the
-- two-phase cross-group handoff, so the prior slot is a row here rather than a
-- row that was deleted. `expires_at` is relay time and is what the sweep reads.
create table if not exists relay_recovery_wrap_prior (
    group_id     bytea       not null references relay_group (group_id) on delete cascade,
    tag          bytea       not null,
    epoch        bigint      not null,
    ct           bytea       not null,
    superseded_at timestamptz not null default now(),
    expires_at   timestamptz not null,
    primary key (group_id, tag),
    constraint relay_recovery_wrap_prior_group_is_32_bytes check (octet_length(group_id) = 32),
    constraint relay_recovery_wrap_prior_tag_is_32_bytes check (octet_length(tag) = 32),
    constraint relay_recovery_wrap_prior_epoch_not_negative check (epoch >= 0),
    constraint relay_recovery_wrap_prior_ct_is_not_empty check (octet_length(ct) > 0)
);

-- The sweep reads this. Retention is a scan by time and nothing else, so the
-- index is on time and nothing else.
create index if not exists relay_recovery_wrap_prior_expiry
    on relay_recovery_wrap_prior (expires_at);
