-- The per-workspace byte budget on the envelope log.
--
-- `WEALD_RELAY_MAX_STORAGE_GB` bounds media and nothing else
-- (`relay_quota.stored_bytes` counts finalized blob bytes), and
-- `WEALD_RELAY_RETENTION_DAYS` is a warning threshold rather than a deletion.
-- So until this migration `relay_envelope` was counted by nothing and capped by
-- nothing, on the store that costs twenty times what R2 costs
-- (`specs/backend/cloud/instance-sizing.md`), and one workspace could fill a
-- relay's database while sitting inside every limit the relay enforced.
--
-- ## Why a counter and not a sum
--
-- The check runs on the accept path, which `specs/backend/relay/operations.md`
-- fixes as one indexed update plus one insert with no aggregate anywhere. A
-- `sum(octet_length(ct))` over a workspace's groups per `SEND` would replace that
-- with a scan whose cost grows with the log it is protecting, which is the one
-- shape a hot path must never have. A counter is O(1) per write, and the trigger
-- below is what keeps it honest.
--
-- ## Why a trigger and not an increment in `accept.rs`
--
-- Because accounting that lives in one caller drifts the moment a second caller
-- appears. Compaction already deletes envelopes from `lifecycle/store.rs`, and a
-- credit written there and nowhere else would be one refactor away from a
-- counter that only ever rises. A trigger cannot be bypassed by any statement
-- from any module, including ones written after this one, so the invariant
-- "`used_bytes` is the sum of `octet_length(ct)` over the workspace's envelopes"
-- is enforced by the database rather than by everybody remembering.
--
-- Statement-level with transition tables, not row-level: compaction deletes in
-- batches, and a per-row trigger would turn one `delete` of fifty thousand rows
-- into fifty thousand updates of the same counter row.
--
-- `ct` is immutable by construction. It is half the content address, and the
-- address is the primary key, so an `update` that changed it would be a
-- different row: there is deliberately no update trigger, because there is no
-- statement anywhere that could fire it.
create table if not exists relay_log_budget (
    workspace_id text primary key,
    -- The sum of octet_length(ct) over every envelope of every group this
    -- workspace owns. Maintained by the triggers below and by nothing else.
    used_bytes   bigint      not null default 0,
    updated_at   timestamptz not null default now()
);

-- Deliberately no `check (used_bytes >= 0)`. The decrement below floors at zero
-- rather than trusting the arithmetic, and a constraint here would convert a
-- hypothetical accounting slip into a failed compaction, which is the strictly
-- worse failure: a customer who cannot reclaim space is worse off than a counter
-- that reads low by a byte.

create or replace function relay_log_budget_charge() returns trigger
language plpgsql as $$
begin
    insert into relay_log_budget (workspace_id, used_bytes)
    select g.workspace_id, sum(octet_length(n.ct))::bigint
      from new_envelopes n
      join relay_group g on g.group_id = n.group_id
     group by g.workspace_id
    on conflict (workspace_id) do update
       set used_bytes = relay_log_budget.used_bytes + excluded.used_bytes,
           updated_at = now();
    return null;
end;
$$;

create or replace function relay_log_budget_credit() returns trigger
language plpgsql as $$
begin
    update relay_log_budget b
       set used_bytes = greatest(0, b.used_bytes - freed.bytes),
           updated_at = now()
      from (select g.workspace_id as workspace_id,
                   sum(octet_length(o.ct))::bigint as bytes
              from old_envelopes o
              join relay_group g on g.group_id = o.group_id
             group by g.workspace_id) as freed
     where b.workspace_id = freed.workspace_id;
    return null;
end;
$$;

drop trigger if exists relay_log_budget_charge on relay_envelope;
create trigger relay_log_budget_charge
    after insert on relay_envelope
    referencing new table as new_envelopes
    for each statement execute function relay_log_budget_charge();

drop trigger if exists relay_log_budget_credit on relay_envelope;
create trigger relay_log_budget_credit
    after delete on relay_envelope
    referencing old table as old_envelopes
    for each statement execute function relay_log_budget_credit();

-- The backfill, so a relay that has been running since 0001 starts with a true
-- counter rather than with zero and a budget it can overshoot by its whole
-- history. One scan, once, inside the migration's own transaction.
insert into relay_log_budget (workspace_id, used_bytes)
select g.workspace_id, coalesce(sum(octet_length(e.ct)), 0)::bigint
  from relay_group g
  left join relay_envelope e on e.group_id = g.group_id
 group by g.workspace_id
on conflict (workspace_id) do update
   set used_bytes = excluded.used_bytes,
       updated_at = now();
