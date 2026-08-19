-- Handshake bytes count against the same per-workspace log budget as envelopes.
--
-- `0010_envelope_budget.sql` sums `octet_length(ct)` over `relay_envelope` only,
-- so `relay_handshake` rows were counted by nothing: a workspace could fill the
-- relay's disk through `HANDSHAKE` while `used_bytes` read zero and the refusal
-- on the accept path never fired. The message body is the payload of that log in
-- exactly the way `ct` is the payload of the envelope log, so it belongs in the
-- same counter rather than in a second one nobody reads.
--
-- Statement-level with transition tables, and a floor at zero on the credit, for
-- the same reasons the envelope triggers give. `message` is immutable: the hash
-- of it is half the uniqueness key, so a statement that changed it would be a
-- different row and there is no update trigger to write.
create or replace function relay_handshake_budget_charge() returns trigger
language plpgsql as $$
begin
    insert into relay_log_budget (workspace_id, used_bytes)
    select g.workspace_id, sum(octet_length(n.message))::bigint
      from new_handshakes n
      join relay_group g on g.group_id = n.group_id
     group by g.workspace_id
    on conflict (workspace_id) do update
       set used_bytes = relay_log_budget.used_bytes + excluded.used_bytes,
           updated_at = now();
    return null;
end;
$$;

create or replace function relay_handshake_budget_credit() returns trigger
language plpgsql as $$
begin
    update relay_log_budget b
       set used_bytes = greatest(0, b.used_bytes - freed.bytes),
           updated_at = now()
      from (select g.workspace_id as workspace_id,
                   sum(octet_length(o.message))::bigint as bytes
              from old_handshakes o
              join relay_group g on g.group_id = o.group_id
             group by g.workspace_id) as freed
     where b.workspace_id = freed.workspace_id;
    return null;
end;
$$;

drop trigger if exists relay_handshake_budget_charge on relay_handshake;
create trigger relay_handshake_budget_charge
    after insert on relay_handshake
    referencing new table as new_handshakes
    for each statement execute function relay_handshake_budget_charge();

drop trigger if exists relay_handshake_budget_credit on relay_handshake;
create trigger relay_handshake_budget_credit
    after delete on relay_handshake
    referencing old table as old_handshakes
    for each statement execute function relay_handshake_budget_credit();

-- The backfill, so a relay that has been running since 0005 starts with a true
-- counter rather than one short by its whole handshake history. Envelope bytes
-- are already in the counter, so this adds rather than replaces.
insert into relay_log_budget (workspace_id, used_bytes)
select g.workspace_id, coalesce(sum(octet_length(h.message)), 0)::bigint
  from relay_group g
  left join relay_handshake h on h.group_id = g.group_id
 group by g.workspace_id
on conflict (workspace_id) do update
   set used_bytes = relay_log_budget.used_bytes + excluded.used_bytes,
       updated_at = now();
