-- Pin the candidate the issuer sealed into the invite record, so a refresh flood
-- cannot evict it. WEALD-338.
--
-- `relay_invite_bundle` retained the newest `RETAINED_BUNDLES` rows per
-- `(token, group_id)` and nothing else, and `refresh_bundle` cannot verify group
-- membership or ciphertext validity: it accepts any bounded non-empty seal from any
-- admitted workspace principal. So the retention rule as written did not do the job
-- its own comment claimed. One valid candidate plus three bogus uploads at three
-- distinct epochs left exactly the three bogus rows, the invitee rejected every
-- retained candidate as MLS-invalid, and an insider denied every outstanding invite
-- without revoking one.
--
-- The fix is a lineage the relay can authenticate indirectly. The candidate carried
-- in the signed invite record is known-good by construction: it arrived inside a
-- record the issuer signed, over the authenticated issue path, not over the
-- unverifiable refresh path. Marking it and excluding it from pruning means the
-- worst a refresh flood achieves is that the joiner falls back to the seal it would
-- have received had nobody refreshed at all, which is the parked-join case the
-- freshness rule exists to improve on and never worse than it.
--
-- The bound stays bounded: `RETAINED_BUNDLES` unpinned rows plus exactly one pinned
-- row per scope, because the issue path inserts one row per scope inside the same
-- transaction that inserts the record and is never re-run for a token.
alter table relay_invite_bundle
    add column if not exists issued boolean not null default false;

-- Backfill. An existing row carries no marker, but the issue path runs once and
-- before any refresh, so the earliest upload per `(token, group_id)` is the issued
-- candidate. Ties cannot occur across the two paths: a refresh is a later
-- statement on a later connection, and within the issue transaction there is one
-- row per scope.
update relay_invite_bundle b
set issued = true
where b.uploaded_at = (
    select min(o.uploaded_at) from relay_invite_bundle o
    where o.token = b.token and o.group_id = b.group_id);

-- Serving reads by `(token, group_id)` and pruning now filters on `issued`, so the
-- recency index gets the flag.
create index if not exists relay_invite_bundle_unpinned_idx
    on relay_invite_bundle (token, group_id, uploaded_at desc) where issued = false;
