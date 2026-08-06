-- The read path's index, and the envelope table's vacuum settings.
--
-- Two changes, both about the same table and both about a small instance.
--
-- ## The covering index
--
-- `log::items` reads `(seq, hash)` for one group ordered by `seq`, and
-- `log::backfill` reads the same shape after a cursor. The existing index is
-- `relay_envelope (group_id, seq)`, which orders the scan but does not carry
-- `hash`, so the planner visits the heap once per row or takes the
-- `(group_id, hash)` primary key and sorts. `src/log.rs` carried that correction
-- as a comment; this is the fix it pointed at.
--
-- `include (hash)` rather than a four-column key: `hash` is payload here, never
-- a predicate and never an ordering term, and putting it in the key would widen
-- every internal page for nothing.
--
-- The cost this removes is not one read. Reconciliation runs this query on every
-- round, several times per reconnecting client, so a relay restart turns it into
-- a herd against a pool of eight connections.
create unique index if not exists relay_envelope_group_seq_hash_idx
    on relay_envelope (group_id, seq) include (hash);

-- The old index is a strict prefix of the new one with nothing extra, so keeping
-- it would mean a second B-tree maintained on every insert and read by nothing.
drop index if exists relay_envelope_group_seq_idx;

-- ## Vacuum
--
-- The envelope log is append-mostly, and its deletes do not trickle: retention
-- GC and compaction remove expired envelopes in batches
-- (`specs/backend/relay/lifecycle.md`). Postgres' defaults are proportional
-- (twenty percent of the table for a vacuum, ten for an analyze), so on a table
-- of a million rows the first vacuum after a GC run waits for two hundred
-- thousand dead tuples. On a 256 MB instance that is the bloat arriving before
-- the reclaim does.
--
-- A scale factor of zero with a flat threshold makes the trigger absolute
-- instead: vacuum after five thousand dead tuples however large the table has
-- grown, analyze after two thousand changes so the planner's row estimate for a
-- group tracks a log that only grows.
alter table relay_envelope set (
    autovacuum_vacuum_scale_factor = 0,
    autovacuum_vacuum_threshold = 5000,
    autovacuum_analyze_scale_factor = 0,
    autovacuum_analyze_threshold = 2000,
    -- The default cost delay yields after a fixed budget of page work, which on
    -- a batch delete means the vacuum is still running when the next batch
    -- lands. Two milliseconds is Postgres 12's own default and is what the
    -- provider's older tuning may not have.
    autovacuum_vacuum_cost_delay = 2
);
