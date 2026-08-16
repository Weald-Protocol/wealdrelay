-- The restore marker: the one row that stops the storage-listing sweep after a
-- database has been rolled back to an earlier point.
--
-- The sweep in `media::gc::sweep_unreferenced_storage` decides that an object is
-- garbage by asking this database for a reservation row. Restore the database to
-- an earlier point, which is the entire purpose of the twice-daily backup cadence
-- in `specs/backend/cloud/backup-dr.md`, and every blob uploaded after that point
-- has no row: the recovery mechanism and the janitor would then combine into
-- permanent data loss on a bucket with no versioning and no object lock.
--
-- One row, enforced by the primary key rather than by convention: `id` is a
-- boolean checked true, so a second marker is a key conflict instead of two
-- disagreeing answers to "is the sweep suppressed". Whoever completes a restore
-- writes it, and the sweep counts it down and clears it.
--
-- It lives in the relay's own database rather than in a file because a relay has
-- no durable local disk in the hosted shape, and it is written after the restore
-- rather than before, so a restore never rolls its own marker away.

create table if not exists relay_gc_restore_marker (
    id boolean primary key default true check (id),
    set_at timestamptz not null default now(),
    passes_remaining integer not null check (passes_remaining >= 0),
    reason text not null default ''
);
