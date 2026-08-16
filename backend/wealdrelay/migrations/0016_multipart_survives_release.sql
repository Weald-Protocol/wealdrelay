-- An aborted multipart session has to outlive its reservation.
--
-- `specs/backend/relay/media.md` requires a session that was already aborted to
-- be answered with the same `MultipartAborted` the first abort gave. It could
-- not be. The abort marks `aborted_at`, deletes the parts and then releases the
-- reservation, and `relay_blob_multipart.reservation_id` cascaded on that
-- delete, so the row carrying `aborted_at` was destroyed by the same operation
-- that set it. The second abort then found nothing and answered
-- `MalformedHeader`, and the repeated-abort branch in `media::mod` had never
-- once executed.
--
-- The reservation is the thing that owns the quota and is right to disappear on
-- release. What must survive is the record that this session existed and how it
-- ended, which is what makes the answer idempotent. So the reference becomes
-- nullable and clears rather than cascading: the row stays, `reservation_id`
-- goes null, and `find_multipart` still declines to resolve it because that
-- join is an inner one and a released session has no quota left to reason
-- about.
--
-- Rows already orphaned by this bug are gone and cannot be recovered; there is
-- nothing to backfill, because the cascade left no trace of them.

alter table relay_blob_multipart
    drop constraint relay_blob_multipart_reservation_id_fkey;

alter table relay_blob_multipart
    alter column reservation_id drop not null;

alter table relay_blob_multipart
    add constraint relay_blob_multipart_reservation_id_fkey
    foreign key (reservation_id)
    references relay_blob_reservation (reservation_id)
    on delete set null;
