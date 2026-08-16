-- Ciphertext columns: skip the compression attempt Postgres makes on every write.
--
-- Every column below holds output from an AEAD or an MLS primitive. Ciphertext is
-- indistinguishable from random to anything without the key, and pglz cannot compress
-- random bytes: it scans the value, fails to find a repeat worth encoding, gives up,
-- and writes the bytes out of line exactly as it would have anyway. The default
-- `extended` storage mode makes it do that on every single insert.
--
-- `external` keeps the out-of-line behaviour and drops the attempt. Nothing about
-- what is stored, read, or returned changes: TOAST is transparent to the query, the
-- column type is unchanged, and there is no data rewrite, because `set storage` is
-- catalogue-only and applies to rows written after it.
--
-- Why it is worth a migration on a relay rather than a footnote. The hosted tier
-- provisions `basic_256mb`, which is 0.1 vCPU, and
-- `specs/backend/cloud/instance-sizing.md` records that if that plan fails in
-- production it fails on CPU under sustained write load rather than on a cache miss.
-- `relay_envelope.ct` is capped at 1 MiB and is written once per message, ticket edit,
-- presence beat and control frame the workspace ever produces, so the compression
-- attempt is the largest avoidable per-write cost on the busiest table, paid on the
-- scarcest resource the instance has. The alternative to this migration is the
-- `basic_1gb` plan at $19.00 against $6.00.
--
-- Applied to the ciphertext and MLS columns only. The hashes, tags, signatures and
-- public keys beside them are tens of bytes, stay inline, never reach TOAST at all,
-- and would be untouched by this either way.

alter table relay_envelope alter column ct set storage external;

alter table relay_key_package alter column package set storage external;

alter table relay_recovery_wrap alter column ct set storage external;

alter table relay_recovery_wrap_prior alter column ct set storage external;

alter table relay_invite_bundle alter column ct set storage external;

alter table relay_handshake alter column message set storage external;
