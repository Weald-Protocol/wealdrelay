-- MLS handshake messages: what the relay stores and forwards, unread.
--
-- specs/backend/relay/groups.md: "The relay stores and forwards key packages and
-- Welcomes. It cannot derive a group secret from either." The same is true of the
-- commits and proposals that move a group between epochs, and those have to reach
-- every member or the group forks.
--
-- They cannot travel as envelopes, and that is not a design preference. An
-- envelope's `ct` under `enc: 1` is an encrypted `Payload` (wire.md), and an MLS
-- handshake message is not one: it is the object that establishes the key an
-- envelope is encrypted under. Carrying commits as `enc: 0` envelopes would make
-- every group's log a mix of ciphertext and plaintext-framed control records, and
-- would make "every stored envelope is encrypted" false on a relay that is behaving
-- perfectly. So handshake messages have a frame and a table of their own, and the
-- envelope log stays exactly what it claims to be.
--
-- What the relay learns from this table is what it already learns from the envelope
-- log: that a group exists, that it is being used, and how large the messages are.
-- It cannot read one, and there is no column here that would help it try.
create table if not exists relay_handshake (
    group_id   bytea    not null references relay_group (group_id) on delete cascade,
    -- Per-group, dense, assigned by the relay. Handshake messages are order
    -- dependent in a way envelopes are not: a commit for epoch N+1 applied before
    -- the commit for epoch N is not a message out of order, it is a message that
    -- cannot be processed at all. So this is a real sequence and not the advisory
    -- cursor `relay_envelope.seq` is.
    seq        bigint   not null,
    -- The MLS message, opaque. One `MlsMessageOut`, as the committing client
    -- serialised it.
    message    bytea    not null,
    -- BLAKE3 of `message`. Deduplicates a resend after a dropped connection, which
    -- is the same promise `SEND` makes: a client that retries is always safe.
    hash       bytea    not null,
    created_at timestamptz not null default now(),
    primary key (group_id, seq),
    constraint relay_handshake_group_is_32_bytes check (octet_length(group_id) = 32),
    constraint relay_handshake_seq_not_negative check (seq >= 0),
    constraint relay_handshake_hash_is_32_bytes check (octet_length(hash) = 32),
    constraint relay_handshake_message_is_not_empty check (octet_length(message) > 0)
);

-- A resend lands on this rather than taking a second sequence number.
create unique index if not exists relay_handshake_hash_unique
    on relay_handshake (group_id, hash);
