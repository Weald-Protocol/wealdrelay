-- The sealed bootstrap handoff.
--
-- `specs/backend/relay/server.md`. On the hosted tier the relay seals both halves
-- of its bootstrap invite to a short-lived X25519 public key the control plane
-- generated for this one instance, and prints neither half. This table is what it
-- keeps: two ciphertexts and a fingerprint, and no plaintext of either half.
--
-- Ciphertext columns are text rather than bytea because they are served as base64
-- and the relay never operates on the bytes. Storing the encoded form is storing
-- exactly what is served, which removes an encode step from the read path and a
-- class of "which encoding" bug from the wire.
--
-- One row per workspace, keyed the same way `relay_genesis` is, because a relay
-- serves one workspace and a second row would be a second bootstrap.
create table if not exists relay_bootstrap_handoff (
    workspace_id        text        primary key references relay_genesis (workspace_id) on delete cascade,
    -- base64(ephemeral_public_key(32) || AES-256-GCM ciphertext || tag(16)) over
    -- the enrollment URL. Openable only by the holder of the handoff private key,
    -- which lives in the control plane and is destroyed on first claim.
    blob                text        not null,
    -- The same construction over the 12 Crockford symbols in grouped form. A row
    -- without it is refused by the control plane rather than served, because a
    -- workspace whose code was never sealed is one nobody can ever enroll into.
    sealed_code         text        not null,
    -- Lower-case hex of BLAKE3 of the genesis public key. Not a secret, and here
    -- rather than joined from `relay_genesis` so one read answers about one key:
    -- two reads would be two chances to answer about two different keys.
    genesis_fingerprint text        not null,
    -- The bootstrap invite's own expiry, copied. Serving a blob for an invite that
    -- can no longer be redeemed would hand the control plane a link that 404s at
    -- the end of it.
    expires_at          timestamptz not null,
    created_at          timestamptz not null default now(),
    constraint relay_bootstrap_handoff_blob_present check (length(blob) > 0),
    constraint relay_bootstrap_handoff_code_present check (length(sealed_code) > 0),
    constraint relay_bootstrap_handoff_fingerprint_is_hex check (genesis_fingerprint ~ '^[0-9a-f]{64}$')
);
