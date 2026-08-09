// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The sealed bootstrap handoff: the relay's half of the two-channel enrollment.
//!
//! `specs/backend/relay/server.md`, "`WEALD_RELAY_BOOTSTRAP_HANDOFF_PUBKEY`". The
//! control plane's half is `backend/weald-cloud/src/provisioning/handoff.ts` and
//! the two are checked against
//! `specs/backend/contracts/wire/vectors/bootstrap-handoff.json` rather than
//! against each other.
//!
//! ## What this is for
//!
//! A self-hoster reads the link, the code and the fingerprint off their own
//! terminal, and the two-channel split protects them from nothing they do not
//! already control. A hosted customer never sees that terminal. So on the hosted
//! tier the relay seals both halves to a short-lived public key the control plane
//! generated for this one instance, keeps only the ciphertexts, and prints nothing
//! secret. The control plane holds the private half wrapped, opens the blob once
//! for the browser and once for the mail, and destroys the key.
//!
//! ## What this is not
//!
//! It is not a second route to trust root. Sealing does not create a reissue: the
//! relay still holds `Argon2id(code, salt=token)` and no recoverable plaintext
//! code, and the ciphertext it keeps is openable only by the holder of a private
//! key that lives in another system and is destroyed on first claim. Reading the
//! blob does not consume the invite; redemption remains the one-time operation.
//!
//! ## The construction, and why each part of it
//!
//! ```text
//! blob  = ephemeral_public_key (32) || AES-256-GCM(key, nonce, plaintext) || tag (16)
//! key   = HKDF-SHA256(ikm  = X25519(ephemeral_private, handoff_public),
//!                     salt = "weald-bootstrap-handoff-v1",
//!                     info = handoff_public_key,
//!                     len  = 32)
//! nonce = 12 zero bytes
//! path  = /handoff/<base64url(SHA-256(handoff_public_key))>
//! ```
//!
//! The nonce is fixed and safe here and only here: the key is derived from a fresh
//! ephemeral pair per sealing, so it encrypts exactly one message. `info` binds the
//! ciphertext to the key it was sealed to, so a blob lifted from one instance and
//! served for another fails to open rather than decrypting into somebody else's
//! invite. The path is derived from the key rather than from the workspace, because
//! a path containing a hostname would be a guessable url for a ciphertext.
//!
//! ## Why `ring` and no new third party
//!
//! HKDF-SHA256, AES-256-GCM and SHA-256 come from `ring`, already linked into this
//! binary underneath `rustls`/`sqlx`: naming it directly adds a line to `Cargo.toml`
//! and no code to the dependency graph, which is the trade `serve.rs` asks for.
//!
//! X25519 comes from `x25519-dalek` rather than from `ring`, and the reason is
//! testability rather than taste. `ring`'s agreement API consumes an ephemeral key
//! it generated itself and offers no way to supply one, while the conformance
//! vectors pin a specific ephemeral private key so both implementations can be
//! checked against the same bytes. A construction no test can reproduce
//! deterministically is a construction checked against nothing. `x25519-dalek` is
//! the same family as `ed25519-dalek`, which is already here, so this rides on a
//! `curve25519-dalek` the binary already links.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::digest::{digest, SHA256};
use ring::hkdf::{Salt, HKDF_SHA256};
use x25519_dalek::{PublicKey, StaticSecret};

/// The HKDF salt. A constant, shared with `handoff.ts`, and versioned in its own
/// text so a second construction would be a different string rather than the same
/// string meaning two things.
pub const HANDOFF_SALT: &[u8] = b"weald-bootstrap-handoff-v1";

/// A public key that is not 32 bytes is a configuration error, not a runtime one.
pub const HANDOFF_KEY_BYTES: usize = 32;

/// What went wrong, in terms an operator can act on.
///
/// Deliberately coarse. The distinction between "the peer key was malformed" and
/// "the agreement failed" is not one an operator can do anything different about,
/// and a sealing routine that reported the shape of its own failures in detail
/// would be describing key material by elimination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffError {
    /// The configured value is not base64, or does not decode to 32 bytes.
    Key(String),
    /// Entropy, agreement or the AEAD refused. Not expected, and fatal to the
    /// sealing rather than to the process: a relay that could not seal is one the
    /// control plane reports as not operable, which is a retry.
    Seal,
}

impl std::fmt::Display for HandoffError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Key(why) => write!(out, "bootstrap handoff public key is unusable: {why}"),
            Self::Seal => write!(out, "could not seal the bootstrap handoff"),
        }
    }
}

impl std::error::Error for HandoffError {}

/// Decode the configured public key.
///
/// Base64 standard alphabet with padding, which is the form the control plane
/// writes into the environment (`render-resources.ts`) and the form the conformance
/// vectors carry.
pub fn parse_public_key(configured: &str) -> Result<[u8; HANDOFF_KEY_BYTES], HandoffError> {
    let bytes = base64_decode(configured.trim())
        .ok_or_else(|| HandoffError::Key("not base64".to_string()))?;
    let len = bytes.len();
    <[u8; HANDOFF_KEY_BYTES]>::try_from(bytes.as_slice())
        .map_err(|_| HandoffError::Key(format!("{len} bytes, expected {HANDOFF_KEY_BYTES}")))
}

/// The path this relay serves the blob at, derived from the key and nothing else.
///
/// `base64url` without padding, because the value sits in a URL path segment and
/// `=` there is legal but needlessly escaped by half the clients that would fetch
/// it.
pub fn handoff_path(public_key: &[u8]) -> String {
    let sum = digest(&SHA256, public_key);
    format!("/handoff/{}", base64url_nopad(sum.as_ref()))
}

/// Seal one plaintext to the handoff public key.
///
/// A fresh ephemeral pair per call, which is what makes the zero nonce safe: this
/// key encrypts exactly one message and is then dropped. Two calls over the same
/// handoff key therefore produce two different blobs, which is why the conformance
/// vectors pin the ephemeral private key rather than asserting on a fresh one.
pub fn seal(
    public_key: &[u8; HANDOFF_KEY_BYTES],
    plaintext: &[u8],
) -> Result<String, HandoffError> {
    let mut ephemeral = [0u8; HANDOFF_KEY_BYTES];
    getrandom::fill(&mut ephemeral).map_err(|_| HandoffError::Seal)?;
    seal_with_ephemeral(public_key, &ephemeral, plaintext)
}

/// `seal`, with the ephemeral private key supplied.
///
/// Public because the conformance vectors pin one, and because a sealing routine
/// whose only entry point mints its own randomness cannot be checked against bytes
/// anybody else produced. It is not a way to seal twice under one key: every
/// production caller is `seal` above, which mints a fresh pair per call, and that is
/// what makes the zero nonce safe.
pub fn seal_with_ephemeral(
    public_key: &[u8; HANDOFF_KEY_BYTES],
    ephemeral_private: &[u8; HANDOFF_KEY_BYTES],
    plaintext: &[u8],
) -> Result<String, HandoffError> {
    let secret = StaticSecret::from(*ephemeral_private);
    let ephemeral_public = PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&PublicKey::from(*public_key));
    let mut sealed = seal_with_shared(shared.as_bytes(), public_key, plaintext)?;
    let mut blob = ephemeral_public.as_bytes().to_vec();
    blob.append(&mut sealed);
    Ok(base64_encode(&blob))
}

/// Open a blob. The other direction of the same construction.
///
/// Not reached in production: the relay seals and never opens, because it holds no
/// handoff private key and the whole point of the design is that it cannot. It is
/// here so the conformance vectors can be checked in both directions from one place,
/// and so "this is ciphertext" is not the only thing standing between a correct
/// implementation and one that merely produces bytes.
pub fn open(
    private_key: &[u8; HANDOFF_KEY_BYTES],
    public_key: &[u8; HANDOFF_KEY_BYTES],
    blob_base64: &str,
) -> Result<Vec<u8>, HandoffError> {
    let blob = base64_decode(blob_base64).ok_or(HandoffError::Seal)?;
    if blob.len() < HANDOFF_KEY_BYTES + 16 {
        return Err(HandoffError::Seal);
    }
    let (ephemeral_public, ciphertext) = blob.split_at(HANDOFF_KEY_BYTES);
    let ephemeral: [u8; HANDOFF_KEY_BYTES] = ephemeral_public
        .try_into()
        .map_err(|_| HandoffError::Seal)?;
    let secret = StaticSecret::from(*private_key);
    let shared = secret.diffie_hellman(&PublicKey::from(ephemeral));
    let key = message_key(shared.as_bytes(), public_key)?;
    let aead =
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).map_err(|_| HandoffError::Seal)?);
    let mut buffer = ciphertext.to_vec();
    let opened = aead
        .open_in_place(
            Nonce::assume_unique_for_key([0u8; NONCE_LEN]),
            Aad::empty(),
            &mut buffer,
        )
        .map_err(|_| HandoffError::Seal)?;
    Ok(opened.to_vec())
}

/// The spec's key schedule, in one place, so sealing and opening cannot read it two
/// different ways.
fn message_key(
    shared: &[u8],
    public_key: &[u8; HANDOFF_KEY_BYTES],
) -> Result<[u8; 32], HandoffError> {
    let mut key = [0u8; 32];
    Salt::new(HKDF_SHA256, HANDOFF_SALT)
        .extract(shared)
        .expand(&[public_key.as_slice()], HkdfLen(key.len()))
        .map_err(|_| HandoffError::Seal)?
        .fill(&mut key)
        .map_err(|_| HandoffError::Seal)?;
    Ok(key)
}

/// Derive the message key from the shared secret and encrypt under it.
fn seal_with_shared(
    shared: &[u8],
    public_key: &[u8; HANDOFF_KEY_BYTES],
    plaintext: &[u8],
) -> Result<Vec<u8>, HandoffError> {
    let key = message_key(shared, public_key)?;
    let unbound = UnboundKey::new(&AES_256_GCM, &key).map_err(|_| HandoffError::Seal)?;
    let aead = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key([0u8; NONCE_LEN]);
    let mut buffer = plaintext.to_vec();
    aead.seal_in_place_append_tag(nonce, Aad::empty(), &mut buffer)
        .map_err(|_| HandoffError::Seal)?;
    Ok(buffer)
}

/// `ring`'s HKDF wants an output length expressed as a `KeyType`. Thirty-two bytes
/// of raw output, which is the AES-256 key and nothing else.
#[derive(Debug, Clone, Copy)]
struct HkdfLen(usize);

impl ring::hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Standard base64 with padding. Written here rather than taken as a dependency:
/// the crate has no base64 and this is the only place in the relay that needs one,
/// so a table and two loops is less to audit than a crate.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    encode_with(bytes, ALPHABET, true)
}

/// URL-safe base64 without padding, for the path segment.
fn base64url_nopad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    encode_with(bytes, ALPHABET, false)
}

fn encode_with(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut block = [0u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let packed = (u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]);
        let symbols = [
            (packed >> 18) & 0x3f,
            (packed >> 12) & 0x3f,
            (packed >> 6) & 0x3f,
            packed & 0x3f,
        ];
        // One symbol per 6 bits, and one symbol dropped for each byte the final
        // chunk was short of three.
        let kept = chunk.len() + 1;
        for symbol in symbols.iter().take(kept) {
            out.push(alphabet[*symbol as usize] as char);
        }
        if pad {
            for _ in kept..4 {
                out.push('=');
            }
        }
    }
    out
}

/// Standard base64, decoding. Rejects any symbol outside the alphabet rather than
/// skipping it: a key with a stray character in it is a key somebody mistyped, and
/// silently dropping the character would seal to a different key than the one the
/// control plane holds.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut held = 0u32;
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for symbol in text.bytes() {
        if symbol == b'=' {
            break;
        }
        let value = match symbol {
            b'A'..=b'Z' => symbol - b'A',
            b'a'..=b'z' => symbol - b'a' + 26,
            b'0'..=b'9' => symbol - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push(((bits >> held) & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        for len in 0..40usize {
            let bytes: Vec<u8> = (0..len).map(|index| (index * 7 + 3) as u8).collect();
            let encoded = base64_encode(&bytes);
            assert_eq!(base64_decode(&encoded).as_deref(), Some(bytes.as_slice()));
        }
    }

    #[test]
    fn base64_refuses_a_stray_symbol() {
        assert_eq!(base64_decode("AA!A"), None);
    }

    #[test]
    fn a_key_of_the_wrong_width_is_named_as_such() {
        let error = parse_public_key("AAAA").expect_err("four bytes is not a key");
        assert!(matches!(error, HandoffError::Key(_)));
    }

    #[test]
    fn the_path_is_derived_from_the_key() {
        let key = [0x11u8; 32];
        let path = handoff_path(&key);
        assert!(path.starts_with("/handoff/"));
        assert!(!path.contains('='));
        assert_eq!(path, handoff_path(&key));
        assert_ne!(path, handoff_path(&[0x12u8; 32]));
    }

    #[test]
    fn sealing_twice_produces_two_blobs() {
        let key = parse_public_key("4NDwbOM3PhZLBl+aZKGWJm1JW8QoWHmVJBJPRz0uMHM=")
            .expect("a 32 byte key");
        let one = seal(&key, b"hello").expect("seal");
        let two = seal(&key, b"hello").expect("seal");
        assert_ne!(one, two, "a fresh ephemeral pair per sealing");
        let bytes = base64_decode(&one).expect("base64");
        assert_eq!(bytes.len(), 32 + b"hello".len() + 16);
    }
}

/// What the relay serves at the derived path.
///
/// Field names are the wire, not a convenience: `render-operations.ts
/// renderHandoffBlob` parses exactly these three and refuses a response missing any
/// of them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SealedHandoff {
    pub blob: String,
    pub sealed_code: String,
    pub genesis_fingerprint: String,
}

/// Seal both halves of a first run and keep only the ciphertexts.
///
/// Called once, inside the first boot that minted the genesis key, because the code
/// exists in memory exactly then and nowhere afterwards: the relay stores
/// `Argon2id(code, salt=token)` and there is no second chance to seal it. A relay
/// that fails here has minted an invite nobody can reach, which the control plane
/// sees as `instance_not_operable` and retries, and which an operator resolves by
/// starting the relay again against an empty database.
pub async fn store(
    pool: &sqlx::PgPool,
    workspace_id: &str,
    hostname: &str,
    run: &super::genesis::FirstRun,
    public_key: &[u8; HANDOFF_KEY_BYTES],
    expires_ms: i64,
) -> Result<SealedHandoff, super::store::StoreError> {
    let link = format!(
        "https://{hostname}/join/{token}",
        token = super::genesis::hex(&run.token)
    );
    let sealed = SealedHandoff {
        blob: seal(public_key, link.as_bytes())
            .map_err(|error| super::store::StoreError::Database(error.to_string()))?,
        // The grouped form, because that is what a human is asked to type and what
        // `cloud/email.md` puts in the mail. Sealing the ungrouped symbols would
        // make the mail's rendering a second implementation of `Code::grouped`.
        sealed_code: seal(public_key, run.code.grouped().as_bytes())
            .map_err(|error| super::store::StoreError::Database(error.to_string()))?,
        genesis_fingerprint: super::genesis::hex(&run.fingerprint),
    };
    sqlx::query(
        "insert into relay_bootstrap_handoff \
         (workspace_id, blob, sealed_code, genesis_fingerprint, expires_at) \
         values ($1, $2, $3, $4, to_timestamp($5::double precision / 1000.0)) \
         on conflict (workspace_id) do nothing",
    )
    .bind(workspace_id)
    .bind(&sealed.blob)
    .bind(&sealed.sealed_code)
    .bind(&sealed.genesis_fingerprint)
    .bind(expires_ms.max(0) as f64)
    .execute(pool)
    .await
    .map_err(super::store::db_error)?;
    // `do nothing` rather than an overwrite: the row that is already there was
    // sealed over a code this process does not have, and replacing it would swap a
    // usable ciphertext for one whose plaintext the relay can no longer produce.
    read(pool, workspace_id)
        .await?
        .ok_or_else(|| super::store::StoreError::Database("handoff vanished mid-seal".into()))
}

/// What is served at the derived path, or nothing.
///
/// Reading does not consume: `server.md` is explicit that the blob may be fetched
/// more than once and that redemption is the one-time operation. The control plane
/// polls this while it waits for a relay to come up, so a read that spent it would
/// destroy the invite before the buyer ever saw it.
pub async fn read(
    pool: &sqlx::PgPool,
    workspace_id: &str,
) -> Result<Option<SealedHandoff>, super::store::StoreError> {
    use sqlx::Row as _;
    let row = sqlx::query(
        "select blob, sealed_code, genesis_fingerprint from relay_bootstrap_handoff \
         where workspace_id = $1",
    )
    .bind(workspace_id)
    .fetch_optional(pool)
    .await
    .map_err(super::store::db_error)?;
    Ok(row.map(|row| SealedHandoff {
        blob: row.get("blob"),
        sealed_code: row.get("sealed_code"),
        genesis_fingerprint: row.get("genesis_fingerprint"),
    }))
}
