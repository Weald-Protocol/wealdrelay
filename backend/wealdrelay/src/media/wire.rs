// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The public retention control records, and the `BLOB` request/response shapes.
//!
//! `specs/backend/relay/media.md`: `RetentionControl`, `RetentionManifest`,
//! `RetentionPolicy` and `RetentionDestruction` "live beside envelopes, not
//! inside `ct`, and use canonical CBOR". They travel over the wire inside
//! `Frame::Blob { payload }`, the same way `invite::redeem::Request` travels
//! inside `Frame::Join { body }`: one opaque byte string at the frame layer, with
//! its own tag and shape decided here. A struct is an array of its fields in
//! declaration order, matching every other structure on this wire
//! (`access::AccessSet`, `envelope::Envelope`).
//!
//! Every record's signature covers the canonical encoding of every field before
//! it, with the signature field(s) themselves omitted: `signing_bytes` is that
//! prefix, computed once and reused by both the signer (in tests and fixtures)
//! and the verifier.

use crate::access::{HASH_BYTES, KEY_BYTES, SIG_BYTES};
use crate::cbor::{self, CborError, Reader};

/// A bound on any list a single wire message may carry, for the same reason
/// `access::MAX_ENTRIES` exists: refusing the count before the allocation.
pub const MAX_LIST: usize = 4096;

/// Why a media wire record could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MediaWireError {
    #[error("media record is not canonical CBOR: {0}")]
    Encoding(#[from] CborError),
    #[error("a list in the record is longer than {MAX_LIST}")]
    TooManyEntries,
    #[error("an empty list where one entry is required")]
    EmptyList,
    #[error("unknown media message tag {0}")]
    UnknownTag(u64),
}

fn read_list(reader: &mut Reader<'_>, width: usize) -> Result<Vec<Vec<u8>>, MediaWireError> {
    let count = reader.array_header()?;
    if count > MAX_LIST {
        return Err(MediaWireError::TooManyEntries);
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(reader.bytes_of(width)?);
    }
    Ok(items)
}

fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    cbor::array(
        &items
            .iter()
            .map(|item| cbor::bytes(item))
            .collect::<Vec<_>>(),
    )
}

/// One signature over a record body, from a claimed authorizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub key: Vec<u8>,
    pub sig: Vec<u8>,
}

fn read_signatures(reader: &mut Reader<'_>) -> Result<Vec<Signature>, MediaWireError> {
    let count = reader.array_header()?;
    if count > MAX_LIST {
        return Err(MediaWireError::TooManyEntries);
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        reader.array(2)?;
        out.push(Signature {
            key: reader.bytes_of(KEY_BYTES)?,
            sig: reader.bytes_of(SIG_BYTES)?,
        });
    }
    Ok(out)
}

fn encode_signatures(signatures: &[Signature]) -> Vec<u8> {
    cbor::array(
        &signatures
            .iter()
            .map(|entry| cbor::array(&[cbor::bytes(&entry.key), cbor::bytes(&entry.sig)]))
            .collect::<Vec<_>>(),
    )
}

/// `RetentionControl { group, epoch, verifier, prev_control_hash, sig }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionControl {
    pub group: Vec<u8>,
    pub epoch: u64,
    pub verifier: Vec<u8>,
    pub prev_control_hash: Option<Vec<u8>>,
    pub sig: Vec<u8>,
}

impl RetentionControl {
    pub fn signing_bytes(&self) -> Vec<u8> {
        cbor::array(&[
            cbor::bytes(&self.group),
            cbor::uint(self.epoch),
            cbor::bytes(&self.verifier),
            cbor::optional_bytes(self.prev_control_hash.as_deref()),
        ])
    }

    pub fn encode(&self) -> Vec<u8> {
        cbor::array(&[
            cbor::bytes(&self.group),
            cbor::uint(self.epoch),
            cbor::bytes(&self.verifier),
            cbor::optional_bytes(self.prev_control_hash.as_deref()),
            cbor::bytes(&self.sig),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MediaWireError> {
        let mut reader = Reader::new(bytes);
        let record = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(record)
    }

    /// The fields only, leaving the reader positioned after them. Used both by
    /// ``decode`` and by ``Request::decode``, which carries this record as one
    /// arm of a larger array and so cannot expect the input to end here.
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, MediaWireError> {
        reader.array(5)?;
        let group = reader.bytes_of(HASH_BYTES)?;
        let epoch = reader.uint()?;
        let verifier = reader.bytes_of(KEY_BYTES)?;
        let prev_control_hash = reader.optional_bytes()?;
        let sig = reader.bytes_of(SIG_BYTES)?;
        Ok(Self {
            group,
            epoch,
            verifier,
            prev_control_hash,
            sig,
        })
    }

    /// The digest a later control's `prev_control_hash` names.
    pub fn digest(&self) -> Vec<u8> {
        blake3::hash(&self.encode()).as_bytes().to_vec()
    }
}

/// `RetentionManifest { group, epoch, sequence, prev_manifest_hash, blobs, sig }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionManifest {
    pub group: Vec<u8>,
    pub epoch: u64,
    pub sequence: u64,
    pub prev_manifest_hash: Option<Vec<u8>>,
    pub blobs: Vec<Vec<u8>>,
    pub sig: Vec<u8>,
}

impl RetentionManifest {
    pub fn signing_bytes(&self) -> Vec<u8> {
        cbor::array(&[
            cbor::bytes(&self.group),
            cbor::uint(self.epoch),
            cbor::uint(self.sequence),
            cbor::optional_bytes(self.prev_manifest_hash.as_deref()),
            encode_list(&self.blobs),
        ])
    }

    pub fn encode(&self) -> Vec<u8> {
        cbor::array(&[
            cbor::bytes(&self.group),
            cbor::uint(self.epoch),
            cbor::uint(self.sequence),
            cbor::optional_bytes(self.prev_manifest_hash.as_deref()),
            encode_list(&self.blobs),
            cbor::bytes(&self.sig),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MediaWireError> {
        let mut reader = Reader::new(bytes);
        let record = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(record)
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, MediaWireError> {
        reader.array(6)?;
        let group = reader.bytes_of(HASH_BYTES)?;
        let epoch = reader.uint()?;
        let sequence = reader.uint()?;
        let prev_manifest_hash = reader.optional_bytes()?;
        let blobs = read_list(reader, HASH_BYTES)?;
        let sig = reader.bytes_of(SIG_BYTES)?;
        Ok(Self {
            group,
            epoch,
            sequence,
            prev_manifest_hash,
            blobs,
            sig,
        })
    }

    pub fn digest(&self) -> Vec<u8> {
        blake3::hash(&self.encode()).as_bytes().to_vec()
    }
}

/// `RetentionPolicy { group, version, media_after_days, text_after_days,
/// not_before, authorizers, signatures }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub group: Vec<u8>,
    pub version: u64,
    pub media_after_days: u32,
    pub text_after_days: u32,
    /// Seconds since the epoch. Relay-evaluated against its own clock.
    pub not_before: u64,
    pub authorizers: Vec<Vec<u8>>,
    pub signatures: Vec<Signature>,
}

impl RetentionPolicy {
    pub fn signing_bytes(&self) -> Vec<u8> {
        cbor::array(&[
            cbor::bytes(&self.group),
            cbor::uint(self.version),
            cbor::uint(u64::from(self.media_after_days)),
            cbor::uint(u64::from(self.text_after_days)),
            cbor::uint(self.not_before),
            encode_list(&self.authorizers),
        ])
    }

    pub fn encode(&self) -> Vec<u8> {
        cbor::array(&[
            cbor::bytes(&self.group),
            cbor::uint(self.version),
            cbor::uint(u64::from(self.media_after_days)),
            cbor::uint(u64::from(self.text_after_days)),
            cbor::uint(self.not_before),
            encode_list(&self.authorizers),
            encode_signatures(&self.signatures),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MediaWireError> {
        let mut reader = Reader::new(bytes);
        let record = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(record)
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, MediaWireError> {
        reader.array(7)?;
        let group = reader.bytes_of(HASH_BYTES)?;
        let version = reader.uint()?;
        let media_after_days = reader.u32()?;
        let text_after_days = reader.u32()?;
        let not_before = reader.uint()?;
        let authorizers = read_list(reader, KEY_BYTES)?;
        let signatures = read_signatures(reader)?;
        if authorizers.is_empty() {
            return Err(MediaWireError::EmptyList);
        }
        Ok(Self {
            group,
            version,
            media_after_days,
            text_after_days,
            not_before,
            authorizers,
            signatures,
        })
    }
}

/// `RetentionDestruction { group, kind, target_digest, policy_version?,
/// not_before, authorizers, signatures }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionDestruction {
    pub group: Vec<u8>,
    pub kind: Vec<u8>,
    pub target_digest: Vec<u8>,
    pub policy_version: Option<u64>,
    pub not_before: u64,
    pub authorizers: Vec<Vec<u8>>,
    pub signatures: Vec<Signature>,
}

impl RetentionDestruction {
    pub fn signing_bytes(&self) -> Vec<u8> {
        cbor::array(&[
            cbor::bytes(&self.group),
            cbor::bytes(&self.kind),
            cbor::bytes(&self.target_digest),
            match self.policy_version {
                Some(version) => cbor::bytes(&version.to_be_bytes()),
                None => cbor::NULL.to_vec(),
            },
            cbor::uint(self.not_before),
            encode_list(&self.authorizers),
        ])
    }

    pub fn encode(&self) -> Vec<u8> {
        cbor::array(&[
            cbor::bytes(&self.group),
            cbor::bytes(&self.kind),
            cbor::bytes(&self.target_digest),
            match self.policy_version {
                Some(version) => cbor::bytes(&version.to_be_bytes()),
                None => cbor::NULL.to_vec(),
            },
            cbor::uint(self.not_before),
            encode_list(&self.authorizers),
            encode_signatures(&self.signatures),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MediaWireError> {
        let mut reader = Reader::new(bytes);
        let record = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(record)
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, MediaWireError> {
        reader.array(7)?;
        let group = reader.bytes_of(HASH_BYTES)?;
        let kind = reader.bytes()?;
        let target_digest = reader.bytes_of(HASH_BYTES)?;
        let policy_version = reader
            .optional_bytes()?
            .map(|bytes| {
                let array: [u8; 8] = bytes
                    .try_into()
                    .map_err(|_| MediaWireError::TooManyEntries)?;
                Ok::<u64, MediaWireError>(u64::from_be_bytes(array))
            })
            .transpose()?;
        let not_before = reader.uint()?;
        let authorizers = read_list(reader, KEY_BYTES)?;
        let signatures = read_signatures(reader)?;
        if authorizers.is_empty() {
            return Err(MediaWireError::EmptyList);
        }
        Ok(Self {
            group,
            kind,
            target_digest,
            policy_version,
            not_before,
            authorizers,
            signatures,
        })
    }
}

// MARK: `BLOB` request and response bodies.

/// One `BLOB` request, client to relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Put {
        workspace: Vec<u8>,
        group: Vec<u8>,
        hash: Vec<u8>,
        ciphertext_len: u64,
    },
    Get {
        workspace: Vec<u8>,
        group: Vec<u8>,
        hash: Vec<u8>,
    },
    /// Ask for (or refresh) one part's presigned URL inside a multipart session.
    MultipartPart {
        session_id: Vec<u8>,
        part_number: u32,
        expected_len: u64,
    },
    /// Finish a multipart session. `parts` is the ordered set the client
    /// actually uploaded, each with the ETag the storage backend returned.
    MultipartComplete {
        session_id: Vec<u8>,
        parts: Vec<(u32, Vec<u8>)>,
    },
    MultipartAbort {
        session_id: Vec<u8>,
    },
    RetentionControl(RetentionControl),
    RetentionManifest(RetentionManifest),
    RetentionPolicy(RetentionPolicy),
    RetentionDestruction(RetentionDestruction),
}

const TAG_PUT: u64 = 1;
const TAG_GET: u64 = 2;
const TAG_MULTIPART_PART: u64 = 3;
const TAG_MULTIPART_COMPLETE: u64 = 4;
const TAG_MULTIPART_ABORT: u64 = 5;
const TAG_RETENTION_CONTROL: u64 = 6;
const TAG_RETENTION_MANIFEST: u64 = 7;
const TAG_RETENTION_POLICY: u64 = 8;
const TAG_RETENTION_DESTRUCTION: u64 = 9;

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let (tag, body) = match self {
            Self::Put {
                workspace,
                group,
                hash,
                ciphertext_len,
            } => (
                TAG_PUT,
                cbor::array(&[
                    cbor::bytes(workspace),
                    cbor::bytes(group),
                    cbor::bytes(hash),
                    cbor::uint(*ciphertext_len),
                ]),
            ),
            Self::Get {
                workspace,
                group,
                hash,
            } => (
                TAG_GET,
                cbor::array(&[
                    cbor::bytes(workspace),
                    cbor::bytes(group),
                    cbor::bytes(hash),
                ]),
            ),
            Self::MultipartPart {
                session_id,
                part_number,
                expected_len,
            } => (
                TAG_MULTIPART_PART,
                cbor::array(&[
                    cbor::bytes(session_id),
                    cbor::uint(u64::from(*part_number)),
                    cbor::uint(*expected_len),
                ]),
            ),
            Self::MultipartComplete { session_id, parts } => (
                TAG_MULTIPART_COMPLETE,
                cbor::array(&[
                    cbor::bytes(session_id),
                    cbor::array(
                        &parts
                            .iter()
                            .map(|(number, etag)| {
                                cbor::array(&[cbor::uint(u64::from(*number)), cbor::bytes(etag)])
                            })
                            .collect::<Vec<_>>(),
                    ),
                ]),
            ),
            Self::MultipartAbort { session_id } => {
                (TAG_MULTIPART_ABORT, cbor::array(&[cbor::bytes(session_id)]))
            }
            Self::RetentionControl(record) => (TAG_RETENTION_CONTROL, record.encode()),
            Self::RetentionManifest(record) => (TAG_RETENTION_MANIFEST, record.encode()),
            Self::RetentionPolicy(record) => (TAG_RETENTION_POLICY, record.encode()),
            Self::RetentionDestruction(record) => (TAG_RETENTION_DESTRUCTION, record.encode()),
        };
        cbor::array(&[cbor::uint(tag), body])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MediaWireError> {
        let mut reader = Reader::new(bytes);
        reader.array(2)?;
        let tag = reader.uint()?;
        Ok(match tag {
            TAG_PUT => {
                reader.array(4)?;
                let workspace = reader.bytes()?;
                let group = reader.bytes_of(HASH_BYTES)?;
                let hash = reader.bytes_of(HASH_BYTES)?;
                let ciphertext_len = reader.uint()?;
                reader.finish()?;
                Self::Put {
                    workspace,
                    group,
                    hash,
                    ciphertext_len,
                }
            }
            TAG_GET => {
                reader.array(3)?;
                let workspace = reader.bytes()?;
                let group = reader.bytes_of(HASH_BYTES)?;
                let hash = reader.bytes_of(HASH_BYTES)?;
                reader.finish()?;
                Self::Get {
                    workspace,
                    group,
                    hash,
                }
            }
            TAG_MULTIPART_PART => {
                reader.array(3)?;
                let session_id = reader.bytes()?;
                let part_number = reader.u32()?;
                let expected_len = reader.uint()?;
                reader.finish()?;
                Self::MultipartPart {
                    session_id,
                    part_number,
                    expected_len,
                }
            }
            TAG_MULTIPART_COMPLETE => {
                reader.array(2)?;
                let session_id = reader.bytes()?;
                let count = reader.array_header()?;
                if count > MAX_LIST {
                    return Err(MediaWireError::TooManyEntries);
                }
                let mut parts = Vec::with_capacity(count);
                for _ in 0..count {
                    reader.array(2)?;
                    let number = reader.u32()?;
                    let etag = reader.bytes()?;
                    parts.push((number, etag));
                }
                reader.finish()?;
                Self::MultipartComplete { session_id, parts }
            }
            TAG_MULTIPART_ABORT => {
                reader.array(1)?;
                let session_id = reader.bytes()?;
                reader.finish()?;
                Self::MultipartAbort { session_id }
            }
            TAG_RETENTION_CONTROL => {
                let record = RetentionControl::decode_from(&mut reader)?;
                reader.finish()?;
                Self::RetentionControl(record)
            }
            TAG_RETENTION_MANIFEST => {
                let record = RetentionManifest::decode_from(&mut reader)?;
                reader.finish()?;
                Self::RetentionManifest(record)
            }
            TAG_RETENTION_POLICY => {
                let record = RetentionPolicy::decode_from(&mut reader)?;
                reader.finish()?;
                Self::RetentionPolicy(record)
            }
            TAG_RETENTION_DESTRUCTION => {
                let record = RetentionDestruction::decode_from(&mut reader)?;
                reader.finish()?;
                Self::RetentionDestruction(record)
            }
            other => return Err(MediaWireError::UnknownTag(other)),
        })
    }
}

/// One `BLOB` response, relay to client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// A presigned upload URL, valid for the stated number of seconds from now.
    Upload {
        url: String,
        expires_in: u32,
    },
    /// The object is already there: a retry after a dropped upload is free.
    Exists,
    /// Above the single-part threshold: a multipart session instead of one URL.
    Multipart {
        session_id: Vec<u8>,
        part_size: u64,
        expires_in: u32,
    },
    Download {
        url: String,
        expires_in: u32,
    },
    NotFound,
    MultipartPartUpload {
        url: String,
        expires_in: u32,
    },
    MultipartCompleted,
    MultipartAborted,
    RetentionAck {
        digest: Vec<u8>,
    },
}

const RTAG_UPLOAD: u64 = 1;
const RTAG_EXISTS: u64 = 2;
const RTAG_MULTIPART: u64 = 3;
const RTAG_DOWNLOAD: u64 = 4;
const RTAG_NOT_FOUND: u64 = 5;
const RTAG_MULTIPART_PART_UPLOAD: u64 = 6;
const RTAG_MULTIPART_COMPLETED: u64 = 7;
const RTAG_MULTIPART_ABORTED: u64 = 8;
const RTAG_RETENTION_ACK: u64 = 9;

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        let (tag, body) = match self {
            Self::Upload { url, expires_in } => (
                RTAG_UPLOAD,
                cbor::array(&[
                    cbor::bytes(url.as_bytes()),
                    cbor::uint(u64::from(*expires_in)),
                ]),
            ),
            Self::Exists => (RTAG_EXISTS, cbor::array(&[])),
            Self::Multipart {
                session_id,
                part_size,
                expires_in,
            } => (
                RTAG_MULTIPART,
                cbor::array(&[
                    cbor::bytes(session_id),
                    cbor::uint(*part_size),
                    cbor::uint(u64::from(*expires_in)),
                ]),
            ),
            Self::Download { url, expires_in } => (
                RTAG_DOWNLOAD,
                cbor::array(&[
                    cbor::bytes(url.as_bytes()),
                    cbor::uint(u64::from(*expires_in)),
                ]),
            ),
            Self::NotFound => (RTAG_NOT_FOUND, cbor::array(&[])),
            Self::MultipartPartUpload { url, expires_in } => (
                RTAG_MULTIPART_PART_UPLOAD,
                cbor::array(&[
                    cbor::bytes(url.as_bytes()),
                    cbor::uint(u64::from(*expires_in)),
                ]),
            ),
            Self::MultipartCompleted => (RTAG_MULTIPART_COMPLETED, cbor::array(&[])),
            Self::MultipartAborted => (RTAG_MULTIPART_ABORTED, cbor::array(&[])),
            Self::RetentionAck { digest } => {
                (RTAG_RETENTION_ACK, cbor::array(&[cbor::bytes(digest)]))
            }
        };
        cbor::array(&[cbor::uint(tag), body])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MediaWireError> {
        let mut reader = Reader::new(bytes);
        reader.array(2)?;
        let tag = reader.uint()?;
        Ok(match tag {
            RTAG_UPLOAD => {
                reader.array(2)?;
                let url = String::from_utf8_lossy(&reader.bytes()?).into_owned();
                let expires_in = reader.u32()?;
                reader.finish()?;
                Self::Upload { url, expires_in }
            }
            RTAG_EXISTS => {
                reader.array(0)?;
                reader.finish()?;
                Self::Exists
            }
            RTAG_MULTIPART => {
                reader.array(3)?;
                let session_id = reader.bytes()?;
                let part_size = reader.uint()?;
                let expires_in = reader.u32()?;
                reader.finish()?;
                Self::Multipart {
                    session_id,
                    part_size,
                    expires_in,
                }
            }
            RTAG_DOWNLOAD => {
                reader.array(2)?;
                let url = String::from_utf8_lossy(&reader.bytes()?).into_owned();
                let expires_in = reader.u32()?;
                reader.finish()?;
                Self::Download { url, expires_in }
            }
            RTAG_NOT_FOUND => {
                reader.array(0)?;
                reader.finish()?;
                Self::NotFound
            }
            RTAG_MULTIPART_PART_UPLOAD => {
                reader.array(2)?;
                let url = String::from_utf8_lossy(&reader.bytes()?).into_owned();
                let expires_in = reader.u32()?;
                reader.finish()?;
                Self::MultipartPartUpload { url, expires_in }
            }
            RTAG_MULTIPART_COMPLETED => {
                reader.array(0)?;
                reader.finish()?;
                Self::MultipartCompleted
            }
            RTAG_MULTIPART_ABORTED => {
                reader.array(0)?;
                reader.finish()?;
                Self::MultipartAborted
            }
            RTAG_RETENTION_ACK => {
                reader.array(1)?;
                let digest = reader.bytes()?;
                reader.finish()?;
                Self::RetentionAck { digest }
            }
            other => return Err(MediaWireError::UnknownTag(other)),
        })
    }
}
