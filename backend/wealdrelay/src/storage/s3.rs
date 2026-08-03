// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The S3 backend, held to the same contract as the filesystem one.
//!
//! Real S3 in deployed environments, real MinIO in the test harness. The same code
//! path in both, because the difference between environments is configuration and
//! never code: MinIO is reached by pointing `AWS_ENDPOINT_URL_S3` at it and turning
//! on path-style addressing, which is what every S3-compatible provider expects.
//!
//! Credentials come from the standard AWS chain, so an operator on a provider
//! that injects a role gets it for free and one on a VPS sets two variables. No
//! Weald-specific credential key exists, because a fourth required configuration
//! value pointing at storage would be a fourth thing to get wrong.

use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;

use super::{BlobInfo, BlobKey, BlobStore, StorageError};

/// The bucket, and the prefix inside it if the URL named one.
#[derive(Debug, Clone)]
pub struct S3Store {
    client: Client,
    bucket: String,
    prefix: String,
}

impl S3Store {
    /// Build a client from the ambient AWS configuration.
    ///
    /// `force_path_style` is on unconditionally. Virtual-host addressing needs
    /// DNS for `<bucket>.<host>`, which no MinIO or self-hosted gateway provides,
    /// and path style works against AWS as well. Choosing per environment would
    /// mean the hosted deployment ran a code path the self-hoster does not.
    pub async fn connect(bucket: String, prefix: String) -> Self {
        let loaded = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let config = aws_sdk_s3::config::Builder::from(&loaded)
            .force_path_style(true)
            .build();
        Self {
            client: Client::from_conf(config),
            bucket,
            prefix,
        }
    }

    /// For tests that already hold a configured client, including the contract
    /// suite pointing at MinIO.
    pub fn with_client(client: Client, bucket: String, prefix: String) -> Self {
        Self {
            client,
            bucket,
            prefix,
        }
    }

    fn object_key(&self, key: &BlobKey) -> String {
        self.join(&key.path())
    }

    fn join(&self, suffix: &str) -> String {
        if self.prefix.is_empty() {
            suffix.to_string()
        } else {
            format!("{}/{}", self.prefix, suffix)
        }
    }

    /// Map an SDK failure onto the typed contract.
    ///
    /// The distinction that matters is transient against terminal, because the
    /// caller turns the first into `retry` and the second into `reject`
    /// (`specs/backend/contracts/registries/error-codes.md`). A dispatch or
    /// timeout failure never reached the bucket; a service error did and was
    /// refused.
    fn map_error<E, R>(context: &str, error: SdkError<E, R>) -> StorageError
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        // `SdkError` is only `Debug` when its response type is, and the response
        // type here is opaque, so the message is built from the variant and the
        // service error rather than from a derived formatter.
        match error {
            SdkError::DispatchFailure(_) => StorageError::Unreachable {
                reason: format!("{context}: the request never reached the bucket"),
            },
            SdkError::TimeoutError(_) => StorageError::Unreachable {
                reason: format!("{context}: timed out"),
            },
            SdkError::ServiceError(service) => StorageError::ReadFailed {
                reason: format!("{context}: {}", service.into_err()),
            },
            // `SdkError` is `#[non_exhaustive]`, so a catch-all is required. What
            // reaches it today is `ConstructionFailure` and `ResponseError`, and
            // both mean the same thing to a caller: no answer came back that could
            // be interpreted, so there is nothing to distinguish.
            _ => StorageError::ReadFailed {
                reason: format!("{context}: the request produced no interpretable response"),
            },
        }
    }
}

impl BlobStore for S3Store {
    async fn put(&self, key: &BlobKey, bytes: &[u8]) -> Result<(), StorageError> {
        // A single `PutObject` is atomic on S3 and on every compatible
        // implementation: the object appears whole or not at all. That is the same
        // guarantee the filesystem backend buys with a rename, which is why the
        // contract can assert it against both.
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.object_key(key))
            .body(ByteStream::from(bytes.to_vec()))
            .send()
            .await
            .map_err(
                |error| match Self::map_error(&format!("put {}", key.path()), error) {
                    // A put that never reached the bucket is transient and stays so; a
                    // put the bucket refused is a write failure rather than a read one.
                    transient @ StorageError::Unreachable { .. } => transient,
                    other => StorageError::WriteFailed {
                        reason: other.to_string(),
                    },
                },
            )?;
        Ok(())
    }

    async fn get(&self, key: &BlobKey) -> Result<Vec<u8>, StorageError> {
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.object_key(key))
            .send()
            .await
            .map_err(|error| {
                if let SdkError::ServiceError(service) = &error {
                    if service.err().is_no_such_key() {
                        return StorageError::NotFound { key: key.path() };
                    }
                }
                Self::map_error(&format!("get {}", key.path()), error)
            })?;
        let bytes = output
            .body
            .collect()
            .await
            .map_err(|error| StorageError::ReadFailed {
                reason: format!("read body of {}: {error}", key.path()),
            })?;
        Ok(bytes.to_vec())
    }

    async fn head(&self, key: &BlobKey) -> Result<Option<BlobInfo>, StorageError> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(self.object_key(key))
            .send()
            .await
        {
            Ok(output) => Ok(Some(BlobInfo {
                len: output.content_length().unwrap_or_default().max(0) as u64,
            })),
            Err(error) => {
                // `HeadObject` reports a missing object as a 404 with no typed
                // variant, so the status is the only signal. Absence is not a
                // failure: `head` answering `None` is how the relay decides
                // whether to issue an upload URL.
                if let SdkError::ServiceError(service) = &error {
                    if service.raw().status().as_u16() == 404 {
                        return Ok(None);
                    }
                }
                Err(Self::map_error(&format!("head {}", key.path()), error))
            }
        }
    }

    async fn delete(&self, key: &BlobKey) -> Result<(), StorageError> {
        // S3 answers a delete of a key that is not there with success, which is
        // the same behaviour the filesystem backend implements deliberately.
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(self.object_key(key))
            .send()
            .await
            .map_err(|error| Self::map_error(&format!("delete {}", key.path()), error))?;
        Ok(())
    }

    async fn list(&self, workspace: &str, group: &str) -> Result<Vec<String>, StorageError> {
        let under = self.join(&format!("{workspace}/{group}/"));
        let mut out = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&under);
            if let Some(token) = continuation.take() {
                request = request.continuation_token(token);
            }
            let page = request
                .send()
                .await
                .map_err(|error| Self::map_error(&format!("list {under}"), error))?;
            for key in page.contents().iter().filter_map(|object| object.key()) {
                // Stripped rather than split on the last separator, so a key the
                // server returned that is not actually under the prefix is dropped
                // instead of being reported as a blob in this group. The result is
                // the last component, which is what the filesystem backend answers,
                // so a caller comparing the two compares like with like.
                let Some(name) = key.strip_prefix(under.as_str()) else {
                    continue;
                };
                if !name.is_empty() {
                    out.push(name.to_string());
                }
            }
            // Paginated rather than truncated: a group with more than a thousand
            // blobs is ordinary at the stated posture, and a list that silently
            // stopped at the first page would make the unreferenced-blob collector
            // delete objects it had not seen.
            if page.is_truncated().unwrap_or(false) {
                continuation = page.next_continuation_token().map(str::to_string);
                if continuation.is_some() {
                    continue;
                }
            }
            break;
        }
        out.sort();
        Ok(out)
    }

    async fn assemble(&self, parts: &[BlobKey], target: &BlobKey) -> Result<u64, StorageError> {
        if parts.is_empty() {
            return Err(StorageError::InvalidKey {
                component: "an object cannot be assembled from no parts".to_string(),
            });
        }
        let destination = self.object_key(target);
        let created = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(&destination)
            .send()
            .await
            .map_err(|error| Self::map_error(&format!("assemble {}", target.path()), error))?;
        let Some(upload_id) = created.upload_id().map(str::to_string) else {
            return Err(StorageError::WriteFailed {
                reason: format!("assemble {}: the bucket opened no upload", target.path()),
            });
        };

        match self.copy_parts(parts, &destination, &upload_id).await {
            Ok(total) => Ok(total),
            Err(error) => {
                // An abandoned multipart upload keeps its already-copied parts
                // alive and billable until a lifecycle rule reaps them, so the
                // failure path aborts rather than leaving one open. The abort's
                // own outcome is not reported: the caller is being told why the
                // assembly failed, and replacing that with why the cleanup failed
                // would lose the useful half.
                let _ = self
                    .client
                    .abort_multipart_upload()
                    .bucket(&self.bucket)
                    .key(&destination)
                    .upload_id(&upload_id)
                    .send()
                    .await;
                Err(error)
            }
        }
    }

    async fn probe(&self) -> Result<(), StorageError> {
        // `HeadBucket` is the cheapest round trip that proves both reachability
        // and that the credentials can see this bucket. A probe that only opened a
        // socket would report a bucket the relay cannot write to as healthy.
        self.client
            .head_bucket()
            .bucket(&self.bucket)
            .send()
            .await
            .map_err(|error| StorageError::Unreachable {
                reason: format!("head bucket {}: {error:?}", self.bucket),
            })?;
        Ok(())
    }

    fn describe(&self) -> String {
        if self.prefix.is_empty() {
            format!("s3://{}", self.bucket)
        } else {
            format!("s3://{}/{}", self.bucket, self.prefix)
        }
    }
}

impl S3Store {
    /// The body of ``assemble``: one `UploadPartCopy` per part, then the
    /// completion. Split out so the abort on failure has exactly one place to
    /// catch, rather than one per statement.
    ///
    /// `UploadPartCopy` is what makes a 2 GiB assembly free: the bytes never
    /// leave the bucket, so the relay's cost is one request per part rather than
    /// one copy of the object in memory and another on the wire.
    async fn copy_parts(
        &self,
        parts: &[BlobKey],
        destination: &str,
        upload_id: &str,
    ) -> Result<u64, StorageError> {
        let mut completed = Vec::with_capacity(parts.len());
        let mut total = 0u64;
        for (index, part) in parts.iter().enumerate() {
            let number = index as i32 + 1;
            let source = format!("{}/{}", self.bucket, self.object_key(part));
            let copied = self
                .client
                .upload_part_copy()
                .bucket(&self.bucket)
                .key(destination)
                .upload_id(upload_id)
                .part_number(number)
                .copy_source(&source)
                .send()
                .await
                .map_err(
                    |error| match Self::map_error(&format!("copy {source}"), error) {
                        transient @ StorageError::Unreachable { .. } => transient,
                        // A part that is not there is the caller finalizing an upload
                        // it did not finish, which is a different thing from the
                        // bucket refusing a write and has to reach the caller as one.
                        other => {
                            let reason = other.to_string();
                            if reason.contains("NoSuchKey") || reason.contains("NotFound") {
                                StorageError::NotFound { key: part.path() }
                            } else {
                                StorageError::WriteFailed { reason }
                            }
                        }
                    },
                )?;
            let etag = copied
                .copy_part_result()
                .and_then(|result| result.e_tag())
                .unwrap_or_default()
                .to_string();
            completed.push(
                aws_sdk_s3::types::CompletedPart::builder()
                    .part_number(number)
                    .e_tag(etag)
                    .build(),
            );
            // The length is read from the source rather than from the copy
            // response, which does not carry one.
            total += self
                .head(part)
                .await?
                .ok_or_else(|| StorageError::NotFound { key: part.path() })?
                .len;
        }

        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(destination)
            .upload_id(upload_id)
            .multipart_upload(
                aws_sdk_s3::types::CompletedMultipartUpload::builder()
                    .set_parts(Some(completed))
                    .build(),
            )
            .send()
            .await
            .map_err(
                |error| match Self::map_error(&format!("complete {destination}"), error) {
                    transient @ StorageError::Unreachable { .. } => transient,
                    other => StorageError::WriteFailed {
                        reason: other.to_string(),
                    },
                },
            )?;
        Ok(total)
    }

    /// A presigned PUT for `key`, valid for `ttl`.
    ///
    /// `media.md`: "a presigned PUT URL valid for 15 minutes". One object per
    /// call: the multipart upload path issues one of these per part rather than
    /// using S3's own multipart API, so both storage backends share exactly one
    /// finalization path in `media::gc` and `media::store` instead of two.
    pub async fn presign_put(
        &self,
        key: &BlobKey,
        ttl: std::time::Duration,
    ) -> Result<String, StorageError> {
        let config =
            aws_sdk_s3::presigning::PresigningConfig::expires_in(ttl).map_err(|error| {
                StorageError::WriteFailed {
                    reason: format!("presigning config: {error}"),
                }
            })?;
        let presigned = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(self.object_key(key))
            .presigned(config)
            .await
            .map_err(|error| Self::map_error(&format!("presign put {}", key.path()), error))?;
        Ok(presigned.uri().to_string())
    }

    /// A presigned GET for `key`, valid for `ttl`.
    pub async fn presign_get(
        &self,
        key: &BlobKey,
        ttl: std::time::Duration,
    ) -> Result<String, StorageError> {
        let config =
            aws_sdk_s3::presigning::PresigningConfig::expires_in(ttl).map_err(|error| {
                StorageError::ReadFailed {
                    reason: format!("presigning config: {error}"),
                }
            })?;
        let presigned = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.object_key(key))
            .presigned(config)
            .await
            .map_err(|error| Self::map_error(&format!("presign get {}", key.path()), error))?;
        Ok(presigned.uri().to_string())
    }
}
