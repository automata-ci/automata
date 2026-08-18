use std::{fmt, str::FromStr as _, time::Duration};

use async_trait::async_trait;
use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    ImmutableRecordStore, MediaType, PutBlobOutcome, ReclaimableBlobStore, VerifiedBlob,
};
use automata_ci_core::Sha256Digest;
use aws_sdk_s3::{
    Client,
    error::{ProvideErrorMetadata, SdkError},
    primitives::ByteStream,
    types::{BucketLocationConstraint, CreateBucketConfiguration},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::{Bytes, BytesMut};
use thiserror::Error;
use tokio::time::{Instant, timeout_at};

use crate::{S3AtRestEncryption, S3BlobStoreConfig};

const DIGEST_METADATA_KEY: &str = "automata-sha256";
const SIZE_METADATA_KEY: &str = "automata-size";
const MAX_GET_ATTEMPTS: u32 = 3;

/// S3-compatible implementation of immutable blob operations.
#[derive(Clone)]
pub struct S3BlobStore {
    client: Client,
    region: String,
    bucket: String,
    prefix: Option<String>,
    operation_timeout: Duration,
    at_rest_encryption: S3AtRestEncryption,
}

impl fmt::Debug for S3BlobStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("S3BlobStore([connection redacted])")
    }
}

/// Successful result of idempotently making one exact bucket ready.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnsureBucketOutcome {
    /// The configured bucket was already accessible to these credentials.
    AlreadyExists,
    /// This invocation created the configured bucket and verified access.
    Created,
}

/// Sanitized failure while making one exact configured bucket ready.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EnsureBucketError {
    /// The initial exact-bucket inspection failed with a result other than not found.
    #[error("initial S3 bucket inspection failed")]
    InitialInspection,
    /// Creating the exact configured bucket failed with a result other than conflict.
    #[error("S3 bucket creation failed")]
    Creation,
    /// The required post-create exact-bucket inspection did not succeed.
    #[error("final S3 bucket inspection failed")]
    FinalInspection,
    /// The complete inspect/create/reinspect sequence exceeded one total deadline.
    #[error("S3 bucket initialization exceeded its total deadline")]
    Deadline,
}

impl S3BlobStore {
    pub(crate) fn from_validated(client: Client, config: &S3BlobStoreConfig) -> Self {
        Self {
            client,
            region: config.region().to_owned(),
            bucket: config.bucket().to_owned(),
            prefix: config.prefix().map(str::to_owned),
            operation_timeout: config.operation_timeout(),
            at_rest_encryption: config.at_rest_encryption().clone(),
        }
    }

    /// Idempotently ensures that this store's exact configured bucket is accessible.
    ///
    /// Only an HTTP not-found response to the initial `HeadBucket` can authorize a
    /// `CreateBucket`. A creation conflict is treated as an ambiguous concurrent
    /// race, never as success by itself; the final `HeadBucket` must still succeed.
    /// Every SDK operation shares one wall-clock deadline. Bucket creation omits
    /// `LocationConstraint` only for `us-east-1`; every other validated signing
    /// region is sent as the exact location constraint.
    ///
    /// # Errors
    ///
    /// Returns a sanitized stage-specific failure. Provider response bodies and
    /// configuration values are not retained in the error.
    pub async fn ensure_bucket(&self) -> Result<EnsureBucketOutcome, EnsureBucketError> {
        let deadline = Instant::now() + self.operation_timeout;
        let initial = timeout_at(
            deadline,
            self.client.head_bucket().bucket(&self.bucket).send(),
        )
        .await
        .map_err(|_| EnsureBucketError::Deadline)?;
        match initial {
            Ok(_) => return Ok(EnsureBucketOutcome::AlreadyExists),
            Err(error) if response_status(&error) == Some(404) => {}
            Err(_) => return Err(EnsureBucketError::InitialInspection),
        }

        let create = self.client.create_bucket().bucket(&self.bucket);
        let create = if self.region == "us-east-1" {
            create
        } else {
            create.create_bucket_configuration(
                CreateBucketConfiguration::builder()
                    .location_constraint(BucketLocationConstraint::from(self.region.as_str()))
                    .build(),
            )
        };
        let create = timeout_at(deadline, create.send())
            .await
            .map_err(|_| EnsureBucketError::Deadline)?;
        let outcome = match create {
            Ok(_) => EnsureBucketOutcome::Created,
            Err(error) if response_status(&error) == Some(409) => {
                EnsureBucketOutcome::AlreadyExists
            }
            Err(_) => return Err(EnsureBucketError::Creation),
        };

        timeout_at(
            deadline,
            self.client.head_bucket().bucket(&self.bucket).send(),
        )
        .await
        .map_err(|_| EnsureBucketError::Deadline)?
        .map_err(|_| EnsureBucketError::FinalInspection)?;
        Ok(outcome)
    }

    fn object_key(&self, descriptor: &BlobDescriptor) -> String {
        self.object_key_for(descriptor.key())
    }

    fn object_key_for(&self, key: &BlobKey) -> String {
        self.prefix.as_ref().map_or_else(
            || key.as_str().to_owned(),
            |prefix| format!("{prefix}/{}", key.as_str()),
        )
    }

    async fn verify_after_put(
        &self,
        descriptor: &BlobDescriptor,
        deadline: Instant,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        self.get_verified_before(descriptor, descriptor.size(), deadline)
            .await
    }

    async fn get_verified_before(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
        deadline: Instant,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        let mut attempts_remaining = MAX_GET_ATTEMPTS;
        loop {
            let now = Instant::now();
            let remaining = deadline
                .checked_duration_since(now)
                .ok_or_else(unavailable)?;
            // Reserve an equal share of the unspent wall-clock budget for
            // every remaining fresh request. A stalled body therefore cannot
            // consume the retry opportunity or extend the operation deadline.
            let attempt_budget = remaining
                .checked_div(attempts_remaining)
                .filter(|budget| !budget.is_zero())
                .ok_or_else(unavailable)?;
            let attempt_deadline = now + attempt_budget;
            match self
                .get_verified_attempt(descriptor, maximum_bytes, attempt_deadline)
                .await
            {
                Ok(blob) => return Ok(blob),
                Err(error)
                    if error.kind() == BlobStoreErrorKind::Unavailable
                        && attempts_remaining > 1 =>
                {
                    attempts_remaining -= 1;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn get_verified_attempt(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
        deadline: Instant,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        if descriptor.size() > maximum_bytes {
            return Err(BlobStoreError::new(BlobStoreErrorKind::TooLarge));
        }
        let expected_size = usize::try_from(descriptor.size())
            .map_err(|_| BlobStoreError::new(BlobStoreErrorKind::TooLarge))?;
        let request = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.object_key(descriptor));
        let mut response = match timeout_at(deadline, request.send()).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => return Err(map_get_error(&error)),
            Err(_) => return Err(BlobStoreError::new(BlobStoreErrorKind::Unavailable)),
        };

        let content_length = response
            .content_length()
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| BlobStoreError::new(BlobStoreErrorKind::InvalidResponse))?;
        if content_length != descriptor.size() || content_length > maximum_bytes {
            return Err(BlobStoreError::new(BlobStoreErrorKind::Integrity));
        }
        if response.content_type() != Some(descriptor.media_type().as_str()) {
            return Err(BlobStoreError::new(BlobStoreErrorKind::Integrity));
        }
        if !self
            .at_rest_encryption
            .verifies(response.server_side_encryption(), response.ssekms_key_id())
        {
            return Err(BlobStoreError::new(BlobStoreErrorKind::Integrity));
        }
        let expected_digest = descriptor.digest().to_string();
        let expected_size_text = descriptor.size().to_string();
        let metadata = response
            .metadata()
            .ok_or_else(|| BlobStoreError::new(BlobStoreErrorKind::Integrity))?;
        if metadata.get(DIGEST_METADATA_KEY).map(String::as_str) != Some(expected_digest.as_str())
            || metadata.get(SIZE_METADATA_KEY).map(String::as_str)
                != Some(expected_size_text.as_str())
        {
            return Err(BlobStoreError::new(BlobStoreErrorKind::Integrity));
        }

        let mut bytes = BytesMut::with_capacity(expected_size);
        loop {
            let next = timeout_at(deadline, response.body.try_next())
                .await
                .map_err(|_| BlobStoreError::new(BlobStoreErrorKind::Unavailable))?
                .map_err(|_| BlobStoreError::new(BlobStoreErrorKind::Unavailable))?;
            let Some(chunk) = next else { break };
            let next_size = bytes
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| BlobStoreError::new(BlobStoreErrorKind::TooLarge))?;
            if next_size > expected_size
                || u64::try_from(next_size).unwrap_or(u64::MAX) > maximum_bytes
            {
                return Err(BlobStoreError::new(BlobStoreErrorKind::TooLarge));
            }
            bytes.extend_from_slice(&chunk);
        }
        let payload = BlobPayload::verify(descriptor.clone(), Bytes::from(bytes))
            .map_err(|_| BlobStoreError::new(BlobStoreErrorKind::Integrity))?;
        Ok(VerifiedBlob::from_payload(payload))
    }

    async fn get_record_before(
        &self,
        key: &BlobKey,
        media_type: &MediaType,
        maximum_bytes: u64,
        deadline: Instant,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        let mut attempts_remaining = MAX_GET_ATTEMPTS;
        loop {
            let now = Instant::now();
            let remaining = deadline
                .checked_duration_since(now)
                .ok_or_else(unavailable)?;
            let attempt_budget = remaining
                .checked_div(attempts_remaining)
                .filter(|budget| !budget.is_zero())
                .ok_or_else(unavailable)?;
            let attempt_deadline = now + attempt_budget;
            match self
                .get_record_attempt(key, media_type, maximum_bytes, attempt_deadline)
                .await
            {
                Ok(record) => return Ok(record),
                Err(error)
                    if error.kind() == BlobStoreErrorKind::Unavailable
                        && attempts_remaining > 1 =>
                {
                    attempts_remaining -= 1;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn get_record_attempt(
        &self,
        key: &BlobKey,
        media_type: &MediaType,
        maximum_bytes: u64,
        deadline: Instant,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        let request = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.object_key_for(key));
        let mut response = match timeout_at(deadline, request.send()).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => return Err(map_get_error(&error)),
            Err(_) => return Err(unavailable()),
        };
        let content_length = response
            .content_length()
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| BlobStoreError::new(BlobStoreErrorKind::InvalidResponse))?;
        if content_length > maximum_bytes {
            return Err(BlobStoreError::new(BlobStoreErrorKind::TooLarge));
        }
        if response.content_type() != Some(media_type.as_str())
            || !self
                .at_rest_encryption
                .verifies(response.server_side_encryption(), response.ssekms_key_id())
        {
            return Err(BlobStoreError::new(BlobStoreErrorKind::Integrity));
        }
        let metadata = response
            .metadata()
            .ok_or_else(|| BlobStoreError::new(BlobStoreErrorKind::Integrity))?;
        let size_text = metadata
            .get(SIZE_METADATA_KEY)
            .ok_or_else(|| BlobStoreError::new(BlobStoreErrorKind::Integrity))?;
        let stored_size = size_text
            .parse::<u64>()
            .map_err(|_| BlobStoreError::new(BlobStoreErrorKind::Integrity))?;
        if stored_size.to_string() != *size_text || stored_size != content_length {
            return Err(BlobStoreError::new(BlobStoreErrorKind::Integrity));
        }
        let digest_text = metadata
            .get(DIGEST_METADATA_KEY)
            .ok_or_else(|| BlobStoreError::new(BlobStoreErrorKind::Integrity))?;
        let digest = Sha256Digest::from_str(digest_text)
            .map_err(|_| BlobStoreError::new(BlobStoreErrorKind::Integrity))?;
        if digest.to_string() != *digest_text {
            return Err(BlobStoreError::new(BlobStoreErrorKind::Integrity));
        }
        let capacity = usize::try_from(stored_size)
            .map_err(|_| BlobStoreError::new(BlobStoreErrorKind::TooLarge))?;
        let mut bytes = BytesMut::with_capacity(capacity);
        loop {
            let next = timeout_at(deadline, response.body.try_next())
                .await
                .map_err(|_| unavailable())?
                .map_err(|_| unavailable())?;
            let Some(chunk) = next else { break };
            let next_size = bytes
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| BlobStoreError::new(BlobStoreErrorKind::TooLarge))?;
            if next_size > capacity {
                return Err(BlobStoreError::new(BlobStoreErrorKind::TooLarge));
            }
            bytes.extend_from_slice(&chunk);
        }
        let descriptor = BlobDescriptor::new(key.clone(), digest, stored_size, media_type.clone());
        let payload = BlobPayload::verify(descriptor, Bytes::from(bytes))
            .map_err(|_| BlobStoreError::new(BlobStoreErrorKind::Integrity))?;
        Ok(VerifiedBlob::from_payload(payload))
    }
}

const fn unavailable() -> BlobStoreError {
    BlobStoreError::new(BlobStoreErrorKind::Unavailable)
}

#[async_trait]
impl ImmutableBlobStore for S3BlobStore {
    async fn put_if_absent(&self, payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        let deadline = Instant::now() + self.operation_timeout;
        let descriptor = payload.descriptor().clone();
        let content_length = i64::try_from(descriptor.size())
            .map_err(|_| BlobStoreError::new(BlobStoreErrorKind::TooLarge))?;
        let checksum = STANDARD.encode(descriptor.digest().as_bytes());
        let request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(self.object_key(&descriptor))
            .if_none_match("*")
            .content_length(content_length)
            .content_type(descriptor.media_type().as_str())
            .checksum_sha256(checksum)
            .metadata(DIGEST_METADATA_KEY, descriptor.digest().to_string())
            .metadata(SIZE_METADATA_KEY, descriptor.size().to_string())
            .server_side_encryption(self.at_rest_encryption.algorithm())
            .body(ByteStream::from(payload.into_parts().1));
        let request = match self.at_rest_encryption.kms_key_id() {
            Some(key_id) => request.ssekms_key_id(key_id),
            None => request,
        };

        match timeout_at(deadline, request.send()).await {
            Ok(Ok(_)) => {
                self.verify_after_put(&descriptor, deadline).await?;
                Ok(PutBlobOutcome::Created)
            }
            Ok(Err(error)) if matches!(response_status(&error), Some(409 | 412)) => {
                self.verify_after_put(&descriptor, deadline)
                    .await
                    .map_err(existing_object_error)?;
                Ok(PutBlobOutcome::AlreadyPresent)
            }
            Ok(Err(error)) => Err(map_put_error(&error)),
            Err(_) => Err(BlobStoreError::new(BlobStoreErrorKind::Unavailable)),
        }
    }

    async fn get_verified(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        self.get_verified_before(
            descriptor,
            maximum_bytes,
            Instant::now() + self.operation_timeout,
        )
        .await
    }
}

#[async_trait]
impl ImmutableRecordStore for S3BlobStore {
    async fn get_record(
        &self,
        key: &BlobKey,
        media_type: &MediaType,
        maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        self.get_record_before(
            key,
            media_type,
            maximum_bytes,
            Instant::now() + self.operation_timeout,
        )
        .await
    }
}

#[async_trait]
impl ReclaimableBlobStore for S3BlobStore {
    async fn delete_if_present(&self, descriptor: &BlobDescriptor) -> Result<(), BlobStoreError> {
        let request = self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(self.object_key(descriptor));
        match timeout_at(Instant::now() + self.operation_timeout, request.send()).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => Err(map_delete_error(&error)),
            Err(_) => Err(BlobStoreError::new(BlobStoreErrorKind::Unavailable)),
        }
    }
}

fn existing_object_error(error: BlobStoreError) -> BlobStoreError {
    match error.kind() {
        BlobStoreErrorKind::Integrity | BlobStoreErrorKind::NotFound => {
            BlobStoreError::new(BlobStoreErrorKind::Conflict)
        }
        _ => error,
    }
}

fn response_status<E>(error: &SdkError<E>) -> Option<u16> {
    error
        .raw_response()
        .map(|response| response.status().as_u16())
}

fn map_put_error(
    error: &aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::put_object::PutObjectError>,
) -> BlobStoreError {
    map_sdk_error(
        response_status(error),
        error.as_service_error().and_then(|value| value.code()),
    )
}

fn map_get_error(
    error: &aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::get_object::GetObjectError>,
) -> BlobStoreError {
    map_sdk_error(
        response_status(error),
        error.as_service_error().and_then(|value| value.code()),
    )
}

fn map_delete_error(
    error: &aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::delete_object::DeleteObjectError>,
) -> BlobStoreError {
    map_sdk_error(
        response_status(error),
        error.as_service_error().and_then(|value| value.code()),
    )
}

fn map_sdk_error(status: Option<u16>, code: Option<&str>) -> BlobStoreError {
    let kind = match (status, code) {
        (Some(401 | 403), _) | (_, Some("AccessDenied")) => BlobStoreErrorKind::Unauthorized,
        (Some(404), _) | (_, Some("NoSuchKey" | "NoSuchBucket" | "NotFound")) => {
            BlobStoreErrorKind::NotFound
        }
        (Some(408 | 425 | 429 | 500..=599) | None, _) => BlobStoreErrorKind::Unavailable,
        _ => BlobStoreErrorKind::InvalidResponse,
    };
    BlobStoreError::new(kind)
}
