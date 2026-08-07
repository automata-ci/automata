use std::time::Duration;

use async_trait::async_trait;
use automata_blob::{
    BlobDescriptor, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    PutBlobOutcome, VerifiedBlob,
};
use aws_sdk_s3::{Client, error::ProvideErrorMetadata, primitives::ByteStream};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::{Bytes, BytesMut};
use tokio::time::{Instant, timeout_at};

use crate::S3BlobStoreConfig;

const DIGEST_METADATA_KEY: &str = "automata-sha256";
const SIZE_METADATA_KEY: &str = "automata-size";
const MAX_GET_ATTEMPTS: u32 = 3;

/// S3-compatible implementation of immutable blob operations.
#[derive(Clone, Debug)]
pub struct S3BlobStore {
    client: Client,
    bucket: String,
    prefix: Option<String>,
    operation_timeout: Duration,
}

impl S3BlobStore {
    /// Binds any externally configured SDK client to validated namespace policy.
    #[must_use]
    pub fn new(client: Client, config: &S3BlobStoreConfig) -> Self {
        Self {
            client,
            bucket: config.bucket().to_owned(),
            prefix: config.prefix().map(str::to_owned),
            operation_timeout: config.operation_timeout(),
        }
    }

    fn object_key(&self, descriptor: &BlobDescriptor) -> String {
        self.prefix.as_ref().map_or_else(
            || descriptor.key().as_str().to_owned(),
            |prefix| format!("{prefix}/{}", descriptor.key().as_str()),
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
            .body(ByteStream::from(payload.into_parts().1));

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

fn existing_object_error(error: BlobStoreError) -> BlobStoreError {
    match error.kind() {
        BlobStoreErrorKind::Integrity | BlobStoreErrorKind::NotFound => {
            BlobStoreError::new(BlobStoreErrorKind::Conflict)
        }
        _ => error,
    }
}

fn response_status<E>(error: &aws_sdk_s3::error::SdkError<E>) -> Option<u16> {
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
