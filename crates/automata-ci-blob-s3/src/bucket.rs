use aws_sdk_s3::{Client, error::SdkError};
use thiserror::Error;
use tokio::time::{Instant, timeout_at};

use crate::S3BlobStoreConfig;

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

/// Idempotently ensures that the configuration's exact bucket is accessible.
///
/// Only an HTTP not-found response to the initial `HeadBucket` can authorize a
/// `CreateBucket`. A creation conflict is treated as an ambiguous concurrent
/// race, never as success by itself; the final `HeadBucket` must still succeed.
/// Every SDK operation shares the configuration's single wall-clock deadline.
///
/// # Errors
///
/// Returns a sanitized stage-specific failure. Provider response bodies and
/// configuration values are not retained in the error.
pub async fn ensure_bucket(
    client: &Client,
    config: &S3BlobStoreConfig,
) -> Result<EnsureBucketOutcome, EnsureBucketError> {
    let deadline = Instant::now() + config.operation_timeout();
    let initial = timeout_at(
        deadline,
        client.head_bucket().bucket(config.bucket()).send(),
    )
    .await
    .map_err(|_| EnsureBucketError::Deadline)?;
    match initial {
        Ok(_) => return Ok(EnsureBucketOutcome::AlreadyExists),
        Err(error) if response_status(&error) == Some(404) => {}
        Err(_) => return Err(EnsureBucketError::InitialInspection),
    }

    let create = timeout_at(
        deadline,
        client.create_bucket().bucket(config.bucket()).send(),
    )
    .await
    .map_err(|_| EnsureBucketError::Deadline)?;
    let outcome = match create {
        Ok(_) => EnsureBucketOutcome::Created,
        Err(error) if response_status(&error) == Some(409) => EnsureBucketOutcome::AlreadyExists,
        Err(_) => return Err(EnsureBucketError::Creation),
    };

    timeout_at(
        deadline,
        client.head_bucket().bucket(config.bucket()).send(),
    )
    .await
    .map_err(|_| EnsureBucketError::Deadline)?
    .map_err(|_| EnsureBucketError::FinalInspection)?;
    Ok(outcome)
}

fn response_status<E>(error: &SdkError<E>) -> Option<u16> {
    error
        .raw_response()
        .map(|response| response.status().as_u16())
}
