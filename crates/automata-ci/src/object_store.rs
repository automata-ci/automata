use automata_ci_blob_s3::{
    S3AtRestEncryption, S3BlobStoreConfig, S3BlobStoreConfigError, StaticS3Credentials,
};
use aws_sdk_s3::Client;
use thiserror::Error;

use crate::server::{S3ConnectionConfig, SecretLoadError};

pub(crate) struct ConnectedObjectStore {
    pub(crate) client: Client,
    pub(crate) config: S3BlobStoreConfig,
}

pub(crate) fn connect(
    connection: &S3ConnectionConfig,
    prefix: Option<String>,
    at_rest_encryption: S3AtRestEncryption,
) -> Result<ConnectedObjectStore, ObjectStoreConnectionError> {
    let config = if connection.allow_loopback_http {
        S3BlobStoreConfig::loopback_development(
            connection.endpoint.clone(),
            connection.region.clone(),
            connection.bucket.clone(),
            prefix,
            connection.operation_timeout,
        )?
    } else {
        S3BlobStoreConfig::new(
            connection.endpoint.clone(),
            connection.region.clone(),
            connection.bucket.clone(),
            prefix,
            connection.force_path_style,
            connection.load_tls_trust()?,
            connection.operation_timeout,
        )?
    }
    .with_at_rest_encryption(at_rest_encryption);
    let access_key = connection.load_access_key()?;
    let secret_key = connection.load_secret_key()?;
    let session_token = connection.load_session_token()?;
    let credentials = StaticS3Credentials::new(
        access_key.as_str(),
        secret_key.as_str(),
        session_token
            .as_ref()
            .map(|value| value.as_str().to_owned()),
    )?;
    let client = config.client(credentials)?;
    Ok(ConnectedObjectStore { client, config })
}

#[derive(Debug, Error)]
pub(crate) enum ObjectStoreConnectionError {
    #[error("an object-store source could not be loaded")]
    Secret(#[from] SecretLoadError),
    #[error("object-store SDK configuration is invalid")]
    Configuration(#[from] S3BlobStoreConfigError),
}
