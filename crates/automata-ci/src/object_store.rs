use automata_ci_blob_s3::{
    MAX_S3_PRIVATE_CA_PEM_BYTES, S3AtRestEncryption, S3BlobStore, S3BlobStoreConfig,
    S3BlobStoreConfigError, S3TlsTrust, StaticS3Credentials,
};
use thiserror::Error;

use crate::server::{S3ConnectionConfig, S3Transport, SecretLoadError};

pub(crate) fn connect(
    connection: &S3ConnectionConfig,
    prefix: Option<String>,
    at_rest_encryption: S3AtRestEncryption,
) -> Result<S3BlobStore, ObjectStoreConnectionError> {
    let config = match connection.transport() {
        S3Transport::WebPki => S3BlobStoreConfig::new(
            connection.endpoint().clone(),
            connection.region(),
            connection.bucket(),
            prefix,
            connection.force_path_style(),
            S3TlsTrust::web_pki(),
            connection.operation_timeout(),
        )?,
        S3Transport::PrivateCa { certificate_source } => {
            let tls_trust = certificate_source
                .load_bytes(MAX_S3_PRIVATE_CA_PEM_BYTES)
                .map(|pem| pem.to_vec())
                .and_then(|pem| {
                    S3TlsTrust::private_ca(pem).map_err(|_| SecretLoadError::InvalidCertificate)
                })?;
            S3BlobStoreConfig::new(
                connection.endpoint().clone(),
                connection.region(),
                connection.bucket(),
                prefix,
                connection.force_path_style(),
                tls_trust,
                connection.operation_timeout(),
            )?
        }
        S3Transport::LoopbackPlaintext => S3BlobStoreConfig::loopback_development(
            connection.endpoint().clone(),
            connection.region(),
            connection.bucket(),
            prefix,
            connection.operation_timeout(),
        )?,
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
    Ok(config.connect(credentials)?)
}

#[derive(Debug, Error)]
pub(crate) enum ObjectStoreConnectionError {
    #[error("an object-store source could not be loaded")]
    Secret(#[from] SecretLoadError),
    #[error("object-store SDK configuration is invalid")]
    Configuration(#[from] S3BlobStoreConfigError),
}
