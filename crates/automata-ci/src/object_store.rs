use automata_ci_blob_s3::{
    MAX_S3_PRIVATE_CA_PEM_BYTES, S3BlobStore, S3BlobStoreConfigError, S3TlsTrust,
    StaticS3Credentials,
};
use thiserror::Error;

use crate::server::{S3ConnectionConfig, S3Transport, SecretLoadError};

pub(crate) fn connect(
    connection: &S3ConnectionConfig,
) -> Result<S3BlobStore, ObjectStoreConnectionError> {
    let config = match connection.transport() {
        S3Transport::WebPki | S3Transport::LoopbackPlaintext => connection.store_config().clone(),
        S3Transport::PrivateCa { certificate_source } => {
            let tls_trust = certificate_source
                .load_bytes(MAX_S3_PRIVATE_CA_PEM_BYTES)
                .map(|pem| pem.to_vec())
                .and_then(|pem| {
                    S3TlsTrust::private_ca(pem).map_err(|_| SecretLoadError::InvalidCertificate)
                })?;
            connection
                .store_config()
                .clone()
                .with_tls_trust(tls_trust)?
        }
    };
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
