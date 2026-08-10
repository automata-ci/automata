use automata_ci_runner_transport::ClientTlsConfig;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
};
use thiserror::Error;

use super::{
    ClientTlsSources,
    files::{SecureInputError, read_public_material},
};

const MAX_CA_BUNDLE_BYTES: usize = 4 * 1024 * 1024;
const MAX_IDENTITY_CHAIN_BYTES: usize = 4 * 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES: usize = 1024 * 1024;
const MAX_ROOT_CERTIFICATES: usize = 256;
const MAX_IDENTITY_CERTIFICATES: usize = 32;

/// Sanitized failure while loading the explicit outbound mTLS identity.
#[derive(Debug, Error)]
pub enum ClientTlsMaterialError {
    /// A bounded source could not be loaded securely.
    #[error("runner TLS material source is unavailable")]
    Source(#[source] SecureInputError),
    /// The CA bundle was malformed, empty, or excessive.
    #[error("runner TLS root bundle is invalid")]
    InvalidRoots,
    /// The runner certificate chain was malformed, empty, or excessive.
    #[error("runner TLS certificate chain is invalid")]
    InvalidCertificateChain,
    /// The runner private key was malformed or unsupported.
    #[error("runner TLS private key is invalid")]
    InvalidPrivateKey,
    /// Rustls rejected the explicit identity or TLS policy.
    #[error("runner TLS client configuration is invalid")]
    InvalidConfiguration,
}

pub(crate) fn load_client_tls(
    sources: &ClientTlsSources,
) -> Result<ClientTlsConfig, ClientTlsMaterialError> {
    let roots_bytes = read_public_material(sources.server_roots(), MAX_CA_BUNDLE_BYTES)
        .map_err(ClientTlsMaterialError::Source)?;
    let mut roots = RootCertStore::empty();
    let mut root_count = 0_usize;
    for certificate in CertificateDer::pem_slice_iter(&roots_bytes) {
        root_count = root_count
            .checked_add(1)
            .ok_or(ClientTlsMaterialError::InvalidRoots)?;
        if root_count > MAX_ROOT_CERTIFICATES {
            return Err(ClientTlsMaterialError::InvalidRoots);
        }
        let certificate = certificate.map_err(|_| ClientTlsMaterialError::InvalidRoots)?;
        roots
            .add(certificate)
            .map_err(|_| ClientTlsMaterialError::InvalidRoots)?;
    }
    if root_count == 0 {
        return Err(ClientTlsMaterialError::InvalidRoots);
    }

    let chain_bytes = read_public_material(sources.certificate_chain(), MAX_IDENTITY_CHAIN_BYTES)
        .map_err(ClientTlsMaterialError::Source)?;
    let certificate_chain = CertificateDer::pem_slice_iter(&chain_bytes)
        .take(MAX_IDENTITY_CERTIFICATES + 1)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ClientTlsMaterialError::InvalidCertificateChain)?;
    if certificate_chain.is_empty() || certificate_chain.len() > MAX_IDENTITY_CERTIFICATES {
        return Err(ClientTlsMaterialError::InvalidCertificateChain);
    }

    let private_key_bytes = sources
        .private_key()
        .read(MAX_PRIVATE_KEY_BYTES)
        .map_err(ClientTlsMaterialError::Source)?;
    let private_key = PrivateKeyDer::from_pem_slice(&private_key_bytes)
        .map_err(|_| ClientTlsMaterialError::InvalidPrivateKey)?;
    ClientTlsConfig::new(roots, certificate_chain, private_key)
        .map_err(|_| ClientTlsMaterialError::InvalidConfiguration)
}
