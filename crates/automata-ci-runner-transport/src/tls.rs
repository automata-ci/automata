use std::{fmt, sync::Arc};

use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    version::TLS13,
};

use crate::ConfigurationError;

static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&TLS13];

fn reviewed_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = ring::default_provider();
    provider.cipher_suites = vec![ring::cipher_suite::TLS13_AES_256_GCM_SHA384];
    Arc::new(provider)
}

/// Reviewed rustls server configuration with mandatory `WebPKI` client authentication.
#[derive(Clone)]
pub struct ServerTlsConfig {
    inner: Arc<ServerConfig>,
    client_root_count: usize,
    certificate_count: usize,
}

impl ServerTlsConfig {
    /// Builds a server identity and mandatory client-certificate verifier.
    ///
    /// The trust store is explicit; platform roots are never loaded. The client
    /// verifier checks chain trust, validity, and client-auth purpose during the
    /// TLS handshake before any HTTP bytes are processed. ALPN offers only `h2`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] for an empty trust store, invalid identity,
    /// or unavailable TLS 1.3 support. Detailed cryptographic errors are
    /// intentionally not retained because they can contain credential metadata.
    pub fn new(
        client_roots: RootCertStore,
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, ConfigurationError> {
        if client_roots.is_empty() {
            return Err(ConfigurationError::InvalidTrustStore);
        }
        let client_root_count = client_roots.len();
        let certificate_count = certificate_chain.len();
        if certificate_count == 0 {
            return Err(ConfigurationError::InvalidIdentity);
        }

        let provider = reviewed_crypto_provider();
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(client_roots),
            Arc::clone(&provider),
        )
        .build()
        .map_err(|_| ConfigurationError::InvalidTrustStore)?;

        let mut inner = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(TLS13_ONLY)
            .map_err(|_| ConfigurationError::Tls13Unavailable)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificate_chain, private_key)
            .map_err(|_| ConfigurationError::InvalidIdentity)?;
        inner.alpn_protocols = vec![b"h2".to_vec()];

        Ok(Self {
            inner: Arc::new(inner),
            client_root_count,
            certificate_count,
        })
    }

    pub(crate) fn acceptor(&self) -> tokio_rustls::TlsAcceptor {
        tokio_rustls::TlsAcceptor::from(Arc::clone(&self.inner))
    }
}

impl fmt::Debug for ServerTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerTlsConfig")
            .field("protocol", &"TLSv1.3")
            .field("cipher_suite", &"TLS_AES_256_GCM_SHA384")
            .field("client_root_count", &self.client_root_count)
            .field("certificate_count", &self.certificate_count)
            .field("alpn", &"h2")
            .finish_non_exhaustive()
    }
}

/// Reviewed rustls runner-client configuration with explicit roots and mTLS identity.
#[derive(Clone)]
pub struct ClientTlsConfig {
    inner: ClientConfig,
    server_root_count: usize,
    certificate_count: usize,
}

impl ClientTlsConfig {
    /// Builds an outbound mTLS identity using only the supplied server roots.
    ///
    /// ALPN is deliberately left empty here and is set to exactly `h2` by the
    /// HTTP connector, which rejects any HTTP/1 fallback.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] for empty roots, invalid identity, or
    /// unavailable TLS 1.3 support. Private-key details are never included in errors.
    pub fn new(
        server_roots: RootCertStore,
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, ConfigurationError> {
        if server_roots.is_empty() {
            return Err(ConfigurationError::InvalidTrustStore);
        }
        let server_root_count = server_roots.len();
        let certificate_count = certificate_chain.len();
        if certificate_count == 0 {
            return Err(ConfigurationError::InvalidIdentity);
        }

        let provider = reviewed_crypto_provider();
        let inner = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(TLS13_ONLY)
            .map_err(|_| ConfigurationError::Tls13Unavailable)?
            .with_root_certificates(server_roots)
            .with_client_auth_cert(certificate_chain, private_key)
            .map_err(|_| ConfigurationError::InvalidIdentity)?;

        Ok(Self {
            inner,
            server_root_count,
            certificate_count,
        })
    }

    pub(crate) fn config(&self) -> ClientConfig {
        self.inner.clone()
    }
}

impl fmt::Debug for ClientTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientTlsConfig")
            .field("protocol", &"TLSv1.3")
            .field("cipher_suite", &"TLS_AES_256_GCM_SHA384")
            .field("server_root_count", &self.server_root_count)
            .field("certificate_count", &self.certificate_count)
            .field("alpn", &"h2")
            .finish_non_exhaustive()
    }
}
