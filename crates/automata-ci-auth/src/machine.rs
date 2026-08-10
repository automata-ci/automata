use std::{fmt, future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::time::UnixTimestamp;

/// A bounded identity asserted by the external runner trust provider.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ExternalRunnerIdentity(String);

impl ExternalRunnerIdentity {
    /// Creates a validated identity asserted by the runner trust provider.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, or control-bearing identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, MachineIdentityError> {
        let value = value.into();
        if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
            return Err(MachineIdentityError::InvalidExternalIdentity);
        }
        Ok(Self(value))
    }

    /// Returns the provider-issued runner identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ExternalRunnerIdentity {
    type Error = MachineIdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ExternalRunnerIdentity> for String {
    fn from(value: ExternalRunnerIdentity) -> Self {
        value.0
    }
}

/// Identity established by the runner mTLS trust domain, never by a human session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "AuthenticatedMachineData")]
pub struct AuthenticatedMachine {
    /// Provider identity that must be mapped explicitly to an internal
    /// `automata_ci_core::RunnerId` before runner-authorized operations.
    external_identity: ExternalRunnerIdentity,
    certificate_sha256: [u8; 32],
    authenticated_at: UnixTimestamp,
    certificate_expires_at: UnixTimestamp,
}

#[derive(Deserialize)]
struct AuthenticatedMachineData {
    external_identity: ExternalRunnerIdentity,
    certificate_sha256: [u8; 32],
    authenticated_at: UnixTimestamp,
    certificate_expires_at: UnixTimestamp,
}

impl AuthenticatedMachine {
    /// Creates an authenticated machine assertion with a non-empty validity window.
    ///
    /// # Errors
    ///
    /// Returns an error unless the certificate expires after authentication.
    pub fn new(
        external_identity: ExternalRunnerIdentity,
        certificate_sha256: [u8; 32],
        authenticated_at: UnixTimestamp,
        certificate_expires_at: UnixTimestamp,
    ) -> Result<Self, MachineIdentityError> {
        if certificate_expires_at <= authenticated_at {
            return Err(MachineIdentityError::InvalidCertificateLifetime);
        }
        Ok(Self {
            external_identity,
            certificate_sha256,
            authenticated_at,
            certificate_expires_at,
        })
    }

    /// Returns the external identity that still requires internal runner mapping.
    pub const fn external_identity(&self) -> &ExternalRunnerIdentity {
        &self.external_identity
    }

    /// Returns the SHA-256 fingerprint of the authenticated leaf certificate.
    pub const fn certificate_sha256(&self) -> &[u8; 32] {
        &self.certificate_sha256
    }

    /// Returns when the trust provider authenticated the certificate.
    pub const fn authenticated_at(&self) -> UnixTimestamp {
        self.authenticated_at
    }

    /// Returns the authenticated certificate's expiry deadline.
    pub const fn certificate_expires_at(&self) -> UnixTimestamp {
        self.certificate_expires_at
    }

    /// Consumes the assertion into its external identity and certificate evidence.
    pub fn into_parts(
        self,
    ) -> (
        ExternalRunnerIdentity,
        [u8; 32],
        UnixTimestamp,
        UnixTimestamp,
    ) {
        (
            self.external_identity,
            self.certificate_sha256,
            self.authenticated_at,
            self.certificate_expires_at,
        )
    }
}

impl TryFrom<AuthenticatedMachineData> for AuthenticatedMachine {
    type Error = MachineIdentityError;

    fn try_from(value: AuthenticatedMachineData) -> Result<Self, Self::Error> {
        Self::new(
            value.external_identity,
            value.certificate_sha256,
            value.authenticated_at,
            value.certificate_expires_at,
        )
    }
}

/// Peer-certificate evidence supplied by the TLS terminator. Private keys must never
/// cross this boundary.
pub struct MachineAuthenticationEvidence {
    certificate_chain_der: Vec<Vec<u8>>,
}

impl MachineAuthenticationEvidence {
    /// Creates TLS evidence containing one or more non-empty DER certificates.
    ///
    /// # Errors
    ///
    /// Returns an error when the chain or any certificate is empty.
    pub fn new(certificate_chain_der: Vec<Vec<u8>>) -> Result<Self, MachineIdentityError> {
        if certificate_chain_der.is_empty() || certificate_chain_der.iter().any(Vec::is_empty) {
            return Err(MachineIdentityError::EmptyCertificateChain);
        }
        Ok(Self {
            certificate_chain_der,
        })
    }

    /// Returns the peer certificate chain in leaf-first DER form.
    pub fn certificate_chain_der(&self) -> &[Vec<u8>] {
        &self.certificate_chain_der
    }
}

impl fmt::Debug for MachineAuthenticationEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineAuthenticationEvidence")
            .field("certificate_count", &self.certificate_chain_der.len())
            .finish_non_exhaustive()
    }
}

/// A machine-authentication operation whose errors contain no credential data.
pub type MachineAuthenticationFuture<'a> = Pin<
    Box<dyn Future<Output = Result<AuthenticatedMachine, MachineAuthenticationError>> + Send + 'a>,
>;

/// Verifies transport-provided certificate evidence in the runner trust domain.
pub trait MachineIdentityVerifier: fmt::Debug + Send + Sync {
    /// Authenticates one peer certificate chain.
    fn authenticate<'a>(
        &'a self,
        evidence: &'a MachineAuthenticationEvidence,
    ) -> MachineAuthenticationFuture<'a>;
}

/// Validation failures for machine identity evidence and assertions.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MachineIdentityError {
    /// The trust-provider identity is empty, oversized, or contains controls.
    #[error("external runner identity is invalid")]
    InvalidExternalIdentity,
    #[error("certificate chain must contain only non-empty certificates")]
    /// The certificate chain or one of its certificates is empty.
    EmptyCertificateChain,
    /// The certificate was not valid after its authentication timestamp.
    #[error("certificate expiration must be after machine authentication")]
    InvalidCertificateLifetime,
}

/// Sanitized outcomes returned by the machine trust verifier.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MachineAuthenticationError {
    /// The presented credential is outside the configured trust domain.
    #[error("the machine credential is not trusted")]
    Untrusted,
    #[error("the machine credential has expired")]
    /// The presented credential is no longer valid.
    Expired,
    /// The verifier could not establish identity due to transient unavailability.
    #[error("the machine identity verifier is unavailable")]
    Unavailable,
}
