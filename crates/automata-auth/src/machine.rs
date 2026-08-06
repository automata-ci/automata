use std::{fmt, future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::time::UnixTimestamp;

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
    /// `automata_core::RunnerId` before runner-authorized operations.
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

    pub const fn external_identity(&self) -> &ExternalRunnerIdentity {
        &self.external_identity
    }

    pub const fn certificate_sha256(&self) -> &[u8; 32] {
        &self.certificate_sha256
    }

    pub const fn authenticated_at(&self) -> UnixTimestamp {
        self.authenticated_at
    }

    pub const fn certificate_expires_at(&self) -> UnixTimestamp {
        self.certificate_expires_at
    }

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

pub type MachineAuthenticationFuture<'a> = Pin<
    Box<dyn Future<Output = Result<AuthenticatedMachine, MachineAuthenticationError>> + Send + 'a>,
>;

pub trait MachineIdentityVerifier: fmt::Debug + Send + Sync {
    fn authenticate<'a>(
        &'a self,
        evidence: &'a MachineAuthenticationEvidence,
    ) -> MachineAuthenticationFuture<'a>;
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MachineIdentityError {
    #[error("external runner identity is invalid")]
    InvalidExternalIdentity,
    #[error("certificate chain must contain only non-empty certificates")]
    EmptyCertificateChain,
    #[error("certificate expiration must be after machine authentication")]
    InvalidCertificateLifetime,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MachineAuthenticationError {
    #[error("the machine credential is not trusted")]
    Untrusted,
    #[error("the machine credential has expired")]
    Expired,
    #[error("the machine identity verifier is unavailable")]
    Unavailable,
}
