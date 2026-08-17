//! Broker-owned admission signing key.

use std::fmt;

use automata_ci_protocol::WindowsRunnerPlacementRenewalClaims;
use automata_ci_windows_broker_core::admission::WindowsBrokerAdmissionError;
use ring::signature::{Ed25519KeyPair, KeyPair as _};

/// Broker admission Ed25519 key retained outside ordinary configuration data.
pub struct WindowsBrokerAdmissionSigningKey {
    issuer_key_id: String,
    key_pair: Ed25519KeyPair,
}

impl WindowsBrokerAdmissionSigningKey {
    /// Opens one PKCS#8 Ed25519 signing key.
    ///
    /// Callers should supply bytes directly from service-account DPAPI
    /// custody and zeroize the source immediately after this call.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers or invalid PKCS#8 Ed25519 material.
    pub fn from_pkcs8(
        issuer_key_id: impl Into<String>,
        pkcs8: &[u8],
    ) -> Result<Self, WindowsBrokerAdmissionError> {
        let issuer_key_id = issuer_key_id.into();
        if !valid_authority_id(&issuer_key_id) {
            return Err(WindowsBrokerAdmissionError::InvalidRequest);
        }
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
        Ok(Self {
            issuer_key_id,
            key_pair,
        })
    }

    /// Returns the non-secret issuer key identifier.
    #[must_use]
    pub fn issuer_key_id(&self) -> &str {
        &self.issuer_key_id
    }

    /// Returns the Ed25519 public key for provisioning/audit checks.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        self.key_pair.public_key().as_ref()
    }

    pub(super) fn sign_admission(&self, payload: &[u8]) -> Vec<u8> {
        self.key_pair.sign(payload).as_ref().to_vec()
    }

    pub(super) fn sign_renewal(
        &self,
        claims: &WindowsRunnerPlacementRenewalClaims,
    ) -> Result<Vec<u8>, WindowsBrokerAdmissionError> {
        let bytes = claims
            .signing_bytes()
            .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        Ok(self.key_pair.sign(&bytes).as_ref().to_vec())
    }
}

impl fmt::Debug for WindowsBrokerAdmissionSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsBrokerAdmissionSigningKey")
            .field("issuer_key_id", &self.issuer_key_id)
            .field("key_pair", &"[SECRET]")
            .finish()
    }
}

fn valid_authority_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=128).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(byte))
}
