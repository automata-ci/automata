//! Independent control-plane trust policy for Windows runner admission.

use std::{collections::BTreeMap, fmt};

use automata_ci_core::EnvironmentProfile;
use automata_ci_protocol::{WindowsRunnerAdmissionTrustAnchor, WindowsRunnerAdmissionTrustStore};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use thiserror::Error;

use super::SecretSource;

const CONFIG_SCHEMA: u16 = 1;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const MAX_ISSUER_ID_BYTES: usize = 128;
const MAX_ISSUERS: usize = 256;

/// Maximum encoded size of the strict Windows admission trust registry.
pub const MAX_WINDOWS_RUNNER_ADMISSION_CONFIG_BYTES: usize = 256 * 1_024;

/// Sanitized Windows admission trust-registry failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Windows runner admission trust configuration is invalid")]
pub struct WindowsRunnerAdmissionConfigError;

/// Immutable control-plane trust registry for broker-signed enrollment receipts.
#[derive(Clone)]
pub struct WindowsRunnerAdmissionPolicy {
    anchors: BTreeMap<String, WindowsRunnerAdmissionTrustAnchor>,
}

impl WindowsRunnerAdmissionPolicy {
    /// Loads one strict current registry through the bounded deployment-source boundary.
    ///
    /// # Errors
    ///
    /// Returns one sanitized error for unavailable or excessive input, malformed
    /// JSON, an unsupported schema, duplicate issuers or signing keys, or an
    /// invalid host/profile/promotion trust scope.
    pub fn load(source: &SecretSource) -> Result<Self, WindowsRunnerAdmissionConfigError> {
        let bytes = source
            .load_bytes(MAX_WINDOWS_RUNNER_ADMISSION_CONFIG_BYTES)
            .map_err(|_| WindowsRunnerAdmissionConfigError)?;
        Self::from_bytes(&bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, WindowsRunnerAdmissionConfigError> {
        let raw: RawConfig =
            serde_json::from_slice(bytes).map_err(|_| WindowsRunnerAdmissionConfigError)?;
        if raw.schema != CONFIG_SCHEMA || raw.issuers.is_empty() || raw.issuers.len() > MAX_ISSUERS
        {
            return Err(WindowsRunnerAdmissionConfigError);
        }

        let mut anchors = BTreeMap::new();
        let mut public_keys = std::collections::BTreeSet::new();
        for issuer in raw.issuers {
            if !valid_issuer_id(&issuer.issuer_key_id) {
                return Err(WindowsRunnerAdmissionConfigError);
            }
            let public_key = decode_public_key(&issuer.ed25519_public_key_base64)?;
            if !public_keys.insert(public_key) {
                return Err(WindowsRunnerAdmissionConfigError);
            }
            let anchor = WindowsRunnerAdmissionTrustAnchor::new(
                public_key,
                issuer.broker_host_id,
                issuer.environment_profile,
                issuer.promotion_trust_bundle_id,
            )
            .map_err(|_| WindowsRunnerAdmissionConfigError)?;
            if anchors.insert(issuer.issuer_key_id, anchor).is_some() {
                return Err(WindowsRunnerAdmissionConfigError);
            }
        }
        Ok(Self { anchors })
    }

    /// Returns the number of exact issuer scopes in this immutable registry.
    #[must_use]
    pub fn issuer_count(&self) -> usize {
        self.anchors.len()
    }
}

impl WindowsRunnerAdmissionTrustStore for WindowsRunnerAdmissionPolicy {
    fn admission_trust_anchor(
        &self,
        issuer_key_id: &str,
    ) -> Option<WindowsRunnerAdmissionTrustAnchor> {
        self.anchors.get(issuer_key_id).cloned()
    }
}

impl fmt::Debug for WindowsRunnerAdmissionPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsRunnerAdmissionPolicy")
            .field("schema", &CONFIG_SCHEMA)
            .field("issuer_count", &self.anchors.len())
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    schema: u16,
    issuers: Vec<RawIssuer>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIssuer {
    issuer_key_id: String,
    ed25519_public_key_base64: String,
    broker_host_id: String,
    environment_profile: EnvironmentProfile,
    promotion_trust_bundle_id: String,
}

fn valid_issuer_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && (3..=MAX_ISSUER_ID_BYTES).contains(&value.len())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn decode_public_key(
    encoded: &str,
) -> Result<[u8; ED25519_PUBLIC_KEY_BYTES], WindowsRunnerAdmissionConfigError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| WindowsRunnerAdmissionConfigError)?;
    let public_key: [u8; ED25519_PUBLIC_KEY_BYTES] = bytes
        .try_into()
        .map_err(|_| WindowsRunnerAdmissionConfigError)?;
    if URL_SAFE_NO_PAD.encode(public_key) != encoded {
        return Err(WindowsRunnerAdmissionConfigError);
    }
    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(issuers: &serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": 1,
            "issuers": issuers,
        }))
        .expect("trust manifest fixture")
    }

    fn issuer(key_id: &str, public_key: [u8; 32]) -> serde_json::Value {
        serde_json::json!({
            "issuer_key_id": key_id,
            "ed25519_public_key_base64": URL_SAFE_NO_PAD.encode(public_key),
            "broker_host_id": "11".repeat(32),
            "environment_profile": {
                "id": "automata/windows-server-2025",
                "digest": "22".repeat(32),
            },
            "promotion_trust_bundle_id": "windows-images-production",
        })
    }

    #[test]
    fn strict_registry_resolves_only_exact_scoped_issuer() {
        let policy =
            WindowsRunnerAdmissionPolicy::from_bytes(&manifest(&serde_json::json!([issuer(
                "broker-primary",
                [7; 32]
            ),])))
            .expect("strict trust registry");

        assert_eq!(policy.issuer_count(), 1);
        let anchor = policy
            .admission_trust_anchor("broker-primary")
            .expect("exact issuer must resolve");
        assert_eq!(anchor.ed25519_public_key(), &[7; 32]);
        assert_eq!(
            anchor.broker_host_id(),
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
        assert!(
            policy
                .admission_trust_anchor("broker-replacement")
                .is_none()
        );
    }

    #[test]
    fn registry_rejects_duplicate_keys_and_unknown_fields() {
        assert!(
            WindowsRunnerAdmissionPolicy::from_bytes(&manifest(&serde_json::json!([
                issuer("broker-primary", [7; 32]),
                issuer("broker-replacement", [7; 32]),
            ])))
            .is_err()
        );

        let mut value: serde_json::Value =
            serde_json::from_slice(&manifest(&serde_json::json!([issuer(
                "broker-primary",
                [7; 32]
            ),])))
            .expect("JSON fixture");
        value["unexpected"] = serde_json::json!(true);
        assert!(
            WindowsRunnerAdmissionPolicy::from_bytes(
                &serde_json::to_vec(&value).expect("JSON fixture")
            )
            .is_err()
        );
    }

    #[test]
    fn registry_rejects_noncanonical_key_encoding_and_empty_set() {
        assert!(
            WindowsRunnerAdmissionPolicy::from_bytes(&manifest(&serde_json::json!([]))).is_err()
        );
        let mut raw = issuer("broker-primary", [7; 32]);
        raw["ed25519_public_key_base64"] =
            serde_json::json!(format!("{}=", URL_SAFE_NO_PAD.encode([7; 32])));
        assert!(
            WindowsRunnerAdmissionPolicy::from_bytes(&manifest(&serde_json::json!([raw]))).is_err()
        );
    }
}
