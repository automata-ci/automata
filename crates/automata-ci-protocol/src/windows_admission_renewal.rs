//! Domain-separated Windows placement-admission renewals.
//!
//! Enrollment receipts authorize one enrollment transaction and expire within
//! fifteen minutes. They are never reused as long-lived placement authority.
//! This module defines a distinct broker-signed renewal which can travel only
//! from an authenticated runner to control with a lease poll. Control must
//! still atomically consume its nonce, enforce the exact next serial, compare
//! promotion/revocation high-water state, and update its durable current head.

use automata_ci_core::{RunnerId, Sha256Digest};
use ring::signature;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    WindowsAdmissionValidity, WindowsRunnerAdmissionBinding, WindowsRunnerAdmissionEvidence,
    WindowsRunnerAdmissionTrustStore,
};

/// Current schema for a broker-signed placement renewal.
pub const WINDOWS_RUNNER_PLACEMENT_RENEWAL_SCHEMA_VERSION: u16 = 2;

const MAX_CANONICAL_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_ID_BYTES: usize = 128;
const ED25519_SIGNATURE_BYTES: usize = 64;
const SIGNING_DOMAIN: &[u8] = b"automata.windows-runner-placement-renewal.signature.v2\0";
const ENVELOPE_DIGEST_DOMAIN: &[u8] = b"automata.windows-runner-placement-renewal-envelope.v2\0";

/// Canonical claims for one independently refreshed placement admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsRunnerPlacementRenewalClaims {
    schema_version: u16,
    issuer_key_id: String,
    runner_id: RunnerId,
    renewal_serial: u64,
    nonce: Sha256Digest,
    enrollment_envelope_sha256: Sha256Digest,
    binding: WindowsRunnerAdmissionBinding,
    evidence: WindowsRunnerAdmissionEvidence,
    validity: WindowsAdmissionValidity,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedWindowsRunnerPlacementRenewalClaims {
    schema_version: u16,
    issuer_key_id: String,
    runner_id: RunnerId,
    renewal_serial: u64,
    nonce: Sha256Digest,
    enrollment_envelope_sha256: Sha256Digest,
    binding: WindowsRunnerAdmissionBinding,
    evidence: WindowsRunnerAdmissionEvidence,
    validity: WindowsAdmissionValidity,
}

impl<'de> Deserialize<'de> for WindowsRunnerPlacementRenewalClaims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedWindowsRunnerPlacementRenewalClaims::deserialize(deserializer)?;
        if value.schema_version != WINDOWS_RUNNER_PLACEMENT_RENEWAL_SCHEMA_VERSION {
            return Err(D::Error::custom(
                WindowsRunnerPlacementRenewalError::UnsupportedSchema,
            ));
        }
        Self::new(
            value.issuer_key_id,
            value.runner_id,
            value.renewal_serial,
            value.nonce,
            value.enrollment_envelope_sha256,
            value.binding,
            value.evidence,
            value.validity,
        )
        .map_err(D::Error::custom)
    }
}

impl WindowsRunnerPlacementRenewalClaims {
    /// Creates one exact renewal proposal ready for broker signing.
    ///
    /// # Errors
    ///
    /// Rejects placeholder identity/commitments, a zero serial, a runner
    /// substitution, a non-disabled network profile, or a horizon beyond the
    /// signed promotion expiry.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer_key_id: impl Into<String>,
        runner_id: RunnerId,
        renewal_serial: u64,
        nonce: Sha256Digest,
        enrollment_envelope_sha256: Sha256Digest,
        binding: WindowsRunnerAdmissionBinding,
        evidence: WindowsRunnerAdmissionEvidence,
        validity: WindowsAdmissionValidity,
    ) -> Result<Self, WindowsRunnerPlacementRenewalError> {
        let issuer_key_id = issuer_key_id.into();
        let broker_profile = binding.broker_profile();
        let promotion = binding.promotion();
        if !valid_id(&issuer_key_id)
            || runner_id.as_uuid().is_nil()
            || renewal_serial == 0
            || zero_digest(nonce)
            || zero_digest(enrollment_envelope_sha256)
            || binding.transaction().runner_id() != runner_id
            || !broker_profile.network_disabled()
            || validity.expires_at_unix_millis() > promotion.validity().expires_at_unix_millis()
        {
            return Err(WindowsRunnerPlacementRenewalError::InvalidClaims);
        }
        Ok(Self {
            schema_version: WINDOWS_RUNNER_PLACEMENT_RENEWAL_SCHEMA_VERSION,
            issuer_key_id,
            runner_id,
            renewal_serial,
            nonce,
            enrollment_envelope_sha256,
            binding,
            evidence,
            validity,
        })
    }

    /// Returns the renewal schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the broker signing-key identifier.
    #[must_use]
    pub fn issuer_key_id(&self) -> &str {
        &self.issuer_key_id
    }

    /// Returns the exact enrolled runner.
    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    /// Returns the broker-durable contiguous renewal serial.
    #[must_use]
    pub const fn renewal_serial(&self) -> u64 {
        self.renewal_serial
    }

    /// Returns the one-use renewal nonce.
    #[must_use]
    pub const fn nonce(&self) -> Sha256Digest {
        self.nonce
    }

    /// Returns the original verified enrollment-envelope commitment.
    #[must_use]
    pub const fn enrollment_envelope_sha256(&self) -> Sha256Digest {
        self.enrollment_envelope_sha256
    }

    /// Returns the exact enrolled broker/profile/promotion/capability binding.
    #[must_use]
    pub const fn binding(&self) -> &WindowsRunnerAdmissionBinding {
        &self.binding
    }

    /// Returns the freshly observed evidence digests.
    #[must_use]
    pub const fn evidence(&self) -> WindowsRunnerAdmissionEvidence {
        self.evidence
    }

    /// Returns the exclusive placement horizon, bounded to fifteen minutes.
    #[must_use]
    pub const fn validity(&self) -> WindowsAdmissionValidity {
        self.validity
    }

    /// Returns the canonical payload stored in the signed envelope.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or exceeds the fixed bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WindowsRunnerPlacementRenewalError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|_| WindowsRunnerPlacementRenewalError::InvalidCanonicalPayload)?;
        if bytes.is_empty() || bytes.len() > MAX_CANONICAL_PAYLOAD_BYTES {
            return Err(WindowsRunnerPlacementRenewalError::PayloadTooLarge);
        }
        Ok(bytes)
    }

    /// Returns the domain-separated bytes which the broker must sign.
    ///
    /// # Errors
    ///
    /// Returns an error if the canonical payload cannot be produced.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, WindowsRunnerPlacementRenewalError> {
        let payload = self.canonical_bytes()?;
        Ok(signing_bytes(&payload))
    }
}

/// Untrusted transport envelope for one Windows placement renewal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsRunnerPlacementRenewalEnvelope {
    schema_version: u16,
    issuer_key_id: String,
    signed_payload: Vec<u8>,
    authenticator: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedWindowsRunnerPlacementRenewalEnvelope {
    schema_version: u16,
    issuer_key_id: String,
    signed_payload: Vec<u8>,
    authenticator: Vec<u8>,
}

impl<'de> Deserialize<'de> for WindowsRunnerPlacementRenewalEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedWindowsRunnerPlacementRenewalEnvelope::deserialize(deserializer)?;
        if value.schema_version != WINDOWS_RUNNER_PLACEMENT_RENEWAL_SCHEMA_VERSION {
            return Err(D::Error::custom(
                WindowsRunnerPlacementRenewalError::UnsupportedSchema,
            ));
        }
        Self::new(
            value.issuer_key_id,
            value.signed_payload,
            value.authenticator,
        )
        .map_err(D::Error::custom)
    }
}

impl WindowsRunnerPlacementRenewalEnvelope {
    /// Wraps canonical renewal claims and one Ed25519 authenticator.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical issuer/payload, issuer substitution, oversized
    /// payload, or a non-Ed25519 authenticator length.
    pub fn new(
        issuer_key_id: impl Into<String>,
        signed_payload: Vec<u8>,
        authenticator: Vec<u8>,
    ) -> Result<Self, WindowsRunnerPlacementRenewalError> {
        let issuer_key_id = issuer_key_id.into();
        if !valid_id(&issuer_key_id) {
            return Err(WindowsRunnerPlacementRenewalError::InvalidIssuer);
        }
        if signed_payload.is_empty() || signed_payload.len() > MAX_CANONICAL_PAYLOAD_BYTES {
            return Err(WindowsRunnerPlacementRenewalError::PayloadTooLarge);
        }
        if authenticator.len() != ED25519_SIGNATURE_BYTES {
            return Err(WindowsRunnerPlacementRenewalError::InvalidAuthenticator);
        }
        let claims: WindowsRunnerPlacementRenewalClaims =
            serde_json::from_slice(&signed_payload)
                .map_err(|_| WindowsRunnerPlacementRenewalError::InvalidCanonicalPayload)?;
        if claims.canonical_bytes()? != signed_payload {
            return Err(WindowsRunnerPlacementRenewalError::NonCanonicalPayload);
        }
        if claims.issuer_key_id() != issuer_key_id {
            return Err(WindowsRunnerPlacementRenewalError::IssuerMismatch);
        }
        Ok(Self {
            schema_version: WINDOWS_RUNNER_PLACEMENT_RENEWAL_SCHEMA_VERSION,
            issuer_key_id,
            signed_payload,
            authenticator,
        })
    }

    /// Returns the renewal envelope schema.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the independently selected issuer key ID.
    #[must_use]
    pub fn issuer_key_id(&self) -> &str {
        &self.issuer_key_id
    }

    /// Returns the canonical signed claims payload.
    #[must_use]
    pub fn signed_payload(&self) -> &[u8] {
        &self.signed_payload
    }

    /// Returns the raw Ed25519 signature.
    #[must_use]
    pub fn authenticator(&self) -> &[u8] {
        &self.authenticator
    }

    /// Returns the domain-separated complete-envelope commitment.
    #[must_use]
    pub fn envelope_sha256(&self) -> Sha256Digest {
        envelope_digest(self)
    }

    /// Decodes the structurally validated canonical claims.
    ///
    /// # Errors
    ///
    /// Returns an error if an in-memory envelope was corrupted.
    pub fn claims(
        &self,
    ) -> Result<WindowsRunnerPlacementRenewalClaims, WindowsRunnerPlacementRenewalError> {
        serde_json::from_slice(&self.signed_payload)
            .map_err(|_| WindowsRunnerPlacementRenewalError::InvalidCanonicalPayload)
    }
}

/// Server-verified placement renewal.
///
/// This type is not sufficient by itself for placement. Control must commit it
/// atomically with nonce/serial/high-water checks before its current-admission
/// reader may expose the new head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedWindowsRunnerPlacementRenewal {
    claims: WindowsRunnerPlacementRenewalClaims,
    envelope_sha256: Sha256Digest,
}

impl VerifiedWindowsRunnerPlacementRenewal {
    /// Returns the authenticated renewal claims.
    #[must_use]
    pub const fn claims(&self) -> &WindowsRunnerPlacementRenewalClaims {
        &self.claims
    }

    /// Returns the complete signed-envelope commitment.
    #[must_use]
    pub const fn envelope_sha256(&self) -> Sha256Digest {
        self.envelope_sha256
    }
}

/// Verifies one renewal against the server-owned scoped broker trust store.
///
/// # Errors
///
/// Rejects unknown/scoped-substituted issuers, invalid signatures,
/// noncanonical claims, future/expired horizons, or expired promotion proof.
pub fn verify_windows_runner_placement_renewal(
    envelope: &WindowsRunnerPlacementRenewalEnvelope,
    trust_store: &dyn WindowsRunnerAdmissionTrustStore,
    now_unix_millis: u64,
) -> Result<VerifiedWindowsRunnerPlacementRenewal, WindowsRunnerPlacementRenewalError> {
    let claims = envelope.claims()?;
    if claims.issuer_key_id() != envelope.issuer_key_id() {
        return Err(WindowsRunnerPlacementRenewalError::IssuerMismatch);
    }
    let anchor = trust_store
        .admission_trust_anchor(envelope.issuer_key_id())
        .ok_or(WindowsRunnerPlacementRenewalError::UnknownIssuer)?;
    let broker = claims.binding().broker_profile();
    let promotion = claims.binding().promotion();
    if broker.broker_host_id() != anchor.broker_host_id()
        || broker.profile() != anchor.profile()
        || promotion.trust_bundle_id() != anchor.promotion_trust_bundle_id()
    {
        return Err(WindowsRunnerPlacementRenewalError::TrustScopeMismatch);
    }
    signature::UnparsedPublicKey::new(&signature::ED25519, anchor.ed25519_public_key())
        .verify(
            &signing_bytes(envelope.signed_payload()),
            envelope.authenticator(),
        )
        .map_err(|_| WindowsRunnerPlacementRenewalError::InvalidSignature)?;
    let validity = claims.validity();
    if validity.issued_at_unix_millis() > now_unix_millis {
        return Err(WindowsRunnerPlacementRenewalError::NotYetValid);
    }
    if now_unix_millis >= validity.expires_at_unix_millis() {
        return Err(WindowsRunnerPlacementRenewalError::Expired);
    }
    let promotion_validity = promotion.validity();
    if promotion_validity.issued_at_unix_millis() > now_unix_millis {
        return Err(WindowsRunnerPlacementRenewalError::NotYetValid);
    }
    if now_unix_millis >= promotion_validity.expires_at_unix_millis() {
        return Err(WindowsRunnerPlacementRenewalError::PromotionExpired);
    }
    Ok(VerifiedWindowsRunnerPlacementRenewal {
        envelope_sha256: envelope.envelope_sha256(),
        claims,
    })
}

/// Fail-closed renewal validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WindowsRunnerPlacementRenewalError {
    /// The message uses an unsupported schema.
    #[error("unsupported Windows placement-renewal schema")]
    UnsupportedSchema,
    /// A signed claim or nested binding is invalid.
    #[error("invalid Windows placement-renewal claims")]
    InvalidClaims,
    /// The issuer key ID is malformed.
    #[error("invalid Windows placement-renewal issuer")]
    InvalidIssuer,
    /// Payload bytes are missing or exceed the fixed budget.
    #[error("Windows placement-renewal payload is too large")]
    PayloadTooLarge,
    /// The payload cannot be decoded canonically.
    #[error("invalid Windows placement-renewal canonical payload")]
    InvalidCanonicalPayload,
    /// Decoded payload bytes are not the unique canonical representation.
    #[error("noncanonical Windows placement-renewal payload")]
    NonCanonicalPayload,
    /// Envelope and claims name different issuers.
    #[error("Windows placement-renewal issuer mismatch")]
    IssuerMismatch,
    /// The authenticator is not exactly one Ed25519 signature.
    #[error("invalid Windows placement-renewal authenticator")]
    InvalidAuthenticator,
    /// The server does not trust this issuer.
    #[error("unknown Windows placement-renewal issuer")]
    UnknownIssuer,
    /// The issuer is trusted for a different host/profile/trust bundle.
    #[error("Windows placement-renewal trust scope mismatch")]
    TrustScopeMismatch,
    /// Signature verification failed.
    #[error("invalid Windows placement-renewal signature")]
    InvalidSignature,
    /// The broker issue time is in the future.
    #[error("Windows placement renewal is not yet valid")]
    NotYetValid,
    /// The exclusive placement horizon passed.
    #[error("Windows placement renewal expired")]
    Expired,
    /// The signed image promotion expired.
    #[error("Windows placement renewal promotion expired")]
    PromotionExpired,
}

fn signing_bytes(payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SIGNING_DOMAIN.len() + 8 + payload.len());
    bytes.extend_from_slice(SIGNING_DOMAIN);
    bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn envelope_digest(envelope: &WindowsRunnerPlacementRenewalEnvelope) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(ENVELOPE_DIGEST_DOMAIN);
    for field in [
        envelope.issuer_key_id().as_bytes(),
        envelope.signed_payload(),
        envelope.authenticator(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn valid_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=MAX_ID_BYTES).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(byte))
}

fn zero_digest(value: Sha256Digest) -> bool {
    value.as_bytes().iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use automata_ci_core::{
        Architecture, EnvironmentProfile, EnvironmentProfileId, IsolationLevel, OperatingSystem,
        OperationId, RunnerCapabilities, RunnerFeature, RunnerPlatform, SandboxCapabilities,
        SandboxFeature,
    };
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair as _},
    };

    use super::*;
    use crate::{
        WINDOWS_RUNNER_ADMISSION_PROVIDER_ID, WindowsAdmissionImage,
        WindowsAuthorityAdmissionEvidence, WindowsBrokerAdmissionEvidence,
        WindowsBrokerProfileBinding, WindowsEnrollmentTransactionBinding,
        WindowsImagePromotionBinding, WindowsPromotionValidity, WindowsRunnerAdmissionTrustAnchor,
    };

    const NOW: u64 = 1_800_000_000_000;

    #[derive(Debug)]
    struct TrustStore(BTreeMap<String, WindowsRunnerAdmissionTrustAnchor>);

    impl WindowsRunnerAdmissionTrustStore for TrustStore {
        fn admission_trust_anchor(
            &self,
            issuer_key_id: &str,
        ) -> Option<WindowsRunnerAdmissionTrustAnchor> {
            self.0.get(issuer_key_id).cloned()
        }
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn key_pair() -> Ed25519KeyPair {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate key");
        Ed25519KeyPair::from_pkcs8(document.as_ref()).expect("parse key")
    }

    fn binding(runner_id: RunnerId, broker_host_id: &str) -> WindowsRunnerAdmissionBinding {
        let profile = EnvironmentProfile::new(
            EnvironmentProfileId::new("automata.example/windows-server-2025").expect("profile ID"),
            digest(4),
        );
        let capabilities = RunnerCapabilities::new(
            runner_id,
            RunnerPlatform::new(OperatingSystem::Windows, Architecture::X86_64),
        )
        .with_sandbox(SandboxCapabilities::new(
            IsolationLevel::VirtualMachine,
            [SandboxFeature::WINDOWS_HYPERV_CONTAINER],
        ))
        .with_features([RunnerFeature::SHELL_STEPS])
        .with_environment_profiles([profile.clone()]);
        let transaction = WindowsEnrollmentTransactionBinding::new(
            runner_id,
            OperationId::new(),
            "https://control.example.test/",
            "https://enroll.example.test/",
            digest(1),
            digest(2),
            digest(3),
        )
        .expect("transaction");
        let image_digest = digest(5);
        let image = WindowsAdmissionImage::new(
            format!("registry.example.test/automata/windows@sha256:{image_digest}"),
            image_digest,
        )
        .expect("image");
        let broker_profile = WindowsBrokerProfileBinding::new(
            broker_host_id,
            WINDOWS_RUNNER_ADMISSION_PROVIDER_ID,
            digest(6),
            profile,
            image,
            digest(7),
            true,
            false,
            64,
        )
        .expect("broker profile");
        let promotion = WindowsImagePromotionBinding::new(
            "production.windows.v1",
            "promotion-key-v1",
            digest(8),
            digest(9),
            41,
            19,
            WindowsPromotionValidity::new(NOW - 60_000, NOW + 3_600_000)
                .expect("promotion validity"),
        )
        .expect("promotion");
        WindowsRunnerAdmissionBinding::new(transaction, broker_profile, promotion, capabilities)
            .expect("binding")
    }

    fn evidence() -> WindowsRunnerAdmissionEvidence {
        let broker = WindowsBrokerAdmissionEvidence::new(
            digest(10),
            digest(11),
            digest(12),
            digest(13),
            digest(14),
        )
        .expect("broker evidence");
        let authority =
            WindowsAuthorityAdmissionEvidence::new(digest(15), digest(16), digest(17), digest(18))
                .expect("authority evidence");
        WindowsRunnerAdmissionEvidence::new(broker, authority)
    }

    fn claims(
        issuer: &str,
        runner_id: RunnerId,
        broker_host_id: &str,
        serial: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> WindowsRunnerPlacementRenewalClaims {
        WindowsRunnerPlacementRenewalClaims::new(
            issuer,
            runner_id,
            serial,
            digest(20),
            digest(21),
            binding(runner_id, broker_host_id),
            evidence(),
            WindowsAdmissionValidity::new(issued_at, expires_at).expect("validity"),
        )
        .expect("claims")
    }

    fn signed(
        issuer: &str,
        key_pair: &Ed25519KeyPair,
        claims: &WindowsRunnerPlacementRenewalClaims,
    ) -> WindowsRunnerPlacementRenewalEnvelope {
        let payload = claims.canonical_bytes().expect("canonical claims");
        WindowsRunnerPlacementRenewalEnvelope::new(
            issuer,
            payload,
            key_pair
                .sign(&claims.signing_bytes().expect("signing bytes"))
                .as_ref()
                .to_vec(),
        )
        .expect("envelope")
    }

    fn trust_store(issuer: &str, key_pair: &Ed25519KeyPair, broker_host_id: &str) -> TrustStore {
        let anchor = WindowsRunnerAdmissionTrustAnchor::new(
            key_pair
                .public_key()
                .as_ref()
                .try_into()
                .expect("public key"),
            broker_host_id,
            EnvironmentProfile::new(
                EnvironmentProfileId::new("automata.example/windows-server-2025")
                    .expect("profile ID"),
                digest(4),
            ),
            "production.windows.v1",
        )
        .expect("anchor");
        TrustStore(BTreeMap::from([(issuer.to_owned(), anchor)]))
    }

    #[test]
    fn verifies_exact_scoped_contiguous_renewal_envelope() {
        let issuer = "broker-admission-v1";
        let host = "a".repeat(64);
        let runner_id = RunnerId::new();
        let key_pair = key_pair();
        let claims = claims(issuer, runner_id, &host, 7, NOW - 1_000, NOW + 60_000);
        let envelope = signed(issuer, &key_pair, &claims);
        let verified = verify_windows_runner_placement_renewal(
            &envelope,
            &trust_store(issuer, &key_pair, &host),
            NOW,
        )
        .expect("verified renewal");

        assert_eq!(verified.claims(), &claims);
        assert_eq!(verified.claims().runner_id(), runner_id);
        assert_eq!(verified.claims().renewal_serial(), 7);
        assert_eq!(verified.envelope_sha256(), envelope.envelope_sha256());
        let encoded = serde_json::to_vec(&envelope).expect("serialize");
        assert_eq!(
            serde_json::from_slice::<WindowsRunnerPlacementRenewalEnvelope>(&encoded)
                .expect("deserialize"),
            envelope
        );
    }

    #[test]
    fn signature_scope_and_enrollment_commitment_substitution_fail_closed() {
        let issuer = "broker-admission-v1";
        let host = "a".repeat(64);
        let runner_id = RunnerId::new();
        let key_pair = key_pair();
        let claims = claims(issuer, runner_id, &host, 1, NOW - 1_000, NOW + 60_000);
        let envelope = signed(issuer, &key_pair, &claims);
        let trust = trust_store(issuer, &key_pair, &host);

        let forged = WindowsRunnerPlacementRenewalEnvelope::new(
            issuer,
            envelope.signed_payload().to_vec(),
            vec![0x5a; ED25519_SIGNATURE_BYTES],
        )
        .expect("structural envelope");
        assert_eq!(
            verify_windows_runner_placement_renewal(&forged, &trust, NOW),
            Err(WindowsRunnerPlacementRenewalError::InvalidSignature)
        );
        assert_eq!(
            verify_windows_runner_placement_renewal(
                &envelope,
                &trust_store(issuer, &key_pair, &"b".repeat(64)),
                NOW,
            ),
            Err(WindowsRunnerPlacementRenewalError::TrustScopeMismatch)
        );

        let substituted = WindowsRunnerPlacementRenewalClaims::new(
            issuer,
            runner_id,
            1,
            claims.nonce(),
            digest(22),
            claims.binding().clone(),
            claims.evidence(),
            claims.validity(),
        )
        .expect("substituted claims");
        let payload = substituted.canonical_bytes().expect("payload");
        let substituted = WindowsRunnerPlacementRenewalEnvelope::new(
            issuer,
            payload,
            envelope.authenticator().to_vec(),
        )
        .expect("structural envelope");
        assert_eq!(
            verify_windows_runner_placement_renewal(&substituted, &trust, NOW),
            Err(WindowsRunnerPlacementRenewalError::InvalidSignature)
        );
    }

    #[test]
    fn future_expired_unknown_and_noncanonical_renewals_are_rejected() {
        let issuer = "broker-admission-v1";
        let host = "a".repeat(64);
        let runner_id = RunnerId::new();
        let key_pair = key_pair();
        let future_claims = claims(issuer, runner_id, &host, 1, NOW + 1, NOW + 60_001);
        let future = signed(issuer, &key_pair, &future_claims);
        let trust = trust_store(issuer, &key_pair, &host);
        assert_eq!(
            verify_windows_runner_placement_renewal(&future, &trust, NOW),
            Err(WindowsRunnerPlacementRenewalError::NotYetValid)
        );

        let expired_claims = claims(issuer, runner_id, &host, 1, NOW - 60_000, NOW);
        let expired = signed(issuer, &key_pair, &expired_claims);
        assert_eq!(
            verify_windows_runner_placement_renewal(&expired, &trust, NOW),
            Err(WindowsRunnerPlacementRenewalError::Expired)
        );
        assert_eq!(
            verify_windows_runner_placement_renewal(&expired, &TrustStore(BTreeMap::new()), NOW,),
            Err(WindowsRunnerPlacementRenewalError::UnknownIssuer)
        );

        let mut noncanonical = b" \n".to_vec();
        noncanonical.extend(future_claims.canonical_bytes().expect("claims"));
        assert_eq!(
            WindowsRunnerPlacementRenewalEnvelope::new(
                issuer,
                noncanonical,
                vec![0x5a; ED25519_SIGNATURE_BYTES],
            ),
            Err(WindowsRunnerPlacementRenewalError::NonCanonicalPayload)
        );
        let mut outer = serde_json::to_value(future).expect("value");
        outer["future_field"] = serde_json::json!(true);
        let error = serde_json::from_value::<WindowsRunnerPlacementRenewalEnvelope>(outer)
            .expect_err("unknown envelope fields must be rejected");
        assert_eq!(error.classify(), serde_json::error::Category::Data);
    }

    #[test]
    fn zero_serial_and_horizon_past_promotion_are_invalid_claims() {
        let issuer = "broker-admission-v1";
        let host = "a".repeat(64);
        let runner_id = RunnerId::new();
        let exact = claims(issuer, runner_id, &host, 1, NOW - 1_000, NOW + 60_000);
        assert_eq!(
            WindowsRunnerPlacementRenewalClaims::new(
                issuer,
                runner_id,
                0,
                exact.nonce(),
                exact.enrollment_envelope_sha256(),
                exact.binding().clone(),
                exact.evidence(),
                exact.validity(),
            ),
            Err(WindowsRunnerPlacementRenewalError::InvalidClaims)
        );
        let mut binding = serde_json::to_value(exact.binding()).expect("binding value");
        binding["promotion"]["validity"]["expires_at_unix_millis"] = serde_json::json!(NOW + 500);
        let binding: WindowsRunnerAdmissionBinding =
            serde_json::from_value(binding).expect("short promotion binding");
        assert_eq!(
            WindowsRunnerPlacementRenewalClaims::new(
                issuer,
                runner_id,
                2,
                exact.nonce(),
                exact.enrollment_envelope_sha256(),
                binding,
                exact.evidence(),
                WindowsAdmissionValidity::new(NOW, NOW + 1_000).expect("validity"),
            ),
            Err(WindowsRunnerPlacementRenewalError::InvalidClaims)
        );
    }
}
