//! Canonical, broker-signed Windows runner admission receipts.
//!
//! These values are deliberately transport-neutral. A runner may perform the
//! same verification as a fail-fast check, but only a control-plane verifier
//! with an independently configured trust store may derive registered
//! capabilities from [`VerifiedWindowsRunnerAdmission`]. Replay, one-use
//! nonce consumption, and promotion/revocation high-water marks are durable
//! control-plane policy and are intentionally outside this pure verifier.

use automata_ci_core::{
    EnvironmentProfile, OperatingSystem, OperationId, RunnerCapabilities, RunnerFeature, RunnerId,
    Sha256Digest,
};
use ring::signature;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use url::Url;

/// Schema version of the canonical Windows admission payload and envelope.
pub const WINDOWS_RUNNER_ADMISSION_SCHEMA_VERSION: u16 = 1;
/// Fixed sandbox provider authorized by this receipt contract.
pub const WINDOWS_RUNNER_ADMISSION_PROVIDER_ID: &str = "windows-hyperv";

const MAX_CANONICAL_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_ID_BYTES: usize = 128;
const MAX_ORIGIN_BYTES: usize = 2_048;
const MAX_IMAGE_REFERENCE_BYTES: usize = 2_048;
const MAX_ADMISSION_LIFETIME_MILLIS: u64 = 15 * 60 * 1_000;
const MAX_PROMOTION_LIFETIME_MILLIS: u64 = 7 * 24 * 60 * 60 * 1_000;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;
const RECEIPT_DIGEST_DOMAIN: &[u8] = b"automata.windows-runner-admission-envelope.v1\0";

/// Exact enrollment transaction named by the broker admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsEnrollmentTransactionBinding {
    runner_id: RunnerId,
    operation_id: OperationId,
    control_origin: String,
    enrollment_origin: String,
    runner_name_sha256: Sha256Digest,
    enrollment_token_sha256: Sha256Digest,
    csr_sha256: Sha256Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedWindowsEnrollmentTransactionBinding {
    runner_id: RunnerId,
    operation_id: OperationId,
    control_origin: String,
    enrollment_origin: String,
    runner_name_sha256: Sha256Digest,
    enrollment_token_sha256: Sha256Digest,
    csr_sha256: Sha256Digest,
}

impl<'de> Deserialize<'de> for WindowsEnrollmentTransactionBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedWindowsEnrollmentTransactionBinding::deserialize(deserializer)?;
        Self::new(
            value.runner_id,
            value.operation_id,
            value.control_origin,
            value.enrollment_origin,
            value.runner_name_sha256,
            value.enrollment_token_sha256,
            value.csr_sha256,
        )
        .map_err(D::Error::custom)
    }
}

impl WindowsEnrollmentTransactionBinding {
    /// Creates a value-free binding for one enrollment operation.
    ///
    /// # Errors
    ///
    /// Rejects nil identities, unsafe origins, and zero placeholder digests.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runner_id: RunnerId,
        operation_id: OperationId,
        control_origin: impl Into<String>,
        enrollment_origin: impl Into<String>,
        runner_name_sha256: Sha256Digest,
        enrollment_token_sha256: Sha256Digest,
        csr_sha256: Sha256Digest,
    ) -> Result<Self, WindowsRunnerAdmissionError> {
        let control_origin = control_origin.into();
        let enrollment_origin = enrollment_origin.into();
        if runner_id.as_uuid().is_nil()
            || operation_id.as_uuid().is_nil()
            || !valid_origin(&control_origin)
            || !valid_origin(&enrollment_origin)
            || [runner_name_sha256, enrollment_token_sha256, csr_sha256]
                .into_iter()
                .any(zero_digest)
        {
            return Err(WindowsRunnerAdmissionError::InvalidTransaction);
        }
        Ok(Self {
            runner_id,
            operation_id,
            control_origin,
            enrollment_origin,
            runner_name_sha256,
            enrollment_token_sha256,
            csr_sha256,
        })
    }

    /// Returns the admitted runner identity.
    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    /// Returns the one-use enrollment operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the exact control origin.
    #[must_use]
    pub fn control_origin(&self) -> &str {
        &self.control_origin
    }

    /// Returns the exact enrollment origin.
    #[must_use]
    pub fn enrollment_origin(&self) -> &str {
        &self.enrollment_origin
    }

    /// Returns the digest of the registered runner name.
    #[must_use]
    pub const fn runner_name_sha256(&self) -> Sha256Digest {
        self.runner_name_sha256
    }

    /// Returns the digest of the broker-custodied enrollment token.
    #[must_use]
    pub const fn enrollment_token_sha256(&self) -> Sha256Digest {
        self.enrollment_token_sha256
    }

    /// Returns the digest of the broker-custodied key's CSR.
    #[must_use]
    pub const fn csr_sha256(&self) -> Sha256Digest {
        self.csr_sha256
    }
}

/// Immutable digest-qualified Windows image identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsAdmissionImage {
    reference: String,
    digest: Sha256Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedWindowsAdmissionImage {
    reference: String,
    digest: Sha256Digest,
}

impl<'de> Deserialize<'de> for WindowsAdmissionImage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedWindowsAdmissionImage::deserialize(deserializer)?;
        Self::new(value.reference, value.digest).map_err(D::Error::custom)
    }
}

impl WindowsAdmissionImage {
    /// Creates an exact immutable image identity.
    ///
    /// # Errors
    ///
    /// Rejects mutable, malformed, oversized, or zero-digest references.
    pub fn new(
        reference: impl Into<String>,
        digest: Sha256Digest,
    ) -> Result<Self, WindowsRunnerAdmissionError> {
        let reference = reference.into();
        let suffix = format!("@sha256:{digest}");
        if zero_digest(digest)
            || reference.is_empty()
            || reference.len() > MAX_IMAGE_REFERENCE_BYTES
            || reference.trim() != reference
            || reference.chars().any(char::is_control)
            || !reference.ends_with(&suffix)
            || reference[..reference.len() - suffix.len()].is_empty()
        {
            return Err(WindowsRunnerAdmissionError::InvalidImage);
        }
        Ok(Self { reference, digest })
    }

    /// Returns the exact digest-qualified image reference.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Returns the exact image manifest digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// Broker and environment inputs covered by active admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsBrokerProfileBinding {
    broker_host_id: String,
    sandbox_provider_id: String,
    request_binding_sha256: Sha256Digest,
    profile: EnvironmentProfile,
    image: WindowsAdmissionImage,
    probe_contract_sha256: Sha256Digest,
    network_disabled: bool,
    sealed_action_trees: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedWindowsBrokerProfileBinding {
    broker_host_id: String,
    sandbox_provider_id: String,
    request_binding_sha256: Sha256Digest,
    profile: EnvironmentProfile,
    image: WindowsAdmissionImage,
    probe_contract_sha256: Sha256Digest,
    network_disabled: bool,
    sealed_action_trees: bool,
}

impl<'de> Deserialize<'de> for WindowsBrokerProfileBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedWindowsBrokerProfileBinding::deserialize(deserializer)?;
        Self::new(
            value.broker_host_id,
            value.sandbox_provider_id,
            value.request_binding_sha256,
            value.profile,
            value.image,
            value.probe_contract_sha256,
            value.network_disabled,
            value.sealed_action_trees,
        )
        .map_err(D::Error::custom)
    }
}

impl WindowsBrokerProfileBinding {
    /// Creates the exact broker/profile request binding.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical broker identity, another provider, placeholder
    /// digests, or a profile which allows network access.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        broker_host_id: impl Into<String>,
        sandbox_provider_id: impl Into<String>,
        request_binding_sha256: Sha256Digest,
        profile: EnvironmentProfile,
        image: WindowsAdmissionImage,
        probe_contract_sha256: Sha256Digest,
        network_disabled: bool,
        sealed_action_trees: bool,
    ) -> Result<Self, WindowsRunnerAdmissionError> {
        let broker_host_id = broker_host_id.into();
        let sandbox_provider_id = sandbox_provider_id.into();
        if !is_lower_hex_64(&broker_host_id)
            || sandbox_provider_id != WINDOWS_RUNNER_ADMISSION_PROVIDER_ID
            || zero_digest(request_binding_sha256)
            || zero_digest(profile.digest())
            || zero_digest(probe_contract_sha256)
            || !network_disabled
        {
            return Err(WindowsRunnerAdmissionError::InvalidBrokerProfile);
        }
        Ok(Self {
            broker_host_id,
            sandbox_provider_id,
            request_binding_sha256,
            profile,
            image,
            probe_contract_sha256,
            network_disabled,
            sealed_action_trees,
        })
    }

    /// Returns the canonical broker host identity.
    #[must_use]
    pub fn broker_host_id(&self) -> &str {
        &self.broker_host_id
    }

    /// Returns the fixed sandbox provider identity.
    #[must_use]
    pub fn sandbox_provider_id(&self) -> &str {
        &self.sandbox_provider_id
    }

    /// Returns the digest of the complete runner-to-broker admission request.
    #[must_use]
    pub const fn request_binding_sha256(&self) -> Sha256Digest {
        self.request_binding_sha256
    }

    /// Returns the exact admitted environment profile.
    #[must_use]
    pub const fn profile(&self) -> &EnvironmentProfile {
        &self.profile
    }

    /// Returns the exact admitted image.
    #[must_use]
    pub const fn image(&self) -> &WindowsAdmissionImage {
        &self.image
    }

    /// Returns the shared live-probe contract digest.
    #[must_use]
    pub const fn probe_contract_sha256(&self) -> Sha256Digest {
        self.probe_contract_sha256
    }

    /// Reports whether the admitted profile is network-disabled.
    #[must_use]
    pub const fn network_disabled(&self) -> bool {
        self.network_disabled
    }

    /// Reports whether the broker attested its opaque, ledger-bound sealed
    /// action-tree materialization contract for this exact profile.
    #[must_use]
    pub const fn sealed_action_trees(&self) -> bool {
        self.sealed_action_trees
    }
}

/// Signed promotion validity window.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsPromotionValidity {
    issued_at_unix_millis: u64,
    expires_at_unix_millis: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedWindowsPromotionValidity {
    issued_at_unix_millis: u64,
    expires_at_unix_millis: u64,
}

impl<'de> Deserialize<'de> for WindowsPromotionValidity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedWindowsPromotionValidity::deserialize(deserializer)?;
        Self::new(value.issued_at_unix_millis, value.expires_at_unix_millis)
            .map_err(D::Error::custom)
    }
}

impl WindowsPromotionValidity {
    /// Creates a bounded signed promotion window.
    ///
    /// # Errors
    ///
    /// Rejects zero, inverted, or overlong validity windows.
    pub fn new(
        issued_at_unix_millis: u64,
        expires_at_unix_millis: u64,
    ) -> Result<Self, WindowsRunnerAdmissionError> {
        validate_window(
            issued_at_unix_millis,
            expires_at_unix_millis,
            MAX_PROMOTION_LIFETIME_MILLIS,
        )?;
        Ok(Self {
            issued_at_unix_millis,
            expires_at_unix_millis,
        })
    }

    /// Returns the signed issue timestamp.
    #[must_use]
    pub const fn issued_at_unix_millis(self) -> u64 {
        self.issued_at_unix_millis
    }

    /// Returns the signed expiry timestamp.
    #[must_use]
    pub const fn expires_at_unix_millis(self) -> u64 {
        self.expires_at_unix_millis
    }
}

/// Broker-verified image promotion identity and anti-rollback coordinates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsImagePromotionBinding {
    trust_bundle_id: String,
    key_id: String,
    payload_sha256: Sha256Digest,
    envelope_sha256: Sha256Digest,
    promotion_serial: u64,
    revocation_generation: u64,
    validity: WindowsPromotionValidity,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedWindowsImagePromotionBinding {
    trust_bundle_id: String,
    key_id: String,
    payload_sha256: Sha256Digest,
    envelope_sha256: Sha256Digest,
    promotion_serial: u64,
    revocation_generation: u64,
    validity: WindowsPromotionValidity,
}

impl<'de> Deserialize<'de> for WindowsImagePromotionBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedWindowsImagePromotionBinding::deserialize(deserializer)?;
        Self::new(
            value.trust_bundle_id,
            value.key_id,
            value.payload_sha256,
            value.envelope_sha256,
            value.promotion_serial,
            value.revocation_generation,
            value.validity,
        )
        .map_err(D::Error::custom)
    }
}

impl WindowsImagePromotionBinding {
    /// Creates the exact promotion and revocation binding.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical authority IDs, placeholders, or zero generations.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trust_bundle_id: impl Into<String>,
        key_id: impl Into<String>,
        payload_sha256: Sha256Digest,
        envelope_sha256: Sha256Digest,
        promotion_serial: u64,
        revocation_generation: u64,
        validity: WindowsPromotionValidity,
    ) -> Result<Self, WindowsRunnerAdmissionError> {
        let trust_bundle_id = trust_bundle_id.into();
        let key_id = key_id.into();
        if !valid_id(&trust_bundle_id)
            || !valid_id(&key_id)
            || zero_digest(payload_sha256)
            || zero_digest(envelope_sha256)
            || promotion_serial == 0
            || revocation_generation == 0
        {
            return Err(WindowsRunnerAdmissionError::InvalidPromotion);
        }
        Ok(Self {
            trust_bundle_id,
            key_id,
            payload_sha256,
            envelope_sha256,
            promotion_serial,
            revocation_generation,
            validity,
        })
    }

    /// Returns the broker/control-owned trust-bundle identity.
    #[must_use]
    pub fn trust_bundle_id(&self) -> &str {
        &self.trust_bundle_id
    }

    /// Returns the selected promotion key identity.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the canonical promotion payload digest.
    #[must_use]
    pub const fn payload_sha256(&self) -> Sha256Digest {
        self.payload_sha256
    }

    /// Returns the complete promotion envelope digest.
    #[must_use]
    pub const fn envelope_sha256(&self) -> Sha256Digest {
        self.envelope_sha256
    }

    /// Returns the broker-advanced promotion serial.
    #[must_use]
    pub const fn promotion_serial(&self) -> u64 {
        self.promotion_serial
    }

    /// Returns the broker-advanced revocation generation.
    #[must_use]
    pub const fn revocation_generation(&self) -> u64 {
        self.revocation_generation
    }

    /// Returns the signed promotion validity window.
    #[must_use]
    pub const fn validity(&self) -> WindowsPromotionValidity {
        self.validity
    }
}

/// Exact binding whose capabilities may be registered after server verification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsRunnerAdmissionBinding {
    transaction: WindowsEnrollmentTransactionBinding,
    broker_profile: WindowsBrokerProfileBinding,
    promotion: WindowsImagePromotionBinding,
    capabilities: RunnerCapabilities,
    capabilities_sha256: Sha256Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedWindowsRunnerAdmissionBinding {
    transaction: WindowsEnrollmentTransactionBinding,
    broker_profile: WindowsBrokerProfileBinding,
    promotion: WindowsImagePromotionBinding,
    capabilities: RunnerCapabilities,
    capabilities_sha256: Sha256Digest,
}

impl<'de> Deserialize<'de> for WindowsRunnerAdmissionBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedWindowsRunnerAdmissionBinding::deserialize(deserializer)?;
        let binding = Self::new(
            value.transaction,
            value.broker_profile,
            value.promotion,
            value.capabilities,
        )
        .map_err(D::Error::custom)?;
        if binding.capabilities_sha256 != value.capabilities_sha256 {
            return Err(D::Error::custom(
                WindowsRunnerAdmissionError::CapabilityDigestMismatch,
            ));
        }
        Ok(binding)
    }
}

impl WindowsRunnerAdmissionBinding {
    /// Creates and validates the exact capability-bearing admission binding.
    ///
    /// # Errors
    ///
    /// Rejects invalid, non-Windows, wrong-runner, profile-superset, or
    /// workspace-local-action capability advertisements.
    pub fn new(
        transaction: WindowsEnrollmentTransactionBinding,
        broker_profile: WindowsBrokerProfileBinding,
        promotion: WindowsImagePromotionBinding,
        capabilities: RunnerCapabilities,
    ) -> Result<Self, WindowsRunnerAdmissionError> {
        capabilities
            .validate()
            .map_err(|_| WindowsRunnerAdmissionError::InvalidCapabilities)?;
        if capabilities.runner_id() != transaction.runner_id
            || capabilities.platform().operating_system() != &OperatingSystem::Windows
            || capabilities.environment_profiles().len() != 1
            || !capabilities
                .environment_profiles()
                .contains(&broker_profile.profile)
            || capabilities
                .features()
                .contains(&RunnerFeature::LOCAL_ACTIONS)
            || !valid_action_feature_relationships(&capabilities)
            || (has_action_features(&capabilities) && !broker_profile.sealed_action_trees)
        {
            return Err(WindowsRunnerAdmissionError::InvalidCapabilities);
        }
        let capabilities_sha256 = canonical_capabilities_digest(&capabilities)?;
        Ok(Self {
            transaction,
            broker_profile,
            promotion,
            capabilities,
            capabilities_sha256,
        })
    }

    /// Returns the exact enrollment transaction.
    #[must_use]
    pub const fn transaction(&self) -> &WindowsEnrollmentTransactionBinding {
        &self.transaction
    }

    /// Returns the exact broker and environment-profile binding.
    #[must_use]
    pub const fn broker_profile(&self) -> &WindowsBrokerProfileBinding {
        &self.broker_profile
    }

    /// Returns the exact verified image promotion binding.
    #[must_use]
    pub const fn promotion(&self) -> &WindowsImagePromotionBinding {
        &self.promotion
    }

    /// Returns the exact capability set authenticated by the broker.
    #[must_use]
    pub const fn capabilities(&self) -> &RunnerCapabilities {
        &self.capabilities
    }

    /// Returns the digest of the canonical capability serialization.
    #[must_use]
    pub const fn capabilities_sha256(&self) -> Sha256Digest {
        self.capabilities_sha256
    }
}

/// Broker-owned host, image, network, and profile evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_field_names)]
pub struct WindowsBrokerAdmissionEvidence {
    broker_attestation_sha256: Sha256Digest,
    host_input_attestation_sha256: Sha256Digest,
    image_attestation_sha256: Sha256Digest,
    network_attestation_sha256: Sha256Digest,
    profile_contract_sha256: Sha256Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
struct UncheckedWindowsBrokerAdmissionEvidence {
    broker_attestation_sha256: Sha256Digest,
    host_input_attestation_sha256: Sha256Digest,
    image_attestation_sha256: Sha256Digest,
    network_attestation_sha256: Sha256Digest,
    profile_contract_sha256: Sha256Digest,
}

impl<'de> Deserialize<'de> for WindowsBrokerAdmissionEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedWindowsBrokerAdmissionEvidence::deserialize(deserializer)?;
        Self::new(
            value.broker_attestation_sha256,
            value.host_input_attestation_sha256,
            value.image_attestation_sha256,
            value.network_attestation_sha256,
            value.profile_contract_sha256,
        )
        .map_err(D::Error::custom)
    }
}

impl WindowsBrokerAdmissionEvidence {
    /// Creates broker evidence with no placeholder digest.
    ///
    /// # Errors
    ///
    /// Rejects any zero evidence digest.
    pub fn new(
        broker_attestation_sha256: Sha256Digest,
        host_input_attestation_sha256: Sha256Digest,
        image_attestation_sha256: Sha256Digest,
        network_attestation_sha256: Sha256Digest,
        profile_contract_sha256: Sha256Digest,
    ) -> Result<Self, WindowsRunnerAdmissionError> {
        if [
            broker_attestation_sha256,
            host_input_attestation_sha256,
            image_attestation_sha256,
            network_attestation_sha256,
            profile_contract_sha256,
        ]
        .into_iter()
        .any(zero_digest)
        {
            return Err(WindowsRunnerAdmissionError::InvalidEvidence);
        }
        Ok(Self {
            broker_attestation_sha256,
            host_input_attestation_sha256,
            image_attestation_sha256,
            network_attestation_sha256,
            profile_contract_sha256,
        })
    }

    /// Returns the broker identity/profile attestation digest.
    #[must_use]
    pub const fn broker_attestation_sha256(self) -> Sha256Digest {
        self.broker_attestation_sha256
    }

    /// Returns the ordered host-input ACL/file-ID attestation digest.
    #[must_use]
    pub const fn host_input_attestation_sha256(self) -> Sha256Digest {
        self.host_input_attestation_sha256
    }

    /// Returns the image/toolchain admission attestation digest.
    #[must_use]
    pub const fn image_attestation_sha256(self) -> Sha256Digest {
        self.image_attestation_sha256
    }

    /// Returns the disabled-network attestation digest.
    #[must_use]
    pub const fn network_attestation_sha256(self) -> Sha256Digest {
        self.network_attestation_sha256
    }

    /// Returns the exact broker-minted launch/profile contract digest.
    #[must_use]
    pub const fn profile_contract_sha256(self) -> Sha256Digest {
        self.profile_contract_sha256
    }
}

/// Control-authority, promotion-key, and cleanup evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_field_names)]
pub struct WindowsAuthorityAdmissionEvidence {
    authority_attestation_sha256: Sha256Digest,
    promotion_trust_bundle_sha256: Sha256Digest,
    promotion_public_key_sha256: Sha256Digest,
    cleanup_receipt_sha256: Sha256Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
struct UncheckedWindowsAuthorityAdmissionEvidence {
    authority_attestation_sha256: Sha256Digest,
    promotion_trust_bundle_sha256: Sha256Digest,
    promotion_public_key_sha256: Sha256Digest,
    cleanup_receipt_sha256: Sha256Digest,
}

impl<'de> Deserialize<'de> for WindowsAuthorityAdmissionEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedWindowsAuthorityAdmissionEvidence::deserialize(deserializer)?;
        Self::new(
            value.authority_attestation_sha256,
            value.promotion_trust_bundle_sha256,
            value.promotion_public_key_sha256,
            value.cleanup_receipt_sha256,
        )
        .map_err(D::Error::custom)
    }
}

impl WindowsAuthorityAdmissionEvidence {
    /// Creates authority evidence with no placeholder digest.
    ///
    /// # Errors
    ///
    /// Rejects any zero evidence digest.
    pub fn new(
        authority_attestation_sha256: Sha256Digest,
        promotion_trust_bundle_sha256: Sha256Digest,
        promotion_public_key_sha256: Sha256Digest,
        cleanup_receipt_sha256: Sha256Digest,
    ) -> Result<Self, WindowsRunnerAdmissionError> {
        if [
            authority_attestation_sha256,
            promotion_trust_bundle_sha256,
            promotion_public_key_sha256,
            cleanup_receipt_sha256,
        ]
        .into_iter()
        .any(zero_digest)
        {
            return Err(WindowsRunnerAdmissionError::InvalidEvidence);
        }
        Ok(Self {
            authority_attestation_sha256,
            promotion_trust_bundle_sha256,
            promotion_public_key_sha256,
            cleanup_receipt_sha256,
        })
    }

    /// Returns the control-authority admission digest.
    #[must_use]
    pub const fn authority_attestation_sha256(self) -> Sha256Digest {
        self.authority_attestation_sha256
    }

    /// Returns the broker/control-owned trust-bundle digest.
    #[must_use]
    pub const fn promotion_trust_bundle_sha256(self) -> Sha256Digest {
        self.promotion_trust_bundle_sha256
    }

    /// Returns the exact approved promotion public-key digest.
    #[must_use]
    pub const fn promotion_public_key_sha256(self) -> Sha256Digest {
        self.promotion_public_key_sha256
    }

    /// Returns the durable cleanup/tombstone commitment digest.
    #[must_use]
    pub const fn cleanup_receipt_sha256(self) -> Sha256Digest {
        self.cleanup_receipt_sha256
    }
}

/// Complete evidence set authenticated by the broker receipt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRunnerAdmissionEvidence {
    broker: WindowsBrokerAdmissionEvidence,
    authority: WindowsAuthorityAdmissionEvidence,
}

impl WindowsRunnerAdmissionEvidence {
    /// Combines independently validated broker and authority evidence.
    #[must_use]
    pub const fn new(
        broker: WindowsBrokerAdmissionEvidence,
        authority: WindowsAuthorityAdmissionEvidence,
    ) -> Self {
        Self { broker, authority }
    }

    /// Returns host, image, network, and profile evidence.
    #[must_use]
    pub const fn broker(self) -> WindowsBrokerAdmissionEvidence {
        self.broker
    }

    /// Returns control, trust-root, and cleanup evidence.
    #[must_use]
    pub const fn authority(self) -> WindowsAuthorityAdmissionEvidence {
        self.authority
    }
}

/// Short-lived broker receipt validity window.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsAdmissionValidity {
    issued_at_unix_millis: u64,
    expires_at_unix_millis: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedWindowsAdmissionValidity {
    issued_at_unix_millis: u64,
    expires_at_unix_millis: u64,
}

impl<'de> Deserialize<'de> for WindowsAdmissionValidity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedWindowsAdmissionValidity::deserialize(deserializer)?;
        Self::new(value.issued_at_unix_millis, value.expires_at_unix_millis)
            .map_err(D::Error::custom)
    }
}

impl WindowsAdmissionValidity {
    /// Creates a short-lived receipt window.
    ///
    /// # Errors
    ///
    /// Rejects zero, inverted, or overlong windows.
    pub fn new(
        issued_at_unix_millis: u64,
        expires_at_unix_millis: u64,
    ) -> Result<Self, WindowsRunnerAdmissionError> {
        validate_window(
            issued_at_unix_millis,
            expires_at_unix_millis,
            MAX_ADMISSION_LIFETIME_MILLIS,
        )?;
        Ok(Self {
            issued_at_unix_millis,
            expires_at_unix_millis,
        })
    }

    /// Returns the broker issue time.
    #[must_use]
    pub const fn issued_at_unix_millis(self) -> u64 {
        self.issued_at_unix_millis
    }

    /// Returns the broker expiry time.
    #[must_use]
    pub const fn expires_at_unix_millis(self) -> u64 {
        self.expires_at_unix_millis
    }
}

/// Canonical claims signed by the Windows broker admission authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsRunnerAdmissionClaims {
    schema_version: u16,
    issuer_key_id: String,
    nonce: Sha256Digest,
    custody_handle_sha256: Sha256Digest,
    completion_nonce_sha256: Sha256Digest,
    binding: WindowsRunnerAdmissionBinding,
    evidence: WindowsRunnerAdmissionEvidence,
    validity: WindowsAdmissionValidity,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedWindowsRunnerAdmissionClaims {
    schema_version: u16,
    issuer_key_id: String,
    nonce: Sha256Digest,
    custody_handle_sha256: Sha256Digest,
    completion_nonce_sha256: Sha256Digest,
    binding: WindowsRunnerAdmissionBinding,
    evidence: WindowsRunnerAdmissionEvidence,
    validity: WindowsAdmissionValidity,
}

impl<'de> Deserialize<'de> for WindowsRunnerAdmissionClaims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedWindowsRunnerAdmissionClaims::deserialize(deserializer)?;
        if value.schema_version != WINDOWS_RUNNER_ADMISSION_SCHEMA_VERSION {
            return Err(D::Error::custom(
                WindowsRunnerAdmissionError::UnsupportedSchema,
            ));
        }
        Self::new(
            value.issuer_key_id,
            value.nonce,
            value.custody_handle_sha256,
            value.completion_nonce_sha256,
            value.binding,
            value.evidence,
            value.validity,
        )
        .map_err(D::Error::custom)
    }
}

impl WindowsRunnerAdmissionClaims {
    /// Creates complete canonical claims ready for broker signing.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical issuer or placeholder nonce/commitment.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer_key_id: impl Into<String>,
        nonce: Sha256Digest,
        custody_handle_sha256: Sha256Digest,
        completion_nonce_sha256: Sha256Digest,
        binding: WindowsRunnerAdmissionBinding,
        evidence: WindowsRunnerAdmissionEvidence,
        validity: WindowsAdmissionValidity,
    ) -> Result<Self, WindowsRunnerAdmissionError> {
        let issuer_key_id = issuer_key_id.into();
        if !valid_id(&issuer_key_id)
            || [nonce, custody_handle_sha256, completion_nonce_sha256]
                .into_iter()
                .any(zero_digest)
        {
            return Err(WindowsRunnerAdmissionError::InvalidClaims);
        }
        Ok(Self {
            schema_version: WINDOWS_RUNNER_ADMISSION_SCHEMA_VERSION,
            issuer_key_id,
            nonce,
            custody_handle_sha256,
            completion_nonce_sha256,
            binding,
            evidence,
            validity,
        })
    }

    /// Returns the receipt schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the broker admission signing-key identifier.
    #[must_use]
    pub fn issuer_key_id(&self) -> &str {
        &self.issuer_key_id
    }

    /// Returns the one-use broker receipt nonce.
    #[must_use]
    pub const fn nonce(&self) -> Sha256Digest {
        self.nonce
    }

    /// Returns the commitment to the opaque broker custody handle.
    #[must_use]
    pub const fn custody_handle_sha256(&self) -> Sha256Digest {
        self.custody_handle_sha256
    }

    /// Returns the exact idempotent completion nonce commitment.
    #[must_use]
    pub const fn completion_nonce_sha256(&self) -> Sha256Digest {
        self.completion_nonce_sha256
    }

    /// Returns the exact enrollment, host, image, and capability binding.
    #[must_use]
    pub const fn binding(&self) -> &WindowsRunnerAdmissionBinding {
        &self.binding
    }

    /// Returns every authenticated evidence digest.
    #[must_use]
    pub const fn evidence(&self) -> WindowsRunnerAdmissionEvidence {
        self.evidence
    }

    /// Returns the short-lived receipt validity window.
    #[must_use]
    pub const fn validity(&self) -> WindowsAdmissionValidity {
        self.validity
    }

    /// Serializes the one accepted canonical signed representation.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or exceeds its fixed bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WindowsRunnerAdmissionError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|_| WindowsRunnerAdmissionError::InvalidCanonicalPayload)?;
        if bytes.len() > MAX_CANONICAL_PAYLOAD_BYTES {
            return Err(WindowsRunnerAdmissionError::PayloadTooLarge);
        }
        Ok(bytes)
    }
}

/// Untrusted serializable broker admission envelope.
///
/// Construction and deserialization do not grant capabilities. Only
/// [`verify_windows_runner_admission`] returns the sealed authority type used
/// by control-plane registration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsRunnerAdmissionEnvelope {
    schema_version: u16,
    issuer_key_id: String,
    signed_payload: Vec<u8>,
    authenticator: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedWindowsRunnerAdmissionEnvelope {
    schema_version: u16,
    issuer_key_id: String,
    signed_payload: Vec<u8>,
    authenticator: Vec<u8>,
}

impl<'de> Deserialize<'de> for WindowsRunnerAdmissionEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedWindowsRunnerAdmissionEnvelope::deserialize(deserializer)?;
        if value.schema_version != WINDOWS_RUNNER_ADMISSION_SCHEMA_VERSION {
            return Err(D::Error::custom(
                WindowsRunnerAdmissionError::UnsupportedSchema,
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

impl WindowsRunnerAdmissionEnvelope {
    /// Wraps canonical signed claims in a transport-safe envelope.
    ///
    /// # Errors
    ///
    /// Rejects unknown schemas, malformed/noncanonical payloads, issuer
    /// substitution, oversized payloads, or non-Ed25519 authenticator sizes.
    pub fn new(
        issuer_key_id: impl Into<String>,
        signed_payload: Vec<u8>,
        authenticator: Vec<u8>,
    ) -> Result<Self, WindowsRunnerAdmissionError> {
        let issuer_key_id = issuer_key_id.into();
        if !valid_id(&issuer_key_id) {
            return Err(WindowsRunnerAdmissionError::InvalidIssuer);
        }
        if signed_payload.is_empty() || signed_payload.len() > MAX_CANONICAL_PAYLOAD_BYTES {
            return Err(WindowsRunnerAdmissionError::PayloadTooLarge);
        }
        if authenticator.len() != ED25519_SIGNATURE_BYTES {
            return Err(WindowsRunnerAdmissionError::InvalidAuthenticator);
        }
        let claims: WindowsRunnerAdmissionClaims = serde_json::from_slice(&signed_payload)
            .map_err(|_| WindowsRunnerAdmissionError::InvalidCanonicalPayload)?;
        let canonical = claims.canonical_bytes()?;
        if canonical != signed_payload {
            return Err(WindowsRunnerAdmissionError::NonCanonicalPayload);
        }
        if claims.issuer_key_id != issuer_key_id {
            return Err(WindowsRunnerAdmissionError::IssuerMismatch);
        }
        Ok(Self {
            schema_version: WINDOWS_RUNNER_ADMISSION_SCHEMA_VERSION,
            issuer_key_id,
            signed_payload,
            authenticator,
        })
    }

    /// Returns the envelope schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the independently selected admission signing-key ID.
    #[must_use]
    pub fn issuer_key_id(&self) -> &str {
        &self.issuer_key_id
    }

    /// Returns the exact canonical bytes covered by the signature.
    #[must_use]
    pub fn signed_payload(&self) -> &[u8] {
        &self.signed_payload
    }

    /// Returns the raw fixed-size Ed25519 signature bytes.
    #[must_use]
    pub fn authenticator(&self) -> &[u8] {
        &self.authenticator
    }

    /// Decodes the already canonical, structurally validated claims.
    ///
    /// # Errors
    ///
    /// Returns an error if an in-memory envelope was corrupted.
    pub fn claims(&self) -> Result<WindowsRunnerAdmissionClaims, WindowsRunnerAdmissionError> {
        serde_json::from_slice(&self.signed_payload)
            .map_err(|_| WindowsRunnerAdmissionError::InvalidCanonicalPayload)
    }
}

/// Immutable control-plane trust policy for one Windows admission issuer.
///
/// Signing authority is scoped to one broker host, one exact environment
/// profile, and one promotion trust bundle. A valid signature therefore cannot
/// move an admitted capability set to another broker or profile merely because
/// that broker happens to trust the same key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsRunnerAdmissionTrustAnchor {
    ed25519_public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
    broker_host_id: String,
    profile: EnvironmentProfile,
    promotion_trust_bundle_id: String,
}

impl WindowsRunnerAdmissionTrustAnchor {
    /// Creates a host/profile-scoped admission trust anchor.
    ///
    /// # Errors
    ///
    /// Rejects a placeholder public key, noncanonical broker host identity,
    /// placeholder profile digest, or noncanonical trust-bundle identity.
    pub fn new(
        ed25519_public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
        broker_host_id: impl Into<String>,
        profile: EnvironmentProfile,
        promotion_trust_bundle_id: impl Into<String>,
    ) -> Result<Self, WindowsRunnerAdmissionError> {
        let broker_host_id = broker_host_id.into();
        let promotion_trust_bundle_id = promotion_trust_bundle_id.into();
        if ed25519_public_key.iter().all(|byte| *byte == 0)
            || !is_lower_hex_64(&broker_host_id)
            || zero_digest(profile.digest())
            || !valid_id(&promotion_trust_bundle_id)
        {
            return Err(WindowsRunnerAdmissionError::InvalidTrustAnchor);
        }
        Ok(Self {
            ed25519_public_key,
            broker_host_id,
            profile,
            promotion_trust_bundle_id,
        })
    }

    /// Returns the exact Ed25519 public key.
    #[must_use]
    pub const fn ed25519_public_key(&self) -> &[u8; ED25519_PUBLIC_KEY_BYTES] {
        &self.ed25519_public_key
    }

    /// Returns the only broker host this key may authorize.
    #[must_use]
    pub fn broker_host_id(&self) -> &str {
        &self.broker_host_id
    }

    /// Returns the only environment profile this key may authorize.
    #[must_use]
    pub const fn profile(&self) -> &EnvironmentProfile {
        &self.profile
    }

    /// Returns the only promotion trust bundle this key may authorize.
    #[must_use]
    pub fn promotion_trust_bundle_id(&self) -> &str {
        &self.promotion_trust_bundle_id
    }
}

/// Immutable control-plane trust source for Windows admission issuers.
pub trait WindowsRunnerAdmissionTrustStore: Send + Sync {
    /// Resolves one approved, scope-bound trust anchor by exact issuer key ID.
    fn admission_trust_anchor(
        &self,
        issuer_key_id: &str,
    ) -> Option<WindowsRunnerAdmissionTrustAnchor>;
}

/// Server-verified Windows registration authority.
///
/// This type has no public constructor or deserializer. Control must still
/// atomically consume the nonce and advance promotion/revocation high-water
/// marks before persisting the returned capabilities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedWindowsRunnerAdmission {
    claims: WindowsRunnerAdmissionClaims,
    envelope_sha256: Sha256Digest,
}

impl VerifiedWindowsRunnerAdmission {
    /// Returns the complete authenticated claims.
    #[must_use]
    pub const fn claims(&self) -> &WindowsRunnerAdmissionClaims {
        &self.claims
    }

    /// Returns the only capability set eligible for Windows registration.
    #[must_use]
    pub const fn capabilities(&self) -> &RunnerCapabilities {
        self.claims.binding.capabilities()
    }

    /// Returns the domain-separated digest of the complete signed envelope.
    #[must_use]
    pub const fn envelope_sha256(&self) -> Sha256Digest {
        self.envelope_sha256
    }
}

/// Verifies a canonical broker admission envelope against server trust.
///
/// # Errors
///
/// Fails closed for unknown issuers, invalid signatures, malformed or
/// noncanonical bytes, future-issued/expired receipts, stale promotions, or
/// any invalid nested binding.
pub fn verify_windows_runner_admission(
    envelope: &WindowsRunnerAdmissionEnvelope,
    trust_store: &dyn WindowsRunnerAdmissionTrustStore,
    now_unix_millis: u64,
) -> Result<VerifiedWindowsRunnerAdmission, WindowsRunnerAdmissionError> {
    let claims = envelope.claims()?;
    if claims.issuer_key_id != envelope.issuer_key_id {
        return Err(WindowsRunnerAdmissionError::IssuerMismatch);
    }
    let trust_anchor = trust_store
        .admission_trust_anchor(&envelope.issuer_key_id)
        .ok_or(WindowsRunnerAdmissionError::UnknownIssuer)?;
    if claims.binding.broker_profile.broker_host_id() != trust_anchor.broker_host_id()
        || claims.binding.broker_profile.profile() != trust_anchor.profile()
        || claims.binding.promotion.trust_bundle_id() != trust_anchor.promotion_trust_bundle_id()
    {
        return Err(WindowsRunnerAdmissionError::TrustScopeMismatch);
    }
    signature::UnparsedPublicKey::new(&signature::ED25519, trust_anchor.ed25519_public_key())
        .verify(&envelope.signed_payload, &envelope.authenticator)
        .map_err(|_| WindowsRunnerAdmissionError::InvalidSignature)?;
    validate_current_window(claims.validity, now_unix_millis)?;
    validate_current_promotion(claims.binding.promotion.validity, now_unix_millis)?;
    Ok(VerifiedWindowsRunnerAdmission {
        envelope_sha256: envelope_digest(envelope),
        claims,
    })
}

/// Fail-closed Windows admission validation errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WindowsRunnerAdmissionError {
    /// The message uses a schema this build cannot verify.
    #[error("unsupported Windows runner admission schema")]
    UnsupportedSchema,
    /// Enrollment identities, origins, or secret-free commitments are invalid.
    #[error("invalid Windows enrollment transaction binding")]
    InvalidTransaction,
    /// The image reference is not an exact immutable digest-qualified identity.
    #[error("invalid Windows admission image")]
    InvalidImage,
    /// Broker, provider, profile, request, probe, or network binding is invalid.
    #[error("invalid Windows broker profile binding")]
    InvalidBrokerProfile,
    /// Promotion identity, serial, generation, or digest binding is invalid.
    #[error("invalid Windows promotion binding")]
    InvalidPromotion,
    /// A signed validity window is zero, inverted, or too long.
    #[error("invalid Windows admission validity window")]
    InvalidValidity,
    /// The advertised Windows capabilities are invalid or exceed the receipt.
    #[error("invalid Windows runner capabilities")]
    InvalidCapabilities,
    /// The serialized capabilities do not match their authenticated digest.
    #[error("Windows capability digest mismatch")]
    CapabilityDigestMismatch,
    /// An evidence digest is a zero placeholder.
    #[error("invalid Windows admission evidence")]
    InvalidEvidence,
    /// The configured issuer key is not bound to a valid immutable scope.
    #[error("invalid Windows admission trust anchor")]
    InvalidTrustAnchor,
    /// Claims contain an invalid issuer, nonce, or custody/completion commitment.
    #[error("invalid Windows admission claims")]
    InvalidClaims,
    /// The outer issuer identity is not canonical.
    #[error("invalid Windows admission issuer")]
    InvalidIssuer,
    /// The outer and signed issuer identities differ.
    #[error("Windows admission issuer substitution detected")]
    IssuerMismatch,
    /// The canonical payload is empty or exceeds its absolute size ceiling.
    #[error("Windows admission payload exceeds its bounded representation")]
    PayloadTooLarge,
    /// The signed payload cannot be decoded as the exact schema.
    #[error("invalid Windows admission canonical payload")]
    InvalidCanonicalPayload,
    /// Parsed claims do not reserialize byte-for-byte to the signed payload.
    #[error("noncanonical Windows admission payload")]
    NonCanonicalPayload,
    /// The authenticator is not an exact Ed25519 signature.
    #[error("invalid Windows admission authenticator")]
    InvalidAuthenticator,
    /// The server trust store does not approve the named issuer.
    #[error("unknown Windows admission issuer")]
    UnknownIssuer,
    /// A valid issuer signature attempted to authorize another broker, profile,
    /// or promotion trust bundle.
    #[error("Windows admission issuer trust scope mismatch")]
    TrustScopeMismatch,
    /// The Ed25519 signature does not authenticate the canonical payload.
    #[error("invalid Windows admission signature")]
    InvalidSignature,
    /// The receipt or promotion is issued in the future.
    #[error("Windows admission is not yet valid")]
    NotYetValid,
    /// The receipt or promotion has expired.
    #[error("Windows admission has expired")]
    Expired,
}

fn valid_origin(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_ORIGIN_BYTES {
        return false;
    }
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    let literal_loopback = url.scheme() == "http"
        && url
            .host_str()
            .and_then(|host| host.parse::<std::net::IpAddr>().ok())
            .is_some_and(|address| address.is_loopback());
    (url.scheme() == "https" || literal_loopback)
        && !url.cannot_be_a_base()
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/"
        && url.as_str() == value
}

fn valid_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && (3..=MAX_ID_BYTES).contains(&value.len())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn zero_digest(digest: Sha256Digest) -> bool {
    digest.as_bytes().iter().all(|byte| *byte == 0)
}

fn validate_window(
    issued_at_unix_millis: u64,
    expires_at_unix_millis: u64,
    maximum_lifetime_millis: u64,
) -> Result<(), WindowsRunnerAdmissionError> {
    let lifetime = expires_at_unix_millis
        .checked_sub(issued_at_unix_millis)
        .filter(|lifetime| *lifetime > 0 && *lifetime <= maximum_lifetime_millis)
        .ok_or(WindowsRunnerAdmissionError::InvalidValidity)?;
    if issued_at_unix_millis == 0 || lifetime == 0 {
        return Err(WindowsRunnerAdmissionError::InvalidValidity);
    }
    Ok(())
}

fn validate_current_window(
    validity: WindowsAdmissionValidity,
    now_unix_millis: u64,
) -> Result<(), WindowsRunnerAdmissionError> {
    if validity.issued_at_unix_millis > now_unix_millis {
        return Err(WindowsRunnerAdmissionError::NotYetValid);
    }
    if now_unix_millis >= validity.expires_at_unix_millis {
        return Err(WindowsRunnerAdmissionError::Expired);
    }
    Ok(())
}

fn validate_current_promotion(
    validity: WindowsPromotionValidity,
    now_unix_millis: u64,
) -> Result<(), WindowsRunnerAdmissionError> {
    if validity.issued_at_unix_millis > now_unix_millis {
        return Err(WindowsRunnerAdmissionError::NotYetValid);
    }
    if now_unix_millis >= validity.expires_at_unix_millis {
        return Err(WindowsRunnerAdmissionError::Expired);
    }
    Ok(())
}

fn canonical_capabilities_digest(
    capabilities: &RunnerCapabilities,
) -> Result<Sha256Digest, WindowsRunnerAdmissionError> {
    let bytes = serde_json::to_vec(capabilities)
        .map_err(|_| WindowsRunnerAdmissionError::InvalidCapabilities)?;
    Ok(Sha256Digest::from_bytes(Sha256::digest(bytes).into()))
}

fn valid_action_feature_relationships(capabilities: &RunnerCapabilities) -> bool {
    let features = capabilities.features();
    let node_generations = [
        &RunnerFeature::NODE12_ACTIONS,
        &RunnerFeature::NODE16_ACTIONS,
        &RunnerFeature::NODE20_ACTIONS,
        &RunnerFeature::NODE24_ACTIONS,
    ];
    let any_node = node_generations
        .into_iter()
        .any(|feature| features.contains(feature));
    let javascript = features.contains(&RunnerFeature::JAVASCRIPT_ACTIONS);
    let any_action = has_action_features(capabilities);
    javascript == any_node && (!any_action || features.contains(&RunnerFeature::REPOSITORY_ACTIONS))
}

fn has_action_features(capabilities: &RunnerCapabilities) -> bool {
    let features = capabilities.features();
    features.contains(&RunnerFeature::JAVASCRIPT_ACTIONS)
        || features.contains(&RunnerFeature::NODE12_ACTIONS)
        || features.contains(&RunnerFeature::NODE16_ACTIONS)
        || features.contains(&RunnerFeature::NODE20_ACTIONS)
        || features.contains(&RunnerFeature::NODE24_ACTIONS)
        || features.contains(&RunnerFeature::COMPOSITE_ACTIONS)
        || features.contains(&RunnerFeature::REPOSITORY_ACTIONS)
}

fn envelope_digest(envelope: &WindowsRunnerAdmissionEnvelope) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(RECEIPT_DIGEST_DOMAIN);
    hasher.update((envelope.issuer_key_id.len() as u64).to_be_bytes());
    hasher.update(envelope.issuer_key_id.as_bytes());
    hasher.update((envelope.signed_payload.len() as u64).to_be_bytes());
    hasher.update(&envelope.signed_payload);
    hasher.update((envelope.authenticator.len() as u64).to_be_bytes());
    hasher.update(&envelope.authenticator);
    Sha256Digest::from_bytes(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use automata_ci_core::{Architecture, EnvironmentProfileId, OperationId, RunnerPlatform};
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair as _},
    };

    use super::*;

    const NOW: u64 = 1_800_000_000_000;

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

    fn trust_anchor(
        key_pair: &Ed25519KeyPair,
        broker_host_id: impl Into<String>,
    ) -> WindowsRunnerAdmissionTrustAnchor {
        WindowsRunnerAdmissionTrustAnchor::new(
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
        .expect("trust anchor")
    }

    fn trust_store(issuer: &str, key_pair: &Ed25519KeyPair) -> TrustStore {
        TrustStore(BTreeMap::from([(
            issuer.to_owned(),
            trust_anchor(key_pair, "a".repeat(64)),
        )]))
    }

    fn claims(issuer: &str, receipt_expires: u64) -> WindowsRunnerAdmissionClaims {
        let runner_id = RunnerId::new();
        let profile = EnvironmentProfile::new(
            EnvironmentProfileId::new("automata.example/windows-server-2025").expect("profile ID"),
            digest(4),
        );
        let capabilities = RunnerCapabilities::new(
            runner_id,
            RunnerPlatform::new(OperatingSystem::Windows, Architecture::X86_64),
        )
        .with_features([
            RunnerFeature::SHELL_STEPS,
            RunnerFeature::REPOSITORY_ACTIONS,
            RunnerFeature::COMPOSITE_ACTIONS,
            RunnerFeature::JAVASCRIPT_ACTIONS,
            RunnerFeature::NODE20_ACTIONS,
        ])
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
            "a".repeat(64),
            WINDOWS_RUNNER_ADMISSION_PROVIDER_ID,
            digest(6),
            profile,
            image,
            digest(7),
            true,
            true,
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
        let binding = WindowsRunnerAdmissionBinding::new(
            transaction,
            broker_profile,
            promotion,
            capabilities,
        )
        .expect("binding");
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
        WindowsRunnerAdmissionClaims::new(
            issuer,
            digest(19),
            digest(20),
            digest(21),
            binding,
            WindowsRunnerAdmissionEvidence::new(broker, authority),
            WindowsAdmissionValidity::new(NOW - 1_000, receipt_expires).expect("receipt validity"),
        )
        .expect("claims")
    }

    fn signed_envelope(
        issuer: &str,
        key_pair: &Ed25519KeyPair,
        receipt_expires: u64,
    ) -> WindowsRunnerAdmissionEnvelope {
        let payload = claims(issuer, receipt_expires)
            .canonical_bytes()
            .expect("canonical claims");
        WindowsRunnerAdmissionEnvelope::new(
            issuer,
            payload.clone(),
            key_pair.sign(&payload).as_ref().to_vec(),
        )
        .expect("envelope")
    }

    #[test]
    fn server_verifies_canonical_receipt_and_derives_exact_capabilities() {
        let key_pair = key_pair();
        let envelope = signed_envelope("broker-admission-v1", &key_pair, NOW + 60_000);
        let trust = trust_store("broker-admission-v1", &key_pair);

        let verified = verify_windows_runner_admission(&envelope, &trust, NOW).expect("verified");
        assert_eq!(
            verified.capabilities(),
            envelope.claims().expect("claims").binding().capabilities()
        );
        assert!(!zero_digest(verified.envelope_sha256()));

        let encoded = serde_json::to_vec(&envelope).expect("serialize envelope");
        let decoded: WindowsRunnerAdmissionEnvelope =
            serde_json::from_slice(&encoded).expect("deserialize envelope");
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn noncanonical_or_unknown_fields_fail_before_signature_authority() {
        let key_pair = key_pair();
        let claims = claims("broker-admission-v1", NOW + 60_000);
        let mut noncanonical = b" \n".to_vec();
        noncanonical.extend(claims.canonical_bytes().expect("claims"));
        assert_eq!(
            WindowsRunnerAdmissionEnvelope::new(
                "broker-admission-v1",
                noncanonical.clone(),
                key_pair.sign(&noncanonical).as_ref().to_vec(),
            ),
            Err(WindowsRunnerAdmissionError::NonCanonicalPayload)
        );

        let mut payload: serde_json::Value = serde_json::to_value(claims).expect("claims value");
        payload["future_field"] = serde_json::json!(true);
        let payload = serde_json::to_vec(&payload).expect("payload");
        assert_eq!(
            WindowsRunnerAdmissionEnvelope::new(
                "broker-admission-v1",
                payload.clone(),
                key_pair.sign(&payload).as_ref().to_vec(),
            ),
            Err(WindowsRunnerAdmissionError::InvalidCanonicalPayload)
        );

        let envelope = signed_envelope("broker-admission-v1", &key_pair, NOW + 60_000);
        let mut outer = serde_json::to_value(envelope).expect("envelope value");
        outer["future_field"] = serde_json::json!(true);
        assert!(serde_json::from_value::<WindowsRunnerAdmissionEnvelope>(outer).is_err());
    }

    #[test]
    fn forged_nonzero_authenticator_unknown_issuer_and_expiry_fail_closed() {
        let key_pair = key_pair();
        let envelope = signed_envelope("broker-admission-v1", &key_pair, NOW + 60_000);
        let trust = trust_store("broker-admission-v1", &key_pair);
        let forged = WindowsRunnerAdmissionEnvelope::new(
            envelope.issuer_key_id.clone(),
            envelope.signed_payload.clone(),
            vec![0x5a; ED25519_SIGNATURE_BYTES],
        )
        .expect("structurally valid forged envelope");
        assert_eq!(
            verify_windows_runner_admission(&forged, &trust, NOW),
            Err(WindowsRunnerAdmissionError::InvalidSignature)
        );
        assert_eq!(
            verify_windows_runner_admission(&envelope, &TrustStore(BTreeMap::new()), NOW,),
            Err(WindowsRunnerAdmissionError::UnknownIssuer)
        );

        let expired = signed_envelope("broker-admission-v1", &key_pair, NOW);
        assert_eq!(
            verify_windows_runner_admission(&expired, &trust, NOW),
            Err(WindowsRunnerAdmissionError::Expired)
        );
    }

    #[test]
    fn same_key_and_issuer_cannot_cross_broker_trust_scope() {
        let key_pair = key_pair();
        let mut claims = claims("broker-admission-v1", NOW + 60_000);
        claims.binding.broker_profile.broker_host_id = "b".repeat(64);
        let payload = claims.canonical_bytes().expect("canonical claims");
        let envelope = WindowsRunnerAdmissionEnvelope::new(
            "broker-admission-v1",
            payload.clone(),
            key_pair.sign(&payload).as_ref().to_vec(),
        )
        .expect("envelope");
        let trust = trust_store("broker-admission-v1", &key_pair);

        assert_eq!(
            verify_windows_runner_admission(&envelope, &trust, NOW),
            Err(WindowsRunnerAdmissionError::TrustScopeMismatch)
        );
    }

    #[test]
    fn accept_all_runner_verifier_cannot_mint_server_capabilities() {
        let attacker = key_pair();
        let envelope = signed_envelope("attacker-broker-v1", &attacker, NOW + 60_000);
        let local_accept_all = trust_store("attacker-broker-v1", &attacker);
        assert!(verify_windows_runner_admission(&envelope, &local_accept_all, NOW).is_ok());

        let production = key_pair();
        let server_trust = trust_store("production-broker-v1", &production);
        assert_eq!(
            verify_windows_runner_admission(&envelope, &server_trust, NOW),
            Err(WindowsRunnerAdmissionError::UnknownIssuer)
        );
    }

    #[test]
    fn local_action_and_capability_digest_supersets_are_rejected() {
        let mut value = serde_json::to_value(claims("broker-admission-v1", NOW + 60_000).binding)
            .expect("binding value");
        value["capabilities"]["features"]
            .as_array_mut()
            .expect("features")
            .push(serde_json::json!(RunnerFeature::LOCAL_ACTIONS.as_str()));
        assert!(serde_json::from_value::<WindowsRunnerAdmissionBinding>(value).is_err());

        let mut value = serde_json::to_value(claims("broker-admission-v1", NOW + 60_000).binding)
            .expect("binding value");
        value["broker_profile"]["sealed_action_trees"] = serde_json::json!(false);
        assert!(serde_json::from_value::<WindowsRunnerAdmissionBinding>(value).is_err());
    }
}
