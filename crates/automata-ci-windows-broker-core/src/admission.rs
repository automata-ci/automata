//! Broker-owned Windows admission policy evaluation.
//!
//! This module is deterministic and adapter-free. Host input acquisition and
//! synthetic lifecycle probing cross explicit ports; service state and custody
//! live in `automata-ci-windows-broker`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr as _,
    sync::Arc,
};

use automata_ci_core::{
    ContainerCapabilities, IsolationLevel, RunnerCapabilities, RunnerFeature, SandboxCapabilities,
    SandboxFeature, Sha256Digest, UnixMillis,
};
use automata_ci_execution::ImmutableImage;
use automata_ci_protocol::{
    WindowsAuthorityAdmissionEvidence, WindowsBrokerAdmissionEvidence, WindowsBrokerProfileBinding,
    WindowsImagePromotionBinding, WindowsPromotionValidity, WindowsRunnerAdmissionBinding,
    WindowsRunnerAdmissionEvidence,
};
use automata_ci_windows_broker_protocol::WINDOWS_HYPERV_PROVIDER_ID;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    host_input::{
        WindowsBrokerHostInputAttestation, WindowsBrokerHostInputKind,
        WindowsBrokerHostInputRequest,
    },
    request::{WindowsAdmissionLaunchContract, WindowsBrokerAdmissionRequest},
};

const MILLIS_PER_SECOND: i64 = 1_000;
const HOST_INPUT_ATTESTATION_LIFETIME_MILLIS: i64 = 5 * 60 * 1_000;
const MAX_PROMOTION_LIFETIME_MILLIS: u64 = 7 * 24 * 60 * 60 * 1_000;
const MAX_PROMOTION_FUTURE_SKEW_MILLIS: u64 = 5 * 60 * 1_000;
const MAX_REVOKED_IMAGES: usize = 4_096;
const PROMOTION_PAYLOAD_SCHEMA_VERSION: u16 = 2;
const EVIDENCE_REFERENCE_MEDIA_TYPE: &str =
    "application/vnd.automata.windows-image-evidence-reference+json";
const PROMOTION_TRUST_BUNDLE_DOMAIN: &[u8] = b"automata.windows-promotion-trust-bundle.v1\0";
const PROFILE_CONTRACT_DOMAIN: &[u8] = b"automata.windows-admitted-profile-contract.v2\0";
const IMAGE_ATTESTATION_DOMAIN: &[u8] = b"automata.windows-image-attestation.v1\0";
const AUTHORITY_ATTESTATION_DOMAIN: &[u8] = b"automata.windows-admission-authority.v1\0";

/// Complete result of broker-owned input, promotion, and synthetic probing.
///
/// This type can be constructed only inside this crate after privileged
/// evaluation. The issue DTO remains non-authoritative and cannot directly
/// manufacture this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsBrokerAdmissionEvaluation {
    binding: WindowsRunnerAdmissionBinding,
    evidence: WindowsRunnerAdmissionEvidence,
    launch: WindowsAdmissionLaunchContract,
    profile_valid_until: UnixMillis,
}

impl WindowsBrokerAdmissionEvaluation {
    /// Creates an evaluated contract after all privileged checks complete.
    ///
    /// # Errors
    ///
    /// Rejects a non-Windows/offline binding, launch substitution, or a
    /// validity horizon beyond the signed image promotion.
    pub(crate) fn new(
        binding: WindowsRunnerAdmissionBinding,
        evidence: &WindowsRunnerAdmissionEvidence,
        launch: WindowsAdmissionLaunchContract,
        profile_valid_until: UnixMillis,
    ) -> Result<Self, WindowsBrokerAdmissionError> {
        let broker = binding.broker_profile();
        let promotion_expiry =
            i64::try_from(binding.promotion().validity().expires_at_unix_millis())
                .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;
        if !broker.network_disabled()
            || broker.profile() != launch.profile()
            || broker.image() != launch.image()
            || launch.network_disabled() != broker.network_disabled()
            || launch.resources().pids() != broker.sandbox_pids_limit()
            || profile_valid_until.get() <= 0
            || profile_valid_until.get() > promotion_expiry
        {
            return Err(WindowsBrokerAdmissionError::EvidenceRejected);
        }
        Ok(Self {
            binding,
            evidence: *evidence,
            launch,
            profile_valid_until,
        })
    }

    /// Returns the exact capability-bearing signed binding.
    #[must_use]
    pub const fn binding(&self) -> &WindowsRunnerAdmissionBinding {
        &self.binding
    }

    /// Returns freshly broker-derived evidence.
    #[must_use]
    pub const fn evidence(&self) -> WindowsRunnerAdmissionEvidence {
        self.evidence
    }

    /// Returns the broker-retained immutable launch contract.
    #[must_use]
    pub const fn launch(&self) -> &WindowsAdmissionLaunchContract {
        &self.launch
    }

    /// Returns the exclusive promotion/profile horizon.
    #[must_use]
    pub const fn profile_valid_until(&self) -> UnixMillis {
        self.profile_valid_until
    }
}

/// Privileged, independently configured admission evaluator.
pub trait WindowsBrokerAdmissionEvaluator: fmt::Debug + Send + Sync {
    /// Reopens and verifies every issue input, enforces promotion high-water,
    /// creates/observes/destroys the fixed synthetic resource, and returns
    /// only broker-derived authority.
    ///
    /// # Errors
    ///
    /// Returns a value-free request, evidence, state, or availability error.
    fn evaluate(
        &self,
        request: &WindowsBrokerAdmissionRequest,
        now: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionEvaluation, WindowsBrokerAdmissionError>;
}

/// Stable-handle result for every broker-authoritative admission input.
///
/// The attestation covers all nine closed input roles. Bytes are retained only
/// for the seven bounded image, evidence, revocation, and promotion documents;
/// configuration and executable content are measured but never copied into an
/// admission parser allocation.
#[derive(Debug)]
pub struct WindowsBrokerAdmissionInputSet {
    attestation: WindowsBrokerHostInputAttestation,
    documents: BTreeMap<WindowsBrokerHostInputKind, Zeroizing<Vec<u8>>>,
}

impl WindowsBrokerAdmissionInputSet {
    /// Constructs one exact, content-bound input set.
    ///
    /// # Errors
    ///
    /// Rejects missing, duplicated, empty, oversized, or digest-substituted
    /// semantic documents, or an attestation for a different request.
    pub fn new(
        request: &WindowsBrokerHostInputRequest,
        attestation: WindowsBrokerHostInputAttestation,
        documents: BTreeMap<WindowsBrokerHostInputKind, Zeroizing<Vec<u8>>>,
    ) -> Result<Self, WindowsBrokerAdmissionError> {
        attestation
            .validate_for(request, attestation.host_id())
            .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;
        let expected = request
            .inputs()
            .iter()
            .filter(|descriptor| admission_document_kind(descriptor.kind()))
            .collect::<Vec<_>>();
        if documents.len() != expected.len()
            || expected.iter().any(|descriptor| {
                documents.get(&descriptor.kind()).is_none_or(|bytes| {
                    bytes.is_empty()
                        || u64::try_from(bytes.len())
                            .map_or(true, |length| length > descriptor.kind().byte_limit())
                        || sha256(bytes) != descriptor.expected_sha256()
                })
            })
        {
            return Err(WindowsBrokerAdmissionError::EvidenceRejected);
        }
        Ok(Self {
            attestation,
            documents,
        })
    }

    /// Returns the stable-handle aggregate attestation.
    #[must_use]
    pub const fn attestation(&self) -> &WindowsBrokerHostInputAttestation {
        &self.attestation
    }

    fn document(
        &self,
        kind: WindowsBrokerHostInputKind,
    ) -> Result<&[u8], WindowsBrokerAdmissionError> {
        self.documents
            .get(&kind)
            .map(AsRef::as_ref)
            .ok_or(WindowsBrokerAdmissionError::EvidenceRejected)
    }
}

/// Closed production/test seam that reopens all admission inputs from stable
/// service-owned handles and returns only digest-checked semantic documents.
pub trait WindowsBrokerAdmissionInputSource: fmt::Debug + Send + Sync {
    /// Attests and loads one exact nine-input batch.
    ///
    /// # Errors
    ///
    /// Fails closed on path, ACL, owner, volume, file-ID, content, or freshness
    /// disagreement.
    fn load(
        &self,
        request: &WindowsBrokerHostInputRequest,
        issued_at: UnixMillis,
        valid_until: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionInputSet, WindowsBrokerAdmissionError>;
}

/// One independently configured Ed25519 promotion verification key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsBrokerPromotionTrustKey {
    key_id: String,
    public_key: [u8; 32],
}

impl WindowsBrokerPromotionTrustKey {
    /// Creates one trust-registry key.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers or a zero public key.
    pub fn new(
        key_id: impl Into<String>,
        public_key: [u8; 32],
    ) -> Result<Self, WindowsBrokerAdmissionError> {
        let key_id = key_id.into();
        if !valid_promotion_id(&key_id) || public_key.iter().all(|byte| *byte == 0) {
            return Err(WindowsBrokerAdmissionError::InvalidRequest);
        }
        Ok(Self { key_id, public_key })
    }
}

/// One versioned broker-owned promotion trust bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsBrokerPromotionTrustBundle {
    trust_bundle_id: String,
    trust_bundle_sha256: Sha256Digest,
    keys: BTreeMap<String, [u8; 32]>,
}

impl WindowsBrokerPromotionTrustBundle {
    /// Creates one canonical bundle and verifies its provisioned commitment.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers, duplicate/empty keys, excessive key
    /// counts, or a commitment that does not match the canonical key set.
    pub fn new(
        trust_bundle_id: impl Into<String>,
        trust_bundle_sha256: Sha256Digest,
        keys: Vec<WindowsBrokerPromotionTrustKey>,
    ) -> Result<Self, WindowsBrokerAdmissionError> {
        let trust_bundle_id = trust_bundle_id.into();
        if !valid_trust_bundle_id(&trust_bundle_id) || keys.is_empty() || keys.len() > 32 {
            return Err(WindowsBrokerAdmissionError::InvalidRequest);
        }
        let mut canonical = BTreeMap::new();
        for key in keys {
            if canonical.insert(key.key_id, key.public_key).is_some() {
                return Err(WindowsBrokerAdmissionError::InvalidRequest);
            }
        }
        let expected = promotion_trust_bundle_sha256(&trust_bundle_id, &canonical);
        if trust_bundle_sha256 != expected {
            return Err(WindowsBrokerAdmissionError::InvalidRequest);
        }
        Ok(Self {
            trust_bundle_id,
            trust_bundle_sha256,
            keys: canonical,
        })
    }

    /// Computes the canonical commitment used when provisioning a bundle.
    #[must_use]
    pub fn canonical_sha256(
        trust_bundle_id: &str,
        keys: &[WindowsBrokerPromotionTrustKey],
    ) -> Sha256Digest {
        let canonical = keys
            .iter()
            .map(|key| (key.key_id.clone(), key.public_key))
            .collect::<BTreeMap<_, _>>();
        promotion_trust_bundle_sha256(trust_bundle_id, &canonical)
    }
}

/// Immutable service-owned registry of accepted promotion bundles and keys.
#[derive(Clone, Debug)]
pub struct WindowsBrokerPromotionTrustRegistry {
    bundles: BTreeMap<String, WindowsBrokerPromotionTrustBundle>,
}

impl WindowsBrokerPromotionTrustRegistry {
    /// Creates a nonempty registry with unique bundle identities.
    ///
    /// # Errors
    ///
    /// Rejects empty, duplicate, or excessive bundle sets.
    pub fn new(
        bundles: Vec<WindowsBrokerPromotionTrustBundle>,
    ) -> Result<Self, WindowsBrokerAdmissionError> {
        if bundles.is_empty() || bundles.len() > 32 {
            return Err(WindowsBrokerAdmissionError::InvalidRequest);
        }
        let mut registry = BTreeMap::new();
        for bundle in bundles {
            if registry
                .insert(bundle.trust_bundle_id.clone(), bundle)
                .is_some()
            {
                return Err(WindowsBrokerAdmissionError::InvalidRequest);
            }
        }
        Ok(Self { bundles: registry })
    }

    fn resolve(
        &self,
        trust_bundle_id: &str,
        key_id: &str,
    ) -> Result<(&WindowsBrokerPromotionTrustBundle, &[u8; 32]), WindowsBrokerAdmissionError> {
        let bundle = self
            .bundles
            .get(trust_bundle_id)
            .ok_or(WindowsBrokerAdmissionError::EvidenceRejected)?;
        let key = bundle
            .keys
            .get(key_id)
            .ok_or(WindowsBrokerAdmissionError::EvidenceRejected)?;
        Ok((bundle, key))
    }
}

/// Evidence returned only after a fixed synthetic resource was created,
/// independently observed, and durably cleaned by the broker boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_field_names)]
pub struct WindowsBrokerSyntheticProbeEvidence {
    broker_attestation_sha256: Sha256Digest,
    network_attestation_sha256: Sha256Digest,
    cleanup_receipt_sha256: Sha256Digest,
}

impl WindowsBrokerSyntheticProbeEvidence {
    /// Creates a complete non-placeholder probe result.
    ///
    /// # Errors
    ///
    /// Rejects any missing evidence commitment.
    pub fn new(
        broker_attestation_sha256: Sha256Digest,
        network_attestation_sha256: Sha256Digest,
        cleanup_receipt_sha256: Sha256Digest,
    ) -> Result<Self, WindowsBrokerAdmissionError> {
        if [
            broker_attestation_sha256,
            network_attestation_sha256,
            cleanup_receipt_sha256,
        ]
        .into_iter()
        .any(zero_digest)
        {
            return Err(WindowsBrokerAdmissionError::EvidenceRejected);
        }
        Ok(Self {
            broker_attestation_sha256,
            network_attestation_sha256,
            cleanup_receipt_sha256,
        })
    }
}

/// Closed seam for the mandatory create/observe/cleanup admission probe.
pub trait WindowsBrokerSyntheticProbe: fmt::Debug + Send + Sync {
    /// Executes the fixed probe for one exact request and returns evidence only
    /// after cleanup is durably complete.
    ///
    /// # Errors
    ///
    /// Fails closed on create, effective-state, tool, network, or cleanup
    /// disagreement.
    fn execute(
        &self,
        request: &WindowsBrokerAdmissionRequest,
        host_inputs: &WindowsBrokerHostInputAttestation,
        now: UnixMillis,
        valid_until: UnixMillis,
    ) -> Result<WindowsBrokerSyntheticProbeEvidence, WindowsBrokerAdmissionError>;
}

/// Explicit fail-closed probe used until a ledger-backed synthetic lifecycle
/// implementation has been injected.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableWindowsBrokerSyntheticProbe;

impl WindowsBrokerSyntheticProbe for UnavailableWindowsBrokerSyntheticProbe {
    fn execute(
        &self,
        _request: &WindowsBrokerAdmissionRequest,
        _host_inputs: &WindowsBrokerHostInputAttestation,
        _now: UnixMillis,
        _valid_until: UnixMillis,
    ) -> Result<WindowsBrokerSyntheticProbeEvidence, WindowsBrokerAdmissionError> {
        Err(WindowsBrokerAdmissionError::Unavailable)
    }
}

/// Production admission evaluator with independently owned input, promotion,
/// and synthetic-lifecycle authorities.
pub struct VerifiedWindowsBrokerAdmissionEvaluator {
    host_id: Sha256Digest,
    inputs: Arc<dyn WindowsBrokerAdmissionInputSource>,
    promotion_trust: WindowsBrokerPromotionTrustRegistry,
    probe: Arc<dyn WindowsBrokerSyntheticProbe>,
}

impl VerifiedWindowsBrokerAdmissionEvaluator {
    /// Composes the closed evaluator dependencies.
    ///
    /// # Errors
    ///
    /// Rejects a placeholder broker host identity.
    pub fn new(
        host_id: Sha256Digest,
        inputs: Arc<dyn WindowsBrokerAdmissionInputSource>,
        promotion_trust: WindowsBrokerPromotionTrustRegistry,
        probe: Arc<dyn WindowsBrokerSyntheticProbe>,
    ) -> Result<Self, WindowsBrokerAdmissionError> {
        if zero_digest(host_id) {
            return Err(WindowsBrokerAdmissionError::InvalidRequest);
        }
        Ok(Self {
            host_id,
            inputs,
            promotion_trust,
            probe,
        })
    }
}

impl fmt::Debug for VerifiedWindowsBrokerAdmissionEvaluator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedWindowsBrokerAdmissionEvaluator")
            .field("host_id", &self.host_id)
            .field("inputs", &self.inputs)
            .field("promotion_trust", &self.promotion_trust)
            .field("probe", &self.probe)
            .finish()
    }
}

impl WindowsBrokerAdmissionEvaluator for VerifiedWindowsBrokerAdmissionEvaluator {
    fn evaluate(
        &self,
        request: &WindowsBrokerAdmissionRequest,
        now: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionEvaluation, WindowsBrokerAdmissionError> {
        if now.get() < 0
            || request.broker_host_id() != self.host_id.to_string()
            || request.sandbox_provider_id() != WINDOWS_HYPERV_PROVIDER_ID
            || !request.launch().network_disabled()
            || request.launch().sealed_action_trees()
        {
            return Err(WindowsBrokerAdmissionError::EvidenceRejected);
        }
        let input_request = admission_host_input_request(request)?;
        let input_issued_at = floor_windows_admission_issued_at(now)?;
        let input_valid_until = UnixMillis::new(
            now.get()
                .checked_add(HOST_INPUT_ATTESTATION_LIFETIME_MILLIS)
                .ok_or(WindowsBrokerAdmissionError::InvalidRequest)?,
        );
        let inputs = self
            .inputs
            .load(&input_request, input_issued_at, input_valid_until)?;
        let promotion = verify_promotion_and_image(request, &inputs, &self.promotion_trust, now)?;
        let profile_valid_until = UnixMillis::new(
            i64::try_from(promotion.binding.validity().expires_at_unix_millis())
                .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?,
        );
        let probe = self
            .probe
            .execute(request, inputs.attestation(), now, profile_valid_until)?;
        let capabilities = shell_only_capabilities(request)?;
        let request_sha256 = request
            .request_sha256()
            .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)?;
        let broker_profile = WindowsBrokerProfileBinding::new(
            self.host_id.to_string(),
            WINDOWS_HYPERV_PROVIDER_ID,
            request_sha256,
            request.launch().profile().clone(),
            request.launch().image().clone(),
            request.probe().contract_sha256(),
            true,
            false,
            request.launch().resources().pids(),
        )
        .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;
        let binding = WindowsRunnerAdmissionBinding::new(
            request.transaction().clone(),
            broker_profile,
            promotion.binding,
            capabilities,
        )
        .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;
        let binding_bytes = serde_json::to_vec(&binding)
            .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;
        let profile_contract_sha256 = domain_digest(
            PROFILE_CONTRACT_DOMAIN,
            &[
                self.host_id.as_bytes(),
                request_sha256.as_bytes(),
                inputs.attestation().digest().as_bytes(),
                promotion.image_attestation_sha256.as_bytes(),
                probe.broker_attestation_sha256.as_bytes(),
                probe.network_attestation_sha256.as_bytes(),
                probe.cleanup_receipt_sha256.as_bytes(),
                &binding_bytes,
            ],
        );
        let broker_evidence = WindowsBrokerAdmissionEvidence::new(
            probe.broker_attestation_sha256,
            inputs.attestation().digest(),
            promotion.image_attestation_sha256,
            probe.network_attestation_sha256,
            profile_contract_sha256,
        )
        .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;
        let authority_attestation_sha256 = domain_digest(
            AUTHORITY_ATTESTATION_DOMAIN,
            &[
                self.host_id.as_bytes(),
                request_sha256.as_bytes(),
                promotion.trust_bundle_sha256.as_bytes(),
                promotion.public_key_sha256.as_bytes(),
                profile_contract_sha256.as_bytes(),
            ],
        );
        let authority_evidence = WindowsAuthorityAdmissionEvidence::new(
            authority_attestation_sha256,
            promotion.trust_bundle_sha256,
            promotion.public_key_sha256,
            probe.cleanup_receipt_sha256,
        )
        .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;
        let evidence = WindowsRunnerAdmissionEvidence::new(broker_evidence, authority_evidence);
        WindowsBrokerAdmissionEvaluation::new(
            binding,
            &evidence,
            request.launch().clone(),
            profile_valid_until,
        )
    }
}

struct VerifiedPromotion {
    binding: WindowsImagePromotionBinding,
    image_attestation_sha256: Sha256Digest,
    trust_bundle_sha256: Sha256Digest,
    public_key_sha256: Sha256Digest,
}

fn admission_host_input_request(
    request: &WindowsBrokerAdmissionRequest,
) -> Result<WindowsBrokerHostInputRequest, WindowsBrokerAdmissionError> {
    request
        .host_inputs()
        .validate()
        .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)?;
    Ok(request.host_inputs().clone())
}

fn shell_only_capabilities(
    request: &WindowsBrokerAdmissionRequest,
) -> Result<RunnerCapabilities, WindowsBrokerAdmissionError> {
    let ceiling = request.capability_ceiling();
    let allowed = ceiling
        .features()
        .iter()
        .filter(|feature| {
            **feature == RunnerFeature::SHELL_STEPS
                || **feature == RunnerFeature::DEFAULT_WINDOWS_SHELL
                || **feature == RunnerFeature::PYTHON_SHELL
                || **feature == RunnerFeature::PWSH_SHELL
                || **feature == RunnerFeature::WINDOWS_POWERSHELL_SHELL
                || **feature == RunnerFeature::CMD_SHELL
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    if !allowed.contains(&RunnerFeature::SHELL_STEPS)
        || !allowed.contains(&RunnerFeature::DEFAULT_WINDOWS_SHELL)
    {
        return Err(WindowsBrokerAdmissionError::EvidenceRejected);
    }
    RunnerCapabilities::new(ceiling.runner_id(), ceiling.platform().clone())
        .with_max_parallel_jobs(1)
        .map(|capabilities| {
            capabilities
                .with_resources_per_job(request.launch().allocation().limits())
                .with_sandbox(SandboxCapabilities::new(
                    IsolationLevel::VirtualMachine,
                    [
                        SandboxFeature::CLEAN_WORKSPACE,
                        SandboxFeature::NETWORK_ISOLATION,
                        SandboxFeature::WINDOWS_HYPERV_CONTAINER,
                    ],
                ))
                .with_containers(ContainerCapabilities::default())
                .with_features(allowed)
                .with_environment_profiles([request.launch().profile().clone()])
        })
        .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)
}

#[allow(clippy::too_many_lines)]
fn verify_promotion_and_image(
    request: &WindowsBrokerAdmissionRequest,
    inputs: &WindowsBrokerAdmissionInputSet,
    trust: &WindowsBrokerPromotionTrustRegistry,
    now: UnixMillis,
) -> Result<VerifiedPromotion, WindowsBrokerAdmissionError> {
    let manifest_bytes = inputs.document(WindowsBrokerHostInputKind::ImageManifest)?;
    let manifest_sha256 = sha256(manifest_bytes);
    if manifest_sha256 != request.promotion().manifest_sha256() {
        return Err(WindowsBrokerAdmissionError::EvidenceRejected);
    }
    let manifest: ImageManifest = parse_document(manifest_bytes)?;
    validate_manifest(&manifest, request)?;

    let lock_bytes = inputs.document(WindowsBrokerHostInputKind::ImageLock)?;
    let lock_sha256 = sha256(lock_bytes);
    if lock_sha256 != request.promotion().lock_sha256() {
        return Err(WindowsBrokerAdmissionError::EvidenceRejected);
    }
    let lock: ImageLock = parse_document(lock_bytes)?;
    if lock.schema_version != 1
        || lock.profile_id != request.launch().profile().id().as_str()
        || lock.image != request.launch().image().reference()
        || lock.base_image != manifest.base_image
        || parse_digest(&lock.manifest_sha256)? != manifest_sha256
    {
        return Err(WindowsBrokerAdmissionError::EvidenceRejected);
    }

    let evidence_inputs = [
        (
            EvidenceKind::Provenance,
            WindowsBrokerHostInputKind::Provenance,
            &manifest.evidence.provenance,
        ),
        (
            EvidenceKind::Sbom,
            WindowsBrokerHostInputKind::Sbom,
            &manifest.evidence.sbom,
        ),
        (
            EvidenceKind::PatchReport,
            WindowsBrokerHostInputKind::PatchReport,
            &manifest.evidence.patch_report,
        ),
        (
            EvidenceKind::Revocations,
            WindowsBrokerHostInputKind::Revocations,
            &manifest.evidence.revocations,
        ),
    ];
    let mut evidence_digests = BTreeMap::new();
    let mut dispositions = BTreeMap::new();
    let mut revocation = None;
    for (kind, input_kind, reference) in evidence_inputs {
        let bytes = inputs.document(input_kind)?;
        let digest = sha256(bytes);
        if reference.media_type != EVIDENCE_REFERENCE_MEDIA_TYPE
            || parse_digest(&reference.sha256)? != digest
        {
            return Err(WindowsBrokerAdmissionError::EvidenceRejected);
        }
        let document: EvidenceReferenceDocument = parse_document(bytes)?;
        let disposition = validate_evidence_document(
            &document,
            kind,
            request.launch().profile().id().as_str(),
            request.launch().image().reference(),
        )?;
        if let Some(value) = disposition.revocation {
            revocation = Some(value);
        }
        evidence_digests.insert(kind, digest);
        dispositions.insert(kind, disposition);
    }
    require_production_evidence(&dispositions)?;
    let revocation = revocation.ok_or(WindowsBrokerAdmissionError::EvidenceRejected)?;

    let envelope_bytes = inputs.document(WindowsBrokerHostInputKind::PromotionEnvelope)?;
    let envelope_sha256 = sha256(envelope_bytes);
    let envelope: PromotionEnvelope = parse_document(envelope_bytes)?;
    if envelope.schema_version != 1 || envelope.key_id != request.promotion().key_id() {
        return Err(WindowsBrokerAdmissionError::EvidenceRejected);
    }
    let (trust_bundle, public_key) = trust.resolve(
        request.promotion().trust_bundle_id(),
        request.promotion().key_id(),
    )?;
    let payload_bytes = Zeroizing::new(
        BASE64
            .decode(&envelope.payload_base64)
            .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?,
    );
    let signature = Zeroizing::new(
        BASE64
            .decode(&envelope.signature_base64)
            .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?,
    );
    if payload_bytes.is_empty() || payload_bytes.len() > 256 * 1024 || signature.len() != 64 {
        return Err(WindowsBrokerAdmissionError::EvidenceRejected);
    }
    let payload: PromotionPayload = parse_document(&payload_bytes)?;
    if serde_json::to_vec(&payload).map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?
        != *payload_bytes
    {
        return Err(WindowsBrokerAdmissionError::EvidenceRejected);
    }
    validate_promotion_payload(
        &payload,
        request,
        &manifest,
        &evidence_digests,
        revocation,
        now,
    )?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&payload_bytes, &signature)
        .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;

    let payload_sha256 = sha256(&payload_bytes);
    let validity = WindowsPromotionValidity::new(
        payload.issued_at_unix_millis,
        payload.expires_at_unix_millis,
    )
    .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;
    let binding = WindowsImagePromotionBinding::new(
        request.promotion().trust_bundle_id(),
        request.promotion().key_id(),
        payload_sha256,
        envelope_sha256,
        payload.promotion_serial,
        payload.revocation_generation,
        validity,
    )
    .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;
    let public_key_sha256 = sha256(public_key);
    let image_attestation_sha256 = domain_digest(
        IMAGE_ATTESTATION_DOMAIN,
        &[
            request.launch().image().digest().as_bytes(),
            manifest_sha256.as_bytes(),
            lock_sha256.as_bytes(),
            evidence_digests[&EvidenceKind::Provenance].as_bytes(),
            evidence_digests[&EvidenceKind::Sbom].as_bytes(),
            evidence_digests[&EvidenceKind::PatchReport].as_bytes(),
            evidence_digests[&EvidenceKind::Revocations].as_bytes(),
            payload_sha256.as_bytes(),
            envelope_sha256.as_bytes(),
        ],
    );
    Ok(VerifiedPromotion {
        binding,
        image_attestation_sha256,
        trust_bundle_sha256: trust_bundle.trust_bundle_sha256,
        public_key_sha256,
    })
}

fn validate_manifest(
    manifest: &ImageManifest,
    request: &WindowsBrokerAdmissionRequest,
) -> Result<(), WindowsBrokerAdmissionError> {
    if manifest.schema_version != 1
        || manifest.status != "candidate"
        || manifest.profile_id != request.launch().profile().id().as_str()
        || manifest.image != request.launch().image().reference()
        || manifest.operating_system != "windows-server-2025"
        || manifest.variant != "server-core"
        || manifest.architecture != "x86_64"
        || manifest.isolation != "hyperv-container"
        || !manifest.network_disabled
        || !manifest.unprivileged
        || !manifest.clean_workspace
        || !manifest
            .workspace
            .eq_ignore_ascii_case(request.launch().workspace())
        || !manifest
            .guest_agent
            .eq_ignore_ascii_case(request.launch().keepalive().program())
        || ImmutableImage::new(manifest.base_image.clone()).is_err()
    {
        return Err(WindowsBrokerAdmissionError::EvidenceRejected);
    }
    let expected_tools = request
        .probe()
        .tool_paths()
        .into_iter()
        .filter_map(|(kind, path)| {
            (kind != "python")
                .then_some(path.map(|path| (kind, path)))
                .flatten()
        })
        .collect::<BTreeMap<_, _>>();
    let mut actual_tools = BTreeMap::new();
    for tool in &manifest.tools {
        if tool.version.is_empty()
            || tool.version.len() > 128
            || !tool.version.is_ascii()
            || parse_digest(&tool.sha256).is_err()
            || actual_tools
                .insert(tool.kind.as_str(), tool.path.as_str())
                .is_some()
        {
            return Err(WindowsBrokerAdmissionError::EvidenceRejected);
        }
    }
    if actual_tools.len() != expected_tools.len()
        || expected_tools.iter().any(|(kind, path)| {
            actual_tools
                .get(kind)
                .is_none_or(|actual| !actual.eq_ignore_ascii_case(path))
        })
    {
        return Err(WindowsBrokerAdmissionError::EvidenceRejected);
    }
    Ok(())
}

fn validate_evidence_document(
    document: &EvidenceReferenceDocument,
    expected_kind: EvidenceKind,
    profile_id: &str,
    image: &str,
) -> Result<EvidenceDisposition, WindowsBrokerAdmissionError> {
    if document.schema_version != 1
        || document.kind != expected_kind
        || document.profile_id != profile_id
        || document.image != image
        || parse_digest(&document.subject.sha256).is_err()
        || document.subject.media_type != expected_subject_media_type(expected_kind)
        || document.statement.is_empty()
        || document.statement.len() > 4_096
        || !document.statement.is_ascii()
    {
        return Err(WindowsBrokerAdmissionError::EvidenceRejected);
    }
    if expected_kind != EvidenceKind::Revocations {
        if document.generation.is_some()
            || document.issued_at_unix_millis.is_some()
            || document.expires_at_unix_millis.is_some()
            || !document.revoked_images.is_empty()
        {
            return Err(WindowsBrokerAdmissionError::EvidenceRejected);
        }
        return Ok(EvidenceDisposition {
            candidate_fixture: document.candidate_fixture == Some(true),
            revocation: None,
        });
    }
    let generation = document
        .generation
        .filter(|generation| *generation > 0)
        .ok_or(WindowsBrokerAdmissionError::EvidenceRejected)?;
    if document.revoked_images.len() > MAX_REVOKED_IMAGES
        || document
            .revoked_images
            .iter()
            .any(|reference| ImmutableImage::new(reference.clone()).is_err())
        || document
            .revoked_images
            .iter()
            .any(|reference| reference == image)
    {
        return Err(WindowsBrokerAdmissionError::EvidenceRejected);
    }
    Ok(EvidenceDisposition {
        candidate_fixture: document.candidate_fixture == Some(true),
        revocation: Some(RevocationMetadata {
            generation,
            issued_at_unix_millis: document.issued_at_unix_millis,
            expires_at_unix_millis: document.expires_at_unix_millis,
        }),
    })
}

fn require_production_evidence(
    dispositions: &BTreeMap<EvidenceKind, EvidenceDisposition>,
) -> Result<(), WindowsBrokerAdmissionError> {
    if dispositions.len() != 4
        || dispositions
            .values()
            .any(|disposition| disposition.candidate_fixture)
    {
        return Err(WindowsBrokerAdmissionError::EvidenceRejected);
    }
    Ok(())
}

fn validate_promotion_payload(
    payload: &PromotionPayload,
    request: &WindowsBrokerAdmissionRequest,
    manifest: &ImageManifest,
    evidence: &BTreeMap<EvidenceKind, Sha256Digest>,
    revocation: RevocationMetadata,
    now: UnixMillis,
) -> Result<(), WindowsBrokerAdmissionError> {
    let now =
        u64::try_from(now.get()).map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;
    let revocation_window = match (
        revocation.issued_at_unix_millis,
        revocation.expires_at_unix_millis,
    ) {
        (Some(issued), Some(expires)) => {
            valid_signed_window(issued, expires, now)
                && issued <= payload.issued_at_unix_millis
                && expires >= payload.expires_at_unix_millis
        }
        _ => false,
    };
    if payload.schema_version != PROMOTION_PAYLOAD_SCHEMA_VERSION
        || payload.decision != "promote"
        || payload.promotion_serial == 0
        || !payload.provenance_accepted
        || !payload.sbom_accepted
        || !payload.patch_accepted
        || !payload.revocations_accepted
        || payload.profile_id != request.launch().profile().id().as_str()
        || payload.image != request.launch().image().reference()
        || payload.base_image != manifest.base_image
        || parse_digest(&payload.manifest_sha256)? != request.promotion().manifest_sha256()
        || parse_digest(&payload.lock_sha256)? != request.promotion().lock_sha256()
        || parse_digest(&payload.provenance_sha256)? != evidence[&EvidenceKind::Provenance]
        || parse_digest(&payload.sbom_sha256)? != evidence[&EvidenceKind::Sbom]
        || parse_digest(&payload.patch_report_sha256)? != evidence[&EvidenceKind::PatchReport]
        || parse_digest(&payload.revocations_sha256)? != evidence[&EvidenceKind::Revocations]
        || payload.revocation_generation == 0
        || payload.revocation_generation != revocation.generation
        || !valid_signed_window(
            payload.issued_at_unix_millis,
            payload.expires_at_unix_millis,
            now,
        )
        || !revocation_window
    {
        return Err(WindowsBrokerAdmissionError::EvidenceRejected);
    }
    Ok(())
}

fn valid_signed_window(issued: u64, expires: u64, now: u64) -> bool {
    issued > 0
        && expires > issued
        && expires.saturating_sub(issued) <= MAX_PROMOTION_LIFETIME_MILLIS
        && issued <= now.saturating_add(MAX_PROMOTION_FUTURE_SKEW_MILLIS)
        && now < expires
}

fn parse_document<'a, T: Deserialize<'a>>(
    bytes: &'a [u8],
) -> Result<T, WindowsBrokerAdmissionError> {
    serde_json::from_slice(bytes).map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)
}

fn parse_digest(value: &str) -> Result<Sha256Digest, WindowsBrokerAdmissionError> {
    Sha256Digest::from_str(value).map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)
}

const fn expected_subject_media_type(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::Provenance => "application/vnd.in-toto+json",
        EvidenceKind::Sbom => "application/spdx+json",
        EvidenceKind::PatchReport => "application/vnd.automata.windows-patch-report+json",
        EvidenceKind::Revocations => "application/vnd.automata.image-revocations+json",
    }
}

const fn admission_document_kind(kind: WindowsBrokerHostInputKind) -> bool {
    !matches!(
        kind,
        WindowsBrokerHostInputKind::Configuration | WindowsBrokerHostInputKind::BackendExecutable
    )
}

fn promotion_trust_bundle_sha256(
    trust_bundle_id: &str,
    keys: &BTreeMap<String, [u8; 32]>,
) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(PROMOTION_TRUST_BUNDLE_DOMAIN);
    digest.update((trust_bundle_id.len() as u64).to_be_bytes());
    digest.update(trust_bundle_id.as_bytes());
    digest.update((keys.len() as u64).to_be_bytes());
    for (key_id, public_key) in keys {
        digest.update((key_id.len() as u64).to_be_bytes());
        digest.update(key_id.as_bytes());
        digest.update(public_key);
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn valid_promotion_id(value: &str) -> bool {
    (3..=128).contains(&value.len())
        && value.is_ascii()
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_trust_bundle_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=128).contains(&bytes.len())
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn zero_digest(value: Sha256Digest) -> bool {
    value.as_bytes().iter().all(|byte| *byte == 0)
}

fn sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageManifest {
    schema_version: u16,
    status: String,
    profile_id: String,
    operating_system: String,
    variant: String,
    architecture: String,
    isolation: String,
    base_image: String,
    image: String,
    workspace: String,
    guest_agent: String,
    network_disabled: bool,
    unprivileged: bool,
    clean_workspace: bool,
    tools: Vec<ToolRecord>,
    evidence: EvidenceReferences,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolRecord {
    kind: ToolKind,
    path: String,
    version: String,
    sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum ToolKind {
    Pwsh,
    Powershell,
    Cmd,
    Sha256,
    Node12,
    Node16,
    Node20,
    Node24,
}

impl ToolKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pwsh => "pwsh",
            Self::Powershell => "powershell",
            Self::Cmd => "cmd",
            Self::Sha256 => "sha256",
            Self::Node12 => "node12",
            Self::Node16 => "node16",
            Self::Node20 => "node20",
            Self::Node24 => "node24",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceReferences {
    provenance: EvidenceReference,
    sbom: EvidenceReference,
    patch_report: EvidenceReference,
    revocations: EvidenceReference,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceReference {
    sha256: String,
    media_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageLock {
    schema_version: u16,
    profile_id: String,
    manifest_sha256: String,
    base_image: String,
    image: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum EvidenceKind {
    Provenance,
    Sbom,
    PatchReport,
    Revocations,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceReferenceDocument {
    schema_version: u16,
    kind: EvidenceKind,
    #[serde(default)]
    candidate_fixture: Option<bool>,
    profile_id: String,
    image: String,
    subject: EvidenceSubject,
    statement: String,
    #[serde(default)]
    generation: Option<u64>,
    #[serde(default)]
    issued_at_unix_millis: Option<u64>,
    #[serde(default)]
    expires_at_unix_millis: Option<u64>,
    #[serde(default)]
    revoked_images: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceSubject {
    sha256: String,
    media_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PromotionEnvelope {
    schema_version: u16,
    key_id: String,
    payload_base64: String,
    signature_base64: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct PromotionPayload {
    schema_version: u16,
    decision: String,
    promotion_serial: u64,
    issued_at_unix_millis: u64,
    expires_at_unix_millis: u64,
    profile_id: String,
    base_image: String,
    image: String,
    manifest_sha256: String,
    lock_sha256: String,
    provenance_sha256: String,
    sbom_sha256: String,
    patch_report_sha256: String,
    revocations_sha256: String,
    revocation_generation: u64,
    provenance_accepted: bool,
    sbom_accepted: bool,
    patch_accepted: bool,
    revocations_accepted: bool,
}

#[derive(Clone, Copy)]
struct EvidenceDisposition {
    candidate_fixture: bool,
    revocation: Option<RevocationMetadata>,
}

#[derive(Clone, Copy)]
struct RevocationMetadata {
    generation: u64,
    issued_at_unix_millis: Option<u64>,
    expires_at_unix_millis: Option<u64>,
}

/// Value-free admission failure shared by policy and the privileged service.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WindowsBrokerAdmissionError {
    /// Canonical request decoding or request binding failed.
    #[error("Windows broker admission request is invalid")]
    InvalidRequest,
    /// Host input, promotion, probe, or trust verification failed.
    #[error("Windows broker admission evidence was rejected")]
    EvidenceRejected,
    /// Durable issue/resume/completion state is absent, conflicting, or corrupt.
    #[error("Windows broker admission state is invalid")]
    InvalidState,
    /// A returned envelope is malformed, mismatched, not current, or substituted.
    #[error("Windows broker admission receipt is invalid")]
    InvalidReceipt,
    /// The complete production authority is not available.
    #[error("Windows broker admission authority is unavailable")]
    Unavailable,
}

/// Floors a broker admission issue timestamp to the database clock's
/// whole-second precision without extending the receipt expiry.
///
/// # Errors
///
/// Rejects pre-epoch timestamps.
pub fn floor_windows_admission_issued_at(
    now: UnixMillis,
) -> Result<UnixMillis, WindowsBrokerAdmissionError> {
    if now.get() < 0 {
        return Err(WindowsBrokerAdmissionError::InvalidRequest);
    }
    Ok(UnixMillis::new(
        now.get() - now.get().rem_euclid(MILLIS_PER_SECOND),
    ))
}

fn domain_digest(domain: &[u8], fields: &[&[u8]]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(domain);
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}
