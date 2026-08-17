//! Dedicated broker-owned Windows enrollment admission boundary.
//!
//! Admission receipts are never accepted through generic custody operations.
//! The authenticated broker service evaluates one canonical issue request,
//! mints the signed envelope internally, and returns only an opaque custody
//! handle plus the non-secret signed envelope. Resume and completion are
//! exact, digest-bound operations on that broker-owned record.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    str::FromStr as _,
    sync::{Arc, Mutex, PoisonError},
};

use automata_ci_core::{
    ContainerCapabilities, IsolationLevel, RunnerCapabilities, RunnerFeature, SandboxCapabilities,
    SandboxFeature, Sha256Digest, UnixMillis,
};
use automata_ci_execution::ImmutableImage;
use automata_ci_protocol::{
    WindowsAdmissionHostInputKind, WindowsAdmissionValidity, WindowsAuthorityAdmissionEvidence,
    WindowsBrokerAdmissionEvidence, WindowsBrokerProfileBinding, WindowsImagePromotionBinding,
    WindowsPromotionValidity, WindowsRunnerAdmissionBinding, WindowsRunnerAdmissionClaims,
    WindowsRunnerAdmissionEnvelope, WindowsRunnerAdmissionEvidence,
    WindowsRunnerAdmissionIssueRequest, WindowsRunnerPlacementRenewalClaims,
    WindowsRunnerPlacementRenewalEnvelope,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    BrokerError, BrokerProfileContractResolver, FileWindowsBrokerCustody,
    WINDOWS_HYPERV_PROVIDER_ID, WindowsBrokerCustodyError, WindowsBrokerCustodyHandle,
    WindowsBrokerCustodyKind, WindowsBrokerHostInputAttestation, WindowsBrokerHostInputDescriptor,
    WindowsBrokerHostInputKind, WindowsBrokerHostInputRequest,
    WindowsHyperVAdmittedProfileContract,
};

const HANDLE_COMMITMENT_DOMAIN: &[u8] = b"automata.windows-runner-admission-custody-handle.v1\0";
const MILLIS_PER_SECOND: i64 = 1_000;
const ADMISSION_LIFETIME_MILLIS: i64 = 15 * 60 * 1_000;
const STATE_SCHEMA: u16 = 1;
const CUSTODY_RECORD_SCHEMA: u16 = 1;
const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ADMISSION_RECORDS: usize = 256;
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

/// Exact result of one broker-owned admission issue or resume operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsBrokerAdmissionReceipt {
    handle: WindowsBrokerCustodyHandle,
    envelope: WindowsRunnerAdmissionEnvelope,
    envelope_sha256: Sha256Digest,
}

/// Durable, expiry-independent proof needed to complete one admission.
///
/// The signed enrollment receipt is deliberately short-lived, but control may
/// have durably committed the exact enrollment before the runner receives its
/// response. Keeping this value with the staged request allows an exact server
/// replay to finish broker tombstoning without reopening or extending the
/// expired admission authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsBrokerAdmissionCompletion {
    handle: WindowsBrokerCustodyHandle,
    envelope_sha256: Sha256Digest,
}

impl WindowsBrokerAdmissionCompletion {
    /// Constructs an exact completion proof from durable public metadata.
    ///
    /// # Errors
    ///
    /// Rejects a zero envelope commitment.
    pub fn new(
        handle: WindowsBrokerCustodyHandle,
        envelope_sha256: Sha256Digest,
    ) -> Result<Self, WindowsBrokerAdmissionError> {
        if envelope_sha256.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(WindowsBrokerAdmissionError::InvalidReceipt);
        }
        Ok(Self {
            handle,
            envelope_sha256,
        })
    }

    /// Returns the opaque broker custody handle.
    #[must_use]
    pub const fn handle(&self) -> &WindowsBrokerCustodyHandle {
        &self.handle
    }

    /// Returns the exact signed-envelope commitment.
    #[must_use]
    pub const fn envelope_sha256(&self) -> Sha256Digest {
        self.envelope_sha256
    }
}

/// Exact result of a broker-owned placement-renewal operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsBrokerPlacementRenewalReceipt {
    envelope: WindowsRunnerPlacementRenewalEnvelope,
    envelope_sha256: Sha256Digest,
}

impl WindowsBrokerPlacementRenewalReceipt {
    pub(crate) fn from_wire(
        envelope: WindowsRunnerPlacementRenewalEnvelope,
        expected_enrollment_envelope_sha256: Sha256Digest,
        observed_at: UnixMillis,
    ) -> Result<Self, WindowsBrokerAdmissionError> {
        let claims = envelope
            .claims()
            .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        let observed_at = u64::try_from(observed_at.get())
            .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        if claims.enrollment_envelope_sha256() != expected_enrollment_envelope_sha256
            || claims.validity().issued_at_unix_millis() > observed_at
            || claims.validity().expires_at_unix_millis() <= observed_at
        {
            return Err(WindowsBrokerAdmissionError::InvalidReceipt);
        }
        let envelope_sha256 = envelope.envelope_sha256();
        Ok(Self {
            envelope,
            envelope_sha256,
        })
    }

    /// Returns the complete broker-signed renewal sent on a lease request.
    #[must_use]
    pub const fn envelope(&self) -> &WindowsRunnerPlacementRenewalEnvelope {
        &self.envelope
    }

    /// Returns the byte-exact renewal-envelope commitment.
    #[must_use]
    pub const fn envelope_sha256(&self) -> Sha256Digest {
        self.envelope_sha256
    }
}

impl WindowsBrokerAdmissionReceipt {
    pub(crate) fn from_wire(
        handle: WindowsBrokerCustodyHandle,
        envelope: WindowsRunnerAdmissionEnvelope,
        expected_request_sha256: Sha256Digest,
        observed_at: UnixMillis,
    ) -> Result<Self, WindowsBrokerAdmissionError> {
        let claims = envelope
            .claims()
            .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        let observed_at = u64::try_from(observed_at.get())
            .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        if claims.binding().broker_profile().request_binding_sha256() != expected_request_sha256
            || claims.custody_handle_sha256() != custody_handle_commitment(&handle)
            || claims.validity().issued_at_unix_millis() > observed_at
            || claims.validity().expires_at_unix_millis() <= observed_at
        {
            return Err(WindowsBrokerAdmissionError::InvalidReceipt);
        }
        let envelope_sha256 = envelope.envelope_sha256();
        Ok(Self {
            handle,
            envelope,
            envelope_sha256,
        })
    }

    /// Returns the path-free broker custody capability.
    #[must_use]
    pub const fn handle(&self) -> &WindowsBrokerCustodyHandle {
        &self.handle
    }

    /// Returns the complete broker-signed envelope sent to control.
    #[must_use]
    pub const fn envelope(&self) -> &WindowsRunnerAdmissionEnvelope {
        &self.envelope
    }

    /// Returns the exact digest required for idempotent completion.
    #[must_use]
    pub const fn envelope_sha256(&self) -> Sha256Digest {
        self.envelope_sha256
    }

    /// Returns expiry-independent metadata for exact post-enrollment cleanup.
    #[must_use]
    pub fn completion(&self) -> WindowsBrokerAdmissionCompletion {
        WindowsBrokerAdmissionCompletion {
            handle: self.handle.clone(),
            envelope_sha256: self.envelope_sha256,
        }
    }
}

/// Privileged implementation behind the authenticated broker service.
///
/// Implementations must independently re-read and verify all host inputs and
/// promotion evidence, execute and clean the fixed synthetic probe, advance
/// durable serial floors, mint the Ed25519 envelope, and persist the admitted
/// launch contract before returning success.
pub trait WindowsBrokerAdmissionAuthority: fmt::Debug + Send + Sync {
    /// Mints or exactly replays one request-indexed admission record.
    ///
    /// # Errors
    ///
    /// Returns a value-free request, evidence, state, or availability error.
    fn issue(
        &self,
        request: &WindowsRunnerAdmissionIssueRequest,
        now: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsBrokerAdmissionError>;

    /// Resumes one exact live receipt without exposing generic custody bytes.
    ///
    /// # Errors
    ///
    /// Returns a value-free binding, state, receipt, or availability error.
    fn resume(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        request_sha256: Sha256Digest,
        now: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsBrokerAdmissionError>;

    /// Atomically tombstones one exact receipt after durable enrollment.
    /// Repeating the same completion is required to succeed.
    ///
    /// # Errors
    ///
    /// Returns a value-free digest, state, or availability error.
    fn complete(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        envelope_sha256: Sha256Digest,
    ) -> Result<(), WindowsBrokerAdmissionError>;

    /// Returns a retained current renewal or durably mints exactly the next
    /// serial for a completed admission handle. The implementation keeps the
    /// handle tombstoned against enrollment reuse while retaining only the
    /// minimal admitted contract needed for renewal.
    ///
    /// # Errors
    ///
    /// Returns a value-free receipt, state, evidence, or availability error.
    fn renew(
        &self,
        completed_handle: &WindowsBrokerCustodyHandle,
        enrollment_envelope_sha256: Sha256Digest,
        now: UnixMillis,
    ) -> Result<WindowsBrokerPlacementRenewalReceipt, WindowsBrokerAdmissionError>;

    /// Acknowledges that control durably accepted one exact renewal.
    ///
    /// Until this exact ACK is retained, the broker replays the same serial
    /// and never advances across an expired lost response. Repeating an exact
    /// ACK is idempotent; substituting a handle or envelope is rejected.
    ///
    /// # Errors
    ///
    /// Returns a value-free receipt, state, or availability error.
    fn acknowledge_renewal(
        &self,
        completed_handle: &WindowsBrokerCustodyHandle,
        renewal_envelope_sha256: Sha256Digest,
    ) -> Result<(), WindowsBrokerAdmissionError>;
}

/// Complete result of broker-owned input, promotion, and synthetic probing.
///
/// This type can be constructed only inside this crate after privileged
/// evaluation. The issue DTO remains non-authoritative and cannot directly
/// manufacture this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsBrokerAdmissionEvaluation {
    binding: WindowsRunnerAdmissionBinding,
    evidence: WindowsRunnerAdmissionEvidence,
    launch: automata_ci_protocol::windows_admission_issue::WindowsAdmissionLaunchContract,
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
        launch: automata_ci_protocol::windows_admission_issue::WindowsAdmissionLaunchContract,
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
    pub const fn launch(
        &self,
    ) -> &automata_ci_protocol::windows_admission_issue::WindowsAdmissionLaunchContract {
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
        request: &WindowsRunnerAdmissionIssueRequest,
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
        request: &WindowsRunnerAdmissionIssueRequest,
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
        _request: &WindowsRunnerAdmissionIssueRequest,
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
        request: &WindowsRunnerAdmissionIssueRequest,
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
            request.launch().sealed_action_policy_sha256(),
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
    request: &WindowsRunnerAdmissionIssueRequest,
) -> Result<WindowsBrokerHostInputRequest, WindowsBrokerAdmissionError> {
    let inputs = request
        .host_inputs()
        .iter()
        .map(|input| {
            WindowsBrokerHostInputDescriptor::new(
                match input.kind() {
                    WindowsAdmissionHostInputKind::Configuration => {
                        WindowsBrokerHostInputKind::Configuration
                    }
                    WindowsAdmissionHostInputKind::BackendExecutable => {
                        WindowsBrokerHostInputKind::BackendExecutable
                    }
                    WindowsAdmissionHostInputKind::ImageManifest => {
                        WindowsBrokerHostInputKind::ImageManifest
                    }
                    WindowsAdmissionHostInputKind::ImageLock => {
                        WindowsBrokerHostInputKind::ImageLock
                    }
                    WindowsAdmissionHostInputKind::Provenance => {
                        WindowsBrokerHostInputKind::Provenance
                    }
                    WindowsAdmissionHostInputKind::Sbom => WindowsBrokerHostInputKind::Sbom,
                    WindowsAdmissionHostInputKind::PatchReport => {
                        WindowsBrokerHostInputKind::PatchReport
                    }
                    WindowsAdmissionHostInputKind::Revocations => {
                        WindowsBrokerHostInputKind::Revocations
                    }
                    WindowsAdmissionHostInputKind::PromotionEnvelope => {
                        WindowsBrokerHostInputKind::PromotionEnvelope
                    }
                },
                input.absolute_path(),
                input.expected_sha256(),
            )
            .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)
        })
        .collect::<Result<Vec<_>, _>>()?;
    WindowsBrokerHostInputRequest::new(request.broker_host_id(), WINDOWS_HYPERV_PROVIDER_ID, inputs)
        .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)
}

fn shell_only_capabilities(
    request: &WindowsRunnerAdmissionIssueRequest,
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
    request: &WindowsRunnerAdmissionIssueRequest,
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
    request: &WindowsRunnerAdmissionIssueRequest,
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
    request: &WindowsRunnerAdmissionIssueRequest,
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
    Tar,
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
            Self::Tar => "tar",
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

    fn sign_admission(&self, payload: &[u8]) -> Vec<u8> {
        self.key_pair.sign(payload).as_ref().to_vec()
    }

    fn sign_renewal(
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

/// Fail-closed authority used until every production trust/input/probe
/// dependency has been initialized and reconciled.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableWindowsBrokerAdmissionAuthority;

impl WindowsBrokerAdmissionAuthority for UnavailableWindowsBrokerAdmissionAuthority {
    fn issue(
        &self,
        _request: &WindowsRunnerAdmissionIssueRequest,
        _now: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsBrokerAdmissionError> {
        Err(WindowsBrokerAdmissionError::Unavailable)
    }

    fn resume(
        &self,
        _handle: &WindowsBrokerCustodyHandle,
        _request_sha256: Sha256Digest,
        _now: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsBrokerAdmissionError> {
        Err(WindowsBrokerAdmissionError::Unavailable)
    }

    fn complete(
        &self,
        _handle: &WindowsBrokerCustodyHandle,
        _envelope_sha256: Sha256Digest,
    ) -> Result<(), WindowsBrokerAdmissionError> {
        Err(WindowsBrokerAdmissionError::Unavailable)
    }

    fn renew(
        &self,
        _completed_handle: &WindowsBrokerCustodyHandle,
        _enrollment_envelope_sha256: Sha256Digest,
        _now: UnixMillis,
    ) -> Result<WindowsBrokerPlacementRenewalReceipt, WindowsBrokerAdmissionError> {
        Err(WindowsBrokerAdmissionError::Unavailable)
    }

    fn acknowledge_renewal(
        &self,
        _completed_handle: &WindowsBrokerCustodyHandle,
        _renewal_envelope_sha256: Sha256Digest,
    ) -> Result<(), WindowsBrokerAdmissionError> {
        Err(WindowsBrokerAdmissionError::Unavailable)
    }
}

/// Crash-recoverable broker admission authority backed by service custody.
pub struct FileWindowsBrokerAdmissionAuthority {
    state_path: PathBuf,
    custody: Arc<FileWindowsBrokerCustody>,
    evaluator: Arc<dyn WindowsBrokerAdmissionEvaluator>,
    signing_key: Arc<WindowsBrokerAdmissionSigningKey>,
    state: Mutex<AdmissionState>,
}

impl FileWindowsBrokerAdmissionAuthority {
    /// Opens and reconciles one service-owned authority state file.
    ///
    /// # Errors
    ///
    /// Rejects a relative path, malformed/oversized state, custody mismatch,
    /// or an incomplete publication which cannot be recovered exactly.
    pub fn open(
        state_path: impl Into<PathBuf>,
        custody: Arc<FileWindowsBrokerCustody>,
        evaluator: Arc<dyn WindowsBrokerAdmissionEvaluator>,
        signing_key: Arc<WindowsBrokerAdmissionSigningKey>,
    ) -> Result<Self, WindowsBrokerAdmissionError> {
        let state_path = state_path.into();
        if !state_path.is_absolute() || state_path.parent().is_none() {
            return Err(WindowsBrokerAdmissionError::InvalidState);
        }
        recover_state_snapshot(&state_path)?;
        let state = read_admission_state(&state_path)?;
        let authority = Self {
            state_path,
            custody,
            evaluator,
            signing_key,
            state: Mutex::new(state),
        };
        authority.reconcile()?;
        Ok(authority)
    }

    fn reconcile(&self) -> Result<(), WindowsBrokerAdmissionError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut changed = false;
        for record in state.records.values_mut() {
            let handle = WindowsBrokerCustodyHandle::parse(&record.handle)
                .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
            let encoded = encode_custody_record(&record.custody)?;
            if sha256(&encoded) != record.custody_content_sha256 {
                return Err(WindowsBrokerAdmissionError::InvalidState);
            }
            match record.phase {
                AdmissionRecordPhase::Issuing => {
                    self.custody
                        .put_reserved(
                            &handle,
                            WindowsBrokerCustodyKind::AdmissionReceipt,
                            &encoded,
                            record.created_at,
                        )
                        .map_err(map_custody)?;
                    record.phase = AdmissionRecordPhase::Issued;
                    changed = true;
                }
                AdmissionRecordPhase::Issued => {
                    match self.custody.get_admission_receipt(&handle, false) {
                        Ok(observed) if observed.as_slice() == encoded => {}
                        Ok(_) => return Err(WindowsBrokerAdmissionError::InvalidState),
                        Err(WindowsBrokerCustodyError::Absent) => {
                            let completed = self
                                .custody
                                .get_admission_receipt(&handle, true)
                                .map_err(map_custody)?;
                            if completed.as_slice() != encoded {
                                return Err(WindowsBrokerAdmissionError::InvalidState);
                            }
                            record.phase = AdmissionRecordPhase::Completed;
                            changed = true;
                        }
                        Err(error) => return Err(map_custody(error)),
                    }
                }
                AdmissionRecordPhase::Completed => {
                    let observed = self
                        .custody
                        .get_admission_receipt(&handle, true)
                        .map_err(map_custody)?;
                    if observed.as_slice() != encoded {
                        return Err(WindowsBrokerAdmissionError::InvalidState);
                    }
                }
            }
        }
        if changed {
            persist_admission_state(&self.state_path, &state)?;
        }
        Ok(())
    }

    fn receipt_from_record(
        &self,
        record: &AdmissionStateRecord,
        expected_request_sha256: Sha256Digest,
        now: UnixMillis,
        completed: bool,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsBrokerAdmissionError> {
        let handle = WindowsBrokerCustodyHandle::parse(&record.handle)
            .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
        let observed = self
            .custody
            .get_admission_receipt(&handle, completed)
            .map_err(map_custody)?;
        let decoded: AdmissionCustodyRecord = serde_json::from_slice(&observed)
            .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
        if decoded != record.custody
            || sha256(&observed) != record.custody_content_sha256
            || decoded.request_sha256 != expected_request_sha256
        {
            return Err(WindowsBrokerAdmissionError::InvalidState);
        }
        WindowsBrokerAdmissionReceipt::from_wire(
            handle,
            decoded.envelope,
            expected_request_sha256,
            now,
        )
    }

    fn checked_evaluation(
        &self,
        request: &WindowsRunnerAdmissionIssueRequest,
        now: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionEvaluation, WindowsBrokerAdmissionError> {
        let evaluation = self.evaluator.evaluate(request, now)?;
        let request_sha256 = request
            .request_sha256()
            .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)?;
        let binding = evaluation.binding();
        if binding.transaction() != request.transaction()
            || binding.broker_profile().request_binding_sha256() != request_sha256
            || binding.broker_profile().broker_host_id() != request.broker_host_id()
            || binding.broker_profile().sandbox_provider_id() != request.sandbox_provider_id()
            || binding.capabilities().runner_id() != request.transaction().runner_id()
            || !request
                .capability_ceiling()
                .environment_profiles()
                .is_superset(binding.capabilities().environment_profiles())
            || !request
                .capability_ceiling()
                .features()
                .is_superset(binding.capabilities().features())
        {
            return Err(WindowsBrokerAdmissionError::EvidenceRejected);
        }
        Ok(evaluation)
    }

    fn enforce_and_advance_high_water(
        state: &mut AdmissionState,
        binding: &WindowsRunnerAdmissionBinding,
    ) -> Result<(), WindowsBrokerAdmissionError> {
        let promotion = binding.promotion();
        let key = promotion_head_key(binding);
        let proposed = PromotionHead {
            promotion_serial: promotion.promotion_serial(),
            revocation_generation: promotion.revocation_generation(),
            payload_sha256: promotion.payload_sha256(),
            envelope_sha256: promotion.envelope_sha256(),
        };
        if let Some(current) = state.promotion_heads.get(&key)
            && (proposed.promotion_serial < current.promotion_serial
                || proposed.revocation_generation < current.revocation_generation
                || (proposed.promotion_serial == current.promotion_serial && proposed != *current))
        {
            return Err(WindowsBrokerAdmissionError::EvidenceRejected);
        }
        state.promotion_heads.insert(key, proposed);
        Ok(())
    }
}

impl fmt::Debug for FileWindowsBrokerAdmissionAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileWindowsBrokerAdmissionAuthority")
            .field("state_path", &"[SERVICE_OWNED]")
            .field("issuer_key_id", &self.signing_key.issuer_key_id())
            .finish_non_exhaustive()
    }
}

impl WindowsBrokerAdmissionAuthority for FileWindowsBrokerAdmissionAuthority {
    #[allow(clippy::too_many_lines)]
    fn issue(
        &self,
        request: &WindowsRunnerAdmissionIssueRequest,
        now: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsBrokerAdmissionError> {
        let request_sha256 = request
            .request_sha256()
            .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)?;
        let request_key = request_sha256.to_string();
        {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(record) = state.records.get(&request_key) {
                if record.phase == AdmissionRecordPhase::Completed {
                    return Err(WindowsBrokerAdmissionError::InvalidState);
                }
                return self.receipt_from_record(record, request_sha256, now, false);
            }
        }

        let evaluation = self.checked_evaluation(request, now)?;
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(record) = state.records.get(&request_key) {
            if record.phase == AdmissionRecordPhase::Completed {
                return Err(WindowsBrokerAdmissionError::InvalidState);
            }
            return self.receipt_from_record(record, request_sha256, now, false);
        }
        if state.records.len() >= MAX_ADMISSION_RECORDS {
            return Err(WindowsBrokerAdmissionError::InvalidState);
        }
        Self::enforce_and_advance_high_water(&mut state, evaluation.binding())?;

        let issued_at = floor_windows_admission_issued_at(now)?;
        let promotion_expiry = i64::try_from(
            evaluation
                .binding()
                .promotion()
                .validity()
                .expires_at_unix_millis(),
        )
        .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;
        let expires_at = UnixMillis::new(
            issued_at
                .get()
                .checked_add(ADMISSION_LIFETIME_MILLIS)
                .ok_or(WindowsBrokerAdmissionError::InvalidRequest)?
                .min(promotion_expiry),
        );
        if expires_at <= issued_at {
            return Err(WindowsBrokerAdmissionError::EvidenceRejected);
        }
        let validity = WindowsAdmissionValidity::new(
            u64::try_from(issued_at.get())
                .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)?,
            u64::try_from(expires_at.get())
                .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)?,
        )
        .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)?;
        let handle = self
            .custody
            .reserve_handle(WindowsBrokerCustodyKind::AdmissionReceipt)
            .map_err(map_custody)?;
        let claims = WindowsRunnerAdmissionClaims::new(
            self.signing_key.issuer_key_id(),
            random_digest()?,
            custody_handle_commitment(&handle),
            random_digest()?,
            evaluation.binding().clone(),
            evaluation.evidence(),
            validity,
        )
        .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        let payload = Zeroizing::new(
            claims
                .canonical_bytes()
                .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?,
        );
        let envelope = WindowsRunnerAdmissionEnvelope::new(
            self.signing_key.issuer_key_id(),
            payload.to_vec(),
            self.signing_key.sign_admission(&payload),
        )
        .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        let custody = AdmissionCustodyRecord {
            schema: CUSTODY_RECORD_SCHEMA,
            request_sha256,
            request: request.clone(),
            envelope: envelope.clone(),
            launch: evaluation.launch().clone(),
            profile_valid_until: evaluation.profile_valid_until(),
        };
        let mut encoded = Zeroizing::new(encode_custody_record(&custody)?);
        let record = AdmissionStateRecord {
            request_sha256,
            handle: handle.opaque().to_owned(),
            custody_content_sha256: sha256(&encoded),
            created_at: issued_at,
            phase: AdmissionRecordPhase::Issuing,
            custody,
            current_renewal: None,
        };
        state.records.insert(request_key.clone(), record);
        persist_admission_state(&self.state_path, &state)?;
        self.custody
            .put_reserved(
                &handle,
                WindowsBrokerCustodyKind::AdmissionReceipt,
                &encoded,
                issued_at,
            )
            .map_err(map_custody)?;
        encoded.zeroize();
        let record = state
            .records
            .get_mut(&request_key)
            .ok_or(WindowsBrokerAdmissionError::InvalidState)?;
        record.phase = AdmissionRecordPhase::Issued;
        persist_admission_state(&self.state_path, &state)?;
        WindowsBrokerAdmissionReceipt::from_wire(handle, envelope, request_sha256, now)
    }

    fn resume(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        request_sha256: Sha256Digest,
        now: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsBrokerAdmissionError> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let record = state
            .records
            .get(&request_sha256.to_string())
            .filter(|record| {
                record.handle == handle.opaque() && record.phase == AdmissionRecordPhase::Issued
            })
            .ok_or(WindowsBrokerAdmissionError::InvalidState)?;
        self.receipt_from_record(record, request_sha256, now, false)
    }

    fn complete(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        envelope_sha256: Sha256Digest,
    ) -> Result<(), WindowsBrokerAdmissionError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let record = state
            .records
            .values_mut()
            .find(|record| record.handle == handle.opaque())
            .ok_or(WindowsBrokerAdmissionError::InvalidState)?;
        if record.custody.envelope.envelope_sha256() != envelope_sha256 {
            return Err(WindowsBrokerAdmissionError::InvalidReceipt);
        }
        self.custody
            .complete_admission_receipt(handle, record.custody_content_sha256)
            .map_err(map_custody)?;
        if record.phase != AdmissionRecordPhase::Completed {
            record.phase = AdmissionRecordPhase::Completed;
            persist_admission_state(&self.state_path, &state)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn renew(
        &self,
        completed_handle: &WindowsBrokerCustodyHandle,
        enrollment_envelope_sha256: Sha256Digest,
        now: UnixMillis,
    ) -> Result<WindowsBrokerPlacementRenewalReceipt, WindowsBrokerAdmissionError> {
        let (request, original_binding) = {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let record = state
                .records
                .values()
                .find(|record| {
                    record.handle == completed_handle.opaque()
                        && record.phase == AdmissionRecordPhase::Completed
                })
                .ok_or(WindowsBrokerAdmissionError::InvalidState)?;
            if record.custody.envelope.envelope_sha256() != enrollment_envelope_sha256 {
                return Err(WindowsBrokerAdmissionError::InvalidReceipt);
            }
            if let Some(current) = &record.current_renewal
                && !current.acknowledged
            {
                let claims = current
                    .envelope
                    .claims()
                    .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
                if now.get()
                    >= i64::try_from(claims.validity().expires_at_unix_millis())
                        .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?
                {
                    return Err(WindowsBrokerAdmissionError::InvalidState);
                }
                return WindowsBrokerPlacementRenewalReceipt::from_wire(
                    current.envelope.clone(),
                    enrollment_envelope_sha256,
                    now,
                );
            }
            let claims = record
                .custody
                .envelope
                .claims()
                .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
            (record.custody.request.clone(), claims.binding().clone())
        };
        let evaluation = self.checked_evaluation(&request, now)?;
        if evaluation.binding() != &original_binding {
            return Err(WindowsBrokerAdmissionError::EvidenceRejected);
        }
        let issued_at = floor_windows_admission_issued_at(now)?;
        let promotion_expiry = i64::try_from(
            original_binding
                .promotion()
                .validity()
                .expires_at_unix_millis(),
        )
        .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;
        let expires_at = UnixMillis::new(
            issued_at
                .get()
                .checked_add(ADMISSION_LIFETIME_MILLIS)
                .ok_or(WindowsBrokerAdmissionError::InvalidRequest)?
                .min(promotion_expiry),
        );
        if expires_at <= issued_at {
            return Err(WindowsBrokerAdmissionError::EvidenceRejected);
        }

        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let record = state
            .records
            .values_mut()
            .find(|record| {
                record.handle == completed_handle.opaque()
                    && record.phase == AdmissionRecordPhase::Completed
            })
            .ok_or(WindowsBrokerAdmissionError::InvalidState)?;
        if record.custody.envelope.envelope_sha256() != enrollment_envelope_sha256 {
            return Err(WindowsBrokerAdmissionError::InvalidReceipt);
        }
        if let Some(current) = &record.current_renewal
            && !current.acknowledged
        {
            let claims = current
                .envelope
                .claims()
                .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
            if now.get()
                >= i64::try_from(claims.validity().expires_at_unix_millis())
                    .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?
            {
                return Err(WindowsBrokerAdmissionError::InvalidState);
            }
            return WindowsBrokerPlacementRenewalReceipt::from_wire(
                current.envelope.clone(),
                enrollment_envelope_sha256,
                now,
            );
        }
        let serial = record
            .current_renewal
            .as_ref()
            .map_or(1, |current| current.serial.saturating_add(1));
        if serial == 0 {
            return Err(WindowsBrokerAdmissionError::InvalidState);
        }
        let validity = WindowsAdmissionValidity::new(
            u64::try_from(issued_at.get())
                .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)?,
            u64::try_from(expires_at.get())
                .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)?,
        )
        .map_err(|_| WindowsBrokerAdmissionError::InvalidRequest)?;
        let claims = WindowsRunnerPlacementRenewalClaims::new(
            self.signing_key.issuer_key_id(),
            original_binding.transaction().runner_id(),
            serial,
            random_digest()?,
            enrollment_envelope_sha256,
            original_binding,
            // Evidence is freshly re-evaluated. Keep the original value only
            // to make the non-use explicit in case the evaluator changes it.
            evaluation.evidence(),
            validity,
        )
        .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        let payload = claims
            .canonical_bytes()
            .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        let envelope = WindowsRunnerPlacementRenewalEnvelope::new(
            self.signing_key.issuer_key_id(),
            payload,
            self.signing_key.sign_renewal(&claims)?,
        )
        .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        record.current_renewal = Some(AdmissionRenewalState {
            serial,
            envelope: envelope.clone(),
            acknowledged: false,
        });
        persist_admission_state(&self.state_path, &state)?;
        WindowsBrokerPlacementRenewalReceipt::from_wire(envelope, enrollment_envelope_sha256, now)
    }

    fn acknowledge_renewal(
        &self,
        completed_handle: &WindowsBrokerCustodyHandle,
        renewal_envelope_sha256: Sha256Digest,
    ) -> Result<(), WindowsBrokerAdmissionError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let record = state
            .records
            .values_mut()
            .find(|record| {
                record.handle == completed_handle.opaque()
                    && record.phase == AdmissionRecordPhase::Completed
            })
            .ok_or(WindowsBrokerAdmissionError::InvalidState)?;
        let renewal = record
            .current_renewal
            .as_mut()
            .filter(|renewal| renewal.envelope.envelope_sha256() == renewal_envelope_sha256)
            .ok_or(WindowsBrokerAdmissionError::InvalidReceipt)?;
        if !renewal.acknowledged {
            renewal.acknowledged = true;
            persist_admission_state(&self.state_path, &state)?;
        }
        Ok(())
    }
}

impl BrokerProfileContractResolver for FileWindowsBrokerAdmissionAuthority {
    fn resolve(
        &self,
        profile_contract_sha256: Sha256Digest,
    ) -> Result<Option<WindowsHyperVAdmittedProfileContract>, BrokerError> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(record) = state.records.values().find(|record| {
            if record.phase != AdmissionRecordPhase::Completed {
                return false;
            }
            record.custody.envelope.claims().is_ok_and(|claims| {
                claims.evidence().broker().profile_contract_sha256() == profile_contract_sha256
            })
        }) else {
            return Ok(None);
        };
        let claims = record
            .custody
            .envelope
            .claims()
            .map_err(|_| BrokerError::InvalidProfileContract)?;
        let host_id = claims
            .binding()
            .broker_profile()
            .broker_host_id()
            .parse()
            .map_err(|_| BrokerError::InvalidProfileContract)?;
        WindowsHyperVAdmittedProfileContract::new(
            host_id,
            profile_contract_sha256,
            record.custody.launch.clone(),
            record.custody.profile_valid_until,
        )
        .map(Some)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AdmissionCustodyRecord {
    schema: u16,
    request_sha256: Sha256Digest,
    request: WindowsRunnerAdmissionIssueRequest,
    envelope: WindowsRunnerAdmissionEnvelope,
    launch: automata_ci_protocol::windows_admission_issue::WindowsAdmissionLaunchContract,
    profile_valid_until: UnixMillis,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AdmissionRecordPhase {
    Issuing,
    Issued,
    Completed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AdmissionRenewalState {
    serial: u64,
    envelope: WindowsRunnerPlacementRenewalEnvelope,
    acknowledged: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AdmissionStateRecord {
    request_sha256: Sha256Digest,
    handle: String,
    custody_content_sha256: Sha256Digest,
    created_at: UnixMillis,
    phase: AdmissionRecordPhase,
    custody: AdmissionCustodyRecord,
    current_renewal: Option<AdmissionRenewalState>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PromotionHead {
    promotion_serial: u64,
    revocation_generation: u64,
    payload_sha256: Sha256Digest,
    envelope_sha256: Sha256Digest,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AdmissionState {
    schema: u16,
    records: BTreeMap<String, AdmissionStateRecord>,
    promotion_heads: BTreeMap<String, PromotionHead>,
}

impl Default for AdmissionState {
    fn default() -> Self {
        Self {
            schema: STATE_SCHEMA,
            records: BTreeMap::new(),
            promotion_heads: BTreeMap::new(),
        }
    }
}

fn encode_custody_record(
    record: &AdmissionCustodyRecord,
) -> Result<Vec<u8>, WindowsBrokerAdmissionError> {
    if record.schema != CUSTODY_RECORD_SCHEMA
        || record.request_sha256
            != record
                .request
                .request_sha256()
                .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?
        || record
            .envelope
            .claims()
            .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?
            .binding()
            .broker_profile()
            .request_binding_sha256()
            != record.request_sha256
    {
        return Err(WindowsBrokerAdmissionError::InvalidState);
    }
    serde_json::to_vec(record).map_err(|_| WindowsBrokerAdmissionError::InvalidState)
}

fn promotion_head_key(binding: &WindowsRunnerAdmissionBinding) -> String {
    format!(
        "{}\0{}\0{}\0{}",
        binding.broker_profile().broker_host_id(),
        binding.promotion().trust_bundle_id(),
        binding.promotion().key_id(),
        binding.broker_profile().profile().digest(),
    )
}

fn map_custody(_error: WindowsBrokerCustodyError) -> WindowsBrokerAdmissionError {
    WindowsBrokerAdmissionError::InvalidState
}

fn random_digest() -> Result<Sha256Digest, WindowsBrokerAdmissionError> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(WindowsBrokerAdmissionError::InvalidState);
    }
    let digest = Sha256Digest::from_bytes(*bytes);
    bytes.zeroize();
    Ok(digest)
}

fn sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn valid_authority_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=128).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(byte))
}

fn read_admission_state(path: &Path) -> Result<AdmissionState, WindowsBrokerAdmissionError> {
    if !path.exists() {
        return Ok(AdmissionState::default());
    }
    let mut file = File::open(path).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
    if file
        .metadata()
        .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?
        .len()
        > MAX_STATE_BYTES
    {
        return Err(WindowsBrokerAdmissionError::InvalidState);
    }
    let mut encoded = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_STATE_BYTES.saturating_add(1))
        .read_to_end(&mut encoded)
        .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
    if encoded.is_empty() || encoded.len() as u64 > MAX_STATE_BYTES {
        return Err(WindowsBrokerAdmissionError::InvalidState);
    }
    let state: AdmissionState =
        serde_json::from_slice(&encoded).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
    if state.schema != STATE_SCHEMA
        || state.records.len() > MAX_ADMISSION_RECORDS
        || state.records.iter().any(|(key, record)| {
            key != &record.request_sha256.to_string()
                || WindowsBrokerCustodyHandle::parse(&record.handle).is_err()
                || record.custody.request_sha256 != record.request_sha256
        })
    {
        return Err(WindowsBrokerAdmissionError::InvalidState);
    }
    Ok(state)
}

fn persist_admission_state(
    path: &Path,
    state: &AdmissionState,
) -> Result<(), WindowsBrokerAdmissionError> {
    if state.schema != STATE_SCHEMA || state.records.len() > MAX_ADMISSION_RECORDS {
        return Err(WindowsBrokerAdmissionError::InvalidState);
    }
    let encoded =
        serde_json::to_vec(state).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
    if encoded.is_empty() || encoded.len() as u64 > MAX_STATE_BYTES {
        return Err(WindowsBrokerAdmissionError::InvalidState);
    }
    let (temporary, previous) = state_sidecars(path)?;
    if temporary.exists() || previous.exists() {
        return Err(WindowsBrokerAdmissionError::InvalidState);
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
    drop(file);
    if path.exists() {
        fs::rename(path, &previous).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
    }
    if fs::rename(&temporary, path).is_err() {
        if previous.exists() && !path.exists() {
            let _ = fs::rename(&previous, path);
        }
        return Err(WindowsBrokerAdmissionError::InvalidState);
    }
    if previous.exists() {
        fs::remove_file(previous).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
    }
    Ok(())
}

fn recover_state_snapshot(path: &Path) -> Result<(), WindowsBrokerAdmissionError> {
    let (temporary, previous) = state_sidecars(path)?;
    if path.exists() {
        let _ = read_admission_state(path)?;
        if temporary.exists() {
            fs::remove_file(&temporary).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
        }
        if previous.exists() {
            fs::remove_file(&previous).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
        }
        return Ok(());
    }
    if temporary.exists() {
        let _ = read_admission_state(&temporary)?;
        fs::rename(&temporary, path).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
        if previous.exists() {
            fs::remove_file(previous).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
        }
        return Ok(());
    }
    if previous.exists() {
        let _ = read_admission_state(&previous)?;
        fs::rename(previous, path).map_err(|_| WindowsBrokerAdmissionError::InvalidState)?;
    }
    Ok(())
}

fn state_sidecars(path: &Path) -> Result<(PathBuf, PathBuf), WindowsBrokerAdmissionError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(WindowsBrokerAdmissionError::InvalidState)?;
    Ok((
        path.with_file_name(format!("{name}.write.tmp")),
        path.with_file_name(format!("{name}.previous")),
    ))
}

/// Value-free admission failure returned by the privileged service.
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

pub(crate) fn custody_handle_commitment(handle: &WindowsBrokerCustodyHandle) -> Sha256Digest {
    domain_digest(HANDLE_COMMITMENT_DOMAIN, &[handle.opaque().as_bytes()])
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WindowsBrokerHostInputObservation;
    use automata_ci_core::{
        Architecture, EnvironmentProfile, EnvironmentProfileId, JobResourceAllocation,
        OperatingSystem, OperationId, ResourceCapacity, RunnerId, RunnerPlatform,
        windows_action_archive_policy_sha256,
    };
    use automata_ci_protocol::{
        WindowsAdmissionArgv, WindowsAdmissionBackendContract, WindowsAdmissionHostInput,
        WindowsAdmissionImage, WindowsAdmissionLaunchContract, WindowsAdmissionProbeContract,
        WindowsAdmissionPromotionRequest, WindowsAdmissionResourceLimits,
        WindowsEnrollmentTransactionBinding,
    };
    use ring::rand::SystemRandom;
    use std::sync::Barrier;

    const TEST_NOW_MILLIS: i64 = 1_000_000;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum PromotionFault {
        None,
        WrongSignature,
        UnknownKey,
        NonCanonicalPayload,
        Stale,
        CandidateEvidence,
    }

    #[derive(Debug)]
    struct FixtureInputSource {
        host_id: Sha256Digest,
        documents: BTreeMap<WindowsBrokerHostInputKind, Vec<u8>>,
    }

    impl WindowsBrokerAdmissionInputSource for FixtureInputSource {
        fn load(
            &self,
            request: &WindowsBrokerHostInputRequest,
            issued_at: UnixMillis,
            valid_until: UnixMillis,
        ) -> Result<WindowsBrokerAdmissionInputSet, WindowsBrokerAdmissionError> {
            let observations = request
                .inputs()
                .iter()
                .enumerate()
                .map(|(index, descriptor)| {
                    let byte_len = self.documents.get(&descriptor.kind()).map_or(64, Vec::len);
                    WindowsBrokerHostInputObservation::new(
                        descriptor,
                        u64::try_from(byte_len)
                            .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?,
                        41,
                        [u8::try_from(index + 1)
                            .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;
                            16],
                        "S-1-5-80-1-2-3-4-5".to_owned(),
                        Sha256Digest::from_bytes([91; 32]),
                    )
                    .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let attestation = WindowsBrokerHostInputAttestation::issue(
                self.host_id,
                request,
                observations,
                issued_at,
                valid_until,
            )
            .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;
            let documents = self
                .documents
                .iter()
                .map(|(kind, bytes)| (*kind, Zeroizing::new(bytes.clone())))
                .collect();
            WindowsBrokerAdmissionInputSet::new(request, attestation, documents)
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct FixtureProbe;

    impl WindowsBrokerSyntheticProbe for FixtureProbe {
        fn execute(
            &self,
            _request: &WindowsRunnerAdmissionIssueRequest,
            _host_inputs: &WindowsBrokerHostInputAttestation,
            _now: UnixMillis,
            _valid_until: UnixMillis,
        ) -> Result<WindowsBrokerSyntheticProbeEvidence, WindowsBrokerAdmissionError> {
            WindowsBrokerSyntheticProbeEvidence::new(
                Sha256Digest::from_bytes([92; 32]),
                Sha256Digest::from_bytes([93; 32]),
                Sha256Digest::from_bytes([94; 32]),
            )
        }
    }

    #[derive(Debug)]
    struct BarrierAdmissionEvaluator {
        inner: Arc<dyn WindowsBrokerAdmissionEvaluator>,
        rendezvous: Arc<Barrier>,
    }

    impl WindowsBrokerAdmissionEvaluator for BarrierAdmissionEvaluator {
        fn evaluate(
            &self,
            request: &WindowsRunnerAdmissionIssueRequest,
            now: UnixMillis,
        ) -> Result<WindowsBrokerAdmissionEvaluation, WindowsBrokerAdmissionError> {
            self.rendezvous.wait();
            self.inner.evaluate(request, now)
        }
    }

    #[derive(Debug)]
    struct FixtureProtector;

    impl crate::WindowsBrokerCustodyProtector for FixtureProtector {
        fn seal(&self, plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, WindowsBrokerCustodyError> {
            let mut sealed = b"admission-test-v1:".to_vec();
            sealed.extend(plaintext.iter().map(|byte| byte ^ 0xa5));
            Ok(Zeroizing::new(sealed))
        }

        fn open(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, WindowsBrokerCustodyError> {
            let ciphertext = sealed
                .strip_prefix(b"admission-test-v1:")
                .ok_or(WindowsBrokerCustodyError::Protector)?;
            Ok(Zeroizing::new(
                ciphertext.iter().map(|byte| byte ^ 0xa5).collect(),
            ))
        }
    }

    struct PromotionFixture {
        host_id: Sha256Digest,
        request: WindowsRunnerAdmissionIssueRequest,
        documents: BTreeMap<WindowsBrokerHostInputKind, Vec<u8>>,
        trust: WindowsBrokerPromotionTrustRegistry,
    }

    impl PromotionFixture {
        fn evaluator(&self) -> VerifiedWindowsBrokerAdmissionEvaluator {
            VerifiedWindowsBrokerAdmissionEvaluator::new(
                self.host_id,
                Arc::new(FixtureInputSource {
                    host_id: self.host_id,
                    documents: self.documents.clone(),
                }),
                self.trust.clone(),
                Arc::new(FixtureProbe),
            )
            .expect("fixture evaluator")
        }
    }

    fn evidence_document(
        kind: &str,
        subject_media_type: &str,
        image: &str,
        candidate_fixture: bool,
        revocation_expiry: Option<u64>,
    ) -> Vec<u8> {
        let mut document = serde_json::json!({
            "schema_version": 1,
            "kind": kind,
            "candidate_fixture": candidate_fixture,
            "profile_id": "example.com/windows-server-2025",
            "image": image,
            "subject": {
                "sha256": Sha256Digest::from_bytes([52; 32]).to_string(),
                "media_type": subject_media_type,
            },
            "statement": "production evidence accepted",
        });
        if kind == "revocations" {
            let object = document.as_object_mut().expect("evidence object");
            object.insert("generation".to_owned(), serde_json::json!(7));
            object.insert(
                "issued_at_unix_millis".to_owned(),
                serde_json::json!(800_000_u64),
            );
            object.insert(
                "expires_at_unix_millis".to_owned(),
                serde_json::json!(revocation_expiry.expect("revocation expiry")),
            );
            object.insert("revoked_images".to_owned(), serde_json::json!([]));
        }
        serde_json::to_vec(&document).expect("evidence document")
    }

    #[allow(clippy::too_many_lines)]
    fn promotion_fixture(fault: PromotionFault, sealed_action_trees: bool) -> PromotionFixture {
        let host_id = Sha256Digest::from_bytes([11; 32]);
        let image_digest = Sha256Digest::from_bytes([12; 32]);
        let image = format!("registry.example/windows/runner@sha256:{image_digest}");
        let base_digest = Sha256Digest::from_bytes([13; 32]);
        let base_image = format!("registry.example/windows/base@sha256:{base_digest}");
        let promotion_expiry = if fault == PromotionFault::Stale {
            u64::try_from(TEST_NOW_MILLIS).expect("positive test clock")
        } else {
            2_000_000
        };

        let provenance = evidence_document(
            "provenance",
            "application/vnd.in-toto+json",
            &image,
            false,
            None,
        );
        let sbom = evidence_document(
            "sbom",
            "application/spdx+json",
            &image,
            fault == PromotionFault::CandidateEvidence,
            None,
        );
        let patch_report = evidence_document(
            "patch_report",
            "application/vnd.automata.windows-patch-report+json",
            &image,
            false,
            None,
        );
        let revocations = evidence_document(
            "revocations",
            "application/vnd.automata.image-revocations+json",
            &image,
            false,
            Some(promotion_expiry),
        );
        let provenance_sha256 = sha256(&provenance);
        let sbom_sha256 = sha256(&sbom);
        let patch_report_sha256 = sha256(&patch_report);
        let revocations_sha256 = sha256(&revocations);
        let tool_sha256 = Sha256Digest::from_bytes([14; 32]).to_string();
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "status": "candidate",
            "profile_id": "example.com/windows-server-2025",
            "operating_system": "windows-server-2025",
            "variant": "server-core",
            "architecture": "x86_64",
            "isolation": "hyperv-container",
            "base_image": base_image,
            "image": image,
            "workspace": r"C:\Automata\workspace",
            "guest_agent": r"C:\Automata\guest.exe",
            "network_disabled": true,
            "unprivileged": true,
            "clean_workspace": true,
            "tools": [
                {"kind": "pwsh", "path": r"C:\Program Files\PowerShell\7\pwsh.exe", "version": "7.4", "sha256": tool_sha256},
                {"kind": "powershell", "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "version": "5.1", "sha256": tool_sha256},
                {"kind": "cmd", "path": r"C:\Windows\System32\cmd.exe", "version": "10.0", "sha256": tool_sha256},
                {"kind": "tar", "path": r"C:\Windows\System32\tar.exe", "version": "10.0", "sha256": tool_sha256},
                {"kind": "sha256", "path": r"C:\Windows\System32\certutil.exe", "version": "10.0", "sha256": tool_sha256},
            ],
            "evidence": {
                "provenance": {"sha256": provenance_sha256.to_string(), "media_type": EVIDENCE_REFERENCE_MEDIA_TYPE},
                "sbom": {"sha256": sbom_sha256.to_string(), "media_type": EVIDENCE_REFERENCE_MEDIA_TYPE},
                "patch_report": {"sha256": patch_report_sha256.to_string(), "media_type": EVIDENCE_REFERENCE_MEDIA_TYPE},
                "revocations": {"sha256": revocations_sha256.to_string(), "media_type": EVIDENCE_REFERENCE_MEDIA_TYPE},
            },
        }))
        .expect("manifest");
        let manifest_sha256 = sha256(&manifest);
        let lock = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "profile_id": "example.com/windows-server-2025",
            "manifest_sha256": manifest_sha256.to_string(),
            "base_image": base_image,
            "image": image,
        }))
        .expect("lock");
        let lock_sha256 = sha256(&lock);
        let payload = PromotionPayload {
            schema_version: PROMOTION_PAYLOAD_SCHEMA_VERSION,
            decision: "promote".to_owned(),
            promotion_serial: 17,
            issued_at_unix_millis: 900_000,
            expires_at_unix_millis: promotion_expiry,
            profile_id: "example.com/windows-server-2025".to_owned(),
            base_image: base_image.clone(),
            image: image.clone(),
            manifest_sha256: manifest_sha256.to_string(),
            lock_sha256: lock_sha256.to_string(),
            provenance_sha256: provenance_sha256.to_string(),
            sbom_sha256: sbom_sha256.to_string(),
            patch_report_sha256: patch_report_sha256.to_string(),
            revocations_sha256: revocations_sha256.to_string(),
            revocation_generation: 7,
            provenance_accepted: true,
            sbom_accepted: true,
            patch_accepted: true,
            revocations_accepted: true,
        };
        let mut payload_bytes = serde_json::to_vec(&payload).expect("payload");
        if fault == PromotionFault::NonCanonicalPayload {
            payload_bytes.push(b' ');
        }
        let trusted_key_pair =
            Ed25519KeyPair::from_seed_unchecked(&[61; 32]).expect("trusted promotion key");
        let signing_key_pair = if fault == PromotionFault::WrongSignature {
            Ed25519KeyPair::from_seed_unchecked(&[62; 32]).expect("untrusted promotion key")
        } else {
            Ed25519KeyPair::from_seed_unchecked(&[61; 32]).expect("promotion key")
        };
        let requested_key_id = if fault == PromotionFault::UnknownKey {
            "missing-promotion-key"
        } else {
            "windows-promotion-key"
        };
        let signature = signing_key_pair.sign(&payload_bytes);
        let promotion_envelope = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "key_id": requested_key_id,
            "payload_base64": BASE64.encode(&payload_bytes),
            "signature_base64": BASE64.encode(signature.as_ref()),
        }))
        .expect("promotion envelope");

        let backend_path = r"C:\Program Files\Automata\automata-windows-hyperv-broker-client.exe";
        let envelope_path = r"C:\Automata\promotion-envelope.json";
        let input_values = [
            (
                WindowsAdmissionHostInputKind::Configuration,
                r"C:\Automata\runner.json",
                Sha256Digest::from_bytes([31; 32]),
            ),
            (
                WindowsAdmissionHostInputKind::BackendExecutable,
                backend_path,
                Sha256Digest::from_bytes([32; 32]),
            ),
            (
                WindowsAdmissionHostInputKind::ImageManifest,
                r"C:\Automata\image-manifest.json",
                manifest_sha256,
            ),
            (
                WindowsAdmissionHostInputKind::ImageLock,
                r"C:\Automata\image-lock.json",
                lock_sha256,
            ),
            (
                WindowsAdmissionHostInputKind::Provenance,
                r"C:\Automata\provenance.json",
                provenance_sha256,
            ),
            (
                WindowsAdmissionHostInputKind::Sbom,
                r"C:\Automata\sbom.json",
                sbom_sha256,
            ),
            (
                WindowsAdmissionHostInputKind::PatchReport,
                r"C:\Automata\patch-report.json",
                patch_report_sha256,
            ),
            (
                WindowsAdmissionHostInputKind::Revocations,
                r"C:\Automata\revocations.json",
                revocations_sha256,
            ),
            (
                WindowsAdmissionHostInputKind::PromotionEnvelope,
                envelope_path,
                sha256(&promotion_envelope),
            ),
        ];
        let host_inputs = input_values
            .into_iter()
            .map(|(kind, path, digest)| {
                WindowsAdmissionHostInput::new(kind, path, digest).expect("host input")
            })
            .collect();
        let profile = EnvironmentProfile::new(
            EnvironmentProfileId::new("example.com/windows-server-2025").expect("profile id"),
            Sha256Digest::from_bytes([15; 32]),
        );
        let capacity = ResourceCapacity::new(2_000, 2 * 1024 * 1024 * 1024, 0, 0);
        let allocation = JobResourceAllocation::new(capacity, capacity).expect("allocation");
        let resources = WindowsAdmissionResourceLimits::new(2 * 1024 * 1024 * 1024, 2_000, 128)
            .expect("resource limits");
        let launch = WindowsAdmissionLaunchContract::new(
            profile.clone(),
            WindowsAdmissionImage::new(image, image_digest).expect("image"),
            WindowsAdmissionArgv::new(r"C:\Automata\guest.exe", vec!["keepalive".to_owned()])
                .expect("keepalive"),
            r"C:\Automata\workspace",
            Vec::new(),
            resources,
            allocation,
            true,
            true,
            true,
            true,
            sealed_action_trees,
            windows_action_archive_policy_sha256(),
        )
        .expect("launch");
        let probe = WindowsAdmissionProbeContract::new(
            1,
            Sha256Digest::from_bytes([16; 32]),
            resources,
            allocation,
            true,
            true,
            true,
            r"C:\Program Files\PowerShell\7\pwsh.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\System32\cmd.exe",
            None,
            r"C:\Windows\System32\tar.exe",
            r"C:\Windows\System32\certutil.exe",
            None,
            None,
            None,
            None,
        )
        .expect("probe");
        let runner_id = RunnerId::new();
        let runner_name = "windows-runner";
        let transaction = WindowsEnrollmentTransactionBinding::new(
            runner_id,
            OperationId::new(),
            "https://control.example/",
            "https://enrollment.example/",
            sha256(runner_name.as_bytes()),
            Sha256Digest::from_bytes([17; 32]),
            Sha256Digest::from_bytes([18; 32]),
        )
        .expect("transaction");
        let mut features = vec![
            RunnerFeature::SHELL_STEPS,
            RunnerFeature::DEFAULT_WINDOWS_SHELL,
            RunnerFeature::PWSH_SHELL,
            RunnerFeature::WINDOWS_POWERSHELL_SHELL,
            RunnerFeature::CMD_SHELL,
        ];
        if sealed_action_trees {
            features.extend([
                RunnerFeature::REPOSITORY_ACTIONS,
                RunnerFeature::COMPOSITE_ACTIONS,
            ]);
        }
        let capabilities = RunnerCapabilities::new(
            runner_id,
            RunnerPlatform::new(OperatingSystem::Windows, Architecture::X86_64),
        )
        .with_max_parallel_jobs(1)
        .expect("parallel jobs")
        .with_resources_per_job(capacity)
        .with_sandbox(SandboxCapabilities::new(
            IsolationLevel::VirtualMachine,
            [
                SandboxFeature::CLEAN_WORKSPACE,
                SandboxFeature::NETWORK_ISOLATION,
                SandboxFeature::WINDOWS_HYPERV_CONTAINER,
            ],
        ))
        .with_containers(ContainerCapabilities::default())
        .with_features(features)
        .with_environment_profiles([profile]);
        let promotion = WindowsAdmissionPromotionRequest::new(
            envelope_path,
            "windows-production-v1",
            requested_key_id,
            manifest_sha256,
            lock_sha256,
        )
        .expect("promotion request");
        let request = WindowsRunnerAdmissionIssueRequest::new(
            transaction,
            runner_name,
            host_id.to_string(),
            WINDOWS_HYPERV_PROVIDER_ID,
            WindowsAdmissionBackendContract::new(
                backend_path,
                Sha256Digest::from_bytes([32; 32]),
                120_000,
            )
            .expect("backend"),
            host_inputs,
            launch,
            probe,
            promotion,
            capabilities,
        )
        .expect("issue request");
        let documents = BTreeMap::from([
            (WindowsBrokerHostInputKind::ImageManifest, manifest),
            (WindowsBrokerHostInputKind::ImageLock, lock),
            (WindowsBrokerHostInputKind::Provenance, provenance),
            (WindowsBrokerHostInputKind::Sbom, sbom),
            (WindowsBrokerHostInputKind::PatchReport, patch_report),
            (WindowsBrokerHostInputKind::Revocations, revocations),
            (
                WindowsBrokerHostInputKind::PromotionEnvelope,
                promotion_envelope,
            ),
        ]);
        let trusted_public_key: [u8; 32] = trusted_key_pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("public key length");
        let trust_key =
            WindowsBrokerPromotionTrustKey::new("windows-promotion-key", trusted_public_key)
                .expect("trust key");
        let trust_sha256 = WindowsBrokerPromotionTrustBundle::canonical_sha256(
            "windows-production-v1",
            std::slice::from_ref(&trust_key),
        );
        let trust = WindowsBrokerPromotionTrustRegistry::new(vec![
            WindowsBrokerPromotionTrustBundle::new(
                "windows-production-v1",
                trust_sha256,
                vec![trust_key],
            )
            .expect("trust bundle"),
        ])
        .expect("trust registry");
        PromotionFixture {
            host_id,
            request,
            documents,
            trust,
        }
    }

    fn temp_root() -> PathBuf {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).expect("random temp root");
        std::env::temp_dir().join(format!("automata-admission-{}", sha256(&nonce)))
    }

    fn signing_key(pkcs8: &[u8]) -> Arc<WindowsBrokerAdmissionSigningKey> {
        Arc::new(
            WindowsBrokerAdmissionSigningKey::from_pkcs8("windows-admission-key", pkcs8)
                .expect("admission signing key"),
        )
    }

    fn binding_with_promotion(
        binding: &WindowsRunnerAdmissionBinding,
        serial: u64,
        revocation_generation: u64,
        digest_marker: u8,
    ) -> WindowsRunnerAdmissionBinding {
        let promotion = WindowsImagePromotionBinding::new(
            binding.promotion().trust_bundle_id(),
            binding.promotion().key_id(),
            Sha256Digest::from_bytes([digest_marker; 32]),
            Sha256Digest::from_bytes([digest_marker.saturating_add(1); 32]),
            serial,
            revocation_generation,
            binding.promotion().validity(),
        )
        .expect("promotion binding");
        WindowsRunnerAdmissionBinding::new(
            binding.transaction().clone(),
            binding.broker_profile().clone(),
            promotion,
            binding.capabilities().clone(),
        )
        .expect("admission binding")
    }

    #[test]
    fn issue_timestamp_is_floored_without_moving_expiry() {
        let observed = UnixMillis::new(12_345);
        let expiry = UnixMillis::new(912_345);
        assert_eq!(
            floor_windows_admission_issued_at(observed).expect("floor"),
            UnixMillis::new(12_000)
        );
        assert_eq!(expiry, UnixMillis::new(912_345));
        assert_eq!(
            floor_windows_admission_issued_at(UnixMillis::new(-1)),
            Err(WindowsBrokerAdmissionError::InvalidRequest)
        );
    }

    #[test]
    fn promotion_trust_bundle_commitment_is_ordered_and_exact() {
        let first = WindowsBrokerPromotionTrustKey::new("key-a", [1_u8; 32]).expect("key");
        let second = WindowsBrokerPromotionTrustKey::new("key-b", [2_u8; 32]).expect("key");
        let forward = WindowsBrokerPromotionTrustBundle::canonical_sha256(
            "windows-production-v1",
            &[first.clone(), second.clone()],
        );
        let reverse = WindowsBrokerPromotionTrustBundle::canonical_sha256(
            "windows-production-v1",
            &[second.clone(), first.clone()],
        );
        assert_eq!(forward, reverse);
        assert!(
            WindowsBrokerPromotionTrustBundle::new(
                "windows-production-v1",
                forward,
                vec![first.clone(), second],
            )
            .is_ok()
        );
        assert!(
            WindowsBrokerPromotionTrustBundle::new(
                "windows-production-v1",
                Sha256Digest::from_bytes([9_u8; 32]),
                vec![first],
            )
            .is_err()
        );
    }

    #[test]
    fn any_candidate_fixture_rejects_the_entire_promotion() {
        let mut dispositions = BTreeMap::new();
        for kind in [
            EvidenceKind::Provenance,
            EvidenceKind::Sbom,
            EvidenceKind::PatchReport,
            EvidenceKind::Revocations,
        ] {
            dispositions.insert(
                kind,
                EvidenceDisposition {
                    candidate_fixture: kind == EvidenceKind::Sbom,
                    revocation: None,
                },
            );
        }
        assert_eq!(
            require_production_evidence(&dispositions),
            Err(WindowsBrokerAdmissionError::EvidenceRejected)
        );
    }

    #[test]
    fn verified_promotion_rejects_signature_key_canonical_stale_and_candidate_failures() {
        let valid = promotion_fixture(PromotionFault::None, false);
        assert!(
            valid
                .evaluator()
                .evaluate(&valid.request, UnixMillis::new(TEST_NOW_MILLIS))
                .is_ok()
        );

        for fault in [
            PromotionFault::WrongSignature,
            PromotionFault::UnknownKey,
            PromotionFault::NonCanonicalPayload,
            PromotionFault::Stale,
            PromotionFault::CandidateEvidence,
        ] {
            let fixture = promotion_fixture(fault, false);
            assert!(matches!(
                fixture
                    .evaluator()
                    .evaluate(&fixture.request, UnixMillis::new(TEST_NOW_MILLIS)),
                Err(WindowsBrokerAdmissionError::EvidenceRejected)
            ));
        }
    }

    #[test]
    fn evaluator_rejects_action_capabilities_until_sealed_trees_are_supported() {
        let fixture = promotion_fixture(PromotionFault::None, true);
        assert!(matches!(
            fixture
                .evaluator()
                .evaluate(&fixture.request, UnixMillis::new(TEST_NOW_MILLIS)),
            Err(WindowsBrokerAdmissionError::EvidenceRejected)
        ));
    }

    #[test]
    fn promotion_high_water_rejects_rollback_and_same_serial_substitution() {
        let fixture = promotion_fixture(PromotionFault::None, false);
        let evaluation = fixture
            .evaluator()
            .evaluate(&fixture.request, UnixMillis::new(TEST_NOW_MILLIS))
            .expect("verified evaluation");
        let binding = evaluation.binding();
        let mut state = AdmissionState::default();
        FileWindowsBrokerAdmissionAuthority::enforce_and_advance_high_water(&mut state, binding)
            .expect("initial head");
        FileWindowsBrokerAdmissionAuthority::enforce_and_advance_high_water(&mut state, binding)
            .expect("exact replay");

        let lower_serial = binding_with_promotion(binding, 16, 7, 81);
        assert_eq!(
            FileWindowsBrokerAdmissionAuthority::enforce_and_advance_high_water(
                &mut state,
                &lower_serial,
            ),
            Err(WindowsBrokerAdmissionError::EvidenceRejected)
        );
        let lower_revocation = binding_with_promotion(binding, 18, 6, 82);
        assert_eq!(
            FileWindowsBrokerAdmissionAuthority::enforce_and_advance_high_water(
                &mut state,
                &lower_revocation,
            ),
            Err(WindowsBrokerAdmissionError::EvidenceRejected)
        );
        let substituted = binding_with_promotion(binding, 17, 7, 83);
        assert_eq!(
            FileWindowsBrokerAdmissionAuthority::enforce_and_advance_high_water(
                &mut state,
                &substituted,
            ),
            Err(WindowsBrokerAdmissionError::EvidenceRejected)
        );
        let advanced = binding_with_promotion(binding, 18, 8, 84);
        FileWindowsBrokerAdmissionAuthority::enforce_and_advance_high_water(&mut state, &advanced)
            .expect("monotonic advance");
    }

    #[test]
    fn concurrent_renewals_replay_the_exact_retained_envelope_until_ack() {
        let fixture = promotion_fixture(PromotionFault::None, false);
        let root = temp_root();
        let state_path = root.join("admission-state.json");
        let custody = Arc::new(
            FileWindowsBrokerCustody::open(root.join("custody"), Arc::new(FixtureProtector))
                .expect("custody"),
        );
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .expect("generate admission key")
            .as_ref()
            .to_vec();
        let authority = FileWindowsBrokerAdmissionAuthority::open(
            &state_path,
            Arc::clone(&custody),
            Arc::new(fixture.evaluator()),
            signing_key(&pkcs8),
        )
        .expect("authority");
        let receipt = authority
            .issue(&fixture.request, UnixMillis::new(TEST_NOW_MILLIS))
            .expect("issue");
        authority
            .complete(receipt.handle(), receipt.envelope_sha256())
            .expect("complete");
        drop(authority);

        let evaluator: Arc<dyn WindowsBrokerAdmissionEvaluator> =
            Arc::new(BarrierAdmissionEvaluator {
                inner: Arc::new(fixture.evaluator()),
                rendezvous: Arc::new(Barrier::new(2)),
            });
        let authority = FileWindowsBrokerAdmissionAuthority::open(
            &state_path,
            custody,
            evaluator,
            signing_key(&pkcs8),
        )
        .expect("restart authority");
        let now = UnixMillis::new(1_100_000);
        let (first, second) = std::thread::scope(|scope| {
            let first =
                scope.spawn(|| authority.renew(receipt.handle(), receipt.envelope_sha256(), now));
            let second =
                scope.spawn(|| authority.renew(receipt.handle(), receipt.envelope_sha256(), now));
            (
                first.join().expect("first renewal thread"),
                second.join().expect("second renewal thread"),
            )
        });
        let first = first.expect("first renewal");
        let second = second.expect("second renewal");
        assert_eq!(first, second);
        assert_eq!(
            first
                .envelope()
                .claims()
                .expect("renewal claims")
                .renewal_serial(),
            1
        );
        authority
            .acknowledge_renewal(receipt.handle(), first.envelope_sha256())
            .expect("ack retained renewal");
        authority
            .acknowledge_renewal(receipt.handle(), first.envelope_sha256())
            .expect("idempotent ACK");

        fs::remove_dir_all(root).expect("remove temp root");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn authority_recovers_issue_and_replays_renewal_until_exact_ack() {
        let fixture = promotion_fixture(PromotionFault::None, false);
        let root = temp_root();
        let state_path = root.join("admission-state.json");
        let custody_root = root.join("custody");
        let protector: Arc<dyn crate::WindowsBrokerCustodyProtector> = Arc::new(FixtureProtector);
        let custody = Arc::new(
            FileWindowsBrokerCustody::open(&custody_root, Arc::clone(&protector)).expect("custody"),
        );
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .expect("generate admission key")
            .as_ref()
            .to_vec();
        let evaluator: Arc<dyn WindowsBrokerAdmissionEvaluator> = Arc::new(fixture.evaluator());
        let authority = FileWindowsBrokerAdmissionAuthority::open(
            &state_path,
            Arc::clone(&custody),
            Arc::clone(&evaluator),
            signing_key(&pkcs8),
        )
        .expect("authority");

        let now = UnixMillis::new(TEST_NOW_MILLIS);
        let receipt = authority.issue(&fixture.request, now).expect("issue");
        let replay = authority
            .issue(&fixture.request, UnixMillis::new(TEST_NOW_MILLIS + 1))
            .expect("issue replay");
        assert_eq!(receipt, replay);
        let request_sha256 = fixture.request.request_sha256().expect("request digest");
        assert_eq!(
            authority
                .resume(
                    receipt.handle(),
                    request_sha256,
                    UnixMillis::new(TEST_NOW_MILLIS + 2),
                )
                .expect("resume"),
            receipt
        );
        drop(authority);

        let mut interrupted = read_admission_state(&state_path).expect("read state");
        interrupted
            .records
            .get_mut(&request_sha256.to_string())
            .expect("issued record")
            .phase = AdmissionRecordPhase::Issuing;
        persist_admission_state(&state_path, &interrupted).expect("persist interrupted issue");
        let authority = FileWindowsBrokerAdmissionAuthority::open(
            &state_path,
            Arc::clone(&custody),
            Arc::clone(&evaluator),
            signing_key(&pkcs8),
        )
        .expect("recover issuing authority");
        assert_eq!(
            authority
                .resume(
                    receipt.handle(),
                    request_sha256,
                    UnixMillis::new(TEST_NOW_MILLIS + 3),
                )
                .expect("resume recovered issue"),
            receipt
        );
        assert_eq!(
            authority.complete(receipt.handle(), Sha256Digest::from_bytes([99; 32])),
            Err(WindowsBrokerAdmissionError::InvalidReceipt)
        );
        authority
            .complete(receipt.handle(), receipt.envelope_sha256())
            .expect("complete");
        authority
            .complete(receipt.handle(), receipt.envelope_sha256())
            .expect("idempotent completion");
        drop(authority);
        drop(custody);

        let restarted_custody = Arc::new(
            FileWindowsBrokerCustody::open(&custody_root, protector).expect("restart custody"),
        );
        let restarted = FileWindowsBrokerAdmissionAuthority::open(
            &state_path,
            restarted_custody,
            evaluator,
            signing_key(&pkcs8),
        )
        .expect("restart authority");
        assert_eq!(
            restarted.issue(&fixture.request, UnixMillis::new(TEST_NOW_MILLIS + 4)),
            Err(WindowsBrokerAdmissionError::InvalidState)
        );

        let first_renewal = restarted
            .renew(
                receipt.handle(),
                receipt.envelope_sha256(),
                UnixMillis::new(1_100_000),
            )
            .expect("first renewal");
        let replayed_renewal = restarted
            .renew(
                receipt.handle(),
                receipt.envelope_sha256(),
                UnixMillis::new(1_100_001),
            )
            .expect("replayed renewal");
        assert_eq!(first_renewal, replayed_renewal);
        assert_eq!(
            first_renewal
                .envelope()
                .claims()
                .expect("renewal claims")
                .renewal_serial(),
            1
        );
        assert_eq!(
            restarted.acknowledge_renewal(receipt.handle(), Sha256Digest::from_bytes([98; 32]),),
            Err(WindowsBrokerAdmissionError::InvalidReceipt)
        );
        restarted
            .acknowledge_renewal(receipt.handle(), first_renewal.envelope_sha256())
            .expect("ack renewal");
        restarted
            .acknowledge_renewal(receipt.handle(), first_renewal.envelope_sha256())
            .expect("idempotent renewal ack");
        let second_renewal = restarted
            .renew(
                receipt.handle(),
                receipt.envelope_sha256(),
                UnixMillis::new(1_200_000),
            )
            .expect("second renewal");
        assert_eq!(
            second_renewal
                .envelope()
                .claims()
                .expect("renewal claims")
                .renewal_serial(),
            2
        );
        drop(restarted);
        fs::remove_dir_all(root).expect("remove temp root");
    }
}
