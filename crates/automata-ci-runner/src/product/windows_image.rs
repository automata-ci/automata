use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    str::FromStr as _,
};

use automata_ci_core::{EnvironmentProfileId, Sha256Digest};
use automata_ci_execution::{ImmutableImage, TargetPath};
use base64::Engine as _;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use super::{
    config::ToolchainConfig,
    files::{read_configuration_file, validate_absolute_path},
};

const MAX_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_LOCK_BYTES: usize = 64 * 1024;
const MAX_EVIDENCE_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROMOTION_BYTES: usize = 256 * 1024;
const EVIDENCE_REFERENCE_MEDIA_TYPE: &str =
    "application/vnd.automata.windows-image-evidence-reference+json";
const MAX_REVOKED_IMAGES: usize = 4_096;

/// Result of the Windows image-evidence gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsImageAdmission {
    /// Configuration has not been loaded through the evidence verifier.
    Unverified,
    /// All candidate artifacts are internally consistent, but no external
    /// promotion authority has accepted them.
    Candidate,
    /// Candidate artifacts and an external Ed25519 promotion envelope verify.
    Promoted,
}

impl WindowsImageAdmission {
    /// Reports whether the configured image has verified external promotion.
    #[must_use]
    pub const fn is_promoted(self) -> bool {
        matches!(self, Self::Promoted)
    }
}

/// Verified image-evidence result retained for later enrollment admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsImageVerification {
    admission: WindowsImageAdmission,
    provenance_sha256: Option<Sha256Digest>,
    sbom_sha256: Option<Sha256Digest>,
    patch_report_sha256: Option<Sha256Digest>,
    revocations_sha256: Option<Sha256Digest>,
    promotion_payload_sha256: Option<Sha256Digest>,
    promotion_public_key_sha256: Option<Sha256Digest>,
    promotion_envelope_sha256: Option<Sha256Digest>,
}

impl WindowsImageVerification {
    /// Creates an unverified result used only before the evidence boundary runs.
    #[must_use]
    pub const fn unverified() -> Self {
        Self {
            admission: WindowsImageAdmission::Unverified,
            provenance_sha256: None,
            sbom_sha256: None,
            patch_report_sha256: None,
            revocations_sha256: None,
            promotion_payload_sha256: None,
            promotion_public_key_sha256: None,
            promotion_envelope_sha256: None,
        }
    }

    /// Creates a verified candidate which cannot authorize action execution.
    #[must_use]
    pub const fn candidate() -> Self {
        Self {
            admission: WindowsImageAdmission::Candidate,
            provenance_sha256: None,
            sbom_sha256: None,
            patch_report_sha256: None,
            revocations_sha256: None,
            promotion_payload_sha256: None,
            promotion_public_key_sha256: None,
            promotion_envelope_sha256: None,
        }
    }

    /// Creates a promoted result bound to the canonical signed payload digest.
    #[must_use]
    pub const fn promoted(
        promotion_payload_sha256: Sha256Digest,
        promotion_public_key_sha256: Sha256Digest,
        promotion_envelope_sha256: Sha256Digest,
    ) -> Self {
        Self {
            admission: WindowsImageAdmission::Promoted,
            provenance_sha256: None,
            sbom_sha256: None,
            patch_report_sha256: None,
            revocations_sha256: None,
            promotion_payload_sha256: Some(promotion_payload_sha256),
            promotion_public_key_sha256: Some(promotion_public_key_sha256),
            promotion_envelope_sha256: Some(promotion_envelope_sha256),
        }
    }

    /// Returns the coarse image admission state.
    #[must_use]
    pub const fn admission(self) -> WindowsImageAdmission {
        self.admission
    }

    pub(super) const fn with_evidence_digests(
        mut self,
        provenance_sha256: Sha256Digest,
        sbom_sha256: Sha256Digest,
        patch_report_sha256: Sha256Digest,
        revocations_sha256: Sha256Digest,
    ) -> Self {
        self.provenance_sha256 = Some(provenance_sha256);
        self.sbom_sha256 = Some(sbom_sha256);
        self.patch_report_sha256 = Some(patch_report_sha256);
        self.revocations_sha256 = Some(revocations_sha256);
        self
    }

    pub(super) const fn evidence_digests(self) -> Option<[Sha256Digest; 4]> {
        match (
            self.provenance_sha256,
            self.sbom_sha256,
            self.patch_report_sha256,
            self.revocations_sha256,
        ) {
            (Some(provenance), Some(sbom), Some(patch_report), Some(revocations)) => {
                Some([provenance, sbom, patch_report, revocations])
            }
            _ => None,
        }
    }

    /// Returns the digest of the canonical, verified promotion payload.
    #[must_use]
    pub const fn promotion_payload_sha256(self) -> Option<Sha256Digest> {
        self.promotion_payload_sha256
    }

    /// Returns the digest of the exact verified external promotion public key.
    #[must_use]
    pub const fn promotion_public_key_sha256(self) -> Option<Sha256Digest> {
        self.promotion_public_key_sha256
    }

    /// Returns the digest of the complete verified promotion envelope.
    #[must_use]
    pub const fn promotion_envelope_sha256(self) -> Option<Sha256Digest> {
        self.promotion_envelope_sha256
    }
}

/// Host-side paths and digests for one immutable Windows image contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsImageContractConfig {
    manifest_path: PathBuf,
    manifest_sha256: Sha256Digest,
    lock_path: PathBuf,
    lock_sha256: Sha256Digest,
    provenance_path: PathBuf,
    sbom_path: PathBuf,
    patch_report_path: PathBuf,
    revocations_path: PathBuf,
    promotion: Option<WindowsImagePromotionConfig>,
}

impl WindowsImageContractConfig {
    /// Returns the candidate image manifest path.
    #[must_use]
    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    /// Returns the exact candidate manifest digest.
    #[must_use]
    pub const fn manifest_sha256(&self) -> Sha256Digest {
        self.manifest_sha256
    }

    /// Returns the lock document path.
    #[must_use]
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    /// Returns the exact lock document digest.
    #[must_use]
    pub const fn lock_sha256(&self) -> Sha256Digest {
        self.lock_sha256
    }

    /// Returns the signed-provenance candidate path.
    #[must_use]
    pub fn provenance_path(&self) -> &Path {
        &self.provenance_path
    }

    /// Returns the SBOM candidate path.
    #[must_use]
    pub fn sbom_path(&self) -> &Path {
        &self.sbom_path
    }

    /// Returns the patch-assessment candidate path.
    #[must_use]
    pub fn patch_report_path(&self) -> &Path {
        &self.patch_report_path
    }

    /// Returns the revocation metadata path.
    #[must_use]
    pub fn revocations_path(&self) -> &Path {
        &self.revocations_path
    }

    /// Returns the optional external promotion authority configuration.
    #[must_use]
    pub const fn promotion(&self) -> Option<&WindowsImagePromotionConfig> {
        self.promotion.as_ref()
    }
}

/// An external promotion envelope and its pinned Ed25519 public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsImagePromotionConfig {
    envelope_path: PathBuf,
    key_id: String,
    public_key_base64: String,
}

impl WindowsImagePromotionConfig {
    /// Returns the detached promotion envelope path.
    #[must_use]
    pub fn envelope_path(&self) -> &Path {
        &self.envelope_path
    }

    /// Returns the exact external authority key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// Exact runner values which the image evidence must bind.
#[derive(Debug)]
pub struct WindowsImageVerificationRequest<'a> {
    pub(crate) contract: &'a WindowsImageContractConfig,
    pub(crate) profile_id: &'a EnvironmentProfileId,
    pub(crate) profile_manifest_sha256: Sha256Digest,
    pub(crate) image: &'a ImmutableImage,
    pub(crate) workspace: &'a TargetPath,
    pub(crate) guest_agent: &'a TargetPath,
    pub(crate) toolchain: &'a ToolchainConfig,
}

impl WindowsImageVerificationRequest<'_> {
    /// Returns the configured evidence locations and digest pins.
    #[must_use]
    pub const fn contract(&self) -> &WindowsImageContractConfig {
        self.contract
    }

    /// Returns the exact environment profile identity.
    #[must_use]
    pub const fn profile_id(&self) -> &EnvironmentProfileId {
        self.profile_id
    }

    /// Returns the scheduler-visible manifest digest.
    #[must_use]
    pub const fn profile_manifest_sha256(&self) -> Sha256Digest {
        self.profile_manifest_sha256
    }

    /// Returns the exact immutable output image.
    #[must_use]
    pub const fn image(&self) -> &ImmutableImage {
        self.image
    }

    /// Returns the exact in-container workspace root.
    #[must_use]
    pub const fn workspace(&self) -> &TargetPath {
        self.workspace
    }

    /// Returns the exact in-image guest agent.
    #[must_use]
    pub const fn guest_agent(&self) -> &TargetPath {
        self.guest_agent
    }

    /// Returns the exact configured in-image tools.
    #[must_use]
    pub const fn toolchain(&self) -> &ToolchainConfig {
        self.toolchain
    }
}

/// Pluggable image evidence boundary used before Windows capabilities exist.
pub trait WindowsImageEvidenceVerifier: Send + Sync {
    /// Verifies every candidate artifact and, when configured, the external
    /// promotion signature.
    ///
    /// # Errors
    ///
    /// Fails closed on missing, malformed, mismatched, revoked, or incorrectly
    /// signed material.
    fn verify(
        &self,
        request: &WindowsImageVerificationRequest<'_>,
    ) -> Result<WindowsImageVerification, WindowsImageVerificationError>;
}

/// Secure-file implementation of the Windows image evidence boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct FilesystemWindowsImageEvidenceVerifier;

/// Sanitized Windows image verification failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WindowsImageVerificationError {
    /// One or more bounded evidence files could not be securely loaded.
    #[error("Windows image evidence is unavailable")]
    Unavailable,
    /// An evidence document is malformed or violates the closed schema.
    #[error("Windows image evidence is invalid")]
    InvalidEvidence,
    /// A digest, profile, image, tool, or path binding differs.
    #[error("Windows image evidence does not match runner configuration")]
    Mismatch,
    /// The image is present in the accepted revocation metadata.
    #[error("Windows image is revoked")]
    Revoked,
    /// The configured external promotion signature is invalid.
    #[error("Windows image promotion signature is invalid")]
    InvalidPromotion,
}

impl WindowsImageEvidenceVerifier for FilesystemWindowsImageEvidenceVerifier {
    fn verify(
        &self,
        request: &WindowsImageVerificationRequest<'_>,
    ) -> Result<WindowsImageVerification, WindowsImageVerificationError> {
        let manifest_bytes = read_evidence(request.contract.manifest_path(), MAX_MANIFEST_BYTES)?;
        if digest(&manifest_bytes) != request.contract.manifest_sha256() {
            return Err(WindowsImageVerificationError::Mismatch);
        }
        let manifest: ImageManifest = parse(&manifest_bytes)?;
        validate_manifest(&manifest, request)?;

        let lock_bytes = read_evidence(request.contract.lock_path(), MAX_LOCK_BYTES)?;
        if digest(&lock_bytes) != request.contract.lock_sha256() {
            return Err(WindowsImageVerificationError::Mismatch);
        }
        let lock: ImageLock = parse(&lock_bytes)?;
        if lock.schema_version != 1
            || lock.profile_id != request.profile_id.as_str()
            || lock.image != request.image.reference()
            || lock.base_image != manifest.base_image
            || parse_digest(&lock.manifest_sha256)? != request.contract.manifest_sha256()
        {
            return Err(WindowsImageVerificationError::Mismatch);
        }

        let evidence = [
            (
                EvidenceKind::Provenance,
                request.contract.provenance_path(),
                &manifest.evidence.provenance,
            ),
            (
                EvidenceKind::Sbom,
                request.contract.sbom_path(),
                &manifest.evidence.sbom,
            ),
            (
                EvidenceKind::PatchReport,
                request.contract.patch_report_path(),
                &manifest.evidence.patch_report,
            ),
            (
                EvidenceKind::Revocations,
                request.contract.revocations_path(),
                &manifest.evidence.revocations,
            ),
        ];
        let mut evidence_digests = BTreeMap::new();
        let mut revocation_generation = None;
        for (expected_kind, path, reference) in evidence {
            let bytes = read_evidence(path, MAX_EVIDENCE_BYTES)?;
            let actual_digest = digest(&bytes);
            if parse_digest(&reference.sha256)? != actual_digest
                || reference.media_type != EVIDENCE_REFERENCE_MEDIA_TYPE
            {
                return Err(WindowsImageVerificationError::Mismatch);
            }
            let document: EvidenceReferenceDocument = parse(&bytes)?;
            if let Some(generation) = validate_evidence_reference_document(
                &document,
                expected_kind,
                request.profile_id.as_str(),
                request.image.reference(),
            )? {
                revocation_generation = Some(generation);
            }
            evidence_digests.insert(expected_kind, actual_digest);
        }

        let Some(promotion) = request.contract.promotion() else {
            return Ok(WindowsImageVerification::candidate().with_evidence_digests(
                evidence_digests[&EvidenceKind::Provenance],
                evidence_digests[&EvidenceKind::Sbom],
                evidence_digests[&EvidenceKind::PatchReport],
                evidence_digests[&EvidenceKind::Revocations],
            ));
        };
        let promotion_verification = verify_promotion(
            promotion,
            request,
            &manifest,
            &evidence_digests,
            revocation_generation.ok_or(WindowsImageVerificationError::InvalidEvidence)?,
        )?;
        Ok(WindowsImageVerification::promoted(
            promotion_verification.payload,
            promotion_verification.public_key,
            promotion_verification.envelope,
        )
        .with_evidence_digests(
            evidence_digests[&EvidenceKind::Provenance],
            evidence_digests[&EvidenceKind::Sbom],
            evidence_digests[&EvidenceKind::PatchReport],
            evidence_digests[&EvidenceKind::Revocations],
        ))
    }
}

fn validate_evidence_reference_document(
    document: &EvidenceReferenceDocument,
    expected_kind: EvidenceKind,
    profile_id: &str,
    image: &str,
) -> Result<Option<u64>, WindowsImageVerificationError> {
    if document.schema_version != 1
        || document.kind != expected_kind
        || document.candidate_fixture == Some(false)
        || document.profile_id != profile_id
        || document.image != image
        || parse_digest(&document.subject.sha256).is_err()
        || document.subject.media_type != expected_subject_media_type(expected_kind)
        || document.statement.is_empty()
        || document.statement.len() > 4_096
        || !document.statement.is_ascii()
    {
        return Err(WindowsImageVerificationError::Mismatch);
    }
    if expected_kind != EvidenceKind::Revocations {
        if document.generation.is_some() || !document.revoked_images.is_empty() {
            return Err(WindowsImageVerificationError::InvalidEvidence);
        }
        return Ok(None);
    }
    let generation = document
        .generation
        .filter(|generation| *generation > 0)
        .ok_or(WindowsImageVerificationError::InvalidEvidence)?;
    if document.revoked_images.len() > MAX_REVOKED_IMAGES
        || document
            .revoked_images
            .iter()
            .any(|revoked| ImmutableImage::new(revoked.clone()).is_err())
    {
        return Err(WindowsImageVerificationError::InvalidEvidence);
    }
    if document
        .revoked_images
        .iter()
        .any(|revoked| revoked == image)
    {
        return Err(WindowsImageVerificationError::Revoked);
    }
    Ok(Some(generation))
}

const fn expected_subject_media_type(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::Provenance => "application/vnd.in-toto+json",
        EvidenceKind::Sbom => "application/spdx+json",
        EvidenceKind::PatchReport => "application/vnd.automata.windows-patch-report+json",
        EvidenceKind::Revocations => "application/vnd.automata.image-revocations+json",
    }
}

fn validate_manifest(
    manifest: &ImageManifest,
    request: &WindowsImageVerificationRequest<'_>,
) -> Result<(), WindowsImageVerificationError> {
    if manifest.schema_version != 1
        || manifest.status != "candidate"
        || manifest.profile_id != request.profile_id.as_str()
        || manifest.image != request.image.reference()
        || request.profile_manifest_sha256 != request.contract.manifest_sha256()
        || manifest.operating_system != "windows-server-2025"
        || manifest.variant != "server-core"
        || manifest.architecture != "x86_64"
        || manifest.isolation != "hyperv-container"
        || !manifest.network_disabled
        || !manifest.unprivileged
        || !manifest.clean_workspace
        || !manifest
            .workspace
            .eq_ignore_ascii_case(request.workspace.as_str())
        || !manifest
            .guest_agent
            .eq_ignore_ascii_case(request.guest_agent.as_str())
        || ImmutableImage::new(manifest.base_image.clone()).is_err()
    {
        return Err(WindowsImageVerificationError::Mismatch);
    }

    let expected = expected_tools(request.toolchain)?;
    let mut actual = BTreeMap::new();
    for tool in &manifest.tools {
        if tool.version.is_empty()
            || tool.version.len() > 128
            || !tool.version.is_ascii()
            || parse_digest(&tool.sha256).is_err()
            || actual.insert(tool.kind, tool.path.as_str()).is_some()
        {
            return Err(WindowsImageVerificationError::InvalidEvidence);
        }
    }
    if actual.len() != expected.len()
        || expected.iter().any(|(kind, path)| {
            actual
                .get(kind)
                .is_none_or(|actual| !actual.eq_ignore_ascii_case(path.as_str()))
        })
    {
        return Err(WindowsImageVerificationError::Mismatch);
    }
    Ok(())
}

fn expected_tools(
    toolchain: &ToolchainConfig,
) -> Result<BTreeMap<ToolKind, &TargetPath>, WindowsImageVerificationError> {
    let mut tools = BTreeMap::new();
    for (kind, path) in [
        (ToolKind::Pwsh, toolchain.pwsh()),
        (ToolKind::Powershell, toolchain.powershell()),
        (ToolKind::Cmd, toolchain.cmd()),
        (ToolKind::Tar, toolchain.tar()),
        (ToolKind::Sha256, toolchain.sha256sum()),
    ] {
        tools.insert(kind, path.ok_or(WindowsImageVerificationError::Mismatch)?);
    }
    for (kind, path) in [
        (ToolKind::Node12, toolchain.node12()),
        (ToolKind::Node16, toolchain.node16()),
        (ToolKind::Node20, toolchain.node20()),
        (ToolKind::Node24, toolchain.node24()),
    ] {
        if let Some(path) = path {
            tools.insert(kind, path);
        }
    }
    Ok(tools)
}

fn verify_promotion(
    promotion: &WindowsImagePromotionConfig,
    request: &WindowsImageVerificationRequest<'_>,
    manifest: &ImageManifest,
    evidence: &BTreeMap<EvidenceKind, Sha256Digest>,
    revocation_generation: u64,
) -> Result<PromotionVerification, WindowsImageVerificationError> {
    let bytes = read_evidence(promotion.envelope_path(), MAX_PROMOTION_BYTES)?;
    let envelope: PromotionEnvelope = parse(&bytes)?;
    if envelope.schema_version != 1 || envelope.key_id != promotion.key_id() {
        return Err(WindowsImageVerificationError::InvalidPromotion);
    }
    let decoder = base64::engine::general_purpose::STANDARD;
    let payload_bytes = decoder
        .decode(envelope.payload_base64)
        .map_err(|_| WindowsImageVerificationError::InvalidPromotion)?;
    let signature = decoder
        .decode(envelope.signature_base64)
        .map_err(|_| WindowsImageVerificationError::InvalidPromotion)?;
    let public_key = decoder
        .decode(&promotion.public_key_base64)
        .map_err(|_| WindowsImageVerificationError::InvalidPromotion)?;
    UnparsedPublicKey::new(&ED25519, &public_key)
        .verify(&payload_bytes, &signature)
        .map_err(|_| WindowsImageVerificationError::InvalidPromotion)?;
    let payload: PromotionPayload = parse(&payload_bytes)?;
    if serde_json::to_vec(&payload).map_err(|_| WindowsImageVerificationError::InvalidPromotion)?
        != payload_bytes
        || payload.schema_version != 1
        || payload.decision != "promote"
        || !payload.provenance_accepted
        || !payload.sbom_accepted
        || !payload.patch_accepted
        || !payload.revocations_accepted
        || payload.profile_id != request.profile_id.as_str()
        || payload.image != request.image.reference()
        || payload.base_image != manifest.base_image
        || parse_digest(&payload.manifest_sha256)? != request.contract.manifest_sha256()
        || parse_digest(&payload.lock_sha256)? != request.contract.lock_sha256()
        || parse_digest(&payload.provenance_sha256)? != evidence[&EvidenceKind::Provenance]
        || parse_digest(&payload.sbom_sha256)? != evidence[&EvidenceKind::Sbom]
        || parse_digest(&payload.patch_report_sha256)? != evidence[&EvidenceKind::PatchReport]
        || parse_digest(&payload.revocations_sha256)? != evidence[&EvidenceKind::Revocations]
        || payload.revocation_generation != revocation_generation
    {
        return Err(WindowsImageVerificationError::InvalidPromotion);
    }
    Ok(PromotionVerification {
        payload: digest(&payload_bytes),
        public_key: digest(&public_key),
        envelope: digest(&bytes),
    })
}

struct PromotionVerification {
    payload: Sha256Digest,
    public_key: Sha256Digest,
    envelope: Sha256Digest,
}

fn read_evidence(path: &Path, maximum: usize) -> Result<Vec<u8>, WindowsImageVerificationError> {
    read_configuration_file(path, maximum).map_err(|_| WindowsImageVerificationError::Unavailable)
}

fn parse<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, WindowsImageVerificationError> {
    serde_json::from_slice(bytes).map_err(|_| WindowsImageVerificationError::InvalidEvidence)
}

fn parse_digest(value: &str) -> Result<Sha256Digest, WindowsImageVerificationError> {
    Sha256Digest::from_str(value).map_err(|_| WindowsImageVerificationError::InvalidEvidence)
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

#[derive(Deserialize)]
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

#[derive(Deserialize)]
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceReferences {
    provenance: EvidenceReference,
    sbom: EvidenceReference,
    patch_report: EvidenceReference,
    revocations: EvidenceReference,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceReference {
    sha256: String,
    media_type: String,
}

#[derive(Deserialize)]
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

#[derive(Deserialize)]
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
    revoked_images: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceSubject {
    sha256: String,
    media_type: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PromotionEnvelope {
    schema_version: u16,
    key_id: String,
    payload_base64: String,
    signature_base64: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct PromotionPayload {
    schema_version: u16,
    decision: String,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawWindowsImageContractConfig {
    manifest_path: PathBuf,
    manifest_sha256: String,
    lock_path: PathBuf,
    lock_sha256: String,
    provenance_path: PathBuf,
    sbom_path: PathBuf,
    patch_report_path: PathBuf,
    revocations_path: PathBuf,
    #[serde(default)]
    promotion: Option<RawWindowsImagePromotionConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWindowsImagePromotionConfig {
    envelope_path: PathBuf,
    key_id: String,
    public_key_base64: String,
}

impl RawWindowsImageContractConfig {
    pub(super) fn validate(
        self,
    ) -> Result<WindowsImageContractConfig, WindowsImageVerificationError> {
        let paths = [
            &self.manifest_path,
            &self.lock_path,
            &self.provenance_path,
            &self.sbom_path,
            &self.patch_report_path,
            &self.revocations_path,
        ];
        if paths
            .into_iter()
            .any(|path| validate_absolute_path(path).is_err())
        {
            return Err(WindowsImageVerificationError::InvalidEvidence);
        }
        let promotion = self
            .promotion
            .map(|promotion| {
                if validate_absolute_path(&promotion.envelope_path).is_err()
                    || promotion.key_id.is_empty()
                    || promotion.key_id.len() > 128
                    || !promotion.key_id.is_ascii()
                    || promotion.key_id.bytes().any(|byte| byte.is_ascii_control())
                    || promotion.public_key_base64.is_empty()
                    || promotion.public_key_base64.len() > 256
                {
                    return Err(WindowsImageVerificationError::InvalidEvidence);
                }
                Ok(WindowsImagePromotionConfig {
                    envelope_path: promotion.envelope_path,
                    key_id: promotion.key_id,
                    public_key_base64: promotion.public_key_base64,
                })
            })
            .transpose()?;
        Ok(WindowsImageContractConfig {
            manifest_path: self.manifest_path,
            manifest_sha256: parse_digest(&self.manifest_sha256)?,
            lock_path: self.lock_path,
            lock_sha256: parse_digest(&self.lock_sha256)?,
            provenance_path: self.provenance_path,
            sbom_path: self.sbom_path,
            patch_report_path: self.patch_report_path,
            revocations_path: self.revocations_path,
            promotion,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_reports_only_verified_external_promotion() {
        assert!(!WindowsImageAdmission::Unverified.is_promoted());
        assert!(!WindowsImageAdmission::Candidate.is_promoted());
        assert!(WindowsImageAdmission::Promoted.is_promoted());
    }

    #[test]
    fn promotion_payload_serialization_is_canonical_and_field_ordered() {
        let payload = PromotionPayload {
            schema_version: 1,
            decision: "promote".to_owned(),
            profile_id: "automata.dev/windows-2025-x64-hyperv-v1".to_owned(),
            base_image: format!("base@example@sha256:{}", "a".repeat(64)),
            image: format!("image@example@sha256:{}", "b".repeat(64)),
            manifest_sha256: "c".repeat(64),
            lock_sha256: "d".repeat(64),
            provenance_sha256: "e".repeat(64),
            sbom_sha256: "f".repeat(64),
            patch_report_sha256: "1".repeat(64),
            revocations_sha256: "2".repeat(64),
            revocation_generation: 1,
            provenance_accepted: true,
            sbom_accepted: true,
            patch_accepted: true,
            revocations_accepted: true,
        };
        let bytes = serde_json::to_vec(&payload).expect("serialize payload");
        let decoded: PromotionPayload = serde_json::from_slice(&bytes).expect("parse payload");
        assert_eq!(serde_json::to_vec(&decoded).expect("reserialize"), bytes);
    }

    #[test]
    fn production_evidence_reference_does_not_require_a_fixture_marker() {
        let image = format!("registry.example/image@sha256:{}", "1".repeat(64));
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "kind": "provenance",
            "profile_id": "automata.dev/windows-2025-x64-hyperv-v1",
            "image": image.clone(),
            "subject": {
                "sha256": "a".repeat(64),
                "media_type": "application/vnd.in-toto+json"
            },
            "statement": "Externally retained provenance reference."
        }))
        .expect("serialize reference");
        let reference: EvidenceReferenceDocument = parse(&bytes).expect("parse reference");

        assert_eq!(reference.candidate_fixture, None);
        assert_eq!(
            validate_evidence_reference_document(
                &reference,
                EvidenceKind::Provenance,
                "automata.dev/windows-2025-x64-hyperv-v1",
                &image,
            ),
            Ok(None)
        );
    }
}
