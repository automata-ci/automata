use std::fmt;

use automata_blob::BlobDescriptor;
use automata_core::{AttemptId, FencingToken, JobId, RunId, Sha256Digest};
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

const INVALID_ARTIFACT_NAME_BYTES: &[u8] = b"\"\\/:<>|*?";
const MAXIMUM_DURABLE_NAME_BYTES: usize = 255;
const MAXIMUM_DURABLE_BLOCK_BYTES: u64 = 4_294_967_296;
const MAXIMUM_DURABLE_BLOCKS: usize = 100_000;
const MAXIMUM_DURABLE_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Stable database identity presented by the GitHub Results API.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArtifactId(i64);

impl ArtifactId {
    /// Creates a positive identity backed by `PostgreSQL` `BIGINT`.
    ///
    /// # Errors
    ///
    /// Rejects zero and negative values.
    pub const fn new(value: i64) -> Result<Self, ArtifactIdError> {
        if value <= 0 {
            return Err(ArtifactIdError);
        }
        Ok(Self(value))
    }

    /// Returns the durable integer value.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl fmt::Display for ArtifactId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Invalid database artifact identity.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("artifact identity must be positive")]
pub struct ArtifactIdError;

/// Unguessable identity used only by the signed Azure-compatible upload facade.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UploadId(Uuid);

impl UploadId {
    /// Creates an upload identity from an RFC 9562 UUID.
    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for UploadId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Cross-platform artifact name accepted by the official action client.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArtifactName(String);

impl ArtifactName {
    /// Validates a bounded GitHub-compatible artifact name.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized names, control bytes, path separators, and
    /// the platform-incompatible punctuation rejected by `upload-artifact`.
    pub fn new(value: impl Into<String>, maximum_bytes: usize) -> Result<Self, ArtifactNameError> {
        let value = value.into();
        if value.is_empty() || value.len() > maximum_bytes {
            return Err(ArtifactNameError::InvalidLength);
        }
        if value
            .bytes()
            .any(|byte| byte.is_ascii_control() || INVALID_ARTIFACT_NAME_BYTES.contains(&byte))
        {
            return Err(ArtifactNameError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Invalid artifact name.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ArtifactNameError {
    /// Name is empty or over the configured UTF-8 byte ceiling.
    #[error("artifact name length is invalid")]
    InvalidLength,
    /// Name is not portable across supported runner platforms.
    #[error("artifact name contains a platform-incompatible character")]
    InvalidCharacter,
}

/// Job-attempt authority carried by one short-lived runtime token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionAuthority {
    run_id: RunId,
    job_id: JobId,
    attempt_id: AttemptId,
    fencing_token: FencingToken,
}

impl ExecutionAuthority {
    /// Creates an exact run/job/attempt/fence binding.
    #[must_use]
    pub const fn new(
        run_id: RunId,
        job_id: JobId,
        attempt_id: AttemptId,
        fencing_token: FencingToken,
    ) -> Self {
        Self {
            run_id,
            job_id,
            attempt_id,
            fencing_token,
        }
    }

    /// Returns the workflow-run backend identity.
    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    /// Returns the workflow-job backend identity.
    #[must_use]
    pub const fn job_id(self) -> JobId {
        self.job_id
    }

    /// Returns the exact execution attempt.
    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the lease fencing token captured when the token was issued.
    #[must_use]
    pub const fn fencing_token(self) -> FencingToken {
        self.fencing_token
    }
}

/// Verified claims from a GitHub-compatible runtime JWT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeTokenClaims {
    authority: ExecutionAuthority,
    issued_at_seconds: u64,
    expires_at_seconds: u64,
}

impl RuntimeTokenClaims {
    /// Creates claims after cryptographic and temporal verification.
    #[must_use]
    pub const fn new(
        authority: ExecutionAuthority,
        issued_at_seconds: u64,
        expires_at_seconds: u64,
    ) -> Self {
        Self {
            authority,
            issued_at_seconds,
            expires_at_seconds,
        }
    }

    /// Returns the exact execution authority.
    #[must_use]
    pub const fn authority(self) -> ExecutionAuthority {
        self.authority
    }

    /// Returns the JWT issue time.
    #[must_use]
    pub const fn issued_at_seconds(self) -> u64 {
        self.issued_at_seconds
    }

    /// Returns the exclusive expiry boundary.
    #[must_use]
    pub const fn expires_at_seconds(self) -> u64 {
        self.expires_at_seconds
    }
}

/// One verified immutable staged block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactBlock {
    block_id: String,
    descriptor: BlobDescriptor,
}

impl ArtifactBlock {
    /// Creates a block after protocol validation.
    #[must_use]
    pub fn new(block_id: String, descriptor: BlobDescriptor) -> Self {
        Self {
            block_id,
            descriptor,
        }
    }

    /// Returns the canonical Azure block identifier.
    #[must_use]
    pub fn block_id(&self) -> &str {
        &self.block_id
    }

    /// Returns the immutable object identity.
    #[must_use]
    pub const fn descriptor(&self) -> &BlobDescriptor {
        &self.descriptor
    }
}

/// Atomic artifact-creation input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateArtifact {
    pub authority: ExecutionAuthority,
    pub upload_id: UploadId,
    pub name: ArtifactName,
    pub version: i32,
    pub mime_type: String,
    pub expires_at_seconds: Option<u64>,
    pub observed_at_seconds: u64,
}

/// Idempotent result of artifact creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateArtifactOutcome {
    pub artifact_id: ArtifactId,
    pub upload_id: UploadId,
}

/// Blob-first staged-block metadata committed under the current attempt fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageArtifactBlock {
    pub upload_id: UploadId,
    pub block: ArtifactBlock,
    pub observed_at_seconds: u64,
    pub maximum_blocks: usize,
    pub maximum_staged_bytes: u64,
}

/// Ordered Azure block-list commit applied under the stored attempt fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitArtifactBlocks {
    pub upload_id: UploadId,
    pub block_ids: Vec<String>,
    pub list_digest: Sha256Digest,
    pub observed_at_seconds: u64,
    pub maximum_blocks: usize,
    pub maximum_artifact_bytes: u64,
}

/// Ordered, durable block-list commit loaded for publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedArtifact {
    pub artifact_id: ArtifactId,
    pub upload_id: UploadId,
    pub authority: ExecutionAuthority,
    pub name: ArtifactName,
    pub mime_type: String,
    pub blocks: Vec<ArtifactBlock>,
    pub size: u64,
}

/// A publication already committed by an idempotent earlier request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedArtifact {
    pub artifact_id: ArtifactId,
    pub content_digest: Sha256Digest,
    pub size: u64,
    pub manifest: BlobDescriptor,
}

/// Repository state observed before finalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactPublicationState {
    /// A block list exists and its bytes still need verification/publication.
    Committed(CommittedArtifact),
    /// The exact immutable manifest was already published.
    Published(PublishedArtifact),
}

/// Exact publication metadata atomically applied after the manifest blob exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizeArtifact {
    pub authority: ExecutionAuthority,
    pub name: ArtifactName,
    pub content_digest: Sha256Digest,
    pub size: u64,
    pub manifest: BlobDescriptor,
    pub observed_at_seconds: u64,
}

/// Idempotent finalization result returned to the action client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizeArtifactOutcome {
    pub artifact_id: ArtifactId,
    pub content_digest: Sha256Digest,
    pub size: u64,
}

/// Canonical immutable artifact manifest. Blocks are replayed in this order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactManifest {
    pub schema: u16,
    pub artifact_id: i64,
    pub upload_id: String,
    pub run_id: String,
    pub job_id: String,
    pub attempt_id: String,
    pub fencing_token: u64,
    pub name: String,
    pub mime_type: String,
    pub size: u64,
    pub sha256: String,
    pub blocks: Vec<ArtifactManifestBlock>,
}

/// One ordered descriptor in an immutable artifact manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactManifestBlock {
    pub block_id: String,
    pub object_key: String,
    pub size: u64,
    pub sha256: String,
    pub media_type: String,
}

impl ArtifactManifest {
    /// Builds the current manifest schema from verified block metadata.
    #[must_use]
    pub fn from_committed(artifact: &CommittedArtifact, digest: Sha256Digest) -> Self {
        let authority = artifact.authority;
        Self {
            schema: 1,
            artifact_id: artifact.artifact_id.get(),
            upload_id: artifact.upload_id.to_string(),
            run_id: authority.run_id().to_string(),
            job_id: authority.job_id().to_string(),
            attempt_id: authority.attempt_id().to_string(),
            fencing_token: authority.fencing_token().get(),
            name: artifact.name.as_str().to_owned(),
            mime_type: artifact.mime_type.clone(),
            size: artifact.size,
            sha256: digest.to_string(),
            blocks: artifact
                .blocks
                .iter()
                .map(|block| ArtifactManifestBlock {
                    block_id: block.block_id().to_owned(),
                    object_key: block.descriptor().key().as_str().to_owned(),
                    size: block.descriptor().size(),
                    sha256: block.descriptor().digest().to_string(),
                    media_type: block.descriptor().media_type().as_str().to_owned(),
                })
                .collect(),
        }
    }
}

/// Resource limits independently configurable at the Results boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultsLimits {
    name_bytes: usize,
    block_bytes: u64,
    artifact_bytes: u64,
    blocks: usize,
    manifest_bytes: u64,
    retention_seconds: u64,
}

impl ResultsLimits {
    /// Creates a nonzero, internally consistent limit set.
    ///
    /// # Errors
    ///
    /// Rejects zero ceilings and an artifact ceiling smaller than one block.
    pub const fn new(
        maximum_name_bytes: usize,
        maximum_block_bytes: u64,
        maximum_artifact_bytes: u64,
        maximum_blocks: usize,
        maximum_manifest_bytes: u64,
        maximum_retention_seconds: u64,
    ) -> Result<Self, ResultsLimitsError> {
        if maximum_name_bytes == 0
            || maximum_block_bytes == 0
            || maximum_artifact_bytes == 0
            || maximum_blocks == 0
            || maximum_manifest_bytes == 0
            || maximum_retention_seconds == 0
            || maximum_artifact_bytes < maximum_block_bytes
            || maximum_name_bytes > MAXIMUM_DURABLE_NAME_BYTES
            || maximum_block_bytes > MAXIMUM_DURABLE_BLOCK_BYTES
            || maximum_artifact_bytes > i64::MAX as u64
            || maximum_blocks > MAXIMUM_DURABLE_BLOCKS
            || maximum_manifest_bytes > MAXIMUM_DURABLE_MANIFEST_BYTES
            || maximum_retention_seconds > i64::MAX as u64
        {
            return Err(ResultsLimitsError);
        }
        Ok(Self {
            name_bytes: maximum_name_bytes,
            block_bytes: maximum_block_bytes,
            artifact_bytes: maximum_artifact_bytes,
            blocks: maximum_blocks,
            manifest_bytes: maximum_manifest_bytes,
            retention_seconds: maximum_retention_seconds,
        })
    }

    /// Maximum artifact-name byte count.
    #[must_use]
    pub const fn maximum_name_bytes(self) -> usize {
        self.name_bytes
    }

    /// Maximum byte count of one staged Azure block.
    #[must_use]
    pub const fn maximum_block_bytes(self) -> u64 {
        self.block_bytes
    }

    /// Maximum logical byte count of one artifact.
    #[must_use]
    pub const fn maximum_artifact_bytes(self) -> u64 {
        self.artifact_bytes
    }

    /// Maximum ordered blocks in one artifact.
    #[must_use]
    pub const fn maximum_blocks(self) -> usize {
        self.blocks
    }

    /// Maximum canonical manifest byte count.
    #[must_use]
    pub const fn maximum_manifest_bytes(self) -> u64 {
        self.manifest_bytes
    }

    /// Maximum requested retention measured from creation.
    #[must_use]
    pub const fn maximum_retention_seconds(self) -> u64 {
        self.retention_seconds
    }
}

impl Default for ResultsLimits {
    fn default() -> Self {
        Self {
            name_bytes: 255,
            block_bytes: 8 * 1024 * 1024,
            artifact_bytes: 10 * 1024 * 1024 * 1024,
            blocks: 2_048,
            manifest_bytes: 1024 * 1024,
            retention_seconds: 400 * 24 * 60 * 60,
        }
    }
}

/// Invalid Results limit configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Results limits must be nonzero and internally consistent")]
pub struct ResultsLimitsError;
