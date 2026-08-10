use std::fmt;

use automata_ci_blob::BlobDescriptor;
use automata_ci_core::{AttemptId, FencingToken, JobId, RunId, Sha256Digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::cache_model::CacheAuthority;

const INVALID_ARTIFACT_NAME_BYTES: &[u8] = b"\"\\/:<>|*?";
const MAXIMUM_DURABLE_NAME_BYTES: usize = 255;
const MAXIMUM_DURABLE_BLOCK_BYTES: u64 = 4_294_967_296;
const MAXIMUM_DURABLE_BLOCKS: usize = 100_000;
/// Maximum encoded size of one canonical immutable artifact manifest.
pub const MAXIMUM_ARTIFACT_MANIFEST_BYTES: u64 = 1024 * 1024;
/// Maximum duration of one renewable artifact-finalization claim.
pub const MAXIMUM_ARTIFACT_FINALIZATION_LEASE_SECONDS: u64 = 60 * 60;
// The default 100 GiB run ceiling holds 12,800 full 8 MiB blocks. This leaves
// bounded slack for small tail blocks without allowing zero-byte row growth to
// approach the 500-artifact by 2,048-block per-artifact product.
const DEFAULT_MAXIMUM_RUN_ARTIFACT_BLOCKS: usize = 16_384;

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeTokenClaims {
    authority: ExecutionAuthority,
    cache: CacheAuthority,
    issued_at_seconds: u64,
    expires_at_seconds: u64,
}

impl RuntimeTokenClaims {
    /// Creates claims after cryptographic and temporal verification.
    #[must_use]
    pub const fn new(
        authority: ExecutionAuthority,
        cache: CacheAuthority,
        issued_at_seconds: u64,
        expires_at_seconds: u64,
    ) -> Self {
        Self {
            authority,
            cache,
            issued_at_seconds,
            expires_at_seconds,
        }
    }

    /// Returns the exact execution authority.
    #[must_use]
    pub const fn authority(&self) -> ExecutionAuthority {
        self.authority
    }

    /// Returns authenticated repository/ref cache access controls.
    #[must_use]
    pub const fn cache(&self) -> &CacheAuthority {
        &self.cache
    }

    /// Returns the JWT issue time.
    #[must_use]
    pub const fn issued_at_seconds(&self) -> u64 {
        self.issued_at_seconds
    }

    /// Returns the exclusive expiry boundary.
    #[must_use]
    pub const fn expires_at_seconds(&self) -> u64 {
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
    /// Exact run, job, attempt, and lease fence authorized to create the artifact.
    pub authority: ExecutionAuthority,
    /// Unguessable identity used to bind subsequent signed upload operations.
    pub upload_id: UploadId,
    /// Validated, run-unique artifact name.
    pub name: ArtifactName,
    /// GitHub artifact protocol version requested by the client.
    pub version: i32,
    /// Validated media type recorded with the artifact.
    pub mime_type: String,
    /// Optional absolute Unix-seconds boundary after which the artifact is hidden.
    pub expires_at_seconds: Option<u64>,
    /// Trusted Unix-seconds time used for authorization and lifecycle decisions.
    pub observed_at_seconds: u64,
    /// Maximum number of artifact identities admitted for the workflow run.
    pub maximum_artifacts_per_run: usize,
}

/// Idempotent result of artifact creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateArtifactOutcome {
    /// Stable positive identity of the created or idempotently recovered artifact.
    pub artifact_id: ArtifactId,
    /// Upload identity bound to the artifact's Azure-compatible block operations.
    pub upload_id: UploadId,
}

/// Durable staged-block reservation committed before object publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveArtifactBlock {
    /// Upload identity whose pending artifact will own the block.
    pub upload_id: UploadId,
    /// Canonical block identifier and immutable object descriptor being reserved.
    pub block: ArtifactBlock,
    /// Trusted Unix-seconds time used to validate the active upload authority.
    pub observed_at_seconds: u64,
    /// Maximum distinct block reservations permitted for this artifact.
    pub maximum_blocks: usize,
    /// Maximum aggregate bytes reserved for this artifact.
    pub maximum_staged_bytes: u64,
    /// Maximum aggregate block reservations permitted for the workflow run.
    pub maximum_run_blocks: usize,
    /// Maximum aggregate artifact bytes reserved for the workflow run.
    pub maximum_run_staged_bytes: u64,
}

/// Idempotent outcome of reserving one immutable block identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactBlockReservation {
    /// The exact block is already ready for block-list commits.
    Ready,
    /// The exact block is reserved and its object upload must be completed.
    UploadRequired,
}

/// Marks one previously reserved block ready after its object is durable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteArtifactBlock {
    /// Upload identity that owns the durable reservation.
    pub upload_id: UploadId,
    /// Exact reserved block whose immutable object was published.
    pub block: ArtifactBlock,
    /// Trusted Unix-seconds time used to validate current upload authority.
    pub observed_at_seconds: u64,
}

/// Ordered Azure block-list commit applied under the stored attempt fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitArtifactBlocks {
    /// Upload identity whose staged blocks will be committed.
    pub upload_id: UploadId,
    /// Canonical block identifiers in the exact artifact replay order.
    pub block_ids: Vec<String>,
    /// Digest authenticating the ordered block-identifier list for idempotency.
    pub list_digest: Sha256Digest,
    /// Trusted Unix-seconds time used to validate current upload authority.
    pub observed_at_seconds: u64,
    /// Maximum number of blocks accepted in the ordered commit.
    pub maximum_blocks: usize,
    /// Maximum sum of committed block bytes accepted for the artifact.
    pub maximum_artifact_bytes: u64,
}

/// Ordered, durable block-list commit loaded for publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedArtifact {
    /// Stable positive artifact identity.
    pub artifact_id: ArtifactId,
    /// Upload identity through which the blocks were staged.
    pub upload_id: UploadId,
    /// Exact execution authority captured when the artifact was created.
    pub authority: ExecutionAuthority,
    /// Validated, run-unique artifact name.
    pub name: ArtifactName,
    /// Validated media type recorded at creation.
    pub mime_type: String,
    /// Verified immutable block descriptors in client-specified replay order.
    pub blocks: Vec<ArtifactBlock>,
    /// Checked sum of the ordered block sizes in bytes.
    pub size: u64,
}

/// One bounded request to acquire exclusive finalization work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeginArtifactFinalization {
    /// Exact run, job, attempt, and lease fence authorized to finalize.
    pub authority: ExecutionAuthority,
    /// Validated name identifying the pending artifact within the run.
    pub name: ArtifactName,
    /// Client-claimed total artifact size in bytes.
    pub claimed_size: u64,
    /// Optional client-claimed SHA-256 digest of the complete artifact.
    pub claimed_digest: Option<Sha256Digest>,
    /// Caller-observed Unix seconds retained only as bounded-skew request evidence.
    ///
    /// Repository-authoritative database time acquires or reconciles the lease.
    pub observed_at_seconds: u64,
    /// Bounded lifetime requested for the exclusive finalization claim.
    pub lease_seconds: u64,
}

/// Fencing capability for one durable artifact-finalization lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactFinalizationClaim {
    artifact_id: ArtifactId,
    authority: ExecutionAuthority,
    name: ArtifactName,
    generation: u64,
}

impl ArtifactFinalizationClaim {
    /// Creates a repository-authenticated finalization capability.
    #[must_use]
    pub fn new(
        artifact_id: ArtifactId,
        authority: ExecutionAuthority,
        name: ArtifactName,
        generation: u64,
    ) -> Self {
        Self {
            artifact_id,
            authority,
            name,
            generation,
        }
    }

    /// Returns the durable artifact identity.
    #[must_use]
    pub const fn artifact_id(&self) -> ArtifactId {
        self.artifact_id
    }

    /// Returns the attempt authority captured by the claim.
    #[must_use]
    pub const fn authority(&self) -> ExecutionAuthority {
        self.authority
    }

    /// Returns the immutable artifact name.
    #[must_use]
    pub fn name(&self) -> &ArtifactName {
        &self.name
    }

    /// Returns the monotonically increasing database fence.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Result of trying to acquire one finalization lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactFinalizationReservation {
    /// The exact request was already published.
    Published(FinalizeArtifactOutcome),
    /// This caller durably owns all verification or publication work.
    Claimed(ArtifactFinalizationClaim),
    /// An exact request is already owned until this exclusive timestamp.
    InProgress {
        /// Exclusive Unix-seconds boundary after which acquisition may be retried.
        retry_at_seconds: u64,
    },
}

/// Claim-bound request to load work only after the lease commit is visible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadArtifactFinalization {
    /// Repository-authenticated capability for the exact claim generation.
    pub claim: ArtifactFinalizationClaim,
    /// Caller-observed Unix seconds retained only as bounded-skew request evidence.
    ///
    /// Repository-authoritative database time decides claim liveness.
    pub observed_at_seconds: u64,
}

/// Verified manifest recovery state persisted before object publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedArtifactFinalization {
    /// Stable positive artifact identity associated with the persisted verification.
    pub artifact_id: ArtifactId,
    /// Verified SHA-256 digest of all blocks in manifest order.
    pub content_digest: Sha256Digest,
    /// Verified total byte size of all ordered blocks.
    pub size: u64,
    /// Immutable descriptor under which the canonical manifest must be published.
    pub manifest: BlobDescriptor,
    /// Exact canonical manifest bytes persisted for crash-safe publication retry.
    pub manifest_bytes: Vec<u8>,
}

/// Exclusive work loaded after a durable claim was acquired.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactFinalizationWork {
    /// Committed block objects still need bounded verification.
    Verify(CommittedArtifact),
    /// Verification is durable; only the exact manifest needs publication.
    Publish(VerifiedArtifactFinalization),
}

/// Extends one live claim without changing its fencing generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewArtifactFinalization {
    /// Repository-authenticated capability for the unchanged claim generation.
    pub claim: ArtifactFinalizationClaim,
    /// Caller-observed Unix seconds retained only as bounded-skew request evidence.
    ///
    /// Repository-authoritative database time decides claim liveness and renewal.
    pub observed_at_seconds: u64,
    /// Bounded duration by which the live claim is extended.
    pub lease_seconds: u64,
}

/// Persists verified content and its canonical manifest before object publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordArtifactVerification {
    /// Repository-authenticated capability that owns the verification work.
    pub claim: ArtifactFinalizationClaim,
    /// Verified SHA-256 digest of all blocks in manifest order.
    pub content_digest: Sha256Digest,
    /// Immutable descriptor derived from the exact canonical manifest bytes.
    pub manifest: BlobDescriptor,
    /// Bounded canonical manifest bytes retained for crash-safe publication.
    pub manifest_bytes: Vec<u8>,
    /// Caller-observed Unix seconds retained only as bounded-skew request evidence.
    ///
    /// Repository-authoritative database time decides claim liveness and persistence.
    pub observed_at_seconds: u64,
    /// Bounded lifetime assigned to the renewed publication claim.
    pub lease_seconds: u64,
}

/// Completes publication only for the still-live holder of the persisted manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteArtifactFinalization {
    /// Repository-authenticated capability that published the persisted manifest.
    pub claim: ArtifactFinalizationClaim,
    /// Caller-observed Unix seconds retained only as bounded-skew request evidence.
    ///
    /// Repository-authoritative database time decides claim liveness and publication.
    pub observed_at_seconds: u64,
}

/// Idempotent finalization result returned to the action client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizeArtifactOutcome {
    /// Stable positive identity of the published artifact.
    pub artifact_id: ArtifactId,
    /// Verified SHA-256 digest of the complete artifact content.
    pub content_digest: Sha256Digest,
    /// Verified total artifact size in bytes.
    pub size: u64,
}

/// Bounded, run-scoped query for published artifact metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListArtifacts {
    /// Exact active execution authority whose run bounds the query.
    pub authority: ExecutionAuthority,
    /// Optional validated exact-name filter.
    pub name: Option<ArtifactName>,
    /// Optional stable exact-identity filter.
    pub artifact_id: Option<ArtifactId>,
    /// Trusted Unix-seconds time used to exclude expired artifacts.
    pub observed_at_seconds: u64,
    /// Maximum number of metadata records that may be returned.
    pub maximum_results: usize,
}

/// Exact immutable artifact identity resolved by a signed download capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolveArtifactDownload {
    /// Stable positive identity carried by the signed download URL.
    pub artifact_id: ArtifactId,
    /// Immutable content digest carried by the signed download URL.
    pub content_digest: Sha256Digest,
    /// Trusted Unix-seconds time used to exclude expired artifacts.
    pub observed_at_seconds: u64,
}

/// Provider-neutral metadata for one published, non-expired artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedArtifactMetadata {
    /// Stable positive artifact identity.
    pub artifact_id: ArtifactId,
    /// Upload identity originally assigned to the artifact.
    pub upload_id: UploadId,
    /// Exact execution authority that created and published the artifact.
    pub authority: ExecutionAuthority,
    /// Validated, run-unique artifact name.
    pub name: ArtifactName,
    /// Validated media type recorded at creation.
    pub mime_type: String,
    /// Verified SHA-256 digest of the complete artifact content.
    pub content_digest: Sha256Digest,
    /// Verified total artifact size in bytes.
    pub size: u64,
    /// Descriptor of the canonical immutable manifest object.
    pub manifest: BlobDescriptor,
    /// Trusted Unix-seconds time at which the artifact was created.
    pub created_at_seconds: u64,
    /// Optional exclusive Unix-seconds visibility boundary.
    pub expires_at_seconds: Option<u64>,
}

/// Canonical immutable artifact manifest. Blocks are replayed in this order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifest {
    /// Current manifest schema version; currently exactly `1`.
    pub schema: u16,
    /// Positive durable artifact identity.
    pub artifact_id: i64,
    /// Canonical UUID text of the Azure-compatible upload identity.
    pub upload_id: String,
    /// Canonical UUID text of the workflow-run identity.
    pub run_id: String,
    /// Canonical UUID text of the workflow-job identity.
    pub job_id: String,
    /// Canonical UUID text of the execution-attempt identity.
    pub attempt_id: String,
    /// Lease fencing token captured when the artifact was created.
    pub fencing_token: u64,
    /// Validated artifact name.
    pub name: String,
    /// Validated artifact media type.
    pub mime_type: String,
    /// Verified sum of all ordered block sizes in bytes.
    pub size: u64,
    /// Lowercase hexadecimal SHA-256 digest of the complete artifact content.
    pub sha256: String,
    /// Immutable block descriptors in exact artifact replay order.
    pub blocks: Vec<ArtifactManifestBlock>,
}

/// One ordered descriptor in an immutable artifact manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifestBlock {
    /// Canonical Azure block identifier supplied by the upload client.
    pub block_id: String,
    /// Validated immutable-object key for this block.
    pub object_key: String,
    /// Exact block size in bytes.
    pub size: u64,
    /// Lowercase hexadecimal SHA-256 digest of the block bytes.
    pub sha256: String,
    /// Validated media type of the immutable block object.
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
    artifacts_per_run: usize,
    run_artifact_blocks: usize,
    run_artifact_bytes: u64,
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
            || maximum_manifest_bytes > MAXIMUM_ARTIFACT_MANIFEST_BYTES
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
            artifacts_per_run: 500,
            run_artifact_blocks: if maximum_blocks > DEFAULT_MAXIMUM_RUN_ARTIFACT_BLOCKS {
                maximum_blocks
            } else {
                DEFAULT_MAXIMUM_RUN_ARTIFACT_BLOCKS
            },
            run_artifact_bytes: if maximum_artifact_bytes > 100 * 1024 * 1024 * 1024 {
                maximum_artifact_bytes
            } else {
                100 * 1024 * 1024 * 1024
            },
        })
    }

    /// Applies aggregate artifact, block-reservation, and byte ceilings per run.
    ///
    /// # Errors
    ///
    /// Rejects zero or non-durable counts, byte values outside `BIGINT`, and a
    /// run ceiling smaller than the per-artifact ceiling.
    pub const fn with_run_admission(
        mut self,
        maximum_artifacts_per_run: usize,
        maximum_run_artifact_bytes: u64,
        maximum_run_artifact_blocks: usize,
    ) -> Result<Self, ResultsLimitsError> {
        if maximum_artifacts_per_run == 0
            || maximum_artifacts_per_run > MAXIMUM_DURABLE_BLOCKS
            || maximum_run_artifact_bytes < self.artifact_bytes
            || maximum_run_artifact_bytes > i64::MAX as u64
            || maximum_run_artifact_blocks < self.blocks
            || maximum_run_artifact_blocks > MAXIMUM_DURABLE_BLOCKS
        {
            return Err(ResultsLimitsError);
        }
        self.artifacts_per_run = maximum_artifacts_per_run;
        self.run_artifact_bytes = maximum_run_artifact_bytes;
        self.run_artifact_blocks = maximum_run_artifact_blocks;
        Ok(self)
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

    /// Maximum artifact identities admitted for one workflow run.
    #[must_use]
    pub const fn maximum_artifacts_per_run(self) -> usize {
        self.artifacts_per_run
    }

    /// Maximum aggregate staged-block reservations for one workflow run.
    #[must_use]
    pub const fn maximum_run_artifact_blocks(self) -> usize {
        self.run_artifact_blocks
    }

    /// Maximum aggregate reserved artifact bytes for one workflow run.
    #[must_use]
    pub const fn maximum_run_artifact_bytes(self) -> u64 {
        self.run_artifact_bytes
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
            artifacts_per_run: 500,
            run_artifact_blocks: DEFAULT_MAXIMUM_RUN_ARTIFACT_BLOCKS,
            run_artifact_bytes: 100 * 1024 * 1024 * 1024,
        }
    }
}

/// Invalid Results limit configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Results limits must be nonzero and internally consistent")]
pub struct ResultsLimitsError;
