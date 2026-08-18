use std::{fmt, future::Future, str::FromStr as _, sync::Arc, time::Instant};

use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobPayload, BlobStoreErrorKind, ImmutableBlobStore, MediaType,
};
use automata_ci_core::Sha256Digest;
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    ArtifactBlock, ArtifactBlockReservation, ArtifactFinalizationClaim,
    ArtifactFinalizationReservation, ArtifactFinalizationWork, ArtifactManifest, ArtifactName,
    ArtifactRepositoryErrorKind, BeginArtifactFinalization, CommitArtifactBlocks,
    CompleteArtifactBlock, CompleteArtifactFinalization, CreateArtifact, CreateArtifactOutcome,
    ExecutionAuthority, FinalizeArtifactOutcome, ListArtifacts, LoadArtifactFinalization,
    NoopResultsObserver, PublishedArtifactMetadata, RecordArtifactVerification,
    RenewArtifactFinalization, ReserveArtifactBlock, ResolveArtifactDownload, ResultsLimits,
    ResultsObserver, ResultsOperation, ResultsOperationOutcome, UploadId,
    azure::{block_list_digest, validate_block_id},
    port::{ArtifactRepositoryPort, ClockPort, IdGeneratorPort},
};

const SUPPORTED_ARTIFACT_VERSION: i32 = 7;
const BLOCK_MEDIA_TYPE: &str = "application/octet-stream";
const FINALIZATION_LEASE_SECONDS: u64 = 5 * 60;
/// Immutable media type used by canonical artifact manifest objects.
pub const ARTIFACT_MANIFEST_MEDIA_TYPE: &str = "application/vnd.automata.artifact-manifest+json";

/// One verified immutable artifact prepared for bounded block-by-block streaming.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedArtifactDownload {
    pub(crate) metadata: PublishedArtifactMetadata,
    pub(crate) blocks: Vec<BlobDescriptor>,
}

/// Stable service failure class mapped independently by provider HTTP adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultsServiceErrorKind {
    /// Request values violate a protocol or configured bound.
    InvalidArgument,
    /// Current durable attempt fencing does not authorize the operation.
    PermissionDenied,
    /// Artifact or one of its staged blocks does not exist.
    NotFound,
    /// Immutable create, block, commit, or publication metadata conflicts.
    Conflict,
    /// The lifecycle transition requires a missing or different prior state.
    FailedPrecondition,
    /// A byte/count resource ceiling would be exceeded.
    ResourceExhausted,
    /// A mandatory provider is temporarily unavailable.
    Unavailable,
    /// Durable or object metadata violates a trusted invariant.
    Internal,
}

/// Sanitized Results application failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Results service operation failed: {kind:?}")]
pub struct ResultsServiceError {
    kind: ResultsServiceErrorKind,
}

impl ResultsServiceError {
    /// Creates a sanitized failure class.
    #[must_use]
    pub const fn new(kind: ResultsServiceErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable class.
    #[must_use]
    pub const fn kind(self) -> ResultsServiceErrorKind {
        self.kind
    }
}

/// Provider-neutral artifact use cases behind the GitHub HTTP compatibility adapter.
pub struct ArtifactService {
    repository: ArtifactRepositoryPort,
    objects: Arc<dyn ImmutableBlobStore>,
    clock: ClockPort,
    ids: IdGeneratorPort,
    limits: ResultsLimits,
    observer: Arc<dyn ResultsObserver>,
}

impl ArtifactService {
    /// Composes durable metadata, immutable object storage, time, and identity ports.
    #[must_use]
    pub fn new(
        repository: ArtifactRepositoryPort,
        objects: Arc<dyn ImmutableBlobStore>,
        clock: ClockPort,
        ids: IdGeneratorPort,
        limits: ResultsLimits,
    ) -> Self {
        Self {
            repository,
            objects,
            clock,
            ids,
            limits,
            observer: Arc::new(NoopResultsObserver),
        }
    }

    /// Installs an infallible identifier-free application observer.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn ResultsObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// Returns the configured resource policy.
    #[must_use]
    pub const fn limits(&self) -> ResultsLimits {
        self.limits
    }

    /// Creates or idempotently recovers one pending v7 artifact.
    ///
    /// # Errors
    ///
    /// Returns a sanitized validation, fence, conflict, or provider failure.
    pub async fn create(
        &self,
        authority: ExecutionAuthority,
        name: String,
        version: i32,
        mime_type: String,
        expires_at_seconds: Option<u64>,
    ) -> Result<CreateArtifactOutcome, ResultsServiceError> {
        self.observe_operation(
            ResultsOperation::Create,
            self.create_inner(authority, name, version, mime_type, expires_at_seconds),
        )
        .await
    }

    async fn create_inner(
        &self,
        authority: ExecutionAuthority,
        name: String,
        version: i32,
        mime_type: String,
        expires_at_seconds: Option<u64>,
    ) -> Result<CreateArtifactOutcome, ResultsServiceError> {
        if version != SUPPORTED_ARTIFACT_VERSION {
            return Err(ResultsServiceError::new(
                ResultsServiceErrorKind::InvalidArgument,
            ));
        }
        let name = ArtifactName::new(name, self.limits.maximum_name_bytes())
            .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::InvalidArgument))?;
        let mime_type = MediaType::new(mime_type)
            .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::InvalidArgument))?
            .as_str()
            .to_owned();
        let observed_at_seconds = self.clock.now_seconds();
        if let Some(expires_at) = expires_at_seconds {
            let latest = observed_at_seconds
                .checked_add(self.limits.maximum_retention_seconds())
                .ok_or_else(|| {
                    ResultsServiceError::new(ResultsServiceErrorKind::InvalidArgument)
                })?;
            if expires_at <= observed_at_seconds || expires_at > latest {
                return Err(ResultsServiceError::new(
                    ResultsServiceErrorKind::InvalidArgument,
                ));
            }
        }
        self.repository
            .create(CreateArtifact {
                authority,
                upload_id: self.ids.next_upload_id(),
                name,
                version,
                mime_type,
                expires_at_seconds,
                observed_at_seconds,
                maximum_artifacts_per_run: self.limits.maximum_artifacts_per_run(),
            })
            .await
            .map_err(map_repository_error)
    }

    /// Reserves, publishes, and completes one immutable staged block.
    ///
    /// # Errors
    ///
    /// Rejects excessive content or stale upload authority and maps provider failures.
    pub async fn stage_block(
        &self,
        upload_id: UploadId,
        block_id: String,
        bytes: Bytes,
    ) -> Result<(), ResultsServiceError> {
        self.observe_operation(
            ResultsOperation::StageBlock,
            self.stage_block_inner(upload_id, block_id, bytes),
        )
        .await
    }

    async fn stage_block_inner(
        &self,
        upload_id: UploadId,
        block_id: String,
        bytes: Bytes,
    ) -> Result<(), ResultsServiceError> {
        let size = u64::try_from(bytes.len())
            .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::ResourceExhausted))?;
        if size > self.limits.maximum_block_bytes() {
            return Err(ResultsServiceError::new(
                ResultsServiceErrorKind::ResourceExhausted,
            ));
        }
        let media_type = MediaType::new(BLOCK_MEDIA_TYPE)
            .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::Internal))?;
        let digest = Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
        let key = BlobKey::new(format!("artifact-staging/v1/{upload_id}/{digest}"))
            .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::Internal))?;
        let payload = BlobPayload::from_bytes(key, media_type, bytes);
        let descriptor = payload.descriptor().clone();
        let block = ArtifactBlock::new(block_id, descriptor.clone());
        let reservation = self
            .repository
            .reserve_block(ReserveArtifactBlock {
                upload_id,
                block: block.clone(),
                observed_at_seconds: self.clock.now_seconds(),
                maximum_blocks: self.limits.maximum_blocks(),
                maximum_staged_bytes: self.limits.maximum_artifact_bytes(),
                maximum_run_blocks: self.limits.maximum_run_artifact_blocks(),
                maximum_run_staged_bytes: self.limits.maximum_run_artifact_bytes(),
            })
            .await
            .map_err(map_repository_error)?;
        if reservation == ArtifactBlockReservation::Ready {
            return Ok(());
        }
        self.objects
            .put_if_absent(payload)
            .await
            .map_err(map_blob_error)?;
        self.repository
            .complete_block(CompleteArtifactBlock {
                upload_id,
                block,
                observed_at_seconds: self.clock.now_seconds(),
            })
            .await
            .map_err(map_repository_error)
    }

    /// Atomically commits one ordered list of already staged blocks.
    ///
    /// # Errors
    ///
    /// Rejects excessive lists, absent blocks, stale fencing, and contradictory retries.
    pub async fn commit_blocks(
        &self,
        upload_id: UploadId,
        block_ids: Vec<String>,
    ) -> Result<(), ResultsServiceError> {
        self.observe_operation(
            ResultsOperation::Commit,
            self.commit_blocks_inner(upload_id, block_ids),
        )
        .await
    }

    async fn commit_blocks_inner(
        &self,
        upload_id: UploadId,
        block_ids: Vec<String>,
    ) -> Result<(), ResultsServiceError> {
        if block_ids.len() > self.limits.maximum_blocks() {
            return Err(ResultsServiceError::new(
                ResultsServiceErrorKind::ResourceExhausted,
            ));
        }
        let list_digest = block_list_digest(&block_ids);
        self.repository
            .commit_blocks(CommitArtifactBlocks {
                upload_id,
                block_ids,
                list_digest,
                observed_at_seconds: self.clock.now_seconds(),
                maximum_blocks: self.limits.maximum_blocks(),
                maximum_artifact_bytes: self.limits.maximum_artifact_bytes(),
            })
            .await
            .map(|_| ())
            .map_err(map_repository_error)
    }

    /// Verifies every committed block and publishes a canonical immutable manifest.
    ///
    /// # Errors
    ///
    /// Rejects request size/hash mismatches and maps stale fencing or provider failures.
    pub async fn finalize(
        &self,
        authority: ExecutionAuthority,
        name: String,
        claimed_size: u64,
        claimed_digest: Option<Sha256Digest>,
    ) -> Result<FinalizeArtifactOutcome, ResultsServiceError> {
        self.observe_operation(
            ResultsOperation::Finalize,
            self.finalize_inner(authority, name, claimed_size, claimed_digest),
        )
        .await
    }

    async fn finalize_inner(
        &self,
        authority: ExecutionAuthority,
        name: String,
        claimed_size: u64,
        claimed_digest: Option<Sha256Digest>,
    ) -> Result<FinalizeArtifactOutcome, ResultsServiceError> {
        if claimed_size > self.limits.maximum_artifact_bytes() {
            return Err(ResultsServiceError::new(
                ResultsServiceErrorKind::ResourceExhausted,
            ));
        }
        let name = ArtifactName::new(name, self.limits.maximum_name_bytes())
            .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::InvalidArgument))?;
        let claim = match self
            .repository
            .begin_finalization(BeginArtifactFinalization {
                authority,
                name,
                claimed_size,
                claimed_digest,
                observed_at_seconds: self.clock.now_seconds(),
                lease_seconds: FINALIZATION_LEASE_SECONDS,
            })
            .await
            .map_err(map_repository_error)?
        {
            ArtifactFinalizationReservation::Published(outcome) => return Ok(outcome),
            ArtifactFinalizationReservation::Claimed(claim) => claim,
            ArtifactFinalizationReservation::InProgress { .. } => {
                return Err(ResultsServiceError::new(
                    ResultsServiceErrorKind::Unavailable,
                ));
            }
        };
        let work = self
            .repository
            .load_finalization(LoadArtifactFinalization {
                claim: claim.clone(),
                observed_at_seconds: self.clock.now_seconds(),
            })
            .await
            .map_err(map_repository_error)?;
        match work {
            ArtifactFinalizationWork::Verify(committed) => {
                if committed.artifact_id != claim.artifact_id()
                    || committed.authority != claim.authority()
                    || committed.name != *claim.name()
                {
                    return Err(ResultsServiceError::new(ResultsServiceErrorKind::Internal));
                }
                let content_digest = self
                    .verify_committed_content(&claim, &committed, claimed_size, claimed_digest)
                    .await?;
                let payload = self.build_manifest_payload(&committed, content_digest)?;
                self.repository
                    .record_verification(RecordArtifactVerification {
                        claim: claim.clone(),
                        content_digest,
                        manifest: payload.descriptor().clone(),
                        manifest_bytes: payload.bytes().to_vec(),
                        observed_at_seconds: self.clock.now_seconds(),
                        lease_seconds: FINALIZATION_LEASE_SECONDS,
                    })
                    .await
                    .map_err(map_repository_error)?;
                self.publish_verified_manifest(&claim, payload).await
            }
            ArtifactFinalizationWork::Publish(verified) => {
                if verified.artifact_id != claim.artifact_id()
                    || verified.size != claimed_size
                    || claimed_digest.is_some_and(|digest| digest != verified.content_digest)
                {
                    return Err(ResultsServiceError::new(ResultsServiceErrorKind::Internal));
                }
                let expected_key = format!(
                    "artifacts/v1/{}/{}/manifest.json",
                    verified.content_digest, verified.artifact_id
                );
                if verified.manifest.key().as_str() != expected_key
                    || verified.manifest.media_type().as_str() != ARTIFACT_MANIFEST_MEDIA_TYPE
                {
                    return Err(ResultsServiceError::new(ResultsServiceErrorKind::Internal));
                }
                let payload =
                    BlobPayload::verify(verified.manifest, Bytes::from(verified.manifest_bytes))
                        .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::Internal))?;
                self.publish_verified_manifest(&claim, payload).await
            }
        }
    }

    /// Lists published, non-expired artifacts from the token's workflow run.
    ///
    /// # Errors
    ///
    /// Rejects malformed filters and maps stale fencing or provider failures.
    pub async fn list(
        &self,
        authority: ExecutionAuthority,
        name: Option<String>,
        artifact_id: Option<crate::ArtifactId>,
    ) -> Result<Vec<PublishedArtifactMetadata>, ResultsServiceError> {
        self.observe_operation(
            ResultsOperation::List,
            self.list_inner(authority, name, artifact_id),
        )
        .await
    }

    async fn list_inner(
        &self,
        authority: ExecutionAuthority,
        name: Option<String>,
        artifact_id: Option<crate::ArtifactId>,
    ) -> Result<Vec<PublishedArtifactMetadata>, ResultsServiceError> {
        let name = name
            .map(|value| ArtifactName::new(value, self.limits.maximum_name_bytes()))
            .transpose()
            .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::InvalidArgument))?;
        self.repository
            .list(ListArtifacts {
                authority,
                name,
                artifact_id,
                observed_at_seconds: self.clock.now_seconds(),
                maximum_results: self.limits.maximum_artifacts_per_run(),
            })
            .await
            .map_err(map_repository_error)
    }

    /// Resolves and verifies the canonical manifest behind one signed download.
    ///
    /// The complete artifact is never buffered: only the bounded manifest is
    /// loaded here, and each immutable block is fetched when the HTTP body is polled.
    ///
    /// # Errors
    ///
    /// Returns not found for an absent or expired identity, and internal for a
    /// manifest or object descriptor that contradicts durable publication metadata.
    pub(crate) async fn prepare_download(
        &self,
        artifact_id: crate::ArtifactId,
        content_digest: Sha256Digest,
    ) -> Result<PreparedArtifactDownload, ResultsServiceError> {
        self.observe_operation(
            ResultsOperation::PrepareDownload,
            self.prepare_download_inner(artifact_id, content_digest),
        )
        .await
    }

    async fn prepare_download_inner(
        &self,
        artifact_id: crate::ArtifactId,
        content_digest: Sha256Digest,
    ) -> Result<PreparedArtifactDownload, ResultsServiceError> {
        let metadata = self
            .repository
            .resolve_download(ResolveArtifactDownload {
                artifact_id,
                content_digest,
                observed_at_seconds: self.clock.now_seconds(),
            })
            .await
            .map_err(map_repository_error)?;
        if metadata.manifest.media_type().as_str() != ARTIFACT_MANIFEST_MEDIA_TYPE {
            return Err(ResultsServiceError::new(ResultsServiceErrorKind::Internal));
        }
        let manifest = self
            .objects
            .get_verified(&metadata.manifest, self.limits.maximum_manifest_bytes())
            .await
            .map_err(map_blob_error)?;
        let manifest: ArtifactManifest = serde_json::from_slice(manifest.bytes())
            .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::Internal))?;
        let blocks = validate_download_manifest(&metadata, &manifest, self.limits)?;
        Ok(PreparedArtifactDownload { metadata, blocks })
    }

    pub(crate) async fn read_download_block(
        &self,
        descriptor: &BlobDescriptor,
    ) -> Result<Bytes, ResultsServiceError> {
        self.observe_operation(
            ResultsOperation::ReadBlock,
            self.read_download_block_inner(descriptor),
        )
        .await
    }

    async fn read_download_block_inner(
        &self,
        descriptor: &BlobDescriptor,
    ) -> Result<Bytes, ResultsServiceError> {
        self.objects
            .get_verified(descriptor, self.limits.maximum_block_bytes())
            .await
            .map(automata_ci_blob::VerifiedBlob::into_bytes)
            .map_err(map_blob_error)
    }

    async fn observe_operation<T>(
        &self,
        operation: ResultsOperation,
        future: impl Future<Output = Result<T, ResultsServiceError>>,
    ) -> Result<T, ResultsServiceError> {
        let observation = ResultsOperationObservation::new(Arc::clone(&self.observer), operation);
        let result = future.await;
        let outcome = match &result {
            Ok(_) => ResultsOperationOutcome::Success,
            Err(error) => results_operation_error_outcome(*error),
        };
        observation.finish(outcome);
        result
    }

    async fn verify_committed_content(
        &self,
        claim: &ArtifactFinalizationClaim,
        committed: &crate::CommittedArtifact,
        claimed_size: u64,
        claimed_digest: Option<Sha256Digest>,
    ) -> Result<Sha256Digest, ResultsServiceError> {
        if committed.size != claimed_size {
            return Err(ResultsServiceError::new(
                ResultsServiceErrorKind::InvalidArgument,
            ));
        }
        let mut hasher = Sha256::new();
        let mut actual_size = 0_u64;
        for block in &committed.blocks {
            self.renew_finalization(claim).await?;
            let verified = self
                .objects
                .get_verified(block.descriptor(), self.limits.maximum_block_bytes())
                .await
                .map_err(map_blob_error)?;
            actual_size = actual_size
                .checked_add(block.descriptor().size())
                .ok_or_else(|| {
                    ResultsServiceError::new(ResultsServiceErrorKind::ResourceExhausted)
                })?;
            if actual_size > self.limits.maximum_artifact_bytes() {
                return Err(ResultsServiceError::new(
                    ResultsServiceErrorKind::ResourceExhausted,
                ));
            }
            hasher.update(verified.bytes());
        }
        if actual_size != claimed_size {
            return Err(ResultsServiceError::new(ResultsServiceErrorKind::Internal));
        }
        let content_digest = Sha256Digest::from_bytes(hasher.finalize().into());
        if claimed_digest.is_some_and(|digest| digest != content_digest) {
            return Err(ResultsServiceError::new(
                ResultsServiceErrorKind::InvalidArgument,
            ));
        }
        self.renew_finalization(claim).await?;
        Ok(content_digest)
    }

    fn build_manifest_payload(
        &self,
        committed: &crate::CommittedArtifact,
        content_digest: Sha256Digest,
    ) -> Result<BlobPayload, ResultsServiceError> {
        let manifest = ArtifactManifest::from_committed(committed, content_digest);
        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::Internal))?;
        if u64::try_from(manifest_bytes.len()).unwrap_or(u64::MAX)
            > self.limits.maximum_manifest_bytes()
        {
            return Err(ResultsServiceError::new(
                ResultsServiceErrorKind::ResourceExhausted,
            ));
        }
        let key = BlobKey::new(format!(
            "artifacts/v1/{content_digest}/{}/manifest.json",
            committed.artifact_id
        ))
        .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::Internal))?;
        let media_type = MediaType::new(ARTIFACT_MANIFEST_MEDIA_TYPE)
            .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::Internal))?;
        Ok(BlobPayload::from_bytes(
            key,
            media_type,
            Bytes::from(manifest_bytes),
        ))
    }

    async fn publish_verified_manifest(
        &self,
        claim: &ArtifactFinalizationClaim,
        payload: BlobPayload,
    ) -> Result<FinalizeArtifactOutcome, ResultsServiceError> {
        self.renew_finalization(claim).await?;
        self.objects
            .put_if_absent(payload)
            .await
            .map_err(map_blob_error)?;
        self.repository
            .complete_finalization(CompleteArtifactFinalization {
                claim: claim.clone(),
                observed_at_seconds: self.clock.now_seconds(),
            })
            .await
            .map_err(map_repository_error)
    }

    async fn renew_finalization(
        &self,
        claim: &ArtifactFinalizationClaim,
    ) -> Result<(), ResultsServiceError> {
        self.repository
            .renew_finalization(RenewArtifactFinalization {
                claim: claim.clone(),
                observed_at_seconds: self.clock.now_seconds(),
                lease_seconds: FINALIZATION_LEASE_SECONDS,
            })
            .await
            .map_err(map_repository_error)
    }
}

struct ResultsOperationObservation {
    observer: Arc<dyn ResultsObserver>,
    operation: ResultsOperation,
    started: Instant,
    completed: bool,
}

impl ResultsOperationObservation {
    fn new(observer: Arc<dyn ResultsObserver>, operation: ResultsOperation) -> Self {
        Self {
            observer,
            operation,
            started: Instant::now(),
            completed: false,
        }
    }

    fn finish(mut self, outcome: ResultsOperationOutcome) {
        self.observer
            .observe_operation(self.operation, outcome, self.started.elapsed());
        self.completed = true;
    }
}

impl Drop for ResultsOperationObservation {
    fn drop(&mut self) {
        if !self.completed {
            self.observer.observe_operation(
                self.operation,
                ResultsOperationOutcome::Cancelled,
                self.started.elapsed(),
            );
        }
    }
}

fn validate_download_manifest(
    metadata: &PublishedArtifactMetadata,
    manifest: &ArtifactManifest,
    limits: ResultsLimits,
) -> Result<Vec<BlobDescriptor>, ResultsServiceError> {
    let authority = metadata.authority;
    if manifest.validate_schema().is_err()
        || manifest.artifact_id != metadata.artifact_id.get()
        || manifest.upload_id != metadata.upload_id.to_string()
        || manifest.run_id != authority.run_id().to_string()
        || manifest.job_id != authority.job_id().to_string()
        || manifest.attempt_id != authority.attempt_id().to_string()
        || manifest.fencing_token != authority.fencing_token().get()
        || manifest.name != metadata.name.as_str()
        || manifest.mime_type != metadata.mime_type
        || manifest.size != metadata.size
        || manifest.sha256 != metadata.content_digest.to_string()
        || manifest.blocks.len() > limits.maximum_blocks()
    {
        return Err(ResultsServiceError::new(ResultsServiceErrorKind::Internal));
    }

    let mut size = 0_u64;
    let mut descriptors = Vec::with_capacity(manifest.blocks.len());
    for block in &manifest.blocks {
        validate_block_id(&block.block_id)
            .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::Internal))?;
        if block.size > limits.maximum_block_bytes() || block.media_type != BLOCK_MEDIA_TYPE {
            return Err(ResultsServiceError::new(ResultsServiceErrorKind::Internal));
        }
        let digest = Sha256Digest::from_str(&block.sha256)
            .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::Internal))?;
        let expected_key = format!("artifact-staging/v1/{}/{digest}", metadata.upload_id);
        if block.object_key != expected_key {
            return Err(ResultsServiceError::new(ResultsServiceErrorKind::Internal));
        }
        let key = BlobKey::new(block.object_key.clone())
            .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::Internal))?;
        let media_type = MediaType::new(block.media_type.clone())
            .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::Internal))?;
        size = size
            .checked_add(block.size)
            .filter(|value| *value <= limits.maximum_artifact_bytes())
            .ok_or_else(|| ResultsServiceError::new(ResultsServiceErrorKind::Internal))?;
        descriptors.push(BlobDescriptor::new(key, digest, block.size, media_type));
    }
    if size != metadata.size {
        return Err(ResultsServiceError::new(ResultsServiceErrorKind::Internal));
    }
    Ok(descriptors)
}

impl fmt::Debug for ArtifactService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactService")
            .field("repository", &self.repository)
            .field("objects", &self.objects)
            .field("clock", &self.clock)
            .field("ids", &self.ids)
            .field("limits", &self.limits)
            .field("observer", &self.observer)
            .finish()
    }
}

fn map_repository_error(error: crate::ArtifactRepositoryError) -> ResultsServiceError {
    let kind = match error.kind() {
        ArtifactRepositoryErrorKind::NotFound => ResultsServiceErrorKind::NotFound,
        ArtifactRepositoryErrorKind::Unauthorized => ResultsServiceErrorKind::PermissionDenied,
        ArtifactRepositoryErrorKind::Conflict => ResultsServiceErrorKind::Conflict,
        ArtifactRepositoryErrorKind::InvalidState => ResultsServiceErrorKind::FailedPrecondition,
        ArtifactRepositoryErrorKind::ResourceExhausted => {
            ResultsServiceErrorKind::ResourceExhausted
        }
        ArtifactRepositoryErrorKind::Unavailable => ResultsServiceErrorKind::Unavailable,
        ArtifactRepositoryErrorKind::CorruptData => ResultsServiceErrorKind::Internal,
    };
    ResultsServiceError::new(kind)
}

fn map_blob_error(error: automata_ci_blob::BlobStoreError) -> ResultsServiceError {
    let kind = match error.kind() {
        BlobStoreErrorKind::TooLarge => ResultsServiceErrorKind::ResourceExhausted,
        BlobStoreErrorKind::Unauthorized => ResultsServiceErrorKind::PermissionDenied,
        BlobStoreErrorKind::NotFound
        | BlobStoreErrorKind::Conflict
        | BlobStoreErrorKind::Integrity
        | BlobStoreErrorKind::InvalidResponse => ResultsServiceErrorKind::Internal,
        BlobStoreErrorKind::Unavailable => ResultsServiceErrorKind::Unavailable,
    };
    ResultsServiceError::new(kind)
}

const fn results_operation_error_outcome(error: ResultsServiceError) -> ResultsOperationOutcome {
    match error.kind() {
        ResultsServiceErrorKind::InvalidArgument => ResultsOperationOutcome::InvalidArgument,
        ResultsServiceErrorKind::PermissionDenied => ResultsOperationOutcome::PermissionDenied,
        ResultsServiceErrorKind::NotFound => ResultsOperationOutcome::NotFound,
        ResultsServiceErrorKind::Conflict => ResultsOperationOutcome::Conflict,
        ResultsServiceErrorKind::FailedPrecondition => ResultsOperationOutcome::FailedPrecondition,
        ResultsServiceErrorKind::ResourceExhausted => ResultsOperationOutcome::ResourceExhausted,
        ResultsServiceErrorKind::Unavailable => ResultsOperationOutcome::Unavailable,
        ResultsServiceErrorKind::Internal => ResultsOperationOutcome::Internal,
    }
}
