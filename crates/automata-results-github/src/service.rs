use std::{fmt, sync::Arc};

use automata_blob::{BlobKey, BlobPayload, BlobStoreErrorKind, ImmutableBlobStore, MediaType};
use automata_core::Sha256Digest;
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    ArtifactBlock, ArtifactManifest, ArtifactName, ArtifactPublicationState,
    ArtifactRepositoryErrorKind, CommitArtifactBlocks, CreateArtifact, CreateArtifactOutcome,
    ExecutionAuthority, FinalizeArtifact, FinalizeArtifactOutcome, ResultsLimits,
    StageArtifactBlock, UploadId,
    azure::block_list_digest,
    port::{ArtifactRepositoryPort, ClockPort, IdGeneratorPort},
};

const SUPPORTED_ARTIFACT_VERSION: i32 = 7;
const BLOCK_MEDIA_TYPE: &str = "application/octet-stream";
const MANIFEST_MEDIA_TYPE: &str = "application/vnd.automata.artifact-manifest+json";

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
        }
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
            })
            .await
            .map_err(map_repository_error)
    }

    /// Publishes one immutable staged block before recording fenced metadata.
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
        let size = u64::try_from(bytes.len())
            .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::ResourceExhausted))?;
        if size > self.limits.maximum_block_bytes() {
            return Err(ResultsServiceError::new(
                ResultsServiceErrorKind::ResourceExhausted,
            ));
        }
        self.repository
            .authorize_upload(upload_id)
            .await
            .map_err(map_repository_error)?;
        let media_type = MediaType::new(BLOCK_MEDIA_TYPE)
            .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::Internal))?;
        let digest = Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
        let key = BlobKey::new(format!("artifact-staging/v1/{upload_id}/{digest}"))
            .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::Internal))?;
        let payload = BlobPayload::from_bytes(key, media_type, bytes);
        let descriptor = payload.descriptor().clone();
        self.objects
            .put_if_absent(payload)
            .await
            .map_err(map_blob_error)?;
        self.repository
            .record_block(StageArtifactBlock {
                upload_id,
                block: ArtifactBlock::new(block_id, descriptor),
                observed_at_seconds: self.clock.now_seconds(),
                maximum_blocks: self.limits.maximum_blocks(),
                maximum_staged_bytes: self.limits.maximum_artifact_bytes(),
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
        if claimed_size > self.limits.maximum_artifact_bytes() {
            return Err(ResultsServiceError::new(
                ResultsServiceErrorKind::ResourceExhausted,
            ));
        }
        let name = ArtifactName::new(name, self.limits.maximum_name_bytes())
            .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::InvalidArgument))?;
        match self
            .repository
            .publication_state(authority, &name)
            .await
            .map_err(map_repository_error)?
        {
            ArtifactPublicationState::Published(published) => {
                if published.size != claimed_size
                    || claimed_digest.is_some_and(|digest| digest != published.content_digest)
                {
                    return Err(ResultsServiceError::new(ResultsServiceErrorKind::Conflict));
                }
                Ok(FinalizeArtifactOutcome {
                    artifact_id: published.artifact_id,
                    content_digest: published.content_digest,
                    size: published.size,
                })
            }
            ArtifactPublicationState::Committed(committed) => {
                if committed.size != claimed_size {
                    return Err(ResultsServiceError::new(
                        ResultsServiceErrorKind::InvalidArgument,
                    ));
                }
                let mut hasher = Sha256::new();
                let mut actual_size = 0_u64;
                for block in &committed.blocks {
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
                let manifest = ArtifactManifest::from_committed(&committed, content_digest);
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
                let media_type = MediaType::new(MANIFEST_MEDIA_TYPE)
                    .map_err(|_| ResultsServiceError::new(ResultsServiceErrorKind::Internal))?;
                let payload = BlobPayload::from_bytes(key, media_type, Bytes::from(manifest_bytes));
                let descriptor = payload.descriptor().clone();
                self.objects
                    .put_if_absent(payload)
                    .await
                    .map_err(map_blob_error)?;
                self.repository
                    .finalize(FinalizeArtifact {
                        authority,
                        name,
                        content_digest,
                        size: actual_size,
                        manifest: descriptor,
                        observed_at_seconds: self.clock.now_seconds(),
                    })
                    .await
                    .map_err(map_repository_error)
            }
        }
    }
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

fn map_blob_error(error: automata_blob::BlobStoreError) -> ResultsServiceError {
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
