use std::{fmt, sync::Arc};

use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    MediaType,
};
use automata_ci_core::Sha256Digest;
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::cache_port::CacheRepositoryPort;
use crate::{
    CacheAccessScope, CacheAuthority, CacheBlock, CacheEntryId, CacheFinalizationPreparation,
    CacheKey, CachePermission, CacheRepositoryError, CacheRepositoryErrorKind,
    CacheRepositoryMetadata, CacheVersion, CommitCacheBlocks, CompleteCacheBlock,
    CompleteCacheFinalization, CreateCacheEntry, CreatedCacheEntry, ExecutionAuthority,
    FinalizedCacheEntry, LookupCacheEntry, PrepareCacheFinalization, ReserveCacheBlock,
    ResolveCacheDownload, ResultsClock, ResultsIdGenerator,
};

const CACHE_BLOCK_MEDIA_TYPE: &str = "application/octet-stream";
const CACHE_BLOCK_LIST_DOMAIN: &[u8] = b"automata-results-cache-block-list-v1\0";
const MAXIMUM_DURABLE_CACHE_BLOCK_BYTES: u64 = 128 * 1024 * 1024;
const MAXIMUM_DURABLE_CACHE_BLOCKS: usize = 50_000;
const MAXIMUM_DURABLE_CACHE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Current cache-v2 resource and retention policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheLimits {
    maximum_block_bytes: u64,
    maximum_blocks: usize,
    maximum_entry_bytes: u64,
    repository_quota_bytes: u64,
    maximum_total_keys: usize,
    inactivity_seconds: u64,
}

impl CacheLimits {
    /// Creates a fully explicit cache policy.
    ///
    /// # Errors
    ///
    /// Rejects zero limits, a per-entry limit above the repository quota, a
    /// key count above the current action maximum, or values outside SQL bounds.
    pub const fn new(
        maximum_block_bytes: u64,
        maximum_blocks: usize,
        maximum_entry_bytes: u64,
        repository_quota_bytes: u64,
        maximum_total_keys: usize,
        inactivity_seconds: u64,
    ) -> Result<Self, CacheLimitsError> {
        if maximum_block_bytes == 0
            || maximum_blocks == 0
            || maximum_entry_bytes == 0
            || repository_quota_bytes == 0
            || maximum_entry_bytes > repository_quota_bytes
            || maximum_block_bytes > MAXIMUM_DURABLE_CACHE_BLOCK_BYTES
            || maximum_blocks > MAXIMUM_DURABLE_CACHE_BLOCKS
            || maximum_entry_bytes > MAXIMUM_DURABLE_CACHE_BYTES
            || repository_quota_bytes > MAXIMUM_DURABLE_CACHE_BYTES
            || repository_quota_bytes > i64::MAX as u64
            || maximum_total_keys == 0
            || maximum_total_keys > 10
            || inactivity_seconds == 0
            || inactivity_seconds > i64::MAX as u64
        {
            return Err(CacheLimitsError);
        }
        Ok(Self {
            maximum_block_bytes,
            maximum_blocks,
            maximum_entry_bytes,
            repository_quota_bytes,
            maximum_total_keys,
            inactivity_seconds,
        })
    }

    /// Returns the maximum body of one staged Azure block.
    #[must_use]
    pub const fn maximum_block_bytes(self) -> u64 {
        self.maximum_block_bytes
    }

    /// Returns the maximum committed block count.
    #[must_use]
    pub const fn maximum_blocks(self) -> usize {
        self.maximum_blocks
    }

    /// Returns the maximum byte count of one cache entry.
    #[must_use]
    pub const fn maximum_entry_bytes(self) -> u64 {
        self.maximum_entry_bytes
    }

    /// Returns the repository-wide finalized cache quota.
    #[must_use]
    pub const fn repository_quota_bytes(self) -> u64 {
        self.repository_quota_bytes
    }

    /// Returns the primary-plus-restore-key count limit.
    #[must_use]
    pub const fn maximum_total_keys(self) -> usize {
        self.maximum_total_keys
    }

    /// Returns the inactivity retention interval.
    #[must_use]
    pub const fn inactivity_seconds(self) -> u64 {
        self.inactivity_seconds
    }
}

impl Default for CacheLimits {
    fn default() -> Self {
        Self {
            maximum_block_bytes: 128 * 1024 * 1024,
            maximum_blocks: 50_000,
            maximum_entry_bytes: 10 * 1024 * 1024 * 1024,
            repository_quota_bytes: 10 * 1024 * 1024 * 1024,
            maximum_total_keys: 10,
            inactivity_seconds: 7 * 24 * 60 * 60,
        }
    }
}

/// Invalid cache resource limits.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub cache limits are invalid")]
pub struct CacheLimitsError;

/// Stable cache service failure class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheServiceErrorKind {
    /// Request syntax or a protocol value is invalid.
    InvalidArgument,
    /// Authenticated access controls do not authorize the request.
    PermissionDenied,
    /// The cache entry does not exist.
    NotFound,
    /// Immutable metadata conflicts with durable state.
    Conflict,
    /// The entry is not in the required lifecycle state.
    FailedPrecondition,
    /// A byte or count limit was exceeded.
    ResourceExhausted,
    /// A required dependency is temporarily unavailable.
    Unavailable,
    /// Durable or provider data violates an invariant.
    Internal,
}

/// Sanitized cache service failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("cache service operation failed: {kind:?}")]
pub struct CacheServiceError {
    kind: CacheServiceErrorKind,
}

impl CacheServiceError {
    const fn new(kind: CacheServiceErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> CacheServiceErrorKind {
        self.kind
    }
}

/// One immutable object slice participating in a ranged cache response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheDownloadSegment {
    descriptor: BlobDescriptor,
    start: usize,
    end: usize,
}

impl CacheDownloadSegment {
    /// Returns the exact immutable object descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &BlobDescriptor {
        &self.descriptor
    }

    /// Returns the half-open byte range within the object.
    #[must_use]
    pub const fn range(&self) -> std::ops::Range<usize> {
        self.start..self.end
    }
}

/// Prepared immutable metadata and object slices for HEAD or GET.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedCacheDownload {
    /// Finalized entry metadata.
    pub metadata: FinalizedCacheEntry,
    /// Exact half-open range within the concatenated archive.
    pub range: std::ops::Range<u64>,
    /// Ordered immutable object slices.
    pub segments: Vec<CacheDownloadSegment>,
}

/// Application service for the current GitHub Actions cache-v2 protocol.
pub struct CacheService {
    repository: CacheRepositoryPort,
    objects: Arc<dyn ImmutableBlobStore>,
    clock: Arc<dyn ResultsClock>,
    ids: Arc<dyn ResultsIdGenerator>,
    limits: CacheLimits,
}

impl CacheService {
    /// Composes cache coordination with immutable storage and deterministic ports.
    #[must_use]
    pub fn new(
        repository: CacheRepositoryPort,
        objects: Arc<dyn ImmutableBlobStore>,
        clock: Arc<dyn ResultsClock>,
        ids: Arc<dyn ResultsIdGenerator>,
        limits: CacheLimits,
    ) -> Self {
        Self {
            repository,
            objects,
            clock,
            ids,
            limits,
        }
    }

    /// Returns the active resource policy.
    #[must_use]
    pub const fn limits(&self) -> CacheLimits {
        self.limits
    }

    /// Creates or exactly replays one pending entry in the current writable ref.
    ///
    /// # Errors
    ///
    /// Rejects invalid key/version data, read-only tokens, stale fences, and
    /// conflicting immutable entries.
    pub async fn create(
        &self,
        execution: ExecutionAuthority,
        cache: CacheAuthority,
        key: String,
        version: String,
    ) -> Result<CreatedCacheEntry, CacheServiceError> {
        let key = CacheKey::new(key).map_err(|_| invalid())?;
        let version = CacheVersion::new(version).map_err(|_| invalid())?;
        if cache.writable_scope().is_none() {
            return Err(CacheServiceError::new(
                CacheServiceErrorKind::PermissionDenied,
            ));
        }
        let entry_id = CacheEntryId::new(self.ids.next_upload_id().as_uuid())
            .map_err(|_| CacheServiceError::new(CacheServiceErrorKind::Internal))?;
        self.repository
            .create(CreateCacheEntry {
                execution,
                cache,
                entry_id,
                key,
                version,
                observed_at_seconds: self.clock.now_seconds(),
            })
            .await
            .map_err(map_repository_error)
    }

    /// Stages one immutable Azure block.
    ///
    /// # Errors
    ///
    /// Rejects excessive blocks, stale signed uploads, and conflicting replay.
    pub async fn stage_block(
        &self,
        entry_id: CacheEntryId,
        block_id: String,
        bytes: Bytes,
    ) -> Result<(), CacheServiceError> {
        let size = u64::try_from(bytes.len()).map_err(|_| exhausted())?;
        if size > self.limits.maximum_block_bytes {
            return Err(exhausted());
        }
        let media_type = MediaType::new(CACHE_BLOCK_MEDIA_TYPE)
            .map_err(|_| CacheServiceError::new(CacheServiceErrorKind::Internal))?;
        let digest = Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
        let key = BlobKey::new(format!("cache-staging/v1/{entry_id}/{digest}"))
            .map_err(|_| CacheServiceError::new(CacheServiceErrorKind::Internal))?;
        let payload = BlobPayload::from_bytes(key, media_type, bytes);
        let block = CacheBlock::new(block_id, payload.descriptor().clone());
        let upload_required = self
            .repository
            .reserve_block(ReserveCacheBlock {
                entry_id,
                block: block.clone(),
                observed_at_seconds: self.clock.now_seconds(),
                maximum_blocks: self.limits.maximum_blocks,
                maximum_entry_bytes: self.limits.maximum_entry_bytes,
            })
            .await
            .map_err(map_repository_error)?;
        if upload_required {
            self.objects
                .put_if_absent(payload)
                .await
                .map_err(map_blob_error)?;
            self.repository
                .complete_block(CompleteCacheBlock {
                    entry_id,
                    block,
                    observed_at_seconds: self.clock.now_seconds(),
                })
                .await
                .map_err(map_repository_error)?;
        }
        Ok(())
    }

    /// Commits one exact ordered Azure block list.
    ///
    /// # Errors
    ///
    /// Rejects excessive lists, missing blocks, stale authority, and replay conflicts.
    pub async fn commit_blocks(
        &self,
        entry_id: CacheEntryId,
        block_ids: Vec<String>,
    ) -> Result<(), CacheServiceError> {
        if block_ids.len() > self.limits.maximum_blocks {
            return Err(exhausted());
        }
        self.repository
            .commit_blocks(CommitCacheBlocks {
                entry_id,
                list_digest: block_list_digest(&block_ids),
                block_ids,
                observed_at_seconds: self.clock.now_seconds(),
                maximum_blocks: self.limits.maximum_blocks,
                maximum_entry_bytes: self.limits.maximum_entry_bytes,
            })
            .await
            .map_err(map_repository_error)
    }

    /// Verifies and finalizes one committed entry, or returns its exact replay.
    ///
    /// # Errors
    ///
    /// Rejects size mismatch, provider corruption, stale authority, and quota failure.
    pub async fn finalize(
        &self,
        execution: ExecutionAuthority,
        cache: CacheAuthority,
        key: String,
        version: String,
        claimed_size: u64,
    ) -> Result<FinalizedCacheEntry, CacheServiceError> {
        let key = CacheKey::new(key).map_err(|_| invalid())?;
        let version = CacheVersion::new(version).map_err(|_| invalid())?;
        if cache.writable_scope().is_none() || claimed_size > self.limits.maximum_entry_bytes {
            return Err(if cache.writable_scope().is_none() {
                CacheServiceError::new(CacheServiceErrorKind::PermissionDenied)
            } else {
                exhausted()
            });
        }
        let prepared = self
            .repository
            .prepare_finalization(PrepareCacheFinalization {
                execution,
                cache: cache.clone(),
                key: key.clone(),
                version: version.clone(),
                claimed_size,
            })
            .await
            .map_err(map_repository_error)?;
        let CacheFinalizationPreparation::Verify(prepared) = prepared else {
            let CacheFinalizationPreparation::Finalized(finalized) = prepared else {
                unreachable!("closed finalization preparation")
            };
            return Ok(finalized);
        };
        if prepared.size != claimed_size {
            return Err(CacheServiceError::new(CacheServiceErrorKind::Conflict));
        }
        let mut hasher = Sha256::new();
        let mut verified_size = 0_u64;
        for block in &prepared.blocks {
            let verified = self
                .objects
                .get_verified(block.descriptor(), self.limits.maximum_block_bytes)
                .await
                .map_err(map_blob_error)?;
            verified_size = verified_size
                .checked_add(block.descriptor().size())
                .ok_or_else(exhausted)?;
            hasher.update(verified.bytes());
        }
        if verified_size != claimed_size {
            return Err(CacheServiceError::new(CacheServiceErrorKind::Conflict));
        }
        let digest = Sha256Digest::from_bytes(hasher.finalize().into());
        self.repository
            .complete_finalization(CompleteCacheFinalization {
                execution,
                cache,
                entry_id: prepared.entry_id,
                key,
                version,
                digest,
                size: verified_size,
                observed_at_seconds: self.clock.now_seconds(),
                repository_quota_bytes: self.limits.repository_quota_bytes,
                inactivity_seconds: self.limits.inactivity_seconds,
            })
            .await
            .map_err(map_repository_error)
    }

    /// Resolves a cache using ordered scope, exact, and prefix precedence.
    ///
    /// # Errors
    ///
    /// Rejects invalid or excessive keys, stale caller authority, and corrupt state.
    pub async fn lookup(
        &self,
        execution: ExecutionAuthority,
        cache: CacheAuthority,
        key: String,
        restore_keys: Vec<String>,
        version: String,
    ) -> Result<Option<FinalizedCacheEntry>, CacheServiceError> {
        if restore_keys.len().saturating_add(1) > self.limits.maximum_total_keys {
            return Err(invalid());
        }
        let key = CacheKey::new(key).map_err(|_| invalid())?;
        let restore_keys = restore_keys
            .into_iter()
            .map(CacheKey::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid())?;
        let version = CacheVersion::new(version).map_err(|_| invalid())?;
        self.repository
            .lookup(LookupCacheEntry {
                execution,
                cache,
                key,
                restore_keys,
                version,
                observed_at_seconds: self.clock.now_seconds(),
                inactivity_seconds: self.limits.inactivity_seconds,
            })
            .await
            .map_err(map_repository_error)
    }

    /// Resolves a signed immutable download and maps an optional byte range.
    ///
    /// # Errors
    ///
    /// Rejects missing/expired entries, digest mismatch, and invalid ranges.
    pub async fn prepare_download(
        &self,
        entry_id: CacheEntryId,
        digest: Sha256Digest,
        range: Option<std::ops::Range<u64>>,
    ) -> Result<PreparedCacheDownload, CacheServiceError> {
        let metadata = self
            .repository
            .resolve_download(ResolveCacheDownload {
                entry_id,
                digest,
                observed_at_seconds: self.clock.now_seconds(),
                inactivity_seconds: self.limits.inactivity_seconds,
            })
            .await
            .map_err(map_repository_error)?;
        let range = range.unwrap_or(0..metadata.size);
        if range.start > range.end || range.end > metadata.size {
            return Err(invalid());
        }
        let mut segments = Vec::new();
        let mut block_start = 0_u64;
        for block in &metadata.blocks {
            let block_end = block_start
                .checked_add(block.descriptor().size())
                .ok_or_else(|| CacheServiceError::new(CacheServiceErrorKind::Internal))?;
            let start = range.start.max(block_start);
            let end = range.end.min(block_end);
            if start < end {
                segments.push(CacheDownloadSegment {
                    descriptor: block.descriptor().clone(),
                    start: usize::try_from(start - block_start)
                        .map_err(|_| CacheServiceError::new(CacheServiceErrorKind::Internal))?,
                    end: usize::try_from(end - block_start)
                        .map_err(|_| CacheServiceError::new(CacheServiceErrorKind::Internal))?,
                });
            }
            block_start = block_end;
        }
        if block_start != metadata.size {
            return Err(CacheServiceError::new(CacheServiceErrorKind::Internal));
        }
        Ok(PreparedCacheDownload {
            metadata,
            range,
            segments,
        })
    }

    /// Reads and verifies one prepared immutable object slice.
    ///
    /// # Errors
    ///
    /// Returns a sanitized provider/integrity failure.
    pub async fn read_download_segment(
        &self,
        segment: &CacheDownloadSegment,
    ) -> Result<Bytes, CacheServiceError> {
        let verified = self
            .objects
            .get_verified(segment.descriptor(), self.limits.maximum_block_bytes)
            .await
            .map_err(map_blob_error)?;
        Ok(verified.into_bytes().slice(segment.range()))
    }
}

impl fmt::Debug for CacheService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CacheService")
            .field("repository", &self.repository)
            .field("objects", &self.objects)
            .field("clock", &self.clock)
            .field("ids", &self.ids)
            .field("limits", &self.limits)
            .finish()
    }
}

/// Derives ordered current- and default-branch scopes from trusted evidence.
///
/// `push` and `pull_request` runs receive read/write permission. Other events
/// remain read-only because the current immutable evidence does not prove a
/// safe writer for externally initiated execution. A distinct default branch
/// comes only from server-owned repository metadata and is always read-only.
///
/// # Errors
///
/// Rejects non-GitHub providers, invalid repository/ref values, or metadata
/// for a different repository.
pub fn derive_cache_authority(
    provider: &str,
    repository: &str,
    git_ref: &str,
    event_name: &str,
    repository_metadata: Option<&CacheRepositoryMetadata>,
) -> Result<CacheAuthority, CacheServiceError> {
    if provider != "github" {
        return Err(CacheServiceError::new(
            CacheServiceErrorKind::PermissionDenied,
        ));
    }
    let permission = if event_name == "push"
        || (event_name == "pull_request" && is_pull_request_merge_ref(git_ref))
    {
        CachePermission::ReadWrite
    } else {
        CachePermission::Read
    };
    let current_scope = CacheAccessScope::new(git_ref, permission).map_err(|_| invalid())?;
    let current =
        CacheAuthority::new(repository, vec![current_scope.clone()]).map_err(|_| invalid())?;
    let mut scopes = vec![current_scope];
    if let Some(metadata) = repository_metadata {
        if metadata.repository() != current.repository() {
            return Err(CacheServiceError::new(
                CacheServiceErrorKind::PermissionDenied,
            ));
        }
        if metadata.default_branch_ref() != git_ref {
            scopes.push(
                CacheAccessScope::new(metadata.default_branch_ref(), CachePermission::Read)
                    .map_err(|_| invalid())?,
            );
        }
    }
    CacheAuthority::new(current.repository(), scopes).map_err(|_| invalid())
}

fn is_pull_request_merge_ref(git_ref: &str) -> bool {
    let Some(remainder) = git_ref.strip_prefix("refs/pull/") else {
        return false;
    };
    let Some((number, suffix)) = remainder.split_once('/') else {
        return false;
    };
    suffix == "merge"
        && !number.is_empty()
        && number != "0"
        && !(number.len() > 1 && number.starts_with('0'))
        && number.bytes().all(|byte| byte.is_ascii_digit())
}

fn block_list_digest(block_ids: &[String]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(CACHE_BLOCK_LIST_DOMAIN);
    hasher.update(
        u64::try_from(block_ids.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for block_id in block_ids {
        hasher.update(
            u64::try_from(block_id.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(block_id.as_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

const fn invalid() -> CacheServiceError {
    CacheServiceError::new(CacheServiceErrorKind::InvalidArgument)
}

const fn exhausted() -> CacheServiceError {
    CacheServiceError::new(CacheServiceErrorKind::ResourceExhausted)
}

const fn map_repository_error(error: CacheRepositoryError) -> CacheServiceError {
    CacheServiceError::new(match error.kind() {
        CacheRepositoryErrorKind::NotFound => CacheServiceErrorKind::NotFound,
        CacheRepositoryErrorKind::Unauthorized => CacheServiceErrorKind::PermissionDenied,
        CacheRepositoryErrorKind::Conflict => CacheServiceErrorKind::Conflict,
        CacheRepositoryErrorKind::InvalidState => CacheServiceErrorKind::FailedPrecondition,
        CacheRepositoryErrorKind::ResourceExhausted => CacheServiceErrorKind::ResourceExhausted,
        CacheRepositoryErrorKind::CorruptData => CacheServiceErrorKind::Internal,
        CacheRepositoryErrorKind::Unavailable => CacheServiceErrorKind::Unavailable,
    })
}

const fn map_blob_error(error: BlobStoreError) -> CacheServiceError {
    CacheServiceError::new(match error.kind() {
        BlobStoreErrorKind::NotFound | BlobStoreErrorKind::Integrity => {
            CacheServiceErrorKind::Internal
        }
        BlobStoreErrorKind::Conflict => CacheServiceErrorKind::Conflict,
        BlobStoreErrorKind::TooLarge => CacheServiceErrorKind::ResourceExhausted,
        BlobStoreErrorKind::Unauthorized => CacheServiceErrorKind::PermissionDenied,
        BlobStoreErrorKind::Unavailable => CacheServiceErrorKind::Unavailable,
        BlobStoreErrorKind::InvalidResponse => CacheServiceErrorKind::Internal,
    })
}
