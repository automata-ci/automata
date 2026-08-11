use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_core::Sha256Digest;
use thiserror::Error;
use url::Url;

use crate::{
    CacheEntryId, CacheFinalizationPreparation, CommitCacheBlocks, CompleteCacheBlock,
    CompleteCacheFinalization, CreateCacheEntry, CreatedCacheEntry, FinalizedCacheEntry,
    LookupCacheEntry, ReserveCacheBlock, ResolveCacheDownload,
};

/// Sanitized durable cache failure class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheRepositoryErrorKind {
    /// The entry, block, commit, or execution authority does not exist.
    NotFound,
    /// The authenticated authority or durable attempt fence is not permitted.
    Unauthorized,
    /// Immutable metadata contradicts an earlier request.
    Conflict,
    /// The requested lifecycle transition is not legal.
    InvalidState,
    /// A configured byte or count ceiling would be exceeded.
    ResourceExhausted,
    /// Durable state violates an invariant.
    CorruptData,
    /// `PostgreSQL` is temporarily unavailable.
    Unavailable,
}

/// Provider-sanitized cache repository failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("cache repository operation failed: {kind:?}")]
pub struct CacheRepositoryError {
    kind: CacheRepositoryErrorKind,
}

impl CacheRepositoryError {
    /// Creates a sanitized failure.
    #[must_use]
    pub const fn new(kind: CacheRepositoryErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> CacheRepositoryErrorKind {
        self.kind
    }
}

/// Provider-neutral durable coordination for GitHub Actions cache-v2 entries.
///
/// Mutations must recheck the exact live attempt fence transactionally. Reads
/// must resolve repository and ref solely from authenticated authority, may
/// cross workflow runs within that repository, and must never cross repositories.
/// `PostgreSQL` implementations derive retention, expiry, and touch decisions
/// from database time sampled after the relevant locks; caller observations are
/// bounded request evidence and never cache-liveness authority.
#[async_trait]
pub trait CacheRepository: fmt::Debug + Send + Sync {
    /// Creates a pending entry or returns the exact idempotent replay.
    async fn create(
        &self,
        request: CreateCacheEntry,
    ) -> Result<CreatedCacheEntry, CacheRepositoryError>;

    /// Reserves immutable block metadata before object publication.
    async fn reserve_block(&self, request: ReserveCacheBlock)
    -> Result<bool, CacheRepositoryError>;

    /// Marks one exact reservation ready after object publication.
    async fn complete_block(&self, request: CompleteCacheBlock)
    -> Result<(), CacheRepositoryError>;

    /// Atomically commits one ordered list of ready blocks.
    async fn commit_blocks(&self, request: CommitCacheBlocks) -> Result<(), CacheRepositoryError>;

    /// Resolves exact committed work or an exact finalized replay.
    async fn prepare_finalization(
        &self,
        request: crate::PrepareCacheFinalization,
    ) -> Result<CacheFinalizationPreparation, CacheRepositoryError>;

    /// Publishes a verified entry and enforces inactivity and quota eviction.
    async fn complete_finalization(
        &self,
        request: CompleteCacheFinalization,
    ) -> Result<FinalizedCacheEntry, CacheRepositoryError>;

    /// Applies scope-first exact-primary/primary-prefix/restore-prefix matching.
    async fn lookup(
        &self,
        request: LookupCacheEntry,
    ) -> Result<Option<FinalizedCacheEntry>, CacheRepositoryError>;

    /// Resolves immutable metadata after a signed download was verified.
    async fn resolve_download(
        &self,
        request: ResolveCacheDownload,
    ) -> Result<FinalizedCacheEntry, CacheRepositoryError>;
}

/// Issuer/verifier for cache upload and download URL capabilities.
pub trait SignedCacheCapability: fmt::Debug + Send + Sync {
    /// Issues a signed Azure-compatible upload URL.
    ///
    /// # Errors
    ///
    /// Returns a sanitized policy or expiry failure.
    fn issue_cache_upload_url(
        &self,
        entry_id: CacheEntryId,
        expires_at_seconds: u64,
    ) -> Result<Url, crate::TokenError>;

    /// Verifies a signed cache upload capability.
    ///
    /// # Errors
    ///
    /// Returns a sanitized syntax, binding, signature, or expiry failure.
    fn verify_cache_upload(
        &self,
        entry_id: CacheEntryId,
        expires_at_seconds: u64,
        signature: &str,
    ) -> Result<(), crate::TokenError>;

    /// Issues a signed immutable cache download URL.
    ///
    /// # Errors
    ///
    /// Returns a sanitized policy or expiry failure.
    fn issue_cache_download_url(
        &self,
        entry_id: CacheEntryId,
        digest: Sha256Digest,
        expires_at_seconds: u64,
    ) -> Result<Url, crate::TokenError>;

    /// Verifies a signed immutable cache download capability.
    ///
    /// # Errors
    ///
    /// Returns a sanitized syntax, binding, signature, or expiry failure.
    fn verify_cache_download(
        &self,
        entry_id: CacheEntryId,
        digest: Sha256Digest,
        expires_at_seconds: u64,
        signature: &str,
    ) -> Result<(), crate::TokenError>;
}

pub(crate) type CacheRepositoryPort = Arc<dyn CacheRepository>;
