#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! GitHub Actions Results compatibility over provider-neutral artifact ports.
//!
//! The public HTTP surface intentionally mirrors the protocol used by
//! `actions/upload-artifact`. Artifact bytes remain immutable, chunked blobs;
//! `PostgreSQL` is the only coordination authority and final publication points
//! at a canonical manifest. No object-store listing participates in state.

mod azure;
mod cache_http;
mod cache_model;
mod cache_port;
mod cache_postgres;
mod cache_service;
mod http;
mod http_support;
mod model;
mod observer;
mod port;
mod postgres;
mod runtime_authority;
mod service;
mod storage_observer;
mod token;

pub use cache_http::{GithubCacheApi, GithubCacheHttpLimits, GithubCacheHttpLimitsError};
pub use cache_model::{
    CacheAccessScope, CacheAuthority, CacheBlock, CacheEntryId, CacheFinalizationPreparation,
    CacheKey, CacheModelError, CachePermission, CacheProtocolEntryId, CacheRepositoryMetadata,
    CacheVersion, CommitCacheBlocks, CompleteCacheBlock, CompleteCacheFinalization,
    CreateCacheEntry, CreatedCacheEntry, FinalizedCacheEntry, LookupCacheEntry,
    PrepareCacheFinalization, PreparedCacheFinalization, ReserveCacheBlock, ResolveCacheDownload,
};
pub use cache_port::{
    CacheRepository, CacheRepositoryError, CacheRepositoryErrorKind, SignedCacheCapability,
};
pub use cache_postgres::PostgresCacheRepository;
pub use cache_service::{
    CacheDownloadSegment, CacheLimits, CacheLimitsError, CacheService, CacheServiceError,
    CacheServiceErrorKind, PreparedCacheDownload, derive_cache_authority,
};
pub use http::{GithubResultsApi, GithubResultsHttpLimits, GithubResultsHttpLimitsError};
pub use model::{
    ARTIFACT_MANIFEST_SCHEMA_VERSION, ArtifactBlock, ArtifactBlockReservation,
    ArtifactFinalizationClaim, ArtifactFinalizationReservation, ArtifactFinalizationWork,
    ArtifactId, ArtifactIdError, ArtifactManifest, ArtifactManifestBlock,
    ArtifactManifestSchemaError, ArtifactName, ArtifactNameError, BeginArtifactFinalization,
    CommitArtifactBlocks, CommittedArtifact, CompleteArtifactBlock, CompleteArtifactFinalization,
    CreateArtifact, CreateArtifactOutcome, ExecutionAuthority, FinalizeArtifactOutcome,
    ListArtifacts, LoadArtifactFinalization, MAXIMUM_ARTIFACT_FINALIZATION_LEASE_SECONDS,
    MAXIMUM_ARTIFACT_MANIFEST_BYTES, PublishedArtifactMetadata, RecordArtifactVerification,
    RenewArtifactFinalization, ReserveArtifactBlock, ResolveArtifactDownload, ResultsLimits,
    ResultsLimitsError, RuntimeTokenClaims, UploadId, VerifiedArtifactFinalization,
};
pub use observer::{
    NoopResultsObserver, ResultsBlobOperation, ResultsBlobOperationOutcome, ResultsHttpMethod,
    ResultsHttpRoute, ResultsHttpStatusClass, ResultsObserver, ResultsOperation,
    ResultsOperationOutcome, ResultsRepositoryOperation, ResultsRepositoryOperationOutcome,
    ResultsTransferDirection,
};
pub use port::{
    ArtifactRepository, ArtifactRepositoryError, ArtifactRepositoryErrorKind, ResultsClock,
    ResultsIdGenerator, RuntimeTokenIssuer, RuntimeTokenVerifier, SignedDownloadCapability,
    SignedUploadCapability, SystemResultsClock, SystemResultsIdGenerator, TokenError,
};
pub use postgres::PostgresArtifactRepository;
pub use runtime_authority::{
    GITHUB_RESULTS_RUNTIME_AUTHORITY, GithubResultsRuntimeAuthorityIssuer,
};
pub use service::{
    ARTIFACT_MANIFEST_MEDIA_TYPE, ArtifactService, ResultsServiceError, ResultsServiceErrorKind,
};
pub use storage_observer::{ObservedResultsArtifactRepository, ObservedResultsBlobStore};
pub use token::{
    HmacResultsAuthority, HmacResultsAuthorityConfig, PrivateNetworkResultsEndpoint,
    ResultsPublicEndpoint, RuntimeToken,
};
