#![forbid(unsafe_code)]
//! GitHub Actions Results compatibility over provider-neutral artifact ports.
//!
//! The public HTTP surface intentionally mirrors the protocol used by
//! `actions/upload-artifact`. Artifact bytes remain immutable, chunked blobs;
//! `PostgreSQL` is the only coordination authority and final publication points
//! at a canonical manifest. No object-store listing participates in state.

mod azure;
mod http;
mod model;
mod port;
mod postgres;
mod runtime_authority;
mod service;
mod token;

pub use http::{GithubResultsApi, GithubResultsHttpLimits, GithubResultsHttpLimitsError};
pub use model::{
    ArtifactBlock, ArtifactId, ArtifactIdError, ArtifactManifest, ArtifactManifestBlock,
    ArtifactName, ArtifactNameError, ArtifactPublicationState, CommitArtifactBlocks,
    CommittedArtifact, CreateArtifact, CreateArtifactOutcome, ExecutionAuthority, FinalizeArtifact,
    FinalizeArtifactOutcome, PublishedArtifact, ResultsLimits, ResultsLimitsError,
    RuntimeTokenClaims, StageArtifactBlock, UploadId,
};
pub use port::{
    ArtifactRepository, ArtifactRepositoryError, ArtifactRepositoryErrorKind, ResultsClock,
    ResultsIdGenerator, RuntimeTokenIssuer, RuntimeTokenVerifier, SignedUploadCapability,
    SystemResultsClock, SystemResultsIdGenerator, TokenError,
};
pub use postgres::PostgresArtifactRepository;
pub use runtime_authority::{
    GITHUB_RESULTS_RUNTIME_AUTHORITY, GithubResultsRuntimeAuthorityIssuer,
};
pub use service::{ArtifactService, ResultsServiceError, ResultsServiceErrorKind};
pub use token::{
    HmacResultsAuthority, HmacResultsAuthorityConfig, ResultsPublicEndpoint, RuntimeToken,
};
