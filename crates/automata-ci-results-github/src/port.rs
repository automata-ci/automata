use std::{fmt, sync::Arc, time::SystemTime};

use async_trait::async_trait;
use automata_ci_core::Sha256Digest;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::CacheAuthority;
use crate::model::{
    ArtifactBlockReservation, ArtifactFinalizationReservation, ArtifactFinalizationWork,
    BeginArtifactFinalization, CommitArtifactBlocks, CompleteArtifactBlock,
    CompleteArtifactFinalization, CreateArtifact, CreateArtifactOutcome, ExecutionAuthority,
    FinalizeArtifactOutcome, ListArtifacts, LoadArtifactFinalization, PublishedArtifactMetadata,
    RecordArtifactVerification, RenewArtifactFinalization, ReserveArtifactBlock,
    ResolveArtifactDownload, RuntimeTokenClaims, UploadId,
};

/// Sanitized durable-artifact failure class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactRepositoryErrorKind {
    /// The attempt, artifact, block, or committed block list does not exist.
    NotFound,
    /// The runtime token or signed upload no longer owns the current fence.
    Unauthorized,
    /// Immutable metadata contradicts an earlier request.
    Conflict,
    /// The requested lifecycle transition is not currently legal.
    InvalidState,
    /// A configured byte or count ceiling would be exceeded.
    ResourceExhausted,
    /// Durable state violates an invariant.
    CorruptData,
    /// `PostgreSQL` is temporarily unavailable.
    Unavailable,
}

/// Provider-sanitized repository failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("artifact repository operation failed: {kind:?}")]
pub struct ArtifactRepositoryError {
    kind: ArtifactRepositoryErrorKind,
}

impl ArtifactRepositoryError {
    /// Creates a sanitized failure.
    #[must_use]
    pub const fn new(kind: ArtifactRepositoryErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> ArtifactRepositoryErrorKind {
        self.kind
    }
}

/// Provider-neutral durable artifact coordination.
///
/// Implementations must verify the run/job/attempt/fence relation in every
/// mutating transaction. Block descriptors are reserved before object I/O and
/// become commit-visible only after exact completion. Finalization liveness,
/// takeover, renewal, and publication decisions use repository-authoritative
/// time sampled after the exact durable locks; request observation times are
/// bounded-skew evidence only.
#[async_trait]
pub trait ArtifactRepository: fmt::Debug + Send + Sync {
    /// Creates a pending artifact or returns the exact prior idempotent create.
    async fn create(
        &self,
        request: CreateArtifact,
    ) -> Result<CreateArtifactOutcome, ArtifactRepositoryError>;

    /// Reserves one immutable block identity before object publication.
    async fn reserve_block(
        &self,
        request: ReserveArtifactBlock,
    ) -> Result<ArtifactBlockReservation, ArtifactRepositoryError>;

    /// Marks one exact reservation ready after immutable object publication.
    async fn complete_block(
        &self,
        request: CompleteArtifactBlock,
    ) -> Result<(), ArtifactRepositoryError>;

    /// Atomically resolves and commits one ordered block list.
    async fn commit_blocks(
        &self,
        request: CommitArtifactBlocks,
    ) -> Result<crate::CommittedArtifact, ArtifactRepositoryError>;

    /// Durably claims exclusive verification/publication work before block reads.
    async fn begin_finalization(
        &self,
        request: BeginArtifactFinalization,
    ) -> Result<ArtifactFinalizationReservation, ArtifactRepositoryError>;

    /// Loads claim-bound work only after the claim transaction committed.
    async fn load_finalization(
        &self,
        request: LoadArtifactFinalization,
    ) -> Result<ArtifactFinalizationWork, ArtifactRepositoryError>;

    /// Renews one unexpired generation fence around bounded object I/O.
    async fn renew_finalization(
        &self,
        request: RenewArtifactFinalization,
    ) -> Result<(), ArtifactRepositoryError>;

    /// Persists verified digest and canonical manifest before manifest object I/O.
    async fn record_verification(
        &self,
        request: RecordArtifactVerification,
    ) -> Result<(), ArtifactRepositoryError>;

    /// Publishes the persisted manifest for the still-live claim holder.
    async fn complete_finalization(
        &self,
        request: CompleteArtifactFinalization,
    ) -> Result<FinalizeArtifactOutcome, ArtifactRepositoryError>;

    /// Lists published, non-expired artifacts visible to one active run attempt.
    async fn list(
        &self,
        request: ListArtifacts,
    ) -> Result<Vec<PublishedArtifactMetadata>, ArtifactRepositoryError>;

    /// Resolves exact immutable metadata after a signed download was verified.
    async fn resolve_download(
        &self,
        request: ResolveArtifactDownload,
    ) -> Result<PublishedArtifactMetadata, ArtifactRepositoryError>;
}

/// Caller clock kept outside JWT and repository implementations for deterministic tests.
///
/// Repository implementations may use this observation as bounded-skew request
/// evidence, but never as finalization lease authority.
pub trait ResultsClock: fmt::Debug + Send + Sync {
    /// Returns caller-observed whole UTC seconds since the Unix epoch.
    fn now_seconds(&self) -> u64;
}

/// System UTC clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResultsClock;

impl ResultsClock for SystemResultsClock {
    fn now_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }
}

/// Upload identity generator kept replaceable for deterministic and future UUID policies.
pub trait ResultsIdGenerator: fmt::Debug + Send + Sync {
    /// Generates a fresh unguessable upload identity.
    fn next_upload_id(&self) -> UploadId;
}

/// RFC 9562 random upload identity generator.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResultsIdGenerator;

impl ResultsIdGenerator for SystemResultsIdGenerator {
    fn next_upload_id(&self) -> UploadId {
        UploadId::from_uuid(Uuid::new_v4())
    }
}

/// Runtime-token or signed-upload failure that does not disclose key material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TokenError {
    /// Token or signature syntax is malformed or exceeds a bound.
    #[error("credential is malformed")]
    Malformed,
    /// Signature or configured issuer/audience/key identity is invalid.
    #[error("credential is invalid")]
    Invalid,
    /// Credential is not yet active or has expired.
    #[error("credential is outside its validity interval")]
    Expired,
    /// Credential does not contain one exact Results run/job scope.
    #[error("credential scope is invalid")]
    Scope,
    /// Issuance parameters violate the configured validity policy.
    #[error("credential issuance policy rejected the request")]
    Policy,
}

/// Pluggable issuer for the per-job secret exposed as `ACTIONS_RUNTIME_TOKEN`.
pub trait RuntimeTokenIssuer: fmt::Debug + Send + Sync {
    /// Issues one bounded token for an exact active attempt fence.
    ///
    /// # Errors
    ///
    /// Returns a policy error for a zero or excessive validity interval.
    fn issue(
        &self,
        authority: ExecutionAuthority,
        cache: CacheAuthority,
        valid_for_seconds: u64,
    ) -> Result<crate::RuntimeToken, TokenError>;
}

/// Pluggable verifier for `ACTIONS_RUNTIME_TOKEN` bearer credentials.
pub trait RuntimeTokenVerifier: fmt::Debug + Send + Sync {
    /// Authenticates and parses one bounded compact JWT.
    ///
    /// # Errors
    ///
    /// Returns a sanitized syntax, signature, time, or scope failure.
    fn verify(&self, token: &str) -> Result<RuntimeTokenClaims, TokenError>;
}

/// Issuer/verifier for the short-lived `sig` query capability used by Azure's client.
pub trait SignedUploadCapability: fmt::Debug + Send + Sync {
    /// Creates a signed URL for one upload, never extending past `expires_at_seconds`.
    ///
    /// # Errors
    ///
    /// Returns a policy or expiry failure when a URL cannot be issued.
    fn issue_url(&self, upload_id: UploadId, expires_at_seconds: u64) -> Result<Url, TokenError>;

    /// Verifies one URL query capability and exact upload binding.
    ///
    /// # Errors
    ///
    /// Returns a sanitized syntax, signature, binding, or expiry failure.
    fn verify(
        &self,
        upload_id: UploadId,
        expires_at_seconds: u64,
        signature: &str,
    ) -> Result<(), TokenError>;
}

/// Issuer/verifier for short-lived immutable artifact download URLs.
pub trait SignedDownloadCapability: fmt::Debug + Send + Sync {
    /// Creates a URL bound to one published artifact identity and digest.
    ///
    /// # Errors
    ///
    /// Returns a policy or expiry failure when a URL cannot be issued.
    fn issue_download_url(
        &self,
        artifact_id: crate::ArtifactId,
        content_digest: Sha256Digest,
        expires_at_seconds: u64,
    ) -> Result<Url, TokenError>;

    /// Verifies the URL capability against its exact immutable identity.
    ///
    /// # Errors
    ///
    /// Returns a sanitized syntax, signature, binding, or expiry failure.
    fn verify_download(
        &self,
        artifact_id: crate::ArtifactId,
        content_digest: Sha256Digest,
        expires_at_seconds: u64,
        signature: &str,
    ) -> Result<(), TokenError>;
}

pub(crate) type ArtifactRepositoryPort = Arc<dyn ArtifactRepository>;
pub(crate) type ClockPort = Arc<dyn ResultsClock>;
pub(crate) type IdGeneratorPort = Arc<dyn ResultsIdGenerator>;
