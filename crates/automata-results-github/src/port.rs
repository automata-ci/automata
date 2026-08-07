use std::{fmt, sync::Arc, time::SystemTime};

use async_trait::async_trait;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::model::{
    ArtifactPublicationState, CommitArtifactBlocks, CreateArtifact, CreateArtifactOutcome,
    ExecutionAuthority, FinalizeArtifact, FinalizeArtifactOutcome, RuntimeTokenClaims,
    StageArtifactBlock, UploadId,
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
/// mutating transaction. Object bytes are published before metadata is passed
/// to this port, so durable rows never point at a known-missing blob.
#[async_trait]
pub trait ArtifactRepository: fmt::Debug + Send + Sync {
    /// Creates a pending artifact or returns the exact prior idempotent create.
    async fn create(
        &self,
        request: CreateArtifact,
    ) -> Result<CreateArtifactOutcome, ArtifactRepositoryError>;

    /// Checks that a signed upload still targets a pending, currently fenced attempt.
    async fn authorize_upload(&self, upload_id: UploadId) -> Result<(), ArtifactRepositoryError>;

    /// Records one already-published immutable block idempotently.
    async fn record_block(
        &self,
        request: StageArtifactBlock,
    ) -> Result<(), ArtifactRepositoryError>;

    /// Atomically resolves and commits one ordered block list.
    async fn commit_blocks(
        &self,
        request: CommitArtifactBlocks,
    ) -> Result<crate::CommittedArtifact, ArtifactRepositoryError>;

    /// Loads either the committed blocks or an exact prior publication.
    async fn publication_state(
        &self,
        authority: ExecutionAuthority,
        name: &crate::ArtifactName,
    ) -> Result<ArtifactPublicationState, ArtifactRepositoryError>;

    /// Atomically publishes an immutable manifest or returns the exact prior result.
    async fn finalize(
        &self,
        request: FinalizeArtifact,
    ) -> Result<FinalizeArtifactOutcome, ArtifactRepositoryError>;
}

/// Clock kept outside JWT and repository implementations for deterministic tests.
pub trait ResultsClock: fmt::Debug + Send + Sync {
    /// Returns whole UTC seconds since the Unix epoch.
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

pub(crate) type ArtifactRepositoryPort = Arc<dyn ArtifactRepository>;
pub(crate) type ClockPort = Arc<dyn ResultsClock>;
pub(crate) type IdGeneratorPort = Arc<dyn ResultsIdGenerator>;
