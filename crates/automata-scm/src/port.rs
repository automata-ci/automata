use async_trait::async_trait;
use thiserror::Error;

use crate::{RepositorySnapshot, ScmProviderId, SnapshotRequest};

/// Stable failure class at an SCM trust boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScmErrorKind {
    NotFound,
    Unauthorized,
    Forbidden,
    RateLimited,
    TooLarge,
    Unavailable,
    InvalidResponse,
    Integrity,
}

/// Sanitized SCM failure with optional bounded retry guidance.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("SCM operation failed: {kind:?}")]
pub struct ScmError {
    kind: ScmErrorKind,
    retry_after_seconds: Option<u64>,
}

impl ScmError {
    #[must_use]
    pub const fn new(kind: ScmErrorKind) -> Self {
        Self {
            kind,
            retry_after_seconds: None,
        }
    }

    #[must_use]
    pub const fn rate_limited(retry_after_seconds: Option<u64>) -> Self {
        Self {
            kind: ScmErrorKind::RateLimited,
            retry_after_seconds,
        }
    }

    #[must_use]
    pub const fn kind(self) -> ScmErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn retry_after_seconds(self) -> Option<u64> {
        self.retry_after_seconds
    }
}

/// Resolves and downloads immutable repository snapshots.
///
/// Implementations must resolve mutable names before downloading, enforce the
/// request byte limit incrementally, disable ambient credentials and redirects,
/// and never retain or report credential material.
#[async_trait]
pub trait ScmProvider: std::fmt::Debug + Send + Sync {
    /// Returns the stable adapter identifier.
    fn provider_id(&self) -> &ScmProviderId;

    /// Resolves the requested revision and returns one bounded archive.
    async fn fetch_snapshot(
        &self,
        request: SnapshotRequest<'_>,
    ) -> Result<RepositorySnapshot, ScmError>;
}
