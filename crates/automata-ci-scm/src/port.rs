use async_trait::async_trait;
use thiserror::Error;

use crate::{
    RepositorySnapshot, RepositorySourceArchive, RepositorySourceRequest, ScmProviderId,
    SnapshotRequest,
};

/// Stable failure class at an SCM trust boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScmErrorKind {
    /// The requested repository or revision does not exist or is not visible.
    NotFound,
    /// The provider rejected missing, expired, or otherwise invalid authentication.
    Unauthorized,
    /// The authenticated principal is not permitted to perform the operation.
    Forbidden,
    /// The provider has temporarily exhausted an applicable request quota.
    RateLimited,
    /// The archive exceeds the caller's byte ceiling.
    TooLarge,
    /// The provider or its transport is temporarily unavailable.
    Unavailable,
    /// The provider returned malformed, unsafe, or contract-incompatible data.
    InvalidResponse,
    /// The returned archive failed an integrity check.
    Integrity,
}

/// Sanitized SCM failure with optional numeric retry guidance.
///
/// This type contains only a closed failure class and, for rate limits, an
/// optional delay. It never retains response bodies, URLs, repository names,
/// revision text, or credential material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("SCM operation failed: {kind:?}")]
pub struct ScmError {
    kind: ScmErrorKind,
    retry_after_seconds: Option<u64>,
}

impl ScmError {
    /// Creates a sanitized failure without retry-delay guidance.
    #[must_use]
    pub const fn new(kind: ScmErrorKind) -> Self {
        Self {
            kind,
            retry_after_seconds: None,
        }
    }

    /// Creates a rate-limit failure with provider-supplied delay guidance.
    ///
    /// `None` means the provider supplied no valid delay. Callers must still
    /// apply their bounded retry policy rather than retrying immediately or
    /// indefinitely.
    #[must_use]
    pub const fn rate_limited(retry_after_seconds: Option<u64>) -> Self {
        Self {
            kind: ScmErrorKind::RateLimited,
            retry_after_seconds,
        }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> ScmErrorKind {
        self.kind
    }

    /// Returns provider retry-delay guidance in seconds, when present.
    ///
    /// Constructors expose a delay only for [`ScmErrorKind::RateLimited`]. The
    /// value is guidance, not authorization for an unbounded retry loop.
    #[must_use]
    pub const fn retry_after_seconds(self) -> Option<u64> {
        self.retry_after_seconds
    }
}

/// Resolves and downloads immutable repository snapshots.
///
/// Implementations must resolve mutable names before downloading, enforce the
/// request byte limit incrementally, disable ambient credential discovery and
/// automatic redirects, and never retain or report credential material. If a
/// provider protocol uses redirects, the adapter must inspect the response,
/// validate the destination against its configured trust policy, and avoid
/// forwarding credentials to that destination.
#[async_trait]
pub trait ScmProvider: std::fmt::Debug + Send + Sync {
    /// Returns the stable identifier used to select and record this adapter.
    fn provider_id(&self) -> &ScmProviderId;

    /// Resolves the requested revision and returns one bounded archive.
    ///
    /// The returned snapshot must record both the original selector and a
    /// provider-proven immutable revision, and its digest must cover the exact
    /// returned bytes.
    ///
    /// # Errors
    ///
    /// Returns a sanitized [`ScmError`] when resolution, authorization,
    /// download, response validation, size enforcement, or integrity checking
    /// fails.
    async fn fetch_snapshot(
        &self,
        request: SnapshotRequest<'_>,
    ) -> Result<RepositorySnapshot, ScmError>;
}

/// Fetches repository source only at a caller-supplied exact revision.
///
/// Implementations have no authority to resolve a mutable selector. They must
/// ask the provider for the requested exact revision, prove that the provider's
/// resolved commit is byte-for-byte equal to it before downloading source,
/// enforce the request byte limit incrementally, disable ambient credentials
/// and automatic redirects, and never retain or report credential material.
#[async_trait]
pub trait RepositorySource: std::fmt::Debug + Send + Sync {
    /// Returns one bounded archive proven to represent the requested revision.
    ///
    /// This operation must fail closed when provider revision evidence is
    /// absent, malformed, noncanonical, or unequal to the requested exact
    /// revision. It must not fall back to branch, tag, default-branch, or other
    /// mutable-selector resolution.
    ///
    /// # Errors
    ///
    /// Returns a sanitized [`ScmError`] when exact-revision proof,
    /// authorization, download, response validation, size enforcement, or
    /// integrity checking fails.
    async fn fetch_repository_source(
        &self,
        request: RepositorySourceRequest<'_>,
    ) -> Result<RepositorySourceArchive, ScmError>;
}
