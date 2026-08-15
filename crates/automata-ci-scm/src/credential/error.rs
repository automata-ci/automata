use thiserror::Error;

/// Stable failure classification at a credential-provider trust boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialErrorKind {
    /// The broker does not serve the request's source-control provider.
    UnsupportedProvider,
    /// The request or broker configuration cannot be translated into a safe
    /// provider operation.
    InvalidRequest,
    /// The provider rejected the broker's own authentication.
    Unauthorized,
    /// The provider recognized the broker but denied the requested operation.
    Forbidden,
    /// The exact provider resource was absent or deliberately not disclosed.
    NotFound,
    /// The provider refused the operation because a quota was exhausted.
    RateLimited,
    /// A provider or another prerequisite required for issuance was
    /// temporarily unavailable.
    Unavailable,
    /// The provider response could not be interpreted safely and completely.
    InvalidResponse,
    /// The provider's response was not bound to the exact requested repository.
    RepositoryMismatch,
    /// The provider granted a permission set other than the exact requested set.
    PermissionMismatch,
    /// The returned credential did not meet the requested validity floor.
    Expired,
}

/// Sanitized credential failure with optional provider retry guidance.
///
/// Provider response bodies, credentials, assertions, and key material are never
/// retained in this error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("repository credential operation failed: {kind:?}")]
pub struct CredentialError {
    kind: CredentialErrorKind,
    retry_after_seconds: Option<u64>,
}

impl CredentialError {
    /// Creates a sanitized failure without provider-supplied retry guidance.
    ///
    /// Provider response bodies and diagnostic text are intentionally not
    /// accepted, keeping the error safe to record in logs and metrics.
    #[must_use]
    pub const fn new(kind: CredentialErrorKind) -> Self {
        Self {
            kind,
            retry_after_seconds: None,
        }
    }

    /// Creates a rate-limit failure with optional provider retry timing.
    ///
    /// The delay is provider guidance, not proof that replaying a side-effectful
    /// issuance operation is idempotent.
    #[must_use]
    pub const fn rate_limited(retry_after_seconds: Option<u64>) -> Self {
        Self {
            kind: CredentialErrorKind::RateLimited,
            retry_after_seconds,
        }
    }

    /// Returns the stable, provider-neutral failure classification.
    #[must_use]
    pub const fn kind(self) -> CredentialErrorKind {
        self.kind
    }

    /// Returns provider retry guidance in seconds, when it was available.
    ///
    /// This field is populated only by [`Self::rate_limited`]. Callers must
    /// still apply their own retry budget and operation-safety policy.
    #[must_use]
    pub const fn retry_after_seconds(self) -> Option<u64> {
        self.retry_after_seconds
    }
}
