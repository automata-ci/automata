use thiserror::Error;

/// Stable failure classification at a credential-provider trust boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialErrorKind {
    UnsupportedProvider,
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    Unavailable,
    InvalidResponse,
    RepositoryMismatch,
    PermissionMismatch,
    Expired,
}

/// Sanitized credential failure with optional bounded retry guidance.
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
    #[must_use]
    pub const fn new(kind: CredentialErrorKind) -> Self {
        Self {
            kind,
            retry_after_seconds: None,
        }
    }

    #[must_use]
    pub const fn rate_limited(retry_after_seconds: Option<u64>) -> Self {
        Self {
            kind: CredentialErrorKind::RateLimited,
            retry_after_seconds,
        }
    }

    #[must_use]
    pub const fn kind(self) -> CredentialErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn retry_after_seconds(self) -> Option<u64> {
        self.retry_after_seconds
    }
}
