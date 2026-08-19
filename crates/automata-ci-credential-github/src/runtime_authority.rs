use std::fmt;

use automata_ci_auth::{secret::SecretString, time::UnixTimestamp};
use automata_ci_provider::ProviderPermissionSet;
use automata_ci_store::GithubRepositoryName;
use thiserror::Error;

const MAX_TOKEN_BYTES: usize = 16 * 1_024;
const MAX_TOKEN_VALIDITY_MILLIS: u64 = 3_600_000;

/// Exact GitHub installation-token request used by both control and workload
/// issuance. It contains only the provider-native audience and permissions;
/// durable callers bind it to their own immutable authority evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubInstallationTokenRequest {
    repository_id: u64,
    repository_name: GithubRepositoryName,
    permissions: ProviderPermissionSet,
    minimum_validity_millis: u64,
}

impl GithubInstallationTokenRequest {
    /// Creates one bounded repository-scoped request.
    ///
    /// # Errors
    ///
    /// Rejects zero repositories, empty permissions, and invalid validity.
    pub fn new(
        repository_id: u64,
        repository_name: GithubRepositoryName,
        permissions: ProviderPermissionSet,
        minimum_validity_millis: u64,
    ) -> Result<Self, GithubInstallationTokenRequestError> {
        if repository_id == 0
            || permissions.is_empty()
            || minimum_validity_millis == 0
            || minimum_validity_millis > MAX_TOKEN_VALIDITY_MILLIS
        {
            return Err(GithubInstallationTokenRequestError);
        }
        Ok(Self {
            repository_id,
            repository_name,
            permissions,
            minimum_validity_millis,
        })
    }

    /// Returns the numeric repository audience.
    #[must_use]
    pub const fn repository_id(&self) -> u64 {
        self.repository_id
    }
    /// Returns the exact owner/repository path.
    #[must_use]
    pub const fn repository_name(&self) -> &GithubRepositoryName {
        &self.repository_name
    }
    /// Returns the complete canonical permission set.
    #[must_use]
    pub const fn permissions(&self) -> &ProviderPermissionSet {
        &self.permissions
    }
    /// Returns the required remaining lifetime after issuance.
    #[must_use]
    pub const fn minimum_validity_millis(&self) -> u64 {
        self.minimum_validity_millis
    }
}

/// Invalid GitHub installation-token request evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub installation-token request is invalid")]
pub struct GithubInstallationTokenRequestError;

/// Closed failure classification for one GitHub installation-token attempt.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubInstallationTokenErrorKind {
    /// The request cannot be represented by GitHub.
    #[error("GitHub installation-token request is invalid")]
    InvalidRequest,
    /// GitHub rejected App authentication.
    #[error("GitHub installation-token authentication failed")]
    Unauthorized,
    /// GitHub rejected the requested authority.
    #[error("GitHub installation-token authorization failed")]
    Forbidden,
    /// The repository does not exist for the installation.
    #[error("GitHub installation-token repository was not found")]
    NotFound,
    /// GitHub requested bounded backoff.
    #[error("GitHub installation-token mint was rate limited")]
    RateLimited,
    /// The provider is temporarily unavailable.
    #[error("GitHub installation-token provider is unavailable")]
    Unavailable,
    /// The response violated the protocol.
    #[error("GitHub installation-token response is invalid")]
    InvalidResponse,
    /// The response selected a different repository.
    #[error("GitHub installation-token repository mismatched")]
    RepositoryMismatch,
    /// The response selected different permissions.
    #[error("GitHub installation-token permissions mismatched")]
    PermissionMismatch,
    /// The response cannot satisfy the requested lifetime.
    #[error("GitHub installation-token validity is insufficient")]
    Expired,
}

/// Sanitized failure from one definitive GitHub token attempt.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub installation-token mint failed: {kind}")]
pub struct GithubInstallationTokenError {
    kind: GithubInstallationTokenErrorKind,
    retry_after_seconds: Option<u64>,
}

impl GithubInstallationTokenError {
    pub(crate) const fn new(kind: GithubInstallationTokenErrorKind) -> Self {
        Self {
            kind,
            retry_after_seconds: None,
        }
    }
    pub(crate) const fn rate_limited(retry_after_seconds: Option<u64>) -> Self {
        Self {
            kind: GithubInstallationTokenErrorKind::RateLimited,
            retry_after_seconds,
        }
    }
    /// Returns the closed failure kind.
    #[must_use]
    pub const fn kind(self) -> GithubInstallationTokenErrorKind {
        self.kind
    }
    /// Returns the bounded provider retry hint.
    #[must_use]
    pub const fn retry_after_seconds(self) -> Option<u64> {
        self.retry_after_seconds
    }
}

/// A uniquely recovered GitHub installation token that still needs revocation.
///
/// The value is move-only, cannot be serialized, is redacted from diagnostics,
/// and is zeroized by [`SecretString`] when dropped. Callers should retain it in
/// protected durable state until GitHub confirms revocation or the provider
/// expiration has passed.
pub struct GithubInstallationTokenRevocationCandidate {
    secret: SecretString,
}

impl GithubInstallationTokenRevocationCandidate {
    pub(crate) const fn new(secret: SecretString) -> Self {
        Self { secret }
    }

    /// Restores a candidate from a protected durable secret envelope.
    ///
    /// # Errors
    ///
    /// Rejects a value that cannot be sent as one bounded bearer credential.
    pub fn from_protected_secret(
        secret: SecretString,
    ) -> Result<Self, GithubInstallationTokenCandidateError> {
        let value = secret.expose_secret();
        if value.len() > MAX_TOKEN_BYTES || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(GithubInstallationTokenCandidateError);
        }
        Ok(Self { secret })
    }

    /// Explicitly crosses the secret boundary for protected persistence or the
    /// installation-token revocation request.
    #[must_use]
    pub const fn secret(&self) -> &SecretString {
        &self.secret
    }

    pub(crate) fn into_secret(self) -> SecretString {
        self.secret
    }
}

/// A protected value is not a syntactically usable GitHub bearer token.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("protected GitHub installation-token candidate is invalid")]
pub struct GithubInstallationTokenCandidateError;

impl fmt::Debug for GithubInstallationTokenRevocationCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GithubInstallationTokenRevocationCandidate([REDACTED])")
    }
}

/// A semantically validated token and its exact non-secret validity metadata.
///
/// This value deliberately remains move-only. A durable issuer must first use
/// the borrowed secret and metadata to prepare its protected record, then make
/// exactly one terminal choice: transfer custody to the protected handoff
/// after a successful finalize CAS, or consume it into a revocation candidate
/// when the finalize loses its fence.
pub struct GithubReadyInstallationToken {
    candidate: GithubInstallationTokenRevocationCandidate,
    request: GithubInstallationTokenRequest,
    issued_at: UnixTimestamp,
    provider_expires_at: UnixTimestamp,
    conservative_expires_at: UnixTimestamp,
    installation_id: u64,
}

impl GithubReadyInstallationToken {
    pub(crate) const fn new(
        candidate: GithubInstallationTokenRevocationCandidate,
        request: GithubInstallationTokenRequest,
        issued_at: UnixTimestamp,
        provider_expires_at: UnixTimestamp,
        conservative_expires_at: UnixTimestamp,
        installation_id: u64,
    ) -> Self {
        Self {
            candidate,
            request,
            issued_at,
            provider_expires_at,
            conservative_expires_at,
            installation_id,
        }
    }

    /// Explicitly crosses the secret boundary for protected durable encoding.
    #[must_use]
    pub const fn secret(&self) -> &SecretString {
        self.candidate.secret()
    }

    #[must_use]
    /// Returns the exact repository, permission, and minimum-validity request.
    pub const fn request(&self) -> &GithubInstallationTokenRequest {
        &self.request
    }

    #[must_use]
    /// Returns when the validated mint response was processed locally.
    pub const fn issued_at(&self) -> UnixTimestamp {
        self.issued_at
    }

    /// Provider-declared absolute expiration.
    #[must_use]
    pub const fn provider_expires_at(&self) -> UnixTimestamp {
        self.provider_expires_at
    }

    /// Conservative local use horizon, including the provider clock-skew margin.
    #[must_use]
    pub const fn conservative_expires_at(&self) -> UnixTimestamp {
        self.conservative_expires_at
    }

    /// Returns the exact installation that minted the token.
    #[must_use]
    pub const fn installation_id(&self) -> u64 {
        self.installation_id
    }

    /// Consumes the token for revocation after a durable finalize loses its fence.
    #[must_use]
    pub fn into_revocation_candidate(self) -> GithubInstallationTokenRevocationCandidate {
        self.candidate
    }
}

impl fmt::Debug for GithubReadyInstallationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubReadyInstallationToken")
            .field("candidate", &self.candidate)
            .field("request", &self.request)
            .field("issued_at", &self.issued_at)
            .field("provider_expires_at", &self.provider_expires_at)
            .field("conservative_expires_at", &self.conservative_expires_at)
            .field("installation_id", &self.installation_id)
            .finish()
    }
}

/// A recovered token whose response failed semantic validation and must be
/// revoked before the issuance can be reconciled.
pub struct GithubInstallationTokenRevokePending {
    candidate: GithubInstallationTokenRevocationCandidate,
    reason: GithubInstallationTokenError,
    provider_expires_at: Option<UnixTimestamp>,
    conservative_expires_at: Option<UnixTimestamp>,
}

impl GithubInstallationTokenRevokePending {
    pub(crate) const fn new(
        candidate: GithubInstallationTokenRevocationCandidate,
        reason: GithubInstallationTokenError,
        provider_expires_at: Option<UnixTimestamp>,
        conservative_expires_at: Option<UnixTimestamp>,
    ) -> Self {
        Self {
            candidate,
            reason,
            provider_expires_at,
            conservative_expires_at,
        }
    }

    #[must_use]
    /// Borrows the recovered token that must be retained pending revocation.
    pub const fn candidate(&self) -> &GithubInstallationTokenRevocationCandidate {
        &self.candidate
    }

    #[must_use]
    /// Returns the sanitized semantic reason the token was not issuable.
    pub const fn reason(&self) -> GithubInstallationTokenError {
        self.reason
    }

    /// Provider expiration when it was independently recoverable and valid.
    #[must_use]
    pub const fn provider_expires_at(&self) -> Option<UnixTimestamp> {
        self.provider_expires_at
    }

    /// Conservative use horizon when it was independently recoverable.
    #[must_use]
    pub const fn conservative_expires_at(&self) -> Option<UnixTimestamp> {
        self.conservative_expires_at
    }

    #[must_use]
    /// Consumes the lifecycle value and returns its revocation candidate.
    pub fn into_candidate(self) -> GithubInstallationTokenRevocationCandidate {
        self.candidate
    }
}

impl fmt::Debug for GithubInstallationTokenRevokePending {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubInstallationTokenRevokePending")
            .field("candidate", &"[REDACTED]")
            .field("reason", &self.reason)
            .field("provider_expires_at", &self.provider_expires_at)
            .field("conservative_expires_at", &self.conservative_expires_at)
            .finish()
    }
}

/// Why GitHub may have created a token but no unique token can be recovered.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubInstallationTokenIndeterminateReason {
    /// The request or response transport failed after a mint may have reached GitHub.
    #[error("GitHub installation-token transport outcome is indeterminate")]
    Transport,
    /// GitHub returned a server failure after the mint request was submitted.
    #[error("GitHub installation-token provider outcome is indeterminate")]
    ProviderUnavailable,
    /// A created response exceeded the configured response-byte ceiling.
    #[error("GitHub installation-token response exceeded its byte limit")]
    ResponseTooLarge,
    /// Reading a created response ended before its body completed.
    #[error("GitHub installation-token response was truncated")]
    TruncatedResponse,
    /// A created body could not yield one syntactically valid token.
    #[error("GitHub installation-token response was malformed")]
    MalformedResponse,
    /// A complete created response contained no token field.
    #[error("GitHub installation-token response did not contain a recoverable token")]
    MissingToken,
    /// A created response contained duplicate token fields.
    #[error("GitHub installation-token response contained ambiguous tokens")]
    AmbiguousToken,
    /// GitHub returned a status that neither proves rejection nor recovers a token.
    #[error("GitHub installation-token response status was ambiguous")]
    UnexpectedStatus,
}

/// Provider-side mint outcome requiring durable operator reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubInstallationTokenIndeterminate {
    reason: GithubInstallationTokenIndeterminateReason,
}

impl GithubInstallationTokenIndeterminate {
    pub(crate) const fn new(reason: GithubInstallationTokenIndeterminateReason) -> Self {
        Self { reason }
    }

    #[must_use]
    /// Returns the sanitized reason this mint must not be retried automatically.
    pub const fn reason(self) -> GithubInstallationTokenIndeterminateReason {
        self.reason
    }
}

/// Complete result of exactly one GitHub installation-token mint attempt.
///
/// This enum is intentionally not `Clone` or serializable. Every variant maps
/// directly to a durable lifecycle transition; callers must never retry a mint
/// after [`Self::Indeterminate`].
#[must_use]
#[derive(Debug)]
pub enum GithubInstallationTokenMintOutcome {
    /// One token exactly matched the requested repository, permissions, and validity.
    Ready(GithubReadyInstallationToken),
    /// One token was recovered but failed validation and must be revoked or expire.
    RevokePending(GithubInstallationTokenRevokePending),
    /// GitHub may have minted a token, but no unique candidate can be recovered.
    Indeterminate(GithubInstallationTokenIndeterminate),
    /// The request was definitively rejected before an unknown token could exist.
    Rejected(GithubInstallationTokenError),
}

/// Sanitized classification of an unconfirmed token-revocation attempt.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubInstallationTokenRevocationFailureKind {
    /// GitHub rejected authorization but did not prove that the token is gone.
    #[error("GitHub did not confirm installation-token revocation")]
    Unauthorized,
    /// GitHub requested that revocation attempts be rate limited.
    #[error("GitHub rate-limited installation-token revocation")]
    RateLimited,
    /// Transport or provider availability prevented revocation confirmation.
    #[error("GitHub installation-token revocation is temporarily unavailable")]
    Retryable,
    /// GitHub returned a response that cannot confirm revocation.
    #[error("GitHub returned an invalid installation-token revocation response")]
    InvalidResponse,
}

/// A revocation failure that retains the caller-owned token candidate.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("installation-token revocation was not confirmed: {kind}")]
pub struct GithubInstallationTokenRevocationFailure {
    kind: GithubInstallationTokenRevocationFailureKind,
    retry_after_seconds: Option<u64>,
}

impl GithubInstallationTokenRevocationFailure {
    pub(crate) const fn new(kind: GithubInstallationTokenRevocationFailureKind) -> Self {
        Self {
            kind,
            retry_after_seconds: None,
        }
    }

    pub(crate) const fn rate_limited(retry_after_seconds: Option<u64>) -> Self {
        Self {
            kind: GithubInstallationTokenRevocationFailureKind::RateLimited,
            retry_after_seconds,
        }
    }

    #[must_use]
    /// Returns the closed, sanitized failure classification.
    pub const fn kind(self) -> GithubInstallationTokenRevocationFailureKind {
        self.kind
    }

    #[must_use]
    /// Returns a bounded provider retry delay when exactly one valid hint existed.
    pub const fn retry_after_seconds(self) -> Option<u64> {
        self.retry_after_seconds
    }

    /// Unauthorized responses remain retry/retain-until-expiry outcomes because
    /// GitHub has not confirmed that this exact token was revoked.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(
            self.kind,
            GithubInstallationTokenRevocationFailureKind::Unauthorized
                | GithubInstallationTokenRevocationFailureKind::RateLimited
                | GithubInstallationTokenRevocationFailureKind::Retryable
        )
    }
}

/// Result of one revocation request. Only `Confirmed` permits secret erasure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubInstallationTokenRevocationOutcome {
    /// GitHub returned `204 No Content`; the candidate may now be erased.
    Confirmed,
    /// Revocation was not proven; the candidate must be retained for retry or expiry.
    Unconfirmed(GithubInstallationTokenRevocationFailure),
}
