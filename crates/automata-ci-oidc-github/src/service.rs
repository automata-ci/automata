use std::{fmt, sync::Arc};

use thiserror::Error;
use uuid::Uuid;

use crate::{
    JsonWebKeySet, OidcAudience, OidcIdToken, OidcIssuanceRepository, OidcIssuer,
    OidcRepositoryErrorKind, OidcSupportedClaims, OidcTokenId, RequestBearerKeyring,
    ReserveOidcIssuance, Rs256Keyring,
};

/// Maximum lifetime accepted for a workload ID token.
pub const MAXIMUM_ID_TOKEN_LIFETIME_SECONDS: u64 = 3_600;

/// Stable class for a sanitized OIDC minting failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcServiceErrorKind {
    /// The private request credential or current execution authority is invalid.
    Unauthorized,
    /// Durable capacity is currently exhausted.
    ResourceExhausted,
    /// The durable provider is temporarily unavailable.
    Unavailable,
    /// A cryptographic, configuration, or durable invariant failed closed.
    Internal,
}

/// Sanitized OIDC minting failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("OIDC token minting failed: {kind:?}")]
pub struct OidcServiceError {
    kind: OidcServiceErrorKind,
}

impl OidcServiceError {
    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> OidcServiceErrorKind {
        self.kind
    }

    const fn new(kind: OidcServiceErrorKind) -> Self {
        Self { kind }
    }
}

/// Validated maximum lifetime for newly reserved workload ID tokens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OidcTokenLifetime(u64);

impl OidcTokenLifetime {
    /// Creates a nonzero lifetime no greater than one hour.
    ///
    /// # Errors
    ///
    /// Rejects zero or a value above [`MAXIMUM_ID_TOKEN_LIFETIME_SECONDS`].
    pub const fn from_seconds(seconds: u64) -> Result<Self, OidcTokenLifetimeError> {
        if seconds == 0 || seconds > MAXIMUM_ID_TOKEN_LIFETIME_SECONDS {
            return Err(OidcTokenLifetimeError);
        }
        Ok(Self(seconds))
    }

    /// Returns the configured lifetime in seconds.
    #[must_use]
    pub const fn seconds(self) -> u64 {
        self.0
    }
}

/// Invalid workload ID-token lifetime.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("OIDC ID-token lifetime is invalid")]
pub struct OidcTokenLifetimeError;

/// Authenticates private requests, atomically reserves claims, and signs tokens.
///
/// The repository remains the sole authority for subjects, default audiences,
/// additional claims, current execution lifecycle, and the final durable
/// expiry cap. This service contributes only credential authentication, a
/// bounded lifetime, a fresh proposal identity, and the configured RS256 key.
#[derive(Clone)]
pub struct OidcService {
    issuer: OidcIssuer,
    supported_claims: OidcSupportedClaims,
    token_lifetime: OidcTokenLifetime,
    request_bearers: Arc<RequestBearerKeyring>,
    signing_keys: Arc<Rs256Keyring>,
    repository: Arc<dyn OidcIssuanceRepository>,
}

impl OidcService {
    /// Composes the isolated OIDC service from explicit authority boundaries.
    #[must_use]
    pub fn new(
        issuer: OidcIssuer,
        supported_claims: OidcSupportedClaims,
        token_lifetime: OidcTokenLifetime,
        request_bearers: Arc<RequestBearerKeyring>,
        signing_keys: Arc<Rs256Keyring>,
        repository: Arc<dyn OidcIssuanceRepository>,
    ) -> Self {
        Self {
            issuer,
            supported_claims,
            token_lifetime,
            request_bearers,
            signing_keys,
            repository,
        }
    }

    /// Returns the exact configured workload-token issuer.
    #[must_use]
    pub const fn issuer(&self) -> &OidcIssuer {
        &self.issuer
    }

    /// Returns the exact claim names published in provider discovery.
    #[must_use]
    pub const fn supported_claims(&self) -> &OidcSupportedClaims {
        &self.supported_claims
    }

    /// Returns all currently accepted public verification keys.
    #[must_use]
    pub fn jwks(&self) -> JsonWebKeySet {
        self.signing_keys.jwks()
    }

    /// Authenticates and mints one default- or caller-audience ID token.
    ///
    /// `observed_at_seconds` must come from a trusted server clock, never an
    /// HTTP field. Request-bearer expiry and the service lifetime are both
    /// upper bounds; the durable repository may shorten them further and must
    /// return fresh current-authorization evidence for this call.
    ///
    /// # Errors
    ///
    /// Returns only a stable sanitized failure class. Credential, subject,
    /// audience, claim, signing, and provider text is never retained.
    pub async fn mint(
        &self,
        request_bearer: &str,
        requested_audience: Option<OidcAudience>,
        observed_at_seconds: u64,
    ) -> Result<OidcIdToken, OidcServiceError> {
        let verified = self
            .request_bearers
            .verify(request_bearer, observed_at_seconds)
            .map_err(|_| OidcServiceError::new(OidcServiceErrorKind::Unauthorized))?;
        if verified.issued_at_seconds() > observed_at_seconds
            || verified.expires_at_seconds() <= observed_at_seconds
        {
            return Err(OidcServiceError::new(OidcServiceErrorKind::Unauthorized));
        }
        let service_deadline = observed_at_seconds
            .checked_add(self.token_lifetime.seconds())
            .ok_or_else(|| OidcServiceError::new(OidcServiceErrorKind::Internal))?;
        let maximum_expires_at_seconds = verified.expires_at_seconds().min(service_deadline);
        if maximum_expires_at_seconds <= observed_at_seconds {
            return Err(OidcServiceError::new(OidcServiceErrorKind::Unauthorized));
        }
        let proposed_token_id = OidcTokenId::from_uuid(Uuid::new_v4())
            .map_err(|_| OidcServiceError::new(OidcServiceErrorKind::Internal))?;
        let request = ReserveOidcIssuance::new(
            verified.authority_id(),
            requested_audience.clone(),
            verified.issued_at_seconds(),
            verified.expires_at_seconds(),
            observed_at_seconds,
            maximum_expires_at_seconds,
            proposed_token_id,
            self.signing_keys.active_key_id().clone(),
        );
        let authorized = self
            .repository
            .reserve(request)
            .await
            .map_err(map_repository_error)?;
        let authorized_at_seconds = authorized.authorized_at_seconds();
        let issuance = authorized.issuance();
        let valid_result = authorized_at_seconds >= observed_at_seconds
            && issuance.authority_id() == verified.authority_id()
            && requested_audience
                .as_ref()
                .is_none_or(|audience| issuance.audience() == audience)
            && issuance.issued_at_seconds() >= verified.issued_at_seconds()
            && issuance.issued_at_seconds() <= authorized_at_seconds
            && issuance.not_before_seconds() >= verified.issued_at_seconds()
            && issuance.not_before_seconds() <= authorized_at_seconds
            && issuance.expires_at_seconds() > authorized_at_seconds
            && issuance.expires_at_seconds() <= maximum_expires_at_seconds
            && issuance
                .expires_at_seconds()
                .checked_sub(issuance.issued_at_seconds())
                .is_some_and(|lifetime| lifetime <= self.token_lifetime.seconds())
            && self.signing_keys.contains_key(issuance.signing_key_id())
            && issuance
                .additional_claims()
                .as_map()
                .keys()
                .all(|name| self.supported_claims.supports_additional(name));
        if !valid_result {
            return Err(OidcServiceError::new(OidcServiceErrorKind::Internal));
        }
        self.signing_keys
            .sign(&self.issuer, issuance)
            .map_err(|_| OidcServiceError::new(OidcServiceErrorKind::Internal))
    }
}

impl fmt::Debug for OidcService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcService")
            .field("issuer", &self.issuer)
            .field("supported_claims", &self.supported_claims)
            .field("token_lifetime", &self.token_lifetime)
            .field("request_bearers", &self.request_bearers)
            .field("signing_keys", &self.signing_keys)
            .field("repository", &"[injected]")
            .finish()
    }
}

const fn map_repository_error(error: crate::OidcRepositoryError) -> OidcServiceError {
    let kind = match error.kind() {
        OidcRepositoryErrorKind::Unauthorized => OidcServiceErrorKind::Unauthorized,
        OidcRepositoryErrorKind::ResourceExhausted => OidcServiceErrorKind::ResourceExhausted,
        OidcRepositoryErrorKind::Unavailable => OidcServiceErrorKind::Unavailable,
        OidcRepositoryErrorKind::Conflict | OidcRepositoryErrorKind::CorruptData => {
            OidcServiceErrorKind::Internal
        }
    };
    OidcServiceError::new(kind)
}
