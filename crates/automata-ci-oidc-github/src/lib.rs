#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Current GitHub Actions-compatible workload OIDC protocol foundation.
//!
//! Product integration is intentionally outside this crate. Callers must
//! provide a durable repository that authenticates current execution authority
//! before any token is minted.

/// Maximum number of simultaneously loaded keys in either OIDC keyring.
pub const MAXIMUM_OIDC_KEYS_PER_KEYRING: usize = 16;

/// Stable namespace for an optional GitHub-compatible OIDC runtime-authority contribution.
///
/// This crate defines the identifier only; runner-control and environment
/// composition remain separate integration boundaries.
pub const GITHUB_OIDC_RUNTIME_AUTHORITY_NAMESPACE: &str = "github-oidc";

mod bearer;
mod http;
mod keys;
mod model;
mod repository;
mod service;

pub use bearer::{
    MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS, MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS,
    OidcRequestBearer, RequestBearerConfig, RequestBearerError, RequestBearerKey,
    RequestBearerKeyring, VerifiedRequestBearer,
};
pub use http::{
    GithubOidcApi, OIDC_DISCOVERY_PATH, OIDC_JWKS_CACHE_SECONDS, OIDC_JWKS_PATH, OIDC_TOKEN_PATH,
    OIDC_TOKEN_REQUEST_PATH_AND_QUERY, OidcClock, OidcClockError, SystemOidcClock,
};
pub use keys::{
    JsonWebKeySet, OidcIdToken, Rs256KeyError, Rs256Keyring, Rs256SigningKey, RsaPublicJwk,
};
pub use model::{
    AuthorizedOidcAuthority, AuthorizedOidcIssuance, MAXIMUM_ADDITIONAL_CLAIM_BYTES,
    MAXIMUM_ADDITIONAL_CLAIMS, MAXIMUM_OIDC_PRINCIPAL_BYTES, MAXIMUM_SUPPORTED_ADDITIONAL_CLAIMS,
    OidcAudience, OidcAuthorityId, OidcClaimSet, OidcIssuance, OidcIssuer, OidcKeyId,
    OidcModelError, OidcSubject, OidcSupportedClaims, OidcTokenId, ReserveOidcIssuance,
};
pub use repository::{
    InMemoryOidcRepository, InMemoryOidcRepositoryLimits, InMemoryOidcRepositoryLimitsError,
    OidcIssuanceRepository, OidcRepositoryError, OidcRepositoryErrorKind,
};
pub use service::{
    MAXIMUM_ID_TOKEN_LIFETIME_SECONDS, OidcService, OidcServiceError, OidcServiceErrorKind,
    OidcTokenLifetime, OidcTokenLifetimeError,
};
