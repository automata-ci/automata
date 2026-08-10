use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use thiserror::Error;
use url::Url;
use uuid::Uuid;

/// Maximum encoded bytes in one OIDC audience or subject.
pub const MAXIMUM_OIDC_PRINCIPAL_BYTES: usize = 2_048;
/// Maximum additional identity claims in one ID token.
pub const MAXIMUM_ADDITIONAL_CLAIMS: usize = 32;
/// Maximum aggregate bytes across additional claim names and values.
pub const MAXIMUM_ADDITIONAL_CLAIM_BYTES: usize = 16 * 1_024;
/// Maximum configured additional claim names advertised in discovery.
pub const MAXIMUM_SUPPORTED_ADDITIONAL_CLAIMS: usize = 64;

const MAXIMUM_CLAIM_NAME_BYTES: usize = 64;
const MAXIMUM_CLAIM_VALUE_BYTES: usize = 2_048;
const MAXIMUM_KEY_ID_BYTES: usize = 128;
const RESERVED_CLAIMS: [&str; 7] = ["aud", "exp", "iat", "iss", "jti", "nbf", "sub"];
const REGISTERED_CLAIM_ORDER: [&str; 7] = ["sub", "aud", "exp", "iat", "iss", "jti", "nbf"];
const MAXIMUM_SUPPORTED_CLAIM_NAME_BYTES: usize = 4 * 1_024;

/// A sanitized current-model validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OidcModelError {
    /// The issuer is not one exact HTTPS root origin.
    #[error("OIDC issuer is invalid")]
    InvalidIssuer,
    /// An opaque identifier is nil or otherwise invalid.
    #[error("OIDC identifier is invalid")]
    InvalidIdentifier,
    /// An audience is empty, contains controls, or exceeds its byte bound.
    #[error("OIDC audience is invalid")]
    InvalidAudience,
    /// A subject is empty, contains controls, or exceeds its byte bound.
    #[error("OIDC subject is invalid")]
    InvalidSubject,
    /// An additional claim name or value violates the current string contract.
    #[error("OIDC additional claim is invalid")]
    InvalidClaim,
    /// The additional claim count or aggregate byte bound was exceeded.
    #[error("OIDC additional claim set exceeds its bound")]
    TooManyClaims,
    /// A validity interval is empty, inverted, or otherwise invalid.
    #[error("OIDC validity interval is invalid")]
    InvalidTime,
    /// A signing key identifier is outside its syntax or byte bound.
    #[error("OIDC signing key identifier is invalid")]
    InvalidKeyId,
}

/// Exact HTTPS root origin used as Automata's workload token issuer.
#[derive(Clone, Eq, PartialEq)]
pub struct OidcIssuer(Url);

impl OidcIssuer {
    /// Validates an HTTPS root URL without credentials, query, or fragment.
    ///
    /// # Errors
    ///
    /// Returns [`OidcModelError::InvalidIssuer`] for any non-root or non-HTTPS
    /// URL. Plaintext development listeners do not change the signed issuer.
    pub fn https(url: Url) -> Result<Self, OidcModelError> {
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(OidcModelError::InvalidIssuer);
        }
        Ok(Self(url))
    }

    /// Returns the exact issuer URL placed in discovery and tokens.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Returns the exact issuer URL.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.0
    }
}

impl fmt::Debug for OidcIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("OidcIssuer")
            .field(&self.0.as_str())
            .finish()
    }
}

/// Validated OIDC audience selected by durable authority or the caller.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct OidcAudience(String);

impl OidcAudience {
    /// Creates a nonempty, control-free audience bounded to 2 KiB.
    ///
    /// # Errors
    ///
    /// Rejects empty or whitespace-only values, controls, and oversized input.
    pub fn new(value: impl Into<String>) -> Result<Self, OidcModelError> {
        let value = value.into();
        if value.is_empty()
            || value.trim().is_empty()
            || value.len() > MAXIMUM_OIDC_PRINCIPAL_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(OidcModelError::InvalidAudience);
        }
        Ok(Self(value))
    }

    /// Returns the audience string used in the `aud` claim.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OidcAudience {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OidcAudience([redacted])")
    }
}

/// Opaque subject whose exact format is owned by authenticated durable policy.
#[derive(Clone, Eq, PartialEq)]
pub struct OidcSubject(String);

impl OidcSubject {
    /// Creates a nonempty, control-free subject bounded to 2 KiB.
    ///
    /// # Errors
    ///
    /// Rejects empty or whitespace-only values, controls, and oversized input.
    pub fn new(value: impl Into<String>) -> Result<Self, OidcModelError> {
        let value = value.into();
        if value.is_empty()
            || value.trim().is_empty()
            || value.len() > MAXIMUM_OIDC_PRINCIPAL_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(OidcModelError::InvalidSubject);
        }
        Ok(Self(value))
    }

    /// Returns the exact value placed in the `sub` claim.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OidcSubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OidcSubject([redacted])")
    }
}

/// ASCII key identifier used in compact JWT headers and JWKS.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct OidcKeyId(String);

impl OidcKeyId {
    /// Validates a portable `kid` containing ASCII letters, digits, `.`, `_`, or `-`.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or non-portable identifiers.
    pub fn new(value: impl Into<String>) -> Result<Self, OidcModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAXIMUM_KEY_ID_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(OidcModelError::InvalidKeyId);
        }
        Ok(Self(value))
    }

    /// Returns the validated key identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OidcKeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("OidcKeyId").field(&self.0).finish()
    }
}

impl fmt::Display for OidcKeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Opaque identity naming one durably authenticated execution authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OidcAuthorityId(Uuid);

impl OidcAuthorityId {
    /// Creates an authority identity from a non-nil UUID.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID.
    pub const fn from_uuid(value: Uuid) -> Result<Self, OidcModelError> {
        if value.is_nil() {
            return Err(OidcModelError::InvalidIdentifier);
        }
        Ok(Self(value))
    }

    /// Returns the UUID representation.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for OidcAuthorityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// RFC 9562 identity naming one exact ID-token issuance.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OidcTokenId(Uuid);

impl OidcTokenId {
    /// Creates a token identity from a non-nil UUID.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID.
    pub const fn from_uuid(value: Uuid) -> Result<Self, OidcModelError> {
        if value.is_nil() {
            return Err(OidcModelError::InvalidIdentifier);
        }
        Ok(Self(value))
    }

    /// Returns the UUID representation.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for OidcTokenId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Bounded string-valued identity claims supplied only by durable authority.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct OidcClaimSet(BTreeMap<String, String>);

impl OidcClaimSet {
    /// Validates and canonicalizes additional string claims.
    ///
    /// Claim names use lowercase ASCII letters, digits, and underscores, with
    /// a leading letter. Registered JWT claims cannot be replaced.
    ///
    /// # Errors
    ///
    /// Rejects duplicate, reserved, malformed, oversized, or excessive claims.
    pub fn new(claims: impl IntoIterator<Item = (String, String)>) -> Result<Self, OidcModelError> {
        let mut values = BTreeMap::new();
        let mut total_bytes = 0_usize;
        for (name, value) in claims {
            if values.len() >= MAXIMUM_ADDITIONAL_CLAIMS {
                return Err(OidcModelError::TooManyClaims);
            }
            validate_claim(&name, &value)?;
            total_bytes = total_bytes
                .checked_add(name.len())
                .and_then(|total| total.checked_add(value.len()))
                .ok_or(OidcModelError::TooManyClaims)?;
            if total_bytes > MAXIMUM_ADDITIONAL_CLAIM_BYTES || values.contains_key(&name) {
                return Err(OidcModelError::TooManyClaims);
            }
            values.insert(name, value);
        }
        Ok(Self(values))
    }

    /// Returns the canonical claim map.
    #[must_use]
    pub const fn as_map(&self) -> &BTreeMap<String, String> {
        &self.0
    }

    /// Returns the number of additional claims.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether no additional claim is present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for OidcClaimSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcClaimSet")
            .field("claim_names", &self.0.keys().collect::<Vec<_>>())
            .finish()
    }
}

fn validate_claim(name: &str, value: &str) -> Result<(), OidcModelError> {
    if !valid_additional_claim_name(name)
        || value.len() > MAXIMUM_CLAIM_VALUE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(OidcModelError::InvalidClaim);
    }
    Ok(())
}

fn valid_additional_claim_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAXIMUM_CLAIM_NAME_BYTES
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && RESERVED_CLAIMS.binary_search(&name).is_err()
}

/// Bounded discovery claim names accepted from durable issuance authority.
///
/// Registered token claims are always present. The constructor accepts only
/// additional claim names and publishes them in canonical lexical order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcSupportedClaims {
    claims: Vec<String>,
    additional: BTreeSet<String>,
}

impl OidcSupportedClaims {
    /// Validates a bounded configured universe of additional claim names.
    ///
    /// # Errors
    ///
    /// Rejects reserved, malformed, duplicate, excessive, or overlong names.
    pub fn new(
        additional_claims: impl IntoIterator<Item = String>,
    ) -> Result<Self, OidcModelError> {
        let mut additional = BTreeSet::new();
        let mut total_bytes = 0_usize;
        for name in additional_claims {
            if !valid_additional_claim_name(&name) {
                return Err(OidcModelError::InvalidClaim);
            }
            total_bytes = total_bytes
                .checked_add(name.len())
                .ok_or(OidcModelError::TooManyClaims)?;
            if additional.len() >= MAXIMUM_SUPPORTED_ADDITIONAL_CLAIMS
                || total_bytes > MAXIMUM_SUPPORTED_CLAIM_NAME_BYTES
                || !additional.insert(name)
            {
                return Err(OidcModelError::TooManyClaims);
            }
        }
        let mut claims = REGISTERED_CLAIM_ORDER.map(str::to_owned).to_vec();
        claims.extend(additional.iter().cloned());
        Ok(Self { claims, additional })
    }

    /// Returns registered claims followed by canonical additional names.
    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.claims
    }

    /// Returns whether an additional claim is configured and advertised.
    #[must_use]
    pub fn supports_additional(&self, name: &str) -> bool {
        self.additional.contains(name)
    }
}

/// Authenticated in-memory authority data used by the reference repository.
///
/// Production adapters must derive the same fields from durable execution and
/// event evidence; callers of the HTTP endpoint cannot supply them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedOidcAuthority {
    authority_id: OidcAuthorityId,
    subject: OidcSubject,
    default_audience: OidcAudience,
    additional_claims: OidcClaimSet,
    not_before_seconds: u64,
    expires_at_seconds: u64,
}

impl AuthorizedOidcAuthority {
    /// Creates one explicit authorized workload identity interval.
    ///
    /// # Errors
    ///
    /// Rejects an empty or inverted interval.
    pub fn new(
        authority_id: OidcAuthorityId,
        subject: OidcSubject,
        default_audience: OidcAudience,
        additional_claims: OidcClaimSet,
        not_before_seconds: u64,
        expires_at_seconds: u64,
    ) -> Result<Self, OidcModelError> {
        if expires_at_seconds <= not_before_seconds {
            return Err(OidcModelError::InvalidTime);
        }
        Ok(Self {
            authority_id,
            subject,
            default_audience,
            additional_claims,
            not_before_seconds,
            expires_at_seconds,
        })
    }

    /// Returns the opaque durable authority identity.
    #[must_use]
    pub const fn authority_id(&self) -> OidcAuthorityId {
        self.authority_id
    }

    /// Returns the durably authorized subject.
    #[must_use]
    pub const fn subject(&self) -> &OidcSubject {
        &self.subject
    }

    /// Returns the explicit default audience.
    #[must_use]
    pub const fn default_audience(&self) -> &OidcAudience {
        &self.default_audience
    }

    /// Returns the durably authorized additional claims.
    #[must_use]
    pub const fn additional_claims(&self) -> &OidcClaimSet {
        &self.additional_claims
    }

    /// Returns the first valid second.
    #[must_use]
    pub const fn not_before_seconds(&self) -> u64 {
        self.not_before_seconds
    }

    /// Returns the exclusive durable authority deadline.
    #[must_use]
    pub const fn expires_at_seconds(&self) -> u64 {
        self.expires_at_seconds
    }
}

/// Atomic durable request to authorize and reserve one ID-token issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveOidcIssuance {
    authority_id: OidcAuthorityId,
    requested_audience: Option<OidcAudience>,
    request_issued_at_seconds: u64,
    request_expires_at_seconds: u64,
    observed_at_seconds: u64,
    maximum_expires_at_seconds: u64,
    proposed_token_id: OidcTokenId,
    proposed_signing_key_id: OidcKeyId,
}

impl ReserveOidcIssuance {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        authority_id: OidcAuthorityId,
        requested_audience: Option<OidcAudience>,
        request_issued_at_seconds: u64,
        request_expires_at_seconds: u64,
        observed_at_seconds: u64,
        maximum_expires_at_seconds: u64,
        proposed_token_id: OidcTokenId,
        proposed_signing_key_id: OidcKeyId,
    ) -> Self {
        Self {
            authority_id,
            requested_audience,
            request_issued_at_seconds,
            request_expires_at_seconds,
            observed_at_seconds,
            maximum_expires_at_seconds,
            proposed_token_id,
            proposed_signing_key_id,
        }
    }

    /// Returns the authenticated authority identity.
    #[must_use]
    pub const fn authority_id(&self) -> OidcAuthorityId {
        self.authority_id
    }

    /// Returns the optional caller-selected audience.
    #[must_use]
    pub const fn requested_audience(&self) -> Option<&OidcAudience> {
        self.requested_audience.as_ref()
    }

    /// Returns the signed request-bearer issuance second.
    #[must_use]
    pub const fn request_issued_at_seconds(&self) -> u64 {
        self.request_issued_at_seconds
    }

    /// Returns the exclusive signed request-bearer deadline.
    #[must_use]
    pub const fn request_expires_at_seconds(&self) -> u64 {
        self.request_expires_at_seconds
    }

    /// Returns the initial trusted clock sample that authorization cannot predate.
    ///
    /// The repository returns its per-call current authorization time separately
    /// in [`AuthorizedOidcIssuance`].
    #[must_use]
    pub const fn observed_at_seconds(&self) -> u64 {
        self.observed_at_seconds
    }

    /// Returns the exclusive upper bound imposed by the request bearer.
    #[must_use]
    pub const fn maximum_expires_at_seconds(&self) -> u64 {
        self.maximum_expires_at_seconds
    }

    /// Returns the proposed identity for a new issuance.
    #[must_use]
    pub const fn proposed_token_id(&self) -> OidcTokenId {
        self.proposed_token_id
    }

    /// Returns the active key proposed for a new issuance.
    #[must_use]
    pub const fn proposed_signing_key_id(&self) -> &OidcKeyId {
        &self.proposed_signing_key_id
    }
}

/// Exact authorized issuance returned by the durable repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcIssuance {
    authority_id: OidcAuthorityId,
    token_id: OidcTokenId,
    signing_key_id: OidcKeyId,
    subject: OidcSubject,
    audience: OidcAudience,
    additional_claims: OidcClaimSet,
    issued_at_seconds: u64,
    not_before_seconds: u64,
    expires_at_seconds: u64,
}

impl OidcIssuance {
    /// Builds the exact token payload reserved by durable authority.
    ///
    /// # Errors
    ///
    /// Rejects an inverted validity interval.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority_id: OidcAuthorityId,
        token_id: OidcTokenId,
        signing_key_id: OidcKeyId,
        subject: OidcSubject,
        audience: OidcAudience,
        additional_claims: OidcClaimSet,
        issued_at_seconds: u64,
        not_before_seconds: u64,
        expires_at_seconds: u64,
    ) -> Result<Self, OidcModelError> {
        if not_before_seconds > issued_at_seconds || expires_at_seconds <= issued_at_seconds {
            return Err(OidcModelError::InvalidTime);
        }
        Ok(Self {
            authority_id,
            token_id,
            signing_key_id,
            subject,
            audience,
            additional_claims,
            issued_at_seconds,
            not_before_seconds,
            expires_at_seconds,
        })
    }

    /// Returns the authority that owns this issuance.
    #[must_use]
    pub const fn authority_id(&self) -> OidcAuthorityId {
        self.authority_id
    }

    /// Returns the exact `jti` identity.
    #[must_use]
    pub const fn token_id(&self) -> OidcTokenId {
        self.token_id
    }

    /// Returns the signing key permanently bound to this issuance.
    #[must_use]
    pub const fn signing_key_id(&self) -> &OidcKeyId {
        &self.signing_key_id
    }

    /// Returns the authorized subject.
    #[must_use]
    pub const fn subject(&self) -> &OidcSubject {
        &self.subject
    }

    /// Returns the resolved audience.
    #[must_use]
    pub const fn audience(&self) -> &OidcAudience {
        &self.audience
    }

    /// Returns the additional authorized claims.
    #[must_use]
    pub const fn additional_claims(&self) -> &OidcClaimSet {
        &self.additional_claims
    }

    /// Returns the `iat` second.
    #[must_use]
    pub const fn issued_at_seconds(&self) -> u64 {
        self.issued_at_seconds
    }

    /// Returns the `nbf` second.
    #[must_use]
    pub const fn not_before_seconds(&self) -> u64 {
        self.not_before_seconds
    }

    /// Returns the exclusive `exp` second.
    #[must_use]
    pub const fn expires_at_seconds(&self) -> u64 {
        self.expires_at_seconds
    }
}

/// One immutable issuance paired with its fresh repository authorization time.
///
/// The timestamp is trusted evidence produced by the repository while it
/// revalidates current execution authority. It is intentionally separate from
/// the immutable token timestamps so an exact replay can carry a fresh
/// authorization decision without changing the signed token payload.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedOidcIssuance {
    issuance: OidcIssuance,
    authorized_at_seconds: u64,
}

impl AuthorizedOidcIssuance {
    /// Pairs a reserved issuance with the repository's trusted authorization time.
    ///
    /// The service independently validates this evidence against its initial
    /// trusted sample, bearer deadline, configured lifetime, and token fields.
    #[must_use]
    pub const fn new(issuance: OidcIssuance, authorized_at_seconds: u64) -> Self {
        Self {
            issuance,
            authorized_at_seconds,
        }
    }

    /// Returns the immutable issuance authorized for this call.
    #[must_use]
    pub const fn issuance(&self) -> &OidcIssuance {
        &self.issuance
    }

    /// Returns the trusted second at which the repository authorized this call.
    #[must_use]
    pub const fn authorized_at_seconds(&self) -> u64 {
        self.authorized_at_seconds
    }
}

impl fmt::Debug for AuthorizedOidcIssuance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizedOidcIssuance([redacted])")
    }
}
