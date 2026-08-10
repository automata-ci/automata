use std::{collections::BTreeSet, fmt, future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use thiserror::Error;

use crate::{
    authorization::RoleName,
    human::{AuthenticatedHuman, PrincipalId, ProviderId, ProviderSubject, TenantId},
    secret::SessionToken,
    time::UnixTimestamp,
};

const MAX_AUDIENCE_LENGTH: usize = 255;
const MAX_DIGEST_KEY_ID_LENGTH: usize = 128;

/// Fixed audience for credentials accepted by browser-facing routes.
pub const BROWSER_SESSION_AUDIENCE: &str = "automata.web";
/// Fixed audience for credentials accepted by CLI-facing routes.
pub const CLI_SESSION_AUDIENCE: &str = "automata.cli";
/// Maximum time after issuance in which a newly finalized CLI session may be
/// activated by the client that has durably stored its bearer credential.
pub const CLI_SESSION_ACTIVATION_LIFETIME_SECONDS: u64 = 300;

/// A bounded session identifier; durable sessions further require canonical UUID text.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct SessionId(String);

impl SessionId {
    /// Creates a validated session identifier.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, or control-bearing identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, SessionError> {
        let value = value.into();
        if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
            return Err(SessionError::InvalidId);
        }
        Ok(Self(value))
    }

    /// Returns the validated session identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SessionId {
    type Error = SessionError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<SessionId> for String {
    fn from(value: SessionId) -> Self {
        value.0
    }
}

/// Safe, serializable claims. The bearer token itself is held separately.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "AutomataSessionClaimsData")]
pub struct AutomataSessionClaims {
    session_id: SessionId,
    tenant_id: TenantId,
    principal_id: PrincipalId,
    provider_id: ProviderId,
    provider_subject: ProviderSubject,
    roles: BTreeSet<RoleName>,
    audience: String,
    issued_at: UnixTimestamp,
    expires_at: UnixTimestamp,
    /// Version of the authorization assignment used when this session was issued.
    authorization_revision: u64,
}

/// Stable identity dimensions carried by an Automata session.
///
/// Grouping these values keeps claims construction explicit without exposing
/// the claims' private representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomataSessionIdentity {
    session_id: SessionId,
    tenant_id: TenantId,
    principal_id: PrincipalId,
    provider_id: ProviderId,
    provider_subject: ProviderSubject,
}

impl AutomataSessionIdentity {
    #[must_use]
    /// Groups stable session, tenant, principal, and provider identity dimensions.
    pub const fn new(
        session_id: SessionId,
        tenant_id: TenantId,
        principal_id: PrincipalId,
        provider_id: ProviderId,
        provider_subject: ProviderSubject,
    ) -> Self {
        Self {
            session_id,
            tenant_id,
            principal_id,
            provider_id,
            provider_subject,
        }
    }
}

/// Builder for validated [`AutomataSessionClaims`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
pub struct AutomataSessionClaimsBuilder {
    identity: AutomataSessionIdentity,
    roles: BTreeSet<RoleName>,
    audience: String,
    issued_at: UnixTimestamp,
    expires_at: UnixTimestamp,
    authorization_revision: u64,
}

impl AutomataSessionClaimsBuilder {
    /// Replaces the roles captured by the session.
    pub fn roles(mut self, roles: BTreeSet<RoleName>) -> Self {
        self.roles = roles;
        self
    }

    /// Records the authorization assignment revision used for issuance.
    pub const fn authorization_revision(mut self, revision: u64) -> Self {
        self.authorization_revision = revision;
        self
    }

    /// Validates and creates session claims.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, or control-bearing audience,
    /// or when expiration is not strictly after issuance.
    pub fn build(self) -> Result<AutomataSessionClaims, SessionValidationError> {
        if self.audience.is_empty()
            || self.audience.len() > MAX_AUDIENCE_LENGTH
            || self.audience.chars().any(char::is_control)
        {
            return Err(SessionValidationError::InvalidAudience);
        }
        if self.issued_at >= self.expires_at {
            return Err(SessionValidationError::InvalidLifetime);
        }
        let AutomataSessionIdentity {
            session_id,
            tenant_id,
            principal_id,
            provider_id,
            provider_subject,
        } = self.identity;
        Ok(AutomataSessionClaims {
            session_id,
            tenant_id,
            principal_id,
            provider_id,
            provider_subject,
            roles: self.roles,
            audience: self.audience,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            authorization_revision: self.authorization_revision,
        })
    }
}

#[derive(Deserialize)]
struct AutomataSessionClaimsData {
    session_id: SessionId,
    tenant_id: TenantId,
    principal_id: PrincipalId,
    provider_id: ProviderId,
    provider_subject: ProviderSubject,
    roles: BTreeSet<RoleName>,
    audience: String,
    issued_at: UnixTimestamp,
    expires_at: UnixTimestamp,
    authorization_revision: u64,
}

impl AutomataSessionClaims {
    /// Starts building safe session claims.
    pub fn builder(
        identity: AutomataSessionIdentity,
        audience: impl Into<String>,
        issued_at: UnixTimestamp,
        expires_at: UnixTimestamp,
    ) -> AutomataSessionClaimsBuilder {
        AutomataSessionClaimsBuilder {
            identity,
            roles: BTreeSet::new(),
            audience: audience.into(),
            issued_at,
            expires_at,
            authorization_revision: 0,
        }
    }

    /// Returns the public session identity.
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the tenant that bounds the session.
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the stable Automata-owned principal.
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    /// Returns the provider that authenticated the principal.
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// Returns the provider's stable subject identity.
    pub const fn provider_subject(&self) -> &ProviderSubject {
        &self.provider_subject
    }

    /// Returns roles captured at issuance; request authorization must re-resolve them.
    pub const fn roles(&self) -> &BTreeSet<RoleName> {
        &self.roles
    }

    /// Returns the service audience authorized to accept the credential.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Returns when the session was issued.
    pub const fn issued_at(&self) -> UnixTimestamp {
        self.issued_at
    }

    /// Returns the immutable absolute session deadline.
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }

    /// Returns the durable authorization revision captured at issuance.
    pub const fn authorization_revision(&self) -> u64 {
        self.authorization_revision
    }

    /// Validates the audience and half-open session lifetime at `now`.
    ///
    /// # Errors
    ///
    /// Returns an error for an audience mismatch, expiration, or inconsistent times.
    pub fn validate(
        &self,
        now: UnixTimestamp,
        expected_audience: &str,
    ) -> Result<(), SessionValidationError> {
        if self.audience != expected_audience {
            return Err(SessionValidationError::WrongAudience);
        }
        if self.expires_at <= now {
            return Err(SessionValidationError::Expired);
        }
        if self.issued_at > now || self.issued_at >= self.expires_at {
            return Err(SessionValidationError::InvalidLifetime);
        }
        Ok(())
    }
}

impl TryFrom<AutomataSessionClaimsData> for AutomataSessionClaims {
    type Error = SessionValidationError;

    fn try_from(value: AutomataSessionClaimsData) -> Result<Self, Self::Error> {
        Self::builder(
            AutomataSessionIdentity::new(
                value.session_id,
                value.tenant_id,
                value.principal_id,
                value.provider_id,
                value.provider_subject,
            ),
            value.audience,
            value.issued_at,
            value.expires_at,
        )
        .roles(value.roles)
        .authorization_revision(value.authorization_revision)
        .build()
    }
}

/// An Automata-scoped session. Provider credentials are never returned here.
pub struct IssuedSession {
    token: SessionToken,
    claims: AutomataSessionClaims,
}

impl IssuedSession {
    /// Associates one raw opaque bearer credential with its safe claims.
    pub const fn new(token: SessionToken, claims: AutomataSessionClaims) -> Self {
        Self { token, claims }
    }

    /// Borrows the raw bearer at the client-delivery boundary.
    pub const fn token(&self) -> &SessionToken {
        &self.token
    }

    /// Returns safe, serializable identity and lifecycle claims.
    pub const fn claims(&self) -> &AutomataSessionClaims {
        &self.claims
    }

    /// Consumes the issuance result into raw bearer and safe claims.
    pub fn into_parts(self) -> (SessionToken, AutomataSessionClaims) {
        (self.token, self.claims)
    }
}

impl fmt::Debug for IssuedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedSession")
            .field("token", &"[REDACTED]")
            .field("claims", &self.claims)
            .finish()
    }
}

/// Browser and CLI sessions are separate credential audiences.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    /// Cookie-oriented session accepted only by the browser audience.
    Browser,
    /// Credential-manager-backed session accepted only by the CLI audience.
    Cli,
}

impl SessionKind {
    #[must_use]
    /// Returns the fixed audience domain for this session kind.
    pub const fn audience(self) -> &'static str {
        match self {
            Self::Browser => BROWSER_SESSION_AUDIENCE,
            Self::Cli => CLI_SESSION_AUDIENCE,
        }
    }
}

/// Identifier for the keyed digest secret used to index an opaque bearer token.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct SessionTokenDigestKeyId(String);

impl SessionTokenDigestKeyId {
    /// Creates a bounded portable key identifier.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or non-portable identifiers.
    pub fn new(value: impl Into<String>) -> Result<Self, SessionPersistenceValueError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_DIGEST_KEY_ID_LENGTH
            || !value.bytes().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, b'-' | b'_' | b':' | b'.')
            })
        {
            return Err(SessionPersistenceValueError::InvalidDigestKeyId);
        }
        Ok(Self(value))
    }

    #[must_use]
    /// Returns the stable digest-key identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SessionTokenDigestKeyId {
    type Error = SessionPersistenceValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<SessionTokenDigestKeyId> for String {
    fn from(value: SessionTokenDigestKeyId) -> Self {
        value.0
    }
}

/// Fixed-size keyed digest of an opaque Automata session token.
///
/// This is the only token-derived value accepted by [`HumanSessionRepository`]. It is
/// serializable for durable storage, but debug output omits its bytes and it cannot
/// be converted back into a bearer token.
#[derive(Clone, Serialize)]
#[serde(transparent)]
pub struct SessionTokenDigest([u8; 32]);

impl SessionTokenDigest {
    #[must_use]
    /// Wraps a fixed-size keyed digest of a raw bearer token.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    /// Borrows the digest without exposing the raw bearer.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SessionTokenDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionTokenDigest([REDACTED])")
    }
}

impl PartialEq for SessionTokenDigest {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for SessionTokenDigest {}

impl<'de> Deserialize<'de> for SessionTokenDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <[u8; 32]>::deserialize(deserializer).map(Self)
    }
}

/// Versioned keyed lookup material derived from a raw opaque bearer token.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionTokenLookup {
    key_id: SessionTokenDigestKeyId,
    digest: SessionTokenDigest,
}

impl SessionTokenLookup {
    #[must_use]
    /// Creates a raw-free lookup from digest-key identity and keyed digest.
    pub const fn new(key_id: SessionTokenDigestKeyId, digest: SessionTokenDigest) -> Self {
        Self { key_id, digest }
    }

    #[must_use]
    /// Returns the digest-key identity required for lookup.
    pub const fn key_id(&self) -> &SessionTokenDigestKeyId {
        &self.key_id
    }

    #[must_use]
    /// Returns the constant-time comparable keyed digest.
    pub const fn digest(&self) -> &SessionTokenDigest {
        &self.digest
    }
}

/// Stable identity dimensions for a durable human session.
///
/// Session and principal IDs must be canonical, non-nil UUID strings so the
/// domain cannot disagree with `PostgreSQL` identity semantics. Provider subjects
/// remain provider-native validated strings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    try_from = "DurableSessionIdentityData",
    into = "DurableSessionIdentityData"
)]
pub struct DurableSessionIdentity {
    session_id: SessionId,
    tenant_id: TenantId,
    principal_id: PrincipalId,
    provider_id: ProviderId,
    provider_subject: ProviderSubject,
    kind: SessionKind,
}

#[derive(Clone, Deserialize, Serialize)]
struct DurableSessionIdentityData {
    session_id: SessionId,
    tenant_id: TenantId,
    principal_id: PrincipalId,
    provider_id: ProviderId,
    provider_subject: ProviderSubject,
    kind: SessionKind,
}

impl DurableSessionIdentity {
    /// Creates a database-aligned durable identity.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical or nil session/principal UUID strings.
    pub fn new(
        session_id: SessionId,
        tenant_id: TenantId,
        principal_id: PrincipalId,
        provider_id: ProviderId,
        provider_subject: ProviderSubject,
        kind: SessionKind,
    ) -> Result<Self, SessionPersistenceValueError> {
        validate_canonical_uuid(session_id.as_str())
            .map_err(|()| SessionPersistenceValueError::InvalidSessionId)?;
        validate_canonical_uuid(principal_id.as_str())
            .map_err(|()| SessionPersistenceValueError::InvalidPrincipalId)?;
        Ok(Self {
            session_id,
            tenant_id,
            principal_id,
            provider_id,
            provider_subject,
            kind,
        })
    }

    #[must_use]
    /// Returns the canonical durable session UUID.
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    /// Returns the tenant that bounds the durable session.
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    /// Returns the stable Automata-owned principal.
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    #[must_use]
    /// Returns the provider that authenticated the principal.
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    #[must_use]
    /// Returns the provider's stable subject identity.
    pub const fn provider_subject(&self) -> &ProviderSubject {
        &self.provider_subject
    }

    #[must_use]
    /// Returns whether the session belongs to browser or CLI authority.
    pub const fn kind(&self) -> SessionKind {
        self.kind
    }

    #[must_use]
    /// Returns the fixed audience derived from the session kind.
    pub const fn audience(&self) -> &'static str {
        self.kind.audience()
    }
}

impl TryFrom<DurableSessionIdentityData> for DurableSessionIdentity {
    type Error = SessionPersistenceValueError;

    fn try_from(value: DurableSessionIdentityData) -> Result<Self, Self::Error> {
        Self::new(
            value.session_id,
            value.tenant_id,
            value.principal_id,
            value.provider_id,
            value.provider_subject,
            value.kind,
        )
    }
}

impl From<DurableSessionIdentity> for DurableSessionIdentityData {
    fn from(value: DurableSessionIdentity) -> Self {
        Self {
            session_id: value.session_id,
            tenant_id: value.tenant_id,
            principal_id: value.principal_id,
            provider_id: value.provider_id,
            provider_subject: value.provider_subject,
            kind: value.kind,
        }
    }
}

/// Safe durable session metadata. Role grants are deliberately absent and must
/// be resolved from current assignments after session authentication.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "DurableSessionData", into = "DurableSessionData")]
pub struct DurableSession {
    identity: DurableSessionIdentity,
    authorization_revision: u64,
    issued_at: UnixTimestamp,
    last_seen_at: UnixTimestamp,
    idle_expires_at: UnixTimestamp,
    expires_at: UnixTimestamp,
    revoked_at: Option<UnixTimestamp>,
}

#[derive(Clone, Deserialize, Serialize)]
struct DurableSessionData {
    identity: DurableSessionIdentity,
    authorization_revision: u64,
    issued_at: UnixTimestamp,
    last_seen_at: UnixTimestamp,
    idle_expires_at: UnixTimestamp,
    expires_at: UnixTimestamp,
    revoked_at: Option<UnixTimestamp>,
}

impl DurableSession {
    /// Creates validated durable session metadata.
    ///
    /// # Errors
    ///
    /// Rejects a zero authorization revision, nonmonotonic lifetime, or a
    /// revocation timestamp preceding issuance.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: DurableSessionIdentity,
        authorization_revision: u64,
        issued_at: UnixTimestamp,
        last_seen_at: UnixTimestamp,
        idle_expires_at: UnixTimestamp,
        expires_at: UnixTimestamp,
        revoked_at: Option<UnixTimestamp>,
    ) -> Result<Self, SessionPersistenceValueError> {
        if authorization_revision == 0 {
            return Err(SessionPersistenceValueError::InvalidAuthorizationRevision);
        }
        if last_seen_at < issued_at
            || idle_expires_at <= last_seen_at
            || idle_expires_at > expires_at
            || expires_at <= issued_at
        {
            return Err(SessionPersistenceValueError::InvalidLifetime);
        }
        if revoked_at.is_some_and(|revoked_at| revoked_at < issued_at) {
            return Err(SessionPersistenceValueError::InvalidRevokedAt);
        }
        Ok(Self {
            identity,
            authorization_revision,
            issued_at,
            last_seen_at,
            idle_expires_at,
            expires_at,
            revoked_at,
        })
    }

    #[must_use]
    /// Returns stable durable identity dimensions.
    pub const fn identity(&self) -> &DurableSessionIdentity {
        &self.identity
    }

    #[must_use]
    /// Returns the positive authorization revision fixed at issuance.
    pub const fn authorization_revision(&self) -> u64 {
        self.authorization_revision
    }

    #[must_use]
    /// Returns the immutable issuance timestamp.
    pub const fn issued_at(&self) -> UnixTimestamp {
        self.issued_at
    }

    #[must_use]
    /// Returns the most recent accepted activity timestamp.
    pub const fn last_seen_at(&self) -> UnixTimestamp {
        self.last_seen_at
    }

    #[must_use]
    /// Returns the current sliding idle deadline.
    pub const fn idle_expires_at(&self) -> UnixTimestamp {
        self.idle_expires_at
    }

    #[must_use]
    /// Returns the immutable absolute session deadline.
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }

    #[must_use]
    /// Returns the durable revocation timestamp, when revoked.
    pub const fn revoked_at(&self) -> Option<UnixTimestamp> {
        self.revoked_at
    }

    /// Classifies a resolved record using current membership authorization state.
    #[must_use]
    pub fn resolution_status(
        &self,
        expected_kind: SessionKind,
        now: UnixTimestamp,
        current_authorization_revision: u64,
    ) -> SessionResolutionStatus {
        if self.identity.kind() != expected_kind
            || self.identity.audience() != expected_kind.audience()
        {
            return SessionResolutionStatus::WrongKindOrAudience;
        }
        if self.revoked_at.is_some() {
            return SessionResolutionStatus::Revoked;
        }
        if self.idle_expires_at <= now || self.expires_at <= now {
            return SessionResolutionStatus::Expired;
        }
        if self.issued_at > now {
            return SessionResolutionStatus::NotYetValid;
        }
        if self.authorization_revision != current_authorization_revision {
            return SessionResolutionStatus::AuthorizationRevisionChanged {
                session_revision: self.authorization_revision,
                current_revision: current_authorization_revision,
            };
        }
        SessionResolutionStatus::Active
    }
}

impl TryFrom<DurableSessionData> for DurableSession {
    type Error = SessionPersistenceValueError;

    fn try_from(value: DurableSessionData) -> Result<Self, Self::Error> {
        Self::new(
            value.identity,
            value.authorization_revision,
            value.issued_at,
            value.last_seen_at,
            value.idle_expires_at,
            value.expires_at,
            value.revoked_at,
        )
    }
}

impl From<DurableSession> for DurableSessionData {
    fn from(value: DurableSession) -> Self {
        Self {
            identity: value.identity,
            authorization_revision: value.authorization_revision,
            issued_at: value.issued_at,
            last_seen_at: value.last_seen_at,
            idle_expires_at: value.idle_expires_at,
            expires_at: value.expires_at,
            revoked_at: value.revoked_at,
        }
    }
}

fn validate_canonical_uuid(value: &str) -> Result<(), ()> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| ())?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err(());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed classification of a durable session against current request authority.
pub enum SessionResolutionStatus {
    /// The session is valid for the requested kind, time, and authorization revision.
    Active,
    /// The credential kind or its fixed audience does not match the accepting route.
    WrongKindOrAudience,
    /// The session has a durable revocation timestamp.
    Revoked,
    /// The idle or absolute lifetime has ended.
    Expired,
    /// The observation precedes the session's issuance timestamp.
    NotYetValid,
    /// Current tenant authority differs from the revision captured at issuance.
    AuthorizationRevisionChanged {
        /// Authorization revision captured in the session.
        session_revision: u64,
        /// Current durable authorization revision for the tenant principal.
        current_revision: u64,
    },
}

/// Raw-free persistence request for creating one durable session.
///
/// The keyed lookup and safe session metadata must be inserted atomically so
/// neither a token digest nor a session identity can be reused independently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateSession {
    lookup: SessionTokenLookup,
    session: DurableSession,
}

impl CreateSession {
    /// Binds an opaque-token lookup to its durable safe metadata.
    #[must_use]
    pub const fn new(lookup: SessionTokenLookup, session: DurableSession) -> Self {
        Self { lookup, session }
    }

    /// Returns the keyed lookup used to authenticate the bearer.
    #[must_use]
    pub const fn lookup(&self) -> &SessionTokenLookup {
        &self.lookup
    }

    /// Returns the safe durable session metadata to create.
    #[must_use]
    pub const fn session(&self) -> &DurableSession {
        &self.session
    }

    /// Consumes the request into its keyed lookup and session metadata.
    pub fn into_parts(self) -> (SessionTokenLookup, DurableSession) {
        (self.lookup, self.session)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Raw-free request to resolve one bearer lookup for an exact session kind.
///
/// Implementations compare the captured authorization revision with current
/// tenant authority in the same durable operation.
pub struct ResolveSession {
    lookup: SessionTokenLookup,
    expected_kind: SessionKind,
    now: UnixTimestamp,
}

/// Raw-free request to activate one exact CLI session lookup.
///
/// The lookup is already audience-domain-separated by the credential service;
/// persistence never accepts or observes the raw bearer credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivateCliSession {
    lookup: SessionTokenLookup,
    now: UnixTimestamp,
}

impl ActivateCliSession {
    /// Creates an activation request from a CLI-domain lookup and one clock observation.
    #[must_use]
    pub const fn new(lookup: SessionTokenLookup, now: UnixTimestamp) -> Self {
        Self { lookup, now }
    }

    /// Returns the safe, keyed lookup accepted by persistence.
    #[must_use]
    pub const fn lookup(&self) -> &SessionTokenLookup {
        &self.lookup
    }

    /// Returns the exact activation-time observation.
    #[must_use]
    pub const fn now(&self) -> UnixTimestamp {
        self.now
    }
}

impl ResolveSession {
    /// Creates a resolution request at one trusted clock observation.
    #[must_use]
    pub const fn new(
        lookup: SessionTokenLookup,
        expected_kind: SessionKind,
        now: UnixTimestamp,
    ) -> Self {
        Self {
            lookup,
            expected_kind,
            now,
        }
    }

    /// Returns the safe keyed lookup to resolve.
    #[must_use]
    pub const fn lookup(&self) -> &SessionTokenLookup {
        &self.lookup
    }

    /// Returns the browser or CLI authority expected by the accepting route.
    #[must_use]
    pub const fn expected_kind(&self) -> SessionKind {
        self.expected_kind
    }

    /// Returns the timestamp used for lifetime validation.
    #[must_use]
    pub const fn now(&self) -> UnixTimestamp {
        self.now
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Request to advance recent activity and the sliding idle deadline.
///
/// Touching never changes the immutable absolute expiry or authorization
/// revision, and only applies to an otherwise active session of the expected kind.
pub struct TouchSession {
    lookup: SessionTokenLookup,
    expected_kind: SessionKind,
    observed_at: UnixTimestamp,
    idle_expires_at: UnixTimestamp,
}

impl TouchSession {
    /// Creates a touch request that extends the idle lifetime after observation.
    ///
    /// # Errors
    ///
    /// Rejects an idle deadline at or before the observation time.
    pub fn new(
        lookup: SessionTokenLookup,
        expected_kind: SessionKind,
        observed_at: UnixTimestamp,
        idle_expires_at: UnixTimestamp,
    ) -> Result<Self, SessionPersistenceValueError> {
        if idle_expires_at <= observed_at {
            return Err(SessionPersistenceValueError::InvalidTouchLifetime);
        }
        Ok(Self {
            lookup,
            expected_kind,
            observed_at,
            idle_expires_at,
        })
    }

    /// Returns the safe keyed lookup of the session to touch.
    #[must_use]
    pub const fn lookup(&self) -> &SessionTokenLookup {
        &self.lookup
    }

    /// Returns the exact session kind required by the accepting route.
    #[must_use]
    pub const fn expected_kind(&self) -> SessionKind {
        self.expected_kind
    }

    /// Returns when activity was observed.
    #[must_use]
    pub const fn observed_at(&self) -> UnixTimestamp {
        self.observed_at
    }

    /// Returns the proposed sliding idle deadline.
    #[must_use]
    pub const fn idle_expires_at(&self) -> UnixTimestamp {
        self.idle_expires_at
    }
}

/// Tenant/principal-bound revocation of one session owned by the authenticated user.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeOwnSession {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    session_id: SessionId,
    revoked_at: UnixTimestamp,
}

impl RevokeOwnSession {
    /// Creates a request whose tenant and principal must own the exact session.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        principal_id: PrincipalId,
        session_id: SessionId,
        revoked_at: UnixTimestamp,
    ) -> Self {
        Self {
            tenant_id,
            principal_id,
            session_id,
            revoked_at,
        }
    }

    /// Returns the tenant boundary for the revocation.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the authenticated principal that must own the session.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    /// Returns the exact durable session identifier to revoke.
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the trusted revocation timestamp.
    #[must_use]
    pub const fn revoked_at(&self) -> UnixTimestamp {
        self.revoked_at
    }
}

/// Administrative revocation of every session for one exact tenant principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokePrincipalSessions {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    revoked_at: UnixTimestamp,
}

impl RevokePrincipalSessions {
    /// Creates an administrative bulk-revocation request for one tenant principal.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        principal_id: PrincipalId,
        revoked_at: UnixTimestamp,
    ) -> Self {
        Self {
            tenant_id,
            principal_id,
            revoked_at,
        }
    }

    /// Returns the tenant boundary for the revocation.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the exact principal whose sessions are revoked.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    /// Returns the trusted revocation timestamp applied to active sessions.
    #[must_use]
    pub const fn revoked_at(&self) -> UnixTimestamp {
        self.revoked_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed result of atomically creating a durable session and token lookup.
pub enum CreateSessionOutcome {
    /// Both the session record and token lookup were created.
    Created,
    /// The durable session identifier is already assigned.
    SessionIdConflict,
    /// The keyed token digest is already assigned to another session.
    TokenDigestConflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Closed result of resolving a durable browser or CLI session.
pub enum ResolveSessionOutcome {
    /// The session is active and current safe metadata is returned.
    Active(Box<DurableSession>),
    /// No session has the supplied keyed lookup.
    NotFound,
    /// The stored session belongs to a different kind or fixed audience.
    WrongKindOrAudience,
    /// The session has been durably revoked.
    Revoked,
    /// The idle or absolute lifetime has ended.
    Expired,
    /// The observation precedes session issuance.
    NotYetValid,
    /// The durable principal is disabled.
    PrincipalDisabled,
    /// The principal's membership in the exact tenant is suspended.
    MembershipSuspended,
    /// Current tenant authority differs from the issuance revision.
    AuthorizationRevisionChanged {
        /// Authorization revision captured in the session.
        session_revision: u64,
        /// Current durable authorization revision for the tenant principal.
        current_revision: u64,
    },
}

/// Closed result of attempting to activate an exact CLI session lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivateCliSessionOutcome {
    /// This request performed the one permitted pending-to-active transition.
    Activated(Box<DurableSession>),
    /// The exact CLI session was already active and remains currently valid.
    AlreadyActive(Box<DurableSession>),
    /// No session has this lookup.
    NotFound,
    /// The lookup belongs to a non-CLI session or a different audience.
    WrongKindOrAudience,
    /// The pending CLI session was revoked before activation.
    Revoked,
    /// The ordinary idle or absolute session lifetime has ended.
    Expired,
    /// The activation observation precedes session issuance.
    NotYetValid,
    /// The pending-only activation window has ended.
    ActivationExpired,
    /// The durable principal is disabled.
    PrincipalDisabled,
    /// The exact tenant membership is suspended.
    MembershipSuspended,
    /// Current tenant authority no longer matches the issuance revision.
    AuthorizationRevisionChanged {
        /// Authorization revision fixed in the pending session.
        session_revision: u64,
        /// Current durable tenant-membership authorization revision.
        current_revision: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Closed result of attempting to advance a session's sliding idle deadline.
pub enum TouchSessionOutcome {
    /// Activity and idle expiry were durably advanced.
    Touched(Box<DurableSession>),
    /// The request was valid but did not advance the stored timestamps.
    Unchanged(Box<DurableSession>),
    /// No session has the supplied keyed lookup.
    NotFound,
    /// The stored session belongs to a different kind or fixed audience.
    WrongKindOrAudience,
    /// The session has been durably revoked.
    Revoked,
    /// The idle or absolute lifetime has ended.
    Expired,
    /// The observation precedes session issuance.
    NotYetValid,
    /// The durable principal is disabled.
    PrincipalDisabled,
    /// The principal's membership in the exact tenant is suspended.
    MembershipSuspended,
    /// Current tenant authority differs from the issuance revision.
    AuthorizationRevisionChanged {
        /// Authorization revision captured in the session.
        session_revision: u64,
        /// Current durable authorization revision for the tenant principal.
        current_revision: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed result of revoking one session owned by the authenticated principal.
pub enum RevokeOwnSessionOutcome {
    /// The active session was durably revoked by this request.
    Revoked,
    /// The exact owned session was already revoked.
    AlreadyRevoked,
    /// No session matched the tenant, principal, and session identifier tuple.
    NotFound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Result of administratively revoking all sessions for one tenant principal.
pub struct RevokePrincipalSessionsOutcome {
    revoked_sessions: u64,
}

impl RevokePrincipalSessionsOutcome {
    /// Records the number of sessions newly revoked by the operation.
    #[must_use]
    pub const fn new(revoked_sessions: u64) -> Self {
        Self { revoked_sessions }
    }

    /// Returns the number of sessions newly revoked by the operation.
    #[must_use]
    pub const fn revoked_sessions(self) -> u64 {
        self.revoked_sessions
    }
}

/// Sendable future returned by the durable human-session repository.
pub type SessionRepositoryFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, SessionRepositoryError>> + Send + 'a>>;

/// Durable human-session boundary. Raw bearer tokens never cross this port.
///
/// `resolve` and `touch` must compare the session's authorization revision with
/// the current durable tenant/principal revision in the same database operation.
pub trait HumanSessionRepository: fmt::Debug + Send + Sync {
    /// Atomically creates safe session metadata and its keyed token lookup.
    fn create(&self, request: CreateSession) -> SessionRepositoryFuture<'_, CreateSessionOutcome>;

    /// Resolves one lookup and current tenant authority without exposing the bearer.
    fn resolve<'a>(
        &'a self,
        request: &'a ResolveSession,
    ) -> SessionRepositoryFuture<'a, ResolveSessionOutcome>;

    /// Activates an exact pending CLI lookup after client-side credential
    /// custody succeeds. Implementations that do not support this newer
    /// boundary fail closed instead of treating a pending session as active.
    fn activate_cli<'a>(
        &'a self,
        _request: &'a ActivateCliSession,
    ) -> SessionRepositoryFuture<'a, ActivateCliSessionOutcome> {
        Box::pin(async { Err(SessionRepositoryError::Unavailable) })
    }

    /// Advances recent activity and idle expiry for an otherwise active session.
    fn touch<'a>(
        &'a self,
        request: &'a TouchSession,
    ) -> SessionRepositoryFuture<'a, TouchSessionOutcome>;

    /// Revokes one session only when it belongs to the supplied tenant principal.
    fn revoke_own<'a>(
        &'a self,
        request: &'a RevokeOwnSession,
    ) -> SessionRepositoryFuture<'a, RevokeOwnSessionOutcome>;

    /// Administratively revokes every session for one exact tenant principal.
    fn revoke_principal<'a>(
        &'a self,
        request: &'a RevokePrincipalSessions,
    ) -> SessionRepositoryFuture<'a, RevokePrincipalSessionsOutcome>;
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
/// Validation failures for values entering durable human-session storage.
pub enum SessionPersistenceValueError {
    #[error("session token digest key ID is invalid")]
    /// The digest-key identifier is empty, oversized, or not portable ASCII.
    InvalidDigestKeyId,
    #[error("durable session ID must be a canonical non-nil UUID")]
    /// The session identifier is not canonical non-nil UUID text.
    InvalidSessionId,
    #[error("durable principal ID must be a canonical non-nil UUID")]
    /// The principal identifier is not canonical non-nil UUID text.
    InvalidPrincipalId,
    #[error("session authorization revision must be positive")]
    /// The captured authorization revision is zero.
    InvalidAuthorizationRevision,
    #[error("session timestamps do not form a valid absolute and idle lifetime")]
    /// Issuance, activity, idle expiry, and absolute expiry are not monotonic.
    InvalidLifetime,
    #[error("session touch must extend idle expiry beyond its observation")]
    /// A touch proposes an idle deadline at or before its observation.
    InvalidTouchLifetime,
    #[error("session revocation cannot precede issuance")]
    /// The revocation timestamp precedes issuance.
    InvalidRevokedAt,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
/// Sanitized durable human-session repository failures.
///
/// Variants deliberately omit bearer, digest, identity, and backend details.
pub enum SessionRepositoryError {
    #[error("human session request violates an identity or lifetime invariant")]
    /// The caller supplied an invalid identity, lifetime, or state transition.
    InvalidRequest,
    #[error("human session storage is unavailable")]
    /// Durable storage could not complete the operation and retry may succeed.
    Unavailable,
    #[error("durable human session data violates an invariant")]
    /// Stored session state is malformed or violates the repository contract.
    CorruptData,
}

/// Safe inputs required to issue a new Automata-scoped bearer session.
///
/// The provider credential is absent. Implementations generate and return a
/// fresh opaque Automata bearer separately from these identity and role claims.
pub struct SessionIssuance<'a> {
    /// Tenant authority for the issued session.
    pub tenant_id: &'a TenantId,
    /// Authenticated provider identity to bind into the session.
    pub human: &'a AuthenticatedHuman,
    /// Role snapshot recorded in safe claims at issuance.
    pub roles: &'a BTreeSet<RoleName>,
    /// Exact service audience authorized to accept the credential.
    pub audience: &'a str,
    /// Durable authorization assignment revision captured at issuance.
    pub authorization_revision: u64,
}

impl fmt::Debug for SessionIssuance<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionIssuance")
            .field("tenant_id", self.tenant_id)
            .field("human", self.human)
            .field("roles", self.roles)
            .field("audience", &self.audience)
            .field("authorization_revision", &self.authorization_revision)
            .finish()
    }
}

/// Sendable future returned by a session issuer.
pub type SessionIssuanceFuture<'a> =
    Pin<Box<dyn Future<Output = Result<IssuedSession, SessionIssuanceError>> + Send + 'a>>;

/// Port that mints an Automata bearer credential and its safe claims.
pub trait SessionIssuer: fmt::Debug + Send + Sync {
    /// Issues a new opaque session for the validated identity and audience.
    fn issue<'a>(&'a self, request: SessionIssuance<'a>) -> SessionIssuanceFuture<'a>;
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
/// Validation failures for general session identifiers.
pub enum SessionError {
    #[error("session ID is invalid")]
    /// The identifier is empty, oversized, or contains a control character.
    InvalidId,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
/// Validation failures for safe in-memory session claims.
pub enum SessionValidationError {
    #[error("session audience is invalid")]
    /// The audience is empty, oversized, or contains a control character.
    InvalidAudience,
    #[error("session audience does not match this service")]
    /// The credential audience differs from the accepting service audience.
    WrongAudience,
    #[error("session has expired")]
    /// The absolute claim expiry is at or before the observation time.
    Expired,
    #[error("session timestamps are inconsistent")]
    /// Issuance is in the future or is not strictly before expiration.
    InvalidLifetime,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
/// Sanitized failures returned while issuing an Automata session.
pub enum SessionIssuanceError {
    #[error("session issuance is temporarily unavailable")]
    /// Required randomness, signing, or durable issuance state is unavailable.
    Unavailable,
    #[error("session issuance request is invalid")]
    /// Identity, audience, lifetime, or authorization inputs are invalid.
    InvalidRequest,
}
