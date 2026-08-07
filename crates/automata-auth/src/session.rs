use std::{collections::BTreeSet, fmt, future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    authorization::RoleName,
    human::{AuthenticatedHuman, PrincipalId, ProviderId, ProviderSubject, TenantId},
    secret::SessionToken,
    time::UnixTimestamp,
};

const MAX_AUDIENCE_LENGTH: usize = 255;

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

    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    pub const fn provider_subject(&self) -> &ProviderSubject {
        &self.provider_subject
    }

    pub const fn roles(&self) -> &BTreeSet<RoleName> {
        &self.roles
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub const fn issued_at(&self) -> UnixTimestamp {
        self.issued_at
    }

    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }

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
    pub const fn new(token: SessionToken, claims: AutomataSessionClaims) -> Self {
        Self { token, claims }
    }

    pub const fn token(&self) -> &SessionToken {
        &self.token
    }

    pub const fn claims(&self) -> &AutomataSessionClaims {
        &self.claims
    }

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

pub struct SessionIssuance<'a> {
    pub tenant_id: &'a TenantId,
    pub human: &'a AuthenticatedHuman,
    pub roles: &'a BTreeSet<RoleName>,
    pub audience: &'a str,
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

pub type SessionIssuanceFuture<'a> =
    Pin<Box<dyn Future<Output = Result<IssuedSession, SessionIssuanceError>> + Send + 'a>>;

pub trait SessionIssuer: fmt::Debug + Send + Sync {
    fn issue<'a>(&'a self, request: SessionIssuance<'a>) -> SessionIssuanceFuture<'a>;
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionError {
    #[error("session ID is invalid")]
    InvalidId,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionValidationError {
    #[error("session audience is invalid")]
    InvalidAudience,
    #[error("session audience does not match this service")]
    WrongAudience,
    #[error("session has expired")]
    Expired,
    #[error("session timestamps are inconsistent")]
    InvalidLifetime,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionIssuanceError {
    #[error("session issuance is temporarily unavailable")]
    Unavailable,
    #[error("session issuance request is invalid")]
    InvalidRequest,
}
