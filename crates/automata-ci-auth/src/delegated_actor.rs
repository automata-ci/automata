//! Request authentication for short-lived identities delegated by a trusted authority.
//!
//! Delegated assertions are deliberately separate from durable browser and CLI
//! sessions. The issuer authenticates an external actor, while Core remains the
//! authority for principal mapping, workspace membership, and RBAC.

use std::{fmt, future::Future, pin::Pin};

use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::{
    authorization::AuthorizationContext, human::TenantId, request_auth::ViewerDisplayMetadata,
    time::UnixTimestamp,
};

const MAX_ASSERTION_LIFETIME_SECONDS: u64 = 5 * 60;

/// The signed, provider-owned identity metadata accepted by Core.
#[derive(Clone, Eq, PartialEq)]
pub struct DelegatedActorAssertion {
    issuer: String,
    subject: Uuid,
    session_id: Uuid,
    assertion_id: Uuid,
    authenticated_at: UnixTimestamp,
    issued_at: UnixTimestamp,
    expires_at: UnixTimestamp,
}

impl DelegatedActorAssertion {
    /// Creates a bounded, internally consistent delegated assertion.
    ///
    /// Signature, audience, and current-time checks remain the responsibility of
    /// the protocol adapter before this domain value is constructed.
    ///
    /// # Errors
    ///
    /// Rejects a non-canonical HTTPS origin, nil identities, non-monotonic times,
    /// or an assertion lifetime longer than five minutes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer: impl Into<String>,
        subject: Uuid,
        session_id: Uuid,
        assertion_id: Uuid,
        authenticated_at: UnixTimestamp,
        issued_at: UnixTimestamp,
        expires_at: UnixTimestamp,
    ) -> Result<Self, DelegatedActorAssertionError> {
        let issuer = issuer.into();
        let parsed = Url::parse(&issuer).map_err(|_| DelegatedActorAssertionError)?;
        expires_at
            .as_seconds()
            .checked_sub(issued_at.as_seconds())
            .filter(|lifetime| *lifetime > 0 && *lifetime <= MAX_ASSERTION_LIFETIME_SECONDS)
            .ok_or(DelegatedActorAssertionError)?;
        if parsed.scheme() != "https"
            || parsed.host().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.origin().ascii_serialization() != issuer
            || subject.is_nil()
            || session_id.is_nil()
            || assertion_id.is_nil()
            || authenticated_at > issued_at
        {
            return Err(DelegatedActorAssertionError);
        }
        Ok(Self {
            issuer,
            subject,
            session_id,
            assertion_id,
            authenticated_at,
            issued_at,
            expires_at,
        })
    }

    /// Returns the exact configured authority origin.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the authority-owned stable account UUID.
    #[must_use]
    pub const fn subject(&self) -> Uuid {
        self.subject
    }

    /// Returns the authority session that performed the request.
    #[must_use]
    pub const fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Returns this assertion's unique replay-correlation identity.
    #[must_use]
    pub const fn assertion_id(&self) -> Uuid {
        self.assertion_id
    }

    /// Returns when the authority last authenticated the actor.
    #[must_use]
    pub const fn authenticated_at(&self) -> UnixTimestamp {
        self.authenticated_at
    }

    /// Returns when the authority issued this assertion.
    #[must_use]
    pub const fn issued_at(&self) -> UnixTimestamp {
        self.issued_at
    }

    /// Returns the assertion's exclusive expiry.
    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }
}

impl fmt::Debug for DelegatedActorAssertion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DelegatedActorAssertion")
            .field("issuer", &self.issuer)
            .field("subject", &self.subject)
            .field("session_id", &self.session_id)
            .field("assertion_id", &self.assertion_id)
            .field("authenticated_at", &self.authenticated_at)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Sanitized delegated-assertion validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("delegated actor assertion is invalid")]
pub struct DelegatedActorAssertionError;

/// One external assertion resolved against current Core-owned authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegatedActorRequestSnapshot {
    assertion: DelegatedActorAssertion,
    viewer: ViewerDisplayMetadata,
    authorization: AuthorizationContext,
}

impl DelegatedActorRequestSnapshot {
    /// Creates a workspace-consistent delegated request snapshot.
    ///
    /// # Errors
    ///
    /// Rejects anonymous or cross-workspace authorization evidence.
    pub fn new(
        assertion: DelegatedActorAssertion,
        expected_tenant_id: &TenantId,
        viewer: ViewerDisplayMetadata,
        authorization: AuthorizationContext,
    ) -> Result<Self, DelegatedActorRequestSnapshotError> {
        if authorization.tenant_id() != Some(expected_tenant_id)
            || authorization.principal_id().is_none()
        {
            return Err(DelegatedActorRequestSnapshotError);
        }
        Ok(Self {
            assertion,
            viewer,
            authorization,
        })
    }

    /// Returns the verified external assertion metadata.
    #[must_use]
    pub const fn assertion(&self) -> &DelegatedActorAssertion {
        &self.assertion
    }

    /// Returns bounded display-only viewer metadata.
    #[must_use]
    pub const fn viewer(&self) -> &ViewerDisplayMetadata {
        &self.viewer
    }

    /// Returns Core's current workspace-scoped RBAC evidence.
    #[must_use]
    pub const fn authorization(&self) -> &AuthorizationContext {
        &self.authorization
    }
}

/// Sanitized inconsistent delegated snapshot failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("delegated actor request snapshot is inconsistent")]
pub struct DelegatedActorRequestSnapshotError;

/// A verified assertion paired with the exact requested workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveDelegatedActorRequest {
    assertion: DelegatedActorAssertion,
    tenant_id: TenantId,
}

impl ResolveDelegatedActorRequest {
    /// Creates a delegated-actor resolution request.
    #[must_use]
    pub const fn new(assertion: DelegatedActorAssertion, tenant_id: TenantId) -> Self {
        Self {
            assertion,
            tenant_id,
        }
    }

    /// Returns the verified authority assertion.
    #[must_use]
    pub const fn assertion(&self) -> &DelegatedActorAssertion {
        &self.assertion
    }

    /// Returns the requested Core workspace identity.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// Closed durable resolution result for a verified delegated assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolveDelegatedActorOutcome {
    /// The external identity resolved to current Core membership and RBAC.
    Authenticated(Box<DelegatedActorRequestSnapshot>),
    /// The external identity or requested workspace membership does not exist.
    NotFound,
    /// The mapped Core principal is disabled.
    PrincipalDisabled,
    /// The mapped workspace membership is suspended.
    MembershipSuspended,
}

/// A delegated-actor resolution operation.
pub type DelegatedActorResolutionFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<ResolveDelegatedActorOutcome, DelegatedActorResolverError>>
            + Send
            + 'a,
    >,
>;

/// Resolves verified external identities against current Core-owned authority.
pub trait DelegatedActorResolver: fmt::Debug + Send + Sync {
    /// Loads the principal mapping, workspace membership, and RBAC snapshot.
    fn resolve<'a>(
        &'a self,
        request: &'a ResolveDelegatedActorRequest,
    ) -> DelegatedActorResolutionFuture<'a>;
}

/// Sanitized delegated-actor storage failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DelegatedActorResolverError {
    /// Durable identity storage is temporarily unavailable.
    #[error("delegated actor storage is unavailable")]
    Unavailable,
    /// Durable identity or authorization data violates an invariant.
    #[error("durable delegated actor data violates an invariant")]
    CorruptData,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertion_is_short_lived_and_uses_an_https_origin() {
        let subject = Uuid::from_u128(1);
        let session = Uuid::from_u128(2);
        let assertion = Uuid::from_u128(3);
        let valid = DelegatedActorAssertion::new(
            "https://cloud.automata.example",
            subject,
            session,
            assertion,
            UnixTimestamp::from_seconds(90),
            UnixTimestamp::from_seconds(100),
            UnixTimestamp::from_seconds(220),
        );
        assert!(valid.is_ok());
        assert!(
            DelegatedActorAssertion::new(
                "http://cloud.automata.example",
                subject,
                session,
                assertion,
                UnixTimestamp::from_seconds(90),
                UnixTimestamp::from_seconds(100),
                UnixTimestamp::from_seconds(220),
            )
            .is_err()
        );
        assert!(
            DelegatedActorAssertion::new(
                "https://cloud.automata.example",
                subject,
                session,
                assertion,
                UnixTimestamp::from_seconds(90),
                UnixTimestamp::from_seconds(100),
                UnixTimestamp::from_seconds(401),
            )
            .is_err()
        );
    }
}
