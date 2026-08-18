//! Request authentication for short-lived identities delegated by a trusted authority.
//!
//! Delegated assertions are deliberately separate from durable browser and CLI
//! sessions. The issuer authenticates an external actor, while Core remains the
//! authority for principal mapping, workspace membership, and RBAC.

use std::{collections::BTreeSet, fmt, future::Future, pin::Pin};

use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::{
    authorization::{AuthorizationContext, Permission},
    human::PrincipalId,
    human::TenantId,
    management::ManagementActor,
    request_auth::ViewerDisplayMetadata,
    time::UnixTimestamp,
};

const MAX_ASSERTION_LIFETIME_SECONDS: u64 = 5 * 60;
/// Maximum distinct tenant permissions one delegated request may evaluate.
pub const MAX_DELEGATED_TENANT_PERMISSION_CHECKS: usize = 16;

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
    granted_tenant_permissions: BTreeSet<Permission>,
}

/// Minimal current authority retained for one delegated repository mutation.
///
/// Role grants from the request snapshot are deliberately not retained here.
/// Durable mutation adapters must reload the identity mapping, membership,
/// authorization revision, and exact repository permission transactionally.
#[derive(Clone, Eq, PartialEq)]
pub struct DelegatedRepositoryMutationActor {
    assertion: DelegatedActorAssertion,
    tenant_id: TenantId,
    principal_id: PrincipalId,
    authorization_revision: u64,
}

impl DelegatedRepositoryMutationActor {
    /// Reduces one resolved request snapshot to mutation reauthorization evidence.
    ///
    /// # Errors
    ///
    /// Rejects anonymous, revisionless, or cross-workspace snapshots.
    pub fn from_snapshot(
        snapshot: &DelegatedActorRequestSnapshot,
    ) -> Result<Self, DelegatedRepositoryMutationActorError> {
        let authorization = snapshot.authorization();
        let tenant_id = authorization
            .tenant_id()
            .cloned()
            .ok_or(DelegatedRepositoryMutationActorError)?;
        let principal_id = authorization
            .principal_id()
            .cloned()
            .ok_or(DelegatedRepositoryMutationActorError)?;
        let authorization_revision = authorization
            .authorization_revision()
            .filter(|revision| *revision > 0)
            .ok_or(DelegatedRepositoryMutationActorError)?;
        Ok(Self {
            assertion: snapshot.assertion().clone(),
            tenant_id,
            principal_id,
            authorization_revision,
        })
    }

    /// Returns the verified external assertion to recheck transactionally.
    #[must_use]
    pub const fn assertion(&self) -> &DelegatedActorAssertion {
        &self.assertion
    }

    /// Returns the exact Core workspace bounding the mutation.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the current Core principal mapped from the external identity.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    /// Returns the exact Core membership revision resolved for this request.
    #[must_use]
    pub const fn authorization_revision(&self) -> u64 {
        self.authorization_revision
    }
}

impl fmt::Debug for DelegatedRepositoryMutationActor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DelegatedRepositoryMutationActor")
            .field("assertion", &self.assertion)
            .field("tenant_id", &self.tenant_id)
            .field("principal_id", &self.principal_id)
            .field("authorization_revision", &self.authorization_revision)
            .finish()
    }
}

/// Sanitized invalid delegated mutation snapshot.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("delegated repository mutation authority is invalid")]
pub struct DelegatedRepositoryMutationActorError;

/// Current Core-session or externally delegated repository mutation authority.
///
/// The variants remain explicit so storage adapters never interpret an
/// external session identifier as a Core-owned `human_sessions` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositoryMutationActor {
    /// A normal Core-owned browser or CLI session.
    CoreSession(ManagementActor),
    /// A short-lived assertion from an explicitly trusted external authority.
    Delegated(DelegatedRepositoryMutationActor),
}

impl RepositoryMutationActor {
    /// Returns the exact Core workspace bounding the mutation.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        match self {
            Self::CoreSession(actor) => actor.tenant_id(),
            Self::Delegated(actor) => actor.tenant_id(),
        }
    }

    /// Returns the current Core principal authorizing the mutation.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        match self {
            Self::CoreSession(actor) => actor.principal_id(),
            Self::Delegated(actor) => actor.principal_id(),
        }
    }

    /// Returns the exact Core authorization revision resolved at ingress.
    #[must_use]
    pub const fn authorization_revision(&self) -> u64 {
        match self {
            Self::CoreSession(actor) => actor.authorization_revision().value(),
            Self::Delegated(actor) => actor.authorization_revision(),
        }
    }

    /// Returns the authority-local session identity used for event correlation.
    ///
    /// For delegated actors this is external evidence only; storage adapters
    /// must not use it as a Core `human_sessions` identity.
    #[must_use]
    pub fn correlation_session_id(&self) -> String {
        match self {
            Self::CoreSession(actor) => actor.session_id().as_str().to_owned(),
            Self::Delegated(actor) => actor.assertion().session_id().hyphenated().to_string(),
        }
    }

    /// Returns the Core session variant, when the actor owns a Core session.
    #[must_use]
    pub const fn core_session(&self) -> Option<&ManagementActor> {
        match self {
            Self::CoreSession(actor) => Some(actor),
            Self::Delegated(_) => None,
        }
    }

    /// Returns delegated assertion evidence, when supplied by an external authority.
    #[must_use]
    pub const fn delegated(&self) -> Option<&DelegatedRepositoryMutationActor> {
        match self {
            Self::CoreSession(_) => None,
            Self::Delegated(actor) => Some(actor),
        }
    }
}

impl From<ManagementActor> for RepositoryMutationActor {
    fn from(actor: ManagementActor) -> Self {
        Self::CoreSession(actor)
    }
}

impl From<DelegatedRepositoryMutationActor> for RepositoryMutationActor {
    fn from(actor: DelegatedRepositoryMutationActor) -> Self {
        Self::Delegated(actor)
    }
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
        granted_tenant_permissions: BTreeSet<Permission>,
    ) -> Result<Self, DelegatedActorRequestSnapshotError> {
        if authorization.tenant_id() != Some(expected_tenant_id)
            || authorization.principal_id().is_none()
            || granted_tenant_permissions.len() > MAX_DELEGATED_TENANT_PERMISSION_CHECKS
        {
            return Err(DelegatedActorRequestSnapshotError);
        }
        Ok(Self {
            assertion,
            viewer,
            authorization,
            granted_tenant_permissions,
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

    /// Reports whether current Core authority grants one tenant-scoped permission.
    ///
    /// The snapshot contains only permissions explicitly requested during
    /// resolution; absence therefore always fails closed.
    #[must_use]
    pub fn allows_tenant_permission(&self, permission: &Permission) -> bool {
        self.granted_tenant_permissions.contains(permission)
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
    requested_tenant_permissions: BTreeSet<Permission>,
}

impl ResolveDelegatedActorRequest {
    /// Creates a delegated-actor resolution request.
    #[must_use]
    pub const fn new(assertion: DelegatedActorAssertion, tenant_id: TenantId) -> Self {
        Self {
            assertion,
            tenant_id,
            requested_tenant_permissions: BTreeSet::new(),
        }
    }

    /// Adds the bounded tenant-scoped permission set that Core must evaluate.
    ///
    /// # Errors
    ///
    /// Rejects a set larger than the delegated authorization protocol bound.
    pub fn with_tenant_permissions(
        mut self,
        permissions: BTreeSet<Permission>,
    ) -> Result<Self, DelegatedActorPermissionRequestError> {
        if permissions.len() > MAX_DELEGATED_TENANT_PERMISSION_CHECKS {
            return Err(DelegatedActorPermissionRequestError);
        }
        self.requested_tenant_permissions = permissions;
        Ok(self)
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

    /// Returns the exact tenant-scoped permissions requested by the adapter.
    #[must_use]
    pub const fn requested_tenant_permissions(&self) -> &BTreeSet<Permission> {
        &self.requested_tenant_permissions
    }
}

/// Sanitized invalid delegated tenant-permission request.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("delegated tenant permission request is invalid")]
pub struct DelegatedActorPermissionRequestError;

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
