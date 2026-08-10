//! Per-request human authentication resolved from durable session state.
//!
//! This boundary accepts only a keyed session lookup. Raw bearer credentials and
//! login-time role claims are deliberately outside the contract. Implementations
//! must resolve the current principal, membership revision, provider identity,
//! and scoped role grants from one consistent storage snapshot.

use std::{fmt, future::Future, pin::Pin};

use thiserror::Error;

use crate::{
    authorization::AuthorizationContext,
    human::AuthenticatedHuman,
    session::{DurableSession, SessionKind, SessionTokenLookup},
    time::UnixTimestamp,
};

const MAX_VIEWER_DISPLAY_NAME_LENGTH: usize = 1_024;

/// Bounded display metadata derived from a durable principal or provider identity.
///
/// This is presentation metadata only. It is never used as a principal, provider,
/// tenant, role, or authorization identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewerDisplayMetadata {
    display_name: String,
}

impl ViewerDisplayMetadata {
    /// Creates validated viewer display metadata.
    ///
    /// # Errors
    ///
    /// Rejects an empty, oversized, or control-bearing display name.
    pub fn new(display_name: impl Into<String>) -> Result<Self, ViewerDisplayMetadataError> {
        let display_name = display_name.into();
        if display_name.is_empty()
            || display_name.len() > MAX_VIEWER_DISPLAY_NAME_LENGTH
            || display_name.chars().any(char::is_control)
        {
            return Err(ViewerDisplayMetadataError);
        }
        Ok(Self { display_name })
    }

    /// Returns the durable, display-only viewer label.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

/// Sanitized viewer-metadata validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("viewer display metadata is invalid")]
pub struct ViewerDisplayMetadataError;

/// One revision-safe authenticated request snapshot.
///
/// The session contains no raw credential or role claims. `authorization` is
/// reconstructed from current durable role bindings at the same snapshot as the
/// session and identity metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedRequestSnapshot {
    session: DurableSession,
    human: AuthenticatedHuman,
    viewer: ViewerDisplayMetadata,
    authorization: AuthorizationContext,
}

impl AuthenticatedRequestSnapshot {
    /// Creates an identity-consistent authenticated request snapshot.
    ///
    /// # Errors
    ///
    /// Rejects anonymous, cross-tenant, or mismatched principal/provider data.
    pub fn new(
        session: DurableSession,
        human: AuthenticatedHuman,
        viewer: ViewerDisplayMetadata,
        authorization: AuthorizationContext,
    ) -> Result<Self, AuthenticatedRequestSnapshotError> {
        let identity = session.identity();
        if identity.principal_id() != human.principal_id()
            || identity.provider_id() != human.provider_id()
            || identity.provider_subject() != human.provider_subject()
            || authorization.tenant_id() != Some(identity.tenant_id())
            || authorization.principal_id() != Some(identity.principal_id())
        {
            return Err(AuthenticatedRequestSnapshotError);
        }
        Ok(Self {
            session,
            human,
            viewer,
            authorization,
        })
    }

    /// Returns safe durable session metadata.
    #[must_use]
    pub const fn session(&self) -> &DurableSession {
        &self.session
    }

    /// Returns the stable provider-authenticated human identity.
    #[must_use]
    pub const fn human(&self) -> &AuthenticatedHuman {
        &self.human
    }

    /// Returns bounded display-only viewer metadata.
    #[must_use]
    pub const fn viewer(&self) -> &ViewerDisplayMetadata {
        &self.viewer
    }

    /// Returns current tenant/resource-scoped role grants.
    #[must_use]
    pub const fn authorization(&self) -> &AuthorizationContext {
        &self.authorization
    }
}

impl fmt::Debug for AuthenticatedRequestSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let identity = self.session.identity();
        formatter
            .debug_struct("AuthenticatedRequestSnapshot")
            .field("session_id", identity.session_id())
            .field("tenant_id", identity.tenant_id())
            .field("principal_id", identity.principal_id())
            .field("kind", &identity.kind())
            .field("viewer", &self.viewer)
            .field("authorization", &self.authorization)
            .finish_non_exhaustive()
    }
}

/// Sanitized inconsistent-snapshot validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("authenticated request snapshot identities are inconsistent")]
pub struct AuthenticatedRequestSnapshotError;

/// Lookup-only request to authenticate one browser or CLI request.
#[derive(Clone, Eq, PartialEq)]
pub struct ResolveAuthenticatedRequest {
    lookup: SessionTokenLookup,
    expected_kind: SessionKind,
    now: UnixTimestamp,
}

impl ResolveAuthenticatedRequest {
    /// Creates a bounded lookup request for the expected session audience.
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

    /// Returns the keyed digest lookup; it never exposes the raw credential.
    #[must_use]
    pub const fn lookup(&self) -> &SessionTokenLookup {
        &self.lookup
    }

    /// Returns the session kind and audience required by this request surface.
    #[must_use]
    pub const fn expected_kind(&self) -> SessionKind {
        self.expected_kind
    }

    /// Returns the timestamp used for lifecycle validation.
    #[must_use]
    pub const fn now(&self) -> UnixTimestamp {
        self.now
    }
}

impl fmt::Debug for ResolveAuthenticatedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolveAuthenticatedRequest")
            .field("lookup", &"[REDACTED]")
            .field("expected_kind", &self.expected_kind)
            .field("now", &self.now)
            .finish()
    }
}

/// Closed authentication result for a request credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolveAuthenticatedRequestOutcome {
    /// The credential resolved to a current, identity-consistent snapshot.
    Authenticated(Box<AuthenticatedRequestSnapshot>),
    /// No durable session matches the keyed credential digest.
    NotFound,
    /// The session belongs to a different request surface or audience.
    WrongKindOrAudience,
    /// The durable session has been revoked.
    Revoked,
    /// The idle or absolute session deadline has elapsed.
    Expired,
    /// The session cannot yet authenticate ordinary requests.
    NotYetValid,
    /// The durable principal is disabled.
    PrincipalDisabled,
    /// The current provider membership is suspended.
    MembershipSuspended,
    /// The session's authorization snapshot is no longer current.
    AuthorizationRevisionChanged {
        /// Authorization revision retained by the session.
        session_revision: u64,
        /// Current durable authorization revision for the principal.
        current_revision: u64,
    },
}

/// A request-authentication operation with sanitized outcomes and errors.
pub type RequestAuthenticationFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = Result<
                    ResolveAuthenticatedRequestOutcome,
                    RequestAuthenticationResolverError,
                >,
            > + Send
            + 'a,
    >,
>;

/// Object-safe, lookup-only per-request authentication boundary.
pub trait RequestAuthenticationResolver: fmt::Debug + Send + Sync {
    /// Resolves a keyed credential lookup against one current durable snapshot.
    fn resolve<'a>(
        &'a self,
        request: &'a ResolveAuthenticatedRequest,
    ) -> RequestAuthenticationFuture<'a>;
}

/// Sanitized storage or durable-data failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RequestAuthenticationResolverError {
    /// The bounded lookup request violates the resolver contract.
    #[error("request authentication request is invalid")]
    InvalidRequest,
    /// Durable authentication storage is temporarily unavailable.
    #[error("request authentication storage is unavailable")]
    Unavailable,
    /// Durable identity or lifecycle data violates a required invariant.
    #[error("durable request authentication data violates an invariant")]
    CorruptData,
}
