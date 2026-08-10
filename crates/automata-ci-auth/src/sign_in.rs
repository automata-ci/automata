use std::{fmt, future::Future, pin::Pin};

use thiserror::Error;

use crate::{
    github::GithubMembershipObservation,
    human::{AuthenticatedHuman, ProviderIdentityAssertion},
    login::{
        LoginReturnPath, LoginTransactionAccess, LoginTransactionKind, LoginTransactionVersion,
    },
    session::{DurableSession, SessionId, SessionKind, SessionTokenLookup},
    time::UnixTimestamp,
    vault::{ProviderGrantKind, ProviderTokenSet},
};

/// Safe session material prepared before a provider callback is finalized.
///
/// The raw bearer token is deliberately absent. Only its keyed lookup digest
/// crosses the finalizer boundary, so neither this value nor its debug output can
/// disclose the credential that the application must return to the client.
#[derive(Debug, Eq, PartialEq)]
pub struct PendingSessionCandidate {
    session_id: SessionId,
    lookup: SessionTokenLookup,
    kind: SessionKind,
    issued_at: UnixTimestamp,
    idle_expires_at: UnixTimestamp,
    expires_at: UnixTimestamp,
}

impl PendingSessionCandidate {
    /// Creates bounded durable-session metadata without accepting a raw bearer.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical or nil UUID and an inconsistent idle or absolute
    /// lifetime.
    pub(crate) fn new(
        session_id: SessionId,
        lookup: SessionTokenLookup,
        kind: SessionKind,
        issued_at: UnixTimestamp,
        idle_expires_at: UnixTimestamp,
        expires_at: UnixTimestamp,
    ) -> Result<Self, SignInValueError> {
        let parsed = uuid::Uuid::parse_str(session_id.as_str())
            .map_err(|_| SignInValueError::InvalidSessionId)?;
        if parsed.is_nil() || parsed.hyphenated().to_string() != session_id.as_str() {
            return Err(SignInValueError::InvalidSessionId);
        }
        if idle_expires_at <= issued_at || idle_expires_at > expires_at || expires_at <= issued_at {
            return Err(SignInValueError::InvalidSessionLifetime);
        }
        Ok(Self {
            session_id,
            lookup,
            kind,
            issued_at,
            idle_expires_at,
            expires_at,
        })
    }

    #[must_use]
    /// Returns the canonical durable session identity.
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    /// Returns the keyed credential digest used for durable lookup.
    pub const fn lookup(&self) -> &SessionTokenLookup {
        &self.lookup
    }

    #[must_use]
    /// Returns whether this candidate is for a browser or CLI session.
    pub const fn kind(&self) -> SessionKind {
        self.kind
    }

    #[must_use]
    /// Returns when the session candidate was issued.
    pub const fn issued_at(&self) -> UnixTimestamp {
        self.issued_at
    }

    #[must_use]
    /// Returns the initial idle-expiration deadline.
    pub const fn idle_expires_at(&self) -> UnixTimestamp {
        self.idle_expires_at
    }

    #[must_use]
    /// Returns the immutable absolute session deadline.
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }

    /// Consumes the candidate into safe identity, lookup, kind, and lifecycle data.
    pub fn into_parts(
        self,
    ) -> (
        SessionId,
        SessionTokenLookup,
        SessionKind,
        UnixTimestamp,
        UnixTimestamp,
        UnixTimestamp,
    ) {
        (
            self.session_id,
            self.lookup,
            self.kind,
            self.issued_at,
            self.idle_expires_at,
            self.expires_at,
        )
    }
}

/// Exact provider-authenticated request to complete one already-consumed sign-in.
pub struct FinalizeSignIn {
    access: LoginTransactionAccess,
    expected_version: LoginTransactionVersion,
    identity: ProviderIdentityAssertion,
    provider_tokens: ProviderTokenSet,
    membership: GithubMembershipObservation,
    session: PendingSessionCandidate,
    now: UnixTimestamp,
}

impl FinalizeSignIn {
    /// Creates a request whose identity, credential, transaction, and session
    /// dimensions agree before the consumed tombstone is finalized.
    ///
    /// # Errors
    ///
    /// Rejects installation transactions, an incorrect session audience, an
    /// unbound or mismatched provider token, expired token metadata, or
    /// inconsistent issuance/authentication/completion times.
    pub fn new(
        access: LoginTransactionAccess,
        expected_version: LoginTransactionVersion,
        identity: ProviderIdentityAssertion,
        provider_tokens: ProviderTokenSet,
        membership: GithubMembershipObservation,
        session: PendingSessionCandidate,
        now: UnixTimestamp,
    ) -> Result<Self, SignInValueError> {
        if access.tenant_id().is_none() {
            return Err(SignInValueError::InvalidPurpose);
        }
        if expected_version.value() > i64::MAX as u64 - 1 {
            return Err(SignInValueError::InvalidVersion);
        }
        let (expected_kind, expected_grant) = match access.kind() {
            LoginTransactionKind::Browser => (
                SessionKind::Browser,
                ProviderGrantKind::BrowserAuthorizationCode,
            ),
            LoginTransactionKind::Device => {
                (SessionKind::Cli, ProviderGrantKind::DeviceAuthorization)
            }
        };
        if session.kind() != expected_kind {
            return Err(SignInValueError::WrongSessionKind);
        }

        let metadata = provider_tokens.metadata();
        if metadata.grant_kind() != expected_grant {
            return Err(SignInValueError::WrongProviderGrantKind);
        }
        if access.provider_id() != identity.provider_id()
            || metadata.provider_id() != identity.provider_id()
            || metadata.provider_subject() != Some(identity.provider_subject())
        {
            return Err(SignInValueError::IdentityCredentialMismatch);
        }
        let access_expires_at = metadata
            .access_expires_at()
            .ok_or(SignInValueError::InvalidProviderTokenLifetime)?;
        if access_expires_at <= now
            || membership.valid_until() > access_expires_at
            || metadata
                .refresh_expires_at()
                .is_some_and(|refresh_expires_at| refresh_expires_at <= access_expires_at)
        {
            return Err(SignInValueError::InvalidProviderTokenLifetime);
        }
        if session.idle_expires_at() <= now || session.expires_at() <= now {
            return Err(SignInValueError::InvalidSessionLifetime);
        }
        if membership.valid_until() <= now {
            return Err(SignInValueError::ExpiredMembershipObservation);
        }
        if metadata.issued_at() > identity.authenticated_at()
            || identity.authenticated_at() > membership.observed_at()
            || membership.observed_at() > session.issued_at()
            || session.issued_at() > now
        {
            return Err(SignInValueError::InvalidTimeOrder);
        }
        Ok(Self {
            access,
            expected_version,
            identity,
            provider_tokens,
            membership,
            session,
            now,
        })
    }

    #[must_use]
    /// Returns consumed login-transaction authority for the finalization.
    pub const fn access(&self) -> &LoginTransactionAccess {
        &self.access
    }

    #[must_use]
    /// Returns the exact transaction version that must still be current.
    pub const fn expected_version(&self) -> LoginTransactionVersion {
        self.expected_version
    }

    #[must_use]
    /// Returns the stable provider identity assertion.
    pub const fn identity(&self) -> &ProviderIdentityAssertion {
        &self.identity
    }

    #[must_use]
    /// Returns subject-bound provider credentials awaiting encrypted custody.
    pub const fn provider_tokens(&self) -> &ProviderTokenSet {
        &self.provider_tokens
    }

    #[must_use]
    /// Returns the current bounded GitHub membership observation.
    pub const fn membership(&self) -> &GithubMembershipObservation {
        &self.membership
    }

    #[must_use]
    /// Returns the raw-token-free session candidate.
    pub const fn session(&self) -> &PendingSessionCandidate {
        &self.session
    }

    #[must_use]
    /// Returns the completion timestamp used for all lifecycle checks.
    pub const fn now(&self) -> UnixTimestamp {
        self.now
    }

    /// Separates the validated base request from its collided session candidate.
    ///
    /// Persistence adapters use this before attempting finalization so an exact
    /// safe retry can be returned if either durable session key collides.
    #[must_use]
    pub fn into_retry_parts(self) -> (RetryFinalizeSignIn, PendingSessionCandidate) {
        let retry = RetryFinalizeSignIn {
            access: self.access,
            expected_version: self.expected_version,
            identity: self.identity,
            provider_tokens: self.provider_tokens,
            membership: self.membership,
            now: self.now,
        };
        (retry, self.session)
    }
}

impl fmt::Debug for FinalizeSignIn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalizeSignIn")
            .field("access", &self.access)
            .field("expected_version", &self.expected_version)
            .field("identity", &self.identity)
            .field("provider_tokens", &self.provider_tokens)
            .field("membership", &self.membership)
            .field("session", &self.session)
            .field("now", &self.now)
            .finish()
    }
}

/// Exact provider-authenticated state retained across a safe session collision.
///
/// The raw Automata bearer remains absent. This value is linearly owned so one
/// provider token set cannot be fanned out across independent finalizations.
pub struct RetryFinalizeSignIn {
    access: LoginTransactionAccess,
    expected_version: LoginTransactionVersion,
    identity: ProviderIdentityAssertion,
    provider_tokens: ProviderTokenSet,
    membership: GithubMembershipObservation,
    now: UnixTimestamp,
}

impl RetryFinalizeSignIn {
    #[must_use]
    /// Returns consumed login-transaction authority retained for retry.
    pub const fn access(&self) -> &LoginTransactionAccess {
        &self.access
    }

    #[must_use]
    /// Returns the transaction version retained for exact replay.
    pub const fn expected_version(&self) -> LoginTransactionVersion {
        self.expected_version
    }

    #[must_use]
    /// Returns the stable provider identity retained for retry.
    pub const fn identity(&self) -> &ProviderIdentityAssertion {
        &self.identity
    }

    #[must_use]
    /// Returns the linearly owned provider credentials retained for retry.
    pub const fn provider_tokens(&self) -> &ProviderTokenSet {
        &self.provider_tokens
    }

    #[must_use]
    /// Returns the bounded membership observation retained for retry.
    pub const fn membership(&self) -> &GithubMembershipObservation {
        &self.membership
    }

    #[must_use]
    /// Returns the last observed completion timestamp.
    pub const fn now(&self) -> UnixTimestamp {
        self.now
    }

    /// Attaches one newly prepared safe session candidate and revalidates every
    /// flow, provider, subject, lifetime, and time-order invariant at a fresh
    /// completion-time observation that cannot move backwards.
    ///
    /// # Errors
    ///
    /// Returns a sanitized value error if the new candidate does not match the
    /// retained login flow, has expired, or is paired with a regressed clock.
    pub fn with_session(
        self,
        session: PendingSessionCandidate,
        now: UnixTimestamp,
    ) -> Result<FinalizeSignIn, SignInValueError> {
        if now < self.now {
            return Err(SignInValueError::InvalidTimeOrder);
        }
        FinalizeSignIn::new(
            self.access,
            self.expected_version,
            self.identity,
            self.provider_tokens,
            self.membership,
            session,
            now,
        )
    }
}

impl fmt::Debug for RetryFinalizeSignIn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetryFinalizeSignIn")
            .field("access", &self.access)
            .field("expected_version", &self.expected_version)
            .field("identity", &self.identity)
            .field("provider_tokens", &self.provider_tokens)
            .field("membership", &self.membership)
            .field("now", &self.now)
            .finish()
    }
}

/// Exact session-lookup collision that may be retried with a new candidate while
/// the provider-authenticated identity and token set remain in memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingSessionConflict {
    /// The generated durable session UUID already exists.
    SessionId,
    /// The keyed bearer-token digest already exists.
    TokenDigest,
}

/// Durable result of normal sign-in finalization.
#[derive(Debug)]
pub enum FinalizeSignInOutcome {
    /// Identity, authorization revision, provider custody, and session committed atomically.
    Admitted {
        /// Current provider-authenticated principal.
        human: AuthenticatedHuman,
        /// Newly durable raw-token-free session.
        session: Box<DurableSession>,
        /// Current positive durable authorization revision.
        current_authorization_revision: u64,
        /// Validated local path to return the browser to, when present.
        return_path: Option<LoginReturnPath>,
    },
    /// No Automata principal is mapped to the stable provider subject.
    Unmapped,
    /// The mapped principal is disabled.
    PrincipalDisabled,
    /// The current provider membership does not permit sign-in.
    MembershipSuspended,
    /// The consumed login transaction no longer exists.
    NotFound,
    /// The consumed login transaction expired before finalization.
    Expired,
    /// The transaction was already finalized or irreversibly consumed.
    AlreadyConsumed,
    /// The durable login transaction changed from the expected version.
    VersionConflict,
    /// Durable provider identity conflicts with the asserted principal mapping.
    IdentityConflict,
    /// A generated safe session key collided without consuming provider credentials.
    SessionConflict {
        /// Durable key that collided.
        conflict: PendingSessionConflict,
        /// Linearly owned provider-authenticated state available for safe retry.
        retry: Box<RetryFinalizeSignIn>,
    },
}

/// A normal-sign-in finalization operation with sanitized durable outcomes.
pub type SignInFinalizerFuture<'a> =
    Pin<Box<dyn Future<Output = Result<FinalizeSignInOutcome, SignInFinalizerError>> + Send + 'a>>;

/// Replica-safe normal-sign-in completion boundary.
pub trait HumanSignInFinalizer: fmt::Debug + Send + Sync {
    /// Atomically finalizes identity mapping, provider custody, authorization, and session.
    fn finalize(&self, request: FinalizeSignIn) -> SignInFinalizerFuture<'_>;
}

/// Validation failures before a sign-in request reaches durable storage.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SignInValueError {
    /// Normal sign-in was attempted with installation-only transaction authority.
    #[error("normal sign-in requires a tenant-bound login purpose")]
    InvalidPurpose,
    #[error("pending session ID must be a canonical non-nil UUID")]
    /// The proposed durable session ID was nil or noncanonical.
    InvalidSessionId,
    /// Idle or absolute session deadlines were inconsistent or already expired.
    #[error("pending session lifetime is invalid")]
    InvalidSessionLifetime,
    #[error("pending session kind does not match the login flow")]
    /// The browser/device flow did not match the proposed session kind.
    WrongSessionKind,
    /// The provider grant flow did not match the login transaction.
    #[error("provider credential grant kind does not match the login flow")]
    WrongProviderGrantKind,
    #[error("provider identity and subject-bound credentials do not match")]
    /// Provider, subject, or token provenance did not agree exactly.
    IdentityCredentialMismatch,
    /// Provider-token deadlines cannot safely cover finalization.
    #[error("provider credential lifetime is invalid for sign-in finalization")]
    InvalidProviderTokenLifetime,
    #[error("GitHub membership observation expired before sign-in finalization")]
    /// Membership evidence was no longer fresh at finalization.
    ExpiredMembershipObservation,
    /// Provider, identity, membership, session, or completion time regressed.
    #[error("provider, authentication, session, and completion times are inconsistent")]
    InvalidTimeOrder,
    #[error("consumed login transaction version cannot accommodate atomic completion")]
    /// The transaction version cannot be incremented safely in storage.
    InvalidVersion,
}

/// Sanitized storage failures while finalizing a sign-in.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SignInFinalizerError {
    /// The bounded finalization request violates the persistence contract.
    #[error("sign-in finalization request is invalid")]
    InvalidRequest,
    #[error("sign-in finalization storage is unavailable")]
    /// Durable authentication storage is temporarily unavailable.
    Unavailable,
    /// Durable login, identity, token, or session state violates an invariant.
    #[error("durable sign-in state failed an integrity check")]
    IntegrityFailure,
}
