use std::{fmt, future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use thiserror::Error;

use crate::{
    github::GithubMembershipObservation,
    human::{PrincipalId, ProviderId, ProviderIdentityAssertion, ProviderSubject, TenantId},
    login::LoginTransactionId,
    session::{DurableSession, SessionKind},
    sign_in::{PendingSessionCandidate, PendingSessionConflict},
    time::UnixTimestamp,
    vault::{ProviderGrantKind, ProviderTokenSet},
};

const MAX_PROOF_KEY_ID_BYTES: usize = 128;
const MAX_TENANT_DISPLAY_NAME_BYTES: usize = 255;
const MAX_SETUP_LIFETIME_SECONDS: u64 = 3_600;

/// Positive CAS revision for the singleton installation state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct InstallationRevision(u64);

impl InstallationRevision {
    /// Creates a positive revision representable by `PostgreSQL` `BIGINT`.
    /// # Errors
    ///
    /// Rejects zero and values larger than the signed BIGINT maximum.
    pub fn new(value: u64) -> Result<Self, InstallationValueError> {
        if value == 0 || value > 9_223_372_036_854_775_807 {
            return Err(InstallationValueError::InvalidRevision);
        }
        Ok(Self(value))
    }

    #[must_use]
    /// Returns the positive compare-and-swap revision.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Identifier of the keyed digest secret used for the operator bootstrap proof.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct InstallationProofKeyId(String);

impl InstallationProofKeyId {
    /// Creates a portable identifier for the keyed proof-digest key.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or non-portable identifiers.
    pub fn new(value: impl Into<String>) -> Result<Self, InstallationValueError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PROOF_KEY_ID_BYTES
            || !value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.')
            })
        {
            return Err(InstallationValueError::InvalidProofKeyId);
        }
        Ok(Self(value))
    }

    #[must_use]
    /// Returns the stable keyed-digest key identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for InstallationProofKeyId {
    type Error = InstallationValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<InstallationProofKeyId> for String {
    fn from(value: InstallationProofKeyId) -> Self {
        value.0
    }
}

/// Fixed keyed digest of the bootstrap token. The raw token never crosses the
/// repository boundary.
pub struct InstallationProofDigest([u8; 32]);

impl InstallationProofDigest {
    #[must_use]
    /// Wraps a fixed-size keyed digest of the operator proof.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    /// Borrows the keyed digest without exposing the raw bootstrap token.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for InstallationProofDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstallationProofDigest([REDACTED])")
    }
}

impl PartialEq for InstallationProofDigest {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for InstallationProofDigest {}

/// Key identity and digest for one bootstrap-token proof.
#[derive(Debug, Eq, PartialEq)]
pub struct InstallationProof {
    key_id: InstallationProofKeyId,
    digest: InstallationProofDigest,
}

impl InstallationProof {
    #[must_use]
    /// Creates a bootstrap proof from its digest-key identity and digest.
    pub const fn new(key_id: InstallationProofKeyId, digest: InstallationProofDigest) -> Self {
        Self { key_id, digest }
    }

    #[must_use]
    /// Returns the key identity needed to verify the digest.
    pub const fn key_id(&self) -> &InstallationProofKeyId {
        &self.key_id
    }

    #[must_use]
    /// Returns the constant-time comparable keyed digest.
    pub const fn digest(&self) -> &InstallationProofDigest {
        &self.digest
    }
}

/// Exact tenant identity and non-secret display label created by setup.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "InstallationTenantData")]
pub struct InstallationTenant {
    tenant_id: TenantId,
    display_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationTenantData {
    tenant_id: TenantId,
    display_name: String,
}

impl InstallationTenant {
    /// Creates the exact tenant identity and display label armed by an operator.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or control-bearing display labels.
    pub fn new(
        tenant_id: TenantId,
        display_name: impl Into<String>,
    ) -> Result<Self, InstallationValueError> {
        let display_name = display_name.into();
        if display_name.is_empty()
            || display_name.len() > MAX_TENANT_DISPLAY_NAME_BYTES
            || display_name.chars().any(char::is_control)
        {
            return Err(InstallationValueError::InvalidTenantDisplayName);
        }
        Ok(Self {
            tenant_id,
            display_name,
        })
    }

    #[must_use]
    /// Returns the exact tenant identity to create during bootstrap.
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    /// Returns the bounded non-authoritative tenant display label.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

impl TryFrom<InstallationTenantData> for InstallationTenant {
    type Error = InstallationValueError;

    fn try_from(value: InstallationTenantData) -> Result<Self, Self::Error> {
        Self::new(value.tenant_id, value.display_name)
    }
}

/// Public, non-secret state of installation bootstrap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstallationState {
    /// No installation challenge has been armed.
    Unconfigured {
        /// Current singleton state revision.
        revision: InstallationRevision,
    },
    /// An operator-authenticated challenge is ready for one expected identity.
    Armed {
        /// Current singleton state revision.
        revision: InstallationRevision,
        /// Tenant identity the operator authorized creating.
        tenant_id: TenantId,
        /// Authentication provider required for setup.
        provider_id: ProviderId,
        /// Stable provider subject required to complete setup.
        expected_provider_subject: ProviderSubject,
        /// Immutable challenge deadline.
        expires_at: UnixTimestamp,
    },
    /// The challenge is bound to one exact login transaction.
    LoginBound {
        /// Current singleton state revision.
        revision: InstallationRevision,
        /// Tenant identity authorized by the operator.
        tenant_id: TenantId,
        /// Authentication provider required for setup.
        provider_id: ProviderId,
        /// Stable provider subject required to complete setup.
        expected_provider_subject: ProviderSubject,
        /// Sole login transaction allowed to consume the challenge.
        login_transaction_id: LoginTransactionId,
        /// Immutable challenge deadline.
        expires_at: UnixTimestamp,
    },
    /// Installation completed with one immutable initial administrator identity.
    Configured {
        /// Current singleton state revision.
        revision: InstallationRevision,
        /// Created tenant identity.
        tenant_id: TenantId,
        /// Created Automata-owned principal identity.
        principal_id: PrincipalId,
        /// Provider that authenticated the initial principal.
        provider_id: ProviderId,
        /// Stable provider subject bound to the principal.
        provider_subject: ProviderSubject,
        /// Login transaction that completed setup.
        login_transaction_id: LoginTransactionId,
        /// Durable setup completion timestamp.
        configured_at: UnixTimestamp,
    },
}

impl InstallationState {
    #[must_use]
    /// Returns the singleton state's current compare-and-swap revision.
    pub const fn revision(&self) -> InstallationRevision {
        match self {
            Self::Unconfigured { revision }
            | Self::Armed { revision, .. }
            | Self::LoginBound { revision, .. }
            | Self::Configured { revision, .. } => *revision,
        }
    }
}

/// Operator-owned request that arms setup before any anonymous browser request.
#[derive(Debug)]
pub struct ArmInstallationSetup {
    tenant: InstallationTenant,
    proof: InstallationProof,
    expected_provider_id: ProviderId,
    expected_provider_subject: ProviderSubject,
    now: UnixTimestamp,
    expires_at: UnixTimestamp,
}

impl ArmInstallationSetup {
    /// Creates a bounded operator-authorized installation challenge.
    ///
    /// # Errors
    ///
    /// Rejects an empty, expired, or longer-than-one-hour challenge lifetime.
    pub fn new(
        tenant: InstallationTenant,
        proof: InstallationProof,
        expected_provider_id: ProviderId,
        expected_provider_subject: ProviderSubject,
        now: UnixTimestamp,
        expires_at: UnixTimestamp,
    ) -> Result<Self, InstallationValueError> {
        let lifetime = expires_at
            .as_seconds()
            .checked_sub(now.as_seconds())
            .ok_or(InstallationValueError::InvalidLifetime)?;
        if lifetime == 0 || lifetime > MAX_SETUP_LIFETIME_SECONDS {
            return Err(InstallationValueError::InvalidLifetime);
        }
        Ok(Self {
            tenant,
            proof,
            expected_provider_id,
            expected_provider_subject,
            now,
            expires_at,
        })
    }

    /// Consumes the request into tenant, proof, expected identity, and lifetime.
    pub fn into_parts(
        self,
    ) -> (
        InstallationTenant,
        InstallationProof,
        ProviderId,
        ProviderSubject,
        UnixTimestamp,
        UnixTimestamp,
    ) {
        (
            self.tenant,
            self.proof,
            self.expected_provider_id,
            self.expected_provider_subject,
            self.now,
            self.expires_at,
        )
    }
}

/// Proof-authorized request that binds the one setup login transaction.
#[derive(Debug)]
pub struct BindInstallationLogin {
    expected_revision: InstallationRevision,
    proof: InstallationProof,
    login_transaction_id: LoginTransactionId,
    now: UnixTimestamp,
}

impl BindInstallationLogin {
    #[must_use]
    /// Creates an exact revision- and proof-bound login binding request.
    pub const fn new(
        expected_revision: InstallationRevision,
        proof: InstallationProof,
        login_transaction_id: LoginTransactionId,
        now: UnixTimestamp,
    ) -> Self {
        Self {
            expected_revision,
            proof,
            login_transaction_id,
            now,
        }
    }

    /// Consumes the request into its revision, proof, transaction, and timestamp.
    pub fn into_parts(
        self,
    ) -> (
        InstallationRevision,
        InstallationProof,
        LoginTransactionId,
        UnixTimestamp,
    ) {
        (
            self.expected_revision,
            self.proof,
            self.login_transaction_id,
            self.now,
        )
    }
}

/// Linear provider-authenticated evidence for installation completion.
#[derive(Debug)]
pub struct InstallationProviderAuthentication {
    login_transaction_id: LoginTransactionId,
    identity: ProviderIdentityAssertion,
    provider_tokens: ProviderTokenSet,
    membership: GithubMembershipObservation,
}

impl InstallationProviderAuthentication {
    /// Binds the exchanged provider token to its stable authenticated subject.
    ///
    /// # Errors
    ///
    /// Rejects provider or subject disagreement.
    pub fn new(
        login_transaction_id: LoginTransactionId,
        identity: ProviderIdentityAssertion,
        provider_tokens: ProviderTokenSet,
        membership: GithubMembershipObservation,
    ) -> Result<Self, InstallationValueError> {
        if identity.provider_id() != provider_tokens.metadata().provider_id() {
            return Err(InstallationValueError::IdentityCredentialMismatch);
        }
        let provider_tokens = provider_tokens
            .bind_provider_subject(identity.provider_subject().clone())
            .map_err(|_| InstallationValueError::IdentityCredentialMismatch)?;
        Ok(Self {
            login_transaction_id,
            identity,
            provider_tokens,
            membership,
        })
    }
}

/// Final provider-authenticated setup request.
#[derive(Debug)]
pub struct CompleteInstallationSetup {
    expected_revision: InstallationRevision,
    tenant: InstallationTenant,
    authentication: InstallationProviderAuthentication,
    session: PendingSessionCandidate,
    now: UnixTimestamp,
}

impl CompleteInstallationSetup {
    /// Binds exchanged credentials to the stable provider identity assertion.
    ///
    /// # Errors
    ///
    /// Rejects mismatched providers or subjects and inconsistent issuance,
    /// authentication, or completion times.
    pub fn new(
        expected_revision: InstallationRevision,
        tenant: InstallationTenant,
        authentication: InstallationProviderAuthentication,
        session: PendingSessionCandidate,
        now: UnixTimestamp,
    ) -> Result<Self, InstallationValueError> {
        let identity = &authentication.identity;
        let provider_tokens = &authentication.provider_tokens;
        let membership = &authentication.membership;
        let metadata = provider_tokens.metadata();
        if identity.provider_id() != metadata.provider_id()
            || metadata.issued_at() > identity.authenticated_at()
        {
            return Err(InstallationValueError::IdentityCredentialMismatch);
        }
        let access_expires_at = metadata
            .access_expires_at()
            .ok_or(InstallationValueError::InvalidProviderTokenLifetime)?;
        if access_expires_at <= now
            || membership.valid_until() > access_expires_at
            || metadata
                .refresh_expires_at()
                .is_some_and(|refresh_expires_at| refresh_expires_at <= access_expires_at)
        {
            return Err(InstallationValueError::InvalidProviderTokenLifetime);
        }
        let expected_kind = match metadata.grant_kind() {
            ProviderGrantKind::BrowserAuthorizationCode => SessionKind::Browser,
            ProviderGrantKind::DeviceAuthorization => SessionKind::Cli,
        };
        if session.kind() != expected_kind {
            return Err(InstallationValueError::WrongSessionKind);
        }
        if session.idle_expires_at() <= now || session.expires_at() <= now {
            return Err(InstallationValueError::InvalidSessionLifetime);
        }
        if membership.valid_until() <= now {
            return Err(InstallationValueError::ExpiredMembershipObservation);
        }
        if identity.authenticated_at() > membership.observed_at()
            || membership.observed_at() > session.issued_at()
            || session.issued_at() > now
        {
            return Err(InstallationValueError::InvalidTimeOrder);
        }
        Ok(Self {
            expected_revision,
            tenant,
            authentication,
            session,
            now,
        })
    }

    /// Separates the linear authenticated request from its collided session.
    #[must_use]
    pub fn into_retry_parts(self) -> (RetryCompleteInstallationSetup, PendingSessionCandidate) {
        let retry = RetryCompleteInstallationSetup {
            expected_revision: self.expected_revision,
            tenant: self.tenant,
            authentication: self.authentication,
            now: self.now,
        };
        (retry, self.session)
    }
}

/// Provider-authenticated installation state retained across a session collision.
pub struct RetryCompleteInstallationSetup {
    expected_revision: InstallationRevision,
    tenant: InstallationTenant,
    authentication: InstallationProviderAuthentication,
    now: UnixTimestamp,
}

impl RetryCompleteInstallationSetup {
    #[must_use]
    /// Returns the exact installation revision retained for retry.
    pub const fn expected_revision(&self) -> InstallationRevision {
        self.expected_revision
    }

    #[must_use]
    /// Returns the exact tenant authorized by the operator.
    pub const fn tenant(&self) -> &InstallationTenant {
        &self.tenant
    }

    #[must_use]
    /// Returns the sole login transaction bound to installation.
    pub const fn login_transaction_id(&self) -> &LoginTransactionId {
        &self.authentication.login_transaction_id
    }

    #[must_use]
    /// Returns the stable provider identity retained for retry.
    pub const fn identity(&self) -> &ProviderIdentityAssertion {
        &self.authentication.identity
    }

    #[must_use]
    /// Returns the linearly owned provider credentials retained for retry.
    pub const fn provider_tokens(&self) -> &ProviderTokenSet {
        &self.authentication.provider_tokens
    }

    #[must_use]
    /// Returns the bounded membership evidence retained for retry.
    pub const fn membership(&self) -> &GithubMembershipObservation {
        &self.authentication.membership
    }

    #[must_use]
    /// Returns the last observed setup-completion timestamp.
    pub const fn now(&self) -> UnixTimestamp {
        self.now
    }

    /// Attaches a replacement candidate while retaining the exact provider data.
    ///
    /// # Errors
    ///
    /// Rejects a regressed completion time or any now-invalid credential,
    /// membership, flow, or session invariant.
    pub fn with_session(
        self,
        session: PendingSessionCandidate,
        now: UnixTimestamp,
    ) -> Result<CompleteInstallationSetup, InstallationValueError> {
        if now < self.now {
            return Err(InstallationValueError::InvalidTimeOrder);
        }
        CompleteInstallationSetup::new(
            self.expected_revision,
            self.tenant,
            self.authentication,
            session,
            now,
        )
    }
}

impl fmt::Debug for RetryCompleteInstallationSetup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetryCompleteInstallationSetup")
            .field("expected_revision", &self.expected_revision)
            .field("tenant", &self.tenant)
            .field(
                "login_transaction_id",
                &self.authentication.login_transaction_id,
            )
            .field("identity", &self.authentication.identity)
            .field("provider_tokens", &self.authentication.provider_tokens)
            .field("membership", &self.authentication.membership)
            .field("now", &self.now)
            .finish()
    }
}

/// Stable identities created by successful installation completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedInstallation {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    installation_revision: InstallationRevision,
    session: Box<DurableSession>,
}

impl CompletedInstallation {
    /// Creates the committed bootstrap result used for immediate session issuance.
    ///
    /// # Errors
    ///
    /// Rejects a session for another tenant or principal, or a revision that
    /// cannot be represented by the durable store.
    pub fn new(
        tenant_id: TenantId,
        principal_id: PrincipalId,
        installation_revision: InstallationRevision,
        session: Box<DurableSession>,
    ) -> Result<Self, InstallationValueError> {
        if session.identity().tenant_id() != &tenant_id
            || session.identity().principal_id() != &principal_id
            || session.authorization_revision() > i64::MAX as u64
        {
            return Err(InstallationValueError::InvalidCompletedSession);
        }
        Ok(Self {
            tenant_id,
            principal_id,
            installation_revision,
            session,
        })
    }

    #[must_use]
    /// Returns the tenant created by installation.
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    /// Returns the initial Automata-owned principal.
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    #[must_use]
    /// Returns the committed singleton installation revision.
    pub const fn revision(&self) -> InstallationRevision {
        self.installation_revision
    }

    /// Current tenant-membership authorization revision for immediate session
    /// issuance after bootstrap commits.
    #[must_use]
    pub const fn authorization_revision(&self) -> u64 {
        self.session.authorization_revision()
    }

    #[must_use]
    /// Borrows the raw-token-free session committed during setup.
    pub const fn session(&self) -> &DurableSession {
        &self.session
    }

    #[must_use]
    /// Consumes the installation result into its durable session.
    pub fn into_session(self) -> Box<DurableSession> {
        self.session
    }
}

/// Atomic installation completion result.
#[derive(Debug)]
pub enum CompleteInstallationOutcome {
    /// Installation and the initial session committed atomically.
    Completed(CompletedInstallation),
    /// A generated safe session key collided before credentials were consumed.
    SessionConflict {
        /// Durable key that collided.
        conflict: PendingSessionConflict,
        /// Provider-authenticated setup state retained for safe retry.
        retry: Box<RetryCompleteInstallationSetup>,
    },
}

/// An installation-repository operation with sanitized outcomes.
pub type InstallationRepositoryFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, InstallationRepositoryError>> + Send + 'a>>;

/// Durable, replica-safe installation bootstrap boundary.
pub trait InstallationRepository: fmt::Debug + Send + Sync {
    /// Loads the public singleton installation state.
    fn load(&self) -> InstallationRepositoryFuture<'_, InstallationState>;

    /// Arms one bounded operator-authorized setup challenge.
    fn arm(
        &self,
        request: ArmInstallationSetup,
    ) -> InstallationRepositoryFuture<'_, InstallationState>;

    /// Binds an armed challenge to one exact login transaction.
    fn bind_login(
        &self,
        request: BindInstallationLogin,
    ) -> InstallationRepositoryFuture<'_, InstallationState>;

    /// Atomically creates tenant, principal, provider custody, roles, and session.
    fn complete(
        &self,
        request: CompleteInstallationSetup,
    ) -> InstallationRepositoryFuture<'_, CompleteInstallationOutcome>;
}

/// Sanitized durable outcomes while operating the installation repository.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InstallationRepositoryError {
    /// The bounded setup request violates the repository contract.
    #[error("installation setup request is invalid")]
    InvalidRequest,
    #[error("installation setup is not armed")]
    /// No operator-authorized setup challenge is currently armed.
    NotArmed,
    /// The supplied keyed bootstrap proof did not match.
    #[error("installation bootstrap proof was rejected")]
    ProofRejected,
    #[error("installation setup challenge expired")]
    /// The armed setup challenge passed its immutable deadline.
    Expired,
    /// A different login transaction is already bound to the challenge.
    #[error("installation setup already has a different login transaction")]
    AlreadyBound,
    #[error("installation is already configured")]
    /// The singleton installation has already completed.
    AlreadyConfigured,
    /// The singleton state changed from the expected revision.
    #[error("installation setup state changed concurrently")]
    VersionConflict,
    #[error("installation identity or tenant conflicts with durable state")]
    /// Requested tenant or provider identity conflicts with durable state.
    IdentityConflict,
    /// Encrypted provider-token custody could not complete atomically.
    #[error("installation credential custody failed")]
    CredentialCustody,
    #[error("installation storage is unavailable")]
    /// Durable installation storage is temporarily unavailable.
    Unavailable,
    /// Durable setup state violates a required invariant.
    #[error("durable installation state violates an invariant")]
    CorruptData,
}

/// Validation failures for installation values and lifecycle requests.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InstallationValueError {
    /// The compare-and-swap revision was zero or outside signed storage range.
    #[error("installation revision is invalid")]
    InvalidRevision,
    #[error("installation proof key ID is invalid")]
    /// The digest-key identifier was empty, oversized, or non-portable.
    InvalidProofKeyId,
    /// The tenant display label was empty, oversized, or control-bearing.
    #[error("installation tenant display name is invalid")]
    InvalidTenantDisplayName,
    #[error("installation challenge lifetime is invalid")]
    /// The setup challenge lifetime was empty, expired, or too long.
    InvalidLifetime,
    /// Provider identity and credential provenance did not agree exactly.
    #[error("provider identity and credential metadata do not match")]
    IdentityCredentialMismatch,
    #[error("provider credential lifetime is invalid for installation completion")]
    /// Provider credentials cannot safely cover installation completion.
    InvalidProviderTokenLifetime,
    /// The provider flow did not match the proposed browser or CLI session.
    #[error("pending session kind does not match the installation login flow")]
    WrongSessionKind,
    #[error("pending installation session lifetime is invalid")]
    /// The proposed session was expired or had inconsistent deadlines.
    InvalidSessionLifetime,
    /// Membership evidence was no longer fresh at completion.
    #[error("GitHub membership observation expired before installation completion")]
    ExpiredMembershipObservation,
    #[error("provider authentication, membership, and completion times are inconsistent")]
    /// Authentication, membership, session, or completion time regressed.
    InvalidTimeOrder,
    /// The completed session did not match the created tenant and principal.
    #[error("completed installation session does not match its tenant and principal")]
    InvalidCompletedSession,
}
