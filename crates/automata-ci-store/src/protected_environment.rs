//! Deployment gates and value-free credential requirements.

use std::{collections::BTreeSet, fmt};

use async_trait::async_trait;
use automata_ci_core::{AttemptId, FencingToken, LeaseId, SecretBinding, Sha256Digest, UnixMillis};
use thiserror::Error;
use uuid::Uuid;

use crate::{StoreError, TenantScope};

/// Maximum distinct names retained for either expression context in one job.
pub const MAX_JOB_CREDENTIAL_REFERENCES: usize = 256;
/// Maximum normalized deployment-environment name length.
pub const MAX_DEPLOYMENT_ENVIRONMENT_NAME_BYTES: usize = 255;

/// Immutable deployment requirement retained at logical admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobEnvironmentRequirement {
    /// The logical job contains no deployment environment.
    None,
    /// Activation must evaluate the template identified by this digest.
    Environment(Sha256Digest),
}

impl JobEnvironmentRequirement {
    pub(crate) const fn kind(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Environment(_) => "environment",
        }
    }

    /// Returns the template digest for an environment-bearing job.
    #[must_use]
    pub const fn template_digest(self) -> Option<Sha256Digest> {
        match self {
            Self::None => None,
            Self::Environment(digest) => Some(digest),
        }
    }
}

/// Exact static `secrets` and `vars` names used by one logical job.
#[derive(Clone, Eq, PartialEq)]
pub struct JobCredentialRequirements {
    environment: JobEnvironmentRequirement,
    secret_names: Vec<String>,
    variable_names: Vec<String>,
}

impl fmt::Debug for JobCredentialRequirements {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobCredentialRequirements")
            .field("environment", &self.environment)
            .field("secret_name_count", &self.secret_names.len())
            .field("variable_name_count", &self.variable_names.len())
            .finish()
    }
}

impl Default for JobCredentialRequirements {
    fn default() -> Self {
        Self {
            environment: JobEnvironmentRequirement::None,
            secret_names: Vec::new(),
            variable_names: Vec::new(),
        }
    }
}

impl JobCredentialRequirements {
    /// Canonicalizes and deduplicates exact static names.
    ///
    /// # Errors
    ///
    /// Rejects unsafe names or a context whose distinct-name budget is exceeded.
    pub fn new(
        environment: JobEnvironmentRequirement,
        secret_names: impl IntoIterator<Item = String>,
        variable_names: impl IntoIterator<Item = String>,
    ) -> Result<Self, ProtectedEnvironmentValueError> {
        Ok(Self {
            environment,
            secret_names: canonical_names(secret_names)?,
            variable_names: canonical_names(variable_names)?,
        })
    }

    /// Returns the immutable deployment requirement.
    #[must_use]
    pub const fn environment(&self) -> JobEnvironmentRequirement {
        self.environment
    }

    /// Returns sorted, unique canonical secret names.
    #[must_use]
    pub fn secret_names(&self) -> &[String] {
        &self.secret_names
    }

    /// Returns sorted, unique canonical variable names.
    #[must_use]
    pub fn variable_names(&self) -> &[String] {
        &self.variable_names
    }
}

/// Case-insensitive deployment environment selected at activation.
#[derive(Clone, Eq, PartialEq)]
pub struct DeploymentEnvironmentName {
    normalized: String,
}

impl fmt::Debug for DeploymentEnvironmentName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeploymentEnvironmentName([REDACTED])")
    }
}

impl DeploymentEnvironmentName {
    /// Validates and normalizes a provider-facing name.
    ///
    /// # Errors
    ///
    /// Rejects empty, surrounding-whitespace, control-bearing, or oversized names.
    pub fn new(value: impl Into<String>) -> Result<Self, ProtectedEnvironmentValueError> {
        let value = value.into();
        if value.is_empty()
            || value.trim() != value
            || value.chars().any(char::is_control)
            || value.len() > MAX_DEPLOYMENT_ENVIRONMENT_NAME_BYTES
        {
            return Err(ProtectedEnvironmentValueError::InvalidEnvironmentName);
        }
        let normalized = value.to_lowercase();
        if normalized.len() > MAX_DEPLOYMENT_ENVIRONMENT_NAME_BYTES {
            return Err(ProtectedEnvironmentValueError::InvalidEnvironmentName);
        }
        Ok(Self { normalized })
    }

    pub(crate) fn normalized(&self) -> &str {
        &self.normalized
    }
}

/// Trust assigned from authenticated event evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobEventTrust {
    /// Source and actor evidence is trusted by policy.
    Trusted,
    /// The job is intentionally treated as untrusted.
    Untrusted,
}

impl JobEventTrust {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Untrusted => "untrusted",
        }
    }
}

/// Closed source classification for secret policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobSourceKind {
    /// Source belongs to the selected repository.
    SameRepository,
    /// Source is a fork pull request.
    Fork,
    /// Source is the provider's dependency-update actor.
    Dependabot,
}

impl JobSourceKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::SameRepository => "same_repository",
            Self::Fork => "fork",
            Self::Dependabot => "dependabot",
        }
    }
}

/// Reusable callers expose secrets only through an explicit reduced binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReusableSecretPermission {
    /// No reusable secret capability is present.
    None,
    /// The caller explicitly forwarded the referenced names.
    Explicit,
}

impl ReusableSecretPermission {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Explicit => "explicit",
        }
    }
}

/// Selection and approval request for one exact concrete attempt.
#[derive(Clone, Eq, PartialEq)]
pub struct PrepareJobEnvironment {
    tenant: TenantScope,
    attempt_id: AttemptId,
    environment: Option<DeploymentEnvironmentName>,
    activation_context_digest: Sha256Digest,
    event_trust: JobEventTrust,
    source_kind: JobSourceKind,
    reusable_secret_permission: ReusableSecretPermission,
    requested_by_principal_id: Option<Uuid>,
    approval_request_id: Uuid,
    requested_at: UnixMillis,
    approval_expires_at: UnixMillis,
}

impl fmt::Debug for PrepareJobEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrepareJobEnvironment")
            .field("tenant", &self.tenant)
            .field("attempt_id", &self.attempt_id)
            .field("has_environment", &self.environment.is_some())
            .field("event_trust", &self.event_trust)
            .field("source_kind", &self.source_kind)
            .finish_non_exhaustive()
    }
}

impl PrepareJobEnvironment {
    /// Constructs a bounded preparation request.
    ///
    /// # Errors
    ///
    /// Returns an error for nil request identities or a non-increasing approval interval.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantScope,
        attempt_id: AttemptId,
        environment: Option<DeploymentEnvironmentName>,
        activation_context_digest: Sha256Digest,
        event_trust: JobEventTrust,
        source_kind: JobSourceKind,
        reusable_secret_permission: ReusableSecretPermission,
        requested_by_principal_id: Option<Uuid>,
        approval_request_id: Uuid,
        requested_at: UnixMillis,
        approval_expires_at: UnixMillis,
    ) -> Result<Self, ProtectedEnvironmentValueError> {
        if approval_request_id.is_nil()
            || requested_by_principal_id.is_some_and(|id| id.is_nil())
            || approval_expires_at <= requested_at
        {
            return Err(ProtectedEnvironmentValueError::InvalidRequest);
        }
        Ok(Self {
            tenant,
            attempt_id,
            environment,
            activation_context_digest,
            event_trust,
            source_kind,
            reusable_secret_permission,
            requested_by_principal_id,
            approval_request_id,
            requested_at,
            approval_expires_at,
        })
    }

    pub(crate) const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }
    pub(crate) const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }
    pub(crate) const fn environment(&self) -> Option<&DeploymentEnvironmentName> {
        self.environment.as_ref()
    }
    pub(crate) const fn activation_context_digest(&self) -> Sha256Digest {
        self.activation_context_digest
    }
    pub(crate) const fn event_trust(&self) -> JobEventTrust {
        self.event_trust
    }
    pub(crate) const fn source_kind(&self) -> JobSourceKind {
        self.source_kind
    }
    pub(crate) const fn reusable_secret_permission(&self) -> ReusableSecretPermission {
        self.reusable_secret_permission
    }
    pub(crate) const fn requested_by_principal_id(&self) -> Option<Uuid> {
        self.requested_by_principal_id
    }
    pub(crate) const fn approval_request_id(&self) -> Uuid {
        self.approval_request_id
    }
    pub(crate) const fn requested_at(&self) -> UnixMillis {
        self.requested_at
    }
    pub(crate) const fn approval_expires_at(&self) -> UnixMillis {
        self.approval_expires_at
    }
}

/// Approval decision for a revision-pinned environment request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvironmentReviewDecision {
    /// Count this reviewer toward the threshold.
    Approve,
    /// Reject the request immediately.
    Reject,
}

impl EnvironmentReviewDecision {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
        }
    }
}

/// One authenticated review of the gate for an attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewJobEnvironment {
    tenant: TenantScope,
    attempt_id: AttemptId,
    principal_id: Uuid,
    decision: EnvironmentReviewDecision,
    decided_at: UnixMillis,
}

impl ReviewJobEnvironment {
    /// Creates a review request with a non-nil reviewer identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the reviewer identity is nil.
    pub fn new(
        tenant: TenantScope,
        attempt_id: AttemptId,
        principal_id: Uuid,
        decision: EnvironmentReviewDecision,
        decided_at: UnixMillis,
    ) -> Result<Self, ProtectedEnvironmentValueError> {
        if principal_id.is_nil() {
            return Err(ProtectedEnvironmentValueError::InvalidRequest);
        }
        Ok(Self {
            tenant,
            attempt_id,
            principal_id,
            decision,
            decided_at,
        })
    }

    pub(crate) const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }
    pub(crate) const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }
    pub(crate) const fn principal_id(&self) -> Uuid {
        self.principal_id
    }
    pub(crate) const fn decision(&self) -> EnvironmentReviewDecision {
        self.decision
    }
    pub(crate) const fn decided_at(&self) -> UnixMillis {
        self.decided_at
    }
}

/// One value-free lease credential for a selected secret.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretLeaseAuthority {
    canonical_name: String,
    grant_id: Uuid,
    authority_digest: Sha256Digest,
    authority_digest_key_id: String,
}

impl fmt::Debug for SecretLeaseAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretLeaseAuthority")
            .field("grant_id", &self.grant_id)
            .finish_non_exhaustive()
    }
}

impl SecretLeaseAuthority {
    /// Creates authority metadata without accepting a plaintext credential.
    ///
    /// # Errors
    ///
    /// Returns an error for a noncanonical name or malformed authority metadata.
    pub fn new(
        name: impl Into<String>,
        grant_id: Uuid,
        authority_digest: Sha256Digest,
        authority_digest_key_id: impl Into<String>,
    ) -> Result<Self, ProtectedEnvironmentValueError> {
        let name = name.into();
        let canonical_name = canonical_name(&name)?;
        let authority_digest_key_id = authority_digest_key_id.into();
        if grant_id.is_nil()
            || authority_digest_key_id.is_empty()
            || authority_digest_key_id.len() > 128
            || !authority_digest_key_id.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-')
            })
        {
            return Err(ProtectedEnvironmentValueError::InvalidRequest);
        }
        Ok(Self {
            canonical_name,
            grant_id,
            authority_digest,
            authority_digest_key_id,
        })
    }

    pub(crate) fn canonical_name(&self) -> &str {
        &self.canonical_name
    }
    pub(crate) const fn grant_id(&self) -> Uuid {
        self.grant_id
    }
    pub(crate) const fn authority_digest(&self) -> Sha256Digest {
        self.authority_digest
    }
    pub(crate) fn authority_digest_key_id(&self) -> &str {
        &self.authority_digest_key_id
    }
}

/// Lease-fenced binding request made after a gate becomes ready.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindLeasedJobSecrets {
    tenant: TenantScope,
    attempt_id: AttemptId,
    lease_id: LeaseId,
    fencing_token: FencingToken,
    authorities: Vec<SecretLeaseAuthority>,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
}

impl BindLeasedJobSecrets {
    /// Validates one authority per canonical selected name.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate authorities or a non-increasing lease interval.
    pub fn new(
        tenant: TenantScope,
        attempt_id: AttemptId,
        lease_id: LeaseId,
        fencing_token: FencingToken,
        authorities: Vec<SecretLeaseAuthority>,
        issued_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, ProtectedEnvironmentValueError> {
        let unique = authorities
            .iter()
            .map(SecretLeaseAuthority::canonical_name)
            .collect::<BTreeSet<_>>();
        if unique.len() != authorities.len() || expires_at <= issued_at {
            return Err(ProtectedEnvironmentValueError::InvalidRequest);
        }
        Ok(Self {
            tenant,
            attempt_id,
            lease_id,
            fencing_token,
            authorities,
            issued_at,
            expires_at,
        })
    }

    pub(crate) const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }
    pub(crate) const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }
    pub(crate) const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }
    pub(crate) const fn fencing_token(&self) -> FencingToken {
        self.fencing_token
    }
    pub(crate) fn authorities(&self) -> &[SecretLeaseAuthority] {
        &self.authorities
    }
    pub(crate) const fn issued_at(&self) -> UnixMillis {
        self.issued_at
    }
    pub(crate) const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

/// Server-owned request to mint the exact opaque bindings for one live lease.
///
/// The caller never supplies secret, grant, provider, authority, or version
/// identities: those are all derived from the durable ready gate and selected
/// versions while the adapter holds the attempt fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueLeasedJobSecretGrants {
    tenant: TenantScope,
    attempt_id: AttemptId,
    lease_id: LeaseId,
    fencing_token: FencingToken,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
}

impl IssueLeasedJobSecretGrants {
    /// Constructs an exact lease-fenced grant issuance request.
    ///
    /// # Errors
    ///
    /// Rejects a non-increasing grant interval.
    pub fn new(
        tenant: TenantScope,
        attempt_id: AttemptId,
        lease_id: LeaseId,
        fencing_token: FencingToken,
        issued_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, ProtectedEnvironmentValueError> {
        if expires_at <= issued_at {
            return Err(ProtectedEnvironmentValueError::InvalidRequest);
        }
        Ok(Self {
            tenant,
            attempt_id,
            lease_id,
            fencing_token,
            issued_at,
            expires_at,
        })
    }

    pub(crate) const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }
    pub(crate) const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }
    pub(crate) const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }
    pub(crate) const fn fencing_token(&self) -> FencingToken {
        self.fencing_token
    }
    pub(crate) const fn issued_at(&self) -> UnixMillis {
        self.issued_at
    }
    pub(crate) const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

/// One canonical secret name and its opaque runtime binding.
#[derive(Clone, Eq, PartialEq)]
pub struct IssuedLeasedJobSecretBinding {
    canonical_name: String,
    binding: SecretBinding,
}

impl IssuedLeasedJobSecretBinding {
    pub(crate) fn new(canonical_name: String, binding: SecretBinding) -> Self {
        Self {
            canonical_name,
            binding,
        }
    }

    /// Returns the canonical name used as the runtime-context key.
    #[must_use]
    pub fn canonical_name(&self) -> &str {
        &self.canonical_name
    }

    /// Returns the value-free workload grant/version locator.
    #[must_use]
    pub const fn binding(&self) -> &SecretBinding {
        &self.binding
    }
}

impl fmt::Debug for IssuedLeasedJobSecretBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedLeasedJobSecretBinding")
            .field("canonical_name", &self.canonical_name)
            .field("binding", &self.binding)
            .finish()
    }
}

/// Durable gate state returned without variable or secret values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobEnvironmentGateState {
    /// A protected environment awaits review.
    Waiting,
    /// Selection is approved and names still need resolution.
    Resolving,
    /// The attempt may be leased.
    Ready,
    /// A reviewer rejected the request.
    Rejected,
    /// The approval lifetime elapsed.
    Expired,
    /// Current policy or workload cancellation invalidated the request.
    Cancelled,
}

/// Invalid protected-environment request metadata.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProtectedEnvironmentValueError {
    /// An expression name was dynamic, reserved, or malformed.
    #[error("credential reference name is not canonical")]
    InvalidReferenceName,
    /// Too many distinct names were retained.
    #[error("credential reference count exceeds the supported limit")]
    TooManyReferences,
    /// Deployment environment name is unsafe or oversized.
    #[error("deployment environment name is invalid")]
    InvalidEnvironmentName,
    /// Identity, interval, or authority metadata is invalid.
    #[error("protected environment request is invalid")]
    InvalidRequest,
}

/// Durable protected-environment operation failure.
#[derive(Debug, Error)]
pub enum ProtectedEnvironmentStoreError {
    /// Storage operation failed.
    #[error(transparent)]
    Operation(#[from] StoreError),
    /// The exact current gate or workload was not found.
    #[error("protected environment workload was not found")]
    NotFound,
    /// Current authority, policy, or fence rejected the request.
    #[error("protected environment authority was rejected")]
    AuthorityRejected,
    /// A replay disagreed with immutable evidence.
    #[error("protected environment request conflicts with durable evidence")]
    Conflict,
    /// Durable rows violate the adapter's closed contract.
    #[error("protected environment data is corrupt")]
    CorruptData,
}

/// Persistence boundary for selection, review, resolution, and lease binding.
#[async_trait]
pub trait ProtectedEnvironmentRepository: fmt::Debug + Send + Sync {
    /// Selects an environment and creates revision-pinned approval evidence when required.
    async fn prepare_job_environment(
        &self,
        request: PrepareJobEnvironment,
    ) -> Result<JobEnvironmentGateState, ProtectedEnvironmentStoreError>;

    /// Appends one reviewer decision and resolves the exact request when decisive.
    async fn review_job_environment(
        &self,
        request: ReviewJobEnvironment,
    ) -> Result<JobEnvironmentGateState, ProtectedEnvironmentStoreError>;

    /// Selects current variable/secret versions or records GitHub-compatible missing names.
    async fn resolve_job_credentials(
        &self,
        tenant: &TenantScope,
        attempt_id: AttemptId,
    ) -> Result<JobEnvironmentGateState, ProtectedEnvironmentStoreError>;

    /// Issues grants and opaque bindings for the attempt's exact live lease fence.
    async fn bind_leased_job_secrets(
        &self,
        request: BindLeasedJobSecrets,
    ) -> Result<(), ProtectedEnvironmentStoreError>;

    /// Derives, issues, and binds every selected managed secret for a live lease.
    async fn issue_leased_job_secret_grants(
        &self,
        request: IssueLeasedJobSecretGrants,
    ) -> Result<Vec<IssuedLeasedJobSecretBinding>, ProtectedEnvironmentStoreError>;
}

fn canonical_names(
    names: impl IntoIterator<Item = String>,
) -> Result<Vec<String>, ProtectedEnvironmentValueError> {
    let names = names
        .into_iter()
        .map(|name| canonical_name(&name))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if names.len() > MAX_JOB_CREDENTIAL_REFERENCES {
        return Err(ProtectedEnvironmentValueError::TooManyReferences);
    }
    Ok(names.into_iter().collect())
}

fn canonical_name(value: &str) -> Result<String, ProtectedEnvironmentValueError> {
    let value = value.to_ascii_uppercase();
    let mut characters = value.chars();
    let valid_first = characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_uppercase());
    if !valid_first
        || value.len() > 255
        || !characters.all(|character| {
            character == '_' || character.is_ascii_uppercase() || character.is_ascii_digit()
        })
        || ["GITHUB_", "ACTIONS_", "RUNNER_", "AUTOMATA_"]
            .iter()
            .any(|prefix| value.starts_with(prefix))
    {
        return Err(ProtectedEnvironmentValueError::InvalidReferenceName);
    }
    Ok(value)
}
