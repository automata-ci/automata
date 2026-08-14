use std::num::{NonZeroU16, NonZeroU64};

use async_trait::async_trait;
use automata_ci_blob::BlobDescriptor;
use automata_ci_core::{JobId, RunId, Sha256Digest, UnixMillis};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    GithubRepositoryName, GithubScheduleFireId, GithubServerServiceAuthoritySelector,
    ProviderConnectionId, ProviderDeliveryId, ProviderInstallationId, ProviderRepositoryId,
    RepositoryId, RepositoryOperationError, TenantScope,
};

/// Maximum number of outbox claims for one desired projection revision.
pub const MAX_GITHUB_CHECK_PROJECTION_ATTEMPTS: u16 = 64;
/// Maximum duration of one exclusive projection claim.
pub const MAX_GITHUB_CHECK_PROJECTION_CLAIM_MILLIS: i64 = 15 * 60 * 1_000;
/// Maximum delay before retrying a projection operation.
pub const MAX_GITHUB_CHECK_PROJECTION_RETRY_MILLIS: i64 = 24 * 60 * 60 * 1_000;
/// Maximum grace after a create issue deadline before reconciliation is eligible.
pub const MAX_GITHUB_CHECK_CREATE_RECONCILE_GRACE_MILLIS: i64 = 7 * 60 * 1_000;

const MAX_CHECK_NAME_BYTES: usize = 255;
const MAX_SUBJECT_KEY_BYTES: usize = 1_024;
const MAX_FAILURE_KIND_BYTES: usize = 128;

macro_rules! uuid_identity {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Constructs a non-nil durable UUID identity.
            ///
            /// # Errors
            ///
            /// Rejects the nil UUID sentinel.
            pub fn from_uuid(value: Uuid) -> Result<Self, GithubCheckValueError> {
                if value.is_nil() {
                    return Err(GithubCheckValueError::NilUuid($field));
                }
                Ok(Self(value))
            }

            /// Returns the durable UUID value.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }
    };
}

uuid_identity!(/// Durable identity of one pre-admission Check subject.
    GithubCheckSubjectId, "GitHub Check subject ID");
uuid_identity!(/// Durable identity of one Checks projection worker.
    GithubCheckProjectionWorkerId, "GitHub Check projection worker ID");

macro_rules! positive_github_id {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// Constructs a positive GitHub identifier within the signed 64-bit storage boundary.
            ///
            /// # Errors
            ///
            /// Rejects zero and values larger than `i64::MAX`.
            pub fn new(value: u64) -> Result<Self, GithubCheckValueError> {
                let value = NonZeroU64::new(value)
                    .ok_or(GithubCheckValueError::InvalidNumericId($field))?;
                if i64::try_from(value.get()).is_err() {
                    return Err(GithubCheckValueError::InvalidNumericId($field));
                }
                Ok(Self(value))
            }

            /// Returns the positive GitHub identifier.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0.get()
            }

        }
    };
}

positive_github_id!(/// Positive GitHub App identifier.
    GithubCheckAppId, "GitHub Check App ID");
positive_github_id!(/// Positive GitHub Check Suite identifier.
    GithubCheckSuiteId, "GitHub Check Suite ID");
positive_github_id!(/// Positive GitHub Check Run identifier.
    GithubCheckRunId, "GitHub Check Run ID");

/// Exact 20-byte Git commit object identity used by GitHub Checks.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubCheckHeadSha([u8; 20]);

impl GithubCheckHeadSha {
    /// Constructs an exact Git commit identity.
    ///
    /// # Errors
    ///
    /// Rejects the all-zero sentinel.
    pub fn new(value: [u8; 20]) -> Result<Self, GithubCheckValueError> {
        if value == [0; 20] {
            return Err(GithubCheckValueError::InvalidHeadSha);
        }
        Ok(Self(value))
    }

    /// Rehydrates an exact Git commit identity from durable bytes.
    ///
    /// # Errors
    ///
    /// Rejects values that are not exactly 20 bytes or are the all-zero sentinel.
    pub fn try_from_slice(value: &[u8]) -> Result<Self, GithubCheckValueError> {
        let bytes =
            <[u8; 20]>::try_from(value).map_err(|_| GithubCheckValueError::InvalidHeadSha)?;
        if bytes == [0; 20] {
            return Err(GithubCheckValueError::InvalidHeadSha);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact raw Git object identity.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 20] {
        self.0
    }
}

impl std::fmt::Debug for GithubCheckHeadSha {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GithubCheckHeadSha([REDACTED])")
    }
}

/// Bounded printable GitHub Check Run name.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubCheckName(String);

impl GithubCheckName {
    /// Constructs a printable UTF-8 Check Run name.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, edge-whitespace, or control-bearing names.
    pub fn new(value: impl Into<String>) -> Result<Self, GithubCheckValueError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_CHECK_NAME_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(GithubCheckValueError::InvalidCheckName);
        }
        Ok(Self(value))
    }

    /// Derives GitHub's bounded Check name from an evaluated Automata job name.
    ///
    /// # Errors
    ///
    /// Rejects names that are empty after trimming or contain control characters.
    /// Edge whitespace is removed only from the provider projection; names over
    /// the provider byte ceiling are truncated at a UTF-8 scalar boundary.
    pub fn from_job_display_name(value: &str) -> Result<Self, GithubCheckValueError> {
        if value.chars().any(char::is_control) {
            return Err(GithubCheckValueError::InvalidCheckName);
        }
        let value = value.trim();
        if value.is_empty() {
            return Err(GithubCheckValueError::InvalidCheckName);
        }
        let mut end = value.len().min(MAX_CHECK_NAME_BYTES);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        let bounded = value[..end].trim_end();
        Self::new(bounded.to_owned())
    }

    /// Returns the validated provider-facing name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for GithubCheckName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GithubCheckName([REDACTED])")
    }
}

/// Stable delivery-local key for the workflow or aggregate represented by a Check.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubCheckSubjectKey(String);

impl GithubCheckSubjectKey {
    /// Constructs a safe relative subject key, normally a workflow path.
    ///
    /// # Errors
    ///
    /// Rejects unsafe, empty, untrimmed, control-bearing, or oversized values.
    pub fn new(value: impl Into<String>) -> Result<Self, GithubCheckValueError> {
        let value = value.into();
        validate_text(&value, MAX_SUBJECT_KEY_BYTES, "GitHub Check subject key")?;
        if value.starts_with('/')
            || value.contains('\\')
            || value.contains("//")
            || value
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
        {
            return Err(GithubCheckValueError::InvalidSubjectKey);
        }
        Ok(Self(value))
    }

    /// Returns the durable subject key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for GithubCheckSubjectKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GithubCheckSubjectKey([REDACTED])")
    }
}

/// Closed durable origin of a GitHub Check subject.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GithubCheckSubjectOrigin {
    /// An authenticated webhook delivery and its signed evidence.
    ProviderDelivery(ProviderDeliveryId),
    /// A fenced invocation from an immutable schedule registry revision.
    ScheduledFire(GithubScheduleFireId),
    /// A fresh physical attempt derived from one exact terminal workflow run.
    WorkflowRerun(RunId),
}

/// Exact immutable routing and provider identity of a pre-admission Check subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubCheckSubjectIdentity {
    tenant: TenantScope,
    repository_id: RepositoryId,
    origin: GithubCheckSubjectOrigin,
    subject_key: GithubCheckSubjectKey,
    connection_id: ProviderConnectionId,
    installation_id: ProviderInstallationId,
    github_repository_id: ProviderRepositoryId,
    github_repository_name: GithubRepositoryName,
    app_id: GithubCheckAppId,
    head_sha: GithubCheckHeadSha,
    name: GithubCheckName,
}

impl GithubCheckSubjectIdentity {
    /// Constructs the complete server-owned identity established before admission.
    ///
    /// # Errors
    ///
    /// Rejects a nil Automata repository UUID.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantScope,
        repository_id: RepositoryId,
        delivery_id: ProviderDeliveryId,
        subject_key: GithubCheckSubjectKey,
        connection_id: ProviderConnectionId,
        installation_id: ProviderInstallationId,
        github_repository_id: ProviderRepositoryId,
        github_repository_name: GithubRepositoryName,
        app_id: GithubCheckAppId,
        head_sha: GithubCheckHeadSha,
        name: GithubCheckName,
    ) -> Result<Self, GithubCheckValueError> {
        if repository_id.as_uuid().is_nil() {
            return Err(GithubCheckValueError::NilUuid("GitHub Check repository ID"));
        }
        Ok(Self {
            tenant,
            repository_id,
            origin: GithubCheckSubjectOrigin::ProviderDelivery(delivery_id),
            subject_key,
            connection_id,
            installation_id,
            github_repository_id,
            github_repository_name,
            app_id,
            head_sha,
            name,
        })
    }

    /// Constructs the complete identity of a fenced scheduled invocation.
    ///
    /// # Errors
    ///
    /// Rejects a nil Automata repository UUID.
    #[allow(clippy::too_many_arguments)]
    pub fn new_scheduled(
        tenant: TenantScope,
        repository_id: RepositoryId,
        fire_id: GithubScheduleFireId,
        subject_key: GithubCheckSubjectKey,
        connection_id: ProviderConnectionId,
        installation_id: ProviderInstallationId,
        github_repository_id: ProviderRepositoryId,
        github_repository_name: GithubRepositoryName,
        app_id: GithubCheckAppId,
        head_sha: GithubCheckHeadSha,
        name: GithubCheckName,
    ) -> Result<Self, GithubCheckValueError> {
        if repository_id.as_uuid().is_nil() {
            return Err(GithubCheckValueError::NilUuid("GitHub Check repository ID"));
        }
        Ok(Self {
            tenant,
            repository_id,
            origin: GithubCheckSubjectOrigin::ScheduledFire(fire_id),
            subject_key,
            connection_id,
            installation_id,
            github_repository_id,
            github_repository_name,
            app_id,
            head_sha,
            name,
        })
    }

    /// Constructs the provider identity of a fresh workflow-rerun Check.
    ///
    /// # Errors
    ///
    /// Rejects a nil Automata repository or rerun UUID.
    #[allow(clippy::too_many_arguments)]
    pub fn new_rerun(
        tenant: TenantScope,
        repository_id: RepositoryId,
        rerun_run_id: RunId,
        subject_key: GithubCheckSubjectKey,
        connection_id: ProviderConnectionId,
        installation_id: ProviderInstallationId,
        github_repository_id: ProviderRepositoryId,
        github_repository_name: GithubRepositoryName,
        app_id: GithubCheckAppId,
        head_sha: GithubCheckHeadSha,
        name: GithubCheckName,
    ) -> Result<Self, GithubCheckValueError> {
        if repository_id.as_uuid().is_nil() {
            return Err(GithubCheckValueError::NilUuid("GitHub Check repository ID"));
        }
        if rerun_run_id.as_uuid().is_nil() {
            return Err(GithubCheckValueError::NilUuid("GitHub Check rerun run ID"));
        }
        Ok(Self {
            tenant,
            repository_id,
            origin: GithubCheckSubjectOrigin::WorkflowRerun(rerun_run_id),
            subject_key,
            connection_id,
            installation_id,
            github_repository_id,
            github_repository_name,
            app_id,
            head_sha,
            name,
        })
    }

    /// Returns the authenticated tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }
    /// Returns the Automata repository identity.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }
    /// Returns the closed durable subject origin.
    #[must_use]
    pub const fn origin(&self) -> GithubCheckSubjectOrigin {
        self.origin
    }
    /// Returns the authenticated delivery identity, when delivery-originated.
    #[must_use]
    pub const fn delivery_id(&self) -> Option<ProviderDeliveryId> {
        match self.origin {
            GithubCheckSubjectOrigin::ProviderDelivery(delivery_id) => Some(delivery_id),
            GithubCheckSubjectOrigin::ScheduledFire(_)
            | GithubCheckSubjectOrigin::WorkflowRerun(_) => None,
        }
    }
    /// Returns the scheduled fire identity, when schedule-originated.
    #[must_use]
    pub const fn schedule_fire_id(&self) -> Option<GithubScheduleFireId> {
        match self.origin {
            GithubCheckSubjectOrigin::ProviderDelivery(_)
            | GithubCheckSubjectOrigin::WorkflowRerun(_) => None,
            GithubCheckSubjectOrigin::ScheduledFire(fire_id) => Some(fire_id),
        }
    }
    /// Returns the physical rerun identity, when rerun-originated.
    #[must_use]
    pub const fn rerun_run_id(&self) -> Option<RunId> {
        match self.origin {
            GithubCheckSubjectOrigin::ProviderDelivery(_)
            | GithubCheckSubjectOrigin::ScheduledFire(_) => None,
            GithubCheckSubjectOrigin::WorkflowRerun(run_id) => Some(run_id),
        }
    }
    /// Returns the delivery-local subject key.
    #[must_use]
    pub const fn subject_key(&self) -> &GithubCheckSubjectKey {
        &self.subject_key
    }
    /// Returns the provider connection identity.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }
    /// Returns the provider installation identity.
    #[must_use]
    pub const fn installation_id(&self) -> ProviderInstallationId {
        self.installation_id
    }
    /// Returns the numeric GitHub repository identity.
    #[must_use]
    pub const fn github_repository_id(&self) -> ProviderRepositoryId {
        self.github_repository_id
    }
    /// Returns the exact canonical provider `owner/repository` spelling.
    #[must_use]
    pub const fn github_repository_name(&self) -> &GithubRepositoryName {
        &self.github_repository_name
    }
    /// Returns the GitHub App identity.
    #[must_use]
    pub const fn app_id(&self) -> GithubCheckAppId {
        self.app_id
    }
    /// Returns the exact Git commit identity.
    #[must_use]
    pub const fn head_sha(&self) -> GithubCheckHeadSha {
        self.head_sha
    }
    /// Returns the provider-facing Check Run name.
    #[must_use]
    pub const fn name(&self) -> &GithubCheckName {
        &self.name
    }
}

/// Desired terminal Check conclusion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubCheckConclusion {
    /// Human or operator action is required before the result is trustworthy.
    ActionRequired,
    /// The workflow was cancelled.
    Cancelled,
    /// The workflow or server failed.
    Failure,
    /// The workflow succeeded.
    Success,
    /// The workflow was intentionally skipped.
    Skipped,
    /// The workflow timed out.
    TimedOut,
}

/// Server-owned reason for terminalizing one desired Check projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubCheckTerminalCause {
    /// Trustworthy workflow success.
    WorkflowSuccess,
    /// Trustworthy workflow skip.
    WorkflowSkipped,
    /// Trustworthy workflow failure, including compile or admission failure.
    WorkflowFailure,
    /// Trustworthy workflow cancellation.
    WorkflowCancelled,
    /// Trustworthy workflow timeout.
    WorkflowTimedOut,
    /// Provider state could not be established exactly.
    ProviderUnknown,
    /// Internal state could not be established exactly.
    SystemUnknown,
}

impl GithubCheckTerminalCause {
    /// Returns the only conclusion permitted for this cause.
    #[must_use]
    pub const fn conclusion(self) -> GithubCheckConclusion {
        match self {
            Self::WorkflowSuccess => GithubCheckConclusion::Success,
            Self::WorkflowSkipped => GithubCheckConclusion::Skipped,
            Self::WorkflowFailure | Self::SystemUnknown => GithubCheckConclusion::Failure,
            Self::WorkflowCancelled => GithubCheckConclusion::Cancelled,
            Self::WorkflowTimedOut => GithubCheckConclusion::TimedOut,
            Self::ProviderUnknown => GithubCheckConclusion::ActionRequired,
        }
    }
}

/// Explicit desired provider projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubCheckDesiredProjection {
    /// Waiting for admission or execution capacity.
    Queued,
    /// Admitted work is executing.
    InProgress,
    /// The subject was terminalized by trusted server logic.
    Terminal(GithubCheckTerminalCause),
}

impl GithubCheckDesiredProjection {
    /// Constructs a terminal projection without caller-controlled conclusion mapping.
    #[must_use]
    pub const fn terminal(cause: GithubCheckTerminalCause) -> Self {
        Self::Terminal(cause)
    }
}

/// Immutable registration request for one pre-admission subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterGithubCheckSubject {
    identity: GithubCheckSubjectIdentity,
    created_at: UnixMillis,
}

impl RegisterGithubCheckSubject {
    /// Constructs a queued subject registration.
    ///
    /// # Errors
    ///
    /// Rejects timestamps before the Unix epoch.
    pub fn new(
        identity: GithubCheckSubjectIdentity,
        created_at: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        validate_timestamp(created_at, "GitHub Check creation time")?;
        Ok(Self {
            identity,
            created_at,
        })
    }

    /// Returns the exact immutable identity.
    #[must_use]
    pub const fn identity(&self) -> &GithubCheckSubjectIdentity {
        &self.identity
    }
    /// Returns the durable creation time.
    #[must_use]
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }
}

/// Tenant-scoped subject target used by all later mutations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubCheckSubjectTarget {
    tenant: TenantScope,
    subject_id: GithubCheckSubjectId,
}

impl GithubCheckSubjectTarget {
    /// Constructs an exact tenant-scoped target.
    #[must_use]
    pub const fn new(tenant: TenantScope, subject_id: GithubCheckSubjectId) -> Self {
        Self { tenant, subject_id }
    }

    /// Returns the authenticated tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }
    /// Returns the durable subject identity.
    #[must_use]
    pub const fn subject_id(&self) -> GithubCheckSubjectId {
        self.subject_id
    }
}

/// Marks a queued desired projection in progress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartGithubCheckProjection {
    target: GithubCheckSubjectTarget,
    started_at: UnixMillis,
}

impl StartGithubCheckProjection {
    /// Constructs a server-owned in-progress transition.
    ///
    /// # Errors
    ///
    /// Rejects timestamps before the Unix epoch.
    pub fn new(
        target: GithubCheckSubjectTarget,
        started_at: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        validate_timestamp(started_at, "GitHub Check start time")?;
        Ok(Self { target, started_at })
    }

    /// Returns the exact subject target.
    #[must_use]
    pub const fn target(&self) -> &GithubCheckSubjectTarget {
        &self.target
    }
    /// Returns the desired-transition time.
    #[must_use]
    pub const fn started_at(&self) -> UnixMillis {
        self.started_at
    }
}

/// Terminalizes a subject through the server-only terminalization port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalizeGithubCheck {
    target: GithubCheckSubjectTarget,
    cause: GithubCheckTerminalCause,
    terminal_at: UnixMillis,
}

impl TerminalizeGithubCheck {
    /// Constructs a terminal transition with a cause-derived conclusion.
    ///
    /// # Errors
    ///
    /// Rejects timestamps before the Unix epoch.
    pub fn new(
        target: GithubCheckSubjectTarget,
        cause: GithubCheckTerminalCause,
        terminal_at: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        validate_timestamp(terminal_at, "GitHub Check terminal time")?;
        Ok(Self {
            target,
            cause,
            terminal_at,
        })
    }

    /// Returns the exact subject target.
    #[must_use]
    pub const fn target(&self) -> &GithubCheckSubjectTarget {
        &self.target
    }
    /// Returns the closed terminal cause.
    #[must_use]
    pub const fn cause(&self) -> GithubCheckTerminalCause {
        self.cause
    }
    /// Returns the cause-derived conclusion.
    #[must_use]
    pub const fn conclusion(&self) -> GithubCheckConclusion {
        self.cause.conclusion()
    }
    /// Returns the terminal transition time.
    #[must_use]
    pub const fn terminal_at(&self) -> UnixMillis {
        self.terminal_at
    }
}

/// Durable current subject state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubCheckSubjectReceipt {
    subject_id: GithubCheckSubjectId,
    external_id: String,
    workflow_run_id: Option<RunId>,
    desired: GithubCheckDesiredProjection,
    desired_revision: NonZeroU64,
}

impl GithubCheckSubjectReceipt {
    /// Rehydrates one current durable subject receipt.
    ///
    /// # Errors
    ///
    /// Rejects a non-derived external identity, a nil linked run, or a desired
    /// revision outside the positive signed durable range.
    pub fn from_durable_parts(
        subject_id: GithubCheckSubjectId,
        external_id: String,
        workflow_run_id: Option<RunId>,
        desired: GithubCheckDesiredProjection,
        desired_revision: u64,
    ) -> Result<Self, GithubCheckValueError> {
        let desired_revision = NonZeroU64::new(desired_revision)
            .filter(|revision| i64::try_from(revision.get()).is_ok())
            .ok_or(GithubCheckValueError::InvalidDesiredRevision)?;
        let expected_external_id = format!("automata-check:{}", subject_id.as_uuid());
        if external_id != expected_external_id {
            return Err(GithubCheckValueError::InvalidExternalId);
        }
        if workflow_run_id.is_some_and(|run_id| run_id.as_uuid().is_nil()) {
            return Err(GithubCheckValueError::NilUuid(
                "GitHub Check workflow run ID",
            ));
        }
        Ok(Self {
            subject_id,
            external_id,
            workflow_run_id,
            desired,
            desired_revision,
        })
    }

    /// Returns the durable subject ID.
    #[must_use]
    pub const fn subject_id(&self) -> GithubCheckSubjectId {
        self.subject_id
    }
    /// Returns the derived immutable GitHub external ID.
    #[must_use]
    pub fn external_id(&self) -> &str {
        &self.external_id
    }
    /// Returns the admitted workflow run when linked.
    #[must_use]
    pub const fn workflow_run_id(&self) -> Option<RunId> {
        self.workflow_run_id
    }
    /// Returns the current desired provider projection.
    #[must_use]
    pub const fn desired(&self) -> GithubCheckDesiredProjection {
        self.desired
    }
    /// Returns the positive desired projection revision.
    #[must_use]
    pub const fn desired_revision(&self) -> u64 {
        self.desired_revision.get()
    }
}

/// Requested exclusive outbox claim.
///
/// `observed_at` is bounded caller-clock admission evidence. `expires_at`
/// supplies only the requested duration; a durable repository issues the
/// returned claim's absolute start and expiry from its authoritative clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimGithubCheckProjection {
    connection_id: ProviderConnectionId,
    owner: GithubCheckProjectionWorkerId,
    observed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ClaimGithubCheckProjection {
    /// Constructs a bounded connection-specific projection claim.
    ///
    /// # Errors
    ///
    /// Rejects invalid timestamps or a claim longer than fifteen minutes.
    pub fn new(
        connection_id: ProviderConnectionId,
        owner: GithubCheckProjectionWorkerId,
        observed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        validate_claim_interval(observed_at, expires_at)?;
        Ok(Self {
            connection_id,
            owner,
            observed_at,
            expires_at,
        })
    }

    /// Returns the provider connection selected by the worker.
    #[must_use]
    pub const fn connection_id(self) -> ProviderConnectionId {
        self.connection_id
    }
    /// Returns the worker identity.
    #[must_use]
    pub const fn owner(self) -> GithubCheckProjectionWorkerId {
        self.owner
    }
    /// Returns the caller observation admitted when requesting the claim.
    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
    /// Returns the caller-proposed expiry whose difference from
    /// [`Self::observed_at`] is the requested claim duration.
    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }
}

/// Provider operation selected from durable external identity and uncertainty state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubCheckProjectionAction {
    /// Ensure the App's suite exists for the exact SHA.
    EnsureSuite,
    /// Persist the irreversible create-start cutoff before issuing the Check Run POST.
    PrepareRunCreate,
    /// Reconcile a possibly-created Check Run; another create is forbidden.
    ReconcileRunCreate,
    /// Publish the claimed desired state to the exact bound Check Run.
    Publish,
}

/// Exact Automata dashboard resource represented by a Check Run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubCheckDetailsTarget {
    /// Repository workflow activity, used by pre-admission diagnostics.
    Repository,
    /// One admitted workflow run.
    WorkflowRun(RunId),
    /// One concrete job inside an admitted workflow run.
    Job { run_id: RunId, job_id: JobId },
}

/// Exact exclusive fence for one claimed outbox attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubCheckProjectionClaimFence {
    subject_id: GithubCheckSubjectId,
    owner: GithubCheckProjectionWorkerId,
    fence: NonZeroU64,
}

impl GithubCheckProjectionClaimFence {
    /// Rehydrates an exact fence returned by a durable outbox claim.
    ///
    /// # Errors
    ///
    /// Rejects zero or values outside the signed durable range.
    pub fn from_durable_parts(
        subject_id: GithubCheckSubjectId,
        owner: GithubCheckProjectionWorkerId,
        fence: u64,
    ) -> Result<Self, GithubCheckValueError> {
        let fence = NonZeroU64::new(fence)
            .filter(|value| i64::try_from(value.get()).is_ok())
            .ok_or(GithubCheckValueError::InvalidClaimFence)?;
        Ok(Self {
            subject_id,
            owner,
            fence,
        })
    }

    /// Returns the subject ID.
    #[must_use]
    pub const fn subject_id(self) -> GithubCheckSubjectId {
        self.subject_id
    }
    /// Returns the worker identity.
    #[must_use]
    pub const fn owner(self) -> GithubCheckProjectionWorkerId {
        self.owner
    }
    /// Returns the positive fencing token.
    #[must_use]
    pub const fn fence(self) -> u64 {
        self.fence.get()
    }
}

/// Claimed provider-independent work plus exact external identity accumulated so far.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedGithubCheckProjection {
    claim: GithubCheckProjectionClaimFence,
    action: GithubCheckProjectionAction,
    attempts: NonZeroU16,
    identity: GithubCheckSubjectIdentity,
    details_target: GithubCheckDetailsTarget,
    checks_authority: GithubServerServiceAuthoritySelector,
    external_id: String,
    desired: GithubCheckDesiredProjection,
    desired_revision: NonZeroU64,
    suite_id: Option<GithubCheckSuiteId>,
    run_id: Option<GithubCheckRunId>,
    created_at: UnixMillis,
    desired_updated_at: UnixMillis,
    terminal_result: Option<BlobDescriptor>,
    annotation_progress: GithubCheckAnnotationProgress,
    started_at: Option<UnixMillis>,
    completed_at: Option<UnixMillis>,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

/// Durable append cursor for one deterministic terminal Check presentation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GithubCheckAnnotationProgress {
    presentation_digest: Option<Sha256Digest>,
    total: u16,
    next: u16,
    uncertain_batch_size: Option<u8>,
}

impl GithubCheckAnnotationProgress {
    /// Rehydrates one bounded monotonic annotation cursor.
    ///
    /// # Errors
    ///
    /// Rejects incomplete presentation identity, excessive counts, a cursor
    /// beyond the total, or an uncertain batch outside the remaining suffix.
    pub fn from_durable_parts(
        presentation_digest: Option<Sha256Digest>,
        total: u16,
        next: u16,
        uncertain_batch_size: Option<u8>,
    ) -> Result<Self, GithubCheckValueError> {
        let uncertainty_is_valid = uncertain_batch_size.is_none_or(|count| {
            count > 0
                && count <= 50
                && next
                    .checked_add(u16::from(count))
                    .is_some_and(|end| end <= total)
        });
        if total > 4_096
            || next > total
            || !uncertainty_is_valid
            || presentation_digest.is_none()
                && (total != 0 || next != 0 || uncertain_batch_size.is_some())
        {
            return Err(GithubCheckValueError::InvalidProjectionBinding);
        }
        Ok(Self {
            presentation_digest,
            total,
            next,
            uncertain_batch_size,
        })
    }

    /// Returns the deterministic presentation digest, once initialized.
    #[must_use]
    pub const fn presentation_digest(self) -> Option<Sha256Digest> {
        self.presentation_digest
    }

    /// Returns the total valid source annotations in the presentation.
    #[must_use]
    pub const fn total(self) -> u16 {
        self.total
    }

    /// Returns the first annotation not durably confirmed at GitHub.
    #[must_use]
    pub const fn next(self) -> u16 {
        self.next
    }

    /// Returns the size of a possibly appended batch requiring reconciliation.
    #[must_use]
    pub const fn uncertain_batch_size(self) -> Option<u8> {
        self.uncertain_batch_size
    }

    /// Reports whether every annotation is durably confirmed.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.presentation_digest.is_some()
            && self.next == self.total
            && self.uncertain_batch_size.is_none()
    }
}

impl ClaimedGithubCheckProjection {
    /// Rehydrates complete provider projection evidence under a durable claim.
    ///
    /// The external identity, action, attempt, revision, and claim interval
    /// must describe one internally consistent current-only outbox record.
    ///
    /// # Errors
    ///
    /// Rejects invalid action/binding combinations, external identities,
    /// attempts, revisions, timestamps, or claim intervals.
    #[allow(clippy::too_many_arguments)]
    pub fn from_durable_parts(
        claim: GithubCheckProjectionClaimFence,
        action: GithubCheckProjectionAction,
        attempts: u16,
        identity: GithubCheckSubjectIdentity,
        details_target: GithubCheckDetailsTarget,
        checks_authority: GithubServerServiceAuthoritySelector,
        external_id: String,
        desired: GithubCheckDesiredProjection,
        desired_revision: u64,
        suite_id: Option<GithubCheckSuiteId>,
        run_id: Option<GithubCheckRunId>,
        created_at: UnixMillis,
        desired_updated_at: UnixMillis,
        terminal_result: Option<BlobDescriptor>,
        annotation_progress: GithubCheckAnnotationProgress,
        started_at: Option<UnixMillis>,
        completed_at: Option<UnixMillis>,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        let attempts = NonZeroU16::new(attempts)
            .filter(|value| value.get() <= MAX_GITHUB_CHECK_PROJECTION_ATTEMPTS)
            .ok_or(GithubCheckValueError::InvalidAttempt)?;
        let desired_revision = NonZeroU64::new(desired_revision)
            .filter(|revision| i64::try_from(revision.get()).is_ok())
            .ok_or(GithubCheckValueError::InvalidDesiredRevision)?;
        let binding_is_valid = matches!(
            (action, suite_id, run_id),
            (GithubCheckProjectionAction::EnsureSuite, None, None)
                | (
                    GithubCheckProjectionAction::PrepareRunCreate
                        | GithubCheckProjectionAction::ReconcileRunCreate,
                    Some(_),
                    None
                )
                | (GithubCheckProjectionAction::Publish, Some(_), Some(_))
        );
        if external_id != format!("automata-check:{}", claim.subject_id().as_uuid()) {
            return Err(GithubCheckValueError::InvalidExternalId);
        }
        if checks_authority.tenant() != identity.tenant() {
            return Err(GithubCheckValueError::AuthoritySelectorMismatch);
        }
        match details_target {
            GithubCheckDetailsTarget::Repository => {}
            GithubCheckDetailsTarget::WorkflowRun(run_id) => {
                if run_id.as_uuid().is_nil() {
                    return Err(GithubCheckValueError::NilUuid(
                        "GitHub Check details workflow run ID",
                    ));
                }
            }
            GithubCheckDetailsTarget::Job { run_id, job_id } => {
                if run_id.as_uuid().is_nil() || job_id.as_uuid().is_nil() {
                    return Err(GithubCheckValueError::NilUuid(
                        "GitHub Check details job target",
                    ));
                }
            }
        }
        if !binding_is_valid {
            return Err(GithubCheckValueError::InvalidProjectionBinding);
        }
        validate_claim_interval(claimed_at, expires_at)?;
        validate_timestamp(created_at, "GitHub Check creation time")?;
        validate_timestamp(desired_updated_at, "GitHub Check desired update time")?;
        if desired_updated_at < created_at || desired_updated_at > claimed_at {
            return Err(GithubCheckValueError::InvalidClaimInterval);
        }
        if started_at.is_some_and(|value| value < created_at || value > claimed_at)
            || completed_at
                .is_some_and(|value| value < started_at.unwrap_or(created_at) || value > claimed_at)
            || !matches!(
                (desired, started_at, completed_at),
                (GithubCheckDesiredProjection::Queued, None, None)
                    | (GithubCheckDesiredProjection::InProgress, Some(_), None)
                    | (GithubCheckDesiredProjection::Terminal(_), _, Some(_))
            )
        {
            return Err(GithubCheckValueError::InvalidClaimInterval);
        }
        if let Some(result) = terminal_result.as_ref()
            && (!matches!(desired, GithubCheckDesiredProjection::Terminal(_))
                || !matches!(details_target, GithubCheckDetailsTarget::Job { .. })
                || !(1..=crate::MAX_TERMINAL_RESULT_BYTES).contains(&result.size())
                || result.media_type().as_str() != crate::HUMAN_JOB_RESULT_MEDIA_TYPE)
        {
            return Err(GithubCheckValueError::InvalidProjectionBinding);
        }
        if annotation_progress.presentation_digest().is_some()
            && (terminal_result.is_none()
                || !matches!(desired, GithubCheckDesiredProjection::Terminal(_))
                || !matches!(details_target, GithubCheckDetailsTarget::Job { .. }))
        {
            return Err(GithubCheckValueError::InvalidProjectionBinding);
        }
        Ok(Self {
            claim,
            action,
            attempts,
            identity,
            details_target,
            checks_authority,
            external_id,
            desired,
            desired_revision,
            suite_id,
            run_id,
            created_at,
            desired_updated_at,
            terminal_result,
            annotation_progress,
            started_at,
            completed_at,
            claimed_at,
            expires_at,
        })
    }

    /// Returns the exact live claim fence.
    #[must_use]
    pub const fn claim(&self) -> GithubCheckProjectionClaimFence {
        self.claim
    }
    /// Returns the only provider operation permitted by durable state.
    #[must_use]
    pub const fn action(&self) -> GithubCheckProjectionAction {
        self.action
    }
    /// Returns the attempt ordinal for this desired revision.
    #[must_use]
    pub const fn attempts(&self) -> u16 {
        self.attempts.get()
    }
    /// Returns immutable routing and Check identity.
    #[must_use]
    pub const fn identity(&self) -> &GithubCheckSubjectIdentity {
        &self.identity
    }
    /// Returns the exact Automata dashboard resource for `details_url`.
    #[must_use]
    pub const fn details_target(&self) -> GithubCheckDetailsTarget {
        self.details_target
    }
    /// Returns the immutable manifest-pinned `checks_write` authority selector.
    #[must_use]
    pub const fn checks_authority(&self) -> &GithubServerServiceAuthoritySelector {
        &self.checks_authority
    }
    /// Returns the immutable external ID.
    #[must_use]
    pub fn external_id(&self) -> &str {
        &self.external_id
    }
    /// Returns the desired projection frozen by this claim.
    #[must_use]
    pub const fn desired(&self) -> GithubCheckDesiredProjection {
        self.desired
    }
    /// Returns the desired revision frozen by this claim.
    #[must_use]
    pub const fn desired_revision(&self) -> u64 {
        self.desired_revision.get()
    }
    /// Returns the exact bound suite, when known.
    #[must_use]
    pub const fn suite_id(&self) -> Option<GithubCheckSuiteId> {
        self.suite_id
    }
    /// Returns the exact bound Check Run, when known.
    #[must_use]
    pub const fn run_id(&self) -> Option<GithubCheckRunId> {
        self.run_id
    }
    /// Returns the durable time at which the Check first became queued.
    #[must_use]
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }
    /// Returns the exact time of the desired lifecycle revision frozen by this claim.
    #[must_use]
    pub const fn desired_updated_at(&self) -> UnixMillis {
        self.desired_updated_at
    }
    /// Returns the verified immutable runner result to present for a terminal job Check.
    #[must_use]
    pub const fn terminal_result(&self) -> Option<&BlobDescriptor> {
        self.terminal_result.as_ref()
    }
    /// Returns the durable deterministic annotation append cursor.
    #[must_use]
    pub const fn annotation_progress(&self) -> GithubCheckAnnotationProgress {
        self.annotation_progress
    }
    /// Returns the durable attempt start represented by this Check revision.
    #[must_use]
    pub const fn started_at(&self) -> Option<UnixMillis> {
        self.started_at
    }
    /// Returns the durable terminal completion represented by this Check revision.
    #[must_use]
    pub const fn completed_at(&self) -> Option<UnixMillis> {
        self.completed_at
    }
    /// Returns the durable time at which this exact fence was claimed.
    #[must_use]
    pub const fn claimed_at(&self) -> UnixMillis {
        self.claimed_at
    }
    /// Returns the exclusive expiry of this exact claim fence.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

/// Determinate suite identity observed under an exact live claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindGithubCheckSuite {
    claim: GithubCheckProjectionClaimFence,
    suite_id: GithubCheckSuiteId,
    observed_at: UnixMillis,
}

impl BindGithubCheckSuite {
    /// Constructs exact suite-binding evidence.
    ///
    /// # Errors
    ///
    /// Rejects an observation time before the Unix epoch.
    pub fn new(
        claim: GithubCheckProjectionClaimFence,
        suite_id: GithubCheckSuiteId,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        validate_timestamp(observed_at, "GitHub Check suite observation time")?;
        Ok(Self {
            claim,
            suite_id,
            observed_at,
        })
    }
    /// Returns the live claim.
    #[must_use]
    pub const fn claim(self) -> GithubCheckProjectionClaimFence {
        self.claim
    }
    /// Returns the exact suite identity.
    #[must_use]
    pub const fn suite_id(self) -> GithubCheckSuiteId {
        self.suite_id
    }
    /// Returns the observation time.
    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
}

/// Irreversible evidence that a Check Run create request may be issued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BeginGithubCheckRunCreate {
    fence: GithubCheckRunCreateFence,
}

impl BeginGithubCheckRunCreate {
    /// Constructs the durable cutoff that must precede provider mutation.
    ///
    /// # Errors
    ///
    /// Rejects a non-create claim, a start outside its exact live interval, or
    /// a reconciliation horizon outside the bounded post-issue grace.
    pub fn new(
        claimed: &ClaimedGithubCheckProjection,
        started_at: UnixMillis,
        reconcile_not_before: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        if claimed.action() != GithubCheckProjectionAction::PrepareRunCreate
            || started_at < claimed.claimed_at()
            || started_at >= claimed.expires_at()
        {
            return Err(GithubCheckValueError::InvalidClaimInterval);
        }
        let fence = GithubCheckRunCreateFence::from_durable_parts(
            claimed.claim(),
            started_at,
            claimed.expires_at(),
            reconcile_not_before,
        )?;
        Ok(Self { fence })
    }
    /// Returns the claim consumed by the cutoff.
    #[must_use]
    pub const fn claim(self) -> GithubCheckProjectionClaimFence {
        self.fence.claim()
    }
    /// Returns the create-start time.
    #[must_use]
    pub const fn started_at(self) -> UnixMillis {
        self.fence.started_at()
    }
    /// Returns the exclusive deadline after which provider issuance is forbidden.
    #[must_use]
    pub const fn issue_expires_at(self) -> UnixMillis {
        self.fence.issue_expires_at()
    }
    /// Returns the earliest safe reconciliation time.
    #[must_use]
    pub const fn reconcile_not_before(self) -> UnixMillis {
        self.fence.reconcile_not_before()
    }
    /// Returns the exact durable create fence this cutoff must commit.
    #[must_use]
    pub const fn fence(self) -> GithubCheckRunCreateFence {
        self.fence
    }
}

/// Exact fence retained after the irreversible create-start cutoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubCheckRunCreateFence {
    claim: GithubCheckProjectionClaimFence,
    started_at: UnixMillis,
    issue_expires_at: UnixMillis,
    reconcile_not_before: UnixMillis,
}

impl GithubCheckRunCreateFence {
    /// Rehydrates the exact timing fence after the durable cutoff commits.
    ///
    /// # Errors
    ///
    /// Rejects invalid issue or reconciliation intervals.
    pub fn from_durable_parts(
        claim: GithubCheckProjectionClaimFence,
        started_at: UnixMillis,
        issue_expires_at: UnixMillis,
        reconcile_not_before: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        validate_timestamp(started_at, "GitHub Check create start time")?;
        issue_expires_at
            .get()
            .checked_sub(started_at.get())
            .filter(|duration| (1..=MAX_GITHUB_CHECK_PROJECTION_CLAIM_MILLIS).contains(duration))
            .ok_or(GithubCheckValueError::InvalidClaimInterval)?;
        reconcile_not_before
            .get()
            .checked_sub(issue_expires_at.get())
            .filter(|grace| (1..=MAX_GITHUB_CHECK_CREATE_RECONCILE_GRACE_MILLIS).contains(grace))
            .ok_or(GithubCheckValueError::InvalidReconcileDelay)?;
        Ok(Self {
            claim,
            started_at,
            issue_expires_at,
            reconcile_not_before,
        })
    }
    /// Returns the consumed projection claim identity.
    #[must_use]
    pub const fn claim(self) -> GithubCheckProjectionClaimFence {
        self.claim
    }
    /// Returns when the durable create cutoff started.
    #[must_use]
    pub const fn started_at(self) -> UnixMillis {
        self.started_at
    }
    /// Returns the exclusive provider-issuance deadline.
    #[must_use]
    pub const fn issue_expires_at(self) -> UnixMillis {
        self.issue_expires_at
    }
    /// Returns the earliest time at which reconciliation may be claimed.
    #[must_use]
    pub const fn reconcile_not_before(self) -> UnixMillis {
        self.reconcile_not_before
    }
}

/// Source of an exact Check Run binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubCheckRunBindingFence {
    /// Determinate response to the one create allowed by this fence.
    Create(GithubCheckRunCreateFence),
    /// Exact single match observed during reconciliation.
    Reconciliation(GithubCheckProjectionClaimFence),
}

/// Exact external Check Run identity observed after create or reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindGithubCheckRun {
    fence: GithubCheckRunBindingFence,
    suite_id: GithubCheckSuiteId,
    run_id: GithubCheckRunId,
    observed_at: UnixMillis,
}

impl BindGithubCheckRun {
    /// Constructs exact external binding evidence.
    ///
    /// # Errors
    ///
    /// Rejects an observation time before the Unix epoch.
    pub fn new(
        fence: GithubCheckRunBindingFence,
        suite_id: GithubCheckSuiteId,
        run_id: GithubCheckRunId,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        validate_timestamp(observed_at, "GitHub Check Run observation time")?;
        Ok(Self {
            fence,
            suite_id,
            run_id,
            observed_at,
        })
    }
    /// Returns the create or reconciliation fence.
    #[must_use]
    pub const fn fence(self) -> GithubCheckRunBindingFence {
        self.fence
    }
    /// Returns the exact suite identity.
    #[must_use]
    pub const fn suite_id(self) -> GithubCheckSuiteId {
        self.suite_id
    }
    /// Returns the exact Check Run identity.
    #[must_use]
    pub const fn run_id(self) -> GithubCheckRunId {
        self.run_id
    }
    /// Returns the observation time.
    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
}

/// Exact result of reconciling an uncertain Check Run create.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubCheckCreateReconciliation {
    /// No exact external identity was visible after a possibly issued create.
    ///
    /// This remains reconcile-only because GitHub exposes no create
    /// idempotency or bounded visibility contract.
    Missing,
    /// Multiple exact identities exist, requiring manual repair.
    Ambiguous,
}

/// Releases a durable cutoff only when the create future provably never began.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseUnissuedGithubCheckRunCreate {
    fence: GithubCheckRunCreateFence,
    released_at: UnixMillis,
    retry_at: UnixMillis,
}

impl ReleaseUnissuedGithubCheckRunCreate {
    /// Constructs exact no-provider-I/O retry evidence.
    ///
    /// # Errors
    ///
    /// Rejects invalid timestamps or an excessive retry delay.
    pub fn new(
        fence: GithubCheckRunCreateFence,
        released_at: UnixMillis,
        retry_at: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        validate_timestamp(released_at, "GitHub Check unissued release time")?;
        if released_at < fence.started_at() {
            return Err(GithubCheckValueError::InvalidRetryBackoff);
        }
        retry_at
            .get()
            .checked_sub(released_at.get())
            .filter(|delay| (1..=MAX_GITHUB_CHECK_PROJECTION_RETRY_MILLIS).contains(delay))
            .ok_or(GithubCheckValueError::InvalidRetryBackoff)?;
        Ok(Self {
            fence,
            released_at,
            retry_at,
        })
    }
    /// Returns the exact create cutoff proven not to have issued provider I/O.
    #[must_use]
    pub const fn fence(self) -> GithubCheckRunCreateFence {
        self.fence
    }
    /// Returns when the unissued operation was released.
    #[must_use]
    pub const fn released_at(self) -> UnixMillis {
        self.released_at
    }
    /// Returns the next eligible retry time.
    #[must_use]
    pub const fn retry_at(self) -> UnixMillis {
        self.retry_at
    }
}

/// Records a non-exact reconciliation result under a live reconciliation claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolveGithubCheckRunCreate {
    claim: GithubCheckProjectionClaimFence,
    outcome: GithubCheckCreateReconciliation,
    observed_at: UnixMillis,
    retry_at: Option<UnixMillis>,
}

impl ResolveGithubCheckRunCreate {
    /// Constructs bounded missing evidence that remains eligible only for
    /// another reconciliation.
    ///
    /// # Errors
    ///
    /// Rejects invalid timestamps or an excessive retry delay.
    pub fn missing(
        claim: GithubCheckProjectionClaimFence,
        observed_at: UnixMillis,
        retry_at: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        validate_timestamp(observed_at, "GitHub Check reconciliation time")?;
        retry_at
            .get()
            .checked_sub(observed_at.get())
            .filter(|delay| (1..=MAX_GITHUB_CHECK_PROJECTION_RETRY_MILLIS).contains(delay))
            .ok_or(GithubCheckValueError::InvalidRetryBackoff)?;
        Ok(Self {
            claim,
            outcome: GithubCheckCreateReconciliation::Missing,
            observed_at,
            retry_at: Some(retry_at),
        })
    }
    /// Constructs durable ambiguous reconciliation evidence.
    ///
    /// # Errors
    ///
    /// Rejects an observation time before the Unix epoch.
    pub fn ambiguous(
        claim: GithubCheckProjectionClaimFence,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        validate_timestamp(observed_at, "GitHub Check reconciliation time")?;
        Ok(Self {
            claim,
            outcome: GithubCheckCreateReconciliation::Ambiguous,
            observed_at,
            retry_at: None,
        })
    }
    /// Returns the exact reconciliation claim.
    #[must_use]
    pub const fn claim(self) -> GithubCheckProjectionClaimFence {
        self.claim
    }
    /// Returns the closed reconciliation outcome.
    #[must_use]
    pub const fn outcome(self) -> GithubCheckCreateReconciliation {
        self.outcome
    }
    /// Returns the observation time.
    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
    /// Returns the next reconcile-only eligibility time for a missing result.
    #[must_use]
    pub const fn retry_at(self) -> Option<UnixMillis> {
        self.retry_at
    }
}

/// Confirms that the provider exactly reflects the desired state frozen by a claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitializeGithubCheckPresentation {
    claim: GithubCheckProjectionClaimFence,
    digest: Sha256Digest,
    annotation_count: u16,
    initialized_at: UnixMillis,
}

impl InitializeGithubCheckPresentation {
    /// Binds one deterministic terminal presentation to a live publish claim.
    ///
    /// # Errors
    ///
    /// Rejects more than 4,096 annotations or a negative observation time.
    pub fn new(
        claim: GithubCheckProjectionClaimFence,
        digest: Sha256Digest,
        annotation_count: u16,
        initialized_at: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        if annotation_count > 4_096 {
            return Err(GithubCheckValueError::InvalidProjectionBinding);
        }
        validate_timestamp(
            initialized_at,
            "GitHub Check presentation initialization time",
        )?;
        Ok(Self {
            claim,
            digest,
            annotation_count,
            initialized_at,
        })
    }

    /// Returns the exact live claim.
    #[must_use]
    pub const fn claim(self) -> GithubCheckProjectionClaimFence {
        self.claim
    }

    /// Returns the deterministic presentation digest.
    #[must_use]
    pub const fn digest(self) -> Sha256Digest {
        self.digest
    }

    /// Returns the complete annotation count.
    #[must_use]
    pub const fn annotation_count(self) -> u16 {
        self.annotation_count
    }

    /// Returns when the presentation was initialized.
    #[must_use]
    pub const fn initialized_at(self) -> UnixMillis {
        self.initialized_at
    }
}

/// Monotonically confirms one exact annotation batch under a live claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdvanceGithubCheckAnnotations {
    claim: GithubCheckProjectionClaimFence,
    digest: Sha256Digest,
    from: u16,
    to: u16,
    observed_at: UnixMillis,
}

impl AdvanceGithubCheckAnnotations {
    /// Creates exact append confirmation for one batch of at most 50 annotations.
    ///
    /// # Errors
    ///
    /// Rejects empty, excessive, or out-of-range batches and negative times.
    pub fn new(
        claim: GithubCheckProjectionClaimFence,
        digest: Sha256Digest,
        from: u16,
        to: u16,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        if to <= from || to > 4_096 || to - from > 50 {
            return Err(GithubCheckValueError::InvalidProjectionBinding);
        }
        validate_timestamp(observed_at, "GitHub Check annotation observation time")?;
        Ok(Self {
            claim,
            digest,
            from,
            to,
            observed_at,
        })
    }

    /// Returns the exact live claim.
    #[must_use]
    pub const fn claim(self) -> GithubCheckProjectionClaimFence {
        self.claim
    }

    /// Returns the presentation digest.
    #[must_use]
    pub const fn digest(self) -> Sha256Digest {
        self.digest
    }

    /// Returns the cursor before the batch.
    #[must_use]
    pub const fn from(self) -> u16 {
        self.from
    }

    /// Returns the cursor after the batch.
    #[must_use]
    pub const fn to(self) -> u16 {
        self.to
    }

    /// Returns when exact provider evidence was observed.
    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
}

/// Releases a possibly appended annotation batch into reconcile-only retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryUncertainGithubCheckAnnotations {
    claim: GithubCheckProjectionClaimFence,
    digest: Sha256Digest,
    from: u16,
    batch_size: u8,
    failed_at: UnixMillis,
    retry_at: UnixMillis,
}

impl RetryUncertainGithubCheckAnnotations {
    /// Creates bounded uncertainty evidence for one possibly appended batch.
    ///
    /// # Errors
    ///
    /// Rejects invalid batch bounds, timestamps, or retry delay.
    pub fn new(
        claim: GithubCheckProjectionClaimFence,
        digest: Sha256Digest,
        from: u16,
        batch_size: u8,
        failed_at: UnixMillis,
        retry_at: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        if from > 4_095 || batch_size == 0 || batch_size > 50 {
            return Err(GithubCheckValueError::InvalidProjectionBinding);
        }
        retry_at
            .get()
            .checked_sub(failed_at.get())
            .filter(|delay| (1..=MAX_GITHUB_CHECK_PROJECTION_RETRY_MILLIS).contains(delay))
            .ok_or(GithubCheckValueError::InvalidRetryBackoff)?;
        validate_timestamp(failed_at, "GitHub Check annotation failure time")?;
        Ok(Self {
            claim,
            digest,
            from,
            batch_size,
            failed_at,
            retry_at,
        })
    }

    /// Returns the exact live claim.
    #[must_use]
    pub const fn claim(self) -> GithubCheckProjectionClaimFence {
        self.claim
    }
    /// Returns the presentation digest.
    #[must_use]
    pub const fn digest(self) -> Sha256Digest {
        self.digest
    }
    /// Returns the cursor before the uncertain batch.
    #[must_use]
    pub const fn from(self) -> u16 {
        self.from
    }
    /// Returns the uncertain batch size.
    #[must_use]
    pub const fn batch_size(self) -> u8 {
        self.batch_size
    }
    /// Returns when ambiguity was observed.
    #[must_use]
    pub const fn failed_at(self) -> UnixMillis {
        self.failed_at
    }
    /// Returns the reconcile-only retry time.
    #[must_use]
    pub const fn retry_at(self) -> UnixMillis {
        self.retry_at
    }
}

/// Clears an uncertain batch after proving GitHub retained the prior prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClearGithubCheckAnnotationUncertainty {
    claim: GithubCheckProjectionClaimFence,
    digest: Sha256Digest,
    from: u16,
    batch_size: u8,
    observed_at: UnixMillis,
}

impl ClearGithubCheckAnnotationUncertainty {
    /// Creates exact unchanged-prefix reconciliation evidence.
    ///
    /// # Errors
    ///
    /// Rejects invalid batch bounds or a negative observation time.
    pub fn new(
        claim: GithubCheckProjectionClaimFence,
        digest: Sha256Digest,
        from: u16,
        batch_size: u8,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        if from > 4_095 || batch_size == 0 || batch_size > 50 {
            return Err(GithubCheckValueError::InvalidProjectionBinding);
        }
        validate_timestamp(observed_at, "GitHub Check annotation reconciliation time")?;
        Ok(Self {
            claim,
            digest,
            from,
            batch_size,
            observed_at,
        })
    }

    /// Returns the exact live claim.
    #[must_use]
    pub const fn claim(self) -> GithubCheckProjectionClaimFence {
        self.claim
    }
    /// Returns the presentation digest.
    #[must_use]
    pub const fn digest(self) -> Sha256Digest {
        self.digest
    }
    /// Returns the unchanged cursor.
    #[must_use]
    pub const fn from(self) -> u16 {
        self.from
    }
    /// Returns the reconciled uncertain batch size.
    #[must_use]
    pub const fn batch_size(self) -> u8 {
        self.batch_size
    }
    /// Returns when the unchanged prefix was observed.
    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
}

/// Permanently blocks a live projection whose provider annotations diverged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockGithubCheckAnnotationMismatch {
    claim: GithubCheckProjectionClaimFence,
    blocked_at: UnixMillis,
}

impl BlockGithubCheckAnnotationMismatch {
    /// Creates exact provider-mismatch block evidence.
    ///
    /// # Errors
    ///
    /// Rejects a block time before the Unix epoch.
    pub fn new(
        claim: GithubCheckProjectionClaimFence,
        blocked_at: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        validate_timestamp(blocked_at, "GitHub Check annotation mismatch time")?;
        Ok(Self { claim, blocked_at })
    }

    /// Returns the exact live claim.
    #[must_use]
    pub const fn claim(self) -> GithubCheckProjectionClaimFence {
        self.claim
    }
    /// Returns when divergence was observed.
    #[must_use]
    pub const fn blocked_at(self) -> UnixMillis {
        self.blocked_at
    }
}

/// Confirms that the provider exactly reflects the desired state frozen by a claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteGithubCheckProjection {
    claim: GithubCheckProjectionClaimFence,
    observed: GithubCheckDesiredProjection,
    observed_at: UnixMillis,
}

impl CompleteGithubCheckProjection {
    /// Constructs exact provider projection evidence.
    ///
    /// # Errors
    ///
    /// Rejects an observation time before the Unix epoch.
    pub fn new(
        claim: GithubCheckProjectionClaimFence,
        observed: GithubCheckDesiredProjection,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        validate_timestamp(observed_at, "GitHub Check projection observation time")?;
        Ok(Self {
            claim,
            observed,
            observed_at,
        })
    }
    /// Returns the exact live publish claim.
    #[must_use]
    pub const fn claim(self) -> GithubCheckProjectionClaimFence {
        self.claim
    }
    /// Returns the exact provider state observed.
    #[must_use]
    pub const fn observed(self) -> GithubCheckDesiredProjection {
        self.observed
    }
    /// Returns the observation time.
    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }
}

/// Blocks one live projection whose immutable credential authority is unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockGithubCheckProjectionForCredentialRejection {
    claim: GithubCheckProjectionClaimFence,
    blocked_at: UnixMillis,
}

impl BlockGithubCheckProjectionForCredentialRejection {
    /// Constructs a closed credential-authority rejection under an exact claim.
    ///
    /// # Errors
    ///
    /// Rejects a block time before the Unix epoch.
    pub fn new(
        claim: GithubCheckProjectionClaimFence,
        blocked_at: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        validate_timestamp(blocked_at, "GitHub Check credential rejection time")?;
        Ok(Self { claim, blocked_at })
    }

    /// Returns the exact live claim being blocked.
    #[must_use]
    pub const fn claim(self) -> GithubCheckProjectionClaimFence {
        self.claim
    }

    /// Returns the trusted time at which local authority rejected the claim.
    #[must_use]
    pub const fn blocked_at(self) -> UnixMillis {
        self.blocked_at
    }
}

/// Releases a live claim for bounded delayed retry without changing external identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryGithubCheckProjection {
    claim: GithubCheckProjectionClaimFence,
    failure_kind: String,
    failed_at: UnixMillis,
    retry_at: UnixMillis,
}

impl RetryGithubCheckProjection {
    /// Constructs a sanitized bounded retry request.
    ///
    /// # Errors
    ///
    /// Rejects invalid failure identifiers or backoff intervals.
    pub fn new(
        claim: GithubCheckProjectionClaimFence,
        failure_kind: impl Into<String>,
        failed_at: UnixMillis,
        retry_at: UnixMillis,
    ) -> Result<Self, GithubCheckValueError> {
        let failure_kind = failure_kind.into();
        validate_machine_identifier(&failure_kind, MAX_FAILURE_KIND_BYTES)?;
        let delay = retry_at
            .get()
            .checked_sub(failed_at.get())
            .filter(|delay| (1..=MAX_GITHUB_CHECK_PROJECTION_RETRY_MILLIS).contains(delay))
            .ok_or(GithubCheckValueError::InvalidRetryBackoff)?;
        let _ = delay;
        validate_timestamp(failed_at, "GitHub Check projection failure time")?;
        Ok(Self {
            claim,
            failure_kind,
            failed_at,
            retry_at,
        })
    }
    /// Returns the exact live claim.
    #[must_use]
    pub const fn claim(&self) -> GithubCheckProjectionClaimFence {
        self.claim
    }
    /// Returns the sanitized failure classification.
    #[must_use]
    pub fn failure_kind(&self) -> &str {
        &self.failure_kind
    }
    /// Returns the failure time.
    #[must_use]
    pub const fn failed_at(&self) -> UnixMillis {
        self.failed_at
    }
    /// Returns the next eligible time.
    #[must_use]
    pub const fn retry_at(&self) -> UnixMillis {
        self.retry_at
    }
}

/// Invalid GitHub Checks durability values rejected before persistence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubCheckValueError {
    /// A UUID identity used the nil sentinel.
    #[error("{0} must not use the nil UUID sentinel")]
    NilUuid(&'static str),
    /// A numeric GitHub identity is zero or outside the signed 64-bit storage boundary.
    #[error("{0} must be a positive identifier representable by BIGINT")]
    InvalidNumericId(&'static str),
    /// The Git commit identity is not an exact nonzero SHA-1 object ID.
    #[error("the GitHub Check head SHA is invalid")]
    InvalidHeadSha,
    /// The provider-facing Check name is invalid.
    #[error("the GitHub Check name is invalid")]
    InvalidCheckName,
    /// The delivery-local subject key is unsafe.
    #[error("the GitHub Check subject key is invalid")]
    InvalidSubjectKey,
    /// A bounded text value is empty or untrimmed.
    #[error("{0} must not be empty or contain surrounding whitespace")]
    EmptyOrUntrimmed(&'static str),
    /// A bounded text value is too long.
    #[error("{0} exceeds its durable byte bound")]
    TooLong(&'static str),
    /// A bounded text value contains controls.
    #[error("{0} must not contain control characters")]
    ControlCharacter(&'static str),
    /// A machine identifier is not canonical.
    #[error("the GitHub Check failure kind is not canonical")]
    InvalidMachineIdentifier,
    /// A timestamp predates the Unix epoch.
    #[error("{0} must not predate the Unix epoch")]
    NegativeTimestamp(&'static str),
    /// A projection claim interval is invalid or too long.
    #[error("the GitHub Check projection claim interval is invalid")]
    InvalidClaimInterval,
    /// A create reconciliation delay is invalid or too long.
    #[error("the GitHub Check create reconciliation delay is invalid")]
    InvalidReconcileDelay,
    /// A projection retry delay is invalid or too long.
    #[error("the GitHub Check projection retry delay is invalid")]
    InvalidRetryBackoff,
    /// A durable claim fence is invalid.
    #[error("the GitHub Check projection fence is invalid")]
    InvalidClaimFence,
    /// An outbox attempt ordinal is invalid.
    #[error("the GitHub Check projection attempt is invalid")]
    InvalidAttempt,
    /// A desired projection revision is invalid.
    #[error("the GitHub Check desired revision is invalid")]
    InvalidDesiredRevision,
    /// A durable external identity is not the subject-derived identity.
    #[error("the GitHub Check external identity is invalid")]
    InvalidExternalId,
    /// A claimed action does not match its retained provider bindings.
    #[error("the GitHub Check projection action and bindings are inconsistent")]
    InvalidProjectionBinding,
    /// The manifest-pinned Checks authority does not match the subject scope.
    #[error("the GitHub Checks authority selector is inconsistent")]
    AuthoritySelectorMismatch,
}

/// Portable failures for the durable GitHub Checks projection boundary.
#[derive(Debug, Error)]
pub enum GithubCheckStoreError {
    /// Backend operation failed without exposing sensitive details.
    #[error(transparent)]
    Operation(#[from] RepositoryOperationError),
    /// The requested subject does not exist in the authenticated scope.
    #[error("the GitHub Check subject is unavailable")]
    NotFound,
    /// Registration replay changed immutable evidence.
    #[error("the GitHub Check subject replay conflicts with durable identity")]
    ReplayConflict,
    /// A run link or desired transition conflicts with durable state.
    #[error("the GitHub Check subject transition conflicts with durable state")]
    TransitionConflict,
    /// Provider delivery, repository, or run authority did not match exactly.
    #[error("the GitHub Check subject authority is not exact")]
    AuthorityRejected,
    /// An outbox claim is stale, expired, or has the wrong action.
    #[error("the GitHub Check projection claim is stale or rejected")]
    ClaimRejected,
    /// The desired-revision attempt limit is exhausted.
    #[error("the GitHub Check projection attempt limit is exhausted")]
    AttemptLimitReached,
    /// A different external suite or Check Run was already bound.
    #[error("the GitHub Check external identity conflicts with durable identity")]
    ExternalIdentityConflict,
    /// Provider projection evidence differs from the claim's frozen desired state.
    #[error("the GitHub Check provider projection is not exact")]
    ProjectionMismatch,
    /// A fence counter reached the durable signed range limit.
    #[error("the GitHub Check projection fence is exhausted")]
    FenceExhausted,
    /// Durable records violate the current-only state model.
    #[error("durable GitHub Check data violates an Automata invariant")]
    CorruptData,
}

impl GithubCheckStoreError {
    /// Wraps a sanitized backend operation failure.
    #[must_use]
    pub fn operation(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        RepositoryOperationError::from_source(source).into()
    }
}

/// Durable pre-admission Check-subject lifecycle, excluding terminalization.
#[async_trait]
pub trait GithubCheckSubjectRepository: Send + Sync {
    /// Registers a queued subject or returns the exact existing replay receipt.
    async fn register_github_check_subject(
        &self,
        request: RegisterGithubCheckSubject,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError>;

    /// Advances a queued subject to in-progress desired state.
    async fn start_github_check_projection(
        &self,
        request: StartGithubCheckProjection,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError>;
}

/// Least-authority server-owned port for explicit Check terminalization.
#[async_trait]
pub trait GithubCheckTerminalizationRepository: Send + Sync {
    /// Terminalizes queued or in-progress desired state with a closed cause mapping.
    async fn terminalize_github_check(
        &self,
        request: TerminalizeGithubCheck,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError>;
}

/// Fenced durable outbox for GitHub Checks provider workers.
#[async_trait]
pub trait GithubCheckProjectionOutbox: Send + Sync {
    /// Claims at most one eligible subject for one provider connection.
    ///
    /// Implementations must preserve the requested duration but return their
    /// own authoritative absolute claim interval.
    async fn claim_github_check_projection(
        &self,
        request: ClaimGithubCheckProjection,
    ) -> Result<Option<ClaimedGithubCheckProjection>, GithubCheckStoreError>;

    /// Binds the exact App/head suite observed under an ensure-suite claim.
    async fn bind_github_check_suite(
        &self,
        request: BindGithubCheckSuite,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError>;

    /// Persists the irreversible cutoff before the worker may issue a create POST.
    async fn begin_github_check_run_create(
        &self,
        request: BeginGithubCheckRunCreate,
    ) -> Result<GithubCheckRunCreateFence, GithubCheckStoreError>;

    /// Releases a create cutoff only when the provider future never began.
    async fn release_unissued_github_check_run_create(
        &self,
        request: ReleaseUnissuedGithubCheckRunCreate,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError>;

    /// Binds one exact Check Run from create or exact reconciliation evidence.
    async fn bind_github_check_run(
        &self,
        request: BindGithubCheckRun,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError>;

    /// Resolves reconciliation as reconcile-only missing or durably ambiguous.
    async fn resolve_github_check_run_create(
        &self,
        request: ResolveGithubCheckRunCreate,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError>;

    /// Binds the deterministic terminal presentation to the live claim.
    async fn initialize_github_check_presentation(
        &self,
        request: InitializeGithubCheckPresentation,
    ) -> Result<GithubCheckAnnotationProgress, GithubCheckStoreError>;

    /// Monotonically confirms one exact appended annotation batch.
    async fn advance_github_check_annotations(
        &self,
        request: AdvanceGithubCheckAnnotations,
    ) -> Result<GithubCheckAnnotationProgress, GithubCheckStoreError>;

    /// Releases a possibly appended batch into reconcile-only retry.
    async fn retry_uncertain_github_check_annotations(
        &self,
        request: RetryUncertainGithubCheckAnnotations,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError>;

    /// Clears uncertainty after proving GitHub retained the prior exact prefix.
    async fn clear_github_check_annotation_uncertainty(
        &self,
        request: ClearGithubCheckAnnotationUncertainty,
    ) -> Result<GithubCheckAnnotationProgress, GithubCheckStoreError>;

    /// Blocks a claim when provider annotations diverge from the presentation.
    async fn block_github_check_annotation_mismatch(
        &self,
        request: BlockGithubCheckAnnotationMismatch,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError>;

    /// Confirms that an exact bound Check Run reflects the claim-frozen projection.
    async fn complete_github_check_projection(
        &self,
        request: CompleteGithubCheckProjection,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError>;

    /// Permanently blocks a live claim rejected by its immutable credential authority.
    async fn block_github_check_projection_for_credential_rejection(
        &self,
        request: BlockGithubCheckProjectionForCredentialRejection,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError>;

    /// Releases a live claim into bounded retry state without losing uncertainty.
    async fn retry_github_check_projection(
        &self,
        request: RetryGithubCheckProjection,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError>;
}

fn validate_text(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), GithubCheckValueError> {
    if value.is_empty() || value.trim() != value {
        return Err(GithubCheckValueError::EmptyOrUntrimmed(field));
    }
    if value.len() > maximum {
        return Err(GithubCheckValueError::TooLong(field));
    }
    if value.chars().any(char::is_control) {
        return Err(GithubCheckValueError::ControlCharacter(field));
    }
    Ok(())
}

fn validate_machine_identifier(value: &str, maximum: usize) -> Result<(), GithubCheckValueError> {
    validate_text(value, maximum, "GitHub Check failure kind")?;
    let mut bytes = value.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(GithubCheckValueError::InvalidMachineIdentifier);
    }
    Ok(())
}

fn validate_timestamp(value: UnixMillis, field: &'static str) -> Result<(), GithubCheckValueError> {
    if value.get() < 0 {
        return Err(GithubCheckValueError::NegativeTimestamp(field));
    }
    Ok(())
}

fn validate_claim_interval(
    observed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<(), GithubCheckValueError> {
    validate_timestamp(observed_at, "GitHub Check claim observation time")?;
    expires_at
        .get()
        .checked_sub(observed_at.get())
        .filter(|duration| (1..=MAX_GITHUB_CHECK_PROJECTION_CLAIM_MILLIS).contains(duration))
        .ok_or(GithubCheckValueError::InvalidClaimInterval)?;
    Ok(())
}
