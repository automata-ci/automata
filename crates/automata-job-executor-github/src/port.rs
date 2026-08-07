use std::{fmt, sync::Arc, time::SystemTime};

use async_trait::async_trait;
use automata_action_github::JavascriptRuntime;
use automata_auth::secret::SecretString;
use automata_core::{
    ActionReference, AttemptId, EnvironmentProfile, JobConclusion, JobContentReference,
    JobIrEnvelope, Lease, OperationId, UnixMillis,
};
use automata_execution::{SandboxEnvironment, TargetPath};
use automata_expression_github::{GithubEvaluationContext, GithubStatus};
use automata_github_runtime::JobCommandState;
use automata_protocol::JobRuntimeAuthorities;
use automata_scm::RepositoryId;
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{ActionPreparationError, PortError, PreparedAction};

/// Resolves one immutable repository action into executable, verified content.
#[async_trait]
pub trait ActionPreparationPort: fmt::Debug + Send + Sync {
    /// Resolves, verifies, decodes, and prepares one action.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure without repository credentials or content.
    async fn prepare(
        &self,
        request: ActionPreparationRequest<'_>,
    ) -> Result<PreparedAction, ActionPreparationError>;
}

/// Loads and verifies immutable content explicitly referenced by `JobIR`.
///
/// The implementation must use the exact logical object key retained by
/// admission. Its configured backing namespace (including any provider prefix)
/// must be shared with the admission publisher; a mismatch is a deployment
/// error that fails execution closed as missing content.
#[async_trait]
pub trait JobContentPort: fmt::Debug + Send + Sync {
    /// Returns exact verified bytes for one credential-free descriptor.
    ///
    /// # Errors
    ///
    /// Fails closed for missing, oversized, unauthorized, or inconsistent
    /// content. `NotFound` also covers a runner whose immutable namespace or
    /// provider prefix does not match the admission publisher.
    async fn load(&self, reference: &JobContentReference) -> Result<Bytes, PortError>;
}

/// Immutable request for action preparation.
#[derive(Clone, Copy, Debug)]
pub struct ActionPreparationRequest<'a> {
    reference: &'a ActionReference,
}

impl<'a> ActionPreparationRequest<'a> {
    /// Wraps the exact action reference retained in `JobIR`.
    #[must_use]
    pub const fn new(reference: &'a ActionReference) -> Self {
        Self { reference }
    }

    /// Returns the exact semantic action reference.
    #[must_use]
    pub const fn reference(self) -> &'a ActionReference {
        self.reference
    }
}

/// Supplies a narrowly scoped credential for fetching a repository action.
pub trait RepositoryCredentialPort: fmt::Debug + Send + Sync {
    /// Returns a fresh credential for this repository, or `None` for public access.
    ///
    /// # Errors
    ///
    /// Returns a secret-free lookup failure.
    fn credential(&self, repository: &RepositoryId) -> Result<Option<SecretString>, PortError>;
}

/// Repository credential port that always requests public access.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoRepositoryCredentials;

impl RepositoryCredentialPort for NoRepositoryCredentials {
    fn credential(&self, _repository: &RepositoryId) -> Result<Option<SecretString>, PortError> {
        Ok(None)
    }
}

/// Resolves a runner-scoped `JobIR` secret reference.
pub trait SecretPort: fmt::Debug + Send + Sync {
    /// Returns fresh secret material for one exact opaque reference.
    ///
    /// # Errors
    ///
    /// Returns a secret-free lookup failure.
    fn resolve(&self, reference: &str) -> Result<SecretString, PortError>;
}

/// Secret port that fails closed for every reference.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSecrets;

impl SecretPort for NoSecrets {
    fn resolve(&self, _reference: &str) -> Result<SecretString, PortError> {
        Err(PortError::new(crate::error::PortErrorKind::NotFound))
    }
}

/// One standard runner environment value returned with a GitHub context.
pub struct ContextEnvironmentVariable {
    name: String,
    value: ContextEnvironmentValue,
}

enum ContextEnvironmentValue {
    Plain(String),
    Secret(Arc<SecretString>),
}

impl ContextEnvironmentVariable {
    /// Creates a non-secret context environment value.
    #[must_use]
    pub fn plain(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: ContextEnvironmentValue::Plain(value.into()),
        }
    }

    /// Creates a secret context environment value with redacted debug output.
    #[must_use]
    pub fn secret(name: impl Into<String>, value: SecretString) -> Self {
        Self {
            name: name.into(),
            value: ContextEnvironmentValue::Secret(Arc::new(value)),
        }
    }

    /// Creates a secret value sharing one zeroized backing allocation.
    #[must_use]
    pub fn shared_secret(name: impl Into<String>, value: Arc<SecretString>) -> Self {
        Self {
            name: name.into(),
            value: ContextEnvironmentValue::Secret(value),
        }
    }

    /// Returns the process environment name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Explicitly exposes the environment value to the process adapter.
    #[must_use]
    pub fn expose_value(&self) -> &str {
        match &self.value {
            ContextEnvironmentValue::Plain(value) => value,
            ContextEnvironmentValue::Secret(value) => value.expose_secret(),
        }
    }

    /// Returns whether the value must be registered with the log masker.
    #[must_use]
    pub const fn is_secret(&self) -> bool {
        matches!(self.value, ContextEnvironmentValue::Secret(_))
    }
}

impl fmt::Debug for ContextEnvironmentVariable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextEnvironmentVariable")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .field("secret", &self.is_secret())
            .finish()
    }
}

/// Runtime phase for context and environment materialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubExecutionPhase {
    /// Whole-job condition evaluation.
    Job,
    /// Workflow `run` step.
    Run,
    /// JavaScript action pre phase.
    ActionPre,
    /// JavaScript action main phase.
    ActionMain,
    /// JavaScript action post phase.
    ActionPost,
}

/// Borrowed request used to build a late GitHub expression context.
#[derive(Clone, Copy, Debug)]
pub struct GithubExecutionIdentity<'a> {
    job: &'a JobIrEnvelope,
    lease: &'a Lease,
    runtime_authorities: &'a JobRuntimeAuthorities,
}

impl<'a> GithubExecutionIdentity<'a> {
    /// Binds context materialization to one exact planned job and fenced attempt.
    #[must_use]
    pub const fn new(
        job: &'a JobIrEnvelope,
        lease: &'a Lease,
        runtime_authorities: &'a JobRuntimeAuthorities,
    ) -> Self {
        Self {
            job,
            lease,
            runtime_authorities,
        }
    }

    /// Returns the immutable job plan.
    #[must_use]
    pub const fn job(self) -> &'a JobIrEnvelope {
        self.job
    }

    /// Returns the exact fenced lease owning this execution.
    #[must_use]
    pub const fn lease(self) -> &'a Lease {
        self.lease
    }

    /// Returns the exact protected authority delivered with this lease.
    #[must_use]
    pub const fn runtime_authorities(self) -> &'a JobRuntimeAuthorities {
        self.runtime_authorities
    }
}

/// Borrowed request used to build a late GitHub expression context.
#[derive(Clone, Copy, Debug)]
pub struct GithubContextRequest<'a> {
    identity: GithubExecutionIdentity<'a>,
    event_path: &'a TargetPath,
    commands: &'a JobCommandState,
    steps: &'a [GithubStepSnapshot],
    status: GithubStatus,
    step_id: Option<&'a str>,
    phase: GithubExecutionPhase,
}

impl<'a> GithubContextRequest<'a> {
    /// Creates an exact phase context request.
    #[must_use]
    pub const fn new(
        identity: GithubExecutionIdentity<'a>,
        event_path: &'a TargetPath,
        commands: &'a JobCommandState,
        steps: &'a [GithubStepSnapshot],
        status: GithubStatus,
        step_id: Option<&'a str>,
        phase: GithubExecutionPhase,
    ) -> Self {
        Self {
            identity,
            event_path,
            commands,
            steps,
            status,
            step_id,
            phase,
        }
    }

    /// Returns the immutable job plan.
    #[must_use]
    pub const fn job(self) -> &'a JobIrEnvelope {
        self.identity.job()
    }

    /// Returns the exact fenced lease owning this execution.
    #[must_use]
    pub const fn lease(self) -> &'a Lease {
        self.identity.lease()
    }

    /// Returns the exact protected authority delivered with this lease.
    #[must_use]
    pub const fn runtime_authorities(self) -> &'a JobRuntimeAuthorities {
        self.identity.runtime_authorities()
    }

    /// Returns the fresh sandbox path containing the verified event payload.
    #[must_use]
    pub const fn event_path(self) -> &'a TargetPath {
        self.event_path
    }

    /// Returns completed-step command state.
    #[must_use]
    pub const fn commands(self) -> &'a JobCommandState {
        self.commands
    }

    /// Returns outcomes already visible through the `steps` context.
    #[must_use]
    pub const fn steps(self) -> &'a [GithubStepSnapshot] {
        self.steps
    }

    /// Returns current status-function state.
    #[must_use]
    pub const fn status(self) -> GithubStatus {
        self.status
    }

    /// Returns the current step ID when this is a step phase.
    #[must_use]
    pub const fn step_id(self) -> Option<&'a str> {
        self.step_id
    }

    /// Returns the exact execution phase.
    #[must_use]
    pub const fn phase(self) -> GithubExecutionPhase {
        self.phase
    }
}

/// One completed step result exposed to late expression contexts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubStepSnapshot {
    id: String,
    outcome: JobConclusion,
    conclusion: JobConclusion,
}

impl GithubStepSnapshot {
    /// Creates one completed-step context value.
    #[must_use]
    pub fn new(id: impl Into<String>, outcome: JobConclusion, conclusion: JobConclusion) -> Self {
        Self {
            id: id.into(),
            outcome,
            conclusion,
        }
    }

    /// Returns the semantic step identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the actual step outcome before `continue-on-error` mapping.
    #[must_use]
    pub const fn outcome(&self) -> JobConclusion {
        self.outcome
    }

    /// Returns the conclusion visible to later status checks.
    #[must_use]
    pub const fn conclusion(&self) -> JobConclusion {
        self.conclusion
    }
}

/// Expression context and standard runner environment produced atomically.
pub struct GithubContextSnapshot {
    expression: Arc<dyn GithubEvaluationContext>,
    environment: Vec<ContextEnvironmentVariable>,
    secret_masks: Vec<Arc<SecretString>>,
}

impl GithubContextSnapshot {
    /// Creates one phase snapshot.
    #[must_use]
    pub fn new(
        expression: Arc<dyn GithubEvaluationContext>,
        environment: Vec<ContextEnvironmentVariable>,
    ) -> Self {
        Self {
            expression,
            environment,
            secret_masks: Vec::new(),
        }
    }

    /// Registers additional context-only secrets with the log masker.
    ///
    /// Use this for values such as `github.token` which can flow through an
    /// expression into an action input without also being a standard process
    /// environment variable.
    #[must_use]
    pub fn with_secret_masks(mut self, secret_masks: Vec<Arc<SecretString>>) -> Self {
        self.secret_masks = secret_masks;
        self
    }

    /// Returns the read-only expression context.
    #[must_use]
    pub fn expression(&self) -> &dyn GithubEvaluationContext {
        self.expression.as_ref()
    }

    /// Returns standard process environment in deterministic order.
    #[must_use]
    pub fn environment(&self) -> &[ContextEnvironmentVariable] {
        &self.environment
    }

    /// Returns context-only values which must be masked before evaluation can
    /// expose them to a process.
    #[must_use]
    pub fn secret_masks(&self) -> &[Arc<SecretString>] {
        &self.secret_masks
    }
}

impl fmt::Debug for GithubContextSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubContextSnapshot")
            .field("expression", &self.expression)
            .field("environment_names", &self.environment)
            .field("secret_mask_count", &self.secret_masks.len())
            .finish()
    }
}

/// Builds late contexts and standard GitHub runner environment per phase.
///
/// This is also the late authority boundary for server-issued, job-scoped
/// values such as `github.token`, `ACTIONS_RUNTIME_TOKEN`, and
/// `ACTIONS_RESULTS_URL`. Implementations must fetch or retain those values as
/// job authority, never derive them from a static runner credential. Context-
/// only values belong in [`GithubContextSnapshot::with_secret_masks`]; values
/// GitHub actually exports belong in [`ContextEnvironmentVariable`].
pub trait GithubContextPort: fmt::Debug + Send + Sync {
    /// Produces one immutable context snapshot.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure for unavailable or inconsistent context data.
    fn snapshot(
        &self,
        request: GithubContextRequest<'_>,
    ) -> Result<GithubContextSnapshot, PortError>;
}

/// Selects exact launch material for a scheduler-attested environment profile.
pub trait SandboxEnvironmentCatalog: fmt::Debug + Send + Sync {
    /// Returns exact immutable launch material, or `None` if no longer available.
    fn select(&self, profile: &EnvironmentProfile) -> Option<SandboxEnvironment>;
}

/// Provides target paths baked into one attested runner environment.
pub trait GithubToolchain: fmt::Debug + Send + Sync {
    /// Returns the exact Bash executable.
    fn bash(&self) -> &TargetPath;
    /// Returns the exact POSIX `sh` executable.
    fn sh(&self) -> &TargetPath;
    /// Returns the exact directory creation utility.
    fn install(&self) -> &TargetPath;
    /// Returns the exact archive extraction utility.
    fn tar(&self) -> &TargetPath;
    /// Returns the exact executable for a metadata-selected Node runtime.
    fn node(&self, runtime: JavascriptRuntime) -> Option<&TargetPath>;
}

/// Stable endpoint operation classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OperationPurpose {
    /// Creates a private sandbox directory.
    PrepareDirectory = 1,
    /// Copies one exact workflow script.
    CopyScript = 2,
    /// Copies one verified action archive.
    CopyActionArchive = 3,
    /// Extracts one verified action archive.
    ExtractActionArchive = 4,
    /// Creates one fresh command file.
    InitializeCommandFile = 5,
    /// Runs one workflow or action phase.
    ExecutePhase = 6,
    /// Reads one completed command file.
    ReadCommandFile = 7,
    /// Materializes the exact verified workflow event payload.
    CopyEvent = 8,
}

/// Derives deterministic IDs for retryable endpoint operations.
pub trait ExecutionOperationIds: fmt::Debug + Send + Sync {
    /// Derives one stable ID from non-secret execution coordinates.
    fn operation_id(
        &self,
        attempt_id: AttemptId,
        purpose: OperationPurpose,
        ordinal: u32,
    ) -> OperationId;
}

/// SHA-256 domain-separated deterministic operation IDs.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeterministicOperationIds;

impl ExecutionOperationIds for DeterministicOperationIds {
    fn operation_id(
        &self,
        attempt_id: AttemptId,
        purpose: OperationPurpose,
        ordinal: u32,
    ) -> OperationId {
        let mut hasher = Sha256::new();
        hasher.update(b"automata/github-job-executor/operation/v1\0");
        hasher.update(attempt_id.as_uuid().as_bytes());
        hasher.update([purpose as u8]);
        hasher.update(ordinal.to_be_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        OperationId::from_uuid(Uuid::from_bytes(bytes))
    }
}

/// Wall clock used only for result timestamps and job deadlines.
pub trait ExecutionClock: fmt::Debug + Send + Sync {
    /// Returns current Unix time in milliseconds.
    fn now(&self) -> UnixMillis;
}

/// Host wall-clock adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemExecutionClock;

impl ExecutionClock for SystemExecutionClock {
    fn now(&self) -> UnixMillis {
        let milliseconds = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |duration| {
                i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
            });
        UnixMillis::new(milliseconds)
    }
}
