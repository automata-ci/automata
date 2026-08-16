use std::{fmt, sync::Arc, time::SystemTime};

use async_trait::async_trait;
use automata_ci_action_github::JavascriptRuntime;
use automata_ci_auth::secret::{SecretString, SharedSensitiveString};
use automata_ci_core::{
    ActionReference, AttemptId, EnvironmentProfile, JobConclusion, JobContentReference,
    JobIrEnvelope, JobRuntimeContext, Lease, OperationId, UnixMillis,
};
use automata_ci_execution::{
    ExecutionArgv, SandboxEnvironment, ServiceContainerBindings, TargetPath, TargetPlatform,
};
use automata_ci_expression_github::{
    ExtensionFunctionResult, GithubEvaluationContext, GithubExpressionFunctionProvider,
    GithubStatus, GithubValue,
};
use automata_ci_github_runtime::JobCommandState;
use automata_ci_protocol::JobRuntimeAuthorities;
use automata_ci_runner_runtime::ExecutorError;
use automata_ci_scm::RepositoryId;
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;
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
    /// Returns shared secret custody for one exact opaque reference.
    ///
    /// The resolution boundary returns no owned plaintext. Creating one
    /// requires a separate, explicit borrowed-exposure and copy boundary.
    ///
    /// # Errors
    ///
    /// Returns a secret-free lookup failure.
    fn resolve(&self, reference: &str) -> Result<SharedSensitiveString, PortError>;
}

/// Commits a non-durable secret-delivery acknowledgement after masking.
///
/// The executor invokes this only after every value in the verified runtime
/// context has been installed in exact [`SecretPort`] custody and registered
/// with the per-execution output masker. Implementations must not retain
/// values, create durable command material, or acknowledge a partial install.
#[async_trait]
pub trait SecretCustodyAcknowledger: fmt::Debug + Send + Sync {
    /// Acknowledges the exact installed custody operation.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure before sandbox, expression, environment,
    /// or command work begins.
    async fn acknowledge(&self, cancellation: CancellationToken) -> Result<(), ExecutorError>;
}

/// Secret port that fails closed for every reference.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSecrets;

impl SecretPort for NoSecrets {
    fn resolve(&self, _reference: &str) -> Result<SharedSensitiveString, PortError> {
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
    Secret(SharedSensitiveString),
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
            value: ContextEnvironmentValue::Secret(SharedSensitiveString::from_secret(Arc::new(
                value,
            ))),
        }
    }

    /// Creates a secret value sharing one zeroized backing allocation.
    #[must_use]
    pub fn shared_secret(name: impl Into<String>, value: Arc<SecretString>) -> Self {
        Self {
            name: name.into(),
            value: ContextEnvironmentValue::Secret(SharedSensitiveString::from_secret(value)),
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

    /// Returns the borrowed shared secret handle without copying plaintext.
    ///
    /// `None` identifies an ordinary context value. Cloning a returned handle
    /// is shallow and retains the same zeroized backing allocation.
    #[must_use]
    pub fn shared_secret_value(&self) -> Option<&SharedSensitiveString> {
        match &self.value {
            ContextEnvironmentValue::Plain(_) => None,
            ContextEnvironmentValue::Secret(value) => Some(value),
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
    runtime_context: &'a JobRuntimeContext,
    lease: &'a Lease,
    runtime_authorities: &'a JobRuntimeAuthorities,
}

impl<'a> GithubExecutionIdentity<'a> {
    /// Binds context materialization to one exact planned job and fenced attempt.
    #[must_use]
    pub const fn new(
        job: &'a JobIrEnvelope,
        runtime_context: &'a JobRuntimeContext,
        lease: &'a Lease,
        runtime_authorities: &'a JobRuntimeAuthorities,
    ) -> Self {
        Self {
            job,
            runtime_context,
            lease,
            runtime_authorities,
        }
    }

    /// Returns the immutable job plan.
    #[must_use]
    pub const fn job(self) -> &'a JobIrEnvelope {
        self.job
    }

    /// Returns the verified immutable context for this concrete job instance.
    #[must_use]
    pub const fn runtime_context(self) -> &'a JobRuntimeContext {
        self.runtime_context
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
    event: &'a GithubValue,
    commands: &'a JobCommandState,
    steps: &'a [GithubStepSnapshot],
    services: Option<&'a ServiceContainerBindings>,
    status: GithubStatus,
    step_id: Option<&'a str>,
    phase: GithubExecutionPhase,
}

impl<'a> GithubContextRequest<'a> {
    /// Creates an exact phase context request.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        identity: GithubExecutionIdentity<'a>,
        event_path: &'a TargetPath,
        event: &'a GithubValue,
        commands: &'a JobCommandState,
        steps: &'a [GithubStepSnapshot],
        status: GithubStatus,
        step_id: Option<&'a str>,
        phase: GithubExecutionPhase,
    ) -> Self {
        Self {
            identity,
            event_path,
            event,
            commands,
            steps,
            services: None,
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

    /// Returns the verified immutable context for this concrete job instance.
    #[must_use]
    pub const fn runtime_context(self) -> &'a JobRuntimeContext {
        self.identity.runtime_context()
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

    /// Returns the verified immutable event payload for `github.event`.
    #[must_use]
    pub const fn event(self) -> &'a GithubValue {
        self.event
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

    /// Adds the healthy service discovery view available after sandbox start.
    #[must_use]
    pub const fn with_services(mut self, services: Option<&'a ServiceContainerBindings>) -> Self {
        self.services = services;
        self
    }

    /// Returns healthy service discovery, when the sandbox has started.
    #[must_use]
    pub const fn services(self) -> Option<&'a ServiceContainerBindings> {
        self.services
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
    secret_masks: Vec<SharedSensitiveString>,
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
        self.secret_masks = secret_masks
            .into_iter()
            .map(SharedSensitiveString::from_secret)
            .collect();
        self
    }

    /// Adds execution-local extension functions while retaining any functions
    /// already supplied by the product context.
    #[must_use]
    pub(crate) fn with_execution_functions(
        mut self,
        functions: Arc<dyn GithubExpressionFunctionProvider>,
    ) -> Self {
        self.expression = Arc::new(ExecutionFunctionContext {
            base: self.expression,
            functions,
        });
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
    pub fn secret_masks(&self) -> &[SharedSensitiveString] {
        &self.secret_masks
    }
}

struct ExecutionFunctionContext {
    base: Arc<dyn GithubEvaluationContext>,
    functions: Arc<dyn GithubExpressionFunctionProvider>,
}

impl GithubEvaluationContext for ExecutionFunctionContext {
    fn named_value(&self, name: &str) -> Option<GithubValue> {
        self.base.named_value(name)
    }

    fn status(&self) -> GithubStatus {
        self.base.status()
    }

    fn functions(&self) -> &dyn GithubExpressionFunctionProvider {
        self
    }
}

impl GithubExpressionFunctionProvider for ExecutionFunctionContext {
    fn call(&self, name: &str, arguments: &[GithubValue]) -> ExtensionFunctionResult {
        self.base
            .functions()
            .call(name, arguments)
            .or_else(|| self.functions.call(name, arguments))
    }
}

impl fmt::Debug for ExecutionFunctionContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionFunctionContext")
            .field("base", &self.base)
            .field("functions", &self.functions)
            .finish()
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

/// Provides target paths baked into one platform-specific runner environment.
pub trait GithubToolchain: fmt::Debug + Send + Sync {
    /// Returns the target platform shared by every configured executable.
    fn platform(&self) -> TargetPlatform;
    /// Returns the exact Bash executable, when available.
    fn bash(&self) -> Option<&TargetPath>;
    /// Returns the exact POSIX `sh` executable, when available.
    fn sh(&self) -> Option<&TargetPath>;
    /// Returns the configured Python executable, when the environment provides one.
    fn python(&self) -> Option<&TargetPath>;
    /// Returns the configured PowerShell Core executable, when the environment provides one.
    fn pwsh(&self) -> Option<&TargetPath>;
    /// Returns the configured Windows PowerShell executable, when available.
    fn powershell(&self) -> Option<&TargetPath>;
    /// Returns the configured Windows command interpreter, when available.
    fn cmd(&self) -> Option<&TargetPath>;
    /// Returns the exact POSIX directory creation utility, when available.
    fn install(&self) -> Option<&TargetPath>;
    /// Returns the exact POSIX archive extraction utility, when available.
    fn tar(&self) -> Option<&TargetPath>;
    /// Returns the exact POSIX SHA-256 utility and its fixed arguments, when available.
    fn sha256(&self) -> Option<&ExecutionArgv>;
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
    /// Creates the fresh per-phase `GITHUB_ARTIFACTS` declaration file.
    InitializeArtifactsFile = 9,
    /// Publishes the fresh read-only `GITHUB_ARTIFACTS_LIST` snapshot.
    InitializeArtifactsList = 10,
    /// Reads one completed `GITHUB_ARTIFACTS` declaration file.
    ReadArtifactsFile = 11,
    /// Evaluates one runner-local `hashFiles` call inside the fenced sandbox.
    HashFiles = 12,
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

    /// Derives a stable hash operation from both phase and per-phase file index.
    fn artifact_hash_operation_id(
        &self,
        attempt_id: AttemptId,
        phase: u32,
        file_index: u32,
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

    fn artifact_hash_operation_id(
        &self,
        attempt_id: AttemptId,
        phase: u32,
        file_index: u32,
    ) -> OperationId {
        let mut hasher = Sha256::new();
        hasher.update(b"automata/github-job-executor/artifact-hash-operation/v1\0");
        hasher.update(attempt_id.as_uuid().as_bytes());
        hasher.update(phase.to_be_bytes());
        hasher.update(file_index.to_be_bytes());
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
