use std::{
    collections::BTreeMap,
    fmt,
    future::Future,
    ops::Deref,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use automata_ci_action_github::{GithubActionMetadataDecoder, JavascriptRuntime};
use automata_ci_core::{
    ActionReference, AttemptId, JOB_RUNTIME_CONTEXT_MEDIA_TYPE, JobAuthorityProfile, JobConclusion,
    JobIrEnvelope, JobLifecycle, JobResult, JobResultOutput, JobResultValidationError,
    JobRuntimeContext, MAX_JOB_RESULT_ANNOTATIONS, MAX_JOB_RESULT_ATTACHMENT_BYTES,
    MAX_STEP_ANNOTATION_PROPERTIES, MAX_STEP_ATTACHMENT_TEXT_BYTES, OperationId, OutputSensitivity,
    RuntimeBoolean, RuntimePositiveInteger, RuntimeTimeoutTemplate, SecretBinding, SemanticStep,
    StepAnnotation, StepAnnotationLevel, StepAnnotationProperty, StepResult, TrustOutputAuthority,
    UnixMillis, ValueSource, ValueTemplate, WORKFLOW_EVENT_MEDIA_TYPE,
};
use automata_ci_execution::{
    Cancellation, CancellationDisposition, CopyFromRequest, CopyToRequest, DestroySandbox,
    ExecutionArgv, ExecutionCommand, ExecutionEndpoint, ExecutionError, ExecutionErrorKind,
    ExecutionOutput, ExecutionTermination, NetworkPolicy, ProviderCapabilities, ProviderError,
    ProviderErrorKind, RootFilesystemPolicy, SandboxCapability, SandboxGeneration, SandboxHandle,
    SandboxLaunch, SandboxProvider, SandboxState, ServiceContainerBindings, ServiceContainerSpecs,
    TargetPath, TargetPlatform,
};
use automata_ci_expression_github::{
    ExtensionFunctionResult, GithubEvaluationContext, GithubExpressionEvaluator,
    GithubExpressionFunctionProvider, GithubObject, GithubStatus, GithubValue,
};
use automata_ci_github_runtime::{
    ActionInvocationId, ArtifactDeclaration, ArtifactDeclarationCommandFile, ArtifactSubject,
    ArtifactSubjectCommandFile, ArtifactSubjectKind, CommandFileDecoder, CommandFileKind,
    CommandFilePlatform, CompletedStepApplicator, CompletedStepCommands, EnvironmentCommandFile,
    GithubCommandFileDecoder, GithubCompletedStepApplicator, JobCommandState,
    MAX_ARTIFACT_DECLARATION_FILE_BYTES, MAX_ARTIFACT_SUBJECTS, ParsedCommandFile, PathCommandFile,
    PhaseApplicationError, PhaseApplicationNotice, StateCommandFile, StepId as RuntimeStepId,
    StepPhase, StepScope, StepSummaryCommandFile, WorkflowCommandLimits, WorkflowCommandPolicy,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_protocol_protobuf::{DecodeError, decode_job_runtime_context};
use automata_ci_runner_journal::{
    ProviderFailureKind, ProviderFailureOutcome, ProviderName, ProviderOperationKind,
    SandboxHandle as JournalSandboxHandle, SandboxIdentity,
};
use automata_ci_runner_runtime::{
    AdmissionRejection, CleanupFuture, CleanupRequest, ExecutionAdmission, ExecutionCancellation,
    ExecutionEvents, ExecutionRequest, ExecutorError, ExecutorErrorKind, ExecutorFuture,
    JobExecutor,
};
use sha2::{Digest as _, Sha256};

use crate::{
    ActionPreparationErrorKind, ActionPreparationPort, ActionPreparationRequest,
    CheckedOutLocalActionPreparer, ExecutionClock, ExecutionOperationIds, GithubContextPort,
    GithubContextRequest, GithubExecutionIdentity, GithubExecutionPhase, GithubJobExecutorConfig,
    GithubStepSnapshot, GithubToolchain, JobContentPort, LocalActionPreparationRequest,
    OperationPurpose, PreparedAction, PreparedActionDefinition, PreparedActionExecution,
    PreparedBoolean, PreparedCompositeAction, PreparedCompositeStep, PreparedKeyValue,
    PreparedLocalAction, PreparedValue, SandboxEnvironmentCatalog, SecretCustodyAcknowledger,
    SecretPort, action_content, container_runtime,
    environment::{
        EnvironmentBuilder, ResolvedActionInputs, ResolvedEnvironmentValue,
        validate_environment_overlay_names,
    },
    error::{ExecutorAdapterError, ExecutorAdapterErrorKind, PortErrorKind},
    output::{SecretMasker, emit_system, parse_output_with_cancellation, process_output},
    shell::{
        ShellAdmissionRejection, admit_shell_template, composite_shell, resolve_shell_template,
        shell_argv,
    },
};
use automata_ci_workflow_github::GithubConditionCompiler;

const DIRECTORY_MODE: &str = "0700";
const MAX_ACTION_NESTING_DEPTH: usize = 10;
const MAX_COMPOSITE_CHILD_STEPS: usize = 10_000;
const MAX_ACTION_INVOCATIONS: u32 = 10_000;
const MAX_COMPOSITE_DERIVED_BYTES: usize = 16_777_216;
const MAX_EVENT_DEPTH: usize = 128;
const COMPOSITE_ORDINAL_BASE: u32 = 1 << 24;
const TRUNCATED_OUTPUT_DIAGNOSTIC: &str =
    "command output exceeded the configured capture limit; user output was suppressed";
const MASKED_SUMMARY_LIMIT_DIAGNOSTIC: &str = "$GITHUB_STEP_SUMMARY content was omitted after secret masking exceeded the retained text limit";
const STEP_SUMMARY_LIMIT_DIAGNOSTIC: &str =
    "$GITHUB_STEP_SUMMARY content was omitted after the cumulative step summary limit was reached";
const JOB_SUMMARY_LIMIT_DIAGNOSTIC: &str =
    "$GITHUB_STEP_SUMMARY content was omitted after the job attachment limit was reached";
const LOCAL_ACTION_PROBE_SCRIPT: &str = "# automata-local-action-metadata\nif [ -f \"$1\" ]; then printf yml; elif [ -f \"$2\" ]; then printf yaml; else exit 44; fi";
const ARTIFACT_HASH_SCRIPT: &str = "# automata-artifact-sha256\npath=$1\nshift\nif [ ! -f \"$path\" ]; then exit 44; fi\nvalue=$(\"$0\" \"$@\" < \"$path\") || exit $?\ndigest=${value%% *}\nprintf '%s' \"$digest\"";
const WINDOWS_ARTIFACT_HASH_SCRIPT: &str = "# automata-artifact-sha256\n$ErrorActionPreference = 'Stop'\n$path = $env:AUTOMATA_INTERNAL_ARTIFACT_PATH\nif (-not [System.IO.File]::Exists($path)) { exit 44 }\n$stream = $null\n$hasher = $null\ntry {\n  $stream = [System.IO.File]::OpenRead($path)\n  $hasher = [System.Security.Cryptography.SHA256]::Create()\n  $bytes = $hasher.ComputeHash($stream)\n  $digest = [System.BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()\n  [Console]::Out.Write($digest)\n} finally {\n  if ($null -ne $stream) { $stream.Dispose() }\n  if ($null -ne $hasher) { $hasher.Dispose() }\n}";
const WINDOWS_ARTIFACT_PATH_ENVIRONMENT: &str = "AUTOMATA_INTERNAL_ARTIFACT_PATH";
const ARTIFACT_HASH_OUTPUT_BYTES: usize = 128;
const ARTIFACT_HASH_TIMEOUT: Duration = Duration::from_mins(5);
const HASH_FILES_OUTPUT_BYTES: usize = 65;
const HASH_FILES_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_HASH_FILES_PATTERN_BYTES: usize = 4_096;
const MAX_HASH_FILES_AGGREGATE_PATTERN_BYTES: usize = 65_536;
const HASH_FILES_SCRIPT: &str = r"/*automata-hash-files*/const fs=require('node:fs/promises');const crypto=require('node:crypto');const path=require('node:path');(async()=>{const root=await fs.realpath(process.cwd());const raw=process.argv.slice(1);const includes=[];const excludes=[];for(const value of raw){if(value.startsWith('!')){if(value.length>1)excludes.push(value.slice(1));}else{includes.push(value);}}const files=new Map();for(const pattern of includes){for await(const candidate of fs.glob(pattern,{cwd:root,exclude:excludes,withFileTypes:false})){const absolute=path.resolve(root,candidate);let resolved;try{resolved=await fs.realpath(absolute);}catch{continue;}const relative=path.relative(root,resolved);if(relative===''||relative==='..'||relative.startsWith('..'+path.sep)||path.isAbsolute(relative))continue;let metadata;try{metadata=await fs.stat(resolved);}catch{continue;}if(metadata.isFile())files.set(relative.split(path.sep).join('/'),resolved);}}const ordered=[...files].sort((left,right)=>left[0]<right[0]?-1:left[0]>right[0]?1:0);const aggregate=crypto.createHash('sha256');for(const[,file]of ordered){aggregate.update(crypto.createHash('sha256').update(await fs.readFile(file)).digest());}process.stdout.write(ordered.length===0?'':aggregate.digest('hex'));})().catch(()=>process.exit(44));";
const ARTIFACTS_LIST_ENVIRONMENT: &str = "GITHUB_ARTIFACTS_LIST";
const COMMAND_FILE_KINDS: [CommandFileKind; 5] = [
    CommandFileKind::Environment,
    CommandFileKind::Output,
    CommandFileKind::Path,
    CommandFileKind::State,
    CommandFileKind::StepSummary,
];

/// Object-safe dependencies composed into a GitHub job executor.
pub struct GithubJobExecutorPorts {
    provider: Arc<dyn SandboxProvider>,
    environments: Arc<dyn SandboxEnvironmentCatalog>,
    actions: Arc<dyn ActionPreparationPort>,
    content: Arc<dyn JobContentPort>,
    secrets: Arc<dyn SecretPort>,
    contexts: Arc<dyn GithubContextPort>,
    toolchain: Arc<dyn GithubToolchain>,
    operation_ids: Arc<dyn ExecutionOperationIds>,
    clock: Arc<dyn ExecutionClock>,
}

impl GithubJobExecutorPorts {
    /// Composes every external dependency explicitly.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        provider: Arc<dyn SandboxProvider>,
        environments: Arc<dyn SandboxEnvironmentCatalog>,
        actions: Arc<dyn ActionPreparationPort>,
        content: Arc<dyn JobContentPort>,
        secrets: Arc<dyn SecretPort>,
        contexts: Arc<dyn GithubContextPort>,
        toolchain: Arc<dyn GithubToolchain>,
        operation_ids: Arc<dyn ExecutionOperationIds>,
        clock: Arc<dyn ExecutionClock>,
    ) -> Self {
        Self {
            provider,
            environments,
            actions,
            content,
            secrets,
            contexts,
            toolchain,
            operation_ids,
            clock,
        }
    }
}

impl fmt::Debug for GithubJobExecutorPorts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubJobExecutorPorts")
            .field("provider", &self.provider)
            .field("environments", &self.environments)
            .field("actions", &self.actions)
            .field("content", &self.content)
            .field("secrets", &self.secrets)
            .field("contexts", &self.contexts)
            .field("toolchain", &self.toolchain)
            .field("operation_ids", &self.operation_ids)
            .field("clock", &self.clock)
            .finish()
    }
}

/// Generic GitHub Actions job executor over one pluggable sandbox provider.
pub struct GithubJobExecutor {
    config: GithubJobExecutorConfig,
    ports: GithubJobExecutorPorts,
    local_actions: CheckedOutLocalActionPreparer,
    expressions: GithubExpressionEvaluator,
    command_files: GithubCommandFileDecoder,
    completed_steps: GithubCompletedStepApplicator,
    workflow_command_limits: WorkflowCommandLimits,
    workflow_command_policy: WorkflowCommandPolicy,
    custody_acknowledger: Option<Arc<dyn SecretCustodyAcknowledger>>,
    managed_secret_bindings: Option<BTreeMap<String, SecretBinding>>,
}

/// An admitted execution request paired with its verified immutable context.
///
/// The context is hydrated once before any sandbox or action work and then
/// borrowed by every phase snapshot for the lifetime of this execution.
#[derive(Clone, Copy)]
struct HydratedExecutionRequest<'a> {
    request: &'a ExecutionRequest,
    runtime_context: &'a JobRuntimeContext,
    execution_functions: Option<&'a Arc<dyn GithubExpressionFunctionProvider>>,
}

impl<'a> HydratedExecutionRequest<'a> {
    const fn new(request: &'a ExecutionRequest, runtime_context: &'a JobRuntimeContext) -> Self {
        Self {
            request,
            runtime_context,
            execution_functions: None,
        }
    }

    const fn runtime_context(self) -> &'a JobRuntimeContext {
        self.runtime_context
    }

    const fn with_execution_functions(
        mut self,
        functions: &'a Arc<dyn GithubExpressionFunctionProvider>,
    ) -> Self {
        self.execution_functions = Some(functions);
        self
    }

    const fn execution_functions(self) -> Option<&'a Arc<dyn GithubExpressionFunctionProvider>> {
        self.execution_functions
    }
}

impl Deref for HydratedExecutionRequest<'_> {
    type Target = ExecutionRequest;

    fn deref(&self) -> &Self::Target {
        self.request
    }
}

struct SandboxExpressionFunctions {
    endpoint: Arc<dyn ExecutionEndpoint>,
    workspace: TargetPath,
    node: TargetPath,
    attempt_id: AttemptId,
    operation_ids: Arc<dyn ExecutionOperationIds>,
    cancellation: ExecutionCancellation,
    next_hash_files_ordinal: AtomicU32,
}

impl SandboxExpressionFunctions {
    fn new(
        endpoint: Arc<dyn ExecutionEndpoint>,
        workspace: TargetPath,
        node: TargetPath,
        attempt_id: AttemptId,
        operation_ids: Arc<dyn ExecutionOperationIds>,
        cancellation: ExecutionCancellation,
    ) -> Self {
        Self {
            endpoint,
            workspace,
            node,
            attempt_id,
            operation_ids,
            cancellation,
            next_hash_files_ordinal: AtomicU32::new(0),
        }
    }

    fn hash_files(&self, arguments: &[GithubValue]) -> Option<String> {
        if self.cancellation.is_cancelled() {
            return None;
        }
        let mut aggregate_bytes = 0_usize;
        let mut patterns = Vec::with_capacity(arguments.len());
        for argument in arguments {
            let pattern = argument.coerce_to_string();
            if pattern.is_empty()
                || pattern.len() > MAX_HASH_FILES_PATTERN_BYTES
                || pattern.chars().any(char::is_control)
            {
                return None;
            }
            aggregate_bytes = aggregate_bytes.checked_add(pattern.len())?;
            if aggregate_bytes > MAX_HASH_FILES_AGGREGATE_PATTERN_BYTES {
                return None;
            }
            patterns.push(pattern);
        }
        let ordinal = self
            .next_hash_files_ordinal
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .ok()?;
        let mut argv = vec![
            "--eval".to_owned(),
            HASH_FILES_SCRIPT.to_owned(),
            "--".to_owned(),
        ];
        argv.extend(patterns);
        let argv = ExecutionArgv::new(self.node.clone(), argv).ok()?;
        let command = ExecutionCommand::new(
            self.operation_ids
                .operation_id(self.attempt_id, OperationPurpose::HashFiles, ordinal),
            argv,
            self.workspace.clone(),
            automata_ci_execution::ExecutionEnvironment::empty(),
            HASH_FILES_TIMEOUT,
            HASH_FILES_OUTPUT_BYTES,
        )
        .ok()?;
        let output = self
            .endpoint
            .exec(&command, &ProviderCancellationBridge(&self.cancellation))
            .ok()?;
        if self.cancellation.is_cancelled()
            || output.was_truncated()
            || output.termination() != ExecutionTermination::Exited(0)
            || !output.stderr().is_empty()
        {
            return None;
        }
        let digest = std::str::from_utf8(output.stdout()).ok()?;
        if digest.is_empty() {
            return Some(String::new());
        }
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        Some(digest.to_ascii_lowercase())
    }
}

impl GithubExpressionFunctionProvider for SandboxExpressionFunctions {
    fn call(&self, name: &str, arguments: &[GithubValue]) -> ExtensionFunctionResult {
        if name != "hashfiles" {
            return None;
        }
        self.hash_files(arguments)
            .map(|digest| Ok(GithubValue::string(digest)))
    }
}

impl fmt::Debug for SandboxExpressionFunctions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SandboxExpressionFunctions")
            .field("endpoint", &self.endpoint)
            .field("workspace", &self.workspace)
            .field("node", &self.node)
            .field("attempt_id", &self.attempt_id)
            .field("operation_ids", &self.operation_ids)
            .field("cancelled", &self.cancellation.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl GithubJobExecutor {
    /// Creates an executor pinned to the reviewed GitHub compatibility engines.
    #[must_use]
    pub fn new(config: GithubJobExecutorConfig, ports: GithubJobExecutorPorts) -> Self {
        Self {
            config,
            ports,
            local_actions: CheckedOutLocalActionPreparer::new(
                Arc::new(GithubActionMetadataDecoder::default()),
                GithubConditionCompiler::default(),
            ),
            expressions: GithubExpressionEvaluator::default(),
            command_files: GithubCommandFileDecoder::default(),
            completed_steps: GithubCompletedStepApplicator::default(),
            workflow_command_limits: WorkflowCommandLimits::default(),
            workflow_command_policy: WorkflowCommandPolicy::default(),
            custody_acknowledger: None,
            managed_secret_bindings: None,
        }
    }

    /// Overrides pure compatibility policies for bounded tests or deployments.
    #[must_use]
    pub const fn with_compatibility_engines(
        mut self,
        expressions: GithubExpressionEvaluator,
        command_files: GithubCommandFileDecoder,
        completed_steps: GithubCompletedStepApplicator,
        workflow_command_limits: WorkflowCommandLimits,
        workflow_command_policy: WorkflowCommandPolicy,
    ) -> Self {
        self.expressions = expressions;
        self.command_files = command_files;
        self.completed_steps = completed_steps;
        self.workflow_command_limits = workflow_command_limits;
        self.workflow_command_policy = workflow_command_policy;
        self
    }

    /// Produces one execution-local executor with non-durable secret custody.
    ///
    /// The original executor remains secretless. The supplied custody object is
    /// shared only by this returned executor and is never cloned by value; its
    /// acknowledgement is invoked after every exact runtime binding is masked
    /// and before any user-observable execution work begins.
    #[must_use]
    pub fn with_secret_custody(
        &self,
        secrets: Arc<dyn SecretPort>,
        acknowledger: Arc<dyn SecretCustodyAcknowledger>,
    ) -> Self {
        Self {
            config: self.config.clone(),
            ports: GithubJobExecutorPorts::new(
                Arc::clone(&self.ports.provider),
                Arc::clone(&self.ports.environments),
                Arc::clone(&self.ports.actions),
                Arc::clone(&self.ports.content),
                secrets,
                Arc::clone(&self.ports.contexts),
                Arc::clone(&self.ports.toolchain),
                Arc::clone(&self.ports.operation_ids),
                Arc::clone(&self.ports.clock),
            ),
            local_actions: self.local_actions.clone(),
            expressions: self.expressions,
            command_files: self.command_files,
            completed_steps: self.completed_steps,
            workflow_command_limits: self.workflow_command_limits,
            workflow_command_policy: self.workflow_command_policy,
            custody_acknowledger: Some(acknowledger),
            managed_secret_bindings: None,
        }
    }

    /// Produces one execution-local executor with an ephemeral binding overlay.
    ///
    /// The immutable runtime-context blob must remain secretless. These
    /// value-free bindings are layered only in memory after that blob is
    /// verified, then every installed value is masked before acknowledgement.
    #[must_use]
    pub fn with_managed_secret_custody(
        &self,
        secrets: Arc<dyn SecretPort>,
        acknowledger: Arc<dyn SecretCustodyAcknowledger>,
        bindings: BTreeMap<String, SecretBinding>,
    ) -> Self {
        let mut executor = self.with_secret_custody(secrets, acknowledger);
        executor.managed_secret_bindings = Some(bindings);
        executor
    }

    /// Loads and verifies the immutable runtime context before private delivery.
    ///
    /// It returns only value-free secret binding locators. Callers must still
    /// use [`Self::with_secret_custody`] before executing a context with
    /// bindings, so the executor can mask and acknowledge its installed values.
    ///
    /// # Errors
    ///
    /// Returns a sanitized executor failure when immutable content is missing,
    /// inconsistent, oversized, or not a valid runtime context.
    pub async fn verified_runtime_context(
        &self,
        job: &JobIrEnvelope,
    ) -> Result<JobRuntimeContext, ExecutorError> {
        self.hydrate_runtime_context(job)
            .await
            .map_err(ExecutorError::from)
    }

    async fn hydrate_runtime_context(
        &self,
        job: &JobIrEnvelope,
    ) -> Result<JobRuntimeContext, ExecutorAdapterError> {
        let reference = job.execution().runtime_context();
        let limits = ProtocolLimits::default();
        if reference.media_type() != JOB_RUNTIME_CONTEXT_MEDIA_TYPE {
            return Err(invalid_job());
        }
        let expected_size =
            usize::try_from(reference.encoded_size()).map_err(|_| resource_exhausted())?;
        if expected_size == 0 {
            return Err(invalid_job());
        }
        if expected_size > limits.max_frame_bytes() {
            return Err(resource_exhausted());
        }

        let encoded = self
            .ports
            .content
            .load(reference)
            .await
            .map_err(|error| map_port_error(error.kind()))?;
        if encoded.len() != expected_size {
            return Err(invalid_job());
        }
        let actual_digest: [u8; 32] = Sha256::digest(&encoded).into();
        if actual_digest != reference.digest().into_bytes() {
            return Err(invalid_job());
        }
        decode_job_runtime_context(&encoded, &limits)
            .map_err(|error| map_runtime_context_decode_error(&error))
    }

    fn apply_managed_secret_bindings(
        &self,
        runtime_context: JobRuntimeContext,
    ) -> Result<JobRuntimeContext, ExecutorAdapterError> {
        let Some(bindings) = &self.managed_secret_bindings else {
            return Ok(runtime_context);
        };
        if !runtime_context.secrets().is_empty() {
            return Err(invalid_job());
        }
        JobRuntimeContext::new(
            runtime_context.inputs().clone(),
            runtime_context.vars().clone(),
            runtime_context.matrix().clone(),
            runtime_context.strategy(),
            runtime_context.needs().clone(),
            bindings.clone(),
        )
        .map_err(|_| invalid_job())
    }

    /// Registers every installed exact binding before evaluating user data.
    ///
    /// Runtime contexts carry locators only. Resolving each one here is the
    /// point at which a per-execution secret port proves it installed the full
    /// bounded set. No expression, environment, action, or command work is
    /// allowed before these masks (and any post-install acknowledgement) exist.
    fn register_runtime_context_secret_masks(
        &self,
        runtime_context: &JobRuntimeContext,
        masker: &mut SecretMasker,
    ) -> Result<(), ExecutorAdapterError> {
        for binding in runtime_context.secrets().values() {
            let secret = self
                .ports
                .secrets
                .resolve(binding.binding_id())
                .map_err(|error| map_port_error(error.kind()))?;
            masker.register(secret.expose_secret())?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn validate_admission(
        &self,
        job: &JobIrEnvelope,
    ) -> Result<automata_ci_execution::SandboxEnvironment, AdmissionRejection> {
        job.validate().map_err(|_| AdmissionRejection::InvalidJob)?;
        if job.job().container().is_some() {
            return Err(AdmissionRejection::InvalidJob);
        }
        let required = job
            .job()
            .requirements()
            .environment_profile()
            .ok_or(AdmissionRejection::CapabilityChanged)?;
        let environment = self
            .ports
            .environments
            .select(required)
            .ok_or(AdmissionRejection::CapabilityChanged)?;
        if environment.attestation() != required {
            return Err(AdmissionRejection::CapabilityChanged);
        }
        if job.job().authority_profile() == JobAuthorityProfile::CredentialFree
            && environment
                .default_environment()
                .values()
                .iter()
                .any(automata_ci_execution::EnvironmentVariable::is_secret)
        {
            return Err(AdmissionRejection::InvalidJob);
        }
        let workspace =
            job_workspace(job, &environment).map_err(|_| AdmissionRejection::InvalidJob)?;
        if self.ports.toolchain.platform() != workspace.platform() {
            return Err(AdmissionRejection::CapabilityChanged);
        }
        for step in job.job().steps() {
            let SemanticStep::Run { values } = step.kind() else {
                continue;
            };
            admit_shell_template(self.ports.toolchain.as_ref(), values.shell()).map_err(
                |rejection| match rejection {
                    ShellAdmissionRejection::Invalid => AdmissionRejection::InvalidJob,
                    ShellAdmissionRejection::MissingTool => AdmissionRejection::CapabilityChanged,
                },
            )?;
        }
        validate_environment_overlay_names(
            command_file_platform(workspace.platform()),
            job.job().environment().keys().map(String::as_str).chain(
                job.job()
                    .steps()
                    .iter()
                    .flat_map(|step| step.environment().keys().map(String::as_str)),
            ),
        )
        .map_err(|_| AdmissionRejection::InvalidJob)?;
        let event = job.execution().event();
        if event.media_type() != WORKFLOW_EVENT_MEDIA_TYPE
            || event.encoded_size() > automata_ci_execution::MAX_COPY_BYTES as u64
        {
            return Err(AdmissionRejection::InvalidJob);
        }
        let runtime_context = job.execution().runtime_context();
        let runtime_context_limit = ProtocolLimits::default().max_frame_bytes() as u64;
        if runtime_context.media_type() != JOB_RUNTIME_CONTEXT_MEDIA_TYPE
            || runtime_context.encoded_size() == 0
            || runtime_context.encoded_size() > runtime_context_limit
        {
            return Err(AdmissionRejection::InvalidJob);
        }
        self.validate_provider_admission(job, &workspace)?;
        validate_action_step_admission(job, &workspace)?;
        Ok(environment)
    }

    fn validate_provider_admission(
        &self,
        job: &JobIrEnvelope,
        workspace: &TargetPath,
    ) -> Result<(), AdmissionRejection> {
        let capabilities = self.ports.provider.capabilities();
        for required in [
            SandboxCapability::WholeJob,
            SandboxCapability::Attach,
            SandboxCapability::Inspect,
            SandboxCapability::Exec,
            SandboxCapability::CopyTo,
            SandboxCapability::CopyFrom,
            SandboxCapability::EnvironmentInjection,
        ] {
            if !capabilities.supports(required) {
                return Err(AdmissionRejection::CapabilityChanged);
            }
        }
        validate_resource_admission(job, capabilities)?;
        let network = match self.config.network() {
            NetworkPolicy::Disabled => SandboxCapability::NetworkDisabled,
            NetworkPolicy::PrivateEgress => SandboxCapability::PrivateEgress,
            NetworkPolicy::Host => SandboxCapability::HostNetwork,
        };
        let filesystem = match self.config.root_filesystem() {
            RootFilesystemPolicy::ReadOnly => SandboxCapability::ReadOnlyRootFilesystem,
            RootFilesystemPolicy::Writable => SandboxCapability::WritableRootFilesystem,
            RootFilesystemPolicy::Host => SandboxCapability::HostFilesystem,
        };
        if !capabilities.supports(network) || !capabilities.supports(filesystem) {
            return Err(AdmissionRejection::CapabilityChanged);
        }
        let allocation = job
            .job()
            .requirements()
            .resource_allocation()
            .ok_or(AdmissionRejection::InvalidJob)?;
        let limits = allocation.limits();
        if limits.ephemeral_disk_bytes() > 0
            && !capabilities.supports(SandboxCapability::EphemeralStorageLimits)
        {
            return Err(AdmissionRejection::CapabilityChanged);
        }
        if limits.gpu_count() > 0 && !capabilities.supports(SandboxCapability::DeviceLimits) {
            return Err(AdmissionRejection::CapabilityChanged);
        }
        let privilege = match self.config.privilege() {
            automata_ci_execution::SandboxPrivilegePolicy::Unprivileged => None,
            automata_ci_execution::SandboxPrivilegePolicy::Administrator => {
                Some(SandboxCapability::Administrator)
            }
            automata_ci_execution::SandboxPrivilegePolicy::Host => {
                Some(SandboxCapability::HostIdentity)
            }
        };
        if privilege.is_some_and(|required| !capabilities.supports(required)) {
            return Err(AdmissionRejection::CapabilityChanged);
        }
        if ProviderName::new(self.ports.provider.provider_id().as_str()).is_err()
            || !valid_toolchain(self.ports.toolchain.as_ref())
            || self.ports.toolchain.platform() != workspace.platform()
            || self.config.runner_root().platform() != workspace.platform()
        {
            return Err(AdmissionRejection::CapabilityChanged);
        }
        if workspace.platform() == TargetPlatform::Windows && !job.job().services().is_empty() {
            return Err(AdmissionRejection::InvalidJob);
        }
        container_runtime::validate_service_admission(job, capabilities)?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_job(
        &self,
        request: ExecutionRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> Result<JobResult, ExecutorAdapterError> {
        // We can safely resume a Preparing saga because no workflow phase has
        // started. Later lifecycle recovery requires durable per-phase state;
        // fail closed instead of replaying arbitrary user code.
        if request.recovery_lifecycle() != JobLifecycle::Preparing {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::Unsupported,
            ));
        }
        let attempt_id = request.lease().attempt_id();
        let mut masker = SecretMasker::new();
        if cancellation.is_cancelled() {
            return self.cancelled_job_result(attempt_id, &masker);
        }
        let started_at = self.ports.clock.now();
        let runtime_context = self.hydrate_runtime_context(request.job()).await;
        let Some(runtime_context) = reconcile_cancelled_operation(runtime_context, &cancellation)?
        else {
            return self.cancelled_job_result(attempt_id, &masker);
        };
        let runtime_context = self.apply_managed_secret_bindings(runtime_context)?;
        if request.job().job().authority_profile() == JobAuthorityProfile::CredentialFree
            && (!request.runtime_authorities().as_slice().is_empty()
                || !runtime_context.secrets().is_empty()
                || request
                    .environment()
                    .default_environment()
                    .values()
                    .iter()
                    .any(automata_ci_execution::EnvironmentVariable::is_secret))
        {
            if cancellation.is_cancelled() {
                return self.cancelled_job_result(attempt_id, &masker);
            }
            return Err(invalid_job());
        }
        self.register_runtime_context_secret_masks(&runtime_context, &mut masker)?;
        if cancellation.is_cancelled() {
            return self.cancelled_job_result(attempt_id, &masker);
        }
        let prepared_repository_actions = match self
            .preflight_repository_actions(request.job(), &cancellation)
            .await
        {
            Ok(actions) => actions,
            Err(ActionLoadError::Preparation(kind)) => {
                if emit_system_while_active(
                    &format!("Action preparation failed ({kind:?})"),
                    &mut masker,
                    &events,
                    &cancellation,
                )?
                .is_none()
                {
                    return self.cancelled_job_result(attempt_id, &masker);
                }
                return self.failed_job_result(attempt_id, &masker);
            }
            Err(ActionLoadError::Executor(error))
                if error.kind() == ExecutorAdapterErrorKind::Cancelled =>
            {
                return self.cancelled_job_result(attempt_id, &masker);
            }
            Err(ActionLoadError::Executor(error)) => return Err(error),
        };
        if cancellation.is_cancelled() {
            return self.cancelled_job_result(attempt_id, &masker);
        }
        if let Some(acknowledger) = &self.custody_acknowledger {
            acknowledger
                .acknowledge(cancellation.token())
                .await
                .map_err(map_executor_error)?;
            if cancellation.is_cancelled() {
                return self.cancelled_job_result(attempt_id, &masker);
            }
        }
        let request = HydratedExecutionRequest::new(&request, &runtime_context);
        let workspace = cancellation_dominant(
            job_workspace(request.job(), request.environment()),
            &cancellation,
        );
        let workspace = match workspace {
            Ok(workspace) => workspace,
            Err(error) if matches!(error.kind(), ExecutorAdapterErrorKind::Cancelled) => {
                return self.cancelled_job_result(attempt_id, &masker);
            }
            Err(error) => return Err(error),
        };
        let paths = cancellation_dominant(
            AttemptPaths::new(self.config.runner_root(), attempt_id, &workspace),
            &cancellation,
        );
        let paths = match paths {
            Ok(paths) => paths,
            Err(error) if matches!(error.kind(), ExecutorAdapterErrorKind::Cancelled) => {
                return self.cancelled_job_result(attempt_id, &masker);
            }
            Err(error) => return Err(error),
        };
        let mut commands = JobCommandState::new(command_file_platform(workspace.platform()));
        let mut records = Vec::<MutableStepResult>::new();
        let mut attachments = ExecutionAttachments::default();
        let event = self
            .ports
            .content
            .load(request.job().execution().event())
            .await
            .map_err(|error| map_port_error(error.kind()));
        let Some(event) = reconcile_cancelled_operation(event, &cancellation)? else {
            return self.cancelled_job_result(attempt_id, &masker);
        };
        let event_document = cancellation_dominant(
            serde_json::from_slice::<serde_json::Value>(&event)
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob)),
            &cancellation,
        );
        let event_document = match event_document {
            Ok(document) => document,
            Err(error) if matches!(error.kind(), ExecutorAdapterErrorKind::Cancelled) => {
                return self.cancelled_job_result(attempt_id, &masker);
            }
            Err(error) => return Err(error),
        };
        let event_context =
            cancellation_dominant(github_value_from_json(&event_document, 0), &cancellation);
        let event_context = match event_context {
            Ok(context) => context,
            Err(error) if matches!(error.kind(), ExecutorAdapterErrorKind::Cancelled) => {
                return self.cancelled_job_result(attempt_id, &masker);
            }
            Err(error) => return Err(error),
        };
        if !matches!(&event_context, GithubValue::Object(_)) {
            if cancellation.is_cancelled() {
                return self.cancelled_job_result(attempt_id, &masker);
            }
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::InvalidJob,
            ));
        }
        let job_context = self.context(
            &request,
            &event_context,
            &commands,
            &records,
            None,
            GithubStatus::Success,
            None,
            GithubExecutionPhase::Job,
        );
        let Some(job_context) = reconcile_cancelled_operation(job_context, &cancellation)? else {
            return self.cancelled_job_result(attempt_id, &masker);
        };
        let service_specs = self.service_specs(&request, &job_context, &mut masker, &cancellation);
        let Some(service_specs) = reconcile_cancelled_operation(service_specs, &cancellation)?
        else {
            return self.cancelled_job_result(attempt_id, &masker);
        };
        let sandbox = self.obtain_endpoint(
            &request,
            &workspace,
            &paths.root,
            &service_specs,
            &events,
            &cancellation,
        );
        let Some(sandbox) = reconcile_cancelled_operation(sandbox, &cancellation)? else {
            return self.cancelled_job_result(attempt_id, &masker);
        };
        let endpoint: Arc<dyn ExecutionEndpoint> = Arc::from(sandbox.endpoint);
        let services = sandbox.services;
        let execution_functions = self
            .ports
            .toolchain
            .node(JavascriptRuntime::Node24)
            .cloned()
            .map(|node| {
                Arc::new(SandboxExpressionFunctions::new(
                    endpoint.clone(),
                    workspace.clone(),
                    node,
                    attempt_id,
                    self.ports.operation_ids.clone(),
                    cancellation.clone(),
                )) as Arc<dyn GithubExpressionFunctionProvider>
            });
        let request = if let Some(execution_functions) = &execution_functions {
            request.with_execution_functions(execution_functions)
        } else {
            request
        };
        let prepared = self.prepare_attempt_directories(
            endpoint.as_ref(),
            &paths,
            attempt_id,
            request.environment().default_environment(),
            &cancellation,
        );
        if reconcile_cancelled_operation(prepared, &cancellation)?.is_none() {
            return self.cancelled_job_result(attempt_id, &masker);
        }
        let copied = self.copy_bytes(
            endpoint.as_ref(),
            attempt_id,
            OperationPurpose::CopyEvent,
            0,
            &paths.event,
            &event,
            &cancellation,
        );
        if reconcile_cancelled_operation(copied, &cancellation)?.is_none() {
            return self.cancelled_job_result(attempt_id, &masker);
        }
        let transitioned = Self::transition_running(request.recovery_lifecycle(), &events);
        if reconcile_cancelled_operation(transitioned, &cancellation)?.is_none() {
            return self.cancelled_job_result(attempt_id, &masker);
        }

        let job_deadline = request
            .job()
            .job()
            .timeout_seconds()
            .and_then(|seconds| deadline(started_at, seconds));
        let mut status = GithubStatus::Success;
        let mut conclusion = JobConclusion::Success;
        let mut posts = PostRegistry::default();
        let mut action_budget = ActionExecutionBudget::new();
        let preloaded_actions = self
            .run_pre_job_actions(
                &request,
                &event_context,
                endpoint.as_ref(),
                &paths,
                &services,
                &mut commands,
                &records,
                &mut status,
                &mut conclusion,
                &mut action_budget,
                &mut posts,
                &mut attachments,
                &mut masker,
                &events,
                &cancellation,
                job_deadline,
                prepared_repository_actions,
            )
            .await?;
        let main_suppressed = preloaded_actions.main_suppressed;
        let mut preloaded_actions = preloaded_actions.actions;
        let executable_steps = if main_suppressed {
            &[]
        } else {
            request.job().job().steps()
        };

        for (index, step) in executable_steps.iter().enumerate() {
            if cancellation.is_cancelled() {
                conclusion = JobConclusion::Cancelled;
                status = GithubStatus::Cancelled;
                break;
            }
            if job_deadline.is_some_and(|deadline| self.ports.clock.now() >= deadline) {
                conclusion = JobConclusion::TimedOut;
                break;
            }
            let index = u32::try_from(index)
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob));
            let Some(index) = reconcile_cancelled_operation(index, &cancellation)? else {
                conclusion = JobConclusion::Cancelled;
                status = GithubStatus::Cancelled;
                break;
            };
            let started = self.ports.clock.now();
            let phase = match step.kind() {
                SemanticStep::Run { .. } => GithubExecutionPhase::Run,
                SemanticStep::Action { .. } => GithubExecutionPhase::ActionMain,
            };
            let execution: Result<Option<(CommandOutcome, bool)>, ExecutorAdapterError> = async {
                let context = cancellation_dominant(
                    self.context(
                        &request,
                        &event_context,
                        &commands,
                        &records,
                        Some(&services),
                        status,
                        Some(step.id().as_str()),
                        phase,
                    ),
                    &cancellation,
                )?;
                let value_builder = EnvironmentBuilder::new(
                    &self.expressions,
                    self.ports.secrets.as_ref(),
                    request.environment().default_environment(),
                );
                let _display_name = cancellation_dominant(
                    Self::resolve_value_template(
                        &value_builder,
                        step.name_template(),
                        context.expression(),
                        &mut masker,
                    ),
                    &cancellation,
                )?;
                if !cancellation_dominant(
                    self.condition(step.condition(), &context),
                    &cancellation,
                )? {
                    return cancellation_dominant(Ok(None), &cancellation);
                }
                let continue_on_error = cancellation_dominant(
                    self.resolve_runtime_boolean(step.continue_on_error(), context.expression()),
                    &cancellation,
                )?;
                let timeout_seconds = cancellation_dominant(
                    self.resolve_runtime_timeout(step.timeout(), context.expression()),
                    &cancellation,
                )?;
                let timeout = cancellation_dominant(
                    self.step_timeout(timeout_seconds, job_deadline),
                    &cancellation,
                )?;
                let outcome = match step.kind() {
                    SemanticStep::Run { values } => {
                        let command = cancellation_dominant(
                            Self::resolve_value_template(
                                &value_builder,
                                values.command(),
                                context.expression(),
                                &mut masker,
                            ),
                            &cancellation,
                        )?;
                        let shell = cancellation_dominant(
                            resolve_shell_template(values.shell(), |value| {
                                Self::resolve_value_template(
                                    &value_builder,
                                    value,
                                    context.expression(),
                                    &mut masker,
                                )
                            }),
                            &cancellation,
                        )?;
                        let working_directory = cancellation_dominant(
                            values
                                .working_directory()
                                .map(|value| {
                                    Self::resolve_value_template(
                                        &value_builder,
                                        value,
                                        context.expression(),
                                        &mut masker,
                                    )
                                })
                                .transpose(),
                            &cancellation,
                        )?;
                        let job_working_directory = if working_directory.is_none() {
                            cancellation_dominant(
                                request
                                    .job()
                                    .job()
                                    .working_directory_template()
                                    .map(|value| {
                                        Self::resolve_value_template(
                                            &value_builder,
                                            value,
                                            context.expression(),
                                            &mut masker,
                                        )
                                    })
                                    .transpose(),
                                &cancellation,
                            )?
                        } else {
                            None
                        };
                        let script = cancellation_dominant(
                            paths.script(index, shell.script_extension(workspace.platform())),
                            &cancellation,
                        )?;
                        let (program, arguments) = cancellation_dominant(
                            shell_argv(self.ports.toolchain.as_ref(), &shell, &script),
                            &cancellation,
                        )?;
                        let script_contents =
                            shell.fix_up_script(workspace.platform(), command.expose());
                        cancellation_dominant(
                            self.copy_bytes(
                                endpoint.as_ref(),
                                attempt_id,
                                OperationPurpose::CopyScript,
                                index,
                                &script,
                                script_contents.as_bytes(),
                                &cancellation,
                            ),
                            &cancellation,
                        )?;
                        let working_directory = working_directory
                            .as_ref()
                            .map(ResolvedEnvironmentValue::expose)
                            .or_else(|| {
                                job_working_directory
                                    .as_ref()
                                    .map(ResolvedEnvironmentValue::expose)
                            });
                        let working_directory = cancellation_dominant(
                            working_directory_path(&workspace, working_directory),
                            &cancellation,
                        )?;
                        let environment = cancellation_dominant(
                            value_builder.phase_environment(
                                &context,
                                &commands,
                                request.job().job().environment(),
                                step.environment(),
                                std::iter::empty(),
                                &mut masker,
                            ),
                            &cancellation,
                        )?;
                        let phase = cancellation_dominant(phase_ordinal(index, 0), &cancellation)?;
                        let execution = PhaseExecution {
                            step_id: step.id().as_str(),
                            report_step_id: step.id().as_str(),
                            phase,
                            scope: StepPhase::Run,
                            program,
                            arguments,
                            working_directory,
                            environment,
                            timeout,
                        };
                        cancellation_dominant(
                            self.run_phase(
                                endpoint.as_ref(),
                                &paths,
                                attempt_id,
                                execution,
                                &mut commands,
                                &mut attachments,
                                &mut masker,
                                &events,
                                &cancellation,
                            ),
                            &cancellation,
                        )?
                    }
                    SemanticStep::Action { reference, inputs } => {
                        let outcome = self
                            .run_action_step(
                                &request,
                                &event_context,
                                endpoint.as_ref(),
                                &paths,
                                step,
                                index,
                                reference,
                                inputs,
                                &context,
                                timeout,
                                &services,
                                &mut commands,
                                &records,
                                status,
                                &mut action_budget,
                                &mut posts,
                                &mut attachments,
                                &mut masker,
                                &events,
                                &cancellation,
                                continue_on_error,
                                &mut preloaded_actions,
                            )
                            .await;
                        cancellation_dominant(outcome, &cancellation)?
                    }
                };
                Ok(Some((outcome, continue_on_error)))
            }
            .await;
            let Some(execution) = reconcile_cancelled_operation(execution, &cancellation)? else {
                conclusion = JobConclusion::Cancelled;
                status = GithubStatus::Cancelled;
                break;
            };
            let Some((outcome, continue_on_error)) = execution else {
                records.push(MutableStepResult::new(
                    step.id().clone(),
                    JobConclusion::Skipped,
                    JobConclusion::Skipped,
                    started,
                    self.ports.clock.now(),
                ));
                continue;
            };
            let mapped = map_continue(outcome.conclusion(), continue_on_error);
            records.push(MutableStepResult::new(
                step.id().clone(),
                outcome.conclusion(),
                mapped,
                started,
                self.ports.clock.now(),
            ));
            if outcome == CommandOutcome::Cancelled {
                conclusion = JobConclusion::Cancelled;
                status = GithubStatus::Cancelled;
                break;
            }
            if mapped != JobConclusion::Success && mapped != JobConclusion::Skipped {
                conclusion = mapped;
                status = status_for(mapped);
            }
        }

        if cancellation.is_cancelled() {
            conclusion = JobConclusion::Cancelled;
            status = GithubStatus::Cancelled;
        }
        let cleanup =
            CleanupCancellation::new(&cancellation, self.config.post_job_cleanup_timeout());
        let post_result = self.run_posts(
            &request,
            &event_context,
            endpoint.as_ref(),
            &paths,
            &services,
            &mut commands,
            &mut records,
            &mut posts,
            &mut status,
            &mut conclusion,
            &mut attachments,
            &mut masker,
            &events,
            &cleanup,
        );
        if let Err(error) = post_result
            && !stop_posts_if_cancelled(&cleanup, &mut status, &mut conclusion)
        {
            return Err(error);
        }
        let mut outputs = BTreeMap::new();
        if conclusion != JobConclusion::Cancelled
            && !reconcile_execution_cancellation(&cancellation, &mut status, &mut conclusion)
        {
            let output_context = match self.context(
                &request,
                &event_context,
                &commands,
                &records,
                Some(&services),
                status,
                None,
                GithubExecutionPhase::Job,
            ) {
                Ok(context) => Some(context),
                Err(error) => {
                    if reconcile_execution_cancellation(&cancellation, &mut status, &mut conclusion)
                    {
                        None
                    } else {
                        return Err(error);
                    }
                }
            };
            if let Some(output_context) = output_context
                && !reconcile_execution_cancellation(&cancellation, &mut status, &mut conclusion)
            {
                for secret in output_context.secret_masks() {
                    if reconcile_execution_cancellation(&cancellation, &mut status, &mut conclusion)
                    {
                        break;
                    }
                    if let Err(error) = masker.register(secret.expose_secret()) {
                        if !reconcile_execution_cancellation(
                            &cancellation,
                            &mut status,
                            &mut conclusion,
                        ) {
                            return Err(error);
                        }
                        break;
                    }
                }
                if !reconcile_execution_cancellation(&cancellation, &mut status, &mut conclusion) {
                    let output_builder = EnvironmentBuilder::new(
                        &self.expressions,
                        self.ports.secrets.as_ref(),
                        request.environment().default_environment(),
                    );
                    let evaluated = Self::evaluate_job_outputs(
                        request.job().job().output_definitions(),
                        request.job().job().trust_snapshot().authority().outputs(),
                        &output_builder,
                        &output_context,
                        &cancellation,
                        &mut masker,
                    );
                    match evaluated {
                        Ok(evaluated) => {
                            if !reconcile_execution_cancellation(
                                &cancellation,
                                &mut status,
                                &mut conclusion,
                            ) {
                                outputs = evaluated;
                            }
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                ExecutorAdapterErrorKind::InvalidJob
                                    | ExecutorAdapterErrorKind::ResourceExhausted
                            ) =>
                        {
                            if !reconcile_execution_cancellation(
                                &cancellation,
                                &mut status,
                                &mut conclusion,
                            ) {
                                conclusion = JobConclusion::Failure;
                                if emit_system_while_active(
                                    "job output evaluation failed; no job outputs were published",
                                    &mut masker,
                                    &events,
                                    &cancellation,
                                )?
                                .is_none()
                                {
                                    let _ = reconcile_execution_cancellation(
                                        &cancellation,
                                        &mut status,
                                        &mut conclusion,
                                    );
                                }
                            }
                        }
                        Err(error) => {
                            if !reconcile_execution_cancellation(
                                &cancellation,
                                &mut status,
                                &mut conclusion,
                            ) {
                                return Err(error);
                            }
                        }
                    }
                }
            }
        }
        if reconcile_execution_cancellation(&cancellation, &mut status, &mut conclusion) {
            outputs.clear();
        }
        let completed_at = self.ports.clock.now();
        let steps = records
            .into_iter()
            .map(|record| {
                let attached = attachments.take(record.step_id.as_str());
                record.into_result(completed_at, attached)
            })
            .collect::<Vec<_>>();
        if reconcile_execution_cancellation(&cancellation, &mut status, &mut conclusion) {
            outputs.clear();
        }
        let mut result = JobResult::new(
            attempt_id,
            conclusion,
            masker.job_secret_exposure(),
            completed_at,
        )
        .with_outputs(outputs)
        .with_steps(steps.clone());
        if let Err(error) = result.validate()
            && !reconcile_execution_cancellation(&cancellation, &mut status, &mut conclusion)
        {
            return Err(map_job_result_validation_error(&error));
        }
        if reconcile_execution_cancellation(&cancellation, &mut status, &mut conclusion) {
            result = JobResult::new(
                attempt_id,
                JobConclusion::Cancelled,
                masker.job_secret_exposure(),
                completed_at,
            )
            .with_steps(steps);
            result
                .validate()
                .map_err(|error| map_job_result_validation_error(&error))?;
        }
        Ok(result)
    }

    fn cancelled_job_result(
        &self,
        attempt_id: AttemptId,
        masker: &SecretMasker,
    ) -> Result<JobResult, ExecutorAdapterError> {
        let result = JobResult::new(
            attempt_id,
            JobConclusion::Cancelled,
            masker.job_secret_exposure(),
            self.ports.clock.now(),
        );
        result
            .validate()
            .map_err(|error| map_job_result_validation_error(&error))?;
        Ok(result)
    }

    fn failed_job_result(
        &self,
        attempt_id: AttemptId,
        masker: &SecretMasker,
    ) -> Result<JobResult, ExecutorAdapterError> {
        let result = JobResult::new(
            attempt_id,
            JobConclusion::Failure,
            masker.job_secret_exposure(),
            self.ports.clock.now(),
        );
        result
            .validate()
            .map_err(|error| map_job_result_validation_error(&error))?;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_action_occurrence<'a>(
        &'a self,
        request: &'a HydratedExecutionRequest<'_>,
        endpoint: &'a dyn ExecutionEndpoint,
        paths: &'a AttemptPaths,
        reference: ActionReference,
        call_path: ActionCallPath,
        preferred_action_slot: Option<u32>,
        budget: &'a mut ActionExecutionBudget,
        planner: &'a mut ActionGraphPlanner,
        actions: &'a mut BTreeMap<ActionCallPath, PreloadedActionOccurrence>,
        cancellation: &'a ExecutionCancellation,
    ) -> Pin<Box<dyn Future<Output = Result<ActionLifecycleFlags, ActionLoadError>> + Send + 'a>>
    {
        Box::pin(async move {
            let key = action_reference_key(&reference);
            if !planner.enter(key.clone()) {
                return Err(ActionLoadError::Preparation(
                    ActionPreparationErrorKind::Metadata,
                ));
            }
            let result = async {
                let loaded = self
                    .load_action_for_graph(
                        request,
                        endpoint,
                        paths,
                        &reference,
                        preferred_action_slot,
                        budget,
                        planner,
                        cancellation,
                    )
                    .await?;
                let child_actions = match loaded.definition.execution() {
                    PreparedActionExecution::Javascript(_) => Vec::new(),
                    PreparedActionExecution::Composite(composite) => composite
                        .steps()
                        .iter()
                        .enumerate()
                        .filter_map(|(index, step)| match step {
                            PreparedCompositeStep::Uses(step)
                                if !matches!(step.reference(), ActionReference::Local { .. }) =>
                            {
                                Some((index, step.reference().clone()))
                            }
                            PreparedCompositeStep::Run(_) | PreparedCompositeStep::Uses(_) => None,
                        })
                        .collect::<Vec<_>>(),
                };
                let mut lifecycle = ActionLifecycleFlags::from_definition(&loaded.definition);
                for (child_index, child_reference) in child_actions {
                    let child_path = call_path.child(child_index).map_err(|_| {
                        ActionLoadError::Preparation(ActionPreparationErrorKind::Metadata)
                    })?;
                    let child_lifecycle = self
                        .prepare_action_occurrence(
                            request,
                            endpoint,
                            paths,
                            child_reference,
                            child_path,
                            None,
                            budget,
                            planner,
                            actions,
                            cancellation,
                        )
                        .await?;
                    lifecycle.include(child_lifecycle);
                }
                if actions
                    .insert(
                        call_path,
                        PreloadedActionOccurrence {
                            loaded: Box::new(loaded),
                            reference: reference.clone(),
                            lifecycle: JavascriptPrePostState::default(),
                            flags: lifecycle,
                        },
                    )
                    .is_some()
                {
                    return Err(ActionLoadError::Preparation(
                        ActionPreparationErrorKind::Metadata,
                    ));
                }
                Ok(lifecycle)
            }
            .await;
            planner.leave();
            result
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn load_action_for_graph(
        &self,
        request: &ExecutionRequest,
        endpoint: &dyn ExecutionEndpoint,
        paths: &AttemptPaths,
        reference: &ActionReference,
        preferred_action_slot: Option<u32>,
        budget: &mut ActionExecutionBudget,
        planner: &mut ActionGraphPlanner,
        cancellation: &ExecutionCancellation,
    ) -> Result<LoadedAction, ActionLoadError> {
        let ActionReference::Repository { .. } = reference else {
            return self
                .load_action(
                    request,
                    endpoint,
                    paths,
                    reference,
                    preferred_action_slot,
                    budget,
                    cancellation,
                )
                .await;
        };
        let key = action_reference_key(reference);
        let action = if let Some(action) = planner.materials.get(&key) {
            action.clone()
        } else {
            let action = self
                .ports
                .actions
                .prepare(ActionPreparationRequest::new(reference))
                .await
                .map_err(|error| ActionLoadError::Preparation(error.kind()))?;
            planner.materials.insert(key, action.clone());
            action
        };
        self.require_action_runtimes(action.definition())?;
        let slot = preferred_action_slot
            .map_or_else(|| budget.action_slot(), Ok)
            .map_err(ActionLoadError::Executor)?;
        let action_paths = self
            .prepare_action_content(
                endpoint,
                paths,
                request.lease().attempt_id(),
                slot,
                &action,
                cancellation,
            )
            .map_err(ActionLoadError::Executor)?;
        Ok(LoadedAction {
            definition: action.definition().clone(),
            paths: action_paths,
        })
    }

    async fn preflight_repository_actions(
        &self,
        job: &JobIrEnvelope,
        cancellation: &ExecutionCancellation,
    ) -> Result<BTreeMap<String, PreparedAction>, ActionLoadError> {
        let mut planner = ActionGraphPlanner::default();
        for step in job.job().steps() {
            if cancellation.is_cancelled() {
                return Err(ActionLoadError::Executor(cancelled()));
            }
            let SemanticStep::Action { reference, .. } = step.kind() else {
                continue;
            };
            match reference {
                ActionReference::Repository { .. } => {
                    self.preflight_repository_action(reference, &mut planner, cancellation)
                        .await?;
                }
                ActionReference::Container { .. } => {
                    return Err(ActionLoadError::Preparation(
                        ActionPreparationErrorKind::UnsupportedExecution,
                    ));
                }
                // Local metadata is created by earlier workflow code and can
                // only be copied from the isolated workspace after provider
                // creation. Its graph remains bounded and fail-closed by the
                // same load/runtime checks before any local action phase.
                ActionReference::Local { .. } => {}
            }
        }
        Ok(planner.materials)
    }

    fn preflight_repository_action<'a>(
        &'a self,
        reference: &'a ActionReference,
        planner: &'a mut ActionGraphPlanner,
        cancellation: &'a ExecutionCancellation,
    ) -> Pin<Box<dyn Future<Output = Result<(), ActionLoadError>> + Send + 'a>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(ActionLoadError::Executor(cancelled()));
            }
            let key = action_reference_key(reference);
            if !planner.enter(key.clone()) {
                return Err(ActionLoadError::Preparation(
                    ActionPreparationErrorKind::Metadata,
                ));
            }
            let result = async {
                let action = if let Some(action) = planner.materials.get(&key) {
                    action.clone()
                } else {
                    let action = self
                        .ports
                        .actions
                        .prepare(ActionPreparationRequest::new(reference))
                        .await
                        .map_err(|error| ActionLoadError::Preparation(error.kind()))?;
                    if cancellation.is_cancelled() {
                        return Err(ActionLoadError::Executor(cancelled()));
                    }
                    planner.materials.insert(key, action.clone());
                    action
                };
                self.require_action_runtimes(action.definition())?;
                let children = match action.definition().execution() {
                    PreparedActionExecution::Javascript(_) => Vec::new(),
                    PreparedActionExecution::Composite(composite) => composite
                        .steps()
                        .iter()
                        .filter_map(|step| match step {
                            PreparedCompositeStep::Uses(step) => Some(step.reference().clone()),
                            PreparedCompositeStep::Run(_) => None,
                        })
                        .collect::<Vec<_>>(),
                };
                for child in children {
                    match &child {
                        ActionReference::Repository { .. } => {
                            self.preflight_repository_action(&child, planner, cancellation)
                                .await?;
                        }
                        ActionReference::Container { .. } => {
                            return Err(ActionLoadError::Preparation(
                                ActionPreparationErrorKind::UnsupportedExecution,
                            ));
                        }
                        // Repository preparation binds `./...` children to
                        // the same immutable repository revision. An
                        // unresolved workspace reference here would otherwise
                        // cross the provider boundary before its mutable
                        // metadata is known.
                        ActionReference::Local { .. } => {
                            return Err(ActionLoadError::Preparation(
                                ActionPreparationErrorKind::Metadata,
                            ));
                        }
                    }
                }
                Ok(())
            }
            .await;
            planner.leave();
            result
        })
    }

    fn require_action_runtimes(
        &self,
        definition: &PreparedActionDefinition,
    ) -> Result<(), ActionLoadError> {
        if let PreparedActionExecution::Javascript(javascript) = definition.execution()
            && self.ports.toolchain.node(javascript.runtime()).is_none()
        {
            return Err(ActionLoadError::Preparation(
                ActionPreparationErrorKind::RuntimeUnavailable,
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn run_pre_job_actions(
        &self,
        request: &HydratedExecutionRequest<'_>,
        event: &GithubValue,
        endpoint: &dyn ExecutionEndpoint,
        paths: &AttemptPaths,
        services: &ServiceContainerBindings,
        commands: &mut JobCommandState,
        records: &[MutableStepResult],
        status: &mut GithubStatus,
        conclusion: &mut JobConclusion,
        budget: &mut ActionExecutionBudget,
        posts: &mut PostRegistry,
        attachments: &mut ExecutionAttachments,
        masker: &mut SecretMasker,
        events: &Arc<dyn ExecutionEvents>,
        cancellation: &ExecutionCancellation,
        job_deadline: Option<UnixMillis>,
        prepared_repository_actions: BTreeMap<String, PreparedAction>,
    ) -> Result<PreloadedJobActions, ExecutorAdapterError> {
        let mut preloaded = BTreeMap::new();
        let mut planner = ActionGraphPlanner::with_materials(prepared_repository_actions);
        for (index, step) in request.job().job().steps().iter().enumerate() {
            if cancellation.is_cancelled() {
                *status = GithubStatus::Cancelled;
                *conclusion = JobConclusion::Cancelled;
                break;
            }
            let SemanticStep::Action { reference, .. } = step.kind() else {
                continue;
            };
            if matches!(reference, ActionReference::Local { .. }) {
                continue;
            }
            let index = u32::try_from(index).map_err(|_| invalid_job())?;
            let call_path = ActionCallPath::top(index);
            let prepared = self
                .prepare_action_occurrence(
                    request,
                    endpoint,
                    paths,
                    reference.clone(),
                    call_path,
                    Some(index),
                    budget,
                    &mut planner,
                    &mut preloaded,
                    cancellation,
                )
                .await;
            match prepared {
                Ok(_) => {}
                Err(ActionLoadError::Preparation(kind)) => {
                    if emit_system_while_active(
                        &format!("Action preparation failed ({kind:?})"),
                        masker,
                        events,
                        cancellation,
                    )?
                    .is_none()
                    {
                        *status = GithubStatus::Cancelled;
                        *conclusion = JobConclusion::Cancelled;
                    } else {
                        *status = GithubStatus::Failure;
                        *conclusion = JobConclusion::Failure;
                    }
                    return Ok(PreloadedJobActions::failed(preloaded));
                }
                Err(ActionLoadError::Executor(error)) => match error.kind() {
                    ExecutorAdapterErrorKind::Cancelled => {
                        *status = GithubStatus::Cancelled;
                        *conclusion = JobConclusion::Cancelled;
                        return Ok(PreloadedJobActions::failed(preloaded));
                    }
                    ExecutorAdapterErrorKind::TimedOut => {
                        *conclusion = JobConclusion::TimedOut;
                        return Ok(PreloadedJobActions::failed(preloaded));
                    }
                    _ => return Err(error),
                },
            }
        }

        for (index, step) in request.job().job().steps().iter().enumerate() {
            if cancellation.is_cancelled() {
                *status = GithubStatus::Cancelled;
                *conclusion = JobConclusion::Cancelled;
                break;
            }
            let SemanticStep::Action { reference, inputs } = step.kind() else {
                continue;
            };
            let index = u32::try_from(index).map_err(|_| invalid_job())?;
            let call_path = ActionCallPath::top(index);
            let Some(occurrence) = preloaded.get(&call_path) else {
                continue;
            };
            if !occurrence.flags.has_pre {
                continue;
            }
            let loaded = (*occurrence.loaded).clone();
            let flags = occurrence.flags;
            let result = match loaded.definition.execution() {
                PreparedActionExecution::Javascript(javascript) => {
                    let result = self.run_pre_job_javascript(
                        request,
                        event,
                        endpoint,
                        paths,
                        step,
                        index,
                        reference,
                        inputs,
                        &loaded.definition,
                        javascript,
                        &loaded.paths,
                        services,
                        commands,
                        records,
                        *status,
                        budget,
                        posts,
                        attachments,
                        masker,
                        events,
                        cancellation,
                        job_deadline,
                    )?;
                    preloaded
                        .get_mut(&call_path)
                        .ok_or_else(invalid_job)?
                        .lifecycle = result.lifecycle;
                    result
                }
                PreparedActionExecution::Composite(_) => {
                    if flags.has_post {
                        posts.reserve(index);
                    }
                    let context = cancellation_dominant(
                        self.context(
                            request,
                            event,
                            commands,
                            records,
                            Some(services),
                            *status,
                            Some(step.id().as_str()),
                            GithubExecutionPhase::ActionPre,
                        ),
                        cancellation,
                    )?;
                    for secret in context.secret_masks() {
                        cancellation_dominant(
                            masker.register(secret.expose_secret()),
                            cancellation,
                        )?;
                    }
                    let builder = EnvironmentBuilder::new(
                        &self.expressions,
                        self.ports.secrets.as_ref(),
                        request.environment().default_environment(),
                    );
                    let mut supplied = BTreeMap::new();
                    for (name, source) in inputs {
                        let value = cancellation_dominant(
                            builder.resolve_source_value(source, context.expression(), masker),
                            cancellation,
                        )?;
                        cancellation_dominant(
                            budget.charge_derived(value.expose().len()),
                            cancellation,
                        )?;
                        supplied.insert(name.clone(), value);
                    }
                    let continue_on_error = cancellation_dominant(
                        self.resolve_runtime_boolean(
                            step.continue_on_error(),
                            context.expression(),
                        ),
                        cancellation,
                    )?;
                    let timeout_seconds = cancellation_dominant(
                        self.resolve_runtime_timeout(step.timeout(), context.expression()),
                        cancellation,
                    )?;
                    let timeout = cancellation_dominant(
                        self.step_timeout(timeout_seconds, job_deadline),
                        cancellation,
                    )?;
                    let mut result = self.run_preloaded_action_pre(
                        request,
                        event,
                        endpoint,
                        paths,
                        step,
                        index,
                        &call_path,
                        &supplied,
                        &[],
                        step.id().as_str().to_owned(),
                        context.expression(),
                        *status,
                        services,
                        commands,
                        records,
                        budget,
                        &mut preloaded,
                        posts,
                        attachments,
                        masker,
                        events,
                        cancellation,
                        ActionDeadline::new(timeout),
                        continue_on_error,
                    )?;
                    result.continue_on_error = continue_on_error;
                    result
                }
            };
            if let Some(outcome) = result.outcome {
                let mapped = map_continue(outcome.conclusion(), result.continue_on_error);
                if outcome == CommandOutcome::Cancelled {
                    *status = GithubStatus::Cancelled;
                    *conclusion = JobConclusion::Cancelled;
                    return Ok(PreloadedJobActions::terminal(preloaded));
                } else if outcome == CommandOutcome::TimedOut && mapped != JobConclusion::Success {
                    *conclusion = JobConclusion::TimedOut;
                    return Ok(PreloadedJobActions::terminal(preloaded));
                } else if mapped != JobConclusion::Success && mapped != JobConclusion::Skipped {
                    *status = status_for(mapped);
                    *conclusion = mapped;
                }
            }
        }
        Ok(PreloadedJobActions::ready(preloaded))
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn run_pre_job_javascript(
        &self,
        request: &HydratedExecutionRequest<'_>,
        event: &GithubValue,
        endpoint: &dyn ExecutionEndpoint,
        paths: &AttemptPaths,
        step: &automata_ci_core::StepIr,
        index: u32,
        reference: &ActionReference,
        supplied_inputs: &BTreeMap<String, ValueSource>,
        definition: &PreparedActionDefinition,
        javascript: &crate::PreparedJavascriptAction,
        action_paths: &ActionPaths,
        services: &ServiceContainerBindings,
        commands: &mut JobCommandState,
        records: &[MutableStepResult],
        status: GithubStatus,
        budget: &mut ActionExecutionBudget,
        posts: &mut PostRegistry,
        attachments: &mut ExecutionAttachments,
        masker: &mut SecretMasker,
        events: &Arc<dyn ExecutionEvents>,
        cancellation: &ExecutionCancellation,
        job_deadline: Option<UnixMillis>,
    ) -> Result<PreJobActionResult, ExecutorAdapterError> {
        let Some(pre) = javascript.pre() else {
            return Ok(PreJobActionResult::default());
        };
        let context = cancellation_dominant(
            self.context(
                request,
                event,
                commands,
                records,
                Some(services),
                status,
                Some(step.id().as_str()),
                GithubExecutionPhase::ActionPre,
            ),
            cancellation,
        )?;
        let identity = ActionIdentity::new(
            step.id().as_str().to_owned(),
            reference.clone(),
            action_paths.directory.clone(),
        );
        let lifecycle_context = cancellation_dominant(
            action_lifecycle_context(context.expression(), &identity, &[], status),
            cancellation,
        )?;
        if !cancellation_dominant(
            self.expressions
                .evaluate_condition(javascript.pre_condition(), &lifecycle_context)
                .map_err(|_| invalid_job()),
            cancellation,
        )? {
            return Ok(PreJobActionResult::skipped());
        }
        for secret in context.secret_masks() {
            cancellation_dominant(masker.register(secret.expose_secret()), cancellation)?;
        }
        let builder = EnvironmentBuilder::new(
            &self.expressions,
            self.ports.secrets.as_ref(),
            request.environment().default_environment(),
        );
        let mut supplied = BTreeMap::new();
        for (name, source) in supplied_inputs {
            let value = cancellation_dominant(
                builder.resolve_source_value(source, context.expression(), masker),
                cancellation,
            )?;
            cancellation_dominant(budget.charge_derived(value.expose().len()), cancellation)?;
            supplied.insert(name.clone(), value);
        }
        let input_context = cancellation_dominant(
            action_expression_context(context.expression(), &[], None, &identity, &[], status),
            cancellation,
        )?;
        let inputs = cancellation_dominant(
            builder.resolve_action_inputs(definition, &supplied, &input_context),
            cancellation,
        )?;
        if !Self::emit_input_deprecations(&inputs, masker, events, cancellation)? {
            return Ok(PreJobActionResult::cancelled());
        }
        for (_, value) in inputs.values() {
            cancellation_dominant(budget.charge_derived(value.expose().len()), cancellation)?;
        }
        let continue_on_error = cancellation_dominant(
            self.resolve_runtime_boolean(step.continue_on_error(), context.expression()),
            cancellation,
        )?;
        let timeout_seconds = cancellation_dominant(
            self.resolve_runtime_timeout(step.timeout(), context.expression()),
            cancellation,
        )?;
        let timeout = cancellation_dominant(
            self.step_timeout(timeout_seconds, job_deadline),
            cancellation,
        )?;
        let call_path = ActionCallPath::top(index);
        posts.record_occurrence(
            call_path.clone(),
            PostActionOccurrence {
                definition: definition.clone(),
                identity: identity.clone(),
            },
        )?;
        let invocation =
            cancellation_dominant(call_path.invocation_id(step.id().as_str()), cancellation)?;
        let input_environment = cancellation_dominant(inputs.environment(), cancellation)?;
        let post_registered = javascript.post().is_some();
        if post_registered {
            posts.register(
                call_path,
                RegisteredPost {
                    top_step_index: index,
                    top_step_id: step.id().as_str().to_owned(),
                    runtime_step_id: step.id().as_str().to_owned(),
                    invocation: invocation.clone(),
                    javascript: javascript.clone(),
                    paths: action_paths.clone(),
                    phase: cancellation_dominant(phase_ordinal(index, 3), cancellation)?,
                },
            )?;
        }
        let Some(node) = self.ports.toolchain.node(javascript.runtime()).cloned() else {
            if emit_system_while_active(
                "Action runtime is unavailable",
                masker,
                events,
                cancellation,
            )?
            .is_none()
            {
                return Ok(PreJobActionResult::cancelled());
            }
            return Ok(PreJobActionResult {
                outcome: Some(CommandOutcome::Failure),
                lifecycle: JavascriptPrePostState {
                    pre_completed: true,
                    post_registered,
                },
                continue_on_error,
            });
        };
        let environment = cancellation_dominant(
            self.action_phase_environment(
                request,
                step,
                &context,
                commands,
                &[],
                &input_environment,
                action_paths,
                &identity,
                Vec::new(),
                masker,
            ),
            cancellation,
        )?;
        let execution = PhaseExecution {
            step_id: step.id().as_str(),
            report_step_id: step.id().as_str(),
            phase: cancellation_dominant(phase_ordinal(index, 1), cancellation)?,
            scope: StepPhase::ActionPre(invocation),
            program: node,
            arguments: vec![
                cancellation_dominant(action_paths.entry(pre), cancellation)?
                    .as_str()
                    .to_owned(),
            ],
            working_directory: paths.workspace.clone(),
            environment,
            timeout,
        };
        let outcome = self.run_phase(
            endpoint,
            paths,
            request.lease().attempt_id(),
            execution,
            commands,
            attachments,
            masker,
            events,
            cancellation,
        )?;
        Ok(PreJobActionResult {
            outcome: Some(outcome),
            lifecycle: JavascriptPrePostState {
                pre_completed: true,
                post_registered,
            },
            continue_on_error,
        })
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn run_preloaded_action_pre(
        &self,
        request: &HydratedExecutionRequest<'_>,
        event: &GithubValue,
        endpoint: &dyn ExecutionEndpoint,
        paths: &AttemptPaths,
        top_step: &automata_ci_core::StepIr,
        top_index: u32,
        call_path: &ActionCallPath,
        supplied_inputs: &BTreeMap<String, ResolvedEnvironmentValue>,
        action_environment: &[(String, ResolvedEnvironmentValue)],
        runtime_step_id: String,
        condition_expression: &dyn GithubEvaluationContext,
        status: GithubStatus,
        services: &ServiceContainerBindings,
        commands: &mut JobCommandState,
        records: &[MutableStepResult],
        budget: &mut ActionExecutionBudget,
        preloaded: &mut BTreeMap<ActionCallPath, PreloadedActionOccurrence>,
        posts: &mut PostRegistry,
        attachments: &mut ExecutionAttachments,
        masker: &mut SecretMasker,
        events: &Arc<dyn ExecutionEvents>,
        cancellation: &ExecutionCancellation,
        deadline: ActionDeadline,
        continue_on_error: bool,
    ) -> Result<PreJobActionResult, ExecutorAdapterError> {
        let occurrence = preloaded.get(call_path).ok_or_else(invalid_job)?;
        if !occurrence.flags.has_pre {
            return Ok(PreJobActionResult::default());
        }
        let loaded = (*occurrence.loaded).clone();
        let reference = occurrence.reference.clone();
        let identity =
            ActionIdentity::new(runtime_step_id, reference, loaded.paths.directory.clone());
        posts.record_occurrence(
            call_path.clone(),
            PostActionOccurrence {
                definition: loaded.definition.clone(),
                identity: identity.clone(),
            },
        )?;
        match loaded.definition.execution() {
            PreparedActionExecution::Javascript(javascript) => {
                let Some(pre) = javascript.pre() else {
                    return Ok(PreJobActionResult::default());
                };
                let lifecycle_context = cancellation_dominant(
                    action_lifecycle_context(
                        condition_expression,
                        &identity,
                        action_environment,
                        status,
                    ),
                    cancellation,
                )?;
                if !cancellation_dominant(
                    self.expressions
                        .evaluate_condition(javascript.pre_condition(), &lifecycle_context)
                        .map_err(|_| invalid_job()),
                    cancellation,
                )? {
                    preloaded
                        .get_mut(call_path)
                        .ok_or_else(invalid_job)?
                        .lifecycle = JavascriptPrePostState {
                        pre_completed: true,
                        post_registered: false,
                    };
                    return Ok(PreJobActionResult::skipped());
                }
                let builder = EnvironmentBuilder::new(
                    &self.expressions,
                    self.ports.secrets.as_ref(),
                    request.environment().default_environment(),
                );
                let input_context = cancellation_dominant(
                    action_expression_context(
                        condition_expression,
                        &[],
                        None,
                        &identity,
                        action_environment,
                        status,
                    ),
                    cancellation,
                )?;
                let inputs = cancellation_dominant(
                    builder.resolve_action_inputs(
                        &loaded.definition,
                        supplied_inputs,
                        &input_context,
                    ),
                    cancellation,
                )?;
                if !Self::emit_input_deprecations(&inputs, masker, events, cancellation)? {
                    return Ok(PreJobActionResult::cancelled());
                }
                for (_, value) in inputs.values() {
                    cancellation_dominant(
                        budget.charge_derived(value.expose().len()),
                        cancellation,
                    )?;
                }
                let invocation = cancellation_dominant(
                    call_path.invocation_id(top_step.id().as_str()),
                    cancellation,
                )?;
                let input_environment = cancellation_dominant(inputs.environment(), cancellation)?;
                let Some(timeout) = deadline.remaining() else {
                    return Ok(PreJobActionResult {
                        outcome: Some(CommandOutcome::TimedOut),
                        lifecycle: JavascriptPrePostState {
                            pre_completed: true,
                            post_registered: false,
                        },
                        continue_on_error,
                    });
                };
                let post_registered = javascript.post().is_some();
                if post_registered {
                    posts.register(
                        call_path.clone(),
                        RegisteredPost {
                            top_step_index: top_index,
                            top_step_id: top_step.id().as_str().to_owned(),
                            runtime_step_id: identity.runtime_step_id.clone(),
                            invocation: invocation.clone(),
                            javascript: javascript.as_ref().clone(),
                            paths: loaded.paths.clone(),
                            phase: cancellation_dominant(
                                action_phase(budget, call_path.is_top(), top_index, 3),
                                cancellation,
                            )?,
                        },
                    )?;
                }
                preloaded
                    .get_mut(call_path)
                    .ok_or_else(invalid_job)?
                    .lifecycle = JavascriptPrePostState {
                    pre_completed: true,
                    post_registered,
                };
                let Some(node) = self.ports.toolchain.node(javascript.runtime()).cloned() else {
                    if emit_system_while_active(
                        "Action runtime is unavailable",
                        masker,
                        events,
                        cancellation,
                    )?
                    .is_none()
                    {
                        return Ok(PreJobActionResult::cancelled());
                    }
                    return Ok(PreJobActionResult {
                        outcome: Some(CommandOutcome::Failure),
                        lifecycle: JavascriptPrePostState {
                            pre_completed: true,
                            post_registered,
                        },
                        continue_on_error,
                    });
                };
                let context = cancellation_dominant(
                    self.context(
                        request,
                        event,
                        commands,
                        records,
                        Some(services),
                        status,
                        Some(top_step.id().as_str()),
                        GithubExecutionPhase::ActionPre,
                    ),
                    cancellation,
                )?;
                for secret in context.secret_masks() {
                    cancellation_dominant(masker.register(secret.expose_secret()), cancellation)?;
                }
                let environment = cancellation_dominant(
                    self.action_phase_environment(
                        request,
                        top_step,
                        &context,
                        commands,
                        action_environment,
                        &input_environment,
                        &loaded.paths,
                        &identity,
                        Vec::new(),
                        masker,
                    ),
                    cancellation,
                )?;
                let execution = PhaseExecution {
                    step_id: &identity.runtime_step_id,
                    report_step_id: top_step.id().as_str(),
                    phase: cancellation_dominant(
                        action_phase(budget, call_path.is_top(), top_index, 1),
                        cancellation,
                    )?,
                    scope: StepPhase::ActionPre(invocation),
                    program: node,
                    arguments: vec![
                        cancellation_dominant(loaded.paths.entry(pre), cancellation)?
                            .as_str()
                            .to_owned(),
                    ],
                    working_directory: paths.workspace.clone(),
                    environment,
                    timeout,
                };
                let outcome = self.run_phase(
                    endpoint,
                    paths,
                    request.lease().attempt_id(),
                    execution,
                    commands,
                    attachments,
                    masker,
                    events,
                    cancellation,
                )?;
                Ok(PreJobActionResult {
                    outcome: Some(outcome),
                    lifecycle: JavascriptPrePostState {
                        pre_completed: true,
                        post_registered,
                    },
                    continue_on_error,
                })
            }
            PreparedActionExecution::Composite(composite) => {
                let builder = EnvironmentBuilder::new(
                    &self.expressions,
                    self.ports.secrets.as_ref(),
                    request.environment().default_environment(),
                );
                let input_context = cancellation_dominant(
                    action_expression_context(
                        condition_expression,
                        &[],
                        None,
                        &identity,
                        action_environment,
                        status,
                    ),
                    cancellation,
                )?;
                let inputs = cancellation_dominant(
                    builder.resolve_action_inputs(
                        &loaded.definition,
                        supplied_inputs,
                        &input_context,
                    ),
                    cancellation,
                )?;
                if !Self::emit_input_deprecations(&inputs, masker, events, cancellation)? {
                    return Ok(PreJobActionResult::cancelled());
                }
                for (_, value) in inputs.values() {
                    cancellation_dominant(
                        budget.charge_derived(value.expose().len()),
                        cancellation,
                    )?;
                }
                self.run_preloaded_composite_pre(
                    request,
                    event,
                    endpoint,
                    paths,
                    top_step,
                    top_index,
                    call_path,
                    composite,
                    &identity,
                    &inputs,
                    action_environment,
                    status,
                    services,
                    commands,
                    records,
                    budget,
                    preloaded,
                    posts,
                    attachments,
                    masker,
                    events,
                    cancellation,
                    deadline,
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn run_preloaded_composite_pre(
        &self,
        request: &HydratedExecutionRequest<'_>,
        event: &GithubValue,
        endpoint: &dyn ExecutionEndpoint,
        paths: &AttemptPaths,
        top_step: &automata_ci_core::StepIr,
        top_index: u32,
        call_path: &ActionCallPath,
        composite: &PreparedCompositeAction,
        identity: &ActionIdentity,
        inputs: &ResolvedActionInputs,
        action_environment: &[(String, ResolvedEnvironmentValue)],
        initial_status: GithubStatus,
        services: &ServiceContainerBindings,
        commands: &mut JobCommandState,
        records: &[MutableStepResult],
        budget: &mut ActionExecutionBudget,
        preloaded: &mut BTreeMap<ActionCallPath, PreloadedActionOccurrence>,
        posts: &mut PostRegistry,
        attachments: &mut ExecutionAttachments,
        masker: &mut SecretMasker,
        events: &Arc<dyn ExecutionEvents>,
        cancellation: &ExecutionCancellation,
        deadline: ActionDeadline,
    ) -> Result<PreJobActionResult, ExecutorAdapterError> {
        let builder = EnvironmentBuilder::new(
            &self.expressions,
            self.ports.secrets.as_ref(),
            request.environment().default_environment(),
        );
        let mut status = initial_status;
        let mut aggregate = None;
        let no_children = Vec::<CompositeChildResult>::new();
        for (child_index, child) in composite.steps().iter().enumerate() {
            let PreparedCompositeStep::Uses(step) = child else {
                continue;
            };
            let child_path = cancellation_dominant(call_path.child(child_index), cancellation)?;
            let Some(child_occurrence) = preloaded.get(&child_path) else {
                if matches!(step.reference(), ActionReference::Local { .. }) {
                    continue;
                }
                return Err(invalid_job());
            };
            if !child_occurrence.flags.has_pre {
                continue;
            }
            let base = cancellation_dominant(
                self.context(
                    request,
                    event,
                    commands,
                    records,
                    Some(services),
                    status,
                    Some(top_step.id().as_str()),
                    GithubExecutionPhase::ActionPre,
                ),
                cancellation,
            )?;
            for secret in base.secret_masks() {
                cancellation_dominant(masker.register(secret.expose_secret()), cancellation)?;
            }
            let steps =
                cancellation_dominant(composite_steps_value(&no_children, commands), cancellation)?;
            let parent_expression = cancellation_dominant(
                action_expression_context(
                    base.expression(),
                    inputs.values(),
                    Some(steps),
                    identity,
                    action_environment,
                    status,
                ),
                cancellation,
            )?;
            let child_environment = cancellation_dominant(
                Self::resolve_composite_values(
                    &builder,
                    step.environment(),
                    &parent_expression,
                    budget,
                ),
                cancellation,
            )?;
            let mut child_action_environment = action_environment.to_vec();
            child_action_environment.extend(child_environment);
            let child_expression = cancellation_dominant(
                action_expression_context(
                    base.expression(),
                    inputs.values(),
                    Some(composite_steps_value(&no_children, commands)?),
                    identity,
                    &child_action_environment,
                    status,
                ),
                cancellation,
            )?;
            let supplied = cancellation_dominant(
                Self::resolve_composite_value_map(
                    &builder,
                    step.inputs(),
                    &child_expression,
                    budget,
                ),
                cancellation,
            )?;
            let continue_on_error = cancellation_dominant(
                self.resolve_prepared_boolean(
                    step.metadata().continue_on_error(),
                    &child_expression,
                ),
                cancellation,
            )?;
            let result = self.run_preloaded_action_pre(
                request,
                event,
                endpoint,
                paths,
                top_step,
                top_index,
                &child_path,
                &supplied,
                &child_action_environment,
                composite_runtime_step_id(&child_path),
                &child_expression,
                status,
                services,
                commands,
                records,
                budget,
                preloaded,
                posts,
                attachments,
                masker,
                events,
                cancellation,
                deadline,
                continue_on_error,
            )?;
            let Some(outcome) = result.outcome else {
                continue;
            };
            if outcome == CommandOutcome::Cancelled {
                return Ok(result);
            }
            let mapped = map_continue(outcome.conclusion(), result.continue_on_error);
            if mapped != JobConclusion::Success && mapped != JobConclusion::Skipped {
                status = status_for(mapped);
                aggregate = Some(outcome);
            }
            if outcome == CommandOutcome::TimedOut && mapped != JobConclusion::Success {
                return Ok(result);
            }
        }
        Ok(PreJobActionResult {
            outcome: aggregate,
            lifecycle: JavascriptPrePostState::default(),
            continue_on_error: false,
        })
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn run_action_step(
        &self,
        request: &HydratedExecutionRequest<'_>,
        event: &GithubValue,
        endpoint: &dyn ExecutionEndpoint,
        paths: &AttemptPaths,
        step: &automata_ci_core::StepIr,
        index: u32,
        reference: &ActionReference,
        supplied_inputs: &std::collections::BTreeMap<String, automata_ci_core::ValueSource>,
        main_context: &crate::GithubContextSnapshot,
        timeout: Duration,
        services: &ServiceContainerBindings,
        commands: &mut JobCommandState,
        records: &[MutableStepResult],
        status: GithubStatus,
        action_budget: &mut ActionExecutionBudget,
        posts: &mut PostRegistry,
        attachments: &mut ExecutionAttachments,
        masker: &mut SecretMasker,
        events: &Arc<dyn ExecutionEvents>,
        cancellation: &ExecutionCancellation,
        continue_on_error: bool,
        preloaded_actions: &mut BTreeMap<ActionCallPath, PreloadedActionOccurrence>,
    ) -> Result<CommandOutcome, ExecutorAdapterError> {
        if cancellation.is_cancelled() {
            return Ok(CommandOutcome::Cancelled);
        }
        let builder = EnvironmentBuilder::new(
            &self.expressions,
            self.ports.secrets.as_ref(),
            request.environment().default_environment(),
        );
        for secret in main_context.secret_masks() {
            cancellation_dominant(masker.register(secret.expose_secret()), cancellation)?;
        }
        let mut supplied = BTreeMap::new();
        for (name, source) in supplied_inputs {
            let value = cancellation_dominant(
                builder.resolve_source_value(source, main_context.expression(), masker),
                cancellation,
            )?;
            cancellation_dominant(
                action_budget.charge_derived(value.expose().len()),
                cancellation,
            )?;
            supplied.insert(name.clone(), value);
        }
        let result = self
            .run_action_reference(
                request,
                event,
                endpoint,
                paths,
                step,
                index,
                reference.clone(),
                supplied,
                Vec::new(),
                step.id().as_str().to_owned(),
                Some(index),
                status,
                services,
                commands,
                records,
                action_budget,
                posts,
                attachments,
                masker,
                events,
                cancellation,
                ActionDeadline::new(timeout),
                continue_on_error,
                ActionCallPath::top(index),
                false,
                preloaded_actions,
            )
            .await;
        if cancellation.is_cancelled() {
            Ok(CommandOutcome::Cancelled)
        } else {
            result
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn run_action_reference<'a>(
        &'a self,
        request: &'a HydratedExecutionRequest<'_>,
        event: &'a GithubValue,
        endpoint: &'a dyn ExecutionEndpoint,
        paths: &'a AttemptPaths,
        top_step: &'a automata_ci_core::StepIr,
        top_index: u32,
        reference: ActionReference,
        supplied_inputs: BTreeMap<String, ResolvedEnvironmentValue>,
        action_environment: Vec<(String, ResolvedEnvironmentValue)>,
        runtime_step_id: String,
        preferred_action_slot: Option<u32>,
        status: GithubStatus,
        services: &'a ServiceContainerBindings,
        commands: &'a mut JobCommandState,
        records: &'a [MutableStepResult],
        budget: &'a mut ActionExecutionBudget,
        posts: &'a mut PostRegistry,
        attachments: &'a mut ExecutionAttachments,
        masker: &'a mut SecretMasker,
        events: &'a Arc<dyn ExecutionEvents>,
        cancellation: &'a ExecutionCancellation,
        deadline: ActionDeadline,
        post_failure_continued: bool,
        call_path: ActionCallPath,
        jit_allowed: bool,
        preloaded_actions: &'a mut BTreeMap<ActionCallPath, PreloadedActionOccurrence>,
    ) -> Pin<Box<dyn Future<Output = Result<CommandOutcome, ExecutorAdapterError>> + Send + 'a>>
    {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Ok(CommandOutcome::Cancelled);
            }
            if deadline.remaining().is_none() {
                return Ok(CommandOutcome::TimedOut);
            }
            let key = action_reference_key(&reference);
            if !budget.enter(key) {
                if emit_system_while_active(
                    "Action nesting limit or recursion check failed",
                    masker,
                    events,
                    cancellation,
                )?
                .is_none()
                {
                    return Ok(CommandOutcome::Cancelled);
                }
                return Ok(CommandOutcome::Failure);
            }
            let result = async {
                let (loaded_result, lifecycle) = match preloaded_actions.remove(&call_path) {
                    Some(PreloadedActionOccurrence {
                        loaded, lifecycle, ..
                    }) => (Ok(*loaded), lifecycle),
                    None if jit_allowed || matches!(reference, ActionReference::Local { .. }) => (
                        self.load_action(
                            request,
                            endpoint,
                            paths,
                            &reference,
                            preferred_action_slot,
                            budget,
                            cancellation,
                        )
                        .await,
                        JavascriptPrePostState::default(),
                    ),
                    None => (
                        Err(ActionLoadError::Preparation(
                            ActionPreparationErrorKind::Metadata,
                        )),
                        JavascriptPrePostState::default(),
                    ),
                };
                if cancellation.is_cancelled() {
                    return Ok(CommandOutcome::Cancelled);
                }
                let loaded = match loaded_result {
                    Ok(action) => action,
                    Err(ActionLoadError::Preparation(kind)) => {
                        if emit_system_while_active(
                            &format!("Action preparation failed ({kind:?})"),
                            masker,
                            events,
                            cancellation,
                        )?
                        .is_none()
                        {
                            return Ok(CommandOutcome::Cancelled);
                        }
                        return Ok(CommandOutcome::Failure);
                    }
                    Err(ActionLoadError::Executor(error)) => {
                        return match error.kind() {
                            ExecutorAdapterErrorKind::Cancelled => Ok(CommandOutcome::Cancelled),
                            ExecutorAdapterErrorKind::TimedOut => Ok(CommandOutcome::TimedOut),
                            _ => Err(error),
                        };
                    }
                };
                let base = cancellation_dominant(
                    self.context(
                        request,
                        event,
                        commands,
                        records,
                        Some(services),
                        status,
                        Some(top_step.id().as_str()),
                        GithubExecutionPhase::ActionMain,
                    ),
                    cancellation,
                )?;
                for secret in base.secret_masks() {
                    cancellation_dominant(masker.register(secret.expose_secret()), cancellation)?;
                }
                let builder = EnvironmentBuilder::new(
                    &self.expressions,
                    self.ports.secrets.as_ref(),
                    request.environment().default_environment(),
                );
                let identity =
                    ActionIdentity::new(runtime_step_id, reference, loaded.paths.directory.clone());
                let input_context = cancellation_dominant(
                    action_expression_context(
                        base.expression(),
                        &[],
                        None,
                        &identity,
                        &action_environment,
                        status,
                    ),
                    cancellation,
                )?;
                let inputs = cancellation_dominant(
                    builder.resolve_action_inputs(
                        &loaded.definition,
                        &supplied_inputs,
                        &input_context,
                    ),
                    cancellation,
                )?;
                if !Self::emit_input_deprecations(&inputs, masker, events, cancellation)? {
                    return Ok(CommandOutcome::Cancelled);
                }
                for (_, value) in inputs.values() {
                    cancellation_dominant(
                        budget.charge_derived(value.expose().len()),
                        cancellation,
                    )?;
                }
                posts.record_occurrence(
                    call_path.clone(),
                    PostActionOccurrence {
                        definition: loaded.definition.clone(),
                        identity: identity.clone(),
                    },
                )?;
                let invocation = cancellation_dominant(
                    call_path.invocation_id(top_step.id().as_str()),
                    cancellation,
                )?;
                match loaded.definition.execution() {
                    PreparedActionExecution::Javascript(javascript) => {
                        let pre_completed = if !lifecycle.pre_completed
                            && javascript.pre().is_some()
                            && matches!(&identity.reference, ActionReference::Local { .. })
                        {
                            if emit_system_while_active(
                                "Pre entrypoints are unsupported for local actions",
                                masker,
                                events,
                                cancellation,
                            )?
                            .is_none()
                            {
                                return Ok(CommandOutcome::Cancelled);
                            }
                            true
                        } else {
                            lifecycle.pre_completed
                        };
                        self.run_javascript_action(
                            request,
                            event,
                            endpoint,
                            paths,
                            top_step,
                            top_index,
                            javascript,
                            &loaded.paths,
                            &identity,
                            &inputs,
                            &action_environment,
                            invocation,
                            preferred_action_slot.is_some(),
                            status,
                            services,
                            commands,
                            records,
                            budget,
                            posts,
                            attachments,
                            masker,
                            events,
                            cancellation,
                            deadline,
                            post_failure_continued,
                            &call_path,
                            JavascriptPrePostState {
                                pre_completed,
                                post_registered: lifecycle.post_registered,
                            },
                        )
                    }
                    PreparedActionExecution::Composite(composite) => {
                        self.run_composite_action(
                            request,
                            event,
                            endpoint,
                            paths,
                            top_step,
                            top_index,
                            composite,
                            loaded.definition.outputs(),
                            &loaded.paths,
                            &identity,
                            &inputs,
                            &action_environment,
                            invocation,
                            status,
                            services,
                            commands,
                            records,
                            budget,
                            posts,
                            attachments,
                            masker,
                            events,
                            cancellation,
                            deadline,
                            post_failure_continued,
                            &call_path,
                            jit_allowed
                                || matches!(&identity.reference, ActionReference::Local { .. }),
                            preloaded_actions,
                        )
                        .await
                    }
                }
            }
            .await;
            budget.leave();
            if cancellation.is_cancelled() {
                Ok(CommandOutcome::Cancelled)
            } else {
                result
            }
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn load_action(
        &self,
        request: &ExecutionRequest,
        endpoint: &dyn ExecutionEndpoint,
        paths: &AttemptPaths,
        reference: &ActionReference,
        preferred_action_slot: Option<u32>,
        budget: &mut ActionExecutionBudget,
        cancellation: &ExecutionCancellation,
    ) -> Result<LoadedAction, ActionLoadError> {
        match reference {
            ActionReference::Repository { .. } => {
                let action = self
                    .ports
                    .actions
                    .prepare(ActionPreparationRequest::new(reference))
                    .await
                    .map_err(|error| ActionLoadError::Preparation(error.kind()))?;
                self.require_action_runtimes(action.definition())?;
                let slot = preferred_action_slot
                    .map_or_else(|| budget.action_slot(), Ok)
                    .map_err(ActionLoadError::Executor)?;
                let action_paths = self
                    .prepare_action_content(
                        endpoint,
                        paths,
                        request.lease().attempt_id(),
                        slot,
                        &action,
                        cancellation,
                    )
                    .map_err(ActionLoadError::Executor)?;
                Ok(LoadedAction {
                    definition: action.definition().clone(),
                    paths: action_paths,
                })
            }
            ActionReference::Local { .. } => {
                let prepared = self.prepare_local_action(
                    request,
                    endpoint,
                    paths,
                    reference,
                    budget,
                    cancellation,
                )?;
                self.require_action_runtimes(prepared.definition())?;
                let directory = local_action_directory(&paths.workspace, prepared.path())
                    .map_err(ActionLoadError::Executor)?;
                Ok(LoadedAction {
                    definition: prepared.definition().clone(),
                    paths: ActionPaths::local(directory),
                })
            }
            ActionReference::Container { .. } => Err(ActionLoadError::Preparation(
                ActionPreparationErrorKind::UnsupportedExecution,
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_local_action(
        &self,
        request: &ExecutionRequest,
        endpoint: &dyn ExecutionEndpoint,
        paths: &AttemptPaths,
        reference: &ActionReference,
        budget: &mut ActionExecutionBudget,
        cancellation: &ExecutionCancellation,
    ) -> Result<PreparedLocalAction, ActionLoadError> {
        let candidates =
            CheckedOutLocalActionPreparer::definition_paths(&paths.workspace, reference)
                .map_err(|error| ActionLoadError::Preparation(error.kind()))?;
        let phase = budget.phase().map_err(ActionLoadError::Executor)?;
        let argv = ExecutionArgv::new(
            required_tool(self.ports.toolchain.sh()).map_err(ActionLoadError::Executor)?,
            vec![
                "-c".to_owned(),
                LOCAL_ACTION_PROBE_SCRIPT.to_owned(),
                "automata-local-action".to_owned(),
                candidates.action_yml().as_str().to_owned(),
                candidates.action_yaml().as_str().to_owned(),
            ],
        )
        .map_err(|_| ActionLoadError::Executor(invalid_job()))?;
        let command = ExecutionCommand::new(
            self.ports.operation_ids.operation_id(
                request.lease().attempt_id(),
                OperationPurpose::ExecutePhase,
                phase,
            ),
            argv,
            paths.workspace.clone(),
            automata_ci_execution::ExecutionEnvironment::empty(),
            self.config.default_step_timeout(),
            64,
        )
        .map_err(|_| ActionLoadError::Executor(invalid_job()))?;
        let output = endpoint
            .exec(&command, &ProviderCancellationBridge(cancellation))
            .map_err(map_execution_error)
            .map_err(ActionLoadError::Executor)?;
        let selected = match (
            output.termination(),
            output.was_truncated(),
            output.stdout(),
        ) {
            (ExecutionTermination::Exited(0), false, b"yml") => candidates.action_yml(),
            (ExecutionTermination::Exited(0), false, b"yaml") => candidates.action_yaml(),
            (ExecutionTermination::Cancelled, _, _) => {
                return Err(ActionLoadError::Executor(ExecutorAdapterError::new(
                    ExecutorAdapterErrorKind::Cancelled,
                )));
            }
            (ExecutionTermination::TimedOut, _, _) => {
                return Err(ActionLoadError::Executor(ExecutorAdapterError::new(
                    ExecutorAdapterErrorKind::TimedOut,
                )));
            }
            _ => {
                return Err(ActionLoadError::Preparation(
                    ActionPreparationErrorKind::Metadata,
                ));
            }
        };
        let ordinal = phase
            .checked_mul(5)
            .ok_or_else(|| ActionLoadError::Executor(invalid_job()))?;
        let copy = CopyFromRequest::new(
            self.ports.operation_ids.operation_id(
                request.lease().attempt_id(),
                OperationPurpose::ReadCommandFile,
                ordinal,
            ),
            selected.clone(),
            automata_ci_execution::MAX_COPY_BYTES,
        )
        .map_err(|_| ActionLoadError::Executor(invalid_job()))?;
        let bytes = endpoint
            .copy_from(&copy, &ProviderCancellationBridge(cancellation))
            .map_err(map_execution_error)
            .map_err(ActionLoadError::Executor)?;
        let (preferred_bytes, fallback_bytes) = if selected == candidates.action_yml() {
            (Some(bytes.as_slice()), None)
        } else {
            (None, Some(bytes.as_slice()))
        };
        self.local_actions
            .prepare(LocalActionPreparationRequest::new(
                reference,
                preferred_bytes,
                fallback_bytes,
            ))
            .map_err(|error| ActionLoadError::Preparation(error.kind()))
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn run_javascript_action(
        &self,
        request: &HydratedExecutionRequest<'_>,
        event: &GithubValue,
        endpoint: &dyn ExecutionEndpoint,
        paths: &AttemptPaths,
        top_step: &automata_ci_core::StepIr,
        top_index: u32,
        javascript: &crate::PreparedJavascriptAction,
        action_paths: &ActionPaths,
        identity: &ActionIdentity,
        inputs: &ResolvedActionInputs,
        action_environment: &[(String, ResolvedEnvironmentValue)],
        invocation: ActionInvocationId,
        top_level: bool,
        status: GithubStatus,
        services: &ServiceContainerBindings,
        commands: &mut JobCommandState,
        records: &[MutableStepResult],
        budget: &mut ActionExecutionBudget,
        posts: &mut PostRegistry,
        attachments: &mut ExecutionAttachments,
        masker: &mut SecretMasker,
        events: &Arc<dyn ExecutionEvents>,
        cancellation: &ExecutionCancellation,
        deadline: ActionDeadline,
        _post_failure_continued: bool,
        call_path: &ActionCallPath,
        lifecycle: JavascriptPrePostState,
    ) -> Result<CommandOutcome, ExecutorAdapterError> {
        if cancellation.is_cancelled() {
            return Ok(CommandOutcome::Cancelled);
        }
        let Some(node) = self.ports.toolchain.node(javascript.runtime()).cloned() else {
            if emit_system_while_active(
                "Action runtime is unavailable",
                masker,
                events,
                cancellation,
            )?
            .is_none()
            {
                return Ok(CommandOutcome::Cancelled);
            }
            return Ok(CommandOutcome::Failure);
        };
        let input_environment = cancellation_dominant(inputs.environment(), cancellation)?;
        let post_phase = if lifecycle.post_registered {
            None
        } else {
            cancellation_dominant(
                javascript
                    .post()
                    .map(|_| action_phase(budget, top_level, top_index, 3))
                    .transpose(),
                cancellation,
            )?
        };
        if let Some(post_phase) = post_phase {
            if cancellation.is_cancelled() {
                return Ok(CommandOutcome::Cancelled);
            }
            posts.register(
                call_path.clone(),
                RegisteredPost {
                    top_step_index: top_index,
                    top_step_id: top_step.id().as_str().to_owned(),
                    runtime_step_id: identity.runtime_step_id.clone(),
                    invocation: invocation.clone(),
                    javascript: javascript.clone(),
                    paths: action_paths.clone(),
                    phase: post_phase,
                },
            )?;
        }

        if !lifecycle.pre_completed
            && let Some(pre) = javascript.pre()
        {
            let context = cancellation_dominant(
                self.context(
                    request,
                    event,
                    commands,
                    records,
                    Some(services),
                    status,
                    Some(top_step.id().as_str()),
                    GithubExecutionPhase::ActionPre,
                ),
                cancellation,
            )?;
            let expression = cancellation_dominant(
                action_expression_context(
                    context.expression(),
                    inputs.values(),
                    None,
                    identity,
                    action_environment,
                    status,
                ),
                cancellation,
            )?;
            if cancellation_dominant(
                self.expressions
                    .evaluate_condition(javascript.pre_condition(), &expression)
                    .map_err(|_| invalid_job()),
                cancellation,
            )? {
                let Some(timeout) = deadline.remaining() else {
                    return Ok(CommandOutcome::TimedOut);
                };
                let environment = cancellation_dominant(
                    self.action_phase_environment(
                        request,
                        top_step,
                        &context,
                        commands,
                        action_environment,
                        &input_environment,
                        action_paths,
                        identity,
                        Vec::new(),
                        masker,
                    ),
                    cancellation,
                )?;
                let execution = PhaseExecution {
                    step_id: &identity.runtime_step_id,
                    report_step_id: top_step.id().as_str(),
                    phase: cancellation_dominant(
                        action_phase(budget, top_level, top_index, 1),
                        cancellation,
                    )?,
                    scope: StepPhase::ActionPre(invocation.clone()),
                    program: node.clone(),
                    arguments: vec![
                        cancellation_dominant(action_paths.entry(pre), cancellation)?
                            .as_str()
                            .to_owned(),
                    ],
                    working_directory: paths.workspace.clone(),
                    environment,
                    timeout,
                };
                let outcome = self.run_phase(
                    endpoint,
                    paths,
                    request.lease().attempt_id(),
                    execution,
                    commands,
                    attachments,
                    masker,
                    events,
                    cancellation,
                )?;
                if outcome != CommandOutcome::Success {
                    return Ok(outcome);
                }
            }
        }

        if cancellation.is_cancelled() {
            return Ok(CommandOutcome::Cancelled);
        }
        let Some(timeout) = deadline.remaining() else {
            return Ok(CommandOutcome::TimedOut);
        };
        let context = cancellation_dominant(
            self.context(
                request,
                event,
                commands,
                records,
                Some(services),
                status,
                Some(top_step.id().as_str()),
                GithubExecutionPhase::ActionMain,
            ),
            cancellation,
        )?;
        let environment = cancellation_dominant(
            self.action_phase_environment(
                request,
                top_step,
                &context,
                commands,
                action_environment,
                &input_environment,
                action_paths,
                identity,
                Vec::new(),
                masker,
            ),
            cancellation,
        )?;
        let execution = PhaseExecution {
            step_id: &identity.runtime_step_id,
            report_step_id: top_step.id().as_str(),
            phase: cancellation_dominant(
                action_phase(budget, top_level, top_index, 2),
                cancellation,
            )?,
            scope: StepPhase::ActionMain(invocation),
            program: node,
            arguments: vec![
                cancellation_dominant(action_paths.entry(javascript.main()), cancellation)?
                    .as_str()
                    .to_owned(),
            ],
            working_directory: paths.workspace.clone(),
            environment,
            timeout,
        };
        self.run_phase(
            endpoint,
            paths,
            request.lease().attempt_id(),
            execution,
            commands,
            attachments,
            masker,
            events,
            cancellation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn action_phase_environment(
        &self,
        request: &ExecutionRequest,
        top_step: &automata_ci_core::StepIr,
        context: &crate::GithubContextSnapshot,
        commands: &JobCommandState,
        action_environment: &[(String, ResolvedEnvironmentValue)],
        input_environment: &[(String, ResolvedEnvironmentValue)],
        action_paths: &ActionPaths,
        identity: &ActionIdentity,
        state: Vec<(String, ResolvedEnvironmentValue)>,
        masker: &mut SecretMasker,
    ) -> Result<automata_ci_execution::ExecutionEnvironment, ExecutorAdapterError> {
        validate_environment_overlay_names(
            commands.platform(),
            action_environment.iter().map(|(name, _)| name.as_str()),
        )?;
        let mut extra = action_environment.to_vec();
        extra.extend(action_extra_environment(
            input_environment,
            action_paths,
            state,
        ));
        extra.extend(identity.environment());
        EnvironmentBuilder::new(
            &self.expressions,
            self.ports.secrets.as_ref(),
            request.environment().default_environment(),
        )
        .phase_environment(
            context,
            commands,
            request.job().job().environment(),
            top_step.environment(),
            extra,
            masker,
        )
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn run_composite_action(
        &self,
        request: &HydratedExecutionRequest<'_>,
        event: &GithubValue,
        endpoint: &dyn ExecutionEndpoint,
        paths: &AttemptPaths,
        top_step: &automata_ci_core::StepIr,
        top_index: u32,
        composite: &PreparedCompositeAction,
        outputs: &[crate::PreparedOutput],
        action_paths: &ActionPaths,
        identity: &ActionIdentity,
        inputs: &ResolvedActionInputs,
        action_environment: &[(String, ResolvedEnvironmentValue)],
        invocation: ActionInvocationId,
        initial_status: GithubStatus,
        services: &ServiceContainerBindings,
        commands: &mut JobCommandState,
        records: &[MutableStepResult],
        budget: &mut ActionExecutionBudget,
        posts: &mut PostRegistry,
        attachments: &mut ExecutionAttachments,
        masker: &mut SecretMasker,
        events: &Arc<dyn ExecutionEvents>,
        cancellation: &ExecutionCancellation,
        deadline: ActionDeadline,
        post_failure_continued: bool,
        call_path: &ActionCallPath,
        jit_allowed: bool,
        preloaded_actions: &mut BTreeMap<ActionCallPath, PreloadedActionOccurrence>,
    ) -> Result<CommandOutcome, ExecutorAdapterError> {
        if cancellation.is_cancelled() {
            return Ok(CommandOutcome::Cancelled);
        }
        let builder = EnvironmentBuilder::new(
            &self.expressions,
            self.ports.secrets.as_ref(),
            request.environment().default_environment(),
        );
        let input_environment = cancellation_dominant(inputs.environment(), cancellation)?;
        let mut child_records = Vec::<CompositeChildResult>::new();
        let mut status = initial_status;
        let mut aggregate = CommandOutcome::Success;

        for (child_index, child) in composite.steps().iter().enumerate() {
            if cancellation.is_cancelled() {
                return Ok(CommandOutcome::Cancelled);
            }
            if deadline.remaining().is_none() {
                return Ok(CommandOutcome::TimedOut);
            }
            let child_call_path =
                cancellation_dominant(call_path.child(child_index), cancellation)?;
            let ordinal = cancellation_dominant(budget.composite_step(), cancellation)?;
            let runtime_step_id = composite_runtime_step_id(&child_call_path);
            let metadata = match child {
                PreparedCompositeStep::Run(step) => step.metadata(),
                PreparedCompositeStep::Uses(step) => step.metadata(),
            };
            let base = cancellation_dominant(
                self.context(
                    request,
                    event,
                    commands,
                    records,
                    Some(services),
                    status,
                    Some(top_step.id().as_str()),
                    GithubExecutionPhase::ActionMain,
                ),
                cancellation,
            )?;
            for secret in base.secret_masks() {
                cancellation_dominant(masker.register(secret.expose_secret()), cancellation)?;
            }
            let steps = cancellation_dominant(
                composite_steps_value(&child_records, commands),
                cancellation,
            )?;
            let environment_context = cancellation_dominant(
                action_expression_context(
                    base.expression(),
                    inputs.values(),
                    Some(steps.clone()),
                    identity,
                    action_environment,
                    status,
                ),
                cancellation,
            )?;
            let child_environment = cancellation_dominant(
                match child {
                    PreparedCompositeStep::Run(step) => Self::resolve_composite_environment(
                        &builder,
                        step.environment(),
                        &environment_context,
                        budget,
                        commands.platform(),
                    ),
                    PreparedCompositeStep::Uses(step) => Self::resolve_composite_environment(
                        &builder,
                        step.environment(),
                        &environment_context,
                        budget,
                        commands.platform(),
                    ),
                },
                cancellation,
            )?;
            let mut step_action_environment = action_environment.to_vec();
            step_action_environment.extend(child_environment);
            let expression = cancellation_dominant(
                action_expression_context(
                    base.expression(),
                    inputs.values(),
                    Some(steps),
                    identity,
                    &step_action_environment,
                    status,
                ),
                cancellation,
            )?;
            if !cancellation_dominant(
                self.expressions
                    .evaluate_condition(metadata.condition(), &expression)
                    .map_err(|_| invalid_job()),
                cancellation,
            )? {
                if cancellation.is_cancelled() {
                    return Ok(CommandOutcome::Cancelled);
                }
                child_records.push(CompositeChildResult::new(
                    metadata,
                    runtime_step_id,
                    JobConclusion::Skipped,
                    JobConclusion::Skipped,
                ));
                continue;
            }
            let continue_on_error = cancellation_dominant(
                self.resolve_prepared_boolean(metadata.continue_on_error(), &expression),
                cancellation,
            )?;
            let outcome = match child {
                PreparedCompositeStep::Run(step) => {
                    let command = cancellation_dominant(
                        Self::resolve_composite_value(
                            &builder,
                            step.command(),
                            &expression,
                            budget,
                        ),
                        cancellation,
                    )?;
                    let shell = cancellation_dominant(
                        Self::resolve_composite_value(&builder, step.shell(), &expression, budget),
                        cancellation,
                    )?;
                    let working_directory = cancellation_dominant(
                        step.working_directory()
                            .map(|value| {
                                Self::resolve_composite_value(&builder, value, &expression, budget)
                            })
                            .transpose(),
                        cancellation,
                    )?;
                    let shell = cancellation_dominant(composite_shell(&shell), cancellation)?;
                    let script = cancellation_dominant(
                        paths.composite_script(
                            ordinal,
                            shell.script_extension(paths.workspace.platform()),
                        ),
                        cancellation,
                    )?;
                    let (program, arguments) = cancellation_dominant(
                        shell_argv(self.ports.toolchain.as_ref(), &shell, &script),
                        cancellation,
                    )?;
                    let script_contents = shell.fix_up_script(paths.workspace.platform(), &command);
                    cancellation_dominant(
                        budget.charge_derived(script_contents.len().saturating_sub(command.len())),
                        cancellation,
                    )?;
                    let operation_ordinal =
                        cancellation_dominant(composite_operation_ordinal(ordinal), cancellation)?;
                    cancellation_dominant(
                        self.copy_bytes(
                            endpoint,
                            request.lease().attempt_id(),
                            OperationPurpose::CopyScript,
                            operation_ordinal,
                            &script,
                            script_contents.as_bytes(),
                            cancellation,
                        ),
                        cancellation,
                    )?;
                    let working_directory = cancellation_dominant(
                        composite_working_directory(
                            &paths.workspace,
                            &action_paths.directory,
                            working_directory.as_deref(),
                        ),
                        cancellation,
                    )?;
                    let child_identity = identity.with_runtime_step_id(&runtime_step_id);
                    let environment = cancellation_dominant(
                        self.action_phase_environment(
                            request,
                            top_step,
                            &base,
                            commands,
                            &step_action_environment,
                            &input_environment,
                            action_paths,
                            &child_identity,
                            Vec::new(),
                            masker,
                        ),
                        cancellation,
                    )?;
                    let Some(timeout) = deadline.remaining() else {
                        return Ok(CommandOutcome::TimedOut);
                    };
                    let execution = PhaseExecution {
                        step_id: &runtime_step_id,
                        report_step_id: top_step.id().as_str(),
                        phase: cancellation_dominant(budget.phase(), cancellation)?,
                        scope: StepPhase::Run,
                        program,
                        arguments,
                        working_directory,
                        environment,
                        timeout,
                    };
                    self.run_phase(
                        endpoint,
                        paths,
                        request.lease().attempt_id(),
                        execution,
                        commands,
                        attachments,
                        masker,
                        events,
                        cancellation,
                    )?
                }
                PreparedCompositeStep::Uses(step) => {
                    let supplied = cancellation_dominant(
                        Self::resolve_composite_value_map(
                            &builder,
                            step.inputs(),
                            &expression,
                            budget,
                        ),
                        cancellation,
                    )?;
                    self.run_action_reference(
                        request,
                        event,
                        endpoint,
                        paths,
                        top_step,
                        top_index,
                        step.reference().clone(),
                        supplied,
                        step_action_environment,
                        runtime_step_id.clone(),
                        None,
                        status,
                        services,
                        commands,
                        records,
                        budget,
                        posts,
                        attachments,
                        masker,
                        events,
                        cancellation,
                        deadline,
                        post_failure_continued || continue_on_error,
                        child_call_path,
                        jit_allowed,
                        preloaded_actions,
                    )
                    .await?
                }
            };
            if cancellation.is_cancelled() {
                return Ok(CommandOutcome::Cancelled);
            }
            if outcome == CommandOutcome::Cancelled {
                return Ok(CommandOutcome::Cancelled);
            }
            let mapped = map_continue(outcome.conclusion(), continue_on_error);
            child_records.push(CompositeChildResult::new(
                metadata,
                runtime_step_id,
                outcome.conclusion(),
                mapped,
            ));
            if mapped != JobConclusion::Success && mapped != JobConclusion::Skipped {
                status = status_for(mapped);
                aggregate = command_outcome(mapped);
            }
        }

        if cancellation.is_cancelled() {
            return Ok(CommandOutcome::Cancelled);
        }
        posts.record_composite_steps(call_path.clone(), child_records.clone())?;
        let base = cancellation_dominant(
            self.context(
                request,
                event,
                commands,
                records,
                Some(services),
                status,
                Some(top_step.id().as_str()),
                GithubExecutionPhase::ActionMain,
            ),
            cancellation,
        )?;
        for secret in base.secret_masks() {
            cancellation_dominant(masker.register(secret.expose_secret()), cancellation)?;
        }
        let steps = cancellation_dominant(
            composite_steps_value(&child_records, commands),
            cancellation,
        )?;
        let expression = cancellation_dominant(
            action_expression_context(
                base.expression(),
                inputs.values(),
                Some(steps),
                identity,
                action_environment,
                status,
            ),
            cancellation,
        )?;
        self.publish_action_outputs(
            outputs,
            &expression,
            &identity.runtime_step_id,
            invocation,
            commands,
            budget,
            cancellation,
        )?;
        Ok(aggregate)
    }

    fn resolve_prepared_boolean(
        &self,
        value: &PreparedBoolean,
        context: &dyn GithubEvaluationContext,
    ) -> Result<bool, ExecutorAdapterError> {
        match value {
            PreparedBoolean::Literal(value) => Ok(*value),
            PreparedBoolean::Expression(program) => self
                .expressions
                .evaluate(program, context)
                .map(|value| value.is_truthy())
                .map_err(|_| invalid_job()),
        }
    }

    fn resolve_composite_value(
        builder: &EnvironmentBuilder<'_>,
        value: &PreparedValue,
        context: &dyn GithubEvaluationContext,
        budget: &mut ActionExecutionBudget,
    ) -> Result<String, ExecutorAdapterError> {
        let value = builder.resolve_prepared(value, context)?;
        budget.charge_derived(value.len())?;
        Ok(value)
    }

    fn resolve_composite_values(
        builder: &EnvironmentBuilder<'_>,
        values: &[PreparedKeyValue],
        context: &dyn GithubEvaluationContext,
        budget: &mut ActionExecutionBudget,
    ) -> Result<Vec<(String, ResolvedEnvironmentValue)>, ExecutorAdapterError> {
        values
            .iter()
            .map(|value| {
                let resolved = builder.resolve_prepared_value(value.value(), context)?;
                budget.charge_derived(resolved.expose().len())?;
                Ok((value.name().to_owned(), resolved))
            })
            .collect()
    }

    fn resolve_composite_environment(
        builder: &EnvironmentBuilder<'_>,
        values: &[PreparedKeyValue],
        context: &dyn GithubEvaluationContext,
        budget: &mut ActionExecutionBudget,
        platform: CommandFilePlatform,
    ) -> Result<Vec<(String, ResolvedEnvironmentValue)>, ExecutorAdapterError> {
        validate_environment_overlay_names(platform, values.iter().map(PreparedKeyValue::name))?;
        Self::resolve_composite_values(builder, values, context, budget)
    }

    fn resolve_composite_value_map(
        builder: &EnvironmentBuilder<'_>,
        values: &[PreparedKeyValue],
        context: &dyn GithubEvaluationContext,
        budget: &mut ActionExecutionBudget,
    ) -> Result<BTreeMap<String, ResolvedEnvironmentValue>, ExecutorAdapterError> {
        Self::resolve_composite_values(builder, values, context, budget)
            .map(|values| values.into_iter().collect())
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_action_outputs(
        &self,
        outputs: &[crate::PreparedOutput],
        context: &dyn GithubEvaluationContext,
        runtime_step_id: &str,
        invocation: ActionInvocationId,
        commands: &mut JobCommandState,
        budget: &mut ActionExecutionBudget,
        cancellation: &dyn ExecutorCancellation,
    ) -> Result<(), ExecutorAdapterError> {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let empty_environment = automata_ci_execution::ExecutionEnvironment::empty();
        let builder = EnvironmentBuilder::new(
            &self.expressions,
            self.ports.secrets.as_ref(),
            &empty_environment,
        );
        let mut values = Vec::new();
        for output in outputs {
            if cancellation.is_cancelled() {
                return Err(cancelled());
            }
            let Some(value) = output.value() else {
                continue;
            };
            let value = cancellation_dominant(
                Self::resolve_composite_value(&builder, value, context, budget),
                cancellation,
            )?;
            values.push((output.name().to_owned(), value));
        }
        if values.is_empty() {
            return cancellation_dominant(Ok(()), cancellation);
        }
        let encoded = cancellation_dominant(encode_action_outputs(&values), cancellation)?;
        let decoded = cancellation_dominant(
            self.command_files
                .decode(CommandFileKind::Output, &encoded, commands.platform())
                .map_err(|_| invalid_job()),
            cancellation,
        )?;
        let ParsedCommandFile::Output(output) = decoded else {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::Internal,
            ));
        };
        let completed = CompletedStepCommands::new(
            EnvironmentCommandFile::default(),
            output,
            PathCommandFile::default(),
            StateCommandFile::default(),
            StepSummaryCommandFile::default(),
        );
        let runtime_step_id = cancellation_dominant(
            RuntimeStepId::new(runtime_step_id).map_err(|_| invalid_job()),
            cancellation,
        )?;
        let scope = StepScope::new(runtime_step_id, StepPhase::ActionMain(invocation));
        let next = cancellation_dominant(
            self.completed_steps
                .apply_completed_step(commands, &scope, &completed)
                .map(automata_ci_github_runtime::PhaseApplication::into_next_state)
                .map_err(|_| resource_exhausted()),
            cancellation,
        )?;
        *commands = next;
        Ok(())
    }

    fn prepare_action_content(
        &self,
        endpoint: &dyn ExecutionEndpoint,
        paths: &AttemptPaths,
        attempt_id: AttemptId,
        index: u32,
        action: &PreparedAction,
        cancellation: &ExecutionCancellation,
    ) -> Result<ActionPaths, ExecutorAdapterError> {
        let action_paths = paths.action(index, action.subpath())?;
        let prepare_ordinal = index.checked_add(1).ok_or_else(invalid_job)?;
        let command = action_content::prepare_directory_command(
            self.ports.operation_ids.operation_id(
                attempt_id,
                OperationPurpose::PrepareDirectory,
                prepare_ordinal,
            ),
            required_tool(self.ports.toolchain.install())?,
            &paths.workspace,
            &action_paths.base,
            &action_paths.extracted,
            self.config.default_step_timeout(),
            self.config.maximum_output_bytes(),
        )?;
        let output = endpoint
            .exec(&command, &ProviderCancellationBridge(cancellation))
            .map_err(map_execution_error)?;
        require_success(&output)?;
        let request = action_content::copy_archive_request(
            self.ports.operation_ids.operation_id(
                attempt_id,
                OperationPurpose::CopyActionArchive,
                index,
            ),
            &action_paths.archive,
            action.archive(),
        )?;
        endpoint
            .copy_to(&request, &ProviderCancellationBridge(cancellation))
            .map_err(map_execution_error)?;
        let command = action_content::extract_archive_command(
            self.ports.operation_ids.operation_id(
                attempt_id,
                OperationPurpose::ExtractActionArchive,
                index,
            ),
            required_tool(self.ports.toolchain.tar())?,
            &paths.workspace,
            &action_paths.extracted,
            &action_paths.archive,
            self.config.default_step_timeout(),
            self.config.maximum_output_bytes(),
        )?;
        let output = endpoint
            .exec(&command, &ProviderCancellationBridge(cancellation))
            .map_err(map_execution_error)?;
        require_success(&output)?;
        Ok(action_paths)
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn resolve_post_templates<'a>(
        &self,
        request: &HydratedExecutionRequest<'_>,
        top_step: &automata_ci_core::StepIr,
        context: &'a crate::GithubContextSnapshot,
        commands: &JobCommandState,
        posts: &PostRegistry,
        call_path: &ActionCallPath,
        post: &RegisteredPost,
        status: GithubStatus,
        masker: &mut SecretMasker,
        budget: &mut ActionExecutionBudget,
    ) -> Result<ResolvedPostTemplates<'a>, ExecutorAdapterError> {
        let SemanticStep::Action {
            reference,
            inputs: supplied,
        } = top_step.kind()
        else {
            return Err(invalid_job());
        };
        let builder = EnvironmentBuilder::new(
            &self.expressions,
            self.ports.secrets.as_ref(),
            request.environment().default_environment(),
        );
        let top_environment = builder.phase_expression_values(
            context,
            commands,
            request.job().job().environment(),
            top_step.environment(),
            masker,
        )?;
        let top_context =
            environment_expression_context(context.expression(), &top_environment, status)?;
        let top_path = call_path.prefix(1)?;
        let mut occurrence = posts.occurrence(&top_path)?;
        if &occurrence.identity.reference != reference {
            return Err(invalid_job());
        }
        let mut continue_on_error = vec![DeferredPostContinue::Runtime {
            value: top_step.continue_on_error().clone(),
            context: top_context.clone(),
        }];

        if call_path.depth() == 1 {
            let lifecycle_context = action_lifecycle_context(
                &top_context,
                &occurrence.identity,
                &top_environment,
                status,
            )?;
            if !self.evaluate_registered_post_condition(post, &occurrence, &lifecycle_context)? {
                return Ok(ResolvedPostTemplates::Skipped);
            }
            let timeout = self.resolve_registered_post_timeout(top_step, &top_context)?;
            let supplied =
                Self::resolve_post_source_inputs(&builder, supplied, &top_context, masker, budget)?;
            let input_context = action_expression_context(
                &top_context,
                &[],
                None,
                &occurrence.identity,
                &top_environment,
                status,
            )?;
            let inputs =
                builder.resolve_action_inputs(&occurrence.definition, &supplied, &input_context)?;
            Self::charge_action_inputs(&inputs, budget)?;
            return Ok(ResolvedPostTemplates::Execute(Box::new(
                ResolvedPostExecution {
                    identity: occurrence.identity,
                    action_environment: Vec::new(),
                    input_environment: inputs.environment()?,
                    timeout,
                    continue_on_error,
                },
            )));
        }

        let timeout = self.resolve_registered_post_timeout(top_step, &top_context)?;
        let supplied =
            Self::resolve_post_source_inputs(&builder, supplied, &top_context, masker, budget)?;
        let input_context = action_expression_context(
            &top_context,
            &[],
            None,
            &occurrence.identity,
            &top_environment,
            status,
        )?;
        let mut inputs =
            builder.resolve_action_inputs(&occurrence.definition, &supplied, &input_context)?;
        Self::charge_action_inputs(&inputs, budget)?;
        let mut expression_environment = top_environment;
        let mut action_environment = Vec::new();
        let mut parent_path = top_path;

        for depth in 1..call_path.depth() {
            let PreparedActionExecution::Composite(composite) = occurrence.definition.execution()
            else {
                return Err(invalid_job());
            };
            let child_index = call_path.index_at(depth)?;
            let Some(PreparedCompositeStep::Uses(step)) = composite.steps().get(child_index) else {
                return Err(invalid_job());
            };
            let steps = posts.composite_steps_value(&parent_path, commands)?;
            let parent_context = action_expression_context(
                context.expression(),
                inputs.values(),
                Some(steps.clone()),
                &occurrence.identity,
                &expression_environment,
                status,
            )?;
            let child_environment = Self::resolve_composite_values(
                &builder,
                step.environment(),
                &parent_context,
                budget,
            )?;
            expression_environment.extend(child_environment.clone());
            action_environment.extend(child_environment);
            let child_context = action_expression_context(
                context.expression(),
                inputs.values(),
                Some(steps),
                &occurrence.identity,
                &expression_environment,
                status,
            )?;
            continue_on_error.push(DeferredPostContinue::Composite {
                value: step.metadata().continue_on_error().clone(),
                context: child_context.clone(),
            });
            let child_path = call_path.prefix(depth + 1)?;
            let child_occurrence = posts.occurrence(&child_path)?;
            if &child_occurrence.identity.reference != step.reference() {
                return Err(invalid_job());
            }
            let lifecycle_context = action_lifecycle_context(
                &child_context,
                &child_occurrence.identity,
                &expression_environment,
                status,
            )?;
            let final_occurrence = depth + 1 == call_path.depth();
            if final_occurrence
                && !self.evaluate_registered_post_condition(
                    post,
                    &child_occurrence,
                    &lifecycle_context,
                )?
            {
                return Ok(ResolvedPostTemplates::Skipped);
            }
            let supplied =
                Self::resolve_composite_value_map(&builder, step.inputs(), &child_context, budget)?;
            let input_context = action_expression_context(
                &child_context,
                &[],
                None,
                &child_occurrence.identity,
                &expression_environment,
                status,
            )?;
            let child_inputs = builder.resolve_action_inputs(
                &child_occurrence.definition,
                &supplied,
                &input_context,
            )?;
            Self::charge_action_inputs(&child_inputs, budget)?;
            if final_occurrence {
                return Ok(ResolvedPostTemplates::Execute(Box::new(
                    ResolvedPostExecution {
                        identity: child_occurrence.identity,
                        action_environment,
                        input_environment: child_inputs.environment()?,
                        timeout,
                        continue_on_error,
                    },
                )));
            }
            occurrence = child_occurrence;
            inputs = child_inputs;
            parent_path = child_path;
        }
        Err(invalid_job())
    }

    fn evaluate_registered_post_condition(
        &self,
        post: &RegisteredPost,
        occurrence: &PostActionOccurrence,
        context: &dyn GithubEvaluationContext,
    ) -> Result<bool, ExecutorAdapterError> {
        let PreparedActionExecution::Javascript(javascript) = occurrence.definition.execution()
        else {
            return Err(invalid_job());
        };
        if javascript.as_ref() != &post.javascript
            || occurrence.identity.runtime_step_id != post.runtime_step_id
            || occurrence.identity.action_path != post.paths.directory
        {
            return Err(invalid_job());
        }
        self.expressions
            .evaluate_condition(post.javascript.post_condition(), context)
            .map_err(|_| invalid_job())
    }

    fn resolve_registered_post_timeout(
        &self,
        step: &automata_ci_core::StepIr,
        context: &dyn GithubEvaluationContext,
    ) -> Result<Duration, ExecutorAdapterError> {
        let seconds = self.resolve_runtime_timeout(step.timeout(), context)?;
        self.step_timeout(seconds, None)
    }

    fn resolve_post_source_inputs(
        builder: &EnvironmentBuilder<'_>,
        sources: &BTreeMap<String, ValueSource>,
        context: &dyn GithubEvaluationContext,
        masker: &mut SecretMasker,
        budget: &mut ActionExecutionBudget,
    ) -> Result<BTreeMap<String, ResolvedEnvironmentValue>, ExecutorAdapterError> {
        sources
            .iter()
            .map(|(name, source)| {
                let value = builder.resolve_source_value(source, context, masker)?;
                budget.charge_derived(value.expose().len())?;
                Ok((name.clone(), value))
            })
            .collect()
    }

    fn charge_action_inputs(
        inputs: &ResolvedActionInputs,
        budget: &mut ActionExecutionBudget,
    ) -> Result<(), ExecutorAdapterError> {
        for (_, value) in inputs.values() {
            budget.charge_derived(value.expose().len())?;
        }
        Ok(())
    }

    fn emit_input_deprecations(
        inputs: &ResolvedActionInputs,
        masker: &mut SecretMasker,
        events: &Arc<dyn ExecutionEvents>,
        cancellation: &dyn ExecutorCancellation,
    ) -> Result<bool, ExecutorAdapterError> {
        for (name, message) in inputs.deprecations() {
            let diagnostic = format!("Input '{name}' has been deprecated with message: {message}");
            if emit_system_while_active(&diagnostic, masker, events, cancellation)?.is_none() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn resolve_post_continue_on_error(
        &self,
        policies: &[DeferredPostContinue<'_>],
    ) -> Result<bool, ExecutorAdapterError> {
        for policy in policies.iter().rev() {
            let continued = match policy {
                DeferredPostContinue::Runtime { value, context } => {
                    self.resolve_runtime_boolean(value, context)?
                }
                DeferredPostContinue::Composite { value, context } => {
                    self.resolve_prepared_boolean(value, context)?
                }
            };
            if continued {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn run_posts(
        &self,
        request: &HydratedExecutionRequest<'_>,
        event: &GithubValue,
        endpoint: &dyn ExecutionEndpoint,
        paths: &AttemptPaths,
        services: &ServiceContainerBindings,
        commands: &mut JobCommandState,
        records: &mut [MutableStepResult],
        posts: &mut PostRegistry,
        status: &mut GithubStatus,
        conclusion: &mut JobConclusion,
        attachments: &mut ExecutionAttachments,
        masker: &mut SecretMasker,
        events: &Arc<dyn ExecutionEvents>,
        cancellation: &CleanupCancellation<'_>,
    ) -> Result<(), ExecutorAdapterError> {
        let mut post_budget = ActionExecutionBudget::new();
        while !posts.is_empty() {
            if stop_posts_if_cancelled(cancellation, status, conclusion) {
                posts.clear();
                break;
            }
            let Some((call_path, post)) = posts.pop_last() else {
                break;
            };
            let Some(context) = reconcile_post_operation(
                self.context(
                    request,
                    event,
                    commands,
                    records,
                    Some(services),
                    *status,
                    Some(&post.top_step_id),
                    GithubExecutionPhase::ActionPost,
                ),
                cancellation,
                status,
                conclusion,
            )?
            else {
                posts.clear();
                break;
            };
            let step_index = usize::try_from(post.top_step_index)
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob));
            let Some(step_index) =
                reconcile_post_operation(step_index, cancellation, status, conclusion)?
            else {
                posts.clear();
                break;
            };
            let step = request
                .job()
                .job()
                .steps()
                .get(step_index)
                .ok_or_else(|| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob));
            let Some(step) = reconcile_post_operation(step, cancellation, status, conclusion)?
            else {
                posts.clear();
                break;
            };
            let templates = self.resolve_post_templates(
                request,
                step,
                &context,
                commands,
                posts,
                &call_path,
                &post,
                *status,
                masker,
                &mut post_budget,
            );
            let Some(templates) =
                reconcile_post_operation(templates, cancellation, status, conclusion)?
            else {
                posts.clear();
                break;
            };
            let ResolvedPostTemplates::Execute(templates) = templates else {
                continue;
            };
            if stop_posts_if_cancelled(cancellation, status, conclusion) {
                posts.clear();
                break;
            }
            let Some(entry) = post.javascript.post() else {
                continue;
            };
            let node = self
                .ports
                .toolchain
                .node(post.javascript.runtime())
                .cloned()
                .ok_or_else(|| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Unsupported));
            let Some(node) = reconcile_post_operation(node, cancellation, status, conclusion)?
            else {
                posts.clear();
                break;
            };
            let state = commands
                .post_action_environment(&post.invocation)
                .into_iter()
                .map(|value| {
                    (
                        value.name().to_owned(),
                        ResolvedEnvironmentValue::secret(value.value()),
                    )
                })
                .collect();
            let Some(environment) = reconcile_post_operation(
                self.action_phase_environment(
                    request,
                    step,
                    &context,
                    commands,
                    &templates.action_environment,
                    &templates.input_environment,
                    &post.paths,
                    &templates.identity,
                    state,
                    masker,
                ),
                cancellation,
                status,
                conclusion,
            )?
            else {
                posts.clear();
                break;
            };
            let remaining = cancellation.remaining();
            if remaining.is_zero() {
                let reason = cancellation
                    .stop_reason(*conclusion)
                    .unwrap_or(PostStopReason::CleanupDeadline);
                reason.reconcile(status, conclusion);
                posts.clear();
                break;
            }
            let entry = post
                .paths
                .entry(entry)
                .map(|entry| entry.as_str().to_owned());
            let Some(entry) = reconcile_post_operation(entry, cancellation, status, conclusion)?
            else {
                posts.clear();
                break;
            };
            let execution = PhaseExecution {
                step_id: &post.runtime_step_id,
                report_step_id: &post.top_step_id,
                phase: post.phase,
                scope: StepPhase::ActionPost(post.invocation),
                program: node,
                arguments: vec![entry],
                working_directory: paths.workspace.clone(),
                environment,
                timeout: templates.timeout.min(remaining),
            };
            if stop_posts_if_cancelled(cancellation, status, conclusion) {
                posts.clear();
                break;
            }
            let Some(outcome) = reconcile_post_operation(
                self.run_phase(
                    endpoint,
                    paths,
                    request.lease().attempt_id(),
                    execution,
                    commands,
                    attachments,
                    masker,
                    events,
                    cancellation,
                ),
                cancellation,
                status,
                conclusion,
            )?
            else {
                posts.clear();
                break;
            };
            let stop_reason = cancellation.stop_reason(*conclusion);
            let effective_outcome = stop_reason.map_or(outcome, PostStopReason::outcome);
            if effective_outcome != CommandOutcome::Success {
                let mapped = if let Some(reason) = stop_reason {
                    reason.outcome().conclusion()
                } else {
                    let continued =
                        self.resolve_post_continue_on_error(&templates.continue_on_error);
                    let Some(continued) =
                        reconcile_post_operation(continued, cancellation, status, conclusion)?
                    else {
                        posts.clear();
                        break;
                    };
                    map_continue(effective_outcome.conclusion(), continued)
                };
                if let Some(record) = records
                    .iter_mut()
                    .find(|record| record.step_id.as_str() == post.top_step_id)
                {
                    if record.outcome == JobConclusion::Success {
                        record.outcome = effective_outcome.conclusion();
                    }
                    record.conclusion = mapped;
                    record.completed_at = self.ports.clock.now();
                }
                if stop_reason.is_none() && mapped != JobConclusion::Success {
                    *conclusion = mapped;
                    *status = status_for(mapped);
                }
            }
            if let Some(reason) = stop_reason {
                reason.reconcile(status, conclusion);
                posts.clear();
                break;
            }
            if stop_posts_if_cancelled(cancellation, status, conclusion) {
                posts.clear();
                break;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn context(
        &self,
        request: &HydratedExecutionRequest<'_>,
        event: &GithubValue,
        commands: &JobCommandState,
        records: &[MutableStepResult],
        services: Option<&ServiceContainerBindings>,
        status: GithubStatus,
        step_id: Option<&str>,
        phase: GithubExecutionPhase,
    ) -> Result<crate::GithubContextSnapshot, ExecutorAdapterError> {
        let steps = records
            .iter()
            .map(MutableStepResult::snapshot)
            .collect::<Vec<_>>();
        let event_path = event_path(self.config.runner_root(), request.lease().attempt_id())?;
        let snapshot = self
            .ports
            .contexts
            .snapshot(
                GithubContextRequest::new(
                    GithubExecutionIdentity::new(
                        request.job(),
                        request.runtime_context(),
                        request.lease(),
                        request.runtime_authorities(),
                    ),
                    &event_path,
                    event,
                    commands,
                    &steps,
                    status,
                    step_id,
                    phase,
                )
                .with_services(services),
            )
            .map_err(|error| map_port_error(error.kind()))?;
        let snapshot = if let Some(functions) = request.execution_functions() {
            snapshot.with_execution_functions((*functions).clone())
        } else {
            snapshot
        };
        if request.job().job().authority_profile() == JobAuthorityProfile::CredentialFree
            && (!snapshot.secret_masks().is_empty()
                || snapshot
                    .environment()
                    .iter()
                    .any(crate::ContextEnvironmentVariable::is_secret))
        {
            return Err(invalid_job());
        }
        Ok(snapshot)
    }

    fn condition(
        &self,
        condition: Option<&automata_ci_core::ExpressionProgram>,
        context: &crate::GithubContextSnapshot,
    ) -> Result<bool, ExecutorAdapterError> {
        condition.map_or(Ok(true), |condition| {
            self.expressions
                .evaluate_condition(condition, context.expression())
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))
        })
    }

    fn resolve_runtime_boolean(
        &self,
        value: &RuntimeBoolean,
        context: &dyn GithubEvaluationContext,
    ) -> Result<bool, ExecutorAdapterError> {
        if let Some(value) = value.literal_value() {
            return Ok(value);
        }
        let program = value.expression_program().ok_or_else(invalid_job)?;
        self.expressions
            .evaluate(program, context)
            .map(|value| value.is_truthy())
            .map_err(|_| invalid_job())
    }

    fn resolve_runtime_timeout(
        &self,
        timeout: Option<&RuntimeTimeoutTemplate>,
        context: &dyn GithubEvaluationContext,
    ) -> Result<Option<u32>, ExecutorAdapterError> {
        let Some(timeout) = timeout else {
            return Ok(None);
        };
        let value = match timeout.value() {
            RuntimePositiveInteger::Literal { value } => *value,
            RuntimePositiveInteger::Expression { program } => {
                let value = self
                    .expressions
                    .evaluate(program, context)
                    .map_err(|_| invalid_job())?;
                let GithubValue::Number(bits) = &value else {
                    return Err(invalid_job());
                };
                let number = f64::from_bits(*bits);
                if !number.is_finite() || number <= 0.0 {
                    return Err(invalid_job());
                }
                value
                    .coerce_to_string()
                    .parse::<u32>()
                    .map_err(|_| invalid_job())?
            }
        };
        let seconds = value
            .checked_mul(timeout.unit().seconds_multiplier())
            .ok_or_else(invalid_job)?;
        if seconds == 0 {
            return Err(invalid_job());
        }
        Ok(Some(seconds))
    }

    fn resolve_value_template(
        builder: &EnvironmentBuilder<'_>,
        value: &ValueTemplate,
        context: &dyn GithubEvaluationContext,
        masker: &mut SecretMasker,
    ) -> Result<ResolvedEnvironmentValue, ExecutorAdapterError> {
        builder.resolve_source_value(&ValueSource::Template(value.clone()), context, masker)
    }

    fn evaluate_job_outputs(
        definitions: &[automata_ci_core::JobOutputDefinition],
        trust: TrustOutputAuthority,
        builder: &EnvironmentBuilder<'_>,
        context: &crate::GithubContextSnapshot,
        cancellation: &ExecutionCancellation,
        masker: &mut SecretMasker,
    ) -> Result<BTreeMap<String, JobResultOutput>, ExecutorAdapterError> {
        let mut outputs = BTreeMap::new();
        for definition in definitions {
            if cancellation.is_cancelled() {
                return Err(ExecutorAdapterError::new(
                    ExecutorAdapterErrorKind::Cancelled,
                ));
            }
            let value = builder.resolve_value_template(definition.value(), context.expression())?;
            if cancellation.is_cancelled() {
                return Err(ExecutorAdapterError::new(
                    ExecutorAdapterErrorKind::Cancelled,
                ));
            }
            if value.is_empty() {
                continue;
            }
            let output = if trust == TrustOutputAuthority::Untrusted
                || definition.sensitivity() == OutputSensitivity::SecretDerived
                || masker.contains_secret(&value)?
            {
                JobResultOutput::secret_derived()
            } else {
                JobResultOutput::public(value)
                    .map_err(|error| map_job_result_validation_error(&error))?
            };
            if outputs
                .insert(definition.name().to_owned(), output)
                .is_some()
            {
                return Err(invalid_job());
            }
        }
        Ok(outputs)
    }

    fn service_specs(
        &self,
        request: &ExecutionRequest,
        context: &crate::GithubContextSnapshot,
        masker: &mut SecretMasker,
        cancellation: &dyn ExecutorCancellation,
    ) -> Result<ServiceContainerSpecs, ExecutorAdapterError> {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let builder = EnvironmentBuilder::new(
            &self.expressions,
            self.ports.secrets.as_ref(),
            request.environment().default_environment(),
        );
        let services = request
            .job()
            .job()
            .services()
            .iter()
            .map(|(name, service)| {
                if cancellation.is_cancelled() {
                    return Err(cancelled());
                }
                if service.credentials().is_some() || !service.volumes().is_empty() {
                    return Err(ExecutorAdapterError::new(
                        ExecutorAdapterErrorKind::Unsupported,
                    ));
                }
                let image =
                    cancellation_dominant(container_runtime::service_image(service), cancellation)?;
                let environment = cancellation_dominant(
                    builder.container_environment(service.environment(), context, masker),
                    cancellation,
                )?;
                let ports =
                    cancellation_dominant(container_runtime::service_ports(service), cancellation)?;
                let health = cancellation_dominant(
                    container_runtime::service_health_policy(service.options()),
                    cancellation,
                )?;
                let spec = cancellation_dominant(
                    container_runtime::service_spec(image, environment, ports, health),
                    cancellation,
                )?;
                Ok((name.clone(), spec))
            })
            .collect::<Result<std::collections::BTreeMap<_, _>, _>>()?;
        cancellation_dominant(
            ServiceContainerSpecs::new(services)
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob)),
            cancellation,
        )
    }

    fn transition_running(
        lifecycle: JobLifecycle,
        events: &Arc<dyn ExecutionEvents>,
    ) -> Result<(), ExecutorAdapterError> {
        match lifecycle {
            JobLifecycle::Preparing => events
                .transition(JobLifecycle::Running)
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal)),
            JobLifecycle::Running | JobLifecycle::Cancelling => Ok(()),
            JobLifecycle::Finalizing => Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::Unsupported,
            )),
            JobLifecycle::Queued
            | JobLifecycle::Leased
            | JobLifecycle::Succeeded
            | JobLifecycle::Failed
            | JobLifecycle::Cancelled
            | JobLifecycle::TimedOut
            | JobLifecycle::Skipped
            | JobLifecycle::Lost => Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::InvalidJob,
            )),
        }
    }

    fn retain_create_failure_custody(
        events: &Arc<dyn ExecutionEvents>,
        operation_id: OperationId,
        error: &ProviderError,
    ) -> Result<(), ExecutorAdapterError> {
        if error.outcome() == automata_ci_execution::OperationOutcome::Uncertain
            && let Some(handle) = error.recovery_handle()
        {
            let identity = journal_identity(handle)?;
            return events
                .sandbox_created(operation_id, identity)
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal));
        }
        let _ = events.provider_operation_failed(operation_id, provider_failure_outcome(error));
        Ok(())
    }

    fn obtain_endpoint(
        &self,
        request: &ExecutionRequest,
        workspace: &TargetPath,
        scratch: &TargetPath,
        service_specs: &ServiceContainerSpecs,
        events: &Arc<dyn ExecutionEvents>,
        cancellation: &dyn ExecutorCancellation,
    ) -> Result<ObtainedSandbox, ExecutorAdapterError> {
        let cancellation = ProviderCancellationBridge(cancellation);
        let generation = SandboxGeneration::new(request.lease().fencing_token().get())
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        let expected_custody = request.sandbox_custody();
        let (handle, invalid_evidence) = if let Some(recovered) = request.recovered_sandbox() {
            if recovered.provider().as_str() != self.ports.provider.provider_id().as_str() {
                return Err(ExecutorAdapterError::new(
                    ExecutorAdapterErrorKind::InvalidJob,
                ));
            }
            let handle = SandboxHandle::new(
                self.ports.provider.provider_id().clone(),
                recovered.handle().as_str(),
            )
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
            (handle, ExecutorAdapterErrorKind::InvalidJob)
        } else {
            let operation_id = events
                .begin_provider_operation(ProviderOperationKind::CreateSandbox)
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
            let spec = container_runtime::sandbox_spec(
                &self.config,
                request,
                operation_id,
                generation,
                workspace,
                scratch,
                service_specs,
            )?;
            let record = match self.ports.provider.create(&spec, &cancellation) {
                Ok(record) => record,
                Err(error) => {
                    Self::retain_create_failure_custody(events, operation_id, &error)?;
                    return Err(map_provider_error(&error));
                }
            };
            if record.generation() != generation
                || record.profile() != request.environment().attestation()
                || record.state() != SandboxState::Running
                || record.handle().provider() != self.ports.provider.provider_id()
            {
                return Err(ExecutorAdapterError::new(
                    ExecutorAdapterErrorKind::Internal,
                ));
            }
            let identity = journal_identity(record.handle())?;
            events
                .sandbox_created(operation_id, identity)
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
            (record.handle().clone(), ExecutorAdapterErrorKind::Internal)
        };
        let inspection = self
            .ports
            .provider
            .inspect(&handle, &cancellation)
            .map_err(|error| map_provider_error(&error))?;
        if inspection.handle() != &handle
            || inspection.handle().provider() != self.ports.provider.provider_id()
            || inspection.generation() != generation
            || inspection.custody() != expected_custody
            || inspection.profile() != request.environment().attestation()
            || inspection.state() != SandboxState::Running
        {
            return Err(ExecutorAdapterError::new(invalid_evidence));
        }
        let services = if service_specs.is_empty() {
            ServiceContainerBindings::empty()
        } else {
            self.ports
                .provider
                .service_bindings(&handle, &cancellation)
                .map_err(|error| map_provider_error(&error))?
        };
        container_runtime::validate_service_bindings(service_specs, &services)?;
        let endpoint = self
            .ports
            .provider
            .attach(&handle, &cancellation)
            .map_err(|error| map_provider_error(&error))?;
        let endpoint = events
            .bind_endpoint(self.ports.provider.clone(), inspection, endpoint)
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        Ok(ObtainedSandbox { endpoint, services })
    }

    fn prepare_attempt_directories(
        &self,
        endpoint: &dyn ExecutionEndpoint,
        paths: &AttemptPaths,
        attempt_id: AttemptId,
        default_environment: &automata_ci_execution::ExecutionEnvironment,
        cancellation: &ExecutionCancellation,
    ) -> Result<(), ExecutorAdapterError> {
        let (program, arguments) = match paths.root.platform() {
            TargetPlatform::Posix => (
                required_tool(self.ports.toolchain.install())?,
                vec![
                    "-d".to_owned(),
                    "-m".to_owned(),
                    DIRECTORY_MODE.to_owned(),
                    "--".to_owned(),
                    paths.root.as_str().to_owned(),
                    paths.scripts.as_str().to_owned(),
                    paths.commands.as_str().to_owned(),
                    paths.actions.as_str().to_owned(),
                ],
            ),
            TargetPlatform::Windows => (
                required_tool(self.ports.toolchain.pwsh())?,
                vec![
                    "-NoLogo".to_owned(),
                    "-NoProfile".to_owned(),
                    "-NonInteractive".to_owned(),
                    "-Command".to_owned(),
                    windows_directory_creation_script([
                        &paths.root,
                        &paths.scripts,
                        &paths.commands,
                        &paths.actions,
                    ]),
                ],
            ),
        };
        let argv = ExecutionArgv::new(program, arguments)
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        let command = ExecutionCommand::new(
            self.ports.operation_ids.operation_id(
                attempt_id,
                OperationPurpose::PrepareDirectory,
                0,
            ),
            argv,
            paths.workspace.clone(),
            default_environment.clone(),
            self.config.default_step_timeout(),
            self.config.maximum_output_bytes(),
        )
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        let output = endpoint
            .exec(&command, &ProviderCancellationBridge(cancellation))
            .map_err(map_execution_error)?;
        require_success(&output)
    }

    #[allow(clippy::too_many_arguments)]
    fn copy_bytes(
        &self,
        endpoint: &dyn ExecutionEndpoint,
        attempt_id: AttemptId,
        purpose: OperationPurpose,
        ordinal: u32,
        path: &TargetPath,
        bytes: &[u8],
        cancellation: &dyn ExecutorCancellation,
    ) -> Result<(), ExecutorAdapterError> {
        let request = CopyToRequest::new(
            self.ports
                .operation_ids
                .operation_id(attempt_id, purpose, ordinal),
            path.clone(),
            bytes.to_vec(),
        )
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::ResourceExhausted))?;
        endpoint
            .copy_to(&request, &ProviderCancellationBridge(cancellation))
            .map_err(map_execution_error)
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn run_phase(
        &self,
        endpoint: &dyn ExecutionEndpoint,
        paths: &AttemptPaths,
        attempt_id: AttemptId,
        execution: PhaseExecution,
        commands: &mut JobCommandState,
        attachments: &mut ExecutionAttachments,
        masker: &mut SecretMasker,
        events: &Arc<dyn ExecutionEvents>,
        cancellation: &dyn ExecutorCancellation,
    ) -> Result<CommandOutcome, ExecutorAdapterError> {
        if cancellation.is_cancelled() {
            return Ok(CommandOutcome::Cancelled);
        }
        let artifact_hash_timeout = execution.timeout.min(ARTIFACT_HASH_TIMEOUT);
        let command_paths = paths.command_files(execution.phase)?;
        let initialized = self
            .initialize_command_files(
                endpoint,
                attempt_id,
                execution.phase,
                &command_paths,
                commands,
                cancellation,
            )
            .map_err(|error| {
                observe_phase_failure(
                    error,
                    attempt_id,
                    execution.phase,
                    "initialize_command_files",
                )
            });
        let Some(()) = reconcile_cancelled_operation(initialized, cancellation)? else {
            return Ok(CommandOutcome::Cancelled);
        };
        let environment = add_command_file_environment(&execution.environment, &command_paths)?;
        let command = self
            .build_phase_command(attempt_id, &execution, environment)
            .map_err(|error| {
                observe_phase_failure(error, attempt_id, execution.phase, "build_phase_command")
            })?;
        let output = endpoint
            .exec(&command, &ProviderCancellationBridge(cancellation))
            .map_err(map_execution_error)
            .map_err(|error| {
                observe_phase_failure(error, attempt_id, execution.phase, "execute_phase")
            });
        let Some(output) = reconcile_cancelled_operation(output, cancellation)? else {
            return Ok(CommandOutcome::Cancelled);
        };
        if cancellation.is_cancelled() {
            return Ok(CommandOutcome::Cancelled);
        }
        let outcome = CommandOutcome::from_termination(output.termination());
        if output.was_truncated() {
            if emit_system_while_active(TRUNCATED_OUTPUT_DIAGNOSTIC, masker, events, cancellation)?
                .is_none()
            {
                return Ok(CommandOutcome::Cancelled);
            }
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::ResourceExhausted,
            ));
        }
        let collected = (|| {
            let completed = self
                .collect_completed_phase(
                    endpoint,
                    attempt_id,
                    execution.phase,
                    &command_paths,
                    commands.platform(),
                    &output,
                    masker,
                    events,
                    cancellation,
                )
                .map_err(|error| {
                    observe_phase_failure(
                        error,
                        attempt_id,
                        execution.phase,
                        "collect_completed_phase",
                    )
                })?;
            if cancellation.is_cancelled() {
                return Err(cancelled());
            }
            let artifacts = self.resolve_artifact_subjects(
                endpoint,
                attempt_id,
                execution.phase,
                &paths.workspace,
                command.environment(),
                &completed.artifacts,
                artifact_hash_timeout,
                cancellation,
            )?;
            let completed_commands = completed.commands.with_artifacts(artifacts);
            let runtime_step_id = RuntimeStepId::new(execution.step_id)
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
            let scope = StepScope::new(runtime_step_id, execution.scope);
            let applied = self
                .completed_steps
                .apply_completed_step(commands, &scope, &completed_commands)
                .map_err(|error| map_phase_application_error(&error))
                .map_err(|error| {
                    observe_phase_failure(
                        error,
                        attempt_id,
                        execution.phase,
                        "apply_completed_step",
                    )
                })?;
            if cancellation.is_cancelled() {
                return Err(cancelled());
            }
            let mut next_attachments = attachments.clone();
            next_attachments.record_phase(
                execution.report_step_id,
                applied.summary().markdown(),
                &completed.annotations,
                applied.notices(),
                completed.command_file_notice,
                masker,
            )?;
            Ok((applied.into_next_state(), next_attachments))
        })();

        match collected {
            Ok((next_commands, next_attachments)) => {
                *commands = next_commands;
                *attachments = next_attachments;
            }
            Err(_) if outcome != CommandOutcome::Success => {
                // The runner processes command files in a finally boundary. A
                // partial or malformed file may not replace the process's
                // already-known failure, timeout, or cancellation outcome.
                return Ok(outcome);
            }
            Err(error) => return Err(error),
        }
        Ok(outcome)
    }

    fn build_phase_command(
        &self,
        attempt_id: AttemptId,
        execution: &PhaseExecution,
        environment: automata_ci_execution::ExecutionEnvironment,
    ) -> Result<ExecutionCommand, ExecutorAdapterError> {
        let argv = ExecutionArgv::new(execution.program.clone(), execution.arguments.clone())
            .map_err(|_| invalid_job())?;
        ExecutionCommand::new(
            self.ports.operation_ids.operation_id(
                attempt_id,
                OperationPurpose::ExecutePhase,
                execution.phase,
            ),
            argv,
            execution.working_directory.clone(),
            environment,
            execution.timeout,
            self.config.maximum_output_bytes(),
        )
        .map_err(|_| invalid_job())
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_completed_phase(
        &self,
        endpoint: &dyn ExecutionEndpoint,
        attempt_id: AttemptId,
        phase: u32,
        paths: &CommandFilePaths,
        platform: CommandFilePlatform,
        output: &ExecutionOutput,
        masker: &mut SecretMasker,
        events: &Arc<dyn ExecutionEvents>,
        cancellation: &dyn ExecutorCancellation,
    ) -> Result<CollectedPhase, ExecutorAdapterError> {
        let completed = self
            .read_command_files(endpoint, attempt_id, phase, paths, platform, cancellation)
            .map_err(|error| {
                observe_phase_failure(error, attempt_id, phase, "read_command_files")
            })?;
        if cancellation.is_cancelled() {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::Cancelled,
            ));
        }
        let parsed = parse_output_with_cancellation(
            output.records(),
            self.workflow_command_limits,
            self.workflow_command_policy,
            masker,
            &|| cancellation.is_cancelled(),
        )
        .map_err(|error| observe_phase_failure(error, attempt_id, phase, "parse_output"))?;
        if cancellation.is_cancelled() {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::Cancelled,
            ));
        }
        let mut legacy = Vec::new();
        let mut annotations = Vec::new();
        let processed = process_output(
            parsed,
            masker,
            events,
            &mut legacy,
            &mut annotations,
            &|| cancellation.is_cancelled(),
        );
        if cancellation.is_cancelled() {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::Cancelled,
            ));
        }
        processed
            .map_err(|error| observe_phase_failure(error, attempt_id, phase, "process_output"))?;
        Ok(CollectedPhase {
            commands: completed.commands.with_legacy_mutations(&legacy),
            artifacts: completed.artifacts,
            annotations,
            command_file_notice: completed.command_file_notice,
        })
    }

    fn initialize_command_files(
        &self,
        endpoint: &dyn ExecutionEndpoint,
        attempt_id: AttemptId,
        phase: u32,
        paths: &CommandFilePaths,
        commands: &JobCommandState,
        cancellation: &dyn ExecutorCancellation,
    ) -> Result<(), ExecutorAdapterError> {
        for (index, (_, path)) in paths.values.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Err(ExecutorAdapterError::new(
                    ExecutorAdapterErrorKind::Cancelled,
                ));
            }
            let ordinal = phase
                .checked_mul(5)
                .and_then(|value| value.checked_add(u32::try_from(index).ok()?))
                .ok_or_else(|| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
            self.copy_bytes(
                endpoint,
                attempt_id,
                OperationPurpose::InitializeCommandFile,
                ordinal,
                path,
                &[],
                cancellation,
            )?;
        }
        self.copy_bytes(
            endpoint,
            attempt_id,
            OperationPurpose::InitializeArtifactsFile,
            phase,
            &paths.artifacts,
            &[],
            cancellation,
        )?;
        let artifact_list = commands
            .artifact_list_json()
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        self.copy_bytes(
            endpoint,
            attempt_id,
            OperationPurpose::InitializeArtifactsList,
            phase,
            &paths.artifacts_list,
            &artifact_list,
            cancellation,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn read_command_files(
        &self,
        endpoint: &dyn ExecutionEndpoint,
        attempt_id: AttemptId,
        phase: u32,
        paths: &CommandFilePaths,
        platform: CommandFilePlatform,
        cancellation: &dyn ExecutorCancellation,
    ) -> Result<DecodedCommandFiles, ExecutorAdapterError> {
        let mut parsed = Vec::with_capacity(COMMAND_FILE_KINDS.len());
        let mut command_file_notice = None;
        for (index, (kind, path)) in paths.values.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Err(ExecutorAdapterError::new(
                    ExecutorAdapterErrorKind::Cancelled,
                ));
            }
            let ordinal = phase
                .checked_mul(5)
                .and_then(|value| value.checked_add(u32::try_from(index).ok()?))
                .ok_or_else(|| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
            let configured_limit = if *kind == CommandFileKind::StepSummary {
                self.command_files.limits().maximum_summary_bytes()
            } else {
                self.command_files.limits().maximum_file_bytes()
            };
            let transfer_limit = if *kind == CommandFileKind::StepSummary {
                configured_limit
                    .checked_add(1)
                    .ok_or_else(|| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?
            } else {
                configured_limit
            };
            let request = CopyFromRequest::new(
                self.ports.operation_ids.operation_id(
                    attempt_id,
                    OperationPurpose::ReadCommandFile,
                    ordinal,
                ),
                path.clone(),
                transfer_limit,
            )
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
            let copied = endpoint.copy_from(&request, &ProviderCancellationBridge(cancellation));
            if cancellation.is_cancelled() {
                return Err(ExecutorAdapterError::new(
                    ExecutorAdapterErrorKind::Cancelled,
                ));
            }
            let bytes = match copied {
                Ok(bytes)
                    if *kind == CommandFileKind::StepSummary && bytes.len() > configured_limit =>
                {
                    command_file_notice = Some(CommandFileNotice::SummaryTooLarge {
                        maximum_bytes: configured_limit,
                    });
                    Vec::new()
                }
                Ok(bytes) => bytes,
                Err(error)
                    if *kind == CommandFileKind::StepSummary
                        && error.kind() == ExecutionErrorKind::NotFound =>
                {
                    Vec::new()
                }
                Err(error)
                    if *kind == CommandFileKind::StepSummary
                        && error.kind() == ExecutionErrorKind::OutputLimitExceeded =>
                {
                    command_file_notice = Some(CommandFileNotice::SummaryTooLarge {
                        maximum_bytes: configured_limit,
                    });
                    Vec::new()
                }
                Err(error) => return Err(map_execution_error(error)),
            };
            parsed.push(
                self.command_files
                    .decode(*kind, &bytes, platform)
                    .map_err(|error| {
                        tracing::warn!(
                            attempt_id = %attempt_id,
                            phase,
                            command_file_kind = ?kind,
                            decode_error = ?error,
                            "GitHub command file was rejected"
                        );
                        ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob)
                    })?,
            );
        }
        let [environment, output, path, state, summary] = parsed
            .try_into()
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        let ParsedCommandFile::Environment(environment) = environment else {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::Internal,
            ));
        };
        let ParsedCommandFile::Output(output) = output else {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::Internal,
            ));
        };
        let ParsedCommandFile::Path(path) = path else {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::Internal,
            ));
        };
        let ParsedCommandFile::State(state) = state else {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::Internal,
            ));
        };
        let ParsedCommandFile::StepSummary(summary) = summary else {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::Internal,
            ));
        };
        let commands = CompletedStepCommands::new(environment, output, path, state, summary);
        let artifacts = self.read_artifact_declarations(
            endpoint,
            attempt_id,
            phase,
            &paths.artifacts,
            cancellation,
        )?;
        Ok(DecodedCommandFiles {
            commands,
            artifacts,
            command_file_notice,
        })
    }

    fn read_artifact_declarations(
        &self,
        endpoint: &dyn ExecutionEndpoint,
        attempt_id: AttemptId,
        phase: u32,
        path: &TargetPath,
        cancellation: &dyn ExecutorCancellation,
    ) -> Result<ArtifactDeclarationCommandFile, ExecutorAdapterError> {
        let request = CopyFromRequest::new(
            self.ports.operation_ids.operation_id(
                attempt_id,
                OperationPurpose::ReadArtifactsFile,
                phase,
            ),
            path.clone(),
            MAX_ARTIFACT_DECLARATION_FILE_BYTES,
        )
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        let bytes = endpoint
            .copy_from(&request, &ProviderCancellationBridge(cancellation))
            .map_err(map_execution_error)?;
        if cancellation.is_cancelled() {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::Cancelled,
            ));
        }
        let ParsedCommandFile::Artifacts(artifacts) = self
            .command_files
            .decode(
                CommandFileKind::Artifacts,
                &bytes,
                CommandFilePlatform::Unix,
            )
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?
        else {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::Internal,
            ));
        };
        Ok(artifacts)
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_artifact_subjects(
        &self,
        endpoint: &dyn ExecutionEndpoint,
        attempt_id: AttemptId,
        phase: u32,
        workspace: &TargetPath,
        launch_environment: &automata_ci_execution::ExecutionEnvironment,
        declarations: &ArtifactDeclarationCommandFile,
        timeout: Duration,
        cancellation: &dyn ExecutorCancellation,
    ) -> Result<ArtifactSubjectCommandFile, ExecutorAdapterError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        let mut file_subjects = BTreeMap::<String, ArtifactSubject>::new();
        let mut subjects = Vec::with_capacity(declarations.declarations().len());
        for declaration in declarations.declarations() {
            if cancellation.is_cancelled() {
                return Err(cancelled());
            }
            match declaration {
                ArtifactDeclaration::Oci(subject) => subjects.push(subject.clone()),
                ArtifactDeclaration::File(file) => {
                    if let Some(subject) = file_subjects.get(file.path()) {
                        subjects.push(subject.clone());
                        continue;
                    }
                    if file_subjects.len() >= MAX_ARTIFACT_SUBJECTS {
                        return Err(resource_exhausted());
                    }
                    let file_index =
                        u32::try_from(file_subjects.len()).map_err(|_| resource_exhausted())?;
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(ExecutorAdapterError::new(
                            ExecutorAdapterErrorKind::TimedOut,
                        ));
                    }
                    let digest = self.hash_artifact_file(
                        endpoint,
                        attempt_id,
                        phase,
                        file_index,
                        workspace,
                        launch_environment,
                        file.path(),
                        remaining,
                        cancellation,
                    )?;
                    let name = artifact_file_name(file.path())?;
                    let subject = ArtifactSubject::new(
                        name,
                        format!("sha256:{digest}"),
                        ArtifactSubjectKind::File,
                    )
                    .map_err(|_| invalid_job())?;
                    file_subjects.insert(file.path().to_owned(), subject.clone());
                    subjects.push(subject);
                }
            }
        }
        Ok(ArtifactSubjectCommandFile::new(subjects))
    }

    #[allow(clippy::too_many_arguments)]
    fn hash_artifact_file(
        &self,
        endpoint: &dyn ExecutionEndpoint,
        attempt_id: AttemptId,
        phase: u32,
        file_index: u32,
        workspace: &TargetPath,
        launch_environment: &automata_ci_execution::ExecutionEnvironment,
        declared_path: &str,
        timeout: Duration,
        cancellation: &dyn ExecutorCancellation,
    ) -> Result<String, ExecutorAdapterError> {
        let (argv, environment) = artifact_hash_invocation(
            self.ports.toolchain.as_ref(),
            workspace.platform(),
            launch_environment,
            declared_path,
        )?;
        let command = ExecutionCommand::new(
            self.ports
                .operation_ids
                .artifact_hash_operation_id(attempt_id, phase, file_index),
            argv,
            workspace.clone(),
            environment,
            timeout,
            ARTIFACT_HASH_OUTPUT_BYTES,
        )
        .map_err(|_| invalid_job())?;
        let output = endpoint
            .exec(&command, &ProviderCancellationBridge(cancellation))
            .map_err(map_execution_error)?;
        if cancellation.is_cancelled() || output.termination() == ExecutionTermination::Cancelled {
            return Err(cancelled());
        }
        match output.termination() {
            ExecutionTermination::Exited(0) => {}
            ExecutionTermination::TimedOut => {
                return Err(ExecutorAdapterError::new(
                    ExecutorAdapterErrorKind::TimedOut,
                ));
            }
            ExecutionTermination::Exited(_)
            | ExecutionTermination::Signalled
            | ExecutionTermination::Cancelled => return Err(invalid_job()),
        }
        if output.was_truncated() || !output.stderr().is_empty() {
            return Err(resource_exhausted());
        }
        let digest = std::str::from_utf8(output.stdout()).map_err(|_| invalid_job())?;
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid_job());
        }
        Ok(digest.to_ascii_lowercase())
    }

    fn step_timeout(
        &self,
        step_timeout_seconds: Option<u32>,
        job_deadline: Option<UnixMillis>,
    ) -> Result<Duration, ExecutorAdapterError> {
        let requested = step_timeout_seconds
            .map_or(self.config.default_step_timeout(), |seconds| {
                Duration::from_secs(u64::from(seconds))
            });
        let Some(job_deadline) = job_deadline else {
            return Ok(requested);
        };
        let remaining = job_deadline
            .get()
            .saturating_sub(self.ports.clock.now().get());
        if remaining <= 0 {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::TimedOut,
            ));
        }
        Ok(requested.min(Duration::from_millis(u64::try_from(remaining).unwrap_or(0))))
    }

    fn cleanup_sandbox(
        &self,
        request: &CleanupRequest,
        events: &Arc<dyn ExecutionEvents>,
        cancellation: &ExecutionCancellation,
    ) -> Result<(), ExecutorAdapterError> {
        if request.sandbox().provider().as_str() != self.ports.provider.provider_id().as_str() {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::InvalidJob,
            ));
        }
        let handle = SandboxHandle::new(
            self.ports.provider.provider_id().clone(),
            request.sandbox().handle().as_str(),
        )
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
        let generation = SandboxGeneration::new(request.guard().fencing_token().get())
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        let operation_id = events
            .begin_provider_operation(ProviderOperationKind::DestroySandbox)
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        let destroy =
            DestroySandbox::new(operation_id, handle, generation, request.sandbox_custody());
        match self
            .ports
            .provider
            .destroy(&destroy, &ProviderCancellationBridge(cancellation))
        {
            Ok(_) => events
                .provider_operation_completed(operation_id)
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal)),
            Err(error) => {
                let _ = events
                    .provider_operation_failed(operation_id, provider_failure_outcome(&error));
                Err(map_provider_error(&error))
            }
        }
    }
}

impl fmt::Debug for GithubJobExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubJobExecutor")
            .field("config", &self.config)
            .field("ports", &self.ports)
            .field("local_actions", &self.local_actions)
            .field("expressions", &self.expressions)
            .field("command_files", &self.command_files)
            .field("completed_steps", &self.completed_steps)
            .field("workflow_command_limits", &self.workflow_command_limits)
            .field("workflow_command_policy", &self.workflow_command_policy)
            .field(
                "custody_acknowledger",
                &self.custody_acknowledger.as_ref().map(|_| "configured"),
            )
            .field(
                "managed_secret_bindings",
                &self.managed_secret_bindings.as_ref().map(BTreeMap::len),
            )
            .finish()
    }
}

impl JobExecutor for GithubJobExecutor {
    fn admit(&self, job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection> {
        self.validate_admission(job).map(ExecutionAdmission::new)
    }

    fn execute(
        &self,
        request: ExecutionRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(async move {
            self.execute_job(request, events, cancellation)
                .await
                .map_err(ExecutorError::from)
        })
    }

    fn cleanup(
        &self,
        request: CleanupRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        Box::pin(async move {
            self.cleanup_sandbox(&request, &events, &cancellation)
                .map_err(ExecutorError::from)
        })
    }
}

trait ExecutorCancellation: Send + Sync {
    fn is_cancelled(&self) -> bool;
}

impl ExecutorCancellation for ExecutionCancellation {
    fn is_cancelled(&self) -> bool {
        ExecutionCancellation::is_cancelled(self)
    }
}

struct CleanupCancellation<'a> {
    execution: &'a ExecutionCancellation,
    deadline: Instant,
}

impl<'a> CleanupCancellation<'a> {
    fn new(execution: &'a ExecutionCancellation, timeout: Duration) -> Self {
        Self {
            execution,
            deadline: Instant::now()
                .checked_add(timeout)
                .unwrap_or_else(Instant::now),
        }
    }

    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    fn execution_is_cancelled(&self) -> bool {
        self.execution.is_cancelled()
    }

    fn deadline_expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    fn stop_reason(&self, conclusion: JobConclusion) -> Option<PostStopReason> {
        if self.execution_is_cancelled() || conclusion == JobConclusion::Cancelled {
            Some(PostStopReason::ExecutionCancellation)
        } else if self.deadline_expired() {
            Some(PostStopReason::CleanupDeadline)
        } else {
            None
        }
    }
}

impl ExecutorCancellation for CleanupCancellation<'_> {
    fn is_cancelled(&self) -> bool {
        self.execution_is_cancelled() || self.deadline_expired()
    }
}

#[derive(Clone, Copy)]
enum PostStopReason {
    ExecutionCancellation,
    CleanupDeadline,
}

impl PostStopReason {
    const fn outcome(self) -> CommandOutcome {
        match self {
            Self::ExecutionCancellation => CommandOutcome::Cancelled,
            Self::CleanupDeadline => CommandOutcome::TimedOut,
        }
    }

    fn reconcile(self, status: &mut GithubStatus, conclusion: &mut JobConclusion) {
        match self {
            Self::ExecutionCancellation => {
                *conclusion = JobConclusion::Cancelled;
                *status = GithubStatus::Cancelled;
            }
            Self::CleanupDeadline => {
                if *conclusion != JobConclusion::Failure {
                    *conclusion = JobConclusion::TimedOut;
                    *status = GithubStatus::Failure;
                }
            }
        }
    }
}

fn stop_posts_if_cancelled(
    cancellation: &CleanupCancellation<'_>,
    status: &mut GithubStatus,
    conclusion: &mut JobConclusion,
) -> bool {
    let Some(reason) = cancellation.stop_reason(*conclusion) else {
        return false;
    };
    reason.reconcile(status, conclusion);
    true
}

fn reconcile_post_operation<T>(
    result: Result<T, ExecutorAdapterError>,
    cancellation: &CleanupCancellation<'_>,
    status: &mut GithubStatus,
    conclusion: &mut JobConclusion,
) -> Result<Option<T>, ExecutorAdapterError> {
    if stop_posts_if_cancelled(cancellation, status, conclusion) {
        Ok(None)
    } else {
        result.map(Some)
    }
}

fn reconcile_cancelled_operation<T>(
    result: Result<T, ExecutorAdapterError>,
    cancellation: &dyn ExecutorCancellation,
) -> Result<Option<T>, ExecutorAdapterError> {
    if cancellation.is_cancelled() {
        Ok(None)
    } else {
        result.map(Some)
    }
}

fn cancellation_dominant<T>(
    result: Result<T, ExecutorAdapterError>,
    cancellation: &dyn ExecutorCancellation,
) -> Result<T, ExecutorAdapterError> {
    reconcile_cancelled_operation(result, cancellation)?.ok_or_else(cancelled)
}

fn emit_system_while_active(
    value: &str,
    masker: &mut SecretMasker,
    events: &Arc<dyn ExecutionEvents>,
    cancellation: &dyn ExecutorCancellation,
) -> Result<Option<()>, ExecutorAdapterError> {
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    reconcile_cancelled_operation(emit_system(value, masker, events), cancellation)
}

fn reconcile_execution_cancellation(
    cancellation: &ExecutionCancellation,
    status: &mut GithubStatus,
    conclusion: &mut JobConclusion,
) -> bool {
    if cancellation.is_cancelled() {
        *conclusion = JobConclusion::Cancelled;
        *status = GithubStatus::Cancelled;
        true
    } else {
        false
    }
}

struct ProviderCancellationBridge<'a>(&'a dyn ExecutorCancellation);

impl Cancellation for ProviderCancellationBridge<'_> {
    fn disposition(&self) -> CancellationDisposition {
        if self.0.is_cancelled() {
            CancellationDisposition::Terminate
        } else {
            CancellationDisposition::Active
        }
    }
}

struct PhaseExecution<'a> {
    step_id: &'a str,
    report_step_id: &'a str,
    phase: u32,
    scope: StepPhase,
    program: TargetPath,
    arguments: Vec<String>,
    working_directory: TargetPath,
    environment: automata_ci_execution::ExecutionEnvironment,
    timeout: Duration,
}

struct CollectedPhase {
    commands: CompletedStepCommands,
    artifacts: ArtifactDeclarationCommandFile,
    annotations: Vec<automata_ci_github_runtime::Annotation>,
    command_file_notice: Option<CommandFileNotice>,
}

struct DecodedCommandFiles {
    commands: CompletedStepCommands,
    artifacts: ArtifactDeclarationCommandFile,
    command_file_notice: Option<CommandFileNotice>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandFileNotice {
    SummaryTooLarge { maximum_bytes: usize },
}

#[derive(Clone, Default)]
struct ExecutionAttachments {
    by_step: BTreeMap<String, RetainedStepAttachments>,
    annotation_count: usize,
    aggregate_bytes: usize,
    summary_budget_exhausted: bool,
}

impl ExecutionAttachments {
    fn record_phase(
        &mut self,
        step_id: &str,
        summary: &str,
        annotations: &[automata_ci_github_runtime::Annotation],
        notices: &[PhaseApplicationNotice],
        command_file_notice: Option<CommandFileNotice>,
        masker: &mut SecretMasker,
    ) -> Result<(), ExecutorAdapterError> {
        self.record_summary(step_id, summary, command_file_notice, masker)?;
        let retained = self.by_step.entry(step_id.to_owned()).or_default();

        for annotation in annotations {
            let properties = annotation
                .properties()
                .iter()
                .filter_map(|property| {
                    canonical_annotation_property(property.name()).map(|name| (name, property))
                })
                .map(|(name, property)| {
                    let value = masked_attachment_text(property.value(), masker)?;
                    charge_attachment_bytes(&mut self.aggregate_bytes, name.len())?;
                    charge_attachment_bytes(&mut self.aggregate_bytes, value.len())?;
                    Ok(StepAnnotationProperty::new(name, value))
                })
                .collect::<Result<Vec<_>, ExecutorAdapterError>>()?;
            if properties.len() > MAX_STEP_ANNOTATION_PROPERTIES {
                return Err(resource_exhausted());
            }
            let message = masked_attachment_text(annotation.message(), masker)?;
            charge_attachment_bytes(&mut self.aggregate_bytes, message.len())?;
            self.annotation_count = self
                .annotation_count
                .checked_add(1)
                .filter(|count| *count <= MAX_JOB_RESULT_ANNOTATIONS)
                .ok_or_else(resource_exhausted)?;
            retained.annotations.push(StepAnnotation::new(
                match annotation.level() {
                    automata_ci_github_runtime::AnnotationLevel::Error => {
                        StepAnnotationLevel::Error
                    }
                    automata_ci_github_runtime::AnnotationLevel::Warning => {
                        StepAnnotationLevel::Warning
                    }
                    automata_ci_github_runtime::AnnotationLevel::Notice => {
                        StepAnnotationLevel::Notice
                    }
                },
                message,
                properties,
            ));
        }

        for notice in notices {
            let message = match notice {
                PhaseApplicationNotice::BlockedNodeOptions => {
                    "NODE_OPTIONS from a command file was ignored"
                }
                PhaseApplicationNotice::BlockedReservedEnvironment(namespace) => match namespace {
                    automata_ci_github_runtime::ReservedEnvironmentNamespace::Github => {
                        "a runner-owned GITHUB default from a command file was ignored"
                    }
                    automata_ci_github_runtime::ReservedEnvironmentNamespace::Runner => {
                        "a runner-owned RUNNER default from a command file was ignored"
                    }
                },
                PhaseApplicationNotice::StateIgnoredForRunStep => {
                    "GITHUB_STATE from a run step was ignored"
                }
            };
            charge_attachment_bytes(&mut self.aggregate_bytes, message.len())?;
            self.annotation_count = self
                .annotation_count
                .checked_add(1)
                .filter(|count| *count <= MAX_JOB_RESULT_ANNOTATIONS)
                .ok_or_else(resource_exhausted)?;
            retained.annotations.push(StepAnnotation::new(
                StepAnnotationLevel::Notice,
                message,
                Vec::new(),
            ));
        }
        Ok(())
    }

    fn record_summary(
        &mut self,
        step_id: &str,
        summary: &str,
        command_file_notice: Option<CommandFileNotice>,
        masker: &mut SecretMasker,
    ) -> Result<(), ExecutorAdapterError> {
        if self.summary_budget_exhausted
            || self
                .by_step
                .get(step_id)
                .is_some_and(|retained| retained.summary_closed)
        {
            return Ok(());
        }

        if let Some(CommandFileNotice::SummaryTooLarge { maximum_bytes }) = command_file_notice {
            self.record_summary_notice(
                step_id,
                &format!(
                    "$GITHUB_STEP_SUMMARY upload aborted: content exceeds the {maximum_bytes}-byte limit"
                ),
                StepAnnotationLevel::Error,
                false,
                masker,
            )?;
            return Ok(());
        }
        if summary.is_empty() {
            return Ok(());
        }

        // Every source file is capped at one byte beyond the configured 1 MiB
        // ceiling before it reaches this boundary. Mask replacement can expand
        // that bounded input by at most three times, so the masking work and
        // temporary allocation remain bounded even for a one-byte secret.
        let redacted_bytes = masker.mask(summary.as_bytes())?;
        if redacted_bytes.len() > MAX_STEP_ATTACHMENT_TEXT_BYTES {
            self.record_summary_notice(
                step_id,
                MASKED_SUMMARY_LIMIT_DIAGNOSTIC,
                StepAnnotationLevel::Warning,
                true,
                masker,
            )?;
            return Ok(());
        }
        let redacted = String::from_utf8(redacted_bytes)
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        if redacted.is_empty() {
            return Ok(());
        }

        let retained_bytes = self
            .by_step
            .get(step_id)
            .map_or(0, |retained| retained.summary.len());
        let Some(projected_step_bytes) = retained_bytes.checked_add(redacted.len()) else {
            self.record_summary_notice(
                step_id,
                STEP_SUMMARY_LIMIT_DIAGNOSTIC,
                StepAnnotationLevel::Warning,
                true,
                masker,
            )?;
            return Ok(());
        };
        if projected_step_bytes > MAX_STEP_ATTACHMENT_TEXT_BYTES {
            self.record_summary_notice(
                step_id,
                STEP_SUMMARY_LIMIT_DIAGNOSTIC,
                StepAnnotationLevel::Warning,
                true,
                masker,
            )?;
            return Ok(());
        }

        if self
            .aggregate_bytes
            .checked_add(redacted.len())
            .is_none_or(|projected| projected > MAX_JOB_RESULT_ATTACHMENT_BYTES)
        {
            self.summary_budget_exhausted = true;
            self.record_summary_notice(
                step_id,
                JOB_SUMMARY_LIMIT_DIAGNOSTIC,
                StepAnnotationLevel::Warning,
                true,
                masker,
            )?;
            return Ok(());
        }

        self.aggregate_bytes += redacted.len();
        self.by_step
            .entry(step_id.to_owned())
            .or_default()
            .summary
            .push_str(&redacted);
        Ok(())
    }

    fn record_summary_notice(
        &mut self,
        step_id: &str,
        message: &str,
        level: StepAnnotationLevel,
        close_summary: bool,
        masker: &mut SecretMasker,
    ) -> Result<(), ExecutorAdapterError> {
        let already_noted = {
            let retained = self.by_step.entry(step_id.to_owned()).or_default();
            retained.summary_closed |= close_summary;
            retained.summary_notice_recorded
        };
        if already_noted {
            return Ok(());
        }

        // Diagnostics are masked too: a dynamically registered short secret
        // can otherwise coincide with text in this runner-owned message.
        let message = String::from_utf8(masker.mask(message.as_bytes())?)
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        if message.len() > MAX_STEP_ATTACHMENT_TEXT_BYTES {
            return Err(resource_exhausted());
        }
        self.make_summary_notice_room(step_id, message.len());
        let message = if self.aggregate_bytes.saturating_add(message.len())
            <= MAX_JOB_RESULT_ATTACHMENT_BYTES
        {
            message
        } else {
            // The structured annotation remains a deterministic indicator even
            // if unrelated, non-summary attachments left no reclaimable bytes.
            String::new()
        };
        if self.annotation_count >= MAX_JOB_RESULT_ANNOTATIONS {
            // Summary retention is observational and must never replace the
            // process result merely because the annotation collection is full.
            return Ok(());
        }
        self.aggregate_bytes += message.len();
        self.annotation_count += 1;
        let retained = self.by_step.entry(step_id.to_owned()).or_default();
        retained.summary_notice_recorded = true;
        retained
            .annotations
            .push(StepAnnotation::new(level, message, Vec::new()));
        Ok(())
    }

    fn make_summary_notice_room(&mut self, preferred_step: &str, bytes: usize) {
        let required = self
            .aggregate_bytes
            .saturating_add(bytes)
            .saturating_sub(MAX_JOB_RESULT_ATTACHMENT_BYTES);
        if required == 0 {
            return;
        }

        let mut remaining = required;
        if let Some(retained) = self.by_step.get_mut(preferred_step) {
            remaining = remaining.saturating_sub(truncate_summary_suffix(
                &mut retained.summary,
                remaining,
                &mut self.aggregate_bytes,
            ));
        }
        if remaining == 0 {
            return;
        }
        for (candidate, retained) in self.by_step.iter_mut().rev() {
            if candidate == preferred_step {
                continue;
            }
            remaining = remaining.saturating_sub(truncate_summary_suffix(
                &mut retained.summary,
                remaining,
                &mut self.aggregate_bytes,
            ));
            if remaining == 0 {
                break;
            }
        }
    }

    fn take(&mut self, step_id: &str) -> RetainedStepAttachments {
        self.by_step.remove(step_id).unwrap_or_default()
    }
}

#[derive(Clone, Default)]
struct RetainedStepAttachments {
    summary: String,
    annotations: Vec<StepAnnotation>,
    summary_closed: bool,
    summary_notice_recorded: bool,
}

fn truncate_summary_suffix(
    summary: &mut String,
    requested: usize,
    aggregate_bytes: &mut usize,
) -> usize {
    let original = summary.len();
    let mut retained = original.saturating_sub(requested);
    while !summary.is_char_boundary(retained) {
        retained = retained.saturating_sub(1);
    }
    summary.truncate(retained);
    let removed = original - retained;
    *aggregate_bytes = aggregate_bytes.saturating_sub(removed);
    removed
}

fn masked_attachment_text(
    value: &str,
    masker: &mut SecretMasker,
) -> Result<String, ExecutorAdapterError> {
    let value = String::from_utf8(masker.mask(value.as_bytes())?)
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
    if value.len() > MAX_STEP_ATTACHMENT_TEXT_BYTES {
        return Err(resource_exhausted());
    }
    Ok(value)
}

fn charge_attachment_bytes(total: &mut usize, bytes: usize) -> Result<(), ExecutorAdapterError> {
    *total = total
        .checked_add(bytes)
        .filter(|total| *total <= MAX_JOB_RESULT_ATTACHMENT_BYTES)
        .ok_or_else(resource_exhausted)?;
    Ok(())
}

fn canonical_annotation_property(name: &str) -> Option<&'static str> {
    ["title", "file", "line", "endLine", "col", "endColumn"]
        .into_iter()
        .find(|candidate| candidate.eq_ignore_ascii_case(name))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandOutcome {
    Success,
    Failure,
    TimedOut,
    Cancelled,
}

impl CommandOutcome {
    const fn from_termination(termination: ExecutionTermination) -> Self {
        match termination {
            ExecutionTermination::Exited(0) => Self::Success,
            ExecutionTermination::Exited(_) | ExecutionTermination::Signalled => Self::Failure,
            ExecutionTermination::TimedOut => Self::TimedOut,
            ExecutionTermination::Cancelled => Self::Cancelled,
        }
    }

    const fn conclusion(self) -> JobConclusion {
        match self {
            Self::Success => JobConclusion::Success,
            Self::Failure => JobConclusion::Failure,
            Self::TimedOut => JobConclusion::TimedOut,
            Self::Cancelled => JobConclusion::Cancelled,
        }
    }
}

struct RegisteredPost {
    top_step_index: u32,
    top_step_id: String,
    runtime_step_id: String,
    invocation: ActionInvocationId,
    javascript: crate::PreparedJavascriptAction,
    paths: ActionPaths,
    phase: u32,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct ActionCallPath(Vec<u32>);

impl ActionCallPath {
    fn top(index: u32) -> Self {
        Self(vec![index])
    }

    fn child(&self, index: usize) -> Result<Self, ExecutorAdapterError> {
        if self.0.len() >= MAX_ACTION_NESTING_DEPTH {
            return Err(resource_exhausted());
        }
        let mut path = self.0.clone();
        path.push(u32::try_from(index).map_err(|_| resource_exhausted())?);
        Ok(Self(path))
    }

    fn top_index(&self) -> u32 {
        self.0[0]
    }

    fn is_top(&self) -> bool {
        self.0.len() == 1
    }

    fn depth(&self) -> usize {
        self.0.len()
    }

    fn prefix(&self, depth: usize) -> Result<Self, ExecutorAdapterError> {
        if depth == 0 || depth > self.0.len() {
            return Err(invalid_job());
        }
        Ok(Self(self.0[..depth].to_vec()))
    }

    fn index_at(&self, depth: usize) -> Result<usize, ExecutorAdapterError> {
        self.0
            .get(depth)
            .copied()
            .ok_or_else(invalid_job)
            .and_then(|index| usize::try_from(index).map_err(|_| invalid_job()))
    }

    fn invocation_id(&self, top_step_id: &str) -> Result<ActionInvocationId, ExecutorAdapterError> {
        let value = if self.0.len() == 1 {
            format!("{top_step_id}-{}", self.0[0])
        } else {
            let suffix = self
                .0
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join("-");
            format!("composite-action-{suffix}")
        };
        ActionInvocationId::new(value).map_err(|_| invalid_job())
    }
}

#[derive(Default)]
struct PostRegistry {
    registration_order: Vec<u32>,
    top_level: BTreeMap<u32, BTreeMap<ActionCallPath, RegisteredPost>>,
    occurrences: BTreeMap<ActionCallPath, PostActionOccurrence>,
    composite_steps: BTreeMap<ActionCallPath, Vec<CompositeChildResult>>,
}

impl PostRegistry {
    fn reserve(&mut self, top_index: u32) {
        if let std::collections::btree_map::Entry::Vacant(entry) = self.top_level.entry(top_index) {
            self.registration_order.push(top_index);
            entry.insert(BTreeMap::new());
        }
    }

    fn register(
        &mut self,
        path: ActionCallPath,
        post: RegisteredPost,
    ) -> Result<(), ExecutorAdapterError> {
        let top_index = path.top_index();
        self.reserve(top_index);
        let posts = self.top_level.get_mut(&top_index).ok_or_else(invalid_job)?;
        if posts.insert(path, post).is_some() {
            return Err(invalid_job());
        }
        Ok(())
    }

    fn record_occurrence(
        &mut self,
        path: ActionCallPath,
        occurrence: PostActionOccurrence,
    ) -> Result<(), ExecutorAdapterError> {
        match self.occurrences.entry(path) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(occurrence);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &occurrence => {
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(_) => Err(invalid_job()),
        }
    }

    fn record_composite_steps(
        &mut self,
        path: ActionCallPath,
        steps: Vec<CompositeChildResult>,
    ) -> Result<(), ExecutorAdapterError> {
        if self.composite_steps.insert(path, steps).is_some() {
            return Err(invalid_job());
        }
        Ok(())
    }

    fn occurrence(
        &self,
        path: &ActionCallPath,
    ) -> Result<PostActionOccurrence, ExecutorAdapterError> {
        self.occurrences.get(path).cloned().ok_or_else(invalid_job)
    }

    fn composite_steps_value(
        &self,
        path: &ActionCallPath,
        commands: &JobCommandState,
    ) -> Result<GithubValue, ExecutorAdapterError> {
        let steps = self
            .composite_steps
            .get(path)
            .map_or(&[][..], Vec::as_slice);
        composite_steps_value(steps, commands)
    }

    fn pop_last(&mut self) -> Option<(ActionCallPath, RegisteredPost)> {
        while let Some(top_index) = self.registration_order.last().copied() {
            let posts = self.top_level.get_mut(&top_index)?;
            if let Some((path, post)) = posts.pop_last() {
                if posts.is_empty() {
                    self.top_level.remove(&top_index);
                    let removed = self.registration_order.pop();
                    debug_assert_eq!(removed, Some(top_index));
                }
                return Some((path, post));
            }
            self.top_level.remove(&top_index);
            let removed = self.registration_order.pop();
            debug_assert_eq!(removed, Some(top_index));
        }
        None
    }

    fn is_empty(&self) -> bool {
        self.registration_order.is_empty()
    }

    fn clear(&mut self) {
        self.registration_order.clear();
        self.top_level.clear();
        self.occurrences.clear();
        self.composite_steps.clear();
    }
}

#[derive(Clone, Eq, PartialEq)]
struct PostActionOccurrence {
    definition: PreparedActionDefinition,
    identity: ActionIdentity,
}

#[derive(Clone)]
struct LoadedAction {
    definition: PreparedActionDefinition,
    paths: ActionPaths,
}

struct PreloadedActionOccurrence {
    loaded: Box<LoadedAction>,
    reference: ActionReference,
    lifecycle: JavascriptPrePostState,
    flags: ActionLifecycleFlags,
}

#[derive(Clone, Copy, Default)]
struct ActionLifecycleFlags {
    has_pre: bool,
    has_post: bool,
}

impl ActionLifecycleFlags {
    fn from_definition(definition: &PreparedActionDefinition) -> Self {
        match definition.execution() {
            PreparedActionExecution::Javascript(javascript) => Self {
                has_pre: javascript.pre().is_some(),
                has_post: javascript.post().is_some(),
            },
            PreparedActionExecution::Composite(composite) => Self {
                has_pre: false,
                has_post: composite.steps().iter().any(|step| {
                    matches!(
                        step,
                        PreparedCompositeStep::Uses(step)
                            if matches!(step.reference(), ActionReference::Local { .. })
                    )
                }),
            },
        }
    }

    fn include(&mut self, child: Self) {
        self.has_pre |= child.has_pre;
        self.has_post |= child.has_post;
    }
}

#[derive(Default)]
struct ActionGraphPlanner {
    active: Vec<String>,
    occurrences: u32,
    materials: BTreeMap<String, PreparedAction>,
}

impl ActionGraphPlanner {
    fn with_materials(materials: BTreeMap<String, PreparedAction>) -> Self {
        Self {
            active: Vec::new(),
            occurrences: 0,
            materials,
        }
    }

    fn enter(&mut self, key: String) -> bool {
        if action_budget_rejection(&self.active, self.occurrences, &key).is_some() {
            return false;
        }
        self.occurrences += 1;
        self.active.push(key);
        true
    }

    fn leave(&mut self) {
        let _ = self.active.pop();
    }
}

struct PreloadedJobActions {
    actions: BTreeMap<ActionCallPath, PreloadedActionOccurrence>,
    main_suppressed: bool,
}

impl PreloadedJobActions {
    const fn ready(actions: BTreeMap<ActionCallPath, PreloadedActionOccurrence>) -> Self {
        Self {
            actions,
            main_suppressed: false,
        }
    }

    const fn failed(actions: BTreeMap<ActionCallPath, PreloadedActionOccurrence>) -> Self {
        Self::terminal(actions)
    }

    const fn terminal(actions: BTreeMap<ActionCallPath, PreloadedActionOccurrence>) -> Self {
        Self {
            actions,
            main_suppressed: true,
        }
    }
}

#[derive(Default)]
struct PreJobActionResult {
    outcome: Option<CommandOutcome>,
    lifecycle: JavascriptPrePostState,
    continue_on_error: bool,
}

#[derive(Clone, Copy, Default)]
struct JavascriptPrePostState {
    pre_completed: bool,
    post_registered: bool,
}

impl PreJobActionResult {
    const fn cancelled() -> Self {
        Self {
            outcome: Some(CommandOutcome::Cancelled),
            lifecycle: JavascriptPrePostState {
                pre_completed: true,
                post_registered: false,
            },
            continue_on_error: false,
        }
    }

    const fn skipped() -> Self {
        Self {
            outcome: None,
            lifecycle: JavascriptPrePostState {
                pre_completed: true,
                post_registered: false,
            },
            continue_on_error: false,
        }
    }
}

enum ActionLoadError {
    Preparation(ActionPreparationErrorKind),
    Executor(ExecutorAdapterError),
}

#[derive(Clone, Eq, PartialEq)]
struct ActionIdentity {
    runtime_step_id: String,
    reference: ActionReference,
    action_path: TargetPath,
}

impl ActionIdentity {
    fn new(runtime_step_id: String, reference: ActionReference, action_path: TargetPath) -> Self {
        Self {
            runtime_step_id,
            reference,
            action_path,
        }
    }

    fn with_runtime_step_id(&self, runtime_step_id: &str) -> Self {
        Self {
            runtime_step_id: runtime_step_id.to_owned(),
            reference: self.reference.clone(),
            action_path: self.action_path.clone(),
        }
    }

    fn environment(&self) -> Vec<(String, ResolvedEnvironmentValue)> {
        let mut values = vec![
            (
                "GITHUB_ACTION".to_owned(),
                ResolvedEnvironmentValue::plain(&self.runtime_step_id),
            ),
            (
                "GITHUB_ACTION_PATH".to_owned(),
                ResolvedEnvironmentValue::plain(self.action_path.as_str()),
            ),
        ];
        if let ActionReference::Repository {
            repository,
            revision,
            ..
        } = &self.reference
        {
            values.push((
                "GITHUB_ACTION_REPOSITORY".to_owned(),
                ResolvedEnvironmentValue::plain(repository),
            ));
            values.push((
                "GITHUB_ACTION_REF".to_owned(),
                ResolvedEnvironmentValue::plain(revision),
            ));
        }
        values
    }
}

struct ActionExecutionBudget {
    active: Vec<String>,
    invocations: u32,
    composite_steps: usize,
    next_phase: u32,
    next_action_slot: u32,
    derived_bytes: usize,
}

impl ActionExecutionBudget {
    const fn new() -> Self {
        Self {
            active: Vec::new(),
            invocations: 0,
            composite_steps: 0,
            next_phase: COMPOSITE_ORDINAL_BASE,
            next_action_slot: COMPOSITE_ORDINAL_BASE,
            derived_bytes: 0,
        }
    }

    fn enter(&mut self, key: String) -> bool {
        if action_budget_rejection(&self.active, self.invocations, &key).is_some() {
            return false;
        }
        self.invocations += 1;
        self.active.push(key);
        true
    }

    fn leave(&mut self) {
        let _ = self.active.pop();
    }

    fn composite_step(&mut self) -> Result<u32, ExecutorAdapterError> {
        let projected = self
            .composite_steps
            .checked_add(1)
            .ok_or_else(resource_exhausted)?;
        if composite_child_step_rejection(projected).is_some() {
            return Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::ResourceExhausted,
            ));
        }
        let value = u32::try_from(self.composite_steps).map_err(|_| invalid_job())?;
        self.composite_steps += 1;
        Ok(value)
    }

    fn phase(&mut self) -> Result<u32, ExecutorAdapterError> {
        let value = self.next_phase;
        self.next_phase = self.next_phase.checked_add(1).ok_or_else(invalid_job)?;
        if value > u32::MAX / 5 {
            return Err(invalid_job());
        }
        Ok(value)
    }

    fn action_slot(&mut self) -> Result<u32, ExecutorAdapterError> {
        let value = self.next_action_slot;
        self.next_action_slot = self
            .next_action_slot
            .checked_add(1)
            .ok_or_else(invalid_job)?;
        Ok(value)
    }

    fn charge_derived(&mut self, bytes: usize) -> Result<(), ExecutorAdapterError> {
        let projected = self
            .derived_bytes
            .checked_add(bytes)
            .ok_or_else(resource_exhausted)?;
        if composite_derived_bytes_rejection(projected).is_some() {
            return Err(resource_exhausted());
        }
        self.derived_bytes = projected;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActionBudgetRejection {
    NestingDepth,
    InvocationCount,
    CompositeChildSteps,
    CompositeDerivedBytes,
    EventDepth,
    Recursion,
}

fn action_budget_rejection(
    active: &[String],
    invocations: u32,
    key: &str,
) -> Option<ActionBudgetRejection> {
    if active.len() >= MAX_ACTION_NESTING_DEPTH {
        return Some(ActionBudgetRejection::NestingDepth);
    }
    let Some(projected) = invocations.checked_add(1) else {
        return Some(ActionBudgetRejection::InvocationCount);
    };
    if action_invocation_count_rejection(projected).is_some() {
        return Some(ActionBudgetRejection::InvocationCount);
    }
    if active.iter().any(|active| active == key) {
        return Some(ActionBudgetRejection::Recursion);
    }
    None
}

const fn action_invocation_count_rejection(projected: u32) -> Option<ActionBudgetRejection> {
    if projected > MAX_ACTION_INVOCATIONS {
        return Some(ActionBudgetRejection::InvocationCount); // stable invocation-limit reason
    }
    None
}

const fn composite_child_step_rejection(projected: usize) -> Option<ActionBudgetRejection> {
    if projected > MAX_COMPOSITE_CHILD_STEPS {
        return Some(ActionBudgetRejection::CompositeChildSteps);
    }
    None
}

const fn composite_derived_bytes_rejection(projected: usize) -> Option<ActionBudgetRejection> {
    if projected > MAX_COMPOSITE_DERIVED_BYTES {
        return Some(ActionBudgetRejection::CompositeDerivedBytes);
    }
    None
}

const fn event_depth_rejection(depth: usize) -> Option<ActionBudgetRejection> {
    if depth > MAX_EVENT_DEPTH {
        return Some(ActionBudgetRejection::EventDepth);
    }
    None
}

#[derive(Clone, Copy)]
struct ActionDeadline {
    deadline: Instant,
}

impl ActionDeadline {
    fn new(timeout: Duration) -> Self {
        Self {
            deadline: Instant::now()
                .checked_add(timeout)
                .unwrap_or_else(Instant::now),
        }
    }

    fn remaining(self) -> Option<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        (!remaining.is_zero()).then_some(remaining)
    }
}

#[derive(Clone, Eq, PartialEq)]
struct CompositeChildResult {
    id: Option<String>,
    runtime_step_id: String,
    outcome: JobConclusion,
    conclusion: JobConclusion,
}

impl CompositeChildResult {
    fn new(
        metadata: &crate::PreparedCompositeStepMetadata,
        runtime_step_id: String,
        outcome: JobConclusion,
        conclusion: JobConclusion,
    ) -> Self {
        Self {
            id: metadata.id().map(|id| id.as_str().to_owned()),
            runtime_step_id,
            outcome,
            conclusion,
        }
    }
}

#[derive(Clone)]
struct ActionExpressionContext<'a> {
    base: &'a dyn GithubEvaluationContext,
    named: BTreeMap<String, GithubValue>,
    status: GithubStatus,
}

#[derive(Clone)]
struct EnvironmentExpressionContext<'a> {
    base: &'a dyn GithubEvaluationContext,
    environment: GithubValue,
    status: GithubStatus,
}

impl fmt::Debug for EnvironmentExpressionContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvironmentExpressionContext")
            .field("environment", &"[REDACTED]")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl GithubEvaluationContext for EnvironmentExpressionContext<'_> {
    fn named_value(&self, name: &str) -> Option<GithubValue> {
        if name.eq_ignore_ascii_case("env") {
            Some(self.environment.clone())
        } else {
            self.base.named_value(name)
        }
    }

    fn status(&self) -> GithubStatus {
        self.status
    }

    fn functions(&self) -> &dyn GithubExpressionFunctionProvider {
        self.base.functions()
    }
}

enum DeferredPostContinue<'a> {
    Runtime {
        value: RuntimeBoolean,
        context: EnvironmentExpressionContext<'a>,
    },
    Composite {
        value: PreparedBoolean,
        context: ActionExpressionContext<'a>,
    },
}

struct ResolvedPostExecution<'a> {
    identity: ActionIdentity,
    action_environment: Vec<(String, ResolvedEnvironmentValue)>,
    input_environment: Vec<(String, ResolvedEnvironmentValue)>,
    timeout: Duration,
    continue_on_error: Vec<DeferredPostContinue<'a>>,
}

enum ResolvedPostTemplates<'a> {
    Skipped,
    Execute(Box<ResolvedPostExecution<'a>>),
}

impl fmt::Debug for ActionExpressionContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActionExpressionContext")
            .field("named_count", &self.named.len())
            .field("values", &"[REDACTED]")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl GithubEvaluationContext for ActionExpressionContext<'_> {
    fn named_value(&self, name: &str) -> Option<GithubValue> {
        self.named
            .get(&name.to_ascii_lowercase())
            .cloned()
            .or_else(|| self.base.named_value(name))
    }

    fn status(&self) -> GithubStatus {
        self.status
    }

    fn functions(&self) -> &dyn GithubExpressionFunctionProvider {
        self.base.functions()
    }
}

struct ObtainedSandbox {
    endpoint: Box<dyn ExecutionEndpoint>,
    services: ServiceContainerBindings,
}

struct MutableStepResult {
    step_id: automata_ci_core::StepId,
    outcome: JobConclusion,
    conclusion: JobConclusion,
    started_at: UnixMillis,
    completed_at: UnixMillis,
}

impl MutableStepResult {
    const fn new(
        step_id: automata_ci_core::StepId,
        outcome: JobConclusion,
        conclusion: JobConclusion,
        started_at: UnixMillis,
        completed_at: UnixMillis,
    ) -> Self {
        Self {
            step_id,
            outcome,
            conclusion,
            started_at,
            completed_at,
        }
    }

    fn snapshot(&self) -> GithubStepSnapshot {
        GithubStepSnapshot::new(self.step_id.as_str(), self.outcome, self.conclusion)
    }

    fn into_result(
        self,
        job_completed_at: UnixMillis,
        attachments: RetainedStepAttachments,
    ) -> StepResult {
        let result = StepResult::new(
            self.step_id,
            self.outcome,
            self.conclusion,
            self.started_at,
            self.completed_at.min(job_completed_at),
        )
        .with_annotations(attachments.annotations);
        if attachments.summary.is_empty() {
            result
        } else {
            result.with_summary_markdown(attachments.summary)
        }
    }
}

struct AttemptPaths {
    root: TargetPath,
    scripts: TargetPath,
    commands: TargetPath,
    actions: TargetPath,
    workspace: TargetPath,
    event: TargetPath,
}

impl AttemptPaths {
    fn new(
        root: &TargetPath,
        attempt_id: AttemptId,
        workspace: &TargetPath,
    ) -> Result<Self, ExecutorAdapterError> {
        let root = child(root, &format!("attempts/{attempt_id}"))?;
        Ok(Self {
            scripts: child(&root, "scripts")?,
            commands: child(&root, "commands")?,
            actions: child(&root, "actions")?,
            event: child(&root, "event.json")?,
            workspace: workspace.clone(),
            root,
        })
    }

    fn script(&self, index: u32, extension: &str) -> Result<TargetPath, ExecutorAdapterError> {
        child(&self.scripts, &format!("step-{index}{extension}"))
    }

    fn composite_script(
        &self,
        ordinal: u32,
        extension: &str,
    ) -> Result<TargetPath, ExecutorAdapterError> {
        child(&self.scripts, &format!("composite-{ordinal}{extension}"))
    }

    fn command_files(&self, phase: u32) -> Result<CommandFilePaths, ExecutorAdapterError> {
        let names = ["env", "output", "path", "state", "summary"];
        let values = COMMAND_FILE_KINDS
            .into_iter()
            .zip(names)
            .map(|(kind, name)| {
                child(&self.commands, &format!("phase-{phase}-{name}")).map(|path| (kind, path))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CommandFilePaths {
            values,
            artifacts: child(&self.commands, &format!("phase-{phase}-artifacts"))?,
            artifacts_list: child(&self.commands, &format!("phase-{phase}-artifacts-list"))?,
        })
    }

    fn action(&self, index: u32, subpath: &str) -> Result<ActionPaths, ExecutorAdapterError> {
        let base = child(&self.actions, &format!("action-{index}"))?;
        let extracted = child(&base, "root")?;
        let archive = child(&base, "bundle.tar.gz")?;
        let directory = if subpath.is_empty() {
            extracted.clone()
        } else {
            child(&extracted, subpath)?
        };
        Ok(ActionPaths {
            base,
            extracted,
            archive,
            directory,
        })
    }
}

#[derive(Clone)]
struct ActionPaths {
    base: TargetPath,
    extracted: TargetPath,
    archive: TargetPath,
    directory: TargetPath,
}

impl ActionPaths {
    fn local(directory: TargetPath) -> Self {
        Self {
            base: directory.clone(),
            extracted: directory.clone(),
            archive: directory.clone(),
            directory,
        }
    }

    fn entry(&self, entry: &str) -> Result<TargetPath, ExecutorAdapterError> {
        child(&self.directory, entry)
    }
}

struct CommandFilePaths {
    values: Vec<(CommandFileKind, TargetPath)>,
    artifacts: TargetPath,
    artifacts_list: TargetPath,
}

fn add_command_file_environment(
    environment: &automata_ci_execution::ExecutionEnvironment,
    paths: &CommandFilePaths,
) -> Result<automata_ci_execution::ExecutionEnvironment, ExecutorAdapterError> {
    let mut values = environment.values().to_vec();
    for (kind, path) in &paths.values {
        values.retain(|variable| match path.platform() {
            TargetPlatform::Posix => variable.name().as_str() != kind.environment_variable(),
            TargetPlatform::Windows => !variable
                .name()
                .as_str()
                .eq_ignore_ascii_case(kind.environment_variable()),
        });
        values.push(automata_ci_execution::EnvironmentVariable::new(
            automata_ci_execution::EnvironmentName::new(kind.environment_variable())
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?,
            automata_ci_execution::EnvironmentValue::new(path.as_str())
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?,
        ));
    }
    for (name, path) in [
        (
            CommandFileKind::Artifacts.environment_variable(),
            &paths.artifacts,
        ),
        (ARTIFACTS_LIST_ENVIRONMENT, &paths.artifacts_list),
    ] {
        values.retain(|variable| match path.platform() {
            TargetPlatform::Posix => variable.name().as_str() != name,
            TargetPlatform::Windows => !variable.name().as_str().eq_ignore_ascii_case(name),
        });
        values.push(automata_ci_execution::EnvironmentVariable::new(
            automata_ci_execution::EnvironmentName::new(name)
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?,
            automata_ci_execution::EnvironmentValue::new(path.as_str())
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?,
        ));
    }
    automata_ci_execution::ExecutionEnvironment::new(values)
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::ResourceExhausted))
}

fn action_extra_environment(
    inputs: &[(String, ResolvedEnvironmentValue)],
    paths: &ActionPaths,
    state: Vec<(String, ResolvedEnvironmentValue)>,
) -> Vec<(String, ResolvedEnvironmentValue)> {
    let mut values = inputs.to_vec();
    values.push((
        "GITHUB_ACTION_PATH".to_owned(),
        ResolvedEnvironmentValue::plain(paths.directory.as_str()),
    ));
    values.extend(state);
    values
}

fn action_reference_key(reference: &ActionReference) -> String {
    match reference {
        ActionReference::Repository {
            repository,
            revision,
            subpath,
        } => format!(
            "repository\0{repository}\0{revision}\0{}",
            subpath.as_deref().unwrap_or_default()
        ),
        ActionReference::Local { path } => format!("local\0{path}"),
        ActionReference::Container { image } => format!("container\0{image}"),
    }
}

fn action_phase(
    budget: &mut ActionExecutionBudget,
    top_level: bool,
    top_index: u32,
    phase: u32,
) -> Result<u32, ExecutorAdapterError> {
    if top_level {
        phase_ordinal(top_index, phase)
    } else {
        budget.phase()
    }
}

fn action_expression_context<'a>(
    base: &'a dyn GithubEvaluationContext,
    inputs: &[(String, ResolvedEnvironmentValue)],
    steps: Option<GithubValue>,
    identity: &ActionIdentity,
    environment: &[(String, ResolvedEnvironmentValue)],
    status: GithubStatus,
) -> Result<ActionExpressionContext<'a>, ExecutorAdapterError> {
    let inputs = github_object(
        inputs
            .iter()
            .map(|(name, value)| (name.clone(), value.github_value()))
            .collect(),
    )?;
    let steps = steps
        .or_else(|| base.named_value("steps"))
        .unwrap_or(github_object(Vec::new())?);
    let GithubValue::Object(github) = base.named_value("github").ok_or_else(invalid_job)? else {
        return Err(invalid_job());
    };
    let mut github = github.entries().to_vec();
    upsert_github_value(
        &mut github,
        "action",
        GithubValue::string(&identity.runtime_step_id),
    );
    upsert_github_value(
        &mut github,
        "action_path",
        GithubValue::string(identity.action_path.as_str()),
    );
    upsert_github_value(
        &mut github,
        "action_status",
        GithubValue::string(github_status_text(status)),
    );
    let (repository, revision) = match &identity.reference {
        ActionReference::Repository {
            repository,
            revision,
            ..
        } => (repository.as_str(), revision.as_str()),
        ActionReference::Local { .. } | ActionReference::Container { .. } => ("", ""),
    };
    upsert_github_value(
        &mut github,
        "action_repository",
        GithubValue::string(repository),
    );
    upsert_github_value(&mut github, "action_ref", GithubValue::string(revision));
    let github = github_object(github)?;
    let env = expression_environment_value(base, environment)?;
    Ok(ActionExpressionContext {
        base,
        named: BTreeMap::from([
            ("env".to_owned(), env),
            ("github".to_owned(), github),
            ("inputs".to_owned(), inputs),
            ("steps".to_owned(), steps),
        ]),
        status,
    })
}

fn action_lifecycle_context<'a>(
    base: &'a dyn GithubEvaluationContext,
    identity: &ActionIdentity,
    environment: &[(String, ResolvedEnvironmentValue)],
    status: GithubStatus,
) -> Result<ActionExpressionContext<'a>, ExecutorAdapterError> {
    let mut context = action_expression_context(base, &[], None, identity, environment, status)?;
    if let Some(inputs) = base.named_value("inputs") {
        context.named.insert("inputs".to_owned(), inputs);
    }
    Ok(context)
}

fn environment_expression_context<'a>(
    base: &'a dyn GithubEvaluationContext,
    environment: &[(String, ResolvedEnvironmentValue)],
    status: GithubStatus,
) -> Result<EnvironmentExpressionContext<'a>, ExecutorAdapterError> {
    Ok(EnvironmentExpressionContext {
        base,
        environment: expression_environment_value(base, environment)?,
        status,
    })
}

fn expression_environment_value(
    base: &dyn GithubEvaluationContext,
    environment: &[(String, ResolvedEnvironmentValue)],
) -> Result<GithubValue, ExecutorAdapterError> {
    let mut values = match base.named_value("env") {
        Some(GithubValue::Object(value)) => value.entries().to_vec(),
        Some(_) | None => Vec::new(),
    };
    for (name, value) in environment {
        upsert_github_value(&mut values, name, value.github_value());
    }
    github_object(values)
}

fn upsert_github_value(values: &mut Vec<(String, GithubValue)>, name: &str, value: GithubValue) {
    if let Some((_, existing)) = values
        .iter_mut()
        .find(|(existing, _)| existing.eq_ignore_ascii_case(name))
    {
        *existing = value;
    } else {
        values.push((name.to_owned(), value));
    }
}

fn github_object(values: Vec<(String, GithubValue)>) -> Result<GithubValue, ExecutorAdapterError> {
    GithubObject::new(values)
        .map(GithubValue::object)
        .map_err(|_| resource_exhausted())
}

fn composite_steps_value(
    records: &[CompositeChildResult],
    commands: &JobCommandState,
) -> Result<GithubValue, ExecutorAdapterError> {
    let mut values = Vec::new();
    for record in records {
        let Some(id) = &record.id else {
            continue;
        };
        let runtime_id = RuntimeStepId::new(&record.runtime_step_id).map_err(|_| invalid_job())?;
        let outputs = commands.outputs(&runtime_id).map_or_else(
            || github_object(Vec::new()),
            |outputs| {
                github_object(
                    outputs
                        .iter()
                        .map(|output| {
                            (
                                output.name().to_owned(),
                                GithubValue::string(output.value()),
                            )
                        })
                        .collect(),
                )
            },
        )?;
        values.push((
            id.clone(),
            github_object(vec![
                (
                    "outcome".to_owned(),
                    GithubValue::string(conclusion_text(record.outcome)),
                ),
                (
                    "conclusion".to_owned(),
                    GithubValue::string(conclusion_text(record.conclusion)),
                ),
                ("outputs".to_owned(), outputs),
            ])?,
        ));
    }
    github_object(values)
}

fn local_action_directory(
    workspace: &TargetPath,
    path: &str,
) -> Result<TargetPath, ExecutorAdapterError> {
    child(workspace, path.trim_start_matches("./"))
}

fn composite_working_directory(
    workspace: &TargetPath,
    action_path: &TargetPath,
    requested: Option<&str>,
) -> Result<TargetPath, ExecutorAdapterError> {
    let Some(requested) = requested else {
        return Ok(workspace.clone());
    };
    if requested.is_empty() || requested.contains('\\') || requested.contains('\0') {
        return Err(invalid_job());
    }
    let path = if requested.starts_with('/') {
        TargetPath::posix(requested)
    } else {
        if requested
            .split('/')
            .any(|component| component.is_empty() || component == "..")
        {
            return Err(invalid_job());
        }
        let requested = requested
            .split('/')
            .filter(|component| *component != ".")
            .collect::<Vec<_>>()
            .join("/");
        if requested.is_empty() {
            return Ok(workspace.clone());
        }
        TargetPath::posix(format!(
            "{}/{requested}",
            workspace.as_str().trim_end_matches('/')
        ))
    }
    .map_err(|_| invalid_job())?;
    if !path_contained_by(&path, workspace) && !path_contained_by(&path, action_path) {
        return Err(invalid_job());
    }
    Ok(path)
}

fn path_contained_by(path: &TargetPath, root: &TargetPath) -> bool {
    if path.platform() != root.platform() {
        return false;
    }
    match path.platform() {
        TargetPlatform::Posix => {
            path == root
                || path
                    .as_str()
                    .strip_prefix(root.as_str().trim_end_matches('/'))
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }
        TargetPlatform::Windows => {
            let root = root.as_str().trim_end_matches('\\');
            let path = path.as_str();
            path.eq_ignore_ascii_case(root)
                || path.get(..root.len()).is_some_and(|prefix| {
                    prefix.eq_ignore_ascii_case(root)
                        && path
                            .get(root.len()..)
                            .is_some_and(|suffix| suffix.starts_with('\\'))
                })
        }
    }
}

fn composite_runtime_step_id(call_path: &ActionCallPath) -> String {
    let suffix = call_path
        .0
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join("_");
    format!("__automata_composite_{suffix}")
}

fn composite_operation_ordinal(ordinal: u32) -> Result<u32, ExecutorAdapterError> {
    COMPOSITE_ORDINAL_BASE
        .checked_add(ordinal)
        .ok_or_else(invalid_job)
}

fn encode_action_outputs(values: &[(String, String)]) -> Result<Vec<u8>, ExecutorAdapterError> {
    let mut encoded = Vec::new();
    for (name, value) in values {
        if !value.contains('\n') && !value.contains('\r') {
            encoded.extend_from_slice(name.as_bytes());
            encoded.push(b'=');
            encoded.extend_from_slice(value.as_bytes());
            encoded.push(b'\n');
            if encoded.len() > automata_ci_execution::MAX_COPY_BYTES {
                return Err(resource_exhausted());
            }
            continue;
        }
        let delimiter = loop {
            let candidate = format!("automata_output_{}", uuid::Uuid::new_v4().simple());
            if !value.lines().any(|line| line == candidate) {
                break candidate;
            }
        };
        encoded.extend_from_slice(name.as_bytes());
        encoded.extend_from_slice(b"<<");
        encoded.extend_from_slice(delimiter.as_bytes());
        encoded.push(b'\n');
        encoded.extend_from_slice(value.as_bytes());
        if !value.ends_with('\n') {
            encoded.push(b'\n');
        }
        encoded.extend_from_slice(delimiter.as_bytes());
        encoded.push(b'\n');
        if encoded.len() > automata_ci_execution::MAX_COPY_BYTES {
            return Err(resource_exhausted());
        }
    }
    Ok(encoded)
}

const fn github_status_text(status: GithubStatus) -> &'static str {
    match status {
        GithubStatus::Success => "success",
        GithubStatus::Failure => "failure",
        GithubStatus::Cancelled => "cancelled",
        GithubStatus::Skipped => "skipped",
    }
}

const fn conclusion_text(conclusion: JobConclusion) -> &'static str {
    match conclusion {
        JobConclusion::Success => "success",
        JobConclusion::Failure => "failure",
        JobConclusion::Cancelled => "cancelled",
        JobConclusion::TimedOut => "timed_out",
        JobConclusion::Skipped => "skipped",
    }
}

fn validate_action_step_admission(
    job: &JobIrEnvelope,
    workspace: &TargetPath,
) -> Result<(), AdmissionRejection> {
    for step in job.job().steps() {
        match step.kind() {
            SemanticStep::Action { .. } if workspace.platform() == TargetPlatform::Windows => {
                return Err(AdmissionRejection::InvalidJob);
            }
            SemanticStep::Action {
                reference: ActionReference::Repository { .. },
                ..
            }
            | SemanticStep::Run { .. } => {}
            SemanticStep::Action { reference, .. }
                if matches!(reference, ActionReference::Local { .. }) =>
            {
                CheckedOutLocalActionPreparer::definition_paths(workspace, reference)
                    .map_err(|_| AdmissionRejection::InvalidJob)?;
            }
            SemanticStep::Action { .. } => return Err(AdmissionRejection::InvalidJob),
        }
    }
    Ok(())
}

fn validate_resource_admission(
    job: &JobIrEnvelope,
    capabilities: &ProviderCapabilities,
) -> Result<(), AdmissionRejection> {
    let allocation = job
        .job()
        .requirements()
        .resource_allocation()
        .ok_or(AdmissionRejection::InvalidJob)?;
    if !capabilities.supports(SandboxCapability::ResourceLimits)
        || !capabilities.supports(SandboxCapability::ProcessLimits)
    {
        return Err(AdmissionRejection::CapabilityChanged);
    }
    let limits = allocation.limits();
    if limits.ephemeral_disk_bytes() > 0
        && !capabilities.supports(SandboxCapability::EphemeralStorageLimits)
    {
        return Err(AdmissionRejection::CapabilityChanged);
    }
    if limits.gpu_count() > 0 && !capabilities.supports(SandboxCapability::DeviceLimits) {
        return Err(AdmissionRejection::CapabilityChanged);
    }
    Ok(())
}

fn tool_path(path: &TargetPath, platform: TargetPlatform) -> bool {
    path.platform() == platform
        && match platform {
            TargetPlatform::Posix => path.as_str() != "/",
            TargetPlatform::Windows => path.as_str().len() > 3,
        }
}

fn valid_toolchain(toolchain: &dyn GithubToolchain) -> bool {
    let platform = toolchain.platform();
    let configured_paths_valid = [
        toolchain.bash(),
        toolchain.sh(),
        toolchain.python(),
        toolchain.pwsh(),
        toolchain.powershell(),
        toolchain.cmd(),
        toolchain.install(),
        toolchain.tar(),
        toolchain.sha256().map(ExecutionArgv::program),
    ]
    .into_iter()
    .flatten()
    .all(|path| tool_path(path, platform));
    configured_paths_valid
        && match platform {
            TargetPlatform::Posix => {
                toolchain.bash().is_some()
                    && toolchain.sh().is_some()
                    && toolchain.install().is_some()
                    && toolchain.tar().is_some()
                    && toolchain.sha256().is_some()
                    && toolchain.powershell().is_none()
                    && toolchain.cmd().is_none()
            }
            TargetPlatform::Windows => {
                toolchain.bash().is_none()
                    && toolchain.sh().is_none()
                    && toolchain.pwsh().is_some()
                    && toolchain.powershell().is_some()
                    && toolchain.cmd().is_some()
                    && toolchain.install().is_none()
                    && toolchain.tar().is_none()
                    && toolchain.sha256().is_none()
            }
        }
}

fn required_tool(path: Option<&TargetPath>) -> Result<TargetPath, ExecutorAdapterError> {
    path.cloned()
        .ok_or_else(|| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Unsupported))
}

fn artifact_hash_invocation(
    toolchain: &dyn GithubToolchain,
    platform: TargetPlatform,
    launch_environment: &automata_ci_execution::ExecutionEnvironment,
    declared_path: &str,
) -> Result<(ExecutionArgv, automata_ci_execution::ExecutionEnvironment), ExecutorAdapterError> {
    match platform {
        TargetPlatform::Posix => {
            let sh = required_tool(toolchain.sh())?;
            let sha256 = toolchain
                .sha256()
                .ok_or_else(|| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Unsupported))?;
            let mut arguments = Vec::with_capacity(4 + sha256.arguments().len());
            arguments.extend([
                "-c".to_owned(),
                ARTIFACT_HASH_SCRIPT.to_owned(),
                sha256.program().as_str().to_owned(),
                declared_path.to_owned(),
            ]);
            arguments.extend(sha256.arguments().iter().cloned());
            let argv = ExecutionArgv::new(sh, arguments).map_err(|_| invalid_job())?;
            Ok((argv, automata_ci_execution::ExecutionEnvironment::empty()))
        }
        TargetPlatform::Windows => {
            windows_artifact_hash_invocation(toolchain, launch_environment, declared_path)
        }
    }
}

fn windows_artifact_hash_invocation(
    toolchain: &dyn GithubToolchain,
    launch_environment: &automata_ci_execution::ExecutionEnvironment,
    declared_path: &str,
) -> Result<(ExecutionArgv, automata_ci_execution::ExecutionEnvironment), ExecutorAdapterError> {
    const LAUNCH_VARIABLES: [&str; 7] = [
        "SystemRoot",
        "WINDIR",
        "ComSpec",
        "TEMP",
        "TMP",
        "PATHEXT",
        "PSModulePath",
    ];
    let pwsh = required_tool(toolchain.pwsh())?;
    let argv = ExecutionArgv::new(
        pwsh,
        vec![
            "-NoLogo".to_owned(),
            "-NoProfile".to_owned(),
            "-NonInteractive".to_owned(),
            "-Command".to_owned(),
            WINDOWS_ARTIFACT_HASH_SCRIPT.to_owned(),
        ],
    )
    .map_err(|_| invalid_job())?;
    let mut values = launch_environment
        .values()
        .iter()
        .filter(|variable| {
            LAUNCH_VARIABLES
                .iter()
                .any(|name| variable.name().as_str().eq_ignore_ascii_case(name))
        })
        .cloned()
        .collect::<Vec<_>>();
    values.push(automata_ci_execution::EnvironmentVariable::new(
        automata_ci_execution::EnvironmentName::new(WINDOWS_ARTIFACT_PATH_ENVIRONMENT)
            .map_err(|_| invalid_job())?,
        automata_ci_execution::EnvironmentValue::new(declared_path).map_err(|_| invalid_job())?,
    ));
    let environment = automata_ci_execution::ExecutionEnvironment::new(values)
        .map_err(|_| resource_exhausted())?;
    Ok((argv, environment))
}

fn windows_directory_creation_script<'path>(
    paths: impl IntoIterator<Item = &'path TargetPath>,
) -> String {
    let mut command = "$ErrorActionPreference = 'Stop';".to_owned();
    for path in paths {
        let path = path.as_str().replace('\'', "''");
        command.push_str(" [System.IO.Directory]::CreateDirectory('");
        command.push_str(&path);
        command.push_str("') | Out-Null;");
    }
    command
}

const fn command_file_platform(platform: TargetPlatform) -> CommandFilePlatform {
    match platform {
        TargetPlatform::Posix => CommandFilePlatform::Unix,
        TargetPlatform::Windows => CommandFilePlatform::Windows,
    }
}

fn artifact_file_name(path: &str) -> Result<String, ExecutorAdapterError> {
    std::path::Path::new(path)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .ok_or_else(invalid_job)
}

fn observe_phase_failure(
    error: ExecutorAdapterError,
    attempt_id: AttemptId,
    phase: u32,
    failure_stage: &'static str,
) -> ExecutorAdapterError {
    tracing::warn!(
        attempt_id = %attempt_id,
        phase,
        failure_stage,
        error_kind = ?error.kind(),
        "GitHub job phase failed"
    );
    error
}

const fn map_phase_application_error(error: &PhaseApplicationError) -> ExecutorAdapterError {
    match error {
        PhaseApplicationError::ArtifactConflict => invalid_job(),
        PhaseApplicationError::TooManyEnvironmentEntries { .. }
        | PhaseApplicationError::TooManyPathEntries { .. }
        | PhaseApplicationError::TooManySteps { .. }
        | PhaseApplicationError::TooManyActionStates { .. }
        | PhaseApplicationError::TooManyArtifactSubjects { .. }
        | PhaseApplicationError::ArtifactListTooLarge { .. }
        | PhaseApplicationError::AggregateTooLarge { .. } => resource_exhausted(),
    }
}

fn phase_ordinal(step: u32, phase: u32) -> Result<u32, ExecutorAdapterError> {
    step.checked_mul(4)
        .and_then(|value| value.checked_add(phase))
        .ok_or_else(|| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))
}

fn child(parent: &TargetPath, child: &str) -> Result<TargetPath, ExecutorAdapterError> {
    let path = match parent.platform() {
        TargetPlatform::Posix => {
            TargetPath::posix(format!("{}/{child}", parent.as_str().trim_end_matches('/')))
        }
        TargetPlatform::Windows => {
            let child = normalize_windows_relative_path(child)?;
            TargetPath::windows(format!(
                "{}\\{child}",
                parent.as_str().trim_end_matches('\\')
            ))
        }
    };
    path.map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))
}

fn normalize_windows_relative_path(path: &str) -> Result<String, ExecutorAdapterError> {
    if path.is_empty()
        || path.starts_with(['/', '\\'])
        || path.ends_with(['/', '\\'])
        || path.contains(':')
    {
        return Err(invalid_job());
    }
    let components = path.split(['/', '\\']).collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| component.is_empty() || matches!(*component, "." | ".."))
    {
        return Err(invalid_job());
    }
    Ok(components.join("\\"))
}

fn event_path(
    runner_root: &TargetPath,
    attempt_id: AttemptId,
) -> Result<TargetPath, ExecutorAdapterError> {
    child(runner_root, &format!("attempts/{attempt_id}/event.json"))
}

fn job_workspace(
    job: &JobIrEnvelope,
    environment: &automata_ci_execution::SandboxEnvironment,
) -> Result<TargetPath, ExecutorAdapterError> {
    const LOGICAL_WORKSPACE_ROOT: &str = "/__w";
    let logical_workspace = TargetPath::posix(job.execution().workspace())
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
    match (environment.workspace().platform(), environment.launch()) {
        (TargetPlatform::Posix, SandboxLaunch::Container { .. }) => {
            let root = environment.workspace().as_str().trim_end_matches('/');
            let prefix = format!("{root}/");
            if logical_workspace.as_str() == root
                || !logical_workspace.as_str().starts_with(&prefix)
            {
                return Err(invalid_job());
            }
            Ok(logical_workspace)
        }
        (TargetPlatform::Posix, SandboxLaunch::VirtualMachine { .. })
        | (TargetPlatform::Windows, SandboxLaunch::WindowsHyperVContainer { .. }) => {
            let relative = logical_workspace
                .as_str()
                .strip_prefix(LOGICAL_WORKSPACE_ROOT)
                .and_then(|path| path.strip_prefix('/'))
                .ok_or_else(invalid_job)?;
            child(environment.workspace(), relative)
        }
        (
            TargetPlatform::Windows,
            SandboxLaunch::Container { .. } | SandboxLaunch::VirtualMachine { .. },
        )
        | (TargetPlatform::Posix, SandboxLaunch::WindowsHyperVContainer { .. }) => {
            Err(invalid_job())
        }
    }
}

fn working_directory_path(
    workspace: &TargetPath,
    requested: Option<&str>,
) -> Result<TargetPath, ExecutorAdapterError> {
    let Some(requested) = requested else {
        return Ok(workspace.clone());
    };
    let path = match workspace.platform() {
        TargetPlatform::Posix if requested.starts_with('/') => {
            TargetPath::posix(requested).map_err(|_| invalid_job())
        }
        TargetPlatform::Posix => {
            let requested = requested
                .split('/')
                .filter(|component| *component != ".")
                .collect::<Vec<_>>()
                .join("/");
            if requested.is_empty() {
                return Ok(workspace.clone());
            }
            TargetPath::posix(format!(
                "{}/{requested}",
                workspace.as_str().trim_end_matches('/')
            ))
            .map_err(|_| invalid_job())
        }
        TargetPlatform::Windows if requested.as_bytes().get(1).copied() == Some(b':') => {
            TargetPath::windows(requested.replace('/', "\\")).map_err(|_| invalid_job())
        }
        TargetPlatform::Windows => {
            let requested = requested
                .split(['/', '\\'])
                .filter(|component| *component != ".")
                .collect::<Vec<_>>()
                .join("\\");
            if requested.is_empty() {
                return Ok(workspace.clone());
            }
            child(workspace, &requested)
        }
    }?;
    if !path_contained_by(&path, workspace) {
        return Err(invalid_job());
    }
    Ok(path)
}

fn deadline(started_at: UnixMillis, seconds: u32) -> Option<UnixMillis> {
    started_at
        .get()
        .checked_add(i64::from(seconds).checked_mul(1_000)?)
        .map(UnixMillis::new)
}

const fn map_continue(outcome: JobConclusion, continue_on_error: bool) -> JobConclusion {
    if continue_on_error && matches!(outcome, JobConclusion::Failure | JobConclusion::TimedOut) {
        JobConclusion::Success
    } else {
        outcome
    }
}

const fn status_for(conclusion: JobConclusion) -> GithubStatus {
    match conclusion {
        JobConclusion::Success | JobConclusion::Skipped => GithubStatus::Success,
        JobConclusion::Failure | JobConclusion::TimedOut => GithubStatus::Failure,
        JobConclusion::Cancelled => GithubStatus::Cancelled,
    }
}

const fn command_outcome(conclusion: JobConclusion) -> CommandOutcome {
    match conclusion {
        JobConclusion::Success | JobConclusion::Skipped => CommandOutcome::Success,
        JobConclusion::Failure => CommandOutcome::Failure,
        JobConclusion::TimedOut => CommandOutcome::TimedOut,
        JobConclusion::Cancelled => CommandOutcome::Cancelled,
    }
}

const fn invalid_job() -> ExecutorAdapterError {
    ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob)
}

const fn resource_exhausted() -> ExecutorAdapterError {
    ExecutorAdapterError::new(ExecutorAdapterErrorKind::ResourceExhausted)
}

const fn cancelled() -> ExecutorAdapterError {
    ExecutorAdapterError::new(ExecutorAdapterErrorKind::Cancelled)
}

fn map_runtime_context_decode_error(error: &DecodeError) -> ExecutorAdapterError {
    match error {
        DecodeError::FrameTooLarge { .. } | DecodeError::CollectionTooLarge { .. } => {
            resource_exhausted()
        }
        _ => invalid_job(),
    }
}

fn map_job_result_validation_error(error: &JobResultValidationError) -> ExecutorAdapterError {
    match error {
        JobResultValidationError::OutputValueTooLarge { .. }
        | JobResultValidationError::OutputValuesTooLarge { .. }
        | JobResultValidationError::TooManyOutputs { .. }
        | JobResultValidationError::StepAttachmentTextTooLarge { .. }
        | JobResultValidationError::StepAttachmentsTooLarge { .. }
        | JobResultValidationError::TooManyStepAnnotations { .. }
        | JobResultValidationError::TooManyStepAnnotationProperties { .. } => resource_exhausted(),
        JobResultValidationError::InvalidOutputName
        | JobResultValidationError::EmptyPublicOutputValue
        | JobResultValidationError::MissingPublicOutputValue
        | JobResultValidationError::SecretDerivedOutputCarriesValue => invalid_job(),
        JobResultValidationError::UnsupportedSchema { .. }
        | JobResultValidationError::StepCompletedBeforeStart(_)
        | JobResultValidationError::StepCompletedAfterJob(_)
        | JobResultValidationError::DuplicateStepId(_)
        | JobResultValidationError::InvalidStepAnnotationProperty => {
            ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal)
        }
    }
}

fn github_value_from_json(
    value: &serde_json::Value,
    depth: usize,
) -> Result<GithubValue, ExecutorAdapterError> {
    if event_depth_rejection(depth).is_some() {
        return Err(ExecutorAdapterError::new(
            ExecutorAdapterErrorKind::InvalidJob,
        ));
    }
    match value {
        serde_json::Value::Null => Ok(GithubValue::Null),
        serde_json::Value::Bool(value) => Ok(GithubValue::Boolean(*value)),
        serde_json::Value::Number(value) => value
            .as_f64()
            .map(GithubValue::number)
            .ok_or_else(|| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob)),
        serde_json::Value::String(value) => Ok(GithubValue::string(value)),
        serde_json::Value::Array(values) => values
            .iter()
            .map(|value| github_value_from_json(value, depth + 1))
            .collect::<Result<Vec<_>, _>>()
            .and_then(|values| {
                GithubValue::array(values)
                    .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))
            }),
        serde_json::Value::Object(values) => values
            .iter()
            .map(|(name, value)| {
                github_value_from_json(value, depth + 1).map(|value| (name.clone(), value))
            })
            .collect::<Result<Vec<_>, _>>()
            .and_then(|values| {
                GithubObject::new(values)
                    .map(GithubValue::object)
                    .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))
            }),
    }
}

fn require_success(output: &ExecutionOutput) -> Result<(), ExecutorAdapterError> {
    match output.termination() {
        ExecutionTermination::Exited(0) if !output.was_truncated() => Ok(()),
        ExecutionTermination::TimedOut => Err(ExecutorAdapterError::new(
            ExecutorAdapterErrorKind::TimedOut,
        )),
        ExecutionTermination::Cancelled => Err(ExecutorAdapterError::new(
            ExecutorAdapterErrorKind::Cancelled,
        )),
        ExecutionTermination::Exited(_) | ExecutionTermination::Signalled
            if output.was_truncated() =>
        {
            Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::ResourceExhausted,
            ))
        }
        ExecutionTermination::Exited(_) | ExecutionTermination::Signalled => Err(
            ExecutorAdapterError::new(ExecutorAdapterErrorKind::Unavailable),
        ),
    }
}

fn journal_identity(handle: &SandboxHandle) -> Result<SandboxIdentity, ExecutorAdapterError> {
    let provider = ProviderName::new(handle.provider().as_str())
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
    let handle = JournalSandboxHandle::new(handle.opaque())
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
    Ok(SandboxIdentity::new(provider, handle))
}

fn map_port_error(kind: PortErrorKind) -> ExecutorAdapterError {
    let kind = match kind {
        PortErrorKind::NotFound | PortErrorKind::InvalidData => {
            ExecutorAdapterErrorKind::InvalidJob
        }
        PortErrorKind::PermissionDenied => ExecutorAdapterErrorKind::PermissionDenied,
        PortErrorKind::Unavailable => ExecutorAdapterErrorKind::Unavailable,
        PortErrorKind::ResourceExhausted => ExecutorAdapterErrorKind::ResourceExhausted,
        PortErrorKind::Unsupported => ExecutorAdapterErrorKind::Unsupported,
        PortErrorKind::Internal => ExecutorAdapterErrorKind::Internal,
    };
    ExecutorAdapterError::new(kind)
}

const fn map_executor_error(error: ExecutorError) -> ExecutorAdapterError {
    let kind = match error.kind() {
        ExecutorErrorKind::InvalidJob => ExecutorAdapterErrorKind::InvalidJob,
        ExecutorErrorKind::Unsupported => ExecutorAdapterErrorKind::Unsupported,
        ExecutorErrorKind::ResourceExhausted => ExecutorAdapterErrorKind::ResourceExhausted,
        ExecutorErrorKind::PermissionDenied => ExecutorAdapterErrorKind::PermissionDenied,
        ExecutorErrorKind::Unavailable => ExecutorAdapterErrorKind::Unavailable,
        ExecutorErrorKind::TimedOut => ExecutorAdapterErrorKind::TimedOut,
        ExecutorErrorKind::Cancelled => ExecutorAdapterErrorKind::Cancelled,
        ExecutorErrorKind::Internal => ExecutorAdapterErrorKind::Internal,
    };
    ExecutorAdapterError::new(kind)
}

fn map_provider_error(error: &ProviderError) -> ExecutorAdapterError {
    let kind = match error.kind() {
        ProviderErrorKind::UnsupportedPlatform | ProviderErrorKind::UnsupportedCapability => {
            ExecutorAdapterErrorKind::Unsupported
        }
        ProviderErrorKind::Cancelled => ExecutorAdapterErrorKind::Cancelled,
        ProviderErrorKind::TimedOut => ExecutorAdapterErrorKind::TimedOut,
        ProviderErrorKind::AdapterUnavailable | ProviderErrorKind::LocalStorage => {
            ExecutorAdapterErrorKind::Unavailable
        }
        ProviderErrorKind::InvalidConfiguration
        | ProviderErrorKind::NotFound
        | ProviderErrorKind::Conflict
        | ProviderErrorKind::OwnershipMismatch
        | ProviderErrorKind::InvalidState
        | ProviderErrorKind::BackendRejected => ExecutorAdapterErrorKind::Internal,
        ProviderErrorKind::OutputLimitExceeded => ExecutorAdapterErrorKind::ResourceExhausted,
    };
    ExecutorAdapterError::new(kind)
}

fn map_execution_error(error: ExecutionError) -> ExecutorAdapterError {
    let kind = match error.kind() {
        ExecutionErrorKind::UnsupportedCapability => ExecutorAdapterErrorKind::Unsupported,
        ExecutionErrorKind::InvalidEnvironment => ExecutorAdapterErrorKind::InvalidJob,
        ExecutionErrorKind::Cancelled => ExecutorAdapterErrorKind::Cancelled,
        ExecutionErrorKind::TimedOut => ExecutorAdapterErrorKind::TimedOut,
        ExecutionErrorKind::OutputLimitExceeded => ExecutorAdapterErrorKind::ResourceExhausted,
        ExecutionErrorKind::NotFound
        | ExecutionErrorKind::OwnershipMismatch
        | ExecutionErrorKind::InvalidState
        | ExecutionErrorKind::BackendRejected
        | ExecutionErrorKind::LocalStorage => ExecutorAdapterErrorKind::Unavailable,
    };
    ExecutorAdapterError::new(kind)
}

fn provider_failure_outcome(error: &ProviderError) -> ProviderFailureOutcome {
    let kind = match error.kind() {
        ProviderErrorKind::InvalidConfiguration => ProviderFailureKind::InvalidRequest,
        ProviderErrorKind::UnsupportedPlatform | ProviderErrorKind::UnsupportedCapability => {
            ProviderFailureKind::Unsupported
        }
        ProviderErrorKind::OutputLimitExceeded => ProviderFailureKind::ResourceExhausted,
        ProviderErrorKind::NotFound => ProviderFailureKind::NotFound,
        ProviderErrorKind::Conflict | ProviderErrorKind::OwnershipMismatch => {
            ProviderFailureKind::Conflict
        }
        ProviderErrorKind::TimedOut => ProviderFailureKind::TimedOut,
        ProviderErrorKind::AdapterUnavailable | ProviderErrorKind::LocalStorage => {
            ProviderFailureKind::Unavailable
        }
        ProviderErrorKind::Cancelled
        | ProviderErrorKind::InvalidState
        | ProviderErrorKind::BackendRejected => ProviderFailureKind::Internal,
    };
    match error.outcome() {
        automata_ci_execution::OperationOutcome::KnownNoEffect => {
            ProviderFailureOutcome::KnownNoEffect(kind)
        }
        automata_ci_execution::OperationOutcome::Uncertain => {
            ProviderFailureOutcome::Uncertain(kind)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        collections::BTreeSet,
        time::{Duration, Instant},
    };

    use automata_ci_core::AttemptId;
    use automata_ci_execution::{
        Cancellation, CancellationDisposition, ExecutionOutputRecord, ExecutionOutputStream,
        TargetPath,
    };
    use automata_ci_expression_github::GithubValue;
    use automata_ci_github_runtime::{
        CommandFileDecoder, CommandFileKind, CommandFilePlatform, GithubCommandFileDecoder,
        ParsedCommandFile, WorkflowCommandLimits, WorkflowCommandPolicy,
    };
    use automata_ci_runner_runtime::{ExecutionCancellation, ExecutionCancellationReason};

    use super::{
        ActionBudgetRejection, ActionExecutionBudget, AttemptPaths, CleanupCancellation,
        ExecutorAdapterErrorKind, GithubStatus, JobConclusion, MAX_ACTION_INVOCATIONS,
        MAX_ACTION_NESTING_DEPTH, MAX_COMPOSITE_CHILD_STEPS, MAX_COMPOSITE_DERIVED_BYTES,
        MAX_EVENT_DEPTH, ProviderCancellationBridge, SecretMasker,
        action_invocation_count_rejection, composite_child_step_rejection,
        composite_derived_bytes_rejection, encode_action_outputs, event_depth_rejection,
        github_value_from_json, parse_output_with_cancellation, reconcile_cancelled_operation,
        reconcile_post_operation, resource_exhausted,
    };

    #[test]
    fn shutdown_authorizes_endpoint_and_provider_termination_handling() {
        let cancellation = ExecutionCancellation::new();
        assert_eq!(
            ProviderCancellationBridge(&cancellation).disposition(),
            CancellationDisposition::Active
        );

        cancellation.signal(ExecutionCancellationReason::Shutdown);

        assert_eq!(
            ProviderCancellationBridge(&cancellation).disposition(),
            CancellationDisposition::Terminate
        );
    }

    #[test]
    fn command_file_paths_are_stable_for_recovery_and_isolated_by_phase_and_attempt() {
        let runner_root = TargetPath::posix("/__automata").expect("runner root");
        let workspace = TargetPath::posix("/__w/automata/automata").expect("workspace");
        let attempt_id = AttemptId::new();
        let first = AttemptPaths::new(&runner_root, attempt_id, &workspace).expect("attempt paths");
        let recovered =
            AttemptPaths::new(&runner_root, attempt_id, &workspace).expect("recovered paths");
        let next_attempt = AttemptPaths::new(&runner_root, AttemptId::new(), &workspace)
            .expect("next attempt paths");

        let first_phase = phase_file_path_values(&first, 7);
        let recovered_phase = phase_file_path_values(&recovered, 7);
        let next_phase = phase_file_path_values(&first, 8);
        let next_attempt_phase = phase_file_path_values(&next_attempt, 7);

        assert_eq!(first_phase, recovered_phase);
        assert_eq!(first_phase.iter().collect::<BTreeSet<_>>().len(), 7);
        assert!(first_phase.iter().all(|path| !next_phase.contains(path)));
        assert!(
            first_phase
                .iter()
                .all(|path| !next_attempt_phase.contains(path))
        );
    }

    fn phase_file_path_values(paths: &AttemptPaths, phase: u32) -> Vec<String> {
        let files = paths.command_files(phase).expect("command file paths");
        let mut values = files
            .values
            .iter()
            .map(|(_, path)| path.as_str().to_owned())
            .collect::<Vec<_>>();
        values.push(files.artifacts.as_str().to_owned());
        values.push(files.artifacts_list.as_str().to_owned());
        values
    }

    #[test]
    fn event_json_conversion_preserves_nested_types() {
        let document = serde_json::json!({
            "action": "opened",
            "installation": { "id": 42 },
            "requested": true,
            "labels": ["ci", null]
        });

        let GithubValue::Object(event) =
            github_value_from_json(&document, 0).expect("valid event payload")
        else {
            panic!("event payload must remain an object");
        };
        assert_eq!(
            event.get("action").and_then(GithubValue::as_str),
            Some("opened")
        );
        assert_eq!(
            event.get("requested").and_then(GithubValue::as_bool),
            Some(true)
        );
        let GithubValue::Object(installation) =
            event.get("installation").expect("installation payload")
        else {
            panic!("installation payload must remain an object");
        };
        assert_eq!(
            installation.get("id").and_then(GithubValue::as_number),
            Some(42.0)
        );
    }

    #[test]
    fn event_json_conversion_rejects_case_insensitive_key_collisions() {
        let document: serde_json::Value = serde_json::from_str(r#"{"Ref":"one","ref":"two"}"#)
            .expect("valid JSON with distinct case-sensitive keys");

        assert!(github_value_from_json(&document, 0).is_err());
    }

    #[test]
    fn composite_runtime_budgets_fail_before_unbounded_work() {
        let mut budget = ActionExecutionBudget::new();
        for depth in 0..(MAX_ACTION_NESTING_DEPTH - 1) {
            assert!(budget.enter(format!("action-{depth}")));
        }
        assert_eq!(budget.active.len(), MAX_ACTION_NESTING_DEPTH - 1);
        assert!(budget.enter("at-depth-limit".to_owned()));
        assert_eq!(budget.active.len(), MAX_ACTION_NESTING_DEPTH);
        assert!(!budget.enter("one-too-deep".to_owned()));
        for _ in 0..MAX_ACTION_NESTING_DEPTH {
            budget.leave();
        }

        let mut invocations = ActionExecutionBudget::new();
        for invocation in 0..MAX_ACTION_INVOCATIONS {
            assert!(invocations.enter(format!("action-{invocation}")));
            invocations.leave();
        }
        assert!(!invocations.enter("one-too-many".to_owned()));

        for _ in 0..MAX_COMPOSITE_CHILD_STEPS {
            budget.composite_step().expect("within child-step budget");
        }
        assert!(budget.composite_step().is_err());
        budget
            .charge_derived(MAX_COMPOSITE_DERIVED_BYTES)
            .expect("exact derived-text budget");
        assert!(budget.charge_derived(1).is_err());
    }

    #[test]
    fn action_invocation_count_limit_has_exact_boundaries() {
        assert_eq!(
            action_invocation_count_rejection(MAX_ACTION_INVOCATIONS - 1),
            None
        );
        assert_eq!(
            action_invocation_count_rejection(MAX_ACTION_INVOCATIONS),
            None
        );
        assert_eq!(
            action_invocation_count_rejection(MAX_ACTION_INVOCATIONS + 1),
            Some(ActionBudgetRejection::InvocationCount)
        );
    }

    #[test]
    fn composite_child_step_limit_has_exact_boundaries() {
        assert_eq!(
            composite_child_step_rejection(MAX_COMPOSITE_CHILD_STEPS - 1),
            None
        );
        assert_eq!(
            composite_child_step_rejection(MAX_COMPOSITE_CHILD_STEPS),
            None
        );
        assert_eq!(
            composite_child_step_rejection(MAX_COMPOSITE_CHILD_STEPS + 1),
            Some(ActionBudgetRejection::CompositeChildSteps)
        );
    }

    #[test]
    fn composite_derived_byte_limit_has_exact_boundaries() {
        assert_eq!(
            composite_derived_bytes_rejection(MAX_COMPOSITE_DERIVED_BYTES - 1),
            None
        );
        assert_eq!(
            composite_derived_bytes_rejection(MAX_COMPOSITE_DERIVED_BYTES),
            None
        );
        assert_eq!(
            composite_derived_bytes_rejection(MAX_COMPOSITE_DERIVED_BYTES + 1),
            Some(ActionBudgetRejection::CompositeDerivedBytes)
        );
    }

    #[test]
    fn event_depth_limit_has_exact_boundaries() {
        assert_eq!(event_depth_rejection(MAX_EVENT_DEPTH - 1), None);
        assert_eq!(event_depth_rejection(MAX_EVENT_DEPTH), None);
        assert_eq!(
            event_depth_rejection(MAX_EVENT_DEPTH + 1),
            Some(ActionBudgetRejection::EventDepth)
        );
    }

    #[test]
    fn composite_action_outputs_round_trip_scalar_and_multiline_values() {
        let encoded = encode_action_outputs(&[
            ("scalar".to_owned(), "value".to_owned()),
            ("multiline".to_owned(), "line one\nline two".to_owned()),
        ])
        .expect("bounded action outputs");
        let ParsedCommandFile::Output(outputs) = GithubCommandFileDecoder::default()
            .decode(CommandFileKind::Output, &encoded, CommandFilePlatform::Unix)
            .expect("valid output command file")
        else {
            panic!("output decoder returned the requested file kind");
        };
        let values = outputs
            .commands()
            .iter()
            .map(|value| (value.name(), value.value()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(values["scalar"], "value");
        assert_eq!(values["multiline"], "line one\nline two");
    }

    #[test]
    fn parser_cancellation_dominates_the_next_invalid_workflow_command() {
        let records = [ExecutionOutputRecord::data(
            ExecutionOutputStream::Stdout,
            b"::add-mask::first-secret\n::stop-commands::add-mask\n".to_vec(),
        )
        .expect("bounded output record")];
        let checks = Cell::new(0_usize);
        let cancellation = || {
            let observed = checks.get();
            checks.set(observed + 1);
            observed >= 2
        };
        let mut masker = SecretMasker::new();

        let error = parse_output_with_cancellation(
            &records,
            WorkflowCommandLimits::default(),
            WorkflowCommandPolicy::default(),
            &mut masker,
            &cancellation,
        )
        .err()
        .expect("cancellation wins before the invalid second command is parsed");

        assert!(matches!(error.kind(), ExecutorAdapterErrorKind::Cancelled));
        assert!(masker.contains_secret("first-secret").expect("first mask"));
    }

    #[test]
    fn completed_step_state_error_is_dominated_by_cancellation_or_cleanup_deadline() {
        let execution = ExecutionCancellation::new();
        execution.signal(ExecutionCancellationReason::ServerRequest);
        let live_cancel =
            reconcile_cancelled_operation::<()>(Err(resource_exhausted()), &execution)
                .expect("live cancellation dominates the state aggregation error");
        assert!(live_cancel.is_none());

        let execution = ExecutionCancellation::new();
        let cleanup = CleanupCancellation {
            execution: &execution,
            deadline: Instant::now(),
        };
        let deadline = reconcile_cancelled_operation::<()>(Err(resource_exhausted()), &cleanup)
            .expect("cleanup deadline dominates the state aggregation error");
        assert!(deadline.is_none());

        let execution = ExecutionCancellation::new();
        let error = reconcile_cancelled_operation::<()>(Err(resource_exhausted()), &execution)
            .expect_err("an ordinary state aggregation error remains unchanged");
        assert!(matches!(
            error.kind(),
            ExecutorAdapterErrorKind::ResourceExhausted
        ));
    }

    #[test]
    fn post_reconciliation_has_deterministic_live_cancel_deadline_and_error_precedence() {
        let execution = ExecutionCancellation::new();
        execution.signal(ExecutionCancellationReason::ServerRequest);
        let cleanup = CleanupCancellation {
            execution: &execution,
            deadline: Instant::now(),
        };
        let mut status = GithubStatus::Failure;
        let mut conclusion = JobConclusion::Failure;
        let live_cancel = reconcile_post_operation::<()>(
            Err(resource_exhausted()),
            &cleanup,
            &mut status,
            &mut conclusion,
        )
        .expect("live cancellation dominates a simultaneous deadline and ordinary error");
        assert!(live_cancel.is_none());
        assert_eq!(status, GithubStatus::Cancelled);
        assert_eq!(conclusion, JobConclusion::Cancelled);

        let execution = ExecutionCancellation::new();
        let cleanup = CleanupCancellation {
            execution: &execution,
            deadline: Instant::now(),
        };
        let mut status = GithubStatus::Success;
        let mut conclusion = JobConclusion::Success;
        let deadline = reconcile_post_operation::<()>(
            Err(resource_exhausted()),
            &cleanup,
            &mut status,
            &mut conclusion,
        )
        .expect("deadline expiry dominates an ordinary error after successful execution");
        assert!(deadline.is_none());
        assert_eq!(status, GithubStatus::Failure);
        assert_eq!(conclusion, JobConclusion::TimedOut);

        let mut status = GithubStatus::Failure;
        let mut conclusion = JobConclusion::Failure;
        let preserved_failure = reconcile_post_operation::<()>(
            Err(resource_exhausted()),
            &cleanup,
            &mut status,
            &mut conclusion,
        )
        .expect("deadline expiry preserves an existing ordinary failure");
        assert!(preserved_failure.is_none());
        assert_eq!(status, GithubStatus::Failure);
        assert_eq!(conclusion, JobConclusion::Failure);

        let execution = ExecutionCancellation::new();
        let cleanup = CleanupCancellation {
            execution: &execution,
            deadline: Instant::now()
                .checked_add(Duration::from_mins(1))
                .expect("bounded future deadline"),
        };
        let mut status = GithubStatus::Success;
        let mut conclusion = JobConclusion::Success;
        let ordinary_error = reconcile_post_operation::<()>(
            Err(resource_exhausted()),
            &cleanup,
            &mut status,
            &mut conclusion,
        )
        .expect_err("without either stop signal, the ordinary error remains authoritative");
        assert!(matches!(
            ordinary_error.kind(),
            ExecutorAdapterErrorKind::ResourceExhausted
        ));
        assert_eq!(status, GithubStatus::Success);
        assert_eq!(conclusion, JobConclusion::Success);
    }
}
