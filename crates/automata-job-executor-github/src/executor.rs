use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use automata_core::{
    ActionReference, AttemptId, JobConclusion, JobIrEnvelope, JobLifecycle, JobResult, LogChannel,
    SemanticStep, ShellSpec, StepResult, UnixMillis,
};
use automata_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, DestroySandbox, ExecutionArgv, ExecutionCommand,
    ExecutionEndpoint, ExecutionError, ExecutionErrorKind, ExecutionOutput, ExecutionTermination,
    NetworkPolicy, ProviderError, ProviderErrorKind, RootFilesystemPolicy, SandboxCapability,
    SandboxGeneration, SandboxHandle, SandboxProvider, SandboxSpec, SandboxState, TargetPath,
    TargetPlatform,
};
use automata_expression_github::{GithubExpressionEvaluator, GithubStatus};
use automata_github_runtime::{
    ActionInvocationId, CommandFileDecoder, CommandFileKind, CommandFilePlatform,
    CompletedStepApplicator, CompletedStepCommands, GithubCommandFileDecoder,
    GithubCompletedStepApplicator, GithubWorkflowCommandSession, JobCommandState,
    ParsedCommandFile, StepId as RuntimeStepId, StepPhase, StepScope, WorkflowCommandLimits,
    WorkflowCommandPolicy,
};
use automata_runner_journal::{
    ProviderFailureKind, ProviderFailureOutcome, ProviderName, ProviderOperationKind,
    SandboxHandle as JournalSandboxHandle, SandboxIdentity,
};
use automata_runner_runtime::{
    AdmissionRejection, CleanupFuture, CleanupRequest, ExecutionAdmission, ExecutionCancellation,
    ExecutionEvents, ExecutionRequest, ExecutorError, ExecutorFuture, JobExecutor,
};

use crate::{
    ActionPreparationPort, ActionPreparationRequest, ExecutionClock, ExecutionOperationIds,
    GithubContextPort, GithubContextRequest, GithubExecutionIdentity, GithubExecutionPhase,
    GithubJobExecutorConfig, GithubStepSnapshot, GithubToolchain, JobContentPort, OperationPurpose,
    PreparedAction, SandboxEnvironmentCatalog, SecretPort,
    environment::EnvironmentBuilder,
    error::{ExecutorAdapterError, ExecutorAdapterErrorKind, PortErrorKind},
    output::{SecretMasker, emit_system, process_output},
};

const DIRECTORY_MODE: &str = "0700";
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
    expressions: GithubExpressionEvaluator,
    command_files: GithubCommandFileDecoder,
    completed_steps: GithubCompletedStepApplicator,
    workflow_command_limits: WorkflowCommandLimits,
    workflow_command_policy: WorkflowCommandPolicy,
}

impl GithubJobExecutor {
    /// Creates an executor pinned to the reviewed GitHub compatibility engines.
    #[must_use]
    pub fn new(config: GithubJobExecutorConfig, ports: GithubJobExecutorPorts) -> Self {
        Self {
            config,
            ports,
            expressions: GithubExpressionEvaluator::default(),
            command_files: GithubCommandFileDecoder::default(),
            completed_steps: GithubCompletedStepApplicator::default(),
            workflow_command_limits: WorkflowCommandLimits::default(),
            workflow_command_policy: WorkflowCommandPolicy::default(),
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

    fn validate_admission(
        &self,
        job: &JobIrEnvelope,
    ) -> Result<automata_execution::SandboxEnvironment, AdmissionRejection> {
        job.validate().map_err(|_| AdmissionRejection::InvalidJob)?;
        if job.job().container().is_some() || !job.job().services().is_empty() {
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
        job_workspace(job, &environment).map_err(|_| AdmissionRejection::InvalidJob)?;
        let event = job.execution().event();
        if event.media_type() != "application/json"
            || event.encoded_size() > automata_execution::MAX_COPY_BYTES as u64
        {
            return Err(AdmissionRejection::InvalidJob);
        }
        let capabilities = self.ports.provider.capabilities();
        for required in [
            SandboxCapability::WholeJob,
            SandboxCapability::Attach,
            SandboxCapability::Inspect,
            SandboxCapability::Exec,
            SandboxCapability::CopyTo,
            SandboxCapability::CopyFrom,
            SandboxCapability::EnvironmentInjection,
            SandboxCapability::ResourceLimits,
        ] {
            if !capabilities.supports(required) {
                return Err(AdmissionRejection::CapabilityChanged);
            }
        }
        let network = match self.config.network() {
            NetworkPolicy::Disabled => SandboxCapability::NetworkDisabled,
            NetworkPolicy::PrivateEgress => SandboxCapability::PrivateEgress,
        };
        let filesystem = match self.config.root_filesystem() {
            RootFilesystemPolicy::ReadOnly => SandboxCapability::ReadOnlyRootFilesystem,
            RootFilesystemPolicy::Writable => SandboxCapability::WritableRootFilesystem,
        };
        if !capabilities.supports(network) || !capabilities.supports(filesystem) {
            return Err(AdmissionRejection::CapabilityChanged);
        }
        if self.config.privilege() == automata_execution::SandboxPrivilegePolicy::Administrator
            && !capabilities.supports(SandboxCapability::Administrator)
        {
            return Err(AdmissionRejection::CapabilityChanged);
        }
        if ProviderName::new(self.ports.provider.provider_id().as_str()).is_err()
            || !tool_path(self.ports.toolchain.bash())
            || !tool_path(self.ports.toolchain.sh())
            || !tool_path(self.ports.toolchain.install())
            || !tool_path(self.ports.toolchain.tar())
        {
            return Err(AdmissionRejection::CapabilityChanged);
        }
        for step in job.job().steps() {
            match step.kind() {
                SemanticStep::Action {
                    reference: ActionReference::Repository { .. },
                    ..
                } => {}
                SemanticStep::Run { shell, .. } if supported_shell(shell) => {}
                SemanticStep::Action { .. } | SemanticStep::Run { .. } => {
                    return Err(AdmissionRejection::InvalidJob);
                }
            }
        }
        Ok(environment)
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
        let started_at = self.ports.clock.now();
        let workspace = job_workspace(request.job(), request.environment())?;
        let paths = AttemptPaths::new(self.config.runner_root(), attempt_id, &workspace)?;
        let mut commands = JobCommandState::new(CommandFilePlatform::Unix);
        let mut records = Vec::<MutableStepResult>::new();
        let mut masker = SecretMasker::new();
        let job_context = self.context(
            &request,
            &commands,
            &records,
            GithubStatus::Success,
            None,
            GithubExecutionPhase::Job,
        )?;
        if !self.condition(request.job().job().condition(), &job_context)? {
            return Ok(JobResult::new(
                attempt_id,
                JobConclusion::Skipped,
                self.ports.clock.now(),
            ));
        }

        let event = self
            .ports
            .content
            .load(request.job().execution().event())
            .await
            .map_err(|error| map_port_error(error.kind()))?;
        serde_json::from_slice::<serde_json::Value>(&event)
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
        let endpoint = self.obtain_endpoint(&request, &workspace, &events, &cancellation)?;
        self.prepare_attempt_directories(endpoint.as_ref(), &paths, attempt_id, &cancellation)?;
        self.copy_bytes(
            endpoint.as_ref(),
            attempt_id,
            OperationPurpose::CopyEvent,
            0,
            &paths.event,
            &event,
            &cancellation,
        )?;
        Self::transition_running(request.recovery_lifecycle(), &events)?;

        let job_deadline = request
            .job()
            .job()
            .timeout_seconds()
            .and_then(|seconds| deadline(started_at, seconds));
        let mut status = GithubStatus::Success;
        let mut conclusion = JobConclusion::Success;
        let mut posts = Vec::<RegisteredPost>::new();

        for (index, step) in request.job().job().steps().iter().enumerate() {
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
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
            let started = self.ports.clock.now();
            let phase = match step.kind() {
                SemanticStep::Run { .. } => GithubExecutionPhase::Run,
                SemanticStep::Action { .. } => GithubExecutionPhase::ActionMain,
            };
            let context = self.context(
                &request,
                &commands,
                &records,
                status,
                Some(step.id().as_str()),
                phase,
            )?;
            if !self.condition(step.condition(), &context)? {
                records.push(MutableStepResult::new(
                    step.id().clone(),
                    JobConclusion::Skipped,
                    JobConclusion::Skipped,
                    started,
                    self.ports.clock.now(),
                ));
                continue;
            }
            let timeout = self.step_timeout(step.timeout_seconds(), job_deadline)?;
            let outcome = match step.kind() {
                SemanticStep::Run {
                    command,
                    shell,
                    working_directory,
                } => {
                    let script = paths.script(index)?;
                    self.copy_bytes(
                        endpoint.as_ref(),
                        attempt_id,
                        OperationPurpose::CopyScript,
                        index,
                        &script,
                        command.as_bytes(),
                        &cancellation,
                    )?;
                    let (program, arguments) = self.shell_argv(shell, &script)?;
                    let working_directory = working_directory
                        .as_deref()
                        .or(request.job().job().working_directory());
                    let working_directory = working_directory_path(&workspace, working_directory)?;
                    let environment = EnvironmentBuilder::new(
                        &self.expressions,
                        self.ports.secrets.as_ref(),
                        request.environment().default_environment(),
                    )
                    .phase_environment(
                        &context,
                        &commands,
                        request.job().job().environment(),
                        step.environment(),
                        std::iter::empty(),
                        &mut masker,
                    )?;
                    let phase = phase_ordinal(index, 0)?;
                    let execution = PhaseExecution {
                        step_id: step.id().as_str(),
                        phase,
                        scope: StepPhase::Run,
                        program,
                        arguments,
                        working_directory,
                        environment,
                        timeout,
                    };
                    self.run_phase(
                        endpoint.as_ref(),
                        &paths,
                        attempt_id,
                        execution,
                        &mut commands,
                        &mut masker,
                        &events,
                        &cancellation,
                    )?
                }
                SemanticStep::Action { reference, inputs } => {
                    self.run_action_step(
                        &request,
                        endpoint.as_ref(),
                        &paths,
                        step,
                        index,
                        reference,
                        inputs,
                        &context,
                        timeout,
                        &mut commands,
                        &records,
                        status,
                        &mut posts,
                        &mut masker,
                        &events,
                        &cancellation,
                    )
                    .await?
                }
            };
            let mapped = map_continue(outcome.conclusion(), step.continue_on_error());
            records.push(MutableStepResult::new(
                step.id().clone(),
                outcome.conclusion(),
                mapped,
                started,
                self.ports.clock.now(),
            ));
            if mapped != JobConclusion::Success && mapped != JobConclusion::Skipped {
                conclusion = mapped;
                status = status_for(mapped);
                break;
            }
        }

        if cancellation.is_cancelled() {
            conclusion = JobConclusion::Cancelled;
            status = GithubStatus::Cancelled;
        }
        let cleanup = CleanupCancellation::new(self.config.post_job_cleanup_timeout());
        self.run_posts(
            &request,
            endpoint.as_ref(),
            &paths,
            &mut commands,
            &mut records,
            &mut posts,
            &mut status,
            &mut conclusion,
            &mut masker,
            &events,
            &cleanup,
        )?;
        let completed_at = self.ports.clock.now();
        let steps = records
            .into_iter()
            .map(|record| record.into_result(completed_at))
            .collect();
        Ok(JobResult::new(attempt_id, conclusion, completed_at).with_steps(steps))
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn run_action_step(
        &self,
        request: &ExecutionRequest,
        endpoint: &dyn ExecutionEndpoint,
        paths: &AttemptPaths,
        step: &automata_core::StepIr,
        index: u32,
        reference: &ActionReference,
        supplied_inputs: &std::collections::BTreeMap<String, automata_core::ValueSource>,
        main_context: &crate::GithubContextSnapshot,
        timeout: Duration,
        commands: &mut JobCommandState,
        records: &[MutableStepResult],
        status: GithubStatus,
        posts: &mut Vec<RegisteredPost>,
        masker: &mut SecretMasker,
        events: &Arc<dyn ExecutionEvents>,
        cancellation: &ExecutionCancellation,
    ) -> Result<CommandOutcome, ExecutorAdapterError> {
        let action = match self
            .ports
            .actions
            .prepare(ActionPreparationRequest::new(reference))
            .await
        {
            Ok(action) => action,
            Err(error) => {
                emit_system(
                    &format!("Action preparation failed ({:?})", error.kind()),
                    masker,
                    events,
                )?;
                return Ok(CommandOutcome::Failure);
            }
        };
        let Some(node) = self
            .ports
            .toolchain
            .node(action.javascript().runtime())
            .cloned()
        else {
            emit_system("Action runtime is unavailable", masker, events)?;
            return Ok(CommandOutcome::Failure);
        };
        let action_paths = self.prepare_action_content(
            endpoint,
            paths,
            request.lease().attempt_id(),
            index,
            &action,
            cancellation,
        )?;
        let builder = EnvironmentBuilder::new(
            &self.expressions,
            self.ports.secrets.as_ref(),
            request.environment().default_environment(),
        );
        let input_environment =
            builder.action_inputs(&action, supplied_inputs, main_context, masker)?;
        let invocation = ActionInvocationId::new(format!("{}-{index}", step.id().as_str()))
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
        if action.javascript().post().is_some() {
            posts.push(RegisteredPost {
                step_index: index,
                step_id: step.id().as_str().to_owned(),
                invocation: invocation.clone(),
                action: action.clone(),
                paths: action_paths.clone(),
                input_environment: input_environment.clone(),
                timeout,
                continue_on_error: step.continue_on_error(),
            });
        }

        if let Some(pre) = action.javascript().pre() {
            let context = self.context(
                request,
                commands,
                records,
                status,
                Some(step.id().as_str()),
                GithubExecutionPhase::ActionPre,
            )?;
            if self
                .expressions
                .evaluate_condition(action.javascript().pre_condition(), context.expression())
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?
            {
                let environment = builder.phase_environment(
                    &context,
                    commands,
                    request.job().job().environment(),
                    step.environment(),
                    action_extra_environment(&input_environment, &action_paths, Vec::new()),
                    masker,
                )?;
                let execution = PhaseExecution {
                    step_id: step.id().as_str(),
                    phase: phase_ordinal(index, 1)?,
                    scope: StepPhase::ActionMain(invocation.clone()),
                    program: node.clone(),
                    arguments: vec![action_paths.entry(pre)?.as_str().to_owned()],
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
                    masker,
                    events,
                    cancellation,
                )?;
                if outcome != CommandOutcome::Success {
                    return Ok(outcome);
                }
            }
        }

        let context = self.context(
            request,
            commands,
            records,
            status,
            Some(step.id().as_str()),
            GithubExecutionPhase::ActionMain,
        )?;
        let environment = builder.phase_environment(
            &context,
            commands,
            request.job().job().environment(),
            step.environment(),
            action_extra_environment(&input_environment, &action_paths, Vec::new()),
            masker,
        )?;
        let execution = PhaseExecution {
            step_id: step.id().as_str(),
            phase: phase_ordinal(index, 2)?,
            scope: StepPhase::ActionMain(invocation),
            program: node,
            arguments: vec![
                action_paths
                    .entry(action.javascript().main())?
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
            masker,
            events,
            cancellation,
        )
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
        let argv = ExecutionArgv::new(
            self.ports.toolchain.install().clone(),
            vec![
                "-d".to_owned(),
                "-m".to_owned(),
                DIRECTORY_MODE.to_owned(),
                "--".to_owned(),
                action_paths.base.as_str().to_owned(),
                action_paths.extracted.as_str().to_owned(),
            ],
        )
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        let command = ExecutionCommand::new(
            self.ports.operation_ids.operation_id(
                attempt_id,
                OperationPurpose::PrepareDirectory,
                index.checked_add(1).ok_or_else(|| {
                    ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob)
                })?,
            ),
            argv,
            paths.workspace.clone(),
            automata_execution::ExecutionEnvironment::empty(),
            self.config.default_step_timeout(),
            self.config.maximum_output_bytes(),
        )
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        let output = endpoint
            .exec(&command, &CancellationBridge(cancellation))
            .map_err(map_execution_error)?;
        require_success(&output)?;
        self.copy_bytes(
            endpoint,
            attempt_id,
            OperationPurpose::CopyActionArchive,
            index,
            &action_paths.archive,
            action.archive(),
            cancellation,
        )?;
        let argv = ExecutionArgv::new(
            self.ports.toolchain.tar().clone(),
            vec![
                "-xzf".to_owned(),
                action_paths.archive.as_str().to_owned(),
                "--directory".to_owned(),
                action_paths.extracted.as_str().to_owned(),
                "--strip-components=1".to_owned(),
                "--no-same-owner".to_owned(),
                "--no-same-permissions".to_owned(),
            ],
        )
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        let command = ExecutionCommand::new(
            self.ports.operation_ids.operation_id(
                attempt_id,
                OperationPurpose::ExtractActionArchive,
                index,
            ),
            argv,
            paths.workspace.clone(),
            automata_execution::ExecutionEnvironment::empty(),
            self.config.default_step_timeout(),
            self.config.maximum_output_bytes(),
        )
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        let output = endpoint
            .exec(&command, &CancellationBridge(cancellation))
            .map_err(map_execution_error)?;
        require_success(&output)?;
        Ok(action_paths)
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn run_posts(
        &self,
        request: &ExecutionRequest,
        endpoint: &dyn ExecutionEndpoint,
        paths: &AttemptPaths,
        commands: &mut JobCommandState,
        records: &mut [MutableStepResult],
        posts: &mut Vec<RegisteredPost>,
        status: &mut GithubStatus,
        conclusion: &mut JobConclusion,
        masker: &mut SecretMasker,
        events: &Arc<dyn ExecutionEvents>,
        cancellation: &CleanupCancellation,
    ) -> Result<(), ExecutorAdapterError> {
        while let Some(post) = posts.pop() {
            if cancellation.is_cancelled() {
                if *conclusion == JobConclusion::Success {
                    *conclusion = JobConclusion::TimedOut;
                    *status = GithubStatus::Failure;
                }
                break;
            }
            let context = self.context(
                request,
                commands,
                records,
                *status,
                Some(&post.step_id),
                GithubExecutionPhase::ActionPost,
            )?;
            if !self
                .expressions
                .evaluate_condition(
                    post.action.javascript().post_condition(),
                    context.expression(),
                )
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?
            {
                continue;
            }
            let Some(entry) = post.action.javascript().post() else {
                continue;
            };
            let Some(node) = self
                .ports
                .toolchain
                .node(post.action.javascript().runtime())
                .cloned()
            else {
                return Err(ExecutorAdapterError::new(
                    ExecutorAdapterErrorKind::Unsupported,
                ));
            };
            let step_index = usize::try_from(post.step_index)
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
            let step =
                request.job().job().steps().get(step_index).ok_or_else(|| {
                    ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob)
                })?;
            let state = commands
                .post_action_environment(&post.invocation)
                .into_iter()
                .map(|value| (value.name().to_owned(), value.value().to_owned()))
                .collect();
            let environment = EnvironmentBuilder::new(
                &self.expressions,
                self.ports.secrets.as_ref(),
                request.environment().default_environment(),
            )
            .phase_environment(
                &context,
                commands,
                request.job().job().environment(),
                step.environment(),
                action_extra_environment(&post.input_environment, &post.paths, state),
                masker,
            )?;
            let remaining = cancellation.remaining();
            if remaining.is_zero() {
                if *conclusion == JobConclusion::Success {
                    *conclusion = JobConclusion::TimedOut;
                    *status = GithubStatus::Failure;
                }
                break;
            }
            let execution = PhaseExecution {
                step_id: &post.step_id,
                phase: phase_ordinal(post.step_index, 3)?,
                scope: StepPhase::ActionPost(post.invocation),
                program: node,
                arguments: vec![post.paths.entry(entry)?.as_str().to_owned()],
                working_directory: paths.workspace.clone(),
                environment,
                timeout: post.timeout.min(remaining),
            };
            let outcome = self.run_phase(
                endpoint,
                paths,
                request.lease().attempt_id(),
                execution,
                commands,
                masker,
                events,
                cancellation,
            )?;
            if outcome != CommandOutcome::Success {
                let mapped = map_continue(outcome.conclusion(), post.continue_on_error);
                if let Some(record) = records
                    .iter_mut()
                    .find(|record| record.step_id.as_str() == post.step_id)
                {
                    if record.outcome == JobConclusion::Success {
                        record.outcome = outcome.conclusion();
                    }
                    record.conclusion = mapped;
                    record.completed_at = self.ports.clock.now();
                }
                if mapped != JobConclusion::Success {
                    *conclusion = mapped;
                    *status = status_for(mapped);
                }
            }
        }
        Ok(())
    }

    fn context(
        &self,
        request: &ExecutionRequest,
        commands: &JobCommandState,
        records: &[MutableStepResult],
        status: GithubStatus,
        step_id: Option<&str>,
        phase: GithubExecutionPhase,
    ) -> Result<crate::GithubContextSnapshot, ExecutorAdapterError> {
        let steps = records
            .iter()
            .map(MutableStepResult::snapshot)
            .collect::<Vec<_>>();
        let event_path = event_path(self.config.runner_root(), request.lease().attempt_id())?;
        self.ports
            .contexts
            .snapshot(GithubContextRequest::new(
                GithubExecutionIdentity::new(
                    request.job(),
                    request.lease(),
                    request.runtime_authorities(),
                ),
                &event_path,
                commands,
                &steps,
                status,
                step_id,
                phase,
            ))
            .map_err(|error| map_port_error(error.kind()))
    }

    fn condition(
        &self,
        condition: Option<&automata_core::ExpressionProgram>,
        context: &crate::GithubContextSnapshot,
    ) -> Result<bool, ExecutorAdapterError> {
        condition.map_or(Ok(true), |condition| {
            self.expressions
                .evaluate_condition(condition, context.expression())
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))
        })
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

    fn obtain_endpoint(
        &self,
        request: &ExecutionRequest,
        workspace: &TargetPath,
        events: &Arc<dyn ExecutionEvents>,
        cancellation: &dyn ExecutorCancellation,
    ) -> Result<Box<dyn ExecutionEndpoint>, ExecutorAdapterError> {
        let cancellation = CancellationBridge(cancellation);
        let generation = SandboxGeneration::new(request.lease().fencing_token().get())
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        let handle = if let Some(recovered) = request.recovered_sandbox() {
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
            let inspection = self
                .ports
                .provider
                .inspect(&handle, &cancellation)
                .map_err(|error| map_provider_error(&error))?;
            if inspection.generation() != generation
                || inspection.profile() != request.environment().attestation()
                || inspection.state() != SandboxState::Running
            {
                return Err(ExecutorAdapterError::new(
                    ExecutorAdapterErrorKind::InvalidJob,
                ));
            }
            handle
        } else {
            let operation_id = events
                .begin_provider_operation(ProviderOperationKind::CreateSandbox)
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
            let spec = SandboxSpec::new(
                operation_id,
                generation,
                request.environment().clone(),
                workspace.clone(),
                self.config.network(),
                self.config.root_filesystem(),
                self.config.resources(),
            )
            .with_privilege(self.config.privilege());
            let record = match self.ports.provider.create(&spec, &cancellation) {
                Ok(record) => record,
                Err(error) => {
                    let _ = events
                        .provider_operation_failed(operation_id, provider_failure_outcome(&error));
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
            record.handle().clone()
        };
        self.ports
            .provider
            .attach(&handle, &cancellation)
            .map_err(|error| map_provider_error(&error))
    }

    fn prepare_attempt_directories(
        &self,
        endpoint: &dyn ExecutionEndpoint,
        paths: &AttemptPaths,
        attempt_id: AttemptId,
        cancellation: &ExecutionCancellation,
    ) -> Result<(), ExecutorAdapterError> {
        let argv = ExecutionArgv::new(
            self.ports.toolchain.install().clone(),
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
        )
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        let command = ExecutionCommand::new(
            self.ports.operation_ids.operation_id(
                attempt_id,
                OperationPurpose::PrepareDirectory,
                0,
            ),
            argv,
            paths.workspace.clone(),
            automata_execution::ExecutionEnvironment::empty(),
            self.config.default_step_timeout(),
            self.config.maximum_output_bytes(),
        )
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
        let output = endpoint
            .exec(&command, &CancellationBridge(cancellation))
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
            .copy_to(&request, &CancellationBridge(cancellation))
            .map_err(map_execution_error)
    }

    fn shell_argv(
        &self,
        shell: &ShellSpec,
        script: &TargetPath,
    ) -> Result<(TargetPath, Vec<String>), ExecutorAdapterError> {
        let script = script.as_str().to_owned();
        match shell {
            ShellSpec::Default => Ok((
                self.ports.toolchain.bash().clone(),
                vec!["-e".into(), script],
            )),
            ShellSpec::Named(name) if name == "bash" => Ok((
                self.ports.toolchain.bash().clone(),
                vec![
                    "--noprofile".into(),
                    "--norc".into(),
                    "-eo".into(),
                    "pipefail".into(),
                    script,
                ],
            )),
            ShellSpec::Named(name) if name == "sh" => {
                Ok((self.ports.toolchain.sh().clone(), vec!["-e".into(), script]))
            }
            ShellSpec::CommandTemplate(template) if template == "bash -e {0}" => Ok((
                self.ports.toolchain.bash().clone(),
                vec!["-e".into(), script],
            )),
            ShellSpec::CommandTemplate(template)
                if template == "bash --noprofile --norc -eo pipefail {0}" =>
            {
                Ok((
                    self.ports.toolchain.bash().clone(),
                    vec![
                        "--noprofile".into(),
                        "--norc".into(),
                        "-eo".into(),
                        "pipefail".into(),
                        script,
                    ],
                ))
            }
            ShellSpec::CommandTemplate(template) if template == "sh -e {0}" => {
                Ok((self.ports.toolchain.sh().clone(), vec!["-e".into(), script]))
            }
            ShellSpec::Named(_) | ShellSpec::CommandTemplate(_) => Err(ExecutorAdapterError::new(
                ExecutorAdapterErrorKind::Unsupported,
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_phase(
        &self,
        endpoint: &dyn ExecutionEndpoint,
        paths: &AttemptPaths,
        attempt_id: AttemptId,
        execution: PhaseExecution,
        commands: &mut JobCommandState,
        masker: &mut SecretMasker,
        events: &Arc<dyn ExecutionEvents>,
        cancellation: &dyn ExecutorCancellation,
    ) -> Result<CommandOutcome, ExecutorAdapterError> {
        let command_paths = paths.command_files(execution.phase)?;
        for (index, (_, path)) in command_paths.values.iter().enumerate() {
            let ordinal = execution
                .phase
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
        let mut environment = execution.environment;
        environment = add_command_file_environment(&environment, &command_paths)?;
        let argv = ExecutionArgv::new(execution.program, execution.arguments)
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
        let command = ExecutionCommand::new(
            self.ports.operation_ids.operation_id(
                attempt_id,
                OperationPurpose::ExecutePhase,
                execution.phase,
            ),
            argv,
            execution.working_directory,
            environment,
            execution.timeout,
            self.config.maximum_output_bytes(),
        )
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
        let output = endpoint
            .exec(&command, &CancellationBridge(cancellation))
            .map_err(map_execution_error)?;
        let mut processor = GithubWorkflowCommandSession::new(
            self.workflow_command_limits,
            self.workflow_command_policy,
        );
        let mut legacy = Vec::new();
        process_output(
            output.stdout(),
            LogChannel::Stdout,
            &mut processor,
            masker,
            events,
            &mut legacy,
        )?;
        process_output(
            output.stderr(),
            LogChannel::Stderr,
            &mut processor,
            masker,
            events,
            &mut legacy,
        )?;
        let completed = self.read_command_files(
            endpoint,
            attempt_id,
            execution.phase,
            &command_paths,
            cancellation,
        )?;
        let completed = completed.with_legacy_mutations(&legacy);
        let runtime_step_id = RuntimeStepId::new(execution.step_id)
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
        let scope = StepScope::new(runtime_step_id, execution.scope);
        *commands = self
            .completed_steps
            .apply_completed_step(commands, &scope, &completed)
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::ResourceExhausted))?
            .into_next_state();
        Ok(CommandOutcome::from_termination(output.termination()))
    }

    fn read_command_files(
        &self,
        endpoint: &dyn ExecutionEndpoint,
        attempt_id: AttemptId,
        phase: u32,
        paths: &CommandFilePaths,
        cancellation: &dyn ExecutorCancellation,
    ) -> Result<CompletedStepCommands, ExecutorAdapterError> {
        let mut parsed = Vec::with_capacity(COMMAND_FILE_KINDS.len());
        for (index, (kind, path)) in paths.values.iter().enumerate() {
            let ordinal = phase
                .checked_mul(5)
                .and_then(|value| value.checked_add(u32::try_from(index).ok()?))
                .ok_or_else(|| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
            let limit = if *kind == CommandFileKind::StepSummary {
                self.command_files.limits().maximum_summary_bytes()
            } else {
                self.command_files.limits().maximum_file_bytes()
            };
            let request = CopyFromRequest::new(
                self.ports.operation_ids.operation_id(
                    attempt_id,
                    OperationPurpose::ReadCommandFile,
                    ordinal,
                ),
                path.clone(),
                limit,
            )
            .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?;
            let bytes = endpoint
                .copy_from(&request, &CancellationBridge(cancellation))
                .map_err(map_execution_error)?;
            parsed.push(
                self.command_files
                    .decode(*kind, &bytes, CommandFilePlatform::Unix)
                    .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?,
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
        Ok(CompletedStepCommands::new(
            environment,
            output,
            path,
            state,
            summary,
        ))
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
        let destroy = DestroySandbox::new(operation_id, handle, generation);
        match self
            .ports
            .provider
            .destroy(&destroy, &CancellationBridge(cancellation))
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
            .field("expressions", &self.expressions)
            .field("command_files", &self.command_files)
            .field("completed_steps", &self.completed_steps)
            .field("workflow_command_limits", &self.workflow_command_limits)
            .field("workflow_command_policy", &self.workflow_command_policy)
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

struct CleanupCancellation {
    deadline: Instant,
}

impl CleanupCancellation {
    fn new(timeout: Duration) -> Self {
        Self {
            deadline: Instant::now()
                .checked_add(timeout)
                .unwrap_or_else(Instant::now),
        }
    }

    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

impl ExecutorCancellation for CleanupCancellation {
    fn is_cancelled(&self) -> bool {
        Instant::now() >= self.deadline
    }
}

struct CancellationBridge<'a>(&'a dyn ExecutorCancellation);

impl Cancellation for CancellationBridge<'_> {
    fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }
}

struct PhaseExecution<'a> {
    step_id: &'a str,
    phase: u32,
    scope: StepPhase,
    program: TargetPath,
    arguments: Vec<String>,
    working_directory: TargetPath,
    environment: automata_execution::ExecutionEnvironment,
    timeout: Duration,
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
    step_index: u32,
    step_id: String,
    invocation: ActionInvocationId,
    action: PreparedAction,
    paths: ActionPaths,
    input_environment: Vec<(String, String)>,
    timeout: Duration,
    continue_on_error: bool,
}

struct MutableStepResult {
    step_id: automata_core::StepId,
    outcome: JobConclusion,
    conclusion: JobConclusion,
    started_at: UnixMillis,
    completed_at: UnixMillis,
}

impl MutableStepResult {
    const fn new(
        step_id: automata_core::StepId,
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

    fn into_result(self, job_completed_at: UnixMillis) -> StepResult {
        StepResult::new(
            self.step_id,
            self.outcome,
            self.conclusion,
            self.started_at,
            self.completed_at.min(job_completed_at),
        )
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

    fn script(&self, index: u32) -> Result<TargetPath, ExecutorAdapterError> {
        child(&self.scripts, &format!("step-{index}.sh"))
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
        Ok(CommandFilePaths { values })
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
    fn entry(&self, entry: &str) -> Result<TargetPath, ExecutorAdapterError> {
        child(&self.directory, entry)
    }
}

struct CommandFilePaths {
    values: Vec<(CommandFileKind, TargetPath)>,
}

fn add_command_file_environment(
    environment: &automata_execution::ExecutionEnvironment,
    paths: &CommandFilePaths,
) -> Result<automata_execution::ExecutionEnvironment, ExecutorAdapterError> {
    let mut values = environment.values().to_vec();
    for (kind, path) in &paths.values {
        values.retain(|variable| variable.name().as_str() != kind.environment_variable());
        values.push(automata_execution::EnvironmentVariable::new(
            automata_execution::EnvironmentName::new(kind.environment_variable())
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?,
            automata_execution::EnvironmentValue::new(path.as_str())
                .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::Internal))?,
        ));
    }
    automata_execution::ExecutionEnvironment::new(values)
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::ResourceExhausted))
}

fn action_extra_environment(
    inputs: &[(String, String)],
    paths: &ActionPaths,
    state: Vec<(String, String)>,
) -> Vec<(String, String)> {
    let mut values = inputs.to_vec();
    values.push((
        "GITHUB_ACTION_PATH".to_owned(),
        paths.directory.as_str().to_owned(),
    ));
    values.extend(state);
    values
}

fn supported_shell(shell: &ShellSpec) -> bool {
    matches!(shell, ShellSpec::Default)
        || matches!(shell, ShellSpec::Named(name) if matches!(name.as_str(), "bash" | "sh"))
        || matches!(
            shell,
            ShellSpec::CommandTemplate(template)
                if matches!(
                    template.as_str(),
                    "bash -e {0}"
                        | "bash --noprofile --norc -eo pipefail {0}"
                        | "sh -e {0}"
                )
        )
}

fn tool_path(path: &TargetPath) -> bool {
    path.platform() == TargetPlatform::Posix && path.as_str() != "/"
}

fn phase_ordinal(step: u32, phase: u32) -> Result<u32, ExecutorAdapterError> {
    step.checked_mul(4)
        .and_then(|value| value.checked_add(phase))
        .ok_or_else(|| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))
}

fn child(parent: &TargetPath, child: &str) -> Result<TargetPath, ExecutorAdapterError> {
    TargetPath::posix(format!("{}/{child}", parent.as_str().trim_end_matches('/')))
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))
}

fn event_path(
    runner_root: &TargetPath,
    attempt_id: AttemptId,
) -> Result<TargetPath, ExecutorAdapterError> {
    child(runner_root, &format!("attempts/{attempt_id}/event.json"))
}

fn job_workspace(
    job: &JobIrEnvelope,
    environment: &automata_execution::SandboxEnvironment,
) -> Result<TargetPath, ExecutorAdapterError> {
    let workspace = TargetPath::posix(job.execution().workspace())
        .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
    let root = environment.workspace().as_str().trim_end_matches('/');
    let prefix = format!("{root}/");
    if workspace.as_str() == root || !workspace.as_str().starts_with(&prefix) {
        return Err(ExecutorAdapterError::new(
            ExecutorAdapterErrorKind::InvalidJob,
        ));
    }
    Ok(workspace)
}

fn working_directory_path(
    workspace: &TargetPath,
    requested: Option<&str>,
) -> Result<TargetPath, ExecutorAdapterError> {
    let Some(requested) = requested else {
        return Ok(workspace.clone());
    };
    let path = if requested.starts_with('/') {
        TargetPath::posix(requested)
    } else {
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
    .map_err(|_| ExecutorAdapterError::new(ExecutorAdapterErrorKind::InvalidJob))?;
    let prefix = format!("{}/", workspace.as_str().trim_end_matches('/'));
    if path != *workspace && !path.as_str().starts_with(&prefix) {
        return Err(ExecutorAdapterError::new(
            ExecutorAdapterErrorKind::InvalidJob,
        ));
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
        automata_execution::OperationOutcome::KnownNoEffect => {
            ProviderFailureOutcome::KnownNoEffect(kind)
        }
        automata_execution::OperationOutcome::Uncertain => ProviderFailureOutcome::Uncertain(kind),
    }
}
