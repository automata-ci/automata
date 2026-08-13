#![allow(dead_code)]

#[cfg(windows)]
use std::path::PathBuf;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use automata_ci_action_github::JavascriptRuntime;
use automata_ci_auth::secret::{SecretString, SharedSensitiveString};
use automata_ci_core::{
    ActionReference, AttemptId, ContainerSpec, ContextValue, EnvironmentProfile,
    EnvironmentProfileId, FencingToken, JobAuthorityProfile, JobContentReference,
    JobExecutionContext, JobId, JobInstanceIdentity, JobIr, JobIrEnvelope, JobLifecycle,
    JobOutputDefinition, JobPermissionRequest, JobResourceAllocation, JobRuntimeContext, JobSource,
    Lease, LeaseId, OperationId, ResourceCapacity, RunId, RunValueTemplates, RunnerId,
    RunnerRequirements, RunnerSessionId, RuntimeBoolean, SecretBinding, SemanticStep, Sha256Digest,
    ShellTemplate, StepId, StepIr, StrategyContext, UnixMillis, ValueSource, ValueTemplate,
    WorkflowId,
};
use automata_ci_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, DestroyDisposition, DestroySandbox,
    ExecutionArgv, ExecutionCommand, ExecutionEndpoint, ExecutionEnvironment, ExecutionError,
    ExecutionErrorKind, ExecutionOutput, ExecutionOutputRecord, ExecutionOutputStream,
    ExecutionStage, ExecutionTermination, ImmutableImage, NetworkPolicy, OperationOutcome,
    ProviderCapabilities, ProviderError, ProviderErrorKind, ProviderId, ProviderStage,
    ResourceLimits, RootFilesystemPolicy, SandboxCapability, SandboxEnvironment, SandboxGeneration,
    SandboxHandle, SandboxInspection, SandboxPrivilegePolicy, SandboxProvider, SandboxRecord,
    SandboxSpec, SandboxState, ServiceContainerBinding, ServiceContainerBindings, ServiceNetwork,
    ServicePortBinding, SignalRequest, TargetPath, TargetPlatform, WaitRequest,
};
use automata_ci_expression_github::{
    ExtensionFunctionResult, GithubEvaluationContext, GithubExpressionEvaluator,
    GithubExpressionFunctionProvider, GithubObject, GithubValue, MapContext,
};
use automata_ci_github_runtime::{
    CommandFileKind, GithubCommandFileDecoder, GithubCompletedStepApplicator,
    StepId as RuntimeStepId, WorkflowCommandLimits, WorkflowCommandPolicy,
};
use automata_ci_job_executor_github::{
    ActionPreparationError, ActionPreparationPort, ActionPreparationRequest,
    ContextEnvironmentVariable, DeterministicOperationIds, ExecutionClock, GithubContextPort,
    GithubContextRequest, GithubContextSnapshot, GithubExecutionPhase, GithubJobExecutor,
    GithubJobExecutorConfig, GithubJobExecutorPorts, ImmutableSandboxEnvironmentCatalog,
    JobContentPort, PortError, PortErrorKind, PreparedAction, PreparedActionDefinition,
    PreparedActionExecution, PreparedInput, PreparedJavascriptAction, PreparedValue,
    SecretCustodyAcknowledger, SecretPort, StaticGithubToolchain,
};
use automata_ci_protocol::{
    JobRuntimeAuthorities, JobRuntimeAuthority, ProtocolLimits, RunnerSlotOrdinal,
    RuntimeAuthorityCredential, RuntimeAuthorityEndpoint, RuntimeAuthorityName,
};
use automata_ci_protocol_protobuf::encode_job_runtime_context;
use automata_ci_runner_journal::{
    CommitStage, ContentKind, DurableContentRef, JournalError, ProviderFailureOutcome,
    ProviderName, ProviderOperationKind, SandboxHandle as JournalSandboxHandle, SandboxIdentity,
};
use automata_ci_runner_runtime::{
    ExecutionCancellation, ExecutionCancellationReason, ExecutionEventError, ExecutionEvents,
    ExecutionRequest, LogEvent,
};
use automata_ci_runner_spool::ProtectionId;
#[cfg(windows)]
use automata_ci_sandbox_windows::{WindowsSandboxProvider, WindowsSandboxProviderOptions};
use automata_ci_workflow_github::{GithubConditionCompiler, GithubConditionPhase};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};

pub const SECRET: &str = "super-secret-value";
pub const CONTEXT_SECRET: &str = "context-only-token";
pub const JOB_RUNTIME_CONTEXT_MEDIA_TYPE: &str =
    "application/vnd.automata.job-runtime-context.protobuf";

pub struct Fixture {
    pub executor: GithubJobExecutor,
    pub provider: Arc<FakeProvider>,
    pub endpoint_state: Arc<Mutex<EndpointState>>,
    pub events: Arc<FakeEvents>,
    pub environment: SandboxEnvironment,
}

#[cfg(windows)]
pub struct NativeWindowsFixture {
    pub executor: GithubJobExecutor,
    pub events: Arc<FakeEvents>,
    pub environment: SandboxEnvironment,
}

#[cfg(windows)]
impl NativeWindowsFixture {
    pub fn new(
        provider_root: PathBuf,
        profile_workspace: TargetPath,
        runner_root: TargetPath,
        default_environment: ExecutionEnvironment,
        toolchain: StaticGithubToolchain,
    ) -> Self {
        let environment =
            SandboxEnvironment::native(windows_profile(), profile_workspace, default_environment)
                .expect("valid native Windows environment");
        let provider = Arc::new(
            WindowsSandboxProvider::open(
                WindowsSandboxProviderOptions::new(provider_root)
                    .expect("valid native Windows provider root"),
            )
            .expect("native Windows provider opens"),
        );
        let catalog = Arc::new(
            ImmutableSandboxEnvironmentCatalog::new([environment.clone()])
                .expect("valid native Windows catalog"),
        );
        let ports = GithubJobExecutorPorts::new(
            provider,
            catalog,
            Arc::new(FakeActionPreparer::new(Vec::new())),
            Arc::new(FakeJobContent::default()),
            Arc::new(FakeSecrets),
            Arc::new(FakeContexts::windows_secretless()),
            Arc::new(toolchain),
            Arc::new(DeterministicOperationIds),
            Arc::new(FakeClock::default()),
        );
        let config = GithubJobExecutorConfig::new(
            ResourceLimits::new(2 * 1024 * 1024 * 1024, 2_000, 1_024).expect("valid resources"),
            NetworkPolicy::Host,
            RootFilesystemPolicy::Host,
            SandboxPrivilegePolicy::Host,
            Duration::from_mins(5),
            4 * 1024 * 1024,
            runner_root,
        )
        .expect("valid native Windows executor config");
        Self {
            executor: GithubJobExecutor::new(config, ports),
            events: Arc::new(FakeEvents::default()),
            environment,
        }
    }

    pub fn request(&self, job: JobIrEnvelope) -> ExecutionRequest {
        execution_request(self.environment.clone(), job)
    }
}

impl Fixture {
    pub fn new(actions: Vec<PreparedAction>, responses: Vec<PhaseResponse>) -> Self {
        Self::with_default_environment(actions, responses, ExecutionEnvironment::empty())
    }

    pub fn windows(responses: Vec<PhaseResponse>) -> Self {
        Self::windows_with_default_environment(responses, ExecutionEnvironment::empty())
    }

    pub fn windows_with_default_environment(
        responses: Vec<PhaseResponse>,
        default_environment: ExecutionEnvironment,
    ) -> Self {
        Self::with_platform_components_and_timeout(
            Vec::new(),
            responses,
            default_environment,
            false,
            Arc::new(FakeJobContent::default()),
            Arc::new(FakeContexts::windows_secretless()),
            Duration::from_mins(5),
            TargetPlatform::Windows,
        )
    }

    pub fn secretless(actions: Vec<PreparedAction>, responses: Vec<PhaseResponse>) -> Self {
        Self::with_components(
            actions,
            responses,
            ExecutionEnvironment::empty(),
            true,
            Arc::new(FakeJobContent::default()),
            Arc::new(FakeContexts::secretless()),
        )
    }

    pub fn with_workflow_command_policy(self, policy: WorkflowCommandPolicy) -> Self {
        let Self {
            executor,
            provider,
            endpoint_state,
            events,
            environment,
        } = self;
        Self {
            executor: executor.with_compatibility_engines(
                GithubExpressionEvaluator::default(),
                GithubCommandFileDecoder::default(),
                GithubCompletedStepApplicator::default(),
                WorkflowCommandLimits::default(),
                policy,
            ),
            provider,
            endpoint_state,
            events,
            environment,
        }
    }

    pub fn with_custody_acknowledger(
        self,
        acknowledger: Arc<dyn SecretCustodyAcknowledger>,
    ) -> Self {
        let Self {
            executor,
            provider,
            endpoint_state,
            events,
            environment,
        } = self;
        Self {
            executor: executor.with_secret_custody(Arc::new(FakeSecrets), acknowledger),
            provider,
            endpoint_state,
            events,
            environment,
        }
    }

    pub fn with_managed_secret_custody(
        self,
        acknowledger: Arc<dyn SecretCustodyAcknowledger>,
        bindings: BTreeMap<String, SecretBinding>,
    ) -> Self {
        let Self {
            executor,
            provider,
            endpoint_state,
            events,
            environment,
        } = self;
        Self {
            executor: executor.with_managed_secret_custody(
                Arc::new(FakeSecrets),
                acknowledger,
                bindings,
            ),
            provider,
            endpoint_state,
            events,
            environment,
        }
    }

    pub fn with_default_environment(
        actions: Vec<PreparedAction>,
        responses: Vec<PhaseResponse>,
        default_environment: ExecutionEnvironment,
    ) -> Self {
        Self::with_service_capability(actions, responses, default_environment, true)
    }

    pub fn without_service_containers(
        actions: Vec<PreparedAction>,
        responses: Vec<PhaseResponse>,
    ) -> Self {
        Self::with_service_capability(actions, responses, ExecutionEnvironment::empty(), false)
    }

    fn with_service_capability(
        actions: Vec<PreparedAction>,
        responses: Vec<PhaseResponse>,
        default_environment: ExecutionEnvironment,
        service_containers: bool,
    ) -> Self {
        Self::with_components(
            actions,
            responses,
            default_environment,
            service_containers,
            Arc::new(FakeJobContent::default()),
            Arc::new(FakeContexts::readable_secret()),
        )
    }

    pub fn with_content_and_contexts(
        actions: Vec<PreparedAction>,
        responses: Vec<PhaseResponse>,
        content: Arc<dyn JobContentPort>,
        contexts: Arc<dyn GithubContextPort>,
    ) -> Self {
        Self::with_components(
            actions,
            responses,
            ExecutionEnvironment::empty(),
            true,
            content,
            contexts,
        )
    }

    pub fn with_step_timeout(
        actions: Vec<PreparedAction>,
        responses: Vec<PhaseResponse>,
        timeout: Duration,
    ) -> Self {
        Self::with_components_and_timeout(
            actions,
            responses,
            ExecutionEnvironment::empty(),
            true,
            Arc::new(FakeJobContent::default()),
            Arc::new(FakeContexts::readable_secret()),
            timeout,
        )
    }

    pub fn with_final_context_cancellation(
        responses: Vec<PhaseResponse>,
        cancellation: ExecutionCancellation,
        point: FinalContextCancellationPoint,
    ) -> Self {
        Self::with_components(
            Vec::new(),
            responses,
            ExecutionEnvironment::empty(),
            true,
            Arc::new(FakeJobContent::default()),
            Arc::new(CancellingFinalContexts {
                cancellation,
                point,
                evaluation_calls: None,
            }),
        )
    }

    pub fn with_counted_output_cancellation(
        responses: Vec<PhaseResponse>,
        cancellation: ExecutionCancellation,
    ) -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let fixture = Self::with_components(
            Vec::new(),
            responses,
            ExecutionEnvironment::empty(),
            true,
            Arc::new(FakeJobContent::default()),
            Arc::new(CancellingFinalContexts {
                cancellation,
                point: FinalContextCancellationPoint::DuringOutputEvaluation,
                evaluation_calls: Some(Arc::clone(&calls)),
            }),
        );
        (fixture, calls)
    }

    pub fn with_counted_action_main_contexts(
        actions: Vec<PreparedAction>,
        responses: Vec<PhaseResponse>,
    ) -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let fixture = Self::with_components(
            actions,
            responses,
            ExecutionEnvironment::empty(),
            true,
            Arc::new(FakeJobContent::default()),
            Arc::new(CountingActionMainContexts {
                calls: Arc::clone(&calls),
            }),
        );
        (fixture, calls)
    }

    pub fn with_main_context_error_cancellation(
        responses: Vec<PhaseResponse>,
        cancellation: ExecutionCancellation,
    ) -> Self {
        Self::with_components(
            Vec::new(),
            responses,
            ExecutionEnvironment::empty(),
            true,
            Arc::new(FakeJobContent::default()),
            Arc::new(CancellingMainContexts { cancellation }),
        )
    }

    pub fn with_main_evaluation_cancellation(
        responses: Vec<PhaseResponse>,
        cancellation: ExecutionCancellation,
    ) -> Self {
        Self::with_components(
            Vec::new(),
            responses,
            ExecutionEnvironment::empty(),
            true,
            Arc::new(FakeJobContent::default()),
            Arc::new(CancellingMainEvaluationContexts { cancellation }),
        )
    }

    pub fn with_post_context_cancellation(
        actions: Vec<PreparedAction>,
        responses: Vec<PhaseResponse>,
        cancellation: ExecutionCancellation,
        point: PostContextCancellationPoint,
    ) -> Self {
        Self::with_components(
            actions,
            responses,
            ExecutionEnvironment::empty(),
            true,
            Arc::new(FakeJobContent::default()),
            Arc::new(CancellingPostContexts {
                cancellation,
                point,
            }),
        )
    }

    fn with_components(
        actions: Vec<PreparedAction>,
        responses: Vec<PhaseResponse>,
        default_environment: ExecutionEnvironment,
        service_containers: bool,
        content: Arc<dyn JobContentPort>,
        contexts: Arc<dyn GithubContextPort>,
    ) -> Self {
        Self::with_components_and_timeout(
            actions,
            responses,
            default_environment,
            service_containers,
            content,
            contexts,
            Duration::from_mins(5),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn with_components_and_timeout(
        actions: Vec<PreparedAction>,
        responses: Vec<PhaseResponse>,
        default_environment: ExecutionEnvironment,
        service_containers: bool,
        content: Arc<dyn JobContentPort>,
        contexts: Arc<dyn GithubContextPort>,
        timeout: Duration,
    ) -> Self {
        Self::with_platform_components_and_timeout(
            actions,
            responses,
            default_environment,
            service_containers,
            content,
            contexts,
            timeout,
            TargetPlatform::Posix,
        )
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn with_platform_components_and_timeout(
        actions: Vec<PreparedAction>,
        responses: Vec<PhaseResponse>,
        default_environment: ExecutionEnvironment,
        service_containers: bool,
        content: Arc<dyn JobContentPort>,
        contexts: Arc<dyn GithubContextPort>,
        timeout: Duration,
        platform: TargetPlatform,
    ) -> Self {
        let environment = match platform {
            TargetPlatform::Posix => sandbox_environment(default_environment),
            TargetPlatform::Windows => windows_sandbox_environment(default_environment),
        };
        let endpoint_state = Arc::new(Mutex::new(EndpointState {
            files: BTreeMap::new(),
            commands: Vec::new(),
            scripts: Vec::new(),
            copy_from_calls: 0,
            copy_from_calls_since_exec: 0,
            cancellation_before_copy_from: None,
            responses: responses.into(),
        }));
        let provider = Arc::new(FakeProvider::new(
            environment.clone(),
            Arc::clone(&endpoint_state),
            service_containers,
        ));
        let catalog = Arc::new(
            ImmutableSandboxEnvironmentCatalog::new([environment.clone()]).expect("valid catalog"),
        );
        let toolchain = match platform {
            TargetPlatform::Posix => StaticGithubToolchain::new(
                target("/usr/bin/bash"),
                target("/usr/bin/sh"),
                target("/usr/bin/install"),
                target("/usr/bin/tar"),
                target("/usr/bin/sha256sum"),
            )
            .expect("valid tools")
            .with_python(target("/usr/bin/python3"))
            .expect("valid python")
            .with_pwsh(target("/usr/bin/pwsh"))
            .expect("valid pwsh")
            .with_node(JavascriptRuntime::Node24, target("/opt/node24/bin/node"))
            .expect("valid node"),
            TargetPlatform::Windows => StaticGithubToolchain::windows(
                windows_target(r"C:\Program Files\PowerShell\7\pwsh.exe"),
                windows_target(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
                windows_target(r"C:\Windows\System32\cmd.exe"),
            )
            .expect("valid Windows tools")
            .with_python(windows_target(
                r"C:\hostedtoolcache\windows\Python\3.13.0\x64\python.exe",
            ))
            .expect("valid Windows python"),
        };
        let ports = GithubJobExecutorPorts::new(
            provider.clone(),
            catalog,
            Arc::new(FakeActionPreparer::new(actions)),
            content,
            Arc::new(FakeSecrets),
            contexts,
            Arc::new(toolchain),
            Arc::new(DeterministicOperationIds),
            Arc::new(FakeClock::default()),
        );
        let (network, filesystem, privilege, runner_root) = match platform {
            TargetPlatform::Posix => (
                NetworkPolicy::PrivateEgress,
                RootFilesystemPolicy::Writable,
                SandboxPrivilegePolicy::Administrator,
                target("/__automata"),
            ),
            TargetPlatform::Windows => (
                NetworkPolicy::Host,
                RootFilesystemPolicy::Host,
                SandboxPrivilegePolicy::Host,
                windows_target(r"D:\_automata"),
            ),
        };
        let config = GithubJobExecutorConfig::new(
            ResourceLimits::new(2 * 1024 * 1024 * 1024, 2_000, 1_024).expect("valid resources"),
            network,
            filesystem,
            privilege,
            timeout,
            4 * 1024 * 1024,
            runner_root,
        )
        .expect("valid config");
        Self {
            executor: GithubJobExecutor::new(config, ports),
            provider,
            endpoint_state,
            events: Arc::new(FakeEvents::default()),
            environment,
        }
    }

    pub fn request(&self, job: JobIrEnvelope) -> ExecutionRequest {
        execution_request(self.environment.clone(), job)
    }
}

fn execution_request(environment: SandboxEnvironment, job: JobIrEnvelope) -> ExecutionRequest {
    let attempt_id = AttemptId::new();
    let lease = Lease::new(
        LeaseId::new(),
        attempt_id,
        RunnerId::new(),
        FencingToken::new(7).expect("valid fence"),
        UnixMillis::new(1),
        UnixMillis::new(1_000_000),
    )
    .expect("valid lease");
    let content = DurableContentRef::after_commit(
        ContentKind::JobIr,
        1,
        Sha256Digest::from_bytes([3; 32]),
        ProtectionId::new("tests").expect("valid protection"),
    )
    .expect("valid content");
    let authorities = match job.job().authority_profile() {
        JobAuthorityProfile::Standard => {
            let authority = JobRuntimeAuthority::new(
                RuntimeAuthorityName::new("github-actions-results").expect("authority name"),
                job.job().run_id(),
                job.job().job_id(),
                lease.attempt_id(),
                lease.fencing_token(),
                RuntimeAuthorityEndpoint::new("https://results.example.test/")
                    .expect("authority endpoint"),
                RuntimeAuthorityCredential::new("test-runtime-token").expect("authority token"),
                UnixMillis::new(1),
                UnixMillis::new(1_000_000),
            )
            .expect("valid authority");
            JobRuntimeAuthorities::new(vec![authority], &job, &lease)
                .expect("valid standard authority bundle")
        }
        JobAuthorityProfile::CredentialFree => JobRuntimeAuthorities::new(Vec::new(), &job, &lease)
            .expect("valid credential-free authority bundle"),
    };
    ExecutionRequest::new(
        RunnerSessionId::new(),
        RunnerSlotOrdinal::new(1).expect("valid slot"),
        lease,
        job,
        authorities,
        content,
        environment,
        JobLifecycle::Preparing,
        None,
    )
}

pub fn run_job(command: &str) -> JobIrEnvelope {
    envelope(vec![run_step_with_shell(
        "run",
        "Run",
        command,
        ShellTemplate::command_template(
            ValueTemplate::literal("bash -e {0}").expect("shell template"),
        ),
    )])
}

pub fn run_step(id: &str, name: &str, command: &str) -> StepIr {
    run_step_with_shell(id, name, command, ShellTemplate::default_shell())
}

pub fn run_step_with_named_shell(id: &str, name: &str, command: &str, shell: &str) -> StepIr {
    run_step_with_shell(
        id,
        name,
        command,
        ShellTemplate::named(ValueTemplate::literal(shell).expect("named shell template")),
    )
}

pub fn run_step_with_working_directory(
    id: &str,
    name: &str,
    command: &str,
    working_directory: &str,
) -> StepIr {
    StepIr::new(
        StepId::new(id).expect("valid step"),
        ValueTemplate::literal(name).expect("step name template"),
        RuntimeBoolean::literal(false),
        SemanticStep::run(
            RunValueTemplates::new(
                ValueTemplate::literal(command).expect("command template"),
                ShellTemplate::default_shell(),
            )
            .with_working_directory(
                ValueTemplate::literal(working_directory).expect("working-directory template"),
            ),
        ),
    )
}

fn run_step_with_shell(id: &str, name: &str, command: &str, shell: ShellTemplate) -> StepIr {
    StepIr::new(
        StepId::new(id).expect("valid step"),
        ValueTemplate::literal(name).expect("step name template"),
        RuntimeBoolean::literal(false),
        SemanticStep::run(RunValueTemplates::new(
            ValueTemplate::literal(command).expect("command template"),
            shell,
        )),
    )
}

pub fn envelope(steps: Vec<StepIr>) -> JobIrEnvelope {
    envelope_with_settings(
        steps,
        BTreeMap::new(),
        BTreeMap::new(),
        None,
        default_runtime_context_reference(),
    )
}

pub fn credential_free_envelope(steps: Vec<StepIr>) -> JobIrEnvelope {
    envelope_with_all_settings_and_profile(
        steps,
        BTreeMap::new(),
        BTreeMap::new(),
        None,
        default_runtime_context_reference(),
        Vec::new(),
        JobAuthorityProfile::CredentialFree,
    )
}

pub fn envelope_with_runtime_context_reference(
    steps: Vec<StepIr>,
    runtime_context: JobContentReference,
) -> JobIrEnvelope {
    envelope_with_settings(
        steps,
        BTreeMap::new(),
        BTreeMap::new(),
        None,
        runtime_context,
    )
}

pub fn envelope_with_runtime_context_and_working_directory(
    steps: Vec<StepIr>,
    runtime_context: JobContentReference,
    working_directory: ValueTemplate,
) -> JobIrEnvelope {
    envelope_with_all_settings(
        steps,
        BTreeMap::new(),
        BTreeMap::new(),
        Some(working_directory),
        runtime_context,
        Vec::new(),
    )
}

pub fn envelope_with_working_directory(
    steps: Vec<StepIr>,
    working_directory: &str,
) -> JobIrEnvelope {
    envelope_with_settings(
        steps,
        BTreeMap::new(),
        BTreeMap::new(),
        Some(working_directory),
        default_runtime_context_reference(),
    )
}

pub fn envelope_with_environment(
    steps: Vec<StepIr>,
    environment: BTreeMap<String, ValueSource>,
) -> JobIrEnvelope {
    envelope_with_settings(
        steps,
        environment,
        BTreeMap::new(),
        None,
        default_runtime_context_reference(),
    )
}

pub fn envelope_with_services(
    steps: Vec<StepIr>,
    services: BTreeMap<String, ContainerSpec>,
) -> JobIrEnvelope {
    envelope_with_settings(
        steps,
        BTreeMap::new(),
        services,
        None,
        default_runtime_context_reference(),
    )
}

pub fn envelope_with_output_definitions(
    steps: Vec<StepIr>,
    outputs: Vec<JobOutputDefinition>,
) -> JobIrEnvelope {
    envelope_with_all_settings(
        steps,
        BTreeMap::new(),
        BTreeMap::new(),
        None,
        default_runtime_context_reference(),
        outputs,
    )
}

fn envelope_with_settings(
    steps: Vec<StepIr>,
    environment: BTreeMap<String, ValueSource>,
    services: BTreeMap<String, ContainerSpec>,
    working_directory: Option<&str>,
    runtime_context: JobContentReference,
) -> JobIrEnvelope {
    let working_directory = working_directory
        .map(|value| ValueTemplate::literal(value).expect("job working-directory template"));
    envelope_with_all_settings(
        steps,
        environment,
        services,
        working_directory,
        runtime_context,
        Vec::new(),
    )
}

fn envelope_with_all_settings(
    steps: Vec<StepIr>,
    environment: BTreeMap<String, ValueSource>,
    services: BTreeMap<String, ContainerSpec>,
    working_directory: Option<ValueTemplate>,
    runtime_context: JobContentReference,
    outputs: Vec<JobOutputDefinition>,
) -> JobIrEnvelope {
    envelope_with_all_settings_and_profile(
        steps,
        environment,
        services,
        working_directory,
        runtime_context,
        outputs,
        JobAuthorityProfile::Standard,
    )
}

fn envelope_with_all_settings_and_profile(
    steps: Vec<StepIr>,
    environment: BTreeMap<String, ValueSource>,
    services: BTreeMap<String, ContainerSpec>,
    working_directory: Option<ValueTemplate>,
    runtime_context: JobContentReference,
    outputs: Vec<JobOutputDefinition>,
    authority_profile: JobAuthorityProfile,
) -> JobIrEnvelope {
    envelope_with_all_settings_and_environment_profile(
        steps,
        environment,
        services,
        working_directory,
        runtime_context,
        outputs,
        authority_profile,
        profile(),
    )
}

#[allow(clippy::too_many_arguments)]
fn envelope_with_all_settings_and_environment_profile(
    steps: Vec<StepIr>,
    environment: BTreeMap<String, ValueSource>,
    services: BTreeMap<String, ContainerSpec>,
    working_directory: Option<ValueTemplate>,
    runtime_context: JobContentReference,
    outputs: Vec<JobOutputDefinition>,
    authority_profile: JobAuthorityProfile,
    environment_profile: EnvironmentProfile,
) -> JobIrEnvelope {
    let allocation = JobResourceAllocation::new(
        ResourceCapacity::new(100, 256 * 1024 * 1024, 0, 0),
        ResourceCapacity::new(2_000, 2 * 1024 * 1024 * 1024, 0, 0),
    )
    .expect("resource allocation");
    let requirements = RunnerRequirements::default()
        .with_environment_profile(environment_profile)
        .with_resource_allocation(allocation);
    let mut job = JobIr::new(
        JobId::new(),
        RunId::new(),
        "test",
        requirements,
        JobInstanceIdentity::new("test", 0, 1, Sha256Digest::from_bytes([0x55; 32]))
            .expect("instance identity"),
        false,
        steps,
    )
    .with_authority_profile(authority_profile)
    .with_permission_request(match authority_profile {
        JobAuthorityProfile::Standard => JobPermissionRequest::ProviderDefault,
        JobAuthorityProfile::CredentialFree => JobPermissionRequest::Mapping(Vec::new()),
    })
    .with_environment(environment)
    .with_services(services)
    .with_output_definitions(outputs);
    if let Some(working_directory) = working_directory {
        job = job.with_working_directory(working_directory);
    }
    JobIrEnvelope::new(
        WorkflowId::new(),
        JobSource::new(
            "github",
            "automata-ci/automata",
            "0123456789abcdef0123456789abcdef01234567",
            ".ci/workflows/ci.yml",
            "push",
        ),
        JobExecutionContext::new(
            "CI",
            "refs/heads/main",
            "/__w/automata/automata",
            event_reference(),
            runtime_context,
        )
        .with_actor("octocat")
        .with_run_number(42)
        .with_run_attempt(1),
        job,
    )
}

pub fn action_step(id: &str, repository: &str) -> StepIr {
    StepIr::new(
        StepId::new(id).expect("valid step"),
        ValueTemplate::literal(id).expect("step name template"),
        RuntimeBoolean::literal(false),
        SemanticStep::action(
            ActionReference::Repository {
                repository: repository.to_owned(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                subpath: None,
            },
            BTreeMap::from([
                (
                    "fetch-depth".to_owned(),
                    ValueSource::Literal("1".to_owned()),
                ),
                (
                    "persist-credentials".to_owned(),
                    ValueSource::Literal("false".to_owned()),
                ),
            ]),
        ),
    )
}

pub fn local_action_step(id: &str, path: &str) -> StepIr {
    StepIr::new(
        StepId::new(id).expect("valid step"),
        ValueTemplate::literal(id).expect("step name template"),
        RuntimeBoolean::literal(false),
        SemanticStep::action(
            ActionReference::Local {
                path: path.to_owned(),
            },
            BTreeMap::new(),
        ),
    )
}

pub fn prepared_node24_action() -> PreparedAction {
    prepared_node24_action_with_post_condition("always()")
}

pub fn prepared_node24_action_with_post_condition(post_condition: &str) -> PreparedAction {
    let compiler = GithubConditionCompiler::default();
    let always = compiler
        .compile_condition(Some("always()"), GithubConditionPhase::Step)
        .expect("valid condition");
    let post_condition = compiler
        .compile_condition(Some(post_condition), GithubConditionPhase::Step)
        .expect("valid post condition");
    let token = compiler
        .compile_value_expression("${{ github.token }}", GithubConditionPhase::Step)
        .expect("valid metadata value expression");
    let javascript = PreparedJavascriptAction::new(
        JavascriptRuntime::Node24,
        "dist/index.js",
        None,
        always,
        Some("dist/index.js".to_owned()),
        post_condition,
    )
    .expect("valid JavaScript action");
    let archive = Bytes::from_static(b"validated-action-archive");
    let digest = Sha256Digest::from_bytes(Sha256::digest(&archive).into());
    let definition = PreparedActionDefinition::new(
        vec![
            PreparedInput::new("fetch-depth", Some(PreparedValue::Literal("1".to_owned())))
                .expect("valid input"),
            PreparedInput::new(
                "persist-credentials",
                Some(PreparedValue::Literal("true".to_owned())),
            )
            .expect("valid input"),
            PreparedInput::new("token", Some(PreparedValue::Expression(token)))
                .expect("valid token input"),
        ],
        Vec::new(),
        PreparedActionExecution::Javascript(Box::new(javascript)),
    )
    .expect("valid JavaScript definition");
    PreparedAction::with_definition(digest, archive, "", definition).expect("valid action")
}

pub fn prepared_node24_action_with_pre() -> PreparedAction {
    prepared_node24_action_with_pre_condition("always()")
}

pub fn prepared_node24_action_with_pre_condition(pre_condition: &str) -> PreparedAction {
    let compiler = GithubConditionCompiler::default();
    let always = compiler
        .compile_condition(Some("always()"), GithubConditionPhase::Step)
        .expect("valid lifecycle condition");
    let pre_condition = compiler
        .compile_condition(Some(pre_condition), GithubConditionPhase::Step)
        .expect("valid pre condition");
    let javascript = PreparedJavascriptAction::new(
        JavascriptRuntime::Node24,
        "dist/main.js",
        Some("dist/pre.js".to_owned()),
        pre_condition,
        Some("dist/post.js".to_owned()),
        always,
    )
    .expect("valid JavaScript action");
    let archive = Bytes::from_static(b"validated-pre-action-archive");
    let digest = Sha256Digest::from_bytes(Sha256::digest(&archive).into());
    let definition = PreparedActionDefinition::new(
        Vec::new(),
        Vec::new(),
        PreparedActionExecution::Javascript(Box::new(javascript)),
    )
    .expect("valid JavaScript definition");
    PreparedAction::with_definition(digest, archive, "", definition).expect("valid action")
}

pub fn profile() -> EnvironmentProfile {
    EnvironmentProfile::new(
        EnvironmentProfileId::new("automata.test/ubuntu-24-04").expect("valid profile"),
        Sha256Digest::from_bytes([7; 32]),
    )
}

pub fn windows_profile() -> EnvironmentProfile {
    EnvironmentProfile::new(
        EnvironmentProfileId::new("automata.test/windows-2025").expect("valid profile"),
        Sha256Digest::from_bytes([8; 32]),
    )
}

pub fn windows_envelope(steps: Vec<StepIr>) -> JobIrEnvelope {
    envelope_with_all_settings_and_environment_profile(
        steps,
        BTreeMap::new(),
        BTreeMap::new(),
        None,
        default_runtime_context_reference(),
        Vec::new(),
        JobAuthorityProfile::Standard,
        windows_profile(),
    )
}

pub fn windows_envelope_with_output_definitions(
    steps: Vec<StepIr>,
    outputs: Vec<JobOutputDefinition>,
) -> JobIrEnvelope {
    envelope_with_all_settings_and_environment_profile(
        steps,
        BTreeMap::new(),
        BTreeMap::new(),
        None,
        default_runtime_context_reference(),
        outputs,
        JobAuthorityProfile::Standard,
        windows_profile(),
    )
}

fn sandbox_environment(default_environment: ExecutionEnvironment) -> SandboxEnvironment {
    SandboxEnvironment::new(
        profile(),
        ImmutableImage::new(format!(
            "registry.example/automata/ubuntu@sha256:{}",
            "a".repeat(64)
        ))
        .expect("valid image"),
        ExecutionArgv::new(target("/usr/bin/sleep"), vec!["infinity".to_owned()])
            .expect("valid keepalive"),
        target("/__w"),
        default_environment,
    )
    .expect("valid environment")
}

fn windows_sandbox_environment(default_environment: ExecutionEnvironment) -> SandboxEnvironment {
    SandboxEnvironment::native(
        windows_profile(),
        windows_target(r"D:\a"),
        default_environment,
    )
    .expect("valid native Windows environment")
}

fn event_reference() -> JobContentReference {
    JobContentReference::new(
        "events/push.json",
        Sha256Digest::from_bytes(Sha256::digest(b"{}").into()),
        2,
        "application/json",
    )
}

pub fn default_runtime_context() -> JobRuntimeContext {
    JobRuntimeContext::new(
        ContextValue::empty_object(),
        ContextValue::empty_object(),
        ContextValue::empty_object(),
        StrategyContext::new(true, 0, 1, 1).expect("strategy context"),
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .expect("default runtime context")
}

pub fn encode_runtime_context(context: &JobRuntimeContext) -> Bytes {
    encode_job_runtime_context(context, &ProtocolLimits::default())
        .map(Bytes::from)
        .expect("encode runtime context")
}

pub fn runtime_context_reference(encoded: &[u8]) -> JobContentReference {
    JobContentReference::new(
        "contexts/test-job.pb",
        Sha256Digest::from_bytes(Sha256::digest(encoded).into()),
        u64::try_from(encoded.len()).expect("bounded runtime context"),
        JOB_RUNTIME_CONTEXT_MEDIA_TYPE,
    )
}

fn default_runtime_context_bytes() -> Bytes {
    encode_runtime_context(&default_runtime_context())
}

fn default_runtime_context_reference() -> JobContentReference {
    runtime_context_reference(&default_runtime_context_bytes())
}

#[derive(Debug)]
struct FakeJobContent {
    runtime_context: Bytes,
}

impl Default for FakeJobContent {
    fn default() -> Self {
        Self {
            runtime_context: default_runtime_context_bytes(),
        }
    }
}

#[async_trait]
impl JobContentPort for FakeJobContent {
    async fn load(&self, reference: &JobContentReference) -> Result<Bytes, PortError> {
        if reference == &event_reference() {
            Ok(Bytes::from_static(b"{}"))
        } else if reference.object_key() == "contexts/test-job.pb" {
            Ok(self.runtime_context.clone())
        } else {
            Err(PortError::new(PortErrorKind::InvalidData))
        }
    }
}

pub fn target(value: &str) -> TargetPath {
    TargetPath::posix(value).expect("valid target")
}

pub fn windows_target(value: &str) -> TargetPath {
    TargetPath::windows(value).expect("valid Windows target")
}

#[derive(Clone)]
pub struct PhaseResponse {
    pub termination: ExecutionTermination,
    pub output: Vec<(ExecutionOutputStream, Vec<u8>)>,
    pub files: Vec<(CommandFileKind, Vec<u8>)>,
    artifacts_list_write: Option<Vec<u8>>,
    truncated: bool,
    cancellation: Option<ExecutionCancellation>,
    cancellation_before_copy_from: Option<ExecutionCancellation>,
    delay: Duration,
}

impl PhaseResponse {
    pub fn success() -> Self {
        Self {
            termination: ExecutionTermination::Exited(0),
            output: Vec::new(),
            files: Vec::new(),
            artifacts_list_write: None,
            truncated: false,
            cancellation: None,
            cancellation_before_copy_from: None,
            delay: Duration::ZERO,
        }
    }

    pub fn with_stdout(mut self, value: impl Into<Vec<u8>>) -> Self {
        self.output
            .push((ExecutionOutputStream::Stdout, value.into()));
        self
    }

    pub fn with_stderr(mut self, value: impl Into<Vec<u8>>) -> Self {
        self.output
            .push((ExecutionOutputStream::Stderr, value.into()));
        self
    }

    pub fn with_file(mut self, kind: CommandFileKind, value: impl Into<Vec<u8>>) -> Self {
        self.files.push((kind, value.into()));
        self
    }

    pub fn with_artifacts_list_write(mut self, value: impl Into<Vec<u8>>) -> Self {
        self.artifacts_list_write = Some(value.into());
        self
    }

    pub fn truncated(mut self) -> Self {
        self.truncated = true;
        self
    }

    pub fn cancelled(mut self) -> Self {
        self.termination = ExecutionTermination::Cancelled;
        self
    }

    pub fn signal(mut self, cancellation: ExecutionCancellation) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    pub fn signal_before_copy_from(mut self, cancellation: ExecutionCancellation) -> Self {
        self.cancellation_before_copy_from = Some(cancellation);
        self
    }

    pub fn delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

pub struct EndpointState {
    pub files: BTreeMap<String, Vec<u8>>,
    pub commands: Vec<ExecutionCommand>,
    pub scripts: Vec<Vec<u8>>,
    pub copy_from_calls: usize,
    pub copy_from_calls_since_exec: usize,
    cancellation_before_copy_from: Option<ExecutionCancellation>,
    responses: VecDeque<PhaseResponse>,
}

#[derive(Clone)]
struct FakeEndpoint {
    handle: SandboxHandle,
    state: Arc<Mutex<EndpointState>>,
    capabilities: Arc<[SandboxCapability]>,
}

impl fmt::Debug for FakeEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeEndpoint")
            .finish_non_exhaustive()
    }
}

impl ExecutionEndpoint for FakeEndpoint {
    fn handle(&self) -> &SandboxHandle {
        &self.handle
    }

    fn capabilities(&self) -> &[SandboxCapability] {
        &self.capabilities
    }

    fn exec(
        &self,
        request: &ExecutionCommand,
        cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, ExecutionError> {
        let program = request.argv().program().as_str();
        let mut state = self.state.lock().expect("endpoint lock");
        state.commands.push(request.clone());
        if cancellation.is_cancelled() {
            return execution_output(ExecutionTermination::Cancelled, Vec::new(), false)
                .map_err(|_| execution_error(ExecutionStage::Exec));
        }
        if matches!(program, "/usr/bin/install" | "/usr/bin/tar") {
            return execution_output(ExecutionTermination::Exited(0), Vec::new(), false)
                .map_err(|_| execution_error(ExecutionStage::Exec));
        }
        if program.eq_ignore_ascii_case(r"C:\Program Files\PowerShell\7\pwsh.exe")
            && request
                .argv()
                .arguments()
                .iter()
                .any(|argument| argument.contains("[System.IO.Directory]::CreateDirectory"))
        {
            return execution_output(ExecutionTermination::Exited(0), Vec::new(), false)
                .map_err(|_| execution_error(ExecutionStage::Exec));
        }
        if program == "/usr/bin/sh"
            && request
                .argv()
                .arguments()
                .get(1)
                .is_some_and(|argument| argument.contains("automata-local-action-metadata"))
        {
            let arguments = request.argv().arguments();
            let preferred = arguments.get(3).expect("preferred metadata path");
            let fallback = arguments.get(4).expect("fallback metadata path");
            let selected = if state.files.contains_key(preferred) {
                Some(b"yml".to_vec())
            } else if state.files.contains_key(fallback) {
                Some(b"yaml".to_vec())
            } else {
                None
            };
            return execution_output(
                selected
                    .as_ref()
                    .map_or(ExecutionTermination::Exited(44), |_| {
                        ExecutionTermination::Exited(0)
                    }),
                selected
                    .map(|bytes| vec![(ExecutionOutputStream::Stdout, bytes)])
                    .unwrap_or_default(),
                false,
            )
            .map_err(|_| execution_error(ExecutionStage::Exec));
        }
        if let Some(output) = artifact_hash_output(request, &state.files) {
            return output;
        }
        let response = state
            .responses
            .pop_front()
            .unwrap_or_else(PhaseResponse::success);
        if let Some(cancellation) = &response.cancellation {
            cancellation.signal(ExecutionCancellationReason::ServerRequest);
        }
        state.copy_from_calls_since_exec = 0;
        state.cancellation_before_copy_from = response.cancellation_before_copy_from;
        if !response.delay.is_zero() {
            std::thread::sleep(response.delay);
        }
        for (kind, bytes) in &response.files {
            let path = request
                .environment()
                .values()
                .iter()
                .find(|value| value.name().as_str() == kind.environment_variable())
                .expect("command file env")
                .value()
                .expose();
            state.files.insert(path.to_owned(), bytes.clone());
        }
        if let Some(bytes) = &response.artifacts_list_write {
            let path = request
                .environment()
                .values()
                .iter()
                .find(|value| value.name().as_str() == "GITHUB_ARTIFACTS_LIST")
                .expect("artifact list env")
                .value()
                .expose();
            state.files.insert(path.to_owned(), bytes.clone());
        }
        execution_output(response.termination, response.output, response.truncated)
            .map_err(|_| execution_error(ExecutionStage::Exec))
    }

    fn signal(
        &self,
        _request: SignalRequest,
        _cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        Err(execution_error(ExecutionStage::Signal))
    }

    fn wait(
        &self,
        _request: WaitRequest,
        _cancellation: &dyn Cancellation,
    ) -> Result<i32, ExecutionError> {
        Err(execution_error(ExecutionStage::Wait))
    }

    fn copy_to(
        &self,
        request: &CopyToRequest,
        _cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        let mut state = self.state.lock().expect("endpoint lock");
        state.files.insert(
            request.target().as_str().to_owned(),
            request.content().to_vec(),
        );
        if std::path::Path::new(request.target().as_str())
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|extension| {
                ["sh", "py", "ps1", "cmd"]
                    .into_iter()
                    .any(|candidate| extension.eq_ignore_ascii_case(candidate))
            })
        {
            state.scripts.push(request.content().to_vec());
        }
        Ok(())
    }

    fn copy_from(
        &self,
        request: &CopyFromRequest,
        _cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ExecutionError> {
        let mut state = self.state.lock().expect("endpoint lock");
        if let Some(cancellation) = state.cancellation_before_copy_from.take() {
            cancellation.signal(ExecutionCancellationReason::ServerRequest);
            return Err(execution_error(ExecutionStage::CopyFrom));
        }
        state.copy_from_calls += 1;
        state.copy_from_calls_since_exec += 1;
        Ok(state
            .files
            .get(request.source().as_str())
            .cloned()
            .unwrap_or_default())
    }
}

fn artifact_hash_output(
    request: &ExecutionCommand,
    files: &BTreeMap<String, Vec<u8>>,
) -> Option<Result<ExecutionOutput, ExecutionError>> {
    if request.argv().program().as_str() != "/usr/bin/sh"
        || !request
            .argv()
            .arguments()
            .get(1)
            .is_some_and(|argument| argument.contains("automata-artifact-sha256"))
    {
        return None;
    }
    let declared = request
        .argv()
        .arguments()
        .get(3)
        .expect("artifact path argument");
    let resolved = if declared.starts_with('/') {
        declared.clone()
    } else {
        format!(
            "{}/{declared}",
            request.working_directory().as_str().trim_end_matches('/')
        )
    };
    let (termination, output) = files.get(&resolved).map_or_else(
        || (ExecutionTermination::Exited(44), Vec::new()),
        |bytes| {
            (
                ExecutionTermination::Exited(0),
                vec![(
                    ExecutionOutputStream::Stdout,
                    sha256_hex(bytes).into_bytes(),
                )],
            )
        },
    );
    Some(
        execution_output(termination, output, false)
            .map_err(|_| execution_error(ExecutionStage::Exec)),
    )
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn execution_error(stage: ExecutionStage) -> ExecutionError {
    ExecutionError::new(ExecutionErrorKind::UnsupportedCapability, stage)
}

fn execution_output(
    termination: ExecutionTermination,
    output: Vec<(ExecutionOutputStream, Vec<u8>)>,
    truncated: bool,
) -> Result<ExecutionOutput, automata_ci_execution::ValueError> {
    let mut records = Vec::new();
    for (stream, bytes) in output {
        for chunk in bytes.chunks(automata_ci_execution::MAX_EXECUTION_OUTPUT_RECORD_BYTES) {
            records.push(ExecutionOutputRecord::data(stream, chunk.to_vec())?);
        }
    }
    records.push(ExecutionOutputRecord::end_of_stream(
        ExecutionOutputStream::Stdout,
    ));
    records.push(ExecutionOutputRecord::end_of_stream(
        ExecutionOutputStream::Stderr,
    ));
    ExecutionOutput::new(termination, records, truncated)
}

pub struct FakeProvider {
    id: ProviderId,
    capabilities: ProviderCapabilities,
    environment: SandboxEnvironment,
    handle: SandboxHandle,
    endpoint_state: Arc<Mutex<EndpointState>>,
    state: Mutex<ProviderState>,
}

#[derive(Default)]
struct ProviderState {
    pub creates: usize,
    pub create_operations: BTreeSet<OperationId>,
    pub create_failures: VecDeque<ProviderError>,
    pub attaches: usize,
    pub destroy_requests: Vec<DestroySandbox>,
    pub specs: Vec<SandboxSpec>,
}

impl FakeProvider {
    fn new(
        environment: SandboxEnvironment,
        endpoint_state: Arc<Mutex<EndpointState>>,
        service_containers: bool,
    ) -> Self {
        let id = ProviderId::new("fake").expect("valid provider");
        let handle = SandboxHandle::new(id.clone(), "sandbox-1").expect("valid handle");
        let (network, filesystem) = match environment.workspace().platform() {
            TargetPlatform::Posix => (
                SandboxCapability::PrivateEgress,
                SandboxCapability::WritableRootFilesystem,
            ),
            TargetPlatform::Windows => (
                SandboxCapability::HostNetwork,
                SandboxCapability::HostFilesystem,
            ),
        };
        let mut capabilities = vec![
            SandboxCapability::WholeJob,
            SandboxCapability::Attach,
            SandboxCapability::Inspect,
            SandboxCapability::Exec,
            SandboxCapability::CopyTo,
            SandboxCapability::CopyFrom,
            SandboxCapability::EnvironmentInjection,
            network,
            filesystem,
            SandboxCapability::ResourceLimits,
            SandboxCapability::ProcessLimits,
            SandboxCapability::Administrator,
        ];
        if environment.workspace().platform() == TargetPlatform::Windows {
            capabilities.push(SandboxCapability::HostIdentity);
        }
        if service_containers && environment.workspace().platform() == TargetPlatform::Posix {
            capabilities.push(SandboxCapability::ServiceContainers);
        }
        let capabilities = ProviderCapabilities::new(capabilities).expect("valid capabilities");
        Self {
            id,
            capabilities,
            environment,
            handle,
            endpoint_state,
            state: Mutex::new(ProviderState::default()),
        }
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let state = self.state.lock().expect("provider lock");
        (state.creates, state.attaches, state.destroy_requests.len())
    }

    pub fn unique_create_operation_count(&self) -> usize {
        self.state
            .lock()
            .expect("provider lock")
            .create_operations
            .len()
    }

    pub fn fail_next_create(&self, kind: ProviderErrorKind, outcome: OperationOutcome) {
        let recovery_handle = (outcome == OperationOutcome::Uncertain).then(|| self.handle.clone());
        self.state
            .lock()
            .expect("provider lock")
            .create_failures
            .push_back(ProviderError::new(
                kind,
                ProviderStage::CreateSandbox,
                outcome,
                recovery_handle,
            ));
    }

    pub fn specs(&self) -> Vec<SandboxSpec> {
        self.state.lock().expect("provider lock").specs.clone()
    }

    pub fn destroy_requests(&self) -> Vec<DestroySandbox> {
        self.state
            .lock()
            .expect("provider lock")
            .destroy_requests
            .clone()
    }
}

impl fmt::Debug for FakeProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeProvider")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl SandboxProvider for FakeProvider {
    fn provider_id(&self) -> &ProviderId {
        &self.id
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    fn create(
        &self,
        spec: &SandboxSpec,
        _cancellation: &dyn Cancellation,
    ) -> Result<SandboxRecord, ProviderError> {
        let mut state = self.state.lock().expect("provider lock");
        state.creates += 1;
        state.create_operations.insert(spec.operation_id());
        state.specs.push(spec.clone());
        if let Some(error) = state.create_failures.pop_front() {
            return Err(error);
        }
        Ok(SandboxRecord::new(
            self.handle.clone(),
            spec.generation(),
            self.environment.attestation().clone(),
            SandboxState::Running,
        ))
    }

    fn attach(
        &self,
        handle: &SandboxHandle,
        _cancellation: &dyn Cancellation,
    ) -> Result<Box<dyn ExecutionEndpoint>, ProviderError> {
        assert_eq!(handle, &self.handle);
        self.state.lock().expect("provider lock").attaches += 1;
        Ok(Box::new(FakeEndpoint {
            handle: self.handle.clone(),
            state: Arc::clone(&self.endpoint_state),
            capabilities: Arc::from(self.capabilities.values().to_vec()),
        }))
    }

    fn inspect(
        &self,
        handle: &SandboxHandle,
        _cancellation: &dyn Cancellation,
    ) -> Result<SandboxInspection, ProviderError> {
        Ok(SandboxInspection::new(
            handle.clone(),
            SandboxGeneration::new(7).expect("valid generation"),
            self.environment.attestation().clone(),
            SandboxState::Running,
        ))
    }

    fn service_bindings(
        &self,
        handle: &SandboxHandle,
        _cancellation: &dyn Cancellation,
    ) -> Result<ServiceContainerBindings, ProviderError> {
        assert_eq!(handle, &self.handle);
        let state = self.state.lock().expect("provider lock");
        let spec = state.specs.last().expect("sandbox spec");
        let network = ServiceNetwork::new("job-network").expect("valid network");
        let values = spec
            .services()
            .iter()
            .enumerate()
            .map(|(service_index, (name, service))| {
                let container =
                    automata_ci_execution::ContainerHandle::new(format!("service-{service_index}"))
                        .expect("valid service handle");
                let ports = service
                    .ports()
                    .iter()
                    .enumerate()
                    .map(|(port_index, port)| {
                        let offset = service_index
                            .checked_mul(100)
                            .and_then(|value| value.checked_add(port_index))
                            .and_then(|value| u16::try_from(value).ok())
                            .expect("bounded test port offset");
                        let host = port.requested_host_port().unwrap_or(30_000 + offset);
                        ServicePortBinding::new(*port, host).expect("valid port binding")
                    })
                    .collect::<Vec<_>>();
                let binding = ServiceContainerBinding::new(container, network.clone(), ports)
                    .expect("valid service binding");
                (name.to_owned(), binding)
            })
            .collect();
        ServiceContainerBindings::new(values).map_err(|_| {
            ProviderError::new(
                automata_ci_execution::ProviderErrorKind::InvalidState,
                automata_ci_execution::ProviderStage::Inspect,
                automata_ci_execution::OperationOutcome::KnownNoEffect,
                None,
            )
        })
    }

    fn destroy(
        &self,
        request: &DestroySandbox,
        _cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, ProviderError> {
        self.state
            .lock()
            .expect("provider lock")
            .destroy_requests
            .push(request.clone());
        Ok(DestroyDisposition::Destroyed)
    }
}

struct FakeActionPreparer {
    actions: Mutex<VecDeque<PreparedAction>>,
}

impl FakeActionPreparer {
    fn new(actions: Vec<PreparedAction>) -> Self {
        Self {
            actions: Mutex::new(actions.into()),
        }
    }
}

impl fmt::Debug for FakeActionPreparer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeActionPreparer")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ActionPreparationPort for FakeActionPreparer {
    async fn prepare(
        &self,
        _request: ActionPreparationRequest<'_>,
    ) -> Result<PreparedAction, ActionPreparationError> {
        self.actions
            .lock()
            .expect("action lock")
            .pop_front()
            .ok_or_else(|| {
                ActionPreparationError::new(
                    automata_ci_job_executor_github::ActionPreparationErrorKind::Resolution,
                )
            })
    }
}

#[derive(Debug)]
struct FakeSecrets;

impl SecretPort for FakeSecrets {
    fn resolve(&self, reference: &str) -> Result<SharedSensitiveString, PortError> {
        if matches!(reference, "test-token" | "secret/deploy-key") {
            SecretString::new(SECRET)
                .map(|secret| SharedSensitiveString::from_secret(Arc::new(secret)))
                .map_err(|_| PortError::new(PortErrorKind::Internal))
        } else {
            Err(PortError::new(PortErrorKind::NotFound))
        }
    }
}

#[derive(Debug)]
struct FakeContexts {
    readable_secret: bool,
    platform: TargetPlatform,
}

impl FakeContexts {
    const fn readable_secret() -> Self {
        Self {
            readable_secret: true,
            platform: TargetPlatform::Posix,
        }
    }

    const fn secretless() -> Self {
        Self {
            readable_secret: false,
            platform: TargetPlatform::Posix,
        }
    }

    const fn windows_secretless() -> Self {
        Self {
            readable_secret: false,
            platform: TargetPlatform::Windows,
        }
    }
}

impl FakeContexts {
    #[allow(clippy::too_many_lines)]
    fn snapshot_with_evaluation_cancellation(
        &self,
        request: GithubContextRequest<'_>,
        cancellation: Option<EvaluationCancellation>,
    ) -> Result<GithubContextSnapshot, PortError> {
        let mut github_values = vec![
            (
                "repository".to_owned(),
                GithubValue::string(request.job().source().repository()),
            ),
            (
                "sha".to_owned(),
                GithubValue::string(request.job().source().revision()),
            ),
            (
                "token".to_owned(),
                GithubValue::string(if self.readable_secret {
                    CONTEXT_SECRET
                } else {
                    ""
                }),
            ),
            (
                "server_url".to_owned(),
                GithubValue::string("https://github.com"),
            ),
        ];
        github_values.extend(phase_context_values(request.phase()));
        let github = GithubObject::new(github_values)
            .map_err(|_| PortError::new(PortErrorKind::Internal))?;
        let mut steps = Vec::with_capacity(request.steps().len());
        for step in request.steps() {
            let runtime_id = RuntimeStepId::new(step.id())
                .map_err(|_| PortError::new(PortErrorKind::Internal))?;
            let outputs = request
                .commands()
                .outputs(&runtime_id)
                .map_or_else(
                    || GithubObject::new(Vec::new()),
                    |values| {
                        GithubObject::new(
                            values
                                .iter()
                                .map(|value| {
                                    (value.name().to_owned(), GithubValue::string(value.value()))
                                })
                                .collect(),
                        )
                    },
                )
                .map_err(|_| PortError::new(PortErrorKind::Internal))?;
            let value = GithubObject::new(vec![
                (
                    "outcome".to_owned(),
                    GithubValue::string(conclusion_text(step.outcome())),
                ),
                (
                    "conclusion".to_owned(),
                    GithubValue::string(conclusion_text(step.conclusion())),
                ),
                ("outputs".to_owned(), GithubValue::object(outputs)),
            ])
            .map_err(|_| PortError::new(PortErrorKind::Internal))?;
            steps.push((step.id().to_owned(), GithubValue::object(value)));
        }
        let steps =
            GithubObject::new(steps).map_err(|_| PortError::new(PortErrorKind::Internal))?;
        let context = MapContext::without_extensions(
            BTreeMap::from([
                ("github".to_owned(), GithubValue::object(github)),
                ("steps".to_owned(), GithubValue::object(steps)),
            ]),
            request.status(),
        )
        .map_err(|_| PortError::new(PortErrorKind::Internal))?;
        let expression: Arc<dyn GithubEvaluationContext> = match cancellation {
            None => Arc::new(context),
            Some(cancellation) => Arc::new(CancellingEvaluationContext {
                inner: context,
                cancellation: cancellation.cancellation,
                named_value_calls: cancellation.named_value_calls,
                trigger: cancellation.trigger,
            }),
        };
        let environment = match self.platform {
            TargetPlatform::Posix => vec![
                ContextEnvironmentVariable::plain("PATH", "/usr/bin:/bin"),
                ContextEnvironmentVariable::plain("HOME", "/home/runner"),
                ContextEnvironmentVariable::plain("GITHUB_WORKSPACE", "/__w/automata/automata"),
                ContextEnvironmentVariable::plain("GITHUB_SERVER_URL", "https://github.com"),
            ],
            TargetPlatform::Windows => vec![
                ContextEnvironmentVariable::plain("PATH", r"C:\Windows\System32"),
                ContextEnvironmentVariable::plain("HOME", r"D:\a\_home"),
                ContextEnvironmentVariable::plain("GITHUB_WORKSPACE", r"D:\a\automata\automata"),
                ContextEnvironmentVariable::plain("RUNNER_OS", "Windows"),
                ContextEnvironmentVariable::plain("GITHUB_SERVER_URL", "https://github.com"),
            ],
        };
        let snapshot = GithubContextSnapshot::new(expression, environment);
        if self.readable_secret {
            Ok(snapshot.with_secret_masks(vec![Arc::new(
                SecretString::new(CONTEXT_SECRET)
                    .map_err(|_| PortError::new(PortErrorKind::Internal))?,
            )]))
        } else {
            Ok(snapshot)
        }
    }
}

impl GithubContextPort for FakeContexts {
    fn snapshot(
        &self,
        request: GithubContextRequest<'_>,
    ) -> Result<GithubContextSnapshot, PortError> {
        self.snapshot_with_evaluation_cancellation(request, None)
    }
}

#[derive(Debug)]
struct CountingActionMainContexts {
    calls: Arc<AtomicUsize>,
}

impl GithubContextPort for CountingActionMainContexts {
    fn snapshot(
        &self,
        request: GithubContextRequest<'_>,
    ) -> Result<GithubContextSnapshot, PortError> {
        if request.phase() == GithubExecutionPhase::ActionMain {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
        FakeContexts::readable_secret().snapshot_with_evaluation_cancellation(request, None)
    }
}

#[derive(Debug)]
struct CancellingMainContexts {
    cancellation: ExecutionCancellation,
}

impl GithubContextPort for CancellingMainContexts {
    fn snapshot(
        &self,
        request: GithubContextRequest<'_>,
    ) -> Result<GithubContextSnapshot, PortError> {
        if matches!(
            request.phase(),
            GithubExecutionPhase::Run | GithubExecutionPhase::ActionMain
        ) {
            self.cancellation
                .signal(ExecutionCancellationReason::ServerRequest);
            return Err(PortError::new(PortErrorKind::InvalidData));
        }
        FakeContexts::secretless().snapshot_with_evaluation_cancellation(request, None)
    }
}

#[derive(Debug)]
struct CancellingMainEvaluationContexts {
    cancellation: ExecutionCancellation,
}

impl GithubContextPort for CancellingMainEvaluationContexts {
    fn snapshot(
        &self,
        request: GithubContextRequest<'_>,
    ) -> Result<GithubContextSnapshot, PortError> {
        let cancellation = matches!(
            request.phase(),
            GithubExecutionPhase::Run | GithubExecutionPhase::ActionMain
        )
        .then(|| EvaluationCancellation {
            cancellation: self.cancellation.clone(),
            named_value_calls: None,
            trigger: EvaluationCancellationTrigger::ExtensionFunction,
        });
        FakeContexts::secretless().snapshot_with_evaluation_cancellation(request, cancellation)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum FinalContextCancellationPoint {
    BeforeReturn,
    BeforeError,
    DuringOutputEvaluation,
}

#[derive(Debug)]
struct CancellingFinalContexts {
    cancellation: ExecutionCancellation,
    point: FinalContextCancellationPoint,
    evaluation_calls: Option<Arc<AtomicUsize>>,
}

impl GithubContextPort for CancellingFinalContexts {
    fn snapshot(
        &self,
        request: GithubContextRequest<'_>,
    ) -> Result<GithubContextSnapshot, PortError> {
        let final_context = request.phase() == GithubExecutionPhase::Job
            && request.step_id().is_none()
            && !request.steps().is_empty();
        if !final_context {
            return FakeContexts::secretless().snapshot_with_evaluation_cancellation(request, None);
        }
        match self.point {
            FinalContextCancellationPoint::BeforeReturn => {
                let snapshot = FakeContexts::readable_secret()
                    .snapshot_with_evaluation_cancellation(request, None)?;
                self.cancellation
                    .signal(ExecutionCancellationReason::ServerRequest);
                Ok(snapshot)
            }
            FinalContextCancellationPoint::BeforeError => {
                self.cancellation
                    .signal(ExecutionCancellationReason::ServerRequest);
                Err(PortError::new(PortErrorKind::InvalidData))
            }
            FinalContextCancellationPoint::DuringOutputEvaluation => {
                FakeContexts::readable_secret().snapshot_with_evaluation_cancellation(
                    request,
                    Some(EvaluationCancellation {
                        cancellation: self.cancellation.clone(),
                        named_value_calls: self.evaluation_calls.clone(),
                        trigger: EvaluationCancellationTrigger::NamedValue,
                    }),
                )
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum PostContextCancellationPoint {
    BeforeError,
    DuringEvaluation,
}

#[derive(Debug)]
struct CancellingPostContexts {
    cancellation: ExecutionCancellation,
    point: PostContextCancellationPoint,
}

impl GithubContextPort for CancellingPostContexts {
    fn snapshot(
        &self,
        request: GithubContextRequest<'_>,
    ) -> Result<GithubContextSnapshot, PortError> {
        if request.phase() != GithubExecutionPhase::ActionPost {
            return FakeContexts::readable_secret()
                .snapshot_with_evaluation_cancellation(request, None);
        }
        match self.point {
            PostContextCancellationPoint::BeforeError => {
                self.cancellation
                    .signal(ExecutionCancellationReason::ServerRequest);
                Err(PortError::new(PortErrorKind::InvalidData))
            }
            PostContextCancellationPoint::DuringEvaluation => FakeContexts::readable_secret()
                .snapshot_with_evaluation_cancellation(
                    request,
                    Some(EvaluationCancellation {
                        cancellation: self.cancellation.clone(),
                        named_value_calls: None,
                        trigger: EvaluationCancellationTrigger::ExtensionFunction,
                    }),
                ),
        }
    }
}

struct EvaluationCancellation {
    cancellation: ExecutionCancellation,
    named_value_calls: Option<Arc<AtomicUsize>>,
    trigger: EvaluationCancellationTrigger,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvaluationCancellationTrigger {
    NamedValue,
    ExtensionFunction,
}

#[derive(Debug)]
struct CancellingEvaluationContext {
    inner: MapContext,
    cancellation: ExecutionCancellation,
    named_value_calls: Option<Arc<AtomicUsize>>,
    trigger: EvaluationCancellationTrigger,
}

impl GithubEvaluationContext for CancellingEvaluationContext {
    fn named_value(&self, name: &str) -> Option<GithubValue> {
        if let Some(calls) = &self.named_value_calls {
            calls.fetch_add(1, Ordering::SeqCst);
        }
        if self.trigger == EvaluationCancellationTrigger::NamedValue {
            self.cancellation
                .signal(ExecutionCancellationReason::ServerRequest);
        }
        self.inner.named_value(name)
    }

    fn status(&self) -> automata_ci_expression_github::GithubStatus {
        self.inner.status()
    }

    fn functions(&self) -> &dyn GithubExpressionFunctionProvider {
        self
    }
}

impl GithubExpressionFunctionProvider for CancellingEvaluationContext {
    fn call(&self, name: &str, arguments: &[GithubValue]) -> ExtensionFunctionResult {
        if self.trigger == EvaluationCancellationTrigger::ExtensionFunction {
            self.cancellation
                .signal(ExecutionCancellationReason::ServerRequest);
        }
        self.inner.functions().call(name, arguments)
    }
}

fn phase_context_values(phase: GithubExecutionPhase) -> [(String, GithubValue); 3] {
    let name = match phase {
        GithubExecutionPhase::Job => "job",
        GithubExecutionPhase::Run => "run",
        GithubExecutionPhase::ActionPre => "action_pre",
        GithubExecutionPhase::ActionMain => "action_main",
        GithubExecutionPhase::ActionPost => "action_post",
    };
    let post = phase == GithubExecutionPhase::ActionPost;
    [
        ("phase".to_owned(), GithubValue::string(name)),
        (
            "phase_timeout".to_owned(),
            GithubValue::number(if post { 1.0 } else { 2.0 }),
        ),
        ("continue_post".to_owned(), GithubValue::Boolean(post)),
    ]
}

const fn conclusion_text(conclusion: automata_ci_core::JobConclusion) -> &'static str {
    match conclusion {
        automata_ci_core::JobConclusion::Success => "success",
        automata_ci_core::JobConclusion::Failure => "failure",
        automata_ci_core::JobConclusion::Cancelled => "cancelled",
        automata_ci_core::JobConclusion::TimedOut => "timed_out",
        automata_ci_core::JobConclusion::Skipped => "skipped",
    }
}

#[derive(Debug, Default)]
struct FakeClock(AtomicI64);

impl ExecutionClock for FakeClock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(self.0.fetch_add(1, Ordering::Relaxed) + 10_000)
    }
}

#[derive(Default)]
pub struct FakeEvents {
    state: Mutex<EventState>,
}

#[derive(Default)]
struct EventState {
    transitions: Vec<JobLifecycle>,
    logs: Vec<LogEvent>,
    sandbox: Option<SandboxIdentity>,
    provider_operation_begins: Vec<(OperationId, ProviderOperationKind)>,
    provider_operation_failures: Vec<(OperationId, ProviderFailureOutcome)>,
    pending_provider_operation: Option<(OperationId, ProviderOperationKind)>,
    provider_event_failures: BTreeSet<ProviderEventFailurePoint>,
    cancellation_on_log: Option<ExecutionCancellation>,
    fail_log_after_cancellation: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ProviderEventFailurePoint {
    BeginOperation,
    SandboxCreated,
    OperationCompleted,
    OperationFailed,
}

impl FakeEvents {
    pub fn logs(&self) -> Vec<LogEvent> {
        self.state.lock().expect("events lock").logs.clone()
    }

    pub fn transitions(&self) -> Vec<JobLifecycle> {
        self.state.lock().expect("events lock").transitions.clone()
    }

    pub fn sandbox(&self) -> Option<SandboxIdentity> {
        self.state.lock().expect("events lock").sandbox.clone()
    }

    pub fn provider_operation_begins(&self) -> Vec<(OperationId, ProviderOperationKind)> {
        self.state
            .lock()
            .expect("events lock")
            .provider_operation_begins
            .clone()
    }

    pub fn pending_provider_operation(&self) -> Option<(OperationId, ProviderOperationKind)> {
        self.state
            .lock()
            .expect("events lock")
            .pending_provider_operation
    }

    pub fn provider_operation_failures(&self) -> Vec<(OperationId, ProviderFailureOutcome)> {
        self.state
            .lock()
            .expect("events lock")
            .provider_operation_failures
            .clone()
    }

    pub fn fail_next_begin_provider_operation(&self) {
        self.state
            .lock()
            .expect("events lock")
            .provider_event_failures
            .insert(ProviderEventFailurePoint::BeginOperation);
    }

    pub fn fail_next_sandbox_created(&self) {
        self.state
            .lock()
            .expect("events lock")
            .provider_event_failures
            .insert(ProviderEventFailurePoint::SandboxCreated);
    }

    pub fn fail_next_provider_operation_completed(&self) {
        self.state
            .lock()
            .expect("events lock")
            .provider_event_failures
            .insert(ProviderEventFailurePoint::OperationCompleted);
    }

    pub fn fail_next_provider_operation_failed(&self) {
        self.state
            .lock()
            .expect("events lock")
            .provider_event_failures
            .insert(ProviderEventFailurePoint::OperationFailed);
    }

    pub fn cancel_on_next_log(&self, cancellation: ExecutionCancellation) {
        self.state.lock().expect("events lock").cancellation_on_log = Some(cancellation);
    }

    pub fn cancel_and_fail_on_next_log(&self, cancellation: ExecutionCancellation) {
        let mut state = self.state.lock().expect("events lock");
        state.cancellation_on_log = Some(cancellation);
        state.fail_log_after_cancellation = true;
    }
}

impl fmt::Debug for FakeEvents {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("FakeEvents").finish_non_exhaustive()
    }
}

impl ExecutionEvents for FakeEvents {
    fn transition(
        &self,
        next: JobLifecycle,
    ) -> Result<(), automata_ci_runner_runtime::ExecutionEventError> {
        self.state
            .lock()
            .expect("events lock")
            .transitions
            .push(next);
        Ok(())
    }

    fn emit_log(
        &self,
        event: LogEvent,
    ) -> Result<(), automata_ci_runner_runtime::ExecutionEventError> {
        let (cancellation, fail_after_cancellation) = {
            let mut state = self.state.lock().expect("events lock");
            state.logs.push(event);
            let cancellation = state.cancellation_on_log.take();
            let fail = state.fail_log_after_cancellation;
            state.fail_log_after_cancellation = false;
            (cancellation, fail)
        };
        if let Some(cancellation) = cancellation {
            cancellation.signal(ExecutionCancellationReason::ServerRequest);
        }
        if fail_after_cancellation {
            Err(automata_ci_runner_runtime::ExecutionEventError::InvalidEvent)
        } else {
            Ok(())
        }
    }

    fn begin_provider_operation(
        &self,
        kind: ProviderOperationKind,
    ) -> Result<OperationId, ExecutionEventError> {
        let mut state = self.state.lock().expect("events lock");
        if state
            .provider_event_failures
            .remove(&ProviderEventFailurePoint::BeginOperation)
        {
            return Err(injected_journal_failure());
        }
        let operation = match state.pending_provider_operation {
            Some((operation, pending_kind)) if pending_kind == kind => operation,
            Some(_) => return Err(ExecutionEventError::InvalidEvent),
            None => {
                let operation = OperationId::new();
                state.pending_provider_operation = Some((operation, kind));
                operation
            }
        };
        state.provider_operation_begins.push((operation, kind));
        Ok(operation)
    }

    fn sandbox_created(
        &self,
        operation_id: OperationId,
        sandbox: SandboxIdentity,
    ) -> Result<(), ExecutionEventError> {
        let mut state = self.state.lock().expect("events lock");
        if state
            .provider_event_failures
            .remove(&ProviderEventFailurePoint::SandboxCreated)
        {
            return Err(injected_journal_failure());
        }
        if state.pending_provider_operation
            != Some((operation_id, ProviderOperationKind::CreateSandbox))
        {
            return Err(ExecutionEventError::InvalidEvent);
        }
        state.sandbox = Some(sandbox);
        state.pending_provider_operation = None;
        Ok(())
    }

    fn provider_operation_completed(
        &self,
        operation_id: OperationId,
    ) -> Result<(), ExecutionEventError> {
        let mut state = self.state.lock().expect("events lock");
        if state
            .provider_event_failures
            .remove(&ProviderEventFailurePoint::OperationCompleted)
        {
            return Err(injected_journal_failure());
        }
        let Some((pending_id, kind)) = state.pending_provider_operation else {
            return Err(ExecutionEventError::InvalidEvent);
        };
        if pending_id != operation_id || kind == ProviderOperationKind::CreateSandbox {
            return Err(ExecutionEventError::InvalidEvent);
        }
        if kind == ProviderOperationKind::DestroySandbox {
            state.sandbox = None;
        }
        state.pending_provider_operation = None;
        Ok(())
    }

    fn provider_operation_failed(
        &self,
        operation_id: OperationId,
        failure: ProviderFailureOutcome,
    ) -> Result<(), ExecutionEventError> {
        let mut state = self.state.lock().expect("events lock");
        if state
            .provider_event_failures
            .remove(&ProviderEventFailurePoint::OperationFailed)
        {
            return Err(injected_journal_failure());
        }
        if state
            .pending_provider_operation
            .is_none_or(|(pending_id, _)| pending_id != operation_id)
        {
            return Err(ExecutionEventError::InvalidEvent);
        }
        state
            .provider_operation_failures
            .push((operation_id, failure));
        if !failure.is_uncertain() {
            state.pending_provider_operation = None;
        }
        Ok(())
    }
}

fn injected_journal_failure() -> ExecutionEventError {
    ExecutionEventError::Journal(JournalError::InjectedFault(CommitStage::FileSynced))
}

pub fn environment_map(command: &ExecutionCommand) -> BTreeMap<String, String> {
    command
        .environment()
        .values()
        .iter()
        .map(|variable| {
            (
                variable.name().as_str().to_owned(),
                variable.value().expose().to_owned(),
            )
        })
        .collect()
}

pub fn journal_identity() -> SandboxIdentity {
    SandboxIdentity::new(
        ProviderName::new("fake").expect("valid provider"),
        JournalSandboxHandle::new("sandbox-1").expect("valid handle"),
    )
}
