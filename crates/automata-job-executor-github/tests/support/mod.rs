#![allow(dead_code)]

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
    },
};

use async_trait::async_trait;
use automata_action_github::JavascriptRuntime;
use automata_auth::secret::SecretString;
use automata_core::{
    ActionReference, AttemptId, EnvironmentProfile, EnvironmentProfileId, FencingToken,
    JobContentReference, JobExecutionContext, JobId, JobIr, JobIrEnvelope, JobLifecycle, JobSource,
    Lease, LeaseId, OperationId, RunId, RunnerId, RunnerRequirements, RunnerSessionId,
    SemanticStep, Sha256Digest, StepId, StepIr, UnixMillis, ValueSource, WorkflowId,
};
use automata_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, DestroyDisposition, DestroySandbox,
    ExecutionArgv, ExecutionCommand, ExecutionEndpoint, ExecutionEnvironment, ExecutionError,
    ExecutionErrorKind, ExecutionOutput, ExecutionStage, ExecutionTermination, ImmutableImage,
    NetworkPolicy, ProviderCapabilities, ProviderError, ProviderId, ResourceLimits,
    RootFilesystemPolicy, SandboxCapability, SandboxEnvironment, SandboxGeneration, SandboxHandle,
    SandboxInspection, SandboxPrivilegePolicy, SandboxProvider, SandboxRecord, SandboxSpec,
    SandboxState, SignalRequest, TargetPath, WaitRequest,
};
use automata_expression_github::{GithubObject, GithubValue, MapContext};
use automata_github_runtime::CommandFileKind;
use automata_job_executor_github::{
    ActionPreparationError, ActionPreparationPort, ActionPreparationRequest,
    ContextEnvironmentVariable, DeterministicOperationIds, ExecutionClock, GithubContextPort,
    GithubContextRequest, GithubContextSnapshot, GithubJobExecutor, GithubJobExecutorConfig,
    GithubJobExecutorPorts, ImmutableSandboxEnvironmentCatalog, JobContentPort, PortError,
    PortErrorKind, PreparedAction, PreparedInput, PreparedJavascriptAction, PreparedValue,
    SecretPort, StaticGithubToolchain,
};
use automata_protocol::{
    JobRuntimeAuthorities, JobRuntimeAuthority, RunnerSlotOrdinal, RuntimeAuthorityCredential,
    RuntimeAuthorityEndpoint, RuntimeAuthorityName,
};
use automata_runner_journal::{
    ContentKind, DurableContentRef, ProviderFailureOutcome, ProviderName, ProviderOperationKind,
    SandboxHandle as JournalSandboxHandle, SandboxIdentity,
};
use automata_runner_runtime::{
    ExecutionCancellation, ExecutionCancellationReason, ExecutionEvents, ExecutionRequest, LogEvent,
};
use automata_runner_spool::ProtectionId;
use automata_workflow_github::{GithubConditionCompiler, GithubConditionPhase};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};

pub const SECRET: &str = "super-secret-value";
pub const CONTEXT_SECRET: &str = "context-only-token";

pub struct Fixture {
    pub executor: GithubJobExecutor,
    pub provider: Arc<FakeProvider>,
    pub endpoint_state: Arc<Mutex<EndpointState>>,
    pub events: Arc<FakeEvents>,
    pub environment: SandboxEnvironment,
}

impl Fixture {
    pub fn new(actions: Vec<PreparedAction>, responses: Vec<PhaseResponse>) -> Self {
        Self::with_default_environment(actions, responses, ExecutionEnvironment::empty())
    }

    pub fn with_default_environment(
        actions: Vec<PreparedAction>,
        responses: Vec<PhaseResponse>,
        default_environment: ExecutionEnvironment,
    ) -> Self {
        let environment = sandbox_environment(default_environment);
        let endpoint_state = Arc::new(Mutex::new(EndpointState {
            files: BTreeMap::new(),
            commands: Vec::new(),
            scripts: Vec::new(),
            responses: responses.into(),
        }));
        let provider = Arc::new(FakeProvider::new(
            environment.clone(),
            Arc::clone(&endpoint_state),
        ));
        let catalog = Arc::new(
            ImmutableSandboxEnvironmentCatalog::new([environment.clone()]).expect("valid catalog"),
        );
        let toolchain = StaticGithubToolchain::new(
            target("/usr/bin/bash"),
            target("/usr/bin/sh"),
            target("/usr/bin/install"),
            target("/usr/bin/tar"),
        )
        .expect("valid tools")
        .with_node(JavascriptRuntime::Node24, target("/opt/node24/bin/node"))
        .expect("valid node");
        let ports = GithubJobExecutorPorts::new(
            provider.clone(),
            catalog,
            Arc::new(FakeActionPreparer::new(actions)),
            Arc::new(FakeJobContent),
            Arc::new(FakeSecrets),
            Arc::new(FakeContexts),
            Arc::new(toolchain),
            Arc::new(DeterministicOperationIds),
            Arc::new(FakeClock::default()),
        );
        let config = GithubJobExecutorConfig::new(
            ResourceLimits::new(2 * 1024 * 1024 * 1024, 2_000, 1_024).expect("valid resources"),
            NetworkPolicy::PrivateEgress,
            RootFilesystemPolicy::Writable,
            SandboxPrivilegePolicy::Administrator,
            std::time::Duration::from_mins(5),
            4 * 1024 * 1024,
            target("/__automata"),
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
        let authorities = JobRuntimeAuthorities::new(vec![authority], &job, &lease)
            .expect("valid authority bundle");
        ExecutionRequest::new(
            RunnerSessionId::new(),
            RunnerSlotOrdinal::new(1).expect("valid slot"),
            lease,
            job,
            authorities,
            content,
            self.environment.clone(),
            JobLifecycle::Preparing,
            None,
        )
    }
}

pub fn run_job(command: &str) -> JobIrEnvelope {
    envelope(vec![StepIr::new(
        StepId::new("run").expect("valid step"),
        "Run",
        SemanticStep::run(
            command,
            automata_core::ShellSpec::CommandTemplate("bash -e {0}".into()),
        ),
    )])
}

pub fn envelope(steps: Vec<StepIr>) -> JobIrEnvelope {
    envelope_with_environment(steps, BTreeMap::new())
}

pub fn envelope_with_working_directory(
    steps: Vec<StepIr>,
    working_directory: &str,
) -> JobIrEnvelope {
    envelope_with_settings(steps, BTreeMap::new(), Some(working_directory), None)
}

pub fn envelope_with_environment(
    steps: Vec<StepIr>,
    environment: BTreeMap<String, ValueSource>,
) -> JobIrEnvelope {
    envelope_with_settings(steps, environment, None, None)
}

pub fn envelope_with_job_condition(steps: Vec<StepIr>, condition: &str) -> JobIrEnvelope {
    envelope_with_settings(steps, BTreeMap::new(), None, Some(condition))
}

fn envelope_with_settings(
    steps: Vec<StepIr>,
    environment: BTreeMap<String, ValueSource>,
    working_directory: Option<&str>,
    job_condition: Option<&str>,
) -> JobIrEnvelope {
    let requirements = RunnerRequirements::default().with_environment_profile(profile());
    let mut job = JobIr::new(JobId::new(), RunId::new(), "test", requirements, steps)
        .with_environment(environment);
    if let Some(working_directory) = working_directory {
        job = job.with_working_directory(working_directory);
    }
    if let Some(condition) = job_condition {
        let condition = GithubConditionCompiler::default()
            .compile_condition(Some(condition), GithubConditionPhase::Job)
            .expect("valid job condition");
        job = job.with_condition(condition);
    }
    JobIrEnvelope::new(
        WorkflowId::new(),
        JobSource::new(
            "github",
            "GoNeuralAI/automata",
            "0123456789abcdef0123456789abcdef01234567",
            ".github/workflows/ci.yml",
            "push",
        ),
        JobExecutionContext::new(
            "CI",
            "refs/heads/main",
            "/__w/automata/automata",
            event_reference(),
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
        id,
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

pub fn prepared_node24_action() -> PreparedAction {
    let compiler = GithubConditionCompiler::default();
    let always = compiler
        .compile_condition(Some("always()"), GithubConditionPhase::Step)
        .expect("valid condition");
    let token = compiler
        .compile_value_expression("${{ github.token }}", GithubConditionPhase::Step)
        .expect("valid metadata value expression");
    let javascript = PreparedJavascriptAction::new(
        JavascriptRuntime::Node24,
        "dist/index.js",
        None,
        always.clone(),
        Some("dist/index.js".to_owned()),
        always,
    )
    .expect("valid JavaScript action");
    let archive = Bytes::from_static(b"validated-action-archive");
    let digest = Sha256Digest::from_bytes(Sha256::digest(&archive).into());
    PreparedAction::new(
        digest,
        archive,
        "",
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
        javascript,
    )
    .expect("valid action")
}

pub fn profile() -> EnvironmentProfile {
    EnvironmentProfile::new(
        EnvironmentProfileId::new("automata.test/ubuntu-24-04").expect("valid profile"),
        Sha256Digest::from_bytes([7; 32]),
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

fn event_reference() -> JobContentReference {
    JobContentReference::new(
        "events/push.json",
        Sha256Digest::from_bytes(Sha256::digest(b"{}").into()),
        2,
        "application/json",
    )
}

#[derive(Debug)]
struct FakeJobContent;

#[async_trait]
impl JobContentPort for FakeJobContent {
    async fn load(&self, reference: &JobContentReference) -> Result<Bytes, PortError> {
        if reference == &event_reference() {
            Ok(Bytes::from_static(b"{}"))
        } else {
            Err(PortError::new(PortErrorKind::InvalidData))
        }
    }
}

pub fn target(value: &str) -> TargetPath {
    TargetPath::posix(value).expect("valid target")
}

#[derive(Clone)]
pub struct PhaseResponse {
    pub termination: ExecutionTermination,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub files: Vec<(CommandFileKind, Vec<u8>)>,
    cancellation: Option<ExecutionCancellation>,
}

impl PhaseResponse {
    pub fn success() -> Self {
        Self {
            termination: ExecutionTermination::Exited(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            files: Vec::new(),
            cancellation: None,
        }
    }

    pub fn with_stdout(mut self, value: impl Into<Vec<u8>>) -> Self {
        self.stdout = value.into();
        self
    }

    pub fn with_file(mut self, kind: CommandFileKind, value: impl Into<Vec<u8>>) -> Self {
        self.files.push((kind, value.into()));
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
}

pub struct EndpointState {
    pub files: BTreeMap<String, Vec<u8>>,
    pub commands: Vec<ExecutionCommand>,
    pub scripts: Vec<Vec<u8>>,
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
            return ExecutionOutput::new(ExecutionTermination::Cancelled, vec![], vec![], false)
                .map_err(|_| execution_error(ExecutionStage::Exec));
        }
        if matches!(program, "/usr/bin/install" | "/usr/bin/tar") {
            return ExecutionOutput::new(ExecutionTermination::Exited(0), vec![], vec![], false)
                .map_err(|_| execution_error(ExecutionStage::Exec));
        }
        let response = state
            .responses
            .pop_front()
            .unwrap_or_else(PhaseResponse::success);
        if let Some(cancellation) = &response.cancellation {
            cancellation.signal(ExecutionCancellationReason::ServerRequest);
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
        ExecutionOutput::new(
            response.termination,
            response.stdout,
            response.stderr,
            false,
        )
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
            .is_some_and(|extension| extension.eq_ignore_ascii_case("sh"))
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
        Ok(self
            .state
            .lock()
            .expect("endpoint lock")
            .files
            .get(request.source().as_str())
            .cloned()
            .unwrap_or_default())
    }
}

fn execution_error(stage: ExecutionStage) -> ExecutionError {
    ExecutionError::new(ExecutionErrorKind::UnsupportedCapability, stage)
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
    pub attaches: usize,
    pub destroys: usize,
    pub specs: Vec<SandboxSpec>,
}

impl FakeProvider {
    fn new(environment: SandboxEnvironment, endpoint_state: Arc<Mutex<EndpointState>>) -> Self {
        let id = ProviderId::new("fake").expect("valid provider");
        let handle = SandboxHandle::new(id.clone(), "sandbox-1").expect("valid handle");
        let capabilities = ProviderCapabilities::new([
            SandboxCapability::WholeJob,
            SandboxCapability::Attach,
            SandboxCapability::Inspect,
            SandboxCapability::Exec,
            SandboxCapability::CopyTo,
            SandboxCapability::CopyFrom,
            SandboxCapability::EnvironmentInjection,
            SandboxCapability::PrivateEgress,
            SandboxCapability::WritableRootFilesystem,
            SandboxCapability::ResourceLimits,
            SandboxCapability::Administrator,
        ])
        .expect("valid capabilities");
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
        (state.creates, state.attaches, state.destroys)
    }

    pub fn specs(&self) -> Vec<SandboxSpec> {
        self.state.lock().expect("provider lock").specs.clone()
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
        state.specs.push(spec.clone());
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

    fn destroy(
        &self,
        _request: &DestroySandbox,
        _cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, ProviderError> {
        self.state.lock().expect("provider lock").destroys += 1;
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
                    automata_job_executor_github::ActionPreparationErrorKind::Resolution,
                )
            })
    }
}

#[derive(Debug)]
struct FakeSecrets;

impl SecretPort for FakeSecrets {
    fn resolve(&self, reference: &str) -> Result<SecretString, PortError> {
        if reference == "test-token" {
            SecretString::new(SECRET).map_err(|_| PortError::new(PortErrorKind::Internal))
        } else {
            Err(PortError::new(PortErrorKind::NotFound))
        }
    }
}

#[derive(Debug)]
struct FakeContexts;

impl GithubContextPort for FakeContexts {
    fn snapshot(
        &self,
        request: GithubContextRequest<'_>,
    ) -> Result<GithubContextSnapshot, PortError> {
        let github = GithubObject::new(vec![
            (
                "repository".to_owned(),
                GithubValue::string(request.job().source().repository()),
            ),
            (
                "sha".to_owned(),
                GithubValue::string(request.job().source().revision()),
            ),
            ("token".to_owned(), GithubValue::string(CONTEXT_SECRET)),
            (
                "server_url".to_owned(),
                GithubValue::string("https://github.com"),
            ),
        ])
        .map_err(|_| PortError::new(PortErrorKind::Internal))?;
        let context = MapContext::without_extensions(
            BTreeMap::from([("github".to_owned(), GithubValue::object(github))]),
            request.status(),
        )
        .map_err(|_| PortError::new(PortErrorKind::Internal))?;
        Ok(GithubContextSnapshot::new(
            Arc::new(context),
            vec![
                ContextEnvironmentVariable::plain("PATH", "/usr/bin:/bin"),
                ContextEnvironmentVariable::plain("HOME", "/home/runner"),
                ContextEnvironmentVariable::plain("GITHUB_WORKSPACE", "/__w/automata/automata"),
                ContextEnvironmentVariable::plain("GITHUB_SERVER_URL", "https://github.com"),
            ],
        )
        .with_secret_masks(vec![Arc::new(
            SecretString::new(CONTEXT_SECRET)
                .map_err(|_| PortError::new(PortErrorKind::Internal))?,
        )]))
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
    provider_operations: Vec<(OperationId, ProviderOperationKind)>,
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
    ) -> Result<(), automata_runner_runtime::ExecutionEventError> {
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
    ) -> Result<(), automata_runner_runtime::ExecutionEventError> {
        self.state.lock().expect("events lock").logs.push(event);
        Ok(())
    }

    fn begin_provider_operation(
        &self,
        kind: ProviderOperationKind,
    ) -> Result<OperationId, automata_runner_runtime::ExecutionEventError> {
        let operation = OperationId::new();
        self.state
            .lock()
            .expect("events lock")
            .provider_operations
            .push((operation, kind));
        Ok(operation)
    }

    fn sandbox_created(
        &self,
        _operation_id: OperationId,
        sandbox: SandboxIdentity,
    ) -> Result<(), automata_runner_runtime::ExecutionEventError> {
        self.state.lock().expect("events lock").sandbox = Some(sandbox);
        Ok(())
    }

    fn provider_operation_completed(
        &self,
        _operation_id: OperationId,
    ) -> Result<(), automata_runner_runtime::ExecutionEventError> {
        self.state.lock().expect("events lock").sandbox = None;
        Ok(())
    }

    fn provider_operation_failed(
        &self,
        _operation_id: OperationId,
        _failure: ProviderFailureOutcome,
    ) -> Result<(), automata_runner_runtime::ExecutionEventError> {
        Ok(())
    }
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
