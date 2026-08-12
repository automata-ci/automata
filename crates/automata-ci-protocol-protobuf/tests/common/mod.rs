#![allow(dead_code)]

use std::collections::BTreeMap;

use automata_ci_core::{
    ActionReference, Architecture, AttemptId, ContainerCapabilities, ContainerCredentials,
    ContainerFeature, ContainerPort, ContainerSpec, EnvironmentProfile, EnvironmentProfileId,
    ExpressionDialect, ExpressionInstruction, ExpressionLiteral, ExpressionProgram, FencingToken,
    IsolationLevel, JobConclusion, JobContentReference, JobExecutionContext, JobId,
    JobInstanceIdentity, JobIr, JobIrEnvelope, JobLifecycle, JobPermissionRequest, JobResult,
    JobResultOutput, JobSecretExposure, JobSource, Lease, LeaseGuard, LeaseId, LogAck, LogChannel,
    LogFrame, LogSequence, LogStreamId, MountSource, OperatingSystem, OperationId,
    ResourceCapacity, RunId, RunValueTemplates, RunnerCapabilities, RunnerFeature, RunnerGroup,
    RunnerId, RunnerLabel, RunnerPlatform, RunnerRequirements, RunnerSessionId, RuntimeBoolean,
    RuntimePositiveInteger, RuntimeTimeoutTemplate, SandboxCapabilities, SandboxFeature,
    SecretBinding, SemanticStep, Sha256Digest, ShellTemplate, StepAnnotation, StepAnnotationLevel,
    StepAnnotationProperty, StepId, StepIr, StepResult, TransportProtocol, UnixMillis, ValueSource,
    ValueTemplate, VolumeMount, WorkflowId,
};
use automata_ci_protocol::{
    CancelJob, CommandAck, CommandCursor, CommandSequence, ErrorMessage, HandshakeErrorCode,
    HandshakeRejected, JobResultMessage, JobRuntimeAuthorities, JobRuntimeAuthority,
    JobStateUpdate, LeaseDisposition, LeaseHeartbeat, LeaseOffer, LeaseRejectionReason,
    LeaseRenewal, LeaseRequest, LeaseResponse, LogAckMessage, LogBatch,
    ManagedSecretBindingOverlay, MessageHeader, NegotiatedSession, NoWork, OperationAck,
    RemoteErrorCode, RunnerHello, RunnerSlotOrdinal, RunnerToServer, RuntimeAuthorityCredential,
    RuntimeAuthorityEndpoint, RuntimeAuthorityName, SUPPORTED_PROTOCOL_RANGE, ServerCommandHeader,
    ServerHello, ServerTiming, ServerToRunner, SessionDisposition, SessionResume,
};
use uuid::Uuid;

pub fn runner_messages() -> Vec<(&'static str, RunnerToServer)> {
    let attempt_id = attempt_id(30);
    let guard = guard();
    let cursor = CommandCursor::through(sequence(7));
    vec![
        (
            "hello",
            RunnerToServer::Hello(
                RunnerHello::new(
                    operation_id(10),
                    SUPPORTED_PROTOCOL_RANGE,
                    automata_ci_core::JobIrVersionRange::current(),
                    capabilities(),
                    UnixMillis::new(1_700_000_000_001),
                )
                .with_resume(SessionResume::new(session_id(11), cursor)),
            ),
        ),
        (
            "lease_request",
            RunnerToServer::LeaseRequest(LeaseRequest::successor(
                request_header(12),
                slot(),
                operation_id(11),
            )),
        ),
        (
            "lease_response",
            RunnerToServer::LeaseResponse(LeaseResponse::new(
                request_header(13),
                attempt_id,
                slot(),
                guard,
                LeaseDisposition::Rejected(LeaseRejectionReason::CapabilityChanged),
            )),
        ),
        (
            "heartbeat",
            RunnerToServer::Heartbeat(LeaseHeartbeat::new(
                request_header(14),
                attempt_id,
                guard,
                JobLifecycle::Running,
                UnixMillis::new(1_700_000_001_000),
            )),
        ),
        (
            "job_state",
            RunnerToServer::JobState(JobStateUpdate::new(
                request_header(15),
                attempt_id,
                guard,
                JobLifecycle::Finalizing,
                UnixMillis::new(1_700_000_002_000),
            )),
        ),
        (
            "job_result",
            RunnerToServer::JobResult(JobResultMessage::new(
                request_header(16),
                guard,
                job_result(attempt_id),
            )),
        ),
        (
            "log_batch",
            RunnerToServer::LogBatch(LogBatch::new(
                request_header(17),
                guard,
                log_frames(attempt_id),
            )),
        ),
        (
            "command_ack",
            RunnerToServer::CommandAck(CommandAck::new(request_header(18), cursor)),
        ),
    ]
}

pub fn server_messages() -> Vec<(&'static str, ServerToRunner)> {
    let attempt_id = attempt_id(30);
    let guard = active_lease(attempt_id, runner_id(1)).guard();
    vec![
        (
            "hello",
            ServerToRunner::Hello(ServerHello::new(
                operation_id(50),
                operation_id(51),
                NegotiatedSession::new(
                    SUPPORTED_PROTOCOL_RANGE.max(),
                    automata_ci_core::JobIrVersion::current(),
                    session_id(52),
                    SessionDisposition::Opened,
                    CommandCursor::initial(),
                ),
                ServerTiming::new(UnixMillis::new(1_700_000_000_000), 5_000, 30_000),
            )),
        ),
        (
            "handshake_rejected",
            ServerToRunner::HandshakeRejected(HandshakeRejected::new(
                operation_id(53),
                operation_id(54),
                HandshakeErrorCode::UnsupportedJobIr,
                SUPPORTED_PROTOCOL_RANGE,
                "no common JobIR schema",
            )),
        ),
        (
            "lease_offer",
            ServerToRunner::LeaseOffer(Box::new(lease_offer_with_job(rich_job()))),
        ),
        (
            "lease_renewal",
            ServerToRunner::LeaseRenewal(LeaseRenewal::new(
                reply_header(56, 57),
                attempt_id,
                guard,
                UnixMillis::new(1_700_000_060_000),
            )),
        ),
        (
            "cancel_job",
            ServerToRunner::CancelJob(CancelJob::new(
                command_header(58, 2),
                attempt_id,
                guard,
                "concurrency group superseded",
                UnixMillis::new(1_700_000_003_000),
            )),
        ),
        (
            "log_ack",
            ServerToRunner::LogAck(LogAckMessage::new(
                reply_header(59, 60),
                LogAck::new(log_stream_id(31), Some(LogSequence::new(2))),
            )),
        ),
        (
            "operation_ack",
            ServerToRunner::OperationAck(OperationAck::new(reply_header(61, 62))),
        ),
        (
            "no_work",
            ServerToRunner::NoWork(NoWork::new(reply_header(63, 64), 1_250)),
        ),
        (
            "error",
            ServerToRunner::Error(
                ErrorMessage::new(
                    reply_header(65, 66),
                    RemoteErrorCode::RetryLater,
                    "capacity temporarily unavailable",
                    true,
                )
                .with_details(BTreeMap::from([
                    ("policy".to_owned(), "least-loaded".to_owned()),
                    ("region".to_owned(), "eu-central".to_owned()),
                ])),
            ),
        ),
    ]
}

pub fn request_header(seed: u128) -> MessageHeader {
    MessageHeader::request(
        SUPPORTED_PROTOCOL_RANGE.max(),
        session_id(2),
        operation_id(seed),
    )
}

pub fn reply_header(seed: u128, reply_to: u128) -> MessageHeader {
    MessageHeader::reply(
        SUPPORTED_PROTOCOL_RANGE.max(),
        session_id(2),
        operation_id(seed),
        operation_id(reply_to),
    )
}

pub fn slot() -> RunnerSlotOrdinal {
    RunnerSlotOrdinal::new(2).expect("fixture slot is valid")
}

pub fn sequence(value: u64) -> CommandSequence {
    CommandSequence::new(value).expect("fixture command sequence is valid")
}

pub fn command_header(operation: u128, command: u64) -> ServerCommandHeader {
    ServerCommandHeader::new(
        SUPPORTED_PROTOCOL_RANGE.max(),
        session_id(2),
        operation_id(operation),
        sequence(command),
    )
}

pub fn guard() -> LeaseGuard {
    LeaseGuard::new(
        lease_id(32),
        FencingToken::new(9).expect("fixture fencing token is valid"),
    )
}

pub fn capabilities() -> RunnerCapabilities {
    RunnerCapabilities::new(
        runner_id(1),
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
    .with_labels([
        RunnerLabel::new("linux").expect("valid label"),
        RunnerLabel::new("self-hosted").expect("valid label"),
        RunnerLabel::new("x64").expect("valid label"),
    ])
    .with_groups([
        RunnerGroup::new("production").expect("valid group"),
        RunnerGroup::new("trusted").expect("valid group"),
    ])
    .with_max_parallel_jobs(4)
    .expect("fixture has runner slots")
    .with_resources_per_job(ResourceCapacity::new(
        4_000,
        8 * 1024 * 1024 * 1024,
        50 * 1024 * 1024 * 1024,
        0,
    ))
    .with_sandbox(SandboxCapabilities::new(
        IsolationLevel::SharedKernel,
        [
            SandboxFeature::CLEAN_WORKSPACE,
            SandboxFeature::NETWORK_ISOLATION,
        ],
    ))
    .with_containers(ContainerCapabilities::new([
        ContainerFeature::CONTAINER_ACTIONS,
        ContainerFeature::DOCKER_COMPATIBLE_API,
        ContainerFeature::JOB_CONTAINERS,
        ContainerFeature::SERVICE_CONTAINERS,
    ]))
    .with_features([
        RunnerFeature::COMMAND_FILES,
        RunnerFeature::JAVASCRIPT_ACTIONS,
        RunnerFeature::SHELL_STEPS,
    ])
    .with_environment_profiles([environment_profile()])
}

fn environment_profile() -> EnvironmentProfile {
    EnvironmentProfile::new(
        EnvironmentProfileId::new("github.com/ubuntu-24.04").expect("valid profile ID"),
        Sha256Digest::from_bytes([0xa5; 32]),
    )
}

pub fn rich_job() -> JobIrEnvelope {
    rich_job_with_requirements(rich_requirements())
}

pub fn rich_job_with_requirements(requirements: RunnerRequirements) -> JobIrEnvelope {
    let step_environment = rich_environment();
    let container = rich_container("ghcr.io/example/build@sha256:0123456789abcdef")
        .with_credentials(ContainerCredentials::new(
            ValueSource::SecretReference("registry-user".to_owned()),
            ValueSource::SecretReference("registry-password".to_owned()),
        ));
    let job = JobIr::new(
        job_id(21),
        run_id(20),
        "verify",
        requirements,
        JobInstanceIdentity::new("verify", 0, 1, Sha256Digest::from_bytes([0xb6; 32]))
            .expect("valid instance"),
        false,
        rich_steps(&step_environment),
    )
    .with_permission_request(JobPermissionRequest::WriteAll)
    .with_timeout_seconds(1_800)
    .with_environment(step_environment)
    .with_working_directory(literal_template("source"))
    .with_container(container)
    .with_services(BTreeMap::from([(
        "postgres".to_owned(),
        rich_container("docker.io/library/postgres:18"),
    )]));
    JobIrEnvelope::new(
        workflow_id(19),
        JobSource::new(
            "github",
            "automata-ci/automata",
            "0123456789abcdef0123456789abcdef01234567",
            ".github/workflows/ci.yml",
            "push",
        ),
        JobExecutionContext::new(
            "CI",
            "refs/heads/main",
            "/__w/automata/automata",
            JobContentReference::new(
                "admission/v1/workflow-event/sha256/event",
                Sha256Digest::from_bytes([0xa5; 32]),
                2,
                "application/json",
            ),
            JobContentReference::new(
                "admission/v1/job-runtime-context/sha256/context",
                Sha256Digest::from_bytes([0xb5; 32]),
                2,
                "application/vnd.automata.job-runtime-context.protobuf",
            ),
        )
        .with_actor("octocat")
        .with_run_number(42)
        .with_run_attempt(2),
        job,
    )
}

pub fn lease_offer_with_job(job: JobIrEnvelope) -> LeaseOffer {
    let lease = active_lease(attempt_id(30), runner_id(1));
    let authorities = runtime_authorities(&job, &lease);
    LeaseOffer::new(command_header(55, 1), slot(), lease, job, authorities)
}

pub fn managed_secret_overlay(lease: &Lease) -> ManagedSecretBindingOverlay {
    ManagedSecretBindingOverlay::new(
        lease,
        [
            (
                "DATABASE_TOKEN".to_owned(),
                SecretBinding::new("00000000-0000-4000-8000-000000000001")
                    .expect("valid grant")
                    .with_version_id("00000000-0000-4000-8000-000000000011")
                    .expect("valid version"),
            ),
            (
                "REGISTRY_TOKEN".to_owned(),
                SecretBinding::new("00000000-0000-4000-8000-000000000002")
                    .expect("valid grant")
                    .with_version_id("00000000-0000-4000-8000-000000000012")
                    .expect("valid version"),
            ),
        ],
    )
    .expect("valid managed-secret overlay")
}

fn rich_requirements() -> RunnerRequirements {
    RunnerRequirements::default()
        .with_labels([
            RunnerLabel::new("linux").expect("valid label"),
            RunnerLabel::new("x64").expect("valid label"),
        ])
        .with_eligible_groups([RunnerGroup::new("trusted").expect("valid group")])
        .with_operating_system(OperatingSystem::Linux)
        .with_architecture(Architecture::X86_64)
        .with_minimum_resources(ResourceCapacity::new(
            2_000,
            4 * 1024 * 1024 * 1024,
            10 * 1024 * 1024 * 1024,
            0,
        ))
        .with_minimum_isolation(IsolationLevel::SharedKernel)
        .with_sandbox_features([
            SandboxFeature::CLEAN_WORKSPACE,
            SandboxFeature::NETWORK_ISOLATION,
        ])
        .with_container_features([
            ContainerFeature::DOCKER_COMPATIBLE_API,
            ContainerFeature::SERVICE_CONTAINERS,
        ])
        .with_features([
            RunnerFeature::COMMAND_FILES,
            RunnerFeature::JAVASCRIPT_ACTIONS,
            RunnerFeature::SHELL_STEPS,
        ])
        .with_environment_profile(environment_profile())
}

fn rich_environment() -> BTreeMap<String, ValueSource> {
    BTreeMap::from([
        (
            "EXPRESSION".to_owned(),
            ValueSource::Expression(github_access("github.sha", "sha")),
        ),
        (
            "LITERAL".to_owned(),
            ValueSource::Literal("value".to_owned()),
        ),
        (
            "SECRET".to_owned(),
            ValueSource::SecretReference("registry-token".to_owned()),
        ),
    ])
}

fn rich_steps(step_environment: &BTreeMap<String, ValueSource>) -> Vec<StepIr> {
    vec![
        StepIr::new(
            StepId::new("run_default").expect("valid step ID"),
            literal_template("Default shell"),
            RuntimeBoolean::literal(false),
            SemanticStep::run(
                RunValueTemplates::new(
                    ValueTemplate::literal("cargo test --workspace").expect("valid command"),
                    ShellTemplate::default_shell(),
                )
                .with_working_directory(
                    ValueTemplate::literal("source").expect("valid working directory"),
                ),
            ),
        )
        .with_condition(success_condition())
        .with_timeout(RuntimeTimeoutTemplate::seconds(
            RuntimePositiveInteger::literal(600),
        ))
        .with_environment(step_environment.clone()),
        StepIr::new(
            StepId::new("run_named").expect("valid step ID"),
            literal_template("Named shell"),
            RuntimeBoolean::literal(false),
            SemanticStep::run(RunValueTemplates::new(
                ValueTemplate::literal("printf '%s\\n' named").expect("valid command"),
                ShellTemplate::named(ValueTemplate::literal("bash").expect("valid shell")),
            )),
        ),
        StepIr::new(
            StepId::new("run_template").expect("valid step ID"),
            literal_template("Template shell"),
            RuntimeBoolean::literal(false),
            SemanticStep::run(RunValueTemplates::new(
                ValueTemplate::literal("printf '%s\\n' template").expect("valid command"),
                ShellTemplate::command_template(
                    ValueTemplate::literal("bash -e {0}").expect("valid shell template"),
                ),
            )),
        ),
        StepIr::new(
            StepId::new("repo_action").expect("valid step ID"),
            literal_template("Repository action"),
            RuntimeBoolean::literal(false),
            SemanticStep::action(
                ActionReference::Repository {
                    repository: "actions/checkout".to_owned(),
                    revision: "de0fac2e4500dabe000000000000000000000000".to_owned(),
                    subpath: Some("sub/action".to_owned()),
                },
                step_environment.clone(),
            ),
        ),
        StepIr::new(
            StepId::new("local_action").expect("valid step ID"),
            literal_template("Local action"),
            RuntimeBoolean::literal(false),
            SemanticStep::action(
                ActionReference::Local {
                    path: "./.github/actions/check".to_owned(),
                },
                BTreeMap::new(),
            ),
        ),
        StepIr::new(
            StepId::new("container_action").expect("valid step ID"),
            literal_template("Container action"),
            RuntimeBoolean::literal(false),
            SemanticStep::action(
                ActionReference::Container {
                    image: "docker://alpine:3.22".to_owned(),
                },
                BTreeMap::new(),
            ),
        ),
    ]
}

fn literal_template(value: &str) -> ValueTemplate {
    ValueTemplate::literal(value).expect("bounded literal template")
}

fn dialect() -> ExpressionDialect {
    ExpressionDialect::new("github-actions", 1).expect("valid expression dialect")
}

fn success_condition() -> ExpressionProgram {
    ExpressionProgram::new(
        dialect(),
        "success()",
        vec![ExpressionInstruction::Call {
            name: "success".to_owned(),
            argument_count: 0,
        }],
    )
    .expect("valid expression")
}

fn github_access(source: &str, property: &str) -> ExpressionProgram {
    ExpressionProgram::new(
        dialect(),
        source,
        vec![
            ExpressionInstruction::NamedValue {
                name: "github".to_owned(),
            },
            ExpressionInstruction::Literal {
                value: ExpressionLiteral::String {
                    value: property.to_owned(),
                },
            },
            ExpressionInstruction::Index,
        ],
    )
    .expect("valid expression")
}

fn rich_container(image: &str) -> ContainerSpec {
    ContainerSpec::new(image)
        .with_environment(BTreeMap::from([(
            "POSTGRES_DB".to_owned(),
            ValueSource::Literal("automata".to_owned()),
        )]))
        .with_ports([
            ContainerPort::new(5432, Some(15432), TransportProtocol::Tcp),
            ContainerPort::new(5353, None, TransportProtocol::Udp),
        ])
        .with_volumes([
            VolumeMount::new(
                MountSource::WorkspaceRelative("cache".to_owned()),
                "/workspace/cache",
                false,
            ),
            VolumeMount::new(
                MountSource::TemporaryVolume("database".to_owned()),
                "/var/lib/postgresql/data",
                false,
            ),
            VolumeMount::new(
                MountSource::HostPath("/dev/kvm".to_owned()),
                "/dev/kvm",
                true,
            ),
        ])
        .with_options(["--userns=keep-id".to_owned(), "--read-only".to_owned()])
}

fn active_lease(attempt: AttemptId, runner: RunnerId) -> Lease {
    Lease::new(
        lease_id(32),
        attempt,
        runner,
        FencingToken::new(9).expect("fixture fencing token is valid"),
        UnixMillis::new(1_700_000_000_000),
        UnixMillis::new(1_700_000_030_000),
    )
    .expect("fixture lease interval is valid")
}

pub fn runtime_authorities(job: &JobIrEnvelope, lease: &Lease) -> JobRuntimeAuthorities {
    let authority = JobRuntimeAuthority::new(
        RuntimeAuthorityName::new("github-actions-results").expect("valid authority name"),
        job.job().run_id(),
        job.job().job_id(),
        lease.attempt_id(),
        lease.fencing_token(),
        RuntimeAuthorityEndpoint::new("https://results.example.test/")
            .expect("valid authority endpoint"),
        RuntimeAuthorityCredential::new("header.payload.signature")
            .expect("valid authority credential"),
        UnixMillis::new(1_700_000_000_000),
        UnixMillis::new(1_700_003_600_000),
    )
    .expect("valid runtime authority");
    JobRuntimeAuthorities::new(vec![authority], job, lease).expect("valid authority bundle")
}

fn job_result(attempt: AttemptId) -> JobResult {
    JobResult::new(
        attempt,
        JobConclusion::Success,
        JobSecretExposure::Secretless,
        UnixMillis::new(1_700_000_020_000),
    )
    .with_outputs(BTreeMap::from([
        (
            "artifact-digest".to_owned(),
            JobResultOutput::public("abc123").expect("public output"),
        ),
        ("receipt".to_owned(), JobResultOutput::secret_derived()),
        (
            "version".to_owned(),
            JobResultOutput::public("0.1.0").expect("public output"),
        ),
    ]))
    .with_steps(vec![
        StepResult::new(
            StepId::new("run_default").expect("valid step ID"),
            JobConclusion::Failure,
            JobConclusion::Success,
            UnixMillis::new(1_700_000_001_000),
            UnixMillis::new(1_700_000_010_000),
        )
        .with_summary_markdown("## Build\nCompleted with a continued warning.\n")
        .with_annotations(vec![StepAnnotation::new(
            StepAnnotationLevel::Warning,
            "synthetic warning",
            vec![StepAnnotationProperty::new("file", "src/lib.rs")],
        )]),
        StepResult::new(
            StepId::new("repo_action").expect("valid step ID"),
            JobConclusion::Success,
            JobConclusion::Success,
            UnixMillis::new(1_700_000_011_000),
            UnixMillis::new(1_700_000_019_000),
        ),
    ])
}

fn log_frames(attempt: AttemptId) -> Vec<LogFrame> {
    let stream = log_stream_id(31);
    [
        (0, LogChannel::Stdout, b"stdout\n".as_slice(), false),
        (1, LogChannel::Stderr, &[0, 0xff, b'\n'][..], false),
        (2, LogChannel::System, &[][..], true),
    ]
    .into_iter()
    .map(|(sequence, channel, payload, end)| {
        LogFrame::new(
            stream,
            attempt,
            LogSequence::new(sequence),
            UnixMillis::new(1_700_000_004_000 + i64::try_from(sequence).expect("small sequence")),
            channel,
            payload.to_vec(),
            end,
        )
        .expect("fixture log frame is valid")
    })
    .collect()
}

fn uuid(seed: u128) -> Uuid {
    Uuid::from_u128(0x1234_5678_9abc_def0_0000_0000_0000_0000 | seed)
}

fn operation_id(seed: u128) -> OperationId {
    OperationId::from_uuid(uuid(seed))
}

fn session_id(seed: u128) -> RunnerSessionId {
    RunnerSessionId::from_uuid(uuid(seed))
}

fn runner_id(seed: u128) -> RunnerId {
    RunnerId::from_uuid(uuid(seed))
}

fn attempt_id(seed: u128) -> AttemptId {
    AttemptId::from_uuid(uuid(seed))
}

fn lease_id(seed: u128) -> LeaseId {
    LeaseId::from_uuid(uuid(seed))
}

fn log_stream_id(seed: u128) -> LogStreamId {
    LogStreamId::from_uuid(uuid(seed))
}

fn workflow_id(seed: u128) -> WorkflowId {
    WorkflowId::from_uuid(uuid(seed))
}

fn run_id(seed: u128) -> RunId {
    RunId::from_uuid(uuid(seed))
}

fn job_id(seed: u128) -> JobId {
    JobId::from_uuid(uuid(seed))
}
