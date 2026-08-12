mod support;

use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use automata_ci_core::{
    ContextValue, JobConclusion, JobContentReference, JobRuntimeContext, NeedContext, NeedOutput,
    OutputSensitivity, RunValueTemplates, RuntimeBoolean, RuntimePositiveInteger,
    RuntimeTimeoutTemplate, SecretBinding, SemanticStep, Sha256Digest, ShellTemplate, StepId,
    StepIr, StrategyContext, ValueTemplate, ValueTemplateSegment,
};
use automata_ci_expression_github::{GithubObject, GithubValue, MapContext};
use automata_ci_job_executor_github::{
    GithubContextPort, GithubContextRequest, GithubContextSnapshot, JobContentPort, PortError,
    PortErrorKind, SecretCustodyAcknowledger,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_runner_runtime::{
    ExecutionCancellation, ExecutionEvents, ExecutorError, ExecutorErrorKind, JobExecutor,
};
use automata_ci_workflow_github::{GithubConditionCompiler, GithubConditionPhase};
use bytes::Bytes;
use tokio_util::sync::CancellationToken;

use support::{
    FakeProvider, Fixture, JOB_RUNTIME_CONTEXT_MEDIA_TYPE, PhaseResponse, SECRET,
    encode_runtime_context, envelope_with_runtime_context_and_working_directory,
    envelope_with_runtime_context_reference, runtime_context_reference,
};

const SECRET_DERIVED_SENTINEL: &str = "classified-need-output-must-stay-opaque";

#[derive(Debug)]
struct PreExecutionAcknowledger {
    provider: Arc<FakeProvider>,
    calls: AtomicUsize,
}

#[async_trait]
impl SecretCustodyAcknowledger for PreExecutionAcknowledger {
    async fn acknowledge(&self, cancellation: CancellationToken) -> Result<(), ExecutorError> {
        assert!(!cancellation.is_cancelled());
        assert_eq!(self.provider.counts(), (0, 0, 0));
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn complete_custody_is_masked_and_acknowledged_before_provider_work() {
    let runtime_context_with_bindings = rich_runtime_context();
    let bindings = runtime_context_with_bindings.secrets().clone();
    let runtime_context = JobRuntimeContext::new(
        runtime_context_with_bindings.inputs().clone(),
        runtime_context_with_bindings.vars().clone(),
        runtime_context_with_bindings.matrix().clone(),
        runtime_context_with_bindings.strategy(),
        runtime_context_with_bindings.needs().clone(),
        BTreeMap::new(),
    )
    .expect("secretless immutable context");
    let encoded = encode_runtime_context(&runtime_context);
    let reference = runtime_context_reference(&encoded);
    let content = Arc::new(RecordingContent::bytes(encoded));
    let contexts = Arc::new(CapturingContexts::default());
    let fixture = Fixture::with_content_and_contexts(
        Vec::new(),
        vec![PhaseResponse::success().with_stdout(format!("{SECRET}\n"))],
        content,
        contexts,
    );
    let acknowledger = Arc::new(PreExecutionAcknowledger {
        provider: Arc::clone(&fixture.provider),
        calls: AtomicUsize::new(0),
    });
    let fixture = fixture.with_managed_secret_custody(acknowledger.clone(), bindings);
    let job = envelope_with_runtime_context_reference(vec![minimal_step()], reference);
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect("masked custody executes");

    assert_eq!(acknowledger.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.provider.counts(), (1, 1, 0));
    assert_eq!(fixture.events.logs()[0].payload(), b"***\n");
}

#[tokio::test]
async fn exact_runtime_context_is_fetched_once_and_borrowed_by_phase_snapshots() {
    let runtime_context = rich_runtime_context();
    let encoded = encode_runtime_context(&runtime_context);
    let reference = runtime_context_reference(&encoded);
    let content = Arc::new(RecordingContent::bytes(encoded));
    let contexts = Arc::new(CapturingContexts::default());
    let fixture = Fixture::with_content_and_contexts(
        Vec::new(),
        Vec::new(),
        content.clone(),
        contexts.clone(),
    );
    let job = envelope_with_runtime_context_reference(vec![minimal_step()], reference.clone());
    fixture
        .executor
        .admit(&job)
        .expect("valid v5 job is admitted");
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect("runtime context hydrates");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert_eq!(contexts.captured().len(), 3);
    assert!(
        contexts
            .captured()
            .iter()
            .all(|captured| captured == &runtime_context)
    );
    assert_eq!(
        contexts.captured()[0].secrets()["DEPLOY_KEY"].binding_id(),
        "secret/deploy-key"
    );
    assert_eq!(
        contexts.captured()[0].needs()["build"].outputs()["private"].public_value(),
        None
    );
    let requested = content.requested();
    assert_eq!(requested.len(), 2);
    assert_eq!(requested[0], reference);
    assert_eq!(requested[1].media_type(), "application/json");
    assert_eq!(fixture.provider.counts(), (1, 1, 0));
}

#[tokio::test]
async fn v5_step_templates_and_runtime_boolean_resolve_from_hydrated_context() {
    let runtime_context = rich_runtime_context();
    let encoded = encode_runtime_context(&runtime_context);
    let reference = runtime_context_reference(&encoded);
    let content = Arc::new(RecordingContent::bytes(encoded));
    let contexts = Arc::new(CapturingContexts::default());
    let mut response = PhaseResponse::success();
    response.termination = automata_ci_execution::ExecutionTermination::Exited(1);
    let fixture = Fixture::with_content_and_contexts(Vec::new(), vec![response], content, contexts);
    let compiler = GithubConditionCompiler::default();
    let expression = |source: &str| {
        compiler
            .compile_value_expression(&format!("${{{{ {source} }}}}"), GithubConditionPhase::Step)
            .expect("runtime expression")
    };
    let command = ValueTemplate::new(vec![
        ValueTemplateSegment::literal("echo "),
        ValueTemplateSegment::expression(expression("matrix.os")),
        ValueTemplateSegment::literal("-"),
        ValueTemplateSegment::expression(expression("matrix.shard")),
        ValueTemplateSegment::literal("-"),
        ValueTemplateSegment::expression(expression("needs.build.outputs.artifact")),
    ])
    .expect("command template");
    let values = RunValueTemplates::new(
        command,
        ShellTemplate::dynamic(
            ValueTemplate::expression(expression("vars.shell")).expect("shell template"),
        ),
    );
    let step = StepIr::new(
        StepId::new("dynamic").expect("step ID"),
        ValueTemplate::expression(expression("vars.step_name")).expect("step name template"),
        RuntimeBoolean::expression(expression("inputs.deploy")),
        SemanticStep::run(values),
    )
    .with_timeout(RuntimeTimeoutTemplate::minutes(
        RuntimePositiveInteger::expression(expression("vars.timeout")),
    ))
    .with_condition(
        compiler
            .compile_condition(Some("inputs.deploy"), GithubConditionPhase::Step)
            .expect("step condition"),
    );
    let job = envelope_with_runtime_context_and_working_directory(
        vec![step],
        reference,
        ValueTemplate::expression(expression("vars.workdir")).expect("working-directory template"),
    );
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect("dynamic run step executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert_eq!(result.steps()[0].outcome(), JobConclusion::Failure);
    assert_eq!(result.steps()[0].conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert_eq!(state.scripts, [b"echo linux-2-bundle-42".to_vec()]);
    let command = state
        .commands
        .iter()
        .find(|command| command.argv().program().as_str() == "/usr/bin/bash")
        .expect("resolved bash command");
    assert_eq!(
        command.working_directory().as_str(),
        "/__w/automata/automata/subdir"
    );
    assert_eq!(command.timeout(), std::time::Duration::from_mins(1));
}

#[tokio::test]
async fn invalid_deferred_step_name_fails_before_user_code_runs() {
    let runtime_context = rich_runtime_context();
    let encoded = encode_runtime_context(&runtime_context);
    let reference = runtime_context_reference(&encoded);
    let content = Arc::new(RecordingContent::bytes(encoded));
    let contexts = Arc::new(CapturingContexts::default());
    let fixture = Fixture::with_content_and_contexts(Vec::new(), Vec::new(), content, contexts);
    let expression = GithubConditionCompiler::default()
        .compile_value_expression("${{ fromJSON('not-json') }}", GithubConditionPhase::Step)
        .expect("deferred name expression");
    let step = StepIr::new(
        StepId::new("invalid-name").expect("step ID"),
        ValueTemplate::expression(expression).expect("step name template"),
        RuntimeBoolean::literal(false),
        SemanticStep::run(RunValueTemplates::new(
            ValueTemplate::literal("must-not-run").expect("command template"),
            ShellTemplate::default_shell(),
        )),
    );
    let job = envelope_with_runtime_context_reference(vec![step], reference);
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let error = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect_err("invalid deferred step name must fail closed");

    assert_eq!(error.kind(), ExecutorErrorKind::InvalidJob);
    assert!(
        fixture
            .endpoint_state
            .lock()
            .expect("endpoint lock")
            .scripts
            .is_empty()
    );
}

#[test]
fn wrong_media_type_and_oversized_descriptors_fail_admission() {
    let fixture = Fixture::new(Vec::new(), Vec::new());
    let encoded = encode_runtime_context(&rich_runtime_context());
    let valid = runtime_context_reference(&encoded);
    let wrong_media = JobContentReference::new(
        valid.object_key(),
        valid.digest(),
        valid.encoded_size(),
        "application/octet-stream",
    );
    let wrong_media_job =
        envelope_with_runtime_context_reference(vec![minimal_step()], wrong_media);
    assert!(fixture.executor.admit(&wrong_media_job).is_err());

    let oversized = JobContentReference::new(
        valid.object_key(),
        valid.digest(),
        u64::try_from(ProtocolLimits::default().max_frame_bytes()).expect("frame limit") + 1,
        JOB_RUNTIME_CONTEXT_MEDIA_TYPE,
    );
    let oversized_job = envelope_with_runtime_context_reference(vec![minimal_step()], oversized);
    assert!(fixture.executor.admit(&oversized_job).is_err());
    assert_eq!(fixture.provider.counts(), (0, 0, 0));
}

#[tokio::test]
async fn missing_size_and_digest_mismatches_fail_before_sandbox_creation() {
    let encoded = encode_runtime_context(&rich_runtime_context());
    let valid = runtime_context_reference(&encoded);

    assert_pre_sandbox_failure(
        valid.clone(),
        RuntimeReply::Error(PortErrorKind::NotFound),
        ExecutorErrorKind::InvalidJob,
    )
    .await;

    let wrong_size = JobContentReference::new(
        valid.object_key(),
        valid.digest(),
        valid.encoded_size() + 1,
        JOB_RUNTIME_CONTEXT_MEDIA_TYPE,
    );
    assert_pre_sandbox_failure(
        wrong_size,
        RuntimeReply::Bytes(encoded.clone()),
        ExecutorErrorKind::InvalidJob,
    )
    .await;

    let wrong_digest = JobContentReference::new(
        valid.object_key(),
        Sha256Digest::from_bytes([0xa7; 32]),
        valid.encoded_size(),
        JOB_RUNTIME_CONTEXT_MEDIA_TYPE,
    );
    assert_pre_sandbox_failure(
        wrong_digest,
        RuntimeReply::Bytes(encoded),
        ExecutorErrorKind::InvalidJob,
    )
    .await;
}

#[tokio::test]
async fn malformed_and_unsupported_context_versions_fail_before_sandbox_creation() {
    let malformed = Bytes::from_static(&[0xff]);
    assert_pre_sandbox_failure(
        runtime_context_reference(&malformed),
        RuntimeReply::Bytes(malformed),
        ExecutorErrorKind::InvalidJob,
    )
    .await;

    let mut unsupported = encode_runtime_context(&rich_runtime_context()).to_vec();
    assert_eq!(
        unsupported.first(),
        Some(&0x08),
        "schema field must be first"
    );
    assert_eq!(unsupported.get(1), Some(&0x02), "fixture schema is v2");
    unsupported[1] = 0x03;
    let unsupported = Bytes::from(unsupported);
    assert_pre_sandbox_failure(
        runtime_context_reference(&unsupported),
        RuntimeReply::Bytes(unsupported),
        ExecutorErrorKind::InvalidJob,
    )
    .await;
}

async fn assert_pre_sandbox_failure(
    reference: JobContentReference,
    reply: RuntimeReply,
    expected: ExecutorErrorKind,
) {
    let content = Arc::new(RecordingContent::new(reply));
    let contexts = Arc::new(CapturingContexts::default());
    let fixture = Fixture::with_content_and_contexts(
        Vec::new(),
        Vec::new(),
        content.clone(),
        contexts.clone(),
    );
    let job = envelope_with_runtime_context_reference(vec![minimal_step()], reference);
    fixture
        .executor
        .admit(&job)
        .expect("descriptor is structurally admissible");
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let error = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect_err("invalid runtime context must fail closed");

    assert_eq!(error.kind(), expected);
    assert_eq!(content.requested().len(), 1);
    assert_eq!(fixture.provider.counts(), (0, 0, 0));
    assert!(contexts.captured().is_empty());
}

fn minimal_step() -> StepIr {
    StepIr::new(
        StepId::new("run").expect("step ID"),
        ValueTemplate::literal("Run").expect("step name template"),
        RuntimeBoolean::literal(false),
        SemanticStep::run(RunValueTemplates::new(
            ValueTemplate::literal("true").expect("command template"),
            ShellTemplate::default_shell(),
        )),
    )
}

fn rich_runtime_context() -> JobRuntimeContext {
    let inputs = ContextValue::object(BTreeMap::from([(
        "deploy".to_owned(),
        ContextValue::boolean(true),
    )]))
    .expect("inputs");
    let vars = ContextValue::object(BTreeMap::from([
        ("channel".to_owned(), ContextValue::string("stable")),
        ("shell".to_owned(), ContextValue::string("bash")),
        ("step_name".to_owned(), ContextValue::string("Dynamic")),
        ("timeout".to_owned(), ContextValue::number(1.0)),
        ("workdir".to_owned(), ContextValue::string("subdir")),
    ]))
    .expect("vars");
    let matrix = ContextValue::object(BTreeMap::from([
        ("os".to_owned(), ContextValue::string("linux")),
        ("shard".to_owned(), ContextValue::number(2.0)),
    ]))
    .expect("matrix");
    let needs = BTreeMap::from([(
        "build".to_owned(),
        NeedContext::new(
            JobConclusion::Success,
            BTreeMap::from([
                (
                    "artifact".to_owned(),
                    NeedOutput::new("bundle-42", OutputSensitivity::Public).expect("public output"),
                ),
                (
                    "private".to_owned(),
                    NeedOutput::new(SECRET_DERIVED_SENTINEL, OutputSensitivity::SecretDerived)
                        .expect("classified output"),
                ),
            ]),
        )
        .expect("need context"),
    )]);
    let secrets = BTreeMap::from([(
        "DEPLOY_KEY".to_owned(),
        SecretBinding::new("secret/deploy-key")
            .and_then(|binding| binding.with_version_id("version-7"))
            .expect("secret binding"),
    )]);
    JobRuntimeContext::new(
        inputs,
        vars,
        matrix,
        StrategyContext::new(false, 0, 1, 1).expect("strategy"),
        needs,
        secrets,
    )
    .expect("runtime context")
}

enum RuntimeReply {
    Bytes(Bytes),
    Error(PortErrorKind),
}

struct RecordingContent {
    reply: RuntimeReply,
    requested: Mutex<Vec<JobContentReference>>,
}

impl RecordingContent {
    fn new(reply: RuntimeReply) -> Self {
        Self {
            reply,
            requested: Mutex::new(Vec::new()),
        }
    }

    fn bytes(bytes: Bytes) -> Self {
        Self::new(RuntimeReply::Bytes(bytes))
    }

    fn requested(&self) -> Vec<JobContentReference> {
        self.requested.lock().expect("content lock").clone()
    }
}

impl fmt::Debug for RecordingContent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingContent")
            .field(
                "requested",
                &self.requested.lock().expect("content lock").len(),
            )
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl JobContentPort for RecordingContent {
    async fn load(&self, reference: &JobContentReference) -> Result<Bytes, PortError> {
        self.requested
            .lock()
            .expect("content lock")
            .push(reference.clone());
        if reference.media_type() == "application/json" {
            return Ok(Bytes::from_static(b"{}"));
        }
        match &self.reply {
            RuntimeReply::Bytes(bytes) => Ok(bytes.clone()),
            RuntimeReply::Error(kind) => Err(PortError::new(*kind)),
        }
    }
}

#[derive(Default)]
struct CapturingContexts {
    captured: Mutex<Vec<JobRuntimeContext>>,
}

impl CapturingContexts {
    fn captured(&self) -> Vec<JobRuntimeContext> {
        self.captured.lock().expect("context lock").clone()
    }
}

impl fmt::Debug for CapturingContexts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturingContexts")
            .field(
                "snapshots",
                &self.captured.lock().expect("context lock").len(),
            )
            .finish_non_exhaustive()
    }
}

impl GithubContextPort for CapturingContexts {
    fn snapshot(
        &self,
        request: GithubContextRequest<'_>,
    ) -> Result<GithubContextSnapshot, PortError> {
        self.captured
            .lock()
            .expect("context lock")
            .push(request.runtime_context().clone());
        let context = MapContext::without_extensions(
            runtime_named_values(request.runtime_context())?,
            request.status(),
        )
        .map_err(|_| PortError::new(PortErrorKind::Internal))?;
        Ok(GithubContextSnapshot::new(Arc::new(context), Vec::new()))
    }
}

fn runtime_named_values(
    runtime: &JobRuntimeContext,
) -> Result<BTreeMap<String, GithubValue>, PortError> {
    let strategy = runtime.strategy();
    let needs = runtime
        .needs()
        .iter()
        .map(|(name, need)| {
            let outputs = github_object(
                need.outputs()
                    .iter()
                    .filter_map(|(name, output)| {
                        output
                            .public_value()
                            .map(|value| (name.clone(), GithubValue::string(value)))
                    })
                    .collect(),
            )?;
            let result = match need.result() {
                JobConclusion::Success => "success",
                JobConclusion::Failure | JobConclusion::TimedOut => "failure",
                JobConclusion::Cancelled => "cancelled",
                JobConclusion::Skipped => "skipped",
            };
            github_object(vec![
                ("result".to_owned(), GithubValue::string(result)),
                ("outputs".to_owned(), outputs),
            ])
            .map(|value| (name.clone(), value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BTreeMap::from([
        ("inputs".to_owned(), github_context_value(runtime.inputs())?),
        ("vars".to_owned(), github_context_value(runtime.vars())?),
        ("matrix".to_owned(), github_context_value(runtime.matrix())?),
        (
            "strategy".to_owned(),
            github_object(vec![
                (
                    "fail-fast".to_owned(),
                    GithubValue::Boolean(strategy.fail_fast()),
                ),
                (
                    "job-index".to_owned(),
                    GithubValue::number(f64::from(strategy.job_index())),
                ),
                (
                    "job-total".to_owned(),
                    GithubValue::number(f64::from(strategy.job_total())),
                ),
                (
                    "max-parallel".to_owned(),
                    GithubValue::number(f64::from(strategy.max_parallel())),
                ),
            ])?,
        ),
        ("needs".to_owned(), github_object(needs)?),
        ("secrets".to_owned(), github_object(Vec::new())?),
    ]))
}

fn github_context_value(value: &ContextValue) -> Result<GithubValue, PortError> {
    match value {
        ContextValue::Null => Ok(GithubValue::Null),
        ContextValue::Boolean { value } => Ok(GithubValue::Boolean(*value)),
        ContextValue::Number { ieee754_bits } => {
            Ok(GithubValue::number(f64::from_bits(*ieee754_bits)))
        }
        ContextValue::String { value } => Ok(GithubValue::string(value)),
        ContextValue::Array { values } => GithubValue::array(
            values
                .iter()
                .map(github_context_value)
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(|_| PortError::new(PortErrorKind::InvalidData)),
        ContextValue::Object { values } => github_object(
            values
                .iter()
                .map(|(name, value)| github_context_value(value).map(|value| (name.clone(), value)))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    }
}

fn github_object(entries: Vec<(String, GithubValue)>) -> Result<GithubValue, PortError> {
    GithubObject::new(entries)
        .map(GithubValue::object)
        .map_err(|_| PortError::new(PortErrorKind::InvalidData))
}
