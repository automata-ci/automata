use std::{collections::BTreeMap, sync::Arc};

use automata_ci_core::{
    Architecture, ContextValue, EnvironmentProfile, EnvironmentProfileId, JobAuthorityProfile,
    JobContentReference, JobExecutionContext, JobId, JobIrEnvelope, JobPermissionGrant,
    JobPermissionRequest, JobValidationError, OperatingSystem, OutputSensitivity, PermissionLevel,
    RunnerFeature, RuntimePositiveInteger, RuntimeTimeoutUnit, SemanticStep, Sha256Digest,
    ShellTemplate, TransportProtocol, ValueSource, ValueTemplateSegment, WorkflowEventProvenance,
    WorkflowId, WorkflowJobKey, WorkflowPlan,
};
use automata_ci_expression_github::{GithubObject, GithubValue};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_workflow_github::{
    CompileWorkflowRequest, GithubRunnerProfileCatalog, GithubRunnerProfileMapping,
    GithubWorkflowCompiler, GithubWorkflowFrontend, ParseWorkflowRequest, SourceId, SourceOrigin,
    SourceProvenance, WorkflowFrontend as _,
};
use automata_ci_workflow_service::{
    ActivateLogicalJobRequest, ActivationStatus, GithubActivationContext,
    GithubLogicalActivationEvaluator, GithubLogicalJobProjector, JOB_RUNTIME_CONTEXT_MEDIA_TYPE,
    LogicalJobActivator, LogicalJobProjectionError, ProjectGithubLogicalJobRequest,
    UnsupportedLogicalJobSemantics, ValidatedLogicalPlan,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const REPOSITORY: &str = "synthetic/example";
const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const WORKFLOW_PATH: &str = ".github/workflows/synthetic.yml";
const GIT_REF: &str = "refs/heads/main";

const SOURCE: &str = r"name: Synthetic CI
on: workflow_dispatch
env:
  ROOT: root-${{ github.ref }}
defaults:
  run:
    working-directory: work
jobs:
  build:
    name: Build ${{ matrix.target }}
    runs-on: ${{ matrix.runner }}
    timeout-minutes: ${{ matrix.job_timeout }}
    strategy:
      matrix:
        target: [core]
        runner: [ubuntu-latest]
        job_timeout: [5]
        step_timeout: [2]
        experimental: [false]
        shell: [bash]
    services:
      database:
        image: registry.example/database@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
        env:
          DATABASE_NAME: ${{ matrix.target }}
          DATABASE_TOKEN: ${{ secrets.SYNTHETIC_TOKEN }}
        ports:
          - 5432:5432
          - 5353/udp
        options: --health-cmd 'ready --database core' --health-interval 5s --health-retries 3
    env:
      TARGET: ${{ matrix.target }}
    defaults:
      run:
        working-directory: work/${{ matrix.target }}
    outputs:
      digest: ${{ steps.produce.outputs.digest }}
      sensitive: ${{ secrets.SYNTHETIC_TOKEN }}
    steps:
      - id: produce
        name: Produce ${{ matrix.target }}
        timeout-minutes: ${{ matrix.step_timeout }}
        continue-on-error: ${{ matrix.experimental }}
        shell: ${{ matrix.shell }}
        env:
          TOKEN_HINT: ${{ secrets.SYNTHETIC_TOKEN }}
        run: echo ${{ matrix.target }}
      - name: Consume ${{ matrix.target }}
        uses: synthetic/example-action/subdir@0123456789abcdef
        with:
          label: artifact-${{ matrix.target }}
";

fn compile(source: &str) -> automata_ci_workflow_github::CompilationReport {
    let provenance = SourceProvenance::new(
        SourceId::new(WORKFLOW_PATH),
        SourceOrigin::Repository {
            repository: Arc::from(REPOSITORY),
            revision: Arc::from(REVISION),
            path: Arc::from(WORKFLOW_PATH),
        },
    );
    let parsed =
        GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(provenance, source));
    assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
    GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", "workflow_dispatch")
            .with_delivery_id("synthetic-projection")
            .with_commit_sha(REVISION)
            .with_git_ref(GIT_REF),
    ))
}

fn plan(source: &str) -> WorkflowPlan {
    let report = compile(source);
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    report.into_parts().0.expect("logical plan")
}

fn github_context() -> GithubActivationContext {
    GithubActivationContext::new(GithubValue::object(
        GithubObject::new(vec![
            (
                "event_name".to_owned(),
                GithubValue::string("workflow_dispatch"),
            ),
            ("ref".to_owned(), GithubValue::string(GIT_REF)),
            ("sha".to_owned(), GithubValue::string(REVISION)),
            ("repository".to_owned(), GithubValue::string(REPOSITORY)),
            ("workflow".to_owned(), GithubValue::string("Synthetic CI")),
            (
                "event".to_owned(),
                GithubValue::object(GithubObject::new(Vec::new()).expect("event")),
            ),
        ])
        .expect("github object"),
    ))
    .expect("activation context")
}

fn activate(plan: &WorkflowPlan) -> automata_ci_workflow_service::LogicalJobActivation {
    let validated = ValidatedLogicalPlan::new(plan).expect("validated plan");
    let job = validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");
    LogicalJobActivator::new(GithubLogicalActivationEvaluator::new(github_context()))
        .activate(ActivateLogicalJobRequest::new(
            job,
            &ContextValue::empty_object(),
            &ContextValue::empty_object(),
            &BTreeMap::new(),
            &BTreeMap::from([(
                "SYNTHETIC_TOKEN".to_owned(),
                automata_ci_core::SecretBinding::new("secret/synthetic").expect("secret binding"),
            )]),
            ActivationStatus::Success,
        ))
        .expect("activation")
}

fn activate_without_secrets(
    plan: &WorkflowPlan,
) -> automata_ci_workflow_service::LogicalJobActivation {
    let validated = ValidatedLogicalPlan::new(plan).expect("validated plan");
    let job = validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");
    LogicalJobActivator::new(GithubLogicalActivationEvaluator::new(github_context()))
        .activate(ActivateLogicalJobRequest::new(
            job,
            &ContextValue::empty_object(),
            &ContextValue::empty_object(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            ActivationStatus::Success,
        ))
        .expect("activation")
}

fn limits() -> ProtocolLimits {
    ProtocolLimits::new(
        16 * 1024 * 1024,
        automata_ci_core::MAX_CONTEXT_VALUE_NODES,
        automata_ci_core::MAX_CONTEXT_VALUE_TEXT_BYTES,
        1,
        1,
    )
    .expect("limits")
}

fn runtime_reference(
    instance: &automata_ci_workflow_service::ActivatedJobInstance,
) -> JobContentReference {
    let encoded = automata_ci_protocol_protobuf::encode_job_runtime_context(
        instance.runtime_context(),
        &limits(),
    )
    .expect("runtime context");
    JobContentReference::new(
        "runs/synthetic/runtime-context.pb",
        Sha256Digest::from_bytes(Sha256::digest(&encoded).into()),
        u64::try_from(encoded.len()).expect("encoded size"),
        JOB_RUNTIME_CONTEXT_MEDIA_TYPE,
    )
}

fn execution(instance: &automata_ci_workflow_service::ActivatedJobInstance) -> JobExecutionContext {
    JobExecutionContext::new(
        "Synthetic CI",
        GIT_REF,
        "/workspace/synthetic",
        JobContentReference::new(
            "runs/synthetic/event.json",
            Sha256Digest::from_bytes([7; 32]),
            2,
            "application/json",
        ),
        runtime_reference(instance),
    )
    .with_actor("synthetic-actor")
    .with_run_number(12)
    .with_run_attempt(1)
}

fn profiles() -> GithubRunnerProfileCatalog {
    GithubRunnerProfileCatalog::new([GithubRunnerProfileMapping::new(
        "ubuntu-latest",
        EnvironmentProfile::new(
            EnvironmentProfileId::new("github/ubuntu-24-04").expect("profile id"),
            Sha256Digest::from_bytes([3; 32]),
        ),
        OperatingSystem::Linux,
        Architecture::X86_64,
    )
    .expect("mapping")])
    .expect("catalog")
}

fn fixed_id<T>(value: u128, constructor: impl FnOnce(Uuid) -> T) -> T {
    constructor(Uuid::from_u128(value))
}

fn project_envelope(source: &str) -> JobIrEnvelope {
    let plan = plan(source);
    let activation = activate(&plan);
    let instance = &activation.instances()[0];
    let validated = ValidatedLogicalPlan::new(&plan).expect("validated plan");
    let job = validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");
    GithubLogicalJobProjector::new()
        .project(ProjectGithubLogicalJobRequest::new(
            job,
            instance,
            fixed_id(31, WorkflowId::from_uuid),
            fixed_id(32, automata_ci_core::RunId::from_uuid),
            fixed_id(33, JobId::from_uuid),
            execution(instance),
            &profiles(),
            JobAuthorityProfile::Standard,
        ))
        .expect("projection")
        .into_parts()
        .0
}

#[test]
#[allow(clippy::too_many_lines)]
fn activated_logical_job_projects_exactly_into_current_job_ir_and_runtime_context() {
    let plan = plan(SOURCE);
    let activation = activate(&plan);
    let [instance] = activation.instances() else {
        panic!("expected one matrix instance")
    };
    assert_eq!(instance.name(), "Build core");
    assert_eq!(instance.timeout_seconds(), Some(300));
    assert!(!instance.continue_on_error());

    let validated = ValidatedLogicalPlan::new(&plan).expect("validated plan");
    let job = validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");
    let projected = GithubLogicalJobProjector::new()
        .project(ProjectGithubLogicalJobRequest::new(
            job,
            instance,
            fixed_id(1, WorkflowId::from_uuid),
            fixed_id(2, automata_ci_core::RunId::from_uuid),
            fixed_id(3, JobId::from_uuid),
            execution(instance),
            &profiles(),
            JobAuthorityProfile::Standard,
        ))
        .expect("projection");

    let envelope = projected.envelope();
    assert_eq!(
        envelope.schema_version(),
        automata_ci_core::JOB_IR_SCHEMA_VERSION
    );
    assert_eq!(envelope.source().repository(), REPOSITORY);
    assert_eq!(envelope.source().revision(), REVISION);
    assert_eq!(envelope.source().workflow_path(), WORKFLOW_PATH);
    assert_eq!(
        envelope.execution().runtime_context().media_type(),
        JOB_RUNTIME_CONTEXT_MEDIA_TYPE
    );
    assert_eq!(envelope.job().name(), "Build core");
    assert_eq!(envelope.job().timeout_seconds(), Some(300));
    assert_eq!(envelope.job().instance_identity(), instance.identity());
    assert_eq!(
        envelope
            .job()
            .requirements()
            .environment_profile()
            .expect("profile")
            .id()
            .as_str(),
        "github/ubuntu-24-04"
    );
    assert!(matches!(
        envelope.job().environment().get("ROOT"),
        Some(ValueSource::Template(_))
    ));
    assert!(matches!(
        envelope.job().environment().get("TARGET"),
        Some(ValueSource::Template(_))
    ));
    assert!(envelope.job().working_directory_template().is_some());
    assert_eq!(envelope.job().output_definitions().len(), 2);
    assert_eq!(
        envelope.job().output_definitions()[0].sensitivity(),
        OutputSensitivity::Public
    );
    assert_eq!(
        envelope.job().output_definitions()[1].sensitivity(),
        OutputSensitivity::SecretDerived
    );
    let database = envelope
        .job()
        .services()
        .get("database")
        .expect("database service");
    assert_eq!(database.ports().len(), 2);
    assert_eq!(database.ports()[0].container_port(), 5432);
    assert_eq!(database.ports()[0].requested_host_port(), Some(5432));
    assert_eq!(database.ports()[0].protocol(), TransportProtocol::Tcp);
    assert_eq!(database.ports()[1].container_port(), 5353);
    assert_eq!(database.ports()[1].requested_host_port(), None);
    assert_eq!(database.ports()[1].protocol(), TransportProtocol::Udp);
    assert!(matches!(
        database.environment().get("DATABASE_TOKEN"),
        Some(ValueSource::Template(_))
    ));
    assert_eq!(database.options()[1], "ready --database core");

    let steps = envelope.job().steps();
    assert_eq!(steps.len(), 2);
    assert!(
        steps[0]
            .name_template()
            .segments()
            .iter()
            .any(|segment| matches!(segment, ValueTemplateSegment::Expression { .. }))
    );
    assert!(steps[0].condition().is_some());
    assert!(steps[0].continue_on_error().expression_program().is_some());
    let timeout = steps[0].timeout().expect("deferred timeout");
    assert_eq!(timeout.unit(), RuntimeTimeoutUnit::Minutes);
    assert!(matches!(
        timeout.value(),
        RuntimePositiveInteger::Expression { .. }
    ));
    assert!(matches!(
        steps[0].kind(),
        SemanticStep::Run { values }
            if matches!(values.shell(), ShellTemplate::Dynamic { .. })
                && values.working_directory().is_none()
    ));
    assert!(matches!(
        steps[1].kind(),
        SemanticStep::Action {
            reference: automata_ci_core::ActionReference::Repository {
                repository,
                revision,
                subpath: Some(subpath),
            },
            inputs,
        } if repository == "synthetic/example-action"
            && revision == "0123456789abcdef"
            && subpath == "subdir"
            && matches!(inputs.get("label"), Some(ValueSource::Template(_)))
    ));

    let decoded = automata_ci_protocol_protobuf::decode_job_runtime_context(
        projected.runtime_context_bytes(),
        &limits(),
    )
    .expect("decode runtime context");
    assert_eq!(&decoded, instance.runtime_context());
    assert_eq!(projected.runtime_context(), instance.runtime_context());
    assert!(!format!("{projected:?}").contains("secret/synthetic"));
}

#[test]
fn credential_free_projection_is_explicit_deny_all_and_rejects_legacy_or_secretful_jobs() {
    let clean_source = r"on: workflow_dispatch
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{run: echo public}]
";
    let clean_plan = plan(clean_source);
    let activation = activate_without_secrets(&clean_plan);
    let instance = &activation.instances()[0];
    let validated = ValidatedLogicalPlan::new(&clean_plan).expect("validated plan");
    let job = validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");
    let projected = GithubLogicalJobProjector::new()
        .project(ProjectGithubLogicalJobRequest::new(
            job,
            instance,
            fixed_id(41, WorkflowId::from_uuid),
            fixed_id(42, automata_ci_core::RunId::from_uuid),
            fixed_id(43, JobId::from_uuid),
            execution(instance),
            &profiles(),
            JobAuthorityProfile::CredentialFree,
        ))
        .expect("explicit credential-free projection");
    assert_eq!(
        projected.envelope().job().authority_profile(),
        JobAuthorityProfile::CredentialFree
    );
    assert_eq!(
        projected.envelope().job().permission_request(),
        &JobPermissionRequest::Mapping(Vec::new())
    );
    assert!(projected.runtime_context().secrets().is_empty());

    let legacy_plan = plan(
        r"on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{run: echo public}]
",
    );
    let legacy_activation = activate_without_secrets(&legacy_plan);
    let legacy_instance = &legacy_activation.instances()[0];
    let legacy_validated = ValidatedLogicalPlan::new(&legacy_plan).expect("validated plan");
    let legacy_job = legacy_validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");
    let error = GithubLogicalJobProjector::new()
        .project(ProjectGithubLogicalJobRequest::new(
            legacy_job,
            legacy_instance,
            fixed_id(44, WorkflowId::from_uuid),
            fixed_id(45, automata_ci_core::RunId::from_uuid),
            fixed_id(46, JobId::from_uuid),
            execution(legacy_instance),
            &profiles(),
            JobAuthorityProfile::CredentialFree,
        ))
        .expect_err("provider-default permissions are not credential-free");
    assert!(matches!(
        error,
        LogicalJobProjectionError::InvalidJobIr(JobValidationError::CredentialFreePermissions)
    ));

    let secret_plan = plan(SOURCE);
    let secret_activation = activate(&secret_plan);
    let secret_instance = &secret_activation.instances()[0];
    let secret_validated = ValidatedLogicalPlan::new(&secret_plan).expect("validated plan");
    let secret_job = secret_validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");
    let error = GithubLogicalJobProjector::new()
        .project(ProjectGithubLogicalJobRequest::new(
            secret_job,
            secret_instance,
            fixed_id(47, WorkflowId::from_uuid),
            fixed_id(48, automata_ci_core::RunId::from_uuid),
            fixed_id(49, JobId::from_uuid),
            execution(secret_instance),
            &profiles(),
            JobAuthorityProfile::CredentialFree,
        ))
        .expect_err("runtime secret bindings are never credential-free");
    assert!(matches!(
        error,
        LogicalJobProjectionError::CredentialFreeRuntimeSecrets
    ));
}

#[test]
fn runtime_context_reference_must_match_exact_canonical_bytes() {
    let plan = plan(SOURCE);
    let activation = activate(&plan);
    let instance = &activation.instances()[0];
    let validated = ValidatedLogicalPlan::new(&plan).expect("validated plan");
    let job = validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");
    let mut mismatched = execution(instance);
    mismatched = JobExecutionContext::new(
        mismatched.workflow_name(),
        mismatched.git_ref(),
        mismatched.workspace(),
        mismatched.event().clone(),
        JobContentReference::new(
            "runs/synthetic/runtime-context.pb",
            Sha256Digest::from_bytes([9; 32]),
            mismatched.runtime_context().encoded_size(),
            JOB_RUNTIME_CONTEXT_MEDIA_TYPE,
        ),
    );
    let error = GithubLogicalJobProjector::new()
        .project(ProjectGithubLogicalJobRequest::new(
            job,
            instance,
            fixed_id(11, WorkflowId::from_uuid),
            fixed_id(12, automata_ci_core::RunId::from_uuid),
            fixed_id(13, JobId::from_uuid),
            mismatched,
            &profiles(),
            JobAuthorityProfile::Standard,
        ))
        .expect_err("mismatched runtime context");
    assert!(matches!(
        error,
        LogicalJobProjectionError::RuntimeContextReferenceMismatch
    ));
}

#[test]
fn permission_requests_resolve_job_over_workflow_without_source_spans() {
    let default = project_envelope(
        r"on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{run: echo ok}]
",
    );
    assert_eq!(
        default.job().permission_request(),
        &JobPermissionRequest::ProviderDefault
    );
    assert_eq!(default.job().timeout_seconds(), Some(360 * 60));

    let inherited_read = project_envelope(
        r"on: workflow_dispatch
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{run: echo ok}]
",
    );
    assert_eq!(
        inherited_read.job().permission_request(),
        &JobPermissionRequest::ReadAll
    );

    let inherited_write = project_envelope(
        r"on: workflow_dispatch
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{run: echo ok}]
",
    );
    assert_eq!(
        inherited_write.job().permission_request(),
        &JobPermissionRequest::WriteAll
    );

    let overridden = project_envelope(
        r"on: workflow_dispatch
permissions: write-all
jobs:
  build:
    permissions:
      statuses: write
      contents: read
      id-token: write
    runs-on: ubuntu-latest
    steps: [{run: echo ok}]
",
    );
    assert_eq!(
        overridden.job().permission_request(),
        &JobPermissionRequest::Mapping(vec![
            JobPermissionGrant::new("contents", PermissionLevel::Read),
            JobPermissionGrant::new("id-token", PermissionLevel::Write),
            JobPermissionGrant::new("statuses", PermissionLevel::Write),
        ])
    );
    let encoded = serde_json::to_value(overridden.job().permission_request())
        .expect("serialize permission request");
    assert_eq!(encoded["mode"], serde_json::json!("mapping"));
    assert!(encoded.to_string().find("span").is_none());
    assert!(encoded.to_string().find(WORKFLOW_PATH).is_none());

    let empty_override = project_envelope(
        r"on: workflow_dispatch
permissions: write-all
jobs:
  build:
    permissions: {}
    runs-on: ubuntu-latest
    steps: [{run: echo ok}]
",
    );
    assert_eq!(
        empty_override.job().permission_request(),
        &JobPermissionRequest::Mapping(Vec::new())
    );

    let empty_workflow = project_envelope(
        r"on: workflow_dispatch
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{run: echo ok}]
",
    );
    assert_eq!(
        empty_workflow.job().permission_request(),
        &JobPermissionRequest::Mapping(Vec::new())
    );
}

#[test]
fn oidc_write_permission_requires_the_runner_capability() {
    let cases = [
        (
            r"on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{run: echo ok}]
",
            false,
        ),
        (
            r"on: workflow_dispatch
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{run: echo ok}]
",
            false,
        ),
        (
            r"on: workflow_dispatch
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{run: echo ok}]
",
            true,
        ),
        (
            r"on: workflow_dispatch
jobs:
  build:
    permissions: {id-token: none}
    runs-on: ubuntu-latest
    steps: [{run: echo ok}]
",
            false,
        ),
        (
            r"on: workflow_dispatch
jobs:
  build:
    permissions: {contents: write}
    runs-on: ubuntu-latest
    steps: [{run: echo ok}]
",
            false,
        ),
        (
            r"on: workflow_dispatch
jobs:
  build:
    permissions: {id-token: write}
    runs-on: [self-hosted, linux, x64]
    steps: [{run: echo ok}]
",
            true,
        ),
    ];
    for (source, expected) in cases {
        let envelope = project_envelope(source);
        assert_eq!(
            envelope
                .job()
                .requirements()
                .features()
                .contains(&RunnerFeature::OIDC_TOKENS),
            expected
        );
    }
}

#[test]
fn unsupported_deployment_and_reusable_semantics_are_not_dropped() {
    let cases = [
        (
            r"on: workflow_dispatch
jobs:
  build:
    environment: preview
    runs-on: linux
    steps: [{run: echo ok}]
",
            UnsupportedLogicalJobSemantics::Deployment,
        ),
        (
            r"on: workflow_dispatch
jobs:
  build:
    uses: synthetic/reusable/.github/workflows/build.yml@main
",
            UnsupportedLogicalJobSemantics::ReusableWorkflowJob,
        ),
    ];
    for (source, expected) in cases {
        let plan = plan(source);
        let activation = activate(&plan);
        let instance = &activation.instances()[0];
        let validated = ValidatedLogicalPlan::new(&plan).expect("validated plan");
        let job = validated
            .job(&WorkflowJobKey::new("build").expect("job key"))
            .expect("validated job");
        let error = GithubLogicalJobProjector::new()
            .project(ProjectGithubLogicalJobRequest::new(
                job,
                instance,
                fixed_id(21, WorkflowId::from_uuid),
                fixed_id(22, automata_ci_core::RunId::from_uuid),
                fixed_id(23, JobId::from_uuid),
                execution(instance),
                &profiles(),
                JobAuthorityProfile::Standard,
            ))
            .expect_err("unsupported semantics");
        assert!(matches!(
            error,
            LogicalJobProjectionError::Unsupported(actual) if actual == expected
        ));
    }
}

#[test]
fn job_containers_and_mutable_services_fail_before_the_logical_projection_boundary() {
    let report = compile(
        r"on: workflow_dispatch
jobs:
  build:
    runs-on: linux
    container: synthetic/image:1
    services:
      database: synthetic/database:1
    steps: [{run: echo ok}]
",
    );
    assert!(report.plan().is_none());
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "github.compile.job_container")
    );
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "github.compile.mutable_service_image")
    );
}
