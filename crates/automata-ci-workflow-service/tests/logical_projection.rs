use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use automata_ci_core::{
    Architecture, ContainerFeature, ContextValue, EnvironmentProfile, EnvironmentProfileId,
    IsolationLevel, JobAuthorityProfile, JobContentReference, JobExecutionContext, JobId,
    JobIrEnvelope, JobPermissionGrant, JobPermissionRequest, JobResourceAllocation,
    JobResourcePolicy, JobValidationError, OperatingSystem, OutputSensitivity, PermissionLevel,
    ResourceCapacity, RunnerFeature, RuntimePositiveInteger, RuntimeTimeoutUnit, SandboxFeature,
    SemanticStep, Sha256Digest, ShellTemplate, TransportProtocol, TrustActorEvidence,
    TrustActorKind, TrustAutomationKind, TrustEventKind, TrustEvidence, TrustOriginKind,
    TrustPolicy, TrustRepositoryEvidence, TrustSnapshot, ValueSource, ValueTemplateSegment,
    WorkflowEventProvenance, WorkflowId, WorkflowJobKey, WorkflowPlan,
};
use automata_ci_expression_github::{GithubObject, GithubValue};
use automata_ci_github_permissions::{
    GITHUB_WORKFLOW_PERMISSIONS, GithubDefaultWorkflowPermission,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_store::WorkflowPermissionPolicy;
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
const WORKFLOW_PATH: &str = ".ci/workflows/synthetic.yml";
const GIT_REF: &str = "refs/heads/main";

fn resource_policy() -> JobResourcePolicy {
    let defaults = JobResourceAllocation::new(
        ResourceCapacity::new(100, 256 * 1_024 * 1_024, 0, 0),
        ResourceCapacity::new(1_000, 1_024 * 1_024 * 1_024, 0, 0),
    )
    .expect("resource defaults");
    JobResourcePolicy::new(
        defaults,
        ResourceCapacity::new(100, 256 * 1_024 * 1_024, 0, 0),
        ResourceCapacity::new(4_000, 8 * 1_024 * 1_024 * 1_024, 0, 0),
    )
    .expect("resource policy")
}

fn permission_policy() -> WorkflowPermissionPolicy {
    WorkflowPermissionPolicy::from_github_default(GithubDefaultWorkflowPermission::Read)
        .expect("permission policy")
}

fn trusted_snapshot() -> TrustSnapshot {
    let repository = TrustRepositoryEvidence::new("42", "7").expect("repository evidence");
    TrustPolicy::current()
        .evaluate(
            TrustEvidence::new(
                TrustOriginKind::WorkflowDispatch,
                TrustEventKind::WorkflowDispatch,
            )
            .with_original_actor(
                TrustActorEvidence::new("100", TrustActorKind::User, TrustAutomationKind::None)
                    .expect("actor evidence"),
            )
            .with_repositories(repository.clone(), repository)
            .with_refs(GIT_REF, GIT_REF, GIT_REF)
            .with_revisions(REVISION, REVISION, REVISION)
            .with_fork(false),
        )
        .expect("trusted snapshot")
}

fn untrusted_automation_snapshot() -> TrustSnapshot {
    let repository = TrustRepositoryEvidence::new("42", "7").expect("repository evidence");
    TrustPolicy::current()
        .evaluate(
            TrustEvidence::new(
                TrustOriginKind::WorkflowDispatch,
                TrustEventKind::WorkflowDispatch,
            )
            .with_original_actor(
                TrustActorEvidence::new("101", TrustActorKind::Bot, TrustAutomationKind::Other)
                    .expect("actor evidence"),
            )
            .with_repositories(repository.clone(), repository)
            .with_refs(GIT_REF, GIT_REF, GIT_REF)
            .with_revisions(REVISION, REVISION, REVISION)
            .with_fork(false),
        )
        .expect("untrusted automation snapshot")
}

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
        uses: synthetic/example-action/subdir@0123456789abcdef0123456789abcdef01234567
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
    execution_with_workspace(instance, "/workspace/synthetic")
}

fn execution_with_workspace(
    instance: &automata_ci_workflow_service::ActivatedJobInstance,
    workspace: &str,
) -> JobExecutionContext {
    JobExecutionContext::new(
        "Synthetic CI",
        GIT_REF,
        workspace,
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
    project_envelope_with_profiles(source, &profiles())
}

fn project_envelope_with_profiles(
    source: &str,
    profiles: &GithubRunnerProfileCatalog,
) -> JobIrEnvelope {
    project_envelope_with_profiles_and_workspace(source, profiles, "/workspace/synthetic")
}

fn project_envelope_with_profiles_and_workspace(
    source: &str,
    profiles: &GithubRunnerProfileCatalog,
    workspace: &str,
) -> JobIrEnvelope {
    let plan = plan(source);
    let activation = activate(&plan);
    let instance = &activation.instances()[0];
    let validated = ValidatedLogicalPlan::new(&plan).expect("validated plan");
    let job = validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");
    GithubLogicalJobProjector::new()
        .project(
            ProjectGithubLogicalJobRequest::new(
                job,
                instance,
                fixed_id(31, WorkflowId::from_uuid),
                fixed_id(32, automata_ci_core::RunId::from_uuid),
                fixed_id(33, JobId::from_uuid),
                execution_with_workspace(instance, workspace),
                profiles,
                JobAuthorityProfile::Standard,
                &permission_policy(),
                resource_policy(),
            )
            .with_trust_snapshot(&trusted_snapshot()),
        )
        .expect("projection")
        .into_parts()
        .0
}

#[test]
fn env_shell_and_working_directory_follow_workflow_job_step_precedence() {
    let source = r"name: Synthetic CI
on: workflow_dispatch
env:
  SHARED: workflow
  WORKFLOW_ONLY: workflow-only
defaults:
  run:
    shell: bash
    working-directory: workflow-dir
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      SHARED: job
      JOB_ONLY: job-only
    defaults:
      run:
        shell: pwsh
        working-directory: job-dir
    steps:
      - run: echo inherited
        env:
          SHARED: step
          STEP_ONLY: step-only
      - run: echo explicit
        shell: python {0}
        working-directory: step-dir
";
    let envelope = project_envelope(source);
    let job = envelope.job();
    assert_literal_source(job.environment().get("SHARED"), "job");
    assert_literal_source(job.environment().get("WORKFLOW_ONLY"), "workflow-only");
    assert_literal_source(job.environment().get("JOB_ONLY"), "job-only");
    assert_eq!(
        literal_template(
            job.working_directory_template()
                .expect("job working-directory")
        ),
        "job-dir"
    );

    let [inherited, explicit] = job.steps() else {
        panic!("two projected steps expected")
    };
    assert_literal_source(inherited.environment().get("SHARED"), "step");
    assert_literal_source(inherited.environment().get("STEP_ONLY"), "step-only");
    assert!(inherited.environment().get("WORKFLOW_ONLY").is_none());
    let SemanticStep::Run { values } = inherited.kind() else {
        panic!("inherited run step")
    };
    assert!(
        matches!(values.shell(), ShellTemplate::Named { value } if literal_template(value) == "pwsh")
    );
    assert!(values.working_directory().is_none());

    let SemanticStep::Run { values } = explicit.kind() else {
        panic!("explicit run step")
    };
    assert!(
        matches!(values.shell(), ShellTemplate::CommandTemplate { value } if literal_template(value) == "python {0}")
    );
    assert_eq!(
        literal_template(
            values
                .working_directory()
                .expect("step working-directory override")
        ),
        "step-dir"
    );
}

#[test]
fn workflow_run_defaults_apply_when_the_job_has_no_override() {
    let source = r"name: Synthetic CI
on: workflow_dispatch
defaults:
  run:
    shell: bash
    working-directory: workflow-dir
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo inherited
";
    let envelope = project_envelope(source);
    assert_eq!(
        literal_template(
            envelope
                .job()
                .working_directory_template()
                .expect("workflow working-directory")
        ),
        "workflow-dir"
    );
    let SemanticStep::Run { values } = envelope.job().steps()[0].kind() else {
        panic!("run step")
    };
    assert!(
        matches!(values.shell(), ShellTemplate::Named { value } if literal_template(value) == "bash")
    );
}

fn assert_literal_source(source: Option<&ValueSource>, expected: &str) {
    assert!(matches!(source, Some(ValueSource::Literal(value)) if value == expected));
}

fn literal_template(template: &automata_ci_core::ValueTemplate) -> &str {
    let [segment] = template.segments() else {
        panic!("one literal segment expected")
    };
    segment.literal_value().expect("literal template")
}

#[test]
fn linux_projection_carries_every_static_runtime_requirement_through_protobuf() {
    let source = r"on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo default
      - shell: bash -e {0}
        run: echo bash
      - shell: python -u {0}
        run: print('python')
      - uses: ./actions/local
      - uses: synthetic/node/action@0123456789abcdef0123456789abcdef01234567
";
    let plan = plan(source);
    let activation = activate_without_secrets(&plan);
    let instance = &activation.instances()[0];
    let validated = ValidatedLogicalPlan::new(&plan).expect("validated plan");
    let job = validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");
    let projected = GithubLogicalJobProjector::new()
        .project(
            ProjectGithubLogicalJobRequest::new(
                job,
                instance,
                fixed_id(81, WorkflowId::from_uuid),
                fixed_id(82, automata_ci_core::RunId::from_uuid),
                fixed_id(83, JobId::from_uuid),
                execution(instance),
                &profiles(),
                JobAuthorityProfile::Standard,
                &permission_policy(),
                resource_policy(),
            )
            .with_runtime_features([
                RunnerFeature::JAVASCRIPT_ACTIONS,
                RunnerFeature::NODE24_ACTIONS,
                RunnerFeature::COMPOSITE_ACTIONS,
            ]),
        )
        .expect("projection");
    let expected = BTreeSet::from([
        RunnerFeature::SHELL_STEPS,
        RunnerFeature::DEFAULT_POSIX_SHELL,
        RunnerFeature::BASH_SHELL,
        RunnerFeature::PYTHON_SHELL,
        RunnerFeature::JAVASCRIPT_ACTIONS,
        RunnerFeature::NODE24_ACTIONS,
        RunnerFeature::COMPOSITE_ACTIONS,
        RunnerFeature::REPOSITORY_ACTIONS,
        RunnerFeature::LOCAL_ACTIONS,
        RunnerFeature::COMMAND_FILES,
        RunnerFeature::JOB_SUMMARIES,
    ]);
    assert_eq!(
        projected.envelope().job().requirements().features(),
        &expected
    );

    let encoded = automata_ci_protocol_protobuf::encode_job_ir(projected.envelope(), &limits())
        .expect("encode JobIR");
    let decoded =
        automata_ci_protocol_protobuf::decode_job_ir(&encoded, &limits()).expect("decode JobIR");
    assert_eq!(decoded.job().requirements().features(), &expected);
}

#[test]
fn windows_projection_carries_exact_shell_requirements_without_inventing_node() {
    let source = r"on: workflow_dispatch
jobs:
  build:
    runs-on: windows-latest
    steps:
      - run: Write-Output default
      - shell: pwsh
        run: Write-Output core
      - shell: powershell -File {0}
        run: Write-Output desktop
      - shell: cmd
        run: echo cmd
";
    let profiles = GithubRunnerProfileCatalog::new([GithubRunnerProfileMapping::new(
        "windows-latest",
        EnvironmentProfile::new(
            EnvironmentProfileId::new("github/windows-2025").expect("profile id"),
            Sha256Digest::from_bytes([8; 32]),
        ),
        OperatingSystem::Windows,
        Architecture::X86_64,
    )
    .expect("mapping")])
    .expect("profiles");
    let plan = plan(source);
    let activation = activate_without_secrets(&plan);
    let instance = &activation.instances()[0];
    let validated = ValidatedLogicalPlan::new(&plan).expect("validated plan");
    let job = validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");
    let execution = JobExecutionContext::new(
        "Synthetic CI",
        GIT_REF,
        r"C:\__w\synthetic",
        JobContentReference::new(
            "runs/synthetic/event.json",
            Sha256Digest::from_bytes([7; 32]),
            2,
            "application/json",
        ),
        runtime_reference(instance),
    );
    let projected = GithubLogicalJobProjector::new()
        .project(ProjectGithubLogicalJobRequest::new(
            job,
            instance,
            fixed_id(84, WorkflowId::from_uuid),
            fixed_id(85, automata_ci_core::RunId::from_uuid),
            fixed_id(86, JobId::from_uuid),
            execution,
            &profiles,
            JobAuthorityProfile::Standard,
            &permission_policy(),
            resource_policy(),
        ))
        .expect("Windows projection");
    assert_eq!(
        projected.envelope().job().requirements().features(),
        &BTreeSet::from([
            RunnerFeature::SHELL_STEPS,
            RunnerFeature::DEFAULT_WINDOWS_SHELL,
            RunnerFeature::PWSH_SHELL,
            RunnerFeature::WINDOWS_POWERSHELL_SHELL,
            RunnerFeature::CMD_SHELL,
            RunnerFeature::COMMAND_FILES,
            RunnerFeature::JOB_SUMMARIES,
        ])
    );
}

#[test]
fn invalid_literal_shell_is_rejected_during_projection_before_scheduling() {
    let source = r"on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - shell: fish
        run: echo unsupported
";
    let plan = plan(source);
    let activation = activate_without_secrets(&plan);
    let instance = &activation.instances()[0];
    let validated = ValidatedLogicalPlan::new(&plan).expect("validated plan");
    let job = validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");
    let error = GithubLogicalJobProjector::new()
        .project(ProjectGithubLogicalJobRequest::new(
            job,
            instance,
            fixed_id(87, WorkflowId::from_uuid),
            fixed_id(88, automata_ci_core::RunId::from_uuid),
            fixed_id(89, JobId::from_uuid),
            execution(instance),
            &profiles(),
            JobAuthorityProfile::Standard,
            &permission_policy(),
            resource_policy(),
        ))
        .expect_err("unknown literal shells fail before scheduling");
    assert!(matches!(error, LogicalJobProjectionError::InvalidShell));
}

#[test]
fn unsupported_matrix_resolved_shell_is_rejected_before_scheduling() {
    let plan = plan(&SOURCE.replace("shell: [bash]", "shell: [fish]"));
    let activation = activate(&plan);
    let instance = &activation.instances()[0];
    let validated = ValidatedLogicalPlan::new(&plan).expect("validated plan");
    let job = validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");
    let activation_evaluator = GithubLogicalActivationEvaluator::new(github_context());
    let error = GithubLogicalJobProjector::new()
        .project(
            ProjectGithubLogicalJobRequest::new(
                job,
                instance,
                fixed_id(90, WorkflowId::from_uuid),
                fixed_id(91, automata_ci_core::RunId::from_uuid),
                fixed_id(92, JobId::from_uuid),
                execution(instance),
                &profiles(),
                JobAuthorityProfile::Standard,
                &permission_policy(),
                resource_policy(),
            )
            .with_activation_evaluation(&activation_evaluator, ActivationStatus::Success),
        )
        .expect_err("matrix-resolved unsupported shells fail before scheduling");
    assert!(matches!(error, LogicalJobProjectionError::InvalidShell));
}

#[test]
fn mutable_repository_action_revision_is_rejected_before_scheduling() {
    let source = r"on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: synthetic/action@v1
";
    let plan = plan(source);
    let activation = activate_without_secrets(&plan);
    let instance = &activation.instances()[0];
    let validated = ValidatedLogicalPlan::new(&plan).expect("validated plan");
    let job = validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");
    let error = GithubLogicalJobProjector::new()
        .project(ProjectGithubLogicalJobRequest::new(
            job,
            instance,
            fixed_id(93, WorkflowId::from_uuid),
            fixed_id(94, automata_ci_core::RunId::from_uuid),
            fixed_id(95, JobId::from_uuid),
            execution(instance),
            &profiles(),
            JobAuthorityProfile::Standard,
            &permission_policy(),
            resource_policy(),
        ))
        .expect_err("mutable action revisions fail before scheduling");
    assert!(matches!(
        error,
        LogicalJobProjectionError::InvalidActionReference
    ));
}

#[test]
fn mapped_profile_preserves_multi_label_and_group_routing() {
    let source = r"name: Synthetic CI
on: workflow_dispatch
jobs:
  build:
    runs-on:
      group: trusted-builders
      labels: [self-hosted, linux, x64, standard-profile]
    steps: [{run: echo public}]
";
    let profile = EnvironmentProfile::new(
        EnvironmentProfileId::new("automata.test/linux-standard").expect("profile id"),
        Sha256Digest::from_bytes([4; 32]),
    );
    let profiles = GithubRunnerProfileCatalog::new([GithubRunnerProfileMapping::new(
        "standard-profile",
        profile.clone(),
        OperatingSystem::Linux,
        Architecture::X86_64,
    )
    .expect("profile mapping")
    .with_container_features([ContainerFeature::DOCKER_COMPATIBLE_API])])
    .expect("profile catalog");

    let envelope = project_envelope_with_profiles(source, &profiles);
    let requirements = envelope.job().requirements();
    assert_eq!(requirements.environment_profile(), Some(&profile));
    assert_eq!(
        requirements.operating_system(),
        Some(&OperatingSystem::Linux)
    );
    assert_eq!(requirements.architecture(), Some(&Architecture::X86_64));
    assert_eq!(
        requirements
            .labels()
            .iter()
            .map(automata_ci_core::RunnerLabel::as_str)
            .collect::<Vec<_>>(),
        ["linux", "self-hosted", "x64"]
    );
    assert_eq!(
        requirements
            .eligible_groups()
            .iter()
            .map(automata_ci_core::RunnerGroup::as_str)
            .collect::<Vec<_>>(),
        ["trusted-builders"]
    );
    assert!(
        requirements
            .container_features()
            .contains(&ContainerFeature::DOCKER_COMPATIBLE_API)
    );
    assert_eq!(requirements.minimum_isolation(), IsolationLevel::Process);
    assert!(
        !requirements
            .sandbox_features()
            .contains(&SandboxFeature::WINDOWS_HYPERV_CONTAINER)
    );
}

#[test]
fn windows_profile_projection_requires_the_exact_hyperv_container_boundary() {
    let source = r"name: Synthetic CI
on: workflow_dispatch
jobs:
  build:
    runs-on: windows-2025
    steps: [{run: Write-Output ok}]
";
    let profile = EnvironmentProfile::new(
        EnvironmentProfileId::new("automata.test/windows-2025").expect("profile id"),
        Sha256Digest::from_bytes([0x25; 32]),
    );
    let profiles = GithubRunnerProfileCatalog::new([GithubRunnerProfileMapping::new(
        "windows-2025",
        profile.clone(),
        OperatingSystem::Windows,
        Architecture::X86_64,
    )
    .expect("Windows profile mapping")])
    .expect("profile catalog");

    let envelope =
        project_envelope_with_profiles_and_workspace(source, &profiles, "/__w/synthetic");
    let requirements = envelope.job().requirements();
    assert_eq!(requirements.environment_profile(), Some(&profile));
    assert_eq!(
        requirements.operating_system(),
        Some(&OperatingSystem::Windows)
    );
    assert_eq!(
        requirements.minimum_isolation(),
        IsolationLevel::VirtualMachine
    );
    assert!(
        requirements
            .sandbox_features()
            .contains(&SandboxFeature::WINDOWS_HYPERV_CONTAINER)
    );
}

#[test]
fn multiple_profile_selectors_remain_ambiguous() {
    let source = r"name: Synthetic CI
on: workflow_dispatch
jobs:
  build:
    runs-on: [self-hosted, linux, x64, profile-alpha, profile-beta]
    steps: [{run: echo public}]
";
    let profiles = GithubRunnerProfileCatalog::new(
        [
            ("profile-alpha", "automata.test/linux-alpha", 5),
            ("profile-beta", "automata.test/linux-beta", 6),
        ]
        .map(|(selector, id, digest)| {
            GithubRunnerProfileMapping::new(
                selector,
                EnvironmentProfile::new(
                    EnvironmentProfileId::new(id).expect("profile id"),
                    Sha256Digest::from_bytes([digest; 32]),
                ),
                OperatingSystem::Linux,
                Architecture::X86_64,
            )
            .expect("profile mapping")
        }),
    )
    .expect("profile catalog");
    let plan = plan(source);
    let activation = activate(&plan);
    let instance = &activation.instances()[0];
    let validated = ValidatedLogicalPlan::new(&plan).expect("validated plan");
    let job = validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");

    let error = GithubLogicalJobProjector::new()
        .project(
            ProjectGithubLogicalJobRequest::new(
                job,
                instance,
                fixed_id(34, WorkflowId::from_uuid),
                fixed_id(35, automata_ci_core::RunId::from_uuid),
                fixed_id(36, JobId::from_uuid),
                execution(instance),
                &profiles,
                JobAuthorityProfile::Standard,
                &permission_policy(),
                resource_policy(),
            )
            .with_trust_snapshot(&trusted_snapshot()),
        )
        .expect_err("two mapped selectors cannot choose one environment");
    assert!(matches!(
        error,
        LogicalJobProjectionError::AmbiguousRunnerProfile
    ));
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
    let activation_evaluator = GithubLogicalActivationEvaluator::new(github_context());
    let projected = GithubLogicalJobProjector::new()
        .project(
            ProjectGithubLogicalJobRequest::new(
                job,
                instance,
                fixed_id(1, WorkflowId::from_uuid),
                fixed_id(2, automata_ci_core::RunId::from_uuid),
                fixed_id(3, JobId::from_uuid),
                execution(instance),
                &profiles(),
                JobAuthorityProfile::Standard,
                &permission_policy(),
                resource_policy(),
            )
            .with_trust_snapshot(&trusted_snapshot())
            .with_activation_evaluation(&activation_evaluator, ActivationStatus::Success),
        )
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
            if matches!(values.shell(), ShellTemplate::Named { .. })
                && values.working_directory().is_none()
    ));
    assert!(
        envelope
            .job()
            .requirements()
            .features()
            .contains(&RunnerFeature::BASH_SHELL)
    );
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
            && revision == "0123456789abcdef0123456789abcdef01234567"
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
#[allow(clippy::too_many_lines)]
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
        .project(
            ProjectGithubLogicalJobRequest::new(
                job,
                instance,
                fixed_id(41, WorkflowId::from_uuid),
                fixed_id(42, automata_ci_core::RunId::from_uuid),
                fixed_id(43, JobId::from_uuid),
                execution(instance),
                &profiles(),
                JobAuthorityProfile::CredentialFree,
                &permission_policy(),
                resource_policy(),
            )
            .with_trust_snapshot(&trusted_snapshot()),
        )
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
        .project(
            ProjectGithubLogicalJobRequest::new(
                legacy_job,
                legacy_instance,
                fixed_id(44, WorkflowId::from_uuid),
                fixed_id(45, automata_ci_core::RunId::from_uuid),
                fixed_id(46, JobId::from_uuid),
                execution(legacy_instance),
                &profiles(),
                JobAuthorityProfile::CredentialFree,
                &permission_policy(),
                resource_policy(),
            )
            .with_trust_snapshot(&trusted_snapshot()),
        )
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
        .project(
            ProjectGithubLogicalJobRequest::new(
                secret_job,
                secret_instance,
                fixed_id(47, WorkflowId::from_uuid),
                fixed_id(48, automata_ci_core::RunId::from_uuid),
                fixed_id(49, JobId::from_uuid),
                execution(secret_instance),
                &profiles(),
                JobAuthorityProfile::CredentialFree,
                &permission_policy(),
                resource_policy(),
            )
            .with_trust_snapshot(&trusted_snapshot()),
        )
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
        .project(
            ProjectGithubLogicalJobRequest::new(
                job,
                instance,
                fixed_id(11, WorkflowId::from_uuid),
                fixed_id(12, automata_ci_core::RunId::from_uuid),
                fixed_id(13, JobId::from_uuid),
                mismatched,
                &profiles(),
                JobAuthorityProfile::Standard,
                &permission_policy(),
                resource_policy(),
            )
            .with_trust_snapshot(&trusted_snapshot()),
        )
        .expect_err("mismatched runtime context");
    assert!(matches!(
        error,
        LogicalJobProjectionError::RuntimeContextReferenceMismatch
    ));
}

#[test]
fn permission_requests_resolve_shorthands_and_job_precedence_without_source_spans() {
    let default = assert_projected_permissions(
        r"on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{run: echo ok}]
",
        &JobPermissionRequest::mapping([
            JobPermissionGrant::new("contents", PermissionLevel::Read),
            JobPermissionGrant::new("packages", PermissionLevel::Read),
        ]),
    );
    assert_eq!(default.job().timeout_seconds(), Some(360 * 60));

    assert_projected_permissions(
        r"on: workflow_dispatch
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{run: echo ok}]
",
        &catalog_read_all_request(),
    );

    assert_projected_permissions(
        r"on: workflow_dispatch
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{run: echo ok}]
",
        &catalog_write_all_request(),
    );

    let overridden = assert_projected_permissions(
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
        &JobPermissionRequest::mapping([
            JobPermissionGrant::new("contents", PermissionLevel::Read),
            JobPermissionGrant::new("id-token", PermissionLevel::Write),
            JobPermissionGrant::new("statuses", PermissionLevel::Write),
        ]),
    );
    let encoded = serde_json::to_value(overridden.job().permission_request())
        .expect("serialize permission request");
    assert_eq!(encoded["mode"], serde_json::json!("mapping"));
    assert!(encoded.to_string().find("span").is_none());
    assert!(encoded.to_string().find(WORKFLOW_PATH).is_none());

    assert_projected_permissions(
        r"on: workflow_dispatch
permissions: write-all
jobs:
  build:
    permissions: {}
    runs-on: ubuntu-latest
    steps: [{run: echo ok}]
",
        &JobPermissionRequest::mapping([]),
    );

    assert_projected_permissions(
        r"on: workflow_dispatch
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{run: echo ok}]
",
        &JobPermissionRequest::mapping([]),
    );
}

#[test]
fn trust_reduction_happens_before_job_ir_and_secret_materialization() {
    let clean_plan = plan(
        r"on: workflow_dispatch
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{run: echo ok}]
",
    );
    let activation = activate_without_secrets(&clean_plan);
    let instance = &activation.instances()[0];
    let validated = ValidatedLogicalPlan::new(&clean_plan).expect("validated plan");
    let job = validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");
    let snapshot = untrusted_automation_snapshot();
    let projected = GithubLogicalJobProjector::new()
        .project(
            ProjectGithubLogicalJobRequest::new(
                job,
                instance,
                fixed_id(51, WorkflowId::from_uuid),
                fixed_id(52, automata_ci_core::RunId::from_uuid),
                fixed_id(53, JobId::from_uuid),
                execution(instance),
                &profiles(),
                JobAuthorityProfile::Standard,
                &permission_policy(),
                resource_policy(),
            )
            .with_trust_snapshot(&snapshot),
        )
        .expect("untrusted projection");
    let job_ir = projected.envelope().job();
    assert_eq!(job_ir.trust_snapshot(), &snapshot);
    assert_eq!(
        job_ir.permission_request().requested_level("contents"),
        Some(PermissionLevel::Read)
    );
    assert_eq!(
        job_ir.permission_request().requested_level("id-token"),
        None
    );
    assert!(
        job_ir
            .permission_request()
            .grants()
            .expect("trust reduction is explicit")
            .iter()
            .all(|grant| grant.level() != PermissionLevel::Write)
    );
    assert!(
        !job_ir
            .requirements()
            .features()
            .contains(&RunnerFeature::OIDC_TOKENS)
    );

    let secret_plan = plan(SOURCE);
    let secret_activation = activate(&secret_plan);
    let secret_instance = &secret_activation.instances()[0];
    let secret_validated = ValidatedLogicalPlan::new(&secret_plan).expect("validated plan");
    let secret_job = secret_validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");
    let error = GithubLogicalJobProjector::new()
        .project(
            ProjectGithubLogicalJobRequest::new(
                secret_job,
                secret_instance,
                fixed_id(54, WorkflowId::from_uuid),
                fixed_id(55, automata_ci_core::RunId::from_uuid),
                fixed_id(56, JobId::from_uuid),
                execution(secret_instance),
                &profiles(),
                JobAuthorityProfile::Standard,
                &permission_policy(),
                resource_policy(),
            )
            .with_trust_snapshot(&snapshot),
        )
        .expect_err("untrusted jobs cannot materialize normal secrets");
    assert!(matches!(
        error,
        LogicalJobProjectionError::TrustDeniedRuntimeSecrets
    ));
}

fn assert_projected_permissions(source: &str, expected: &JobPermissionRequest) -> JobIrEnvelope {
    let envelope = project_envelope(source);
    assert_eq!(
        envelope.job().permission_request(),
        expected,
        "projected permission request"
    );
    envelope
}

fn catalog_read_all_request() -> JobPermissionRequest {
    JobPermissionRequest::mapping(
        GITHUB_WORKFLOW_PERMISSIONS
            .iter()
            .copied()
            .filter(|permission| permission.allows_read())
            .map(|permission| JobPermissionGrant::new(permission.name(), PermissionLevel::Read)),
    )
}

fn catalog_write_all_request() -> JobPermissionRequest {
    JobPermissionRequest::mapping(GITHUB_WORKFLOW_PERMISSIONS.iter().copied().filter_map(
        |permission| {
            let level = if permission.allows_write() {
                PermissionLevel::Write
            } else if permission.allows_read() {
                PermissionLevel::Read
            } else {
                return None;
            };
            Some(JobPermissionGrant::new(permission.name(), level))
        },
    ))
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
fn reusable_workflow_semantics_are_not_dropped_by_job_projection() {
    let source = r"on: workflow_dispatch
jobs:
  build:
    uses: synthetic/reusable/.github/workflows/build.yml@main
";
    let plan = plan(source);
    let activation = activate(&plan);
    let instance = &activation.instances()[0];
    let validated = ValidatedLogicalPlan::new(&plan).expect("validated plan");
    let job = validated
        .job(&WorkflowJobKey::new("build").expect("job key"))
        .expect("validated job");
    let error = GithubLogicalJobProjector::new()
        .project(
            ProjectGithubLogicalJobRequest::new(
                job,
                instance,
                fixed_id(21, WorkflowId::from_uuid),
                fixed_id(22, automata_ci_core::RunId::from_uuid),
                fixed_id(23, JobId::from_uuid),
                execution(instance),
                &profiles(),
                JobAuthorityProfile::Standard,
                &permission_policy(),
                resource_policy(),
            )
            .with_trust_snapshot(&trusted_snapshot()),
        )
        .expect_err("unsupported semantics");
    assert!(matches!(
        error,
        LogicalJobProjectionError::Unsupported(UnsupportedLogicalJobSemantics::ReusableWorkflowJob)
    ));
}

#[test]
fn reusable_callee_contract_does_not_block_step_job_projection() {
    let envelope = project_envelope(
        r"on:
  workflow_call:
    inputs:
      release:
        type: boolean
        required: true
  workflow_dispatch:
jobs:
  build:
    runs-on: linux
    steps: [{run: echo ok}]
",
    );
    assert_eq!(envelope.job().steps().len(), 1);
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
