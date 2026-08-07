use std::{fmt::Write as _, str::FromStr as _, sync::Arc};

use automata_core::{
    ActionReference, Architecture, ContainerFeature, EnvironmentProfile, EnvironmentProfileId,
    ExpressionInstruction, JobContentReference, JobId, OperatingSystem, PlanSourceOrigin, RunId,
    SemanticStep, Sha256Digest, ShellSpec, ValueSource, WorkflowEventProvenance, WorkflowId,
    WorkflowJobKey, WorkflowPlan,
};
use automata_workflow_github::{
    CompileWorkflowRequest, DEFAULT_GITHUB_LINUX_SHELL_TEMPLATE, EvaluateJobRequest,
    GithubJobContext, GithubJobEvaluator, GithubRunnerProfileCatalog, GithubRunnerProfileMapping,
    GithubTargetPathStyle, GithubWorkflowCompiler, GithubWorkflowFrontend, GithubWorkspacePath,
    JobEvaluationReport, ParseWorkflowRequest, SourceId, SourceOrigin, SourceProvenance,
    WorkflowFrontend, WorkflowJobEvaluator,
};
use sha2::{Digest as _, Sha256};

const REPOSITORY: &str = "GoNeuralAI/automata";
const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const GIT_REF: &str = "refs/heads/main";
const WORKFLOW_PATH: &str = ".github/workflows/ci.yml";
const WORKSPACE: &str = "/__automata/sandboxes/run-42/workspace";
const REPOSITORY_CI: &str = include_str!("../../../.github/workflows/ci.yml");
const VERIFY_GOLDEN: &str = include_str!("fixtures/ci-verify-job-ir-v4.golden");
const FRONTEND_GOLDEN: &str = include_str!("fixtures/ci-frontend-job-ir-v4.golden");
const DIST_GOLDEN: &str = include_str!("fixtures/ci-dist-job-ir-v4.golden");

fn workflow_id() -> WorkflowId {
    WorkflowId::from_str("00000000-0000-4000-8000-000000000001").expect("workflow UUID")
}

fn run_id() -> RunId {
    RunId::from_str("00000000-0000-4000-8000-000000000002").expect("run UUID")
}

fn job_id() -> JobId {
    JobId::from_str("00000000-0000-4000-8000-000000000003").expect("job UUID")
}

fn environment_profile() -> EnvironmentProfile {
    EnvironmentProfile::new(
        EnvironmentProfileId::new("github.com/ubuntu-24.04").expect("profile ID"),
        Sha256Digest::from_bytes([0x24; 32]),
    )
}

fn profile_catalog() -> GithubRunnerProfileCatalog {
    GithubRunnerProfileCatalog::new([GithubRunnerProfileMapping::new(
        "ubuntu-24.04",
        environment_profile(),
        OperatingSystem::Linux,
        Architecture::X86_64,
    )
    .expect("profile mapping")
    .with_container_features([ContainerFeature::DOCKER_COMPATIBLE_API])])
    .expect("profile catalog")
}

fn compile(source: &str) -> WorkflowPlan {
    let frontend = GithubWorkflowFrontend::default();
    let provenance = SourceProvenance::new(
        SourceId::new(WORKFLOW_PATH),
        SourceOrigin::Repository {
            repository: Arc::from(REPOSITORY),
            revision: Arc::from(REVISION),
            path: Arc::from(WORKFLOW_PATH),
        },
    );
    let parsed = frontend.parse(ParseWorkflowRequest::new(provenance, source));
    assert!(
        parsed.is_accepted(),
        "source diagnostics: {:#?}",
        parsed.diagnostics()
    );
    let compiled = GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", "push")
            .with_commit_sha(REVISION)
            .with_git_ref(GIT_REF),
    ));
    assert!(
        compiled.is_accepted(),
        "compile diagnostics: {:#?}",
        compiled.diagnostics()
    );
    compiled.into_parts().0.expect("workflow plan")
}

fn context(workflow_name: &str) -> GithubJobContext {
    GithubJobContext::builder(workflow_id(), run_id(), job_id())
        .repository(REPOSITORY)
        .commit_sha(REVISION)
        .git_ref(GIT_REF)
        .workflow_name(workflow_name)
        .workspace(unix_workspace())
        .event(event_reference())
        .build()
        .expect("evaluation context")
}

fn event_reference() -> JobContentReference {
    JobContentReference::new(
        "events/push.json",
        Sha256Digest::from_bytes(Sha256::digest(b"{}").into()),
        2,
        "application/json",
    )
}

fn unix_workspace() -> GithubWorkspacePath {
    GithubWorkspacePath::new(GithubTargetPathStyle::Unix, WORKSPACE).expect("Unix workspace")
}

fn evaluate_with_catalog(
    plan: &WorkflowPlan,
    job: &str,
    context: &GithubJobContext,
    catalog: &GithubRunnerProfileCatalog,
) -> JobEvaluationReport {
    let request = EvaluateJobRequest::new(
        plan,
        context,
        catalog,
        WorkflowJobKey::new(job).expect("job key"),
    );
    GithubJobEvaluator::new().evaluate(&request)
}

fn evaluate(plan: &WorkflowPlan, job: &str, workflow_name: &str) -> JobEvaluationReport {
    evaluate_with_catalog(plan, job, &context(workflow_name), &profile_catalog())
}

#[test]
fn evaluation_port_is_object_safe_for_orchestration_adapters() {
    let plan = compile(
        "name: Port\non: push\njobs:\n  verify:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo port\n",
    );
    let context = context("Port");
    let profiles = profile_catalog();
    let request = EvaluateJobRequest::new(
        &plan,
        &context,
        &profiles,
        WorkflowJobKey::new("verify").expect("job key"),
    );
    let evaluator: Box<dyn WorkflowJobEvaluator> = Box::new(GithubJobEvaluator::new());

    assert!(evaluator.evaluate(&request).is_accepted());
}

#[test]
fn supported_github_context_is_single_pass_and_opaque_to_injection() {
    let source = r"name: CI-${{ secrets.DO_NOT_EVALUATE }}
on: push
env:
  WORKFLOW: before-${{ github.workflow }}-after
  REF: ${{ github.ref }}
  SHA: ${{ github.sha }}
  WORKSPACE: ${{ github.workspace }}/target
  REPOSITORY: ${{ github.repository }}
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - run: echo safe
";
    let plan = compile(source);
    let report = evaluate(&plan, "verify", "CI-${{ secrets.DO_NOT_EVALUATE }}");
    assert!(
        report.is_accepted(),
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    let environment = report.envelope().expect("job").job().environment();
    assert_eq!(
        environment.get("WORKFLOW"),
        Some(&ValueSource::Literal(
            "before-CI-${{ secrets.DO_NOT_EVALUATE }}-after".to_owned()
        ))
    );
    assert_eq!(
        environment.get("REF"),
        Some(&ValueSource::Literal(GIT_REF.to_owned()))
    );
    assert_eq!(
        environment.get("SHA"),
        Some(&ValueSource::Literal(REVISION.to_owned()))
    );
    assert_eq!(
        environment.get("WORKSPACE"),
        Some(&ValueSource::Literal(format!("{WORKSPACE}/target")))
    );
    assert_eq!(
        environment.get("REPOSITORY"),
        Some(&ValueSource::Literal(REPOSITORY.to_owned()))
    );
}

#[test]
fn unsupported_functions_contexts_and_late_contexts_fail_with_source_spans() {
    let cases = [
        ("${{ secrets.TOKEN }}", "github.evaluate.late_context"),
        (
            "${{ format('{0}', github.sha) }}",
            "github.evaluate.unsupported_function",
        ),
        ("${{ github.actor }}", "github.evaluate.unsupported_context"),
    ];
    for (expression, code) in cases {
        let source = format!(
            "name: Unsupported\non: push\nenv:\n  BAD: \"{expression}\"\njobs:\n  verify:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo safe\n"
        );
        let plan = compile(&source);
        let report = evaluate(&plan, "verify", "Unsupported");
        assert!(report.envelope().is_none());
        let diagnostic = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code() == code)
            .unwrap_or_else(|| panic!("missing {code}: {:#?}", report.diagnostics()));
        assert_eq!(diagnostic.primary_span().start().line(), 4);
        assert_eq!(
            diagnostic.primary_span().source_id().as_str(),
            WORKFLOW_PATH
        );
    }
}

#[test]
fn environment_and_run_defaults_are_overlaid_workflow_then_job_then_step() {
    let source = r"name: Layers
on: push
env:
  SHARED: workflow
  WORKFLOW_ONLY: workflow
defaults:
  run:
    working-directory: workflow-dir
jobs:
  verify:
    runs-on: ubuntu-24.04
    env:
      SHARED: job
      JOB_ONLY: job
    defaults:
      run:
        working-directory: job-dir
    steps:
      - id: github_p_00000001
        name: Override
        env:
          SHARED: step
          STEP_ONLY: step
        working-directory: step-dir
        run: echo override
      - name: Inherit
        if: env.SHARED == 'job'
        run: echo inherit
";
    let plan = compile(source);
    let report = evaluate(&plan, "verify", "Layers");
    assert!(
        report.is_accepted(),
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    let job = report.envelope().expect("job").job();
    assert_eq!(job.working_directory(), Some("job-dir"));
    assert_eq!(
        job.environment().get("SHARED"),
        Some(&ValueSource::Literal("job".to_owned()))
    );
    assert_eq!(job.environment().len(), 3);
    assert_eq!(job.steps()[0].id().as_str(), "github_p_00000001");
    assert_eq!(job.steps()[1].id().as_str(), "github_p_00000001_1");
    assert_ne!(job.steps()[0].id(), job.steps()[1].id());
    assert_eq!(job.steps()[0].environment().len(), 4);
    assert_eq!(
        job.steps()[0].environment().get("SHARED"),
        Some(&ValueSource::Literal("step".to_owned()))
    );
    assert_eq!(
        job.steps()[0].environment().get("WORKFLOW_ONLY"),
        Some(&ValueSource::Literal("workflow".to_owned()))
    );
    assert_eq!(
        job.steps()[0].environment().get("JOB_ONLY"),
        Some(&ValueSource::Literal("job".to_owned()))
    );
    assert_eq!(
        job.steps()[0].environment().get("STEP_ONLY"),
        Some(&ValueSource::Literal("step".to_owned()))
    );
    let SemanticStep::Run {
        shell,
        working_directory,
        ..
    } = job.steps()[0].kind()
    else {
        panic!("run step");
    };
    assert_eq!(
        shell,
        &ShellSpec::CommandTemplate(DEFAULT_GITHUB_LINUX_SHELL_TEMPLATE.to_owned())
    );
    assert_eq!(working_directory.as_deref(), Some("step-dir"));
    let SemanticStep::Run {
        working_directory, ..
    } = job.steps()[1].kind()
    else {
        panic!("run step");
    };
    assert_eq!(working_directory.as_deref(), Some("job-dir"));
    assert_condition_source(job.steps()[1].condition(), "env.SHARED == 'job'");
}

#[test]
fn explicit_step_id_is_the_exact_semantic_expression_key() {
    let source = r"name: Step outputs
on: push
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - id: build
        run: echo build
      - if: steps.build.outputs.digest == 'expected'
        run: echo consume
";
    let plan = compile(source);
    let report = evaluate(&plan, "verify", "Step outputs");
    assert!(
        report.is_accepted(),
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    let steps = report.envelope().expect("job").job().steps();
    assert_eq!(steps[0].id().as_str(), "build");
    assert_condition_source(
        steps[1].condition(),
        "steps.build.outputs.digest == 'expected'",
    );
}

#[test]
fn job_condition_keeps_needs_access_late_bound_in_job_ir() {
    let source = r"name: Needs condition
on: push
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - run: echo build
  verify:
    needs: build
    if: needs.build.result == 'success'
    runs-on: ubuntu-24.04
    steps:
      - run: echo consume
";
    let plan = compile(source);
    let report = evaluate(&plan, "verify", "Needs condition");
    assert!(
        report.is_accepted(),
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    assert_condition_source(
        report.envelope().expect("job").job().condition(),
        "needs.build.result == 'success'",
    );
}

#[test]
fn invalid_condition_diagnostics_point_to_the_exact_operator() {
    let source = "name: Bad condition\non: push\njobs:\n  verify:\n    runs-on: ubuntu-24.04\n    steps:\n      - if: github.ref = 'main'\n        run: echo unreachable\n";
    let plan = compile(source);
    let report = evaluate(&plan, "verify", "Bad condition");
    assert!(report.envelope().is_none());
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code() == "github.expression.unexpected_symbol")
        .expect("expression diagnostic");
    let expected_offset = source.find("= 'main'").expect("operator offset");
    assert_eq!(
        diagnostic.primary_span().start().byte_offset(),
        expected_offset
    );
    assert_eq!(
        diagnostic.primary_span().end().byte_offset(),
        expected_offset + 1
    );
    assert_eq!(diagnostic.primary_span().start().line(), 7);
    assert_eq!(diagnostic.primary_span().start().column(), 24);
}

#[test]
fn quoted_expression_delimiters_survive_compile_and_evaluation() {
    let source = "name: Delimiter data\non: push\njobs:\n  verify:\n    runs-on: ubuntu-24.04\n    steps:\n      - if: contains('${{', '}}')\n        run: echo safe\n";
    let plan = compile(source);
    let report = evaluate(&plan, "verify", "Delimiter data");
    assert!(
        report.is_accepted(),
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    assert_condition_source(
        report.envelope().expect("JobIR").job().steps()[0].condition(),
        "contains('${{', '}}')",
    );
}

#[test]
fn action_references_parse_generically_and_preserve_revisions() {
    let source = r"name: Actions
on: push
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - uses: owner/repository/path/to/action@0123456789abcdef0123456789abcdef01234567
        with:
          boolean: false
          number: 42
      - uses: ./.github/actions/local
";
    let plan = compile(source);
    let report = evaluate(&plan, "verify", "Actions");
    assert!(
        report.is_accepted(),
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    let steps = report.envelope().expect("job").job().steps();
    let SemanticStep::Action { reference, inputs } = steps[0].kind() else {
        panic!("repository action");
    };
    assert_eq!(
        reference,
        &ActionReference::Repository {
            repository: "owner/repository".to_owned(),
            revision: REVISION.to_owned(),
            subpath: Some("path/to/action".to_owned()),
        }
    );
    assert_eq!(
        inputs.get("boolean"),
        Some(&ValueSource::Literal("false".to_owned()))
    );
    assert_eq!(
        inputs.get("number"),
        Some(&ValueSource::Literal("42".to_owned()))
    );
    let SemanticStep::Action { reference, .. } = steps[1].kind() else {
        panic!("local action");
    };
    assert_eq!(
        reference,
        &ActionReference::Local {
            path: "./.github/actions/local".to_owned()
        }
    );
}

#[test]
fn action_reference_traversal_and_malformed_revisions_fail_closed() {
    let cases = [
        ("./../outside", "github.evaluate.invalid_local_action"),
        (
            "owner/repository/../outside@v1",
            "github.evaluate.invalid_action_reference",
        ),
        (
            "owner/repository/path",
            "github.evaluate.invalid_action_reference",
        ),
        (
            "owner/repository/path@refs/heads/../evil",
            "github.evaluate.invalid_action_reference",
        ),
        (
            "owner:injected/repository@v1",
            "github.evaluate.invalid_action_reference",
        ),
        (
            "owner/repository@feature bad",
            "github.evaluate.invalid_action_reference",
        ),
        (
            "owner/repository@refs//heads/main",
            "github.evaluate.invalid_action_reference",
        ),
        (
            "owner/repository@refs/tags/release.lock",
            "github.evaluate.invalid_action_reference",
        ),
        (
            "owner/repository@refs/heads/.hidden",
            "github.evaluate.invalid_action_reference",
        ),
        (
            "owner/repository@-upload-pack=evil",
            "github.evaluate.invalid_action_reference",
        ),
    ];
    for (reference, code) in cases {
        let source = format!(
            "name: Invalid action\non: push\njobs:\n  verify:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: {reference}\n"
        );
        let plan = compile(&source);
        let report = evaluate(&plan, "verify", "Invalid action");
        assert!(report.envelope().is_none());
        assert!(
            report
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code() == code)
        );
    }
}

#[test]
fn container_actions_fail_with_a_precise_unsupported_diagnostic() {
    let plan = compile(
        "name: Container action\non: push\njobs:\n  verify:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: docker://alpine:3.22\n",
    );
    let report = evaluate(&plan, "verify", "Container action");
    assert!(report.envelope().is_none());
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code() == "github.evaluate.container_action")
        .expect("container-action diagnostic");
    assert_eq!(diagnostic.primary_span().start().line(), 7);
}

#[test]
fn catalog_owned_hosted_selector_maps_to_exact_profile() {
    let plan = compile(
        "name: Runner\non: push\njobs:\n  verify:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo safe\n",
    );
    let context = context("Runner");
    let catalog = profile_catalog();
    let report = evaluate_with_catalog(&plan, "verify", &context, &catalog);
    assert!(report.is_accepted());
    let requirements = report.envelope().expect("job").job().requirements();
    assert_eq!(
        requirements.environment_profile(),
        Some(&environment_profile())
    );
    assert_eq!(
        requirements.operating_system(),
        Some(&OperatingSystem::Linux)
    );
    assert_eq!(requirements.architecture(), Some(&Architecture::X86_64));
    assert!(requirements.labels().is_empty());
    assert!(
        requirements
            .container_features()
            .contains(&ContainerFeature::DOCKER_COMPATIBLE_API)
    );

    let empty = GithubRunnerProfileCatalog::default();
    let self_hosted = evaluate_with_catalog(&plan, "verify", &context, &empty);
    assert!(
        self_hosted.is_accepted(),
        "diagnostics: {:#?}",
        self_hosted.diagnostics()
    );
    let job = self_hosted.envelope().expect("job").job();
    assert!(job.requirements().environment_profile().is_none());
    assert!(
        job.requirements()
            .labels()
            .iter()
            .any(|label| label.as_str() == "ubuntu-24.04")
    );
    let SemanticStep::Run { shell, .. } = job.steps()[0].kind() else {
        panic!("run step");
    };
    assert_eq!(shell, &ShellSpec::Default);
}

#[test]
fn unresolved_self_hosted_platform_defers_shell_and_accepts_group_action_jobs() {
    let custom = compile(
        "name: Custom\non: push\njobs:\n  verify:\n    runs-on: ubuntu-cuda\n    steps:\n      - run: echo custom\n",
    );
    let empty = GithubRunnerProfileCatalog::default();
    let custom_context = context("Custom");
    let report = evaluate_with_catalog(&custom, "verify", &custom_context, &empty);
    assert!(
        report.is_accepted(),
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    let SemanticStep::Run { shell, .. } = report.envelope().expect("job").job().steps()[0].kind()
    else {
        panic!("run step");
    };
    assert_eq!(shell, &ShellSpec::Default);

    let self_hosted_linux = compile(
        "name: Self-hosted Linux\non: push\njobs:\n  verify:\n    runs-on: [self-hosted, linux, x64]\n    steps:\n      - run: echo runner-selected-fallback\n",
    );
    let linux_context = context("Self-hosted Linux");
    let report = evaluate_with_catalog(&self_hosted_linux, "verify", &linux_context, &empty);
    assert!(
        report.is_accepted(),
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    let SemanticStep::Run { shell, .. } = report.envelope().expect("job").job().steps()[0].kind()
    else {
        panic!("run step");
    };
    assert_eq!(shell, &ShellSpec::Default);

    let group_action = compile(
        "name: Group action\non: push\njobs:\n  verify:\n    runs-on:\n      group: secure-builders\n    steps:\n      - uses: owner/repository@v1\n",
    );
    let group_context = context("Group action");
    let report = evaluate_with_catalog(&group_action, "verify", &group_context, &empty);
    assert!(
        report.is_accepted(),
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    assert!(
        report
            .envelope()
            .expect("job")
            .job()
            .requirements()
            .eligible_groups()
            .iter()
            .any(|group| group.as_str() == "secure-builders")
    );

    let explicit_shell = compile(
        "name: Explicit shell\non: push\njobs:\n  verify:\n    runs-on:\n      group: secure-builders\n    steps:\n      - shell: bash\n        run: echo explicit\n",
    );
    let shell_context = context("Explicit shell");
    let report = evaluate_with_catalog(&explicit_shell, "verify", &shell_context, &empty);
    assert!(
        report.is_accepted(),
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    let SemanticStep::Run { shell, .. } = report.envelope().expect("job").job().steps()[0].kind()
    else {
        panic!("run step");
    };
    assert_eq!(shell, &ShellSpec::Named("bash".to_owned()));
}

#[test]
fn target_path_validation_is_host_independent_for_unix_and_windows() {
    let windows_workspace =
        GithubWorkspacePath::new(GithubTargetPathStyle::Windows, r"D:\a\automata\automata")
            .expect("Windows workspace");
    let windows_context = GithubJobContext::builder(workflow_id(), run_id(), job_id())
        .repository(REPOSITORY)
        .commit_sha(REVISION)
        .git_ref(GIT_REF)
        .workflow_name("Windows paths")
        .workspace(windows_workspace)
        .event(event_reference())
        .build()
        .expect("Windows evaluation context on any control-plane host");
    let inside = compile(
        r"name: Windows paths
on: push
env:
  CHILD: '${{ github.workspace }}\target'
jobs:
  verify:
    runs-on: [self-hosted, windows, x64]
    defaults:
      run:
        working-directory: 'D:\a\automata\automata\ui'
    steps:
      - run: echo inside
",
    );
    let empty = GithubRunnerProfileCatalog::default();
    let report = evaluate_with_catalog(&inside, "verify", &windows_context, &empty);
    assert!(
        report.is_accepted(),
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    let job = report.envelope().expect("job").job();
    assert_eq!(job.working_directory(), Some(r"D:\a\automata\automata\ui"));
    assert_eq!(
        job.environment().get("CHILD"),
        Some(&ValueSource::Literal(
            r"D:\a\automata\automata\target".to_owned()
        ))
    );

    for directory in [r"D:\a\automata\automata-escape", r"ui\..\outside"] {
        let source = format!(
            "name: Windows paths\non: push\njobs:\n  verify:\n    runs-on: [self-hosted, windows, x64]\n    defaults:\n      run:\n        working-directory: '{directory}'\n    steps:\n      - run: echo escape\n"
        );
        let plan = compile(&source);
        let report = evaluate_with_catalog(&plan, "verify", &windows_context, &empty);
        assert!(report.envelope().is_none(), "accepted {directory}");
        assert!(
            report
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code() == "github.evaluate.working_directory_escape")
        );
    }

    let mismatched_context = context("Windows paths");
    let report = evaluate_with_catalog(&inside, "verify", &mismatched_context, &empty);
    assert!(report.envelope().is_none());
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "github.evaluate.workspace_path_style")
    );

    let unix_outside = compile(
        "name: Unix paths\non: push\njobs:\n  verify:\n    runs-on: custom-unix-pool\n    defaults:\n      run:\n        working-directory: /__automata/sandboxes/run-42/workspace-escape\n    steps:\n      - run: echo escape\n",
    );
    let unix_context = context("Unix paths");
    let report = evaluate_with_catalog(&unix_outside, "verify", &unix_context, &empty);
    assert!(report.envelope().is_none());
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "github.evaluate.working_directory_escape")
    );
}

#[test]
fn evaluation_context_rejects_mutable_or_escaping_coordinates() {
    let base = GithubJobContext::builder(workflow_id(), run_id(), job_id())
        .repository(REPOSITORY)
        .git_ref(GIT_REF)
        .workflow_name("CI")
        .workspace(unix_workspace())
        .event(event_reference());
    assert!(base.clone().commit_sha("main").build().is_err());
    assert!(
        base.clone()
            .commit_sha(REVISION)
            .git_ref("main")
            .build()
            .is_err()
    );
    assert!(
        base.clone()
            .commit_sha(REVISION)
            .git_ref("refs/heads/release.lock")
            .build()
            .is_err()
    );
    assert!(
        GithubWorkspacePath::new(GithubTargetPathStyle::Unix, "/workspace/../outside").is_err()
    );
    assert!(
        base.commit_sha(REVISION)
            .repository("owner/repository/extra")
            .build()
            .is_err()
    );
}

#[test]
fn repository_workflow_path_is_relative_canonical_and_source_bound() {
    let plan = compile(
        "name: Provenance\non: push\njobs:\n  verify:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo safe\n",
    );
    for (path, code) in [
        ("../ci.yml", "github.evaluate.invalid_workflow_path"),
        (
            ".github/workflows/other.yml",
            "github.evaluate.workflow_source_identity",
        ),
    ] {
        let mut encoded = serde_json::to_value(&plan).expect("serialize workflow plan");
        encoded["source"]["origin"]["path"] = serde_json::json!(path);
        let mutated: WorkflowPlan =
            serde_json::from_value(encoded).expect("core plan permits adapter provenance audit");
        let report = evaluate(&mutated, "verify", "Provenance");
        assert!(report.envelope().is_none());
        assert!(
            report
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code() == code)
        );
    }
}

#[test]
fn repository_ci_jobs_and_needs_match_exact_job_ir_goldens() {
    let plan = compile(REPOSITORY_CI);
    assert!(matches!(
        plan.source().origin(),
        PlanSourceOrigin::Repository { revision, .. } if revision == REVISION
    ));
    let dist = plan
        .job(&WorkflowJobKey::new("dist").expect("dist key"))
        .expect("dist job");
    assert_eq!(
        dist.needs()
            .iter()
            .map(|need| need.value().as_str())
            .collect::<Vec<_>>(),
        ["verify", "frontend"]
    );
    for (job, golden) in [
        ("verify", VERIFY_GOLDEN),
        ("frontend", FRONTEND_GOLDEN),
        ("dist", DIST_GOLDEN),
    ] {
        let report = evaluate(&plan, job, "CI");
        assert!(
            report.is_accepted(),
            "{job} diagnostics: {:#?}",
            report.diagnostics()
        );
        let envelope = report.envelope().expect("JobIR");
        envelope.validate().expect("valid JobIR");
        assert_eq!(render_job_ir(envelope), golden, "{job} JobIR golden");
    }
}

fn render_job_ir(envelope: &automata_core::JobIrEnvelope) -> String {
    let job = envelope.job();
    let mut output = String::new();
    writeln!(output, "job-ir-v{}", envelope.version().get()).expect("write string");
    writeln!(output, "workflow-id={}", envelope.workflow_id()).expect("write string");
    writeln!(
        output,
        "source={}",
        serde_json::to_string(envelope.source()).expect("serialize source")
    )
    .expect("write string");
    writeln!(
        output,
        "job={} run={} name={} condition={} timeout={:?} wd={} steps={}",
        job.job_id(),
        job.run_id(),
        json(job.name()),
        job.condition()
            .map_or_else(|| "-".to_owned(), expression_json),
        job.timeout_seconds(),
        job.working_directory().map_or_else(|| "-".to_owned(), json),
        job.steps().len(),
    )
    .expect("write string");
    let encoded = serde_json::to_vec(envelope).expect("serialize canonical JobIR JSON");
    writeln!(output, "json-sha256={:x}", Sha256::digest(encoded)).expect("write string");
    output
}

fn expression_json(value: &automata_core::ExpressionProgram) -> String {
    serde_json::to_string(value).expect("serialize expression program")
}

fn assert_condition_source(condition: Option<&automata_core::ExpressionProgram>, expected: &str) {
    let condition = condition.expect("condition program");
    assert_eq!(condition.source(), expected);
    assert!(matches!(
        condition.instructions().first(),
        Some(ExpressionInstruction::Call {
            name,
            argument_count: 0,
        }) if name == "success"
    ));
}

fn json(value: &str) -> String {
    serde_json::to_string(value).expect("serialize string")
}
