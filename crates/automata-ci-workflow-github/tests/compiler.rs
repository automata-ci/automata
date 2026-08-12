mod support;

use automata_ci_core::{WorkflowEventProvenance, WorkflowPlan, WorkflowPlanVersion};
use automata_ci_workflow_github::{
    CompilationDisposition, CompileWorkflowRequest, DiagnosticKind, GithubEventMetadataV1,
    GithubWorkflowCompiler, WorkflowCompiler, WorkflowNotSelectedReason,
};

fn event(name: &str) -> WorkflowEventProvenance {
    WorkflowEventProvenance::new("github", name)
        .with_delivery_id("compiler-current")
        .with_commit_sha("0123456789abcdef0123456789abcdef01234567")
        .with_git_ref("refs/heads/main")
}

fn compile(source: &str, event_name: &str) -> automata_ci_workflow_github::CompilationReport {
    let parsed = support::parse(source);
    let request = CompileWorkflowRequest::new(
        parsed.plan().expect("loss-aware source plan"),
        event(event_name),
    );
    let request = match event_name {
        "push" => request.with_event_metadata_v1(GithubEventMetadataV1::push(false)),
        "pull_request" => {
            request.with_event_metadata_v1(GithubEventMetadataV1::pull_request("opened", "main"))
        }
        _ => request,
    };
    GithubWorkflowCompiler::new().compile(request)
}

#[test]
fn inherent_and_trait_paths_emit_only_the_current_logical_plan() {
    let source = r"on: workflow_dispatch
jobs:
  verify:
    runs-on: linux
    steps:
      - run: echo verify
";
    let parsed = support::parse(source);
    assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
    let source_plan = parsed.plan().expect("source plan");
    let compiler = GithubWorkflowCompiler::new();
    let inherent = compiler.compile(CompileWorkflowRequest::new(
        source_plan,
        event("workflow_dispatch"),
    ));
    let through_trait = <GithubWorkflowCompiler as WorkflowCompiler>::compile(
        &compiler,
        source_plan,
        event("workflow_dispatch"),
    );

    for report in [inherent, through_trait] {
        assert!(report.is_accepted(), "{:#?}", report.diagnostics());
        let plan = report.plan().expect("current plan");
        assert_eq!(plan.version(), WorkflowPlanVersion::v1());
        assert_eq!(plan.jobs().len(), 1);
        plan.validate().expect("valid current plan");
        let encoded = serde_json::to_string(plan).expect("serialize plan");
        let decoded: WorkflowPlan = serde_json::from_str(&encoded).expect("deserialize plan");
        assert_eq!(decoded, *plan);
    }
}

#[test]
fn compiler_rejects_duplicate_keys_retained_by_the_loss_aware_frontend() {
    let report = compile(
        "on: workflow_dispatch\njobs:\n  verify:\n    runs-on: linux\n    steps: [{run: echo one}]\n  verify:\n    runs-on: linux\n    steps: [{run: echo two}]\n",
        "workflow_dispatch",
    );
    assert!(report.plan().is_none());
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.code() == "github.compile.duplicate_mapping_key"
            && diagnostic.related().len() == 1
    }));
}

#[test]
fn compiler_rejects_invalid_event_filters() {
    let cases = [
        (
            "on:\n  push:\n    branches: [main]\n    branches-ignore: [legacy]\njobs:\n  build:\n    runs-on: linux\n    steps: [{run: true}]\n",
            "github.compile.mutually_exclusive_filters",
        ),
        (
            "on:\n  push:\n    branches: ['!legacy/**']\njobs:\n  build:\n    runs-on: linux\n    steps: [{run: true}]\n",
            "github.compile.negative_filter_without_positive",
        ),
        (
            "on:\n  push:\n    branches: ['release/[']\njobs:\n  build:\n    runs-on: linux\n    steps: [{run: true}]\n",
            "github.compile.invalid_filter_pattern",
        ),
    ];
    for (source, code) in cases {
        let report = compile(source, "push");
        assert!(report.plan().is_none(), "{code} must suppress the plan");
        assert!(
            report
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code() == code),
            "missing {code}: {:#?}",
            report.diagnostics()
        );
    }
}

#[test]
fn compiler_distinguishes_unconfigured_events_from_lossy_yaml_rejection() {
    let unconfigured = compile(
        "on: workflow_dispatch\njobs:\n  build:\n    runs-on: linux\n    steps: [{run: echo ok}]\n",
        "schedule",
    );
    assert!(unconfigured.plan().is_none());
    assert_eq!(
        unconfigured.disposition(),
        CompilationDisposition::NotSelected(WorkflowNotSelectedReason::EventNotConfigured)
    );
    assert!(unconfigured.diagnostics().is_empty());

    let invalid_unconfigured = compile(
        "on: workflow_dispatch\nunknown-workflow-field: true\njobs:\n  build:\n    runs-on: linux\n    steps: [{run: echo ok}]\n",
        "schedule",
    );
    assert_eq!(
        invalid_unconfigured.disposition(),
        CompilationDisposition::Rejected,
        "invalid source must not be disguised as ordinary non-selection"
    );
    assert!(invalid_unconfigured.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == DiagnosticKind::Unsupported
            && diagnostic.code() == "github.compile.unsupported_field"
    }));

    let aliases = compile(include_str!("fixtures/aliases.yml"), "push");
    assert!(aliases.plan().is_none());
    assert_eq!(aliases.disposition(), CompilationDisposition::Rejected);
    assert!(aliases.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == DiagnosticKind::Unsupported
            && matches!(
                diagnostic.code(),
                "github.compile.yaml_anchor" | "github.compile.yaml_alias"
            )
    }));
}
