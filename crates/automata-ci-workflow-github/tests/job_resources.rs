use crate::support;

use automata_ci_core::{
    CompiledValueTemplate, ExpressionContext, LogicalJobKind, WorkflowEventProvenance,
    WorkflowPlanVersion,
};
use automata_ci_workflow_github::{CompileWorkflowRequest, GithubWorkflowCompiler};

fn compile(source: &str) -> automata_ci_workflow_github::CompilationReport {
    let parsed = support::parse(source);
    assert!(
        parsed.is_accepted(),
        "source diagnostics: {:#?}",
        parsed.diagnostics()
    );
    GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", "workflow_dispatch")
            .with_delivery_id("resource-test")
            .with_commit_sha("0123456789abcdef0123456789abcdef01234567")
            .with_git_ref("refs/heads/main"),
    ))
}

#[test]
fn compiles_literal_and_matrix_resource_quantities() {
    let report = compile(
        r#"on: workflow_dispatch
jobs:
  build:
    strategy:
      matrix:
        cpu: ["500m", "1"]
    runs-on: linux
    resources:
      requests:
        cpu: ${{ matrix.cpu }}
        memory: 512Mi
        ephemeral-storage: 1Gi
      limits:
        cpu: "2"
        memory: 2Gi
        ephemeral-storage: 4Gi
    steps:
      - run: echo build
"#,
    );
    assert!(report.is_accepted(), "{:#?}", report.diagnostics());
    let plan = report.plan().expect("resource plan");
    assert_eq!(plan.version(), WorkflowPlanVersion::v1());
    let LogicalJobKind::Steps(job) = plan.jobs()[0].execution() else {
        panic!("step job")
    };
    let resources = job.resources().expect("resources");
    let requests = resources.requests().expect("requests");
    let CompiledValueTemplate::Expression(cpu) = requests.cpu().expect("CPU").value() else {
        panic!("dynamic CPU")
    };
    assert!(cpu.references_context(ExpressionContext::Matrix));
    assert!(matches!(
        requests.memory().expect("memory").value(),
        CompiledValueTemplate::Literal(value) if value == "512Mi"
    ));
    assert!(matches!(
        resources
            .limits()
            .expect("limits")
            .cpu()
            .expect("CPU")
            .value(),
        CompiledValueTemplate::Literal(value) if value == "2"
    ));
}

#[test]
fn rejects_invalid_literal_resource_quantities() {
    let report = compile(
        r"on: workflow_dispatch
jobs:
  build:
    runs-on: linux
    resources:
      requests:
        cpu: 0.0001
        memory: 1.5Gi
    steps:
      - run: echo build
",
    );
    assert!(report.plan().is_none());
    assert!(
        report
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code() == "github.compile.invalid_resource_quantity")
            .count()
            >= 2,
        "{:#?}",
        report.diagnostics()
    );
}

#[test]
fn resources_are_rejected_on_reusable_workflow_calls() {
    let report = support::parse(
        r#"on: push
jobs:
  delegated:
    uses: owner/repository/.github/workflows/reuse.yml@main
    resources:
      limits:
        cpu: "1"
"#,
    );
    assert!(!report.is_accepted());
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.code() == "github.step_job_field_on_reusable_workflow_call"
            || diagnostic.code() == "github.compile.step_job_field_on_reusable_workflow_call"
    }));
}
