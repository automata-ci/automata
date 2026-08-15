use crate::support;

use automata_ci_core::WorkflowEventProvenance;
use automata_ci_workflow_github::{CompileWorkflowRequest, DiagnosticKind, GithubWorkflowCompiler};

fn assert_rejected_before_plan(source: &str, code: &str, exact_span: &str) {
    assert_rejected_before_plan_for_event(source, "workflow_dispatch", code, exact_span);
}

fn assert_rejected_before_plan_for_event(
    source: &str,
    event_name: &str,
    code: &str,
    exact_span: &str,
) {
    let parsed = support::parse(source);
    assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
    let source_plan = parsed.plan().expect("source plan");
    let report = GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        source_plan,
        WorkflowEventProvenance::new("github", event_name),
    ));

    assert!(
        report.plan().is_none(),
        "a run-capable plan must not be emitted"
    );
    let diagnostics = report
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code() == code)
        .collect::<Vec<_>>();
    assert_eq!(diagnostics.len(), 1, "{:#?}", report.diagnostics());
    assert_eq!(diagnostics[0].kind(), DiagnosticKind::Unsupported);
    assert_eq!(
        source_plan.source().slice(diagnostics[0].primary_span()),
        Some(exact_span)
    );
}

#[test]
fn job_concurrency_is_rejected_during_compilation_with_its_value_span() {
    assert_rejected_before_plan(
        "on: workflow_dispatch\njobs:\n  test:\n    concurrency: queued-${{ github.ref }}\n    runs-on: linux\n    steps: [{run: echo test}]\n",
        "github.compile.job_concurrency_unavailable",
        "queued-${{ github.ref }}",
    );
}

#[test]
fn deployment_environment_is_rejected_during_compilation_with_its_value_span() {
    assert_rejected_before_plan(
        "on: workflow_dispatch\njobs:\n  deploy:\n    runs-on: linux\n    environment:\n      name: production\n    steps: [{run: echo deploy}]\n",
        "github.compile.deployment_environment_unavailable",
        "production",
    );
}

#[test]
fn reusable_workflow_matrix_is_rejected_during_compilation_with_its_value_span() {
    assert_rejected_before_plan(
        "on: workflow_dispatch\njobs:\n  call:\n    strategy:\n      matrix: ${{ fromJSON(github.event.matrix) }}\n    uses: ./.ci/workflows/reusable.yml\n",
        "github.compile.reusable_workflow_matrix_unavailable",
        "${{ fromJSON(github.event.matrix) }}",
    );
}

#[test]
fn job_container_is_rejected_during_compilation_with_its_value_span() {
    assert_rejected_before_plan(
        "on: workflow_dispatch\njobs:\n  test:\n    runs-on: linux\n    container: ubuntu:24.04\n    steps: [{run: echo test}]\n",
        "github.compile.job_container",
        "ubuntu:24.04",
    );
}

#[test]
fn direct_container_action_is_rejected_during_compilation_with_its_reference_span() {
    assert_rejected_before_plan(
        "on: workflow_dispatch\njobs:\n  test:\n    runs-on: linux\n    steps:\n      - uses: docker://alpine:3.23\n",
        "github.compile.container_action_unavailable",
        "docker://alpine:3.23",
    );
}

#[test]
fn decoder_only_provider_event_is_rejected_during_compilation_with_its_name_span() {
    assert_rejected_before_plan_for_event(
        "on: issues\njobs:\n  test:\n    runs-on: linux\n    steps: [{run: echo test}]\n",
        "issues",
        "github.compile.provider_event_unavailable",
        "issues",
    );
}

#[test]
fn unselected_decoder_only_event_still_rejects_publication() {
    assert_rejected_before_plan_for_event(
        "on: [push, issues]\njobs:\n  test:\n    runs-on: linux\n    steps: [{run: echo test}]\n",
        "push",
        "github.compile.provider_event_unavailable",
        "issues",
    );
}
