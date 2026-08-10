use automata_ci_workflow_github::{
    DiagnosticKind, GithubFrontendReport, GithubWorkflowFrontend, ParseWorkflowRequest,
    SourceProvenance, WorkflowFrontend, WorkflowParseLimits,
};

#[test]
fn source_size_is_checked_before_yaml_construction() {
    let frontend =
        GithubWorkflowFrontend::new(WorkflowParseLimits::default().with_max_source_bytes(8));
    let report = frontend.parse(request("on: push\njobs: {}\n"));
    assert!(report.plan().is_none());
    assert_eq!(
        report.diagnostics()[0].kind(),
        DiagnosticKind::ResourceLimit
    );
    assert_eq!(report.diagnostics()[0].code(), "yaml.source_too_large");
}

#[test]
fn excessive_nesting_is_a_resource_limit_not_a_parser_crash() {
    let frontend = GithubWorkflowFrontend::new(WorkflowParseLimits::default().with_max_depth(3));
    let report = frontend.parse(request("[[[[[[value]]]]]]"));
    assert!(report.plan().is_none());
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "yaml.maximum_depth_exceeded")
    );
}

#[test]
fn aliases_have_an_independent_budget_and_are_not_expanded() {
    let frontend = GithubWorkflowFrontend::new(WorkflowParseLimits::default().with_max_aliases(0));
    let report = frontend.parse(request(include_str!("fixtures/aliases.yml")));
    assert!(report.plan().is_none());
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "yaml.maximum_aliases_exceeded")
    );
}

#[test]
fn node_count_has_a_hard_budget() {
    let frontend = GithubWorkflowFrontend::new(WorkflowParseLimits::default().with_max_nodes(3));
    let report = frontend.parse(request("[one, two, three, four]"));
    assert!(report.plan().is_none());
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "yaml.maximum_nodes_exceeded")
    );
}

#[test]
fn long_matrix_dimension_with_scalar_fanout_hits_one_derived_text_limit() {
    let dimension = "dimension".repeat(4_096);
    let values = std::iter::repeat_n("linux", 700)
        .collect::<Vec<_>>()
        .join(", ");
    let source = format!(
        "on: push\njobs:\n  test:\n    runs-on: linux\n    strategy:\n      matrix:\n        ? \"{dimension}\"\n        : [{values}]\n    steps: [{{run: echo test}}]\n"
    );

    assert_one_derived_text_limit(&source);
}

#[test]
fn null_key_diagnostic_fanout_hits_one_derived_text_limit() {
    let dimension = "dimension".repeat(4_096);
    let values = std::iter::repeat_n("          - {null: value}\n", 700).collect::<String>();
    let source = format!(
        "on: push\njobs:\n  test:\n    runs-on: linux\n    strategy:\n      matrix:\n        ? \"{dimension}\"\n        :\n{values}    steps: [{{run: echo test}}]\n"
    );

    let report = GithubWorkflowFrontend::default().parse(request(&source));
    assert_report_has_one_derived_text_limit(&report);
    assert!(report.diagnostics().len() < 1_000);
}

#[test]
fn long_job_identifier_with_step_fanout_hits_one_derived_text_limit() {
    let job_id = format!("j{}", "ob".repeat(20_000));
    let steps = std::iter::repeat_n("      - run: echo test\n", 700).collect::<String>();
    let source =
        format!("on: push\njobs:\n  ? \"{job_id}\"\n  :\n    runs-on: linux\n    steps:\n{steps}");

    assert_one_derived_text_limit(&source);
}

#[test]
fn multiple_documents_are_rejected_without_discarding_the_distinction() {
    let report = GithubWorkflowFrontend::default().parse(request(
        "on: push\njobs: {}\n---\non: pull_request\njobs: {}\n",
    ));
    assert!(report.plan().is_none());
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code() == "github.document_count")
        .expect("document count diagnostic");
    assert_eq!(diagnostic.kind(), DiagnosticKind::Semantic);
}

fn assert_one_derived_text_limit(source: &str) {
    let report = GithubWorkflowFrontend::default().parse(request(source));
    assert_report_has_one_derived_text_limit(&report);
}

fn assert_report_has_one_derived_text_limit(report: &GithubFrontendReport) {
    assert!(report.plan().is_none());
    let matching = report
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code() == "github.decode.derived_text_limit")
        .collect::<Vec<_>>();
    assert_eq!(
        matching.len(),
        1,
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    assert_eq!(matching[0].kind(), DiagnosticKind::ResourceLimit);
    assert_eq!(
        report
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.kind() == DiagnosticKind::ResourceLimit)
            .count(),
        1,
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    assert_eq!(
        matching[0].message(),
        "workflow decoding exceeded the 16 MiB derived-text and diagnostic budget"
    );
}

fn request(source: &str) -> ParseWorkflowRequest<'_> {
    ParseWorkflowRequest::new(SourceProvenance::memory("limits.yml"), source)
}
