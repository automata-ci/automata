use automata_workflow_github::{
    DiagnosticKind, GithubWorkflowFrontend, ParseWorkflowRequest, SourceProvenance,
    WorkflowFrontend, WorkflowParseLimits,
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

fn request(source: &str) -> ParseWorkflowRequest<'_> {
    ParseWorkflowRequest::new(SourceProvenance::memory("limits.yml"), source)
}
