use automata_ci_core::WorkflowEventProvenance;
use automata_ci_workflow_actions::{
    CompilationDisposition, CompilationReport, CompileWorkflowRequest, GithubEventMetadata,
    GithubFrontendReport, GithubWorkflowCompiler, GithubWorkflowFrontend, GithubWorkflowSourcePlan,
    ParseWorkflowRequest, SourceProvenance, WorkflowFrontend, WorkflowNotSelectedReason,
};

pub fn parse(source: &str) -> GithubFrontendReport {
    GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(
        SourceProvenance::memory("test.yml"),
        source,
    ))
}

pub(super) fn parse_accepted(source: &str) -> GithubFrontendReport {
    let report = parse(source);
    assert!(
        report.is_accepted(),
        "source diagnostics: {:#?}",
        report.diagnostics()
    );
    report
}

pub(super) fn compile(
    source_plan: &GithubWorkflowSourcePlan,
    event: WorkflowEventProvenance,
    metadata: Option<GithubEventMetadata>,
) -> CompilationReport {
    let request = CompileWorkflowRequest::new(source_plan, event);
    let request = match metadata {
        Some(metadata) => request.with_event_metadata(metadata),
        None => request,
    };
    GithubWorkflowCompiler::new().compile(request)
}

pub(super) fn assert_rejected_with(report: &CompilationReport, code: &str) {
    assert!(
        report.plan().is_none(),
        "unexpected plan: {:#?}",
        report.plan()
    );
    assert!(
        report.disposition() == CompilationDisposition::Rejected,
        "unexpected disposition: {:?}",
        report.disposition()
    );
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == code),
        "missing diagnostic `{code}`: {:#?}",
        report.diagnostics()
    );
}

pub(super) fn assert_not_selected(report: &CompilationReport, reason: WorkflowNotSelectedReason) {
    assert_eq!(report.plan(), None);
    assert_eq!(
        report.disposition(),
        CompilationDisposition::NotSelected(reason)
    );
    assert!(
        report.diagnostics().is_empty(),
        "ordinary non-selection must not emit diagnostics: {:#?}",
        report.diagnostics()
    );
}
