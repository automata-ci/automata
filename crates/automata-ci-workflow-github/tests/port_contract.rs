use std::fmt::Debug;

use automata_ci_workflow_github::{
    Diagnostic, DiagnosticKind, FrontendReport, GithubWorkflowFrontend, GithubWorkflowSourcePlan,
    ParseWorkflowRequest, SourceFile, SourceLocation, SourceProvenance, SourceSpan,
    WorkflowFrontend,
};

#[test]
fn workflow_frontend_is_object_safe_and_thread_safe() {
    fn assert_port<T: ?Sized + Debug + Send + Sync>() {}
    assert_port::<dyn WorkflowFrontend<Plan = GithubWorkflowSourcePlan>>();

    let frontend: Box<dyn WorkflowFrontend<Plan = GithubWorkflowSourcePlan>> =
        Box::new(GithubWorkflowFrontend::default());
    let report = frontend.parse(ParseWorkflowRequest::new(
        SourceProvenance::memory("port.yml"),
        "on: push\njobs:\n  build:\n    runs-on: linux\n    steps:\n      - run: true\n",
    ));
    assert!(
        report.is_accepted(),
        "diagnostics: {:#?}",
        report.diagnostics()
    );
    report.plan().expect("plan");
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AlternatePlan {
    source_bytes: usize,
}

#[derive(Debug)]
struct AlternateFrontend;

impl WorkflowFrontend for AlternateFrontend {
    type Plan = AlternatePlan;

    fn parse(&self, request: ParseWorkflowRequest<'_>) -> FrontendReport<Self::Plan> {
        let source = SourceFile::new(request.provenance().clone(), request.source());
        let location = SourceLocation::try_new(0, 1, 1).expect("valid coordinate");
        let span = SourceSpan::try_new(source.provenance().id().clone(), location, location)
            .expect("valid span");
        FrontendReport::new(
            source,
            Some(AlternatePlan {
                source_bytes: request.source().len(),
            }),
            vec![Diagnostic::warning(
                DiagnosticKind::Unsupported,
                "alternate.example",
                "alternate dialect fixture",
                span,
            )],
        )
    }
}

#[test]
fn external_frontends_own_their_plan_type_and_can_construct_reports() {
    let frontend: Box<dyn WorkflowFrontend<Plan = AlternatePlan>> = Box::new(AlternateFrontend);
    let report = frontend.parse(ParseWorkflowRequest::new(
        SourceProvenance::memory("alternate.workflow"),
        "alternate source",
    ));

    assert!(report.is_accepted());
    assert_eq!(report.plan(), Some(&AlternatePlan { source_bytes: 16 }));
    assert_eq!(report.diagnostics()[0].code(), "alternate.example");
}
