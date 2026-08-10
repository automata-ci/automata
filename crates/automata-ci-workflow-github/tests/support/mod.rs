use automata_ci_workflow_github::{
    GithubFrontendReport, GithubWorkflowFrontend, ParseWorkflowRequest, SourceProvenance,
    WorkflowFrontend,
};

pub fn parse(source: &str) -> GithubFrontendReport {
    GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(
        SourceProvenance::memory("test.yml"),
        source,
    ))
}
