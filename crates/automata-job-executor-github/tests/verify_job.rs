mod support;

use std::sync::Arc;

use automata_core::{
    Architecture, JobConclusion, JobContentReference, JobId, OperatingSystem, RunId, Sha256Digest,
    WorkflowEventProvenance, WorkflowId, WorkflowJobKey,
};
use automata_runner_runtime::{ExecutionCancellation, ExecutionEvents, JobExecutor};
use automata_workflow_github::{
    CompileWorkflowRequest, EvaluateJobRequest, GithubJobContext, GithubJobEvaluator,
    GithubRunnerProfileCatalog, GithubRunnerProfileMapping, GithubTargetPathStyle,
    GithubWorkflowCompiler, GithubWorkflowFrontend, GithubWorkspacePath, ParseWorkflowRequest,
    SourceId, SourceOrigin, SourceProvenance, WorkflowFrontend,
};
use sha2::Digest as _;

use support::{Fixture, PhaseResponse, prepared_node24_action, profile};

const CI: &str = include_str!("../../../.github/workflows/ci.yml");
const REPOSITORY: &str = "GoNeuralAI/automata";
const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const WORKFLOW_PATH: &str = ".github/workflows/ci.yml";
const WORKSPACE: &str = "/__w/automata/automata";

#[tokio::test]
async fn unchanged_verify_job_is_admitted_and_every_semantic_step_executes() {
    let frontend = GithubWorkflowFrontend::default();
    let provenance = SourceProvenance::new(
        SourceId::new(WORKFLOW_PATH),
        SourceOrigin::Repository {
            repository: Arc::from(REPOSITORY),
            revision: Arc::from(REVISION),
            path: Arc::from(WORKFLOW_PATH),
        },
    );
    let parsed = frontend.parse(ParseWorkflowRequest::new(provenance, CI));
    assert!(parsed.is_accepted(), "parse: {:#?}", parsed.diagnostics());
    let compiled = GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", "push")
            .with_commit_sha(REVISION)
            .with_git_ref("refs/heads/main"),
    ));
    assert!(
        compiled.is_accepted(),
        "compile: {:#?}",
        compiled.diagnostics()
    );
    let plan = compiled.into_parts().0.expect("workflow plan");
    let context = GithubJobContext::builder(WorkflowId::new(), RunId::new(), JobId::new())
        .repository(REPOSITORY)
        .commit_sha(REVISION)
        .git_ref("refs/heads/main")
        .workflow_name("CI")
        .workspace(
            GithubWorkspacePath::new(GithubTargetPathStyle::Unix, WORKSPACE).expect("workspace"),
        )
        .event(JobContentReference::new(
            "events/push.json",
            Sha256Digest::from_bytes(sha2::Sha256::digest(b"{}").into()),
            2,
            "application/json",
        ))
        .build()
        .expect("job context");
    let catalog = GithubRunnerProfileCatalog::new([GithubRunnerProfileMapping::new(
        "ubuntu-24.04",
        profile(),
        OperatingSystem::Linux,
        Architecture::X86_64,
    )
    .expect("profile mapping")])
    .expect("profile catalog");
    let evaluated = GithubJobEvaluator::new().evaluate(&EvaluateJobRequest::new(
        &plan,
        &context,
        &catalog,
        WorkflowJobKey::new("verify").expect("job key"),
    ));
    assert!(
        evaluated.is_accepted(),
        "evaluate: {:#?}",
        evaluated.diagnostics()
    );
    let job = evaluated.into_parts().0.expect("verify JobIR");
    assert_eq!(job.job().steps().len(), 12);

    // Checkout main, eleven run steps, then checkout post.
    let fixture = Fixture::new(
        vec![prepared_node24_action()],
        std::iter::repeat_with(PhaseResponse::success)
            .take(13)
            .collect(),
    );
    fixture.executor.admit(&job).expect("verify is admitted");
    let request = fixture.request(job);
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();
    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("verify executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert_eq!(result.steps().len(), 12);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert_eq!(state.scripts.len(), 11);
    assert_eq!(
        state
            .commands
            .iter()
            .filter(|command| command.argv().program().as_str() == "/usr/bin/bash")
            .count(),
        11
    );
    assert_eq!(
        state
            .commands
            .iter()
            .filter(|command| command.argv().program().as_str() == "/opt/node24/bin/node")
            .count(),
        2
    );
}
