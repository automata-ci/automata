use std::sync::Arc;

use automata_core::{OperationId, WorkflowEventProvenance};
use automata_store::{TenantScope, WorkflowAdmissionIdempotency};
use automata_workflow_github::{
    CompileWorkflowRequest, GithubWorkflowCompiler, GithubWorkflowFrontend, ParseWorkflowRequest,
    SourceId, SourceOrigin, SourceProvenance, WorkflowFrontend as _,
};
use automata_workflow_service::{AdmissionRepositoryCoordinates, WorkflowAdmissionRequest};
use bytes::Bytes;

pub const CI_SOURCE: &str = include_str!("../../../../.github/workflows/ci.yml");
pub const REPOSITORY: &str = "GoNeuralAI/automata";
pub const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
pub const GIT_REF: &str = "refs/heads/main";
pub const WORKFLOW_PATH: &str = ".github/workflows/ci.yml";
pub const WORKSPACE: &str = "/__w/automata/automata";
pub const DELIVERY: &str = "delivery-workflow-admission-42";

pub fn ci_request(
    tenant: &str,
    idempotency: WorkflowAdmissionIdempotency,
) -> WorkflowAdmissionRequest {
    let provenance = SourceProvenance::new(
        SourceId::new(WORKFLOW_PATH),
        SourceOrigin::Repository {
            repository: Arc::from(REPOSITORY),
            revision: Arc::from(REVISION),
            path: Arc::from(WORKFLOW_PATH),
        },
    );
    let parsed =
        GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(provenance, CI_SOURCE));
    assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
    let compiled = GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", "workflow_dispatch")
            .with_delivery_id(DELIVERY)
            .with_commit_sha(REVISION)
            .with_git_ref(GIT_REF),
    ));
    assert!(compiled.is_accepted(), "{:#?}", compiled.diagnostics());
    let plan = compiled.into_parts().0.expect("compiled plan");
    WorkflowAdmissionRequest::builder(
        TenantScope::from_authenticated_tenant_id(tenant).expect("tenant"),
        AdmissionRepositoryCoordinates::new(
            "github",
            "repository-automata",
            "GoNeuralAI",
            "automata",
        )
        .expect("repository"),
        WORKFLOW_PATH,
        Bytes::copy_from_slice(CI_SOURCE.as_bytes()),
        Bytes::from_static(b"{}"),
        plan,
        idempotency,
    )
    .commit_sha(REVISION)
    .git_ref(GIT_REF)
    .workflow_name("CI")
    .workspace(WORKSPACE)
    .actor("local-bootstrap")
    .run_attempt(1)
    .build()
    .expect("valid CI admission")
}

pub fn operation_request(tenant: &str) -> WorkflowAdmissionRequest {
    ci_request(
        tenant,
        WorkflowAdmissionIdempotency::operation(OperationId::new()),
    )
}
