#![allow(dead_code)]

use std::sync::Arc;

use automata_ci_core::{OperationId, WorkflowEventProvenance};
use automata_ci_store::{TenantScope, WorkflowAdmissionIdempotency};
use automata_ci_workflow_github::{
    CompilationReport, CompileWorkflowRequest, GithubEventMetadataV1, GithubWorkflowCompiler,
    GithubWorkflowFrontend, ParseWorkflowRequest, SourceId, SourceOrigin, SourceProvenance,
    WorkflowFrontend as _,
};
use automata_ci_workflow_service::{AdmissionRepositoryCoordinates, WorkflowAdmissionRequest};
use bytes::Bytes;

pub const CI_SOURCE: &str = include_str!("../fixtures/repository-ci.yml");
pub const REPOSITORY: &str = "automata-ci/automata";
pub const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
pub const GIT_REF: &str = "refs/heads/main";
pub const WORKFLOW_PATH: &str = ".github/workflows/ci.yml";
pub const SECOND_WORKFLOW_PATH: &str = ".github/workflows/secondary.yml";
pub const DELIVERY: &str = "delivery-workflow-admission-42";

pub fn ci_request(
    tenant: &str,
    idempotency: WorkflowAdmissionIdempotency,
) -> WorkflowAdmissionRequest {
    ci_request_at_path(tenant, WORKFLOW_PATH, idempotency)
}

pub fn ci_request_at_path(
    tenant: &str,
    workflow_path: &str,
    idempotency: WorkflowAdmissionIdempotency,
) -> WorkflowAdmissionRequest {
    request_from_compilation(
        tenant,
        workflow_path,
        Bytes::from_static(b"{}"),
        idempotency,
        compile_ci_at_path(workflow_path, "workflow_dispatch", None),
    )
}

pub fn push_request(tenant: &str) -> WorkflowAdmissionRequest {
    request_from_compilation(
        tenant,
        WORKFLOW_PATH,
        Bytes::from_static(b"{\"deleted\":false}"),
        WorkflowAdmissionIdempotency::provider_delivery(DELIVERY).expect("delivery"),
        compile_ci_at_path(
            WORKFLOW_PATH,
            "push",
            Some(GithubEventMetadataV1::push(false)),
        ),
    )
}

pub fn compile_ci_at_path(
    workflow_path: &str,
    event_name: &str,
    metadata: Option<GithubEventMetadataV1>,
) -> CompilationReport {
    let provenance = SourceProvenance::new(
        SourceId::new(workflow_path),
        SourceOrigin::Repository {
            repository: Arc::from(REPOSITORY),
            revision: Arc::from(REVISION),
            path: Arc::from(workflow_path),
        },
    );
    let parsed =
        GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(provenance, CI_SOURCE));
    assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
    let request = CompileWorkflowRequest::new(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", event_name)
            .with_delivery_id(DELIVERY)
            .with_commit_sha(REVISION)
            .with_git_ref(GIT_REF),
    );
    let request = match metadata {
        Some(metadata) => request.with_event_metadata_v1(metadata),
        None => request,
    };
    GithubWorkflowCompiler::new().compile(request)
}

pub fn recompile_preselected(request: &WorkflowAdmissionRequest) -> CompilationReport {
    let source = std::str::from_utf8(request.source()).expect("fixture source is UTF-8");
    let provenance = SourceProvenance::new(
        SourceId::new(request.workflow_path()),
        SourceOrigin::Repository {
            repository: Arc::from(request.repository().slug()),
            revision: Arc::from(request.commit_sha()),
            path: Arc::from(request.workflow_path()),
        },
    );
    let parsed =
        GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(provenance, source));
    assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
    GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::for_preselected_event(
        parsed.plan().expect("source plan"),
        request.plan().event().clone(),
    ))
}

fn request_from_compilation(
    tenant: &str,
    workflow_path: &str,
    event: Bytes,
    idempotency: WorkflowAdmissionIdempotency,
    compiled: CompilationReport,
) -> WorkflowAdmissionRequest {
    assert!(compiled.is_accepted(), "{:#?}", compiled.diagnostics());
    let plan = compiled.into_parts().0.expect("compiled plan");
    WorkflowAdmissionRequest::builder(
        TenantScope::from_authenticated_tenant_id(tenant).expect("tenant"),
        AdmissionRepositoryCoordinates::new(
            "github",
            "repository-automata",
            "automata-ci",
            "automata",
        )
        .expect("repository"),
        workflow_path,
        Bytes::copy_from_slice(CI_SOURCE.as_bytes()),
        event,
        plan,
        idempotency,
    )
    .commit_sha(REVISION)
    .git_ref(GIT_REF)
    .workflow_name("CI")
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

pub fn changed_event_request(original: &WorkflowAdmissionRequest) -> WorkflowAdmissionRequest {
    WorkflowAdmissionRequest::builder(
        original.tenant().clone(),
        original.repository().clone(),
        original.workflow_path(),
        original.source().clone(),
        Bytes::from_static(b"{\"changed\":true}"),
        original.plan().clone(),
        original.idempotency().clone(),
    )
    .commit_sha(original.commit_sha())
    .git_ref(original.git_ref())
    .workflow_name(original.workflow_name())
    .actor(original.actor().expect("fixture actor"))
    .run_attempt(original.run_attempt().expect("fixture attempt"))
    .build()
    .expect("changed exact event remains structurally valid")
}
