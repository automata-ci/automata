use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use automata::app::workflow_api::{
    LocalAdmissionToken, LocalWorkflowAdmission, LocalWorkflowAdmissionError,
    LocalWorkflowAdmissionRequest, LocalWorkflowAdmissionResponse, local_workflow_admission_router,
};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::Value;
use tower::ServiceExt as _;

const RUN_ID: &str = "45e8cc88-5075-40c5-a6cb-9f1dad46c3b1";
const TOKEN: &str = "0123456789abcdef0123456789abcdef";

#[derive(Debug)]
struct FakeAdmission {
    calls: AtomicUsize,
    result: Result<LocalWorkflowAdmissionResponse, LocalWorkflowAdmissionError>,
}

impl FakeAdmission {
    fn new(result: Result<LocalWorkflowAdmissionResponse, LocalWorkflowAdmissionError>) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            result,
        }
    }
}

#[async_trait]
impl LocalWorkflowAdmission for FakeAdmission {
    async fn admit(
        &self,
        _request: LocalWorkflowAdmissionRequest,
    ) -> Result<LocalWorkflowAdmissionResponse, LocalWorkflowAdmissionError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.result.clone()
    }
}

fn token() -> Arc<LocalAdmissionToken> {
    Arc::new(LocalAdmissionToken::new(TOKEN).expect("valid test token"))
}

fn document() -> LocalWorkflowAdmissionRequest {
    LocalWorkflowAdmissionRequest::new(
        "repository-1",
        "GoNeuralAI",
        "automata",
        ".github/workflows/ci.yml",
        "name: CI\non: workflow_dispatch\njobs: {}\n",
        "{}",
        "workflow_dispatch",
        "delivery-1",
        "0123456789abcdef0123456789abcdef01234567",
        "refs/heads/main",
        "CI",
    )
}

fn request(body: Body, authorization: Option<&str>) -> Request<Body> {
    let mut builder = Request::post("/api/v1/local/workflow-runs")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(authorization) = authorization {
        builder = builder.header(header::AUTHORIZATION, authorization);
    }
    builder.body(body).expect("request")
}

#[tokio::test]
async fn authentication_precedes_json_parsing_and_application_dispatch() {
    let fake = Arc::new(FakeAdmission::new(Err(
        LocalWorkflowAdmissionError::Internal,
    )));
    let app = local_workflow_admission_router(fake.clone(), token());
    let response = app
        .oneshot(request(Body::from("not json"), None))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(fake.calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
}

#[tokio::test]
async fn authorized_new_and_replayed_admissions_have_stable_status_and_documents() {
    for (replayed, expected_status) in [(false, StatusCode::CREATED), (true, StatusCode::OK)] {
        let admitted =
            LocalWorkflowAdmissionResponse::new(RUN_ID, 7, replayed).expect("valid response");
        let fake = Arc::new(FakeAdmission::new(Ok(admitted)));
        let app = local_workflow_admission_router(fake.clone(), token());
        let response = app
            .oneshot(request(
                Body::from(serde_json::to_vec(&document()).expect("JSON")),
                Some(&format!("Bearer {TOKEN}")),
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), expected_status);
        assert_eq!(fake.calls.load(Ordering::Relaxed), 1);
        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        let decoded: LocalWorkflowAdmissionResponse =
            serde_json::from_slice(&body).expect("response document");
        assert_eq!(decoded.run_id(), RUN_ID);
        assert_eq!(decoded.run_number(), 7);
        assert_eq!(decoded.is_replay(), replayed);
    }
}

#[tokio::test]
async fn application_failures_are_sanitized_without_losing_diagnostic_codes() {
    let fake = Arc::new(FakeAdmission::new(Err(
        LocalWorkflowAdmissionError::CompilationRejected(vec![
            "github.unsupported".to_owned(),
            "github.unsupported".to_owned(),
            "github.expression".to_owned(),
        ]),
    )));
    let app = local_workflow_admission_router(fake, token());
    let response = app
        .oneshot(request(
            Body::from(serde_json::to_vec(&document()).expect("JSON")),
            Some(&format!("Bearer {TOKEN}")),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    let decoded: Value = serde_json::from_slice(&body).expect("JSON");
    assert_eq!(decoded["code"], "compilation_rejected");
    assert_eq!(
        decoded["diagnostics"],
        serde_json::json!(["github.expression", "github.unsupported"])
    );
}

#[test]
fn admission_tokens_are_bounded_and_redacted() {
    assert!(LocalAdmissionToken::new(&"a".repeat(31)).is_err());
    assert!(LocalAdmissionToken::new(&"a b".repeat(16)).is_err());
    let token = LocalAdmissionToken::new(TOKEN).expect("token");
    assert_eq!(format!("{token:?}"), "LocalAdmissionToken([redacted])");
    assert!(!format!("{token:?}").contains(TOKEN));
}

#[test]
fn response_constructor_rejects_non_durable_receipts() {
    assert!(LocalWorkflowAdmissionResponse::new("not-a-run-id", 1, false).is_err());
    assert!(LocalWorkflowAdmissionResponse::new(RUN_ID, 0, false).is_err());
}
