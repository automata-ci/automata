use std::{
    fs,
    io::{Read as _, Write as _},
    net::TcpListener,
    path::Path,
    process::{Command, Output},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
};

use async_trait::async_trait;
use automata_ci::app::workflow_api::{
    LocalAdmissionToken, LocalWorkflowAdmission, LocalWorkflowAdmissionError,
    LocalWorkflowAdmissionErrorDocument, LocalWorkflowAdmissionRequest,
    LocalWorkflowAdmissionResponse, local_workflow_admission_router,
};
use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Method, Request, StatusCode, header},
};
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
        "automata-ci",
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

fn assert_closed_json_headers(response: &axum::response::Response, retry_after: Option<&str>) {
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let mut content_types = response.headers().get_all(header::CONTENT_TYPE).iter();
    assert!(content_types.next().is_some());
    assert!(content_types.next().is_none());
    let mut cache_controls = response.headers().get_all(header::CACHE_CONTROL).iter();
    assert!(cache_controls.next().is_some());
    assert!(cache_controls.next().is_none());
    assert_eq!(
        response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        retry_after
    );
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
    assert_eq!(
        response.headers()[header::WWW_AUTHENTICATE],
        "Bearer realm=\"automata-local-admission\""
    );
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    assert_eq!(body.as_ref(), br#"{"error":"unauthorized"}"#);
    let decoded: LocalWorkflowAdmissionErrorDocument =
        serde_json::from_slice(&body).expect("exact error document");
    assert_eq!(decoded.error(), "unauthorized");
    assert!(decoded.diagnostics().is_empty());
    assert!(decoded.is_current_for_status(StatusCode::UNAUTHORIZED));
}

#[tokio::test]
async fn request_envelope_is_exact_and_duplicate_authority_never_dispatches() {
    let fake = Arc::new(FakeAdmission::new(Err(
        LocalWorkflowAdmissionError::Internal,
    )));
    let app = local_workflow_admission_router(fake.clone(), token());

    let mut duplicate_authority = request(
        Body::from(serde_json::to_vec(&document()).expect("JSON")),
        Some(&format!("Bearer {TOKEN}")),
    );
    duplicate_authority.headers_mut().append(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {TOKEN}")).expect("authorization header"),
    );
    let response = app
        .clone()
        .oneshot(duplicate_authority)
        .await
        .expect("duplicate-authority response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");

    let mut query_alias = request(
        Body::from(serde_json::to_vec(&document()).expect("JSON")),
        Some(&format!("Bearer {TOKEN}")),
    );
    *query_alias.uri_mut() = "/api/v1/local/workflow-runs?ignored=1"
        .parse()
        .expect("query URI");
    let response = app
        .clone()
        .oneshot(query_alias)
        .await
        .expect("query response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let mut duplicate_content_type = request(
        Body::from(serde_json::to_vec(&document()).expect("JSON")),
        Some(&format!("Bearer {TOKEN}")),
    );
    duplicate_content_type.headers_mut().append(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let response = app
        .clone()
        .oneshot(duplicate_content_type)
        .await
        .expect("duplicate-content-type response");
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/local/workflow-runs")
                .body(Body::empty())
                .expect("method request"),
        )
        .await
        .expect("method response");
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()[header::ALLOW], "POST");
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("method body");
    let decoded: LocalWorkflowAdmissionErrorDocument =
        serde_json::from_slice(&body).expect("exact method error document");
    assert_eq!(decoded.error(), "method_not_allowed");
    assert!(decoded.is_current_for_status(StatusCode::METHOD_NOT_ALLOWED));
    assert_eq!(fake.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn semantic_request_validation_precedes_every_application_dispatch() {
    let fake = Arc::new(FakeAdmission::new(Err(
        LocalWorkflowAdmissionError::Internal,
    )));
    let app = local_workflow_admission_router(fake.clone(), token());
    let original = serde_json::to_value(document()).expect("request value");
    for (field, invalid) in [
        ("event_json", serde_json::Value::String("{".to_owned())),
        ("commit_sha", serde_json::Value::String("A".repeat(40))),
        ("git_ref", serde_json::Value::String("main".to_owned())),
        (
            "repository_owner",
            serde_json::Value::String("bad/owner".to_owned()),
        ),
    ] {
        let mut malformed = original.clone();
        malformed[field] = invalid;
        let response = app
            .clone()
            .oneshot(request(
                Body::from(serde_json::to_vec(&malformed).expect("JSON")),
                Some(&format!("Bearer {TOKEN}")),
            ))
            .await
            .expect("semantic validation response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "field {field}");
        assert_closed_json_headers(&response, None);
        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("semantic error body");
        assert_eq!(body.as_ref(), br#"{"error":"invalid_request"}"#);
    }
    assert_eq!(fake.calls.load(Ordering::Relaxed), 0);
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
        assert_closed_json_headers(&response, None);
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
async fn application_error_route_matrix_is_exact_and_only_unavailability_is_retryable() {
    for (error, expected_status, expected_code, retry_after) in [
        (
            LocalWorkflowAdmissionError::InvalidRequest,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            None,
        ),
        (
            LocalWorkflowAdmissionError::FrontendRejected(vec!["github.frontend.invalid".into()]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "frontend_rejected",
            None,
        ),
        (
            LocalWorkflowAdmissionError::CompilationRejected(vec!["github.compile.invalid".into()]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "compilation_rejected",
            None,
        ),
        (
            LocalWorkflowAdmissionError::Conflict,
            StatusCode::CONFLICT,
            "admission_conflict",
            None,
        ),
        (
            LocalWorkflowAdmissionError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "dependency_unavailable",
            Some("1"),
        ),
        (
            LocalWorkflowAdmissionError::Internal,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            None,
        ),
    ] {
        let fake = Arc::new(FakeAdmission::new(Err(error)));
        let response = local_workflow_admission_router(fake.clone(), token())
            .oneshot(request(
                Body::from(serde_json::to_vec(&document()).expect("JSON")),
                Some(&format!("Bearer {TOKEN}")),
            ))
            .await
            .expect("application error response");
        assert_eq!(response.status(), expected_status);
        assert_closed_json_headers(&response, retry_after);
        let decoded: LocalWorkflowAdmissionErrorDocument = serde_json::from_slice(
            &to_bytes(response.into_body(), 64 * 1024)
                .await
                .expect("application error body"),
        )
        .expect("current application error");
        assert_eq!(decoded.error(), expected_code);
        assert!(decoded.is_current_for_status(expected_status));
        assert_eq!(fake.calls.load(Ordering::Relaxed), 1);
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
    let decoded: LocalWorkflowAdmissionErrorDocument =
        serde_json::from_slice(&body).expect("exact error document");
    assert_eq!(decoded.error(), "compilation_rejected");
    assert_eq!(
        decoded.diagnostics(),
        ["github.expression", "github.unsupported"]
    );
    assert!(decoded.is_current_for_status(StatusCode::UNPROCESSABLE_ENTITY));
}

#[tokio::test]
async fn malformed_adapter_diagnostics_are_never_reflected() {
    let mut diagnostics = (0..256)
        .map(|index| format!("github.compile.code_{index:03}"))
        .collect::<Vec<_>>();
    diagnostics.push("z_hostile\u{1b}[2J".to_owned());
    let fake = Arc::new(FakeAdmission::new(Err(
        LocalWorkflowAdmissionError::CompilationRejected(diagnostics),
    )));
    let app = local_workflow_admission_router(fake, token());
    let response = app
        .oneshot(request(
            Body::from(serde_json::to_vec(&document()).expect("JSON")),
            Some(&format!("Bearer {TOKEN}")),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    assert!(
        !body
            .windows(b"hostile".len())
            .any(|bytes| bytes == b"hostile")
    );
    let decoded: LocalWorkflowAdmissionErrorDocument =
        serde_json::from_slice(&body).expect("exact error document");
    assert_eq!(decoded.error(), "internal_error");
    assert!(decoded.diagnostics().is_empty());
    assert!(decoded.is_current_for_status(StatusCode::INTERNAL_SERVER_ERROR));
}

#[tokio::test]
async fn adapter_diagnostics_are_sorted_deduplicated_and_bounded() {
    let diagnostics = (0..300)
        .rev()
        .flat_map(|index| {
            let code = format!("github.compile.code_{index:03}");
            [code.clone(), code]
        })
        .collect();
    let fake = Arc::new(FakeAdmission::new(Err(
        LocalWorkflowAdmissionError::FrontendRejected(diagnostics),
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
    let decoded: LocalWorkflowAdmissionErrorDocument =
        serde_json::from_slice(&body).expect("exact error document");
    assert_eq!(decoded.diagnostics().len(), 256);
    assert_eq!(
        decoded.diagnostics().first().map(String::as_str),
        Some("github.compile.code_000")
    );
    assert_eq!(
        decoded.diagnostics().last().map(String::as_str),
        Some("github.compile.code_255")
    );
    assert!(decoded.is_current_for_status(StatusCode::UNPROCESSABLE_ENTITY));
}

#[test]
fn public_error_documents_cannot_deserialize_outside_exact_bounds() {
    for document in [
        serde_json::json!({"error": "invalid_request", "diagnostics": null}),
        serde_json::json!({"error": "compilation_rejected"}),
        serde_json::json!({"error": "unknown_error"}),
    ] {
        assert!(serde_json::from_value::<LocalWorkflowAdmissionErrorDocument>(document).is_err());
    }

    let oversized_code = format!("github.{}", "a".repeat(122));
    let oversized_code_document = serde_json::json!({
        "error": "compilation_rejected",
        "diagnostics": [oversized_code],
    });
    assert!(
        serde_json::from_value::<LocalWorkflowAdmissionErrorDocument>(oversized_code_document)
            .is_err()
    );

    let too_many_codes = (0..257)
        .map(|index| format!("github.compile.code_{index:03}"))
        .collect::<Vec<_>>();
    let too_many_document = serde_json::json!({
        "error": "frontend_rejected",
        "diagnostics": too_many_codes,
    });
    assert!(
        serde_json::from_value::<LocalWorkflowAdmissionErrorDocument>(too_many_document).is_err()
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
    assert!(LocalWorkflowAdmissionResponse::new(RUN_ID.to_ascii_uppercase(), 1, false).is_err());
    assert!(
        LocalWorkflowAdmissionResponse::new("00000000-0000-0000-0000-000000000000", 1, false)
            .is_err()
    );
    assert!(LocalWorkflowAdmissionResponse::new(RUN_ID, 0, false).is_err());

    for run_id in [
        RUN_ID.to_ascii_uppercase(),
        "00000000-0000-0000-0000-000000000000".to_owned(),
    ] {
        assert!(
            serde_json::from_value::<LocalWorkflowAdmissionResponse>(serde_json::json!({
                "run_id": run_id,
                "run_number": 1,
                "replayed": false,
            }))
            .is_err()
        );
    }
}

#[test]
fn workflow_cli_process_obeys_success_failure_and_header_contracts() {
    let source_path = std::env::temp_dir().join(format!(
        "automata-workflow-admission-{}.yml",
        std::process::id()
    ));
    fs::write(&source_path, "name: CI\non: workflow_dispatch\njobs: {}\n")
        .expect("workflow fixture must be writable");

    let current_headers = vec![
        ("Content-Type", "application/json"),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
    ];
    let (server, worker) = serve_workflow_reply(
        "201 Created",
        current_headers.clone(),
        br#"{"run_id":"45e8cc88-5075-40c5-a6cb-9f1dad46c3b1","run_number":7,"replayed":false}"#,
    );
    let output = run_workflow_cli(&server, &source_path);
    assert!(output.status.success(), "stderr: {:?}", output.stderr);
    assert_eq!(
        output.stdout,
        b"run\t45e8cc88-5075-40c5-a6cb-9f1dad46c3b1\nnumber\t7\nreplayed\tfalse\n"
    );
    assert!(output.stderr.is_empty());
    worker.join().expect("success server must finish");

    let mut unavailable_headers = current_headers.clone();
    unavailable_headers.push(("Retry-After", "1"));
    let (server, worker) = serve_workflow_reply(
        "503 Service Unavailable",
        unavailable_headers,
        br#"{"error":"dependency_unavailable"}"#,
    );
    let output = run_workflow_cli(&server, &source_path);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr must be UTF-8");
    assert!(stderr.contains("dependency_unavailable"));
    assert!(stderr.contains("503 Service Unavailable"));
    assert!(!stderr.contains(TOKEN));
    worker.join().expect("unavailable server must finish");

    let invalid_headers = vec![
        ("Content-Type", "application/json"),
        ("Cache-Control", "public"),
        ("X-Content-Type-Options", "nosniff"),
    ];
    let (server, worker) =
        serve_workflow_reply("201 Created", invalid_headers, b"workflow-response-secret");
    let output = run_workflow_cli(&server, &source_path);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr must be UTF-8");
    assert!(stderr.contains("invalid workflow admission response"));
    assert!(!stderr.contains("workflow-response-secret"));
    assert!(!stderr.contains(TOKEN));
    worker.join().expect("invalid-header server must finish");

    fs::remove_file(source_path).expect("workflow fixture must be removable");
}

fn run_workflow_cli(server: &str, source_path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_automata"))
        .args([
            "--server-url",
            server,
            "workflow",
            "admit",
            "-R",
            "automata-ci/automata",
            "--provider-repository-id",
            "repository-1",
            "--source-file",
            source_path.to_str().expect("UTF-8 fixture path"),
            "--delivery-id",
            "delivery-1",
            "--commit-sha",
            "0123456789abcdef0123456789abcdef01234567",
        ])
        .env("AUTOMATA_LOCAL_ADMISSION_TOKEN", TOKEN)
        .env_remove("RUST_LOG")
        .output()
        .expect("workflow CLI process must run")
}

fn serve_workflow_reply(
    status: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    body: &'static [u8],
) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("workflow server must bind");
    let address = listener.local_addr().expect("workflow server address");
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("workflow request must connect");
        let request = read_http_request(&mut stream);
        assert!(request.starts_with(b"POST /api/v1/local/workflow-runs HTTP/1.1\r\n"));
        let request_text = String::from_utf8_lossy(&request).to_ascii_lowercase();
        assert!(request_text.contains("\r\ncontent-type: application/json\r\n"));
        assert!(request_text.contains("\r\nauthorization: bearer "));

        write!(stream, "HTTP/1.1 {status}\r\n").expect("status must be writable");
        for (name, value) in headers {
            write!(stream, "{name}: {value}\r\n").expect("header must be writable");
        }
        write!(
            stream,
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("framing must be writable");
        stream.write_all(body).expect("body must be writable");
        stream.flush().expect("response must flush");
    });
    (format!("http://{address}"), worker)
}

fn read_http_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut expected_length = None;
    loop {
        let mut buffer = [0_u8; 4 * 1024];
        let read = stream.read(&mut buffer).expect("request must be readable");
        assert_ne!(read, 0, "request ended before its declared body");
        request.extend_from_slice(&buffer[..read]);
        let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let body_start = header_end + 4;
        let length = *expected_length.get_or_insert_with(|| {
            String::from_utf8_lossy(&request[..header_end])
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .and_then(|value| value.parse::<usize>().ok())
                })
                .expect("request content length")
        });
        if request.len() >= body_start + length {
            return request;
        }
    }
}
