mod support;

use std::time::Duration;

use automata_ci_auth::secret::SecretString;
use automata_ci_github::{
    GithubCheckAnnotation, GithubCheckAnnotationLevel, GithubCheckAppId, GithubCheckCompletion,
    GithubCheckConclusion, GithubCheckCreateIndeterminateKind, GithubCheckDetailsUrl,
    GithubCheckExternalId, GithubCheckModelError, GithubCheckName, GithubCheckOutput,
    GithubCheckRequestedAction, GithubCheckRunCreateOutcome, GithubCheckRunId,
    GithubCheckRunIdentity, GithubCheckRunReconciliation, GithubCheckRunState,
    GithubCheckSuiteCreateOutcome, GithubCheckSuiteId, GithubCheckTimestamp, GithubChecksError,
    GithubHttpEndpoint, GithubHttpLimits, GithubObservedCheckConclusion,
};
use automata_ci_scm::{ExactRevision, RepositoryId};
use serde_json::{Value, json};
use support::{FixtureServer, ResponseSpec};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    task::JoinHandle,
};
use url::Url;

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const OTHER_SHA: &str = "1123456789abcdef0123456789abcdef01234567";
const TOKEN: &str = "github_pat_top_secret_checks_token";
const NAME: &str = "Automata CI / verify";
const EXTERNAL_ID: &str = "run:00000000-0000-4000-8000-000000000001";
const DETAILS_URL: &str = "https://ci.automata.example/acme/widget/actions/runs/run/jobs/job";

fn repository() -> RepositoryId {
    RepositoryId::new("acme/widget").expect("repository")
}

fn revision() -> ExactRevision {
    ExactRevision::new(SHA).expect("revision")
}

fn token() -> SecretString {
    SecretString::new(TOKEN).expect("token")
}

fn lifecycle_timestamp() -> GithubCheckTimestamp {
    GithubCheckTimestamp::from_unix_millis(1_786_666_505_000).expect("timestamp")
}

fn identity() -> GithubCheckRunIdentity {
    GithubCheckRunIdentity::new(
        GithubCheckAppId::new(17).expect("app id"),
        GithubCheckSuiteId::new(23).expect("suite id"),
        revision(),
        GithubCheckName::new(NAME).expect("check name"),
        GithubCheckExternalId::new(EXTERNAL_ID).expect("external id"),
        GithubCheckDetailsUrl::new(Url::parse(DETAILS_URL).expect("details URL"))
            .expect("valid details URL"),
    )
}

fn suite_json(id: u64, app_id: u64, sha: &str) -> String {
    json!({"id": id, "head_sha": sha, "app": {"id": app_id}}).to_string()
}

fn run_value(
    id: u64,
    app_id: u64,
    suite_id: u64,
    sha: &str,
    name: &str,
    external_id: Option<&str>,
    state: (&str, Option<&str>),
) -> Value {
    let (status, conclusion) = state;
    json!({
        "id": id,
        "head_sha": sha,
        "external_id": external_id,
        "details_url": DETAILS_URL,
        "status": status,
        "conclusion": conclusion,
        "name": name,
        "check_suite": {"id": suite_id},
        "app": {"id": app_id},
        "output": {
            "title": "provider-controlled output must never enter the model",
            "summary": "provider body marker"
        }
    })
}

fn exact_run_value(id: u64, status: &str, conclusion: Option<&str>) -> Value {
    run_value(
        id,
        17,
        23,
        SHA,
        NAME,
        Some(EXTERNAL_ID),
        (status, conclusion),
    )
}

fn list_url(server: &FixtureServer, page: u64) -> Url {
    let mut url = server.url("api/repos/acme/widget/check-suites/23/check-runs");
    url.query_pairs_mut()
        .append_pair("check_name", NAME)
        .append_pair("filter", "all")
        .append_pair("per_page", "100")
        .append_pair("page", &page.to_string());
    url
}

fn annotation(path: &str, line: u32, message: &str) -> GithubCheckAnnotation {
    GithubCheckAnnotation::new(
        path,
        line,
        line,
        None,
        None,
        GithubCheckAnnotationLevel::Failure,
        message,
        Some("compiler".to_owned()),
    )
    .expect("annotation")
}

#[tokio::test]
async fn check_suite_creation_preserves_the_exact_200_and_201_distinction() {
    let server = FixtureServer::spawn().await;
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        suite_json(23, 17, SHA),
    ));
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::CREATED,
        suite_json(24, 17, SHA),
    ));
    let endpoint = server.endpoint();
    let token = token();
    let app = GithubCheckAppId::new(17).expect("app id");

    let existing = endpoint
        .create_check_suite(&repository(), &revision(), app, &token)
        .await
        .expect("existing suite response");
    let created = endpoint
        .create_check_suite(&repository(), &revision(), app, &token)
        .await
        .expect("created suite response");

    let GithubCheckSuiteCreateOutcome::Existing(existing) = existing else {
        panic!("expected existing suite");
    };
    let GithubCheckSuiteCreateOutcome::Created(created) = created else {
        panic!("expected created suite");
    };
    assert_eq!(existing.id().get(), 23);
    assert_eq!(created.id().get(), 24);
    assert_eq!(existing.app_id(), app);
    assert_eq!(existing.head_sha(), &revision());

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert_eq!(request.method, "POST");
        assert_eq!(request.uri, "/api/repos/acme/widget/check-suites");
        assert_eq!(
            request.headers["authorization"].to_str().expect("auth"),
            format!("Bearer {TOKEN}")
        );
        assert_eq!(request.headers["accept"], "application/vnd.github+json");
        assert_eq!(
            serde_json::from_slice::<Value>(&request.body).expect("request JSON"),
            json!({"head_sha": SHA})
        );
    }
}

#[tokio::test]
async fn annotation_batches_are_bounded_and_preserve_exact_source_locations() {
    let server = FixtureServer::spawn().await;
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        exact_run_value(41, "completed", Some("failure")).to_string(),
    ));
    let output = GithubCheckOutput::new(
        "Failed",
        "One source diagnostic",
        Some("See the full run in Automata.".to_owned()),
    )
    .expect("output");
    let annotations = [GithubCheckAnnotation::new(
        "src/lib.rs",
        7,
        7,
        Some(3),
        Some(9),
        GithubCheckAnnotationLevel::Failure,
        "type mismatch",
        Some("compiler".to_owned()),
    )
    .expect("annotation")];

    server
        .endpoint()
        .append_check_run_annotations(
            &repository(),
            GithubCheckRunId::new(41).expect("run id"),
            &identity(),
            GithubCheckConclusion::Failure,
            &output,
            &annotations,
            &token(),
        )
        .await
        .expect("annotation append");

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "PATCH");
    assert_eq!(requests[0].uri, "/api/repos/acme/widget/check-runs/41");
    let body: Value = serde_json::from_slice(&requests[0].body).expect("request JSON");
    assert_eq!(body["output"]["title"], "Failed");
    assert_eq!(body["output"]["annotations"][0]["path"], "src/lib.rs");
    assert_eq!(body["output"]["annotations"][0]["start_line"], 7);
    assert_eq!(body["output"]["annotations"][0]["start_column"], 3);
    assert_eq!(
        body["output"]["annotations"][0]["annotation_level"],
        "failure"
    );

    let oversized = vec![annotation("src/lib.rs", 1, "failure"); 51];
    assert_eq!(
        server
            .endpoint()
            .append_check_run_annotations(
                &repository(),
                GithubCheckRunId::new(41).expect("run id"),
                &identity(),
                GithubCheckConclusion::Failure,
                &output,
                &oversized,
                &token(),
            )
            .await,
        Err(GithubChecksError::InvalidRequest)
    );
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn annotation_reconciliation_fully_paginates_same_origin_results() {
    let server = FixtureServer::spawn().await;
    let page_two =
        server.url("api/repos/acme/widget/check-runs/41/annotations?per_page=100&page=2");
    server.enqueue(
        ResponseSpec::json(
            axum::http::StatusCode::OK,
            json!([{
                "path": "src/lib.rs", "start_line": 7, "end_line": 7,
                "start_column": null, "end_column": null,
                "annotation_level": "failure", "message": "first", "title": "compiler"
            }])
            .to_string(),
        )
        .header("link", format!("<{page_two}>; rel=\"next\"")),
    );
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        json!([{
            "path": "src/main.rs", "start_line": 9, "end_line": 10,
            "start_column": null, "end_column": null,
            "annotation_level": "warning", "message": "second", "title": null
        }])
        .to_string(),
    ));

    let annotations = server
        .endpoint()
        .list_check_run_annotations(
            &repository(),
            GithubCheckRunId::new(41).expect("run id"),
            &token(),
        )
        .await
        .expect("annotation list");
    assert_eq!(annotations.len(), 2);
    assert_eq!(annotations[0].path(), "src/lib.rs");
    assert_eq!(annotations[1].level(), GithubCheckAnnotationLevel::Warning);
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn check_suite_creation_resolves_the_exact_auto_created_suite_after_422() {
    let server = FixtureServer::spawn().await;
    server.enqueue(ResponseSpec::status(
        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
    ));
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        json!({
            "total_count": 1,
            "check_suites": [
                {"id": 23, "head_sha": SHA, "app": {"id": 17}}
            ]
        })
        .to_string(),
    ));
    let endpoint = server.endpoint();
    let app = GithubCheckAppId::new(17).expect("app id");

    let outcome = endpoint
        .create_check_suite(&repository(), &revision(), app, &token())
        .await
        .expect("existing suite must reconcile");
    let GithubCheckSuiteCreateOutcome::Existing(suite) = outcome else {
        panic!("expected an existing suite");
    };
    assert_eq!(suite.id().get(), 23);
    assert_eq!(suite.app_id(), app);
    assert_eq!(suite.head_sha(), &revision());

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].uri, "/api/repos/acme/widget/check-suites");
    assert_eq!(requests[1].method, "GET");
    assert_eq!(
        requests[1].uri,
        concat!(
            "/api/repos/acme/widget/commits/",
            "0123456789abcdef0123456789abcdef01234567",
            "/check-suites?app_id=17&per_page=100&page=1"
        )
    );
    assert!(requests[1].body.is_empty());
}

#[tokio::test]
async fn check_suite_creation_does_not_hide_a_rejected_request_without_an_exact_suite() {
    let server = FixtureServer::spawn().await;
    server.enqueue(ResponseSpec::status(
        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
    ));
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        json!({"total_count": 0, "check_suites": []}).to_string(),
    ));

    let error = server
        .endpoint()
        .create_check_suite(
            &repository(),
            &revision(),
            GithubCheckAppId::new(17).expect("app id"),
            &token(),
        )
        .await
        .expect_err("an unrelated rejected request must stay rejected");
    assert_eq!(error, GithubChecksError::Rejected);
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn check_run_creation_sends_only_bounded_identity_and_accepts_exact_201() {
    let server = FixtureServer::spawn().await;
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::CREATED,
        exact_run_value(41, "queued", None).to_string(),
    ));
    let endpoint = server.endpoint();
    let identity = identity();

    let outcome = endpoint
        .create_check_run(&repository(), &identity, &token())
        .await
        .expect("create response");
    let GithubCheckRunCreateOutcome::Created(run) = outcome else {
        panic!("expected a determinate create");
    };
    assert_eq!(run.id().get(), 41);
    assert_eq!(run.identity(), &identity);
    assert_eq!(run.state(), GithubCheckRunState::Queued);

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].uri, "/api/repos/acme/widget/check-runs");
    let body: Value = serde_json::from_slice(&requests[0].body).expect("request JSON");
    assert_eq!(
        body,
        json!({
            "name": NAME,
            "head_sha": SHA,
            "status": "queued",
            "external_id": EXTERNAL_ID,
            "details_url": DETAILS_URL,
            "output": {
                "title": "Queued",
                "summary": format!("Waiting for a runner.\n\n[Open this job in Automata]({DETAILS_URL})")
            }
        })
    );
    for forbidden in ["annotations", "actions", "images", "logs", "artifacts"] {
        assert!(body.get(forbidden).is_none(), "forbidden field {forbidden}");
    }
}

#[tokio::test]
async fn create_success_contract_mismatches_are_indeterminate_not_retryable_errors() {
    let server = FixtureServer::spawn().await;
    let wrong_responses = [
        run_value(41, 18, 23, SHA, NAME, Some(EXTERNAL_ID), ("queued", None)),
        run_value(
            41,
            17,
            23,
            OTHER_SHA,
            NAME,
            Some(EXTERNAL_ID),
            ("queued", None),
        ),
        run_value(
            41,
            17,
            23,
            SHA,
            "other",
            Some(EXTERNAL_ID),
            ("queued", None),
        ),
        run_value(41, 17, 23, SHA, NAME, Some("other"), ("queued", None)),
        run_value(41, 17, 24, SHA, NAME, Some(EXTERNAL_ID), ("queued", None)),
        exact_run_value(41, "in_progress", None),
        exact_run_value(41, "queued", Some("success")),
    ];
    for body in wrong_responses {
        server.enqueue(ResponseSpec::json(
            axum::http::StatusCode::CREATED,
            body.to_string(),
        ));
    }
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::CREATED,
        "{malformed",
    ));
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        exact_run_value(41, "queued", None).to_string(),
    ));
    let endpoint = server.endpoint();

    for _ in 0..9 {
        let outcome = endpoint
            .create_check_run(&repository(), &identity(), &token())
            .await
            .expect("indeterminate outcome");
        let GithubCheckRunCreateOutcome::Indeterminate(indeterminate) = outcome else {
            panic!("mismatched success must be indeterminate");
        };
        assert_eq!(
            indeterminate.kind(),
            GithubCheckCreateIndeterminateKind::InvalidSuccessResponse
        );
    }
}

#[tokio::test]
async fn create_5xx_and_timeout_are_explicitly_indeterminate_and_never_retried() {
    let server = FixtureServer::spawn().await;
    server.enqueue(
        ResponseSpec::json(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            format!(r#"{{"message":"{TOKEN}"}}"#),
        )
        .header("retry-after", "19")
        .header("x-ratelimit-reset", "1893456000")
        .header("x-ratelimit-remaining", "0"),
    );
    let outcome = server
        .endpoint()
        .create_check_run(&repository(), &identity(), &token())
        .await
        .expect("indeterminate response");
    let GithubCheckRunCreateOutcome::Indeterminate(indeterminate) = outcome else {
        panic!("5xx create must be indeterminate");
    };
    assert_eq!(
        indeterminate.kind(),
        GithubCheckCreateIndeterminateKind::ProviderUnavailable
    );
    assert_eq!(
        indeterminate.retry_evidence().retry_after_seconds(),
        Some(19)
    );
    assert_eq!(
        indeterminate.retry_evidence().rate_limit_reset_at(),
        Some(1_893_456_000)
    );
    assert!(indeterminate.retry_evidence().rate_limit_remaining_zero());
    assert_eq!(server.requests().len(), 1);

    let limits = GithubHttpLimits::new(
        1_048_576,
        4,
        100,
        Duration::from_millis(10),
        Duration::from_millis(30),
    )
    .expect("limits");
    let raw = RawServer::hanging(Duration::from_secs(1)).await;
    let outcome = raw
        .endpoint(limits)
        .create_check_suite(
            &repository(),
            &revision(),
            GithubCheckAppId::new(17).expect("app id"),
            &token(),
        )
        .await
        .expect("timeout outcome");
    let GithubCheckSuiteCreateOutcome::Indeterminate(indeterminate) = outcome else {
        panic!("timeout must be indeterminate");
    };
    assert_eq!(
        indeterminate.kind(),
        GithubCheckCreateIndeterminateKind::Transport
    );
}

#[tokio::test]
async fn truncated_create_success_is_indeterminate() {
    let raw = RawServer::reply(
        b"HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: 999\r\nconnection: close\r\n\r\n{\"id\":41"
            .to_vec(),
    )
    .await;
    let outcome = raw
        .endpoint(GithubHttpLimits::default())
        .create_check_run(&repository(), &identity(), &token())
        .await
        .expect("truncated outcome");
    let GithubCheckRunCreateOutcome::Indeterminate(indeterminate) = outcome else {
        panic!("truncated success must be indeterminate");
    };
    assert_eq!(
        indeterminate.kind(),
        GithubCheckCreateIndeterminateKind::InvalidSuccessResponse
    );
}

#[tokio::test]
async fn redirects_are_not_followed_and_repository_paths_are_confined() {
    let server = FixtureServer::spawn().await;
    server.enqueue(
        ResponseSpec::status(axum::http::StatusCode::FOUND)
            .header("location", server.url("escaped").as_str()),
    );
    let error = server
        .endpoint()
        .create_check_suite(
            &repository(),
            &revision(),
            GithubCheckAppId::new(17).expect("app id"),
            &token(),
        )
        .await
        .expect_err("redirect must fail");
    assert_eq!(error, GithubChecksError::InvalidResponse);
    assert_eq!(server.requests().len(), 1);
    assert_eq!(server.remaining_responses(), 0);

    for invalid in ["acme/widget/extra", "acme/widget.git", "acme/%2fwidget"] {
        let repository = RepositoryId::new(invalid).expect("opaque repository id");
        let error = server
            .endpoint()
            .get_check_run(
                &repository,
                GithubCheckRunId::new(41).expect("run id"),
                &identity(),
                &token(),
            )
            .await
            .expect_err("unsafe GitHub path must fail locally");
        assert_eq!(error, GithubChecksError::InvalidRequest);
    }
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn get_validates_id_app_sha_name_external_suite_status_and_conclusion() {
    let server = FixtureServer::spawn().await;
    let mut missing_external_id = exact_run_value(41, "queued", None);
    missing_external_id
        .as_object_mut()
        .expect("run object")
        .remove("external_id");
    let mut missing_details_url = exact_run_value(41, "queued", None);
    missing_details_url
        .as_object_mut()
        .expect("run object")
        .remove("details_url");
    let mut wrong_details_url = exact_run_value(41, "queued", None);
    wrong_details_url["details_url"] = json!("https://attacker.invalid/run");
    let mut missing_conclusion = exact_run_value(41, "queued", None);
    missing_conclusion
        .as_object_mut()
        .expect("run object")
        .remove("conclusion");
    let wrong_responses = [
        exact_run_value(42, "queued", None),
        run_value(41, 18, 23, SHA, NAME, Some(EXTERNAL_ID), ("queued", None)),
        run_value(
            41,
            17,
            23,
            OTHER_SHA,
            NAME,
            Some(EXTERNAL_ID),
            ("queued", None),
        ),
        run_value(
            41,
            17,
            23,
            SHA,
            "other",
            Some(EXTERNAL_ID),
            ("queued", None),
        ),
        run_value(41, 17, 23, SHA, NAME, Some("other"), ("queued", None)),
        run_value(41, 17, 24, SHA, NAME, Some(EXTERNAL_ID), ("queued", None)),
        exact_run_value(41, "waiting", None),
        exact_run_value(41, "completed", None),
        exact_run_value(41, "completed", Some("startup_failure")),
        missing_external_id,
        missing_details_url,
        wrong_details_url,
        missing_conclusion,
    ];
    for body in wrong_responses {
        server.enqueue(ResponseSpec::json(
            axum::http::StatusCode::OK,
            body.to_string(),
        ));
    }
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        exact_run_value(41, "completed", Some("stale")).to_string(),
    ));
    let endpoint = server.endpoint();
    for _ in 0..13 {
        let error = endpoint
            .get_check_run(
                &repository(),
                GithubCheckRunId::new(41).expect("run id"),
                &identity(),
                &token(),
            )
            .await
            .expect_err("mismatch must fail");
        assert_eq!(error, GithubChecksError::InvalidResponse);
    }
    let run = endpoint
        .get_check_run(
            &repository(),
            GithubCheckRunId::new(41).expect("run id"),
            &identity(),
            &token(),
        )
        .await
        .expect("stale is a valid observed conclusion");
    assert_eq!(
        run.state(),
        GithubCheckRunState::Completed(GithubObservedCheckConclusion::Stale)
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn terminal_patch_sends_completion_time_and_native_output_and_validates_exact_response() {
    let server = FixtureServer::spawn().await;
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        exact_run_value(41, "completed", Some("success")).to_string(),
    ));
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        exact_run_value(41, "completed", Some("failure")).to_string(),
    ));
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        exact_run_value(41, "completed", Some("success")).to_string(),
    ));
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        exact_run_value(41, "completed", Some("success")).to_string(),
    ));
    let endpoint = server.endpoint();
    let run = endpoint
        .complete_check_run(
            &repository(),
            GithubCheckRunId::new(41).expect("run id"),
            &identity(),
            GithubCheckCompletion::new(
                GithubCheckConclusion::Success,
                Some(&lifecycle_timestamp()),
                &lifecycle_timestamp(),
                None,
                &[],
            )
            .expect("completion"),
            &token(),
        )
        .await
        .expect("terminal response");
    assert_eq!(
        run.state(),
        GithubCheckRunState::Completed(GithubObservedCheckConclusion::Success)
    );
    let error = endpoint
        .complete_check_run(
            &repository(),
            GithubCheckRunId::new(41).expect("run id"),
            &identity(),
            GithubCheckCompletion::new(
                GithubCheckConclusion::Success,
                Some(&lifecycle_timestamp()),
                &lifecycle_timestamp(),
                None,
                &[],
            )
            .expect("completion"),
            &token(),
        )
        .await
        .expect_err("wrong terminal response");
    assert_eq!(error, GithubChecksError::InvalidResponse);
    let custom_output = GithubCheckOutput::new(
        "Passed with details",
        "**2 steps** — 2 passed.",
        Some("| Step | Result |\n| --- | --- |\n| `test` | passed |".to_owned()),
    )
    .expect("custom output");
    endpoint
        .complete_check_run(
            &repository(),
            GithubCheckRunId::new(41).expect("run id"),
            &identity(),
            GithubCheckCompletion::new(
                GithubCheckConclusion::Success,
                Some(&lifecycle_timestamp()),
                &lifecycle_timestamp(),
                Some(&custom_output),
                &[],
            )
            .expect("completion"),
            &token(),
        )
        .await
        .expect("custom terminal response");
    let actions = [GithubCheckRequestedAction::new(
        "Re-run all jobs",
        "Run every job in this workflow",
        "rerun_all",
    )
    .expect("requested action")];
    endpoint
        .complete_check_run(
            &repository(),
            GithubCheckRunId::new(41).expect("run id"),
            &identity(),
            GithubCheckCompletion::new(
                GithubCheckConclusion::Success,
                Some(&lifecycle_timestamp()),
                &lifecycle_timestamp(),
                None,
                &actions,
            )
            .expect("completion"),
            &token(),
        )
        .await
        .expect("terminal response with action");

    let requests = server.requests();
    assert_eq!(requests[0].method, "PATCH");
    assert_eq!(requests[0].uri, "/api/repos/acme/widget/check-runs/41");
    let body: Value = serde_json::from_slice(&requests[0].body).expect("patch JSON");
    assert_eq!(
        body,
        json!({
            "status": "completed",
            "conclusion": "success",
            "started_at": "2026-08-14T00:15:05Z",
            "completed_at": "2026-08-14T00:15:05Z",
            "output": {
                "title": "Passed",
                "summary": format!("The job completed successfully.\n\n[Open this job in Automata]({DETAILS_URL})")
            }
        })
    );
    assert_eq!(body.as_object().expect("object").len(), 5);
    let custom_body: Value = serde_json::from_slice(&requests[2].body).expect("custom patch JSON");
    assert_eq!(custom_body["output"]["title"], "Passed with details");
    assert_eq!(custom_body["output"]["summary"], "**2 steps** — 2 passed.");
    assert!(
        custom_body["output"]["text"]
            .as_str()
            .expect("custom text")
            .contains("`test`")
    );
    let action_body: Value =
        serde_json::from_slice(&requests[3].body).expect("requested-action patch JSON");
    assert_eq!(
        action_body["actions"],
        json!([{
            "label": "Re-run all jobs",
            "description": "Run every job in this workflow",
            "identifier": "rerun_all"
        }])
    );
}

#[tokio::test]
async fn in_progress_patch_sends_start_time_and_native_output_and_validates_exact_response() {
    let server = FixtureServer::spawn().await;
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        exact_run_value(41, "in_progress", None).to_string(),
    ));
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        exact_run_value(41, "queued", None).to_string(),
    ));
    let endpoint = server.endpoint();
    let run = endpoint
        .start_check_run(
            &repository(),
            GithubCheckRunId::new(41).expect("run id"),
            &identity(),
            &lifecycle_timestamp(),
            &token(),
        )
        .await
        .expect("in-progress response");
    assert_eq!(run.state(), GithubCheckRunState::InProgress);
    let error = endpoint
        .start_check_run(
            &repository(),
            GithubCheckRunId::new(41).expect("run id"),
            &identity(),
            &lifecycle_timestamp(),
            &token(),
        )
        .await
        .expect_err("wrong nonterminal response");
    assert_eq!(error, GithubChecksError::InvalidResponse);

    let requests = server.requests();
    assert_eq!(requests[0].method, "PATCH");
    assert_eq!(requests[0].uri, "/api/repos/acme/widget/check-runs/41");
    let body: Value = serde_json::from_slice(&requests[0].body).expect("patch JSON");
    assert_eq!(
        body,
        json!({
            "status": "in_progress",
            "started_at": "2026-08-14T00:15:05Z",
            "output": {
                "title": "Running",
                "summary": format!("This job is running. Live progress and logs are available in Automata.\n\n[Open this job in Automata]({DETAILS_URL})")
            }
        })
    );
    assert_eq!(body.as_object().expect("object").len(), 3);
}

#[tokio::test]
async fn list_for_exact_suite_fully_paginates_filters_and_reconciles_one_match() {
    let server = FixtureServer::spawn().await;
    let next = list_url(&server, 2);
    server.enqueue(
        ResponseSpec::json(
            axum::http::StatusCode::OK,
            json!({
                "total_count": 2,
                "check_runs": [run_value(
                    40, 17, 23, SHA, NAME, Some("another-run"), ("completed", Some("failure"))
                )]
            })
            .to_string(),
        )
        .header("link", format!("<{next}>; rel=\"next\"")),
    );
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        json!({
            "total_count": 2,
            "check_runs": [exact_run_value(41, "queued", None)]
        })
        .to_string(),
    ));

    let outcome = server
        .endpoint()
        .reconcile_check_run_creation(&repository(), &identity(), &token())
        .await
        .expect("reconciliation");
    let GithubCheckRunReconciliation::Exact(run) = outcome else {
        panic!("expected exact reconciliation");
    };
    assert_eq!(run.id().get(), 41);

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(request.method, "GET");
        let url = Url::parse(&format!("http://localhost{}", request.uri)).expect("request URL");
        assert_eq!(
            url.path(),
            "/api/repos/acme/widget/check-suites/23/check-runs"
        );
        let query: std::collections::BTreeMap<_, _> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(query.get("check_name").map(String::as_str), Some(NAME));
        assert_eq!(query.get("filter").map(String::as_str), Some("all"));
        assert_eq!(query.get("per_page").map(String::as_str), Some("100"));
        assert_eq!(
            query.get("page").map(String::as_str),
            Some(if index == 0 { "1" } else { "2" })
        );
    }
}

#[tokio::test]
async fn reconciliation_distinguishes_missing_exact_and_duplicate_exact_matches() {
    let missing_server = FixtureServer::spawn().await;
    missing_server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        json!({
            "total_count": 1,
            "check_runs": [run_value(
                40, 17, 23, SHA, NAME, Some("another-run"), ("queued", None)
            )]
        })
        .to_string(),
    ));
    assert_eq!(
        missing_server
            .endpoint()
            .reconcile_check_run_creation(&repository(), &identity(), &token())
            .await
            .expect("missing reconciliation"),
        GithubCheckRunReconciliation::Missing
    );

    let duplicate_server = FixtureServer::spawn().await;
    duplicate_server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        json!({
            "total_count": 2,
            "check_runs": [
                exact_run_value(41, "queued", None),
                exact_run_value(42, "queued", None)
            ]
        })
        .to_string(),
    ));
    assert_eq!(
        duplicate_server
            .endpoint()
            .reconcile_check_run_creation(&repository(), &identity(), &token())
            .await
            .expect("duplicate reconciliation"),
        GithubCheckRunReconciliation::Ambiguous
    );
}

#[tokio::test]
async fn reconciliation_validates_every_page_even_after_finding_duplicates() {
    let server = FixtureServer::spawn().await;
    server.enqueue(
        ResponseSpec::json(
            axum::http::StatusCode::OK,
            json!({
                "total_count": 3,
                "check_runs": [
                    exact_run_value(41, "queued", None),
                    exact_run_value(42, "queued", None)
                ]
            })
            .to_string(),
        )
        .header("link", format!("<{}>; rel=\"next\"", list_url(&server, 2))),
    );
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        json!({
            "total_count": 3,
            "check_runs": [run_value(
                43,
                18,
                23,
                SHA,
                NAME,
                Some(EXTERNAL_ID),
                ("queued", None)
            )]
        })
        .to_string(),
    ));

    let error = server
        .endpoint()
        .reconcile_check_run_creation(&repository(), &identity(), &token())
        .await
        .expect_err("later invalid page must take precedence over ambiguity");
    assert_eq!(error, GithubChecksError::InvalidResponse);
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn pagination_rejects_cycles_cross_origin_path_filter_and_query_drift() {
    let mut cases = Vec::new();
    let server = FixtureServer::spawn().await;
    cases.push(list_url(&server, 1));
    cases.push(Url::parse("http://127.0.0.1:9/api/repos/acme/widget/check-suites/23/check-runs?check_name=Automata%20CI%20%2F%20verify&filter=all&per_page=100&page=2").expect("cross-origin URL"));
    cases.push(server.url("api/repos/acme/widget/check-runs?check_name=Automata%20CI%20%2F%20verify&filter=all&per_page=100&page=2"));
    let mut latest = list_url(&server, 2);
    latest
        .query_pairs_mut()
        .clear()
        .append_pair("check_name", NAME)
        .append_pair("filter", "latest")
        .append_pair("per_page", "100")
        .append_pair("page", "2");
    cases.push(latest);
    let mut unexpected_app_filter = list_url(&server, 2);
    unexpected_app_filter
        .query_pairs_mut()
        .append_pair("app_id", "17");
    cases.push(unexpected_app_filter);

    for next in cases {
        server.enqueue(
            ResponseSpec::json(
                axum::http::StatusCode::OK,
                json!({"total_count": 0, "check_runs": []}).to_string(),
            )
            .header("link", format!("<{next}>; rel=\"next\"")),
        );
        let error = server
            .endpoint()
            .reconcile_check_run_creation(&repository(), &identity(), &token())
            .await
            .expect_err("unsafe pagination URL must fail");
        assert_eq!(error, GithubChecksError::InvalidResponse);
    }
}

#[tokio::test]
async fn pagination_and_response_body_ceilings_fail_closed() {
    let page_server = FixtureServer::spawn().await;
    page_server.enqueue(
        ResponseSpec::json(
            axum::http::StatusCode::OK,
            json!({"total_count": 1, "check_runs": [exact_run_value(41, "queued", None)]})
                .to_string(),
        )
        .header(
            "link",
            format!("<{}>; rel=\"next\"", list_url(&page_server, 2)),
        ),
    );
    let one_page_limits = GithubHttpLimits::new(
        1_048_576,
        1,
        100,
        Duration::from_secs(1),
        Duration::from_secs(2),
    )
    .expect("limits");
    let error = page_server
        .endpoint_with_limits(one_page_limits)
        .reconcile_check_run_creation(&repository(), &identity(), &token())
        .await
        .expect_err("page ceiling");
    assert_eq!(error, GithubChecksError::InvalidResponse);
    assert_eq!(page_server.requests().len(), 1);

    let body_server = FixtureServer::spawn().await;
    body_server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        json!({"total_count": 0, "check_runs": [], "padding": "x".repeat(512)}).to_string(),
    ));
    let small_body_limits =
        GithubHttpLimits::new(128, 4, 100, Duration::from_secs(1), Duration::from_secs(2))
            .expect("limits");
    let error = body_server
        .endpoint_with_limits(small_body_limits)
        .reconcile_check_run_creation(&repository(), &identity(), &token())
        .await
        .expect_err("body ceiling");
    assert_eq!(error, GithubChecksError::InvalidResponse);

    let item_server = FixtureServer::spawn().await;
    let runs: Vec<_> = (1..=101)
        .map(|id| run_value(id, 17, 22, SHA, NAME, None, ("queued", None)))
        .collect();
    item_server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        json!({"total_count": 101, "check_runs": runs}).to_string(),
    ));
    let error = item_server
        .endpoint()
        .reconcile_check_run_creation(&repository(), &identity(), &token())
        .await
        .expect_err("item ceiling");
    assert_eq!(error, GithubChecksError::InvalidResponse);
}

#[tokio::test]
async fn list_rejects_query_scope_mismatch_duplicate_ids_and_total_count_drift() {
    let server = FixtureServer::spawn().await;
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        json!({
            "total_count": 1,
            "check_runs": [run_value(41, 18, 23, SHA, NAME, Some(EXTERNAL_ID), ("queued", None))]
        })
        .to_string(),
    ));
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        json!({
            "total_count": 1,
            "check_runs": [run_value(41, 17, 22, SHA, NAME, Some(EXTERNAL_ID), ("queued", None))]
        })
        .to_string(),
    ));
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        json!({
            "total_count": 2,
            "check_runs": [
                run_value(41, 17, 23, SHA, NAME, None, ("queued", None)),
                run_value(41, 17, 23, SHA, NAME, None, ("queued", None))
            ]
        })
        .to_string(),
    ));
    server.enqueue(ResponseSpec::json(
        axum::http::StatusCode::OK,
        json!({"total_count": 1, "check_runs": []}).to_string(),
    ));
    for _ in 0..4 {
        let error = server
            .endpoint()
            .reconcile_check_run_creation(&repository(), &identity(), &token())
            .await
            .expect_err("invalid list response");
        assert_eq!(error, GithubChecksError::InvalidResponse);
    }
}

#[tokio::test]
async fn provider_http_failures_map_without_reading_or_exposing_bodies() {
    let server = FixtureServer::spawn().await;
    let statuses = [
        axum::http::StatusCode::UNAUTHORIZED,
        axum::http::StatusCode::FORBIDDEN,
        axum::http::StatusCode::NOT_FOUND,
        axum::http::StatusCode::CONFLICT,
        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
    ];
    for status in statuses {
        server.enqueue(ResponseSpec::json(
            status,
            format!(r#"{{"message":"provider-body-{TOKEN}"}}"#),
        ));
    }
    server.enqueue(
        ResponseSpec::json(
            axum::http::StatusCode::FORBIDDEN,
            format!(r#"{{"message":"rate-body-{TOKEN}"}}"#),
        )
        .header("x-ratelimit-remaining", "0")
        .header("x-ratelimit-reset", "1893456000"),
    );
    server.enqueue(
        ResponseSpec::json(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            format!(r#"{{"message":"rate-body-{TOKEN}"}}"#),
        )
        .header("retry-after", "17")
        .header("x-ratelimit-remaining", "0"),
    );
    server.enqueue(
        ResponseSpec::json(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!(r#"{{"message":"server-body-{TOKEN}"}}"#),
        )
        .header("retry-after", "999999")
        .header("x-ratelimit-reset", "01893456000"),
    );
    let expected = [
        GithubChecksError::Unauthorized,
        GithubChecksError::Forbidden,
        GithubChecksError::NotFound,
        GithubChecksError::Conflict,
        GithubChecksError::Rejected,
        GithubChecksError::RateLimited(automata_ci_github::GithubCheckRetryEvidence::default()),
        GithubChecksError::RateLimited(automata_ci_github::GithubCheckRetryEvidence::default()),
        GithubChecksError::Unavailable(automata_ci_github::GithubCheckRetryEvidence::default()),
    ];
    let endpoint = server.endpoint();
    for (index, expected_kind) in expected.into_iter().enumerate() {
        let error = endpoint
            .get_check_run(
                &repository(),
                GithubCheckRunId::new(41).expect("run id"),
                &identity(),
                &token(),
            )
            .await
            .expect_err("provider error");
        match index {
            5 => {
                let GithubChecksError::RateLimited(evidence) = error else {
                    panic!("expected rate limit");
                };
                assert_eq!(evidence.rate_limit_reset_at(), Some(1_893_456_000));
                assert!(evidence.rate_limit_remaining_zero());
            }
            6 => {
                let GithubChecksError::RateLimited(evidence) = error else {
                    panic!("expected rate limit");
                };
                assert_eq!(evidence.retry_after_seconds(), Some(17));
                assert!(evidence.rate_limit_remaining_zero());
            }
            _ => assert_eq!(error, expected_kind),
        }
        let debug = format!("{error:?} {error}");
        assert!(!debug.contains(TOKEN));
        assert!(!debug.contains("provider-body"));
        assert!(!debug.contains("rate-body"));
        assert!(!debug.contains("server-body"));
    }
}

#[test]
fn bounded_models_and_diagnostics_are_redacted() {
    assert_eq!(
        GithubCheckAppId::new(0),
        Err(GithubCheckModelError::InvalidIdentifier)
    );
    assert_eq!(
        GithubCheckRunId::new((i64::MAX as u64) + 1),
        Err(GithubCheckModelError::InvalidIdentifier)
    );
    for invalid in ["", " leading", "trailing ", "bad\nname"] {
        assert_eq!(
            GithubCheckName::new(invalid),
            Err(GithubCheckModelError::InvalidCheckName)
        );
    }
    assert_eq!(
        GithubCheckName::new("x".repeat(256)),
        Err(GithubCheckModelError::InvalidCheckName)
    );
    for invalid in ["", "has space", "bad\nvalue"] {
        assert_eq!(
            GithubCheckExternalId::new(invalid),
            Err(GithubCheckModelError::InvalidExternalId)
        );
    }
    assert_eq!(
        GithubCheckExternalId::new("x".repeat(1_025)),
        Err(GithubCheckModelError::InvalidExternalId)
    );
    assert_eq!(
        GithubCheckTimestamp::from_unix_millis(-1),
        Err(GithubCheckModelError::InvalidTimestamp)
    );
    for invalid in [
        GithubCheckOutput::new("", "summary", None),
        GithubCheckOutput::new(" title", "summary", None),
        GithubCheckOutput::new("title", " \n\t", None),
        GithubCheckOutput::new("title", "bad\u{0000}summary", None),
        GithubCheckOutput::new("title", "summary", Some("\n".to_owned())),
    ] {
        assert_eq!(invalid, Err(GithubCheckModelError::InvalidOutput));
    }
    assert_eq!(
        GithubCheckOutput::new("x".repeat(256), "summary", None),
        Err(GithubCheckModelError::InvalidOutput)
    );
    let output = GithubCheckOutput::new(
        "secret title",
        "secret summary",
        Some("secret text".to_owned()),
    )
    .expect("output");
    let output_debug = format!("{output:?}");
    assert!(!output_debug.contains("secret"));
    let fractional_timestamp =
        GithubCheckTimestamp::from_unix_millis(1_786_666_505_123).expect("timestamp");
    assert_eq!(fractional_timestamp.as_str(), "2026-08-14T00:15:05.123Z");
    assert_eq!(
        format!("{fractional_timestamp:?}"),
        "GithubCheckTimestamp([validated])"
    );

    let name = GithubCheckName::new(NAME).expect("name");
    let external = GithubCheckExternalId::new(EXTERNAL_ID).expect("external id");
    assert_eq!(format!("{name:?}"), "GithubCheckName([REDACTED])");
    assert_eq!(format!("{external:?}"), "GithubCheckExternalId([REDACTED])");
    let identity_debug = format!("{:?}", identity());
    assert!(!identity_debug.contains(NAME));
    assert!(!identity_debug.contains(EXTERNAL_ID));
    assert!(!identity_debug.contains(DETAILS_URL));
    assert!(!format!("{:?}", token()).contains(TOKEN));
}

struct RawServer {
    origin: Url,
    task: JoinHandle<()>,
}

impl RawServer {
    async fn reply(response: Vec<u8>) -> Self {
        Self::spawn(move |mut stream| async move {
            let mut request = vec![0_u8; 8_192];
            let _ = stream.read(&mut request).await;
            let _ = stream.write_all(&response).await;
            let _ = stream.shutdown().await;
        })
        .await
    }

    async fn hanging(duration: Duration) -> Self {
        Self::spawn(move |mut stream| async move {
            let mut request = vec![0_u8; 8_192];
            let _ = stream.read(&mut request).await;
            tokio::time::sleep(duration).await;
        })
        .await
    }

    async fn spawn<F, Fut>(handler: F) -> Self
    where
        F: FnOnce(tokio::net::TcpStream) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("raw fixture listener");
        let address = listener.local_addr().expect("raw fixture address");
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("raw fixture accept");
            handler(stream).await;
        });
        let origin = Url::parse(&format!("http://{address}/")).expect("raw fixture URL");
        Self { origin, task }
    }

    fn endpoint(&self, limits: GithubHttpLimits) -> GithubHttpEndpoint {
        GithubHttpEndpoint::new_for_loopback_emulator(
            self.origin.clone(),
            self.origin.join("api/").expect("API base"),
            "automata-check-tests/0.1.0",
            limits,
        )
        .expect("raw fixture endpoint")
    }
}

impl Drop for RawServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
