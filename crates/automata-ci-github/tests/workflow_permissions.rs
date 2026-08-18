use crate::support;

use std::time::{Duration, Instant};

use automata_ci_auth::{github::GithubEndpointError, secret::SecretString};
use automata_ci_github::{
    ActionsDefaultWorkflowPermission, GithubHttpLimits, GithubWorkflowPermissionDefaultsRequest,
};
use automata_ci_scm::RepositoryId;
use axum::http::StatusCode;
use support::{FixtureServer, ResponseSpec};

fn repository() -> RepositoryId {
    RepositoryId::new("octo-org/octo-repo").expect("repository")
}

fn token() -> SecretString {
    SecretString::new("ghs_admin_read_secret").expect("token")
}

#[tokio::test]
async fn effective_defaults_are_exact_versioned_and_repository_scoped() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}"#,
    ));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        r#"{"default_workflow_permissions":"write","can_approve_pull_request_reviews":true}"#,
    ));
    let endpoint = fixture.endpoint();
    let repository = repository();
    let token = token();

    let read = endpoint
        .workflow_permission_defaults(GithubWorkflowPermissionDefaultsRequest::new(
            &repository,
            &token,
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect("read defaults");
    assert_eq!(
        read.default_workflow_permissions(),
        ActionsDefaultWorkflowPermission::Read
    );
    assert!(!read.can_approve_pull_request_reviews());

    let write = endpoint
        .workflow_permission_defaults(GithubWorkflowPermissionDefaultsRequest::new(
            &repository,
            &token,
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect("write defaults");
    assert_eq!(
        write.default_workflow_permissions(),
        ActionsDefaultWorkflowPermission::Write
    );
    assert!(write.can_approve_pull_request_reviews());

    let requests = fixture.requests();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.uri,
            "/api/repos/octo-org/octo-repo/actions/permissions/workflow"
        );
        assert_eq!(
            request.headers["authorization"],
            "Bearer ghs_admin_read_secret"
        );
        assert_eq!(request.headers["accept"], "application/vnd.github+json");
        assert_eq!(request.headers["x-github-api-version"], "2026-03-10");
        assert!(request.body.is_empty());
    }
}

#[tokio::test]
async fn schema_drift_redirects_and_expired_deadlines_fail_closed() {
    let fixture = FixtureServer::spawn().await;
    for body in [
        r#"{"default_workflow_permissions":"admin","can_approve_pull_request_reviews":false}"#,
        r#"{"default_workflow_permissions":"read"}"#,
        r#"{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false,"future":true}"#,
        r#"{"default_workflow_permissions":"read","can_approve_pull_request_reviews":"false"}"#,
    ] {
        fixture.enqueue(ResponseSpec::json(StatusCode::OK, body));
    }
    fixture.enqueue(
        ResponseSpec::status(StatusCode::FOUND).header("location", fixture.url("sink").as_str()),
    );
    let endpoint = fixture.endpoint();
    let repository = repository();
    let token = token();
    for _ in 0..5 {
        let error = endpoint
            .workflow_permission_defaults(GithubWorkflowPermissionDefaultsRequest::new(
                &repository,
                &token,
                Instant::now() + Duration::from_secs(1),
            ))
            .await
            .expect_err("invalid provider response");
        assert_eq!(error, GithubEndpointError::InvalidResponse);
    }
    assert_eq!(fixture.remaining_responses(), 0);

    let expired_deadline = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .expect("the monotonic clock represents one millisecond in the past");
    let error = endpoint
        .workflow_permission_defaults(GithubWorkflowPermissionDefaultsRequest::new(
            &repository,
            &token,
            expired_deadline,
        ))
        .await
        .expect_err("expired deadline");
    assert_eq!(error, GithubEndpointError::Unavailable);
    assert_eq!(fixture.requests().len(), 5);
}

#[tokio::test]
async fn response_and_status_failures_are_bounded_and_redacted() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        format!(
            r#"{{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false,"padding":"{}"}}"#,
            "x".repeat(256)
        ),
    ));
    fixture.enqueue(ResponseSpec::status(StatusCode::FORBIDDEN));
    fixture
        .enqueue(ResponseSpec::status(StatusCode::TOO_MANY_REQUESTS).header("retry-after", "11"));
    let limits = GithubHttpLimits::new(128, 2, 10, Duration::from_secs(1), Duration::from_secs(2))
        .expect("limits");
    let endpoint = fixture.endpoint_with_limits(limits);
    let repository = repository();
    let token = token();
    let request = || {
        GithubWorkflowPermissionDefaultsRequest::new(
            &repository,
            &token,
            Instant::now() + Duration::from_secs(1),
        )
    };

    let errors = [
        endpoint
            .workflow_permission_defaults(request())
            .await
            .expect_err("oversized"),
        endpoint
            .workflow_permission_defaults(request())
            .await
            .expect_err("forbidden"),
        endpoint
            .workflow_permission_defaults(request())
            .await
            .expect_err("rate limited"),
    ];
    assert_eq!(errors[0], GithubEndpointError::InvalidResponse);
    assert_eq!(errors[1], GithubEndpointError::Forbidden);
    assert_eq!(
        errors[2],
        GithubEndpointError::RateLimited {
            retry_after_seconds: Some(11)
        }
    );
    for error in errors {
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("ghs_admin_read_secret"));
    }
}
