mod support;

use std::time::{Duration, Instant};

use automata_ci_auth::secret::SecretString;
use automata_ci_github::{
    GithubHttpEndpoint, GithubHttpLimits, GithubPullRequestDiffOutcome,
    GithubPullRequestDiffRequest, GithubPushDiffAuthority, GithubPushDiffError,
    GithubPushDiffIncompleteReason, GithubPushDiffOutcome, GithubPushDiffRange,
    GithubPushDiffRequest, MAX_COMPLETE_GITHUB_COMPARE_FILES,
};
use automata_ci_scm::{ExactRevision, RepositoryId};
use axum::http::StatusCode;
use serde_json::{Value, json};
use support::{FixtureServer, ResponseSpec};
use tokio::{net::TcpListener, task::JoinHandle};
use url::Url;

const BEFORE: &str = "1111111111111111111111111111111111111111";
const AFTER: &str = "2222222222222222222222222222222222222222";
const OTHER: &str = "3333333333333333333333333333333333333333";

fn revision(value: &str) -> ExactRevision {
    ExactRevision::new(value).expect("exact fixture revision")
}

fn repository() -> RepositoryId {
    RepositoryId::new("octo-org/private-repo").expect("fixture repository")
}

fn changed_file(path: &str, status: &str) -> Value {
    json!({"filename": path, "status": status})
}

fn compare_page(
    before: &str,
    merge_base: &str,
    total: usize,
    commits: &[String],
    files: Option<Vec<Value>>,
) -> String {
    let mut body = json!({
        "status": "ahead",
        "ahead_by": total,
        "behind_by": 0,
        "total_commits": total,
        "base_commit": {"sha": before},
        "merge_base_commit": {"sha": merge_base},
        "commits": commits.iter().map(|sha| json!({"sha": sha})).collect::<Vec<_>>()
    });
    if let Some(files) = files {
        body.as_object_mut()
            .expect("comparison object")
            .insert("files".to_owned(), Value::Array(files));
    }
    serde_json::to_string(&body).expect("comparison JSON")
}

fn pull_request_compare_page(base: &str, merge_base: &str, head: &str, files: &[Value]) -> String {
    serde_json::to_string(&json!({
        "status": "diverged",
        "ahead_by": 1,
        "behind_by": 2,
        "total_commits": 1,
        "base_commit": {"sha": base},
        "merge_base_commit": {"sha": merge_base},
        "commits": [{"sha": head}],
        "files": files,
    }))
    .expect("pull-request comparison JSON")
}

async fn existing_diff<'a>(
    endpoint: &'a GithubHttpEndpoint,
    repository: &'a RepositoryId,
    before: &'a ExactRevision,
    after: &'a ExactRevision,
    pushed_commits: &'a [ExactRevision],
    authority: GithubPushDiffAuthority<'a>,
) -> Result<GithubPushDiffOutcome, GithubPushDiffError> {
    endpoint
        .push_changed_files(GithubPushDiffRequest::new(
            repository,
            GithubPushDiffRange::Existing {
                before: before.clone(),
                after: after.clone(),
                pushed_commits: pushed_commits.to_vec(),
            },
            authority,
            Instant::now() + Duration::from_secs(2),
        ))
        .await
}

async fn pull_request_diff<'a>(
    endpoint: &'a GithubHttpEndpoint,
    repository: &'a RepositoryId,
    base: &'a ExactRevision,
    head: &'a ExactRevision,
) -> GithubPullRequestDiffOutcome {
    endpoint
        .pull_request_changed_files(GithubPullRequestDiffRequest::new(
            repository,
            base,
            head,
            GithubPushDiffAuthority::PublicAnonymous,
            Instant::now() + Duration::from_secs(2),
        ))
        .await
        .expect("pull-request comparison")
}

#[tokio::test]
async fn pull_request_three_dot_comparison_accepts_divergence_and_binds_exact_revisions() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_compare_page(
            BEFORE,
            OTHER,
            AFTER,
            &[
                changed_file("web/index.html", "modified"),
                changed_file("src/lib.rs", "added"),
            ],
        ),
    ));
    let repository = repository();
    let base = revision(BEFORE);
    let head = revision(AFTER);

    let outcome = pull_request_diff(&fixture.endpoint(), &repository, &base, &head).await;
    let GithubPullRequestDiffOutcome::Complete(evidence) = outcome else {
        panic!("expected complete pull-request comparison");
    };
    assert_eq!(evidence.base(), &base);
    assert_eq!(evidence.head(), &head);
    assert_eq!(evidence.changed_paths(), ["src/lib.rs", "web/index.html"]);
    assert_eq!(fixture.requests().len(), 1);
    assert_eq!(
        fixture.requests()[0].uri,
        format!("/api/repos/octo-org/private-repo/compare/{BEFORE}...{AFTER}?per_page=100&page=1")
    );
}

#[tokio::test]
async fn pull_request_comparison_rejects_a_response_not_ending_at_signed_head() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_compare_page(BEFORE, OTHER, OTHER, &[]),
    ));
    let outcome = pull_request_diff(
        &fixture.endpoint(),
        &repository(),
        &revision(BEFORE),
        &revision(AFTER),
    )
    .await;
    assert_eq!(
        outcome,
        GithubPullRequestDiffOutcome::Incomplete(GithubPushDiffIncompleteReason::InvalidEvidence)
    );
}

#[tokio::test]
async fn public_comparison_is_anonymous_exact_and_canonical() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        compare_page(
            BEFORE,
            BEFORE,
            1,
            &[AFTER.to_owned()],
            Some(vec![
                changed_file("z-last", "added"),
                changed_file("a-first", "modified"),
                changed_file("middle", "removed"),
            ]),
        ),
    ));
    let repository = repository();
    let before = revision(BEFORE);
    let after = revision(AFTER);
    let commits = [after.clone()];

    let outcome = existing_diff(
        &fixture.endpoint(),
        &repository,
        &before,
        &after,
        &commits,
        GithubPushDiffAuthority::PublicAnonymous,
    )
    .await
    .expect("public comparison");
    let GithubPushDiffOutcome::Complete(evidence) = outcome else {
        panic!("expected complete comparison");
    };
    assert_eq!(evidence.before(), &before);
    assert_eq!(evidence.after(), &after);
    assert_eq!(evidence.changed_paths(), ["a-first", "middle", "z-last"]);

    let requests = fixture.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].uri,
        format!("/api/repos/octo-org/private-repo/compare/{BEFORE}...{AFTER}?per_page=100&page=1")
    );
    assert_eq!(requests[0].headers["accept"], "application/vnd.github+json");
    assert_eq!(requests[0].headers["x-github-api-version"], "2026-03-10");
    assert!(!requests[0].headers.contains_key("authorization"));
}

#[tokio::test]
async fn private_comparison_sends_only_the_exact_bearer_to_the_api_origin() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        compare_page(
            BEFORE,
            BEFORE,
            1,
            &[AFTER.to_owned()],
            Some(vec![changed_file("src/private.rs", "modified")]),
        ),
    ));
    let endpoint = fixture.endpoint();
    let repository = repository();
    let before = revision(BEFORE);
    let after = revision(AFTER);
    let commits = [after.clone()];
    let token = SecretString::new("ghs_exact_private_changed_files").unwrap();

    let outcome = existing_diff(
        &endpoint,
        &repository,
        &before,
        &after,
        &commits,
        GithubPushDiffAuthority::PrivateInstallationContentsRead(&token),
    )
    .await
    .expect("private comparison");
    assert!(matches!(outcome, GithubPushDiffOutcome::Complete(_)));
    let requests = fixture.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].headers["authorization"],
        "Bearer ghs_exact_private_changed_files"
    );
    assert!(!format!("{outcome:?}").contains("src/private.rs"));
    assert!(!format!("{outcome:?}").contains("ghs_exact_private_changed_files"));
}

#[tokio::test]
async fn unsupported_push_shapes_are_typed_incomplete_without_provider_io() {
    let fixture = FixtureServer::spawn().await;
    let endpoint = fixture.endpoint();
    let repository = repository();
    let deadline = || Instant::now() + Duration::from_secs(1);
    for (range, expected) in [
        (
            GithubPushDiffRange::Created,
            GithubPushDiffIncompleteReason::CreatedPush,
        ),
        (
            GithubPushDiffRange::Deleted,
            GithubPushDiffIncompleteReason::DeletedPush,
        ),
        (
            GithubPushDiffRange::Forced,
            GithubPushDiffIncompleteReason::DivergedPush,
        ),
    ] {
        let outcome = endpoint
            .push_changed_files(GithubPushDiffRequest::new(
                &repository,
                range,
                GithubPushDiffAuthority::PublicAnonymous,
                deadline(),
            ))
            .await
            .expect("typed incomplete outcome");
        assert_eq!(outcome, GithubPushDiffOutcome::Incomplete(expected));
    }
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn exactly_three_hundred_files_are_never_labeled_complete() {
    assert_eq!(MAX_COMPLETE_GITHUB_COMPARE_FILES, 299);
    let fixture = FixtureServer::spawn().await;
    let files = (0..300)
        .map(|index| changed_file(&format!("files/{index:03}.txt"), "modified"))
        .collect();
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        compare_page(BEFORE, BEFORE, 1, &[AFTER.to_owned()], Some(files)),
    ));
    let repository = repository();
    let before = revision(BEFORE);
    let after = revision(AFTER);
    let commits = [after.clone()];

    let outcome = existing_diff(
        &fixture.endpoint(),
        &repository,
        &before,
        &after,
        &commits,
        GithubPushDiffAuthority::PublicAnonymous,
    )
    .await
    .expect("capped comparison disposition");
    assert_eq!(
        outcome,
        GithubPushDiffOutcome::Incomplete(GithubPushDiffIncompleteReason::FileListCapped)
    );
}

#[tokio::test]
async fn pagination_must_equal_the_complete_signed_commit_set_and_end_at_after() {
    let fixture = FixtureServer::spawn().await;
    let commits = (10..=110)
        .map(|value| revision(&format!("{value:040x}")))
        .collect::<Vec<_>>();
    let after = commits.last().expect("last commit").clone();
    let mut first_page = commits[..100]
        .iter()
        .map(|commit| commit.as_str().to_owned())
        .collect::<Vec<_>>();
    let second_page = vec![after.as_str().to_owned()];
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        compare_page(
            BEFORE,
            BEFORE,
            commits.len(),
            &first_page,
            Some(vec![changed_file("src/lib.rs", "modified")]),
        ),
    ));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        compare_page(BEFORE, BEFORE, commits.len(), &second_page, None),
    ));
    let repository = repository();
    let before = revision(BEFORE);
    let mut signed_commits = commits.clone();
    signed_commits.reverse();

    let outcome = existing_diff(
        &fixture.endpoint(),
        &repository,
        &before,
        &after,
        &signed_commits,
        GithubPushDiffAuthority::PublicAnonymous,
    )
    .await
    .expect("fully paginated comparison");
    assert!(matches!(outcome, GithubPushDiffOutcome::Complete(_)));
    let requests = fixture.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].uri.ends_with("per_page=100&page=1"));
    assert!(requests[1].uri.ends_with("per_page=100&page=2"));

    first_page[42] = OTHER.to_owned();
    let mismatch = FixtureServer::spawn().await;
    mismatch.enqueue(ResponseSpec::json(
        StatusCode::OK,
        compare_page(BEFORE, BEFORE, commits.len(), &first_page, Some(vec![])),
    ));
    mismatch.enqueue(ResponseSpec::json(
        StatusCode::OK,
        compare_page(BEFORE, BEFORE, commits.len(), &second_page, None),
    ));
    let outcome = existing_diff(
        &mismatch.endpoint(),
        &repository,
        &before,
        &after,
        &signed_commits,
        GithubPushDiffAuthority::PublicAnonymous,
    )
    .await
    .expect("mismatched evidence disposition");
    assert_eq!(
        outcome,
        GithubPushDiffOutcome::Incomplete(GithubPushDiffIncompleteReason::InvalidEvidence)
    );
}

#[tokio::test]
async fn divergence_and_renames_are_explicitly_incomplete() {
    let repository = repository();
    let before = revision(BEFORE);
    let after = revision(AFTER);
    let commits = [after.clone()];

    let diverged = FixtureServer::spawn().await;
    diverged.enqueue(ResponseSpec::json(
        StatusCode::OK,
        compare_page(BEFORE, OTHER, 1, &[AFTER.to_owned()], Some(vec![])),
    ));
    let outcome = existing_diff(
        &diverged.endpoint(),
        &repository,
        &before,
        &after,
        &commits,
        GithubPushDiffAuthority::PublicAnonymous,
    )
    .await
    .unwrap();
    assert_eq!(
        outcome,
        GithubPushDiffOutcome::Incomplete(GithubPushDiffIncompleteReason::DivergedPush)
    );

    let renamed = FixtureServer::spawn().await;
    renamed.enqueue(ResponseSpec::json(
        StatusCode::OK,
        compare_page(
            BEFORE,
            BEFORE,
            1,
            &[AFTER.to_owned()],
            Some(vec![json!({
                "filename": "new/name.rs",
                "previous_filename": "old/name.rs",
                "status": "renamed"
            })]),
        ),
    ));
    let outcome = existing_diff(
        &renamed.endpoint(),
        &repository,
        &before,
        &after,
        &commits,
        GithubPushDiffAuthority::PublicAnonymous,
    )
    .await
    .unwrap();
    assert_eq!(
        outcome,
        GithubPushDiffOutcome::Incomplete(GithubPushDiffIncompleteReason::RenamedPath)
    );
}

#[tokio::test]
async fn duplicate_or_malformed_paths_fail_closed() {
    for files in [
        vec![
            changed_file("same/path", "added"),
            changed_file("same/path", "modified"),
        ],
        vec![changed_file("../escape", "modified")],
        vec![changed_file("double//separator", "modified")],
        vec![changed_file("control\npath", "modified")],
        vec![changed_file("valid", "copied")],
    ] {
        let fixture = FixtureServer::spawn().await;
        fixture.enqueue(ResponseSpec::json(
            StatusCode::OK,
            compare_page(BEFORE, BEFORE, 1, &[AFTER.to_owned()], Some(files)),
        ));
        let repository = repository();
        let before = revision(BEFORE);
        let after = revision(AFTER);
        let commits = [after.clone()];
        let outcome = existing_diff(
            &fixture.endpoint(),
            &repository,
            &before,
            &after,
            &commits,
            GithubPushDiffAuthority::PublicAnonymous,
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            GithubPushDiffOutcome::Incomplete(GithubPushDiffIncompleteReason::InvalidEvidence)
        );
    }
}

#[tokio::test]
async fn redirects_and_oversized_responses_fail_closed_without_following() {
    let repository = repository();
    let before = revision(BEFORE);
    let after = revision(AFTER);
    let commits = [after.clone()];
    let redirect = FixtureServer::spawn().await;
    redirect.enqueue(
        ResponseSpec::status(StatusCode::FOUND).header("location", redirect.url("sink").as_str()),
    );
    redirect.enqueue(ResponseSpec::json(
        StatusCode::OK,
        compare_page(BEFORE, BEFORE, 1, &[AFTER.to_owned()], Some(vec![])),
    ));
    let outcome = existing_diff(
        &redirect.endpoint(),
        &repository,
        &before,
        &after,
        &commits,
        GithubPushDiffAuthority::PublicAnonymous,
    )
    .await
    .unwrap();
    assert_eq!(
        outcome,
        GithubPushDiffOutcome::Incomplete(GithubPushDiffIncompleteReason::InvalidEvidence)
    );
    assert_eq!(redirect.requests().len(), 1);
    assert_eq!(redirect.remaining_responses(), 1);

    let oversized = FixtureServer::spawn().await;
    oversized.enqueue(ResponseSpec::json(
        StatusCode::OK,
        compare_page(
            BEFORE,
            BEFORE,
            1,
            &[AFTER.to_owned()],
            Some(vec![changed_file(
                &format!("src/{}", "x".repeat(800)),
                "added",
            )]),
        ),
    ));
    let limits = GithubHttpLimits::new(
        512,
        8,
        1_000,
        Duration::from_millis(100),
        Duration::from_secs(1),
    )
    .unwrap();
    let outcome = existing_diff(
        &oversized.endpoint_with_limits(limits),
        &repository,
        &before,
        &after,
        &commits,
        GithubPushDiffAuthority::PublicAnonymous,
    )
    .await
    .unwrap();
    assert_eq!(
        outcome,
        GithubPushDiffOutcome::Incomplete(GithubPushDiffIncompleteReason::InvalidEvidence)
    );
}

#[tokio::test]
async fn only_exact_ok_is_accepted_and_credential_rejection_is_typed() {
    let repository = repository();
    let before = revision(BEFORE);
    let after = revision(AFTER);
    let commits = [after.clone()];
    let unexpected_success = FixtureServer::spawn().await;
    unexpected_success.enqueue(ResponseSpec::json(
        StatusCode::CREATED,
        compare_page(BEFORE, BEFORE, 1, &[AFTER.to_owned()], Some(vec![])),
    ));
    let outcome = existing_diff(
        &unexpected_success.endpoint(),
        &repository,
        &before,
        &after,
        &commits,
        GithubPushDiffAuthority::PublicAnonymous,
    )
    .await
    .unwrap();
    assert_eq!(
        outcome,
        GithubPushDiffOutcome::Incomplete(GithubPushDiffIncompleteReason::InvalidEvidence)
    );

    let rejected = FixtureServer::spawn().await;
    rejected.enqueue(ResponseSpec::status(StatusCode::UNAUTHORIZED));
    let token = SecretString::new("ghs_rejected_private_token").unwrap();
    let outcome = existing_diff(
        &rejected.endpoint(),
        &repository,
        &before,
        &after,
        &commits,
        GithubPushDiffAuthority::PrivateInstallationContentsRead(&token),
    )
    .await
    .unwrap();
    assert_eq!(
        outcome,
        GithubPushDiffOutcome::Incomplete(GithubPushDiffIncompleteReason::ProviderRejected)
    );

    let secondary_limit = FixtureServer::spawn().await;
    secondary_limit.enqueue(ResponseSpec::status(StatusCode::FORBIDDEN));
    let error = existing_diff(
        &secondary_limit.endpoint(),
        &repository,
        &before,
        &after,
        &commits,
        GithubPushDiffAuthority::PublicAnonymous,
    )
    .await
    .unwrap_err();
    assert_eq!(error, GithubPushDiffError::Unavailable);
}

#[tokio::test]
async fn rate_limits_and_the_overall_deadline_are_unavailable() {
    let repository = repository();
    let before = revision(BEFORE);
    let after = revision(AFTER);
    let commits = [after.clone()];
    let limited = FixtureServer::spawn().await;
    limited.enqueue(ResponseSpec::status(StatusCode::TOO_MANY_REQUESTS).header("retry-after", "3"));
    let error = existing_diff(
        &limited.endpoint(),
        &repository,
        &before,
        &after,
        &commits,
        GithubPushDiffAuthority::PublicAnonymous,
    )
    .await
    .unwrap_err();
    assert_eq!(error, GithubPushDiffError::Unavailable);

    let no_io = FixtureServer::spawn().await;
    let error = no_io
        .endpoint()
        .push_changed_files(GithubPushDiffRequest::new(
            &repository,
            GithubPushDiffRange::Existing {
                before: before.clone(),
                after: after.clone(),
                pushed_commits: commits.to_vec(),
            },
            GithubPushDiffAuthority::PublicAnonymous,
            Instant::now()
                .checked_sub(Duration::from_millis(1))
                .unwrap(),
        ))
        .await
        .unwrap_err();
    assert_eq!(error, GithubPushDiffError::Unavailable);
    assert!(no_io.requests().is_empty());

    let (timeout_endpoint, server) = unresponsive_endpoint().await;
    let error = existing_diff(
        &timeout_endpoint,
        &repository,
        &before,
        &after,
        &commits,
        GithubPushDiffAuthority::PublicAnonymous,
    )
    .await
    .unwrap_err();
    assert_eq!(error, GithubPushDiffError::Unavailable);
    server.abort();
}

async fn unresponsive_endpoint() -> (GithubHttpEndpoint, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind unresponsive fixture");
    let origin = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    let server = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.expect("accept comparison");
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    let limits = GithubHttpLimits::new(
        1_048_576,
        8,
        1_000,
        Duration::from_millis(20),
        Duration::from_millis(40),
    )
    .unwrap();
    let endpoint = GithubHttpEndpoint::new_for_loopback_emulator(
        origin.clone(),
        origin.join("api/").unwrap(),
        "automata-changed-files-test/0.1.0",
        limits,
    )
    .unwrap();
    (endpoint, server)
}
