use crate::support;

use std::{
    num::NonZeroU64,
    time::{Duration, Instant},
};

use automata_ci_auth::secret::SecretString;
use automata_ci_github::{
    GithubChangedFilesEvidenceDigest, GithubHttpEndpoint, GithubHttpLimits,
    GithubPullRequestDiffAuthority, GithubPullRequestDiffOutcome, GithubPullRequestDiffRequest,
    GithubPushDiffAuthority, GithubPushDiffIncompleteReason, GithubPushDiffOutcome,
    GithubPushDiffRange, GithubPushDiffRequest, MAX_GITHUB_COMPARE_PATH_FILTER_FILES,
    MAX_GITHUB_PULL_REQUEST_PATH_FILTER_FILES,
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

fn pull_request_snapshot(number: u64, base: &str, head: &str, changed_files: usize) -> String {
    pull_request_snapshot_with_repositories(
        number,
        base,
        head,
        changed_files,
        "octo-org/private-repo",
        "octo-org/private-repo",
    )
}

fn pull_request_snapshot_with_repositories(
    number: u64,
    base: &str,
    head: &str,
    changed_files: usize,
    base_repository: &str,
    head_repository: &str,
) -> String {
    serde_json::to_string(&json!({
        "number": number,
        "state": "open",
        "changed_files": changed_files,
        "base": {"sha": base, "repo": {"full_name": base_repository}},
        "head": {"sha": head, "repo": {"full_name": head_repository}},
    }))
    .expect("pull-request snapshot JSON")
}

fn pull_request_file(path: &str, status: &str) -> Value {
    json!({"sha": OTHER, "filename": path, "status": status})
}

async fn existing_diff<'a>(
    endpoint: &'a GithubHttpEndpoint,
    repository: &'a RepositoryId,
    before: &'a ExactRevision,
    after: &'a ExactRevision,
    pushed_commits: &'a [ExactRevision],
    authority: GithubPushDiffAuthority<'a>,
) -> GithubPushDiffOutcome {
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
    pull_request_diff_with(
        endpoint,
        repository,
        repository,
        base,
        head,
        GithubPullRequestDiffAuthority::PublicAnonymous,
    )
    .await
}

async fn pull_request_diff_with<'a>(
    endpoint: &'a GithubHttpEndpoint,
    repository: &'a RepositoryId,
    head_repository: &'a RepositoryId,
    base: &'a ExactRevision,
    head: &'a ExactRevision,
    authority: GithubPullRequestDiffAuthority<'a>,
) -> GithubPullRequestDiffOutcome {
    endpoint
        .pull_request_changed_files(GithubPullRequestDiffRequest::new(
            repository,
            head_repository,
            NonZeroU64::new(17).expect("PR number"),
            base,
            head,
            authority,
            Instant::now() + Duration::from_secs(10),
        ))
        .await
}

async fn pull_request_digest(files: Vec<Value>) -> GithubChangedFilesEvidenceDigest {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, AFTER, files.len()),
    ));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        serde_json::to_string(&files).expect("pull-request files JSON"),
    ));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, AFTER, files.len()),
    ));
    let outcome = pull_request_diff(
        &fixture.endpoint(),
        &repository(),
        &revision(BEFORE),
        &revision(AFTER),
    )
    .await;
    let GithubPullRequestDiffOutcome::Complete(evidence) = outcome else {
        panic!("expected complete pull-request evidence");
    };
    evidence.evidence_digest()
}

#[tokio::test]
async fn pull_request_three_dot_comparison_accepts_divergence_and_binds_exact_revisions() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, AFTER, 2),
    ));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        serde_json::to_string(&[
            pull_request_file("web/index.html", "modified"),
            pull_request_file("src/lib.rs", "added"),
        ])
        .unwrap(),
    ));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, AFTER, 2),
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
    assert_eq!(evidence.number().get(), 17);
    assert_eq!(evidence.changed_paths(), ["src/lib.rs", "web/index.html"]);
    assert_eq!(fixture.requests().len(), 3);
    assert_eq!(
        fixture.requests()[1].uri,
        "/api/repos/octo-org/private-repo/pulls/17/files?per_page=100&page=1"
    );
}

#[tokio::test]
async fn pull_request_comparison_rejects_a_response_not_ending_at_signed_head() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, OTHER, 0),
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
        GithubPullRequestDiffOutcome::Invalid(GithubPushDiffIncompleteReason::InvalidEvidence)
    );
}

#[tokio::test]
async fn pull_request_transport_and_authority_failures_have_disjoint_dispositions() {
    let unavailable = FixtureServer::spawn().await;
    unavailable.enqueue(ResponseSpec::status(StatusCode::TOO_MANY_REQUESTS));
    assert_eq!(
        pull_request_diff(
            &unavailable.endpoint(),
            &repository(),
            &revision(BEFORE),
            &revision(AFTER),
        )
        .await,
        GithubPullRequestDiffOutcome::RetryableUnavailable
    );

    let rejected = FixtureServer::spawn().await;
    rejected.enqueue(ResponseSpec::status(StatusCode::UNAUTHORIZED));
    let repository = repository();
    let token = SecretString::new("ghs_rejected_pull_requests_read").unwrap();
    assert_eq!(
        pull_request_diff_with(
            &rejected.endpoint(),
            &repository,
            &repository,
            &revision(BEFORE),
            &revision(AFTER),
            GithubPullRequestDiffAuthority::PrivateInstallationPullRequestsRead(&token),
        )
        .await,
        GithubPullRequestDiffOutcome::Invalid(GithubPushDiffIncompleteReason::ProviderRejected)
    );
}

#[tokio::test]
async fn pull_request_selection_is_pinned_to_the_first_three_thousand_files() {
    for reported_changed_files in [2_999_usize, 3_000, 3_001] {
        let selected_file_count =
            reported_changed_files.min(MAX_GITHUB_PULL_REQUEST_PATH_FILTER_FILES);
        let fixture = FixtureServer::spawn().await;
        fixture.enqueue(ResponseSpec::json(
            StatusCode::OK,
            pull_request_snapshot(17, BEFORE, AFTER, reported_changed_files),
        ));
        for page in 0..selected_file_count.div_ceil(100) {
            let page_start = page * 100;
            let page_end = (page_start + 100).min(selected_file_count);
            let files = (page_start..page_end)
                .map(|index| pull_request_file(&format!("src/file-{index:04}.rs"), "modified"))
                .collect::<Vec<_>>();
            fixture.enqueue(ResponseSpec::json(
                StatusCode::OK,
                serde_json::to_string(&files).expect("pull-request page JSON"),
            ));
        }
        fixture.enqueue(ResponseSpec::json(
            StatusCode::OK,
            pull_request_snapshot(17, BEFORE, AFTER, reported_changed_files),
        ));

        let outcome = pull_request_diff(
            &fixture.endpoint(),
            &repository(),
            &revision(BEFORE),
            &revision(AFTER),
        )
        .await;
        let GithubPullRequestDiffOutcome::Complete(evidence) = outcome else {
            panic!("expected complete provider selection window");
        };
        assert_eq!(
            evidence.total_changed_files(),
            u64::try_from(reported_changed_files).expect("bounded fixture count")
        );
        assert_eq!(evidence.selected_file_count(), selected_file_count);
        assert_eq!(evidence.changed_paths().len(), selected_file_count);
        assert_eq!(evidence.page_digests().len(), 30);
        assert!(
            !evidence
                .changed_paths()
                .iter()
                .any(|path| path == "src/file-3000.rs")
        );
        let requests = fixture.requests();
        assert_eq!(requests.len(), 32);
        assert!(requests[30].uri.ends_with("per_page=100&page=30"));
        assert_eq!(
            requests[31].uri,
            "/api/repos/octo-org/private-repo/pulls/17"
        );
    }
}

#[tokio::test]
async fn pull_request_page_chain_detects_duplicate_omitted_and_mutated_evidence() {
    let duplicate = FixtureServer::spawn().await;
    duplicate.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, AFTER, 101),
    ));
    let first_page = (0..100)
        .map(|index| pull_request_file(&format!("src/{index:03}.rs"), "modified"))
        .collect::<Vec<_>>();
    duplicate.enqueue(ResponseSpec::json(
        StatusCode::OK,
        serde_json::to_string(&first_page).unwrap(),
    ));
    duplicate.enqueue(ResponseSpec::json(
        StatusCode::OK,
        serde_json::to_string(&[pull_request_file("src/099.rs", "modified")]).unwrap(),
    ));
    duplicate.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, AFTER, 101),
    ));
    assert_eq!(
        pull_request_diff(
            &duplicate.endpoint(),
            &repository(),
            &revision(BEFORE),
            &revision(AFTER),
        )
        .await,
        GithubPullRequestDiffOutcome::Invalid(GithubPushDiffIncompleteReason::InvalidEvidence)
    );

    let omitted = FixtureServer::spawn().await;
    omitted.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, AFTER, 101),
    ));
    omitted.enqueue(ResponseSpec::json(
        StatusCode::OK,
        serde_json::to_string(&first_page).unwrap(),
    ));
    omitted.enqueue(ResponseSpec::json(StatusCode::OK, "[]"));
    assert_eq!(
        pull_request_diff(
            &omitted.endpoint(),
            &repository(),
            &revision(BEFORE),
            &revision(AFTER),
        )
        .await,
        GithubPullRequestDiffOutcome::Invalid(GithubPushDiffIncompleteReason::InvalidEvidence)
    );
    assert_eq!(omitted.requests().len(), 3);

    let mutated = FixtureServer::spawn().await;
    mutated.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, AFTER, 1),
    ));
    mutated.enqueue(ResponseSpec::json(
        StatusCode::OK,
        serde_json::to_string(&[pull_request_file("src/lib.rs", "modified")]).unwrap(),
    ));
    mutated.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, OTHER, 1),
    ));
    assert_eq!(
        pull_request_diff(
            &mutated.endpoint(),
            &repository(),
            &revision(BEFORE),
            &revision(AFTER),
        )
        .await,
        GithubPullRequestDiffOutcome::Invalid(GithubPushDiffIncompleteReason::InvalidEvidence)
    );
}

#[tokio::test]
async fn pull_request_page_order_is_digest_bound_and_restart_is_deterministic() {
    let first = pull_request_file("src/first.rs", "modified");
    let second = pull_request_file("src/second.rs", "added");
    let original = pull_request_digest(vec![first.clone(), second.clone()]).await;
    let replay = pull_request_digest(vec![first.clone(), second.clone()]).await;
    let reordered = pull_request_digest(vec![second, first]).await;

    assert_eq!(replay, original);
    assert_ne!(reordered, original);
}

#[tokio::test]
async fn pull_request_retry_restarts_at_page_one_and_reproduces_clean_evidence() {
    let fixture = FixtureServer::spawn().await;
    let first_page = (0..100)
        .map(|index| pull_request_file(&format!("src/{index:03}.rs"), "modified"))
        .collect::<Vec<_>>();
    let final_page = vec![pull_request_file("src/final.rs", "added")];

    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, AFTER, 101),
    ));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        serde_json::to_string(&first_page).unwrap(),
    ));
    fixture.enqueue(ResponseSpec::status(StatusCode::SERVICE_UNAVAILABLE));
    assert_eq!(
        pull_request_diff(
            &fixture.endpoint(),
            &repository(),
            &revision(BEFORE),
            &revision(AFTER),
        )
        .await,
        GithubPullRequestDiffOutcome::RetryableUnavailable
    );

    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, AFTER, 101),
    ));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        serde_json::to_string(&first_page).unwrap(),
    ));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        serde_json::to_string(&final_page).unwrap(),
    ));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, AFTER, 101),
    ));
    let replay = pull_request_diff(
        &fixture.endpoint(),
        &repository(),
        &revision(BEFORE),
        &revision(AFTER),
    )
    .await;
    let GithubPullRequestDiffOutcome::Complete(replay) = replay else {
        panic!("expected complete replay evidence");
    };

    let clean = FixtureServer::spawn().await;
    clean.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, AFTER, 101),
    ));
    clean.enqueue(ResponseSpec::json(
        StatusCode::OK,
        serde_json::to_string(&first_page).unwrap(),
    ));
    clean.enqueue(ResponseSpec::json(
        StatusCode::OK,
        serde_json::to_string(&final_page).unwrap(),
    ));
    clean.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, AFTER, 101),
    ));
    let clean_outcome = pull_request_diff(
        &clean.endpoint(),
        &repository(),
        &revision(BEFORE),
        &revision(AFTER),
    )
    .await;
    let GithubPullRequestDiffOutcome::Complete(clean_evidence) = clean_outcome else {
        panic!("expected clean evidence");
    };
    assert_eq!(replay.evidence_digest(), clean_evidence.evidence_digest());

    let requests = fixture.requests();
    assert_eq!(requests.len(), 7);
    assert_eq!(requests[0].uri, "/api/repos/octo-org/private-repo/pulls/17");
    assert_eq!(requests[3].uri, requests[0].uri);
}

#[tokio::test]
async fn pull_request_authority_and_fork_repository_are_exactly_bound() {
    let fixture = FixtureServer::spawn().await;
    let head_repository = RepositoryId::new("fork-owner/fork-repo").unwrap();
    let snapshot = pull_request_snapshot_with_repositories(
        17,
        BEFORE,
        AFTER,
        1,
        "octo-org/private-repo",
        head_repository.as_str(),
    );
    fixture.enqueue(ResponseSpec::json(StatusCode::OK, snapshot.clone()));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        serde_json::to_string(&[pull_request_file("src/fork.rs", "added")]).unwrap(),
    ));
    fixture.enqueue(ResponseSpec::json(StatusCode::OK, snapshot));
    let token = SecretString::new("ghs_exact_pull_requests_read").unwrap();
    let outcome = pull_request_diff_with(
        &fixture.endpoint(),
        &repository(),
        &head_repository,
        &revision(BEFORE),
        &revision(AFTER),
        GithubPullRequestDiffAuthority::PrivateInstallationPullRequestsRead(&token),
    )
    .await;
    assert!(matches!(outcome, GithubPullRequestDiffOutcome::Complete(_)));
    let requests = fixture.requests();
    assert_eq!(requests.len(), 3);
    for request in requests {
        assert_eq!(
            request.headers["authorization"],
            "Bearer ghs_exact_pull_requests_read"
        );
    }
    assert!(!format!("{outcome:?}").contains("ghs_exact_pull_requests_read"));

    let mismatch = FixtureServer::spawn().await;
    mismatch.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, AFTER, 1),
    ));
    assert_eq!(
        pull_request_diff_with(
            &mismatch.endpoint(),
            &repository(),
            &head_repository,
            &revision(BEFORE),
            &revision(AFTER),
            GithubPullRequestDiffAuthority::PublicAnonymous,
        )
        .await,
        GithubPullRequestDiffOutcome::Invalid(GithubPushDiffIncompleteReason::InvalidEvidence)
    );
    assert_eq!(mismatch.requests().len(), 1);
}

#[tokio::test]
async fn pull_request_deletions_and_both_rename_paths_are_complete() {
    let deletion = FixtureServer::spawn().await;
    deletion.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, AFTER, 1),
    ));
    deletion.enqueue(ResponseSpec::json(
        StatusCode::OK,
        serde_json::to_string(&[pull_request_file("src/removed.rs", "removed")]).unwrap(),
    ));
    deletion.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, AFTER, 1),
    ));
    let outcome = pull_request_diff(
        &deletion.endpoint(),
        &repository(),
        &revision(BEFORE),
        &revision(AFTER),
    )
    .await;
    let GithubPullRequestDiffOutcome::Complete(evidence) = outcome else {
        panic!("expected deletion evidence");
    };
    assert_eq!(evidence.changed_paths(), ["src/removed.rs"]);

    let rename = FixtureServer::spawn().await;
    rename.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, AFTER, 1),
    ));
    rename.enqueue(ResponseSpec::json(
        StatusCode::OK,
        serde_json::to_string(&[json!({
            "sha": OTHER,
            "filename": "src/new.rs",
            "previous_filename": "src/old.rs",
            "status": "renamed"
        })])
        .unwrap(),
    ));
    rename.enqueue(ResponseSpec::json(
        StatusCode::OK,
        pull_request_snapshot(17, BEFORE, AFTER, 1),
    ));
    let outcome = pull_request_diff(
        &rename.endpoint(),
        &repository(),
        &revision(BEFORE),
        &revision(AFTER),
    )
    .await;
    let GithubPullRequestDiffOutcome::Complete(evidence) = outcome else {
        panic!("expected rename evidence");
    };
    assert_eq!(evidence.selected_file_count(), 1);
    assert_eq!(evidence.changed_files()[0].current_path(), "src/new.rs");
    assert_eq!(
        evidence.changed_files()[0].previous_path(),
        Some("src/old.rs")
    );
    assert_eq!(evidence.changed_paths(), ["src/new.rs", "src/old.rs"]);
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
    .await;
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
    .await;
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
            .await;
        assert_eq!(outcome, GithubPushDiffOutcome::Invalid(expected));
    }
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn compare_selection_has_exact_299_300_301_boundaries() {
    assert_eq!(MAX_GITHUB_COMPARE_PATH_FILTER_FILES, 300);
    for file_count in [299_usize, 300, 301] {
        let fixture = FixtureServer::spawn().await;
        let files = (0..file_count)
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
        .await;
        if file_count <= MAX_GITHUB_COMPARE_PATH_FILTER_FILES {
            let GithubPushDiffOutcome::Complete(evidence) = outcome else {
                panic!("expected complete {file_count}-file selection");
            };
            assert_eq!(evidence.selected_file_count(), file_count);
            assert_eq!(evidence.changed_paths().len(), file_count);
        } else {
            assert_eq!(
                outcome,
                GithubPushDiffOutcome::Invalid(GithubPushDiffIncompleteReason::FileListCapped)
            );
        }
    }
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
    .await;
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
    .await;
    assert_eq!(
        outcome,
        GithubPushDiffOutcome::Invalid(GithubPushDiffIncompleteReason::InvalidEvidence)
    );
}

#[tokio::test]
async fn divergence_is_invalid_and_push_renames_include_both_paths() {
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
    .await;
    assert_eq!(
        outcome,
        GithubPushDiffOutcome::Invalid(GithubPushDiffIncompleteReason::DivergedPush)
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
    .await;
    let GithubPushDiffOutcome::Complete(evidence) = outcome else {
        panic!("expected complete rename selection");
    };
    assert_eq!(evidence.selected_file_count(), 1);
    assert_eq!(evidence.changed_files()[0].current_path(), "new/name.rs");
    assert_eq!(
        evidence.changed_files()[0].previous_path(),
        Some("old/name.rs")
    );
    assert_eq!(evidence.changed_paths(), ["new/name.rs", "old/name.rs"]);
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
        vec![json!({"filename": "new/path", "status": "renamed"})],
        vec![json!({
            "filename": "new/path",
            "previous_filename": "../old/path",
            "status": "renamed"
        })],
        vec![json!({
            "filename": "same/path",
            "previous_filename": "same/path",
            "status": "renamed"
        })],
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
        .await;
        assert_eq!(
            outcome,
            GithubPushDiffOutcome::Invalid(GithubPushDiffIncompleteReason::InvalidEvidence)
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
    .await;
    assert_eq!(
        outcome,
        GithubPushDiffOutcome::Invalid(GithubPushDiffIncompleteReason::InvalidEvidence)
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
    .await;
    assert_eq!(
        outcome,
        GithubPushDiffOutcome::Invalid(GithubPushDiffIncompleteReason::InvalidEvidence)
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
    .await;
    assert_eq!(
        outcome,
        GithubPushDiffOutcome::Invalid(GithubPushDiffIncompleteReason::InvalidEvidence)
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
    .await;
    assert_eq!(
        outcome,
        GithubPushDiffOutcome::Invalid(GithubPushDiffIncompleteReason::ProviderRejected)
    );

    let secondary_limit = FixtureServer::spawn().await;
    secondary_limit.enqueue(ResponseSpec::status(StatusCode::FORBIDDEN));
    let outcome = existing_diff(
        &secondary_limit.endpoint(),
        &repository,
        &before,
        &after,
        &commits,
        GithubPushDiffAuthority::PublicAnonymous,
    )
    .await;
    assert_eq!(outcome, GithubPushDiffOutcome::RetryableUnavailable);
}

#[tokio::test]
async fn rate_limits_and_the_overall_deadline_are_unavailable() {
    let repository = repository();
    let before = revision(BEFORE);
    let after = revision(AFTER);
    let commits = [after.clone()];
    let limited = FixtureServer::spawn().await;
    limited.enqueue(ResponseSpec::status(StatusCode::TOO_MANY_REQUESTS).header("retry-after", "3"));
    let outcome = existing_diff(
        &limited.endpoint(),
        &repository,
        &before,
        &after,
        &commits,
        GithubPushDiffAuthority::PublicAnonymous,
    )
    .await;
    assert_eq!(outcome, GithubPushDiffOutcome::RetryableUnavailable);

    let no_io = FixtureServer::spawn().await;
    let outcome = no_io
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
        .await;
    assert_eq!(outcome, GithubPushDiffOutcome::RetryableUnavailable);
    assert!(no_io.requests().is_empty());

    let (timeout_endpoint, server) = unresponsive_endpoint().await;
    let outcome = existing_diff(
        &timeout_endpoint,
        &repository,
        &before,
        &after,
        &commits,
        GithubPushDiffAuthority::PublicAnonymous,
    )
    .await;
    assert_eq!(outcome, GithubPushDiffOutcome::RetryableUnavailable);
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
