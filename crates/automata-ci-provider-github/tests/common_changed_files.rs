use crate::support::{FixtureServer, ResponseSpec};

use automata_ci_auth::secret::SecretString;
use automata_ci_core::{GitObjectId, Sha256Digest, UnixMillis, WorkspaceId};
use automata_ci_provider::{
    ExternalRepositoryId, ExternalRepositoryIdentity, NormalizedTrigger, ProviderArchiveLimits,
    ProviderConfigurationRevision, ProviderConnectionConfiguration, ProviderConnectionId,
    ProviderConnectionManifest, ProviderConnectionRevision, ProviderDefaultBranch, ProviderGitRef,
    ProviderGitRefKind, ProviderInstanceId, ProviderLifecycleState, ProviderRepository,
    ProviderRepositoryPath, ProviderRunnerPolicyBinding, ProviderSchemaVersion,
    ProviderWorkflowSource, PushTrigger, RepositoryVisibility,
};
use automata_ci_provider_github::GithubConnectionPolicy;
use automata_ci_scm::{
    ChangedFileIncompleteReason, ChangedFileLimits, ChangedFileRead, ChangedFileReader,
    ChangedFileRequest, ScmErrorKind,
};
use axum::http::StatusCode;
use serde_json::json;

const BEFORE: &str = "1111111111111111111111111111111111111111";
const MIDDLE: &str = "3333333333333333333333333333333333333333";
const AFTER: &str = "2222222222222222222222222222222222222222";

fn revision(value: &str) -> GitObjectId {
    GitObjectId::from_provider_hex(value).expect("revision")
}

fn identity() -> ExternalRepositoryIdentity {
    ExternalRepositoryIdentity::new(
        "22222222-2222-4222-8222-222222222222"
            .parse::<ProviderInstanceId>()
            .expect("instance"),
        ExternalRepositoryId::new("42").expect("external repository"),
    )
}

fn connection() -> ProviderConnectionManifest {
    let configuration = ProviderConnectionConfiguration::new(
        WorkspaceId::parse("11111111-1111-4111-8111-111111111111").expect("workspace"),
        identity(),
        ProviderConfigurationRevision::new(1).expect("provider revision"),
        Sha256Digest::from_bytes([3; 32]),
        Sha256Digest::from_bytes([4; 32]),
        RepositoryVisibility::Public,
        ProviderDefaultBranch::new("main").expect("branch"),
        ProviderWorkflowSource::Directory(
            ProviderRepositoryPath::new(".github/workflows").expect("workflow root"),
        ),
        ProviderRunnerPolicyBinding::new(
            ProviderSchemaVersion::new(1).expect("runner schema"),
            Sha256Digest::from_bytes([5; 32]),
        ),
        ProviderArchiveLimits::new(1_000_000, 2_000_000, 1_000, 4_096, 100, 1_000_000)
            .expect("archive limits"),
        GithubConnectionPolicy::new(
            7,
            automata_ci_scm::RepositoryId::new("octo-org/private-repo").expect("repository route"),
        )
        .expect("GitHub policy")
        .document()
        .expect("policy document"),
    );
    ProviderConnectionManifest::new(
        "33333333-3333-4333-8333-333333333333"
            .parse::<ProviderConnectionId>()
            .expect("connection"),
        ProviderConnectionRevision::new(1).expect("connection revision"),
        ProviderLifecycleState::Active,
        configuration,
        UnixMillis::new(1_000),
        Some(UnixMillis::new(1_000)),
        None,
    )
    .expect("connection manifest")
}

fn push(
    before: Option<GitObjectId>,
    after: Option<GitObjectId>,
    forced: bool,
) -> automata_ci_provider::SealedNormalizedTrigger {
    push_with_evidence(
        before,
        after,
        automata_ci_provider::PushCommitEvidence::complete(after).expect("commit evidence"),
        forced,
    )
}

fn push_with_evidence(
    before: Option<GitObjectId>,
    after: Option<GitObjectId>,
    commit_evidence: automata_ci_provider::PushCommitEvidence,
    forced: bool,
) -> automata_ci_provider::SealedNormalizedTrigger {
    NormalizedTrigger::Push(
        PushTrigger::new(
            ProviderRepository::new(
                identity(),
                automata_ci_provider::ExternalSubjectId::new("7").expect("owner ID"),
                ProviderRepositoryPath::new("octo-org/private-repo").expect("repository path"),
                RepositoryVisibility::Public,
            ),
            ProviderGitRef::new("refs/heads/main", ProviderGitRefKind::Branch).expect("ref"),
            before,
            after,
            commit_evidence,
            forced,
            None,
        )
        .expect("push"),
    )
    .seal()
    .expect("sealed push")
}

fn limits() -> ChangedFileLimits {
    ChangedFileLimits::new(100, 10, 1_000_000).expect("changed-file limits")
}

#[tokio::test]
async fn common_reader_uses_the_complete_multi_commit_observation() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        serde_json::to_string(&json!({
            "status": "ahead",
            "ahead_by": 2,
            "behind_by": 0,
            "total_commits": 2,
            "base_commit": {"sha": BEFORE},
            "merge_base_commit": {"sha": BEFORE},
            "commits": [{"sha": MIDDLE}, {"sha": AFTER}],
            "files": [{"filename": "src/lib.rs", "status": "modified"}]
        }))
        .expect("compare JSON"),
    ));
    let connection = connection();
    let trigger = push_with_evidence(
        Some(revision(BEFORE)),
        Some(revision(AFTER)),
        automata_ci_provider::PushCommitEvidence::complete([revision(MIDDLE), revision(AFTER)])
            .expect("commit evidence"),
        false,
    );
    let token = SecretString::new("ghs_changed_files_test").expect("fixture token");
    let request = ChangedFileRequest::authenticated(
        &connection,
        &trigger,
        &token,
        limits(),
        UnixMillis::new(2_000),
    )
    .expect("request");

    assert!(matches!(
        fixture
            .endpoint()
            .read_changed_files(request)
            .await
            .expect("complete multi-commit evidence"),
        ChangedFileRead::Complete { .. }
    ));
}

#[tokio::test]
async fn provider_commit_limit_short_circuits_without_partial_comparison() {
    let fixture = FixtureServer::spawn().await;
    let connection = connection();
    let trigger = push_with_evidence(
        Some(revision(BEFORE)),
        Some(revision(AFTER)),
        automata_ci_provider::PushCommitEvidence::ProviderLimitExceeded,
        false,
    );
    let token = SecretString::new("ghs_changed_files_test").expect("fixture token");
    let request = ChangedFileRequest::authenticated(
        &connection,
        &trigger,
        &token,
        limits(),
        UnixMillis::new(2_000),
    )
    .expect("request");

    let ChangedFileRead::Incomplete { reason, .. } = fixture
        .endpoint()
        .read_changed_files(request)
        .await
        .expect("explicit provider limit")
    else {
        panic!("expected incomplete evidence")
    };
    assert_eq!(reason, ChangedFileIncompleteReason::ProviderRecordLimit);
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn common_reader_seals_raw_compare_page_and_canonical_renames() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        serde_json::to_string(&json!({
            "status": "ahead",
            "ahead_by": 1,
            "behind_by": 0,
            "total_commits": 1,
            "base_commit": {"sha": BEFORE},
            "merge_base_commit": {"sha": BEFORE},
            "commits": [{"sha": AFTER}],
            "files": [
                {"filename": "src/new.rs", "previous_filename": "src/old.rs", "status": "renamed"},
                {"filename": "README.md", "status": "modified"}
            ]
        }))
        .expect("compare JSON"),
    ));
    let connection = connection();
    let trigger = push(Some(revision(BEFORE)), Some(revision(AFTER)), false);
    let token = SecretString::new("ghs_changed_files_test").expect("fixture token");
    let request = ChangedFileRequest::authenticated(
        &connection,
        &trigger,
        &token,
        limits(),
        UnixMillis::new(2_000),
    )
    .expect("request");

    let result = fixture
        .endpoint()
        .read_changed_files(request)
        .await
        .expect("changed-file read");
    let ChangedFileRead::Complete { files, evidence } = result else {
        panic!("expected complete changed-file evidence")
    };
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].current_path().as_str(), "README.md");
    assert_eq!(files[1].current_path().as_str(), "src/new.rs");
    assert_eq!(
        files[1].previous_path().map(ProviderRepositoryPath::as_str),
        Some("src/old.rs")
    );
    assert_eq!(evidence.connection_id(), connection.connection_id());
    assert_eq!(evidence.page_count(), 1);
    assert!(evidence.response_bytes() > 100);
    assert_eq!(fixture.requests().len(), 1);
}

#[tokio::test]
async fn common_reader_reports_created_and_forced_pushes_without_provider_io() {
    for (trigger, expected) in [
        (
            push(None, Some(revision(AFTER)), false),
            ChangedFileIncompleteReason::CreatedRef,
        ),
        (
            push(Some(revision(BEFORE)), Some(revision(AFTER)), true),
            ChangedFileIncompleteReason::ForcedUpdate,
        ),
    ] {
        let fixture = FixtureServer::spawn().await;
        let connection = connection();
        let token = SecretString::new("ghs_changed_files_test").expect("fixture token");
        let request = ChangedFileRequest::authenticated(
            &connection,
            &trigger,
            &token,
            limits(),
            UnixMillis::new(2_000),
        )
        .expect("request");
        let result = fixture
            .endpoint()
            .read_changed_files(request)
            .await
            .expect("incomplete observation");
        let ChangedFileRead::Incomplete { reason, evidence } = result else {
            panic!("expected incomplete evidence")
        };
        assert_eq!(reason, expected);
        assert_eq!(evidence.page_count(), 0);
        assert!(fixture.requests().is_empty());
    }
}

#[tokio::test]
async fn common_reader_preserves_rejection_and_invalid_response_failures() {
    for (response, expected) in [
        (
            ResponseSpec::status(StatusCode::UNAUTHORIZED),
            ScmErrorKind::Forbidden,
        ),
        (
            ResponseSpec::json(StatusCode::OK, "not-json"),
            ScmErrorKind::InvalidResponse,
        ),
    ] {
        let fixture = FixtureServer::spawn().await;
        fixture.enqueue(response);
        let connection = connection();
        let trigger = push(Some(revision(BEFORE)), Some(revision(AFTER)), false);
        let token = SecretString::new("ghs_changed_files_test").expect("fixture token");
        let request = ChangedFileRequest::authenticated(
            &connection,
            &trigger,
            &token,
            limits(),
            UnixMillis::new(2_000),
        )
        .expect("request");

        let error = fixture
            .endpoint()
            .read_changed_files(request)
            .await
            .expect_err("provider failure must remain an SCM error");
        assert_eq!(error.kind(), expected);
    }
}
