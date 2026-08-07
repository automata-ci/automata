mod support;

use automata_auth::secret::SecretString;
use automata_github::GithubTrustedOrigins;
use automata_scm::{
    ArchiveLimits, RepositoryId, RevisionSpec, ScmErrorKind, ScmProvider, SnapshotRequest,
};
use axum::http::StatusCode;
use support::{FixtureServer, ResponseSpec};
use url::Url;

const SHA: &str = "de0fac2e4500dabe0009e67214ff5f5447ce83dd";

fn token() -> SecretString {
    SecretString::new("ghs_installation_secret").unwrap()
}

fn request_values() -> (RepositoryId, RevisionSpec) {
    (
        RepositoryId::new("actions/checkout").unwrap(),
        RevisionSpec::new("releases/v6").unwrap(),
    )
}

#[tokio::test]
async fn resolves_then_downloads_without_forwarding_the_credential() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        format!(r#"{{"sha":"{SHA}","ignored":true}}"#),
    ));
    fixture.enqueue(ResponseSpec::status(StatusCode::FOUND).header(
        "location",
        fixture.url("archive/actions-checkout.tar.gz").as_str(),
    ));
    fixture.enqueue(ResponseSpec::binary(
        StatusCode::OK,
        "application/x-gzip",
        vec![0x1f, 0x8b, 0x08, 0x00, 1, 2, 3, 4],
    ));
    let endpoint = fixture.endpoint();
    let (repository, revision) = request_values();
    let token = token();

    let snapshot = endpoint
        .fetch_snapshot(SnapshotRequest::authenticated(
            &repository,
            &revision,
            &token,
            ArchiveLimits::new(1024).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(snapshot.provider().as_str(), "github");
    assert_eq!(snapshot.repository(), &repository);
    assert_eq!(snapshot.requested_revision(), &revision);
    assert_eq!(snapshot.resolved_revision().as_str(), SHA);
    assert_eq!(snapshot.size(), 8);

    let requests = fixture.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[0].uri,
        "/api/repos/actions/checkout/commits/releases%2Fv6"
    );
    assert_eq!(
        requests[1].uri,
        format!("/api/repos/actions/checkout/tarball/{SHA}")
    );
    assert_eq!(requests[2].uri, "/archive/actions-checkout.tar.gz");
    assert_eq!(
        requests[0].headers["authorization"],
        "Bearer ghs_installation_secret"
    );
    assert_eq!(
        requests[1].headers["authorization"],
        "Bearer ghs_installation_secret"
    );
    assert!(!requests[2].headers.contains_key("authorization"));
}

#[tokio::test]
async fn rejects_untrusted_redirects_and_oversized_archives_before_buffering() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        format!(r#"{{"sha":"{SHA}"}}"#),
    ));
    fixture.enqueue(
        ResponseSpec::status(StatusCode::FOUND)
            .header("location", "https://attacker.example/archive.tar.gz"),
    );
    let endpoint = fixture.endpoint();
    let (repository, revision) = request_values();
    let error = endpoint
        .fetch_snapshot(SnapshotRequest::public(
            &repository,
            &revision,
            ArchiveLimits::new(16).unwrap(),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ScmErrorKind::InvalidResponse);
    assert_eq!(fixture.requests().len(), 2);

    let oversized = FixtureServer::spawn().await;
    oversized.enqueue(ResponseSpec::json(
        StatusCode::OK,
        format!(r#"{{"sha":"{SHA}"}}"#),
    ));
    oversized.enqueue(
        ResponseSpec::status(StatusCode::FOUND)
            .header("location", oversized.url("archive.tar.gz").as_str()),
    );
    let mut oversized_body = vec![0_u8; 4096];
    oversized_body[..3].copy_from_slice(&[0x1f, 0x8b, 0x08]);
    oversized.enqueue(ResponseSpec::binary(
        StatusCode::OK,
        "application/gzip",
        oversized_body,
    ));
    let endpoint = oversized.endpoint();
    let error = endpoint
        .fetch_snapshot(SnapshotRequest::public(
            &repository,
            &revision,
            ArchiveLimits::new(16).unwrap(),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ScmErrorKind::TooLarge);
}

#[tokio::test]
async fn rejects_invalid_revision_commit_and_archive_payloads_with_sanitized_errors() {
    let fixture = FixtureServer::spawn().await;
    let endpoint = fixture.endpoint();
    let repository = RepositoryId::new("actions/checkout").unwrap();
    let revision = RevisionSpec::new("feature bad").unwrap();
    let error = endpoint
        .fetch_snapshot(SnapshotRequest::public(
            &repository,
            &revision,
            ArchiveLimits::default(),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ScmErrorKind::InvalidResponse);
    assert!(fixture.requests().is_empty());

    fixture.enqueue(ResponseSpec::json(StatusCode::OK, r#"{"sha":"short"}"#));
    let revision = RevisionSpec::new("v6").unwrap();
    let error = endpoint
        .fetch_snapshot(SnapshotRequest::public(
            &repository,
            &revision,
            ArchiveLimits::default(),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ScmErrorKind::InvalidResponse);
    assert!(!format!("{error:?} {error}").contains("short"));
}

#[test]
fn explicit_archive_origin_requires_a_safe_origin_url() {
    let trusted = GithubTrustedOrigins::github_dot_com("automata-tests/0.1.0").unwrap();
    for invalid in [
        "http://codeload.github.com/",
        "https://user@codeload.github.com/",
        "https://codeload.github.com/path",
    ] {
        assert!(
            automata_github::GithubHttpEndpoint::new_with_archive_origin(
                trusted.clone(),
                Url::parse(invalid).unwrap(),
            )
            .is_err()
        );
    }

    assert!(
        automata_github::GithubHttpEndpoint::new_with_archive_origin(
            trusted,
            Url::parse("https://codeload.github.com/").unwrap(),
        )
        .is_ok()
    );
}
