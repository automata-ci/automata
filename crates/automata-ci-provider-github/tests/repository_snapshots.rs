use crate::support;

use automata_ci_auth::secret::SecretString;
use automata_ci_core::GitObjectId;
use automata_ci_provider::{ExternalRepositoryId, ProviderConnectionId};
use automata_ci_provider_github::GithubTrustedOrigins;
use automata_ci_scm::{
    ArchiveLimits, RepositoryId, RepositorySource, RepositorySourceConnection,
    RepositorySourceRedirectPolicy, RepositorySourceRequest, RevisionSpec, ScmErrorKind,
    ScmProvider, SnapshotRequest,
};
use axum::http::StatusCode;
use support::{FixtureServer, ResponseSpec};
use url::Url;

const SHA: &str = "de0fac2e4500dabe0009e67214ff5f5447ce83dd";
const DIFFERENT_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn token() -> SecretString {
    SecretString::new("ghs_installation_secret").unwrap()
}

fn source_connection(repository: &RepositoryId, external_id: &str) -> RepositorySourceConnection {
    RepositorySourceConnection::new(
        "33333333-3333-4333-8333-333333333333"
            .parse::<ProviderConnectionId>()
            .unwrap(),
        ExternalRepositoryId::new(external_id).unwrap(),
        repository.clone(),
    )
}

fn repository_response(id: u64, full_name: &str) -> ResponseSpec {
    ResponseSpec::json(
        StatusCode::OK,
        format!(r#"{{"id":{id},"full_name":"{full_name}"}}"#),
    )
}

#[tokio::test]
async fn exact_source_proves_the_requested_commit_before_downloading() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(repository_response(42, "automata-ci/automata"));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        format!(r#"{{"sha":"{SHA}","ignored":true}}"#),
    ));
    fixture.enqueue(ResponseSpec::status(StatusCode::FOUND).header(
        "location",
        fixture.url("archive/exact-source.tar.gz").as_str(),
    ));
    fixture.enqueue(ResponseSpec::binary(
        StatusCode::OK,
        "application/gzip",
        vec![0x1f, 0x8b, 0x08, 0x00, 9, 8, 7, 6],
    ));
    let endpoint = fixture.endpoint();
    let repository = RepositoryId::new("automata-ci/automata").unwrap();
    let connection = source_connection(&repository, "42");
    let revision = GitObjectId::from_provider_hex(SHA).unwrap();
    let token = token();

    let source = endpoint
        .fetch_repository_source(RepositorySourceRequest::authenticated(
            &connection,
            &revision,
            &token,
            ArchiveLimits::new(1024).unwrap(),
            RepositorySourceRedirectPolicy::ConfiguredArchiveOrigin,
        ))
        .await
        .unwrap();

    assert_eq!(source.connection_id(), connection.connection_id());
    assert_eq!(source.external_repository_id().as_str(), "42");
    assert_eq!(source.repository(), &repository);
    assert_eq!(source.revision(), &revision);
    assert_eq!(source.size(), 8);

    let requests = fixture.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].uri, "/api/repos/automata-ci/automata");
    assert_eq!(
        requests[1].uri,
        format!("/api/repos/automata-ci/automata/commits/{SHA}")
    );
    assert_eq!(
        requests[2].uri,
        format!("/api/repos/automata-ci/automata/tarball/{SHA}")
    );
    assert_eq!(requests[3].uri, "/archive/exact-source.tar.gz");
    assert_eq!(
        requests[0].headers["authorization"],
        "Bearer ghs_installation_secret"
    );
    assert_eq!(
        requests[1].headers["authorization"],
        "Bearer ghs_installation_secret"
    );
    assert_eq!(
        requests[2].headers["authorization"],
        "Bearer ghs_installation_secret"
    );
    assert!(!requests[3].headers.contains_key("authorization"));
}

#[tokio::test]
async fn exact_source_rejects_malformed_or_mismatched_commit_evidence_without_fallback() {
    for returned_sha in [
        DIFFERENT_SHA.to_owned(),
        SHA.to_ascii_uppercase(),
        "short".to_owned(),
    ] {
        let fixture = FixtureServer::spawn().await;
        fixture.enqueue(repository_response(42, "automata-ci/automata"));
        fixture.enqueue(ResponseSpec::json(
            StatusCode::OK,
            format!(r#"{{"sha":"{returned_sha}"}}"#),
        ));
        fixture.enqueue(
            ResponseSpec::status(StatusCode::FOUND)
                .header("location", fixture.url("must-not-download.tar.gz").as_str()),
        );
        fixture.enqueue(ResponseSpec::binary(
            StatusCode::OK,
            "application/gzip",
            vec![0x1f, 0x8b, 0x08],
        ));
        let endpoint = fixture.endpoint();
        let repository = RepositoryId::new("automata-ci/automata").unwrap();
        let connection = source_connection(&repository, "42");
        let revision = GitObjectId::from_provider_hex(SHA).unwrap();
        let token = token();

        let error = endpoint
            .fetch_repository_source(RepositorySourceRequest::authenticated(
                &connection,
                &revision,
                &token,
                ArchiveLimits::default(),
                RepositorySourceRedirectPolicy::ConfiguredArchiveOrigin,
            ))
            .await
            .unwrap_err();

        assert_eq!(error.kind(), ScmErrorKind::InvalidResponse);
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains(&returned_sha));
        assert_eq!(fixture.requests().len(), 2);
        assert_eq!(fixture.remaining_responses(), 2);
    }
}

#[tokio::test]
async fn exact_source_rejects_native_identity_or_route_rebinding_before_commit_io() {
    for repository_evidence in [
        repository_response(41, "automata-ci/automata"),
        repository_response(42, "attacker/rebound"),
    ] {
        let fixture = FixtureServer::spawn().await;
        fixture.enqueue(repository_evidence);
        fixture.enqueue(ResponseSpec::json(
            StatusCode::OK,
            format!(r#"{{"sha":"{SHA}"}}"#),
        ));
        let endpoint = fixture.endpoint();
        let repository = RepositoryId::new("automata-ci/automata").unwrap();
        let connection = source_connection(&repository, "42");
        let revision = GitObjectId::from_provider_hex(SHA).unwrap();
        let error = endpoint
            .fetch_repository_source(RepositorySourceRequest::public(
                &connection,
                &revision,
                ArchiveLimits::default(),
                RepositorySourceRedirectPolicy::Deny,
            ))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ScmErrorKind::InvalidResponse);
        assert_eq!(fixture.requests().len(), 1);
        assert_eq!(fixture.remaining_responses(), 1);
    }
}

#[tokio::test]
async fn authenticated_exact_source_requires_explicit_configured_redirect_authority() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(repository_response(42, "automata-ci/automata"));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        format!(r#"{{"sha":"{SHA}"}}"#),
    ));
    let endpoint = fixture.endpoint();
    let repository = RepositoryId::new("automata-ci/automata").unwrap();
    let connection = source_connection(&repository, "42");
    let revision = GitObjectId::from_provider_hex(SHA).unwrap();
    let token = token();
    let error = endpoint
        .fetch_repository_source(RepositorySourceRequest::authenticated(
            &connection,
            &revision,
            &token,
            ArchiveLimits::default(),
            RepositorySourceRedirectPolicy::Deny,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ScmErrorKind::InvalidResponse);
    assert_eq!(fixture.requests().len(), 2);
}

#[tokio::test]
async fn exact_source_rejects_untrusted_redirects_and_invalid_archive_media() {
    let untrusted = FixtureServer::spawn().await;
    untrusted.enqueue(repository_response(42, "automata-ci/automata"));
    untrusted.enqueue(ResponseSpec::json(
        StatusCode::OK,
        format!(r#"{{"sha":"{SHA}"}}"#),
    ));
    untrusted.enqueue(
        ResponseSpec::status(StatusCode::FOUND)
            .header("location", "https://attacker.example/exact-source.tar.gz"),
    );
    let endpoint = untrusted.endpoint();
    let repository = RepositoryId::new("automata-ci/automata").unwrap();
    let connection = source_connection(&repository, "42");
    let revision = GitObjectId::from_provider_hex(SHA).unwrap();
    let token = token();
    let error = endpoint
        .fetch_repository_source(RepositorySourceRequest::authenticated(
            &connection,
            &revision,
            &token,
            ArchiveLimits::default(),
            RepositorySourceRedirectPolicy::ConfiguredArchiveOrigin,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ScmErrorKind::InvalidResponse);
    assert_eq!(untrusted.requests().len(), 3);

    let invalid_media = FixtureServer::spawn().await;
    invalid_media.enqueue(repository_response(42, "automata-ci/automata"));
    invalid_media.enqueue(ResponseSpec::json(
        StatusCode::OK,
        format!(r#"{{"sha":"{SHA}"}}"#),
    ));
    invalid_media.enqueue(ResponseSpec::status(StatusCode::FOUND).header(
        "location",
        invalid_media.url("exact-source.tar.gz").as_str(),
    ));
    invalid_media.enqueue(ResponseSpec::binary(
        StatusCode::OK,
        "text/plain",
        vec![0x1f, 0x8b, 0x08],
    ));
    let endpoint = invalid_media.endpoint();
    let error = endpoint
        .fetch_repository_source(RepositorySourceRequest::authenticated(
            &connection,
            &revision,
            &token,
            ArchiveLimits::default(),
            RepositorySourceRedirectPolicy::ConfiguredArchiveOrigin,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ScmErrorKind::InvalidResponse);
}

#[tokio::test]
async fn exact_source_enforces_the_incremental_archive_byte_ceiling() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(repository_response(42, "automata-ci/automata"));
    fixture.enqueue(ResponseSpec::json(
        StatusCode::OK,
        format!(r#"{{"sha":"{SHA}"}}"#),
    ));
    fixture.enqueue(ResponseSpec::status(StatusCode::FOUND).header(
        "location",
        fixture.url("large-exact-source.tar.gz").as_str(),
    ));
    let mut body = vec![0_u8; 4096];
    body[..3].copy_from_slice(&[0x1f, 0x8b, 0x08]);
    fixture.enqueue(ResponseSpec::binary(
        StatusCode::OK,
        "application/octet-stream",
        body,
    ));
    let endpoint = fixture.endpoint();
    let repository = RepositoryId::new("automata-ci/automata").unwrap();
    let connection = source_connection(&repository, "42");
    let revision = GitObjectId::from_provider_hex(SHA).unwrap();
    let token = token();

    let error = endpoint
        .fetch_repository_source(RepositorySourceRequest::authenticated(
            &connection,
            &revision,
            &token,
            ArchiveLimits::new(16).unwrap(),
            RepositorySourceRedirectPolicy::ConfiguredArchiveOrigin,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ScmErrorKind::TooLarge);
}

fn request_values() -> (RepositoryId, RevisionSpec) {
    (
        RepositoryId::new("actions/checkout").unwrap(),
        RevisionSpec::new("releases/v6").unwrap(),
    )
}

#[tokio::test]
async fn public_exact_revision_uses_the_immutable_archive_origin_without_api_requests() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::binary(
        StatusCode::OK,
        "application/x-gzip",
        vec![0x1f, 0x8b, 0x08, 0x00, 1, 2, 3, 4],
    ));
    let endpoint = fixture.endpoint();
    let repository = RepositoryId::new("actions/checkout").unwrap();
    let revision = RevisionSpec::new(SHA).unwrap();

    let snapshot = endpoint
        .fetch_snapshot(SnapshotRequest::public(
            &repository,
            &revision,
            ArchiveLimits::new(1024).unwrap(),
        ))
        .await
        .unwrap();

    assert_eq!(snapshot.resolved_revision().to_string(), SHA);
    assert_eq!(snapshot.size(), 8);
    let requests = fixture.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].uri,
        format!("/actions/checkout/legacy.tar.gz/{SHA}")
    );
    assert!(!requests[0].headers.contains_key("authorization"));
}

#[tokio::test]
async fn public_exact_source_uses_the_immutable_archive_origin_without_api_requests() {
    let fixture = FixtureServer::spawn().await;
    fixture.enqueue(ResponseSpec::binary(
        StatusCode::OK,
        "application/x-gzip",
        vec![0x1f, 0x8b, 0x08, 0x00, 1, 2, 3, 4],
    ));
    let endpoint = fixture.endpoint();
    let repository = RepositoryId::new("automata-ci/automata").unwrap();
    let connection = source_connection(&repository, "42");
    let revision = GitObjectId::from_provider_hex(SHA).unwrap();

    let source = endpoint
        .fetch_repository_source(RepositorySourceRequest::public(
            &connection,
            &revision,
            ArchiveLimits::new(1024).unwrap(),
            RepositorySourceRedirectPolicy::Deny,
        ))
        .await
        .unwrap();

    assert_eq!(source.revision(), &revision);
    assert_eq!(source.size(), 8);
    let requests = fixture.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].uri,
        format!("/automata-ci/automata/legacy.tar.gz/{SHA}")
    );
    assert!(!requests[0].headers.contains_key("authorization"));
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
    assert_eq!(snapshot.resolved_revision().to_string(), SHA);
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
            automata_ci_provider_github::GithubHttpEndpoint::new_with_archive_origin(
                trusted.clone(),
                Url::parse(invalid).unwrap(),
            )
            .is_err()
        );
    }

    assert!(
        automata_ci_provider_github::GithubHttpEndpoint::new_with_archive_origin(
            trusted,
            Url::parse("https://codeload.github.com/").unwrap(),
        )
        .is_ok()
    );
}
