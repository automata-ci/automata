use automata_github::GithubHttpEndpoint;
use automata_scm::{ArchiveLimits, RepositoryId, RevisionSpec, ScmProvider, SnapshotRequest};

const CHECKOUT_COMMIT: &str = "de0fac2e4500dabe0009e67214ff5f5447ce83dd";

/// Opt-in compatibility probe against GitHub.com and its codeload origin.
#[tokio::test]
#[ignore = "requires public GitHub network access"]
async fn downloads_the_pinned_checkout_action_without_credentials() {
    let endpoint = GithubHttpEndpoint::github_dot_com("automata-live-test/0.1.0").unwrap();
    let repository = RepositoryId::new("actions/checkout").unwrap();
    let revision = RevisionSpec::new(CHECKOUT_COMMIT).unwrap();
    let snapshot = endpoint
        .fetch_snapshot(SnapshotRequest::public(
            &repository,
            &revision,
            ArchiveLimits::new(64 * 1024 * 1024).unwrap(),
        ))
        .await
        .unwrap();

    assert_eq!(snapshot.resolved_revision().as_str(), CHECKOUT_COMMIT);
    assert!(snapshot.size() > 1_024);
    assert_eq!(&snapshot.bytes()[..3], &[0x1f, 0x8b, 0x08]);
}
