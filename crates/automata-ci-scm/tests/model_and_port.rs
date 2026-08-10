use automata_ci_auth::secret::SecretString;
use automata_ci_scm::{
    ArchiveFormat, ArchiveLimits, ExactRevision, RepositoryId, RepositorySnapshot,
    RepositorySource, RepositorySourcePort, RepositorySourceRequest, ResolvedRevision,
    RevisionSpec, ScmProvider, ScmProviderId, SnapshotRequest,
};
use bytes::Bytes;
use static_assertions::assert_obj_safe;

assert_obj_safe!(ScmProvider);
assert_obj_safe!(RepositorySourcePort);

#[test]
fn identifiers_are_strict_and_serde_revalidates() {
    assert!(ScmProviderId::new("github").is_ok());
    for invalid in ["", "GitHub", "github/enterprise", "github-", "git hub"] {
        assert!(ScmProviderId::new(invalid).is_err());
    }

    assert!(RepositoryId::new("actions/checkout").is_ok());
    for invalid in [
        "",
        "/actions/checkout",
        "actions//checkout",
        "../checkout",
        "a\\b",
    ] {
        assert!(RepositoryId::new(invalid).is_err());
    }

    let provider: ScmProviderId = serde_json::from_str(r#""github""#).unwrap();
    assert_eq!(provider.as_str(), "github");
    assert!(serde_json::from_str::<ScmProviderId>(r#""GitHub""#).is_err());
}

#[test]
fn exact_revisions_are_lowercase_full_length_and_serde_revalidates() {
    const REVISION: &str = "de0fac2e4500dabe0009e67214ff5f5447ce83dd";

    let revision = ExactRevision::new(REVISION).unwrap();
    assert_eq!(revision.as_str(), REVISION);
    assert_eq!(
        serde_json::to_string(&revision).unwrap(),
        format!(r#""{REVISION}""#)
    );
    assert_eq!(
        serde_json::from_str::<ExactRevision>(&format!(r#""{REVISION}""#)).unwrap(),
        revision
    );

    for invalid in [
        "",
        "de0fac2e4500dabe0009e67214ff5f5447ce83d",
        "de0fac2e4500dabe0009e67214ff5f5447ce83ddd",
        "DE0FAC2E4500DABE0009E67214FF5F5447CE83DD",
        "ge0fac2e4500dabe0009e67214ff5f5447ce83dd",
        "de0fac2e4500dabe0009e67214ff5f5447ce83d/",
    ] {
        assert!(ExactRevision::new(invalid).is_err(), "accepted {invalid:?}");
        assert!(
            serde_json::from_str::<ExactRevision>(&format!(r#""{invalid}""#)).is_err(),
            "deserialized {invalid:?}"
        );
    }
}

#[test]
fn request_debug_and_snapshot_never_retain_credentials_in_metadata() {
    let repository = RepositoryId::new("actions/checkout").unwrap();
    let revision = RevisionSpec::new("v6").unwrap();
    let credential = SecretString::new("installation-secret-value").unwrap();
    let request = SnapshotRequest::authenticated(
        &repository,
        &revision,
        &credential,
        ArchiveLimits::new(1024).unwrap(),
    );
    let rendered = format!("{request:?}");
    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("installation-secret-value"));

    let snapshot = RepositorySnapshot::from_bytes(
        ScmProviderId::new("github").unwrap(),
        repository,
        revision,
        ResolvedRevision::new("de0fac2e4500dabe0009e67214ff5f5447ce83dd").unwrap(),
        ArchiveFormat::TarGzip,
        Bytes::from_static(b"archive"),
    );
    assert_eq!(snapshot.size(), 7);
    assert_eq!(snapshot.bytes(), &Bytes::from_static(b"archive"));
    assert_eq!(snapshot.digest().to_string().len(), 64);
}

#[test]
fn exact_source_request_redacts_credentials_and_source_binds_one_revision() {
    let repository = RepositoryId::new("automata-ci/automata").unwrap();
    let revision = ExactRevision::new("de0fac2e4500dabe0009e67214ff5f5447ce83dd").unwrap();
    let credential = SecretString::new("exact-source-installation-secret").unwrap();
    let request = RepositorySourceRequest::authenticated(
        &repository,
        &revision,
        &credential,
        ArchiveLimits::new(1024).unwrap(),
    );
    let rendered = format!("{request:?}");
    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("exact-source-installation-secret"));
    assert_eq!(request.repository(), &repository);
    assert_eq!(request.revision(), &revision);
    assert_eq!(request.limits().maximum_bytes(), 1024);

    let source = RepositorySource::from_bytes(
        ScmProviderId::new("github").unwrap(),
        repository,
        revision.clone(),
        ArchiveFormat::TarGzip,
        Bytes::from_static(b"exact source"),
    );
    assert_eq!(source.revision(), &revision);
    assert_eq!(source.size(), 12);
    assert_eq!(source.bytes(), &Bytes::from_static(b"exact source"));
    assert_eq!(source.digest().to_string().len(), 64);
}

#[test]
fn archive_limits_are_nonzero_and_bounded() {
    assert!(ArchiveLimits::new(0).is_err());
    assert!(ArchiveLimits::new(4 * 1024 * 1024 * 1024).is_ok());
    assert!(ArchiveLimits::new(4 * 1024 * 1024 * 1024 + 1).is_err());
}
