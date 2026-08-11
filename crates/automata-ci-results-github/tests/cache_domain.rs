use automata_ci_results_github::{
    CacheAccessScope, CacheAuthority, CacheKey, CacheLimits, CachePermission, CacheProtocolEntryId,
    CacheRepositoryMetadata, CacheVersion, GithubCacheHttpLimits, derive_cache_authority,
};

#[test]
fn access_controls_use_the_current_capitalized_numeric_wire_shape() {
    let scopes = vec![
        CacheAccessScope::new("refs/heads/main", CachePermission::ReadWrite)
            .expect("read/write scope"),
        CacheAccessScope::new("refs/heads/release", CachePermission::Read).expect("read scope"),
    ];
    assert_eq!(
        serde_json::to_string(&scopes).expect("serialize access controls"),
        r#"[{"Scope":"refs/heads/main","Permission":3},{"Scope":"refs/heads/release","Permission":1}]"#
    );
    let decoded: Vec<CacheAccessScope> =
        serde_json::from_str(r#"[{"Scope":"refs/heads/main","Permission":2}]"#)
            .expect("numeric permission");
    assert_eq!(decoded[0].permission(), CachePermission::Write);
    for rejected in [
        r#"[{"scope":"refs/heads/main","Permission":3}]"#,
        r#"[{"Scope":"refs/heads/main","permission":3}]"#,
        r#"[{"Scope":"refs/heads/main","Permission":0}]"#,
        r#"[{"Scope":"refs/heads/main","Permission":4}]"#,
        r#"[{"Scope":"refs/heads/main","Permission":"ReadWrite"}]"#,
    ] {
        assert!(serde_json::from_str::<Vec<CacheAccessScope>>(rejected).is_err());
    }
}

#[test]
fn repository_scope_and_protocol_values_are_bounded_and_unambiguous() {
    let scope =
        CacheAccessScope::new("refs/heads/Main", CachePermission::ReadWrite).expect("scope");
    let authority =
        CacheAuthority::new("Owner/Repository", vec![scope.clone()]).expect("authority");
    assert_eq!(authority.repository(), "owner/repository");
    assert_eq!(authority.writable_scope(), Some("refs/heads/Main"));
    assert!(CacheAuthority::new("owner/repository", vec![scope.clone(), scope]).is_err());
    assert!(
        CacheAuthority::new(
            "missing-slash",
            vec![CacheAccessScope::new("refs/heads/main", CachePermission::Read).expect("scope")]
        )
        .is_err()
    );

    assert!(CacheKey::new("cargo-linux").is_ok());
    assert!(CacheKey::new("cargo,linux").is_err());
    assert!(CacheKey::new("x".repeat(513)).is_err());
    assert!(CacheVersion::new("sha256-value").is_ok());
    assert!(CacheVersion::new("has whitespace").is_err());
    assert_eq!(CacheProtocolEntryId::new(1).expect("protocol ID").get(), 1);
    assert!(CacheProtocolEntryId::new(0).is_err());
    assert!(CacheProtocolEntryId::new(-1).is_err());
    assert!(CacheLimits::new(1, 1, 1, 1, 10, 1).is_ok());
    assert!(CacheLimits::new(1, 1, 2, 1, 10, 1).is_err());
    assert!(CacheLimits::new(1, 1, 1, 1, 11, 1).is_err());
    let defaults = CacheLimits::default();
    assert_eq!(defaults.repository_quota_bytes(), 10 * 1024 * 1024 * 1024);
    assert_eq!(defaults.inactivity_seconds(), 7 * 24 * 60 * 60);
    assert!(GithubCacheHttpLimits::new(64 * 1024, 128 * 1024 * 1024).is_ok());
    assert!(GithubCacheHttpLimits::new(64 * 1024 + 1, 1).is_err());
    assert!(GithubCacheHttpLimits::new(1, 128 * 1024 * 1024 + 1).is_err());
}

#[test]
fn server_repository_metadata_derives_one_canonical_default_branch_ref() {
    let metadata = CacheRepositoryMetadata::new("Owner/Repository", "release/stable")
        .expect("repository metadata");
    assert_eq!(metadata.repository(), "owner/repository");
    assert_eq!(metadata.default_branch_ref(), "refs/heads/release/stable");
    assert_eq!(
        CacheRepositoryMetadata::new("owner/repository", "refs/release")
            .expect("nested refs branch")
            .default_branch_ref(),
        "refs/heads/refs/release"
    );

    for rejected in [
        "",
        "refs//heads/main",
        "-main",
        ".hidden",
        "main.lock",
        "feature..branch",
        "feature//branch",
        "feature@{branch",
        "feature branch",
        "feature~branch",
        "feature\\branch",
    ] {
        assert!(
            CacheRepositoryMetadata::new("owner/repository", rejected).is_err(),
            "accepted noncanonical branch {rejected:?}"
        );
    }
}

#[test]
fn write_authority_is_limited_to_safe_current_ref_evidence() {
    let metadata =
        CacheRepositoryMetadata::new("owner/repository", "main").expect("repository metadata");
    for (event, git_ref) in [
        ("push", "refs/heads/main"),
        ("push", "refs/tags/v1"),
        ("pull_request", "refs/pull/42/merge"),
    ] {
        let authority = derive_cache_authority(
            "github",
            "owner/repository",
            git_ref,
            event,
            Some(&metadata),
        )
        .expect("safe authority");
        assert_eq!(authority.writable_scope(), Some(git_ref));
        assert_eq!(authority.scopes()[0].scope(), git_ref);
        if git_ref == "refs/heads/main" {
            assert_eq!(authority.scopes().len(), 1);
        } else {
            assert_eq!(authority.scopes().len(), 2);
            assert_eq!(authority.scopes()[1].scope(), "refs/heads/main");
            assert_eq!(authority.scopes()[1].permission(), CachePermission::Read);
        }
    }

    for (event, git_ref) in [
        ("pull_request", "refs/heads/main"),
        ("pull_request_target", "refs/heads/main"),
        ("workflow_run", "refs/heads/main"),
        ("repository_dispatch", "refs/heads/main"),
        ("schedule", "refs/heads/main"),
        ("workflow_dispatch", "refs/heads/main"),
        ("pull_request", "refs/pull/0/merge"),
        ("pull_request", "refs/pull/01/merge"),
        ("pull_request", "refs/pull/42/head"),
        ("pull_request", "refs/pull/42/merge/extra"),
    ] {
        let authority = derive_cache_authority(
            "github",
            "owner/repository",
            git_ref,
            event,
            Some(&metadata),
        )
        .expect("read-only authority");
        assert_eq!(authority.writable_scope(), None);
        assert!(authority.can_read(git_ref));
        assert_eq!(authority.scopes()[0].scope(), git_ref);
    }

    assert!(
        derive_cache_authority(
            "gitlab",
            "owner/repository",
            "refs/heads/main",
            "push",
            Some(&metadata),
        )
        .is_err()
    );
    let sibling =
        CacheRepositoryMetadata::new("sibling/repository", "main").expect("sibling metadata");
    assert!(
        derive_cache_authority(
            "github",
            "owner/repository",
            "refs/heads/feature",
            "push",
            Some(&sibling),
        )
        .is_err()
    );
}
