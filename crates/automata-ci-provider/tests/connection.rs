use automata_ci_core::{Sha256Digest, UnixMillis, WorkspaceId};
use automata_ci_provider::{
    ExternalRepositoryId, ExternalRepositoryIdentity, ProviderArchiveLimits,
    ProviderConfigurationRevision, ProviderConnectionConfiguration, ProviderConnectionError,
    ProviderConnectionId, ProviderConnectionManifest, ProviderConnectionPolicyDocument,
    ProviderConnectionRevision, ProviderDefaultBranch, ProviderInstanceId, ProviderLifecycleState,
    ProviderRepositoryPath, ProviderRunnerPolicyBinding, ProviderSchemaVersion,
    ProviderWorkflowSource, RepositoryVisibility,
};
use uuid::Uuid;

fn configuration(visibility: RepositoryVisibility) -> ProviderConnectionConfiguration {
    ProviderConnectionConfiguration::new(
        WorkspaceId::parse("11111111-1111-4111-8111-111111111111").expect("workspace"),
        ExternalRepositoryIdentity::new(
            ProviderInstanceId::from_uuid(Uuid::from_u128(2)).expect("instance"),
            ExternalRepositoryId::new("repository-42").expect("repository"),
        ),
        ProviderConfigurationRevision::new(3).expect("provider revision"),
        Sha256Digest::from_bytes([3; 32]),
        Sha256Digest::from_bytes([4; 32]),
        visibility,
        ProviderDefaultBranch::new("main").expect("default branch"),
        ProviderWorkflowSource::Directory(
            ProviderRepositoryPath::new(".forgejo/workflows").expect("workflow root"),
        ),
        ProviderRunnerPolicyBinding::new(
            ProviderSchemaVersion::new(2).expect("runner schema"),
            Sha256Digest::from_bytes([5; 32]),
        ),
        ProviderArchiveLimits::new(
            256 * 1_024 * 1_024,
            2 * 1_024 * 1_024 * 1_024,
            100_000,
            4 * 1_024,
            256,
            500 * 1_024,
        )
        .expect("archive limits"),
        ProviderConnectionPolicyDocument::new(
            ProviderSchemaVersion::new(1).expect("policy schema"),
            br#"{"installation_id":42}"#.to_vec(),
        )
        .expect("adapter policy"),
    )
}

fn manifest(
    revision: u64,
    state: ProviderLifecycleState,
    configuration: ProviderConnectionConfiguration,
    activated_at: Option<UnixMillis>,
    retired_at: Option<UnixMillis>,
) -> ProviderConnectionManifest {
    ProviderConnectionManifest::new(
        ProviderConnectionId::from_uuid(Uuid::from_u128(9)).expect("connection"),
        ProviderConnectionRevision::new(revision).expect("revision"),
        state,
        configuration,
        UnixMillis::new(1_000),
        activated_at,
        retired_at,
    )
    .expect("manifest")
}

#[test]
fn default_branches_reject_ambiguous_git_names() {
    for valid in ["main", "release/v1", "feature/привет", "topic.LOCK"] {
        assert!(
            ProviderDefaultBranch::new(valid).is_ok(),
            "rejected {valid}"
        );
    }
    for invalid in [
        "",
        "refs/heads/main",
        "/main",
        "main/",
        ".hidden",
        "main.",
        "main.lock",
        "feature//one",
        "feature/../one",
        "feature@{one",
        "white space",
        "question?",
        "back\\slash",
    ] {
        assert!(
            ProviderDefaultBranch::new(invalid).is_err(),
            "accepted {invalid}"
        );
    }
}

#[test]
fn workflow_sources_use_normalized_repository_relative_paths() {
    for valid in [
        ".github/workflows",
        ".forgejo/workflows/build.yaml",
        ".gitlab-ci.yml",
    ] {
        assert!(
            ProviderRepositoryPath::new(valid).is_ok(),
            "rejected {valid}"
        );
    }
    for invalid in [
        "",
        "/.github/workflows",
        ".github/workflows/",
        ".github//workflows",
        "./workflow.yml",
        "../workflow.yml",
        "a/../workflow.yml",
        "a\\workflow.yml",
        "a\nworkflow.yml",
    ] {
        assert!(
            ProviderRepositoryPath::new(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }

    let source =
        ProviderWorkflowSource::File(ProviderRepositoryPath::new(".gitlab-ci.yml").expect("path"));
    let encoded = serde_json::to_string(&source).expect("serialize source");
    assert_eq!(
        serde_json::from_str::<ProviderWorkflowSource>(&encoded).expect("deserialize source"),
        source
    );
}

#[test]
fn archive_limits_are_nonzero_bounded_and_consistent() {
    assert!(ProviderArchiveLimits::new(1, 1, 1, 1, 1, 1).is_ok());
    for invalid in [
        ProviderArchiveLimits::new(0, 1, 1, 1, 1, 1),
        ProviderArchiveLimits::new(2, 1, 1, 1, 1, 1),
        ProviderArchiveLimits::new(1, 1, 1, 1, 2, 1),
        ProviderArchiveLimits::new(1, 1, 1, 1, 1, 2),
    ] {
        assert_eq!(invalid, Err(ProviderConnectionError::InvalidArchiveLimits));
    }
    assert!(
        serde_json::from_str::<ProviderArchiveLimits>(
            r#"{"compressed_bytes":1,"expanded_bytes":1,"entries":1,"entry_path_bytes":1,"workflows":1,"workflow_bytes":1,"extra":1}"#
        )
        .is_err()
    );
}

#[test]
fn connection_configuration_digest_covers_common_and_adapter_policy() {
    let public = configuration(RepositoryVisibility::Public);
    let private = configuration(RepositoryVisibility::Private);
    assert_ne!(public.digest(), private.digest());
    assert_eq!(
        public.repository().instance_id(),
        ProviderInstanceId::from_uuid(Uuid::from_u128(2)).expect("instance")
    );
    assert_eq!(public.provider_revision().get(), 3);
    assert_eq!(public.default_branch().as_str(), "main");
    assert_eq!(
        public.workflow_source().path().as_str(),
        ".forgejo/workflows"
    );
    assert_eq!(public.adapter_policy().schema_version().get(), 1);
}

#[test]
fn connection_successors_require_real_change_and_terminal_retirement() {
    let disabled = manifest(
        1,
        ProviderLifecycleState::Disabled,
        configuration(RepositoryVisibility::Public),
        None,
        None,
    );
    let revision_only = manifest(
        2,
        ProviderLifecycleState::Disabled,
        configuration(RepositoryVisibility::Public),
        None,
        None,
    );
    assert_eq!(
        revision_only.validate_successor(&disabled),
        Err(ProviderConnectionError::InvalidSuccessor)
    );

    let active = manifest(
        2,
        ProviderLifecycleState::Active,
        configuration(RepositoryVisibility::Public),
        Some(UnixMillis::new(2_000)),
        None,
    );
    active.validate_successor(&disabled).expect("activation");

    let retired = manifest(
        3,
        ProviderLifecycleState::Retired,
        configuration(RepositoryVisibility::Public),
        Some(UnixMillis::new(2_000)),
        Some(UnixMillis::new(3_000)),
    );
    retired.validate_successor(&active).expect("retirement");

    let after_retirement = manifest(
        4,
        ProviderLifecycleState::Retired,
        configuration(RepositoryVisibility::Private),
        Some(UnixMillis::new(2_000)),
        Some(UnixMillis::new(3_000)),
    );
    assert_eq!(
        after_retirement.validate_successor(&retired),
        Err(ProviderConnectionError::InvalidSuccessor)
    );
}

#[test]
fn connection_lifecycle_rejects_missing_or_out_of_order_evidence() {
    let connection = ProviderConnectionId::from_uuid(Uuid::from_u128(9)).expect("connection");
    let revision = ProviderConnectionRevision::new(1).expect("revision");
    assert_eq!(
        ProviderConnectionManifest::new(
            connection,
            revision,
            ProviderLifecycleState::Active,
            configuration(RepositoryVisibility::Public),
            UnixMillis::new(2_000),
            None,
            None,
        ),
        Err(ProviderConnectionError::InvalidLifecycle)
    );
    assert_eq!(
        ProviderConnectionManifest::new(
            connection,
            revision,
            ProviderLifecycleState::Retired,
            configuration(RepositoryVisibility::Public),
            UnixMillis::new(2_000),
            Some(UnixMillis::new(3_000)),
            Some(UnixMillis::new(2_500)),
        ),
        Err(ProviderConnectionError::InvalidLifecycle)
    );
}
