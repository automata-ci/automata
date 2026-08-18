use automata_ci_core::{Sha256Digest, UnixMillis, WorkspaceId};
use automata_ci_provider::{
    ExternalRepositoryId, ExternalRepositoryIdentity, ProviderArchiveLimits,
    ProviderConfigurationRevision, ProviderConnectionConfiguration, ProviderConnectionId,
    ProviderConnectionManifest, ProviderConnectionPolicyDocument, ProviderConnectionRevision,
    ProviderDefaultBranch, ProviderInstanceId, ProviderLifecycleState, ProviderRepositoryPath,
    ProviderRunnerPolicyBinding, ProviderSchemaVersion, ProviderWorkflowSource,
    RepositoryVisibility,
};

pub(crate) fn active_connection(repository: &str) -> ProviderConnectionManifest {
    connection_with_state(repository, ProviderLifecycleState::Active)
}

pub(crate) fn connection_with_state(
    repository: &str,
    state: ProviderLifecycleState,
) -> ProviderConnectionManifest {
    let configuration = ProviderConnectionConfiguration::new(
        WorkspaceId::parse("11111111-1111-4111-8111-111111111111").expect("workspace"),
        ExternalRepositoryIdentity::new(
            "22222222-2222-4222-8222-222222222222"
                .parse::<ProviderInstanceId>()
                .expect("instance"),
            ExternalRepositoryId::new(repository).expect("repository"),
        ),
        ProviderConfigurationRevision::new(3).expect("provider revision"),
        Sha256Digest::from_bytes([3; 32]),
        Sha256Digest::from_bytes([4; 32]),
        RepositoryVisibility::Private,
        ProviderDefaultBranch::new("main").expect("default branch"),
        ProviderWorkflowSource::Directory(
            ProviderRepositoryPath::new(".github/workflows").expect("workflow root"),
        ),
        ProviderRunnerPolicyBinding::new(
            ProviderSchemaVersion::new(1).expect("runner schema"),
            Sha256Digest::from_bytes([5; 32]),
        ),
        ProviderArchiveLimits::new(
            16 * 1_024 * 1_024,
            256 * 1_024 * 1_024,
            10_000,
            4_096,
            256,
            1_024 * 1_024,
        )
        .expect("archive limits"),
        ProviderConnectionPolicyDocument::new(
            ProviderSchemaVersion::new(1).expect("policy schema"),
            b"{}".to_vec(),
        )
        .expect("adapter policy"),
    );
    ProviderConnectionManifest::new(
        "33333333-3333-4333-8333-333333333333"
            .parse::<ProviderConnectionId>()
            .expect("connection"),
        ProviderConnectionRevision::new(7).expect("connection revision"),
        state,
        configuration,
        UnixMillis::new(1_000),
        (state != ProviderLifecycleState::Disabled).then(|| UnixMillis::new(1_001)),
        (state == ProviderLifecycleState::Retired).then(|| UnixMillis::new(1_002)),
    )
    .expect("active connection")
}
