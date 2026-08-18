use std::sync::Arc;

use automata_ci_core::{Sha256Digest, UnixMillis, WorkspaceId};
use automata_ci_provider::{
    ExternalRepositoryId, ExternalRepositoryIdentity, ProviderArchiveLimits,
    ProviderConfigurationDocument, ProviderConfigurationFactory, ProviderConfigurationRevision,
    ProviderConnectionConfiguration, ProviderConnectionId, ProviderConnectionManifest,
    ProviderConnectionRevision, ProviderDefaultBranch, ProviderFactoryRegistry,
    ProviderFactoryRegistryError, ProviderInstanceId, ProviderInstanceManifest,
    ProviderLifecycleState, ProviderOrigins, ProviderRepositoryPath, ProviderRunnerPolicyBinding,
    ProviderSchemaVersion, ProviderSecretBindings, ProviderSecretSet, ProviderTypeId,
    ProviderWorkflowSource, RepositoryVisibility, provider_capability_digest,
};
use automata_ci_provider_github::{
    GithubConnectionPolicy, GithubHttpLimits, GithubInstanceConfiguration, GithubProviderFactory,
};
use automata_ci_scm::RepositoryId;

fn instance(instance_id: &str, web: &str, api: &str, archive: &str) -> ProviderInstanceManifest {
    let capabilities = GithubProviderFactory::capabilities().expect("GitHub capabilities");
    ProviderInstanceManifest::new(
        instance_id
            .parse::<ProviderInstanceId>()
            .expect("instance ID"),
        ProviderTypeId::new("github").expect("provider type"),
        ProviderConfigurationRevision::new(1).expect("revision"),
        ProviderLifecycleState::Active,
        ProviderOrigins::new(web, api).expect("origins"),
        GithubInstanceConfiguration::new(archive.parse().expect("archive URL"))
            .expect("instance configuration")
            .document()
            .expect("configuration document"),
        ProviderSecretBindings::empty(),
        provider_capability_digest(&capabilities).expect("capability digest"),
        UnixMillis::new(1_000),
        Some(UnixMillis::new(1_000)),
        None,
    )
    .expect("instance manifest")
}

fn connection(
    instance: &ProviderInstanceManifest,
    connection_id: &str,
    external_repository_id: &str,
    installation_id: u64,
    repository: &str,
) -> ProviderConnectionManifest {
    let configuration = ProviderConnectionConfiguration::new(
        WorkspaceId::parse("11111111-1111-4111-8111-111111111111").expect("workspace"),
        ExternalRepositoryIdentity::new(
            instance.instance_id(),
            ExternalRepositoryId::new(external_repository_id).expect("external repository ID"),
        ),
        instance.revision(),
        instance.configuration().digest(),
        instance.capability_digest(),
        RepositoryVisibility::Private,
        ProviderDefaultBranch::new("main").expect("default branch"),
        ProviderWorkflowSource::Directory(
            ProviderRepositoryPath::new(".github/workflows").expect("workflow root"),
        ),
        ProviderRunnerPolicyBinding::new(
            ProviderSchemaVersion::new(1).expect("runner schema"),
            Sha256Digest::from_bytes([7; 32]),
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
        GithubConnectionPolicy::new(
            installation_id,
            RepositoryId::new(repository).expect("repository route"),
        )
        .expect("connection policy")
        .document()
        .expect("connection document"),
    );
    ProviderConnectionManifest::new(
        connection_id
            .parse::<ProviderConnectionId>()
            .expect("connection ID"),
        ProviderConnectionRevision::new(1).expect("connection revision"),
        ProviderLifecycleState::Active,
        configuration,
        UnixMillis::new(1_000),
        Some(UnixMillis::new(1_000)),
        None,
    )
    .expect("connection manifest")
}

fn registry() -> ProviderFactoryRegistry {
    ProviderFactoryRegistry::new([
        Arc::new(GithubProviderFactory::new()) as Arc<dyn ProviderConfigurationFactory>
    ])
    .expect("GitHub factory registry")
}

#[test]
fn one_factory_builds_two_isolated_github_instances_and_connections() {
    let first = instance(
        "22222222-2222-4222-8222-222222222221",
        "https://github.first.example/",
        "https://api.github.first.example/v3/",
        "https://archives.github.first.example/",
    );
    let second = instance(
        "22222222-2222-4222-8222-222222222222",
        "https://github.second.example/",
        "https://api.github.second.example/v3/",
        "https://archives.github.second.example/",
    );
    let secrets =
        ProviderSecretSet::new(&ProviderSecretBindings::empty(), []).expect("empty secret set");
    let registry = registry();
    let first_descriptor = registry
        .build_descriptor(first.clone(), &secrets)
        .expect("first descriptor");
    let second_descriptor = registry
        .build_descriptor(second.clone(), &secrets)
        .expect("second descriptor");
    assert_ne!(
        first_descriptor.manifest().instance_id(),
        second_descriptor.manifest().instance_id()
    );

    let factory = GithubProviderFactory::new();
    let first_source = factory
        .repository_source(
            &first_descriptor,
            "automata-provider-test/1",
            GithubHttpLimits::default(),
        )
        .expect("first source");
    let second_source = factory
        .repository_source(
            &second_descriptor,
            "automata-provider-test/1",
            GithubHttpLimits::default(),
        )
        .expect("second source");
    assert_eq!(
        first_source.trusted_origins().api_base().as_str(),
        "https://api.github.first.example/v3/"
    );
    assert_eq!(
        second_source.trusted_origins().api_base().as_str(),
        "https://api.github.second.example/v3/"
    );

    let first_connection = connection(
        &first,
        "33333333-3333-4333-8333-333333333331",
        "42",
        7,
        "first/project",
    );
    let second_connection = connection(
        &second,
        "33333333-3333-4333-8333-333333333332",
        "42",
        9,
        "second/project",
    );
    registry
        .validate_connection(&first_descriptor, &first_connection)
        .expect("first connection");
    registry
        .validate_connection(&second_descriptor, &second_connection)
        .expect("second connection");
    let first_binding = factory
        .source_connection(&first_descriptor, &first_connection)
        .expect("first source binding");
    let second_binding = factory
        .source_connection(&second_descriptor, &second_connection)
        .expect("second source binding");
    assert_ne!(
        first_binding.connection_id(),
        second_binding.connection_id()
    );
    assert_eq!(first_binding.external_repository_id().as_str(), "42");
    assert_eq!(second_binding.external_repository_id().as_str(), "42");
    assert_eq!(first_binding.repository().as_str(), "first/project");
    assert_eq!(second_binding.repository().as_str(), "second/project");
}

#[test]
fn registry_rejects_noncanonical_github_documents_and_cross_instance_connections() {
    let valid = instance(
        "22222222-2222-4222-8222-222222222221",
        "https://github.example/",
        "https://api.github.example/v3/",
        "https://archives.github.example/",
    );
    let secrets =
        ProviderSecretSet::new(&ProviderSecretBindings::empty(), []).expect("empty secret set");
    let registry = registry();
    let descriptor = registry
        .build_descriptor(valid.clone(), &secrets)
        .expect("descriptor");
    let other = instance(
        "22222222-2222-4222-8222-222222222222",
        "https://github.other.example/",
        "https://api.github.other.example/v3/",
        "https://archives.github.other.example/",
    );
    let rebound = connection(
        &other,
        "33333333-3333-4333-8333-333333333333",
        "42",
        7,
        "other/project",
    );
    assert_eq!(
        registry.validate_connection(&descriptor, &rebound),
        Err(ProviderFactoryRegistryError::ConnectionEvidence)
    );

    let noncanonical = ProviderConfigurationDocument::new(
        ProviderSchemaVersion::new(1).expect("schema"),
        br#"{ "rest_api_version":"2026-03-10", "archive_origin":"https://archives.github.example/" }"#
            .to_vec(),
    )
    .expect("bounded document");
    let malformed = ProviderInstanceManifest::new(
        valid.instance_id(),
        valid.provider_type().clone(),
        valid.revision(),
        valid.state(),
        valid.origins().clone(),
        noncanonical,
        ProviderSecretBindings::empty(),
        valid.capability_digest(),
        valid.created_at(),
        valid.activated_at(),
        valid.retired_at(),
    )
    .expect("structurally valid manifest");
    assert!(matches!(
        registry.build_descriptor(malformed, &secrets),
        Err(ProviderFactoryRegistryError::Validation(_))
    ));
}

#[test]
fn typed_policies_reject_implicit_or_unsafe_authority() {
    assert!(GithubConnectionPolicy::new(0, RepositoryId::new("owner/repo").unwrap()).is_err());
    assert!(GithubInstanceConfiguration::new("http://github.example/".parse().unwrap()).is_err());
    assert!(
        GithubInstanceConfiguration::new("https://user@github.example/".parse().unwrap()).is_err()
    );
}
