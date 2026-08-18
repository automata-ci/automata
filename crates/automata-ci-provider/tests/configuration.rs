use std::sync::Arc;

use automata_ci_core::{GitObjectAlgorithm, Sha256Digest, UnixMillis, WorkspaceId};
use automata_ci_key_management::SecretBytes;
use automata_ci_provider::{
    ExternalRepositoryId, ExternalRepositoryIdentity, MAX_PROVIDER_SCHEMA_VERSION,
    ProviderArchiveLimits, ProviderCapabilities, ProviderCapability, ProviderConfigurationDocument,
    ProviderConfigurationError, ProviderConfigurationFactory, ProviderConfigurationRevision,
    ProviderConnectionConfiguration, ProviderConnectionFactoryRequest, ProviderConnectionId,
    ProviderConnectionManifest, ProviderConnectionPolicyDocument, ProviderConnectionRevision,
    ProviderDefaultBranch, ProviderFactoryRegistry, ProviderFactoryRegistryError,
    ProviderFactoryRequest, ProviderFactoryValidationError, ProviderInstanceId,
    ProviderInstanceManifest, ProviderLifecycleState, ProviderOrigins, ProviderRepositoryPath,
    ProviderRunnerPolicyBinding, ProviderSchemaVersion, ProviderSecret, ProviderSecretBinding,
    ProviderSecretBindings, ProviderSecretGeneration, ProviderSecretName, ProviderSecretSet,
    ProviderTypeId, ProviderWorkflowSource, RepositoryVisibility, SourceReadCapability,
    provider_capability_digest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

#[derive(Debug)]
struct FakeFactory {
    provider_type: ProviderTypeId,
    api_family: &'static str,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FakeConfiguration {
    api_family: String,
}

impl FakeFactory {
    fn new(provider_type: &str, api_family: &'static str) -> Self {
        Self {
            provider_type: ProviderTypeId::new(provider_type).expect("provider type"),
            api_family,
        }
    }
}

impl ProviderConfigurationFactory for FakeFactory {
    fn provider_type(&self) -> &ProviderTypeId {
        &self.provider_type
    }

    fn validate_instance(
        &self,
        request: ProviderFactoryRequest<'_>,
    ) -> Result<ProviderCapabilities, ProviderFactoryValidationError> {
        if request.manifest().configuration().schema_version().get() != 1 {
            return Err(ProviderFactoryValidationError::UnsupportedSchema);
        }
        let decoded =
            serde_json::from_slice::<FakeConfiguration>(request.manifest().configuration().bytes())
                .map_err(|_| ProviderFactoryValidationError::InvalidConfiguration)?;
        let canonical = serde_json::to_vec(&decoded)
            .map_err(|_| ProviderFactoryValidationError::InvalidConfiguration)?;
        if canonical != request.manifest().configuration().bytes()
            || decoded.api_family != self.api_family
        {
            return Err(ProviderFactoryValidationError::InvalidConfiguration);
        }

        let token = ProviderSecretName::new("control-token").expect("secret name");
        if request.manifest().secrets().len() != 1 || request.secrets().get(&token).is_none() {
            return Err(ProviderFactoryValidationError::InvalidSecrets);
        }

        source_capabilities().map_err(|_| ProviderFactoryValidationError::InvalidCapabilities)
    }

    fn validate_connection(
        &self,
        request: ProviderConnectionFactoryRequest<'_>,
    ) -> Result<(), ProviderFactoryValidationError> {
        let document = request.connection().configuration().adapter_policy();
        if document.schema_version().get() != 1 {
            return Err(ProviderFactoryValidationError::UnsupportedSchema);
        }
        let decoded = serde_json::from_slice::<FakeConfiguration>(document.bytes())
            .map_err(|_| ProviderFactoryValidationError::InvalidConfiguration)?;
        let canonical = serde_json::to_vec(&decoded)
            .map_err(|_| ProviderFactoryValidationError::InvalidConfiguration)?;
        if canonical != document.bytes() || decoded.api_family != self.api_family {
            return Err(ProviderFactoryValidationError::InvalidConfiguration);
        }
        Ok(())
    }
}

fn source_capabilities()
-> Result<ProviderCapabilities, automata_ci_provider::ProviderCapabilitiesError> {
    ProviderCapabilities::new([ProviderCapability::SourceRead(SourceReadCapability::new(
        [GitObjectAlgorithm::Sha1],
    )?)])
}

fn secret_digest(value: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(value).into())
}

fn bindings(value: &[u8], generation: u64) -> ProviderSecretBindings {
    ProviderSecretBindings::new([ProviderSecretBinding::new(
        ProviderSecretName::new("control-token").expect("secret name"),
        ProviderSecretGeneration::new(generation).expect("secret generation"),
        secret_digest(value),
    )])
    .expect("bindings")
}

fn secret_set(value: &[u8], generation: u64) -> ProviderSecretSet {
    let bindings = bindings(value, generation);
    ProviderSecretSet::new(
        &bindings,
        [ProviderSecret::new(
            ProviderSecretName::new("control-token").expect("secret name"),
            ProviderSecretGeneration::new(generation).expect("secret generation"),
            SecretBytes::new(value.to_vec()).expect("secret bytes"),
        )],
    )
    .expect("secret set")
}

#[allow(clippy::too_many_arguments)]
fn manifest(
    provider_type: &str,
    api_family: &str,
    schema: u16,
    revision: u64,
    state: ProviderLifecycleState,
    secrets: ProviderSecretBindings,
    capability_digest: Sha256Digest,
    activated_at: Option<UnixMillis>,
    retired_at: Option<UnixMillis>,
) -> ProviderInstanceManifest {
    let bytes = serde_json::to_vec(&FakeConfiguration {
        api_family: api_family.to_owned(),
    })
    .expect("configuration bytes");
    ProviderInstanceManifest::new(
        ProviderInstanceId::from_uuid(Uuid::from_u128(7)).expect("instance ID"),
        ProviderTypeId::new(provider_type).expect("provider type"),
        ProviderConfigurationRevision::new(revision).expect("revision"),
        state,
        ProviderOrigins::new("https://code.example/", "https://code.example/api/v1/")
            .expect("origins"),
        ProviderConfigurationDocument::new(
            ProviderSchemaVersion::new(schema).expect("schema"),
            bytes,
        )
        .expect("configuration"),
        secrets,
        capability_digest,
        UnixMillis::new(1_000),
        activated_at,
        retired_at,
    )
    .expect("manifest")
}

fn registry() -> ProviderFactoryRegistry {
    ProviderFactoryRegistry::new([
        Arc::new(FakeFactory::new("github", "github")) as Arc<dyn ProviderConfigurationFactory>,
        Arc::new(FakeFactory::new("forgejo", "forgejo")) as Arc<dyn ProviderConfigurationFactory>,
    ])
    .expect("registry")
}

fn connection_manifest(
    instance: &ProviderInstanceManifest,
    api_family: &str,
    schema: u16,
    provider_configuration_digest: Sha256Digest,
) -> ProviderConnectionManifest {
    let configuration = ProviderConnectionConfiguration::new(
        WorkspaceId::parse("11111111-1111-4111-8111-111111111111").expect("workspace"),
        ExternalRepositoryIdentity::new(
            instance.instance_id(),
            ExternalRepositoryId::new("42").expect("repository"),
        ),
        instance.revision(),
        provider_configuration_digest,
        instance.capability_digest(),
        RepositoryVisibility::Private,
        ProviderDefaultBranch::new("main").expect("branch"),
        ProviderWorkflowSource::Directory(
            ProviderRepositoryPath::new(".ci/workflows").expect("workflow source"),
        ),
        ProviderRunnerPolicyBinding::new(
            ProviderSchemaVersion::new(1).expect("runner schema"),
            Sha256Digest::from_bytes([7; 32]),
        ),
        ProviderArchiveLimits::new(1, 1, 1, 1, 1, 1).expect("archive limits"),
        ProviderConnectionPolicyDocument::new(
            ProviderSchemaVersion::new(schema).expect("adapter schema"),
            serde_json::to_vec(&FakeConfiguration {
                api_family: api_family.to_owned(),
            })
            .expect("adapter policy"),
        )
        .expect("adapter document"),
    );
    ProviderConnectionManifest::new(
        ProviderConnectionId::from_uuid(Uuid::from_u128(8)).expect("connection"),
        ProviderConnectionRevision::new(1).expect("connection revision"),
        ProviderLifecycleState::Active,
        configuration,
        UnixMillis::new(1_000),
        Some(UnixMillis::new(1_000)),
        None,
    )
    .expect("connection manifest")
}

#[test]
fn origins_require_exact_canonical_https_bases() {
    let valid = ProviderOrigins::new("https://code.example/", "https://code.example:8443/api/v1/")
        .expect("origins");
    assert_eq!(valid.web(), "https://code.example/");
    assert_eq!(valid.api(), "https://code.example:8443/api/v1/");

    for (web, api) in [
        ("http://code.example/", "https://code.example/api/v1/"),
        ("https://code.example/path", "https://code.example/api/v1/"),
        ("https://user@code.example/", "https://code.example/api/v1/"),
        ("https://code.example/", "https://code.example/api/v1"),
        (
            "https://code.example/",
            "https://code.example/api/v1/?page=1",
        ),
        ("https://CODE.example/", "https://code.example/api/v1/"),
    ] {
        assert!(
            ProviderOrigins::new(web, api).is_err(),
            "accepted {web} {api}"
        );
    }
}

#[test]
fn configuration_documents_are_positive_bounded_and_domain_separated() {
    assert_eq!(
        ProviderSchemaVersion::new(0),
        Err(ProviderConfigurationError::InvalidSchemaVersion)
    );
    assert_eq!(
        ProviderSchemaVersion::new(MAX_PROVIDER_SCHEMA_VERSION.saturating_add(1)),
        Err(ProviderConfigurationError::InvalidSchemaVersion)
    );
    let first = ProviderConfigurationDocument::new(
        ProviderSchemaVersion::new(1).expect("schema"),
        b"{}".to_vec(),
    )
    .expect("document");
    let second = ProviderConfigurationDocument::new(
        ProviderSchemaVersion::new(2).expect("schema"),
        b"{}".to_vec(),
    )
    .expect("document");
    assert_ne!(first.digest(), second.digest());
    assert_eq!(
        ProviderConfigurationDocument::new(
            ProviderSchemaVersion::new(1).expect("schema"),
            Vec::new(),
        ),
        Err(ProviderConfigurationError::InvalidConfigurationDocument)
    );
}

#[test]
fn secret_sets_require_exact_names_generations_and_plaintext() {
    let expected = bindings(b"correct", 2);
    let valid = ProviderSecretSet::new(
        &expected,
        [ProviderSecret::new(
            ProviderSecretName::new("control-token").expect("name"),
            ProviderSecretGeneration::new(2).expect("generation"),
            SecretBytes::new(b"correct".to_vec()).expect("secret"),
        )],
    )
    .expect("secret set");
    assert_eq!(valid.names().count(), 1);
    assert!(!format!("{valid:?}").contains("correct"));

    let missing = ProviderSecretSet::new(&expected, []);
    assert!(matches!(
        missing,
        Err(ProviderConfigurationError::MissingSecret)
    ));
    let wrong_value = ProviderSecretSet::new(
        &expected,
        [ProviderSecret::new(
            ProviderSecretName::new("control-token").expect("name"),
            ProviderSecretGeneration::new(2).expect("generation"),
            SecretBytes::new(b"wrong".to_vec()).expect("secret"),
        )],
    );
    assert!(matches!(
        wrong_value,
        Err(ProviderConfigurationError::SecretMismatch)
    ));
    let unexpected = ProviderSecretSet::new(
        &expected,
        [ProviderSecret::new(
            ProviderSecretName::new("other-token").expect("name"),
            ProviderSecretGeneration::new(2).expect("generation"),
            SecretBytes::new(b"correct".to_vec()).expect("secret"),
        )],
    );
    assert!(matches!(
        unexpected,
        Err(ProviderConfigurationError::UnexpectedSecret)
    ));
}

#[test]
fn manifest_successors_require_real_change_and_exact_lifecycle_evidence() {
    let capabilities = source_capabilities().expect("capabilities");
    let digest = provider_capability_digest(&capabilities).expect("capability digest");
    let prior = manifest(
        "github",
        "github",
        1,
        1,
        ProviderLifecycleState::Disabled,
        bindings(b"first", 1),
        digest,
        None,
        None,
    );
    let revision_only = manifest(
        "github",
        "github",
        1,
        2,
        ProviderLifecycleState::Disabled,
        bindings(b"first", 1),
        digest,
        None,
        None,
    );
    assert_eq!(
        revision_only.validate_successor(&prior),
        Err(ProviderConfigurationError::InvalidSuccessor)
    );

    let activated = manifest(
        "github",
        "github",
        1,
        2,
        ProviderLifecycleState::Active,
        bindings(b"first", 1),
        digest,
        Some(UnixMillis::new(2_000)),
        None,
    );
    activated.validate_successor(&prior).expect("activation");

    let rotated = manifest(
        "github",
        "github",
        1,
        3,
        ProviderLifecycleState::Active,
        bindings(b"second", 2),
        digest,
        Some(UnixMillis::new(2_000)),
        None,
    );
    rotated.validate_successor(&activated).expect("rotation");

    let skipped_generation = manifest(
        "github",
        "github",
        1,
        3,
        ProviderLifecycleState::Active,
        bindings(b"second", 3),
        digest,
        Some(UnixMillis::new(2_000)),
        None,
    );
    assert_eq!(
        skipped_generation.validate_successor(&activated),
        Err(ProviderConfigurationError::InvalidSuccessor)
    );
}

#[test]
fn registry_dispatches_two_factories_without_provider_fallback() {
    let registry = registry();
    assert_eq!(
        registry
            .provider_types()
            .map(ProviderTypeId::as_str)
            .collect::<Vec<_>>(),
        ["forgejo", "github"]
    );
    let capabilities = source_capabilities().expect("capabilities");
    let digest = provider_capability_digest(&capabilities).expect("capability digest");

    for (provider_type, api_family) in [("github", "github"), ("forgejo", "forgejo")] {
        let manifest = manifest(
            provider_type,
            api_family,
            1,
            1,
            ProviderLifecycleState::Active,
            bindings(b"token", 1),
            digest,
            Some(UnixMillis::new(1_000)),
            None,
        );
        let descriptor = registry
            .build_descriptor(manifest, &secret_set(b"token", 1))
            .expect("descriptor");
        assert_eq!(
            descriptor.manifest().provider_type().as_str(),
            provider_type
        );
        assert_eq!(descriptor.capabilities(), &capabilities);
    }

    let unknown = manifest(
        "gitlab",
        "gitlab",
        1,
        1,
        ProviderLifecycleState::Active,
        bindings(b"token", 1),
        digest,
        Some(UnixMillis::new(1_000)),
        None,
    );
    assert_eq!(
        registry.build_descriptor(unknown, &secret_set(b"token", 1)),
        Err(ProviderFactoryRegistryError::UnknownProviderType)
    );
}

#[test]
fn registry_validates_connection_policy_against_exact_provider_evidence() {
    let registry = registry();
    let capabilities = source_capabilities().expect("capabilities");
    let digest = provider_capability_digest(&capabilities).expect("capability digest");
    let instance = manifest(
        "forgejo",
        "forgejo",
        1,
        1,
        ProviderLifecycleState::Active,
        bindings(b"token", 1),
        digest,
        Some(UnixMillis::new(1_000)),
        None,
    );
    let descriptor = registry
        .build_descriptor(instance, &secret_set(b"token", 1))
        .expect("descriptor");
    let configuration_digest = descriptor.manifest().configuration().digest();
    let valid = connection_manifest(descriptor.manifest(), "forgejo", 1, configuration_digest);
    registry
        .validate_connection(&descriptor, &valid)
        .expect("connection policy");

    let unknown_schema =
        connection_manifest(descriptor.manifest(), "forgejo", 2, configuration_digest);
    assert_eq!(
        registry.validate_connection(&descriptor, &unknown_schema),
        Err(ProviderFactoryRegistryError::Validation(
            ProviderFactoryValidationError::UnsupportedSchema
        ))
    );
    let wrong_provider_evidence = connection_manifest(
        descriptor.manifest(),
        "forgejo",
        1,
        Sha256Digest::from_bytes([9; 32]),
    );
    assert_eq!(
        registry.validate_connection(&descriptor, &wrong_provider_evidence),
        Err(ProviderFactoryRegistryError::ConnectionEvidence)
    );
}

#[test]
fn registry_fails_closed_on_schema_document_secret_and_capability_drift() {
    let registry = registry();
    let capabilities = source_capabilities().expect("capabilities");
    let digest = provider_capability_digest(&capabilities).expect("capability digest");

    let unsupported = manifest(
        "github",
        "github",
        2,
        1,
        ProviderLifecycleState::Active,
        bindings(b"token", 1),
        digest,
        Some(UnixMillis::new(1_000)),
        None,
    );
    assert_eq!(
        registry.build_descriptor(unsupported, &secret_set(b"token", 1)),
        Err(ProviderFactoryRegistryError::Validation(
            ProviderFactoryValidationError::UnsupportedSchema
        ))
    );

    let mut unknown_field = manifest(
        "github",
        "github",
        1,
        1,
        ProviderLifecycleState::Active,
        bindings(b"token", 1),
        digest,
        Some(UnixMillis::new(1_000)),
        None,
    );
    let document = ProviderConfigurationDocument::new(
        ProviderSchemaVersion::new(1).expect("schema"),
        br#"{"api_family":"github","extra":true}"#.to_vec(),
    )
    .expect("document");
    unknown_field = ProviderInstanceManifest::new(
        unknown_field.instance_id(),
        unknown_field.provider_type().clone(),
        unknown_field.revision(),
        unknown_field.state(),
        unknown_field.origins().clone(),
        document,
        unknown_field.secrets().clone(),
        unknown_field.capability_digest(),
        unknown_field.created_at(),
        unknown_field.activated_at(),
        unknown_field.retired_at(),
    )
    .expect("manifest");
    assert_eq!(
        registry.build_descriptor(unknown_field, &secret_set(b"token", 1)),
        Err(ProviderFactoryRegistryError::Validation(
            ProviderFactoryValidationError::InvalidConfiguration
        ))
    );

    let wrong_secret_manifest = manifest(
        "github",
        "github",
        1,
        1,
        ProviderLifecycleState::Active,
        bindings(b"first", 1),
        digest,
        Some(UnixMillis::new(1_000)),
        None,
    );
    assert_eq!(
        registry.build_descriptor(wrong_secret_manifest, &secret_set(b"second", 1)),
        Err(ProviderFactoryRegistryError::SecretEvidence)
    );

    let wrong_digest = manifest(
        "github",
        "github",
        1,
        1,
        ProviderLifecycleState::Active,
        bindings(b"token", 1),
        Sha256Digest::from_bytes([9; 32]),
        Some(UnixMillis::new(1_000)),
        None,
    );
    assert_eq!(
        registry.build_descriptor(wrong_digest, &secret_set(b"token", 1)),
        Err(ProviderFactoryRegistryError::CapabilityDigest)
    );
}

#[test]
fn registry_rejects_empty_and_duplicate_factory_sets_without_debug_leaks() {
    assert!(matches!(
        ProviderFactoryRegistry::new([]),
        Err(ProviderFactoryRegistryError::NoFactories)
    ));
    assert!(matches!(
        ProviderFactoryRegistry::new([
            Arc::new(FakeFactory::new("github", "first")) as Arc<dyn ProviderConfigurationFactory>,
            Arc::new(FakeFactory::new("github", "second")) as Arc<dyn ProviderConfigurationFactory>,
        ]),
        Err(ProviderFactoryRegistryError::DuplicateFactory)
    ));

    let debug = format!("{:?}", registry());
    assert!(debug.contains("github"));
    assert!(debug.contains("forgejo"));
    assert!(!debug.contains("api_family"));
}
