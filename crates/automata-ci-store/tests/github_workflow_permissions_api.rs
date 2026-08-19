use crate::{github_manifest_fixture, github_provider_manifest_api};

use automata_ci_actions_permissions::ActionsDefaultWorkflowPermission;
use automata_ci_core::{Sha256Digest, UnixMillis, WorkspaceId};
use automata_ci_provider::{
    ControlCredentialClaim, ControlCredentialRequest, ExternalRepositoryId,
    ExternalRepositoryIdentity, ProviderArchiveLimits, ProviderConfigurationRevision,
    ProviderConnectionConfiguration, ProviderConnectionManifest, ProviderConnectionPolicyDocument,
    ProviderConnectionRevision, ProviderControlCredentialId, ProviderControlCredentialWorkerId,
    ProviderControlOperation, ProviderControlOperationSet, ProviderCredentialGeneration,
    ProviderDefaultBranch, ProviderInstanceId, ProviderLifecycleState, ProviderRepositoryPath,
    ProviderRunnerPolicyBinding, ProviderSchemaVersion, ProviderWorkflowSource,
    RepositoryVisibility,
};
use automata_ci_store::{
    FinalizeGithubWorkflowPermissionObservation, GithubProviderManifest,
    GithubServerServiceAppClientId, GithubServerServiceAuthorityId,
    GithubServerServiceAuthorityIdentity, GithubServerServiceConsumerId,
    GithubServerServiceJwtIssuer, GithubServerServiceRevision, GithubServerServiceScope,
    GithubServerServiceWorkerId, GithubWorkflowPermissionDefaultsObservation,
    GithubWorkflowPermissionDefaultsObservationError,
    GithubWorkflowPermissionDefaultsObservationRepository,
    GithubWorkflowPermissionObservationCandidate,
};
use uuid::Uuid;

#[test]
fn candidate_is_fresh_exact_and_rejects_every_authority_identity_disagreement() {
    let bootstrap = bootstrap();
    let manifest = bootstrap.manifest().manifest();
    let exact = authority(manifest, AuthorityMutation::Exact);
    let claimed_at = UnixMillis::new(10_000);
    let first = candidate(&bootstrap, &exact, 0x501, 0x601, claimed_at);
    let replay = candidate(&bootstrap, &exact, 0x501, 0x601, claimed_at);
    let fresh = candidate(&bootstrap, &exact, 0x502, 0x601, claimed_at);
    let other_owner = candidate(&bootstrap, &exact, 0x503, 0x602, claimed_at);
    let later = candidate(&bootstrap, &exact, 0x504, 0x601, UnixMillis::new(10_001));

    assert_eq!(first, replay);
    assert_eq!(first.digest(), replay.digest());
    assert_ne!(first.observation_id(), fresh.observation_id());
    assert_ne!(first.digest(), fresh.digest());
    assert_ne!(first.digest(), other_owner.digest());
    assert_ne!(first.digest(), later.digest());
    assert_eq!(first.consumer().consumer_id(), first.observation_id());
    assert_eq!(
        first.expected_default(),
        ActionsDefaultWorkflowPermission::Read
    );
    assert_eq!(first.expires_at(), UnixMillis::new(370_000));

    for mutation in [
        AuthorityMutation::AppClient,
        AuthorityMutation::JwtIssuer,
        AuthorityMutation::Key,
        AuthorityMutation::AppConfigurationRevision,
        AuthorityMutation::PolicyRevision,
        AuthorityMutation::AuthorityRepository,
    ] {
        let mismatched = authority(manifest, mutation);
        assert_eq!(
            GithubWorkflowPermissionObservationCandidate::new(
                &bootstrap,
                &mismatched,
                consumer_id(0x700 + mutation as u128),
                worker(0x800 + mutation as u128),
                claimed_at,
            ),
            Err(GithubWorkflowPermissionDefaultsObservationError::InvalidBinding),
            "authority mutation {mutation:?} must fail closed"
        );
    }
}

#[test]
fn observation_and_finalization_bind_common_credential_generation_time_and_outcome() {
    let bootstrap = bootstrap();
    let authority = authority(bootstrap.manifest().manifest(), AuthorityMutation::Exact);
    let candidate = candidate(
        &bootstrap,
        &authority,
        0x901,
        0x902,
        UnixMillis::new(20_000),
    );
    let request = credential_request(&candidate, ProviderControlOperation::WorkflowPermissionRead);
    let generation = ProviderCredentialGeneration::new(3).expect("generation");
    let exact = GithubWorkflowPermissionDefaultsObservation::new(
        &bootstrap,
        candidate.clone(),
        &request,
        generation,
        ActionsDefaultWorkflowPermission::Read,
        false,
        UnixMillis::new(20_100),
    )
    .expect("observation");
    let can_approve = GithubWorkflowPermissionDefaultsObservation::new(
        &bootstrap,
        candidate.clone(),
        &request,
        generation,
        ActionsDefaultWorkflowPermission::Read,
        true,
        UnixMillis::new(20_100),
    )
    .expect("approval observation");
    let write = GithubWorkflowPermissionDefaultsObservation::new(
        &bootstrap,
        candidate.clone(),
        &request,
        generation,
        ActionsDefaultWorkflowPermission::Write,
        false,
        UnixMillis::new(20_100),
    )
    .expect("write observation");
    let later_provider = GithubWorkflowPermissionDefaultsObservation::new(
        &bootstrap,
        candidate.clone(),
        &request,
        generation,
        ActionsDefaultWorkflowPermission::Read,
        false,
        UnixMillis::new(20_101),
    )
    .expect("later observation");
    let other_generation = GithubWorkflowPermissionDefaultsObservation::new(
        &bootstrap,
        candidate.clone(),
        &request,
        ProviderCredentialGeneration::new(4).expect("generation"),
        ActionsDefaultWorkflowPermission::Read,
        false,
        UnixMillis::new(20_100),
    )
    .expect("other generation");

    for mutated in [&can_approve, &write, &later_provider, &other_generation] {
        assert_ne!(exact.digest(), mutated.digest());
    }
    assert_eq!(exact.credential_request_digest(), request.digest());
    assert_eq!(exact.credential_generation(), generation);
    assert!(exact.matches_expected_default());
    assert!(!can_approve.matches_expected_default());
    assert!(!write.matches_expected_default());
    assert!(FinalizeGithubWorkflowPermissionObservation::new(bootstrap.clone(), exact).is_ok());

    let wrong_operation = credential_request(&candidate, ProviderControlOperation::RepositoryRead);
    assert_eq!(
        GithubWorkflowPermissionDefaultsObservation::new(
            &bootstrap,
            candidate.clone(),
            &wrong_operation,
            generation,
            ActionsDefaultWorkflowPermission::Read,
            false,
            UnixMillis::new(20_100),
        ),
        Err(GithubWorkflowPermissionDefaultsObservationError::InvalidBinding)
    );
    assert_eq!(
        GithubWorkflowPermissionDefaultsObservation::new(
            &bootstrap,
            candidate,
            &request,
            generation,
            ActionsDefaultWorkflowPermission::Read,
            false,
            UnixMillis::new(320_000),
        ),
        Err(GithubWorkflowPermissionDefaultsObservationError::InvalidBinding)
    );
}
#[test]
fn repository_port_remains_backend_neutral_and_object_safe() {
    fn accepts_dyn(_: &dyn GithubWorkflowPermissionDefaultsObservationRepository) {}
    let _ = accepts_dyn;
}

fn bootstrap() -> automata_ci_store::BootstrapGithubProviderRepository {
    github_manifest_fixture::fixture_github_repository_bootstrap(
        github_provider_manifest_api::manifest(1, 1, 1, [7; 32], "Automata CI"),
        UnixMillis::new(1_000),
    )
}

fn candidate(
    bootstrap: &automata_ci_store::BootstrapGithubProviderRepository,
    authority: &GithubServerServiceAuthorityIdentity,
    observation: u128,
    owner: u128,
    claimed_at: UnixMillis,
) -> GithubWorkflowPermissionObservationCandidate {
    GithubWorkflowPermissionObservationCandidate::new(
        bootstrap,
        authority,
        consumer_id(observation),
        worker(owner),
        claimed_at,
    )
    .expect("candidate")
}

fn credential_request(
    candidate: &GithubWorkflowPermissionObservationCandidate,
    operation: ProviderControlOperation,
) -> ControlCredentialRequest {
    let expires_at = UnixMillis::new(candidate.claimed_at().get() + 300_000);
    let claim = ControlCredentialClaim::new(
        ProviderControlCredentialId::from_uuid(candidate.observation_id().as_uuid())
            .expect("credential ID"),
        ProviderControlCredentialWorkerId::from_uuid(candidate.consumer().owner().as_uuid())
            .expect("worker ID"),
        candidate.consumer().fence().get(),
        candidate.consumer().revision().get(),
        expires_at,
    )
    .expect("control claim");
    ControlCredentialRequest::new(
        claim,
        &connection(candidate),
        ProviderControlOperationSet::new([operation]).expect("operations"),
        candidate.claimed_at(),
        300_000,
    )
    .expect("credential request")
}

fn connection(
    candidate: &GithubWorkflowPermissionObservationCandidate,
) -> ProviderConnectionManifest {
    let configuration = ProviderConnectionConfiguration::new(
        WorkspaceId::parse("11111111-1111-4111-8111-111111111111").expect("workspace"),
        ExternalRepositoryIdentity::new(
            ProviderInstanceId::from_uuid(Uuid::from_u128(0x1000)).expect("instance"),
            ExternalRepositoryId::new(candidate.github_repository_id().get().to_string())
                .expect("external repository"),
        ),
        ProviderConfigurationRevision::new(1).expect("provider revision"),
        Sha256Digest::from_bytes([0x11; 32]),
        Sha256Digest::from_bytes([0x12; 32]),
        RepositoryVisibility::Public,
        ProviderDefaultBranch::new("main").expect("default branch"),
        ProviderWorkflowSource::Directory(
            ProviderRepositoryPath::new(".github/workflows").expect("workflow root"),
        ),
        ProviderRunnerPolicyBinding::new(
            ProviderSchemaVersion::new(1).expect("runner schema"),
            Sha256Digest::from_bytes([0x13; 32]),
        ),
        ProviderArchiveLimits::new(1_024, 8_192, 100, 1_024, 10, 1_024).expect("archive limits"),
        ProviderConnectionPolicyDocument::new(
            ProviderSchemaVersion::new(1).expect("policy schema"),
            b"{}".to_vec(),
        )
        .expect("connection policy"),
    );
    ProviderConnectionManifest::new(
        candidate.connection_id(),
        ProviderConnectionRevision::new(1).expect("connection revision"),
        ProviderLifecycleState::Active,
        configuration,
        UnixMillis::new(1),
        Some(UnixMillis::new(1)),
        None,
    )
    .expect("connection")
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum AuthorityMutation {
    Exact = 0,
    AppClient = 1,
    JwtIssuer = 2,
    Key = 3,
    AppConfigurationRevision = 4,
    PolicyRevision = 5,
    AuthorityRepository = 6,
}

fn authority(
    manifest: &GithubProviderManifest,
    mutation: AuthorityMutation,
) -> GithubServerServiceAuthorityIdentity {
    let app_client = if matches!(mutation, AuthorityMutation::AppClient) {
        GithubServerServiceAppClientId::new("Iv1.8a61f9b3a7aba767").expect("client")
    } else {
        manifest.app_client_id().clone()
    };
    let jwt_issuer = if matches!(mutation, AuthorityMutation::JwtIssuer) {
        GithubServerServiceJwtIssuer::AppId
    } else {
        manifest.jwt_issuer()
    };
    let key = if matches!(mutation, AuthorityMutation::Key) {
        Sha256Digest::from_bytes([8; 32])
    } else {
        manifest.app_key_spki_sha256()
    };
    let app_revision = if matches!(mutation, AuthorityMutation::AppConfigurationRevision) {
        GithubServerServiceRevision::new(manifest.app_configuration_revision().get() + 1)
            .expect("revision")
    } else {
        manifest.app_configuration_revision()
    };
    let policy_revision = if matches!(mutation, AuthorityMutation::PolicyRevision) {
        GithubServerServiceRevision::new(manifest.policy_revision().get() + 1).expect("revision")
    } else {
        manifest.policy_revision()
    };
    let repository_id = if matches!(mutation, AuthorityMutation::AuthorityRepository) {
        automata_ci_store::RepositoryId::from_uuid(Uuid::from_u128(0xb01))
    } else {
        manifest.repository_id()
    };
    GithubServerServiceAuthorityIdentity::new(
        manifest.tenant().clone(),
        GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(0xc01)).expect("authority"),
        repository_id,
        manifest.connection_id(),
        manifest.installation_id(),
        manifest.github_app_id(),
        manifest.github_repository_id(),
        manifest.github_repository_name().clone(),
        GithubServerServiceScope::WorkflowPermissionsRead,
        app_client,
        jwt_issuer,
        key,
        app_revision,
        policy_revision,
        Sha256Digest::from_bytes([0xd0; 32]),
    )
    .expect("authority")
}

fn consumer_id(value: u128) -> GithubServerServiceConsumerId {
    GithubServerServiceConsumerId::from_uuid(Uuid::from_u128(value)).expect("consumer")
}

fn worker(value: u128) -> GithubServerServiceWorkerId {
    GithubServerServiceWorkerId::from_uuid(Uuid::from_u128(value)).expect("worker")
}
