use crate::{github_manifest_fixture, github_provider_manifest_api};

use automata_ci_actions_permissions::ActionsDefaultWorkflowPermission;
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_store::{
    FinalizeGithubWorkflowPermissionObservation, GithubProviderManifest,
    GithubServerServiceAppClientId, GithubServerServiceAuthorityId,
    GithubServerServiceAuthorityIdentity, GithubServerServiceConsumerId,
    GithubServerServiceGeneration, GithubServerServiceHandoffId, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubServerServiceScope, GithubServerServiceWorkerId,
    GithubWorkflowPermissionDefaultsObservation, GithubWorkflowPermissionDefaultsObservationError,
    GithubWorkflowPermissionDefaultsObservationRepository,
    GithubWorkflowPermissionHandoffReconciliation, GithubWorkflowPermissionObservationCandidate,
    ReconcileGithubWorkflowPermissionHandoff, ReleaseGithubServerServiceHandoff,
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
#[allow(clippy::too_many_lines)] // One end-to-end lifecycle contract is clearer as a single test.
fn observation_and_finalization_bind_release_generation_time_outcome_and_bootstrap() {
    let bootstrap = bootstrap();
    let authority = authority(bootstrap.manifest().manifest(), AuthorityMutation::Exact);
    let observation_candidate = candidate(
        &bootstrap,
        &authority,
        0x901,
        0x902,
        UnixMillis::new(20_000),
    );
    let generation = GithubServerServiceGeneration::new(3).expect("generation");
    let exact_release = release(&observation_candidate, 0xa01, UnixMillis::new(20_200));
    let exact = GithubWorkflowPermissionDefaultsObservation::new(
        &bootstrap,
        observation_candidate.clone(),
        &exact_release,
        generation,
        ActionsDefaultWorkflowPermission::Read,
        false,
        UnixMillis::new(20_100),
    )
    .expect("observation");
    let can_approve = GithubWorkflowPermissionDefaultsObservation::new(
        &bootstrap,
        observation_candidate.clone(),
        &exact_release,
        generation,
        ActionsDefaultWorkflowPermission::Read,
        true,
        UnixMillis::new(20_100),
    )
    .expect("approval observation");
    let write = GithubWorkflowPermissionDefaultsObservation::new(
        &bootstrap,
        observation_candidate.clone(),
        &exact_release,
        generation,
        ActionsDefaultWorkflowPermission::Write,
        false,
        UnixMillis::new(20_100),
    )
    .expect("write observation");
    let later_provider = GithubWorkflowPermissionDefaultsObservation::new(
        &bootstrap,
        observation_candidate.clone(),
        &exact_release,
        generation,
        ActionsDefaultWorkflowPermission::Read,
        false,
        UnixMillis::new(20_101),
    )
    .expect("later observation");
    let other_generation = GithubWorkflowPermissionDefaultsObservation::new(
        &bootstrap,
        observation_candidate.clone(),
        &exact_release,
        GithubServerServiceGeneration::new(4).expect("generation"),
        ActionsDefaultWorkflowPermission::Read,
        false,
        UnixMillis::new(20_100),
    )
    .expect("other generation");
    let later_release = release(&observation_candidate, 0xa02, UnixMillis::new(20_201));
    let other_handoff = GithubWorkflowPermissionDefaultsObservation::new(
        &bootstrap,
        observation_candidate.clone(),
        &later_release,
        generation,
        ActionsDefaultWorkflowPermission::Read,
        false,
        UnixMillis::new(20_100),
    )
    .expect("other handoff");

    for mutated in [
        &can_approve,
        &write,
        &later_provider,
        &other_generation,
        &other_handoff,
    ] {
        assert_ne!(exact.digest(), mutated.digest());
    }
    assert!(exact.matches_expected_default());
    assert!(!observation_candidate.expected_can_approve_pull_request_reviews());
    assert!(!can_approve.matches_expected_default());
    assert!(!write.matches_expected_default());
    assert!(
        FinalizeGithubWorkflowPermissionObservation::new(
            bootstrap.clone(),
            exact_release.clone(),
            exact.clone(),
        )
        .is_ok()
    );
    assert_eq!(
        FinalizeGithubWorkflowPermissionObservation::new(
            bootstrap.clone(),
            later_release,
            exact.clone(),
        ),
        Err(GithubWorkflowPermissionDefaultsObservationError::InvalidBinding)
    );

    let early_release = release(&observation_candidate, 0xa03, UnixMillis::new(20_050));
    assert_eq!(
        GithubWorkflowPermissionDefaultsObservation::new(
            &bootstrap,
            observation_candidate.clone(),
            &early_release,
            generation,
            ActionsDefaultWorkflowPermission::Read,
            false,
            UnixMillis::new(20_100),
        ),
        Err(GithubWorkflowPermissionDefaultsObservationError::InvalidBinding)
    );
    let foreign_release = ReleaseGithubServerServiceHandoff::new(
        observation_candidate.authority_selector().clone(),
        GithubServerServiceHandoffId::from_uuid(Uuid::from_u128(0xa04)).expect("handoff"),
        candidate(
            &bootstrap,
            &authority,
            0x905,
            0x906,
            UnixMillis::new(20_000),
        )
        .consumer(),
        UnixMillis::new(20_200),
    )
    .expect("foreign release");
    assert_eq!(
        GithubWorkflowPermissionDefaultsObservation::new(
            &bootstrap,
            observation_candidate,
            &foreign_release,
            generation,
            ActionsDefaultWorkflowPermission::Read,
            false,
            UnixMillis::new(20_100),
        ),
        Err(GithubWorkflowPermissionDefaultsObservationError::InvalidBinding)
    );
}

#[test]
fn repository_port_remains_backend_neutral_and_object_safe() {
    fn accepts_dyn(_: &dyn GithubWorkflowPermissionDefaultsObservationRepository) {}
    let _ = accepts_dyn;
}

#[test]
fn ambiguous_handoff_reconciliation_is_value_free_and_candidate_bound() {
    let bootstrap = bootstrap();
    let authority = authority(bootstrap.manifest().manifest(), AuthorityMutation::Exact);
    let observation_candidate = candidate(
        &bootstrap,
        &authority,
        0xb01,
        0xb02,
        UnixMillis::new(30_000),
    );
    let request = ReconcileGithubWorkflowPermissionHandoff::new(observation_candidate.clone())
        .expect("reconciliation request");
    assert_eq!(request.candidate(), &observation_candidate);
    assert_eq!(request.required_through(), UnixMillis::new(330_000));
    assert!(request.required_through() < observation_candidate.expires_at());

    let handoff_id =
        GithubServerServiceHandoffId::from_uuid(Uuid::from_u128(0xb03)).expect("handoff");
    let generation = GithubServerServiceGeneration::new(7).expect("generation");
    let released_at = UnixMillis::new(30_100);
    let outcomes = [
        GithubWorkflowPermissionHandoffReconciliation::AbsentClosed {
            closed_at: released_at,
        },
        GithubWorkflowPermissionHandoffReconciliation::Released {
            handoff_id,
            generation,
            released_at,
        },
        GithubWorkflowPermissionHandoffReconciliation::AlreadyReleased {
            handoff_id,
            generation,
            released_at,
        },
    ];
    assert_ne!(outcomes[0], outcomes[1]);
    assert_ne!(outcomes[1], outcomes[2]);
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

fn release(
    candidate: &GithubWorkflowPermissionObservationCandidate,
    handoff: u128,
    released_at: UnixMillis,
) -> ReleaseGithubServerServiceHandoff {
    ReleaseGithubServerServiceHandoff::new(
        candidate.authority_selector().clone(),
        GithubServerServiceHandoffId::from_uuid(Uuid::from_u128(handoff)).expect("handoff"),
        candidate.consumer(),
        released_at,
    )
    .expect("release")
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
