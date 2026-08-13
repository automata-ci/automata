use automata_ci_auth::{
    human::{PrincipalId, TenantId},
    management::{ManagementActor, ManagementRevision},
    session::SessionId,
    time::UnixTimestamp,
};
use automata_ci_core::UnixMillis;
use automata_ci_store::{
    BuiltinRepositorySecretVersion, BuiltinSecretCleanupTask, BuiltinSecretProviderHealth,
    BuiltinSecretProviderInspection, BuiltinSecretProviderState, ClaimBuiltinSecretCleanup,
    ClaimSecretMutationRecovery, CompleteBuiltinSecretCleanup,
    ConfirmRepositorySecretVersionMutation, DeleteRepositorySecret, GetRepositorySecretMetadata,
    GithubRepositoryName, InspectBuiltinSecretProvider, MAX_SECRET_CLEANUP_CLAIM_MILLIS,
    MAX_SECRET_CLEANUP_RETRY_BACKOFF_MILLIS, MAX_SECRET_MUTATION_RECOVERY_CLAIM_MILLIS,
    ManagedSecretProviderId, PostgresSecretManagementRepository, RecoverSecretMutationReservation,
    RepositoryId, RepositorySecretId, RepositorySecretMutationId, RepositorySecretName,
    RepositorySecretProviderMutationResult, RepositorySecretVersionId,
    ReserveRepositorySecretVersionMutation, ResolveGithubRepositorySecretMetadata,
    RetryBuiltinSecretCleanup, SecretCleanupFailureKind, SecretCleanupFence, SecretCleanupWorkerId,
    SecretManagementValueError, SecretMetadataPageSize, SecretMutationRecoveryFence,
    SecretMutationRecoveryReconciliation, TenantScope,
};
use uuid::Uuid;

fn actor() -> ManagementActor {
    ManagementActor::new(
        TenantId::new("tenant-a").expect("valid tenant"),
        PrincipalId::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("valid principal"),
        SessionId::new("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("valid session"),
        ManagementRevision::new(1).expect("positive revision"),
        None,
        UnixTimestamp::from_seconds(1),
    )
}

#[test]
fn names_identifiers_and_page_bounds_fail_closed() {
    assert_eq!(
        RepositorySecretName::new("release_token")
            .expect("valid secret name")
            .as_str(),
        "RELEASE_TOKEN"
    );
    assert!(matches!(
        RepositorySecretName::new("github_token"),
        Err(SecretManagementValueError::ReservedSecretName)
    ));
    assert!(RepositorySecretName::new("9TOKEN").is_err());
    assert!(RepositorySecretName::new("TOKEN-DASH").is_err());
    assert!(RepositorySecretId::from_uuid(Uuid::nil()).is_err());
    assert!(SecretMetadataPageSize::new(0).is_err());
    assert!(SecretMetadataPageSize::new(100).is_ok());
    assert!(SecretMetadataPageSize::new(101).is_err());
    assert!(ManagedSecretProviderId::new("vault.prod").is_ok());
    assert!(ManagedSecretProviderId::new("Vault").is_err());
    assert!(SecretCleanupWorkerId::new("worker\nvalue").is_err());
}

#[test]
fn create_api_has_no_plaintext_or_provider_handle() {
    let secret_id = RepositorySecretId::from_uuid(Uuid::new_v4()).expect("non-nil secret ID");
    let mutation_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)
        .expect("independent mutation ID");
    let request = ReserveRepositorySecretVersionMutation::create(
        actor(),
        mutation_id,
        secret_id,
        RepositoryId::from_uuid(Uuid::new_v4()),
        RepositorySecretName::new("DEPLOY_TOKEN").expect("valid secret name"),
        None,
    )
    .expect("valid reservation");
    let debug = format!("{request:?}");
    assert!(debug.contains("DEPLOY_TOKEN"));
    assert!(!debug.contains("value"));
    assert!(!debug.contains("locator"));
    assert!(!debug.contains("handle"));

    let target = BuiltinRepositorySecretVersion::new(
        secret_id,
        RepositorySecretVersionId::from_uuid(Uuid::new_v4()).expect("version ID"),
        1,
    )
    .expect("positive version");
    let confirmation = ConfirmRepositorySecretVersionMutation::new(
        actor(),
        mutation_id,
        RepositorySecretProviderMutationResult::BuiltinCreated(target),
    );
    let debug = format!("{confirmation:?}");
    assert!(!debug.contains("value"));
    assert!(!debug.contains("ciphertext"));
    assert!(!debug.contains("handle"));
    assert!(!debug.contains("locator"));
}

#[test]
fn operational_read_requests_are_exact_and_value_free() {
    let repository_id = RepositoryId::from_uuid(Uuid::new_v4());
    let resolution = ResolveGithubRepositorySecretMetadata::new(
        actor(),
        GithubRepositoryName::new("automata-ci/automata").expect("canonical repository"),
    );
    assert_eq!(resolution.repository().as_str(), "automata-ci/automata");
    let lookup = GetRepositorySecretMetadata::new(
        actor(),
        repository_id,
        RepositorySecretName::new("DEPLOY_TOKEN").expect("canonical secret name"),
    )
    .expect("non-nil repository");
    assert_eq!(lookup.repository_id(), repository_id);
    assert_eq!(lookup.name().as_str(), "DEPLOY_TOKEN");
    let inspection = InspectBuiltinSecretProvider::new(actor());
    let provider = BuiltinSecretProviderInspection::from_durable_parts(
        BuiltinSecretProviderState::Unconfigured,
        BuiltinSecretProviderHealth::Unknown,
        ManagementRevision::new(3).expect("revision"),
        true,
    );
    assert_eq!(
        provider
            .activation()
            .expect("manager activation evidence")
            .expected_revision(),
        provider.revision()
    );
    for debug in [
        format!("{resolution:?}"),
        format!("{lookup:?}"),
        format!("{inspection:?}"),
    ] {
        assert!(!debug.contains("plaintext"));
        assert!(!debug.contains("ciphertext"));
        assert!(!debug.contains("handle"));
        assert!(!debug.contains("locator"));
    }
    assert!(
        GetRepositorySecretMetadata::new(
            actor(),
            RepositoryId::from_uuid(Uuid::nil()),
            RepositorySecretName::new("DEPLOY_TOKEN").expect("canonical secret name"),
        )
        .is_err()
    );
}

#[test]
fn mutation_and_version_identities_fail_closed() {
    let secret_id = RepositorySecretId::from_uuid(Uuid::new_v4()).expect("secret ID");
    assert!(RepositorySecretMutationId::from_uuid(Uuid::nil(), secret_id).is_err());
    assert!(RepositorySecretMutationId::from_uuid(secret_id.as_uuid(), secret_id).is_err());
    let other_secret = RepositorySecretId::from_uuid(Uuid::new_v4()).expect("other secret ID");
    let laundered = RepositorySecretMutationId::from_uuid(other_secret.as_uuid(), secret_id)
        .expect("UUID differs from the construction-time secret");
    assert!(matches!(
        ReserveRepositorySecretVersionMutation::create(
            actor(),
            laundered,
            other_secret,
            RepositoryId::from_uuid(Uuid::new_v4()),
            RepositorySecretName::new("LAUNDERED_ID").expect("valid name"),
            None,
        ),
        Err(SecretManagementValueError::MutationIdReusesSecretId)
    ));
    assert!(RepositorySecretVersionId::from_uuid(Uuid::nil()).is_err());

    assert!(matches!(
        DeleteRepositorySecret::new(
            actor(),
            RepositoryId::from_uuid(Uuid::nil()),
            secret_id,
            ManagementRevision::new(1).expect("revision"),
        ),
        Err(SecretManagementValueError::NilRepositoryId),
    ));
    let repository_id = RepositoryId::from_uuid(Uuid::new_v4());
    let deletion = DeleteRepositorySecret::new(
        actor(),
        repository_id,
        secret_id,
        ManagementRevision::new(1).expect("revision"),
    )
    .expect("repository-bound deletion");
    assert_eq!(deletion.repository_id(), repository_id);
}

#[test]
fn cleanup_api_requires_monotonic_fences() {
    let worker = SecretCleanupWorkerId::new("cleanup-a").expect("valid worker");
    let fence = SecretCleanupFence::new(Uuid::new_v4(), worker.clone(), 1, UnixMillis::new(10));
    let task = BuiltinSecretCleanupTask::new(
        fence.clone(),
        TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant scope"),
        ManagedSecretProviderId::new("builtin").expect("provider ID"),
        RepositorySecretId::from_uuid(Uuid::new_v4()).expect("secret ID"),
        RepositoryId::from_uuid(Uuid::new_v4()),
        RepositorySecretName::new("CLEANUP_TOKEN").expect("secret name"),
        Uuid::new_v4(),
        1,
        "secret-destroy:00000000-0000-4000-8000-000000000001".into(),
        1,
    );
    assert_eq!(task.tenant().as_str(), "tenant-a");
    assert_eq!(task.provider_id().as_str(), "builtin");
    assert!(CompleteBuiltinSecretCleanup::new(fence.clone(), UnixMillis::new(9)).is_err());
    let maximum_retry_at = 10 + i64::try_from(MAX_SECRET_CLEANUP_RETRY_BACKOFF_MILLIS).unwrap();
    assert!(
        RetryBuiltinSecretCleanup::new(
            fence.clone(),
            UnixMillis::new(10),
            UnixMillis::new(maximum_retry_at),
            SecretCleanupFailureKind::Unavailable,
        )
        .is_ok()
    );
    assert!(
        RetryBuiltinSecretCleanup::new(
            fence,
            UnixMillis::new(10),
            UnixMillis::new(maximum_retry_at + 1),
            SecretCleanupFailureKind::Unavailable,
        )
        .is_err()
    );
    assert!(
        ClaimBuiltinSecretCleanup::new(
            worker.clone(),
            UnixMillis::new(0),
            MAX_SECRET_CLEANUP_CLAIM_MILLIS,
        )
        .is_ok()
    );
    assert!(
        ClaimBuiltinSecretCleanup::new(
            worker,
            UnixMillis::new(0),
            MAX_SECRET_CLEANUP_CLAIM_MILLIS + 1,
        )
        .is_err()
    );
}

#[test]
fn recovery_api_requires_positive_monotonic_claim_generations() {
    let worker = SecretCleanupWorkerId::new("recovery-a").expect("valid worker");
    assert!(
        SecretMutationRecoveryFence::new(Uuid::nil(), worker.clone(), 1, UnixMillis::new(10),)
            .is_err()
    );
    assert!(
        SecretMutationRecoveryFence::new(Uuid::new_v4(), worker.clone(), 0, UnixMillis::new(10),)
            .is_err()
    );
    let claim_generation = 9;
    let fence = SecretMutationRecoveryFence::new(
        Uuid::new_v4(),
        worker.clone(),
        claim_generation,
        UnixMillis::new(10),
    )
    .expect("valid recovery fence");
    assert_eq!(fence.claim_generation(), claim_generation);
    assert!(
        RecoverSecretMutationReservation::new(
            fence.clone(),
            UnixMillis::new(9),
            SecretMutationRecoveryReconciliation::DefinitivelyNotCommitted,
        )
        .is_err()
    );
    assert!(
        RecoverSecretMutationReservation::new(
            fence,
            UnixMillis::new(10),
            SecretMutationRecoveryReconciliation::DefinitivelyNotCommitted,
        )
        .is_ok()
    );
    assert!(
        ClaimSecretMutationRecovery::new(
            worker.clone(),
            UnixMillis::new(10),
            MAX_SECRET_MUTATION_RECOVERY_CLAIM_MILLIS,
        )
        .is_ok()
    );
    assert!(
        ClaimSecretMutationRecovery::new(
            worker,
            UnixMillis::new(10),
            MAX_SECRET_MUTATION_RECOVERY_CLAIM_MILLIS + 1,
        )
        .is_err()
    );
}

#[tokio::test]
async fn concrete_adapter_debug_is_redacted() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://sentinel-user:sentinel-password@127.0.0.1:1/sentinel")
        .expect("valid lazy URL");
    let adapter = PostgresSecretManagementRepository::new(pool);
    let debug = format!("{adapter:?}");
    assert!(!debug.contains("sentinel-password"));
    assert_eq!(debug, "PostgresSecretManagementRepository { .. }");
}
