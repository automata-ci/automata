use std::{sync::Arc, time::Duration};

use automata_ci_auth::{
    human::{PrincipalId, TenantId},
    management::{ManagementActor, ManagementRevision},
    session::SessionId,
    time::UnixTimestamp,
};
use automata_ci_core::UnixMillis;
use automata_ci_key_management::{
    EnvelopeCodec, KeyEncryptionContext, KeyEncryptionProvider, KeyId, KeyPurpose,
    LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes,
};
use automata_ci_postgres::store::{
    PostgresSecretCustodyRepository, PostgresSecretManagementRepository,
};
use automata_ci_store::{
    ActivateBuiltinSecretProvider, ActivateBuiltinSecretProviderOutcome,
    BUILTIN_SECRET_PROVIDER_ID, BuiltinRepositorySecretVersion, BuiltinSecretCleanupRepository,
    BuiltinSecretProviderHealth, BuiltinSecretProviderState, ClaimBuiltinSecretCleanup,
    ClaimBuiltinSecretCleanupOutcome, ClaimSecretMutationRecovery,
    ClaimSecretMutationRecoveryOutcome, CompleteBuiltinSecretCleanup,
    CompleteBuiltinSecretCleanupOutcome, ConfirmRepositorySecretVersionMutation,
    ConfirmRepositorySecretVersionMutationOutcome, DeleteRepositorySecret,
    DeleteRepositorySecretOutcome, GetRepositorySecretMetadata, GetRepositorySecretMetadataOutcome,
    GithubRepositoryName, InspectBuiltinSecretProvider, InspectBuiltinSecretProviderOutcome,
    ListRepositorySecrets, ListRepositorySecretsOutcome, ManagedSecretProviderId,
    RecoverSecretMutationReservation, RecoverSecretMutationReservationOutcome, RepositoryId,
    RepositorySecretId, RepositorySecretManagementReadRepository,
    RepositorySecretManagementRepository, RepositorySecretMutationId, RepositorySecretName,
    RepositorySecretProviderMutationResult, RepositorySecretVersionId,
    ReserveRepositorySecretVersionMutation, ReserveRepositorySecretVersionMutationOutcome,
    ResolveGithubRepositorySecretMetadata, ResolveGithubRepositorySecretMetadataOutcome,
    RetryBuiltinSecretCleanup, RetryBuiltinSecretCleanupOutcome, SecretCleanupFailureKind,
    SecretCleanupWorkerId, SecretCustodyKeySet, SecretCustodyRepository as _,
    SecretMetadataPageSize, SecretMutationRecoveryFence, SecretMutationRecoveryReconciliation,
    SecretMutationRecoveryRepository, VerifySecretCustody, VerifySecretCustodyOutcome,
};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::support::{TestResult, run_with_database};

const BUILTIN_VALUE_PURPOSE: &str = "secrets/builtin-value:v1";

struct Fixture {
    tenant_id: String,
    repository_id: Uuid,
    principal_id: Uuid,
    session_id: Uuid,
    authorization_revision: u64,
}

impl Fixture {
    fn actor(&self) -> ManagementActor {
        self.actor_at(100)
    }

    fn actor_at(&self, now_seconds: u64) -> ManagementActor {
        ManagementActor::new(
            TenantId::new(&self.tenant_id).expect("tenant"),
            PrincipalId::new(self.principal_id.hyphenated().to_string()).expect("principal"),
            SessionId::new(self.session_id.hyphenated().to_string()).expect("session"),
            ManagementRevision::new(self.authorization_revision).expect("revision"),
            None,
            UnixTimestamp::from_seconds(now_seconds),
        )
    }
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn encrypted_create_list_delete_and_cleanup_are_atomic_and_sanitized() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(database.pool(), "7001", true).await?;
        let adapter = PostgresSecretManagementRepository::new(database.pool().clone());

        let inspection = adapter
            .inspect_builtin_secret_provider(InspectBuiltinSecretProvider::new(fixture.actor()))
            .await?;
        let InspectBuiltinSecretProviderOutcome::Found(inspection) = inspection else {
            return Err("built-in provider inspection was not authorized".into());
        };
        assert_eq!(inspection.state(), BuiltinSecretProviderState::Unconfigured);
        assert_eq!(inspection.health(), BuiltinSecretProviderHealth::Unknown);
        assert_eq!(inspection.revision().value(), 1);
        assert_eq!(
            inspection
                .activation()
                .ok_or("provider manager did not receive activation evidence")?
                .expected_revision(),
            inspection.revision()
        );

        let activation = adapter
            .activate_builtin_secret_provider(ActivateBuiltinSecretProvider::new(
                fixture.actor(),
                ManagementRevision::new(1)?,
            ))
            .await?;
        let ActivateBuiltinSecretProviderOutcome::Activated(provider) = activation else {
            return Err("built-in provider was not activated".into());
        };
        assert_eq!(provider.state(), BuiltinSecretProviderState::Active);
        assert_eq!(provider.revision().value(), 2);
        let InspectBuiltinSecretProviderOutcome::Found(inspection) = adapter
            .inspect_builtin_secret_provider(InspectBuiltinSecretProvider::new(fixture.actor()))
            .await?
        else {
            return Err("active built-in provider inspection was unavailable".into());
        };
        assert_eq!(inspection.state(), BuiltinSecretProviderState::Active);
        assert_eq!(inspection.health(), BuiltinSecretProviderHealth::Healthy);
        assert_eq!(inspection.revision().value(), 2);
        assert!(inspection.activation().is_none());

        let secret_id = RepositorySecretId::from_uuid(Uuid::new_v4())?;
        let mutation_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        let create = ReserveRepositorySecretVersionMutation::create(
            fixture.actor(),
            mutation_id,
            secret_id,
            RepositoryId::from_uuid(fixture.repository_id),
            RepositorySecretName::new("release_token")?,
            None,
        )?;
        let reservation = adapter
            .reserve_repository_secret_version_mutation(create.clone())
            .await?;
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(reservation) =
            reservation
        else {
            return Err("secret descriptor was not reserved".into());
        };
        assert_eq!(
            reservation.provider_id().as_str(),
            BUILTIN_SECRET_PROVIDER_ID
        );
        assert_eq!(
            reservation.provider_create_request_id(),
            format!("secret-version:{}", mutation_id.as_uuid().hyphenated())
        );
        assert!(reservation.expected_predecessor().is_none());

        let sentinel = b"raw-secret-sentinel-85a57bd10cae4d72";
        let version_id = Uuid::new_v4();
        stage_encrypted_builtin_version(
            database.pool(),
            &fixture,
            secret_id,
            version_id,
            1,
            None,
            1,
            reservation.provider_create_request_id(),
            sentinel,
        )
        .await?;

        let persisted: (Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
            r"
            SELECT ciphertext, nonce, wrapped_data_key
            FROM secret_version_envelopes
            WHERE tenant_id = $1 AND secret_version_id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(version_id)
        .fetch_one(database.pool())
        .await?;
        for bytes in [&persisted.0, &persisted.1, &persisted.2] {
            assert!(!contains(bytes, sentinel));
        }
        let mutation_json: String = sqlx::query_scalar(
            r"
            SELECT row_to_json(mutation)::TEXT
            FROM secret_version_mutations AS mutation
            WHERE tenant_id = $1 AND mutation_id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(mutation_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert!(!mutation_json.contains(std::str::from_utf8(sentinel)?));
        assert!(!mutation_json.contains("ciphertext"));
        assert!(!mutation_json.contains("provider_handle"));

        let ReserveRepositorySecretVersionMutationOutcome::ReconcileRequired(replayed) = adapter
            .reserve_repository_secret_version_mutation(create)
            .await?
        else {
            return Err("crash-after-provider-commit reservation did not replay".into());
        };
        assert_eq!(replayed, reservation);

        let target = BuiltinRepositorySecretVersion::new(
            secret_id,
            RepositorySecretVersionId::from_uuid(version_id)?,
            1,
        )?;
        let confirm = ConfirmRepositorySecretVersionMutation::new(
            fixture.actor(),
            mutation_id,
            RepositorySecretProviderMutationResult::BuiltinCreated(target),
        );
        let confirmation = adapter
            .confirm_repository_secret_version_mutation(confirm.clone())
            .await?;
        let ConfirmRepositorySecretVersionMutationOutcome::Applied(receipt) = confirmation else {
            return Err("encrypted secret version was not confirmed".into());
        };
        assert_eq!(receipt.committed(), target);
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(confirm)
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Applied(receipt),
            "terminal confirmation must replay exactly"
        );
        let altered = BuiltinRepositorySecretVersion::new(
            secret_id,
            RepositorySecretVersionId::from_uuid(Uuid::new_v4())?,
            1,
        )?;
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        mutation_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(altered),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Conflict,
            "altered terminal replay must fail closed"
        );
        let confirmation_audits: i64 = sqlx::query_scalar(
            r"
            SELECT count(*) FROM security_audit_events
            WHERE tenant_id = $1
              AND action = 'secret.version.confirm'
              AND outcome = 'succeeded'
              AND resource_id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(mutation_id.as_uuid().hyphenated().to_string())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            confirmation_audits, 1,
            "application and its exact replay must retain one atomic success audit"
        );
        let durable_confirmation: (String, i64, String, Option<Uuid>, i64) = sqlx::query_as(
            r"
            SELECT mutation.state, mutation.confirmed_secret_revision,
                   lifecycle.status, lifecycle.mutation_id, secret.revision
            FROM secret_version_mutations AS mutation
            JOIN secret_version_lifecycle AS lifecycle
              ON lifecycle.tenant_id = mutation.tenant_id
             AND lifecycle.mutation_id = mutation.mutation_id
            JOIN secrets AS secret
              ON secret.tenant_id = mutation.tenant_id
             AND secret.id = mutation.secret_id
            WHERE mutation.tenant_id = $1 AND mutation.mutation_id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(mutation_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            durable_confirmation,
            (
                "confirmed".into(),
                2,
                "active".into(),
                Some(mutation_id.as_uuid()),
                2,
            )
        );

        let page = adapter
            .list_repository_secrets(ListRepositorySecrets::new(
                fixture.actor(),
                RepositoryId::from_uuid(fixture.repository_id),
                None,
                SecretMetadataPageSize::new(10)?,
            )?)
            .await?;
        let ListRepositorySecretsOutcome::Found(page) = page else {
            return Err("secret metadata list was not authorized".into());
        };
        let [metadata] = page.records() else {
            return Err("confirmed secret metadata was not listed exactly once".into());
        };
        assert_eq!(metadata.current_version_number(), Some(1));
        assert_eq!(metadata.revision().value(), 2);

        let sibling_repository = seed_repository(database.pool(), &fixture.tenant_id).await?;
        assert_eq!(
            adapter
                .delete_repository_secret(DeleteRepositorySecret::new(
                    fixture.actor(),
                    RepositoryId::from_uuid(sibling_repository),
                    secret_id,
                    metadata.revision(),
                )?)
                .await?,
            DeleteRepositorySecretOutcome::NotFound,
            "a sibling repository path must not delete the secret's actual parent",
        );
        let untouched: (String, i64, i64) = sqlx::query_as(
            r"
            SELECT status, revision,
                   (SELECT count(*) FROM secret_cleanup_outbox
                    WHERE tenant_id = $1 AND secret_id = $2)
            FROM secrets
            WHERE tenant_id = $1 AND repository_id = $3 AND id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(secret_id.as_uuid())
        .bind(fixture.repository_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(untouched, ("active".into(), 2, 0));

        let deletion = adapter
            .delete_repository_secret(DeleteRepositorySecret::new(
                fixture.actor(),
                RepositoryId::from_uuid(fixture.repository_id),
                secret_id,
                metadata.revision(),
            )?)
            .await?;
        let DeleteRepositorySecretOutcome::Deleted(receipt) = deletion else {
            return Err("secret was not logically deleted".into());
        };
        assert_eq!(receipt.cleanup_operations(), 1);
        let durable: (String, String, String) = sqlx::query_as(
            r"
            SELECT secret.status, lifecycle.status, outbox.status
            FROM secrets AS secret
            JOIN secret_version_lifecycle AS lifecycle
              ON lifecycle.tenant_id = secret.tenant_id
             AND lifecycle.secret_id = secret.id
            JOIN secret_cleanup_outbox AS outbox
              ON outbox.tenant_id = secret.tenant_id
             AND outbox.secret_version_id = lifecycle.secret_version_id
            WHERE secret.tenant_id = $1 AND secret.id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(secret_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            durable,
            ("deleted".into(), "destroy_pending".into(), "pending".into())
        );

        let claim = adapter
            .claim_builtin_secret_cleanup(ClaimBuiltinSecretCleanup::new(
                SecretCleanupWorkerId::new("cleanup-worker-a")?,
                automata_ci_core::UnixMillis::new(101_000),
                60_000,
            )?)
            .await?;
        let ClaimBuiltinSecretCleanupOutcome::Claimed(task) = claim else {
            return Err("cleanup was not claimed".into());
        };
        assert_eq!(task.secret_id(), secret_id);
        assert_eq!(task.secret_version_id(), version_id);
        assert_eq!(task.attempts(), 1);
        assert_eq!(task.tenant().as_str(), fixture.tenant_id.as_str());

        assert_eq!(
            adapter
                .retry_builtin_secret_cleanup(RetryBuiltinSecretCleanup::new(
                    task.fence().clone(),
                    automata_ci_core::UnixMillis::new(101_100),
                    automata_ci_core::UnixMillis::new(102_000),
                    SecretCleanupFailureKind::Unavailable,
                )?)
                .await?,
            RetryBuiltinSecretCleanupOutcome::RetryScheduled
        );
        assert_eq!(
            adapter
                .complete_builtin_secret_cleanup(CompleteBuiltinSecretCleanup::new(
                    task.fence().clone(),
                    automata_ci_core::UnixMillis::new(102_000),
                )?)
                .await?,
            CompleteBuiltinSecretCleanupOutcome::FenceRejected,
            "a completion from a released claim must not acknowledge later work"
        );
        let claim = adapter
            .claim_builtin_secret_cleanup(ClaimBuiltinSecretCleanup::new(
                SecretCleanupWorkerId::new("cleanup-worker-b")?,
                automata_ci_core::UnixMillis::new(102_000),
                60_000,
            )?)
            .await?;
        let ClaimBuiltinSecretCleanupOutcome::Claimed(task) = claim else {
            return Err("retry cleanup was not claimed".into());
        };
        assert_eq!(task.attempts(), 2);
        assert_eq!(task.tenant().as_str(), fixture.tenant_id.as_str());

        let mut task = task;
        let mut claim_time = 102_000_i64;
        while task.attempts() < automata_ci_store::MAX_SECRET_CLEANUP_ATTEMPTS {
            let failed_at = automata_ci_core::UnixMillis::new(claim_time + 1);
            let retry_at = automata_ci_core::UnixMillis::new(claim_time + 2);
            assert_eq!(
                adapter
                    .retry_builtin_secret_cleanup(RetryBuiltinSecretCleanup::new(
                        task.fence().clone(),
                        failed_at,
                        retry_at,
                        SecretCleanupFailureKind::Unavailable,
                    )?)
                    .await?,
                RetryBuiltinSecretCleanupOutcome::RetryScheduled
            );
            let ClaimBuiltinSecretCleanupOutcome::Claimed(next) = adapter
                .claim_builtin_secret_cleanup(ClaimBuiltinSecretCleanup::new(
                    SecretCleanupWorkerId::new(format!(
                        "cleanup-retry-worker-{}",
                        task.attempts()
                    ))?,
                    retry_at,
                    60_000,
                )?)
                .await?
            else {
                return Err("bounded cleanup retry was not claimable".into());
            };
            assert_eq!(next.attempts(), task.attempts() + 1);
            assert!(next.fence().claim_generation() > task.fence().claim_generation());
            task = next;
            claim_time = retry_at.get();
        }
        let stale_final_fence = task.fence().clone();
        let takeover_at = automata_ci_core::UnixMillis::new(claim_time + 500);
        let reclaim = adapter
            .claim_builtin_secret_cleanup(ClaimBuiltinSecretCleanup::new(
                SecretCleanupWorkerId::new("cleanup-worker-c")?,
                takeover_at,
                500,
            )?)
            .await?;
        let ClaimBuiltinSecretCleanupOutcome::Claimed(task) = reclaim else {
            return Err("stale final cleanup attempt was dead-lettered before replay".into());
        };
        assert_eq!(
            task.attempts(),
            automata_ci_store::MAX_SECRET_CLEANUP_ATTEMPTS,
            "reclaiming a crashed attempt must replay rather than spend a new attempt"
        );
        assert_eq!(
            task.fence().claim_generation(),
            stale_final_fence.claim_generation() + 1
        );
        assert_eq!(
            adapter
                .complete_builtin_secret_cleanup(CompleteBuiltinSecretCleanup::new(
                    stale_final_fence,
                    takeover_at,
                )?)
                .await?,
            CompleteBuiltinSecretCleanupOutcome::FenceRejected,
        );
        assert_eq!(task.tenant().as_str(), fixture.tenant_id.as_str());

        let erased_at = takeover_at.get() + 1;
        simulate_builtin_cryptographic_erasure(
            database.pool(),
            &fixture.tenant_id,
            version_id,
            erased_at,
        )
        .await?;
        assert_eq!(
            adapter
                .complete_builtin_secret_cleanup(CompleteBuiltinSecretCleanup::new(
                    task.fence().clone(),
                    automata_ci_core::UnixMillis::new(erased_at),
                )?)
                .await?,
            CompleteBuiltinSecretCleanupOutcome::Completed
        );
        let outbox_status: String =
            sqlx::query_scalar("SELECT status FROM secret_cleanup_outbox WHERE operation_id = $1")
                .bind(task.fence().operation_id())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(outbox_status, "completed");

        let audit_text: Vec<String> = sqlx::query_scalar(
            r"
            SELECT concat_ws('|', action, outcome, resource_kind,
                             COALESCE(resource_id, ''), COALESCE(request_id, ''))
            FROM security_audit_events
            WHERE tenant_id = $1 AND action LIKE 'secret%'
            ORDER BY sequence
            ",
        )
        .bind(&fixture.tenant_id)
        .fetch_all(database.pool())
        .await?;
        assert!(audit_text.len() >= 6);
        for event in audit_text {
            assert!(!event.contains(std::str::from_utf8(sentinel)?));
            assert!(!event.contains("RELEASE_TOKEN"));
            assert!(!event.contains(&version_id.to_string()));
            assert!(!event.contains("locator"));
            assert!(!event.contains("handle"));
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn replacement_mutations_bind_replay_predecessor_cas_and_fresh_authority() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(database.pool(), "7002", true).await?;
        let adapter = PostgresSecretManagementRepository::new(database.pool().clone());
        let activation = adapter
            .activate_builtin_secret_provider(ActivateBuiltinSecretProvider::new(
                fixture.actor(),
                ManagementRevision::new(1)?,
            ))
            .await?;
        assert!(matches!(
            activation,
            ActivateBuiltinSecretProviderOutcome::Activated(_)
        ));

        sqlx::query(
            r"
            INSERT INTO secret_providers (
                tenant_id, provider_id, adapter_kind, display_name,
                supports_create_version, supports_destroy_version,
                supports_dynamic_leases, supports_renew_leases,
                supports_revoke_leases, is_default, status, health,
                revision, created_by_principal_id, created_at_ms, updated_at_ms
            ) VALUES (
                $1, 'vault.test', 'external_vault', 'External encrypted vault',
                TRUE, TRUE, FALSE, FALSE, FALSE, FALSE, 'active', 'healthy',
                1, $2, 1, 1
            )
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(fixture.principal_id)
        .execute(database.pool())
        .await?;
        let external_secret = RepositorySecretId::from_uuid(Uuid::new_v4())?;
        let external_mutation =
            RepositorySecretMutationId::from_uuid(Uuid::new_v4(), external_secret)?;
        assert_eq!(
            adapter
                .reserve_repository_secret_version_mutation(
                    ReserveRepositorySecretVersionMutation::create(
                        fixture.actor(),
                        external_mutation,
                        external_secret,
                        RepositoryId::from_uuid(fixture.repository_id),
                        RepositorySecretName::new("external_token")?,
                        Some(ManagedSecretProviderId::new("vault.test")?),
                    )?,
                )
                .await?,
            ReserveRepositorySecretVersionMutationOutcome::ProviderUnavailable,
            "external handles must remain unavailable until a custodian is composed"
        );
        let external_rows: i64 = sqlx::query_scalar(
            r"
            SELECT
                (SELECT count(*) FROM secrets WHERE tenant_id = $1 AND id = $2)
              + (SELECT count(*) FROM secret_version_mutations
                 WHERE tenant_id = $1 AND mutation_id = $3)
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(external_secret.as_uuid())
        .bind(external_mutation.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(external_rows, 0);

        let secret_id = RepositorySecretId::from_uuid(Uuid::new_v4())?;
        let create_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        let create = ReserveRepositorySecretVersionMutation::create(
            fixture.actor(),
            create_id,
            secret_id,
            RepositoryId::from_uuid(fixture.repository_id),
            RepositorySecretName::new("rotation_token")?,
            None,
        )?;
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(create) = adapter
            .reserve_repository_secret_version_mutation(create)
            .await?
        else {
            return Err("initial create was not reserved".into());
        };
        let version_one = Uuid::new_v4();
        stage_encrypted_builtin_version(
            database.pool(),
            &fixture,
            secret_id,
            version_one,
            1,
            None,
            1,
            create.provider_create_request_id(),
            b"rotation-value-one",
        )
        .await?;
        let target_one = BuiltinRepositorySecretVersion::new(
            secret_id,
            RepositorySecretVersionId::from_uuid(version_one)?,
            1,
        )?;
        assert!(matches!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        create_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(target_one),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Applied(_)
        ));

        let stale_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        assert_eq!(
            adapter
                .reserve_repository_secret_version_mutation(
                    ReserveRepositorySecretVersionMutation::replace(
                        fixture.actor(),
                        stale_id,
                        secret_id,
                        RepositoryId::from_uuid(fixture.repository_id),
                        RepositorySecretName::new("rotation_token")?,
                        ManagementRevision::new(1)?,
                    )?,
                )
                .await?,
            ReserveRepositorySecretVersionMutationOutcome::RevisionConflict {
                current: ManagementRevision::new(2)?,
            }
        );

        let first_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        let second_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        let replacement = |mutation_id| {
            ReserveRepositorySecretVersionMutation::replace(
                fixture.actor(),
                mutation_id,
                secret_id,
                RepositoryId::from_uuid(fixture.repository_id),
                RepositorySecretName::new("rotation_token").expect("name"),
                ManagementRevision::new(2).expect("revision"),
            )
            .expect("replacement request")
        };
        let (first_result, second_result) = tokio::join!(
            adapter.reserve_repository_secret_version_mutation(replacement(first_id)),
            adapter.reserve_repository_secret_version_mutation(replacement(second_id)),
        );
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(first) = first_result? else {
            return Err("first replacement was not reserved".into());
        };
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(second) = second_result? else {
            return Err("concurrent replacement was not reserved".into());
        };
        assert_eq!(first.expected_predecessor(), Some(target_one));
        assert_eq!(second.expected_predecessor(), Some(target_one));
        let mut concurrent_ordinals = [
            first.reserved_version_number(),
            second.reserved_version_number(),
        ];
        concurrent_ordinals.sort_unstable();
        assert_eq!(concurrent_ordinals, [2, 3]);

        let independent_secret = RepositorySecretId::from_uuid(Uuid::new_v4())?;
        let independent_create_id =
            RepositorySecretMutationId::from_uuid(Uuid::new_v4(), independent_secret)?;
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(independent_create) = adapter
            .reserve_repository_secret_version_mutation(
                ReserveRepositorySecretVersionMutation::create(
                    fixture.actor(),
                    independent_create_id,
                    independent_secret,
                    RepositoryId::from_uuid(fixture.repository_id),
                    RepositorySecretName::new("independent_rotation_token")?,
                    None,
                )?,
            )
            .await?
        else {
            return Err("independent create was not reserved".into());
        };
        let independent_version = Uuid::new_v4();
        stage_encrypted_builtin_version(
            database.pool(),
            &fixture,
            independent_secret,
            independent_version,
            1,
            None,
            1,
            independent_create.provider_create_request_id(),
            b"independent-rotation-value-one",
        )
        .await?;
        let independent_target = BuiltinRepositorySecretVersion::new(
            independent_secret,
            RepositorySecretVersionId::from_uuid(independent_version)?,
            1,
        )?;
        assert!(matches!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        independent_create_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(independent_target),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Applied(_)
        ));
        let independent_replace_id =
            RepositorySecretMutationId::from_uuid(Uuid::new_v4(), independent_secret)?;
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(independent_replace) = adapter
            .reserve_repository_secret_version_mutation(
                ReserveRepositorySecretVersionMutation::replace(
                    fixture.actor(),
                    independent_replace_id,
                    independent_secret,
                    RepositoryId::from_uuid(fixture.repository_id),
                    RepositorySecretName::new("independent_rotation_token")?,
                    ManagementRevision::new(2)?,
                )?,
            )
            .await?
        else {
            return Err("independent replacement was not reserved".into());
        };
        assert_eq!(
            independent_replace.reserved_version_number(),
            2,
            "reservation ordinals must not disclose activity from another logical secret"
        );

        let altered_replay = ReserveRepositorySecretVersionMutation::replace(
            fixture.actor(),
            first_id,
            secret_id,
            RepositoryId::from_uuid(fixture.repository_id),
            RepositorySecretName::new("different_token")?,
            ManagementRevision::new(2)?,
        )?;
        assert_eq!(
            adapter
                .reserve_repository_secret_version_mutation(altered_replay)
                .await?,
            ReserveRepositorySecretVersionMutationOutcome::Conflict
        );

        let version_two = Uuid::new_v4();
        stage_encrypted_builtin_version(
            database.pool(),
            &fixture,
            secret_id,
            version_two,
            i64::try_from(first.reserved_version_number())?,
            Some(version_one),
            2,
            first.provider_create_request_id(),
            b"rotation-value-two",
        )
        .await?;
        let target_two = BuiltinRepositorySecretVersion::new(
            secret_id,
            RepositorySecretVersionId::from_uuid(version_two)?,
            first.reserved_version_number(),
        )?;
        assert!(matches!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        first_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(target_two),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Applied(_)
        ));
        let cas_lost = ConfirmRepositorySecretVersionMutation::new(
            fixture.actor(),
            second_id,
            RepositorySecretProviderMutationResult::CasLost,
        );
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(cas_lost.clone())
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::CasLost
        );
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(cas_lost)
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::CasLost,
            "CAS-lost terminal replay must stay distinct from deletion cancellation"
        );

        let third_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(third) = adapter
            .reserve_repository_secret_version_mutation(
                ReserveRepositorySecretVersionMutation::replace(
                    fixture.actor(),
                    third_id,
                    secret_id,
                    RepositoryId::from_uuid(fixture.repository_id),
                    RepositorySecretName::new("rotation_token")?,
                    ManagementRevision::new(3)?,
                )?,
            )
            .await?
        else {
            return Err("third replacement was not reserved".into());
        };
        assert_eq!(third.expected_predecessor(), Some(target_two));
        assert_eq!(third.reserved_version_number(), 4);
        let version_three = Uuid::new_v4();
        stage_encrypted_builtin_version(
            database.pool(),
            &fixture,
            secret_id,
            version_three,
            i64::try_from(third.reserved_version_number())?,
            Some(version_two),
            3,
            third.provider_create_request_id(),
            b"rotation-value-three",
        )
        .await?;
        let target_three = BuiltinRepositorySecretVersion::new(
            secret_id,
            RepositorySecretVersionId::from_uuid(version_three)?,
            third.reserved_version_number(),
        )?;

        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        first_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(target_three),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Conflict,
            "a winner from another request must not confirm this mutation"
        );
        let third_confirmation = adapter
            .confirm_repository_secret_version_mutation(
                ConfirmRepositorySecretVersionMutation::new(
                    fixture.actor(),
                    third_id,
                    RepositorySecretProviderMutationResult::BuiltinCreated(target_three),
                ),
            )
            .await?;
        assert!(matches!(
            third_confirmation,
            ConfirmRepositorySecretVersionMutationOutcome::Applied(_)
        ));
        let first_confirmation = adapter
            .confirm_repository_secret_version_mutation(
                ConfirmRepositorySecretVersionMutation::new(
                    fixture.actor(),
                    first_id,
                    RepositorySecretProviderMutationResult::BuiltinCreated(target_two),
                ),
            )
            .await?;
        assert!(matches!(
            first_confirmation,
            ConfirmRepositorySecretVersionMutationOutcome::AppliedThenSuperseded(_)
        ));
        let receipt_chain: (String, i64, String, i64) = sqlx::query_as(
            r"
            SELECT predecessor.state, predecessor.confirmed_secret_revision,
                   current.state, secret.revision
            FROM secret_version_mutations AS predecessor
            JOIN secret_version_mutations AS current
              ON current.tenant_id = predecessor.tenant_id
             AND current.mutation_id = $3
            JOIN secrets AS secret
              ON secret.tenant_id = predecessor.tenant_id
             AND secret.id = predecessor.secret_id
            WHERE predecessor.tenant_id = $1
              AND predecessor.mutation_id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(first_id.as_uuid())
        .bind(third_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            receipt_chain,
            ("superseded".into(), 3, "confirmed".into(), 4),
            "replacement atomically terminalizes its predecessor without rewriting the applied revision"
        );
        assert!(matches!(
            adapter
                .reserve_repository_secret_version_mutation(
                    ReserveRepositorySecretVersionMutation::replace(
                        fixture.actor(),
                        third_id,
                        secret_id,
                        RepositoryId::from_uuid(fixture.repository_id),
                        RepositorySecretName::new("rotation_token")?,
                        ManagementRevision::new(3)?,
                    )?,
                )
                .await?,
            ReserveRepositorySecretVersionMutationOutcome::Applied(_)
        ));

        let fourth_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(fourth) = adapter
            .reserve_repository_secret_version_mutation(
                ReserveRepositorySecretVersionMutation::replace(
                    fixture.actor(),
                    fourth_id,
                    secret_id,
                    RepositoryId::from_uuid(fixture.repository_id),
                    RepositorySecretName::new("rotation_token")?,
                    ManagementRevision::new(4)?,
                )?,
            )
            .await?
        else {
            return Err("fourth replacement was not reserved".into());
        };
        assert_eq!(fourth.reserved_version_number(), 5);
        let version_four = Uuid::new_v4();
        stage_encrypted_builtin_version(
            database.pool(),
            &fixture,
            secret_id,
            version_four,
            i64::try_from(fourth.reserved_version_number())?,
            Some(version_three),
            4,
            fourth.provider_create_request_id(),
            b"rotation-value-four",
        )
        .await?;
        assert!(matches!(
            adapter
                .reserve_repository_secret_version_mutation(
                    ReserveRepositorySecretVersionMutation::replace(
                        fixture.actor(),
                        third_id,
                        secret_id,
                        RepositoryId::from_uuid(fixture.repository_id),
                        RepositorySecretName::new("rotation_token")?,
                        ManagementRevision::new(3)?,
                    )?,
                )
                .await?,
            ReserveRepositorySecretVersionMutationOutcome::Applied(_)
        ));
        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET authorization_revision = authorization_revision + 1,
                updated_at_ms = updated_at_ms + 1
            WHERE tenant_id = $1 AND principal_id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(fixture.principal_id)
        .execute(database.pool())
        .await?;
        let target_four = BuiltinRepositorySecretVersion::new(
            secret_id,
            RepositorySecretVersionId::from_uuid(version_four)?,
            fourth.reserved_version_number(),
        )?;
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        fourth_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(target_four),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::SessionStale,
            "confirmation must freshly reauthorize after the provider call"
        );

        let mutation_columns: Vec<String> = sqlx::query_scalar(
            r"
            SELECT column_name FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'secret_version_mutations'
            ORDER BY ordinal_position
            ",
        )
        .fetch_all(database.pool())
        .await?;
        let columns = mutation_columns.join("|");
        for prohibited in ["value", "ciphertext", "handle", "locator", "plaintext"] {
            assert!(!columns.contains(prohibited));
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn concurrent_reservation_waiter_observes_preceding_committed_ordinal() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(database.pool(), "7011", true).await?;
        let adapter = PostgresSecretManagementRepository::new(database.pool().clone());
        assert!(matches!(
            adapter
                .activate_builtin_secret_provider(ActivateBuiltinSecretProvider::new(
                    fixture.actor(),
                    ManagementRevision::new(1)?,
                ))
                .await?,
            ActivateBuiltinSecretProviderOutcome::Activated(_)
        ));

        let secret_id = RepositorySecretId::from_uuid(Uuid::new_v4())?;
        let create_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(create) = adapter
            .reserve_repository_secret_version_mutation(
                ReserveRepositorySecretVersionMutation::create(
                    fixture.actor(),
                    create_id,
                    secret_id,
                    RepositoryId::from_uuid(fixture.repository_id),
                    RepositorySecretName::new("reservation_race_token")?,
                    None,
                )?,
            )
            .await?
        else {
            return Err("concurrency fixture creation was not reserved".into());
        };
        let version_one = Uuid::new_v4();
        stage_encrypted_builtin_version(
            database.pool(),
            &fixture,
            secret_id,
            version_one,
            1,
            None,
            1,
            create.provider_create_request_id(),
            b"reservation-race-value-one",
        )
        .await?;
        let target_one = BuiltinRepositorySecretVersion::new(
            secret_id,
            RepositorySecretVersionId::from_uuid(version_one)?,
            1,
        )?;
        assert!(matches!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        create_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(target_one),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Applied(_)
        ));

        let first_mutation_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        let second_mutation_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        let replacement = |mutation_id| {
            ReserveRepositorySecretVersionMutation::replace(
                fixture.actor(),
                mutation_id,
                secret_id,
                RepositoryId::from_uuid(fixture.repository_id),
                RepositorySecretName::new("reservation_race_token").expect("name"),
                ManagementRevision::new(2).expect("revision"),
            )
            .expect("replacement request")
        };
        let first_request = replacement(first_mutation_id);
        let second_request = replacement(second_mutation_id);

        let mut blocker = database.pool().begin().await?;
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        let locked_repository: Uuid = sqlx::query_scalar(
            "SELECT id FROM repositories WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(&fixture.tenant_id)
        .bind(fixture.repository_id)
        .fetch_one(&mut *blocker)
        .await?;
        assert_eq!(locked_repository, fixture.repository_id);

        let first_adapter = adapter.clone();
        let mut first_task = tokio::spawn(async move {
            first_adapter
                .reserve_repository_secret_version_mutation(first_request)
                .await
        });
        let first_backend_pid = match wait_for_backend_blocked_by(
            database.pool(),
            blocker_pid,
            "SELECT id FROM repositories",
        )
        .await
        {
            Ok(backend_pid) => backend_pid,
            Err(error) => {
                blocker.rollback().await?;
                first_task.abort();
                let _ = first_task.await;
                return Err(error);
            }
        };

        let second_adapter = adapter.clone();
        let mut second_task = tokio::spawn(async move {
            second_adapter
                .reserve_repository_secret_version_mutation(second_request)
                .await
        });
        let second_backend_pid = match wait_for_backend_blocked_by(
            database.pool(),
            first_backend_pid,
            "FROM human_sessions AS session",
        )
        .await
        {
            Ok(backend_pid) => backend_pid,
            Err(error) => {
                blocker.rollback().await?;
                first_task.abort();
                second_task.abort();
                let _ = tokio::join!(first_task, second_task);
                return Err(error);
            }
        };
        assert_ne!(second_backend_pid, first_backend_pid);
        blocker.commit().await?;

        let completions = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(&mut first_task, &mut second_task)
        })
        .await;
        let Ok((first_result, second_result)) = completions else {
            first_task.abort();
            second_task.abort();
            let _ = tokio::join!(first_task, second_task);
            return Err("timed out waiting for serialized reservations".into());
        };
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(first) = first_result??
        else {
            return Err("first serialized replacement was not reserved".into());
        };
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(second) =
            second_result??
        else {
            return Err("waiting serialized replacement was not reserved".into());
        };
        assert_eq!(first.expected_predecessor(), Some(target_one));
        assert_eq!(second.expected_predecessor(), Some(target_one));
        assert_eq!(first.reserved_version_number(), 2);
        assert_eq!(second.reserved_version_number(), 3);

        assert_eq!(
            adapter
                .reserve_repository_secret_version_mutation(replacement(first_mutation_id))
                .await?,
            ReserveRepositorySecretVersionMutationOutcome::ReconcileRequired(first.clone()),
            "exact replay must return the committed reservation without allocating a gap"
        );
        assert_eq!(
            adapter
                .reserve_repository_secret_version_mutation(replacement(second_mutation_id))
                .await?,
            ReserveRepositorySecretVersionMutationOutcome::ReconcileRequired(second),
            "the waiting reservation must retain its exact committed ordinal on replay"
        );
        let ordinals: Vec<i64> = sqlx::query_scalar(
            r"
            SELECT reserved_version_number
            FROM secret_version_mutations
            WHERE tenant_id = $1 AND secret_id = $2
            ORDER BY reserved_version_number
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(secret_id.as_uuid())
        .fetch_all(database.pool())
        .await?;
        assert_eq!(ordinals, [1, 2, 3]);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines, clippy::type_complexity)]
async fn expired_staged_replacement_is_generation_fenced_erased_and_gap_safe() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(database.pool(), "7010", true).await?;
        let adapter = PostgresSecretManagementRepository::new(database.pool().clone());
        assert!(matches!(
            adapter
                .activate_builtin_secret_provider(ActivateBuiltinSecretProvider::new(
                    fixture.actor(),
                    ManagementRevision::new(1)?,
                ))
                .await?,
            ActivateBuiltinSecretProviderOutcome::Activated(_)
        ));

        let secret_id = RepositorySecretId::from_uuid(Uuid::new_v4())?;
        let create_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(create) = adapter
            .reserve_repository_secret_version_mutation(
                ReserveRepositorySecretVersionMutation::create(
                    fixture.actor(),
                    create_id,
                    secret_id,
                    RepositoryId::from_uuid(fixture.repository_id),
                    RepositorySecretName::new("recovery_token")?,
                    None,
                )?,
            )
            .await?
        else {
            return Err("recovery fixture creation was not reserved".into());
        };
        let version_one = Uuid::new_v4();
        stage_encrypted_builtin_version(
            database.pool(),
            &fixture,
            secret_id,
            version_one,
            1,
            None,
            1,
            create.provider_create_request_id(),
            b"recovery-value-one",
        )
        .await?;
        let target_one = BuiltinRepositorySecretVersion::new(
            secret_id,
            RepositorySecretVersionId::from_uuid(version_one)?,
            1,
        )?;
        assert!(matches!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        create_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(target_one),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Applied(_)
        ));

        let abandoned_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(abandoned) = adapter
            .reserve_repository_secret_version_mutation(
                ReserveRepositorySecretVersionMutation::replace(
                    fixture.actor(),
                    abandoned_id,
                    secret_id,
                    RepositoryId::from_uuid(fixture.repository_id),
                    RepositorySecretName::new("recovery_token")?,
                    ManagementRevision::new(2)?,
                )?,
            )
            .await?
        else {
            return Err("abandoned replacement was not reserved".into());
        };
        assert_eq!(abandoned.reserved_version_number(), 2);
        assert_eq!(abandoned.confirmation_deadline(), UnixMillis::new(700_000));
        let abandoned_version = Uuid::new_v4();
        stage_encrypted_builtin_version(
            database.pool(),
            &fixture,
            secret_id,
            abandoned_version,
            i64::try_from(abandoned.reserved_version_number())?,
            Some(version_one),
            2,
            abandoned.provider_create_request_id(),
            b"abandoned-recovery-value",
        )
        .await?;
        let abandoned_target = BuiltinRepositorySecretVersion::new(
            secret_id,
            RepositorySecretVersionId::from_uuid(abandoned_version)?,
            abandoned.reserved_version_number(),
        )?;
        let abandoned_replay = |actor| {
            ReserveRepositorySecretVersionMutation::replace(
                actor,
                abandoned_id,
                secret_id,
                RepositoryId::from_uuid(fixture.repository_id),
                RepositorySecretName::new("recovery_token").expect("name"),
                ManagementRevision::new(2).expect("revision"),
            )
            .expect("replacement replay")
        };
        assert_eq!(
            adapter
                .reserve_repository_secret_version_mutation(
                    abandoned_replay(fixture.actor_at(699),)
                )
                .await?,
            ReserveRepositorySecretVersionMutationOutcome::ReconcileRequired(abandoned.clone()),
            "the live reservation remains reconciliation-only before its persisted deadline"
        );
        assert_eq!(
            adapter
                .reserve_repository_secret_version_mutation(
                    abandoned_replay(fixture.actor_at(700),)
                )
                .await?,
            ReserveRepositorySecretVersionMutationOutcome::Expired,
            "exact deadline replay must stop before provider handoff"
        );
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor_at(700),
                        abandoned_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(abandoned_target),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Expired,
            "deadline confirmation must reconcile the exact staged receipt without promotion"
        );
        let mismatched_expired_target = BuiltinRepositorySecretVersion::new(
            secret_id,
            RepositorySecretVersionId::from_uuid(Uuid::new_v4())?,
            abandoned.reserved_version_number(),
        )?;
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor_at(700),
                        abandoned_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(
                            mismatched_expired_target,
                        ),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Conflict,
            "deadline confirmation must not mask a mismatched provider receipt"
        );

        let recovery_delete = sqlx::query(
            "DELETE FROM secret_mutation_recovery_outbox WHERE tenant_id = $1 AND mutation_id = $2",
        )
        .bind(&fixture.tenant_id)
        .bind(abandoned_id.as_uuid())
        .execute(database.pool())
        .await
        .expect_err("durable recovery receipt deletion must fail");
        assert_sql_constraint(
            &recovery_delete,
            "secret_mutation_recovery_delete_forbidden",
        );
        let recovery_truncate = sqlx::query("TRUNCATE secret_mutation_recovery_outbox")
            .execute(database.pool())
            .await
            .expect_err("durable recovery receipt truncation must fail");
        assert_sql_constraint(
            &recovery_truncate,
            "secret_mutation_recovery_delete_forbidden",
        );
        let recovery_identity = sqlx::query(
            r"
            UPDATE secret_mutation_recovery_outbox
            SET operation_id = $3
            WHERE tenant_id = $1 AND mutation_id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(abandoned_id.as_uuid())
        .bind(Uuid::new_v4())
        .execute(database.pool())
        .await
        .expect_err("recovery identity mutation must fail");
        assert_sql_constraint(
            &recovery_identity,
            "secret_mutation_recovery_identity_immutable",
        );
        let recovery_generation_jump = sqlx::query(
            r"
            UPDATE secret_mutation_recovery_outbox
            SET status = 'in_progress', attempts = 1, claim_generation = 2,
                locked_by = 'direct-writer', locked_at_ms = next_attempt_at_ms
            WHERE tenant_id = $1 AND mutation_id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(abandoned_id.as_uuid())
        .execute(database.pool())
        .await
        .expect_err("recovery generation jump must fail");
        assert_sql_constraint(
            &recovery_generation_jump,
            "secret_mutation_recovery_claim_exact",
        );

        let worker_a = SecretCleanupWorkerId::new("recovery-worker-a")?;
        let ClaimSecretMutationRecoveryOutcome::Claimed(first_claim) = adapter
            .claim_secret_mutation_recovery(ClaimSecretMutationRecovery::new(
                worker_a,
                UnixMillis::new(700_000),
                1_000,
            )?)
            .await?
        else {
            return Err("due mutation recovery was not claimed".into());
        };
        assert_eq!(first_claim.fence().claim_generation(), 1);
        assert_eq!(
            first_claim.provider_id().as_str(),
            BUILTIN_SECRET_PROVIDER_ID
        );
        assert_eq!(first_claim.repository_id().as_uuid(), fixture.repository_id);
        assert_eq!(first_claim.name().as_str(), "RECOVERY_TOKEN");
        assert_eq!(
            first_claim.provider_create_request_id(),
            format!("secret-version:{}", abandoned_id.as_uuid().hyphenated())
        );
        assert_eq!(first_claim.expected_predecessor(), Some(target_one));
        assert_eq!(
            first_claim.reserved_version_number(),
            abandoned_target.version_number()
        );
        assert_eq!(
            adapter
                .claim_secret_mutation_recovery(ClaimSecretMutationRecovery::new(
                    SecretCleanupWorkerId::new("recovery-worker-b")?,
                    UnixMillis::new(700_999),
                    1_000,
                )?)
                .await?,
            ClaimSecretMutationRecoveryOutcome::NoWork
        );
        let mut takeover = first_claim;
        for takeover_number in 1..=101_i64 {
            let takeover_at = UnixMillis::new(700_000 + takeover_number * 1_000);
            let previous_fence = takeover.fence().clone();
            let ClaimSecretMutationRecoveryOutcome::Claimed(next_takeover) = adapter
                .claim_secret_mutation_recovery(ClaimSecretMutationRecovery::new(
                    SecretCleanupWorkerId::new(format!("recovery-worker-{takeover_number}"))?,
                    takeover_at,
                    1_000,
                )?)
                .await?
            else {
                return Err(format!("stale recovery takeover {takeover_number} failed").into());
            };
            assert_eq!(
                next_takeover.fence().claim_generation(),
                previous_fence.claim_generation() + 1,
                "every takeover must advance the ownership generation exactly once"
            );
            assert!(next_takeover.fence().locked_at() > previous_fence.locked_at());
            assert_eq!(
                adapter
                    .recover_secret_mutation_reservation(RecoverSecretMutationReservation::new(
                        previous_fence,
                        takeover_at,
                        SecretMutationRecoveryReconciliation::AlreadyCommitted(abandoned_target),
                    )?,)
                    .await?,
                RecoverSecretMutationReservationOutcome::FenceRejected,
                "an older replica must never complete after takeover {takeover_number}"
            );
            takeover = next_takeover;
        }
        let recovered_at = UnixMillis::new(801_000);
        assert_eq!(
            adapter
                .recover_secret_mutation_reservation(RecoverSecretMutationReservation::new(
                    takeover.fence().clone(),
                    recovered_at,
                    SecretMutationRecoveryReconciliation::DefinitivelyNotCommitted,
                )?)
                .await
                .expect_err("a staged winner cannot reconcile as definitively absent"),
            automata_ci_store::SecretManagementRepositoryError::CorruptData
        );
        assert_eq!(
            adapter
                .recover_secret_mutation_reservation(RecoverSecretMutationReservation::new(
                    takeover.fence().clone(),
                    recovered_at,
                    SecretMutationRecoveryReconciliation::AlreadyCommitted(
                        mismatched_expired_target,
                    ),
                )?)
                .await
                .expect_err("reconciliation must bind the exact staged winner"),
            automata_ci_store::SecretManagementRepositoryError::CorruptData
        );
        let takeover_request = RecoverSecretMutationReservation::new(
            takeover.fence().clone(),
            recovered_at,
            SecretMutationRecoveryReconciliation::AlreadyCommitted(abandoned_target),
        )?;
        assert_eq!(
            adapter
                .recover_secret_mutation_reservation(takeover_request.clone())
                .await?,
            RecoverSecretMutationReservationOutcome::ExpiredWithCleanup
        );
        assert_eq!(
            adapter
                .recover_secret_mutation_reservation(takeover_request)
                .await?,
            RecoverSecretMutationReservationOutcome::ExpiredWithCleanup,
            "the exact terminal recovery receipt must replay"
        );
        assert_eq!(
            adapter
                .recover_secret_mutation_reservation(RecoverSecretMutationReservation::new(
                    takeover.fence().clone(),
                    recovered_at,
                    SecretMutationRecoveryReconciliation::DefinitivelyNotCommitted,
                )?)
                .await?,
            RecoverSecretMutationReservationOutcome::FenceRejected,
            "terminal replay must retain the exact provider reconciliation evidence"
        );
        let abandoned_lifecycle: String = sqlx::query_scalar(
            r"
            SELECT status FROM secret_version_lifecycle
            WHERE tenant_id = $1 AND secret_version_id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(abandoned_version)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(abandoned_lifecycle, "destroy_pending");
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor_at(700),
                        abandoned_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(abandoned_target),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Expired,
            "terminal staged expiry must replay only its exact abandoned winner"
        );
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor_at(700),
                        abandoned_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(
                            mismatched_expired_target,
                        ),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Conflict
        );
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor_at(700),
                        abandoned_id,
                        RepositorySecretProviderMutationResult::CasLost,
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Conflict
        );
        let altered_generation = SecretMutationRecoveryFence::new(
            takeover.fence().operation_id(),
            takeover.fence().worker_id().clone(),
            takeover.fence().claim_generation() + 1,
            takeover.fence().locked_at(),
        )?;
        assert_eq!(
            adapter
                .recover_secret_mutation_reservation(RecoverSecretMutationReservation::new(
                    altered_generation,
                    recovered_at,
                    SecretMutationRecoveryReconciliation::AlreadyCommitted(abandoned_target),
                )?)
                .await?,
            RecoverSecretMutationReservationOutcome::FenceRejected,
            "terminal replay must match the completed claim generation exactly"
        );
        assert_eq!(
            adapter
                .recover_secret_mutation_reservation(RecoverSecretMutationReservation::new(
                    takeover.fence().clone(),
                    UnixMillis::new(recovered_at.get() + 1),
                    SecretMutationRecoveryReconciliation::AlreadyCommitted(abandoned_target),
                )?)
                .await?,
            RecoverSecretMutationReservationOutcome::FenceRejected,
            "terminal replay must match the completed observation exactly"
        );

        let durable: (
            String,
            Uuid,
            i64,
            String,
            String,
            String,
            i64,
            Option<i64>,
            Option<String>,
            Option<i64>,
        ) = sqlx::query_as(
            r"
            SELECT secret.status, secret.current_version_id,
                   secret.current_version_number, mutation.state,
                   mutation.completion_kind, mutation.expiration_authority,
                   recovery.claim_generation, recovery.completed_claim_generation,
                   recovery.completed_by, recovery.completed_locked_at_ms
            FROM secrets AS secret
            JOIN secret_version_mutations AS mutation
              ON mutation.tenant_id = secret.tenant_id
             AND mutation.secret_id = secret.id
            JOIN secret_mutation_recovery_outbox AS recovery
              ON recovery.tenant_id = mutation.tenant_id
             AND recovery.mutation_id = mutation.mutation_id
            WHERE mutation.tenant_id = $1 AND mutation.mutation_id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(abandoned_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            durable,
            (
                "active".into(),
                version_one,
                1,
                "cancelled".into(),
                "reservation_expired".into(),
                "lost".into(),
                i64::try_from(takeover.fence().claim_generation())?,
                Some(i64::try_from(takeover.fence().claim_generation())?),
                Some(takeover.fence().worker_id().as_str().into()),
                Some(recovered_at.get()),
            )
        );
        let audit: (
            String,
            Option<Uuid>,
            Option<Uuid>,
            Option<i64>,
            String,
            String,
        ) = sqlx::query_as(
            r"
                SELECT actor_kind, actor_principal_id, actor_session_id,
                       authorization_revision, action, resource_id
                FROM security_audit_events
                WHERE tenant_id = $1 AND action = 'secret.version.expire'
                ",
        )
        .bind(&fixture.tenant_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            audit,
            (
                "system".into(),
                None,
                None,
                None,
                "secret.version.expire".into(),
                abandoned_id.as_uuid().hyphenated().to_string(),
            )
        );

        let no_stage_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        let no_stage_request = |actor| {
            ReserveRepositorySecretVersionMutation::replace(
                actor,
                no_stage_id,
                secret_id,
                RepositoryId::from_uuid(fixture.repository_id),
                RepositorySecretName::new("recovery_token").expect("name"),
                ManagementRevision::new(2).expect("revision"),
            )
            .expect("no-stage replacement")
        };
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(no_stage) = adapter
            .reserve_repository_secret_version_mutation(no_stage_request(fixture.actor()))
            .await?
        else {
            return Err("no-stage replacement was not reserved".into());
        };
        assert_eq!(no_stage.reserved_version_number(), 3);
        assert_eq!(
            adapter
                .reserve_repository_secret_version_mutation(
                    no_stage_request(fixture.actor_at(700),)
                )
                .await?,
            ReserveRepositorySecretVersionMutationOutcome::Expired
        );
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor_at(700),
                        no_stage_id,
                        RepositorySecretProviderMutationResult::CasLost,
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Expired,
            "late no-stage CAS loss proves that no provider winner exists"
        );
        let fabricated_no_stage_target = BuiltinRepositorySecretVersion::new(
            secret_id,
            RepositorySecretVersionId::from_uuid(Uuid::new_v4())?,
            no_stage.reserved_version_number(),
        )?;
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor_at(700),
                        no_stage_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(
                            fabricated_no_stage_target,
                        ),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Conflict
        );
        let no_stage_recovered_at = UnixMillis::new(recovered_at.get() + 1);
        let ClaimSecretMutationRecoveryOutcome::Claimed(no_stage_recovery) = adapter
            .claim_secret_mutation_recovery(ClaimSecretMutationRecovery::new(
                SecretCleanupWorkerId::new("no-stage-recovery-worker")?,
                no_stage_recovered_at,
                1_000,
            )?)
            .await?
        else {
            return Err("no-stage recovery was not claimable".into());
        };
        assert_eq!(no_stage_recovery.mutation_id(), no_stage_id);
        assert_eq!(
            adapter
                .recover_secret_mutation_reservation(RecoverSecretMutationReservation::new(
                    no_stage_recovery.fence().clone(),
                    no_stage_recovered_at,
                    SecretMutationRecoveryReconciliation::AlreadyCommitted(
                        fabricated_no_stage_target,
                    ),
                )?)
                .await
                .expect_err("an absent winner cannot reconcile as committed"),
            automata_ci_store::SecretManagementRepositoryError::CorruptData
        );
        assert_eq!(
            adapter
                .recover_secret_mutation_reservation(RecoverSecretMutationReservation::new(
                    no_stage_recovery.fence().clone(),
                    no_stage_recovered_at,
                    SecretMutationRecoveryReconciliation::DefinitivelyNotCommitted,
                )?)
                .await?,
            RecoverSecretMutationReservationOutcome::ExpiredWithoutStage
        );
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor_at(700),
                        no_stage_id,
                        RepositorySecretProviderMutationResult::CasLost,
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Expired,
            "terminal no-stage expiry must replay only the no-winner receipt"
        );
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor_at(700),
                        no_stage_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(
                            fabricated_no_stage_target,
                        ),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Conflict
        );

        let cleanup_delete = sqlx::query(
            "DELETE FROM secret_cleanup_outbox WHERE tenant_id = $1 AND secret_version_id = $2",
        )
        .bind(&fixture.tenant_id)
        .bind(abandoned_version)
        .execute(database.pool())
        .await
        .expect_err("durable cleanup receipt deletion must fail");
        assert_sql_constraint(&cleanup_delete, "secret_cleanup_delete_forbidden");
        let cleanup_truncate = sqlx::query("TRUNCATE secret_cleanup_outbox")
            .execute(database.pool())
            .await
            .expect_err("durable cleanup receipt truncation must fail");
        assert_sql_constraint(&cleanup_truncate, "secret_cleanup_delete_forbidden");
        let cleanup_identity = sqlx::query(
            r"
            UPDATE secret_cleanup_outbox
            SET operation_id = $3
            WHERE tenant_id = $1 AND secret_version_id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(abandoned_version)
        .bind(Uuid::new_v4())
        .execute(database.pool())
        .await
        .expect_err("cleanup identity mutation must fail");
        assert_sql_constraint(&cleanup_identity, "secret_cleanup_identity_immutable");
        let cleanup_generation_jump = sqlx::query(
            r"
            UPDATE secret_cleanup_outbox
            SET status = 'in_progress', attempts = 1, claim_generation = 2,
                locked_by = 'direct-writer', locked_at_ms = next_attempt_at_ms
            WHERE tenant_id = $1 AND secret_version_id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(abandoned_version)
        .execute(database.pool())
        .await
        .expect_err("cleanup generation jump must fail");
        assert_sql_constraint(&cleanup_generation_jump, "secret_cleanup_claim_exact");

        let ClaimBuiltinSecretCleanupOutcome::Claimed(cleanup) = adapter
            .claim_builtin_secret_cleanup(ClaimBuiltinSecretCleanup::new(
                SecretCleanupWorkerId::new("recovery-cleanup-worker")?,
                UnixMillis::new(recovered_at.get() + 1),
                1_000,
            )?)
            .await?
        else {
            return Err("expired candidate erasure was not claimable".into());
        };
        assert_eq!(cleanup.secret_version_id(), abandoned_version);
        let stale_cleanup_fence = cleanup.fence().clone();
        let cleanup_takeover_at = UnixMillis::new(recovered_at.get() + 1_001);
        let ClaimBuiltinSecretCleanupOutcome::Claimed(cleanup) = adapter
            .claim_builtin_secret_cleanup(ClaimBuiltinSecretCleanup::new(
                SecretCleanupWorkerId::new("recovery-cleanup-worker-takeover")?,
                cleanup_takeover_at,
                1_000,
            )?)
            .await?
        else {
            return Err("stale cleanup task was not taken over".into());
        };
        assert_eq!(
            cleanup.fence().claim_generation(),
            stale_cleanup_fence.claim_generation() + 1
        );
        assert_eq!(
            adapter
                .complete_builtin_secret_cleanup(CompleteBuiltinSecretCleanup::new(
                    stale_cleanup_fence.clone(),
                    cleanup_takeover_at,
                )?)
                .await?,
            CompleteBuiltinSecretCleanupOutcome::FenceRejected,
            "a stale cleanup owner cannot complete after takeover"
        );
        assert_eq!(
            adapter
                .retry_builtin_secret_cleanup(RetryBuiltinSecretCleanup::new(
                    stale_cleanup_fence,
                    cleanup_takeover_at,
                    UnixMillis::new(cleanup_takeover_at.get() + 1),
                    SecretCleanupFailureKind::Unavailable,
                )?)
                .await?,
            RetryBuiltinSecretCleanupOutcome::FenceRejected,
            "a stale cleanup owner cannot reschedule after takeover"
        );
        let erased_at = cleanup_takeover_at.get() + 1;
        simulate_builtin_cryptographic_erasure(
            database.pool(),
            &fixture.tenant_id,
            abandoned_version,
            erased_at,
        )
        .await?;
        assert_eq!(
            adapter
                .complete_builtin_secret_cleanup(CompleteBuiltinSecretCleanup::new(
                    cleanup.fence().clone(),
                    UnixMillis::new(erased_at),
                )?)
                .await?,
            CompleteBuiltinSecretCleanupOutcome::Completed
        );
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor_at(700),
                        abandoned_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(abandoned_target),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Expired,
            "exact terminal replay remains bound after cryptographic erasure"
        );

        let fresh = seed_session(
            database.pool(),
            fixture.tenant_id.clone(),
            fixture.repository_id,
            fixture.principal_id,
            "7010",
        )
        .await?;
        let next_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(next) = adapter
            .reserve_repository_secret_version_mutation(
                ReserveRepositorySecretVersionMutation::replace(
                    fresh.actor(),
                    next_id,
                    secret_id,
                    RepositoryId::from_uuid(fresh.repository_id),
                    RepositorySecretName::new("recovery_token")?,
                    ManagementRevision::new(2)?,
                )?,
            )
            .await?
        else {
            return Err("post-erasure replacement was not reserved".into());
        };
        assert_eq!(
            next.reserved_version_number(),
            4,
            "abandoned committed attempts leave only per-secret ledger gaps"
        );
        let next_version = Uuid::new_v4();
        stage_encrypted_builtin_version(
            database.pool(),
            &fresh,
            secret_id,
            next_version,
            i64::try_from(next.reserved_version_number())?,
            Some(version_one),
            2,
            next.provider_create_request_id(),
            b"post-recovery-value",
        )
        .await?;
        let next_target = BuiltinRepositorySecretVersion::new(
            secret_id,
            RepositorySecretVersionId::from_uuid(next_version)?,
            next.reserved_version_number(),
        )?;
        assert!(matches!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fresh.actor(),
                        next_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(next_target),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Applied(_)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn replacement_requires_update_permission_at_reserve_and_confirm() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(database.pool(), "7002-permissions", true).await?;
        let adapter = PostgresSecretManagementRepository::new(database.pool().clone());
        assert!(matches!(
            adapter
                .activate_builtin_secret_provider(ActivateBuiltinSecretProvider::new(
                    fixture.actor(),
                    ManagementRevision::new(1)?,
                ))
                .await?,
            ActivateBuiltinSecretProviderOutcome::Activated(_)
        ));

        let secret_id = RepositorySecretId::from_uuid(Uuid::new_v4())?;
        let create_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(create) = adapter
            .reserve_repository_secret_version_mutation(
                ReserveRepositorySecretVersionMutation::create(
                    fixture.actor(),
                    create_id,
                    secret_id,
                    RepositoryId::from_uuid(fixture.repository_id),
                    RepositorySecretName::new("permission_split_token")?,
                    None,
                )?,
            )
            .await?
        else {
            return Err("initial create was not reserved".into());
        };
        let version_one = Uuid::new_v4();
        stage_encrypted_builtin_version(
            database.pool(),
            &fixture,
            secret_id,
            version_one,
            1,
            None,
            1,
            create.provider_create_request_id(),
            b"permission-split-canonical",
        )
        .await?;
        let target_one = BuiltinRepositorySecretVersion::new(
            secret_id,
            RepositorySecretVersionId::from_uuid(version_one)?,
            1,
        )?;
        assert!(matches!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        create_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(target_one),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Applied(_)
        ));

        let create_only = seed_repository_permission_actor(
            database.pool(),
            &fixture,
            "70021",
            "secrets:create",
        )
        .await?;
        let denied_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        assert_eq!(
            adapter
                .reserve_repository_secret_version_mutation(
                    ReserveRepositorySecretVersionMutation::replace(
                        create_only.actor(),
                        denied_id,
                        secret_id,
                        RepositoryId::from_uuid(fixture.repository_id),
                        RepositorySecretName::new("permission_split_token")?,
                        ManagementRevision::new(2)?,
                    )?,
                )
                .await?,
            ReserveRepositorySecretVersionMutationOutcome::Forbidden
        );
        let denied_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM secret_version_mutations WHERE tenant_id = $1 AND mutation_id = $2",
        )
        .bind(&fixture.tenant_id)
        .bind(denied_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(denied_rows, 0, "denied replacement must not reserve an intent");

        let update_only = seed_repository_permission_actor(
            database.pool(),
            &fixture,
            "70022",
            "secrets:update",
        )
        .await?;
        let replace_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(replacement) = adapter
            .reserve_repository_secret_version_mutation(
                ReserveRepositorySecretVersionMutation::replace(
                    update_only.actor(),
                    replace_id,
                    secret_id,
                    RepositoryId::from_uuid(fixture.repository_id),
                    RepositorySecretName::new("permission_split_token")?,
                    ManagementRevision::new(2)?,
                )?,
            )
            .await?
        else {
            return Err("update-only replacement was not reserved".into());
        };
        assert_eq!(replacement.expected_predecessor(), Some(target_one));
        let version_two = Uuid::new_v4();
        stage_encrypted_builtin_version(
            database.pool(),
            &update_only,
            secret_id,
            version_two,
            2,
            Some(version_one),
            2,
            replacement.provider_create_request_id(),
            b"permission-split-version-two",
        )
        .await?;
        let target_two = BuiltinRepositorySecretVersion::new(
            secret_id,
            RepositorySecretVersionId::from_uuid(version_two)?,
            2,
        )?;
        assert!(matches!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        update_only.actor(),
                        replace_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(target_two),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Applied(_)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn deletion_distinguishes_unapplied_cancel_from_applied_provider_race() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(database.pool(), "7003", true).await?;
        let adapter = PostgresSecretManagementRepository::new(database.pool().clone());
        assert!(matches!(
            adapter
                .activate_builtin_secret_provider(ActivateBuiltinSecretProvider::new(
                    fixture.actor(),
                    ManagementRevision::new(1)?,
                ))
                .await?,
            ActivateBuiltinSecretProviderOutcome::Activated(_)
        ));

        let cancelled_secret = RepositorySecretId::from_uuid(Uuid::new_v4())?;
        let cancelled_mutation =
            RepositorySecretMutationId::from_uuid(Uuid::new_v4(), cancelled_secret)?;
        assert!(matches!(
            adapter
                .reserve_repository_secret_version_mutation(
                    ReserveRepositorySecretVersionMutation::create(
                        fixture.actor(),
                        cancelled_mutation,
                        cancelled_secret,
                        RepositoryId::from_uuid(fixture.repository_id),
                        RepositorySecretName::new("cancelled_token")?,
                        None,
                    )?,
                )
                .await?,
            ReserveRepositorySecretVersionMutationOutcome::FreshReservation(_)
        ));
        let DeleteRepositorySecretOutcome::Deleted(cancelled_deletion) = adapter
            .delete_repository_secret(DeleteRepositorySecret::new(
                fixture.actor(),
                RepositoryId::from_uuid(fixture.repository_id),
                cancelled_secret,
                ManagementRevision::new(1)?,
            )?)
            .await?
        else {
            return Err("unapplied reservation was not deleted".into());
        };
        assert_eq!(cancelled_deletion.cleanup_operations(), 0);
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        cancelled_mutation,
                        RepositorySecretProviderMutationResult::CasLost,
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Cancelled
        );
        let impossible_cancelled_target = BuiltinRepositorySecretVersion::new(
            cancelled_secret,
            RepositorySecretVersionId::from_uuid(Uuid::new_v4())?,
            1,
        )?;
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        cancelled_mutation,
                        RepositorySecretProviderMutationResult::BuiltinCreated(
                            impossible_cancelled_target,
                        ),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Conflict,
            "a cancellation without a staged winner must replay only CasLost"
        );
        let reused_mutation =
            RepositorySecretMutationId::from_uuid(Uuid::new_v4(), cancelled_secret)?;
        assert_eq!(
            adapter
                .reserve_repository_secret_version_mutation(
                    ReserveRepositorySecretVersionMutation::create(
                        fixture.actor(),
                        reused_mutation,
                        cancelled_secret,
                        RepositoryId::from_uuid(fixture.repository_id),
                        RepositorySecretName::new("cancelled_token")?,
                        None,
                    )?,
                )
                .await?,
            ReserveRepositorySecretVersionMutationOutcome::Conflict,
            "a logically retired UUID must never acquire a second creation intent"
        );

        let staged_secret = RepositorySecretId::from_uuid(Uuid::new_v4())?;
        let staged_mutation = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), staged_secret)?;
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(reservation) = adapter
            .reserve_repository_secret_version_mutation(
                ReserveRepositorySecretVersionMutation::create(
                    fixture.actor(),
                    staged_mutation,
                    staged_secret,
                    RepositoryId::from_uuid(fixture.repository_id),
                    RepositorySecretName::new("staged_token")?,
                    None,
                )?,
            )
            .await?
        else {
            return Err("applied race create was not reserved".into());
        };
        let version_id = Uuid::new_v4();
        stage_encrypted_builtin_version(
            database.pool(),
            &fixture,
            staged_secret,
            version_id,
            1,
            None,
            1,
            reservation.provider_create_request_id(),
            b"applied-before-delete",
        )
        .await?;
        let DeleteRepositorySecretOutcome::Deleted(staged_deletion) = adapter
            .delete_repository_secret(DeleteRepositorySecret::new(
                fixture.actor(),
                RepositoryId::from_uuid(fixture.repository_id),
                staged_secret,
                ManagementRevision::new(1)?,
            )?)
            .await?
        else {
            return Err("staged provider winner was not logically deleted".into());
        };
        assert_eq!(staged_deletion.cleanup_operations(), 1);
        let staged_target = BuiltinRepositorySecretVersion::new(
            staged_secret,
            RepositorySecretVersionId::from_uuid(version_id)?,
            1,
        )?;
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        staged_mutation,
                        RepositorySecretProviderMutationResult::BuiltinCreated(staged_target),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Cancelled,
            "a staged winner is not applied before management confirmation"
        );
        assert_eq!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        staged_mutation,
                        RepositorySecretProviderMutationResult::CasLost,
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Conflict,
            "a staged-winner cancellation must replay only its exact target"
        );

        let applied_secret = RepositorySecretId::from_uuid(Uuid::new_v4())?;
        let applied_mutation =
            RepositorySecretMutationId::from_uuid(Uuid::new_v4(), applied_secret)?;
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(applied_reservation) =
            adapter
                .reserve_repository_secret_version_mutation(
                    ReserveRepositorySecretVersionMutation::create(
                        fixture.actor(),
                        applied_mutation,
                        applied_secret,
                        RepositoryId::from_uuid(fixture.repository_id),
                        RepositorySecretName::new("applied_token")?,
                        None,
                    )?,
                )
                .await?
        else {
            return Err("applied create was not reserved".into());
        };
        let applied_version = Uuid::new_v4();
        stage_encrypted_builtin_version(
            database.pool(),
            &fixture,
            applied_secret,
            applied_version,
            1,
            None,
            1,
            applied_reservation.provider_create_request_id(),
            b"confirmed-before-delete",
        )
        .await?;
        let applied_target = BuiltinRepositorySecretVersion::new(
            applied_secret,
            RepositorySecretVersionId::from_uuid(applied_version)?,
            1,
        )?;
        assert!(matches!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        applied_mutation,
                        RepositorySecretProviderMutationResult::BuiltinCreated(applied_target),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Applied(_)
        ));

        let replacement_mutation =
            RepositorySecretMutationId::from_uuid(Uuid::new_v4(), applied_secret)?;
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(
            replacement_reservation,
        ) = adapter
            .reserve_repository_secret_version_mutation(
                ReserveRepositorySecretVersionMutation::replace(
                    fixture.actor(),
                    replacement_mutation,
                    applied_secret,
                    RepositoryId::from_uuid(fixture.repository_id),
                    RepositorySecretName::new("applied_token")?,
                    ManagementRevision::new(2)?,
                )?,
            )
            .await?
        else {
            return Err("pre-deletion replacement was not reserved".into());
        };
        let replacement_version = Uuid::new_v4();
        stage_encrypted_builtin_version(
            database.pool(),
            &fixture,
            applied_secret,
            replacement_version,
            2,
            Some(applied_version),
            2,
            replacement_reservation.provider_create_request_id(),
            b"confirmed-replacement-before-delete",
        )
        .await?;
        let replacement_target = BuiltinRepositorySecretVersion::new(
            applied_secret,
            RepositorySecretVersionId::from_uuid(replacement_version)?,
            2,
        )?;
        assert!(matches!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        replacement_mutation,
                        RepositorySecretProviderMutationResult::BuiltinCreated(replacement_target,),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Applied(_)
        ));
        let DeleteRepositorySecretOutcome::Deleted(applied_deletion) = adapter
            .delete_repository_secret(DeleteRepositorySecret::new(
                fixture.actor(),
                RepositoryId::from_uuid(fixture.repository_id),
                applied_secret,
                ManagementRevision::new(3)?,
            )?)
            .await?
        else {
            return Err("replaced secret was not deleted".into());
        };
        assert_eq!(applied_deletion.cleanup_operations(), 2);
        assert!(matches!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        applied_mutation,
                        RepositorySecretProviderMutationResult::BuiltinCreated(applied_target),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::AppliedThenSuperseded(_)
        ));
        assert!(matches!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        replacement_mutation,
                        RepositorySecretProviderMutationResult::BuiltinCreated(replacement_target,),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::AppliedThenDeleted(_)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn mutation_schema_rejects_fabricated_receipts_and_mutable_intents() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(database.pool(), "7004", true).await?;
        let adapter = PostgresSecretManagementRepository::new(database.pool().clone());
        assert!(matches!(
            adapter
                .activate_builtin_secret_provider(ActivateBuiltinSecretProvider::new(
                    fixture.actor(),
                    ManagementRevision::new(1)?,
                ))
                .await?,
            ActivateBuiltinSecretProviderOutcome::Activated(_)
        ));

        let environment_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO repository_environments (
                tenant_id, repository_id, id, name, normalized_name,
                created_by_principal_id, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, $3, 'Ledger scope', 'ledger-scope', $4, 1, 1)
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(fixture.repository_id)
        .bind(environment_id)
        .bind(fixture.principal_id)
        .execute(database.pool())
        .await?;
        for (scope_kind, repository_id, environment_id, canonical_name) in [
            ("tenant", None, None, "TENANT_LEDGER_TOKEN"),
            (
                "environment",
                Some(fixture.repository_id),
                Some(environment_id),
                "ENVIRONMENT_LEDGER_TOKEN",
            ),
        ] {
            let scoped_secret = RepositorySecretId::from_uuid(Uuid::new_v4())?;
            let scoped_mutation =
                RepositorySecretMutationId::from_uuid(Uuid::new_v4(), scoped_secret)?;
            sqlx::query(
                r"
                INSERT INTO secrets (
                    tenant_id, id, canonical_name, scope_kind,
                    repository_id, environment_id, provider_id,
                    created_by_principal_id, updated_by_principal_id,
                    created_at_ms, updated_at_ms
                ) VALUES ($1, $2, $3, $4, $5, $6, 'builtin', $7, $7, 1, 1)
                ",
            )
            .bind(&fixture.tenant_id)
            .bind(scoped_secret.as_uuid())
            .bind(canonical_name)
            .bind(scope_kind)
            .bind(repository_id)
            .bind(environment_id)
            .bind(fixture.principal_id)
            .execute(database.pool())
            .await?;
            let mut scoped_transaction = database.pool().begin().await?;
            sqlx::query(
                r"
                INSERT INTO secret_version_mutations (
                    tenant_id, mutation_id, secret_id, scope_kind,
                    repository_id, environment_id, canonical_name,
                    provider_id, mutation_kind, reserved_secret_revision,
                    reserved_version_number, confirmation_deadline_ms,
                    provider_create_request_id, reserved_by_principal_id,
                    reserved_by_session_id, reserved_authorization_revision,
                    reserved_at_ms
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7,
                    'builtin', 'create', 1, 1, 700000, $8, $9, $10, $11, 100000
                )
                ",
            )
            .bind(&fixture.tenant_id)
            .bind(scoped_mutation.as_uuid())
            .bind(scoped_secret.as_uuid())
            .bind(scope_kind)
            .bind(repository_id)
            .bind(environment_id)
            .bind(canonical_name)
            .bind(format!("secret-version:{}", scoped_mutation.as_uuid()))
            .bind(fixture.principal_id)
            .bind(fixture.session_id)
            .bind(i64::try_from(fixture.authorization_revision)?)
            .execute(&mut *scoped_transaction)
            .await?;
            sqlx::query(
                r"
                INSERT INTO secret_mutation_recovery_outbox (
                    operation_id, tenant_id, mutation_id,
                    next_attempt_at_ms, created_at_ms
                ) VALUES (
                    automata_secret_mutation_recovery_operation_id($1, $2),
                    $1, $2, 700000, 100000
                )
                ",
            )
            .bind(&fixture.tenant_id)
            .bind(scoped_mutation.as_uuid())
            .execute(&mut *scoped_transaction)
            .await?;
            scoped_transaction.commit().await?;

            assert_eq!(
                adapter
                    .confirm_repository_secret_version_mutation(
                        ConfirmRepositorySecretVersionMutation::new(
                            fixture.actor(),
                            scoped_mutation,
                            RepositorySecretProviderMutationResult::CasLost,
                        ),
                    )
                    .await?,
                ConfirmRepositorySecretVersionMutationOutcome::NotFound,
            );
            assert_eq!(
                adapter
                    .delete_repository_secret(DeleteRepositorySecret::new(
                        fixture.actor(),
                        RepositoryId::from_uuid(fixture.repository_id),
                        scoped_secret,
                        ManagementRevision::new(1)?,
                    )?)
                    .await?,
                DeleteRepositorySecretOutcome::NotFound,
            );
        }

        let secret_id = RepositorySecretId::from_uuid(Uuid::new_v4())?;
        let create_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(create) = adapter
            .reserve_repository_secret_version_mutation(
                ReserveRepositorySecretVersionMutation::create(
                    fixture.actor(),
                    create_id,
                    secret_id,
                    RepositoryId::from_uuid(fixture.repository_id),
                    RepositorySecretName::new("schema_token")?,
                    None,
                )?,
            )
            .await?
        else {
            return Err("schema test create was not reserved".into());
        };

        let mutation_id_nullable: String = sqlx::query_scalar(
            r"
            SELECT is_nullable
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'secret_version_lifecycle'
              AND column_name = 'mutation_id'
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(mutation_id_nullable, "NO");

        let fabricated_secret = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO secrets (
                tenant_id, id, canonical_name, scope_kind, repository_id,
                provider_id, created_by_principal_id, updated_by_principal_id,
                created_at_ms, updated_at_ms
            ) VALUES (
                $1, $2, 'FABRICATED_TERMINAL', 'repository', $3,
                'builtin', $4, $4, 100000, 100000
            )
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(fabricated_secret)
        .bind(fixture.repository_id)
        .bind(fixture.principal_id)
        .execute(database.pool())
        .await?;
        let terminal_id = Uuid::new_v4();
        let fabricated_terminal = sqlx::query(
            r"
            INSERT INTO secret_version_mutations (
                tenant_id, mutation_id, secret_id, scope_kind, repository_id,
                canonical_name, provider_id, mutation_kind,
                reserved_secret_revision, reserved_version_number,
                confirmation_deadline_ms, provider_create_request_id,
                state, completion_kind, reserved_by_principal_id,
                reserved_by_session_id, reserved_authorization_revision,
                reserved_at_ms, confirmed_by_principal_id,
                confirmed_by_session_id, confirmed_authorization_revision,
                confirmed_at_ms, terminal_actor_kind, terminal_reason, revision
            ) VALUES (
                $1, $2, $3, 'repository', $4, 'SCHEMA_TOKEN', 'builtin', 'create',
                1, 1, 700000, $5, 'cancelled', 'system_cancelled', $6,
                $7, $8, 100000, $6, $7, $8, 100000, 'human',
                'secret_deleted', 1
            )
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(terminal_id)
        .bind(fabricated_secret)
        .bind(fixture.repository_id)
        .bind(format!("secret-version:{terminal_id}"))
        .bind(fixture.principal_id)
        .bind(fixture.session_id)
        .bind(i64::try_from(fixture.authorization_revision)?)
        .execute(database.pool())
        .await
        .expect_err("terminal mutation insertion must fail");
        assert_sql_constraint(
            &fabricated_terminal,
            "secret_version_mutations_initial_state",
        );

        let mutable_intent = sqlx::query(
            r"
            UPDATE secret_version_mutations
            SET canonical_name = 'ALTERED_TOKEN', revision = revision + 1
            WHERE tenant_id = $1 AND mutation_id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(create_id.as_uuid())
        .execute(database.pool())
        .await
        .expect_err("reserved intent mutation must fail");
        assert_sql_constraint(&mutable_intent, "secret_version_mutations_intent_immutable");

        let fabricated_winner = Uuid::new_v4();
        let fabricated_receipt = sqlx::query(
            r"
            UPDATE secret_version_mutations
            SET state = 'confirmed', completion_kind = 'builtin_created',
                committed_version_id = $3, committed_version_number = 1,
                confirmed_secret_revision = 2,
                confirmed_by_principal_id = $4, confirmed_at_ms = 100000,
                revision = revision + 1
            WHERE tenant_id = $1 AND mutation_id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(create_id.as_uuid())
        .bind(fabricated_winner)
        .bind(fixture.principal_id)
        .execute(database.pool())
        .await
        .expect_err("receipt without exact request winner must fail");
        assert_sql_constraint(&fabricated_receipt, "secret_version_mutations_winner_exact");

        let mutable_delete = sqlx::query(
            "DELETE FROM secret_version_mutations WHERE tenant_id = $1 AND mutation_id = $2",
        )
        .bind(&fixture.tenant_id)
        .bind(create_id.as_uuid())
        .execute(database.pool())
        .await
        .expect_err("mutation receipt deletion must fail");
        assert_sql_constraint(&mutable_delete, "secret_version_mutations_append_only");
        let mutable_truncate = sqlx::query("TRUNCATE secret_version_mutations CASCADE")
            .execute(database.pool())
            .await
            .expect_err("mutation receipt truncation must fail");
        assert_sql_constraint(&mutable_truncate, "secret_version_mutations_append_only");

        let orphan_version = Uuid::new_v4();
        let mut orphan_stage = database.pool().begin().await?;
        sqlx::query(
            r"
            INSERT INTO secret_versions (
                tenant_id, id, secret_id, version_number, provider_id,
                create_request_id, storage_kind,
                created_by_principal_id, created_at_ms
            ) VALUES (
                $1, $2, $3, 1, 'builtin', $4, 'built_in_ciphertext', $5, 100000
            )
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(orphan_version)
        .bind(secret_id.as_uuid())
        .bind(create.provider_create_request_id())
        .bind(fixture.principal_id)
        .execute(&mut *orphan_stage)
        .await?;
        let orphan_commit = orphan_stage
            .commit()
            .await
            .expect_err("an orphan version must not occupy the provider request ID");
        assert_sql_constraint(&orphan_commit, "secret_versions_mutation_stage_exact");

        let direct_active_version = Uuid::new_v4();
        let mut direct_active = database.pool().begin().await?;
        sqlx::query(
            r"
            INSERT INTO secret_versions (
                tenant_id, id, secret_id, version_number, provider_id,
                create_request_id, storage_kind,
                created_by_principal_id, created_at_ms
            ) VALUES (
                $1, $2, $3, 1, 'builtin', $4, 'built_in_ciphertext', $5, 100000
            )
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(direct_active_version)
        .bind(secret_id.as_uuid())
        .bind(create.provider_create_request_id())
        .bind(fixture.principal_id)
        .execute(&mut *direct_active)
        .await?;
        let direct_active_error = sqlx::query(
            r"
            INSERT INTO secret_version_lifecycle (
                tenant_id, secret_version_id, secret_id, version_number,
                provider_id, mutation_id, status, revision,
                changed_by_principal_id, changed_at_ms
            ) VALUES ($1, $2, $3, 1, 'builtin', $4, 'active', 1, $5, 100000)
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(direct_active_version)
        .bind(secret_id.as_uuid())
        .bind(create_id.as_uuid())
        .bind(fixture.principal_id)
        .execute(&mut *direct_active)
        .await
        .expect_err("provider must not insert an already-active lifecycle");
        assert_sql_constraint(
            &direct_active_error,
            "secret_version_lifecycle_initial_staged",
        );
        direct_active.rollback().await?;

        let wrong_intent_version = Uuid::new_v4();
        let wrong_intent_id = Uuid::new_v4();
        let mut wrong_intent = database.pool().begin().await?;
        sqlx::query(
            r"
            INSERT INTO secret_versions (
                tenant_id, id, secret_id, version_number, provider_id,
                create_request_id, storage_kind,
                created_by_principal_id, created_at_ms
            ) VALUES (
                $1, $2, $3, 1, 'builtin', $4, 'built_in_ciphertext', $5, 100000
            )
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(wrong_intent_version)
        .bind(secret_id.as_uuid())
        .bind(create.provider_create_request_id())
        .bind(fixture.principal_id)
        .execute(&mut *wrong_intent)
        .await?;
        let wrong_intent_error = sqlx::query(
            r"
            INSERT INTO secret_version_lifecycle (
                tenant_id, secret_version_id, secret_id, version_number,
                provider_id, mutation_id, status, revision,
                changed_by_principal_id, changed_at_ms
            ) VALUES ($1, $2, $3, 1, 'builtin', $4, 'staged', 1, $5, 100000)
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(wrong_intent_version)
        .bind(secret_id.as_uuid())
        .bind(wrong_intent_id)
        .bind(fixture.principal_id)
        .execute(&mut *wrong_intent)
        .await
        .expect_err("staged lifecycle must join the exact reserved mutation");
        assert_sql_constraint(
            &wrong_intent_error,
            "secret_version_lifecycle_staged_intent_exact",
        );
        wrong_intent.rollback().await?;

        let version_one = Uuid::new_v4();
        stage_encrypted_builtin_version(
            database.pool(),
            &fixture,
            secret_id,
            version_one,
            1,
            None,
            1,
            create.provider_create_request_id(),
            b"schema-value-one",
        )
        .await?;
        let target_one = BuiltinRepositorySecretVersion::new(
            secret_id,
            RepositorySecretVersionId::from_uuid(version_one)?,
            1,
        )?;
        assert!(matches!(
            adapter
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        create_id,
                        RepositorySecretProviderMutationResult::BuiltinCreated(target_one),
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::Applied(_)
        ));
        let delete_lifecycle = sqlx::query(
            "DELETE FROM secret_version_lifecycle WHERE tenant_id = $1 AND secret_version_id = $2",
        )
        .bind(&fixture.tenant_id)
        .bind(version_one)
        .execute(database.pool())
        .await
        .expect_err("mutation-backed lifecycle rows must be append-only");
        assert_sql_constraint(&delete_lifecycle, "secret_version_lifecycle_append_only");
        let truncate_lifecycle = sqlx::query("TRUNCATE secret_version_lifecycle CASCADE")
            .execute(database.pool())
            .await
            .expect_err("mutation-backed lifecycle rows must reject truncation");
        assert_sql_constraint(&truncate_lifecycle, "secret_version_lifecycle_append_only");

        let skipped_ordinal_id = Uuid::new_v4();
        let skipped_ordinal = sqlx::query(
            r"
            INSERT INTO secret_version_mutations (
                tenant_id, mutation_id, secret_id, scope_kind, repository_id,
                canonical_name, provider_id, mutation_kind,
                expected_secret_revision, reserved_secret_revision,
                expected_predecessor_version_id,
                expected_predecessor_version_number,
                reserved_version_number, confirmation_deadline_ms,
                provider_create_request_id, reserved_by_principal_id,
                reserved_by_session_id, reserved_authorization_revision,
                reserved_at_ms
            ) VALUES (
                $1, $2, $3, 'repository', $4, 'SCHEMA_TOKEN', 'builtin', 'replace',
                2, 2, $5, 1, 3, 700000, $6, $7, $8, $9, 100000
            )
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(skipped_ordinal_id)
        .bind(secret_id.as_uuid())
        .bind(fixture.repository_id)
        .bind(version_one)
        .bind(format!("secret-version:{skipped_ordinal_id}"))
        .bind(fixture.principal_id)
        .bind(fixture.session_id)
        .bind(i64::try_from(fixture.authorization_revision)?)
        .execute(database.pool())
        .await
        .expect_err("a direct writer must not skip the next committed reservation ordinal");
        assert_sql_constraint(
            &skipped_ordinal,
            "secret_version_mutations_reserved_version_exact",
        );

        let wrong_predecessor_id = Uuid::new_v4();
        let wrong_predecessor_version = Uuid::new_v4();
        let wrong_predecessor = sqlx::query(
            r"
            INSERT INTO secret_version_mutations (
                tenant_id, mutation_id, secret_id, scope_kind, repository_id,
                canonical_name, provider_id, mutation_kind,
                expected_secret_revision, reserved_secret_revision,
                expected_predecessor_version_id,
                expected_predecessor_version_number,
                reserved_version_number, confirmation_deadline_ms,
                provider_create_request_id, reserved_by_principal_id,
                reserved_by_session_id, reserved_authorization_revision,
                reserved_at_ms
            ) VALUES (
                $1, $2, $3, 'repository', $4, 'SCHEMA_TOKEN', 'builtin', 'replace',
                2, 2, $5, 1, 2, 700000, $6, $7, $8, $9, 100000
            )
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(wrong_predecessor_id)
        .bind(secret_id.as_uuid())
        .bind(fixture.repository_id)
        .bind(wrong_predecessor_version)
        .bind(format!("secret-version:{wrong_predecessor_id}"))
        .bind(fixture.principal_id)
        .bind(fixture.session_id)
        .bind(i64::try_from(fixture.authorization_revision)?)
        .execute(database.pool())
        .await
        .expect_err("replacement with a noncurrent predecessor must fail");
        assert_sql_constraint(&wrong_predecessor, "secret_version_mutations_replace_head");

        let replace_id = RepositorySecretMutationId::from_uuid(Uuid::new_v4(), secret_id)?;
        let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(replacement) = adapter
            .reserve_repository_secret_version_mutation(
                ReserveRepositorySecretVersionMutation::replace(
                    fixture.actor(),
                    replace_id,
                    secret_id,
                    RepositoryId::from_uuid(fixture.repository_id),
                    RepositorySecretName::new("schema_token")?,
                    ManagementRevision::new(2)?,
                )?,
            )
            .await?
        else {
            return Err("schema replacement was not reserved".into());
        };
        let version_two = Uuid::new_v4();
        stage_encrypted_builtin_version(
            database.pool(),
            &fixture,
            secret_id,
            version_two,
            2,
            Some(version_one),
            2,
            replacement.provider_create_request_id(),
            b"schema-value-two",
        )
        .await?;
        let wrong_head = sqlx::query(
            r"
            UPDATE secret_version_mutations
            SET state = 'confirmed', completion_kind = 'builtin_created',
                committed_version_id = $3, committed_version_number = 2,
                confirmed_secret_revision = 999,
                confirmed_by_principal_id = $4, confirmed_at_ms = 100000,
                revision = revision + 1
            WHERE tenant_id = $1 AND mutation_id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(replace_id.as_uuid())
        .bind(version_two)
        .bind(fixture.principal_id)
        .execute(database.pool())
        .await
        .expect_err("receipt with a mismatched logical head must fail");
        assert_sql_constraint(&wrong_head, "secret_version_mutations_winner_head");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn operational_secret_reads_are_exact_reauthorized_and_non_enumerating() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(database.pool(), "7991", false).await?;
        let adapter = PostgresSecretManagementRepository::new(database.pool().clone());
        let (owner, name): (String, String) =
            sqlx::query_as("SELECT owner, name FROM repositories WHERE tenant_id = $1 AND id = $2")
                .bind(&fixture.tenant_id)
                .bind(fixture.repository_id)
                .fetch_one(database.pool())
                .await?;
        let resolution = |repository: GithubRepositoryName| {
            ResolveGithubRepositorySecretMetadata::new(fixture.actor(), repository)
        };
        assert_eq!(
            adapter
                .resolve_github_repository_secret_metadata(resolution(GithubRepositoryName::new(
                    format!(
                        "{}/{}",
                        owner.to_ascii_uppercase(),
                        name.to_ascii_uppercase()
                    )
                )?,))
                .await?,
            ResolveGithubRepositorySecretMetadataOutcome::Found(RepositoryId::from_uuid(
                fixture.repository_id
            )),
            "GitHub coordinates use the schema's exact case-insensitive unique identity"
        );
        let missing_resolution = adapter
            .resolve_github_repository_secret_metadata(resolution(GithubRepositoryName::new(
                "automata/missing-secret-read-bridge",
            )?))
            .await?;
        assert_eq!(
            missing_resolution,
            ResolveGithubRepositorySecretMetadataOutcome::NotFound
        );

        let sibling_id = seed_repository(database.pool(), &fixture.tenant_id).await?;
        let (sibling_owner, sibling_name): (String, String) =
            sqlx::query_as("SELECT owner, name FROM repositories WHERE tenant_id = $1 AND id = $2")
                .bind(&fixture.tenant_id)
                .bind(sibling_id)
                .fetch_one(database.pool())
                .await?;
        let forbidden_resolution = adapter
            .resolve_github_repository_secret_metadata(resolution(GithubRepositoryName::new(
                format!("{sibling_owner}/{sibling_name}"),
            )?))
            .await?;
        assert_eq!(
            forbidden_resolution, missing_resolution,
            "missing and forbidden repository coordinates must be indistinguishable"
        );

        let secret_name = RepositorySecretName::new("read_bridge_token")?;
        let own_secret_id = seed_provisioning_repository_secret(
            database.pool(),
            &fixture,
            fixture.repository_id,
            &secret_name,
        )
        .await?;
        seed_provisioning_repository_secret(database.pool(), &fixture, sibling_id, &secret_name)
            .await?;
        let lookup = |repository_id, name| {
            GetRepositorySecretMetadata::new(fixture.actor(), repository_id, name)
                .expect("non-nil repository")
        };
        let GetRepositorySecretMetadataOutcome::Found(metadata) = adapter
            .get_repository_secret_metadata(lookup(
                RepositoryId::from_uuid(fixture.repository_id),
                secret_name.clone(),
            ))
            .await?
        else {
            return Err("exact repository secret metadata was not found".into());
        };
        assert_eq!(metadata.id().as_uuid(), own_secret_id);
        assert_eq!(metadata.name(), &secret_name);
        assert_eq!(metadata.provider_id().as_str(), BUILTIN_SECRET_PROVIDER_ID);
        assert_eq!(metadata.current_version_number(), None);
        let missing_secret = adapter
            .get_repository_secret_metadata(lookup(
                RepositoryId::from_uuid(fixture.repository_id),
                RepositorySecretName::new("missing_read_bridge_token")?,
            ))
            .await?;
        assert_eq!(missing_secret, GetRepositorySecretMetadataOutcome::NotFound);
        let forbidden_secret = adapter
            .get_repository_secret_metadata(lookup(
                RepositoryId::from_uuid(sibling_id),
                secret_name.clone(),
            ))
            .await?;
        assert_eq!(
            forbidden_secret, missing_secret,
            "an existing unauthorized secret must look absent"
        );

        assert_eq!(
            adapter
                .inspect_builtin_secret_provider(InspectBuiltinSecretProvider::new(fixture.actor()))
                .await?,
            InspectBuiltinSecretProviderOutcome::Forbidden,
            "repository-scoped provider permissions must not become tenant authority"
        );
        let read_only_principal = Uuid::new_v4();
        seed_principal(
            database.pool(),
            &fixture.tenant_id,
            read_only_principal,
            "7992",
        )
        .await?;
        let read_only_role = seed_role(
            database.pool(),
            &fixture.tenant_id,
            read_only_principal,
            &["secret-providers:read"],
        )
        .await?;
        seed_direct_binding(
            database.pool(),
            &fixture.tenant_id,
            read_only_principal,
            read_only_role,
            None,
        )
        .await?;
        let read_only = seed_session(
            database.pool(),
            fixture.tenant_id.clone(),
            fixture.repository_id,
            read_only_principal,
            "7992",
        )
        .await?;
        let InspectBuiltinSecretProviderOutcome::Found(provider) = adapter
            .inspect_builtin_secret_provider(InspectBuiltinSecretProvider::new(read_only.actor()))
            .await?
        else {
            return Err("provider reader could not inspect redacted state".into());
        };
        assert_eq!(provider.state(), BuiltinSecretProviderState::Unconfigured);
        assert_eq!(provider.health(), BuiltinSecretProviderHealth::Unknown);
        assert_eq!(provider.revision().value(), 1);
        assert!(
            provider.activation().is_none(),
            "redacted read authority must not produce activation evidence"
        );

        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET authorization_revision = authorization_revision + 1,
                updated_at_ms = updated_at_ms + 1
            WHERE tenant_id = $1 AND principal_id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(fixture.principal_id)
        .execute(database.pool())
        .await?;
        assert_eq!(
            adapter
                .resolve_github_repository_secret_metadata(resolution(GithubRepositoryName::new(
                    format!("{owner}/{name}")
                )?,))
                .await?,
            ResolveGithubRepositorySecretMetadataOutcome::SessionStale
        );
        assert_eq!(
            adapter
                .get_repository_secret_metadata(lookup(
                    RepositoryId::from_uuid(fixture.repository_id),
                    secret_name,
                ))
                .await?,
            GetRepositorySecretMetadataOutcome::SessionStale
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn newest_numeric_github_mapping_is_exact_scoped_and_token_version_bound() -> TestResult {
    run_with_database(|database| async move {
        let tenant_id = format!("secret-github-{}", Uuid::new_v4().simple());
        let repository_id = seed_tenant_and_repository(database.pool(), &tenant_id).await?;
        let sibling = seed_repository(database.pool(), &tenant_id).await?;
        let principal_id = Uuid::new_v4();
        let subject = "424242";
        seed_principal(database.pool(), &tenant_id, principal_id, subject).await?;
        seed_provider_token(database.pool(), &tenant_id, principal_id, subject).await?;
        let role_id = seed_role(
            database.pool(),
            &tenant_id,
            principal_id,
            &[SECRET_METADATA_PERMISSION],
        )
        .await?;
        seed_github_mapping(database.pool(), &tenant_id, role_id, repository_id, 9_001).await?;
        seed_github_snapshot(
            database.pool(),
            &tenant_id,
            principal_id,
            subject,
            90_000,
            200_000,
            1,
            Some(9_001),
        )
        .await?;
        let fixture = seed_session(
            database.pool(),
            tenant_id.clone(),
            repository_id,
            principal_id,
            subject,
        )
        .await?;
        let adapter = PostgresSecretManagementRepository::new(database.pool().clone());
        let query = |repository_id| {
            ListRepositorySecrets::new(
                fixture.actor(),
                RepositoryId::from_uuid(repository_id),
                None,
                SecretMetadataPageSize::new(10).expect("page size"),
            )
            .expect("query")
        };
        assert!(matches!(
            adapter
                .list_repository_secrets(query(repository_id))
                .await?,
            ListRepositorySecretsOutcome::Found(_)
        ));
        assert_eq!(
            adapter.list_repository_secrets(query(sibling)).await?,
            ListRepositorySecretsOutcome::Forbidden
        );

        seed_github_snapshot(
            database.pool(),
            &tenant_id,
            principal_id,
            subject,
            95_000,
            99_000,
            1,
            Some(9_001),
        )
        .await?;
        assert_eq!(
            adapter
                .list_repository_secrets(query(repository_id))
                .await?,
            ListRepositorySecretsOutcome::Forbidden,
            "an expired newest snapshot must not fall back to older authority"
        );

        seed_github_snapshot(
            database.pool(),
            &tenant_id,
            principal_id,
            subject,
            99_000,
            200_000,
            1,
            Some(9_001),
        )
        .await?;
        assert!(matches!(
            adapter
                .list_repository_secrets(query(repository_id))
                .await?,
            ListRepositorySecretsOutcome::Found(_)
        ));
        sqlx::query(
            r"
            UPDATE human_provider_tokens
            SET version = 2, access_expires_at_ms = 100000,
                updated_at_ms = updated_at_ms + 1
            WHERE tenant_id = $1 AND provider_id = 'github'
              AND provider_subject = $2 AND revoked_at_ms IS NULL
            ",
        )
        .bind(&tenant_id)
        .bind(subject)
        .execute(database.pool())
        .await?;
        seed_github_snapshot(
            database.pool(),
            &tenant_id,
            principal_id,
            subject,
            99_500,
            200_000,
            2,
            Some(9_001),
        )
        .await?;
        assert_eq!(
            adapter
                .list_repository_secrets(query(repository_id))
                .await?,
            ListRepositorySecretsOutcome::Forbidden,
            "an expired provider token must invalidate mapped authority"
        );
        sqlx::query(
            r"
            UPDATE human_provider_tokens
            SET version = 3, access_expires_at_ms = 300000,
                updated_at_ms = updated_at_ms + 1
            WHERE tenant_id = $1 AND provider_id = 'github'
              AND provider_subject = $2 AND revoked_at_ms IS NULL
            ",
        )
        .bind(&tenant_id)
        .bind(subject)
        .execute(database.pool())
        .await?;
        seed_github_snapshot(
            database.pool(),
            &tenant_id,
            principal_id,
            subject,
            99_750,
            200_000,
            3,
            Some(9_001),
        )
        .await?;
        assert!(matches!(
            adapter
                .list_repository_secrets(query(repository_id))
                .await?,
            ListRepositorySecretsOutcome::Found(_)
        ));
        sqlx::query(
            r"
            UPDATE human_provider_tokens
            SET version = 4, updated_at_ms = updated_at_ms + 1
            WHERE tenant_id = $1 AND provider_id = 'github'
              AND provider_subject = $2 AND revoked_at_ms IS NULL
            ",
        )
        .bind(&tenant_id)
        .bind(subject)
        .execute(database.pool())
        .await?;
        assert_eq!(
            adapter
                .list_repository_secrets(query(repository_id))
                .await?,
            ListRepositorySecretsOutcome::Forbidden,
            "a snapshot from an obsolete provider-token version must not authorize"
        );
        Ok(())
    })
    .await
}

const SECRET_METADATA_PERMISSION: &str = "secrets:metadata:read";

async fn seed_provisioning_repository_secret(
    pool: &PgPool,
    fixture: &Fixture,
    repository_id: Uuid,
    name: &RepositorySecretName,
) -> TestResult<Uuid> {
    let secret_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO secrets (
            tenant_id, id, canonical_name, scope_kind, repository_id,
            environment_id, provider_id, status, revision,
            created_by_principal_id, updated_by_principal_id,
            created_at_ms, updated_at_ms
        ) VALUES (
            $1, $2, $3, 'repository', $4, NULL, 'builtin',
            'provisioning', 1, $5, $5, 1, 1
        )
        ",
    )
    .bind(&fixture.tenant_id)
    .bind(secret_id)
    .bind(name.as_str())
    .bind(repository_id)
    .bind(fixture.principal_id)
    .execute(pool)
    .await?;
    Ok(secret_id)
}

async fn seed_fixture(pool: &PgPool, subject: &str, tenant_grant: bool) -> TestResult<Fixture> {
    let tenant_id = format!("secret-management-{}", Uuid::new_v4().simple());
    let repository_id = seed_tenant_and_repository(pool, &tenant_id).await?;
    let principal_id = Uuid::new_v4();
    seed_principal(pool, &tenant_id, principal_id, subject).await?;
    let role_id = seed_role(
        pool,
        &tenant_id,
        principal_id,
        &[
            "secret-providers:read",
            "secret-providers:manage",
            SECRET_METADATA_PERMISSION,
            "secrets:create",
            "secrets:update",
            "secrets:delete",
        ],
    )
    .await?;
    seed_direct_binding(
        pool,
        &tenant_id,
        principal_id,
        role_id,
        (!tenant_grant).then_some(repository_id),
    )
    .await?;
    seed_session(pool, tenant_id, repository_id, principal_id, subject).await
}

async fn seed_repository_permission_actor(
    pool: &PgPool,
    fixture: &Fixture,
    subject: &str,
    permission: &str,
) -> TestResult<Fixture> {
    let principal_id = Uuid::new_v4();
    seed_principal(pool, &fixture.tenant_id, principal_id, subject).await?;
    let role_id = seed_role(pool, &fixture.tenant_id, principal_id, &[permission]).await?;
    seed_direct_binding(
        pool,
        &fixture.tenant_id,
        principal_id,
        role_id,
        Some(fixture.repository_id),
    )
    .await?;
    seed_session(
        pool,
        fixture.tenant_id.clone(),
        fixture.repository_id,
        principal_id,
        subject,
    )
    .await
}

async fn seed_tenant_and_repository(pool: &PgPool, tenant_id: &str) -> TestResult<Uuid> {
    sqlx::query(
        "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Secret tenant', 1, 1)",
    )
    .bind(tenant_id)
    .execute(pool)
    .await?;
    seed_repository(pool, tenant_id).await
}

async fn seed_repository(pool: &PgPool, tenant_id: &str) -> TestResult<Uuid> {
    let repository_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id,
            owner, name, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, 'github', $3, 'automata', $4, 1, 1)
        ",
    )
    .bind(repository_id)
    .bind(tenant_id)
    .bind(repository_id.to_string())
    .bind(format!("secret-{}", repository_id.simple()))
    .execute(pool)
    .await?;
    Ok(repository_id)
}

async fn seed_principal(
    pool: &PgPool,
    tenant_id: &str,
    principal_id: Uuid,
    provider_subject: &str,
) -> TestResult {
    sqlx::query(
        "INSERT INTO human_principals (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Secret actor', 1, 1)",
    )
    .bind(principal_id)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO human_provider_identities (
            principal_id, provider_id, provider_subject, provider_login,
            normalized_login, first_authenticated_at_ms, last_authenticated_at_ms,
            last_observed_at_ms, created_at_ms, updated_at_ms
        ) VALUES ($1, 'github', $2, $3, $3, 1, 1, 1, 1, 1)
        ",
    )
    .bind(principal_id)
    .bind(provider_subject)
    .bind(format!("actor-{}", principal_id.simple()))
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO tenant_human_memberships (tenant_id, principal_id, created_at_ms, updated_at_ms) VALUES ($1, $2, 1, 1)",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn seed_role(
    pool: &PgPool,
    tenant_id: &str,
    principal_id: Uuid,
    permissions: &[&str],
) -> TestResult<Uuid> {
    let role_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO rbac_roles (
            tenant_id, id, name, display_name, role_kind, immutable,
            created_by_principal_id, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, $3, 'Secret manager', 'custom', FALSE, $4, 1, 1)
        ",
    )
    .bind(tenant_id)
    .bind(role_id)
    .bind(format!("secret-manager-{}", role_id.simple()))
    .bind(principal_id)
    .execute(pool)
    .await?;
    for permission in permissions {
        sqlx::query(
            r"
            INSERT INTO rbac_role_permissions (
                tenant_id, role_id, permission_name,
                granted_by_principal_id, granted_at_ms
            ) VALUES ($1, $2, $3, $4, 1)
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .bind(permission)
        .bind(principal_id)
        .execute(pool)
        .await?;
    }
    Ok(role_id)
}

async fn seed_direct_binding(
    pool: &PgPool,
    tenant_id: &str,
    principal_id: Uuid,
    role_id: Uuid,
    repository_scope: Option<Uuid>,
) -> TestResult {
    let (scope_kind, repository_id) = repository_scope.map_or(("tenant", None), |repository_id| {
        ("repository", Some(repository_id))
    });
    sqlx::query(
        r"
        INSERT INTO rbac_role_bindings (
            tenant_id, id, principal_id, role_id, scope_kind, repository_id,
            assignment_source, created_by_principal_id, created_at_ms
        ) VALUES ($1, $2, $3, $4, $5, $6, 'manual', $3, 1)
        ",
    )
    .bind(tenant_id)
    .bind(Uuid::new_v4())
    .bind(principal_id)
    .bind(role_id)
    .bind(scope_kind)
    .bind(repository_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn seed_session(
    pool: &PgPool,
    tenant_id: String,
    repository_id: Uuid,
    principal_id: Uuid,
    provider_subject: &str,
) -> TestResult<Fixture> {
    let revision: i64 = sqlx::query_scalar(
        "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id = $1 AND principal_id = $2",
    )
    .bind(&tenant_id)
    .bind(principal_id)
    .fetch_one(pool)
    .await?;
    let session_id = Uuid::new_v4();
    let mut token_hash = [0_u8; 32];
    token_hash[..16].copy_from_slice(session_id.as_bytes());
    token_hash[16..].copy_from_slice(session_id.as_bytes());
    sqlx::query(
        r"
        INSERT INTO human_sessions (
            id, tenant_id, principal_id, provider_id, provider_subject,
            session_kind, audience, token_hash, token_hash_key_id,
            authorization_revision, issued_at_ms, last_seen_at_ms,
            idle_expires_at_ms, expires_at_ms
        ) VALUES (
            $1, $2, $3, 'github', $4, 'browser', 'automata.web',
            $5, 'secret-session-v1', $6, 90000, 90000, 740000, 750000
        )
        ",
    )
    .bind(session_id)
    .bind(&tenant_id)
    .bind(principal_id)
    .bind(provider_subject)
    .bind(token_hash.as_slice())
    .bind(revision)
    .execute(pool)
    .await?;
    Ok(Fixture {
        tenant_id,
        repository_id,
        principal_id,
        session_id,
        authorization_revision: u64::try_from(revision)?,
    })
}

async fn seed_provider_token(
    pool: &PgPool,
    tenant_id: &str,
    principal_id: Uuid,
    provider_subject: &str,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO human_provider_tokens (
            tenant_id, principal_id, provider_id, provider_subject, version,
            grant_kind, scopes, encrypted_payload, payload_nonce,
            wrapped_data_key, encryption_key_id, encryption_schema,
            issued_at_ms, access_expires_at_ms, refresh_expires_at_ms,
            created_at_ms, updated_at_ms, envelope_record_id, token_type
        ) VALUES (
            $1, $2, 'github', $3, 1, 'browser_authorization_code',
            ARRAY['read:org']::TEXT[], $4, $5, $6, 'github-test-kek-v1', 1,
            1, 300000, NULL, 1, 1, $7, 'bearer'
        )
        ",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .bind(provider_subject)
    .bind(vec![0x41_u8; 32])
    .bind(vec![0x42_u8; 12])
    .bind(vec![0x43_u8; 32])
    .bind(Uuid::new_v4())
    .execute(pool)
    .await?;
    Ok(())
}

async fn seed_github_mapping(
    pool: &PgPool,
    tenant_id: &str,
    role_id: Uuid,
    repository_id: Uuid,
    organization_id: i64,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO github_role_mappings (
            tenant_id, id, provider_id, organization_id, organization_login,
            role_id, scope_kind, repository_id, status, created_at_ms, updated_at_ms
        ) VALUES (
            $1, $2, 'github', $3, 'display-only', $4, 'repository', $5,
            'active', 1, 1
        )
        ",
    )
    .bind(tenant_id)
    .bind(Uuid::new_v4())
    .bind(organization_id)
    .bind(role_id)
    .bind(repository_id)
    .execute(pool)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn seed_github_snapshot(
    pool: &PgPool,
    tenant_id: &str,
    principal_id: Uuid,
    provider_subject: &str,
    observed_at_ms: i64,
    valid_until_ms: i64,
    provider_token_version: i64,
    organization_id: Option<i64>,
) -> TestResult {
    let snapshot_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO github_membership_snapshots (
            tenant_id, id, principal_id, provider_id, provider_subject,
            provider_token_version, observed_at_ms, valid_until_ms
        ) VALUES ($1, $2, $3, 'github', $4, $5, $6, $7)
        ",
    )
    .bind(tenant_id)
    .bind(snapshot_id)
    .bind(principal_id)
    .bind(provider_subject)
    .bind(provider_token_version)
    .bind(observed_at_ms)
    .bind(valid_until_ms)
    .execute(pool)
    .await?;
    if let Some(organization_id) = organization_id {
        sqlx::query(
            r"
            INSERT INTO github_organization_membership_observations (
                tenant_id, snapshot_id, organization_id,
                organization_login, membership_role
            ) VALUES ($1, $2, $3, 'display-only', 'member')
            ",
        )
        .bind(tenant_id)
        .bind(snapshot_id)
        .bind(organization_id)
        .execute(pool)
        .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
async fn stage_encrypted_builtin_version(
    pool: &PgPool,
    fixture: &Fixture,
    secret_id: RepositorySecretId,
    version_id: Uuid,
    version_number: i64,
    expected_predecessor: Option<Uuid>,
    expected_revision: i64,
    create_request_id: &str,
    plaintext: &[u8],
) -> TestResult {
    let mutation_id = create_request_id
        .strip_prefix("secret-version:")
        .ok_or("provider request id did not use the mutation domain")?
        .parse::<Uuid>()?;
    if mutation_id.is_nil() {
        return Err("provider request id used a nil mutation UUID".into());
    }
    let key_id = KeyId::new("secret-management-test-kek-v1")?;
    let key = LocalKeyMaterial::new(key_id.clone(), SecretBytes::new(vec![0x79; 32])?)?;
    let key_provider: Arc<dyn KeyEncryptionProvider> =
        Arc::new(LocalAes256GcmKeyring::new(key, Vec::new(), [])?);
    let custody = PostgresSecretCustodyRepository::new(pool.clone())
        .with_key_encryption_provider(Arc::clone(&key_provider));
    assert!(matches!(
        custody
            .verify_or_create_secret_custody(VerifySecretCustody::configured(
                SecretCustodyKeySet::new(key_id, Vec::new())?,
            ))
            .await?,
        VerifySecretCustodyOutcome::Verified(_)
    ));
    let codec = EnvelopeCodec::new(key_provider);
    let context = KeyEncryptionContext::new(
        &fixture.tenant_id,
        KeyPurpose::new(BUILTIN_VALUE_PURPOSE)?,
        version_id.hyphenated().to_string(),
    )?;
    let envelope = codec
        .seal(&context, SecretBytes::new(plaintext.to_vec())?)
        .await?;
    let (schema, wrapped, nonce, ciphertext) = envelope.into_parts();
    let (key_id, wrapped_data_key) = wrapped.into_parts();
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r"
        INSERT INTO secret_versions (
            tenant_id, id, secret_id, version_number, provider_id,
            create_request_id, storage_kind, created_by_principal_id, created_at_ms
        ) VALUES ($1, $2, $3, $4, 'builtin', $5, 'built_in_ciphertext', $6, 100000)
        ",
    )
    .bind(&fixture.tenant_id)
    .bind(version_id)
    .bind(secret_id.as_uuid())
    .bind(version_number)
    .bind(create_request_id)
    .bind(fixture.principal_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_version_lifecycle (
            tenant_id, secret_version_id, secret_id, version_number,
            provider_id, mutation_id, status, revision,
            changed_by_principal_id, changed_at_ms
        ) VALUES ($1, $2, $3, $4, 'builtin', $5, 'staged', 1, $6, 100000)
        ",
    )
    .bind(&fixture.tenant_id)
    .bind(version_id)
    .bind(secret_id.as_uuid())
    .bind(version_number)
    .bind(mutation_id)
    .bind(fixture.principal_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_version_envelopes (
            tenant_id, secret_version_id, secret_id, version_number,
            storage_kind, envelope_generation, ciphertext, nonce,
            wrapped_data_key, wrapping_key_id, envelope_schema, created_at_ms
        ) VALUES (
            $1, $2, $3, $4, 'built_in_ciphertext', 1, $5, $6, $7, $8, $9, 100000
        )
        ",
    )
    .bind(&fixture.tenant_id)
    .bind(version_id)
    .bind(secret_id.as_uuid())
    .bind(version_number)
    .bind(ciphertext)
    .bind(nonce.as_slice())
    .bind(wrapped_data_key)
    .bind(key_id.as_str())
    .bind(i32::from(schema))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_version_envelope_heads (
            tenant_id, secret_version_id, envelope_generation, revision, updated_at_ms
        ) VALUES ($1, $2, 1, 1, 100000)
        ",
    )
    .bind(&fixture.tenant_id)
    .bind(version_id)
    .execute(&mut *transaction)
    .await?;
    let unchanged: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1 FROM secrets
            WHERE tenant_id = $1 AND id = $2 AND revision = $3
              AND current_version_id IS NOT DISTINCT FROM $4
              AND (
                  ($4::UUID IS NULL AND status = 'provisioning')
                  OR ($4::UUID IS NOT NULL AND status = 'active')
              )
        )
        ",
    )
    .bind(&fixture.tenant_id)
    .bind(secret_id.as_uuid())
    .bind(expected_revision)
    .bind(expected_predecessor)
    .fetch_one(&mut *transaction)
    .await?;
    if !unchanged {
        return Err("provider staging changed or lost the logical head".into());
    }
    transaction.commit().await?;
    Ok(())
}

async fn simulate_builtin_cryptographic_erasure(
    pool: &PgPool,
    tenant_id: &str,
    version_id: Uuid,
    completed_at_ms: i64,
) -> TestResult {
    let mut transaction: Transaction<'_, Postgres> = pool.begin().await?;
    sqlx::query(
        "DELETE FROM secret_version_envelope_heads WHERE tenant_id = $1 AND secret_version_id = $2",
    )
    .bind(tenant_id)
    .bind(version_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "DELETE FROM secret_version_envelopes WHERE tenant_id = $1 AND secret_version_id = $2",
    )
    .bind(tenant_id)
    .bind(version_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        UPDATE secret_version_lifecycle
        SET status = 'destroyed', revision = revision + 1,
            changed_at_ms = $3, destroyed_at_ms = $3
        WHERE tenant_id = $1 AND secret_version_id = $2
          AND status = 'destroy_pending'
        ",
    )
    .bind(tenant_id)
    .bind(version_id)
    .bind(completed_at_ms)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}

fn assert_sql_constraint(error: &sqlx::Error, expected: &str) {
    let sqlx::Error::Database(database) = error else {
        panic!("expected database constraint {expected}, got {error:?}");
    };
    assert_eq!(database.constraint(), Some(expected));
}

async fn wait_for_backend_blocked_by(
    pool: &PgPool,
    blocking_backend_pid: i32,
    query_fragment: &str,
) -> TestResult<i32> {
    for _ in 0..500 {
        let waiting_backend_pid: Option<i32> = sqlx::query_scalar(
            r"
            SELECT pid
            FROM pg_stat_activity
            WHERE datname = current_database()
              AND pid <> $1
              AND $1 = ANY(pg_blocking_pids(pid))
              AND query LIKE '%' || $2 || '%'
            ORDER BY pid
            LIMIT 1
            ",
        )
        .bind(blocking_backend_pid)
        .bind(query_fragment)
        .fetch_optional(pool)
        .await?;
        if let Some(waiting_backend_pid) = waiting_backend_pid {
            return Ok(waiting_backend_pid);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("backend did not block on expected {query_fragment} lock").into())
}
