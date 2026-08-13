use std::sync::Arc;

use automata_ci_auth::{
    human::{PrincipalId, TenantId},
    management::{ManagementActor, ManagementRevision},
    session::SessionId,
    time::UnixTimestamp,
};
use automata_ci_key_management::{KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes};
use automata_ci_secret::{
    CreateSecretVersionRequest, CreatedSecretVersion, DestroySecretVersionRequest,
    ExistingSecretVersion, ProviderErrorKind, ProviderHealth, ProviderOperationContext,
    ProviderRequestId, ProviderSecretLocator, ProviderVersionId,
    ReconcileCreateSecretVersionOutcome, ReconcileCreateSecretVersionRequest, RepositoryScopeId,
    ResolveSecretVersionRequest, SecretDescriptor, SecretId, SecretName, SecretProvider,
    SecretScope, SecretValue, TenantScopeId, WorkloadContext, WorkloadId,
};
use automata_ci_secret_postgres::PostgresSecretProvider;
use automata_ci_store::{
    ActivateBuiltinSecretProvider, ActivateBuiltinSecretProviderOutcome,
    BuiltinRepositorySecretVersion, BuiltinSecretCleanupRepository, BuiltinSecretCleanupTask,
    ClaimBuiltinSecretCleanup, ClaimBuiltinSecretCleanupOutcome, CompleteBuiltinSecretCleanup,
    CompleteBuiltinSecretCleanupOutcome, ConfirmRepositorySecretVersionMutation,
    ConfirmRepositorySecretVersionMutationOutcome, DeleteRepositorySecret,
    DeleteRepositorySecretOutcome, PostgresSecretCustodyRepository,
    PostgresSecretManagementRepository, RepositoryId, RepositorySecretId,
    RepositorySecretManagementRepository, RepositorySecretMutationId, RepositorySecretName,
    RepositorySecretProviderMutationResult, RepositorySecretVersionId,
    RepositorySecretVersionMutationReservation, ReserveRepositorySecretVersionMutation,
    ReserveRepositorySecretVersionMutationOutcome, SecretCleanupWorkerId, SecretCustodyKeySet,
    SecretCustodyRepository as _, VerifySecretCustody, VerifySecretCustodyOutcome,
};
use sqlx::PgPool;
use uuid::Uuid;

use super::support::{TestResult, run_with_database};

const FIRST_SENTINEL: &[u8] = b"first-plaintext-db-sentinel-3be018c4d4024e02";
const RETRY_SENTINEL: &[u8] = b"retry-plaintext-db-sentinel-79501d2437624b62";
const SECOND_SENTINEL: &[u8] = b"second-plaintext-db-sentinel-7d0140dc30ce4a3e";
const TEST_KEY_ID: &str = "secret-kek-v1";

#[allow(clippy::struct_field_names)] // The suffix distinguishes unrelated durable identities.
struct Fixture {
    tenant_id: String,
    repository_id: Uuid,
    principal_id: Uuid,
    session_id: Uuid,
    authorization_revision: u64,
    now_ms: i64,
}

impl Fixture {
    fn actor(&self) -> ManagementActor {
        ManagementActor::new(
            TenantId::new(&self.tenant_id).expect("tenant ID"),
            PrincipalId::new(self.principal_id.hyphenated().to_string()).expect("principal ID"),
            SessionId::new(self.session_id.hyphenated().to_string()).expect("session ID"),
            ManagementRevision::new(self.authorization_revision).expect("authorization revision"),
            None,
            UnixTimestamp::from_seconds(
                u64::try_from(self.now_ms / 1_000).expect("positive fixture time"),
            ),
        )
    }
}

fn keyring() -> Arc<LocalAes256GcmKeyring> {
    let material = LocalKeyMaterial::new(
        KeyId::new(TEST_KEY_ID).expect("key ID"),
        SecretBytes::new(vec![0x5a; 32]).expect("key bytes"),
    )
    .expect("key material");
    Arc::new(LocalAes256GcmKeyring::new(material, Vec::new(), []).expect("keyring"))
}

fn operation(tenant_id: &str, request_id: &str) -> ProviderOperationContext {
    ProviderOperationContext::new(
        TenantScopeId::new(tenant_id).expect("tenant ID"),
        ProviderRequestId::new(request_id).expect("request ID"),
    )
}

fn descriptor(fixture: &Fixture, secret_id: Uuid) -> SecretDescriptor {
    SecretDescriptor::new(
        SecretId::new(secret_id.hyphenated().to_string()).expect("secret ID"),
        SecretName::new("release_token").expect("secret name"),
        SecretScope::repository(
            TenantScopeId::new(&fixture.tenant_id).expect("tenant ID"),
            RepositoryScopeId::new(fixture.repository_id.hyphenated().to_string())
                .expect("repository ID"),
        ),
    )
}

fn create_request(
    fixture: &Fixture,
    secret_id: Uuid,
    request_id: &str,
    expected_existing_version: Option<ExistingSecretVersion>,
    value: &[u8],
) -> CreateSecretVersionRequest {
    CreateSecretVersionRequest::new(
        operation(&fixture.tenant_id, request_id),
        descriptor(fixture, secret_id),
        expected_existing_version,
        SecretValue::new(value.to_vec()).expect("secret value"),
    )
    .expect("create request")
}

fn reconcile_request(
    fixture: &Fixture,
    secret_id: Uuid,
    request_id: &str,
    expected_existing_version: Option<ExistingSecretVersion>,
) -> ReconcileCreateSecretVersionRequest {
    ReconcileCreateSecretVersionRequest::new(
        operation(&fixture.tenant_id, request_id),
        descriptor(fixture, secret_id),
        expected_existing_version,
    )
    .expect("reconciliation request")
}

fn resolve_request(
    fixture: &Fixture,
    secret_id: Uuid,
    created: &CreatedSecretVersion,
) -> ResolveSecretVersionRequest {
    ResolveSecretVersionRequest::new(
        operation(
            &fixture.tenant_id,
            &format!("resolve-{}", Uuid::new_v4().simple()),
        ),
        WorkloadContext::new(
            WorkloadId::new(Uuid::new_v4().hyphenated().to_string()).expect("workload ID"),
            SecretScope::repository(
                TenantScopeId::new(&fixture.tenant_id).expect("tenant ID"),
                RepositoryScopeId::new(fixture.repository_id.hyphenated().to_string())
                    .expect("repository ID"),
            ),
        )
        .expect("workload"),
        descriptor(fixture, secret_id),
        created.locator().clone(),
        created.version().clone(),
    )
    .expect("resolve request")
}

fn cleanup_destroy_request(
    task: &BuiltinSecretCleanupTask,
) -> TestResult<DestroySecretVersionRequest> {
    let tenant = TenantScopeId::new(task.tenant().as_str())?;
    let descriptor = SecretDescriptor::new(
        SecretId::new(task.secret_id().as_uuid().hyphenated().to_string())?,
        SecretName::new(task.name().as_str())?,
        SecretScope::repository(
            tenant.clone(),
            RepositoryScopeId::new(task.repository_id().as_uuid().hyphenated().to_string())?,
        ),
    );
    Ok(DestroySecretVersionRequest::new(
        ProviderOperationContext::new(
            tenant,
            ProviderRequestId::new(task.provider_destroy_request_id())?,
        ),
        descriptor,
        ProviderSecretLocator::new(task.secret_id().as_uuid().hyphenated().to_string())?,
        ProviderVersionId::new(task.secret_version_id().hyphenated().to_string())?,
    )?)
}

fn target(
    secret_id: Uuid,
    created: &CreatedSecretVersion,
    version_number: u64,
) -> TestResult<BuiltinRepositorySecretVersion> {
    Ok(BuiltinRepositorySecretVersion::new(
        RepositorySecretId::from_uuid(secret_id)?,
        RepositorySecretVersionId::from_uuid(Uuid::parse_str(created.version().as_str())?)?,
        version_number,
    )?)
}

fn provider(pool: &PgPool) -> PostgresSecretProvider {
    PostgresSecretProvider::new(
        pool.clone(),
        keyring() as Arc<dyn automata_ci_key_management::KeyEncryptionProvider>,
    )
}

#[allow(clippy::too_many_lines)] // The fixture spells out every RBAC/session row explicitly.
async fn seed_fixture(pool: &PgPool) -> TestResult<Fixture> {
    let database_now_ms: i64 =
        sqlx::query_scalar("SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(pool)
            .await?;
    let now_ms = (database_now_ms / 1_000) * 1_000;
    let tenant_id = format!("secret-provider-{}", Uuid::new_v4().simple());
    let repository_id = Uuid::new_v4();
    let principal_id = Uuid::new_v4();
    let provider_subject = format!("provider-subject-{}", principal_id.simple());
    sqlx::query(
        "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Secret provider test', 1, 1)",
    )
    .bind(&tenant_id)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id,
            owner, name, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, 'github', $3, 'automata', $4, 1, 1)
        ",
    )
    .bind(repository_id)
    .bind(&tenant_id)
    .bind(repository_id.to_string())
    .bind(format!("secret-{}", repository_id.simple()))
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO human_principals (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Secret provider actor', 1, 1)",
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
    .bind(&provider_subject)
    .bind(format!("actor-{}", principal_id.simple()))
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO tenant_human_memberships (tenant_id, principal_id, created_at_ms, updated_at_ms) VALUES ($1, $2, 1, 1)",
    )
    .bind(&tenant_id)
    .bind(principal_id)
    .execute(pool)
    .await?;
    let role_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO rbac_roles (
            tenant_id, id, name, display_name, role_kind, immutable,
            created_by_principal_id, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, $3, 'Secret provider manager', 'custom', FALSE, $4, 1, 1)
        ",
    )
    .bind(&tenant_id)
    .bind(role_id)
    .bind(format!("secret-manager-{}", role_id.simple()))
    .bind(principal_id)
    .execute(pool)
    .await?;
    for permission in [
        "secret-providers:manage",
        "secrets:create",
        "secrets:update",
        "secrets:delete",
    ] {
        sqlx::query(
            r"
            INSERT INTO rbac_role_permissions (
                tenant_id, role_id, permission_name,
                granted_by_principal_id, granted_at_ms
            ) VALUES ($1, $2, $3, $4, 1)
            ",
        )
        .bind(&tenant_id)
        .bind(role_id)
        .bind(permission)
        .bind(principal_id)
        .execute(pool)
        .await?;
    }
    sqlx::query(
        r"
        INSERT INTO rbac_role_bindings (
            tenant_id, id, principal_id, role_id, scope_kind,
            assignment_source, created_by_principal_id, created_at_ms
        ) VALUES ($1, $2, $3, $4, 'tenant', 'manual', $3, 1)
        ",
    )
    .bind(&tenant_id)
    .bind(Uuid::new_v4())
    .bind(principal_id)
    .bind(role_id)
    .execute(pool)
    .await?;
    let authorization_revision: i64 = sqlx::query_scalar(
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
            $5, 'secret-session-v1', $6, $7, $7, $8, $9
        )
        ",
    )
    .bind(session_id)
    .bind(&tenant_id)
    .bind(principal_id)
    .bind(provider_subject)
    .bind(token_hash.as_slice())
    .bind(authorization_revision)
    .bind(now_ms - 10_000)
    .bind(now_ms + 100_000)
    .bind(now_ms + 200_000)
    .execute(pool)
    .await?;
    let custody_key_id = KeyId::new(TEST_KEY_ID)?;
    let custody =
        PostgresSecretCustodyRepository::new(pool.clone()).with_key_encryption_provider(keyring());
    assert!(matches!(
        custody
            .verify_or_create_secret_custody(VerifySecretCustody::configured(
                SecretCustodyKeySet::new(custody_key_id, Vec::new())?,
            ))
            .await?,
        VerifySecretCustodyOutcome::Verified(_)
    ));
    Ok(Fixture {
        tenant_id,
        repository_id,
        principal_id,
        session_id,
        authorization_revision: u64::try_from(authorization_revision)?,
        now_ms,
    })
}

async fn activate_provider(
    management: &PostgresSecretManagementRepository,
    fixture: &Fixture,
) -> TestResult {
    let outcome = management
        .activate_builtin_secret_provider(ActivateBuiltinSecretProvider::new(
            fixture.actor(),
            ManagementRevision::new(1)?,
        ))
        .await?;
    if !matches!(outcome, ActivateBuiltinSecretProviderOutcome::Activated(_)) {
        return Err("built-in secret provider was not activated".into());
    }
    Ok(())
}

async fn reserve_create(
    management: &PostgresSecretManagementRepository,
    fixture: &Fixture,
    secret_id: Uuid,
    mutation_id: Uuid,
) -> TestResult<RepositorySecretVersionMutationReservation> {
    let secret_id = RepositorySecretId::from_uuid(secret_id)?;
    let mutation_id = RepositorySecretMutationId::from_uuid(mutation_id, secret_id)?;
    let request = ReserveRepositorySecretVersionMutation::create(
        fixture.actor(),
        mutation_id,
        secret_id,
        RepositoryId::from_uuid(fixture.repository_id),
        RepositorySecretName::new("release_token")?,
        None,
    )?;
    let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(reservation) = management
        .reserve_repository_secret_version_mutation(request)
        .await?
    else {
        return Err("secret create mutation was not reserved".into());
    };
    Ok(reservation)
}

async fn reserve_replace(
    management: &PostgresSecretManagementRepository,
    fixture: &Fixture,
    secret_id: Uuid,
    mutation_id: Uuid,
    expected_revision: u64,
) -> TestResult<RepositorySecretVersionMutationReservation> {
    let secret_id = RepositorySecretId::from_uuid(secret_id)?;
    let mutation_id = RepositorySecretMutationId::from_uuid(mutation_id, secret_id)?;
    let request = ReserveRepositorySecretVersionMutation::replace(
        fixture.actor(),
        mutation_id,
        secret_id,
        RepositoryId::from_uuid(fixture.repository_id),
        RepositorySecretName::new("release_token")?,
        ManagementRevision::new(expected_revision)?,
    )?;
    let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(reservation) = management
        .reserve_repository_secret_version_mutation(request)
        .await?
    else {
        return Err("secret replacement mutation was not reserved".into());
    };
    Ok(reservation)
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // One scenario checks staging, replay, encryption, and promotion.
async fn encrypted_create_stays_unresolvable_until_management_confirmation() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(database.pool()).await?;
        let management = PostgresSecretManagementRepository::new(database.pool().clone());
        activate_provider(&management, &fixture).await?;
        let provider = provider(database.pool());
        assert_eq!(
            provider
                .health(&operation(&fixture.tenant_id, "health-check"))
                .await?,
            ProviderHealth::Healthy
        );

        let secret_id = Uuid::new_v4();
        let noncanonical_id = Uuid::new_v4();
        for invalid_request_id in [
            "create-canonical".to_owned(),
            "secret-version:00000000-0000-0000-0000-000000000000".to_owned(),
            format!("secret-version:{}", noncanonical_id.simple()),
            format!(
                "secret-version:{}",
                noncanonical_id.hyphenated().to_string().to_uppercase()
            ),
        ] {
            let invalid = create_request(
                &fixture,
                secret_id,
                &invalid_request_id,
                None,
                FIRST_SENTINEL,
            );
            assert_eq!(
                provider.create_version(invalid).await.unwrap_err().kind(),
                ProviderErrorKind::InvalidRequest
            );
        }

        let mutation_id = Uuid::new_v4();
        let reservation = reserve_create(&management, &fixture, secret_id, mutation_id).await?;
        let request_id = reservation.provider_create_request_id();
        let (left, right) = tokio::join!(
            provider.create_version(create_request(
                &fixture,
                secret_id,
                request_id,
                None,
                FIRST_SENTINEL,
            )),
            provider.create_version(create_request(
                &fixture,
                secret_id,
                request_id,
                None,
                FIRST_SENTINEL,
            )),
        );
        let created = left?;
        assert_eq!(created, right?);
        let ReconcileCreateSecretVersionOutcome::AlreadyCommitted(staged_reconciliation) = provider
            .reconcile_create_version(reconcile_request(&fixture, secret_id, request_id, None))
            .await?
        else {
            return Err("durable staged version reconciled as absent".into());
        };
        assert_eq!(staged_reconciliation, created);
        let version_id = Uuid::parse_str(created.version().as_str())?;
        let durable: (String, Option<Uuid>, Option<i64>, i64, String, Option<Uuid>) =
            sqlx::query_as(
                r"
                SELECT secret.status, secret.current_version_id,
                       secret.current_version_number, secret.revision,
                       lifecycle.status, lifecycle.mutation_id
                FROM secrets AS secret
                JOIN secret_version_lifecycle AS lifecycle
                  ON lifecycle.tenant_id = secret.tenant_id
                 AND lifecycle.secret_id = secret.id
                WHERE secret.tenant_id = $1 AND secret.id = $2
                ",
            )
            .bind(&fixture.tenant_id)
            .bind(secret_id)
            .fetch_one(database.pool())
            .await?;
        assert_eq!(
            durable,
            (
                "provisioning".into(),
                None,
                None,
                1,
                "staged".into(),
                Some(mutation_id),
            )
        );
        assert_eq!(
            provider
                .resolve_version(resolve_request(&fixture, secret_id, &created))
                .await
                .unwrap_err()
                .kind(),
            ProviderErrorKind::NotFound
        );

        let envelope_before: (Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
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
        let replay = provider
            .create_version(create_request(
                &fixture,
                secret_id,
                request_id,
                None,
                RETRY_SENTINEL,
            ))
            .await?;
        assert_eq!(created, replay);
        let envelope_after: (Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
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
        assert_eq!(envelope_before, envelope_after);
        for bytes in [&envelope_after.0, &envelope_after.1, &envelope_after.2] {
            assert!(
                !bytes
                    .windows(FIRST_SENTINEL.len())
                    .any(|window| window == FIRST_SENTINEL)
            );
            assert!(
                !bytes
                    .windows(RETRY_SENTINEL.len())
                    .any(|window| window == RETRY_SENTINEL)
            );
        }

        let committed = target(secret_id, &created, 1)?;
        let confirmation = management
            .confirm_repository_secret_version_mutation(
                ConfirmRepositorySecretVersionMutation::new(
                    fixture.actor(),
                    RepositorySecretMutationId::from_uuid(
                        mutation_id,
                        RepositorySecretId::from_uuid(secret_id)?,
                    )?,
                    RepositorySecretProviderMutationResult::BuiltinCreated(committed),
                ),
            )
            .await?;
        assert!(matches!(
            confirmation,
            ConfirmRepositorySecretVersionMutationOutcome::Applied(_)
        ));
        let ReconcileCreateSecretVersionOutcome::AlreadyCommitted(committed_reconciliation) =
            provider
                .reconcile_create_version(reconcile_request(&fixture, secret_id, request_id, None))
                .await?
        else {
            return Err("committed version reconciled as absent".into());
        };
        assert_eq!(committed_reconciliation, created);
        assert_eq!(
            provider
                .resolve_version(resolve_request(&fixture, secret_id, &created))
                .await?
                .value()
                .expose_secret(),
            FIRST_SENTINEL
        );
        let promoted: (String, Uuid, i64, i64, String, Option<Uuid>) = sqlx::query_as(
            r"
            SELECT secret.status, secret.current_version_id,
                   secret.current_version_number, secret.revision,
                   lifecycle.status, lifecycle.mutation_id
            FROM secrets AS secret
            JOIN secret_version_lifecycle AS lifecycle
              ON lifecycle.tenant_id = secret.tenant_id
             AND lifecycle.secret_version_id = secret.current_version_id
            WHERE secret.tenant_id = $1 AND secret.id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(secret_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            promoted,
            (
                "active".into(),
                version_id,
                1,
                2,
                "active".into(),
                Some(mutation_id)
            )
        );

        let DeleteRepositorySecretOutcome::Deleted(deletion) = management
            .delete_repository_secret(DeleteRepositorySecret::new(
                fixture.actor(),
                RepositoryId::from_uuid(fixture.repository_id),
                RepositorySecretId::from_uuid(secret_id)?,
                ManagementRevision::new(2)?,
            )?)
            .await?
        else {
            return Err("confirmed secret was not scheduled for cleanup".into());
        };
        assert_eq!(deletion.cleanup_operations(), 1);
        let claim = management
            .claim_builtin_secret_cleanup(ClaimBuiltinSecretCleanup::new(
                SecretCleanupWorkerId::new("provider-cleanup-worker")?,
                (fixture.now_ms + 1_000).into(),
                60_000,
            )?)
            .await?;
        let ClaimBuiltinSecretCleanupOutcome::Claimed(task) = claim else {
            return Err("provider cleanup task was not claimed".into());
        };
        assert_eq!(task.tenant().as_str(), fixture.tenant_id);

        provider
            .destroy_version(cleanup_destroy_request(&task)?)
            .await?;
        provider
            .destroy_version(cleanup_destroy_request(&task)?)
            .await?;
        assert_eq!(
            management
                .complete_builtin_secret_cleanup(CompleteBuiltinSecretCleanup::new(
                    task.fence().clone(),
                    (fixture.now_ms + 1_100).into(),
                )?)
                .await?,
            CompleteBuiltinSecretCleanupOutcome::Completed,
        );
        let cleanup_state: (String, String, i64) = sqlx::query_as(
            r"
            SELECT lifecycle.status, outbox.status,
                   (SELECT count(*) FROM secret_version_envelopes
                    WHERE tenant_id = $1 AND secret_version_id = $2)
            FROM secret_version_lifecycle AS lifecycle
            JOIN secret_cleanup_outbox AS outbox
              ON outbox.tenant_id = lifecycle.tenant_id
             AND outbox.secret_version_id = lifecycle.secret_version_id
            WHERE lifecycle.tenant_id = $1
              AND lifecycle.secret_version_id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(version_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(cleanup_state, ("destroyed".into(), "completed".into(), 0));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // One scenario checks predecessor, CAS, replay, and promotion.
async fn replacement_stage_preserves_predecessor_until_atomic_confirmation() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(database.pool()).await?;
        let management = PostgresSecretManagementRepository::new(database.pool().clone());
        activate_provider(&management, &fixture).await?;
        let provider = provider(database.pool());
        let secret_id = Uuid::new_v4();
        let create_mutation = Uuid::new_v4();
        let create = reserve_create(&management, &fixture, secret_id, create_mutation).await?;
        let first = provider
            .create_version(create_request(
                &fixture,
                secret_id,
                create.provider_create_request_id(),
                None,
                FIRST_SENTINEL,
            ))
            .await?;
        let first_target = target(secret_id, &first, 1)?;
        let created = management
            .confirm_repository_secret_version_mutation(
                ConfirmRepositorySecretVersionMutation::new(
                    fixture.actor(),
                    RepositorySecretMutationId::from_uuid(
                        create_mutation,
                        RepositorySecretId::from_uuid(secret_id)?,
                    )?,
                    RepositorySecretProviderMutationResult::BuiltinCreated(first_target),
                ),
            )
            .await?;
        assert!(matches!(
            created,
            ConfirmRepositorySecretVersionMutationOutcome::Applied(_)
        ));
        let predecessor =
            ExistingSecretVersion::new(first.locator().clone(), first.version().clone());
        let predecessor_id = Uuid::parse_str(first.version().as_str())?;

        let first_mutation = Uuid::new_v4();
        let second_mutation = Uuid::new_v4();
        let (first_reservation, second_reservation) = tokio::join!(
            reserve_replace(&management, &fixture, secret_id, first_mutation, 2),
            reserve_replace(&management, &fixture, secret_id, second_mutation, 2),
        );
        let first_reservation = first_reservation?;
        let second_reservation = second_reservation?;
        let (first_mutation, first_reservation, second_mutation, second_reservation) =
            if first_reservation.reserved_version_number()
                > second_reservation.reserved_version_number()
            {
                (
                    first_mutation,
                    first_reservation,
                    second_mutation,
                    second_reservation,
                )
            } else {
                (
                    second_mutation,
                    second_reservation,
                    first_mutation,
                    first_reservation,
                )
            };
        assert_eq!(first_reservation.expected_predecessor(), Some(first_target));
        assert_eq!(
            second_reservation.expected_predecessor(),
            Some(first_target)
        );
        assert!(
            first_reservation.reserved_version_number()
                > second_reservation.reserved_version_number(),
            "the exercised provider winner must leave a burned ordinal gap"
        );

        let wrong_predecessor = ExistingSecretVersion::new(
            first.locator().clone(),
            ProviderVersionId::new(Uuid::new_v4().hyphenated().to_string())?,
        );
        let wrong_intent = provider
            .reconcile_create_version(reconcile_request(
                &fixture,
                secret_id,
                first_reservation.provider_create_request_id(),
                Some(wrong_predecessor),
            ))
            .await
            .expect_err("replacement reconciliation must bind the exact predecessor");
        assert_eq!(wrong_intent.kind(), ProviderErrorKind::Conflict);
        let live_absence = provider
            .reconcile_create_version(reconcile_request(
                &fixture,
                secret_id,
                first_reservation.provider_create_request_id(),
                Some(predecessor.clone()),
            ))
            .await
            .expect_err("a live replacement reservation remains ambiguous");
        assert_eq!(live_absence.kind(), ProviderErrorKind::Unavailable);

        let staged = provider
            .create_version(create_request(
                &fixture,
                secret_id,
                first_reservation.provider_create_request_id(),
                Some(predecessor.clone()),
                SECOND_SENTINEL,
            ))
            .await?;
        let ReconcileCreateSecretVersionOutcome::AlreadyCommitted(reconciled_stage) = provider
            .reconcile_create_version(reconcile_request(
                &fixture,
                secret_id,
                first_reservation.provider_create_request_id(),
                Some(predecessor.clone()),
            ))
            .await?
        else {
            return Err("staged replacement reconciled as absent".into());
        };
        assert_eq!(reconciled_stage, staged);
        let staged_id = Uuid::parse_str(staged.version().as_str())?;
        let durable: (Uuid, i64, i64, String, String, Uuid) = sqlx::query_as(
            r"
            SELECT secret.current_version_id, secret.current_version_number,
                   secret.revision, predecessor.status, candidate.status,
                   candidate.mutation_id
            FROM secrets AS secret
            JOIN secret_version_lifecycle AS predecessor
              ON predecessor.tenant_id = secret.tenant_id
             AND predecessor.secret_version_id = secret.current_version_id
            JOIN secret_version_lifecycle AS candidate
              ON candidate.tenant_id = secret.tenant_id
             AND candidate.secret_id = secret.id
             AND candidate.status = 'staged'
            WHERE secret.tenant_id = $1 AND secret.id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(secret_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            durable,
            (
                predecessor_id,
                1,
                2,
                "active".into(),
                "staged".into(),
                first_mutation,
            )
        );
        assert_eq!(
            provider
                .resolve_version(resolve_request(&fixture, secret_id, &staged))
                .await
                .unwrap_err()
                .kind(),
            ProviderErrorKind::NotFound
        );
        let destroy = DestroySecretVersionRequest::new(
            operation(
                &fixture.tenant_id,
                &format!("destroy-staged:{}", Uuid::new_v4().hyphenated()),
            ),
            descriptor(&fixture, secret_id),
            staged.locator().clone(),
            staged.version().clone(),
        )?;
        assert_eq!(
            provider.destroy_version(destroy).await.unwrap_err().kind(),
            ProviderErrorKind::Conflict
        );
        assert_eq!(
            provider
                .create_version(create_request(
                    &fixture,
                    secret_id,
                    second_reservation.provider_create_request_id(),
                    Some(predecessor.clone()),
                    RETRY_SENTINEL,
                ))
                .await
                .unwrap_err()
                .kind(),
            ProviderErrorKind::Conflict
        );
        let replay = provider
            .create_version(create_request(
                &fixture,
                secret_id,
                first_reservation.provider_create_request_id(),
                Some(predecessor),
                FIRST_SENTINEL,
            ))
            .await?;
        assert_eq!(staged, replay);

        let staged_target = target(
            secret_id,
            &staged,
            first_reservation.reserved_version_number(),
        )?;
        let confirmation = management
            .confirm_repository_secret_version_mutation(
                ConfirmRepositorySecretVersionMutation::new(
                    fixture.actor(),
                    RepositorySecretMutationId::from_uuid(
                        first_mutation,
                        RepositorySecretId::from_uuid(secret_id)?,
                    )?,
                    RepositorySecretProviderMutationResult::BuiltinCreated(staged_target),
                ),
            )
            .await?;
        assert!(matches!(
            confirmation,
            ConfirmRepositorySecretVersionMutationOutcome::Applied(_)
        ));
        let ReconcileCreateSecretVersionOutcome::AlreadyCommitted(reconciled_commit) = provider
            .reconcile_create_version(reconcile_request(
                &fixture,
                secret_id,
                first_reservation.provider_create_request_id(),
                Some(ExistingSecretVersion::new(
                    first.locator().clone(),
                    first.version().clone(),
                )),
            ))
            .await?
        else {
            return Err("committed replacement reconciled as absent".into());
        };
        assert_eq!(reconciled_commit, staged);
        assert_eq!(
            management
                .confirm_repository_secret_version_mutation(
                    ConfirmRepositorySecretVersionMutation::new(
                        fixture.actor(),
                        RepositorySecretMutationId::from_uuid(
                            second_mutation,
                            RepositorySecretId::from_uuid(secret_id)?,
                        )?,
                        RepositorySecretProviderMutationResult::CasLost,
                    ),
                )
                .await?,
            ConfirmRepositorySecretVersionMutationOutcome::CasLost
        );
        let promoted: (Uuid, i64, i64, String, String, Option<Uuid>) = sqlx::query_as(
            r"
            SELECT secret.current_version_id, secret.current_version_number,
                   secret.revision, predecessor.status, candidate.status,
                   candidate.mutation_id
            FROM secrets AS secret
            JOIN secret_version_lifecycle AS predecessor
              ON predecessor.tenant_id = secret.tenant_id
             AND predecessor.secret_version_id = $3
            JOIN secret_version_lifecycle AS candidate
              ON candidate.tenant_id = secret.tenant_id
             AND candidate.secret_version_id = secret.current_version_id
            WHERE secret.tenant_id = $1 AND secret.id = $2
            ",
        )
        .bind(&fixture.tenant_id)
        .bind(secret_id)
        .bind(predecessor_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            promoted,
            (
                staged_id,
                i64::try_from(first_reservation.reserved_version_number())?,
                3,
                "superseded".into(),
                "active".into(),
                Some(first_mutation),
            )
        );
        assert_eq!(
            provider
                .resolve_version(resolve_request(&fixture, secret_id, &first))
                .await?
                .value()
                .expose_secret(),
            FIRST_SENTINEL
        );
        assert_eq!(
            provider
                .resolve_version(resolve_request(&fixture, secret_id, &staged))
                .await?
                .value()
                .expose_secret(),
            SECOND_SENTINEL
        );
        Ok(())
    })
    .await
}
