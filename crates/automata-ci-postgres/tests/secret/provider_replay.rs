use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use automata_ci_key_management::{
    KeyEncryptionContext, KeyEncryptionError, KeyEncryptionProvider, KeyId, LocalAes256GcmKeyring,
    LocalKeyMaterial, SecretBytes, WrappedDataKey,
};
use automata_ci_postgres::test_support::TestClock;
use automata_ci_secret::{
    CreateSecretVersionRequest, CreatedSecretVersion, ExistingSecretVersion, ProviderCapability,
    ProviderErrorKind, ProviderOperationContext, ProviderRequestId, ProviderSecretLocator,
    ProviderVersionId, ReconcileCreateSecretVersionOutcome, ReconcileCreateSecretVersionRequest,
    RepositoryScopeId, SecretDescriptor, SecretId, SecretName, SecretProvider, SecretScope,
    SecretValue, TenantScopeId,
};
use automata_ci_secret_postgres::PostgresSecretProvider;
use automata_ci_store::{
    SECRET_MUTATION_CONFIRMATION_TTL_MILLIS, SecretCustodyKeySet, SecretCustodyRepository as _,
    VerifySecretCustody, VerifySecretCustodyOutcome,
};
use automata_ci_store_postgres::PostgresSecretCustodyRepository;
use sqlx::PgPool;
use uuid::Uuid;

use crate::support::{TestResult, run_with_database};

const FIRST_VALUE: &[u8] = b"first-replay-value-3f5bfd0ea8df4ce5";
const SECOND_VALUE: &[u8] = b"second-replay-value-b9df4ed5e123453e";
const REPLAY_KEY_ID: &str = "secret-replay-kek-v1";

fn confirmation_ttl_millis() -> i64 {
    i64::try_from(SECRET_MUTATION_CONFIRMATION_TTL_MILLIS).expect("confirmation lifetime fits i64")
}

#[derive(Debug)]
struct OneShotKeyProvider {
    inner: LocalAes256GcmKeyring,
    wrap_calls: AtomicUsize,
}

impl OneShotKeyProvider {
    fn new() -> Self {
        let key = LocalKeyMaterial::new(
            KeyId::new(REPLAY_KEY_ID).expect("key ID"),
            SecretBytes::new(vec![0x5d; 32]).expect("key bytes"),
        )
        .expect("key material");
        Self {
            inner: LocalAes256GcmKeyring::new(key, Vec::new(), []).expect("local keyring"),
            wrap_calls: AtomicUsize::new(0),
        }
    }

    fn wrap_calls(&self) -> usize {
        self.wrap_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl KeyEncryptionProvider for OneShotKeyProvider {
    async fn wrap_data_key(
        &self,
        plaintext_key: &SecretBytes,
        context: &KeyEncryptionContext,
    ) -> Result<WrappedDataKey, KeyEncryptionError> {
        if self.wrap_calls.fetch_add(1, Ordering::SeqCst) != 0 {
            return Err(KeyEncryptionError::Unavailable);
        }
        self.inner.wrap_data_key(plaintext_key, context).await
    }

    async fn unwrap_data_key(
        &self,
        wrapped_key: &WrappedDataKey,
        context: &KeyEncryptionContext,
    ) -> Result<SecretBytes, KeyEncryptionError> {
        self.inner.unwrap_data_key(wrapped_key, context).await
    }
}

struct Fixture {
    tenant: String,
    repository: Uuid,
    secret: Uuid,
    mutation: Uuid,
}

impl Fixture {
    fn descriptor(&self) -> SecretDescriptor {
        SecretDescriptor::new(
            SecretId::new(self.secret.hyphenated().to_string()).expect("secret ID"),
            SecretName::new("release_token").expect("secret name"),
            SecretScope::repository(
                TenantScopeId::new(&self.tenant).expect("tenant ID"),
                RepositoryScopeId::new(self.repository.hyphenated().to_string())
                    .expect("repository ID"),
            ),
        )
    }

    fn request(&self, request_id: &str, value: &[u8]) -> CreateSecretVersionRequest {
        CreateSecretVersionRequest::new(
            ProviderOperationContext::new(
                TenantScopeId::new(&self.tenant).expect("tenant ID"),
                ProviderRequestId::new(request_id).expect("provider request ID"),
            ),
            self.descriptor(),
            None,
            SecretValue::new(value.to_vec()).expect("secret value"),
        )
        .expect("create request")
    }

    fn request_id(&self) -> String {
        format!("secret-version:{}", self.mutation.hyphenated())
    }

    fn reconciliation(
        &self,
        request_id: &str,
        expected_existing_version: Option<ExistingSecretVersion>,
    ) -> ReconcileCreateSecretVersionRequest {
        ReconcileCreateSecretVersionRequest::new(
            ProviderOperationContext::new(
                TenantScopeId::new(&self.tenant).expect("tenant ID"),
                ProviderRequestId::new(request_id).expect("provider request ID"),
            ),
            self.descriptor(),
            expected_existing_version,
        )
        .expect("reconciliation request")
    }
}

fn wrong_predecessor(fixture: &Fixture) -> ExistingSecretVersion {
    ExistingSecretVersion::new(
        ProviderSecretLocator::new(fixture.secret.hyphenated().to_string()).expect("locator"),
        ProviderVersionId::new(Uuid::new_v4().hyphenated().to_string()).expect("version ID"),
    )
}

fn assert_exact_reconciliation(
    outcome: &ReconcileCreateSecretVersionOutcome,
    created: &CreatedSecretVersion,
) -> TestResult {
    let ReconcileCreateSecretVersionOutcome::AlreadyCommitted(reconciled) = outcome else {
        return Err("staged create reconciled as definitively absent".into());
    };
    assert_eq!(reconciled, created);
    let debug = format!("{outcome:?}");
    assert!(!debug.contains(created.locator().as_str()));
    assert!(!debug.contains(created.version().as_str()));
    assert!(debug.contains("[OPAQUE]"));
    Ok(())
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
            WHERE pid <> $1
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

#[allow(clippy::too_many_lines)] // The direct fixture isolates the provider from management RBAC.
async fn seed_fixture(pool: &PgPool) -> TestResult<Fixture> {
    seed_fixture_with_deadline_margin(pool, confirmation_ttl_millis()).await
}

#[allow(clippy::too_many_lines)] // The direct fixture isolates the provider from management RBAC.
async fn seed_fixture_with_deadline_margin(
    pool: &PgPool,
    deadline_margin_ms: i64,
) -> TestResult<Fixture> {
    let fixture = Fixture {
        tenant: format!("secret-replay-{}", Uuid::new_v4().simple()),
        repository: Uuid::new_v4(),
        secret: Uuid::new_v4(),
        mutation: Uuid::new_v4(),
    };
    let principal_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let provider_subject = format!("secret-replay-subject-{}", principal_id.simple());
    let database_now_ms: i64 =
        sqlx::query_scalar("SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(pool)
            .await?;
    let confirmation_ttl_millis = confirmation_ttl_millis();
    let reserved_at_ms =
        (database_now_ms / 1_000) * 1_000 - confirmation_ttl_millis + deadline_margin_ms;
    let confirmation_deadline_ms = reserved_at_ms
        .checked_add(confirmation_ttl_millis)
        .ok_or("confirmation deadline overflow")?;
    sqlx::query(
        "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Secret replay test', 1, 1)",
    )
    .bind(&fixture.tenant)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id,
            owner, name, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, 'github', $3, 'automata', 'secret-replay', 1, 1)
        ",
    )
    .bind(fixture.repository)
    .bind(&fixture.tenant)
    .bind(fixture.repository.to_string())
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO human_principals (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Secret replay reserver', 1, 1)",
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
    .bind(format!("replay-{}", principal_id.simple()))
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO tenant_human_memberships (tenant_id, principal_id, created_at_ms, updated_at_ms) VALUES ($1, $2, 1, 1)",
    )
    .bind(&fixture.tenant)
    .bind(principal_id)
    .execute(pool)
    .await?;
    let authorization_revision: i64 = sqlx::query_scalar(
        "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id = $1 AND principal_id = $2",
    )
    .bind(&fixture.tenant)
    .bind(principal_id)
    .fetch_one(pool)
    .await?;
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
            $5, 'secret-replay-session-v1', $6, $7, $7, $8, $9
        )
        ",
    )
    .bind(session_id)
    .bind(&fixture.tenant)
    .bind(principal_id)
    .bind(&provider_subject)
    .bind(token_hash.as_slice())
    .bind(authorization_revision)
    .bind(reserved_at_ms - 10_000)
    .bind(reserved_at_ms + 100_000)
    .bind(reserved_at_ms + 200_000)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        UPDATE secret_providers
        SET status = 'active', health = 'healthy', revision = revision + 1,
            updated_at_ms = 2
        WHERE tenant_id = $1 AND provider_id = 'builtin'
        ",
    )
    .bind(&fixture.tenant)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secrets (
            tenant_id, id, canonical_name, scope_kind, repository_id,
            provider_id, status, revision, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, 'RELEASE_TOKEN', 'repository', $3,
                  'builtin', 'provisioning', 1, 2, 2)
        ",
    )
    .bind(&fixture.tenant)
    .bind(fixture.secret)
    .bind(fixture.repository)
    .execute(pool)
    .await?;
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r"
        INSERT INTO secret_version_mutations (
            tenant_id, mutation_id, secret_id, scope_kind, repository_id, canonical_name,
            provider_id, mutation_kind, reserved_secret_revision,
            reserved_version_number, confirmation_deadline_ms,
            provider_create_request_id, reserved_by_principal_id,
            reserved_by_session_id, reserved_authorization_revision, reserved_at_ms
        ) VALUES ($1, $2, $3, 'repository', $4, 'RELEASE_TOKEN', 'builtin', 'create', 1,
                  1, $5, $6, $7, $8, $9, $10)
        ",
    )
    .bind(&fixture.tenant)
    .bind(fixture.mutation)
    .bind(fixture.secret)
    .bind(fixture.repository)
    .bind(confirmation_deadline_ms)
    .bind(fixture.request_id())
    .bind(principal_id)
    .bind(session_id)
    .bind(authorization_revision)
    .bind(reserved_at_ms)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_mutation_recovery_outbox (
            operation_id, tenant_id, mutation_id,
            next_attempt_at_ms, created_at_ms
        ) VALUES (
            automata_secret_mutation_recovery_operation_id($1, $2),
            $1, $2, $3, $4
        )
        ",
    )
    .bind(&fixture.tenant)
    .bind(fixture.mutation)
    .bind(confirmation_deadline_ms)
    .bind(reserved_at_ms)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    let custody_key_id = KeyId::new(REPLAY_KEY_ID)?;
    let custody_keys: Arc<dyn KeyEncryptionProvider> = Arc::new(LocalAes256GcmKeyring::new(
        LocalKeyMaterial::new(custody_key_id.clone(), SecretBytes::new(vec![0x5d; 32])?)?,
        Vec::new(),
        [],
    )?);
    let custody = PostgresSecretCustodyRepository::new(pool.clone())
        .with_key_encryption_provider(custody_keys);
    assert!(matches!(
        custody
            .verify_or_create_secret_custody(VerifySecretCustody::configured(
                SecretCustodyKeySet::new(custody_key_id, Vec::new())?,
            ))
            .await?,
        VerifySecretCustodyOutcome::Verified(_)
    ));
    Ok(fixture)
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn reconciliation_is_exact_value_free_and_replay_stable() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(database.pool()).await?;
        let key_provider = Arc::new(OneShotKeyProvider::new());
        let provider = PostgresSecretProvider::new(
            database.pool().clone(),
            Arc::<OneShotKeyProvider>::clone(&key_provider),
        );
        assert!(
            provider
                .capabilities()
                .supports(ProviderCapability::ReconcileCreateVersion)
        );

        let request_id = fixture.request_id();
        let live_absence = provider
            .reconcile_create_version(fixture.reconciliation(&request_id, None))
            .await
            .expect_err("a live reservation without a winner remains ambiguous");
        assert_eq!(live_absence.kind(), ProviderErrorKind::Unavailable);
        assert_eq!(key_provider.wrap_calls(), 0);

        let wrong_predecessor_error = provider
            .reconcile_create_version(
                fixture.reconciliation(&request_id, Some(wrong_predecessor(&fixture))),
            )
            .await
            .expect_err("a create intent cannot be reconciled as a replacement");
        assert_eq!(wrong_predecessor_error.kind(), ProviderErrorKind::Conflict);
        let wrong_locator_error = provider
            .reconcile_create_version(fixture.reconciliation(
                &request_id,
                Some(ExistingSecretVersion::new(
                    ProviderSecretLocator::new(Uuid::new_v4().hyphenated().to_string())?,
                    ProviderVersionId::new(Uuid::new_v4().hyphenated().to_string())?,
                )),
            ))
            .await
            .expect_err("a predecessor locator cannot name another logical secret");
        assert_eq!(wrong_locator_error.kind(), ProviderErrorKind::Conflict);

        let wrong_descriptor = SecretDescriptor::new(
            SecretId::new(fixture.secret.hyphenated().to_string())?,
            SecretName::new("other_token")?,
            SecretScope::repository(
                TenantScopeId::new(&fixture.tenant)?,
                RepositoryScopeId::new(fixture.repository.hyphenated().to_string())?,
            ),
        );
        let descriptor_error = provider
            .reconcile_create_version(ReconcileCreateSecretVersionRequest::new(
                ProviderOperationContext::new(
                    TenantScopeId::new(&fixture.tenant)?,
                    ProviderRequestId::new(&request_id)?,
                ),
                wrong_descriptor,
                None,
            )?)
            .await
            .expect_err("a request ID cannot be replayed with another descriptor");
        assert_eq!(descriptor_error.kind(), ProviderErrorKind::Conflict);

        let created = provider
            .create_version(fixture.request(&request_id, FIRST_VALUE))
            .await?;
        assert_eq!(key_provider.wrap_calls(), 1);
        for _ in 0..2 {
            let outcome = provider
                .reconcile_create_version(fixture.reconciliation(&request_id, None))
                .await?;
            assert_exact_reconciliation(&outcome, &created)?;
        }
        assert_eq!(key_provider.wrap_calls(), 1);

        let expired = seed_fixture_with_deadline_margin(database.pool(), 0).await?;
        let expired_keys = Arc::new(OneShotKeyProvider::new());
        let expired_provider = PostgresSecretProvider::new(
            database.pool().clone(),
            Arc::<OneShotKeyProvider>::clone(&expired_keys),
        );
        let expired_request_id = expired.request_id();
        for _ in 0..2 {
            assert_eq!(
                expired_provider
                    .reconcile_create_version(expired.reconciliation(&expired_request_id, None),)
                    .await?,
                ReconcileCreateSecretVersionOutcome::DefinitivelyNotCommitted
            );
        }
        assert_eq!(expired_keys.wrap_calls(), 0);
        let expired_wrong_intent = expired_provider
            .reconcile_create_version(
                expired.reconciliation(&expired_request_id, Some(wrong_predecessor(&expired))),
            )
            .await
            .expect_err("wrong predecessor cannot be reported definitively absent");
        assert_eq!(expired_wrong_intent.kind(), ProviderErrorKind::Conflict);
        assert_eq!(expired_keys.wrap_calls(), 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn reconciliation_waits_for_the_exact_concurrent_create_commit() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(database.pool()).await?;
        let key_provider = Arc::new(OneShotKeyProvider::new());
        let provider = Arc::new(PostgresSecretProvider::new(
            database.pool().clone(),
            Arc::<OneShotKeyProvider>::clone(&key_provider),
        ));
        let request_id = fixture.request_id();

        let mut blocker = database.pool().begin().await?;
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        let locked_key_id: String = sqlx::query_scalar(
            "SELECT wrapping_key_id FROM secret_custody_key_canaries \
             WHERE wrapping_key_id = $1 FOR UPDATE",
        )
        .bind(REPLAY_KEY_ID)
        .fetch_one(&mut *blocker)
        .await?;
        assert_eq!(locked_key_id, REPLAY_KEY_ID);

        let create_provider = Arc::clone(&provider);
        let create_request = fixture.request(&request_id, FIRST_VALUE);
        let mut create_task =
            tokio::spawn(async move { create_provider.create_version(create_request).await });
        let create_backend_pid = match wait_for_backend_blocked_by(
            database.pool(),
            blocker_pid,
            "INSERT INTO secret_version_envelopes",
        )
        .await
        {
            Ok(pid) => pid,
            Err(error) => {
                blocker.rollback().await?;
                create_task.abort();
                let _ = create_task.await;
                return Err(error);
            }
        };

        let reconcile_provider = Arc::clone(&provider);
        let reconcile_request = fixture.reconciliation(&request_id, None);
        let mut reconcile_task = tokio::spawn(async move {
            reconcile_provider
                .reconcile_create_version(reconcile_request)
                .await
        });
        let reconciliation_backend_pid = match wait_for_backend_blocked_by(
            database.pool(),
            create_backend_pid,
            "SELECT adapter_kind, status, supports_create_version",
        )
        .await
        {
            Ok(pid) => pid,
            Err(error) => {
                blocker.rollback().await?;
                create_task.abort();
                reconcile_task.abort();
                let _ = tokio::join!(create_task, reconcile_task);
                return Err(error);
            }
        };
        assert_ne!(reconciliation_backend_pid, create_backend_pid);
        assert!(!create_task.is_finished());
        assert!(!reconcile_task.is_finished());
        blocker.rollback().await?;

        let completions = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(&mut create_task, &mut reconcile_task)
        })
        .await;
        let Ok((created, reconciled)) = completions else {
            create_task.abort();
            reconcile_task.abort();
            let _ = tokio::join!(create_task, reconcile_task);
            return Err("timed out waiting for create/reconciliation serialization".into());
        };
        let created = created??;
        let reconciled = reconciled??;
        let ReconcileCreateSecretVersionOutcome::AlreadyCommitted(reconciled) = reconciled else {
            return Err("concurrent committed create reconciled as definitively absent".into());
        };
        assert_eq!(reconciled, created);
        assert_eq!(key_provider.wrap_calls(), 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn expired_reservations_and_staged_replays_never_wrap_new_material() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let expired = seed_fixture_with_deadline_margin(database.pool(), 0).await?;
        let expired_keys = Arc::new(OneShotKeyProvider::new());
        let expired_provider = PostgresSecretProvider::new(
            database.pool().clone(),
            Arc::<OneShotKeyProvider>::clone(&expired_keys),
        );
        let expired_error = expired_provider
            .create_version(expired.request(&expired.request_id(), FIRST_VALUE))
            .await
            .expect_err("an expired reservation must not stage ciphertext");
        assert_eq!(expired_error.kind(), ProviderErrorKind::Conflict);
        assert_eq!(expired_keys.wrap_calls(), 0);

        let staged = seed_fixture_with_deadline_margin(database.pool(), 3_000).await?;
        let staged_keys = Arc::new(OneShotKeyProvider::new());
        let staged_provider = PostgresSecretProvider::new(
            database.pool().clone(),
            Arc::<OneShotKeyProvider>::clone(&staged_keys),
        );
        let request_id = staged.request_id();
        staged_provider
            .create_version(staged.request(&request_id, FIRST_VALUE))
            .await?;
        assert_eq!(staged_keys.wrap_calls(), 1);
        let (deadline_ms, now_ms): (i64, i64) = sqlx::query_as(
            r"
            SELECT mutation.confirmation_deadline_ms,
                   floor(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT
            FROM secret_version_mutations AS mutation
            WHERE mutation.tenant_id = $1 AND mutation.mutation_id = $2
            ",
        )
        .bind(&staged.tenant)
        .bind(staged.mutation)
        .fetch_one(database.pool())
        .await?;
        let advance_ms = deadline_ms
            .checked_sub(now_ms)
            .filter(|advance_ms| *advance_ms > 0)
            .ok_or("staged mutation must begin before its confirmation deadline")?;
        assert_eq!(clock.advance(advance_ms).await?, deadline_ms);
        let replay_error = staged_provider
            .create_version(staged.request(&request_id, SECOND_VALUE))
            .await
            .expect_err("an expired staged reservation must not replay as live");
        assert_eq!(replay_error.kind(), ProviderErrorKind::Conflict);
        assert_eq!(staged_keys.wrap_calls(), 1);
        let staged_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM secret_versions WHERE tenant_id = $1 AND secret_id = $2",
        )
        .bind(&staged.tenant)
        .bind(staged.secret)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(staged_count, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn exact_staged_replay_and_invalid_intents_never_wrap_twice() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(database.pool()).await?;
        let key_provider = Arc::new(OneShotKeyProvider::new());
        let provider = PostgresSecretProvider::new(
            database.pool().clone(),
            Arc::<OneShotKeyProvider>::clone(&key_provider),
        );

        for malformed in [
            "create-version",
            "secret-version:00000000-0000-0000-0000-000000000000",
            "secret-version:aaaaaaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa",
        ] {
            assert_eq!(
                provider
                    .create_version(fixture.request(malformed, FIRST_VALUE))
                    .await
                    .unwrap_err()
                    .kind(),
                ProviderErrorKind::InvalidRequest
            );
            assert_eq!(key_provider.wrap_calls(), 0);
        }

        let unreserved = format!("secret-version:{}", Uuid::new_v4().hyphenated());
        assert_eq!(
            provider
                .create_version(fixture.request(&unreserved, FIRST_VALUE))
                .await
                .unwrap_err()
                .kind(),
            ProviderErrorKind::Conflict
        );
        assert_eq!(key_provider.wrap_calls(), 0);

        let request_id = fixture.request_id();
        let first = provider
            .create_version(fixture.request(&request_id, FIRST_VALUE))
            .await?;
        assert_eq!(key_provider.wrap_calls(), 1);

        let replay = provider
            .create_version(fixture.request(&request_id, SECOND_VALUE))
            .await?;
        assert_eq!(replay, first);
        assert_eq!(key_provider.wrap_calls(), 1);

        let staged: (i64, String, Uuid) = sqlx::query_as(
            r"
            SELECT count(*) OVER (), lifecycle.status, lifecycle.mutation_id
            FROM secret_versions AS version
            JOIN secret_version_lifecycle AS lifecycle
              ON lifecycle.tenant_id = version.tenant_id
             AND lifecycle.secret_version_id = version.id
            WHERE version.tenant_id = $1 AND version.secret_id = $2
            ",
        )
        .bind(&fixture.tenant)
        .bind(fixture.secret)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(staged, (1, "staged".into(), fixture.mutation));
        Ok(())
    })
    .await
}
