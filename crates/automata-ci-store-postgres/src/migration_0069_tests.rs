use std::{collections::BTreeMap, env, future::Future, str::FromStr, sync::Arc};

use automata_ci_auth::{human::TenantId, installation::InstallationTenant};
use automata_ci_auth_postgres::{
    ConfigureDeploymentInstallation, ConfigureDeploymentInstallationOutcome,
    PostgresInstallationAuthorityRepository, PostgresRunnerEnrollmentRepository,
    management::{
        ConsumeRunnerEnrollment, EnsureInstallationBootstrapRunnerEnrollmentToken,
        INSTALLATION_BOOTSTRAP_ENROLLMENT_TOKEN_LIFETIME_MS, InstallationBootstrapRecoveryToken,
        InstallationBootstrapRequestError, InstallationBootstrapRunnerEnrollmentTokenOutcome,
        InstallationRunnerRecoveryConsumeOutcome, InstallationRunnerRecoveryPredecessor,
        InstallationRunnerRecoveryPrepareOutcome, MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS,
        PrepareRunnerEnrollment, RunnerEnrollmentConsumeOutcome, RunnerEnrollmentPrepareOutcome,
        WindowsRunnerAdmissionRecord,
    },
};
use automata_ci_core::{
    Architecture, EnvironmentProfile, EnvironmentProfileId, IsolationLevel, OperatingSystem,
    OperationId, RunnerCapabilities, RunnerFeature, RunnerGroup, RunnerId, RunnerPlatform,
    SandboxCapabilities, SandboxFeature, Sha256Digest,
};
use automata_ci_protocol::{
    WINDOWS_RUNNER_ADMISSION_PROVIDER_ID, WindowsAdmissionImage, WindowsAdmissionValidity,
    WindowsAuthorityAdmissionEvidence, WindowsBrokerAdmissionEvidence, WindowsBrokerProfileBinding,
    WindowsEnrollmentTransactionBinding, WindowsImagePromotionBinding, WindowsPromotionValidity,
    WindowsRunnerAdmissionBinding, WindowsRunnerAdmissionClaims, WindowsRunnerAdmissionEnvelope,
    WindowsRunnerAdmissionEvidence, WindowsRunnerAdmissionTrustAnchor,
    WindowsRunnerAdmissionTrustStore, verify_windows_runner_admission,
};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair as _},
};
use sha2::{Digest as _, Sha256};
use sqlx::{
    AssertSqlSafe, Connection as _, PgConnection, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use uuid::Uuid;

use crate::migration::MIGRATOR;

const DATABASE_URL_ENVIRONMENT: &str = "AUTOMATA_TEST_DATABASE_URL";
const TEST_SCHEMA: &str = "automata_test";
const MINIMUM_POSTGRES_VERSION: i32 = 180_000;
const LEGACY_TENANT_ID: &str = "upgrade-human-token";
const LEGACY_TENANT_DISPLAY_NAME: &str = " Upgrade human tenant ";
const LEGACY_PROVIDER_ID: &str = "github";
const LEGACY_PROVIDER_SUBJECT: &str = "upgrade-human-subject";

type TestError = Box<dyn std::error::Error + Send + Sync + 'static>;
type TestResult<T = ()> = Result<T, TestError>;

#[derive(Debug)]
struct TestDatabase {
    pool: PgPool,
    connect_options: PgConnectOptions,
}

impl TestDatabase {
    fn pool(&self) -> &PgPool {
        &self.pool
    }

    async fn connect_pool(&self) -> TestResult<PgPool> {
        connect_pool(self.connect_options.clone()).await
    }
}

async fn run_with_unmigrated_database<Test, TestFuture>(test: Test) -> TestResult
where
    Test: FnOnce(Arc<TestDatabase>) -> TestFuture + Send + 'static,
    TestFuture: Future<Output = TestResult> + Send + 'static,
{
    let database_url = env::var(DATABASE_URL_ENVIRONMENT).map_err(|error| {
        message_error(format!(
            "set {DATABASE_URL_ENVIRONMENT} to an isolated PostgreSQL 18 test server URL: {error}"
        ))
    })?;
    let admin_options = PgConnectOptions::from_str(&database_url).map_err(|error| {
        message_error(format!(
            "invalid PostgreSQL URL supplied through {DATABASE_URL_ENVIRONMENT}: {error}"
        ))
    })?;
    let database_name = format!("automata_m68_{}", Uuid::new_v4().simple());
    debug_assert!(
        database_name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    );

    let mut admin = PgConnection::connect_with(&admin_options).await?;
    require_postgres_18(&mut admin).await?;
    sqlx::query(AssertSqlSafe(format!(
        "CREATE DATABASE \"{database_name}\" TEMPLATE template0"
    )))
    .execute(&mut admin)
    .await?;
    admin.close().await?;

    let database_options = admin_options.clone().database(&database_name);
    let pool = match connect_pool(database_options.clone()).await {
        Ok(pool) => pool,
        Err(error) => {
            cleanup_database(&admin_options, &database_name).await?;
            return Err(error);
        }
    };
    if let Err(error) = sqlx::query("CREATE SCHEMA automata_test")
        .execute(&pool)
        .await
    {
        pool.close().await;
        cleanup_database(&admin_options, &database_name).await?;
        return Err(error.into());
    }
    let database = Arc::new(TestDatabase {
        pool,
        connect_options: database_options,
    });
    let task = tokio::spawn(test(Arc::clone(&database))).await;
    database.pool.close().await;
    let cleanup = cleanup_database(&admin_options, &database_name).await;

    match task {
        Ok(Ok(())) => cleanup,
        Ok(Err(test_error)) => {
            if let Err(cleanup_error) = cleanup {
                return Err(message_error(format!(
                    "PostgreSQL migration test failed ({test_error}) and cleanup failed ({cleanup_error})"
                )));
            }
            Err(test_error)
        }
        Err(join_error) => {
            if let Err(cleanup_error) = cleanup {
                eprintln!(
                    "PostgreSQL migration test task failed and cleanup also failed: {cleanup_error}"
                );
            }
            if join_error.is_panic() {
                std::panic::resume_unwind(join_error.into_panic());
            }
            Err(join_error.into())
        }
    }
}

async fn connect_pool(options: PgConnectOptions) -> TestResult<PgPool> {
    Ok(PgPoolOptions::new()
        .max_connections(8)
        .after_connect(|connection, _metadata| {
            Box::pin(async move {
                sqlx::query("SELECT pg_catalog.set_config('search_path', $1, false)")
                    .bind(format!("{TEST_SCHEMA}, pg_catalog"))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await?)
}

async fn require_postgres_18(connection: &mut PgConnection) -> TestResult {
    let version: i32 =
        sqlx::query_scalar("SELECT pg_catalog.current_setting('server_version_num')::INTEGER")
            .fetch_one(&mut *connection)
            .await?;
    if version < MINIMUM_POSTGRES_VERSION {
        return Err(message_error(format!(
            "migration 0068 live tests require PostgreSQL 18 or newer; server_version_num is {version}"
        )));
    }
    let can_create_database: bool = sqlx::query_scalar(
        r"
        SELECT COALESCE(
            (
                SELECT rolcreatedb OR rolsuper
                FROM pg_catalog.pg_roles
                WHERE rolname = CURRENT_USER
            ),
            FALSE
        )
        ",
    )
    .fetch_one(&mut *connection)
    .await?;
    if !can_create_database {
        return Err(message_error(
            "migration 0068 live tests require CREATEDB on the isolated PostgreSQL server",
        ));
    }
    Ok(())
}

async fn cleanup_database(options: &PgConnectOptions, database_name: &str) -> TestResult {
    let mut admin = PgConnection::connect_with(options).await?;
    sqlx::query(AssertSqlSafe(format!(
        "DROP DATABASE \"{database_name}\" WITH (FORCE)"
    )))
    .execute(&mut admin)
    .await?;
    admin.close().await?;
    Ok(())
}

fn message_error(message: impl Into<String>) -> TestError {
    std::io::Error::other(message.into()).into()
}

#[derive(Debug)]
struct TestClock {
    pool: PgPool,
}

impl TestClock {
    async fn freeze_at_database_now(pool: &PgPool) -> TestResult<Self> {
        let now_ms: i64 = sqlx::query_scalar(
            r"
            SELECT floor(
                extract(epoch FROM pg_catalog.clock_timestamp()) * 1000
            )::BIGINT
            ",
        )
        .fetch_one(pool)
        .await?;
        let mut transaction = pool.begin().await?;
        sqlx::query(
            r"
            CREATE TABLE automata_test.__automata_m68_clock (
                singleton BOOLEAN PRIMARY KEY CHECK (singleton),
                now_ms BIGINT NOT NULL
            )
            ",
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO automata_test.__automata_m68_clock (singleton, now_ms)
            VALUES (TRUE, $1)
            ",
        )
        .bind(now_ms)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            CREATE FUNCTION automata_test.clock_timestamp()
            RETURNS TIMESTAMPTZ
            LANGUAGE SQL
            VOLATILE
            AS $automata_m68_clock$
                SELECT TIMESTAMPTZ 'epoch' + now_ms * INTERVAL '1 millisecond'
                FROM automata_test.__automata_m68_clock
                WHERE singleton
            $automata_m68_clock$
            ",
        )
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        let clock = Self { pool: pool.clone() };
        assert_eq!(clock.now().await?, now_ms);
        Ok(clock)
    }

    async fn set(&self, now_ms: i64) -> TestResult {
        let updated =
            sqlx::query("UPDATE automata_test.__automata_m68_clock SET now_ms=$1 WHERE singleton")
                .bind(now_ms)
                .execute(&self.pool)
                .await?;
        if updated.rows_affected() != 1 {
            return Err(message_error("migration test clock singleton is missing"));
        }
        assert_eq!(self.now().await?, now_ms);
        Ok(())
    }

    async fn now(&self) -> TestResult<i64> {
        Ok(
            sqlx::query_scalar(
                "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
            )
            .fetch_one(&self.pool)
            .await?,
        )
    }
}

#[derive(sqlx::FromRow)]
struct StoredInstallationBootstrapToken {
    issuer_kind: String,
    issued_by_principal_id: Option<Uuid>,
    issued_by_session_id: Option<Uuid>,
    issued_authorization_revision: Option<i64>,
    installation_authority_sha256: Option<Vec<u8>>,
    installation_runner_id: Option<Uuid>,
    installation_generation: Option<i64>,
    installation_predecessor_enrollment_id: Option<Uuid>,
    issued_at_ms: i64,
    last_refreshed_at_ms: Option<i64>,
    expires_at_ms: i64,
}

#[derive(sqlx::FromRow)]
struct StoredLegacyHumanConsumption {
    consumed_at_ms: Option<i64>,
    consumed_runner_id: Option<Uuid>,
    redeem_operation_id: Option<Uuid>,
    redeem_request_sha256: Option<Vec<u8>>,
    redeem_response: Option<Vec<u8>>,
    redeem_certificate_leaf_sha256: Option<Vec<u8>>,
    redeem_predecessor_certificate_leaf_sha256: Option<Vec<u8>>,
    redeem_predecessor_certificate_expires_at_seconds: Option<i64>,
    redeem_certificate_expires_at_seconds: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct StoredLegacyHumanInstallation {
    state: String,
    configuration_mode: Option<String>,
    tenant_id: Option<String>,
    tenant_display_name: Option<String>,
    configured_tenant_id: Option<String>,
    configured_principal_id: Option<Uuid>,
    setup_transaction_id: Option<Uuid>,
    configured_at_ms: Option<i64>,
    revision: i64,
    deployment_authority_sha256: Option<Vec<u8>>,
    deployment_bootstrap_operation_id: Option<Uuid>,
    deployment_bootstrap_audit_event_id: Option<Uuid>,
}

#[derive(Debug)]
struct LegacyHumanUpgradeFixture {
    now_ms: i64,
    principal_id: Uuid,
    session_id: Uuid,
    authorization_revision: i64,
    runner_group_id: Uuid,
    enrollment_id: Uuid,
    token_sha256: [u8; 32],
}

struct TrustStore(BTreeMap<String, WindowsRunnerAdmissionTrustAnchor>);

impl WindowsRunnerAdmissionTrustStore for TrustStore {
    fn admission_trust_anchor(
        &self,
        issuer_key_id: &str,
    ) -> Option<WindowsRunnerAdmissionTrustAnchor> {
        self.0.get(issuer_key_id).cloned()
    }
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn installation_recovery_identity(
    generation: u64,
) -> Result<InstallationBootstrapRecoveryToken, InstallationBootstrapRequestError> {
    installation_recovery_identity_for(0x41, generation)
}

fn installation_recovery_identity_for(
    chain: u8,
    generation: u64,
) -> Result<InstallationBootstrapRecoveryToken, InstallationBootstrapRequestError> {
    let mut id_hasher = Sha256::new();
    id_hasher.update(b"automata.test/installation-recovery-id/v1\0");
    id_hasher.update([chain]);
    id_hasher.update(generation.to_be_bytes());
    let material: [u8; 32] = id_hasher.finalize().into();
    let mut id = <[u8; 16]>::try_from(&material[..16]).expect("16-byte recovery UUID");
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    let mut token_hasher = Sha256::new();
    token_hasher.update(b"automata.test/installation-recovery-token/v1\0");
    token_hasher.update([chain]);
    token_hasher.update(generation.to_be_bytes());
    let digest: [u8; 32] = token_hasher.finalize().into();
    InstallationBootstrapRecoveryToken::new(Uuid::from_bytes(id), digest)
}

#[allow(
    clippy::too_many_lines,
    reason = "the helper constructs one complete signed Windows admission witness"
)]
fn windows_admission(
    database_time_ms: i64,
    runner_id: RunnerId,
    operation_id: Uuid,
    runner_name: &str,
    token_sha256: [u8; 32],
    group: RunnerGroup,
) -> TestResult<(RunnerCapabilities, WindowsRunnerAdmissionRecord)> {
    let now = u64::try_from(database_time_ms)?;
    let profile = EnvironmentProfile::new(
        EnvironmentProfileId::new("automata.example/windows-server-2025")?,
        digest(4),
    );
    let capabilities = RunnerCapabilities::new(
        runner_id,
        RunnerPlatform::new(OperatingSystem::Windows, Architecture::X86_64),
    )
    .with_groups([group])
    .with_sandbox(SandboxCapabilities::new(
        IsolationLevel::VirtualMachine,
        [SandboxFeature::WINDOWS_HYPERV_CONTAINER],
    ))
    .with_features([
        RunnerFeature::SHELL_STEPS,
        RunnerFeature::REPOSITORY_ACTIONS,
        RunnerFeature::COMPOSITE_ACTIONS,
        RunnerFeature::JAVASCRIPT_ACTIONS,
        RunnerFeature::NODE20_ACTIONS,
    ])
    .with_environment_profiles([profile.clone()]);
    let transaction = WindowsEnrollmentTransactionBinding::new(
        runner_id,
        OperationId::from_uuid(operation_id),
        "https://control.example.test/",
        "https://enroll.example.test/",
        sha256(runner_name.as_bytes()),
        Sha256Digest::from_bytes(token_sha256),
        digest(3),
    )?;
    let image_digest = digest(5);
    let image = WindowsAdmissionImage::new(
        format!("registry.example.test/automata/windows@sha256:{image_digest}"),
        image_digest,
    )?;
    let broker_host_id = "a".repeat(64);
    let broker_profile = WindowsBrokerProfileBinding::new(
        broker_host_id.clone(),
        WINDOWS_RUNNER_ADMISSION_PROVIDER_ID,
        digest(6),
        profile.clone(),
        image,
        digest(7),
        true,
        true,
        64,
    )?;
    let promotion = WindowsImagePromotionBinding::new(
        "production.windows.v1",
        "promotion-key-v1",
        digest(8),
        digest(9),
        41,
        19,
        WindowsPromotionValidity::new(now - 60_000, now + 3_600_000)?,
    )?;
    let binding = WindowsRunnerAdmissionBinding::new(
        transaction,
        broker_profile,
        promotion,
        capabilities.clone(),
    )?;
    let evidence = WindowsRunnerAdmissionEvidence::new(
        WindowsBrokerAdmissionEvidence::new(
            digest(10),
            digest(11),
            digest(12),
            digest(13),
            digest(14),
        )?,
        WindowsAuthorityAdmissionEvidence::new(digest(15), digest(16), digest(17), digest(18))?,
    );
    let issuer = "broker-admission-v1";
    let claims = WindowsRunnerAdmissionClaims::new(
        issuer,
        digest(19),
        digest(20),
        digest(21),
        binding,
        evidence,
        WindowsAdmissionValidity::new(now - 1_000, now + 60_000)?,
    )?;
    let key_document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())?;
    let key_pair = Ed25519KeyPair::from_pkcs8(key_document.as_ref())?;
    let payload = claims.canonical_bytes()?;
    let envelope = WindowsRunnerAdmissionEnvelope::new(
        issuer,
        payload.clone(),
        key_pair.sign(&payload).as_ref().to_vec(),
    )?;
    let public_key: [u8; 32] = key_pair
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| message_error("test Ed25519 public key has the wrong size"))?;
    let trust = TrustStore(BTreeMap::from([(
        issuer.to_owned(),
        WindowsRunnerAdmissionTrustAnchor::new(
            public_key,
            broker_host_id,
            profile,
            "production.windows.v1",
        )?,
    )]));
    let verified = verify_windows_runner_admission(&envelope, &trust, now)?;
    Ok((
        capabilities,
        WindowsRunnerAdmissionRecord::from_verified(verified),
    ))
}

#[allow(
    clippy::too_many_arguments,
    reason = "the helper names every exact field in the enrollment request"
)]
fn consume_request(
    token_sha256: [u8; 32],
    operation_id: Uuid,
    request_sha256: [u8; 32],
    runner_id: RunnerId,
    runner_name: &str,
    capabilities: RunnerCapabilities,
    certificate_issued_at_seconds: i64,
    response: Vec<u8>,
    windows_admission: WindowsRunnerAdmissionRecord,
) -> ConsumeRunnerEnrollment {
    ConsumeRunnerEnrollment {
        token_sha256,
        operation_id,
        request_sha256,
        runner_id: runner_id.as_uuid(),
        runner_name: runner_name.to_owned(),
        capabilities,
        certificate_leaf_sha256: [0x52; 32],
        certificate_issued_at_seconds,
        certificate_expires_at_seconds: certificate_issued_at_seconds
            + MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS,
        response,
        windows_admission: Some(windows_admission),
    }
}

fn assert_constraint(error: &sqlx::Error, expected: &str) {
    let actual = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint);
    assert_eq!(actual, Some(expected), "unexpected database error: {error}");
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixture builds one referentially complete 0051 human authority shared by both migration branches"
)]
async fn seed_0051_human_upgrade_fixture(
    database: &TestDatabase,
) -> TestResult<LegacyHumanUpgradeFixture> {
    let predecessor = sqlx::migrate::Migrator::with_migrations(
        MIGRATOR
            .iter()
            .filter(|migration| migration.version <= 51)
            .cloned()
            .collect(),
    );
    predecessor.run(database.pool()).await?;
    let predecessor_version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(database.pool())
        .await?;
    assert_eq!(predecessor_version, 51);

    let now_ms: i64 = sqlx::query_scalar(
        "SELECT floor(extract(epoch FROM pg_catalog.clock_timestamp()))::BIGINT * 1000",
    )
    .fetch_one(database.pool())
    .await?;
    sqlx::query(
        "INSERT INTO tenants (id,display_name,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,$3)",
    )
    .bind(LEGACY_TENANT_ID)
    .bind(LEGACY_TENANT_DISPLAY_NAME)
    .bind(now_ms)
    .execute(database.pool())
    .await?;

    let principal_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO human_principals (
            id,status,display_name,created_at_ms,updated_at_ms
        ) VALUES ($1,'active','Upgrade human',$2,$2)
        ",
    )
    .bind(principal_id)
    .bind(now_ms)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO human_provider_identities (
            principal_id,provider_id,provider_subject,provider_login,
            normalized_login,display_name,first_authenticated_at_ms,
            last_authenticated_at_ms,last_observed_at_ms,created_at_ms,updated_at_ms
        ) VALUES ($1,$2,$3,'upgrade-human',
                  'upgrade-human','Upgrade human',$4,$4,$4,$4,$4)
        ",
    )
    .bind(principal_id)
    .bind(LEGACY_PROVIDER_ID)
    .bind(LEGACY_PROVIDER_SUBJECT)
    .bind(now_ms)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO tenant_human_memberships (
            tenant_id,principal_id,status,created_at_ms,updated_at_ms
        ) VALUES ($1,$2,'active',$3,$3)
        ",
    )
    .bind(LEGACY_TENANT_ID)
    .bind(principal_id)
    .bind(now_ms)
    .execute(database.pool())
    .await?;
    let authorization_revision: i64 = sqlx::query_scalar(
        "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id=$1 AND principal_id=$2",
    )
    .bind(LEGACY_TENANT_ID)
    .bind(principal_id)
    .fetch_one(database.pool())
    .await?;

    let session_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO human_sessions (
            id,tenant_id,principal_id,provider_id,provider_subject,
            session_kind,audience,token_hash,token_hash_key_id,
            authorization_revision,issued_at_ms,last_seen_at_ms,
            idle_expires_at_ms,expires_at_ms
        ) VALUES ($1,$2,$3,$4,$5,
                  'browser','automata.web',$6,$7,$8,$9,$9,$10,$11)
        ",
    )
    .bind(session_id)
    .bind(LEGACY_TENANT_ID)
    .bind(principal_id)
    .bind(LEGACY_PROVIDER_ID)
    .bind(LEGACY_PROVIDER_SUBJECT)
    .bind(session_id.as_bytes().repeat(2))
    .bind(format!("migration-0068-{session_id}"))
    .bind(authorization_revision)
    .bind(now_ms - 1_000)
    .bind(now_ms + 600_000)
    .bind(now_ms + 1_200_000)
    .execute(database.pool())
    .await?;

    let runner_group_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO runner_groups (
            id,tenant_id,name,normalized_name,created_at_ms,updated_at_ms
        ) VALUES ($1,$2,'upgrade','upgrade',$3,$3)
        ",
    )
    .bind(runner_group_id)
    .bind(LEGACY_TENANT_ID)
    .bind(now_ms)
    .execute(database.pool())
    .await?;

    let enrollment_id = Uuid::new_v4();
    let token_sha256 = [0x62_u8; 32];
    sqlx::query(
        r"
        INSERT INTO runner_enrollment_tokens (
            id,tenant_id,runner_group_id,token_sha256,
            issued_by_principal_id,issued_by_session_id,
            issued_authorization_revision,issued_at_ms,expires_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        ",
    )
    .bind(enrollment_id)
    .bind(LEGACY_TENANT_ID)
    .bind(runner_group_id)
    .bind(token_sha256.as_slice())
    .bind(principal_id)
    .bind(session_id)
    .bind(authorization_revision)
    .bind(now_ms)
    .bind(now_ms + 600_000)
    .execute(database.pool())
    .await?;

    Ok(LegacyHumanUpgradeFixture {
        now_ms,
        principal_id,
        session_id,
        authorization_revision,
        runner_group_id,
        enrollment_id,
        token_sha256,
    })
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 via AUTOMATA_TEST_DATABASE_URL"]
#[allow(
    clippy::too_many_lines,
    reason = "the test keeps migration, concurrent retries, clock boundaries, Windows consumption, and corruption probes in one isolated database"
)]
async fn migration_0069_fresh_database_supports_exact_deployment_bootstrap() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        MIGRATOR.run(database.pool()).await?;
        let applied_version: i64 =
            sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
                .fetch_one(database.pool())
                .await?;
        assert_eq!(applied_version, 69);
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;

        let corrupt_tenant = "corrupt-audit-probe";
        let corrupt_operation_id = Uuid::new_v4();
        let corrupt_audit_event_id = Uuid::new_v4();
        let corrupt_time_ms = clock.now().await?;
        sqlx::query(
            "INSERT INTO tenants (id,display_name,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,$3)",
        )
        .bind(corrupt_tenant)
        .bind("Corrupt audit probe")
        .bind(corrupt_time_ms)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO security_audit_events (
                event_id,tenant_id,occurred_at_ms,actor_kind,action,outcome,
                resource_kind,resource_id,request_id
            ) VALUES ($1,$2,$3,'system','auth.installation.crossed',
                      'succeeded','installation','singleton',$4)
            ",
        )
        .bind(corrupt_audit_event_id)
        .bind(corrupt_tenant)
        .bind(corrupt_time_ms)
        .bind(corrupt_operation_id.hyphenated().to_string())
        .execute(database.pool())
        .await?;
        let corrupt_installation_error = sqlx::query(
            r"
            UPDATE installation_state
            SET state='configured',configuration_mode='deployment',
                tenant_id=$1,tenant_display_name='Corrupt audit probe',
                configured_tenant_id=$1,configured_at_ms=$2,
                deployment_authority_sha256=$3,
                deployment_bootstrap_operation_id=$4,
                deployment_bootstrap_audit_event_id=$5,
                updated_at_ms=$2,revision=revision+1
            WHERE singleton=TRUE
            ",
        )
        .bind(corrupt_tenant)
        .bind(corrupt_time_ms)
        .bind([0x30_u8; 32].as_slice())
        .bind(corrupt_operation_id)
        .bind(corrupt_audit_event_id)
        .execute(database.pool())
        .await
        .expect_err("crossed deployment audit evidence must not configure the singleton");
        assert_constraint(
            &corrupt_installation_error,
            "installation_state_deployment_completion_exact",
        );
        let installation_state: String =
            sqlx::query_scalar("SELECT state FROM installation_state WHERE singleton")
                .fetch_one(database.pool())
                .await?;
        assert_eq!(installation_state, "unconfigured");

        let installation_repository =
            PostgresInstallationAuthorityRepository::new(database.pool().clone());
        let bootstrap_operation_id = Uuid::new_v4();
        let installation_request = ConfigureDeploymentInstallation::new(
            [0x31; 32],
            bootstrap_operation_id,
            InstallationTenant::new(
                TenantId::new("local-deployment-bootstrap")?,
                "Local deployment bootstrap",
            )?,
        )?;
        let (left, right) = tokio::join!(
            installation_repository.configure_deployment(installation_request.clone()),
            installation_repository.configure_deployment(installation_request.clone()),
        );
        let installation_outcomes = [left?, right?];
        assert_eq!(
            installation_outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ConfigureDeploymentInstallationOutcome::Applied(_)))
                .count(),
            1
        );
        assert_eq!(
            installation_outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ConfigureDeploymentInstallationOutcome::Replayed(_)))
                .count(),
            1
        );
        let installation = installation_outcomes
            .into_iter()
            .find_map(|outcome| match outcome {
                ConfigureDeploymentInstallationOutcome::Applied(proof) => Some(proof),
                ConfigureDeploymentInstallationOutcome::Replayed(_)
                | ConfigureDeploymentInstallationOutcome::Conflict => None,
            })
            .ok_or_else(|| message_error("deployment installation was not applied"))?;
        assert!(matches!(
            installation_repository
                .configure_deployment(ConfigureDeploymentInstallation::new(
                    [0x32; 32],
                    bootstrap_operation_id,
                    InstallationTenant::new(
                        TenantId::new("local-deployment-bootstrap")?,
                        "Local deployment bootstrap",
                    )?,
                )?)
                .await?,
            ConfigureDeploymentInstallationOutcome::Conflict
        ));

        let restart_pool = database.connect_pool().await?;
        let restarted_installation_repository =
            PostgresInstallationAuthorityRepository::new(restart_pool.clone());
        assert!(matches!(
            restarted_installation_repository
                .configure_deployment(installation_request.clone())
                .await?,
            ConfigureDeploymentInstallationOutcome::Replayed(_)
        ));
        restart_pool.close().await;
        let installation_counts: (i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM tenants
                    WHERE id='local-deployment-bootstrap'
                      AND display_name='Local deployment bootstrap'),
                (SELECT count(*) FROM installation_state
                    WHERE state='configured' AND configuration_mode='deployment'),
                (SELECT count(*) FROM security_audit_events
                    WHERE action='auth.installation.deployment_configured'
                      AND outcome='succeeded')
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(installation_counts, (1, 1, 1));

        let enrollment_repository =
            PostgresRunnerEnrollmentRepository::new(database.pool().clone());
        let runner_id = RunnerId::new();
        let enrollment_id = Uuid::new_v4();
        let token_sha256 = [0x41_u8; 32];
        let group = RunnerGroup::new("default")?;
        let ensure = EnsureInstallationBootstrapRunnerEnrollmentToken::new(
            installation.clone(),
            runner_id.as_uuid(),
            enrollment_id,
            token_sha256,
            group.clone(),
            INSTALLATION_BOOTSTRAP_ENROLLMENT_TOKEN_LIFETIME_MS,
        )?;
        let (left, right) = tokio::join!(
            enrollment_repository.ensure_installation_bootstrap_runner_enrollment_token(
                ensure.clone(),
                installation_recovery_identity,
            ),
            enrollment_repository.ensure_installation_bootstrap_runner_enrollment_token(
                ensure.clone(),
                installation_recovery_identity,
            ),
        );
        let enrollment_outcomes = [left?, right?];
        assert_eq!(
            enrollment_outcomes
                .iter()
                .filter(|outcome| matches!(outcome, InstallationBootstrapRunnerEnrollmentTokenOutcome::Applied(_)))
                .count(),
            1
        );
        assert_eq!(
            enrollment_outcomes
                .iter()
                .filter(|outcome| matches!(outcome, InstallationBootstrapRunnerEnrollmentTokenOutcome::Replayed(_)))
                .count(),
            1
        );
        let issued = enrollment_outcomes
            .into_iter()
            .find_map(|outcome| match outcome {
                InstallationBootstrapRunnerEnrollmentTokenOutcome::Applied(record) => Some(record),
                InstallationBootstrapRunnerEnrollmentTokenOutcome::Replayed(_)
                | InstallationBootstrapRunnerEnrollmentTokenOutcome::Refreshed(_)
                | InstallationBootstrapRunnerEnrollmentTokenOutcome::Conflict => None,
            })
            .ok_or_else(|| message_error("installation enrollment token was not applied"))?;
        assert_eq!(
            enrollment_repository
                .ensure_installation_bootstrap_runner_enrollment_token(
                    ensure.clone(),
                    installation_recovery_identity,
                )
                .await?,
            InstallationBootstrapRunnerEnrollmentTokenOutcome::Replayed(issued.clone())
        );
        let stored_initial: StoredInstallationBootstrapToken = sqlx::query_as(
            r"
            SELECT issuer_kind,issued_by_principal_id,issued_by_session_id,
                   issued_authorization_revision,installation_authority_sha256,
                   installation_runner_id,installation_generation,
                   installation_predecessor_enrollment_id,
                   issued_at_ms,last_refreshed_at_ms,expires_at_ms
            FROM runner_enrollment_tokens WHERE id=$1
            ",
        )
        .bind(enrollment_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(stored_initial.issuer_kind, "installation_bootstrap");
        assert_eq!(
            (
                stored_initial.issued_by_principal_id,
                stored_initial.issued_by_session_id,
                stored_initial.issued_authorization_revision,
            ),
            (None, None, None)
        );
        assert_eq!(
            stored_initial.installation_authority_sha256,
            Some(vec![0x31; 32])
        );
        assert_eq!(stored_initial.last_refreshed_at_ms, None);
        assert_eq!(stored_initial.installation_runner_id, Some(runner_id.as_uuid()));
        assert_eq!(stored_initial.installation_generation, Some(0));
        assert_eq!(stored_initial.installation_predecessor_enrollment_id, None);
        assert_eq!(stored_initial.expires_at_ms, issued.expires_at_ms);

        let conflicting = EnsureInstallationBootstrapRunnerEnrollmentToken::new(
            installation.clone(),
            runner_id.as_uuid(),
            enrollment_id,
            [0x42; 32],
            group.clone(),
            INSTALLATION_BOOTSTRAP_ENROLLMENT_TOKEN_LIFETIME_MS,
        )?;
        assert_eq!(
            enrollment_repository
                .ensure_installation_bootstrap_runner_enrollment_token(
                    conflicting,
                    installation_recovery_identity,
                )
                .await?,
            InstallationBootstrapRunnerEnrollmentTokenOutcome::Conflict
        );
        clock.set(issued.expires_at_ms - 1).await?;
        assert_eq!(
            enrollment_repository
                .ensure_installation_bootstrap_runner_enrollment_token(
                    ensure.clone(),
                    installation_recovery_identity,
                )
                .await?,
            InstallationBootstrapRunnerEnrollmentTokenOutcome::Replayed(issued.clone())
        );
        clock.set(issued.expires_at_ms).await?;
        match enrollment_repository
            .prepare_runner_enrollment(PrepareRunnerEnrollment {
                token_sha256,
                operation_id: Uuid::new_v4(),
                request_sha256: [0x43; 32],
            })
            .await?
        {
            RunnerEnrollmentPrepareOutcome::Rejected => {}
            RunnerEnrollmentPrepareOutcome::Prepared(prepared) => {
                return Err(message_error(format!(
                    "database-time expiry boundary was not observed: database_time_ms={}, expires_at_ms={}",
                    prepared.database_time_ms, prepared.expires_at_ms
                )));
            }
            RunnerEnrollmentPrepareOutcome::Replayed(_) => {
                return Err(message_error(
                    "unconsumed installation token unexpectedly replayed a redemption",
                ));
            }
        }
        let refreshed = match enrollment_repository
            .ensure_installation_bootstrap_runner_enrollment_token(
                ensure.clone(),
                installation_recovery_identity,
            )
            .await?
        {
            InstallationBootstrapRunnerEnrollmentTokenOutcome::Refreshed(record) => record,
            outcome => {
                return Err(message_error(format!(
                    "exact expiry boundary did not refresh installation token: {outcome:?}"
                )));
            }
        };
        assert_eq!(
            refreshed.expires_at_ms,
            issued.expires_at_ms + INSTALLATION_BOOTSTRAP_ENROLLMENT_TOKEN_LIFETIME_MS
        );
        let stored_refreshed: (i64, Option<i64>, i64) = sqlx::query_as(
            "SELECT issued_at_ms,last_refreshed_at_ms,expires_at_ms FROM runner_enrollment_tokens WHERE id=$1",
        )
        .bind(enrollment_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(stored_refreshed.0, stored_initial.issued_at_ms);
        assert_eq!(stored_refreshed.1, Some(issued.expires_at_ms));
        assert_eq!(stored_refreshed.2, refreshed.expires_at_ms);

        let restart_pool = database.connect_pool().await?;
        let restarted_enrollment_repository =
            PostgresRunnerEnrollmentRepository::new(restart_pool.clone());
        assert_eq!(
            restarted_enrollment_repository
                .ensure_installation_bootstrap_runner_enrollment_token(
                    ensure.clone(),
                    installation_recovery_identity,
                )
                .await?,
            InstallationBootstrapRunnerEnrollmentTokenOutcome::Replayed(refreshed.clone())
        );
        restart_pool.close().await;

        let operation_id = Uuid::new_v4();
        let request_sha256 = [0x51_u8; 32];
        let runner_name = "local-windows-runner";
        let response = br#"{"runner":"local-windows-runner"}"#.to_vec();
        let database_time_ms = clock.now().await?;
        let (capabilities, windows_admission) = windows_admission(
            database_time_ms,
            runner_id,
            operation_id,
            runner_name,
            token_sha256,
            group,
        )?;
        let certificate_issued_at_seconds = database_time_ms.div_euclid(1_000);
        let left_request = consume_request(
            token_sha256,
            operation_id,
            request_sha256,
            runner_id,
            runner_name,
            capabilities.clone(),
            certificate_issued_at_seconds,
            response.clone(),
            windows_admission.clone(),
        );
        let right_request = consume_request(
            token_sha256,
            operation_id,
            request_sha256,
            runner_id,
            runner_name,
            capabilities,
            certificate_issued_at_seconds,
            response.clone(),
            windows_admission,
        );
        let (left, right) = tokio::join!(
            enrollment_repository.consume_runner_enrollment(left_request),
            enrollment_repository.consume_runner_enrollment(right_request),
        );
        let consume_outcomes = [left?, right?];
        assert_eq!(
            consume_outcomes
                .iter()
                .filter(|outcome| matches!(outcome, RunnerEnrollmentConsumeOutcome::Applied(_)))
                .count(),
            1
        );
        assert_eq!(
            consume_outcomes
                .iter()
                .filter(|outcome| matches!(outcome, RunnerEnrollmentConsumeOutcome::Replayed(_)))
                .count(),
            1
        );
        let windows_counts: (i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM windows_runner_admissions WHERE runner_id=$1),
                (SELECT count(*) FROM windows_runner_admission_nonces WHERE enrollment_id=$2),
                (SELECT count(*) FROM windows_image_promotion_high_water),
                (SELECT count(*) FROM runners
                 WHERE id=$1
                   AND capabilities #>> '{platform,operating_system,kind}'='windows')
            ",
        )
        .bind(runner_id.as_uuid())
        .bind(enrollment_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(windows_counts, (1, 1, 1, 1));
        let recovery = match enrollment_repository
            .ensure_installation_bootstrap_runner_enrollment_token(
                ensure.clone(),
                installation_recovery_identity,
            )
            .await?
        {
            InstallationBootstrapRunnerEnrollmentTokenOutcome::Applied(record) => record,
            outcome => {
                return Err(message_error(format!(
                    "consumed generation zero did not advance exactly once: {outcome:?}"
                )));
            }
        };
        assert_eq!(recovery.generation, 1);
        assert_eq!(
            recovery.enrollment_id,
            installation_recovery_identity(1)?.enrollment_id()
        );
        clock.set(recovery.expires_at_ms).await?;
        let recovery_refreshed = match enrollment_repository
            .ensure_installation_bootstrap_runner_enrollment_token(
                ensure,
                installation_recovery_identity,
            )
            .await?
        {
            InstallationBootstrapRunnerEnrollmentTokenOutcome::Refreshed(record) => record,
            outcome => {
                return Err(message_error(format!(
                    "expired unconsumed recovery generation was not refreshed: {outcome:?}"
                )));
            }
        };
        assert_eq!(recovery_refreshed.generation, 1);
        assert_eq!(recovery_refreshed.enrollment_id, recovery.enrollment_id);

        // A distinct Linux installation runner exercises the positive-
        // generation recovery path itself. The earlier Windows runner proves
        // that generation issuance does not broaden broker-owned admission;
        // recovery consumption remains deliberately unavailable to Windows.
        let linux_runner_id = RunnerId::new();
        let linux_enrollment_id = Uuid::new_v4();
        let linux_token_sha256 = [0x81_u8; 32];
        let linux_group = RunnerGroup::new("default")?;
        let linux_ensure = EnsureInstallationBootstrapRunnerEnrollmentToken::new(
            installation.clone(),
            linux_runner_id.as_uuid(),
            linux_enrollment_id,
            linux_token_sha256,
            linux_group.clone(),
            INSTALLATION_BOOTSTRAP_ENROLLMENT_TOKEN_LIFETIME_MS,
        )?;
        let linux_initial = match enrollment_repository
            .ensure_installation_bootstrap_runner_enrollment_token(
                linux_ensure.clone(),
                |generation| installation_recovery_identity_for(0x81, generation),
            )
            .await?
        {
            InstallationBootstrapRunnerEnrollmentTokenOutcome::Applied(record) => record,
            outcome => {
                return Err(message_error(format!(
                    "Linux generation zero was not issued: {outcome:?}"
                )));
            }
        };
        assert_eq!(linux_initial.generation, 0);
        let linux_capabilities = RunnerCapabilities::new(
            linux_runner_id,
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        )
        .with_groups([linux_group]);
        let linux_now_ms = clock.now().await?;
        let linux_now_seconds = linux_now_ms.div_euclid(1_000);
        let linux_name = "local-linux-runner";
        let initial_leaf = [0x82_u8; 32];
        let initial_expires_at_seconds =
            linux_now_seconds + MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS;
        let initial_response = br#"{"runner":"local-linux-runner","generation":0}"#.to_vec();
        let initial_operation_id = Uuid::new_v4();
        let initial_request_sha256 = [0x83_u8; 32];
        let initial_consume = ConsumeRunnerEnrollment {
            token_sha256: linux_token_sha256,
            operation_id: initial_operation_id,
            request_sha256: initial_request_sha256,
            runner_id: linux_runner_id.as_uuid(),
            runner_name: linux_name.to_owned(),
            capabilities: linux_capabilities.clone(),
            certificate_leaf_sha256: initial_leaf,
            certificate_issued_at_seconds: linux_now_seconds,
            certificate_expires_at_seconds: initial_expires_at_seconds,
            response: initial_response,
            windows_admission: None,
        };
        assert!(matches!(
            enrollment_repository
                .consume_runner_enrollment(initial_consume)
                .await?,
            RunnerEnrollmentConsumeOutcome::Applied(_)
        ));
        let linux_recovery = match enrollment_repository
            .ensure_installation_bootstrap_runner_enrollment_token(
                linux_ensure.clone(),
                |generation| installation_recovery_identity_for(0x81, generation),
            )
            .await?
        {
            InstallationBootstrapRunnerEnrollmentTokenOutcome::Applied(record) => record,
            outcome => {
                return Err(message_error(format!(
                    "Linux recovery generation was not issued: {outcome:?}"
                )));
            }
        };
        let recovery_identity = installation_recovery_identity_for(0x81, 1)?;
        assert_eq!(linux_recovery.generation, 1);
        assert_eq!(linux_recovery.enrollment_id, recovery_identity.enrollment_id());
        let drifted_linux_genesis = EnsureInstallationBootstrapRunnerEnrollmentToken::new(
            installation.clone(),
            linux_runner_id.as_uuid(),
            Uuid::new_v4(),
            [0x91; 32],
            RunnerGroup::new("default")?,
            INSTALLATION_BOOTSTRAP_ENROLLMENT_TOKEN_LIFETIME_MS,
        )?;
        assert_eq!(
            enrollment_repository
                .ensure_installation_bootstrap_runner_enrollment_token(
                    drifted_linux_genesis,
                    |generation| installation_recovery_identity_for(0x81, generation),
                )
                .await?,
            InstallationBootstrapRunnerEnrollmentTokenOutcome::Conflict,
            "a positive-generation tail must remain bound to its exact generation-zero identity"
        );
        assert_eq!(
            enrollment_repository
                .consume_installation_runner_recovery(
                    ConsumeRunnerEnrollment {
                        token_sha256: recovery_identity.token_sha256(),
                        operation_id: Uuid::new_v4(),
                        request_sha256: [0x87; 32],
                        runner_id: linux_runner_id.as_uuid(),
                        runner_name: linux_name.to_owned(),
                        capabilities: linux_capabilities.clone(),
                        certificate_leaf_sha256: [0x88; 32],
                        certificate_issued_at_seconds: linux_now_seconds,
                        certificate_expires_at_seconds: initial_expires_at_seconds,
                        response: br#"{"premature":true}"#.to_vec(),
                        windows_admission: None,
                    },
                    InstallationRunnerRecoveryPredecessor {
                        certificate_leaf_sha256: initial_leaf,
                        certificate_expires_at_seconds: initial_expires_at_seconds,
                    },
                )
                .await?,
            InstallationRunnerRecoveryConsumeOutcome::Rejected,
            "the installation token must not rotate a still-current local predecessor"
        );
        clock
            .set(initial_expires_at_seconds.saturating_mul(1_000))
            .await?;
        let linux_recovery = match enrollment_repository
            .ensure_installation_bootstrap_runner_enrollment_token(
                linux_ensure.clone(),
                |generation| installation_recovery_identity_for(0x81, generation),
            )
            .await?
        {
            InstallationBootstrapRunnerEnrollmentTokenOutcome::Refreshed(record) => record,
            outcome => {
                return Err(message_error(format!(
                    "expired Linux recovery token was not refreshed: {outcome:?}"
                )));
            }
        };
        assert_eq!(linux_recovery.generation, 1);
        let recovery_now_ms = clock.now().await?;
        let recovery_now_seconds = recovery_now_ms.div_euclid(1_000);
        let newer_live_leaf = [0x86_u8; 32];
        let newer_live_expires_at_seconds = recovery_now_seconds + 1;
        sqlx::query(
            "INSERT INTO runner_machine_certificates (leaf_sha256,runner_id,expires_at_seconds) VALUES ($1,$2,$3)",
        )
        .bind(newer_live_leaf.as_slice())
        .bind(linux_runner_id.as_uuid())
        .bind(newer_live_expires_at_seconds)
        .execute(database.pool())
        .await?;
        let recovery_operation_id = Uuid::new_v4();
        let recovery_request_sha256 = [0x84_u8; 32];
        let recovery_prepare = PrepareRunnerEnrollment {
            token_sha256: recovery_identity.token_sha256(),
            operation_id: recovery_operation_id,
            request_sha256: recovery_request_sha256,
        };
        match enrollment_repository
            .prepare_installation_runner_recovery(recovery_prepare)
            .await?
        {
            InstallationRunnerRecoveryPrepareOutcome::Prepared(prepared) => {
                assert_eq!(prepared.runner_id, linux_runner_id.as_uuid());
                assert_eq!(prepared.generation, 1);
                assert_eq!(prepared.runner_group, "default");
            }
            outcome => {
                return Err(message_error(format!(
                    "Linux recovery generation was not prepared: {outcome:?}"
                )));
            }
        }
        let recovered_leaf = [0x85_u8; 32];
        let recovered_expires_at_seconds =
            recovery_now_seconds + MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS;
        let recovered_response =
            br#"{"runner":"local-linux-runner","generation":1}"#.to_vec();
        let recovery_consume = || ConsumeRunnerEnrollment {
            token_sha256: recovery_identity.token_sha256(),
            operation_id: recovery_operation_id,
            request_sha256: recovery_request_sha256,
            runner_id: linux_runner_id.as_uuid(),
            runner_name: linux_name.to_owned(),
            capabilities: linux_capabilities.clone(),
            certificate_leaf_sha256: recovered_leaf,
            certificate_issued_at_seconds: recovery_now_seconds,
            certificate_expires_at_seconds: recovered_expires_at_seconds,
            response: recovered_response.clone(),
            windows_admission: None,
        };
        let revoked_historical_leaf = [0x89_u8; 32];
        let revoked_historical_expiry = recovery_now_seconds - 1;
        sqlx::query(
            "INSERT INTO runner_machine_certificates (leaf_sha256,runner_id,expires_at_seconds,revoked_at_seconds) VALUES ($1,$2,$3,$4)",
        )
        .bind(revoked_historical_leaf.as_slice())
        .bind(linux_runner_id.as_uuid())
        .bind(revoked_historical_expiry)
        .bind(revoked_historical_expiry - 1)
        .execute(database.pool())
        .await?;
        assert_eq!(
            enrollment_repository
                .consume_installation_runner_recovery(
                    recovery_consume(),
                    InstallationRunnerRecoveryPredecessor {
                        certificate_leaf_sha256: revoked_historical_leaf,
                        certificate_expires_at_seconds: revoked_historical_expiry,
                    },
                )
                .await?,
            InstallationRunnerRecoveryConsumeOutcome::Rejected,
            "a revoked historical leaf must not authorize installation recovery"
        );
        assert_eq!(
            enrollment_repository
                .consume_installation_runner_recovery(
                    recovery_consume(),
                    InstallationRunnerRecoveryPredecessor {
                        certificate_leaf_sha256: initial_leaf,
                        certificate_expires_at_seconds: initial_expires_at_seconds,
                    },
                )
                .await?,
            InstallationRunnerRecoveryConsumeOutcome::Rejected,
            "an expired historical leaf must not rotate a newer live successor"
        );
        let stale_predecessor_state: (i64, Option<i64>, bool, Option<i64>) =
            sqlx::query_as(
                r"
                SELECT
                    (SELECT generation FROM runners WHERE id=$1),
                    (SELECT consumed_at_ms FROM runner_enrollment_tokens WHERE id=$2),
                    EXISTS (SELECT 1 FROM runner_machine_certificates WHERE leaf_sha256=$3),
                    (SELECT revoked_at_seconds FROM runner_machine_certificates
                     WHERE leaf_sha256=$4)
                ",
            )
            .bind(linux_runner_id.as_uuid())
            .bind(linux_recovery.enrollment_id)
            .bind(recovered_leaf.as_slice())
            .bind(newer_live_leaf.as_slice())
            .fetch_one(database.pool())
            .await?;
        assert_eq!(
            stale_predecessor_state,
            (1, None, false, None),
            "stale-predecessor rejection must not mutate runner, token, or certificate authority"
        );
        let recovery_boundary_ms = newer_live_expires_at_seconds.saturating_mul(1_000);
        clock.set(recovery_boundary_ms).await?;
        let mut runner_lock = database.pool().begin().await?;
        let locked_runner: Uuid = sqlx::query_scalar(
            "SELECT id FROM runners WHERE id=$1 FOR UPDATE",
        )
        .bind(linux_runner_id.as_uuid())
        .fetch_one(&mut *runner_lock)
        .await?;
        assert_eq!(locked_runner, linux_runner_id.as_uuid());
        let blocked_repository = enrollment_repository.clone();
        let blocked_request = recovery_consume();
        let blocked_predecessor = InstallationRunnerRecoveryPredecessor {
            certificate_leaf_sha256: newer_live_leaf,
            certificate_expires_at_seconds: newer_live_expires_at_seconds,
        };
        let blocked_consume = tokio::spawn(async move {
            blocked_repository
                .consume_installation_runner_recovery(blocked_request, blocked_predecessor)
                .await
        });
        let mut consume_waits_for_runner = false;
        for _ in 0..200 {
            consume_waits_for_runner = sqlx::query_scalar(
                r"
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_stat_activity
                    WHERE datname=pg_catalog.current_database()
                      AND pid <> pg_catalog.pg_backend_pid()
                      AND wait_event_type='Lock'
                      AND query LIKE '%FROM runners%'
                      AND query LIKE '%FOR UPDATE%'
                )
                ",
            )
            .fetch_one(database.pool())
            .await?;
            if consume_waits_for_runner {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            consume_waits_for_runner,
            "recovery consumption did not reach the runner authority lock"
        );
        clock.set(linux_recovery.expires_at_ms).await?;
        runner_lock.commit().await?;
        assert_eq!(
            blocked_consume.await??,
            InstallationRunnerRecoveryConsumeOutcome::Rejected,
            "consumption blocked across token expiry must use a fresh post-lock database time"
        );
        let rejected_recovery_state: (i64, Option<i64>, bool) = sqlx::query_as(
            r"
            SELECT
                (SELECT generation FROM runners WHERE id=$1),
                (SELECT consumed_at_ms FROM runner_enrollment_tokens WHERE id=$2),
                EXISTS (SELECT 1 FROM runner_machine_certificates WHERE leaf_sha256=$3)
            ",
        )
        .bind(linux_runner_id.as_uuid())
        .bind(linux_recovery.enrollment_id)
        .bind(recovered_leaf.as_slice())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            rejected_recovery_state,
            (1, None, false),
            "post-lock token expiry must leave runner, token, and certificate custody unchanged"
        );
        clock.set(recovery_boundary_ms).await?;
        assert_eq!(
            enrollment_repository
                .consume_installation_runner_recovery(
                    recovery_consume(),
                    InstallationRunnerRecoveryPredecessor {
                        certificate_leaf_sha256: newer_live_leaf,
                        certificate_expires_at_seconds: newer_live_expires_at_seconds,
                    },
                )
                .await?,
            InstallationRunnerRecoveryConsumeOutcome::Applied(recovered_response.clone())
        );
        let recovered_runner_fence: (i64, i64) = sqlx::query_as(
            "SELECT generation,updated_at_ms FROM runners WHERE id=$1",
        )
        .bind(linux_runner_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            recovered_runner_fence,
            (2, clock.now().await?),
            "recovery must advance the durable runner generation before an old-leaf handshake can open a session"
        );
        let stored_recovery_predecessor: (Vec<u8>, i64) = sqlx::query_as(
            r"
            SELECT redeem_predecessor_certificate_leaf_sha256,
                   redeem_predecessor_certificate_expires_at_seconds
            FROM runner_enrollment_tokens
            WHERE id=$1
            ",
        )
        .bind(linux_recovery.enrollment_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            stored_recovery_predecessor.0.as_slice(),
            newer_live_leaf.as_slice()
        );
        assert_eq!(
            stored_recovery_predecessor.1,
            newer_live_expires_at_seconds
        );
        assert_eq!(
            enrollment_repository
                .consume_installation_runner_recovery(
                    recovery_consume(),
                    InstallationRunnerRecoveryPredecessor {
                        certificate_leaf_sha256: newer_live_leaf,
                        certificate_expires_at_seconds: newer_live_expires_at_seconds,
                    },
                )
                .await?,
            InstallationRunnerRecoveryConsumeOutcome::Replayed(recovered_response.clone())
        );
        let certificate_state: (Option<i64>, Option<i64>, Option<i64>) = sqlx::query_as(
            r"
            SELECT
                (SELECT revoked_at_seconds FROM runner_machine_certificates
                 WHERE leaf_sha256=$1),
                (SELECT revoked_at_seconds FROM runner_machine_certificates
                 WHERE leaf_sha256=$2),
                (SELECT revoked_at_seconds FROM runner_machine_certificates
                 WHERE leaf_sha256=$3)
            ",
        )
        .bind(initial_leaf.as_slice())
        .bind(newer_live_leaf.as_slice())
        .bind(recovered_leaf.as_slice())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(certificate_state, (None, None, None));
        let mut certificate_lock = database.pool().begin().await?;
        sqlx::query(
            "SELECT leaf_sha256 FROM runner_machine_certificates WHERE leaf_sha256=$1 FOR UPDATE",
        )
        .bind(recovered_leaf.as_slice())
        .fetch_one(&mut *certificate_lock)
        .await?;
        let replay_repository = enrollment_repository.clone();
        let blocked_replay = tokio::spawn(async move {
            replay_repository
                .prepare_installation_runner_recovery(PrepareRunnerEnrollment {
                    token_sha256: recovery_identity.token_sha256(),
                    operation_id: recovery_operation_id,
                    request_sha256: recovery_request_sha256,
                })
                .await
        });
        let mut replay_waits_for_certificate = false;
        for _ in 0..200 {
            replay_waits_for_certificate = sqlx::query_scalar(
                r"
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_stat_activity
                    WHERE datname=pg_catalog.current_database()
                      AND pid <> pg_catalog.pg_backend_pid()
                      AND wait_event_type='Lock'
                      AND query LIKE '%FROM runner_machine_certificates%'
                      AND query LIKE '%FOR SHARE%'
                )
                ",
            )
            .fetch_one(database.pool())
            .await?;
            if replay_waits_for_certificate {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            replay_waits_for_certificate,
            "exact replay did not reach the certificate currentness lock"
        );
        clock
            .set(recovered_expires_at_seconds.saturating_mul(1_000))
            .await?;
        certificate_lock.commit().await?;
        assert_eq!(
            blocked_replay.await??,
            InstallationRunnerRecoveryPrepareOutcome::Rejected,
            "replay blocked across leaf expiry must use a fresh post-lock database time"
        );
        // The blocked replay was read-only. Restore its pre-boundary test time
        // so the independent revoked-current-leaf gate remains isolated.
        clock.set(recovery_boundary_ms).await?;
        let recovery_audits: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM security_audit_events WHERE action='runner.certificate.installation_recover' AND outcome='succeeded'",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(recovery_audits, 1);
        let linux_next = match enrollment_repository
            .ensure_installation_bootstrap_runner_enrollment_token(
                linux_ensure,
                |generation| installation_recovery_identity_for(0x81, generation),
            )
            .await?
        {
            InstallationBootstrapRunnerEnrollmentTokenOutcome::Applied(record) => record,
            outcome => {
                return Err(message_error(format!(
                    "consumed Linux recovery did not advance once: {outcome:?}"
                )));
            }
        };
        assert_eq!(linux_next.generation, 2);
        assert_eq!(
            linux_next.enrollment_id,
            installation_recovery_identity_for(0x81, 2)?.enrollment_id()
        );
        sqlx::query(
            "UPDATE runner_machine_certificates SET revoked_at_seconds=$2 WHERE leaf_sha256=$1",
        )
        .bind(recovered_leaf.as_slice())
        .bind(newer_live_expires_at_seconds)
        .execute(database.pool())
        .await?;
        assert_eq!(
            enrollment_repository
                .prepare_installation_runner_recovery(PrepareRunnerEnrollment {
                    token_sha256: recovery_identity.token_sha256(),
                    operation_id: recovery_operation_id,
                    request_sha256: recovery_request_sha256,
                })
                .await?,
            InstallationRunnerRecoveryPrepareOutcome::Rejected,
            "exact replay must not return credentials after their response leaf is revoked"
        );
        assert_eq!(
            enrollment_repository
                .consume_installation_runner_recovery(
                    recovery_consume(),
                    InstallationRunnerRecoveryPredecessor {
                        certificate_leaf_sha256: newer_live_leaf,
                        certificate_expires_at_seconds: newer_live_expires_at_seconds,
                    },
                )
                .await?,
            InstallationRunnerRecoveryConsumeOutcome::Rejected,
            "consume replay must not reinstall a revoked response leaf"
        );

        let mutation_error = sqlx::query(
            "UPDATE runner_enrollment_tokens SET redeem_response=$2 WHERE id=$1",
        )
        .bind(enrollment_id)
        .bind(br#"{"corrupt":true}"#.as_slice())
        .execute(database.pool())
        .await
        .expect_err("consumed installation token mutation must fail");
        assert_constraint(
            &mutation_error,
            "runner_enrollment_tokens_consume_once",
        );
        let audit_event_id: Uuid = sqlx::query_scalar(
            "SELECT deployment_bootstrap_audit_event_id FROM installation_state WHERE singleton",
        )
        .fetch_one(database.pool())
        .await?;
        let audit_error = sqlx::query("DELETE FROM security_audit_events WHERE event_id=$1")
            .bind(audit_event_id)
            .execute(database.pool())
            .await
            .expect_err("installation audit evidence must be append-only");
        assert_constraint(&audit_error, "security_audit_events_append_only");
        let runner_group_id: Uuid = sqlx::query_scalar(
            "SELECT runner_group_id FROM runner_enrollment_tokens WHERE id=$1",
        )
        .bind(enrollment_id)
        .fetch_one(database.pool())
        .await?;
        let foreign_key_error = sqlx::query(
            r"
            INSERT INTO runner_enrollment_tokens (
                id,tenant_id,runner_group_id,token_sha256,issuer_kind,
                installation_authority_sha256,installation_runner_id,
                installation_generation,issued_at_ms,expires_at_ms
            ) VALUES ($1,'local-deployment-bootstrap',$2,$3,
                      'installation_bootstrap',$4,$5,0,$6,$7)
            ",
        )
        .bind(Uuid::new_v4())
        .bind(runner_group_id)
        .bind([0x71_u8; 32].as_slice())
        .bind([0x72_u8; 32].as_slice())
        .bind(Uuid::new_v4())
        .bind(clock.now().await?)
        .bind(clock.now().await? + INSTALLATION_BOOTSTRAP_ENROLLMENT_TOKEN_LIFETIME_MS)
        .execute(database.pool())
        .await
        .expect_err("crossed installation authority must fail its foreign key");
        assert_constraint(
            &foreign_key_error,
            "runner_enrollment_tokens_installation_authority_fkey",
        );
        let bootstrap_audits: (i64, i64) = sqlx::query_as(
            r"
            SELECT
                count(*) FILTER (WHERE outcome='succeeded'),
                count(*) FILTER (WHERE outcome='failed')
            FROM security_audit_events
            WHERE action='runner.enrollment_token.installation_bootstrap'
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(bootstrap_audits, (8, 2));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 via AUTOMATA_TEST_DATABASE_URL"]
#[allow(
    clippy::too_many_lines,
    reason = "the predecessor fixture and post-migration continuity assertions are intentionally contiguous"
)]
async fn migration_0069_upgrades_0051_human_installation_and_token_exactly() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        let fixture = seed_0051_human_upgrade_fixture(&database).await?;
        let LegacyHumanUpgradeFixture {
            now_ms,
            principal_id,
            session_id,
            authorization_revision,
            enrollment_id,
            token_sha256,
            ..
        } = fixture;
        sqlx::query(
            r"
            UPDATE human_auth_installation_state
            SET state='pending',bootstrap_token_hash=$1,
                bootstrap_hash_key_id='upgrade-key',expected_provider_id='github',
                expected_provider_subject='upgrade-subject',
                challenge_expires_at_ms=$2,target_tenant_id=$3,
                target_tenant_display_name=$4,updated_at_ms=$5,
                revision=revision+1
            WHERE singleton=TRUE AND state='unconfigured'
            ",
        )
        .bind([0x61_u8; 32].as_slice())
        .bind(now_ms + 600_000)
        .bind(LEGACY_TENANT_ID)
        .bind(LEGACY_TENANT_DISPLAY_NAME)
        .bind(now_ms)
        .execute(database.pool())
        .await?;

        MIGRATOR.run(database.pool()).await?;
        let applied_version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
            .fetch_one(database.pool())
            .await?;
        assert_eq!(applied_version, 69);
        let relation_names: (Option<String>, Option<String>) = sqlx::query_as(
            r"
            SELECT
                pg_catalog.to_regclass('human_auth_installation_state')::TEXT,
                pg_catalog.to_regclass('installation_state')::TEXT
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            relation_names,
            (None, Some("installation_state".to_owned()))
        );
        let upgraded_installation: (String, Option<String>, Option<String>, Option<String>, i64) =
            sqlx::query_as(
                r"
                SELECT state,configuration_mode,tenant_id,tenant_display_name,revision
                FROM installation_state WHERE singleton=TRUE
                ",
            )
            .fetch_one(database.pool())
            .await?;
        assert_eq!(
            upgraded_installation,
            (
                "pending".to_owned(),
                Some("human".to_owned()),
                Some(LEGACY_TENANT_ID.to_owned()),
                Some(LEGACY_TENANT_DISPLAY_NAME.to_owned()),
                2,
            )
        );
        let tenant_display_name: String =
            sqlx::query_scalar("SELECT display_name FROM tenants WHERE id=$1")
                .bind(LEGACY_TENANT_ID)
                .fetch_one(database.pool())
                .await?;
        assert_eq!(tenant_display_name, LEGACY_TENANT_DISPLAY_NAME);
        let upgraded_token: StoredInstallationBootstrapToken = sqlx::query_as(
            r"
            SELECT issuer_kind,issued_by_principal_id,issued_by_session_id,
                   issued_authorization_revision,installation_authority_sha256,
                   installation_runner_id,installation_generation,
                   installation_predecessor_enrollment_id,
                   issued_at_ms,last_refreshed_at_ms,expires_at_ms
            FROM runner_enrollment_tokens WHERE id=$1
            ",
        )
        .bind(enrollment_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(upgraded_token.issuer_kind, "human");
        assert_eq!(upgraded_token.issued_by_principal_id, Some(principal_id));
        assert_eq!(upgraded_token.issued_by_session_id, Some(session_id));
        assert_eq!(
            upgraded_token.issued_authorization_revision,
            Some(authorization_revision)
        );
        assert_eq!(upgraded_token.installation_authority_sha256, None);
        assert_eq!(upgraded_token.installation_runner_id, None);
        assert_eq!(upgraded_token.installation_generation, None);
        assert_eq!(upgraded_token.installation_predecessor_enrollment_id, None);
        assert_eq!(upgraded_token.last_refreshed_at_ms, None);
        assert_eq!(upgraded_token.issued_at_ms, now_ms);
        assert_eq!(upgraded_token.expires_at_ms, now_ms + 600_000);

        let enrollment_repository =
            PostgresRunnerEnrollmentRepository::new(database.pool().clone());
        let prepared = enrollment_repository
            .prepare_runner_enrollment(PrepareRunnerEnrollment {
                token_sha256,
                operation_id: Uuid::new_v4(),
                request_sha256: [0x63; 32],
            })
            .await
            .map_err(|error| {
                message_error(format!(
                    "upgraded human enrollment token was rejected as corrupt: {error:?}"
                ))
            })?;
        assert!(matches!(
            prepared,
            RunnerEnrollmentPrepareOutcome::Prepared(_)
        ));
        let installation_repository =
            PostgresInstallationAuthorityRepository::new(database.pool().clone());
        let crossed = installation_repository
            .configure_deployment(ConfigureDeploymentInstallation::new(
                [0x64; 32],
                Uuid::new_v4(),
                InstallationTenant::new(
                    TenantId::new("crossed-deployment")?,
                    "Crossed deployment",
                )?,
            )?)
            .await
            .map_err(|error| {
                message_error(format!(
                    "upgraded pending human installation was rejected as corrupt: {error:?}"
                ))
            })?;
        assert!(matches!(
            crossed,
            ConfigureDeploymentInstallationOutcome::Conflict
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 via AUTOMATA_TEST_DATABASE_URL"]
#[allow(
    clippy::too_many_lines,
    reason = "the configured singleton and consumed token must cross the migration together as one legacy authority witness"
)]
async fn migration_0069_upgrades_configured_human_and_consumed_token_exactly() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        let fixture = seed_0051_human_upgrade_fixture(&database).await?;
        let LegacyHumanUpgradeFixture {
            now_ms,
            principal_id,
            session_id,
            authorization_revision,
            runner_group_id,
            enrollment_id,
            token_sha256,
        } = fixture;

        let armed = sqlx::query(
            r"
            UPDATE human_auth_installation_state
            SET state='pending',bootstrap_token_hash=$1,
                bootstrap_hash_key_id='configured-upgrade-key',
                expected_provider_id=$2,expected_provider_subject=$3,
                challenge_expires_at_ms=$4,target_tenant_id=$5,
                target_tenant_display_name=$6,updated_at_ms=$7,
                revision=revision+1
            WHERE singleton=TRUE AND state='unconfigured'
            ",
        )
        .bind([0x65_u8; 32].as_slice())
        .bind(LEGACY_PROVIDER_ID)
        .bind(LEGACY_PROVIDER_SUBJECT)
        .bind(now_ms + 600_000)
        .bind(LEGACY_TENANT_ID)
        .bind(LEGACY_TENANT_DISPLAY_NAME)
        .bind(now_ms)
        .execute(database.pool())
        .await?;
        assert_eq!(armed.rows_affected(), 1);

        let setup_transaction_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO human_login_transactions (
                id,tenant_id,purpose,flow_kind,provider_id,return_path,
                state_hash,state_hash_key_id,browser_binding_hash,
                browser_binding_hash_key_id,poll_proof_hash,
                poll_proof_hash_key_id,encrypted_payload,payload_nonce,
                wrapped_data_key,encryption_key_id,encryption_schema,
                poll_interval_ms,next_poll_at_ms,created_at_ms,updated_at_ms,
                expires_at_ms
            ) VALUES (
                $1,NULL,'installation_setup','browser',$2,NULL,
                $3,'configured-upgrade-state',$4,
                'configured-upgrade-browser',NULL,NULL,$5,$6,$7,
                'configured-upgrade-envelope',1,NULL,NULL,$8,$8,$9
            )
            ",
        )
        .bind(setup_transaction_id)
        .bind(LEGACY_PROVIDER_ID)
        .bind([0x66_u8; 32].as_slice())
        .bind([0x67_u8; 32].as_slice())
        .bind(vec![0x68_u8; 17])
        .bind(vec![0x69_u8; 12])
        .bind(vec![0x6a_u8; 32])
        .bind(now_ms)
        .bind(now_ms + 600_000)
        .execute(database.pool())
        .await?;
        let bound = sqlx::query(
            r"
            UPDATE human_auth_installation_state
            SET setup_transaction_id=$1,updated_at_ms=$2,revision=revision+1
            WHERE singleton=TRUE AND state='pending'
              AND setup_transaction_id IS NULL
            ",
        )
        .bind(setup_transaction_id)
        .bind(now_ms)
        .execute(database.pool())
        .await?;
        assert_eq!(bound.rows_affected(), 1);

        let consumed_login = sqlx::query(
            r"
            UPDATE human_login_transactions
            SET status='consumed',consumed_at_ms=$2,updated_at_ms=$2,
                revision=revision+1
            WHERE id=$1 AND status='pending'
            ",
        )
        .bind(setup_transaction_id)
        .bind(now_ms)
        .execute(database.pool())
        .await?;
        assert_eq!(consumed_login.rows_affected(), 1);
        let completed_login = sqlx::query(
            r"
            UPDATE human_login_transactions
            SET status='succeeded',completed_principal_id=$2,updated_at_ms=$3,
                revision=revision+1
            WHERE id=$1 AND status='consumed'
            ",
        )
        .bind(setup_transaction_id)
        .bind(principal_id)
        .bind(now_ms)
        .execute(database.pool())
        .await?;
        assert_eq!(completed_login.rows_affected(), 1);
        let configured = sqlx::query(
            r"
            UPDATE human_auth_installation_state
            SET state='configured',bootstrap_token_hash=NULL,
                bootstrap_hash_key_id=NULL,challenge_expires_at_ms=NULL,
                configured_tenant_id=$1,configured_principal_id=$2,
                configured_at_ms=$3,updated_at_ms=$3,revision=revision+1
            WHERE singleton=TRUE AND state='pending'
              AND setup_transaction_id=$4
            ",
        )
        .bind(LEGACY_TENANT_ID)
        .bind(principal_id)
        .bind(now_ms)
        .bind(setup_transaction_id)
        .execute(database.pool())
        .await?;
        assert_eq!(configured.rows_affected(), 1);

        let consumed_runner = RunnerId::new();
        let runner_group = RunnerGroup::new("upgrade")?;
        let runner_capabilities = RunnerCapabilities::new(
            consumed_runner,
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        )
        .with_groups([runner_group]);
        let runner_labels = runner_capabilities
            .labels()
            .iter()
            .map(automata_ci_core::RunnerLabel::as_str)
            .collect::<Vec<_>>();
        sqlx::query(
            r"
            INSERT INTO runners (
                id,tenant_id,group_id,name,normalized_name,labels,capabilities,
                slots,status,generation,created_at_ms,updated_at_ms,
                external_identity,desired_state
            ) VALUES (
                $1,$2,$3,'upgrade-runner','upgrade-runner',$4,$5,$6,
                'offline',1,$7,$7,$8,'active'
            )
            ",
        )
        .bind(consumed_runner.as_uuid())
        .bind(LEGACY_TENANT_ID)
        .bind(runner_group_id)
        .bind(runner_labels)
        .bind(serde_json::to_value(&runner_capabilities)?)
        .bind(i32::from(runner_capabilities.max_parallel_jobs()))
        .bind(now_ms)
        .bind(format!(
            "automata:runner:{}",
            consumed_runner.as_uuid().hyphenated()
        ))
        .execute(database.pool())
        .await?;

        let redeem_operation_id = Uuid::new_v4();
        let redeem_request_sha256 = [0x6b_u8; 32];
        let redeem_response = br#"{"runner":"upgrade-runner","source":"0051"}"#.to_vec();
        let certificate_expires_at_seconds = now_ms.div_euclid(1_000) + 3_600;
        let consumed_token = sqlx::query(
            r"
            UPDATE runner_enrollment_tokens
            SET consumed_at_ms=$2,consumed_runner_id=$3,
                redeem_operation_id=$4,redeem_request_sha256=$5,
                redeem_response=$6,redeem_certificate_expires_at_seconds=$7
            WHERE id=$1 AND consumed_at_ms IS NULL
            ",
        )
        .bind(enrollment_id)
        .bind(now_ms)
        .bind(consumed_runner.as_uuid())
        .bind(redeem_operation_id)
        .bind(redeem_request_sha256.as_slice())
        .bind(&redeem_response)
        .bind(certificate_expires_at_seconds)
        .execute(database.pool())
        .await?;
        assert_eq!(consumed_token.rows_affected(), 1);
        sqlx::query(
            r"
            INSERT INTO runner_machine_certificates (
                leaf_sha256,runner_id,expires_at_seconds
            ) VALUES ($1,$2,$3)
            ",
        )
        .bind([0x6c_u8; 32].as_slice())
        .bind(consumed_runner.as_uuid())
        .bind(certificate_expires_at_seconds)
        .execute(database.pool())
        .await?;

        MIGRATOR.run(database.pool()).await?;
        let applied_version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
            .fetch_one(database.pool())
            .await?;
        assert_eq!(applied_version, 69);

        let upgraded_installation: StoredLegacyHumanInstallation = sqlx::query_as(
            r"
            SELECT state,configuration_mode,tenant_id,tenant_display_name,
                   configured_tenant_id,configured_principal_id,
                   setup_transaction_id,configured_at_ms,revision,
                   deployment_authority_sha256,
                   deployment_bootstrap_operation_id,
                   deployment_bootstrap_audit_event_id
            FROM installation_state WHERE singleton=TRUE
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(upgraded_installation.state, "configured");
        assert_eq!(
            upgraded_installation.configuration_mode.as_deref(),
            Some("human")
        );
        assert_eq!(
            upgraded_installation.tenant_id.as_deref(),
            Some(LEGACY_TENANT_ID)
        );
        assert_eq!(
            upgraded_installation.tenant_display_name.as_deref(),
            Some(LEGACY_TENANT_DISPLAY_NAME)
        );
        assert_eq!(
            upgraded_installation.configured_tenant_id.as_deref(),
            Some(LEGACY_TENANT_ID)
        );
        assert_eq!(
            upgraded_installation.configured_principal_id,
            Some(principal_id)
        );
        assert_eq!(
            upgraded_installation.setup_transaction_id,
            Some(setup_transaction_id)
        );
        assert_eq!(upgraded_installation.configured_at_ms, Some(now_ms));
        assert_eq!(upgraded_installation.revision, 4);
        assert_eq!(upgraded_installation.deployment_authority_sha256, None);
        assert_eq!(
            upgraded_installation.deployment_bootstrap_operation_id,
            None
        );
        assert_eq!(
            upgraded_installation.deployment_bootstrap_audit_event_id,
            None
        );

        let upgraded_token: StoredInstallationBootstrapToken = sqlx::query_as(
            r"
            SELECT issuer_kind,issued_by_principal_id,issued_by_session_id,
                   issued_authorization_revision,installation_authority_sha256,
                   installation_runner_id,installation_generation,
                   installation_predecessor_enrollment_id,
                   issued_at_ms,last_refreshed_at_ms,expires_at_ms
            FROM runner_enrollment_tokens WHERE id=$1
            ",
        )
        .bind(enrollment_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(upgraded_token.issuer_kind, "human");
        assert_eq!(upgraded_token.issued_by_principal_id, Some(principal_id));
        assert_eq!(upgraded_token.issued_by_session_id, Some(session_id));
        assert_eq!(
            upgraded_token.issued_authorization_revision,
            Some(authorization_revision)
        );
        assert_eq!(upgraded_token.installation_authority_sha256, None);
        assert_eq!(upgraded_token.installation_runner_id, None);
        assert_eq!(upgraded_token.installation_generation, None);
        assert_eq!(upgraded_token.installation_predecessor_enrollment_id, None);
        assert_eq!(upgraded_token.last_refreshed_at_ms, None);
        assert_eq!(upgraded_token.issued_at_ms, now_ms);
        assert_eq!(upgraded_token.expires_at_ms, now_ms + 600_000);

        let upgraded_consumption: StoredLegacyHumanConsumption = sqlx::query_as(
            r"
            SELECT consumed_at_ms,consumed_runner_id,redeem_operation_id,
                   redeem_request_sha256,redeem_response,
                   redeem_certificate_leaf_sha256,
                   redeem_predecessor_certificate_leaf_sha256,
                   redeem_predecessor_certificate_expires_at_seconds,
                   redeem_certificate_expires_at_seconds
            FROM runner_enrollment_tokens WHERE id=$1
            ",
        )
        .bind(enrollment_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(upgraded_consumption.consumed_at_ms, Some(now_ms));
        assert_eq!(
            upgraded_consumption.consumed_runner_id,
            Some(consumed_runner.as_uuid())
        );
        assert_eq!(
            upgraded_consumption.redeem_operation_id,
            Some(redeem_operation_id)
        );
        assert_eq!(
            upgraded_consumption.redeem_request_sha256.as_deref(),
            Some(redeem_request_sha256.as_slice())
        );
        assert_eq!(
            upgraded_consumption.redeem_response.as_deref(),
            Some(redeem_response.as_slice())
        );
        assert_eq!(upgraded_consumption.redeem_certificate_leaf_sha256, None);
        assert_eq!(
            upgraded_consumption.redeem_predecessor_certificate_leaf_sha256,
            None
        );
        assert_eq!(
            upgraded_consumption.redeem_predecessor_certificate_expires_at_seconds,
            None
        );
        assert_eq!(
            upgraded_consumption.redeem_certificate_expires_at_seconds,
            Some(certificate_expires_at_seconds)
        );

        let enrollment_repository =
            PostgresRunnerEnrollmentRepository::new(database.pool().clone());
        let replay = enrollment_repository
            .prepare_runner_enrollment(PrepareRunnerEnrollment {
                token_sha256,
                operation_id: redeem_operation_id,
                request_sha256: redeem_request_sha256,
            })
            .await
            .map_err(|error| {
                message_error(format!(
                    "upgraded consumed human token was rejected as corrupt: {error:?}"
                ))
            })?;
        assert!(matches!(
            replay,
            RunnerEnrollmentPrepareOutcome::Replayed(response)
                if response == redeem_response
        ));
        let consumed_retry = enrollment_repository
            .prepare_runner_enrollment(PrepareRunnerEnrollment {
                token_sha256,
                operation_id: Uuid::new_v4(),
                request_sha256: [0x6d; 32],
            })
            .await?;
        assert!(matches!(
            consumed_retry,
            RunnerEnrollmentPrepareOutcome::Rejected
        ));
        Ok(())
    })
    .await
}
