use std::{error::Error, future::Future, sync::Arc};

use automata_ci_core::{
    Architecture, JobId, JobIrVersion, OperatingSystem, RunId, RunnerCapabilities, RunnerId,
    RunnerPlatform, RunnerRequirements, RunnerSessionId, UnixMillis,
};
use automata_ci_key_management::{
    KeyEncryptionProvider, KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes,
};
#[allow(unused_imports)] // Consolidated binaries consume different fixture subsets.
pub use automata_ci_postgres_test_support::{DATABASE_URL_ENVIRONMENT, TestClock};
use automata_ci_postgres_test_support::{
    PostgresTestHarness, PreparedTemplate, TestDatabase as IsolatedTestDatabase,
};
use automata_ci_store::{
    OpenRunnerSession, PostgresStore, RoutingDocument, RunnerGeneration, RunnerProtocolVersion,
    RunnerSessionFence, RunnerSessionRepository as _,
};
use sqlx::PgPool;
use tokio::sync::OnceCell;
use uuid::Uuid;

pub type TestError = Box<dyn Error + Send + Sync>;
pub type TestResult<T = ()> = Result<T, TestError>;

#[allow(dead_code)]
pub fn authenticated_github_event_object(
    event: &automata_ci_store::AdmissionObject,
) -> TestResult<automata_ci_store::AdmissionObject> {
    Ok(automata_ci_store::AdmissionObject::new_event(
        event.digest(),
        event.object_key().clone(),
        event.encoded_size(),
        "application/vnd.automata.github-authenticated-event+json",
    )?)
}

static PREPARED_TEMPLATE: OnceCell<PreparedTemplate> = OnceCell::const_new();

async fn prepared_template() -> TestResult<&'static PreparedTemplate> {
    PREPARED_TEMPLATE
        .get_or_try_init(|| async {
            PostgresTestHarness::from_environment()?
                .prepare_template(|pool| async move {
                    PostgresStore::from_postgres_pool(pool)
                        .with_runner_payload_encryption(test_runner_payload_key_provider())
                        .migrate()
                        .await?;
                    Ok(())
                })
                .await
        })
        .await
}

pub fn test_runner_payload_key_provider() -> Arc<dyn KeyEncryptionProvider> {
    let active = LocalKeyMaterial::new(
        KeyId::new("store-test-runner-payload-v1").expect("canonical test key ID"),
        SecretBytes::new(vec![0x6d; 32]).expect("exact test wrapping key length"),
    )
    .expect("valid test wrapping key");
    Arc::new(
        LocalAes256GcmKeyring::new(active, Vec::new(), Vec::<KeyId>::new())
            .expect("valid deterministic test keyring"),
    )
}

pub async fn run_with_database<Test, TestFuture>(test: Test) -> TestResult
where
    Test: FnOnce(Arc<TestDatabase>) -> TestFuture,
    TestFuture: Future<Output = TestResult> + Send + 'static,
{
    let database = Arc::new(TestDatabase::create().await?);
    let outcome = tokio::spawn(test(Arc::clone(&database))).await;
    let cleanup = database.cleanup().await;

    match outcome {
        Ok(result) => {
            result?;
            cleanup
        }
        Err(join_error) => {
            cleanup?;
            if join_error.is_panic() {
                std::panic::resume_unwind(join_error.into_panic());
            }
            Err(join_error.into())
        }
    }
}

#[allow(dead_code)] // Only integration tests that control migration application use this fixture.
pub async fn run_with_unmigrated_database<Test, TestFuture>(test: Test) -> TestResult
where
    Test: FnOnce(Arc<TestDatabase>) -> TestFuture,
    TestFuture: Future<Output = TestResult> + Send + 'static,
{
    let database = Arc::new(TestDatabase::create_unmigrated().await?);
    let outcome = tokio::spawn(test(Arc::clone(&database))).await;
    let cleanup = database.cleanup().await;

    match outcome {
        Ok(result) => {
            result?;
            cleanup
        }
        Err(join_error) => {
            cleanup?;
            if join_error.is_panic() {
                std::panic::resume_unwind(join_error.into_panic());
            }
            Err(join_error.into())
        }
    }
}

#[derive(Debug)]
pub struct TestDatabase {
    database: IsolatedTestDatabase,
    store: PostgresStore,
}

impl TestDatabase {
    pub async fn create() -> TestResult<Self> {
        Self::create_inner(true).await
    }

    #[allow(dead_code)] // Each integration-test crate compiles this shared module independently.
    pub async fn create_unmigrated() -> TestResult<Self> {
        Self::create_inner(false).await
    }

    async fn create_inner(run_migrations: bool) -> TestResult<Self> {
        let harness = PostgresTestHarness::from_environment()?;
        let database = if run_migrations {
            prepared_template().await?.create_database().await?
        } else {
            harness.create_empty_database().await?
        };
        let store = PostgresStore::from_postgres_pool(database.pool().clone())
            .with_runner_payload_encryption(test_runner_payload_key_provider());
        Ok(Self { database, store })
    }

    pub const fn store(&self) -> &PostgresStore {
        &self.store
    }

    pub const fn pool(&self) -> &PgPool {
        self.store().postgres_pool()
    }

    /// Creates another pool connected to this exact isolated database.
    #[allow(dead_code)] // Only connection-replacement tests consume this helper.
    pub async fn connect_pool(&self, max_connections: u32) -> TestResult<PgPool> {
        self.database.connect_pool(max_connections).await
    }

    pub async fn cleanup(&self) -> TestResult {
        self.store.postgres_pool().close().await;
        self.database.cleanup().await
    }
}

#[derive(Debug)]
#[allow(dead_code)] // Each integration-test crate consumes a different fixture subset.
pub struct SeedData {
    pub tenant_id: String,
    pub repository_id: Uuid,
    pub workflow_id: Uuid,
    pub run_id: RunId,
    pub job_id: JobId,
    pub runner_ids: Vec<RunnerId>,
    pub session_fences: Vec<RunnerSessionFence>,
}

#[allow(clippy::too_many_lines, dead_code)] // Shared fixture; integration targets consume subsets.
pub async fn seed_control_plane(pool: &PgPool, runner_count: usize) -> TestResult<SeedData> {
    seed_control_plane_with_optional_concurrency(pool, runner_count, None).await
}

#[allow(dead_code)] // Only concurrency-focused integration targets consume this fixture variant.
pub async fn seed_control_plane_with_concurrency(
    pool: &PgPool,
    runner_count: usize,
    group: &str,
    queue_policy: &str,
) -> TestResult<SeedData> {
    seed_control_plane_with_optional_concurrency(pool, runner_count, Some((group, queue_policy)))
        .await
}

#[allow(clippy::too_many_lines)] // Shared relational fixture with one optional concurrency pin.
async fn seed_control_plane_with_optional_concurrency(
    pool: &PgPool,
    runner_count: usize,
    concurrency: Option<(&str, &str)>,
) -> TestResult<SeedData> {
    let repository_id = Uuid::new_v4();
    let workflow_id = Uuid::new_v4();
    let snapshot_id = Uuid::new_v4();
    let run_id = Uuid::new_v4();
    let job_id = JobId::new();
    let tenant_id = format!("tenant-{}", Uuid::new_v4().simple());
    let (admission_epoch, job_ir_schema, runner_requirements_schema): (i32, i32, i32) =
        sqlx::query_as(
            r"
        SELECT minimum_admission_epoch, job_ir_schema, runner_requirements_schema
        FROM automata_cluster_compatibility
        WHERE singleton
        ",
        )
        .fetch_one(pool)
        .await?;
    let job_ir_version = JobIrVersion::new(u16::try_from(job_ir_schema)?)?;

    let requirements = serde_json::to_value(RunnerRequirements::default())?;

    sqlx::query(
        r"
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        VALUES ($1, 'Store test tenant', 1, 1)
        ",
    )
    .bind(&tenant_id)
    .execute(pool)
    .await?;

    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id, owner, name,
            created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, 'test', $3, 'automata', 'store-test', 1, 1)
        ",
    )
    .bind(repository_id)
    .bind(&tenant_id)
    .bind(repository_id.to_string())
    .execute(pool)
    .await?;
    if let Some((group, _)) = concurrency {
        sqlx::query(
            r"
            INSERT INTO concurrency_groups (
                repository_id, normalized_key, display_key, updated_at_ms
            ) VALUES ($1, $2, $2, 1)
            ",
        )
        .bind(repository_id)
        .bind(group)
        .execute(pool)
        .await?;
    }
    sqlx::query(
        r"
        INSERT INTO workflow_definitions (
            id, repository_id, path, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, '.ci/workflows/test.yml', 1, 1)
        ",
    )
    .bind(workflow_id)
    .bind(repository_id)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_snapshots (
            id, workflow_id, source_digest, source_object_key,
            frontend_schema, created_at_ms
        )
        VALUES ($1, $2, $3, 'test/workflow', 1, 1)
        ",
    )
    .bind(snapshot_id)
    .bind(workflow_id)
    .bind(vec![7_u8; 32])
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number, event_name,
            event_object_key, event_digest, event_size_bytes, event_media_type,
            plan_digest, plan_object_key, plan_size_bytes, plan_media_type,
            plan_schema, workflow_name, head_sha, status, created_at_ms, updated_at_ms,
            concurrency_group_key, concurrency_queue_policy,
            runner_requirements_schema
        ) VALUES (
            $1, $2, $3, $4, 1, 'push', 'test/event',
            decode(repeat('09', 32), 'hex'), 1, 'application/json',
            decode(repeat('0a', 32), 'hex'), 'test/plan', 1,
            'application/vnd.automata.workflow-plan.protobuf', 1, 'Store test',
            $5, 'queued', 1, 1, $6, $7, $8
        )
        ",
    )
    .bind(run_id)
    .bind(repository_id)
    .bind(workflow_id)
    .bind(snapshot_id)
    .bind(vec![9_u8; 20])
    .bind(concurrency.map(|(group, _)| group))
    .bind(concurrency.map(|(_, queue_policy)| queue_policy))
    .bind(i16::try_from(runner_requirements_schema)?)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO jobs (
            id, run_id, job_key, display_name, job_ir_digest,
            job_ir_object_key, requirements, admission_epoch,
            job_ir_schema, job_ir_size_bytes, created_at_ms
        )
        VALUES (
            $1, $2, 'test', 'Store test', $3,
            'test/job-ir', $4::jsonb, $5, $6, 128, 1
        )
        ",
    )
    .bind(job_id.as_uuid())
    .bind(run_id)
    .bind(vec![11_u8; 32])
    .bind(requirements)
    .bind(admission_epoch)
    .bind(job_ir_schema)
    .execute(pool)
    .await?;

    let runner_ids = seed_runners(pool, &tenant_id, runner_count).await?;
    let mut session_fences = Vec::with_capacity(runner_ids.len());
    let store = PostgresStore::from_postgres_pool(pool.clone())
        .with_runner_payload_encryption(test_runner_payload_key_provider());
    for runner_id in &runner_ids {
        let capabilities = runner_capability_document(pool, *runner_id).await?;
        let session = store
            .open_session(OpenRunnerSession::new(
                RunnerSessionId::new(),
                *runner_id,
                RunnerGeneration::new(1)?,
                RunnerProtocolVersion::new(1)?,
                job_ir_version,
                capabilities,
                UnixMillis::new(2),
            ))
            .await?;
        session_fences.push(session.fence());
    }

    Ok(SeedData {
        tenant_id,
        repository_id,
        workflow_id,
        run_id: RunId::from_uuid(run_id),
        job_id,
        runner_ids,
        session_fences,
    })
}

#[allow(dead_code)] // Shared fixture; integration targets consume subsets.
pub async fn runner_capability_document(
    pool: &PgPool,
    runner_id: RunnerId,
) -> TestResult<RoutingDocument> {
    let capabilities: serde_json::Value =
        sqlx::query_scalar("SELECT capabilities FROM runners WHERE id = $1")
            .bind(runner_id.as_uuid())
            .fetch_one(pool)
            .await?;
    Ok(RoutingDocument::new(serde_json::to_string(&capabilities)?)?)
}

#[allow(dead_code)] // Used transitively only by integration targets that seed control-plane state.
async fn seed_runners(
    pool: &PgPool,
    tenant_id: &str,
    runner_count: usize,
) -> TestResult<Vec<RunnerId>> {
    let mut runner_ids = Vec::with_capacity(runner_count);
    for index in 0..runner_count {
        let runner_id = RunnerId::new();
        let capabilities = RunnerCapabilities::new(
            runner_id,
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        );
        sqlx::query(
            r"
            INSERT INTO runners (
                id, tenant_id, name, normalized_name, capabilities, slots, status,
                desired_state, created_at_ms, updated_at_ms
            )
            VALUES ($1, $2, $3, $3, $4::jsonb, 65535, 'online', 'active', 1, 1)
            ",
        )
        .bind(runner_id.as_uuid())
        .bind(tenant_id)
        .bind(format!("test-runner-{index}"))
        .bind(serde_json::to_value(capabilities)?)
        .execute(pool)
        .await?;
        runner_ids.push(runner_id);
    }
    Ok(runner_ids)
}
