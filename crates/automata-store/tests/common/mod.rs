use std::{error::Error, future::Future, str::FromStr as _, sync::Arc};

use automata_core::{JobId, RunnerId};
use automata_store::PostgresStore;
use sqlx::{
    AssertSqlSafe, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use uuid::Uuid;

pub const DATABASE_URL_ENVIRONMENT: &str = "AUTOMATA_TEST_DATABASE_URL";
pub type TestError = Box<dyn Error + Send + Sync>;
pub type TestResult<T = ()> = Result<T, TestError>;

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

#[derive(Debug)]
pub struct TestDatabase {
    schema: String,
    admin: PgPool,
    store: PostgresStore,
}

impl TestDatabase {
    pub async fn create() -> TestResult<Self> {
        let database_url = std::env::var(DATABASE_URL_ENVIRONMENT).map_err(|_| {
            format!("set {DATABASE_URL_ENVIRONMENT} to an isolated PostgreSQL test server URL")
        })?;
        let admin = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await?;
        let schema = format!("automata_test_{}", Uuid::new_v4().simple());
        let quoted_schema = quote_identifier(&admin, &schema).await?;
        sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA {quoted_schema}")))
            .execute(&admin)
            .await?;

        let connection_schema = schema.clone();
        let options = PgConnectOptions::from_str(&database_url)?;
        let pool = match PgPoolOptions::new()
            .max_connections(16)
            .after_connect(move |connection, _metadata| {
                let schema = connection_schema.clone();
                Box::pin(async move {
                    sqlx::query("SELECT pg_catalog.set_config('search_path', $1, false)")
                        .bind(schema)
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await
        {
            Ok(pool) => pool,
            Err(error) => {
                let cleanup = drop_schema(&admin, &schema).await;
                admin.close().await;
                cleanup?;
                return Err(error.into());
            }
        };
        let store = PostgresStore::from_postgres_pool(pool);
        if let Err(error) = store.migrate().await {
            store.postgres_pool().close().await;
            let cleanup = drop_schema(&admin, &schema).await;
            admin.close().await;
            cleanup?;
            return Err(error.into());
        }
        Ok(Self {
            schema,
            admin,
            store,
        })
    }

    pub const fn store(&self) -> &PostgresStore {
        &self.store
    }

    pub const fn pool(&self) -> &PgPool {
        self.store.postgres_pool()
    }

    pub async fn cleanup(&self) -> TestResult {
        self.store.postgres_pool().close().await;
        drop_schema(&self.admin, &self.schema).await?;
        self.admin.close().await;
        Ok(())
    }
}

#[derive(Debug)]
#[allow(dead_code)] // Each integration-test crate consumes a different fixture subset.
pub struct SeedData {
    pub tenant_id: String,
    pub repository_id: Uuid,
    pub workflow_id: Uuid,
    pub job_id: JobId,
    pub runner_ids: Vec<RunnerId>,
}

pub async fn seed_control_plane(pool: &PgPool, runner_count: usize) -> TestResult<SeedData> {
    let repository_id = Uuid::new_v4();
    let workflow_id = Uuid::new_v4();
    let snapshot_id = Uuid::new_v4();
    let run_id = Uuid::new_v4();
    let job_id = JobId::new();
    let tenant_id = format!("tenant-{}", Uuid::new_v4().simple());

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
    sqlx::query(
        r"
        INSERT INTO workflow_definitions (
            id, repository_id, path, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, '.github/workflows/test.yml', 1, 1)
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
            event_object_key, head_sha, status, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, $3, $4, 1, 'push', 'test/event', $5, 'queued', 1, 1)
        ",
    )
    .bind(run_id)
    .bind(repository_id)
    .bind(workflow_id)
    .bind(snapshot_id)
    .bind(vec![9_u8; 20])
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO jobs (
            id, run_id, job_key, display_name, job_ir_digest,
            job_ir_object_key, requirements, labels, created_at_ms
        )
        VALUES (
            $1, $2, 'test', 'Store test', $3,
            'test/job-ir', '{}'::jsonb, '{}', 1
        )
        ",
    )
    .bind(job_id.as_uuid())
    .bind(run_id)
    .bind(vec![11_u8; 32])
    .execute(pool)
    .await?;

    let runner_ids = seed_runners(pool, &tenant_id, runner_count).await?;

    Ok(SeedData {
        tenant_id,
        repository_id,
        workflow_id,
        job_id,
        runner_ids,
    })
}

async fn seed_runners(
    pool: &PgPool,
    tenant_id: &str,
    runner_count: usize,
) -> TestResult<Vec<RunnerId>> {
    let mut runner_ids = Vec::with_capacity(runner_count);
    for index in 0..runner_count {
        let runner_id = RunnerId::new();
        sqlx::query(
            r"
            INSERT INTO runners (
                id, tenant_id, name, normalized_name, capabilities, slots, status,
                created_at_ms, updated_at_ms
            )
            VALUES ($1, $2, $3, $3, '{}'::jsonb, 1, 'online', 1, 1)
            ",
        )
        .bind(runner_id.as_uuid())
        .bind(tenant_id)
        .bind(format!("test-runner-{index}"))
        .execute(pool)
        .await?;
        runner_ids.push(runner_id);
    }
    Ok(runner_ids)
}

async fn quote_identifier(pool: &PgPool, identifier: &str) -> TestResult<String> {
    // PostgreSQL performs the identifier escaping; no untrusted identifier is
    // ever concatenated directly into DDL.
    Ok(sqlx::query_scalar("SELECT pg_catalog.quote_ident($1)")
        .bind(identifier)
        .fetch_one(pool)
        .await?)
}

async fn drop_schema(pool: &PgPool, schema: &str) -> TestResult {
    let quoted_schema = quote_identifier(pool, schema).await?;
    sqlx::query(AssertSqlSafe(format!(
        "DROP SCHEMA {quoted_schema} CASCADE"
    )))
    .execute(pool)
    .await?;
    Ok(())
}
