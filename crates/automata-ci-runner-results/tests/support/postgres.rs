use automata_ci_control::runner_control::repository::RunnerSessionRepository as _;
use automata_ci_core::{
    Architecture, JobId, JobIrVersion, OperatingSystem, RunId, RunnerCapabilities, RunnerId,
    RunnerPlatform, RunnerRequirements, RunnerSessionId, UnixMillis,
};
pub use automata_ci_postgres::test_support::{
    PostgresTestDatabase as TestDatabase, TestResult, run_with_database,
};
use automata_ci_store::{
    OpenRunnerSession, RoutingDocument, RunnerGeneration, RunnerProtocolVersion,
    RunnerSessionFence, WORKFLOW_ADMISSION_EPOCH,
};
use automata_ci_store_postgres::PostgresStore;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug)]
pub struct SeedData {
    pub run_id: RunId,
    pub job_id: JobId,
    pub session_fence: RunnerSessionFence,
    #[allow(dead_code)] // Used only by object-store integration targets.
    pub observed_at: UnixMillis,
}

#[allow(clippy::too_many_lines)]
pub async fn seed_control_plane(pool: &PgPool) -> TestResult<SeedData> {
    let tenant_id = format!("results-tenant-{}", Uuid::new_v4().simple());
    let repository_id = Uuid::new_v4();
    let workflow_id = Uuid::new_v4();
    let snapshot_id = Uuid::new_v4();
    let run_id = Uuid::new_v4();
    let job_id = JobId::new();
    let runner_id = RunnerId::new();

    sqlx::query(
        r"
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        VALUES ($1, 'Results test tenant', 1, 1)
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
        VALUES ($1, $2, 'test', $3, 'automata', 'results-test', 1, 1)
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
        VALUES ($1, $2, '.ci/workflows/results.yml', 1, 1)
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
        VALUES ($1, $2, $3, 'test/results-workflow', 1, 1)
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
            runner_requirements_schema, scheduling_priority
        )
        VALUES (
            $1, $2, $3, $4, 1, 'push', 'test/results-event',
            decode(repeat('21', 32), 'hex'), 1, 'application/json',
            decode(repeat('22', 32), 'hex'), 'test/results-plan', 1,
            'application/vnd.automata.workflow-plan.protobuf', 1, 'Results test',
            $5, 'queued', 1, 1, 1, 0
        )
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
            job_ir_object_key, requirements, admission_epoch,
            job_ir_schema, job_ir_size_bytes, created_at_ms
        )
        VALUES (
            $1, $2, 'results', 'Results test', $3,
            'test/results-job-ir', $4::jsonb, $5, $6, 128, 1
        )
        ",
    )
    .bind(job_id.as_uuid())
    .bind(run_id)
    .bind(vec![11_u8; 32])
    .bind(serde_json::to_value(RunnerRequirements::default())?)
    .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
    .bind(i32::from(JobIrVersion::current().get()))
    .execute(pool)
    .await?;

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
        VALUES ($1, $2, 'results-runner', 'results-runner', $3::jsonb, 1,
                'online', 'active', 1, 1)
        ",
    )
    .bind(runner_id.as_uuid())
    .bind(&tenant_id)
    .bind(serde_json::to_value(capabilities)?)
    .execute(pool)
    .await?;
    let capabilities: serde_json::Value =
        sqlx::query_scalar("SELECT capabilities FROM runners WHERE id = $1")
            .bind(runner_id.as_uuid())
            .fetch_one(pool)
            .await?;
    let routing = RoutingDocument::new(serde_json::to_string(&capabilities)?)?;
    let database_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(pool)
            .await?;
    let observed_at = UnixMillis::new(database_now);
    let session = PostgresStore::from_postgres_pool(pool.clone())
        .open_session(OpenRunnerSession::new(
            RunnerSessionId::new(),
            runner_id,
            RunnerGeneration::new(1)?,
            RunnerProtocolVersion::new(1)?,
            JobIrVersion::current(),
            routing,
            observed_at,
        ))
        .await?;

    Ok(SeedData {
        run_id: RunId::from_uuid(run_id),
        job_id,
        session_fence: session.fence(),
        observed_at,
    })
}
