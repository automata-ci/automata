mod support;

use std::{str::FromStr as _, sync::Arc, time::Duration};

use automata_blob::{BlobDescriptor, BlobKey, ImmutableBlobStore, MediaType};
use automata_blob_s3::{S3BlobStore, S3BlobStoreConfig, StaticS3Credentials};
use automata_core::{AttemptId, RunId, Sha256Digest, UnixMillis};
use automata_store::{
    BlockedAttemptRepository as _, BlockedConclusion, ConcludeBlockedAttempt, PostgresStore,
    RunReconciliationRepository as _, WorkflowAdmissionIdempotency, WorkflowAdmissionStoreError,
    WorkflowRunStatus,
};
use automata_workflow_service::{
    GithubWorkflowMaterializer, WorkflowAdmissionError, WorkflowAdmissionRequest,
    WorkflowAdmissionService, github_hosted_ubuntu_24_04_catalog,
};
use bytes::Bytes;
use sqlx::{
    AssertSqlSafe, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use url::Url;
use uuid::Uuid;

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult<T = ()> = Result<T, TestError>;

#[tokio::test]
async fn live_rustfs_postgres_admission_is_atomic_idempotent_tenant_scoped_and_exact() -> TestResult
{
    let Some(mut fixture) = LiveFixture::create().await? else {
        return Ok(());
    };
    let result = fixture.exercise().await;
    let cleanup = fixture.cleanup().await;
    result?;
    cleanup
}

struct LiveFixture {
    schema: String,
    admin: PgPool,
    store: Arc<PostgresStore>,
    blobs: Arc<S3BlobStore>,
    service: WorkflowAdmissionService,
}

impl LiveFixture {
    async fn create() -> TestResult<Option<Self>> {
        let Some(database_url) = std::env::var_os("AUTOMATA_TEST_DATABASE_URL") else {
            return Ok(None);
        };
        let Some(endpoint) = std::env::var_os("AUTOMATA_TEST_S3_ENDPOINT") else {
            return Ok(None);
        };
        let database_url = database_url.to_string_lossy().into_owned();
        let admin = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await?;
        let schema = format!("automata_admission_{}", Uuid::new_v4().simple());
        let quoted: String = sqlx::query_scalar("SELECT quote_ident($1)")
            .bind(&schema)
            .fetch_one(&admin)
            .await?;
        sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA {quoted}")))
            .execute(&admin)
            .await?;
        let connection_schema = schema.clone();
        let options = PgConnectOptions::from_str(&database_url)?;
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .after_connect(move |connection, _| {
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
            .await?;
        let store = Arc::new(PostgresStore::from_postgres_pool(pool));
        store.migrate().await?;

        let bucket = std::env::var("AUTOMATA_TEST_S3_BUCKET")?;
        let access_key = std::env::var("AUTOMATA_TEST_S3_ACCESS_KEY")?;
        let secret_key = std::env::var("AUTOMATA_TEST_S3_SECRET_KEY")?;
        let s3_config = S3BlobStoreConfig::loopback_development(
            Url::parse(&endpoint.to_string_lossy())?,
            "us-east-1",
            bucket,
            Some("workflow-admission-live-v1".to_owned()),
            Duration::from_secs(30),
        )?;
        let client = s3_config.client(StaticS3Credentials::new(access_key, secret_key, None)?);
        let blobs = Arc::new(S3BlobStore::new(client, &s3_config));
        let materializer = Arc::new(GithubWorkflowMaterializer::new(
            github_hosted_ubuntu_24_04_catalog()?,
        ));
        let service =
            WorkflowAdmissionService::with_system_ports(blobs.clone(), store.clone(), materializer);
        Ok(Some(Self {
            schema,
            admin,
            store,
            blobs,
            service,
        }))
    }

    async fn exercise(&mut self) -> TestResult {
        let tenant_a = format!("admission-a-{}", Uuid::new_v4().simple());
        let tenant_b = format!("admission-b-{}", Uuid::new_v4().simple());
        let tenant_rollback = format!("admission-rollback-{}", Uuid::new_v4().simple());
        for tenant in [&tenant_a, &tenant_b, &tenant_rollback] {
            self.insert_tenant(tenant).await?;
        }

        let delivery = WorkflowAdmissionIdempotency::provider_delivery(support::DELIVERY)?;
        let first_request = support::ci_request(&tenant_a, delivery.clone());
        let (left, right) = tokio::join!(
            self.service.admit(first_request.clone()),
            self.service.admit(first_request.clone())
        );
        let left = left?.receipt();
        let right = right?.receipt();
        assert_eq!(left.run_id(), right.run_id());
        assert_eq!(left.run_number(), 1);
        assert_eq!(right.run_number(), 1);
        assert_ne!(left.is_replay(), right.is_replay());
        self.assert_exact_ci_dag(left.run_id().as_uuid()).await?;
        self.assert_blob_evidence(left.run_id().as_uuid()).await?;
        self.assert_blocked_ci_dag_completes(left.run_id()).await?;

        let operation_one = support::operation_request(&tenant_a);
        let operation_two = support::operation_request(&tenant_a);
        let (one, two) = tokio::join!(
            self.service.admit(operation_one),
            self.service.admit(operation_two)
        );
        let mut run_numbers = [one?.receipt().run_number(), two?.receipt().run_number()];
        run_numbers.sort_unstable();
        assert_eq!(run_numbers, [2, 3]);

        let tenant_b_run = self
            .service
            .admit(support::ci_request(&tenant_b, delivery.clone()))
            .await?
            .receipt();
        assert_eq!(tenant_b_run.run_number(), 1);
        assert_ne!(tenant_b_run.run_id(), left.run_id());
        let receipt_tenants: i64 = sqlx::query_scalar(
            "SELECT count(DISTINCT tenant_id) FROM workflow_admission_receipts WHERE idempotency_kind = 'provider_delivery'",
        )
        .fetch_one(self.store.postgres_pool())
        .await?;
        assert_eq!(receipt_tenants, 2);

        let conflicting = changed_event_request(&first_request);
        let conflict = self
            .service
            .admit(conflicting)
            .await
            .expect_err("same delivery with different exact event must fail closed");
        assert!(matches!(
            conflict,
            WorkflowAdmissionError::Store(WorkflowAdmissionStoreError::IdempotencyConflict)
        ));

        self.insert_conflicting_repository(&tenant_rollback).await?;
        let rollback_error = self
            .service
            .admit(support::operation_request(&tenant_rollback))
            .await
            .expect_err("pre-existing non-server identity must reject admission");
        assert!(matches!(
            rollback_error,
            WorkflowAdmissionError::Store(WorkflowAdmissionStoreError::IdentityConflict(
                "repository"
            ))
        ));
        let rollback_receipts: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workflow_admission_receipts WHERE tenant_id = $1",
        )
        .bind(&tenant_rollback)
        .fetch_one(self.store.postgres_pool())
        .await?;
        let rollback_runs: i64 = sqlx::query_scalar(
            r"
            SELECT count(*) FROM workflow_runs AS run
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE repository.tenant_id = $1
            ",
        )
        .bind(&tenant_rollback)
        .fetch_one(self.store.postgres_pool())
        .await?;
        assert_eq!((rollback_receipts, rollback_runs), (0, 0));
        Ok(())
    }

    async fn insert_tenant(&self, tenant: &str) -> TestResult {
        sqlx::query(
            "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Admission test', 1, 1)",
        )
        .bind(tenant)
        .execute(self.store.postgres_pool())
        .await?;
        Ok(())
    }

    async fn assert_exact_ci_dag(&self, run_id: Uuid) -> TestResult {
        let jobs: Vec<(String, String, String)> = sqlx::query_as(
            r"
            SELECT job.job_key, attempt.lifecycle, run.status
            FROM jobs AS job
            JOIN job_attempts AS attempt ON attempt.job_id = job.id
            JOIN workflow_runs AS run ON run.id = job.run_id
            WHERE job.run_id = $1
            ORDER BY job.job_key
            ",
        )
        .bind(run_id)
        .fetch_all(self.store.postgres_pool())
        .await?;
        assert_eq!(jobs.len(), 3);
        assert!(
            jobs.iter()
                .all(|(_, lifecycle, status)| { lifecycle == "queued" && status == "queued" })
        );
        assert_eq!(
            jobs.iter()
                .map(|(key, _, _)| key.as_str())
                .collect::<Vec<_>>(),
            ["dist", "frontend", "verify"]
        );
        let roots: Vec<String> = sqlx::query_scalar(
            r"
            SELECT job.job_key FROM jobs AS job
            WHERE job.run_id = $1 AND NOT EXISTS (
                SELECT 1 FROM job_dependencies AS dependency
                WHERE dependency.run_id = job.run_id AND dependency.job_id = job.id
            ) ORDER BY job.job_key
            ",
        )
        .bind(run_id)
        .fetch_all(self.store.postgres_pool())
        .await?;
        assert_eq!(roots, ["frontend", "verify"]);
        let dependencies: Vec<String> = sqlx::query_scalar(
            r"
            SELECT prerequisite.job_key
            FROM job_dependencies AS dependency
            JOIN jobs AS job ON job.id = dependency.job_id
            JOIN jobs AS prerequisite ON prerequisite.id = dependency.prerequisite_job_id
            WHERE dependency.run_id = $1 AND job.job_key = 'dist'
            ORDER BY prerequisite.job_key
            ",
        )
        .bind(run_id)
        .fetch_all(self.store.postgres_pool())
        .await?;
        assert_eq!(dependencies, ["frontend", "verify"]);
        let concurrency: (String, bool) = sqlx::query_as(
            r"
            SELECT run.concurrency_group_key, concurrency.running_run_id = run.id
            FROM workflow_runs AS run
            JOIN concurrency_groups AS concurrency
              ON concurrency.repository_id = run.repository_id
             AND concurrency.normalized_key = run.concurrency_group_key
            WHERE run.id = $1
            ",
        )
        .bind(run_id)
        .fetch_one(self.store.postgres_pool())
        .await?;
        assert_eq!(concurrency, ("ci-ci-refs/heads/main".into(), true));
        Ok(())
    }

    async fn assert_blob_evidence(&self, run_id: Uuid) -> TestResult {
        let objects: Vec<(Vec<u8>, String, i64, String)> = sqlx::query_as(
            r"
            SELECT snapshot.source_digest, snapshot.source_object_key,
                   snapshot.source_size_bytes, snapshot.source_media_type
            FROM workflow_runs AS run
            JOIN workflow_snapshots AS snapshot ON snapshot.id = run.snapshot_id
            WHERE run.id = $1
            UNION ALL
            SELECT run.event_digest, run.event_object_key,
                   run.event_size_bytes, run.event_media_type
            FROM workflow_runs AS run WHERE run.id = $1
            UNION ALL
            SELECT run.plan_digest, run.plan_object_key,
                   run.plan_size_bytes, run.plan_media_type
            FROM workflow_runs AS run WHERE run.id = $1
            UNION ALL
            SELECT job.job_ir_digest, job.job_ir_object_key,
                   job.job_ir_size_bytes, 'application/vnd.automata.job-ir.protobuf'
            FROM jobs AS job WHERE job.run_id = $1
            ",
        )
        .bind(run_id)
        .fetch_all(self.store.postgres_pool())
        .await?;
        assert_eq!(objects.len(), 6);
        for (digest, key, size, media_type) in objects {
            let digest: [u8; 32] = digest.try_into().map_err(|_| "invalid digest length")?;
            let descriptor = BlobDescriptor::new(
                BlobKey::new(key)?,
                Sha256Digest::from_bytes(digest),
                u64::try_from(size)?,
                MediaType::new(media_type)?,
            );
            let verified = self
                .blobs
                .get_verified(&descriptor, descriptor.size())
                .await?;
            assert_eq!(verified.descriptor(), &descriptor);
        }
        Ok(())
    }

    async fn assert_blocked_ci_dag_completes(&self, run_id: RunId) -> TestResult {
        let baseline: i64 = sqlx::query_scalar(
            r"
            SELECT max(attempt.changed_at_ms)
            FROM job_attempts AS attempt
            JOIN jobs AS job ON job.id = attempt.job_id
            WHERE job.run_id = $1
            ",
        )
        .bind(run_id.as_uuid())
        .fetch_one(self.store.postgres_pool())
        .await?;
        let roots_at = baseline.checked_add(1).ok_or("test timestamp overflow")?;
        let updated = sqlx::query(
            r"
            UPDATE job_attempts AS attempt
            SET lifecycle = CASE job.job_key
                    WHEN 'verify' THEN 'failed'
                    WHEN 'frontend' THEN 'succeeded'
                    ELSE attempt.lifecycle
                END,
                changed_at_ms = $2
            FROM jobs AS job
            WHERE attempt.job_id = job.id AND job.run_id = $1
              AND job.job_key IN ('verify', 'frontend')
              AND attempt.lifecycle = 'queued'
            ",
        )
        .bind(run_id.as_uuid())
        .bind(roots_at)
        .execute(self.store.postgres_pool())
        .await?;
        assert_eq!(updated.rows_affected(), 2);

        let active = self
            .store
            .reconcile_run(run_id, UnixMillis::new(roots_at + 1))
            .await?;
        assert_eq!(active.status(), WorkflowRunStatus::InProgress);
        let dist_attempt: Uuid = sqlx::query_scalar(
            r"
            SELECT attempt.id
            FROM job_attempts AS attempt
            JOIN jobs AS job ON job.id = attempt.job_id
            WHERE job.run_id = $1 AND job.job_key = 'dist'
            ",
        )
        .bind(run_id.as_uuid())
        .fetch_one(self.store.postgres_pool())
        .await?;
        let conclusion = self
            .store
            .conclude_blocked(ConcludeBlockedAttempt::new(
                AttemptId::from_uuid(dist_attempt),
                UnixMillis::new(roots_at + 2),
            ))
            .await?;
        assert_eq!(conclusion, BlockedConclusion::Skipped);

        let durable: (String, Vec<String>, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
            r"
            SELECT run.status,
                   array_agg(attempt.lifecycle ORDER BY job.job_key),
                   concurrency.running_run_id,
                   concurrency.pending_run_id
            FROM workflow_runs AS run
            JOIN jobs AS job ON job.run_id = run.id
            JOIN job_attempts AS attempt ON attempt.job_id = job.id
            JOIN concurrency_groups AS concurrency
              ON concurrency.repository_id = run.repository_id
             AND concurrency.normalized_key = run.concurrency_group_key
            WHERE run.id = $1
            GROUP BY run.status, concurrency.running_run_id, concurrency.pending_run_id
            ",
        )
        .bind(run_id.as_uuid())
        .fetch_one(self.store.postgres_pool())
        .await?;
        assert_eq!(durable.0, "completed");
        assert_eq!(durable.1, ["skipped", "succeeded", "failed"]);
        assert_eq!((durable.2, durable.3), (None, None));
        Ok(())
    }

    async fn insert_conflicting_repository(&self, tenant: &str) -> TestResult {
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, scm_provider, provider_repository_id, owner, name,
                created_at_ms, updated_at_ms
            ) VALUES ($1,$2,'github','repository-automata','GoNeuralAI','automata',1,1)
            ",
        )
        .bind(Uuid::new_v4())
        .bind(tenant)
        .execute(self.store.postgres_pool())
        .await?;
        Ok(())
    }

    async fn cleanup(&mut self) -> TestResult {
        self.store.postgres_pool().close().await;
        let quoted: String = sqlx::query_scalar("SELECT quote_ident($1)")
            .bind(&self.schema)
            .fetch_one(&self.admin)
            .await?;
        sqlx::query(AssertSqlSafe(format!("DROP SCHEMA {quoted} CASCADE")))
            .execute(&self.admin)
            .await?;
        self.admin.close().await;
        Ok(())
    }
}

fn changed_event_request(original: &WorkflowAdmissionRequest) -> WorkflowAdmissionRequest {
    WorkflowAdmissionRequest::builder(
        original.tenant().clone(),
        original.repository().clone(),
        original.workflow_path(),
        original.source().clone(),
        Bytes::from_static(b"{\"changed\":true}"),
        original.plan().clone(),
        original.idempotency().clone(),
    )
    .commit_sha(original.commit_sha())
    .git_ref(original.git_ref())
    .workflow_name(original.workflow_name())
    .workspace(original.workspace())
    .actor(original.actor().expect("fixture actor"))
    .run_attempt(original.run_attempt().expect("fixture attempt"))
    .build()
    .expect("changed exact event remains structurally valid")
}
