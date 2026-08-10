mod support;

use std::{str::FromStr as _, sync::Arc, time::Duration};

use automata_ci_blob::{BlobDescriptor, BlobKey, ImmutableBlobStore, MediaType};
use automata_ci_blob_s3::{S3BlobStore, S3BlobStoreConfig, StaticS3Credentials};
use automata_ci_core::Sha256Digest;
use automata_ci_store::{
    LogicalWorkflowAdmissionStoreError, PostgresStore, WorkflowAdmissionIdempotency,
};
use automata_ci_workflow_service::{
    GithubWorkflowPlanVerifier, WorkflowAdmissionError, WorkflowAdmissionService,
};
use sqlx::{
    AssertSqlSafe, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use url::Url;
use uuid::Uuid;

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult<T = ()> = Result<T, TestError>;

fn required_environment(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|error| panic!("{name} is required: {error}"))
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL and S3-compatible test services"]
async fn live_logical_admission_is_atomic_exact_and_blob_first() -> TestResult {
    let mut fixture = LiveFixture::create().await?;
    let result = Box::pin(fixture.exercise()).await;
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
    async fn create() -> TestResult<Self> {
        let database_url = required_environment("AUTOMATA_TEST_DATABASE_URL");
        let endpoint = required_environment("AUTOMATA_TEST_S3_ENDPOINT");
        let admin = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await?;
        let schema = format!("automata_logical_admission_{}", Uuid::new_v4().simple());
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

        let config = S3BlobStoreConfig::loopback_development(
            Url::parse(&endpoint)?,
            "us-east-1",
            required_environment("AUTOMATA_TEST_S3_BUCKET"),
            Some("workflow-logical-admission-live-v2".to_owned()),
            Duration::from_secs(30),
        )?;
        let client = config.client(StaticS3Credentials::new(
            required_environment("AUTOMATA_TEST_S3_ACCESS_KEY"),
            required_environment("AUTOMATA_TEST_S3_SECRET_KEY"),
            None,
        )?);
        let blobs = Arc::new(S3BlobStore::new(client, &config));
        let service = WorkflowAdmissionService::with_system_ports(
            blobs.clone(),
            store.clone(),
            Arc::new(GithubWorkflowPlanVerifier::new()),
        );
        Ok(Self {
            schema,
            admin,
            store,
            blobs,
            service,
        })
    }

    async fn exercise(&self) -> TestResult {
        let tenant = format!("logical-admission-{}", Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Logical admission test', 1, 1)",
        )
        .bind(&tenant)
        .execute(self.store.postgres_pool())
        .await?;
        let request = support::ci_request(
            &tenant,
            WorkflowAdmissionIdempotency::provider_delivery(support::DELIVERY)?,
        );
        let (left, right) = tokio::join!(
            self.service.admit(request.clone()),
            self.service.admit(request.clone())
        );
        let left = left?.receipt();
        let right = right?.receipt();
        assert_eq!(left.run_id(), right.run_id());
        assert_eq!(left.root_invocation_id(), right.root_invocation_id());
        assert_ne!(left.is_replay(), right.is_replay());

        let run_id = left.run_id().as_uuid();
        let current_shape: (i16, i16, i16) = sqlx::query_as(
            "SELECT run.admission_epoch, run.plan_schema, marker.orchestration_schema FROM workflow_runs AS run JOIN workflow_plan_v2_runs AS marker ON marker.run_id = run.id WHERE run.id = $1",
        )
        .bind(run_id)
        .fetch_one(self.store.postgres_pool())
        .await?;
        assert_eq!(current_shape, (4, 2, 1));
        let logical_counts: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM workflow_plan_v2_invocations WHERE run_id = $1), (SELECT count(*) FROM workflow_plan_v2_jobs WHERE run_id = $1), (SELECT count(*) FROM workflow_plan_v2_dependencies WHERE run_id = $1)",
        )
        .bind(run_id)
        .fetch_one(self.store.postgres_pool())
        .await?;
        assert_eq!(logical_counts, (1, 4, 3));
        let eager_counts: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM jobs WHERE run_id = $1), (SELECT count(*) FROM job_attempts AS attempt JOIN jobs AS job ON job.id = attempt.job_id WHERE job.run_id = $1), (SELECT count(*) FROM job_dependencies AS dependency JOIN jobs AS job ON job.id = dependency.job_id WHERE job.run_id = $1)",
        )
        .bind(run_id)
        .fetch_one(self.store.postgres_pool())
        .await?;
        assert_eq!(eager_counts, (0, 0, 0));
        self.assert_blob_evidence(run_id).await?;

        assert!(matches!(
            self.service
                .admit(support::changed_event_request(&request))
                .await
                .expect_err("changed evidence under one delivery must conflict"),
            WorkflowAdmissionError::Store(LogicalWorkflowAdmissionStoreError::IdempotencyConflict)
        ));
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
            ",
        )
        .bind(run_id)
        .fetch_all(self.store.postgres_pool())
        .await?;
        assert_eq!(objects.len(), 3);
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
