mod common;

use automata_ci_core::{
    AttemptId, JobId, OperationId, RunId, RunnerRequirements, Sha256Digest, UnixMillis, WorkflowId,
};
use automata_ci_store::{
    AdmissionObject, AdmissionRepository, AdmitWorkflowRun, AdmittedWorkflowJob, ObjectKey,
    RepositoryId, RoutingDocument, TenantScope, WorkflowAdmissionIdempotency,
    WorkflowAdmissionRepository as _, WorkflowSnapshotId,
};
use sqlx::migrate::Migrate as _;
use uuid::Uuid;

use common::{
    TestDatabase, TestResult, run_with_database, run_with_unmigrated_database, seed_control_plane,
};

const UI_PROJECTION_MIGRATION: &str =
    include_str!("../migrations/0011_workflow_run_ui_projection.sql");

#[derive(Debug, Eq, PartialEq, sqlx::FromRow)]
struct ProjectionRow {
    workflow_name: Option<String>,
    git_ref: Option<String>,
    actor: Option<String>,
    display_title: Option<String>,
    commit_subject: Option<String>,
    run_attempt: i32,
}

#[test]
fn projection_migration_is_legacy_nullable_and_keyset_indexed() {
    for column in [
        "workflow_name TEXT",
        "git_ref TEXT",
        "actor TEXT",
        "display_title TEXT",
        "commit_subject TEXT",
    ] {
        assert!(
            UI_PROJECTION_MIGRATION.contains(column),
            "missing projection column {column}"
        );
        assert!(
            !UI_PROJECTION_MIGRATION.contains(&format!("{column} NOT NULL")),
            "legacy projection column must remain nullable: {column}"
        );
    }
    for index in [
        "workflow_runs_repository_created",
        "workflow_runs_repository_workflow_created",
        "workflow_runs_repository_status_created",
        "workflow_runs_repository_ref_created",
    ] {
        assert!(
            UI_PROJECTION_MIGRATION.contains(index),
            "missing dashboard index {index}"
        );
    }
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn projection_upgrade_preserves_legacy_nulls_and_enforces_shapes() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_before_projection_migration(&database).await?;
        let seed = seed_control_plane(database.pool(), 0).await?;

        apply_projection_migration(&database).await?;

        let legacy: ProjectionRow = sqlx::query_as(
            r"
            SELECT workflow_name, git_ref, actor, display_title, commit_subject,
                   run_attempt
            FROM workflow_runs
            WHERE id = $1
            ",
        )
        .bind(seed.run_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            legacy,
            ProjectionRow {
                workflow_name: None,
                git_ref: None,
                actor: None,
                display_title: None,
                commit_subject: None,
                run_attempt: 1,
            }
        );

        let invalid_ref = sqlx::query("UPDATE workflow_runs SET git_ref = 'main' WHERE id = $1")
            .bind(seed.run_id.as_uuid())
            .execute(database.pool())
            .await
            .expect_err("short refs must be rejected");
        assert_constraint(&invalid_ref, "workflow_runs_git_ref_shape");

        let indexes: Vec<String> = sqlx::query_scalar(
            r"
            SELECT indexname
            FROM pg_indexes
            WHERE schemaname = current_schema() AND tablename = 'workflow_runs'
            ",
        )
        .fetch_all(database.pool())
        .await?;
        for expected in [
            "workflow_runs_repository_created",
            "workflow_runs_repository_workflow_created",
            "workflow_runs_repository_status_created",
            "workflow_runs_repository_ref_created",
        ] {
            assert!(indexes.iter().any(|index| index == expected));
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn admission_persists_human_projection_and_requested_run_attempt() -> TestResult {
    run_with_database(|database| async move {
        let tenant_id = format!("ui-projection-{}", Uuid::new_v4().simple());
        sqlx::query(
            r"
            INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
            VALUES ($1, 'UI projection test', 1, 1)
            ",
        )
        .bind(&tenant_id)
        .execute(database.pool())
        .await?;

        let repository_id = RepositoryId::from_uuid(Uuid::new_v4());
        let workflow_id = WorkflowId::new();
        let snapshot_id = WorkflowSnapshotId::from_uuid(Uuid::new_v4());
        let run_id = RunId::new();
        let job_id = JobId::new();
        let job = AdmittedWorkflowJob::new(
            job_id,
            AttemptId::new(),
            "verify",
            "Verify",
            object(4, "ui-projection/job-ir", "application/octet-stream")?,
            RoutingDocument::new(serde_json::to_string(&RunnerRequirements::default())?)?,
            Vec::new(),
        )?;
        let command = AdmitWorkflowRun::builder(
            TenantScope::from_authenticated_tenant_id(&tenant_id)?,
            WorkflowAdmissionIdempotency::operation(OperationId::new()),
            Sha256Digest::from_bytes([9; 32]),
            AdmissionRepository::new(
                repository_id,
                "github",
                Uuid::new_v4().to_string(),
                "automata-ci",
                "automata",
            )?,
            workflow_id,
            ".ci/workflows/ci.yml",
            "CI",
            "refs/heads/main",
            snapshot_id,
            object(1, "ui-projection/source", "application/yaml")?,
            object(2, "ui-projection/plan", "application/json")?,
            run_id,
            7,
            "push",
            object(3, "ui-projection/event", "application/json")?,
            vec![5; 20],
            vec![job],
            UnixMillis::new(10),
        )
        .actor("octocat")
        .display_title("Keep admission metadata durable")
        .commit_subject("Store the requested attempt")
        .build()?;

        let receipt = database.store().admit_workflow(command).await?;
        assert_eq!(receipt.run_id(), run_id);
        let persisted: ProjectionRow = sqlx::query_as(
            r"
                SELECT workflow_name, git_ref, actor, display_title, commit_subject,
                       run_attempt
                FROM workflow_runs
                WHERE id = $1
                ",
        )
        .bind(run_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            persisted,
            ProjectionRow {
                workflow_name: Some("CI".into()),
                git_ref: Some("refs/heads/main".into()),
                actor: Some("octocat".into()),
                display_title: Some("Keep admission metadata durable".into()),
                commit_subject: Some("Store the requested attempt".into()),
                run_attempt: 7,
            }
        );
        Ok(())
    })
    .await
}

fn object(digest_tag: u8, key: impl Into<String>, media_type: &str) -> TestResult<AdmissionObject> {
    Ok(AdmissionObject::new(
        Sha256Digest::from_bytes([digest_tag; 32]),
        ObjectKey::new(key)?,
        8,
        media_type,
    )?)
}

async fn apply_before_projection_migration(database: &TestDatabase) -> TestResult {
    static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
    let mut connection = database.pool().acquire().await?;
    let table_name = MIGRATOR.table_name.as_ref();
    connection.ensure_migrations_table(table_name).await?;
    for migration in MIGRATOR.iter().take(10) {
        connection.apply(table_name, migration).await?;
    }
    Ok(())
}

async fn apply_projection_migration(database: &TestDatabase) -> TestResult {
    static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
    let mut connection = database.pool().acquire().await?;
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 11)
        .expect("migration 0011");
    connection
        .apply(MIGRATOR.table_name.as_ref(), migration)
        .await?;
    Ok(())
}

fn assert_constraint(error: &sqlx::Error, expected: &str) {
    let actual = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint);
    assert_eq!(actual, Some(expected), "unexpected database error: {error}");
}
