use automata_ci_core::{
    AttemptId, JobId, OperationId, RunId, RunnerRequirements, Sha256Digest, UnixMillis, WorkflowId,
};
use automata_ci_store::{
    AdmissionObject, AdmissionRepository, AdmitWorkflowRun, AdmittedWorkflowJob, ObjectKey,
    RepositoryId, RoutingDocument, TenantScope, WorkflowAdmissionIdempotency,
    WorkflowAdmissionRepository as _, WorkflowSnapshotId,
};
use uuid::Uuid;

use crate::support::{TestResult, run_with_database};

#[derive(Debug, Eq, PartialEq, sqlx::FromRow)]
struct ProjectionRow {
    workflow_name: String,
    git_ref: Option<String>,
    actor: Option<String>,
    display_title: Option<String>,
    commit_subject: Option<String>,
    run_attempt: i32,
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
                workflow_name: "CI".into(),
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
