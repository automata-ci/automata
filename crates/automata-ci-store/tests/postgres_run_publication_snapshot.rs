mod common;

use automata_ci_core::{
    AttemptId, JobId, RunId, RunnerRequirements, Sha256Digest, UnixMillis, WorkflowId,
    WorkflowJobKey,
};
use automata_ci_store::{
    AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun, AdmitWorkflowRun,
    AdmittedLogicalWorkflowJob, AdmittedWorkflowJob, LogicalWorkflowAdmissionRepository as _,
    LogicalWorkflowAdmissionStoreError, LogicalWorkflowInvocationId, LogicalWorkflowJobId,
    LogicalWorkflowJobKind, ObjectKey, RepositoryId, RoutingDocument, StoreError, TenantScope,
    WorkflowAdmissionIdempotency, WorkflowAdmissionRepository as _, WorkflowAdmissionStoreError,
    WorkflowSnapshotId,
};
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_database};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Policy<'a> {
    revision: i64,
    dashboard: &'a str,
    logs: &'a str,
    artifacts: &'a str,
}

#[derive(Debug, Eq, PartialEq)]
struct DurableSnapshot {
    revision: i64,
    requested_dashboard: String,
    effective_dashboard: String,
    requested_logs: String,
    requested_artifacts: String,
    reason: String,
    schema: i32,
}

#[derive(Debug, Eq, PartialEq)]
struct DurableAttemptSafety {
    secret_exposure: String,
    raw_log_disposition: String,
    requested_visibility: String,
    effective_visibility: String,
    reason: String,
    schema: i32,
    classified_at: i64,
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates an isolated PostgreSQL schema"]
async fn both_admission_paths_snapshot_the_closed_publication_matrix() -> TestResult {
    run_with_database(|database| async move {
        let tenant = format!("run-publication-{}", Uuid::new_v4().simple());
        seed_tenant(&database, &tenant).await?;

        for (index, audience) in ["private", "authenticated", "public"]
            .into_iter()
            .enumerate()
        {
            let repository_id = RepositoryId::from_uuid(Uuid::new_v4());
            let provider_repository_id = format!("publication-matrix-{index}");
            let policy = Policy {
                revision: i64::try_from(index)? + 3,
                dashboard: audience,
                logs: audience,
                artifacts: audience,
            };
            seed_repository(
                &database,
                &tenant,
                repository_id,
                &provider_repository_id,
                policy,
            )
            .await?;

            let legacy = legacy_command(
                &tenant,
                repository_id,
                &provider_repository_id,
                &format!("matrix-{index}-legacy"),
            )?;
            let logical = logical_command(
                &tenant,
                repository_id,
                &provider_repository_id,
                &format!("matrix-{index}-logical"),
            )?;
            database.store().admit_workflow(legacy.clone()).await?;
            database
                .store()
                .admit_logical_workflow(logical.clone())
                .await?;

            let expected = snapshot(policy);
            assert_eq!(load_snapshot(&database, legacy.run_id()).await?, expected);
            assert_eq!(load_snapshot(&database, logical.run_id()).await?, expected);
            assert_eq!(
                load_attempt_safety(&database, legacy.run_id()).await?,
                readable_attempt_safety(audience, 1_000)
            );
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates an isolated PostgreSQL schema"]
async fn later_policy_changes_preserve_and_replay_the_original_snapshot() -> TestResult {
    run_with_database(|database| async move {
        let tenant = format!("run-publication-change-{}", Uuid::new_v4().simple());
        let repository_id = RepositoryId::from_uuid(Uuid::new_v4());
        let provider_repository_id = "publication-change";
        let admitted_policy = Policy {
            revision: 7,
            dashboard: "public",
            logs: "authenticated",
            artifacts: "private",
        };
        seed_tenant(&database, &tenant).await?;
        seed_repository(
            &database,
            &tenant,
            repository_id,
            provider_repository_id,
            admitted_policy,
        )
        .await?;
        let legacy = legacy_command(
            &tenant,
            repository_id,
            provider_repository_id,
            "change-legacy",
        )?;
        let logical = logical_command(
            &tenant,
            repository_id,
            provider_repository_id,
            "change-logical",
        )?;
        database.store().admit_workflow(legacy.clone()).await?;
        database
            .store()
            .admit_logical_workflow(logical.clone())
            .await?;

        set_policy(
            &database,
            &tenant,
            repository_id,
            Policy {
                revision: 8,
                dashboard: "private",
                logs: "public",
                artifacts: "authenticated",
            },
        )
        .await?;

        assert!(
            database
                .store()
                .admit_workflow(legacy.clone())
                .await?
                .is_replay()
        );
        assert!(
            database
                .store()
                .admit_logical_workflow(logical.clone())
                .await?
                .is_replay()
        );
        let expected = snapshot(admitted_policy);
        assert_eq!(load_snapshot(&database, legacy.run_id()).await?, expected);
        assert_eq!(load_snapshot(&database, logical.run_id()).await?, expected);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates an isolated PostgreSQL schema"]
#[allow(clippy::too_many_lines)] // One isolated schema exercises both corrupt policy shapes.
async fn missing_and_malformed_repository_policies_fail_both_paths_atomically() -> TestResult {
    run_with_database(|database| async move {
        let tenant = format!("run-publication-invalid-{}", Uuid::new_v4().simple());
        seed_tenant(&database, &tenant).await?;

        let missing_repository = RepositoryId::from_uuid(Uuid::new_v4());
        seed_repository(
            &database,
            &tenant,
            missing_repository,
            "publication-missing",
            Policy {
                revision: 1,
                dashboard: "private",
                logs: "private",
                artifacts: "private",
            },
        )
        .await?;
        sqlx::query(
            "DELETE FROM repository_publication_policies WHERE tenant_id = $1 AND repository_id = $2",
        )
        .bind(&tenant)
        .bind(missing_repository.as_uuid())
        .execute(database.pool())
        .await?;
        let missing_legacy = legacy_command(
            &tenant,
            missing_repository,
            "publication-missing",
            "missing-legacy",
        )?;
        let missing_logical = logical_command(
            &tenant,
            missing_repository,
            "publication-missing",
            "missing-logical",
        )?;
        assert_legacy_corruption(&database.store().admit_workflow(missing_legacy.clone()).await);
        assert_logical_corruption(
            &database
                .store()
                .admit_logical_workflow(missing_logical.clone())
                .await,
        );
        assert_no_admission(&database, missing_legacy.run_id()).await?;
        assert_no_admission(&database, missing_logical.run_id()).await?;
        assert_eq!(admission_receipt_count(&database).await?, 0);

        let malformed_repository = RepositoryId::from_uuid(Uuid::new_v4());
        seed_repository(
            &database,
            &tenant,
            malformed_repository,
            "publication-malformed",
            Policy {
                revision: 2,
                dashboard: "authenticated",
                logs: "private",
                artifacts: "public",
            },
        )
        .await?;
        sqlx::query(
            r"
            ALTER TABLE repository_publication_policies
            DROP CONSTRAINT repository_publication_policies_dashboard_audience
            ",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            UPDATE repository_publication_policies
            SET dashboard_audience = 'unsupported'
            WHERE tenant_id = $1 AND repository_id = $2
            ",
        )
        .bind(&tenant)
        .bind(malformed_repository.as_uuid())
        .execute(database.pool())
        .await?;
        let malformed_legacy = legacy_command(
            &tenant,
            malformed_repository,
            "publication-malformed",
            "malformed-legacy",
        )?;
        let malformed_logical = logical_command(
            &tenant,
            malformed_repository,
            "publication-malformed",
            "malformed-logical",
        )?;
        assert_legacy_corruption(
            &database
                .store()
                .admit_workflow(malformed_legacy.clone())
                .await,
        );
        assert_logical_corruption(
            &database
                .store()
                .admit_logical_workflow(malformed_logical.clone())
                .await,
        );
        assert_no_admission(&database, malformed_legacy.run_id()).await?;
        assert_no_admission(&database, malformed_logical.run_id()).await?;
        assert_eq!(admission_receipt_count(&database).await?, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates an isolated PostgreSQL schema"]
async fn exact_replay_rejects_tampered_publication_snapshot_evidence() -> TestResult {
    run_with_database(|database| async move {
        let tenant = format!("run-publication-tamper-{}", Uuid::new_v4().simple());
        let repository_id = RepositoryId::from_uuid(Uuid::new_v4());
        let provider_repository_id = "publication-tamper";
        seed_tenant(&database, &tenant).await?;
        seed_repository(
            &database,
            &tenant,
            repository_id,
            provider_repository_id,
            Policy {
                revision: 11,
                dashboard: "public",
                logs: "authenticated",
                artifacts: "public",
            },
        )
        .await?;
        let legacy = legacy_command(
            &tenant,
            repository_id,
            provider_repository_id,
            "tamper-legacy",
        )?;
        let logical = logical_command(
            &tenant,
            repository_id,
            provider_repository_id,
            "tamper-logical",
        )?;
        database.store().admit_workflow(legacy.clone()).await?;
        database
            .store()
            .admit_logical_workflow(logical.clone())
            .await?;

        sqlx::query(
            "ALTER TABLE workflow_runs DISABLE TRIGGER workflow_runs_publication_snapshot_immutable",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            "UPDATE workflow_runs SET effective_dashboard_visibility = 'private' WHERE id = $1",
        )
        .bind(legacy.run_id().as_uuid())
        .execute(database.pool())
        .await?;
        sqlx::query(
            "UPDATE workflow_runs SET requested_log_visibility = 'private' WHERE id = $1",
        )
        .bind(logical.run_id().as_uuid())
        .execute(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE workflow_runs ENABLE TRIGGER workflow_runs_publication_snapshot_immutable",
        )
        .execute(database.pool())
        .await?;

        assert_legacy_corruption(&database.store().admit_workflow(legacy).await);
        assert_logical_corruption(&database.store().admit_logical_workflow(logical).await);
        Ok(())
    })
    .await
}

async fn seed_tenant(database: &TestDatabase, tenant: &str) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        VALUES ($1, 'Run publication snapshot test', 1, 1)
        ",
    )
    .bind(tenant)
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn seed_repository(
    database: &TestDatabase,
    tenant: &str,
    repository_id: RepositoryId,
    provider_repository_id: &str,
    policy: Policy<'_>,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id, owner, name,
            created_at_ms, updated_at_ms
        ) VALUES ($1,$2,'forge',$3,'sample-owner',$3,1,1)
        ",
    )
    .bind(repository_id.as_uuid())
    .bind(tenant)
    .bind(provider_repository_id)
    .execute(database.pool())
    .await?;
    set_policy(database, tenant, repository_id, policy).await
}

async fn set_policy(
    database: &TestDatabase,
    tenant: &str,
    repository_id: RepositoryId,
    policy: Policy<'_>,
) -> TestResult {
    let updated = sqlx::query(
        r"
        UPDATE repository_publication_policies
        SET revision = $3, dashboard_audience = $4, log_audience = $5,
            artifact_audience = $6, updated_at_ms = 2
        WHERE tenant_id = $1 AND repository_id = $2
        ",
    )
    .bind(tenant)
    .bind(repository_id.as_uuid())
    .bind(policy.revision)
    .bind(policy.dashboard)
    .bind(policy.logs)
    .bind(policy.artifacts)
    .execute(database.pool())
    .await?;
    assert_eq!(updated.rows_affected(), 1);
    Ok(())
}

fn legacy_command(
    tenant: &str,
    repository_id: RepositoryId,
    provider_repository_id: &str,
    tag: &str,
) -> TestResult<AdmitWorkflowRun> {
    let job_id = JobId::new();
    let job = AdmittedWorkflowJob::new(
        job_id,
        AttemptId::new(),
        "build",
        "Build",
        object(tag, "job", 4)?,
        RoutingDocument::new(serde_json::to_string(&RunnerRequirements::default())?)?,
        Vec::new(),
    )?;
    Ok(AdmitWorkflowRun::builder(
        TenantScope::from_authenticated_tenant_id(tenant)?,
        WorkflowAdmissionIdempotency::provider_delivery(format!("{tag}-delivery"))?,
        digest(tag, 9),
        repository(repository_id, provider_repository_id)?,
        WorkflowId::new(),
        format!(".ci/workflows/{tag}.yml"),
        "Build",
        "refs/heads/main",
        WorkflowSnapshotId::from_uuid(Uuid::new_v4()),
        object(tag, "source", 1)?,
        object(tag, "plan", 2)?,
        RunId::new(),
        1,
        "push",
        object(tag, "event", 3)?,
        vec![7; 20],
        vec![job],
        UnixMillis::new(1_000),
    )
    .build()?)
}

fn logical_command(
    tenant: &str,
    repository_id: RepositoryId,
    provider_repository_id: &str,
    tag: &str,
) -> TestResult<AdmitLogicalWorkflowRun> {
    let logical_job_id = LogicalWorkflowJobId::from_uuid(Uuid::new_v4())?;
    let job = AdmittedLogicalWorkflowJob::new(
        logical_job_id,
        WorkflowJobKey::new("build")?,
        0,
        LogicalWorkflowJobKind::Steps,
        Vec::new(),
    )?;
    Ok(AdmitLogicalWorkflowRun::builder(
        TenantScope::from_authenticated_tenant_id(tenant)?,
        WorkflowAdmissionIdempotency::provider_delivery(format!("{tag}-delivery"))?,
        digest(tag, 10),
        repository(repository_id, provider_repository_id)?,
        WorkflowId::new(),
        format!(".ci/workflows/{tag}.yml"),
        "Build",
        "refs/heads/main",
        WorkflowSnapshotId::from_uuid(Uuid::new_v4()),
        object(tag, "source", 5)?,
        object(tag, "plan", 6)?,
        RunId::new(),
        1,
        LogicalWorkflowInvocationId::from_uuid(Uuid::new_v4())?,
        "push",
        object(tag, "event", 7)?,
        vec![8; 20],
        vec![job],
        UnixMillis::new(1_001),
    )
    .build()?)
}

fn repository(
    repository_id: RepositoryId,
    provider_repository_id: &str,
) -> TestResult<AdmissionRepository> {
    Ok(AdmissionRepository::new(
        repository_id,
        "forge",
        provider_repository_id,
        "sample-owner",
        provider_repository_id,
    )?)
}

fn object(tag: &str, kind: &str, digest_tag: u8) -> TestResult<AdmissionObject> {
    Ok(AdmissionObject::new(
        digest(tag, digest_tag),
        ObjectKey::new(format!("publication/{tag}/{kind}"))?,
        512,
        "application/json",
    )?)
}

fn digest(tag: &str, salt: u8) -> Sha256Digest {
    let mut bytes = [salt; 32];
    for (target, source) in bytes.iter_mut().zip(tag.as_bytes()) {
        *target ^= *source;
    }
    Sha256Digest::from_bytes(bytes)
}

fn snapshot(policy: Policy<'_>) -> DurableSnapshot {
    DurableSnapshot {
        revision: policy.revision,
        requested_dashboard: policy.dashboard.to_owned(),
        effective_dashboard: policy.dashboard.to_owned(),
        requested_logs: policy.logs.to_owned(),
        requested_artifacts: policy.artifacts.to_owned(),
        reason: "repository_policy".to_owned(),
        schema: 1,
    }
}

async fn load_snapshot(database: &TestDatabase, run_id: RunId) -> TestResult<DurableSnapshot> {
    let row: (i64, String, String, String, String, String, i32) = sqlx::query_as(
        r"
        SELECT publication_policy_revision, requested_dashboard_visibility,
               effective_dashboard_visibility, requested_log_visibility,
               requested_artifact_visibility, publication_safety_reason,
               publication_safety_schema
        FROM workflow_runs WHERE id = $1
        ",
    )
    .bind(run_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    Ok(DurableSnapshot {
        revision: row.0,
        requested_dashboard: row.1,
        effective_dashboard: row.2,
        requested_logs: row.3,
        requested_artifacts: row.4,
        reason: row.5,
        schema: row.6,
    })
}

async fn load_attempt_safety(
    database: &TestDatabase,
    run_id: RunId,
) -> TestResult<DurableAttemptSafety> {
    let row: (String, String, String, String, String, i32, i64) = sqlx::query_as(
        r"
        SELECT attempt.secret_exposure_class, attempt.raw_log_disposition,
               attempt.requested_log_visibility,
               attempt.effective_log_visibility,
               attempt.output_safety_reason, attempt.output_safety_schema,
               attempt.classified_at_ms
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        WHERE job.run_id = $1
        ",
    )
    .bind(run_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    Ok(DurableAttemptSafety {
        secret_exposure: row.0,
        raw_log_disposition: row.1,
        requested_visibility: row.2,
        effective_visibility: row.3,
        reason: row.4,
        schema: row.5,
        classified_at: row.6,
    })
}

fn readable_attempt_safety(requested: &str, classified_at: i64) -> DurableAttemptSafety {
    DurableAttemptSafety {
        secret_exposure: "readable_secret".to_owned(),
        raw_log_disposition: "suppress_user_output".to_owned(),
        requested_visibility: requested.to_owned(),
        effective_visibility: "private".to_owned(),
        reason: if requested == "private" {
            "repository_policy"
        } else {
            "secret_exposure"
        }
        .to_owned(),
        schema: 1,
        classified_at,
    }
}

async fn assert_no_admission(database: &TestDatabase, run_id: RunId) -> TestResult {
    let run_count: i64 = sqlx::query_scalar("SELECT count(*) FROM workflow_runs WHERE id = $1")
        .bind(run_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
    let receipt_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM workflow_admission_receipts WHERE run_id = $1")
            .bind(run_id.as_uuid())
            .fetch_one(database.pool())
            .await?;
    assert_eq!((run_count, receipt_count), (0, 0));
    Ok(())
}

async fn admission_receipt_count(database: &TestDatabase) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM workflow_admission_receipts")
            .fetch_one(database.pool())
            .await?,
    )
}

fn assert_legacy_corruption(
    result: &Result<automata_ci_store::WorkflowAdmissionReceipt, WorkflowAdmissionStoreError>,
) {
    assert!(matches!(
        result,
        Err(WorkflowAdmissionStoreError::Store(StoreError::CorruptData(
            _
        )))
    ));
}

fn assert_logical_corruption(
    result: &Result<
        automata_ci_store::LogicalWorkflowAdmissionReceipt,
        LogicalWorkflowAdmissionStoreError,
    >,
) {
    assert!(matches!(
        result,
        Err(LogicalWorkflowAdmissionStoreError::Store(
            StoreError::CorruptData(_)
        ))
    ));
}
