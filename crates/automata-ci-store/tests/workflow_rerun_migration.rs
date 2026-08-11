#[allow(dead_code)]
mod common;

use automata_ci_auth::{
    human::{PrincipalId, TenantId},
    management::{ManagementActor, ManagementRevision},
    session::SessionId,
    time::UnixTimestamp,
};
use automata_ci_core::{OperationId, RunId};
use automata_ci_store::{
    PostgresStore, RepositoryId, RerunWorkflow, WorkflowRerunRepository as _,
    WorkflowRerunSelection, WorkflowRerunStoreError,
};
use sqlx::PgPool;
use uuid::Uuid;

use common::{TestResult, run_with_database};

const MIGRATION_VERSION: i64 = 64;
const MIGRATION: &str = include_str!("../migrations/0064_workflow_reruns.sql");

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_0064_seals_public_identity_authority_and_source_lineage() {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == MIGRATION_VERSION)
        .expect("migration 0064 is embedded");
    assert_eq!(migration.description.as_ref(), "workflow reruns");
    for required in [
        "CREATE UNIQUE INDEX workflow_runs_public_id_attempt",
        "workflow_rerun_attempts_run_source_unique",
        "workflow_rerun_requests_revision_positive CHECK (authorization_revision > 0)",
        "workflow_rerun_requests_actor_membership_fk",
        "workflow_rerun_requests_actor_session_fk",
        "workflow_rerun_attempt_jobs_source_run_fk",
        "workflow_rerun_attempt_jobs_source_job_fk",
        "workflow_rerun_carried_job_results_source_run_fk",
        "REFERENCES workflow_plan_v2_run_result_jobs(run_id, logical_job_id)",
        "workflow_rerun_carried_job_results_no_update_delete",
        "automata_required_github_subject_evidence_committed",
        "FROM github_workflow_run_subject_evidence AS evidence",
        "FROM github_schedule_workflow_run_subject_evidence AS evidence",
        "origin.origin_kind = 'workflow_rerun'",
        "automata_require_open_workflow_admission_graph",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing rerun invariant: {required}"
        );
    }
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn rerun_request_authority_requires_a_live_positive_session_revision() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_actor(database.pool()).await?;
        let tenant_id = seed.tenant_id.as_str();
        let repository_id = seed.repository_id;
        let workflow_id = seed.workflow_id;
        let snapshot_id = seed.snapshot_id;
        let source_run_id = Uuid::new_v4();

        insert_source_run(
            database.pool(),
            repository_id,
            workflow_id,
            snapshot_id,
            source_run_id,
            1,
            1,
            1,
        )
        .await?;

        let error = sqlx::query(
            r"
            INSERT INTO workflow_rerun_requests (
                tenant_id, operation_id, request_digest, repository_id, source_run_id,
                selection_kind, selected_source_job_id, actor_principal_id,
                actor_session_id, authorization_revision, rerun_run_id, committed_at_ms
            ) VALUES (
                $1, $2, $3, $4, $5, 'entire_workflow', NULL, $6, $7, 0, NULL, NULL
            )
            ",
        )
        .bind(tenant_id)
        .bind(Uuid::new_v4())
        .bind([0x11_u8; 32].as_slice())
        .bind(repository_id)
        .bind(source_run_id)
        .bind(seed.principal_id)
        .bind(seed.session_id)
        .execute(database.pool())
        .await
        .expect_err("rerun requests must reject authorization revision zero");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("workflow_rerun_requests_revision_positive"),
        );

        let orphan_error = sqlx::query(
            r"
            INSERT INTO workflow_rerun_requests (
                tenant_id, operation_id, request_digest, repository_id, source_run_id,
                selection_kind, selected_source_job_id, actor_principal_id,
                actor_session_id, authorization_revision, rerun_run_id, committed_at_ms
            ) VALUES (
                $1, $2, $3, $4, $5, 'entire_workflow', NULL, $6, $7, 1, NULL, NULL
            )
            ",
        )
        .bind(tenant_id)
        .bind(Uuid::new_v4())
        .bind([0x22_u8; 32].as_slice())
        .bind(repository_id)
        .bind(source_run_id)
        .bind(seed.principal_id)
        .bind(Uuid::new_v4())
        .execute(database.pool())
        .await
        .expect_err("rerun requests must not accept an unknown actor session");
        assert_eq!(
            orphan_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("workflow_rerun_requests_actor_session_fk"),
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn rerun_schema_enforces_unique_visible_attempt_identity_and_source_lineage() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_actor(database.pool()).await?;
        let repository_id = seed.repository_id;
        let workflow_id = seed.workflow_id;
        let snapshot_id = seed.snapshot_id;

        insert_source_run(
            database.pool(),
            repository_id,
            workflow_id,
            snapshot_id,
            Uuid::new_v4(),
            1,
            1,
            1,
        )
        .await?;
        let duplicate_error = insert_source_run(
            database.pool(),
            repository_id,
            workflow_id,
            snapshot_id,
            Uuid::new_v4(),
            2,
            1,
            1,
        )
        .await
        .expect_err("public rerun identity must be unique per workflow attempt");
        assert_eq!(
            duplicate_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("workflow_runs_public_id_attempt"),
        );

        let constraint_names: Vec<String> = sqlx::query_scalar(
            r"
            SELECT conname
            FROM pg_constraint
            WHERE connamespace = current_schema()::regnamespace
              AND conname = ANY($1)
            ORDER BY conname
            ",
        )
        .bind(vec![
            "workflow_rerun_attempt_jobs_source_job_fk",
            "workflow_rerun_attempt_jobs_source_run_fk",
            "workflow_rerun_carried_job_results_source_fk",
            "workflow_rerun_carried_job_results_source_run_fk",
        ])
        .fetch_all(database.pool())
        .await?;
        assert_eq!(
            constraint_names,
            vec![
                "workflow_rerun_attempt_jobs_source_job_fk",
                "workflow_rerun_attempt_jobs_source_run_fk",
                "workflow_rerun_carried_job_results_source_fk",
                "workflow_rerun_carried_job_results_source_run_fk",
            ],
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn postgres_rerun_adapter_is_explicitly_unsupported_and_writes_no_state() -> TestResult {
    run_with_database(|database| async move {
        let store = PostgresStore::from_postgres_pool(database.pool().clone());
        let actor = ManagementActor::new(
            TenantId::new("unauthorized-rerun-test").expect("tenant"),
            PrincipalId::new(Uuid::from_u128(0x641).hyphenated().to_string()).expect("principal"),
            SessionId::new(Uuid::from_u128(0x642).hyphenated().to_string()).expect("session"),
            ManagementRevision::new(1).expect("revision"),
            None,
            UnixTimestamp::from_seconds(0),
        );
        let before: (i64, i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM workflow_runs),
                (SELECT count(*) FROM workflow_rerun_requests),
                (SELECT count(*) FROM workflow_rerun_attempts),
                (SELECT count(*) FROM workflow_rerun_attempt_jobs),
                (SELECT count(*) FROM security_audit_events)
            ",
        )
        .fetch_one(database.pool())
        .await?;
        for (selection, operation_id) in [
            (WorkflowRerunSelection::EntireWorkflow, 0x645),
            (WorkflowRerunSelection::FailedJobsAndDependents, 0x646),
            (
                WorkflowRerunSelection::JobAndDependents(
                    automata_ci_store::LogicalWorkflowJobId::from_uuid(Uuid::from_u128(0x647))?,
                ),
                0x648,
            ),
        ] {
            let request = RerunWorkflow::new(
                actor.clone(),
                RepositoryId::from_uuid(Uuid::from_u128(0x643)),
                RunId::from_uuid(Uuid::from_u128(0x644)),
                selection,
                OperationId::from_uuid(Uuid::from_u128(operation_id)),
            )?;
            assert!(matches!(
                store.rerun_workflow(request).await,
                Err(WorkflowRerunStoreError::Unsupported)
            ));
        }

        let after: (i64, i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM workflow_runs),
                (SELECT count(*) FROM workflow_rerun_requests),
                (SELECT count(*) FROM workflow_rerun_attempts),
                (SELECT count(*) FROM workflow_rerun_attempt_jobs),
                (SELECT count(*) FROM security_audit_events)
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            after, before,
            "unsupported reruns must not write rerun, workflow, or audit state"
        );
        Ok(())
    })
    .await
}

#[derive(Debug)]
#[allow(clippy::struct_field_names)] // Fixture field names mirror durable IDs under test.
struct ActorSeed {
    tenant_id: String,
    repository_id: Uuid,
    workflow_id: Uuid,
    snapshot_id: Uuid,
    principal_id: Uuid,
    session_id: Uuid,
}

#[allow(clippy::too_many_lines)] // Explicit auth/session setup keeps the fixture auditable.
async fn seed_actor(pool: &PgPool) -> TestResult<ActorSeed> {
    let tenant_id = format!("tenant-{}", Uuid::new_v4().simple());
    let repository_id = Uuid::new_v4();
    let workflow_id = Uuid::new_v4();
    let snapshot_id = Uuid::new_v4();
    let principal_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let provider_subject = format!("workflow-rerun-{}", principal_id.simple());
    sqlx::query(
        "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Workflow rerun tenant', 1, 1)",
    )
    .bind(&tenant_id)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id,
            owner, name, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, 'github', $3, 'automata', 'reruns', 1, 1)
        ",
    )
    .bind(repository_id)
    .bind(&tenant_id)
    .bind(format!("repo-{}", repository_id.simple()))
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_definitions (
            id, repository_id, path, enabled, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, '.github/workflows/rerun.yml', TRUE, 1, 1)
        ",
    )
    .bind(workflow_id)
    .bind(repository_id)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_snapshots (
            id, workflow_id, source_digest, source_object_key, frontend_schema,
            created_at_ms, admission_epoch, source_size_bytes, source_media_type
        ) VALUES ($1, $2, $3, 'snapshot.pb', 1, 1, 4, 128, 'application/octet-stream')
        ",
    )
    .bind(snapshot_id)
    .bind(workflow_id)
    .bind([0x33_u8; 32].as_slice())
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO human_principals (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Workflow rerun actor', 1, 1)",
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
    .bind(format!("workflow-rerun-actor-{}", principal_id.simple()))
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO tenant_human_memberships (tenant_id, principal_id, created_at_ms, updated_at_ms) VALUES ($1, $2, 1, 1)",
    )
    .bind(&tenant_id)
    .bind(principal_id)
    .execute(pool)
    .await?;
    let revision: i64 = sqlx::query_scalar(
        "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id = $1 AND principal_id = $2",
    )
    .bind(&tenant_id)
    .bind(principal_id)
    .fetch_one(pool)
    .await?;
    let now_ms: i64 =
        sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT")
            .fetch_one(pool)
            .await?;
    let issued_at = now_ms.saturating_sub(1_000);
    let idle_expires_at = now_ms.checked_add(3_600_000).ok_or("clock overflow")?;
    let expires_at = now_ms.checked_add(7_200_000).ok_or("clock overflow")?;
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
            $1, $2, $3, 'github', $4, 'browser', 'automata.web', $5,
            'workflow-rerun-session-v1', $6, $7, $7, $8, $9
        )
        ",
    )
    .bind(session_id)
    .bind(&tenant_id)
    .bind(principal_id)
    .bind(provider_subject)
    .bind(token_hash.as_slice())
    .bind(revision)
    .bind(issued_at)
    .bind(idle_expires_at)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(ActorSeed {
        tenant_id,
        repository_id,
        workflow_id,
        snapshot_id,
        principal_id,
        session_id,
    })
}

#[allow(clippy::too_many_arguments)] // Callers pass the exact durable run identity under test.
async fn insert_source_run(
    pool: &PgPool,
    repository_id: Uuid,
    workflow_id: Uuid,
    snapshot_id: Uuid,
    run_id: Uuid,
    run_number: i64,
    public_run_id_alias: i64,
    run_attempt: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number, run_attempt,
            event_name, event_object_key, head_sha, status, created_at_ms, updated_at_ms,
            concurrency_group_key, admission_epoch, event_digest, event_size_bytes,
            event_media_type, plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema, workflow_name, git_ref, actor,
            display_title, commit_subject, public_run_id_alias, triggering_actor
        ) VALUES (
            $1, $2, $3, $4, $5, $6, 'push', 'event.json', $7, 'completed', 1, 2,
            NULL, 4, $8, 128, 'application/json', $9, 'plan.pb', 128,
            'application/vnd.automata.workflow-plan+json', 2, 'workflow', 'refs/heads/main',
            'github-actions[bot]', 'Workflow', 'Initial commit', $10, NULL
        )
        ",
    )
    .bind(run_id)
    .bind(repository_id)
    .bind(workflow_id)
    .bind(snapshot_id)
    .bind(run_number)
    .bind(run_attempt)
    .bind([0x44_u8; 32].as_slice())
    .bind([0x55_u8; 32].as_slice())
    .bind([0x66_u8; 32].as_slice())
    .bind(public_run_id_alias)
    .execute(pool)
    .await?;
    Ok(())
}
