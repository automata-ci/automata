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
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, migrate::Migrate as _};
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_database, run_with_unmigrated_database};

const MIGRATION_VERSION: i64 = 64;
const MIGRATION: &str = include_str!("../migrations/0064_workflow_reruns.sql");
const POSTGRES_ADAPTER: &str = include_str!("../src/postgres/workflow_rerun.rs");
const RELEASED_0061: &str =
    include_str!("../migrations/0061_reusable_workflow_runtime_authority.sql");

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn released_0061_is_byte_exact_and_rerun_authority_is_forward_only() {
    let digest: [u8; 32] = Sha256::digest(RELEASED_0061.as_bytes()).into();
    assert_eq!(
        digest,
        [
            0xe3, 0x18, 0x3a, 0x74, 0x6f, 0x8e, 0x60, 0x00, 0x12, 0x90, 0x9e, 0x41, 0x15, 0xe0,
            0x6b, 0xae, 0x5d, 0x0b, 0xce, 0xd3, 0xbd, 0x68, 0x73, 0x7c, 0x88, 0xf3, 0xe5, 0x03,
            0x6a, 0xae, 0xbd, 0x19,
        ],
        "released migration 0061 changed bytes"
    );
    assert!(
        !RELEASED_0061.contains("workflow_rerun"),
        "0061 contains forward-only rerun authority"
    );
}

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
        "attempt BETWEEN 2 AND 51",
        "workflow_rerun_requests_revision_positive CHECK (authorization_revision > 0)",
        "workflow_rerun_requests_actor_membership_fk",
        "workflow_rerun_requests_actor_session_fk",
        "workflow_rerun_requests_tenant_run_unique",
        "workflow_rerun_requests_operation_run_unique",
        "workflow_rerun_attempt_jobs_source_run_fk",
        "workflow_rerun_attempt_jobs_source_job_fk",
        "workflow_rerun_carried_job_results_source_run_fk",
        "workflow_rerun_carried_job_results_mapping_fk",
        "REFERENCES workflow_plan_v2_run_result_jobs(run_id, logical_job_id)",
        "workflow_rerun_carried_job_results_no_update_delete",
        "workflow_rerun_carried_job_results_validate_source",
        "workflow_rerun_carried_job_source_exact",
        "workflow_rerun_carried_job_outputs_validate_source",
        "workflow_rerun_carried_results_validate_classification",
        "workflow_rerun_executed_results_validate_classification",
        "workflow_rerun_graph_exact",
        "workflow_rerun_attempts_validate_graph",
        "workflow_rerun_requests_validate_graph",
        "workflow_rerun_attempt_jobs_validate_graph",
        "workflow_rerun_check_evidence_exact",
        "workflow_rerun_check_evidence_manifest",
        "provider_manifest_revision, provider_manifest_digest",
        "authority.state = 'active'",
        "authority.state_updated_at_ms <= NEW.recorded_at_ms",
        "FOR SHARE OF attempt, request, receipt, run, manifest, authority",
        "github_workflow_rerun_subject_evidence",
        "automata_github_workflow_rerun_subject_evidence_digest",
        "github_workflow_rerun_subject_evidence_exact",
        "github_check_subjects_require_rerun_link_evidence",
        "workflow_rerun_check_link_evidence_required",
        "github_check_subjects_require_atomic_rerun_evidence",
        "workflow_rerun_check_atomic_evidence_required",
        "workflow_rerun_attempts_validate_lineage",
        "source_marker.admission_digest = NEW.source_admission_digest",
        "source_run.plan_digest = NEW.source_plan_digest",
        "source_run.event_digest = NEW.source_event_digest",
        "run.created_at_ms = NEW.created_at_ms",
        "workflow_rerun_requests_no_update_delete",
        "workflow_rerun_requests_attempt_source_fk",
        "automata_required_github_subject_evidence_committed",
        "FROM github_workflow_run_subject_evidence AS evidence",
        "FROM github_schedule_workflow_run_subject_evidence AS evidence",
        "FROM github_workflow_rerun_subject_evidence AS evidence",
        "'workflow_rerun'::TEXT AS origin_kind",
        "automata_require_open_workflow_admission_graph",
        "automata_github_oidc_authority_is_current",
        "automata_validate_github_runtime_authority_v3_identity",
        "'scheduled_fire', 'workflow_rerun'",
        "automata_require_preparation_runner_policy_provenance",
        "automata_validate_logical_activation_preparation_claim",
        "LEFT JOIN workflow_plan_v2_effective_job_results AS result",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing rerun invariant: {required}"
        );
    }
}

#[test]
fn root_and_nested_reruns_take_the_group_lock_before_the_source_row() {
    let admission = POSTGRES_ADAPTER
        .split_once("async fn admit_authorized_rerun(")
        .expect("rerun admission function")
        .1
        .split_once("async fn persist_rerun(")
        .expect("bounded rerun admission body")
        .0;
    let hint = admission
        .find("let root_run_id_hint = resolve_rerun_root_hint")
        .expect("unlocked root hint");
    let group_lock = admission
        .find("lock_rerun_group(&mut transaction, root_run_id_hint)")
        .expect("root group lock");
    let source_lock = admission
        .find("let source = lock_source_run(&mut transaction, &request)")
        .expect("selected source row lock");
    let root_recheck = admission
        .find("if source.root_run_id != root_run_id_hint")
        .expect("locked root recheck");
    assert!(hint < group_lock && group_lock < source_lock && source_lock < root_recheck);

    let resolver = POSTGRES_ADAPTER
        .split_once("async fn resolve_rerun_root_hint(")
        .expect("root hint resolver")
        .1
        .split_once("async fn lock_source_run(")
        .expect("bounded root hint resolver")
        .0;
    assert!(resolver.contains("COALESCE(attempt.root_run_id, run.id)"));
    assert!(!resolver.contains("FOR UPDATE"));
    assert!(!resolver.contains("FOR SHARE"));
    assert!(MIGRATION.contains("workflow_rerun_attempts_no_update_delete"));

    let source_resolver = POSTGRES_ADAPTER
        .split_once("async fn lock_source_run(")
        .expect("source row resolver")
        .1
        .split_once("async fn lock_private_source_authority(")
        .expect("bounded source row resolver")
        .0;
    assert!(source_resolver.contains("FOR UPDATE OF run"));
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn pre_rerun_schema_upgrades_forward_only_and_matches_current_authority() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_before(&database, MIGRATION_VERSION).await?;
        let seed = seed_actor(database.pool()).await?;
        let run_id = Uuid::new_v4();
        insert_pre_rerun_source_run(
            database.pool(),
            seed.repository_id,
            seed.workflow_id,
            seed.snapshot_id,
            run_id,
        )
        .await?;
        let legacy_alias: i64 =
            sqlx::query_scalar("SELECT run_id_alias FROM workflow_runs WHERE id = $1")
                .bind(run_id)
                .fetch_one(database.pool())
                .await?;

        apply_version(&database, MIGRATION_VERSION).await?;

        let upgraded: (i64, i64, i32) = sqlx::query_as(
            "SELECT run_id_alias, public_run_id_alias, run_attempt FROM workflow_runs WHERE id = $1",
        )
        .bind(run_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(upgraded, (legacy_alias, legacy_alias, 1));

        let post_upgrade_attempt = Uuid::new_v4();
        insert_source_run(
            database.pool(),
            seed.repository_id,
            seed.workflow_id,
            seed.snapshot_id,
            post_upgrade_attempt,
            7,
            None,
            7,
        )
        .await?;
        let own_alias: (i64, i64, i32) = sqlx::query_as(
            "SELECT run_id_alias, public_run_id_alias, run_attempt FROM workflow_runs WHERE id = $1",
        )
        .bind(post_upgrade_attempt)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(own_alias.0, own_alias.1);
        assert_eq!(own_alias.2, 7);

        let rerun_aware_functions: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)::BIGINT
            FROM pg_proc
            WHERE pronamespace = current_schema()::regnamespace
              AND proname = ANY($1)
              AND position('workflow_rerun' IN pg_get_functiondef(oid)) > 0
            ",
        )
        .bind(vec![
            "automata_github_oidc_authority_is_current",
            "automata_require_standard_github_oidc_profile",
            "automata_lock_github_oidc_authority_dependencies",
            "automata_github_runtime_authority_v2_base_is_current",
            "automata_github_runtime_authority_has_v3_provenance",
        ])
        .fetch_one(database.pool())
        .await?;
        assert_eq!(rerun_aware_functions, 5);

        let migration_applied: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 64 AND success)",
        )
        .fetch_one(database.pool())
        .await?;
        assert!(migration_applied);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // One table-driven transaction checks every authority fault.
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
            Some(1),
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

        let mut incomplete = database.pool().begin().await?;
        sqlx::query(
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
        .bind([0x33_u8; 32].as_slice())
        .bind(repository_id)
        .bind(source_run_id)
        .bind(seed.principal_id)
        .bind(seed.session_id)
        .execute(&mut *incomplete)
        .await?;
        let incomplete_error = incomplete
            .commit()
            .await
            .expect_err("an incomplete rerun request must not squat an operation ID");
        assert_eq!(
            incomplete_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("workflow_rerun_requests_completion_exact"),
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
            Some(1),
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
            Some(1),
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
        let source_seal: (bool, bool) = sqlx::query_as(
            r"
            SELECT trigger.tgdeferrable, trigger.tginitdeferred
            FROM pg_trigger AS trigger
            WHERE trigger.tgrelid =
                      'workflow_rerun_carried_job_results'::regclass
              AND trigger.tgname =
                      'workflow_rerun_carried_job_results_validate_source'
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(source_seal, (true, true));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn unauthorized_rerun_is_rejected_without_writes() -> TestResult {
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
                Err(WorkflowRerunStoreError::AuthorityRejected)
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
            "unauthorized reruns must not write rerun, workflow, or audit state"
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
    public_run_id_alias: Option<i64>,
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

async fn insert_pre_rerun_source_run(
    pool: &PgPool,
    repository_id: Uuid,
    workflow_id: Uuid,
    snapshot_id: Uuid,
    run_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number, run_attempt,
            event_name, event_object_key, head_sha, status, created_at_ms, updated_at_ms,
            concurrency_group_key, admission_epoch, event_digest, event_size_bytes,
            event_media_type, plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema, workflow_name, git_ref, actor,
            display_title, commit_subject
        ) VALUES (
            $1, $2, $3, $4, 1, 1, 'push', 'event.json', $5, 'completed', 1, 2,
            NULL, 4, $6, 128, 'application/json', $7, 'plan.pb', 128,
            'application/vnd.automata.workflow-plan+json', 2, 'workflow', 'refs/heads/main',
            'github-actions[bot]', 'Workflow', 'Initial commit'
        )
        ",
    )
    .bind(run_id)
    .bind(repository_id)
    .bind(workflow_id)
    .bind(snapshot_id)
    .bind([0x77_u8; 32].as_slice())
    .bind([0x78_u8; 32].as_slice())
    .bind([0x79_u8; 32].as_slice())
    .execute(pool)
    .await?;
    Ok(())
}

async fn apply_before(database: &TestDatabase, version: i64) -> TestResult {
    let mut connection = database.pool().acquire().await?;
    connection
        .ensure_migrations_table(MIGRATOR.table_name.as_ref())
        .await?;
    for migration in MIGRATOR
        .iter()
        .filter(|migration| migration.version < version)
    {
        connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await?;
    }
    Ok(())
}

async fn apply_version(database: &TestDatabase, version: i64) -> TestResult {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == version)
        .expect("migration is embedded");
    let mut connection = database.pool().acquire().await?;
    connection
        .apply(MIGRATOR.table_name.as_ref(), migration)
        .await?;
    Ok(())
}
