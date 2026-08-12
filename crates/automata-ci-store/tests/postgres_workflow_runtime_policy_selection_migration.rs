#[allow(dead_code)]
mod common;

use sqlx::migrate::Migrate as _;
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_unmigrated_database};

const MIGRATION_VERSION: i64 = 43;
const MIGRATION_SQL: &str =
    include_str!("../migrations/0043_workflow_runtime_policy_and_selection.sql");
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_0043_is_single_pass_current_only_and_closes_selection_custody() {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == MIGRATION_VERSION)
        .expect("migration 0043 is embedded");
    assert_eq!(
        migration.description.as_ref(),
        "workflow runtime policy and selection"
    );
    for required in [
        "workflow_runtime_policy_current_only",
        "CREATE TABLE workflow_runtime_policy_revisions",
        "CREATE TABLE workflow_plan_v2_activation_work_selections",
        "CREATE TABLE workflow_plan_v2_materialization_work_selections",
        "CREATE TABLE workflow_plan_v2_activation_work_quarantines",
        "CREATE TABLE workflow_plan_v2_materialization_work_quarantines",
        "CREATE TABLE workflow_plan_v2_activation_renewal_receipts",
        "CREATE TABLE workflow_plan_v2_materialization_renewal_receipts",
        "successor_generation = predecessor_generation + 1",
        "receipt_count >= 64",
        "claim_origin_selection_id UUID NOT NULL",
        "workflow_plan_v2_preparation_claims_truncate",
        "DEFERRABLE INITIALLY DEFERRED",
    ] {
        assert!(
            MIGRATION_SQL.contains(required),
            "migration lost required invariant: {required}"
        );
    }
    for prohibited in [
        "DROP TABLE workflow_plan_v2_activation_work_selections",
        "DROP TABLE workflow_plan_v2_materialization_work_selections",
        "DROP TABLE workflow_plan_v2_activation_work_quarantines",
        "DROP TABLE workflow_plan_v2_materialization_work_quarantines",
        "automata_validate_activation_work_fence",
        "automata_validate_materialization_work_fence",
        "automata_validate_work_selection_receipt",
        "automata_validate_work_quarantine",
        "automata_enforce_work_selection_receipt_delete",
    ] {
        assert!(
            !MIGRATION_SQL.contains(prohibited),
            "migration retained transitional surface: {prohibited}"
        );
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn pre_policy_logical_state_refuses_atomically_then_clean_upgrade_is_guarded() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_before_0043(&database).await?;
        let run_id = insert_pre_policy_logical_run(&database).await?;

        let migration = migration_0043();
        let mut connection = database.pool().acquire().await?;
        let error = connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await
            .expect_err("pre-policy logical state must refuse the current-only upgrade");
        assert_migration_refusal(error, "workflow_runtime_policy_current_only");
        drop(connection);

        let rolled_back: (i64, i64, Option<String>) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM workflow_plan_v2_runs WHERE run_id = $1),
                (SELECT count(*) FROM _sqlx_migrations WHERE version = 43 AND success),
                to_regclass('workflow_runtime_policy_revisions')::TEXT
            ",
        )
        .bind(run_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(rolled_back, (1, 0, None));

        reconcile_pre_policy_logical_run(&database, run_id).await?;

        let mut connection = database.pool().acquire().await?;
        connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await?;
        drop(connection);

        assert_applied_catalog(&database).await?;
        assert_preparation_claim_truncate_is_guarded(&database).await?;
        Ok(())
    })
    .await
}

fn migration_0043() -> &'static sqlx::migrate::Migration {
    MIGRATOR
        .iter()
        .find(|migration| migration.version == MIGRATION_VERSION)
        .expect("migration 0043 is embedded")
}

async fn apply_before_0043(database: &TestDatabase) -> TestResult {
    let mut connection = database.pool().acquire().await?;
    connection
        .ensure_migrations_table(MIGRATOR.table_name.as_ref())
        .await?;
    for migration in MIGRATOR
        .iter()
        .filter(|migration| migration.version < MIGRATION_VERSION)
    {
        connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the historical fixture is one atomic relational aggregate whose row order is part of the migration proof"
)]
async fn insert_pre_policy_logical_run(database: &TestDatabase) -> TestResult<Uuid> {
    let tenant = format!("tenant-{}", Uuid::new_v4().simple());
    let repository = Uuid::new_v4();
    let workflow = Uuid::new_v4();
    let snapshot = Uuid::new_v4();
    let run = Uuid::new_v4();
    let invocation = Uuid::new_v4();
    let logical_job = Uuid::new_v4();
    let mut transaction = database.pool().begin().await?;
    sqlx::query(
        "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) \
         VALUES ($1, 'Migration 0043 fixture', 1, 1)",
    )
    .bind(&tenant)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id,
            owner, name, created_at_ms, updated_at_ms
        ) VALUES ($1,$2,'github',$3,'automata-ci','migration-0043',1,1)
        ",
    )
    .bind(repository)
    .bind(&tenant)
    .bind(repository.to_string())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_definitions (
            id, repository_id, path, created_at_ms, updated_at_ms
        ) VALUES ($1,$2,'.ci/workflows/ci.yml',1,1)
        ",
    )
    .bind(workflow)
    .bind(repository)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_snapshots (
            id, workflow_id, source_digest, source_object_key,
            source_size_bytes, source_media_type, frontend_schema,
            admission_epoch, created_at_ms
        ) VALUES ($1,$2,$3,'migration-0043/workflow.yml',128,
                  'application/yaml',1,4,1)
        ",
    )
    .bind(snapshot)
    .bind(workflow)
    .bind([1_u8; 32].as_slice())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number,
            event_name, event_object_key, event_digest, event_size_bytes,
            event_media_type, plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema, head_sha, status, admission_epoch,
            created_at_ms, updated_at_ms
        ) VALUES (
            $1,$2,$3,$4,1,'push','migration-0043/event.json',$5,128,
            'application/json',$6,'migration-0043/plan.pb',128,
            'application/vnd.automata.workflow-plan.protobuf',2,$7,
            'queued',4,1,1
        )
        ",
    )
    .bind(run)
    .bind(repository)
    .bind(workflow)
    .bind(snapshot)
    .bind([2_u8; 32].as_slice())
    .bind([3_u8; 32].as_slice())
    .bind([4_u8; 20].as_slice())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_runs (
            run_id, root_invocation_id, admission_digest,
            state, admitted_at_ms, updated_at_ms
        ) VALUES ($1,$2,$3,'active',1,1)
        ",
    )
    .bind(run)
    .bind(invocation)
    .bind([5_u8; 32].as_slice())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_invocations (
            id, run_id, plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema, state, created_at_ms, updated_at_ms
        ) VALUES (
            $1,$2,$3,'migration-0043/plan.pb',128,
            'application/vnd.automata.workflow-plan.protobuf',2,'active',1,1
        )
        ",
    )
    .bind(invocation)
    .bind(run)
    .bind([3_u8; 32].as_slice())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_jobs (
            id, run_id, invocation_id, logical_key, source_order,
            execution_kind, state, activation_fence,
            created_at_ms, updated_at_ms
        ) VALUES ($1,$2,$3,'root',0,'steps','pending',0,1,1)
        ",
    )
    .bind(logical_job)
    .bind(run)
    .bind(invocation)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(run)
}

async fn reconcile_pre_policy_logical_run(database: &TestDatabase, run_id: Uuid) -> TestResult {
    // Historical result-evidence guards deliberately prevent ordinary deletes.
    // The current-only operator procedure drains the closed aggregate under an
    // exclusive maintenance boundary before retrying the migration.
    let mut transaction = database.pool().begin().await?;
    sqlx::query("ALTER TABLE workflow_plan_v2_jobs DISABLE TRIGGER USER")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("ALTER TABLE workflow_plan_v2_invocations DISABLE TRIGGER USER")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("ALTER TABLE workflow_plan_v2_runs DISABLE TRIGGER USER")
        .execute(&mut *transaction)
        .await?;
    let deleted = sqlx::query("DELETE FROM workflow_plan_v2_runs WHERE run_id = $1")
        .bind(run_id)
        .execute(&mut *transaction)
        .await?;
    assert_eq!(deleted.rows_affected(), 1);
    sqlx::query("ALTER TABLE workflow_plan_v2_runs ENABLE TRIGGER USER")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("ALTER TABLE workflow_plan_v2_invocations ENABLE TRIGGER USER")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("ALTER TABLE workflow_plan_v2_jobs ENABLE TRIGGER USER")
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

fn assert_migration_refusal(error: sqlx::migrate::MigrateError, expected_constraint: &str) {
    match error {
        sqlx::migrate::MigrateError::ExecuteMigration(error, MIGRATION_VERSION) => {
            let database_error = error
                .as_database_error()
                .expect("migration refusal is a PostgreSQL error");
            assert_eq!(database_error.code().as_deref(), Some("23514"));
            assert_eq!(database_error.constraint(), Some(expected_constraint));
        }
        other => panic!("unexpected migration error: {other}"),
    }
}

async fn assert_applied_catalog(database: &TestDatabase) -> TestResult {
    let catalog: (i64, Option<String>, Option<String>, Option<String>, String) = sqlx::query_as(
        r"
            SELECT
                (SELECT count(*) FROM _sqlx_migrations WHERE version = 43 AND success),
                to_regclass('workflow_runtime_policy_revisions')::TEXT,
                to_regclass('workflow_plan_v2_activation_work_quarantines')::TEXT,
                to_regclass('workflow_plan_v2_materialization_work_quarantines')::TEXT,
                (SELECT is_nullable FROM information_schema.columns
                 WHERE table_schema = current_schema()
                   AND table_name = 'workflow_plan_v2_activation_preparations'
                   AND column_name = 'claim_origin_selection_id')
            ",
    )
    .fetch_one(database.pool())
    .await?;
    assert_eq!(catalog.0, 1);
    assert!(catalog.1.is_some());
    assert!(catalog.2.is_some());
    assert!(catalog.3.is_some());
    assert_eq!(catalog.4, "NO");
    Ok(())
}

async fn assert_preparation_claim_truncate_is_guarded(database: &TestDatabase) -> TestResult {
    let error = sqlx::query("TRUNCATE workflow_plan_v2_activation_preparation_claims CASCADE")
        .execute(database.pool())
        .await
        .expect_err("preparation authority evidence must reject truncate");
    let database_error = error
        .as_database_error()
        .expect("truncate refusal is a PostgreSQL error");
    assert_eq!(database_error.code().as_deref(), Some("23514"));
    assert_eq!(
        database_error.constraint(),
        Some("workflow_work_selection_evidence_immutable")
    );
    Ok(())
}
