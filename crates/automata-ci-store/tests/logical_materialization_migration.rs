const MIGRATION_SQL: &str = include_str!("../migrations/0021_workflow_plan_v2_concrete_jobs.sql");

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_0021_is_embedded_as_the_current_concrete_job_phase() {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 21)
        .expect("migration 0021 is embedded");
    assert_eq!(
        migration.description.as_ref(),
        "workflow plan v2 concrete jobs"
    );
    for table in [
        "workflow_plan_v2_materialization_claims",
        "workflow_plan_v2_concrete_jobs",
    ] {
        assert!(
            MIGRATION_SQL.contains(&format!("CREATE TABLE {table}")),
            "migration must create {table}"
        );
    }
}

#[test]
fn migration_fences_exact_v5_jobs_attempts_and_logical_completion() {
    for required in [
        "descriptor_digest BYTEA NOT NULL",
        "expected_job_id UUID NOT NULL UNIQUE",
        "expected_attempt_id UUID NOT NULL UNIQUE",
        "state IN ('materializing', 'materialized')",
        "generation > 0",
        "expires_at_ms - claimed_at_ms <= 900000",
        "instance.job_ir_version = 5",
        "instance.runtime_context_schema = 2",
        "JOIN jobs AS job ON job.id = NEW.job_id",
        "JOIN job_attempts AS attempt ON attempt.id = NEW.initial_attempt_id",
        "attempt.attempt_number = 1",
        "attempt.lifecycle = 'queued'",
        "job.admission_epoch = 4",
        "job.job_ir_schema = 5",
        "WorkflowPlan-v2 jobs do not use legacy job dependencies",
        "WorkflowPlan-v2 run cannot complete before orchestration finalization",
        "DEFERRABLE INITIALLY DEFERRED",
    ] {
        assert!(
            MIGRATION_SQL.contains(required),
            "migration lost current concrete-job gate: {required}"
        );
    }
    assert!(!MIGRATION_SQL.contains("INSERT INTO job_dependencies"));
    assert!(!MIGRATION_SQL.contains("job_ir_schema IN"));
    assert!(!MIGRATION_SQL.contains("admission_epoch BETWEEN"));
    assert!(!MIGRATION_SQL.contains("legacy JobIR"));
}
