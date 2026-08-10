const MIGRATION_SQL: &str = include_str!("../migrations/0019_workflow_plan_v2_orchestration.sql");

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_0019_is_embedded_as_the_current_logical_foundation() {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 19)
        .expect("migration 0019 is embedded");
    assert_eq!(
        migration.description.as_ref(),
        "workflow plan v2 orchestration"
    );

    for table in [
        "workflow_plan_v2_runs",
        "workflow_plan_v2_invocations",
        "workflow_plan_v2_jobs",
        "workflow_plan_v2_dependencies",
    ] {
        assert!(
            MIGRATION_SQL.contains(&format!("CREATE TABLE {table}")),
            "migration must create {table}"
        );
    }
    for deferred_table in [
        "workflow_plan_v2_instances",
        "workflow_plan_v2_results",
        "workflow_plan_v2_outputs",
    ] {
        assert!(
            !MIGRATION_SQL.contains(&format!("CREATE TABLE {deferred_table}")),
            "later lifecycle table {deferred_table} must not be admitted without its invariants"
        );
    }
}

#[test]
fn migration_fences_exact_schema_and_immutable_claim_shapes() {
    for required in [
        "admission_epoch = 4",
        "plan_schema = 2",
        "orchestration_schema = 1",
        "octet_length(admission_digest) = 32",
        "workflow_plan_v2_jobs_claim_shape",
        "activation_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid",
        "activation_expires_at_ms > activation_claimed_at_ms",
        "workflow_runs_enforce_plan_v2_immutable",
        "workflow_plan_v2_dependencies_reject_update",
        "DEFERRABLE INITIALLY DEFERRED",
    ] {
        assert!(
            MIGRATION_SQL.contains(required),
            "migration lost required gate: {required}"
        );
    }

    for forbidden_write in [
        "INSERT INTO jobs",
        "INSERT INTO job_attempts",
        "INSERT INTO job_dependencies",
    ] {
        assert!(
            !MIGRATION_SQL.contains(forbidden_write),
            "logical migration must not publish concrete work: {forbidden_write}"
        );
    }
}
