const MIGRATION_SQL: &str = include_str!("../migrations/0020_logical_activation_publication.sql");

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_0020_is_embedded_as_the_current_activation_phase() {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 20)
        .expect("migration 0020 is embedded");
    assert_eq!(
        migration.description.as_ref(),
        "logical activation publication"
    );
    for table in [
        "workflow_plan_v2_activation_publications",
        "workflow_plan_v2_instances",
    ] {
        assert!(
            MIGRATION_SQL.contains(&format!("CREATE TABLE {table}")),
            "migration must create {table}"
        );
    }
}

#[test]
fn migration_fences_current_blobs_and_exact_atomic_counts() {
    for required in [
        "LOCK TABLE automata_cluster_compatibility",
        "minimum_admission_epoch = 4",
        "job_ir_schema = 5",
        "runner_sessions_live_job_ir_v5",
        "jobs_admission_epoch_exact",
        "admission_epoch = 4",
        "obsolete concrete JobIR state must be recreated",
        "activation_input_digest",
        "activation_generation > 0",
        "instance_count BETWEEN 0 AND 256",
        "job_ir_version = 5",
        "runtime_context_schema = 2",
        "application/vnd.automata.job-ir.protobuf",
        "application/vnd.automata.job-runtime-context.protobuf",
        "DEFERRABLE INITIALLY DEFERRED",
        "workflow_plan_v2_publication_count_exact",
        "workflow_plan_v2_jobs_validate_activation_transition",
        "only root jobs have authenticated inputs",
    ] {
        assert!(
            MIGRATION_SQL.contains(required),
            "migration lost required activation gate: {required}"
        );
    }

    for forbidden_write in [
        "INSERT INTO jobs",
        "INSERT INTO job_attempts",
        "INSERT INTO job_dependencies",
    ] {
        assert!(
            !MIGRATION_SQL.contains(forbidden_write),
            "descriptor phase must not publish runnable work: {forbidden_write}"
        );
    }

    for forbidden_compatibility in [
        "claimed_job_ir_schema IN (3, 4)",
        "job_ir_schema IN (3, 4)",
        "admission_epoch BETWEEN 1 AND 3",
    ] {
        assert!(
            !MIGRATION_SQL.contains(forbidden_compatibility),
            "current migration must not retain an executable compatibility branch: {forbidden_compatibility}"
        );
    }
}
