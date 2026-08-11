const ACTIVATION_MIGRATION: &str =
    include_str!("../migrations/0020_logical_activation_publication.sql");
const MATERIALIZATION_MIGRATION: &str =
    include_str!("../migrations/0021_workflow_plan_v2_concrete_jobs.sql");

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn greenfield_job_ir_v5_installs_runner_requirements_v3_directly() {
    for required in [
        "runner_requirements_schema = 3",
        "requirements @> '{\"schema_version\": 3}'::jsonb",
    ] {
        assert!(
            ACTIVATION_MIGRATION.contains(required),
            "JobIR-v5 migration is missing current resource evidence: {required}"
        );
    }
    assert!(
        MATERIALIZATION_MIGRATION.contains("requirements @> '{\"schema_version\": 3}'::jsonb"),
        "logical materialization must require the current resource-aware document"
    );
}

#[test]
fn no_resource_schema_upgrade_migration_or_v2_allowance_remains() {
    assert!(MIGRATOR.iter().all(|migration| migration.version != 57));
    for migration in [ACTIVATION_MIGRATION, MATERIALIZATION_MIGRATION] {
        assert!(!migration.contains("requirements @> '{\"schema_version\": 2}'::jsonb"));
        assert!(!migration.contains("schema_version\": 2}')) OR"));
    }
}
