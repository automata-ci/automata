const MIGRATION: &str = include_str!("../migrations/0048_workflow_base_runtime_context.sql");

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_binds_one_exact_current_base_context() {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 48)
        .expect("migration 0048 is embedded");
    assert_eq!(
        migration.description.as_ref(),
        "workflow base runtime context"
    );

    for required in [
        "workflow_plan_v2_runs_base_context",
        "base_context_digest IS NOT NULL",
        "base_context_object_key IS NOT NULL",
        "base_context_size_bytes IS NOT NULL",
        "base_context_media_type IS NOT NULL",
        "base_context_schema IS NOT NULL",
        "base_context_schema = 2",
        "application/vnd.automata.job-runtime-context.protobuf",
        "workflow_plan_v2_runs_base_context_immutable",
        "workflow_plan_v2_activation_preparation_base_context_exact",
        "workflow_plan_v2_activation_preparation_base_context_immutable",
        "marker.base_context_digest = NEW.base_context_digest",
        "status IN ('queued', 'in_progress')",
        "requires drained active runs",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
}

#[test]
fn migration_keeps_secret_material_out_of_the_relational_schema() {
    for prohibited in [
        "secret_value",
        "plaintext_secret",
        "decrypted_secret",
        "provider_secret",
    ] {
        assert!(
            !MIGRATION.contains(prohibited),
            "migration must persist only opaque context metadata: {prohibited}"
        );
    }
}
