const MIGRATION: &str = include_str!("../migrations/0051_reusable_workflow_expansion.sql");

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_0051_is_embedded_without_renumbering_0050() {
    let reusable = MIGRATOR
        .iter()
        .find(|migration| migration.version == 51)
        .expect("migration 0051 is embedded");
    assert_eq!(reusable.description.as_ref(), "reusable workflow expansion");
    let concurrency = MIGRATOR
        .iter()
        .find(|migration| migration.version == 50)
        .expect("migration 0050 remains embedded");
    assert_eq!(
        concurrency.description.as_ref(),
        "generalized workflow concurrency"
    );
}

#[test]
fn exact_catalog_and_planned_graph_are_separate_from_runnable_jobs() {
    for required in [
        "workflow_plan_v2_reusable_workflow_runs",
        "workflow_plan_v2_reusable_workflow_catalog",
        "workflow_plan_v2_reusable_invocation_expansions",
        "workflow_plan_v2_reusable_expanded_jobs",
        "workflow_plan_v2_reusable_expanded_dependencies",
        "source_digest BYTEA NOT NULL",
        "plan_digest BYTEA NOT NULL",
        "invocation_contract_digest BYTEA",
        "descriptor_digest BYTEA NOT NULL",
        "workflow_plan_v2_reusable_catalog_exact_unique",
        "workflow_plan_v2_reusable_expansions_catalog_exact_fk",
        "source_revision ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'",
        "catalog.source_revision = encode(run.head_sha, 'hex')",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }

    let planned_jobs = MIGRATION
        .split_once("CREATE TABLE workflow_plan_v2_reusable_expanded_jobs")
        .expect("planned job table")
        .1
        .split_once("CREATE TABLE workflow_plan_v2_reusable_expanded_dependencies")
        .expect("bounded planned job table")
        .0;
    assert!(
        !planned_jobs.contains("REFERENCES jobs("),
        "planned jobs must not become scheduler-visible concrete jobs"
    );
}

#[test]
fn invocation_cardinality_is_lifted_without_weakening_root_uniqueness() {
    for required in [
        "DROP CONSTRAINT workflow_plan_v2_invocations_run_id_key",
        "invocation_kind IN ('root', 'reusable')",
        "workflow_plan_v2_invocations_one_root_per_run",
        "WHERE invocation_kind = 'root'",
        "workflow_plan_v2_reusable_invocation_plan_exact",
        "workflow_plan_v2_invocation_descriptor_immutable",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
    assert!(
        !MIGRATION
            .contains("DROP CONSTRAINT workflow_plan_v2_invocations_run_invocation_id_unique"),
        "the composite run/invocation identity must remain available"
    );
}

#[test]
fn limits_cycles_lineage_and_replay_are_database_enforced() {
    for required in [
        "catalog_entry_count BETWEEN 1 AND 50",
        "invocation_count BETWEEN 1 AND 256",
        "expanded_job_count BETWEEN 1 AND 4096",
        "maximum_depth BETWEEN 0 AND 9",
        "durable_maximum_depth <> expected_maximum_depth",
        "cardinality(call_path) = depth + 1",
        "workflow_plan_v2_reusable_expansion_parent_exact",
        "workflow_plan_v2_reusable_expansion_acyclic",
        "workflow_plan_v2_reusable_expansion_callsites_exact",
        "workflow_plan_v2_reusable_expansion_counts_exact",
        "workflow_plan_v2_reusable_runs_validate_expansion",
        "workflow_plan_v2_reusable_dependencies_validate_expansion",
        "dependency_count BETWEEN 0 AND 1047552",
        "expansion_digest BYTEA NOT NULL",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
}

#[test]
fn typed_boundaries_and_permission_reduction_have_durable_shapes() {
    for required in [
        "workflow_plan_v2_reusable_input_bindings",
        "input_type IN ('boolean', 'number', 'string')",
        "binding_kind IN ('caller', 'default', 'implicit_default')",
        "workflow_plan_v2_reusable_secret_bindings",
        "workflow_plan_v2_reusable_secret_bindings_name_only",
        "workflow_plan_v2_reusable_outputs",
        "sensitivity IN ('public', 'secret_derived')",
        "workflow_plan_v2_reusable_permission_snapshots",
        "workflow_plan_v2_reusable_permission_grants",
        "default_level IN ('none', 'read', 'write')",
        "workflow_plan_v2_reusable_expansion_permissions_exact",
        "workflow_plan_v2_reusable_expansion_permission_reduction",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
    for prohibited in [
        "secret_value",
        "plaintext_secret",
        "decrypted_secret",
        "provider_secret",
    ] {
        assert!(
            !MIGRATION.contains(prohibited),
            "the ledger may retain names but never secret material: {prohibited}"
        );
    }
}

#[test]
fn planning_serializes_with_finalization_and_evidence_is_immutable() {
    for required in [
        "automata_lock_reusable_workflow_expansion_window",
        "workflow_plan_v2_run_result_claims",
        "FOR UPDATE OF marker, run, root",
        "admission_graph_sealed_at_ms IS NOT NULL",
        "workflow_plan_v2_reusable_expansion_window",
        "automata_reject_reusable_workflow_ledger_mutation",
        "workflow_plan_v2_reusable_expansion_immutable",
        "workflow_plan_v2_reusable_catalog_validate_expansion",
        "workflow_plan_v2_reusable_permission_grants_validate_expansion",
        "BEFORE TRUNCATE ON workflow_plan_v2_reusable_workflow_catalog",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
    for prohibited in [
        "DELETE FROM workflow_plan_v2_jobs",
        "DELETE FROM workflow_plan_v2_invocations",
        "DROP TABLE workflow_plan_v2_jobs",
        "admission_graph_sealed_at_ms = NULL",
    ] {
        assert!(
            !MIGRATION.contains(prohibited),
            "migration must preserve and never reopen admitted graphs: {prohibited}"
        );
    }
}
