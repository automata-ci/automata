static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
const MIGRATION: &str = include_str!("../migrations/0066_job_environment_gate_evidence.sql");

#[test]
fn migration_0066_is_embedded_after_resource_policy_v2() {
    let migrations = MIGRATOR.iter().collect::<Vec<_>>();
    let index = migrations
        .iter()
        .position(|migration| migration.version == 66)
        .expect("migration 0066 is embedded");
    assert_eq!(migrations[index - 1].version, 65);
    assert_eq!(
        migrations[index].description.as_ref(),
        "job environment gate evidence"
    );
}

#[test]
fn upgrade_guard_serializes_exact_state_and_refuses_only_live_instances() {
    let table_offset = MIGRATION
        .find("CREATE TABLE workflow_plan_v2_job_environment_evidence")
        .expect("evidence table declaration");
    let guard = &MIGRATION[..table_offset];
    for required in [
        "LOCK TABLE workflow_runs, workflow_plan_v2_instances\n    IN ACCESS EXCLUSIVE MODE",
        "FROM workflow_plan_v2_instances AS instance",
        "JOIN workflow_runs AS run ON run.id = instance.run_id",
        "WHERE run.status IN ('queued', 'in_progress')",
        "ERRCODE = 'check_violation'",
        "job_environment_evidence_active_legacy_instances",
    ] {
        assert!(
            guard.contains(required),
            "missing upgrade invariant: {required}"
        );
    }
    assert!(
        !guard.contains("workflow_plan_v2_activation_publications"),
        "active zero-instance publications must remain upgradeable"
    );
}

#[test]
fn evidence_schema_is_value_free_and_exact() {
    let table = MIGRATION
        .split_once("CREATE TABLE workflow_plan_v2_job_environment_evidence (")
        .expect("evidence table declaration")
        .1
        .split_once("\n);")
        .expect("evidence table terminator")
        .0;
    for column in [
        "instance_id UUID PRIMARY KEY",
        "environment_normalized_name TEXT COLLATE \"C\"",
        "event_trust TEXT NOT NULL",
        "source_kind TEXT NOT NULL",
        "reusable_secret_permission TEXT NOT NULL",
        "created_at_ms BIGINT NOT NULL",
    ] {
        assert!(table.contains(column), "missing evidence column: {column}");
    }
    for forbidden in [
        "secret_value",
        "variable_value",
        "plaintext",
        "ciphertext",
        "bearer",
        "access_token",
    ] {
        assert!(
            !table.to_ascii_lowercase().contains(forbidden),
            "evidence table must not persist {forbidden}"
        );
    }
}

#[test]
fn evidence_is_exact_append_only_and_replay_authenticated() {
    for required in [
        "automata_validate_job_environment_activation_evidence",
        "workflow_plan_v2_job_environment_evidence_validate",
        "job_environment_evidence_source_trust",
        "job_environment_evidence_exact",
        "workflow_plan_v2_reusable_secret_bindings",
        "instance.invocation_id = root_invocation",
        "has_reusable_secret_binding",
        "automata_reject_job_environment_evidence_mutation",
        "workflow_plan_v2_job_environment_evidence_append_only",
        "workflow_plan_v2_job_environment_evidence_no_truncate",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
}

#[test]
fn reusable_secret_evidence_tracks_the_selected_job_secret_count() {
    for required in [
        "cardinality(logical_job.secret_reference_names) > 0",
        "FROM unnest(logical_job.secret_reference_names) AS referenced_secret(name)",
        "workflow_plan_v2_reusable_secret_targets_casefold_unique",
        "AND upper(binding.target_name) = referenced_secret.name",
        "NOT all_reusable_secret_references_bound\n               OR NEW.reusable_secret_permission <> 'explicit'",
        "cardinality(logical_job.secret_reference_names) = 0",
        "NEW.reusable_secret_permission <> 'none'",
        "CREATE OR REPLACE FUNCTION automata_secret_is_available_to_gate",
        "AND upper(binding.target_name) = (target_secret).canonical_name",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing selected-secret invariant: {required}"
        );
    }
}

#[test]
fn database_rejects_variable_bearing_lease_bypass_without_custody() {
    for required in [
        "automata_reject_job_variable_lease_without_custody",
        "OLD.lifecycle = 'queued'",
        "NEW.lifecycle = 'leased'",
        "cardinality(logical_job.variable_reference_names) > 0",
        "job_attempts_variable_custody_required",
        "job_attempts_00_require_variable_custody_before_lease",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
    assert!(
        !MIGRATION.contains("CREATE TABLE job_variable_custody_receipts"),
        "0066 must fail closed rather than inventing durable value custody"
    );
}
