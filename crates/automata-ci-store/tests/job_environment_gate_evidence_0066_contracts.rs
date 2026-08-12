const MIGRATION: &str = include_str!("../migrations/0066_job_environment_gate_evidence.sql");

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
        "REFERENCES workflow_plan_v2_instances(id) ON DELETE CASCADE",
        "environment_normalized_name TEXT COLLATE \"C\"",
        "event_trust TEXT NOT NULL",
        "source_kind TEXT NOT NULL",
        "reusable_secret_permission TEXT NOT NULL",
        "created_at_ms BIGINT NOT NULL",
    ] {
        assert!(table.contains(column), "missing evidence column: {column}");
    }
    assert!(
        !table.contains("DEFERRABLE"),
        "the instance must be inserted before its evidence row"
    );
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
        "instance.invocation_id = root_invocation",
        "cardinality(logical_job.secret_reference_names) > 0",
        "cardinality(logical_job.secret_reference_names) = 0",
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
fn reusable_secret_authority_requires_an_exact_recursive_identity_chain() {
    for required in [
        "CREATE FUNCTION automata_reusable_secret_identity_chain_is_exact(",
        "current_invocation_id UUID := target_invocation_id",
        "current_invocation_id = ANY(visited_invocations)",
        "expansion.parent_invocation_id, expansion.depth",
        "OR expected_depth IS NOT NULL AND current_depth <> expected_depth",
        "AND upper(binding.target_name) = target_canonical_name",
        "WHERE upper(binding.source_name) = target_canonical_name",
        "matching_target_count <> 1 OR same_name_source_count <> 1",
        "expected_depth := current_depth - 1",
        "current_invocation_id := parent_invocation_id",
        "FROM unnest(logical_job.secret_reference_names) AS referenced_secret(name)",
        "WHERE NOT automata_reusable_secret_identity_chain_is_exact(",
        "CREATE OR REPLACE FUNCTION automata_secret_is_available_to_gate",
        "AND automata_reusable_secret_identity_chain_is_exact(",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing recursive identity-chain invariant: {required}"
        );
    }
}

#[test]
fn legacy_reusable_secret_bindings_remain_unmodified() {
    for forbidden in [
        "workflow_plan_v2_reusable_secret_targets_canonicalizable",
        "workflow_plan_v2_reusable_secret_targets_casefold_unique",
        "ALTER TABLE workflow_plan_v2_reusable_secret_bindings",
    ] {
        assert!(
            !MIGRATION.contains(forbidden),
            "0066 must not globally constrain retained reusable bindings: {forbidden}"
        );
    }
}

#[test]
fn every_new_activation_instance_requires_evidence_by_commit() {
    let trigger = MIGRATION
        .split_once("CREATE FUNCTION automata_require_job_environment_activation_evidence()")
        .expect("commit-time evidence function")
        .1;
    for required in [
        "WHERE instance.id = NEW.id",
        "WHERE evidence.instance_id = NEW.id",
        "workflow_plan_v2_instances_environment_evidence_required",
        "CREATE CONSTRAINT TRIGGER workflow_plan_v2_instances_require_environment_evidence",
        "AFTER INSERT ON workflow_plan_v2_instances",
        "DEFERRABLE INITIALLY DEFERRED",
        "EXECUTE FUNCTION automata_require_job_environment_activation_evidence()",
    ] {
        assert!(
            trigger.contains(required),
            "missing commit-time evidence invariant: {required}"
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
