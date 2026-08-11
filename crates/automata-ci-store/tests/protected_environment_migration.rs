const MIGRATION: &str = include_str!("../migrations/0062_protected_environment_variables.sql");
const POSTGRES_ADAPTER: &str = include_str!("../src/postgres/protected_environment.rs");

#[test]
fn migration_rejects_ambiguous_credential_arrays_and_unclassified_activation() {
    for required in [
        "array_ndims(NEW.secret_reference_names)",
        "array_lower(NEW.secret_reference_names, 1)",
        "array_position(NEW.secret_reference_names, NULL)",
        "array_ndims(NEW.variable_reference_names)",
        "array_lower(NEW.variable_reference_names, 1)",
        "array_position(NEW.variable_reference_names, NULL)",
        "secret references must be sorted unique canonical names",
        "variable references must be sorted unique canonical names",
        "workflow_plan_v2_jobs_credential_requirements_classified",
        "workflow_plan_v2_runs_credential_requirements_classified",
        "job_attempts_cancel_pending_environment_gate",
        "workload_cancelled",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
}

#[test]
fn migration_proves_current_reviewer_threshold_and_has_no_administrative_bypass() {
    for required in [
        "automata_principal_has_repository_permission",
        "environments:approve",
        "environments:manage",
        "repository_environment_reviewers_current",
        "protected_environment_approval_decisions_authorized",
        "protected_environment_approval_threshold_proven",
        "protected_environment_approval_rejection_proven",
        "protected_environment_approval_decisions_self_review",
        "request.requested_by_principal_id",
        "request.prevent_self_review",
        "approval_threshold_met",
        "approval_rejected",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
    assert!(
        !MIGRATION.contains("administrative_approval"),
        "0062 must not introduce an administrative approval bypass"
    );
    assert!(
        !MIGRATION.contains("administrative_rejection"),
        "0062 must not introduce an administrative rejection bypass"
    );
}

#[test]
fn migration_uses_nonkeyword_workload_authority_aliases() {
    assert!(
        !MIGRATION.contains(" AS grant"),
        "GRANT is a SQL keyword and must not be used as an alias"
    );
    assert!(MIGRATION.contains("AS workload_grant"));
}

#[test]
fn adapter_keeps_gate_workflow_value_free_and_lease_fenced() {
    for required in [
        "runtime_context_digest",
        "attempt.lifecycle = 'queued'",
        "load_prepare_replay(&mut transaction, &gate, request.tenant())",
        "verify_prepare_replay(&stored, &request)?",
        ".bind(gate.attempt_id)",
        "automata_job_variable_binding_digest",
        "automata_job_secret_selection_digest",
        "automata_job_secret_binding_digest",
        "fencing_token",
        "lease_id",
        "authority_digest_key_id",
    ] {
        assert!(
            POSTGRES_ADAPTER.contains(required),
            "missing adapter guard: {required}"
        );
    }
    for prohibited in ["secret_value", "credential_value"] {
        assert!(
            !POSTGRES_ADAPTER.contains(prohibited),
            "adapter must not persist or project {prohibited}"
        );
    }
}

#[test]
fn adapter_issues_only_server_derived_name_only_lease_bindings() {
    for required in [
        "IssueLeasedJobSecretGrants",
        "IssuedLeasedJobSecretBinding",
        "lifecycle != \"leased\"",
        "automata_protected_environment_approval_is_current",
        "automata_secret_is_available_to_gate",
        "built_in_ciphertext",
        "job_secret_bindings",
        "leased-job-secret-grant-v1",
        "deterministic_grant_id",
        "SecretBinding::new",
    ] {
        assert!(
            POSTGRES_ADAPTER.contains(required),
            "missing server-owned lease issuance guard: {required}"
        );
    }
    for prohibited in ["secret_value", "credential_value"] {
        assert!(
            !POSTGRES_ADAPTER.contains(prohibited),
            "issuer must not accept or persist {prohibited}"
        );
    }
}
