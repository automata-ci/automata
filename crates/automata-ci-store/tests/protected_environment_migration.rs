const MIGRATION: &str = include_str!("../migrations/0064_protected_environment_variables.sql");
const POSTGRES_ADAPTER: &str = include_str!("../src/postgres/protected_environment.rs");
const REUSABLE_ADMISSION_ADAPTER: &str =
    include_str!("../src/postgres/reusable_workflow_admission.rs");
const REUSABLE_RUNTIME_ADAPTER: &str = include_str!("../src/postgres/reusable_workflow_runtime.rs");

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
fn reusable_child_credentials_are_classified_before_publication() {
    for required in [
        "ALTER TABLE workflow_plan_v2_reusable_expanded_jobs",
        "environment_requirement_kind TEXT NOT NULL DEFAULT 'unclassified'",
        "reusable_expanded_jobs_environment_shape",
        "reusable_expanded_jobs_reference_limits",
        "reusable_expanded_jobs_credential_schema",
        "workflow_plan_v2_reusable_jobs_credential_requirements_validate",
        "automata_require_exact_reusable_child_credentials_at_seal",
        "planned.environment_requirement_kind = 'unclassified'",
        "active.environment_requirement_kind IS DISTINCT FROM",
        "active.environment_template_digest IS DISTINCT FROM",
        "active.secret_reference_names IS DISTINCT FROM",
        "active.variable_reference_names IS DISTINCT FROM",
        "active.credential_requirements_schema IS DISTINCT FROM",
        "workflow_plan_v2_reusable_call_credential_requirements_exact",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing reusable credential invariant: {required}"
        );
    }
    for required in [
        "job.credential_requirements().environment().kind()",
        "job.credential_requirements().secret_names()",
        "job.credential_requirements().variable_names()",
    ] {
        assert!(
            REUSABLE_ADMISSION_ADAPTER.contains(required),
            "reusable admission drops credential evidence: {required}"
        );
    }
    for required in [
        "planned.environment_requirement_kind",
        "planned.environment_template_digest",
        "planned.secret_reference_names",
        "planned.variable_reference_names",
        "planned.credential_requirements_schema",
    ] {
        assert!(
            REUSABLE_RUNTIME_ADAPTER.contains(required),
            "reusable publication drops credential evidence: {required}"
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
        "0064 must not introduce an administrative approval bypass"
    );
    assert!(
        !MIGRATION.contains("administrative_rejection"),
        "0064 must not introduce an administrative rejection bypass"
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
        "concrete.runtime_context_digest",
        "attempt.lifecycle = 'queued'",
        "FOR UPDATE OF gate, attempt",
        "verify_runtime_context(&gate, request.activation_context_digest().as_bytes())?;",
        "load_prepare_replay(&mut transaction, &gate, request.tenant()).await?;",
        "verify_prepare_replay(&stored, &request, requested_by_principal_id)?;",
        ".bind(gate.attempt_id)",
        "automata_job_variable_binding_digest",
        "automata_job_secret_selection_digest",
        "automata_secret_is_available_to_gate",
        "state.as_deref() != Some(\"ready\")",
        "selected_names.iter().collect::<BTreeSet<_>>() != supplied_names.iter().collect()",
        "authority_digest = $3 AND authority_digest_key_id = $4",
        "issued_at_ms = $5 AND expires_at_ms = $6",
        "automata_job_secret_binding_digest($1,$2,$3,$4,$5,$6)",
        ".bind(request.lease_id().as_uuid())",
        "request.fencing_token().get()",
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
        "InspectLeasedJobSecretBindings",
        "IssuedLeasedJobSecretBinding",
        "if state != \"ready\"",
        "lifecycle != \"leased\"",
        "lease_id != Some(request.lease_id().as_uuid())",
        "stored_fence != fence",
        "lease_issued_at != Some(request.issued_at().get())",
        "lease_expires_at.is_none_or(|expiry| request.expires_at().get() > expiry)",
        "automata_protected_environment_approval_is_current",
        "secret_selection_permission_allows_issue",
        "selection.binding_digest IS NOT DISTINCT FROM",
        "automata_secret_is_available_to_gate(secret, policy, current_gate)",
        "version.storage_kind = 'built_in_ciphertext'",
        "let grant_id = deterministic_grant_id(",
        "let authority_digest = deterministic_grant_authority_digest(",
        "environment_approval_request_id",
        "authority_digest_key_id",
        "leased-job-secret-grant-v1",
        "let binding_exact: bool",
        "grant_id = $4 AND lease_id = $5 AND fencing_token = $6",
        "binding_digest IS NOT DISTINCT FROM",
        "SecretBinding::new(grant_id.hyphenated().to_string())",
        "with_version_id(version_id.hyphenated().to_string())",
        "!matches!(lifecycle.as_str(), \"leased\" | \"preparing\" | \"running\")",
        "runner_id != Some(lease.runner_id().as_uuid())",
        "binding.lease_id = $3",
        "binding.fencing_token = $4",
        "grant.lease_id = $3",
        "grant.fencing_token = $4",
        "grant.issued_at_ms = $5",
        "grant.expires_at_ms = $6",
        "grant.status = 'active'",
        "issued != expected || rows.len() != expected",
    ] {
        assert!(
            POSTGRES_ADAPTER.contains(required),
            "missing server-owned lease issuance guard: {required}"
        );
    }
    for prohibited in ["secret_value", "credential_value"] {
        assert!(
            !POSTGRES_ADAPTER.contains(prohibited),
            "issuer must not accept, persist, or project {prohibited}"
        );
    }
}
