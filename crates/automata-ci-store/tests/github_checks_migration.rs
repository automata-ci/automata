const MIGRATION: &str = include_str!("../migrations/0029_github_checks_projection.sql");

#[test]
fn migration_is_current_only_and_credential_free() {
    for prohibited in [
        "ALTER TABLE github_check_subjects",
        "legacy",
        "access_token",
        "authorization_header",
        "encrypted_payload",
        "workflow_runs.status",
        "job_attempts.lifecycle",
    ] {
        assert!(
            !MIGRATION.contains(prohibited),
            "unexpected compatibility, credential, or inferred-state surface: {prohibited}"
        );
    }
}

#[test]
fn migration_retains_exact_identity_and_uncertain_create_state() {
    for required in [
        "github_check_subjects_delivery_key_unique",
        "external_id = 'automata-check:' || id::TEXT",
        "github_check_subjects_authority_exact",
        "github_check_subjects_run_exact",
        "github_check_subjects_terminal_mapping",
        "provider_unknown' THEN desired_conclusion = 'action_required'",
        "system_unknown' THEN desired_conclusion = 'failure'",
        "create_indeterminate",
        "create_issue_expires_at_ms",
        "next_reconcile_at_ms",
        "reconcile_run_create",
        "github_check_projection_create_fence_exact",
        "github_check_projection_create_evidence_immutable",
        "github_check_projection_next_reconcile_exact",
        "github_check_projection_delivery_exact",
        "github_check_projection_external_run_unique",
        "ambiguous_create",
        "FOR SHARE",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
}
