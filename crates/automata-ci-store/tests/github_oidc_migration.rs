const BASE_MIGRATION: &str = include_str!("../migrations/0033_github_oidc_issuances.sql");
const CURRENT_MIGRATION: &str =
    include_str!("../migrations/0039_github_oidc_signed_currentness.sql");
const RERUN_MIGRATION: &str = include_str!("../migrations/0064_workflow_reruns.sql");
const POSTGRES_ADAPTER: &str = include_str!("../src/postgres/github_oidc.rs");
const JOB_RUNTIME_ADAPTER: &str = include_str!("../src/postgres/github_job_runtime_authority.rs");
const RUNTIME_AUTHORITY_ADAPTER: &str = include_str!("../src/postgres/runtime_authority.rs");

#[test]
fn base_migration_defines_only_the_three_durable_ledgers() {
    for table in [
        "CREATE TABLE github_oidc_authorities",
        "CREATE TABLE github_oidc_issuance_slots",
        "CREATE TABLE github_oidc_key_deadlines",
    ] {
        assert!(BASE_MIGRATION.contains(table), "missing {table}");
    }
    assert_eq!(
        BASE_MIGRATION.matches("CREATE TABLE github_oidc_").count(),
        3
    );
}

#[test]
fn current_only_migration_refuses_unsafe_state_and_joins_the_signed_receipt() {
    for contract in [
        "LOCK TABLE github_oidc_authorities IN ACCESS EXCLUSIVE MODE",
        "LOCK TABLE github_oidc_issuance_slots IN ACCESS EXCLUSIVE MODE",
        "pre-signed-evidence GitHub OIDC state must be explicitly drained",
        "RENAME COLUMN source_evidence_sha256",
        "TO github_run_subject_evidence_sha256",
        "github_oidc_authorities_stable_owner_policy",
        "subject_policy_mode = 'stable_owner_evidence'",
        "github_owner_id > 0",
        "github_oidc_authorities_signed_run_evidence",
        "github_workflow_run_subject_evidence_exact_digest_unique",
        "repository_id, run_id, github_run_subject_evidence_sha256",
        "repository_id, run_id, subject_evidence_sha256",
    ] {
        assert!(CURRENT_MIGRATION.contains(contract), "missing {contract}");
    }
    assert!(!CURRENT_MIGRATION.contains("github_run_subject_evidence_sha256 = job_ir_digest"));
    assert!(!POSTGRES_ADAPTER.contains("source_evidence_sha256"));
}

#[test]
fn reserve_and_every_mint_lock_the_exact_current_execution_and_materialization_receipt() {
    for contract in [
        "attempt.fencing_token = authority.fencing_token",
        "attempt.lease_id = authority.lease_id",
        "attempt.runner_session_id = authority.runner_session_id",
        "attempt.runner_slot = authority.runner_slot",
        "job.admission_epoch = 4",
        "job.job_ir_schema = 5",
        "authority.permission_evidence_sha256 = authority.job_ir_digest",
        "run.plan_schema = 2",
        "invocation.plan_schema = 2",
        "instance.job_ir_version = 5",
        "concrete.runtime_context_schema = 2",
        "concrete.runtime_context_digest = authority.runtime_context_digest",
        "materialization.descriptor_digest = concrete.descriptor_digest",
        "materialization.expected_job_id = concrete.job_id",
        "materialization.expected_attempt_id = concrete.initial_attempt_id",
        "materialization.owner_id = concrete.claim_owner_id",
        "materialization.generation = concrete.claim_generation",
        "materialization.claimed_at_ms = concrete.claim_started_at_ms",
        "materialization.expires_at_ms = concrete.claim_expires_at_ms",
        "materialization.updated_at_ms = concrete.committed_at_ms",
        "materialization.state = 'materialized'",
        "concrete, materialization",
        "session.disconnected_at_ms IS NULL",
    ] {
        assert!(CURRENT_MIGRATION.contains(contract), "missing {contract}");
    }
    assert_eq!(
        CURRENT_MIGRATION
            .matches("JOIN workflow_plan_v2_materialization_claims AS materialization")
            .count(),
        2,
        "currentness and dependency-lock paths must both bind materialization"
    );
    assert!(
        POSTGRES_ADAPTER
            .contains("JOIN workflow_plan_v2_materialization_claims AS materialization")
    );
    assert!(POSTGRES_ADAPTER.contains("materialization, instance"));
    assert!(POSTGRES_ADAPTER.contains("lock_and_observe_current_authority"));
    assert!(POSTGRES_ADAPTER.contains("automata_lock_github_oidc_authority_dependencies"));
}

#[test]
fn provider_currentness_is_descriptor_only_and_exact() {
    for contract in [
        "github_workflow_run_subject_evidence AS subject_evidence",
        "subject_evidence.subject_evidence_sha256 =\n             authority.github_run_subject_evidence_sha256",
        "workflow_admission_receipts AS admission_receipt",
        "admission_receipt.github_subject_evidence_required",
        "github_provider_manifest_current AS current_manifest",
        "manifest.webhook_verifier_fingerprint_sha256",
        "manifest.webhook_verifier_revision",
        "github_server_service_authorities AS checks_authority",
        "checks_authority.service_scope = 'checks_write'",
        "checks_authority.identity_digest",
        "checks_authority.app_configuration_revision",
        "checks_authority.policy_revision",
        "checks_authority.state = 'active'",
        "private_repository_source_read",
        "private_authority.state = 'active'",
    ] {
        assert!(CURRENT_MIGRATION.contains(contract), "missing {contract}");
    }
    for forbidden in [
        "github_server_credential_issuances",
        "credential_expires_at_ms",
        "access_token",
    ] {
        assert!(
            !CURRENT_MIGRATION.contains(forbidden),
            "OIDC currentness must not couple to {forbidden}"
        );
    }
}

#[test]
fn stable_owner_claims_are_store_derived_and_exactly_github_compatible() {
    for claim in [
        "'event_name'",
        "'ref'",
        "'repository'",
        "'repository_owner'",
        "'run_attempt'",
        "'run_number'",
        "'runner_environment'",
        "'sha'",
        "'workflow'",
        "'workflow_ref'",
        "'workflow_sha'",
    ] {
        assert!(CURRENT_MIGRATION.contains(claim), "missing {claim}");
        assert!(
            POSTGRES_ADAPTER.contains(claim.trim_matches('\'')),
            "missing {claim}"
        );
    }
    for forbidden in [
        "'repository_owner_id'",
        "job_workflow_ref",
        "job_workflow_sha",
        "\"actor\"",
    ] {
        assert!(
            !CURRENT_MIGRATION.contains(forbidden),
            "unexpected claim {forbidden}"
        );
    }
    assert!(POSTGRES_ADAPTER.contains("github_oidc_claim_evidence_digest"));
    assert!(POSTGRES_ADAPTER.contains("github_run_subject_evidence_sha256"));
    assert!(POSTGRES_ADAPTER.contains("computed_claim_evidence"));
}

#[test]
fn issuance_uses_fresh_post_lock_authorization_time_and_preserves_key_safety() {
    for contract in [
        ".now_millis()",
        "fresh_observed_at_ms < initial_observed_at_ms",
        "authorized_at_seconds",
        "AuthorizedOidcIssuance::new(",
        "final_authorized_at_seconds",
        "expires_at <= authorized_at_seconds",
        "MAXIMUM_OIDC_KEYS_PER_KEYRING",
        "pg_advisory_xact_lock(hashtextextended($1, $2))",
        "ORDER BY key_use COLLATE \"C\", key_id COLLATE \"C\"",
        "LIMIT 33",
    ] {
        assert!(POSTGRES_ADAPTER.contains(contract), "missing {contract}");
    }
    assert!(BASE_MIGRATION.contains("IF slot_count >= 64"));
    assert!(BASE_MIGRATION.contains("github_oidc_issuance_slot_replacement"));
}

#[test]
fn schema_and_adapter_never_persist_credential_or_token_plaintext() {
    for forbidden in [
        "request_bearer TEXT",
        "request_bearer BYTEA",
        "id_token TEXT",
        "id_token BYTEA",
        "private_key TEXT",
        "private_key BYTEA",
        "jwt TEXT",
        "jwt BYTEA",
    ] {
        assert!(!BASE_MIGRATION.contains(forbidden));
        assert!(!CURRENT_MIGRATION.contains(forbidden));
    }
    assert!(BASE_MIGRATION.contains("request_bearer_sha256 BYTEA NOT NULL"));
    assert!(!POSTGRES_ADAPTER.contains("expose_secret"));
    assert!(!POSTGRES_ADAPTER.contains("private_key_pem"));
}

#[test]
fn rerun_origin_keeps_current_authority_private_source_and_child_permission_checks() {
    for contract in [
        "origin.origin_kind IN ('scheduled_fire', 'workflow_rerun')",
        "origin.admission_idempotency_kind = 'operation'",
        "checks_authority.state = 'active'",
        "automata_workflow_plan_v2_invocation_published",
        "automata_reusable_workflow_oidc_permission_authorized",
        "private_repository_source_read",
        "authority.state = 'active'",
    ] {
        assert!(POSTGRES_ADAPTER.contains(contract), "missing {contract}");
    }
    for adapter in [JOB_RUNTIME_ADAPTER, RUNTIME_AUTHORITY_ADAPTER] {
        assert!(adapter.contains("github_manifest_origin_is_closed"));
        assert!(adapter.contains("private_repository_source_read"));
        assert!(adapter.contains("authority.state = 'active'"));
    }
    for contract in [
        "'provider_delivery', 'scheduled_fire', 'workflow_rerun'",
        "automata_workflow_plan_v2_invocation_published",
        "automata_reusable_workflow_oidc_permission_authorized",
    ] {
        assert!(RERUN_MIGRATION.contains(contract), "missing {contract}");
    }
    assert!(JOB_RUNTIME_ADAPTER.contains("checks_authority.state = 'active'"));
    assert!(JOB_RUNTIME_ADAPTER.contains("automata_workflow_plan_v2_invocation_published"));
}
