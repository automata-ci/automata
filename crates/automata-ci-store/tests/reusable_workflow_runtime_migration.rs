const MIGRATION: &str = include_str!("../migrations/0055_reusable_workflow_runtime.sql");
const AUTHORITY_MIGRATION: &str =
    include_str!("../migrations/0063_reusable_workflow_runtime_authority.sql");

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_0055_is_embedded_after_the_planning_ledger() {
    let planning = MIGRATOR
        .iter()
        .find(|migration| migration.version == 51)
        .expect("migration 0051 is embedded");
    let runtime = MIGRATOR
        .iter()
        .find(|migration| migration.version == 55)
        .expect("migration 0055 is embedded");
    assert_eq!(planning.description.as_ref(), "reusable workflow expansion");
    assert_eq!(runtime.description.as_ref(), "reusable workflow runtime");
}

#[test]
fn publication_is_inert_fenced_and_exactly_sealed() {
    for required in [
        "workflow_plan_v2_reusable_call_publications",
        "workflow_plan_v2_reusable_call_publication_window",
        "workflow_plan_v2_reusable_call_graph_exact",
        "caller.activation_fence = durable.activation_generation",
        "caller.activation_input_digest = durable.activation_input_digest",
        "authority_profile = 'credential_free'",
        "publication.child_graph_sealed_at_ms IS NULL",
        "workflow_plan_v2_reusable_expanded_jobs",
        "workflow_plan_v2_reusable_expanded_dependencies",
        "runtime_context_object_key",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
    for prohibited in [
        "INSERT INTO jobs",
        "INSERT INTO workflow_plan_v2_instances",
        "admission_graph_sealed_at_ms = NULL",
    ] {
        assert!(
            !MIGRATION.contains(prohibited),
            "publication must remain non-runnable: {prohibited}"
        );
    }
}

#[test]
fn caller_output_aliases_have_a_one_way_insert_seal() {
    for required in [
        "workflow_plan_v2_reusable_call_output_contracts",
        "mapping_count INTEGER NOT NULL",
        "mapping_digest BYTEA NOT NULL",
        "workflow_plan_v2_reusable_output_contracts_validate",
        "workflow_plan_v2_reusable_output_mappings_validate",
        "workflow_plan_v2_reusable_call_output_contract_exact",
        "mapping.sensitivity = 'public'",
        "callee.sensitivity = 'secret_derived'",
        "workflow_plan_v2_reusable_output_contracts_reject_mutation",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
}

#[test]
fn completion_consumes_exact_child_results_and_declared_outputs() {
    for required in [
        "workflow_plan_v2_reusable_call_results",
        "workflow_plan_v2_reusable_call_result_jobs",
        "workflow_plan_v2_reusable_call_result_outputs",
        "workflow_output_evaluation_digest BYTEA NOT NULL",
        "child.plan_digest = NEW.callee_plan_digest",
        "child_claim.state = 'finalized'",
        "declared.output_key = output.callee_output_name",
        "declared.sensitivity = output.sensitivity",
        "workflow_plan_v2_reusable_call_result_conclusion",
        "workflow_plan_v2_reusable_call_result_immutable",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
}

#[test]
fn reusable_completion_enters_the_existing_needs_and_run_result_model_once() {
    for required in [
        "CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_job_result_claim",
        "job.execution_kind = 'reusable_workflow'",
        "call_result.parent_result_descriptor_digest = NEW.descriptor_digest",
        "call_result.parent_instances_digest = NEW.instances_digest",
        "call_result.parent_prerequisites_digest = NEW.prerequisites_digest",
        "call_result.parent_outputs_digest = NEW.outputs_digest",
        "call_result.parent_commit_digest = NEW.commit_digest",
        "mapping.parent_output_name = NEW.output_name",
        "child_output.callee_output_name =",
        "OLD.invocation_kind = 'reusable'",
        "workflow_plan_v2_reusable_results_freeze_for_run_result",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
}

#[test]
fn migration_0063_binds_child_authority_to_publication_and_permission_evidence() {
    let authority = MIGRATOR
        .iter()
        .find(|migration| migration.version == 63)
        .expect("migration 0063 is embedded");
    assert_eq!(
        authority.description.as_ref(),
        "reusable workflow runtime authority"
    );
    for required in [
        "automata_workflow_plan_v2_invocation_published",
        "automata_reusable_workflow_oidc_permission_authorized",
        "publication.permission_digest = planned.permission_digest",
        "permission_snapshot.permission_digest = planned.permission_digest",
        "id_token_grant.permission_name = 'id-token'",
        ") = 'write'",
        "origin.root_invocation_id = marker.root_invocation_id",
        "invocation.plan_digest = authority.plan_digest",
        "automata_validate_logical_preparation_base_context",
        "publication.runtime_context_digest =",
        "github_workflow_run_manifest_origins AS origin",
        "origin.admission_idempotency_kind",
        "automata_github_runtime_authority_has_v3_provenance",
        "automata_validate_github_runtime_authority_v3_identity",
        "automata_github_oidc_authority_is_current",
        "automata_require_standard_github_oidc_profile",
        "automata_lock_github_oidc_authority_dependencies",
        "origin.subject_evidence_sha256",
        "origin.private_source_authority_identity_digest",
        "origin.private_source_authority_app_configuration_revision",
        "origin.private_source_authority_policy_revision",
        "private_authority.service_scope = 'private_repository_source_read'",
        "admission.idempotency_kind = origin.admission_idempotency_kind",
        "origin.origin_kind = 'scheduled_fire'",
    ] {
        assert!(
            AUTHORITY_MIGRATION.contains(required),
            "missing child authority invariant: {required}"
        );
    }
    assert!(
        !AUTHORITY_MIGRATION.contains("github_workflow_run_subject_evidence AS")
            && !AUTHORITY_MIGRATION.contains("github_provider_delivery_evidence AS"),
        "migration 0063 must consume only the closed run-origin projection"
    );
}

#[test]
fn migration_0063_idle_reconciliation_uses_the_execution_visibility_predicate() {
    for required in [
        "CREATE OR REPLACE FUNCTION automata_validate_activation_work_selection_transition",
        "CREATE OR REPLACE FUNCTION automata_validate_materialization_work_selection_transition",
        "marker.run_id, invocation.id",
        "workflow_activation_selection_receipt_exact",
        "workflow_materialization_selection_receipt_exact",
    ] {
        assert!(
            AUTHORITY_MIGRATION.contains(required),
            "missing child reconciliation invariant: {required}"
        );
    }
    assert!(
        !AUTHORITY_MIGRATION.contains("AND invocation.id = marker.root_invocation_id"),
        "idle reconciliation must not silently exclude sealed children"
    );
}
