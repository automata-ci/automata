const MIGRATION: &str =
    include_str!("../migrations/0028_workflow_plan_v2_dependent_activation_preparation.sql");

#[test]
fn migration_pins_exact_evidence_and_replaces_the_root_only_guards() {
    for required in [
        "workflow_plan_v2_activation_preparation_claims",
        "workflow_plan_v2_activation_preparation_prerequisites",
        "workflow_plan_v2_activation_preparation_outputs",
        "workflow_plan_v2_activation_preparations",
        "result_claim.state = 'finalized'",
        "output.public_value IS NOT DISTINCT FROM NEW.public_value",
        "preparation.activation_input_digest = NEW.activation_input_digest",
        "CREATE OR REPLACE FUNCTION automata_enforce_workflow_plan_v2_activation_input()",
        "CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_activation_publication()",
        "invocation.id = marker.root_invocation_id",
        "base_context_kind = 'root_empty'",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
    assert!(!MIGRATION.contains(
        "NOT EXISTS (\n              SELECT 1\n              FROM workflow_plan_v2_dependencies"
    ));
}

#[test]
fn migration_keeps_secret_derived_outputs_value_free_and_evidence_immutable() {
    for required in [
        "sensitivity = 'secret_derived' AND public_value IS NULL",
        "logical activation preparation evidence is immutable",
        "bound logical activation preparation is immutable",
        "logical activation preparation claim is durable",
        "logical activation preparation pin set is incomplete",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
    for prohibited in ["secret_value", "plaintext_secret", "legacy_preparation"] {
        assert!(!MIGRATION.contains(prohibited));
    }
}
