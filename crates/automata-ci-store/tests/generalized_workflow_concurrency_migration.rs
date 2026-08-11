const MIGRATION: &str = include_str!("../migrations/0050_generalized_workflow_concurrency.sql");

#[test]
fn generalized_queue_is_ordered_repository_scoped_and_distinct_from_running() {
    for required in [
        "CREATE TABLE concurrency_group_pending_runs",
        "UNIQUE (run_id)",
        "FOREIGN KEY (repository_id, normalized_key)",
        "FOREIGN KEY (repository_id, run_id)",
        "queue_sequence BIGINT GENERATED ALWAYS AS IDENTITY",
        "repository_id, normalized_key, queue_sequence",
        "automata_validate_concurrency_pending_run",
        "automata_validate_concurrency_running_run",
        "DROP COLUMN pending_run_id",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing queue invariant: {required}"
        );
    }
}

#[test]
fn queue_policy_and_logical_preemption_evidence_are_retained_exactly() {
    for required in [
        "concurrency_queue_policy IN ('single', 'max')",
        "automata_enforce_workflow_concurrency_policy_immutable",
        "CREATE TABLE workflow_plan_v2_concurrency_cancellations",
        "workflow_plan_v2_concurrency_cancellation_exact",
        "prior_workflow_updated_at_ms",
        "prior_marker_revision",
        "prior_invocation_revision",
        "cancelled_at_ms",
        "workflow_plan_v2_concurrency_cancellation_immutable",
        "NEW.state = 'cancelled'",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing cancellation invariant: {required}"
        );
    }
}

#[test]
fn migration_does_not_discard_runs_or_orchestration_evidence() {
    for forbidden in [
        "DELETE FROM workflow_runs",
        "DELETE FROM workflow_plan_v2_runs",
        "DELETE FROM workflow_plan_v2_jobs",
        "DROP TABLE workflow_plan_v2",
    ] {
        assert!(
            !MIGRATION.contains(forbidden),
            "migration must retain durable evidence: {forbidden}"
        );
    }
}
