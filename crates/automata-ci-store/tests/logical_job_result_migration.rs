const MIGRATION_SQL: &str = include_str!("../migrations/0025_workflow_plan_v2_job_results.sql");
const DUE_MIGRATION_SQL: &str =
    include_str!("../migrations/0038_logical_result_projection_due.sql");
const JOB_RESULT_POSTGRES_ADAPTER: &str = include_str!("../src/postgres/logical_job_result.rs");

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_0025_is_embedded_as_the_current_logical_result_phase() {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 25)
        .expect("migration 0025 is embedded");
    assert_eq!(
        migration.description.as_ref(),
        "workflow plan v2 job results"
    );
    for table in [
        "workflow_plan_v2_job_terminal_counters",
        "workflow_plan_v2_job_result_claims",
        "workflow_plan_v2_job_results",
        "workflow_plan_v2_job_result_instances",
        "workflow_plan_v2_job_result_prerequisites",
        "workflow_plan_v2_job_result_outputs",
    ] {
        assert!(
            MIGRATION_SQL.contains(&format!("CREATE TABLE {table}")),
            "migration must create {table}"
        );
    }
}

#[test]
fn terminal_order_is_server_assigned_without_touching_the_g1_writer() {
    for required in [
        "AFTER INSERT ON attempt_terminal_results",
        "automata_assign_workflow_plan_v2_terminal_ordinal",
        "ON CONFLICT (logical_job_id) DO UPDATE",
        "last_ordinal = workflow_plan_v2_job_terminal_counters.last_ordinal + 1",
        "BEFORE INSERT OR UPDATE ON workflow_plan_v2_job_terminal_counters",
        "pg_trigger_depth() <= 1",
        "terminal order must not be supplied by a writer",
        "workflow_plan_v2_terminal_ordinal",
        "UNIQUE (logical_job_id, terminal_ordinal)",
        "WorkflowPlan-v2 terminal ordinal evidence is immutable",
    ] {
        assert!(
            MIGRATION_SQL.contains(required),
            "migration lost terminal-order invariant: {required}"
        );
    }
    assert!(!MIGRATION_SQL.contains("DEFAULT 1"));
    assert!(!MIGRATION_SQL.contains("max(workflow_plan_v2_terminal_ordinal)"));
}

#[test]
fn claim_and_commit_pin_complete_current_aggregation_evidence() {
    for required in [
        "state IN ('aggregating', 'finalized')",
        "expires_at_ms - claimed_at_ms <= 900000",
        "publication.instance_count = 0",
        "workflow_plan_v2_instance_results",
        "instance_claim.state = 'finalized'",
        "workflow_plan_v2_dependencies",
        "prerequisite_claim.state = 'finalized'",
        "application/vnd.automata.workflow-plan+json",
        "plan_schema = 2",
        "instance_descriptor_digest",
        "instance_outputs_digest",
        "instance_commit_digest",
        "closure_has_failure",
        "closure_has_cancelled",
        "closure_has_skipped",
        "public_value IS NOT NULL",
        "sensitivity = 'secret_derived' AND public_value IS NULL",
        "WorkflowPlan-v2 logical-job result evidence is immutable",
    ] {
        assert!(
            MIGRATION_SQL.contains(required),
            "migration lost logical-result invariant: {required}"
        );
    }
    assert!(!MIGRATION_SQL.contains("plan_schema IN"));
    assert!(!MIGRATION_SQL.contains("legacy"));
}

#[test]
fn migration_0038_is_embedded_as_the_current_autonomous_projection_phase() {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 38)
        .expect("migration 0038 is embedded");
    assert_eq!(
        migration.description.as_ref(),
        "logical result projection due"
    );
}

#[test]
fn projection_replay_horizons_use_a_bounded_authoritative_database_clock() {
    for required in [
        "WITH authoritative_clock AS MATERIALIZED",
        "floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
        "NEW.replay_floor_ms < OLD.replay_floor_ms",
        "NEW.updated_at_ms < OLD.updated_at_ms",
        "NEW.replay_floor_ms > NEW.updated_at_ms",
        "NEW.updated_at_ms > authoritative_now_ms",
        "60000, NEW.updated_at_ms - OLD.updated_at_ms",
        "workflow_plan_v2_result_selection_replay_horizons_advance",
    ] {
        assert!(
            DUE_MIGRATION_SQL.contains(required),
            "due migration lost its replay-horizon boundary: {required}"
        );
    }
    assert!(
        !DUE_MIGRATION_SQL.contains("VALUES ('instance', 0, 0), ('job', 0, 0)"),
        "a bounded horizon cannot bootstrap from the Unix epoch"
    );
}

#[test]
fn job_selector_has_indexed_quarantine_aware_due_support() {
    for required in [
        "CREATE INDEX workflow_plan_v2_job_result_due_next",
        "available_at_ms, ready_at_ms, run_id, invocation_id,",
        "source_order, logical_job_id",
        "logical_job_id UUID PRIMARY KEY",
    ] {
        assert!(
            DUE_MIGRATION_SQL.contains(required),
            "due migration lost job-selector support: {required}"
        );
    }

    let selector = JOB_RESULT_POSTGRES_ADAPTER
        .split_once("async fn lock_next_target(")
        .expect("job selector function")
        .1
        .split_once("async fn lock_due_target(")
        .expect("bounded job selector function")
        .0;
    for required in [
        "FROM workflow_plan_v2_job_result_due",
        "FROM workflow_plan_v2_job_result_quarantines AS quarantine",
        "quarantine.logical_job_id =",
        "FOR UPDATE SKIP LOCKED",
    ] {
        assert!(
            selector.contains(required),
            "job selector must skip target-keyed quarantine ledgers: {required}"
        );
    }
}

#[test]
fn due_migration_retains_terminal_order_and_dependency_sources() {
    for table in [
        "workflow_plan_v2_job_terminal_counters",
        "workflow_plan_v2_dependencies",
    ] {
        assert!(
            DUE_MIGRATION_SQL.contains(&format!(
                "BEFORE DELETE ON {table} FOR EACH ROW\nEXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal()"
            )),
            "due migration must reject row removal and parent cascades for {table}"
        );
        assert!(
            DUE_MIGRATION_SQL.contains(&format!(
                "BEFORE TRUNCATE ON {table} FOR EACH STATEMENT\nEXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal()"
            )),
            "due migration must reject truncate cascades for {table}"
        );
    }
}

#[test]
fn job_quarantine_is_target_keyed_fenced_and_immutable() {
    for required in [
        "CREATE TABLE workflow_plan_v2_job_result_quarantines",
        "logical_job_id UUID PRIMARY KEY",
        "'relational_evidence', 'object_evidence', 'payload_evidence'",
        "claim_owner_id IS NULL",
        "claim_descriptor_digest IS NULL",
        "quarantined_at_ms >= ready_at_ms",
        "quarantined_at_ms >= claim_claimed_at_ms",
        "claim.expires_at_ms = NEW.claim_expires_at_ms",
        "claim.descriptor_digest = NEW.claim_descriptor_digest",
        "claim.state = 'aggregating'",
        "FROM workflow_plan_v2_job_result_due AS due",
        "FOR UPDATE",
        "workflow_plan_v2_job_result_quarantines_due_exact",
        "workflow_plan_v2_job_result_quarantines_claim_exact",
        "NEW.quarantined_at_ms :=",
        "BEFORE UPDATE ON workflow_plan_v2_job_result_quarantines",
        "BEFORE DELETE ON workflow_plan_v2_job_result_quarantines",
        "BEFORE TRUNCATE ON workflow_plan_v2_job_result_quarantines",
    ] {
        assert!(
            DUE_MIGRATION_SQL.contains(required),
            "due migration lost its job quarantine boundary: {required}"
        );
    }

    let definition = DUE_MIGRATION_SQL
        .split_once("CREATE TABLE workflow_plan_v2_job_result_quarantines")
        .expect("job quarantine table")
        .1
        .split_once("CREATE FUNCTION automata_validate_workflow_plan_v2_instance_result_quarantine")
        .expect("bounded job quarantine table")
        .0;
    for required in [
        "REFERENCES workflow_plan_v2_jobs(run_id, invocation_id, id)",
        "ON DELETE RESTRICT",
        "AND quarantined_at_ms >= available_at_ms",
        "AND quarantined_at_ms < claim_expires_at_ms",
    ] {
        assert!(
            definition.contains(required),
            "job quarantine lost exact target/time evidence: {required}"
        );
    }
}

#[test]
fn job_selection_replays_an_atomic_preclaim_quarantine_exactly() {
    let definition = DUE_MIGRATION_SQL
        .split_once("CREATE TABLE workflow_plan_v2_job_result_selections")
        .expect("job selection table")
        .1
        .split_once("CREATE INDEX workflow_plan_v2_instance_result_selections_expired_receipts")
        .expect("bounded job selection table")
        .0;
    for required in [
        "REFERENCES workflow_plan_v2_jobs(run_id, invocation_id, id) MATCH FULL",
        "outcome = 'quarantined'",
        "AND invocation_id IS NOT NULL AND logical_job_id IS NOT NULL",
        "AND generation IS NULL",
    ] {
        assert!(
            definition.contains(required),
            "job selection lost its quarantined shape: {required}"
        );
    }

    let transition = DUE_MIGRATION_SQL
        .split_once("CREATE FUNCTION automata_enforce_workflow_plan_v2_job_result_selection()")
        .expect("job selection transition")
        .1
        .split_once("CREATE TRIGGER workflow_plan_v2_job_result_selections_enforce")
        .expect("bounded job selection transition")
        .0;
    for required in [
        "FROM workflow_plan_v2_job_result_quarantines AS quarantine",
        "quarantine.logical_job_id = NEW.logical_job_id",
        "quarantine.tenant_id = NEW.tenant_id",
        "quarantine.run_id = NEW.run_id",
        "quarantine.invocation_id = NEW.invocation_id",
    ] {
        assert!(
            transition.contains(required),
            "due migration lost exact job-quarantine replay: {required}"
        );
    }
}
