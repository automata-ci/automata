const MIGRATION_SQL: &str =
    include_str!("../migrations/0022_workflow_plan_v2_instance_results.sql");
const DUE_MIGRATION_SQL: &str =
    include_str!("../migrations/0038_logical_result_projection_due.sql");
const G1_POSTGRES_ADAPTER: &str = include_str!("../src/postgres/g1.rs");
const INSTANCE_RESULT_POSTGRES_ADAPTER: &str =
    include_str!("../src/postgres/logical_instance_result.rs");

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_0022_is_embedded_as_the_current_instance_result_phase() {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 22)
        .expect("migration 0022 is embedded");
    assert_eq!(
        migration.description.as_ref(),
        "workflow plan v2 instance results"
    );
    for table in [
        "workflow_plan_v2_instance_result_claims",
        "workflow_plan_v2_instance_results",
        "workflow_plan_v2_instance_result_outputs",
    ] {
        assert!(
            MIGRATION_SQL.contains(&format!("CREATE TABLE {table}")),
            "migration must create {table}"
        );
    }
}

#[test]
fn migration_fences_current_terminal_blobs_and_secret_safe_outputs() {
    for required in [
        "state IN ('projecting', 'finalized')",
        "expires_at_ms - claimed_at_ms <= 900000",
        "job.admission_epoch = 4",
        "job.job_ir_schema = 5",
        "instance.job_ir_version = 5",
        "terminal.result_schema = 1",
        "concrete.initial_attempt_id = attempt.id",
        "result_media_type = 'application/vnd.automata.job-result+json'",
        "job_ir_media_type = 'application/vnd.automata.job-ir.protobuf'",
        "output_count BETWEEN 0 AND 1024",
        "sensitivity = 'public' AND public_value IS NOT NULL",
        "sensitivity = 'secret_derived' AND public_value IS NULL",
        "continue_on_error",
        "raw_conclusion = 'failure'",
        "effective_conclusion = 'success'",
        "secret_exposure_class",
        "OR (attempt.secret_exposure_class = 'readable_secret'\n                  AND NEW.secret_exposure_class = 'readable_secret')",
        "NEW.sensitivity = 'secret_derived'",
        "WorkflowPlan-v2 instance-result evidence is immutable",
    ] {
        assert!(
            MIGRATION_SQL.contains(required),
            "migration lost current instance-result gate: {required}"
        );
    }
    assert!(!MIGRATION_SQL.contains("job.job_ir_schema IN"));
    assert!(!MIGRATION_SQL.contains("terminal.result_schema BETWEEN"));
    assert!(!MIGRATION_SQL.contains("legacy"));
}

#[test]
fn due_migration_refreshes_after_the_production_terminal_lifecycle_transition() {
    for required in [
        "attempt_terminal_results_refresh_result_projection_due",
        "automata_refresh_workflow_plan_v2_attempt_lifecycle_due_trigger",
        "NEW.lifecycle IS DISTINCT FROM OLD.lifecycle",
        "'succeeded', 'failed', 'cancelled', 'timed_out', 'skipped'",
        "AFTER UPDATE OF lifecycle ON job_attempts",
        "automata_refresh_workflow_plan_v2_instance_result_due(NEW.id)",
    ] {
        assert!(
            DUE_MIGRATION_SQL.contains(required),
            "due migration lost the terminal-order wakeup: {required}"
        );
    }

    let terminal_insert = G1_POSTGRES_ADAPTER
        .find("insert_terminal_result(&mut transaction, &request, locked.slot).await?")
        .expect("production terminal commit inserts its immutable result");
    let lifecycle_transition = G1_POSTGRES_ADAPTER
        .find("conclude_terminal_attempt(&mut transaction, &request, decision_at).await?")
        .expect("production terminal commit advances the attempt lifecycle");
    assert!(
        terminal_insert < lifecycle_transition,
        "the due wakeup must continue to cover insert-before-lifecycle production order"
    );
}

#[test]
fn instance_selector_has_indexed_quarantine_aware_due_support() {
    for required in [
        "CREATE INDEX workflow_plan_v2_instance_result_due_next",
        "available_at_ms, ready_at_ms, run_id, invocation_id,",
        "source_order, logical_job_id, attempt_id",
        "attempt_id UUID PRIMARY KEY",
    ] {
        assert!(
            DUE_MIGRATION_SQL.contains(required),
            "due migration lost instance-selector support: {required}"
        );
    }

    let selector = INSTANCE_RESULT_POSTGRES_ADAPTER
        .split_once("async fn lock_next_target(")
        .expect("instance selector function")
        .1
        .split_once("async fn lock_due_target(")
        .expect("bounded instance selector function")
        .0;
    for required in [
        "FROM workflow_plan_v2_instance_result_due",
        "FROM workflow_plan_v2_instance_result_quarantines AS quarantine",
        "quarantine.attempt_id =",
        "FOR UPDATE SKIP LOCKED",
    ] {
        assert!(
            selector.contains(required),
            "instance selector must skip target-keyed quarantine ledgers: {required}"
        );
    }
}

#[test]
fn due_migration_retains_materialization_and_logical_graph_sources() {
    for table in [
        "workflow_plan_v2_materialization_claims",
        "workflow_plan_v2_concrete_jobs",
        "workflow_plan_v2_jobs",
        "workflow_plan_v2_invocations",
        "workflow_plan_v2_runs",
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

    for required in [
        "CREATE FUNCTION automata_reject_retained_workflow_plan_v2_instance_delete()",
        "FROM workflow_plan_v2_activation_publications AS publication",
        "BEFORE DELETE ON workflow_plan_v2_instances FOR EACH ROW",
        "BEFORE TRUNCATE ON workflow_plan_v2_instances FOR EACH STATEMENT",
        "BEFORE TRUNCATE ON workflow_plan_v2_activation_publications FOR EACH STATEMENT",
    ] {
        assert!(
            DUE_MIGRATION_SQL.contains(required),
            "due migration lost retained activation/materialization evidence: {required}"
        );
    }
}

#[test]
fn instance_quarantine_is_target_keyed_fenced_and_immutable() {
    for required in [
        "CREATE TABLE workflow_plan_v2_instance_result_quarantines",
        "attempt_id UUID PRIMARY KEY",
        "'relational_evidence', 'object_evidence', 'payload_evidence'",
        "claim_owner_id IS NULL",
        "claim_descriptor_digest IS NULL",
        "quarantined_at_ms >= ready_at_ms",
        "quarantined_at_ms >= claim_claimed_at_ms",
        "claim.expires_at_ms = NEW.claim_expires_at_ms",
        "claim.descriptor_digest = NEW.claim_descriptor_digest",
        "claim.state = 'projecting'",
        "FROM workflow_plan_v2_instance_result_due AS due",
        "FOR UPDATE",
        "workflow_plan_v2_instance_result_quarantines_due_exact",
        "workflow_plan_v2_instance_result_quarantines_claim_exact",
        "NEW.quarantined_at_ms :=",
        "BEFORE UPDATE ON workflow_plan_v2_instance_result_quarantines",
        "BEFORE DELETE ON workflow_plan_v2_instance_result_quarantines",
        "BEFORE TRUNCATE ON workflow_plan_v2_instance_result_quarantines",
    ] {
        assert!(
            DUE_MIGRATION_SQL.contains(required),
            "due migration lost its instance quarantine boundary: {required}"
        );
    }

    let definition = DUE_MIGRATION_SQL
        .split_once("CREATE TABLE workflow_plan_v2_instance_result_quarantines")
        .expect("instance quarantine table")
        .1
        .split_once("CREATE TABLE workflow_plan_v2_job_result_quarantines")
        .expect("bounded instance quarantine table")
        .0;
    for required in [
        "REFERENCES attempt_terminal_results(attempt_id) ON DELETE RESTRICT",
        "REFERENCES workflow_plan_v2_jobs(run_id, invocation_id, id)",
        "AND quarantined_at_ms >= available_at_ms",
        "AND quarantined_at_ms < claim_expires_at_ms",
    ] {
        assert!(
            definition.contains(required),
            "instance quarantine lost exact target/time evidence: {required}"
        );
    }
}

#[test]
fn instance_selection_replays_an_atomic_preclaim_quarantine_exactly() {
    let definition = DUE_MIGRATION_SQL
        .split_once("CREATE TABLE workflow_plan_v2_instance_result_selections")
        .expect("instance selection table")
        .1
        .split_once("CREATE TABLE workflow_plan_v2_job_result_selections")
        .expect("bounded instance selection table")
        .0;
    for required in [
        "REFERENCES attempt_terminal_results(attempt_id)",
        "outcome = 'quarantined'",
        "AND tenant_id IS NOT NULL AND attempt_id IS NOT NULL",
        "AND generation IS NULL",
    ] {
        assert!(
            definition.contains(required),
            "instance selection lost its quarantined shape: {required}"
        );
    }

    let transition = DUE_MIGRATION_SQL
        .split_once("CREATE FUNCTION automata_enforce_workflow_plan_v2_instance_result_selection()")
        .expect("instance selection transition")
        .1
        .split_once("CREATE TRIGGER workflow_plan_v2_instance_result_selections_enforce")
        .expect("bounded instance selection transition")
        .0;
    for required in [
        "FROM workflow_plan_v2_instance_result_quarantines AS quarantine",
        "quarantine.attempt_id = NEW.attempt_id",
        "quarantine.tenant_id = NEW.tenant_id",
    ] {
        assert!(
            transition.contains(required),
            "due migration lost exact instance-quarantine replay: {required}"
        );
    }
}
