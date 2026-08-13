const INITIAL_SCHEMA: &str = include_str!("../migrations/0001_initial_schema.sql");

fn constraint(name: &str) -> &'static str {
    INITIAL_SCHEMA
        .lines()
        .find(|line| line.contains(&format!("CONSTRAINT {name} CHECK")))
        .unwrap_or_else(|| panic!("initial schema must define {name}"))
}

fn table_definition(name: &str) -> &'static str {
    let marker = format!("CREATE TABLE {name} (");
    let start = INITIAL_SCHEMA
        .find(&marker)
        .unwrap_or_else(|| panic!("initial schema must define table {name}"));
    let definition = &INITIAL_SCHEMA[start..];
    let end = definition
        .find("\n);")
        .unwrap_or_else(|| panic!("initial schema must terminate table {name}"));
    &definition[..end + "\n);".len()]
}

fn assert_bound(constraint_name: &str, column: &str, maximum: u64) {
    let definition = constraint(constraint_name);
    let expected = format!("({column} >= 1) AND ({column} <= {maximum})");
    assert!(
        definition.contains(&expected),
        "{constraint_name} must bound {column} to {maximum} bytes"
    );
}

#[test]
fn every_durable_provider_event_uses_the_twenty_five_mib_ceiling() {
    for (constraint_name, column) in [
        ("workflow_runs_current_event_metadata", "event_size_bytes"),
        (
            "provider_delivery_inbox_raw_size_bounded",
            "raw_event_size_bytes",
        ),
        (
            "logical_workflow_activation_preparation_claims_event",
            "event_size_bytes",
        ),
        (
            "logical_workflow_concrete_jobs_event_size",
            "event_size_bytes",
        ),
    ] {
        assert_bound(constraint_name, column, 26_214_400);
    }

    assert!(!INITIAL_SCHEMA.contains("event_size_bytes <= 16777216"));
    assert!(!INITIAL_SCHEMA.contains("raw_event_size_bytes <= 16777216"));
}

#[test]
fn source_plan_and_runtime_objects_keep_the_sixteen_mib_ceiling() {
    for (constraint_name, column) in [
        (
            "workflow_snapshots_current_object_metadata",
            "source_size_bytes",
        ),
        ("workflow_runs_current_event_metadata", "plan_size_bytes"),
        (
            "github_oidc_authorities_current_schemas",
            "job_ir_size_bytes",
        ),
        (
            "runner_operation_receipts_job_ir_shape",
            "claimed_job_ir_size_bytes",
        ),
        (
            "logical_workflow_activation_preparation_claims_plan",
            "plan_size_bytes",
        ),
        (
            "logical_workflow_activation_preparations_contexts",
            "base_context_size_bytes",
        ),
        (
            "logical_workflow_activation_preparations_contexts",
            "prerequisite_context_size_bytes",
        ),
        (
            "logical_workflow_concrete_jobs_runtime_size",
            "runtime_context_size_bytes",
        ),
    ] {
        assert_bound(constraint_name, column, 16_777_216);
    }
}

#[test]
fn canonical_rows_require_complete_current_contract_metadata() {
    let workflow_runs = table_definition("workflow_runs");
    for required_column in [
        "event_digest bytea NOT NULL",
        "event_size_bytes bigint NOT NULL",
        "event_media_type text NOT NULL",
        "plan_digest bytea NOT NULL",
        "plan_object_key text NOT NULL",
        "plan_size_bytes bigint NOT NULL",
        "plan_media_type text NOT NULL",
        "plan_schema integer NOT NULL",
        "workflow_name text NOT NULL",
    ] {
        assert!(
            workflow_runs.contains(required_column),
            "canonical workflow_runs schema must require {required_column}"
        );
    }

    let jobs = table_definition("jobs");
    for required_column in [
        "job_ir_schema integer NOT NULL",
        "job_ir_size_bytes bigint NOT NULL",
    ] {
        assert!(
            jobs.contains(required_column),
            "canonical jobs schema must require {required_column}"
        );
    }

    assert!(
        INITIAL_SCHEMA
            .contains("CONSTRAINT runner_sessions_job_ir_current CHECK ((job_ir_schema = 1))")
    );
    assert!(
        INITIAL_SCHEMA
            .contains("CONSTRAINT runner_sessions_protocol_current CHECK ((protocol_version = 1))")
    );
    assert!(!INITIAL_SCHEMA.contains("runner_sessions_live_job_ir_current"));
    assert!(!INITIAL_SCHEMA.contains("runner_sessions_live_protocol_current"));
    assert!(!INITIAL_SCHEMA.contains("jobs_ir_metadata_complete"));
}
