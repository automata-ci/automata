const WORKFLOW_ADMISSION: &str = include_str!("../migrations/0005_workflow_admission.sql");
const JOB_IR_CONTEXT: &str = include_str!("../migrations/0007_job_ir_v4_execution_context.sql");
const PROVIDER_INBOX: &str = include_str!("../migrations/0017_provider_delivery_inbox.sql");
const LOGICAL_ORCHESTRATION: &str =
    include_str!("../migrations/0019_workflow_plan_v2_orchestration.sql");
const CONCRETE_JOBS: &str = include_str!("../migrations/0021_workflow_plan_v2_concrete_jobs.sql");
const DEPENDENT_PREPARATION: &str =
    include_str!("../migrations/0028_workflow_plan_v2_dependent_activation_preparation.sql");

#[test]
fn every_durable_provider_event_uses_the_twenty_five_mib_ceiling() {
    for migration in [
        WORKFLOW_ADMISSION,
        JOB_IR_CONTEXT,
        PROVIDER_INBOX,
        LOGICAL_ORCHESTRATION,
        CONCRETE_JOBS,
        DEPENDENT_PREPARATION,
    ] {
        assert!(
            migration.contains("event_size_bytes BETWEEN 1 AND 26214400")
                || migration.contains("raw_event_size_bytes BETWEEN 1 AND 26214400"),
            "migration must carry the exact provider-event ceiling"
        );
        assert!(
            !migration.contains("event_size_bytes BETWEEN 1 AND 16777216")
                && !migration.contains("raw_event_size_bytes BETWEEN 1 AND 16777216"),
            "migration must not retain the standard object ceiling for provider events"
        );
    }
}

#[test]
fn source_plan_and_runtime_objects_keep_the_sixteen_mib_ceiling() {
    for (migration, standard_constraints) in [
        (
            WORKFLOW_ADMISSION,
            &[
                "source_size_bytes BETWEEN 1 AND 16777216",
                "plan_size_bytes BETWEEN 1 AND 16777216",
            ][..],
        ),
        (
            JOB_IR_CONTEXT,
            &[
                "source_size_bytes BETWEEN 1 AND 16777216",
                "plan_size_bytes BETWEEN 1 AND 16777216",
                "job_ir_size_bytes BETWEEN 1 AND 16777216",
                "claimed_job_ir_size_bytes BETWEEN 1 AND 16777216",
            ][..],
        ),
        (
            LOGICAL_ORCHESTRATION,
            &[
                "source_size_bytes BETWEEN 1 AND 16777216",
                "plan_size_bytes BETWEEN 1 AND 16777216",
            ][..],
        ),
        (
            CONCRETE_JOBS,
            &["runtime_context_size_bytes BETWEEN 1 AND 16777216"][..],
        ),
        (
            DEPENDENT_PREPARATION,
            &[
                "plan_size_bytes BETWEEN 1 AND 16777216",
                "base_context_size_bytes BETWEEN 1 AND 16777216",
                "prerequisite_context_size_bytes BETWEEN 1 AND 16777216",
            ][..],
        ),
    ] {
        for constraint in standard_constraints {
            assert!(
                migration.contains(constraint),
                "migration must retain the exact standard ceiling for {constraint}"
            );
        }
    }
}
