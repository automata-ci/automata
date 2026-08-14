use automata_ci_core::{
    CORE_SCHEMA_VERSION, JOB_IR_SCHEMA_VERSION, JOB_RUNTIME_CONTEXT_SCHEMA_VERSION,
    RUNNER_REQUIREMENTS_SCHEMA_VERSION,
};

use automata_ci_store::{
    HUMAN_OUTPUT_PUBLICATION_SAFETY_SCHEMA, LOGICAL_ORCHESTRATION_SCHEMA, WORKFLOW_ADMISSION_EPOCH,
    WORKFLOW_PLAN_SCHEMA, WORKFLOW_WORKSPACE_DERIVATION_VERSION,
    adapter_spi::secret_custody_canary_schema_version,
};

/// Database-width values for the durable formats accepted by current Store readers.
///
/// Keeping the checked conversions in one place prevents SQL readers from silently
/// drifting away from their canonical domain-format declarations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CurrentDurableSchemas {
    pub(super) admission_epoch_i32: i32,
    pub(super) core_i16: i16,
    pub(super) core_i32: i32,
    pub(super) job_ir_i16: i16,
    pub(super) job_ir_i32: i32,
    pub(super) logical_orchestration_i16: i16,
    pub(super) runtime_context_i16: i16,
    pub(super) runner_requirements_i16: i16,
    pub(super) publication_safety_i32: i32,
    pub(super) secret_custody_canary_i32: i32,
    pub(super) workflow_plan_i16: i16,
    pub(super) workflow_plan_i32: i32,
    pub(super) workflow_workspace_derivation_i16: i16,
}

/// Returns the exact current schemas in their signed storage widths.
#[must_use]
pub(super) fn current_durable_schemas() -> CurrentDurableSchemas {
    CurrentDurableSchemas {
        admission_epoch_i32: i32::from(WORKFLOW_ADMISSION_EPOCH),
        core_i16: i16::try_from(CORE_SCHEMA_VERSION)
            .expect("current core schema fits PostgreSQL SMALLINT"),
        core_i32: i32::from(CORE_SCHEMA_VERSION),
        job_ir_i16: i16::try_from(JOB_IR_SCHEMA_VERSION)
            .expect("current JobIR schema fits PostgreSQL SMALLINT"),
        job_ir_i32: i32::from(JOB_IR_SCHEMA_VERSION),
        logical_orchestration_i16: i16::try_from(LOGICAL_ORCHESTRATION_SCHEMA)
            .expect("current logical-orchestration schema fits PostgreSQL SMALLINT"),
        runtime_context_i16: i16::try_from(JOB_RUNTIME_CONTEXT_SCHEMA_VERSION)
            .expect("current runtime-context schema fits PostgreSQL SMALLINT"),
        runner_requirements_i16: i16::try_from(RUNNER_REQUIREMENTS_SCHEMA_VERSION)
            .expect("current runner-requirements schema fits PostgreSQL SMALLINT"),
        publication_safety_i32: HUMAN_OUTPUT_PUBLICATION_SAFETY_SCHEMA,
        secret_custody_canary_i32: i32::from(secret_custody_canary_schema_version()),
        workflow_plan_i16: i16::try_from(WORKFLOW_PLAN_SCHEMA)
            .expect("current workflow-plan schema fits PostgreSQL SMALLINT"),
        workflow_plan_i32: i32::from(WORKFLOW_PLAN_SCHEMA),
        workflow_workspace_derivation_i16: i16::try_from(WORKFLOW_WORKSPACE_DERIVATION_VERSION)
            .expect("current workspace-derivation version fits PostgreSQL SMALLINT"),
    }
}

/// Returns whether a persisted secret-custody canary uses the only schema this
/// Store build can decode.
#[must_use]
pub(super) fn is_current_secret_custody_canary_schema(schema: i32) -> bool {
    schema == current_durable_schemas().secret_custody_canary_i32
}

#[cfg(test)]
mod tests {
    use automata_ci_core::{
        CORE_SCHEMA_VERSION, JOB_IR_SCHEMA_VERSION, JOB_RUNTIME_CONTEXT_SCHEMA_VERSION,
        RUNNER_REQUIREMENTS_SCHEMA_VERSION,
    };

    use super::{current_durable_schemas, is_current_secret_custody_canary_schema};
    use automata_ci_store::{
        HUMAN_OUTPUT_PUBLICATION_SAFETY_SCHEMA, LOGICAL_ORCHESTRATION_SCHEMA,
        WORKFLOW_ADMISSION_EPOCH, WORKFLOW_PLAN_SCHEMA, WORKFLOW_WORKSPACE_DERIVATION_VERSION,
        adapter_spi::secret_custody_canary_schema_version,
    };

    #[test]
    fn postgres_schema_values_are_derived_from_canonical_formats() {
        let schemas = current_durable_schemas();

        assert_eq!(
            schemas.admission_epoch_i32,
            i32::from(WORKFLOW_ADMISSION_EPOCH)
        );
        assert_eq!(
            schemas.core_i16,
            i16::try_from(CORE_SCHEMA_VERSION).expect("test schema fits SMALLINT")
        );
        assert_eq!(schemas.core_i32, i32::from(CORE_SCHEMA_VERSION));
        assert_eq!(
            schemas.job_ir_i16,
            i16::try_from(JOB_IR_SCHEMA_VERSION).expect("test schema fits SMALLINT")
        );
        assert_eq!(schemas.job_ir_i32, i32::from(JOB_IR_SCHEMA_VERSION));
        assert_eq!(
            schemas.logical_orchestration_i16,
            i16::try_from(LOGICAL_ORCHESTRATION_SCHEMA).expect("test schema fits SMALLINT")
        );
        assert_eq!(
            schemas.runtime_context_i16,
            i16::try_from(JOB_RUNTIME_CONTEXT_SCHEMA_VERSION).expect("test schema fits SMALLINT")
        );
        assert_eq!(
            schemas.runner_requirements_i16,
            i16::try_from(RUNNER_REQUIREMENTS_SCHEMA_VERSION).expect("test schema fits SMALLINT")
        );
        assert_eq!(
            schemas.publication_safety_i32,
            HUMAN_OUTPUT_PUBLICATION_SAFETY_SCHEMA
        );
        assert_eq!(
            schemas.secret_custody_canary_i32,
            i32::from(secret_custody_canary_schema_version())
        );
        assert_eq!(
            schemas.workflow_plan_i16,
            i16::try_from(WORKFLOW_PLAN_SCHEMA).expect("test schema fits SMALLINT")
        );
        assert_eq!(schemas.workflow_plan_i32, i32::from(WORKFLOW_PLAN_SCHEMA));
        assert_eq!(
            schemas.workflow_workspace_derivation_i16,
            i16::try_from(WORKFLOW_WORKSPACE_DERIVATION_VERSION)
                .expect("test schema fits SMALLINT")
        );
    }

    #[test]
    fn secret_custody_canary_reader_rejects_noncurrent_schema() {
        let current = i32::from(secret_custody_canary_schema_version());

        assert!(is_current_secret_custody_canary_schema(current));
        assert!(!is_current_secret_custody_canary_schema(current + 1));
    }
}
