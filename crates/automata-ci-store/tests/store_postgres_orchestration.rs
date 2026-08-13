//! Current-schema `PostgreSQL` logical-orchestration and read-model tests.

mod common;

#[path = "github_manifest_fixture.rs"]
mod github_manifest_fixture;

#[path = "postgres_logical_activation.rs"]
mod postgres_logical_activation;
#[path = "postgres_logical_activation_preparation.rs"]
mod postgres_logical_activation_preparation;
#[path = "postgres_logical_instance_result.rs"]
mod postgres_logical_instance_result;
#[path = "postgres_logical_job_result.rs"]
mod postgres_logical_job_result;
#[path = "postgres_logical_materialization.rs"]
mod postgres_logical_materialization;
#[path = "postgres_logical_orchestration.rs"]
mod postgres_logical_orchestration;
#[path = "postgres_logical_renewal_ack.rs"]
mod postgres_logical_renewal_ack;
#[path = "postgres_logical_run_finalization.rs"]
mod postgres_logical_run_finalization;
#[path = "postgres_logical_work_selection.rs"]
mod postgres_logical_work_selection;
#[path = "postgres_web_reads.rs"]
mod postgres_web_reads;
#[path = "postgres_workflow_run_ui_projection.rs"]
mod postgres_workflow_run_ui_projection;
