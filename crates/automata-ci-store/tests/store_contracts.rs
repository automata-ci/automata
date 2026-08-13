//! Source-only and in-memory Store contract tests.

#[path = "github_manifest_fixture.rs"]
mod github_manifest_fixture;

#[path = "adapter_port.rs"]
mod adapter_port;
#[path = "admission_event_limits.rs"]
mod admission_event_limits;
#[path = "attempt_api.rs"]
mod attempt_api;
#[path = "g1_api.rs"]
mod g1_api;
#[path = "github_authenticated_event.rs"]
mod github_authenticated_event;
#[path = "github_checks_api.rs"]
mod github_checks_api;
#[path = "github_job_runtime_authority_api.rs"]
mod github_job_runtime_authority_api;
#[path = "github_oidc_api.rs"]
mod github_oidc_api;
#[path = "github_provider_manifest_api.rs"]
mod github_provider_manifest_api;
#[path = "github_schedule_api.rs"]
mod github_schedule_api;
#[path = "github_service_authority_api.rs"]
mod github_service_authority_api;
#[path = "github_subject_evidence_api.rs"]
mod github_subject_evidence_api;
#[path = "logical_activation_api.rs"]
mod logical_activation_api;
#[path = "logical_activation_preparation_api.rs"]
mod logical_activation_preparation_api;
#[path = "logical_instance_result_api.rs"]
mod logical_instance_result_api;
#[path = "logical_job_result_api.rs"]
mod logical_job_result_api;
#[path = "logical_materialization_api.rs"]
mod logical_materialization_api;
#[path = "logical_orchestration_api.rs"]
mod logical_orchestration_api;
#[path = "logical_run_finalization_api.rs"]
mod logical_run_finalization_api;
#[path = "logical_work_selection_api.rs"]
mod logical_work_selection_api;
#[path = "maintenance_api.rs"]
mod maintenance_api;
#[path = "managed_secret_authority_api.rs"]
mod managed_secret_authority_api;
#[path = "observability_api.rs"]
mod observability_api;
#[path = "provider_delivery_api.rs"]
mod provider_delivery_api;
#[path = "provider_delivery_receipt.rs"]
mod provider_delivery_receipt;
#[path = "reusable_workflow_admission_api.rs"]
mod reusable_workflow_admission_api;
#[path = "runner_payload_tombstone_api.rs"]
mod runner_payload_tombstone_api;
#[path = "runtime_authority_api.rs"]
mod runtime_authority_api;
#[path = "secret_custody_api.rs"]
mod secret_custody_api;
#[path = "secret_management_api.rs"]
mod secret_management_api;
#[path = "snapshot_api.rs"]
mod snapshot_api;
#[path = "tenant_scope.rs"]
mod tenant_scope;
