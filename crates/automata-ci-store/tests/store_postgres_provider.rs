//! Current-schema PostgreSQL provider-ingress and publication tests.

mod common;

#[path = "github_manifest_fixture.rs"]
mod github_manifest_fixture;

#[path = "postgres_bootstrap.rs"]
mod postgres_bootstrap;
#[path = "postgres_github_job_runtime_authority.rs"]
mod postgres_github_job_runtime_authority;
#[path = "postgres_github_oidc.rs"]
mod postgres_github_oidc;
#[path = "postgres_github_provider_manifest.rs"]
mod postgres_github_provider_manifest;
#[path = "postgres_github_schedule.rs"]
mod postgres_github_schedule;
#[path = "postgres_github_service_authority.rs"]
mod postgres_github_service_authority;
#[path = "postgres_github_service_authority_clock.rs"]
mod postgres_github_service_authority_clock;
#[path = "postgres_github_subject_evidence.rs"]
mod postgres_github_subject_evidence;
#[path = "postgres_provider_delivery.rs"]
mod postgres_provider_delivery;
#[path = "postgres_publication.rs"]
mod postgres_publication;
#[path = "postgres_reusable_workflow_expansion.rs"]
mod postgres_reusable_workflow_expansion;
#[path = "postgres_run_publication_snapshot.rs"]
mod postgres_run_publication_snapshot;
