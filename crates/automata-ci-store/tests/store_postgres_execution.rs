//! Current-schema `PostgreSQL` execution, runner, and runtime-authority tests.

mod common;

#[path = "github_manifest_fixture.rs"]
mod github_manifest_fixture;

#[path = "postgres_attempts.rs"]
mod postgres_attempts;
#[path = "postgres_concurrency_cancellation.rs"]
mod postgres_concurrency_cancellation;
#[path = "postgres_g1.rs"]
mod postgres_g1;
#[path = "postgres_maintenance.rs"]
mod postgres_maintenance;
#[path = "postgres_runner_clock.rs"]
mod postgres_runner_clock;
#[path = "postgres_runner_control.rs"]
mod postgres_runner_control;
#[path = "postgres_runner_payload_tombstones.rs"]
mod postgres_runner_payload_tombstones;
#[path = "postgres_runtime_authority.rs"]
mod postgres_runtime_authority;
