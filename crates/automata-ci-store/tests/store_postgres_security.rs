//! Current-schema `PostgreSQL` security, observability, and schema-boundary tests.

mod common;

#[path = "github_manifest_fixture.rs"]
mod github_manifest_fixture;

#[path = "postgres_human_auth_schema.rs"]
mod postgres_human_auth_schema;
#[path = "postgres_managed_secret_authority.rs"]
mod postgres_managed_secret_authority;
#[path = "postgres_observability.rs"]
mod postgres_observability;
#[path = "postgres_secret_custody.rs"]
mod postgres_secret_custody;
#[path = "postgres_secret_management.rs"]
mod postgres_secret_management;
#[path = "postgres_secrets_output_safety.rs"]
mod postgres_secrets_output_safety;
