//! `PostgreSQL` human-authentication and RBAC adapter tests.

mod support;

#[path = "postgres_cli_session_activation.rs"]
mod postgres_cli_session_activation;
#[path = "postgres_github_mapping_management.rs"]
mod postgres_github_mapping_management;
#[path = "postgres_github_membership.rs"]
mod postgres_github_membership;
#[path = "postgres_human_auth.rs"]
mod postgres_human_auth;
#[path = "postgres_installation.rs"]
mod postgres_installation;
#[path = "postgres_login_device_cas.rs"]
mod postgres_login_device_cas;
#[path = "postgres_management.rs"]
mod postgres_management;
#[path = "postgres_provider_tokens.rs"]
mod postgres_provider_tokens;
#[path = "postgres_request_auth.rs"]
mod postgres_request_auth;
#[path = "postgres_sign_in.rs"]
mod postgres_sign_in;
