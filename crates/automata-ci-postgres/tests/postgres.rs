//! Consolidated `PostgreSQL` adapter contracts and database tests.

mod support;

#[path = "support/github_manifest_fixture.rs"]
mod github_manifest_fixture;

mod auth;
mod provisioning;
mod runner_auth;
mod secret;
mod store;
