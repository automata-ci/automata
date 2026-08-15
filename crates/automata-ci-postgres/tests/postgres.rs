//! Consolidated `PostgreSQL` adapter contracts and database tests.

#[cfg(feature = "test-support")]
mod support;

#[cfg(feature = "test-support")]
#[path = "support/github_manifest_fixture.rs"]
mod github_manifest_fixture;

mod auth;
#[cfg(feature = "test-support")]
mod provisioning;
mod runner_auth;
mod secret;
mod store;
