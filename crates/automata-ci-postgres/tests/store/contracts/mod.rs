//! Concrete Store adapter contracts that do not require a live database.

mod github_oidc;
#[cfg(feature = "test-support")]
mod schema_catalog;
mod secret_management;
