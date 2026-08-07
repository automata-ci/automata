//! Production composition and strict configuration for the runner daemon.

mod composition;
mod config;
mod context;
mod files;
mod state;
mod tls;

pub use composition::{RunnerProductError, run};
pub use config::{
    ClientTlsSources, ExecutorProductConfig, GithubProductConfig, ObjectStoreProductConfig,
    PodmanProductConfig, RUNNER_PRODUCT_CONFIG_SCHEMA_VERSION, RunnerProductConfig,
    RunnerProductConfigError, SpoolProtectionConfig, StateRoots, ToolchainConfig,
};
pub use context::StandardGithubContext;
pub use files::{SecretSource, SecureInputError};
pub use state::ProductStateRootError;
pub use tls::ClientTlsMaterialError;
