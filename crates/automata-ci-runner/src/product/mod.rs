//! Production composition and strict configuration for the runner daemon.

mod composition;
mod config;
mod context;
mod files;
mod metrics;
mod profile_admission;
mod resource_metrics;
mod state;
mod tls;

pub use composition::{
    RunnerProductError, RunnerShutdown, load_s3_credentials, load_spool_key, load_spool_keyring,
    run,
};
pub use config::{
    ClientTlsSources, ExecutorProductConfig, GithubProductConfig, MetricsProductConfig,
    ObjectStoreProductConfig, PodmanProductConfig, RUNNER_PRODUCT_CONFIG_SCHEMA_VERSION,
    RunnerProductConfig, RunnerProductConfigError, RunnerProviderConfig, SpoolProtectionConfig,
    StateRoots, ToolchainConfig, WindowsNativeProductConfig,
};
pub use context::StandardGithubContext;
pub use files::{SecretSource, SecureInputError};
pub use state::ProductStateRootError;
pub use tls::ClientTlsMaterialError;
