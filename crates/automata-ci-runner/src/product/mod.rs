//! Production composition and strict configuration for the runner daemon.

pub(crate) mod action_cache;
mod composition;
mod config;
mod context;
mod files;
mod managed_secret_delivery;
mod metrics;
mod profile_admission;
mod resource_metrics;
mod spool_crypto;
mod state;
mod tls;

pub use composition::{
    RunnerProductError, RunnerShutdown, load_s3_credentials, load_s3_tls_trust, load_spool_key,
    load_spool_keyring, run,
};
pub use config::{
    ClientTlsSources, ExecutorProductConfig, GithubProductConfig, KubernetesProductConfig,
    MacosVirtualizationProductConfig, MetricsProductConfig, ObjectStoreProductConfig,
    ObjectStoreTlsTrust, PodmanProductConfig, RUNNER_PRODUCT_CONFIG_SCHEMA_VERSION,
    RunnerProductConfig, RunnerProductConfigError, RunnerProviderConfig, SpoolProtectionConfig,
    StateRoots, ToolchainConfig, WindowsHyperVProductConfig,
};
pub use context::StandardGithubContext;
pub(crate) use files::{
    ScalarLineEnding, normalize_scalar_bytes, validate_absolute_path, validate_environment_name,
};
pub use files::{SecretSource, SecureInputError};
pub use state::ProductStateRootError;
pub use tls::ClientTlsMaterialError;
