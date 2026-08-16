//! Production composition and strict configuration for the runner daemon.

#[cfg(unix)]
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
mod windows_enrollment_admission;
mod windows_image;

pub use composition::{
    RunnerProductError, RunnerShutdown, load_s3_credentials, load_spool_key, load_spool_keyring,
    run,
};
pub use config::{
    ClientTlsSources, ExecutorProductConfig, GithubProductConfig, KubernetesProductConfig,
    LocalDockerProductConfig, MacosVirtualizationProductConfig, MetricsProductConfig,
    PodmanProductConfig, RUNNER_PRODUCT_CONFIG_SCHEMA_VERSION, RunnerProductConfig,
    RunnerProductConfigError, RunnerProviderConfig, SpoolProtectionConfig, StateRoots,
    ToolchainConfig, WindowsHyperVProductConfig,
};
pub use context::StandardGithubContext;
pub(crate) use files::{
    ScalarLineEnding, normalize_scalar_bytes, validate_absolute_path, validate_environment_name,
};
pub use files::{SecretSource, SecureInputError};
pub use state::ProductStateRootError;
pub use tls::ClientTlsMaterialError;
pub use windows_enrollment_admission::{
    WindowsEnrollmentAdmissionBinding, WindowsEnrollmentAdmissionError,
    WindowsEnrollmentAdmissionRequest, WindowsEnrollmentIntent, WindowsEnrollmentProbePolicy,
    WindowsHostInputDescriptor, WindowsHostInputKind, probe_windows_enrollment_request,
    windows_enrollment_admission_request,
};
pub use windows_image::{
    FilesystemWindowsImageEvidenceVerifier, WindowsImageAdmission, WindowsImageContractConfig,
    WindowsImageEvidenceVerifier, WindowsImagePromotionConfig, WindowsImageVerification,
    WindowsImageVerificationError, WindowsImageVerificationRequest, WindowsPromotionTrustBundleId,
};
