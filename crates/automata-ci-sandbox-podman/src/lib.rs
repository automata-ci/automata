#![forbid(unsafe_code)]
#![deny(missing_docs)]
// The public adapter remains constructible on other targets only to return a
// typed unsupported-platform error; Linux-only implementation helpers are then
// intentionally unreachable.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
//! Local rootless Podman adapter for one-container whole-job sandboxes.
//!
//! Every Podman invocation is local (`--remote=false`), argv-only, bounded,
//! and executed with an explicitly allowlisted host environment. The adapter
//! never mounts a Podman socket, never forwards host credentials, and never
//! issues a global prune. Ownership labels are inspected immediately before
//! every destructive operation.

mod command;
mod config;
#[cfg(unix)]
mod docker;
#[cfg(not(unix))]
#[path = "docker_unsupported.rs"]
mod docker;
mod docker_contract;
mod endpoint;
mod error;
mod naming;
mod observer;
mod provider;
mod service;
mod service_proxy;
mod state;

pub use command::{
    CommandOutput, CommandRequest, CommandTermination, PodmanCommandExecutor,
    PodmanProcessEnvironment, SystemCommandExecutor,
};
pub use config::{
    JobContainerEngine, PodmanBinary, PodmanHostGatewayAlias, PodmanLaunchTrust,
    PodmanLaunchTrustHandle, PodmanLimits, PodmanOptions,
};
pub(crate) use error::provider_error;
pub use error::{PodmanConfigurationError, PodmanOpenError, PodmanStateRootError};
pub use observer::{
    DockerProxyOutcome, DockerProxyRejection, DockerProxyRoute, NoopPodmanObserver,
    PodmanCommandOutcome, PodmanCommandStage, PodmanEvent, PodmanObserver,
};
pub use provider::RootlessPodmanProvider;
pub use state::PodmanStateRoot;

/// Stable provider identifier for this adapter generation.
pub const PODMAN_PROVIDER_ID: &str = "podman-rootless-v1";
