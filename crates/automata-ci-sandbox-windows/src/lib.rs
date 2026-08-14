#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Hyper-V-isolated Windows container provider.
//!
//! This crate exposes exactly one Windows execution boundary. Every job uses
//! a fresh digest-pinned Windows container created with Hyper-V isolation,
//! and the provider verifies the effective runtime state before returning a
//! handle. Process-isolated and native-host Windows execution are not present.

#[cfg(windows)]
mod command;
#[cfg(windows)]
mod endpoint;
#[cfg(windows)]
mod error;
#[cfg(windows)]
mod naming;
#[cfg(windows)]
mod persistence;
#[cfg(windows)]
mod provider;
#[cfg(not(windows))]
mod unsupported;

#[cfg(windows)]
pub use command::{
    RuntimeCommandExecutor, RuntimeCommandOutput, RuntimeCommandRequest,
    RuntimeCommandRequestError, RuntimeCommandTermination, SystemRuntimeCommandExecutor,
};
#[cfg(windows)]
pub use provider::{WindowsHyperVContainerProvider, WindowsHyperVContainerProviderOptions};
#[cfg(not(windows))]
pub use unsupported::{WindowsHyperVContainerProvider, WindowsHyperVContainerProviderOptions};

/// Stable provider identifier for Hyper-V-isolated Windows containers.
pub const WINDOWS_HYPERV_PROVIDER_ID: &str = "windows-hyperv";
