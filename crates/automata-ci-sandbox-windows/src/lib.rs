#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Hyper-V-isolated Windows container provider.
//!
//! This crate exposes exactly one Windows execution boundary. Every job uses
//! a fresh digest-pinned Windows container created with Hyper-V isolation,
//! and the provider verifies the effective runtime state before returning a
//! handle. Process-isolated and native-host Windows execution are not present.

mod broker;
#[cfg(windows)]
mod command;
#[cfg(windows)]
mod endpoint;
#[cfg(windows)]
mod error;
#[cfg(windows)]
mod hcs_engine;
#[cfg(windows)]
mod naming;
#[cfg(windows)]
mod persistence;
#[cfg(windows)]
mod provider;
#[cfg(not(windows))]
mod unsupported;

pub use broker::{
    BrokerAdapterEffect, BrokerCopyFromRequest, BrokerCopyToRequest, BrokerError,
    BrokerExecRequest, BrokerGrantKeyring, BrokerLedger, BrokerLedgerError, BrokerLifecyclePhase,
    BrokerProfileContractResolver, BrokerReconcileReport, BrokerSandboxInspection,
    BrokerSandboxTicket, BrokerWatchdog, FileBrokerLedger, HostComputeAdapterError,
    HostComputeCreateRequest, HostComputeInspection, HostComputeObservedIsolation,
    HostComputeObservedState, HostComputeProcess, HostComputeProfileObservation,
    HostComputeProfileRequest, InMemoryBrokerLedger, RestrictedWindowsHyperVBroker,
    WindowsHostComputeAdapter, WindowsHyperVAdmittedProfileContract,
    WindowsHyperVBrokerProfileAttestation,
};
#[cfg(windows)]
pub use command::{
    RuntimeCommandExecutor, RuntimeCommandOutput, RuntimeCommandRequest,
    RuntimeCommandRequestError, RuntimeCommandTermination, SystemRuntimeCommandExecutor,
};
#[cfg(windows)]
pub use hcs_engine::WindowsEngineHostComputeAdapter;
#[cfg(windows)]
pub use provider::{WindowsHyperVContainerProvider, WindowsHyperVContainerProviderOptions};
#[cfg(not(windows))]
pub use unsupported::{WindowsHyperVContainerProvider, WindowsHyperVContainerProviderOptions};

/// Stable provider identifier for Hyper-V-isolated Windows containers.
pub const WINDOWS_HYPERV_PROVIDER_ID: &str = "windows-hyperv";
