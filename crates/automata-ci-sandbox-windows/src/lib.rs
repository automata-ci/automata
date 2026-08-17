#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Hyper-V-isolated Windows container provider.
//!
//! This crate exposes exactly one Windows execution boundary. Every job uses
//! a fresh digest-pinned Windows container created with Hyper-V isolation,
//! and the provider verifies the effective runtime state before returning a
//! handle. Process-isolated and native-host Windows execution are not present.

mod admission;
mod broker;
#[cfg(windows)]
mod command;
mod custody;
#[cfg(windows)]
mod endpoint;
#[cfg(windows)]
mod error;
#[cfg(windows)]
mod hcs_engine;
mod host_input;
#[cfg(windows)]
mod naming;
#[cfg(windows)]
mod persistence;
#[cfg(windows)]
mod provider;
#[cfg(not(windows))]
mod unsupported;

pub use admission::{
    FileWindowsBrokerAdmissionAuthority, UnavailableWindowsBrokerAdmissionAuthority,
    UnavailableWindowsBrokerSyntheticProbe, VerifiedWindowsBrokerAdmissionEvaluator,
    WindowsBrokerAdmissionAuthority, WindowsBrokerAdmissionCompletion, WindowsBrokerAdmissionError,
    WindowsBrokerAdmissionEvaluation, WindowsBrokerAdmissionEvaluator,
    WindowsBrokerAdmissionInputSet, WindowsBrokerAdmissionInputSource,
    WindowsBrokerAdmissionReceipt, WindowsBrokerAdmissionSigningKey,
    WindowsBrokerPlacementRenewalReceipt, WindowsBrokerPromotionTrustBundle,
    WindowsBrokerPromotionTrustKey, WindowsBrokerPromotionTrustRegistry,
    WindowsBrokerSyntheticProbe, WindowsBrokerSyntheticProbeEvidence,
    floor_windows_admission_issued_at,
};
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
pub use custody::{
    FileWindowsBrokerCustody, WindowsBrokerCustodyError, WindowsBrokerCustodyHandle,
    WindowsBrokerCustodyKind, WindowsBrokerCustodyMetadata, WindowsBrokerCustodyProtector,
};
#[cfg(windows)]
pub use hcs_engine::WindowsEngineHostComputeAdapter;
pub use host_input::{
    WindowsBrokerHostInputAttestation, WindowsBrokerHostInputAttestor,
    WindowsBrokerHostInputDescriptor, WindowsBrokerHostInputError, WindowsBrokerHostInputKind,
    WindowsBrokerHostInputObservation, WindowsBrokerHostInputRequest,
};
#[cfg(windows)]
pub use provider::{WindowsHyperVContainerProvider, WindowsHyperVContainerProviderOptions};
#[cfg(not(windows))]
pub use unsupported::{WindowsHyperVContainerProvider, WindowsHyperVContainerProviderOptions};

/// Stable provider identifier for Hyper-V-isolated Windows containers.
pub const WINDOWS_HYPERV_PROVIDER_ID: &str = "windows-hyperv";
