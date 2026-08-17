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
mod broker_provider;
#[cfg(windows)]
mod broker_service_host;
#[cfg(windows)]
mod broker_service_protocol;
// The former runner-owned Docker provider remains compilable only inside this
// crate's Windows unit tests. Production builds expose the restricted broker
// provider exclusively, so composition cannot fall back to a direct engine
// or inherit its broader endpoint capabilities.
#[cfg(windows)]
mod command;
mod custody;
#[cfg(all(windows, test))]
mod endpoint;
#[cfg(all(windows, test))]
mod error;
#[cfg(windows)]
mod hcs_engine;
mod host_input;
#[cfg(all(windows, test))]
mod naming;
#[cfg(all(windows, test))]
mod persistence;
#[cfg(all(windows, test))]
mod provider;

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
pub use broker_provider::{
    WINDOWS_HYPERV_BROKER_CLIENT_BASENAME, WindowsHyperVBrokerAuthorityClient,
    WindowsHyperVBrokerClient, WindowsHyperVBrokerClientEffect, WindowsHyperVBrokerClientError,
    WindowsHyperVBrokerProvider, WindowsHyperVBrokerProviderOptions, WindowsHyperVBrokerSandbox,
};
#[cfg(windows)]
pub use broker_service_host::{
    WINDOWS_HYPERV_BROKER_PIPE, WindowsHyperVBrokerServiceError,
    install_windows_hyperv_broker_state_root, run_windows_hyperv_broker_service,
    run_windows_hyperv_broker_service_with_ready,
};
#[cfg(all(windows, test))]
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
#[cfg(all(windows, test))]
pub use provider::{WindowsHyperVContainerProvider, WindowsHyperVContainerProviderOptions};

/// Stable provider identifier for Hyper-V-isolated Windows containers.
pub const WINDOWS_HYPERV_PROVIDER_ID: &str = "windows-hyperv";
