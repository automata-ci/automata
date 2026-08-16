#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Hyper-V-isolated Windows container provider.
//!
//! This crate exposes exactly one Windows execution boundary. Every job uses
//! a fresh digest-pinned Windows container created with Hyper-V isolation,
//! and the provider verifies the effective runtime state before returning a
//! handle. Process-isolated and native-host Windows execution are not present.

use std::fmt;

use automata_ci_execution::{
    EnvironmentProfile, JobResourceAllocation, OperationId, ProviderError, SandboxAuthorization,
    SandboxCustody, SandboxExecutionBinding, SandboxGeneration,
};

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

/// Stable sandbox fields presented to the restricted Windows authorization consumer.
///
/// Signed placement authority binds the exact execution and stable policy
/// fields. The broker's consumption ledger additionally binds the grant to the
/// first runner-local create operation so a crash retry is idempotent but the
/// same grant cannot authorize another job or local sandbox.
#[derive(Clone, Copy, Debug)]
pub struct WindowsHyperVSandboxAuthorizationRequest<'a> {
    operation_id: OperationId,
    custody: SandboxCustody,
    execution_binding: SandboxExecutionBinding,
    environment_profile: &'a EnvironmentProfile,
    generation: SandboxGeneration,
    resource_allocation: JobResourceAllocation,
    pids_limit: u32,
}

impl<'a> WindowsHyperVSandboxAuthorizationRequest<'a> {
    #[cfg(windows)]
    pub(crate) const fn new(
        operation_id: OperationId,
        custody: SandboxCustody,
        execution_binding: SandboxExecutionBinding,
        environment_profile: &'a EnvironmentProfile,
        generation: SandboxGeneration,
        resource_allocation: JobResourceAllocation,
        pids_limit: u32,
    ) -> Self {
        Self {
            operation_id,
            custody,
            execution_binding,
            environment_profile,
            generation,
            resource_allocation,
            pids_limit,
        }
    }

    /// Returns the durable local create operation bound on first consumption.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Returns the exact runner and job-slot custody selected for the sandbox.
    #[must_use]
    pub const fn custody(self) -> SandboxCustody {
        self.custody
    }

    /// Returns the exact session, job, attempt, lease, offer, and `JobIR` identity.
    #[must_use]
    pub const fn execution_binding(self) -> SandboxExecutionBinding {
        self.execution_binding
    }

    /// Returns the exact environment-profile attestation selected for launch.
    #[must_use]
    pub const fn environment_profile(self) -> &'a EnvironmentProfile {
        self.environment_profile
    }

    /// Returns the durable lease fence used as the sandbox generation.
    #[must_use]
    pub const fn generation(self) -> SandboxGeneration {
        self.generation
    }

    /// Returns the exact provider-neutral request and hard-limit allocation.
    #[must_use]
    pub const fn resource_allocation(self) -> JobResourceAllocation {
        self.resource_allocation
    }

    /// Returns the exact hard process ceiling selected for the sandbox.
    #[must_use]
    pub const fn pids_limit(self) -> u32 {
        self.pids_limit
    }

    /// Confirms that this closed Windows launch contract disables networking.
    #[must_use]
    pub const fn network_disabled(self) -> bool {
        true
    }
}

/// Restricted broker boundary that validates and consumes one Windows placement authority.
///
/// Implementations must decode the canonical protobuf payload, validate its
/// namespace and payload schema, signature, host and validity window, bind its
/// claims to `request.execution_binding()` and every signed policy field, and
/// atomically bind its grant digest to `request.operation_id()` in the broker's one-use ledger
/// before returning success. An exact retry of the same grant, local operation,
/// and stable sandbox policy must replay success so a crash between broker
/// acceptance and the provider's local create intent remains recoverable;
/// reuse with a different operation or policy must fail closed. Payload bytes
/// and signatures must not be logged or persisted by the provider.
pub trait WindowsHyperVSandboxAuthorizationConsumer: fmt::Debug + Send + Sync {
    /// Validates and consumes the exact authorization for one new sandbox.
    ///
    /// # Errors
    ///
    /// Returns a sanitized provider error without consuming or launching when
    /// the payload is malformed, stale, spent for a different execution,
    /// operation, or policy, or does not authorize the supplied stable sandbox
    /// fields. Exact replay after an earlier successful consumption returns
    /// success.
    fn consume(
        &self,
        authorization: &SandboxAuthorization,
        request: WindowsHyperVSandboxAuthorizationRequest<'_>,
    ) -> Result<(), ProviderError>;
}
