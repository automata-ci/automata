#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Narrow, provider-neutral runner boundary for the privileged Windows broker.
//!
//! This crate contains no grant verifier, durable ledger, watchdog, host-compute
//! adapter, or service composition. The runner-side sandbox adapter depends only
//! on this bounded request/consumer contract; privileged implementation details
//! live behind it.

use std::fmt;

use automata_ci_execution::{
    EnvironmentProfile, JobResourceAllocation, OperationId, ProviderError, SandboxAuthorization,
    SandboxCustody, SandboxExecutionBinding, SandboxGeneration,
};

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
    /// Constructs the exact stable request forwarded by the sandbox adapter.
    #[must_use]
    pub const fn new(
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

/// Restricted client boundary that asks the privileged broker to consume one authority.
///
/// Implementations must decode the canonical payload, validate its namespace,
/// schema, signature, host and validity window, bind its claims to every stable
/// request field, and atomically bind the grant digest to the first local
/// create operation. Payload bytes and signatures must not be logged or stored
/// by the runner adapter.
pub trait WindowsHyperVSandboxAuthorizationConsumer: fmt::Debug + Send + Sync {
    /// Validates and consumes the exact authorization for one new sandbox.
    ///
    /// # Errors
    ///
    /// Returns a sanitized provider error without consuming or launching when
    /// the payload is malformed, stale, spent for a different execution,
    /// operation, or policy, or does not authorize the supplied stable fields.
    /// Exact replay after an earlier successful consumption returns success.
    fn consume(
        &self,
        authorization: &SandboxAuthorization,
        request: WindowsHyperVSandboxAuthorizationRequest<'_>,
    ) -> Result<(), ProviderError>;
}
