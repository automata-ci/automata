//! Runner-side provider for the restricted Windows broker protocol.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use automata_ci_core::{EnvironmentProfile, Sha256Digest, UnixMillis};
use automata_ci_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, DestroyDisposition, DestroySandbox,
    EnvironmentVariable, ExecutionCommand, ExecutionEndpoint, ExecutionError, ExecutionErrorKind,
    ExecutionOutput, ExecutionStage, ImmutableImage, NetworkPolicy, OperationOutcome,
    ProviderCapabilities, ProviderError, ProviderErrorKind, ProviderId, ProviderStage,
    RootFilesystemPolicy, SandboxCapability, SandboxCustody, SandboxGeneration, SandboxHandle,
    SandboxInspection, SandboxLaunch, SandboxPrivilegePolicy, SandboxProvider, SandboxRecord,
    SandboxSpec, SandboxState, SignalRequest, WaitRequest,
};
use automata_ci_protocol::WindowsRunnerAdmissionIssueRequest;
use thiserror::Error;

use crate::{
    WINDOWS_HYPERV_PROVIDER_ID, WindowsBrokerAdmissionCompletion, WindowsBrokerAdmissionReceipt,
    WindowsBrokerCustodyHandle, WindowsBrokerHostInputAttestation, WindowsBrokerHostInputRequest,
    WindowsBrokerPlacementRenewalReceipt, WindowsHyperVBrokerProfileAttestation,
};

/// Exact basename required for the pinned runner-side broker client.
pub const WINDOWS_HYPERV_BROKER_CLIENT_BASENAME: &str = "automata-windows-hyperv-broker-client.exe";

/// Closed runner-side configuration for the restricted broker client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsHyperVBrokerProviderOptions {
    client_executable: PathBuf,
    client_sha256: Sha256Digest,
    host_id: Sha256Digest,
    operation_timeout: Duration,
}

impl WindowsHyperVBrokerProviderOptions {
    /// Creates an exact pinned broker-client configuration.
    ///
    /// # Errors
    ///
    /// Rejects a relative/non-Windows executable, the wrong fixed basename, or
    /// zero security identities. This type contains no engine endpoint.
    pub fn new(
        client_executable: impl Into<PathBuf>,
        client_sha256: Sha256Digest,
        host_id: Sha256Digest,
    ) -> Result<Self, ProviderError> {
        let client_executable = client_executable.into();
        let valid_path = is_exact_windows_client_path(&client_executable);
        if !valid_path || zero_digest(client_sha256) || zero_digest(host_id) {
            return Err(provider_error(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
                OperationOutcome::KnownNoEffect,
                None,
            ));
        }
        Ok(Self {
            client_executable,
            client_sha256,
            host_id,
            operation_timeout: Duration::from_mins(2),
        })
    }

    /// Replaces the default two-minute broker-operation timeout.
    ///
    /// # Errors
    ///
    /// Rejects zero or more than ten minutes.
    pub fn with_operation_timeout(mut self, timeout: Duration) -> Result<Self, ProviderError> {
        if timeout.is_zero() || timeout > Duration::from_mins(10) {
            return Err(provider_error(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
                OperationOutcome::KnownNoEffect,
                None,
            ));
        }
        self.operation_timeout = timeout;
        Ok(self)
    }

    /// Returns the exact pinned broker-client executable.
    #[must_use]
    pub fn client_executable(&self) -> &Path {
        &self.client_executable
    }

    /// Returns the expected broker-client content digest.
    #[must_use]
    pub const fn client_sha256(&self) -> Sha256Digest {
        self.client_sha256
    }

    /// Returns the host identity every accepted grant must name.
    #[must_use]
    pub const fn host_id(&self) -> Sha256Digest {
        self.host_id
    }

    /// Returns the fixed upper bound for one broker request.
    #[must_use]
    pub const fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }
}

/// Broker-returned sandbox metadata revalidated by the provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsHyperVBrokerSandbox {
    handle: String,
    generation: SandboxGeneration,
    custody: SandboxCustody,
    profile: EnvironmentProfile,
    state: SandboxState,
}

impl WindowsHyperVBrokerSandbox {
    /// Constructs bounded broker-returned metadata.
    ///
    /// # Errors
    ///
    /// Rejects a handle that cannot fit the provider's opaque namespace.
    pub fn new(
        handle: impl Into<String>,
        generation: SandboxGeneration,
        custody: SandboxCustody,
        profile: EnvironmentProfile,
        state: SandboxState,
    ) -> Result<Self, WindowsHyperVBrokerClientError> {
        let handle = handle.into();
        let provider = ProviderId::new(WINDOWS_HYPERV_PROVIDER_ID)
            .map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
        SandboxHandle::new(provider, handle.clone())
            .map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
        Ok(Self {
            handle,
            generation,
            custody,
            profile,
            state,
        })
    }
}

/// Whether a broker-client failure may have changed broker/HCS state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsHyperVBrokerClientEffect {
    /// No broker or HCS mutation occurred.
    KnownNoEffect,
    /// The caller must reconcile the exact handle or operation.
    StateMayHaveChanged,
}

/// Secret-free runner-to-broker client failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WindowsHyperVBrokerClientError {
    /// The broker client or authenticated local IPC endpoint is unavailable.
    #[error("restricted Windows broker is unavailable")]
    Unavailable(WindowsHyperVBrokerClientEffect),
    /// The fixed broker request exceeded its deadline.
    #[error("restricted Windows broker request timed out")]
    TimedOut(WindowsHyperVBrokerClientEffect),
    /// The broker rejected authorization, ownership, or lifecycle state.
    #[error("restricted Windows broker rejected the request")]
    Rejected(WindowsHyperVBrokerClientEffect),
    /// The broker response violated the bounded versioned protocol.
    #[error("restricted Windows broker protocol response is invalid")]
    Protocol,
}

impl WindowsHyperVBrokerClientError {
    const fn effect(self) -> WindowsHyperVBrokerClientEffect {
        match self {
            Self::Unavailable(effect) | Self::TimedOut(effect) | Self::Rejected(effect) => effect,
            Self::Protocol => WindowsHyperVBrokerClientEffect::StateMayHaveChanged,
        }
    }
}

/// Narrow typed runner-to-broker operation surface.
///
/// Production uses a pinned client over authenticated local IPC. Tests may use
/// a fake; no method accepts raw CLI argv, an engine endpoint, or an HCS document.
pub trait WindowsHyperVBrokerClient: fmt::Debug + Send + Sync {
    /// Consumes one signed grant and creates or exactly replays one sandbox.
    ///
    /// # Errors
    ///
    /// Returns a typed broker transport or policy failure.
    fn create(
        &self,
        spec: &SandboxSpec,
        cancellation: &dyn Cancellation,
    ) -> Result<WindowsHyperVBrokerSandbox, WindowsHyperVBrokerClientError>;

    /// Reattaches to one exact broker ticket.
    ///
    /// # Errors
    ///
    /// Returns a typed broker transport or ownership failure.
    fn attach(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<(), WindowsHyperVBrokerClientError>;

    /// Inspects one exact broker ticket.
    ///
    /// # Errors
    ///
    /// Returns a typed broker transport or ownership failure.
    fn inspect(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<WindowsHyperVBrokerSandbox, WindowsHyperVBrokerClientError>;

    /// Executes one literal guest argv through the broker.
    ///
    /// # Errors
    ///
    /// Returns a typed broker execution failure.
    fn exec(
        &self,
        handle: &SandboxHandle,
        request: &ExecutionCommand,
        cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, WindowsHyperVBrokerClientError>;

    /// Copies bounded anonymous bytes into the guest.
    ///
    /// # Errors
    ///
    /// Returns a typed broker copy failure.
    fn copy_to(
        &self,
        handle: &SandboxHandle,
        request: &CopyToRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), WindowsHyperVBrokerClientError>;

    /// Copies bounded anonymous bytes out of the guest.
    ///
    /// # Errors
    ///
    /// Returns a typed broker copy failure.
    fn copy_from(
        &self,
        handle: &SandboxHandle,
        request: &CopyFromRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, WindowsHyperVBrokerClientError>;

    /// Destroys one exact broker-owned sandbox and its descendants.
    ///
    /// # Errors
    ///
    /// Returns a typed broker cleanup failure.
    fn destroy(
        &self,
        request: &DestroySandbox,
        cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, WindowsHyperVBrokerClientError>;

    /// Obtains fresh effective Hyper-V/image/network evidence from the broker.
    ///
    /// # Errors
    ///
    /// Returns a typed broker transport or effective-state failure.
    fn attest_profile(
        &self,
        profile: &EnvironmentProfile,
        image: &ImmutableImage,
        cancellation: &dyn Cancellation,
    ) -> Result<WindowsHyperVBrokerProfileAttestation, WindowsHyperVBrokerClientError>;

    /// Independently attests every exact file used to admit this Windows runner.
    ///
    /// # Errors
    ///
    /// Returns a typed broker transport, path, digest, volume, owner, or ACL failure.
    fn attest_host_inputs(
        &self,
        request: &WindowsBrokerHostInputRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<WindowsBrokerHostInputAttestation, WindowsHyperVBrokerClientError>;

    /// Asks the broker to verify, probe, mint, and persist one admission.
    ///
    /// # Errors
    ///
    /// Returns a typed broker transport, evidence, or durable-state failure.
    fn admission_issue(
        &self,
        request: &WindowsRunnerAdmissionIssueRequest,
        observed_at: UnixMillis,
        cancellation: &dyn Cancellation,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsHyperVBrokerClientError> {
        let _ = (request, observed_at, cancellation);
        Err(WindowsHyperVBrokerClientError::Unavailable(
            WindowsHyperVBrokerClientEffect::KnownNoEffect,
        ))
    }

    /// Resumes one exact broker-minted admission without generic custody read.
    ///
    /// # Errors
    ///
    /// Returns a typed broker transport, binding, or durable-state failure.
    fn admission_resume(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        request_sha256: Sha256Digest,
        observed_at: UnixMillis,
        cancellation: &dyn Cancellation,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsHyperVBrokerClientError> {
        let _ = (handle, request_sha256, observed_at, cancellation);
        Err(WindowsHyperVBrokerClientError::Unavailable(
            WindowsHyperVBrokerClientEffect::KnownNoEffect,
        ))
    }

    /// Completes one exact broker-minted admission with a durable tombstone.
    ///
    /// # Errors
    ///
    /// Returns a typed broker transport, digest, or durable-state failure.
    fn admission_complete(
        &self,
        completion: &WindowsBrokerAdmissionCompletion,
        cancellation: &dyn Cancellation,
    ) -> Result<(), WindowsHyperVBrokerClientError> {
        let _ = (completion, cancellation);
        Err(WindowsHyperVBrokerClientError::Unavailable(
            WindowsHyperVBrokerClientEffect::KnownNoEffect,
        ))
    }

    /// Returns the retained current placement renewal or durably advances it
    /// by exactly one for a completed admission handle.
    ///
    /// # Errors
    ///
    /// Returns a typed broker transport, receipt, or durable-state failure.
    fn admission_renew(
        &self,
        completed_handle: &WindowsBrokerCustodyHandle,
        enrollment_envelope_sha256: Sha256Digest,
        observed_at: UnixMillis,
        cancellation: &dyn Cancellation,
    ) -> Result<WindowsBrokerPlacementRenewalReceipt, WindowsHyperVBrokerClientError> {
        let _ = (
            completed_handle,
            enrollment_envelope_sha256,
            observed_at,
            cancellation,
        );
        Err(WindowsHyperVBrokerClientError::Unavailable(
            WindowsHyperVBrokerClientEffect::KnownNoEffect,
        ))
    }

    /// Acknowledges one exact control-accepted renewal before the broker may
    /// advance its durable serial.
    ///
    /// # Errors
    ///
    /// Returns a typed broker transport, digest, or durable-state failure.
    fn admission_renew_ack(
        &self,
        completed_handle: &WindowsBrokerCustodyHandle,
        renewal_envelope_sha256: Sha256Digest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), WindowsHyperVBrokerClientError> {
        let _ = (completed_handle, renewal_envelope_sha256, cancellation);
        Err(WindowsHyperVBrokerClientError::Unavailable(
            WindowsHyperVBrokerClientEffect::KnownNoEffect,
        ))
    }
}

/// Cloneable runner-side authority for profile evidence and dedicated admission operations.
#[derive(Clone)]
pub struct WindowsHyperVBrokerAuthorityClient {
    client: Arc<dyn WindowsHyperVBrokerClient>,
}

impl WindowsHyperVBrokerAuthorityClient {
    /// Obtains fresh broker evidence for one exact profile and image.
    ///
    /// # Errors
    ///
    /// Returns a typed broker transport or attestation failure.
    pub fn attest_profile(
        &self,
        profile: &EnvironmentProfile,
        image: &ImmutableImage,
        cancellation: &dyn Cancellation,
    ) -> Result<WindowsHyperVBrokerProfileAttestation, WindowsHyperVBrokerClientError> {
        self.client.attest_profile(profile, image, cancellation)
    }

    /// Independently attests every exact file used by Windows enrollment.
    ///
    /// # Errors
    ///
    /// Returns a typed broker transport or host-input policy failure.
    pub fn attest_host_inputs(
        &self,
        request: &WindowsBrokerHostInputRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<WindowsBrokerHostInputAttestation, WindowsHyperVBrokerClientError> {
        self.client.attest_host_inputs(request, cancellation)
    }

    /// Asks the privileged broker to independently admit one exact request.
    ///
    /// # Errors
    ///
    /// Returns a typed broker transport, evidence, or durable-state failure.
    pub fn admission_issue(
        &self,
        request: &WindowsRunnerAdmissionIssueRequest,
        observed_at: UnixMillis,
        cancellation: &dyn Cancellation,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsHyperVBrokerClientError> {
        self.client
            .admission_issue(request, observed_at, cancellation)
    }

    /// Resumes one exact broker-minted admission receipt.
    ///
    /// # Errors
    ///
    /// Returns a typed broker transport, binding, or durable-state failure.
    pub fn admission_resume(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        request_sha256: Sha256Digest,
        observed_at: UnixMillis,
        cancellation: &dyn Cancellation,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsHyperVBrokerClientError> {
        self.client
            .admission_resume(handle, request_sha256, observed_at, cancellation)
    }

    /// Completes one exact receipt idempotently after durable enrollment.
    ///
    /// # Errors
    ///
    /// Returns a typed broker transport, digest, or durable-state failure.
    pub fn admission_complete(
        &self,
        completion: &WindowsBrokerAdmissionCompletion,
        cancellation: &dyn Cancellation,
    ) -> Result<(), WindowsHyperVBrokerClientError> {
        self.client.admission_complete(completion, cancellation)
    }

    /// Acquires an exact broker-signed placement renewal from retained
    /// completed-admission custody.
    ///
    /// # Errors
    ///
    /// Returns a typed broker transport, receipt, or durable-state failure.
    pub fn admission_renew(
        &self,
        completed_handle: &WindowsBrokerCustodyHandle,
        enrollment_envelope_sha256: Sha256Digest,
        observed_at: UnixMillis,
        cancellation: &dyn Cancellation,
    ) -> Result<WindowsBrokerPlacementRenewalReceipt, WindowsHyperVBrokerClientError> {
        self.client.admission_renew(
            completed_handle,
            enrollment_envelope_sha256,
            observed_at,
            cancellation,
        )
    }

    /// Confirms durable control acceptance of one exact placement renewal.
    ///
    /// # Errors
    ///
    /// Returns a typed broker transport, digest, or durable-state failure.
    pub fn admission_renew_ack(
        &self,
        completed_handle: &WindowsBrokerCustodyHandle,
        renewal_envelope_sha256: Sha256Digest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), WindowsHyperVBrokerClientError> {
        self.client
            .admission_renew_ack(completed_handle, renewal_envelope_sha256, cancellation)
    }
}

impl fmt::Debug for WindowsHyperVBrokerAuthorityClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsHyperVBrokerAuthorityClient")
            .finish_non_exhaustive()
    }
}

/// Shipped runner provider backed only by the restricted broker protocol.
#[derive(Clone)]
pub struct WindowsHyperVBrokerProvider {
    options: WindowsHyperVBrokerProviderOptions,
    client: Arc<dyn WindowsHyperVBrokerClient>,
    provider_id: ProviderId,
    capabilities: ProviderCapabilities,
}

impl WindowsHyperVBrokerProvider {
    /// Returns the authenticated broker authority paired with this provider.
    #[must_use]
    pub fn authority_client(&self) -> WindowsHyperVBrokerAuthorityClient {
        WindowsHyperVBrokerAuthorityClient {
            client: Arc::clone(&self.client),
        }
    }

    /// Opens the pinned production broker client on Windows.
    ///
    /// # Errors
    ///
    /// Fails closed on non-Windows or if the pinned client cannot be verified.
    pub fn open(options: &WindowsHyperVBrokerProviderOptions) -> Result<Self, ProviderError> {
        #[cfg(windows)]
        {
            let client = Arc::new(ProcessWindowsHyperVBrokerClient::open(options.clone())?);
            Self::open_with_client(options.clone(), client)
        }
        #[cfg(not(windows))]
        {
            let _ = options;
            Err(provider_error(
                ProviderErrorKind::UnsupportedPlatform,
                ProviderStage::Validate,
                OperationOutcome::KnownNoEffect,
                None,
            ))
        }
    }

    /// Opens with a closed fake client for cross-platform contract tests.
    ///
    /// # Errors
    ///
    /// Returns an invariant failure if constant provider metadata is invalid.
    pub fn open_with_client(
        options: WindowsHyperVBrokerProviderOptions,
        client: Arc<dyn WindowsHyperVBrokerClient>,
    ) -> Result<Self, ProviderError> {
        let provider_id = ProviderId::new(WINDOWS_HYPERV_PROVIDER_ID).map_err(|_| {
            provider_error(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
                OperationOutcome::KnownNoEffect,
                None,
            )
        })?;
        let capabilities = ProviderCapabilities::new(BROKER_PROVIDER_CAPABILITIES.iter().copied())
            .map_err(|_| {
                provider_error(
                    ProviderErrorKind::InvalidConfiguration,
                    ProviderStage::Validate,
                    OperationOutcome::KnownNoEffect,
                    None,
                )
            })?;
        Ok(Self {
            options,
            client,
            provider_id,
            capabilities,
        })
    }
}

const BROKER_PROVIDER_CAPABILITIES: &[SandboxCapability] = &[
    SandboxCapability::WholeJob,
    SandboxCapability::Attach,
    SandboxCapability::Inspect,
    SandboxCapability::Exec,
    SandboxCapability::CopyTo,
    SandboxCapability::CopyFrom,
    SandboxCapability::NetworkDisabled,
    SandboxCapability::WritableRootFilesystem,
    SandboxCapability::ResourceLimits,
    SandboxCapability::ProcessLimits,
];

impl fmt::Debug for WindowsHyperVBrokerProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsHyperVBrokerProvider")
            .field("provider_id", &self.provider_id)
            .field("host_id", &self.options.host_id)
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

impl SandboxProvider for WindowsHyperVBrokerProvider {
    fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    fn create(
        &self,
        spec: &SandboxSpec,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxRecord, ProviderError> {
        validate_broker_spec(spec, self.options.host_id())?;
        let sandbox = self
            .client
            .create(spec, cancellation)
            .map_err(|error| map_provider_error(error, ProviderStage::CreateSandbox, None))?;
        if sandbox.generation != spec.generation()
            || sandbox.custody != spec.custody()
            || sandbox.profile != *spec.profile().attestation()
            || !matches!(sandbox.state, SandboxState::Created | SandboxState::Running)
        {
            return Err(provider_error(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::VerifyOwnership,
                OperationOutcome::Uncertain,
                None,
            ));
        }
        let handle =
            SandboxHandle::new(self.provider_id.clone(), sandbox.handle).map_err(|_| {
                provider_error(
                    ProviderErrorKind::BackendRejected,
                    ProviderStage::VerifyOwnership,
                    OperationOutcome::Uncertain,
                    None,
                )
            })?;
        Ok(SandboxRecord::new(
            handle,
            sandbox.generation,
            sandbox.profile,
            sandbox.state,
        ))
    }

    fn attach(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<Box<dyn ExecutionEndpoint>, ProviderError> {
        validate_handle(handle, &self.provider_id)?;
        self.client.attach(handle, cancellation).map_err(|error| {
            map_provider_error(error, ProviderStage::Attach, Some(handle.clone()))
        })?;
        Ok(Box::new(BrokerExecutionEndpoint {
            handle: handle.clone(),
            client: Arc::clone(&self.client),
        }))
    }

    fn inspect(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxInspection, ProviderError> {
        validate_handle(handle, &self.provider_id)?;
        let sandbox = self.client.inspect(handle, cancellation).map_err(|error| {
            map_provider_error(error, ProviderStage::Inspect, Some(handle.clone()))
        })?;
        if sandbox.handle != handle.opaque() {
            return Err(provider_error(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::VerifyOwnership,
                OperationOutcome::KnownNoEffect,
                None,
            ));
        }
        Ok(SandboxInspection::new(
            handle.clone(),
            sandbox.generation,
            sandbox.custody,
            sandbox.profile,
            sandbox.state,
        ))
    }

    fn destroy(
        &self,
        request: &DestroySandbox,
        cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, ProviderError> {
        validate_handle(request.handle(), &self.provider_id)?;
        self.client.destroy(request, cancellation).map_err(|error| {
            map_provider_error(
                error,
                ProviderStage::DestroySandbox,
                Some(request.handle().clone()),
            )
        })
    }
}

#[derive(Clone)]
struct BrokerExecutionEndpoint {
    handle: SandboxHandle,
    client: Arc<dyn WindowsHyperVBrokerClient>,
}

impl fmt::Debug for BrokerExecutionEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerExecutionEndpoint")
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

const BROKER_ENDPOINT_CAPABILITIES: &[SandboxCapability] = &[
    SandboxCapability::Exec,
    SandboxCapability::CopyTo,
    SandboxCapability::CopyFrom,
];

impl ExecutionEndpoint for BrokerExecutionEndpoint {
    fn handle(&self) -> &SandboxHandle {
        &self.handle
    }

    fn capabilities(&self) -> &[SandboxCapability] {
        BROKER_ENDPOINT_CAPABILITIES
    }

    fn exec(
        &self,
        request: &ExecutionCommand,
        cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, ExecutionError> {
        if request
            .environment()
            .values()
            .iter()
            .any(EnvironmentVariable::is_secret)
        {
            return Err(ExecutionError::new(
                ExecutionErrorKind::UnsupportedCapability,
                ExecutionStage::Exec,
            ));
        }
        self.client
            .exec(&self.handle, request, cancellation)
            .map_err(|error| map_execution_error(error, ExecutionStage::Exec))
    }

    fn signal(
        &self,
        request: SignalRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        let _ = (request, cancellation);
        Err(ExecutionError::new(
            ExecutionErrorKind::UnsupportedCapability,
            ExecutionStage::Signal,
        ))
    }

    fn wait(
        &self,
        request: WaitRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<i32, ExecutionError> {
        let _ = (request, cancellation);
        Err(ExecutionError::new(
            ExecutionErrorKind::UnsupportedCapability,
            ExecutionStage::Wait,
        ))
    }

    fn copy_to(
        &self,
        request: &CopyToRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        self.client
            .copy_to(&self.handle, request, cancellation)
            .map_err(|error| map_execution_error(error, ExecutionStage::CopyTo))
    }

    fn copy_from(
        &self,
        request: &CopyFromRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ExecutionError> {
        let bytes = self
            .client
            .copy_from(&self.handle, request, cancellation)
            .map_err(|error| map_execution_error(error, ExecutionStage::CopyFrom))?;
        if bytes.len() > request.byte_limit() {
            return Err(ExecutionError::new(
                ExecutionErrorKind::OutputLimitExceeded,
                ExecutionStage::CopyFrom,
            ));
        }
        Ok(bytes)
    }
}

fn validate_broker_spec(spec: &SandboxSpec, host_id: Sha256Digest) -> Result<(), ProviderError> {
    let grant = spec.windows_hyperv_broker_grant().ok_or_else(|| {
        provider_error(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::Validate,
            OperationOutcome::KnownNoEffect,
            None,
        )
    })?;
    let valid = grant.claims().host_id() == host_id
        && matches!(
            spec.custody(),
            SandboxCustody::Job {
                runner_id,
                slot_ordinal,
            } if runner_id == grant.claims().runner_id()
                && slot_ordinal.get() == grant.claims().slot()
        )
        && grant.claims().environment_profile() == spec.profile().attestation()
        && grant.claims().fencing_token().get() == spec.generation().get()
        && matches!(
            spec.profile().launch(),
            SandboxLaunch::WindowsHyperVContainer { .. }
        )
        && spec.network() == NetworkPolicy::Disabled
        && spec.root_filesystem() == RootFilesystemPolicy::Writable
        && spec.privilege() == SandboxPrivilegePolicy::Unprivileged
        && !spec
            .profile()
            .default_environment()
            .values()
            .iter()
            .any(EnvironmentVariable::is_secret)
        && spec.scratch().is_none()
        && spec.services().is_empty()
        && spec.resource_allocation() == Some(grant.claims().job_resource_allocation())
        && spec.windows_action_graph_sha256() == grant.claims().windows_action_graph_sha256()
        && spec.has_coherent_resource_contract();
    valid.then_some(()).ok_or_else(|| {
        provider_error(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::Validate,
            OperationOutcome::KnownNoEffect,
            None,
        )
    })
}

fn validate_handle(handle: &SandboxHandle, provider: &ProviderId) -> Result<(), ProviderError> {
    (handle.provider() == provider)
        .then_some(())
        .ok_or_else(|| {
            provider_error(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::Validate,
                OperationOutcome::KnownNoEffect,
                None,
            )
        })
}

fn map_provider_error(
    error: WindowsHyperVBrokerClientError,
    stage: ProviderStage,
    recovery: Option<SandboxHandle>,
) -> ProviderError {
    let outcome = match error.effect() {
        WindowsHyperVBrokerClientEffect::KnownNoEffect => OperationOutcome::KnownNoEffect,
        WindowsHyperVBrokerClientEffect::StateMayHaveChanged => OperationOutcome::Uncertain,
    };
    let kind = match error {
        WindowsHyperVBrokerClientError::Unavailable(_) => ProviderErrorKind::AdapterUnavailable,
        WindowsHyperVBrokerClientError::TimedOut(_) => ProviderErrorKind::TimedOut,
        WindowsHyperVBrokerClientError::Rejected(_) | WindowsHyperVBrokerClientError::Protocol => {
            ProviderErrorKind::BackendRejected
        }
    };
    provider_error(
        kind,
        stage,
        outcome,
        recovery.filter(|_| outcome == OperationOutcome::Uncertain),
    )
}

fn map_execution_error(
    error: WindowsHyperVBrokerClientError,
    stage: ExecutionStage,
) -> ExecutionError {
    let kind = match error {
        WindowsHyperVBrokerClientError::Unavailable(_) => ExecutionErrorKind::LocalStorage,
        WindowsHyperVBrokerClientError::TimedOut(_) => ExecutionErrorKind::TimedOut,
        WindowsHyperVBrokerClientError::Rejected(_) | WindowsHyperVBrokerClientError::Protocol => {
            ExecutionErrorKind::BackendRejected
        }
    };
    ExecutionError::new(kind, stage)
}

const fn provider_error(
    kind: ProviderErrorKind,
    stage: ProviderStage,
    outcome: OperationOutcome,
    recovery: Option<SandboxHandle>,
) -> ProviderError {
    ProviderError::new(kind, stage, outcome, recovery)
}

fn zero_digest(digest: Sha256Digest) -> bool {
    digest.as_bytes().iter().all(|byte| *byte == 0)
}

fn is_exact_windows_client_path(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    let bytes = value.as_bytes();
    if bytes.len() < 4
        || bytes.len() > 240
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'\\'
        || value.contains(['/', '%'])
    {
        return false;
    }
    let mut components = value[3..].split('\\').peekable();
    let mut basename = None;
    while let Some(component) = components.next() {
        let valid_component = !component.is_empty()
            && component != "."
            && component != ".."
            && !component.ends_with([' ', '.'])
            && !component
                .chars()
                .any(|character| character.is_control() || "<>:\"|?*".contains(character));
        if !valid_component {
            return false;
        }
        if components.peek().is_none() {
            basename = Some(component);
        }
    }
    basename.is_some_and(|component| {
        component.eq_ignore_ascii_case(WINDOWS_HYPERV_BROKER_CLIENT_BASENAME)
    })
}

#[cfg(windows)]
mod process_client {
    use std::{
        ffi::OsString,
        fs::{File, OpenOptions},
        io::Read as _,
        os::windows::fs::OpenOptionsExt as _,
        sync::Arc,
    };

    use crate::WindowsBrokerAdmissionCompletion;
    use automata_ci_core::UnixMillis;
    use automata_ci_execution::{
        EnvironmentVariable, ExecutionOutputRecord, ExecutionOutputStream, ExecutionTermination,
        ImmutableImage, TargetPlatform,
    };
    use automata_ci_protocol::{
        WindowsRunnerAdmissionEnvelope, WindowsRunnerPlacementRenewalEnvelope,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use serde::Deserialize;
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};
    use zeroize::{Zeroize as _, Zeroizing};

    use super::{
        Cancellation, CopyFromRequest, CopyToRequest, DestroyDisposition, DestroySandbox,
        EnvironmentProfile, ExecutionCommand, ExecutionOutput, OperationOutcome, ProviderError,
        ProviderErrorKind, ProviderStage, SandboxCustody, SandboxGeneration, SandboxHandle,
        SandboxLaunch, SandboxSpec, SandboxState, Sha256Digest, WindowsBrokerAdmissionReceipt,
        WindowsBrokerCustodyHandle, WindowsBrokerHostInputAttestation,
        WindowsBrokerHostInputRequest, WindowsBrokerPlacementRenewalReceipt,
        WindowsHyperVBrokerClient, WindowsHyperVBrokerClientEffect, WindowsHyperVBrokerClientError,
        WindowsHyperVBrokerProfileAttestation, WindowsHyperVBrokerProviderOptions,
        WindowsHyperVBrokerSandbox, WindowsRunnerAdmissionIssueRequest, fmt, provider_error,
    };
    use crate::{
        HostComputeObservedIsolation,
        command::{
            RuntimeCommandExecutor, RuntimeCommandRequest, RuntimeCommandTermination,
            SystemRuntimeCommandExecutor,
        },
    };

    const MAX_BROKER_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
    const FILE_SHARE_READ: u32 = 0x0000_0001;

    #[derive(Clone)]
    pub(super) struct ProcessWindowsHyperVBrokerClient {
        options: WindowsHyperVBrokerProviderOptions,
        executor: Arc<dyn RuntimeCommandExecutor>,
        _client_guard: Arc<File>,
    }

    impl ProcessWindowsHyperVBrokerClient {
        pub(super) fn open(
            options: WindowsHyperVBrokerProviderOptions,
        ) -> Result<Self, ProviderError> {
            let mut file = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .open(options.client_executable())
                .map_err(|_| invalid_client())?;
            let metadata = file.metadata().map_err(|_| invalid_client())?;
            if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 64 * 1024 * 1024 {
                return Err(invalid_client());
            }
            let mut digest = Sha256::new();
            let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
            loop {
                let read = file.read(&mut buffer).map_err(|_| invalid_client())?;
                if read == 0 {
                    break;
                }
                digest.update(&buffer[..read]);
            }
            if Sha256Digest::from_bytes(digest.finalize().into()) != options.client_sha256() {
                return Err(invalid_client());
            }
            Ok(Self {
                options,
                executor: Arc::new(SystemRuntimeCommandExecutor),
                _client_guard: Arc::new(file),
            })
        }

        fn call(
            &self,
            operation: &'static str,
            payload: &Value,
            cancellation: &dyn Cancellation,
        ) -> Result<Value, WindowsHyperVBrokerClientError> {
            let request = json!({
                "schema": 1,
                "operation": operation,
                "payload": payload,
            });
            let encoded = serde_json::to_vec(&request)
                .map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
            let request = RuntimeCommandRequest::new(
                self.options.client_executable().to_path_buf(),
                vec![OsString::from("request-v1")],
                self.options.operation_timeout(),
                MAX_BROKER_RESPONSE_BYTES,
            )
            .and_then(|request| request.with_stdin(encoded))
            .map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
            let output = self.executor.execute(&request, cancellation);
            match output.termination() {
                RuntimeCommandTermination::TimedOut => {
                    return Err(WindowsHyperVBrokerClientError::TimedOut(
                        WindowsHyperVBrokerClientEffect::StateMayHaveChanged,
                    ));
                }
                RuntimeCommandTermination::Cancelled => {
                    return Err(WindowsHyperVBrokerClientError::Unavailable(
                        WindowsHyperVBrokerClientEffect::StateMayHaveChanged,
                    ));
                }
                RuntimeCommandTermination::FailedToStart => {
                    return Err(WindowsHyperVBrokerClientError::Unavailable(
                        WindowsHyperVBrokerClientEffect::KnownNoEffect,
                    ));
                }
                RuntimeCommandTermination::Exited(_) => {}
            }
            if !output.succeeded()
                || !output.stderr().is_empty()
                || !output.stdin_was_fully_written()
                || output.was_truncated()
            {
                return Err(WindowsHyperVBrokerClientError::Unavailable(
                    WindowsHyperVBrokerClientEffect::StateMayHaveChanged,
                ));
            }
            let response: WireResponse = serde_json::from_slice(output.stdout())
                .map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
            if response.schema != 1 {
                return Err(WindowsHyperVBrokerClientError::Protocol);
            }
            if response.ok {
                response
                    .payload
                    .ok_or(WindowsHyperVBrokerClientError::Protocol)
            } else {
                Err(WindowsHyperVBrokerClientError::Rejected(response.effect()))
            }
        }
    }

    impl fmt::Debug for ProcessWindowsHyperVBrokerClient {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("ProcessWindowsHyperVBrokerClient")
                .field("client_executable", &self.options.client_executable())
                .field("host_id", &self.options.host_id())
                .finish_non_exhaustive()
        }
    }

    impl WindowsHyperVBrokerClient for ProcessWindowsHyperVBrokerClient {
        fn create(
            &self,
            spec: &SandboxSpec,
            cancellation: &dyn Cancellation,
        ) -> Result<WindowsHyperVBrokerSandbox, WindowsHyperVBrokerClientError> {
            let grant = spec
                .windows_hyperv_broker_grant()
                .ok_or(WindowsHyperVBrokerClientError::Protocol)?;
            let SandboxLaunch::WindowsHyperVContainer { image, keepalive } =
                spec.profile().launch()
            else {
                return Err(WindowsHyperVBrokerClientError::Protocol);
            };
            let allocation = spec
                .resource_allocation()
                .ok_or(WindowsHyperVBrokerClientError::Protocol)?;
            let payload = json!({
                "operation_id": spec.operation_id(),
                "generation": spec.generation().get(),
                "custody": spec.custody(),
                "profile": spec.profile().attestation(),
                "image_reference": image.reference(),
                "image_digest": image.digest(),
                "keepalive": argv_value(keepalive),
                "profile_workspace": spec.profile().workspace().as_str(),
                "default_environment": environment_value(spec.profile().default_environment().values()),
                "workspace": spec.workspace().as_str(),
                "network": "disabled",
                "root_filesystem": "writable",
                "privilege": "unprivileged",
                "resources": resources_value(spec.resources()),
                "resource_requests": capacity_value(allocation.requests()),
                "resource_limits": capacity_value(allocation.limits()),
                "windows_action_graph_sha256": spec.windows_action_graph_sha256(),
                "grant": grant,
            });
            sandbox_from_value(self.call("create", &payload, cancellation)?)
        }

        fn attach(
            &self,
            handle: &SandboxHandle,
            cancellation: &dyn Cancellation,
        ) -> Result<(), WindowsHyperVBrokerClientError> {
            self.call("attach", &handle_value(handle), cancellation)
                .map(|_| ())
        }

        fn inspect(
            &self,
            handle: &SandboxHandle,
            cancellation: &dyn Cancellation,
        ) -> Result<WindowsHyperVBrokerSandbox, WindowsHyperVBrokerClientError> {
            sandbox_from_value(self.call("inspect", &handle_value(handle), cancellation)?)
        }

        fn exec(
            &self,
            handle: &SandboxHandle,
            request: &ExecutionCommand,
            cancellation: &dyn Cancellation,
        ) -> Result<ExecutionOutput, WindowsHyperVBrokerClientError> {
            if request
                .environment()
                .values()
                .iter()
                .any(EnvironmentVariable::is_secret)
            {
                return Err(WindowsHyperVBrokerClientError::Rejected(
                    WindowsHyperVBrokerClientEffect::KnownNoEffect,
                ));
            }
            let payload = json!({
                "handle": handle.opaque(),
                "operation_id": request.operation_id(),
                "argv": argv_value(request.argv()),
                "working_directory": request.working_directory().as_str(),
                "environment": environment_value(request.environment().values()),
                "timeout_millis": u64::try_from(request.timeout().as_millis()).map_err(|_| WindowsHyperVBrokerClientError::Protocol)?,
                "output_limit": request.output_limit(),
            });
            output_from_value(
                self.call("exec", &payload, cancellation)?,
                request.output_limit(),
            )
        }

        fn copy_to(
            &self,
            handle: &SandboxHandle,
            request: &CopyToRequest,
            cancellation: &dyn Cancellation,
        ) -> Result<(), WindowsHyperVBrokerClientError> {
            self.call(
                "copy_to",
                &json!({
                    "handle": handle.opaque(),
                    "operation_id": request.operation_id(),
                    "target": request.target().as_str(),
                    "content_base64": BASE64.encode(request.content()),
                }),
                cancellation,
            )
            .map(|_| ())
        }

        fn copy_from(
            &self,
            handle: &SandboxHandle,
            request: &CopyFromRequest,
            cancellation: &dyn Cancellation,
        ) -> Result<Vec<u8>, WindowsHyperVBrokerClientError> {
            let value = self.call(
                "copy_from",
                &json!({
                    "handle": handle.opaque(),
                    "operation_id": request.operation_id(),
                    "source": request.source().as_str(),
                    "byte_limit": request.byte_limit(),
                }),
                cancellation,
            )?;
            let encoded = value
                .get("content_base64")
                .and_then(Value::as_str)
                .ok_or(WindowsHyperVBrokerClientError::Protocol)?;
            let bytes = BASE64
                .decode(encoded)
                .map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
            if bytes.len() > request.byte_limit() {
                return Err(WindowsHyperVBrokerClientError::Protocol);
            }
            Ok(bytes)
        }

        fn destroy(
            &self,
            request: &DestroySandbox,
            cancellation: &dyn Cancellation,
        ) -> Result<DestroyDisposition, WindowsHyperVBrokerClientError> {
            let value = self.call(
                "destroy",
                &json!({
                    "handle": request.handle().opaque(),
                    "operation_id": request.operation_id(),
                    "generation": request.generation().get(),
                    "custody": request.custody(),
                }),
                cancellation,
            )?;
            match value.get("disposition").and_then(Value::as_str) {
                Some("destroyed") => Ok(DestroyDisposition::Destroyed),
                Some("already_absent") => Ok(DestroyDisposition::AlreadyAbsent),
                _ => Err(WindowsHyperVBrokerClientError::Protocol),
            }
        }

        fn attest_profile(
            &self,
            profile: &EnvironmentProfile,
            image: &ImmutableImage,
            cancellation: &dyn Cancellation,
        ) -> Result<WindowsHyperVBrokerProfileAttestation, WindowsHyperVBrokerClientError> {
            let value = self.call(
                "attest_profile",
                &json!({
                    "profile": profile,
                    "image_reference": image.reference(),
                    "image_digest": image.digest(),
                }),
                cancellation,
            )?;
            attestation_from_value(value, self.options.host_id(), profile, image.digest())
        }

        fn attest_host_inputs(
            &self,
            request: &WindowsBrokerHostInputRequest,
            cancellation: &dyn Cancellation,
        ) -> Result<WindowsBrokerHostInputAttestation, WindowsHyperVBrokerClientError> {
            let payload = serde_json::to_value(request)
                .map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
            let value = self.call("attest_host_inputs", &payload, cancellation)?;
            let attestation: WindowsBrokerHostInputAttestation = serde_json::from_value(value)
                .map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
            attestation
                .validate_for(request, self.options.host_id())
                .map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
            Ok(attestation)
        }

        fn admission_issue(
            &self,
            request: &WindowsRunnerAdmissionIssueRequest,
            observed_at: UnixMillis,
            cancellation: &dyn Cancellation,
        ) -> Result<WindowsBrokerAdmissionReceipt, WindowsHyperVBrokerClientError> {
            let expected_request_sha256 = request
                .request_sha256()
                .map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
            let mut canonical = Zeroizing::new(
                request
                    .canonical_bytes()
                    .map_err(|_| WindowsHyperVBrokerClientError::Protocol)?,
            );
            let encoded = BASE64.encode(&canonical[..]);
            canonical.zeroize();
            admission_receipt_from_value(
                self.call(
                    "admission_issue",
                    &json!({"request_base64": encoded}),
                    cancellation,
                )?,
                expected_request_sha256,
                observed_at,
            )
        }

        fn admission_resume(
            &self,
            handle: &WindowsBrokerCustodyHandle,
            request_sha256: Sha256Digest,
            observed_at: UnixMillis,
            cancellation: &dyn Cancellation,
        ) -> Result<WindowsBrokerAdmissionReceipt, WindowsHyperVBrokerClientError> {
            let receipt = admission_receipt_from_value(
                self.call(
                    "admission_resume",
                    &json!({
                        "handle": handle.opaque(),
                        "request_sha256": request_sha256,
                    }),
                    cancellation,
                )?,
                request_sha256,
                observed_at,
            )?;
            if receipt.handle() != handle {
                return Err(WindowsHyperVBrokerClientError::Protocol);
            }
            Ok(receipt)
        }

        fn admission_complete(
            &self,
            completion: &WindowsBrokerAdmissionCompletion,
            cancellation: &dyn Cancellation,
        ) -> Result<(), WindowsHyperVBrokerClientError> {
            self.call(
                "admission_complete",
                &json!({
                    "handle": completion.handle().opaque(),
                    "envelope_sha256": completion.envelope_sha256(),
                }),
                cancellation,
            )
            .map(|_| ())
        }

        fn admission_renew(
            &self,
            completed_handle: &WindowsBrokerCustodyHandle,
            enrollment_envelope_sha256: Sha256Digest,
            observed_at: UnixMillis,
            cancellation: &dyn Cancellation,
        ) -> Result<WindowsBrokerPlacementRenewalReceipt, WindowsHyperVBrokerClientError> {
            placement_renewal_receipt_from_value(
                self.call(
                    "admission_renew",
                    &json!({
                        "handle": completed_handle.opaque(),
                        "enrollment_envelope_sha256": enrollment_envelope_sha256,
                    }),
                    cancellation,
                )?,
                enrollment_envelope_sha256,
                observed_at,
            )
        }

        fn admission_renew_ack(
            &self,
            completed_handle: &WindowsBrokerCustodyHandle,
            renewal_envelope_sha256: Sha256Digest,
            cancellation: &dyn Cancellation,
        ) -> Result<(), WindowsHyperVBrokerClientError> {
            self.call(
                "admission_renew_ack",
                &json!({
                    "handle": completed_handle.opaque(),
                    "renewal_envelope_sha256": renewal_envelope_sha256,
                }),
                cancellation,
            )
            .map(|_| ())
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct WireResponse {
        pub(super) schema: u16,
        pub(super) ok: bool,
        #[serde(default)]
        pub(super) effect: Option<String>,
        #[serde(default)]
        pub(super) payload: Option<Value>,
    }

    impl WireResponse {
        fn effect(&self) -> WindowsHyperVBrokerClientEffect {
            match self.effect.as_deref() {
                Some("known_no_effect") => WindowsHyperVBrokerClientEffect::KnownNoEffect,
                _ => WindowsHyperVBrokerClientEffect::StateMayHaveChanged,
            }
        }
    }

    fn invalid_client() -> ProviderError {
        provider_error(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::Validate,
            OperationOutcome::KnownNoEffect,
            None,
        )
    }

    fn handle_value(handle: &SandboxHandle) -> Value {
        json!({"handle": handle.opaque()})
    }

    fn argv_value(argv: &automata_ci_execution::ExecutionArgv) -> Value {
        json!({
            "program": argv.program().as_str(),
            "platform": match argv.program().platform() {
                TargetPlatform::Windows => "windows",
                TargetPlatform::Posix => "posix",
            },
            "arguments": argv.arguments(),
        })
    }

    fn environment_value(values: &[EnvironmentVariable]) -> Value {
        Value::Array(
            values
                .iter()
                .map(|variable| {
                    json!({
                        "name": variable.name().as_str(),
                        "value": variable.value().expose(),
                        "secret": variable.is_secret(),
                    })
                })
                .collect(),
        )
    }

    fn resources_value(resources: automata_ci_execution::ResourceLimits) -> Value {
        json!({
            "memory_bytes": resources.memory_bytes(),
            "cpu_millis": resources.cpu_millis(),
            "pids": resources.pids(),
        })
    }

    fn capacity_value(capacity: automata_ci_core::ResourceCapacity) -> Value {
        json!({
            "memory_bytes": capacity.memory_bytes(),
            "cpu_millis": capacity.cpu_millis(),
            "ephemeral_disk_bytes": capacity.ephemeral_disk_bytes(),
            "gpu_count": capacity.gpu_count(),
        })
    }

    fn sandbox_from_value(
        value: Value,
    ) -> Result<WindowsHyperVBrokerSandbox, WindowsHyperVBrokerClientError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SandboxValue {
            handle: String,
            generation: u64,
            custody: SandboxCustody,
            profile: EnvironmentProfile,
            state: String,
        }
        let value: SandboxValue =
            serde_json::from_value(value).map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
        let generation = SandboxGeneration::new(value.generation)
            .map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
        let state = match value.state.as_str() {
            "absent" => SandboxState::Absent,
            "created" => SandboxState::Created,
            "running" => SandboxState::Running,
            "stopped" => SandboxState::Stopped,
            "degraded" => SandboxState::Degraded,
            _ => return Err(WindowsHyperVBrokerClientError::Protocol),
        };
        WindowsHyperVBrokerSandbox::new(
            value.handle,
            generation,
            value.custody,
            value.profile,
            state,
        )
    }

    fn output_from_value(
        value: Value,
        request_limit: usize,
    ) -> Result<ExecutionOutput, WindowsHyperVBrokerClientError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct OutputValue {
            termination: String,
            #[serde(default)]
            exit_code: Option<i32>,
            records: Vec<RecordValue>,
            truncated: bool,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RecordValue {
            stream: String,
            #[serde(default)]
            bytes_base64: Option<String>,
            end_of_stream: bool,
        }
        let value: OutputValue =
            serde_json::from_value(value).map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
        let termination = match (value.termination.as_str(), value.exit_code) {
            ("exited", Some(code)) => ExecutionTermination::Exited(code),
            ("signalled", None) => ExecutionTermination::Signalled,
            ("timed_out", None) => ExecutionTermination::TimedOut,
            ("cancelled", None) => ExecutionTermination::Cancelled,
            _ => return Err(WindowsHyperVBrokerClientError::Protocol),
        };
        let mut bytes = 0_usize;
        let mut records = Vec::with_capacity(value.records.len());
        for record in value.records {
            let stream = match record.stream.as_str() {
                "stdout" => ExecutionOutputStream::Stdout,
                "stderr" => ExecutionOutputStream::Stderr,
                _ => return Err(WindowsHyperVBrokerClientError::Protocol),
            };
            let output_record = if record.end_of_stream {
                if record.bytes_base64.is_some() {
                    return Err(WindowsHyperVBrokerClientError::Protocol);
                }
                ExecutionOutputRecord::end_of_stream(stream)
            } else {
                let decoded = BASE64
                    .decode(
                        record
                            .bytes_base64
                            .ok_or(WindowsHyperVBrokerClientError::Protocol)?,
                    )
                    .map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
                bytes = bytes
                    .checked_add(decoded.len())
                    .ok_or(WindowsHyperVBrokerClientError::Protocol)?;
                ExecutionOutputRecord::data(stream, decoded)
                    .map_err(|_| WindowsHyperVBrokerClientError::Protocol)?
            };
            records.push(output_record);
        }
        if bytes > request_limit {
            return Err(WindowsHyperVBrokerClientError::Protocol);
        }
        ExecutionOutput::new(termination, records, value.truncated)
            .map_err(|_| WindowsHyperVBrokerClientError::Protocol)
    }

    fn attestation_from_value(
        value: Value,
        expected_host_id: Sha256Digest,
        expected_profile: &EnvironmentProfile,
        expected_image_digest: Sha256Digest,
    ) -> Result<WindowsHyperVBrokerProfileAttestation, WindowsHyperVBrokerClientError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct AttestationValue {
            host_id: Sha256Digest,
            profile: EnvironmentProfile,
            image_digest: Sha256Digest,
            isolation: HostComputeObservedIsolation,
            network_disabled: bool,
            issued_at: UnixMillis,
            valid_until: UnixMillis,
            digest: Sha256Digest,
        }
        let value: AttestationValue =
            serde_json::from_value(value).map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
        if value.host_id != expected_host_id
            || value.profile != *expected_profile
            || value.image_digest != expected_image_digest
        {
            return Err(WindowsHyperVBrokerClientError::Protocol);
        }
        WindowsHyperVBrokerProfileAttestation::from_wire(
            value.host_id,
            value.profile,
            value.image_digest,
            value.isolation,
            value.network_disabled,
            value.issued_at,
            value.valid_until,
            value.digest,
        )
        .map_err(|_| WindowsHyperVBrokerClientError::Protocol)
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AdmissionReceiptValue {
        handle: String,
        envelope: WindowsRunnerAdmissionEnvelope,
        envelope_sha256: Sha256Digest,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PlacementRenewalReceiptValue {
        envelope: WindowsRunnerPlacementRenewalEnvelope,
        envelope_sha256: Sha256Digest,
    }

    fn admission_receipt_from_value(
        value: Value,
        expected_request_sha256: Sha256Digest,
        observed_at: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsHyperVBrokerClientError> {
        let value: AdmissionReceiptValue =
            serde_json::from_value(value).map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
        let handle = WindowsBrokerCustodyHandle::parse(&value.handle)
            .map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
        let receipt = WindowsBrokerAdmissionReceipt::from_wire(
            handle,
            value.envelope,
            expected_request_sha256,
            observed_at,
        )
        .map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
        if receipt.envelope_sha256() != value.envelope_sha256 {
            return Err(WindowsHyperVBrokerClientError::Protocol);
        }
        Ok(receipt)
    }

    fn placement_renewal_receipt_from_value(
        value: Value,
        expected_enrollment_envelope_sha256: Sha256Digest,
        observed_at: UnixMillis,
    ) -> Result<WindowsBrokerPlacementRenewalReceipt, WindowsHyperVBrokerClientError> {
        let value: PlacementRenewalReceiptValue =
            serde_json::from_value(value).map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
        let receipt = WindowsBrokerPlacementRenewalReceipt::from_wire(
            value.envelope,
            expected_enrollment_envelope_sha256,
            observed_at,
        )
        .map_err(|_| WindowsHyperVBrokerClientError::Protocol)?;
        if receipt.envelope_sha256() != value.envelope_sha256 {
            return Err(WindowsHyperVBrokerClientError::Protocol);
        }
        Ok(receipt)
    }
}

#[cfg(windows)]
use process_client::ProcessWindowsHyperVBrokerClient;

#[cfg(all(windows, test))]
pub(crate) fn decode_client_wire_response_for_test(
    encoded: &[u8],
) -> Result<(u16, bool, Option<String>, Option<serde_json::Value>), serde_json::Error> {
    let response: process_client::WireResponse = serde_json::from_slice(encoded)?;
    Ok((
        response.schema,
        response.ok,
        response.effect,
        response.payload,
    ))
}

#[cfg(test)]
mod capability_tests {
    use std::sync::Mutex;

    use automata_ci_core::{EnvironmentProfileId, OperationId, RunnerId};
    use automata_ci_execution::NeverCancelled;

    use super::*;

    #[derive(Debug)]
    struct LifecycleClient {
        sandbox: WindowsHyperVBrokerSandbox,
        calls: Mutex<Vec<&'static str>>,
    }

    impl LifecycleClient {
        fn record(&self, call: &'static str) {
            self.calls.lock().expect("call ledger lock").push(call);
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().expect("call ledger lock").clone()
        }
    }

    impl WindowsHyperVBrokerClient for LifecycleClient {
        fn create(
            &self,
            _spec: &SandboxSpec,
            _cancellation: &dyn Cancellation,
        ) -> Result<WindowsHyperVBrokerSandbox, WindowsHyperVBrokerClientError> {
            panic!("create is outside this recovery lifecycle fixture")
        }

        fn attach(
            &self,
            handle: &SandboxHandle,
            _cancellation: &dyn Cancellation,
        ) -> Result<(), WindowsHyperVBrokerClientError> {
            assert_eq!(handle.opaque(), self.sandbox.handle);
            self.record("attach");
            Ok(())
        }

        fn inspect(
            &self,
            handle: &SandboxHandle,
            _cancellation: &dyn Cancellation,
        ) -> Result<WindowsHyperVBrokerSandbox, WindowsHyperVBrokerClientError> {
            assert_eq!(handle.opaque(), self.sandbox.handle);
            self.record("inspect");
            Ok(self.sandbox.clone())
        }

        fn exec(
            &self,
            _handle: &SandboxHandle,
            _request: &ExecutionCommand,
            _cancellation: &dyn Cancellation,
        ) -> Result<ExecutionOutput, WindowsHyperVBrokerClientError> {
            panic!("exec is outside this recovery lifecycle fixture")
        }

        fn copy_to(
            &self,
            _handle: &SandboxHandle,
            _request: &CopyToRequest,
            _cancellation: &dyn Cancellation,
        ) -> Result<(), WindowsHyperVBrokerClientError> {
            panic!("copy_to is outside this recovery lifecycle fixture")
        }

        fn copy_from(
            &self,
            _handle: &SandboxHandle,
            _request: &CopyFromRequest,
            _cancellation: &dyn Cancellation,
        ) -> Result<Vec<u8>, WindowsHyperVBrokerClientError> {
            panic!("copy_from is outside this recovery lifecycle fixture")
        }

        fn destroy(
            &self,
            request: &DestroySandbox,
            _cancellation: &dyn Cancellation,
        ) -> Result<DestroyDisposition, WindowsHyperVBrokerClientError> {
            assert_eq!(request.handle().opaque(), self.sandbox.handle);
            assert_eq!(request.generation(), self.sandbox.generation);
            assert_eq!(request.custody(), self.sandbox.custody);
            self.record("destroy");
            Ok(DestroyDisposition::Destroyed)
        }

        fn attest_profile(
            &self,
            _profile: &EnvironmentProfile,
            _image: &ImmutableImage,
            _cancellation: &dyn Cancellation,
        ) -> Result<WindowsHyperVBrokerProfileAttestation, WindowsHyperVBrokerClientError> {
            panic!("profile attestation is outside this recovery lifecycle fixture")
        }

        fn attest_host_inputs(
            &self,
            _request: &WindowsBrokerHostInputRequest,
            _cancellation: &dyn Cancellation,
        ) -> Result<WindowsBrokerHostInputAttestation, WindowsHyperVBrokerClientError> {
            panic!("host-input attestation is outside this recovery lifecycle fixture")
        }
    }

    #[test]
    fn production_broker_surface_never_advertises_unimplemented_authority_or_egress() {
        for forbidden in [
            SandboxCapability::EnvironmentInjection,
            SandboxCapability::PrivateEgress,
        ] {
            assert!(!BROKER_PROVIDER_CAPABILITIES.contains(&forbidden));
            assert!(!BROKER_ENDPOINT_CAPABILITIES.contains(&forbidden));
        }
    }

    #[test]
    fn fake_client_recovery_lifecycle_preserves_exact_broker_ownership() {
        let host_id = Sha256Digest::from_bytes([1_u8; 32]);
        let options = WindowsHyperVBrokerProviderOptions::new(
            r"C:\Automata\automata-windows-hyperv-broker-client.exe",
            Sha256Digest::from_bytes([2_u8; 32]),
            host_id,
        )
        .expect("provider options");
        let generation = SandboxGeneration::new(7).expect("generation");
        let custody = SandboxCustody::ProfileAdmission {
            runner_id: RunnerId::new(),
        };
        let profile = EnvironmentProfile::new(
            EnvironmentProfileId::new("example.com/windows-hyperv").expect("profile id"),
            Sha256Digest::from_bytes([3_u8; 32]),
        );
        let client = Arc::new(LifecycleClient {
            sandbox: WindowsHyperVBrokerSandbox::new(
                "opaque-ticket",
                generation,
                custody,
                profile.clone(),
                SandboxState::Running,
            )
            .expect("broker sandbox"),
            calls: Mutex::new(Vec::new()),
        });
        let provider = WindowsHyperVBrokerProvider::open_with_client(
            options,
            client.clone() as Arc<dyn WindowsHyperVBrokerClient>,
        )
        .expect("provider");
        let handle = SandboxHandle::new(
            ProviderId::new(WINDOWS_HYPERV_PROVIDER_ID).expect("provider id"),
            "opaque-ticket",
        )
        .expect("sandbox handle");

        let inspection = provider
            .inspect(&handle, &NeverCancelled)
            .expect("inspect through provider");
        assert_eq!(inspection.handle(), &handle);
        assert_eq!(inspection.generation(), generation);
        assert_eq!(inspection.custody(), custody);
        assert_eq!(inspection.profile(), &profile);
        assert_eq!(inspection.state(), SandboxState::Running);

        let endpoint = provider
            .attach(&handle, &NeverCancelled)
            .expect("attach through provider");
        assert_eq!(endpoint.handle(), &handle);
        let destroy = DestroySandbox::new(OperationId::new(), handle, generation, custody);
        assert_eq!(
            provider
                .destroy(&destroy, &NeverCancelled)
                .expect("destroy through provider"),
            DestroyDisposition::Destroyed
        );
        assert_eq!(client.calls(), ["inspect", "attach", "destroy"]);
    }
}
