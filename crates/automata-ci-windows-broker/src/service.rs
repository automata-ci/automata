//! Restricted, grant-gated Windows Hyper-V host-compute lifecycle.
//!
//! The broker surface contains no caller-selectable process-isolation or
//! full-virtual-machine route. Its adapter receives a closed Hyper-V request
//! only after an Ed25519 grant has been verified and durably consumed.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    num::NonZeroU16,
    sync::{
        Arc, Condvar, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use automata_ci_core::{
    EnvironmentProfile, OperationId, RunnerId, RunnerSessionId, Sha256Digest, UnixMillis,
    WindowsHyperVBrokerGrant,
};
use automata_ci_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, ExecutionArgv, ExecutionCommand, ExecutionOutput,
    ExecutionOutputRecord, ExecutionOutputStream, ExecutionTermination, ImmutableImage,
    MAX_COPY_BYTES, MAX_ENDPOINT_OPERATIONS_PER_JOB, MAX_EXECUTION_OUTPUT_BYTES,
    MAX_EXECUTION_OUTPUT_RECORDS, NetworkPolicy, ResourceLimits, RootFilesystemPolicy,
    SandboxCustody, SandboxEnvironment, SandboxGeneration, SandboxLaunch, SandboxPrivilegePolicy,
    SandboxSpec, TargetPath,
};
use automata_ci_runner_spool::{ContentKind, DurableContentRef};
use ring::signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

mod file_ledger;
mod result_store;

pub use file_ledger::FileBrokerLedger;
#[cfg(test)]
use file_ledger::ledger_sidecar_paths;
pub use result_store::ProtectedBrokerResultStore;

const RESOURCE_DOMAIN: &[u8] = b"automata.windows-hyperv-resource.v1\0";
const TICKET_DOMAIN: &[u8] = b"automata.windows-hyperv-ticket.v2\0";
const SPEC_DOMAIN: &[u8] = b"automata.windows-hyperv-spec.v3\0";
const PROCESS_DOMAIN: &[u8] = b"automata.windows-hyperv-process.v1\0";
const EXEC_REQUEST_DOMAIN: &[u8] = b"automata.windows-hyperv-exec-request.v1\0";
const COPY_TO_REQUEST_DOMAIN: &[u8] = b"automata.windows-hyperv-copy-to-request.v1\0";
const COPY_FROM_REQUEST_DOMAIN: &[u8] = b"automata.windows-hyperv-copy-from-request.v1\0";
const PROFILE_ATTESTATION_DOMAIN: &[u8] = b"automata.windows-hyperv-profile-attestation.v1\0";
const LEDGER_DOMAIN: &[u8] = b"automata.windows-hyperv-broker-ledger.v3\0";
const RESULT_HEADER: &[u8] = b"automata.windows-hyperv-broker-result\0";
const RESULT_SCHEMA_VERSION: u16 = 1;
const RESULT_RECORD_METADATA_BYTES: usize = 6;
const MAX_LEDGER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LEDGER_EVENTS: usize = 100_000;
const LEDGER_TOMBSTONE_CLOCK_SKEW_MILLIS: i64 = 5 * 60 * 1_000;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;

/// Whether a failed adapter call is proven not to have changed host state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerAdapterEffect {
    /// The adapter proves that the requested mutation had no effect.
    KnownNoEffect,
    /// The host may have changed and must be inspected before another action.
    StateMayHaveChanged,
}

/// Exact host-compute operation which failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostComputeOperation {
    /// Attest that a digest-pinned image is admissible on the fixed engine.
    AttestProfile,
    /// Create one Hyper-V-isolated compute system.
    Create,
    /// Inspect one exact compute-system identity.
    Inspect,
    /// Attach an execution channel to one exact compute system.
    Attach,
    /// Create and wait for one guest process.
    Exec,
    /// Copy bounded bytes into the guest.
    CopyTo,
    /// Copy bounded bytes out of the guest.
    CopyFrom,
    /// Terminate descendants owned by one compute system.
    TerminateDescendants,
    /// Destroy one exact compute system.
    Destroy,
    /// Enumerate only broker-owned compute systems.
    ListOwned,
}

/// Closed profile-admission request passed to the host engine adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostComputeProfileRequest {
    profile: EnvironmentProfile,
    image: ImmutableImage,
}

impl HostComputeProfileRequest {
    /// Constructs the closed profile observation request used by a privileged host adapter.
    #[must_use]
    pub const fn new(profile: EnvironmentProfile, image: ImmutableImage) -> Self {
        Self { profile, image }
    }

    /// Returns the exact profile being admitted.
    #[must_use]
    pub const fn profile(&self) -> &EnvironmentProfile {
        &self.profile
    }

    /// Returns the digest-qualified Windows image being admitted.
    #[must_use]
    pub const fn image(&self) -> &ImmutableImage {
        &self.image
    }
}

/// Effective engine observation used to issue a broker profile attestation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostComputeProfileObservation {
    image_digest: Sha256Digest,
    isolation: HostComputeObservedIsolation,
    network_disabled: bool,
    windows_amd64: bool,
}

impl HostComputeProfileObservation {
    /// Constructs a complete effective profile observation.
    #[must_use]
    pub const fn new(
        image_digest: Sha256Digest,
        isolation: HostComputeObservedIsolation,
        network_disabled: bool,
        windows_amd64: bool,
    ) -> Self {
        Self {
            image_digest,
            isolation,
            network_disabled,
            windows_amd64,
        }
    }

    /// Returns the digest observed for the exact requested image.
    #[must_use]
    pub const fn image_digest(&self) -> Sha256Digest {
        self.image_digest
    }
}

/// Fresh, value-free attestation issued by the authenticated broker service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsHyperVBrokerProfileAttestation {
    host_id: Sha256Digest,
    profile: EnvironmentProfile,
    image_digest: Sha256Digest,
    isolation: HostComputeObservedIsolation,
    network_disabled: bool,
    issued_at: UnixMillis,
    valid_until: UnixMillis,
    digest: Sha256Digest,
}

/// Broker-owned durable profile contract resolved from a signed admission receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsHyperVAdmittedProfileContract {
    host_id: Sha256Digest,
    profile_contract_sha256: Sha256Digest,
    profile: SandboxEnvironment,
    valid_until: UnixMillis,
}

impl WindowsHyperVAdmittedProfileContract {
    /// Constructs a contract only after broker-side input/promotion/probe verification.
    ///
    /// # Errors
    ///
    /// Rejects zero identities or an empty validity horizon. The trusted
    /// resolver remains responsible for proving the digest was broker-minted.
    pub fn new(
        host_id: Sha256Digest,
        profile_contract_sha256: Sha256Digest,
        profile: SandboxEnvironment,
        valid_until: UnixMillis,
    ) -> Result<Self, BrokerError> {
        let is_windows_hyperv = matches!(
            profile.launch(),
            SandboxLaunch::WindowsHyperVContainer { .. }
        );
        if is_zero_digest(host_id)
            || is_zero_digest(profile_contract_sha256)
            || is_zero_digest(profile.attestation().digest())
            || !is_windows_hyperv
            || profile
                .default_environment()
                .values()
                .iter()
                .any(automata_ci_execution::EnvironmentVariable::is_secret)
            || valid_until.get() <= 0
        {
            return Err(BrokerError::InvalidProfileContract);
        }
        Ok(Self {
            host_id,
            profile_contract_sha256,
            profile,
            valid_until,
        })
    }

    /// Returns the broker host that minted this contract.
    #[must_use]
    pub const fn host_id(&self) -> Sha256Digest {
        self.host_id
    }

    /// Returns the exact signed receipt evidence identity.
    #[must_use]
    pub const fn profile_contract_sha256(&self) -> Sha256Digest {
        self.profile_contract_sha256
    }

    /// Returns the exact broker-admitted launch profile.
    #[must_use]
    pub const fn profile(&self) -> &SandboxEnvironment {
        &self.profile
    }

    /// Returns the exclusive freshness horizon.
    #[must_use]
    pub const fn valid_until(&self) -> UnixMillis {
        self.valid_until
    }
}

/// Trusted durable resolver for broker-minted profile contracts.
pub trait BrokerProfileContractResolver: fmt::Debug + Send + Sync {
    /// Resolves an exact digest without consulting runner-owned configuration.
    ///
    /// # Errors
    ///
    /// Fails closed on corrupt or unavailable durable state.
    fn resolve(
        &self,
        profile_contract_sha256: Sha256Digest,
    ) -> Result<Option<WindowsHyperVAdmittedProfileContract>, BrokerError>;
}

impl WindowsHyperVBrokerProfileAttestation {
    /// Returns the exact broker host identity.
    #[must_use]
    pub const fn host_id(&self) -> Sha256Digest {
        self.host_id
    }

    /// Returns the admitted environment profile.
    #[must_use]
    pub const fn profile(&self) -> &EnvironmentProfile {
        &self.profile
    }

    /// Returns the admitted immutable image digest.
    #[must_use]
    pub const fn image_digest(&self) -> Sha256Digest {
        self.image_digest
    }

    /// Returns the proved isolation mode.
    #[must_use]
    pub const fn isolation(&self) -> HostComputeObservedIsolation {
        self.isolation
    }

    /// Reports whether the fixed engine path proved networking disabled.
    #[must_use]
    pub const fn network_disabled(&self) -> bool {
        self.network_disabled
    }

    /// Returns the trusted broker issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> UnixMillis {
        self.issued_at
    }

    /// Returns the exclusive freshness deadline.
    #[must_use]
    pub const fn valid_until(&self) -> UnixMillis {
        self.valid_until
    }

    /// Returns the canonical value-free attestation digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// Secret-free failure returned by the HCS adapter boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Windows host-compute adapter operation failed")]
pub struct HostComputeAdapterError {
    operation: HostComputeOperation,
    effect: BrokerAdapterEffect,
}

impl HostComputeAdapterError {
    /// Constructs a typed, non-textual adapter failure.
    #[must_use]
    pub const fn new(operation: HostComputeOperation, effect: BrokerAdapterEffect) -> Self {
        Self { operation, effect }
    }

    /// Returns the adapter boundary which failed.
    #[must_use]
    pub const fn operation(self) -> HostComputeOperation {
        self.operation
    }

    /// Returns whether host state may have changed.
    #[must_use]
    pub const fn effect(self) -> BrokerAdapterEffect {
        self.effect
    }
}

/// Effective isolation observed for an existing compute system.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostComputeObservedIsolation {
    /// HCS reports the required utility-VM-backed Hyper-V isolation.
    HyperV,
    /// HCS reports forbidden shared-kernel process isolation.
    Process,
    /// HCS could not prove either isolation mode.
    Unknown,
}

/// Effective lifecycle state observed for an existing compute system.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostComputeObservedState {
    /// The compute system exists and can be attached.
    Created,
    /// At least one broker-owned process is running.
    Running,
    /// The compute system exists with no running primary process.
    Stopped,
    /// HCS reports a degraded or indeterminate state.
    Degraded,
}

/// Closed create request accepted by the host-compute adapter.
///
/// The type has no isolation selector: every instance means Hyper-V isolation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostComputeCreateRequest {
    resource_id: String,
    grant_digest: Sha256Digest,
    spec_digest: Sha256Digest,
    operation_id: OperationId,
    generation: SandboxGeneration,
    custody: SandboxCustody,
    profile: EnvironmentProfile,
    image: ImmutableImage,
    keepalive: ExecutionArgv,
    workspace: TargetPath,
    resources: ResourceLimits,
}

impl HostComputeCreateRequest {
    /// Returns the deterministic broker-owned HCS identity.
    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    /// Returns the digest of the consumed signed grant.
    #[must_use]
    pub const fn grant_digest(&self) -> Sha256Digest {
        self.grant_digest
    }

    /// Returns the exact replay fingerprint of the sandbox request.
    #[must_use]
    pub const fn spec_digest(&self) -> Sha256Digest {
        self.spec_digest
    }

    /// Returns the idempotent create operation.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the lease-derived generation fence.
    #[must_use]
    pub const fn generation(&self) -> SandboxGeneration {
        self.generation
    }

    /// Returns the exact runner and slot custody carried by the signed grant.
    #[must_use]
    pub const fn custody(&self) -> SandboxCustody {
        self.custody
    }

    /// Returns the exact admitted environment profile.
    #[must_use]
    pub const fn profile(&self) -> &EnvironmentProfile {
        &self.profile
    }

    /// Returns the immutable Windows image.
    #[must_use]
    pub const fn image(&self) -> &ImmutableImage {
        &self.image
    }

    /// Returns the literal in-guest keepalive argv.
    #[must_use]
    pub const fn keepalive(&self) -> &ExecutionArgv {
        &self.keepalive
    }

    /// Returns the normalized in-guest workspace.
    #[must_use]
    pub const fn workspace(&self) -> &TargetPath {
        &self.workspace
    }

    /// Returns hard CPU, memory, and process limits.
    #[must_use]
    pub const fn resources(&self) -> ResourceLimits {
        self.resources
    }
}

/// Effective HCS state used for ownership and isolation verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostComputeInspection {
    resource_id: String,
    grant_digest: Sha256Digest,
    spec_digest: Sha256Digest,
    generation: SandboxGeneration,
    custody: SandboxCustody,
    profile: EnvironmentProfile,
    image_digest: Sha256Digest,
    resources: ResourceLimits,
    isolation: HostComputeObservedIsolation,
    state: HostComputeObservedState,
    network_disabled: bool,
    writable_disposable_root: bool,
    unprivileged_container_user: bool,
    host_mount_count: u32,
    named_pipe_count: u32,
    device_count: u32,
}

impl HostComputeInspection {
    /// Constructs a complete effective-state observation.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        resource_id: impl Into<String>,
        grant_digest: Sha256Digest,
        spec_digest: Sha256Digest,
        generation: SandboxGeneration,
        custody: SandboxCustody,
        profile: EnvironmentProfile,
        image_digest: Sha256Digest,
        resources: ResourceLimits,
        isolation: HostComputeObservedIsolation,
        state: HostComputeObservedState,
        network_disabled: bool,
        writable_disposable_root: bool,
        unprivileged_container_user: bool,
        host_mount_count: u32,
        named_pipe_count: u32,
        device_count: u32,
    ) -> Self {
        Self {
            resource_id: resource_id.into(),
            grant_digest,
            spec_digest,
            generation,
            custody,
            profile,
            image_digest,
            resources,
            isolation,
            state,
            network_disabled,
            writable_disposable_root,
            unprivileged_container_user,
            host_mount_count,
            named_pipe_count,
            device_count,
        }
    }

    /// Returns the exact broker-owned resource identity.
    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    /// Returns the consumed-grant label observed on the resource.
    #[must_use]
    pub const fn grant_digest(&self) -> Sha256Digest {
        self.grant_digest
    }

    /// Returns the spec fingerprint label observed on the resource.
    #[must_use]
    pub const fn spec_digest(&self) -> Sha256Digest {
        self.spec_digest
    }

    /// Returns the generation label observed on the resource.
    #[must_use]
    pub const fn generation(&self) -> SandboxGeneration {
        self.generation
    }

    /// Returns the custody labels observed on the resource.
    #[must_use]
    pub const fn custody(&self) -> SandboxCustody {
        self.custody
    }

    /// Returns the observed profile attestation.
    #[must_use]
    pub const fn profile(&self) -> &EnvironmentProfile {
        &self.profile
    }

    /// Returns the observed immutable image digest.
    #[must_use]
    pub const fn image_digest(&self) -> Sha256Digest {
        self.image_digest
    }

    /// Returns the effective resource limits.
    #[must_use]
    pub const fn resources(&self) -> ResourceLimits {
        self.resources
    }

    /// Returns the effective isolation mode.
    #[must_use]
    pub const fn isolation(&self) -> HostComputeObservedIsolation {
        self.isolation
    }

    /// Returns the current compute-system state.
    #[must_use]
    pub const fn state(&self) -> HostComputeObservedState {
        self.state
    }

    /// Reports whether HCS proves all closed policy properties.
    #[must_use]
    pub const fn has_closed_policy(&self) -> bool {
        self.network_disabled
            && self.writable_disposable_root
            && self.unprivileged_container_user
            && self.host_mount_count == 0
            && self.named_pipe_count == 0
            && self.device_count == 0
    }
}

/// Deterministic identity of one broker-owned guest process.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HostComputeProcess(String);

impl HostComputeProcess {
    /// Returns the opaque process identity understood by the adapter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact attached execution request passed to HCS.
pub struct BrokerExecRequest<'a> {
    resource_id: &'a str,
    process: &'a HostComputeProcess,
    guest_agent_path: &'a str,
    process_limit: u32,
    command: &'a ExecutionCommand,
}

impl BrokerExecRequest<'_> {
    /// Returns the exact compute-system identity.
    #[must_use]
    pub const fn resource_id(&self) -> &str {
        self.resource_id
    }

    /// Returns the deterministic descendant identity.
    #[must_use]
    pub const fn process(&self) -> &HostComputeProcess {
        self.process
    }

    /// Returns the immutable in-image guest-agent executable path.
    #[must_use]
    pub const fn guest_agent_path(&self) -> &str {
        self.guest_agent_path
    }

    /// Returns the whole-command-tree process ceiling enforced by the guest.
    #[must_use]
    pub const fn process_limit(&self) -> u32 {
        self.process_limit
    }

    /// Returns the literal, bounded guest command.
    #[must_use]
    pub const fn command(&self) -> &ExecutionCommand {
        self.command
    }
}

impl fmt::Debug for BrokerExecRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerExecRequest")
            .field("resource_id", &self.resource_id)
            .field("process", &self.process)
            .field("guest_agent_path", &self.guest_agent_path)
            .field("process_limit", &self.process_limit)
            .field("command", &self.command)
            .finish()
    }
}

/// Exact bounded copy-to request passed to HCS.
#[derive(Debug)]
pub struct BrokerCopyToRequest<'a> {
    resource_id: &'a str,
    guest_agent_path: &'a str,
    request: &'a CopyToRequest,
}

impl BrokerCopyToRequest<'_> {
    /// Returns the exact compute-system identity.
    #[must_use]
    pub const fn resource_id(&self) -> &str {
        self.resource_id
    }

    /// Returns the immutable in-image guest-agent executable path.
    #[must_use]
    pub const fn guest_agent_path(&self) -> &str {
        self.guest_agent_path
    }

    /// Returns the bounded copy request.
    #[must_use]
    pub const fn request(&self) -> &CopyToRequest {
        self.request
    }
}

/// Exact bounded copy-from request passed to HCS.
#[derive(Debug)]
pub struct BrokerCopyFromRequest<'a> {
    resource_id: &'a str,
    guest_agent_path: &'a str,
    request: &'a CopyFromRequest,
}

impl BrokerCopyFromRequest<'_> {
    /// Returns the exact compute-system identity.
    #[must_use]
    pub const fn resource_id(&self) -> &str {
        self.resource_id
    }

    /// Returns the immutable in-image guest-agent executable path.
    #[must_use]
    pub const fn guest_agent_path(&self) -> &str {
        self.guest_agent_path
    }

    /// Returns the bounded copy request.
    #[must_use]
    pub const fn request(&self) -> &CopyFromRequest {
        self.request
    }
}

/// Narrow HCS/Hyper-V adapter used only by the restricted broker.
///
/// A production implementation belongs behind `cfg(windows)`. Cross-platform
/// tests use a closed fake through the same exact methods.
pub trait WindowsHostComputeAdapter: fmt::Debug + Send + Sync {
    /// Proves image metadata and the fixed Hyper-V/offline engine policy.
    ///
    /// # Errors
    ///
    /// Returns a typed, non-mutating profile-admission failure.
    fn attest_profile(
        &self,
        request: &HostComputeProfileRequest,
    ) -> Result<HostComputeProfileObservation, HostComputeAdapterError>;
    /// Creates exactly one Hyper-V-isolated compute system.
    ///
    /// # Errors
    ///
    /// Returns a typed failure with an explicit mutation-effect classification.
    fn create(&self, request: &HostComputeCreateRequest) -> Result<(), HostComputeAdapterError>;
    /// Inspects exactly one broker-selected compute-system identity.
    ///
    /// # Errors
    ///
    /// Returns a typed inspection failure.
    fn inspect(
        &self,
        resource_id: &str,
    ) -> Result<Option<HostComputeInspection>, HostComputeAdapterError>;
    /// Attaches the broker-controlled guest channel.
    ///
    /// # Errors
    ///
    /// Returns a typed attachment failure.
    fn attach(&self, resource_id: &str) -> Result<(), HostComputeAdapterError>;
    /// Invokes the fixed guest agent, which executes one literal argv inside a
    /// nested Windows Job Object without a host or container-engine shell.
    ///
    /// # Errors
    ///
    /// Returns a typed execution failure.
    fn exec(
        &self,
        request: &BrokerExecRequest<'_>,
        cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, HostComputeAdapterError>;
    /// Copies bounded anonymous bytes into the guest.
    ///
    /// # Errors
    ///
    /// Returns a typed copy failure.
    fn copy_to(
        &self,
        request: &BrokerCopyToRequest<'_>,
        cancellation: &dyn Cancellation,
    ) -> Result<(), HostComputeAdapterError>;
    /// Copies bounded anonymous bytes out of the guest.
    ///
    /// # Errors
    ///
    /// Returns a typed copy failure.
    fn copy_from(
        &self,
        request: &BrokerCopyFromRequest<'_>,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, HostComputeAdapterError>;
    /// Terminates all descendants of one exact broker-owned compute system.
    ///
    /// # Errors
    ///
    /// Returns a typed cleanup failure.
    fn terminate_descendants(&self, resource_id: &str) -> Result<(), HostComputeAdapterError>;
    /// Destroys one exact broker-owned compute system.
    ///
    /// # Errors
    ///
    /// Returns a typed destroy failure.
    fn destroy(&self, resource_id: &str) -> Result<(), HostComputeAdapterError>;
    /// Lists only resources carrying the broker's immutable ownership marker.
    ///
    /// # Errors
    ///
    /// Returns a typed inventory failure.
    fn list_owned(&self) -> Result<Vec<HostComputeInspection>, HostComputeAdapterError>;
}

/// Durable lifecycle phase of a consumed one-use grant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerLifecyclePhase {
    /// Create intent is durable; HCS create may or may not have happened.
    Creating,
    /// The resource exists and passed effective-state verification.
    Ready,
    /// The guest execution channel was attached and reverified.
    Attached,
    /// Cleanup intent is durable; destroy may or may not have completed.
    Destroying,
    /// The exact resource is proved absent.
    Destroyed,
    /// The create grant was consumed but the adapter proved no resource exists.
    ConsumedFailed,
    /// State could not be proved safe and awaits reconciliation cleanup.
    Quarantined,
}

/// Durable per-resource adapter operation used as a compare-and-swap fence.
///
/// Normal operations never wait for one another while holding the broker's
/// global state mutex. Cleanup is allowed to supersede any of these intents;
/// the superseded caller must then discard its result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BrokerOperationKind {
    Attach,
    Exec,
    CopyTo,
    CopyFrom,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BrokerOperationIntent {
    epoch: u64,
    kind: BrokerOperationKind,
    operation_id: OperationId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BrokerDurableTermination {
    Exited(i32),
    Signalled,
    TimedOut,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrokerDurableOutputStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Eq, PartialEq)]
struct BrokerDurableOutputRecord {
    stream: BrokerDurableOutputStream,
    content: Vec<u8>,
    end_of_stream: bool,
}

impl fmt::Debug for BrokerDurableOutputRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerDurableOutputRecord")
            .field("stream", &self.stream)
            .field("bytes", &self.content.len())
            .field("content", &"[REDACTED]")
            .field("end_of_stream", &self.end_of_stream)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
enum BrokerCompletedOutcome {
    Exec {
        termination: BrokerDurableTermination,
        records: Vec<BrokerDurableOutputRecord>,
        truncated: bool,
    },
    CopyTo,
    CopyFrom {
        content: Vec<u8>,
    },
}

impl fmt::Debug for BrokerCompletedOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exec {
                termination,
                records,
                truncated,
            } => formatter
                .debug_struct("BrokerCompletedOutcome::Exec")
                .field("termination", termination)
                .field("records", &records.len())
                .field("output", &"[REDACTED]")
                .field("truncated", truncated)
                .finish(),
            Self::CopyTo => formatter.write_str("BrokerCompletedOutcome::CopyTo"),
            Self::CopyFrom { content } => formatter
                .debug_struct("BrokerCompletedOutcome::CopyFrom")
                .field("bytes", &content.len())
                .field("content", &"[REDACTED]")
                .finish(),
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BrokerCompletedOperation {
    kind: BrokerOperationKind,
    request_fingerprint: Sha256Digest,
    result: BrokerCompletedResult,
}

impl fmt::Debug for BrokerCompletedOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerCompletedOperation")
            .field("kind", &self.kind)
            .field("request_fingerprint", &self.request_fingerprint)
            .field("result", &self.result)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum BrokerCompletedResult {
    Pending { reference: DurableContentRef },
    GarbageCollecting { reference: DurableContentRef },
    Acknowledged,
}

enum ReplayableOperation {
    Begin(Box<BrokerLedgerEntry>),
    Replay(BrokerCompletedOutcome),
}

/// Complete latest durable state for one consumed grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerLedgerEntry {
    grant_digest: Sha256Digest,
    spec_digest: Sha256Digest,
    resource_id: String,
    ticket_digest: Sha256Digest,
    runner_id: RunnerId,
    runner_session_id: RunnerSessionId,
    runner_generation: u64,
    session_epoch: u64,
    generation: u64,
    custody: SandboxCustody,
    profile: EnvironmentProfile,
    image_digest: Sha256Digest,
    memory_bytes: u64,
    cpu_millis: u32,
    pids: u32,
    guest_agent_path: String,
    expires_at: UnixMillis,
    phase: BrokerLifecyclePhase,
    descendants: BTreeSet<String>,
    destroy_operation_id: Option<OperationId>,
    operation_epoch: u64,
    active_operation: Option<BrokerOperationIntent>,
    completed_operations: BTreeMap<OperationId, BrokerCompletedOperation>,
}

impl BrokerLedgerEntry {
    /// Returns the one-use grant digest indexing the entry.
    #[must_use]
    pub const fn grant_digest(&self) -> Sha256Digest {
        self.grant_digest
    }

    /// Returns the current lifecycle phase.
    #[must_use]
    pub const fn phase(&self) -> BrokerLifecyclePhase {
        self.phase
    }

    /// Returns the exact internal HCS identity.
    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    /// Returns the lease-derived generation fence for this resource.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact runner and slot custody persisted for this resource.
    #[must_use]
    pub const fn custody(&self) -> SandboxCustody {
        self.custody
    }

    /// Returns the exact admitted environment profile.
    #[must_use]
    pub const fn profile(&self) -> &EnvironmentProfile {
        &self.profile
    }
}

/// Durable append boundary for broker grant consumption and lifecycle intents.
pub trait BrokerLedger: fmt::Debug + Send + Sync {
    /// Loads all synchronized state transitions in append order.
    ///
    /// # Errors
    ///
    /// Returns a typed I/O, corruption, or capacity failure.
    fn load(&self) -> Result<Vec<BrokerLedgerEntry>, BrokerLedgerError>;
    /// Synchronizes a complete replacement state before returning.
    ///
    /// # Errors
    ///
    /// Returns a typed I/O, corruption, or capacity failure.
    fn append(&self, entry: &BrokerLedgerEntry) -> Result<(), BrokerLedgerError>;
}

/// Durable-ledger failure. No host path or serialized payload is exposed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BrokerLedgerError {
    /// The journal could not be opened, read, appended, or synchronized.
    #[error("Windows broker ledger I/O failed")]
    Io,
    /// A record was malformed, non-contiguous, oversized, or checksum-invalid.
    #[error("Windows broker ledger is corrupt")]
    Corrupt,
    /// The configured journal exceeded its bounded size or event count.
    #[error("Windows broker ledger capacity was exceeded")]
    Capacity,
}

/// Payload-first publication awaiting adoption by the lifecycle ledger.
///
/// Dropping a publication before [`Self::adopt`] leaves an unreferenced object
/// for the next result-store reconciliation; it never removes content that an
/// uncertain ledger append may already reference.
pub trait BrokerResultPublication: fmt::Debug + Send {
    /// Returns the immutable protected-content receipt to persist in the ledger.
    fn reference(&self) -> &DurableContentRef;

    /// Confirms that the synchronized lifecycle ledger adopted this reference.
    fn adopt(self: Box<Self>);
}

/// Capacity held before one host mutation that may return replayable content.
pub trait BrokerResultCapacityReservation<'store>: fmt::Debug + Send {
    /// Protects and synchronizes the exact bounded result payload.
    ///
    /// # Errors
    ///
    /// Fails without returning plaintext or key material when protection or
    /// durable publication cannot complete.
    fn persist(
        self: Box<Self>,
        plaintext: &[u8],
    ) -> Result<Box<dyn BrokerResultPublication + 'store>, BrokerResultStoreError>;
}

/// Protected, bounded store for exact broker-operation replay payloads.
///
/// Implementations must authenticate and encrypt content before durable write,
/// reserve aggregate capacity before the corresponding host mutation, and
/// fence reconciliation while a payload awaits ledger adoption.
pub trait BrokerResultStore: fmt::Debug + Send + Sync {
    /// Reserves one result object and its maximum protected allocation.
    ///
    /// # Errors
    ///
    /// Returns a typed capacity or availability failure before host mutation.
    fn reserve(
        &self,
        maximum_plaintext_bytes: u64,
    ) -> Result<Box<dyn BrokerResultCapacityReservation<'_> + '_>, BrokerResultStoreError>;

    /// Authenticates, decrypts, and loads one exact durable result.
    ///
    /// # Errors
    ///
    /// Fails closed when content is absent, altered, or unavailable.
    fn load(&self, reference: &DurableContentRef) -> Result<Vec<u8>, BrokerResultStoreError>;

    /// Durably removes one acknowledged result when no pending operation shares it.
    ///
    /// Returns `false` only when the validated reference is already absent.
    ///
    /// # Errors
    ///
    /// Fails closed when existing content cannot be authenticated or deletion
    /// cannot be synchronized.
    fn remove(&self, reference: &DurableContentRef) -> Result<bool, BrokerResultStoreError>;

    /// Verifies every retained reference and removes payload-first crash leftovers.
    ///
    /// # Errors
    ///
    /// Fails closed on any missing, altered, unsupported, or unavailable object.
    fn reconcile(&self, retained: &[DurableContentRef]) -> Result<(), BrokerResultStoreError>;
}

/// Secret-free protected result-store failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BrokerResultStoreError {
    /// A per-object, aggregate-byte, or object-count limit was exhausted.
    #[error("Windows broker protected result-store capacity was exceeded")]
    Capacity,
    /// A durable reference or its protected bytes were absent, malformed, or altered.
    #[error("Windows broker protected result-store content is corrupt")]
    Corrupt,
    /// Protection authority or durable storage was unavailable.
    #[error("Windows broker protected result store is unavailable")]
    Unavailable,
}

/// In-memory ledger intended for deterministic cross-platform conformance tests.
#[derive(Debug, Default)]
pub struct InMemoryBrokerLedger {
    entries: Mutex<Vec<BrokerLedgerEntry>>,
}

impl InMemoryBrokerLedger {
    /// Creates an empty fake ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }
}

impl BrokerLedger for InMemoryBrokerLedger {
    fn load(&self) -> Result<Vec<BrokerLedgerEntry>, BrokerLedgerError> {
        Ok(self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone())
    }

    fn append(&self, entry: &BrokerLedgerEntry) -> Result<(), BrokerLedgerError> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.len() >= MAX_LEDGER_EVENTS {
            return Err(BrokerLedgerError::Capacity);
        }
        entries.push(entry.clone());
        Ok(())
    }
}
/// Closed set of control-plane Ed25519 verification keys trusted by a host.
#[derive(Clone)]
pub struct BrokerGrantKeyring {
    keys: Arc<BTreeMap<Sha256Digest, [u8; ED25519_PUBLIC_KEY_BYTES]>>,
}

impl BrokerGrantKeyring {
    /// Builds a non-empty keyring and verifies every key identifier.
    ///
    /// Key identifiers are exactly SHA-256 over the raw Ed25519 public key.
    ///
    /// # Errors
    ///
    /// Rejects an empty keyring, duplicate identifiers, or an identifier which
    /// does not match its public key.
    pub fn new(
        keys: impl IntoIterator<Item = (Sha256Digest, [u8; ED25519_PUBLIC_KEY_BYTES])>,
    ) -> Result<Self, BrokerError> {
        let mut verified = BTreeMap::new();
        for (key_id, public_key) in keys {
            if key_id != Sha256Digest::from_bytes(Sha256::digest(public_key).into()) {
                return Err(BrokerError::VerificationKeyMismatch);
            }
            if verified.insert(key_id, public_key).is_some() {
                return Err(BrokerError::DuplicateVerificationKey);
            }
        }
        if verified.is_empty() {
            return Err(BrokerError::EmptyVerificationKeyring);
        }
        Ok(Self {
            keys: Arc::new(verified),
        })
    }

    fn verify(&self, grant: &WindowsHyperVBrokerGrant) -> Result<(), BrokerError> {
        let public_key = self
            .keys
            .get(&grant.key_id())
            .ok_or(BrokerError::UnknownVerificationKey)?;
        signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
            .verify(&grant.signing_bytes(), grant.signature())
            .map_err(|_| BrokerError::InvalidGrantSignature)
    }
}

impl fmt::Debug for BrokerGrantKeyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerGrantKeyring")
            .field("key_count", &self.keys.len())
            .finish()
    }
}

/// Opaque capability returned after a grant-backed create succeeds.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerSandboxTicket {
    grant_digest: Sha256Digest,
    ticket_digest: Sha256Digest,
}

impl BrokerSandboxTicket {
    /// Returns the consumed-grant identity used for exact replay lookup.
    #[must_use]
    pub const fn grant_digest(&self) -> Sha256Digest {
        self.grant_digest
    }

    /// Encodes the capability as a fixed, versioned, path-free token.
    ///
    /// The two digests are authorization material only when presented to the
    /// broker that owns the durable ledger. The token contains no resource
    /// name, host path, engine endpoint, or caller-selectable policy.
    #[must_use]
    pub fn opaque(&self) -> String {
        format!("v2-{}-{}", self.grant_digest, self.ticket_digest)
    }

    /// Decodes one exact versioned broker capability.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions, non-canonical digests, or extra fields.
    pub fn from_opaque(value: &str) -> Result<Self, BrokerError> {
        let mut fields = value.split('-');
        if fields.next() != Some("v2") {
            return Err(BrokerError::InvalidTicket);
        }
        let grant = fields
            .next()
            .ok_or(BrokerError::InvalidTicket)?
            .parse::<Sha256Digest>()
            .map_err(|_| BrokerError::InvalidTicket)?;
        let ticket = fields
            .next()
            .ok_or(BrokerError::InvalidTicket)?
            .parse::<Sha256Digest>()
            .map_err(|_| BrokerError::InvalidTicket)?;
        if fields.next().is_some()
            || is_zero_digest(grant)
            || is_zero_digest(ticket)
            || value != format!("v2-{grant}-{ticket}")
        {
            return Err(BrokerError::InvalidTicket);
        }
        Ok(Self {
            grant_digest: grant,
            ticket_digest: ticket,
        })
    }
}

/// Durable metadata returned for one authenticated broker capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerSandboxInspection {
    generation: SandboxGeneration,
    custody: SandboxCustody,
    profile: EnvironmentProfile,
    phase: BrokerLifecyclePhase,
}

impl BrokerSandboxInspection {
    /// Returns the lease-derived sandbox generation.
    #[must_use]
    pub const fn generation(&self) -> SandboxGeneration {
        self.generation
    }

    /// Returns the exact runner and slot custody of the durable resource.
    #[must_use]
    pub const fn custody(&self) -> SandboxCustody {
        self.custody
    }

    /// Returns the exact admitted profile.
    #[must_use]
    pub const fn profile(&self) -> &EnvironmentProfile {
        &self.profile
    }

    /// Returns the durable broker lifecycle phase.
    #[must_use]
    pub const fn phase(&self) -> BrokerLifecyclePhase {
        self.phase
    }
}

impl fmt::Debug for BrokerSandboxTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerSandboxTicket")
            .field("grant_digest", &self.grant_digest)
            .field("ticket", &"[OPAQUE]")
            .finish_non_exhaustive()
    }
}

/// Startup/watchdog reconciliation result containing counts only.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BrokerReconcileReport {
    retained: u32,
    destroyed: u32,
    orphaned: u32,
    quarantined: u32,
}

/// Recurring in-process deadline watchdog owned by the broker service.
///
/// This guard improves ordinary service liveness but is not an independent
/// watchdog boundary: a separate service/process must invoke
/// [`RestrictedWindowsHyperVBroker::watchdog_tick`] against the durable ledger
/// to survive broker-process loss or deadlock.
pub struct BrokerWatchdog {
    stop: Arc<(Mutex<bool>, Condvar)>,
    healthy: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl BrokerWatchdog {
    /// Reports whether the most recent cleanup pass completed successfully.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }
}

impl fmt::Debug for BrokerWatchdog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerWatchdog")
            .field("healthy", &self.is_healthy())
            .finish_non_exhaustive()
    }
}

impl Drop for BrokerWatchdog {
    fn drop(&mut self) {
        let (lock, wake) = self.stop.as_ref();
        *lock.lock().unwrap_or_else(PoisonError::into_inner) = true;
        wake.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl BrokerReconcileReport {
    /// Returns active resources retained after exact verification.
    #[must_use]
    pub const fn retained(self) -> u32 {
        self.retained
    }

    /// Returns journal-owned resources proved destroyed.
    #[must_use]
    pub const fn destroyed(self) -> u32 {
        self.destroyed
    }

    /// Returns unjournaled broker-owned resources removed as orphans.
    #[must_use]
    pub const fn orphaned(self) -> u32 {
        self.orphaned
    }

    /// Returns resources whose safe state could not be established.
    #[must_use]
    pub const fn quarantined(self) -> u32 {
        self.quarantined
    }
}

/// Restricted broker validation, replay, or lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BrokerError {
    /// No verification keys were configured.
    #[error("Windows broker verification keyring is empty")]
    EmptyVerificationKeyring,
    /// A configured key ID did not equal SHA-256 of its public key.
    #[error("Windows broker verification key ID does not match its public key")]
    VerificationKeyMismatch,
    /// The same verification-key identifier appeared more than once.
    #[error("duplicate Windows broker verification key")]
    DuplicateVerificationKey,
    /// The grant refers to a key not trusted by this host.
    #[error("Windows broker grant uses an unknown verification key")]
    UnknownVerificationKey,
    /// Ed25519 verification failed.
    #[error("Windows broker grant signature is invalid")]
    InvalidGrantSignature,
    /// The grant's structural invariants failed.
    #[error("Windows broker grant is malformed")]
    MalformedGrant,
    /// The grant is not bound to this exact host.
    #[error("Windows broker grant is bound to another host")]
    WrongHost,
    /// The trusted broker clock is outside the grant interval.
    #[error("Windows broker grant is not currently valid")]
    GrantNotCurrent,
    /// The sandbox request violates the closed Hyper-V contract.
    #[error("sandbox request violates the restricted Windows Hyper-V contract")]
    InvalidSandboxSpec,
    /// The broker-minted durable launch/profile contract was unavailable or invalid.
    #[error("Windows broker profile contract is unavailable or invalid")]
    InvalidProfileContract,
    /// This grant was previously consumed for different request material.
    #[error("Windows broker grant replay conflicts with its durable consumption")]
    ReplayConflict,
    /// The consumed grant cannot create another resource after terminal failure.
    #[error("Windows broker grant is already terminally consumed")]
    GrantAlreadyConsumed,
    /// The supplied ticket is not the broker-issued ticket for this resource.
    #[error("Windows broker sandbox ticket is invalid")]
    InvalidTicket,
    /// Secret-marked environment cannot cross the restricted exec boundary.
    #[error("Windows broker execution environment contains secret authority")]
    SecretEnvironmentForbidden,
    /// A newer durable per-resource operation or cleanup fence won the race.
    #[error("Windows broker operation was superseded by a durable resource fence")]
    OperationFenced,
    /// The caller repeated an operation after durably acknowledging its result.
    #[error("Windows broker operation result was already acknowledged")]
    OperationAcknowledged,
    /// The caller acknowledged an operation which has no durable completed result.
    #[error("Windows broker operation result is not durably complete")]
    OperationNotCompleted,
    /// The resource's effective state or ownership labels did not match.
    #[error("Windows host-compute effective state failed closed verification")]
    EffectiveStateMismatch,
    /// Startup reconciliation must complete before accepting broker calls.
    #[error("Windows broker startup reconciliation is required")]
    ReconciliationRequired,
    /// An adapter boundary failed.
    #[error("Windows host-compute adapter failed")]
    Adapter(#[source] HostComputeAdapterError),
    /// Durable grant-consumption or lifecycle state could not be synchronized.
    #[error("Windows broker durable ledger failed")]
    Ledger(#[source] BrokerLedgerError),
    /// Protected replay content could not be reserved, authenticated, or synchronized.
    #[error("Windows broker protected result store failed")]
    ResultStore(#[source] BrokerResultStoreError),
}

impl From<BrokerLedgerError> for BrokerError {
    fn from(value: BrokerLedgerError) -> Self {
        Self::Ledger(value)
    }
}

impl From<HostComputeAdapterError> for BrokerError {
    fn from(value: HostComputeAdapterError) -> Self {
        Self::Adapter(value)
    }
}

impl From<BrokerResultStoreError> for BrokerError {
    fn from(value: BrokerResultStoreError) -> Self {
        Self::ResultStore(value)
    }
}

#[derive(Debug)]
struct BrokerState {
    entries: BTreeMap<Sha256Digest, BrokerLedgerEntry>,
    reconciled: bool,
    live_creates: BTreeSet<Sha256Digest>,
}

#[derive(Clone, Debug)]
struct PreparedCreate {
    grant_digest: Sha256Digest,
    spec_digest: Sha256Digest,
    request: HostComputeCreateRequest,
    entry: BrokerLedgerEntry,
}

/// Grant-verifying, one-use, durable Windows Hyper-V lifecycle broker.
///
/// Call [`Self::reconcile_startup`] exactly once after construction. Until it
/// succeeds, every mutating or attachment call fails closed.
pub struct RestrictedWindowsHyperVBroker {
    host_id: Sha256Digest,
    keys: BrokerGrantKeyring,
    adapter: Arc<dyn WindowsHostComputeAdapter>,
    ledger: Arc<dyn BrokerLedger>,
    results: Arc<dyn BrokerResultStore>,
    profile_contracts: Arc<dyn BrokerProfileContractResolver>,
    state: Mutex<BrokerState>,
}

impl RestrictedWindowsHyperVBroker {
    /// Loads value-free lifecycle state without invoking HCS.
    ///
    /// Protected replay content is supplied through a separate result-store
    /// port and is authenticated by [`Self::reconcile_startup`] before calls
    /// are accepted.
    ///
    /// # Errors
    ///
    /// Rejects a zero host identity, a corrupt ledger, or conflicting durable
    /// identities for one grant. Result-store availability is checked during
    /// startup reconciliation rather than construction.
    pub fn open(
        host_id: Sha256Digest,
        keys: BrokerGrantKeyring,
        adapter: Arc<dyn WindowsHostComputeAdapter>,
        ledger: Arc<dyn BrokerLedger>,
        results: Arc<dyn BrokerResultStore>,
        profile_contracts: Arc<dyn BrokerProfileContractResolver>,
    ) -> Result<Self, BrokerError> {
        if is_zero_digest(host_id) {
            return Err(BrokerError::WrongHost);
        }
        let mut entries = BTreeMap::new();
        for entry in ledger.load()? {
            validate_ledger_entry(&entry)?;
            if let Some(previous) = entries.get(&entry.grant_digest)
                && !same_durable_identity(previous, &entry)
            {
                return Err(BrokerLedgerError::Corrupt.into());
            }
            entries.insert(entry.grant_digest, entry);
        }
        Ok(Self {
            host_id,
            keys,
            adapter,
            ledger,
            results,
            profile_contracts,
            state: Mutex::new(BrokerState {
                entries,
                reconciled: false,
                live_creates: BTreeSet::new(),
            }),
        })
    }

    /// Reconciles ambiguous intents, expired resources, and owned orphans.
    ///
    /// Unexpired resources that passed effective-state verification are
    /// retained. A pre-crash create intent is cleaned rather than adopted,
    /// because no caller could have durably received its ticket.
    ///
    /// # Errors
    ///
    /// Returns a typed adapter or durable-ledger failure. Calls remain closed
    /// until a complete pass succeeds.
    pub fn reconcile_startup(&self, now: UnixMillis) -> Result<BrokerReconcileReport, BrokerError> {
        self.reconcile_results()?;

        let observed = self.adapter.list_owned()?;
        let mut observed_by_id = BTreeMap::new();
        for inspection in observed {
            if observed_by_id
                .insert(inspection.resource_id.clone(), inspection)
                .is_some()
            {
                return Err(BrokerError::EffectiveStateMismatch);
            }
        }
        let entries = {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.entries.values().cloned().collect::<Vec<_>>()
        };
        let mut report = BrokerReconcileReport::default();
        for entry in entries {
            let observation = observed_by_id.remove(&entry.resource_id);
            match entry.phase {
                BrokerLifecyclePhase::Ready | BrokerLifecyclePhase::Attached
                    if now.get() < entry.expires_at.get() && entry.active_operation.is_none() =>
                {
                    if let Some(inspection) = observation {
                        if verify_observation(&entry, &inspection).is_ok() {
                            report.retained = report.retained.saturating_add(1);
                            continue;
                        }
                        let cleanup = self.begin_cleanup(&entry)?;
                        if self.cleanup_entry(&cleanup)? {
                            report.destroyed = report.destroyed.saturating_add(1);
                        } else {
                            report.quarantined = report.quarantined.saturating_add(1);
                        }
                    } else {
                        let mut failed = entry.clone();
                        failed.phase = BrokerLifecyclePhase::ConsumedFailed;
                        failed.descendants.clear();
                        failed.active_operation = None;
                        self.persist_if_current(&entry, failed)?;
                    }
                }
                BrokerLifecyclePhase::Destroyed | BrokerLifecyclePhase::ConsumedFailed => {
                    if observation.is_some() {
                        let cleanup = self.begin_cleanup(&entry)?;
                        if self.cleanup_entry(&cleanup)? {
                            report.destroyed = report.destroyed.saturating_add(1);
                        } else {
                            report.quarantined = report.quarantined.saturating_add(1);
                        }
                    }
                }
                _ => {
                    if observation.is_some() {
                        let cleanup = self.begin_cleanup(&entry)?;
                        if self.cleanup_entry(&cleanup)? {
                            report.destroyed = report.destroyed.saturating_add(1);
                        } else {
                            report.quarantined = report.quarantined.saturating_add(1);
                        }
                    } else {
                        let mut destroyed = entry.clone();
                        destroyed.phase = BrokerLifecyclePhase::Destroyed;
                        destroyed.descendants.clear();
                        destroyed.active_operation = None;
                        self.persist_if_current(&entry, destroyed)?;
                    }
                }
            }
        }
        for (resource_id, _) in observed_by_id {
            let descendants = self.adapter.terminate_descendants(&resource_id);
            let destroyed = self.adapter.destroy(&resource_id);
            if descendants.is_ok() && destroyed.is_ok() {
                report.orphaned = report.orphaned.saturating_add(1);
            } else {
                return Err(descendants
                    .err()
                    .or_else(|| destroyed.err())
                    .map_or(BrokerError::EffectiveStateMismatch, BrokerError::Adapter));
            }
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.reconciled = true;
        Ok(report)
    }

    /// Issues a fresh profile attestation from the fixed host engine path.
    ///
    /// This call accepts no engine endpoint or isolation selector. The adapter
    /// must prove the digest-pinned image is Windows AMD64 and that its only
    /// admissible create policy is Hyper-V isolated with networking disabled.
    ///
    /// # Errors
    ///
    /// Rejects stale/oversized freshness intervals and any incomplete or
    /// mismatched effective engine observation.
    pub fn attest_profile(
        &self,
        profile: &EnvironmentProfile,
        image: &ImmutableImage,
        issued_at: UnixMillis,
        valid_until: UnixMillis,
    ) -> Result<WindowsHyperVBrokerProfileAttestation, BrokerError> {
        let valid_lifetime = valid_until
            .get()
            .checked_sub(issued_at.get())
            .is_some_and(|lifetime| lifetime > 0 && lifetime <= 15 * 60 * 1_000);
        if !valid_lifetime {
            return Err(BrokerError::InvalidSandboxSpec);
        }
        let request = HostComputeProfileRequest {
            profile: profile.clone(),
            image: image.clone(),
        };
        let observed = self.adapter.attest_profile(&request)?;
        if observed.image_digest != image.digest()
            || observed.isolation != HostComputeObservedIsolation::HyperV
            || !observed.network_disabled
            || !observed.windows_amd64
        {
            return Err(BrokerError::EffectiveStateMismatch);
        }
        let digest = domain_digest(
            PROFILE_ATTESTATION_DOMAIN,
            &[
                self.host_id.as_bytes(),
                profile.id().as_str().as_bytes(),
                profile.digest().as_bytes(),
                image.digest().as_bytes(),
                &[HostComputeObservedIsolation::HyperV as u8],
                &[1],
                &issued_at.get().to_be_bytes(),
                &valid_until.get().to_be_bytes(),
            ],
        );
        Ok(WindowsHyperVBrokerProfileAttestation {
            host_id: self.host_id,
            profile: profile.clone(),
            image_digest: image.digest(),
            isolation: HostComputeObservedIsolation::HyperV,
            network_disabled: true,
            issued_at,
            valid_until,
            digest,
        })
    }

    /// Verifies and consumes a signed grant before creating one resource.
    ///
    /// An exact replay returns the existing ticket only after reinspection.
    /// A conflicting or terminal replay never reaches HCS.
    ///
    /// # Errors
    ///
    /// Returns a typed grant, replay, effective-state, adapter, or ledger error.
    pub fn create(
        &self,
        spec: &SandboxSpec,
        grant: &WindowsHyperVBrokerGrant,
        now: UnixMillis,
    ) -> Result<BrokerSandboxTicket, BrokerError> {
        let prepared = self.prepare_create(spec, grant, now)?;
        let existing = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            ensure_reconciled(&state)?;
            if let Some(existing) = state.entries.get(&prepared.grant_digest).cloned() {
                Some((
                    existing,
                    state.live_creates.contains(&prepared.grant_digest),
                ))
            } else {
                self.persist_locked(&mut state, prepared.entry.clone())?;
                state.live_creates.insert(prepared.grant_digest);
                None
            }
        };
        if let Some((existing, live_create)) = existing {
            if existing.spec_digest != prepared.spec_digest
                || existing.resource_id != prepared.request.resource_id
            {
                return Err(BrokerError::ReplayConflict);
            }
            return match existing.phase {
                BrokerLifecyclePhase::Ready | BrokerLifecyclePhase::Attached => {
                    self.inspect_verified(&existing)?;
                    Ok(ticket_from_entry(&existing))
                }
                BrokerLifecyclePhase::Creating if !live_create => {
                    self.reconcile_uncertain_create(&existing)
                }
                BrokerLifecyclePhase::Creating => Err(BrokerError::ReplayConflict),
                _ => Err(BrokerError::GrantAlreadyConsumed),
            };
        }

        let create_result = self.adapter.create(&prepared.request);
        {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.live_creates.remove(&prepared.grant_digest);
        }
        match create_result {
            Ok(()) => self.finish_create(&prepared.entry),
            Err(error) if error.effect() == BrokerAdapterEffect::KnownNoEffect => {
                let expected = prepared.entry;
                let mut failed = expected.clone();
                failed.phase = BrokerLifecyclePhase::ConsumedFailed;
                self.persist_if_current(&expected, failed)?;
                Err(error.into())
            }
            Err(error) => {
                let result = self.reconcile_uncertain_create(&prepared.entry);
                result.map_err(|reconcile| match reconcile {
                    BrokerError::EffectiveStateMismatch => BrokerError::Adapter(error),
                    other => other,
                })
            }
        }
    }

    /// Reinspects and attaches the broker-controlled guest channel.
    ///
    /// # Errors
    ///
    /// Rejects an invalid ticket, drifted effective state, or adapter failure.
    pub fn attach(&self, ticket: &BrokerSandboxTicket, now: UnixMillis) -> Result<(), BrokerError> {
        let entry = self.current_ticket_entry(ticket, now)?;
        if !matches!(
            entry.phase,
            BrokerLifecyclePhase::Ready | BrokerLifecyclePhase::Attached
        ) {
            return Err(BrokerError::GrantAlreadyConsumed);
        }
        self.inspect_verified(&entry)?;
        let intent = self.begin_operation(
            &entry,
            BrokerOperationKind::Attach,
            OperationId::new(),
            None,
        )?;
        match self.adapter.attach(&intent.resource_id) {
            Ok(()) => self.finish_operation(&intent, BrokerLifecyclePhase::Attached, None),
            Err(error) if error.effect() == BrokerAdapterEffect::KnownNoEffect => {
                self.finish_operation(&intent, entry.phase, None)?;
                Err(error.into())
            }
            Err(error) => {
                self.quarantine_operation(&intent)?;
                Err(error.into())
            }
        }
    }

    /// Reauthenticates one durable ticket and returns value-free metadata.
    ///
    /// # Errors
    ///
    /// Rejects an unknown ticket, requires completed startup reconciliation,
    /// and fails closed if an active resource cannot be reinspected exactly.
    pub fn inspect_ticket(
        &self,
        ticket: &BrokerSandboxTicket,
        now: UnixMillis,
    ) -> Result<BrokerSandboxInspection, BrokerError> {
        let entry = self.ticket_entry(ticket)?;
        if !matches!(
            entry.phase,
            BrokerLifecyclePhase::Destroyed | BrokerLifecyclePhase::ConsumedFailed
        ) {
            let entry = self.current_ticket_entry(ticket, now)?;
            self.inspect_verified(&entry)?;
        }
        let generation =
            SandboxGeneration::new(entry.generation).map_err(|_| BrokerLedgerError::Corrupt)?;
        Ok(BrokerSandboxInspection {
            generation,
            custody: entry.custody,
            profile: entry.profile,
            phase: entry.phase,
        })
    }

    /// Executes one command after durable descendant intent and reinspection.
    ///
    /// # Errors
    ///
    /// Leaves an uncertain descendant in the ledger for watchdog cleanup.
    pub fn exec(
        &self,
        ticket: &BrokerSandboxTicket,
        command: &ExecutionCommand,
        now: UnixMillis,
        cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, BrokerError> {
        if command
            .environment()
            .values()
            .iter()
            .any(automata_ci_execution::EnvironmentVariable::is_secret)
        {
            return Err(BrokerError::SecretEnvironmentForbidden);
        }
        let entry = self.current_ticket_entry(ticket, now)?;
        if entry.phase != BrokerLifecyclePhase::Attached {
            return Err(BrokerError::InvalidTicket);
        }
        self.inspect_verified(&entry)?;
        let process = process_id(entry.grant_digest, command.operation_id());
        let request_fingerprint = exec_request_fingerprint(command, entry.pids)?;
        if let Some(result) = self.completed_outcome(
            &entry,
            BrokerOperationKind::Exec,
            command.operation_id(),
            request_fingerprint,
        )? {
            return replay_exec_outcome(&result);
        }
        let reservation = self.results.reserve(
            u64::try_from(maximum_completed_outcome_bytes(
                BrokerOperationKind::Exec,
                command.output_limit(),
            )?)
            .map_err(|_| BrokerResultStoreError::Capacity)?,
        )?;
        let intent = match self.begin_replayable_operation(
            &entry,
            BrokerOperationKind::Exec,
            command.operation_id(),
            request_fingerprint,
            Some(process.as_str()),
        )? {
            ReplayableOperation::Begin(intent) => *intent,
            ReplayableOperation::Replay(result) => return replay_exec_outcome(&result),
        };
        let request = BrokerExecRequest {
            resource_id: &intent.resource_id,
            process: &process,
            guest_agent_path: &intent.guest_agent_path,
            process_limit: intent.pids,
            command,
        };
        match self.adapter.exec(&request, cancellation) {
            Ok(output) => {
                let durable = completed_exec_outcome(&output);
                self.commit_replayable_operation(
                    &intent,
                    BrokerLifecyclePhase::Attached,
                    request_fingerprint,
                    &durable,
                    Some(process.as_str()),
                    reservation,
                )?;
                Ok(output)
            }
            Err(error) if error.effect() == BrokerAdapterEffect::KnownNoEffect => {
                self.finish_operation(
                    &intent,
                    BrokerLifecyclePhase::Attached,
                    Some(process.as_str()),
                )?;
                Err(error.into())
            }
            Err(error) => {
                self.quarantine_operation(&intent)?;
                Err(error.into())
            }
        }
    }

    /// Copies bounded bytes to the attached guest.
    ///
    /// # Errors
    ///
    /// Rejects stale tickets, effective-state drift, or adapter failure.
    pub fn copy_to(
        &self,
        ticket: &BrokerSandboxTicket,
        request: &CopyToRequest,
        now: UnixMillis,
        cancellation: &dyn Cancellation,
    ) -> Result<(), BrokerError> {
        let entry = self.current_ticket_entry(ticket, now)?;
        if entry.phase != BrokerLifecyclePhase::Attached {
            return Err(BrokerError::InvalidTicket);
        }
        self.inspect_verified(&entry)?;
        let request_fingerprint = copy_to_request_fingerprint(request);
        if let Some(result) = self.completed_outcome(
            &entry,
            BrokerOperationKind::CopyTo,
            request.operation_id(),
            request_fingerprint,
        )? {
            return replay_copy_to_outcome(&result);
        }
        let reservation = self.results.reserve(
            u64::try_from(maximum_completed_outcome_bytes(
                BrokerOperationKind::CopyTo,
                0,
            )?)
            .map_err(|_| BrokerResultStoreError::Capacity)?,
        )?;
        let intent = match self.begin_replayable_operation(
            &entry,
            BrokerOperationKind::CopyTo,
            request.operation_id(),
            request_fingerprint,
            None,
        )? {
            ReplayableOperation::Begin(intent) => *intent,
            ReplayableOperation::Replay(result) => return replay_copy_to_outcome(&result),
        };
        let result = self.adapter.copy_to(
            &BrokerCopyToRequest {
                resource_id: &intent.resource_id,
                guest_agent_path: &intent.guest_agent_path,
                request,
            },
            cancellation,
        );
        match result {
            Ok(()) => self.commit_replayable_operation(
                &intent,
                BrokerLifecyclePhase::Attached,
                request_fingerprint,
                &BrokerCompletedOutcome::CopyTo,
                None,
                reservation,
            ),
            Err(error) if error.effect() == BrokerAdapterEffect::KnownNoEffect => {
                self.finish_operation(&intent, BrokerLifecyclePhase::Attached, None)?;
                Err(error.into())
            }
            Err(error) => {
                self.quarantine_operation(&intent)?;
                Err(error.into())
            }
        }
    }

    /// Copies bounded bytes from the attached guest.
    ///
    /// # Errors
    ///
    /// Rejects stale tickets, excessive adapter output, drift, or failure.
    pub fn copy_from(
        &self,
        ticket: &BrokerSandboxTicket,
        request: &CopyFromRequest,
        now: UnixMillis,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, BrokerError> {
        let entry = self.current_ticket_entry(ticket, now)?;
        if entry.phase != BrokerLifecyclePhase::Attached {
            return Err(BrokerError::InvalidTicket);
        }
        self.inspect_verified(&entry)?;
        let request_fingerprint = copy_from_request_fingerprint(request)?;
        if let Some(result) = self.completed_outcome(
            &entry,
            BrokerOperationKind::CopyFrom,
            request.operation_id(),
            request_fingerprint,
        )? {
            return replay_copy_from_outcome(&result, request.byte_limit());
        }
        let reservation = self.results.reserve(
            u64::try_from(maximum_completed_outcome_bytes(
                BrokerOperationKind::CopyFrom,
                request.byte_limit(),
            )?)
            .map_err(|_| BrokerResultStoreError::Capacity)?,
        )?;
        let intent = match self.begin_replayable_operation(
            &entry,
            BrokerOperationKind::CopyFrom,
            request.operation_id(),
            request_fingerprint,
            None,
        )? {
            ReplayableOperation::Begin(intent) => *intent,
            ReplayableOperation::Replay(result) => {
                return replay_copy_from_outcome(&result, request.byte_limit());
            }
        };
        let bytes = self.adapter.copy_from(
            &BrokerCopyFromRequest {
                resource_id: &intent.resource_id,
                guest_agent_path: &intent.guest_agent_path,
                request,
            },
            cancellation,
        );
        let bytes = match bytes {
            Ok(bytes) => bytes,
            Err(error) if error.effect() == BrokerAdapterEffect::KnownNoEffect => {
                self.finish_operation(&intent, BrokerLifecyclePhase::Attached, None)?;
                return Err(error.into());
            }
            Err(error) => {
                self.quarantine_operation(&intent)?;
                return Err(error.into());
            }
        };
        if bytes.len() > request.byte_limit() {
            self.quarantine_operation(&intent)?;
            return Err(BrokerError::EffectiveStateMismatch);
        }
        self.commit_replayable_operation(
            &intent,
            BrokerLifecyclePhase::Attached,
            request_fingerprint,
            &BrokerCompletedOutcome::CopyFrom {
                content: bytes.clone(),
            },
            None,
            reservation,
        )?;
        Ok(bytes)
    }

    /// Durably acknowledges one exact replay result and reclaims its protected payload.
    ///
    /// The operation identity remains as a value-free tombstone, so a delayed
    /// duplicate cannot repeat the host mutation after garbage collection.
    /// Exact repeated acknowledgements are idempotent.
    ///
    /// # Errors
    ///
    /// Rejects an invalid ticket, an unknown operation, or protected content
    /// that cannot be authenticated or durably removed.
    pub fn acknowledge_operation(
        &self,
        ticket: &BrokerSandboxTicket,
        operation_id: OperationId,
    ) -> Result<(), BrokerError> {
        let (grant_digest, reference, already_collecting) = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            ensure_reconciled(&state)?;
            let current = ticket_entry(&state, ticket)?;
            let completed = current
                .completed_operations
                .get(&operation_id)
                .ok_or(BrokerError::OperationNotCompleted)?;
            match &completed.result {
                BrokerCompletedResult::Acknowledged => return Ok(()),
                BrokerCompletedResult::GarbageCollecting { reference } => {
                    (current.grant_digest, reference.clone(), true)
                }
                BrokerCompletedResult::Pending { reference } => {
                    load_completed_outcome(self.results.as_ref(), completed.kind, reference)?;
                    let mut collecting = current.clone();
                    collecting
                        .completed_operations
                        .get_mut(&operation_id)
                        .ok_or(BrokerLedgerError::Corrupt)?
                        .result = BrokerCompletedResult::GarbageCollecting {
                        reference: reference.clone(),
                    };
                    self.persist_locked(&mut state, collecting)?;
                    (current.grant_digest, reference.clone(), false)
                }
            }
        };
        self.finish_result_gc(grant_digest, operation_id, &reference, already_collecting)
    }

    /// Durably begins exact descendant cleanup and compute-system destruction.
    ///
    /// # Errors
    ///
    /// An ambiguous destroy is inspected; the ledger remains `Destroying`
    /// unless absence is proved.
    pub fn destroy(
        &self,
        ticket: &BrokerSandboxTicket,
        operation_id: OperationId,
        generation: SandboxGeneration,
        custody: SandboxCustody,
    ) -> Result<(), BrokerError> {
        let cleanup = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            ensure_reconciled(&state)?;
            let mut entry = ticket_entry(&state, ticket)?;
            if entry.generation != generation.get() || entry.custody != custody {
                return Err(BrokerError::InvalidTicket);
            }
            if entry.phase == BrokerLifecyclePhase::Destroyed {
                return Ok(());
            }
            if let Some(previous) = entry.destroy_operation_id
                && previous != operation_id
            {
                return Err(BrokerError::ReplayConflict);
            }
            entry.destroy_operation_id = Some(operation_id);
            entry.phase = BrokerLifecyclePhase::Destroying;
            entry.active_operation = None;
            self.persist_locked(&mut state, entry.clone())?;
            entry
        };
        if self.cleanup_entry(&cleanup)? {
            Ok(())
        } else {
            Err(BrokerError::EffectiveStateMismatch)
        }
    }

    /// One watchdog pass for expired, quarantined, and ambiguous state.
    ///
    /// This method does not prescribe its process boundary. Calling it from
    /// the broker service itself is not an independent watchdog guarantee.
    ///
    /// # Errors
    ///
    /// Returns after the first resource whose exact absence cannot be proved;
    /// its durable state remains eligible for the next pass.
    pub fn watchdog_tick(&self, now: UnixMillis) -> Result<BrokerReconcileReport, BrokerError> {
        let candidates = {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            ensure_reconciled(&state)?;
            state
                .entries
                .values()
                .filter(|entry| {
                    !matches!(
                        entry.phase,
                        BrokerLifecyclePhase::Destroyed | BrokerLifecyclePhase::ConsumedFailed
                    ) && (now.get() >= entry.expires_at.get()
                        || matches!(
                            entry.phase,
                            BrokerLifecyclePhase::Destroying | BrokerLifecyclePhase::Quarantined
                        )
                        || (entry.phase == BrokerLifecyclePhase::Creating
                            && !state.live_creates.contains(&entry.grant_digest)))
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        let mut report = BrokerReconcileReport::default();
        for entry in candidates {
            let cleanup = self.begin_cleanup(&entry)?;
            if self.cleanup_entry(&cleanup)? {
                report.destroyed = report.destroyed.saturating_add(1);
            } else {
                return Err(BrokerError::EffectiveStateMismatch);
            }
        }
        Ok(report)
    }

    /// Starts a recurring in-process deadline/reconciliation watchdog.
    ///
    /// The returned guard stops and joins the thread on drop. The broker must
    /// be hosted by the privileged broker service; starting this from a runner
    /// process would not satisfy the service-identity boundary. This thread
    /// also does not replace the separately deployed watchdog required to
    /// survive broker-process loss.
    ///
    /// # Errors
    ///
    /// Rejects intervals outside one second through five minutes or a thread
    /// creation failure.
    pub fn start_watchdog(
        self: &Arc<Self>,
        interval: Duration,
    ) -> Result<BrokerWatchdog, BrokerError> {
        if interval < Duration::from_secs(1) || interval > Duration::from_mins(5) {
            return Err(BrokerError::InvalidSandboxSpec);
        }
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let healthy = Arc::new(AtomicBool::new(true));
        let weak = Arc::downgrade(self);
        let thread_stop = Arc::clone(&stop);
        let thread_healthy = Arc::clone(&healthy);
        let thread = thread::Builder::new()
            .name("automata-windows-broker-watchdog".to_owned())
            .spawn(move || {
                loop {
                    let (lock, wake) = thread_stop.as_ref();
                    let stopped = lock.lock().unwrap_or_else(PoisonError::into_inner);
                    let (stopped, _) = wake
                        .wait_timeout_while(stopped, interval, |stopped| !*stopped)
                        .unwrap_or_else(PoisonError::into_inner);
                    if *stopped {
                        break;
                    }
                    drop(stopped);
                    let Some(broker) = weak.upgrade() else {
                        break;
                    };
                    let now = system_unix_millis();
                    thread_healthy.store(
                        now.is_some_and(|now| broker.watchdog_tick(now).is_ok()),
                        Ordering::Release,
                    );
                }
            })
            .map_err(|_| {
                BrokerError::Adapter(HostComputeAdapterError::new(
                    HostComputeOperation::Inspect,
                    BrokerAdapterEffect::KnownNoEffect,
                ))
            })?;
        Ok(BrokerWatchdog {
            stop,
            healthy,
            thread: Some(thread),
        })
    }

    /// Fences all resources for an older or different session of one runner.
    ///
    /// # Errors
    ///
    /// Returns if any fenced resource cannot be proved destroyed.
    pub fn fence_runner_session(
        &self,
        runner_id: RunnerId,
        current_session_id: RunnerSessionId,
        current_runner_generation: u64,
        current_session_epoch: u64,
    ) -> Result<u32, BrokerError> {
        if current_runner_generation == 0 || current_session_epoch == 0 {
            return Err(BrokerError::InvalidSandboxSpec);
        }
        let stale_entries = {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            ensure_reconciled(&state)?;
            state
                .entries
                .values()
                .filter(|entry| {
                    entry.runner_id == runner_id
                        && !matches!(
                            entry.phase,
                            BrokerLifecyclePhase::Destroyed | BrokerLifecyclePhase::ConsumedFailed
                        )
                        && (entry.runner_session_id != current_session_id
                            || entry.runner_generation != current_runner_generation
                            || entry.session_epoch != current_session_epoch)
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        let mut destroyed = 0_u32;
        for entry in stale_entries {
            let cleanup = self.begin_cleanup(&entry)?;
            if !self.cleanup_entry(&cleanup)? {
                return Err(BrokerError::EffectiveStateMismatch);
            }
            destroyed = destroyed.saturating_add(1);
        }
        Ok(destroyed)
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_create(
        &self,
        spec: &SandboxSpec,
        grant: &WindowsHyperVBrokerGrant,
        now: UnixMillis,
    ) -> Result<PreparedCreate, BrokerError> {
        grant
            .claims()
            .validate()
            .map_err(|_| BrokerError::MalformedGrant)?;
        self.keys.verify(grant)?;
        let claims = grant.claims();
        if claims.host_id() != self.host_id {
            return Err(BrokerError::WrongHost);
        }
        if !claims.is_valid_at(now) {
            return Err(BrokerError::GrantNotCurrent);
        }
        let admitted = self
            .profile_contracts
            .resolve(claims.profile_contract_sha256())?
            .ok_or(BrokerError::InvalidProfileContract)?;
        if admitted.host_id() != self.host_id
            || admitted.profile_contract_sha256() != claims.profile_contract_sha256()
            || admitted.profile().attestation() != claims.environment_profile()
            || admitted.valid_until() < claims.expires_at()
            || now >= admitted.valid_until()
        {
            return Err(BrokerError::InvalidProfileContract);
        }
        let (image, keepalive) = match spec.profile().launch() {
            SandboxLaunch::WindowsHyperVContainer { image, keepalive } => (image, keepalive),
            SandboxLaunch::Container { .. } | SandboxLaunch::VirtualMachine { .. } => {
                return Err(BrokerError::InvalidSandboxSpec);
            }
        };
        let allocation = spec
            .resource_allocation()
            .ok_or(BrokerError::InvalidSandboxSpec)?;
        let execution_binding = spec
            .execution_binding()
            .ok_or(BrokerError::InvalidSandboxSpec)?;
        let lease_guard = execution_binding.guard();
        let expected_custody = SandboxCustody::Job {
            runner_id: claims.runner_id(),
            slot_ordinal: NonZeroU16::new(claims.slot()).ok_or(BrokerError::MalformedGrant)?,
        };
        let requests = allocation.requests();
        let limits = allocation.limits();
        let closed_contract = spec.generation().get() == claims.fencing_token().get()
            && spec.custody() == expected_custody
            && spec.profile().attestation() == claims.environment_profile()
            && allocation == claims.job_resource_allocation()
            && spec.workspace() == spec.profile().workspace()
            && spec.network() == NetworkPolicy::Disabled
            && spec.root_filesystem() == RootFilesystemPolicy::Writable
            && spec.privilege() == SandboxPrivilegePolicy::Unprivileged
            && spec.scratch().is_none()
            && spec.services().is_empty()
            && spec.runtime_service_routes().is_empty()
            && spec.sandbox_authorizations().as_slice().is_empty()
            && spec.has_coherent_resource_contract()
            && execution_binding.runner_session_id() == claims.runner_session_id()
            && execution_binding.run_id() == claims.run_id()
            && execution_binding.job_id() == claims.job_id()
            && execution_binding.attempt_id() == claims.attempt_id()
            && lease_guard.lease_id() == claims.lease_id()
            && lease_guard.fencing_token() == claims.fencing_token()
            && execution_binding.accepted_offer_operation_id()
                == claims.accepted_offer_operation_id()
            && execution_binding.accepted_offer_sequence().get()
                == claims.accepted_offer_sequence()
            && execution_binding.job_ir_version() == claims.job_ir_version()
            && execution_binding.job_ir_digest() == claims.job_ir_digest()
            && requests.ephemeral_disk_bytes() == 0
            && requests.gpu_count() == 0
            && limits.ephemeral_disk_bytes() == 0
            && limits.gpu_count() == 0
            && claims.authorizes_sandbox_spec(
                admitted.profile_contract_sha256(),
                spec.generation().get(),
                allocation,
                spec.resources().pids(),
                spec.network() == NetworkPolicy::Disabled,
            )
            && spec.profile() == admitted.profile();
        if !closed_contract {
            return Err(BrokerError::InvalidSandboxSpec);
        }
        let grant_digest = grant.digest();
        let spec_digest = sandbox_spec_digest(spec)?;
        let resource_id = resource_id(grant_digest);
        let ticket_digest = ticket_digest(
            grant_digest,
            &resource_id,
            spec.generation(),
            spec.custody(),
        );
        let resources = spec.resources();
        let entry = BrokerLedgerEntry {
            grant_digest,
            spec_digest,
            resource_id: resource_id.clone(),
            ticket_digest,
            runner_id: claims.runner_id(),
            runner_session_id: claims.runner_session_id(),
            runner_generation: claims.runner_generation(),
            session_epoch: claims.session_epoch(),
            generation: spec.generation().get(),
            custody: spec.custody(),
            profile: claims.environment_profile().clone(),
            image_digest: image.digest(),
            memory_bytes: resources.memory_bytes(),
            cpu_millis: resources.cpu_millis(),
            pids: resources.pids(),
            guest_agent_path: keepalive.program().as_str().to_owned(),
            expires_at: claims.expires_at(),
            phase: BrokerLifecyclePhase::Creating,
            descendants: BTreeSet::new(),
            destroy_operation_id: None,
            operation_epoch: 0,
            active_operation: None,
            completed_operations: BTreeMap::new(),
        };
        Ok(PreparedCreate {
            grant_digest,
            spec_digest,
            request: HostComputeCreateRequest {
                resource_id,
                grant_digest,
                spec_digest,
                operation_id: spec.operation_id(),
                generation: spec.generation(),
                custody: spec.custody(),
                profile: claims.environment_profile().clone(),
                image: image.clone(),
                keepalive: keepalive.clone(),
                workspace: spec.workspace().clone(),
                resources,
            },
            entry,
        })
    }

    fn finish_create(&self, entry: &BrokerLedgerEntry) -> Result<BrokerSandboxTicket, BrokerError> {
        match self.adapter.inspect(&entry.resource_id) {
            Ok(Some(inspection)) if verify_observation(entry, &inspection).is_ok() => {
                let mut ready = entry.clone();
                ready.phase = BrokerLifecyclePhase::Ready;
                self.persist_if_current(entry, ready.clone())?;
                Ok(ticket_from_entry(&ready))
            }
            Ok(Some(_)) => {
                let cleanup = self.begin_cleanup(entry)?;
                let _ = self.cleanup_entry(&cleanup);
                Err(BrokerError::EffectiveStateMismatch)
            }
            Ok(None) => {
                let mut failed = entry.clone();
                failed.phase = BrokerLifecyclePhase::ConsumedFailed;
                self.persist_if_current(entry, failed)?;
                Err(BrokerError::EffectiveStateMismatch)
            }
            Err(error) => {
                self.quarantine_snapshot(entry)?;
                Err(error.into())
            }
        }
    }

    fn reconcile_uncertain_create(
        &self,
        entry: &BrokerLedgerEntry,
    ) -> Result<BrokerSandboxTicket, BrokerError> {
        match self.adapter.inspect(&entry.resource_id) {
            Ok(Some(inspection)) if verify_observation(entry, &inspection).is_ok() => {
                let mut ready = entry.clone();
                ready.phase = BrokerLifecyclePhase::Ready;
                self.persist_if_current(entry, ready.clone())?;
                Ok(ticket_from_entry(&ready))
            }
            Ok(Some(_)) => {
                let cleanup = self.begin_cleanup(entry)?;
                let _ = self.cleanup_entry(&cleanup);
                Err(BrokerError::EffectiveStateMismatch)
            }
            Ok(None) => {
                let mut failed = entry.clone();
                failed.phase = BrokerLifecyclePhase::ConsumedFailed;
                self.persist_if_current(entry, failed)?;
                Err(BrokerError::EffectiveStateMismatch)
            }
            Err(error) => {
                self.quarantine_snapshot(entry)?;
                Err(error.into())
            }
        }
    }

    fn ticket_entry(&self, ticket: &BrokerSandboxTicket) -> Result<BrokerLedgerEntry, BrokerError> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        ensure_reconciled(&state)?;
        ticket_entry(&state, ticket)
    }

    fn current_ticket_entry(
        &self,
        ticket: &BrokerSandboxTicket,
        now: UnixMillis,
    ) -> Result<BrokerLedgerEntry, BrokerError> {
        let entry = self.ticket_entry(ticket)?;
        if now.get() < entry.expires_at.get() {
            return Ok(entry);
        }
        let cleanup = self.begin_cleanup(&entry)?;
        let _ = self.cleanup_entry(&cleanup);
        Err(BrokerError::GrantNotCurrent)
    }

    fn begin_operation(
        &self,
        expected: &BrokerLedgerEntry,
        kind: BrokerOperationKind,
        operation_id: OperationId,
        descendant: Option<&str>,
    ) -> Result<BrokerLedgerEntry, BrokerError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        ensure_reconciled(&state)?;
        let current = state
            .entries
            .get(&expected.grant_digest)
            .cloned()
            .ok_or(BrokerError::OperationFenced)?;
        if current != *expected || current.active_operation.is_some() {
            return Err(BrokerError::OperationFenced);
        }
        let mut intent = current;
        intent.operation_epoch = intent
            .operation_epoch
            .checked_add(1)
            .ok_or(BrokerLedgerError::Capacity)?;
        intent.active_operation = Some(BrokerOperationIntent {
            epoch: intent.operation_epoch,
            kind,
            operation_id,
        });
        if let Some(descendant) = descendant
            && !intent.descendants.insert(descendant.to_owned())
        {
            return Err(BrokerError::ReplayConflict);
        }
        self.persist_locked(&mut state, intent.clone())?;
        Ok(intent)
    }

    fn begin_replayable_operation(
        &self,
        expected: &BrokerLedgerEntry,
        kind: BrokerOperationKind,
        operation_id: OperationId,
        request_fingerprint: Sha256Digest,
        descendant: Option<&str>,
    ) -> Result<ReplayableOperation, BrokerError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        ensure_reconciled(&state)?;
        let current = state
            .entries
            .get(&expected.grant_digest)
            .cloned()
            .ok_or(BrokerError::OperationFenced)?;
        if let Some(completed) = current.completed_operations.get(&operation_id) {
            if completed.kind != kind || completed.request_fingerprint != request_fingerprint {
                return Err(BrokerError::ReplayConflict);
            }
            return match &completed.result {
                BrokerCompletedResult::Pending { reference } => Ok(ReplayableOperation::Replay(
                    load_completed_outcome(self.results.as_ref(), kind, reference)?,
                )),
                BrokerCompletedResult::GarbageCollecting { .. }
                | BrokerCompletedResult::Acknowledged => Err(BrokerError::OperationAcknowledged),
            };
        }
        if current != *expected || current.active_operation.is_some() {
            return Err(BrokerError::OperationFenced);
        }
        if current.completed_operations.len() >= MAX_ENDPOINT_OPERATIONS_PER_JOB {
            return Err(BrokerLedgerError::Capacity.into());
        }
        let mut intent = current;
        intent.operation_epoch = intent
            .operation_epoch
            .checked_add(1)
            .ok_or(BrokerLedgerError::Capacity)?;
        intent.active_operation = Some(BrokerOperationIntent {
            epoch: intent.operation_epoch,
            kind,
            operation_id,
        });
        if let Some(descendant) = descendant
            && !intent.descendants.insert(descendant.to_owned())
        {
            return Err(BrokerError::ReplayConflict);
        }
        self.persist_locked(&mut state, intent.clone())?;
        Ok(ReplayableOperation::Begin(Box::new(intent)))
    }

    fn completed_outcome(
        &self,
        expected: &BrokerLedgerEntry,
        kind: BrokerOperationKind,
        operation_id: OperationId,
        request_fingerprint: Sha256Digest,
    ) -> Result<Option<BrokerCompletedOutcome>, BrokerError> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        ensure_reconciled(&state)?;
        let current = state
            .entries
            .get(&expected.grant_digest)
            .ok_or(BrokerError::OperationFenced)?;
        if current != expected {
            return Err(BrokerError::OperationFenced);
        }
        let Some(completed) = current.completed_operations.get(&operation_id) else {
            return Ok(None);
        };
        if completed.kind != kind || completed.request_fingerprint != request_fingerprint {
            return Err(BrokerError::ReplayConflict);
        }
        match &completed.result {
            BrokerCompletedResult::Pending { reference } => {
                load_completed_outcome(self.results.as_ref(), kind, reference).map(Some)
            }
            BrokerCompletedResult::GarbageCollecting { .. }
            | BrokerCompletedResult::Acknowledged => Err(BrokerError::OperationAcknowledged),
        }
    }

    fn finish_operation(
        &self,
        expected: &BrokerLedgerEntry,
        phase: BrokerLifecyclePhase,
        descendant: Option<&str>,
    ) -> Result<(), BrokerError> {
        let mut finished = expected.clone();
        if finished.active_operation.is_none() {
            return Err(BrokerLedgerError::Corrupt.into());
        }
        finished.active_operation = None;
        finished.phase = phase;
        if let Some(descendant) = descendant
            && !finished.descendants.remove(descendant)
        {
            return Err(BrokerLedgerError::Corrupt.into());
        }
        self.persist_if_current(expected, finished)
    }

    fn finish_replayable_operation(
        &self,
        expected: &BrokerLedgerEntry,
        phase: BrokerLifecyclePhase,
        request_fingerprint: Sha256Digest,
        result: DurableContentRef,
        descendant: Option<&str>,
    ) -> Result<(), BrokerError> {
        let active = expected
            .active_operation
            .as_ref()
            .ok_or(BrokerLedgerError::Corrupt)?;
        if result.kind() != ContentKind::EndpointResult
            || expected
                .completed_operations
                .contains_key(&active.operation_id)
        {
            return Err(BrokerLedgerError::Corrupt.into());
        }
        let mut finished = expected.clone();
        finished.active_operation = None;
        finished.phase = phase;
        if let Some(descendant) = descendant
            && !finished.descendants.remove(descendant)
        {
            return Err(BrokerLedgerError::Corrupt.into());
        }
        finished.completed_operations.insert(
            active.operation_id,
            BrokerCompletedOperation {
                kind: active.kind,
                request_fingerprint,
                result: BrokerCompletedResult::Pending { reference: result },
            },
        );
        validate_ledger_entry(&finished)?;
        self.persist_if_current(expected, finished)
    }

    fn commit_replayable_operation(
        &self,
        expected: &BrokerLedgerEntry,
        phase: BrokerLifecyclePhase,
        request_fingerprint: Sha256Digest,
        result: &BrokerCompletedOutcome,
        descendant: Option<&str>,
        reservation: Box<dyn BrokerResultCapacityReservation<'_> + '_>,
    ) -> Result<(), BrokerError> {
        let encoded = encode_completed_outcome(result)?;
        let publication = match reservation.persist(&encoded) {
            Ok(publication) => publication,
            Err(error) => {
                self.quarantine_operation(expected)?;
                return Err(error.into());
            }
        };
        let reference = publication.reference().clone();
        self.finish_replayable_operation(
            expected,
            phase,
            request_fingerprint,
            reference,
            descendant,
        )?;
        publication.adopt();
        Ok(())
    }

    fn finish_result_gc(
        &self,
        grant_digest: Sha256Digest,
        operation_id: OperationId,
        reference: &DurableContentRef,
        missing_is_recovered: bool,
    ) -> Result<(), BrokerError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        ensure_reconciled(&state)?;
        let current = state
            .entries
            .get(&grant_digest)
            .cloned()
            .ok_or(BrokerError::OperationFenced)?;
        let completed = current
            .completed_operations
            .get(&operation_id)
            .ok_or(BrokerError::OperationNotCompleted)?;
        match &completed.result {
            BrokerCompletedResult::Acknowledged => return Ok(()),
            BrokerCompletedResult::Pending { .. } => return Err(BrokerError::OperationFenced),
            BrokerCompletedResult::GarbageCollecting {
                reference: current_reference,
            } if current_reference == reference => {}
            BrokerCompletedResult::GarbageCollecting { .. } => {
                return Err(BrokerLedgerError::Corrupt.into());
            }
        }
        let shared = state.entries.values().any(|entry| {
            entry
                .completed_operations
                .iter()
                .any(|(candidate_id, candidate)| {
                    !(entry.grant_digest == grant_digest && *candidate_id == operation_id)
                        && matches!(
                            &candidate.result,
                            BrokerCompletedResult::Pending {
                                reference: candidate_reference
                            } if candidate_reference == reference
                        )
                })
        });
        if !shared {
            let removed = self.results.remove(reference)?;
            if !removed && !missing_is_recovered {
                return Err(BrokerResultStoreError::Corrupt.into());
            }
        }
        let mut acknowledged = current;
        acknowledged
            .completed_operations
            .get_mut(&operation_id)
            .ok_or(BrokerLedgerError::Corrupt)?
            .result = BrokerCompletedResult::Acknowledged;
        self.persist_locked(&mut state, acknowledged)
    }

    fn finish_reconciled_result_gc(
        &self,
        grant_digest: Sha256Digest,
        operation_id: OperationId,
    ) -> Result<(), BrokerError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let current = state
            .entries
            .get(&grant_digest)
            .cloned()
            .ok_or(BrokerLedgerError::Corrupt)?;
        let completed = current
            .completed_operations
            .get(&operation_id)
            .ok_or(BrokerLedgerError::Corrupt)?;
        if !matches!(
            completed.result,
            BrokerCompletedResult::GarbageCollecting { .. }
        ) {
            return Err(BrokerLedgerError::Corrupt.into());
        }
        let mut acknowledged = current;
        acknowledged
            .completed_operations
            .get_mut(&operation_id)
            .ok_or(BrokerLedgerError::Corrupt)?
            .result = BrokerCompletedResult::Acknowledged;
        self.persist_locked(&mut state, acknowledged)
    }

    fn reconcile_results(&self) -> Result<(), BrokerError> {
        let (retained_results, pending_garbage) = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.reconciled = false;
            state.live_creates.clear();
            let mut retained = Vec::new();
            let mut garbage = Vec::new();
            for entry in state.entries.values() {
                for (operation_id, operation) in &entry.completed_operations {
                    match &operation.result {
                        BrokerCompletedResult::Pending { reference } => {
                            retained.push(reference.clone());
                        }
                        BrokerCompletedResult::GarbageCollecting { .. } => {
                            garbage.push((entry.grant_digest, *operation_id));
                        }
                        BrokerCompletedResult::Acknowledged => {}
                    }
                }
            }
            (retained, garbage)
        };
        self.results.reconcile(&retained_results)?;
        for (grant_digest, operation_id) in pending_garbage {
            self.finish_reconciled_result_gc(grant_digest, operation_id)?;
        }
        Ok(())
    }

    fn quarantine_operation(&self, expected: &BrokerLedgerEntry) -> Result<(), BrokerError> {
        if expected.active_operation.is_none() {
            return Err(BrokerLedgerError::Corrupt.into());
        }
        self.quarantine_snapshot(expected)
    }

    fn quarantine_snapshot(&self, expected: &BrokerLedgerEntry) -> Result<(), BrokerError> {
        let mut quarantined = expected.clone();
        quarantined.phase = BrokerLifecyclePhase::Quarantined;
        quarantined.active_operation = None;
        self.persist_if_current(expected, quarantined)
    }

    fn begin_cleanup(
        &self,
        snapshot: &BrokerLedgerEntry,
    ) -> Result<BrokerLedgerEntry, BrokerError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let current = state
            .entries
            .get(&snapshot.grant_digest)
            .cloned()
            .ok_or(BrokerError::OperationFenced)?;
        if !same_durable_identity(&current, snapshot) {
            return Err(BrokerError::OperationFenced);
        }
        if current.phase == BrokerLifecyclePhase::Destroyed {
            return Ok(current);
        }
        if current.phase == BrokerLifecyclePhase::Destroying {
            return Ok(current);
        }
        let mut destroying = current;
        destroying.phase = BrokerLifecyclePhase::Destroying;
        destroying.active_operation = None;
        destroying.operation_epoch = destroying
            .operation_epoch
            .checked_add(1)
            .ok_or(BrokerLedgerError::Capacity)?;
        self.persist_locked(&mut state, destroying.clone())?;
        Ok(destroying)
    }

    fn cleanup_entry(&self, expected: &BrokerLedgerEntry) -> Result<bool, BrokerError> {
        if expected.phase == BrokerLifecyclePhase::Destroyed {
            return Ok(true);
        }
        if expected.phase != BrokerLifecyclePhase::Destroying {
            return Err(BrokerLedgerError::Corrupt.into());
        }
        let descendants = self.adapter.terminate_descendants(&expected.resource_id);
        let destroy = self.adapter.destroy(&expected.resource_id);
        match self.adapter.inspect(&expected.resource_id) {
            Ok(None) => {
                let mut destroyed = expected.clone();
                destroyed.phase = BrokerLifecyclePhase::Destroyed;
                destroyed.descendants.clear();
                destroyed.active_operation = None;
                match self.persist_if_current(expected, destroyed) {
                    Ok(()) => Ok(true),
                    Err(BrokerError::OperationFenced) => {
                        let current = self.entry_by_digest(expected.grant_digest)?;
                        Ok(current.phase == BrokerLifecyclePhase::Destroyed)
                    }
                    Err(error) => Err(error),
                }
            }
            Ok(Some(_)) => {
                let mut quarantined = expected.clone();
                quarantined.phase = BrokerLifecyclePhase::Quarantined;
                self.persist_if_current(expected, quarantined)?;
                if let Some(error) = descendants.err().or_else(|| destroy.err()) {
                    return Err(error.into());
                }
                Ok(false)
            }
            Err(error) => {
                let mut quarantined = expected.clone();
                quarantined.phase = BrokerLifecyclePhase::Quarantined;
                self.persist_if_current(expected, quarantined)?;
                Err(error.into())
            }
        }
    }

    fn inspect_verified(&self, expected: &BrokerLedgerEntry) -> Result<(), BrokerError> {
        match self.adapter.inspect(&expected.resource_id) {
            Ok(Some(inspection)) if verify_observation(expected, &inspection).is_ok() => {
                self.assert_snapshot_current(expected)
            }
            Ok(Some(_)) => {
                let cleanup = self.begin_cleanup(expected)?;
                let _ = self.cleanup_entry(&cleanup);
                Err(BrokerError::EffectiveStateMismatch)
            }
            Ok(None) => {
                let mut failed = expected.clone();
                failed.phase = BrokerLifecyclePhase::ConsumedFailed;
                failed.descendants.clear();
                failed.active_operation = None;
                self.persist_if_current(expected, failed)?;
                Err(BrokerError::EffectiveStateMismatch)
            }
            Err(error) => {
                self.quarantine_snapshot(expected)?;
                Err(error.into())
            }
        }
    }

    fn assert_snapshot_current(&self, expected: &BrokerLedgerEntry) -> Result<(), BrokerError> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let current = state
            .entries
            .get(&expected.grant_digest)
            .ok_or(BrokerError::OperationFenced)?;
        if current == expected {
            Ok(())
        } else {
            Err(BrokerError::OperationFenced)
        }
    }

    fn entry_by_digest(
        &self,
        grant_digest: Sha256Digest,
    ) -> Result<BrokerLedgerEntry, BrokerError> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .get(&grant_digest)
            .cloned()
            .ok_or(BrokerError::OperationFenced)
    }

    fn persist_if_current(
        &self,
        expected: &BrokerLedgerEntry,
        replacement: BrokerLedgerEntry,
    ) -> Result<(), BrokerError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.entries.get(&expected.grant_digest) != Some(expected) {
            return Err(BrokerError::OperationFenced);
        }
        self.persist_locked(&mut state, replacement)
    }

    fn persist_locked(
        &self,
        state: &mut BrokerState,
        entry: BrokerLedgerEntry,
    ) -> Result<(), BrokerError> {
        self.ledger.append(&entry)?;
        state.entries.insert(entry.grant_digest, entry);
        Ok(())
    }
}

impl fmt::Debug for RestrictedWindowsHyperVBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        formatter
            .debug_struct("RestrictedWindowsHyperVBroker")
            .field("host_id", &self.host_id)
            .field("keys", &self.keys)
            .field("entry_count", &state.entries.len())
            .field("reconciled", &state.reconciled)
            .finish_non_exhaustive()
    }
}

fn ensure_reconciled(state: &BrokerState) -> Result<(), BrokerError> {
    state
        .reconciled
        .then_some(())
        .ok_or(BrokerError::ReconciliationRequired)
}

fn ticket_entry(
    state: &BrokerState,
    ticket: &BrokerSandboxTicket,
) -> Result<BrokerLedgerEntry, BrokerError> {
    let entry = state
        .entries
        .get(&ticket.grant_digest)
        .ok_or(BrokerError::InvalidTicket)?;
    if entry.ticket_digest != ticket.ticket_digest {
        return Err(BrokerError::InvalidTicket);
    }
    Ok(entry.clone())
}

fn ticket_from_entry(entry: &BrokerLedgerEntry) -> BrokerSandboxTicket {
    BrokerSandboxTicket {
        grant_digest: entry.grant_digest,
        ticket_digest: entry.ticket_digest,
    }
}

fn verify_observation(
    entry: &BrokerLedgerEntry,
    inspection: &HostComputeInspection,
) -> Result<(), BrokerError> {
    let resources = inspection.resources();
    let valid = inspection.resource_id == entry.resource_id
        && inspection.grant_digest == entry.grant_digest
        && inspection.spec_digest == entry.spec_digest
        && inspection.generation.get() == entry.generation
        && inspection.custody == entry.custody
        && inspection.profile == entry.profile
        && inspection.image_digest == entry.image_digest
        && resources.memory_bytes() == entry.memory_bytes
        && resources.cpu_millis() == entry.cpu_millis
        && resources.pids() == entry.pids
        && inspection.isolation == HostComputeObservedIsolation::HyperV
        && !matches!(inspection.state, HostComputeObservedState::Degraded)
        && inspection.has_closed_policy();
    valid
        .then_some(())
        .ok_or(BrokerError::EffectiveStateMismatch)
}

fn validate_ledger_entry(entry: &BrokerLedgerEntry) -> Result<(), BrokerError> {
    let valid_resource = entry.resource_id.starts_with("automata-hv-")
        && entry.resource_id.len() == "automata-hv-".len() + 64
        && entry
            .resource_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    let valid_custody = matches!(
        entry.custody,
        SandboxCustody::Job { runner_id, .. } if runner_id == entry.runner_id
    );
    let valid_binding = SandboxGeneration::new(entry.generation).is_ok_and(|generation| {
        entry.resource_id == resource_id(entry.grant_digest)
            && entry.ticket_digest
                == ticket_digest(
                    entry.grant_digest,
                    &entry.resource_id,
                    generation,
                    entry.custody,
                )
    });
    let valid_guest_agent = TargetPath::windows(entry.guest_agent_path.clone()).is_ok();
    let completed_valid = entry
        .completed_operations
        .values()
        .all(|operation| validate_completed_operation(operation).is_ok());
    if is_zero_digest(entry.grant_digest)
        || is_zero_digest(entry.spec_digest)
        || is_zero_digest(entry.ticket_digest)
        || is_zero_digest(entry.profile.digest())
        || is_zero_digest(entry.image_digest)
        || !valid_resource
        || entry.runner_generation == 0
        || entry.session_epoch == 0
        || entry.generation == 0
        || !valid_custody
        || !valid_binding
        || entry.memory_bytes == 0
        || entry.cpu_millis == 0
        || entry.pids == 0
        || !valid_guest_agent
        || entry.descendants.len() > 1024
        || entry.completed_operations.len() > MAX_ENDPOINT_OPERATIONS_PER_JOB
        || !completed_valid
        || entry.active_operation.as_ref().is_some_and(|operation| {
            operation.epoch == 0 || operation.epoch != entry.operation_epoch
        })
        || (matches!(
            entry.phase,
            BrokerLifecyclePhase::Destroying
                | BrokerLifecyclePhase::Destroyed
                | BrokerLifecyclePhase::ConsumedFailed
        ) && entry.active_operation.is_some())
    {
        return Err(BrokerLedgerError::Corrupt.into());
    }
    Ok(())
}

fn same_durable_identity(left: &BrokerLedgerEntry, right: &BrokerLedgerEntry) -> bool {
    left.grant_digest == right.grant_digest
        && left.spec_digest == right.spec_digest
        && left.resource_id == right.resource_id
        && left.ticket_digest == right.ticket_digest
        && left.runner_id == right.runner_id
        && left.runner_session_id == right.runner_session_id
        && left.runner_generation == right.runner_generation
        && left.session_epoch == right.session_epoch
        && left.generation == right.generation
        && left.custody == right.custody
        && left.profile == right.profile
        && left.image_digest == right.image_digest
        && left.memory_bytes == right.memory_bytes
        && left.cpu_millis == right.cpu_millis
        && left.pids == right.pids
        && left.guest_agent_path == right.guest_agent_path
        && left.expires_at == right.expires_at
}

fn exec_request_fingerprint(
    command: &ExecutionCommand,
    process_limit: u32,
) -> Result<Sha256Digest, BrokerError> {
    let mut digest = Sha256::new();
    digest.update(EXEC_REQUEST_DOMAIN);
    hash_field(&mut digest, command.argv().program().as_str().as_bytes());
    hash_field(
        &mut digest,
        &u64::try_from(command.argv().arguments().len())
            .map_err(|_| BrokerError::ReplayConflict)?
            .to_be_bytes(),
    );
    for argument in command.argv().arguments() {
        hash_field(&mut digest, argument.as_bytes());
    }
    hash_field(
        &mut digest,
        &u64::try_from(command.environment().values().len())
            .map_err(|_| BrokerError::ReplayConflict)?
            .to_be_bytes(),
    );
    for variable in command.environment().values() {
        hash_field(&mut digest, variable.name().as_str().as_bytes());
        hash_field(&mut digest, variable.value().expose().as_bytes());
        hash_field(&mut digest, &[u8::from(variable.is_secret())]);
    }
    hash_field(&mut digest, command.working_directory().as_str().as_bytes());
    let timeout_millis =
        u64::try_from(command.timeout().as_millis()).map_err(|_| BrokerError::ReplayConflict)?;
    hash_field(&mut digest, &timeout_millis.to_be_bytes());
    hash_field(
        &mut digest,
        &u64::try_from(command.output_limit())
            .map_err(|_| BrokerError::ReplayConflict)?
            .to_be_bytes(),
    );
    hash_field(&mut digest, &process_limit.to_be_bytes());
    Ok(Sha256Digest::from_bytes(digest.finalize().into()))
}

fn copy_to_request_fingerprint(request: &CopyToRequest) -> Sha256Digest {
    domain_digest(
        COPY_TO_REQUEST_DOMAIN,
        &[request.target().as_str().as_bytes(), request.content()],
    )
}

fn copy_from_request_fingerprint(request: &CopyFromRequest) -> Result<Sha256Digest, BrokerError> {
    Ok(domain_digest(
        COPY_FROM_REQUEST_DOMAIN,
        &[
            request.source().as_str().as_bytes(),
            &u64::try_from(request.byte_limit())
                .map_err(|_| BrokerError::ReplayConflict)?
                .to_be_bytes(),
        ],
    ))
}

fn completed_exec_outcome(output: &ExecutionOutput) -> BrokerCompletedOutcome {
    let records = output
        .records()
        .iter()
        .map(|record| BrokerDurableOutputRecord {
            stream: match record.stream() {
                ExecutionOutputStream::Stdout => BrokerDurableOutputStream::Stdout,
                ExecutionOutputStream::Stderr => BrokerDurableOutputStream::Stderr,
            },
            content: record.bytes().to_vec(),
            end_of_stream: record.is_end_of_stream(),
        })
        .collect();
    BrokerCompletedOutcome::Exec {
        termination: match output.termination() {
            ExecutionTermination::Exited(code) => BrokerDurableTermination::Exited(code),
            ExecutionTermination::Signalled => BrokerDurableTermination::Signalled,
            ExecutionTermination::TimedOut => BrokerDurableTermination::TimedOut,
            ExecutionTermination::Cancelled => BrokerDurableTermination::Cancelled,
        },
        records,
        truncated: output.was_truncated(),
    }
}

fn replay_exec_outcome(result: &BrokerCompletedOutcome) -> Result<ExecutionOutput, BrokerError> {
    execution_output_from_completed(result).map_err(Into::into)
}

fn execution_output_from_completed(
    result: &BrokerCompletedOutcome,
) -> Result<ExecutionOutput, BrokerResultStoreError> {
    let BrokerCompletedOutcome::Exec {
        termination,
        records,
        truncated,
    } = result
    else {
        return Err(BrokerResultStoreError::Corrupt);
    };
    let records = records
        .iter()
        .map(|record| {
            let stream = match record.stream {
                BrokerDurableOutputStream::Stdout => ExecutionOutputStream::Stdout,
                BrokerDurableOutputStream::Stderr => ExecutionOutputStream::Stderr,
            };
            if record.end_of_stream {
                if !record.content.is_empty() {
                    return Err(BrokerResultStoreError::Corrupt);
                }
                Ok(ExecutionOutputRecord::end_of_stream(stream))
            } else {
                ExecutionOutputRecord::data(stream, record.content.clone())
                    .map_err(|_| BrokerResultStoreError::Corrupt)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let termination = match termination {
        BrokerDurableTermination::Exited(code) => ExecutionTermination::Exited(*code),
        BrokerDurableTermination::Signalled => ExecutionTermination::Signalled,
        BrokerDurableTermination::TimedOut => ExecutionTermination::TimedOut,
        BrokerDurableTermination::Cancelled => ExecutionTermination::Cancelled,
    };
    ExecutionOutput::new(termination, records, *truncated)
        .map_err(|_| BrokerResultStoreError::Corrupt)
}

fn replay_copy_to_outcome(result: &BrokerCompletedOutcome) -> Result<(), BrokerError> {
    matches!(result, BrokerCompletedOutcome::CopyTo)
        .then_some(())
        .ok_or(BrokerResultStoreError::Corrupt.into())
}

fn replay_copy_from_outcome(
    result: &BrokerCompletedOutcome,
    byte_limit: usize,
) -> Result<Vec<u8>, BrokerError> {
    let BrokerCompletedOutcome::CopyFrom { content } = result else {
        return Err(BrokerResultStoreError::Corrupt.into());
    };
    if content.len() > byte_limit {
        return Err(BrokerResultStoreError::Corrupt.into());
    }
    Ok(content.clone())
}

fn completed_outcome_kind(result: &BrokerCompletedOutcome) -> BrokerOperationKind {
    match result {
        BrokerCompletedOutcome::Exec { .. } => BrokerOperationKind::Exec,
        BrokerCompletedOutcome::CopyTo => BrokerOperationKind::CopyTo,
        BrokerCompletedOutcome::CopyFrom { .. } => BrokerOperationKind::CopyFrom,
    }
}

fn validate_completed_operation(
    operation: &BrokerCompletedOperation,
) -> Result<(), BrokerLedgerError> {
    let valid_reference = match &operation.result {
        BrokerCompletedResult::Pending { reference }
        | BrokerCompletedResult::GarbageCollecting { reference } => {
            reference.kind() == ContentKind::EndpointResult
        }
        BrokerCompletedResult::Acknowledged => true,
    };
    if is_zero_digest(operation.request_fingerprint) || !valid_reference {
        return Err(BrokerLedgerError::Corrupt);
    }
    Ok(())
}

fn maximum_completed_outcome_bytes(
    kind: BrokerOperationKind,
    payload_limit: usize,
) -> Result<usize, BrokerResultStoreError> {
    let prefix = RESULT_HEADER
        .len()
        .checked_add(3)
        .ok_or(BrokerResultStoreError::Capacity)?;
    match kind {
        BrokerOperationKind::Exec => {
            if payload_limit > MAX_EXECUTION_OUTPUT_BYTES {
                return Err(BrokerResultStoreError::Capacity);
            }
            prefix
                .checked_add(10)
                .and_then(|bytes| {
                    bytes.checked_add(MAX_EXECUTION_OUTPUT_RECORDS * RESULT_RECORD_METADATA_BYTES)
                })
                .and_then(|bytes| bytes.checked_add(payload_limit))
                .ok_or(BrokerResultStoreError::Capacity)
        }
        BrokerOperationKind::CopyTo => Ok(prefix),
        BrokerOperationKind::CopyFrom => {
            if payload_limit > MAX_COPY_BYTES {
                return Err(BrokerResultStoreError::Capacity);
            }
            prefix
                .checked_add(4)
                .and_then(|bytes| bytes.checked_add(payload_limit))
                .ok_or(BrokerResultStoreError::Capacity)
        }
        BrokerOperationKind::Attach => Err(BrokerResultStoreError::Corrupt),
    }
}

fn encode_completed_outcome(
    outcome: &BrokerCompletedOutcome,
) -> Result<Vec<u8>, BrokerResultStoreError> {
    let kind = completed_outcome_kind(outcome);
    let payload_bytes = match outcome {
        BrokerCompletedOutcome::Exec { records, .. } => {
            execution_output_from_completed(outcome)?;
            records.iter().try_fold(0_usize, |total, record| {
                total.checked_add(record.content.len())
            })
        }
        BrokerCompletedOutcome::CopyTo => Some(0),
        BrokerCompletedOutcome::CopyFrom { content } => Some(content.len()),
    }
    .ok_or(BrokerResultStoreError::Capacity)?;
    let maximum = maximum_completed_outcome_bytes(kind, payload_bytes)?;
    let record_bytes = match outcome {
        BrokerCompletedOutcome::Exec { records, .. } => records
            .len()
            .checked_mul(RESULT_RECORD_METADATA_BYTES)
            .and_then(|bytes| bytes.checked_add(10)),
        BrokerCompletedOutcome::CopyTo => Some(0),
        BrokerCompletedOutcome::CopyFrom { .. } => Some(4),
    };
    let capacity = RESULT_HEADER
        .len()
        .checked_add(3)
        .and_then(|bytes| bytes.checked_add(record_bytes?))
        .and_then(|bytes| bytes.checked_add(payload_bytes))
        .ok_or(BrokerResultStoreError::Capacity)?;
    if capacity > maximum {
        return Err(BrokerResultStoreError::Capacity);
    }
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(RESULT_HEADER);
    encoded.extend_from_slice(&RESULT_SCHEMA_VERSION.to_be_bytes());
    encoded.push(match kind {
        BrokerOperationKind::Exec => 1,
        BrokerOperationKind::CopyTo => 2,
        BrokerOperationKind::CopyFrom => 3,
        BrokerOperationKind::Attach => return Err(BrokerResultStoreError::Corrupt),
    });
    match outcome {
        BrokerCompletedOutcome::Exec {
            termination,
            records,
            truncated,
        } => {
            let (termination_tag, exit_code) = match termination {
                BrokerDurableTermination::Exited(code) => (0, *code),
                BrokerDurableTermination::Signalled => (1, 0),
                BrokerDurableTermination::TimedOut => (2, 0),
                BrokerDurableTermination::Cancelled => (3, 0),
            };
            encoded.push(termination_tag);
            encoded.extend_from_slice(&exit_code.to_be_bytes());
            encoded.push(u8::from(*truncated));
            encoded.extend_from_slice(
                &u32::try_from(records.len())
                    .map_err(|_| BrokerResultStoreError::Capacity)?
                    .to_be_bytes(),
            );
            for record in records {
                encoded.push(match record.stream {
                    BrokerDurableOutputStream::Stdout => 0,
                    BrokerDurableOutputStream::Stderr => 1,
                });
                encoded.push(u8::from(record.end_of_stream));
                encoded.extend_from_slice(
                    &u32::try_from(record.content.len())
                        .map_err(|_| BrokerResultStoreError::Capacity)?
                        .to_be_bytes(),
                );
                encoded.extend_from_slice(&record.content);
            }
        }
        BrokerCompletedOutcome::CopyTo => {}
        BrokerCompletedOutcome::CopyFrom { content } => {
            encoded.extend_from_slice(
                &u32::try_from(content.len())
                    .map_err(|_| BrokerResultStoreError::Capacity)?
                    .to_be_bytes(),
            );
            encoded.extend_from_slice(content);
        }
    }
    if encoded.len() != capacity {
        return Err(BrokerResultStoreError::Corrupt);
    }
    Ok(encoded)
}

fn decode_completed_outcome(
    encoded: &[u8],
) -> Result<BrokerCompletedOutcome, BrokerResultStoreError> {
    let mut decoder = CompletedOutcomeDecoder::new(encoded)?;
    let outcome = match decoder.byte()? {
        1 => {
            let termination_tag = decoder.byte()?;
            let exit_code = decoder.i32()?;
            let termination = match (termination_tag, exit_code) {
                (0, code) => BrokerDurableTermination::Exited(code),
                (1, 0) => BrokerDurableTermination::Signalled,
                (2, 0) => BrokerDurableTermination::TimedOut,
                (3, 0) => BrokerDurableTermination::Cancelled,
                _ => return Err(BrokerResultStoreError::Corrupt),
            };
            let truncated = match decoder.byte()? {
                0 => false,
                1 => true,
                _ => return Err(BrokerResultStoreError::Corrupt),
            };
            let record_count =
                usize::try_from(decoder.u32()?).map_err(|_| BrokerResultStoreError::Corrupt)?;
            if record_count > MAX_EXECUTION_OUTPUT_RECORDS {
                return Err(BrokerResultStoreError::Corrupt);
            }
            let mut records = Vec::with_capacity(record_count);
            let mut output_bytes = 0_usize;
            for _ in 0..record_count {
                let stream = match decoder.byte()? {
                    0 => BrokerDurableOutputStream::Stdout,
                    1 => BrokerDurableOutputStream::Stderr,
                    _ => return Err(BrokerResultStoreError::Corrupt),
                };
                let end_of_stream = match decoder.byte()? {
                    0 => false,
                    1 => true,
                    _ => return Err(BrokerResultStoreError::Corrupt),
                };
                let length =
                    usize::try_from(decoder.u32()?).map_err(|_| BrokerResultStoreError::Corrupt)?;
                output_bytes = output_bytes
                    .checked_add(length)
                    .filter(|bytes| *bytes <= MAX_EXECUTION_OUTPUT_BYTES)
                    .ok_or(BrokerResultStoreError::Corrupt)?;
                records.push(BrokerDurableOutputRecord {
                    stream,
                    content: decoder.bytes(length)?.to_vec(),
                    end_of_stream,
                });
            }
            let outcome = BrokerCompletedOutcome::Exec {
                termination,
                records,
                truncated,
            };
            execution_output_from_completed(&outcome)?;
            outcome
        }
        2 => BrokerCompletedOutcome::CopyTo,
        3 => {
            let length =
                usize::try_from(decoder.u32()?).map_err(|_| BrokerResultStoreError::Corrupt)?;
            if length > MAX_COPY_BYTES {
                return Err(BrokerResultStoreError::Corrupt);
            }
            BrokerCompletedOutcome::CopyFrom {
                content: decoder.bytes(length)?.to_vec(),
            }
        }
        _ => return Err(BrokerResultStoreError::Corrupt),
    };
    decoder.finish()?;
    Ok(outcome)
}

fn load_completed_outcome(
    results: &dyn BrokerResultStore,
    expected_kind: BrokerOperationKind,
    reference: &DurableContentRef,
) -> Result<BrokerCompletedOutcome, BrokerError> {
    if reference.kind() != ContentKind::EndpointResult {
        return Err(BrokerResultStoreError::Corrupt.into());
    }
    let encoded = results.load(reference)?;
    let outcome = decode_completed_outcome(&encoded)?;
    if completed_outcome_kind(&outcome) != expected_kind
        || encode_completed_outcome(&outcome)? != encoded
    {
        return Err(BrokerResultStoreError::Corrupt.into());
    }
    Ok(outcome)
}

struct CompletedOutcomeDecoder<'a> {
    encoded: &'a [u8],
    cursor: usize,
}

impl<'a> CompletedOutcomeDecoder<'a> {
    fn new(encoded: &'a [u8]) -> Result<Self, BrokerResultStoreError> {
        let prefix = RESULT_HEADER
            .len()
            .checked_add(2)
            .ok_or(BrokerResultStoreError::Corrupt)?;
        if encoded.len() < prefix
            || &encoded[..RESULT_HEADER.len()] != RESULT_HEADER
            || u16::from_be_bytes(
                encoded[RESULT_HEADER.len()..prefix]
                    .try_into()
                    .map_err(|_| BrokerResultStoreError::Corrupt)?,
            ) != RESULT_SCHEMA_VERSION
        {
            return Err(BrokerResultStoreError::Corrupt);
        }
        Ok(Self {
            encoded,
            cursor: prefix,
        })
    }

    fn byte(&mut self) -> Result<u8, BrokerResultStoreError> {
        let byte = *self
            .encoded
            .get(self.cursor)
            .ok_or(BrokerResultStoreError::Corrupt)?;
        self.cursor += 1;
        Ok(byte)
    }

    fn u32(&mut self) -> Result<u32, BrokerResultStoreError> {
        let bytes: [u8; 4] = self
            .bytes(4)?
            .try_into()
            .map_err(|_| BrokerResultStoreError::Corrupt)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn i32(&mut self) -> Result<i32, BrokerResultStoreError> {
        let bytes: [u8; 4] = self
            .bytes(4)?
            .try_into()
            .map_err(|_| BrokerResultStoreError::Corrupt)?;
        Ok(i32::from_be_bytes(bytes))
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], BrokerResultStoreError> {
        let end = self
            .cursor
            .checked_add(length)
            .filter(|end| *end <= self.encoded.len())
            .ok_or(BrokerResultStoreError::Corrupt)?;
        let bytes = &self.encoded[self.cursor..end];
        self.cursor = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), BrokerResultStoreError> {
        if self.cursor == self.encoded.len() {
            Ok(())
        } else {
            Err(BrokerResultStoreError::Corrupt)
        }
    }
}

fn sandbox_spec_digest(spec: &SandboxSpec) -> Result<Sha256Digest, BrokerError> {
    let mut digest = Sha256::new();
    digest.update(SPEC_DOMAIN);
    hash_field(&mut digest, spec.operation_id().as_uuid().as_bytes());
    hash_field(&mut digest, &spec.generation().get().to_be_bytes());
    hash_custody(&mut digest, spec.custody());
    hash_field(&mut digest, spec.profile().id().as_str().as_bytes());
    hash_field(&mut digest, spec.profile().digest().as_bytes());
    let (image, keepalive) = match spec.profile().launch() {
        SandboxLaunch::WindowsHyperVContainer { image, keepalive } => (image, keepalive),
        SandboxLaunch::Container { .. } | SandboxLaunch::VirtualMachine { .. } => {
            return Err(BrokerError::InvalidSandboxSpec);
        }
    };
    hash_field(&mut digest, image.reference().as_bytes());
    hash_field(&mut digest, image.digest().as_bytes());
    hash_field(&mut digest, keepalive.program().as_str().as_bytes());
    for argument in keepalive.arguments() {
        hash_field(&mut digest, argument.as_bytes());
    }
    hash_field(&mut digest, spec.profile().workspace().as_str().as_bytes());
    hash_field(&mut digest, spec.workspace().as_str().as_bytes());
    for variable in spec.profile().default_environment().values() {
        hash_field(&mut digest, variable.name().as_str().as_bytes());
        hash_field(&mut digest, variable.value().expose().as_bytes());
        hash_field(&mut digest, &[u8::from(variable.is_secret())]);
    }
    hash_field(&mut digest, &[spec.network() as u8]);
    hash_field(&mut digest, &[spec.root_filesystem() as u8]);
    hash_field(&mut digest, &[spec.privilege() as u8]);
    let resources = spec.resources();
    hash_field(&mut digest, &resources.memory_bytes().to_be_bytes());
    hash_field(&mut digest, &resources.cpu_millis().to_be_bytes());
    hash_field(&mut digest, &resources.pids().to_be_bytes());
    let allocation = spec
        .resource_allocation()
        .ok_or(BrokerError::InvalidSandboxSpec)?;
    for capacity in [allocation.requests(), allocation.limits()] {
        hash_field(&mut digest, &capacity.cpu_millis().to_be_bytes());
        hash_field(&mut digest, &capacity.memory_bytes().to_be_bytes());
        hash_field(&mut digest, &capacity.ephemeral_disk_bytes().to_be_bytes());
        hash_field(&mut digest, &capacity.gpu_count().to_be_bytes());
    }
    let binding = spec
        .execution_binding()
        .ok_or(BrokerError::InvalidSandboxSpec)?;
    let guard = binding.guard();
    hash_field(
        &mut digest,
        binding.runner_session_id().as_uuid().as_bytes(),
    );
    hash_field(&mut digest, binding.run_id().as_uuid().as_bytes());
    hash_field(&mut digest, binding.job_id().as_uuid().as_bytes());
    hash_field(&mut digest, binding.attempt_id().as_uuid().as_bytes());
    hash_field(&mut digest, guard.lease_id().as_uuid().as_bytes());
    hash_field(&mut digest, &guard.fencing_token().get().to_be_bytes());
    hash_field(
        &mut digest,
        binding.accepted_offer_operation_id().as_uuid().as_bytes(),
    );
    hash_field(
        &mut digest,
        &binding.accepted_offer_sequence().get().to_be_bytes(),
    );
    hash_field(&mut digest, &binding.job_ir_version().get().to_be_bytes());
    hash_field(&mut digest, binding.job_ir_digest().as_bytes());
    Ok(Sha256Digest::from_bytes(digest.finalize().into()))
}

fn resource_id(grant_digest: Sha256Digest) -> String {
    let digest = domain_digest(RESOURCE_DOMAIN, &[grant_digest.as_bytes()]);
    format!("automata-hv-{digest}")
}

fn ticket_digest(
    grant_digest: Sha256Digest,
    resource_id: &str,
    generation: SandboxGeneration,
    custody: SandboxCustody,
) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(TICKET_DOMAIN);
    hash_field(&mut digest, grant_digest.as_bytes());
    hash_field(&mut digest, resource_id.as_bytes());
    hash_field(&mut digest, &generation.get().to_be_bytes());
    hash_custody(&mut digest, custody);
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn process_id(grant_digest: Sha256Digest, operation_id: OperationId) -> HostComputeProcess {
    let digest = domain_digest(
        PROCESS_DOMAIN,
        &[grant_digest.as_bytes(), operation_id.as_uuid().as_bytes()],
    );
    HostComputeProcess(format!("automata-process-{digest}"))
}

fn domain_digest(domain: &[u8], fields: &[&[u8]]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(domain);
    for value in fields {
        hash_field(&mut digest, value);
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn hash_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn hash_custody(digest: &mut Sha256, custody: SandboxCustody) {
    match custody {
        SandboxCustody::ProfileAdmission { runner_id } => {
            hash_field(digest, b"profile_admission");
            hash_field(digest, runner_id.as_uuid().as_bytes());
        }
        SandboxCustody::Job {
            runner_id,
            slot_ordinal,
        } => {
            hash_field(digest, b"job");
            hash_field(digest, runner_id.as_uuid().as_bytes());
            hash_field(digest, &slot_ordinal.get().to_be_bytes());
        }
    }
}

fn is_zero_digest(digest: Sha256Digest) -> bool {
    digest.as_bytes().iter().all(|byte| *byte == 0)
}

fn system_unix_millis() -> Option<UnixMillis> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(elapsed.as_millis()).ok().map(UnixMillis::new)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        num::NonZeroU64,
        path::PathBuf,
        sync::atomic::{AtomicU32, AtomicUsize, Ordering},
    };

    use automata_ci_core::{
        AttemptId, EnvironmentProfileId, FencingToken, JobId, JobIrVersion, JobResourceAllocation,
        LeaseGuard, LeaseId, ResourceCapacity, RunId, WindowsHyperVBrokerGrantClaims,
    };
    use automata_ci_execution::{
        EnvironmentName, EnvironmentProfile, EnvironmentValue, EnvironmentVariable,
        ExecutionEnvironment, ExecutionOutputRecord, ExecutionOutputStream, ExecutionTermination,
        NeverCancelled, SandboxEnvironment, SandboxExecutionBinding,
    };
    use automata_ci_runner_spool::{
        MAX_CONTENT_OBJECT_BYTES, MAX_CONTENT_SPOOL_BYTES, OpaqueContentIdentity, ProtectionId,
        endpoint_result_allocation,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    use super::*;

    struct TemporaryLedgerDirectory(PathBuf);

    impl TemporaryLedgerDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "automata-windows-broker-ledger-{}",
                OperationId::new().as_uuid()
            ));
            fs::create_dir(&path).expect("create temporary ledger directory");
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TemporaryLedgerDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove temporary ledger directory");
        }
    }

    #[derive(Debug)]
    struct InMemoryBrokerResultStore {
        state: Mutex<InMemoryResultState>,
        max_bytes: u64,
        max_objects: usize,
    }

    #[derive(Debug, Default)]
    struct InMemoryResultState {
        objects: BTreeMap<DurableContentRef, Vec<u8>>,
        reserved_bytes: u64,
        reserved_objects: usize,
        publications: usize,
    }

    impl InMemoryBrokerResultStore {
        fn new() -> Self {
            Self::with_limits(MAX_CONTENT_SPOOL_BYTES, MAX_ENDPOINT_OPERATIONS_PER_JOB)
        }

        fn with_limits(max_bytes: u64, max_objects: usize) -> Self {
            Self {
                state: Mutex::new(InMemoryResultState::default()),
                max_bytes,
                max_objects,
            }
        }

        fn used_bytes(state: &InMemoryResultState) -> u64 {
            state
                .objects
                .keys()
                .map(DurableContentRef::accounted_bytes)
                .sum()
        }

        fn reference(plaintext: &[u8]) -> Result<DurableContentRef, BrokerResultStoreError> {
            let bytes =
                u64::try_from(plaintext.len()).map_err(|_| BrokerResultStoreError::Capacity)?;
            let allocation =
                endpoint_result_allocation(bytes).map_err(|_| BrokerResultStoreError::Capacity)?;
            let digest = Sha256Digest::from_bytes(Sha256::digest(plaintext).into());
            DurableContentRef::after_endpoint_result_commit(
                allocation,
                OpaqueContentIdentity::from_bytes(*digest.as_bytes()),
                ProtectionId::new("test-key-v1").expect("fixed protection ID"),
            )
            .map_err(|_| BrokerResultStoreError::Corrupt)
        }

        fn verify(reference: &DurableContentRef, plaintext: &[u8]) -> bool {
            Self::reference(plaintext).is_ok_and(|observed| observed == *reference)
        }

        fn tamper(&self, reference: &DurableContentRef) {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state
                .objects
                .get_mut(reference)
                .expect("referenced test result")
                .push(0xff);
        }

        fn retained_objects(&self) -> usize {
            self.state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .objects
                .len()
        }
    }

    impl Default for InMemoryBrokerResultStore {
        fn default() -> Self {
            Self::new()
        }
    }

    #[derive(Debug)]
    struct InMemoryResultReservation<'store> {
        store: &'store InMemoryBrokerResultStore,
        maximum_plaintext_bytes: u64,
        reserved_bytes: u64,
        active: bool,
    }

    impl Drop for InMemoryResultReservation<'_> {
        fn drop(&mut self) {
            if !self.active {
                return;
            }
            let mut state = self
                .store
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            state.reserved_bytes -= self.reserved_bytes;
            state.reserved_objects -= 1;
        }
    }

    #[derive(Debug)]
    struct InMemoryResultPublication<'store> {
        store: &'store InMemoryBrokerResultStore,
        reference: DurableContentRef,
        active: bool,
    }

    impl InMemoryResultPublication<'_> {
        fn finish(&mut self) {
            if !self.active {
                return;
            }
            let mut state = self
                .store
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            state.publications -= 1;
            self.active = false;
        }
    }

    impl Drop for InMemoryResultPublication<'_> {
        fn drop(&mut self) {
            self.finish();
        }
    }

    impl BrokerResultPublication for InMemoryResultPublication<'_> {
        fn reference(&self) -> &DurableContentRef {
            &self.reference
        }

        fn adopt(mut self: Box<Self>) {
            self.finish();
        }
    }

    impl<'store> BrokerResultCapacityReservation<'store> for InMemoryResultReservation<'store> {
        fn persist(
            mut self: Box<Self>,
            plaintext: &[u8],
        ) -> Result<Box<dyn BrokerResultPublication + 'store>, BrokerResultStoreError> {
            if u64::try_from(plaintext.len()).map_err(|_| BrokerResultStoreError::Capacity)?
                > self.maximum_plaintext_bytes
            {
                return Err(BrokerResultStoreError::Capacity);
            }
            let reference = InMemoryBrokerResultStore::reference(plaintext)?;
            let mut state = self
                .store
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            state.reserved_bytes -= self.reserved_bytes;
            state.reserved_objects -= 1;
            self.active = false;
            if let Some(existing) = state.objects.get(&reference) {
                if existing != plaintext {
                    return Err(BrokerResultStoreError::Corrupt);
                }
            } else {
                state.objects.insert(reference.clone(), plaintext.to_vec());
            }
            state.publications += 1;
            drop(state);
            Ok(Box::new(InMemoryResultPublication {
                store: self.store,
                reference,
                active: true,
            }))
        }
    }

    impl BrokerResultStore for InMemoryBrokerResultStore {
        fn reserve(
            &self,
            maximum_plaintext_bytes: u64,
        ) -> Result<Box<dyn BrokerResultCapacityReservation<'_> + '_>, BrokerResultStoreError>
        {
            if maximum_plaintext_bytes > MAX_CONTENT_OBJECT_BYTES {
                return Err(BrokerResultStoreError::Capacity);
            }
            let reserved_bytes = endpoint_result_allocation(maximum_plaintext_bytes)
                .map_err(|_| BrokerResultStoreError::Capacity)?;
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let objects = state
                .objects
                .len()
                .checked_add(state.reserved_objects)
                .and_then(|objects| objects.checked_add(1))
                .ok_or(BrokerResultStoreError::Capacity)?;
            let bytes = Self::used_bytes(&state)
                .checked_add(state.reserved_bytes)
                .and_then(|bytes| bytes.checked_add(reserved_bytes))
                .ok_or(BrokerResultStoreError::Capacity)?;
            if objects > self.max_objects || bytes > self.max_bytes {
                return Err(BrokerResultStoreError::Capacity);
            }
            state.reserved_objects += 1;
            state.reserved_bytes += reserved_bytes;
            Ok(Box::new(InMemoryResultReservation {
                store: self,
                maximum_plaintext_bytes,
                reserved_bytes,
                active: true,
            }))
        }

        fn load(&self, reference: &DurableContentRef) -> Result<Vec<u8>, BrokerResultStoreError> {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let plaintext = state
                .objects
                .get(reference)
                .ok_or(BrokerResultStoreError::Corrupt)?;
            if !Self::verify(reference, plaintext) {
                return Err(BrokerResultStoreError::Corrupt);
            }
            Ok(plaintext.clone())
        }

        fn remove(&self, reference: &DurableContentRef) -> Result<bool, BrokerResultStoreError> {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(plaintext) = state.objects.get(reference)
                && !Self::verify(reference, plaintext)
            {
                return Err(BrokerResultStoreError::Corrupt);
            }
            Ok(state.objects.remove(reference).is_some())
        }

        fn reconcile(&self, retained: &[DurableContentRef]) -> Result<(), BrokerResultStoreError> {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if state.publications != 0 {
                return Err(BrokerResultStoreError::Unavailable);
            }
            for reference in retained {
                let plaintext = state
                    .objects
                    .get(reference)
                    .ok_or(BrokerResultStoreError::Corrupt)?;
                if !Self::verify(reference, plaintext) {
                    return Err(BrokerResultStoreError::Corrupt);
                }
            }
            state
                .objects
                .retain(|reference, _| retained.contains(reference));
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct FakeHostCompute {
        resources: Mutex<BTreeMap<String, HostComputeInspection>>,
        creates: AtomicUsize,
        execs: AtomicUsize,
        copy_tos: AtomicUsize,
        copy_froms: AtomicUsize,
        destroys: AtomicUsize,
        last_guest_agent_path: Mutex<Option<String>>,
        last_process_limit: AtomicU32,
        uncertain_create: Mutex<bool>,
        uncertain_destroy: Mutex<bool>,
        uncertain_exec: Mutex<bool>,
        copy_from_output: Mutex<Option<Vec<u8>>>,
        exec_gate: (Mutex<ExecGate>, Condvar),
    }

    #[derive(Debug, Default)]
    struct ExecGate {
        blocked: bool,
        entered: bool,
        released: bool,
    }

    impl FakeHostCompute {
        fn drift_to_process_isolation(&self) {
            for inspection in self
                .resources
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .values_mut()
            {
                inspection.isolation = HostComputeObservedIsolation::Process;
            }
        }

        fn block_exec(&self) {
            let mut gate = self
                .exec_gate
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            gate.blocked = true;
            gate.entered = false;
            gate.released = false;
        }

        fn set_copy_from_output(&self, output: Vec<u8>) {
            *self
                .copy_from_output
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(output);
        }

        fn wait_for_blocked_exec(&self) {
            let gate = self
                .exec_gate
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let (gate, timeout) = self
                .exec_gate
                .1
                .wait_timeout_while(gate, Duration::from_secs(5), |gate| !gate.entered)
                .unwrap_or_else(PoisonError::into_inner);
            assert!(!timeout.timed_out(), "exec did not enter fake adapter");
            assert!(gate.entered);
        }
    }

    impl WindowsHostComputeAdapter for FakeHostCompute {
        fn attest_profile(
            &self,
            request: &HostComputeProfileRequest,
        ) -> Result<HostComputeProfileObservation, HostComputeAdapterError> {
            Ok(HostComputeProfileObservation::new(
                request.image().digest(),
                HostComputeObservedIsolation::HyperV,
                true,
                true,
            ))
        }

        fn create(
            &self,
            request: &HostComputeCreateRequest,
        ) -> Result<(), HostComputeAdapterError> {
            self.creates.fetch_add(1, Ordering::SeqCst);
            self.resources
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(
                    request.resource_id.clone(),
                    HostComputeInspection::new(
                        request.resource_id.clone(),
                        request.grant_digest,
                        request.spec_digest,
                        request.generation,
                        request.custody,
                        request.profile.clone(),
                        request.image.digest(),
                        request.resources,
                        HostComputeObservedIsolation::HyperV,
                        HostComputeObservedState::Running,
                        true,
                        true,
                        true,
                        0,
                        0,
                        0,
                    ),
                );
            if *self
                .uncertain_create
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
            {
                Err(HostComputeAdapterError::new(
                    HostComputeOperation::Create,
                    BrokerAdapterEffect::StateMayHaveChanged,
                ))
            } else {
                Ok(())
            }
        }

        fn inspect(
            &self,
            resource_id: &str,
        ) -> Result<Option<HostComputeInspection>, HostComputeAdapterError> {
            Ok(self
                .resources
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(resource_id)
                .cloned())
        }

        fn attach(&self, _resource_id: &str) -> Result<(), HostComputeAdapterError> {
            Ok(())
        }

        fn exec(
            &self,
            request: &BrokerExecRequest<'_>,
            _cancellation: &dyn Cancellation,
        ) -> Result<ExecutionOutput, HostComputeAdapterError> {
            self.execs.fetch_add(1, Ordering::SeqCst);
            *self
                .last_guest_agent_path
                .lock()
                .unwrap_or_else(PoisonError::into_inner) =
                Some(request.guest_agent_path().to_owned());
            self.last_process_limit
                .store(request.process_limit(), Ordering::SeqCst);
            let mut gate = self
                .exec_gate
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if gate.blocked {
                gate.entered = true;
                self.exec_gate.1.notify_all();
                gate = self
                    .exec_gate
                    .1
                    .wait_while(gate, |gate| !gate.released)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            drop(gate);
            if *self
                .uncertain_exec
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
            {
                return Err(HostComputeAdapterError::new(
                    HostComputeOperation::Exec,
                    BrokerAdapterEffect::StateMayHaveChanged,
                ));
            }
            ExecutionOutput::new(
                ExecutionTermination::Exited(0),
                vec![
                    ExecutionOutputRecord::data(
                        ExecutionOutputStream::Stdout,
                        b"broker-output".to_vec(),
                    )
                    .map_err(|_| {
                        HostComputeAdapterError::new(
                            HostComputeOperation::Exec,
                            BrokerAdapterEffect::KnownNoEffect,
                        )
                    })?,
                    ExecutionOutputRecord::end_of_stream(ExecutionOutputStream::Stdout),
                    ExecutionOutputRecord::end_of_stream(ExecutionOutputStream::Stderr),
                ],
                false,
            )
            .map_err(|_| {
                HostComputeAdapterError::new(
                    HostComputeOperation::Exec,
                    BrokerAdapterEffect::KnownNoEffect,
                )
            })
        }

        fn copy_to(
            &self,
            request: &BrokerCopyToRequest<'_>,
            _cancellation: &dyn Cancellation,
        ) -> Result<(), HostComputeAdapterError> {
            self.copy_tos.fetch_add(1, Ordering::SeqCst);
            *self
                .last_guest_agent_path
                .lock()
                .unwrap_or_else(PoisonError::into_inner) =
                Some(request.guest_agent_path().to_owned());
            Ok(())
        }

        fn copy_from(
            &self,
            request: &BrokerCopyFromRequest<'_>,
            _cancellation: &dyn Cancellation,
        ) -> Result<Vec<u8>, HostComputeAdapterError> {
            self.copy_froms.fetch_add(1, Ordering::SeqCst);
            *self
                .last_guest_agent_path
                .lock()
                .unwrap_or_else(PoisonError::into_inner) =
                Some(request.guest_agent_path().to_owned());
            Ok(self
                .copy_from_output
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
                .unwrap_or_else(|| b"copy".to_vec()))
        }

        fn terminate_descendants(&self, _resource_id: &str) -> Result<(), HostComputeAdapterError> {
            let mut gate = self
                .exec_gate
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            gate.released = true;
            self.exec_gate.1.notify_all();
            Ok(())
        }

        fn destroy(&self, resource_id: &str) -> Result<(), HostComputeAdapterError> {
            self.destroys.fetch_add(1, Ordering::SeqCst);
            self.resources
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(resource_id);
            if *self
                .uncertain_destroy
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
            {
                Err(HostComputeAdapterError::new(
                    HostComputeOperation::Destroy,
                    BrokerAdapterEffect::StateMayHaveChanged,
                ))
            } else {
                Ok(())
            }
        }

        fn list_owned(&self) -> Result<Vec<HostComputeInspection>, HostComputeAdapterError> {
            Ok(self
                .resources
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .values()
                .cloned()
                .collect())
        }
    }

    struct Fixture {
        host_id: Sha256Digest,
        keyring: BrokerGrantKeyring,
        key_id: Sha256Digest,
        public_key: [u8; 32],
        profile_contract: WindowsHyperVAdmittedProfileContract,
        grant: WindowsHyperVBrokerGrant,
        spec: SandboxSpec,
    }

    #[derive(Debug)]
    struct FixedProfileContractResolver(WindowsHyperVAdmittedProfileContract);

    impl BrokerProfileContractResolver for FixedProfileContractResolver {
        fn resolve(
            &self,
            profile_contract_sha256: Sha256Digest,
        ) -> Result<Option<WindowsHyperVAdmittedProfileContract>, BrokerError> {
            Ok(
                (self.0.profile_contract_sha256() == profile_contract_sha256)
                    .then(|| self.0.clone()),
            )
        }
    }

    fn sign_fixture_grant(
        claims: WindowsHyperVBrokerGrantClaims,
    ) -> (
        BrokerGrantKeyring,
        Sha256Digest,
        [u8; 32],
        WindowsHyperVBrokerGrant,
    ) {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).expect("signing key");
        let public_key: [u8; 32] = key_pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("public key");
        let key_id = Sha256Digest::from_bytes(Sha256::digest(public_key).into());
        let signature = key_pair.sign(&WindowsHyperVBrokerGrant::signing_bytes_for(
            key_id, &claims,
        ));
        let grant = WindowsHyperVBrokerGrant::new(key_id, claims, signature.as_ref())
            .expect("signed grant");
        let keyring = BrokerGrantKeyring::new([(key_id, public_key)]).expect("keyring");
        (keyring, key_id, public_key, grant)
    }

    fn fixture_execution_binding(grant: &WindowsHyperVBrokerGrant) -> SandboxExecutionBinding {
        SandboxExecutionBinding::new(
            grant.claims().runner_session_id(),
            grant.claims().run_id(),
            grant.claims().job_id(),
            grant.claims().attempt_id(),
            LeaseGuard::new(grant.claims().lease_id(), grant.claims().fencing_token()),
            grant.claims().accepted_offer_operation_id(),
            NonZeroU64::new(grant.claims().accepted_offer_sequence())
                .expect("nonzero offer sequence"),
            grant.claims().job_ir_version(),
            grant.claims().job_ir_digest(),
        )
    }

    fn fixture() -> Fixture {
        let host_id = Sha256Digest::from_bytes([1; 32]);
        let profile = EnvironmentProfile::new(
            EnvironmentProfileId::new("example.com/windows-hyperv").expect("profile id"),
            Sha256Digest::from_bytes([2; 32]),
        );
        let runner_id = RunnerId::new();
        let capacity = ResourceCapacity::new(2_000, 2 * 1024 * 1024 * 1024, 0, 0);
        let allocation = JobResourceAllocation::new(capacity, capacity).expect("allocation");
        let sandbox_operation_id = OperationId::new();
        let claims = WindowsHyperVBrokerGrantClaims::new(
            host_id,
            Sha256Digest::from_bytes([3; 32]),
            AttemptId::new(),
            JobId::new(),
            RunId::new(),
            OperationId::new(),
            OperationId::new(),
            1,
            sandbox_operation_id,
            Sha256Digest::from_bytes([7; 32]),
            runner_id,
            RunnerSessionId::new(),
            4,
            5,
            1,
            LeaseId::new(),
            FencingToken::new(7).expect("fence"),
            JobIrVersion::current(),
            128,
            Sha256Digest::from_bytes([4; 32]),
            Sha256Digest::from_bytes([5; 32]),
            allocation,
            128,
            Sha256Digest::from_bytes([6; 32]),
            profile.clone(),
            Sha256Digest::from_bytes([8; 32]),
            UnixMillis::new(100),
            UnixMillis::new(200),
        )
        .expect("claims");
        let (keyring, key_id, public_key, grant) = sign_fixture_grant(claims);
        let workspace = TargetPath::windows(r"C:\__w").expect("workspace");
        let image = ImmutableImage::new(format!(
            "mcr.microsoft.com/windows/servercore@sha256:{}",
            "11".repeat(32)
        ))
        .expect("image");
        let keepalive = ExecutionArgv::new(
            TargetPath::windows(r"C:\automata\guest.exe").expect("guest"),
            vec!["keepalive".to_owned()],
        )
        .expect("keepalive");
        let environment = SandboxEnvironment::windows_hyperv_container(
            profile,
            image,
            keepalive,
            workspace.clone(),
            ExecutionEnvironment::empty(),
        )
        .expect("environment");
        let profile_contract = WindowsHyperVAdmittedProfileContract::new(
            host_id,
            Sha256Digest::from_bytes([8; 32]),
            environment.clone(),
            UnixMillis::new(300),
        )
        .expect("admitted profile contract");
        let spec = SandboxSpec::new(
            sandbox_operation_id,
            SandboxGeneration::new(7).expect("generation"),
            SandboxCustody::Job {
                runner_id,
                slot_ordinal: NonZeroU16::new(1).expect("one-based slot"),
            },
            environment,
            workspace,
            NetworkPolicy::Disabled,
            RootFilesystemPolicy::Writable,
            ResourceLimits::new(2 * 1024 * 1024 * 1024, 2_000, 128).expect("limits"),
        )
        .with_resource_allocation(allocation)
        .with_execution_binding(fixture_execution_binding(&grant));
        Fixture {
            host_id,
            keyring,
            key_id,
            public_key,
            profile_contract,
            grant,
            spec,
        }
    }

    fn broker<L>(
        fixture: &Fixture,
        adapter: Arc<FakeHostCompute>,
        ledger: Arc<L>,
    ) -> RestrictedWindowsHyperVBroker
    where
        L: BrokerLedger + 'static,
    {
        broker_with_results(
            fixture,
            adapter,
            ledger,
            Arc::new(InMemoryBrokerResultStore::new()),
        )
    }

    fn broker_with_results<L, R>(
        fixture: &Fixture,
        adapter: Arc<FakeHostCompute>,
        ledger: Arc<L>,
        results: Arc<R>,
    ) -> RestrictedWindowsHyperVBroker
    where
        L: BrokerLedger + 'static,
        R: BrokerResultStore + 'static,
    {
        let broker = RestrictedWindowsHyperVBroker::open(
            fixture.host_id,
            fixture.keyring.clone(),
            adapter,
            ledger,
            results,
            Arc::new(FixedProfileContractResolver(
                fixture.profile_contract.clone(),
            )),
        )
        .expect("open broker");
        broker
            .reconcile_startup(UnixMillis::new(110))
            .expect("startup reconciliation");
        broker
    }

    fn fixture_spec_with_custody(spec: &SandboxSpec, custody: SandboxCustody) -> SandboxSpec {
        SandboxSpec::new(
            spec.operation_id(),
            spec.generation(),
            custody,
            spec.profile().clone(),
            spec.workspace().clone(),
            spec.network(),
            spec.root_filesystem(),
            spec.resources(),
        )
        .with_privilege(spec.privilege())
        .with_resource_allocation(spec.resource_allocation().expect("fixture allocation"))
        .with_execution_binding(spec.execution_binding().expect("fixture execution binding"))
    }

    fn fixture_command(operation_id: OperationId, marker: &str) -> ExecutionCommand {
        ExecutionCommand::new(
            operation_id,
            ExecutionArgv::new(
                TargetPath::windows(r"C:\Windows\System32\cmd.exe").expect("program"),
                vec!["/d".to_owned(), "/c".to_owned(), marker.to_owned()],
            )
            .expect("argv"),
            TargetPath::windows(r"C:\__w").expect("working directory"),
            ExecutionEnvironment::empty(),
            Duration::from_secs(30),
            1024,
        )
        .expect("command")
    }

    fn assert_completed_operation_conflicts(
        broker: &RestrictedWindowsHyperVBroker,
        ticket: &BrokerSandboxTicket,
        exec_operation: OperationId,
        copy_operation: OperationId,
    ) {
        assert_eq!(
            broker
                .exec(
                    ticket,
                    &fixture_command(exec_operation, "echo changed"),
                    UnixMillis::new(134),
                    &NeverCancelled,
                )
                .expect_err("conflicting exec replay"),
            BrokerError::ReplayConflict
        );
        let conflicting_copy = CopyToRequest::new(
            copy_operation,
            TargetPath::windows(r"C:\__w\durable.txt").expect("copy target"),
            b"changed".to_vec(),
        )
        .expect("conflicting copy request");
        assert_eq!(
            broker
                .copy_to(
                    ticket,
                    &conflicting_copy,
                    UnixMillis::new(135),
                    &NeverCancelled,
                )
                .expect_err("conflicting copy replay"),
            BrokerError::ReplayConflict
        );
    }

    fn completed_reference(
        ledger: &dyn BrokerLedger,
        operation_id: OperationId,
    ) -> DurableContentRef {
        let entry = ledger
            .load()
            .expect("load completed operation")
            .into_iter()
            .rev()
            .find(|entry| entry.completed_operations.contains_key(&operation_id))
            .expect("completed operation entry");
        match &entry
            .completed_operations
            .get(&operation_id)
            .expect("completed operation")
            .result
        {
            BrokerCompletedResult::Pending { reference } => reference.clone(),
            BrokerCompletedResult::GarbageCollecting { .. }
            | BrokerCompletedResult::Acknowledged => {
                panic!("result must still await acknowledgement")
            }
        }
    }

    fn acknowledge_replayed_operations(
        broker: &RestrictedWindowsHyperVBroker,
        ticket: &BrokerSandboxTicket,
        results: &InMemoryBrokerResultStore,
        command: &ExecutionCommand,
        operation_ids: [OperationId; 3],
    ) {
        for operation_id in operation_ids {
            broker
                .acknowledge_operation(ticket, operation_id)
                .expect("acknowledge replay result");
        }
        broker
            .acknowledge_operation(ticket, operation_ids[0])
            .expect("repeated acknowledgement is idempotent");
        assert_eq!(results.retained_objects(), 0);
        assert_eq!(
            broker
                .exec(ticket, command, UnixMillis::new(136), &NeverCancelled)
                .expect_err("acknowledged result cannot repeat host mutation"),
            BrokerError::OperationAcknowledged
        );
    }

    #[test]
    fn completed_exec_and_copy_to_replay_exactly_after_response_loss_and_restart() {
        let directory = TemporaryLedgerDirectory::new();
        let path = directory.path("completed-operations.jsonl");
        let fixture = fixture();
        let adapter = Arc::new(FakeHostCompute::default());
        let ledger = Arc::new(FileBrokerLedger::open(&path).expect("open ledger"));
        let results = Arc::new(InMemoryBrokerResultStore::new());
        let first = broker_with_results(
            &fixture,
            Arc::clone(&adapter),
            Arc::clone(&ledger),
            Arc::clone(&results),
        );
        let ticket = first
            .create(&fixture.spec, &fixture.grant, UnixMillis::new(120))
            .expect("create");
        first.attach(&ticket, UnixMillis::new(121)).expect("attach");

        let exec_operation = OperationId::new();
        let command = fixture_command(exec_operation, "echo once");
        let expected_output = first
            .exec(&ticket, &command, UnixMillis::new(130), &NeverCancelled)
            .expect("first exec whose response is lost");
        let copy_operation = OperationId::new();
        let copy = CopyToRequest::new(
            copy_operation,
            TargetPath::windows(r"C:\__w\durable.txt").expect("copy target"),
            b"written-once".to_vec(),
        )
        .expect("copy request");
        first
            .copy_to(&ticket, &copy, UnixMillis::new(131), &NeverCancelled)
            .expect("first copy whose response is lost");
        let read_operation = OperationId::new();
        let read = CopyFromRequest::new(
            read_operation,
            TargetPath::windows(r"C:\__w\durable.txt").expect("copy source"),
            1024,
        )
        .expect("copy-from request");
        let expected_read = first
            .copy_from(&ticket, &read, UnixMillis::new(131), &NeverCancelled)
            .expect("first read whose response is lost");
        assert_eq!(adapter.execs.load(Ordering::SeqCst), 1);
        assert_eq!(adapter.copy_tos.load(Ordering::SeqCst), 1);
        assert_eq!(adapter.copy_froms.load(Ordering::SeqCst), 1);
        let ledger_text = fs::read_to_string(&path).expect("read lifecycle ledger");
        assert!(!ledger_text.contains("broker-output"));
        assert!(!ledger_text.contains("YnJva2VyLW91dHB1dA=="));
        assert!(!ledger_text.contains("Y29weQ=="));
        assert_eq!(adapter.last_process_limit.load(Ordering::SeqCst), 128);
        assert_eq!(
            adapter
                .last_guest_agent_path
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_deref(),
            Some(r"C:\automata\guest.exe")
        );

        drop(first);
        drop(ledger);
        let restarted_ledger =
            Arc::new(FileBrokerLedger::open(&path).expect("reopen completed ledger"));
        let restarted = broker_with_results(
            &fixture,
            Arc::clone(&adapter),
            Arc::clone(&restarted_ledger),
            Arc::clone(&results),
        );
        assert_eq!(
            restarted
                .exec(&ticket, &command, UnixMillis::new(132), &NeverCancelled,)
                .expect("exact exec replay"),
            expected_output
        );
        restarted
            .copy_to(&ticket, &copy, UnixMillis::new(133), &NeverCancelled)
            .expect("exact copy replay");
        assert_eq!(
            restarted
                .copy_from(&ticket, &read, UnixMillis::new(133), &NeverCancelled)
                .expect("exact read replay"),
            expected_read
        );
        assert_eq!(adapter.execs.load(Ordering::SeqCst), 1);
        assert_eq!(adapter.copy_tos.load(Ordering::SeqCst), 1);
        assert_eq!(adapter.copy_froms.load(Ordering::SeqCst), 1);

        assert_completed_operation_conflicts(&restarted, &ticket, exec_operation, copy_operation);
        acknowledge_replayed_operations(
            &restarted,
            &ticket,
            results.as_ref(),
            &command,
            [exec_operation, copy_operation, read_operation],
        );
        assert_eq!(adapter.execs.load(Ordering::SeqCst), 1);
        assert_eq!(adapter.copy_tos.load(Ordering::SeqCst), 1);
        assert_eq!(adapter.copy_froms.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn startup_fails_closed_when_a_retained_result_is_missing_or_altered() {
        for alter in [false, true] {
            let fixture = fixture();
            let adapter = Arc::new(FakeHostCompute::default());
            let ledger = Arc::new(InMemoryBrokerLedger::new());
            let results = Arc::new(InMemoryBrokerResultStore::new());
            let first = broker_with_results(
                &fixture,
                Arc::clone(&adapter),
                Arc::clone(&ledger),
                Arc::clone(&results),
            );
            let ticket = first
                .create(&fixture.spec, &fixture.grant, UnixMillis::new(120))
                .expect("create");
            first.attach(&ticket, UnixMillis::new(121)).expect("attach");
            let operation_id = OperationId::new();
            first
                .exec(
                    &ticket,
                    &fixture_command(operation_id, "echo protected"),
                    UnixMillis::new(130),
                    &NeverCancelled,
                )
                .expect("persist protected result");
            let reference = completed_reference(ledger.as_ref(), operation_id);
            if alter {
                results.tamper(&reference);
            } else {
                assert!(results.remove(&reference).expect("remove retained result"));
            }
            drop(first);

            let restarted = RestrictedWindowsHyperVBroker::open(
                fixture.host_id,
                fixture.keyring.clone(),
                adapter,
                ledger,
                results,
                Arc::new(FixedProfileContractResolver(
                    fixture.profile_contract.clone(),
                )),
            )
            .expect("open reads value-free ledger metadata");
            assert_eq!(
                restarted
                    .reconcile_startup(UnixMillis::new(131))
                    .expect_err("missing or altered protected content must fail recovery"),
                BrokerError::ResultStore(BrokerResultStoreError::Corrupt)
            );
            assert_eq!(
                restarted
                    .inspect_ticket(&ticket, UnixMillis::new(132))
                    .expect_err("broker remains closed after failed result recovery"),
                BrokerError::ReconciliationRequired
            );
        }
    }

    #[test]
    fn maximum_shared_copy_result_is_durable_replayable_and_reclaimable() {
        let fixture = fixture();
        let adapter = Arc::new(FakeHostCompute::default());
        adapter.set_copy_from_output(vec![0x5a; MAX_COPY_BYTES]);
        let ledger = Arc::new(InMemoryBrokerLedger::new());
        let results = Arc::new(InMemoryBrokerResultStore::new());
        let broker =
            broker_with_results(&fixture, Arc::clone(&adapter), ledger, Arc::clone(&results));
        let ticket = broker
            .create(&fixture.spec, &fixture.grant, UnixMillis::new(120))
            .expect("create");
        broker
            .attach(&ticket, UnixMillis::new(121))
            .expect("attach");
        let operation_id = OperationId::new();
        let request = CopyFromRequest::new(
            operation_id,
            TargetPath::windows(r"C:\__w\maximum.bin").expect("maximum path"),
            MAX_COPY_BYTES,
        )
        .expect("maximum shared copy request");

        let first = broker
            .copy_from(&ticket, &request, UnixMillis::new(130), &NeverCancelled)
            .expect("maximum shared copy result");
        assert_eq!(first.len(), MAX_COPY_BYTES);
        assert!(first.iter().all(|byte| *byte == 0x5a));
        assert_eq!(
            broker
                .copy_from(&ticket, &request, UnixMillis::new(131), &NeverCancelled)
                .expect("maximum result replay"),
            first
        );
        assert_eq!(adapter.copy_froms.load(Ordering::SeqCst), 1);

        broker
            .acknowledge_operation(&ticket, operation_id)
            .expect("acknowledge maximum result");
        assert_eq!(results.retained_objects(), 0);
    }

    #[test]
    fn acknowledged_result_gc_releases_the_exact_cumulative_capacity() {
        let fixture = fixture();
        let adapter = Arc::new(FakeHostCompute::default());
        let ledger = Arc::new(InMemoryBrokerLedger::new());
        let maximum_result = maximum_completed_outcome_bytes(BrokerOperationKind::CopyFrom, 1024)
            .expect("copy-from result bound");
        let exact_capacity = endpoint_result_allocation(
            u64::try_from(maximum_result).expect("bounded result length"),
        )
        .expect("protected result allocation");
        let results = Arc::new(InMemoryBrokerResultStore::with_limits(exact_capacity, 2));
        let broker =
            broker_with_results(&fixture, Arc::clone(&adapter), ledger, Arc::clone(&results));
        let ticket = broker
            .create(&fixture.spec, &fixture.grant, UnixMillis::new(120))
            .expect("create");
        broker
            .attach(&ticket, UnixMillis::new(121))
            .expect("attach");
        let first_id = OperationId::new();
        let first = CopyFromRequest::new(
            first_id,
            TargetPath::windows(r"C:\__w\first.bin").expect("first path"),
            1024,
        )
        .expect("first request");
        broker
            .copy_from(&ticket, &first, UnixMillis::new(130), &NeverCancelled)
            .expect("result fits the exact cumulative capacity");
        let second = CopyFromRequest::new(
            OperationId::new(),
            TargetPath::windows(r"C:\__w\second.bin").expect("second path"),
            1024,
        )
        .expect("second request");
        assert_eq!(
            broker
                .copy_from(&ticket, &second, UnixMillis::new(131), &NeverCancelled)
                .expect_err("another maximum reservation exceeds cumulative capacity"),
            BrokerError::ResultStore(BrokerResultStoreError::Capacity)
        );
        assert_eq!(adapter.copy_froms.load(Ordering::SeqCst), 1);

        broker
            .acknowledge_operation(&ticket, first_id)
            .expect("durable acknowledgement reclaims the first payload");
        assert_eq!(results.retained_objects(), 0);
        broker
            .copy_from(&ticket, &second, UnixMillis::new(132), &NeverCancelled)
            .expect("reclaimed capacity admits the next result");
        assert_eq!(adapter.copy_froms.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn startup_finishes_acknowledgement_after_result_removal_crash() {
        let fixture = fixture();
        let adapter = Arc::new(FakeHostCompute::default());
        let ledger = Arc::new(InMemoryBrokerLedger::new());
        let results = Arc::new(InMemoryBrokerResultStore::new());
        let first = broker_with_results(
            &fixture,
            Arc::clone(&adapter),
            Arc::clone(&ledger),
            Arc::clone(&results),
        );
        let ticket = first
            .create(&fixture.spec, &fixture.grant, UnixMillis::new(120))
            .expect("create");
        first.attach(&ticket, UnixMillis::new(121)).expect("attach");
        let operation_id = OperationId::new();
        let command = fixture_command(operation_id, "echo once");
        first
            .exec(&ticket, &command, UnixMillis::new(130), &NeverCancelled)
            .expect("persist replay result");
        let reference = completed_reference(ledger.as_ref(), operation_id);
        let mut collecting = ledger
            .load()
            .expect("load pending result")
            .into_iter()
            .last()
            .expect("latest ledger entry");
        collecting
            .completed_operations
            .get_mut(&operation_id)
            .expect("completed operation")
            .result = BrokerCompletedResult::GarbageCollecting {
            reference: reference.clone(),
        };
        ledger
            .append(&collecting)
            .expect("durably record acknowledgement before deletion");
        assert!(
            results
                .remove(&reference)
                .expect("remove result before simulated crash")
        );
        drop(first);

        let restarted = broker_with_results(
            &fixture,
            Arc::clone(&adapter),
            Arc::clone(&ledger),
            Arc::clone(&results),
        );
        restarted
            .acknowledge_operation(&ticket, operation_id)
            .expect("recovered acknowledgement is idempotent");
        assert_eq!(
            restarted
                .exec(&ticket, &command, UnixMillis::new(131), &NeverCancelled)
                .expect_err("acknowledged mutation cannot execute again"),
            BrokerError::OperationAcknowledged
        );
        let final_entry = ledger
            .load()
            .expect("load recovered acknowledgement")
            .into_iter()
            .last()
            .expect("recovered ledger entry");
        assert!(matches!(
            final_entry
                .completed_operations
                .get(&operation_id)
                .expect("operation tombstone")
                .result,
            BrokerCompletedResult::Acknowledged
        ));
        assert_eq!(results.retained_objects(), 0);
        assert_eq!(adapter.execs.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn completed_operation_metadata_uses_the_shared_endpoint_budget_boundary() {
        let fixture = fixture();
        let adapter = Arc::new(FakeHostCompute::default());
        let seed_ledger = Arc::new(InMemoryBrokerLedger::new());
        let seed = broker(&fixture, Arc::clone(&adapter), Arc::clone(&seed_ledger));
        let ticket = seed
            .create(&fixture.spec, &fixture.grant, UnixMillis::new(120))
            .expect("create");
        seed.attach(&ticket, UnixMillis::new(121)).expect("attach");
        let mut entry = seed_ledger
            .load()
            .expect("seed ledger")
            .into_iter()
            .last()
            .expect("seed entry");
        drop(seed);
        entry.completed_operations.clear();
        for _ in 0..MAX_ENDPOINT_OPERATIONS_PER_JOB {
            entry.completed_operations.insert(
                OperationId::new(),
                BrokerCompletedOperation {
                    kind: BrokerOperationKind::CopyTo,
                    request_fingerprint: Sha256Digest::from_bytes([9; 32]),
                    result: BrokerCompletedResult::Acknowledged,
                },
            );
        }
        validate_ledger_entry(&entry).expect("shared endpoint budget is valid");

        let full_ledger = Arc::new(InMemoryBrokerLedger {
            entries: Mutex::new(vec![entry.clone()]),
        });
        let full = broker(&fixture, Arc::clone(&adapter), full_ledger);
        let rejected = CopyToRequest::new(
            OperationId::new(),
            TargetPath::windows(r"C:\__w\over-budget.bin").expect("target"),
            Vec::new(),
        )
        .expect("copy request");
        assert_eq!(
            full.copy_to(&ticket, &rejected, UnixMillis::new(130), &NeverCancelled)
                .expect_err("operation above shared endpoint budget"),
            BrokerError::Ledger(BrokerLedgerError::Capacity)
        );
        assert_eq!(adapter.copy_tos.load(Ordering::SeqCst), 0);
        drop(full);

        let removed = *entry
            .completed_operations
            .keys()
            .next()
            .expect("one completed operation");
        entry.completed_operations.remove(&removed);
        let boundary_ledger = Arc::new(InMemoryBrokerLedger {
            entries: Mutex::new(vec![entry]),
        });
        let boundary = broker(&fixture, Arc::clone(&adapter), boundary_ledger);
        boundary
            .copy_to(&ticket, &rejected, UnixMillis::new(131), &NeverCancelled)
            .expect("last shared endpoint operation is admitted");
        assert_eq!(adapter.copy_tos.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn signed_grant_is_consumed_once_and_exact_replay_is_inspected() {
        let fixture = fixture();
        let adapter = Arc::new(FakeHostCompute::default());
        let broker = broker(
            &fixture,
            Arc::clone(&adapter),
            Arc::new(InMemoryBrokerLedger::new()),
        );
        let first = broker
            .create(&fixture.spec, &fixture.grant, UnixMillis::new(120))
            .expect("create");
        let replay = broker
            .create(&fixture.spec, &fixture.grant, UnixMillis::new(121))
            .expect("exact replay");
        assert_eq!(first, replay);
        let opaque = first.opaque();
        let decoded = BrokerSandboxTicket::from_opaque(&opaque).expect("opaque ticket");
        assert_eq!(decoded, first);
        assert_eq!(
            broker
                .inspect_ticket(&decoded, UnixMillis::new(122))
                .expect("ticket inspection")
                .phase(),
            BrokerLifecyclePhase::Ready
        );
        assert_eq!(
            BrokerSandboxTicket::from_opaque(&format!("{opaque}-extra"))
                .expect_err("extra ticket field"),
            BrokerError::InvalidTicket
        );
        assert_eq!(adapter.creates.load(Ordering::SeqCst), 1);
        let SandboxLaunch::WindowsHyperVContainer { image, .. } = fixture.spec.profile().launch()
        else {
            panic!("Windows fixture");
        };
        let attestation = broker
            .attest_profile(
                fixture.spec.profile().attestation(),
                image,
                UnixMillis::new(123),
                UnixMillis::new(124),
            )
            .expect("profile attestation");
        assert_eq!(attestation.host_id(), fixture.host_id);
        assert!(attestation.network_disabled());
        assert_ne!(attestation.digest(), Sha256Digest::from_bytes([0; 32]));
    }

    #[test]
    fn signed_grant_binds_exact_job_custody_before_ledger_or_engine_mutation() {
        let fixture = fixture();
        let adapter = Arc::new(FakeHostCompute::default());
        let ledger = Arc::new(InMemoryBrokerLedger::new());
        let broker = broker(&fixture, Arc::clone(&adapter), Arc::clone(&ledger));
        let SandboxCustody::Job {
            runner_id,
            slot_ordinal,
        } = fixture.spec.custody()
        else {
            panic!("job fixture");
        };
        let exact_digest = sandbox_spec_digest(&fixture.spec).expect("exact spec digest");
        let mutations = [
            SandboxCustody::ProfileAdmission { runner_id },
            SandboxCustody::Job {
                runner_id: RunnerId::new(),
                slot_ordinal,
            },
            SandboxCustody::Job {
                runner_id,
                slot_ordinal: NonZeroU16::new(slot_ordinal.get() + 1).expect("different slot"),
            },
        ];
        for custody in mutations {
            let mutated = fixture_spec_with_custody(&fixture.spec, custody);
            assert_ne!(
                sandbox_spec_digest(&mutated).expect("mutated spec digest"),
                exact_digest
            );
            assert_eq!(
                broker
                    .create(&mutated, &fixture.grant, UnixMillis::new(120))
                    .expect_err("custody substitution must fail closed"),
                BrokerError::InvalidSandboxSpec
            );
        }
        assert!(ledger.load().expect("ledger after rejection").is_empty());
        assert_eq!(adapter.creates.load(Ordering::SeqCst), 0);

        let ticket = broker
            .create(&fixture.spec, &fixture.grant, UnixMillis::new(120))
            .expect("exact signed custody creates");
        assert_eq!(
            broker
                .inspect_ticket(&ticket, UnixMillis::new(121))
                .expect("inspect exact custody")
                .custody(),
            fixture.spec.custody()
        );
        assert_eq!(
            ledger.load().expect("durable exact custody")[0].custody(),
            fixture.spec.custody()
        );
        assert_eq!(adapter.creates.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn signed_grant_rejects_execution_binding_substitution_before_mutation() {
        let fixture = fixture();
        let adapter = Arc::new(FakeHostCompute::default());
        let ledger = Arc::new(InMemoryBrokerLedger::new());
        let broker = broker(&fixture, Arc::clone(&adapter), Arc::clone(&ledger));
        let binding = fixture
            .spec
            .execution_binding()
            .expect("fixture execution binding");
        let substituted =
            fixture
                .spec
                .clone()
                .with_execution_binding(SandboxExecutionBinding::new(
                    binding.runner_session_id(),
                    binding.run_id(),
                    binding.job_id(),
                    AttemptId::new(),
                    binding.guard(),
                    binding.accepted_offer_operation_id(),
                    binding.accepted_offer_sequence(),
                    binding.job_ir_version(),
                    binding.job_ir_digest(),
                ));

        assert_eq!(
            broker
                .create(&substituted, &fixture.grant, UnixMillis::new(120))
                .expect_err("attempt substitution must fail closed"),
            BrokerError::InvalidSandboxSpec
        );
        assert!(ledger.load().expect("ledger after rejection").is_empty());
        assert_eq!(adapter.creates.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn verification_key_rotation_overlap_is_exact_and_unknown_keys_never_reach_engine() {
        let fixture = fixture();
        let rotated = Ed25519KeyPair::from_seed_unchecked(&[10; 32]).expect("rotated key");
        let rotated_public: [u8; 32] = rotated
            .public_key()
            .as_ref()
            .try_into()
            .expect("rotated public key");
        let rotated_id = Sha256Digest::from_bytes(Sha256::digest(rotated_public).into());
        let overlap = BrokerGrantKeyring::new([
            (fixture.key_id, fixture.public_key),
            (rotated_id, rotated_public),
        ])
        .expect("rotation-overlap keyring");
        let adapter = Arc::new(FakeHostCompute::default());
        let broker = RestrictedWindowsHyperVBroker::open(
            fixture.host_id,
            overlap,
            adapter.clone(),
            Arc::new(InMemoryBrokerLedger::new()),
            Arc::new(InMemoryBrokerResultStore::new()),
            Arc::new(FixedProfileContractResolver(
                fixture.profile_contract.clone(),
            )),
        )
        .expect("open overlap broker");
        broker
            .reconcile_startup(UnixMillis::new(110))
            .expect("reconcile overlap broker");
        broker
            .create(&fixture.spec, &fixture.grant, UnixMillis::new(120))
            .expect("old key remains accepted during overlap");
        assert_eq!(adapter.creates.load(Ordering::SeqCst), 1);

        let unknown_adapter = Arc::new(FakeHostCompute::default());
        let unknown = RestrictedWindowsHyperVBroker::open(
            fixture.host_id,
            BrokerGrantKeyring::new([(rotated_id, rotated_public)]).expect("rotated-only keyring"),
            unknown_adapter.clone(),
            Arc::new(InMemoryBrokerLedger::new()),
            Arc::new(InMemoryBrokerResultStore::new()),
            Arc::new(FixedProfileContractResolver(
                fixture.profile_contract.clone(),
            )),
        )
        .expect("open rotated-only broker");
        unknown
            .reconcile_startup(UnixMillis::new(110))
            .expect("reconcile rotated-only broker");
        assert_eq!(
            unknown
                .create(&fixture.spec, &fixture.grant, UnixMillis::new(120))
                .expect_err("retired key must be unknown"),
            BrokerError::UnknownVerificationKey
        );
        assert_eq!(unknown_adapter.creates.load(Ordering::SeqCst), 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn every_runner_selected_launch_or_resource_mutation_precedes_engine_create() {
        let fixture = fixture();
        let adapter = Arc::new(FakeHostCompute::default());
        let broker = broker(
            &fixture,
            Arc::clone(&adapter),
            Arc::new(InMemoryBrokerLedger::new()),
        );
        let SandboxLaunch::WindowsHyperVContainer {
            image: base_image,
            keepalive: base_keepalive,
        } = fixture.spec.profile().launch()
        else {
            panic!("Windows fixture");
        };
        let profile = fixture.spec.profile().attestation().clone();
        let workspace = fixture.spec.workspace().clone();
        let allocation = fixture.spec.resource_allocation().expect("allocation");
        let resources = fixture.spec.resources();
        let build = |operation_id,
                     image: ImmutableImage,
                     keepalive: ExecutionArgv,
                     environment: ExecutionEnvironment,
                     workspace: TargetPath,
                     resources: ResourceLimits,
                     allocation: JobResourceAllocation| {
            let sandbox_environment = SandboxEnvironment::windows_hyperv_container(
                profile.clone(),
                image,
                keepalive,
                workspace.clone(),
                environment,
            )
            .expect("mutated environment remains structurally valid");
            SandboxSpec::new(
                operation_id,
                SandboxGeneration::new(7).expect("generation"),
                fixture.spec.custody(),
                sandbox_environment,
                workspace,
                NetworkPolicy::Disabled,
                RootFilesystemPolicy::Writable,
                resources,
            )
            .with_resource_allocation(allocation)
        };
        let changed_image = ImmutableImage::new(format!(
            "mcr.microsoft.com/windows/servercore@sha256:{}",
            "22".repeat(32)
        ))
        .expect("changed image");
        let changed_keepalive =
            ExecutionArgv::new(base_keepalive.program().clone(), vec!["changed".to_owned()])
                .expect("changed keepalive");
        let changed_environment = ExecutionEnvironment::new(vec![EnvironmentVariable::new(
            EnvironmentName::new("PUBLIC_VALUE").expect("environment name"),
            EnvironmentValue::new("changed").expect("environment value"),
        )])
        .expect("changed environment");
        let changed_workspace = TargetPath::windows(r"C:\__w_changed").expect("workspace");
        let changed_memory_capacity = ResourceCapacity::new(
            allocation.limits().cpu_millis(),
            allocation.limits().memory_bytes() + 1024 * 1024,
            0,
            0,
        );
        let changed_memory_allocation =
            JobResourceAllocation::new(changed_memory_capacity, changed_memory_capacity)
                .expect("changed memory allocation");
        let changed_cpu_capacity = ResourceCapacity::new(
            allocation.limits().cpu_millis() + 1,
            allocation.limits().memory_bytes(),
            0,
            0,
        );
        let changed_cpu_allocation =
            JobResourceAllocation::new(changed_cpu_capacity, changed_cpu_capacity)
                .expect("changed CPU allocation");
        let changed_requests = JobResourceAllocation::new(
            ResourceCapacity::new(
                allocation.requests().cpu_millis() - 1,
                allocation.requests().memory_bytes(),
                0,
                0,
            ),
            allocation.limits(),
        )
        .expect("changed request allocation");
        let candidates = [
            build(
                fixture.spec.operation_id(),
                changed_image,
                base_keepalive.clone(),
                ExecutionEnvironment::empty(),
                workspace.clone(),
                resources,
                allocation,
            ),
            build(
                fixture.spec.operation_id(),
                base_image.clone(),
                changed_keepalive,
                ExecutionEnvironment::empty(),
                workspace.clone(),
                resources,
                allocation,
            ),
            build(
                fixture.spec.operation_id(),
                base_image.clone(),
                base_keepalive.clone(),
                changed_environment,
                workspace.clone(),
                resources,
                allocation,
            ),
            build(
                fixture.spec.operation_id(),
                base_image.clone(),
                base_keepalive.clone(),
                ExecutionEnvironment::empty(),
                changed_workspace,
                resources,
                allocation,
            ),
            build(
                fixture.spec.operation_id(),
                base_image.clone(),
                base_keepalive.clone(),
                ExecutionEnvironment::empty(),
                workspace.clone(),
                ResourceLimits::new(
                    changed_memory_capacity.memory_bytes(),
                    changed_memory_capacity.cpu_millis(),
                    resources.pids(),
                )
                .expect("changed memory limits"),
                changed_memory_allocation,
            ),
            build(
                fixture.spec.operation_id(),
                base_image.clone(),
                base_keepalive.clone(),
                ExecutionEnvironment::empty(),
                workspace.clone(),
                ResourceLimits::new(
                    changed_cpu_capacity.memory_bytes(),
                    changed_cpu_capacity.cpu_millis(),
                    resources.pids(),
                )
                .expect("changed CPU limits"),
                changed_cpu_allocation,
            ),
            build(
                fixture.spec.operation_id(),
                base_image.clone(),
                base_keepalive.clone(),
                ExecutionEnvironment::empty(),
                workspace.clone(),
                ResourceLimits::new(
                    resources.memory_bytes(),
                    resources.cpu_millis(),
                    resources.pids() + 1,
                )
                .expect("changed PID limits"),
                allocation,
            ),
            build(
                fixture.spec.operation_id(),
                base_image.clone(),
                base_keepalive.clone(),
                ExecutionEnvironment::empty(),
                workspace,
                resources,
                changed_requests,
            ),
        ];
        for candidate in candidates {
            assert!(matches!(
                broker.create(&candidate, &fixture.grant, UnixMillis::new(120)),
                Err(BrokerError::InvalidSandboxSpec | BrokerError::InvalidProfileContract)
            ));
        }
        assert_eq!(adapter.creates.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn expiry_and_effective_process_isolation_fail_closed() {
        let fixture = fixture();
        let adapter = Arc::new(FakeHostCompute::default());
        let broker = broker(
            &fixture,
            Arc::clone(&adapter),
            Arc::new(InMemoryBrokerLedger::new()),
        );
        assert_eq!(
            broker
                .create(&fixture.spec, &fixture.grant, UnixMillis::new(200))
                .expect_err("exclusive expiry"),
            BrokerError::GrantNotCurrent
        );
        let ticket = broker
            .create(&fixture.spec, &fixture.grant, UnixMillis::new(120))
            .expect("create before expiry");
        adapter.drift_to_process_isolation();
        assert_eq!(
            broker
                .attach(&ticket, UnixMillis::new(121))
                .expect_err("process isolation drift"),
            BrokerError::EffectiveStateMismatch
        );
    }

    #[test]
    fn uncertain_create_is_inspected_and_uncertain_destroy_requires_absence() {
        let fixture = fixture();
        let adapter = Arc::new(FakeHostCompute::default());
        *adapter
            .uncertain_create
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = true;
        let broker = broker(
            &fixture,
            Arc::clone(&adapter),
            Arc::new(InMemoryBrokerLedger::new()),
        );
        let ticket = broker
            .create(&fixture.spec, &fixture.grant, UnixMillis::new(120))
            .expect("inspection adopts exact uncertain create");
        *adapter
            .uncertain_destroy
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = true;
        broker
            .destroy(
                &ticket,
                OperationId::new(),
                fixture.spec.generation(),
                fixture.spec.custody(),
            )
            .expect("absence resolves uncertain destroy");
        assert_eq!(adapter.destroys.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn destroy_requires_exact_generation_and_custody_before_durable_mutation() {
        let fixture = fixture();
        let adapter = Arc::new(FakeHostCompute::default());
        let ledger = Arc::new(InMemoryBrokerLedger::new());
        let broker = broker(&fixture, Arc::clone(&adapter), Arc::clone(&ledger));
        let ticket = broker
            .create(&fixture.spec, &fixture.grant, UnixMillis::new(120))
            .expect("create");
        let operation_id = OperationId::new();
        let events_before = ledger.load().expect("ledger before rejected destroy");
        let SandboxCustody::Job { runner_id, .. } = fixture.spec.custody() else {
            panic!("job fixture");
        };

        assert_eq!(
            broker
                .destroy(
                    &ticket,
                    operation_id,
                    SandboxGeneration::new(fixture.spec.generation().get() + 1)
                        .expect("different generation"),
                    fixture.spec.custody(),
                )
                .expect_err("wrong generation must not destroy"),
            BrokerError::InvalidTicket
        );
        assert_eq!(
            broker
                .destroy(
                    &ticket,
                    operation_id,
                    fixture.spec.generation(),
                    SandboxCustody::ProfileAdmission { runner_id },
                )
                .expect_err("wrong custody must not destroy"),
            BrokerError::InvalidTicket
        );
        assert_eq!(
            ledger.load().expect("ledger after rejected destroy"),
            events_before
        );
        assert_eq!(adapter.destroys.load(Ordering::SeqCst), 0);

        broker
            .destroy(
                &ticket,
                operation_id,
                fixture.spec.generation(),
                fixture.spec.custody(),
            )
            .expect("exact destroy");
        assert_eq!(adapter.destroys.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn blocked_exec_cannot_starve_expiry_watchdog_or_revive_destroyed_state() {
        let fixture = fixture();
        let adapter = Arc::new(FakeHostCompute::default());
        let broker = Arc::new(broker(
            &fixture,
            Arc::clone(&adapter),
            Arc::new(InMemoryBrokerLedger::new()),
        ));
        let ticket = broker
            .create(&fixture.spec, &fixture.grant, UnixMillis::new(120))
            .expect("create");
        broker
            .attach(&ticket, UnixMillis::new(121))
            .expect("attach");
        let command = ExecutionCommand::new(
            OperationId::new(),
            ExecutionArgv::new(
                TargetPath::windows(r"C:\Windows\System32\cmd.exe").expect("program"),
                vec!["/d".to_owned(), "/c".to_owned(), "exit 0".to_owned()],
            )
            .expect("argv"),
            TargetPath::windows(r"C:\__w").expect("working directory"),
            ExecutionEnvironment::empty(),
            Duration::from_secs(30),
            1024,
        )
        .expect("command");
        adapter.block_exec();
        let exec_broker = Arc::clone(&broker);
        let exec_ticket = ticket.clone();
        let exec = thread::spawn(move || {
            exec_broker.exec(
                &exec_ticket,
                &command,
                UnixMillis::new(130),
                &NeverCancelled,
            )
        });
        adapter.wait_for_blocked_exec();

        assert_eq!(
            broker
                .watchdog_tick(UnixMillis::new(200))
                .expect("watchdog must not wait for blocked exec")
                .destroyed(),
            1
        );
        assert_eq!(
            exec.join()
                .expect("exec thread")
                .expect_err("exec was fenced"),
            BrokerError::OperationFenced
        );
        assert_eq!(adapter.destroys.load(Ordering::SeqCst), 1);
        assert_eq!(
            broker
                .inspect_ticket(&ticket, UnixMillis::new(201))
                .expect("terminal ticket remains inspectable")
                .phase(),
            BrokerLifecyclePhase::Destroyed
        );
    }

    #[test]
    fn secret_environment_is_rejected_before_ledger_or_adapter_mutation() {
        let fixture = fixture();
        let adapter = Arc::new(FakeHostCompute::default());
        let ledger = Arc::new(InMemoryBrokerLedger::new());
        let broker = broker(&fixture, Arc::clone(&adapter), Arc::clone(&ledger));
        let ticket = broker
            .create(&fixture.spec, &fixture.grant, UnixMillis::new(120))
            .expect("create");
        broker
            .attach(&ticket, UnixMillis::new(121))
            .expect("attach");
        let events_before = ledger.load().expect("ledger snapshot before exec");
        let environment = ExecutionEnvironment::new(vec![EnvironmentVariable::secret(
            EnvironmentName::new("AUTOMATA_SECRET").expect("environment name"),
            EnvironmentValue::new("must-not-cross").expect("environment value"),
        )])
        .expect("secret environment");
        let command = ExecutionCommand::new(
            OperationId::new(),
            ExecutionArgv::new(
                TargetPath::windows(r"C:\Windows\System32\cmd.exe").expect("program"),
                vec!["/d".to_owned(), "/c".to_owned(), "exit 0".to_owned()],
            )
            .expect("argv"),
            TargetPath::windows(r"C:\__w").expect("working directory"),
            environment,
            Duration::from_secs(30),
            1024,
        )
        .expect("command");

        assert_eq!(
            broker
                .exec(&ticket, &command, UnixMillis::new(130), &NeverCancelled,)
                .expect_err("secret environment must fail closed"),
            BrokerError::SecretEnvironmentForbidden
        );
        assert_eq!(adapter.execs.load(Ordering::SeqCst), 0);
        assert_eq!(
            ledger.load().expect("ledger snapshot after exec"),
            events_before
        );
    }

    #[test]
    fn restart_preserves_consumption_and_watchdog_reaps_expiry() {
        let fixture = fixture();
        let adapter = Arc::new(FakeHostCompute::default());
        let ledger = Arc::new(InMemoryBrokerLedger::new());
        let first = broker(&fixture, Arc::clone(&adapter), Arc::clone(&ledger));
        let ticket = first
            .create(&fixture.spec, &fixture.grant, UnixMillis::new(120))
            .expect("create");
        assert_eq!(
            first
                .inspect_ticket(&ticket, UnixMillis::new(121))
                .expect("inspection before restart")
                .custody(),
            fixture.spec.custody()
        );
        drop(first);
        let restarted = broker(&fixture, Arc::clone(&adapter), ledger);
        assert_eq!(
            restarted
                .inspect_ticket(&ticket, UnixMillis::new(129))
                .expect("inspection after restart")
                .custody(),
            fixture.spec.custody()
        );
        assert_eq!(
            restarted
                .create(&fixture.spec, &fixture.grant, UnixMillis::new(130))
                .expect("restart replay"),
            ticket
        );
        assert_eq!(adapter.creates.load(Ordering::SeqCst), 1);
        assert_eq!(
            restarted
                .watchdog_tick(UnixMillis::new(200))
                .expect("watchdog")
                .destroyed(),
            1
        );
        assert_eq!(adapter.destroys.load(Ordering::SeqCst), 1);
        assert_eq!(
            restarted
                .create(&fixture.spec, &fixture.grant, UnixMillis::new(199))
                .expect_err("destroyed grant cannot create again"),
            BrokerError::GrantAlreadyConsumed
        );
    }

    #[test]
    fn file_ledger_compaction_retains_live_and_unexpired_tombstone_state() {
        let directory = TemporaryLedgerDirectory::new();
        let fixture = fixture();
        let adapter = Arc::new(FakeHostCompute::default());
        let ledger = Arc::new(
            FileBrokerLedger::open(directory.path("broker-ledger.jsonl"))
                .expect("open file ledger"),
        );
        let broker = broker(&fixture, Arc::clone(&adapter), ledger.clone());
        let ticket = broker
            .create(&fixture.spec, &fixture.grant, UnixMillis::new(120))
            .expect("create");

        ledger
            .compact_at(UnixMillis::new(i64::MAX))
            .expect("live state survives compaction regardless of expiry");
        let live = ledger.load().expect("load compacted live ledger");
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].phase(), BrokerLifecyclePhase::Ready);

        broker
            .destroy(
                &ticket,
                OperationId::new(),
                fixture.spec.generation(),
                fixture.spec.custody(),
            )
            .expect("destroy");
        let retention_boundary = fixture
            .grant
            .claims()
            .expires_at()
            .get()
            .saturating_add(LEDGER_TOMBSTONE_CLOCK_SKEW_MILLIS);
        ledger
            .compact_at(UnixMillis::new(retention_boundary))
            .expect("compact retained tombstone");
        let retained = ledger.load().expect("load retained tombstone");
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].phase(), BrokerLifecyclePhase::Destroyed);

        ledger
            .compact_at(UnixMillis::new(retention_boundary.saturating_add(1)))
            .expect("compact expired tombstone");
        assert!(ledger.load().expect("load pruned ledger").is_empty());
    }

    #[test]
    fn file_ledger_recovers_every_atomic_compaction_rotation_state() {
        let directory = TemporaryLedgerDirectory::new();
        let fixture = fixture();
        let seed_path = directory.path("seed.jsonl");
        let seed = Arc::new(FileBrokerLedger::open(&seed_path).expect("open seed ledger"));
        let seed_broker = broker(&fixture, Arc::new(FakeHostCompute::default()), seed.clone());
        seed_broker
            .create(&fixture.spec, &fixture.grant, UnixMillis::new(120))
            .expect("seed create");
        let expected = seed.load().expect("seed entries");
        drop(seed_broker);
        drop(seed);

        let before_rotation = directory.path("before-rotation.jsonl");
        fs::copy(&seed_path, &before_rotation).expect("copy main journal");
        let (temporary, previous) = ledger_sidecar_paths(&before_rotation).expect("sidecar paths");
        fs::copy(&seed_path, &temporary).expect("copy synchronized temporary journal");
        let recovered = FileBrokerLedger::open(&before_rotation).expect("recover before rotation");
        assert_eq!(recovered.load().expect("load main"), expected);
        assert!(!temporary.exists());
        assert!(!previous.exists());
        drop(recovered);

        let old_renamed = directory.path("old-renamed.jsonl");
        let (temporary, previous) = ledger_sidecar_paths(&old_renamed).expect("sidecar paths");
        fs::copy(&seed_path, &temporary).expect("copy synchronized temporary journal");
        fs::copy(&seed_path, &previous).expect("copy previous journal");
        let recovered = FileBrokerLedger::open(&old_renamed).expect("recover renamed old journal");
        assert_eq!(recovered.load().expect("load promoted temporary"), expected);
        assert!(!temporary.exists());
        assert!(!previous.exists());
        drop(recovered);

        let previous_only = directory.path("previous-only.jsonl");
        let (_, previous) = ledger_sidecar_paths(&previous_only).expect("sidecar paths");
        fs::copy(&seed_path, &previous).expect("copy previous-only journal");
        let recovered =
            FileBrokerLedger::open(&previous_only).expect("recover previous-only journal");
        assert_eq!(recovered.load().expect("load restored previous"), expected);
        assert!(!previous.exists());
        drop(recovered);

        let promoted = directory.path("promoted.jsonl");
        fs::copy(&seed_path, &promoted).expect("copy promoted journal");
        let (_, previous) = ledger_sidecar_paths(&promoted).expect("sidecar paths");
        fs::copy(&seed_path, &previous).expect("copy leftover previous journal");
        let recovered = FileBrokerLedger::open(&promoted).expect("recover promoted journal");
        assert_eq!(recovered.load().expect("load promoted main"), expected);
        assert!(!previous.exists());
    }
}
