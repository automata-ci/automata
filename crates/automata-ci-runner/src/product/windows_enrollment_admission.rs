#![cfg_attr(test, allow(dead_code))]

use std::{
    collections::BTreeMap,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use automata_ci_core::{
    EnvironmentProfile, JobResourceAllocation, OperationId, RunnerCapabilities, RunnerId,
    Sha256Digest, windows_action_archive_policy_sha256,
};
use automata_ci_execution::{
    NetworkPolicy, ResourceLimits, RootFilesystemPolicy, SandboxEnvironment, SandboxLaunch,
    SandboxPrivilegePolicy, SandboxProvider, TargetPath,
};
use automata_ci_protocol::{
    WindowsAdmissionArgv, WindowsAdmissionBackendContract, WindowsAdmissionEnvironmentVariable,
    WindowsAdmissionHostInput, WindowsAdmissionHostInputKind, WindowsAdmissionImage,
    WindowsAdmissionLaunchContract, WindowsAdmissionProbeContract,
    WindowsAdmissionPromotionRequest, WindowsAdmissionResourceLimits, WindowsBrokerProfileBinding,
    WindowsEnrollmentTransactionBinding, WindowsImagePromotionBinding, WindowsPromotionValidity,
    WindowsRunnerAdmissionBinding, WindowsRunnerAdmissionIssueRequest,
};
use automata_ci_sandbox_windows::WINDOWS_HYPERV_PROVIDER_ID;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use super::{
    RunnerProductConfig,
    config::windows_broker_admission_feature_ceiling,
    profile_admission::{
        ProfileAdmissionOutcome, ProfileAdmissionPolicy, WINDOWS_PROFILE_PROBE_SCHEMA_VERSION,
        admit_environment_profiles, windows_profile_probe_contract_sha256,
    },
};

#[cfg(test)]
const MAX_ID_BYTES: usize = 128;
const MAX_SERVER_ORIGIN_BYTES: usize = 2_048;
const MAX_RUNNER_NAME_BYTES: usize = 255;
#[cfg(test)]
const MAX_RECEIPT_LIFETIME_SECONDS: u64 = 15 * 60;
#[cfg(test)]
const WINDOWS_ENROLLMENT_RECEIPT_SCHEMA_VERSION: u16 = 1;
#[cfg(test)]
const MIN_RECEIPT_AUTHENTICATOR_BYTES: usize = 16;
#[cfg(test)]
const MAX_RECEIPT_AUTHENTICATOR_BYTES: usize = 512;
const WINDOWS_HOST_INPUT_KINDS: [WindowsHostInputKind; 9] = [
    WindowsHostInputKind::Configuration,
    WindowsHostInputKind::BackendExecutable,
    WindowsHostInputKind::ImageManifest,
    WindowsHostInputKind::ImageLock,
    WindowsHostInputKind::Provenance,
    WindowsHostInputKind::Sbom,
    WindowsHostInputKind::PatchReport,
    WindowsHostInputKind::Revocations,
    WindowsHostInputKind::PromotionEnvelope,
];

/// Closed classes of host files independently attested by the Windows broker.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsHostInputKind {
    /// The exact runner product configuration document.
    Configuration,
    /// The exact restricted broker client/provider executable.
    BackendExecutable,
    /// The image manifest.
    ImageManifest,
    /// The image lock document.
    ImageLock,
    /// The provenance acceptance/reference record.
    Provenance,
    /// The SBOM acceptance/reference record.
    Sbom,
    /// The patch acceptance/reference record.
    PatchReport,
    /// The revocation record.
    Revocations,
    /// The externally signed promotion envelope.
    PromotionEnvelope,
}

/// Exact host-file identity which broker admission must independently attest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsHostInputDescriptor {
    kind: WindowsHostInputKind,
    absolute_path: PathBuf,
    expected_sha256: Sha256Digest,
}

impl WindowsHostInputDescriptor {
    /// Returns the closed semantic input class.
    #[must_use]
    pub const fn kind(&self) -> WindowsHostInputKind {
        self.kind
    }

    /// Returns the exact local-drive-qualified host path.
    #[must_use]
    pub fn absolute_path(&self) -> &Path {
        &self.absolute_path
    }

    /// Returns the content digest the broker must reproduce from a stable handle.
    #[must_use]
    pub const fn expected_sha256(&self) -> Sha256Digest {
        self.expected_sha256
    }
}

/// Exact one-time enrollment transaction authorized by active admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsEnrollmentIntent {
    operation_id: Uuid,
    server_origin: String,
    runner_name: String,
    enrollment_token_sha256: Sha256Digest,
    csr_sha256: Sha256Digest,
}

impl WindowsEnrollmentIntent {
    /// Creates a secret-free binding for one exact enrollment operation.
    ///
    /// The token and private key remain inside broker custody; only the
    /// one-way token digest and public certificate-request digest cross this
    /// boundary.
    ///
    /// # Errors
    ///
    /// Rejects a nil operation, unsafe server origin or runner name, or a zero
    /// placeholder digest.
    pub fn new(
        operation_id: Uuid,
        server_origin: &reqwest::Url,
        runner_name: impl Into<String>,
        enrollment_token_sha256: Sha256Digest,
        csr_sha256: Sha256Digest,
    ) -> Result<Self, WindowsEnrollmentAdmissionError> {
        let runner_name = runner_name.into();
        let origin = server_origin.as_str();
        let literal_loopback = server_origin.scheme() == "http"
            && server_origin
                .host_str()
                .and_then(|host| host.parse::<IpAddr>().ok())
                .is_some_and(|address| address.is_loopback());
        if operation_id.is_nil()
            || (server_origin.scheme() != "https" && !literal_loopback)
            || server_origin.cannot_be_a_base()
            || server_origin.host().is_none()
            || server_origin.username() != ""
            || server_origin.password().is_some()
            || server_origin.query().is_some()
            || server_origin.fragment().is_some()
            || server_origin.path() != "/"
            || origin.len() > MAX_SERVER_ORIGIN_BYTES
            || runner_name.is_empty()
            || runner_name.len() > MAX_RUNNER_NAME_BYTES
            || runner_name.trim() != runner_name
            || runner_name.chars().any(char::is_control)
            || zero_digest(enrollment_token_sha256)
            || zero_digest(csr_sha256)
        {
            return Err(WindowsEnrollmentAdmissionError::InvalidRequest);
        }
        Ok(Self {
            operation_id,
            server_origin: origin.to_owned(),
            runner_name,
            enrollment_token_sha256,
            csr_sha256,
        })
    }

    /// Returns the idempotent enrollment operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    /// Returns the exact validated enrollment-server origin.
    #[must_use]
    pub fn server_origin(&self) -> &str {
        &self.server_origin
    }

    /// Returns the exact registered runner display name.
    #[must_use]
    pub fn runner_name(&self) -> &str {
        &self.runner_name
    }

    /// Returns the digest of the one-time enrollment token held by the broker.
    #[must_use]
    pub const fn enrollment_token_sha256(&self) -> Sha256Digest {
        self.enrollment_token_sha256
    }

    /// Returns the digest of the broker-custodied key's certificate request.
    #[must_use]
    pub const fn csr_sha256(&self) -> Sha256Digest {
        self.csr_sha256
    }
}

/// Exact configuration and capability binding submitted to active admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsEnrollmentAdmissionBinding {
    runner_id: RunnerId,
    control_endpoint: String,
    intent: WindowsEnrollmentIntent,
    backend_id: String,
    sandbox_provider_id: String,
    backend_executable: PathBuf,
    backend_executable_sha256: Sha256Digest,
    backend_operation_timeout: Duration,
    host_inputs: Vec<WindowsHostInputDescriptor>,
    profile: EnvironmentProfile,
    image: String,
    environment: SandboxEnvironment,
    probe_policy: WindowsEnrollmentProbePolicy,
    manifest_sha256: Sha256Digest,
    lock_sha256: Sha256Digest,
    promotion_trust_bundle_id: String,
    promotion_key_id: String,
    promotion_payload_sha256: Sha256Digest,
    promotion_envelope_sha256: Sha256Digest,
    promotion_serial: u64,
    revocation_generation: u64,
    promotion_issued_at_unix_millis: u64,
    promotion_expires_at_unix_millis: u64,
    capabilities: RunnerCapabilities,
    capabilities_sha256: Sha256Digest,
}

impl WindowsEnrollmentAdmissionBinding {
    /// Returns the durable runner identity being admitted.
    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    /// Returns the exact control endpoint expected in the enrollment result.
    #[must_use]
    pub fn control_endpoint(&self) -> &str {
        &self.control_endpoint
    }

    /// Returns the one-time enrollment transaction bound to this receipt.
    #[must_use]
    pub const fn intent(&self) -> &WindowsEnrollmentIntent {
        &self.intent
    }

    /// Returns the lowercase SHA-256 identity of the exact broker host authority.
    #[must_use]
    pub fn backend_id(&self) -> &str {
        &self.backend_id
    }

    /// Returns the fixed sandbox-provider identity used by active admission.
    #[must_use]
    pub fn sandbox_provider_id(&self) -> &str {
        &self.sandbox_provider_id
    }

    /// Returns the exact broker client/provider executable admitted on the host.
    #[must_use]
    pub fn backend_executable(&self) -> &Path {
        &self.backend_executable
    }

    /// Returns the expected digest of the broker client/provider executable.
    #[must_use]
    pub const fn backend_executable_sha256(&self) -> Sha256Digest {
        self.backend_executable_sha256
    }

    /// Returns the exact deadline applied to each broker/provider operation.
    #[must_use]
    pub const fn backend_operation_timeout(&self) -> Duration {
        self.backend_operation_timeout
    }

    /// Returns the fixed ordered host inputs requiring broker ACL/file-ID proof.
    #[must_use]
    pub fn host_inputs(&self) -> &[WindowsHostInputDescriptor] {
        &self.host_inputs
    }

    /// Returns the exact content-attested environment profile.
    #[must_use]
    pub const fn profile(&self) -> &EnvironmentProfile {
        &self.profile
    }

    /// Returns the immutable digest-qualified image reference.
    #[must_use]
    pub fn image(&self) -> &str {
        &self.image
    }

    /// Returns the complete immutable launch material admitted by the receipt.
    #[must_use]
    pub const fn environment(&self) -> &SandboxEnvironment {
        &self.environment
    }

    /// Returns the exact lifecycle and tool probes admitted by the receipt.
    #[must_use]
    pub const fn probe_policy(&self) -> &WindowsEnrollmentProbePolicy {
        &self.probe_policy
    }

    /// Returns the exact image-manifest digest.
    #[must_use]
    pub const fn manifest_sha256(&self) -> Sha256Digest {
        self.manifest_sha256
    }

    /// Returns the exact image-lock digest.
    #[must_use]
    pub const fn lock_sha256(&self) -> Sha256Digest {
        self.lock_sha256
    }

    /// Returns the broker/control-owned versioned promotion trust bundle.
    #[must_use]
    pub fn promotion_trust_bundle_id(&self) -> &str {
        &self.promotion_trust_bundle_id
    }

    /// Returns the requested external promotion-authority key identifier.
    #[must_use]
    pub fn promotion_key_id(&self) -> &str {
        &self.promotion_key_id
    }

    /// Returns the digest of the canonical signed promotion payload.
    #[must_use]
    pub const fn promotion_payload_sha256(&self) -> Sha256Digest {
        self.promotion_payload_sha256
    }

    /// Returns the digest of the complete envelope pending broker verification.
    #[must_use]
    pub const fn promotion_envelope_sha256(&self) -> Sha256Digest {
        self.promotion_envelope_sha256
    }

    /// Returns the signed monotonic promotion serial the broker must advance.
    #[must_use]
    pub const fn promotion_serial(&self) -> u64 {
        self.promotion_serial
    }

    /// Returns the signed revocation generation the broker must advance.
    #[must_use]
    pub const fn revocation_generation(&self) -> u64 {
        self.revocation_generation
    }

    /// Returns the signed promotion issue time.
    #[must_use]
    pub const fn promotion_issued_at_unix_millis(&self) -> u64 {
        self.promotion_issued_at_unix_millis
    }

    /// Returns the signed promotion expiry time.
    #[must_use]
    pub const fn promotion_expires_at_unix_millis(&self) -> u64 {
        self.promotion_expires_at_unix_millis
    }

    /// Returns the exact post-admission registration inventory.
    #[must_use]
    pub const fn capabilities(&self) -> &RunnerCapabilities {
        &self.capabilities
    }

    /// Returns the canonical serialized capability-set digest.
    #[must_use]
    pub const fn capabilities_sha256(&self) -> Sha256Digest {
        self.capabilities_sha256
    }

    /// Converts this runner-generated request into the canonical, evidence-
    /// free protocol binding which the broker must prove and sign.
    ///
    /// This method cannot construct admission evidence, a custody handle, or
    /// registered capability authority. Those values exist only in the
    /// canonical broker-signed protocol envelope and are independently
    /// verified by control.
    ///
    /// # Errors
    ///
    /// Rejects any request which cannot satisfy the shared protocol schema.
    pub fn to_protocol_binding(
        &self,
    ) -> Result<WindowsRunnerAdmissionBinding, WindowsEnrollmentAdmissionError> {
        let issue_request = self.to_protocol_issue_request()?;
        let image = self
            .environment
            .image()
            .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?;
        let transaction = WindowsEnrollmentTransactionBinding::new(
            self.runner_id,
            OperationId::from_uuid(self.intent.operation_id),
            self.control_endpoint.clone(),
            self.intent.server_origin.clone(),
            digest_bytes(self.intent.runner_name.as_bytes()),
            self.intent.enrollment_token_sha256,
            self.intent.csr_sha256,
        )
        .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?;
        let image = WindowsAdmissionImage::new(self.image.clone(), image.digest())
            .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?;
        let broker_profile = WindowsBrokerProfileBinding::new(
            self.backend_id.clone(),
            self.sandbox_provider_id.clone(),
            issue_request
                .request_sha256()
                .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?,
            self.profile.clone(),
            image,
            self.probe_policy.contract_sha256,
            self.probe_policy.network == NetworkPolicy::Disabled,
            true,
            windows_action_archive_policy_sha256(),
            self.probe_policy.resources.pids(),
        )
        .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?;
        let promotion = WindowsImagePromotionBinding::new(
            self.promotion_trust_bundle_id.clone(),
            self.promotion_key_id.clone(),
            self.promotion_payload_sha256,
            self.promotion_envelope_sha256,
            self.promotion_serial,
            self.revocation_generation,
            WindowsPromotionValidity::new(
                self.promotion_issued_at_unix_millis,
                self.promotion_expires_at_unix_millis,
            )
            .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?,
        )
        .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?;
        WindowsRunnerAdmissionBinding::new(
            transaction,
            broker_profile,
            promotion,
            self.capabilities.clone(),
        )
        .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)
    }

    /// Converts the complete runner proposal into the strict, serializable,
    /// non-authoritative broker issue request.
    ///
    /// The broker must independently reopen every host input, verify the
    /// promotion with its own trust policy/high-water ledger, reproduce the
    /// exact probe, and sign the resulting admission envelope. This DTO and
    /// its digest alone convey no registration authority.
    ///
    /// # Errors
    ///
    /// Rejects secret-bearing defaults or any launch, host-input, promotion,
    /// resource, or tool field outside the shared protocol contract.
    #[allow(clippy::too_many_lines)]
    pub fn to_protocol_issue_request(
        &self,
    ) -> Result<WindowsRunnerAdmissionIssueRequest, WindowsEnrollmentAdmissionError> {
        let executable = self
            .backend_executable
            .to_str()
            .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?;
        let timeout = u64::try_from(self.backend_operation_timeout.as_millis())
            .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?;
        let backend = WindowsAdmissionBackendContract::new(
            executable,
            self.backend_executable_sha256,
            timeout,
        )
        .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?;
        let host_inputs = self
            .host_inputs
            .iter()
            .map(|input| {
                WindowsAdmissionHostInput::new(
                    protocol_host_input_kind(input.kind),
                    input
                        .absolute_path
                        .to_str()
                        .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?,
                    input.expected_sha256,
                )
                .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let SandboxLaunch::WindowsHyperVContainer { image, keepalive } = self.environment.launch()
        else {
            return Err(WindowsEnrollmentAdmissionError::InvalidRequest);
        };
        let image = WindowsAdmissionImage::new(image.reference(), image.digest())
            .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?;
        let keepalive =
            WindowsAdmissionArgv::new(keepalive.program().as_str(), keepalive.arguments().to_vec())
                .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?;
        let default_environment = self
            .environment
            .default_environment()
            .values()
            .iter()
            .map(|variable| {
                if variable.is_secret() {
                    return Err(WindowsEnrollmentAdmissionError::InvalidRequest);
                }
                WindowsAdmissionEnvironmentVariable::new(
                    variable.name().as_str(),
                    variable.value().expose(),
                )
                .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let resources = protocol_resource_limits(self.probe_policy.resources)?;
        let launch = WindowsAdmissionLaunchContract::new(
            self.profile.clone(),
            image,
            keepalive,
            self.environment.workspace().as_str(),
            default_environment,
            resources,
            self.probe_policy.allocation,
            self.probe_policy.network == NetworkPolicy::Disabled,
            self.probe_policy.root_filesystem == RootFilesystemPolicy::Writable,
            self.probe_policy.privilege == SandboxPrivilegePolicy::Unprivileged,
            true,
            true,
            windows_action_archive_policy_sha256(),
        )
        .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?;
        let probe = WindowsAdmissionProbeContract::new(
            self.probe_policy.contract_schema_version,
            self.probe_policy.contract_sha256,
            resources,
            self.probe_policy.allocation,
            self.probe_policy.network == NetworkPolicy::Disabled,
            self.probe_policy.root_filesystem == RootFilesystemPolicy::Writable,
            self.probe_policy.privilege == SandboxPrivilegePolicy::Unprivileged,
            self.probe_policy.pwsh.as_str(),
            self.probe_policy.powershell.as_str(),
            self.probe_policy.cmd.as_str(),
            self.probe_policy
                .python
                .as_ref()
                .map(|path| path.as_str().to_owned()),
            self.probe_policy.tar.as_str(),
            self.probe_policy.sha256.as_str(),
            self.probe_policy
                .node12
                .as_ref()
                .map(|path| path.as_str().to_owned()),
            self.probe_policy
                .node16
                .as_ref()
                .map(|path| path.as_str().to_owned()),
            self.probe_policy
                .node20
                .as_ref()
                .map(|path| path.as_str().to_owned()),
            self.probe_policy
                .node24
                .as_ref()
                .map(|path| path.as_str().to_owned()),
        )
        .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?;
        let envelope_path = self
            .host_inputs
            .iter()
            .find(|input| input.kind == WindowsHostInputKind::PromotionEnvelope)
            .and_then(|input| input.absolute_path.to_str())
            .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?;
        let promotion = WindowsAdmissionPromotionRequest::new(
            envelope_path,
            self.promotion_trust_bundle_id.clone(),
            self.promotion_key_id.clone(),
            self.manifest_sha256,
            self.lock_sha256,
        )
        .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?;
        let transaction = WindowsEnrollmentTransactionBinding::new(
            self.runner_id,
            OperationId::from_uuid(self.intent.operation_id),
            self.control_endpoint.clone(),
            self.intent.server_origin.clone(),
            digest_bytes(self.intent.runner_name.as_bytes()),
            self.intent.enrollment_token_sha256,
            self.intent.csr_sha256,
        )
        .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?;
        WindowsRunnerAdmissionIssueRequest::new(
            transaction,
            self.intent.runner_name.clone(),
            self.backend_id.clone(),
            self.sandbox_provider_id.clone(),
            backend,
            host_inputs,
            launch,
            probe,
            promotion,
            self.capabilities.clone(),
        )
        .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)
    }
}

/// Exact provider-policy and toolchain inputs which active admission must probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsEnrollmentProbePolicy {
    contract_schema_version: u16,
    contract_sha256: Sha256Digest,
    resources: ResourceLimits,
    allocation: JobResourceAllocation,
    network: NetworkPolicy,
    root_filesystem: RootFilesystemPolicy,
    privilege: SandboxPrivilegePolicy,
    pwsh: TargetPath,
    powershell: TargetPath,
    cmd: TargetPath,
    python: Option<TargetPath>,
    tar: TargetPath,
    sha256: TargetPath,
    node12: Option<TargetPath>,
    node16: Option<TargetPath>,
    node20: Option<TargetPath>,
    node24: Option<TargetPath>,
}

impl WindowsEnrollmentProbePolicy {
    /// Returns the version of the shared lifecycle/tool probe contract.
    #[must_use]
    pub const fn contract_schema_version(&self) -> u16 {
        self.contract_schema_version
    }

    /// Returns the digest of the exact shared probe semantics.
    #[must_use]
    pub const fn contract_sha256(&self) -> Sha256Digest {
        self.contract_sha256
    }

    /// Returns the enforced per-sandbox CPU, memory, and process limits.
    #[must_use]
    pub const fn resources(&self) -> ResourceLimits {
        self.resources
    }

    /// Returns the exact resource request and limit used by the admission sandbox.
    #[must_use]
    pub const fn allocation(&self) -> JobResourceAllocation {
        self.allocation
    }

    /// Returns the required disabled-network policy.
    #[must_use]
    pub const fn network(&self) -> NetworkPolicy {
        self.network
    }

    /// Returns the required disposable writable-root policy.
    #[must_use]
    pub const fn root_filesystem(&self) -> RootFilesystemPolicy {
        self.root_filesystem
    }

    /// Returns the required non-administrator workload identity.
    #[must_use]
    pub const fn privilege(&self) -> SandboxPrivilegePolicy {
        self.privilege
    }

    /// Returns the exact PowerShell Core executable to probe.
    #[must_use]
    pub const fn pwsh(&self) -> &TargetPath {
        &self.pwsh
    }

    /// Returns the exact Windows PowerShell executable to probe.
    #[must_use]
    pub const fn powershell(&self) -> &TargetPath {
        &self.powershell
    }

    /// Returns the exact Windows command interpreter to probe.
    #[must_use]
    pub const fn cmd(&self) -> &TargetPath {
        &self.cmd
    }

    /// Returns the optional standalone Python executable to probe.
    #[must_use]
    pub const fn python(&self) -> Option<&TargetPath> {
        self.python.as_ref()
    }

    /// Returns the exact archive executable to probe.
    #[must_use]
    pub const fn tar(&self) -> &TargetPath {
        &self.tar
    }

    /// Returns the exact SHA-256 helper executable to probe.
    #[must_use]
    pub const fn sha256(&self) -> &TargetPath {
        &self.sha256
    }

    /// Returns the optional exact Node 12 executable to probe.
    #[must_use]
    pub const fn node12(&self) -> Option<&TargetPath> {
        self.node12.as_ref()
    }

    /// Returns the optional exact Node 16 executable to probe.
    #[must_use]
    pub const fn node16(&self) -> Option<&TargetPath> {
        self.node16.as_ref()
    }

    /// Returns the optional exact Node 20 executable to probe.
    #[must_use]
    pub const fn node20(&self) -> Option<&TargetPath> {
        self.node20.as_ref()
    }

    /// Returns the optional exact Node 24 executable to probe.
    #[must_use]
    pub const fn node24(&self) -> Option<&TargetPath> {
        self.node24.as_ref()
    }
}

/// Request passed to the trusted Windows active-admission and custody port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsEnrollmentAdmissionRequest {
    binding: WindowsEnrollmentAdmissionBinding,
}

impl WindowsEnrollmentAdmissionRequest {
    /// Returns the exact receipt binding to prove and retain.
    #[must_use]
    pub const fn binding(&self) -> &WindowsEnrollmentAdmissionBinding {
        &self.binding
    }

    /// Returns the immutable environment which must pass a fresh full lifecycle probe.
    #[must_use]
    pub const fn environment(&self) -> &SandboxEnvironment {
        self.binding.environment()
    }

    /// Returns the exact lifecycle and tool probes required before enrollment.
    #[must_use]
    pub const fn probe_policy(&self) -> &WindowsEnrollmentProbePolicy {
        self.binding.probe_policy()
    }

    /// Returns the canonical evidence-free binding for the broker/control
    /// admission envelope.
    ///
    /// # Errors
    ///
    /// Rejects a request which cannot satisfy the shared protocol schema.
    pub fn to_protocol_binding(
        &self,
    ) -> Result<WindowsRunnerAdmissionBinding, WindowsEnrollmentAdmissionError> {
        self.binding.to_protocol_binding()
    }

    /// Returns the complete canonical proposal the broker must independently
    /// verify before it may mint a signed admission envelope.
    ///
    /// # Errors
    ///
    /// Rejects any field outside the shared non-authoritative issue schema.
    pub fn to_protocol_issue_request(
        &self,
    ) -> Result<WindowsRunnerAdmissionIssueRequest, WindowsEnrollmentAdmissionError> {
        self.binding.to_protocol_issue_request()
    }
}

/// Executes the shared, versioned lifecycle and tool probe for enrollment.
///
/// This is the only probe implementation accepted by the enrollment port. It
/// uses the same create/inspect/attach/copy/exec/destroy admission path used at
/// runner startup, including the exact shell scripts, argument vectors, version
/// prefixes, Node-major checks, output bounds, cleanup, and absence proof.
///
/// # Errors
///
/// Fails closed if the request names another probe contract or provider, the
/// probe is cancelled, or any lifecycle, tool, output, or cleanup evidence is
/// invalid.
pub fn probe_windows_enrollment_request(
    request: &WindowsEnrollmentAdmissionRequest,
    provider: &dyn SandboxProvider,
    cancellation: &crate::podman_probe::ProbeCancellation,
) -> Result<(), WindowsEnrollmentAdmissionError> {
    let probe = request.probe_policy();
    if probe.contract_schema_version != WINDOWS_PROFILE_PROBE_SCHEMA_VERSION
        || probe.contract_sha256 != windows_profile_probe_contract_sha256()
        || provider.provider_id().as_str() != request.binding.sandbox_provider_id
    {
        return Err(WindowsEnrollmentAdmissionError::InvalidRequest);
    }
    let policy = ProfileAdmissionPolicy::new(
        probe.network,
        probe.root_filesystem,
        probe.privilege,
        probe.resources,
        probe.allocation,
    )
    .with_windows_hyperv_tools(
        probe.pwsh.clone(),
        probe.powershell.clone(),
        probe.cmd.clone(),
        probe.python.clone(),
        probe.tar.clone(),
        probe.sha256.clone(),
        probe.node12.clone(),
        probe.node16.clone(),
        probe.node20.clone(),
        probe.node24.clone(),
    )
    .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?;
    let environment = request.environment();
    let environments = BTreeMap::from([(environment.attestation().clone(), environment.clone())]);
    match admit_environment_profiles(
        provider,
        request.binding().runner_id(),
        &environments,
        policy,
        cancellation,
    ) {
        Ok(ProfileAdmissionOutcome::Admitted) => Ok(()),
        Ok(ProfileAdmissionOutcome::Cancelled) => Err(WindowsEnrollmentAdmissionError::Unavailable),
        Err(_) => Err(WindowsEnrollmentAdmissionError::ProbeFailed),
    }
}

/// Builds the active-admission request for a promotion-pending Windows image.
///
/// A candidate or unverified image returns `None` and retains the shell-only
/// durable inventory. Local envelope checks are only fail-fast: the broker must
/// independently resolve the trust bundle/key, verify every host input and
/// signature, advance durable serial floors, and return an authenticated
/// receipt before its inventory may be sent during enrollment.
///
/// # Errors
///
/// Rejects missing promotion identity, an invalid broker-host digest, an
/// ambiguous environment catalog, or an invalid derived capability set.
pub fn windows_enrollment_admission_request(
    config: &RunnerProductConfig,
    backend_id: &str,
    intent: WindowsEnrollmentIntent,
) -> Result<Option<WindowsEnrollmentAdmissionRequest>, WindowsEnrollmentAdmissionError> {
    let Some(windows) = config.windows_hyperv() else {
        return Ok(None);
    };
    if !windows.image_admission().is_promotion_pending() {
        return Ok(None);
    }
    if !valid_backend_id(backend_id) || config.executor().network() != NetworkPolicy::Disabled {
        return Err(WindowsEnrollmentAdmissionError::InvalidRequest);
    }
    let (profile, environment) = config
        .environments()
        .first_key_value()
        .filter(|_| config.environments().len() == 1)
        .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?;
    let image = environment
        .image()
        .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?;
    let promotion = windows
        .image_contract()
        .promotion()
        .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?;
    let promotion_payload_sha256 = windows
        .promotion_payload_sha256()
        .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?;
    let promotion_envelope_sha256 = windows
        .promotion_envelope_sha256()
        .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?;
    let capabilities =
        config
            .inventory()
            .clone()
            .with_features(windows_broker_admission_feature_ceiling(
                config.executor().toolchain(),
            ));
    capabilities
        .validate()
        .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?;
    let capabilities_sha256 = canonical_digest(&capabilities)?;
    let capacity = config.executor().resource_capacity();
    let allocation = JobResourceAllocation::new(capacity, capacity)
        .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?;
    let host_inputs = windows_host_inputs(config)?;
    Ok(Some(WindowsEnrollmentAdmissionRequest {
        binding: WindowsEnrollmentAdmissionBinding {
            runner_id: config.runner_id(),
            control_endpoint: config.control_endpoint().to_string(),
            intent,
            backend_id: backend_id.to_owned(),
            sandbox_provider_id: WINDOWS_HYPERV_PROVIDER_ID.to_owned(),
            backend_executable: windows.runtime_executable().to_owned(),
            backend_executable_sha256: windows.runtime_sha256(),
            backend_operation_timeout: windows.operation_timeout(),
            host_inputs,
            profile: profile.clone(),
            image: image.reference().to_owned(),
            environment: environment.clone(),
            probe_policy: windows_enrollment_probe_policy(config, allocation)?,
            manifest_sha256: windows.image_contract().manifest_sha256(),
            lock_sha256: windows.image_contract().lock_sha256(),
            promotion_trust_bundle_id: promotion.trust_bundle_id().as_str().to_owned(),
            promotion_key_id: promotion.key_id().to_owned(),
            promotion_payload_sha256,
            promotion_envelope_sha256,
            promotion_serial: windows
                .promotion_serial()
                .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?,
            revocation_generation: windows
                .revocation_generation()
                .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?,
            promotion_issued_at_unix_millis: windows
                .promotion_issued_at_unix_millis()
                .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?,
            promotion_expires_at_unix_millis: windows
                .promotion_expires_at_unix_millis()
                .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?,
            capabilities,
            capabilities_sha256,
        },
    }))
}

fn windows_host_inputs(
    config: &RunnerProductConfig,
) -> Result<Vec<WindowsHostInputDescriptor>, WindowsEnrollmentAdmissionError> {
    let windows = config
        .windows_hyperv()
        .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?;
    let contract = windows.image_contract();
    let promotion = contract
        .promotion()
        .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?;
    let [provenance, sbom, patch_report, revocations] = windows
        .evidence_digests()
        .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?;
    let inputs = vec![
        WindowsHostInputDescriptor {
            kind: WindowsHostInputKind::Configuration,
            absolute_path: config
                .configuration_path()
                .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?
                .to_owned(),
            expected_sha256: config
                .configuration_sha256()
                .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?,
        },
        WindowsHostInputDescriptor {
            kind: WindowsHostInputKind::BackendExecutable,
            absolute_path: windows.runtime_executable().to_owned(),
            expected_sha256: windows.runtime_sha256(),
        },
        WindowsHostInputDescriptor {
            kind: WindowsHostInputKind::ImageManifest,
            absolute_path: contract.manifest_path().to_owned(),
            expected_sha256: contract.manifest_sha256(),
        },
        WindowsHostInputDescriptor {
            kind: WindowsHostInputKind::ImageLock,
            absolute_path: contract.lock_path().to_owned(),
            expected_sha256: contract.lock_sha256(),
        },
        WindowsHostInputDescriptor {
            kind: WindowsHostInputKind::Provenance,
            absolute_path: contract.provenance_path().to_owned(),
            expected_sha256: provenance,
        },
        WindowsHostInputDescriptor {
            kind: WindowsHostInputKind::Sbom,
            absolute_path: contract.sbom_path().to_owned(),
            expected_sha256: sbom,
        },
        WindowsHostInputDescriptor {
            kind: WindowsHostInputKind::PatchReport,
            absolute_path: contract.patch_report_path().to_owned(),
            expected_sha256: patch_report,
        },
        WindowsHostInputDescriptor {
            kind: WindowsHostInputKind::Revocations,
            absolute_path: contract.revocations_path().to_owned(),
            expected_sha256: revocations,
        },
        WindowsHostInputDescriptor {
            kind: WindowsHostInputKind::PromotionEnvelope,
            absolute_path: promotion.envelope_path().to_owned(),
            expected_sha256: windows
                .promotion_envelope_sha256()
                .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?,
        },
    ];
    if !valid_host_inputs(&inputs) {
        return Err(WindowsEnrollmentAdmissionError::InvalidRequest);
    }
    Ok(inputs)
}

fn valid_host_inputs(inputs: &[WindowsHostInputDescriptor]) -> bool {
    let unique_paths = inputs
        .iter()
        .map(|input| input.absolute_path.as_os_str())
        .collect::<std::collections::BTreeSet<_>>();
    unique_paths.len() == inputs.len()
        && inputs.len() == WINDOWS_HOST_INPUT_KINDS.len()
        && inputs
            .iter()
            .zip(WINDOWS_HOST_INPUT_KINDS)
            .all(|(input, kind)| input.kind == kind)
        && inputs.iter().all(|input| {
            input.absolute_path.to_str().is_some_and(|path| {
                WindowsAdmissionHostInput::new(
                    protocol_host_input_kind(input.kind),
                    path,
                    input.expected_sha256,
                )
                .is_ok()
            })
        })
}

fn windows_enrollment_probe_policy(
    config: &RunnerProductConfig,
    allocation: JobResourceAllocation,
) -> Result<WindowsEnrollmentProbePolicy, WindowsEnrollmentAdmissionError> {
    let toolchain = config.executor().toolchain();
    Ok(WindowsEnrollmentProbePolicy {
        contract_schema_version: WINDOWS_PROFILE_PROBE_SCHEMA_VERSION,
        contract_sha256: windows_profile_probe_contract_sha256(),
        resources: config.executor().resources(),
        allocation,
        network: config.executor().network(),
        root_filesystem: config.executor().root_filesystem(),
        privilege: config.executor().privilege(),
        pwsh: toolchain
            .pwsh()
            .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?
            .clone(),
        powershell: toolchain
            .powershell()
            .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?
            .clone(),
        cmd: toolchain
            .cmd()
            .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?
            .clone(),
        python: toolchain.python().cloned(),
        tar: toolchain
            .tar()
            .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?
            .clone(),
        sha256: toolchain
            .sha256sum()
            .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?
            .clone(),
        node12: toolchain.node12().cloned(),
        node16: toolchain.node16().cloned(),
        node20: toolchain.node20().cloned(),
        node24: toolchain.node24().cloned(),
    })
}

/// Opaque broker-custody handle retained across an interrupted enrollment.
#[cfg(test)]
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct WindowsEnrollmentAdmissionHandle(String);

#[cfg(test)]
impl WindowsEnrollmentAdmissionHandle {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(value: impl Into<String>) -> Result<Self, WindowsEnrollmentAdmissionError> {
        let value = value.into();
        if !valid_id(&value) {
            return Err(WindowsEnrollmentAdmissionError::InvalidReceipt);
        }
        Ok(Self(value))
    }

    /// Returns the opaque handle for a broker resume or completion call.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
impl std::fmt::Debug for WindowsEnrollmentAdmissionHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WindowsEnrollmentAdmissionHandle")
            .field("value", &"[OPAQUE]")
            .finish()
    }
}

/// Digests of the independently authenticated evidence consumed by admission.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsEnrollmentAdmissionEvidence {
    broker_attestation: Sha256Digest,
    host_input_attestation: Sha256Digest,
    image_attestation: Sha256Digest,
    network_attestation: Sha256Digest,
    authority_attestation: Sha256Digest,
    profile_contract: Sha256Digest,
    promotion_trust_bundle: Sha256Digest,
    promotion_public_key: Sha256Digest,
    cleanup_receipt: Sha256Digest,
}

#[cfg(test)]
impl WindowsEnrollmentAdmissionEvidence {
    #[cfg_attr(not(test), allow(dead_code))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        broker_attestation_sha256: Sha256Digest,
        host_input_attestation_sha256: Sha256Digest,
        image_attestation_sha256: Sha256Digest,
        network_attestation_sha256: Sha256Digest,
        authority_attestation_sha256: Sha256Digest,
        profile_contract_sha256: Sha256Digest,
        promotion_trust_bundle_sha256: Sha256Digest,
        promotion_public_key_sha256: Sha256Digest,
        cleanup_receipt_sha256: Sha256Digest,
    ) -> Result<Self, WindowsEnrollmentAdmissionError> {
        let digests = [
            broker_attestation_sha256,
            host_input_attestation_sha256,
            image_attestation_sha256,
            network_attestation_sha256,
            authority_attestation_sha256,
            profile_contract_sha256,
            promotion_trust_bundle_sha256,
            promotion_public_key_sha256,
            cleanup_receipt_sha256,
        ];
        if digests.iter().copied().any(zero_digest) {
            return Err(WindowsEnrollmentAdmissionError::InvalidReceipt);
        }
        Ok(Self {
            broker_attestation: broker_attestation_sha256,
            host_input_attestation: host_input_attestation_sha256,
            image_attestation: image_attestation_sha256,
            network_attestation: network_attestation_sha256,
            authority_attestation: authority_attestation_sha256,
            profile_contract: profile_contract_sha256,
            promotion_trust_bundle: promotion_trust_bundle_sha256,
            promotion_public_key: promotion_public_key_sha256,
            cleanup_receipt: cleanup_receipt_sha256,
        })
    }

    /// Returns the broker host/profile attestation digest.
    #[must_use]
    pub const fn broker_attestation_sha256(self) -> Sha256Digest {
        self.broker_attestation
    }

    /// Returns the broker's ordered ACL/file-ID/volume input attestation digest.
    #[must_use]
    pub const fn host_input_attestation_sha256(self) -> Sha256Digest {
        self.host_input_attestation
    }

    /// Returns the image/tool-probe attestation digest.
    #[must_use]
    pub const fn image_attestation_sha256(self) -> Sha256Digest {
        self.image_attestation
    }

    /// Returns the disabled-network attestation digest.
    #[must_use]
    pub const fn network_attestation_sha256(self) -> Sha256Digest {
        self.network_attestation
    }

    /// Returns the control-authority admission attestation digest.
    #[must_use]
    pub const fn authority_attestation_sha256(self) -> Sha256Digest {
        self.authority_attestation
    }

    /// Returns the broker-minted exact launch/profile contract digest.
    #[must_use]
    pub const fn profile_contract_sha256(self) -> Sha256Digest {
        self.profile_contract
    }

    /// Returns the digest of the broker/control-owned versioned trust bundle.
    #[must_use]
    pub const fn promotion_trust_bundle_sha256(self) -> Sha256Digest {
        self.promotion_trust_bundle
    }

    /// Returns the exact approved promotion key digest selected by the broker.
    #[must_use]
    pub const fn promotion_public_key_sha256(self) -> Sha256Digest {
        self.promotion_public_key
    }

    /// Returns the precommitted durable cleanup/tombstone receipt digest.
    #[must_use]
    pub const fn cleanup_receipt_sha256(self) -> Sha256Digest {
        self.cleanup_receipt
    }
}

/// Unvalidated receipt returned from the trusted active-admission port.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsEnrollmentAdmissionReceipt {
    schema_version: u16,
    issuer_key_id: String,
    nonce: Sha256Digest,
    handle: WindowsEnrollmentAdmissionHandle,
    binding: WindowsEnrollmentAdmissionBinding,
    evidence: WindowsEnrollmentAdmissionEvidence,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    authenticator: Vec<u8>,
}

#[cfg(test)]
impl WindowsEnrollmentAdmissionReceipt {
    #[cfg_attr(not(test), allow(dead_code))]
    #[allow(clippy::too_many_arguments, clippy::large_types_passed_by_value)]
    pub(crate) fn new(
        issuer_key_id: impl Into<String>,
        nonce: Sha256Digest,
        handle: WindowsEnrollmentAdmissionHandle,
        binding: WindowsEnrollmentAdmissionBinding,
        evidence: WindowsEnrollmentAdmissionEvidence,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
        authenticator: Vec<u8>,
    ) -> Result<Self, WindowsEnrollmentAdmissionError> {
        let issuer_key_id = issuer_key_id.into();
        if !valid_id(&issuer_key_id)
            || zero_digest(nonce)
            || !(MIN_RECEIPT_AUTHENTICATOR_BYTES..=MAX_RECEIPT_AUTHENTICATOR_BYTES)
                .contains(&authenticator.len())
        {
            return Err(WindowsEnrollmentAdmissionError::InvalidReceipt);
        }
        Ok(Self {
            schema_version: WINDOWS_ENROLLMENT_RECEIPT_SCHEMA_VERSION,
            issuer_key_id,
            nonce,
            handle,
            binding,
            evidence,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            authenticator,
        })
    }

    /// Returns the opaque broker-custody handle retained by this receipt.
    #[must_use]
    pub const fn handle(&self) -> &WindowsEnrollmentAdmissionHandle {
        &self.handle
    }

    /// Returns the complete admission binding authenticated by the authority.
    #[must_use]
    pub const fn binding(&self) -> &WindowsEnrollmentAdmissionBinding {
        &self.binding
    }

    /// Returns every authenticated evidence digest named by the receipt.
    #[must_use]
    pub const fn evidence(&self) -> WindowsEnrollmentAdmissionEvidence {
        self.evidence
    }

    /// Returns the authority-controlled receipt issue time.
    #[must_use]
    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }

    /// Returns the authority-controlled receipt expiry time.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    /// Returns the opaque broker receipt issuer/key identifier.
    #[must_use]
    pub fn issuer_key_id(&self) -> &str {
        &self.issuer_key_id
    }

    /// Returns the broker-minted one-use receipt nonce.
    #[must_use]
    pub const fn nonce(&self) -> Sha256Digest {
        self.nonce
    }

    /// Validates current bindings and freshness, then exposes enrollment authority.
    ///
    /// # Errors
    ///
    /// Rejects mismatched, malformed, future-issued, expired, or overlong receipts.
    pub fn validate(
        self,
        request: &WindowsEnrollmentAdmissionRequest,
        now_unix_seconds: u64,
        authority: &dyn WindowsEnrollmentAdmissionPort,
    ) -> Result<ValidatedWindowsEnrollmentAdmission, WindowsEnrollmentAdmissionError> {
        if self.schema_version != WINDOWS_ENROLLMENT_RECEIPT_SCHEMA_VERSION
            || !valid_id(&self.issuer_key_id)
            || zero_digest(self.nonce)
            || !(MIN_RECEIPT_AUTHENTICATOR_BYTES..=MAX_RECEIPT_AUTHENTICATOR_BYTES)
                .contains(&self.authenticator.len())
            || self.binding != request.binding
            || canonical_digest(&self.binding.capabilities)? != self.binding.capabilities_sha256
            || self.binding.capabilities.validate().is_err()
            || !valid_host_inputs(&self.binding.host_inputs)
            || !valid_binding_authority(&self.binding)
            || !valid_evidence(&self.evidence)
        {
            return Err(WindowsEnrollmentAdmissionError::Mismatch);
        }
        if self.issued_at_unix_seconds > now_unix_seconds {
            return Err(WindowsEnrollmentAdmissionError::Clock);
        }
        let lifetime = self
            .expires_at_unix_seconds
            .checked_sub(self.issued_at_unix_seconds)
            .filter(|lifetime| *lifetime > 0 && *lifetime <= MAX_RECEIPT_LIFETIME_SECONDS)
            .ok_or(WindowsEnrollmentAdmissionError::InvalidReceipt)?;
        debug_assert!(lifetime > 0);
        if now_unix_seconds >= self.expires_at_unix_seconds {
            return Err(WindowsEnrollmentAdmissionError::Expired);
        }
        let now_millis = now_unix_seconds
            .checked_mul(1_000)
            .ok_or(WindowsEnrollmentAdmissionError::Clock)?;
        if self.binding.promotion_issued_at_unix_millis > now_millis {
            return Err(WindowsEnrollmentAdmissionError::Clock);
        }
        if now_millis >= self.binding.promotion_expires_at_unix_millis {
            return Err(WindowsEnrollmentAdmissionError::Expired);
        }
        let payload = self.signed_payload()?;
        authority.verify_receipt_authenticator(
            &self.issuer_key_id,
            &payload,
            &self.authenticator,
        )?;
        let receipt_sha256 = receipt_digest(&payload, &self.authenticator);
        Ok(ValidatedWindowsEnrollmentAdmission {
            receipt: self,
            receipt_sha256,
        })
    }

    fn signed_payload(&self) -> Result<Vec<u8>, WindowsEnrollmentAdmissionError> {
        let document = WindowsEnrollmentReceiptSignedPayload {
            schema_version: self.schema_version,
            issuer_key_id: &self.issuer_key_id,
            nonce: self.nonce,
            handle: self.handle.as_str(),
            binding_sha256: binding_digest(&self.binding)?,
            evidence: self.evidence,
            issued_at_unix_seconds: self.issued_at_unix_seconds,
            expires_at_unix_seconds: self.expires_at_unix_seconds,
        };
        serde_json::to_vec(&document).map_err(|_| WindowsEnrollmentAdmissionError::InvalidReceipt)
    }
}

#[cfg(test)]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsEnrollmentReceiptSignedPayload<'a> {
    schema_version: u16,
    issuer_key_id: &'a str,
    nonce: Sha256Digest,
    handle: &'a str,
    binding_sha256: Sha256Digest,
    evidence: WindowsEnrollmentAdmissionEvidence,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

/// Receipt whose exact binding and freshness have been validated for enrollment.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedWindowsEnrollmentAdmission {
    receipt: WindowsEnrollmentAdmissionReceipt,
    receipt_sha256: Sha256Digest,
}

#[cfg(test)]
impl ValidatedWindowsEnrollmentAdmission {
    /// Rechecks freshness and returns the post-admission registration inventory.
    ///
    /// Call this immediately before every enrollment send or retry; retaining
    /// this value never extends the authority's expiry.
    ///
    /// # Errors
    ///
    /// Rejects a clock earlier than issuance or a receipt at or after expiry.
    pub fn capabilities_at(
        &self,
        now_unix_seconds: u64,
    ) -> Result<&RunnerCapabilities, WindowsEnrollmentAdmissionError> {
        if now_unix_seconds < self.receipt.issued_at_unix_seconds {
            return Err(WindowsEnrollmentAdmissionError::Clock);
        }
        if now_unix_seconds >= self.receipt.expires_at_unix_seconds {
            return Err(WindowsEnrollmentAdmissionError::Expired);
        }
        Ok(&self.receipt.binding.capabilities)
    }

    /// Returns the broker custody handle which must be bound to a staged retry.
    #[must_use]
    pub const fn handle(&self) -> &WindowsEnrollmentAdmissionHandle {
        &self.receipt.handle
    }

    /// Returns the authenticated durable receipt digest for exact retry binding.
    #[must_use]
    pub const fn receipt_sha256(&self) -> Sha256Digest {
        self.receipt_sha256
    }

    /// Returns the receipt expiry checked at each use.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.receipt.expires_at_unix_seconds
    }

    /// Returns every independently authenticated evidence digest.
    #[must_use]
    pub const fn evidence(&self) -> WindowsEnrollmentAdmissionEvidence {
        self.receipt.evidence
    }

    /// Returns the broker-minted profile contract retained for placement grants.
    #[must_use]
    pub const fn profile_contract_sha256(&self) -> Sha256Digest {
        self.receipt.evidence.profile_contract
    }
}

/// Trusted active-probe and opaque-custody boundary implemented by the broker lane.
#[cfg(test)]
pub trait WindowsEnrollmentAdmissionPort: Send + Sync {
    /// Runs fresh broker/image/network admission and durably retains its receipt.
    /// Implementations must invoke [`probe_windows_enrollment_request`] with the
    /// exact provider named by the request before minting authority.
    ///
    /// # Errors
    ///
    /// Fails closed when the authenticated broker or its custody boundary is
    /// unavailable, or when any required admission evidence cannot be proved.
    fn issue(
        &self,
        request: &WindowsEnrollmentAdmissionRequest,
    ) -> Result<WindowsEnrollmentAdmissionReceipt, WindowsEnrollmentAdmissionError>;

    /// Reloads and reauthenticates the exact receipt named by a staged handle.
    ///
    /// # Errors
    ///
    /// Fails closed when custody is absent or the retained receipt does not
    /// authenticate the current request exactly.
    fn resume(
        &self,
        handle: &WindowsEnrollmentAdmissionHandle,
        request: &WindowsEnrollmentAdmissionRequest,
    ) -> Result<WindowsEnrollmentAdmissionReceipt, WindowsEnrollmentAdmissionError>;

    /// Verifies the receipt's broker signature or MAC through the canonical
    /// authenticated broker trust root. Runner configuration never supplies
    /// issuer keys.
    fn verify_receipt_authenticator(
        &self,
        issuer_key_id: &str,
        signed_payload: &[u8],
        authenticator: &[u8],
    ) -> Result<(), WindowsEnrollmentAdmissionError>;

    /// Completes broker custody only after enrollment credentials are durable.
    /// The broker must bind both values, prohibit handle reuse, and retain a
    /// tombstone so repeating the exact completion after a crash succeeds.
    ///
    /// # Errors
    ///
    /// Fails closed when the handle/digest pair differs or broker cleanup is
    /// not durable. An exact already-completed pair returns success.
    fn complete(
        &self,
        admission: &ValidatedWindowsEnrollmentAdmission,
    ) -> Result<(), WindowsEnrollmentAdmissionError>;
}

/// Reads a trustworthy wall clock for receipt validation.
///
/// # Errors
///
/// Fails closed if the clock is before the Unix epoch or does not fit `u64`.
#[cfg(test)]
pub fn current_unix_seconds() -> Result<u64, WindowsEnrollmentAdmissionError> {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| WindowsEnrollmentAdmissionError::Clock)
}

/// Sanitized pre-enrollment Windows admission failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WindowsEnrollmentAdmissionError {
    /// The requested configuration or backend identity is invalid.
    #[error("Windows enrollment admission request is invalid")]
    InvalidRequest,
    /// The trusted broker/custody boundary is unavailable.
    #[error("Windows enrollment admission is unavailable")]
    Unavailable,
    /// The active lifecycle or exact tool probe did not prove the contract.
    #[error("Windows enrollment admission probe failed")]
    ProbeFailed,
    /// A returned or resumed receipt violates the closed contract.
    #[error("Windows enrollment admission receipt is invalid")]
    InvalidReceipt,
    /// The receipt does not match the current runner/profile/image/capabilities.
    #[error("Windows enrollment admission receipt does not match")]
    Mismatch,
    /// The receipt expired before it could authorize enrollment.
    #[error("Windows enrollment admission receipt expired")]
    Expired,
    /// The wall clock could not safely validate receipt time.
    #[error("Windows enrollment admission clock is invalid")]
    Clock,
}

#[cfg(test)]
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value.is_ascii()
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_backend_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn zero_digest(digest: Sha256Digest) -> bool {
    digest.as_bytes().iter().all(|byte| *byte == 0)
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

const fn protocol_host_input_kind(kind: WindowsHostInputKind) -> WindowsAdmissionHostInputKind {
    match kind {
        WindowsHostInputKind::Configuration => WindowsAdmissionHostInputKind::Configuration,
        WindowsHostInputKind::BackendExecutable => WindowsAdmissionHostInputKind::BackendExecutable,
        WindowsHostInputKind::ImageManifest => WindowsAdmissionHostInputKind::ImageManifest,
        WindowsHostInputKind::ImageLock => WindowsAdmissionHostInputKind::ImageLock,
        WindowsHostInputKind::Provenance => WindowsAdmissionHostInputKind::Provenance,
        WindowsHostInputKind::Sbom => WindowsAdmissionHostInputKind::Sbom,
        WindowsHostInputKind::PatchReport => WindowsAdmissionHostInputKind::PatchReport,
        WindowsHostInputKind::Revocations => WindowsAdmissionHostInputKind::Revocations,
        WindowsHostInputKind::PromotionEnvelope => WindowsAdmissionHostInputKind::PromotionEnvelope,
    }
}

fn protocol_resource_limits(
    limits: ResourceLimits,
) -> Result<WindowsAdmissionResourceLimits, WindowsEnrollmentAdmissionError> {
    WindowsAdmissionResourceLimits::new(limits.memory_bytes(), limits.cpu_millis(), limits.pids())
        .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)
}

#[cfg(test)]
fn valid_evidence(evidence: &WindowsEnrollmentAdmissionEvidence) -> bool {
    [
        evidence.broker_attestation,
        evidence.host_input_attestation,
        evidence.image_attestation,
        evidence.network_attestation,
        evidence.authority_attestation,
        evidence.profile_contract,
        evidence.promotion_trust_bundle,
        evidence.promotion_public_key,
        evidence.cleanup_receipt,
    ]
    .into_iter()
    .all(|digest| !zero_digest(digest))
}

#[cfg(test)]
fn valid_binding_authority(binding: &WindowsEnrollmentAdmissionBinding) -> bool {
    super::windows_image::WindowsPromotionTrustBundleId::new(
        binding.promotion_trust_bundle_id.clone(),
    )
    .is_ok()
        && valid_id(&binding.promotion_key_id)
        && !zero_digest(binding.promotion_payload_sha256)
        && !zero_digest(binding.promotion_envelope_sha256)
        && binding.promotion_serial > 0
        && binding.revocation_generation > 0
        && binding.promotion_issued_at_unix_millis > 0
        && binding.promotion_expires_at_unix_millis > binding.promotion_issued_at_unix_millis
}

fn canonical_digest<T: Serialize>(
    value: &T,
) -> Result<Sha256Digest, WindowsEnrollmentAdmissionError> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?;
    Ok(Sha256Digest::from_bytes(Sha256::digest(bytes).into()))
}

#[cfg(test)]
#[derive(Serialize)]
struct WindowsEnrollmentBindingSignatureDocument<'a> {
    schema_version: u16,
    runner_id: RunnerId,
    control_endpoint: &'a str,
    enrollment_operation_id: Uuid,
    enrollment_server_origin: &'a str,
    runner_name: &'a str,
    enrollment_token_sha256: Sha256Digest,
    csr_sha256: Sha256Digest,
    backend_id: &'a str,
    sandbox_provider_id: &'a str,
    backend_executable: &'a str,
    backend_executable_sha256: Sha256Digest,
    backend_operation_timeout_millis: u64,
    host_inputs: &'a [WindowsHostInputDescriptor],
    profile: &'a EnvironmentProfile,
    image: &'a str,
    environment_sha256: Sha256Digest,
    probe_contract_schema_version: u16,
    probe_contract_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    lock_sha256: Sha256Digest,
    promotion_trust_bundle_id: &'a str,
    promotion_key_id: &'a str,
    promotion_payload_sha256: Sha256Digest,
    promotion_envelope_sha256: Sha256Digest,
    promotion_serial: u64,
    revocation_generation: u64,
    promotion_issued_at_unix_millis: u64,
    promotion_expires_at_unix_millis: u64,
    capabilities_sha256: Sha256Digest,
}

#[cfg(test)]
fn binding_digest(
    binding: &WindowsEnrollmentAdmissionBinding,
) -> Result<Sha256Digest, WindowsEnrollmentAdmissionError> {
    let executable = binding
        .backend_executable
        .to_str()
        .ok_or(WindowsEnrollmentAdmissionError::InvalidRequest)?;
    let timeout = u64::try_from(binding.backend_operation_timeout.as_millis())
        .map_err(|_| WindowsEnrollmentAdmissionError::InvalidRequest)?;
    canonical_digest(&WindowsEnrollmentBindingSignatureDocument {
        schema_version: 1,
        runner_id: binding.runner_id,
        control_endpoint: &binding.control_endpoint,
        enrollment_operation_id: binding.intent.operation_id,
        enrollment_server_origin: &binding.intent.server_origin,
        runner_name: &binding.intent.runner_name,
        enrollment_token_sha256: binding.intent.enrollment_token_sha256,
        csr_sha256: binding.intent.csr_sha256,
        backend_id: &binding.backend_id,
        sandbox_provider_id: &binding.sandbox_provider_id,
        backend_executable: executable,
        backend_executable_sha256: binding.backend_executable_sha256,
        backend_operation_timeout_millis: timeout,
        host_inputs: &binding.host_inputs,
        profile: &binding.profile,
        image: &binding.image,
        environment_sha256: sandbox_environment_digest(&binding.environment)?,
        probe_contract_schema_version: binding.probe_policy.contract_schema_version,
        probe_contract_sha256: binding.probe_policy.contract_sha256,
        manifest_sha256: binding.manifest_sha256,
        lock_sha256: binding.lock_sha256,
        promotion_trust_bundle_id: &binding.promotion_trust_bundle_id,
        promotion_key_id: &binding.promotion_key_id,
        promotion_payload_sha256: binding.promotion_payload_sha256,
        promotion_envelope_sha256: binding.promotion_envelope_sha256,
        promotion_serial: binding.promotion_serial,
        revocation_generation: binding.revocation_generation,
        promotion_issued_at_unix_millis: binding.promotion_issued_at_unix_millis,
        promotion_expires_at_unix_millis: binding.promotion_expires_at_unix_millis,
        capabilities_sha256: binding.capabilities_sha256,
    })
}

#[cfg(test)]
fn sandbox_environment_digest(
    environment: &SandboxEnvironment,
) -> Result<Sha256Digest, WindowsEnrollmentAdmissionError> {
    let SandboxLaunch::WindowsHyperVContainer { image, keepalive } = environment.launch() else {
        return Err(WindowsEnrollmentAdmissionError::InvalidRequest);
    };
    let mut digest = Sha256::new();
    digest.update(b"automata.windows-enrollment-environment.v1\0");
    update_digest_string(&mut digest, environment.attestation().id().as_str());
    digest.update(environment.attestation().digest().as_bytes());
    update_digest_string(&mut digest, image.reference());
    digest.update(image.digest().as_bytes());
    update_digest_string(&mut digest, keepalive.program().as_str());
    digest.update((keepalive.arguments().len() as u64).to_be_bytes());
    for argument in keepalive.arguments() {
        update_digest_string(&mut digest, argument);
    }
    update_digest_string(&mut digest, environment.workspace().as_str());
    let values = environment.default_environment().values();
    digest.update((values.len() as u64).to_be_bytes());
    for variable in values {
        update_digest_string(&mut digest, variable.name().as_str());
        update_digest_string(&mut digest, variable.value().expose());
        digest.update([u8::from(variable.is_secret())]);
    }
    Ok(Sha256Digest::from_bytes(digest.finalize().into()))
}

#[cfg(test)]
fn update_digest_string(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

#[cfg(test)]
fn receipt_digest(payload: &[u8], authenticator: &[u8]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(b"automata.windows-enrollment-receipt.v1\0");
    digest.update((payload.len() as u64).to_be_bytes());
    digest.update(payload);
    digest.update((authenticator.len() as u64).to_be_bytes());
    digest.update(authenticator);
    Sha256Digest::from_bytes(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use automata_ci_core::{
        Architecture, EnvironmentProfileId, OperatingSystem, RunnerFeature, RunnerPlatform,
    };

    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn test_host_inputs() -> Vec<WindowsHostInputDescriptor> {
        WINDOWS_HOST_INPUT_KINDS
            .into_iter()
            .enumerate()
            .map(|(index, kind)| WindowsHostInputDescriptor {
                kind,
                absolute_path: PathBuf::from(format!(r"C:\trusted\input-{index}.bin")),
                expected_sha256: Sha256Digest::from_bytes(
                    [u8::try_from(index).expect("bounded input index") + 20; 32],
                ),
            })
            .collect()
    }

    fn test_probe_policy(resources: ResourceLimits) -> WindowsEnrollmentProbePolicy {
        let capacity = automata_ci_core::ResourceCapacity::new(
            resources.cpu_millis(),
            resources.memory_bytes(),
            0,
            0,
        );
        WindowsEnrollmentProbePolicy {
            contract_schema_version: WINDOWS_PROFILE_PROBE_SCHEMA_VERSION,
            contract_sha256: windows_profile_probe_contract_sha256(),
            resources,
            allocation: JobResourceAllocation::new(capacity, capacity)
                .expect("resource allocation"),
            network: NetworkPolicy::Disabled,
            root_filesystem: RootFilesystemPolicy::Writable,
            privilege: SandboxPrivilegePolicy::Unprivileged,
            pwsh: automata_ci_execution::TargetPath::windows(
                r"C:\Program Files\PowerShell\7\pwsh.exe",
            )
            .expect("pwsh"),
            powershell: automata_ci_execution::TargetPath::windows(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            )
            .expect("PowerShell"),
            cmd: automata_ci_execution::TargetPath::windows(r"C:\Windows\System32\cmd.exe")
                .expect("cmd"),
            python: None,
            tar: automata_ci_execution::TargetPath::windows(r"C:\Windows\System32\tar.exe")
                .expect("tar"),
            sha256: automata_ci_execution::TargetPath::windows(
                r"C:\automata\bin\automata-sha256.exe",
            )
            .expect("hash"),
            node12: None,
            node16: None,
            node20: None,
            node24: Some(
                automata_ci_execution::TargetPath::windows(
                    r"C:\automata\externals\node24\node.exe",
                )
                .expect("Node 24"),
            ),
        }
    }

    fn request(
        features: impl IntoIterator<Item = RunnerFeature>,
    ) -> WindowsEnrollmentAdmissionRequest {
        let runner_id = RunnerId::new();
        let profile = EnvironmentProfile::new(
            EnvironmentProfileId::new("automata.test/windows-2025").expect("profile id"),
            Sha256Digest::from_bytes([2; 32]),
        );
        let capabilities = RunnerCapabilities::new(
            runner_id,
            RunnerPlatform::new(OperatingSystem::Windows, Architecture::X86_64),
        )
        .with_features(features)
        .with_environment_profiles([profile.clone()]);
        let capabilities_sha256 = canonical_digest(&capabilities).expect("capability digest");
        let environment = SandboxEnvironment::windows_hyperv_container(
            profile.clone(),
            automata_ci_execution::ImmutableImage::new(format!(
                "registry.example/image@sha256:{}",
                "1".repeat(64)
            ))
            .expect("immutable image"),
            automata_ci_execution::ExecutionArgv::new(
                automata_ci_execution::TargetPath::windows(r"C:\guest\agent.exe").expect("guest"),
                vec!["keepalive".to_owned()],
            )
            .expect("keepalive"),
            automata_ci_execution::TargetPath::windows(r"C:\__w").expect("workspace"),
            automata_ci_execution::ExecutionEnvironment::empty(),
        )
        .expect("environment");
        let resources =
            ResourceLimits::new(4 * 1_024 * 1_024 * 1_024, 2_000, 256).expect("resource limits");
        WindowsEnrollmentAdmissionRequest {
            binding: WindowsEnrollmentAdmissionBinding {
                runner_id,
                control_endpoint: "https://control.example.test/".to_owned(),
                intent: WindowsEnrollmentIntent::new(
                    Uuid::from_u128(1),
                    &reqwest::Url::parse("https://enroll.example.test/")
                        .expect("enrollment origin"),
                    "windows-runner",
                    Sha256Digest::from_bytes([10; 32]),
                    Sha256Digest::from_bytes([11; 32]),
                )
                .expect("enrollment intent"),
                backend_id: "a".repeat(64),
                sandbox_provider_id: WINDOWS_HYPERV_PROVIDER_ID.to_owned(),
                backend_executable: PathBuf::from(r"C:\automata\broker-client.exe"),
                backend_executable_sha256: Sha256Digest::from_bytes([12; 32]),
                backend_operation_timeout: Duration::from_mins(2),
                host_inputs: test_host_inputs(),
                profile,
                image: format!("registry.example/image@sha256:{}", "1".repeat(64)),
                environment,
                probe_policy: test_probe_policy(resources),
                manifest_sha256: Sha256Digest::from_bytes([3; 32]),
                lock_sha256: Sha256Digest::from_bytes([4; 32]),
                promotion_trust_bundle_id: "windows-promotion.test.v1".to_owned(),
                promotion_key_id: "promotion.test/v1".to_owned(),
                promotion_payload_sha256: Sha256Digest::from_bytes([5; 32]),
                promotion_envelope_sha256: Sha256Digest::from_bytes([14; 32]),
                promotion_serial: 7,
                revocation_generation: 4,
                promotion_issued_at_unix_millis: NOW * 1_000 - 1_000,
                promotion_expires_at_unix_millis: (NOW + 300) * 1_000,
                capabilities,
                capabilities_sha256,
            },
        }
    }

    fn receipt(request: &WindowsEnrollmentAdmissionRequest) -> WindowsEnrollmentAdmissionReceipt {
        let mut receipt = WindowsEnrollmentAdmissionReceipt::new(
            "broker-receipt.test.v1",
            Sha256Digest::from_bytes([15; 32]),
            WindowsEnrollmentAdmissionHandle::new("receipt-1").expect("handle"),
            request.binding.clone(),
            WindowsEnrollmentAdmissionEvidence::new(
                Sha256Digest::from_bytes([6; 32]),
                Sha256Digest::from_bytes([7; 32]),
                Sha256Digest::from_bytes([8; 32]),
                Sha256Digest::from_bytes([9; 32]),
                Sha256Digest::from_bytes([10; 32]),
                Sha256Digest::from_bytes([11; 32]),
                Sha256Digest::from_bytes([12; 32]),
                Sha256Digest::from_bytes([13; 32]),
                Sha256Digest::from_bytes([14; 32]),
            )
            .expect("evidence"),
            NOW,
            NOW + 300,
            vec![0; 32],
        )
        .expect("receipt");
        receipt.authenticator = test_authenticator(&receipt.signed_payload().expect("payload"));
        receipt
    }

    fn test_authenticator(payload: &[u8]) -> Vec<u8> {
        let mut digest = Sha256::new();
        digest.update(b"test-broker-receipt-key\0");
        digest.update(payload);
        digest.finalize().to_vec()
    }

    #[derive(Debug)]
    struct RestartingPort {
        state: Mutex<RestartingPortState>,
    }

    #[derive(Debug, Default)]
    struct RestartingPortState {
        retained: Option<WindowsEnrollmentAdmissionReceipt>,
        completed: Option<(WindowsEnrollmentAdmissionHandle, Sha256Digest, Sha256Digest)>,
    }

    impl WindowsEnrollmentAdmissionPort for RestartingPort {
        fn issue(
            &self,
            request: &WindowsEnrollmentAdmissionRequest,
        ) -> Result<WindowsEnrollmentAdmissionReceipt, WindowsEnrollmentAdmissionError> {
            let receipt = receipt(request);
            let mut state = self.state.lock().expect("receipt lock");
            if state.retained.is_some() || state.completed.is_some() {
                return Err(WindowsEnrollmentAdmissionError::Mismatch);
            }
            state.retained = Some(receipt.clone());
            Ok(receipt)
        }

        fn resume(
            &self,
            handle: &WindowsEnrollmentAdmissionHandle,
            _request: &WindowsEnrollmentAdmissionRequest,
        ) -> Result<WindowsEnrollmentAdmissionReceipt, WindowsEnrollmentAdmissionError> {
            self.state
                .lock()
                .expect("receipt lock")
                .retained
                .clone()
                .filter(|receipt| receipt.handle == *handle)
                .ok_or(WindowsEnrollmentAdmissionError::Unavailable)
        }

        fn verify_receipt_authenticator(
            &self,
            issuer_key_id: &str,
            signed_payload: &[u8],
            authenticator: &[u8],
        ) -> Result<(), WindowsEnrollmentAdmissionError> {
            if issuer_key_id != "broker-receipt.test.v1"
                || authenticator != test_authenticator(signed_payload)
            {
                return Err(WindowsEnrollmentAdmissionError::InvalidReceipt);
            }
            Ok(())
        }

        fn complete(
            &self,
            admission: &ValidatedWindowsEnrollmentAdmission,
        ) -> Result<(), WindowsEnrollmentAdmissionError> {
            let mut state = self.state.lock().expect("receipt lock");
            let completed = (
                admission.handle().clone(),
                admission.receipt_sha256(),
                admission.evidence().cleanup_receipt_sha256(),
            );
            if state.completed.as_ref() == Some(&completed) {
                return Ok(());
            }
            let Some(retained) = state.retained.as_ref() else {
                return Err(WindowsEnrollmentAdmissionError::Unavailable);
            };
            let payload = retained.signed_payload()?;
            if retained.handle != *admission.handle()
                || receipt_digest(&payload, &retained.authenticator) != admission.receipt_sha256()
                || retained.evidence.cleanup_receipt
                    != admission.evidence().cleanup_receipt_sha256()
            {
                return Err(WindowsEnrollmentAdmissionError::Mismatch);
            }
            if state
                .completed
                .as_ref()
                .is_some_and(|prior| prior != &completed)
            {
                return Err(WindowsEnrollmentAdmissionError::Unavailable);
            }
            state.retained = None;
            state.completed = Some(completed);
            Ok(())
        }
    }

    #[test]
    fn restart_reauthenticates_the_same_broker_custody_receipt() {
        let request = request([
            RunnerFeature::SHELL_STEPS,
            RunnerFeature::JAVASCRIPT_ACTIONS,
            RunnerFeature::NODE24_ACTIONS,
        ]);
        let port = RestartingPort {
            state: Mutex::new(RestartingPortState::default()),
        };
        let issued = port
            .issue(&request)
            .expect("issue")
            .validate(&request, NOW, &port)
            .expect("validate issued receipt");
        let resumed = port
            .resume(issued.handle(), &request)
            .expect("resume")
            .validate(&request, NOW + 1, &port)
            .expect("validate resumed receipt");

        assert_eq!(issued.receipt_sha256(), resumed.receipt_sha256());
        assert_eq!(
            issued.capabilities_at(NOW).expect("issued authority"),
            resumed.capabilities_at(NOW + 1).expect("resumed authority")
        );
        assert_eq!(
            resumed.capabilities_at(NOW + 300),
            Err(WindowsEnrollmentAdmissionError::Expired),
            "a previously validated value cannot outlive its receipt"
        );
        port.complete(&resumed).expect("complete custody");
        port.complete(&resumed)
            .expect("exact completion is idempotent after a crash");
        assert_eq!(
            port.resume(resumed.handle(), &request),
            Err(WindowsEnrollmentAdmissionError::Unavailable)
        );
    }

    #[test]
    fn tamper_capability_superset_and_binding_substitution_fail_closed() {
        let request = request([RunnerFeature::SHELL_STEPS]);
        let port = RestartingPort {
            state: Mutex::new(RestartingPortState::default()),
        };
        let mut tampered = receipt(&request);
        tampered.binding.image = format!("registry.example/other@sha256:{}", "a".repeat(64));
        assert_eq!(
            tampered.validate(&request, NOW, &port),
            Err(WindowsEnrollmentAdmissionError::Mismatch)
        );

        let mut superset = receipt(&request);
        superset.binding.capabilities = superset.binding.capabilities.clone().with_features([
            RunnerFeature::SHELL_STEPS,
            RunnerFeature::JAVASCRIPT_ACTIONS,
        ]);
        superset.binding.capabilities_sha256 =
            canonical_digest(&superset.binding.capabilities).expect("superset digest");
        assert_eq!(
            superset.validate(&request, NOW, &port),
            Err(WindowsEnrollmentAdmissionError::Mismatch)
        );

        let mut changed_probe = request.clone();
        changed_probe.binding.probe_policy.node24 = Some(
            automata_ci_execution::TargetPath::windows(r"C:\substituted\node.exe")
                .expect("substituted Node"),
        );
        assert_eq!(
            receipt(&request).validate(&changed_probe, NOW, &port),
            Err(WindowsEnrollmentAdmissionError::Mismatch),
            "a custody receipt must not cross an exact tool-probe policy change"
        );

        let mut changed_probe_contract = request.clone();
        changed_probe_contract.binding.probe_policy.contract_sha256 =
            Sha256Digest::from_bytes([76; 32]);
        assert_eq!(
            receipt(&request).validate(&changed_probe_contract, NOW, &port),
            Err(WindowsEnrollmentAdmissionError::Mismatch),
            "a probe-semantic change invalidates retained custody"
        );

        let mut changed_backend = request.clone();
        changed_backend.binding.backend_executable_sha256 = Sha256Digest::from_bytes([88; 32]);
        assert_eq!(
            receipt(&request).validate(&changed_backend, NOW, &port),
            Err(WindowsEnrollmentAdmissionError::Mismatch),
            "backend executable substitution invalidates retained custody"
        );

        let mut changed_provider = request.clone();
        changed_provider.binding.sandbox_provider_id = "substituted-provider".to_owned();
        assert_eq!(
            receipt(&request).validate(&changed_provider, NOW, &port),
            Err(WindowsEnrollmentAdmissionError::Mismatch),
            "sandbox-provider substitution invalidates retained custody"
        );

        let mut changed_authority = request.clone();
        changed_authority.binding.promotion_trust_bundle_id =
            "windows-promotion.test.v2".to_owned();
        assert_eq!(
            receipt(&request).validate(&changed_authority, NOW, &port),
            Err(WindowsEnrollmentAdmissionError::Mismatch),
            "promotion trust-anchor rotation invalidates retained custody"
        );

        let mut changed_transaction = request.clone();
        changed_transaction.binding.intent.operation_id = Uuid::from_u128(2);
        assert_eq!(
            receipt(&request).validate(&changed_transaction, NOW, &port),
            Err(WindowsEnrollmentAdmissionError::Mismatch),
            "one receipt cannot authorize a second enrollment operation"
        );
    }

    #[test]
    fn enrollment_intent_rejects_unsafe_origins_names_and_placeholder_digests() {
        let valid_origin = reqwest::Url::parse("https://enroll.example.test/").expect("origin");
        assert!(
            WindowsEnrollmentIntent::new(
                Uuid::nil(),
                &valid_origin,
                "runner",
                Sha256Digest::from_bytes([1; 32]),
                Sha256Digest::from_bytes([2; 32]),
            )
            .is_err()
        );
        for origin in [
            "http://enroll.example.test/",
            "https://user@enroll.example.test/",
            "https://enroll.example.test/path",
        ] {
            assert!(
                WindowsEnrollmentIntent::new(
                    Uuid::from_u128(1),
                    &reqwest::Url::parse(origin).expect("test URL"),
                    "runner",
                    Sha256Digest::from_bytes([1; 32]),
                    Sha256Digest::from_bytes([2; 32]),
                )
                .is_err(),
                "unexpectedly accepted {origin}"
            );
        }
        assert!(
            WindowsEnrollmentIntent::new(
                Uuid::from_u128(1),
                &valid_origin,
                " runner ",
                Sha256Digest::from_bytes([1; 32]),
                Sha256Digest::from_bytes([2; 32]),
            )
            .is_err()
        );
        assert!(
            WindowsEnrollmentIntent::new(
                Uuid::from_u128(1),
                &valid_origin,
                "runner",
                Sha256Digest::from_bytes([0; 32]),
                Sha256Digest::from_bytes([2; 32]),
            )
            .is_err()
        );
    }

    #[test]
    fn future_expired_zero_and_overlong_lifetimes_fail_closed() {
        let request = request([RunnerFeature::SHELL_STEPS]);
        let port = RestartingPort {
            state: Mutex::new(RestartingPortState::default()),
        };
        for (issued, expires, now, expected) in [
            (
                NOW + 1,
                NOW + 10,
                NOW,
                WindowsEnrollmentAdmissionError::Clock,
            ),
            (
                NOW,
                NOW,
                NOW,
                WindowsEnrollmentAdmissionError::InvalidReceipt,
            ),
            (
                NOW,
                NOW + 1,
                NOW + 1,
                WindowsEnrollmentAdmissionError::Expired,
            ),
            (
                NOW,
                NOW + MAX_RECEIPT_LIFETIME_SECONDS + 1,
                NOW,
                WindowsEnrollmentAdmissionError::InvalidReceipt,
            ),
        ] {
            let mut receipt = receipt(&request);
            receipt.issued_at_unix_seconds = issued;
            receipt.expires_at_unix_seconds = expires;
            assert_eq!(receipt.validate(&request, now, &port), Err(expected));
        }
    }

    #[test]
    fn forged_nonzero_authenticator_nonce_and_cleanup_binding_fail_closed() {
        let request = request([RunnerFeature::SHELL_STEPS]);
        let port = RestartingPort {
            state: Mutex::new(RestartingPortState::default()),
        };

        let mut forged = receipt(&request);
        forged.authenticator = vec![77; 32];
        assert_eq!(
            forged.validate(&request, NOW, &port),
            Err(WindowsEnrollmentAdmissionError::InvalidReceipt)
        );

        let mut nonce = receipt(&request);
        nonce.nonce = Sha256Digest::from_bytes([88; 32]);
        assert_eq!(
            nonce.validate(&request, NOW, &port),
            Err(WindowsEnrollmentAdmissionError::InvalidReceipt)
        );

        let mut cleanup = receipt(&request);
        cleanup.evidence.cleanup_receipt = Sha256Digest::from_bytes([99; 32]);
        assert_eq!(
            cleanup.validate(&request, NOW, &port),
            Err(WindowsEnrollmentAdmissionError::InvalidReceipt)
        );
    }
}
