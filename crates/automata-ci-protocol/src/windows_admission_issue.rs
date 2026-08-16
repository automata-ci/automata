//! Canonical, non-authoritative Windows runner admission issue request.
//!
//! The runner may propose this contract, but it conveys no capability
//! authority. The privileged broker must independently reopen and attest every
//! host input, verify the promotion through its own trust bundle and durable
//! high-water ledger, reproduce the live probe, and sign the resulting
//! [`crate::WindowsRunnerAdmissionEnvelope`].

use std::collections::BTreeSet;

use automata_ci_core::{
    EnvironmentProfile, JobResourceAllocation, OperatingSystem, RunnerCapabilities, RunnerFeature,
    Sha256Digest, windows_action_archive_policy_sha256,
};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    WINDOWS_RUNNER_ADMISSION_PROVIDER_ID, WindowsAdmissionImage,
    WindowsEnrollmentTransactionBinding,
};

/// Schema version of the broker-verifiable issue request.
pub const WINDOWS_RUNNER_ADMISSION_ISSUE_SCHEMA_VERSION: u16 = 2;

const REQUEST_DIGEST_DOMAIN: &[u8] = b"automata.windows-runner-admission-issue.v2\0";
const MAX_CANONICAL_REQUEST_BYTES: usize = 512 * 1024;
const MAX_HOST_PATH_BYTES: usize = 4_096;
const MAX_TARGET_PATH_BYTES: usize = 4_096;
const MAX_ARGUMENTS: usize = 128;
const MAX_ARGV_BYTES: usize = 64 * 1024;
const MAX_ENVIRONMENT_VARIABLES: usize = 256;
const MAX_ENVIRONMENT_BYTES: usize = 1024 * 1024;
const MAX_OPERATION_TIMEOUT_MILLIS: u64 = 5 * 60 * 1_000;
const MIN_MEMORY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MEMORY_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_CPU_MILLIS: u32 = 1_000_000;
const MAX_PIDS: u32 = 1_000_000;

/// Closed ordered set of host files the broker must attest from stable handles.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAdmissionHostInputKind {
    /// Complete runner product configuration.
    Configuration,
    /// Pinned broker client/provider executable.
    BackendExecutable,
    /// Exact Windows image manifest.
    ImageManifest,
    /// Exact Windows image lock.
    ImageLock,
    /// Provenance acceptance record.
    Provenance,
    /// SBOM acceptance record.
    Sbom,
    /// Patch acceptance record.
    PatchReport,
    /// Revocation record.
    Revocations,
    /// Externally signed promotion envelope.
    PromotionEnvelope,
}

const HOST_INPUT_ORDER: [WindowsAdmissionHostInputKind; 9] = [
    WindowsAdmissionHostInputKind::Configuration,
    WindowsAdmissionHostInputKind::BackendExecutable,
    WindowsAdmissionHostInputKind::ImageManifest,
    WindowsAdmissionHostInputKind::ImageLock,
    WindowsAdmissionHostInputKind::Provenance,
    WindowsAdmissionHostInputKind::Sbom,
    WindowsAdmissionHostInputKind::PatchReport,
    WindowsAdmissionHostInputKind::Revocations,
    WindowsAdmissionHostInputKind::PromotionEnvelope,
];

/// One exact path and caller-observed digest requiring broker reattestation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAdmissionHostInput {
    kind: WindowsAdmissionHostInputKind,
    absolute_path: String,
    expected_sha256: Sha256Digest,
}

impl WindowsAdmissionHostInput {
    /// Creates a non-authoritative host-input descriptor.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical local-drive paths and zero placeholder digests.
    pub fn new(
        kind: WindowsAdmissionHostInputKind,
        absolute_path: impl Into<String>,
        expected_sha256: Sha256Digest,
    ) -> Result<Self, WindowsRunnerAdmissionIssueError> {
        let value = Self {
            kind,
            absolute_path: absolute_path.into(),
            expected_sha256,
        };
        if !valid_windows_path(&value.absolute_path) || zero_digest(value.expected_sha256) {
            return Err(WindowsRunnerAdmissionIssueError::InvalidHostInputs);
        }
        Ok(value)
    }

    /// Returns the closed semantic input kind.
    #[must_use]
    pub const fn kind(&self) -> WindowsAdmissionHostInputKind {
        self.kind
    }

    /// Returns the exact drive-qualified host path.
    #[must_use]
    pub fn absolute_path(&self) -> &str {
        &self.absolute_path
    }

    /// Returns the untrusted expected digest the broker must reproduce.
    #[must_use]
    pub const fn expected_sha256(&self) -> Sha256Digest {
        self.expected_sha256
    }
}

/// Exact broker client executable and operation timeout proposed by the runner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAdmissionBackendContract {
    executable_path: String,
    executable_sha256: Sha256Digest,
    operation_timeout_millis: u64,
}

impl WindowsAdmissionBackendContract {
    /// Creates the backend process contract.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical paths, placeholder digests, and unbounded timeouts.
    pub fn new(
        executable_path: impl Into<String>,
        executable_sha256: Sha256Digest,
        operation_timeout_millis: u64,
    ) -> Result<Self, WindowsRunnerAdmissionIssueError> {
        let value = Self {
            executable_path: executable_path.into(),
            executable_sha256,
            operation_timeout_millis,
        };
        if !valid_windows_path(&value.executable_path)
            || zero_digest(value.executable_sha256)
            || !(1..=MAX_OPERATION_TIMEOUT_MILLIS).contains(&value.operation_timeout_millis)
        {
            return Err(WindowsRunnerAdmissionIssueError::InvalidBackend);
        }
        Ok(value)
    }

    /// Returns the exact executable path.
    #[must_use]
    pub fn executable_path(&self) -> &str {
        &self.executable_path
    }

    /// Returns the executable digest requiring broker reproduction.
    #[must_use]
    pub const fn executable_sha256(&self) -> Sha256Digest {
        self.executable_sha256
    }

    /// Returns the per-operation timeout.
    #[must_use]
    pub const fn operation_timeout_millis(&self) -> u64 {
        self.operation_timeout_millis
    }
}

/// Literal Windows command line represented without shell reparsing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAdmissionArgv {
    program: String,
    arguments: Vec<String>,
}

impl WindowsAdmissionArgv {
    /// Creates a bounded literal argv.
    ///
    /// # Errors
    ///
    /// Rejects an unsafe program path, control bytes, or excessive arguments.
    pub fn new(
        program: impl Into<String>,
        arguments: Vec<String>,
    ) -> Result<Self, WindowsRunnerAdmissionIssueError> {
        let value = Self {
            program: program.into(),
            arguments,
        };
        if !valid_windows_path(&value.program)
            || value.arguments.len() > MAX_ARGUMENTS
            || value
                .arguments
                .iter()
                .any(|argument| argument.contains('\0'))
            || value
                .arguments
                .iter()
                .try_fold(value.program.len(), |sum, argument| {
                    sum.checked_add(argument.len())
                })
                .is_none_or(|bytes| bytes > MAX_ARGV_BYTES)
        {
            return Err(WindowsRunnerAdmissionIssueError::InvalidLaunch);
        }
        Ok(value)
    }

    /// Returns the absolute executable path.
    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    /// Returns literal arguments in exact order.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }
}

/// One non-secret profile-default environment variable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAdmissionEnvironmentVariable {
    name: String,
    value: String,
}

impl WindowsAdmissionEnvironmentVariable {
    /// Creates one non-secret environment entry.
    ///
    /// # Errors
    ///
    /// Rejects invalid names, NUL values, and excessive fields.
    pub fn new(
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, WindowsRunnerAdmissionIssueError> {
        let value = Self {
            name: name.into(),
            value: value.into(),
        };
        if !valid_environment_name(&value.name)
            || value.value.contains('\0')
            || value.value.len() > MAX_ENVIRONMENT_BYTES
        {
            return Err(WindowsRunnerAdmissionIssueError::InvalidLaunch);
        }
        Ok(value)
    }

    /// Returns the exact variable name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the non-secret profile-default value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// Enforceable CPU, memory, and process ceiling.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAdmissionResourceLimits {
    memory_bytes: u64,
    cpu_millis: u32,
    pids: u32,
}

impl WindowsAdmissionResourceLimits {
    /// Creates bounded non-zero resource limits.
    ///
    /// # Errors
    ///
    /// Rejects values outside the shared execution bounds.
    pub fn new(
        memory_bytes: u64,
        cpu_millis: u32,
        pids: u32,
    ) -> Result<Self, WindowsRunnerAdmissionIssueError> {
        if !(MIN_MEMORY_BYTES..=MAX_MEMORY_BYTES).contains(&memory_bytes)
            || !(1..=MAX_CPU_MILLIS).contains(&cpu_millis)
            || !(1..=MAX_PIDS).contains(&pids)
        {
            return Err(WindowsRunnerAdmissionIssueError::InvalidLaunch);
        }
        Ok(Self {
            memory_bytes,
            cpu_millis,
            pids,
        })
    }

    /// Returns the hard memory limit.
    #[must_use]
    pub const fn memory_bytes(self) -> u64 {
        self.memory_bytes
    }

    /// Returns CPU quota in thousandths of one CPU.
    #[must_use]
    pub const fn cpu_millis(self) -> u32 {
        self.cpu_millis
    }

    /// Returns the hard process ceiling.
    #[must_use]
    pub const fn pids(self) -> u32 {
        self.pids
    }
}

/// Complete immutable Hyper-V-container launch contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct WindowsAdmissionLaunchContract {
    profile: EnvironmentProfile,
    image: WindowsAdmissionImage,
    keepalive: WindowsAdmissionArgv,
    workspace: String,
    default_environment: Vec<WindowsAdmissionEnvironmentVariable>,
    resources: WindowsAdmissionResourceLimits,
    allocation: JobResourceAllocation,
    network_disabled: bool,
    writable_disposable_root: bool,
    unprivileged: bool,
    hyperv_isolation: bool,
    sealed_action_trees: bool,
    sealed_action_policy_sha256: Sha256Digest,
}

impl WindowsAdmissionLaunchContract {
    /// Creates the exact launch material the broker must reproduce.
    ///
    /// # Errors
    ///
    /// Rejects non-Windows, weaker-isolation, secret, duplicate, or
    /// resource-incoherent launch contracts.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::fn_params_excessive_bools)]
    pub fn new(
        profile: EnvironmentProfile,
        image: WindowsAdmissionImage,
        keepalive: WindowsAdmissionArgv,
        workspace: impl Into<String>,
        default_environment: Vec<WindowsAdmissionEnvironmentVariable>,
        resources: WindowsAdmissionResourceLimits,
        allocation: JobResourceAllocation,
        network_disabled: bool,
        writable_disposable_root: bool,
        unprivileged: bool,
        hyperv_isolation: bool,
        sealed_action_trees: bool,
        sealed_action_policy_sha256: Sha256Digest,
    ) -> Result<Self, WindowsRunnerAdmissionIssueError> {
        let value = Self {
            profile,
            image,
            keepalive,
            workspace: workspace.into(),
            default_environment,
            resources,
            allocation,
            network_disabled,
            writable_disposable_root,
            unprivileged,
            hyperv_isolation,
            sealed_action_trees,
            sealed_action_policy_sha256,
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns the exact environment profile.
    #[must_use]
    pub const fn profile(&self) -> &EnvironmentProfile {
        &self.profile
    }

    /// Returns the exact immutable image.
    #[must_use]
    pub const fn image(&self) -> &WindowsAdmissionImage {
        &self.image
    }

    /// Returns the whole-sandbox keepalive argv.
    #[must_use]
    pub const fn keepalive(&self) -> &WindowsAdmissionArgv {
        &self.keepalive
    }

    /// Returns the exact Windows workspace path.
    #[must_use]
    pub fn workspace(&self) -> &str {
        &self.workspace
    }

    /// Returns non-secret default variables in exact order.
    #[must_use]
    pub fn default_environment(&self) -> &[WindowsAdmissionEnvironmentVariable] {
        &self.default_environment
    }

    /// Returns the hard resource limits.
    #[must_use]
    pub const fn resources(&self) -> WindowsAdmissionResourceLimits {
        self.resources
    }

    /// Returns the placement/allocation contract.
    #[must_use]
    pub const fn allocation(&self) -> JobResourceAllocation {
        self.allocation
    }

    /// Reports the required disabled-network policy.
    #[must_use]
    pub const fn network_disabled(&self) -> bool {
        self.network_disabled
    }

    /// Reports the required disposable writable root.
    #[must_use]
    pub const fn writable_disposable_root(&self) -> bool {
        self.writable_disposable_root
    }

    /// Reports the required non-administrator identity.
    #[must_use]
    pub const fn unprivileged(&self) -> bool {
        self.unprivileged
    }

    /// Reports the no-fallback Hyper-V isolation contract.
    #[must_use]
    pub const fn hyperv_isolation(&self) -> bool {
        self.hyperv_isolation
    }

    /// Reports whether pre-sandbox sealed action trees are mandatory.
    #[must_use]
    pub const fn sealed_action_trees(&self) -> bool {
        self.sealed_action_trees
    }

    /// Returns the exact sealed-action namespace policy requested for admission.
    #[must_use]
    pub const fn sealed_action_policy_sha256(&self) -> Sha256Digest {
        self.sealed_action_policy_sha256
    }

    fn validate(&self) -> Result<(), WindowsRunnerAdmissionIssueError> {
        let mut names = BTreeSet::new();
        let environment_bytes =
            self.default_environment
                .iter()
                .try_fold(0_usize, |sum, variable| {
                    if !valid_environment_name(&variable.name)
                        || variable.value.contains('\0')
                        || !names.insert(variable.name.to_ascii_uppercase())
                    {
                        return None;
                    }
                    sum.checked_add(variable.name.len())?
                        .checked_add(variable.value.len())
                });
        let limits = self.allocation.limits();
        if zero_digest(self.profile.digest())
            || !valid_windows_path(&self.workspace)
            || self.default_environment.len() > MAX_ENVIRONMENT_VARIABLES
            || environment_bytes.is_none_or(|bytes| bytes > MAX_ENVIRONMENT_BYTES)
            || self.resources.memory_bytes != limits.memory_bytes()
            || self.resources.cpu_millis != limits.cpu_millis()
            || limits.gpu_count() != 0
            || !self.network_disabled
            || !self.writable_disposable_root
            || !self.unprivileged
            || !self.hyperv_isolation
            || self.sealed_action_policy_sha256 != windows_action_archive_policy_sha256()
        {
            return Err(WindowsRunnerAdmissionIssueError::InvalidLaunch);
        }
        WindowsAdmissionArgv::new(
            self.keepalive.program.clone(),
            self.keepalive.arguments.clone(),
        )?;
        Ok(())
    }
}

/// Exact shared probe semantics and pinned tool paths.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAdmissionProbeContract {
    schema_version: u16,
    contract_sha256: Sha256Digest,
    resources: WindowsAdmissionResourceLimits,
    allocation: JobResourceAllocation,
    network_disabled: bool,
    writable_disposable_root: bool,
    unprivileged: bool,
    pwsh: String,
    powershell: String,
    cmd: String,
    python: Option<String>,
    tar: String,
    sha256: String,
    node12: Option<String>,
    node16: Option<String>,
    node20: Option<String>,
    node24: Option<String>,
}

impl WindowsAdmissionProbeContract {
    /// Creates a versioned exact probe request.
    ///
    /// # Errors
    ///
    /// Rejects placeholders, weaker policies, and unsafe tool paths.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema_version: u16,
        contract_sha256: Sha256Digest,
        resources: WindowsAdmissionResourceLimits,
        allocation: JobResourceAllocation,
        network_disabled: bool,
        writable_disposable_root: bool,
        unprivileged: bool,
        pwsh: impl Into<String>,
        powershell: impl Into<String>,
        cmd: impl Into<String>,
        python: Option<String>,
        tar: impl Into<String>,
        sha256: impl Into<String>,
        node12: Option<String>,
        node16: Option<String>,
        node20: Option<String>,
        node24: Option<String>,
    ) -> Result<Self, WindowsRunnerAdmissionIssueError> {
        let value = Self {
            schema_version,
            contract_sha256,
            resources,
            allocation,
            network_disabled,
            writable_disposable_root,
            unprivileged,
            pwsh: pwsh.into(),
            powershell: powershell.into(),
            cmd: cmd.into(),
            python,
            tar: tar.into(),
            sha256: sha256.into(),
            node12,
            node16,
            node20,
            node24,
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns the shared probe schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the digest of exact argv/scripts/output semantics.
    #[must_use]
    pub const fn contract_sha256(&self) -> Sha256Digest {
        self.contract_sha256
    }

    /// Returns the hard resource limits.
    #[must_use]
    pub const fn resources(&self) -> WindowsAdmissionResourceLimits {
        self.resources
    }

    /// Returns the exact placement allocation.
    #[must_use]
    pub const fn allocation(&self) -> JobResourceAllocation {
        self.allocation
    }

    /// Returns required tool paths as `(name, optional path)` tuples.
    #[must_use]
    pub fn tool_paths(&self) -> [(&'static str, Option<&str>); 10] {
        [
            ("pwsh", Some(&self.pwsh)),
            ("powershell", Some(&self.powershell)),
            ("cmd", Some(&self.cmd)),
            ("python", self.python.as_deref()),
            ("tar", Some(&self.tar)),
            ("sha256", Some(&self.sha256)),
            ("node12", self.node12.as_deref()),
            ("node16", self.node16.as_deref()),
            ("node20", self.node20.as_deref()),
            ("node24", self.node24.as_deref()),
        ]
    }

    fn validate(&self) -> Result<(), WindowsRunnerAdmissionIssueError> {
        if self.schema_version == 0
            || zero_digest(self.contract_sha256)
            || !self.network_disabled
            || !self.writable_disposable_root
            || !self.unprivileged
            || self
                .tool_paths()
                .into_iter()
                .filter_map(|(_, path)| path)
                .any(|path| !valid_windows_path(path))
        {
            return Err(WindowsRunnerAdmissionIssueError::InvalidProbe);
        }
        Ok(())
    }
}

/// External promotion input the broker must reopen and verify itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAdmissionPromotionRequest {
    envelope_path: String,
    trust_bundle_id: String,
    key_id: String,
    manifest_sha256: Sha256Digest,
    lock_sha256: Sha256Digest,
}

impl WindowsAdmissionPromotionRequest {
    /// Creates a non-authoritative promotion request.
    ///
    /// # Errors
    ///
    /// Rejects unsafe paths, invalid identifiers, and placeholder digests.
    pub fn new(
        envelope_path: impl Into<String>,
        trust_bundle_id: impl Into<String>,
        key_id: impl Into<String>,
        manifest_sha256: Sha256Digest,
        lock_sha256: Sha256Digest,
    ) -> Result<Self, WindowsRunnerAdmissionIssueError> {
        let value = Self {
            envelope_path: envelope_path.into(),
            trust_bundle_id: trust_bundle_id.into(),
            key_id: key_id.into(),
            manifest_sha256,
            lock_sha256,
        };
        if !valid_windows_path(&value.envelope_path)
            || !valid_trust_bundle_id(&value.trust_bundle_id)
            || !valid_id(&value.key_id)
            || zero_digest(value.manifest_sha256)
            || zero_digest(value.lock_sha256)
        {
            return Err(WindowsRunnerAdmissionIssueError::InvalidPromotion);
        }
        Ok(value)
    }

    /// Returns the exact promotion envelope path.
    #[must_use]
    pub fn envelope_path(&self) -> &str {
        &self.envelope_path
    }

    /// Returns the broker-owned trust bundle identity.
    #[must_use]
    pub fn trust_bundle_id(&self) -> &str {
        &self.trust_bundle_id
    }

    /// Returns the requested key identity within the bundle.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the caller-observed manifest digest.
    #[must_use]
    pub const fn manifest_sha256(&self) -> Sha256Digest {
        self.manifest_sha256
    }

    /// Returns the caller-observed lock digest.
    #[must_use]
    pub const fn lock_sha256(&self) -> Sha256Digest {
        self.lock_sha256
    }
}

/// Complete canonical proposal supplied to the privileged broker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsRunnerAdmissionIssueRequest {
    schema_version: u16,
    transaction: WindowsEnrollmentTransactionBinding,
    runner_name: String,
    broker_host_id: String,
    sandbox_provider_id: String,
    backend: WindowsAdmissionBackendContract,
    host_inputs: Vec<WindowsAdmissionHostInput>,
    launch: WindowsAdmissionLaunchContract,
    probe: WindowsAdmissionProbeContract,
    promotion: WindowsAdmissionPromotionRequest,
    capability_ceiling: RunnerCapabilities,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedWindowsRunnerAdmissionIssueRequest {
    schema_version: u16,
    transaction: WindowsEnrollmentTransactionBinding,
    runner_name: String,
    broker_host_id: String,
    sandbox_provider_id: String,
    backend: WindowsAdmissionBackendContract,
    host_inputs: Vec<WindowsAdmissionHostInput>,
    launch: WindowsAdmissionLaunchContract,
    probe: WindowsAdmissionProbeContract,
    promotion: WindowsAdmissionPromotionRequest,
    capability_ceiling: RunnerCapabilities,
}

impl<'de> Deserialize<'de> for WindowsRunnerAdmissionIssueRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = UncheckedWindowsRunnerAdmissionIssueRequest::deserialize(deserializer)?;
        Self::new(
            value.transaction,
            value.runner_name,
            value.broker_host_id,
            value.sandbox_provider_id,
            value.backend,
            value.host_inputs,
            value.launch,
            value.probe,
            value.promotion,
            value.capability_ceiling,
        )
        .and_then(|request| {
            (value.schema_version == WINDOWS_RUNNER_ADMISSION_ISSUE_SCHEMA_VERSION)
                .then_some(request)
                .ok_or(WindowsRunnerAdmissionIssueError::UnsupportedSchema)
        })
        .map_err(D::Error::custom)
    }
}

impl WindowsRunnerAdmissionIssueRequest {
    /// Creates a strict broker-verifiable proposal.
    ///
    /// # Errors
    ///
    /// Rejects malformed, inconsistent, weaker, secret-bearing, or
    /// placeholder request data.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transaction: WindowsEnrollmentTransactionBinding,
        runner_name: impl Into<String>,
        broker_host_id: impl Into<String>,
        sandbox_provider_id: impl Into<String>,
        backend: WindowsAdmissionBackendContract,
        host_inputs: Vec<WindowsAdmissionHostInput>,
        launch: WindowsAdmissionLaunchContract,
        probe: WindowsAdmissionProbeContract,
        promotion: WindowsAdmissionPromotionRequest,
        capability_ceiling: RunnerCapabilities,
    ) -> Result<Self, WindowsRunnerAdmissionIssueError> {
        let value = Self {
            schema_version: WINDOWS_RUNNER_ADMISSION_ISSUE_SCHEMA_VERSION,
            transaction,
            runner_name: runner_name.into(),
            broker_host_id: broker_host_id.into(),
            sandbox_provider_id: sandbox_provider_id.into(),
            backend,
            host_inputs,
            launch,
            probe,
            promotion,
            capability_ceiling,
        };
        value.validate()?;
        Ok(value)
    }

    /// Decodes only the byte-for-byte canonical JSON representation.
    ///
    /// # Errors
    ///
    /// Rejects oversized, unknown-field, invalid, or noncanonical input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, WindowsRunnerAdmissionIssueError> {
        if bytes.is_empty() || bytes.len() > MAX_CANONICAL_REQUEST_BYTES {
            return Err(WindowsRunnerAdmissionIssueError::PayloadTooLarge);
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| WindowsRunnerAdmissionIssueError::InvalidCanonicalPayload)?;
        if value.canonical_bytes()? != bytes {
            return Err(WindowsRunnerAdmissionIssueError::NonCanonicalPayload);
        }
        Ok(value)
    }

    /// Serializes the unique canonical request representation.
    ///
    /// # Errors
    ///
    /// Fails if serialization exceeds the fixed protocol bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WindowsRunnerAdmissionIssueError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|_| WindowsRunnerAdmissionIssueError::InvalidCanonicalPayload)?;
        if bytes.is_empty() || bytes.len() > MAX_CANONICAL_REQUEST_BYTES {
            return Err(WindowsRunnerAdmissionIssueError::PayloadTooLarge);
        }
        Ok(bytes)
    }

    /// Returns the domain-separated digest bound into the broker-signed receipt.
    ///
    /// # Errors
    ///
    /// Fails if this request cannot be serialized canonically.
    pub fn request_sha256(&self) -> Result<Sha256Digest, WindowsRunnerAdmissionIssueError> {
        let bytes = self.canonical_bytes()?;
        let mut digest = Sha256::new();
        digest.update(REQUEST_DIGEST_DOMAIN);
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
        Ok(Sha256Digest::from_bytes(digest.finalize().into()))
    }

    /// Returns the enrollment transaction binding.
    #[must_use]
    pub const fn transaction(&self) -> &WindowsEnrollmentTransactionBinding {
        &self.transaction
    }

    /// Returns the exact display name whose digest is transaction-bound.
    #[must_use]
    pub fn runner_name(&self) -> &str {
        &self.runner_name
    }

    /// Returns the exact broker host identity.
    #[must_use]
    pub fn broker_host_id(&self) -> &str {
        &self.broker_host_id
    }

    /// Returns the fixed sandbox provider identity.
    #[must_use]
    pub fn sandbox_provider_id(&self) -> &str {
        &self.sandbox_provider_id
    }

    /// Returns the backend process contract.
    #[must_use]
    pub const fn backend(&self) -> &WindowsAdmissionBackendContract {
        &self.backend
    }

    /// Returns the exact ordered host inputs.
    #[must_use]
    pub fn host_inputs(&self) -> &[WindowsAdmissionHostInput] {
        &self.host_inputs
    }

    /// Returns the complete launch contract.
    #[must_use]
    pub const fn launch(&self) -> &WindowsAdmissionLaunchContract {
        &self.launch
    }

    /// Returns the exact shared probe contract.
    #[must_use]
    pub const fn probe(&self) -> &WindowsAdmissionProbeContract {
        &self.probe
    }

    /// Returns the external promotion inputs.
    #[must_use]
    pub const fn promotion(&self) -> &WindowsAdmissionPromotionRequest {
        &self.promotion
    }

    /// Returns the non-authoritative maximum capability set the broker may prove.
    #[must_use]
    pub const fn capability_ceiling(&self) -> &RunnerCapabilities {
        &self.capability_ceiling
    }

    fn validate(&self) -> Result<(), WindowsRunnerAdmissionIssueError> {
        let name_digest =
            Sha256Digest::from_bytes(Sha256::digest(self.runner_name.as_bytes()).into());
        if self.schema_version != WINDOWS_RUNNER_ADMISSION_ISSUE_SCHEMA_VERSION {
            return Err(WindowsRunnerAdmissionIssueError::UnsupportedSchema);
        }
        if self.runner_name.is_empty()
            || self.runner_name.len() > 255
            || self.runner_name.trim() != self.runner_name
            || self.runner_name.chars().any(char::is_control)
            || name_digest != self.transaction.runner_name_sha256()
            || self.broker_host_id.len() != 64
            || !self
                .broker_host_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            || self.sandbox_provider_id != WINDOWS_RUNNER_ADMISSION_PROVIDER_ID
            || self.transaction.runner_id() != self.capability_ceiling.runner_id()
            || self.capability_ceiling.platform().operating_system() != &OperatingSystem::Windows
            || self
                .capability_ceiling
                .features()
                .contains(&RunnerFeature::LOCAL_ACTIONS)
        {
            return Err(WindowsRunnerAdmissionIssueError::InvalidCapabilities);
        }
        self.launch.validate()?;
        self.probe.validate()?;
        if self
            .launch
            .profile
            .digest()
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
            || !self
                .capability_ceiling
                .environment_profiles()
                .contains(&self.launch.profile)
            || self.probe.resources != self.launch.resources
            || self.probe.allocation != self.launch.allocation
            || self
                .probe
                .contract_sha256
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(WindowsRunnerAdmissionIssueError::InvalidProbe);
        }
        validate_host_inputs(self)?;
        validate_node_capabilities(self)?;
        Ok(())
    }
}

/// Fail-closed issue-request validation error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WindowsRunnerAdmissionIssueError {
    /// The request uses an unsupported schema.
    #[error("unsupported Windows runner admission issue schema")]
    UnsupportedSchema,
    /// Host input descriptors are missing, reordered, duplicated, or unsafe.
    #[error("invalid Windows admission host inputs")]
    InvalidHostInputs,
    /// Backend executable or operation policy is invalid.
    #[error("invalid Windows admission backend contract")]
    InvalidBackend,
    /// Launch material or sandbox policy is invalid.
    #[error("invalid Windows admission launch contract")]
    InvalidLaunch,
    /// Probe semantics, tools, or resource bindings are invalid.
    #[error("invalid Windows admission probe contract")]
    InvalidProbe,
    /// Promotion inputs are invalid or do not match host inputs.
    #[error("invalid Windows admission promotion request")]
    InvalidPromotion,
    /// The proposed capability ceiling is invalid or inconsistent.
    #[error("invalid Windows admission capability ceiling")]
    InvalidCapabilities,
    /// The request exceeds its fixed representation bound.
    #[error("Windows admission issue request exceeds its bounded representation")]
    PayloadTooLarge,
    /// The canonical request cannot be decoded.
    #[error("invalid Windows admission issue canonical payload")]
    InvalidCanonicalPayload,
    /// The decoded request does not reserialize byte-for-byte.
    #[error("noncanonical Windows admission issue payload")]
    NonCanonicalPayload,
}

fn validate_host_inputs(
    request: &WindowsRunnerAdmissionIssueRequest,
) -> Result<(), WindowsRunnerAdmissionIssueError> {
    if request.host_inputs.len() != HOST_INPUT_ORDER.len() {
        return Err(WindowsRunnerAdmissionIssueError::InvalidHostInputs);
    }
    let mut paths = BTreeSet::new();
    for (input, expected_kind) in request.host_inputs.iter().zip(HOST_INPUT_ORDER) {
        if input.kind != expected_kind
            || !valid_windows_path(&input.absolute_path)
            || zero_digest(input.expected_sha256)
            || !paths.insert(input.absolute_path.to_ascii_uppercase())
        {
            return Err(WindowsRunnerAdmissionIssueError::InvalidHostInputs);
        }
    }
    let backend = &request.host_inputs[1];
    let manifest = &request.host_inputs[2];
    let lock = &request.host_inputs[3];
    let envelope = &request.host_inputs[8];
    if backend.absolute_path != request.backend.executable_path
        || backend.expected_sha256 != request.backend.executable_sha256
        || manifest.expected_sha256 != request.promotion.manifest_sha256
        || lock.expected_sha256 != request.promotion.lock_sha256
        || envelope.absolute_path != request.promotion.envelope_path
    {
        return Err(WindowsRunnerAdmissionIssueError::InvalidPromotion);
    }
    Ok(())
}

fn validate_node_capabilities(
    request: &WindowsRunnerAdmissionIssueRequest,
) -> Result<(), WindowsRunnerAdmissionIssueError> {
    let features = request.capability_ceiling.features();
    let action_features = [
        RunnerFeature::JAVASCRIPT_ACTIONS,
        RunnerFeature::COMPOSITE_ACTIONS,
        RunnerFeature::REPOSITORY_ACTIONS,
        RunnerFeature::LOCAL_ACTIONS,
        RunnerFeature::NODE12_ACTIONS,
        RunnerFeature::NODE16_ACTIONS,
        RunnerFeature::NODE20_ACTIONS,
        RunnerFeature::NODE24_ACTIONS,
    ];
    if !request.launch.sealed_action_trees {
        return action_features
            .iter()
            .all(|feature| !features.contains(feature))
            .then_some(())
            .ok_or(WindowsRunnerAdmissionIssueError::InvalidCapabilities);
    }
    let generations = [
        (
            RunnerFeature::NODE12_ACTIONS,
            request.probe.node12.is_some(),
        ),
        (
            RunnerFeature::NODE16_ACTIONS,
            request.probe.node16.is_some(),
        ),
        (
            RunnerFeature::NODE20_ACTIONS,
            request.probe.node20.is_some(),
        ),
        (
            RunnerFeature::NODE24_ACTIONS,
            request.probe.node24.is_some(),
        ),
    ];
    let any_node = generations.iter().any(|(_, present)| *present);
    if generations
        .iter()
        .any(|(feature, present)| features.contains(feature) != *present)
        || features.contains(&RunnerFeature::JAVASCRIPT_ACTIONS) != any_node
        || !features.contains(&RunnerFeature::REPOSITORY_ACTIONS)
        || !features.contains(&RunnerFeature::COMPOSITE_ACTIONS)
    {
        return Err(WindowsRunnerAdmissionIssueError::InvalidCapabilities);
    }
    Ok(())
}

fn valid_windows_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    if value.is_empty()
        || value.len() > MAX_HOST_PATH_BYTES.max(MAX_TARGET_PATH_BYTES)
        || !value.is_ascii()
        || value.chars().any(char::is_control)
        || bytes.len() < 3
        || !bytes[0].is_ascii_uppercase()
        || bytes[1] != b':'
        || bytes[2] != b'\\'
        || value.contains('/')
        || value.starts_with("\\\\")
    {
        return false;
    }
    value[3..].split('\\').all(valid_windows_component)
}

fn valid_windows_component(value: &str) -> bool {
    if value.is_empty()
        || matches!(value, "." | "..")
        || value.ends_with([' ', '.'])
        || value
            .bytes()
            .any(|byte| matches!(byte, b'<' | b'>' | b':' | b'"' | b'|' | b'?' | b'*'))
    {
        return false;
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    !matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) && !stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
        .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
}

fn valid_environment_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.contains('=')
        && !value.chars().any(char::is_control)
}

fn valid_id(value: &str) -> bool {
    (3..=128).contains(&value.len())
        && value.is_ascii()
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_trust_bundle_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=128).contains(&bytes.len())
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn zero_digest(value: Sha256Digest) -> bool {
    value.as_bytes().iter().all(|byte| *byte == 0)
}
