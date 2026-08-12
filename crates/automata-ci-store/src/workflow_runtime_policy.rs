//! Immutable runner-policy evidence pinned to every WorkflowPlan-v2 run.

use std::{collections::BTreeSet, fmt, num::NonZeroU64};

use async_trait::async_trait;
use automata_ci_core::{
    Architecture, ContainerFeature, EnvironmentProfile, EnvironmentProfileId, OperatingSystem,
    RunId, RunnerLabel, Sha256Digest, UnixMillis,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    LogicalActivationPreparationWorkspace, LogicalWorkflowInvocationId, LogicalWorkflowJobId,
    RepositoryId, StoreError, TenantScope,
};

/// Current immutable runner-policy schema.
pub const WORKFLOW_RUNTIME_POLICY_SCHEMA: u16 = 1;
/// Current pure workspace derivation contract.
pub const WORKFLOW_WORKSPACE_DERIVATION_VERSION: u16 = 1;
/// Maximum exact selector mappings retained by one policy.
pub const MAX_WORKFLOW_RUNTIME_POLICY_MAPPINGS: usize = 64;
/// Maximum container features retained by one exact mapping.
pub const MAX_WORKFLOW_RUNTIME_POLICY_FEATURES: usize = 64;
/// Maximum exact canonical JSON representation retained by Store and Blob.
pub const MAX_WORKFLOW_RUNTIME_POLICY_BYTES: usize = 64 * 1_024;
/// Exact immutable object media type for the canonical policy representation.
pub const WORKFLOW_RUNTIME_POLICY_MEDIA_TYPE: &str =
    "application/vnd.automata.github-runner-policy+json";
/// The sole current workspace root supported by derivation version 1.
pub const WORKFLOW_RUNTIME_POLICY_WORKSPACE_ROOT: &str = "/__w";

const POLICY_DIGEST_DOMAIN: &[u8] = b"automata.store.workflow-runtime-policy.v1\0";

/// Positive immutable policy revision representable by `PostgreSQL` `BIGINT`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkflowRuntimePolicyRevision(NonZeroU64);

impl WorkflowRuntimePolicyRevision {
    /// Constructs one positive revision.
    ///
    /// # Errors
    ///
    /// Rejects zero and values greater than `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, WorkflowRuntimePolicyValueError> {
        NonZeroU64::new(value)
            .filter(|value| i64::try_from(value.get()).is_ok())
            .map(Self)
            .ok_or(WorkflowRuntimePolicyValueError::InvalidRevision)
    }

    /// Returns the positive numeric revision.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub(crate) fn as_i64(self) -> i64 {
        i64::try_from(self.get()).expect("validated runtime-policy revision fits BIGINT")
    }
}

/// One exact GitHub label to immutable environment-profile mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowRuntimePolicyMapping {
    selector: RunnerLabel,
    environment: EnvironmentProfile,
    operating_system: OperatingSystem,
    architecture: Architecture,
    container_features: BTreeSet<ContainerFeature>,
}

impl WorkflowRuntimePolicyMapping {
    /// Constructs one closed, bounded mapping.
    ///
    /// # Errors
    ///
    /// Rejects provider-specific platform variants, non-ASCII policy selectors,
    /// duplicate features, or more than 64 raw features.
    pub fn new(
        selector: RunnerLabel,
        environment: EnvironmentProfile,
        operating_system: OperatingSystem,
        architecture: Architecture,
        container_features: impl IntoIterator<Item = ContainerFeature>,
    ) -> Result<Self, WorkflowRuntimePolicyValueError> {
        if matches!(operating_system, OperatingSystem::Other(_))
            || matches!(architecture, Architecture::Other(_))
        {
            return Err(WorkflowRuntimePolicyValueError::OpenPlatform);
        }
        if !selector.as_str().is_ascii() {
            return Err(WorkflowRuntimePolicyValueError::InvalidSelector);
        }
        let raw_features = container_features.into_iter().collect::<Vec<_>>();
        if raw_features.len() > MAX_WORKFLOW_RUNTIME_POLICY_FEATURES {
            return Err(WorkflowRuntimePolicyValueError::TooManyFeatures);
        }
        let container_features = raw_features.iter().cloned().collect::<BTreeSet<_>>();
        if container_features.len() != raw_features.len() {
            return Err(WorkflowRuntimePolicyValueError::DuplicateFeature);
        }
        Ok(Self {
            selector,
            environment,
            operating_system,
            architecture,
            container_features,
        })
    }

    /// Returns the sole exact runner-label selector.
    #[must_use]
    pub const fn selector(&self) -> &RunnerLabel {
        &self.selector
    }

    /// Returns the immutable environment profile and manifest digest.
    #[must_use]
    pub const fn environment(&self) -> &EnvironmentProfile {
        &self.environment
    }

    /// Returns the closed operating-system family.
    #[must_use]
    pub const fn operating_system(&self) -> &OperatingSystem {
        &self.operating_system
    }

    /// Returns the closed processor architecture.
    #[must_use]
    pub const fn architecture(&self) -> &Architecture {
        &self.architecture
    }

    /// Returns the exact canonical container-feature set.
    #[must_use]
    pub const fn container_features(&self) -> &BTreeSet<ContainerFeature> {
        &self.container_features
    }
}

/// Complete immutable non-secret runner and workspace policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowRuntimePolicy {
    workspace_root: String,
    mappings: Vec<WorkflowRuntimePolicyMapping>,
    digest: Sha256Digest,
    canonical_digest: Sha256Digest,
}

impl WorkflowRuntimePolicy {
    /// Decodes trusted configuration and returns its canonical typed value.
    ///
    /// Configuration may contain insignificant whitespace and arbitrary object
    /// key ordering. Unknown fields and aliases are rejected.
    ///
    /// # Errors
    ///
    /// Rejects empty, malformed, excessive, ambiguous, or invalid policy JSON.
    pub fn decode_configuration(encoded: &[u8]) -> Result<Self, WorkflowRuntimePolicyValueError> {
        Self::decode(encoded, false)
    }

    /// Decodes immutable object bytes and requires their byte-exact canonical
    /// representation.
    ///
    /// # Errors
    ///
    /// Rejects malformed, excessive, invalid, or noncanonical policy bytes.
    pub fn decode_canonical(encoded: &[u8]) -> Result<Self, WorkflowRuntimePolicyValueError> {
        Self::decode(encoded, true)
    }

    fn decode(
        encoded: &[u8],
        require_canonical: bool,
    ) -> Result<Self, WorkflowRuntimePolicyValueError> {
        if encoded.is_empty() || encoded.len() > MAX_WORKFLOW_RUNTIME_POLICY_BYTES {
            return Err(WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy);
        }
        let raw: RawPolicy = serde_json::from_slice(encoded)
            .map_err(|_| WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy)?;
        if raw.schema != WORKFLOW_RUNTIME_POLICY_SCHEMA
            || raw.workspace.schema != WORKFLOW_RUNTIME_POLICY_SCHEMA
            || raw.workspace.root != WORKFLOW_RUNTIME_POLICY_WORKSPACE_ROOT
            || raw.workspace.derivation != WORKFLOW_WORKSPACE_DERIVATION_VERSION
            || raw.mappings.is_empty()
            || raw.mappings.len() > MAX_WORKFLOW_RUNTIME_POLICY_MAPPINGS
        {
            return Err(WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy);
        }
        let mappings = raw
            .mappings
            .into_iter()
            .map(WorkflowRuntimePolicyMapping::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let policy = Self::new(raw.workspace.root, mappings)?;
        if require_canonical && policy.canonical_bytes()?.as_slice() != encoded {
            return Err(WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy);
        }
        Ok(policy)
    }

    /// Constructs one canonical policy.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical POSIX root, an empty/oversized catalog, or
    /// duplicate exact selectors.
    pub fn new(
        workspace_root: impl Into<String>,
        mappings: impl IntoIterator<Item = WorkflowRuntimePolicyMapping>,
    ) -> Result<Self, WorkflowRuntimePolicyValueError> {
        let workspace_root = workspace_root.into();
        validate_workspace_root(&workspace_root)?;
        let mut mappings = mappings.into_iter().collect::<Vec<_>>();
        if mappings.is_empty() || mappings.len() > MAX_WORKFLOW_RUNTIME_POLICY_MAPPINGS {
            return Err(WorkflowRuntimePolicyValueError::InvalidMappingCount);
        }
        mappings.sort_by(|left, right| left.selector().cmp(right.selector()));
        if mappings
            .windows(2)
            .any(|pair| pair[0].selector() == pair[1].selector())
        {
            return Err(WorkflowRuntimePolicyValueError::DuplicateSelector);
        }
        let mut policy = Self {
            workspace_root,
            mappings,
            digest: Sha256Digest::from_bytes([0; 32]),
            canonical_digest: Sha256Digest::from_bytes([0; 32]),
        };
        let canonical = encode_canonical_policy(policy.workspace_root(), policy.mappings())?;
        validate_canonical_policy_bytes(&canonical)?;
        policy.digest = policy_digest(&policy);
        policy.canonical_digest = Sha256Digest::from_bytes(Sha256::digest(canonical).into());
        Ok(policy)
    }

    /// Returns the exact canonical immutable-object bytes for this semantic value.
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be represented by the bounded
    /// current canonical policy format.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WorkflowRuntimePolicyValueError> {
        let encoded = encode_canonical_policy(self.workspace_root(), self.mappings())?;
        validate_canonical_policy_bytes(&encoded)?;
        Ok(encoded)
    }

    /// Returns the canonical POSIX workspace root.
    #[must_use]
    pub fn workspace_root(&self) -> &str {
        &self.workspace_root
    }

    /// Returns mappings in canonical selector order.
    #[must_use]
    pub fn mappings(&self) -> &[WorkflowRuntimePolicyMapping] {
        &self.mappings
    }

    /// Returns the content-addressed policy digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the SHA-256 identity of [`Self::canonical_bytes`].
    ///
    /// This immutable-object identity is intentionally distinct from the
    /// domain-separated relational semantic [`Self::digest`].
    #[must_use]
    pub const fn canonical_digest(&self) -> Sha256Digest {
        self.canonical_digest
    }

    /// Purely derives the exact job workspace under schema/version 1.
    ///
    /// # Errors
    ///
    /// Rejects a derived path outside the bounded canonical workspace shape.
    pub fn derive_workspace(
        &self,
        run_id: RunId,
        invocation_id: LogicalWorkflowInvocationId,
        logical_job_id: LogicalWorkflowJobId,
    ) -> Result<LogicalActivationPreparationWorkspace, WorkflowRuntimePolicyValueError> {
        let value = format!(
            "{}/{}/{}/{}",
            self.workspace_root,
            run_id.as_uuid(),
            invocation_id.as_uuid(),
            logical_job_id.as_uuid()
        );
        LogicalActivationPreparationWorkspace::new(value)
            .map_err(|_| WorkflowRuntimePolicyValueError::InvalidWorkspaceRoot)
    }
}

/// Immutable repository policy identity pinned to one admitted run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowRuntimePolicyPin {
    tenant: TenantScope,
    repository_id: RepositoryId,
    revision: WorkflowRuntimePolicyRevision,
    digest: Sha256Digest,
}

impl WorkflowRuntimePolicyPin {
    /// Rehydrates one exact durable policy pin.
    #[must_use]
    pub const fn new(
        tenant: TenantScope,
        repository_id: RepositoryId,
        revision: WorkflowRuntimePolicyRevision,
        digest: Sha256Digest,
    ) -> Self {
        Self {
            tenant,
            repository_id,
            revision,
            digest,
        }
    }

    /// Returns the authenticated tenant.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    /// Returns the exact repository identity.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the immutable policy revision.
    #[must_use]
    pub const fn revision(&self) -> WorkflowRuntimePolicyRevision {
        self.revision
    }

    /// Returns the exact content digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// Complete historical policy rehydrated for one admitted run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedWorkflowRuntimePolicy {
    run_id: RunId,
    pin: WorkflowRuntimePolicyPin,
    policy: WorkflowRuntimePolicy,
}

impl PinnedWorkflowRuntimePolicy {
    /// Rehydrates one pin and rejects content disagreement.
    ///
    /// # Errors
    ///
    /// Rejects a nil run or a policy whose digest differs from the pin.
    pub fn new(
        run_id: RunId,
        pin: WorkflowRuntimePolicyPin,
        policy: WorkflowRuntimePolicy,
    ) -> Result<Self, WorkflowRuntimePolicyValueError> {
        if run_id.as_uuid().is_nil() {
            return Err(WorkflowRuntimePolicyValueError::NilRun);
        }
        if pin.digest() != policy.digest() {
            return Err(WorkflowRuntimePolicyValueError::DigestMismatch);
        }
        Ok(Self {
            run_id,
            pin,
            policy,
        })
    }

    /// Returns the admitted run.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the exact immutable pin.
    #[must_use]
    pub const fn pin(&self) -> &WorkflowRuntimePolicyPin {
        &self.pin
    }

    /// Returns the verified historical policy.
    #[must_use]
    pub const fn policy(&self) -> &WorkflowRuntimePolicy {
        &self.policy
    }
}

/// Bootstrap request that registers and atomically selects one policy revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterWorkflowRuntimePolicy {
    pin: WorkflowRuntimePolicyPin,
    policy: WorkflowRuntimePolicy,
    registered_at: UnixMillis,
}

impl RegisterWorkflowRuntimePolicy {
    /// Constructs an exact registration request.
    ///
    /// # Errors
    ///
    /// Rejects a caller-supplied digest mismatch or negative timestamp.
    pub fn new(
        tenant: TenantScope,
        repository_id: RepositoryId,
        revision: WorkflowRuntimePolicyRevision,
        policy: WorkflowRuntimePolicy,
        registered_at: UnixMillis,
    ) -> Result<Self, WorkflowRuntimePolicyValueError> {
        if repository_id.as_uuid().is_nil() {
            return Err(WorkflowRuntimePolicyValueError::NilRepository);
        }
        if registered_at.get() < 0 {
            return Err(WorkflowRuntimePolicyValueError::InvalidTimestamp);
        }
        let pin = WorkflowRuntimePolicyPin::new(tenant, repository_id, revision, policy.digest());
        Ok(Self {
            pin,
            policy,
            registered_at,
        })
    }

    /// Returns the exact revision identity.
    #[must_use]
    pub const fn pin(&self) -> &WorkflowRuntimePolicyPin {
        &self.pin
    }

    /// Returns the complete non-secret policy.
    #[must_use]
    pub const fn policy(&self) -> &WorkflowRuntimePolicy {
        &self.policy
    }

    /// Returns the trusted registration observation.
    #[must_use]
    pub const fn registered_at(&self) -> UnixMillis {
        self.registered_at
    }
}

/// Exact registration receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowRuntimePolicyReceipt {
    pin: WorkflowRuntimePolicyPin,
    registered_at: UnixMillis,
    replayed: bool,
}

impl WorkflowRuntimePolicyReceipt {
    /// Rehydrates an exact repository receipt.
    #[must_use]
    pub const fn new(
        pin: WorkflowRuntimePolicyPin,
        registered_at: UnixMillis,
        replayed: bool,
    ) -> Self {
        Self {
            pin,
            registered_at,
            replayed,
        }
    }

    /// Returns the registered revision identity.
    #[must_use]
    pub const fn pin(&self) -> &WorkflowRuntimePolicyPin {
        &self.pin
    }

    /// Returns the immutable registration time.
    #[must_use]
    pub const fn registered_at(&self) -> UnixMillis {
        self.registered_at
    }

    /// Reports exact replay.
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.replayed
    }
}

/// Invalid policy value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkflowRuntimePolicyValueError {
    /// A revision was zero or outside `PostgreSQL` `BIGINT`.
    #[error("workflow runtime policy revision is invalid")]
    InvalidRevision,
    /// The repository identity was nil.
    #[error("workflow runtime policy repository ID is nil")]
    NilRepository,
    /// The run identity was nil.
    #[error("workflow runtime policy run ID is nil")]
    NilRun,
    /// The workspace root was not a canonical bounded POSIX path.
    #[error("workflow runtime policy workspace root is invalid")]
    InvalidWorkspaceRoot,
    /// The policy had zero or more than 64 mappings.
    #[error("workflow runtime policy mapping count is invalid")]
    InvalidMappingCount,
    /// More than one mapping named the same canonical selector.
    #[error("workflow runtime policy contains a duplicate selector")]
    DuplicateSelector,
    /// A policy selector was outside the exact printable ASCII persistence grammar.
    #[error("workflow runtime policy selector is invalid")]
    InvalidSelector,
    /// A mapping used an open provider-specific platform value.
    #[error("workflow runtime policy platform must use a closed value")]
    OpenPlatform,
    /// One mapping exceeded the fixed feature bound.
    #[error("workflow runtime policy mapping has too many features")]
    TooManyFeatures,
    /// One mapping repeated a feature before canonical set construction.
    #[error("workflow runtime policy mapping contains a duplicate feature")]
    DuplicateFeature,
    /// The canonical JSON value was malformed, noncanonical, or exceeded 64 KiB.
    #[error("workflow runtime policy canonical representation is invalid")]
    InvalidCanonicalPolicy,
    /// Rehydrated content disagreed with its immutable digest pin.
    #[error("workflow runtime policy content disagrees with its pin")]
    DigestMismatch,
    /// A trusted timestamp was negative.
    #[error("workflow runtime policy timestamp is invalid")]
    InvalidTimestamp,
}

/// Durable runtime-policy failure.
#[derive(Debug, Error)]
pub enum WorkflowRuntimePolicyStoreError {
    /// The relational store failed or contained malformed current data.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The repository is absent, foreign, or not configured for this policy.
    #[error("workflow runtime policy repository is not available")]
    InvalidTarget,
    /// Registration disagreed with current immutable revision state.
    #[error("workflow runtime policy registration conflicts with durable state")]
    Conflict,
}

/// Persistence boundary for historical run-policy rehydration.
///
/// Current policy registration is intentionally available only through the
/// aggregate GitHub repository bootstrap boundary, which commits the matching
/// manifest current pointer in the same transaction.
#[async_trait]
pub trait WorkflowRuntimePolicyRepository: fmt::Debug + Send + Sync {
    /// Loads only the immutable policy revision already pinned to `run_id`.
    async fn load_workflow_runtime_policy_for_run(
        &self,
        run_id: RunId,
    ) -> Result<PinnedWorkflowRuntimePolicy, WorkflowRuntimePolicyStoreError>;
}

fn validate_workspace_root(value: &str) -> Result<(), WorkflowRuntimePolicyValueError> {
    if value == WORKFLOW_RUNTIME_POLICY_WORKSPACE_ROOT {
        Ok(())
    } else {
        Err(WorkflowRuntimePolicyValueError::InvalidWorkspaceRoot)
    }
}

fn policy_digest(policy: &WorkflowRuntimePolicy) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(POLICY_DIGEST_DOMAIN);
    hasher.update(WORKFLOW_RUNTIME_POLICY_SCHEMA.to_be_bytes());
    hasher.update(WORKFLOW_WORKSPACE_DERIVATION_VERSION.to_be_bytes());
    hash_text(&mut hasher, policy.workspace_root());
    hasher.update(
        u64::try_from(policy.mappings().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for mapping in policy.mappings() {
        hash_text(&mut hasher, mapping.selector().as_str());
        hash_text(&mut hasher, mapping.environment().id().as_str());
        hasher.update(mapping.environment().digest().as_bytes());
        hasher.update([operating_system_code(mapping.operating_system())]);
        hasher.update([architecture_code(mapping.architecture())]);
        hasher.update(
            u64::try_from(mapping.container_features().len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for feature in mapping.container_features() {
            hash_text(&mut hasher, feature.as_str());
        }
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn encode_canonical_policy(
    workspace_root: &str,
    mappings: &[WorkflowRuntimePolicyMapping],
) -> Result<Vec<u8>, WorkflowRuntimePolicyValueError> {
    let canonical = CanonicalPolicy {
        schema: WORKFLOW_RUNTIME_POLICY_SCHEMA,
        workspace: CanonicalWorkspace {
            schema: WORKFLOW_RUNTIME_POLICY_SCHEMA,
            root: workspace_root,
            derivation: WORKFLOW_WORKSPACE_DERIVATION_VERSION,
        },
        mappings: mappings
            .iter()
            .map(CanonicalMapping::try_from)
            .collect::<Result<Vec<_>, _>>()?,
    };
    serde_json::to_vec(&canonical)
        .map_err(|_| WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy)
}

fn validate_canonical_policy_bytes(encoded: &[u8]) -> Result<(), WorkflowRuntimePolicyValueError> {
    if encoded.is_empty() || encoded.len() > MAX_WORKFLOW_RUNTIME_POLICY_BYTES {
        Err(WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy)
    } else {
        Ok(())
    }
}

const fn operating_system_code(value: &OperatingSystem) -> u8 {
    match value {
        OperatingSystem::Linux => 1,
        OperatingSystem::Windows => 2,
        OperatingSystem::Macos => 3,
        OperatingSystem::Other(_) => 0,
    }
}

const fn architecture_code(value: &Architecture) -> u8 {
    match value {
        Architecture::X86_64 => 1,
        Architecture::Aarch64 => 2,
        Architecture::Other(_) => 0,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    schema: u16,
    workspace: RawWorkspace,
    mappings: Vec<RawMapping>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWorkspace {
    schema: u16,
    root: String,
    derivation: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMapping {
    selector: String,
    environment_profile: RawEnvironmentProfile,
    operating_system: CanonicalOperatingSystem,
    architecture: CanonicalArchitecture,
    container_features: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvironmentProfile {
    id: String,
    manifest_sha256: Sha256Digest,
}

impl TryFrom<RawMapping> for WorkflowRuntimePolicyMapping {
    type Error = WorkflowRuntimePolicyValueError;

    fn try_from(raw: RawMapping) -> Result<Self, Self::Error> {
        if !raw.selector.is_ascii() {
            return Err(WorkflowRuntimePolicyValueError::InvalidSelector);
        }
        if raw.container_features.len() > MAX_WORKFLOW_RUNTIME_POLICY_FEATURES {
            return Err(WorkflowRuntimePolicyValueError::TooManyFeatures);
        }
        let selector = RunnerLabel::new(raw.selector)
            .map_err(|_| WorkflowRuntimePolicyValueError::InvalidSelector)?;
        let profile_id = EnvironmentProfileId::new(raw.environment_profile.id)
            .map_err(|_| WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy)?;
        let environment =
            EnvironmentProfile::new(profile_id, raw.environment_profile.manifest_sha256);
        let features = raw
            .container_features
            .into_iter()
            .map(ContainerFeature::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy)?;
        Self::new(
            selector,
            environment,
            raw.operating_system.into(),
            raw.architecture.into(),
            features,
        )
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CanonicalOperatingSystem {
    Linux,
    Windows,
    Macos,
}

impl From<CanonicalOperatingSystem> for OperatingSystem {
    fn from(value: CanonicalOperatingSystem) -> Self {
        match value {
            CanonicalOperatingSystem::Linux => Self::Linux,
            CanonicalOperatingSystem::Windows => Self::Windows,
            CanonicalOperatingSystem::Macos => Self::Macos,
        }
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CanonicalArchitecture {
    X86_64,
    Aarch64,
}

impl From<CanonicalArchitecture> for Architecture {
    fn from(value: CanonicalArchitecture) -> Self {
        match value {
            CanonicalArchitecture::X86_64 => Self::X86_64,
            CanonicalArchitecture::Aarch64 => Self::Aarch64,
        }
    }
}

#[derive(Serialize)]
struct CanonicalPolicy<'a> {
    schema: u16,
    workspace: CanonicalWorkspace<'a>,
    mappings: Vec<CanonicalMapping<'a>>,
}

#[derive(Serialize)]
struct CanonicalWorkspace<'a> {
    schema: u16,
    root: &'a str,
    derivation: u16,
}

#[derive(Serialize)]
struct CanonicalMapping<'a> {
    selector: &'a str,
    environment_profile: CanonicalEnvironmentProfile<'a>,
    operating_system: CanonicalOperatingSystem,
    architecture: CanonicalArchitecture,
    container_features: Vec<&'a str>,
}

#[derive(Serialize)]
struct CanonicalEnvironmentProfile<'a> {
    id: &'a str,
    manifest_sha256: Sha256Digest,
}

impl<'a> TryFrom<&'a WorkflowRuntimePolicyMapping> for CanonicalMapping<'a> {
    type Error = WorkflowRuntimePolicyValueError;

    fn try_from(mapping: &'a WorkflowRuntimePolicyMapping) -> Result<Self, Self::Error> {
        Ok(Self {
            selector: mapping.selector().as_str(),
            environment_profile: CanonicalEnvironmentProfile {
                id: mapping.environment().id().as_str(),
                manifest_sha256: mapping.environment().digest(),
            },
            operating_system: match mapping.operating_system() {
                OperatingSystem::Linux => CanonicalOperatingSystem::Linux,
                OperatingSystem::Windows => CanonicalOperatingSystem::Windows,
                OperatingSystem::Macos => CanonicalOperatingSystem::Macos,
                OperatingSystem::Other(_) => {
                    return Err(WorkflowRuntimePolicyValueError::OpenPlatform);
                }
            },
            architecture: match mapping.architecture() {
                Architecture::X86_64 => CanonicalArchitecture::X86_64,
                Architecture::Aarch64 => CanonicalArchitecture::Aarch64,
                Architecture::Other(_) => {
                    return Err(WorkflowRuntimePolicyValueError::OpenPlatform);
                }
            },
            container_features: mapping
                .container_features()
                .iter()
                .map(ContainerFeature::as_str)
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use automata_ci_core::MAX_CAPABILITY_ID_LENGTH;

    const POLICY: &[u8] = br#"{
      "workspace":{"derivation":1,"root":"/__w","schema":1},
      "mappings":[{
        "container_features":["automata.core/job-containers@v1"],
        "architecture":"x86_64","operating_system":"linux",
        "environment_profile":{"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","id":"automata.example/ubuntu-24-04"},
        "selector":"Ubuntu-24.04"
      }],"schema":1
    }"#;
    const CANONICAL_POLICY: &[u8] = br#"{"schema":1,"workspace":{"schema":1,"root":"/__w","derivation":1},"mappings":[{"selector":"ubuntu-24.04","environment_profile":{"id":"automata.example/ubuntu-24-04","manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111"},"operating_system":"linux","architecture":"x86_64","container_features":["automata.core/job-containers@v1"]}]}"#;

    #[test]
    fn canonical_bytes_and_both_digest_domains_have_exact_golden_identities() {
        let policy = WorkflowRuntimePolicy::decode_configuration(POLICY).expect("configuration");
        let encoded = policy.canonical_bytes().expect("canonical bytes");
        assert_eq!(encoded, CANONICAL_POLICY);
        assert_eq!(
            policy.canonical_digest(),
            Sha256Digest::from_bytes(Sha256::digest(&encoded).into())
        );
        assert_eq!(
            policy.digest().to_string(),
            "e3eec3e76e41a5f430fe3558fadb4018fc271145cb621ed2b20ee1342bc53471"
        );
        assert_eq!(
            policy.canonical_digest().to_string(),
            "5347b0931418cda5e4b5f7de7860a1659ef829dfe3781103d206a7aa9a338d58"
        );
        assert_ne!(policy.digest(), policy.canonical_digest());
        assert_eq!(
            WorkflowRuntimePolicy::decode_canonical(&encoded).expect("canonical object"),
            policy
        );
    }

    #[test]
    fn constructor_accepts_exact_canonical_limit_and_rejects_one_byte_more() {
        let exact_mappings = boundary_mappings(MAX_WORKFLOW_RUNTIME_POLICY_BYTES);
        let exact = WorkflowRuntimePolicy::new(
            WORKFLOW_RUNTIME_POLICY_WORKSPACE_ROOT,
            exact_mappings.clone(),
        )
        .expect("exact canonical byte limit");
        let exact_bytes = exact.canonical_bytes().expect("exact canonical bytes");
        assert_eq!(exact_bytes.len(), MAX_WORKFLOW_RUNTIME_POLICY_BYTES);
        assert_eq!(
            WorkflowRuntimePolicy::decode_canonical(&exact_bytes).expect("exact canonical policy"),
            exact
        );

        let oversized_mappings = boundary_mappings(MAX_WORKFLOW_RUNTIME_POLICY_BYTES + 1);
        assert_eq!(
            WorkflowRuntimePolicy::new(WORKFLOW_RUNTIME_POLICY_WORKSPACE_ROOT, oversized_mappings,),
            Err(WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy)
        );
    }

    #[test]
    fn mapping_count_accepts_exact_limit_and_rejects_one_more() {
        let exact_padding = vec![vec![0]; 64];
        let exact_mappings = build_boundary_mappings(&exact_padding);
        let exact = WorkflowRuntimePolicy::new(
            WORKFLOW_RUNTIME_POLICY_WORKSPACE_ROOT,
            exact_mappings.clone(),
        )
        .expect("exact mapping-count limit");
        assert_eq!(exact.mappings().len(), MAX_WORKFLOW_RUNTIME_POLICY_MAPPINGS);

        let excessive_padding = vec![vec![0]; 65];
        let excessive_mappings = build_boundary_mappings(&excessive_padding);
        assert_eq!(
            WorkflowRuntimePolicy::new(WORKFLOW_RUNTIME_POLICY_WORKSPACE_ROOT, excessive_mappings,),
            Err(WorkflowRuntimePolicyValueError::InvalidMappingCount)
        );
    }

    #[test]
    fn duplicate_raw_object_fields_are_rejected_even_when_values_are_equal() {
        let canonical = std::str::from_utf8(CANONICAL_POLICY).expect("UTF-8 canonical policy");
        let duplicate_top_schema =
            canonical.replacen(r#""schema":1"#, r#""schema":1,"schema":1"#, 1);
        let duplicate_workspace_schema = canonical.replacen(
            r#""workspace":{"schema":1"#,
            r#""workspace":{"schema":1,"schema":1"#,
            1,
        );
        let duplicate_selector = canonical.replacen(
            r#""selector":"ubuntu-24.04""#,
            r#""selector":"ubuntu-24.04","selector":"ubuntu-24.04""#,
            1,
        );
        let duplicate_profile_id = canonical.replacen(
            r#""environment_profile":{"id":"automata.example/ubuntu-24-04""#,
            r#""environment_profile":{"id":"automata.example/ubuntu-24-04","id":"automata.example/ubuntu-24-04""#,
            1,
        );
        for duplicate in [
            duplicate_top_schema,
            duplicate_workspace_schema,
            duplicate_selector,
            duplicate_profile_id,
        ] {
            assert_eq!(
                WorkflowRuntimePolicy::decode_configuration(duplicate.as_bytes()),
                Err(WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy)
            );
        }
    }

    #[test]
    fn raw_kelvin_sign_selector_is_rejected_before_runner_label_case_folding() {
        let normalized = RunnerLabel::new("\u{212a}ernel").expect("general runner label");
        assert_eq!(normalized.as_str(), "kernel");
        let configuration = std::str::from_utf8(POLICY).expect("UTF-8 policy");
        for raw_selector in ["\u{212a}ernel", r"\u212aernel"] {
            let encoded = configuration.replace("Ubuntu-24.04", raw_selector);
            assert_eq!(
                WorkflowRuntimePolicy::decode_configuration(encoded.as_bytes()),
                Err(WorkflowRuntimePolicyValueError::InvalidSelector)
            );
        }
    }

    #[test]
    fn raw_feature_count_and_duplicates_are_rejected_before_set_collapse() {
        let policy = WorkflowRuntimePolicy::decode_configuration(POLICY).expect("configuration");
        let mapping = policy.mappings()[0].clone();
        let feature = mapping
            .container_features()
            .iter()
            .next()
            .expect("feature")
            .clone();
        assert_eq!(
            WorkflowRuntimePolicyMapping::new(
                mapping.selector().clone(),
                mapping.environment().clone(),
                mapping.operating_system().clone(),
                mapping.architecture().clone(),
                [feature.clone(), feature],
            ),
            Err(WorkflowRuntimePolicyValueError::DuplicateFeature)
        );

        let features = (1..=65)
            .map(|version| ContainerFeature::new(format!("example.test/feature@v{version}")))
            .collect::<Result<Vec<_>, _>>()
            .expect("features");
        assert_eq!(
            WorkflowRuntimePolicyMapping::new(
                mapping.selector().clone(),
                mapping.environment().clone(),
                mapping.operating_system().clone(),
                mapping.architecture().clone(),
                features,
            ),
            Err(WorkflowRuntimePolicyValueError::TooManyFeatures)
        );
    }

    #[test]
    fn workspace_and_policy_selector_grammar_are_closed() {
        let policy = WorkflowRuntimePolicy::decode_configuration(POLICY).expect("configuration");
        assert_eq!(policy.workspace_root(), "/__w");
        assert!(WorkflowRuntimePolicy::new("/tmp", policy.mappings().iter().cloned()).is_err());
        let unicode = RunnerLabel::new("İstanbul").expect("general runner label");
        let mapping = &policy.mappings()[0];
        assert_eq!(
            WorkflowRuntimePolicyMapping::new(
                unicode,
                mapping.environment().clone(),
                OperatingSystem::Linux,
                Architecture::X86_64,
                [],
            ),
            Err(WorkflowRuntimePolicyValueError::InvalidSelector)
        );
    }

    fn boundary_mappings(target_size: usize) -> Vec<WorkflowRuntimePolicyMapping> {
        const MAPPING_COUNT: usize = 8;
        const FEATURE_COUNT: usize = MAX_WORKFLOW_RUNTIME_POLICY_FEATURES;

        let mut padding = vec![vec![0_usize; FEATURE_COUNT]; MAPPING_COUNT];
        let base = build_boundary_mappings(&padding);
        let base_size = encode_canonical_policy(WORKFLOW_RUNTIME_POLICY_WORKSPACE_ROOT, &base)
            .expect("base boundary encoding")
            .len();
        let mut remaining = target_size
            .checked_sub(base_size)
            .expect("boundary fixture starts below target");
        for (mapping_index, mapping_padding) in padding.iter_mut().enumerate() {
            for (feature_index, feature_padding) in mapping_padding.iter_mut().enumerate() {
                let base_length = boundary_feature_value(mapping_index, feature_index, 0).len();
                let available = MAX_CAPABILITY_ID_LENGTH - base_length;
                let selected = remaining.min(available);
                *feature_padding = selected;
                remaining -= selected;
            }
        }
        assert_eq!(remaining, 0, "boundary fixture has sufficient padding");
        let mappings = build_boundary_mappings(&padding);
        assert_eq!(
            encode_canonical_policy(WORKFLOW_RUNTIME_POLICY_WORKSPACE_ROOT, &mappings)
                .expect("boundary encoding")
                .len(),
            target_size
        );
        mappings
    }

    fn build_boundary_mappings(padding: &[Vec<usize>]) -> Vec<WorkflowRuntimePolicyMapping> {
        padding
            .iter()
            .enumerate()
            .map(|(mapping_index, feature_padding)| {
                let features = feature_padding
                    .iter()
                    .enumerate()
                    .map(|(feature_index, padding)| {
                        ContainerFeature::new(boundary_feature_value(
                            mapping_index,
                            feature_index,
                            *padding,
                        ))
                        .expect("boundary feature")
                    })
                    .collect::<Vec<_>>();
                WorkflowRuntimePolicyMapping::new(
                    RunnerLabel::new(format!("boundary-{mapping_index}"))
                        .expect("boundary selector"),
                    EnvironmentProfile::new(
                        EnvironmentProfileId::new(format!("example.test/profile-{mapping_index}"))
                            .expect("boundary profile"),
                        Sha256Digest::from_bytes(
                            [u8::try_from(mapping_index + 1).expect("small mapping index"); 32],
                        ),
                    ),
                    OperatingSystem::Linux,
                    Architecture::X86_64,
                    features,
                )
                .expect("boundary mapping")
            })
            .collect()
    }

    fn boundary_feature_value(
        mapping_index: usize,
        feature_index: usize,
        padding: usize,
    ) -> String {
        let value = format!(
            "example.test/feature-{mapping_index}-{feature_index}{}@v1",
            "a".repeat(padding)
        );
        assert!(value.len() <= MAX_CAPABILITY_ID_LENGTH);
        value
    }
}
