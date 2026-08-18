//! Immutable runner-policy evidence pinned to every logical workflow run.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    num::NonZeroU64,
};

use async_trait::async_trait;
use automata_ci_actions_permissions::{
    ACTIONS_WORKFLOW_PERMISSIONS, ActionsDefaultWorkflowPermission, actions_workflow_permission,
};
use automata_ci_core::{
    Architecture, ContainerFeature, EnvironmentProfile, EnvironmentProfileId, JobPermissionGrant,
    JobPermissionRequest, JobResourcePolicy, MAX_JOB_PERMISSION_GRANTS,
    MAX_JOB_PERMISSION_NAME_BYTES, OperatingSystem, PermissionLevel, RunId, RunnerFeature,
    RunnerLabel, Sha256Digest, UnixMillis,
};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{MapAccess, Visitor},
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    LogicalActivationPreparationWorkspace, LogicalWorkflowInvocationId, LogicalWorkflowJobId,
    RepositoryId, StoreError, TenantScope,
};

/// Current immutable runner-policy schema.
pub const WORKFLOW_RUNTIME_POLICY_SCHEMA: u16 = 2;
/// Current schema of the independently versioned workspace section.
pub const WORKFLOW_RUNTIME_POLICY_WORKSPACE_SCHEMA: u16 = 1;
/// Current schema of each independently versioned runner-feature policy.
pub const WORKFLOW_RUNTIME_POLICY_RUNNER_FEATURE_SCHEMA: u16 = 1;
/// Current pure workspace derivation contract.
pub const WORKFLOW_WORKSPACE_DERIVATION_VERSION: u16 = 1;
/// Maximum exact selector mappings retained by one policy.
pub const MAX_WORKFLOW_RUNTIME_POLICY_MAPPINGS: usize = 64;
/// Maximum container features retained by one exact mapping.
pub const MAX_WORKFLOW_RUNTIME_POLICY_FEATURES: usize = 64;
/// Maximum runner features retained by one exact profile policy.
pub const MAX_WORKFLOW_RUNTIME_POLICY_RUNNER_FEATURES: usize = 64;
/// Maximum exact canonical JSON representation retained by Store and Blob.
pub const MAX_WORKFLOW_RUNTIME_POLICY_BYTES: usize = 64 * 1_024;
/// Exact immutable object media type for the canonical policy representation.
pub const WORKFLOW_RUNTIME_POLICY_MEDIA_TYPE: &str =
    "application/vnd.automata.github-runner-policy+json";
/// The sole current workspace root supported by derivation version 1.
pub const WORKFLOW_RUNTIME_POLICY_WORKSPACE_ROOT: &str = "/__w";

const POLICY_DIGEST_DOMAIN: &[u8] = b"automata.store.workflow-runtime-policy.v2\0";

/// Exact repository-pinned expansions for GitHub permission shorthands.
///
/// Every map is total for its source shorthand: omitted names are denied. The
/// maps are stored in canonical name order and become explicit `JobIR` grants
/// before a job can reach a runner or credential issuer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowPermissionPolicy {
    provider_default: BTreeMap<String, PermissionLevel>,
    read_all: BTreeMap<String, PermissionLevel>,
    write_all: BTreeMap<String, PermissionLevel>,
}

impl WorkflowPermissionPolicy {
    /// Constructs exact expansions for all source permission shorthands.
    ///
    /// # Errors
    ///
    /// Rejects empty or excessive maps, malformed names, explicit `none`
    /// entries, an invalid `id-token` read grant, non-read `read-all` entries,
    /// a default outside the readable universe, or defaults that exceed the
    /// configured `write-all` capability ceiling.
    pub fn new(
        provider_default: BTreeMap<String, PermissionLevel>,
        read_all: BTreeMap<String, PermissionLevel>,
        write_all: BTreeMap<String, PermissionLevel>,
    ) -> Result<Self, WorkflowRuntimePolicyValueError> {
        validate_permission_map(&provider_default)?;
        validate_permission_map(&read_all)?;
        validate_permission_map(&write_all)?;
        if read_all != catalog_read_all()
            || write_all != catalog_write_all()
            || !matches_provider_default(&provider_default)
            || provider_default
                .iter()
                .any(|(name, level)| !catalog_allows(name, *level))
        {
            return Err(WorkflowRuntimePolicyValueError::InvalidPermissionPolicy);
        }
        Ok(Self {
            provider_default,
            read_all,
            write_all,
        })
    }

    /// Constructs a policy from the exact repository default and the current
    /// closed GitHub shorthand expansions.
    ///
    /// # Errors
    ///
    /// Rejects a malformed default or a name/level absent from the current
    /// GitHub workflow permission catalog.
    pub fn from_provider_default(
        provider_default: BTreeMap<String, PermissionLevel>,
    ) -> Result<Self, WorkflowRuntimePolicyValueError> {
        Self::new(provider_default, catalog_read_all(), catalog_write_all())
    }

    /// Constructs a policy from one effective default observed through GitHub REST.
    ///
    /// # Errors
    ///
    /// Returns an error only if the closed catalog can no longer represent
    /// GitHub's restricted or permissive default.
    pub fn from_github_default(
        provider_default: ActionsDefaultWorkflowPermission,
    ) -> Result<Self, WorkflowRuntimePolicyValueError> {
        Self::from_provider_default(provider_default_permissions(provider_default))
    }

    /// Returns which closed GitHub default this policy represents.
    #[must_use]
    pub fn github_default(&self) -> ActionsDefaultWorkflowPermission {
        if self.provider_default == restricted_provider_default() {
            ActionsDefaultWorkflowPermission::Read
        } else {
            debug_assert_eq!(self.provider_default, catalog_write_all());
            ActionsDefaultWorkflowPermission::Write
        }
    }

    /// Resolves one source request to a complete canonical permission map.
    #[must_use]
    pub fn resolve(&self, request: JobPermissionRequest) -> JobPermissionRequest {
        let permissions = match request {
            JobPermissionRequest::ProviderDefault => &self.provider_default,
            JobPermissionRequest::ReadAll => &self.read_all,
            JobPermissionRequest::WriteAll => &self.write_all,
            JobPermissionRequest::Mapping(_) => return request,
        };
        JobPermissionRequest::mapping(
            permissions
                .iter()
                .map(|(name, level)| JobPermissionGrant::new(name.clone(), *level)),
        )
    }

    /// Returns the exact canonical JSON bytes persisted beside the durable
    /// policy aggregate.
    ///
    /// # Errors
    ///
    /// Returns an error only if this already-validated bounded value cannot be
    /// represented by the current canonical codec.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WorkflowRuntimePolicyValueError> {
        serde_json::to_vec(&CanonicalPermissionPolicy {
            provider_default: self.provider_default(),
            read_all: self.read_all(),
            write_all: self.write_all(),
        })
        .map_err(|_| WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy)
    }

    /// Returns the exact repository default expansion.
    #[must_use]
    pub const fn provider_default(&self) -> &BTreeMap<String, PermissionLevel> {
        &self.provider_default
    }

    /// Returns the exact `read-all` expansion.
    #[must_use]
    pub const fn read_all(&self) -> &BTreeMap<String, PermissionLevel> {
        &self.read_all
    }

    /// Returns the exact `write-all` expansion.
    #[must_use]
    pub const fn write_all(&self) -> &BTreeMap<String, PermissionLevel> {
        &self.write_all
    }
}

/// Positive immutable policy revision within the signed 64-bit storage boundary.
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
}

/// One exact GitHub label to immutable environment-profile mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowRuntimePolicyMapping {
    selector: RunnerLabel,
    environment: EnvironmentProfile,
    operating_system: OperatingSystem,
    architecture: Architecture,
    runner_feature_policy: Option<WorkflowRunnerFeaturePolicy>,
    container_features: BTreeSet<ContainerFeature>,
}

/// Immutable, independently versioned runner-runtime support ceiling for one profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowRunnerFeaturePolicy {
    supported: BTreeSet<RunnerFeature>,
}

impl WorkflowRunnerFeaturePolicy {
    /// Constructs an exact current-schema runner-feature support set.
    ///
    /// # Errors
    ///
    /// Rejects more than 64 raw values, duplicates, and syntactically valid
    /// feature identifiers whose semantics this control plane does not know.
    pub fn new(
        supported: impl IntoIterator<Item = RunnerFeature>,
    ) -> Result<Self, WorkflowRuntimePolicyValueError> {
        let raw = supported.into_iter().collect::<Vec<_>>();
        if raw.len() > MAX_WORKFLOW_RUNTIME_POLICY_RUNNER_FEATURES {
            return Err(WorkflowRuntimePolicyValueError::TooManyRunnerFeatures);
        }
        if raw.iter().any(|feature| !known_runner_feature(feature)) {
            return Err(WorkflowRuntimePolicyValueError::UnknownRunnerFeature);
        }
        let supported = raw.iter().cloned().collect::<BTreeSet<_>>();
        if supported.len() != raw.len() {
            return Err(WorkflowRuntimePolicyValueError::DuplicateRunnerFeature);
        }
        Ok(Self { supported })
    }

    /// Returns the exact canonical feature support set.
    #[must_use]
    pub const fn supported(&self) -> &BTreeSet<RunnerFeature> {
        &self.supported
    }

    /// Returns the independently versioned feature-policy schema.
    #[must_use]
    pub const fn schema(&self) -> u16 {
        WORKFLOW_RUNTIME_POLICY_RUNNER_FEATURE_SCHEMA
    }
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
        runner_feature_policy: WorkflowRunnerFeaturePolicy,
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
        validate_profile_runner_features(&operating_system, &runner_feature_policy)?;
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
            runner_feature_policy: Some(runner_feature_policy),
            container_features,
        })
    }

    fn legacy(
        selector: RunnerLabel,
        environment: EnvironmentProfile,
        operating_system: OperatingSystem,
        architecture: Architecture,
        container_features: impl IntoIterator<Item = ContainerFeature>,
    ) -> Result<Self, WorkflowRuntimePolicyValueError> {
        let mut mapping = Self::new(
            selector,
            environment,
            operating_system,
            architecture,
            WorkflowRunnerFeaturePolicy::new([])?,
            container_features,
        )?;
        mapping.runner_feature_policy = None;
        Ok(mapping)
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

    /// Returns the exact support policy, or `None` only for historical schema 1.
    #[must_use]
    pub const fn runner_feature_policy(&self) -> Option<&WorkflowRunnerFeaturePolicy> {
        self.runner_feature_policy.as_ref()
    }

    /// Returns the exact canonical container-feature set.
    #[must_use]
    pub const fn container_features(&self) -> &BTreeSet<ContainerFeature> {
        &self.container_features
    }
}

/// Complete immutable non-secret runner, permission, resource, and workspace policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowRuntimePolicy {
    schema: u16,
    workspace_root: String,
    mappings: Vec<WorkflowRuntimePolicyMapping>,
    permission_policy: WorkflowPermissionPolicy,
    resource_policy: JobResourcePolicy,
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
        Self::decode(encoded, false, true)
    }

    /// Decodes immutable object bytes and requires their byte-exact canonical
    /// representation.
    ///
    /// # Errors
    ///
    /// Rejects malformed, excessive, invalid, or noncanonical policy bytes.
    pub fn decode_canonical(encoded: &[u8]) -> Result<Self, WorkflowRuntimePolicyValueError> {
        Self::decode(encoded, true, false)
    }

    fn decode(
        encoded: &[u8],
        require_canonical: bool,
        require_current: bool,
    ) -> Result<Self, WorkflowRuntimePolicyValueError> {
        if encoded.is_empty() || encoded.len() > MAX_WORKFLOW_RUNTIME_POLICY_BYTES {
            return Err(WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy);
        }
        let raw: RawPolicy = serde_json::from_slice(encoded)
            .map_err(|_| WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy)?;
        if !matches!(raw.schema, 1 | WORKFLOW_RUNTIME_POLICY_SCHEMA)
            || (require_current && raw.schema != WORKFLOW_RUNTIME_POLICY_SCHEMA)
            || raw.workspace.schema != WORKFLOW_RUNTIME_POLICY_WORKSPACE_SCHEMA
            || raw.workspace.root != WORKFLOW_RUNTIME_POLICY_WORKSPACE_ROOT
            || raw.workspace.derivation != WORKFLOW_WORKSPACE_DERIVATION_VERSION
            || raw.mappings.is_empty()
            || raw.mappings.len() > MAX_WORKFLOW_RUNTIME_POLICY_MAPPINGS
        {
            return Err(WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy);
        }
        let schema = raw.schema;
        let mappings = raw
            .mappings
            .into_iter()
            .map(|mapping| WorkflowRuntimePolicyMapping::try_from_raw(mapping, schema))
            .collect::<Result<Vec<_>, _>>()?;
        let permission_policy = WorkflowPermissionPolicy::try_from(raw.permissions)?;
        let policy = Self::from_decoded_parts(
            schema,
            raw.workspace.root,
            mappings,
            permission_policy,
            raw.resources,
        )?;
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
        permission_policy: WorkflowPermissionPolicy,
        resource_policy: JobResourcePolicy,
    ) -> Result<Self, WorkflowRuntimePolicyValueError> {
        Self::from_parts(
            workspace_root.into(),
            mappings,
            permission_policy,
            resource_policy,
        )
    }

    fn from_parts(
        workspace_root: String,
        mappings: impl IntoIterator<Item = WorkflowRuntimePolicyMapping>,
        permission_policy: WorkflowPermissionPolicy,
        resource_policy: JobResourcePolicy,
    ) -> Result<Self, WorkflowRuntimePolicyValueError> {
        Self::from_decoded_parts(
            WORKFLOW_RUNTIME_POLICY_SCHEMA,
            workspace_root,
            mappings,
            permission_policy,
            resource_policy,
        )
    }

    fn from_decoded_parts(
        schema: u16,
        workspace_root: String,
        mappings: impl IntoIterator<Item = WorkflowRuntimePolicyMapping>,
        permission_policy: WorkflowPermissionPolicy,
        resource_policy: JobResourcePolicy,
    ) -> Result<Self, WorkflowRuntimePolicyValueError> {
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
        if mappings.iter().any(|mapping| {
            mapping.runner_feature_policy().is_some() != (schema == WORKFLOW_RUNTIME_POLICY_SCHEMA)
        }) {
            return Err(WorkflowRuntimePolicyValueError::InvalidRunnerFeaturePolicy);
        }
        let mut policy = Self {
            schema,
            workspace_root,
            mappings,
            permission_policy,
            resource_policy,
            digest: Sha256Digest::from_bytes([0; 32]),
            canonical_digest: Sha256Digest::from_bytes([0; 32]),
        };
        let canonical = encode_canonical_policy(
            policy.schema(),
            policy.workspace_root(),
            policy.mappings(),
            policy.permission_policy(),
            policy.resource_policy(),
        )?;
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
        let encoded = encode_canonical_policy(
            self.schema(),
            self.workspace_root(),
            self.mappings(),
            self.permission_policy(),
            self.resource_policy(),
        )?;
        validate_canonical_policy_bytes(&encoded)?;
        Ok(encoded)
    }

    /// Returns the canonical POSIX workspace root.
    #[must_use]
    pub fn workspace_root(&self) -> &str {
        &self.workspace_root
    }

    /// Returns the immutable policy schema represented by this value.
    #[must_use]
    pub const fn schema(&self) -> u16 {
        self.schema
    }

    /// Returns mappings in canonical selector order.
    #[must_use]
    pub fn mappings(&self) -> &[WorkflowRuntimePolicyMapping] {
        &self.mappings
    }

    /// Returns the exact repository-pinned permission shorthand expansions.
    #[must_use]
    pub const fn permission_policy(&self) -> &WorkflowPermissionPolicy {
        &self.permission_policy
    }

    /// Returns the repository-pinned job-resource defaults and bounds.
    #[must_use]
    pub const fn resource_policy(&self) -> JobResourcePolicy {
        self.resource_policy
    }

    /// Returns the content-addressed policy digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the SHA-256 identity of [`Self::canonical_bytes`].
    ///
    /// This immutable-object identity is intentionally distinct from the
    /// domain-separated repository semantic [`Self::digest`].
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
    /// A revision was zero or outside the signed 64-bit storage boundary.
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
    /// One mapping exceeded the fixed runner-feature bound.
    #[error("workflow runtime policy mapping has too many runner features")]
    TooManyRunnerFeatures,
    /// One mapping repeated a runner feature before canonical set construction.
    #[error("workflow runtime policy mapping contains a duplicate runner feature")]
    DuplicateRunnerFeature,
    /// One mapping named a runner feature unknown to this policy schema.
    #[error("workflow runtime policy mapping contains an unknown runner feature")]
    UnknownRunnerFeature,
    /// A profile runner-feature policy was missing, wrongly versioned, or platform-invalid.
    #[error("workflow runtime policy runner feature policy is invalid")]
    InvalidRunnerFeaturePolicy,
    /// Permission shorthand expansions were empty, malformed, or inconsistent.
    #[error("workflow runtime permission policy is invalid")]
    InvalidPermissionPolicy,
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
    /// The repository failed or contained malformed current data.
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

fn known_runner_feature(feature: &RunnerFeature) -> bool {
    matches!(
        feature.as_str(),
        "automata.core/shell-steps@v1"
            | "automata.core/default-posix-shell@v1"
            | "automata.core/default-windows-shell@v1"
            | "automata.core/bash-shell@v1"
            | "automata.core/sh-shell@v1"
            | "automata.core/python-shell@v1"
            | "automata.core/pwsh-shell@v1"
            | "automata.core/windows-powershell-shell@v1"
            | "automata.core/cmd-shell@v1"
            | "automata.core/javascript-actions@v1"
            | "automata.core/node12-actions@v1"
            | "automata.core/node16-actions@v1"
            | "automata.core/node20-actions@v1"
            | "automata.core/node24-actions@v1"
            | "automata.core/composite-actions@v1"
            | "automata.core/repository-actions@v1"
            | "automata.core/local-actions@v1"
            | "automata.core/command-files@v1"
            | "automata.core/job-summaries@v1"
            | "automata.core/oidc-tokens@v1"
    )
}

fn validate_profile_runner_features(
    operating_system: &OperatingSystem,
    policy: &WorkflowRunnerFeaturePolicy,
) -> Result<(), WorkflowRuntimePolicyValueError> {
    let supported = policy.supported();
    let node = [
        &RunnerFeature::NODE12_ACTIONS,
        &RunnerFeature::NODE16_ACTIONS,
        &RunnerFeature::NODE20_ACTIONS,
        &RunnerFeature::NODE24_ACTIONS,
    ];
    if node.iter().any(|feature| supported.contains(*feature))
        && !supported.contains(&RunnerFeature::JAVASCRIPT_ACTIONS)
    {
        return Err(WorkflowRuntimePolicyValueError::InvalidRunnerFeaturePolicy);
    }
    match operating_system {
        OperatingSystem::Windows
            if supported.contains(&RunnerFeature::DEFAULT_POSIX_SHELL)
                || supported.iter().any(|feature| {
                    matches!(
                        feature.as_str(),
                        "automata.core/javascript-actions@v1"
                            | "automata.core/node12-actions@v1"
                            | "automata.core/node16-actions@v1"
                            | "automata.core/node20-actions@v1"
                            | "automata.core/node24-actions@v1"
                            | "automata.core/composite-actions@v1"
                            | "automata.core/repository-actions@v1"
                            | "automata.core/local-actions@v1"
                    )
                }) =>
        {
            Err(WorkflowRuntimePolicyValueError::InvalidRunnerFeaturePolicy)
        }
        OperatingSystem::Linux | OperatingSystem::Macos
            if supported.contains(&RunnerFeature::DEFAULT_WINDOWS_SHELL) =>
        {
            Err(WorkflowRuntimePolicyValueError::InvalidRunnerFeaturePolicy)
        }
        OperatingSystem::Other(_) => Err(WorkflowRuntimePolicyValueError::OpenPlatform),
        OperatingSystem::Linux | OperatingSystem::Windows | OperatingSystem::Macos => Ok(()),
    }
}

fn validate_permission_map(
    permissions: &BTreeMap<String, PermissionLevel>,
) -> Result<(), WorkflowRuntimePolicyValueError> {
    if permissions.is_empty() || permissions.len() > MAX_JOB_PERMISSION_GRANTS {
        return Err(WorkflowRuntimePolicyValueError::InvalidPermissionPolicy);
    }
    for (name, level) in permissions {
        if !canonical_permission_name(name)
            || *level == PermissionLevel::None
            || !catalog_allows(name, *level)
        {
            return Err(WorkflowRuntimePolicyValueError::InvalidPermissionPolicy);
        }
    }
    Ok(())
}

fn catalog_read_all() -> BTreeMap<String, PermissionLevel> {
    ACTIONS_WORKFLOW_PERMISSIONS
        .iter()
        .copied()
        .filter(|permission| permission.allows_read())
        .map(|permission| (permission.name().to_owned(), PermissionLevel::Read))
        .collect()
}

fn catalog_write_all() -> BTreeMap<String, PermissionLevel> {
    ACTIONS_WORKFLOW_PERMISSIONS
        .iter()
        .copied()
        .filter_map(|permission| {
            let level = if permission.allows_write() {
                PermissionLevel::Write
            } else if permission.allows_read() {
                PermissionLevel::Read
            } else {
                return None;
            };
            Some((permission.name().to_owned(), level))
        })
        .collect()
}

fn restricted_provider_default() -> BTreeMap<String, PermissionLevel> {
    BTreeMap::from([
        ("contents".to_owned(), PermissionLevel::Read),
        ("packages".to_owned(), PermissionLevel::Read),
    ])
}

fn provider_default_permissions(
    provider_default: ActionsDefaultWorkflowPermission,
) -> BTreeMap<String, PermissionLevel> {
    match provider_default {
        ActionsDefaultWorkflowPermission::Read => restricted_provider_default(),
        ActionsDefaultWorkflowPermission::Write => catalog_write_all(),
    }
}

fn matches_provider_default(provider_default: &BTreeMap<String, PermissionLevel>) -> bool {
    *provider_default == restricted_provider_default() || *provider_default == catalog_write_all()
}

fn catalog_allows(name: &str, level: PermissionLevel) -> bool {
    actions_workflow_permission(name).is_some_and(|permission| match level {
        PermissionLevel::Read => permission.allows_read(),
        PermissionLevel::Write => permission.allows_write(),
        PermissionLevel::None => true,
    })
}

fn canonical_permission_name(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_JOB_PERMISSION_NAME_BYTES {
        return false;
    }
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase()) {
        return false;
    }
    let mut previous_hyphen = false;
    for byte in bytes {
        if byte == b'-' {
            if previous_hyphen {
                return false;
            }
            previous_hyphen = true;
        } else if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            previous_hyphen = false;
        } else {
            return false;
        }
    }
    !previous_hyphen
}

const fn permission_level_code(value: PermissionLevel) -> u8 {
    match value {
        PermissionLevel::None => 0,
        PermissionLevel::Read => 1,
        PermissionLevel::Write => 2,
    }
}

fn deserialize_permission_map<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, PermissionLevel>, D::Error>
where
    D: Deserializer<'de>,
{
    struct PermissionMapVisitor;

    impl<'de> Visitor<'de> for PermissionMapVisitor {
        type Value = BTreeMap<String, PermissionLevel>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a unique permission-name map")
        }

        fn visit_map<A>(self, mut values: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut permissions = BTreeMap::new();
            while let Some((name, level)) = values.next_entry::<String, PermissionLevel>()? {
                if permissions.insert(name, level).is_some() {
                    return Err(serde::de::Error::custom("duplicate permission name"));
                }
            }
            Ok(permissions)
        }
    }

    deserializer.deserialize_map(PermissionMapVisitor)
}

fn policy_digest(policy: &WorkflowRuntimePolicy) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(POLICY_DIGEST_DOMAIN);
    hasher.update(policy.schema().to_be_bytes());
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
        if let Some(feature_policy) = mapping.runner_feature_policy() {
            hasher.update(b"runner-features\0");
            hasher.update(feature_policy.schema().to_be_bytes());
            hasher.update(
                u64::try_from(feature_policy.supported().len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            for feature in feature_policy.supported() {
                hash_text(&mut hasher, feature.as_str());
            }
        }
    }
    hasher.update(b"permissions\0");
    for (label, permissions) in [
        (
            b"provider-default\0".as_slice(),
            policy.permission_policy().provider_default(),
        ),
        (
            b"read-all\0".as_slice(),
            policy.permission_policy().read_all(),
        ),
        (
            b"write-all\0".as_slice(),
            policy.permission_policy().write_all(),
        ),
    ] {
        hasher.update(label);
        hasher.update(
            u64::try_from(permissions.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for (name, level) in permissions {
            hash_text(&mut hasher, name);
            hasher.update([permission_level_code(*level)]);
        }
    }
    let resources = policy.resource_policy();
    hasher.update(b"resources\0");
    for capacity in [
        resources.defaults().requests(),
        resources.defaults().limits(),
        resources.minimum_requests(),
        resources.maximum_limits(),
    ] {
        hasher.update(capacity.cpu_millis().to_be_bytes());
        hasher.update(capacity.memory_bytes().to_be_bytes());
        hasher.update(capacity.ephemeral_disk_bytes().to_be_bytes());
        hasher.update(capacity.gpu_count().to_be_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn encode_canonical_policy(
    schema: u16,
    workspace_root: &str,
    mappings: &[WorkflowRuntimePolicyMapping],
    permissions: &WorkflowPermissionPolicy,
    resources: JobResourcePolicy,
) -> Result<Vec<u8>, WorkflowRuntimePolicyValueError> {
    let canonical = CanonicalPolicy {
        schema,
        workspace: CanonicalWorkspace {
            schema: WORKFLOW_RUNTIME_POLICY_WORKSPACE_SCHEMA,
            root: workspace_root,
            derivation: WORKFLOW_WORKSPACE_DERIVATION_VERSION,
        },
        mappings: mappings
            .iter()
            .map(CanonicalMapping::try_from)
            .collect::<Result<Vec<_>, _>>()?,
        permissions: CanonicalPermissionPolicy {
            provider_default: permissions.provider_default(),
            read_all: permissions.read_all(),
            write_all: permissions.write_all(),
        },
        resources,
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
    permissions: RawPermissionPolicy,
    resources: JobResourcePolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPermissionPolicy {
    #[serde(deserialize_with = "deserialize_permission_map")]
    provider_default: BTreeMap<String, PermissionLevel>,
    #[serde(deserialize_with = "deserialize_permission_map")]
    read_all: BTreeMap<String, PermissionLevel>,
    #[serde(deserialize_with = "deserialize_permission_map")]
    write_all: BTreeMap<String, PermissionLevel>,
}

impl TryFrom<RawPermissionPolicy> for WorkflowPermissionPolicy {
    type Error = WorkflowRuntimePolicyValueError;

    fn try_from(raw: RawPermissionPolicy) -> Result<Self, Self::Error> {
        Self::new(raw.provider_default, raw.read_all, raw.write_all)
    }
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
    runner_features: Option<RawRunnerFeaturePolicy>,
    container_features: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRunnerFeaturePolicy {
    schema: u16,
    supported: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvironmentProfile {
    id: String,
    manifest_sha256: Sha256Digest,
}

impl WorkflowRuntimePolicyMapping {
    fn try_from_raw(
        raw: RawMapping,
        policy_schema: u16,
    ) -> Result<Self, WorkflowRuntimePolicyValueError> {
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
        let operating_system = raw.operating_system.into();
        let architecture = raw.architecture.into();
        match (policy_schema, raw.runner_features) {
            (1, None) => Self::legacy(
                selector,
                environment,
                operating_system,
                architecture,
                features,
            ),
            (WORKFLOW_RUNTIME_POLICY_SCHEMA, Some(raw_policy))
                if raw_policy.schema == WORKFLOW_RUNTIME_POLICY_RUNNER_FEATURE_SCHEMA =>
            {
                if raw_policy.supported.len() > MAX_WORKFLOW_RUNTIME_POLICY_RUNNER_FEATURES {
                    return Err(WorkflowRuntimePolicyValueError::TooManyRunnerFeatures);
                }
                let supported = raw_policy
                    .supported
                    .into_iter()
                    .map(RunnerFeature::new)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| WorkflowRuntimePolicyValueError::InvalidRunnerFeaturePolicy)?;
                Self::new(
                    selector,
                    environment,
                    operating_system,
                    architecture,
                    WorkflowRunnerFeaturePolicy::new(supported)?,
                    features,
                )
            }
            _ => Err(WorkflowRuntimePolicyValueError::InvalidRunnerFeaturePolicy),
        }
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
    permissions: CanonicalPermissionPolicy<'a>,
    resources: JobResourcePolicy,
}

#[derive(Serialize)]
struct CanonicalPermissionPolicy<'a> {
    provider_default: &'a BTreeMap<String, PermissionLevel>,
    read_all: &'a BTreeMap<String, PermissionLevel>,
    write_all: &'a BTreeMap<String, PermissionLevel>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    runner_features: Option<CanonicalRunnerFeaturePolicy<'a>>,
    container_features: Vec<&'a str>,
}

#[derive(Serialize)]
struct CanonicalRunnerFeaturePolicy<'a> {
    schema: u16,
    supported: Vec<&'a str>,
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
            runner_features: mapping.runner_feature_policy().map(|policy| {
                CanonicalRunnerFeaturePolicy {
                    schema: policy.schema(),
                    supported: policy
                        .supported()
                        .iter()
                        .map(RunnerFeature::as_str)
                        .collect(),
                }
            }),
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
    use automata_ci_core::{
        JobResourceAllocation, JobResourcePolicy, MAX_CAPABILITY_ID_LENGTH, ResourceCapacity,
    };

    const POLICY: &[u8] = br#"{
      "workspace":{"derivation":1,"root":"/__w","schema":1},
      "mappings":[{
        "container_features":["automata.core/job-containers@v1"],
        "runner_features":{"schema":1,"supported":[
          "automata.core/shell-steps@v1",
          "automata.core/default-posix-shell@v1",
          "automata.core/bash-shell@v1",
          "automata.core/sh-shell@v1",
          "automata.core/command-files@v1",
          "automata.core/job-summaries@v1"
        ]},
        "architecture":"x86_64","operating_system":"linux",
        "environment_profile":{"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","id":"automata.example/ubuntu-24-04"},
        "selector":"Ubuntu-24.04"
      }],
      "permissions":{
        "provider_default":{"contents":"read","packages":"read"},
        "read_all":{"actions":"read","artifact-metadata":"read","attestations":"read","checks":"read","code-quality":"read","contents":"read","deployments":"read","discussions":"read","issues":"read","models":"read","packages":"read","pages":"read","pull-requests":"read","security-events":"read","statuses":"read","vulnerability-alerts":"read"},
        "write_all":{"actions":"write","artifact-metadata":"write","attestations":"write","checks":"write","code-quality":"write","contents":"write","deployments":"write","discussions":"write","id-token":"write","issues":"write","models":"read","packages":"write","pages":"write","pull-requests":"write","security-events":"write","statuses":"write","vulnerability-alerts":"read"}
      },
      "resources":{
        "maximum_limits":{"gpu_count":0,"ephemeral_disk_bytes":0,"memory_bytes":17179869184,"cpu_millis":8000},
        "minimum_requests":{"gpu_count":0,"ephemeral_disk_bytes":0,"memory_bytes":134217728,"cpu_millis":100},
        "defaults":{
          "limits":{"gpu_count":0,"ephemeral_disk_bytes":0,"memory_bytes":2147483648,"cpu_millis":2000},
          "requests":{"gpu_count":0,"ephemeral_disk_bytes":0,"memory_bytes":536870912,"cpu_millis":500}
        }
      },
      "schema":2
    }"#;
    const CANONICAL_POLICY: &[u8] = br#"{"schema":2,"workspace":{"schema":1,"root":"/__w","derivation":1},"mappings":[{"selector":"ubuntu-24.04","environment_profile":{"id":"automata.example/ubuntu-24-04","manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111"},"operating_system":"linux","architecture":"x86_64","runner_features":{"schema":1,"supported":["automata.core/bash-shell@v1","automata.core/command-files@v1","automata.core/default-posix-shell@v1","automata.core/job-summaries@v1","automata.core/sh-shell@v1","automata.core/shell-steps@v1"]},"container_features":["automata.core/job-containers@v1"]}],"permissions":{"provider_default":{"contents":"read","packages":"read"},"read_all":{"actions":"read","artifact-metadata":"read","attestations":"read","checks":"read","code-quality":"read","contents":"read","deployments":"read","discussions":"read","issues":"read","models":"read","packages":"read","pages":"read","pull-requests":"read","security-events":"read","statuses":"read","vulnerability-alerts":"read"},"write_all":{"actions":"write","artifact-metadata":"write","attestations":"write","checks":"write","code-quality":"write","contents":"write","deployments":"write","discussions":"write","id-token":"write","issues":"write","models":"read","packages":"write","pages":"write","pull-requests":"write","security-events":"write","statuses":"write","vulnerability-alerts":"read"}},"resources":{"defaults":{"requests":{"cpu_millis":500,"memory_bytes":536870912,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":2000,"memory_bytes":2147483648,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":134217728,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":8000,"memory_bytes":17179869184,"ephemeral_disk_bytes":0,"gpu_count":0}}}"#;
    const LEGACY_CANONICAL_POLICY: &[u8] = br#"{"schema":1,"workspace":{"schema":1,"root":"/__w","derivation":1},"mappings":[{"selector":"ubuntu-24.04","environment_profile":{"id":"automata.example/ubuntu-24-04","manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111"},"operating_system":"linux","architecture":"x86_64","container_features":["automata.core/job-containers@v1"]}],"permissions":{"provider_default":{"contents":"read","packages":"read"},"read_all":{"actions":"read","artifact-metadata":"read","attestations":"read","checks":"read","code-quality":"read","contents":"read","deployments":"read","discussions":"read","issues":"read","models":"read","packages":"read","pages":"read","pull-requests":"read","security-events":"read","statuses":"read","vulnerability-alerts":"read"},"write_all":{"actions":"write","artifact-metadata":"write","attestations":"write","checks":"write","code-quality":"write","contents":"write","deployments":"write","discussions":"write","id-token":"write","issues":"write","models":"read","packages":"write","pages":"write","pull-requests":"write","security-events":"write","statuses":"write","vulnerability-alerts":"read"}},"resources":{"defaults":{"requests":{"cpu_millis":500,"memory_bytes":536870912,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":2000,"memory_bytes":2147483648,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":134217728,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":8000,"memory_bytes":17179869184,"ephemeral_disk_bytes":0,"gpu_count":0}}}"#;

    #[test]
    fn resource_policy_is_canonical_pinned_evidence() {
        let policy = WorkflowRuntimePolicy::decode_configuration(POLICY).expect("policy");
        let resources = resource_policy();
        assert_eq!(policy.schema(), WORKFLOW_RUNTIME_POLICY_SCHEMA);
        let canonical = policy.canonical_bytes().expect("canonical");
        let decoded = WorkflowRuntimePolicy::decode_canonical(&canonical).expect("decode");
        assert_eq!(decoded.schema(), WORKFLOW_RUNTIME_POLICY_SCHEMA);
        assert_eq!(decoded.resource_policy(), resources);
        assert_eq!(decoded.digest(), policy.digest());
        assert!(
            std::str::from_utf8(&canonical)
                .expect("UTF-8")
                .contains("\"minimum_requests\"")
        );
    }

    #[test]
    fn missing_sections_and_noncurrent_schemas_fail_closed() {
        let current: serde_json::Value =
            serde_json::from_slice(CANONICAL_POLICY).expect("canonical policy JSON");

        let mut missing_resources = current.clone();
        missing_resources
            .as_object_mut()
            .expect("policy object")
            .remove("resources");
        assert_eq!(
            WorkflowRuntimePolicy::decode_configuration(
                &serde_json::to_vec(&missing_resources).expect("policy JSON")
            ),
            Err(WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy)
        );

        let mut missing_permissions = current.clone();
        missing_permissions
            .as_object_mut()
            .expect("policy object")
            .remove("permissions");
        assert_eq!(
            WorkflowRuntimePolicy::decode_configuration(
                &serde_json::to_vec(&missing_permissions).expect("policy JSON")
            ),
            Err(WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy)
        );

        let mut missing_runner_features = current.clone();
        missing_runner_features["mappings"][0]
            .as_object_mut()
            .expect("mapping object")
            .remove("runner_features");
        assert_eq!(
            WorkflowRuntimePolicy::decode_configuration(
                &serde_json::to_vec(&missing_runner_features).expect("policy JSON")
            ),
            Err(WorkflowRuntimePolicyValueError::InvalidRunnerFeaturePolicy)
        );

        for unsupported in [0, 3, u16::MAX] {
            let mut document = current.clone();
            document["schema"] = serde_json::json!(unsupported);
            assert_eq!(
                WorkflowRuntimePolicy::decode_configuration(
                    &serde_json::to_vec(&document).expect("policy JSON")
                ),
                Err(WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy)
            );

            let mut workspace_schema = current.clone();
            workspace_schema["workspace"]["schema"] = serde_json::json!(unsupported);
            assert_eq!(
                WorkflowRuntimePolicy::decode_configuration(
                    &serde_json::to_vec(&workspace_schema).expect("policy JSON")
                ),
                Err(WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy)
            );

            let mut derivation = current.clone();
            derivation["workspace"]["derivation"] = serde_json::json!(unsupported);
            assert_eq!(
                WorkflowRuntimePolicy::decode_configuration(
                    &serde_json::to_vec(&derivation).expect("policy JSON")
                ),
                Err(WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy)
            );
        }
        let mut legacy = current.clone();
        legacy["schema"] = serde_json::json!(1);
        assert!(
            WorkflowRuntimePolicy::decode_configuration(
                &serde_json::to_vec(&legacy).expect("policy JSON")
            )
            .is_err()
        );
        for unsupported in [0, 2, 3, u16::MAX] {
            let mut feature_schema = current.clone();
            feature_schema["mappings"][0]["runner_features"]["schema"] =
                serde_json::json!(unsupported);
            assert_eq!(
                WorkflowRuntimePolicy::decode_configuration(
                    &serde_json::to_vec(&feature_schema).expect("policy JSON")
                ),
                Err(WorkflowRuntimePolicyValueError::InvalidRunnerFeaturePolicy)
            );
        }
    }

    #[test]
    fn canonical_bytes_and_digest_have_exact_golden_identities() {
        let policy = WorkflowRuntimePolicy::decode_configuration(POLICY).expect("configuration");
        let encoded = policy.canonical_bytes().expect("canonical bytes");
        assert_eq!(encoded, CANONICAL_POLICY);
        assert_eq!(
            policy.canonical_digest(),
            Sha256Digest::from_bytes(Sha256::digest(&encoded).into())
        );
        assert_eq!(
            policy.digest().to_string(),
            "1b1591aafd25b957e5add450f14aaf2404a60ac964d075bae0aaf5bb5ba8826b"
        );
        assert_eq!(
            policy.canonical_digest().to_string(),
            "83589132879d5a75c8c7cff2b067080f0fd7f90034171a9e5950d16418fe94ea"
        );
        assert_ne!(policy.digest(), policy.canonical_digest());
        assert_eq!(
            WorkflowRuntimePolicy::decode_canonical(&encoded).expect("canonical object"),
            policy
        );
    }

    #[test]
    fn historical_schema_one_replays_byte_and_digest_exactly_but_is_not_new_configuration() {
        let legacy = WorkflowRuntimePolicy::decode_canonical(LEGACY_CANONICAL_POLICY)
            .expect("historical canonical policy");
        assert_eq!(legacy.schema(), 1);
        assert!(legacy.mappings()[0].runner_feature_policy().is_none());
        assert_eq!(
            legacy.canonical_bytes().expect("historical bytes"),
            LEGACY_CANONICAL_POLICY
        );
        assert_eq!(
            legacy.digest().to_string(),
            "b7fabdda7258224aae1ed1fd4f015b947888ba1a0dc2f13feae11151a6ffebc2"
        );
        assert_eq!(
            legacy.canonical_digest().to_string(),
            "6b7d4868b6d58ae27ebfa9606419209faa17eba81542d85929008dcf3a446814"
        );
        assert!(WorkflowRuntimePolicy::decode_configuration(LEGACY_CANONICAL_POLICY).is_err());
    }

    #[test]
    fn constructor_accepts_exact_canonical_limit_and_rejects_one_byte_more() {
        let exact_mappings = boundary_mappings(MAX_WORKFLOW_RUNTIME_POLICY_BYTES);
        let exact = WorkflowRuntimePolicy::new(
            WORKFLOW_RUNTIME_POLICY_WORKSPACE_ROOT,
            exact_mappings.clone(),
            permission_policy(),
            resource_policy(),
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
            WorkflowRuntimePolicy::new(
                WORKFLOW_RUNTIME_POLICY_WORKSPACE_ROOT,
                oversized_mappings,
                permission_policy(),
                resource_policy(),
            ),
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
            permission_policy(),
            resource_policy(),
        )
        .expect("exact mapping-count limit");
        assert_eq!(exact.mappings().len(), MAX_WORKFLOW_RUNTIME_POLICY_MAPPINGS);

        let excessive_padding = vec![vec![0]; 65];
        let excessive_mappings = build_boundary_mappings(&excessive_padding);
        assert_eq!(
            WorkflowRuntimePolicy::new(
                WORKFLOW_RUNTIME_POLICY_WORKSPACE_ROOT,
                excessive_mappings,
                permission_policy(),
                resource_policy(),
            ),
            Err(WorkflowRuntimePolicyValueError::InvalidMappingCount)
        );
    }

    #[test]
    fn duplicate_raw_object_fields_are_rejected_even_when_values_are_equal() {
        let canonical = std::str::from_utf8(CANONICAL_POLICY).expect("UTF-8 canonical policy");
        let duplicate_top_schema =
            canonical.replacen(r#""schema":2"#, r#""schema":2,"schema":2"#, 1);
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
        let duplicate_runner_features = canonical.replacen(
            r#""runner_features":{"schema":1"#,
            r#""runner_features":{"schema":1,"schema":1"#,
            1,
        );
        let duplicate_supported = canonical.replacen(
            r#""supported":["automata.core/bash-shell@v1""#,
            r#""supported":["automata.core/bash-shell@v1"],"supported":["automata.core/bash-shell@v1""#,
            1,
        );
        let duplicate_permission = canonical.replacen(
            r#""provider_default":{"contents":"read","packages":"read"}"#,
            r#""provider_default":{"contents":"read","contents":"read","packages":"read"}"#,
            1,
        );
        for duplicate in [
            duplicate_top_schema,
            duplicate_workspace_schema,
            duplicate_selector,
            duplicate_profile_id,
            duplicate_runner_features,
            duplicate_supported,
            duplicate_permission,
        ] {
            assert_eq!(
                WorkflowRuntimePolicy::decode_configuration(duplicate.as_bytes()),
                Err(WorkflowRuntimePolicyValueError::InvalidCanonicalPolicy)
            );
        }
    }

    #[test]
    fn permission_policy_rejects_ambiguous_or_inconsistent_expansions() {
        let valid = permission_policy();
        assert_eq!(
            valid.resolve(JobPermissionRequest::ProviderDefault),
            JobPermissionRequest::mapping([
                JobPermissionGrant::new("contents", PermissionLevel::Read),
                JobPermissionGrant::new("packages", PermissionLevel::Read),
            ])
        );
        for invalid in [
            WorkflowPermissionPolicy::new(
                BTreeMap::new(),
                valid.read_all().clone(),
                valid.write_all().clone(),
            ),
            WorkflowPermissionPolicy::new(
                valid.provider_default().clone(),
                BTreeMap::from([("id-token".to_owned(), PermissionLevel::Read)]),
                BTreeMap::from([("id-token".to_owned(), PermissionLevel::Write)]),
            ),
            WorkflowPermissionPolicy::new(
                BTreeMap::from([("future-scope".to_owned(), PermissionLevel::Read)]),
                valid.read_all().clone(),
                valid.write_all().clone(),
            ),
            WorkflowPermissionPolicy::new(
                BTreeMap::from([("vulnerability-alerts".to_owned(), PermissionLevel::Write)]),
                valid.read_all().clone(),
                valid.write_all().clone(),
            ),
        ] {
            assert_eq!(
                invalid,
                Err(WorkflowRuntimePolicyValueError::InvalidPermissionPolicy)
            );
        }
    }

    #[test]
    fn github_provider_defaults_are_closed_and_round_trip() {
        let restricted =
            WorkflowPermissionPolicy::from_github_default(ActionsDefaultWorkflowPermission::Read)
                .expect("restricted GitHub default");
        assert_eq!(
            restricted.provider_default(),
            &BTreeMap::from([
                ("contents".to_owned(), PermissionLevel::Read),
                ("packages".to_owned(), PermissionLevel::Read),
            ])
        );
        assert_eq!(
            restricted.github_default(),
            ActionsDefaultWorkflowPermission::Read
        );

        let permissive =
            WorkflowPermissionPolicy::from_github_default(ActionsDefaultWorkflowPermission::Write)
                .expect("permissive GitHub default");
        assert_eq!(permissive.provider_default(), permissive.write_all());
        assert_eq!(
            permissive.github_default(),
            ActionsDefaultWorkflowPermission::Write
        );

        for arbitrary_subset in [
            BTreeMap::from([("contents".to_owned(), PermissionLevel::Read)]),
            BTreeMap::from([
                ("contents".to_owned(), PermissionLevel::Read),
                ("issues".to_owned(), PermissionLevel::Read),
                ("packages".to_owned(), PermissionLevel::Read),
            ]),
        ] {
            assert_eq!(
                WorkflowPermissionPolicy::from_provider_default(arbitrary_subset),
                Err(WorkflowRuntimePolicyValueError::InvalidPermissionPolicy)
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
                mapping
                    .runner_feature_policy()
                    .expect("current feature policy")
                    .clone(),
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
                mapping
                    .runner_feature_policy()
                    .expect("current feature policy")
                    .clone(),
                features,
            ),
            Err(WorkflowRuntimePolicyValueError::TooManyFeatures)
        );
    }

    #[test]
    fn runner_feature_policy_rejects_raw_bounds_duplicates_unknowns_and_windows_actions() {
        assert_eq!(
            WorkflowRunnerFeaturePolicy::new(std::iter::repeat_n(RunnerFeature::SHELL_STEPS, 65)),
            Err(WorkflowRuntimePolicyValueError::TooManyRunnerFeatures)
        );
        assert_eq!(
            WorkflowRunnerFeaturePolicy::new([
                RunnerFeature::SHELL_STEPS,
                RunnerFeature::SHELL_STEPS,
            ]),
            Err(WorkflowRuntimePolicyValueError::DuplicateRunnerFeature)
        );
        assert_eq!(
            WorkflowRunnerFeaturePolicy::new([RunnerFeature::new(
                "example.test/future-runtime@v1"
            )
            .expect("syntactically valid future feature")]),
            Err(WorkflowRuntimePolicyValueError::UnknownRunnerFeature)
        );

        let current: serde_json::Value =
            serde_json::from_slice(CANONICAL_POLICY).expect("canonical policy JSON");
        for (supported, expected) in [
            (
                vec![RunnerFeature::SHELL_STEPS.as_str(); 65],
                WorkflowRuntimePolicyValueError::TooManyRunnerFeatures,
            ),
            (
                vec![
                    RunnerFeature::SHELL_STEPS.as_str(),
                    RunnerFeature::SHELL_STEPS.as_str(),
                ],
                WorkflowRuntimePolicyValueError::DuplicateRunnerFeature,
            ),
            (
                vec!["example.test/future-runtime@v1"],
                WorkflowRuntimePolicyValueError::UnknownRunnerFeature,
            ),
        ] {
            let mut document = current.clone();
            document["mappings"][0]["runner_features"]["supported"] = serde_json::json!(supported);
            assert_eq!(
                WorkflowRuntimePolicy::decode_configuration(
                    &serde_json::to_vec(&document).expect("policy JSON")
                ),
                Err(expected)
            );
        }

        let policy = WorkflowRuntimePolicy::decode_configuration(POLICY).expect("configuration");
        let mapping = &policy.mappings()[0];
        assert_eq!(
            WorkflowRuntimePolicyMapping::new(
                mapping.selector().clone(),
                mapping.environment().clone(),
                OperatingSystem::Windows,
                Architecture::X86_64,
                WorkflowRunnerFeaturePolicy::new([
                    RunnerFeature::SHELL_STEPS,
                    RunnerFeature::JAVASCRIPT_ACTIONS,
                    RunnerFeature::NODE24_ACTIONS,
                ])
                .expect("known feature policy"),
                [],
            ),
            Err(WorkflowRuntimePolicyValueError::InvalidRunnerFeaturePolicy)
        );
    }

    #[test]
    fn workspace_and_policy_selector_grammar_are_closed() {
        let policy = WorkflowRuntimePolicy::decode_configuration(POLICY).expect("configuration");
        assert_eq!(policy.workspace_root(), "/__w");
        assert!(
            WorkflowRuntimePolicy::new(
                "/tmp",
                policy.mappings().iter().cloned(),
                permission_policy(),
                resource_policy(),
            )
            .is_err()
        );
        let unicode = RunnerLabel::new("İstanbul").expect("general runner label");
        let mapping = &policy.mappings()[0];
        assert_eq!(
            WorkflowRuntimePolicyMapping::new(
                unicode,
                mapping.environment().clone(),
                OperatingSystem::Linux,
                Architecture::X86_64,
                runner_feature_policy(),
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
        let base_size = encode_canonical_policy(
            WORKFLOW_RUNTIME_POLICY_SCHEMA,
            WORKFLOW_RUNTIME_POLICY_WORKSPACE_ROOT,
            &base,
            &permission_policy(),
            resource_policy(),
        )
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
            encode_canonical_policy(
                WORKFLOW_RUNTIME_POLICY_SCHEMA,
                WORKFLOW_RUNTIME_POLICY_WORKSPACE_ROOT,
                &mappings,
                &permission_policy(),
                resource_policy(),
            )
            .expect("boundary encoding")
            .len(),
            target_size
        );
        mappings
    }

    fn permission_policy() -> WorkflowPermissionPolicy {
        WorkflowPermissionPolicy::from_github_default(ActionsDefaultWorkflowPermission::Read)
            .expect("permission policy")
    }

    fn runner_feature_policy() -> WorkflowRunnerFeaturePolicy {
        WorkflowRunnerFeaturePolicy::new([
            RunnerFeature::SHELL_STEPS,
            RunnerFeature::DEFAULT_POSIX_SHELL,
            RunnerFeature::BASH_SHELL,
            RunnerFeature::SH_SHELL,
            RunnerFeature::COMMAND_FILES,
            RunnerFeature::JOB_SUMMARIES,
        ])
        .expect("runner feature policy")
    }

    fn resource_policy() -> JobResourcePolicy {
        let defaults = JobResourceAllocation::new(
            ResourceCapacity::new(500, 512 * 1_024 * 1_024, 0, 0),
            ResourceCapacity::new(2_000, 2 * 1_024 * 1_024 * 1_024, 0, 0),
        )
        .expect("defaults");
        JobResourcePolicy::new(
            defaults,
            ResourceCapacity::new(100, 128 * 1_024 * 1_024, 0, 0),
            ResourceCapacity::new(8_000, 16 * 1_024 * 1_024 * 1_024, 0, 0),
        )
        .expect("resource policy")
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
                    runner_feature_policy(),
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
