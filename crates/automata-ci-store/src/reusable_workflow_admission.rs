//! Typed immutable reusable-workflow expansion attached to run admission.

use automata_ci_core::{
    GitObjectId, InvocationInputType, OutputSensitivity, PermissionLevel, Sha256Digest,
    WorkflowJobKey,
};

use crate::{
    AdmissionObject, JobCredentialRequirements, LogicalWorkflowInvocationId, LogicalWorkflowJobId,
    WorkflowSnapshotId,
};

/// One exact source/plan pair in a repository-local reusable-workflow catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedReusableWorkflowCatalogEntry {
    id: WorkflowSnapshotId,
    workflow_path: String,
    source_revision: GitObjectId,
    source: AdmissionObject,
    plan: AdmissionObject,
    invocation_contract_digest: Option<Sha256Digest>,
    descriptor_digest: Sha256Digest,
    logical_job_count: u16,
    reusable_call_count: u16,
}

impl AdmittedReusableWorkflowCatalogEntry {
    /// Creates one exact catalog entry. The enclosing graph validates cross-entry invariants.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        id: WorkflowSnapshotId,
        workflow_path: impl Into<String>,
        source_revision: GitObjectId,
        source: AdmissionObject,
        plan: AdmissionObject,
        invocation_contract_digest: Option<Sha256Digest>,
        descriptor_digest: Sha256Digest,
        logical_job_count: u16,
        reusable_call_count: u16,
    ) -> Self {
        Self {
            id,
            workflow_path: workflow_path.into(),
            source_revision,
            source,
            plan,
            invocation_contract_digest,
            descriptor_digest,
            logical_job_count,
            reusable_call_count,
        }
    }

    /// Returns the deterministic catalog identity.
    #[must_use]
    pub const fn id(&self) -> WorkflowSnapshotId {
        self.id
    }

    /// Returns the canonical repository-local path.
    #[must_use]
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    /// Returns the exact lowercase source revision.
    #[must_use]
    pub const fn source_revision(&self) -> GitObjectId {
        self.source_revision
    }

    /// Returns the exact source object.
    #[must_use]
    pub const fn source(&self) -> &AdmissionObject {
        &self.source
    }

    /// Returns the exact canonical plan object.
    #[must_use]
    pub const fn plan(&self) -> &AdmissionObject {
        &self.plan
    }

    /// Returns the declared invocation-contract digest, absent for the root.
    #[must_use]
    pub const fn invocation_contract_digest(&self) -> Option<Sha256Digest> {
        self.invocation_contract_digest
    }

    /// Returns the catalog descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(&self) -> Sha256Digest {
        self.descriptor_digest
    }

    /// Returns the plan's logical-job count.
    #[must_use]
    pub const fn logical_job_count(&self) -> u16 {
        self.logical_job_count
    }

    /// Returns the plan's reusable-call count.
    #[must_use]
    pub const fn reusable_call_count(&self) -> u16 {
        self.reusable_call_count
    }
}

/// Durable source of one typed reusable input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmittedReusableInputKind {
    /// A caller-supplied literal or compiled expression.
    Caller,
    /// A typed default declared by the callee.
    Default,
    /// The provider-defined zero value for an omitted optional input.
    ImplicitDefault,
}

impl AdmittedReusableInputKind {
    /// Returns the durable canonical name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Caller => "caller",
            Self::Default => "default",
            Self::ImplicitDefault => "implicit_default",
        }
    }
}

/// One typed, value-free reusable input ledger record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedReusableInput {
    key: String,
    input_type: InvocationInputType,
    kind: AdmittedReusableInputKind,
    value_digest: Option<Sha256Digest>,
}

impl AdmittedReusableInput {
    /// Creates one input ledger record.
    #[must_use]
    pub fn new(
        key: impl Into<String>,
        input_type: InvocationInputType,
        kind: AdmittedReusableInputKind,
        value_digest: Option<Sha256Digest>,
    ) -> Self {
        Self {
            key: key.into(),
            input_type,
            kind,
            value_digest,
        }
    }

    /// Returns the callee input key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the declared input type.
    #[must_use]
    pub const fn input_type(&self) -> InvocationInputType {
        self.input_type
    }

    /// Returns how the input obtains its value.
    #[must_use]
    pub const fn kind(&self) -> AdmittedReusableInputKind {
        self.kind
    }

    /// Returns the exact value/template digest when one exists.
    #[must_use]
    pub const fn value_digest(&self) -> Option<Sha256Digest> {
        self.value_digest
    }
}

/// One name-only reusable secret forwarding edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedReusableSecret {
    target: String,
    source: String,
}

impl AdmittedReusableSecret {
    /// Creates a name-only edge; no secret value is accepted here.
    #[must_use]
    pub fn new(target: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            source: source.into(),
        }
    }

    /// Returns the callee-visible name.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns the caller-side name.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// One declared callee workflow output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedReusableOutput {
    key: String,
    sensitivity: OutputSensitivity,
}

impl AdmittedReusableOutput {
    /// Creates one output contract record.
    #[must_use]
    pub fn new(key: impl Into<String>, sensitivity: OutputSensitivity) -> Self {
        Self {
            key: key.into(),
            sensitivity,
        }
    }

    /// Returns the workflow-output key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns its information-flow classification.
    #[must_use]
    pub const fn sensitivity(&self) -> OutputSensitivity {
        self.sensitivity
    }
}

/// One normalized least-authority permission snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedReusablePermissions {
    default_level: PermissionLevel,
    grants: Vec<(String, PermissionLevel)>,
    digest: Sha256Digest,
}

impl AdmittedReusablePermissions {
    /// Creates an ordered permission snapshot.
    #[must_use]
    pub fn new(
        default_level: PermissionLevel,
        grants: Vec<(String, PermissionLevel)>,
        digest: Sha256Digest,
    ) -> Self {
        Self {
            default_level,
            grants,
            digest,
        }
    }

    /// Returns the unlisted-scope level.
    #[must_use]
    pub const fn default_level(&self) -> PermissionLevel {
        self.default_level
    }

    /// Returns explicit grants in canonical name order.
    #[must_use]
    pub fn grants(&self) -> &[(String, PermissionLevel)] {
        &self.grants
    }

    /// Returns the canonical permission descriptor digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// One deterministic logical job in a planned invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedReusableJob {
    id: LogicalWorkflowJobId,
    key: WorkflowJobKey,
    source_order: u16,
    reusable: bool,
    descriptor_digest: Sha256Digest,
    prerequisites: Vec<LogicalWorkflowJobId>,
    credential_requirements: JobCredentialRequirements,
}

impl AdmittedReusableJob {
    /// Creates one planned logical job.
    #[must_use]
    pub fn new(
        id: LogicalWorkflowJobId,
        key: WorkflowJobKey,
        source_order: u16,
        reusable: bool,
        descriptor_digest: Sha256Digest,
        prerequisites: Vec<LogicalWorkflowJobId>,
    ) -> Self {
        Self {
            id,
            key,
            source_order,
            reusable,
            descriptor_digest,
            prerequisites,
            credential_requirements: JobCredentialRequirements::default(),
        }
    }

    /// Binds exact static credential references discovered from the child plan.
    #[must_use]
    pub fn with_credential_requirements(
        mut self,
        credential_requirements: JobCredentialRequirements,
    ) -> Self {
        self.credential_requirements = credential_requirements;
        self
    }

    /// Returns the deterministic job identity.
    #[must_use]
    pub const fn id(&self) -> LogicalWorkflowJobId {
        self.id
    }

    /// Returns the plan-local key.
    #[must_use]
    pub const fn key(&self) -> &WorkflowJobKey {
        &self.key
    }

    /// Returns the canonical source order.
    #[must_use]
    pub const fn source_order(&self) -> u16 {
        self.source_order
    }

    /// Reports whether the job is another reusable callsite.
    #[must_use]
    pub const fn is_reusable(&self) -> bool {
        self.reusable
    }

    /// Returns the job descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(&self) -> Sha256Digest {
        self.descriptor_digest
    }

    /// Returns direct prerequisites within this invocation.
    #[must_use]
    pub fn prerequisites(&self) -> &[LogicalWorkflowJobId] {
        &self.prerequisites
    }

    /// Returns immutable deployment and credential-reference requirements.
    #[must_use]
    pub const fn credential_requirements(&self) -> &JobCredentialRequirements {
        &self.credential_requirements
    }
}

/// One occurrence in the immutable reusable-workflow call graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedReusableInvocation {
    id: LogicalWorkflowInvocationId,
    parent_id: Option<LogicalWorkflowInvocationId>,
    caller_job_id: Option<LogicalWorkflowJobId>,
    catalog_entry_id: WorkflowSnapshotId,
    depth: u16,
    call_path: Vec<String>,
    workflow_path: String,
    source_digest: Sha256Digest,
    plan_digest: Sha256Digest,
    call_reference_digest: Option<Sha256Digest>,
    input_bindings_digest: Sha256Digest,
    secret_bindings_digest: Sha256Digest,
    output_contract_digest: Sha256Digest,
    descriptor_digest: Sha256Digest,
    inputs: Vec<AdmittedReusableInput>,
    secrets: Vec<AdmittedReusableSecret>,
    outputs: Vec<AdmittedReusableOutput>,
    permissions: AdmittedReusablePermissions,
    jobs: Vec<AdmittedReusableJob>,
}

impl AdmittedReusableInvocation {
    /// Creates one planned invocation occurrence.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        id: LogicalWorkflowInvocationId,
        parent_id: Option<LogicalWorkflowInvocationId>,
        caller_job_id: Option<LogicalWorkflowJobId>,
        catalog_entry_id: WorkflowSnapshotId,
        depth: u16,
        call_path: Vec<String>,
        workflow_path: impl Into<String>,
        source_digest: Sha256Digest,
        plan_digest: Sha256Digest,
        call_reference_digest: Option<Sha256Digest>,
        input_bindings_digest: Sha256Digest,
        secret_bindings_digest: Sha256Digest,
        output_contract_digest: Sha256Digest,
        descriptor_digest: Sha256Digest,
        inputs: Vec<AdmittedReusableInput>,
        secrets: Vec<AdmittedReusableSecret>,
        outputs: Vec<AdmittedReusableOutput>,
        permissions: AdmittedReusablePermissions,
        jobs: Vec<AdmittedReusableJob>,
    ) -> Self {
        Self {
            id,
            parent_id,
            caller_job_id,
            catalog_entry_id,
            depth,
            call_path,
            workflow_path: workflow_path.into(),
            source_digest,
            plan_digest,
            call_reference_digest,
            input_bindings_digest,
            secret_bindings_digest,
            output_contract_digest,
            descriptor_digest,
            inputs,
            secrets,
            outputs,
            permissions,
            jobs,
        }
    }

    /// Returns the deterministic invocation ID.
    #[must_use]
    pub const fn id(&self) -> LogicalWorkflowInvocationId {
        self.id
    }
    /// Returns the parent invocation, absent only for the root.
    #[must_use]
    pub const fn parent_id(&self) -> Option<LogicalWorkflowInvocationId> {
        self.parent_id
    }
    /// Returns the parent callsite job, absent only for the root.
    #[must_use]
    pub const fn caller_job_id(&self) -> Option<LogicalWorkflowJobId> {
        self.caller_job_id
    }
    /// Returns the exact catalog entry.
    #[must_use]
    pub const fn catalog_entry_id(&self) -> WorkflowSnapshotId {
        self.catalog_entry_id
    }
    /// Returns zero-based call depth.
    #[must_use]
    pub const fn depth(&self) -> u16 {
        self.depth
    }
    /// Returns the root-to-current canonical path.
    #[must_use]
    pub fn call_path(&self) -> &[String] {
        &self.call_path
    }
    /// Returns this occurrence's canonical workflow path.
    #[must_use]
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }
    /// Returns its exact source digest.
    #[must_use]
    pub const fn source_digest(&self) -> Sha256Digest {
        self.source_digest
    }
    /// Returns its exact plan digest.
    #[must_use]
    pub const fn plan_digest(&self) -> Sha256Digest {
        self.plan_digest
    }
    /// Returns the parent call-reference digest.
    #[must_use]
    pub const fn call_reference_digest(&self) -> Option<Sha256Digest> {
        self.call_reference_digest
    }
    /// Returns the ordered input-binding digest.
    #[must_use]
    pub const fn input_bindings_digest(&self) -> Sha256Digest {
        self.input_bindings_digest
    }
    /// Returns the ordered secret-binding digest.
    #[must_use]
    pub const fn secret_bindings_digest(&self) -> Sha256Digest {
        self.secret_bindings_digest
    }
    /// Returns the declared output-contract digest.
    #[must_use]
    pub const fn output_contract_digest(&self) -> Sha256Digest {
        self.output_contract_digest
    }
    /// Returns the complete invocation descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(&self) -> Sha256Digest {
        self.descriptor_digest
    }
    /// Returns typed inputs in contract order.
    #[must_use]
    pub fn inputs(&self) -> &[AdmittedReusableInput] {
        &self.inputs
    }
    /// Returns name-only secret edges in contract order.
    #[must_use]
    pub fn secrets(&self) -> &[AdmittedReusableSecret] {
        &self.secrets
    }
    /// Returns declared outputs in contract order.
    #[must_use]
    pub fn outputs(&self) -> &[AdmittedReusableOutput] {
        &self.outputs
    }
    /// Returns the least-authority permission snapshot.
    #[must_use]
    pub const fn permissions(&self) -> &AdmittedReusablePermissions {
        &self.permissions
    }
    /// Returns planned jobs in source order.
    #[must_use]
    pub fn jobs(&self) -> &[AdmittedReusableJob] {
        &self.jobs
    }
    /// Returns the total dependency edge count.
    #[must_use]
    pub fn dependency_count(&self) -> usize {
        self.jobs.iter().map(|job| job.prerequisites.len()).sum()
    }
}

/// Complete immutable call graph persisted in the root admission transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedReusableWorkflowExpansion {
    digest: Sha256Digest,
    catalog: Vec<AdmittedReusableWorkflowCatalogEntry>,
    invocations: Vec<AdmittedReusableInvocation>,
}

impl AdmittedReusableWorkflowExpansion {
    /// Creates a complete graph. The repository revalidates counts, cycles,
    /// and reductions at commit.
    #[must_use]
    pub fn new(
        digest: Sha256Digest,
        catalog: Vec<AdmittedReusableWorkflowCatalogEntry>,
        invocations: Vec<AdmittedReusableInvocation>,
    ) -> Self {
        Self {
            digest,
            catalog,
            invocations,
        }
    }

    /// Returns the exact expansion replay digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
    /// Returns exact catalog entries in canonical path order.
    #[must_use]
    pub fn catalog(&self) -> &[AdmittedReusableWorkflowCatalogEntry] {
        &self.catalog
    }
    /// Returns invocation occurrences in deterministic pre-order.
    #[must_use]
    pub fn invocations(&self) -> &[AdmittedReusableInvocation] {
        &self.invocations
    }
    /// Returns the aggregate planned-job count.
    #[must_use]
    pub fn job_count(&self) -> usize {
        self.invocations
            .iter()
            .map(|invocation| invocation.jobs.len())
            .sum()
    }
    /// Returns the maximum call depth.
    #[must_use]
    pub fn maximum_depth(&self) -> u16 {
        self.invocations
            .iter()
            .map(AdmittedReusableInvocation::depth)
            .max()
            .unwrap_or(0)
    }
}
