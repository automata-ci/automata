//! Exact-source planning for repository-local reusable workflows.
//!
//! This module deliberately stops before executable-job publication. It
//! produces an immutable, deterministic expansion ledger that can be committed
//! with admission and composed into the orchestration graph by a later fenced
//! phase. Keeping that boundary explicit prevents nested plans from being
//! mistaken for already-authorized runner work.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    path::Path,
    sync::Arc,
};

use automata_ci_core::{
    CompiledValueTemplate, ExpressionInstruction, ExpressionLiteral, ExpressionSegment,
    InvocationInputDefault, InvocationInputType, LogicalJobKind, LogicalJobOutputSource,
    OutputSensitivity, PermissionLevel, PermissionSnapshotRequest, PlanSourceOrigin,
    ReusableSecretForwarding, ReusableWorkflowInvocation, RunId, Sha256Digest,
    WorkflowInvocationContract, WorkflowJobKey, WorkflowPermissions, WorkflowPlan,
};
use automata_ci_store::{LogicalWorkflowInvocationId, LogicalWorkflowJobId};
use automata_ci_workflow_github::{
    CompileWorkflowRequest, Diagnostic, GithubWorkflowCompiler, GithubWorkflowFrontend,
    ParseWorkflowRequest, SourceId, SourceOrigin, SourceProvenance, WorkflowFrontend as _,
};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Maximum repository workflow files accepted by one reusable catalog.
pub const MAX_REUSABLE_WORKFLOW_CATALOG_ENTRIES: usize = 50;
/// Maximum caller-to-callee edges below the root invocation.
pub const MAX_REUSABLE_WORKFLOW_DEPTH: usize = 9;
/// Maximum invocation occurrences, including the root, in one expansion.
pub const MAX_REUSABLE_WORKFLOW_INVOCATIONS: usize = 256;
/// Maximum logical jobs across all invocation occurrences in one expansion.
pub const MAX_REUSABLE_WORKFLOW_EXPANDED_JOBS: usize = 4_096;

const MAX_REUSABLE_WORKFLOW_PATH_BYTES: usize = 1_024;
const MAX_REUSABLE_WORKFLOW_SOURCE_BYTES: usize = 16 * 1_024 * 1_024;
const MAX_PERMISSION_NAME_BYTES: usize = 256;
const MAX_PERMISSION_GRANTS: usize = 256;
const REUSABLE_INVOCATION_ID_DOMAIN: &[u8] = b"automata.reusable-workflow.invocation.v1\0";
const REUSABLE_JOB_ID_DOMAIN: &[u8] = b"automata.reusable-workflow.job.v1\0";
const ROOT_JOB_ID_DOMAIN: &[u8] = b"automata.admission.logical-job.v1\0";
const EXPANSION_DIGEST_DOMAIN: &[u8] = b"automata.reusable-workflow.expansion.v1\0";

/// Independent hard-bounded limits applied while constructing an expansion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReusableWorkflowLimits {
    depth: usize,
    invocations: usize,
    jobs: usize,
}

impl ReusableWorkflowLimits {
    /// Creates a policy no larger than the implementation hard limits.
    ///
    /// # Errors
    ///
    /// Rejects zero invocation/job ceilings or values above the corresponding
    /// public ceiling. A depth of zero permits a root with no calls.
    pub fn new(
        maximum_depth: usize,
        maximum_invocations: usize,
        maximum_jobs: usize,
    ) -> Result<Self, ReusableWorkflowExpansionError> {
        if maximum_depth > MAX_REUSABLE_WORKFLOW_DEPTH {
            return Err(ReusableWorkflowExpansionError::InvalidLimits);
        }
        if maximum_invocations == 0 || maximum_invocations > MAX_REUSABLE_WORKFLOW_INVOCATIONS {
            return Err(ReusableWorkflowExpansionError::InvalidLimits);
        }
        if maximum_jobs == 0 || maximum_jobs > MAX_REUSABLE_WORKFLOW_EXPANDED_JOBS {
            return Err(ReusableWorkflowExpansionError::InvalidLimits);
        }
        Ok(Self {
            depth: maximum_depth,
            invocations: maximum_invocations,
            jobs: maximum_jobs,
        })
    }

    /// Returns the maximum number of caller-to-callee edges.
    #[must_use]
    pub const fn maximum_depth(self) -> usize {
        self.depth
    }

    /// Returns the maximum invocation occurrence count, including the root.
    #[must_use]
    pub const fn maximum_invocations(self) -> usize {
        self.invocations
    }

    /// Returns the maximum expanded logical-job count.
    #[must_use]
    pub const fn maximum_jobs(self) -> usize {
        self.jobs
    }
}

impl Default for ReusableWorkflowLimits {
    fn default() -> Self {
        Self {
            depth: MAX_REUSABLE_WORKFLOW_DEPTH,
            invocations: MAX_REUSABLE_WORKFLOW_INVOCATIONS,
            jobs: MAX_REUSABLE_WORKFLOW_EXPANDED_JOBS,
        }
    }
}

/// One exact repository workflow source offered to the reusable catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryWorkflowSource {
    path: String,
    source: Bytes,
}

impl RepositoryWorkflowSource {
    /// Creates an uncompiled exact source candidate.
    #[must_use]
    pub fn new(path: impl Into<String>, source: Bytes) -> Self {
        Self {
            path: path.into(),
            source,
        }
    }

    /// Returns the candidate repository-relative path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the exact immutable source bytes.
    #[must_use]
    pub const fn source(&self) -> &Bytes {
        &self.source
    }
}

/// One exact, independently recompiled reusable workflow in a catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogedReusableWorkflow {
    path: String,
    source: Bytes,
    source_digest: Sha256Digest,
    plan: WorkflowPlan,
    plan_digest: Sha256Digest,
}

impl CatalogedReusableWorkflow {
    /// Returns the canonical repository-relative path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the exact immutable source bytes.
    #[must_use]
    pub const fn source(&self) -> &Bytes {
        &self.source
    }

    /// Returns the SHA-256 digest of the exact source bytes.
    #[must_use]
    pub const fn source_digest(&self) -> Sha256Digest {
        self.source_digest
    }

    /// Returns the exact-source recompiled `workflow_call` plan.
    #[must_use]
    pub const fn plan(&self) -> &WorkflowPlan {
        &self.plan
    }

    /// Returns the digest of the canonical serialized plan.
    #[must_use]
    pub const fn plan_digest(&self) -> Sha256Digest {
        self.plan_digest
    }
}

/// Closed exact-revision catalog used to resolve local workflow references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubReusableWorkflowCatalog {
    repository: String,
    revision: String,
    entries: BTreeMap<String, CatalogedReusableWorkflow>,
}

impl GithubReusableWorkflowCatalog {
    /// Recompiles and binds all supplied sources to one repository revision.
    ///
    /// # Errors
    ///
    /// Rejects invalid or duplicate paths, excessive catalogs, non-UTF-8 or
    /// rejected source, and workflows without an exact `workflow_call`
    /// contract.
    pub fn compile(
        repository: impl Into<String>,
        revision: impl Into<String>,
        sources: impl IntoIterator<Item = RepositoryWorkflowSource>,
    ) -> Result<Self, ReusableWorkflowExpansionError> {
        let repository = repository.into();
        let revision = revision.into();
        validate_coordinate(&repository)?;
        validate_exact_revision(&revision)?;
        let sources = sources.into_iter().collect::<Vec<_>>();
        if sources.len() > MAX_REUSABLE_WORKFLOW_CATALOG_ENTRIES {
            return Err(ReusableWorkflowExpansionError::CatalogLimitExceeded);
        }
        let mut entries = BTreeMap::new();
        for source in sources {
            let path = canonical_workflow_path(source.path())?;
            if source.source().is_empty()
                || source.source().len() > MAX_REUSABLE_WORKFLOW_SOURCE_BYTES
            {
                return Err(ReusableWorkflowExpansionError::InvalidSourceSize);
            }
            if entries.contains_key(&path) {
                return Err(ReusableWorkflowExpansionError::DuplicateCatalogPath(path));
            }
            let plan = compile_github_source(
                &repository,
                &revision,
                &path,
                source.source(),
                automata_ci_core::WorkflowEventProvenance::new("github", "workflow_call")
                    .with_commit_sha(&revision),
                false,
            )?;
            if plan.logical().invocation().is_none() {
                return Err(ReusableWorkflowExpansionError::MissingInvocationContract(
                    path,
                ));
            }
            let source_digest = digest(source.source());
            let plan_digest = digest_plan(&plan)?;
            entries.insert(
                path.clone(),
                CatalogedReusableWorkflow {
                    path,
                    source: source.source,
                    source_digest,
                    plan,
                    plan_digest,
                },
            );
        }
        Ok(Self {
            repository,
            revision,
            entries,
        })
    }

    /// Returns the immutable repository identity shared by all entries.
    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// Returns the immutable repository revision shared by all entries.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Returns entries ordered by canonical repository-relative path.
    #[must_use]
    pub fn entries(&self) -> impl ExactSizeIterator<Item = &CatalogedReusableWorkflow> {
        self.entries.values()
    }

    fn resolve(
        &self,
        reference: &str,
    ) -> Result<&CatalogedReusableWorkflow, ReusableWorkflowExpansionError> {
        let path = resolve_local_reference(reference)?;
        self.entries
            .get(&path)
            .ok_or(ReusableWorkflowExpansionError::MissingCatalogPath(path))
    }
}

/// Canonical least-authority provider permission ceiling for one invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReusableWorkflowPermissions {
    default: PermissionLevel,
    grants: BTreeMap<String, PermissionLevel>,
}

impl ReusableWorkflowPermissions {
    /// Creates a normalized root permission ceiling.
    ///
    /// Explicit entries equal to `default` are removed. Permission names must
    /// be nonempty, bounded, trimmed, and free of control characters.
    ///
    /// # Errors
    ///
    /// Rejects an invalid permission name.
    pub fn new(
        default: PermissionLevel,
        grants: impl IntoIterator<Item = (String, PermissionLevel)>,
    ) -> Result<Self, ReusableWorkflowExpansionError> {
        let mut normalized = BTreeMap::new();
        for (name, level) in grants {
            if normalized.len() >= MAX_PERMISSION_GRANTS {
                return Err(ReusableWorkflowExpansionError::PermissionLimitExceeded);
            }
            validate_permission_name(&name)?;
            if normalized.insert(name.clone(), level).is_some() {
                return Err(ReusableWorkflowExpansionError::DuplicatePermission(name));
            }
        }
        normalized.retain(|_, level| *level != default);
        Ok(Self {
            default,
            grants: normalized,
        })
    }

    /// Returns the permission level applied to unlisted scopes.
    #[must_use]
    pub const fn default_level(&self) -> PermissionLevel {
        self.default
    }

    /// Returns normalized explicit grants ordered by scope name.
    #[must_use]
    pub const fn grants(&self) -> &BTreeMap<String, PermissionLevel> {
        &self.grants
    }

    /// Resolves one scope against the default and explicit grants.
    #[must_use]
    pub fn level(&self, name: &str) -> PermissionLevel {
        self.grants.get(name).copied().unwrap_or(self.default)
    }

    fn reduce(&self, request: Option<&PermissionSnapshotRequest>) -> Self {
        let Some(request) = request else {
            return self.clone();
        };
        let requested = permissions_from_request(request.permissions());
        intersect_permissions(self, &requested)
    }
}

/// Why one invocation input obtains a value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReusableInputBindingSource {
    /// A caller-supplied literal or deferred compiled expression.
    Caller(CompiledValueTemplate),
    /// The callee's declared typed default.
    Default(InvocationInputDefault),
    /// The provider-defined zero value for an optional input without a default.
    ImplicitDefault,
}

/// One validated typed input binding retained for later activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpandedReusableInput {
    target: String,
    input_type: InvocationInputType,
    source: ReusableInputBindingSource,
}

impl ExpandedReusableInput {
    /// Returns the callee input name.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns the callee's declared type.
    #[must_use]
    pub const fn input_type(&self) -> InvocationInputType {
        self.input_type
    }

    /// Returns the validated caller/default source.
    #[must_use]
    pub const fn source(&self) -> &ReusableInputBindingSource {
        &self.source
    }
}

/// One name-only secret edge; no secret value enters the expansion ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpandedReusableSecret {
    target: String,
    source: String,
}

impl ExpandedReusableSecret {
    /// Returns the secret name visible in the callee.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns the caller-side secret name to resolve later.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// One reusable output contract entry exposed to its caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpandedReusableOutput {
    key: String,
    sensitivity: OutputSensitivity,
}

impl ExpandedReusableOutput {
    /// Returns the exported output key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the durable output sensitivity.
    #[must_use]
    pub const fn sensitivity(&self) -> OutputSensitivity {
        self.sensitivity
    }
}

/// One deterministic logical-job identity inside an invocation occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpandedReusableJob {
    id: LogicalWorkflowJobId,
    key: WorkflowJobKey,
    source_order: u16,
    reusable: bool,
    prerequisites: Vec<LogicalWorkflowJobId>,
}

impl ExpandedReusableJob {
    /// Returns the deterministic durable job identity.
    #[must_use]
    pub const fn id(&self) -> LogicalWorkflowJobId {
        self.id
    }

    /// Returns the plan-local job key.
    #[must_use]
    pub const fn key(&self) -> &WorkflowJobKey {
        &self.key
    }

    /// Returns the canonical source order within this invocation.
    #[must_use]
    pub const fn source_order(&self) -> u16 {
        self.source_order
    }

    /// Reports whether this is a reusable call coordinator rather than a step job.
    #[must_use]
    pub const fn is_reusable(&self) -> bool {
        self.reusable
    }

    /// Returns direct prerequisite identities within the same invocation.
    #[must_use]
    pub fn prerequisites(&self) -> &[LogicalWorkflowJobId] {
        &self.prerequisites
    }
}

/// One occurrence in the immutable reusable-workflow call graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReusableWorkflowInvocationExpansion {
    id: LogicalWorkflowInvocationId,
    parent_id: Option<LogicalWorkflowInvocationId>,
    caller_job_id: Option<LogicalWorkflowJobId>,
    depth: u16,
    workflow_path: String,
    source_digest: Sha256Digest,
    plan_digest: Sha256Digest,
    permissions: ReusableWorkflowPermissions,
    inputs: Vec<ExpandedReusableInput>,
    secrets: Vec<ExpandedReusableSecret>,
    outputs: Vec<ExpandedReusableOutput>,
    jobs: Vec<ExpandedReusableJob>,
}

impl ReusableWorkflowInvocationExpansion {
    /// Returns the deterministic invocation identity.
    #[must_use]
    pub const fn id(&self) -> LogicalWorkflowInvocationId {
        self.id
    }

    /// Returns the parent invocation, absent only for the root.
    #[must_use]
    pub const fn parent_id(&self) -> Option<LogicalWorkflowInvocationId> {
        self.parent_id
    }

    /// Returns the parent call-job identity, absent only for the root.
    #[must_use]
    pub const fn caller_job_id(&self) -> Option<LogicalWorkflowJobId> {
        self.caller_job_id
    }

    /// Returns the zero-based call depth.
    #[must_use]
    pub const fn depth(&self) -> u16 {
        self.depth
    }

    /// Returns the canonical repository-relative workflow path.
    #[must_use]
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    /// Returns the exact bound source digest.
    #[must_use]
    pub const fn source_digest(&self) -> Sha256Digest {
        self.source_digest
    }

    /// Returns the exact canonical-plan digest.
    #[must_use]
    pub const fn plan_digest(&self) -> Sha256Digest {
        self.plan_digest
    }

    /// Returns the caller/call/callee permission intersection.
    #[must_use]
    pub const fn permissions(&self) -> &ReusableWorkflowPermissions {
        &self.permissions
    }

    /// Returns typed input bindings in callee contract order.
    #[must_use]
    pub fn inputs(&self) -> &[ExpandedReusableInput] {
        &self.inputs
    }

    /// Returns name-only secret edges in callee contract order.
    #[must_use]
    pub fn secrets(&self) -> &[ExpandedReusableSecret] {
        &self.secrets
    }

    /// Returns exported outputs in callee contract order.
    #[must_use]
    pub fn outputs(&self) -> &[ExpandedReusableOutput] {
        &self.outputs
    }

    /// Returns deterministic source-ordered logical jobs.
    #[must_use]
    pub fn jobs(&self) -> &[ExpandedReusableJob] {
        &self.jobs
    }
}

/// Deterministic exact-source catalog and expansion ledger for one run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReusableWorkflowExpansion {
    run_id: RunId,
    root_invocation_id: LogicalWorkflowInvocationId,
    digest: Sha256Digest,
    invocations: Vec<ReusableWorkflowInvocationExpansion>,
}

impl ReusableWorkflowExpansion {
    /// Returns the server-owned run identity.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the root invocation identity supplied by admission.
    #[must_use]
    pub const fn root_invocation_id(&self) -> LogicalWorkflowInvocationId {
        self.root_invocation_id
    }

    /// Returns the canonical digest used to reject non-identical replay.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns invocation occurrences in deterministic depth-first call order.
    #[must_use]
    pub fn invocations(&self) -> &[ReusableWorkflowInvocationExpansion] {
        &self.invocations
    }
}

/// Borrowed exact inputs for constructing one reusable expansion.
#[derive(Clone, Copy, Debug)]
pub struct ExpandReusableWorkflowRequest<'a> {
    run_id: RunId,
    root_invocation_id: LogicalWorkflowInvocationId,
    root_path: &'a str,
    root_source: &'a [u8],
    root_plan: &'a WorkflowPlan,
    catalog: &'a GithubReusableWorkflowCatalog,
    root_secret_names: &'a BTreeSet<String>,
    root_permissions: &'a ReusableWorkflowPermissions,
}

impl<'a> ExpandReusableWorkflowRequest<'a> {
    /// Binds a root plan to exact source, catalog, caller secret names, and a
    /// provider-authorized permission ceiling.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        run_id: RunId,
        root_invocation_id: LogicalWorkflowInvocationId,
        root_path: &'a str,
        root_source: &'a [u8],
        root_plan: &'a WorkflowPlan,
        catalog: &'a GithubReusableWorkflowCatalog,
        root_secret_names: &'a BTreeSet<String>,
        root_permissions: &'a ReusableWorkflowPermissions,
    ) -> Self {
        Self {
            run_id,
            root_invocation_id,
            root_path,
            root_source,
            root_plan,
            catalog,
            root_secret_names,
            root_permissions,
        }
    }
}

/// Stateless exact-source reusable-workflow expansion planner.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReusableWorkflowExpander {
    limits: ReusableWorkflowLimits,
}

impl ReusableWorkflowExpander {
    /// Creates an expander with the public hard limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: ReusableWorkflowLimits {
                depth: MAX_REUSABLE_WORKFLOW_DEPTH,
                invocations: MAX_REUSABLE_WORKFLOW_INVOCATIONS,
                jobs: MAX_REUSABLE_WORKFLOW_EXPANDED_JOBS,
            },
        }
    }

    /// Creates an expander with a narrower validated policy.
    #[must_use]
    pub const fn with_limits(limits: ReusableWorkflowLimits) -> Self {
        Self { limits }
    }

    /// Builds an exact-source, typed, least-authority expansion ledger.
    ///
    /// No nested `JobIR` or runnable job is produced here.
    ///
    /// # Errors
    ///
    /// Rejects source/plan mismatches, non-local references, missing catalog
    /// entries, cycles, resource-limit exhaustion, incompatible typed
    /// inputs/secrets/outputs, matrix calls, and deterministic ID collisions.
    pub fn expand(
        &self,
        request: ExpandReusableWorkflowRequest<'_>,
    ) -> Result<ReusableWorkflowExpansion, ReusableWorkflowExpansionError> {
        expand_reusable_workflow(request, self.limits)
    }
}

/// Fail-closed reusable-workflow catalog or expansion failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ReusableWorkflowExpansionError {
    /// A configured limit is zero or exceeds the implementation ceiling.
    #[error("reusable workflow limits are invalid")]
    InvalidLimits,
    /// A repository or immutable revision coordinate is invalid.
    #[error("reusable workflow repository coordinates are invalid")]
    InvalidRepositoryCoordinate,
    /// A path is not a canonical direct `.github/workflows` YAML path.
    #[error("reusable workflow path is not canonical")]
    InvalidWorkflowPath,
    /// A call uses something other than a canonical `./...` repository-local reference.
    #[error("reusable workflow reference must be a canonical repository-local path")]
    NonLocalReference,
    /// More workflow sources were supplied than the catalog ceiling permits.
    #[error("reusable workflow catalog exceeds its entry limit")]
    CatalogLimitExceeded,
    /// The same canonical path appeared more than once.
    #[error("duplicate reusable workflow catalog path `{0}`")]
    DuplicateCatalogPath(String),
    /// A referenced canonical path was not present in the exact-revision catalog.
    #[error("reusable workflow catalog does not contain `{0}`")]
    MissingCatalogPath(String),
    /// Exact source was not valid UTF-8.
    #[error("reusable workflow source is not UTF-8")]
    InvalidSourceEncoding,
    /// Exact source was empty or exceeded the immutable object ceiling.
    #[error("reusable workflow source size is invalid")]
    InvalidSourceSize,
    /// The provider frontend rejected exact source.
    #[error("reusable workflow frontend rejected exact source: {0}")]
    FrontendRejected(String),
    /// The provider compiler rejected exact source for its selected event.
    #[error("reusable workflow compiler rejected exact source: {0}")]
    CompilationRejected(String),
    /// Canonical plan serialization failed.
    #[error("reusable workflow plan serialization failed")]
    PlanSerialization,
    /// Recompiling exact root source did not reproduce the supplied plan.
    #[error("reusable workflow root source and plan differ")]
    RootPlanMismatch,
    /// A catalog entry did not declare a `workflow_call` contract.
    #[error("reusable workflow `{0}` has no workflow_call contract")]
    MissingInvocationContract(String),
    /// A path recurred on the active call stack.
    #[error("reusable workflow call cycle reaches `{0}`")]
    Cycle(String),
    /// The configured call-depth ceiling was exceeded.
    #[error("reusable workflow expansion exceeds its depth limit")]
    DepthLimitExceeded,
    /// The configured invocation-count ceiling was exceeded.
    #[error("reusable workflow expansion exceeds its invocation limit")]
    InvocationLimitExceeded,
    /// The configured aggregate logical-job ceiling was exceeded.
    #[error("reusable workflow expansion exceeds its job limit")]
    JobLimitExceeded,
    /// Matrix reusable calls require a later per-instance expansion phase.
    #[error("matrix reusable workflow calls are not supported by this expansion slice")]
    MatrixCallUnsupported,
    /// A caller supplied an input that the callee did not declare.
    #[error("reusable workflow input `{0}` is not declared by the callee")]
    UnknownInput(String),
    /// A required callee input has neither a caller value nor a default.
    #[error("required reusable workflow input `{0}` is missing")]
    MissingRequiredInput(String),
    /// A statically known caller input has the wrong type.
    #[error("reusable workflow input `{0}` has an incompatible literal type")]
    InputTypeMismatch(String),
    /// A caller targeted a secret that the callee did not declare.
    #[error("reusable workflow secret `{0}` is not declared by the callee")]
    UnknownSecret(String),
    /// A named caller secret is not available at this invocation boundary.
    #[error("reusable workflow secret source `{0}` is unavailable")]
    UnavailableSecret(String),
    /// A required callee secret has no validated forwarding edge.
    #[error("required reusable workflow secret `{0}` is missing")]
    MissingRequiredSecret(String),
    /// A caller job requests an output that the callee did not declare.
    #[error("reusable workflow output `{0}` is not declared by the callee")]
    UnknownOutput(String),
    /// A public caller output would lower a secret-derived callee output.
    #[error("reusable workflow output `{0}` would lose its secret-derived classification")]
    OutputSensitivityReduction(String),
    /// A permission scope name is invalid.
    #[error("reusable workflow permission name is invalid")]
    InvalidPermissionName,
    /// The same permission name was supplied more than once.
    #[error("duplicate reusable workflow permission `{0}`")]
    DuplicatePermission(String),
    /// The root permission ceiling contains too many explicit scopes.
    #[error("reusable workflow permission grant limit exceeded")]
    PermissionLimitExceeded,
    /// A source-order value cannot fit the durable schema.
    #[error("reusable workflow job source order exceeds the durable schema")]
    SourceOrderOverflow,
    /// A deterministic UUID collided inside one expansion.
    #[error("reusable workflow deterministic identity collision")]
    IdentityCollision,
    /// A durable identity unexpectedly became nil.
    #[error("reusable workflow deterministic identity is invalid")]
    InvalidIdentity,
}

struct ExpansionContext<'a> {
    run_id: RunId,
    catalog: &'a GithubReusableWorkflowCatalog,
    limits: ReusableWorkflowLimits,
    invocation_ids: BTreeSet<Uuid>,
    job_ids: BTreeSet<Uuid>,
    invocations: Vec<ReusableWorkflowInvocationExpansion>,
    job_count: usize,
}

#[allow(clippy::too_many_lines)]
fn expand_reusable_workflow(
    request: ExpandReusableWorkflowRequest<'_>,
    limits: ReusableWorkflowLimits,
) -> Result<ReusableWorkflowExpansion, ReusableWorkflowExpansionError> {
    let root_path = canonical_workflow_path(request.root_path)?;
    if request.root_source.is_empty()
        || request.root_source.len() > MAX_REUSABLE_WORKFLOW_SOURCE_BYTES
    {
        return Err(ReusableWorkflowExpansionError::InvalidSourceSize);
    }
    validate_plan_origin(
        request.root_plan,
        request.catalog.repository(),
        request.catalog.revision(),
        &root_path,
    )?;
    let recompiled_root = compile_github_source(
        request.catalog.repository(),
        request.catalog.revision(),
        &root_path,
        request.root_source,
        request.root_plan.event().clone(),
        true,
    )
    .map_err(|error| match error {
        ReusableWorkflowExpansionError::FrontendRejected(_)
        | ReusableWorkflowExpansionError::CompilationRejected(_) => {
            ReusableWorkflowExpansionError::RootPlanMismatch
        }
        other => other,
    })?;
    if recompiled_root != *request.root_plan {
        return Err(ReusableWorkflowExpansionError::RootPlanMismatch);
    }

    let root_source_digest = digest(request.root_source);
    let root_plan_digest = digest_plan(request.root_plan)?;
    let root_permissions = request
        .root_permissions
        .reduce(request.root_plan.logical().permissions());
    let root_outputs = request
        .root_plan
        .logical()
        .invocation()
        .map_or_else(Vec::new, contract_outputs);
    let mut context = ExpansionContext {
        run_id: request.run_id,
        catalog: request.catalog,
        limits,
        invocation_ids: BTreeSet::from([request.root_invocation_id.as_uuid()]),
        job_ids: BTreeSet::new(),
        invocations: Vec::new(),
        job_count: 0,
    };
    let mut active_paths = Vec::new();
    expand_invocation(
        &mut context,
        InvocationRequest {
            id: request.root_invocation_id,
            parent_id: None,
            caller_job_id: None,
            depth: 0,
            workflow_path: &root_path,
            source_digest: root_source_digest,
            plan_digest: root_plan_digest,
            plan: request.root_plan,
            permissions: root_permissions,
            inputs: Vec::new(),
            secrets: Vec::new(),
            available_secret_names: request.root_secret_names.clone(),
            outputs: root_outputs,
            root: true,
        },
        &mut active_paths,
    )?;

    let digest = expansion_digest(
        request.run_id,
        request.root_invocation_id,
        &context.invocations,
    )?;
    Ok(ReusableWorkflowExpansion {
        run_id: request.run_id,
        root_invocation_id: request.root_invocation_id,
        digest,
        invocations: context.invocations,
    })
}

struct InvocationRequest<'a> {
    id: LogicalWorkflowInvocationId,
    parent_id: Option<LogicalWorkflowInvocationId>,
    caller_job_id: Option<LogicalWorkflowJobId>,
    depth: usize,
    workflow_path: &'a str,
    source_digest: Sha256Digest,
    plan_digest: Sha256Digest,
    plan: &'a WorkflowPlan,
    permissions: ReusableWorkflowPermissions,
    inputs: Vec<ExpandedReusableInput>,
    secrets: Vec<ExpandedReusableSecret>,
    available_secret_names: BTreeSet<String>,
    outputs: Vec<ExpandedReusableOutput>,
    root: bool,
}

// Keeping the recursive push/pop and fail-closed edge construction together
// makes the active-cycle stack and partially built ledger easier to audit.
#[allow(clippy::too_many_lines)]
fn expand_invocation(
    context: &mut ExpansionContext<'_>,
    request: InvocationRequest<'_>,
    active_paths: &mut Vec<String>,
) -> Result<(), ReusableWorkflowExpansionError> {
    if request.depth > context.limits.maximum_depth() {
        return Err(ReusableWorkflowExpansionError::DepthLimitExceeded);
    }
    if context.invocations.len() >= context.limits.maximum_invocations() {
        return Err(ReusableWorkflowExpansionError::InvocationLimitExceeded);
    }
    if active_paths
        .iter()
        .any(|candidate| candidate == request.workflow_path)
    {
        return Err(ReusableWorkflowExpansionError::Cycle(
            request.workflow_path.to_owned(),
        ));
    }
    active_paths.push(request.workflow_path.to_owned());

    let jobs = expanded_jobs(context, request.id, request.plan, request.root)?;
    let invocation_index = context.invocations.len();
    context
        .invocations
        .push(ReusableWorkflowInvocationExpansion {
            id: request.id,
            parent_id: request.parent_id,
            caller_job_id: request.caller_job_id,
            depth: u16::try_from(request.depth)
                .map_err(|_| ReusableWorkflowExpansionError::DepthLimitExceeded)?,
            workflow_path: request.workflow_path.to_owned(),
            source_digest: request.source_digest,
            plan_digest: request.plan_digest,
            permissions: request.permissions.clone(),
            inputs: request.inputs,
            secrets: request.secrets,
            outputs: request.outputs,
            jobs,
        });

    for job in request.plan.jobs() {
        let LogicalJobKind::ReusableWorkflow(call) = job.execution() else {
            continue;
        };
        if job.strategy().is_some() {
            active_paths.pop();
            return Err(ReusableWorkflowExpansionError::MatrixCallUnsupported);
        }
        let callee = context.catalog.resolve(call.reference().value())?;
        if active_paths
            .iter()
            .any(|candidate| candidate == callee.path())
        {
            active_paths.pop();
            return Err(ReusableWorkflowExpansionError::Cycle(
                callee.path().to_owned(),
            ));
        }
        let contract = callee.plan().logical().invocation().ok_or_else(|| {
            ReusableWorkflowExpansionError::MissingInvocationContract(callee.path().to_owned())
        })?;
        let inputs = validate_inputs(call, contract)?;
        let secrets = validate_secrets(call, contract, &request.available_secret_names)?;
        validate_call_outputs(job.outputs(), contract)?;
        let available_secret_names = secrets
            .iter()
            .map(|binding| binding.target.clone())
            .collect();
        let caller_job_id = context.invocations[invocation_index]
            .jobs
            .iter()
            .find(|expanded| expanded.key() == job.key().value())
            .map(ExpandedReusableJob::id)
            .ok_or(ReusableWorkflowExpansionError::InvalidIdentity)?;
        let invocation_id = derived_invocation_id(
            context.run_id,
            request.id,
            caller_job_id,
            callee.path(),
            callee.source_digest(),
        )?;
        if !context.invocation_ids.insert(invocation_id.as_uuid()) {
            active_paths.pop();
            return Err(ReusableWorkflowExpansionError::IdentityCollision);
        }
        let permissions = request
            .permissions
            .reduce(job.permissions())
            .reduce(callee.plan().logical().permissions());
        let outputs = contract_outputs(contract);
        expand_invocation(
            context,
            InvocationRequest {
                id: invocation_id,
                parent_id: Some(request.id),
                caller_job_id: Some(caller_job_id),
                depth: request.depth + 1,
                workflow_path: callee.path(),
                source_digest: callee.source_digest(),
                plan_digest: callee.plan_digest(),
                plan: callee.plan(),
                permissions,
                inputs,
                secrets,
                available_secret_names,
                outputs,
                root: false,
            },
            active_paths,
        )?;
    }
    active_paths.pop();
    Ok(())
}

fn expanded_jobs(
    context: &mut ExpansionContext<'_>,
    invocation_id: LogicalWorkflowInvocationId,
    plan: &WorkflowPlan,
    root: bool,
) -> Result<Vec<ExpandedReusableJob>, ReusableWorkflowExpansionError> {
    context.job_count = context
        .job_count
        .checked_add(plan.jobs().len())
        .ok_or(ReusableWorkflowExpansionError::JobLimitExceeded)?;
    if context.job_count > context.limits.maximum_jobs() {
        return Err(ReusableWorkflowExpansionError::JobLimitExceeded);
    }
    let mut ids = BTreeMap::new();
    for job in plan.jobs() {
        let id = if root {
            derived_root_job_id(context.run_id, job.key().value())?
        } else {
            derived_job_id(context.run_id, invocation_id, job.key().value())?
        };
        if !context.job_ids.insert(id.as_uuid()) {
            return Err(ReusableWorkflowExpansionError::IdentityCollision);
        }
        ids.insert(job.key().value().clone(), id);
    }
    plan.jobs()
        .iter()
        .map(|job| {
            let id = ids
                .get(job.key().value())
                .copied()
                .ok_or(ReusableWorkflowExpansionError::InvalidIdentity)?;
            let prerequisites = job
                .needs()
                .iter()
                .map(|need| {
                    ids.get(need.value())
                        .copied()
                        .ok_or(ReusableWorkflowExpansionError::InvalidIdentity)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ExpandedReusableJob {
                id,
                key: job.key().value().clone(),
                source_order: u16::try_from(job.source_order())
                    .map_err(|_| ReusableWorkflowExpansionError::SourceOrderOverflow)?,
                reusable: matches!(job.execution(), LogicalJobKind::ReusableWorkflow(_)),
                prerequisites,
            })
        })
        .collect()
}

fn validate_inputs(
    call: &ReusableWorkflowInvocation,
    contract: &WorkflowInvocationContract,
) -> Result<Vec<ExpandedReusableInput>, ReusableWorkflowExpansionError> {
    let definitions = contract
        .inputs()
        .iter()
        .map(|definition| (definition.key().value().as_str(), definition))
        .collect::<BTreeMap<_, _>>();
    let supplied = call
        .inputs()
        .iter()
        .map(|binding| {
            let target = binding.target().value().as_str();
            let Some(definition) = definitions.get(target) else {
                return Err(ReusableWorkflowExpansionError::UnknownInput(
                    target.to_owned(),
                ));
            };
            if statically_known_input_type(binding.value().value())
                .is_some_and(|input_type| input_type != *definition.input_type().value())
            {
                return Err(ReusableWorkflowExpansionError::InputTypeMismatch(
                    target.to_owned(),
                ));
            }
            Ok((target, binding.value().value().clone()))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    contract
        .inputs()
        .iter()
        .map(|definition| {
            let target = definition.key().value().as_str();
            let source = if let Some(value) = supplied.get(target) {
                ReusableInputBindingSource::Caller(value.clone())
            } else if let Some(default) = definition.default() {
                ReusableInputBindingSource::Default(default.value().clone())
            } else if definition.required() {
                return Err(ReusableWorkflowExpansionError::MissingRequiredInput(
                    target.to_owned(),
                ));
            } else {
                ReusableInputBindingSource::ImplicitDefault
            };
            Ok(ExpandedReusableInput {
                target: target.to_owned(),
                input_type: *definition.input_type().value(),
                source,
            })
        })
        .collect()
}

fn statically_known_input_type(value: &CompiledValueTemplate) -> Option<InvocationInputType> {
    match value {
        CompiledValueTemplate::Literal(_) => Some(InvocationInputType::String),
        CompiledValueTemplate::Expression(expression) => {
            if !matches!(
                expression.expression().segments(),
                [ExpressionSegment::Evaluation(_)]
            ) {
                return Some(InvocationInputType::String);
            }
            let [program] = expression.programs() else {
                return None;
            };
            let [ExpressionInstruction::Literal { value }] = program.instructions() else {
                return None;
            };
            match value {
                ExpressionLiteral::Boolean { .. } => Some(InvocationInputType::Boolean),
                ExpressionLiteral::Number { .. } => Some(InvocationInputType::Number),
                ExpressionLiteral::String { .. } => Some(InvocationInputType::String),
                ExpressionLiteral::Null => None,
            }
        }
    }
}

fn validate_secrets(
    call: &ReusableWorkflowInvocation,
    contract: &WorkflowInvocationContract,
    available: &BTreeSet<String>,
) -> Result<Vec<ExpandedReusableSecret>, ReusableWorkflowExpansionError> {
    let definitions = contract
        .secrets()
        .iter()
        .map(|definition| (definition.key().value().as_str(), definition))
        .collect::<BTreeMap<_, _>>();
    let mut supplied = BTreeMap::<&str, String>::new();
    match call.secrets() {
        ReusableSecretForwarding::Mapping(bindings) => {
            for binding in bindings {
                let target = binding.target().value().as_str();
                if !definitions.contains_key(target) {
                    return Err(ReusableWorkflowExpansionError::UnknownSecret(
                        target.to_owned(),
                    ));
                }
                let source = binding.source().value().as_str();
                if !available.contains(source) {
                    return Err(ReusableWorkflowExpansionError::UnavailableSecret(
                        source.to_owned(),
                    ));
                }
                supplied.insert(target, source.to_owned());
            }
        }
        ReusableSecretForwarding::Inherit(_) => {
            for definition in contract.secrets() {
                let target = definition.key().value().as_str();
                if available.contains(target) {
                    supplied.insert(target, target.to_owned());
                }
            }
        }
    }

    contract
        .secrets()
        .iter()
        .filter_map(|definition| {
            let target = definition.key().value().as_str();
            if let Some(source) = supplied.get(target) {
                Some(Ok(ExpandedReusableSecret {
                    target: target.to_owned(),
                    source: source.clone(),
                }))
            } else if definition.required() {
                Some(Err(ReusableWorkflowExpansionError::MissingRequiredSecret(
                    target.to_owned(),
                )))
            } else {
                None
            }
        })
        .collect()
}

fn validate_call_outputs(
    call_outputs: &[automata_ci_core::LogicalJobOutputDefinition],
    contract: &WorkflowInvocationContract,
) -> Result<(), ReusableWorkflowExpansionError> {
    let outputs = contract
        .outputs()
        .iter()
        .map(|output| (output.key().value().as_str(), output))
        .collect::<BTreeMap<_, _>>();
    for output in call_outputs {
        let LogicalJobOutputSource::InvocationOutput(source) = output.source() else {
            return Err(ReusableWorkflowExpansionError::UnknownOutput(
                output.key().value().as_str().to_owned(),
            ));
        };
        let key = source.value().as_str();
        let Some(callee) = outputs.get(key) else {
            return Err(ReusableWorkflowExpansionError::UnknownOutput(
                key.to_owned(),
            ));
        };
        if output.sensitivity() == OutputSensitivity::Public
            && callee.sensitivity() == OutputSensitivity::SecretDerived
        {
            return Err(ReusableWorkflowExpansionError::OutputSensitivityReduction(
                key.to_owned(),
            ));
        }
    }
    Ok(())
}

fn contract_outputs(contract: &WorkflowInvocationContract) -> Vec<ExpandedReusableOutput> {
    contract
        .outputs()
        .iter()
        .map(|output| ExpandedReusableOutput {
            key: output.key().value().as_str().to_owned(),
            sensitivity: output.sensitivity(),
        })
        .collect()
}

fn permissions_from_request(permissions: &WorkflowPermissions) -> ReusableWorkflowPermissions {
    match permissions {
        WorkflowPermissions::ReadAll(_) => ReusableWorkflowPermissions {
            default: PermissionLevel::Read,
            grants: BTreeMap::new(),
        },
        WorkflowPermissions::WriteAll(_) => ReusableWorkflowPermissions {
            default: PermissionLevel::Write,
            grants: BTreeMap::new(),
        },
        WorkflowPermissions::Mapping(grants) => ReusableWorkflowPermissions {
            default: PermissionLevel::None,
            grants: grants
                .iter()
                .map(|grant| (grant.name().value().clone(), *grant.level().value()))
                .filter(|(_, level)| *level != PermissionLevel::None)
                .collect(),
        },
    }
}

fn intersect_permissions(
    left: &ReusableWorkflowPermissions,
    right: &ReusableWorkflowPermissions,
) -> ReusableWorkflowPermissions {
    let default = minimum_permission(left.default, right.default);
    let names = left
        .grants
        .keys()
        .chain(right.grants.keys())
        .collect::<BTreeSet<_>>();
    let grants = names
        .into_iter()
        .filter_map(|name| {
            let level = minimum_permission(left.level(name), right.level(name));
            (level != default).then(|| (name.clone(), level))
        })
        .collect();
    ReusableWorkflowPermissions { default, grants }
}

const fn minimum_permission(left: PermissionLevel, right: PermissionLevel) -> PermissionLevel {
    match (left, right) {
        (PermissionLevel::None, _) | (_, PermissionLevel::None) => PermissionLevel::None,
        (PermissionLevel::Read, _) | (_, PermissionLevel::Read) => PermissionLevel::Read,
        (PermissionLevel::Write, PermissionLevel::Write) => PermissionLevel::Write,
    }
}

fn compile_github_source(
    repository: &str,
    revision: &str,
    path: &str,
    source: &[u8],
    event: automata_ci_core::WorkflowEventProvenance,
    preselected: bool,
) -> Result<WorkflowPlan, ReusableWorkflowExpansionError> {
    let source = std::str::from_utf8(source)
        .map_err(|_| ReusableWorkflowExpansionError::InvalidSourceEncoding)?;
    let provenance = SourceProvenance::new(
        SourceId::new(path),
        SourceOrigin::Repository {
            repository: Arc::from(repository),
            revision: Arc::from(revision),
            path: Arc::from(path),
        },
    );
    let parsed =
        GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(provenance, source));
    if !parsed.is_accepted() {
        return Err(ReusableWorkflowExpansionError::FrontendRejected(
            diagnostic_codes(parsed.diagnostics()),
        ));
    }
    let source_plan = parsed
        .plan()
        .ok_or_else(|| ReusableWorkflowExpansionError::FrontendRejected("no plan".to_owned()))?;
    let request = if preselected {
        CompileWorkflowRequest::for_preselected_event(source_plan, event)
    } else {
        CompileWorkflowRequest::new(source_plan, event)
    };
    let compiled = GithubWorkflowCompiler::new().compile(request);
    if !compiled.is_accepted() {
        return Err(ReusableWorkflowExpansionError::CompilationRejected(
            diagnostic_codes(compiled.diagnostics()),
        ));
    }
    compiled
        .into_parts()
        .0
        .ok_or_else(|| ReusableWorkflowExpansionError::CompilationRejected("no plan".to_owned()))
}

fn validate_plan_origin(
    plan: &WorkflowPlan,
    repository: &str,
    revision: &str,
    path: &str,
) -> Result<(), ReusableWorkflowExpansionError> {
    let PlanSourceOrigin::Repository {
        repository: plan_repository,
        revision: plan_revision,
        path: plan_path,
    } = plan.source().origin()
    else {
        return Err(ReusableWorkflowExpansionError::RootPlanMismatch);
    };
    if plan.source().provider() != "github"
        || plan.source().source_id() != path
        || plan_repository != repository
        || plan_revision != revision
        || plan_path != path
    {
        return Err(ReusableWorkflowExpansionError::RootPlanMismatch);
    }
    Ok(())
}

fn canonical_workflow_path(value: &str) -> Result<String, ReusableWorkflowExpansionError> {
    if value.is_empty()
        || value.len() > MAX_REUSABLE_WORKFLOW_PATH_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return Err(ReusableWorkflowExpansionError::InvalidWorkflowPath);
    }
    let components = value.split('/').collect::<Vec<_>>();
    let [dot_github, workflows, file] = components.as_slice() else {
        return Err(ReusableWorkflowExpansionError::InvalidWorkflowPath);
    };
    let extension = Path::new(file).extension();
    if *dot_github != ".github"
        || *workflows != "workflows"
        || file.is_empty()
        || *file == "."
        || *file == ".."
        || !(extension == Some(OsStr::new("yml")) || extension == Some(OsStr::new("yaml")))
    {
        return Err(ReusableWorkflowExpansionError::InvalidWorkflowPath);
    }
    Ok(value.to_owned())
}

fn resolve_local_reference(reference: &str) -> Result<String, ReusableWorkflowExpansionError> {
    let Some(path) = reference.strip_prefix("./") else {
        return Err(ReusableWorkflowExpansionError::NonLocalReference);
    };
    if path.starts_with('/') || path.contains("//") {
        return Err(ReusableWorkflowExpansionError::NonLocalReference);
    }
    canonical_workflow_path(path).map_err(|_| ReusableWorkflowExpansionError::NonLocalReference)
}

fn validate_coordinate(value: &str) -> Result<(), ReusableWorkflowExpansionError> {
    if value.is_empty()
        || value.len() > MAX_REUSABLE_WORKFLOW_PATH_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ReusableWorkflowExpansionError::InvalidRepositoryCoordinate);
    }
    Ok(())
}

fn validate_exact_revision(value: &str) -> Result<(), ReusableWorkflowExpansionError> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ReusableWorkflowExpansionError::InvalidRepositoryCoordinate);
    }
    Ok(())
}

fn validate_permission_name(name: &str) -> Result<(), ReusableWorkflowExpansionError> {
    if name.is_empty()
        || name.len() > MAX_PERMISSION_NAME_BYTES
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        return Err(ReusableWorkflowExpansionError::InvalidPermissionName);
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn digest_plan(plan: &WorkflowPlan) -> Result<Sha256Digest, ReusableWorkflowExpansionError> {
    serde_json::to_vec(plan)
        .map(|bytes| digest(&bytes))
        .map_err(|_| ReusableWorkflowExpansionError::PlanSerialization)
}

fn derived_root_job_id(
    run_id: RunId,
    key: &WorkflowJobKey,
) -> Result<LogicalWorkflowJobId, ReusableWorkflowExpansionError> {
    logical_job_id(derived_uuid(
        ROOT_JOB_ID_DOMAIN,
        &[run_id.as_uuid().as_bytes(), key.as_str().as_bytes()],
    ))
}

fn derived_job_id(
    run_id: RunId,
    invocation_id: LogicalWorkflowInvocationId,
    key: &WorkflowJobKey,
) -> Result<LogicalWorkflowJobId, ReusableWorkflowExpansionError> {
    logical_job_id(derived_uuid(
        REUSABLE_JOB_ID_DOMAIN,
        &[
            run_id.as_uuid().as_bytes(),
            invocation_id.as_uuid().as_bytes(),
            key.as_str().as_bytes(),
        ],
    ))
}

fn logical_job_id(value: Uuid) -> Result<LogicalWorkflowJobId, ReusableWorkflowExpansionError> {
    LogicalWorkflowJobId::from_uuid(value)
        .map_err(|_| ReusableWorkflowExpansionError::InvalidIdentity)
}

fn derived_invocation_id(
    run_id: RunId,
    parent_id: LogicalWorkflowInvocationId,
    caller_job_id: LogicalWorkflowJobId,
    path: &str,
    source_digest: Sha256Digest,
) -> Result<LogicalWorkflowInvocationId, ReusableWorkflowExpansionError> {
    LogicalWorkflowInvocationId::from_uuid(derived_uuid(
        REUSABLE_INVOCATION_ID_DOMAIN,
        &[
            run_id.as_uuid().as_bytes(),
            parent_id.as_uuid().as_bytes(),
            caller_job_id.as_uuid().as_bytes(),
            path.as_bytes(),
            source_digest.as_bytes(),
        ],
    ))
    .map_err(|_| ReusableWorkflowExpansionError::InvalidIdentity)
}

fn derived_uuid(domain: &[u8], components: &[&[u8]]) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for component in components {
        hash_part(&mut hasher, component);
    }
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn expansion_digest(
    run_id: RunId,
    root_id: LogicalWorkflowInvocationId,
    invocations: &[ReusableWorkflowInvocationExpansion],
) -> Result<Sha256Digest, ReusableWorkflowExpansionError> {
    let mut hasher = Sha256::new();
    hasher.update(EXPANSION_DIGEST_DOMAIN);
    hash_part(&mut hasher, run_id.as_uuid().as_bytes());
    hash_part(&mut hasher, root_id.as_uuid().as_bytes());
    hash_u64(&mut hasher, invocations.len())?;
    for invocation in invocations {
        hash_part(&mut hasher, invocation.id.as_uuid().as_bytes());
        hash_optional_uuid(
            &mut hasher,
            invocation
                .parent_id
                .map(LogicalWorkflowInvocationId::as_uuid),
        );
        hash_optional_uuid(
            &mut hasher,
            invocation.caller_job_id.map(LogicalWorkflowJobId::as_uuid),
        );
        hasher.update(invocation.depth.to_be_bytes());
        hash_part(&mut hasher, invocation.workflow_path.as_bytes());
        hash_part(&mut hasher, invocation.source_digest.as_bytes());
        hash_part(&mut hasher, invocation.plan_digest.as_bytes());
        hash_permissions(&mut hasher, &invocation.permissions)?;
        hash_inputs(&mut hasher, &invocation.inputs)?;
        hash_u64(&mut hasher, invocation.secrets.len())?;
        for secret in &invocation.secrets {
            hash_part(&mut hasher, secret.target.as_bytes());
            hash_part(&mut hasher, secret.source.as_bytes());
        }
        hash_u64(&mut hasher, invocation.outputs.len())?;
        for output in &invocation.outputs {
            hash_part(&mut hasher, output.key.as_bytes());
            hash_part(
                &mut hasher,
                match output.sensitivity {
                    OutputSensitivity::Public => b"public",
                    OutputSensitivity::SecretDerived => b"secret_derived",
                },
            );
        }
        hash_u64(&mut hasher, invocation.jobs.len())?;
        for job in &invocation.jobs {
            hash_part(&mut hasher, job.id.as_uuid().as_bytes());
            hash_part(&mut hasher, job.key.as_str().as_bytes());
            hasher.update(job.source_order.to_be_bytes());
            hasher.update([u8::from(job.reusable)]);
            hash_u64(&mut hasher, job.prerequisites.len())?;
            for prerequisite in &job.prerequisites {
                hash_part(&mut hasher, prerequisite.as_uuid().as_bytes());
            }
        }
    }
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn hash_permissions(
    hasher: &mut Sha256,
    permissions: &ReusableWorkflowPermissions,
) -> Result<(), ReusableWorkflowExpansionError> {
    hash_part(hasher, permission_name(permissions.default).as_bytes());
    hash_u64(hasher, permissions.grants.len())?;
    for (name, level) in &permissions.grants {
        hash_part(hasher, name.as_bytes());
        hash_part(hasher, permission_name(*level).as_bytes());
    }
    Ok(())
}

fn hash_inputs(
    hasher: &mut Sha256,
    inputs: &[ExpandedReusableInput],
) -> Result<(), ReusableWorkflowExpansionError> {
    hash_u64(hasher, inputs.len())?;
    for input in inputs {
        hash_part(hasher, input.target.as_bytes());
        hash_part(hasher, input_type_name(input.input_type).as_bytes());
        match &input.source {
            ReusableInputBindingSource::Caller(value) => {
                hash_part(hasher, b"caller");
                let encoded = serde_json::to_vec(value)
                    .map_err(|_| ReusableWorkflowExpansionError::PlanSerialization)?;
                hash_part(hasher, &encoded);
            }
            ReusableInputBindingSource::Default(value) => {
                hash_part(hasher, b"default");
                let encoded = serde_json::to_vec(value)
                    .map_err(|_| ReusableWorkflowExpansionError::PlanSerialization)?;
                hash_part(hasher, &encoded);
            }
            ReusableInputBindingSource::ImplicitDefault => hash_part(hasher, b"implicit"),
        }
    }
    Ok(())
}

const fn permission_name(level: PermissionLevel) -> &'static str {
    match level {
        PermissionLevel::None => "none",
        PermissionLevel::Read => "read",
        PermissionLevel::Write => "write",
    }
}

const fn input_type_name(input_type: InvocationInputType) -> &'static str {
    match input_type {
        InvocationInputType::Boolean => "boolean",
        InvocationInputType::Number => "number",
        InvocationInputType::String => "string",
    }
}

fn hash_optional_uuid(hasher: &mut Sha256, value: Option<Uuid>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hash_part(hasher, value.as_bytes());
        }
        None => hasher.update([0]),
    }
}

fn hash_u64(hasher: &mut Sha256, value: usize) -> Result<(), ReusableWorkflowExpansionError> {
    let value = u64::try_from(value)
        .map_err(|_| ReusableWorkflowExpansionError::InvocationLimitExceeded)?;
    hasher.update(value.to_be_bytes());
    Ok(())
}

fn hash_part(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn diagnostic_codes(diagnostics: &[Diagnostic]) -> String {
    let mut codes = diagnostics.iter().map(Diagnostic::code).collect::<Vec<_>>();
    codes.sort_unstable();
    codes.dedup();
    if codes.is_empty() {
        "unspecified diagnostic".to_owned()
    } else {
        codes.join(",")
    }
}
