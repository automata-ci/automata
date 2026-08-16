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
    LogicalJobTemplate, OutputSensitivity, PermissionLevel, PermissionSnapshotRequest,
    PlanSourceOrigin, ReusableSecretForwarding, ReusableWorkflowInvocation, RunId, Sha256Digest,
    WorkflowInvocationContract, WorkflowJobKey, WorkflowPermissions, WorkflowPlan,
};
use automata_ci_store::{LogicalWorkflowInvocationId, LogicalWorkflowJobId};
use automata_ci_workflow_github::{
    CompileWorkflowRequest, Diagnostic, GithubWorkflowCompiler, GithubWorkflowDispatchInputs,
    GithubWorkflowFrontend, LocalGithubArchiveCompilation,
    LocalGithubArchiveCompilationFailureKind, ParseWorkflowRequest,
    RepositoryWorkflowDiscoveryLimits, RepositoryWorkflowLocation, SourceId, SourceOrigin,
    SourceProvenance, WorkflowFrontend as _, compile_local_github_archive,
};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::credential_requirements::{
    BuiltInCredentialRequirement, built_in_secret_requirement, discover_job_credentials,
};

/// Maximum repository workflow files accepted by one reusable catalog.
pub const MAX_REUSABLE_WORKFLOW_CATALOG_ENTRIES: usize = 50;
/// Maximum caller-to-callee edges below the root invocation.
pub const MAX_REUSABLE_WORKFLOW_DEPTH: usize = 9;
/// Maximum invocation occurrences, including the root, in one expansion.
pub const MAX_REUSABLE_WORKFLOW_INVOCATIONS: usize = 256;
/// Maximum logical jobs across all invocation occurrences in one expansion.
pub const MAX_REUSABLE_WORKFLOW_EXPANDED_JOBS: usize = 4_096;

const MAX_REUSABLE_WORKFLOW_PATH_BYTES: usize = 1_024;
const MAX_REUSABLE_WORKFLOW_SOURCE_BYTES: usize = 16_777_216;
const MAX_PERMISSION_NAME_BYTES: usize = 256;
const MAX_PERMISSION_GRANTS: usize = 256;
const REUSABLE_INVOCATION_ID_DOMAIN: &[u8] = b"automata.reusable-workflow.invocation.v1\0";
const REUSABLE_JOB_ID_DOMAIN: &[u8] = b"automata.reusable-workflow.job.v1\0";
const ROOT_JOB_ID_DOMAIN: &[u8] = b"automata.admission.logical-job.v1\0";
const EXPANSION_DIGEST_DOMAIN: &[u8] = b"automata.reusable-workflow.expansion.v1\0";

/// Stable failure class for sealed local GitHub workflow analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalGithubArchiveAnalysisFailureKind {
    /// Cooperative cancellation interrupted bounded analysis.
    Cancelled,
    /// The sealed archive violates its local workflow policy.
    Archive,
    /// The archive contains no direct `.github/workflows` workflow.
    WorkflowMissing,
    /// More than one workflow requires one exact canonical selector.
    WorkflowSelectionRequired,
    /// The supplied selector is not one exact archive member.
    WorkflowNotFound,
    /// A selected workflow source is empty, excessive, or not UTF-8.
    WorkflowSource,
    /// The GitHub Actions frontend rejected a selected source.
    Frontend,
    /// Explicit local `workflow_dispatch` selection rejected the root.
    Compilation,
    /// A reusable call, contract, cycle, or propagation rule was rejected.
    ReusableWorkflow,
    /// Static credential-name discovery rejected a dynamic or invalid access.
    CredentialDiscovery,
}

/// Sanitized failure from sealed local GitHub workflow analysis.
#[derive(Clone, Debug)]
pub struct LocalGithubArchiveAnalysisFailure {
    kind: LocalGithubArchiveAnalysisFailureKind,
    diagnostics: Vec<Diagnostic>,
}

impl LocalGithubArchiveAnalysisFailure {
    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(&self) -> LocalGithubArchiveAnalysisFailureKind {
        self.kind
    }

    /// Returns value-free source diagnostics collected before failure.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
}

/// One logical job discovered by sealed local GitHub workflow analysis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalGithubAnalyzedJob {
    key: String,
    reusable: bool,
    secrets: Vec<String>,
    variables: Vec<String>,
    built_in_credentials: Vec<BuiltInCredentialRequirement>,
}

impl LocalGithubAnalyzedJob {
    /// Returns the source-level logical job key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns whether the job invokes another reusable workflow.
    #[must_use]
    pub const fn reusable(&self) -> bool {
        self.reusable
    }

    /// Returns canonical external secret names without values.
    #[must_use]
    pub fn secrets(&self) -> &[String] {
        &self.secrets
    }

    /// Returns canonical repository-variable names without values.
    #[must_use]
    pub fn variables(&self) -> &[String] {
        &self.variables
    }

    /// Returns closed provider-built-in requirements in stable order.
    #[must_use]
    pub fn built_in_credentials(&self) -> &[BuiltInCredentialRequirement] {
        &self.built_in_credentials
    }
}

/// One root or reachable same-archive workflow analyzed locally.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalGithubAnalyzedWorkflow {
    path: String,
    reusable: bool,
    jobs: Vec<LocalGithubAnalyzedJob>,
}

impl LocalGithubAnalyzedWorkflow {
    /// Returns the exact canonical `.github/workflows` archive member.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns whether this workflow was reached through `workflow_call`.
    #[must_use]
    pub const fn reusable(&self) -> bool {
        self.reusable
    }

    /// Returns jobs in source order.
    #[must_use]
    pub fn jobs(&self) -> &[LocalGithubAnalyzedJob] {
        &self.jobs
    }
}

/// Value-free analysis derived from one exact sealed local archive.
#[derive(Clone, Debug)]
pub struct LocalGithubArchiveAnalysis {
    snapshot_digest: Sha256Digest,
    selected_path: String,
    required_root_secrets: Vec<String>,
    required_built_in_credentials: Vec<BuiltInCredentialRequirement>,
    workflows: Vec<LocalGithubAnalyzedWorkflow>,
    diagnostics: Vec<Diagnostic>,
}

impl LocalGithubArchiveAnalysis {
    /// Returns SHA-256 over the exact archive bytes that were analyzed.
    #[must_use]
    pub const fn snapshot_digest(&self) -> Sha256Digest {
        self.snapshot_digest
    }

    /// Returns the exact selected canonical root workflow path.
    #[must_use]
    pub fn selected_path(&self) -> &str {
        &self.selected_path
    }

    /// Returns external secret names required at the root boundary.
    #[must_use]
    pub fn required_root_secrets(&self) -> &[String] {
        &self.required_root_secrets
    }

    /// Returns provider-built-in credentials required anywhere reachable.
    #[must_use]
    pub fn required_built_in_credentials(&self) -> &[BuiltInCredentialRequirement] {
        &self.required_built_in_credentials
    }

    /// Returns the root and reachable workflows in canonical path order.
    #[must_use]
    pub fn workflows(&self) -> &[LocalGithubAnalyzedWorkflow] {
        &self.workflows
    }

    /// Returns all value-free frontend and compiler diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CatalogSourceAuthority {
    GithubDelivery,
    LocalGithubArchive,
}

impl CatalogSourceAuthority {
    const fn provider(self) -> &'static str {
        match self {
            Self::GithubDelivery => "github",
            Self::LocalGithubArchive => "local",
        }
    }

    const fn workflow_location(self) -> RepositoryWorkflowLocation {
        match self {
            Self::GithubDelivery => RepositoryWorkflowLocation::Automata,
            Self::LocalGithubArchive => RepositoryWorkflowLocation::Github,
        }
    }
}

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
    /// Recompiles only local workflows reachable from the supplied root plan.
    ///
    /// Candidate files may contain unrelated direct workflows; they never enter
    /// the catalog or its replay digest. Missing, cyclic, remote, invalid, or
    /// over-limit reachable calls fail before admission.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed expansion error for any invalid reachable edge.
    pub fn compile_reachable(
        repository: impl Into<String>,
        revision: impl Into<String>,
        root_plan: &WorkflowPlan,
        sources: impl IntoIterator<Item = RepositoryWorkflowSource>,
    ) -> Result<Self, ReusableWorkflowExpansionError> {
        let repository = repository.into();
        let revision = revision.into();
        validate_coordinate(&repository)?;
        validate_exact_revision(&revision)?;
        let PlanSourceOrigin::Repository {
            path: root_path, ..
        } = root_plan.source().origin()
        else {
            return Err(ReusableWorkflowExpansionError::RootPlanMismatch);
        };
        let root_path = canonical_workflow_path(root_path, RepositoryWorkflowLocation::Automata)?;
        validate_plan_origin(
            root_plan,
            CatalogSourceAuthority::GithubDelivery,
            &repository,
            &revision,
            &root_path,
        )?;

        let mut available = BTreeMap::new();
        for source in sources {
            let path =
                canonical_workflow_path(source.path(), RepositoryWorkflowLocation::Automata)?;
            if source.source().is_empty()
                || validate_reusable_workflow_source_bytes(source.source().len()).is_err()
            {
                continue;
            }
            if available.insert(path.clone(), source.source).is_some() {
                return Err(ReusableWorkflowExpansionError::DuplicateCatalogPath(path));
            }
        }
        let mut pending = root_plan
            .jobs()
            .iter()
            .filter_map(|job| match job.execution() {
                LogicalJobKind::ReusableWorkflow(call) => Some(call.reference().value().clone()),
                LogicalJobKind::Steps(_) => None,
            })
            .collect::<Vec<_>>();
        let mut entries = BTreeMap::new();
        while let Some(reference) = pending.pop() {
            let path = resolve_local_reference(&reference, RepositoryWorkflowLocation::Automata)?;
            if path == root_path {
                return Err(ReusableWorkflowExpansionError::Cycle(path));
            }
            if entries.contains_key(&path) {
                continue;
            }
            let projected = entries
                .len()
                .checked_add(1)
                .ok_or(ReusableWorkflowExpansionError::CatalogLimitExceeded)?;
            validate_reusable_catalog_entry_count(projected)?;
            let source = available
                .get(&path)
                .ok_or_else(|| ReusableWorkflowExpansionError::MissingCatalogPath(path.clone()))?;
            let plan = compile_reusable_source(&repository, &revision, &path, source)?;
            if plan.logical().invocation().is_none() {
                return Err(ReusableWorkflowExpansionError::MissingInvocationContract(
                    path,
                ));
            }
            pending.extend(plan.jobs().iter().filter_map(|job| match job.execution() {
                LogicalJobKind::ReusableWorkflow(call) => Some(call.reference().value().clone()),
                LogicalJobKind::Steps(_) => None,
            }));
            let source_digest = digest(source);
            let plan_digest = digest_plan(&plan)?;
            entries.insert(
                path.clone(),
                CatalogedReusableWorkflow {
                    path,
                    source: source.clone(),
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
        validate_reusable_catalog_entry_count(sources.len())?;
        let mut entries = BTreeMap::new();
        for source in sources {
            let path =
                canonical_workflow_path(source.path(), RepositoryWorkflowLocation::Automata)?;
            if source.source().is_empty() {
                return Err(ReusableWorkflowExpansionError::InvalidSourceSize);
            }
            validate_reusable_workflow_source_bytes(source.source().len())?;
            if entries.contains_key(&path) {
                return Err(ReusableWorkflowExpansionError::DuplicateCatalogPath(path));
            }
            let plan = compile_reusable_source(&repository, &revision, &path, source.source())?;
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
}

#[derive(Clone, Copy)]
struct ResolvedCatalogEntry<'a> {
    path: &'a str,
    source_digest: Sha256Digest,
    plan_digest: Sha256Digest,
    plan: &'a WorkflowPlan,
}

trait ReusableWorkflowCatalogResolver {
    fn authority(&self) -> CatalogSourceAuthority;
    fn repository(&self) -> &str;
    fn revision(&self) -> &str;
    fn resolve(
        &self,
        reference: &str,
    ) -> Result<ResolvedCatalogEntry<'_>, ReusableWorkflowExpansionError>;
}

impl ReusableWorkflowCatalogResolver for GithubReusableWorkflowCatalog {
    fn authority(&self) -> CatalogSourceAuthority {
        CatalogSourceAuthority::GithubDelivery
    }

    fn repository(&self) -> &str {
        &self.repository
    }

    fn revision(&self) -> &str {
        &self.revision
    }

    fn resolve(
        &self,
        reference: &str,
    ) -> Result<ResolvedCatalogEntry<'_>, ReusableWorkflowExpansionError> {
        let path = resolve_local_reference(reference, self.authority().workflow_location())?;
        let entry = self
            .entries
            .get(&path)
            .ok_or(ReusableWorkflowExpansionError::MissingCatalogPath(path))?;
        Ok(ResolvedCatalogEntry {
            path: entry.path(),
            source_digest: entry.source_digest(),
            plan_digest: entry.plan_digest(),
            plan: entry.plan(),
        })
    }
}

struct LocalReusableWorkflowCatalog<'a> {
    compilation: &'a LocalGithubArchiveCompilation,
    repository: &'static str,
    revision: String,
    plan_digests: BTreeMap<String, Sha256Digest>,
}

impl<'a> LocalReusableWorkflowCatalog<'a> {
    fn new(
        compilation: &'a LocalGithubArchiveCompilation,
    ) -> Result<Self, ReusableWorkflowExpansionError> {
        let plan_digests = compilation
            .reusable_workflows()
            .iter()
            .map(|workflow| Ok((workflow.path().to_owned(), digest_plan(workflow.plan())?)))
            .collect::<Result<_, ReusableWorkflowExpansionError>>()?;
        Ok(Self {
            compilation,
            repository: "local",
            revision: compilation.snapshot_digest().to_string(),
            plan_digests,
        })
    }
}

impl ReusableWorkflowCatalogResolver for LocalReusableWorkflowCatalog<'_> {
    fn authority(&self) -> CatalogSourceAuthority {
        CatalogSourceAuthority::LocalGithubArchive
    }

    fn repository(&self) -> &str {
        self.repository
    }

    fn revision(&self) -> &str {
        &self.revision
    }

    fn resolve(
        &self,
        reference: &str,
    ) -> Result<ResolvedCatalogEntry<'_>, ReusableWorkflowExpansionError> {
        let path = resolve_local_reference(reference, self.authority().workflow_location())?;
        let workflow = self
            .compilation
            .reusable_workflows()
            .iter()
            .find(|workflow| workflow.path() == path)
            .ok_or_else(|| ReusableWorkflowExpansionError::MissingCatalogPath(path.clone()))?;
        let plan_digest = self
            .plan_digests
            .get(&path)
            .copied()
            .ok_or(ReusableWorkflowExpansionError::InvalidIdentity)?;
        Ok(ResolvedCatalogEntry {
            path: workflow.path(),
            source_digest: workflow.source_digest(),
            plan_digest,
            plan: workflow.plan(),
        })
    }
}

/// Compiles and analyzes one exact local GitHub workflow archive without
/// creating provider evidence, admission state, Checks, or executable work.
///
/// Local source authority and reusable membership are created only inside the
/// sealed archive compiler. This boundary then runs the same recursive
/// input/output/secret/cycle contract traversal used by durable expansion,
/// under a symbolic credential policy. The returned value retains no archive
/// or workflow source bytes and no executable plan.
///
/// # Errors
///
/// Returns a value-free failure for archive policy, exact selection,
/// parse/compile rejection, reusable-call contract rejection, credential
/// discovery failure, resource exhaustion, or cooperative cancellation.
pub fn analyze_local_github_archive(
    archive_bytes: &[u8],
    selector: Option<&str>,
    inputs: GithubWorkflowDispatchInputs,
    archive_limits: RepositoryWorkflowDiscoveryLimits,
    reusable_limits: ReusableWorkflowLimits,
    cancellation: &dyn Fn() -> bool,
) -> Result<LocalGithubArchiveAnalysis, LocalGithubArchiveAnalysisFailure> {
    let compilation = compile_local_github_archive(
        archive_bytes,
        selector,
        inputs,
        archive_limits,
        cancellation,
    )
    .map_err(|failure| local_compilation_failure(&failure))?;
    let diagnostics = compilation.diagnostics().to_vec();
    if cancellation() {
        return Err(LocalGithubArchiveAnalysisFailure {
            kind: LocalGithubArchiveAnalysisFailureKind::Cancelled,
            diagnostics,
        });
    }

    let catalog = LocalReusableWorkflowCatalog::new(&compilation)
        .map_err(|error| local_reusable_failure(&error, diagnostics.clone()))?;
    let root_path = canonical_workflow_path(
        compilation.selected_path(),
        RepositoryWorkflowLocation::Github,
    )
    .map_err(|error| local_reusable_failure(&error, diagnostics.clone()))?;
    validate_plan_origin(
        compilation.root_plan(),
        catalog.authority(),
        catalog.repository(),
        catalog.revision(),
        &root_path,
    )
    .map_err(|error| local_reusable_failure(&error, diagnostics.clone()))?;
    let root_plan_digest = digest_plan(compilation.root_plan())
        .map_err(|error| local_reusable_failure(&error, diagnostics.clone()))?;
    let mut workflow_analyses = BTreeMap::new();
    let root_analysis =
        analyze_local_workflow(&root_path, false, compilation.root_plan(), cancellation).map_err(
            |kind| LocalGithubArchiveAnalysisFailure {
                kind,
                diagnostics: diagnostics.clone(),
            },
        )?;
    workflow_analyses.insert(root_path.clone(), root_analysis);
    for reusable in compilation.reusable_workflows() {
        let entry = analyze_local_workflow(reusable.path(), true, reusable.plan(), cancellation)
            .map_err(|kind| LocalGithubArchiveAnalysisFailure {
                kind,
                diagnostics: diagnostics.clone(),
            })?;
        if workflow_analyses
            .insert(reusable.path().to_owned(), entry)
            .is_some()
        {
            return Err(local_reusable_failure(
                &ReusableWorkflowExpansionError::InvalidIdentity,
                diagnostics,
            ));
        }
    }
    let mut counts = TraversalCounts {
        limits: reusable_limits,
        invocation_count: 0,
        job_count: 0,
    };
    let mut policy = SymbolicCredentialPolicy {
        analyses: &workflow_analyses,
    };
    let mut active_paths = Vec::new();
    let requirements = traverse_reusable_invocation(
        &catalog,
        &mut policy,
        &mut counts,
        TraversalNode {
            workflow_path: &root_path,
            plan: compilation.root_plan(),
            depth: 0,
            source_digest: compilation.root_source_digest(),
            plan_digest: root_plan_digest,
            root: true,
        },
        (),
        &mut active_paths,
        cancellation,
    )
    .map_err(|error| local_reusable_failure(&error, diagnostics.clone()))?;

    let workflows = workflow_analyses
        .into_values()
        .map(|analysis| analysis.workflow)
        .collect();

    Ok(LocalGithubArchiveAnalysis {
        snapshot_digest: compilation.snapshot_digest(),
        selected_path: root_path,
        required_root_secrets: requirements.external.into_iter().collect(),
        required_built_in_credentials: requirements.built_in.into_iter().collect(),
        workflows,
        diagnostics,
    })
}

struct AnalyzedLocalWorkflow {
    workflow: LocalGithubAnalyzedWorkflow,
    requirements: SymbolicCredentialRequirements,
}

fn analyze_local_workflow(
    path: &str,
    reusable: bool,
    plan: &WorkflowPlan,
    cancellation: &dyn Fn() -> bool,
) -> Result<AnalyzedLocalWorkflow, LocalGithubArchiveAnalysisFailureKind> {
    let mut jobs = Vec::with_capacity(plan.jobs().len());
    let mut requirements = SymbolicCredentialRequirements::default();
    for job in plan.jobs() {
        if cancellation() {
            return Err(LocalGithubArchiveAnalysisFailureKind::Cancelled);
        }
        let credentials = discover_job_credentials(plan.logical(), job)
            .map_err(|_| LocalGithubArchiveAnalysisFailureKind::CredentialDiscovery)?;
        requirements
            .external
            .extend(credentials.external().secret_names().iter().cloned());
        requirements
            .built_in
            .extend(credentials.built_in().iter().copied());
        jobs.push(LocalGithubAnalyzedJob {
            key: job.key().value().to_string(),
            reusable: matches!(job.execution(), LogicalJobKind::ReusableWorkflow(_)),
            secrets: credentials.external().secret_names().to_vec(),
            variables: credentials.external().variable_names().to_vec(),
            built_in_credentials: credentials.built_in().to_vec(),
        });
    }
    if let Some(contract) = plan.logical().invocation() {
        for secret in contract.secrets().iter().filter(|secret| secret.required()) {
            let name = secret.key().value().as_str();
            if let Some(requirement) = built_in_secret_requirement(name) {
                requirements.built_in.insert(requirement);
            } else {
                requirements.external.insert(name.to_ascii_uppercase());
            }
        }
    }
    Ok(AnalyzedLocalWorkflow {
        workflow: LocalGithubAnalyzedWorkflow {
            path: path.to_owned(),
            reusable,
            jobs,
        },
        requirements,
    })
}

fn local_compilation_failure(
    failure: &automata_ci_workflow_github::LocalGithubArchiveCompilationFailure,
) -> LocalGithubArchiveAnalysisFailure {
    let kind = match failure.kind() {
        LocalGithubArchiveCompilationFailureKind::Cancelled => {
            LocalGithubArchiveAnalysisFailureKind::Cancelled
        }
        LocalGithubArchiveCompilationFailureKind::Archive => {
            LocalGithubArchiveAnalysisFailureKind::Archive
        }
        LocalGithubArchiveCompilationFailureKind::WorkflowMissing => {
            LocalGithubArchiveAnalysisFailureKind::WorkflowMissing
        }
        LocalGithubArchiveCompilationFailureKind::WorkflowSelectionRequired => {
            LocalGithubArchiveAnalysisFailureKind::WorkflowSelectionRequired
        }
        LocalGithubArchiveCompilationFailureKind::WorkflowNotFound => {
            LocalGithubArchiveAnalysisFailureKind::WorkflowNotFound
        }
        LocalGithubArchiveCompilationFailureKind::WorkflowSource => {
            LocalGithubArchiveAnalysisFailureKind::WorkflowSource
        }
        LocalGithubArchiveCompilationFailureKind::Frontend => {
            LocalGithubArchiveAnalysisFailureKind::Frontend
        }
        LocalGithubArchiveCompilationFailureKind::Compilation => {
            LocalGithubArchiveAnalysisFailureKind::Compilation
        }
        LocalGithubArchiveCompilationFailureKind::ReusableWorkflow => {
            LocalGithubArchiveAnalysisFailureKind::ReusableWorkflow
        }
    };
    LocalGithubArchiveAnalysisFailure {
        kind,
        diagnostics: failure.diagnostics().to_vec(),
    }
}

fn local_reusable_failure(
    error: &ReusableWorkflowExpansionError,
    diagnostics: Vec<Diagnostic>,
) -> LocalGithubArchiveAnalysisFailure {
    let kind = match error {
        ReusableWorkflowExpansionError::Cancelled => {
            LocalGithubArchiveAnalysisFailureKind::Cancelled
        }
        ReusableWorkflowExpansionError::CredentialRequirements => {
            LocalGithubArchiveAnalysisFailureKind::CredentialDiscovery
        }
        _ => LocalGithubArchiveAnalysisFailureKind::ReusableWorkflow,
    };
    LocalGithubArchiveAnalysisFailure { kind, diagnostics }
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
            let projected = normalized
                .len()
                .checked_add(1)
                .ok_or(ReusableWorkflowExpansionError::PermissionLimitExceeded)?;
            validate_reusable_permission_grant_count(projected)?;
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

/// One caller-visible output name bound to an exact callee workflow output.
///
/// This mapping is deliberately distinct from the callee's invocation
/// contract.  The contract says what the callee may produce; this row says
/// which of those values the parent logical call job exposes to `needs`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpandedReusableOutputMapping {
    parent_key: String,
    child_key: String,
    sensitivity: OutputSensitivity,
}

impl ExpandedReusableOutputMapping {
    /// Returns the output key exposed by the parent call job.
    #[must_use]
    pub fn parent_key(&self) -> &str {
        &self.parent_key
    }

    /// Returns the declared callee workflow-output key supplying the value.
    #[must_use]
    pub fn child_key(&self) -> &str {
        &self.child_key
    }

    /// Returns the sensitivity retained by the parent call job.
    #[must_use]
    pub const fn sensitivity(&self) -> OutputSensitivity {
        self.sensitivity
    }
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
    caller_outputs: Vec<ExpandedReusableOutputMapping>,
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

    /// Returns name-only secret edges in canonical target-name order.
    ///
    /// An inherited edge can name a secret that the callee did not declare in
    /// `on.workflow_call.secrets`, matching the provider's direct-call
    /// inheritance contract.
    #[must_use]
    pub fn secrets(&self) -> &[ExpandedReusableSecret] {
        &self.secrets
    }

    /// Returns exported outputs in callee contract order.
    #[must_use]
    pub fn outputs(&self) -> &[ExpandedReusableOutput] {
        &self.outputs
    }

    /// Returns caller-visible output mappings in the parent declaration order.
    ///
    /// The root invocation has no caller and therefore returns an empty slice.
    #[must_use]
    pub fn caller_outputs(&self) -> &[ExpandedReusableOutputMapping] {
        &self.caller_outputs
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
    /// A path is not canonical in the authority's exact workflow namespace.
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
    /// Static secret-name discovery rejected a malformed or dynamic reference.
    #[error("reusable workflow credential requirements are invalid")]
    CredentialRequirements,
    /// Cooperative cancellation interrupted reusable-workflow traversal.
    #[error("reusable workflow analysis was cancelled")]
    Cancelled,
}

const fn validate_reusable_catalog_entry_count(
    observed: usize,
) -> Result<(), ReusableWorkflowExpansionError> {
    if observed > MAX_REUSABLE_WORKFLOW_CATALOG_ENTRIES {
        return Err(ReusableWorkflowExpansionError::CatalogLimitExceeded); // stable catalog-limit reason
    }
    Ok(())
}

const fn validate_reusable_workflow_depth(
    observed: usize,
    maximum: usize,
) -> Result<(), ReusableWorkflowExpansionError> {
    if observed > maximum {
        return Err(ReusableWorkflowExpansionError::DepthLimitExceeded); // stable depth-limit reason
    }
    Ok(())
}

const fn validate_reusable_workflow_invocation_count(
    observed: usize,
    maximum: usize,
) -> Result<(), ReusableWorkflowExpansionError> {
    if observed > maximum {
        return Err(ReusableWorkflowExpansionError::InvocationLimitExceeded); // stable invocation-limit reason
    }
    Ok(())
}

const fn validate_reusable_workflow_job_count(
    observed: usize,
    maximum: usize,
) -> Result<(), ReusableWorkflowExpansionError> {
    if observed > maximum {
        return Err(ReusableWorkflowExpansionError::JobLimitExceeded); // stable job-limit reason
    }
    Ok(())
}

const fn validate_reusable_workflow_source_bytes(
    observed: usize,
) -> Result<(), ReusableWorkflowExpansionError> {
    if observed > MAX_REUSABLE_WORKFLOW_SOURCE_BYTES {
        return Err(ReusableWorkflowExpansionError::InvalidSourceSize); // stable source-byte-limit reason
    }
    Ok(())
}

const fn validate_reusable_workflow_path_bytes(
    observed: usize,
) -> Result<(), ReusableWorkflowExpansionError> {
    if observed > MAX_REUSABLE_WORKFLOW_PATH_BYTES {
        return Err(ReusableWorkflowExpansionError::InvalidWorkflowPath); // stable path-byte-limit reason
    }
    Ok(())
}

const fn validate_reusable_repository_coordinate_bytes(
    observed: usize,
) -> Result<(), ReusableWorkflowExpansionError> {
    if observed > MAX_REUSABLE_WORKFLOW_PATH_BYTES {
        return Err(ReusableWorkflowExpansionError::InvalidRepositoryCoordinate); // stable coordinate-limit reason
    }
    Ok(())
}

const fn validate_reusable_permission_name_bytes(
    observed: usize,
) -> Result<(), ReusableWorkflowExpansionError> {
    if observed > MAX_PERMISSION_NAME_BYTES {
        return Err(ReusableWorkflowExpansionError::InvalidPermissionName); // stable permission-name-limit reason
    }
    Ok(())
}

const fn validate_reusable_permission_grant_count(
    observed: usize,
) -> Result<(), ReusableWorkflowExpansionError> {
    if observed > MAX_PERMISSION_GRANTS {
        return Err(ReusableWorkflowExpansionError::PermissionLimitExceeded); // stable permission-grant-limit reason
    }
    Ok(())
}

struct ExpansionContext {
    run_id: RunId,
    invocation_ids: BTreeSet<Uuid>,
    job_ids: BTreeSet<Uuid>,
    invocations: Vec<ReusableWorkflowInvocationExpansion>,
}

struct TraversalCounts {
    limits: ReusableWorkflowLimits,
    invocation_count: usize,
    job_count: usize,
}

#[derive(Clone, Copy)]
struct TraversalNode<'a> {
    workflow_path: &'a str,
    plan: &'a WorkflowPlan,
    depth: usize,
    source_digest: Sha256Digest,
    plan_digest: Sha256Digest,
    root: bool,
}

struct TraversalEdge<'node, 'catalog> {
    job: &'node LogicalJobTemplate,
    call: &'node ReusableWorkflowInvocation,
    callee: ResolvedCatalogEntry<'catalog>,
    contract: &'catalog WorkflowInvocationContract,
    inputs: Vec<ExpandedReusableInput>,
    outputs: Vec<ExpandedReusableOutputMapping>,
}

trait CredentialTraversalPolicy {
    type Seed;
    type State;
    type Edge;
    type Output;

    fn enter(
        &mut self,
        node: &TraversalNode<'_>,
        seed: Self::Seed,
    ) -> Result<Self::State, ReusableWorkflowExpansionError>;

    fn prepare_edge(
        &mut self,
        parent: &mut Self::State,
        edge: TraversalEdge<'_, '_>,
    ) -> Result<(Self::Seed, Self::Edge), ReusableWorkflowExpansionError>;

    fn finish_edge(
        &mut self,
        parent: &mut Self::State,
        edge: Self::Edge,
        child: Self::Output,
    ) -> Result<(), ReusableWorkflowExpansionError>;

    fn finish(
        &mut self,
        state: Self::State,
    ) -> Result<Self::Output, ReusableWorkflowExpansionError>;
}

fn traverse_reusable_invocation<C, P>(
    catalog: &C,
    policy: &mut P,
    counts: &mut TraversalCounts,
    node: TraversalNode<'_>,
    seed: P::Seed,
    active_paths: &mut Vec<String>,
    cancellation: &dyn Fn() -> bool,
) -> Result<P::Output, ReusableWorkflowExpansionError>
where
    C: ReusableWorkflowCatalogResolver,
    P: CredentialTraversalPolicy,
{
    if cancellation() {
        return Err(ReusableWorkflowExpansionError::Cancelled);
    }
    validate_reusable_workflow_depth(node.depth, counts.limits.maximum_depth())?;
    counts.invocation_count = counts
        .invocation_count
        .checked_add(1)
        .ok_or(ReusableWorkflowExpansionError::InvocationLimitExceeded)?;
    validate_reusable_workflow_invocation_count(
        counts.invocation_count,
        counts.limits.maximum_invocations(),
    )?;
    counts.job_count = counts
        .job_count
        .checked_add(node.plan.jobs().len())
        .ok_or(ReusableWorkflowExpansionError::JobLimitExceeded)?;
    validate_reusable_workflow_job_count(counts.job_count, counts.limits.maximum_jobs())?;
    if active_paths
        .iter()
        .any(|active| active == node.workflow_path)
    {
        return Err(ReusableWorkflowExpansionError::Cycle(
            node.workflow_path.to_owned(),
        ));
    }
    active_paths.push(node.workflow_path.to_owned());
    let result = (|| {
        let mut state = policy.enter(&node, seed)?;
        for job in node.plan.jobs() {
            if cancellation() {
                return Err(ReusableWorkflowExpansionError::Cancelled);
            }
            let LogicalJobKind::ReusableWorkflow(call) = job.execution() else {
                continue;
            };
            if job.strategy().is_some() {
                return Err(ReusableWorkflowExpansionError::MatrixCallUnsupported);
            }
            let callee = catalog.resolve(call.reference().value())?;
            if active_paths.iter().any(|active| active == callee.path) {
                return Err(ReusableWorkflowExpansionError::Cycle(
                    callee.path.to_owned(),
                ));
            }
            validate_plan_origin(
                callee.plan,
                catalog.authority(),
                catalog.repository(),
                catalog.revision(),
                callee.path,
            )?;
            let contract = callee.plan.logical().invocation().ok_or_else(|| {
                ReusableWorkflowExpansionError::MissingInvocationContract(callee.path.to_owned())
            })?;
            let inputs = validate_inputs(call, contract)?;
            let outputs = validate_call_outputs(job.outputs(), contract)?;
            let (child_seed, edge) = policy.prepare_edge(
                &mut state,
                TraversalEdge {
                    job,
                    call,
                    callee,
                    contract,
                    inputs,
                    outputs,
                },
            )?;
            let child = traverse_reusable_invocation(
                catalog,
                policy,
                counts,
                TraversalNode {
                    workflow_path: callee.path,
                    plan: callee.plan,
                    depth: node.depth + 1,
                    source_digest: callee.source_digest,
                    plan_digest: callee.plan_digest,
                    root: false,
                },
                child_seed,
                active_paths,
                cancellation,
            )?;
            policy.finish_edge(&mut state, edge, child)?;
        }
        policy.finish(state)
    })();
    active_paths.pop();
    result
}

#[derive(Clone)]
struct MaterializedTraversalSeed {
    id: LogicalWorkflowInvocationId,
    parent_id: Option<LogicalWorkflowInvocationId>,
    caller_job_id: Option<LogicalWorkflowJobId>,
    permissions: ReusableWorkflowPermissions,
    inputs: Vec<ExpandedReusableInput>,
    secrets: Vec<ExpandedReusableSecret>,
    available_secret_names: BTreeSet<String>,
    outputs: Vec<ExpandedReusableOutput>,
    caller_outputs: Vec<ExpandedReusableOutputMapping>,
}

struct MaterializedTraversalState {
    invocation_index: usize,
    id: LogicalWorkflowInvocationId,
    permissions: ReusableWorkflowPermissions,
    available_secret_names: BTreeSet<String>,
}

struct MaterializedCredentialPolicy<'a> {
    context: &'a mut ExpansionContext,
}

impl CredentialTraversalPolicy for MaterializedCredentialPolicy<'_> {
    type Seed = MaterializedTraversalSeed;
    type State = MaterializedTraversalState;
    type Edge = ();
    type Output = ();

    fn enter(
        &mut self,
        node: &TraversalNode<'_>,
        seed: Self::Seed,
    ) -> Result<Self::State, ReusableWorkflowExpansionError> {
        let jobs = expanded_jobs(self.context, seed.id, node.plan, node.root)?;
        let invocation_index = self.context.invocations.len();
        let id = seed.id;
        let permissions = seed.permissions.clone();
        let available_secret_names = seed.available_secret_names.clone();
        self.context
            .invocations
            .push(ReusableWorkflowInvocationExpansion {
                id,
                parent_id: seed.parent_id,
                caller_job_id: seed.caller_job_id,
                depth: u16::try_from(node.depth)
                    .map_err(|_| ReusableWorkflowExpansionError::DepthLimitExceeded)?,
                workflow_path: node.workflow_path.to_owned(),
                source_digest: node.source_digest,
                plan_digest: node.plan_digest,
                permissions: seed.permissions,
                inputs: seed.inputs,
                secrets: seed.secrets,
                outputs: seed.outputs,
                caller_outputs: seed.caller_outputs,
                jobs,
            });
        Ok(MaterializedTraversalState {
            invocation_index,
            id,
            permissions,
            available_secret_names,
        })
    }

    fn prepare_edge(
        &mut self,
        parent: &mut Self::State,
        edge: TraversalEdge<'_, '_>,
    ) -> Result<(Self::Seed, Self::Edge), ReusableWorkflowExpansionError> {
        let secrets = validate_secrets(edge.call, edge.contract, &parent.available_secret_names)?;
        let available_secret_names = secrets
            .iter()
            .map(|binding| binding.target.clone())
            .collect();
        let caller_job_id = self.context.invocations[parent.invocation_index]
            .jobs
            .iter()
            .find(|expanded| expanded.key() == edge.job.key().value())
            .map(ExpandedReusableJob::id)
            .ok_or(ReusableWorkflowExpansionError::InvalidIdentity)?;
        let invocation_id = derived_invocation_id(
            self.context.run_id,
            parent.id,
            caller_job_id,
            edge.callee.path,
            edge.callee.source_digest,
        )?;
        if !self.context.invocation_ids.insert(invocation_id.as_uuid()) {
            return Err(ReusableWorkflowExpansionError::IdentityCollision);
        }
        let permissions = parent
            .permissions
            .reduce(edge.job.permissions())
            .reduce(edge.callee.plan.logical().permissions());
        Ok((
            MaterializedTraversalSeed {
                id: invocation_id,
                parent_id: Some(parent.id),
                caller_job_id: Some(caller_job_id),
                permissions,
                inputs: edge.inputs,
                secrets,
                available_secret_names,
                outputs: contract_outputs(edge.contract),
                caller_outputs: edge.outputs,
            },
            (),
        ))
    }

    fn finish_edge(
        &mut self,
        _parent: &mut Self::State,
        (): Self::Edge,
        (): Self::Output,
    ) -> Result<(), ReusableWorkflowExpansionError> {
        Ok(())
    }

    fn finish(
        &mut self,
        _state: Self::State,
    ) -> Result<Self::Output, ReusableWorkflowExpansionError> {
        Ok(())
    }
}

enum SymbolicSecretEdge {
    Mapping(BTreeMap<String, SymbolicSecretSource>),
    Inherit,
}

enum SymbolicSecretSource {
    External(String),
    BuiltIn(BuiltInCredentialRequirement),
}

#[derive(Clone, Default)]
struct SymbolicCredentialRequirements {
    external: BTreeSet<String>,
    built_in: BTreeSet<BuiltInCredentialRequirement>,
}

struct SymbolicCredentialPolicy<'a> {
    analyses: &'a BTreeMap<String, AnalyzedLocalWorkflow>,
}

impl CredentialTraversalPolicy for SymbolicCredentialPolicy<'_> {
    type Seed = ();
    type State = SymbolicCredentialRequirements;
    type Edge = SymbolicSecretEdge;
    type Output = SymbolicCredentialRequirements;

    fn enter(
        &mut self,
        node: &TraversalNode<'_>,
        (): Self::Seed,
    ) -> Result<Self::State, ReusableWorkflowExpansionError> {
        self.analyses
            .get(node.workflow_path)
            .map(|analysis| analysis.requirements.clone())
            .ok_or(ReusableWorkflowExpansionError::InvalidIdentity)
    }

    fn prepare_edge(
        &mut self,
        _parent: &mut Self::State,
        edge: TraversalEdge<'_, '_>,
    ) -> Result<(Self::Seed, Self::Edge), ReusableWorkflowExpansionError> {
        Ok(((), symbolic_secret_edge(edge.call, edge.contract)?))
    }

    fn finish_edge(
        &mut self,
        parent: &mut Self::State,
        edge: Self::Edge,
        child: Self::Output,
    ) -> Result<(), ReusableWorkflowExpansionError> {
        parent.built_in.extend(child.built_in);
        match edge {
            SymbolicSecretEdge::Inherit => parent.external.extend(child.external),
            SymbolicSecretEdge::Mapping(bindings) => {
                for target in child.external {
                    let source = bindings.get(&target).ok_or_else(|| {
                        ReusableWorkflowExpansionError::MissingRequiredSecret(target.clone())
                    })?;
                    match source {
                        SymbolicSecretSource::External(source) => {
                            parent.external.insert(source.clone());
                        }
                        SymbolicSecretSource::BuiltIn(requirement) => {
                            parent.built_in.insert(*requirement);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn finish(
        &mut self,
        state: Self::State,
    ) -> Result<Self::Output, ReusableWorkflowExpansionError> {
        Ok(state)
    }
}

fn symbolic_secret_edge(
    call: &ReusableWorkflowInvocation,
    contract: &WorkflowInvocationContract,
) -> Result<SymbolicSecretEdge, ReusableWorkflowExpansionError> {
    let definitions = contract
        .secrets()
        .iter()
        .map(|definition| (definition.key().value().as_str(), definition))
        .collect::<BTreeMap<_, _>>();
    match call.secrets() {
        ReusableSecretForwarding::Inherit(_) => Ok(SymbolicSecretEdge::Inherit),
        ReusableSecretForwarding::Mapping(values) => {
            let mut bindings = BTreeMap::new();
            for binding in values {
                let target = binding.target().value().as_str();
                if !definitions.contains_key(target) {
                    return Err(ReusableWorkflowExpansionError::UnknownSecret(
                        target.to_owned(),
                    ));
                }
                let source = binding.source().value().as_str();
                bindings.insert(
                    target.to_ascii_uppercase(),
                    if let Some(requirement) = built_in_secret_requirement(source) {
                        SymbolicSecretSource::BuiltIn(requirement)
                    } else {
                        SymbolicSecretSource::External(source.to_ascii_uppercase())
                    },
                );
            }
            for definition in contract.secrets() {
                let target = definition.key().value().as_str().to_ascii_uppercase();
                if definition.required() && !bindings.contains_key(&target) {
                    return Err(ReusableWorkflowExpansionError::MissingRequiredSecret(
                        target,
                    ));
                }
            }
            Ok(SymbolicSecretEdge::Mapping(bindings))
        }
    }
}

#[allow(clippy::too_many_lines)]
fn expand_reusable_workflow(
    request: ExpandReusableWorkflowRequest<'_>,
    limits: ReusableWorkflowLimits,
) -> Result<ReusableWorkflowExpansion, ReusableWorkflowExpansionError> {
    let root_path =
        canonical_workflow_path(request.root_path, RepositoryWorkflowLocation::Automata)?;
    if request.root_source.is_empty() {
        return Err(ReusableWorkflowExpansionError::InvalidSourceSize);
    }
    validate_reusable_workflow_source_bytes(request.root_source.len())?;
    validate_plan_origin(
        request.root_plan,
        CatalogSourceAuthority::GithubDelivery,
        request.catalog.repository(),
        request.catalog.revision(),
        &root_path,
    )?;
    let recompiled_root = recompile_root_source(
        request.catalog.repository(),
        request.catalog.revision(),
        &root_path,
        request.root_source,
        request.root_plan.event().clone(),
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
        invocation_ids: BTreeSet::from([request.root_invocation_id.as_uuid()]),
        job_ids: BTreeSet::new(),
        invocations: Vec::new(),
    };
    let mut counts = TraversalCounts {
        limits,
        invocation_count: 0,
        job_count: 0,
    };
    let mut active_paths = Vec::new();
    let mut policy = MaterializedCredentialPolicy {
        context: &mut context,
    };
    traverse_reusable_invocation(
        request.catalog,
        &mut policy,
        &mut counts,
        TraversalNode {
            workflow_path: &root_path,
            plan: request.root_plan,
            depth: 0,
            source_digest: root_source_digest,
            plan_digest: root_plan_digest,
            root: true,
        },
        MaterializedTraversalSeed {
            id: request.root_invocation_id,
            parent_id: None,
            caller_job_id: None,
            permissions: root_permissions,
            inputs: Vec::new(),
            secrets: Vec::new(),
            available_secret_names: request.root_secret_names.clone(),
            outputs: root_outputs,
            caller_outputs: Vec::new(),
        },
        &mut active_paths,
        &|| false,
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

fn expanded_jobs(
    context: &mut ExpansionContext,
    invocation_id: LogicalWorkflowInvocationId,
    plan: &WorkflowPlan,
    root: bool,
) -> Result<Vec<ExpandedReusableJob>, ReusableWorkflowExpansionError> {
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
                let Some(source) = available
                    .iter()
                    .find(|candidate| candidate.eq_ignore_ascii_case(source))
                else {
                    return Err(ReusableWorkflowExpansionError::UnavailableSecret(
                        source.to_owned(),
                    ));
                };
                supplied.insert(target, source.clone());
            }
        }
        ReusableSecretForwarding::Inherit(_) => {
            for source in available {
                supplied.insert(source.as_str(), source.clone());
            }
            for definition in contract.secrets() {
                let target = definition.key().value().as_str();
                let Some(source) = available
                    .iter()
                    .find(|candidate| candidate.eq_ignore_ascii_case(target))
                else {
                    continue;
                };
                supplied.remove(source.as_str());
                supplied.insert(target, source.clone());
            }
        }
    }

    for definition in contract.secrets() {
        let target = definition.key().value().as_str();
        if definition.required() && !supplied.contains_key(target) {
            return Err(ReusableWorkflowExpansionError::MissingRequiredSecret(
                target.to_owned(),
            ));
        }
    }

    Ok(supplied
        .into_iter()
        .map(|(target, source)| ExpandedReusableSecret {
            target: target.to_owned(),
            source,
        })
        .collect())
}

fn validate_call_outputs(
    call_outputs: &[automata_ci_core::LogicalJobOutputDefinition],
    contract: &WorkflowInvocationContract,
) -> Result<Vec<ExpandedReusableOutputMapping>, ReusableWorkflowExpansionError> {
    let outputs = contract
        .outputs()
        .iter()
        .map(|output| (output.key().value().as_str(), output))
        .collect::<BTreeMap<_, _>>();
    call_outputs
        .iter()
        .map(|output| {
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
            Ok(ExpandedReusableOutputMapping {
                parent_key: output.key().value().as_str().to_owned(),
                child_key: key.to_owned(),
                sensitivity: output.sensitivity(),
            })
        })
        .collect()
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

fn compile_reusable_source(
    repository: &str,
    revision: &str,
    path: &str,
    source: &[u8],
) -> Result<WorkflowPlan, ReusableWorkflowExpansionError> {
    compile_source(
        repository,
        revision,
        path,
        source,
        ReusableCompilationSelection::GithubWorkflowCall,
    )
}

fn recompile_root_source(
    repository: &str,
    revision: &str,
    path: &str,
    source: &[u8],
    event: automata_ci_core::WorkflowEventProvenance,
) -> Result<WorkflowPlan, ReusableWorkflowExpansionError> {
    compile_source(
        repository,
        revision,
        path,
        source,
        ReusableCompilationSelection::GithubPreselected(Box::new(event)),
    )
}

enum ReusableCompilationSelection {
    GithubPreselected(Box<automata_ci_core::WorkflowEventProvenance>),
    GithubWorkflowCall,
}

fn compile_source(
    repository: &str,
    revision: &str,
    path: &str,
    source: &[u8],
    selection: ReusableCompilationSelection,
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
    let request = match selection {
        ReusableCompilationSelection::GithubPreselected(event) => {
            CompileWorkflowRequest::for_preselected_event(source_plan, *event)
        }
        ReusableCompilationSelection::GithubWorkflowCall => CompileWorkflowRequest::new(
            source_plan,
            automata_ci_core::WorkflowEventProvenance::new("github", "workflow_call")
                .with_commit_sha(revision),
        ),
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
    authority: CatalogSourceAuthority,
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
    if plan.source().provider() != authority.provider()
        || plan.source().source_id() != path
        || plan_repository != repository
        || plan_revision != revision
        || plan_path != path
    {
        return Err(ReusableWorkflowExpansionError::RootPlanMismatch);
    }
    Ok(())
}

fn canonical_workflow_path(
    value: &str,
    workflow_location: RepositoryWorkflowLocation,
) -> Result<String, ReusableWorkflowExpansionError> {
    validate_reusable_workflow_path_bytes(value.len())?;
    if value.is_empty()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return Err(ReusableWorkflowExpansionError::InvalidWorkflowPath);
    }
    let components = value.split('/').collect::<Vec<_>>();
    let [dot_ci, workflows, file] = components.as_slice() else {
        return Err(ReusableWorkflowExpansionError::InvalidWorkflowPath);
    };
    let extension = Path::new(file).extension();
    let expected_directory = match workflow_location {
        RepositoryWorkflowLocation::Automata => ".ci",
        RepositoryWorkflowLocation::Github => ".github",
    };
    if *dot_ci != expected_directory
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

fn resolve_local_reference(
    reference: &str,
    workflow_location: RepositoryWorkflowLocation,
) -> Result<String, ReusableWorkflowExpansionError> {
    let prefix = match workflow_location {
        RepositoryWorkflowLocation::Automata => "./.ci/workflows/",
        RepositoryWorkflowLocation::Github => "./.github/workflows/",
    };
    let Some(file) = reference.strip_prefix(prefix) else {
        return Err(ReusableWorkflowExpansionError::NonLocalReference);
    };
    if file.is_empty() || file.contains('/') || file.contains('\\') {
        return Err(ReusableWorkflowExpansionError::NonLocalReference);
    }
    canonical_workflow_path(reference.trim_start_matches("./"), workflow_location)
        .map_err(|_| ReusableWorkflowExpansionError::NonLocalReference)
}

fn validate_coordinate(value: &str) -> Result<(), ReusableWorkflowExpansionError> {
    validate_reusable_repository_coordinate_bytes(value.len())?;
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
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
    validate_reusable_permission_name_bytes(name.len())?;
    if name.is_empty() || name.trim() != name || name.chars().any(char::is_control) {
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
        hash_u64(&mut hasher, invocation.caller_outputs.len())?;
        for output in &invocation.caller_outputs {
            hash_part(&mut hasher, output.parent_key.as_bytes());
            hash_part(&mut hasher, output.child_key.as_bytes());
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

#[cfg(test)]
mod limit_contract_tests {
    use super::*;

    #[test]
    fn reusable_catalog_entry_limit_has_exact_boundaries() {
        assert!(
            validate_reusable_catalog_entry_count(MAX_REUSABLE_WORKFLOW_CATALOG_ENTRIES - 1)
                .is_ok()
        );
        assert!(
            validate_reusable_catalog_entry_count(MAX_REUSABLE_WORKFLOW_CATALOG_ENTRIES).is_ok()
        );
        assert_eq!(
            validate_reusable_catalog_entry_count(MAX_REUSABLE_WORKFLOW_CATALOG_ENTRIES + 1),
            Err(ReusableWorkflowExpansionError::CatalogLimitExceeded)
        );
    }

    #[test]
    fn reusable_workflow_depth_limit_has_exact_boundaries() {
        let minus_one = MAX_REUSABLE_WORKFLOW_DEPTH - 1;
        let at = MAX_REUSABLE_WORKFLOW_DEPTH;
        let plus_one = MAX_REUSABLE_WORKFLOW_DEPTH + 1;
        assert!(validate_reusable_workflow_depth(minus_one, MAX_REUSABLE_WORKFLOW_DEPTH).is_ok());
        assert!(validate_reusable_workflow_depth(at, MAX_REUSABLE_WORKFLOW_DEPTH).is_ok());
        assert_eq!(
            validate_reusable_workflow_depth(plus_one, MAX_REUSABLE_WORKFLOW_DEPTH),
            Err(ReusableWorkflowExpansionError::DepthLimitExceeded)
        );
    }

    #[test]
    fn reusable_workflow_invocation_limit_has_exact_boundaries() {
        let minus_one = MAX_REUSABLE_WORKFLOW_INVOCATIONS - 1;
        let at = MAX_REUSABLE_WORKFLOW_INVOCATIONS;
        let plus_one = MAX_REUSABLE_WORKFLOW_INVOCATIONS + 1;
        assert!(
            validate_reusable_workflow_invocation_count(
                minus_one,
                MAX_REUSABLE_WORKFLOW_INVOCATIONS
            )
            .is_ok()
        );
        assert!(
            validate_reusable_workflow_invocation_count(at, MAX_REUSABLE_WORKFLOW_INVOCATIONS)
                .is_ok()
        );
        assert_eq!(
            validate_reusable_workflow_invocation_count(
                plus_one,
                MAX_REUSABLE_WORKFLOW_INVOCATIONS
            ),
            Err(ReusableWorkflowExpansionError::InvocationLimitExceeded)
        );
    }

    #[test]
    fn reusable_workflow_job_limit_has_exact_boundaries() {
        let minus_one = MAX_REUSABLE_WORKFLOW_EXPANDED_JOBS - 1;
        let at = MAX_REUSABLE_WORKFLOW_EXPANDED_JOBS;
        let plus_one = MAX_REUSABLE_WORKFLOW_EXPANDED_JOBS + 1;
        assert!(
            validate_reusable_workflow_job_count(minus_one, MAX_REUSABLE_WORKFLOW_EXPANDED_JOBS)
                .is_ok()
        );
        assert!(
            validate_reusable_workflow_job_count(at, MAX_REUSABLE_WORKFLOW_EXPANDED_JOBS).is_ok()
        );
        assert_eq!(
            validate_reusable_workflow_job_count(plus_one, MAX_REUSABLE_WORKFLOW_EXPANDED_JOBS),
            Err(ReusableWorkflowExpansionError::JobLimitExceeded)
        );
    }

    #[test]
    fn reusable_workflow_source_byte_limit_has_exact_boundaries() {
        assert!(
            validate_reusable_workflow_source_bytes(MAX_REUSABLE_WORKFLOW_SOURCE_BYTES - 1).is_ok()
        );
        assert!(
            validate_reusable_workflow_source_bytes(MAX_REUSABLE_WORKFLOW_SOURCE_BYTES).is_ok()
        );
        assert_eq!(
            validate_reusable_workflow_source_bytes(MAX_REUSABLE_WORKFLOW_SOURCE_BYTES + 1),
            Err(ReusableWorkflowExpansionError::InvalidSourceSize)
        );
    }

    #[test]
    fn reusable_workflow_path_byte_limit_has_exact_boundaries() {
        assert!(
            validate_reusable_workflow_path_bytes(MAX_REUSABLE_WORKFLOW_PATH_BYTES - 1).is_ok()
        );
        assert!(validate_reusable_workflow_path_bytes(MAX_REUSABLE_WORKFLOW_PATH_BYTES).is_ok());
        assert_eq!(
            validate_reusable_workflow_path_bytes(MAX_REUSABLE_WORKFLOW_PATH_BYTES + 1),
            Err(ReusableWorkflowExpansionError::InvalidWorkflowPath)
        );
    }

    #[test]
    fn reusable_repository_coordinate_byte_limit_has_exact_boundaries() {
        assert!(
            validate_reusable_repository_coordinate_bytes(MAX_REUSABLE_WORKFLOW_PATH_BYTES - 1)
                .is_ok()
        );
        assert!(
            validate_reusable_repository_coordinate_bytes(MAX_REUSABLE_WORKFLOW_PATH_BYTES).is_ok()
        );
        assert_eq!(
            validate_reusable_repository_coordinate_bytes(MAX_REUSABLE_WORKFLOW_PATH_BYTES + 1),
            Err(ReusableWorkflowExpansionError::InvalidRepositoryCoordinate)
        );
    }

    #[test]
    fn reusable_permission_name_byte_limit_has_exact_boundaries() {
        assert!(validate_reusable_permission_name_bytes(MAX_PERMISSION_NAME_BYTES - 1).is_ok());
        assert!(validate_reusable_permission_name_bytes(MAX_PERMISSION_NAME_BYTES).is_ok());
        assert_eq!(
            validate_reusable_permission_name_bytes(MAX_PERMISSION_NAME_BYTES + 1),
            Err(ReusableWorkflowExpansionError::InvalidPermissionName)
        );
    }

    #[test]
    fn reusable_permission_grant_limit_has_exact_boundaries() {
        assert!(validate_reusable_permission_grant_count(MAX_PERMISSION_GRANTS - 1).is_ok());
        assert!(validate_reusable_permission_grant_count(MAX_PERMISSION_GRANTS).is_ok());
        assert_eq!(
            validate_reusable_permission_grant_count(MAX_PERMISSION_GRANTS + 1),
            Err(ReusableWorkflowExpansionError::PermissionLimitExceeded)
        );
    }
}
