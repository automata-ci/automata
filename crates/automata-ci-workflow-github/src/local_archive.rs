//! Closed local-archive compilation for the GitHub Actions dialect.

use std::{collections::BTreeMap, path::Path, sync::Arc};

use automata_ci_core::{LogicalJobKind, Sha256Digest, WorkflowPlan};
use sha2::{Digest as _, Sha256};

use crate::compiler::{LocalWorkflowDispatchEvidence, LocalWorkflowSourceEvidence};
use crate::repository_archive::discover_local_github_workflows;
use crate::{
    CompilationDisposition, CompileWorkflowRequest, Diagnostic, GithubWorkflowCompiler,
    GithubWorkflowDispatchInputs, GithubWorkflowFrontend, ParseWorkflowRequest,
    RepositoryWorkflowDiscoveryLimits, SourceId, SourceOrigin, SourceProvenance,
    WorkflowFrontend as _,
};

const LOCAL_SOURCE_REPOSITORY: &str = "local";
const MAX_LOCAL_WORKFLOW_SELECTOR_BYTES: usize = 1_024;

/// Closed failure class for exact local GitHub-workflow archive compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalGithubArchiveCompilationFailureKind {
    /// Cooperative cancellation interrupted archive inspection or compilation.
    Cancelled,
    /// The sealed archive failed its local `.github/workflows` policy.
    Archive,
    /// The archive contains no direct `.github/workflows` YAML workflow.
    WorkflowMissing,
    /// More than one workflow requires one exact canonical selector.
    WorkflowSelectionRequired,
    /// The supplied selector is not one exact discovered workflow path.
    WorkflowNotFound,
    /// A selected source is empty, oversized, or not UTF-8.
    WorkflowSource,
    /// The source frontend rejected the selected root workflow.
    Frontend,
    /// Explicit local `workflow_dispatch` selection rejected the root workflow.
    Compilation,
    /// A reachable reusable workflow is missing, remote, dynamic, invalid, or excessive.
    ReusableWorkflow,
}

/// Sanitized local archive compilation failure with source diagnostics.
#[derive(Clone, Debug)]
pub struct LocalGithubArchiveCompilationFailure {
    kind: LocalGithubArchiveCompilationFailureKind,
    diagnostics: Vec<Diagnostic>,
}

impl LocalGithubArchiveCompilationFailure {
    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(&self) -> LocalGithubArchiveCompilationFailureKind {
        self.kind
    }

    /// Returns value-free source diagnostics produced before failure.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    fn new(kind: LocalGithubArchiveCompilationFailureKind) -> Self {
        Self {
            kind,
            diagnostics: Vec::new(),
        }
    }

    fn with_diagnostics(
        kind: LocalGithubArchiveCompilationFailureKind,
        diagnostics: Vec<Diagnostic>,
    ) -> Self {
        Self { kind, diagnostics }
    }
}

/// One reachable reusable workflow compiled from membership-proven archive bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalGithubCompiledReusableWorkflow {
    path: String,
    source_digest: Sha256Digest,
    plan: WorkflowPlan,
}

impl LocalGithubCompiledReusableWorkflow {
    /// Returns the exact canonical same-archive source path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns SHA-256 over this workflow's exact discovered source bytes.
    #[must_use]
    pub const fn source_digest(&self) -> Sha256Digest {
        self.source_digest
    }

    /// Returns the local-only `workflow_call` plan.
    #[must_use]
    pub const fn plan(&self) -> &WorkflowPlan {
        &self.plan
    }
}

/// Complete root and reachable reusable compilation derived from one archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalGithubArchiveCompilation {
    snapshot_digest: Sha256Digest,
    selected_path: String,
    root_source_digest: Sha256Digest,
    root_plan: WorkflowPlan,
    reusable_workflows: Vec<LocalGithubCompiledReusableWorkflow>,
    diagnostics: Vec<Diagnostic>,
}

impl LocalGithubArchiveCompilation {
    /// Returns SHA-256 over the exact sealed archive bytes inspected here.
    #[must_use]
    pub const fn snapshot_digest(&self) -> Sha256Digest {
        self.snapshot_digest
    }

    /// Returns the exact selected canonical `.github/workflows` path.
    #[must_use]
    pub fn selected_path(&self) -> &str {
        &self.selected_path
    }

    /// Returns SHA-256 over the exact selected root source bytes.
    #[doc(hidden)]
    #[must_use]
    pub const fn root_source_digest(&self) -> Sha256Digest {
        self.root_source_digest
    }

    /// Returns the local-only root `workflow_dispatch` plan.
    #[must_use]
    pub const fn root_plan(&self) -> &WorkflowPlan {
        &self.root_plan
    }

    /// Returns only reachable same-archive reusable workflows in path order.
    #[must_use]
    pub fn reusable_workflows(&self) -> &[LocalGithubCompiledReusableWorkflow] {
        &self.reusable_workflows
    }

    /// Returns all value-free root and reusable source diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
}

/// Discovers and compiles one exact local GitHub workflow archive without
/// provider admission or execution authority.
///
/// The archive digest, local source provenance, root membership, and reusable
/// membership are derived internally from `archive_bytes`. Callers cannot
/// provide or coordinate any of those values independently. Only direct
/// `.github/workflows/*.{yml,yaml}` sources and same-archive relative reusable
/// references are accepted.
///
/// # Errors
///
/// Returns a sanitized failure for cancellation, unsafe or excessive archive
/// content, non-exact selection, rejected source, unsupported trigger, or an
/// invalid reachable reusable reference.
pub fn compile_local_github_archive(
    archive_bytes: &[u8],
    selector: Option<&str>,
    inputs: GithubWorkflowDispatchInputs,
    limits: RepositoryWorkflowDiscoveryLimits,
    cancellation: &dyn Fn() -> bool,
) -> Result<LocalGithubArchiveCompilation, LocalGithubArchiveCompilationFailure> {
    check_cancelled(cancellation)?;
    if selector.is_some_and(|path| !valid_selector(path)) {
        return Err(LocalGithubArchiveCompilationFailure::new(
            LocalGithubArchiveCompilationFailureKind::WorkflowNotFound,
        ));
    }
    let snapshot_digest = Sha256Digest::from_bytes(Sha256::digest(archive_bytes).into());
    let discovered =
        discover_local_github_workflows(archive_bytes, limits, cancellation).map_err(|error| {
            LocalGithubArchiveCompilationFailure::new(
                if matches!(error, crate::RepositoryWorkflowDiscoveryError::Cancelled) {
                    LocalGithubArchiveCompilationFailureKind::Cancelled
                } else {
                    LocalGithubArchiveCompilationFailureKind::Archive
                },
            )
        })?;
    check_cancelled(cancellation)?;

    let mut available = discovered
        .into_iter()
        .map(crate::RepositoryWorkflowDiscoveryOutcome::into_parts)
        .collect::<BTreeMap<_, _>>();
    let selected_path = select_workflow(&available, selector)?.to_owned();
    let selected_source = available
        .get(&selected_path)
        .ok_or_else(|| {
            LocalGithubArchiveCompilationFailure::new(
                LocalGithubArchiveCompilationFailureKind::WorkflowNotFound,
            )
        })?
        .as_ref()
        .map_err(|_| {
            LocalGithubArchiveCompilationFailure::new(
                LocalGithubArchiveCompilationFailureKind::WorkflowSource,
            )
        })?;
    let root_source_digest = Sha256Digest::from_bytes(Sha256::digest(selected_source).into());
    let (root_plan, diagnostics) = compile_source(
        &selected_path,
        selected_source,
        snapshot_digest,
        LocalCompilationEvent::WorkflowDispatch(inputs),
        cancellation,
    )?;
    let (reusable_workflows, diagnostics) = compile_reusable_workflows(
        &root_plan,
        &selected_path,
        snapshot_digest,
        &mut available,
        limits,
        diagnostics,
        cancellation,
    )?;

    Ok(LocalGithubArchiveCompilation {
        snapshot_digest,
        selected_path,
        root_source_digest,
        root_plan,
        reusable_workflows,
        diagnostics,
    })
}

fn compile_reusable_workflows(
    root_plan: &WorkflowPlan,
    selected_path: &str,
    snapshot_digest: Sha256Digest,
    available: &mut BTreeMap<String, Result<Vec<u8>, crate::RepositoryWorkflowDiscoveryFailure>>,
    limits: RepositoryWorkflowDiscoveryLimits,
    mut diagnostics: Vec<Diagnostic>,
    cancellation: &dyn Fn() -> bool,
) -> Result<
    (Vec<LocalGithubCompiledReusableWorkflow>, Vec<Diagnostic>),
    LocalGithubArchiveCompilationFailure,
> {
    let mut pending = reusable_references(root_plan);
    let mut reusable = BTreeMap::new();
    while let Some(reference) = pending.pop() {
        check_cancelled(cancellation)?;
        let path = resolve_local_reference(&reference)?;
        if path == selected_path {
            return Err(LocalGithubArchiveCompilationFailure::with_diagnostics(
                LocalGithubArchiveCompilationFailureKind::ReusableWorkflow,
                diagnostics,
            ));
        }
        if reusable.contains_key(&path) {
            continue;
        }
        if reusable.len() >= limits.maximum_workflows() {
            return Err(LocalGithubArchiveCompilationFailure::with_diagnostics(
                LocalGithubArchiveCompilationFailureKind::ReusableWorkflow,
                diagnostics,
            ));
        }
        let source = available
            .remove(&path)
            .ok_or_else(|| {
                LocalGithubArchiveCompilationFailure::with_diagnostics(
                    LocalGithubArchiveCompilationFailureKind::ReusableWorkflow,
                    diagnostics.clone(),
                )
            })?
            .map_err(|_| {
                LocalGithubArchiveCompilationFailure::with_diagnostics(
                    LocalGithubArchiveCompilationFailureKind::WorkflowSource,
                    diagnostics.clone(),
                )
            })?;
        let source_digest = Sha256Digest::from_bytes(Sha256::digest(&source).into());
        let (plan, source_diagnostics) = compile_source(
            &path,
            &source,
            snapshot_digest,
            LocalCompilationEvent::WorkflowCall,
            cancellation,
        )
        .map_err(|failure| {
            let mut all = diagnostics.clone();
            all.extend_from_slice(failure.diagnostics());
            LocalGithubArchiveCompilationFailure::with_diagnostics(
                LocalGithubArchiveCompilationFailureKind::ReusableWorkflow,
                all,
            )
        })?;
        if plan.logical().invocation().is_none() {
            return Err(LocalGithubArchiveCompilationFailure::with_diagnostics(
                LocalGithubArchiveCompilationFailureKind::ReusableWorkflow,
                diagnostics,
            ));
        }
        pending.extend(reusable_references(&plan));
        diagnostics.extend(source_diagnostics);
        reusable.insert(
            path.clone(),
            LocalGithubCompiledReusableWorkflow {
                path,
                source_digest,
                plan,
            },
        );
    }

    Ok((reusable.into_values().collect(), diagnostics))
}

fn select_workflow<'a>(
    available: &'a BTreeMap<String, Result<Vec<u8>, crate::RepositoryWorkflowDiscoveryFailure>>,
    selector: Option<&str>,
) -> Result<&'a str, LocalGithubArchiveCompilationFailure> {
    match selector {
        Some(path) => available
            .get_key_value(path)
            .map(|(path, _)| path.as_str())
            .ok_or_else(|| {
                LocalGithubArchiveCompilationFailure::new(
                    LocalGithubArchiveCompilationFailureKind::WorkflowNotFound,
                )
            }),
        None => match available
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
        {
            [] => Err(LocalGithubArchiveCompilationFailure::new(
                LocalGithubArchiveCompilationFailureKind::WorkflowMissing,
            )),
            [path] => Ok(path),
            _ => Err(LocalGithubArchiveCompilationFailure::new(
                LocalGithubArchiveCompilationFailureKind::WorkflowSelectionRequired,
            )),
        },
    }
}

enum LocalCompilationEvent {
    WorkflowDispatch(GithubWorkflowDispatchInputs),
    WorkflowCall,
}

fn compile_source(
    path: &str,
    source: &[u8],
    snapshot_digest: Sha256Digest,
    event: LocalCompilationEvent,
    cancellation: &dyn Fn() -> bool,
) -> Result<(WorkflowPlan, Vec<Diagnostic>), LocalGithubArchiveCompilationFailure> {
    check_cancelled(cancellation)?;
    let source = std::str::from_utf8(source).map_err(|_| {
        LocalGithubArchiveCompilationFailure::new(
            LocalGithubArchiveCompilationFailureKind::WorkflowSource,
        )
    })?;
    let revision = snapshot_digest.to_string();
    let provenance = SourceProvenance::new(
        SourceId::new(path),
        SourceOrigin::Repository {
            repository: Arc::from(LOCAL_SOURCE_REPOSITORY),
            revision: Arc::from(revision),
            path: Arc::from(path),
        },
    );
    let parsed =
        GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(provenance, source));
    let mut diagnostics = parsed.diagnostics().to_vec();
    if !parsed.is_accepted() {
        return Err(LocalGithubArchiveCompilationFailure::with_diagnostics(
            LocalGithubArchiveCompilationFailureKind::Frontend,
            diagnostics,
        ));
    }
    let source_plan = parsed.plan().ok_or_else(|| {
        LocalGithubArchiveCompilationFailure::with_diagnostics(
            LocalGithubArchiveCompilationFailureKind::Frontend,
            diagnostics.clone(),
        )
    })?;
    check_cancelled(cancellation)?;
    let evidence = LocalWorkflowSourceEvidence::new(snapshot_digest);
    let request = match event {
        LocalCompilationEvent::WorkflowDispatch(inputs) => {
            CompileWorkflowRequest::for_local_workflow_dispatch(
                source_plan,
                LocalWorkflowDispatchEvidence::new(evidence, inputs),
            )
        }
        LocalCompilationEvent::WorkflowCall => {
            CompileWorkflowRequest::for_local_workflow_call(source_plan, evidence)
        }
    };
    let compiled = GithubWorkflowCompiler::new().compile(request);
    diagnostics.extend_from_slice(compiled.diagnostics());
    if compiled.disposition() != CompilationDisposition::Accepted {
        return Err(LocalGithubArchiveCompilationFailure::with_diagnostics(
            LocalGithubArchiveCompilationFailureKind::Compilation,
            diagnostics,
        ));
    }
    let (plan, _) = compiled.into_parts();
    let plan = plan.ok_or_else(|| {
        LocalGithubArchiveCompilationFailure::with_diagnostics(
            LocalGithubArchiveCompilationFailureKind::Compilation,
            diagnostics.clone(),
        )
    })?;
    check_cancelled(cancellation)?;
    Ok((plan, diagnostics))
}

fn reusable_references(plan: &WorkflowPlan) -> Vec<String> {
    plan.jobs()
        .iter()
        .filter_map(|job| match job.execution() {
            LogicalJobKind::ReusableWorkflow(call) => Some(call.reference().value().clone()),
            LogicalJobKind::Steps(_) => None,
        })
        .collect()
}

fn resolve_local_reference(
    reference: &str,
) -> Result<String, LocalGithubArchiveCompilationFailure> {
    let Some(path) = reference.strip_prefix("./") else {
        return Err(LocalGithubArchiveCompilationFailure::new(
            LocalGithubArchiveCompilationFailureKind::ReusableWorkflow,
        ));
    };
    if !valid_selector(path) {
        return Err(LocalGithubArchiveCompilationFailure::new(
            LocalGithubArchiveCompilationFailureKind::ReusableWorkflow,
        ));
    }
    Ok(path.to_owned())
}

fn valid_selector(path: &str) -> bool {
    if path.is_empty()
        || path.len() > MAX_LOCAL_WORKFLOW_SELECTOR_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
    {
        return false;
    }
    let components = path.split('/').collect::<Vec<_>>();
    let [dot_github, workflows, file] = components.as_slice() else {
        return false;
    };
    *dot_github == ".github"
        && *workflows == "workflows"
        && !file.is_empty()
        && !matches!(*file, "." | "..")
        && matches!(
            Path::new(file).extension().and_then(|value| value.to_str()),
            Some("yml" | "yaml")
        )
}

fn check_cancelled(
    cancellation: &dyn Fn() -> bool,
) -> Result<(), LocalGithubArchiveCompilationFailure> {
    if cancellation() {
        Err(LocalGithubArchiveCompilationFailure::new(
            LocalGithubArchiveCompilationFailureKind::Cancelled,
        ))
    } else {
        Ok(())
    }
}
