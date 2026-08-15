use std::{path::PathBuf, sync::Arc};

use automata_ci_core::{LogicalJobKind, Sha256Digest, WorkflowPlan};
use automata_ci_workflow_github::{
    CompilationDisposition, CompileWorkflowRequest, Diagnostic, GithubWorkflowCompiler,
    GithubWorkflowFrontend, LocalWorkflowDispatchEvidence, LocalWorkflowDispatchInputs,
    LocalWorkflowSourceEvidence, ParseWorkflowRequest, RepositoryWorkflowDiscoveryLimits,
    RepositoryWorkflowDiscoveryOutcome, RepositoryWorkflowLocation, SourceId, SourceOrigin,
    SourceProvenance, WorkflowFrontend as _,
};
use automata_ci_workflow_service::{
    GithubReusableWorkflowCatalog, GithubReusableWorkflowSourceAuthority, RepositoryWorkflowSource,
    discover_job_credential_requirements,
};
use bytes::Bytes;
use serde::Serialize;

use crate::{LocalRepositoryId, LocalSnapshot, LocalSnapshotRequest, capture_snapshot};

const LOCAL_CHECK_SCHEMA: u32 = 1;
const MAX_WORKFLOW_SELECTOR_BYTES: usize = 1_024;

/// Read-only request to validate one workflow from one exact local snapshot.
#[derive(Clone, Debug)]
pub struct LocalCheckRequest {
    directory: PathBuf,
    workflow: Option<String>,
    inputs: LocalWorkflowDispatchInputs,
    limits: RepositoryWorkflowDiscoveryLimits,
}

impl LocalCheckRequest {
    /// Creates a source-only local validation request.
    #[must_use]
    pub fn new(
        directory: impl Into<PathBuf>,
        workflow: Option<String>,
        inputs: LocalWorkflowDispatchInputs,
    ) -> Self {
        Self {
            directory: directory.into(),
            workflow,
            inputs,
            limits: RepositoryWorkflowDiscoveryLimits::default(),
        }
    }

    #[cfg(test)]
    fn with_limits(mut self, limits: RepositoryWorkflowDiscoveryLimits) -> Self {
        self.limits = limits;
        self
    }
}

/// Stable result of read-only local workflow validation.
#[derive(Clone, Debug, Serialize)]
pub struct LocalCheckReport {
    schema: u32,
    valid: bool,
    source: Option<LocalCheckSource>,
    required_root_secrets: Vec<String>,
    workflows: Vec<LocalCheckedWorkflow>,
    diagnostics: Vec<LocalCheckDiagnostic>,
    issue: Option<LocalCheckIssue>,
}

impl LocalCheckReport {
    /// Returns whether source capture, selection, compilation, reachable
    /// reusable-workflow loading, and credential discovery all succeeded.
    #[must_use]
    pub const fn valid(&self) -> bool {
        self.valid
    }

    /// Returns retained source evidence when snapshot capture succeeded.
    #[must_use]
    pub const fn source(&self) -> Option<&LocalCheckSource> {
        self.source.as_ref()
    }

    /// Returns canonical secret names required from the local root scope after
    /// reusable-workflow mapping and inheritance propagation.
    #[must_use]
    pub fn required_root_secrets(&self) -> &[String] {
        &self.required_root_secrets
    }

    /// Returns checked root and reachable reusable workflows in path order.
    #[must_use]
    pub fn workflows(&self) -> &[LocalCheckedWorkflow] {
        &self.workflows
    }

    /// Returns sanitized frontend and compiler diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[LocalCheckDiagnostic] {
        &self.diagnostics
    }

    /// Returns the stable failure, when validation did not complete.
    #[must_use]
    pub const fn issue(&self) -> Option<&LocalCheckIssue> {
        self.issue.as_ref()
    }
}

/// Value-free source evidence retained by a local check.
#[derive(Clone, Debug, Serialize)]
pub struct LocalCheckSource {
    repository_id: LocalRepositoryId,
    snapshot_digest: Sha256Digest,
    head: String,
    dirty: bool,
    workflow_location: &'static str,
    workflow_path: Option<String>,
    entry_count: usize,
    expanded_bytes: u64,
}

impl LocalCheckSource {
    /// Returns the selected canonical repository-relative workflow path.
    #[must_use]
    pub fn workflow_path(&self) -> Option<&str> {
        self.workflow_path.as_deref()
    }

    /// Returns whether the sealed live worktree differed from `HEAD`.
    #[must_use]
    pub const fn dirty(&self) -> bool {
        self.dirty
    }

    /// Returns SHA-256 over the exact archive bytes compiled by the check.
    #[must_use]
    pub const fn snapshot_digest(&self) -> Sha256Digest {
        self.snapshot_digest
    }
}

/// Value-free requirements for one compiled workflow source.
#[derive(Clone, Debug, Serialize)]
pub struct LocalCheckedWorkflow {
    path: String,
    reusable: bool,
    jobs: Vec<LocalCheckedJob>,
}

impl LocalCheckedWorkflow {
    /// Returns the canonical repository-relative source path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns job requirements in source order.
    #[must_use]
    pub fn jobs(&self) -> &[LocalCheckedJob] {
        &self.jobs
    }

    /// Returns whether this source was loaded through a reachable reusable call.
    #[must_use]
    pub const fn reusable(&self) -> bool {
        self.reusable
    }
}

/// Static credential names and execution kind discovered for one logical job.
#[derive(Clone, Debug, Serialize)]
pub struct LocalCheckedJob {
    id: String,
    kind: &'static str,
    environment_required: bool,
    secrets: Vec<String>,
    variables: Vec<String>,
}

impl LocalCheckedJob {
    /// Returns the source-level job identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns `steps` or `reusable_workflow` for the compiled job kind.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        self.kind
    }

    /// Returns whether activation must resolve a deployment environment.
    #[must_use]
    pub const fn environment_required(&self) -> bool {
        self.environment_required
    }

    /// Returns sorted, canonical secret names without values.
    #[must_use]
    pub fn secrets(&self) -> &[String] {
        &self.secrets
    }

    /// Returns sorted, canonical variable names without values.
    #[must_use]
    pub fn variables(&self) -> &[String] {
        &self.variables
    }
}

/// Sanitized source-bound diagnostic.
#[derive(Clone, Debug, Serialize)]
pub struct LocalCheckDiagnostic {
    kind: &'static str,
    severity: &'static str,
    code: String,
    message: String,
    source: String,
    line: usize,
    column: usize,
}

impl LocalCheckDiagnostic {
    /// Returns the stable dialect diagnostic code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the sanitized diagnostic message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Stable failure class for a local workflow check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalCheckIssueCode {
    /// Exact local snapshot capture failed.
    Snapshot,
    /// The repository contains no explicit workflow namespace.
    WorkflowNamespaceMissing,
    /// No workflow was discovered in the explicit namespace.
    WorkflowMissing,
    /// More than one workflow requires an explicit canonical selector.
    WorkflowSelectionRequired,
    /// The supplied workflow selector is not one exact discovered path.
    WorkflowNotFound,
    /// The selected workflow source is empty, oversized, or not UTF-8.
    WorkflowSource,
    /// The GitHub Actions frontend rejected the selected source.
    Frontend,
    /// The selected local `workflow_dispatch` invocation did not compile.
    Compilation,
    /// A reachable same-snapshot reusable workflow could not be loaded.
    ReusableWorkflow,
    /// Static credential-reference discovery rejected dynamic or invalid access.
    CredentialDiscovery,
}

impl LocalCheckIssueCode {
    /// Returns the stable snake-case report code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::WorkflowNamespaceMissing => "workflow_namespace_missing",
            Self::WorkflowMissing => "workflow_missing",
            Self::WorkflowSelectionRequired => "workflow_selection_required",
            Self::WorkflowNotFound => "workflow_not_found",
            Self::WorkflowSource => "workflow_source",
            Self::Frontend => "frontend",
            Self::Compilation => "compilation",
            Self::ReusableWorkflow => "reusable_workflow",
            Self::CredentialDiscovery => "credential_discovery",
        }
    }
}

/// One sanitized local-check failure.
#[derive(Clone, Debug, Serialize)]
pub struct LocalCheckIssue {
    code: LocalCheckIssueCode,
    message: String,
}

impl LocalCheckIssue {
    /// Returns the stable failure class.
    #[must_use]
    pub const fn code(&self) -> LocalCheckIssueCode {
        self.code
    }

    /// Returns the actionable, value-free failure description.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Captures and validates one exact local workflow without admission or
/// execution side effects.
pub async fn check_workflow(request: LocalCheckRequest) -> LocalCheckReport {
    if request.workflow.as_ref().is_some_and(|workflow| {
        workflow.is_empty()
            || workflow.len() > MAX_WORKFLOW_SELECTOR_BYTES
            || workflow.chars().any(char::is_control)
    }) {
        return LocalCheckReport::failure(
            None,
            LocalCheckIssueCode::WorkflowNotFound,
            "workflow must be one bounded canonical repository-relative path",
            Vec::new(),
        );
    }
    let snapshot = match capture_snapshot(LocalSnapshotRequest::new(
        request.directory,
        request.limits,
    ))
    .await
    {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return LocalCheckReport::failure(
                None,
                LocalCheckIssueCode::Snapshot,
                error.code().message(),
                Vec::new(),
            );
        }
    };
    let mut source = LocalCheckSource::from_snapshot(&snapshot);
    let Some(location) = snapshot.workflow_location() else {
        return LocalCheckReport::failure(
            Some(source),
            LocalCheckIssueCode::WorkflowNamespaceMissing,
            "add workflows to exactly one of .github/workflows or .ci/workflows",
            Vec::new(),
        );
    };
    let selected = match select_workflow(&snapshot, request.workflow.as_deref()) {
        Ok(selected) => selected,
        Err((code, message)) => {
            return LocalCheckReport::failure(Some(source), code, message, Vec::new());
        }
    };
    source.workflow_path = Some(selected.path().to_owned());
    match validate_snapshot_workflow(&snapshot, location, selected, request.inputs) {
        Ok(checked) => LocalCheckReport {
            schema: LOCAL_CHECK_SCHEMA,
            valid: true,
            source: Some(source),
            required_root_secrets: checked.required_root_secrets,
            workflows: checked.workflows,
            diagnostics: checked.diagnostics,
            issue: None,
        },
        Err(failure) => failure.into_report(source),
    }
}

struct CheckFailure {
    code: LocalCheckIssueCode,
    message: String,
    diagnostics: Vec<LocalCheckDiagnostic>,
}

struct CheckedSnapshotWorkflow {
    required_root_secrets: Vec<String>,
    workflows: Vec<LocalCheckedWorkflow>,
    diagnostics: Vec<LocalCheckDiagnostic>,
}

impl CheckFailure {
    fn new(code: LocalCheckIssueCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            diagnostics: Vec::new(),
        }
    }

    fn with_diagnostics(mut self, diagnostics: Vec<LocalCheckDiagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }

    fn into_report(self, source: LocalCheckSource) -> LocalCheckReport {
        LocalCheckReport::failure(Some(source), self.code, self.message, self.diagnostics)
    }
}

fn validate_snapshot_workflow(
    snapshot: &LocalSnapshot,
    location: RepositoryWorkflowLocation,
    selected: &RepositoryWorkflowDiscoveryOutcome,
    inputs: LocalWorkflowDispatchInputs,
) -> Result<CheckedSnapshotWorkflow, CheckFailure> {
    let repository = snapshot.repository_id().to_string();
    let revision = snapshot.digest().to_string();
    let (root_plan, diagnostics) =
        compile_selected_workflow(snapshot, selected, &repository, &revision, inputs)?;
    let (catalog, required_root_secrets) =
        compile_reusable_catalog(snapshot, location, &repository, &revision, &root_plan).map_err(
            |message| {
                CheckFailure::new(LocalCheckIssueCode::ReusableWorkflow, message)
                    .with_diagnostics(diagnostics.clone())
            },
        )?;
    let workflows =
        collect_checked_workflows(selected.path(), &root_plan, &catalog).map_err(|message| {
            CheckFailure::new(LocalCheckIssueCode::CredentialDiscovery, message)
                .with_diagnostics(diagnostics.clone())
        })?;
    Ok(CheckedSnapshotWorkflow {
        required_root_secrets,
        workflows,
        diagnostics,
    })
}

fn compile_selected_workflow(
    snapshot: &LocalSnapshot,
    selected: &RepositoryWorkflowDiscoveryOutcome,
    repository: &str,
    revision: &str,
    inputs: LocalWorkflowDispatchInputs,
) -> Result<(WorkflowPlan, Vec<LocalCheckDiagnostic>), CheckFailure> {
    let selected_bytes = selected.result().map_err(|error| {
        CheckFailure::new(LocalCheckIssueCode::WorkflowSource, error.to_string())
    })?;
    let selected_text = std::str::from_utf8(selected_bytes).map_err(|_| {
        CheckFailure::new(
            LocalCheckIssueCode::WorkflowSource,
            "selected workflow source is not UTF-8",
        )
    })?;
    let provenance = SourceProvenance::new(
        SourceId::new(selected.path()),
        SourceOrigin::Repository {
            repository: Arc::from(repository),
            revision: Arc::from(revision),
            path: Arc::from(selected.path()),
        },
    );
    let parsed = GithubWorkflowFrontend::default()
        .parse(ParseWorkflowRequest::new(provenance, selected_text));
    let frontend_diagnostics = diagnostics(parsed.diagnostics());
    if !parsed.is_accepted() {
        return Err(CheckFailure::new(
            LocalCheckIssueCode::Frontend,
            "selected workflow was rejected by the GitHub Actions frontend",
        )
        .with_diagnostics(frontend_diagnostics));
    }
    let Some(source_plan) = parsed.plan() else {
        return Err(CheckFailure::new(
            LocalCheckIssueCode::Frontend,
            "accepted frontend report did not contain a source plan",
        )
        .with_diagnostics(frontend_diagnostics));
    };
    let compiled =
        GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::for_local_workflow_dispatch(
            source_plan,
            LocalWorkflowDispatchEvidence::new(
                LocalWorkflowSourceEvidence::new(snapshot.digest()),
                inputs,
            ),
        ));
    let mut all_diagnostics = frontend_diagnostics;
    all_diagnostics.extend(diagnostics(compiled.diagnostics()));
    if compiled.disposition() != CompilationDisposition::Accepted {
        return Err(CheckFailure::new(
            LocalCheckIssueCode::Compilation,
            "selected workflow must accept the explicit local workflow_dispatch invocation",
        )
        .with_diagnostics(all_diagnostics));
    }
    let (plan, _) = compiled.into_parts();
    let Some(root_plan) = plan else {
        return Err(CheckFailure::new(
            LocalCheckIssueCode::Compilation,
            "accepted compilation did not contain a workflow plan",
        )
        .with_diagnostics(all_diagnostics));
    };
    Ok((root_plan, all_diagnostics))
}

fn compile_reusable_catalog(
    snapshot: &LocalSnapshot,
    location: RepositoryWorkflowLocation,
    repository: &str,
    revision: &str,
    root_plan: &WorkflowPlan,
) -> Result<(GithubReusableWorkflowCatalog, Vec<String>), String> {
    let candidate_sources = snapshot.workflows().iter().filter_map(|workflow| {
        workflow.result().ok().map(|bytes| {
            RepositoryWorkflowSource::new(workflow.path(), Bytes::copy_from_slice(bytes))
        })
    });
    let catalog = GithubReusableWorkflowCatalog::compile_reachable(
        GithubReusableWorkflowSourceAuthority::LocalSnapshot {
            workflow_location: location,
            snapshot_digest: snapshot.digest(),
        },
        repository,
        revision,
        root_plan,
        candidate_sources,
    )
    .map_err(|error| error.to_string())?;
    let analysis = catalog
        .analyze_reachable_calls(root_plan)
        .map_err(|error| error.to_string())?;
    let required_root_secrets = analysis.required_root_secret_names().to_vec();
    Ok((catalog, required_root_secrets))
}

fn collect_checked_workflows(
    selected_path: &str,
    root_plan: &WorkflowPlan,
    catalog: &GithubReusableWorkflowCatalog,
) -> Result<Vec<LocalCheckedWorkflow>, String> {
    let mut workflows = Vec::with_capacity(catalog.entries().len() + 1);
    workflows.push(checked_workflow(selected_path, false, root_plan)?);
    for entry in catalog.entries() {
        workflows.push(checked_workflow(entry.path(), true, entry.plan())?);
    }
    workflows.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(workflows)
}

impl LocalCheckReport {
    fn failure(
        source: Option<LocalCheckSource>,
        code: LocalCheckIssueCode,
        message: impl Into<String>,
        diagnostics: Vec<LocalCheckDiagnostic>,
    ) -> Self {
        Self {
            schema: LOCAL_CHECK_SCHEMA,
            valid: false,
            source,
            required_root_secrets: Vec::new(),
            workflows: Vec::new(),
            diagnostics,
            issue: Some(LocalCheckIssue {
                code,
                message: message.into(),
            }),
        }
    }
}

impl LocalCheckSource {
    fn from_snapshot(snapshot: &LocalSnapshot) -> Self {
        Self {
            repository_id: snapshot.repository_id(),
            snapshot_digest: snapshot.digest(),
            head: snapshot.head().to_owned(),
            dirty: snapshot.dirty(),
            workflow_location: match snapshot.workflow_location() {
                Some(RepositoryWorkflowLocation::Automata) => ".ci/workflows",
                Some(RepositoryWorkflowLocation::Github) => ".github/workflows",
                None => "none",
            },
            workflow_path: None,
            entry_count: snapshot.entry_count(),
            expanded_bytes: snapshot.expanded_bytes(),
        }
    }
}

fn select_workflow<'a>(
    snapshot: &'a LocalSnapshot,
    requested: Option<&str>,
) -> Result<&'a RepositoryWorkflowDiscoveryOutcome, (LocalCheckIssueCode, &'static str)> {
    match requested {
        Some(path) => snapshot
            .workflows()
            .iter()
            .find(|workflow| workflow.path() == path)
            .ok_or((
                LocalCheckIssueCode::WorkflowNotFound,
                "workflow is not one exact discovered repository-relative path",
            )),
        None => match snapshot.workflows() {
            [] => Err((
                LocalCheckIssueCode::WorkflowMissing,
                "the explicit workflow namespace contains no direct YAML workflow",
            )),
            [workflow] => Ok(workflow),
            _ => Err((
                LocalCheckIssueCode::WorkflowSelectionRequired,
                "multiple workflows were discovered; supply one canonical repository-relative path",
            )),
        },
    }
}

fn checked_workflow(
    path: &str,
    reusable: bool,
    plan: &WorkflowPlan,
) -> Result<LocalCheckedWorkflow, String> {
    let mut jobs = Vec::with_capacity(plan.jobs().len());
    for job in plan.jobs() {
        let requirements = discover_job_credential_requirements(plan.logical(), job)
            .map_err(|error| error.to_string())?;
        jobs.push(LocalCheckedJob {
            id: job.key().value().to_string(),
            kind: match job.execution() {
                LogicalJobKind::Steps(_) => "steps",
                LogicalJobKind::ReusableWorkflow(_) => "reusable_workflow",
            },
            environment_required: requirements.environment().template_digest().is_some(),
            secrets: requirements.secret_names().to_vec(),
            variables: requirements.variable_names().to_vec(),
        });
    }
    Ok(LocalCheckedWorkflow {
        path: path.to_owned(),
        reusable,
        jobs,
    })
}

fn diagnostics(values: &[Diagnostic]) -> Vec<LocalCheckDiagnostic> {
    values
        .iter()
        .map(|diagnostic| LocalCheckDiagnostic {
            kind: diagnostic.kind().as_str(),
            severity: diagnostic.severity().as_str(),
            code: diagnostic.code().to_owned(),
            message: diagnostic.message().to_owned(),
            source: diagnostic.primary_span().source_id().as_str().to_owned(),
            line: diagnostic.primary_span().start().line(),
            column: diagnostic.primary_span().start().column(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path, process::Command};

    use automata_ci_workflow_github::{
        LocalWorkflowDispatchInputs, RepositoryWorkflowDiscoveryLimits,
    };
    use uuid::Uuid;

    use super::{LocalCheckIssueCode, LocalCheckRequest, check_workflow};

    #[tokio::test]
    async fn dirty_snapshot_compiles_reusable_workflows_and_discovers_names_without_values() {
        let fixture = Fixture::new();
        fixture.write(
            ".github/workflows/root.yml",
            r"on:
  workflow_dispatch:
    inputs:
      deploy:
        type: boolean
        required: true
jobs:
  invoke:
    uses: ./.github/workflows/reusable.yml
    secrets:
      token: ${{ secrets.root_token }}
",
        );
        fixture.write(
            ".github/workflows/reusable.yml",
            r"on:
  workflow_call:
    secrets:
      token:
        required: true
jobs:
  test:
    runs-on: linux
    steps:
      - run: echo '${{ vars.region }}' '${{ secrets.token }}'
",
        );
        fixture.commit_all();
        fixture.write("dirty.txt", "live bytes\n");
        let inputs = LocalWorkflowDispatchInputs::try_new([("deploy", "true")]).unwrap();

        let first = check_workflow(LocalCheckRequest::new(
            fixture.path(),
            Some(".github/workflows/root.yml".to_owned()),
            inputs.clone(),
        ))
        .await;
        let repeated = check_workflow(LocalCheckRequest::new(
            fixture.path(),
            Some(".github/workflows/root.yml".to_owned()),
            inputs,
        ))
        .await;

        assert!(first.valid(), "{:#?}", first.issue());
        assert!(first.source().unwrap().dirty());
        assert_eq!(
            first.source().unwrap().snapshot_digest(),
            repeated.source().unwrap().snapshot_digest()
        );
        assert_eq!(first.workflows().len(), 2);
        assert_eq!(first.required_root_secrets(), &["ROOT_TOKEN"]);
        let root = first
            .workflows()
            .iter()
            .find(|workflow| workflow.path().ends_with("root.yml"))
            .unwrap();
        assert_eq!(root.jobs()[0].secrets(), &["ROOT_TOKEN"]);
        let reusable = first
            .workflows()
            .iter()
            .find(|workflow| workflow.path().ends_with("reusable.yml"))
            .unwrap();
        assert_eq!(reusable.jobs()[0].secrets(), &["TOKEN"]);
        assert_eq!(reusable.jobs()[0].variables(), &["REGION"]);
        let json = serde_json::to_string(&first).unwrap();
        assert!(!json.contains("live bytes"));
        assert!(!json.contains(fixture.path().to_string_lossy().as_ref()));
    }

    #[tokio::test]
    async fn selection_and_event_fail_closed() {
        let fixture = Fixture::new();
        fixture.write(
            ".ci/workflows/a.yml",
            "on: push\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: true\n",
        );
        fixture.write(
            ".ci/workflows/b.yml",
            "on: workflow_dispatch\njobs:\n  b:\n    runs-on: linux\n    steps:\n      - run: true\n",
        );
        fixture.commit_all();
        let empty = LocalWorkflowDispatchInputs::try_new(Vec::<(String, String)>::new()).unwrap();

        let ambiguous =
            check_workflow(LocalCheckRequest::new(fixture.path(), None, empty.clone())).await;
        assert_eq!(
            ambiguous.issue().unwrap().code(),
            LocalCheckIssueCode::WorkflowSelectionRequired
        );
        let push = check_workflow(LocalCheckRequest::new(
            fixture.path(),
            Some(".ci/workflows/a.yml".to_owned()),
            empty,
        ))
        .await;
        assert_eq!(
            push.issue().unwrap().code(),
            LocalCheckIssueCode::Compilation
        );
    }

    #[tokio::test]
    async fn reusable_call_contracts_and_cycles_fail_before_a_valid_report() {
        let missing_secret = Fixture::new();
        missing_secret.write(
            ".github/workflows/root.yml",
            "on: workflow_dispatch\njobs:\n  call:\n    uses: ./.github/workflows/callee.yml\n",
        );
        missing_secret.write(
            ".github/workflows/callee.yml",
            "on:\n  workflow_call:\n    secrets:\n      token:\n        required: true\njobs:\n  check:\n    runs-on: linux\n    steps:\n      - run: true\n",
        );
        missing_secret.commit_all();
        let empty = LocalWorkflowDispatchInputs::try_new(Vec::<(String, String)>::new()).unwrap();
        let report = check_workflow(LocalCheckRequest::new(
            missing_secret.path(),
            Some(".github/workflows/root.yml".to_owned()),
            empty.clone(),
        ))
        .await;
        assert_eq!(
            report.issue().unwrap().code(),
            LocalCheckIssueCode::ReusableWorkflow
        );
        assert!(report.issue().unwrap().message().contains("required"));

        let cycle = Fixture::new();
        cycle.write(
            ".ci/workflows/root.yml",
            "on: workflow_dispatch\njobs:\n  call:\n    uses: ./.ci/workflows/a.yml\n",
        );
        cycle.write(
            ".ci/workflows/a.yml",
            "on: workflow_call\njobs:\n  call:\n    uses: ./.ci/workflows/b.yml\n",
        );
        cycle.write(
            ".ci/workflows/b.yml",
            "on: workflow_call\njobs:\n  call:\n    uses: ./.ci/workflows/a.yml\n",
        );
        cycle.commit_all();
        let report = check_workflow(LocalCheckRequest::new(
            cycle.path(),
            Some(".ci/workflows/root.yml".to_owned()),
            empty,
        ))
        .await;
        assert_eq!(
            report.issue().unwrap().code(),
            LocalCheckIssueCode::ReusableWorkflow
        );
        assert!(report.issue().unwrap().message().contains("cycle"));
    }

    #[tokio::test]
    async fn snapshot_limits_remain_part_of_check_capture() {
        let fixture = Fixture::new();
        fixture.write(
            ".ci/workflows/check.yml",
            "on: workflow_dispatch\njobs:\n  check:\n    runs-on: linux\n    steps:\n      - run: true\n",
        );
        fixture.commit_all();
        let limits = RepositoryWorkflowDiscoveryLimits::new(1, 1, 1, 1, 1, 1, 1).unwrap();
        let report = check_workflow(
            LocalCheckRequest::new(
                fixture.path(),
                None,
                LocalWorkflowDispatchInputs::try_new(Vec::<(String, String)>::new()).unwrap(),
            )
            .with_limits(limits),
        )
        .await;
        assert_eq!(
            report.issue().unwrap().code(),
            LocalCheckIssueCode::Snapshot
        );
    }

    struct Fixture {
        root: std::path::PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .join(format!("automata-local-check-{}", Uuid::new_v4().simple()));
            fs::create_dir(&root).unwrap();
            let fixture = Self { root };
            fixture.git(&["init", "--quiet"]);
            fixture.git(&["config", "user.name", "Automata Test"]);
            fixture.git(&["config", "user.email", "automata@example.invalid"]);
            fixture
        }

        fn path(&self) -> &Path {
            &self.root
        }

        fn write(&self, path: &str, value: &str) {
            let path = self.root.join(path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, value).unwrap();
        }

        fn commit_all(&self) {
            self.git(&["add", "--all"]);
            self.git(&["commit", "--quiet", "--message", "fixture"]);
        }

        fn git(&self, arguments: &[&str]) {
            assert!(
                Command::new("git")
                    .arg("-C")
                    .arg(&self.root)
                    .args(arguments)
                    .status()
                    .unwrap()
                    .success()
            );
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
