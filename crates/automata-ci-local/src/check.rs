use std::{fmt, path::PathBuf};

use automata_ci_core::Sha256Digest;
use automata_ci_workflow_github::{
    Diagnostic, GithubWorkflowDispatchInputs, RepositoryWorkflowDiscoveryLimits,
};
use automata_ci_workflow_service::{
    BuiltInCredentialRequirement, LocalGithubArchiveAnalysis,
    LocalGithubArchiveAnalysisFailureKind, ReusableWorkflowLimits, analyze_local_github_archive,
};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::{
    snapshot::{LocalSnapshot, LocalSnapshotErrorCode, LocalSnapshotRequest, capture_snapshot},
    snapshot_limits::local_snapshot_limits,
};

const LOCAL_CHECK_SCHEMA: u32 = 1;

/// Read-only request to validate one workflow from one exact local snapshot.
#[derive(Clone)]
pub struct LocalCheckRequest {
    directory: PathBuf,
    workflow: Option<String>,
    inputs: GithubWorkflowDispatchInputs,
    limits: RepositoryWorkflowDiscoveryLimits,
    reusable_limits: ReusableWorkflowLimits,
}

impl fmt::Debug for LocalCheckRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalCheckRequest")
            .field("workflow", &self.workflow)
            .field("inputs", &self.inputs)
            .field("limits", &self.limits)
            .field("reusable_limits", &self.reusable_limits)
            .finish_non_exhaustive()
    }
}

impl LocalCheckRequest {
    /// Creates a bounded source-only local validation request.
    #[must_use]
    pub fn new(
        directory: impl Into<PathBuf>,
        workflow: Option<String>,
        inputs: GithubWorkflowDispatchInputs,
    ) -> Self {
        Self {
            directory: directory.into(),
            workflow,
            inputs,
            limits: local_snapshot_limits(),
            reusable_limits: ReusableWorkflowLimits::default(),
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
    required_built_in_credentials: Vec<BuiltInCredentialRequirement>,
    workflows: Vec<LocalCheckedWorkflow>,
    diagnostics: Vec<LocalCheckDiagnostic>,
    issue: Option<LocalCheckIssue>,
}

impl LocalCheckReport {
    /// Returns whether capture, exact selection, compilation, reusable-call
    /// validation, and credential discovery all succeeded.
    #[must_use]
    pub const fn valid(&self) -> bool {
        self.valid
    }

    /// Returns value-free snapshot evidence when capture succeeded.
    #[must_use]
    pub const fn source(&self) -> Option<&LocalCheckSource> {
        self.source.as_ref()
    }

    /// Returns canonical external secret names required at the root boundary.
    #[must_use]
    pub fn required_root_secrets(&self) -> &[String] {
        &self.required_root_secrets
    }

    /// Returns closed provider-built-in credentials required by reachable jobs.
    #[must_use]
    pub fn required_built_in_credentials(&self) -> &[BuiltInCredentialRequirement] {
        &self.required_built_in_credentials
    }

    /// Returns checked root and reachable reusable workflows in path order.
    #[must_use]
    pub fn workflows(&self) -> &[LocalCheckedWorkflow] {
        &self.workflows
    }

    /// Returns value-free frontend and compiler diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[LocalCheckDiagnostic] {
        &self.diagnostics
    }

    /// Returns the stable failure, when validation did not complete.
    #[must_use]
    pub const fn issue(&self) -> Option<&LocalCheckIssue> {
        self.issue.as_ref()
    }

    fn success(source: LocalCheckSource, analysis: &LocalGithubArchiveAnalysis) -> Self {
        Self {
            schema: LOCAL_CHECK_SCHEMA,
            valid: true,
            source: Some(source),
            required_root_secrets: analysis.required_root_secrets().to_vec(),
            required_built_in_credentials: analysis.required_built_in_credentials().to_vec(),
            workflows: analysis
                .workflows()
                .iter()
                .map(LocalCheckedWorkflow::from_analysis)
                .collect(),
            diagnostics: diagnostics(analysis.diagnostics()),
            issue: None,
        }
    }

    fn failure(
        source: Option<LocalCheckSource>,
        code: LocalCheckIssueCode,
        diagnostics: Vec<LocalCheckDiagnostic>,
    ) -> Self {
        Self {
            schema: LOCAL_CHECK_SCHEMA,
            valid: false,
            source,
            required_root_secrets: Vec::new(),
            required_built_in_credentials: Vec::new(),
            workflows: Vec::new(),
            diagnostics,
            issue: Some(LocalCheckIssue {
                code,
                message: code.message(),
            }),
        }
    }
}

/// Value-free source evidence retained by a local check.
#[derive(Clone, Debug, Serialize)]
pub struct LocalCheckSource {
    snapshot_digest: Sha256Digest,
    head: String,
    dirty: bool,
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

    fn from_snapshot(snapshot: &LocalSnapshot) -> Self {
        Self {
            snapshot_digest: snapshot.digest(),
            head: snapshot.head().to_owned(),
            dirty: snapshot.dirty(),
            workflow_path: None,
            entry_count: snapshot.entry_count(),
            expanded_bytes: snapshot.expanded_bytes(),
        }
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

    /// Returns jobs in source order.
    #[must_use]
    pub fn jobs(&self) -> &[LocalCheckedJob] {
        &self.jobs
    }

    /// Returns whether this source was loaded through a reachable reusable call.
    #[must_use]
    pub const fn reusable(&self) -> bool {
        self.reusable
    }

    fn from_analysis(value: &automata_ci_workflow_service::LocalGithubAnalyzedWorkflow) -> Self {
        Self {
            path: value.path().to_owned(),
            reusable: value.reusable(),
            jobs: value
                .jobs()
                .iter()
                .map(LocalCheckedJob::from_analysis)
                .collect(),
        }
    }
}

/// Static credential names and execution kind discovered for one logical job.
#[derive(Clone, Debug, Serialize)]
pub struct LocalCheckedJob {
    id: String,
    kind: &'static str,
    secrets: Vec<String>,
    variables: Vec<String>,
    built_in_credentials: Vec<BuiltInCredentialRequirement>,
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

    /// Returns sorted canonical external secret names without values.
    #[must_use]
    pub fn secrets(&self) -> &[String] {
        &self.secrets
    }

    /// Returns sorted canonical variable names without values.
    #[must_use]
    pub fn variables(&self) -> &[String] {
        &self.variables
    }

    /// Returns closed provider-built-in requirements in stable order.
    #[must_use]
    pub fn built_in_credentials(&self) -> &[BuiltInCredentialRequirement] {
        &self.built_in_credentials
    }

    fn from_analysis(value: &automata_ci_workflow_service::LocalGithubAnalyzedJob) -> Self {
        Self {
            id: value.key().to_owned(),
            kind: if value.reusable() {
                "reusable_workflow"
            } else {
                "steps"
            },
            secrets: value.secrets().to_vec(),
            variables: value.variables().to_vec(),
            built_in_credentials: value.built_in_credentials().to_vec(),
        }
    }
}

/// Sanitized source-bound diagnostic containing no source or input value.
#[derive(Clone, Debug, Serialize)]
pub struct LocalCheckDiagnostic {
    kind: &'static str,
    severity: &'static str,
    code: String,
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

    /// Returns the canonical source path for this diagnostic.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the one-based source line.
    #[must_use]
    pub const fn line(&self) -> usize {
        self.line
    }

    /// Returns the one-based source column.
    #[must_use]
    pub const fn column(&self) -> usize {
        self.column
    }
}

/// Stable failure class for a local workflow check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalCheckIssueCode {
    /// Exact local snapshot capture failed.
    Snapshot,
    /// Cooperative shutdown interrupted local analysis.
    Cancelled,
    /// The sealed archive violated its bounded policy.
    Archive,
    /// No direct `.github/workflows` YAML workflow was discovered.
    WorkflowMissing,
    /// More than one workflow requires an explicit canonical selector.
    WorkflowSelectionRequired,
    /// The supplied workflow selector is not one exact discovered path.
    WorkflowNotFound,
    /// A selected workflow source is empty, oversized, or not UTF-8.
    WorkflowSource,
    /// The GitHub Actions frontend rejected a selected source.
    Frontend,
    /// The root does not accept the explicit local `workflow_dispatch` selection.
    Compilation,
    /// A same-snapshot reusable workflow or call contract was rejected.
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
            Self::Cancelled => "cancelled",
            Self::Archive => "archive",
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

    const fn message(self) -> &'static str {
        match self {
            Self::Snapshot => "the exact local Git worktree snapshot could not be sealed",
            Self::Cancelled => "local workflow analysis was cancelled",
            Self::Archive => "the sealed worktree archive violates local analysis policy",
            Self::WorkflowMissing => "add a direct YAML workflow under .github/workflows",
            Self::WorkflowSelectionRequired => {
                "multiple workflows were discovered; supply one exact canonical path"
            }
            Self::WorkflowNotFound => {
                "workflow must be one exact discovered .github/workflows path"
            }
            Self::WorkflowSource => "a selected workflow source is invalid",
            Self::Frontend => "a selected workflow was rejected by the GitHub Actions frontend",
            Self::Compilation => {
                "the root workflow must accept the explicit local workflow_dispatch selection"
            }
            Self::ReusableWorkflow => {
                "a reachable same-snapshot reusable workflow or call contract is invalid"
            }
            Self::CredentialDiscovery => {
                "a workflow contains a dynamic or invalid credential reference"
            }
        }
    }
}

/// One sanitized local-check failure.
#[derive(Clone, Debug, Serialize)]
pub struct LocalCheckIssue {
    code: LocalCheckIssueCode,
    message: &'static str,
}

impl LocalCheckIssue {
    /// Returns the stable failure class.
    #[must_use]
    pub const fn code(&self) -> LocalCheckIssueCode {
        self.code
    }

    /// Returns the actionable value-free failure description.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

/// Captures and validates one exact local workflow without admission,
/// execution, Docker, network, or provider side effects.
pub async fn check_workflow(
    request: LocalCheckRequest,
    cancellation: CancellationToken,
) -> LocalCheckReport {
    let snapshot = match capture_snapshot(
        LocalSnapshotRequest::new(request.directory, request.limits),
        &cancellation,
    )
    .await
    {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let code = if error.code() == LocalSnapshotErrorCode::Cancelled {
                LocalCheckIssueCode::Cancelled
            } else {
                LocalCheckIssueCode::Snapshot
            };
            return LocalCheckReport::failure(None, code, Vec::new());
        }
    };
    let mut source = LocalCheckSource::from_snapshot(&snapshot);
    let expected_digest = snapshot.digest();
    let archive = snapshot.into_archive();
    let selector = request.workflow;
    let inputs = request.inputs;
    let archive_limits = request.limits;
    let reusable_limits = request.reusable_limits;
    let worker_cancellation = cancellation.clone();
    let analysis = tokio::task::spawn_blocking(move || {
        analyze_local_github_archive(
            &archive,
            selector.as_deref(),
            inputs,
            archive_limits,
            reusable_limits,
            &|| worker_cancellation.is_cancelled(),
        )
    })
    .await;
    let analysis = match analysis {
        Ok(Ok(analysis)) => analysis,
        Ok(Err(failure)) => {
            return LocalCheckReport::failure(
                Some(source),
                issue_code(failure.kind()),
                diagnostics(failure.diagnostics()),
            );
        }
        Err(_) => {
            return LocalCheckReport::failure(
                Some(source),
                if cancellation.is_cancelled() {
                    LocalCheckIssueCode::Cancelled
                } else {
                    LocalCheckIssueCode::Archive
                },
                Vec::new(),
            );
        }
    };
    if analysis.snapshot_digest() != expected_digest {
        return LocalCheckReport::failure(
            Some(source),
            LocalCheckIssueCode::Archive,
            diagnostics(analysis.diagnostics()),
        );
    }
    source.workflow_path = Some(analysis.selected_path().to_owned());
    LocalCheckReport::success(source, &analysis)
}

const fn issue_code(kind: LocalGithubArchiveAnalysisFailureKind) -> LocalCheckIssueCode {
    match kind {
        LocalGithubArchiveAnalysisFailureKind::Cancelled => LocalCheckIssueCode::Cancelled,
        LocalGithubArchiveAnalysisFailureKind::Archive => LocalCheckIssueCode::Archive,
        LocalGithubArchiveAnalysisFailureKind::WorkflowMissing => {
            LocalCheckIssueCode::WorkflowMissing
        }
        LocalGithubArchiveAnalysisFailureKind::WorkflowSelectionRequired => {
            LocalCheckIssueCode::WorkflowSelectionRequired
        }
        LocalGithubArchiveAnalysisFailureKind::WorkflowNotFound => {
            LocalCheckIssueCode::WorkflowNotFound
        }
        LocalGithubArchiveAnalysisFailureKind::WorkflowSource => {
            LocalCheckIssueCode::WorkflowSource
        }
        LocalGithubArchiveAnalysisFailureKind::Frontend => LocalCheckIssueCode::Frontend,
        LocalGithubArchiveAnalysisFailureKind::Compilation => LocalCheckIssueCode::Compilation,
        LocalGithubArchiveAnalysisFailureKind::ReusableWorkflow => {
            LocalCheckIssueCode::ReusableWorkflow
        }
        LocalGithubArchiveAnalysisFailureKind::CredentialDiscovery => {
            LocalCheckIssueCode::CredentialDiscovery
        }
    }
}

fn diagnostics(values: &[Diagnostic]) -> Vec<LocalCheckDiagnostic> {
    values
        .iter()
        .map(|diagnostic| LocalCheckDiagnostic {
            kind: diagnostic.kind().as_str(),
            severity: diagnostic.severity().as_str(),
            code: diagnostic.code().to_owned(),
            source: diagnostic.primary_span().source_id().as_str().to_owned(),
            line: diagnostic.primary_span().start().line(),
            column: diagnostic.primary_span().start().column(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        process::Command,
    };

    use automata_ci_workflow_github::{
        GithubWorkflowDispatchInputs, RepositoryWorkflowDiscoveryLimits,
    };
    use automata_ci_workflow_service::BuiltInCredentialRequirement;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use super::{LocalCheckIssueCode, LocalCheckRequest, check_workflow};

    fn empty_inputs() -> GithubWorkflowDispatchInputs {
        GithubWorkflowDispatchInputs::try_new(Vec::<(String, String)>::new()).unwrap()
    }

    #[test]
    fn request_debug_omits_directory_and_input_values() {
        let private_directory = "/private/local-check-directory";
        let private_value = "private-local-check-input";
        let request = LocalCheckRequest::new(
            private_directory,
            Some(".github/workflows/check.yml".to_owned()),
            GithubWorkflowDispatchInputs::try_new([("target", private_value)]).unwrap(),
        );
        let debug = format!("{request:?}");
        assert!(!debug.contains(private_directory));
        assert!(!debug.contains(private_value));
    }

    #[tokio::test]
    async fn dirty_snapshot_validates_reusable_contracts_without_retaining_values() {
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
        fixture.write("dirty.txt", "unreportable-source-marker\n");
        let inputs = GithubWorkflowDispatchInputs::try_new([("deploy", true)]).unwrap();

        let first = check_workflow(
            LocalCheckRequest::new(
                fixture.path(),
                Some(".github/workflows/root.yml".to_owned()),
                inputs.clone(),
            ),
            CancellationToken::new(),
        )
        .await;
        let repeated = check_workflow(
            LocalCheckRequest::new(
                fixture.path(),
                Some(".github/workflows/root.yml".to_owned()),
                inputs,
            ),
            CancellationToken::new(),
        )
        .await;

        assert!(first.valid(), "{:#?}", first.issue());
        assert!(first.source().unwrap().dirty());
        assert_eq!(
            first.source().unwrap().snapshot_digest(),
            repeated.source().unwrap().snapshot_digest()
        );
        assert_eq!(first.required_root_secrets(), &["ROOT_TOKEN"]);
        assert_eq!(first.workflows().len(), 2);
        let reusable = first
            .workflows()
            .iter()
            .find(|workflow| workflow.reusable())
            .unwrap();
        assert_eq!(reusable.jobs()[0].secrets(), &["TOKEN"]);
        assert_eq!(reusable.jobs()[0].variables(), &["REGION"]);
        let json = serde_json::to_string(&first).unwrap();
        assert!(!json.contains("unreportable-source-marker"));
        assert!(!json.contains(fixture.path().to_string_lossy().as_ref()));
        assert!(!json.contains("repository_id"));
        assert!(!json.contains("environment_required"));
    }

    #[tokio::test]
    async fn exact_github_selector_and_workflow_dispatch_are_mandatory() {
        let fixture = Fixture::new();
        fixture.write(
            ".github/workflows/a.yml",
            "on: push\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: true\n",
        );
        fixture.write(
            ".github/workflows/b.yml",
            "on: workflow_dispatch\njobs:\n  b:\n    runs-on: linux\n    steps:\n      - run: true\n",
        );
        fixture.commit_all();

        let ambiguous = check_workflow(
            LocalCheckRequest::new(fixture.path(), None, empty_inputs()),
            CancellationToken::new(),
        )
        .await;
        assert_eq!(
            ambiguous.issue().unwrap().code(),
            LocalCheckIssueCode::WorkflowSelectionRequired
        );
        let push = check_workflow(
            LocalCheckRequest::new(
                fixture.path(),
                Some(".github/workflows/a.yml".to_owned()),
                empty_inputs(),
            ),
            CancellationToken::new(),
        )
        .await;
        assert_eq!(
            push.issue().unwrap().code(),
            LocalCheckIssueCode::Compilation
        );
        let shorthand = check_workflow(
            LocalCheckRequest::new(fixture.path(), Some("b.yml".to_owned()), empty_inputs()),
            CancellationToken::new(),
        )
        .await;
        assert_eq!(
            shorthand.issue().unwrap().code(),
            LocalCheckIssueCode::WorkflowNotFound
        );

        let automata_namespace = Fixture::new();
        automata_namespace.write(
            ".ci/workflows/not-local-github.yml",
            "on: workflow_dispatch\njobs:\n  ignored:\n    runs-on: linux\n    steps:\n      - run: true\n",
        );
        automata_namespace.commit_all();
        let rejected = check_workflow(
            LocalCheckRequest::new(automata_namespace.path(), None, empty_inputs()),
            CancellationToken::new(),
        )
        .await;
        assert_eq!(
            rejected.issue().unwrap().code(),
            LocalCheckIssueCode::Archive
        );
    }

    #[tokio::test]
    async fn reusable_contract_cycles_remote_calls_and_missing_secrets_fail() {
        let missing = Fixture::new();
        missing.write(
            ".github/workflows/root.yml",
            "on: workflow_dispatch\njobs:\n  call:\n    uses: ./.github/workflows/callee.yml\n",
        );
        missing.write(
            ".github/workflows/callee.yml",
            "on:\n  workflow_call:\n    secrets:\n      token:\n        required: true\njobs:\n  check:\n    runs-on: linux\n    steps:\n      - run: true\n",
        );
        missing.commit_all();
        let report = check_workflow(
            LocalCheckRequest::new(
                missing.path(),
                Some(".github/workflows/root.yml".to_owned()),
                empty_inputs(),
            ),
            CancellationToken::new(),
        )
        .await;
        assert_eq!(
            report.issue().unwrap().code(),
            LocalCheckIssueCode::ReusableWorkflow
        );

        let cycle = Fixture::new();
        cycle.write(
            ".github/workflows/root.yml",
            "on: workflow_dispatch\njobs:\n  call:\n    uses: ./.github/workflows/a.yml\n",
        );
        cycle.write(
            ".github/workflows/a.yml",
            "on: workflow_call\njobs:\n  call:\n    uses: ./.github/workflows/b.yml\n",
        );
        cycle.write(
            ".github/workflows/b.yml",
            "on: workflow_call\njobs:\n  call:\n    uses: ./.github/workflows/a.yml\n",
        );
        cycle.commit_all();
        let report = check_workflow(
            LocalCheckRequest::new(
                cycle.path(),
                Some(".github/workflows/root.yml".to_owned()),
                empty_inputs(),
            ),
            CancellationToken::new(),
        )
        .await;
        assert_eq!(
            report.issue().unwrap().code(),
            LocalCheckIssueCode::ReusableWorkflow
        );

        let remote = Fixture::new();
        remote.write(
            ".github/workflows/root.yml",
            "on: workflow_dispatch\njobs:\n  call:\n    uses: owner/repository/.github/workflows/a.yml@main\n",
        );
        remote.commit_all();
        let report = check_workflow(
            LocalCheckRequest::new(
                remote.path(),
                Some(".github/workflows/root.yml".to_owned()),
                empty_inputs(),
            ),
            CancellationToken::new(),
        )
        .await;
        assert_eq!(
            report.issue().unwrap().code(),
            LocalCheckIssueCode::ReusableWorkflow
        );
    }

    #[tokio::test]
    async fn github_token_is_builtin_and_never_promptable() {
        let fixture = Fixture::new();
        fixture.write(
            ".github/workflows/root.yml",
            r"on: workflow_dispatch
jobs:
  direct:
    runs-on: linux
    steps:
      - run: echo '${{ github.token }}' '${{ secrets.GITHUB_TOKEN }}'
  call:
    uses: ./.github/workflows/callee.yml
    secrets:
      token: ${{ secrets.GITHUB_TOKEN }}
",
        );
        fixture.write(
            ".github/workflows/callee.yml",
            r"on:
  workflow_call:
    secrets:
      token:
        required: true
jobs:
  use:
    runs-on: linux
    steps:
      - run: echo '${{ secrets.token }}'
",
        );
        fixture.commit_all();
        let report = check_workflow(
            LocalCheckRequest::new(
                fixture.path(),
                Some(".github/workflows/root.yml".to_owned()),
                empty_inputs(),
            ),
            CancellationToken::new(),
        )
        .await;
        assert!(report.valid(), "{:#?}", report.issue());
        assert!(report.required_root_secrets().is_empty());
        assert_eq!(
            report.required_built_in_credentials(),
            &[BuiltInCredentialRequirement::GithubToken]
        );
    }

    #[tokio::test]
    async fn cancellation_and_small_capture_bounds_fail_closed() {
        let fixture = Fixture::new();
        fixture.write(
            ".github/workflows/check.yml",
            "on: workflow_dispatch\njobs:\n  check:\n    runs-on: linux\n    steps:\n      - run: true\n",
        );
        fixture.commit_all();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = check_workflow(
            LocalCheckRequest::new(fixture.path(), None, empty_inputs()),
            cancellation,
        )
        .await;
        assert_eq!(
            cancelled.issue().unwrap().code(),
            LocalCheckIssueCode::Cancelled
        );

        let limits = RepositoryWorkflowDiscoveryLimits::new(1, 1, 1, 1, 1, 1, 1).unwrap();
        let bounded = check_workflow(
            LocalCheckRequest::new(fixture.path(), None, empty_inputs()).with_limits(limits),
            CancellationToken::new(),
        )
        .await;
        assert_eq!(
            bounded.issue().unwrap().code(),
            LocalCheckIssueCode::Snapshot
        );
    }

    struct Fixture {
        root: PathBuf,
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
