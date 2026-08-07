//! Early-bound evaluation from a neutral workflow plan to one executable job.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use automata_core::{
    ActionReference, Architecture, ContainerFeature, DeferredBoolean, EnvironmentProfile,
    ExpressionProgram, ExpressionSegment, JobContentReference, JobExecutionContext, JobId, JobIr,
    JobIrEnvelope, JobSource, Located, OperatingSystem, PlanExpression, PlanSourceOrigin,
    PlanSourceSpan, PlanValue, PlannedJob, PlannedStep, PlannedStepKind, RunId, RunnerGroup,
    RunnerLabel, RunnerRequirements, SemanticStep, ShellSpec, StepId, StepIr, ValueMapPlan,
    ValueSource, WorkflowId, WorkflowJobKey, WorkflowPlan,
};

use crate::{
    Diagnostic, DiagnosticKind, DiagnosticSeverity, GithubConditionCompiler, GithubConditionPhase,
    GithubExpressionError, GithubExpressionErrorKind, SourceId, SourceLocation, SourceSpan,
};

/// GitHub's default shell command on Linux when `shell` is omitted.
///
/// The fallback to `sh -e {0}` is runner selection metadata in GitHub. An
/// attested hosted Linux profile guarantees Bash; other targets retain
/// [`ShellSpec::Default`] for the selected runner to resolve.
pub const DEFAULT_GITHUB_LINUX_SHELL_TEMPLATE: &str = "bash -e {0}";

/// Native path grammar exposed to a target job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubTargetPathStyle {
    /// POSIX-style absolute roots and `/` separators.
    Unix,
    /// Drive-rooted absolute paths and `\` separators.
    Windows,
}

/// Validated absolute workspace path in the target job's native grammar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubWorkspacePath {
    style: GithubTargetPathStyle,
    value: String,
}

impl GithubWorkspacePath {
    /// Validates an absolute, normalized workspace path without consulting the
    /// control-plane host filesystem.
    ///
    /// # Errors
    ///
    /// Returns [`JobEvaluationInputError::InvalidWorkspace`] for a noncanonical
    /// or relative target path.
    pub fn new(
        style: GithubTargetPathStyle,
        value: impl Into<String>,
    ) -> Result<Self, JobEvaluationInputError> {
        let value = value.into();
        validate_workspace_value(style, &value)?;
        Ok(Self { style, value })
    }

    #[must_use]
    pub const fn style(&self) -> GithubTargetPathStyle {
        self.style
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

/// Validated, server-owned values exposed through the early `github` context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubJobContext {
    workflow_id: WorkflowId,
    run_id: RunId,
    job_id: JobId,
    repository: String,
    commit_sha: String,
    git_ref: String,
    workflow_name: String,
    workspace: GithubWorkspacePath,
    actor: Option<String>,
    run_number: Option<u64>,
    run_attempt: Option<u32>,
    event: JobContentReference,
}

/// Named construction path for [`GithubJobContext`].
#[derive(Clone, Debug)]
pub struct GithubJobContextBuilder {
    workflow_id: WorkflowId,
    run_id: RunId,
    job_id: JobId,
    repository: Option<String>,
    commit_sha: Option<String>,
    git_ref: Option<String>,
    workflow_name: Option<String>,
    workspace: Option<GithubWorkspacePath>,
    actor: Option<String>,
    run_number: Option<u64>,
    run_attempt: Option<u32>,
    event: Option<JobContentReference>,
}

impl GithubJobContext {
    /// Starts a builder with the strongly typed run identities.
    #[must_use]
    pub const fn builder(
        workflow_id: WorkflowId,
        run_id: RunId,
        job_id: JobId,
    ) -> GithubJobContextBuilder {
        GithubJobContextBuilder {
            workflow_id,
            run_id,
            job_id,
            repository: None,
            commit_sha: None,
            git_ref: None,
            workflow_name: None,
            workspace: None,
            actor: None,
            run_number: None,
            run_attempt: None,
            event: None,
        }
    }

    #[must_use]
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    #[must_use]
    pub fn commit_sha(&self) -> &str {
        &self.commit_sha
    }

    #[must_use]
    pub fn git_ref(&self) -> &str {
        &self.git_ref
    }

    #[must_use]
    pub fn workflow_name(&self) -> &str {
        &self.workflow_name
    }

    #[must_use]
    pub const fn workspace(&self) -> &GithubWorkspacePath {
        &self.workspace
    }

    #[must_use]
    pub fn actor(&self) -> Option<&str> {
        self.actor.as_deref()
    }

    #[must_use]
    pub const fn run_number(&self) -> Option<u64> {
        self.run_number
    }

    #[must_use]
    pub const fn run_attempt(&self) -> Option<u32> {
        self.run_attempt
    }

    #[must_use]
    pub const fn event(&self) -> &JobContentReference {
        &self.event
    }
}

impl GithubJobContextBuilder {
    #[must_use]
    pub fn repository(mut self, repository: impl Into<String>) -> Self {
        self.repository = Some(repository.into());
        self
    }

    #[must_use]
    pub fn commit_sha(mut self, commit_sha: impl Into<String>) -> Self {
        self.commit_sha = Some(commit_sha.into());
        self
    }

    #[must_use]
    pub fn git_ref(mut self, git_ref: impl Into<String>) -> Self {
        self.git_ref = Some(git_ref.into());
        self
    }

    #[must_use]
    pub fn workflow_name(mut self, workflow_name: impl Into<String>) -> Self {
        self.workflow_name = Some(workflow_name.into());
        self
    }

    #[must_use]
    pub fn workspace(mut self, workspace: GithubWorkspacePath) -> Self {
        self.workspace = Some(workspace);
        self
    }

    #[must_use]
    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    #[must_use]
    pub const fn run_number(mut self, run_number: u64) -> Self {
        self.run_number = Some(run_number);
        self
    }

    #[must_use]
    pub const fn run_attempt(mut self, run_attempt: u32) -> Self {
        self.run_attempt = Some(run_attempt);
        self
    }

    #[must_use]
    pub fn event(mut self, event: JobContentReference) -> Self {
        self.event = Some(event);
        self
    }

    /// Validates and freezes all early GitHub context values.
    ///
    /// # Errors
    ///
    /// Returns [`JobEvaluationInputError`] for missing or non-canonical input.
    pub fn build(self) -> Result<GithubJobContext, JobEvaluationInputError> {
        let repository = required(self.repository, "repository")?;
        let commit_sha = required(self.commit_sha, "commit SHA")?;
        let git_ref = required(self.git_ref, "Git ref")?;
        let workflow_name = required(self.workflow_name, "workflow name")?;
        let workspace = required(self.workspace, "sandbox workspace")?;
        let event = required(self.event, "event content reference")?;
        validate_repository(&repository)?;
        validate_commit_sha(&commit_sha)?;
        validate_git_ref(&git_ref)?;
        validate_workflow_name(&workflow_name)?;
        Ok(GithubJobContext {
            workflow_id: self.workflow_id,
            run_id: self.run_id,
            job_id: self.job_id,
            repository,
            commit_sha,
            git_ref,
            workflow_name,
            workspace,
            actor: self.actor,
            run_number: self.run_number,
            run_attempt: self.run_attempt,
            event,
        })
    }
}

/// One server-owned mapping from a GitHub runner selector to an attested image profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubRunnerProfileMapping {
    selector: RunnerLabel,
    environment_profile: EnvironmentProfile,
    operating_system: OperatingSystem,
    architecture: Architecture,
    container_features: BTreeSet<ContainerFeature>,
}

impl GithubRunnerProfileMapping {
    /// Creates a typed mapping without resolving or inspecting an image.
    ///
    /// # Errors
    ///
    /// Returns [`JobEvaluationInputError`] for an invalid selector or platform.
    pub fn new(
        selector: impl AsRef<str>,
        environment_profile: EnvironmentProfile,
        operating_system: OperatingSystem,
        architecture: Architecture,
    ) -> Result<Self, JobEvaluationInputError> {
        let selector = RunnerLabel::new(selector)
            .map_err(|_| JobEvaluationInputError::InvalidProfileSelector)?;
        validate_platform_value(&operating_system, &architecture)?;
        Ok(Self {
            selector,
            environment_profile,
            operating_system,
            architecture,
            container_features: BTreeSet::new(),
        })
    }

    /// Adds provider-neutral container features guaranteed by this exact
    /// attested environment profile.
    #[must_use]
    pub fn with_container_features(
        mut self,
        features: impl IntoIterator<Item = ContainerFeature>,
    ) -> Self {
        self.container_features = features.into_iter().collect();
        self
    }

    #[must_use]
    pub const fn selector(&self) -> &RunnerLabel {
        &self.selector
    }

    #[must_use]
    pub const fn environment_profile(&self) -> &EnvironmentProfile {
        &self.environment_profile
    }

    #[must_use]
    pub const fn operating_system(&self) -> &OperatingSystem {
        &self.operating_system
    }

    #[must_use]
    pub const fn architecture(&self) -> &Architecture {
        &self.architecture
    }

    #[must_use]
    pub const fn container_features(&self) -> &BTreeSet<ContainerFeature> {
        &self.container_features
    }
}

/// Validated catalog of server-attested GitHub-hosted runner profiles.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GithubRunnerProfileCatalog {
    mappings: BTreeMap<RunnerLabel, GithubRunnerProfileMapping>,
}

impl GithubRunnerProfileCatalog {
    /// Builds a catalog and rejects duplicate canonical selectors.
    ///
    /// # Errors
    ///
    /// Returns [`JobEvaluationInputError::DuplicateProfileSelector`] for duplicates.
    pub fn new(
        mappings: impl IntoIterator<Item = GithubRunnerProfileMapping>,
    ) -> Result<Self, JobEvaluationInputError> {
        let mut catalog = BTreeMap::new();
        for mapping in mappings {
            let selector = mapping.selector.clone();
            if catalog.insert(selector.clone(), mapping).is_some() {
                return Err(JobEvaluationInputError::DuplicateProfileSelector(
                    selector.as_str().to_owned(),
                ));
            }
        }
        Ok(Self { mappings: catalog })
    }

    #[must_use]
    pub fn get(&self, selector: &RunnerLabel) -> Option<&GithubRunnerProfileMapping> {
        self.mappings.get(selector)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }
}

/// Validated evaluation input failures, before a workflow source span is involved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JobEvaluationInputError {
    MissingField(&'static str),
    InvalidRepository,
    InvalidCommitSha,
    InvalidGitRef,
    InvalidWorkflowName,
    InvalidWorkspace,
    InvalidProfileSelector,
    InvalidProfilePlatform,
    DuplicateProfileSelector(String),
}

impl fmt::Display for JobEvaluationInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => write!(formatter, "required evaluation field `{field}` is missing"),
            Self::InvalidRepository => formatter.write_str("repository must be canonical `owner/name` text"),
            Self::InvalidCommitSha => formatter.write_str("commit SHA must be 40 or 64 lower-case hexadecimal characters"),
            Self::InvalidGitRef => formatter.write_str("Git ref must be a canonical full `refs/...` name"),
            Self::InvalidWorkflowName => formatter.write_str("workflow name must be non-empty bounded text without control characters"),
            Self::InvalidWorkspace => formatter.write_str(
                "sandbox workspace must be a normalized absolute path in the declared target grammar",
            ),
            Self::InvalidProfileSelector => formatter.write_str("profile selector is not a canonical runner selector"),
            Self::InvalidProfilePlatform => formatter.write_str("profile platform contains an empty or non-canonical custom value"),
            Self::DuplicateProfileSelector(selector) => write!(formatter, "profile selector `{selector}` is mapped more than once"),
        }
    }
}

impl Error for JobEvaluationInputError {}

/// Borrowed request to evaluate exactly one selected workflow job.
#[derive(Clone, Debug)]
pub struct EvaluateJobRequest<'request> {
    plan: &'request WorkflowPlan,
    context: &'request GithubJobContext,
    profiles: &'request GithubRunnerProfileCatalog,
    selected_job: WorkflowJobKey,
}

impl<'request> EvaluateJobRequest<'request> {
    #[must_use]
    pub const fn new(
        plan: &'request WorkflowPlan,
        context: &'request GithubJobContext,
        profiles: &'request GithubRunnerProfileCatalog,
        selected_job: WorkflowJobKey,
    ) -> Self {
        Self {
            plan,
            context,
            profiles,
            selected_job,
        }
    }

    #[must_use]
    pub const fn plan(&self) -> &'request WorkflowPlan {
        self.plan
    }

    #[must_use]
    pub const fn context(&self) -> &'request GithubJobContext {
        self.context
    }

    #[must_use]
    pub const fn profiles(&self) -> &'request GithubRunnerProfileCatalog {
        self.profiles
    }

    #[must_use]
    pub const fn selected_job(&self) -> &WorkflowJobKey {
        &self.selected_job
    }
}

/// Output of one fail-closed job evaluation.
#[derive(Clone, Debug)]
pub struct JobEvaluationReport {
    envelope: Option<JobIrEnvelope>,
    diagnostics: Vec<Diagnostic>,
}

/// Replaceable orchestration port for GitHub workflow-plan job evaluation.
///
/// This early phase resolves only server-owned context. Conditions are parsed
/// into a versioned durable program while their runtime values remain late-bound.
pub trait WorkflowJobEvaluator: fmt::Debug + Send + Sync {
    fn evaluate(&self, request: &EvaluateJobRequest<'_>) -> JobEvaluationReport;
}

impl JobEvaluationReport {
    #[must_use]
    pub const fn envelope(&self) -> Option<&JobIrEnvelope> {
        self.envelope.as_ref()
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    #[must_use]
    pub fn is_accepted(&self) -> bool {
        self.envelope.is_some()
            && !self
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity() == DiagnosticSeverity::Error)
    }

    #[must_use]
    pub fn into_parts(self) -> (Option<JobIrEnvelope>, Vec<Diagnostic>) {
        (self.envelope, self.diagnostics)
    }
}

/// Pure GitHub early-context evaluator. It performs no I/O or action fetching.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct GithubJobEvaluator;

impl GithubJobEvaluator {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn evaluate(&self, request: &EvaluateJobRequest<'_>) -> JobEvaluationReport {
        evaluate_job(request)
    }
}

impl WorkflowJobEvaluator for GithubJobEvaluator {
    fn evaluate(&self, request: &EvaluateJobRequest<'_>) -> JobEvaluationReport {
        evaluate_job(request)
    }
}

#[derive(Debug)]
struct EvaluationState<'request> {
    context: &'request GithubJobContext,
    profiles: &'request GithubRunnerProfileCatalog,
    diagnostics: Vec<Diagnostic>,
}

impl EvaluationState<'_> {
    fn unsupported(&mut self, code: &str, message: impl Into<String>, span: &PlanSourceSpan) {
        self.diagnostics.push(Diagnostic::error(
            DiagnosticKind::Unsupported,
            code,
            message,
            source_span(span),
        ));
    }

    fn semantic(&mut self, code: &str, message: impl Into<String>, span: &PlanSourceSpan) {
        self.diagnostics.push(Diagnostic::error(
            DiagnosticKind::Semantic,
            code,
            message,
            source_span(span),
        ));
    }

    fn expression(&mut self, error: &GithubExpressionError, source: &str, span: &PlanSourceSpan) {
        let kind = match error.kind() {
            GithubExpressionErrorKind::Syntax => DiagnosticKind::Syntax,
            GithubExpressionErrorKind::ResourceLimit => DiagnosticKind::ResourceLimit,
            GithubExpressionErrorKind::Context | GithubExpressionErrorKind::Internal => {
                DiagnosticKind::Semantic
            }
        };
        self.diagnostics.push(Diagnostic::error(
            kind,
            error.code(),
            error.message(),
            expression_source_span(span, source, error.byte_offset(), error.byte_length()),
        ));
    }

    fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity() == DiagnosticSeverity::Error)
    }
}

fn evaluate_job(request: &EvaluateJobRequest<'_>) -> JobEvaluationReport {
    let mut state = EvaluationState {
        context: request.context,
        profiles: request.profiles,
        diagnostics: Vec::new(),
    };
    if let Err(error) = request.plan.validate() {
        state.semantic(
            "github.evaluate.invalid_workflow_plan",
            error.to_string(),
            request.plan.span(),
        );
        return report(None, state);
    }
    let source_path = validate_plan_context(request.plan, &mut state);
    let Some(job) = request.plan.job(&request.selected_job) else {
        state.semantic(
            "github.evaluate.unknown_job",
            format!("workflow has no job `{}`", request.selected_job),
            request.plan.span(),
        );
        return report(None, state);
    };
    let envelope = evaluate_selected_job(request.plan, job, source_path.as_deref(), &mut state);
    report(envelope.filter(|_| !state.has_errors()), state)
}

fn report(envelope: Option<JobIrEnvelope>, state: EvaluationState<'_>) -> JobEvaluationReport {
    JobEvaluationReport {
        envelope,
        diagnostics: state.diagnostics,
    }
}

fn validate_plan_context(plan: &WorkflowPlan, state: &mut EvaluationState<'_>) -> Option<String> {
    if plan.source().provider() != "github" || plan.event().provider() != "github" {
        state.semantic(
            "github.evaluate.provider_mismatch",
            "GitHub evaluation requires GitHub source and event provenance",
            plan.span(),
        );
    }
    let source_path = match plan.source().origin() {
        PlanSourceOrigin::Repository {
            repository,
            revision,
            path,
        } => {
            if repository != state.context.repository() {
                state.semantic(
                    "github.evaluate.repository_mismatch",
                    "request repository does not match workflow provenance",
                    plan.span(),
                );
            }
            if revision != state.context.commit_sha() {
                state.semantic(
                    "github.evaluate.revision_mismatch",
                    "request commit SHA does not match immutable workflow provenance",
                    plan.span(),
                );
            }
            if !valid_repository_path(path) {
                state.semantic(
                    "github.evaluate.invalid_workflow_path",
                    "workflow provenance path must be canonical repository-relative text",
                    plan.span(),
                );
                None
            } else if plan.source().source_id() != path {
                state.semantic(
                    "github.evaluate.workflow_source_identity",
                    "repository workflow path does not match its source identity",
                    plan.span(),
                );
                None
            } else {
                Some(path.clone())
            }
        }
        PlanSourceOrigin::LocalPath { .. } | PlanSourceOrigin::Memory { .. } => {
            state.unsupported(
                "github.evaluate.non_repository_source",
                "job evaluation requires immutable repository source provenance",
                plan.span(),
            );
            None
        }
    };
    validate_event_context(plan, state);
    if let Some(name) = plan.name()
        && name.value() != state.context.workflow_name()
    {
        state.semantic(
            "github.evaluate.workflow_name_mismatch",
            "request workflow name does not match the compiled workflow name",
            name.span(),
        );
    }
    source_path
}

fn validate_event_context(plan: &WorkflowPlan, state: &mut EvaluationState<'_>) {
    if let Some(commit_sha) = plan.event().commit_sha()
        && commit_sha != state.context.commit_sha()
    {
        state.semantic(
            "github.evaluate.event_sha_mismatch",
            "request commit SHA does not match event provenance",
            plan.event()
                .configured_trigger_span()
                .unwrap_or_else(|| plan.span()),
        );
    }
    if let Some(git_ref) = plan.event().git_ref()
        && git_ref != state.context.git_ref()
    {
        state.semantic(
            "github.evaluate.event_ref_mismatch",
            "request Git ref does not match event provenance",
            plan.event()
                .configured_trigger_span()
                .unwrap_or_else(|| plan.span()),
        );
    }
}

fn evaluate_selected_job(
    plan: &WorkflowPlan,
    job: &PlannedJob,
    source_path: Option<&str>,
    state: &mut EvaluationState<'_>,
) -> Option<JobIrEnvelope> {
    reject_unrepresented_job_fields(job, state);
    let requirements = evaluate_runner(job, state)?;
    validate_workspace_path_style(job, &requirements, state)?;
    let job_environment = evaluate_job_environment(plan, job, state)?;
    let job_shell_value = job
        .run_defaults()
        .shell()
        .or_else(|| plan.run_defaults().shell());
    let job_shell = evaluate_shell(job_shell_value, &requirements, state)?;
    let job_directory_value = job
        .run_defaults()
        .working_directory()
        .or_else(|| plan.run_defaults().working_directory());
    let job_directory = match job_directory_value {
        Some(value) => Some(evaluate_working_directory(value, state)?),
        None => None,
    };
    let steps = evaluate_steps(
        job,
        &job_environment,
        &job_shell,
        job_directory.as_deref(),
        &requirements,
        state,
    );
    let job_condition = evaluate_job_condition(job, state);
    let source_path = source_path?;
    if state.has_errors() {
        return None;
    }
    let mut ir = JobIr::new(
        state.context.job_id(),
        state.context.run_id(),
        job.name()
            .map_or_else(|| job.key().value().as_str(), |name| name.value()),
        requirements,
        steps,
    )
    .with_environment(job_environment);
    if let Some(condition) = job_condition {
        ir = ir.with_condition(condition);
    }
    if let Some(timeout) = job.timeout_seconds() {
        ir = ir.with_timeout_seconds(timeout);
    }
    if let Some(directory) = job_directory {
        ir = ir.with_working_directory(directory);
    }
    let execution = job_execution_context(state.context);
    let envelope = JobIrEnvelope::new(
        state.context.workflow_id(),
        JobSource::new(
            "github",
            state.context.repository(),
            state.context.commit_sha(),
            source_path,
            plan.event().name(),
        ),
        execution,
        ir,
    );
    if let Err(error) = envelope.validate() {
        state.semantic(
            "github.evaluate.invalid_job_ir",
            error.to_string(),
            job.span(),
        );
        return None;
    }
    Some(envelope)
}

fn evaluate_job_condition(
    job: &PlannedJob,
    state: &mut EvaluationState<'_>,
) -> Option<ExpressionProgram> {
    let compiler = GithubConditionCompiler::default();
    let (source, span) = job.condition().map_or((None, job.span()), |condition| {
        (Some(condition.value().source()), condition.span())
    });
    match compiler.compile_condition(source, GithubConditionPhase::Job) {
        Ok(program) => Some(program),
        Err(error) => {
            state.expression(&error, source.unwrap_or_default(), span);
            None
        }
    }
}

fn job_execution_context(context: &GithubJobContext) -> JobExecutionContext {
    let mut execution = JobExecutionContext::new(
        context.workflow_name(),
        context.git_ref(),
        context.workspace().as_str(),
        context.event().clone(),
    );
    if let Some(actor) = context.actor() {
        execution = execution.with_actor(actor);
    }
    if let Some(run_number) = context.run_number() {
        execution = execution.with_run_number(run_number);
    }
    if let Some(run_attempt) = context.run_attempt() {
        execution = execution.with_run_attempt(run_attempt);
    }
    execution
}

fn reject_unrepresented_job_fields(job: &PlannedJob, state: &mut EvaluationState<'_>) {
    if let Some(value) = job.continue_on_error() {
        state.unsupported(
            "github.evaluate.job_continue_on_error",
            "current JobIR cannot represent job-level continue-on-error",
            value.span(),
        );
    }
    if let Some(name) = job.name()
        && name.value().contains("${{")
    {
        state.unsupported(
            "github.evaluate.dynamic_job_name",
            "compiled workflow-plan job names cannot be evaluated losslessly",
            name.span(),
        );
    }
}

fn evaluate_job_environment(
    plan: &WorkflowPlan,
    job: &PlannedJob,
    state: &mut EvaluationState<'_>,
) -> Option<BTreeMap<String, ValueSource>> {
    let mut environment = BTreeMap::new();
    overlay_value_map(&mut environment, plan.environment(), state);
    overlay_value_map(&mut environment, job.environment(), state);
    (!state.has_errors()).then_some(environment)
}

fn evaluate_steps(
    job: &PlannedJob,
    job_environment: &BTreeMap<String, ValueSource>,
    job_shell: &ShellSpec,
    job_directory: Option<&str>,
    requirements: &RunnerRequirements,
    state: &mut EvaluationState<'_>,
) -> Vec<StepIr> {
    let Some(ids) = evaluate_step_ids(job, state) else {
        return Vec::new();
    };
    job.steps()
        .iter()
        .zip(ids)
        .filter_map(|(step, id)| {
            evaluate_step(
                step,
                id,
                job_environment,
                job_shell,
                job_directory,
                requirements,
                state,
            )
        })
        .collect()
}

fn evaluate_step(
    step: &PlannedStep,
    id: StepId,
    job_environment: &BTreeMap<String, ValueSource>,
    job_shell: &ShellSpec,
    job_directory: Option<&str>,
    requirements: &RunnerRequirements,
    state: &mut EvaluationState<'_>,
) -> Option<StepIr> {
    let mut environment = job_environment.clone();
    overlay_value_map(&mut environment, step.environment(), state);
    let kind = match step.execution() {
        PlannedStepKind::Run(run) => {
            evaluate_run_step(run, job_shell, job_directory, requirements, state)?
        }
        PlannedStepKind::Uses(uses) => {
            let reference = parse_action_reference(uses.reference(), state)?;
            let mut inputs = BTreeMap::new();
            overlay_value_map(&mut inputs, uses.inputs(), state);
            SemanticStep::action(reference, inputs)
        }
    };
    let name = step
        .name()
        .map_or_else(|| step.key().as_str(), |name| name.value());
    if name.contains("${{") {
        state.unsupported(
            "github.evaluate.dynamic_step_name",
            "compiled workflow-plan step names cannot be evaluated losslessly",
            step.name().map_or_else(|| step.span(), Located::span),
        );
        return None;
    }
    let mut ir = StepIr::new(id, name, kind).with_environment(environment);
    let condition_compiler = GithubConditionCompiler::default();
    let condition = match step.condition() {
        Some(condition) => match condition_compiler
            .compile_condition(Some(condition.value().source()), GithubConditionPhase::Step)
        {
            Ok(program) => program,
            Err(error) => {
                state.expression(&error, condition.value().source(), condition.span());
                return None;
            }
        },
        None => match condition_compiler.compile_condition(None, GithubConditionPhase::Step) {
            Ok(program) => program,
            Err(error) => {
                state.expression(&error, "", step.span());
                return None;
            }
        },
    };
    ir = ir.with_condition(condition);
    if let Some(value) = step.continue_on_error() {
        match value.value() {
            DeferredBoolean::Literal(enabled) => ir = ir.with_continue_on_error(*enabled),
            DeferredBoolean::Expression(_) => state.unsupported(
                "github.evaluate.late_continue_on_error",
                "expression-valued continue-on-error is late-bound and current JobIR requires a boolean",
                value.span(),
            ),
        }
    }
    if let Some(timeout) = step.timeout_seconds() {
        ir = ir.with_timeout_seconds(timeout);
    }
    Some(ir)
}

fn evaluate_run_step(
    run: &automata_core::RunStepPlan,
    job_shell: &ShellSpec,
    job_directory: Option<&str>,
    requirements: &RunnerRequirements,
    state: &mut EvaluationState<'_>,
) -> Option<SemanticStep> {
    let command = evaluate_value(run.script(), state)?;
    let shell = match run.shell() {
        Some(value) => evaluate_shell(Some(value), requirements, state)?,
        None => job_shell.clone(),
    };
    let directory = match run.working_directory() {
        Some(value) => Some(evaluate_working_directory(value, state)?),
        None => job_directory.map(str::to_owned),
    };
    Some(SemanticStep::Run {
        command,
        shell,
        working_directory: directory,
    })
}

fn evaluate_shell(
    value: Option<&Located<PlanValue>>,
    requirements: &RunnerRequirements,
    state: &mut EvaluationState<'_>,
) -> Option<ShellSpec> {
    let Some(value) = value else {
        return Some(
            if requirements.environment_profile().is_some()
                && matches!(
                    requirements.operating_system(),
                    Some(OperatingSystem::Linux)
                )
            {
                ShellSpec::CommandTemplate(DEFAULT_GITHUB_LINUX_SHELL_TEMPLATE.to_owned())
            } else {
                ShellSpec::Default
            },
        );
    };
    let shell = evaluate_value(value, state)?;
    if shell.is_empty() || shell.chars().any(char::is_control) {
        state.semantic(
            "github.evaluate.invalid_shell",
            "shell must be non-empty text without control characters",
            value.span(),
        );
        return None;
    }
    Some(if shell.contains("{0}") {
        ShellSpec::CommandTemplate(shell)
    } else {
        ShellSpec::Named(shell)
    })
}

fn evaluate_working_directory(
    value: &Located<PlanValue>,
    state: &mut EvaluationState<'_>,
) -> Option<String> {
    let directory = evaluate_value(value, state)?;
    if !contained_working_directory(&directory, state.context.workspace()) {
        state.semantic(
            "github.evaluate.working_directory_escape",
            "working-directory must remain within the sandbox workspace",
            value.span(),
        );
        return None;
    }
    Some(directory)
}

fn overlay_value_map(
    destination: &mut BTreeMap<String, ValueSource>,
    layer: &ValueMapPlan,
    state: &mut EvaluationState<'_>,
) {
    for (key, value) in layer.entries() {
        if let Some(value) = evaluate_value(value, state) {
            destination.insert(key.value().clone(), ValueSource::Literal(value));
        }
    }
}

fn evaluate_value(value: &Located<PlanValue>, state: &mut EvaluationState<'_>) -> Option<String> {
    match value.value() {
        PlanValue::Literal(value) => Some(value.clone()),
        PlanValue::Expression(expression) => evaluate_expression(expression, value.span(), state),
    }
}

fn evaluate_expression(
    expression: &PlanExpression,
    span: &PlanSourceSpan,
    state: &mut EvaluationState<'_>,
) -> Option<String> {
    let mut output = String::new();
    for segment in expression.segments() {
        match segment {
            ExpressionSegment::Literal(value) => output.push_str(value),
            ExpressionSegment::Evaluation(source) => {
                output.push_str(evaluate_github_access(source, span, state)?);
            }
        }
    }
    Some(output)
}

fn evaluate_github_access<'context>(
    source: &str,
    span: &PlanSourceSpan,
    state: &'context mut EvaluationState<'_>,
) -> Option<&'context str> {
    let inner = source
        .strip_prefix("${{")
        .and_then(|value| value.strip_suffix("}}"))
        .map(str::trim);
    let Some(inner) = inner else {
        state.unsupported(
            "github.evaluate.expression_shape",
            "only delimited GitHub context property evaluations are early-bound",
            span,
        );
        return None;
    };
    if inner.contains('(') || inner.contains(')') {
        state.unsupported(
            "github.evaluate.unsupported_function",
            "functions are not supported during early GitHub context evaluation",
            span,
        );
        return None;
    }
    let normalized = inner.to_ascii_lowercase();
    let value = match normalized.as_str() {
        "github.workflow" => state.context.workflow_name(),
        "github.ref" => state.context.git_ref(),
        "github.sha" => state.context.commit_sha(),
        "github.workspace" => state.context.workspace().as_str(),
        "github.repository" => state.context.repository(),
        _ => {
            let context = inner.split_once('.').map_or(inner, |(context, _)| context);
            let (code, message) = if is_late_context(context) {
                (
                    "github.evaluate.late_context",
                    format!("context `{context}` is late-bound in this evaluation phase"),
                )
            } else {
                (
                    "github.evaluate.unsupported_context",
                    format!("expression `{inner}` is not a supported early GitHub property"),
                )
            };
            state.unsupported(code, message, span);
            return None;
        }
    };
    Some(value)
}

fn is_late_context(context: &str) -> bool {
    [
        "env", "inputs", "job", "matrix", "needs", "runner", "secrets", "steps", "strategy", "vars",
    ]
    .iter()
    .any(|candidate| context.eq_ignore_ascii_case(candidate))
}

fn evaluate_runner(
    job: &PlannedJob,
    state: &mut EvaluationState<'_>,
) -> Option<RunnerRequirements> {
    let group = job
        .runner()
        .group()
        .and_then(|value| evaluate_runner_group(value, state));
    let labels = job
        .runner()
        .labels()
        .iter()
        .filter_map(|value| evaluate_runner_label(value, state).map(|label| (label, value.span())))
        .collect::<Vec<_>>();
    if state.has_errors() {
        return None;
    }
    let mapped = labels
        .iter()
        .filter_map(|(label, span)| state.profiles.get(label).map(|mapping| (mapping, *span)))
        .collect::<Vec<_>>();
    if let Some((mapping, _)) = mapped.first() {
        if mapped.len() != 1 || labels.len() != 1 || group.is_some() {
            state.unsupported(
                "github.evaluate.ambiguous_hosted_profile",
                "an attested GitHub-hosted profile must be the sole runner selector",
                job.runner().span(),
            );
            return None;
        }
        return Some(
            RunnerRequirements::default()
                .with_environment_profile(mapping.environment_profile().clone())
                .with_operating_system(mapping.operating_system().clone())
                .with_architecture(mapping.architecture().clone())
                .with_container_features(mapping.container_features().iter().cloned()),
        );
    }
    evaluate_self_hosted_requirements(group, labels, job.runner().span(), state)
}

fn validate_workspace_path_style(
    job: &PlannedJob,
    requirements: &RunnerRequirements,
    state: &mut EvaluationState<'_>,
) -> Option<()> {
    let compatible = match requirements.operating_system() {
        Some(OperatingSystem::Windows) => {
            state.context.workspace().style() == GithubTargetPathStyle::Windows
        }
        Some(OperatingSystem::Linux | OperatingSystem::Macos) => {
            state.context.workspace().style() == GithubTargetPathStyle::Unix
        }
        Some(OperatingSystem::Other(_)) | None => true,
    };
    if !compatible {
        state.semantic(
            "github.evaluate.workspace_path_style",
            "sandbox workspace path grammar does not match the selected runner operating system",
            job.runner().span(),
        );
        return None;
    }
    Some(())
}

fn evaluate_runner_group(
    value: &Located<PlanValue>,
    state: &mut EvaluationState<'_>,
) -> Option<RunnerGroup> {
    let group = evaluate_value(value, state)?;
    RunnerGroup::new(&group)
        .map_err(|error| {
            state.semantic(
                "github.evaluate.invalid_runner_group",
                error.to_string(),
                value.span(),
            );
        })
        .ok()
}

fn evaluate_runner_label(
    value: &Located<PlanValue>,
    state: &mut EvaluationState<'_>,
) -> Option<RunnerLabel> {
    let label = evaluate_value(value, state)?;
    RunnerLabel::new(&label)
        .map_err(|error| {
            state.semantic(
                "github.evaluate.invalid_runner_label",
                error.to_string(),
                value.span(),
            );
        })
        .ok()
}

fn evaluate_self_hosted_requirements(
    group: Option<RunnerGroup>,
    labels: Vec<(RunnerLabel, &PlanSourceSpan)>,
    runner_span: &PlanSourceSpan,
    state: &mut EvaluationState<'_>,
) -> Option<RunnerRequirements> {
    let mut operating_system = MergedSelector::Unset;
    let mut architecture = MergedSelector::Unset;
    for (label, _) in &labels {
        match label.as_str() {
            "linux" => merge_selector(&mut operating_system, OperatingSystem::Linux),
            "windows" => merge_selector(&mut operating_system, OperatingSystem::Windows),
            "macos" => merge_selector(&mut operating_system, OperatingSystem::Macos),
            "x64" | "x86_64" => merge_selector(&mut architecture, Architecture::X86_64),
            "arm64" | "aarch64" => merge_selector(&mut architecture, Architecture::Aarch64),
            _ => {}
        }
    }
    if matches!(operating_system, MergedSelector::Conflict)
        || matches!(architecture, MergedSelector::Conflict)
    {
        state.semantic(
            "github.evaluate.conflicting_runner_selectors",
            "runner selectors require conflicting typed platforms",
            runner_span,
        );
        return None;
    }
    let mut requirements =
        RunnerRequirements::default().with_labels(labels.into_iter().map(|(label, _)| label));
    if let Some(group) = group {
        requirements = requirements.with_eligible_groups([group]);
    }
    if let MergedSelector::Value(value) = operating_system {
        requirements = requirements.with_operating_system(value);
    }
    if let MergedSelector::Value(value) = architecture {
        requirements = requirements.with_architecture(value);
    }
    Some(requirements)
}

enum MergedSelector<T> {
    Unset,
    Value(T),
    Conflict,
}

fn merge_selector<T: Eq>(slot: &mut MergedSelector<T>, value: T) {
    match slot {
        MergedSelector::Unset => {
            *slot = MergedSelector::Value(value);
        }
        MergedSelector::Value(current) if current == &value => {}
        MergedSelector::Value(_) | MergedSelector::Conflict => {
            *slot = MergedSelector::Conflict;
        }
    }
}

fn evaluate_step_ids(job: &PlannedJob, state: &mut EvaluationState<'_>) -> Option<Vec<StepId>> {
    let mut allocated = BTreeSet::new();
    let mut ids = Vec::with_capacity(job.steps().len());
    for step in job.steps() {
        let Some(explicit) = step.id() else {
            ids.push(None);
            continue;
        };
        let id = match StepId::new(explicit.value().clone()) {
            Ok(id) => id,
            Err(error) => {
                state.semantic(
                    "github.evaluate.invalid_step_id",
                    error.to_string(),
                    explicit.span(),
                );
                ids.push(None);
                continue;
            }
        };
        if !allocated.insert(id.clone()) {
            state.semantic(
                "github.evaluate.step_id_collision",
                format!("GitHub step ID `{id}` is not unique"),
                explicit.span(),
            );
        }
        ids.push(Some(id));
    }
    if state.has_errors() {
        return None;
    }
    ids.into_iter()
        .zip(job.steps())
        .map(|(id, step)| match id {
            Some(id) => Some(id),
            None => allocate_anonymous_step_id(step, &mut allocated, state),
        })
        .collect()
}

fn allocate_anonymous_step_id(
    step: &PlannedStep,
    allocated: &mut BTreeSet<StepId>,
    state: &mut EvaluationState<'_>,
) -> Option<StepId> {
    let Some(position) = step.key().as_str().strip_prefix("position/") else {
        state.unsupported(
            "github.evaluate.anonymous_step_key",
            "anonymous GitHub steps require a compiler-assigned position key",
            step.span(),
        );
        return None;
    };
    let base = format!("github_p_{position}");
    for suffix in 0_u32..=u32::MAX {
        let candidate = if suffix == 0 {
            base.clone()
        } else {
            format!("{base}_{suffix}")
        };
        let id = match StepId::new(candidate) {
            Ok(id) => id,
            Err(error) => {
                state.unsupported(
                    "github.evaluate.step_id_capacity",
                    format!("anonymous workflow step cannot be assigned an ID: {error}"),
                    step.span(),
                );
                return None;
            }
        };
        if allocated.insert(id.clone()) {
            return Some(id);
        }
    }
    unreachable!("the finite step list cannot exhaust every numeric suffix")
}

fn parse_action_reference(
    reference: &Located<String>,
    state: &mut EvaluationState<'_>,
) -> Option<ActionReference> {
    let source = reference.value();
    if source.contains("${{") {
        state.unsupported(
            "github.evaluate.dynamic_action_reference",
            "action references cannot be late-bound",
            reference.span(),
        );
        return None;
    }
    if source.starts_with("docker://") {
        state.unsupported(
            "github.evaluate.container_action",
            "container actions are recognized but are not implemented by this JobIR evaluation phase",
            reference.span(),
        );
        return None;
    }
    if source.starts_with("./") {
        return validate_local_action_path(source)
            .map(|()| ActionReference::Local {
                path: source.clone(),
            })
            .map_err(|message| {
                state.semantic(
                    "github.evaluate.invalid_local_action",
                    message,
                    reference.span(),
                );
            })
            .ok();
    }
    parse_repository_action(source)
        .map_err(|message| {
            state.semantic(
                "github.evaluate.invalid_action_reference",
                message,
                reference.span(),
            );
        })
        .ok()
}

fn parse_repository_action(source: &str) -> Result<ActionReference, &'static str> {
    if source.matches('@').count() != 1 {
        return Err("repository action must contain exactly one `@revision`");
    }
    let (path, revision) = source
        .split_once('@')
        .ok_or("repository action is missing `@revision`")?;
    if !valid_action_revision(revision) {
        return Err("action revision is not a canonical Git revision");
    }
    let components = path.split('/').collect::<Vec<_>>();
    if components.len() < 2
        || !valid_repository_component(components[0])
        || !valid_repository_component(components[1])
        || components[2..]
            .iter()
            .any(|part| !valid_action_component(part))
    {
        return Err("repository action must be `owner/repository[/subpath]@revision`");
    }
    let repository = format!("{}/{}", components[0], components[1]);
    let subpath = (components.len() > 2).then(|| components[2..].join("/"));
    Ok(ActionReference::Repository {
        repository,
        revision: revision.to_owned(),
        subpath,
    })
}

fn validate_local_action_path(source: &str) -> Result<(), &'static str> {
    if source.contains('\\') || source.chars().any(char::is_control) {
        return Err("local action path must use canonical `/` separators");
    }
    let relative = source
        .strip_prefix("./")
        .ok_or("local action path must begin with `./`")?;
    if relative.is_empty()
        || relative
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err("local action path must remain below the checked-out workspace");
    }
    Ok(())
}

fn valid_action_component(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

fn valid_action_revision(value: &str) -> bool {
    // This is Git's `--allow-onelevel` ref grammar with an intentional ban on
    // whitespace and option-like leading `-` revisions at every adapter edge.
    !value.is_empty()
        && value != "@"
        && value.trim() == value
        && !value.starts_with(['/', '.', '-'])
        && !value.ends_with(['/', '.'])
        && !value.contains("//")
        && !value.contains("..")
        && !value.contains("@{")
        && value.split('/').all(|component| {
            !component.is_empty()
                && !component.starts_with('.')
                && !component.ends_with('.')
                && !component.as_bytes().ends_with(b".lock")
        })
        && !value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || "\\~^:?*[]".contains(character)
        })
}

fn contained_working_directory(value: &str, workspace: &GithubWorkspacePath) -> bool {
    if value.is_empty() || value.chars().any(char::is_control) {
        return false;
    }
    match workspace.style() {
        GithubTargetPathStyle::Unix => contained_unix_path(value, workspace.as_str()),
        GithubTargetPathStyle::Windows => contained_windows_path(value, workspace.as_str()),
    }
}

fn contained_unix_path(value: &str, workspace: &str) -> bool {
    if value.contains('\\') {
        return false;
    }
    if !value.starts_with('/') {
        return valid_relative_components(value, '/', valid_unix_component);
    }
    let Some(value_components) = absolute_unix_components(value) else {
        return false;
    };
    let Some(workspace_components) = absolute_unix_components(workspace) else {
        return false;
    };
    value_components.starts_with(&workspace_components)
}

fn contained_windows_path(value: &str, workspace: &str) -> bool {
    if value.contains('/') {
        return false;
    }
    if !is_windows_absolute(value) {
        return !value.contains(':')
            && valid_relative_components(value, '\\', valid_windows_component);
    }
    let Some((value_drive, value_components)) = absolute_windows_components(value) else {
        return false;
    };
    let Some((workspace_drive, workspace_components)) = absolute_windows_components(workspace)
    else {
        return false;
    };
    value_drive.eq_ignore_ascii_case(workspace_drive)
        && value_components.len() >= workspace_components.len()
        && value_components
            .iter()
            .zip(workspace_components)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn validate_workspace_value(
    style: GithubTargetPathStyle,
    value: &str,
) -> Result<(), JobEvaluationInputError> {
    let valid = match style {
        GithubTargetPathStyle::Unix => absolute_unix_components(value).is_some(),
        GithubTargetPathStyle::Windows => absolute_windows_components(value).is_some(),
    };
    if valid {
        Ok(())
    } else {
        Err(JobEvaluationInputError::InvalidWorkspace)
    }
}

fn absolute_unix_components(value: &str) -> Option<Vec<&str>> {
    if value.chars().any(char::is_control)
        || value.contains('\\')
        || !value.starts_with('/')
        || value == "/"
        || value.ends_with('/')
    {
        return None;
    }
    let components = value.strip_prefix('/')?.split('/').collect::<Vec<_>>();
    components
        .iter()
        .all(|component| valid_unix_component(component))
        .then_some(components)
}

fn absolute_windows_components(value: &str) -> Option<(&str, Vec<&str>)> {
    if value.chars().any(char::is_control) || value.contains('/') || !is_windows_absolute(value) {
        return None;
    }
    let (drive, relative) = value.split_at(2);
    let relative = relative.strip_prefix('\\')?;
    if relative.is_empty() || relative.ends_with('\\') {
        return None;
    }
    let components = relative.split('\\').collect::<Vec<_>>();
    components
        .iter()
        .all(|component| valid_windows_component(component))
        .then_some((drive, components))
}

fn is_windows_absolute(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
}

fn valid_relative_components(
    value: &str,
    separator: char,
    valid_component: fn(&str) -> bool,
) -> bool {
    value
        .split(separator)
        .all(|component| component == "." || (component != ".." && valid_component(component)))
}

fn valid_unix_component(value: &str) -> bool {
    !value.is_empty() && !matches!(value, "." | "..") && !value.chars().any(char::is_control)
}

fn valid_windows_component(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && !value.ends_with([' ', '.'])
        && !value
            .chars()
            .any(|character| character.is_control() || "<>:\"/\\|?*".contains(character))
}

fn validate_repository(repository: &str) -> Result<(), JobEvaluationInputError> {
    let components = repository.split('/').collect::<Vec<_>>();
    if components.len() != 2
        || components
            .iter()
            .any(|part| !valid_repository_component(part))
    {
        return Err(JobEvaluationInputError::InvalidRepository);
    }
    Ok(())
}

fn valid_repository_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

fn valid_repository_component(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_commit_sha(commit_sha: &str) -> Result<(), JobEvaluationInputError> {
    if !matches!(commit_sha.len(), 40 | 64)
        || !commit_sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(JobEvaluationInputError::InvalidCommitSha);
    }
    Ok(())
}

fn validate_git_ref(git_ref: &str) -> Result<(), JobEvaluationInputError> {
    if !git_ref.starts_with("refs/") || !valid_action_revision(git_ref) {
        return Err(JobEvaluationInputError::InvalidGitRef);
    }
    Ok(())
}

fn validate_workflow_name(workflow_name: &str) -> Result<(), JobEvaluationInputError> {
    if workflow_name.trim().is_empty()
        || workflow_name.len() > 256
        || workflow_name.chars().any(char::is_control)
    {
        return Err(JobEvaluationInputError::InvalidWorkflowName);
    }
    Ok(())
}

fn validate_platform_value(
    operating_system: &OperatingSystem,
    architecture: &Architecture,
) -> Result<(), JobEvaluationInputError> {
    let values = [
        match operating_system {
            OperatingSystem::Other(value) => Some(value.as_str()),
            OperatingSystem::Linux | OperatingSystem::Windows | OperatingSystem::Macos => None,
        },
        match architecture {
            Architecture::Other(value) => Some(value.as_str()),
            Architecture::X86_64 | Architecture::Aarch64 => None,
        },
    ];
    if values.into_iter().flatten().any(|value| {
        value.trim().is_empty() || value.trim() != value || value.chars().any(char::is_control)
    }) {
        return Err(JobEvaluationInputError::InvalidProfilePlatform);
    }
    Ok(())
}

fn required<T>(value: Option<T>, field: &'static str) -> Result<T, JobEvaluationInputError> {
    value.ok_or(JobEvaluationInputError::MissingField(field))
}

fn source_span(span: &PlanSourceSpan) -> SourceSpan {
    let start = span.start();
    let end = span.end();
    let start = SourceLocation::try_new(
        usize::try_from(start.byte_offset()).unwrap_or(usize::MAX),
        start.line() as usize,
        start.column() as usize,
    )
    .expect("workflow-plan locations are one-based");
    let end = SourceLocation::try_new(
        usize::try_from(end.byte_offset()).unwrap_or(usize::MAX),
        end.line() as usize,
        end.column() as usize,
    )
    .expect("workflow-plan locations are one-based");
    SourceSpan::try_new(SourceId::new(span.source_id()), start, end)
        .expect("workflow-plan spans are ordered")
}

fn expression_source_span(
    span: &PlanSourceSpan,
    source: &str,
    offset: usize,
    length: usize,
) -> SourceSpan {
    let bounded_start = offset.min(source.len());
    let bounded_end = bounded_start.saturating_add(length).min(source.len());
    let base = span.start();
    let start = offset_location(base, &source[..bounded_start]);
    let end = offset_location(base, &source[..bounded_end]);
    let start = SourceLocation::try_new(
        usize::try_from(start.0).unwrap_or(usize::MAX),
        start.1 as usize,
        start.2 as usize,
    )
    .unwrap_or_else(|_| source_span(span).start());
    let end = SourceLocation::try_new(
        usize::try_from(end.0).unwrap_or(usize::MAX),
        end.1 as usize,
        end.2 as usize,
    )
    .unwrap_or(start);
    SourceSpan::try_new(SourceId::new(span.source_id()), start, end)
        .unwrap_or_else(|_| source_span(span))
}

fn offset_location(base: automata_core::PlanSourceLocation, fragment: &str) -> (u64, u32, u32) {
    let byte_offset = base
        .byte_offset()
        .saturating_add(u64::try_from(fragment.len()).unwrap_or(u64::MAX));
    let mut line = base.line();
    let mut column = base.column();
    if fragment.is_empty() {
        return (byte_offset, line, column);
    }
    for character in fragment.chars() {
        if character == '\n' {
            line = line.saturating_add(1);
            column = 1;
        } else {
            column = column.saturating_add(1);
        }
    }
    (byte_offset, line, column)
}
