use std::{collections::BTreeMap, fmt, sync::Arc};

use automata_auth::secret::SecretString;
use automata_core::{JobConclusion, RunnerId, SemanticStep, ValueSource};
use automata_execution::TargetPath;
use automata_expression_github::{
    GithubObject, GithubStatus, GithubValue, MapContext, NoExtensionFunctions,
};
use automata_github_runtime::StepId as RuntimeStepId;
use automata_job_executor_github::{
    ContextEnvironmentVariable, GithubContextPort, GithubContextRequest, GithubContextSnapshot,
    PortError, PortErrorKind,
};

use super::{ExecutorProductConfig, GithubProductConfig, SecretSource};

const MAX_RUNTIME_TOKEN_BYTES: usize = 65_536;
const GITHUB_RESULTS_RUNTIME_AUTHORITY: &str = "github-actions-results";

/// Standard Linux GitHub context and default-environment authority.
///
/// Values are derived only from immutable `JobIR`, durable command state, and
/// explicit product configuration. Event payloads and job-scoped credentials
/// are not invented when the orchestrator did not supply them. Results
/// authority comes only from the exact protected lease offer.
pub struct StandardGithubContext {
    runner_id: RunnerId,
    workspaces: BTreeMap<automata_core::EnvironmentProfile, String>,
    runner_root: String,
    home: String,
    path: String,
    temp: String,
    tool_cache: String,
    github: GithubProductConfig,
}

impl StandardGithubContext {
    /// Binds exact environment attestations to their workspace and standard
    /// runner paths.
    ///
    /// # Errors
    ///
    /// Rejects an empty environment catalog.
    pub fn new(
        runner_id: RunnerId,
        environments: &BTreeMap<
            automata_core::EnvironmentProfile,
            automata_execution::SandboxEnvironment,
        >,
        executor: &ExecutorProductConfig,
        github: GithubProductConfig,
    ) -> Result<Self, PortError> {
        if environments.is_empty() {
            return Err(invalid_data());
        }
        let workspaces = environments
            .iter()
            .map(|(profile, environment)| {
                (profile.clone(), environment.workspace().as_str().to_owned())
            })
            .collect();
        Ok(Self {
            runner_id,
            workspaces,
            runner_root: executor.runner_root().as_str().to_owned(),
            home: executor.home().as_str().to_owned(),
            path: executor.path().to_owned(),
            temp: executor.temp().as_str().to_owned(),
            tool_cache: executor.tool_cache().as_str().to_owned(),
            github,
        })
    }

    fn workspace<'request>(
        &self,
        request: GithubContextRequest<'request>,
    ) -> Result<&'request str, PortError> {
        let profile = request
            .job()
            .job()
            .requirements()
            .environment_profile()
            .ok_or_else(invalid_data)?;
        let root = self
            .workspaces
            .get(profile)
            .map(String::as_str)
            .ok_or_else(invalid_data)?;
        let workspace = request.job().execution().workspace();
        TargetPath::posix(workspace).map_err(|_| invalid_data())?;
        let prefix = format!("{}/", root.trim_end_matches('/'));
        if workspace == root || !workspace.starts_with(&prefix) {
            return Err(invalid_data());
        }
        Ok(workspace)
    }

    fn expression_context(
        &self,
        request: GithubContextRequest<'_>,
        workspace: &str,
        workflow_token: Option<&SecretString>,
    ) -> Result<MapContext, PortError> {
        let mut named = BTreeMap::new();
        named.insert(
            "github".to_owned(),
            github_value(&request, workspace, &self.github, workflow_token)?,
        );
        named.insert("runner".to_owned(), self.runner_value()?);
        named.insert("job".to_owned(), job_value(request.status())?);
        named.insert("steps".to_owned(), steps_value(request)?);
        named.insert("env".to_owned(), env_value(request)?);
        for empty in [
            "event", "inputs", "matrix", "needs", "secrets", "strategy", "vars",
        ] {
            named.insert(empty.to_owned(), object(Vec::new())?);
        }
        MapContext::new(named, request.status(), Arc::new(NoExtensionFunctions))
            .map_err(|_| invalid_data())
    }

    fn runner_value(&self) -> Result<GithubValue, PortError> {
        object(vec![
            string_entry("name", self.runner_id.to_string()),
            string_entry("os", "Linux"),
            string_entry("arch", github_architecture()),
            string_entry("temp", &self.temp),
            string_entry("tool_cache", &self.tool_cache),
            string_entry("debug", "0"),
        ])
    }

    fn standard_environment(
        &self,
        request: GithubContextRequest<'_>,
        workspace: &str,
        results: &automata_protocol::JobRuntimeAuthority,
    ) -> Vec<ContextEnvironmentVariable> {
        let job = request.job();
        let source = job.source();
        let execution = job.execution();
        let mut values = vec![
            plain("CI", "true"),
            plain("GITHUB_ACTIONS", "true"),
            plain("GITHUB_API_URL", self.github.api_url().as_str()),
            plain("GITHUB_EVENT_NAME", source.event_name()),
            plain("GITHUB_EVENT_PATH", request.event_path().as_str()),
            plain("GITHUB_GRAPHQL_URL", self.github.graphql_url().as_str()),
            plain("GITHUB_JOB", job.job().job_id().to_string()),
            plain("GITHUB_REPOSITORY", source.repository()),
            plain("GITHUB_REF", execution.git_ref()),
            plain("GITHUB_RUN_ID", job.job().run_id().to_string()),
            plain("GITHUB_SERVER_URL", self.github.server_url().as_str()),
            plain("GITHUB_SHA", source.revision()),
            plain("GITHUB_WORKFLOW", execution.workflow_name()),
            plain("GITHUB_WORKSPACE", workspace),
            plain("HOME", &self.home),
            plain("PATH", &self.path),
            plain("RUNNER_ARCH", github_architecture()),
            plain("RUNNER_NAME", self.runner_id.to_string()),
            plain("RUNNER_OS", "Linux"),
            plain("RUNNER_TEMP", &self.temp),
            plain("RUNNER_TOOL_CACHE", &self.tool_cache),
        ];
        if let Some(actor) = execution.actor() {
            values.push(plain("GITHUB_ACTOR", actor));
        }
        if let Some(run_number) = execution.run_number() {
            values.push(plain("GITHUB_RUN_NUMBER", run_number.to_string()));
        }
        if let Some(run_attempt) = execution.run_attempt() {
            values.push(plain("GITHUB_RUN_ATTEMPT", run_attempt.to_string()));
        }
        if let Some(step_id) = request.step_id() {
            values.push(plain("GITHUB_ACTION", step_id));
            if let Some(repository) = action_repository(request, step_id) {
                values.push(plain("GITHUB_ACTION_REPOSITORY", repository));
            }
        }
        values.push(plain("ACTIONS_RESULTS_URL", results.endpoint().as_str()));
        values.push(ContextEnvironmentVariable::shared_secret(
            "ACTIONS_RUNTIME_TOKEN",
            results.credential().shared_secret(),
        ));
        values
    }
}

impl GithubContextPort for StandardGithubContext {
    fn snapshot(
        &self,
        request: GithubContextRequest<'_>,
    ) -> Result<GithubContextSnapshot, PortError> {
        let workspace = self.workspace(request)?;
        let workflow_token = self
            .github
            .workflow_token()
            .map(read_secret_string)
            .transpose()?
            .map(Arc::new);
        let results = request
            .runtime_authorities()
            .get(GITHUB_RESULTS_RUNTIME_AUTHORITY)
            .ok_or_else(invalid_data)?;
        results
            .validate_for(request.job(), request.lease())
            .map_err(|_| invalid_data())?;
        let expression =
            Arc::new(self.expression_context(request, workspace, workflow_token.as_deref())?);
        let environment = self.standard_environment(request, workspace, results);
        let masks = workflow_token.into_iter().collect();
        Ok(GithubContextSnapshot::new(expression, environment).with_secret_masks(masks))
    }
}

impl fmt::Debug for StandardGithubContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StandardGithubContext")
            .field("runner_id", &self.runner_id)
            .field("environment_count", &self.workspaces.len())
            .field("runner_root", &self.runner_root)
            .field("github", &self.github)
            .field("context_values", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

fn github_value(
    request: &GithubContextRequest<'_>,
    workspace: &str,
    github: &GithubProductConfig,
    workflow_token: Option<&SecretString>,
) -> Result<GithubValue, PortError> {
    let job = request.job();
    let source = job.source();
    let execution = job.execution();
    let repository_owner = source.repository().split('/').next().unwrap_or_default();
    let workflow_ref = format!(
        "{}/{}@{}",
        source.repository(),
        source.workflow_path(),
        execution.git_ref()
    );
    let mut values = vec![
        string_entry("action", request.step_id().unwrap_or_default()),
        string_entry("action_path", ""),
        string_entry("action_ref", ""),
        string_entry("action_repository", ""),
        string_entry("action_status", status_text(request.status())),
        string_entry("api_url", github.api_url().as_str()),
        string_entry("base_ref", ""),
        string_entry("event_name", source.event_name()),
        string_entry("event_path", request.event_path().as_str()),
        string_entry("graphql_url", github.graphql_url().as_str()),
        string_entry("head_ref", ""),
        string_entry("job", job.job().job_id().to_string()),
        string_entry("ref", execution.git_ref()),
        string_entry("repository", source.repository()),
        string_entry("repository_owner", repository_owner),
        string_entry("run_id", job.job().run_id().to_string()),
        string_entry("server_url", github.server_url().as_str()),
        string_entry("sha", source.revision()),
        string_entry(
            "token",
            workflow_token.map_or("", SecretString::expose_secret),
        ),
        string_entry("workflow", execution.workflow_name()),
        string_entry("workflow_ref", workflow_ref),
        string_entry("workspace", workspace),
    ];
    if let Some((ref_type, ref_name)) = github_ref_parts(execution.git_ref()) {
        values.push(string_entry("ref_name", ref_name));
        values.push(string_entry("ref_type", ref_type));
    }
    if let Some(actor) = execution.actor() {
        values.push(string_entry("actor", actor));
    }
    if let Some(run_number) = execution.run_number() {
        values.push(string_entry("run_number", run_number.to_string()));
    }
    if let Some(run_attempt) = execution.run_attempt() {
        values.push(string_entry("run_attempt", run_attempt.to_string()));
    }
    object(values)
}

fn github_ref_parts(git_ref: &str) -> Option<(&'static str, &str)> {
    git_ref
        .strip_prefix("refs/heads/")
        .map(|name| ("branch", name))
        .or_else(|| git_ref.strip_prefix("refs/tags/").map(|name| ("tag", name)))
}

fn steps_value(request: GithubContextRequest<'_>) -> Result<GithubValue, PortError> {
    let mut steps = Vec::with_capacity(request.steps().len());
    for step in request.steps() {
        let runtime_id = RuntimeStepId::new(step.id()).map_err(|_| invalid_data())?;
        let outputs = request.commands().outputs(&runtime_id).map_or_else(
            || object(Vec::new()),
            |values| {
                object(
                    values
                        .iter()
                        .map(|value| string_entry(value.name(), value.value()))
                        .collect(),
                )
            },
        )?;
        steps.push((
            step.id().to_owned(),
            object(vec![
                string_entry("outcome", conclusion_text(step.outcome())),
                string_entry("conclusion", conclusion_text(step.conclusion())),
                ("outputs".to_owned(), outputs),
            ])?,
        ));
    }
    object(steps)
}

fn env_value(request: GithubContextRequest<'_>) -> Result<GithubValue, PortError> {
    let mut values = BTreeMap::<String, GithubValue>::new();
    for (name, source) in request.job().job().environment() {
        if let ValueSource::Literal(value) = source {
            values.insert(name.clone(), GithubValue::string(value));
        }
    }
    if let Some(step_id) = request.step_id()
        && let Some(step) = request
            .job()
            .job()
            .steps()
            .iter()
            .find(|step| step.id().as_str() == step_id)
    {
        for (name, source) in step.environment() {
            if let ValueSource::Literal(value) = source {
                values.insert(name.clone(), GithubValue::string(value));
            }
        }
    }
    for value in request.commands().environment() {
        values.insert(value.name().to_owned(), GithubValue::string(value.value()));
    }
    object(values.into_iter().collect())
}

fn job_value(status: GithubStatus) -> Result<GithubValue, PortError> {
    object(vec![
        string_entry("status", status_text(status)),
        ("services".to_owned(), object(Vec::new())?),
    ])
}

fn action_repository<'a>(request: GithubContextRequest<'a>, step_id: &str) -> Option<&'a str> {
    let step = request
        .job()
        .job()
        .steps()
        .iter()
        .find(|step| step.id().as_str() == step_id)?;
    match step.kind() {
        SemanticStep::Action {
            reference: automata_core::ActionReference::Repository { repository, .. },
            ..
        } => Some(repository),
        _ => None,
    }
}

fn read_secret_string(source: &SecretSource) -> Result<SecretString, PortError> {
    // Secret files are commonly provisioned as one POSIX text line. Accept
    // exactly one terminal line ending without weakening environment-source
    // semantics or permitting embedded whitespace in bearer credentials.
    let maximum_input_bytes = match source {
        SecretSource::File { .. } => MAX_RUNTIME_TOKEN_BYTES + 2,
        SecretSource::Environment { .. } => MAX_RUNTIME_TOKEN_BYTES,
    };
    let mut bytes = source
        .read(maximum_input_bytes)
        .map_err(|_| PortError::new(PortErrorKind::Unavailable))?;
    if matches!(source, SecretSource::File { .. }) {
        if bytes.ends_with(b"\r\n") {
            let content_length = bytes.len() - 2;
            bytes.truncate(content_length);
        } else if bytes.ends_with(b"\n") {
            let content_length = bytes.len() - 1;
            bytes.truncate(content_length);
        }
    }
    if bytes.is_empty() || bytes.len() > MAX_RUNTIME_TOKEN_BYTES {
        return Err(PortError::new(PortErrorKind::InvalidData));
    }
    let value =
        std::str::from_utf8(&bytes).map_err(|_| PortError::new(PortErrorKind::InvalidData))?;
    if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(PortError::new(PortErrorKind::InvalidData));
    }
    SecretString::new(value.to_owned()).map_err(|_| PortError::new(PortErrorKind::InvalidData))
}

fn object(entries: Vec<(String, GithubValue)>) -> Result<GithubValue, PortError> {
    GithubObject::new(entries)
        .map(GithubValue::object)
        .map_err(|_| invalid_data())
}

fn string_entry(name: impl Into<String>, value: impl Into<String>) -> (String, GithubValue) {
    (name.into(), GithubValue::string(value))
}

fn plain(name: impl Into<String>, value: impl Into<String>) -> ContextEnvironmentVariable {
    ContextEnvironmentVariable::plain(name, value)
}

const fn invalid_data() -> PortError {
    PortError::new(PortErrorKind::InvalidData)
}

const fn status_text(status: GithubStatus) -> &'static str {
    match status {
        GithubStatus::Success => "success",
        GithubStatus::Failure => "failure",
        GithubStatus::Cancelled => "cancelled",
    }
}

const fn conclusion_text(conclusion: JobConclusion) -> &'static str {
    match conclusion {
        JobConclusion::Success => "success",
        JobConclusion::Failure => "failure",
        JobConclusion::Cancelled => "cancelled",
        JobConclusion::TimedOut => "timed_out",
        JobConclusion::Skipped => "skipped",
    }
}

fn github_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "X64",
        "aarch64" => "ARM64",
        _ => "Unknown",
    }
}
