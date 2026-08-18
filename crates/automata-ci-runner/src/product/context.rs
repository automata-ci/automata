use std::{collections::BTreeMap, fmt, sync::Arc};

use automata_ci_core::{
    Architecture, ContextValue, JobAuthorityProfile, JobConclusion, NeedContext, OperatingSystem,
    PermissionLevel, RunnerId, RunnerPlatform, SemanticStep, StrategyContext, TrustOidcAuthority,
    TrustPermissionAuthority, TrustResultsAuthority, TrustSecretAuthority, ValueSource,
};
use automata_ci_execution::{TargetPath, TargetPlatform};
use automata_ci_expression_actions::{
    GithubObject, GithubStatus, GithubValue, MapContext, NoExtensionFunctions,
};
use automata_ci_github_runtime::StepId as RuntimeStepId;
use automata_ci_job_executor_github::{
    ContextEnvironmentVariable, GithubContextPort, GithubContextRequest, GithubContextSnapshot,
    PortError, PortErrorKind,
};
use automata_ci_protocol::{JobRuntimeAuthority, RuntimeAuthorityEndpointSecurity};

use super::{ExecutorProductConfig, GithubProductConfig};

const GITHUB_RESULTS_RUNTIME_AUTHORITY: &str = "github-actions-results";
const GITHUB_REPOSITORY_RUNTIME_AUTHORITY: &str = "github-repository";
const GITHUB_OIDC_RUNTIME_AUTHORITY: &str = "github-oidc";
const GITHUB_ID_TOKEN_PERMISSION: &str = "id-token";
const GITHUB_OIDC_TOKEN_PATH: &str = "/oidc/token";
const GITHUB_OIDC_API_VERSION_QUERY: &str = "api-version=2.0";

/// Standard platform-aware GitHub context and default-environment authority.
///
/// Values are derived only from immutable `JobIR`, durable command state, and
/// explicit product configuration. Event payloads and job-scoped credentials
/// are not invented when the orchestrator did not supply them. Results and
/// repository authorities come only from the exact protected lease offer; the
/// repository token must also target the configured GitHub origin and its
/// exact production-TLS or explicit loopback-development trust class.
pub struct StandardGithubContext {
    runner_id: RunnerId,
    workspaces: BTreeMap<automata_ci_core::EnvironmentProfile, TargetPath>,
    platform: TargetPlatform,
    runner_platform: RunnerPlatform,
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
        runner_platform: RunnerPlatform,
        environments: &BTreeMap<
            automata_ci_core::EnvironmentProfile,
            automata_ci_execution::SandboxEnvironment,
        >,
        executor: &ExecutorProductConfig,
        github: GithubProductConfig,
    ) -> Result<Self, PortError> {
        if environments.is_empty() {
            return Err(invalid_data());
        }
        let workspaces: BTreeMap<_, _> = environments
            .iter()
            .map(|(profile, environment)| (profile.clone(), environment.workspace().clone()))
            .collect();
        let platform = workspaces
            .values()
            .next()
            .map(TargetPath::platform)
            .ok_or_else(invalid_data)?;
        if workspaces
            .values()
            .any(|workspace| workspace.platform() != platform)
            || executor.runner_root().platform() != platform
            || executor.home().platform() != platform
            || executor.temp().platform() != platform
            || executor.tool_cache().platform() != platform
        {
            return Err(invalid_data());
        }
        let expected_target_platform = match runner_platform.operating_system() {
            OperatingSystem::Linux | OperatingSystem::Macos => TargetPlatform::Posix,
            OperatingSystem::Windows => TargetPlatform::Windows,
            OperatingSystem::Other(_) => return Err(invalid_data()),
        };
        if platform != expected_target_platform {
            return Err(invalid_data());
        }
        Ok(Self {
            runner_id,
            workspaces,
            platform,
            runner_platform,
            runner_root: executor.runner_root().as_str().to_owned(),
            home: executor.home().as_str().to_owned(),
            path: executor.path().to_owned(),
            temp: executor.temp().as_str().to_owned(),
            tool_cache: executor.tool_cache().as_str().to_owned(),
            github,
        })
    }

    fn workspace(&self, request: GithubContextRequest<'_>) -> Result<String, PortError> {
        let profile = request
            .job()
            .job()
            .requirements()
            .environment_profile()
            .ok_or_else(invalid_data)?;
        let root = self.workspaces.get(profile).ok_or_else(invalid_data)?;
        let workspace = request.job().execution().workspace();
        match (self.runner_platform.operating_system(), self.platform) {
            (OperatingSystem::Linux, TargetPlatform::Posix) => {
                TargetPath::posix(workspace).map_err(|_| invalid_data())?;
                let prefix = format!("{}/", root.as_str().trim_end_matches('/'));
                if workspace == root.as_str() || !workspace.starts_with(&prefix) {
                    return Err(invalid_data());
                }
                Ok(workspace.to_owned())
            }
            (OperatingSystem::Macos, TargetPlatform::Posix) => {
                TargetPath::posix(workspace).map_err(|_| invalid_data())?;
                let suffix = workspace.strip_prefix("/__w/").ok_or_else(invalid_data)?;
                let mapped = format!("{}/{suffix}", root.as_str().trim_end_matches('/'));
                TargetPath::posix(mapped.clone()).map_err(|_| invalid_data())?;
                Ok(mapped)
            }
            (OperatingSystem::Windows, TargetPlatform::Windows) => {
                TargetPath::posix(workspace).map_err(|_| invalid_data())?;
                let suffix = workspace.strip_prefix("/__w/").ok_or_else(invalid_data)?;
                let mut mapped = root.as_str().trim_end_matches('\\').to_owned();
                mapped.push('\\');
                mapped.push_str(&suffix.replace('/', "\\"));
                TargetPath::windows(mapped.clone()).map_err(|_| invalid_data())?;
                Ok(mapped)
            }
            _ => Err(invalid_data()),
        }
    }

    fn expression_context(
        &self,
        request: GithubContextRequest<'_>,
        workspace: &str,
        repository: Option<&JobRuntimeAuthority>,
    ) -> Result<MapContext, PortError> {
        let mut named = BTreeMap::new();
        named.insert(
            "github".to_owned(),
            github_value(&request, workspace, &self.github, repository)?,
        );
        named.insert("event".to_owned(), request.event().clone());
        named.insert("runner".to_owned(), self.runner_value()?);
        named.insert(
            "job".to_owned(),
            job_value(request.status(), request.services())?,
        );
        named.insert("steps".to_owned(), steps_value(request)?);
        named.insert("env".to_owned(), env_value(request)?);
        let runtime = request.runtime_context();
        named.insert("inputs".to_owned(), context_value(runtime.inputs())?);
        named.insert("vars".to_owned(), context_value(runtime.vars())?);
        named.insert("matrix".to_owned(), context_value(runtime.matrix())?);
        named.insert("strategy".to_owned(), strategy_value(runtime.strategy())?);
        named.insert("needs".to_owned(), needs_value(runtime.needs())?);
        // Secret bindings remain opaque locators on `runtime_context()`. They
        // must never be exposed as ordinary expression strings. The one
        // exception is GitHub's built-in GITHUB_TOKEN alias, which is backed
        // by the same exact-fence repository authority as `github.token`.
        let secrets = repository.map_or_else(Vec::new, |authority| {
            vec![sensitive_string_entry(
                "GITHUB_TOKEN",
                authority.credential().expose_secret(),
            )]
        });
        named.insert("secrets".to_owned(), object(secrets)?);
        MapContext::new(named, request.status(), Arc::new(NoExtensionFunctions))
            .map_err(|_| invalid_data())
    }

    fn repository_authority<'request>(
        &self,
        request: GithubContextRequest<'request>,
    ) -> Result<Option<&'request JobRuntimeAuthority>, PortError> {
        let Some(authority) = request
            .runtime_authorities()
            .get(GITHUB_REPOSITORY_RUNTIME_AUTHORITY)
        else {
            return Ok(None);
        };
        authority
            .validate_for(request.job(), request.lease())
            .map_err(|_| invalid_data())?;
        if request
            .job()
            .job()
            .trust_snapshot()
            .authority()
            .permissions()
            == TrustPermissionAuthority::DenyAll
        {
            return Err(invalid_data());
        }
        let expected_security = if self.github.allow_insecure_http()
            && self
                .github
                .server_url()
                .host_str()
                .is_some_and(|host| host.to_ascii_lowercase().ends_with(".invalid"))
        {
            RuntimeAuthorityEndpointSecurity::TrustedPrivateDevelopment
        } else if self.github.allow_insecure_http() {
            RuntimeAuthorityEndpointSecurity::LoopbackDevelopment
        } else {
            RuntimeAuthorityEndpointSecurity::Tls
        };
        if request.job().source().provider() != "github"
            || authority.endpoint().security() != expected_security
            || authority.endpoint().as_url() != self.github.server_url()
        {
            return Err(invalid_data());
        }
        Ok(Some(authority))
    }

    fn oidc_authority(
        request: GithubContextRequest<'_>,
    ) -> Result<Option<&JobRuntimeAuthority>, PortError> {
        let Some(authority) = request
            .runtime_authorities()
            .get(GITHUB_OIDC_RUNTIME_AUTHORITY)
        else {
            return Ok(None);
        };
        authority
            .validate_for(request.job(), request.lease())
            .map_err(|_| invalid_data())?;
        if request.job().source().provider() != "github"
            || request.job().job().trust_snapshot().authority().oidc()
                != TrustOidcAuthority::Eligible
            || request
                .job()
                .job()
                .permission_request()
                .requested_level(GITHUB_ID_TOKEN_PERMISSION)
                != Some(PermissionLevel::Write)
            || authority.endpoint().security() != RuntimeAuthorityEndpointSecurity::Tls
        {
            return Err(invalid_data());
        }
        Ok(Some(authority))
    }

    fn runner_value(&self) -> Result<GithubValue, PortError> {
        object(vec![
            string_entry("name", self.runner_id.to_string()),
            string_entry("os", self.runner_os()),
            string_entry(
                "arch",
                github_architecture(self.runner_platform.architecture()),
            ),
            string_entry("environment", "self-hosted"),
            string_entry("temp", &self.temp),
            string_entry("tool_cache", &self.tool_cache),
            string_entry("debug", "0"),
        ])
    }

    fn standard_environment(
        &self,
        request: GithubContextRequest<'_>,
        workspace: &str,
        results: Option<&automata_ci_protocol::JobRuntimeAuthority>,
        oidc: Option<&automata_ci_protocol::JobRuntimeAuthority>,
    ) -> Vec<ContextEnvironmentVariable> {
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
            plain("CI", "true"),
            plain("GITHUB_ACTIONS", "true"),
            plain("GITHUB_API_URL", self.github.api_url().as_str()),
            plain("GITHUB_EVENT_NAME", source.event_name()),
            plain("GITHUB_EVENT_PATH", request.event_path().as_str()),
            plain("GITHUB_GRAPHQL_URL", self.github.graphql_url().as_str()),
            plain("GITHUB_JOB", job.job().job_id().to_string()),
            plain("GITHUB_REPOSITORY", source.repository()),
            plain("GITHUB_REPOSITORY_OWNER", repository_owner),
            plain("GITHUB_REF", execution.git_ref()),
            plain("GITHUB_SERVER_URL", self.github.server_url().as_str()),
            plain("GITHUB_SHA", source.revision().to_string()),
            plain("GITHUB_WORKFLOW", execution.workflow_name()),
            plain("GITHUB_WORKFLOW_REF", workflow_ref),
            plain("GITHUB_WORKFLOW_SHA", source.revision().to_string()),
            plain("GITHUB_WORKSPACE", workspace),
            plain("HOME", &self.home),
            plain("PATH", &self.path),
            plain(
                "RUNNER_ARCH",
                github_architecture(self.runner_platform.architecture()),
            ),
            plain("RUNNER_ENVIRONMENT", "self-hosted"),
            plain("RUNNER_NAME", self.runner_id.to_string()),
            plain("RUNNER_OS", self.runner_os()),
            plain("RUNNER_TEMP", &self.temp),
            plain("RUNNER_TOOL_CACHE", &self.tool_cache),
        ];
        if let Some((ref_type, ref_name)) = github_ref_parts(execution.git_ref()) {
            values.push(plain("GITHUB_REF_NAME", ref_name));
            values.push(plain("GITHUB_REF_TYPE", ref_type));
        }
        if let Some(head_ref) = event_path_string(request.event(), &["pull_request", "head", "ref"])
        {
            values.push(plain("GITHUB_HEAD_REF", head_ref));
        }
        if let Some(base_ref) = event_path_string(request.event(), &["pull_request", "base", "ref"])
        {
            values.push(plain("GITHUB_BASE_REF", base_ref));
        }
        if let Some(actor) = execution.actor() {
            values.push(plain("GITHUB_ACTOR", actor));
        }
        if let Some(run_id_alias) = execution.run_id_alias() {
            values.push(plain("GITHUB_RUN_ID", run_id_alias.to_string()));
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
        if let Some(results) = results {
            values.push(plain("ACTIONS_RESULTS_URL", results.endpoint().as_str()));
            values.push(plain("ACTIONS_CACHE_SERVICE_V2", "true"));
            values.push(ContextEnvironmentVariable::shared_secret(
                "ACTIONS_RUNTIME_TOKEN",
                results.credential().shared_secret(),
            ));
        }
        if let Some(oidc) = oidc {
            let mut request_url = oidc.endpoint().as_url().clone();
            request_url.set_path(GITHUB_OIDC_TOKEN_PATH);
            request_url.set_query(Some(GITHUB_OIDC_API_VERSION_QUERY));
            values.push(plain("ACTIONS_ID_TOKEN_REQUEST_URL", request_url.as_str()));
            values.push(ContextEnvironmentVariable::shared_secret(
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                oidc.credential().shared_secret(),
            ));
        }
        values
    }

    const fn runner_os(&self) -> &'static str {
        match self.runner_platform.operating_system() {
            OperatingSystem::Linux => "Linux",
            OperatingSystem::Windows => "Windows",
            OperatingSystem::Macos => "macOS",
            OperatingSystem::Other(_) => "Unknown",
        }
    }
}

impl GithubContextPort for StandardGithubContext {
    fn snapshot(
        &self,
        request: GithubContextRequest<'_>,
    ) -> Result<GithubContextSnapshot, PortError> {
        let workspace = self.workspace(request)?;
        let trust = request.job().job().trust_snapshot();
        if trust.is_construction_placeholder()
            || (trust.authority().secrets() == TrustSecretAuthority::Denied
                && !request.runtime_context().secrets().is_empty())
        {
            return Err(invalid_data());
        }
        let (results, repository, oidc) = match request.job().job().authority_profile() {
            JobAuthorityProfile::Standard => {
                let results = request
                    .runtime_authorities()
                    .get(GITHUB_RESULTS_RUNTIME_AUTHORITY);
                let results = match (trust.authority().results(), results) {
                    (TrustResultsAuthority::Denied, None) => None,
                    (
                        TrustResultsAuthority::Standard | TrustResultsAuthority::Untrusted,
                        Some(results),
                    ) => {
                        results
                            .validate_for(request.job(), request.lease())
                            .map_err(|_| invalid_data())?;
                        Some(results)
                    }
                    _ => return Err(invalid_data()),
                };
                (
                    results,
                    self.repository_authority(request)?,
                    Self::oidc_authority(request)?,
                )
            }
            JobAuthorityProfile::CredentialFree => {
                if !request.runtime_authorities().as_slice().is_empty()
                    || !request.runtime_context().secrets().is_empty()
                {
                    return Err(invalid_data());
                }
                (None, None, None)
            }
        };
        let expression = Arc::new(self.expression_context(request, &workspace, repository)?);
        let environment = self.standard_environment(request, &workspace, results, oidc);
        let secret_masks = repository
            .map(|authority| vec![authority.credential().shared_secret()])
            .unwrap_or_default();
        Ok(GithubContextSnapshot::new(expression, environment).with_secret_masks(secret_masks))
    }
}

impl fmt::Debug for StandardGithubContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StandardGithubContext")
            .field("runner_id", &self.runner_id)
            .field("environment_count", &self.workspaces.len())
            .field("runner_platform", &self.runner_platform)
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
    repository: Option<&JobRuntimeAuthority>,
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
        string_entry(
            "base_ref",
            event_path_string(request.event(), &["pull_request", "base", "ref"])
                .unwrap_or_default(),
        ),
        string_entry("event_name", source.event_name()),
        string_entry("event_path", request.event_path().as_str()),
        ("event".to_owned(), request.event().clone()),
        string_entry("graphql_url", github.graphql_url().as_str()),
        string_entry(
            "head_ref",
            event_path_string(request.event(), &["pull_request", "head", "ref"])
                .unwrap_or_default(),
        ),
        string_entry("job", job.job().job_id().to_string()),
        string_entry("ref", execution.git_ref()),
        string_entry("repository", source.repository()),
        string_entry("repository_owner", repository_owner),
        string_entry("server_url", github.server_url().as_str()),
        string_entry("sha", source.revision().to_string()),
        repository.map_or_else(
            || string_entry("token", ""),
            |authority| sensitive_string_entry("token", authority.credential().expose_secret()),
        ),
        string_entry("workflow", execution.workflow_name()),
        string_entry("workflow_ref", workflow_ref),
        string_entry("workflow_sha", source.revision().to_string()),
        string_entry("workspace", workspace),
    ];
    if let Some((ref_type, ref_name)) = github_ref_parts(execution.git_ref()) {
        values.push(string_entry("ref_name", ref_name));
        values.push(string_entry("ref_type", ref_type));
    }
    if let Some(actor) = execution.actor() {
        values.push(string_entry("actor", actor));
    }
    if let Some(run_id_alias) = execution.run_id_alias() {
        values.push(string_entry("run_id", run_id_alias.to_string()));
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

fn event_path_string<'a>(event: &'a GithubValue, path: &[&str]) -> Option<&'a str> {
    let mut value = event;
    for segment in path {
        let GithubValue::Object(object) = value else {
            return None;
        };
        value = object.get(segment)?;
    }
    value.as_str()
}

fn context_value(value: &ContextValue) -> Result<GithubValue, PortError> {
    match value {
        ContextValue::Null => Ok(GithubValue::Null),
        ContextValue::Boolean { value } => Ok(GithubValue::Boolean(*value)),
        ContextValue::Number { ieee754_bits } => {
            Ok(GithubValue::number(f64::from_bits(*ieee754_bits)))
        }
        ContextValue::String { value } => Ok(GithubValue::string(value)),
        ContextValue::Array { values } => GithubValue::array(
            values
                .iter()
                .map(context_value)
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(|_| invalid_data()),
        ContextValue::Object { values } => object(
            values
                .iter()
                .map(|(key, value)| context_value(value).map(|value| (key.clone(), value)))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    }
}

fn strategy_value(strategy: StrategyContext) -> Result<GithubValue, PortError> {
    object(vec![
        (
            "fail-fast".to_owned(),
            GithubValue::Boolean(strategy.fail_fast()),
        ),
        (
            "job-index".to_owned(),
            GithubValue::number(f64::from(strategy.job_index())),
        ),
        (
            "job-total".to_owned(),
            GithubValue::number(f64::from(strategy.job_total())),
        ),
        (
            "max-parallel".to_owned(),
            GithubValue::number(f64::from(strategy.max_parallel())),
        ),
    ])
}

fn needs_value(needs: &BTreeMap<String, NeedContext>) -> Result<GithubValue, PortError> {
    object(
        needs
            .iter()
            .map(|(job, need)| {
                let outputs = object(
                    need.outputs()
                        .iter()
                        .filter_map(|(name, output)| {
                            output.public_value().map(|value| string_entry(name, value))
                        })
                        .collect(),
                )?;
                let result = match need.result() {
                    JobConclusion::Success => "success",
                    JobConclusion::Failure | JobConclusion::TimedOut => "failure",
                    JobConclusion::Cancelled => "cancelled",
                    JobConclusion::Skipped => "skipped",
                };
                object(vec![
                    string_entry("result", result),
                    ("outputs".to_owned(), outputs),
                ])
                .map(|value| (job.clone(), value))
            })
            .collect::<Result<Vec<_>, _>>()?,
    )
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

fn job_value(
    status: GithubStatus,
    services: Option<&automata_ci_execution::ServiceContainerBindings>,
) -> Result<GithubValue, PortError> {
    object(vec![
        string_entry("status", status_text(status)),
        ("services".to_owned(), services_value(services)?),
    ])
}

fn services_value(
    services: Option<&automata_ci_execution::ServiceContainerBindings>,
) -> Result<GithubValue, PortError> {
    let Some(services) = services else {
        return object(Vec::new());
    };
    object(
        services
            .iter()
            .map(|(name, service)| {
                let ports = object(
                    service
                        .ports()
                        .iter()
                        .map(|binding| {
                            string_entry(
                                binding.service_port().container_port().to_string(),
                                binding.host_port().to_string(),
                            )
                        })
                        .collect(),
                )?;
                Ok((
                    name.to_owned(),
                    object(vec![
                        string_entry("id", service.container().opaque()),
                        string_entry("network", service.network().expose()),
                        ("ports".to_owned(), ports),
                    ])?,
                ))
            })
            .collect::<Result<Vec<_>, PortError>>()?,
    )
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
            reference: automata_ci_core::ActionReference::Repository { repository, .. },
            ..
        } => Some(repository),
        _ => None,
    }
}

fn object(entries: Vec<(String, GithubValue)>) -> Result<GithubValue, PortError> {
    GithubObject::new(entries)
        .map(GithubValue::object)
        .map_err(|_| invalid_data())
}

fn string_entry(name: impl Into<String>, value: impl Into<String>) -> (String, GithubValue) {
    (name.into(), GithubValue::string(value))
}

fn sensitive_string_entry(
    name: impl Into<String>,
    value: impl Into<String>,
) -> (String, GithubValue) {
    (name.into(), GithubValue::sensitive_string(value))
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
        GithubStatus::Skipped => "skipped",
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

const fn github_architecture(architecture: &Architecture) -> &'static str {
    match architecture {
        Architecture::X86_64 => "X64",
        Architecture::Aarch64 => "ARM64",
        Architecture::Other(_) => "Unknown",
    }
}
