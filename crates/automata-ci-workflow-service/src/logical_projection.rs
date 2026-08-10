//! Current-contract projection from activated logical jobs into executable `JobIR`.

use std::{collections::BTreeMap, fmt};

use automata_ci_core::{
    ActionReference, Architecture, CompiledBooleanTemplate, CompiledExpressionTemplate,
    CompiledPositiveIntegerTemplate, CompiledValueTemplate, ContainerSpec, ExpressionProgram,
    ExpressionSegment, JobAuthorityProfile, JobContentReference, JobExecutionContext, JobId, JobIr,
    JobIrEnvelope, JobOutputDefinition, JobPermissionGrant, JobPermissionRequest, JobSource,
    JobValidationError, LogicalJobKind, LogicalJobOutputSource, LogicalOutputMergePolicy,
    LogicalServiceContainerTemplate, LogicalStepKind, LogicalStepTemplate, LogicalTimeoutTemplate,
    LogicalTimeoutUnit, MAX_CONTEXT_VALUE_NODES, MAX_CONTEXT_VALUE_TEXT_BYTES, OperatingSystem,
    PermissionLevel, PermissionSnapshotRequest, PlanSourceOrigin, RunId, RunValueTemplates,
    RunnerFeature, RunnerRequirements, RuntimeBoolean, RuntimePositiveInteger,
    RuntimeTimeoutTemplate, RuntimeTimeoutUnit, SemanticStep, Sha256Digest, ShellTemplate, StepId,
    StepIr, TemplateValueMap, ValueSource, ValueTemplate, ValueTemplateError, ValueTemplateSegment,
    WorkflowId, WorkflowPermissions,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_workflow_github::{
    GithubConditionCompiler, GithubConditionPhase, GithubRunnerProfileCatalog,
};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{ActivatedJobInstance, ActivatedRunnerSelection, ValidatedLogicalJob};

/// Canonical content type for a protobuf-encoded current job runtime context.
pub const JOB_RUNTIME_CONTEXT_MEDIA_TYPE: &str =
    "application/vnd.automata.job-runtime-context.protobuf";

const MAX_JOB_CONTENT_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_GITHUB_JOB_TIMEOUT_SECONDS: u32 = 360 * 60;

/// Borrowed immutable inputs for one GitHub logical-job projection.
pub struct ProjectGithubLogicalJobRequest<'a> {
    job: ValidatedLogicalJob<'a>,
    instance: &'a ActivatedJobInstance,
    workflow_id: WorkflowId,
    run_id: RunId,
    job_id: JobId,
    execution: JobExecutionContext,
    profiles: &'a GithubRunnerProfileCatalog,
    authority_profile: JobAuthorityProfile,
}

impl fmt::Debug for ProjectGithubLogicalJobRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectGithubLogicalJobRequest")
            .field("logical_job", self.job.key().value())
            .field("workflow_id", &self.workflow_id)
            .field("run_id", &self.run_id)
            .field("job_id", &self.job_id)
            .field("execution", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl<'a> ProjectGithubLogicalJobRequest<'a> {
    /// Binds a validated logical job and activated instance to exact execution identities.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        job: ValidatedLogicalJob<'a>,
        instance: &'a ActivatedJobInstance,
        workflow_id: WorkflowId,
        run_id: RunId,
        job_id: JobId,
        execution: JobExecutionContext,
        profiles: &'a GithubRunnerProfileCatalog,
        authority_profile: JobAuthorityProfile,
    ) -> Self {
        Self {
            job,
            instance,
            workflow_id,
            run_id,
            job_id,
            execution,
            profiles,
            authority_profile,
        }
    }
}

/// Executable v5 envelope and the exact runtime-context object to publish.
pub struct ProjectedGithubLogicalJob {
    envelope: JobIrEnvelope,
    runtime_context: automata_ci_core::JobRuntimeContext,
    runtime_context_bytes: Bytes,
}

impl ProjectedGithubLogicalJob {
    /// Returns the validated current `JobIR` envelope.
    #[must_use]
    pub const fn envelope(&self) -> &JobIrEnvelope {
        &self.envelope
    }

    /// Returns the runtime context referenced by the envelope.
    #[must_use]
    pub const fn runtime_context(&self) -> &automata_ci_core::JobRuntimeContext {
        &self.runtime_context
    }

    /// Returns the canonical protobuf encoding of the runtime context.
    #[must_use]
    pub const fn runtime_context_bytes(&self) -> &Bytes {
        &self.runtime_context_bytes
    }

    /// Splits the projection into its envelope, runtime context, and canonical bytes.
    #[must_use]
    pub fn into_parts(self) -> (JobIrEnvelope, automata_ci_core::JobRuntimeContext, Bytes) {
        (
            self.envelope,
            self.runtime_context,
            self.runtime_context_bytes,
        )
    }
}

impl fmt::Debug for ProjectedGithubLogicalJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectedGithubLogicalJob")
            .field("job_id", &self.envelope.job().job_id())
            .field("schema_version", &self.envelope.schema_version())
            .field("runtime_context_bytes", &self.runtime_context_bytes.len())
            .field("runtime_context", &"[REDACTED]")
            .finish()
    }
}

/// Pure GitHub provider adapter for an already activated logical step job.
#[derive(Clone, Copy, Debug, Default)]
pub struct GithubLogicalJobProjector;

impl GithubLogicalJobProjector {
    /// Creates the stateless current-contract GitHub projector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Projects one activated logical job without performing I/O.
    ///
    /// # Errors
    ///
    /// Rejects provenance/context mismatches, unsupported authorization or
    /// orchestration semantics, malformed actions/selectors/templates, an
    /// inexact runtime-context content reference, or invalid current `JobIR`.
    pub fn project(
        &self,
        request: ProjectGithubLogicalJobRequest<'_>,
    ) -> Result<ProjectedGithubLogicalJob, LogicalJobProjectionError> {
        project_github_logical_job(request)
    }
}

fn project_github_logical_job(
    request: ProjectGithubLogicalJobRequest<'_>,
) -> Result<ProjectedGithubLogicalJob, LogicalJobProjectionError> {
    let plan = request.job.plan();
    reject_unsupported_semantics(request.job)?;
    validate_plan_execution(plan, &request.execution)?;
    if request.instance.identity().logical_job_key() != request.job.key().value().as_str() {
        return Err(LogicalJobProjectionError::InstanceJobMismatch);
    }

    let LogicalJobKind::Steps(step_job) = request.job.execution() else {
        unreachable!("unsupported reusable jobs were rejected above");
    };
    let runner = request
        .instance
        .runner()
        .ok_or(LogicalJobProjectionError::MissingActivatedRunner)?;
    let permission_request = resolved_permission_request(
        request
            .job
            .permissions()
            .or_else(|| plan.logical().permissions()),
    );
    let requirements = permission_requirements(
        runner_requirements(runner, request.profiles)?,
        &permission_request,
    );
    validate_workspace_platform(&requirements, request.execution.workspace())?;

    let runtime_context = request.instance.runtime_context().clone();
    if request.authority_profile == JobAuthorityProfile::CredentialFree
        && !runtime_context.secrets().is_empty()
    {
        return Err(LogicalJobProjectionError::CredentialFreeRuntimeSecrets);
    }
    let runtime_context_bytes = encode_runtime_context(&runtime_context)?;
    validate_runtime_context_reference(
        request.execution.runtime_context(),
        &runtime_context_bytes,
    )?;

    let mut job_environment = value_map(plan.logical().environment())?;
    overlay_value_map(&mut job_environment, request.job.environment())?;
    let default_shell = request
        .job
        .run_defaults()
        .shell()
        .or_else(|| plan.logical().run_defaults().shell());
    let default_directory = request
        .job
        .run_defaults()
        .working_directory()
        .or_else(|| plan.logical().run_defaults().working_directory());
    let steps = project_steps(step_job.steps(), default_shell)?;
    let outputs = project_outputs(request.job.outputs())?;
    let services = project_services(step_job.services())?;
    let mut job = JobIr::new(
        request.job_id,
        request.run_id,
        request.instance.name(),
        requirements,
        request.instance.identity().clone(),
        request.instance.continue_on_error(),
        steps,
    )
    .with_authority_profile(request.authority_profile)
    .with_permission_request(permission_request)
    .with_environment(job_environment)
    .with_output_definitions(outputs)
    .with_services(services);
    job = job.with_timeout_seconds(
        request
            .instance
            .timeout_seconds()
            .unwrap_or(DEFAULT_GITHUB_JOB_TIMEOUT_SECONDS),
    );
    if let Some(directory) = default_directory {
        job = job.with_working_directory(value_template(directory.value())?);
    }

    let source = github_job_source(plan)?;
    let envelope = JobIrEnvelope::new(request.workflow_id, source, request.execution, job);
    envelope
        .validate()
        .map_err(LogicalJobProjectionError::InvalidJobIr)?;
    Ok(ProjectedGithubLogicalJob {
        envelope,
        runtime_context,
        runtime_context_bytes: Bytes::from(runtime_context_bytes),
    })
}

fn reject_unsupported_semantics(
    job: ValidatedLogicalJob<'_>,
) -> Result<(), LogicalJobProjectionError> {
    let plan = job.plan();
    for (present, unsupported) in [
        (
            plan.logical().invocation().is_some(),
            UnsupportedLogicalJobSemantics::ReusableWorkflowInvocation,
        ),
        (
            plan.logical().concurrency().is_some(),
            UnsupportedLogicalJobSemantics::WorkflowConcurrency,
        ),
        (
            job.concurrency().is_some(),
            UnsupportedLogicalJobSemantics::JobConcurrency,
        ),
        (
            job.deployment().is_some(),
            UnsupportedLogicalJobSemantics::Deployment,
        ),
        (
            matches!(job.execution(), LogicalJobKind::ReusableWorkflow(_)),
            UnsupportedLogicalJobSemantics::ReusableWorkflowJob,
        ),
    ] {
        if present {
            return Err(LogicalJobProjectionError::Unsupported(unsupported));
        }
    }
    Ok(())
}

fn resolved_permission_request(
    request: Option<&PermissionSnapshotRequest>,
) -> JobPermissionRequest {
    let Some(request) = request else {
        return JobPermissionRequest::ProviderDefault;
    };
    match request.permissions() {
        WorkflowPermissions::ReadAll(_) => JobPermissionRequest::ReadAll,
        WorkflowPermissions::WriteAll(_) => JobPermissionRequest::WriteAll,
        WorkflowPermissions::Mapping(grants) => {
            JobPermissionRequest::mapping(grants.iter().map(|grant| {
                JobPermissionGrant::new(grant.name().value().clone(), *grant.level().value())
            }))
        }
    }
}

fn permission_requirements(
    requirements: RunnerRequirements,
    permission_request: &JobPermissionRequest,
) -> RunnerRequirements {
    if permission_request.requested_level("id-token") != Some(PermissionLevel::Write) {
        return requirements;
    }
    let mut features = requirements.features().clone();
    features.insert(RunnerFeature::OIDC_TOKENS);
    requirements.with_features(features)
}

fn validate_plan_execution(
    plan: &automata_ci_core::WorkflowPlan,
    execution: &JobExecutionContext,
) -> Result<(), LogicalJobProjectionError> {
    if plan.source().provider() != "github" || plan.event().provider() != "github" {
        return Err(LogicalJobProjectionError::ProviderMismatch);
    }
    if let Some(name) = plan.name()
        && name.value() != execution.workflow_name()
    {
        return Err(LogicalJobProjectionError::ExecutionProvenanceMismatch);
    }
    if let Some(git_ref) = plan.event().git_ref()
        && git_ref != execution.git_ref()
    {
        return Err(LogicalJobProjectionError::ExecutionProvenanceMismatch);
    }
    let PlanSourceOrigin::Repository { revision, .. } = plan.source().origin() else {
        return Err(LogicalJobProjectionError::NonRepositorySource);
    };
    if let Some(commit_sha) = plan.event().commit_sha()
        && commit_sha != revision
    {
        return Err(LogicalJobProjectionError::ExecutionProvenanceMismatch);
    }
    Ok(())
}

fn github_job_source(
    plan: &automata_ci_core::WorkflowPlan,
) -> Result<JobSource, LogicalJobProjectionError> {
    let PlanSourceOrigin::Repository {
        repository,
        revision,
        path,
    } = plan.source().origin()
    else {
        return Err(LogicalJobProjectionError::NonRepositorySource);
    };
    Ok(JobSource::new(
        "github",
        repository,
        revision,
        path,
        plan.event().name(),
    ))
}

fn runner_requirements(
    runner: &ActivatedRunnerSelection,
    profiles: &GithubRunnerProfileCatalog,
) -> Result<RunnerRequirements, LogicalJobProjectionError> {
    let mapped = runner
        .labels()
        .iter()
        .filter_map(|label| profiles.get(label))
        .collect::<Vec<_>>();
    if let Some(mapping) = mapped.first() {
        if mapped.len() != 1 || runner.labels().len() != 1 || runner.group().is_some() {
            return Err(LogicalJobProjectionError::AmbiguousHostedProfile);
        }
        return Ok(RunnerRequirements::default()
            .with_environment_profile(mapping.environment_profile().clone())
            .with_operating_system(mapping.operating_system().clone())
            .with_architecture(mapping.architecture().clone())
            .with_container_features(mapping.container_features().iter().cloned()));
    }

    let mut operating_system = MergedSelector::Unset;
    let mut architecture = MergedSelector::Unset;
    for label in runner.labels() {
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
        return Err(LogicalJobProjectionError::ConflictingRunnerSelectors);
    }
    let mut requirements =
        RunnerRequirements::default().with_labels(runner.labels().iter().cloned());
    if let Some(group) = runner.group() {
        requirements = requirements.with_eligible_groups([group.clone()]);
    }
    if let MergedSelector::Value(value) = operating_system {
        requirements = requirements.with_operating_system(value);
    }
    if let MergedSelector::Value(value) = architecture {
        requirements = requirements.with_architecture(value);
    }
    Ok(requirements)
}

enum MergedSelector<T> {
    Unset,
    Value(T),
    Conflict,
}

fn merge_selector<T: Eq>(slot: &mut MergedSelector<T>, value: T) {
    match slot {
        MergedSelector::Unset => *slot = MergedSelector::Value(value),
        MergedSelector::Value(current) if current == &value => {}
        MergedSelector::Value(_) | MergedSelector::Conflict => {
            *slot = MergedSelector::Conflict;
        }
    }
}

fn validate_workspace_platform(
    requirements: &RunnerRequirements,
    workspace: &str,
) -> Result<(), LogicalJobProjectionError> {
    let compatible = match requirements.operating_system() {
        Some(OperatingSystem::Windows) => {
            let bytes = workspace.as_bytes();
            bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && bytes[2] == b'\\'
        }
        Some(OperatingSystem::Linux | OperatingSystem::Macos) => workspace.starts_with('/'),
        Some(OperatingSystem::Other(_)) | None => true,
    };
    if compatible {
        Ok(())
    } else {
        Err(LogicalJobProjectionError::WorkspacePlatformMismatch)
    }
}

fn project_steps(
    steps: &[LogicalStepTemplate],
    default_shell: Option<&automata_ci_core::Located<CompiledValueTemplate>>,
) -> Result<Vec<StepIr>, LogicalJobProjectionError> {
    let ids = step_ids(steps)?;
    steps
        .iter()
        .zip(ids)
        .map(|(step, id)| project_step(step, id, default_shell))
        .collect()
}

fn project_step(
    step: &LogicalStepTemplate,
    id: StepId,
    default_shell: Option<&automata_ci_core::Located<CompiledValueTemplate>>,
) -> Result<StepIr, LogicalJobProjectionError> {
    let name = match step.name() {
        Some(name) => value_template(name.value())?,
        None => ValueTemplate::literal(step.key().value().as_str())
            .map_err(LogicalJobProjectionError::InvalidValueTemplate)?,
    };
    let continue_on_error = runtime_boolean(
        step.continue_on_error()
            .map(automata_ci_core::Located::value),
    )?;
    let kind = match step.execution() {
        LogicalStepKind::Run(run) => {
            let command = value_template(run.script().value())?;
            let shell = shell_template(run.shell().or(default_shell))?;
            let mut values = RunValueTemplates::new(command, shell);
            if let Some(directory) = run.working_directory() {
                values = values.with_working_directory(value_template(directory.value())?);
            }
            SemanticStep::run(values)
        }
        LogicalStepKind::Uses(uses) => SemanticStep::action(
            action_reference(uses.reference().value())?,
            value_map(uses.inputs())?,
        ),
    };
    let mut projected = StepIr::new(id, name, continue_on_error, kind)
        .with_environment(value_map(step.environment())?);
    let condition = match step.condition() {
        Some(condition) => single_program(condition.value(), "step condition")?.clone(),
        None => GithubConditionCompiler::default()
            .compile_condition(None, GithubConditionPhase::Step)
            .map_err(|_| LogicalJobProjectionError::InvalidDefaultStepCondition)?,
    };
    projected = projected.with_condition(condition);
    if let Some(timeout) = step.timeout() {
        projected = projected.with_timeout(runtime_timeout(timeout.value())?);
    }
    Ok(projected)
}

fn step_ids(steps: &[LogicalStepTemplate]) -> Result<Vec<StepId>, LogicalJobProjectionError> {
    let mut allocated = std::collections::BTreeSet::new();
    let mut projected = Vec::with_capacity(steps.len());
    for step in steps {
        if let Some(explicit) = step.id() {
            let id = StepId::new(explicit.value().clone())
                .map_err(LogicalJobProjectionError::InvalidJobIr)?;
            if !allocated.insert(id.clone()) {
                return Err(LogicalJobProjectionError::DuplicateStepId);
            }
            projected.push(id);
            continue;
        }
        let position = step
            .key()
            .value()
            .as_str()
            .strip_prefix("position/")
            .ok_or(LogicalJobProjectionError::InvalidAnonymousStepKey)?;
        let base = format!("github_p_{position}");
        let id = (0_u32..)
            .find_map(|suffix| {
                let candidate = if suffix == 0 {
                    base.clone()
                } else {
                    format!("{base}_{suffix}")
                };
                StepId::new(candidate)
                    .ok()
                    .filter(|candidate| allocated.insert(candidate.clone()))
            })
            .ok_or(LogicalJobProjectionError::InvalidAnonymousStepKey)?;
        projected.push(id);
    }
    Ok(projected)
}

fn value_map(
    values: &TemplateValueMap,
) -> Result<BTreeMap<String, ValueSource>, LogicalJobProjectionError> {
    let mut projected = BTreeMap::new();
    overlay_value_map(&mut projected, values)?;
    Ok(projected)
}

fn overlay_value_map(
    destination: &mut BTreeMap<String, ValueSource>,
    layer: &TemplateValueMap,
) -> Result<(), LogicalJobProjectionError> {
    for (key, value) in layer.entries() {
        let source = match value.value() {
            CompiledValueTemplate::Literal(value) => ValueSource::Literal(value.clone()),
            CompiledValueTemplate::Expression(_) => {
                ValueSource::Template(value_template(value.value())?)
            }
        };
        destination.insert(key.value().clone(), source);
    }
    Ok(())
}

fn value_template(
    template: &CompiledValueTemplate,
) -> Result<ValueTemplate, LogicalJobProjectionError> {
    match template {
        CompiledValueTemplate::Literal(value) => {
            ValueTemplate::literal(value).map_err(LogicalJobProjectionError::InvalidValueTemplate)
        }
        CompiledValueTemplate::Expression(expression) => expression_value_template(expression),
    }
}

fn expression_value_template(
    expression: &CompiledExpressionTemplate,
) -> Result<ValueTemplate, LogicalJobProjectionError> {
    let mut programs = expression.programs().iter();
    let mut segments = Vec::with_capacity(expression.expression().segments().len());
    for segment in expression.expression().segments() {
        match segment {
            ExpressionSegment::Literal(value) if value.is_empty() => {}
            ExpressionSegment::Literal(value) => {
                segments.push(ValueTemplateSegment::literal(value.clone()));
            }
            ExpressionSegment::Evaluation(_) => {
                let program = programs
                    .next()
                    .ok_or(LogicalJobProjectionError::TemplateProgramCountMismatch)?;
                segments.push(ValueTemplateSegment::expression(program.clone()));
            }
        }
    }
    if programs.next().is_some() {
        return Err(LogicalJobProjectionError::TemplateProgramCountMismatch);
    }
    ValueTemplate::new(segments).map_err(LogicalJobProjectionError::InvalidValueTemplate)
}

fn runtime_boolean(
    value: Option<&CompiledBooleanTemplate>,
) -> Result<RuntimeBoolean, LogicalJobProjectionError> {
    match value {
        None => Ok(RuntimeBoolean::literal(false)),
        Some(CompiledBooleanTemplate::Literal(value)) => Ok(RuntimeBoolean::literal(*value)),
        Some(CompiledBooleanTemplate::Expression(expression)) => Ok(RuntimeBoolean::expression(
            single_program(expression, "step continue-on-error")?.clone(),
        )),
    }
}

fn runtime_timeout(
    timeout: &LogicalTimeoutTemplate,
) -> Result<RuntimeTimeoutTemplate, LogicalJobProjectionError> {
    let value = match timeout.value() {
        CompiledPositiveIntegerTemplate::Literal(value) => RuntimePositiveInteger::literal(*value),
        CompiledPositiveIntegerTemplate::Expression(expression) => {
            RuntimePositiveInteger::expression(single_program(expression, "step timeout")?.clone())
        }
    };
    Ok(RuntimeTimeoutTemplate::new(
        value,
        match timeout.unit() {
            LogicalTimeoutUnit::Seconds => RuntimeTimeoutUnit::Seconds,
            LogicalTimeoutUnit::Minutes => RuntimeTimeoutUnit::Minutes,
        },
    ))
}

fn shell_template(
    shell: Option<&automata_ci_core::Located<CompiledValueTemplate>>,
) -> Result<ShellTemplate, LogicalJobProjectionError> {
    let Some(shell) = shell else {
        return Ok(ShellTemplate::default_shell());
    };
    match shell.value() {
        CompiledValueTemplate::Literal(value) => {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(LogicalJobProjectionError::InvalidShell);
            }
            let template = ValueTemplate::literal(value)
                .map_err(LogicalJobProjectionError::InvalidValueTemplate)?;
            if value.contains("{0}") {
                Ok(ShellTemplate::command_template(template))
            } else {
                Ok(ShellTemplate::named(template))
            }
        }
        CompiledValueTemplate::Expression(_) => {
            Ok(ShellTemplate::dynamic(value_template(shell.value())?))
        }
    }
}

fn project_outputs(
    outputs: &[automata_ci_core::LogicalJobOutputDefinition],
) -> Result<Vec<JobOutputDefinition>, LogicalJobProjectionError> {
    outputs
        .iter()
        .map(|output| {
            let LogicalJobOutputSource::Template(value) = output.source() else {
                return Err(LogicalJobProjectionError::Unsupported(
                    UnsupportedLogicalJobSemantics::ReusableWorkflowOutput,
                ));
            };
            if output.merge() != LogicalOutputMergePolicy::SingleInstance
                && output.merge() != LogicalOutputMergePolicy::LastSuccessfulCompletion
            {
                return Err(LogicalJobProjectionError::Unsupported(
                    UnsupportedLogicalJobSemantics::OutputMerge,
                ));
            }
            JobOutputDefinition::new(
                output.key().value().as_str(),
                value_template(value.value())?,
                output.sensitivity(),
            )
            .map_err(LogicalJobProjectionError::InvalidJobIr)
        })
        .collect()
}

fn project_services(
    services: &[LogicalServiceContainerTemplate],
) -> Result<BTreeMap<String, ContainerSpec>, LogicalJobProjectionError> {
    services
        .iter()
        .map(|service| {
            if !valid_immutable_service_image(service.image().value()) {
                return Err(LogicalJobProjectionError::InvalidServiceContainer);
            }
            let spec = ContainerSpec::new(service.image().value().clone())
                .with_environment(value_map(service.environment())?)
                .with_ports(service.ports().iter().map(|port| *port.value()))
                .with_options(
                    service
                        .options()
                        .iter()
                        .map(|option| option.value().clone()),
                );
            Ok((service.key().value().as_str().to_owned(), spec))
        })
        .collect()
}

fn valid_immutable_service_image(value: &str) -> bool {
    value.len() <= 512
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_whitespace())
        && value
            .rsplit_once("@sha256:")
            .is_some_and(|(repository, digest)| {
                !repository.is_empty()
                    && !repository.contains('@')
                    && repository.contains('/')
                    && repository
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"./:_-".contains(&byte))
                    && digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
}

fn single_program<'a>(
    expression: &'a CompiledExpressionTemplate,
    _field: &'static str,
) -> Result<&'a ExpressionProgram, LogicalJobProjectionError> {
    let [program] = expression.programs() else {
        return Err(LogicalJobProjectionError::ExpectedSingleProgram);
    };
    Ok(program)
}

fn action_reference(source: &str) -> Result<ActionReference, LogicalJobProjectionError> {
    if source.contains("${{") {
        return Err(LogicalJobProjectionError::InvalidActionReference);
    }
    if let Some(image) = source.strip_prefix("docker://") {
        if image.is_empty()
            || source.len() > 4_096
            || source.chars().any(char::is_control)
            || source.chars().any(char::is_whitespace)
        {
            return Err(LogicalJobProjectionError::InvalidActionReference);
        }
        return Err(LogicalJobProjectionError::Unsupported(
            UnsupportedLogicalJobSemantics::ContainerAction,
        ));
    }
    if source.starts_with("./") {
        validate_local_action(source)?;
        return Ok(ActionReference::Local {
            path: source.to_owned(),
        });
    }
    let (path, revision) = source
        .split_once('@')
        .ok_or(LogicalJobProjectionError::InvalidActionReference)?;
    if source.matches('@').count() != 1 || !valid_action_revision(revision) {
        return Err(LogicalJobProjectionError::InvalidActionReference);
    }
    let components = path.split('/').collect::<Vec<_>>();
    if components.len() < 2
        || !valid_repository_component(components[0])
        || !valid_repository_component(components[1])
        || components[2..]
            .iter()
            .any(|component| !valid_action_component(component))
    {
        return Err(LogicalJobProjectionError::InvalidActionReference);
    }
    Ok(ActionReference::Repository {
        repository: format!("{}/{}", components[0], components[1]),
        revision: revision.to_owned(),
        subpath: (components.len() > 2).then(|| components[2..].join("/")),
    })
}

fn validate_local_action(source: &str) -> Result<(), LogicalJobProjectionError> {
    let relative = source
        .strip_prefix("./")
        .ok_or(LogicalJobProjectionError::InvalidActionReference)?;
    if relative.is_empty()
        || source.len() > 4_096
        || source.ends_with('/')
        || source.contains('\\')
        || source.chars().any(char::is_control)
        || relative
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(LogicalJobProjectionError::InvalidActionReference);
    }
    Ok(())
}

fn valid_repository_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_action_component(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

fn valid_action_revision(value: &str) -> bool {
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

fn encode_runtime_context(
    context: &automata_ci_core::JobRuntimeContext,
) -> Result<Vec<u8>, LogicalJobProjectionError> {
    automata_ci_protocol_protobuf::encode_job_runtime_context(context, &projection_limits())
        .map_err(LogicalJobProjectionError::RuntimeContextEncoding)
}

fn projection_limits() -> ProtocolLimits {
    ProtocolLimits::new(
        MAX_JOB_CONTENT_BYTES,
        MAX_CONTEXT_VALUE_NODES,
        MAX_CONTEXT_VALUE_TEXT_BYTES,
        1,
        1,
    )
    .expect("projection limits are statically coherent")
}

fn validate_runtime_context_reference(
    reference: &JobContentReference,
    encoded: &[u8],
) -> Result<(), LogicalJobProjectionError> {
    let size = u64::try_from(encoded.len())
        .map_err(|_| LogicalJobProjectionError::RuntimeContextReferenceMismatch)?;
    let digest = Sha256Digest::from_bytes(Sha256::digest(encoded).into());
    if reference.media_type() != JOB_RUNTIME_CONTEXT_MEDIA_TYPE
        || reference.encoded_size() != size
        || reference.digest() != digest
    {
        return Err(LogicalJobProjectionError::RuntimeContextReferenceMismatch);
    }
    Ok(())
}

/// Logical semantics deliberately rejected instead of being erased from `JobIR`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedLogicalJobSemantics {
    /// The workflow delegates its invocation to another workflow.
    ReusableWorkflowInvocation,
    /// The logical job invokes a reusable workflow instead of executing steps.
    ReusableWorkflowJob,
    /// A job output is sourced from a reusable-workflow result.
    ReusableWorkflowOutput,
    /// Workflow-level concurrency semantics are present.
    WorkflowConcurrency,
    /// Job-level concurrency semantics are present.
    JobConcurrency,
    /// Deployment-environment semantics are present.
    Deployment,
    /// A step directly executes a container action.
    ContainerAction,
    /// A logical output requests an unsupported multi-instance merge policy.
    OutputMerge,
}

impl fmt::Display for UnsupportedLogicalJobSemantics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ReusableWorkflowInvocation => "reusable workflow invocation contract",
            Self::ReusableWorkflowJob => "reusable workflow job",
            Self::ReusableWorkflowOutput => "reusable workflow output",
            Self::WorkflowConcurrency => "workflow concurrency",
            Self::JobConcurrency => "job concurrency",
            Self::Deployment => "deployment environment",
            Self::ContainerAction => "container action",
            Self::OutputMerge => "logical output merge policy",
        })
    }
}

/// Sanitized fail-closed projection error.
#[derive(Debug, Error)]
pub enum LogicalJobProjectionError {
    /// The logical job carries semantics that current `JobIR` cannot preserve.
    #[error("logical job contains unsupported semantics: {0}")]
    Unsupported(UnsupportedLogicalJobSemantics),
    /// Source or event provenance belongs to a provider other than GitHub.
    #[error("GitHub projection requires GitHub source and event provenance")]
    ProviderMismatch,
    /// The plan source does not identify an immutable repository revision.
    #[error("GitHub projection requires immutable repository source provenance")]
    NonRepositorySource,
    /// Execution metadata disagrees with immutable plan provenance.
    #[error("execution metadata does not match immutable workflow provenance")]
    ExecutionProvenanceMismatch,
    /// The activated instance identifies another logical job.
    #[error("activated instance does not belong to the selected logical job")]
    InstanceJobMismatch,
    /// A step job reached projection without an activated runner selection.
    #[error("activated step job has no resolved runner selectors")]
    MissingActivatedRunner,
    /// Hosted-profile selectors do not resolve to one exact profile.
    #[error("hosted runner profile selector is ambiguous")]
    AmbiguousHostedProfile,
    /// Generic labels select mutually incompatible platforms.
    #[error("runner selectors require conflicting platforms")]
    ConflictingRunnerSelectors,
    /// The server-selected workspace is invalid for the selected platform.
    #[error("workspace path grammar does not match the selected runner platform")]
    WorkspacePlatformMismatch,
    /// Template literal segments and compiled programs do not correspond.
    #[error("logical template program count does not match its expression segments")]
    TemplateProgramCountMismatch,
    /// A scalar logical expression contains other than one compiled program.
    #[error("logical scalar requires exactly one compiled expression program")]
    ExpectedSingleProgram,
    /// A logical value cannot be represented as a current runtime template.
    #[error("logical value template is invalid")]
    InvalidValueTemplate(#[source] ValueTemplateError),
    /// The implicit GitHub step condition could not be compiled.
    #[error("default GitHub step condition could not be compiled")]
    InvalidDefaultStepCondition,
    /// Explicit or generated step identities collide.
    #[error("step ID is duplicated after deterministic allocation")]
    DuplicateStepId,
    /// An anonymous step lacks the canonical source-position key needed for allocation.
    #[error("anonymous step key cannot be deterministically projected")]
    InvalidAnonymousStepKey,
    /// An action reference is malformed, mutable where disallowed, or unsafe.
    #[error("action reference is invalid")]
    InvalidActionReference,
    /// A shell selector or command template is malformed.
    #[error("shell template is invalid")]
    InvalidShell,
    /// A service container lacks an immutable safe image or valid settings.
    #[error("logical service-container definition is invalid")]
    InvalidServiceContainer,
    /// The execution reference does not authenticate the canonical context bytes.
    #[error("runtime-context content reference does not match canonical bytes")]
    RuntimeContextReferenceMismatch,
    /// Credential-free projection retained a managed-secret binding.
    #[error("credential-free projection cannot retain runtime secret bindings")]
    CredentialFreeRuntimeSecrets,
    /// Canonical runtime-context protobuf encoding failed.
    #[error("canonical runtime-context encoding failed")]
    RuntimeContextEncoding(#[source] automata_ci_protocol_protobuf::EncodeError),
    /// The projected current `JobIR` violates a domain invariant.
    #[error("projected current JobIR is invalid")]
    InvalidJobIr(#[source] JobValidationError),
}
