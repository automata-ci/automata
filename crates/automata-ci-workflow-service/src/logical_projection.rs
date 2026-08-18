//! Current-contract projection from activated logical jobs into executable `JobIR`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use automata_ci_actions_permissions::actions_workflow_permission;
use automata_ci_core::{
    ActionReference, Architecture, CompiledBooleanTemplate, CompiledExpressionTemplate,
    CompiledPositiveIntegerTemplate, CompiledValueTemplate, ContainerFeature, ContainerSpec,
    ExpressionProgram, ExpressionSegment, JobAuthorityProfile, JobContentReference,
    JobExecutionContext, JobId, JobIr, JobIrEnvelope, JobOutputDefinition, JobPermissionGrant,
    JobPermissionRequest, JobResourceAllocation, JobResourcePolicy, JobSource, JobValidationError,
    LogicalJobKind, LogicalJobOutputSource, LogicalOutputMergePolicy,
    LogicalServiceContainerTemplate, LogicalStepKind, LogicalStepTemplate, LogicalTimeoutTemplate,
    LogicalTimeoutUnit, MAX_CONTEXT_VALUE_NODES, MAX_CONTEXT_VALUE_TEXT_BYTES, OperatingSystem,
    PermissionLevel, PermissionSnapshotRequest, PlanSourceOrigin, ResourceAllocationError,
    ResourceCapacity, ResourcePolicyError, RunId, RunValueTemplates, RunnerFeature,
    RunnerRequirements, RuntimeBoolean, RuntimePositiveInteger, RuntimeTimeoutTemplate,
    RuntimeTimeoutUnit, SemanticStep, Sha256Digest, ShellTemplate, StepId, StepIr,
    TemplateValueMap, TrustEnvironmentAuthority, TrustPermissionAuthority, TrustSecretAuthority,
    TrustSnapshot, ValueSource, ValueTemplate, ValueTemplateError, ValueTemplateSegment,
    WorkflowId, WorkflowJobKey, WorkflowPermissions,
};
use automata_ci_job_executor_actions::static_shell_requirement;
use automata_ci_protocol::ProtocolLimits;
use automata_ci_store::{ReusableWorkflowPermissionSnapshot, WorkflowPermissionPolicy};
use automata_ci_workflow_actions::{
    GithubConditionCompiler, GithubConditionPhase, GithubRunnerProfileCatalog,
    GithubRunnerProfileMapping,
};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::activation::evaluate_activated_string;
use crate::{
    ActivatedJobInstance, ActivatedJobResources, ActivatedRunnerSelection,
    ActivationEvaluationSite, ActivationStatus, GithubLogicalActivationEvaluator,
    ValidatedLogicalJob,
};

/// Canonical content type for a protobuf-encoded current job runtime context.
pub use automata_ci_core::JOB_RUNTIME_CONTEXT_MEDIA_TYPE;

const MAX_JOB_CONTENT_BYTES: usize = 16_777_216;
const DEFAULT_ACTIONS_JOB_TIMEOUT_SECONDS: u32 = 360 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogicalJobProjectionLimitRejection {
    JobContentBytes,
}

const fn job_content_byte_rejection(observed: usize) -> Option<LogicalJobProjectionLimitRejection> {
    if observed > MAX_JOB_CONTENT_BYTES {
        return Some(LogicalJobProjectionLimitRejection::JobContentBytes);
    }
    None
}

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
    permission_policy: &'a WorkflowPermissionPolicy,
    resource_policy: JobResourcePolicy,
    permission_ceiling: Option<&'a ReusableWorkflowPermissionSnapshot>,
    trust_snapshot: Option<&'a TrustSnapshot>,
    runtime_features: BTreeSet<RunnerFeature>,
    activation_evaluation: Option<(&'a GithubLogicalActivationEvaluator, ActivationStatus)>,
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
        permission_policy: &'a WorkflowPermissionPolicy,
        resource_policy: JobResourcePolicy,
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
            permission_policy,
            resource_policy,
            permission_ceiling: None,
            trust_snapshot: None,
            runtime_features: BTreeSet::new(),
            activation_evaluation: None,
        }
    }

    /// Binds the immutable least-authority ceiling for a sealed reusable child.
    #[must_use]
    pub const fn with_permission_ceiling(
        mut self,
        ceiling: &'a ReusableWorkflowPermissionSnapshot,
    ) -> Self {
        self.permission_ceiling = Some(ceiling);
        self
    }

    /// Binds the digest-verified run-origin trust decision.
    #[must_use]
    pub const fn with_trust_snapshot(mut self, snapshot: &'a TrustSnapshot) -> Self {
        self.trust_snapshot = Some(snapshot);
        self
    }

    /// Adds runtime requirements prepared from immutable repository-action metadata.
    #[must_use]
    pub fn with_runtime_features(
        mut self,
        features: impl IntoIterator<Item = RunnerFeature>,
    ) -> Self {
        self.runtime_features.extend(features);
        self
    }

    /// Binds the evaluator and aggregate status used to resolve instance-known shells.
    #[must_use]
    pub const fn with_activation_evaluation(
        mut self,
        evaluator: &'a GithubLogicalActivationEvaluator,
        status: ActivationStatus,
    ) -> Self {
        self.activation_evaluation = Some((evaluator, status));
        self
    }
}

/// Executable envelope and the exact runtime-context object to publish.
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
    let trust_snapshot = required_trust_snapshot(request.trust_snapshot, request.instance)?;
    let runner = request
        .instance
        .runner()
        .ok_or(LogicalJobProjectionError::MissingActivatedRunner)?;
    let permission_request = resolved_permission_request(
        request
            .job
            .permissions()
            .or_else(|| plan.logical().permissions()),
        request.permission_policy,
        request.permission_ceiling,
        trust_snapshot.authority().permissions(),
    )?;
    let (requirements, selected_profile) = runner_requirements(runner, request.profiles)?;
    let requirements = requirements.with_resource_allocation(resource_allocation(
        request.instance.resources().copied(),
        request.resource_policy,
    )?);
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
    let steps = project_steps(
        step_job.steps(),
        default_shell,
        request.job.key().value(),
        request.instance.runtime_context(),
        request.activation_evaluation,
    )?;
    let requirements = runtime_requirements(requirements, &steps, &request.runtime_features)?;
    let requirements = permission_requirements(requirements, &permission_request);
    let outputs = project_outputs(request.job.outputs())?;
    let services = project_services(step_job.services())?;
    let requirements = service_requirements(requirements, &services);
    validate_profile_runtime_features(selected_profile, requirements.features())?;
    let mut job = JobIr::new(
        request.job_id,
        request.run_id,
        request.instance.name(),
        requirements,
        request.instance.identity().clone(),
        request.instance.continue_on_error(),
        steps,
    )
    .with_trust_snapshot(trust_snapshot.clone())
    .with_authority_profile(request.authority_profile)
    .with_permission_request(permission_request)
    .with_environment(job_environment)
    .with_output_definitions(outputs)
    .with_services(services);
    job = job.with_timeout_seconds(
        request
            .instance
            .timeout_seconds()
            .unwrap_or(DEFAULT_ACTIONS_JOB_TIMEOUT_SECONDS),
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

fn required_trust_snapshot<'a>(
    snapshot: Option<&'a TrustSnapshot>,
    instance: &ActivatedJobInstance,
) -> Result<&'a TrustSnapshot, LogicalJobProjectionError> {
    let snapshot = snapshot.ok_or(LogicalJobProjectionError::MissingTrustSnapshot)?;
    if snapshot.is_construction_placeholder() {
        return Err(LogicalJobProjectionError::MissingTrustSnapshot);
    }
    validate_trust_runtime_authority(snapshot, instance)?;
    Ok(snapshot)
}

fn validate_trust_runtime_authority(
    trust_snapshot: &TrustSnapshot,
    instance: &ActivatedJobInstance,
) -> Result<(), LogicalJobProjectionError> {
    if trust_snapshot.authority().secrets() == TrustSecretAuthority::Denied
        && !instance.runtime_context().secrets().is_empty()
    {
        return Err(LogicalJobProjectionError::TrustDeniedRuntimeSecrets);
    }
    if trust_snapshot.authority().environment() == TrustEnvironmentAuthority::Denied
        && instance.deployment_environment().is_some()
    {
        return Err(LogicalJobProjectionError::TrustDeniedEnvironment);
    }
    Ok(())
}

fn reject_unsupported_semantics(
    job: ValidatedLogicalJob<'_>,
) -> Result<(), LogicalJobProjectionError> {
    for (present, unsupported) in [
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
    permission_policy: &WorkflowPermissionPolicy,
    ceiling: Option<&ReusableWorkflowPermissionSnapshot>,
    trust_authority: TrustPermissionAuthority,
) -> Result<JobPermissionRequest, LogicalJobProjectionError> {
    let mut request = permission_policy.resolve(source_permission_request(request));
    validate_resolved_permission_request(&request)?;
    if let Some(ceiling) = ceiling {
        request = reduce_permission_request(request, ceiling.default_level(), ceiling.grants())?;
        validate_resolved_permission_request(&request)?;
    }
    let request = reduce_permission_request_for_trust(request, trust_authority)?;
    validate_resolved_permission_request(&request)?;
    Ok(request)
}

fn reduce_permission_request_for_trust(
    request: JobPermissionRequest,
    authority: TrustPermissionAuthority,
) -> Result<JobPermissionRequest, LogicalJobProjectionError> {
    match authority {
        TrustPermissionAuthority::Requested => Ok(request),
        TrustPermissionAuthority::DenyAll => Ok(JobPermissionRequest::mapping([])),
        TrustPermissionAuthority::ReadOnly => {
            let JobPermissionRequest::Mapping(grants) = request else {
                return Err(LogicalJobProjectionError::UnrepresentableTrustCeiling);
            };
            Ok(JobPermissionRequest::mapping(
                grants.into_iter().filter_map(|grant| {
                    let permission = actions_workflow_permission(grant.name())?;
                    match grant.level() {
                        PermissionLevel::Read => Some(grant),
                        PermissionLevel::Write if permission.allows_read() => Some(
                            JobPermissionGrant::new(grant.name().to_owned(), PermissionLevel::Read),
                        ),
                        PermissionLevel::None | PermissionLevel::Write => None,
                    }
                }),
            ))
        }
    }
}

fn validate_resolved_permission_request(
    request: &JobPermissionRequest,
) -> Result<(), LogicalJobProjectionError> {
    let JobPermissionRequest::Mapping(grants) = request else {
        return Err(LogicalJobProjectionError::InvalidPermissionRequest);
    };
    for grant in grants {
        let Some(permission) = actions_workflow_permission(grant.name()) else {
            return Err(LogicalJobProjectionError::InvalidPermissionRequest);
        };
        let allowed = match grant.level() {
            PermissionLevel::None => true,
            PermissionLevel::Read => permission.allows_read(),
            PermissionLevel::Write => permission.allows_write(),
        };
        if !allowed {
            return Err(LogicalJobProjectionError::InvalidPermissionRequest);
        }
    }
    Ok(())
}

fn reduce_permission_request(
    request: JobPermissionRequest,
    default_level: PermissionLevel,
    ceiling_grants: &BTreeMap<String, PermissionLevel>,
) -> Result<JobPermissionRequest, LogicalJobProjectionError> {
    match request {
        JobPermissionRequest::Mapping(requested_grants) => Ok(JobPermissionRequest::mapping(
            requested_grants.into_iter().filter_map(|grant| {
                let ceiling = ceiling_grants
                    .get(grant.name())
                    .copied()
                    .unwrap_or(default_level);
                let level = minimum_permission(grant.level(), ceiling);
                (level != PermissionLevel::None)
                    .then(|| JobPermissionGrant::new(grant.name().to_owned(), level))
            }),
        )),
        JobPermissionRequest::ProviderDefault
        | JobPermissionRequest::ReadAll
        | JobPermissionRequest::WriteAll => {
            Err(LogicalJobProjectionError::UnrepresentablePermissionCeiling)
        }
    }
}

fn source_permission_request(request: Option<&PermissionSnapshotRequest>) -> JobPermissionRequest {
    request.map_or(
        JobPermissionRequest::ProviderDefault,
        |request| match request.permissions() {
            WorkflowPermissions::ReadAll(_) => JobPermissionRequest::ReadAll,
            WorkflowPermissions::WriteAll(_) => JobPermissionRequest::WriteAll,
            WorkflowPermissions::Mapping(grants) => {
                JobPermissionRequest::mapping(grants.iter().map(|grant| {
                    JobPermissionGrant::new(grant.name().value().clone(), *grant.level().value())
                }))
            }
        },
    )
}

const fn minimum_permission(left: PermissionLevel, right: PermissionLevel) -> PermissionLevel {
    match (left, right) {
        (PermissionLevel::None, _) | (_, PermissionLevel::None) => PermissionLevel::None,
        (PermissionLevel::Read, _) | (_, PermissionLevel::Read) => PermissionLevel::Read,
        (PermissionLevel::Write, PermissionLevel::Write) => PermissionLevel::Write,
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

fn runtime_requirements(
    requirements: RunnerRequirements,
    steps: &[StepIr],
    prepared: &BTreeSet<RunnerFeature>,
) -> Result<RunnerRequirements, LogicalJobProjectionError> {
    let mut features = requirements.features().clone();
    features.extend(prepared.iter().cloned());
    for step in steps {
        features.insert(RunnerFeature::COMMAND_FILES);
        features.insert(RunnerFeature::JOB_SUMMARIES);
        match step.kind() {
            SemanticStep::Run { values } => {
                features.insert(RunnerFeature::SHELL_STEPS);
                match values.shell() {
                    ShellTemplate::Default => match requirements.operating_system() {
                        Some(OperatingSystem::Windows) => {
                            features.insert(RunnerFeature::DEFAULT_WINDOWS_SHELL);
                        }
                        Some(OperatingSystem::Linux | OperatingSystem::Macos) => {
                            features.insert(RunnerFeature::DEFAULT_POSIX_SHELL);
                        }
                        Some(OperatingSystem::Other(_)) | None => {}
                    },
                    ShellTemplate::Named { value } | ShellTemplate::CommandTemplate { value } => {
                        let literal = literal_value_template(value)
                            .ok_or(LogicalJobProjectionError::InvalidShell)?;
                        features.insert(
                            static_shell_requirement(literal)
                                .map_err(|_| LogicalJobProjectionError::InvalidShell)?,
                        );
                    }
                    ShellTemplate::Dynamic { .. } => {}
                }
            }
            SemanticStep::Action { reference, .. } => match reference {
                ActionReference::Repository { .. } => {
                    features.insert(RunnerFeature::REPOSITORY_ACTIONS);
                }
                ActionReference::Local { .. } => {
                    features.insert(RunnerFeature::LOCAL_ACTIONS);
                }
                ActionReference::Container { .. } => {
                    return Err(LogicalJobProjectionError::Unsupported(
                        UnsupportedLogicalJobSemantics::ContainerAction,
                    ));
                }
            },
        }
    }
    Ok(requirements.with_features(features))
}

fn service_requirements(
    requirements: RunnerRequirements,
    services: &BTreeMap<String, ContainerSpec>,
) -> RunnerRequirements {
    if services.is_empty() {
        return requirements;
    }
    let mut features = requirements.container_features().clone();
    features.insert(ContainerFeature::SERVICE_CONTAINERS);
    requirements.with_container_features(features)
}

fn literal_value_template(value: &ValueTemplate) -> Option<&str> {
    let [segment] = value.segments() else {
        return None;
    };
    segment.literal_value()
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
        && commit_sha != *revision
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
        *revision,
        path,
        plan.event().name(),
    ))
}

fn runner_requirements<'a>(
    runner: &ActivatedRunnerSelection,
    profiles: &'a GithubRunnerProfileCatalog,
) -> Result<(RunnerRequirements, &'a GithubRunnerProfileMapping), LogicalJobProjectionError> {
    let mut mapped: Option<&GithubRunnerProfileMapping> = None;
    for label in runner.labels() {
        let Some(candidate) = profiles.get(label) else {
            continue;
        };
        if mapped.is_some_and(|current| current.selector() != candidate.selector()) {
            return Err(LogicalJobProjectionError::AmbiguousRunnerProfile);
        }
        mapped = Some(candidate);
    }
    let mapped = mapped.ok_or(LogicalJobProjectionError::MissingRunnerProfilePolicy)?;

    let mut requirements = RunnerRequirements::default().with_labels(
        runner
            .labels()
            .iter()
            .filter(|label| mapped.selector() != *label)
            .cloned(),
    );
    if let Some(group) = runner.group() {
        requirements = requirements.with_eligible_groups([group.clone()]);
    }

    let mut operating_system = MergedSelector::Value(mapped.operating_system().clone());
    let mut architecture = MergedSelector::Value(mapped.architecture().clone());
    for label in runner.labels() {
        match label.as_str() {
            "linux" => merge_selector(&mut operating_system, &OperatingSystem::Linux),
            "windows" => merge_selector(&mut operating_system, &OperatingSystem::Windows),
            "macos" => merge_selector(&mut operating_system, &OperatingSystem::Macos),
            "x64" | "x86_64" => merge_selector(&mut architecture, &Architecture::X86_64),
            "arm64" | "aarch64" => merge_selector(&mut architecture, &Architecture::Aarch64),
            _ => {}
        }
    }
    if matches!(operating_system, MergedSelector::Conflict)
        || matches!(architecture, MergedSelector::Conflict)
    {
        return Err(LogicalJobProjectionError::ConflictingRunnerSelectors);
    }
    requirements = requirements
        .with_environment_profile(mapped.environment_profile().clone())
        .with_container_features(mapped.container_features().iter().cloned());
    if let MergedSelector::Value(value) = operating_system {
        requirements = match value {
            OperatingSystem::Windows => requirements.with_windows_hyperv_container(),
            operating_system => requirements.with_operating_system(operating_system),
        };
    }
    if let MergedSelector::Value(value) = architecture {
        requirements = requirements.with_architecture(value);
    }
    Ok((requirements, mapped))
}

fn validate_profile_runtime_features(
    selected: &GithubRunnerProfileMapping,
    required: &BTreeSet<RunnerFeature>,
) -> Result<(), LogicalJobProjectionError> {
    let supported = selected
        .supported_runner_features()
        .ok_or(LogicalJobProjectionError::MissingRunnerFeaturePolicy)?;
    if let Some(feature) = required.difference(supported).next() {
        return Err(LogicalJobProjectionError::UnsupportedRunnerFeature {
            feature: feature.clone(),
        });
    }
    Ok(())
}

fn resource_allocation(
    resources: Option<ActivatedJobResources>,
    policy: JobResourcePolicy,
) -> Result<JobResourceAllocation, LogicalJobProjectionError> {
    let resources = resources.unwrap_or(ActivatedJobResources::empty());
    let requests = resources.requests().unwrap_or_default();
    let limits = resources.limits().unwrap_or_default();
    let defaults = policy.defaults();
    let default_requests = defaults.requests();
    let default_limits = defaults.limits();
    let cpu_request = requests
        .cpu_millis()
        .unwrap_or(default_requests.cpu_millis());
    let cpu_limit = limits.cpu_millis().unwrap_or(default_limits.cpu_millis());
    let memory_request = requests
        .memory_bytes()
        .unwrap_or(default_requests.memory_bytes());
    let memory_limit = limits
        .memory_bytes()
        .unwrap_or(default_limits.memory_bytes());
    let ephemeral_request = requests
        .ephemeral_storage_bytes()
        .unwrap_or(default_requests.ephemeral_disk_bytes());
    let ephemeral_limit = limits
        .ephemeral_storage_bytes()
        .unwrap_or(default_limits.ephemeral_disk_bytes());
    let gpu_request = requests.gpu_count().unwrap_or(default_requests.gpu_count());
    let gpu_limit = limits.gpu_count().unwrap_or(default_limits.gpu_count());
    let allocation = JobResourceAllocation::new(
        ResourceCapacity::new(cpu_request, memory_request, ephemeral_request, gpu_request),
        ResourceCapacity::new(cpu_limit, memory_limit, ephemeral_limit, gpu_limit),
    )
    .map_err(LogicalJobProjectionError::InvalidResourceAllocation)?;
    policy
        .validate_allocation(allocation)
        .map_err(LogicalJobProjectionError::ResourcePolicyViolation)?;
    Ok(allocation)
}

enum MergedSelector<T> {
    Value(T),
    Conflict,
}

fn merge_selector<T: Eq>(slot: &mut MergedSelector<T>, value: &T) {
    match slot {
        MergedSelector::Value(current) if current == value => {}
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
            (bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && bytes[2] == b'\\')
                || workspace == "/__w"
                || workspace.starts_with("/__w/")
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
    job_key: &WorkflowJobKey,
    runtime: &automata_ci_core::JobRuntimeContext,
    activation_evaluation: Option<(&GithubLogicalActivationEvaluator, ActivationStatus)>,
) -> Result<Vec<StepIr>, LogicalJobProjectionError> {
    let ids = step_ids(steps)?;
    steps
        .iter()
        .zip(ids)
        .map(|(step, id)| {
            project_step(
                step,
                id,
                default_shell,
                job_key,
                runtime,
                activation_evaluation,
            )
        })
        .collect()
}

fn project_step(
    step: &LogicalStepTemplate,
    id: StepId,
    default_shell: Option<&automata_ci_core::Located<CompiledValueTemplate>>,
    job_key: &WorkflowJobKey,
    runtime: &automata_ci_core::JobRuntimeContext,
    activation_evaluation: Option<(&GithubLogicalActivationEvaluator, ActivationStatus)>,
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
            let shell = shell_template(
                run.shell().or(default_shell),
                job_key,
                runtime,
                activation_evaluation,
            )?;
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
    job_key: &WorkflowJobKey,
    runtime: &automata_ci_core::JobRuntimeContext,
    activation_evaluation: Option<(&GithubLogicalActivationEvaluator, ActivationStatus)>,
) -> Result<ShellTemplate, LogicalJobProjectionError> {
    let Some(shell) = shell else {
        return Ok(ShellTemplate::default_shell());
    };
    let value = match shell.value() {
        CompiledValueTemplate::Literal(value) => value.clone(),
        CompiledValueTemplate::Expression(expression) => {
            let (evaluator, status) =
                activation_evaluation.ok_or(LogicalJobProjectionError::InvalidShell)?;
            evaluate_activated_string(
                evaluator,
                expression,
                job_key,
                runtime,
                status,
                ActivationEvaluationSite::StepShell,
            )
            .map_err(|_| LogicalJobProjectionError::InvalidShell)?
        }
    };
    literal_shell_template(&value)
}

fn literal_shell_template(value: &str) -> Result<ShellTemplate, LogicalJobProjectionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(LogicalJobProjectionError::InvalidShell);
    }
    let template =
        ValueTemplate::literal(value).map_err(LogicalJobProjectionError::InvalidValueTemplate)?;
    if value.contains("{0}") {
        Ok(ShellTemplate::command_template(template))
    } else {
        Ok(ShellTemplate::named(template))
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

pub(crate) fn logical_action_references(
    job: ValidatedLogicalJob<'_>,
) -> Result<Vec<ActionReference>, LogicalJobProjectionError> {
    let LogicalJobKind::Steps(step_job) = job.execution() else {
        return Err(LogicalJobProjectionError::Unsupported(
            UnsupportedLogicalJobSemantics::ReusableWorkflowJob,
        ));
    };
    step_job
        .steps()
        .iter()
        .filter_map(|step| match step.execution() {
            LogicalStepKind::Run(_) => None,
            LogicalStepKind::Uses(uses) => Some(action_reference(uses.reference().value())),
        })
        .collect()
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
        selector: revision.to_owned(),
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
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn encode_runtime_context(
    context: &automata_ci_core::JobRuntimeContext,
) -> Result<Vec<u8>, LogicalJobProjectionError> {
    let encoded =
        automata_ci_protocol_protobuf::encode_job_runtime_context(context, &projection_limits())
            .map_err(LogicalJobProjectionError::RuntimeContextEncoding)?;
    if job_content_byte_rejection(encoded.len()).is_some() {
        return Err(LogicalJobProjectionError::RuntimeContextTooLarge);
    }
    Ok(encoded)
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
    /// The logical job invokes a reusable workflow instead of executing steps.
    ReusableWorkflowJob,
    /// A job output is sourced from a reusable-workflow result.
    ReusableWorkflowOutput,
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
            Self::ReusableWorkflowJob => "reusable workflow job",
            Self::ReusableWorkflowOutput => "reusable workflow output",
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
    /// Projection was attempted without the run-bound authenticated trust decision.
    #[error("logical job projection requires a run-bound trust snapshot")]
    MissingTrustSnapshot,
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
    /// More than one activated selector maps to an exact environment profile.
    #[error("runner profile selector is ambiguous")]
    AmbiguousRunnerProfile,
    /// No activated selector named an immutable repository-pinned profile.
    #[error("runner selection has no immutable runtime profile policy")]
    MissingRunnerProfilePolicy,
    /// A historical selected profile predates the current feature-policy contract.
    #[error("selected runner profile has no current runner-feature policy")]
    MissingRunnerFeaturePolicy,
    /// Immutable source requirements exceed the selected profile's declared support.
    #[error("selected runner profile does not support source-required feature {feature}")]
    UnsupportedRunnerFeature {
        /// Canonical, non-secret feature identity derived from immutable source semantics.
        feature: RunnerFeature,
    },
    /// Generic labels select mutually incompatible platforms.
    #[error("runner selectors require conflicting platforms")]
    ConflictingRunnerSelectors,
    /// Resolved requests and limits violate the provider-neutral allocation contract.
    #[error("job resource allocation is invalid")]
    InvalidResourceAllocation(#[source] ResourceAllocationError),
    /// A resolved allocation falls outside the pinned repository bounds.
    #[error("job resource allocation violates pinned repository policy")]
    ResourcePolicyViolation(#[source] ResourcePolicyError),
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
    /// Run-origin trust denied normal secrets but runtime context retained them.
    #[error("run-origin trust denies runtime secret bindings")]
    TrustDeniedRuntimeSecrets,
    /// Run-origin trust denied protected-environment admission.
    #[error("run-origin trust denies deployment environments")]
    TrustDeniedEnvironment,
    /// The resolved request contains an unknown permission or unsupported level.
    #[error("resolved GitHub permission request is outside the pinned catalog")]
    InvalidPermissionRequest,
    /// A reusable permission ceiling cannot be encoded without broadening authority.
    #[error("reusable workflow permission ceiling is not representable")]
    UnrepresentablePermissionCeiling,
    /// The run-origin trust permission ceiling cannot be represented exactly.
    #[error("run-origin trust permission ceiling is not representable")]
    UnrepresentableTrustCeiling,
    /// Canonical runtime-context protobuf encoding failed.
    #[error("canonical runtime-context encoding failed")]
    RuntimeContextEncoding(#[source] automata_ci_protocol_protobuf::EncodeError),
    /// Canonical runtime-context bytes exceed the job-content ceiling.
    #[error("canonical runtime-context exceeds the job-content limit")]
    RuntimeContextTooLarge,
    /// The projected current `JobIR` violates a domain invariant.
    #[error("projected current JobIR is invalid")]
    InvalidJobIr(#[source] JobValidationError),
}

#[cfg(test)]
mod limit_contract_tests {
    use super::{
        LogicalJobProjectionLimitRejection, MAX_JOB_CONTENT_BYTES, job_content_byte_rejection,
    };

    #[test]
    fn job_content_byte_limit_has_exact_boundaries() {
        assert_eq!(job_content_byte_rejection(MAX_JOB_CONTENT_BYTES - 1), None);
        assert_eq!(job_content_byte_rejection(MAX_JOB_CONTENT_BYTES), None);
        assert_eq!(
            job_content_byte_rejection(MAX_JOB_CONTENT_BYTES + 1),
            Some(LogicalJobProjectionLimitRejection::JobContentBytes)
        );
    }
}

#[cfg(test)]
mod resource_policy_tests {
    use automata_ci_core::{
        JobResourceAllocation, JobResourcePolicy, ResourceAllocationError, ResourceCapacity,
    };

    use super::*;
    use crate::ActivatedResourceVector;

    #[test]
    fn pinned_policy_supplies_omitted_allocation() {
        let policy = resource_policy();
        assert_eq!(
            resource_allocation(None, policy).expect("allocation"),
            policy.defaults()
        );
    }

    #[test]
    fn distinct_gpu_request_and_limit_fail_closed() {
        let resources = ActivatedJobResources::new(
            Some(ActivatedResourceVector::new(
                Some(500),
                Some(512 * 1_024 * 1_024),
                None,
                Some(1),
            )),
            Some(ActivatedResourceVector::new(
                Some(1_000),
                Some(1_024 * 1_024 * 1_024),
                None,
                Some(2),
            )),
        );
        assert!(matches!(
            resource_allocation(Some(resources), resource_policy()),
            Err(LogicalJobProjectionError::InvalidResourceAllocation(
                ResourceAllocationError::GpuRequestLimitMismatch
            ))
        ));
    }

    fn resource_policy() -> JobResourcePolicy {
        let defaults = JobResourceAllocation::new(
            ResourceCapacity::new(500, 512 * 1_024 * 1_024, 0, 0),
            ResourceCapacity::new(2_000, 2 * 1_024 * 1_024 * 1_024, 0, 0),
        )
        .expect("defaults");
        JobResourcePolicy::new(
            defaults,
            ResourceCapacity::new(100, 128 * 1_024 * 1_024, 0, 0),
            ResourceCapacity::new(8_000, 16 * 1_024 * 1_024 * 1_024, 0, 2),
        )
        .expect("policy")
    }
}

#[cfg(test)]
mod permission_ceiling_tests {
    use super::*;

    #[test]
    fn repository_policy_resolves_all_permission_shorthands_to_exact_mappings() {
        let policy = WorkflowPermissionPolicy::from_github_default(
            automata_ci_actions_permissions::ActionsDefaultWorkflowPermission::Read,
        )
        .expect("permission policy");
        assert_eq!(
            resolved_permission_request(None, &policy, None, TrustPermissionAuthority::Requested,)
                .expect("provider default"),
            JobPermissionRequest::mapping([
                JobPermissionGrant::new("contents", PermissionLevel::Read),
                JobPermissionGrant::new("packages", PermissionLevel::Read),
            ]),
        );
        let write_all = policy.resolve(JobPermissionRequest::WriteAll);
        assert_eq!(
            write_all.requested_level("contents"),
            Some(PermissionLevel::Write)
        );
        assert_eq!(
            write_all.requested_level("id-token"),
            Some(PermissionLevel::Write)
        );
        assert_eq!(
            write_all.requested_level("vulnerability-alerts"),
            Some(PermissionLevel::Read)
        );
        let ceiling = BTreeMap::from([
            ("contents".to_owned(), PermissionLevel::Read),
            ("id-token".to_owned(), PermissionLevel::None),
        ]);
        assert_eq!(
            reduce_permission_request(write_all, PermissionLevel::None, &ceiling,)
                .expect("resolved shorthand ceiling"),
            JobPermissionRequest::mapping([JobPermissionGrant::new(
                "contents",
                PermissionLevel::Read,
            )]),
        );
    }

    #[test]
    fn explicit_permissions_are_intersected_without_adding_scopes() {
        let ceiling = BTreeMap::from([("contents".to_owned(), PermissionLevel::Read)]);
        let requested = JobPermissionRequest::mapping([
            JobPermissionGrant::new("contents", PermissionLevel::Write),
            JobPermissionGrant::new("packages", PermissionLevel::Read),
        ]);
        assert_eq!(
            reduce_permission_request(requested, PermissionLevel::None, &ceiling)
                .expect("mapping intersection"),
            JobPermissionRequest::mapping([JobPermissionGrant::new(
                "contents",
                PermissionLevel::Read,
            )]),
        );
    }

    #[test]
    fn forged_permission_requests_fail_closed_at_projection() {
        for request in [
            JobPermissionRequest::mapping([JobPermissionGrant::new(
                "future-permission",
                PermissionLevel::Read,
            )]),
            JobPermissionRequest::mapping([JobPermissionGrant::new(
                "id-token",
                PermissionLevel::Read,
            )]),
            JobPermissionRequest::mapping([JobPermissionGrant::new(
                "vulnerability-alerts",
                PermissionLevel::Write,
            )]),
        ] {
            assert!(matches!(
                validate_resolved_permission_request(&request),
                Err(LogicalJobProjectionError::InvalidPermissionRequest)
            ));
        }
        validate_resolved_permission_request(&JobPermissionRequest::mapping([
            JobPermissionGrant::new("contents", PermissionLevel::None),
            JobPermissionGrant::new("id-token", PermissionLevel::Write),
            JobPermissionGrant::new("vulnerability-alerts", PermissionLevel::Read),
        ]))
        .expect("catalog-valid explicit mapping");
    }
}
