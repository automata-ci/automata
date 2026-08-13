//! Logical-workflow logical workflow and job templates.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Deserializer, Serialize};

use crate::ContainerPort;

use super::{
    CompiledBooleanTemplate, CompiledExpressionTemplate, CompiledPositiveIntegerTemplate,
    CompiledValueTemplate, ExpressionContext, Located, OutputSensitivity, PlanEvaluationPhase,
    PlanSourceSpan, QueuePolicy, WorkflowInputKey, WorkflowInvocationContract, WorkflowJobKey,
    WorkflowOutputKey, WorkflowPermissions, WorkflowPlanError, WorkflowSecretKey,
    WorkflowServiceKey, WorkflowStepKey, WorkflowStrategyTemplate, source::validate_span_source,
    validation::LogicalPlanBudget,
};

/// Maximum logical jobs in one logical-workflow workflow plan.
pub const MAX_LOGICAL_JOBS: usize = 1_024;
/// Maximum direct prerequisite jobs for one logical job.
pub const MAX_LOGICAL_JOB_NEEDS: usize = 128;
/// Maximum declared result references consumed by one logical job.
pub const MAX_LOGICAL_RESULT_REFERENCES: usize = 512;
/// Maximum outputs declared by one logical job.
pub const MAX_LOGICAL_JOB_OUTPUTS: usize = 256;
/// Maximum step templates in one logical job.
pub const MAX_LOGICAL_STEPS: usize = 2_048;
/// Maximum service containers attached to one logical job.
pub const MAX_LOGICAL_SERVICES: usize = 64;
/// Maximum exposed ports on one logical service container.
pub const MAX_LOGICAL_SERVICE_PORTS: usize = 256;
/// Maximum parsed engine-option tokens retained for one logical service.
pub const MAX_LOGICAL_SERVICE_OPTIONS: usize = 64;
/// Maximum entries in one environment/input layer.
pub const MAX_TEMPLATE_MAP_ENTRIES: usize = 512;
/// Maximum runner labels in one logical job.
pub const MAX_LOGICAL_RUNNER_LABELS: usize = 64;
/// Maximum input/secret bindings on one reusable invocation.
pub const MAX_REUSABLE_BINDINGS: usize = 256;
/// Maximum bytes in a logical-plan name, key, reference, or description.
pub const MAX_LOGICAL_FIELD_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LogicalWorkflowLimitRejection {
    Jobs,
    JobNeeds,
    ResultReferences,
    JobOutputs,
    Steps,
    Services,
    ServicePorts,
    ServiceOptions,
    TemplateMapEntries,
    RunnerLabels,
    ReusableBindings,
    FieldBytes,
}

pub(super) const fn logical_job_count_rejection(
    observed: usize,
) -> Option<LogicalWorkflowLimitRejection> {
    if observed > MAX_LOGICAL_JOBS {
        return Some(LogicalWorkflowLimitRejection::Jobs);
    }
    None
}
pub(super) const fn logical_job_need_count_rejection(
    observed: usize,
) -> Option<LogicalWorkflowLimitRejection> {
    if observed > MAX_LOGICAL_JOB_NEEDS {
        return Some(LogicalWorkflowLimitRejection::JobNeeds);
    }
    None
}
pub(super) const fn logical_result_reference_count_rejection(
    observed: usize,
) -> Option<LogicalWorkflowLimitRejection> {
    if observed > MAX_LOGICAL_RESULT_REFERENCES {
        return Some(LogicalWorkflowLimitRejection::ResultReferences);
    }
    None
}
pub(super) const fn logical_job_output_count_rejection(
    observed: usize,
) -> Option<LogicalWorkflowLimitRejection> {
    if observed > MAX_LOGICAL_JOB_OUTPUTS {
        return Some(LogicalWorkflowLimitRejection::JobOutputs);
    }
    None
}
pub(super) const fn logical_step_count_rejection(
    observed: usize,
) -> Option<LogicalWorkflowLimitRejection> {
    if observed > MAX_LOGICAL_STEPS {
        return Some(LogicalWorkflowLimitRejection::Steps);
    }
    None
}
pub(super) const fn logical_service_count_rejection(
    observed: usize,
) -> Option<LogicalWorkflowLimitRejection> {
    if observed > MAX_LOGICAL_SERVICES {
        return Some(LogicalWorkflowLimitRejection::Services);
    }
    None
}
pub(super) const fn logical_service_port_count_rejection(
    observed: usize,
) -> Option<LogicalWorkflowLimitRejection> {
    if observed > MAX_LOGICAL_SERVICE_PORTS {
        return Some(LogicalWorkflowLimitRejection::ServicePorts);
    }
    None
}
pub(super) const fn logical_service_option_count_rejection(
    observed: usize,
) -> Option<LogicalWorkflowLimitRejection> {
    if observed > MAX_LOGICAL_SERVICE_OPTIONS {
        return Some(LogicalWorkflowLimitRejection::ServiceOptions);
    }
    None
}
pub(super) const fn template_map_entry_count_rejection(
    observed: usize,
) -> Option<LogicalWorkflowLimitRejection> {
    if observed > MAX_TEMPLATE_MAP_ENTRIES {
        return Some(LogicalWorkflowLimitRejection::TemplateMapEntries);
    }
    None
}
pub(super) const fn logical_runner_label_count_rejection(
    observed: usize,
) -> Option<LogicalWorkflowLimitRejection> {
    if observed > MAX_LOGICAL_RUNNER_LABELS {
        return Some(LogicalWorkflowLimitRejection::RunnerLabels);
    }
    None
}
pub(super) const fn reusable_binding_count_rejection(
    observed: usize,
) -> Option<LogicalWorkflowLimitRejection> {
    if observed > MAX_REUSABLE_BINDINGS {
        return Some(LogicalWorkflowLimitRejection::ReusableBindings);
    }
    None
}
pub(super) const fn logical_field_byte_rejection(
    observed: usize,
) -> Option<LogicalWorkflowLimitRejection> {
    if observed > MAX_LOGICAL_FIELD_BYTES {
        return Some(LogicalWorkflowLimitRejection::FieldBytes);
    }
    None
}

/// Unit retained for a deferred positive timeout value.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogicalTimeoutUnit {
    /// The deferred value is already expressed in seconds.
    Seconds,
    /// The deferred value is expressed in minutes and must be scaled safely.
    Minutes,
}

impl LogicalTimeoutUnit {
    /// Scale applied by activation after evaluating the positive integer.
    #[must_use]
    pub const fn seconds_multiplier(self) -> u32 {
        match self {
            Self::Seconds => 1,
            Self::Minutes => 60,
        }
    }
}

/// A positive timeout template whose source unit remains explicit until
/// activation performs a checked conversion into concrete seconds.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalTimeoutTemplate {
    value: CompiledPositiveIntegerTemplate,
    unit: LogicalTimeoutUnit,
}

impl LogicalTimeoutTemplate {
    /// Creates a timeout template without validating positivity or scale overflow.
    #[must_use]
    pub const fn new(value: CompiledPositiveIntegerTemplate, unit: LogicalTimeoutUnit) -> Self {
        Self { value, unit }
    }

    /// Creates a timeout whose evaluated value is measured in seconds.
    #[must_use]
    pub const fn seconds(value: CompiledPositiveIntegerTemplate) -> Self {
        Self::new(value, LogicalTimeoutUnit::Seconds)
    }

    /// Creates a timeout whose evaluated value is measured in minutes.
    #[must_use]
    pub const fn minutes(value: CompiledPositiveIntegerTemplate) -> Self {
        Self::new(value, LogicalTimeoutUnit::Minutes)
    }

    /// Returns the positive integer literal or deferred expression.
    #[must_use]
    pub const fn value(&self) -> &CompiledPositiveIntegerTemplate {
        &self.value
    }

    /// Returns the source unit retained for checked activation-time conversion.
    #[must_use]
    pub const fn unit(&self) -> LogicalTimeoutUnit {
        self.unit
    }

    fn validate(
        &self,
        field: &'static str,
        latest: PlanEvaluationPhase,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        self.value.validate(field, latest, budget)?;
        if let CompiledPositiveIntegerTemplate::Literal(value) = &self.value {
            value
                .checked_mul(self.unit.seconds_multiplier())
                .ok_or(WorkflowPlanError::TimeoutScaleOverflow { field })?;
        }
        Ok(())
    }
}

/// One source-ordered map layer whose values can remain deferred.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateValueMap {
    entries: Vec<(Located<String>, Located<CompiledValueTemplate>)>,
}

impl TemplateValueMap {
    /// Creates a source-ordered map layer without validating keys or templates.
    #[must_use]
    pub const fn new(entries: Vec<(Located<String>, Located<CompiledValueTemplate>)>) -> Self {
        Self { entries }
    }

    /// Returns the entries in their source order.
    #[must_use]
    pub fn entries(&self) -> &[(Located<String>, Located<CompiledValueTemplate>)] {
        &self.entries
    }

    /// Returns the last value assigned to `key`, matching layered-map semantics.
    ///
    /// Validated maps contain unique keys, but reverse lookup also makes this
    /// method deterministic for unvalidated construction.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Located<CompiledValueTemplate>> {
        self.entries
            .iter()
            .rev()
            .find_map(|(candidate, value)| (candidate.value() == key).then_some(value))
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn validate(
        &self,
        source_id: &str,
        field: &'static str,
        latest: PlanEvaluationPhase,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node(field)?;
        if template_map_entry_count_rejection(self.entries.len()).is_some() {
            return Err(WorkflowPlanError::LimitExceeded {
                field,
                maximum: MAX_TEMPLATE_MAP_ENTRIES,
            });
        }
        let mut keys = BTreeSet::new();
        for (key, value) in &self.entries {
            validate_span_source(key.span(), source_id, field)?;
            validate_span_source(value.span(), source_id, field)?;
            budget.charge_text(field, key.value(), MAX_LOGICAL_FIELD_BYTES)?;
            if key.value().is_empty() {
                return Err(WorkflowPlanError::EmptyField(field));
            }
            if !keys.insert(key.value().as_str()) {
                return Err(WorkflowPlanError::DuplicateDefinition {
                    field,
                    key: key.value().clone(),
                });
            }
            value.value().validate(field, latest, budget)?;
        }
        Ok(())
    }
}

/// Provider permission request retained for an immutable authorization snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionSnapshotRequest {
    permissions: WorkflowPermissions,
    span: PlanSourceSpan,
}

impl PermissionSnapshotRequest {
    /// Creates an authorization-snapshot request without validating grants or span.
    #[must_use]
    pub const fn new(permissions: WorkflowPermissions, span: PlanSourceSpan) -> Self {
        Self { permissions, span }
    }

    /// Returns the requested provider permission grants.
    #[must_use]
    pub const fn permissions(&self) -> &WorkflowPermissions {
        &self.permissions
    }

    /// Returns the source span covering the permission declaration.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    fn validate(&self, source_id: &str) -> Result<(), WorkflowPlanError> {
        validate_span_source(&self.span, source_id, "permission snapshot request")?;
        self.permissions.validate()
    }
}

/// Workflow/job concurrency request retained until its group can be evaluated
/// and snapshotted by the control plane.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalConcurrencyTemplate {
    group: Located<CompiledValueTemplate>,
    cancel_in_progress: Option<Located<CompiledBooleanTemplate>>,
    queue: QueuePolicy,
    span: PlanSourceSpan,
}

impl LogicalConcurrencyTemplate {
    /// Creates a concurrency request without validating its group or expressions.
    #[must_use]
    pub const fn new(
        group: Located<CompiledValueTemplate>,
        cancel_in_progress: Option<Located<CompiledBooleanTemplate>>,
        queue: QueuePolicy,
        span: PlanSourceSpan,
    ) -> Self {
        Self {
            group,
            cancel_in_progress,
            queue,
            span,
        }
    }

    /// Returns the expression or literal used to derive the concurrency group.
    #[must_use]
    pub const fn group(&self) -> &Located<CompiledValueTemplate> {
        &self.group
    }

    /// Returns the optional policy for cancelling an existing group member.
    #[must_use]
    pub const fn cancel_in_progress(&self) -> Option<&Located<CompiledBooleanTemplate>> {
        self.cancel_in_progress.as_ref()
    }

    /// Returns the admission policy to use when the group is occupied.
    #[must_use]
    pub const fn queue(&self) -> QueuePolicy {
        self.queue
    }

    /// Returns the source span covering the concurrency declaration.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    fn validate(
        &self,
        source_id: &str,
        latest: PlanEvaluationPhase,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("logical concurrency")?;
        validate_span_source(&self.span, source_id, "logical concurrency")?;
        validate_span_source(self.group.span(), source_id, "logical concurrency group")?;
        if self.group.value().source().trim().is_empty() {
            return Err(WorkflowPlanError::EmptyField("logical concurrency group"));
        }
        self.group
            .value()
            .validate("logical concurrency group", latest, budget)?;
        if let Some(cancel) = &self.cancel_in_progress {
            validate_span_source(cancel.span(), source_id, "logical concurrency cancellation")?;
            cancel
                .value()
                .validate("logical concurrency cancellation", latest, budget)?;
        }
        Ok(())
    }
}

/// Deferred defaults applied only to run-step templates.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalRunDefaultsTemplate {
    shell: Option<Located<CompiledValueTemplate>>,
    working_directory: Option<Located<CompiledValueTemplate>>,
}

impl LogicalRunDefaultsTemplate {
    /// Creates run-step defaults without validating their evaluation phases.
    #[must_use]
    pub const fn new(
        shell: Option<Located<CompiledValueTemplate>>,
        working_directory: Option<Located<CompiledValueTemplate>>,
    ) -> Self {
        Self {
            shell,
            working_directory,
        }
    }

    /// Returns the optional default shell for run steps.
    #[must_use]
    pub const fn shell(&self) -> Option<&Located<CompiledValueTemplate>> {
        self.shell.as_ref()
    }

    /// Returns the optional default working directory for run steps.
    #[must_use]
    pub const fn working_directory(&self) -> Option<&Located<CompiledValueTemplate>> {
        self.working_directory.as_ref()
    }

    fn is_empty(&self) -> bool {
        self.shell.is_none() && self.working_directory.is_none()
    }

    fn validate(
        &self,
        source_id: &str,
        latest: PlanEvaluationPhase,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("logical run defaults")?;
        for (value, field) in [
            (&self.shell, "logical default shell"),
            (&self.working_directory, "logical default working directory"),
        ] {
            if let Some(value) = value {
                validate_span_source(value.span(), source_id, field)?;
                value.value().validate(field, latest, budget)?;
            }
        }
        Ok(())
    }
}

/// Runner group/labels evaluated after prerequisites and matrix selection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalRunnerTemplate {
    group: Option<Located<CompiledValueTemplate>>,
    labels: Vec<Located<CompiledValueTemplate>>,
    span: PlanSourceSpan,
}

impl LogicalRunnerTemplate {
    /// Creates a deferred runner selector without validating labels or limits.
    #[must_use]
    pub const fn new(
        group: Option<Located<CompiledValueTemplate>>,
        labels: Vec<Located<CompiledValueTemplate>>,
        span: PlanSourceSpan,
    ) -> Self {
        Self {
            group,
            labels,
            span,
        }
    }

    /// Returns the optional runner group selector.
    #[must_use]
    pub const fn group(&self) -> Option<&Located<CompiledValueTemplate>> {
        self.group.as_ref()
    }

    /// Returns the required runner-label selectors in source order.
    #[must_use]
    pub fn labels(&self) -> &[Located<CompiledValueTemplate>] {
        &self.labels
    }

    /// Returns the source span covering the runner selector.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    fn validate(
        &self,
        source_id: &str,
        job: &WorkflowJobKey,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("logical runner")?;
        validate_span_source(&self.span, source_id, "logical runner")?;
        if self.group.is_none() && self.labels.is_empty() {
            return Err(WorkflowPlanError::EmptyRunnerProfile(job.to_string()));
        }
        if logical_runner_label_count_rejection(self.labels.len()).is_some() {
            return Err(WorkflowPlanError::LimitExceeded {
                field: "logical runner labels",
                maximum: MAX_LOGICAL_RUNNER_LABELS,
            });
        }
        for value in self.group.iter().chain(&self.labels) {
            validate_span_source(value.span(), source_id, "logical runner selector")?;
            if value.value().source().trim().is_empty() {
                return Err(WorkflowPlanError::EmptyField("logical runner selector"));
            }
            value.value().validate(
                "logical runner selector",
                PlanEvaluationPhase::JobActivation,
                budget,
            )?;
        }
        Ok(())
    }
}

/// Deferred script execution fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalRunStepTemplate {
    script: Located<CompiledValueTemplate>,
    shell: Option<Located<CompiledValueTemplate>>,
    working_directory: Option<Located<CompiledValueTemplate>>,
}

impl LogicalRunStepTemplate {
    /// Creates a run step without validating its script or execution-time fields.
    #[must_use]
    pub const fn new(
        script: Located<CompiledValueTemplate>,
        shell: Option<Located<CompiledValueTemplate>>,
        working_directory: Option<Located<CompiledValueTemplate>>,
    ) -> Self {
        Self {
            script,
            shell,
            working_directory,
        }
    }

    /// Returns the script template together with its source location.
    #[must_use]
    pub const fn script(&self) -> &Located<CompiledValueTemplate> {
        &self.script
    }

    /// Returns the optional shell override for this step.
    #[must_use]
    pub const fn shell(&self) -> Option<&Located<CompiledValueTemplate>> {
        self.shell.as_ref()
    }

    /// Returns the optional working-directory override for this step.
    #[must_use]
    pub const fn working_directory(&self) -> Option<&Located<CompiledValueTemplate>> {
        self.working_directory.as_ref()
    }

    fn validate(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        validate_span_source(self.script.span(), source_id, "logical run script")?;
        if self.script.value().source().is_empty() {
            return Err(WorkflowPlanError::EmptyField("logical run script"));
        }
        self.script.value().validate(
            "logical run script",
            PlanEvaluationPhase::JobExecution,
            budget,
        )?;
        for (value, field) in [
            (&self.shell, "logical run shell"),
            (&self.working_directory, "logical run working directory"),
        ] {
            if let Some(value) = value {
                validate_span_source(value.span(), source_id, field)?;
                value
                    .value()
                    .validate(field, PlanEvaluationPhase::JobExecution, budget)?;
            }
        }
        Ok(())
    }
}

/// Unresolved action reference and deferred caller input layer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalUsesStepTemplate {
    reference: Located<String>,
    inputs: TemplateValueMap,
}

impl LogicalUsesStepTemplate {
    /// Creates an action step without validating its reference or input templates.
    #[must_use]
    pub const fn new(reference: Located<String>, inputs: TemplateValueMap) -> Self {
        Self { reference, inputs }
    }

    /// Returns the unresolved action reference and its source location.
    #[must_use]
    pub const fn reference(&self) -> &Located<String> {
        &self.reference
    }

    /// Returns the caller input layer evaluated during job execution.
    #[must_use]
    pub const fn inputs(&self) -> &TemplateValueMap {
        &self.inputs
    }

    fn validate(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        validate_span_source(self.reference.span(), source_id, "logical action reference")?;
        budget.charge_text(
            "logical action reference",
            self.reference.value(),
            MAX_LOGICAL_FIELD_BYTES,
        )?;
        if self.reference.value().is_empty() {
            return Err(WorkflowPlanError::EmptyField("logical action reference"));
        }
        self.inputs.validate(
            source_id,
            "logical action inputs",
            PlanEvaluationPhase::JobExecution,
            budget,
        )
    }
}

/// Closed set of executable step-template kinds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum LogicalStepKind {
    /// A script executed by the job's selected shell.
    Run(Box<LogicalRunStepTemplate>),
    /// An action resolved from an immutable external reference.
    Uses(LogicalUsesStepTemplate),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedLogicalStepKind {
    Run { value: Box<LogicalRunStepTemplate> },
    Uses { value: LogicalUsesStepTemplate },
}

impl<'de> Deserialize<'de> for LogicalStepKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match UncheckedLogicalStepKind::deserialize(deserializer)? {
            UncheckedLogicalStepKind::Run { value } => Self::Run(value),
            UncheckedLogicalStepKind::Uses { value } => Self::Uses(value),
        })
    }
}

/// One ordered step retained until a concrete `JobIR` is activated.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalStepTemplate {
    key: Located<WorkflowStepKey>,
    id: Option<Located<String>>,
    name: Option<Located<CompiledValueTemplate>>,
    condition: Option<Located<CompiledExpressionTemplate>>,
    environment: TemplateValueMap,
    continue_on_error: Option<Located<CompiledBooleanTemplate>>,
    timeout: Option<Located<LogicalTimeoutTemplate>>,
    execution: LogicalStepKind,
    span: PlanSourceSpan,
}

/// Named construction path for one logical step template.
#[derive(Clone, Debug)]
pub struct LogicalStepTemplateBuilder {
    key: Located<WorkflowStepKey>,
    id: Option<Located<String>>,
    name: Option<Located<CompiledValueTemplate>>,
    condition: Option<Located<CompiledExpressionTemplate>>,
    environment: TemplateValueMap,
    continue_on_error: Option<Located<CompiledBooleanTemplate>>,
    timeout: Option<Located<LogicalTimeoutTemplate>>,
    execution: LogicalStepKind,
    span: PlanSourceSpan,
}

impl LogicalStepTemplate {
    /// Starts a step builder with no optional metadata, environment, or policies.
    #[must_use]
    pub fn builder(
        key: Located<WorkflowStepKey>,
        execution: LogicalStepKind,
        span: PlanSourceSpan,
    ) -> LogicalStepTemplateBuilder {
        LogicalStepTemplateBuilder {
            key,
            id: None,
            name: None,
            condition: None,
            environment: TemplateValueMap::default(),
            continue_on_error: None,
            timeout: None,
            execution,
            span,
        }
    }

    /// Returns the plan-local step key and its source location.
    #[must_use]
    pub const fn key(&self) -> &Located<WorkflowStepKey> {
        &self.key
    }

    /// Returns the optional provider-facing step identifier.
    #[must_use]
    pub const fn id(&self) -> Option<&Located<String>> {
        self.id.as_ref()
    }

    /// Returns the optional execution-time display-name template.
    #[must_use]
    pub const fn name(&self) -> Option<&Located<CompiledValueTemplate>> {
        self.name.as_ref()
    }

    /// Returns the optional execution-time condition.
    #[must_use]
    pub const fn condition(&self) -> Option<&Located<CompiledExpressionTemplate>> {
        self.condition.as_ref()
    }

    /// Returns this step's environment layer.
    #[must_use]
    pub const fn environment(&self) -> &TemplateValueMap {
        &self.environment
    }

    /// Returns the optional execution-time continue-on-error policy.
    #[must_use]
    pub const fn continue_on_error(&self) -> Option<&Located<CompiledBooleanTemplate>> {
        self.continue_on_error.as_ref()
    }

    /// Returns the optional positive timeout with its retained source unit.
    #[must_use]
    pub const fn timeout(&self) -> Option<&Located<LogicalTimeoutTemplate>> {
        self.timeout.as_ref()
    }

    /// Returns the closed run-or-action execution definition.
    #[must_use]
    pub const fn execution(&self) -> &LogicalStepKind {
        &self.execution
    }

    /// Returns the source span covering the complete step.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    fn validate(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("logical step")?;
        for (span, field) in [
            (self.span(), "logical step"),
            (self.key.span(), "logical step key"),
        ] {
            validate_span_source(span, source_id, field)?;
        }
        if let Some(id) = &self.id {
            validate_span_source(id.span(), source_id, "logical step id")?;
            budget.charge_text("logical step id", id.value(), MAX_LOGICAL_FIELD_BYTES)?;
            if id.value().is_empty() {
                return Err(WorkflowPlanError::EmptyField("logical step id"));
            }
        }
        if let Some(name) = &self.name {
            validate_span_source(name.span(), source_id, "logical step name")?;
            name.value().validate(
                "logical step name",
                PlanEvaluationPhase::JobExecution,
                budget,
            )?;
        }
        if let Some(condition) = &self.condition {
            validate_span_source(condition.span(), source_id, "logical step condition")?;
            condition.value().validate(
                "logical step condition",
                PlanEvaluationPhase::JobExecution,
                budget,
            )?;
        }
        self.environment.validate(
            source_id,
            "logical step environment",
            PlanEvaluationPhase::JobExecution,
            budget,
        )?;
        if let Some(value) = &self.continue_on_error {
            validate_span_source(value.span(), source_id, "logical step continue-on-error")?;
            value.value().validate(
                "logical step continue-on-error",
                PlanEvaluationPhase::JobExecution,
                budget,
            )?;
        }
        if let Some(value) = &self.timeout {
            validate_span_source(value.span(), source_id, "logical step timeout")?;
            value.value().validate(
                "logical step timeout",
                PlanEvaluationPhase::JobExecution,
                budget,
            )?;
        }
        match &self.execution {
            LogicalStepKind::Run(run) => run.validate(source_id, budget),
            LogicalStepKind::Uses(uses) => uses.validate(source_id, budget),
        }
    }
}

impl LogicalStepTemplateBuilder {
    /// Sets the optional provider-facing step identifier.
    #[must_use]
    pub fn id(mut self, id: Option<Located<String>>) -> Self {
        self.id = id;
        self
    }

    /// Sets the optional execution-time display-name template.
    #[must_use]
    pub fn name(mut self, name: Option<Located<CompiledValueTemplate>>) -> Self {
        self.name = name;
        self
    }

    /// Sets the optional execution-time condition.
    #[must_use]
    pub fn condition(mut self, condition: Option<Located<CompiledExpressionTemplate>>) -> Self {
        self.condition = condition;
        self
    }

    /// Replaces the step-specific environment layer.
    #[must_use]
    pub fn environment(mut self, environment: TemplateValueMap) -> Self {
        self.environment = environment;
        self
    }

    /// Sets the optional execution-time continue-on-error policy.
    #[must_use]
    pub fn continue_on_error(mut self, value: Option<Located<CompiledBooleanTemplate>>) -> Self {
        self.continue_on_error = value;
        self
    }

    /// Sets the optional execution-time timeout.
    #[must_use]
    pub fn timeout(mut self, value: Option<Located<LogicalTimeoutTemplate>>) -> Self {
        self.timeout = value;
        self
    }

    /// Validates and freezes one step template.
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowPlanError`] for invalid spans, templates, maps, or
    /// execution fields.
    pub fn build(self) -> Result<LogicalStepTemplate, WorkflowPlanError> {
        let step = LogicalStepTemplate {
            key: self.key,
            id: self.id,
            name: self.name,
            condition: self.condition,
            environment: self.environment,
            continue_on_error: self.continue_on_error,
            timeout: self.timeout,
            execution: self.execution,
            span: self.span,
        };
        let mut budget = LogicalPlanBudget::new();
        step.validate(step.span().source_id(), &mut budget)?;
        Ok(step)
    }
}

/// One service container retained until job-execution templates are projected.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalServiceContainerTemplate {
    key: Located<WorkflowServiceKey>,
    image: Located<String>,
    environment: TemplateValueMap,
    ports: Vec<Located<ContainerPort>>,
    options: Vec<Located<String>>,
    span: PlanSourceSpan,
}

impl LogicalServiceContainerTemplate {
    /// Creates a service-container template without validating image, ports, or options.
    #[must_use]
    pub const fn new(
        key: Located<WorkflowServiceKey>,
        image: Located<String>,
        environment: TemplateValueMap,
        ports: Vec<Located<ContainerPort>>,
        options: Vec<Located<String>>,
        span: PlanSourceSpan,
    ) -> Self {
        Self {
            key,
            image,
            environment,
            ports,
            options,
            span,
        }
    }

    /// Returns the plan-local service key and its source location.
    #[must_use]
    pub const fn key(&self) -> &Located<WorkflowServiceKey> {
        &self.key
    }

    /// Returns the immutable container image reference.
    #[must_use]
    pub const fn image(&self) -> &Located<String> {
        &self.image
    }

    /// Returns the environment layer projected into the service container.
    #[must_use]
    pub const fn environment(&self) -> &TemplateValueMap {
        &self.environment
    }

    /// Returns the requested container-port mappings in source order.
    #[must_use]
    pub fn ports(&self) -> &[Located<ContainerPort>] {
        &self.ports
    }

    /// Returns parsed engine-option tokens in source order.
    #[must_use]
    pub fn options(&self) -> &[Located<String>] {
        &self.options
    }

    /// Returns the source span covering the complete service declaration.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    fn validate(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("logical service container")?;
        validate_span_source(self.key.span(), source_id, "logical service key")?;
        validate_span_source(self.image.span(), source_id, "logical service image")?;
        validate_span_source(&self.span, source_id, "logical service container")?;
        budget.charge_text(
            "logical service key",
            self.key.value().as_str(),
            MAX_LOGICAL_FIELD_BYTES,
        )?;
        budget.charge_text(
            "logical service image",
            self.image.value(),
            MAX_LOGICAL_FIELD_BYTES,
        )?;
        if self.image.value().trim().is_empty()
            || self.image.value().trim() != self.image.value()
            || self.image.value().chars().any(char::is_control)
        {
            return Err(WorkflowPlanError::InvalidKey {
                kind: "logical service image",
                value: self.image.value().clone(),
            });
        }
        self.environment.validate(
            source_id,
            "logical service environment",
            PlanEvaluationPhase::JobExecution,
            budget,
        )?;
        if logical_service_port_count_rejection(self.ports.len()).is_some() {
            return Err(WorkflowPlanError::LimitExceeded {
                field: "logical service ports",
                maximum: MAX_LOGICAL_SERVICE_PORTS,
            });
        }
        let mut containers = BTreeSet::new();
        let mut requested = BTreeSet::new();
        for port in &self.ports {
            validate_span_source(port.span(), source_id, "logical service port")?;
            budget.charge_node("logical service port")?;
            if port.value().container_port() == 0
                || port.value().requested_host_port() == Some(0)
                || !containers.insert(port.value().container_port())
                || port
                    .value()
                    .requested_host_port()
                    .is_some_and(|host| !requested.insert((port.value().protocol(), host)))
            {
                return Err(WorkflowPlanError::InvalidKey {
                    kind: "logical service port",
                    value: port.value().container_port().to_string(),
                });
            }
        }
        if logical_service_option_count_rejection(self.options.len()).is_some() {
            return Err(WorkflowPlanError::LimitExceeded {
                field: "logical service options",
                maximum: MAX_LOGICAL_SERVICE_OPTIONS,
            });
        }
        for option in &self.options {
            validate_span_source(option.span(), source_id, "logical service option")?;
            budget.charge_node("logical service option")?;
            budget.charge_text(
                "logical service option",
                option.value(),
                MAX_LOGICAL_FIELD_BYTES,
            )?;
            if option.value().is_empty() || option.value().chars().any(char::is_control) {
                return Err(WorkflowPlanError::InvalidKey {
                    kind: "logical service option",
                    value: option.value().clone(),
                });
            }
        }
        Ok(())
    }
}

/// Deferred values for one resource vector in a logical job plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalResourceVectorTemplate {
    cpu: Option<Located<CompiledValueTemplate>>,
    memory: Option<Located<CompiledValueTemplate>>,
    ephemeral_storage: Option<Located<CompiledValueTemplate>>,
    gpu: Option<Located<CompiledValueTemplate>>,
    span: PlanSourceSpan,
}

impl LogicalResourceVectorTemplate {
    /// Creates one unvalidated resource-vector template.
    #[must_use]
    pub const fn new(
        cpu: Option<Located<CompiledValueTemplate>>,
        memory: Option<Located<CompiledValueTemplate>>,
        ephemeral_storage: Option<Located<CompiledValueTemplate>>,
        gpu: Option<Located<CompiledValueTemplate>>,
        span: PlanSourceSpan,
    ) -> Self {
        Self {
            cpu,
            memory,
            ephemeral_storage,
            gpu,
            span,
        }
    }

    /// Returns the deferred CPU quantity.
    #[must_use]
    pub const fn cpu(&self) -> Option<&Located<CompiledValueTemplate>> {
        self.cpu.as_ref()
    }

    /// Returns the deferred memory quantity.
    #[must_use]
    pub const fn memory(&self) -> Option<&Located<CompiledValueTemplate>> {
        self.memory.as_ref()
    }

    /// Returns the deferred ephemeral-storage quantity.
    #[must_use]
    pub const fn ephemeral_storage(&self) -> Option<&Located<CompiledValueTemplate>> {
        self.ephemeral_storage.as_ref()
    }

    /// Returns the deferred integral GPU quantity.
    #[must_use]
    pub const fn gpu(&self) -> Option<&Located<CompiledValueTemplate>> {
        self.gpu.as_ref()
    }

    /// Returns the span covering this resource vector.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    fn is_empty(&self) -> bool {
        self.cpu.is_none()
            && self.memory.is_none()
            && self.ephemeral_storage.is_none()
            && self.gpu.is_none()
    }

    fn validate(
        &self,
        source_id: &str,
        field: &'static str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node(field)?;
        validate_span_source(&self.span, source_id, field)?;
        if self.is_empty() {
            return Err(WorkflowPlanError::EmptyField(field));
        }
        for (value, value_field) in [
            (&self.cpu, "job resource CPU"),
            (&self.memory, "job resource memory"),
            (&self.ephemeral_storage, "job resource ephemeral storage"),
            (&self.gpu, "job resource GPU"),
        ] {
            if let Some(value) = value {
                validate_span_source(value.span(), source_id, value_field)?;
                value
                    .value()
                    .validate(value_field, PlanEvaluationPhase::JobActivation, budget)?;
            }
        }
        Ok(())
    }
}

/// Deferred Kubernetes-style requests and limits for one logical step job.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalJobResourcesTemplate {
    requests: Option<LogicalResourceVectorTemplate>,
    limits: Option<LogicalResourceVectorTemplate>,
    span: PlanSourceSpan,
}

impl LogicalJobResourcesTemplate {
    /// Creates an unvalidated resource allocation template.
    #[must_use]
    pub const fn new(
        requests: Option<LogicalResourceVectorTemplate>,
        limits: Option<LogicalResourceVectorTemplate>,
        span: PlanSourceSpan,
    ) -> Self {
        Self {
            requests,
            limits,
            span,
        }
    }

    /// Returns deferred placement requests.
    #[must_use]
    pub const fn requests(&self) -> Option<&LogicalResourceVectorTemplate> {
        self.requests.as_ref()
    }

    /// Returns deferred enforcement limits.
    #[must_use]
    pub const fn limits(&self) -> Option<&LogicalResourceVectorTemplate> {
        self.limits.as_ref()
    }

    /// Returns the source span covering both vectors.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    fn validate(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("job resources")?;
        validate_span_source(&self.span, source_id, "job resources")?;
        if self.requests.is_none() && self.limits.is_none() {
            return Err(WorkflowPlanError::EmptyField("job resources"));
        }
        if let Some(requests) = &self.requests {
            requests.validate(source_id, "job resource requests", budget)?;
        }
        if let Some(limits) = &self.limits {
            limits.validate(source_id, "job resource limits", budget)?;
        }
        Ok(())
    }
}

/// Concrete-step side of the closed logical job-kind union.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StepJobTemplate {
    runner: LogicalRunnerTemplate,
    #[serde(deserialize_with = "deserialize_required_resources")]
    resources: Option<Box<LogicalJobResourcesTemplate>>,
    services: Vec<LogicalServiceContainerTemplate>,
    steps: Vec<LogicalStepTemplate>,
    span: PlanSourceSpan,
}

fn deserialize_required_resources<'de, D>(
    deserializer: D,
) -> Result<Option<Box<LogicalJobResourcesTemplate>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::deserialize(deserializer)
}

impl StepJobTemplate {
    /// Creates a step job with no service containers and without validating it.
    #[must_use]
    pub const fn new(
        runner: LogicalRunnerTemplate,
        steps: Vec<LogicalStepTemplate>,
        span: PlanSourceSpan,
    ) -> Self {
        Self {
            runner,
            resources: None,
            services: Vec::new(),
            steps,
            span,
        }
    }

    /// Returns the deferred runner selection.
    #[must_use]
    pub const fn runner(&self) -> &LogicalRunnerTemplate {
        &self.runner
    }

    /// Returns deferred resource requests and limits, when configured.
    #[must_use]
    pub fn resources(&self) -> Option<&LogicalJobResourcesTemplate> {
        self.resources.as_deref()
    }

    /// Returns service containers in source order.
    #[must_use]
    pub fn services(&self) -> &[LogicalServiceContainerTemplate] {
        &self.services
    }

    /// Returns executable steps in source order.
    #[must_use]
    pub fn steps(&self) -> &[LogicalStepTemplate] {
        &self.steps
    }

    /// Returns the source span covering the step-job body.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    /// Replaces the service-container list without validating it.
    #[must_use]
    pub fn with_services(
        mut self,
        services: impl IntoIterator<Item = LogicalServiceContainerTemplate>,
    ) -> Self {
        self.services = services.into_iter().collect();
        self
    }

    /// Attaches deferred resource requests and limits without validating them.
    #[must_use]
    pub fn with_resources(mut self, resources: Option<LogicalJobResourcesTemplate>) -> Self {
        self.resources = resources.map(Box::new);
        self
    }

    fn validate(
        &self,
        source_id: &str,
        job: &WorkflowJobKey,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("step job template")?;
        validate_span_source(&self.span, source_id, "step job template")?;
        self.runner.validate(source_id, job, budget)?;
        if let Some(resources) = &self.resources {
            resources.validate(source_id, budget)?;
        }
        if logical_service_count_rejection(self.services.len()).is_some() {
            return Err(WorkflowPlanError::LimitExceeded {
                field: "logical services",
                maximum: MAX_LOGICAL_SERVICES,
            });
        }
        let mut service_keys = BTreeSet::new();
        for service in &self.services {
            if !service_keys.insert(service.key().value().as_str().to_ascii_lowercase()) {
                return Err(WorkflowPlanError::DuplicateDefinition {
                    field: "logical services",
                    key: service.key().value().as_str().to_owned(),
                });
            }
            service.validate(source_id, budget)?;
        }
        if self.steps.is_empty() {
            return Err(WorkflowPlanError::NoSteps(job.to_string()));
        }
        if logical_step_count_rejection(self.steps.len()).is_some() {
            return Err(WorkflowPlanError::LimitExceeded {
                field: "logical steps",
                maximum: MAX_LOGICAL_STEPS,
            });
        }
        let mut keys = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for step in &self.steps {
            if !keys.insert(step.key().value()) {
                return Err(WorkflowPlanError::DuplicateStep {
                    job: job.to_string(),
                    step: step.key().value().to_string(),
                });
            }
            if let Some(id) = step.id()
                && !ids.insert(id.value().as_str())
            {
                return Err(WorkflowPlanError::DuplicateDefinition {
                    field: "logical step ids",
                    key: id.value().clone(),
                });
            }
            step.validate(source_id, budget)?;
        }
        Ok(())
    }
}

/// One non-secret reusable-workflow input binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReusableInputBinding {
    target: Located<WorkflowInputKey>,
    value: Located<CompiledValueTemplate>,
}

impl ReusableInputBinding {
    /// Creates an input binding without validating its target, value, or spans.
    #[must_use]
    pub const fn new(
        target: Located<WorkflowInputKey>,
        value: Located<CompiledValueTemplate>,
    ) -> Self {
        Self { target, value }
    }

    /// Returns the callee input key together with its source location.
    #[must_use]
    pub const fn target(&self) -> &Located<WorkflowInputKey> {
        &self.target
    }

    /// Returns the caller-side value evaluated during job activation.
    #[must_use]
    pub const fn value(&self) -> &Located<CompiledValueTemplate> {
        &self.value
    }
}

/// One name-only reusable secret forwarding edge. It cannot contain secret bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReusableSecretBinding {
    target: Located<WorkflowSecretKey>,
    source: Located<WorkflowSecretKey>,
}

impl ReusableSecretBinding {
    /// Creates a name-only secret forwarding edge.
    #[must_use]
    pub const fn new(
        target: Located<WorkflowSecretKey>,
        source: Located<WorkflowSecretKey>,
    ) -> Self {
        Self { target, source }
    }

    /// Returns the secret name expected by the called workflow.
    #[must_use]
    pub const fn target(&self) -> &Located<WorkflowSecretKey> {
        &self.target
    }

    /// Returns the caller-side secret name to resolve at execution.
    #[must_use]
    pub const fn source(&self) -> &Located<WorkflowSecretKey> {
        &self.source
    }
}

/// Closed reusable secret-forwarding modes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ReusableSecretForwarding {
    /// Explicit name-only caller-to-callee forwarding edges.
    Mapping(Vec<ReusableSecretBinding>),
    /// A source-located request to inherit eligible caller secret bindings.
    ///
    /// The plan stores only the request and never embeds secret bytes.
    Inherit(PlanSourceSpan),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedReusableSecretForwarding {
    Mapping { value: Vec<ReusableSecretBinding> },
    Inherit { value: PlanSourceSpan },
}

impl<'de> Deserialize<'de> for ReusableSecretForwarding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            match UncheckedReusableSecretForwarding::deserialize(deserializer)? {
                UncheckedReusableSecretForwarding::Mapping { value } => Self::Mapping(value),
                UncheckedReusableSecretForwarding::Inherit { value } => Self::Inherit(value),
            },
        )
    }
}

/// Reusable-workflow side of the closed logical job-kind union.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReusableWorkflowInvocation {
    reference: Located<String>,
    inputs: Vec<ReusableInputBinding>,
    secrets: ReusableSecretForwarding,
    span: PlanSourceSpan,
}

impl ReusableWorkflowInvocation {
    /// Creates a reusable-workflow call without validating its reference or bindings.
    #[must_use]
    pub const fn new(
        reference: Located<String>,
        inputs: Vec<ReusableInputBinding>,
        secrets: ReusableSecretForwarding,
        span: PlanSourceSpan,
    ) -> Self {
        Self {
            reference,
            inputs,
            secrets,
            span,
        }
    }

    /// Returns the unresolved reusable-workflow reference.
    #[must_use]
    pub const fn reference(&self) -> &Located<String> {
        &self.reference
    }

    /// Returns non-secret caller input bindings in source order.
    #[must_use]
    pub fn inputs(&self) -> &[ReusableInputBinding] {
        &self.inputs
    }

    /// Returns the name-only secret forwarding policy.
    #[must_use]
    pub const fn secrets(&self) -> &ReusableSecretForwarding {
        &self.secrets
    }

    /// Returns the source span covering the reusable invocation.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    fn validate(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("reusable workflow invocation")?;
        validate_span_source(&self.span, source_id, "reusable workflow invocation")?;
        validate_span_source(
            self.reference.span(),
            source_id,
            "reusable workflow reference",
        )?;
        budget.charge_text(
            "reusable workflow reference",
            self.reference.value(),
            MAX_LOGICAL_FIELD_BYTES,
        )?;
        if self.reference.value().is_empty() {
            return Err(WorkflowPlanError::EmptyField("reusable workflow reference"));
        }
        if reusable_binding_count_rejection(self.inputs.len()).is_some() {
            return Err(WorkflowPlanError::LimitExceeded {
                field: "reusable workflow inputs",
                maximum: MAX_REUSABLE_BINDINGS,
            });
        }
        let mut input_targets = BTreeSet::new();
        for input in &self.inputs {
            validate_span_source(input.target().span(), source_id, "reusable input target")?;
            validate_span_source(input.value().span(), source_id, "reusable input value")?;
            if !input_targets.insert(input.target().value()) {
                return Err(WorkflowPlanError::DuplicateDefinition {
                    field: "reusable workflow inputs",
                    key: input.target().value().to_string(),
                });
            }
            input.value().value().validate(
                "reusable input value",
                PlanEvaluationPhase::JobActivation,
                budget,
            )?;
        }
        match &self.secrets {
            ReusableSecretForwarding::Inherit(span) => {
                validate_span_source(span, source_id, "reusable inherited secrets")?;
            }
            ReusableSecretForwarding::Mapping(bindings) => {
                if reusable_binding_count_rejection(bindings.len()).is_some() {
                    return Err(WorkflowPlanError::LimitExceeded {
                        field: "reusable workflow secrets",
                        maximum: MAX_REUSABLE_BINDINGS,
                    });
                }
                let mut targets = BTreeSet::new();
                for binding in bindings {
                    validate_span_source(
                        binding.target().span(),
                        source_id,
                        "reusable secret target",
                    )?;
                    validate_span_source(
                        binding.source().span(),
                        source_id,
                        "reusable secret source",
                    )?;
                    if !targets.insert(binding.target().value()) {
                        return Err(WorkflowPlanError::DuplicateDefinition {
                            field: "reusable workflow secrets",
                            key: binding.target().value().to_string(),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

/// Result field on one logical prerequisite job.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum LogicalResultValue {
    /// The prerequisite job's aggregate terminal result.
    Result,
    /// One named, declared output of the prerequisite job.
    Output(WorkflowOutputKey),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedLogicalResultValue {
    Result,
    Output { value: WorkflowOutputKey },
}

impl<'de> Deserialize<'de> for LogicalResultValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            match UncheckedLogicalResultValue::deserialize(deserializer)? {
                UncheckedLogicalResultValue::Result => Self::Result,
                UncheckedLogicalResultValue::Output { value } => Self::Output(value),
            },
        )
    }
}

/// Typed reference to the aggregate result or output of a logical job.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalResultReference {
    job: WorkflowJobKey,
    value: LogicalResultValue,
}

impl LogicalResultReference {
    /// Creates a typed result reference without checking graph reachability.
    #[must_use]
    pub const fn new(job: WorkflowJobKey, value: LogicalResultValue) -> Self {
        Self { job, value }
    }

    /// Returns the referenced logical job key.
    #[must_use]
    pub const fn job(&self) -> &WorkflowJobKey {
        &self.job
    }

    /// Returns whether the reference selects the result or a named output.
    #[must_use]
    pub const fn value(&self) -> &LogicalResultValue {
        &self.value
    }
}

impl fmt::Display for LogicalResultReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            LogicalResultValue::Result => write!(formatter, "{}.result", self.job),
            LogicalResultValue::Output(output) => {
                write!(formatter, "{}.outputs.{output}", self.job)
            }
        }
    }
}

/// How per-instance values become one logical-job output.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogicalOutputMergePolicy {
    /// Accept the value from the job's sole selected instance.
    SingleInstance,
    /// Select the value from the last instance that completes successfully.
    LastSuccessfulCompletion,
}

/// Source of one logical job output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum LogicalJobOutputSource {
    /// A template evaluated when a step job finalizes.
    Template(Located<CompiledValueTemplate>),
    /// A named output returned by a reusable-workflow invocation.
    InvocationOutput(Located<WorkflowOutputKey>),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedLogicalJobOutputSource {
    Template {
        value: Located<CompiledValueTemplate>,
    },
    InvocationOutput {
        value: Located<WorkflowOutputKey>,
    },
}

impl<'de> Deserialize<'de> for LogicalJobOutputSource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            match UncheckedLogicalJobOutputSource::deserialize(deserializer)? {
                UncheckedLogicalJobOutputSource::Template { value } => Self::Template(value),
                UncheckedLogicalJobOutputSource::InvocationOutput { value } => {
                    Self::InvocationOutput(value)
                }
            },
        )
    }
}

/// One logical-job output definition retained through instance finalization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalJobOutputDefinition {
    key: Located<WorkflowOutputKey>,
    source: LogicalJobOutputSource,
    merge: LogicalOutputMergePolicy,
    sensitivity: OutputSensitivity,
    span: PlanSourceSpan,
}

impl LogicalJobOutputDefinition {
    /// Creates an output definition without validating job-kind compatibility,
    /// merge policy, sensitivity, or source spans.
    #[must_use]
    pub const fn new(
        key: Located<WorkflowOutputKey>,
        source: LogicalJobOutputSource,
        merge: LogicalOutputMergePolicy,
        sensitivity: OutputSensitivity,
        span: PlanSourceSpan,
    ) -> Self {
        Self {
            key,
            source,
            merge,
            sensitivity,
            span,
        }
    }

    /// Returns the exported output key and its source location.
    #[must_use]
    pub const fn key(&self) -> &Located<WorkflowOutputKey> {
        &self.key
    }

    /// Returns the step-template or invocation-output source.
    #[must_use]
    pub const fn source(&self) -> &LogicalJobOutputSource {
        &self.source
    }

    /// Returns the policy for reducing per-instance values.
    #[must_use]
    pub const fn merge(&self) -> LogicalOutputMergePolicy {
        self.merge
    }

    /// Returns the durable-data sensitivity assigned to this output.
    #[must_use]
    pub const fn sensitivity(&self) -> OutputSensitivity {
        self.sensitivity
    }

    /// Returns the source span covering the complete output declaration.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    fn validate(
        &self,
        source_id: &str,
        job: &WorkflowJobKey,
        job_kind: &LogicalJobKind,
        has_strategy: bool,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("logical job output")?;
        validate_span_source(&self.span, source_id, "logical job output")?;
        validate_span_source(self.key.span(), source_id, "logical job output key")?;
        if !has_strategy && self.merge != LogicalOutputMergePolicy::SingleInstance {
            return Err(WorkflowPlanError::InvalidOutputMergePolicy {
                job: job.to_string(),
            });
        }
        match (&self.source, job_kind) {
            (LogicalJobOutputSource::Template(value), LogicalJobKind::Steps(_)) => {
                validate_span_source(value.span(), source_id, "logical job output value")?;
                value.value().validate(
                    "logical job output value",
                    PlanEvaluationPhase::JobFinalization,
                    budget,
                )?;
                if self.sensitivity == OutputSensitivity::Public
                    && value.value().references_context(ExpressionContext::Secrets)
                {
                    return Err(WorkflowPlanError::PublicOutputReferencesSecrets(
                        self.key.value().to_string(),
                    ));
                }
            }
            (
                LogicalJobOutputSource::InvocationOutput(output),
                LogicalJobKind::ReusableWorkflow(_),
            ) => {
                validate_span_source(output.span(), source_id, "reusable workflow output")?;
            }
            (LogicalJobOutputSource::Template(_), LogicalJobKind::ReusableWorkflow(_)) => {
                return Err(WorkflowPlanError::IncompatibleLogicalJobField {
                    job: job.to_string(),
                    field: "template output",
                });
            }
            (LogicalJobOutputSource::InvocationOutput(_), LogicalJobKind::Steps(_)) => {
                return Err(WorkflowPlanError::IncompatibleLogicalJobField {
                    job: job.to_string(),
                    field: "invocation output",
                });
            }
        }
        Ok(())
    }
}

/// Deployment environment selected when a logical job activates.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSelection {
    name: Located<CompiledValueTemplate>,
    url: Option<Located<CompiledValueTemplate>>,
    span: PlanSourceSpan,
}

impl DeploymentSelection {
    /// Creates a deployment selection without validating templates or spans.
    #[must_use]
    pub const fn new(
        name: Located<CompiledValueTemplate>,
        url: Option<Located<CompiledValueTemplate>>,
        span: PlanSourceSpan,
    ) -> Self {
        Self { name, url, span }
    }

    /// Returns the environment-name template evaluated during job activation.
    #[must_use]
    pub const fn name(&self) -> &Located<CompiledValueTemplate> {
        &self.name
    }

    /// Returns the optional environment URL evaluated during job finalization.
    #[must_use]
    pub const fn url(&self) -> Option<&Located<CompiledValueTemplate>> {
        self.url.as_ref()
    }

    /// Returns the source span covering the deployment selection.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    fn validate(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("deployment selection")?;
        validate_span_source(&self.span, source_id, "deployment selection")?;
        validate_span_source(self.name.span(), source_id, "deployment environment name")?;
        if self.name.value().source().trim().is_empty() {
            return Err(WorkflowPlanError::EmptyField("deployment environment name"));
        }
        self.name.value().validate(
            "deployment environment name",
            PlanEvaluationPhase::JobActivation,
            budget,
        )?;
        if let Some(url) = &self.url {
            validate_span_source(url.span(), source_id, "deployment environment URL")?;
            url.value().validate(
                "deployment environment URL",
                PlanEvaluationPhase::JobFinalization,
                budget,
            )?;
        }
        Ok(())
    }
}

/// Closed logical job kinds. A job cannot mix `steps` with a reusable call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum LogicalJobKind {
    /// A runner-backed job containing executable steps.
    Steps(StepJobTemplate),
    /// A control-plane invocation of another workflow.
    ReusableWorkflow(ReusableWorkflowInvocation),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedLogicalJobKind {
    Steps { value: StepJobTemplate },
    ReusableWorkflow { value: ReusableWorkflowInvocation },
}

impl<'de> Deserialize<'de> for LogicalJobKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match UncheckedLogicalJobKind::deserialize(deserializer)? {
            UncheckedLogicalJobKind::Steps { value } => Self::Steps(value),
            UncheckedLogicalJobKind::ReusableWorkflow { value } => Self::ReusableWorkflow(value),
        })
    }
}

/// One source-level logical job that activates into zero or more instances.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalJobTemplate {
    key: Located<WorkflowJobKey>,
    source_order: u32,
    name: Option<Located<CompiledValueTemplate>>,
    needs: Vec<Located<WorkflowJobKey>>,
    result_references: Vec<Located<LogicalResultReference>>,
    condition: Option<Located<CompiledExpressionTemplate>>,
    strategy: Option<WorkflowStrategyTemplate>,
    permissions: Option<PermissionSnapshotRequest>,
    concurrency: Option<LogicalConcurrencyTemplate>,
    environment: TemplateValueMap,
    run_defaults: LogicalRunDefaultsTemplate,
    timeout: Option<Located<LogicalTimeoutTemplate>>,
    continue_on_error: Option<Located<CompiledBooleanTemplate>>,
    outputs: Vec<LogicalJobOutputDefinition>,
    deployment: Option<DeploymentSelection>,
    execution: LogicalJobKind,
    span: PlanSourceSpan,
}

/// Named construction path for a logical job template.
#[derive(Clone, Debug)]
pub struct LogicalJobTemplateBuilder {
    key: Located<WorkflowJobKey>,
    source_order: u32,
    name: Option<Located<CompiledValueTemplate>>,
    needs: Vec<Located<WorkflowJobKey>>,
    result_references: Vec<Located<LogicalResultReference>>,
    condition: Option<Located<CompiledExpressionTemplate>>,
    strategy: Option<WorkflowStrategyTemplate>,
    permissions: Option<PermissionSnapshotRequest>,
    concurrency: Option<LogicalConcurrencyTemplate>,
    environment: TemplateValueMap,
    run_defaults: LogicalRunDefaultsTemplate,
    timeout: Option<Located<LogicalTimeoutTemplate>>,
    continue_on_error: Option<Located<CompiledBooleanTemplate>>,
    outputs: Vec<LogicalJobOutputDefinition>,
    deployment: Option<DeploymentSelection>,
    execution: LogicalJobKind,
    span: PlanSourceSpan,
}

impl LogicalJobTemplate {
    /// Starts a job builder with empty optional fields and collection layers.
    ///
    /// `source_order` must equal the job's zero-based position in the final
    /// workflow plan; graph-wide validation enforces that canonical ordering.
    #[must_use]
    pub fn builder(
        key: Located<WorkflowJobKey>,
        source_order: u32,
        execution: LogicalJobKind,
        span: PlanSourceSpan,
    ) -> LogicalJobTemplateBuilder {
        LogicalJobTemplateBuilder {
            key,
            source_order,
            name: None,
            needs: Vec::new(),
            result_references: Vec::new(),
            condition: None,
            strategy: None,
            permissions: None,
            concurrency: None,
            environment: TemplateValueMap::default(),
            run_defaults: LogicalRunDefaultsTemplate::default(),
            timeout: None,
            continue_on_error: None,
            outputs: Vec::new(),
            deployment: None,
            execution,
            span,
        }
    }

    /// Returns the plan-local job key and its source location.
    #[must_use]
    pub const fn key(&self) -> &Located<WorkflowJobKey> {
        &self.key
    }

    /// Returns the canonical zero-based source position.
    #[must_use]
    pub const fn source_order(&self) -> u32 {
        self.source_order
    }

    /// Returns the optional activation-time display-name template.
    #[must_use]
    pub const fn name(&self) -> Option<&Located<CompiledValueTemplate>> {
        self.name.as_ref()
    }

    /// Returns direct prerequisite jobs in source order.
    #[must_use]
    pub fn needs(&self) -> &[Located<WorkflowJobKey>] {
        &self.needs
    }

    /// Returns the prerequisite results explicitly consumed by this job.
    ///
    /// Graph validation requires every reference to target a declared `needs`
    /// edge and, for outputs, an output declared by that prerequisite.
    #[must_use]
    pub fn result_references(&self) -> &[Located<LogicalResultReference>] {
        &self.result_references
    }

    /// Returns the optional condition evaluated when the job activates.
    #[must_use]
    pub const fn condition(&self) -> Option<&Located<CompiledExpressionTemplate>> {
        self.condition.as_ref()
    }

    /// Returns the optional matrix and activation-control strategy.
    #[must_use]
    pub const fn strategy(&self) -> Option<&WorkflowStrategyTemplate> {
        self.strategy.as_ref()
    }

    /// Returns the optional job-level authorization snapshot request.
    #[must_use]
    pub const fn permissions(&self) -> Option<&PermissionSnapshotRequest> {
        self.permissions.as_ref()
    }

    /// Returns the optional job-level concurrency request.
    #[must_use]
    pub const fn concurrency(&self) -> Option<&LogicalConcurrencyTemplate> {
        self.concurrency.as_ref()
    }

    /// Returns the job environment layer evaluated during execution.
    #[must_use]
    pub const fn environment(&self) -> &TemplateValueMap {
        &self.environment
    }

    /// Returns defaults applied only to run steps in this job.
    #[must_use]
    pub const fn run_defaults(&self) -> &LogicalRunDefaultsTemplate {
        &self.run_defaults
    }

    /// Returns the optional job timeout evaluated during activation.
    #[must_use]
    pub const fn timeout(&self) -> Option<&Located<LogicalTimeoutTemplate>> {
        self.timeout.as_ref()
    }

    /// Returns the optional activation-time continue-on-error policy.
    #[must_use]
    pub const fn continue_on_error(&self) -> Option<&Located<CompiledBooleanTemplate>> {
        self.continue_on_error.as_ref()
    }

    /// Returns declared logical-job outputs in source order.
    #[must_use]
    pub fn outputs(&self) -> &[LogicalJobOutputDefinition] {
        &self.outputs
    }

    /// Returns the optional deployment environment selection.
    #[must_use]
    pub const fn deployment(&self) -> Option<&DeploymentSelection> {
        self.deployment.as_ref()
    }

    /// Returns the closed step-job or reusable-workflow body.
    #[must_use]
    pub const fn execution(&self) -> &LogicalJobKind {
        &self.execution
    }

    /// Returns the source span covering the complete logical job.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    fn validate(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("logical job")?;
        self.validate_links(source_id)?;
        self.validate_templates(source_id, budget)?;
        self.validate_outputs(source_id, budget)?;
        self.validate_execution(source_id, budget)
    }

    fn validate_links(&self, source_id: &str) -> Result<(), WorkflowPlanError> {
        for (span, field) in [
            (self.span(), "logical job"),
            (self.key.span(), "logical job key"),
        ] {
            validate_span_source(span, source_id, field)?;
        }
        if logical_job_need_count_rejection(self.needs.len()).is_some() {
            return Err(WorkflowPlanError::LimitExceeded {
                field: "logical job needs",
                maximum: MAX_LOGICAL_JOB_NEEDS,
            });
        }
        let mut needs = BTreeSet::new();
        for dependency in &self.needs {
            validate_span_source(dependency.span(), source_id, "logical job need")?;
            if !needs.insert(dependency.value()) {
                return Err(WorkflowPlanError::DuplicateDefinition {
                    field: "logical job needs",
                    key: dependency.value().to_string(),
                });
            }
        }
        if logical_result_reference_count_rejection(self.result_references.len()).is_some() {
            return Err(WorkflowPlanError::LimitExceeded {
                field: "logical result references",
                maximum: MAX_LOGICAL_RESULT_REFERENCES,
            });
        }
        let mut references = BTreeSet::new();
        for reference in &self.result_references {
            validate_span_source(reference.span(), source_id, "logical result reference")?;
            if !references.insert(reference.value()) {
                return Err(WorkflowPlanError::DuplicateDefinition {
                    field: "logical result references",
                    key: reference.value().to_string(),
                });
            }
        }
        Ok(())
    }

    fn validate_templates(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        if let Some(name) = &self.name {
            validate_span_source(name.span(), source_id, "logical job name")?;
            name.value().validate(
                "logical job name",
                PlanEvaluationPhase::JobActivation,
                budget,
            )?;
        }
        if let Some(condition) = &self.condition {
            validate_span_source(condition.span(), source_id, "logical job condition")?;
            condition.value().validate(
                "logical job condition",
                PlanEvaluationPhase::JobActivation,
                budget,
            )?;
        }
        if let Some(strategy) = &self.strategy {
            strategy.validate(source_id, budget)?;
        }
        if let Some(permissions) = &self.permissions {
            permissions.validate(source_id)?;
        }
        if let Some(concurrency) = &self.concurrency {
            concurrency.validate(source_id, PlanEvaluationPhase::JobActivation, budget)?;
        }
        self.environment.validate(
            source_id,
            "logical job environment",
            PlanEvaluationPhase::JobExecution,
            budget,
        )?;
        self.run_defaults
            .validate(source_id, PlanEvaluationPhase::JobExecution, budget)?;
        if let Some(timeout) = &self.timeout {
            validate_span_source(timeout.span(), source_id, "logical job timeout")?;
            timeout.value().validate(
                "logical job timeout",
                PlanEvaluationPhase::JobActivation,
                budget,
            )?;
        }
        if let Some(value) = &self.continue_on_error {
            validate_span_source(value.span(), source_id, "logical job continue-on-error")?;
            value.value().validate(
                "logical job continue-on-error",
                PlanEvaluationPhase::JobActivation,
                budget,
            )?;
        }
        Ok(())
    }

    fn validate_outputs(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        if logical_job_output_count_rejection(self.outputs.len()).is_some() {
            return Err(WorkflowPlanError::LimitExceeded {
                field: "logical job outputs",
                maximum: MAX_LOGICAL_JOB_OUTPUTS,
            });
        }
        let mut outputs = BTreeSet::new();
        for output in &self.outputs {
            if !outputs.insert(output.key().value()) {
                return Err(WorkflowPlanError::DuplicateDefinition {
                    field: "logical job outputs",
                    key: output.key().value().to_string(),
                });
            }
            output.validate(
                source_id,
                self.key.value(),
                &self.execution,
                self.strategy.is_some(),
                budget,
            )?;
        }
        if let Some(deployment) = &self.deployment {
            deployment.validate(source_id, budget)?;
        }
        Ok(())
    }

    fn validate_execution(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        match &self.execution {
            LogicalJobKind::Steps(steps) => steps.validate(source_id, self.key.value(), budget),
            LogicalJobKind::ReusableWorkflow(invocation) => {
                for (present, field) in [
                    (!self.environment.is_empty(), "environment"),
                    (!self.run_defaults.is_empty(), "run defaults"),
                    (self.timeout.is_some(), "timeout"),
                    (self.continue_on_error.is_some(), "continue-on-error"),
                    (self.deployment.is_some(), "deployment"),
                ] {
                    if present {
                        return Err(WorkflowPlanError::IncompatibleLogicalJobField {
                            job: self.key.value().to_string(),
                            field,
                        });
                    }
                }
                invocation.validate(source_id, budget)
            }
        }
    }
}

impl LogicalJobTemplateBuilder {
    /// Sets the optional activation-time display-name template.
    #[must_use]
    pub fn name(mut self, name: Option<Located<CompiledValueTemplate>>) -> Self {
        self.name = name;
        self
    }

    /// Replaces the direct prerequisite list.
    #[must_use]
    pub fn needs(mut self, needs: Vec<Located<WorkflowJobKey>>) -> Self {
        self.needs = needs;
        self
    }

    /// Replaces the explicit prerequisite-result consumption list.
    #[must_use]
    pub fn result_references(mut self, references: Vec<Located<LogicalResultReference>>) -> Self {
        self.result_references = references;
        self
    }

    /// Sets the optional job-activation condition.
    #[must_use]
    pub fn condition(mut self, condition: Option<Located<CompiledExpressionTemplate>>) -> Self {
        self.condition = condition;
        self
    }

    /// Sets the optional matrix and activation-control strategy.
    #[must_use]
    pub fn strategy(mut self, strategy: Option<WorkflowStrategyTemplate>) -> Self {
        self.strategy = strategy;
        self
    }

    /// Sets the optional job-level authorization snapshot request.
    #[must_use]
    pub fn permissions(mut self, permissions: Option<PermissionSnapshotRequest>) -> Self {
        self.permissions = permissions;
        self
    }

    /// Sets the optional job-level concurrency request.
    #[must_use]
    pub fn concurrency(mut self, concurrency: Option<LogicalConcurrencyTemplate>) -> Self {
        self.concurrency = concurrency;
        self
    }

    /// Replaces the job environment layer.
    #[must_use]
    pub fn environment(mut self, environment: TemplateValueMap) -> Self {
        self.environment = environment;
        self
    }

    /// Replaces defaults inherited by run steps.
    #[must_use]
    pub fn run_defaults(mut self, run_defaults: LogicalRunDefaultsTemplate) -> Self {
        self.run_defaults = run_defaults;
        self
    }

    /// Sets the optional job timeout.
    #[must_use]
    pub fn timeout(mut self, timeout: Option<Located<LogicalTimeoutTemplate>>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the optional job-level continue-on-error policy.
    #[must_use]
    pub fn continue_on_error(mut self, value: Option<Located<CompiledBooleanTemplate>>) -> Self {
        self.continue_on_error = value;
        self
    }

    /// Replaces the logical-job output declarations.
    #[must_use]
    pub fn outputs(mut self, outputs: Vec<LogicalJobOutputDefinition>) -> Self {
        self.outputs = outputs;
        self
    }

    /// Sets the optional deployment environment selection.
    #[must_use]
    pub fn deployment(mut self, deployment: Option<DeploymentSelection>) -> Self {
        self.deployment = deployment;
        self
    }

    /// Validates and freezes one logical job template. Graph-wide dependency
    /// and result-reference validation occurs in [`super::WorkflowPlan`].
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowPlanError`] for invalid job-local fields.
    pub fn build(self) -> Result<LogicalJobTemplate, WorkflowPlanError> {
        let job = LogicalJobTemplate {
            key: self.key,
            source_order: self.source_order,
            name: self.name,
            needs: self.needs,
            result_references: self.result_references,
            condition: self.condition,
            strategy: self.strategy,
            permissions: self.permissions,
            concurrency: self.concurrency,
            environment: self.environment,
            run_defaults: self.run_defaults,
            timeout: self.timeout,
            continue_on_error: self.continue_on_error,
            outputs: self.outputs,
            deployment: self.deployment,
            execution: self.execution,
            span: self.span,
        };
        let mut budget = LogicalPlanBudget::new();
        job.validate(job.span().source_id(), &mut budget)?;
        Ok(job)
    }
}

/// Logical-workflow logical workflow body. The outer plan owns source/event evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalWorkflowPlan {
    invocation: Option<WorkflowInvocationContract>,
    run_name: Option<Located<CompiledValueTemplate>>,
    permissions: Option<PermissionSnapshotRequest>,
    environment: TemplateValueMap,
    run_defaults: LogicalRunDefaultsTemplate,
    concurrency: Option<LogicalConcurrencyTemplate>,
    jobs: Vec<LogicalJobTemplate>,
    span: PlanSourceSpan,
}

pub(super) struct LogicalWorkflowPlanParts {
    pub(super) invocation: Option<WorkflowInvocationContract>,
    pub(super) run_name: Option<Located<CompiledValueTemplate>>,
    pub(super) permissions: Option<PermissionSnapshotRequest>,
    pub(super) environment: TemplateValueMap,
    pub(super) run_defaults: LogicalRunDefaultsTemplate,
    pub(super) concurrency: Option<LogicalConcurrencyTemplate>,
    pub(super) jobs: Vec<LogicalJobTemplate>,
    pub(super) span: PlanSourceSpan,
}

impl LogicalWorkflowPlan {
    /// Returns the optional reusable-workflow boundary contract.
    #[must_use]
    pub const fn invocation(&self) -> Option<&WorkflowInvocationContract> {
        self.invocation.as_ref()
    }

    /// Returns the optional run name evaluated during admission.
    #[must_use]
    pub const fn run_name(&self) -> Option<&Located<CompiledValueTemplate>> {
        self.run_name.as_ref()
    }

    /// Returns the optional workflow-level authorization snapshot request.
    #[must_use]
    pub const fn permissions(&self) -> Option<&PermissionSnapshotRequest> {
        self.permissions.as_ref()
    }

    /// Returns the workflow environment layer inherited by jobs.
    #[must_use]
    pub const fn environment(&self) -> &TemplateValueMap {
        &self.environment
    }

    /// Returns workflow defaults inherited by run steps.
    #[must_use]
    pub const fn run_defaults(&self) -> &LogicalRunDefaultsTemplate {
        &self.run_defaults
    }

    /// Returns the optional workflow-level admission concurrency request.
    #[must_use]
    pub const fn concurrency(&self) -> Option<&LogicalConcurrencyTemplate> {
        self.concurrency.as_ref()
    }

    /// Returns logical jobs in canonical source order.
    #[must_use]
    pub fn jobs(&self) -> &[LogicalJobTemplate] {
        &self.jobs
    }

    /// Returns the source span covering the complete workflow body.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    pub(super) fn from_parts(parts: LogicalWorkflowPlanParts) -> Self {
        Self {
            invocation: parts.invocation,
            run_name: parts.run_name,
            permissions: parts.permissions,
            environment: parts.environment,
            run_defaults: parts.run_defaults,
            concurrency: parts.concurrency,
            jobs: parts.jobs,
            span: parts.span,
        }
    }

    pub(super) fn validate(&self, source_id: &str) -> Result<(), WorkflowPlanError> {
        let mut budget = LogicalPlanBudget::new();
        budget.charge_node("logical workflow")?;
        validate_span_source(&self.span, source_id, "logical workflow")?;
        if self.jobs.is_empty() {
            return Err(WorkflowPlanError::NoJobs);
        }
        if logical_job_count_rejection(self.jobs.len()).is_some() {
            return Err(WorkflowPlanError::LimitExceeded {
                field: "logical jobs",
                maximum: MAX_LOGICAL_JOBS,
            });
        }
        if let Some(invocation) = &self.invocation {
            invocation.validate(source_id, &mut budget)?;
        }
        if let Some(run_name) = &self.run_name {
            validate_span_source(run_name.span(), source_id, "logical workflow run name")?;
            run_name.value().validate(
                "logical workflow run name",
                PlanEvaluationPhase::Admission,
                &mut budget,
            )?;
        }
        if let Some(permissions) = &self.permissions {
            permissions.validate(source_id)?;
        }
        self.environment.validate(
            source_id,
            "logical workflow environment",
            PlanEvaluationPhase::JobExecution,
            &mut budget,
        )?;
        self.run_defaults
            .validate(source_id, PlanEvaluationPhase::JobExecution, &mut budget)?;
        if let Some(concurrency) = &self.concurrency {
            concurrency.validate(source_id, PlanEvaluationPhase::Admission, &mut budget)?;
        }

        let mut keys = BTreeSet::new();
        for (index, job) in self.jobs.iter().enumerate() {
            if usize::try_from(job.source_order()).ok() != Some(index) {
                return Err(WorkflowPlanError::NonCanonicalJobOrder);
            }
            if !keys.insert(job.key().value()) {
                return Err(WorkflowPlanError::DuplicateJob(
                    job.key().value().to_string(),
                ));
            }
            job.validate(source_id, &mut budget)?;
        }
        validate_logical_graph(&self.jobs, &keys)?;
        if let Some(invocation) = &self.invocation {
            for output in invocation.outputs() {
                for reference in output.references() {
                    validate_result_reference(reference.value(), &self.jobs)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod limit_contract_tests {
    use super::*;

    #[test]
    fn logical_job_count_limit_has_exact_boundaries() {
        assert_eq!(logical_job_count_rejection(MAX_LOGICAL_JOBS - 1), None);
        assert_eq!(logical_job_count_rejection(MAX_LOGICAL_JOBS), None);
        assert_eq!(
            logical_job_count_rejection(MAX_LOGICAL_JOBS + 1),
            Some(LogicalWorkflowLimitRejection::Jobs)
        );
    }

    #[test]
    fn logical_job_need_count_limit_has_exact_boundaries() {
        assert_eq!(
            logical_job_need_count_rejection(MAX_LOGICAL_JOB_NEEDS - 1),
            None
        );
        assert_eq!(
            logical_job_need_count_rejection(MAX_LOGICAL_JOB_NEEDS),
            None
        );
        assert_eq!(
            logical_job_need_count_rejection(MAX_LOGICAL_JOB_NEEDS + 1),
            Some(LogicalWorkflowLimitRejection::JobNeeds)
        );
    }

    #[test]
    fn logical_result_reference_count_limit_has_exact_boundaries() {
        assert_eq!(
            logical_result_reference_count_rejection(MAX_LOGICAL_RESULT_REFERENCES - 1),
            None
        );
        assert_eq!(
            logical_result_reference_count_rejection(MAX_LOGICAL_RESULT_REFERENCES),
            None
        );
        assert_eq!(
            logical_result_reference_count_rejection(MAX_LOGICAL_RESULT_REFERENCES + 1),
            Some(LogicalWorkflowLimitRejection::ResultReferences)
        );
    }

    #[test]
    fn logical_job_output_count_limit_has_exact_boundaries() {
        assert_eq!(
            logical_job_output_count_rejection(MAX_LOGICAL_JOB_OUTPUTS - 1),
            None
        );
        assert_eq!(
            logical_job_output_count_rejection(MAX_LOGICAL_JOB_OUTPUTS),
            None
        );
        assert_eq!(
            logical_job_output_count_rejection(MAX_LOGICAL_JOB_OUTPUTS + 1),
            Some(LogicalWorkflowLimitRejection::JobOutputs)
        );
    }

    #[test]
    fn logical_step_count_limit_has_exact_boundaries() {
        assert_eq!(logical_step_count_rejection(MAX_LOGICAL_STEPS - 1), None);
        assert_eq!(logical_step_count_rejection(MAX_LOGICAL_STEPS), None);
        assert_eq!(
            logical_step_count_rejection(MAX_LOGICAL_STEPS + 1),
            Some(LogicalWorkflowLimitRejection::Steps)
        );
    }

    #[test]
    fn logical_service_count_limit_has_exact_boundaries() {
        assert_eq!(
            logical_service_count_rejection(MAX_LOGICAL_SERVICES - 1),
            None
        );
        assert_eq!(logical_service_count_rejection(MAX_LOGICAL_SERVICES), None);
        assert_eq!(
            logical_service_count_rejection(MAX_LOGICAL_SERVICES + 1),
            Some(LogicalWorkflowLimitRejection::Services)
        );
    }

    #[test]
    fn logical_service_port_count_limit_has_exact_boundaries() {
        assert_eq!(
            logical_service_port_count_rejection(MAX_LOGICAL_SERVICE_PORTS - 1),
            None
        );
        assert_eq!(
            logical_service_port_count_rejection(MAX_LOGICAL_SERVICE_PORTS),
            None
        );
        assert_eq!(
            logical_service_port_count_rejection(MAX_LOGICAL_SERVICE_PORTS + 1),
            Some(LogicalWorkflowLimitRejection::ServicePorts)
        );
    }

    #[test]
    fn logical_service_option_count_limit_has_exact_boundaries() {
        assert_eq!(
            logical_service_option_count_rejection(MAX_LOGICAL_SERVICE_OPTIONS - 1),
            None
        );
        assert_eq!(
            logical_service_option_count_rejection(MAX_LOGICAL_SERVICE_OPTIONS),
            None
        );
        assert_eq!(
            logical_service_option_count_rejection(MAX_LOGICAL_SERVICE_OPTIONS + 1),
            Some(LogicalWorkflowLimitRejection::ServiceOptions)
        );
    }

    #[test]
    fn template_map_entry_count_limit_has_exact_boundaries() {
        assert_eq!(
            template_map_entry_count_rejection(MAX_TEMPLATE_MAP_ENTRIES - 1),
            None
        );
        assert_eq!(
            template_map_entry_count_rejection(MAX_TEMPLATE_MAP_ENTRIES),
            None
        );
        assert_eq!(
            template_map_entry_count_rejection(MAX_TEMPLATE_MAP_ENTRIES + 1),
            Some(LogicalWorkflowLimitRejection::TemplateMapEntries)
        );
    }

    #[test]
    fn logical_runner_label_count_limit_has_exact_boundaries() {
        assert_eq!(
            logical_runner_label_count_rejection(MAX_LOGICAL_RUNNER_LABELS - 1),
            None
        );
        assert_eq!(
            logical_runner_label_count_rejection(MAX_LOGICAL_RUNNER_LABELS),
            None
        );
        assert_eq!(
            logical_runner_label_count_rejection(MAX_LOGICAL_RUNNER_LABELS + 1),
            Some(LogicalWorkflowLimitRejection::RunnerLabels)
        );
    }

    #[test]
    fn reusable_binding_count_limit_has_exact_boundaries() {
        assert_eq!(
            reusable_binding_count_rejection(MAX_REUSABLE_BINDINGS - 1),
            None
        );
        assert_eq!(
            reusable_binding_count_rejection(MAX_REUSABLE_BINDINGS),
            None
        );
        assert_eq!(
            reusable_binding_count_rejection(MAX_REUSABLE_BINDINGS + 1),
            Some(LogicalWorkflowLimitRejection::ReusableBindings)
        );
    }

    #[test]
    fn logical_field_byte_limit_has_exact_boundaries() {
        assert_eq!(
            logical_field_byte_rejection(MAX_LOGICAL_FIELD_BYTES - 1),
            None
        );
        assert_eq!(logical_field_byte_rejection(MAX_LOGICAL_FIELD_BYTES), None);
        assert_eq!(
            logical_field_byte_rejection(MAX_LOGICAL_FIELD_BYTES + 1),
            Some(LogicalWorkflowLimitRejection::FieldBytes)
        );
    }
}

fn validate_logical_graph(
    jobs: &[LogicalJobTemplate],
    keys: &BTreeSet<&WorkflowJobKey>,
) -> Result<(), WorkflowPlanError> {
    for job in jobs {
        for dependency in job.needs() {
            if dependency.value() == job.key().value() {
                return Err(WorkflowPlanError::SelfDependency(
                    job.key().value().to_string(),
                ));
            }
            if !keys.contains(dependency.value()) {
                return Err(WorkflowPlanError::UnknownDependency {
                    job: job.key().value().to_string(),
                    dependency: dependency.value().to_string(),
                });
            }
        }
        for reference in job.result_references() {
            if !keys.contains(reference.value().job()) {
                return Err(WorkflowPlanError::UnknownResultJob {
                    job: job.key().value().to_string(),
                    dependency: reference.value().job().to_string(),
                });
            }
            if !job
                .needs()
                .iter()
                .any(|dependency| dependency.value() == reference.value().job())
            {
                return Err(WorkflowPlanError::ResultNotDependency {
                    job: job.key().value().to_string(),
                    dependency: reference.value().job().to_string(),
                });
            }
            validate_result_reference(reference.value(), jobs)?;
        }
    }
    validate_acyclic(jobs)
}

fn validate_result_reference(
    reference: &LogicalResultReference,
    jobs: &[LogicalJobTemplate],
) -> Result<(), WorkflowPlanError> {
    let Some(job) = jobs
        .iter()
        .find(|candidate| candidate.key().value() == reference.job())
    else {
        return Err(WorkflowPlanError::UnknownResultJob {
            job: "workflow output".to_owned(),
            dependency: reference.job().to_string(),
        });
    };
    if let LogicalResultValue::Output(output) = reference.value()
        && !job
            .outputs()
            .iter()
            .any(|item| item.key().value() == output)
    {
        return Err(WorkflowPlanError::UnknownResultOutput {
            job: reference.job().to_string(),
            output: output.to_string(),
        });
    }
    Ok(())
}

fn validate_acyclic(jobs: &[LogicalJobTemplate]) -> Result<(), WorkflowPlanError> {
    let mut complete = BTreeSet::new();
    let mut visiting = BTreeSet::new();
    for job in jobs {
        visit(job.key().value(), jobs, &mut visiting, &mut complete)?;
    }
    Ok(())
}

fn visit<'a>(
    key: &'a WorkflowJobKey,
    jobs: &'a [LogicalJobTemplate],
    visiting: &mut BTreeSet<&'a WorkflowJobKey>,
    complete: &mut BTreeSet<&'a WorkflowJobKey>,
) -> Result<(), WorkflowPlanError> {
    if complete.contains(key) {
        return Ok(());
    }
    if !visiting.insert(key) {
        return Err(WorkflowPlanError::DependencyCycle);
    }
    let job = jobs
        .iter()
        .find(|candidate| candidate.key().value() == key)
        .expect("dependency existence was checked");
    for dependency in job.needs() {
        visit(dependency.value(), jobs, visiting, complete)?;
    }
    visiting.remove(key);
    complete.insert(key);
    Ok(())
}
