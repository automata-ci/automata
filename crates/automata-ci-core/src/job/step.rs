//! Ordered semantic workflow steps.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{
    ExpressionProgram, JobValidationError, RuntimeBoolean, StepId, ValueSource, ValueTemplate,
    ValueTemplateError,
};

/// Positive integer retained for execution-time evaluation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum RuntimePositiveInteger {
    /// Concrete integer checked for positivity by the containing field.
    Literal {
        /// Unevaluated integer payload.
        value: u32,
    },
    /// Integer deferred to the expression runtime.
    Expression {
        /// Typed program whose result is interpreted as a positive integer.
        program: ExpressionProgram,
    },
}

impl RuntimePositiveInteger {
    /// Creates a concrete value; containing timeout validation rejects zero.
    #[must_use]
    pub const fn literal(value: u32) -> Self {
        Self::Literal { value }
    }

    /// Creates a positive integer deferred to expression evaluation.
    #[must_use]
    pub const fn expression(program: ExpressionProgram) -> Self {
        Self::Expression { program }
    }

    /// Returns the concrete integer when evaluation is not required.
    #[must_use]
    pub const fn literal_value(&self) -> Option<u32> {
        match self {
            Self::Literal { value } => Some(*value),
            Self::Expression { .. } => None,
        }
    }

    /// Returns the deferred program when the value is not literal.
    #[must_use]
    pub const fn expression_program(&self) -> Option<&ExpressionProgram> {
        match self {
            Self::Literal { .. } => None,
            Self::Expression { program } => Some(program),
        }
    }
}

/// Source unit applied after a deferred timeout value is evaluated.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTimeoutUnit {
    /// Interprets the evaluated integer directly as seconds.
    Seconds,
    /// Multiplies the evaluated integer by 60 with overflow checks.
    Minutes,
}

impl RuntimeTimeoutUnit {
    /// Returns the checked conversion factor from this source unit to seconds.
    #[must_use]
    pub const fn seconds_multiplier(self) -> u32 {
        match self {
            Self::Seconds => 1,
            Self::Minutes => 60,
        }
    }
}

/// Positive step timeout whose value may remain deferred until execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTimeoutTemplate {
    value: RuntimePositiveInteger,
    unit: RuntimeTimeoutUnit,
}

impl RuntimeTimeoutTemplate {
    /// Creates a deferred timeout from its value and source unit.
    #[must_use]
    pub const fn new(value: RuntimePositiveInteger, unit: RuntimeTimeoutUnit) -> Self {
        Self { value, unit }
    }

    /// Creates a timeout measured in seconds.
    #[must_use]
    pub const fn seconds(value: RuntimePositiveInteger) -> Self {
        Self::new(value, RuntimeTimeoutUnit::Seconds)
    }

    /// Creates a timeout measured in minutes.
    #[must_use]
    pub const fn minutes(value: RuntimePositiveInteger) -> Self {
        Self::new(value, RuntimeTimeoutUnit::Minutes)
    }

    /// Returns the concrete or expression-backed timeout value.
    #[must_use]
    pub const fn value(&self) -> &RuntimePositiveInteger {
        &self.value
    }

    /// Returns the source unit applied after value evaluation.
    #[must_use]
    pub const fn unit(&self) -> RuntimeTimeoutUnit {
        self.unit
    }

    pub(super) fn validate(&self, step_id: &StepId) -> Result<(), JobValidationError> {
        match &self.value {
            RuntimePositiveInteger::Literal { value: 0 } => {
                Err(JobValidationError::ZeroStepTimeout(step_id.clone()))
            }
            RuntimePositiveInteger::Literal { value } => value
                .checked_mul(self.unit.seconds_multiplier())
                .map(|_| ())
                .ok_or_else(|| JobValidationError::StepTimeoutScaleOverflow(step_id.clone())),
            RuntimePositiveInteger::Expression { program } => {
                program
                    .validate()
                    .map_err(|source| JobValidationError::InvalidExpression {
                        field: "step timeout",
                        source,
                    })
            }
        }
    }
}

/// One semantically ordered workflow step.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StepIr {
    id: StepId,
    name: ValueTemplate,
    condition: Option<ExpressionProgram>,
    continue_on_error: RuntimeBoolean,
    timeout: Option<RuntimeTimeoutTemplate>,
    environment: BTreeMap<String, ValueSource>,
    kind: SemanticStep,
}

impl StepIr {
    /// Creates a minimal semantic step.
    #[must_use]
    pub fn new(
        id: StepId,
        name: ValueTemplate,
        continue_on_error: RuntimeBoolean,
        kind: SemanticStep,
    ) -> Self {
        Self {
            id,
            name,
            condition: None,
            continue_on_error,
            timeout: None,
            environment: BTreeMap::new(),
            kind,
        }
    }

    /// Creates a semantic step with one bounded literal name segment.
    ///
    /// # Errors
    ///
    /// Returns [`ValueTemplateError`] when the literal exceeds the template
    /// text budget.
    pub fn new_literal_name(
        id: StepId,
        name: impl Into<String>,
        continue_on_error: RuntimeBoolean,
        kind: SemanticStep,
    ) -> Result<Self, ValueTemplateError> {
        Ok(Self::new(
            id,
            ValueTemplate::literal(name)?,
            continue_on_error,
            kind,
        ))
    }

    /// Returns the stable step identity used by results and diagnostics.
    #[must_use]
    pub const fn id(&self) -> &StepId {
        &self.id
    }

    /// Returns the execution-time display-name template.
    #[must_use]
    pub const fn name_template(&self) -> &ValueTemplate {
        &self.name
    }

    /// Returns the optional typed execution condition.
    #[must_use]
    pub const fn condition(&self) -> Option<&ExpressionProgram> {
        self.condition.as_ref()
    }

    /// Returns the literal or deferred effective-failure policy.
    #[must_use]
    pub const fn continue_on_error(&self) -> &RuntimeBoolean {
        &self.continue_on_error
    }

    /// Returns the optional positive timeout template.
    #[must_use]
    pub const fn timeout(&self) -> Option<&RuntimeTimeoutTemplate> {
        self.timeout.as_ref()
    }

    /// Returns deferred step environment values keyed canonically.
    #[must_use]
    pub const fn environment(&self) -> &BTreeMap<String, ValueSource> {
        &self.environment
    }

    /// Returns the semantic run or action operation.
    #[must_use]
    pub const fn kind(&self) -> &SemanticStep {
        &self.kind
    }

    /// Sets the typed execution condition; envelope validation rechecks it.
    #[must_use]
    pub fn with_condition(mut self, condition: ExpressionProgram) -> Self {
        self.condition = Some(condition);
        self
    }

    /// Replaces the literal or deferred `continue-on-error` policy.
    #[must_use]
    pub fn with_continue_on_error(mut self, continue_on_error: RuntimeBoolean) -> Self {
        self.continue_on_error = continue_on_error;
        self
    }

    /// Sets the step timeout; envelope validation rejects zero and overflow.
    #[must_use]
    pub fn with_timeout(mut self, timeout: RuntimeTimeoutTemplate) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Replaces the complete deferred step environment.
    #[must_use]
    pub fn with_environment(mut self, environment: BTreeMap<String, ValueSource>) -> Self {
        self.environment = environment;
        self
    }
}

/// Deferred shell selection for a run step.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum ShellTemplate {
    /// Uses the runner's platform default shell.
    Default,
    /// Resolves a supported shell by rendered name.
    Named {
        /// Execution-time shell-name template.
        value: ValueTemplate,
    },
    /// Uses a rendered command-line template supplied by the workflow.
    CommandTemplate {
        /// Execution-time shell command template.
        value: ValueTemplate,
    },
    /// Defers named-shell versus command-template classification.
    Dynamic {
        /// Value classified only after execution-time rendering.
        value: ValueTemplate,
    },
}

impl ShellTemplate {
    /// Selects the runner's platform default shell.
    #[must_use]
    pub const fn default_shell() -> Self {
        Self::Default
    }

    /// Selects a shell by execution-time rendered name.
    #[must_use]
    pub const fn named(value: ValueTemplate) -> Self {
        Self::Named { value }
    }

    /// Selects an execution-time rendered shell command template.
    #[must_use]
    pub const fn command_template(value: ValueTemplate) -> Self {
        Self::CommandTemplate { value }
    }

    /// Defers named-shell versus command-template classification until the
    /// rendered value is available at execution time.
    #[must_use]
    pub const fn dynamic(value: ValueTemplate) -> Self {
        Self::Dynamic { value }
    }

    /// Returns the deferred value for non-default shell selection.
    #[must_use]
    pub const fn value(&self) -> Option<&ValueTemplate> {
        match self {
            Self::Default => None,
            Self::Named { value } | Self::CommandTemplate { value } | Self::Dynamic { value } => {
                Some(value)
            }
        }
    }

    pub(super) fn validate(&self) -> Result<(), JobValidationError> {
        let Some(value) = self.value() else {
            return Ok(());
        };
        value
            .validate()
            .map_err(|source| JobValidationError::InvalidValueTemplate {
                field: "run shell",
                source,
            })
    }
}

/// Deferred command, shell, and working-directory values for one run step.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunValueTemplates {
    command: ValueTemplate,
    shell: ShellTemplate,
    working_directory: Option<ValueTemplate>,
}

impl RunValueTemplates {
    /// Creates required command and shell templates with no working-directory override.
    #[must_use]
    pub const fn new(command: ValueTemplate, shell: ShellTemplate) -> Self {
        Self {
            command,
            shell,
            working_directory: None,
        }
    }

    /// Sets an execution-time working-directory template for this run step.
    #[must_use]
    pub fn with_working_directory(mut self, working_directory: ValueTemplate) -> Self {
        self.working_directory = Some(working_directory);
        self
    }

    /// Returns the execution-time command template.
    #[must_use]
    pub const fn command(&self) -> &ValueTemplate {
        &self.command
    }

    /// Returns the deferred shell-selection contract.
    #[must_use]
    pub const fn shell(&self) -> &ShellTemplate {
        &self.shell
    }

    /// Returns the optional execution-time working-directory template.
    #[must_use]
    pub const fn working_directory(&self) -> Option<&ValueTemplate> {
        self.working_directory.as_ref()
    }

    pub(super) fn validate(&self) -> Result<(), JobValidationError> {
        self.command
            .validate()
            .map_err(|source| JobValidationError::InvalidValueTemplate {
                field: "run command",
                source,
            })?;
        self.shell.validate()?;
        if let Some(working_directory) = &self.working_directory {
            working_directory.validate().map_err(|source| {
                JobValidationError::InvalidValueTemplate {
                    field: "run working directory",
                    source,
                }
            })?;
        }
        Ok(())
    }
}

/// Semantic step kinds understood by the action engine.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum SemanticStep {
    /// Executes a rendered command through an admitted shell.
    Run {
        /// Deferred command, shell, and working-directory values.
        values: RunValueTemplates,
    },
    /// Resolves and executes an immutable action reference.
    Action {
        /// Local, repository, or container action identity.
        reference: ActionReference,
        /// Deferred action inputs keyed canonically.
        inputs: BTreeMap<String, ValueSource>,
    },
}

impl SemanticStep {
    /// Creates a run-step semantic operation.
    #[must_use]
    pub const fn run(values: RunValueTemplates) -> Self {
        Self::Run { values }
    }

    /// Creates an action-step semantic operation with its complete input map.
    #[must_use]
    pub fn action(reference: ActionReference, inputs: BTreeMap<String, ValueSource>) -> Self {
        Self::Action { reference, inputs }
    }
}

/// Immutable reference to a local, repository, or container action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionReference {
    /// Action content fetched from an immutable repository revision.
    Repository {
        /// Credential-free provider repository identity.
        repository: String,
        /// Immutable revision selected by planning.
        revision: String,
        /// Optional path to an action below the repository root.
        subpath: Option<String>,
    },
    /// Action resolved from the admitted workflow repository checkout.
    Local {
        /// Repository-relative action path.
        path: String,
    },
    /// Action executed from a container image reference.
    Container {
        /// Image reference subject to execution-provider admission.
        image: String,
    },
}

impl ActionReference {
    pub(super) fn validate(&self) -> Result<(), JobValidationError> {
        match self {
            Self::Repository {
                repository,
                revision,
                ..
            } => {
                if repository.trim().is_empty() {
                    return Err(JobValidationError::EmptyField("action repository"));
                }
                if revision.trim().is_empty() {
                    return Err(JobValidationError::EmptyField("action revision"));
                }
            }
            Self::Local { path } if path.trim().is_empty() => {
                return Err(JobValidationError::EmptyField("local action path"));
            }
            Self::Container { image } if image.trim().is_empty() => {
                return Err(JobValidationError::EmptyField("container action image"));
            }
            _ => {}
        }
        Ok(())
    }
}
