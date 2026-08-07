//! Ordered semantic workflow steps.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{ExpressionProgram, JobValidationError, StepId, ValueSource};

/// One semantically ordered workflow step.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StepIr {
    id: StepId,
    name: String,
    condition: Option<ExpressionProgram>,
    continue_on_error: bool,
    timeout_seconds: Option<u32>,
    environment: BTreeMap<String, ValueSource>,
    kind: SemanticStep,
}

impl StepIr {
    /// Creates a minimal semantic step.
    #[must_use]
    pub fn new(id: StepId, name: impl Into<String>, kind: SemanticStep) -> Self {
        Self {
            id,
            name: name.into(),
            condition: None,
            continue_on_error: false,
            timeout_seconds: None,
            environment: BTreeMap::new(),
            kind,
        }
    }

    #[must_use]
    pub const fn id(&self) -> &StepId {
        &self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn condition(&self) -> Option<&ExpressionProgram> {
        self.condition.as_ref()
    }

    #[must_use]
    pub const fn continue_on_error(&self) -> bool {
        self.continue_on_error
    }

    #[must_use]
    pub const fn timeout_seconds(&self) -> Option<u32> {
        self.timeout_seconds
    }

    #[must_use]
    pub const fn environment(&self) -> &BTreeMap<String, ValueSource> {
        &self.environment
    }

    #[must_use]
    pub const fn kind(&self) -> &SemanticStep {
        &self.kind
    }

    #[must_use]
    pub fn with_condition(mut self, condition: ExpressionProgram) -> Self {
        self.condition = Some(condition);
        self
    }

    #[must_use]
    pub const fn with_continue_on_error(mut self, continue_on_error: bool) -> Self {
        self.continue_on_error = continue_on_error;
        self
    }

    #[must_use]
    pub const fn with_timeout_seconds(mut self, timeout_seconds: u32) -> Self {
        self.timeout_seconds = Some(timeout_seconds);
        self
    }

    #[must_use]
    pub fn with_environment(mut self, environment: BTreeMap<String, ValueSource>) -> Self {
        self.environment = environment;
        self
    }
}

/// Semantic step kinds understood by the action engine.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SemanticStep {
    Run {
        command: String,
        shell: ShellSpec,
        working_directory: Option<String>,
    },
    Action {
        reference: ActionReference,
        inputs: BTreeMap<String, ValueSource>,
    },
}

impl SemanticStep {
    #[must_use]
    pub fn run(command: impl Into<String>, shell: ShellSpec) -> Self {
        Self::Run {
            command: command.into(),
            shell,
            working_directory: None,
        }
    }

    #[must_use]
    pub fn action(reference: ActionReference, inputs: BTreeMap<String, ValueSource>) -> Self {
        Self::Action { reference, inputs }
    }
}

/// Shell selection without binding the IR to a process handle.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ShellSpec {
    #[default]
    Default,
    Named(String),
    CommandTemplate(String),
}

/// Immutable reference to a local, repository, or container action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionReference {
    Repository {
        repository: String,
        revision: String,
        subpath: Option<String>,
    },
    Local {
        path: String,
    },
    Container {
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
