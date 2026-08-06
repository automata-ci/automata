use crate::{
    BooleanValue, EnvironmentVariables, PreservedField, ScalarValue, SourceSpan, Spanned, ValueMap,
};

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct StepId(pub(crate) Spanned<String>);

impl StepId {
    pub fn as_str(&self) -> &str {
        self.0.value()
    }

    pub fn span(&self) -> &SourceSpan {
        self.0.span()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RunStep {
    pub(crate) script: Spanned<String>,
    pub(crate) shell: Option<Spanned<String>>,
    pub(crate) working_directory: Option<Spanned<String>>,
}

impl RunStep {
    pub const fn script(&self) -> &Spanned<String> {
        &self.script
    }

    pub fn shell(&self) -> Option<&Spanned<String>> {
        self.shell.as_ref()
    }

    pub fn working_directory(&self) -> Option<&Spanned<String>> {
        self.working_directory.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ActionStep {
    /// Raw action reference. Fetching and resolving it belongs to an action resolver adapter.
    pub(crate) reference: Spanned<String>,
    pub(crate) inputs: ValueMap,
}

impl ActionStep {
    pub const fn reference(&self) -> &Spanned<String> {
        &self.reference
    }

    pub const fn inputs(&self) -> &ValueMap {
        &self.inputs
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StepExecution {
    Run(RunStep),
    Action(ActionStep),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Step {
    pub(crate) id: Option<StepId>,
    pub(crate) name: Option<Spanned<String>>,
    /// Raw conditional text. A separate expression frontend owns its grammar and evaluation.
    pub(crate) condition: Option<Spanned<String>>,
    pub(crate) execution: Option<StepExecution>,
    pub(crate) environment: EnvironmentVariables,
    pub(crate) continue_on_error: Option<BooleanValue>,
    pub(crate) timeout_minutes: Option<ScalarValue>,
    pub(crate) extensions: Vec<PreservedField>,
    pub(crate) span: SourceSpan,
}

impl Step {
    pub fn id(&self) -> Option<&StepId> {
        self.id.as_ref()
    }

    pub fn name(&self) -> Option<&Spanned<String>> {
        self.name.as_ref()
    }

    pub fn condition(&self) -> Option<&Spanned<String>> {
        self.condition.as_ref()
    }

    pub fn execution(&self) -> Option<&StepExecution> {
        self.execution.as_ref()
    }

    pub const fn environment(&self) -> &EnvironmentVariables {
        &self.environment
    }

    pub fn continue_on_error(&self) -> Option<&BooleanValue> {
        self.continue_on_error.as_ref()
    }

    pub fn timeout_minutes(&self) -> Option<&ScalarValue> {
        self.timeout_minutes.as_ref()
    }

    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }

    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}
