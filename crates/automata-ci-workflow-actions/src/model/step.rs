use crate::{
    BooleanValue, EnvironmentVariables, PreservedField, ScalarValue, SourceSpan, Spanned, ValueMap,
};

/// Canonical source-bound identifier of one workflow step.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct StepId(pub(crate) Spanned<String>);

impl StepId {
    /// Returns the decoded step identifier.
    pub fn as_str(&self) -> &str {
        self.0.value()
    }

    /// Returns the exact source span covering the identifier.
    pub fn span(&self) -> &SourceSpan {
        self.0.span()
    }
}

/// Source model for a shell/script step.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RunStep {
    pub(crate) script: Spanned<String>,
    pub(crate) shell: Option<Spanned<String>>,
    pub(crate) working_directory: Option<Spanned<String>>,
}

impl RunStep {
    /// Returns the source-bound script text.
    pub const fn script(&self) -> &Spanned<String> {
        &self.script
    }

    /// Returns the explicit shell expression or literal, if configured.
    pub fn shell(&self) -> Option<&Spanned<String>> {
        self.shell.as_ref()
    }

    /// Returns the explicit working directory, if configured.
    pub fn working_directory(&self) -> Option<&Spanned<String>> {
        self.working_directory.as_ref()
    }
}

/// Source model for a step that invokes an action reference.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ActionStep {
    /// Raw action reference. Fetching and resolving it belongs to an action resolver adapter.
    pub(crate) reference: Spanned<String>,
    pub(crate) inputs: ValueMap,
}

impl ActionStep {
    /// Returns the unresolved action reference exactly as decoded from source.
    ///
    /// Fetching and pin validation belong to the action resolver, not this frontend.
    pub const fn reference(&self) -> &Spanned<String> {
        &self.reference
    }

    /// Returns action inputs in source order without evaluating expressions.
    pub const fn inputs(&self) -> &ValueMap {
        &self.inputs
    }
}

/// Mutually exclusive execution form of one workflow step.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StepExecution {
    /// Execute a shell or script body.
    Run(RunStep),
    /// Resolve and execute an external or local action reference.
    Action(ActionStep),
}

/// Complete source-preserving GitHub workflow step.
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
    /// Returns the step identifier, if explicitly configured.
    pub fn id(&self) -> Option<&StepId> {
        self.id.as_ref()
    }

    /// Returns the display name, if explicitly configured.
    pub fn name(&self) -> Option<&Spanned<String>> {
        self.name.as_ref()
    }

    /// Returns raw conditional text for the bounded expression compiler.
    pub fn condition(&self) -> Option<&Spanned<String>> {
        self.condition.as_ref()
    }

    /// Returns the script or action execution form, if one decoded successfully.
    pub fn execution(&self) -> Option<&StepExecution> {
        self.execution.as_ref()
    }

    /// Returns step-local environment entries in source order.
    pub const fn environment(&self) -> &EnvironmentVariables {
        &self.environment
    }

    /// Returns the literal or deferred continue-on-error policy, if configured.
    pub fn continue_on_error(&self) -> Option<&BooleanValue> {
        self.continue_on_error.as_ref()
    }

    /// Returns the unevaluated timeout-minutes scalar, if configured.
    pub fn timeout_minutes(&self) -> Option<&ScalarValue> {
        self.timeout_minutes.as_ref()
    }

    /// Returns fields preserved from source but unsupported by current compilation.
    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }

    /// Returns the exact source span covering the complete step mapping.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}
