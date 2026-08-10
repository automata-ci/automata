use crate::{
    BooleanValue, Concurrency, Defaults, EnvironmentVariables, JobContainer, JobServices,
    JobStrategy, Permissions, PreservedField, ScalarValue, SourceSpan, Spanned, Step, ValueMap,
};

/// Canonical source-bound identifier of one workflow job.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct JobId(pub(crate) Spanned<String>);

impl JobId {
    /// Returns the decoded job identifier.
    pub fn as_str(&self) -> &str {
        self.0.value()
    }

    /// Returns the exact source span covering the identifier.
    pub fn span(&self) -> &SourceSpan {
        self.0.span()
    }
}

/// Source form of a job's dependency set.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Needs {
    /// One source-bound dependency identifier.
    One(Spanned<String>),
    /// Multiple dependency identifiers retained in source order.
    Many(Vec<Spanned<String>>),
}

/// Source form of GitHub's `runs-on` runner selector.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RunnerSelection {
    /// A single label or deferred expression.
    Label(Spanned<String>),
    /// An ordered sequence of runner labels.
    Labels {
        /// Labels in source order.
        labels: Vec<Spanned<String>>,
        /// Exact source span covering the sequence.
        span: SourceSpan,
    },
    /// A runner group with optional additional labels.
    Group {
        /// Source-bound runner group name.
        group: Spanned<String>,
        /// Additional labels in source order.
        labels: Vec<Spanned<String>>,
        /// Fields retained but unsupported by current compilation.
        extensions: Vec<PreservedField>,
        /// Exact source span covering the selection mapping.
        span: SourceSpan,
    },
}

/// Inputs supplied by a caller to a reusable workflow.
///
/// The mapping span is retained separately from its values so diagnostics can
/// point at the complete `with` value, including an empty mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ReusableWorkflowInputs {
    pub(crate) values: ValueMap,
    pub(crate) span: SourceSpan,
}

impl ReusableWorkflowInputs {
    /// Returns caller inputs in source order without evaluating expressions.
    pub const fn values(&self) -> &ValueMap {
        &self.values
    }

    /// Returns the exact source span covering the complete `with` mapping.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Explicit secret bindings supplied to a reusable workflow.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ReusableWorkflowSecretMap {
    pub(crate) values: ValueMap,
    pub(crate) span: SourceSpan,
}

impl ReusableWorkflowSecretMap {
    /// Returns explicit secret bindings in source order.
    ///
    /// Values remain unevaluated source expressions and must not be copied into
    /// diagnostics or operational logs.
    pub const fn values(&self) -> &ValueMap {
        &self.values
    }

    /// Returns the exact source span covering the secret mapping.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Secrets made available to a called reusable workflow.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReusableWorkflowSecrets {
    /// Pass every secret available to the caller.
    Inherit(SourceSpan),
    /// Pass only the named secret bindings.
    Mapping(ReusableWorkflowSecretMap),
}

impl ReusableWorkflowSecrets {
    /// Returns explicit bindings, or `None` for the `inherit` form.
    pub fn values(&self) -> Option<&ValueMap> {
        match self {
            Self::Inherit(_) => None,
            Self::Mapping(mapping) => Some(mapping.values()),
        }
    }

    /// Returns the exact source span covering either secrets form.
    pub fn span(&self) -> &SourceSpan {
        match self {
            Self::Inherit(span) => span,
            Self::Mapping(mapping) => mapping.span(),
        }
    }
}

/// Source-level invocation of a reusable GitHub Actions workflow.
///
/// `reference` is optional because a loss-aware source plan remains available
/// after a malformed `uses` value. The syntax tree and the spans on this node
/// preserve enough information for a caller to report or repair that source.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ReusableWorkflowCall {
    pub(crate) reference: Option<Spanned<String>>,
    pub(crate) inputs: Option<ReusableWorkflowInputs>,
    pub(crate) secrets: Option<ReusableWorkflowSecrets>,
    pub(crate) span: SourceSpan,
}

impl ReusableWorkflowCall {
    /// Returns the unresolved reusable-workflow reference, if it decoded.
    pub fn reference(&self) -> Option<&Spanned<String>> {
        self.reference.as_ref()
    }

    /// Returns caller-provided workflow inputs, if configured.
    pub fn inputs(&self) -> Option<&ReusableWorkflowInputs> {
        self.inputs.as_ref()
    }

    /// Returns the source-level secret forwarding policy, if configured.
    pub fn secrets(&self) -> Option<&ReusableWorkflowSecrets> {
        self.secrets.as_ref()
    }

    /// Returns the exact source span covering the reusable-workflow call.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Outputs published by a job for dependent jobs through the `needs` context.
///
/// This source-level representation deliberately retains expressions. Publishing
/// and evaluating the values belongs to a later workflow execution phase.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct JobOutputs {
    pub(crate) values: ValueMap,
    pub(crate) span: SourceSpan,
}

impl JobOutputs {
    /// Returns output expressions in source order without evaluating them.
    pub const fn values(&self) -> &ValueMap {
        &self.values
    }

    /// Returns the exact source span covering the outputs mapping.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// A GitHub deployment environment selected by a job.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum JobEnvironment {
    /// Scalar deployment-environment name.
    Name(Spanned<String>),
    /// Mapping form retaining a name, URL, and unsupported fields.
    Detailed(DetailedJobEnvironment),
}

impl JobEnvironment {
    /// Returns the deployment-environment name from either source form.
    pub fn name(&self) -> Option<&Spanned<String>> {
        match self {
            Self::Name(name) => Some(name),
            Self::Detailed(environment) => environment.name(),
        }
    }

    /// Returns the source-level deployment URL from the detailed form.
    pub fn url(&self) -> Option<&Spanned<String>> {
        match self {
            Self::Name(_) => None,
            Self::Detailed(environment) => environment.url(),
        }
    }

    /// Returns fields retained from a detailed form but unsupported by current compilation.
    pub fn extensions(&self) -> &[PreservedField] {
        match self {
            Self::Name(_) => &[],
            Self::Detailed(environment) => environment.extensions(),
        }
    }

    /// Returns the exact source span covering either environment form.
    pub fn span(&self) -> &SourceSpan {
        match self {
            Self::Name(name) => name.span(),
            Self::Detailed(environment) => environment.span(),
        }
    }
}

/// Mapping form of a GitHub deployment environment.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DetailedJobEnvironment {
    pub(crate) name: Option<Spanned<String>>,
    pub(crate) url: Option<Spanned<String>>,
    pub(crate) extensions: Vec<PreservedField>,
    pub(crate) span: SourceSpan,
}

impl DetailedJobEnvironment {
    /// Returns the deployment-environment name, if configured.
    pub fn name(&self) -> Option<&Spanned<String>> {
        self.name.as_ref()
    }

    /// Returns the source-level deployment URL, if configured.
    pub fn url(&self) -> Option<&Spanned<String>> {
        self.url.as_ref()
    }

    /// Returns fields retained but unsupported by current compilation.
    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }

    /// Returns the exact source span covering the environment mapping.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Complete source-preserving GitHub workflow job.
///
/// Deferred expressions, action references, and provider-owned environment
/// details are retained here; compilation validates and lowers them separately.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Job {
    pub(crate) name: Option<Spanned<String>>,
    pub(crate) needs: Option<Needs>,
    pub(crate) condition: Option<Spanned<String>>,
    pub(crate) permissions: Option<Permissions>,
    pub(crate) concurrency: Option<Concurrency>,
    pub(crate) strategy: Option<JobStrategy>,
    pub(crate) strategy_source_span: Option<SourceSpan>,
    pub(crate) environment: EnvironmentVariables,
    pub(crate) outputs: Option<JobOutputs>,
    pub(crate) outputs_source_span: Option<SourceSpan>,
    pub(crate) deployment_environment: Option<JobEnvironment>,
    pub(crate) deployment_environment_source_span: Option<SourceSpan>,
    pub(crate) defaults: Option<Defaults>,
    pub(crate) runner: Option<RunnerSelection>,
    pub(crate) container: Option<JobContainer>,
    pub(crate) container_source_span: Option<SourceSpan>,
    pub(crate) services: Option<JobServices>,
    pub(crate) services_source_span: Option<SourceSpan>,
    pub(crate) timeout_minutes: Option<ScalarValue>,
    pub(crate) continue_on_error: Option<BooleanValue>,
    pub(crate) steps: Vec<Step>,
    pub(crate) reusable_workflow_call: Option<ReusableWorkflowCall>,
    pub(crate) extensions: Vec<PreservedField>,
    pub(crate) span: SourceSpan,
}

impl Job {
    /// Returns the job display name, if configured.
    pub fn name(&self) -> Option<&Spanned<String>> {
        self.name.as_ref()
    }

    /// Returns upstream job dependencies, if configured.
    pub fn needs(&self) -> Option<&Needs> {
        self.needs.as_ref()
    }

    /// Returns raw conditional text for the bounded expression compiler.
    pub fn condition(&self) -> Option<&Spanned<String>> {
        self.condition.as_ref()
    }

    /// Returns the job-level GitHub token permission request, if configured.
    pub fn permissions(&self) -> Option<&Permissions> {
        self.permissions.as_ref()
    }

    /// Returns the job-level concurrency policy, if configured.
    pub fn concurrency(&self) -> Option<&Concurrency> {
        self.concurrency.as_ref()
    }

    /// Returns the matrix execution strategy, if configured.
    pub fn strategy(&self) -> Option<&JobStrategy> {
        self.strategy.as_ref()
    }

    pub(crate) fn strategy_source_span(&self) -> Option<&SourceSpan> {
        self.strategy_source_span.as_ref()
    }

    /// Returns job-level environment entries in source order.
    pub const fn environment(&self) -> &EnvironmentVariables {
        &self.environment
    }

    /// Returns source-level job outputs, if configured.
    pub fn outputs(&self) -> Option<&JobOutputs> {
        self.outputs.as_ref()
    }

    pub(crate) fn outputs_source_span(&self) -> Option<&SourceSpan> {
        self.outputs_source_span.as_ref()
    }

    /// Returns the GitHub deployment environment, if configured.
    pub fn deployment_environment(&self) -> Option<&JobEnvironment> {
        self.deployment_environment.as_ref()
    }

    pub(crate) fn deployment_environment_source_span(&self) -> Option<&SourceSpan> {
        self.deployment_environment_source_span.as_ref()
    }

    /// Returns job-level execution defaults, if configured.
    pub fn defaults(&self) -> Option<&Defaults> {
        self.defaults.as_ref()
    }

    /// Returns the source-level runner selection, if configured.
    pub fn runner(&self) -> Option<&RunnerSelection> {
        self.runner.as_ref()
    }

    /// Returns the job container, if configured.
    pub fn container(&self) -> Option<&JobContainer> {
        self.container.as_ref()
    }

    pub(crate) fn container_source_span(&self) -> Option<&SourceSpan> {
        self.container_source_span.as_ref()
    }

    /// Returns source-ordered service containers, if configured.
    pub fn services(&self) -> Option<&JobServices> {
        self.services.as_ref()
    }

    pub(crate) fn services_source_span(&self) -> Option<&SourceSpan> {
        self.services_source_span.as_ref()
    }

    /// Returns the unevaluated job timeout, if configured.
    pub fn timeout_minutes(&self) -> Option<&ScalarValue> {
        self.timeout_minutes.as_ref()
    }

    /// Returns the literal or deferred continue-on-error policy, if configured.
    pub fn continue_on_error(&self) -> Option<&BooleanValue> {
        self.continue_on_error.as_ref()
    }

    /// Returns execution steps in source order.
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// Returns a reusable-workflow invocation when this is a call job.
    pub fn reusable_workflow_call(&self) -> Option<&ReusableWorkflowCall> {
        self.reusable_workflow_call.as_ref()
    }

    /// Returns fields retained from source but unsupported by current compilation.
    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }

    /// Returns the exact source span covering the complete job mapping.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// One source-ordered job entry pairing its identifier with its job model.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct WorkflowJob {
    pub(crate) id: JobId,
    pub(crate) job: Job,
}

impl WorkflowJob {
    /// Returns the source-bound job identifier.
    pub const fn id(&self) -> &JobId {
        &self.id
    }

    /// Returns the decoded source-level job.
    pub const fn job(&self) -> &Job {
        &self.job
    }
}
