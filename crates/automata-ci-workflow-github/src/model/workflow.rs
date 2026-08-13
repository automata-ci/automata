use crate::{
    Concurrency, Defaults, EnvironmentVariables, Permissions, PreservedField, SourceFile,
    SourceSpan, Spanned, TriggerSet, WorkflowJob, YamlDocument,
};

/// Complete GitHub workflow model decoded from one exact YAML document.
///
/// Values and expressions remain source-level. This type is not scheduler IR;
/// event selection and provider-neutral lowering occur in the compiler.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct GithubWorkflow {
    pub(crate) name: Option<Spanned<String>>,
    pub(crate) run_name: Option<Spanned<String>>,
    pub(crate) triggers: Option<TriggerSet>,
    pub(crate) permissions: Option<Permissions>,
    pub(crate) environment: EnvironmentVariables,
    pub(crate) defaults: Option<Defaults>,
    pub(crate) concurrency: Option<Concurrency>,
    pub(crate) jobs: Vec<WorkflowJob>,
    pub(crate) extensions: Vec<PreservedField>,
    pub(crate) span: SourceSpan,
}

impl GithubWorkflow {
    /// Returns the workflow display name, if configured.
    pub fn name(&self) -> Option<&Spanned<String>> {
        self.name.as_ref()
    }

    /// Returns the source-level dynamic run name, if configured.
    pub fn run_name(&self) -> Option<&Spanned<String>> {
        self.run_name.as_ref()
    }

    /// Returns the configured event trigger set, if present.
    pub fn triggers(&self) -> Option<&TriggerSet> {
        self.triggers.as_ref()
    }

    /// Returns the workflow-level GitHub token permission request, if present.
    pub fn permissions(&self) -> Option<&Permissions> {
        self.permissions.as_ref()
    }

    /// Returns workflow-level environment entries in source order.
    pub const fn environment(&self) -> &EnvironmentVariables {
        &self.environment
    }

    /// Returns workflow-level execution defaults, if configured.
    pub fn defaults(&self) -> Option<&Defaults> {
        self.defaults.as_ref()
    }

    /// Returns workflow-level concurrency policy, if configured.
    pub fn concurrency(&self) -> Option<&Concurrency> {
        self.concurrency.as_ref()
    }

    /// Returns decoded jobs in source order.
    pub fn jobs(&self) -> &[WorkflowJob] {
        &self.jobs
    }

    /// Returns fields retained from source but unsupported by current compilation.
    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }

    /// Returns the exact source span covering the workflow mapping.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Source-level output. It deliberately is not scheduler or runner IR.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct GithubWorkflowSourcePlan {
    pub(crate) source: SourceFile,
    pub(crate) document: YamlDocument,
    pub(crate) workflow: GithubWorkflow,
}

impl GithubWorkflowSourcePlan {
    /// Returns the exact immutable source text and origin evidence.
    pub const fn source(&self) -> &SourceFile {
        &self.source
    }

    /// Returns the loss-aware YAML document retained for exact source evidence.
    pub const fn document(&self) -> &YamlDocument {
        &self.document
    }

    /// Returns the semantically decoded GitHub workflow source model.
    pub const fn workflow(&self) -> &GithubWorkflow {
        &self.workflow
    }
}
