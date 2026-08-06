use crate::{
    Concurrency, Defaults, EnvironmentVariables, Permissions, PreservedField, SourceFile,
    SourceSpan, Spanned, TriggerSet, WorkflowJob, YamlDocument,
};

pub const SOURCE_PLAN_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SourcePlanVersion {
    V1,
}

impl SourcePlanVersion {
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::V1 => SOURCE_PLAN_SCHEMA_VERSION,
        }
    }
}

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
    pub fn name(&self) -> Option<&Spanned<String>> {
        self.name.as_ref()
    }

    pub fn run_name(&self) -> Option<&Spanned<String>> {
        self.run_name.as_ref()
    }

    pub fn triggers(&self) -> Option<&TriggerSet> {
        self.triggers.as_ref()
    }

    pub fn permissions(&self) -> Option<&Permissions> {
        self.permissions.as_ref()
    }

    pub const fn environment(&self) -> &EnvironmentVariables {
        &self.environment
    }

    pub fn defaults(&self) -> Option<&Defaults> {
        self.defaults.as_ref()
    }

    pub fn concurrency(&self) -> Option<&Concurrency> {
        self.concurrency.as_ref()
    }

    pub fn jobs(&self) -> &[WorkflowJob] {
        &self.jobs
    }

    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }

    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Versioned source-level output. It deliberately is not scheduler or runner IR.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct GithubWorkflowSourcePlan {
    pub(crate) version: SourcePlanVersion,
    pub(crate) source: SourceFile,
    pub(crate) document: YamlDocument,
    pub(crate) workflow: GithubWorkflow,
}

impl GithubWorkflowSourcePlan {
    pub const fn version(&self) -> SourcePlanVersion {
        self.version
    }

    pub const fn source(&self) -> &SourceFile {
        &self.source
    }

    pub const fn document(&self) -> &YamlDocument {
        &self.document
    }

    pub const fn workflow(&self) -> &GithubWorkflow {
        &self.workflow
    }
}
