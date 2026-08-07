use crate::{
    BooleanValue, Concurrency, Defaults, EnvironmentVariables, Permissions, PreservedField,
    ScalarValue, SourceSpan, Spanned, Step,
};

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct JobId(pub(crate) Spanned<String>);

impl JobId {
    pub fn as_str(&self) -> &str {
        self.0.value()
    }

    pub fn span(&self) -> &SourceSpan {
        self.0.span()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Needs {
    One(Spanned<String>),
    Many(Vec<Spanned<String>>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RunnerSelection {
    Label(Spanned<String>),
    Labels {
        labels: Vec<Spanned<String>>,
        span: SourceSpan,
    },
    Group {
        group: Spanned<String>,
        labels: Vec<Spanned<String>>,
        extensions: Vec<PreservedField>,
        span: SourceSpan,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Job {
    pub(crate) name: Option<Spanned<String>>,
    pub(crate) needs: Option<Needs>,
    pub(crate) condition: Option<Spanned<String>>,
    pub(crate) permissions: Option<Permissions>,
    pub(crate) concurrency: Option<Concurrency>,
    pub(crate) environment: EnvironmentVariables,
    pub(crate) defaults: Option<Defaults>,
    pub(crate) runner: Option<RunnerSelection>,
    pub(crate) timeout_minutes: Option<ScalarValue>,
    pub(crate) continue_on_error: Option<BooleanValue>,
    pub(crate) steps: Vec<Step>,
    pub(crate) extensions: Vec<PreservedField>,
    pub(crate) span: SourceSpan,
}

impl Job {
    pub fn name(&self) -> Option<&Spanned<String>> {
        self.name.as_ref()
    }

    pub fn needs(&self) -> Option<&Needs> {
        self.needs.as_ref()
    }

    pub fn condition(&self) -> Option<&Spanned<String>> {
        self.condition.as_ref()
    }

    pub fn permissions(&self) -> Option<&Permissions> {
        self.permissions.as_ref()
    }

    pub fn concurrency(&self) -> Option<&Concurrency> {
        self.concurrency.as_ref()
    }

    pub const fn environment(&self) -> &EnvironmentVariables {
        &self.environment
    }

    pub fn defaults(&self) -> Option<&Defaults> {
        self.defaults.as_ref()
    }

    pub fn runner(&self) -> Option<&RunnerSelection> {
        self.runner.as_ref()
    }

    pub fn timeout_minutes(&self) -> Option<&ScalarValue> {
        self.timeout_minutes.as_ref()
    }

    pub fn continue_on_error(&self) -> Option<&BooleanValue> {
        self.continue_on_error.as_ref()
    }

    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }

    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct WorkflowJob {
    pub(crate) id: JobId,
    pub(crate) job: Job,
}

impl WorkflowJob {
    pub const fn id(&self) -> &JobId {
        &self.id
    }

    pub const fn job(&self) -> &Job {
        &self.job
    }
}
