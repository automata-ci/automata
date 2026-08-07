//! Serializable source and event evidence retained by a compiled plan.

use serde::{Deserialize, Serialize};

/// One source coordinate: a zero-based byte offset and one-based display position.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(try_from = "UncheckedPlanSourceLocation")]
pub struct PlanSourceLocation {
    byte_offset: u64,
    line: u32,
    column: u32,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedPlanSourceLocation {
    byte_offset: u64,
    line: u32,
    column: u32,
}

impl TryFrom<UncheckedPlanSourceLocation> for PlanSourceLocation {
    type Error = super::WorkflowPlanError;

    fn try_from(value: UncheckedPlanSourceLocation) -> Result<Self, Self::Error> {
        Self::new(value.byte_offset, value.line, value.column)
    }
}

impl PlanSourceLocation {
    /// Creates a valid source coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`super::WorkflowPlanError`] when line or column is zero.
    pub fn new(byte_offset: u64, line: u32, column: u32) -> Result<Self, super::WorkflowPlanError> {
        if line == 0 || column == 0 {
            return Err(super::WorkflowPlanError::InvalidSourceLocation);
        }
        Ok(Self {
            byte_offset,
            line,
            column,
        })
    }

    #[must_use]
    pub const fn byte_offset(self) -> u64 {
        self.byte_offset
    }

    #[must_use]
    pub const fn line(self) -> u32 {
        self.line
    }

    #[must_use]
    pub const fn column(self) -> u32 {
        self.column
    }
}

/// Half-open source range associated with one source identity.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(try_from = "UncheckedPlanSourceSpan")]
pub struct PlanSourceSpan {
    source_id: String,
    start: PlanSourceLocation,
    end: PlanSourceLocation,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedPlanSourceSpan {
    source_id: String,
    start: PlanSourceLocation,
    end: PlanSourceLocation,
}

impl TryFrom<UncheckedPlanSourceSpan> for PlanSourceSpan {
    type Error = super::WorkflowPlanError;

    fn try_from(value: UncheckedPlanSourceSpan) -> Result<Self, Self::Error> {
        Self::new(value.source_id, value.start, value.end)
    }
}

impl PlanSourceSpan {
    /// Creates a range whose end cannot precede its start.
    ///
    /// # Errors
    ///
    /// Returns [`super::WorkflowPlanError`] for an empty source identity or a
    /// reversed byte range.
    pub fn new(
        source_id: impl Into<String>,
        start: PlanSourceLocation,
        end: PlanSourceLocation,
    ) -> Result<Self, super::WorkflowPlanError> {
        let source_id = source_id.into();
        if source_id.trim().is_empty() {
            return Err(super::WorkflowPlanError::EmptyField("source span identity"));
        }
        if end.byte_offset < start.byte_offset {
            return Err(super::WorkflowPlanError::ReversedSourceSpan);
        }
        Ok(Self {
            source_id,
            start,
            end,
        })
    }

    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    #[must_use]
    pub const fn start(&self) -> PlanSourceLocation {
        self.start
    }

    #[must_use]
    pub const fn end(&self) -> PlanSourceLocation {
        self.end
    }
}

/// A semantic value and the exact source range that produced it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Located<T> {
    value: T,
    span: PlanSourceSpan,
}

impl<T> Located<T> {
    #[must_use]
    pub const fn new(value: T, span: PlanSourceSpan) -> Self {
        Self { value, span }
    }

    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }

    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    #[must_use]
    pub fn into_value(self) -> T {
        self.value
    }
}

/// Provider-neutral source origin. It records evidence and grants no I/O authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum PlanSourceOrigin {
    Repository {
        repository: String,
        revision: String,
        path: String,
    },
    LocalPath {
        path: String,
    },
    Memory {
        name: String,
    },
}

/// Source frontend and origin evidence retained in the durable plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSourceProvenance {
    provider: String,
    source_id: String,
    origin: PlanSourceOrigin,
}

impl WorkflowSourceProvenance {
    #[must_use]
    pub fn new(
        provider: impl Into<String>,
        source_id: impl Into<String>,
        origin: PlanSourceOrigin,
    ) -> Self {
        Self {
            provider: provider.into(),
            source_id: source_id.into(),
            origin,
        }
    }

    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    #[must_use]
    pub const fn origin(&self) -> &PlanSourceOrigin {
        &self.origin
    }
}

/// Identity of the event payload that selected this workflow definition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowEventProvenance {
    provider: String,
    name: String,
    delivery_id: Option<String>,
    commit_sha: Option<String>,
    git_ref: Option<String>,
    configured_trigger_span: Option<PlanSourceSpan>,
}

impl WorkflowEventProvenance {
    #[must_use]
    pub fn new(provider: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            name: name.into(),
            delivery_id: None,
            commit_sha: None,
            git_ref: None,
            configured_trigger_span: None,
        }
    }

    #[must_use]
    pub fn with_delivery_id(mut self, delivery_id: impl Into<String>) -> Self {
        self.delivery_id = Some(delivery_id.into());
        self
    }

    #[must_use]
    pub fn with_commit_sha(mut self, commit_sha: impl Into<String>) -> Self {
        self.commit_sha = Some(commit_sha.into());
        self
    }

    #[must_use]
    pub fn with_git_ref(mut self, git_ref: impl Into<String>) -> Self {
        self.git_ref = Some(git_ref.into());
        self
    }

    #[must_use]
    pub fn with_configured_trigger_span(mut self, span: PlanSourceSpan) -> Self {
        self.configured_trigger_span = Some(span);
        self
    }

    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn delivery_id(&self) -> Option<&str> {
        self.delivery_id.as_deref()
    }

    #[must_use]
    pub fn commit_sha(&self) -> Option<&str> {
        self.commit_sha.as_deref()
    }

    #[must_use]
    pub fn git_ref(&self) -> Option<&str> {
        self.git_ref.as_deref()
    }

    #[must_use]
    pub const fn configured_trigger_span(&self) -> Option<&PlanSourceSpan> {
        self.configured_trigger_span.as_ref()
    }
}
