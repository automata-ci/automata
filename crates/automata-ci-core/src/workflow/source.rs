//! Serializable source and event evidence retained by a compiled plan.

use serde::{Deserialize, Serialize};

use crate::Sha256Digest;

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

    /// Returns the zero-based UTF-8 byte offset.
    #[must_use]
    pub const fn byte_offset(self) -> u64 {
        self.byte_offset
    }

    /// Returns the one-based display line.
    #[must_use]
    pub const fn line(self) -> u32 {
        self.line
    }

    /// Returns the one-based display column.
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

    /// Returns the source identity to which both endpoints belong.
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Returns the inclusive start coordinate.
    #[must_use]
    pub const fn start(&self) -> PlanSourceLocation {
        self.start
    }

    /// Returns the exclusive end coordinate.
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
    /// Binds a semantic value to the exact source range that produced it.
    #[must_use]
    pub const fn new(value: T, span: PlanSourceSpan) -> Self {
        Self { value, span }
    }

    /// Borrows the semantic value without discarding its source evidence.
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }

    /// Returns the exact source range that produced the value.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    /// Consumes the wrapper and discards source evidence explicitly.
    #[must_use]
    pub fn into_value(self) -> T {
        self.value
    }
}

/// Provider-neutral source origin. It records evidence and grants no I/O authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum PlanSourceOrigin {
    /// Immutable repository source coordinates.
    Repository {
        /// Credential-free provider repository identity.
        repository: String,
        /// Immutable revision from which the workflow was read.
        revision: String,
        /// Repository-relative workflow source path.
        path: String,
    },
    /// Local diagnostic source path that grants no filesystem authority.
    LocalPath {
        /// Display path retained as provenance only.
        path: String,
    },
    /// In-memory source used by an embedding frontend.
    Memory {
        /// Stable diagnostic name for the in-memory source.
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
    /// Creates source evidence; complete plan validation rejects empty coordinates.
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

    /// Returns the frontend/provider namespace.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the identity shared by all nested source spans.
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Returns immutable origin evidence without granting retrieval authority.
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    selection_digest: Option<Sha256Digest>,
    configured_trigger_span: Option<PlanSourceSpan>,
}

impl WorkflowEventProvenance {
    /// Creates required provider and event-name evidence with optional fields absent.
    #[must_use]
    pub fn new(provider: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            name: name.into(),
            delivery_id: None,
            commit_sha: None,
            git_ref: None,
            selection_digest: None,
            configured_trigger_span: None,
        }
    }

    /// Attaches an authenticated provider delivery identity.
    #[must_use]
    pub fn with_delivery_id(mut self, delivery_id: impl Into<String>) -> Self {
        self.delivery_id = Some(delivery_id.into());
        self
    }

    /// Attaches the immutable commit selected by the event.
    #[must_use]
    pub fn with_commit_sha(mut self, commit_sha: impl Into<String>) -> Self {
        self.commit_sha = Some(commit_sha.into());
        self
    }

    /// Attaches the provider's full Git reference without synthesizing one when absent.
    #[must_use]
    pub fn with_git_ref(mut self, git_ref: impl Into<String>) -> Self {
        self.git_ref = Some(git_ref.into());
        self
    }

    /// Attaches the digest of provider evidence used to select this exact workflow.
    ///
    /// The digest grants no provider authority. It makes external selection
    /// evidence part of immutable logical admission and replay evidence.
    #[must_use]
    pub const fn with_selection_digest(mut self, digest: Sha256Digest) -> Self {
        self.selection_digest = Some(digest);
        self
    }

    /// Attaches source evidence for the trigger configuration that matched.
    #[must_use]
    pub fn with_configured_trigger_span(mut self, span: PlanSourceSpan) -> Self {
        self.configured_trigger_span = Some(span);
        self
    }

    /// Returns the provider namespace expected to match source provenance.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the provider event or trigger name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the authenticated delivery identity when supplied by ingress.
    #[must_use]
    pub fn delivery_id(&self) -> Option<&str> {
        self.delivery_id.as_deref()
    }

    /// Returns the immutable event commit when one was supplied.
    #[must_use]
    pub fn commit_sha(&self) -> Option<&str> {
        self.commit_sha.as_deref()
    }

    /// Returns the full event Git reference when one was supplied.
    #[must_use]
    pub fn git_ref(&self) -> Option<&str> {
        self.git_ref.as_deref()
    }

    /// Returns provider-selection evidence retained by the immutable plan.
    #[must_use]
    pub const fn selection_digest(&self) -> Option<Sha256Digest> {
        self.selection_digest
    }

    /// Returns source evidence for the configured trigger that selected the workflow.
    #[must_use]
    pub const fn configured_trigger_span(&self) -> Option<&PlanSourceSpan> {
        self.configured_trigger_span.as_ref()
    }
}

pub(super) fn validate_span_source(
    span: &PlanSourceSpan,
    source_id: &str,
    field: &'static str,
) -> Result<(), super::WorkflowPlanError> {
    if span.source_id() != source_id {
        return Err(super::WorkflowPlanError::NestedSourceMismatch { field });
    }
    Ok(())
}
