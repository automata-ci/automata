use crate::SourceSpan;

/// Which frontend stage rejected or cannot yet interpret input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DiagnosticKind {
    Syntax,
    Semantic,
    Unsupported,
    ResourceLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DiagnosticSeverity {
    Warning,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RelatedDiagnostic {
    message: String,
    span: SourceSpan,
}

impl RelatedDiagnostic {
    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Structured diagnostic suitable for a CLI, API, editor, or web UI.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Diagnostic {
    pub(crate) kind: DiagnosticKind,
    pub(crate) severity: DiagnosticSeverity,
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) primary_span: SourceSpan,
    pub(crate) related: Vec<RelatedDiagnostic>,
}

impl Diagnostic {
    /// Creates an error diagnostic for a frontend stage.
    #[must_use]
    pub fn error(
        kind: DiagnosticKind,
        code: impl Into<String>,
        message: impl Into<String>,
        primary_span: SourceSpan,
    ) -> Self {
        Self {
            kind,
            severity: DiagnosticSeverity::Error,
            code: code.into(),
            message: message.into(),
            primary_span,
            related: Vec::new(),
        }
    }

    /// Creates a warning diagnostic for a frontend stage.
    #[must_use]
    pub fn warning(
        kind: DiagnosticKind,
        code: impl Into<String>,
        message: impl Into<String>,
        primary_span: SourceSpan,
    ) -> Self {
        Self {
            kind,
            severity: DiagnosticSeverity::Warning,
            code: code.into(),
            message: message.into(),
            primary_span,
            related: Vec::new(),
        }
    }

    /// Adds a related source location to this diagnostic.
    #[must_use]
    pub fn with_related(mut self, message: impl Into<String>, span: SourceSpan) -> Self {
        self.related.push(RelatedDiagnostic {
            message: message.into(),
            span,
        });
        self
    }

    pub const fn kind(&self) -> DiagnosticKind {
        self.kind
    }

    pub const fn severity(&self) -> DiagnosticSeverity {
        self.severity
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn primary_span(&self) -> &SourceSpan {
        &self.primary_span
    }

    pub fn related(&self) -> &[RelatedDiagnostic] {
        &self.related
    }
}
