use crate::SourceSpan;

/// Which frontend stage rejected or cannot yet interpret input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DiagnosticKind {
    /// The YAML token or document structure is invalid.
    Syntax,
    /// The YAML is valid but violates the GitHub workflow data model.
    Semantic,
    /// The source uses valid GitHub syntax that this current dialect cannot compile.
    Unsupported,
    /// A configured source, structure, or expression bound was exceeded.
    ResourceLimit,
}

impl DiagnosticKind {
    /// Returns the stable machine-readable stage name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Syntax => "syntax",
            Self::Semantic => "semantic",
            Self::Unsupported => "unsupported",
            Self::ResourceLimit => "resource_limit",
        }
    }
}

/// Whether a diagnostic prevents the source plan from being accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DiagnosticSeverity {
    /// The source can still be accepted, subject to any other diagnostics.
    Warning,
    /// The source cannot be accepted by the relevant frontend stage.
    Error,
}

impl DiagnosticSeverity {
    /// Returns the stable machine-readable severity name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

/// A secondary, source-bound location that provides context for a diagnostic.
///
/// Related diagnostics retain a sanitized message and source coordinates, not
/// provider responses, credentials, or evaluated runtime values.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RelatedDiagnostic {
    message: String,
    span: SourceSpan,
}

impl RelatedDiagnostic {
    /// Returns the sanitized explanatory message for this related location.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the exact source span related to the primary diagnostic.
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

    /// Returns the frontend stage or limit category that emitted the diagnostic.
    pub const fn kind(&self) -> DiagnosticKind {
        self.kind
    }

    /// Returns whether this diagnostic is a warning or an error.
    pub const fn severity(&self) -> DiagnosticSeverity {
        self.severity
    }

    /// Returns the stable, machine-readable diagnostic code.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the sanitized human-readable diagnostic message.
    ///
    /// Messages describe source-shape failures and must not contain credentials,
    /// provider response bodies, or evaluated secret values.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the exact source span at which the diagnostic originated.
    pub fn primary_span(&self) -> &SourceSpan {
        &self.primary_span
    }

    /// Returns any secondary source locations associated with the diagnostic.
    pub fn related(&self) -> &[RelatedDiagnostic] {
        &self.related
    }
}
