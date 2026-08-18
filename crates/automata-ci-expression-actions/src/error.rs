use thiserror::Error;

/// Stable, secret-free expression failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubExpressionEvaluationErrorKind {
    /// Program dialect or schema is unsupported.
    UnsupportedProgram,
    /// A named value, property, or function is unavailable.
    UnavailableContext,
    /// A function received invalid arguments or data.
    InvalidOperation,
    /// Evaluation exceeded a configured resource limit.
    ResourceLimit,
    /// An extension dependency failed without exposing its diagnostics.
    Extension,
    /// The validated program violated an internal invariant.
    Internal,
}

/// Sanitized expression failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub expression evaluation failed with {kind:?}")]
pub struct GithubExpressionEvaluationError {
    kind: GithubExpressionEvaluationErrorKind,
}

impl GithubExpressionEvaluationError {
    pub(crate) const fn new(kind: GithubExpressionEvaluationErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(self) -> GithubExpressionEvaluationErrorKind {
        self.kind
    }
}
