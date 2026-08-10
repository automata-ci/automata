//! Bounded value templates retained for job-execution-time evaluation.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{ExpressionProgram, ExpressionProgramError};

/// Maximum number of literal/evaluation segments in one value template.
pub const MAX_VALUE_TEMPLATE_SEGMENTS: usize = 1_024;
/// Maximum aggregate UTF-8 source bytes retained by one value template.
pub const MAX_VALUE_TEMPLATE_TEXT_BYTES: usize = 16 * 1_024 * 1_024;

/// One already-parsed segment of an execution-time value template.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum ValueTemplateSegment {
    /// Text copied into the rendered value without interpretation.
    Literal {
        /// Exact UTF-8 text retained in the template.
        value: String,
    },
    /// A validated expression program evaluated by the selected runtime dialect.
    Expression {
        /// Typed program evaluated at the execution boundary.
        program: ExpressionProgram,
    },
}

impl ValueTemplateSegment {
    /// Creates one literal segment.
    #[must_use]
    pub fn literal(value: impl Into<String>) -> Self {
        Self::Literal {
            value: value.into(),
        }
    }

    /// Creates one already-validated expression segment.
    #[must_use]
    pub const fn expression(program: ExpressionProgram) -> Self {
        Self::Expression { program }
    }

    /// Returns literal text when this segment is not an expression.
    #[must_use]
    pub fn literal_value(&self) -> Option<&str> {
        match self {
            Self::Literal { value } => Some(value),
            Self::Expression { .. } => None,
        }
    }

    /// Returns the typed program when this segment is not literal text.
    #[must_use]
    pub const fn expression_program(&self) -> Option<&ExpressionProgram> {
        match self {
            Self::Literal { .. } => None,
            Self::Expression { program } => Some(program),
        }
    }
}

/// A canonical sequence of literal and expression segments rendered at execution time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ValueTemplate {
    segments: Vec<ValueTemplateSegment>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedValueTemplate {
    segments: Vec<ValueTemplateSegment>,
}

impl<'de> Deserialize<'de> for ValueTemplate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = UncheckedValueTemplate::deserialize(deserializer)?;
        Self::new(value.segments).map_err(serde::de::Error::custom)
    }
}

impl ValueTemplate {
    /// Creates and validates a canonical template.
    ///
    /// # Errors
    ///
    /// Returns [`ValueTemplateError`] when the template is empty, ambiguous,
    /// or exceeds its segment or aggregate text budget.
    pub fn new(segments: Vec<ValueTemplateSegment>) -> Result<Self, ValueTemplateError> {
        let template = Self { segments };
        template.validate()?;
        Ok(template)
    }

    /// Creates a one-segment literal template, including an empty literal value.
    ///
    /// # Errors
    ///
    /// Returns [`ValueTemplateError`] when `value` exceeds the template text budget.
    pub fn literal(value: impl Into<String>) -> Result<Self, ValueTemplateError> {
        Self::new(vec![ValueTemplateSegment::literal(value)])
    }

    /// Creates a one-segment expression template.
    ///
    /// # Errors
    ///
    /// Returns [`ValueTemplateError`] if the expression fails revalidation.
    pub fn expression(program: ExpressionProgram) -> Result<Self, ValueTemplateError> {
        Self::new(vec![ValueTemplateSegment::expression(program)])
    }

    /// Returns the canonical, nonempty segment sequence.
    #[must_use]
    pub fn segments(&self) -> &[ValueTemplateSegment] {
        &self.segments
    }

    /// Revalidates a template at an interchange or durable-storage boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ValueTemplateError`] for noncanonical segmentation, invalid
    /// expressions, or resource-limit violations.
    pub fn validate(&self) -> Result<(), ValueTemplateError> {
        if self.segments.is_empty() {
            return Err(ValueTemplateError::Empty);
        }
        if self.segments.len() > MAX_VALUE_TEMPLATE_SEGMENTS {
            return Err(ValueTemplateError::TooManySegments {
                maximum: MAX_VALUE_TEMPLATE_SEGMENTS,
            });
        }

        let mut text_bytes = 0_usize;
        let mut previous_was_literal = false;
        for segment in &self.segments {
            match segment {
                ValueTemplateSegment::Literal { value } => {
                    if previous_was_literal {
                        return Err(ValueTemplateError::AdjacentLiterals);
                    }
                    if value.is_empty() && self.segments.len() != 1 {
                        return Err(ValueTemplateError::EmptyLiteral);
                    }
                    text_bytes = text_bytes.checked_add(value.len()).ok_or(
                        ValueTemplateError::TextTooLong {
                            maximum: MAX_VALUE_TEMPLATE_TEXT_BYTES,
                        },
                    )?;
                    previous_was_literal = true;
                }
                ValueTemplateSegment::Expression { program } => {
                    program
                        .validate()
                        .map_err(ValueTemplateError::InvalidExpression)?;
                    text_bytes = text_bytes.checked_add(program.source().len()).ok_or(
                        ValueTemplateError::TextTooLong {
                            maximum: MAX_VALUE_TEMPLATE_TEXT_BYTES,
                        },
                    )?;
                    previous_was_literal = false;
                }
            }
            if text_bytes > MAX_VALUE_TEMPLATE_TEXT_BYTES {
                return Err(ValueTemplateError::TextTooLong {
                    maximum: MAX_VALUE_TEMPLATE_TEXT_BYTES,
                });
            }
        }
        Ok(())
    }
}

/// A boolean that may remain deferred until a step is about to execute.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum RuntimeBoolean {
    /// A boolean already known before execution.
    Literal {
        /// Concrete boolean value.
        value: bool,
    },
    /// A boolean deferred to the expression evaluator.
    Expression {
        /// Typed program that must evaluate to the required boolean semantics.
        program: ExpressionProgram,
    },
}

impl RuntimeBoolean {
    /// Creates an immediately available boolean value.
    #[must_use]
    pub const fn literal(value: bool) -> Self {
        Self::Literal { value }
    }

    /// Creates a boolean deferred to the expression evaluator.
    #[must_use]
    pub const fn expression(program: ExpressionProgram) -> Self {
        Self::Expression { program }
    }

    /// Returns the concrete value when evaluation is not required.
    #[must_use]
    pub const fn literal_value(&self) -> Option<bool> {
        match self {
            Self::Literal { value } => Some(*value),
            Self::Expression { .. } => None,
        }
    }

    /// Returns the deferred program when the value is not literal.
    #[must_use]
    pub const fn expression_program(&self) -> Option<&ExpressionProgram> {
        match self {
            Self::Literal { .. } => None,
            Self::Expression { program } => Some(program),
        }
    }

    pub(super) fn validate(&self) -> Result<(), ValueTemplateError> {
        match self {
            Self::Literal { .. } => Ok(()),
            Self::Expression { program } => program
                .validate()
                .map_err(ValueTemplateError::InvalidExpression),
        }
    }
}

/// A malformed or excessively large execution-time value template.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ValueTemplateError {
    /// No segment was supplied, so the template has no canonical value.
    #[error("a value template must contain at least one segment")]
    Empty,
    /// The segment count exceeded the bounded evaluation contract.
    #[error("a value template exceeds the maximum of {maximum} segments")]
    TooManySegments {
        /// Maximum accepted segment count.
        maximum: usize,
    },
    /// An empty literal appeared alongside another segment.
    #[error("an empty literal is canonical only as the sole template segment")]
    EmptyLiteral,
    /// Consecutive literals were not coalesced into canonical form.
    #[error("adjacent literal template segments must be coalesced")]
    AdjacentLiterals,
    /// Aggregate literal and expression source text exceeded its byte budget.
    #[error("a value template exceeds the maximum of {maximum} UTF-8 source bytes")]
    TextTooLong {
        /// Maximum retained UTF-8 source bytes.
        maximum: usize,
    },
    /// A nested typed expression failed its own structural validation.
    #[error("invalid value-template expression: {0}")]
    InvalidExpression(ExpressionProgramError),
}
