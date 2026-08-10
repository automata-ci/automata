//! Versioned, unevaluated expression programs.

use std::num::NonZeroU16;

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use super::WorkflowPlanError;

/// Expression representation emitted by this build.
pub const WORKFLOW_EXPRESSION_SCHEMA_VERSION: u16 = WorkflowExpressionVersion::current().get();

/// A positive workflow-expression representation version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct WorkflowExpressionVersion(NonZeroU16);

impl WorkflowExpressionVersion {
    /// Creates a positive expression representation version.
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowPlanError::ZeroExpressionVersion`] for zero.
    pub fn new(version: u16) -> Result<Self, WorkflowPlanError> {
        NonZeroU16::new(version)
            .map(Self)
            .ok_or(WorkflowPlanError::ZeroExpressionVersion)
    }

    /// Returns the expression representation emitted by this build.
    #[must_use]
    pub const fn current() -> Self {
        Self(NonZeroU16::MIN)
    }

    /// Returns the positive numeric wire version.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl<'de> Deserialize<'de> for WorkflowExpressionVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let version = u16::deserialize(deserializer)?;
        Self::new(version).map_err(D::Error::custom)
    }
}

/// One already-delimited part of a GitHub-compatible expression template.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "source", rename_all = "snake_case")]
pub enum ExpressionSegment {
    /// Text copied without expression evaluation.
    Literal(String),
    /// Already-delimited expression source evaluated by the selected frontend.
    Evaluation(String),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedExpressionSegment {
    Literal { source: String },
    Evaluation { source: String },
}

impl<'de> Deserialize<'de> for ExpressionSegment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            match UncheckedExpressionSegment::deserialize(deserializer)? {
                UncheckedExpressionSegment::Literal { source } => Self::Literal(source),
                UncheckedExpressionSegment::Evaluation { source } => Self::Evaluation(source),
            },
        )
    }
}

impl ExpressionSegment {
    /// Returns the exact text used to reconstruct the lossless template source.
    #[must_use]
    pub fn source(&self) -> &str {
        match self {
            Self::Literal(source) | Self::Evaluation(source) => source,
        }
    }
}

/// A lossless expression template compiled into literal and evaluation segments.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedPlanExpression")]
pub struct PlanExpression {
    version: WorkflowExpressionVersion,
    source: String,
    segments: Vec<ExpressionSegment>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedPlanExpression {
    version: WorkflowExpressionVersion,
    source: String,
    segments: Vec<ExpressionSegment>,
}

impl TryFrom<UncheckedPlanExpression> for PlanExpression {
    type Error = WorkflowPlanError;

    fn try_from(value: UncheckedPlanExpression) -> Result<Self, Self::Error> {
        let expression = Self {
            version: value.version,
            source: value.source,
            segments: value.segments,
        };
        expression.validate()?;
        Ok(expression)
    }
}

impl PlanExpression {
    /// Creates the current expression representation.
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowPlanError`] when the segments are empty, contain an
    /// empty evaluation, or do not reconstruct the preserved source exactly.
    pub fn new(
        source: impl Into<String>,
        segments: Vec<ExpressionSegment>,
    ) -> Result<Self, WorkflowPlanError> {
        let expression = Self {
            version: WorkflowExpressionVersion::current(),
            source: source.into(),
            segments,
        };
        expression.validate()?;
        Ok(expression)
    }

    /// Returns the independently versioned expression representation.
    #[must_use]
    pub const fn version(&self) -> WorkflowExpressionVersion {
        self.version
    }

    /// Returns the exact original template text.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns segments whose concatenated source must equal [`Self::source`].
    #[must_use]
    pub fn segments(&self) -> &[ExpressionSegment] {
        &self.segments
    }

    pub(crate) fn validate(&self) -> Result<(), WorkflowPlanError> {
        if self.version != WorkflowExpressionVersion::current() {
            return Err(WorkflowPlanError::UnsupportedExpressionVersion {
                supported: WorkflowExpressionVersion::current().get(),
                received: self.version.get(),
            });
        }
        if self.segments.is_empty() {
            return Err(WorkflowPlanError::EmptyExpressionSegments);
        }
        if self.segments.iter().any(
            |segment| matches!(segment, ExpressionSegment::Evaluation(source) if source.trim().is_empty()),
        ) {
            return Err(WorkflowPlanError::EmptyEvaluation);
        }
        let reconstructed = self
            .segments
            .iter()
            .map(ExpressionSegment::source)
            .collect::<String>();
        if reconstructed != self.source {
            return Err(WorkflowPlanError::ExpressionSourceMismatch);
        }
        Ok(())
    }
}
