use crate::{BooleanValue, PreservedField, ScalarValue, SourceSpan, Spanned};

/// Source-level execution policy for a matrix job.
///
/// Values remain unevaluated here because GitHub resolves each field in a
/// provider-defined expression phase before expanding the job graph.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct JobStrategy {
    pub(crate) fail_fast: Option<BooleanValue>,
    pub(crate) max_parallel: Option<ScalarValue>,
    pub(crate) matrix: Option<StrategyMatrix>,
    pub(crate) extensions: Vec<PreservedField>,
    pub(crate) span: SourceSpan,
}

impl JobStrategy {
    /// Returns the literal or deferred fail-fast policy, if configured.
    pub fn fail_fast(&self) -> Option<&BooleanValue> {
        self.fail_fast.as_ref()
    }

    /// Returns the unevaluated maximum-parallel scalar, if configured.
    pub fn max_parallel(&self) -> Option<&ScalarValue> {
        self.max_parallel.as_ref()
    }

    /// Returns the deferred or source-mapped matrix definition, if configured.
    pub fn matrix(&self) -> Option<&StrategyMatrix> {
        self.matrix.as_ref()
    }

    /// Returns fields retained but unsupported by current compilation.
    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }

    /// Returns the exact source span covering the strategy mapping.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// A matrix supplied either as one deferred expression or as YAML source.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StrategyMatrix {
    /// A deferred expression expected to produce the complete matrix object.
    Expression(ScalarValue),
    /// A source-mapped matrix with explicit axes and include/exclude entries.
    Mapping(Box<MatrixMapping>),
}

impl StrategyMatrix {
    /// Returns the exact source span covering either matrix form.
    pub fn span(&self) -> &SourceSpan {
        match self {
            Self::Expression(expression) => expression.span(),
            Self::Mapping(mapping) => mapping.span(),
        }
    }
}

/// Matrix axes and optional include/exclude configuration lists.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MatrixMapping {
    pub(crate) dimensions: Vec<MatrixDimension>,
    pub(crate) include: Option<MatrixConfigurations>,
    pub(crate) exclude: Option<MatrixConfigurations>,
    pub(crate) extensions: Vec<PreservedField>,
    pub(crate) span: SourceSpan,
}

impl MatrixMapping {
    /// Returns explicit matrix axes in source order.
    pub fn dimensions(&self) -> &[MatrixDimension] {
        &self.dimensions
    }

    /// Returns include configurations, if the key was present.
    pub fn include(&self) -> Option<&MatrixConfigurations> {
        self.include.as_ref()
    }

    /// Returns exclude configurations, if the key was present.
    pub fn exclude(&self) -> Option<&MatrixConfigurations> {
        self.exclude.as_ref()
    }

    /// Returns fields retained but unsupported by current compilation.
    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }

    /// Returns the exact source span covering the matrix mapping.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// One named matrix axis.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MatrixDimension {
    pub(crate) name: Spanned<String>,
    pub(crate) values: MatrixDimensionValues,
    pub(crate) span: SourceSpan,
}

impl MatrixDimension {
    /// Returns the source-bound axis name.
    pub fn name(&self) -> &Spanned<String> {
        &self.name
    }

    /// Returns the deferred or explicit values for this axis.
    pub const fn values(&self) -> &MatrixDimensionValues {
        &self.values
    }

    /// Returns the exact source span covering the axis entry.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Values for an axis, including an expression that produces the value array.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MatrixDimensionValues {
    /// A deferred expression expected to produce the axis array.
    Expression(ScalarValue),
    /// Explicit source-ordered values for the axis.
    Sequence {
        /// Values retained without expression evaluation or coercion.
        values: Vec<MatrixValue>,
        /// Exact source span covering the sequence.
        span: SourceSpan,
    },
}

impl MatrixDimensionValues {
    /// Returns the exact source span covering either axis-value form.
    pub fn span(&self) -> &SourceSpan {
        match self {
            Self::Expression(expression) => expression.span(),
            Self::Sequence { span, .. } => span,
        }
    }
}

/// Include/exclude configurations, either listed in YAML or produced by one
/// deferred expression.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MatrixConfigurations {
    /// A deferred expression expected to produce configuration objects.
    Expression(ScalarValue),
    /// Explicit source-ordered configuration mappings.
    Sequence {
        /// Included or excluded combinations in source order.
        configurations: Vec<MatrixConfiguration>,
        /// Exact source span covering the sequence.
        span: SourceSpan,
    },
}

impl MatrixConfigurations {
    /// Returns the exact source span covering either configuration form.
    pub fn span(&self) -> &SourceSpan {
        match self {
            Self::Expression(expression) => expression.span(),
            Self::Sequence { span, .. } => span,
        }
    }
}

/// One matrix combination from an `include` or `exclude` list.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MatrixConfiguration {
    pub(crate) entries: Vec<MatrixValueEntry>,
    pub(crate) extensions: Vec<PreservedField>,
    pub(crate) span: SourceSpan,
}

impl MatrixConfiguration {
    /// Returns named values in source order.
    pub fn entries(&self) -> &[MatrixValueEntry] {
        &self.entries
    }

    /// Returns fields retained but unsupported by current compilation.
    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }

    /// Returns the exact source span covering this configuration mapping.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// A named value inside a matrix object or configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MatrixValueEntry {
    pub(crate) key: Spanned<String>,
    pub(crate) value: MatrixValue,
    pub(crate) span: SourceSpan,
}

impl MatrixValueEntry {
    /// Returns the source-bound entry name.
    pub fn key(&self) -> &Spanned<String> {
        &self.key
    }

    /// Returns the loss-aware entry value.
    pub const fn value(&self) -> &MatrixValue {
        &self.value
    }

    /// Returns the exact source span covering this mapping entry.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// A loss-aware YAML value retained in a matrix.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MatrixValue {
    /// A scalar retained before expression evaluation or coercion.
    Scalar(ScalarValue),
    /// A nested source-ordered sequence.
    Sequence {
        /// Nested values in source order.
        values: Vec<MatrixValue>,
        /// Exact source span covering the sequence.
        span: SourceSpan,
    },
    /// A nested source-ordered mapping.
    Mapping {
        /// Named entries in source order.
        entries: Vec<MatrixValueEntry>,
        /// Fields retained but unsupported by current compilation.
        extensions: Vec<PreservedField>,
        /// Exact source span covering the mapping.
        span: SourceSpan,
    },
}

impl MatrixValue {
    /// Returns the exact source span covering this recursive value.
    pub fn span(&self) -> &SourceSpan {
        match self {
            Self::Scalar(value) => value.span(),
            Self::Sequence { span, .. } | Self::Mapping { span, .. } => span,
        }
    }
}
