use thiserror::Error;

/// One-based source position when an error can be tied to YAML input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataLocation {
    line: usize,
    column: usize,
}

impl MetadataLocation {
    pub(crate) const fn new(line: usize, column: usize) -> Self {
        Self { line, column }
    }

    #[must_use]
    /// Returns the one-based source line.
    pub const fn line(self) -> usize {
        self.line
    }

    #[must_use]
    /// Returns the one-based source column.
    pub const fn column(self) -> usize {
        self.column
    }
}

/// Stable category for a metadata decoding failure.
///
/// Variants intentionally carry no source values. Use [`MetadataDecodeError::field`] and
/// [`MetadataDecodeError::location`] for bounded diagnostic context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MetadataDecodeErrorKind {
    /// The selected action definition is not an `action.yml` or `action.yaml` document.
    UnsupportedDefinition,
    /// The metadata bytes are not valid UTF-8.
    InvalidUtf8,
    /// The input is not exactly one structurally complete YAML document.
    InvalidYaml,
    /// A configured source, depth, node, or decoded-text limit was exceeded.
    ResourceLimit,
    /// YAML alias or anchor syntax was encountered.
    AliasOrAnchor,
    /// A YAML node uses an explicit type tag.
    ExplicitTag,
    /// A mapping repeats a key under case-insensitive comparison.
    DuplicateKey,
    /// A YAML merge key was encountered.
    MergeKey,
    /// A decoded node does not match the reviewed GitHub metadata structure.
    InvalidStructure,
    /// A required metadata field is absent or empty.
    MissingRequiredField,
    /// `runs.using` names an execution runtime outside the supported baseline.
    UnsupportedRuntime,
    /// The metadata declares the unsupported GitHub runner plugin execution form.
    UnsupportedPlugin,
    /// An entry path or Docker image reference is unsafe, ambiguous, or outside its byte bound.
    UnsafeEntryPath,
}

/// Sanitized, typed action metadata error.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("GitHub action metadata decode failed: {kind:?} at {field}")]
pub struct MetadataDecodeError {
    kind: MetadataDecodeErrorKind,
    field: String,
    location: Option<MetadataLocation>,
}

impl MetadataDecodeError {
    pub(crate) fn new(
        kind: MetadataDecodeErrorKind,
        field: impl Into<String>,
        location: Option<MetadataLocation>,
    ) -> Self {
        Self {
            kind,
            field: field.into(),
            location,
        }
    }

    #[must_use]
    /// Returns the typed failure category.
    pub const fn kind(&self) -> MetadataDecodeErrorKind {
        self.kind
    }

    #[must_use]
    /// Returns the sanitized logical field associated with the failure.
    ///
    /// Examples include `runs.main` and `yaml.depth`; metadata values are never included.
    pub fn field(&self) -> &str {
        &self.field
    }

    #[must_use]
    /// Returns the one-based YAML source position when the failure maps to an input node.
    pub const fn location(&self) -> Option<MetadataLocation> {
        self.location
    }
}
