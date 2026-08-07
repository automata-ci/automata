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
    pub const fn line(self) -> usize {
        self.line
    }

    #[must_use]
    pub const fn column(self) -> usize {
        self.column
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MetadataDecodeErrorKind {
    UnsupportedDefinition,
    InvalidUtf8,
    InvalidYaml,
    ResourceLimit,
    AliasOrAnchor,
    ExplicitTag,
    DuplicateKey,
    MergeKey,
    InvalidStructure,
    MissingRequiredField,
    UnsupportedRuntime,
    UnsupportedPlugin,
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
    pub const fn kind(&self) -> MetadataDecodeErrorKind {
        self.kind
    }

    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }

    #[must_use]
    pub const fn location(&self) -> Option<MetadataLocation> {
        self.location
    }
}
