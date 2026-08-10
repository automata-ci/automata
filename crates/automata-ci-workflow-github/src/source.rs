use std::{error::Error, fmt, sync::Arc};

/// Stable identity of one source file within a source-level plan.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceId(Arc<str>);

impl SourceId {
    /// Creates an identifier. Callers should use a repository-relative path or another stable key.
    pub fn new(value: impl Into<Arc<str>>) -> Self {
        Self(value.into())
    }

    /// Returns the stable identifier text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Where workflow text came from. No filesystem or network access is implied by this value.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SourceOrigin {
    /// Source captured from one exact repository revision and path.
    Repository {
        /// Stable repository identity supplied by the source adapter.
        repository: Arc<str>,
        /// Immutable source revision; callers should use an exact commit identifier.
        revision: Arc<str>,
        /// Repository-relative path of the workflow file.
        path: Arc<str>,
    },
    /// Source read from a local path outside provider admission.
    LocalPath {
        /// Display-safe local source path.
        path: Arc<str>,
    },
    /// Synthetic or caller-owned source held only in memory.
    Memory {
        /// Stable display name for the in-memory source.
        name: Arc<str>,
    },
}

/// Identity and origin evidence attached to a parsed source.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SourceProvenance {
    id: SourceId,
    origin: SourceOrigin,
}

impl SourceProvenance {
    /// Creates provenance from an explicit source identity and origin evidence.
    #[must_use]
    pub fn new(id: SourceId, origin: SourceOrigin) -> Self {
        Self { id, origin }
    }

    /// Creates provenance for synthetic source held in memory.
    #[must_use]
    pub fn memory(name: impl Into<Arc<str>>) -> Self {
        let name = name.into();
        Self {
            id: SourceId::new(Arc::clone(&name)),
            origin: SourceOrigin::Memory { name },
        }
    }

    /// Returns the stable identity referenced by every source span.
    pub fn id(&self) -> &SourceId {
        &self.id
    }

    /// Returns the immutable evidence describing where the source originated.
    pub fn origin(&self) -> &SourceOrigin {
        &self.origin
    }
}

/// A one-based line and column plus a zero-based UTF-8 byte offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SourceLocation {
    pub(crate) byte_offset: usize,
    pub(crate) line: usize,
    pub(crate) column: usize,
}

impl SourceLocation {
    pub(crate) const fn new(byte_offset: usize, line: usize, column: usize) -> Self {
        Self {
            byte_offset,
            line,
            column,
        }
    }

    /// Creates a source coordinate with one-based line and column values.
    ///
    /// # Errors
    ///
    /// Returns an error when either display coordinate is zero.
    pub const fn try_new(
        byte_offset: usize,
        line: usize,
        column: usize,
    ) -> Result<Self, SourceModelError> {
        if line == 0 {
            return Err(SourceModelError::ZeroLine);
        }
        if column == 0 {
            return Err(SourceModelError::ZeroColumn);
        }
        Ok(Self::new(byte_offset, line, column))
    }

    /// Returns the zero-based UTF-8 byte offset.
    pub const fn byte_offset(self) -> usize {
        self.byte_offset
    }

    /// Returns the one-based display line.
    pub const fn line(self) -> usize {
        self.line
    }

    /// Returns the one-based display column.
    pub const fn column(self) -> usize {
        self.column
    }
}

/// A half-open byte range in a particular source.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SourceSpan {
    pub(crate) source_id: SourceId,
    pub(crate) start: SourceLocation,
    pub(crate) end: SourceLocation,
}

impl SourceSpan {
    pub(crate) fn new(source_id: SourceId, start: SourceLocation, end: SourceLocation) -> Self {
        Self {
            source_id,
            start,
            end,
        }
    }

    pub(crate) fn empty(source_id: SourceId, location: SourceLocation) -> Self {
        Self::new(source_id, location, location)
    }

    /// Creates a half-open span whose end cannot precede its start.
    ///
    /// # Errors
    ///
    /// Returns an error when the end byte offset precedes the start offset.
    pub fn try_new(
        source_id: SourceId,
        start: SourceLocation,
        end: SourceLocation,
    ) -> Result<Self, SourceModelError> {
        if end.byte_offset < start.byte_offset {
            return Err(SourceModelError::ReversedSpan);
        }
        Ok(Self::new(source_id, start, end))
    }

    /// Returns the identity of the source containing this range.
    pub fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    /// Returns the inclusive start coordinate of the half-open range.
    pub const fn start(&self) -> SourceLocation {
        self.start
    }

    /// Returns the exclusive end coordinate of the half-open range.
    pub const fn end(&self) -> SourceLocation {
        self.end
    }

    /// Returns the half-open UTF-8 byte range within the source.
    pub fn byte_range(&self) -> std::ops::Range<usize> {
        self.start.byte_offset..self.end.byte_offset
    }

    /// Returns whether this span encloses `other` in the same source.
    pub fn contains(&self, other: &Self) -> bool {
        self.source_id == other.source_id
            && self.start.byte_offset <= other.start.byte_offset
            && self.end.byte_offset >= other.end.byte_offset
    }
}

/// A value retaining the exact source range that produced it.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Spanned<T> {
    pub(crate) value: T,
    pub(crate) span: SourceSpan,
}

impl<T> Spanned<T> {
    /// Associates a value with the exact source range that produced it.
    #[must_use]
    pub fn new(value: T, span: SourceSpan) -> Self {
        Self { value, span }
    }

    /// Returns the source-derived value.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Returns the exact source range that produced the value.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Immutable workflow source. Keeping the original text makes parsing loss-aware.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SourceFile {
    provenance: SourceProvenance,
    text: Arc<str>,
}

impl SourceFile {
    /// Retains immutable source text together with its origin evidence.
    #[must_use]
    pub fn new(provenance: SourceProvenance, text: impl Into<Arc<str>>) -> Self {
        Self {
            provenance,
            text: text.into(),
        }
    }

    /// Returns the source identity and immutable origin evidence.
    pub fn provenance(&self) -> &SourceProvenance {
        &self.provenance
    }

    /// Returns the exact retained UTF-8 source text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns the text covered by a valid span from this exact source.
    ///
    /// A foreign source identity, non-character boundary, or out-of-range span
    /// returns `None` rather than slicing unrelated bytes.
    pub fn slice(&self, span: &SourceSpan) -> Option<&str> {
        if span.source_id != *self.provenance.id() {
            return None;
        }
        self.text.get(span.byte_range())
    }
}

/// Invalid source coordinate or range supplied by a frontend adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceModelError {
    /// A source location used zero for its one-based line.
    ZeroLine,
    /// A source location used zero for its one-based column.
    ZeroColumn,
    /// A span's end byte offset preceded its start.
    ReversedSpan,
}

impl fmt::Display for SourceModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroLine => "source line must be one-based",
            Self::ZeroColumn => "source column must be one-based",
            Self::ReversedSpan => "source span end must not precede its start",
        })
    }
}

impl Error for SourceModelError {}
