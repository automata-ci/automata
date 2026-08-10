use crate::{ScalarResolution, SourceSpan, Spanned, YamlMappingEntry, YamlScalar};

/// Scalar spelling and YAML 1.2 classification before expression evaluation or coercion.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ScalarValue {
    pub(crate) decoded: String,
    pub(crate) resolution: ScalarResolution,
    pub(crate) span: SourceSpan,
}

impl ScalarValue {
    pub(crate) fn from_yaml(scalar: &YamlScalar, span: SourceSpan) -> Self {
        Self {
            decoded: scalar.decoded.clone(),
            resolution: scalar.resolution,
            span,
        }
    }

    /// Indicates text that a separate GitHub expression frontend must inspect.
    pub fn contains_expression_candidate(&self) -> bool {
        self.decoded.contains("${{")
    }

    /// Returns the decoded YAML scalar spelling before expression evaluation.
    pub fn decoded(&self) -> &str {
        &self.decoded
    }

    /// Returns the YAML 1.2 Core Schema classification of the scalar.
    pub const fn resolution(&self) -> ScalarResolution {
        self.resolution
    }

    /// Returns the exact source span covering this scalar.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// One source-ordered scalar mapping entry.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ValueMapEntry {
    pub(crate) key: Spanned<String>,
    pub(crate) value: ScalarValue,
}

impl ValueMapEntry {
    /// Returns the source-bound mapping key.
    pub fn key(&self) -> &Spanned<String> {
        &self.key
    }

    /// Returns the unevaluated scalar mapping value.
    pub fn value(&self) -> &ScalarValue {
        &self.value
    }
}

/// Source-ordered scalar mapping that retains exact value spans.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ValueMap {
    pub(crate) entries: Vec<ValueMapEntry>,
}

impl ValueMap {
    pub(crate) const fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Returns mapping entries in source order.
    pub fn entries(&self) -> &[ValueMapEntry] {
        &self.entries
    }

    /// Returns whether the mapping contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of retained mapping entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Source-level environment-variable mapping.
pub type EnvironmentVariables = ValueMap;

/// Boolean-valued GitHub fields may also hold deferred expressions.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BooleanValue {
    /// A source-bound literal Boolean.
    Literal(Spanned<bool>),
    /// A deferred GitHub expression whose result must be Boolean-compatible.
    Expression(Spanned<String>),
}

/// Closed permission level accepted by the current GitHub workflow dialect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PermissionLevel {
    /// Read-only access to the named permission scope.
    Read,
    /// Read/write access to the named permission scope.
    Write,
    /// No access to the named permission scope.
    None,
}

/// One explicit permission-scope assignment with source evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PermissionEntry {
    pub(crate) name: Spanned<String>,
    pub(crate) level: Spanned<PermissionLevel>,
}

impl PermissionEntry {
    /// Returns the source-bound GitHub permission scope name.
    pub fn name(&self) -> &Spanned<String> {
        &self.name
    }

    /// Returns the source-bound closed permission level.
    pub fn level(&self) -> &Spanned<PermissionLevel> {
        &self.level
    }
}

/// Workflow- or job-level GitHub token permission request.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Permissions {
    /// GitHub's `read-all` shorthand and its exact source span.
    ReadAll(SourceSpan),
    /// GitHub's `write-all` shorthand and its exact source span.
    WriteAll(SourceSpan),
    /// Explicit permission-scope mapping.
    Mapping {
        /// Scope assignments in source order.
        entries: Vec<PermissionEntry>,
        /// Exact source span covering the mapping.
        span: SourceSpan,
    },
}

impl Permissions {
    /// Returns the exact source span covering this permission request.
    pub fn span(&self) -> &SourceSpan {
        match self {
            Self::ReadAll(span) | Self::WriteAll(span) | Self::Mapping { span, .. } => span,
        }
    }
}

/// Queue policy for an Automata concurrency group extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConcurrencyQueue {
    /// Retain at most one queued member of the group.
    Single,
    /// Retain the maximum queue supported by the scheduler policy.
    Max,
}

/// Scalar or detailed source form of a workflow concurrency policy.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Concurrency {
    /// Scalar concurrency-group expression or literal.
    Group(Spanned<String>),
    /// Detailed concurrency policy mapping.
    Detailed(Box<DetailedConcurrency>),
}

/// Detailed concurrency group and queue policy retained from source.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DetailedConcurrency {
    pub(crate) group: Spanned<String>,
    pub(crate) cancel_in_progress: Option<BooleanValue>,
    pub(crate) queue: Option<Spanned<ConcurrencyQueue>>,
    pub(crate) extensions: Vec<PreservedField>,
    pub(crate) span: SourceSpan,
}

impl DetailedConcurrency {
    /// Returns the source-bound concurrency group expression or literal.
    pub fn group(&self) -> &Spanned<String> {
        &self.group
    }

    /// Returns the deferred or literal cancellation policy, if configured.
    pub fn cancel_in_progress(&self) -> Option<&BooleanValue> {
        self.cancel_in_progress.as_ref()
    }

    /// Returns the source-bound queue policy extension, if configured.
    pub fn queue(&self) -> Option<&Spanned<ConcurrencyQueue>> {
        self.queue.as_ref()
    }

    /// Returns fields retained but unsupported by current compilation.
    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }

    /// Returns the exact source span covering the concurrency mapping.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Defaults inherited by script-based `run` steps.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RunDefaults {
    pub(crate) shell: Option<Spanned<String>>,
    pub(crate) working_directory: Option<Spanned<String>>,
    pub(crate) extensions: Vec<PreservedField>,
}

impl RunDefaults {
    /// Returns the default shell expression or literal, if configured.
    pub fn shell(&self) -> Option<&Spanned<String>> {
        self.shell.as_ref()
    }

    /// Returns the default working directory, if configured.
    pub fn working_directory(&self) -> Option<&Spanned<String>> {
        self.working_directory.as_ref()
    }

    /// Returns fields retained but unsupported by current compilation.
    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }
}

/// Workflow- or job-level defaults mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Defaults {
    pub(crate) run: Option<RunDefaults>,
    pub(crate) extensions: Vec<PreservedField>,
}

impl Defaults {
    /// Returns defaults for script-based steps, if configured.
    pub fn run(&self) -> Option<&RunDefaults> {
        self.run.as_ref()
    }

    /// Returns fields retained but unsupported by current compilation.
    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }
}

/// A field retained losslessly in the syntax tree but not interpreted by this frontend version.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PreservedField {
    pub(crate) path: String,
    pub(crate) entry: YamlMappingEntry,
}

impl PreservedField {
    /// Returns the normalized model path identifying the unsupported field.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the exact loss-aware YAML mapping entry.
    pub fn entry(&self) -> &YamlMappingEntry {
        &self.entry
    }
}
