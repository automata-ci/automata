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

    pub fn decoded(&self) -> &str {
        &self.decoded
    }

    pub const fn resolution(&self) -> ScalarResolution {
        self.resolution
    }

    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ValueMapEntry {
    pub(crate) key: Spanned<String>,
    pub(crate) value: ScalarValue,
}

impl ValueMapEntry {
    pub fn key(&self) -> &Spanned<String> {
        &self.key
    }

    pub fn value(&self) -> &ScalarValue {
        &self.value
    }
}

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

    pub fn entries(&self) -> &[ValueMapEntry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

pub type EnvironmentVariables = ValueMap;

/// Boolean-valued GitHub fields may also hold deferred expressions.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BooleanValue {
    Literal(Spanned<bool>),
    Expression(Spanned<String>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PermissionLevel {
    Read,
    Write,
    None,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PermissionEntry {
    pub(crate) name: Spanned<String>,
    pub(crate) level: Spanned<PermissionLevel>,
}

impl PermissionEntry {
    pub fn name(&self) -> &Spanned<String> {
        &self.name
    }

    pub fn level(&self) -> &Spanned<PermissionLevel> {
        &self.level
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Permissions {
    ReadAll(SourceSpan),
    WriteAll(SourceSpan),
    Mapping {
        entries: Vec<PermissionEntry>,
        span: SourceSpan,
    },
}

impl Permissions {
    pub fn span(&self) -> &SourceSpan {
        match self {
            Self::ReadAll(span) | Self::WriteAll(span) | Self::Mapping { span, .. } => span,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConcurrencyQueue {
    Single,
    Max,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Concurrency {
    Group(Spanned<String>),
    Detailed(Box<DetailedConcurrency>),
}

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
    pub fn group(&self) -> &Spanned<String> {
        &self.group
    }

    pub fn cancel_in_progress(&self) -> Option<&BooleanValue> {
        self.cancel_in_progress.as_ref()
    }

    pub fn queue(&self) -> Option<&Spanned<ConcurrencyQueue>> {
        self.queue.as_ref()
    }

    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }

    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RunDefaults {
    pub(crate) shell: Option<Spanned<String>>,
    pub(crate) working_directory: Option<Spanned<String>>,
    pub(crate) extensions: Vec<PreservedField>,
}

impl RunDefaults {
    pub fn shell(&self) -> Option<&Spanned<String>> {
        self.shell.as_ref()
    }

    pub fn working_directory(&self) -> Option<&Spanned<String>> {
        self.working_directory.as_ref()
    }

    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Defaults {
    pub(crate) run: Option<RunDefaults>,
    pub(crate) extensions: Vec<PreservedField>,
}

impl Defaults {
    pub fn run(&self) -> Option<&RunDefaults> {
        self.run.as_ref()
    }

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
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn entry(&self) -> &YamlMappingEntry {
        &self.entry
    }
}
