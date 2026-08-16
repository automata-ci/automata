use crate::SourceSpan;

/// Document-local identity assigned to a YAML anchor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct AnchorId(pub(crate) usize);

impl AnchorId {
    /// Returns the parser-assigned document-local numeric identity.
    pub const fn get(self) -> usize {
        self.0
    }
}

/// Surface style used to spell a YAML scalar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ScalarStyle {
    /// An unquoted plain scalar.
    Plain,
    /// A single-quoted scalar.
    SingleQuoted,
    /// A double-quoted scalar.
    DoubleQuoted,
    /// A literal block scalar introduced by `|`.
    Literal,
    /// A folded block scalar introduced by `>`.
    Folded,
}

/// YAML 1.2 Core Schema classification. The decoded spelling is always retained separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ScalarResolution {
    /// A string under the YAML 1.2 Core Schema.
    String,
    /// A null spelling under the YAML 1.2 Core Schema.
    Null,
    /// A Boolean spelling under the YAML 1.2 Core Schema.
    Boolean,
    /// An integer spelling under the YAML 1.2 Core Schema.
    Integer,
    /// A floating-point spelling under the YAML 1.2 Core Schema.
    Float,
}

/// Loss-aware YAML scalar retaining decoded text, surface style, and schema resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct YamlScalar {
    pub(crate) decoded: String,
    pub(crate) style: ScalarStyle,
    pub(crate) resolution: ScalarResolution,
}

impl YamlScalar {
    /// Returns whether the scalar resolves to YAML null.
    pub fn is_null(&self) -> bool {
        self.resolution == ScalarResolution::Null
    }

    /// Returns the decoded scalar text without its YAML quoting syntax.
    pub fn decoded(&self) -> &str {
        &self.decoded
    }

    /// Returns the scalar's original surface style.
    pub const fn style(&self) -> ScalarStyle {
        self.style
    }

    /// Returns the YAML 1.2 Core Schema classification.
    pub const fn resolution(&self) -> ScalarResolution {
        self.resolution
    }
}

/// Explicit YAML tag split into its handle and suffix.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct YamlTag {
    pub(crate) handle: String,
    pub(crate) suffix: String,
}

impl YamlTag {
    /// Returns the tag handle, such as `!!`.
    pub fn handle(&self) -> &str {
        &self.handle
    }

    /// Returns the tag suffix following the handle.
    pub fn suffix(&self) -> &str {
        &self.suffix
    }
}

/// YAML alias referencing a document-local anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct YamlAlias {
    pub(crate) target: AnchorId,
}

/// Provenance recorded when one alias occurrence is expanded into a derived YAML node.
///
/// The expanded node's primary [`YamlNode::span`] is always the alias-use span. The
/// definition span retained here points back to the source node copied for that use.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct YamlAliasExpansion {
    pub(crate) target: AnchorId,
    pub(crate) alias_use_span: SourceSpan,
    pub(crate) definition_span: SourceSpan,
}

impl YamlAliasExpansion {
    /// Returns the parser identity of the anchor selected at this alias occurrence.
    pub const fn target(&self) -> AnchorId {
        self.target
    }

    /// Returns the exact span of the alias token that caused this copy.
    pub const fn alias_use_span(&self) -> &SourceSpan {
        &self.alias_use_span
    }

    /// Returns the source span of the node copied from the selected definition.
    pub const fn definition_span(&self) -> &SourceSpan {
        &self.definition_span
    }
}

impl YamlAlias {
    /// Returns the document-local anchor targeted by this alias.
    pub const fn target(&self) -> AnchorId {
        self.target
    }
}

/// One loss-aware YAML mapping entry with an exact source span.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct YamlMappingEntry {
    pub(crate) key: YamlNode,
    pub(crate) value: YamlNode,
    pub(crate) span: SourceSpan,
}

impl YamlMappingEntry {
    /// Returns the key node exactly as parsed.
    pub fn key(&self) -> &YamlNode {
        &self.key
    }

    /// Returns the value node exactly as parsed.
    pub fn value(&self) -> &YamlNode {
        &self.value
    }

    /// Returns the source span covering the entire key/value entry.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Structural kind of one parsed YAML node.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum YamlNodeKind {
    /// A scalar with its decoded spelling and source style.
    Scalar(YamlScalar),
    /// An ordered YAML sequence.
    Sequence(Vec<YamlNode>),
    /// An ordered YAML mapping that retains duplicate entries for validation.
    Mapping(Vec<YamlMappingEntry>),
    /// An alias to a document-local anchor.
    Alias(YamlAlias),
}

/// Loss-aware YAML node used before GitHub workflow semantic decoding.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct YamlNode {
    pub(crate) kind: YamlNodeKind,
    pub(crate) span: SourceSpan,
    pub(crate) anchor: Option<AnchorId>,
    pub(crate) tag: Option<YamlTag>,
    pub(crate) alias_expansions: Vec<YamlAliasExpansion>,
}

impl YamlNode {
    /// Returns the scalar payload when this node is scalar.
    pub fn as_scalar(&self) -> Option<&YamlScalar> {
        match &self.kind {
            YamlNodeKind::Scalar(scalar) => Some(scalar),
            _ => None,
        }
    }

    /// Returns ordered mapping entries when this node is a mapping.
    pub fn as_mapping(&self) -> Option<&[YamlMappingEntry]> {
        match &self.kind {
            YamlNodeKind::Mapping(entries) => Some(entries),
            _ => None,
        }
    }

    /// Returns ordered sequence items when this node is a sequence.
    pub fn as_sequence(&self) -> Option<&[YamlNode]> {
        match &self.kind {
            YamlNodeKind::Sequence(items) => Some(items),
            _ => None,
        }
    }

    /// Returns the node's structural kind.
    pub fn kind(&self) -> &YamlNodeKind {
        &self.kind
    }

    /// Returns the exact source span covering this node.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }

    /// Returns the document-local anchor declared on this node, if any.
    pub const fn anchor(&self) -> Option<AnchorId> {
        self.anchor
    }

    /// Returns the explicit YAML tag applied to this node, if any.
    pub fn tag(&self) -> Option<&YamlTag> {
        self.tag.as_ref()
    }

    /// Returns the alias-expansion chain that produced this derived node.
    ///
    /// Entries are ordered from the innermost alias copy to the outermost one.
    /// Nodes in the original retained document have an empty chain.
    pub fn alias_expansions(&self) -> &[YamlAliasExpansion] {
        &self.alias_expansions
    }
}

/// One parsed YAML document with its loss-aware root node.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct YamlDocument {
    pub(crate) root: YamlNode,
    pub(crate) explicit_start: bool,
    pub(crate) span: SourceSpan,
}

impl YamlDocument {
    /// Returns the document root node.
    pub fn root(&self) -> &YamlNode {
        &self.root
    }

    /// Returns the exact source span covering the document.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}
