use crate::SourceSpan;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct AnchorId(pub(crate) usize);

impl AnchorId {
    pub const fn get(self) -> usize {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ScalarStyle {
    Plain,
    SingleQuoted,
    DoubleQuoted,
    Literal,
    Folded,
}

/// YAML 1.2 Core Schema classification. The decoded spelling is always retained separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ScalarResolution {
    String,
    Null,
    Boolean,
    Integer,
    Float,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct YamlScalar {
    pub(crate) decoded: String,
    pub(crate) style: ScalarStyle,
    pub(crate) resolution: ScalarResolution,
}

impl YamlScalar {
    pub fn is_null(&self) -> bool {
        self.resolution == ScalarResolution::Null
    }

    pub fn decoded(&self) -> &str {
        &self.decoded
    }

    pub const fn style(&self) -> ScalarStyle {
        self.style
    }

    pub const fn resolution(&self) -> ScalarResolution {
        self.resolution
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct YamlTag {
    pub(crate) handle: String,
    pub(crate) suffix: String,
}

impl YamlTag {
    pub fn handle(&self) -> &str {
        &self.handle
    }

    pub fn suffix(&self) -> &str {
        &self.suffix
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct YamlAlias {
    pub(crate) target: AnchorId,
}

impl YamlAlias {
    pub const fn target(&self) -> AnchorId {
        self.target
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct YamlMappingEntry {
    pub(crate) key: YamlNode,
    pub(crate) value: YamlNode,
    pub(crate) span: SourceSpan,
}

impl YamlMappingEntry {
    pub fn key(&self) -> &YamlNode {
        &self.key
    }

    pub fn value(&self) -> &YamlNode {
        &self.value
    }

    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum YamlNodeKind {
    Scalar(YamlScalar),
    Sequence(Vec<YamlNode>),
    Mapping(Vec<YamlMappingEntry>),
    Alias(YamlAlias),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct YamlNode {
    pub(crate) kind: YamlNodeKind,
    pub(crate) span: SourceSpan,
    pub(crate) anchor: Option<AnchorId>,
    pub(crate) tag: Option<YamlTag>,
}

impl YamlNode {
    pub fn as_scalar(&self) -> Option<&YamlScalar> {
        match &self.kind {
            YamlNodeKind::Scalar(scalar) => Some(scalar),
            _ => None,
        }
    }

    pub fn as_mapping(&self) -> Option<&[YamlMappingEntry]> {
        match &self.kind {
            YamlNodeKind::Mapping(entries) => Some(entries),
            _ => None,
        }
    }

    pub fn as_sequence(&self) -> Option<&[YamlNode]> {
        match &self.kind {
            YamlNodeKind::Sequence(items) => Some(items),
            _ => None,
        }
    }

    pub fn kind(&self) -> &YamlNodeKind {
        &self.kind
    }

    pub fn span(&self) -> &SourceSpan {
        &self.span
    }

    pub const fn anchor(&self) -> Option<AnchorId> {
        self.anchor
    }

    pub fn tag(&self) -> Option<&YamlTag> {
        self.tag.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct YamlDocument {
    pub(crate) root: YamlNode,
    pub(crate) explicit_start: bool,
    pub(crate) span: SourceSpan,
}

impl YamlDocument {
    pub fn root(&self) -> &YamlNode {
        &self.root
    }

    pub const fn has_explicit_start(&self) -> bool {
        self.explicit_start
    }

    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}
