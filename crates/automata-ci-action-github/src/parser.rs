use std::collections::HashSet;

use saphyr_parser::{
    Event, Marker, Parser, ScalarStyle as ParserScalarStyle, Span, SpannedEventReceiver,
};

use crate::{
    GithubActionMetadataLimits, MetadataDecodeError, MetadataDecodeErrorKind, MetadataLocation,
    MetadataScalar, MetadataScalarKind, MetadataScalarStyle,
};

#[derive(Debug)]
pub(crate) enum YamlNode {
    Scalar(MetadataScalar),
    Sequence {
        items: Vec<YamlNode>,
        location: MetadataLocation,
    },
    Mapping {
        entries: Vec<YamlMappingEntry>,
        location: MetadataLocation,
    },
}

impl YamlNode {
    pub(crate) fn location(&self) -> MetadataLocation {
        match self {
            Self::Scalar(value) => value.location().unwrap_or(MetadataLocation::new(1, 1)),
            Self::Sequence { location, .. } | Self::Mapping { location, .. } => *location,
        }
    }

    pub(crate) fn into_scalar(self) -> Option<MetadataScalar> {
        match self {
            Self::Scalar(value) => Some(value),
            Self::Sequence { .. } | Self::Mapping { .. } => None,
        }
    }

    pub(crate) fn into_sequence(self) -> Option<Vec<Self>> {
        match self {
            Self::Sequence { items, .. } => Some(items),
            Self::Scalar(_) | Self::Mapping { .. } => None,
        }
    }

    pub(crate) fn into_mapping(self) -> Option<Vec<YamlMappingEntry>> {
        match self {
            Self::Mapping { entries, .. } => Some(entries),
            Self::Scalar(_) | Self::Sequence { .. } => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct YamlMappingEntry {
    key: MetadataScalar,
    value: YamlNode,
}

impl YamlMappingEntry {
    pub(crate) fn key(&self) -> &str {
        self.key.text()
    }

    pub(crate) const fn key_scalar(&self) -> &MetadataScalar {
        &self.key
    }

    pub(crate) fn into_value(self) -> YamlNode {
        self.value
    }
}

#[derive(Debug)]
enum CollectionFrame {
    Sequence {
        items: Vec<YamlNode>,
        location: MetadataLocation,
    },
    Mapping {
        entries: Vec<YamlMappingEntry>,
        pending_key: Option<YamlNode>,
        seen_keys: HashSet<String>,
        location: MetadataLocation,
    },
}

#[derive(Debug)]
struct Receiver {
    limits: GithubActionMetadataLimits,
    document_open: bool,
    document_count: usize,
    root: Option<YamlNode>,
    stack: Vec<CollectionFrame>,
    nodes: usize,
    decoded_text_bytes: usize,
    error: Option<MetadataDecodeError>,
}

impl Receiver {
    const fn new(limits: GithubActionMetadataLimits) -> Self {
        Self {
            limits,
            document_open: false,
            document_count: 0,
            root: None,
            stack: Vec::new(),
            nodes: 0,
            decoded_text_bytes: 0,
            error: None,
        }
    }

    fn fail(
        &mut self,
        kind: MetadataDecodeErrorKind,
        field: &'static str,
        location: MetadataLocation,
    ) {
        if self.error.is_none() {
            self.error = Some(MetadataDecodeError::new(kind, field, Some(location)));
        }
    }

    fn observe_node(&mut self, location: MetadataLocation) -> bool {
        if self.error.is_some() {
            return false;
        }
        let Some(next) = self.nodes.checked_add(1) else {
            self.fail(
                MetadataDecodeErrorKind::ResourceLimit,
                "yaml.nodes",
                location,
            );
            return false;
        };
        self.nodes = next;
        if self.nodes > self.limits.maximum_nodes() {
            self.fail(
                MetadataDecodeErrorKind::ResourceLimit,
                "yaml.nodes",
                location,
            );
            return false;
        }
        true
    }

    fn start_collection(&mut self, span: Span, anchor: usize, tagged: bool, mapping: bool) {
        let location = location(span.start);
        if !self.observe_node(location) {
            return;
        }
        if anchor != 0 {
            self.fail(
                MetadataDecodeErrorKind::AliasOrAnchor,
                "yaml.anchor",
                location,
            );
            return;
        }
        if tagged {
            self.fail(MetadataDecodeErrorKind::ExplicitTag, "yaml.tag", location);
            return;
        }
        if self.stack.len().saturating_add(1) > self.limits.maximum_depth() {
            self.fail(
                MetadataDecodeErrorKind::ResourceLimit,
                "yaml.depth",
                location,
            );
            return;
        }
        self.stack.push(if mapping {
            CollectionFrame::Mapping {
                entries: Vec::new(),
                pending_key: None,
                seen_keys: HashSet::new(),
                location,
            }
        } else {
            CollectionFrame::Sequence {
                items: Vec::new(),
                location,
            }
        });
    }

    fn end_collection(&mut self, span: Span, mapping: bool) {
        if self.error.is_some() {
            return;
        }
        let end_location = location(span.start);
        let Some(frame) = self.stack.pop() else {
            self.fail(
                MetadataDecodeErrorKind::InvalidYaml,
                "yaml.collection",
                end_location,
            );
            return;
        };
        let node = match frame {
            CollectionFrame::Sequence { items, location } if !mapping => {
                YamlNode::Sequence { items, location }
            }
            CollectionFrame::Mapping {
                entries,
                pending_key: None,
                location,
                ..
            } if mapping => YamlNode::Mapping { entries, location },
            CollectionFrame::Mapping {
                pending_key: Some(key),
                ..
            } if mapping => {
                self.fail(
                    MetadataDecodeErrorKind::InvalidYaml,
                    "yaml.mapping.value",
                    key.location(),
                );
                return;
            }
            CollectionFrame::Sequence { .. } | CollectionFrame::Mapping { .. } => {
                self.fail(
                    MetadataDecodeErrorKind::InvalidYaml,
                    "yaml.collection",
                    end_location,
                );
                return;
            }
        };
        self.attach(node);
    }

    fn scalar(
        &mut self,
        decoded: std::borrow::Cow<'_, str>,
        style: ParserScalarStyle,
        anchor: usize,
        tagged: bool,
        span: Span,
    ) {
        let value_location = location(span.start);
        if !self.observe_node(value_location) {
            return;
        }
        if anchor != 0 {
            self.fail(
                MetadataDecodeErrorKind::AliasOrAnchor,
                "yaml.anchor",
                value_location,
            );
            return;
        }
        if tagged {
            self.fail(
                MetadataDecodeErrorKind::ExplicitTag,
                "yaml.tag",
                value_location,
            );
            return;
        }
        let Some(total) = self.decoded_text_bytes.checked_add(decoded.len()) else {
            self.fail(
                MetadataDecodeErrorKind::ResourceLimit,
                "yaml.text",
                value_location,
            );
            return;
        };
        self.decoded_text_bytes = total;
        if total > self.limits.maximum_decoded_text_bytes() {
            self.fail(
                MetadataDecodeErrorKind::ResourceLimit,
                "yaml.text",
                value_location,
            );
            return;
        }
        let style = convert_style(style);
        let kind = resolve_scalar(&decoded, style);
        self.attach(YamlNode::Scalar(MetadataScalar::new(
            decoded.into_owned(),
            style,
            kind,
            value_location,
        )));
    }

    fn attach(&mut self, node: YamlNode) {
        if self.error.is_some() {
            return;
        }
        if let Some(frame) = self.stack.last_mut() {
            match frame {
                CollectionFrame::Sequence { items, .. } => items.push(node),
                CollectionFrame::Mapping {
                    entries,
                    pending_key,
                    seen_keys,
                    ..
                } => {
                    let Some(key_node) = pending_key.take() else {
                        *pending_key = Some(node);
                        return;
                    };
                    let key_location = key_node.location();
                    let Some(key) = key_node.into_scalar() else {
                        self.fail(
                            MetadataDecodeErrorKind::InvalidStructure,
                            "yaml.mapping.key",
                            key_location,
                        );
                        return;
                    };
                    if key.text() == "<<" {
                        self.fail(
                            MetadataDecodeErrorKind::MergeKey,
                            "yaml.merge",
                            key_location,
                        );
                        return;
                    }
                    if !seen_keys.insert(fold_key(key.text())) {
                        self.fail(
                            MetadataDecodeErrorKind::DuplicateKey,
                            "yaml.mapping.key",
                            key_location,
                        );
                        return;
                    }
                    entries.push(YamlMappingEntry { key, value: node });
                }
            }
            return;
        }
        if !self.document_open || self.root.replace(node).is_some() {
            self.fail(
                MetadataDecodeErrorKind::InvalidYaml,
                "yaml.document",
                MetadataLocation::new(1, 1),
            );
        }
    }
}

impl<'input> SpannedEventReceiver<'input> for Receiver {
    fn on_event(&mut self, event: Event<'input>, span: Span) {
        match event {
            Event::Nothing | Event::StreamStart | Event::StreamEnd => {}
            Event::DocumentStart(_) => {
                let event_location = location(span.start);
                if self.document_open || self.document_count > 0 {
                    self.fail(
                        MetadataDecodeErrorKind::InvalidYaml,
                        "yaml.documents",
                        event_location,
                    );
                    return;
                }
                self.document_open = true;
                self.document_count = 1;
            }
            Event::DocumentEnd => {
                if !self.document_open {
                    self.fail(
                        MetadataDecodeErrorKind::InvalidYaml,
                        "yaml.document",
                        location(span.start),
                    );
                    return;
                }
                self.document_open = false;
            }
            Event::Alias(_) => self.fail(
                MetadataDecodeErrorKind::AliasOrAnchor,
                "yaml.alias",
                location(span.start),
            ),
            Event::Scalar(decoded, style, anchor, tag) => {
                self.scalar(decoded, style, anchor, tag.is_some(), span);
            }
            Event::SequenceStart(anchor, tag) => {
                self.start_collection(span, anchor, tag.is_some(), false);
            }
            Event::SequenceEnd => self.end_collection(span, false),
            Event::MappingStart(anchor, tag) => {
                self.start_collection(span, anchor, tag.is_some(), true);
            }
            Event::MappingEnd => self.end_collection(span, true),
        }
    }
}

pub(crate) fn parse_yaml(
    source: &str,
    limits: GithubActionMetadataLimits,
) -> Result<YamlNode, MetadataDecodeError> {
    let mut receiver = Receiver::new(limits);
    if let Err(error) = Parser::new_from_str(source).load(&mut receiver, true)
        && receiver.error.is_none()
    {
        receiver.error = Some(MetadataDecodeError::new(
            MetadataDecodeErrorKind::InvalidYaml,
            "yaml.syntax",
            Some(location(*error.marker())),
        ));
    }
    if let Some(error) = receiver.error {
        return Err(error);
    }
    if receiver.document_open || !receiver.stack.is_empty() {
        return Err(MetadataDecodeError::new(
            MetadataDecodeErrorKind::InvalidYaml,
            "yaml.document",
            None,
        ));
    }
    receiver.root.ok_or_else(|| {
        MetadataDecodeError::new(MetadataDecodeErrorKind::InvalidYaml, "yaml.document", None)
    })
}

pub(crate) fn key_eq(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(expected)
}

fn fold_key(key: &str) -> String {
    key.chars().flat_map(char::to_lowercase).collect()
}

fn location(marker: Marker) -> MetadataLocation {
    MetadataLocation::new(marker.line().max(1), marker.col().saturating_add(1))
}

const fn convert_style(style: ParserScalarStyle) -> MetadataScalarStyle {
    match style {
        ParserScalarStyle::Plain => MetadataScalarStyle::Plain,
        ParserScalarStyle::SingleQuoted => MetadataScalarStyle::SingleQuoted,
        ParserScalarStyle::DoubleQuoted => MetadataScalarStyle::DoubleQuoted,
        ParserScalarStyle::Literal => MetadataScalarStyle::Literal,
        ParserScalarStyle::Folded => MetadataScalarStyle::Folded,
    }
}

fn resolve_scalar(decoded: &str, style: MetadataScalarStyle) -> MetadataScalarKind {
    if style != MetadataScalarStyle::Plain {
        return MetadataScalarKind::String;
    }
    match decoded {
        "" | "~" | "null" | "Null" | "NULL" => MetadataScalarKind::Null,
        "true" | "True" | "TRUE" | "false" | "False" | "FALSE" => MetadataScalarKind::Boolean,
        value if is_integer(value) => MetadataScalarKind::Integer,
        value if is_float(value) => MetadataScalarKind::Float,
        _ => MetadataScalarKind::String,
    }
}

fn is_integer(value: &str) -> bool {
    if let Some(octal) = value.strip_prefix("0o") {
        return digits(octal, |character| matches!(character, '0'..='7'));
    }
    if let Some(hexadecimal) = value.strip_prefix("0x") {
        return digits(hexadecimal, |character| character.is_ascii_hexdigit());
    }
    digits(
        value.strip_prefix(['+', '-']).unwrap_or(value),
        |character| character.is_ascii_digit(),
    )
}

fn is_float(value: &str) -> bool {
    if matches!(
        value,
        ".inf"
            | ".Inf"
            | ".INF"
            | "+.inf"
            | "+.Inf"
            | "+.INF"
            | "-.inf"
            | "-.Inf"
            | "-.INF"
            | ".nan"
            | ".NaN"
            | ".NAN"
    ) {
        return true;
    }
    if !value.contains(['.', 'e', 'E']) {
        return false;
    }
    value.parse::<f64>().is_ok()
}

fn digits(value: &str, is_digit: impl Fn(char) -> bool) -> bool {
    !value.is_empty() && value.chars().all(is_digit)
}
