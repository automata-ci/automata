use std::collections::HashMap;

use saphyr_parser::{
    Event, Marker, Parser, ScalarStyle as ParserScalarStyle, Span as ParserSpan,
    SpannedEventReceiver, Tag,
};

use crate::{
    Diagnostic, DiagnosticKind, SourceFile, SourceLocation, SourceSpan,
    syntax::{
        AnchorId, ScalarStyle, YamlAlias, YamlDocument, YamlMappingEntry, YamlNode, YamlNodeKind,
        YamlScalar, YamlTag, scalar::resolve_scalar,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_field_names)]
#[non_exhaustive]
pub struct ParseLimits {
    max_source_bytes: usize,
    max_depth: usize,
    max_nodes: usize,
    max_aliases: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 2 * 1024 * 1024,
            max_depth: 64,
            max_nodes: 100_000,
            max_aliases: 1_024,
        }
    }
}

impl ParseLimits {
    pub const fn new(
        max_source_bytes: usize,
        max_depth: usize,
        max_nodes: usize,
        max_aliases: usize,
    ) -> Self {
        Self {
            max_source_bytes,
            max_depth,
            max_nodes,
            max_aliases,
        }
    }

    pub const fn max_source_bytes(self) -> usize {
        self.max_source_bytes
    }

    pub const fn max_depth(self) -> usize {
        self.max_depth
    }

    pub const fn max_nodes(self) -> usize {
        self.max_nodes
    }

    pub const fn max_aliases(self) -> usize {
        self.max_aliases
    }

    pub const fn with_max_source_bytes(mut self, maximum: usize) -> Self {
        self.max_source_bytes = maximum;
        self
    }

    pub const fn with_max_depth(mut self, maximum: usize) -> Self {
        self.max_depth = maximum;
        self
    }

    pub const fn with_max_nodes(mut self, maximum: usize) -> Self {
        self.max_nodes = maximum;
        self
    }

    pub const fn with_max_aliases(mut self, maximum: usize) -> Self {
        self.max_aliases = maximum;
        self
    }
}

#[derive(Debug)]
pub(crate) struct SyntaxReport {
    pub(crate) documents: Vec<YamlDocument>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) fatal: bool,
}

pub fn parse_yaml(source: &SourceFile, limits: ParseLimits) -> SyntaxReport {
    if source.text().len() > limits.max_source_bytes {
        return SyntaxReport {
            documents: Vec::new(),
            diagnostics: vec![Diagnostic::error(
                DiagnosticKind::ResourceLimit,
                "yaml.source_too_large",
                format!(
                    "workflow source is {} bytes; the configured limit is {} bytes",
                    source.text().len(),
                    limits.max_source_bytes
                ),
                whole_source_span(source),
            )],
            fatal: true,
        };
    }

    let mut receiver = AstReceiver::new(source, limits);
    let result = Parser::new_from_str(source.text()).load(&mut receiver, true);
    if let Err(error) = result {
        receiver.diagnostics.push(Diagnostic::error(
            DiagnosticKind::Syntax,
            "yaml.invalid_syntax",
            error.info(),
            empty_marker_span(source, &receiver.coordinates, *error.marker()),
        ));
        receiver.fatal = true;
    }
    receiver.finish()
}

#[derive(Debug)]
struct DocumentFrame {
    explicit_start: bool,
    start: SourceSpan,
    root: Option<YamlNode>,
}

#[derive(Debug)]
enum CollectionFrame {
    Sequence(Box<SequenceFrame>),
    Mapping(Box<MappingFrame>),
}

#[derive(Debug)]
struct SequenceFrame {
    start: SourceSpan,
    anchor: Option<AnchorId>,
    tag: Option<YamlTag>,
    items: Vec<YamlNode>,
}

#[derive(Debug)]
struct MappingFrame {
    start: SourceSpan,
    anchor: Option<AnchorId>,
    tag: Option<YamlTag>,
    entries: Vec<YamlMappingEntry>,
    pending_key: Option<YamlNode>,
    seen_keys: HashMap<String, SourceSpan>,
}

#[derive(Debug)]
struct AstReceiver<'source> {
    source: &'source SourceFile,
    coordinates: SourceCoordinates,
    limits: ParseLimits,
    documents: Vec<YamlDocument>,
    document: Option<DocumentFrame>,
    stack: Vec<CollectionFrame>,
    diagnostics: Vec<Diagnostic>,
    node_count: usize,
    alias_count: usize,
    fatal: bool,
}

impl<'source> AstReceiver<'source> {
    fn new(source: &'source SourceFile, limits: ParseLimits) -> Self {
        Self {
            source,
            coordinates: SourceCoordinates::new(source.text()),
            limits,
            documents: Vec::new(),
            document: None,
            stack: Vec::new(),
            diagnostics: Vec::new(),
            node_count: 0,
            alias_count: 0,
            fatal: false,
        }
    }

    fn finish(mut self) -> SyntaxReport {
        if !self.fatal && (self.document.is_some() || !self.stack.is_empty()) {
            self.diagnostics.push(Diagnostic::error(
                DiagnosticKind::Syntax,
                "yaml.incomplete_document",
                "YAML parser ended with an incomplete document",
                whole_source_span(self.source),
            ));
            self.fatal = true;
        }

        SyntaxReport {
            documents: self.documents,
            diagnostics: self.diagnostics,
            fatal: self.fatal,
        }
    }

    fn start_collection(
        &mut self,
        span: ParserSpan,
        anchor: usize,
        tag: Option<std::borrow::Cow<'_, Tag>>,
        mapping: bool,
    ) {
        if !self.observe_node(span) {
            return;
        }
        if self.stack.len().saturating_add(1) > self.limits.max_depth {
            self.fail_limit(
                "yaml.maximum_depth_exceeded",
                format!(
                    "YAML nesting exceeds the configured maximum depth of {}",
                    self.limits.max_depth
                ),
                convert_span(self.source, &self.coordinates, span),
            );
            return;
        }

        let source_span = convert_span(self.source, &self.coordinates, span);
        let anchor = anchor_id(anchor);
        let tag = tag.map(|tag| convert_tag(&tag));
        self.report_metadata(anchor, tag.as_ref(), source_span.clone());

        let frame = if mapping {
            CollectionFrame::Mapping(Box::new(MappingFrame {
                start: source_span,
                anchor,
                tag,
                entries: Vec::new(),
                pending_key: None,
                seen_keys: HashMap::new(),
            }))
        } else {
            CollectionFrame::Sequence(Box::new(SequenceFrame {
                start: source_span,
                anchor,
                tag,
                items: Vec::new(),
            }))
        };
        self.stack.push(frame);
    }

    fn end_collection(&mut self, span: ParserSpan, mapping: bool) {
        if self.fatal {
            return;
        }
        let Some(frame) = self.stack.pop() else {
            self.fail_internal(span, "collection end without a matching start");
            return;
        };

        let end = convert_span(self.source, &self.coordinates, span);
        let node = match frame {
            CollectionFrame::Sequence(frame) if !mapping => YamlNode {
                span: join_spans(&frame.start, &end),
                kind: YamlNodeKind::Sequence(frame.items),
                anchor: frame.anchor,
                tag: frame.tag,
            },
            CollectionFrame::Mapping(frame) if mapping && frame.pending_key.is_none() => YamlNode {
                span: join_spans(&frame.start, &end),
                kind: YamlNodeKind::Mapping(frame.entries),
                anchor: frame.anchor,
                tag: frame.tag,
            },
            CollectionFrame::Mapping(mut frame) if frame.pending_key.is_some() => {
                let key = frame.pending_key.take().expect("pending key was checked");
                self.diagnostics.push(Diagnostic::error(
                    DiagnosticKind::Syntax,
                    "yaml.mapping_value_missing",
                    "mapping key has no value",
                    key.span,
                ));
                self.fatal = true;
                return;
            }
            _ => {
                self.fail_internal(span, "mismatched collection delimiters");
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
        tag: Option<std::borrow::Cow<'_, Tag>>,
        span: ParserSpan,
    ) {
        if !self.observe_node(span) {
            return;
        }
        let style = convert_style(style);
        let source_span = convert_span(self.source, &self.coordinates, span);
        let anchor = anchor_id(anchor);
        let tag = tag.map(|tag| convert_tag(&tag));
        self.report_metadata(anchor, tag.as_ref(), source_span.clone());
        let resolution = resolve_scalar(&decoded, style);
        self.attach(YamlNode {
            kind: YamlNodeKind::Scalar(YamlScalar {
                decoded: decoded.into_owned(),
                style,
                resolution,
            }),
            span: source_span,
            anchor,
            tag,
        });
    }

    fn alias(&mut self, target: usize, span: ParserSpan) {
        if !self.observe_node(span) {
            return;
        }
        self.alias_count = self.alias_count.saturating_add(1);
        let source_span = convert_span(self.source, &self.coordinates, span);
        if self.alias_count > self.limits.max_aliases {
            self.fail_limit(
                "yaml.maximum_aliases_exceeded",
                format!(
                    "YAML contains more than {} aliases",
                    self.limits.max_aliases
                ),
                source_span,
            );
            return;
        }
        self.diagnostics.push(Diagnostic::error(
            DiagnosticKind::Unsupported,
            "github.yaml_alias_not_expanded",
            "YAML aliases are preserved but alias expansion is not implemented by this frontend version",
            source_span.clone(),
        ));
        self.attach(YamlNode {
            kind: YamlNodeKind::Alias(YamlAlias {
                target: AnchorId(target),
            }),
            span: source_span,
            anchor: None,
            tag: None,
        });
    }

    fn attach(&mut self, node: YamlNode) {
        if self.fatal {
            return;
        }
        let mut key_diagnostics = Vec::new();
        if let Some(frame) = self.stack.last_mut() {
            match frame {
                CollectionFrame::Sequence(frame) => frame.items.push(node),
                CollectionFrame::Mapping(frame) => {
                    if frame.pending_key.is_none() {
                        frame.pending_key = Some(node);
                        return;
                    }
                    let key = frame.pending_key.take().expect("pending key was checked");
                    inspect_mapping_key(&key, &mut frame.seen_keys, &mut key_diagnostics);
                    let entry_span = join_spans(&key.span, &node.span);
                    frame.entries.push(YamlMappingEntry {
                        key,
                        value: node,
                        span: entry_span,
                    });
                }
            }
            self.diagnostics.extend(key_diagnostics);
            return;
        }

        let Some(document) = self.document.as_mut() else {
            self.diagnostics.push(Diagnostic::error(
                DiagnosticKind::Syntax,
                "yaml.node_outside_document",
                "YAML node occurred outside a document",
                node.span,
            ));
            self.fatal = true;
            return;
        };
        if document.root.replace(node).is_some() {
            self.diagnostics.push(Diagnostic::error(
                DiagnosticKind::Syntax,
                "yaml.multiple_roots",
                "YAML document contains more than one root node",
                document.start.clone(),
            ));
            self.fatal = true;
        }
    }

    fn report_metadata(
        &mut self,
        anchor: Option<AnchorId>,
        tag: Option<&YamlTag>,
        span: SourceSpan,
    ) {
        if anchor.is_some() {
            self.diagnostics.push(Diagnostic::error(
                DiagnosticKind::Unsupported,
                "github.yaml_anchor_not_expanded",
                "YAML anchors are preserved but anchor expansion is not implemented by this frontend version",
                span.clone(),
            ));
        }
        if tag.is_some() {
            self.diagnostics.push(Diagnostic::error(
                DiagnosticKind::Unsupported,
                "github.yaml_tag",
                "explicit YAML tags are not supported in GitHub workflow fields",
                span,
            ));
        }
    }

    fn observe_node(&mut self, span: ParserSpan) -> bool {
        if self.fatal {
            return false;
        }
        self.node_count = self.node_count.saturating_add(1);
        if self.node_count > self.limits.max_nodes {
            self.fail_limit(
                "yaml.maximum_nodes_exceeded",
                format!("YAML contains more than {} nodes", self.limits.max_nodes),
                convert_span(self.source, &self.coordinates, span),
            );
            return false;
        }
        true
    }

    fn fail_limit(&mut self, code: &str, message: String, span: SourceSpan) {
        if !self.fatal {
            self.diagnostics.push(Diagnostic::error(
                DiagnosticKind::ResourceLimit,
                code,
                message,
                span,
            ));
        }
        self.fatal = true;
    }

    fn fail_internal(&mut self, span: ParserSpan, message: &str) {
        self.diagnostics.push(Diagnostic::error(
            DiagnosticKind::Syntax,
            "yaml.invalid_event_stream",
            message,
            convert_span(self.source, &self.coordinates, span),
        ));
        self.fatal = true;
    }
}

impl<'input> SpannedEventReceiver<'input> for AstReceiver<'_> {
    fn on_event(&mut self, event: Event<'input>, span: ParserSpan) {
        match event {
            Event::Nothing | Event::StreamStart | Event::StreamEnd => {}
            Event::DocumentStart(explicit_start) => {
                if self.fatal {
                    return;
                }
                if self.document.is_some() {
                    self.fail_internal(span, "nested YAML document start");
                    return;
                }
                self.document = Some(DocumentFrame {
                    explicit_start,
                    start: convert_span(self.source, &self.coordinates, span),
                    root: None,
                });
            }
            Event::DocumentEnd => {
                if self.fatal {
                    return;
                }
                let Some(document) = self.document.take() else {
                    self.fail_internal(span, "document end without a document start");
                    return;
                };
                let Some(root) = document.root else {
                    self.fail_internal(span, "YAML document has no root node");
                    return;
                };
                let end = convert_span(self.source, &self.coordinates, span);
                self.documents.push(YamlDocument {
                    span: join_spans(&document.start, &end),
                    root,
                    explicit_start: document.explicit_start,
                });
            }
            Event::Alias(target) => self.alias(target, span),
            Event::Scalar(decoded, style, anchor, tag) => {
                self.scalar(decoded, style, anchor, tag, span);
            }
            Event::SequenceStart(anchor, tag) => {
                self.start_collection(span, anchor, tag, false);
            }
            Event::SequenceEnd => self.end_collection(span, false),
            Event::MappingStart(anchor, tag) => {
                self.start_collection(span, anchor, tag, true);
            }
            Event::MappingEnd => self.end_collection(span, true),
        }
    }
}

fn anchor_id(id: usize) -> Option<AnchorId> {
    (id != 0).then_some(AnchorId(id))
}

fn inspect_mapping_key(
    key: &YamlNode,
    seen_keys: &mut HashMap<String, SourceSpan>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(scalar) = key.as_scalar() else {
        diagnostics.push(Diagnostic::error(
            DiagnosticKind::Unsupported,
            "github.complex_mapping_key",
            "GitHub workflow mappings require scalar keys",
            key.span.clone(),
        ));
        return;
    };

    if scalar.decoded == "<<" {
        diagnostics.push(Diagnostic::error(
            DiagnosticKind::Unsupported,
            "github.yaml_merge_key",
            "GitHub Actions supports anchors and aliases but does not support YAML merge keys",
            key.span.clone(),
        ));
    }

    if let Some(original) = seen_keys.get(&scalar.decoded) {
        diagnostics.push(
            Diagnostic::error(
                DiagnosticKind::Semantic,
                "github.duplicate_mapping_key",
                format!("duplicate mapping key `{}`", scalar.decoded),
                key.span.clone(),
            )
            .with_related("first defined here", original.clone()),
        );
    } else {
        seen_keys.insert(scalar.decoded.clone(), key.span.clone());
    }
}

fn convert_tag(tag: &Tag) -> YamlTag {
    YamlTag {
        handle: tag.handle.clone(),
        suffix: tag.suffix.clone(),
    }
}

fn convert_style(style: ParserScalarStyle) -> ScalarStyle {
    match style {
        ParserScalarStyle::Plain => ScalarStyle::Plain,
        ParserScalarStyle::SingleQuoted => ScalarStyle::SingleQuoted,
        ParserScalarStyle::DoubleQuoted => ScalarStyle::DoubleQuoted,
        ParserScalarStyle::Literal => ScalarStyle::Literal,
        ParserScalarStyle::Folded => ScalarStyle::Folded,
    }
}

#[derive(Debug)]
struct SourceCoordinates {
    character_to_byte: Vec<usize>,
}

impl SourceCoordinates {
    fn new(source: &str) -> Self {
        let mut character_to_byte = source
            .char_indices()
            .map(|(byte_offset, _)| byte_offset)
            .collect::<Vec<_>>();
        character_to_byte.push(source.len());
        Self { character_to_byte }
    }

    fn byte_offset(&self, character_index: usize) -> usize {
        self.character_to_byte
            .get(character_index)
            .copied()
            .unwrap_or_else(|| self.character_to_byte.last().copied().unwrap_or(0))
    }
}

fn marker_location(marker: Marker, coordinates: &SourceCoordinates) -> SourceLocation {
    SourceLocation::new(
        coordinates.byte_offset(marker.index()),
        marker.line().max(1),
        marker.col().saturating_add(1),
    )
}

fn convert_span(
    source: &SourceFile,
    coordinates: &SourceCoordinates,
    span: ParserSpan,
) -> SourceSpan {
    SourceSpan::new(
        source.provenance().id().clone(),
        marker_location(span.start, coordinates),
        marker_location(span.end, coordinates),
    )
}

fn empty_marker_span(
    source: &SourceFile,
    coordinates: &SourceCoordinates,
    marker: Marker,
) -> SourceSpan {
    SourceSpan::empty(
        source.provenance().id().clone(),
        marker_location(marker, coordinates),
    )
}

fn whole_source_span(source: &SourceFile) -> SourceSpan {
    let mut line = 1;
    let mut column = 1;
    for character in source.text().chars() {
        if character == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    SourceSpan::new(
        source.provenance().id().clone(),
        SourceLocation::new(0, 1, 1),
        SourceLocation::new(source.text().len(), line, column),
    )
}

fn join_spans(start: &SourceSpan, end: &SourceSpan) -> SourceSpan {
    debug_assert_eq!(start.source_id, end.source_id);
    let end_location = if end.end.byte_offset >= start.end.byte_offset {
        end.end
    } else {
        start.end
    };
    SourceSpan::new(start.source_id.clone(), start.start, end_location)
}
