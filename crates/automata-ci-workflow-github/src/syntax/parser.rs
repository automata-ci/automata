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

/// Automata's pinned maximum raw UTF-8 byte length for one GitHub workflow.
///
/// GitHub documents the accepted workflow extensions but does not publish an
/// exact byte-accounting contract. Automata therefore interprets the parity
/// plan's 500 KB ceiling as 500 KiB and applies it to the original bytes,
/// before YAML parsing or newline/BOM normalization.
pub const MAX_GITHUB_WORKFLOW_SOURCE_BYTES: usize = 500 * 1_024;

/// Independent bounds applied while parsing loss-aware YAML syntax.
///
/// These limits bound retained input, nesting, node allocation, alias uses,
/// and the derived tree produced by alias expansion before GitHub workflow
/// semantic decoding begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_field_names)]
#[non_exhaustive]
pub struct ParseLimits {
    max_source_bytes: usize,
    max_depth: usize,
    max_nodes: usize,
    max_aliases: usize,
    max_alias_expansion_depth: usize,
    max_expanded_nodes: usize,
    max_expanded_scalar_bytes: usize,
    max_alias_expansion_work: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: MAX_GITHUB_WORKFLOW_SOURCE_BYTES,
            max_depth: 64,
            max_nodes: 100_000,
            max_aliases: 1_024,
            max_alias_expansion_depth: 64,
            max_expanded_nodes: 100_000,
            max_expanded_scalar_bytes: 8 * 1024 * 1024,
            max_alias_expansion_work: 1_000_000,
        }
    }
}

impl ParseLimits {
    /// Creates a parsing policy with explicit source-tree ceilings.
    ///
    /// Alias-expansion ceilings retain their secure defaults and can be
    /// replaced independently with the `with_max_*` builders.
    #[must_use]
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
            max_alias_expansion_depth: 64,
            max_expanded_nodes: 100_000,
            max_expanded_scalar_bytes: 8 * 1024 * 1024,
            max_alias_expansion_work: 1_000_000,
        }
    }

    /// Returns the maximum accepted UTF-8 source byte length.
    pub const fn max_source_bytes(self) -> usize {
        self.max_source_bytes
    }

    /// Returns the maximum nested sequence/mapping depth.
    pub const fn max_depth(self) -> usize {
        self.max_depth
    }

    /// Returns the maximum number of scalar, alias, and collection nodes.
    pub const fn max_nodes(self) -> usize {
        self.max_nodes
    }

    /// Returns the maximum number of alias nodes observed.
    pub const fn max_aliases(self) -> usize {
        self.max_aliases
    }

    /// Returns the maximum number of nested alias substitutions.
    pub const fn max_alias_expansion_depth(self) -> usize {
        self.max_alias_expansion_depth
    }

    /// Returns the maximum number of nodes in the expanded YAML document.
    pub const fn max_expanded_nodes(self) -> usize {
        self.max_expanded_nodes
    }

    /// Returns the maximum decoded scalar bytes in the expanded YAML document.
    pub const fn max_expanded_scalar_bytes(self) -> usize {
        self.max_expanded_scalar_bytes
    }

    /// Returns the maximum aggregate work charged during alias expansion.
    pub const fn max_alias_expansion_work(self) -> usize {
        self.max_alias_expansion_work
    }

    #[must_use]
    /// Replaces the maximum accepted UTF-8 source byte length.
    pub const fn with_max_source_bytes(mut self, maximum: usize) -> Self {
        self.max_source_bytes = maximum;
        self
    }

    #[must_use]
    /// Replaces the maximum nested sequence/mapping depth.
    pub const fn with_max_depth(mut self, maximum: usize) -> Self {
        self.max_depth = maximum;
        self
    }

    #[must_use]
    /// Replaces the maximum parsed node count.
    pub const fn with_max_nodes(mut self, maximum: usize) -> Self {
        self.max_nodes = maximum;
        self
    }

    #[must_use]
    /// Replaces the maximum observed alias count.
    pub const fn with_max_aliases(mut self, maximum: usize) -> Self {
        self.max_aliases = maximum;
        self
    }

    #[must_use]
    /// Replaces the maximum number of nested alias substitutions.
    pub const fn with_max_alias_expansion_depth(mut self, maximum: usize) -> Self {
        self.max_alias_expansion_depth = maximum;
        self
    }

    #[must_use]
    /// Replaces the maximum node count in the expanded YAML document.
    pub const fn with_max_expanded_nodes(mut self, maximum: usize) -> Self {
        self.max_expanded_nodes = maximum;
        self
    }

    #[must_use]
    /// Replaces the maximum decoded scalar bytes in the expanded YAML document.
    pub const fn with_max_expanded_scalar_bytes(mut self, maximum: usize) -> Self {
        self.max_expanded_scalar_bytes = maximum;
        self
    }

    #[must_use]
    /// Replaces the maximum aggregate work charged during alias expansion.
    pub const fn with_max_alias_expansion_work(mut self, maximum: usize) -> Self {
        self.max_alias_expansion_work = maximum;
        self
    }
}

#[derive(Debug)]
pub(crate) struct SyntaxReport {
    pub(crate) documents: Vec<YamlDocument>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) fatal: bool,
}

pub(crate) fn parse_yaml(source: &SourceFile, limits: ParseLimits) -> SyntaxReport {
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

    let (parser_source, ignored_leading_characters) = source
        .text()
        .strip_prefix('\u{feff}')
        .map_or((source.text(), 0), |without_bom| (without_bom, 1));
    let mut receiver = AstReceiver::new(source, limits, ignored_leading_characters);
    let result = Parser::new_from_str(parser_source).load(&mut receiver, true);
    if let Err(error) = result {
        let marker = *error.marker();
        let marker_offset = receiver.coordinates.byte_offset(marker.index());
        receiver.diagnostics.push(
            unresolved_alias_diagnostic(source, marker_offset).unwrap_or_else(|| {
                Diagnostic::error(
                    DiagnosticKind::Syntax,
                    "yaml.invalid_syntax",
                    error.info(),
                    empty_marker_span(source, &receiver.coordinates, marker),
                )
            }),
        );
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
    fn new(
        source: &'source SourceFile,
        limits: ParseLimits,
        ignored_leading_characters: usize,
    ) -> Self {
        Self {
            source,
            coordinates: SourceCoordinates::new(source.text(), ignored_leading_characters),
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
        self.report_metadata(tag.as_ref(), source_span.clone());

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
                alias_expansions: Vec::new(),
            },
            CollectionFrame::Mapping(frame) if mapping && frame.pending_key.is_none() => YamlNode {
                span: join_spans(&frame.start, &end),
                kind: YamlNodeKind::Mapping(frame.entries),
                anchor: frame.anchor,
                tag: frame.tag,
                alias_expansions: Vec::new(),
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
        self.report_metadata(tag.as_ref(), source_span.clone());
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
            alias_expansions: Vec::new(),
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
        self.attach(YamlNode {
            kind: YamlNodeKind::Alias(YamlAlias {
                target: AnchorId(target),
            }),
            span: source_span,
            anchor: None,
            tag: None,
            alias_expansions: Vec::new(),
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

    fn report_metadata(&mut self, tag: Option<&YamlTag>, span: SourceSpan) {
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
    fn new(source: &str, ignored_leading_characters: usize) -> Self {
        let mut character_to_byte = source
            .char_indices()
            .map(|(byte_offset, _)| byte_offset)
            .skip(ignored_leading_characters)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SurfaceTokenKind {
    Anchor,
    Alias,
}

#[derive(Debug)]
struct SurfaceToken<'source> {
    kind: SurfaceTokenKind,
    name: &'source str,
    document: usize,
    start: usize,
    end: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SurfaceMode {
    Plain,
    SingleQuoted,
    DoubleQuoted,
}

/// Saphyr deliberately does not expose anchor names through its event API and
/// rejects an unresolved alias before emitting an alias event. This bounded
/// source pass keeps candidate recognition linear in the retained source size
/// and never matches dependency error strings, so those failures still carry
/// stable alias/definition provenance.
fn unresolved_alias_diagnostic(source: &SourceFile, marker_offset: usize) -> Option<Diagnostic> {
    let (unresolved, forward_definition) = scan_unresolved_alias(source.text(), marker_offset)?;
    let alias_span = source_offsets_span(source, unresolved.start, unresolved.end);

    Some(if let Some(definition) = &forward_definition {
        Diagnostic::error(
            DiagnosticKind::Semantic,
            "github.yaml_forward_alias",
            format!(
                "YAML alias `*{}` appears before its anchor definition",
                unresolved.name
            ),
            alias_span,
        )
        .with_related(
            "anchor is defined later in this document",
            source_offsets_span(source, definition.start, definition.end),
        )
    } else {
        Diagnostic::error(
            DiagnosticKind::Semantic,
            "github.yaml_undefined_alias",
            format!(
                "YAML alias `*{}` has no preceding anchor definition",
                unresolved.name
            ),
            alias_span,
        )
    })
}

// Quote, comment, document, and block-scalar state deliberately stays in one
// bounded pass so token-classification transitions can be audited together.
#[allow(clippy::too_many_lines)]
fn scan_unresolved_alias(
    source: &str,
    marker_offset: usize,
) -> Option<(SurfaceToken<'_>, Option<SurfaceToken<'_>>)> {
    let mut unresolved = None;
    let mut forward_definition = None;
    let mut document = 0_usize;
    let mut mode = SurfaceMode::Plain;
    let mut block_indent = None;
    let mut line_offset = 0_usize;

    for line_with_ending in source.split_inclusive('\n') {
        let line = line_with_ending
            .strip_suffix('\n')
            .unwrap_or(line_with_ending);
        let line = line.strip_suffix('\r').unwrap_or(line);
        let indent = line
            .chars()
            .take_while(|character| *character == ' ')
            .count();
        let trimmed = line.trim_start_matches(' ');

        if mode == SurfaceMode::Plain {
            if let Some(parent_indent) = block_indent {
                if trimmed.is_empty() || indent > parent_indent {
                    line_offset = line_offset.saturating_add(line_with_ending.len());
                    continue;
                }
                block_indent = None;
            }

            if indent == 0 && is_document_marker(trimmed) {
                document = document.saturating_add(1);
            }
        }

        let mut relative = 0_usize;
        let mut previous = None;
        while relative < line.len() {
            let rest = &line[relative..];
            let character = rest.chars().next().expect("offset is a character boundary");
            let width = character.len_utf8();
            match mode {
                SurfaceMode::SingleQuoted => {
                    if character == '\'' {
                        let next = rest[width..].chars().next();
                        if next == Some('\'') {
                            relative = relative.saturating_add(width * 2);
                            previous = Some('\'');
                            continue;
                        }
                        mode = SurfaceMode::Plain;
                    }
                }
                SurfaceMode::DoubleQuoted => {
                    if character == '\\' {
                        relative = relative.saturating_add(width);
                        if relative < line.len() {
                            let escaped_width = line[relative..]
                                .chars()
                                .next()
                                .expect("offset is a character boundary")
                                .len_utf8();
                            relative = relative.saturating_add(escaped_width);
                        }
                        previous = Some(character);
                        continue;
                    }
                    if character == '"' {
                        mode = SurfaceMode::Plain;
                    }
                }
                SurfaceMode::Plain => {
                    let comment_boundary = previous.is_none_or(is_yaml_blank);
                    if character == '#' && comment_boundary {
                        break;
                    }
                    let node_position = matches!(character, '\'' | '"' | '|' | '>' | '&' | '*')
                        && is_surface_node_position(&line[..relative]);
                    if character == '\'' && node_position {
                        mode = SurfaceMode::SingleQuoted;
                    } else if character == '"' && node_position {
                        mode = SurfaceMode::DoubleQuoted;
                    } else if matches!(character, '|' | '>')
                        && node_position
                        && is_block_scalar_header(rest)
                    {
                        block_indent = Some(indent);
                        break;
                    } else if matches!(character, '&' | '*') && node_position {
                        let name_start = relative.saturating_add(width);
                        let mut name_end = name_start;
                        for (offset, candidate) in line[name_start..].char_indices() {
                            if !is_anchor_name_character(candidate) {
                                break;
                            }
                            name_end = name_start
                                .saturating_add(offset)
                                .saturating_add(candidate.len_utf8());
                        }
                        if name_end > name_start {
                            let token = SurfaceToken {
                                kind: if character == '&' {
                                    SurfaceTokenKind::Anchor
                                } else {
                                    SurfaceTokenKind::Alias
                                },
                                name: &line[name_start..name_end],
                                document,
                                start: line_offset.saturating_add(relative),
                                end: line_offset.saturating_add(name_end),
                            };
                            if token.kind == SurfaceTokenKind::Alias && token.start == marker_offset
                            {
                                unresolved = Some(token);
                            } else if forward_definition.is_none()
                                && unresolved.as_ref().is_some_and(|alias| {
                                    token.kind == SurfaceTokenKind::Anchor
                                        && token.document == alias.document
                                        && token.start > alias.start
                                        && token.name == alias.name
                                })
                            {
                                forward_definition = Some(token);
                            }
                            relative = name_end;
                            previous = line[..relative].chars().next_back();
                            continue;
                        }
                    }
                }
            }
            relative = relative.saturating_add(width);
            previous = Some(character);
        }

        line_offset = line_offset.saturating_add(line_with_ending.len());
    }

    unresolved.map(|alias| (alias, forward_definition))
}

fn is_surface_node_position(mut prefix: &str) -> bool {
    let mut property_count = 0_usize;
    loop {
        let trimmed = prefix.trim_end_matches(is_yaml_blank);
        if trimmed.is_empty() {
            return true;
        }
        if trimmed
            .chars()
            .next_back()
            .is_some_and(|character| matches!(character, '-' | '?' | ':' | ',' | '[' | '{'))
        {
            return true;
        }
        if trimmed.len() == prefix.len() {
            return false;
        }

        let property_start = trimmed.rfind(is_yaml_blank).map_or(0, |index| index + 1);
        let property = &trimmed[property_start..];
        let is_property = property.starts_with('!')
            || property
                .strip_prefix('&')
                .is_some_and(|name| !name.is_empty() && name.chars().all(is_anchor_name_character));
        if !is_property {
            return false;
        }
        property_count = property_count.saturating_add(1);
        if property_count > 2 {
            return false;
        }
        prefix = &trimmed[..property_start];
    }
}

fn is_yaml_blank(character: char) -> bool {
    matches!(character, ' ' | '\t')
}

fn is_anchor_name_character(character: char) -> bool {
    !matches!(
        character,
        '\0' | '\n' | '\r' | ' ' | '\t' | '\u{feff}' | ',' | '[' | ']' | '{' | '}'
    )
}

fn is_document_marker(line: &str) -> bool {
    ["---", "..."].iter().any(|marker| {
        line.strip_prefix(marker).is_some_and(|suffix| {
            suffix.is_empty() || suffix.chars().next().is_some_and(is_yaml_blank)
        })
    })
}

fn is_block_scalar_header(rest: &str) -> bool {
    let mut suffix = &rest[1..];
    let mut saw_chomping = false;
    let mut saw_indent = false;
    while let Some(character) = suffix.chars().next() {
        if matches!(character, '+' | '-') && !saw_chomping {
            saw_chomping = true;
        } else if matches!(character, '1'..='9') && !saw_indent {
            saw_indent = true;
        } else {
            break;
        }
        suffix = &suffix[character.len_utf8()..];
    }
    suffix.is_empty()
        || suffix.starts_with('#')
        || suffix.chars().next().is_some_and(char::is_whitespace)
}

fn source_offsets_span(source: &SourceFile, start: usize, end: usize) -> SourceSpan {
    SourceSpan::new(
        source.provenance().id().clone(),
        source_location_at(source.text(), start),
        source_location_at(source.text(), end),
    )
}

fn source_location_at(source: &str, byte_offset: usize) -> SourceLocation {
    let mut line = 1_usize;
    let mut column = 1_usize;
    for (offset, character) in source.char_indices() {
        if offset >= byte_offset {
            break;
        }
        if character == '\n' {
            line = line.saturating_add(1);
            column = 1;
        } else {
            column = column.saturating_add(1);
        }
    }
    SourceLocation::new(byte_offset.min(source.len()), line, column)
}
