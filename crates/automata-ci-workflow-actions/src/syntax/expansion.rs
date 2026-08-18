use std::collections::{HashMap, HashSet};

use crate::{Diagnostic, DiagnosticKind, SourceSpan};

use super::{
    AnchorId, ParseLimits, YamlAliasExpansion, YamlDocument, YamlMappingEntry, YamlNode,
    YamlNodeKind, YamlTag,
};

type ExpansionResult<T> = Result<T, Box<Diagnostic>>;

#[derive(Clone, Copy, Debug, Default)]
struct ExpansionSize {
    nodes: usize,
    scalar_bytes: usize,
}

impl ExpansionSize {
    fn with_node(self) -> Self {
        Self {
            nodes: self.nodes.saturating_add(1),
            scalar_bytes: self.scalar_bytes,
        }
    }

    fn add(self, other: Self) -> Self {
        Self {
            nodes: self.nodes.saturating_add(other.nodes),
            scalar_bytes: self.scalar_bytes.saturating_add(other.scalar_bytes),
        }
    }
}

#[derive(Clone, Debug)]
struct ExpandedNode {
    node: YamlNode,
    size: ExpansionSize,
    alias_height: usize,
    provenance_records: usize,
}

#[derive(Debug)]
enum ExpansionTask<'document> {
    Visit {
        node: &'document YamlNode,
        alias_depth: usize,
        alias_use_span: Option<&'document SourceSpan>,
    },
    FinishSequence {
        item_count: usize,
        span: SourceSpan,
        limit_span: SourceSpan,
        tag: Option<YamlTag>,
        alias_expansions: Vec<YamlAliasExpansion>,
    },
    FinishMapping {
        entry_spans: Vec<SourceSpan>,
        span: SourceSpan,
        limit_span: SourceSpan,
        tag: Option<YamlTag>,
        alias_expansions: Vec<YamlAliasExpansion>,
    },
    FinishAlias {
        target: AnchorId,
        alias_use_span: SourceSpan,
    },
}

#[derive(Debug)]
struct AliasExpander<'document> {
    anchors: HashMap<AnchorId, &'document YamlNode>,
    memo: HashMap<AnchorId, ExpandedNode>,
    active: HashSet<AnchorId>,
    limits: ParseLimits,
    work: usize,
}

pub(crate) fn expand_aliases(
    document: &YamlDocument,
    limits: ParseLimits,
) -> ExpansionResult<YamlDocument> {
    let (anchors, table_work) = collect_anchors(document.root())?;
    let mut expander = AliasExpander {
        anchors,
        memo: HashMap::new(),
        active: HashSet::new(),
        limits,
        work: table_work,
    };
    expander.check_work(document.root().span())?;
    let expanded_root = expander.expand(document.root())?;
    Ok(YamlDocument {
        root: expanded_root.node,
        explicit_start: document.explicit_start,
        span: document.span.clone(),
    })
}

fn collect_anchors(root: &YamlNode) -> ExpansionResult<(HashMap<AnchorId, &YamlNode>, usize)> {
    let mut anchors = HashMap::new();
    let mut stack = vec![root];
    let mut work = 0_usize;
    while let Some(node) = stack.pop() {
        work = work.saturating_add(1);
        if let Some(anchor) = node.anchor()
            && let Some(previous) = anchors.insert(anchor, node)
        {
            return Err(Box::new(
                Diagnostic::error(
                    DiagnosticKind::Syntax,
                    "yaml.duplicate_anchor_identity",
                    "YAML parser reused an internal anchor identity",
                    node.span().clone(),
                )
                .with_related("first identity assignment is here", previous.span().clone()),
            ));
        }
        match node.kind() {
            YamlNodeKind::Scalar(_) | YamlNodeKind::Alias(_) => {}
            YamlNodeKind::Sequence(items) => stack.extend(items.iter().rev()),
            YamlNodeKind::Mapping(entries) => {
                for entry in entries.iter().rev() {
                    stack.push(entry.value());
                    stack.push(entry.key());
                }
            }
        }
    }
    Ok((anchors, work))
}

impl<'document> AliasExpander<'document> {
    // Keeping this state-machine loop in one place makes the non-recursive
    // stack/value invariants reviewable together.
    #[allow(clippy::too_many_lines)]
    fn expand(&mut self, root: &'document YamlNode) -> ExpansionResult<ExpandedNode> {
        let mut tasks = vec![ExpansionTask::Visit {
            node: root,
            alias_depth: 0,
            alias_use_span: None,
        }];
        let mut values = Vec::new();
        let mut frontier_size = ExpansionSize::default();

        while let Some(task) = tasks.pop() {
            match task {
                ExpansionTask::Visit {
                    node,
                    alias_depth,
                    alias_use_span,
                } => {
                    self.charge_work(1, node.span())?;
                    let limit_span = alias_use_span.unwrap_or_else(|| node.span());
                    match node.kind() {
                        YamlNodeKind::Scalar(scalar) => {
                            let size = ExpansionSize {
                                nodes: 1,
                                scalar_bytes: scalar.decoded().len(),
                            };
                            let next_frontier = frontier_size.add(size);
                            self.check_size(next_frontier, limit_span)?;
                            values.push(ExpandedNode {
                                node: YamlNode {
                                    kind: YamlNodeKind::Scalar(scalar.clone()),
                                    span: node.span.clone(),
                                    anchor: None,
                                    tag: node.tag.clone(),
                                    alias_expansions: node.alias_expansions.clone(),
                                },
                                size,
                                alias_height: 0,
                                provenance_records: node.alias_expansions.len(),
                            });
                            frontier_size = next_frontier;
                        }
                        YamlNodeKind::Sequence(items) => {
                            tasks.push(ExpansionTask::FinishSequence {
                                item_count: items.len(),
                                span: node.span.clone(),
                                limit_span: limit_span.clone(),
                                tag: node.tag.clone(),
                                alias_expansions: node.alias_expansions.clone(),
                            });
                            for item in items.iter().rev() {
                                tasks.push(ExpansionTask::Visit {
                                    node: item,
                                    alias_depth,
                                    alias_use_span,
                                });
                            }
                        }
                        YamlNodeKind::Mapping(entries) => {
                            tasks.push(ExpansionTask::FinishMapping {
                                entry_spans: entries
                                    .iter()
                                    .map(|entry| entry.span.clone())
                                    .collect(),
                                span: node.span.clone(),
                                limit_span: limit_span.clone(),
                                tag: node.tag.clone(),
                                alias_expansions: node.alias_expansions.clone(),
                            });
                            for entry in entries.iter().rev() {
                                tasks.push(ExpansionTask::Visit {
                                    node: entry.value(),
                                    alias_depth,
                                    alias_use_span,
                                });
                                tasks.push(ExpansionTask::Visit {
                                    node: entry.key(),
                                    alias_depth,
                                    alias_use_span,
                                });
                            }
                        }
                        YamlNodeKind::Alias(alias) => {
                            self.visit_alias(
                                alias.target(),
                                node.span(),
                                alias_depth,
                                &mut tasks,
                                &mut values,
                                &mut frontier_size,
                            )?;
                        }
                    }
                }
                ExpansionTask::FinishSequence {
                    item_count,
                    span,
                    limit_span,
                    tag,
                    alias_expansions,
                } => {
                    let next_frontier = frontier_size.with_node();
                    self.check_size(next_frontier, &limit_span)?;
                    let start = values
                        .len()
                        .checked_sub(item_count)
                        .expect("sequence children were scheduled before their parent");
                    let children = values.split_off(start);
                    let mut size = ExpansionSize::default().with_node();
                    let mut alias_height = 0_usize;
                    let mut provenance_records = alias_expansions.len();
                    let mut items = Vec::with_capacity(item_count);
                    for child in children {
                        size = size.add(child.size);
                        alias_height = alias_height.max(child.alias_height);
                        provenance_records =
                            provenance_records.saturating_add(child.provenance_records);
                        items.push(child.node);
                    }
                    values.push(ExpandedNode {
                        node: YamlNode {
                            kind: YamlNodeKind::Sequence(items),
                            span,
                            anchor: None,
                            tag,
                            alias_expansions,
                        },
                        size,
                        alias_height,
                        provenance_records,
                    });
                    frontier_size = next_frontier;
                }
                ExpansionTask::FinishMapping {
                    entry_spans,
                    span,
                    limit_span,
                    tag,
                    alias_expansions,
                } => {
                    let next_frontier = frontier_size.with_node();
                    self.check_size(next_frontier, &limit_span)?;
                    let child_count = entry_spans.len().saturating_mul(2);
                    let start = values
                        .len()
                        .checked_sub(child_count)
                        .expect("mapping children were scheduled before their parent");
                    let mut children = values.split_off(start).into_iter();
                    let mut size = ExpansionSize::default().with_node();
                    let mut alias_height = 0_usize;
                    let mut provenance_records = alias_expansions.len();
                    let mut entries = Vec::with_capacity(entry_spans.len());
                    for entry_span in entry_spans {
                        let key = children.next().expect("mapping key was expanded");
                        size = size.add(key.size);
                        alias_height = alias_height.max(key.alias_height);
                        provenance_records =
                            provenance_records.saturating_add(key.provenance_records);
                        let value = children.next().expect("mapping value was expanded");
                        size = size.add(value.size);
                        alias_height = alias_height.max(value.alias_height);
                        provenance_records =
                            provenance_records.saturating_add(value.provenance_records);
                        entries.push(YamlMappingEntry {
                            key: key.node,
                            value: value.node,
                            span: entry_span,
                        });
                    }
                    values.push(ExpandedNode {
                        node: YamlNode {
                            kind: YamlNodeKind::Mapping(entries),
                            span,
                            anchor: None,
                            tag,
                            alias_expansions,
                        },
                        size,
                        alias_height,
                        provenance_records,
                    });
                    frontier_size = next_frontier;
                }
                ExpansionTask::FinishAlias {
                    target,
                    alias_use_span,
                } => {
                    let expanded_definition = values
                        .pop()
                        .expect("alias definition was scheduled before completion");
                    let removed = self.active.remove(&target);
                    debug_assert!(removed, "completed alias target must be active");
                    let size = expanded_definition.size;
                    let alias_height = expanded_definition.alias_height.saturating_add(1);
                    let provenance_records = expanded_definition
                        .provenance_records
                        .saturating_add(size.nodes);
                    let clone_work = expanded_definition
                        .provenance_records
                        .saturating_add(size.nodes.saturating_mul(2));
                    self.memo.entry(target).or_insert(expanded_definition);
                    self.charge_work(clone_work, &alias_use_span)?;
                    let mut node = self
                        .memo
                        .get(&target)
                        .expect("completed alias target was memoized")
                        .node
                        .clone();
                    rebind_alias_copy(&mut node, target, &alias_use_span);
                    values.push(ExpandedNode {
                        node,
                        size,
                        alias_height,
                        provenance_records,
                    });
                }
            }
        }

        debug_assert!(self.active.is_empty());
        debug_assert_eq!(values.len(), 1);
        let expanded = values.pop().expect("root expansion produced one value");
        debug_assert_eq!(frontier_size.nodes, expanded.size.nodes);
        debug_assert_eq!(frontier_size.scalar_bytes, expanded.size.scalar_bytes);
        Ok(expanded)
    }

    fn visit_alias(
        &mut self,
        target: AnchorId,
        alias_use_span: &'document SourceSpan,
        alias_depth: usize,
        tasks: &mut Vec<ExpansionTask<'document>>,
        values: &mut Vec<ExpandedNode>,
        frontier_size: &mut ExpansionSize,
    ) -> ExpansionResult<()> {
        let Some(definition) = self.anchors.get(&target).copied() else {
            return Err(Box::new(Diagnostic::error(
                DiagnosticKind::Semantic,
                "github.yaml_undefined_alias",
                "YAML alias references an anchor definition that does not exist",
                alias_use_span.clone(),
            )));
        };

        if self.active.contains(&target) {
            return Err(Box::new(
                Diagnostic::error(
                    DiagnosticKind::Semantic,
                    "github.yaml_alias_cycle",
                    "YAML alias expansion contains a cycle",
                    alias_use_span.clone(),
                )
                .with_related("cyclic anchor is defined here", definition.span().clone()),
            ));
        }
        self.check_alias_depth(alias_depth.saturating_add(1), alias_use_span, definition)?;

        if let Some((size, target_height, target_provenance)) = self
            .memo
            .get(&target)
            .map(|cached| (cached.size, cached.alias_height, cached.provenance_records))
        {
            let alias_height = target_height.saturating_add(1);
            let provenance_records = target_provenance.saturating_add(size.nodes);
            self.check_alias_depth(
                alias_depth.saturating_add(alias_height),
                alias_use_span,
                definition,
            )?;
            let next_frontier = frontier_size.add(size);
            self.check_size(next_frontier, alias_use_span)?;
            self.charge_work(
                target_provenance.saturating_add(size.nodes.saturating_mul(2)),
                alias_use_span,
            )?;
            let mut node = self
                .memo
                .get(&target)
                .expect("memo size came from this entry")
                .node
                .clone();
            rebind_alias_copy(&mut node, target, alias_use_span);
            values.push(ExpandedNode {
                node,
                size,
                alias_height,
                provenance_records,
            });
            *frontier_size = next_frontier;
            return Ok(());
        }

        self.active.insert(target);
        tasks.push(ExpansionTask::FinishAlias {
            target,
            alias_use_span: alias_use_span.clone(),
        });
        tasks.push(ExpansionTask::Visit {
            node: definition,
            alias_depth: alias_depth.saturating_add(1),
            alias_use_span: Some(alias_use_span),
        });
        Ok(())
    }

    fn check_alias_depth(
        &self,
        depth: usize,
        alias_use_span: &SourceSpan,
        definition: &YamlNode,
    ) -> ExpansionResult<()> {
        if depth > self.limits.max_alias_expansion_depth() {
            return Err(Box::new(
                Diagnostic::error(
                    DiagnosticKind::ResourceLimit,
                    "yaml.maximum_alias_expansion_depth_exceeded",
                    format!(
                        "YAML alias expansion exceeds the configured maximum depth of {}",
                        self.limits.max_alias_expansion_depth()
                    ),
                    alias_use_span.clone(),
                )
                .with_related("selected anchor is defined here", definition.span().clone()),
            ));
        }
        Ok(())
    }

    fn check_size(&self, size: ExpansionSize, span: &SourceSpan) -> ExpansionResult<()> {
        if size.nodes > self.limits.max_expanded_nodes() {
            return Err(Box::new(Diagnostic::error(
                DiagnosticKind::ResourceLimit,
                "yaml.maximum_expanded_nodes_exceeded",
                format!(
                    "expanded YAML contains more than {} nodes",
                    self.limits.max_expanded_nodes()
                ),
                span.clone(),
            )));
        }
        if size.scalar_bytes > self.limits.max_expanded_scalar_bytes() {
            return Err(Box::new(Diagnostic::error(
                DiagnosticKind::ResourceLimit,
                "yaml.maximum_expanded_scalar_bytes_exceeded",
                format!(
                    "expanded YAML contains more than {} decoded scalar bytes",
                    self.limits.max_expanded_scalar_bytes()
                ),
                span.clone(),
            )));
        }
        Ok(())
    }

    fn charge_work(&mut self, amount: usize, span: &SourceSpan) -> ExpansionResult<()> {
        self.work = self.work.saturating_add(amount);
        self.check_work(span)
    }

    fn check_work(&self, span: &SourceSpan) -> ExpansionResult<()> {
        if self.work > self.limits.max_alias_expansion_work() {
            return Err(Box::new(Diagnostic::error(
                DiagnosticKind::ResourceLimit,
                "yaml.maximum_alias_expansion_work_exceeded",
                format!(
                    "YAML alias expansion exceeds the configured work limit of {}",
                    self.limits.max_alias_expansion_work()
                ),
                span.clone(),
            )));
        }
        Ok(())
    }
}

fn rebind_alias_copy(node: &mut YamlNode, target: AnchorId, alias_use_span: &SourceSpan) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        let definition_span = node.span.clone();
        node.span = alias_use_span.clone();
        node.anchor = None;
        node.alias_expansions.push(YamlAliasExpansion {
            target,
            alias_use_span: alias_use_span.clone(),
            definition_span,
        });
        match &mut node.kind {
            YamlNodeKind::Scalar(_) => {}
            YamlNodeKind::Alias(_) => {
                debug_assert!(false, "expanded alias copy must not retain aliases");
            }
            YamlNodeKind::Sequence(items) => stack.extend(items.iter_mut()),
            YamlNodeKind::Mapping(entries) => {
                for entry in entries {
                    entry.span = alias_use_span.clone();
                    let YamlMappingEntry { key, value, .. } = entry;
                    stack.push(key);
                    stack.push(value);
                }
            }
        }
    }
}
