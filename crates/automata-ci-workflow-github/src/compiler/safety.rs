//! Checks that prevent source constructs from disappearing during lowering.

use std::collections::BTreeMap;

use crate::{Diagnostic, DiagnosticKind, GithubWorkflowSourcePlan, YamlNode, YamlNodeKind};

use super::CompileContext;

pub(super) fn scan_lossy_yaml(
    source_plan: &GithubWorkflowSourcePlan,
    context: &mut CompileContext<'_>,
) {
    scan_tags(source_plan.document().root(), context);
    scan_mapping_safety(source_plan.expanded_document().root(), context);
}

fn scan_tags(node: &YamlNode, context: &mut CompileContext<'_>) {
    if node.tag().is_some() {
        context.unsupported(
            "github.compile.yaml_tag",
            "explicit YAML tags have no durable workflow-plan representation",
            node.span().clone(),
        );
    }
    match node.kind() {
        YamlNodeKind::Scalar(_) | YamlNodeKind::Alias(_) => {}
        YamlNodeKind::Sequence(items) => {
            for item in items {
                scan_tags(item, context);
            }
        }
        YamlNodeKind::Mapping(entries) => {
            for entry in entries {
                scan_tags(entry.key(), context);
                scan_tags(entry.value(), context);
            }
        }
    }
}

fn scan_mapping_safety(node: &YamlNode, context: &mut CompileContext<'_>) {
    match node.kind() {
        YamlNodeKind::Scalar(_) | YamlNodeKind::Alias(_) => {}
        YamlNodeKind::Sequence(items) => {
            for item in items {
                scan_mapping_safety(item, context);
            }
        }
        YamlNodeKind::Mapping(entries) => {
            let mut keys = BTreeMap::new();
            for entry in entries {
                if let Some(key) = entry.key().as_scalar() {
                    if key.decoded() == "<<" {
                        context.unsupported(
                            "github.compile.yaml_merge_key",
                            "YAML merge keys cannot be compiled without an explicit expansion policy",
                            entry.key().span().clone(),
                        );
                    }
                    if let Some(previous) = keys.insert(key.decoded(), entry.key().span()) {
                        context.diagnostics.push(
                            Diagnostic::error(
                                DiagnosticKind::Semantic,
                                "github.compile.duplicate_mapping_key",
                                format!(
                                    "mapping key `{}` is defined more than once and cannot be compiled deterministically",
                                    key.decoded()
                                ),
                                entry.key().span().clone(),
                            )
                            .with_related("first definition is here", previous.clone()),
                        );
                    }
                }
                scan_mapping_safety(entry.key(), context);
                scan_mapping_safety(entry.value(), context);
            }
        }
    }
}
