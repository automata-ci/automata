//! Checks that prevent source constructs from disappearing during lowering.

use std::collections::BTreeMap;

use crate::{Diagnostic, DiagnosticKind, YamlNode, YamlNodeKind};

use super::CompileContext;

pub(super) fn scan_lossy_yaml(node: &YamlNode, context: &mut CompileContext<'_>) {
    if node.anchor().is_some() {
        context.unsupported(
            "github.compile.yaml_anchor",
            "YAML anchors cannot be compiled without changing GitHub source semantics",
            node.span().clone(),
        );
    }
    if node.tag().is_some() {
        context.unsupported(
            "github.compile.yaml_tag",
            "explicit YAML tags are not represented by workflow-plan v1",
            node.span().clone(),
        );
    }
    match node.kind() {
        YamlNodeKind::Scalar(_) => {}
        YamlNodeKind::Alias(_) => context.unsupported(
            "github.compile.yaml_alias",
            "YAML aliases cannot be compiled without an explicit expansion policy",
            node.span().clone(),
        ),
        YamlNodeKind::Sequence(items) => {
            for item in items {
                scan_lossy_yaml(item, context);
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
                scan_lossy_yaml(entry.key(), context);
                scan_lossy_yaml(entry.value(), context);
            }
        }
    }
}
