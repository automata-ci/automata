use crate::{
    BooleanValue, Concurrency, ConcurrencyQueue, Defaults, DetailedConcurrency, PermissionEntry,
    PermissionLevel, Permissions, PreservedField, RunDefaults, ScalarResolution, ScalarValue,
    Spanned, ValueMap, ValueMapEntry, YamlNode,
};
use automata_ci_github_permissions::{
    GITHUB_WORKFLOW_PERMISSION_CATALOG_REVISION, github_workflow_permission,
};

use super::{DecodeContext, field_name};

pub(super) fn scalar_value(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<ScalarValue> {
    let scalar = context.scalar(node, path)?;
    Some(ScalarValue::from_yaml(scalar, node.span.clone()))
}

pub(super) fn positive_integer(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<ScalarValue> {
    let value = scalar_value(node, path, context)?;
    if !value.contains_expression_candidate()
        && (value.resolution != ScalarResolution::Integer
            || value
                .decoded
                .parse::<u64>()
                .map_or(true, |number| number == 0))
    {
        context.semantic(
            "github.expected_positive_integer",
            format!("`{path}` must be a positive integer or expression"),
            node.span.clone(),
        );
    }
    Some(value)
}

pub(super) fn boolean(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<BooleanValue> {
    let scalar = context.scalar(node, path)?;
    if scalar.decoded.contains("${{") {
        return Some(BooleanValue::Expression(Spanned::new(
            scalar.decoded.clone(),
            node.span.clone(),
        )));
    }
    let value = match (scalar.resolution, scalar.decoded.as_str()) {
        (ScalarResolution::Boolean, "true" | "True" | "TRUE") => Some(true),
        (ScalarResolution::Boolean, "false" | "False" | "FALSE") => Some(false),
        _ => None,
    };
    if let Some(value) = value {
        return Some(BooleanValue::Literal(Spanned::new(
            value,
            node.span.clone(),
        )));
    }
    context.semantic(
        "github.expected_boolean",
        format!("`{path}` must be a YAML 1.2 boolean or expression"),
        node.span.clone(),
    );
    None
}

pub(super) fn value_map(node: &YamlNode, path: &str, context: &mut DecodeContext<'_>) -> ValueMap {
    let Some(entries) = context.expect_mapping(node, path) else {
        return ValueMap::empty();
    };
    let mut values = Vec::with_capacity(entries.len());
    for entry in entries {
        if context.is_exhausted() {
            break;
        }
        let Some(key) = entry.key.as_scalar() else {
            continue;
        };
        let Some(entry_path) = context.child_path(path, &key.decoded, &entry.key.span) else {
            break;
        };
        if let Some(value) = scalar_value(&entry.value, &entry_path, context) {
            values.push(ValueMapEntry {
                key: Spanned::new(key.decoded.clone(), entry.key.span.clone()),
                value,
            });
        }
    }
    ValueMap { entries: values }
}

pub(super) fn permissions(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<Permissions> {
    if let Some(scalar) = node.as_scalar() {
        return match scalar.decoded.as_str() {
            "read-all" => Some(Permissions::ReadAll(node.span.clone())),
            "write-all" => Some(Permissions::WriteAll(node.span.clone())),
            _ => {
                context.semantic(
                    "github.invalid_permissions",
                    format!("`{path}` must be `read-all`, `write-all`, or a mapping"),
                    node.span.clone(),
                );
                None
            }
        };
    }

    let entries = context.expect_mapping(node, path)?;
    let mut permissions = Vec::with_capacity(entries.len());
    for entry in entries {
        if context.is_exhausted() {
            break;
        }
        let Some(name) = entry.key.as_scalar() else {
            continue;
        };
        let Some(entry_path) = context.child_path(path, &name.decoded, &entry.key.span) else {
            break;
        };
        let Some(permission) = github_workflow_permission(&name.decoded) else {
            context.semantic(
                "github.unknown_permission",
                format!(
                    "`{entry_path}` is not present in GitHub workflow permission catalog revision {GITHUB_WORKFLOW_PERMISSION_CATALOG_REVISION}"
                ),
                entry.key.span.clone(),
            );
            continue;
        };
        let Some(level) = context.scalar(&entry.value, &entry_path) else {
            continue;
        };
        let level = match level.decoded.as_str() {
            "read" if permission.allows_read() => PermissionLevel::Read,
            "write" if permission.allows_write() => PermissionLevel::Write,
            "none" => PermissionLevel::None,
            "read" if name.decoded == "id-token" => {
                context.semantic(
                    "github.invalid_id_token_permission_level",
                    format!("`{entry_path}` must be `write` or `none`"),
                    entry.value.span.clone(),
                );
                continue;
            }
            "write" if name.decoded == "vulnerability-alerts" => {
                context.semantic(
                    "github.invalid_permission_level",
                    format!("`{entry_path}` must be `read` or `none`"),
                    entry.value.span.clone(),
                );
                continue;
            }
            _ => {
                context.semantic(
                    "github.invalid_permission_level",
                    format!("`{entry_path}` must be `read`, `write`, or `none`"),
                    entry.value.span.clone(),
                );
                continue;
            }
        };
        permissions.push(PermissionEntry {
            name: Spanned::new(name.decoded.clone(), entry.key.span.clone()),
            level: Spanned::new(level, entry.value.span.clone()),
        });
    }
    if context.is_exhausted() {
        return None;
    }
    Some(Permissions::Mapping {
        entries: permissions,
        span: node.span.clone(),
    })
}

pub(super) fn defaults(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<Defaults> {
    let entries = context.expect_mapping(node, path)?;
    let mut run = None;
    let mut extensions = Vec::new();
    for entry in entries {
        if context.is_exhausted() {
            break;
        }
        match field_name(entry) {
            Some("run") if run.is_none() => {
                let Some(field_path) = context.child_path(path, "run", &entry.key.span) else {
                    break;
                };
                run = parse_run_defaults(&entry.value, &field_path, context);
            }
            Some("run") => {}
            _ => {
                if let Some(extension) = context.preserve_unknown(path, entry) {
                    extensions.push(extension);
                }
            }
        }
    }
    if context.is_exhausted() {
        return None;
    }
    Some(Defaults { run, extensions })
}

fn parse_run_defaults(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<RunDefaults> {
    let entries = context.expect_mapping(node, path)?;
    let mut shell = None;
    let mut working_directory = None;
    let mut extensions = Vec::new();
    for entry in entries {
        if context.is_exhausted() {
            break;
        }
        match field_name(entry) {
            Some("shell") if shell.is_none() => {
                let Some(field_path) = context.child_path(path, "shell", &entry.key.span) else {
                    break;
                };
                shell = context.text(&entry.value, &field_path);
            }
            Some("working-directory") if working_directory.is_none() => {
                let Some(field_path) =
                    context.child_path(path, "working-directory", &entry.key.span)
                else {
                    break;
                };
                working_directory = context.text(&entry.value, &field_path);
            }
            Some("shell" | "working-directory") => {}
            _ => {
                if let Some(extension) = context.preserve_unknown(path, entry) {
                    extensions.push(extension);
                }
            }
        }
    }
    if context.is_exhausted() {
        return None;
    }
    Some(RunDefaults {
        shell,
        working_directory,
        extensions,
    })
}

pub(super) fn concurrency(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<Concurrency> {
    if node.as_scalar().is_some() {
        return context.text(node, path).map(Concurrency::Group);
    }

    let entries = context.expect_mapping(node, path)?;
    let mut group = None;
    let mut cancel_in_progress = None;
    let mut queue = None;
    let mut extensions: Vec<PreservedField> = Vec::new();
    for entry in entries {
        if context.is_exhausted() {
            break;
        }
        match field_name(entry) {
            Some("group") if group.is_none() => {
                let Some(field_path) = context.child_path(path, "group", &entry.key.span) else {
                    break;
                };
                group = context.text(&entry.value, &field_path);
            }
            Some("cancel-in-progress") if cancel_in_progress.is_none() => {
                let Some(field_path) =
                    context.child_path(path, "cancel-in-progress", &entry.key.span)
                else {
                    break;
                };
                cancel_in_progress = boolean(&entry.value, &field_path, context);
            }
            Some("queue") if queue.is_none() => {
                let Some(field_path) = context.child_path(path, "queue", &entry.key.span) else {
                    break;
                };
                queue = parse_queue(&entry.value, &field_path, context);
            }
            Some("group" | "cancel-in-progress" | "queue") => {}
            _ => {
                if let Some(extension) = context.preserve_unknown(path, entry) {
                    extensions.push(extension);
                }
            }
        }
    }
    if context.is_exhausted() {
        return None;
    }
    let Some(group) = group else {
        context.semantic(
            "github.concurrency_group_required",
            format!("`{path}.group` is required"),
            node.span.clone(),
        );
        return None;
    };

    if matches!(
        (&queue, &cancel_in_progress),
        (
            Some(Spanned {
                value: ConcurrencyQueue::Max,
                ..
            }),
            Some(BooleanValue::Literal(Spanned { value: true, .. }))
        )
    ) {
        context.semantic(
            "github.concurrency_queue_conflict",
            "`queue: max` cannot be combined with `cancel-in-progress: true`",
            node.span.clone(),
        );
    }

    Some(Concurrency::Detailed(Box::new(DetailedConcurrency {
        group,
        cancel_in_progress,
        queue,
        extensions,
        span: node.span.clone(),
    })))
}

fn parse_queue(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<Spanned<ConcurrencyQueue>> {
    let text = context.text(node, path)?;
    let value = match text.value.as_str() {
        "single" => ConcurrencyQueue::Single,
        "max" => ConcurrencyQueue::Max,
        _ => {
            context.semantic(
                "github.invalid_concurrency_queue",
                format!("`{path}` must be `single` or `max`"),
                text.span,
            );
            return None;
        }
    };
    Some(Spanned::new(value, text.span))
}
