use crate::{
    BooleanValue, JobStrategy, MatrixConfiguration, MatrixConfigurations, MatrixDimension,
    MatrixDimensionValues, MatrixMapping, MatrixValue, MatrixValueEntry, PreservedField,
    ScalarResolution, ScalarValue, Spanned, StrategyMatrix, YamlMappingEntry, YamlNode,
};

use super::{
    DecodeContext, field_name,
    value::{boolean, scalar_value},
};

pub(super) fn strategy(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<JobStrategy> {
    let Some(entries) = node.as_mapping() else {
        context.semantic(
            "github.expected_strategy_mapping",
            format!("`{path}` must be a mapping"),
            node.span.clone(),
        );
        return None;
    };

    if entries.is_empty() {
        context.semantic(
            "github.empty_strategy",
            format!("`{path}` must contain at least one strategy field"),
            node.span.clone(),
        );
    }

    let mut fail_fast = None;
    let mut fail_fast_seen = false;
    let mut max_parallel = None;
    let mut max_parallel_seen = false;
    let mut matrix = None;
    let mut matrix_seen = false;
    let mut extensions = Vec::new();

    for entry in entries {
        if context.is_exhausted() {
            break;
        }
        match field_name(entry) {
            Some("fail-fast") if !fail_fast_seen => {
                let Some(field_path) = context.child_path(path, "fail-fast", &entry.key.span)
                else {
                    break;
                };
                fail_fast = boolean(&entry.value, &field_path, context);
                if let Some(BooleanValue::Expression(expression)) = &fail_fast
                    && !is_single_expression(expression.value())
                {
                    context.semantic(
                        "github.expected_strategy_fail_fast",
                        format!("`{field_path}` must be a boolean or one complete expression"),
                        expression.span().clone(),
                    );
                }
                fail_fast_seen = true;
            }
            Some("max-parallel") if !max_parallel_seen => {
                let Some(field_path) = context.child_path(path, "max-parallel", &entry.key.span)
                else {
                    break;
                };
                max_parallel = parse_max_parallel(&entry.value, &field_path, context);
                max_parallel_seen = true;
            }
            Some("matrix") if !matrix_seen => {
                let Some(field_path) = context.child_path(path, "matrix", &entry.key.span) else {
                    break;
                };
                matrix = parse_matrix(&entry.value, &field_path, context);
                matrix_seen = true;
            }
            Some("fail-fast" | "max-parallel" | "matrix") => {}
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
    Some(JobStrategy {
        fail_fast,
        max_parallel,
        matrix,
        extensions,
        span: node.span.clone(),
    })
}

fn parse_max_parallel(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<ScalarValue> {
    let value = scalar_value(node, path, context)?;
    let bytes = value.decoded().as_bytes();
    let is_positive_integer = value.resolution() == ScalarResolution::Integer
        && matches!(bytes.first(), Some(b'1'..=b'9'))
        && bytes[1..].iter().all(u8::is_ascii_digit)
        && value.decoded().parse::<i64>().is_ok();
    if !is_positive_integer && !is_single_expression(value.decoded()) {
        context.semantic(
            "github.expected_strategy_max_parallel",
            format!("`{path}` must be a positive integer or one complete expression"),
            node.span.clone(),
        );
    }
    Some(value)
}

fn parse_matrix(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<StrategyMatrix> {
    if node.as_scalar().is_some() {
        let value = scalar_value(node, path, context)?;
        if is_single_expression(value.decoded()) {
            return Some(StrategyMatrix::Expression(value));
        }
        context.semantic(
            "github.expected_strategy_matrix",
            format!("`{path}` must be a mapping or one complete expression"),
            node.span.clone(),
        );
        return None;
    }

    let Some(entries) = node.as_mapping() else {
        context.semantic(
            "github.expected_strategy_matrix",
            format!("`{path}` must be a mapping or one complete expression"),
            node.span.clone(),
        );
        return None;
    };
    reject_empty_matrix(entries, path, node, context);
    if context.is_exhausted() {
        return None;
    }

    let mut dimensions = Vec::new();
    let mut include = None;
    let mut include_seen = false;
    let mut exclude = None;
    let mut exclude_seen = false;
    let mut extensions = Vec::new();

    for (index, entry) in entries.iter().enumerate() {
        if context.is_exhausted() {
            break;
        }
        let Some(key) = entry.key.as_scalar() else {
            context.semantic(
                "github.expected_matrix_dimension_name",
                format!("matrix key at `{path}` must be a scalar name"),
                entry.key.span.clone(),
            );
            if let Some(extension) = preserve_complex_key(path, index, entry, context) {
                extensions.push(extension);
            }
            continue;
        };
        match key.decoded.as_str() {
            "include" if !include_seen => {
                let Some(field_path) = context.child_path(path, "include", &entry.key.span) else {
                    break;
                };
                include = parse_configurations(&entry.value, &field_path, context);
                include_seen = true;
            }
            "exclude" if !exclude_seen => {
                let Some(field_path) = context.child_path(path, "exclude", &entry.key.span) else {
                    break;
                };
                exclude = parse_configurations(&entry.value, &field_path, context);
                exclude_seen = true;
            }
            "include" | "exclude" => {}
            _ => {
                if key.is_null() || key.decoded.is_empty() {
                    context.semantic(
                        "github.expected_matrix_dimension_name",
                        format!("matrix dimension at `{path}` must have a non-null name"),
                        entry.key.span.clone(),
                    );
                    if let Some(extension) = preserve_complex_key(path, index, entry, context) {
                        extensions.push(extension);
                    }
                    continue;
                }
                let Some(dimension_path) = context.child_path(path, &key.decoded, &entry.key.span)
                else {
                    break;
                };
                if let Some(values) = parse_dimension_values(&entry.value, &dimension_path, context)
                {
                    dimensions.push(MatrixDimension {
                        name: Spanned::new(key.decoded.clone(), entry.key.span.clone()),
                        values,
                        span: entry.span.clone(),
                    });
                }
            }
        }
    }

    if context.is_exhausted() {
        return None;
    }
    Some(StrategyMatrix::Mapping(Box::new(MatrixMapping {
        dimensions,
        include,
        exclude,
        extensions,
        span: node.span.clone(),
    })))
}

fn reject_empty_matrix(
    entries: &[YamlMappingEntry],
    path: &str,
    node: &YamlNode,
    context: &mut DecodeContext<'_>,
) {
    if entries.is_empty() {
        context.semantic(
            "github.empty_strategy_matrix",
            format!("`{path}` must contain a dimension, `include`, or `exclude`"),
            node.span.clone(),
        );
    }
}

fn parse_dimension_values(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<MatrixDimensionValues> {
    if node.as_scalar().is_some() {
        let expression = scalar_value(node, path, context)?;
        if is_single_expression(expression.decoded()) {
            return Some(MatrixDimensionValues::Expression(expression));
        }
        context.semantic(
            "github.expected_matrix_dimension_values",
            format!("`{path}` must be a non-empty sequence or one complete expression"),
            node.span.clone(),
        );
        return None;
    }

    let Some(items) = node.as_sequence() else {
        context.semantic(
            "github.expected_matrix_dimension_values",
            format!("`{path}` must be a non-empty sequence or one complete expression"),
            node.span.clone(),
        );
        return None;
    };
    if items.is_empty() {
        context.semantic(
            "github.empty_matrix_dimension",
            format!("`{path}` must contain at least one value"),
            node.span.clone(),
        );
    }
    let mut values = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        if context.is_exhausted() {
            break;
        }
        let Some(item_path) = context.indexed_path(path, index, &item.span) else {
            break;
        };
        if let Some(value) = matrix_value(item, &item_path, context) {
            values.push(value);
        }
    }
    if context.is_exhausted() {
        return None;
    }
    Some(MatrixDimensionValues::Sequence {
        values,
        span: node.span.clone(),
    })
}

fn parse_configurations(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<MatrixConfigurations> {
    if node.as_scalar().is_some() {
        let expression = scalar_value(node, path, context)?;
        if is_single_expression(expression.decoded()) {
            return Some(MatrixConfigurations::Expression(expression));
        }
        context.semantic(
            "github.expected_matrix_configurations",
            format!("`{path}` must be a non-empty sequence of mappings or one complete expression"),
            node.span.clone(),
        );
        return None;
    }

    let Some(items) = node.as_sequence() else {
        context.semantic(
            "github.expected_matrix_configurations",
            format!("`{path}` must be a non-empty sequence of mappings or one complete expression"),
            node.span.clone(),
        );
        return None;
    };
    if items.is_empty() {
        context.semantic(
            "github.empty_matrix_configurations",
            format!("`{path}` must contain at least one configuration"),
            node.span.clone(),
        );
    }

    let mut configurations = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        if context.is_exhausted() {
            break;
        }
        let Some(item_path) = context.indexed_path(path, index, &item.span) else {
            break;
        };
        if let Some(configuration) = matrix_configuration(item, &item_path, context) {
            configurations.push(configuration);
        }
    }
    if context.is_exhausted() {
        return None;
    }
    Some(MatrixConfigurations::Sequence {
        configurations,
        span: node.span.clone(),
    })
}

fn matrix_configuration(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<MatrixConfiguration> {
    let Some(entries) = node.as_mapping() else {
        context.semantic(
            "github.expected_matrix_configuration",
            format!("`{path}` must be a mapping"),
            node.span.clone(),
        );
        return None;
    };
    if entries.is_empty() {
        context.semantic(
            "github.empty_matrix_configuration",
            format!("`{path}` must contain at least one value"),
            node.span.clone(),
        );
    }
    let (entries, extensions) = matrix_object_entries(entries, path, context);
    if context.is_exhausted() {
        return None;
    }
    Some(MatrixConfiguration {
        entries,
        extensions,
        span: node.span.clone(),
    })
}

fn matrix_value(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<MatrixValue> {
    if context.is_exhausted() {
        return None;
    }
    if node.as_scalar().is_some() {
        return scalar_value(node, path, context).map(MatrixValue::Scalar);
    }
    if let Some(items) = node.as_sequence() {
        let mut values = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            if context.is_exhausted() {
                break;
            }
            let Some(item_path) = context.indexed_path(path, index, &item.span) else {
                break;
            };
            if let Some(value) = matrix_value(item, &item_path, context) {
                values.push(value);
            }
        }
        if context.is_exhausted() {
            return None;
        }
        return Some(MatrixValue::Sequence {
            values,
            span: node.span.clone(),
        });
    }
    if let Some(entries) = node.as_mapping() {
        let (entries, extensions) = matrix_object_entries(entries, path, context);
        if context.is_exhausted() {
            return None;
        }
        return Some(MatrixValue::Mapping {
            entries,
            extensions,
            span: node.span.clone(),
        });
    }
    context.semantic(
        "github.expected_matrix_value",
        format!("`{path}` must be a scalar, sequence, or mapping"),
        node.span.clone(),
    );
    None
}

fn matrix_object_entries(
    entries: &[YamlMappingEntry],
    path: &str,
    context: &mut DecodeContext<'_>,
) -> (Vec<MatrixValueEntry>, Vec<PreservedField>) {
    let mut values = Vec::with_capacity(entries.len());
    let mut extensions = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        if context.is_exhausted() {
            break;
        }
        let Some(key) = entry.key.as_scalar() else {
            context.semantic(
                "github.expected_matrix_value_name",
                format!("matrix object key at `{path}` must be a scalar name"),
                entry.key.span.clone(),
            );
            if let Some(extension) = preserve_complex_key(path, index, entry, context) {
                extensions.push(extension);
            }
            continue;
        };
        if key.is_null() || key.decoded.is_empty() {
            context.semantic(
                "github.expected_matrix_value_name",
                format!("matrix object at `{path}` must have a non-null key"),
                entry.key.span.clone(),
            );
            if let Some(extension) = preserve_complex_key(path, index, entry, context) {
                extensions.push(extension);
            }
            continue;
        }
        let Some(value_path) = context.child_path(path, &key.decoded, &entry.key.span) else {
            break;
        };
        if let Some(value) = matrix_value(&entry.value, &value_path, context) {
            values.push(MatrixValueEntry {
                key: Spanned::new(key.decoded.clone(), entry.key.span.clone()),
                value,
                span: entry.span.clone(),
            });
        }
    }
    (values, extensions)
}

fn preserve_complex_key(
    path: &str,
    index: usize,
    entry: &YamlMappingEntry,
    context: &mut DecodeContext<'_>,
) -> Option<PreservedField> {
    let path = context.invalid_key_path(path, index, &entry.key.span)?;
    Some(PreservedField {
        path,
        entry: entry.clone(),
    })
}

fn is_single_expression(source: &str) -> bool {
    let source = source.trim();
    let Some(mut cursor) = source.strip_prefix("${{").map(|_| 3) else {
        return false;
    };
    let bytes = source.as_bytes();
    let mut quoted = false;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\'' {
            if quoted && bytes.get(cursor + 1) == Some(&b'\'') {
                cursor += 2;
                continue;
            }
            quoted = !quoted;
            cursor += 1;
            continue;
        }
        if !quoted && bytes[cursor..].starts_with(b"${{") {
            return false;
        }
        if !quoted && bytes[cursor..].starts_with(b"}}") {
            return !source[3..cursor].trim().is_empty() && cursor + 2 == bytes.len();
        }
        cursor += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::is_single_expression;

    #[test]
    fn detects_one_complete_expression() {
        assert!(is_single_expression("${{ fromJSON(inputs.matrix) }}"));
        assert!(is_single_expression("  ${{ format('x}}y') }}  "));
        assert!(!is_single_expression("prefix-${{ inputs.matrix }}"));
        assert!(!is_single_expression("${{ inputs.a }}-${{ inputs.b }}"));
        assert!(!is_single_expression("${{ }}"));
        assert!(!is_single_expression("${{ inputs.matrix"));
    }
}
