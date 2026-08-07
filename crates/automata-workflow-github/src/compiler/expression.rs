//! Lossless compilation of deferred GitHub expression templates.

use automata_core::{ExpressionSegment, Located, PlanExpression, PlanValue};

use crate::{SourceSpan, Spanned};

use super::CompileContext;

pub(super) fn compile_condition(
    value: &Spanned<String>,
    context: &mut CompileContext<'_>,
) -> Option<Located<PlanExpression>> {
    let expression = if crate::expression::condition_has_expression_opening(value.value()) {
        compile_expression(value.value(), value.span(), context)?
    } else {
        PlanExpression::new(
            value.value(),
            vec![ExpressionSegment::Evaluation(value.value().clone())],
        )
        .map_err(|error| {
            context.semantic(
                "github.compile.invalid_condition",
                error.to_string(),
                value.span().clone(),
            );
        })
        .ok()?
    };
    context.located(expression, value.span())
}

pub(super) fn compile_value(
    source: &str,
    span: &SourceSpan,
    context: &mut CompileContext<'_>,
) -> Option<PlanValue> {
    if !source.contains("${{") {
        return Some(PlanValue::Literal(source.to_owned()));
    }
    compile_expression(source, span, context).map(PlanValue::Expression)
}

pub(super) fn compile_expression(
    source: &str,
    span: &SourceSpan,
    context: &mut CompileContext<'_>,
) -> Option<PlanExpression> {
    let segments = match expression_segments(source) {
        Ok(segments) => segments,
        Err(message) => {
            context.semantic("github.compile.invalid_expression", message, span.clone());
            return None;
        }
    };
    PlanExpression::new(source, segments)
        .map_err(|error| {
            context.semantic(
                "github.compile.invalid_expression",
                error.to_string(),
                span.clone(),
            );
        })
        .ok()
}

pub(super) fn expression_segments(source: &str) -> Result<Vec<ExpressionSegment>, &'static str> {
    let mut segments = Vec::new();
    let mut cursor = 0;
    while let Some(relative_start) = source[cursor..].find("${{") {
        let start = cursor + relative_start;
        if start > cursor {
            segments.push(ExpressionSegment::Literal(source[cursor..start].to_owned()));
        }
        let end = find_expression_end(source, start + 3)?;
        let evaluation = &source[start..end];
        let inner = &source[start + 3..end - 2];
        if inner.trim().is_empty() {
            return Err("expression evaluation cannot be empty");
        }
        segments.push(ExpressionSegment::Evaluation(evaluation.to_owned()));
        cursor = end;
    }
    if cursor < source.len() {
        segments.push(ExpressionSegment::Literal(source[cursor..].to_owned()));
    }
    if segments.is_empty() {
        segments.push(ExpressionSegment::Literal(source.to_owned()));
    }
    Ok(segments)
}

pub(super) fn find_expression_end(source: &str, mut cursor: usize) -> Result<usize, &'static str> {
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
            return Err("nested expression opening delimiter is not supported");
        }
        if !quoted && bytes[cursor..].starts_with(b"}}") {
            return Ok(cursor + 2);
        }
        cursor += 1;
    }
    Err("expression opening delimiter has no closing delimiter")
}
