//! Lossless compilation of deferred GitHub expression templates.

use std::collections::BTreeSet;

use automata_ci_core::{
    CompiledBooleanTemplate, CompiledExpressionTemplate, CompiledPositiveIntegerTemplate,
    CompiledValueTemplate, ExpressionContext, ExpressionInstruction, ExpressionLiteral,
    ExpressionProgram, ExpressionSegment, PlanEvaluationPhase, PlanExpression,
};

use crate::{
    BooleanValue, GithubConditionCompiler, GithubConditionPhase, ScalarResolution, ScalarValue,
    SourceSpan, Spanned, expression::GithubValueExpressionPolicy,
};

use super::CompileContext;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum ParsedNeedValue {
    Result,
    Output(String),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct ParsedNeedReference {
    pub(super) job: String,
    pub(super) value: ParsedNeedValue,
}

#[derive(Clone, Debug)]
pub(super) struct Analyzed<T> {
    pub(super) value: T,
    pub(super) references: Vec<ParsedNeedReference>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ValueExpressionPolicy {
    description: &'static str,
    phase: PlanEvaluationPhase,
    contexts: &'static [ExpressionContext],
    hash_files: bool,
}

impl ValueExpressionPolicy {
    pub(super) const fn new(
        description: &'static str,
        phase: PlanEvaluationPhase,
        contexts: &'static [ExpressionContext],
        hash_files: bool,
    ) -> Self {
        Self {
            description,
            phase,
            contexts,
            hash_files,
        }
    }

    pub(super) const fn phase(self) -> PlanEvaluationPhase {
        self.phase
    }

    fn parser_policy(self) -> GithubValueExpressionPolicy {
        GithubValueExpressionPolicy::new(self.description, self.contexts, self.hash_files)
    }
}

/// Compiles a string-valued template while retaining its exact source,
/// evaluation phase, context dependencies, and exact `needs` result edges.
pub(super) fn compile_template(
    source: &str,
    span: &SourceSpan,
    policy: ValueExpressionPolicy,
    context: &mut CompileContext<'_>,
) -> Option<Analyzed<CompiledValueTemplate>> {
    if !source.contains("${{") {
        return Some(Analyzed {
            value: CompiledValueTemplate::Literal(source.to_owned()),
            references: Vec::new(),
        });
    }

    let segments = match expression_segments(source) {
        Ok(segments) => segments,
        Err(message) => {
            context.semantic("github.compile.invalid_expression", message, span.clone());
            return None;
        }
    };
    let mut contexts = BTreeSet::new();
    let mut references = BTreeSet::new();
    let mut programs = Vec::new();
    for segment in &segments {
        let ExpressionSegment::Evaluation(evaluation) = segment else {
            continue;
        };
        let program = compile_policy_program(evaluation, span, policy, context)?;
        let analysis = analyze_program(&program);
        contexts.extend(analysis.contexts);
        references.extend(analysis.references);
        programs.push(program);
    }
    let expression = PlanExpression::new(source, segments)
        .map_err(|error| {
            context.semantic(
                "github.compile.invalid_expression",
                error.to_string(),
                span.clone(),
            );
        })
        .ok()?;
    Some(Analyzed {
        value: CompiledValueTemplate::Expression(CompiledExpressionTemplate::new(
            policy.phase(),
            expression,
            programs,
            contexts.into_iter().collect(),
        )),
        references: references.into_iter().collect(),
    })
}

/// Compiles a field that must contain exactly one expression evaluation.
pub(super) fn compile_single_expression(
    source: &str,
    span: &SourceSpan,
    policy: ValueExpressionPolicy,
    context: &mut CompileContext<'_>,
) -> Option<Analyzed<CompiledExpressionTemplate>> {
    let source = source.trim();
    let program = compile_policy_program(source, span, policy, context)?;
    let analysis = analyze_program(&program);
    let segments = expression_segments(source).ok()?;
    if !matches!(segments.as_slice(), [ExpressionSegment::Evaluation(_)]) {
        context.semantic(
            "github.compile.expected_single_expression",
            "field must contain one complete expression",
            span.clone(),
        );
        return None;
    }
    let expression = PlanExpression::new(source, segments)
        .map_err(|error| {
            context.semantic(
                "github.compile.invalid_expression",
                error.to_string(),
                span.clone(),
            );
        })
        .ok()?;
    Some(Analyzed {
        value: CompiledExpressionTemplate::new(
            policy.phase(),
            expression,
            vec![program],
            analysis.contexts.into_iter().collect(),
        ),
        references: analysis.references.into_iter().collect(),
    })
}

pub(super) fn compile_condition_template(
    value: &Spanned<String>,
    phase: GithubConditionPhase,
    evaluation_phase: PlanEvaluationPhase,
    context: &mut CompileContext<'_>,
) -> Option<Analyzed<CompiledExpressionTemplate>> {
    let program = GithubConditionCompiler::default()
        .compile_condition(Some(value.value()), phase)
        .map_err(|error| {
            context.semantic(error.code(), error.message(), value.span().clone());
        })
        .ok()?;
    let analysis = analyze_program(&program);
    let expression = PlanExpression::new(
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
    .ok()?;
    Some(Analyzed {
        value: CompiledExpressionTemplate::new(
            evaluation_phase,
            expression,
            vec![program],
            analysis.contexts.into_iter().collect(),
        ),
        references: analysis.references.into_iter().collect(),
    })
}

pub(super) fn compile_boolean_template(
    value: &BooleanValue,
    policy: ValueExpressionPolicy,
    context: &mut CompileContext<'_>,
) -> Option<Analyzed<CompiledBooleanTemplate>> {
    match value {
        BooleanValue::Literal(value) => Some(Analyzed {
            value: CompiledBooleanTemplate::Literal(*value.value()),
            references: Vec::new(),
        }),
        BooleanValue::Expression(value) => {
            let expression =
                compile_single_expression(value.value(), value.span(), policy, context)?;
            Some(Analyzed {
                value: CompiledBooleanTemplate::Expression(expression.value),
                references: expression.references,
            })
        }
    }
}

pub(super) fn compile_positive_integer_template(
    value: &ScalarValue,
    policy: ValueExpressionPolicy,
    context: &mut CompileContext<'_>,
) -> Option<Analyzed<CompiledPositiveIntegerTemplate>> {
    if value.contains_expression_candidate() {
        let expression = compile_single_expression(value.decoded(), value.span(), policy, context)?;
        return Some(Analyzed {
            value: CompiledPositiveIntegerTemplate::Expression(expression.value),
            references: expression.references,
        });
    }
    if value.resolution() != ScalarResolution::Integer {
        context.semantic(
            "github.compile.expected_positive_integer",
            "field must be a positive integer or one complete expression",
            value.span().clone(),
        );
        return None;
    }
    let Ok(number) = value.decoded().parse::<u32>() else {
        context.semantic(
            "github.compile.positive_integer_overflow",
            "positive integer does not fit the workflow-plan representation",
            value.span().clone(),
        );
        return None;
    };
    if number == 0 {
        context.semantic(
            "github.compile.zero_positive_integer",
            "field must be greater than zero",
            value.span().clone(),
        );
        return None;
    }
    Some(Analyzed {
        value: CompiledPositiveIntegerTemplate::Literal(number),
        references: Vec::new(),
    })
}

/// Converts a typed reusable-call literal without erasing boolean/number
/// identity. String values remain literals; booleans and finite decimal
/// numbers are represented as context-free evaluation programs.
pub(super) fn compile_reusable_input_template(
    value: &ScalarValue,
    policy: ValueExpressionPolicy,
    context: &mut CompileContext<'_>,
) -> Option<Analyzed<CompiledValueTemplate>> {
    if value.contains_expression_candidate() {
        return compile_template(value.decoded(), value.span(), policy, context);
    }
    match value.resolution() {
        ScalarResolution::String => Some(Analyzed {
            value: CompiledValueTemplate::Literal(value.decoded().to_owned()),
            references: Vec::new(),
        }),
        ScalarResolution::Boolean => compile_scalar_evaluation(
            &value.decoded().to_ascii_lowercase(),
            value.span(),
            policy,
            context,
        ),
        ScalarResolution::Integer | ScalarResolution::Float => {
            let normalized = normalize_number(value, context)?;
            compile_scalar_evaluation(&normalized, value.span(), policy, context)
        }
        ScalarResolution::Null => {
            context.semantic(
                "github.compile.null_reusable_input",
                "reusable workflow inputs must be strings, booleans, numbers, or expressions",
                value.span().clone(),
            );
            None
        }
    }
}

pub(super) fn exact_reference_path(
    source: &str,
    span: &SourceSpan,
    policy: ValueExpressionPolicy,
    context: &mut CompileContext<'_>,
) -> Option<Vec<String>> {
    let program = compile_policy_program(source.trim(), span, policy, context)?;
    let analysis = analyze_program(&program);
    if analysis.dynamic_needs {
        context.unsupported(
            "github.compile.dynamic_needs_reference",
            "`needs` references must name one direct prerequisite result or output exactly",
            span.clone(),
        );
        return None;
    }
    analysis.exact_path
}

fn compile_scalar_evaluation(
    source: &str,
    span: &SourceSpan,
    policy: ValueExpressionPolicy,
    context: &mut CompileContext<'_>,
) -> Option<Analyzed<CompiledValueTemplate>> {
    let program = compile_policy_program(source, span, policy, context)?;
    let analysis = analyze_program(&program);
    let expression = PlanExpression::new(
        source,
        vec![ExpressionSegment::Evaluation(source.to_owned())],
    )
    .map_err(|error| {
        context.semantic(
            "github.compile.invalid_expression",
            error.to_string(),
            span.clone(),
        );
    })
    .ok()?;
    Some(Analyzed {
        value: CompiledValueTemplate::Expression(CompiledExpressionTemplate::new(
            policy.phase(),
            expression,
            vec![program],
            analysis.contexts.into_iter().collect(),
        )),
        references: analysis.references.into_iter().collect(),
    })
}

fn compile_policy_program(
    source: &str,
    span: &SourceSpan,
    policy: ValueExpressionPolicy,
    context: &mut CompileContext<'_>,
) -> Option<ExpressionProgram> {
    GithubConditionCompiler::default()
        .compile_value_expression_for_policy(source, policy.parser_policy())
        .map_err(|error| {
            context.semantic(error.code(), error.message(), span.clone());
        })
        .ok()
}

fn normalize_number(value: &ScalarValue, context: &mut CompileContext<'_>) -> Option<String> {
    let normalized = value.decoded().strip_prefix('+').unwrap_or(value.decoded());
    let negative = normalized.starts_with('-');
    let unsigned = normalized.strip_prefix('-').unwrap_or(normalized);
    let converted = if let Some(hexadecimal) = unsigned.strip_prefix("0x") {
        u128::from_str_radix(hexadecimal, 16)
            .ok()
            .map(|number| number.to_string())
    } else if let Some(octal) = unsigned.strip_prefix("0o") {
        u128::from_str_radix(octal, 8)
            .ok()
            .map(|number| number.to_string())
    } else if normalized.parse::<f64>().is_ok_and(f64::is_finite) {
        Some(normalized.to_owned())
    } else {
        None
    };
    let Some(mut converted) = converted else {
        context.unsupported(
            "github.compile.non_finite_or_oversized_number",
            "number cannot be represented as a finite durable workflow value",
            value.span().clone(),
        );
        return None;
    };
    if negative && !converted.starts_with('-') && converted != "0" {
        converted.insert(0, '-');
    }
    Some(converted)
}

#[derive(Clone, Debug, Default)]
struct ProgramAnalysis {
    contexts: BTreeSet<ExpressionContext>,
    references: BTreeSet<ParsedNeedReference>,
    dynamic_needs: bool,
    exact_path: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default)]
struct AnalysisNode {
    path: Option<Vec<String>>,
    constant_string: Option<String>,
    references: BTreeSet<ParsedNeedReference>,
    dynamic_needs: bool,
}

fn analyze_program(program: &ExpressionProgram) -> ProgramAnalysis {
    let mut contexts = BTreeSet::new();
    let mut stack = Vec::<AnalysisNode>::new();
    for instruction in program.instructions() {
        match instruction {
            ExpressionInstruction::NamedValue { name } => {
                if let Some(context) = expression_context(name) {
                    contexts.insert(context);
                }
                stack.push(AnalysisNode {
                    path: Some(vec![name.clone()]),
                    ..AnalysisNode::default()
                });
            }
            ExpressionInstruction::Literal {
                value: ExpressionLiteral::String { value },
            } => stack.push(AnalysisNode {
                constant_string: Some(value.clone()),
                ..AnalysisNode::default()
            }),
            ExpressionInstruction::Literal { .. } | ExpressionInstruction::Wildcard => {
                stack.push(AnalysisNode::default());
            }
            ExpressionInstruction::Index => {
                let index = stack.pop().unwrap_or_default();
                let target = stack.pop().unwrap_or_default();
                stack.push(index_node(target, index));
            }
            ExpressionInstruction::Not => {
                let node = stack.pop().unwrap_or_default();
                stack.push(finalize_node(node));
            }
            ExpressionInstruction::Compare { .. } => {
                let right = finalize_node(stack.pop().unwrap_or_default());
                let left = finalize_node(stack.pop().unwrap_or_default());
                stack.push(combine_nodes([left, right]));
            }
            ExpressionInstruction::Logical { operand_count, .. }
            | ExpressionInstruction::Call {
                argument_count: operand_count,
                ..
            } => {
                let mut nodes = Vec::with_capacity(usize::from(*operand_count));
                for _ in 0..*operand_count {
                    nodes.push(finalize_node(stack.pop().unwrap_or_default()));
                }
                stack.push(combine_node_iter(nodes));
            }
        }
    }
    let root = stack.pop().unwrap_or_default();
    let exact_path = root.path.clone();
    let root = finalize_node(root);
    ProgramAnalysis {
        contexts,
        references: root.references,
        dynamic_needs: root.dynamic_needs,
        exact_path,
    }
}

fn index_node(mut target: AnalysisNode, mut index: AnalysisNode) -> AnalysisNode {
    if let (Some(mut path), Some(property)) = (target.path.take(), index.constant_string.take()) {
        path.push(property);
        target.path = Some(path);
        target.references.append(&mut index.references);
        target.dynamic_needs |= index.dynamic_needs;
        return target;
    }
    let target = finalize_node(target);
    let index = finalize_node(index);
    combine_nodes([target, index])
}

fn finalize_node(mut node: AnalysisNode) -> AnalysisNode {
    let Some(path) = node.path.take() else {
        return node;
    };
    if path.first().is_some_and(|root| root == "needs") {
        match path.as_slice() {
            [_, job, result] if result.eq_ignore_ascii_case("result") => {
                node.references.insert(ParsedNeedReference {
                    job: job.clone(),
                    value: ParsedNeedValue::Result,
                });
            }
            [_, job, outputs, output] if outputs.eq_ignore_ascii_case("outputs") => {
                node.references.insert(ParsedNeedReference {
                    job: job.clone(),
                    value: ParsedNeedValue::Output(output.clone()),
                });
            }
            _ => node.dynamic_needs = true,
        }
    }
    node
}

fn combine_nodes<const N: usize>(nodes: [AnalysisNode; N]) -> AnalysisNode {
    combine_node_iter(nodes)
}

fn combine_node_iter(nodes: impl IntoIterator<Item = AnalysisNode>) -> AnalysisNode {
    let mut combined = AnalysisNode::default();
    for mut node in nodes {
        combined.references.append(&mut node.references);
        combined.dynamic_needs |= node.dynamic_needs;
    }
    combined
}

fn expression_context(name: &str) -> Option<ExpressionContext> {
    Some(match name {
        "github" => ExpressionContext::Github,
        "inputs" => ExpressionContext::Inputs,
        "vars" => ExpressionContext::Vars,
        "needs" => ExpressionContext::Needs,
        "strategy" => ExpressionContext::Strategy,
        "matrix" => ExpressionContext::Matrix,
        "env" => ExpressionContext::Env,
        "secrets" => ExpressionContext::Secrets,
        "job" => ExpressionContext::Job,
        "runner" => ExpressionContext::Runner,
        "steps" => ExpressionContext::Steps,
        "jobs" => ExpressionContext::Jobs,
        _ => return None,
    })
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
