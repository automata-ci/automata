use std::{cmp::Ordering, num::NonZeroUsize};

use automata_ci_core::{
    ExpressionComparison, ExpressionInstruction, ExpressionLiteral, ExpressionLogical,
    ExpressionProgram,
};

use crate::{
    GithubEvaluationContext, GithubExpressionEvaluationError, GithubExpressionEvaluationErrorKind,
    GithubStatus, GithubValue, coercion, functions,
};

const DIALECT: &str = "github-actions";
const DIALECT_VERSION: u16 = 1;

/// Independent bounds applied while evaluating an already validated program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubExpressionLimits {
    result_bytes: NonZeroUsize,
    collection_items: NonZeroUsize,
    value_depth: NonZeroUsize,
}

impl GithubExpressionLimits {
    /// Creates bounded evaluation policy.
    ///
    /// # Errors
    ///
    /// Rejects zero values or limits beyond hard evaluator ceilings.
    pub const fn new(
        result_bytes: usize,
        collection_items: usize,
        value_depth: usize,
    ) -> Result<Self, GithubExpressionEvaluationError> {
        if result_bytes == 0
            || result_bytes > 16 * 1_024 * 1_024
            || collection_items == 0
            || collection_items > 65_536
            || value_depth == 0
            || value_depth > 50
        {
            return Err(GithubExpressionEvaluationError::new(
                GithubExpressionEvaluationErrorKind::ResourceLimit,
            ));
        }
        let Some(result_bytes) = NonZeroUsize::new(result_bytes) else {
            return Err(GithubExpressionEvaluationError::new(
                GithubExpressionEvaluationErrorKind::ResourceLimit,
            ));
        };
        let Some(collection_items) = NonZeroUsize::new(collection_items) else {
            return Err(GithubExpressionEvaluationError::new(
                GithubExpressionEvaluationErrorKind::ResourceLimit,
            ));
        };
        let Some(value_depth) = NonZeroUsize::new(value_depth) else {
            return Err(GithubExpressionEvaluationError::new(
                GithubExpressionEvaluationErrorKind::ResourceLimit,
            ));
        };
        Ok(Self {
            result_bytes,
            collection_items,
            value_depth,
        })
    }

    /// Returns the aggregate UTF-8/result-size bound.
    #[must_use]
    pub const fn result_bytes(self) -> usize {
        self.result_bytes.get()
    }

    /// Returns the collection-item bound.
    #[must_use]
    pub const fn collection_items(self) -> usize {
        self.collection_items.get()
    }

    /// Returns the nested value-depth bound.
    #[must_use]
    pub const fn value_depth(self) -> usize {
        self.value_depth.get()
    }
}

impl Default for GithubExpressionLimits {
    fn default() -> Self {
        Self {
            result_bytes: NonZeroUsize::new(1_048_576).expect("constant is positive"),
            collection_items: NonZeroUsize::new(65_536).expect("constant is positive"),
            value_depth: NonZeroUsize::new(50).expect("constant is positive"),
        }
    }
}

/// Stateless evaluator for one reviewed GitHub Actions expression dialect.
#[derive(Clone, Copy, Debug, Default)]
pub struct GithubExpressionEvaluator {
    limits: GithubExpressionLimits,
}

impl GithubExpressionEvaluator {
    /// Creates an evaluator with explicit resource limits.
    #[must_use]
    pub const fn new(limits: GithubExpressionLimits) -> Self {
        Self { limits }
    }

    /// Returns the active limits.
    #[must_use]
    pub const fn limits(self) -> GithubExpressionLimits {
        self.limits
    }

    /// Evaluates a validated postfix program with lazy logical/case semantics.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error for an unsupported dialect, unavailable
    /// extension, invalid operation, or resource-limit violation.
    pub fn evaluate(
        &self,
        program: &ExpressionProgram,
        context: &dyn GithubEvaluationContext,
    ) -> Result<GithubValue, GithubExpressionEvaluationError> {
        program.validate().map_err(|_| unsupported_program())?;
        if program.dialect().name() != DIALECT || program.dialect().version() != DIALECT_VERSION {
            return Err(unsupported_program());
        }
        let tree = Tree::compile(program.instructions())?;
        let evaluated = tree.evaluate(tree.root, context, self.limits)?;
        enforce_value_limits(&evaluated.value, self.limits)?;
        Ok(evaluated.value)
    }

    /// Evaluates and applies GitHub condition truthiness.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::evaluate`].
    pub fn evaluate_condition(
        &self,
        program: &ExpressionProgram,
        context: &dyn GithubEvaluationContext,
    ) -> Result<bool, GithubExpressionEvaluationError> {
        self.evaluate(program, context)
            .map(|value| value.is_truthy())
    }
}

#[derive(Clone, Debug)]
enum Node {
    Literal(GithubValue),
    Named(String),
    Wildcard,
    Index {
        target: usize,
        index: usize,
    },
    Not {
        operand: usize,
    },
    Compare {
        operator: ExpressionComparison,
        left: usize,
        right: usize,
    },
    Logical {
        operator: ExpressionLogical,
        operands: Vec<usize>,
    },
    Call {
        name: String,
        arguments: Vec<usize>,
    },
}

#[derive(Clone, Debug)]
struct Tree {
    nodes: Vec<Node>,
    root: usize,
}

impl Tree {
    fn compile(
        instructions: &[ExpressionInstruction],
    ) -> Result<Self, GithubExpressionEvaluationError> {
        let mut nodes = Vec::with_capacity(instructions.len());
        let mut stack = Vec::with_capacity(instructions.len());
        for instruction in instructions {
            let node = match instruction {
                ExpressionInstruction::Literal { value } => Node::Literal(match value {
                    ExpressionLiteral::Null => GithubValue::Null,
                    ExpressionLiteral::Boolean { value } => GithubValue::Boolean(*value),
                    ExpressionLiteral::Number { ieee754_bits } => {
                        GithubValue::number(f64::from_bits(*ieee754_bits))
                    }
                    ExpressionLiteral::String { value } => GithubValue::string(value.clone()),
                }),
                ExpressionInstruction::NamedValue { name } => Node::Named(name.clone()),
                ExpressionInstruction::Wildcard => Node::Wildcard,
                ExpressionInstruction::Index => {
                    let index = stack.pop().ok_or_else(internal)?;
                    let target = stack.pop().ok_or_else(internal)?;
                    Node::Index { target, index }
                }
                ExpressionInstruction::Not => Node::Not {
                    operand: stack.pop().ok_or_else(internal)?,
                },
                ExpressionInstruction::Compare { operator } => {
                    let right = stack.pop().ok_or_else(internal)?;
                    let left = stack.pop().ok_or_else(internal)?;
                    Node::Compare {
                        operator: *operator,
                        left,
                        right,
                    }
                }
                ExpressionInstruction::Logical {
                    operator,
                    operand_count,
                } => Node::Logical {
                    operator: *operator,
                    operands: pop_many(&mut stack, usize::from(*operand_count))?,
                },
                ExpressionInstruction::Call {
                    name,
                    argument_count,
                } => Node::Call {
                    name: name.clone(),
                    arguments: pop_many(&mut stack, usize::from(*argument_count))?,
                },
            };
            let index = nodes.len();
            nodes.push(node);
            stack.push(index);
        }
        if stack.len() != 1 {
            return Err(internal());
        }
        Ok(Self {
            nodes,
            root: stack[0],
        })
    }

    fn evaluate(
        &self,
        node: usize,
        context: &dyn GithubEvaluationContext,
        limits: GithubExpressionLimits,
    ) -> Result<Evaluated, GithubExpressionEvaluationError> {
        match self.nodes.get(node).ok_or_else(internal)? {
            Node::Literal(value) => Ok(Evaluated::plain(value.clone())),
            Node::Named(name) => {
                let value = context.named_value(name).unwrap_or(GithubValue::Null);
                enforce_value_limits(&value, limits)?;
                Ok(Evaluated::plain(value))
            }
            Node::Wildcard => Err(internal()),
            Node::Index { target, index } => {
                let target = self.evaluate(*target, context, limits)?;
                self.evaluate_index(&target, *index, context, limits)
            }
            Node::Not { operand } => {
                let operand = self.evaluate(*operand, context, limits)?.value;
                let sensitive = operand.is_sensitive();
                Ok(Evaluated::plain(
                    GithubValue::Boolean(!operand.is_truthy()).inherit_sensitivity(sensitive),
                ))
            }
            Node::Compare {
                operator,
                left,
                right,
            } => {
                let left = self.evaluate(*left, context, limits)?;
                let right = self.evaluate(*right, context, limits)?;
                let sensitive = left.value.is_sensitive() || right.value.is_sensitive();
                let result = match operator {
                    ExpressionComparison::Equal => {
                        coercion::abstract_equal(&left.value, &right.value)
                    }
                    ExpressionComparison::NotEqual => {
                        !coercion::abstract_equal(&left.value, &right.value)
                    }
                    ExpressionComparison::GreaterThan => {
                        coercion::abstract_compare(&left.value, &right.value)
                            == Some(Ordering::Greater)
                    }
                    ExpressionComparison::GreaterThanOrEqual => {
                        coercion::abstract_equal(&left.value, &right.value)
                            || coercion::abstract_compare(&left.value, &right.value)
                                == Some(Ordering::Greater)
                    }
                    ExpressionComparison::LessThan => {
                        coercion::abstract_compare(&left.value, &right.value)
                            == Some(Ordering::Less)
                    }
                    ExpressionComparison::LessThanOrEqual => {
                        coercion::abstract_equal(&left.value, &right.value)
                            || coercion::abstract_compare(&left.value, &right.value)
                                == Some(Ordering::Less)
                    }
                };
                Ok(Evaluated::plain(
                    GithubValue::Boolean(result).inherit_sensitivity(sensitive),
                ))
            }
            Node::Logical { operator, operands } => {
                self.evaluate_logical(*operator, operands, context, limits)
            }
            Node::Call { name, arguments } => self.evaluate_call(name, arguments, context, limits),
        }
    }

    fn evaluate_logical(
        &self,
        operator: ExpressionLogical,
        operands: &[usize],
        context: &dyn GithubEvaluationContext,
        limits: GithubExpressionLimits,
    ) -> Result<Evaluated, GithubExpressionEvaluationError> {
        let mut last = Evaluated::plain(GithubValue::Null);
        let mut sensitive = false;
        for operand in operands {
            last = self.evaluate(*operand, context, limits)?;
            sensitive |= last.value.is_sensitive();
            let stop = match operator {
                ExpressionLogical::And => !last.value.is_truthy(),
                ExpressionLogical::Or => last.value.is_truthy(),
            };
            if stop {
                break;
            }
        }
        last.value = last.value.inherit_sensitivity(sensitive);
        Ok(last)
    }

    fn evaluate_call(
        &self,
        name: &str,
        arguments: &[usize],
        context: &dyn GithubEvaluationContext,
        limits: GithubExpressionLimits,
    ) -> Result<Evaluated, GithubExpressionEvaluationError> {
        let name = name.to_ascii_lowercase();
        if name == "success" || name == "failure" {
            // The pinned workflow schema deliberately registers job-level
            // success/failure with (0, MAX). Their implementations inspect
            // status only, so arguments are not evaluated. Step compilation
            // remains strict (0, 0).
            let expected = if name == "success" {
                GithubStatus::Success
            } else {
                GithubStatus::Failure
            };
            return Ok(Evaluated::plain(GithubValue::Boolean(
                context.status() == expected,
            )));
        }
        if name == "always" || name == "cancelled" {
            if !arguments.is_empty() {
                return Err(functions::invalid_operation());
            }
            let value = name == "always" || context.status() == GithubStatus::Cancelled;
            return Ok(Evaluated::plain(GithubValue::Boolean(value)));
        }
        if name == "case" {
            return self.evaluate_case(arguments, context, limits);
        }
        if name == "format" {
            return self.evaluate_format(arguments, context, limits);
        }
        if matches!(name.as_str(), "contains" | "startswith" | "endswith") {
            return self.evaluate_binary_function(&name, arguments, context, limits);
        }
        if name == "join" {
            return self.evaluate_join(arguments, context, limits);
        }
        match name.as_str() {
            "fromjson" | "tojson" if arguments.len() != 1 => {
                return Err(functions::invalid_operation());
            }
            "hashfiles" if !(1..=255).contains(&arguments.len()) => {
                return Err(functions::invalid_operation());
            }
            _ => {}
        }
        let arguments = arguments
            .iter()
            .map(|argument| {
                self.evaluate(*argument, context, limits)
                    .map(|value| value.value)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let sensitive = arguments.iter().any(GithubValue::is_sensitive);
        let value = match name.as_str() {
            "fromjson" => functions::from_json(&arguments, limits)?,
            "tojson" => functions::to_json(&arguments, limits)?,
            _ => context
                .functions()
                .call(&name, &arguments)
                .ok_or_else(unavailable)??,
        };
        let value = value.inherit_sensitivity(sensitive);
        enforce_value_limits(&value, limits)?;
        Ok(Evaluated::plain(value))
    }

    fn evaluate_binary_function(
        &self,
        name: &str,
        arguments: &[usize],
        context: &dyn GithubEvaluationContext,
        limits: GithubExpressionLimits,
    ) -> Result<Evaluated, GithubExpressionEvaluationError> {
        if arguments.len() != 2 {
            return Err(functions::invalid_operation());
        }
        let left = self.evaluate(arguments[0], context, limits)?.value;
        let should_evaluate_right = match (left.without_sensitivity(), name) {
            (GithubValue::Array(values), "contains") => !values.is_empty(),
            (value, _) => value.is_primitive(),
        };
        if !should_evaluate_right {
            let sensitive = left.is_sensitive();
            return Ok(Evaluated::plain(
                GithubValue::Boolean(false).inherit_sensitivity(sensitive),
            ));
        }
        let right = self.evaluate(arguments[1], context, limits)?.value;
        let value = match name {
            "contains" => functions::contains(&[left, right])?,
            "startswith" => functions::starts_with(&[left, right])?,
            "endswith" => functions::ends_with(&[left, right])?,
            _ => return Err(internal()),
        };
        Ok(Evaluated::plain(value))
    }

    fn evaluate_join(
        &self,
        arguments: &[usize],
        context: &dyn GithubEvaluationContext,
        limits: GithubExpressionLimits,
    ) -> Result<Evaluated, GithubExpressionEvaluationError> {
        if !(1..=2).contains(&arguments.len()) {
            return Err(functions::invalid_operation());
        }
        let items = self.evaluate(arguments[0], context, limits)?.value;
        let needs_separator =
            matches!(items.without_sensitivity(), GithubValue::Array(values) if values.len() > 1);
        let mut values = vec![items];
        if needs_separator && arguments.len() == 2 {
            values.push(self.evaluate(arguments[1], context, limits)?.value);
        }
        Ok(Evaluated::plain(functions::join(
            &values,
            limits.result_bytes(),
        )?))
    }

    fn evaluate_format(
        &self,
        arguments: &[usize],
        context: &dyn GithubEvaluationContext,
        limits: GithubExpressionLimits,
    ) -> Result<Evaluated, GithubExpressionEvaluationError> {
        if arguments.is_empty() || arguments.len() > 255 {
            return Err(functions::invalid_operation());
        }
        let template = self.evaluate(arguments[0], context, limits)?.value;
        let template_sensitive = template.is_sensitive();
        let template = coercion::to_string(&template);
        let value_nodes = &arguments[1..];
        let value = functions::format_template(
            &template,
            template_sensitive,
            value_nodes.len(),
            limits.result_bytes(),
            |index| {
                self.evaluate(value_nodes[index], context, limits)
                    .map(|value| value.value)
            },
        )?;
        enforce_value_limits(&value, limits)?;
        Ok(Evaluated::plain(value))
    }

    fn evaluate_case(
        &self,
        arguments: &[usize],
        context: &dyn GithubEvaluationContext,
        limits: GithubExpressionLimits,
    ) -> Result<Evaluated, GithubExpressionEvaluationError> {
        if arguments.len() < 3 || arguments.len() > 255 || arguments.len().is_multiple_of(2) {
            return Err(functions::invalid_operation());
        }
        let mut sensitive = false;
        for pair in arguments[..arguments.len() - 1].chunks_exact(2) {
            let predicate = self.evaluate(pair[0], context, limits)?;
            sensitive |= predicate.value.is_sensitive();
            if predicate
                .value
                .without_sensitivity()
                .as_bool()
                .ok_or_else(functions::invalid_operation)?
            {
                let mut selected = self.evaluate(pair[1], context, limits)?;
                selected.value = selected.value.inherit_sensitivity(sensitive);
                return Ok(selected);
            }
        }
        let mut selected =
            self.evaluate(*arguments.last().ok_or_else(internal)?, context, limits)?;
        selected.value = selected.value.inherit_sensitivity(sensitive);
        Ok(selected)
    }

    fn evaluate_index(
        &self,
        target: &Evaluated,
        index_node: usize,
        context: &dyn GithubEvaluationContext,
        limits: GithubExpressionLimits,
    ) -> Result<Evaluated, GithubExpressionEvaluationError> {
        let wildcard = matches!(self.nodes.get(index_node), Some(Node::Wildcard));
        let (index, index_sensitive) = if wildcard {
            (None, false)
        } else {
            let index = self.evaluate(index_node, context, limits)?.value;
            let sensitive = index.is_sensitive();
            (Some(index), sensitive)
        };
        let mut result = if target.filtered {
            Self::index_filtered(&target.value, index.as_ref(), wildcard, limits)?
        } else {
            index_one(&target.value, index.as_ref(), wildcard, limits)?
        };
        result.value = result.value.inherit_sensitivity(index_sensitive);
        Ok(result)
    }

    fn index_filtered(
        target: &GithubValue,
        index: Option<&GithubValue>,
        wildcard: bool,
        limits: GithubExpressionLimits,
    ) -> Result<Evaluated, GithubExpressionEvaluationError> {
        let inherited_sensitive = target.is_explicitly_sensitive();
        let GithubValue::Array(values) = target.without_sensitivity() else {
            return Err(internal());
        };
        let mut result = Vec::new();
        for value in values.iter() {
            let element_sensitive = value.is_explicitly_sensitive();
            match value.without_sensitivity() {
                GithubValue::Object(object) => {
                    if wildcard {
                        result.extend(object.entries().iter().map(|(_, value)| {
                            value.clone().inherit_sensitivity(element_sensitive)
                        }));
                    } else if let Some(key) = index.and_then(primitive_index_string)
                        && let Some(value) = object.get(&key)
                    {
                        result.push(value.clone().inherit_sensitivity(element_sensitive));
                    }
                }
                GithubValue::Array(values) => {
                    if wildcard {
                        result.extend(
                            values
                                .iter()
                                .cloned()
                                .map(|value| value.inherit_sensitivity(element_sensitive)),
                        );
                    } else if let Some(position) = index.and_then(array_index)
                        && let Some(value) = values.get(position)
                    {
                        result.push(value.clone().inherit_sensitivity(element_sensitive));
                    }
                }
                GithubValue::Sensitive(_) => {
                    unreachable!("sensitivity wrappers are removed recursively")
                }
                _ => {}
            }
            if result.len() > limits.collection_items() {
                return Err(functions::resource_limit());
            }
        }
        let value = GithubValue::array(result)
            .map_err(|_| functions::resource_limit())?
            .inherit_sensitivity(inherited_sensitive);
        Ok(Evaluated {
            value,
            filtered: true,
        })
    }
}

#[derive(Clone, Debug)]
struct Evaluated {
    value: GithubValue,
    filtered: bool,
}

impl Evaluated {
    const fn plain(value: GithubValue) -> Self {
        Self {
            value,
            filtered: false,
        }
    }
}

fn index_one(
    target: &GithubValue,
    index: Option<&GithubValue>,
    wildcard: bool,
    limits: GithubExpressionLimits,
) -> Result<Evaluated, GithubExpressionEvaluationError> {
    let inherited_sensitive = target.is_explicitly_sensitive();
    let mut result = match target.without_sensitivity() {
        GithubValue::Object(object) if wildcard => filtered_array(
            object
                .entries()
                .iter()
                .map(|(_, value)| value.clone())
                .collect(),
            limits,
        ),
        GithubValue::Object(object) => Ok(Evaluated::plain(
            index
                .and_then(primitive_index_string)
                .and_then(|key| object.get(&key).cloned())
                .unwrap_or(GithubValue::Null),
        )),
        GithubValue::Array(values) if wildcard => filtered_array(values.to_vec(), limits),
        GithubValue::Array(values) => Ok(Evaluated::plain(
            index
                .and_then(array_index)
                .and_then(|position| values.get(position).cloned())
                .unwrap_or(GithubValue::Null),
        )),
        _ if wildcard => filtered_array(Vec::new(), limits),
        GithubValue::Sensitive(_) => unreachable!("sensitivity wrappers are removed recursively"),
        _ => Ok(Evaluated::plain(GithubValue::Null)),
    }?;
    result.value = result.value.inherit_sensitivity(inherited_sensitive);
    Ok(result)
}

fn filtered_array(
    values: Vec<GithubValue>,
    limits: GithubExpressionLimits,
) -> Result<Evaluated, GithubExpressionEvaluationError> {
    if values.len() > limits.collection_items() {
        return Err(functions::resource_limit());
    }
    Ok(Evaluated {
        value: GithubValue::array(values).map_err(|_| functions::resource_limit())?,
        filtered: true,
    })
}

fn primitive_index_string(value: &GithubValue) -> Option<String> {
    value.is_primitive().then(|| coercion::to_string(value))
}

fn array_index(value: &GithubValue) -> Option<usize> {
    let number = coercion::to_number(value);
    if number.is_nan() || number < 0.0 || number > f64::from(i32::MAX) {
        return None;
    }
    format!("{:.0}", number.floor()).parse::<usize>().ok()
}

fn pop_many(
    stack: &mut Vec<usize>,
    count: usize,
) -> Result<Vec<usize>, GithubExpressionEvaluationError> {
    if stack.len() < count {
        return Err(internal());
    }
    Ok(stack.split_off(stack.len() - count))
}

fn enforce_value_limits(
    value: &GithubValue,
    limits: GithubExpressionLimits,
) -> Result<(), GithubExpressionEvaluationError> {
    let mut aggregate = 0_usize;
    let mut stack = vec![(value, 1_usize)];
    let mut items = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        if depth > limits.value_depth() {
            return Err(functions::resource_limit());
        }
        items = items.checked_add(1).ok_or_else(functions::resource_limit)?;
        if items > limits.collection_items() {
            return Err(functions::resource_limit());
        }
        match value.without_sensitivity() {
            GithubValue::String(value) => {
                aggregate = aggregate
                    .checked_add(value.len())
                    .ok_or_else(functions::resource_limit)?;
            }
            GithubValue::Array(values) => {
                stack.extend(values.iter().map(|value| (value, depth + 1)));
            }
            GithubValue::Object(object) => {
                for (key, value) in object.entries() {
                    aggregate = aggregate
                        .checked_add(key.len())
                        .ok_or_else(functions::resource_limit)?;
                    stack.push((value, depth + 1));
                }
            }
            GithubValue::Null | GithubValue::Boolean(_) | GithubValue::Number(_) => {}
            GithubValue::Sensitive(_) => {
                unreachable!("sensitivity wrappers are removed recursively")
            }
        }
        if aggregate > limits.result_bytes() {
            return Err(functions::resource_limit());
        }
    }
    Ok(())
}

const fn unsupported_program() -> GithubExpressionEvaluationError {
    GithubExpressionEvaluationError::new(GithubExpressionEvaluationErrorKind::UnsupportedProgram)
}

const fn unavailable() -> GithubExpressionEvaluationError {
    GithubExpressionEvaluationError::new(GithubExpressionEvaluationErrorKind::UnavailableContext)
}

const fn internal() -> GithubExpressionEvaluationError {
    GithubExpressionEvaluationError::new(GithubExpressionEvaluationErrorKind::Internal)
}
