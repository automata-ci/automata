//! Validated, provider-neutral expression programs retained for runtime phases.

use std::{error::Error, fmt, num::NonZeroU16};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current durable expression-program representation.
pub const EXPRESSION_PROGRAM_SCHEMA_VERSION: u16 = 1;
/// Maximum preserved expression source size in UTF-8 bytes.
pub const MAX_EXPRESSION_SOURCE_BYTES: usize = 84_000;
/// Maximum number of instructions in one expression program.
pub const MAX_EXPRESSION_INSTRUCTIONS: usize = 4_096;
/// Maximum validated expression stack-tree depth.
pub const MAX_EXPRESSION_DEPTH: usize = 50;
/// Maximum aggregate UTF-8 bytes stored by instruction text operands.
pub const MAX_EXPRESSION_TEXT_BYTES: usize = 84_000;
/// Maximum durable expression dialect identifier length.
pub const MAX_EXPRESSION_DIALECT_LENGTH: usize = 64;

/// A versioned expression semantic dialect implemented by an adapter.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(try_from = "UncheckedExpressionDialect")]
pub struct ExpressionDialect {
    name: String,
    version: NonZeroU16,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedExpressionDialect {
    name: String,
    version: u16,
}

impl TryFrom<UncheckedExpressionDialect> for ExpressionDialect {
    type Error = ExpressionProgramError;

    fn try_from(value: UncheckedExpressionDialect) -> Result<Self, Self::Error> {
        Self::new(value.name, value.version)
    }
}

impl ExpressionDialect {
    /// Creates a canonical lower-case dialect identity and positive version.
    ///
    /// # Errors
    ///
    /// Returns [`ExpressionProgramError`] when the identity or version is not
    /// canonical.
    pub fn new(name: impl Into<String>, version: u16) -> Result<Self, ExpressionProgramError> {
        let name = name.into();
        if name.is_empty() {
            return Err(ExpressionProgramError::EmptyDialect);
        }
        if name.len() > MAX_EXPRESSION_DIALECT_LENGTH {
            return Err(ExpressionProgramError::DialectTooLong {
                maximum: MAX_EXPRESSION_DIALECT_LENGTH,
            });
        }
        if !canonical_identifier(&name, true) {
            return Err(ExpressionProgramError::InvalidDialect);
        }
        let version = NonZeroU16::new(version).ok_or(ExpressionProgramError::ZeroDialectVersion)?;
        Ok(Self { name, version })
    }

    /// Returns the canonical adapter dialect name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the adapter dialect semantics version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version.get()
    }
}

/// A canonical literal value pushed by an expression program.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum ExpressionLiteral {
    /// Dialect null value.
    Null,
    /// Concrete boolean value.
    Boolean {
        /// Boolean payload.
        value: bool,
    },
    /// Exact IEEE-754 binary64 representation, including infinities and NaN.
    Number {
        /// Exact IEEE-754 bits; NaN is normalized to one canonical encoding.
        ieee754_bits: u64,
    },
    /// UTF-8 string value charged against the program text budget.
    String {
        /// Exact literal text.
        value: String,
    },
}

impl ExpressionLiteral {
    /// Creates a number literal from its exact runtime representation.
    #[must_use]
    pub const fn number(value: f64) -> Self {
        let value = if value.is_nan() { f64::NAN } else { value };
        Self::Number {
            ieee754_bits: value.to_bits(),
        }
    }

    /// Returns the number represented by this literal, when applicable.
    #[must_use]
    pub const fn as_number(&self) -> Option<f64> {
        match self {
            Self::Number { ieee754_bits } => Some(f64::from_bits(*ieee754_bits)),
            Self::Null | Self::Boolean { .. } | Self::String { .. } => None,
        }
    }
}

/// Comparison operators with GitHub-compatible coercion semantics supplied by
/// the selected dialect runtime.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpressionComparison {
    /// Dialect-defined equality comparison.
    Equal,
    /// Dialect-defined inequality comparison.
    NotEqual,
    /// Strict greater-than comparison.
    GreaterThan,
    /// Inclusive greater-than comparison.
    GreaterThanOrEqual,
    /// Strict less-than comparison.
    LessThan,
    /// Inclusive less-than comparison.
    LessThanOrEqual,
}

/// Flattened short-circuit logical operators.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpressionLogical {
    /// Lazy conjunction across two or more operands.
    And,
    /// Lazy disjunction across two or more operands.
    Or,
}

/// One node in a canonical, postfix-encoded expression tree.
///
/// This is a bounded structural encoding, not eager stack bytecode. Dialect
/// runtimes must recover operand subtrees and preserve lazy semantics (for
/// example short-circuit logical operators and GitHub's `case` function).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum ExpressionInstruction {
    /// Pushes one canonical literal subtree.
    Literal {
        /// Literal to push.
        value: ExpressionLiteral,
    },
    /// Pushes one dialect context or named value.
    NamedValue {
        /// Canonical lower-case identifier resolved by the dialect runtime.
        name: String,
    },
    /// Pushes the wildcard marker accepted only as a subsequent index operand.
    Wildcard,
    /// Pops an index and target and pushes their indexed lookup subtree.
    Index,
    /// Pops one operand and pushes its dialect-defined logical negation.
    Not,
    /// Pops right and left operands and pushes a comparison subtree.
    Compare {
        /// Comparison operator to apply.
        operator: ExpressionComparison,
    },
    /// Pops a flattened operand sequence and preserves lazy logical semantics.
    Logical {
        /// Short-circuit operator to apply.
        operator: ExpressionLogical,
        /// Number of operands, which must be at least two.
        operand_count: u16,
    },
    /// Pops arguments and pushes a dialect function-call subtree.
    Call {
        /// Canonical lower-case function name.
        name: String,
        /// Number of argument subtrees to consume.
        argument_count: u16,
    },
}

/// A versioned source expression plus a validated runtime-safe canonical tree.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExpressionProgram {
    schema_version: u16,
    dialect: ExpressionDialect,
    source: String,
    instructions: Vec<ExpressionInstruction>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedExpressionProgram {
    schema_version: u16,
    dialect: ExpressionDialect,
    source: String,
    instructions: Vec<ExpressionInstruction>,
}

impl<'de> Deserialize<'de> for ExpressionProgram {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = UncheckedExpressionProgram::deserialize(deserializer)?;
        let program = Self {
            schema_version: value.schema_version,
            dialect: value.dialect,
            source: value.source,
            instructions: value.instructions,
        };
        program.validate().map_err(serde::de::Error::custom)?;
        Ok(program)
    }
}

impl ExpressionProgram {
    /// Creates and validates a current expression program.
    ///
    /// # Errors
    ///
    /// Returns [`ExpressionProgramError`] for unsupported schemas, excessive
    /// resource use, noncanonical instructions, or an invalid stack program.
    pub fn new(
        dialect: ExpressionDialect,
        source: impl Into<String>,
        instructions: Vec<ExpressionInstruction>,
    ) -> Result<Self, ExpressionProgramError> {
        let program = Self {
            schema_version: EXPRESSION_PROGRAM_SCHEMA_VERSION,
            dialect,
            source: source.into(),
            instructions,
        };
        program.validate()?;
        Ok(program)
    }

    /// Returns the durable expression-program schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the versioned dialect required to evaluate the program.
    #[must_use]
    pub const fn dialect(&self) -> &ExpressionDialect {
        &self.dialect
    }

    /// Returns the exact original expression text retained for diagnostics and binding.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the canonical postfix structural encoding.
    #[must_use]
    pub fn instructions(&self) -> &[ExpressionInstruction] {
        &self.instructions
    }

    /// Revalidates the durable program at a trust boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ExpressionProgramError`] for unsupported schemas, resource
    /// limit violations, or noncanonical stack-machine structure.
    pub fn validate(&self) -> Result<(), ExpressionProgramError> {
        if self.schema_version != EXPRESSION_PROGRAM_SCHEMA_VERSION {
            return Err(ExpressionProgramError::UnsupportedSchema {
                supported: EXPRESSION_PROGRAM_SCHEMA_VERSION,
                received: self.schema_version,
            });
        }
        if self.source.is_empty() {
            return Err(ExpressionProgramError::EmptySource);
        }
        if self.source.len() > MAX_EXPRESSION_SOURCE_BYTES {
            return Err(ExpressionProgramError::SourceTooLong {
                maximum: MAX_EXPRESSION_SOURCE_BYTES,
            });
        }
        if self
            .source
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        {
            return Err(ExpressionProgramError::InvalidSourceControl);
        }
        if self.instructions.is_empty() {
            return Err(ExpressionProgramError::EmptyProgram);
        }
        if self.instructions.len() > MAX_EXPRESSION_INSTRUCTIONS {
            return Err(ExpressionProgramError::TooManyInstructions {
                maximum: MAX_EXPRESSION_INSTRUCTIONS,
            });
        }

        let mut text_bytes = 0_usize;
        let mut stack = Vec::with_capacity(self.instructions.len().min(MAX_EXPRESSION_DEPTH));
        for instruction in &self.instructions {
            validate_instruction(instruction, &mut text_bytes, &mut stack)?;
        }
        if stack.len() != 1 {
            return Err(ExpressionProgramError::InvalidFinalStack {
                values: stack.len(),
            });
        }
        let Some(result) = stack.pop() else {
            return Err(ExpressionProgramError::InvalidFinalStack { values: 0 });
        };
        if result.wildcard {
            return Err(ExpressionProgramError::WildcardOutsideIndex);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct StackValue {
    depth: usize,
    wildcard: bool,
    logical: Option<ExpressionLogical>,
}

fn validate_instruction(
    instruction: &ExpressionInstruction,
    text_bytes: &mut usize,
    stack: &mut Vec<StackValue>,
) -> Result<(), ExpressionProgramError> {
    match instruction {
        ExpressionInstruction::Literal { value } => {
            if let ExpressionLiteral::String { value } = value {
                charge_text(value, text_bytes)?;
            }
            if let ExpressionLiteral::Number { ieee754_bits } = value {
                let number = f64::from_bits(*ieee754_bits);
                if number.is_nan() && *ieee754_bits != f64::NAN.to_bits() {
                    return Err(ExpressionProgramError::NonCanonicalNan);
                }
            }
            push_value(stack, 1, false, None)?;
        }
        ExpressionInstruction::NamedValue { name } => {
            validate_program_identifier(name)?;
            charge_text(name, text_bytes)?;
            push_value(stack, 1, false, None)?;
        }
        ExpressionInstruction::Wildcard => push_value(stack, 1, true, None)?,
        ExpressionInstruction::Index => {
            let index = pop_value(stack)?;
            let target = pop_non_wildcard(stack)?;
            push_value(stack, target.depth.max(index.depth) + 1, false, None)?;
        }
        ExpressionInstruction::Not => {
            let operand = pop_non_wildcard(stack)?;
            push_value(stack, operand.depth + 1, false, None)?;
        }
        ExpressionInstruction::Compare { .. } => {
            let right = pop_non_wildcard(stack)?;
            let left = pop_non_wildcard(stack)?;
            push_value(stack, left.depth.max(right.depth) + 1, false, None)?;
        }
        ExpressionInstruction::Logical {
            operator,
            operand_count,
        } => {
            if *operand_count < 2 {
                return Err(ExpressionProgramError::InvalidLogicalOperandCount);
            }
            let operands = pop_values(stack, usize::from(*operand_count))?;
            if operands
                .iter()
                .any(|operand| operand.logical == Some(*operator))
            {
                return Err(ExpressionProgramError::NonCanonicalLogicalNesting);
            }
            let depth = operands
                .iter()
                .map(|operand| operand.depth)
                .max()
                .unwrap_or(0)
                + 1;
            push_value(stack, depth, false, Some(*operator))?;
        }
        ExpressionInstruction::Call {
            name,
            argument_count,
        } => {
            validate_program_identifier(name)?;
            charge_text(name, text_bytes)?;
            let arguments = pop_values(stack, usize::from(*argument_count))?;
            let depth = arguments
                .iter()
                .map(|argument| argument.depth)
                .max()
                .unwrap_or(0)
                + 1;
            push_value(stack, depth, false, None)?;
        }
    }
    Ok(())
}

fn validate_program_identifier(value: &str) -> Result<(), ExpressionProgramError> {
    if !canonical_identifier(value, false) {
        return Err(ExpressionProgramError::InvalidIdentifier);
    }
    Ok(())
}

fn canonical_identifier(value: &str, allow_dot: bool) -> bool {
    if allow_dot {
        value.split('.').all(canonical_identifier_segment)
    } else {
        canonical_identifier_segment(value)
    }
}

fn canonical_identifier_segment(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first == b'_')
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn charge_text(value: &str, total: &mut usize) -> Result<(), ExpressionProgramError> {
    *total = total
        .checked_add(value.len())
        .ok_or(ExpressionProgramError::TextTooLong {
            maximum: MAX_EXPRESSION_TEXT_BYTES,
        })?;
    if *total > MAX_EXPRESSION_TEXT_BYTES {
        return Err(ExpressionProgramError::TextTooLong {
            maximum: MAX_EXPRESSION_TEXT_BYTES,
        });
    }
    Ok(())
}

fn pop_value(stack: &mut Vec<StackValue>) -> Result<StackValue, ExpressionProgramError> {
    stack.pop().ok_or(ExpressionProgramError::StackUnderflow)
}

fn pop_non_wildcard(stack: &mut Vec<StackValue>) -> Result<StackValue, ExpressionProgramError> {
    let value = pop_value(stack)?;
    if value.wildcard {
        return Err(ExpressionProgramError::WildcardOutsideIndex);
    }
    Ok(value)
}

fn pop_values(
    stack: &mut Vec<StackValue>,
    count: usize,
) -> Result<Vec<StackValue>, ExpressionProgramError> {
    if stack.len() < count {
        return Err(ExpressionProgramError::StackUnderflow);
    }
    let values = stack.split_off(stack.len() - count);
    if values.iter().any(|value| value.wildcard) {
        return Err(ExpressionProgramError::WildcardOutsideIndex);
    }
    Ok(values)
}

fn push_value(
    stack: &mut Vec<StackValue>,
    depth: usize,
    wildcard: bool,
    logical: Option<ExpressionLogical>,
) -> Result<(), ExpressionProgramError> {
    if depth > MAX_EXPRESSION_DEPTH {
        return Err(ExpressionProgramError::TooDeep {
            maximum: MAX_EXPRESSION_DEPTH,
        });
    }
    stack.push(StackValue {
        depth,
        wildcard,
        logical,
    });
    Ok(())
}

/// Invalid durable expression dialect, source, or canonical program.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ExpressionProgramError {
    /// The durable program uses a schema this build cannot evaluate.
    #[error("unsupported expression-program schema {received}; this build supports {supported}")]
    UnsupportedSchema {
        /// Schema version understood by this build.
        supported: u16,
        /// Schema version found in the program.
        received: u16,
    },
    /// The dialect identity omitted its adapter name.
    #[error("expression dialect cannot be empty")]
    EmptyDialect,
    /// The dialect identity exceeded its durable text bound.
    #[error("expression dialect exceeds {maximum} UTF-8 bytes")]
    DialectTooLong {
        /// Maximum accepted UTF-8 bytes.
        maximum: usize,
    },
    /// The dialect name violated the lower-case namespaced identifier grammar.
    #[error("expression dialect must be canonical lower-case ASCII identifier text")]
    InvalidDialect,
    /// Dialect version zero was rejected because versions are positive.
    #[error("expression dialect version must be positive")]
    ZeroDialectVersion,
    /// No original expression text was retained.
    #[error("expression source cannot be empty")]
    EmptySource,
    /// Original expression text exceeded its durable byte budget.
    #[error("expression source exceeds {maximum} UTF-8 bytes")]
    SourceTooLong {
        /// Maximum retained source bytes.
        maximum: usize,
    },
    /// Source text contained a control character other than tab or newline forms.
    #[error("expression source contains a forbidden control character")]
    InvalidSourceControl,
    /// The structural program contained no root expression.
    #[error("expression program cannot be empty")]
    EmptyProgram,
    /// Instruction count exceeded the bounded evaluator contract.
    #[error("expression program exceeds {maximum} instructions")]
    TooManyInstructions {
        /// Maximum instruction count.
        maximum: usize,
    },
    /// Aggregate literal, named-value, and function text exceeded its budget.
    #[error("expression instruction text exceeds {maximum} aggregate UTF-8 bytes")]
    TextTooLong {
        /// Maximum aggregate instruction-text bytes.
        maximum: usize,
    },
    /// A named value or function violated the portable lower-case grammar.
    #[error("expression named values and functions must be canonical lower-case identifiers")]
    InvalidIdentifier,
    /// A NaN literal retained a noncanonical IEEE-754 payload.
    #[error("expression NaN must use the canonical IEEE-754 representation")]
    NonCanonicalNan,
    /// An instruction attempted to consume more subtrees than were available.
    #[error("expression instruction requires unavailable stack operands")]
    StackUnderflow,
    /// The postfix program did not reduce to exactly one root subtree.
    #[error("expression program leaves {values} values on its final stack")]
    InvalidFinalStack {
        /// Number of values left after validation.
        values: usize,
    },
    /// A wildcard escaped the sole context in which it has defined semantics.
    #[error("expression wildcard may only be consumed as an index operand")]
    WildcardOutsideIndex,
    /// A flattened logical instruction declared fewer than two operands.
    #[error("logical expression instructions require at least two operands")]
    InvalidLogicalOperandCount,
    /// Identical logical operators were nested instead of flattened canonically.
    #[error("nested identical logical operators must be flattened canonically")]
    NonCanonicalLogicalNesting,
    /// The reconstructed expression tree exceeded its recursion-depth bound.
    #[error("expression tree exceeds maximum depth {maximum}")]
    TooDeep {
        /// Maximum validated structural depth.
        maximum: usize,
    },
}

const _: fn() = || {
    fn assert_error<T: Error + Send + Sync + 'static>() {}
    fn assert_display<T: fmt::Display>() {}
    assert_error::<ExpressionProgramError>();
    assert_display::<ExpressionProgramError>();
};
