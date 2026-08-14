//! GitHub Actions condition parser and compiler.
//!
//! This module deliberately compiles syntax without resolving runtime values.
//! In particular, secret material is neither an allowed named context nor read
//! during planning. A later dialect runtime evaluates the validated program.

use std::{error::Error, fmt};

use automata_ci_core::{
    ExpressionComparison, ExpressionContext, ExpressionDialect, ExpressionInstruction,
    ExpressionLiteral, ExpressionLogical, ExpressionProgram, MAX_EXPRESSION_DEPTH,
    MAX_EXPRESSION_INSTRUCTIONS, MAX_EXPRESSION_SOURCE_BYTES, MAX_EXPRESSION_TEXT_BYTES,
};

/// Durable dialect name for GitHub Actions expression semantics.
pub const GITHUB_EXPRESSION_DIALECT: &str = "github-actions";
/// Semantics version implemented by this parser/compiler.
pub const GITHUB_EXPRESSION_DIALECT_VERSION: u16 = 1;
/// Upstream runner limit, measured as .NET UTF-16 code units.
pub const GITHUB_EXPRESSION_MAX_UTF16_UNITS: usize = 21_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GithubExpressionLimitRejection {
    Utf16Units,
}

const fn github_expression_utf16_units_rejection(
    observed: usize,
) -> Option<GithubExpressionLimitRejection> {
    if observed > GITHUB_EXPRESSION_MAX_UTF16_UNITS {
        return Some(GithubExpressionLimitRejection::Utf16Units);
    }
    None
}

/// Planning phase whose context and function availability is enforced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubConditionPhase {
    /// `jobs.<job_id>.if`, before matrix expansion and runner execution.
    Job,
    /// A concrete job step's `if` condition.
    Step,
}

/// Field-specific availability used by the workflow-plan v1 lowering path.
///
/// GitHub publishes context availability per workflow key. Keeping the policy
/// explicit prevents a template accepted for a late runner field from being
/// accidentally reused in an earlier control-plane field.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GithubValueExpressionPolicy {
    description: &'static str,
    contexts: &'static [ExpressionContext],
    hash_files: bool,
}

impl GithubValueExpressionPolicy {
    pub(crate) const fn new(
        description: &'static str,
        contexts: &'static [ExpressionContext],
        hash_files: bool,
    ) -> Self {
        Self {
            description,
            contexts,
            hash_files,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StatusFunctionAvailability {
    None,
    Job,
    Step,
}

#[derive(Clone, Copy, Debug)]
struct ParserAvailability {
    description: &'static str,
    contexts: &'static [ExpressionContext],
    status_functions: StatusFunctionAvailability,
    hash_files: bool,
}

impl ParserAvailability {
    const fn for_condition(phase: GithubConditionPhase) -> Self {
        match phase {
            GithubConditionPhase::Job => Self {
                description: "job conditions",
                contexts: &[
                    ExpressionContext::Github,
                    ExpressionContext::Inputs,
                    ExpressionContext::Needs,
                    ExpressionContext::Vars,
                ],
                status_functions: StatusFunctionAvailability::Job,
                hash_files: false,
            },
            GithubConditionPhase::Step => Self {
                description: "step conditions",
                contexts: &[
                    ExpressionContext::Github,
                    ExpressionContext::Inputs,
                    ExpressionContext::Vars,
                    ExpressionContext::Needs,
                    ExpressionContext::Strategy,
                    ExpressionContext::Matrix,
                    ExpressionContext::Env,
                    ExpressionContext::Job,
                    ExpressionContext::Runner,
                    ExpressionContext::Steps,
                ],
                status_functions: StatusFunctionAvailability::Step,
                hash_files: true,
            },
        }
    }

    const fn for_value(policy: GithubValueExpressionPolicy) -> Self {
        Self {
            description: policy.description,
            contexts: policy.contexts,
            status_functions: StatusFunctionAvailability::None,
            hash_files: policy.hash_files,
        }
    }
}

/// Independent resource budgets applied before a program reaches durable IR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubExpressionLimits {
    input_bytes: usize,
    nodes: usize,
    depth: usize,
    text_bytes: usize,
}

impl GithubExpressionLimits {
    /// Creates bounded parser limits compatible with the durable core format.
    ///
    /// The GitHub-specific UTF-16 limit is always enforced in addition to the
    /// byte limit supplied here.
    ///
    /// # Errors
    ///
    /// Returns [`GithubExpressionLimitError`] when a limit is zero or exceeds
    /// the provider-neutral durable-program ceiling.
    pub fn new(
        max_input_bytes: usize,
        max_nodes: usize,
        max_depth: usize,
        max_text_bytes: usize,
    ) -> Result<Self, GithubExpressionLimitError> {
        check_limit("input bytes", max_input_bytes, MAX_EXPRESSION_SOURCE_BYTES)?;
        check_limit("nodes", max_nodes, MAX_EXPRESSION_INSTRUCTIONS)?;
        check_limit("depth", max_depth, MAX_EXPRESSION_DEPTH)?;
        check_limit(
            "instruction text bytes",
            max_text_bytes,
            MAX_EXPRESSION_TEXT_BYTES,
        )?;
        Ok(Self {
            input_bytes: max_input_bytes,
            nodes: max_nodes,
            depth: max_depth,
            text_bytes: max_text_bytes,
        })
    }

    #[must_use]
    /// Returns the maximum accepted UTF-8 source byte length.
    pub const fn max_input_bytes(self) -> usize {
        self.input_bytes
    }

    #[must_use]
    /// Returns the maximum parsed and emitted expression node count.
    pub const fn max_nodes(self) -> usize {
        self.nodes
    }

    #[must_use]
    /// Returns the maximum parser nesting and emitted AST depth.
    pub const fn max_depth(self) -> usize {
        self.depth
    }

    #[must_use]
    /// Returns the maximum retained text bytes across durable instructions.
    pub const fn max_text_bytes(self) -> usize {
        self.text_bytes
    }
}

impl Default for GithubExpressionLimits {
    fn default() -> Self {
        Self {
            input_bytes: MAX_EXPRESSION_SOURCE_BYTES,
            nodes: MAX_EXPRESSION_INSTRUCTIONS,
            depth: MAX_EXPRESSION_DEPTH,
            text_bytes: MAX_EXPRESSION_TEXT_BYTES,
        }
    }
}

fn check_limit(
    name: &'static str,
    value: usize,
    maximum: usize,
) -> Result<(), GithubExpressionLimitError> {
    if value == 0 {
        return Err(GithubExpressionLimitError::Zero { name });
    }
    if value > maximum {
        return Err(GithubExpressionLimitError::ExceedsDurableMaximum {
            name,
            value,
            maximum,
        });
    }
    Ok(())
}

/// Invalid parser resource-limit configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GithubExpressionLimitError {
    /// One configured expression budget was zero.
    Zero {
        /// Stable name of the invalid budget.
        name: &'static str,
    },
    /// A configured budget exceeded the provider-neutral durable-program bound.
    ExceedsDurableMaximum {
        /// Stable name of the invalid budget.
        name: &'static str,
        /// Requested budget.
        value: usize,
        /// Largest value representable by the durable expression format.
        maximum: usize,
    },
}

impl fmt::Display for GithubExpressionLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero { name } => write!(formatter, "expression {name} limit must be positive"),
            Self::ExceedsDurableMaximum {
                name,
                value,
                maximum,
            } => write!(
                formatter,
                "expression {name} limit {value} exceeds durable maximum {maximum}"
            ),
        }
    }
}

impl Error for GithubExpressionLimitError {}

/// Stable category for a source-exact condition diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubExpressionErrorKind {
    /// The condition does not follow the accepted GitHub expression grammar.
    Syntax,
    /// A named context or function is unavailable in the selected planning phase.
    Context,
    /// Source, UTF-16, node, depth, or retained-text bounds were exceeded.
    ResourceLimit,
    /// Valid syntax could not be represented by the current durable program format.
    Internal,
}

/// Failure to compile a GitHub condition into its durable program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubExpressionError {
    kind: GithubExpressionErrorKind,
    code: &'static str,
    message: String,
    byte_offset: usize,
    byte_length: usize,
}

impl GithubExpressionError {
    /// Returns the stable diagnostic category.
    #[must_use]
    pub const fn kind(&self) -> GithubExpressionErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable diagnostic code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Returns a sanitized description of the source-shape failure.
    ///
    /// The compiler never evaluates expressions, reads secrets, or includes
    /// provider response bodies or runtime values in this message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Zero-based UTF-8 byte offset in the exact preserved source.
    #[must_use]
    pub const fn byte_offset(&self) -> usize {
        self.byte_offset
    }

    /// UTF-8 byte length of the offending source range (zero at EOF).
    #[must_use]
    pub const fn byte_length(&self) -> usize {
        self.byte_length
    }
}

impl fmt::Display for GithubExpressionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at byte {}: {}",
            self.code, self.byte_offset, self.message
        )
    }
}

impl Error for GithubExpressionError {}

/// Safe, deterministic GitHub condition frontend.
#[derive(Clone, Copy, Debug, Default)]
pub struct GithubConditionCompiler {
    limits: GithubExpressionLimits,
}

impl GithubConditionCompiler {
    /// Creates a deterministic compiler with explicit resource budgets.
    #[must_use]
    pub const fn new(limits: GithubExpressionLimits) -> Self {
        Self { limits }
    }

    /// Returns the resource budgets enforced before durable IR is produced.
    #[must_use]
    pub const fn limits(self) -> GithubExpressionLimits {
        self.limits
    }

    /// Compiles an optional condition and applies GitHub's implicit status
    /// guard. `None` and all-whitespace scalar values compile to `success()`.
    ///
    /// # Errors
    ///
    /// Returns a source-ranged syntax, context, or resource-limit diagnostic.
    pub fn compile_condition(
        &self,
        source: Option<&str>,
        phase: GithubConditionPhase,
    ) -> Result<ExpressionProgram, GithubExpressionError> {
        let source = source.unwrap_or_default();
        enforce_source_limits(source, self.limits)?;
        if source.trim().is_empty() {
            return success_program();
        }
        let range = expression_range(source)?;
        enforce_github_length(source, range)?;
        let mut parser = Parser::new(
            source,
            range,
            ParserAvailability::for_condition(phase),
            self.limits,
        )?;
        let mut expression = parser.parse()?;
        if !expression.has_status_function() {
            expression = Ast::logical(
                ExpressionLogical::And,
                vec![Ast::call("success", Vec::new()), expression],
            );
        }
        self.finish_program(source, range, expression)
    }

    /// Compiles one scalar value expression without condition semantics.
    ///
    /// Unlike [`Self::compile_condition`], this does not inject an implicit
    /// `success()` guard. It is intended for deferred scalar values such as an
    /// action metadata input default `${{ github.token }}` whose evaluated
    /// value, not truthiness, is consumed by the runner.
    ///
    /// # Errors
    ///
    /// Returns a source-ranged syntax, context, or resource-limit diagnostic.
    pub fn compile_value_expression(
        &self,
        source: &str,
        phase: GithubConditionPhase,
    ) -> Result<ExpressionProgram, GithubExpressionError> {
        enforce_source_limits(source, self.limits)?;
        if source.trim().is_empty() {
            return Err(syntax_error(
                "github.expression.empty",
                "expression evaluation cannot be empty",
                0,
                source.len(),
            ));
        }
        let range = expression_range(source)?;
        enforce_github_length(source, range)?;
        let mut parser = Parser::new(
            source,
            range,
            ParserAvailability::for_condition(phase),
            self.limits,
        )?;
        let expression = parser.parse()?;
        self.finish_program(source, range, expression)
    }

    /// Compiles one scalar expression against an exact workflow-key context
    /// policy. This is crate-private because callers must select a policy from
    /// the source field being lowered, rather than accepting an arbitrary bag
    /// of contexts.
    pub(crate) fn compile_value_expression_for_policy(
        &self,
        source: &str,
        policy: GithubValueExpressionPolicy,
    ) -> Result<ExpressionProgram, GithubExpressionError> {
        enforce_source_limits(source, self.limits)?;
        if source.trim().is_empty() {
            return Err(syntax_error(
                "github.expression.empty",
                "expression evaluation cannot be empty",
                0,
                source.len(),
            ));
        }
        let range = expression_range(source)?;
        enforce_github_length(source, range)?;
        let mut parser = Parser::new(
            source,
            range,
            ParserAvailability::for_value(policy),
            self.limits,
        )?;
        let expression = parser.parse()?;
        self.finish_program(source, range, expression)
    }

    fn finish_program(
        &self,
        source: &str,
        range: ByteRange,
        expression: Ast,
    ) -> Result<ExpressionProgram, GithubExpressionError> {
        let metrics = expression.metrics();
        if metrics.nodes > self.limits.nodes {
            return Err(resource_error(
                "github.expression.node_limit",
                format!(
                    "condition expands to {} nodes; maximum is {}",
                    metrics.nodes, self.limits.nodes
                ),
                range.start,
                range.end.saturating_sub(range.start),
            ));
        }
        if metrics.depth > self.limits.depth {
            return Err(resource_error(
                "github.expression.depth_limit",
                format!(
                    "condition depth is {}; maximum is {}",
                    metrics.depth, self.limits.depth
                ),
                range.start,
                range.end.saturating_sub(range.start),
            ));
        }
        let mut instructions = Vec::with_capacity(metrics.nodes);
        expression.emit(&mut instructions);
        let text_bytes = instruction_text_bytes(&instructions)?;
        if text_bytes > self.limits.text_bytes {
            return Err(resource_error(
                "github.expression.text_limit",
                format!(
                    "condition instruction text is {text_bytes} bytes; maximum is {}",
                    self.limits.text_bytes
                ),
                range.start,
                range.end.saturating_sub(range.start),
            ));
        }
        let dialect =
            ExpressionDialect::new(GITHUB_EXPRESSION_DIALECT, GITHUB_EXPRESSION_DIALECT_VERSION)
                .map_err(|error| internal_error(error.to_string()))?;
        ExpressionProgram::new(dialect, source, instructions)
            .map_err(|error| internal_error(error.to_string()))
    }
}

fn success_program() -> Result<ExpressionProgram, GithubExpressionError> {
    let dialect =
        ExpressionDialect::new(GITHUB_EXPRESSION_DIALECT, GITHUB_EXPRESSION_DIALECT_VERSION)
            .map_err(|error| internal_error(error.to_string()))?;
    ExpressionProgram::new(
        dialect,
        "success()",
        vec![ExpressionInstruction::Call {
            name: "success".to_owned(),
            argument_count: 0,
        }],
    )
    .map_err(|error| internal_error(error.to_string()))
}

fn enforce_source_limits(
    source: &str,
    limits: GithubExpressionLimits,
) -> Result<(), GithubExpressionError> {
    if source.len() > limits.input_bytes {
        return Err(resource_error(
            "github.expression.input_limit",
            format!(
                "condition is {} UTF-8 bytes; maximum is {}",
                source.len(),
                limits.input_bytes
            ),
            limits.input_bytes,
            source.len() - limits.input_bytes,
        ));
    }
    if let Some(offset) = source.char_indices().find_map(|(offset, character)| {
        (character.is_control() && !matches!(character, '\n' | '\r' | '\t')).then_some(offset)
    }) {
        return Err(syntax_error(
            "github.expression.forbidden_control",
            "condition contains a forbidden control character",
            offset,
            source[offset..].chars().next().map_or(0, char::len_utf8),
        ));
    }
    Ok(())
}

fn enforce_github_length(source: &str, range: ByteRange) -> Result<(), GithubExpressionError> {
    let utf16_units = source[range.start..range.end].encode_utf16().count();
    if github_expression_utf16_units_rejection(utf16_units).is_some() {
        return Err(resource_error(
            "github.expression.github_length_limit",
            format!(
                "condition is {utf16_units} UTF-16 code units; GitHub's maximum is {GITHUB_EXPRESSION_MAX_UTF16_UNITS}"
            ),
            range.end,
            0,
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct ByteRange {
    start: usize,
    end: usize,
}

fn expression_range(source: &str) -> Result<ByteRange, GithubExpressionError> {
    let start = source.len() - source.trim_start().len();
    let end = source.trim_end().len();
    let trimmed = &source[start..end];
    if trimmed.starts_with("${{") {
        let inner_start = start + 3;
        let inner_end = find_condition_delimiter(source, inner_start, end, start)?;
        if inner_end + 2 != end {
            return Err(syntax_error(
                "github.expression.trailing_expression",
                "a condition must contain exactly one expression",
                inner_end,
                2,
            ));
        }
        let inner = &source[inner_start..inner_end];
        if inner.trim().is_empty() {
            return Err(syntax_error(
                "github.expression.empty",
                "expression evaluation cannot be empty",
                inner_start,
                inner.len(),
            ));
        }
        let expression_start = inner_start + inner.len() - inner.trim_start().len();
        let expression_end = inner_start + inner.trim_end().len();
        return Ok(ByteRange {
            start: expression_start,
            end: expression_end,
        });
    }
    if let Some((offset, length)) = first_unquoted_delimiter(source, start, end) {
        return Err(syntax_error(
            "github.expression.mixed_delimiter",
            "a condition cannot mix literal text with an expression delimiter",
            offset,
            length,
        ));
    }
    Ok(ByteRange { start, end })
}

fn first_unquoted_delimiter(source: &str, mut cursor: usize, end: usize) -> Option<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut quoted = false;
    while cursor < end {
        if bytes[cursor] == b'\'' {
            if quoted && bytes.get(cursor + 1) == Some(&b'\'') {
                cursor += 2;
                continue;
            }
            quoted = !quoted;
            cursor += 1;
            continue;
        }
        if !quoted && bytes[cursor..end].starts_with(b"${{") {
            return Some((cursor, 3));
        }
        if !quoted && bytes[cursor..end].starts_with(b"}}") {
            return Some((cursor, 2));
        }
        let character = source[cursor..end].chars().next()?;
        cursor += character.len_utf8();
    }
    None
}

fn find_condition_delimiter(
    source: &str,
    mut cursor: usize,
    end: usize,
    opening: usize,
) -> Result<usize, GithubExpressionError> {
    let bytes = source.as_bytes();
    let mut quoted = false;
    while cursor < end {
        if bytes[cursor] == b'\'' {
            if quoted && bytes.get(cursor + 1) == Some(&b'\'') {
                cursor += 2;
                continue;
            }
            quoted = !quoted;
            cursor += 1;
            continue;
        }
        if !quoted && bytes[cursor..end].starts_with(b"${{") {
            return Err(syntax_error(
                "github.expression.nested_delimiter",
                "nested expression delimiters are not allowed",
                cursor,
                3,
            ));
        }
        if !quoted && bytes[cursor..end].starts_with(b"}}") {
            return Ok(cursor);
        }
        let character = source[cursor..end]
            .chars()
            .next()
            .expect("cursor precedes expression end");
        cursor += character.len_utf8();
    }
    Err(syntax_error(
        "github.expression.unclosed_delimiter",
        "expression opening delimiter has no matching closing delimiter",
        opening,
        3,
    ))
}

#[derive(Clone, Debug, PartialEq)]
enum TokenKind {
    Identifier(String),
    String(String),
    Number(u64),
    Null,
    Boolean(bool),
    LeftParen,
    RightParen,
    LeftBracket,
    RightBracket,
    Comma,
    Dot,
    Star,
    Not,
    Equal,
    NotEqual,
    Greater,
    GreaterOrEqual,
    Less,
    LessOrEqual,
    And,
    Or,
    Eof,
}

#[derive(Clone, Debug)]
struct Token {
    kind: TokenKind,
    start: usize,
    end: usize,
}

struct Lexer<'source> {
    source: &'source str,
    cursor: usize,
    end: usize,
    operand_expected: bool,
    property_expected: bool,
}

impl<'source> Lexer<'source> {
    fn new(source: &'source str, range: ByteRange) -> Self {
        Self {
            source,
            cursor: range.start,
            end: range.end,
            operand_expected: true,
            property_expected: false,
        }
    }

    fn next(&mut self) -> Result<Token, GithubExpressionError> {
        self.skip_whitespace();
        if self.cursor >= self.end {
            return Ok(Token {
                kind: TokenKind::Eof,
                start: self.end,
                end: self.end,
            });
        }
        let start = self.cursor;
        let character = self.peek_char().expect("cursor before lexer end");
        let kind = match character {
            '(' => {
                self.advance(character);
                TokenKind::LeftParen
            }
            ')' => {
                self.advance(character);
                TokenKind::RightParen
            }
            '[' => {
                self.advance(character);
                TokenKind::LeftBracket
            }
            ']' => {
                self.advance(character);
                TokenKind::RightBracket
            }
            ',' => {
                self.advance(character);
                TokenKind::Comma
            }
            '*' => {
                self.advance(character);
                TokenKind::Star
            }
            '\'' => return self.string_token(),
            '!' | '>' | '<' | '=' | '&' | '|' => self.operator_token(character, start)?,
            '.' if self.operand_expected => return self.number_token(),
            '.' => {
                self.advance(character);
                self.property_expected = true;
                TokenKind::Dot
            }
            '+' | '-' | '0'..='9' => return self.number_token(),
            _ if legal_identifier_start(character) => return self.identifier_token(),
            _ => {
                self.advance(character);
                return Err(syntax_error(
                    "github.expression.unexpected_symbol",
                    format!("unexpected symbol `{character}`"),
                    start,
                    self.cursor - start,
                ));
            }
        };
        let end = self.cursor;
        self.operand_expected = token_expects_operand_after(&kind);
        if kind != TokenKind::Dot {
            self.property_expected = false;
        }
        Ok(Token { kind, start, end })
    }

    fn operator_token(
        &mut self,
        character: char,
        start: usize,
    ) -> Result<TokenKind, GithubExpressionError> {
        self.advance(character);
        let kind = match character {
            '!' => {
                if self.consume('=') {
                    TokenKind::NotEqual
                } else {
                    TokenKind::Not
                }
            }
            '>' => {
                if self.consume('=') {
                    TokenKind::GreaterOrEqual
                } else {
                    TokenKind::Greater
                }
            }
            '<' => {
                if self.consume('=') {
                    TokenKind::LessOrEqual
                } else {
                    TokenKind::Less
                }
            }
            '=' if self.consume('=') => TokenKind::Equal,
            '&' if self.consume('&') => TokenKind::And,
            '|' if self.consume('|') => TokenKind::Or,
            '=' => {
                return Err(syntax_error(
                    "github.expression.unexpected_symbol",
                    "expected `==`; assignment is not part of the expression grammar",
                    start,
                    self.cursor - start,
                ));
            }
            '&' => {
                return Err(syntax_error(
                    "github.expression.unexpected_symbol",
                    "expected logical operator `&&`",
                    start,
                    self.cursor - start,
                ));
            }
            '|' => {
                return Err(syntax_error(
                    "github.expression.unexpected_symbol",
                    "expected logical operator `||`",
                    start,
                    self.cursor - start,
                ));
            }
            _ => return Err(internal_error("lexer dispatched a non-operator")),
        };
        Ok(kind)
    }

    fn string_token(&mut self) -> Result<Token, GithubExpressionError> {
        let start = self.cursor;
        self.advance('\'');
        let mut value = String::new();
        while self.cursor < self.end {
            let character = self.peek_char().expect("cursor before lexer end");
            self.advance(character);
            if character == '\'' {
                if self.peek_char() == Some('\'') {
                    self.advance('\'');
                    value.push('\'');
                    continue;
                }
                self.operand_expected = false;
                self.property_expected = false;
                return Ok(Token {
                    kind: TokenKind::String(value),
                    start,
                    end: self.cursor,
                });
            }
            value.push(character);
        }
        Err(syntax_error(
            "github.expression.unclosed_string",
            "single-quoted string has no closing quote",
            start,
            self.end - start,
        ))
    }

    fn identifier_token(&mut self) -> Result<Token, GithubExpressionError> {
        let start = self.cursor;
        let first = self.peek_char().expect("identifier has first character");
        self.advance(first);
        while let Some(character) = self.peek_char() {
            if keyword_boundary(character) {
                break;
            }
            self.advance(character);
        }
        let raw = &self.source[start..self.cursor];
        if !legal_identifier(raw) {
            return Err(syntax_error(
                "github.expression.invalid_identifier",
                format!("`{raw}` is not a legal GitHub expression identifier"),
                start,
                self.cursor - start,
            ));
        }
        let kind = if self.property_expected {
            TokenKind::Identifier(raw.to_owned())
        } else {
            match raw {
                "null" => TokenKind::Null,
                "true" => TokenKind::Boolean(true),
                "false" => TokenKind::Boolean(false),
                "NaN" => TokenKind::Number(f64::NAN.to_bits()),
                "Infinity" => TokenKind::Number(f64::INFINITY.to_bits()),
                _ => TokenKind::Identifier(raw.to_owned()),
            }
        };
        self.property_expected = false;
        self.operand_expected = false;
        Ok(Token {
            kind,
            start,
            end: self.cursor,
        })
    }

    fn number_token(&mut self) -> Result<Token, GithubExpressionError> {
        let start = self.cursor;
        while let Some(character) = self.peek_char() {
            if number_boundary(character) {
                break;
            }
            self.advance(character);
        }
        let raw = &self.source[start..self.cursor];
        let Some(number) = parse_number(raw) else {
            return Err(syntax_error(
                "github.expression.invalid_number",
                format!("`{raw}` is not a valid GitHub expression number"),
                start,
                self.cursor - start,
            ));
        };
        self.operand_expected = false;
        self.property_expected = false;
        let ExpressionLiteral::Number { ieee754_bits } = ExpressionLiteral::number(number) else {
            return Err(internal_error(
                "number literal constructor returned a non-number",
            ));
        };
        Ok(Token {
            kind: TokenKind::Number(ieee754_bits),
            start,
            end: self.cursor,
        })
    }

    fn skip_whitespace(&mut self) {
        while let Some(character) = self.peek_char() {
            if !character.is_whitespace() {
                break;
            }
            self.advance(character);
        }
    }

    fn peek_char(&self) -> Option<char> {
        (self.cursor < self.end)
            .then(|| self.source[self.cursor..self.end].chars().next())
            .flatten()
    }

    fn advance(&mut self, character: char) {
        self.cursor += character.len_utf8();
    }

    fn consume(&mut self, expected: char) -> bool {
        if self.peek_char() == Some(expected) {
            self.advance(expected);
            true
        } else {
            false
        }
    }
}

fn token_expects_operand_after(kind: &TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::LeftParen
            | TokenKind::LeftBracket
            | TokenKind::Comma
            | TokenKind::Not
            | TokenKind::Equal
            | TokenKind::NotEqual
            | TokenKind::Greater
            | TokenKind::GreaterOrEqual
            | TokenKind::Less
            | TokenKind::LessOrEqual
            | TokenKind::And
            | TokenKind::Or
    )
}

fn legal_identifier_start(character: char) -> bool {
    character.is_ascii_alphabetic() || character == '_'
}

fn legal_identifier_continue(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
}

fn legal_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters.next().is_some_and(legal_identifier_start)
        && characters.all(legal_identifier_continue)
}

fn keyword_boundary(character: char) -> bool {
    number_boundary(character) || character == '.'
}

fn number_boundary(character: char) -> bool {
    character.is_whitespace()
        || matches!(
            character,
            '(' | ')' | '[' | ']' | ',' | '!' | '>' | '<' | '=' | '&' | '|'
        )
}

fn parse_number(raw: &str) -> Option<f64> {
    if raw == "Infinity" {
        return Some(f64::INFINITY);
    }
    if raw == "-Infinity" {
        return Some(f64::NEG_INFINITY);
    }
    if let Some(hex) = raw.strip_prefix("0x") {
        if hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        return u32::from_str_radix(hex, 16)
            .ok()
            .map(|value| f64::from(i32::from_be_bytes(value.to_be_bytes())));
    }
    if let Some(octal) = raw.strip_prefix("0o") {
        if octal.is_empty() || !octal.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
            return None;
        }
        return u32::from_str_radix(octal, 8)
            .ok()
            .map(|value| f64::from(i32::from_be_bytes(value.to_be_bytes())));
    }
    valid_decimal(raw)
        .then(|| raw.parse::<f64>().ok())
        .flatten()
}

fn valid_decimal(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    let mut cursor = usize::from(matches!(bytes.first(), Some(b'+' | b'-')));
    if cursor == bytes.len() {
        return false;
    }
    let integer_start = cursor;
    while matches!(bytes.get(cursor), Some(b'0'..=b'9')) {
        cursor += 1;
    }
    let integer_digits = cursor - integer_start;
    let mut fraction_digits = 0;
    if bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        let fraction_start = cursor;
        while matches!(bytes.get(cursor), Some(b'0'..=b'9')) {
            cursor += 1;
        }
        fraction_digits = cursor - fraction_start;
    }
    if integer_digits == 0 && fraction_digits == 0 {
        return false;
    }
    if matches!(bytes.get(cursor), Some(b'e' | b'E')) {
        cursor += 1;
        if matches!(bytes.get(cursor), Some(b'+' | b'-')) {
            cursor += 1;
        }
        let exponent_start = cursor;
        while matches!(bytes.get(cursor), Some(b'0'..=b'9')) {
            cursor += 1;
        }
        if cursor == exponent_start {
            return false;
        }
    }
    cursor == bytes.len()
}

struct Parser<'source> {
    lexer: Lexer<'source>,
    current: Token,
    availability: ParserAvailability,
    limits: GithubExpressionLimits,
    parsed_nodes: usize,
    nesting_depth: usize,
}

impl<'source> Parser<'source> {
    fn new(
        source: &'source str,
        range: ByteRange,
        availability: ParserAvailability,
        limits: GithubExpressionLimits,
    ) -> Result<Self, GithubExpressionError> {
        let mut lexer = Lexer::new(source, range);
        let current = lexer.next()?;
        Ok(Self {
            lexer,
            current,
            availability,
            limits,
            parsed_nodes: 0,
            nesting_depth: 0,
        })
    }

    fn parse(&mut self) -> Result<Ast, GithubExpressionError> {
        let expression = self.parse_binary(0)?;
        if self.current.kind != TokenKind::Eof {
            return Err(self.unexpected("end of condition"));
        }
        Ok(expression)
    }

    fn parse_binary(&mut self, minimum_precedence: u8) -> Result<Ast, GithubExpressionError> {
        let mut left = self.parse_unary()?;
        while let Some((precedence, operator)) = binary_operator(&self.current.kind) {
            if precedence < minimum_precedence {
                break;
            }
            let operator_token = self.current.clone();
            self.advance()?;
            let right = self.parse_binary(precedence + 1)?;
            let combined = match operator {
                BinaryOperator::Compare(operator) => {
                    self.bump_node()?;
                    Ast::Compare {
                        operator,
                        left: Box::new(left),
                        right: Box::new(right),
                    }
                }
                BinaryOperator::Logical(operator) => {
                    self.bump_node()?;
                    Ast::logical(operator, vec![left, right])
                }
            };
            self.ensure_ast_depth(&combined, operator_token.start, operator_token.end)?;
            left = combined;
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Ast, GithubExpressionError> {
        if self.current.kind == TokenKind::Not {
            let operator = self.current.clone();
            self.advance()?;
            self.begin_nested()?;
            let operand = self.parse_unary();
            self.end_nested();
            let operand = operand?;
            self.bump_node()?;
            let expression = Ast::Not(Box::new(operand));
            self.ensure_ast_depth(&expression, operator.start, operator.end)?;
            return Ok(expression);
        }
        let (primary, postfix_allowed) = self.parse_primary()?;
        if !postfix_allowed && matches!(self.current.kind, TokenKind::Dot | TokenKind::LeftBracket)
        {
            return Err(self.unexpected("an operator after a literal"));
        }
        self.parse_postfix(primary)
    }

    fn parse_primary(&mut self) -> Result<(Ast, bool), GithubExpressionError> {
        let token = self.current.clone();
        match token.kind {
            TokenKind::Null => {
                self.advance()?;
                self.bump_node()?;
                Ok((Ast::Literal(ExpressionLiteral::Null), false))
            }
            TokenKind::Boolean(value) => {
                self.advance()?;
                self.bump_node()?;
                Ok((Ast::Literal(ExpressionLiteral::Boolean { value }), false))
            }
            TokenKind::Number(ieee754_bits) => {
                self.advance()?;
                self.bump_node()?;
                Ok((
                    Ast::Literal(ExpressionLiteral::Number { ieee754_bits }),
                    false,
                ))
            }
            TokenKind::String(value) => {
                self.advance()?;
                self.bump_node()?;
                Ok((Ast::Literal(ExpressionLiteral::String { value }), false))
            }
            TokenKind::Identifier(name) => {
                self.advance()?;
                if self.current.kind == TokenKind::LeftParen {
                    self.parse_call(&name, token.start, token.end)
                        .map(|call| (call, true))
                } else {
                    let canonical = name.to_ascii_lowercase();
                    if !context_allowed(self.availability, &canonical) {
                        return Err(context_error(
                            "github.expression.unrecognized_context",
                            format!(
                                "context `{name}` is unavailable in {}",
                                self.availability.description
                            ),
                            token.start,
                            token.end - token.start,
                        ));
                    }
                    self.bump_node()?;
                    Ok((Ast::NamedValue(canonical), true))
                }
            }
            TokenKind::LeftParen => {
                self.advance()?;
                self.begin_nested()?;
                let expression = self.parse_binary(0);
                self.end_nested();
                let expression = expression?;
                self.expect(&TokenKind::RightParen, "closing `)`")?;
                Ok((expression, true))
            }
            TokenKind::Eof => Err(syntax_error(
                "github.expression.unexpected_end",
                "expected an expression operand",
                token.start,
                0,
            )),
            _ => Err(self.unexpected("an expression operand")),
        }
    }

    fn parse_call(
        &mut self,
        name: &str,
        name_start: usize,
        name_end: usize,
    ) -> Result<Ast, GithubExpressionError> {
        let canonical = name.to_ascii_lowercase();
        let Some(signature) = function_signature(self.availability, &canonical) else {
            return Err(context_error(
                "github.expression.unrecognized_function",
                format!(
                    "function `{name}` is unavailable in {}",
                    self.availability.description
                ),
                name_start,
                name_end - name_start,
            ));
        };
        self.expect(&TokenKind::LeftParen, "function parameter list")?;
        let mut arguments = Vec::new();
        if self.current.kind != TokenKind::RightParen {
            loop {
                self.begin_nested()?;
                let argument = self.parse_binary(0);
                self.end_nested();
                arguments.push(argument?);
                if self.current.kind != TokenKind::Comma {
                    break;
                }
                self.advance()?;
                if self.current.kind == TokenKind::RightParen {
                    return Err(self.unexpected("a function argument after `,`"));
                }
            }
        }
        let close = self.current.clone();
        self.expect(&TokenKind::RightParen, "closing `)`")?;
        if arguments.len() < signature.minimum {
            return Err(context_error(
                "github.expression.too_few_arguments",
                format!(
                    "function `{name}` requires at least {} argument(s); received {}",
                    signature.minimum,
                    arguments.len()
                ),
                close.start,
                close.end - close.start,
            ));
        }
        if arguments.len() > signature.maximum {
            return Err(context_error(
                "github.expression.too_many_arguments",
                format!(
                    "function `{name}` accepts at most {} argument(s); received {}",
                    signature.maximum,
                    arguments.len()
                ),
                close.start,
                close.end - close.start,
            ));
        }
        if canonical == "case" && arguments.len() % 2 == 0 {
            return Err(context_error(
                "github.expression.even_case_arguments",
                "function `case` requires predicate/result pairs followed by one default value",
                close.start,
                close.end - close.start,
            ));
        }
        self.bump_node()?;
        let expression = Ast::Call {
            name: canonical,
            arguments,
        };
        self.ensure_ast_depth(&expression, name_start, name_end)?;
        Ok(expression)
    }

    fn parse_postfix(&mut self, mut target: Ast) -> Result<Ast, GithubExpressionError> {
        loop {
            match self.current.kind {
                TokenKind::Dot => {
                    self.advance()?;
                    let property = self.current.clone();
                    let index = match property.kind {
                        TokenKind::Identifier(value) => {
                            self.advance()?;
                            self.bump_node()?;
                            Ast::Literal(ExpressionLiteral::String { value })
                        }
                        TokenKind::Star => {
                            self.advance()?;
                            self.bump_node()?;
                            Ast::Wildcard
                        }
                        _ => return Err(self.unexpected("a property name or `*` after `.`")),
                    };
                    self.bump_node()?;
                    target = Ast::Index {
                        target: Box::new(target),
                        index: Box::new(index),
                    };
                    self.ensure_ast_depth(&target, property.start, property.end)?;
                }
                TokenKind::LeftBracket => {
                    self.advance()?;
                    let index = if self.current.kind == TokenKind::Star {
                        self.advance()?;
                        self.bump_node()?;
                        Ast::Wildcard
                    } else {
                        self.begin_nested()?;
                        let index = self.parse_binary(0);
                        self.end_nested();
                        index?
                    };
                    self.expect(&TokenKind::RightBracket, "closing `]`")?;
                    self.bump_node()?;
                    target = Ast::Index {
                        target: Box::new(target),
                        index: Box::new(index),
                    };
                    self.ensure_ast_depth(&target, self.current.start, self.current.end)?;
                }
                _ => return Ok(target),
            }
        }
    }

    fn expect(
        &mut self,
        expected: &TokenKind,
        description: &'static str,
    ) -> Result<(), GithubExpressionError> {
        if self.current.kind != *expected {
            return Err(self.unexpected(description));
        }
        self.advance()
    }

    fn advance(&mut self) -> Result<(), GithubExpressionError> {
        self.current = self.lexer.next()?;
        Ok(())
    }

    fn bump_node(&mut self) -> Result<(), GithubExpressionError> {
        self.parsed_nodes = self.parsed_nodes.saturating_add(1);
        if self.parsed_nodes > self.limits.nodes {
            return Err(resource_error(
                "github.expression.node_limit",
                format!("condition exceeds maximum node count {}", self.limits.nodes),
                self.current.start,
                self.current.end - self.current.start,
            ));
        }
        Ok(())
    }

    fn begin_nested(&mut self) -> Result<(), GithubExpressionError> {
        self.nesting_depth = self.nesting_depth.saturating_add(1);
        if self.nesting_depth > self.limits.depth {
            self.nesting_depth = self.nesting_depth.saturating_sub(1);
            return Err(resource_error(
                "github.expression.depth_limit",
                format!(
                    "condition nesting exceeds maximum depth {}",
                    self.limits.depth
                ),
                self.current.start,
                self.current.end - self.current.start,
            ));
        }
        Ok(())
    }

    fn end_nested(&mut self) {
        self.nesting_depth = self.nesting_depth.saturating_sub(1);
    }

    fn ensure_ast_depth(
        &self,
        expression: &Ast,
        start: usize,
        end: usize,
    ) -> Result<(), GithubExpressionError> {
        let depth = expression.metrics().depth;
        if depth > self.limits.depth {
            return Err(resource_error(
                "github.expression.depth_limit",
                format!(
                    "condition depth is {depth}; maximum is {}",
                    self.limits.depth
                ),
                start,
                end - start,
            ));
        }
        Ok(())
    }

    fn unexpected(&self, expected: &'static str) -> GithubExpressionError {
        let received = token_description(&self.current.kind);
        syntax_error(
            "github.expression.unexpected_token",
            format!("expected {expected}, received {received}"),
            self.current.start,
            self.current.end - self.current.start,
        )
    }
}

#[derive(Clone, Copy)]
enum BinaryOperator {
    Compare(ExpressionComparison),
    Logical(ExpressionLogical),
}

fn binary_operator(kind: &TokenKind) -> Option<(u8, BinaryOperator)> {
    let value = match kind {
        TokenKind::Greater => (
            11,
            BinaryOperator::Compare(ExpressionComparison::GreaterThan),
        ),
        TokenKind::GreaterOrEqual => (
            11,
            BinaryOperator::Compare(ExpressionComparison::GreaterThanOrEqual),
        ),
        TokenKind::Less => (11, BinaryOperator::Compare(ExpressionComparison::LessThan)),
        TokenKind::LessOrEqual => (
            11,
            BinaryOperator::Compare(ExpressionComparison::LessThanOrEqual),
        ),
        TokenKind::Equal => (10, BinaryOperator::Compare(ExpressionComparison::Equal)),
        TokenKind::NotEqual => (10, BinaryOperator::Compare(ExpressionComparison::NotEqual)),
        TokenKind::And => (6, BinaryOperator::Logical(ExpressionLogical::And)),
        TokenKind::Or => (5, BinaryOperator::Logical(ExpressionLogical::Or)),
        _ => return None,
    };
    Some(value)
}

#[derive(Clone, Copy)]
struct FunctionSignature {
    minimum: usize,
    maximum: usize,
}

fn function_signature(availability: ParserAvailability, name: &str) -> Option<FunctionSignature> {
    let shared = match name {
        "case" => Some(FunctionSignature {
            minimum: 3,
            maximum: 255,
        }),
        "contains" | "endswith" | "startswith" => Some(FunctionSignature {
            minimum: 2,
            maximum: 2,
        }),
        "format" => Some(FunctionSignature {
            minimum: 1,
            maximum: 255,
        }),
        "join" => Some(FunctionSignature {
            minimum: 1,
            maximum: 2,
        }),
        "tojson" | "fromjson" => Some(FunctionSignature {
            minimum: 1,
            maximum: 1,
        }),
        _ => None,
    };
    if shared.is_some() {
        return shared;
    }
    match (availability.status_functions, name) {
        (StatusFunctionAvailability::Job, "always" | "cancelled") => Some(FunctionSignature {
            minimum: 0,
            maximum: 0,
        }),
        (StatusFunctionAvailability::Job, "failure" | "success") => Some(FunctionSignature {
            minimum: 0,
            maximum: u16::MAX as usize,
        }),
        (StatusFunctionAvailability::Step, "always" | "cancelled" | "failure" | "success") => {
            Some(FunctionSignature {
                minimum: 0,
                maximum: 0,
            })
        }
        (_, "hashfiles") if availability.hash_files => Some(FunctionSignature {
            minimum: 1,
            maximum: 255,
        }),
        _ => None,
    }
}

fn context_allowed(availability: ParserAvailability, name: &str) -> bool {
    context_from_name(name).is_some_and(|context| availability.contexts.contains(&context))
}

fn context_from_name(name: &str) -> Option<ExpressionContext> {
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

fn token_description(kind: &TokenKind) -> &'static str {
    match kind {
        TokenKind::Identifier(_) => "an identifier",
        TokenKind::String(_) => "a string",
        TokenKind::Number(_) => "a number",
        TokenKind::Null => "`null`",
        TokenKind::Boolean(_) => "a boolean",
        TokenKind::LeftParen => "`(`",
        TokenKind::RightParen => "`)`",
        TokenKind::LeftBracket => "`[`",
        TokenKind::RightBracket => "`]`",
        TokenKind::Comma => "`,`",
        TokenKind::Dot => "`.`",
        TokenKind::Star => "`*`",
        TokenKind::Not => "`!`",
        TokenKind::Equal => "`==`",
        TokenKind::NotEqual => "`!=`",
        TokenKind::Greater => "`>`",
        TokenKind::GreaterOrEqual => "`>=`",
        TokenKind::Less => "`<`",
        TokenKind::LessOrEqual => "`<=`",
        TokenKind::And => "`&&`",
        TokenKind::Or => "`||`",
        TokenKind::Eof => "end of condition",
    }
}

enum Ast {
    Literal(ExpressionLiteral),
    NamedValue(String),
    Wildcard,
    Index {
        target: Box<Self>,
        index: Box<Self>,
    },
    Not(Box<Self>),
    Compare {
        operator: ExpressionComparison,
        left: Box<Self>,
        right: Box<Self>,
    },
    Logical {
        operator: ExpressionLogical,
        operands: Vec<Self>,
    },
    Call {
        name: String,
        arguments: Vec<Self>,
    },
}

impl Ast {
    fn call(name: &str, arguments: Vec<Self>) -> Self {
        Self::Call {
            name: name.to_owned(),
            arguments,
        }
    }

    fn logical(operator: ExpressionLogical, operands: Vec<Self>) -> Self {
        let mut flattened = Vec::new();
        for operand in operands {
            if let Self::Logical {
                operator: nested_operator,
                operands: nested,
            } = operand
            {
                if nested_operator == operator {
                    flattened.extend(nested);
                } else {
                    flattened.push(Self::Logical {
                        operator: nested_operator,
                        operands: nested,
                    });
                }
            } else {
                flattened.push(operand);
            }
        }
        Self::Logical {
            operator,
            operands: flattened,
        }
    }

    fn has_status_function(&self) -> bool {
        match self {
            Self::Call { name, arguments } => {
                matches!(
                    name.as_str(),
                    "always" | "success" | "failure" | "cancelled"
                ) || arguments.iter().any(Self::has_status_function)
            }
            Self::Index { target, index }
            | Self::Compare {
                left: target,
                right: index,
                ..
            } => target.has_status_function() || index.has_status_function(),
            Self::Not(operand) => operand.has_status_function(),
            Self::Logical { operands, .. } => operands.iter().any(Self::has_status_function),
            Self::Literal(_) | Self::NamedValue(_) | Self::Wildcard => false,
        }
    }

    fn metrics(&self) -> AstMetrics {
        match self {
            Self::Literal(_) | Self::NamedValue(_) | Self::Wildcard => {
                AstMetrics { nodes: 1, depth: 1 }
            }
            Self::Index { target, index }
            | Self::Compare {
                left: target,
                right: index,
                ..
            } => {
                let target = target.metrics();
                let index = index.metrics();
                AstMetrics {
                    nodes: target.nodes + index.nodes + 1,
                    depth: target.depth.max(index.depth) + 1,
                }
            }
            Self::Not(operand) => {
                let operand = operand.metrics();
                AstMetrics {
                    nodes: operand.nodes + 1,
                    depth: operand.depth + 1,
                }
            }
            Self::Logical { operands, .. }
            | Self::Call {
                arguments: operands,
                ..
            } => {
                let mut nodes = 1;
                let mut depth = 0;
                for operand in operands {
                    let metrics = operand.metrics();
                    nodes += metrics.nodes;
                    depth = depth.max(metrics.depth);
                }
                AstMetrics {
                    nodes,
                    depth: depth + 1,
                }
            }
        }
    }

    fn emit(self, output: &mut Vec<ExpressionInstruction>) {
        match self {
            Self::Literal(value) => output.push(ExpressionInstruction::Literal { value }),
            Self::NamedValue(name) => output.push(ExpressionInstruction::NamedValue { name }),
            Self::Wildcard => output.push(ExpressionInstruction::Wildcard),
            Self::Index { target, index } => {
                target.emit(output);
                index.emit(output);
                output.push(ExpressionInstruction::Index);
            }
            Self::Not(operand) => {
                operand.emit(output);
                output.push(ExpressionInstruction::Not);
            }
            Self::Compare {
                operator,
                left,
                right,
            } => {
                left.emit(output);
                right.emit(output);
                output.push(ExpressionInstruction::Compare { operator });
            }
            Self::Logical { operator, operands } => {
                let operand_count = u16::try_from(operands.len()).expect("expression node limit");
                for operand in operands {
                    operand.emit(output);
                }
                output.push(ExpressionInstruction::Logical {
                    operator,
                    operand_count,
                });
            }
            Self::Call { name, arguments } => {
                let argument_count = u16::try_from(arguments.len()).expect("expression node limit");
                for argument in arguments {
                    argument.emit(output);
                }
                output.push(ExpressionInstruction::Call {
                    name,
                    argument_count,
                });
            }
        }
    }
}

#[derive(Clone, Copy)]
struct AstMetrics {
    nodes: usize,
    depth: usize,
}

fn instruction_text_bytes(
    instructions: &[ExpressionInstruction],
) -> Result<usize, GithubExpressionError> {
    let mut total = 0_usize;
    for instruction in instructions {
        let length = match instruction {
            ExpressionInstruction::Literal {
                value: ExpressionLiteral::String { value },
            } => value.len(),
            ExpressionInstruction::NamedValue { name }
            | ExpressionInstruction::Call { name, .. } => name.len(),
            ExpressionInstruction::Literal { .. }
            | ExpressionInstruction::Wildcard
            | ExpressionInstruction::Index
            | ExpressionInstruction::Not
            | ExpressionInstruction::Compare { .. }
            | ExpressionInstruction::Logical { .. } => 0,
        };
        total = total.checked_add(length).ok_or_else(|| {
            resource_error(
                "github.expression.text_limit",
                "condition instruction text length overflowed",
                0,
                0,
            )
        })?;
    }
    Ok(total)
}

fn syntax_error(
    code: &'static str,
    message: impl Into<String>,
    byte_offset: usize,
    byte_length: usize,
) -> GithubExpressionError {
    GithubExpressionError {
        kind: GithubExpressionErrorKind::Syntax,
        code,
        message: message.into(),
        byte_offset,
        byte_length,
    }
}

fn context_error(
    code: &'static str,
    message: impl Into<String>,
    byte_offset: usize,
    byte_length: usize,
) -> GithubExpressionError {
    GithubExpressionError {
        kind: GithubExpressionErrorKind::Context,
        code,
        message: message.into(),
        byte_offset,
        byte_length,
    }
}

fn resource_error(
    code: &'static str,
    message: impl Into<String>,
    byte_offset: usize,
    byte_length: usize,
) -> GithubExpressionError {
    GithubExpressionError {
        kind: GithubExpressionErrorKind::ResourceLimit,
        code,
        message: message.into(),
        byte_offset,
        byte_length,
    }
}

fn internal_error(message: impl Into<String>) -> GithubExpressionError {
    GithubExpressionError {
        kind: GithubExpressionErrorKind::Internal,
        code: "github.expression.internal_program",
        message: message.into(),
        byte_offset: 0,
        byte_length: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GITHUB_EXPRESSION_MAX_UTF16_UNITS, GithubExpressionLimitRejection,
        github_expression_utf16_units_rejection,
    };

    #[test]
    fn github_expression_utf16_units_has_exact_boundaries() {
        assert_eq!(
            github_expression_utf16_units_rejection(GITHUB_EXPRESSION_MAX_UTF16_UNITS - 1),
            None
        );
        assert_eq!(
            github_expression_utf16_units_rejection(GITHUB_EXPRESSION_MAX_UTF16_UNITS),
            None
        );
        assert_eq!(
            github_expression_utf16_units_rejection(GITHUB_EXPRESSION_MAX_UTF16_UNITS + 1),
            Some(GithubExpressionLimitRejection::Utf16Units)
        );
    }
}
