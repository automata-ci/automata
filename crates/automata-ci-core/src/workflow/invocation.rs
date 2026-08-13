//! Typed reusable-workflow invocation contract.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};

use super::{
    CompiledValueTemplate, ExpressionContext, Located, LogicalResultReference,
    MAX_LOGICAL_RESULT_REFERENCES, PlanEvaluationPhase, PlanSourceSpan, WorkflowInputKey,
    WorkflowOutputKey, WorkflowPlanError, WorkflowSecretKey, source::validate_span_source,
    validation::LogicalPlanBudget,
};

/// Maximum definitions in each invocation contract namespace.
pub const MAX_INVOCATION_DEFINITIONS: usize = 256;
/// Maximum bytes in an invocation description or string default.
pub const MAX_INVOCATION_TEXT_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkflowInvocationLimitRejection {
    Definitions,
    TextBytes,
}

const fn workflow_invocation_definition_rejection(
    observed: usize,
) -> Option<WorkflowInvocationLimitRejection> {
    if observed > MAX_INVOCATION_DEFINITIONS {
        return Some(WorkflowInvocationLimitRejection::Definitions);
    }
    None
}

const fn workflow_invocation_text_byte_rejection(
    observed: usize,
) -> Option<WorkflowInvocationLimitRejection> {
    if observed > MAX_INVOCATION_TEXT_BYTES {
        return Some(WorkflowInvocationLimitRejection::TextBytes);
    }
    None
}

fn charge_invocation_text(
    budget: &mut LogicalPlanBudget,
    field: &'static str,
    value: &str,
) -> Result<(), WorkflowPlanError> {
    if workflow_invocation_text_byte_rejection(value.len()).is_some() {
        return Err(WorkflowPlanError::LimitExceeded {
            field,
            maximum: MAX_INVOCATION_TEXT_BYTES,
        });
    }
    budget.charge_text(field, value, MAX_INVOCATION_TEXT_BYTES)
}

/// Declared input type for a reusable workflow.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationInputType {
    /// A JSON-compatible Boolean value.
    Boolean,
    /// A decimal number represented by the contract's canonical string grammar.
    Number,
    /// An arbitrary UTF-8 string within the invocation text limit.
    String,
}

/// A typed, non-secret invocation default.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum InvocationInputDefault {
    /// A Boolean default.
    Boolean(bool),
    /// A decimal default preserved as text to avoid numeric precision loss.
    Number(String),
    /// A string default.
    String(String),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedInvocationInputDefault {
    Boolean { value: bool },
    Number { value: String },
    String { value: String },
}

impl<'de> Deserialize<'de> for InvocationInputDefault {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            match UncheckedInvocationInputDefault::deserialize(deserializer)? {
                UncheckedInvocationInputDefault::Boolean { value } => Self::Boolean(value),
                UncheckedInvocationInputDefault::Number { value } => Self::Number(value),
                UncheckedInvocationInputDefault::String { value } => Self::String(value),
            },
        )
    }
}

impl InvocationInputDefault {
    /// Returns the invocation input type accepted by this default value.
    #[must_use]
    pub const fn input_type(&self) -> InvocationInputType {
        match self {
            Self::Boolean(_) => InvocationInputType::Boolean,
            Self::Number(_) => InvocationInputType::Number,
            Self::String(_) => InvocationInputType::String,
        }
    }

    fn validate(&self, budget: &mut LogicalPlanBudget) -> Result<(), WorkflowPlanError> {
        budget.charge_node("invocation input default")?;
        match self {
            Self::Boolean(_) => Ok(()),
            Self::Number(value) => {
                budget.charge_text("invocation number default", value, 128)?;
                if valid_decimal(value) {
                    Ok(())
                } else {
                    Err(WorkflowPlanError::InvalidNumber(value.clone()))
                }
            }
            Self::String(value) => {
                charge_invocation_text(budget, "invocation string default", value)
            }
        }
    }
}

/// One typed input accepted at the workflow boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationInputDefinition {
    key: Located<WorkflowInputKey>,
    input_type: Located<InvocationInputType>,
    required: bool,
    default: Option<Located<InvocationInputDefault>>,
    description: Option<Located<String>>,
    span: PlanSourceSpan,
}

impl InvocationInputDefinition {
    /// Creates an input definition without validating its spans, limits, or default.
    #[must_use]
    pub const fn new(
        key: Located<WorkflowInputKey>,
        input_type: Located<InvocationInputType>,
        required: bool,
        default: Option<Located<InvocationInputDefault>>,
        description: Option<Located<String>>,
        span: PlanSourceSpan,
    ) -> Self {
        Self {
            key,
            input_type,
            required,
            default,
            description,
            span,
        }
    }

    /// Returns the input key together with its source location.
    #[must_use]
    pub const fn key(&self) -> &Located<WorkflowInputKey> {
        &self.key
    }

    /// Returns the declared type together with its source location.
    #[must_use]
    pub const fn input_type(&self) -> &Located<InvocationInputType> {
        &self.input_type
    }

    /// Returns whether callers must supply this input.
    ///
    /// Validation rejects required inputs that also declare a default.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }

    /// Returns the optional typed default together with its source location.
    #[must_use]
    pub const fn default(&self) -> Option<&Located<InvocationInputDefault>> {
        self.default.as_ref()
    }

    /// Returns the optional human-readable description and its source location.
    #[must_use]
    pub const fn description(&self) -> Option<&Located<String>> {
        self.description.as_ref()
    }

    /// Returns the source span covering the complete input definition.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    fn validate(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("invocation input")?;
        for (span, field) in [
            (self.span(), "invocation input"),
            (self.key.span(), "invocation input key"),
            (self.input_type.span(), "invocation input type"),
        ] {
            validate_span_source(span, source_id, field)?;
        }
        if self.required && self.default.is_some() {
            return Err(WorkflowPlanError::RequiredInputHasDefault(
                self.key.value().to_string(),
            ));
        }
        if let Some(default) = &self.default {
            validate_span_source(default.span(), source_id, "invocation input default")?;
            default.value().validate(budget)?;
            if default.value().input_type() != *self.input_type.value() {
                return Err(WorkflowPlanError::InvocationDefaultTypeMismatch {
                    input: self.key.value().to_string(),
                });
            }
        }
        if let Some(description) = &self.description {
            validate_span_source(
                description.span(),
                source_id,
                "invocation input description",
            )?;
            charge_invocation_text(budget, "invocation input description", description.value())?;
        }
        Ok(())
    }
}

/// One opaque secret binding accepted at the workflow boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationSecretDefinition {
    key: Located<WorkflowSecretKey>,
    required: bool,
    description: Option<Located<String>>,
    span: PlanSourceSpan,
}

impl InvocationSecretDefinition {
    /// Creates a secret definition without validating its spans or text limits.
    #[must_use]
    pub const fn new(
        key: Located<WorkflowSecretKey>,
        required: bool,
        description: Option<Located<String>>,
        span: PlanSourceSpan,
    ) -> Self {
        Self {
            key,
            required,
            description,
            span,
        }
    }

    /// Returns the secret key together with its source location.
    #[must_use]
    pub const fn key(&self) -> &Located<WorkflowSecretKey> {
        &self.key
    }

    /// Returns whether callers must bind this secret.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }

    /// Returns the optional human-readable description and its source location.
    #[must_use]
    pub const fn description(&self) -> Option<&Located<String>> {
        self.description.as_ref()
    }

    /// Returns the source span covering the complete secret definition.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    fn validate(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("invocation secret")?;
        validate_span_source(self.span(), source_id, "invocation secret")?;
        validate_span_source(self.key.span(), source_id, "invocation secret key")?;
        if let Some(description) = &self.description {
            validate_span_source(
                description.span(),
                source_id,
                "invocation secret description",
            )?;
            charge_invocation_text(budget, "invocation secret description", description.value())?;
        }
        Ok(())
    }
}

/// Sensitivity classification propagated into durable result handling.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputSensitivity {
    /// The output may be persisted and displayed without secret handling.
    Public,
    /// The output may reveal secret-derived data and requires protected handling.
    SecretDerived,
}

/// One output exposed by a reusable workflow invocation contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowOutputDefinition {
    key: Located<WorkflowOutputKey>,
    value: Located<CompiledValueTemplate>,
    references: Vec<Located<LogicalResultReference>>,
    sensitivity: OutputSensitivity,
    description: Option<Located<String>>,
    span: PlanSourceSpan,
}

impl WorkflowOutputDefinition {
    /// Creates an output definition without validating expression safety or provenance.
    #[must_use]
    pub const fn new(
        key: Located<WorkflowOutputKey>,
        value: Located<CompiledValueTemplate>,
        references: Vec<Located<LogicalResultReference>>,
        sensitivity: OutputSensitivity,
        description: Option<Located<String>>,
        span: PlanSourceSpan,
    ) -> Self {
        Self {
            key,
            value,
            references,
            sensitivity,
            description,
            span,
        }
    }

    /// Returns the exported output key together with its source location.
    #[must_use]
    pub const fn key(&self) -> &Located<WorkflowOutputKey> {
        &self.key
    }

    /// Returns the compiled output template together with its source location.
    #[must_use]
    pub const fn value(&self) -> &Located<CompiledValueTemplate> {
        &self.value
    }

    /// Returns the logical results that the output template is permitted to consume.
    #[must_use]
    pub fn references(&self) -> &[Located<LogicalResultReference>] {
        &self.references
    }

    /// Returns the durable-data sensitivity assigned to the output.
    #[must_use]
    pub const fn sensitivity(&self) -> OutputSensitivity {
        self.sensitivity
    }

    /// Returns the optional human-readable description and its source location.
    #[must_use]
    pub const fn description(&self) -> Option<&Located<String>> {
        self.description.as_ref()
    }

    /// Returns the source span covering the complete output definition.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    fn validate(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("workflow output")?;
        for (span, field) in [
            (self.span(), "workflow output"),
            (self.key.span(), "workflow output key"),
            (self.value.span(), "workflow output value"),
        ] {
            validate_span_source(span, source_id, field)?;
        }
        self.value.value().validate(
            "workflow output value",
            PlanEvaluationPhase::WorkflowFinalization,
            budget,
        )?;
        if self.sensitivity == OutputSensitivity::Public
            && self
                .value
                .value()
                .references_context(ExpressionContext::Secrets)
        {
            return Err(WorkflowPlanError::PublicOutputReferencesSecrets(
                self.key.value().to_string(),
            ));
        }
        if self.references.len() > MAX_LOGICAL_RESULT_REFERENCES {
            return Err(WorkflowPlanError::LimitExceeded {
                field: "workflow output result references",
                maximum: MAX_LOGICAL_RESULT_REFERENCES,
            });
        }
        let mut references = BTreeSet::new();
        for reference in &self.references {
            budget.charge_node("workflow output result reference")?;
            validate_span_source(
                reference.span(),
                source_id,
                "workflow output result reference",
            )?;
            if !references.insert(reference.value()) {
                return Err(WorkflowPlanError::DuplicateDefinition {
                    field: "workflow output result references",
                    key: reference.value().to_string(),
                });
            }
        }
        if let Some(description) = &self.description {
            validate_span_source(description.span(), source_id, "workflow output description")?;
            charge_invocation_text(budget, "workflow output description", description.value())?;
        }
        Ok(())
    }
}

/// Inputs, secret bindings, and outputs at a reusable-workflow boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowInvocationContract {
    inputs: Vec<InvocationInputDefinition>,
    secrets: Vec<InvocationSecretDefinition>,
    outputs: Vec<WorkflowOutputDefinition>,
    span: PlanSourceSpan,
}

impl WorkflowInvocationContract {
    /// Creates an invocation contract without validating namespace uniqueness or limits.
    #[must_use]
    pub const fn new(
        inputs: Vec<InvocationInputDefinition>,
        secrets: Vec<InvocationSecretDefinition>,
        outputs: Vec<WorkflowOutputDefinition>,
        span: PlanSourceSpan,
    ) -> Self {
        Self {
            inputs,
            secrets,
            outputs,
            span,
        }
    }

    /// Returns the workflow's declared caller-supplied inputs.
    #[must_use]
    pub fn inputs(&self) -> &[InvocationInputDefinition] {
        &self.inputs
    }

    /// Returns the workflow's declared opaque secret bindings.
    #[must_use]
    pub fn secrets(&self) -> &[InvocationSecretDefinition] {
        &self.secrets
    }

    /// Returns the workflow's declared reusable outputs.
    #[must_use]
    pub fn outputs(&self) -> &[WorkflowOutputDefinition] {
        &self.outputs
    }

    /// Returns the source span covering the complete invocation contract.
    #[must_use]
    pub const fn span(&self) -> &PlanSourceSpan {
        &self.span
    }

    pub(super) fn validate(
        &self,
        source_id: &str,
        budget: &mut LogicalPlanBudget,
    ) -> Result<(), WorkflowPlanError> {
        budget.charge_node("workflow invocation contract")?;
        validate_span_source(&self.span, source_id, "workflow invocation contract")?;
        validate_count("invocation inputs", self.inputs.len())?;
        validate_count("invocation secrets", self.secrets.len())?;
        validate_count("invocation outputs", self.outputs.len())?;

        let mut input_keys = BTreeSet::new();
        for input in &self.inputs {
            if !input_keys.insert(input.key().value()) {
                return Err(WorkflowPlanError::DuplicateDefinition {
                    field: "invocation inputs",
                    key: input.key().value().to_string(),
                });
            }
            input.validate(source_id, budget)?;
        }
        let mut secret_keys = BTreeSet::new();
        for secret in &self.secrets {
            if !secret_keys.insert(secret.key().value()) {
                return Err(WorkflowPlanError::DuplicateDefinition {
                    field: "invocation secrets",
                    key: secret.key().value().to_string(),
                });
            }
            secret.validate(source_id, budget)?;
        }
        let mut output_keys = BTreeSet::new();
        for output in &self.outputs {
            if !output_keys.insert(output.key().value()) {
                return Err(WorkflowPlanError::DuplicateDefinition {
                    field: "invocation outputs",
                    key: output.key().value().to_string(),
                });
            }
            output.validate(source_id, budget)?;
        }
        Ok(())
    }
}

fn validate_count(field: &'static str, count: usize) -> Result<(), WorkflowPlanError> {
    if workflow_invocation_definition_rejection(count).is_some() {
        return Err(WorkflowPlanError::LimitExceeded {
            field,
            maximum: MAX_INVOCATION_DEFINITIONS,
        });
    }
    Ok(())
}

#[cfg(test)]
mod limit_contract_tests {
    use super::{
        MAX_INVOCATION_DEFINITIONS, MAX_INVOCATION_TEXT_BYTES, WorkflowInvocationLimitRejection,
        workflow_invocation_definition_rejection, workflow_invocation_text_byte_rejection,
    };

    #[test]
    fn workflow_invocation_definition_limit_has_exact_boundaries() {
        assert_eq!(
            workflow_invocation_definition_rejection(MAX_INVOCATION_DEFINITIONS - 1),
            None
        );
        assert_eq!(
            workflow_invocation_definition_rejection(MAX_INVOCATION_DEFINITIONS),
            None
        );
        assert_eq!(
            workflow_invocation_definition_rejection(MAX_INVOCATION_DEFINITIONS + 1),
            Some(WorkflowInvocationLimitRejection::Definitions)
        );
    }

    #[test]
    fn workflow_invocation_text_byte_limit_has_exact_boundaries() {
        assert_eq!(
            workflow_invocation_text_byte_rejection(MAX_INVOCATION_TEXT_BYTES - 1),
            None
        );
        assert_eq!(
            workflow_invocation_text_byte_rejection(MAX_INVOCATION_TEXT_BYTES),
            None
        );
        assert_eq!(
            workflow_invocation_text_byte_rejection(MAX_INVOCATION_TEXT_BYTES + 1),
            Some(WorkflowInvocationLimitRejection::TextBytes)
        );
    }
}

fn valid_decimal(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut cursor = usize::from(bytes.first() == Some(&b'-'));
    match bytes.get(cursor) {
        Some(b'0') => cursor += 1,
        Some(b'1'..=b'9') => {
            cursor += 1;
            while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                cursor += 1;
            }
        }
        _ => return false,
    }
    if bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        let start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == start {
            return false;
        }
    }
    if matches!(bytes.get(cursor), Some(b'e' | b'E')) {
        cursor += 1;
        if matches!(bytes.get(cursor), Some(b'+' | b'-')) {
            cursor += 1;
        }
        let start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == start {
            return false;
        }
    }
    cursor == bytes.len()
}
