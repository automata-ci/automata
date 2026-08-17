//! Canonical bounded values and the immutable runtime context for one job instance.

use std::{collections::BTreeMap, fmt, marker::PhantomData};

use serde::{Deserialize, Serialize, de::MapAccess, de::Visitor};
use thiserror::Error;

use super::JobConclusion;
use crate::workflow::OutputSensitivity;

/// Schema emitted for independently persisted [`JobRuntimeContext`] blobs.
pub const JOB_RUNTIME_CONTEXT_SCHEMA_VERSION: u16 = 1;
/// Canonical media type for a protobuf-encoded job runtime context.
pub const JOB_RUNTIME_CONTEXT_MEDIA_TYPE: &str =
    "application/vnd.automata.job-runtime-context.protobuf";
/// Maximum nesting depth of a canonical runtime-context value.
pub const MAX_CONTEXT_VALUE_DEPTH: usize = 32;
/// Maximum aggregate value nodes in one canonical value or runtime context.
pub const MAX_CONTEXT_VALUE_NODES: usize = 65_536;
/// Maximum aggregate UTF-8 bytes in one canonical value or runtime context.
pub const MAX_CONTEXT_VALUE_TEXT_BYTES: usize = 1_048_576;
/// Maximum UTF-8 bytes in one runtime-context key or opaque binding identifier.
pub const MAX_RUNTIME_CONTEXT_IDENTIFIER_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeContextLimitRejection {
    ValueDepth,
    ValueNodes,
    ValueTextBytes,
    IdentifierBytes,
}

const fn context_value_depth_rejection(observed: usize) -> Option<RuntimeContextLimitRejection> {
    if observed > MAX_CONTEXT_VALUE_DEPTH {
        return Some(RuntimeContextLimitRejection::ValueDepth);
    }
    None
}

const fn context_value_node_rejection(observed: usize) -> Option<RuntimeContextLimitRejection> {
    if observed > MAX_CONTEXT_VALUE_NODES {
        return Some(RuntimeContextLimitRejection::ValueNodes);
    }
    None
}

const fn context_value_text_byte_rejection(
    observed: usize,
) -> Option<RuntimeContextLimitRejection> {
    if observed > MAX_CONTEXT_VALUE_TEXT_BYTES {
        return Some(RuntimeContextLimitRejection::ValueTextBytes);
    }
    None
}

const fn runtime_context_identifier_byte_rejection(
    observed: usize,
) -> Option<RuntimeContextLimitRejection> {
    if observed > MAX_RUNTIME_CONTEXT_IDENTIFIER_BYTES {
        return Some(RuntimeContextLimitRejection::IdentifierBytes);
    }
    None
}

/// A type-preserving value exposed to an expression runtime.
///
/// Objects use [`BTreeMap`] so their serialized representation and digest input
/// are stable regardless of insertion order. Number values retain exact IEEE-754
/// binary64 bits, including a single canonical NaN representation.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum ContextValue {
    /// Explicit null value.
    Null,
    /// Concrete boolean value.
    Boolean {
        /// Boolean payload.
        value: bool,
    },
    /// Exact IEEE-754 binary64 value.
    Number {
        /// Canonical IEEE-754 bits; NaN has one permitted encoding.
        ieee754_bits: u64,
    },
    /// UTF-8 string charged against the aggregate text budget.
    String {
        /// Exact string payload.
        value: String,
    },
    /// Ordered collection of nested context values.
    Array {
        /// Elements retained in source order.
        values: Vec<Self>,
    },
    /// Deterministically ordered mapping of names to nested values.
    Object {
        /// Entries sorted by key through [`BTreeMap`].
        values: BTreeMap<String, Self>,
    },
}

impl fmt::Debug for ContextValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => formatter.write_str("ContextValue::Null"),
            Self::Boolean { .. } => formatter.write_str("ContextValue::Boolean([REDACTED])"),
            Self::Number { .. } => formatter.write_str("ContextValue::Number([REDACTED])"),
            Self::String { value } => formatter
                .debug_tuple("ContextValue::String")
                .field(&format_args!("{} bytes [REDACTED]", value.len()))
                .finish(),
            Self::Array { values } => formatter
                .debug_tuple("ContextValue::Array")
                .field(&format_args!("{} items [REDACTED]", values.len()))
                .finish(),
            Self::Object { values } => formatter
                .debug_tuple("ContextValue::Object")
                .field(&format_args!("{} entries [REDACTED]", values.len()))
                .finish(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum UncheckedContextValue {
    Null,
    Boolean { value: bool },
    Number { ieee754_bits: u64 },
    String { value: String },
    Array { values: Vec<ContextValue> },
    Object { values: CanonicalMap<ContextValue> },
}

impl<'de> Deserialize<'de> for ContextValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = match UncheckedContextValue::deserialize(deserializer)? {
            UncheckedContextValue::Null => Self::Null,
            UncheckedContextValue::Boolean { value } => Self::Boolean { value },
            UncheckedContextValue::Number { ieee754_bits } => Self::Number { ieee754_bits },
            UncheckedContextValue::String { value } => Self::String { value },
            UncheckedContextValue::Array { values } => Self::Array { values },
            UncheckedContextValue::Object { values } => Self::Object { values: values.0 },
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl ContextValue {
    /// Creates an explicit null value.
    #[must_use]
    pub const fn null() -> Self {
        Self::Null
    }

    /// Creates a concrete boolean value.
    #[must_use]
    pub const fn boolean(value: bool) -> Self {
        Self::Boolean { value }
    }

    /// Creates an exact number value and canonicalizes NaN payloads.
    #[must_use]
    pub fn number(value: f64) -> Self {
        let value = if value.is_nan() { f64::NAN } else { value };
        Self::Number {
            ieee754_bits: value.to_bits(),
        }
    }

    /// Creates a string value; enclosing context validation enforces text budgets.
    #[must_use]
    pub fn string(value: impl Into<String>) -> Self {
        Self::String {
            value: value.into(),
        }
    }

    /// Creates and validates an array value.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeContextError`] when the resulting tree exceeds its
    /// depth, node, or text budget.
    pub fn array(values: Vec<Self>) -> Result<Self, RuntimeContextError> {
        let value = Self::Array { values };
        value.validate()?;
        Ok(value)
    }

    /// Creates and validates a canonical object value.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeContextError`] when the resulting tree exceeds its
    /// depth, node, or text budget.
    pub fn object(values: BTreeMap<String, Self>) -> Result<Self, RuntimeContextError> {
        let value = Self::Object { values };
        value.validate()?;
        Ok(value)
    }

    /// Creates the canonical empty object used for absent root contexts.
    #[must_use]
    pub const fn empty_object() -> Self {
        Self::Object {
            values: BTreeMap::new(),
        }
    }

    /// Returns the boolean payload when this value has boolean type.
    #[must_use]
    pub const fn as_boolean(&self) -> Option<bool> {
        match self {
            Self::Boolean { value } => Some(*value),
            _ => None,
        }
    }

    /// Returns the reconstructed binary64 value when this value has number type.
    #[must_use]
    pub const fn as_number(&self) -> Option<f64> {
        match self {
            Self::Number { ieee754_bits } => Some(f64::from_bits(*ieee754_bits)),
            _ => None,
        }
    }

    /// Returns the UTF-8 payload when this value has string type.
    #[must_use]
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String { value } => Some(value),
            _ => None,
        }
    }

    /// Returns ordered elements when this value has array type.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array { values } => Some(values),
            _ => None,
        }
    }

    /// Returns the deterministic mapping when this value has object type.
    #[must_use]
    pub const fn as_object(&self) -> Option<&BTreeMap<String, Self>> {
        match self {
            Self::Object { values } => Some(values),
            _ => None,
        }
    }

    /// Revalidates canonical form and resource bounds.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeContextError`] for excessive depth, node count, text,
    /// or a noncanonical NaN bit pattern.
    pub fn validate(&self) -> Result<(), RuntimeContextError> {
        let mut budget = ContextBudget::default();
        self.charge(&mut budget)
    }

    fn charge(&self, budget: &mut ContextBudget) -> Result<(), RuntimeContextError> {
        let mut pending = vec![(self, 1_usize)];
        while let Some((value, depth)) = pending.pop() {
            if context_value_depth_rejection(depth).is_some() {
                return Err(RuntimeContextError::ValueTooDeep {
                    maximum: MAX_CONTEXT_VALUE_DEPTH,
                });
            }
            budget.charge_node()?;
            match value {
                Self::Null | Self::Boolean { .. } => {}
                Self::Number { ieee754_bits } => {
                    let number = f64::from_bits(*ieee754_bits);
                    if number.is_nan() && *ieee754_bits != f64::NAN.to_bits() {
                        return Err(RuntimeContextError::NonCanonicalNan);
                    }
                }
                Self::String { value } => budget.charge_text(value.len())?,
                Self::Array { values } => {
                    budget.ensure_node_capacity(pending.len(), values.len())?;
                    pending.extend(values.iter().rev().map(|value| (value, depth + 1)));
                }
                Self::Object { values } => {
                    budget.ensure_node_capacity(pending.len(), values.len())?;
                    for (key, value) in values.iter().rev() {
                        budget.charge_text(key.len())?;
                        pending.push((value, depth + 1));
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct ContextBudget {
    nodes: usize,
    text_bytes: usize,
}

impl ContextBudget {
    fn ensure_node_capacity(
        &self,
        pending: usize,
        additional: usize,
    ) -> Result<(), RuntimeContextError> {
        let projected = self
            .nodes
            .checked_add(pending)
            .and_then(|value| value.checked_add(additional))
            .ok_or(RuntimeContextError::TooManyValueNodes {
                maximum: MAX_CONTEXT_VALUE_NODES,
            })?;
        if context_value_node_rejection(projected).is_some() {
            return Err(RuntimeContextError::TooManyValueNodes {
                maximum: MAX_CONTEXT_VALUE_NODES,
            });
        }
        Ok(())
    }

    fn charge_node(&mut self) -> Result<(), RuntimeContextError> {
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(RuntimeContextError::TooManyValueNodes {
                maximum: MAX_CONTEXT_VALUE_NODES,
            })?;
        if context_value_node_rejection(self.nodes).is_some() {
            return Err(RuntimeContextError::TooManyValueNodes {
                maximum: MAX_CONTEXT_VALUE_NODES,
            });
        }
        Ok(())
    }

    fn charge_text(&mut self, bytes: usize) -> Result<(), RuntimeContextError> {
        self.text_bytes =
            self.text_bytes
                .checked_add(bytes)
                .ok_or(RuntimeContextError::TooMuchValueText {
                    maximum: MAX_CONTEXT_VALUE_TEXT_BYTES,
                })?;
        if context_value_text_byte_rejection(self.text_bytes).is_some() {
            return Err(RuntimeContextError::TooMuchValueText {
                maximum: MAX_CONTEXT_VALUE_TEXT_BYTES,
            });
        }
        Ok(())
    }
}

/// Runtime `strategy` values for one concrete job instance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedStrategyContext")]
pub struct StrategyContext {
    fail_fast: bool,
    job_index: u32,
    job_total: u32,
    max_parallel: u32,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedStrategyContext {
    fail_fast: bool,
    job_index: u32,
    job_total: u32,
    max_parallel: u32,
}

impl TryFrom<UncheckedStrategyContext> for StrategyContext {
    type Error = RuntimeContextError;

    fn try_from(value: UncheckedStrategyContext) -> Result<Self, Self::Error> {
        Self::new(
            value.fail_fast,
            value.job_index,
            value.job_total,
            value.max_parallel,
        )
    }
}

impl StrategyContext {
    /// Creates a valid strategy context. `job_index` is zero based.
    ///
    /// # Errors
    ///
    /// Rejects empty expansions, out-of-range indices, and zero parallelism.
    pub fn new(
        fail_fast: bool,
        job_index: u32,
        job_total: u32,
        max_parallel: u32,
    ) -> Result<Self, RuntimeContextError> {
        if job_total == 0 {
            return Err(RuntimeContextError::ZeroJobTotal);
        }
        if job_index >= job_total {
            return Err(RuntimeContextError::JobIndexOutOfRange {
                index: job_index,
                total: job_total,
            });
        }
        if max_parallel == 0 {
            return Err(RuntimeContextError::ZeroMaxParallel);
        }
        Ok(Self {
            fail_fast,
            job_index,
            job_total,
            max_parallel,
        })
    }

    /// Reports whether a failing matrix sibling should cancel outstanding siblings.
    #[must_use]
    pub const fn fail_fast(self) -> bool {
        self.fail_fast
    }

    /// Returns this concrete expansion's zero-based matrix position.
    #[must_use]
    pub const fn job_index(self) -> u32 {
        self.job_index
    }

    /// Returns the total number of concrete matrix expansions.
    #[must_use]
    pub const fn job_total(self) -> u32 {
        self.job_total
    }

    /// Returns the positive concurrency ceiling for this logical job.
    #[must_use]
    pub const fn max_parallel(self) -> u32 {
        self.max_parallel
    }

    fn validate(self) -> Result<(), RuntimeContextError> {
        Self::new(
            self.fail_fast,
            self.job_index,
            self.job_total,
            self.max_parallel,
        )
        .map(|_| ())
    }
}

/// One sensitivity-bearing output published by a prerequisite logical job.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedNeedOutput")]
pub struct NeedOutput {
    value: String,
    sensitivity: OutputSensitivity,
}

impl fmt::Debug for NeedOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NeedOutput")
            .field(
                "value",
                &format_args!("{} bytes [REDACTED]", self.value.len()),
            )
            .field("sensitivity", &self.sensitivity)
            .finish()
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedNeedOutput {
    value: String,
    sensitivity: OutputSensitivity,
}

impl TryFrom<UncheckedNeedOutput> for NeedOutput {
    type Error = RuntimeContextError;

    fn try_from(value: UncheckedNeedOutput) -> Result<Self, Self::Error> {
        Self::new(value.value, value.sensitivity)
    }
}

impl NeedOutput {
    /// Creates one bounded prerequisite output with an explicit sensitivity.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeContextError`] when the value exceeds the runtime
    /// context text budget.
    pub fn new(
        value: impl Into<String>,
        sensitivity: OutputSensitivity,
    ) -> Result<Self, RuntimeContextError> {
        let output = Self {
            value: value.into(),
            sensitivity,
        };
        let mut budget = ContextBudget::default();
        output.charge(&mut budget)?;
        Ok(output)
    }

    /// Explicitly exposes the exact value to an authorized persistence or
    /// execution boundary. Expression adapters must use [`Self::public_value`]
    /// instead.
    #[must_use]
    pub fn expose_value(&self) -> &str {
        &self.value
    }

    /// Returns the value only when it is safe to expose to ordinary
    /// expressions.
    #[must_use]
    pub fn public_value(&self) -> Option<&str> {
        (self.sensitivity == OutputSensitivity::Public).then_some(self.value.as_str())
    }

    /// Returns the output's disclosure classification.
    #[must_use]
    pub const fn sensitivity(&self) -> OutputSensitivity {
        self.sensitivity
    }

    fn charge(&self, budget: &mut ContextBudget) -> Result<(), RuntimeContextError> {
        budget.charge_node()?;
        budget.charge_text(self.value.len())
    }
}

/// Immutable terminal context published by one prerequisite logical job.
///
/// Consumers constructing an ordinary expression context must expose output
/// values through [`NeedOutput::public_value`] rather than
/// [`NeedOutput::expose_value`].
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedNeedContext")]
pub struct NeedContext {
    result: JobConclusion,
    outputs: BTreeMap<String, NeedOutput>,
}

impl fmt::Debug for NeedContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NeedContext")
            .field("result", &self.result)
            .field(
                "outputs",
                &format_args!("{} entries [REDACTED]", self.outputs.len()),
            )
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedNeedContext {
    result: JobConclusion,
    outputs: CanonicalMap<NeedOutput>,
}

impl TryFrom<UncheckedNeedContext> for NeedContext {
    type Error = RuntimeContextError;

    fn try_from(value: UncheckedNeedContext) -> Result<Self, Self::Error> {
        Self::new(value.result, value.outputs.0)
    }
}

impl NeedContext {
    /// Creates one prerequisite context with bounded canonical output names and values.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeContextError`] for an invalid key or excessive text.
    pub fn new(
        result: JobConclusion,
        outputs: BTreeMap<String, NeedOutput>,
    ) -> Result<Self, RuntimeContextError> {
        let value = Self { result, outputs };
        let mut budget = ContextBudget::default();
        value.charge(&mut budget)?;
        Ok(value)
    }

    /// Returns the prerequisite job's effective terminal conclusion.
    #[must_use]
    pub const fn result(&self) -> JobConclusion {
        self.result
    }

    /// Returns deterministic, name-keyed prerequisite outputs.
    #[must_use]
    pub const fn outputs(&self) -> &BTreeMap<String, NeedOutput> {
        &self.outputs
    }

    fn charge(&self, budget: &mut ContextBudget) -> Result<(), RuntimeContextError> {
        budget.charge_node()?;
        for (key, value) in &self.outputs {
            validate_runtime_key(key, "need output")?;
            budget.charge_text(key.len())?;
            value.charge(budget)?;
        }
        Ok(())
    }
}

/// A non-secret locator for a separately authorized secret value.
///
/// Binding and version identifiers must not themselves be bearer credentials.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedSecretBinding")]
pub struct SecretBinding {
    binding_id: String,
    version_id: Option<String>,
}

impl fmt::Debug for SecretBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBinding")
            .field("binding_id", &"[REDACTED]")
            .field(
                "version_id",
                &self.version_id.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedSecretBinding {
    binding_id: String,
    version_id: Option<String>,
}

impl TryFrom<UncheckedSecretBinding> for SecretBinding {
    type Error = RuntimeContextError;

    fn try_from(value: UncheckedSecretBinding) -> Result<Self, Self::Error> {
        let binding = Self {
            binding_id: value.binding_id,
            version_id: value.version_id,
        };
        binding.validate()?;
        Ok(binding)
    }
}

impl SecretBinding {
    /// Creates an opaque secret binding without selecting a version.
    ///
    /// # Errors
    ///
    /// Rejects empty, overlong, or control-bearing identifiers.
    pub fn new(binding_id: impl Into<String>) -> Result<Self, RuntimeContextError> {
        let binding = Self {
            binding_id: binding_id.into(),
            version_id: None,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Selects an immutable secret version.
    ///
    /// # Errors
    ///
    /// Rejects empty, overlong, or control-bearing version identifiers.
    pub fn with_version_id(
        mut self,
        version_id: impl Into<String>,
    ) -> Result<Self, RuntimeContextError> {
        self.version_id = Some(version_id.into());
        self.validate()?;
        Ok(self)
    }

    /// Returns the opaque authorization binding identity, not a bearer secret.
    #[must_use]
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }

    /// Returns the optionally pinned immutable secret-version identity.
    #[must_use]
    pub fn version_id(&self) -> Option<&str> {
        self.version_id.as_deref()
    }

    fn validate(&self) -> Result<(), RuntimeContextError> {
        validate_opaque_identifier(&self.binding_id, "secret binding ID")?;
        if let Some(version_id) = &self.version_id {
            validate_opaque_identifier(version_id, "secret version ID")?;
        }
        Ok(())
    }

    fn charge(&self, budget: &mut ContextBudget) -> Result<(), RuntimeContextError> {
        self.validate()?;
        budget.charge_node()?;
        budget.charge_text(self.binding_id.len())?;
        if let Some(version_id) = &self.version_id {
            budget.charge_text(version_id.len())?;
        }
        Ok(())
    }
}

/// Complete immutable expression context for one concrete job instance.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct JobRuntimeContext {
    schema_version: u16,
    inputs: ContextValue,
    vars: ContextValue,
    matrix: ContextValue,
    strategy: StrategyContext,
    needs: BTreeMap<String, NeedContext>,
    secrets: BTreeMap<String, SecretBinding>,
}

impl fmt::Debug for JobRuntimeContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobRuntimeContext")
            .field("schema_version", &self.schema_version)
            .field("inputs", &"[REDACTED]")
            .field("vars", &"[REDACTED]")
            .field("matrix", &"[REDACTED]")
            .field("strategy", &self.strategy)
            .field(
                "needs",
                &format_args!("{} jobs [REDACTED]", self.needs.len()),
            )
            .field(
                "secrets",
                &format_args!("{} bindings [REDACTED]", self.secrets.len()),
            )
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedJobRuntimeContext {
    schema_version: u16,
    inputs: ContextValue,
    vars: ContextValue,
    matrix: ContextValue,
    strategy: StrategyContext,
    needs: CanonicalMap<NeedContext>,
    secrets: CanonicalMap<SecretBinding>,
}

impl<'de> Deserialize<'de> for JobRuntimeContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = UncheckedJobRuntimeContext::deserialize(deserializer)?;
        let context = Self {
            schema_version: value.schema_version,
            inputs: value.inputs,
            vars: value.vars,
            matrix: value.matrix,
            strategy: value.strategy,
            needs: value.needs.0,
            secrets: value.secrets.0,
        };
        context.validate().map_err(serde::de::Error::custom)?;
        Ok(context)
    }
}

impl JobRuntimeContext {
    /// Creates the provider-neutral base context admitted before job expansion.
    ///
    /// Inputs and variables are canonical public expression objects. Secret
    /// entries are opaque locators for separately authorized values. Matrix,
    /// strategy expansion, and prerequisite results are intentionally empty.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeContextError`] for invalid object shapes, names,
    /// bindings, or aggregate resource-limit violations.
    pub fn new_base(
        inputs: ContextValue,
        vars: ContextValue,
        secrets: BTreeMap<String, SecretBinding>,
    ) -> Result<Self, RuntimeContextError> {
        Self::new(
            inputs,
            vars,
            ContextValue::empty_object(),
            StrategyContext::new(true, 0, 1, 1)?,
            BTreeMap::new(),
            secrets,
        )
    }

    /// Creates the canonical empty admission base context.
    #[must_use]
    pub fn empty_base() -> Self {
        Self {
            schema_version: JOB_RUNTIME_CONTEXT_SCHEMA_VERSION,
            inputs: ContextValue::empty_object(),
            vars: ContextValue::empty_object(),
            matrix: ContextValue::empty_object(),
            strategy: StrategyContext {
                fail_fast: true,
                job_index: 0,
                job_total: 1,
                max_parallel: 1,
            },
            needs: BTreeMap::new(),
            secrets: BTreeMap::new(),
        }
    }

    /// Creates and validates the runtime contexts for one job instance.
    ///
    /// `inputs`, `vars`, and `matrix` must be canonical object values, including
    /// when the corresponding context is empty.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeContextError`] for invalid shapes, keys, strategy
    /// values, bindings, or aggregate resource-limit violations.
    pub fn new(
        inputs: ContextValue,
        vars: ContextValue,
        matrix: ContextValue,
        strategy: StrategyContext,
        needs: BTreeMap<String, NeedContext>,
        secrets: BTreeMap<String, SecretBinding>,
    ) -> Result<Self, RuntimeContextError> {
        let context = Self {
            schema_version: JOB_RUNTIME_CONTEXT_SCHEMA_VERSION,
            inputs,
            vars,
            matrix,
            strategy,
            needs,
            secrets,
        };
        context.validate()?;
        Ok(context)
    }

    /// Returns the independently persisted runtime-context schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the canonical object exposed as the `inputs` expression context.
    #[must_use]
    pub const fn inputs(&self) -> &ContextValue {
        &self.inputs
    }

    /// Returns the canonical object exposed as the `vars` expression context.
    #[must_use]
    pub const fn vars(&self) -> &ContextValue {
        &self.vars
    }

    /// Returns the canonical object exposed as the `matrix` expression context.
    #[must_use]
    pub const fn matrix(&self) -> &ContextValue {
        &self.matrix
    }

    /// Returns the concrete expansion and concurrency metadata.
    #[must_use]
    pub const fn strategy(&self) -> StrategyContext {
        self.strategy
    }

    /// Returns terminal evidence for declared prerequisite jobs.
    #[must_use]
    pub const fn needs(&self) -> &BTreeMap<String, NeedContext> {
        &self.needs
    }

    /// Returns non-secret locators for separately authorized secret values.
    #[must_use]
    pub const fn secrets(&self) -> &BTreeMap<String, SecretBinding> {
        &self.secrets
    }

    /// Revalidates a decoded runtime-context blob.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeContextError`] for unsupported schemas, non-object
    /// root contexts, or any canonicalization/resource-bound violation.
    pub fn validate(&self) -> Result<(), RuntimeContextError> {
        if self.schema_version != JOB_RUNTIME_CONTEXT_SCHEMA_VERSION {
            return Err(RuntimeContextError::UnsupportedSchema {
                supported: JOB_RUNTIME_CONTEXT_SCHEMA_VERSION,
                received: self.schema_version,
            });
        }
        for (field, value) in [
            ("inputs", &self.inputs),
            ("vars", &self.vars),
            ("matrix", &self.matrix),
        ] {
            let ContextValue::Object { values } = value else {
                return Err(RuntimeContextError::ContextMustBeObject(field));
            };
            for key in values.keys() {
                validate_runtime_key(key, field)?;
            }
        }
        self.strategy.validate()?;

        let mut budget = ContextBudget::default();
        self.inputs.charge(&mut budget)?;
        self.vars.charge(&mut budget)?;
        self.matrix.charge(&mut budget)?;
        for (key, need) in &self.needs {
            validate_runtime_key(key, "needs job")?;
            budget.charge_text(key.len())?;
            need.charge(&mut budget)?;
        }
        for (key, binding) in &self.secrets {
            validate_runtime_key(key, "secret name")?;
            budget.charge_text(key.len())?;
            binding.charge(&mut budget)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct CanonicalMap<T>(BTreeMap<String, T>);

impl<'de, T> Deserialize<'de> for CanonicalMap<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(CanonicalMapVisitor(PhantomData))
    }
}

struct CanonicalMapVisitor<T>(PhantomData<T>);

impl<'de, T> Visitor<'de> for CanonicalMapVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = CanonicalMap<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object with unique string keys")
    }

    fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some((key, value)) = entries.next_entry::<String, T>()? {
            if values.insert(key, value).is_some() {
                return Err(serde::de::Error::custom(
                    "duplicate key in canonical object",
                ));
            }
        }
        Ok(CanonicalMap(values))
    }
}

fn validate_runtime_key(value: &str, field: &'static str) -> Result<(), RuntimeContextError> {
    if value.is_empty()
        || value.trim() != value
        || runtime_context_identifier_byte_rejection(value.len()).is_some()
        || value.chars().any(char::is_control)
    {
        return Err(RuntimeContextError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_opaque_identifier(value: &str, field: &'static str) -> Result<(), RuntimeContextError> {
    validate_runtime_key(value, field)
}

#[cfg(test)]
crate::test_support::limit_contract_tests! {
    context_value_depth_limit_has_exact_boundaries: (
        super::context_value_depth_rejection,
        super::MAX_CONTEXT_VALUE_DEPTH,
    ) => super::RuntimeContextLimitRejection::ValueDepth;
    context_value_node_limit_has_exact_boundaries: (
        super::context_value_node_rejection,
        super::MAX_CONTEXT_VALUE_NODES,
    ) => super::RuntimeContextLimitRejection::ValueNodes;
    context_value_text_byte_limit_has_exact_boundaries: (
        super::context_value_text_byte_rejection,
        super::MAX_CONTEXT_VALUE_TEXT_BYTES,
    ) => super::RuntimeContextLimitRejection::ValueTextBytes;
    runtime_context_identifier_byte_limit_has_exact_boundaries: (
        super::runtime_context_identifier_byte_rejection,
        super::MAX_RUNTIME_CONTEXT_IDENTIFIER_BYTES,
    ) => super::RuntimeContextLimitRejection::IdentifierBytes;
}

/// Invalid canonical value or runtime-context blob.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RuntimeContextError {
    /// The persisted context uses a schema this build cannot interpret.
    #[error("unsupported job runtime-context schema {received}; this build supports {supported}")]
    UnsupportedSchema {
        /// Schema version understood by this build.
        supported: u16,
        /// Schema version found in the context blob.
        received: u16,
    },
    /// One of the required top-level expression contexts was not an object.
    #[error("runtime context `{0}` must be a canonical object value")]
    ContextMustBeObject(&'static str),
    /// A nested value exceeded the evaluator's bounded traversal depth.
    #[error("a context value exceeds the maximum depth of {maximum}")]
    ValueTooDeep {
        /// Maximum permitted nesting depth.
        maximum: usize,
    },
    /// Aggregate nested values exceeded the node-count budget.
    #[error("a context value exceeds the maximum of {maximum} aggregate nodes")]
    TooManyValueNodes {
        /// Maximum aggregate value nodes.
        maximum: usize,
    },
    /// Aggregate keys, strings, outputs, and binding identifiers exceeded the text budget.
    #[error("a context value exceeds the maximum of {maximum} aggregate UTF-8 bytes")]
    TooMuchValueText {
        /// Maximum aggregate UTF-8 bytes.
        maximum: usize,
    },
    /// A number retained a noncanonical NaN payload.
    #[error("context number uses a noncanonical NaN bit pattern")]
    NonCanonicalNan,
    /// Strategy metadata declared no concrete job expansions.
    #[error("strategy job total cannot be zero")]
    ZeroJobTotal,
    /// The concrete expansion index fell outside the declared total.
    #[error("strategy job index {index} is outside job total {total}")]
    JobIndexOutOfRange {
        /// Rejected zero-based expansion index.
        index: u32,
        /// Declared expansion count.
        total: u32,
    },
    /// Strategy concurrency was zero and could never admit an instance.
    #[error("strategy maximum parallelism cannot be zero")]
    ZeroMaxParallel,
    /// A map key or opaque locator violated its bounded, unpadded text contract.
    #[error("runtime-context {field} is empty, overlong, padded, or contains control characters")]
    InvalidIdentifier {
        /// Context field containing the rejected identifier.
        field: &'static str,
    },
}
