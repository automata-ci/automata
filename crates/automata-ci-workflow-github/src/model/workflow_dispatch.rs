use std::{collections::BTreeMap, error::Error, fmt};

use automata_ci_core::WorkflowInputKey;

/// Maximum number of inputs accepted by a GitHub manual-dispatch contract or payload.
// foundation-governance: parity-limit
pub const MAX_GITHUB_WORKFLOW_DISPATCH_INPUTS: usize = 25;

/// Maximum aggregate characters accepted in one verified manual-dispatch payload.
///
/// The budget includes input identifiers and the textual representation of each
/// value. It matches GitHub's documented 65,535-character payload ceiling while
/// remaining independent of a webhook's JSON serialization details.
// foundation-governance: parity-limit
pub const MAX_GITHUB_WORKFLOW_DISPATCH_INPUT_CHARACTERS: usize = 65_535;

/// Supported source type for one manually dispatched workflow input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubWorkflowDispatchInputType {
    /// A Boolean value exposed as a Boolean in the canonical `inputs` context.
    Boolean,
    /// One string selected from the source contract's exact option set.
    Choice,
    /// An arbitrary string value.
    String,
}

/// Type-preserving default declared by a manual-dispatch input definition.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubWorkflowDispatchInputDefault {
    /// A Boolean default.
    Boolean(bool),
    /// A string or choice default.
    String(String),
}

impl fmt::Debug for GithubWorkflowDispatchInputDefault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boolean(_) => formatter.write_str("Boolean([REDACTED])"),
            Self::String(value) => formatter
                .debug_tuple("String")
                .field(&format_args!("{} chars [REDACTED]", value.chars().count()))
                .finish(),
        }
    }
}

/// One validated input definition from an `on.workflow_dispatch` source contract.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct GithubWorkflowDispatchInputDefinition {
    input_type: GithubWorkflowDispatchInputType,
    required: bool,
    default: Option<GithubWorkflowDispatchInputDefault>,
    options: Vec<String>,
    description: Option<String>,
}

impl GithubWorkflowDispatchInputDefinition {
    pub(crate) fn new(
        input_type: GithubWorkflowDispatchInputType,
        required: bool,
        default: Option<GithubWorkflowDispatchInputDefault>,
        options: Vec<String>,
        description: Option<String>,
    ) -> Self {
        Self {
            input_type,
            required,
            default,
            options,
            description,
        }
    }

    /// Returns the source-declared input type.
    #[must_use]
    pub const fn input_type(&self) -> GithubWorkflowDispatchInputType {
        self.input_type
    }

    /// Returns whether callers must provide this input when no default exists.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }

    /// Returns the validated source default, when configured.
    #[must_use]
    pub const fn default(&self) -> Option<&GithubWorkflowDispatchInputDefault> {
        self.default.as_ref()
    }

    /// Returns the exact allowed values for a choice input.
    ///
    /// This is empty for Boolean and string definitions.
    #[must_use]
    pub fn options(&self) -> &[String] {
        &self.options
    }

    /// Returns the optional user-facing source description.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// Canonically ordered, validated source contract for a manually dispatched workflow.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct GithubWorkflowDispatchContract {
    inputs: BTreeMap<WorkflowInputKey, GithubWorkflowDispatchInputDefinition>,
}

impl GithubWorkflowDispatchContract {
    pub(crate) fn new(
        inputs: BTreeMap<WorkflowInputKey, GithubWorkflowDispatchInputDefinition>,
    ) -> Self {
        Self { inputs }
    }

    /// Returns the definitions in deterministic input-key order.
    #[must_use]
    pub const fn inputs(
        &self,
    ) -> &BTreeMap<WorkflowInputKey, GithubWorkflowDispatchInputDefinition> {
        &self.inputs
    }

    /// Returns whether the workflow declares no manual-dispatch inputs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty()
    }
}

/// Raw value from a provider-verified manual-dispatch payload.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubWorkflowDispatchInputValue {
    /// A provider-native Boolean value.
    Boolean(bool),
    /// A provider-native string value.
    String(String),
}

impl fmt::Debug for GithubWorkflowDispatchInputValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boolean(_) => formatter.write_str("Boolean([REDACTED])"),
            Self::String(value) => formatter
                .debug_tuple("String")
                .field(&format_args!("{} chars [REDACTED]", value.chars().count()))
                .finish(),
        }
    }
}

impl From<bool> for GithubWorkflowDispatchInputValue {
    fn from(value: bool) -> Self {
        Self::Boolean(value)
    }
}

impl From<String> for GithubWorkflowDispatchInputValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for GithubWorkflowDispatchInputValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

/// Structural failure while creating bounded manual-dispatch evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubWorkflowDispatchInputsError {
    /// The payload contains more than the supported number of input properties.
    TooManyInputs,
    /// An input identifier is empty, padded, overlong, or contains control characters.
    InvalidInputKey,
    /// The payload repeats an input identifier.
    DuplicateInputKey,
    /// The aggregate identifier and value character budget is exceeded.
    PayloadTooLarge,
}

impl fmt::Display for GithubWorkflowDispatchInputsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyInputs => write!(
                formatter,
                "workflow_dispatch payloads may contain at most {MAX_GITHUB_WORKFLOW_DISPATCH_INPUTS} inputs"
            ),
            Self::InvalidInputKey => formatter.write_str(
                "workflow_dispatch payload input identifiers must be valid workflow input keys",
            ),
            Self::DuplicateInputKey => {
                formatter.write_str("workflow_dispatch payload input identifiers must be unique")
            }
            Self::PayloadTooLarge => write!(
                formatter,
                "workflow_dispatch input identifiers and values may contain at most {MAX_GITHUB_WORKFLOW_DISPATCH_INPUT_CHARACTERS} aggregate characters"
            ),
        }
    }
}

impl Error for GithubWorkflowDispatchInputsError {}

/// Bounded input properties from a provider-verified manual-dispatch event.
///
/// Construction validates only the provider payload's canonical shape and
/// resource bounds. The compiler subsequently validates these values against
/// the exact source contract before exposing an `inputs` context. Callers must
/// construct this type only from integrity-verified provider evidence.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct GithubWorkflowDispatchInputs {
    values: BTreeMap<WorkflowInputKey, GithubWorkflowDispatchInputValue>,
}

impl GithubWorkflowDispatchInputs {
    /// Creates bounded, deterministically ordered provider input evidence.
    ///
    /// # Errors
    ///
    /// Returns [`GithubWorkflowDispatchInputsError`] for invalid or duplicate
    /// identifiers, too many inputs, or an excessive aggregate character count.
    pub fn try_new<K, V, I>(inputs: I) -> Result<Self, GithubWorkflowDispatchInputsError>
    where
        K: Into<String>,
        V: Into<GithubWorkflowDispatchInputValue>,
        I: IntoIterator<Item = (K, V)>,
    {
        let mut values = BTreeMap::new();
        let mut characters = 0_usize;
        for (key, value) in inputs {
            if values.len() == MAX_GITHUB_WORKFLOW_DISPATCH_INPUTS {
                return Err(GithubWorkflowDispatchInputsError::TooManyInputs);
            }
            let key = WorkflowInputKey::new(key.into())
                .map_err(|_| GithubWorkflowDispatchInputsError::InvalidInputKey)?;
            let value = value.into();
            characters = characters
                .checked_add(key.as_str().chars().count())
                .and_then(|count| count.checked_add(value.character_count()))
                .filter(|count| *count <= MAX_GITHUB_WORKFLOW_DISPATCH_INPUT_CHARACTERS)
                .ok_or(GithubWorkflowDispatchInputsError::PayloadTooLarge)?;
            if values.insert(key, value).is_some() {
                return Err(GithubWorkflowDispatchInputsError::DuplicateInputKey);
            }
        }
        Ok(Self { values })
    }

    /// Returns the verified raw values in deterministic input-key order.
    #[must_use]
    pub const fn values(&self) -> &BTreeMap<WorkflowInputKey, GithubWorkflowDispatchInputValue> {
        &self.values
    }

    /// Returns whether the provider payload supplied no input properties.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl GithubWorkflowDispatchInputValue {
    /// Returns the provider-native Boolean value, when this value is Boolean.
    #[must_use]
    pub const fn as_boolean(&self) -> Option<bool> {
        match self {
            Self::Boolean(value) => Some(*value),
            Self::String(_) => None,
        }
    }

    /// Returns the provider-native string value, when this value is textual.
    #[must_use]
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            Self::Boolean(_) => None,
        }
    }

    fn character_count(&self) -> usize {
        match self {
            Self::Boolean(value) => {
                if *value {
                    "true".len()
                } else {
                    "false".len()
                }
            }
            Self::String(value) => value.chars().count(),
        }
    }
}

impl fmt::Debug for GithubWorkflowDispatchInputs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubWorkflowDispatchInputs")
            .field("input_count", &self.values.len())
            .finish_non_exhaustive()
    }
}
