use std::fmt;

use automata_ci_action_actions::JavascriptRuntime;
use automata_ci_core::{ActionReference, ExpressionProgram, Sha256Digest, StepId};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const MAX_PREPARED_ARCHIVE_BYTES: usize = 16_777_216;
const MAX_PREPARED_INPUTS: usize = 1_024;
const MAX_PREPARED_OUTPUTS: usize = 1_024;
const MAX_COMPOSITE_STEPS: usize = 1_024;
const MAX_COMPOSITE_VALUES: usize = 1_024;
const MAX_ACTION_PATH_BYTES: usize = 4_096;
const MAX_INPUT_REQUIRED_BYTES: usize = 64;
const MAX_INPUT_DEPRECATION_BYTES: usize = 4_096;

/// One already-compiled action input default.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedValue {
    /// Exact literal metadata text.
    Literal(String),
    /// Runner-phase expression compiled with the pinned GitHub dialect.
    Expression(ExpressionProgram),
    /// A scalar containing alternating literal and evaluated expression parts.
    Template(Vec<PreparedValueSegment>),
}

/// One ordered part of a prepared scalar template.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedValueSegment {
    /// Exact literal text between expression delimiters.
    Literal(String),
    /// One runner-phase expression compiled with the pinned GitHub dialect.
    Expression(ExpressionProgram),
}

/// One metadata-declared action input and its compatibility metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedInput {
    name: String,
    default: Option<PreparedValue>,
    required: Option<String>,
    deprecation_message: Option<String>,
}

/// One metadata-declared action output and its optional value expression.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedOutput {
    name: String,
    value: Option<PreparedValue>,
}

impl PreparedOutput {
    /// Creates an action output declaration.
    ///
    /// # Errors
    ///
    /// Rejects empty, control-containing, or oversized output names.
    pub fn new(
        name: impl Into<String>,
        value: Option<PreparedValue>,
    ) -> Result<Self, PreparedActionError> {
        let name = name.into();
        if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            return Err(PreparedActionError::InvalidOutput);
        }
        Ok(Self { name, value })
    }

    /// Returns the metadata output name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the prepared output value, when declared.
    #[must_use]
    pub const fn value(&self) -> Option<&PreparedValue> {
        self.value.as_ref()
    }
}

/// Prepared literal or late-bound `continue-on-error` value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedBoolean {
    /// Exact metadata boolean.
    Literal(bool),
    /// Runner-phase expression whose result uses GitHub truthiness.
    Expression(ExpressionProgram),
}

/// Common metadata retained for one composite child step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedCompositeStepMetadata {
    name: Option<PreparedValue>,
    id: Option<StepId>,
    condition: ExpressionProgram,
    continue_on_error: PreparedBoolean,
}

impl PreparedCompositeStepMetadata {
    /// Creates common composite-step metadata.
    #[must_use]
    pub const fn new(
        name: Option<PreparedValue>,
        id: Option<StepId>,
        condition: ExpressionProgram,
        continue_on_error: PreparedBoolean,
    ) -> Self {
        Self {
            name,
            id,
            condition,
            continue_on_error,
        }
    }

    /// Returns the prepared display name.
    #[must_use]
    pub const fn name(&self) -> Option<&PreparedValue> {
        self.name.as_ref()
    }

    /// Returns the explicit step context ID.
    #[must_use]
    pub const fn id(&self) -> Option<&StepId> {
        self.id.as_ref()
    }

    /// Returns the compiled step condition, including GitHub's status guard.
    #[must_use]
    pub const fn condition(&self) -> &ExpressionProgram {
        &self.condition
    }

    /// Returns the prepared continuation policy.
    #[must_use]
    pub const fn continue_on_error(&self) -> &PreparedBoolean {
        &self.continue_on_error
    }
}

/// One environment or action-input entry retained in source order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedKeyValue {
    name: String,
    value: PreparedValue,
}

impl PreparedKeyValue {
    /// Creates a prepared named value.
    ///
    /// # Errors
    ///
    /// Rejects empty, control-containing, or oversized names.
    pub fn new(name: impl Into<String>, value: PreparedValue) -> Result<Self, PreparedActionError> {
        let name = name.into();
        if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            return Err(PreparedActionError::InvalidCompositeStep);
        }
        Ok(Self { name, value })
    }

    /// Returns the exact metadata key.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the prepared scalar value.
    #[must_use]
    pub const fn value(&self) -> &PreparedValue {
        &self.value
    }
}

/// Prepared composite `run` child step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedCompositeRunStep {
    metadata: PreparedCompositeStepMetadata,
    command: PreparedValue,
    shell: PreparedValue,
    environment: Vec<PreparedKeyValue>,
    working_directory: Option<PreparedValue>,
}

impl PreparedCompositeRunStep {
    /// Creates a composite run step from validated metadata.
    ///
    /// # Errors
    ///
    /// Rejects an excessive environment size.
    pub fn new(
        metadata: PreparedCompositeStepMetadata,
        command: PreparedValue,
        shell: PreparedValue,
        environment: Vec<PreparedKeyValue>,
        working_directory: Option<PreparedValue>,
    ) -> Result<Self, PreparedActionError> {
        validate_values(&environment)?;
        Ok(Self {
            metadata,
            command,
            shell,
            environment,
            working_directory,
        })
    }

    /// Returns common child-step metadata.
    #[must_use]
    pub const fn metadata(&self) -> &PreparedCompositeStepMetadata {
        &self.metadata
    }

    /// Returns the prepared command template.
    #[must_use]
    pub const fn command(&self) -> &PreparedValue {
        &self.command
    }

    /// Returns the prepared shell template.
    #[must_use]
    pub const fn shell(&self) -> &PreparedValue {
        &self.shell
    }

    /// Returns child-step environment entries in source order.
    #[must_use]
    pub fn environment(&self) -> &[PreparedKeyValue] {
        &self.environment
    }

    /// Returns the prepared working directory, when declared.
    #[must_use]
    pub const fn working_directory(&self) -> Option<&PreparedValue> {
        self.working_directory.as_ref()
    }
}

/// Prepared composite nested-action child step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedCompositeUsesStep {
    metadata: PreparedCompositeStepMetadata,
    reference: ActionReference,
    inputs: Vec<PreparedKeyValue>,
    environment: Vec<PreparedKeyValue>,
}

impl PreparedCompositeUsesStep {
    /// Creates a nested action step from validated metadata.
    ///
    /// # Errors
    ///
    /// Rejects excessive or duplicate input/environment keys.
    pub fn new(
        metadata: PreparedCompositeStepMetadata,
        reference: ActionReference,
        inputs: Vec<PreparedKeyValue>,
        environment: Vec<PreparedKeyValue>,
    ) -> Result<Self, PreparedActionError> {
        validate_values(&inputs)?;
        validate_values(&environment)?;
        Ok(Self {
            metadata,
            reference,
            inputs,
            environment,
        })
    }

    /// Returns common child-step metadata.
    #[must_use]
    pub const fn metadata(&self) -> &PreparedCompositeStepMetadata {
        &self.metadata
    }

    /// Returns the statically resolved nested action reference.
    #[must_use]
    pub const fn reference(&self) -> &ActionReference {
        &self.reference
    }

    /// Returns nested action inputs in source order.
    #[must_use]
    pub fn inputs(&self) -> &[PreparedKeyValue] {
        &self.inputs
    }

    /// Returns child-step environment entries in source order.
    #[must_use]
    pub fn environment(&self) -> &[PreparedKeyValue] {
        &self.environment
    }
}

/// One prepared composite child-step kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedCompositeStep {
    /// A shell command child step.
    Run(PreparedCompositeRunStep),
    /// A nested local, repository, or container action child step.
    Uses(PreparedCompositeUsesStep),
}

/// Validated, compiled composite-action execution plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedCompositeAction {
    steps: Vec<PreparedCompositeStep>,
}

impl PreparedCompositeAction {
    /// Creates a composite execution plan.
    ///
    /// # Errors
    ///
    /// Rejects empty or excessive step lists and duplicate explicit IDs.
    pub fn new(steps: Vec<PreparedCompositeStep>) -> Result<Self, PreparedActionError> {
        if steps.is_empty() {
            return Err(PreparedActionError::TooManyCompositeSteps);
        }
        validate_prepared_composite_step_count(steps.len())?;
        let mut ids = std::collections::BTreeSet::new();
        for step in &steps {
            let metadata = match step {
                PreparedCompositeStep::Run(step) => step.metadata(),
                PreparedCompositeStep::Uses(step) => step.metadata(),
            };
            if let Some(id) = metadata.id()
                && !ids.insert(id.as_str().to_ascii_lowercase())
            {
                return Err(PreparedActionError::DuplicateCompositeStepId);
            }
        }
        Ok(Self { steps })
    }

    /// Returns child steps in execution order.
    #[must_use]
    pub fn steps(&self) -> &[PreparedCompositeStep] {
        &self.steps
    }
}

/// Prepared action execution kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedActionExecution {
    /// Metadata-driven JavaScript execution.
    Javascript(Box<PreparedJavascriptAction>),
    /// Ordered composite child-step execution.
    Composite(PreparedCompositeAction),
}

/// Source-independent prepared action metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedActionDefinition {
    inputs: Vec<PreparedInput>,
    outputs: Vec<PreparedOutput>,
    execution: PreparedActionExecution,
}

impl PreparedActionDefinition {
    /// Creates a prepared action definition.
    ///
    /// # Errors
    ///
    /// Rejects excessive or duplicate input/output declarations.
    pub fn new(
        inputs: Vec<PreparedInput>,
        outputs: Vec<PreparedOutput>,
        execution: PreparedActionExecution,
    ) -> Result<Self, PreparedActionError> {
        validate_input_declarations(&inputs)?;
        validate_output_declarations(&outputs)?;
        Ok(Self {
            inputs,
            outputs,
            execution,
        })
    }

    /// Returns metadata input declarations in source order.
    #[must_use]
    pub fn inputs(&self) -> &[PreparedInput] {
        &self.inputs
    }

    /// Returns metadata output declarations in source order.
    #[must_use]
    pub fn outputs(&self) -> &[PreparedOutput] {
        &self.outputs
    }

    /// Returns the prepared execution kind.
    #[must_use]
    pub const fn execution(&self) -> &PreparedActionExecution {
        &self.execution
    }

    /// Returns JavaScript execution metadata when applicable.
    #[must_use]
    pub fn javascript(&self) -> Option<&PreparedJavascriptAction> {
        match &self.execution {
            PreparedActionExecution::Javascript(value) => Some(value.as_ref()),
            PreparedActionExecution::Composite(_) => None,
        }
    }

    /// Returns composite execution metadata when applicable.
    #[must_use]
    pub const fn composite(&self) -> Option<&PreparedCompositeAction> {
        match &self.execution {
            PreparedActionExecution::Composite(value) => Some(value),
            PreparedActionExecution::Javascript(_) => None,
        }
    }
}

/// Prepared metadata for a checked-out action contained below the job workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedLocalAction {
    path: String,
    definition: PreparedActionDefinition,
}

impl PreparedLocalAction {
    /// Creates a checked-out local action contract.
    ///
    /// # Errors
    ///
    /// Rejects a non-canonical path or traversal outside the workspace.
    pub fn new(
        path: impl Into<String>,
        definition: PreparedActionDefinition,
    ) -> Result<Self, PreparedActionError> {
        let path = validate_local_action_path(path.into())?;
        Ok(Self { path, definition })
    }

    /// Returns the canonical `./`-prefixed workspace-relative action path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the source-independent compiled metadata.
    #[must_use]
    pub const fn definition(&self) -> &PreparedActionDefinition {
        &self.definition
    }
}

impl PreparedInput {
    /// Creates an action input declaration.
    ///
    /// # Errors
    ///
    /// Rejects empty, control-containing, or oversized input names.
    pub fn new(
        name: impl Into<String>,
        default: Option<PreparedValue>,
    ) -> Result<Self, PreparedActionError> {
        Self::with_metadata(name, default, None, None)
    }

    /// Creates an action input declaration with the exact ignored `required`
    /// marker and an optional safe deprecation message.
    ///
    /// GitHub records `required` but does not reject a missing action input;
    /// callers must not reinterpret the retained scalar as validation policy.
    /// Deprecation messages are static metadata, never expression-evaluated.
    ///
    /// # Errors
    ///
    /// Rejects invalid names and control-containing or oversized compatibility
    /// metadata that could forge runner diagnostics.
    pub fn with_metadata(
        name: impl Into<String>,
        default: Option<PreparedValue>,
        required: Option<String>,
        deprecation_message: Option<&str>,
    ) -> Result<Self, PreparedActionError> {
        let name = name.into();
        if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            return Err(PreparedActionError::InvalidInput);
        }
        if required.as_ref().is_some_and(|value| {
            value.len() > MAX_INPUT_REQUIRED_BYTES || value.chars().any(char::is_control)
        }) {
            return Err(PreparedActionError::InvalidInput);
        }
        let deprecation_message = deprecation_message
            .map(normalize_deprecation_message)
            .transpose()?;
        Ok(Self {
            name,
            default,
            required,
            deprecation_message,
        })
    }

    /// Returns the metadata input name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the compiled default, when declared.
    #[must_use]
    pub const fn default(&self) -> Option<&PreparedValue> {
        self.default.as_ref()
    }

    /// Returns the exact metadata `required` scalar, when declared.
    ///
    /// This marker is informational. In particular, `true` does not make the
    /// executor invent missing-input validation that GitHub does not perform.
    #[must_use]
    pub fn required(&self) -> Option<&str> {
        self.required.as_deref()
    }

    /// Returns the bounded static deprecation message, when declared.
    #[must_use]
    pub fn deprecation_message(&self) -> Option<&str> {
        self.deprecation_message.as_deref()
    }
}

fn normalize_deprecation_message(value: &str) -> Result<String, PreparedActionError> {
    if value.len() > MAX_INPUT_DEPRECATION_BYTES {
        return Err(PreparedActionError::InvalidInput);
    }
    let mut normalized = String::with_capacity(value.len());
    let mut pending_space = false;
    for character in value.chars() {
        if character.is_control() && !character.is_whitespace() {
            return Err(PreparedActionError::InvalidInput);
        }
        if character.is_whitespace() {
            pending_space = !normalized.is_empty();
        } else {
            if pending_space {
                normalized.push(' ');
                pending_space = false;
            }
            normalized.push(character);
        }
    }
    Ok(normalized)
}

/// Validated metadata-driven JavaScript execution plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedJavascriptAction {
    runtime: JavascriptRuntime,
    main: String,
    pre: Option<String>,
    pre_condition: ExpressionProgram,
    post: Option<String>,
    post_condition: ExpressionProgram,
}

impl PreparedJavascriptAction {
    /// Creates a JavaScript action from already-decoded metadata.
    ///
    /// # Errors
    ///
    /// Rejects any path that is absolute, aliased, backslash-containing, or
    /// otherwise unsafe beneath the immutable action root.
    pub fn new(
        runtime: JavascriptRuntime,
        main: impl Into<String>,
        pre: Option<String>,
        pre_condition: ExpressionProgram,
        post: Option<String>,
        post_condition: ExpressionProgram,
    ) -> Result<Self, PreparedActionError> {
        let main = validate_relative_path(main.into())?;
        let pre = pre.map(validate_relative_path).transpose()?;
        let post = post.map(validate_relative_path).transpose()?;
        Ok(Self {
            runtime,
            main,
            pre,
            pre_condition,
            post,
            post_condition,
        })
    }

    /// Returns the metadata-selected Node runtime.
    #[must_use]
    pub const fn runtime(&self) -> JavascriptRuntime {
        self.runtime
    }

    /// Returns the canonical action-relative main entry path.
    #[must_use]
    pub fn main(&self) -> &str {
        &self.main
    }

    /// Returns the canonical action-relative pre entry path.
    #[must_use]
    pub fn pre(&self) -> Option<&str> {
        self.pre.as_deref()
    }

    /// Returns the compiled pre condition.
    #[must_use]
    pub const fn pre_condition(&self) -> &ExpressionProgram {
        &self.pre_condition
    }

    /// Returns the canonical action-relative post entry path.
    #[must_use]
    pub fn post(&self) -> Option<&str> {
        self.post.as_deref()
    }

    /// Returns the compiled post condition.
    #[must_use]
    pub const fn post_condition(&self) -> &ExpressionProgram {
        &self.post_condition
    }
}

/// Immutable action archive and its validated executable contract.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedAction {
    archive_digest: Sha256Digest,
    archive: Bytes,
    subpath: String,
    definition: PreparedActionDefinition,
}

impl PreparedAction {
    /// Creates an immutable repository-action plan with its complete metadata.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized archive, a digest mismatch, or an unsafe
    /// action subpath.
    pub fn with_definition(
        archive_digest: Sha256Digest,
        archive: Bytes,
        subpath: impl Into<String>,
        definition: PreparedActionDefinition,
    ) -> Result<Self, PreparedActionError> {
        if archive.is_empty() {
            return Err(PreparedActionError::ArchiveSize);
        }
        validate_prepared_archive_bytes(archive.len())?;
        let computed = Sha256Digest::from_bytes(Sha256::digest(&archive).into());
        if computed != archive_digest {
            return Err(PreparedActionError::DigestMismatch);
        }
        let subpath = subpath.into();
        if !subpath.is_empty() {
            validate_relative_path(subpath.clone())?;
        }
        Ok(Self {
            archive_digest,
            archive,
            subpath,
            definition,
        })
    }

    /// Returns the verified archive digest.
    #[must_use]
    pub const fn archive_digest(&self) -> Sha256Digest {
        self.archive_digest
    }

    /// Returns verified compressed archive bytes. Callers must retain the copy bound.
    #[must_use]
    pub const fn archive(&self) -> &Bytes {
        &self.archive
    }

    /// Returns the action directory beneath the single repository archive root.
    #[must_use]
    pub fn subpath(&self) -> &str {
        &self.subpath
    }

    /// Returns metadata-declared inputs in source order.
    #[must_use]
    pub fn inputs(&self) -> &[PreparedInput] {
        self.definition.inputs()
    }

    /// Returns the complete compiled action definition.
    #[must_use]
    pub const fn definition(&self) -> &PreparedActionDefinition {
        &self.definition
    }

    /// Returns JavaScript execution metadata when applicable.
    #[must_use]
    pub fn javascript(&self) -> Option<&PreparedJavascriptAction> {
        self.definition.javascript()
    }

    /// Returns composite execution metadata when applicable.
    #[must_use]
    pub const fn composite(&self) -> Option<&PreparedCompositeAction> {
        self.definition.composite()
    }
}

impl fmt::Debug for PreparedAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAction")
            .field("archive_digest", &self.archive_digest)
            .field("archive_bytes", &self.archive.len())
            .field("subpath", &self.subpath)
            .field("definition", &self.definition)
            .finish()
    }
}

/// Invalid prepared action returned across a trust boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PreparedActionError {
    /// Archive is empty or exceeds one bounded endpoint copy.
    #[error("prepared action archive has an invalid size")]
    ArchiveSize,
    /// Declared archive identity did not match the exact returned bytes.
    #[error("prepared action archive digest does not match its content")]
    DigestMismatch,
    /// An action-relative path escapes or exceeds its root.
    #[error("prepared action contains an unsafe path")]
    UnsafePath,
    /// An action input name is invalid.
    #[error("prepared action contains an invalid input")]
    InvalidInput,
    /// Input count exceeds the configured hard ceiling.
    #[error("prepared action contains too many inputs")]
    TooManyInputs,
    /// Input names collide under GitHub's case-insensitive lookup.
    #[error("prepared action contains duplicate inputs")]
    DuplicateInput,
    /// An action output name is invalid.
    #[error("prepared action contains an invalid output")]
    InvalidOutput,
    /// Output names collide under GitHub's case-insensitive lookup.
    #[error("prepared action contains duplicate outputs")]
    DuplicateOutput,
    /// Output count exceeds the configured hard ceiling.
    #[error("prepared action contains too many outputs")]
    TooManyOutputs,
    /// Composite child-step metadata is invalid.
    #[error("prepared action contains an invalid composite step")]
    InvalidCompositeStep,
    /// Composite child-step count is empty or exceeds the hard ceiling.
    #[error("prepared action has an invalid composite step count")]
    TooManyCompositeSteps,
    /// Explicit composite step IDs collide ignoring case.
    #[error("prepared action contains duplicate composite step IDs")]
    DuplicateCompositeStepId,
}

const fn validate_prepared_archive_bytes(observed: usize) -> Result<(), PreparedActionError> {
    if observed > MAX_PREPARED_ARCHIVE_BYTES {
        return Err(PreparedActionError::ArchiveSize); // stable archive-byte-limit reason
    }
    Ok(())
}

const fn validate_prepared_input_count(observed: usize) -> Result<(), PreparedActionError> {
    if observed > MAX_PREPARED_INPUTS {
        return Err(PreparedActionError::TooManyInputs); // stable input-count-limit reason
    }
    Ok(())
}

const fn validate_prepared_output_count(observed: usize) -> Result<(), PreparedActionError> {
    if observed > MAX_PREPARED_OUTPUTS {
        return Err(PreparedActionError::TooManyOutputs); // stable output-count-limit reason
    }
    Ok(())
}

const fn validate_prepared_composite_step_count(
    observed: usize,
) -> Result<(), PreparedActionError> {
    if observed > MAX_COMPOSITE_STEPS {
        return Err(PreparedActionError::TooManyCompositeSteps); // stable composite-step-limit reason
    }
    Ok(())
}

const fn validate_prepared_composite_value_count(
    observed: usize,
) -> Result<(), PreparedActionError> {
    if observed > MAX_COMPOSITE_VALUES {
        return Err(PreparedActionError::InvalidCompositeStep); // stable composite-value-limit reason
    }
    Ok(())
}

const fn validate_prepared_action_path_bytes(observed: usize) -> Result<(), PreparedActionError> {
    if observed > MAX_ACTION_PATH_BYTES {
        return Err(PreparedActionError::UnsafePath); // stable action-path-limit reason
    }
    Ok(())
}

fn validate_input_declarations(values: &[PreparedInput]) -> Result<(), PreparedActionError> {
    validate_prepared_input_count(values.len())?;
    let mut names = std::collections::BTreeSet::new();
    if values
        .iter()
        .any(|value| !names.insert(value.name().to_ascii_lowercase()))
    {
        return Err(PreparedActionError::DuplicateInput);
    }
    Ok(())
}

fn validate_output_declarations(values: &[PreparedOutput]) -> Result<(), PreparedActionError> {
    validate_prepared_output_count(values.len())?;
    let mut names = std::collections::BTreeSet::new();
    if values
        .iter()
        .any(|value| !names.insert(value.name().to_ascii_lowercase()))
    {
        return Err(PreparedActionError::DuplicateOutput);
    }
    Ok(())
}

fn validate_values(values: &[PreparedKeyValue]) -> Result<(), PreparedActionError> {
    validate_prepared_composite_value_count(values.len())?;
    let mut names = std::collections::BTreeSet::new();
    if values
        .iter()
        .any(|value| !names.insert(value.name().to_ascii_lowercase()))
    {
        return Err(PreparedActionError::InvalidCompositeStep);
    }
    Ok(())
}

fn validate_local_action_path(value: String) -> Result<String, PreparedActionError> {
    validate_prepared_action_path_bytes(value.len())?;
    let relative = value
        .strip_prefix("./")
        .ok_or(PreparedActionError::UnsafePath)?;
    let valid = !relative.is_empty()
        && !value.ends_with('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && relative
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."));
    valid
        .then_some(value)
        .ok_or(PreparedActionError::UnsafePath)
}

fn validate_relative_path(value: String) -> Result<String, PreparedActionError> {
    validate_prepared_action_path_bytes(value.len())?;
    let valid = !value.is_empty()
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."));
    valid
        .then_some(value)
        .ok_or(PreparedActionError::UnsafePath)
}

#[cfg(test)]
mod limit_contract_tests {
    use super::*;

    #[test]
    fn prepared_archive_byte_limit_has_exact_boundaries() {
        assert!(validate_prepared_archive_bytes(MAX_PREPARED_ARCHIVE_BYTES - 1).is_ok());
        assert!(validate_prepared_archive_bytes(MAX_PREPARED_ARCHIVE_BYTES).is_ok());
        assert_eq!(
            validate_prepared_archive_bytes(MAX_PREPARED_ARCHIVE_BYTES + 1),
            Err(PreparedActionError::ArchiveSize)
        );
    }

    #[test]
    fn prepared_input_count_limit_has_exact_boundaries() {
        assert!(validate_prepared_input_count(MAX_PREPARED_INPUTS - 1).is_ok());
        assert!(validate_prepared_input_count(MAX_PREPARED_INPUTS).is_ok());
        assert_eq!(
            validate_prepared_input_count(MAX_PREPARED_INPUTS + 1),
            Err(PreparedActionError::TooManyInputs)
        );
    }

    #[test]
    fn prepared_output_count_limit_has_exact_boundaries() {
        assert!(validate_prepared_output_count(MAX_PREPARED_OUTPUTS - 1).is_ok());
        assert!(validate_prepared_output_count(MAX_PREPARED_OUTPUTS).is_ok());
        assert_eq!(
            validate_prepared_output_count(MAX_PREPARED_OUTPUTS + 1),
            Err(PreparedActionError::TooManyOutputs)
        );
    }

    #[test]
    fn prepared_composite_step_limit_has_exact_boundaries() {
        assert!(validate_prepared_composite_step_count(MAX_COMPOSITE_STEPS - 1).is_ok());
        assert!(validate_prepared_composite_step_count(MAX_COMPOSITE_STEPS).is_ok());
        assert_eq!(
            validate_prepared_composite_step_count(MAX_COMPOSITE_STEPS + 1),
            Err(PreparedActionError::TooManyCompositeSteps)
        );
    }

    #[test]
    fn prepared_composite_value_limit_has_exact_boundaries() {
        assert!(validate_prepared_composite_value_count(MAX_COMPOSITE_VALUES - 1).is_ok());
        assert!(validate_prepared_composite_value_count(MAX_COMPOSITE_VALUES).is_ok());
        assert_eq!(
            validate_prepared_composite_value_count(MAX_COMPOSITE_VALUES + 1),
            Err(PreparedActionError::InvalidCompositeStep)
        );
    }

    #[test]
    fn prepared_action_path_byte_limit_has_exact_boundaries() {
        assert!(validate_prepared_action_path_bytes(MAX_ACTION_PATH_BYTES - 1).is_ok());
        assert!(validate_prepared_action_path_bytes(MAX_ACTION_PATH_BYTES).is_ok());
        assert_eq!(
            validate_prepared_action_path_bytes(MAX_ACTION_PATH_BYTES + 1),
            Err(PreparedActionError::UnsafePath)
        );
    }
}
