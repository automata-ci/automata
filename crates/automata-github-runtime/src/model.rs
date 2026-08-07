use std::fmt;

use crate::CommandScopeIdError;

const MAX_SCOPE_ID_BYTES: usize = 512;

/// One well-known per-step command file.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CommandFileKind {
    Environment,
    Output,
    Path,
    State,
    StepSummary,
}

impl CommandFileKind {
    /// Exact environment variable used by GitHub actions for this file.
    #[must_use]
    pub const fn environment_variable(self) -> &'static str {
        match self {
            Self::Environment => "GITHUB_ENV",
            Self::Output => "GITHUB_OUTPUT",
            Self::Path => "GITHUB_PATH",
            Self::State => "GITHUB_STATE",
            Self::StepSummary => "GITHUB_STEP_SUMMARY",
        }
    }
}

/// Selects the reviewed runner's platform-specific env-file line reader.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CommandFilePlatform {
    /// Linux and macOS split on LF and retain a preceding CR.
    Unix,
    /// Windows recognizes CRLF as one newline and also accepts bare LF.
    Windows,
}

#[derive(Clone, Default, Eq, PartialEq)]
pub(crate) struct SensitiveText(String);

impl SensitiveText {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for SensitiveText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveText")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// One name/value command parsed from `GITHUB_ENV`, `GITHUB_OUTPUT`, or
/// `GITHUB_STATE`.
#[derive(Clone, Eq, PartialEq)]
pub struct NameValueCommand {
    pub(crate) name: String,
    pub(crate) value: SensitiveText,
}

impl NameValueCommand {
    pub(crate) fn from_parts(name: String, value: String) -> Self {
        Self {
            name,
            value: SensitiveText::new(value),
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns command data to an execution adapter. `Debug` output remains
    /// redacted; callers must treat this value as potentially secret.
    #[must_use]
    pub fn value(&self) -> &str {
        self.value.as_str()
    }
}

impl fmt::Debug for NameValueCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NameValueCommand")
            .field("name", &self.name)
            .field("value", &self.value)
            .finish()
    }
}

macro_rules! name_value_file {
    ($name:ident) => {
        #[derive(Clone, Debug, Default, Eq, PartialEq)]
        pub struct $name {
            pub(crate) commands: Vec<NameValueCommand>,
        }

        impl $name {
            #[must_use]
            pub fn commands(&self) -> &[NameValueCommand] {
                &self.commands
            }

            #[must_use]
            pub fn is_empty(&self) -> bool {
                self.commands.is_empty()
            }
        }
    };
}

name_value_file!(EnvironmentCommandFile);
name_value_file!(OutputCommandFile);
name_value_file!(StateCommandFile);

/// Ordered non-empty entries from `GITHUB_PATH`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PathCommandFile {
    pub(crate) paths: Vec<SensitiveText>,
}

impl PathCommandFile {
    #[must_use]
    pub fn paths(&self) -> impl ExactSizeIterator<Item = &str> {
        self.paths.iter().map(SensitiveText::as_str)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

/// Validated Markdown from `GITHUB_STEP_SUMMARY`.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct StepSummaryCommandFile {
    pub(crate) markdown: SensitiveText,
}

impl StepSummaryCommandFile {
    #[must_use]
    pub fn markdown(&self) -> &str {
        self.markdown.as_str()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.markdown.as_str().is_empty()
    }
}

impl fmt::Debug for StepSummaryCommandFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StepSummaryCommandFile")
            .field("markdown", &self.markdown)
            .finish()
    }
}

/// Typed result from one command-file decode operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedCommandFile {
    Environment(EnvironmentCommandFile),
    Output(OutputCommandFile),
    Path(PathCommandFile),
    State(StateCommandFile),
    StepSummary(StepSummaryCommandFile),
}

/// All file-command mutations produced by one completed step.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompletedStepCommands {
    pub(crate) environment: EnvironmentCommandFile,
    pub(crate) output: OutputCommandFile,
    pub(crate) path: PathCommandFile,
    pub(crate) state: StateCommandFile,
    pub(crate) summary: StepSummaryCommandFile,
}

impl CompletedStepCommands {
    #[must_use]
    pub const fn new(
        environment: EnvironmentCommandFile,
        output: OutputCommandFile,
        path: PathCommandFile,
        state: StateCommandFile,
        summary: StepSummaryCommandFile,
    ) -> Self {
        Self {
            environment,
            output,
            path,
            state,
            summary,
        }
    }

    /// Merges deprecated stdout mutations into the corresponding command-file
    /// channels. This is pure and preserves observation order within each
    /// channel.
    #[must_use]
    pub fn with_legacy_mutations(mut self, mutations: &[LegacyStepMutation]) -> Self {
        for mutation in mutations {
            match mutation {
                LegacyStepMutation::Environment(command) => {
                    self.environment.commands.push(command.clone());
                }
                LegacyStepMutation::Output(command) => {
                    self.output.commands.push(command.clone());
                }
                LegacyStepMutation::State(command) => {
                    self.state.commands.push(command.clone());
                }
                LegacyStepMutation::Path(path) => self.path.paths.push(path.0.clone()),
            }
        }
        self
    }

    #[must_use]
    pub const fn environment(&self) -> &EnvironmentCommandFile {
        &self.environment
    }

    #[must_use]
    pub const fn output(&self) -> &OutputCommandFile {
        &self.output
    }

    #[must_use]
    pub const fn path(&self) -> &PathCommandFile {
        &self.path
    }

    #[must_use]
    pub const fn state(&self) -> &StateCommandFile {
        &self.state
    }

    #[must_use]
    pub const fn summary(&self) -> &StepSummaryCommandFile {
        &self.summary
    }
}

/// A validated workflow step context name.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct StepId(String);

impl StepId {
    /// Creates a durable step identifier.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, whitespace-containing, or control-containing
    /// identifiers.
    pub fn new(value: impl Into<String>) -> Result<Self, CommandScopeIdError> {
        validated_scope_id(value.into()).map(Self)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated identity shared by an action's main and post phases.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ActionInvocationId(String);

impl ActionInvocationId {
    /// Creates a durable action-invocation identifier.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, whitespace-containing, or control-containing
    /// identifiers.
    pub fn new(value: impl Into<String>) -> Result<Self, CommandScopeIdError> {
        validated_scope_id(value.into()).map(Self)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validated_scope_id(value: String) -> Result<String, CommandScopeIdError> {
    if value.is_empty()
        || value.len() > MAX_SCOPE_ID_BYTES
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(CommandScopeIdError);
    }
    Ok(value)
}

/// Temporal role of the completed step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StepPhase {
    Run,
    ActionMain(ActionInvocationId),
    ActionPost(ActionInvocationId),
}

/// Exact scope used when committing a completed step's mutations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepScope {
    step_id: StepId,
    phase: StepPhase,
}

impl StepScope {
    #[must_use]
    pub const fn new(step_id: StepId, phase: StepPhase) -> Self {
        Self { step_id, phase }
    }

    #[must_use]
    pub const fn step_id(&self) -> &StepId {
        &self.step_id
    }

    #[must_use]
    pub const fn phase(&self) -> &StepPhase {
        &self.phase
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StepOutputState {
    pub(crate) step_id: StepId,
    pub(crate) values: Vec<NameValueCommand>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActionState {
    pub(crate) invocation_id: ActionInvocationId,
    pub(crate) values: Vec<NameValueCommand>,
}

/// Snapshot of file-command state visible before the next step begins.
#[derive(Clone, Eq, PartialEq)]
pub struct JobCommandState {
    pub(crate) platform: CommandFilePlatform,
    pub(crate) environment: Vec<NameValueCommand>,
    pub(crate) prepend_path: Vec<SensitiveText>,
    pub(crate) outputs: Vec<StepOutputState>,
    pub(crate) action_states: Vec<ActionState>,
}

impl JobCommandState {
    #[must_use]
    pub const fn new(platform: CommandFilePlatform) -> Self {
        Self {
            platform,
            environment: Vec::new(),
            prepend_path: Vec::new(),
            outputs: Vec::new(),
            action_states: Vec::new(),
        }
    }

    #[must_use]
    pub const fn platform(&self) -> CommandFilePlatform {
        self.platform
    }

    /// Job-level environment visible to the next step. Values may contain
    /// secrets and have redacted `Debug` output.
    #[must_use]
    pub fn environment(&self) -> &[NameValueCommand] {
        &self.environment
    }

    /// PATH entries in actual prepend order (newest command first).
    pub fn prepend_path(&self) -> impl ExactSizeIterator<Item = &str> {
        self.prepend_path.iter().rev().map(SensitiveText::as_str)
    }

    /// Outputs published by one prior step.
    #[must_use]
    pub fn outputs(&self, step_id: &StepId) -> Option<&[NameValueCommand]> {
        self.outputs
            .iter()
            .find(|entry| entry.step_id == *step_id)
            .map(|entry| entry.values.as_slice())
    }

    /// `STATE_*` variables visible only to the paired post action.
    #[must_use]
    pub fn post_action_environment(
        &self,
        invocation_id: &ActionInvocationId,
    ) -> Vec<NameValueCommand> {
        self.action_states
            .iter()
            .find(|entry| entry.invocation_id == *invocation_id)
            .map_or_else(Vec::new, |entry| {
                entry
                    .values
                    .iter()
                    .map(|value| {
                        NameValueCommand::from_parts(
                            format!("STATE_{}", value.name()),
                            value.value().to_owned(),
                        )
                    })
                    .collect()
            })
    }
}

impl fmt::Debug for JobCommandState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobCommandState")
            .field("platform", &self.platform)
            .field("environment_entries", &self.environment.len())
            .field("path_entries", &self.prepend_path.len())
            .field("output_steps", &self.outputs.len())
            .field("action_states", &self.action_states.len())
            .finish()
    }
}

/// Non-fatal compatibility decision made while applying a completed step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseApplicationNotice {
    BlockedNodeOptions,
    StateIgnoredForRunStep,
}

/// Atomic result of applying one completed step.
#[derive(Clone, Eq, PartialEq)]
pub struct PhaseApplication {
    pub(crate) next_state: JobCommandState,
    pub(crate) summary: StepSummaryCommandFile,
    pub(crate) notices: Vec<PhaseApplicationNotice>,
}

impl PhaseApplication {
    #[must_use]
    pub const fn next_state(&self) -> &JobCommandState {
        &self.next_state
    }

    #[must_use]
    pub fn into_next_state(self) -> JobCommandState {
        self.next_state
    }

    #[must_use]
    pub const fn summary(&self) -> &StepSummaryCommandFile {
        &self.summary
    }

    #[must_use]
    pub fn notices(&self) -> &[PhaseApplicationNotice] {
        &self.notices
    }
}

impl fmt::Debug for PhaseApplication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PhaseApplication")
            .field("next_state", &self.next_state)
            .field("summary", &self.summary)
            .field("notices", &self.notices)
            .finish()
    }
}

/// A captured non-command output line. Its `Debug` implementation never emits
/// line contents.
#[derive(Clone, Eq, PartialEq)]
pub struct OutputLine(SensitiveText);

impl OutputLine {
    pub(crate) fn new(value: String) -> Self {
        Self(SensitiveText::new(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for OutputLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("OutputLine").field(&self.0).finish()
    }
}

/// One secret masker registration. The raw value is never included in Debug
/// output or protocol errors.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretMask(SensitiveText);

impl SecretMask {
    pub(crate) fn new(value: String) -> Self {
        Self(SensitiveText::new(value))
    }

    /// Exposes the value only for transfer to a secret-mask adapter.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretMask {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretMask")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Full and per-line masks produced by one `add-mask` command.
#[derive(Clone, Eq, PartialEq)]
pub struct MaskRegistration {
    masks: Vec<SecretMask>,
}

impl MaskRegistration {
    pub(crate) fn new(masks: Vec<SecretMask>) -> Self {
        Self { masks }
    }

    #[must_use]
    pub fn masks(&self) -> &[SecretMask] {
        &self.masks
    }
}

impl fmt::Debug for MaskRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaskRegistration")
            .field("mask_count", &self.masks.len())
            .finish_non_exhaustive()
    }
}

/// Side effect of entering command-suppression mode.
#[derive(Clone, Eq, PartialEq)]
pub struct StopCommands {
    token_mask: Option<SecretMask>,
}

impl StopCommands {
    pub(crate) const fn new(token_mask: Option<SecretMask>) -> Self {
        Self { token_mask }
    }

    /// Upstream masks stop tokens longer than six characters for the remainder
    /// of the job.
    #[must_use]
    pub const fn token_mask(&self) -> Option<&SecretMask> {
        self.token_mask.as_ref()
    }
}

impl fmt::Debug for StopCommands {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StopCommands")
            .field("token_masked", &self.token_mask.is_some())
            .finish_non_exhaustive()
    }
}

macro_rules! sensitive_message {
    ($name:ident, $accessor:ident) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name(SensitiveText);

        impl $name {
            pub(crate) fn new(value: String) -> Self {
                Self(SensitiveText::new(value))
            }

            #[must_use]
            pub fn $accessor(&self) -> &str {
                self.0.as_str()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }
    };
}

sensitive_message!(DebugMessage, message);
sensitive_message!(GroupTitle, title);

/// Annotation severity from an `error`, `warning`, or `notice` command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnotationLevel {
    Error,
    Warning,
    Notice,
}

/// One normalized annotation property. Property values are treated as
/// potentially sensitive in Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct AnnotationProperty {
    pub(crate) name: String,
    pub(crate) value: SensitiveText,
}

impl AnnotationProperty {
    pub(crate) fn new(name: String, value: String) -> Self {
        Self {
            name,
            value: SensitiveText::new(value),
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn value(&self) -> &str {
        self.value.as_str()
    }
}

impl fmt::Debug for AnnotationProperty {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnnotationProperty")
            .field("name", &self.name)
            .field("value", &self.value)
            .finish()
    }
}

/// Typed annotation command after upstream-compatible location normalization.
#[derive(Clone, Eq, PartialEq)]
pub struct Annotation {
    pub(crate) level: AnnotationLevel,
    pub(crate) message: SensitiveText,
    pub(crate) properties: Vec<AnnotationProperty>,
}

impl Annotation {
    #[must_use]
    pub const fn level(&self) -> AnnotationLevel {
        self.level
    }

    #[must_use]
    pub fn message(&self) -> &str {
        self.message.as_str()
    }

    #[must_use]
    pub fn properties(&self) -> &[AnnotationProperty] {
        &self.properties
    }

    #[must_use]
    pub fn property(&self, name: &str) -> Option<&str> {
        self.properties
            .iter()
            .find(|property| property.name.eq_ignore_ascii_case(name))
            .map(AnnotationProperty::value)
    }
}

impl fmt::Debug for Annotation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Annotation")
            .field("level", &self.level)
            .field("message", &self.message)
            .field("properties", &self.properties)
            .finish()
    }
}

/// A problem-matcher file reference. Resolving it beneath the workspace is an
/// execution-adapter responsibility.
#[derive(Clone, Eq, PartialEq)]
pub struct MatcherFile(SensitiveText);

impl MatcherFile {
    pub(crate) fn new(value: String) -> Self {
        Self(SensitiveText::new(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for MatcherFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("MatcherFile").field(&self.0).finish()
    }
}

/// A problem-matcher owner selected for removal.
#[derive(Clone, Eq, PartialEq)]
pub struct MatcherOwner(SensitiveText);

impl MatcherOwner {
    pub(crate) fn new(value: String) -> Self {
        Self(SensitiveText::new(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for MatcherOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("MatcherOwner")
            .field(&self.0)
            .finish()
    }
}

/// One legacy PATH update, wrapped so its contents remain Debug-redacted.
#[derive(Clone, Eq, PartialEq)]
pub struct PathEntry(SensitiveText);

impl PathEntry {
    pub(crate) fn new(value: String) -> Self {
        Self(SensitiveText::new(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for PathEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("PathEntry").field(&self.0).finish()
    }
}

/// Pure problem-matcher declaration. Loading and validating JSON belongs to a
/// workspace-confined matcher adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MatcherCommand {
    Add(MatcherFile),
    RemoveOwner(MatcherOwner),
    RemoveFile(MatcherFile),
}

impl MatcherCommand {
    #[must_use]
    pub fn file(&self) -> Option<&str> {
        match self {
            Self::Add(file) | Self::RemoveFile(file) => Some(file.as_str()),
            Self::RemoveOwner(_) => None,
        }
    }

    #[must_use]
    pub fn owner(&self) -> Option<&str> {
        match self {
            Self::RemoveOwner(owner) => Some(owner.as_str()),
            Self::Add(_) | Self::RemoveFile(_) => None,
        }
    }
}

/// Deprecated stdout mutation retained for compatibility with older actions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyStepMutation {
    Environment(NameValueCommand),
    Output(NameValueCommand),
    State(NameValueCommand),
    Path(PathEntry),
}

/// Non-fatal command behavior that a runner adapter should surface as a
/// warning or compatibility diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandNotice {
    EmptyMaskIgnored,
    MissingMatcherPath,
    InvalidMatcherRemoval,
    BlockedNodeOptions,
}

/// Immediate typed effect of one recognized stdout/stderr workflow command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowCommandEvent {
    RegisterMask(MaskRegistration),
    Annotation(Annotation),
    BeginGroup(GroupTitle),
    EndGroup,
    Debug(DebugMessage),
    StopCommands(StopCommands),
    ResumeCommands,
    Matcher(MatcherCommand),
    LegacyMutation(LegacyStepMutation),
    EchoChanged(bool),
    Notice(CommandNotice),
}

/// Result of scanning one captured stdout/stderr line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowLine {
    Output(OutputLine),
    Command(WorkflowCommandEvent),
}

/// Opt-in compatibility switches matching upstream feature gates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkflowCommandPolicy {
    allow_insecure_legacy_commands: bool,
    enhanced_annotations: bool,
}

impl WorkflowCommandPolicy {
    #[must_use]
    pub const fn new(allow_insecure_legacy_commands: bool, enhanced_annotations: bool) -> Self {
        Self {
            allow_insecure_legacy_commands,
            enhanced_annotations,
        }
    }

    #[must_use]
    pub const fn allow_insecure_legacy_commands(self) -> bool {
        self.allow_insecure_legacy_commands
    }

    #[must_use]
    pub const fn enhanced_annotations(self) -> bool {
        self.enhanced_annotations
    }
}

impl Default for WorkflowCommandPolicy {
    fn default() -> Self {
        Self {
            allow_insecure_legacy_commands: false,
            enhanced_annotations: true,
        }
    }
}
