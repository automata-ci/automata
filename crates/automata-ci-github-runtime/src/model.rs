use std::fmt;

use serde::Serialize;

use crate::environment::ReservedEnvironmentNamespace;
use crate::{ArtifactListEncodingError, ArtifactSubjectError, CommandScopeIdError};

const MAX_SCOPE_ID_BYTES: usize = 512;

/// Exact schema of the read-only `GITHUB_ARTIFACTS_LIST` JSON payload.
pub const ARTIFACT_LIST_SCHEMA_VERSION: u8 = 1;

/// Fixed upstream ceiling for one `GITHUB_ARTIFACTS` declaration file.
pub const MAX_ARTIFACT_DECLARATION_FILE_BYTES: usize = 1_048_576;

/// Fixed upstream ceiling for distinct artifact subjects accumulated by one job.
pub const MAX_ARTIFACT_SUBJECTS: usize = 500;

/// Automata transport ceiling for the generated read-only artifact list.
pub const MAX_ARTIFACT_LIST_BYTES: usize = 16_777_216;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArtifactRuntimeLimitRejection {
    ScopeId,
    DeclarationFile,
    ArtifactList,
}

pub(crate) const fn command_scope_id_byte_rejection(
    observed: usize,
) -> Option<ArtifactRuntimeLimitRejection> {
    if observed > MAX_SCOPE_ID_BYTES {
        return Some(ArtifactRuntimeLimitRejection::ScopeId);
    }
    None
}
pub(crate) const fn artifact_declaration_file_byte_rejection(
    observed: usize,
) -> Option<ArtifactRuntimeLimitRejection> {
    if observed > MAX_ARTIFACT_DECLARATION_FILE_BYTES {
        return Some(ArtifactRuntimeLimitRejection::DeclarationFile);
    }
    None
}
pub(crate) const fn artifact_list_byte_rejection(
    observed: usize,
) -> Option<ArtifactRuntimeLimitRejection> {
    if observed > MAX_ARTIFACT_LIST_BYTES {
        return Some(ArtifactRuntimeLimitRejection::ArtifactList);
    }
    None
}

/// One well-known per-step command file.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CommandFileKind {
    /// Job environment mutations from `GITHUB_ENV`.
    Environment,
    /// Step output publications from `GITHUB_OUTPUT`.
    Output,
    /// Job PATH prepends from `GITHUB_PATH`.
    Path,
    /// Action invocation state from `GITHUB_STATE`.
    State,
    /// Markdown attachment content from `GITHUB_STEP_SUMMARY`.
    StepSummary,
    /// Artifact-subject declarations from `GITHUB_ARTIFACTS`.
    Artifacts,
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
            Self::Artifacts => "GITHUB_ARTIFACTS",
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

/// Artifact subject representation exposed to later steps.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactSubjectKind {
    /// A regular file hashed by the runner inside the job sandbox.
    File,
    /// An OCI reference carrying a caller-declared digest.
    Oci,
}

/// One validated, job-scoped artifact subject.
#[derive(Clone, Eq, PartialEq)]
pub struct ArtifactSubject {
    name: String,
    digest: String,
    kind: ArtifactSubjectKind,
}

impl ArtifactSubject {
    /// Creates one subject with a canonical lower-case SHA digest.
    ///
    /// # Errors
    ///
    /// Rejects an empty name or a digest outside canonical
    /// `sha256`, `sha384`, or `sha512` syntax and length.
    pub fn new(
        name: impl Into<String>,
        digest: impl Into<String>,
        kind: ArtifactSubjectKind,
    ) -> Result<Self, ArtifactSubjectError> {
        let name = name.into();
        let digest = digest.into();
        if name.is_empty() || !canonical_artifact_digest(&digest) {
            return Err(ArtifactSubjectError);
        }
        Ok(Self { name, digest, kind })
    }

    /// Returns the exact subject name or OCI reference.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the canonical algorithm-prefixed digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Returns whether the subject is a regular file or OCI reference.
    #[must_use]
    pub const fn kind(&self) -> ArtifactSubjectKind {
        self.kind
    }
}

impl fmt::Debug for ArtifactSubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactSubject")
            .field("kind", &self.kind)
            .field("name_bytes", &self.name.len())
            .field("digest_bytes", &self.digest.len())
            .finish_non_exhaustive()
    }
}

fn canonical_artifact_digest(digest: &str) -> bool {
    let Some((algorithm, hexadecimal)) = digest.split_once(':') else {
        return false;
    };
    let expected = match algorithm {
        "sha256" => 64,
        "sha384" => 96,
        "sha512" => 128,
        _ => return false,
    };
    hexadecimal.len() == expected
        && hexadecimal
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// One unresolved declaration parsed from `GITHUB_ARTIFACTS`.
#[derive(Clone, Eq, PartialEq)]
pub enum ArtifactDeclaration {
    /// A path that must be resolved and SHA-256 hashed in the job sandbox.
    File(ArtifactFileDeclaration),
    /// A complete OCI subject whose digest was validated during parsing.
    Oci(ArtifactSubject),
}

impl fmt::Debug for ArtifactDeclaration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(file) => formatter.debug_tuple("File").field(file).finish(),
            Self::Oci(subject) => formatter.debug_tuple("Oci").field(subject).finish(),
        }
    }
}

/// One workspace-relative or absolute file path awaiting sandbox hashing.
#[derive(Clone, Eq, PartialEq)]
pub struct ArtifactFileDeclaration {
    path: SensitiveText,
}

impl ArtifactFileDeclaration {
    pub(crate) fn new(path: String) -> Self {
        Self {
            path: SensitiveText::new(path),
        }
    }

    /// Returns the declared path for the trusted execution adapter.
    #[must_use]
    pub fn path(&self) -> &str {
        self.path.as_str()
    }
}

impl fmt::Debug for ArtifactFileDeclaration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactFileDeclaration")
            .field("path", &self.path)
            .finish()
    }
}

/// Ordered unresolved declarations from one completed step.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ArtifactDeclarationCommandFile {
    pub(crate) declarations: Vec<ArtifactDeclaration>,
}

impl ArtifactDeclarationCommandFile {
    /// Returns declarations in file-observation order.
    #[must_use]
    pub fn declarations(&self) -> &[ArtifactDeclaration] {
        &self.declarations
    }

    /// Reports whether the file contained no effective declarations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.declarations.is_empty()
    }
}

impl fmt::Debug for ArtifactDeclarationCommandFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactDeclarationCommandFile")
            .field("declaration_count", &self.declarations.len())
            .finish_non_exhaustive()
    }
}

/// Fully resolved subjects ready for one atomic job-state application.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ArtifactSubjectCommandFile {
    subjects: Vec<ArtifactSubject>,
}

impl ArtifactSubjectCommandFile {
    /// Wraps subjects resolved by the trusted sandbox adapter.
    #[must_use]
    pub fn new(subjects: Vec<ArtifactSubject>) -> Self {
        Self { subjects }
    }

    /// Returns resolved subjects in declaration order.
    #[must_use]
    pub fn subjects(&self) -> &[ArtifactSubject] {
        &self.subjects
    }

    /// Reports whether this step resolved no subjects.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.subjects.is_empty()
    }
}

impl fmt::Debug for ArtifactSubjectCommandFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactSubjectCommandFile")
            .field("subject_count", &self.subjects.len())
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

    /// Returns the command name exactly as decoded from the command file.
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
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Default, Eq, PartialEq)]
        pub struct $name {
            pub(crate) commands: Vec<NameValueCommand>,
        }

        impl $name {
            /// Returns decoded mutations in file-observation order.
            #[must_use]
            pub fn commands(&self) -> &[NameValueCommand] {
                &self.commands
            }

            /// Reports whether the file produced no mutations.
            #[must_use]
            pub fn is_empty(&self) -> bool {
                self.commands.is_empty()
            }
        }
    };
}

name_value_file!(
    EnvironmentCommandFile,
    "Ordered environment mutations decoded from `GITHUB_ENV`."
);
name_value_file!(
    OutputCommandFile,
    "Ordered step outputs decoded from `GITHUB_OUTPUT`."
);
name_value_file!(
    StateCommandFile,
    "Ordered action state mutations decoded from `GITHUB_STATE`."
);

/// Ordered non-empty entries from `GITHUB_PATH`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PathCommandFile {
    pub(crate) paths: Vec<SensitiveText>,
}

impl PathCommandFile {
    /// Iterates non-empty PATH entries in command-file observation order.
    ///
    /// Entries may contain sensitive workspace information and remain redacted
    /// from this type's `Debug` output.
    #[must_use]
    pub fn paths(&self) -> impl ExactSizeIterator<Item = &str> {
        self.paths.iter().map(SensitiveText::as_str)
    }

    /// Reports whether the file produced no PATH entries.
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
    /// Returns the validated Markdown for transfer to a summary adapter.
    ///
    /// The content remains redacted from this type's `Debug` output.
    #[must_use]
    pub fn markdown(&self) -> &str {
        self.markdown.as_str()
    }

    /// Reports whether the decoded summary has no content.
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
    /// Decoded `GITHUB_ENV` mutations.
    Environment(EnvironmentCommandFile),
    /// Decoded `GITHUB_OUTPUT` publications.
    Output(OutputCommandFile),
    /// Decoded `GITHUB_PATH` entries.
    Path(PathCommandFile),
    /// Decoded `GITHUB_STATE` mutations.
    State(StateCommandFile),
    /// Decoded `GITHUB_STEP_SUMMARY` Markdown.
    StepSummary(StepSummaryCommandFile),
    /// Decoded unresolved `GITHUB_ARTIFACTS` declarations.
    Artifacts(ArtifactDeclarationCommandFile),
}

/// All file-command mutations produced by one completed step.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompletedStepCommands {
    pub(crate) environment: EnvironmentCommandFile,
    pub(crate) output: OutputCommandFile,
    pub(crate) path: PathCommandFile,
    pub(crate) state: StateCommandFile,
    pub(crate) summary: StepSummaryCommandFile,
    pub(crate) artifacts: ArtifactSubjectCommandFile,
}

impl CompletedStepCommands {
    /// Groups all five command-file channels captured for one completed step.
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
            artifacts: ArtifactSubjectCommandFile {
                subjects: Vec::new(),
            },
        }
    }

    /// Adds fully resolved artifact subjects for atomic phase application.
    #[must_use]
    pub fn with_artifacts(mut self, artifacts: ArtifactSubjectCommandFile) -> Self {
        self.artifacts = artifacts;
        self
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

    /// Returns decoded job-environment mutations.
    #[must_use]
    pub const fn environment(&self) -> &EnvironmentCommandFile {
        &self.environment
    }

    /// Returns decoded step-output publications.
    #[must_use]
    pub const fn output(&self) -> &OutputCommandFile {
        &self.output
    }

    /// Returns decoded job-PATH entries.
    #[must_use]
    pub const fn path(&self) -> &PathCommandFile {
        &self.path
    }

    /// Returns decoded action-invocation state mutations.
    #[must_use]
    pub const fn state(&self) -> &StateCommandFile {
        &self.state
    }

    /// Returns decoded step-summary Markdown.
    #[must_use]
    pub const fn summary(&self) -> &StepSummaryCommandFile {
        &self.summary
    }

    /// Returns fully resolved artifact subjects from this step.
    #[must_use]
    pub const fn artifacts(&self) -> &ArtifactSubjectCommandFile {
        &self.artifacts
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

    /// Returns the validated step context name.
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

    /// Returns the validated identity shared by the action phases.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validated_scope_id(value: String) -> Result<String, CommandScopeIdError> {
    if value.is_empty()
        || command_scope_id_byte_rejection(value.len()).is_some()
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
    /// A plain workflow `run` step, with no paired post-action state.
    Run,
    /// The pre phase of the identified action invocation.
    ActionPre(ActionInvocationId),
    /// The main phase of the identified action invocation.
    ActionMain(ActionInvocationId),
    /// The post phase paired with the identified action invocation.
    ActionPost(ActionInvocationId),
}

/// Exact scope used when committing a completed step's mutations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepScope {
    step_id: StepId,
    phase: StepPhase,
}

impl StepScope {
    /// Associates a workflow step identifier with its temporal phase.
    #[must_use]
    pub const fn new(step_id: StepId, phase: StepPhase) -> Self {
        Self { step_id, phase }
    }

    /// Returns the workflow step whose effects are being committed.
    #[must_use]
    pub const fn step_id(&self) -> &StepId {
        &self.step_id
    }

    /// Returns the run, action-pre, action-main, or action-post phase.
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
    pub(crate) artifact_subjects: Vec<ArtifactSubject>,
}

impl JobCommandState {
    /// Creates an empty job snapshot using the platform's name semantics.
    #[must_use]
    pub const fn new(platform: CommandFilePlatform) -> Self {
        Self {
            platform,
            environment: Vec::new(),
            prepend_path: Vec::new(),
            outputs: Vec::new(),
            action_states: Vec::new(),
            artifact_subjects: Vec::new(),
        }
    }

    /// Returns the platform governing environment-name comparisons.
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

    /// Returns job-scoped artifact subjects sorted by exact subject name.
    #[must_use]
    pub fn artifact_subjects(&self) -> &[ArtifactSubject] {
        &self.artifact_subjects
    }

    /// Encodes the deterministic read-only `GITHUB_ARTIFACTS_LIST` payload.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure if JSON serialization unexpectedly fails.
    pub fn artifact_list_json(&self) -> Result<Vec<u8>, ArtifactListEncodingError> {
        #[derive(Serialize)]
        struct Subject<'a> {
            name: &'a str,
            digest: &'a str,
            kind: ArtifactSubjectKind,
        }

        #[derive(Serialize)]
        struct ArtifactList<'a> {
            version: u8,
            subjects: Vec<Subject<'a>>,
        }

        let subjects = self
            .artifact_subjects
            .iter()
            .map(|subject| Subject {
                name: subject.name(),
                digest: subject.digest(),
                kind: subject.kind(),
            })
            .collect();
        serde_json::to_vec(&ArtifactList {
            version: ARTIFACT_LIST_SCHEMA_VERSION,
            subjects,
        })
        .map_err(|_| ArtifactListEncodingError)
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
            .field("artifact_subjects", &self.artifact_subjects.len())
            .finish()
    }
}

/// Non-fatal compatibility decision made while applying a completed step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseApplicationNotice {
    /// A `NODE_OPTIONS` environment mutation was intentionally ignored.
    BlockedNodeOptions,
    /// A mutation of a runner-owned default environment variable was ignored.
    BlockedReservedEnvironment(ReservedEnvironmentNamespace),
    /// `GITHUB_STATE` content was ignored because a plain run step has no post phase.
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
    /// Borrows the complete job state derived for subsequent steps.
    #[must_use]
    pub const fn next_state(&self) -> &JobCommandState {
        &self.next_state
    }

    /// Consumes the result and returns the complete derived job state.
    #[must_use]
    pub fn into_next_state(self) -> JobCommandState {
        self.next_state
    }

    /// Returns this step's summary attachment, which is not durable job state.
    #[must_use]
    pub const fn summary(&self) -> &StepSummaryCommandFile {
        &self.summary
    }

    /// Returns non-fatal compatibility decisions made during application.
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

    /// Returns the captured non-command line for the execution adapter.
    ///
    /// Captured output may contain secrets and is redacted from `Debug`.
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

    /// Returns all masks produced by the command in registration order.
    ///
    /// The first entry masks the full command value; subsequent entries mask
    /// its non-empty trimmed lines, matching the reviewed upstream runner.
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
    ($name:ident, $accessor:ident, $description:literal, $accessor_description:literal) => {
        #[doc = $description]
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name(SensitiveText);

        impl $name {
            pub(crate) fn new(value: String) -> Self {
                Self(SensitiveText::new(value))
            }

            #[doc = $accessor_description]
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

sensitive_message!(
    DebugMessage,
    message,
    "A message emitted by a recognized `debug` command.",
    "Returns the potentially sensitive debug message for a logging adapter."
);
sensitive_message!(
    GroupTitle,
    title,
    "A title emitted by a recognized `group` command.",
    "Returns the potentially sensitive title for a log-group adapter."
);

/// Annotation severity from an `error`, `warning`, or `notice` command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnotationLevel {
    /// A failing diagnostic produced by an `error` command.
    Error,
    /// A warning diagnostic produced by a `warning` command.
    Warning,
    /// An informational diagnostic produced by a `notice` command.
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

    /// Returns the property name after case-insensitive duplicate folding.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the potentially sensitive decoded property value.
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
    /// Returns the command's normalized severity.
    #[must_use]
    pub const fn level(&self) -> AnnotationLevel {
        self.level
    }

    /// Returns the potentially sensitive annotation message.
    #[must_use]
    pub fn message(&self) -> &str {
        self.message.as_str()
    }

    /// Returns normalized properties in their retained observation order.
    #[must_use]
    pub fn properties(&self) -> &[AnnotationProperty] {
        &self.properties
    }

    /// Finds a normalized property by an ASCII-case-insensitive name.
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

    /// Returns the untrusted file reference for a workspace-confined adapter.
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

    /// Returns the potentially sensitive matcher owner for the adapter.
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

    /// Returns the potentially sensitive path for a job-environment adapter.
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
    /// Load and register matchers from the referenced workspace file.
    Add(MatcherFile),
    /// Remove all registered matchers belonging to the specified owner.
    RemoveOwner(MatcherOwner),
    /// Remove matchers originating from the referenced workspace file.
    RemoveFile(MatcherFile),
}

impl MatcherCommand {
    /// Returns the file reference for file-based commands, if present.
    #[must_use]
    pub fn file(&self) -> Option<&str> {
        match self {
            Self::Add(file) | Self::RemoveFile(file) => Some(file.as_str()),
            Self::RemoveOwner(_) => None,
        }
    }

    /// Returns the owner for an owner-based removal, if present.
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
    /// Set or replace one job environment entry.
    Environment(NameValueCommand),
    /// Publish or replace one output for the current step.
    Output(NameValueCommand),
    /// Save or replace one value for the paired action post phase.
    State(NameValueCommand),
    /// Prepend one entry to the job PATH.
    Path(PathEntry),
}

/// Non-fatal command behavior that a runner adapter should surface as a
/// warning or compatibility diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandNotice {
    /// An `add-mask` command contained only whitespace and registered nothing.
    EmptyMaskIgnored,
    /// An `add-matcher` command did not supply a file reference.
    MissingMatcherPath,
    /// A `remove-matcher` command supplied both or neither removal selector.
    InvalidMatcherRemoval,
    /// A legacy attempt to set `NODE_OPTIONS` was intentionally ignored.
    BlockedNodeOptions,
}

/// Immediate typed effect of one recognized stdout/stderr workflow command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowCommandEvent {
    /// Register full-value and per-line secret masks before further logging.
    RegisterMask(MaskRegistration),
    /// Publish a normalized error, warning, or notice annotation.
    Annotation(Annotation),
    /// Begin a nested log group with the supplied title.
    BeginGroup(GroupTitle),
    /// End the current log group.
    EndGroup,
    /// Emit a debug-only message.
    Debug(DebugMessage),
    /// Suppress command recognition until the dynamic resume token appears.
    StopCommands(StopCommands),
    /// Resume normal command recognition.
    ResumeCommands,
    /// Add or remove one or more problem matchers.
    Matcher(MatcherCommand),
    /// Apply a recognized legacy environment, output, state, or PATH mutation.
    LegacyMutation(LegacyStepMutation),
    /// Change whether recognized command lines are echoed to the job log.
    EchoChanged(bool),
    /// Surface a non-fatal compatibility decision.
    Notice(CommandNotice),
}

/// Result of scanning one captured stdout/stderr line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowLine {
    /// A line that must be treated as ordinary captured process output.
    Output(OutputLine),
    /// A recognized command and its typed immediate effect.
    Command(WorkflowCommandEvent),
}

/// Opt-in compatibility switches matching upstream feature gates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkflowCommandPolicy {
    allow_insecure_legacy_commands: bool,
    enhanced_annotations: bool,
}

impl WorkflowCommandPolicy {
    /// Creates a compatibility policy for one command session.
    ///
    /// `allow_insecure_legacy_commands` controls only legacy environment and
    /// PATH mutation commands. `enhanced_annotations` controls recognition of
    /// the newer `notice` command.
    #[must_use]
    pub const fn new(allow_insecure_legacy_commands: bool, enhanced_annotations: bool) -> Self {
        Self {
            allow_insecure_legacy_commands,
            enhanced_annotations,
        }
    }

    /// Reports whether legacy `set-env` and `add-path` commands are accepted.
    #[must_use]
    pub const fn allow_insecure_legacy_commands(self) -> bool {
        self.allow_insecure_legacy_commands
    }

    /// Reports whether `notice` is recognized as an annotation command.
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

#[cfg(test)]
mod limit_contract_tests {
    use super::*;

    #[test]
    fn command_scope_id_byte_limit_has_exact_boundaries() {
        assert_eq!(
            command_scope_id_byte_rejection(MAX_SCOPE_ID_BYTES - 1),
            None
        );
        assert_eq!(command_scope_id_byte_rejection(MAX_SCOPE_ID_BYTES), None);
        assert_eq!(
            command_scope_id_byte_rejection(MAX_SCOPE_ID_BYTES + 1),
            Some(ArtifactRuntimeLimitRejection::ScopeId)
        );
    }
    #[test]
    fn artifact_declaration_file_byte_limit_has_exact_boundaries() {
        assert_eq!(
            artifact_declaration_file_byte_rejection(MAX_ARTIFACT_DECLARATION_FILE_BYTES - 1),
            None
        );
        assert_eq!(
            artifact_declaration_file_byte_rejection(MAX_ARTIFACT_DECLARATION_FILE_BYTES),
            None
        );
        assert_eq!(
            artifact_declaration_file_byte_rejection(MAX_ARTIFACT_DECLARATION_FILE_BYTES + 1),
            Some(ArtifactRuntimeLimitRejection::DeclarationFile)
        );
    }
    #[test]
    fn artifact_list_byte_limit_has_exact_boundaries() {
        assert_eq!(
            artifact_list_byte_rejection(MAX_ARTIFACT_LIST_BYTES - 1),
            None
        );
        assert_eq!(artifact_list_byte_rejection(MAX_ARTIFACT_LIST_BYTES), None);
        assert_eq!(
            artifact_list_byte_rejection(MAX_ARTIFACT_LIST_BYTES + 1),
            Some(ArtifactRuntimeLimitRejection::ArtifactList)
        );
    }
}
