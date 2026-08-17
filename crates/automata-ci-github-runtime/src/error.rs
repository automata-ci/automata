use thiserror::Error;

use crate::CommandFileKind;

/// A step or action-invocation identifier is not safe for durable scoping.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("command scope identifier is empty, too long, or contains unsupported characters")]
pub struct CommandScopeIdError;

/// An artifact subject name or canonical digest is invalid.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("artifact subject is invalid")]
pub struct ArtifactSubjectError;

/// A deterministic artifact-list payload could not be encoded.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("artifact subject list could not be encoded")]
pub struct ArtifactListEncodingError;

/// A command file is malformed or exceeds the configured protocol envelope.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CommandFileError {
    /// A command file is larger than its configured byte ceiling.
    #[error("{kind:?} command file exceeds its {maximum}-byte limit ({received} bytes)")]
    FileTooLarge {
        /// Channel whose captured file exceeded the limit.
        kind: CommandFileKind,
        /// Configured maximum number of bytes.
        maximum: usize,
        /// Number of bytes in the rejected capture.
        received: usize,
    },
    /// A step summary is larger than its separately configured byte ceiling.
    #[error("step-summary command file exceeds its {maximum}-byte limit ({received} bytes)")]
    SummaryTooLarge {
        /// Configured maximum number of summary bytes.
        maximum: usize,
        /// Number of bytes in the rejected summary.
        received: usize,
    },
    /// A command file cannot be decoded as UTF-8 after an optional BOM.
    #[error("{kind:?} command file is not valid UTF-8")]
    NonUtf8 {
        /// Channel containing invalid UTF-8.
        kind: CommandFileKind,
    },
    /// One logical line is larger than the configured byte ceiling.
    #[error("{kind:?} command file contains a line longer than {maximum} bytes")]
    LineTooLong {
        /// Channel containing the oversized line.
        kind: CommandFileKind,
        /// Configured maximum number of bytes per line.
        maximum: usize,
    },
    /// A command file contains more logical records than permitted.
    #[error("{kind:?} command file exceeds its {maximum}-record limit")]
    TooManyRecords {
        /// Channel containing too many records.
        kind: CommandFileKind,
        /// Configured maximum record count.
        maximum: usize,
    },
    /// A non-summary channel contains a record outside its accepted grammar.
    #[error("{kind:?} command file contains a malformed record")]
    MalformedRecord {
        /// Channel containing the malformed record.
        kind: CommandFileKind,
    },
    /// A name/value record has an empty name.
    #[error("{kind:?} command file contains an empty command name")]
    EmptyName {
        /// Channel containing the empty name.
        kind: CommandFileKind,
    },
    /// A command name or heredoc delimiter exceeds the configured ceiling.
    #[error("{kind:?} command file contains a command name longer than {maximum} bytes")]
    NameTooLong {
        /// Channel containing the oversized name or delimiter.
        kind: CommandFileKind,
        /// Configured maximum number of name bytes.
        maximum: usize,
    },
    /// A command value or path entry exceeds the configured ceiling.
    #[error("{kind:?} command file contains a value longer than {maximum} bytes")]
    ValueTooLong {
        /// Channel containing the oversized value.
        kind: CommandFileKind,
        /// Configured maximum number of value bytes.
        maximum: usize,
    },
    /// A heredoc declaration has no delimiter after `<<`.
    #[error("{kind:?} heredoc has an empty delimiter")]
    EmptyDelimiter {
        /// Channel containing the invalid heredoc declaration.
        kind: CommandFileKind,
    },
    /// A heredoc reaches end of file without its declared delimiter.
    #[error("{kind:?} heredoc delimiter was not found")]
    MissingDelimiter {
        /// Channel containing the unterminated heredoc.
        kind: CommandFileKind,
    },
    /// A heredoc value's final line lacks a newline before the delimiter.
    #[error("{kind:?} heredoc value ends without a newline before its delimiter")]
    HeredocValueMissingNewline {
        /// Channel containing the invalid heredoc value.
        kind: CommandFileKind,
    },
    /// One artifact declaration violates the reviewed upstream grammar.
    #[error("Artifacts command file contains an invalid declaration on line {line}")]
    InvalidArtifactDeclaration {
        /// One-based line number without the rejected declaration text.
        line: usize,
    },
}

/// A workflow command line is malformed, unsafe, or exceeds session limits.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkflowCommandError {
    /// Captured line bytes accumulated beyond the session ceiling.
    #[error("workflow-command stream exceeds its {maximum}-byte aggregate limit")]
    StreamTooLarge {
        /// Configured maximum aggregate byte count.
        maximum: usize,
    },
    /// The session observed more lines than permitted.
    #[error("workflow-command stream exceeds its {maximum}-line aggregate limit")]
    TooManyLines {
        /// Configured maximum line count.
        maximum: usize,
    },
    /// One captured stdout or stderr line exceeds the byte ceiling.
    #[error("workflow-command line exceeds its {maximum}-byte limit")]
    LineTooLong {
        /// Configured maximum number of bytes per line.
        maximum: usize,
    },
    /// A captured line is not valid UTF-8.
    #[error("workflow-command line is not valid UTF-8")]
    NonUtf8,
    /// The session recognized more commands than permitted.
    #[error("workflow-command stream exceeds its {maximum}-command limit")]
    TooManyCommands {
        /// Configured maximum recognized-command count.
        maximum: usize,
    },
    /// One recognized command contains too many raw properties.
    #[error("workflow command exceeds its {maximum}-property limit")]
    TooManyProperties {
        /// Configured maximum property count per command.
        maximum: usize,
    },
    /// A command or property name exceeds the byte ceiling.
    #[error("workflow command name exceeds its {maximum}-byte limit")]
    NameTooLong {
        /// Configured maximum number of name bytes.
        maximum: usize,
    },
    /// Decoded command data or a decoded property value is too large.
    #[error("workflow command data exceeds its {maximum}-byte limit")]
    DataTooLong {
        /// Configured maximum number of decoded data bytes.
        maximum: usize,
    },
    /// A recognized command omits a required non-empty property.
    #[error("workflow command is missing a required property")]
    MissingRequiredProperty,
    /// A `stop-commands` token is unsafe or collides with a command name.
    #[error("stop-commands token is empty, reserved, malformed, or too long")]
    InvalidStopToken,
    /// Secret registrations accumulated beyond the session ceiling.
    #[error("workflow-command stream exceeds its {maximum}-mask limit")]
    TooManyMasks {
        /// Configured maximum number of registered masks.
        maximum: usize,
    },
    /// An `echo` command contains a value other than `on` or `off`.
    #[error("echo workflow command accepts only 'on' or 'off'")]
    InvalidEchoValue,
}

/// Completed-step effects cannot be applied without violating job-state bounds.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PhaseApplicationError {
    /// The derived job environment contains too many names.
    #[error("job command state exceeds its {maximum}-environment-entry limit")]
    TooManyEnvironmentEntries {
        /// Configured maximum environment-entry count.
        maximum: usize,
    },
    /// The derived job PATH contains too many prepended entries.
    #[error("job command state exceeds its {maximum}-PATH-entry limit")]
    TooManyPathEntries {
        /// Configured maximum prepended-PATH-entry count.
        maximum: usize,
    },
    /// The derived output map contains too many step scopes.
    #[error("job command state exceeds its {maximum}-step-output limit")]
    TooManySteps {
        /// Configured maximum number of steps with outputs.
        maximum: usize,
    },
    /// The derived action-state map contains too many invocation scopes.
    #[error("job command state exceeds its {maximum}-action-state limit")]
    TooManyActionStates {
        /// Configured maximum number of action-state scopes.
        maximum: usize,
    },
    /// A declaration reused a subject name with a different digest.
    #[error("artifact subject conflicts with an earlier declaration")]
    ArtifactConflict,
    /// The derived artifact-subject set exceeds the upstream job cap.
    #[error("job command state exceeds its {maximum}-artifact-subject limit")]
    TooManyArtifactSubjects {
        /// Fixed maximum number of distinct job-scoped subjects.
        maximum: usize,
    },
    /// The generated read-only artifact list exceeds Automata's copy boundary.
    #[error("artifact subject list exceeds its {maximum}-byte transport limit")]
    ArtifactListTooLarge {
        /// Maximum encoded JSON bytes supported by the sandbox copy boundary.
        maximum: usize,
    },
    /// The sum of durable names, values, paths, and scope IDs is too large.
    #[error("job command state exceeds its {maximum}-byte aggregate limit")]
    AggregateTooLarge {
        /// Configured maximum aggregate byte count.
        maximum: usize,
    },
}
