use thiserror::Error;

use crate::CommandFileKind;

/// A step or action-invocation identifier is not safe for durable scoping.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("command scope identifier is empty, too long, or contains unsupported characters")]
pub struct CommandScopeIdError;

/// A command file is malformed or exceeds the configured protocol envelope.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CommandFileError {
    #[error("{kind:?} command file exceeds its {maximum}-byte limit ({received} bytes)")]
    FileTooLarge {
        kind: CommandFileKind,
        maximum: usize,
        received: usize,
    },
    #[error("step-summary command file exceeds its {maximum}-byte limit ({received} bytes)")]
    SummaryTooLarge { maximum: usize, received: usize },
    #[error("{kind:?} command file is not valid UTF-8")]
    NonUtf8 { kind: CommandFileKind },
    #[error("{kind:?} command file contains a line longer than {maximum} bytes")]
    LineTooLong {
        kind: CommandFileKind,
        maximum: usize,
    },
    #[error("{kind:?} command file exceeds its {maximum}-record limit")]
    TooManyRecords {
        kind: CommandFileKind,
        maximum: usize,
    },
    #[error("{kind:?} command file contains a malformed record")]
    MalformedRecord { kind: CommandFileKind },
    #[error("{kind:?} command file contains an empty command name")]
    EmptyName { kind: CommandFileKind },
    #[error("{kind:?} command file contains a command name longer than {maximum} bytes")]
    NameTooLong {
        kind: CommandFileKind,
        maximum: usize,
    },
    #[error("{kind:?} command file contains a value longer than {maximum} bytes")]
    ValueTooLong {
        kind: CommandFileKind,
        maximum: usize,
    },
    #[error("{kind:?} heredoc has an empty delimiter")]
    EmptyDelimiter { kind: CommandFileKind },
    #[error("{kind:?} heredoc delimiter was not found")]
    MissingDelimiter { kind: CommandFileKind },
    #[error("{kind:?} heredoc value ends without a newline before its delimiter")]
    HeredocValueMissingNewline { kind: CommandFileKind },
}

/// A workflow command line is malformed, unsafe, or exceeds session limits.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkflowCommandError {
    #[error("workflow-command stream exceeds its {maximum}-byte aggregate limit")]
    StreamTooLarge { maximum: usize },
    #[error("workflow-command stream exceeds its {maximum}-line aggregate limit")]
    TooManyLines { maximum: usize },
    #[error("workflow-command line exceeds its {maximum}-byte limit")]
    LineTooLong { maximum: usize },
    #[error("workflow-command line is not valid UTF-8")]
    NonUtf8,
    #[error("workflow-command stream exceeds its {maximum}-command limit")]
    TooManyCommands { maximum: usize },
    #[error("workflow command exceeds its {maximum}-property limit")]
    TooManyProperties { maximum: usize },
    #[error("workflow command name exceeds its {maximum}-byte limit")]
    NameTooLong { maximum: usize },
    #[error("workflow command data exceeds its {maximum}-byte limit")]
    DataTooLong { maximum: usize },
    #[error("workflow command is missing a required property")]
    MissingRequiredProperty,
    #[error("insecure legacy workflow command is disabled")]
    LegacyCommandDisabled,
    #[error("stop-commands token is empty, reserved, malformed, or too long")]
    InvalidStopToken,
    #[error("workflow-command stream exceeds its {maximum}-mask limit")]
    TooManyMasks { maximum: usize },
    #[error("echo workflow command accepts only 'on' or 'off'")]
    InvalidEchoValue,
}

/// Completed-step effects cannot be applied without violating job-state bounds.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PhaseApplicationError {
    #[error("job command state exceeds its {maximum}-environment-entry limit")]
    TooManyEnvironmentEntries { maximum: usize },
    #[error("job command state exceeds its {maximum}-PATH-entry limit")]
    TooManyPathEntries { maximum: usize },
    #[error("job command state exceeds its {maximum}-step-output limit")]
    TooManySteps { maximum: usize },
    #[error("job command state exceeds its {maximum}-action-state limit")]
    TooManyActionStates { maximum: usize },
    #[error("job command state exceeds its {maximum}-byte aggregate limit")]
    AggregateTooLarge { maximum: usize },
}
