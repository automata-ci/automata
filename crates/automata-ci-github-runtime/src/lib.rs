//! GitHub Actions step-to-runner command protocol compatibility.
//!
//! This crate is deliberately pure: it parses already-captured command files
//! and output lines, then applies their effects to an immutable job snapshot.
//! Process, filesystem, masking, annotation, and problem-matcher adapters live
//! outside this compatibility boundary.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod artifact;
mod environment;
mod error;
mod file_command;
mod limits;
mod model;
mod phase;
mod workflow_command;

pub use environment::{
    EnvironmentMutationBlockReason, ReservedEnvironmentNamespace, classify_environment_mutation,
};
pub use error::{
    ArtifactListEncodingError, ArtifactSubjectError, CommandFileError, CommandScopeIdError,
    PhaseApplicationError, WorkflowCommandError,
};
pub use file_command::{CommandFileDecoder, GithubCommandFileDecoder};
pub use limits::{
    CommandFileLimits, CommandFileLimitsError, PhaseApplicationLimits, PhaseApplicationLimitsError,
    WorkflowCommandLimits, WorkflowCommandLimitsBuilder, WorkflowCommandLimitsError,
};
pub use model::{
    ARTIFACT_LIST_SCHEMA_VERSION, ActionInvocationId, Annotation, AnnotationLevel,
    AnnotationProperty, ArtifactDeclaration, ArtifactDeclarationCommandFile,
    ArtifactFileDeclaration, ArtifactSubject, ArtifactSubjectCommandFile, ArtifactSubjectKind,
    CommandFileKind, CommandFilePlatform, CommandNotice, CompletedStepCommands, DebugMessage,
    EnvironmentCommandFile, GroupTitle, JobCommandState, LegacyStepMutation,
    MAX_ARTIFACT_DECLARATION_FILE_BYTES, MAX_ARTIFACT_LIST_BYTES, MAX_ARTIFACT_SUBJECTS,
    MaskRegistration, MatcherCommand, MatcherFile, MatcherOwner, NameValueCommand,
    OutputCommandFile, OutputLine, ParsedCommandFile, PathCommandFile, PathEntry, PhaseApplication,
    PhaseApplicationNotice, SecretMask, StateCommandFile, StepId, StepPhase, StepScope,
    StepSummaryCommandFile, StopCommands, WorkflowCommandEvent, WorkflowCommandPolicy,
    WorkflowLine,
};
pub use phase::{CompletedStepApplicator, GithubCompletedStepApplicator};
pub use workflow_command::{GithubWorkflowCommandSession, WorkflowCommandProcessor};

/// Reviewed upstream runner release.
pub const GITHUB_RUNTIME_PROTOCOL_BASELINE: &str = "actions/runner@v2.336.0";

/// Immutable commit behind [`GITHUB_RUNTIME_PROTOCOL_BASELINE`].
pub const GITHUB_RUNTIME_PROTOCOL_BASELINE_COMMIT: &str =
    "98aabcd429c4e8402406c56ce2d26387fed3b9ce";

/// Separately reviewed upstream commit for the artifacts environment-file delta.
///
/// This does not advance [`GITHUB_RUNTIME_PROTOCOL_BASELINE`].
pub const GITHUB_RUNTIME_ARTIFACTS_DELTA_COMMIT: &str = "35e45850b519df66a669e2c91e0917804a33d0c7";

/// Complete upstream review set for the artifacts environment-file delta.
pub const GITHUB_RUNTIME_ARTIFACTS_DELTA_UPSTREAM_SOURCES: &[&str] = &[
    "src/Runner.Common/Constants.cs",
    "src/Runner.Common/ExtensionManager.cs",
    "src/Runner.Worker/ArtifactSubject.cs",
    "src/Runner.Worker/ArtifactsListFileCommand.cs",
    "src/Runner.Worker/CreateArtifactsFileCommand.cs",
    "src/Runner.Worker/ExecutionContext.cs",
    "src/Runner.Worker/FileCommandManager.cs",
    "src/Runner.Worker/GitHubContext.cs",
    "src/Runner.Worker/GlobalContext.cs",
    "src/Test/L0/Worker/ArtifactsListFileCommandL0.cs",
    "src/Test/L0/Worker/CreateArtifactsFileCommandL0.cs",
    "src/Test/L0/Worker/FileCommandManagerL0.cs",
];
