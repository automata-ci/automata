#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! GitHub Actions compatible execution over provider-neutral whole-job sandboxes.
//!
//! The crate owns GitHub step sequencing and process contracts. Sandbox lifecycle,
//! immutable action resolution, credentials, secrets, expression contexts, runtime
//! tool paths, clocks, and operation identities remain explicit object-safe ports.

mod action;
mod adapter;
mod config;
mod content;
mod environment;
mod error;
mod executor;
mod output;
mod port;
mod prepared;
mod secret;

pub use action::{
    CheckedOutLocalActionPreparer, LocalActionDefinitionPaths, LocalActionPreparationRequest,
    ResolvedBundleActionPreparer,
};
pub use adapter::{ImmutableSandboxEnvironmentCatalog, StaticGithubToolchain};
pub use config::{GithubJobExecutorConfig, GithubJobExecutorConfigError};
pub use content::ImmutableJobContent;
pub use error::{
    ActionPreparationError, ActionPreparationErrorKind, ExecutorAdapterError, PortError,
    PortErrorKind,
};
pub use executor::{GithubJobExecutor, GithubJobExecutorPorts};
pub use port::{
    ActionPreparationPort, ActionPreparationRequest, ContextEnvironmentVariable,
    DeterministicOperationIds, ExecutionClock, ExecutionOperationIds, GithubContextPort,
    GithubContextRequest, GithubContextSnapshot, GithubExecutionIdentity, GithubExecutionPhase,
    GithubStepSnapshot, GithubToolchain, JobContentPort, NoRepositoryCredentials, NoSecrets,
    OperationPurpose, RepositoryCredentialPort, SandboxEnvironmentCatalog,
    SecretCustodyAcknowledger, SecretPort, SystemExecutionClock,
};
pub use prepared::{
    PreparedAction, PreparedActionDefinition, PreparedActionError, PreparedActionExecution,
    PreparedBoolean, PreparedCompositeAction, PreparedCompositeRunStep, PreparedCompositeStep,
    PreparedCompositeStepMetadata, PreparedCompositeUsesStep, PreparedInput,
    PreparedJavascriptAction, PreparedKeyValue, PreparedLocalAction, PreparedOutput, PreparedValue,
    PreparedValueSegment,
};
pub use secret::{
    EphemeralJobSecret, EphemeralJobSecrets, EphemeralJobSecretsError,
    MAX_EPHEMERAL_JOB_SECRET_BYTES, MAX_EPHEMERAL_JOB_SECRETS,
};
