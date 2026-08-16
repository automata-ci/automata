//! Planning-time validation failures for the job IR.

use thiserror::Error;

use super::{ExpressionProgramError, StepId, ValueTemplateError, WindowsActionGraphError};

/// Validation failure that must stop a plan before execution.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum JobValidationError {
    /// The `JobIR` envelope uses a schema this build cannot execute.
    #[error("unsupported job IR schema {received}; this build supports {supported}")]
    UnsupportedSchema {
        /// Schema version understood by this build.
        supported: u16,
        /// Schema version carried by the rejected envelope.
        received: u16,
    },
    /// Nested runner requirements use a schema this build cannot enforce.
    #[error("unsupported runner-requirements schema {received}; this build supports {supported}")]
    UnsupportedRequirementsSchema {
        /// Requirements schema version understood by this build.
        supported: u16,
        /// Requirements schema version carried by the rejected job.
        received: u16,
    },
    /// A named field required by the execution contract was empty.
    #[error("required field `{0}` is empty")]
    EmptyField(&'static str),
    /// An execution-context field violated its bounded canonical form.
    #[error("execution context field `{0}` is invalid")]
    InvalidContextField(&'static str),
    /// The Git reference was not a full canonical `refs/...` value.
    #[error("execution Git ref is not a canonical full ref")]
    InvalidGitRef,
    /// The workspace was not a canonical absolute target path.
    #[error("execution workspace is not a canonical absolute target path")]
    InvalidWorkspace,
    /// A content reference had invalid key, digest, size, or media-type evidence.
    #[error("execution content reference is invalid")]
    InvalidContentReference,
    /// The immutable repository-action graph was malformed or exceeded its
    /// fixed Windows materialization bounds.
    #[error("invalid Windows repository-action graph: {source}")]
    InvalidWindowsActionGraph {
        /// Exact graph validation failure.
        source: WindowsActionGraphError,
    },
    /// A logical job or output name violated length, whitespace, or control-byte rules.
    #[error("logical {field} is empty, overlong, padded, or contains control characters")]
    InvalidLogicalName {
        /// Logical field whose name was rejected.
        field: &'static str,
    },
    /// A concrete instance claimed a matrix with no members.
    #[error("matrix expansion total cannot be zero")]
    ZeroMatrixTotal,
    /// A concrete instance index fell outside its declared matrix cardinality.
    #[error("matrix expansion index {index} is outside total {total}")]
    MatrixIndexOutOfRange {
        /// Rejected zero-based expansion index.
        index: u32,
        /// Declared number of matrix expansions.
        total: u32,
    },
    /// A provider run number violated its one-based contract.
    #[error("provider run number cannot be zero")]
    ZeroRunNumber,
    /// A provider run-attempt number violated its one-based contract.
    #[error("provider run attempt cannot be zero")]
    ZeroRunAttempt,
    /// The job contained no executable semantic steps.
    #[error("a job must contain at least one step")]
    NoSteps,
    /// The job-level timeout requested immediate expiration.
    #[error("job timeout cannot be zero")]
    ZeroTimeout,
    /// Container port requests were zero or collided within their endpoint namespace.
    #[error("container ports must be non-zero and have unique container and requested endpoints")]
    InvalidContainerPorts,
    /// A step omitted its stable identifier.
    #[error("step ID cannot be empty")]
    EmptyStepId,
    /// A step identifier exceeded the bounded wire representation.
    #[error("step ID exceeds {maximum} bytes")]
    StepIdTooLong {
        /// Maximum accepted UTF-8 bytes.
        maximum: usize,
    },
    /// A step identifier contained a byte outside its portable ASCII grammar.
    #[error("invalid step ID `{0}`; only ASCII letters, numbers, `_`, and `-` are allowed")]
    InvalidStepId(String),
    /// More than one step used the same stable identifier.
    #[error("duplicate step ID `{0:?}`")]
    DuplicateStepId(StepId),
    /// A step timeout evaluated to zero before execution.
    #[error("timeout for step `{0:?}` cannot be zero")]
    ZeroStepTimeout(StepId),
    /// Converting a source-unit timeout to seconds overflowed `u32`.
    #[error("timeout for step `{0:?}` overflows seconds after applying its source unit")]
    StepTimeoutScaleOverflow(StepId),
    /// A typed expression attached to the named field was structurally invalid.
    #[error("invalid {field}: {source}")]
    InvalidExpression {
        /// Job field containing the invalid program.
        field: &'static str,
        /// Nested expression validation failure.
        source: ExpressionProgramError,
    },
    /// A value template attached to the named field was not canonical or bounded.
    #[error("invalid {field} value template: {source}")]
    InvalidValueTemplate {
        /// Job field containing the invalid template.
        field: &'static str,
        /// Nested template validation failure.
        source: ValueTemplateError,
    },
    /// Output definitions were duplicated or not sorted by canonical name.
    #[error("job output `{0}` appears more than once or is not in canonical order")]
    NonCanonicalJobOutput(String),
    /// The job exceeded the bounded number of terminal output definitions.
    #[error("a job exceeds the maximum of {maximum} output definitions")]
    TooManyJobOutputs {
        /// Maximum output-definition count accepted for one job.
        maximum: usize,
    },
    /// The explicit provider permission mapping exceeded its bounded cardinality.
    #[error("a job exceeds the maximum of {maximum} explicit permission grants")]
    TooManyPermissionGrants {
        /// Maximum explicit grants accepted for one job.
        maximum: usize,
    },
    /// A provider permission name violated the bounded canonical ASCII grammar.
    #[error("a job contains an invalid provider permission name")]
    InvalidPermissionName,
    /// Explicit provider permissions were duplicated or not sorted by canonical name.
    #[error("job provider permissions are duplicated or not in canonical order")]
    NonCanonicalPermissionMapping,
    /// The OIDC token permission used the unsupported read level.
    #[error("the `id-token` permission must be `write` or `none`")]
    IdTokenReadPermission,
    /// Credential-free execution did not explicitly deny every provider permission.
    #[error("credential-free execution requires an explicit deny-all provider permission map")]
    CredentialFreePermissions,
    /// Credential-free execution retained a secret or credential resolution path.
    #[error("credential-free execution cannot retain a secret or credential dependency")]
    CredentialFreeSecretDependency,
    /// Credential-free execution requested a runner feature that exposes credentials.
    #[error("credential-free execution cannot request a credential-bearing runner feature")]
    CredentialFreeRunnerFeature,
    /// Credential-free execution selected a Results cache or artifact action.
    #[error("credential-free execution cannot select a Results cache or artifact action")]
    CredentialFreeResultsAction,
    /// Effective trust required repository permissions to be reduced before `JobIR`.
    #[error("job provider permissions exceed the sealed trust snapshot")]
    TrustPermissionReduction,
    /// Effective trust denied a secret path retained by `JobIR`.
    #[error("job retains a secret dependency denied by the sealed trust snapshot")]
    TrustSecretDependency,
    /// Effective trust denied an OIDC path retained by `JobIR`.
    #[error("job retains an OIDC dependency denied by the sealed trust snapshot")]
    TrustOidcDependency,
    /// Effective trust denied a Results path retained by `JobIR`.
    #[error("job retains a Results dependency denied by the sealed trust snapshot")]
    TrustResultsDependency,
    /// A public output template attempted to read the secrets context.
    #[error("a public job output must not reference the secrets context")]
    PublicOutputReferencesSecrets,
}
