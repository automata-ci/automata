//! Strict, bounded decoding of GitHub repository-action metadata.
//!
//! This adapter consumes the provider-neutral [`automata_action::ActionDefinitionDocument`]
//! selected from an immutable action bundle. It intentionally preserves metadata values and
//! expressions for later compilation; it does not evaluate workflow expressions.

#![forbid(unsafe_code)]

mod decoder;
mod error;
mod limits;
mod model;
mod parser;
mod path;

pub use decoder::{ActionMetadataDecoder, GithubActionMetadataDecoder};
pub use error::{MetadataDecodeError, MetadataDecodeErrorKind, MetadataLocation};
pub use limits::{GithubActionMetadataLimits, GithubActionMetadataLimitsError};
pub use model::{
    ActionExecution, ActionInput, ActionOutput, CompositeAction, CompositeRunStep, CompositeStep,
    CompositeUsesStep, DockerAction, DockerImage, DockerImageKind, GithubActionMetadata,
    JavascriptAction, JavascriptRuntime, MetadataEntryPath, MetadataKeyValue, MetadataScalar,
    MetadataScalarKind, MetadataScalarStyle,
};

/// Metadata dialect decoded by this adapter.
pub const GITHUB_ACTION_METADATA_DIALECT: &str = "github-actions.action-metadata";

/// Upstream runner release used to review schema and conversion behavior.
pub const GITHUB_ACTION_METADATA_BASELINE: &str = "actions/runner@v2.336.0";

/// Immutable upstream source revision for the compatibility baseline.
pub const GITHUB_ACTION_METADATA_BASELINE_COMMIT: &str = "98aabcd429c4e8402406c56ce2d26387fed3b9ce";
