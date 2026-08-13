//! Strict, bounded decoding of GitHub repository-action metadata.
//!
//! This adapter consumes the provider-neutral [`automata_ci_action::ActionDefinitionDocument`]
//! selected from an immutable action bundle. Resolving an action reference to an immutable
//! repository revision happens before this boundary; this crate never fetches a repository or
//! follows a mutable action reference. Nested composite `uses` values and Docker registry image
//! references remain deferred source values for later admission and execution policy.
//!
//! The decoder classifies the supported JavaScript, Docker, and composite execution forms while
//! retaining YAML scalar spelling, kind, style, source position, and user-map order. It does not
//! evaluate expressions or coerce inputs and outputs into runtime values.
//!
//! Parsing is bounded by [`GithubActionMetadataLimits`] and fails closed on malformed YAML,
//! aliases and anchors, explicit tags, merge or duplicate keys, unsupported execution forms, and
//! unsafe bundle-relative executable paths. Error diagnostics identify a schema field and an
//! optional source location without including metadata contents.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

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
