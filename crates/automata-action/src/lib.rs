//! Immutable, provider-neutral action bundle resolution.
//!
//! The resolver composes an [`automata_scm::ScmProvider`] with an
//! [`automata_blob::ImmutableBlobStore`]. It validates an SCM archive entirely
//! before publishing the raw content-addressed bundle. GitHub metadata parsing
//! and runtime semantics deliberately live above this provider-neutral layer.

#![forbid(unsafe_code)]

mod archive;
mod cache;
mod model;
mod resolver;

pub use archive::{inspect_archive, inspect_archive_bytes};
pub use cache::{
    ActionReferenceIndex, ActionReferenceIndexError, ActionReferenceIndexErrorKind,
    ImmutableActionReference, ImmutableActionReferenceError, IndexedActionBundle,
    MemoryActionReferenceIndex, PutActionReferenceOutcome,
};
pub use model::{
    ActionArchiveError, ActionBundleLimits, ActionBundleLimitsError, ActionDefinitionDocument,
    ActionDefinitionKind, ActionResolveError, ActionResolveErrorKind, ActionSubpath,
    ActionSubpathError, RepositoryActionRequest, ResolvedActionBundle,
};
pub use resolver::{ActionResolver, ImmutableActionResolver};
