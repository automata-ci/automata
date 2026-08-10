//! Immutable, provider-neutral action bundle resolution.
//!
//! The resolver composes an [`automata_ci_scm::ScmProvider`] with an
//! [`automata_ci_blob::ImmutableBlobStore`]. It validates an SCM archive entirely
//! before publishing the raw content-addressed bundle. GitHub metadata parsing
//! and runtime semantics deliberately live above this provider-neutral layer.
//!
//! Resolution preserves both the requested revision and the provider's resolved
//! immutable revision. Public errors intentionally expose only stable classes,
//! not repository, path, credential, provider-response, or backend-error detail.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod archive;
mod model;
mod resolver;

pub use archive::inspect_archive;
pub use model::{
    ActionArchiveError, ActionBundleLimits, ActionBundleLimitsError, ActionDefinitionDocument,
    ActionDefinitionKind, ActionResolveError, ActionResolveErrorKind, ActionSubpath,
    ActionSubpathError, RepositoryActionRequest, ResolvedActionBundle,
};
pub use resolver::{ActionResolver, ImmutableActionResolver};
