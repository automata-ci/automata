//! Shared release capability for GitHub server-service credentials.

use std::fmt;

use async_trait::async_trait;

/// Move-only capability that releases one exact durable server-service handoff.
///
/// Implementations own the complete non-secret credential release binding. They
/// make one bounded exact release attempt and retain replayable ambiguous
/// release evidence until it is resolved or the immutable handoff horizon
/// expires. A credential must drop its bearer before invoking this capability.
#[async_trait]
pub trait GithubServerServiceCredentialRelease: fmt::Debug + Send + Sync {
    /// Releases the exact handoff after its final provider future has ended.
    async fn release(self: Box<Self>);
}
