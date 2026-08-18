//! Durable control boundary for GitHub-native Check rerun requests.

use std::fmt;

use async_trait::async_trait;
use automata_ci_core::{GitObjectId, Sha256Digest};
use thiserror::Error;

use crate::{
    GithubCheckAppId, GithubCheckRunId, GithubCheckSuiteId, StoreError, TenantScope,
    WorkflowRerunReceipt,
};
use automata_ci_provider::ProviderConnectionId;

const MAX_DELIVERY_ID_BYTES: usize = 255;
const MAX_EXTERNAL_ID_BYTES: usize = 255;

/// Closed rerun operation accepted from a signed Check Run webhook.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubCheckRerunAction {
    /// GitHub's native re-request action for the selected Check Run.
    Rerequested,
    /// Re-executes the entire workflow represented by the Check.
    RerunAll,
    /// Re-executes failed jobs and their downstream dependants.
    RerunFailed,
    /// Re-executes the selected job and its downstream dependants.
    RerunJob,
}

/// Exact provider object selected by a signed rerun webhook.
#[derive(Clone, Eq, PartialEq)]
pub enum GithubCheckRerunTarget {
    /// One Check Run, including Automata's immutable external identity.
    Run {
        /// Provider Check Run identity.
        run_id: GithubCheckRunId,
        /// Parent Check Suite identity.
        suite_id: GithubCheckSuiteId,
        /// Automata subject identity echoed by GitHub.
        external_id: String,
        /// Requested rerun mode.
        action: GithubCheckRerunAction,
    },
    /// Every Automata workflow Check in one Check Suite.
    Suite {
        /// Provider Check Suite identity.
        suite_id: GithubCheckSuiteId,
    },
}

impl fmt::Debug for GithubCheckRerunTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Run {
                run_id,
                suite_id,
                action,
                ..
            } => formatter
                .debug_struct("Run")
                .field("run_id", run_id)
                .field("suite_id", suite_id)
                .field("external_id", &"[redacted]")
                .field("action", action)
                .finish(),
            Self::Suite { suite_id } => formatter
                .debug_struct("Suite")
                .field("suite_id", suite_id)
                .finish(),
        }
    }
}

/// Signed, repository-bound GitHub Check control request.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubCheckRerunRequest {
    tenant: TenantScope,
    connection_id: ProviderConnectionId,
    installation_id: u64,
    github_repository_id: u64,
    app_id: GithubCheckAppId,
    head_sha: GitObjectId,
    sender_id: u64,
    delivery_id: String,
    body_sha256: Sha256Digest,
    target: GithubCheckRerunTarget,
}

impl GithubCheckRerunRequest {
    /// Constructs exact control evidence after webhook authentication and route selection.
    ///
    /// # Errors
    ///
    /// Rejects zero provider identities and unbounded replay identities.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantScope,
        connection_id: ProviderConnectionId,
        installation_id: u64,
        github_repository_id: u64,
        app_id: GithubCheckAppId,
        head_sha: GitObjectId,
        sender_id: u64,
        delivery_id: impl Into<String>,
        body_sha256: Sha256Digest,
        target: GithubCheckRerunTarget,
    ) -> Result<Self, GithubCheckRerunValueError> {
        let delivery_id = delivery_id.into();
        if installation_id == 0 || github_repository_id == 0 || sender_id == 0 {
            return Err(GithubCheckRerunValueError);
        }
        if delivery_id.is_empty()
            || delivery_id.len() > MAX_DELIVERY_ID_BYTES
            || delivery_id.chars().any(char::is_control)
        {
            return Err(GithubCheckRerunValueError);
        }
        if let GithubCheckRerunTarget::Run { external_id, .. } = &target
            && (external_id.is_empty()
                || external_id.len() > MAX_EXTERNAL_ID_BYTES
                || external_id.chars().any(char::is_control))
        {
            return Err(GithubCheckRerunValueError);
        }
        Ok(Self {
            tenant,
            connection_id,
            installation_id,
            github_repository_id,
            app_id,
            head_sha,
            sender_id,
            delivery_id,
            body_sha256,
            target,
        })
    }

    /// Returns the configured tenant selected by stable provider coordinates.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }
    /// Returns the server-owned provider connection.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }
    /// Returns the signed installation identity.
    #[must_use]
    pub const fn installation_id(&self) -> u64 {
        self.installation_id
    }
    /// Returns the signed repository identity.
    #[must_use]
    pub const fn github_repository_id(&self) -> u64 {
        self.github_repository_id
    }
    /// Returns the App that owns the selected Check.
    #[must_use]
    pub const fn app_id(&self) -> GithubCheckAppId {
        self.app_id
    }
    /// Returns the exact selected commit.
    #[must_use]
    pub const fn head_sha(&self) -> GitObjectId {
        self.head_sha
    }
    /// Returns the signed GitHub user identity.
    #[must_use]
    pub const fn sender_id(&self) -> u64 {
        self.sender_id
    }
    /// Returns GitHub's delivery replay identity.
    #[must_use]
    pub fn delivery_id(&self) -> &str {
        &self.delivery_id
    }
    /// Returns the authenticated body digest.
    #[must_use]
    pub const fn body_sha256(&self) -> Sha256Digest {
        self.body_sha256
    }
    /// Returns the exact selected Check object.
    #[must_use]
    pub const fn target(&self) -> &GithubCheckRerunTarget {
        &self.target
    }
}

impl fmt::Debug for GithubCheckRerunRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubCheckRerunRequest")
            .field("connection_id", &self.connection_id)
            .field("installation_id", &self.installation_id)
            .field("github_repository_id", &self.github_repository_id)
            .field("app_id", &self.app_id)
            .field("head_sha", &self.head_sha)
            .field("sender_id", &self.sender_id)
            .field("delivery_id", &"[redacted]")
            .field("body_sha256", &self.body_sha256)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

/// Invalid GitHub-native rerun evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub Check rerun evidence is invalid")]
pub struct GithubCheckRerunValueError;

/// Closed native-control admission failures.
#[derive(Debug, Error)]
pub enum GithubCheckRerunStoreError {
    /// The backing durable store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The Check identity, sender identity, or current permission was rejected.
    #[error("GitHub Check rerun authority was rejected")]
    AuthorityRejected,
    /// The exact Check no longer represents a terminal source run.
    #[error("GitHub Check rerun source is not eligible")]
    Conflict,
}

/// Durable bridge from GitHub-native controls to workflow rerun admission.
#[async_trait]
pub trait GithubCheckRerunRepository: fmt::Debug + Send + Sync {
    /// Resolves signed Check identity, reauthorizes the sender, and requests reruns.
    async fn rerun_github_check(
        &self,
        request: GithubCheckRerunRequest,
    ) -> Result<Vec<WorkflowRerunReceipt>, GithubCheckRerunStoreError>;
}
