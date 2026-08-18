use std::{collections::BTreeSet, fmt, num::NonZeroU64};

use automata_ci_core::{JobAuthorityProfile, WorkspaceId};
use automata_ci_github::GithubWebhookVerifier;
use automata_ci_store::{
    GithubCheckName, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceJwtIssuer, ProviderInstallationId,
    ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility,
};
use automata_ci_workflow_service::GithubRunnerPolicy;
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::{OperationId, ProvisioningAuthority, ShardId};

/// Maximum private-key PEM accepted through the management boundary.
pub const MAX_GITHUB_PROVIDER_PRIVATE_KEY_BYTES: usize = 32 * 1_024;
/// Maximum repositories served by one shard-wide GitHub provider runtime.
pub const MAX_GITHUB_PROVIDER_REPOSITORIES: usize = 256;
/// Maximum repositories in one workspace desired-set revision.
pub const MAX_WORKSPACE_GITHUB_REPOSITORIES: usize = MAX_GITHUB_PROVIDER_REPOSITORIES;

const PROTOBUF_TIMESTAMP_MIN_SECONDS: i64 = -62_135_596_800;
const PROTOBUF_TIMESTAMP_MAX_SECONDS: i64 = 253_402_300_799;
const NANOS_PER_SECOND: u32 = 1_000_000_000;
const MAX_POLL_MILLIS: i64 = 60_000;
const MAX_CLAIM_MILLIS: i64 = 30 * 60 * 1_000;
const MAX_RETRY_MILLIS: i64 = 60 * 60 * 1_000;
const MAX_STALENESS_MILLIS: i64 = 366 * 24 * 60 * 60 * 1_000;
const MAX_FIRES_PER_PASS: u16 = 1_024;

macro_rules! positive_revision {
    ($(#[$meta:meta])* $name:ident, $error:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// Creates a positive revision representable by `PostgreSQL` `BIGINT`.
            ///
            /// # Errors
            ///
            /// Rejects zero and values larger than a signed 64-bit integer.
            pub const fn new(value: u64) -> Result<Self, GithubProviderValueError> {
                match NonZeroU64::new(value) {
                    Some(value) if value.get() <= i64::MAX as u64 => Ok(Self(value)),
                    _ => Err(GithubProviderValueError::$error),
                }
            }

            /// Returns the positive numeric revision.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0.get()
            }
        }
    };
}

positive_revision!(
    /// Monotonic shard-wide GitHub provider configuration revision.
    GithubProviderConfigurationRevision,
    InvalidProviderRevision
);
positive_revision!(
    /// Monotonic complete GitHub repository desired-set revision for one workspace.
    WorkspaceGithubRepositoriesRevision,
    InvalidWorkspaceRevision
);

/// Owned GitHub provider credential accepted only at a secret-handling boundary.
///
/// The value is redacted from diagnostics and zeroized when dropped. It is not
/// cloneable so application code cannot accidentally fork plaintext custody.
pub struct GithubProviderSecret(Zeroizing<Vec<u8>>);

impl GithubProviderSecret {
    /// Creates a bounded App private-key PEM.
    ///
    /// # Errors
    ///
    /// Rejects empty or excessive values.
    pub fn private_key(value: Vec<u8>) -> Result<Self, GithubProviderValueError> {
        if value.is_empty() || value.len() > MAX_GITHUB_PROVIDER_PRIVATE_KEY_BYTES {
            return Err(GithubProviderValueError::InvalidPrivateKey);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    /// Creates a bounded webhook HMAC secret using the verifier's exact policy.
    ///
    /// # Errors
    ///
    /// Rejects values that cannot construct the production webhook verifier.
    pub fn webhook(value: Vec<u8>) -> Result<Self, GithubProviderValueError> {
        GithubWebhookVerifier::new(&value)
            .map_err(|_| GithubProviderValueError::InvalidWebhookSecret)?;
        Ok(Self(Zeroizing::new(value)))
    }

    /// Explicitly exposes plaintext only to encryption or runtime construction.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Consumes this value into an independently zeroizing buffer.
    #[must_use]
    pub fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl fmt::Debug for GithubProviderSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GithubProviderSecret([REDACTED])")
    }
}

/// Bounded shard-wide scheduler policy persisted with provider configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubProviderSchedulePolicy {
    poll_millis: i64,
    discovery_claim_millis: i64,
    fire_claim_millis: i64,
    retry_millis: i64,
    staleness_millis: i64,
    maximum_manifests: u16,
    maximum_fires_per_pass: u16,
}

impl GithubProviderSchedulePolicy {
    /// Creates one bounded deterministic scheduler policy.
    ///
    /// # Errors
    ///
    /// Rejects zero, negative, or excessive durations and work bounds.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        poll_millis: i64,
        discovery_claim_millis: i64,
        fire_claim_millis: i64,
        retry_millis: i64,
        staleness_millis: i64,
        maximum_manifests: u16,
        maximum_fires_per_pass: u16,
    ) -> Result<Self, GithubProviderValueError> {
        if poll_millis <= 0
            || poll_millis > MAX_POLL_MILLIS
            || discovery_claim_millis <= 0
            || discovery_claim_millis > MAX_CLAIM_MILLIS
            || fire_claim_millis <= 0
            || fire_claim_millis > MAX_CLAIM_MILLIS
            || retry_millis <= 0
            || retry_millis > MAX_RETRY_MILLIS
            || staleness_millis <= 0
            || staleness_millis > MAX_STALENESS_MILLIS
            || maximum_manifests == 0
            || maximum_fires_per_pass == 0
            || maximum_fires_per_pass > MAX_FIRES_PER_PASS
        {
            return Err(GithubProviderValueError::InvalidSchedulePolicy);
        }
        Ok(Self {
            poll_millis,
            discovery_claim_millis,
            fire_claim_millis,
            retry_millis,
            staleness_millis,
            maximum_manifests,
            maximum_fires_per_pass,
        })
    }

    /// Returns the idle interval between scheduler passes.
    #[must_use]
    pub const fn poll_millis(self) -> i64 {
        self.poll_millis
    }

    /// Returns the discovery claim duration.
    #[must_use]
    pub const fn discovery_claim_millis(self) -> i64 {
        self.discovery_claim_millis
    }

    /// Returns the due-fire claim duration.
    #[must_use]
    pub const fn fire_claim_millis(self) -> i64 {
        self.fire_claim_millis
    }

    /// Returns the durable retry interval.
    #[must_use]
    pub const fn retry_millis(self) -> i64 {
        self.retry_millis
    }

    /// Returns the maximum catch-up staleness.
    #[must_use]
    pub const fn staleness_millis(self) -> i64 {
        self.staleness_millis
    }

    /// Returns the bounded manifest scan size.
    #[must_use]
    pub const fn maximum_manifests(self) -> u16 {
        self.maximum_manifests
    }

    /// Returns the bounded due-fire work count.
    #[must_use]
    pub const fn maximum_fires_per_pass(self) -> u16 {
        self.maximum_fires_per_pass
    }
}

impl Default for GithubProviderSchedulePolicy {
    fn default() -> Self {
        Self::new(1_000, 300_000, 300_000, 30_000, 3_600_000, 256, 32)
            .expect("fixed provider scheduler defaults are valid")
    }
}

/// Complete shard-wide GitHub App and provider runtime configuration.
pub struct GithubProviderConfiguration {
    dashboard_url: Url,
    app_id: GithubServerServiceAppId,
    app_client_id: GithubServerServiceAppClientId,
    jwt_issuer: GithubServerServiceJwtIssuer,
    private_key: GithubProviderSecret,
    webhook_secret: GithubProviderSecret,
    check_name: GithubCheckName,
    runner_policy: GithubRunnerPolicy,
    schedule: GithubProviderSchedulePolicy,
}

impl GithubProviderConfiguration {
    /// Creates a complete validated provider configuration.
    ///
    /// # Errors
    ///
    /// Rejects a dashboard URL that is not a canonical HTTPS base origin.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dashboard_url: Url,
        app_id: GithubServerServiceAppId,
        app_client_id: GithubServerServiceAppClientId,
        jwt_issuer: GithubServerServiceJwtIssuer,
        private_key: GithubProviderSecret,
        webhook_secret: GithubProviderSecret,
        check_name: GithubCheckName,
        runner_policy: GithubRunnerPolicy,
        schedule: GithubProviderSchedulePolicy,
    ) -> Result<Self, GithubProviderValueError> {
        if dashboard_url.scheme() != "https"
            || dashboard_url.host_str().is_none()
            || !dashboard_url.username().is_empty()
            || dashboard_url.password().is_some()
            || dashboard_url.path() != "/"
            || dashboard_url.query().is_some()
            || dashboard_url.fragment().is_some()
        {
            return Err(GithubProviderValueError::InvalidDashboardUrl);
        }
        Ok(Self {
            dashboard_url,
            app_id,
            app_client_id,
            jwt_issuer,
            private_key,
            webhook_secret,
            check_name,
            runner_policy,
            schedule,
        })
    }

    /// Returns the canonical external dashboard base URL.
    #[must_use]
    pub const fn dashboard_url(&self) -> &Url {
        &self.dashboard_url
    }

    /// Returns the numeric GitHub App identity.
    #[must_use]
    pub const fn app_id(&self) -> GithubServerServiceAppId {
        self.app_id
    }

    /// Returns the GitHub-issued App client identity.
    #[must_use]
    pub const fn app_client_id(&self) -> &GithubServerServiceAppClientId {
        &self.app_client_id
    }

    /// Returns the configured App JWT issuer family.
    #[must_use]
    pub const fn jwt_issuer(&self) -> GithubServerServiceJwtIssuer {
        self.jwt_issuer
    }

    /// Returns the plaintext App private key at the encryption boundary.
    #[must_use]
    pub const fn private_key(&self) -> &GithubProviderSecret {
        &self.private_key
    }

    /// Returns the plaintext webhook secret at the encryption boundary.
    #[must_use]
    pub const fn webhook_secret(&self) -> &GithubProviderSecret {
        &self.webhook_secret
    }

    /// Returns the provider-facing Check name.
    #[must_use]
    pub const fn check_name(&self) -> &GithubCheckName {
        &self.check_name
    }

    /// Returns the validated default runner policy.
    #[must_use]
    pub const fn runner_policy(&self) -> &GithubRunnerPolicy {
        &self.runner_policy
    }

    /// Returns the scheduler policy.
    #[must_use]
    pub const fn schedule(&self) -> GithubProviderSchedulePolicy {
        self.schedule
    }

    /// Consumes the configuration into runtime-ready validated parts.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Url,
        GithubServerServiceAppId,
        GithubServerServiceAppClientId,
        GithubServerServiceJwtIssuer,
        GithubProviderSecret,
        GithubProviderSecret,
        GithubCheckName,
        GithubRunnerPolicy,
        GithubProviderSchedulePolicy,
    ) {
        (
            self.dashboard_url,
            self.app_id,
            self.app_client_id,
            self.jwt_issuer,
            self.private_key,
            self.webhook_secret,
            self.check_name,
            self.runner_policy,
            self.schedule,
        )
    }
}

impl fmt::Debug for GithubProviderConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubProviderConfiguration")
            .field("dashboard_url", &"[CONFIGURED]")
            .field("app_id", &self.app_id)
            .field("app_client_id", &self.app_client_id)
            .field("jwt_issuer", &self.jwt_issuer)
            .field("private_key", &"[REDACTED]")
            .field("webhook_secret", &"[REDACTED]")
            .field("check_name", &"[CONFIGURED]")
            .field("runner_policy", &"[VALIDATED]")
            .field("schedule", &self.schedule)
            .finish()
    }
}

/// Complete validated shard-wide provider configuration command.
pub struct ApplyGithubProviderConfigurationCommand {
    operation_id: OperationId,
    shard_id: ShardId,
    revision: GithubProviderConfigurationRevision,
    configuration: GithubProviderConfiguration,
}

impl ApplyGithubProviderConfigurationCommand {
    /// Creates a complete provider configuration replacement.
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        shard_id: ShardId,
        revision: GithubProviderConfigurationRevision,
        configuration: GithubProviderConfiguration,
    ) -> Self {
        Self {
            operation_id,
            shard_id,
            revision,
            configuration,
        }
    }

    /// Returns the stable idempotency identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the expected shard identity.
    #[must_use]
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    /// Returns the monotonic configuration revision.
    #[must_use]
    pub const fn revision(&self) -> GithubProviderConfigurationRevision {
        self.revision
    }

    /// Returns the complete configuration.
    #[must_use]
    pub const fn configuration(&self) -> &GithubProviderConfiguration {
        &self.configuration
    }
}

impl fmt::Debug for ApplyGithubProviderConfigurationCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplyGithubProviderConfigurationCommand")
            .field("operation_id", &self.operation_id)
            .field("shard_id", &self.shard_id)
            .field("revision", &self.revision)
            .field("configuration", &self.configuration)
            .finish()
    }
}

/// Provider command proven to target the caller's configured shard.
pub struct AuthorizedApplyGithubProviderConfiguration {
    authority: ProvisioningAuthority,
    command: ApplyGithubProviderConfigurationCommand,
}

impl AuthorizedApplyGithubProviderConfiguration {
    /// Authorizes the requested shard against authenticated workload authority.
    ///
    /// # Errors
    ///
    /// Rejects a command addressed to another shard.
    pub fn authorize(
        authority: ProvisioningAuthority,
        command: ApplyGithubProviderConfigurationCommand,
    ) -> Result<Self, GithubProviderValueError> {
        if authority.shard_id() != command.shard_id() {
            return Err(GithubProviderValueError::Forbidden);
        }
        Ok(Self { authority, command })
    }

    /// Returns the authenticated workload authority.
    #[must_use]
    pub const fn authority(&self) -> &ProvisioningAuthority {
        &self.authority
    }

    /// Returns the validated command.
    #[must_use]
    pub const fn command(&self) -> &ApplyGithubProviderConfigurationCommand {
        &self.command
    }

    /// Consumes the authorized request.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ProvisioningAuthority,
        ApplyGithubProviderConfigurationCommand,
    ) {
        (self.authority, self.command)
    }
}

impl fmt::Debug for AuthorizedApplyGithubProviderConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedApplyGithubProviderConfiguration")
            .field("authority", &self.authority)
            .field("command", &self.command)
            .finish()
    }
}

/// One selected GitHub repository in a complete workspace desired set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubProviderRepositorySelection {
    installation_id: ProviderInstallationId,
    repository_id: ProviderRepositoryId,
    repository_owner_id: ProviderRepositoryOwnerId,
    repository_name: GithubRepositoryName,
    default_branch: String,
    visibility: ProviderRepositoryVisibility,
    authority_profile: JobAuthorityProfile,
}

impl GithubProviderRepositorySelection {
    /// Creates one validated repository selection.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical default branch or a credential-free private repository.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: ProviderInstallationId,
        repository_id: ProviderRepositoryId,
        repository_owner_id: ProviderRepositoryOwnerId,
        repository_name: GithubRepositoryName,
        default_branch: impl Into<String>,
        visibility: ProviderRepositoryVisibility,
        authority_profile: JobAuthorityProfile,
    ) -> Result<Self, GithubProviderValueError> {
        let default_branch = default_branch.into();
        if !canonical_branch_name(&default_branch)
            || matches!(
                (visibility, authority_profile),
                (
                    ProviderRepositoryVisibility::Private,
                    JobAuthorityProfile::CredentialFree
                )
            )
        {
            return Err(GithubProviderValueError::InvalidRepository);
        }
        Ok(Self {
            installation_id,
            repository_id,
            repository_owner_id,
            repository_name,
            default_branch,
            visibility,
            authority_profile,
        })
    }

    /// Returns the GitHub App installation identity.
    #[must_use]
    pub const fn installation_id(&self) -> ProviderInstallationId {
        self.installation_id
    }

    /// Returns the stable numeric GitHub repository identity.
    #[must_use]
    pub const fn repository_id(&self) -> ProviderRepositoryId {
        self.repository_id
    }

    /// Returns the stable numeric GitHub owner identity.
    #[must_use]
    pub const fn repository_owner_id(&self) -> ProviderRepositoryOwnerId {
        self.repository_owner_id
    }

    /// Returns the canonical case-sensitive `owner/name` identity.
    #[must_use]
    pub const fn repository_name(&self) -> &GithubRepositoryName {
        &self.repository_name
    }

    /// Returns the canonical default branch name without `refs/heads/`.
    #[must_use]
    pub fn default_branch(&self) -> &str {
        &self.default_branch
    }

    /// Returns the authenticated repository visibility.
    #[must_use]
    pub const fn visibility(&self) -> ProviderRepositoryVisibility {
        self.visibility
    }

    /// Returns the job-visible authority profile.
    #[must_use]
    pub const fn authority_profile(&self) -> JobAuthorityProfile {
        self.authority_profile
    }
}

/// Complete validated repository desired-set command for one workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyWorkspaceGithubRepositoriesCommand {
    operation_id: OperationId,
    shard_id: ShardId,
    workspace_id: WorkspaceId,
    revision: WorkspaceGithubRepositoriesRevision,
    repositories: Vec<GithubProviderRepositorySelection>,
}

impl ApplyWorkspaceGithubRepositoriesCommand {
    /// Creates a complete, stably ordered repository desired set.
    ///
    /// An empty set is valid and disconnects every repository from the workspace.
    ///
    /// # Errors
    ///
    /// Rejects excessive or duplicate numeric/name identities.
    pub fn new(
        operation_id: OperationId,
        shard_id: ShardId,
        workspace_id: WorkspaceId,
        revision: WorkspaceGithubRepositoriesRevision,
        repositories: Vec<GithubProviderRepositorySelection>,
    ) -> Result<Self, GithubProviderValueError> {
        let repositories = normalize_repositories(repositories)?;
        Ok(Self {
            operation_id,
            shard_id,
            workspace_id,
            revision,
            repositories,
        })
    }

    /// Returns the stable operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the expected shard identity.
    #[must_use]
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    /// Returns the workspace receiving this desired set.
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// Returns the monotonic workspace desired-set revision.
    #[must_use]
    pub const fn revision(&self) -> WorkspaceGithubRepositoriesRevision {
        self.revision
    }

    /// Returns repositories in stable installation/repository numeric order.
    #[must_use]
    pub fn repositories(&self) -> &[GithubProviderRepositorySelection] {
        &self.repositories
    }
}

/// Workspace desired-set command proven to target the caller's configured shard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedApplyWorkspaceGithubRepositories {
    authority: ProvisioningAuthority,
    command: ApplyWorkspaceGithubRepositoriesCommand,
}

impl AuthorizedApplyWorkspaceGithubRepositories {
    /// Authorizes the requested shard against authenticated workload authority.
    ///
    /// Durable persistence additionally verifies that the authority owns the workspace.
    ///
    /// # Errors
    ///
    /// Rejects a command addressed to another shard.
    pub fn authorize(
        authority: ProvisioningAuthority,
        command: ApplyWorkspaceGithubRepositoriesCommand,
    ) -> Result<Self, GithubProviderValueError> {
        if authority.shard_id() != command.shard_id() {
            return Err(GithubProviderValueError::Forbidden);
        }
        Ok(Self { authority, command })
    }

    /// Returns the authenticated workload authority.
    #[must_use]
    pub const fn authority(&self) -> &ProvisioningAuthority {
        &self.authority
    }

    /// Returns the validated command.
    #[must_use]
    pub const fn command(&self) -> &ApplyWorkspaceGithubRepositoriesCommand {
        &self.command
    }

    /// Consumes the authorized request.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ProvisioningAuthority,
        ApplyWorkspaceGithubRepositoriesCommand,
    ) {
        (self.authority, self.command)
    }
}

/// Current complete repository desired set for one workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceGithubRepositoriesDesiredState {
    workspace_id: WorkspaceId,
    revision: WorkspaceGithubRepositoriesRevision,
    repositories: Vec<GithubProviderRepositorySelection>,
}

impl WorkspaceGithubRepositoriesDesiredState {
    /// Creates one already-validated, stably ordered workspace desired set.
    ///
    /// # Errors
    ///
    /// Rejects excessive or duplicate repository identities.
    pub fn new(
        workspace_id: WorkspaceId,
        revision: WorkspaceGithubRepositoriesRevision,
        repositories: Vec<GithubProviderRepositorySelection>,
    ) -> Result<Self, GithubProviderValueError> {
        Ok(Self {
            workspace_id,
            revision,
            repositories: normalize_repositories(repositories)?,
        })
    }

    /// Returns the workspace owning this desired set.
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// Returns its monotonic complete-set revision.
    #[must_use]
    pub const fn revision(&self) -> WorkspaceGithubRepositoriesRevision {
        self.revision
    }

    /// Returns repositories in stable installation/repository order.
    #[must_use]
    pub fn repositories(&self) -> &[GithubProviderRepositorySelection] {
        &self.repositories
    }
}

fn normalize_repositories(
    mut repositories: Vec<GithubProviderRepositorySelection>,
) -> Result<Vec<GithubProviderRepositorySelection>, GithubProviderValueError> {
    if repositories.len() > MAX_WORKSPACE_GITHUB_REPOSITORIES {
        return Err(GithubProviderValueError::TooManyRepositories);
    }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for repository in &repositories {
        if !ids.insert(repository.repository_id())
            || !names.insert(repository.repository_name().as_str().to_ascii_lowercase())
        {
            return Err(GithubProviderValueError::DuplicateRepository);
        }
    }
    repositories.sort_unstable_by_key(|repository| {
        (repository.installation_id(), repository.repository_id())
    });
    Ok(repositories)
}

/// Current database-backed GitHub provider desired state for one shard.
pub struct GithubProviderDesiredState {
    shard_id: ShardId,
    configuration_revision: GithubProviderConfigurationRevision,
    app_configuration_revision: u64,
    webhook_verifier_revision: u64,
    configuration: GithubProviderConfiguration,
    workspaces: Vec<WorkspaceGithubRepositoriesDesiredState>,
}

impl GithubProviderDesiredState {
    /// Creates one complete, ordered desired-state snapshot.
    ///
    /// # Errors
    ///
    /// Rejects zero runtime revisions or duplicate workspace identities.
    pub fn new(
        shard_id: ShardId,
        configuration_revision: GithubProviderConfigurationRevision,
        app_configuration_revision: u64,
        webhook_verifier_revision: u64,
        configuration: GithubProviderConfiguration,
        mut workspaces: Vec<WorkspaceGithubRepositoriesDesiredState>,
    ) -> Result<Self, GithubProviderValueError> {
        if app_configuration_revision == 0 || webhook_verifier_revision == 0 {
            return Err(GithubProviderValueError::InvalidProviderRevision);
        }
        workspaces.sort_unstable_by_key(WorkspaceGithubRepositoriesDesiredState::workspace_id);
        if workspaces
            .windows(2)
            .any(|pair| pair[0].workspace_id == pair[1].workspace_id)
        {
            return Err(GithubProviderValueError::DuplicateWorkspace);
        }
        Ok(Self {
            shard_id,
            configuration_revision,
            app_configuration_revision,
            webhook_verifier_revision,
            configuration,
            workspaces,
        })
    }

    /// Returns the shard owning the snapshot.
    #[must_use]
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    /// Returns the persisted shard-wide configuration revision.
    #[must_use]
    pub const fn configuration_revision(&self) -> GithubProviderConfigurationRevision {
        self.configuration_revision
    }

    /// Returns the App identity/key revision derived during persistence.
    #[must_use]
    pub const fn app_configuration_revision(&self) -> u64 {
        self.app_configuration_revision
    }

    /// Returns the webhook verifier revision derived during persistence.
    #[must_use]
    pub const fn webhook_verifier_revision(&self) -> u64 {
        self.webhook_verifier_revision
    }

    /// Returns the validated shard-wide provider configuration.
    #[must_use]
    pub const fn configuration(&self) -> &GithubProviderConfiguration {
        &self.configuration
    }

    /// Returns current workspace sets in stable workspace order.
    #[must_use]
    pub fn workspaces(&self) -> &[WorkspaceGithubRepositoriesDesiredState] {
        &self.workspaces
    }

    /// Consumes the snapshot into runtime projection parts.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ShardId,
        GithubProviderConfigurationRevision,
        u64,
        u64,
        GithubProviderConfiguration,
        Vec<WorkspaceGithubRepositoriesDesiredState>,
    ) {
        (
            self.shard_id,
            self.configuration_revision,
            self.app_configuration_revision,
            self.webhook_verifier_revision,
            self.configuration,
            self.workspaces,
        )
    }
}

impl fmt::Debug for GithubProviderDesiredState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubProviderDesiredState")
            .field("shard_id", &self.shard_id)
            .field("configuration_revision", &self.configuration_revision)
            .field(
                "app_configuration_revision",
                &self.app_configuration_revision,
            )
            .field("webhook_verifier_revision", &self.webhook_verifier_revision)
            .field("configuration", &self.configuration)
            .field("workspace_count", &self.workspaces.len())
            .field(
                "repository_count",
                &self
                    .workspaces
                    .iter()
                    .map(|workspace| workspace.repositories.len())
                    .sum::<usize>(),
            )
            .finish()
    }
}

/// Protobuf-compatible UTC instant returned by provider management operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubProviderTimestamp {
    seconds: i64,
    nanoseconds: u32,
}

impl GithubProviderTimestamp {
    /// Creates an instant in the Protobuf Timestamp range.
    ///
    /// # Errors
    ///
    /// Rejects out-of-range seconds or nanoseconds.
    pub const fn new(seconds: i64, nanoseconds: u32) -> Result<Self, GithubProviderValueError> {
        if seconds < PROTOBUF_TIMESTAMP_MIN_SECONDS
            || seconds > PROTOBUF_TIMESTAMP_MAX_SECONDS
            || nanoseconds >= NANOS_PER_SECOND
        {
            return Err(GithubProviderValueError::InvalidTimestamp);
        }
        Ok(Self {
            seconds,
            nanoseconds,
        })
    }

    /// Returns whole Unix seconds.
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }

    /// Returns fractional nanoseconds.
    #[must_use]
    pub const fn nanoseconds(self) -> u32 {
        self.nanoseconds
    }
}

/// Stable result of applying one provider configuration revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyGithubProviderConfigurationResult {
    operation_id: OperationId,
    shard_id: ShardId,
    revision: GithubProviderConfigurationRevision,
    applied_at: GithubProviderTimestamp,
}

impl ApplyGithubProviderConfigurationResult {
    /// Creates a stable durable result.
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        shard_id: ShardId,
        revision: GithubProviderConfigurationRevision,
        applied_at: GithubProviderTimestamp,
    ) -> Self {
        Self {
            operation_id,
            shard_id,
            revision,
            applied_at,
        }
    }

    /// Returns the request operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the configured shard identity.
    #[must_use]
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    /// Returns the committed configuration revision.
    #[must_use]
    pub const fn revision(&self) -> GithubProviderConfigurationRevision {
        self.revision
    }

    /// Returns the stable database commit time.
    #[must_use]
    pub const fn applied_at(&self) -> GithubProviderTimestamp {
        self.applied_at
    }
}

/// Stable result of applying one workspace repository desired-set revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyWorkspaceGithubRepositoriesResult {
    operation_id: OperationId,
    shard_id: ShardId,
    workspace_id: WorkspaceId,
    revision: WorkspaceGithubRepositoriesRevision,
    applied_at: GithubProviderTimestamp,
}

impl ApplyWorkspaceGithubRepositoriesResult {
    /// Creates a stable durable result.
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        shard_id: ShardId,
        workspace_id: WorkspaceId,
        revision: WorkspaceGithubRepositoriesRevision,
        applied_at: GithubProviderTimestamp,
    ) -> Self {
        Self {
            operation_id,
            shard_id,
            workspace_id,
            revision,
            applied_at,
        }
    }

    /// Returns the request operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the configured shard identity.
    #[must_use]
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    /// Returns the affected workspace identity.
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// Returns the committed desired-set revision.
    #[must_use]
    pub const fn revision(&self) -> WorkspaceGithubRepositoriesRevision {
        self.revision
    }

    /// Returns the stable database commit time.
    #[must_use]
    pub const fn applied_at(&self) -> GithubProviderTimestamp {
        self.applied_at
    }
}

/// Closed provider configuration failure classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubProviderConfigurationFailureKind {
    /// An operation ID was reused for different input.
    OperationConflict,
    /// The revision did not advance the current configuration.
    StaleRevision,
    /// The authenticated workload cannot mutate this shard.
    Forbidden,
    /// Credential encryption or durable storage is temporarily unavailable.
    TemporarilyUnavailable,
    /// Core failed without a safer specific classification.
    Internal,
}

/// Sanitized provider configuration application failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("GitHub provider configuration failed: {kind:?}")]
pub struct GithubProviderConfigurationFailure {
    kind: GithubProviderConfigurationFailureKind,
}

impl GithubProviderConfigurationFailure {
    /// Creates one closed failure.
    #[must_use]
    pub const fn new(kind: GithubProviderConfigurationFailureKind) -> Self {
        Self { kind }
    }

    /// Returns the machine-readable failure kind.
    #[must_use]
    pub const fn kind(&self) -> GithubProviderConfigurationFailureKind {
        self.kind
    }
}

/// Closed workspace repository desired-set failure classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceGithubRepositoriesFailureKind {
    /// An operation ID was reused for different input.
    OperationConflict,
    /// The revision did not advance the current workspace desired set.
    StaleRevision,
    /// The workspace is absent or managed by another authority.
    WorkspaceUnavailable,
    /// The resulting shard registry would duplicate a repository or exceed capacity.
    ShardRegistryConflict,
    /// Durable storage is temporarily unavailable.
    TemporarilyUnavailable,
    /// Core failed without a safer specific classification.
    Internal,
}

/// Sanitized workspace repository desired-set application failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("workspace GitHub repository configuration failed: {kind:?}")]
pub struct WorkspaceGithubRepositoriesFailure {
    kind: WorkspaceGithubRepositoriesFailureKind,
}

impl WorkspaceGithubRepositoriesFailure {
    /// Creates one closed failure.
    #[must_use]
    pub const fn new(kind: WorkspaceGithubRepositoriesFailureKind) -> Self {
        Self { kind }
    }

    /// Returns the machine-readable failure kind.
    #[must_use]
    pub const fn kind(&self) -> WorkspaceGithubRepositoriesFailureKind {
        self.kind
    }
}

/// Closed desired-state snapshot loading failure classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubProviderDesiredStateFailureKind {
    /// `PostgreSQL` or the configured wrapping-key provider is unavailable.
    TemporarilyUnavailable,
    /// Durable desired state is malformed, inconsistent, or cannot be authenticated.
    CorruptState,
}

/// Sanitized failure loading current database-backed provider desired state.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("GitHub provider desired state could not be loaded: {kind:?}")]
pub struct GithubProviderDesiredStateFailure {
    kind: GithubProviderDesiredStateFailureKind,
}

impl GithubProviderDesiredStateFailure {
    /// Creates one closed desired-state load failure.
    #[must_use]
    pub const fn new(kind: GithubProviderDesiredStateFailureKind) -> Self {
        Self { kind }
    }

    /// Returns the machine-readable failure kind.
    #[must_use]
    pub const fn kind(&self) -> GithubProviderDesiredStateFailureKind {
        self.kind
    }
}

/// Validation or authorization failure before provider persistence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubProviderValueError {
    /// The shard-wide configuration revision is invalid.
    #[error("GitHub provider configuration revision is invalid")]
    InvalidProviderRevision,
    /// The workspace repository desired-set revision is invalid.
    #[error("workspace GitHub repository revision is invalid")]
    InvalidWorkspaceRevision,
    /// The dashboard URL is not a canonical HTTPS base origin.
    #[error("GitHub provider dashboard URL is invalid")]
    InvalidDashboardUrl,
    /// The App private key is empty or excessive.
    #[error("GitHub provider private key is invalid")]
    InvalidPrivateKey,
    /// The webhook secret is invalid.
    #[error("GitHub provider webhook secret is invalid")]
    InvalidWebhookSecret,
    /// The scheduler policy is invalid.
    #[error("GitHub provider schedule policy is invalid")]
    InvalidSchedulePolicy,
    /// One repository selection is invalid.
    #[error("GitHub provider repository selection is invalid")]
    InvalidRepository,
    /// A complete desired set contains duplicate repository identity.
    #[error("GitHub provider repository selection is duplicated")]
    DuplicateRepository,
    /// A desired-state snapshot contains a duplicate workspace identity.
    #[error("GitHub provider workspace desired state is duplicated")]
    DuplicateWorkspace,
    /// A complete desired set exceeds the hard repository bound.
    #[error("workspace GitHub repository selection is excessive")]
    TooManyRepositories,
    /// A management command targets another shard.
    #[error("GitHub provider management is outside the workload authority")]
    Forbidden,
    /// A durable result timestamp is invalid.
    #[error("GitHub provider timestamp is invalid")]
    InvalidTimestamp,
}

fn canonical_branch_name(branch: &str) -> bool {
    !branch.is_empty()
        && branch.len() <= 255
        && branch != "@"
        && !branch.starts_with(['-', '/', '.'])
        && !branch.ends_with(['/', '.'])
        && !branch.contains("//")
        && !branch.contains("..")
        && !branch.contains("@{")
        && !branch.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(character, '~' | '^' | ':' | '?' | '*' | '[' | '\\')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DelegatedActorIssuer, ProvisioningAuthorityId};
    use automata_ci_core::RunnerFeature;

    const RUNNER_POLICY: &[u8] = br#"{
      "workspace":{"derivation":1,"root":"/__w","schema":1},
      "mappings":[{"runner_features":{"schema":1,"supported":["automata.core/bash-shell@v1","automata.core/command-files@v1","automata.core/composite-actions@v1","automata.core/default-posix-shell@v1","automata.core/javascript-actions@v1","automata.core/job-summaries@v1","automata.core/local-actions@v1","automata.core/node24-actions@v1","automata.core/python-shell@v1","automata.core/repository-actions@v1","automata.core/sh-shell@v1","automata.core/shell-steps@v1"]},"container_features":["automata.core/job-containers@v1"],"architecture":"x86_64","operating_system":"linux","environment_profile":{"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","id":"automata.example/ubuntu-24-04"},"selector":"Ubuntu-24.04"}],
      "permissions":{"provider_default":{"contents":"read","packages":"read"},"read_all":{"actions":"read","artifact-metadata":"read","attestations":"read","checks":"read","code-quality":"read","contents":"read","deployments":"read","discussions":"read","issues":"read","models":"read","packages":"read","pages":"read","pull-requests":"read","security-events":"read","statuses":"read","vulnerability-alerts":"read"},"write_all":{"actions":"write","artifact-metadata":"write","attestations":"write","checks":"write","code-quality":"write","contents":"write","deployments":"write","discussions":"write","id-token":"write","issues":"write","models":"read","packages":"write","pages":"write","pull-requests":"write","security-events":"write","statuses":"write","vulnerability-alerts":"read"}},
      "resources":{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}},
      "schema":2
    }"#;

    fn authority() -> ProvisioningAuthority {
        ProvisioningAuthority::new(
            ProvisioningAuthorityId::new("cloud").unwrap(),
            ShardId::new("local").unwrap(),
            DelegatedActorIssuer::new("https://cloud.example").unwrap(),
        )
    }

    fn repository(id: u64, name: &str) -> GithubProviderRepositorySelection {
        GithubProviderRepositorySelection::new(
            ProviderInstallationId::new(10).unwrap(),
            ProviderRepositoryId::new(id).unwrap(),
            ProviderRepositoryOwnerId::new(20).unwrap(),
            GithubRepositoryName::new(name).unwrap(),
            "main",
            ProviderRepositoryVisibility::Public,
            JobAuthorityProfile::CredentialFree,
        )
        .unwrap()
    }

    #[test]
    fn provider_secrets_are_redacted_and_bounded() {
        let secret = GithubProviderSecret::private_key(b"private".to_vec()).unwrap();
        assert_eq!(format!("{secret:?}"), "GithubProviderSecret([REDACTED])");
        assert_eq!(secret.expose_secret().len(), 7);
        assert_eq!(
            GithubProviderSecret::private_key(Vec::new()).unwrap_err(),
            GithubProviderValueError::InvalidPrivateKey
        );
        assert_eq!(
            GithubProviderSecret::webhook(Vec::new()).unwrap_err(),
            GithubProviderValueError::InvalidWebhookSecret
        );
    }

    #[test]
    fn repository_desired_set_is_complete_sorted_and_unique() {
        let command = ApplyWorkspaceGithubRepositoriesCommand::new(
            OperationId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            ShardId::new("local").unwrap(),
            WorkspaceId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
            WorkspaceGithubRepositoriesRevision::new(1).unwrap(),
            vec![repository(2, "owner/two"), repository(1, "owner/one")],
        )
        .unwrap();
        assert_eq!(command.repositories()[0].repository_id().get(), 1);

        assert_eq!(
            ApplyWorkspaceGithubRepositoriesCommand::new(
                OperationId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
                ShardId::new("local").unwrap(),
                WorkspaceId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
                WorkspaceGithubRepositoriesRevision::new(1).unwrap(),
                vec![repository(1, "owner/one"), repository(1, "owner/two")],
            )
            .unwrap_err(),
            GithubProviderValueError::DuplicateRepository
        );
    }

    #[test]
    fn private_repositories_cannot_claim_credential_free_execution() {
        assert_eq!(
            GithubProviderRepositorySelection::new(
                ProviderInstallationId::new(10).unwrap(),
                ProviderRepositoryId::new(30).unwrap(),
                ProviderRepositoryOwnerId::new(20).unwrap(),
                GithubRepositoryName::new("owner/private").unwrap(),
                "main",
                ProviderRepositoryVisibility::Private,
                JobAuthorityProfile::CredentialFree,
            )
            .unwrap_err(),
            GithubProviderValueError::InvalidRepository
        );
    }

    #[test]
    fn provider_configuration_authorizes_only_its_shard() {
        let configuration = GithubProviderConfiguration::new(
            Url::parse("https://ci.example/").unwrap(),
            GithubServerServiceAppId::new(1).unwrap(),
            GithubServerServiceAppClientId::new("Iv1.client").unwrap(),
            GithubServerServiceJwtIssuer::AppClientId,
            GithubProviderSecret::private_key(b"private".to_vec()).unwrap(),
            GithubProviderSecret::webhook(b"webhook".to_vec()).unwrap(),
            GithubCheckName::new("Automata CI").unwrap(),
            GithubRunnerPolicy::decode_configuration(RUNNER_POLICY).unwrap(),
            GithubProviderSchedulePolicy::default(),
        )
        .unwrap();
        let feature_policy = configuration.runner_policy().runtime_policy().mappings()[0]
            .runner_feature_policy()
            .expect("current provider policy carries a runner-feature ceiling");
        assert_eq!(feature_policy.supported().len(), 12);
        assert!(
            feature_policy
                .supported()
                .contains(&RunnerFeature::NODE24_ACTIONS)
        );
        let command = ApplyGithubProviderConfigurationCommand::new(
            OperationId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            ShardId::new("other").unwrap(),
            GithubProviderConfigurationRevision::new(1).unwrap(),
            configuration,
        );
        assert_eq!(
            AuthorizedApplyGithubProviderConfiguration::authorize(authority(), command)
                .unwrap_err()
                .to_string(),
            GithubProviderValueError::Forbidden.to_string()
        );
    }
}
