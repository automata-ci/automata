//! GitHub projection into the provider-neutral complete desired-state contract.

use automata_ci_key_management::SecretBytes;
use automata_ci_provider::{
    ExternalRepositoryId, ProviderArchiveLimits, ProviderConnectionId, ProviderDefaultBranch,
    ProviderLifecycleState, ProviderOrigins, ProviderRepositoryPath, ProviderRunnerPolicyBinding,
    ProviderSchemaVersion, ProviderSecretName, ProviderWorkflowSource, RepositoryVisibility,
};
use automata_ci_provider_delivery::{
    ProviderConnectionDesiredState, ProviderDesiredState, ProviderInstanceDesiredState,
    ProviderWebhookEndpointDesiredState,
};
use automata_ci_provider_github::{
    GITHUB_APP_PRIVATE_KEY_SECRET_NAME, GITHUB_WEBHOOK_SECRET_NAME, GithubConnectionPolicy,
    GithubInstanceConfiguration, GithubJwtIssuer,
};
use automata_ci_scm::RepositoryId;
use automata_ci_store::{
    GithubProviderManifestLimits, GithubServerServiceJwtIssuer, ProviderRepositoryVisibility,
    WORKFLOW_RUNTIME_POLICY_SCHEMA,
};
use url::Url;
use uuid::Uuid;

use super::{GithubProviderConfig, GithubProviderConfigError, GithubProviderTransport};

const COMMON_WORKFLOW_ROOT: &str = ".ci/workflows";
const RAW_WEBHOOK_RETENTION_MILLIS: u64 = 30 * 24 * 60 * 60 * 1_000;

pub(super) fn github_common_desired_state(
    config: &GithubProviderConfig,
    app_private_key: &[u8],
    webhook_secret: &[u8],
) -> Result<ProviderDesiredState, GithubProviderConfigError> {
    let (origins, archive_origin) = common_origins(config.transport())?;
    let app = config.app();
    let instance_configuration = GithubInstanceConfiguration::new(
        app.app_id().get(),
        app.client_id().as_str(),
        match app.jwt_issuer() {
            GithubServerServiceJwtIssuer::AppId => GithubJwtIssuer::AppId,
            GithubServerServiceJwtIssuer::AppClientId => GithubJwtIssuer::AppClientId,
        },
        archive_origin,
    )
    .map_err(|_| GithubProviderConfigError)?;
    let instance = ProviderInstanceDesiredState::new(
        config.instance_id(),
        automata_ci_provider::ProviderTypeId::new("github")
            .map_err(|_| GithubProviderConfigError)?,
        config.configuration_revision(),
        ProviderLifecycleState::Active,
        origins,
        instance_configuration
            .document()
            .map_err(|_| GithubProviderConfigError)?,
        [
            (
                ProviderSecretName::new(GITHUB_APP_PRIVATE_KEY_SECRET_NAME)
                    .map_err(|_| GithubProviderConfigError)?,
                SecretBytes::new(app_private_key.to_vec())
                    .map_err(|_| GithubProviderConfigError)?,
            ),
            (
                ProviderSecretName::new(GITHUB_WEBHOOK_SECRET_NAME)
                    .map_err(|_| GithubProviderConfigError)?,
                SecretBytes::new(webhook_secret.to_vec()).map_err(|_| GithubProviderConfigError)?,
            ),
        ],
        config.applied_at(),
    )
    .map_err(|_| GithubProviderConfigError)?;

    let limits = GithubProviderManifestLimits::github_dot_com_ci();
    let connections = common_connections(config, limits)?;
    let endpoint = ProviderWebhookEndpointDesiredState::new(
        config.endpoint_id(),
        limits.webhook_max_body_bytes(),
        RAW_WEBHOOK_RETENTION_MILLIS,
        vec![
            ProviderSecretName::new(GITHUB_WEBHOOK_SECRET_NAME)
                .map_err(|_| GithubProviderConfigError)?,
        ],
    )
    .map_err(|_| GithubProviderConfigError)?;
    ProviderDesiredState::new(instance, connections, endpoint)
        .map_err(|_| GithubProviderConfigError)
}

fn common_connections(
    config: &GithubProviderConfig,
    limits: GithubProviderManifestLimits,
) -> Result<Vec<ProviderConnectionDesiredState>, GithubProviderConfigError> {
    let archive_limits = ProviderArchiveLimits::new(
        limits.archive_max_compressed_bytes(),
        limits.archive_max_expanded_bytes(),
        limits.archive_max_entries(),
        limits.archive_max_entry_path_bytes(),
        limits.archive_max_workflows(),
        limits.workflow_max_bytes(),
    )
    .map_err(|_| GithubProviderConfigError)?;
    let runner_schema = ProviderSchemaVersion::new(WORKFLOW_RUNTIME_POLICY_SCHEMA)
        .map_err(|_| GithubProviderConfigError)?;
    let workflow_root =
        ProviderRepositoryPath::new(COMMON_WORKFLOW_ROOT).map_err(|_| GithubProviderConfigError)?;
    let mut connections = Vec::with_capacity(config.repositories().len());
    for repository in config.repositories() {
        let connection_id = ProviderConnectionId::from_uuid(Uuid::from_bytes(
            repository.connection_id().as_bytes(),
        ))
        .map_err(|_| GithubProviderConfigError)?;
        let tenant_id = automata_ci_core::ManagedTenantId::parse(repository.tenant().as_str())
            .map_err(|_| GithubProviderConfigError)?;
        let external_repository_id =
            ExternalRepositoryId::new(repository.repository_id().get().to_string())
                .map_err(|_| GithubProviderConfigError)?;
        let default_branch = repository
            .cache_repository()
            .default_branch_ref()
            .strip_prefix("refs/heads/")
            .ok_or(GithubProviderConfigError)?;
        let visibility = match repository.visibility() {
            ProviderRepositoryVisibility::Public => RepositoryVisibility::Public,
            ProviderRepositoryVisibility::Private => RepositoryVisibility::Private,
        };
        let adapter_policy = GithubConnectionPolicy::new(
            repository.installation_id().get(),
            RepositoryId::new(repository.repository_name().as_str())
                .map_err(|_| GithubProviderConfigError)?,
        )
        .and_then(|policy| policy.document())
        .map_err(|_| GithubProviderConfigError)?;
        connections.push(
            ProviderConnectionDesiredState::new(
                connection_id,
                tenant_id,
                external_repository_id,
                visibility,
                ProviderDefaultBranch::new(default_branch)
                    .map_err(|_| GithubProviderConfigError)?,
                ProviderWorkflowSource::Directory(workflow_root.clone()),
                ProviderRunnerPolicyBinding::new(
                    runner_schema,
                    repository
                        .runner_policy()
                        .runtime_policy()
                        .canonical_digest(),
                ),
                archive_limits,
                adapter_policy,
                repository.applied_at(),
            )
            .map_err(|_| GithubProviderConfigError)?,
        );
    }
    Ok(connections)
}

fn common_origins(
    transport: &GithubProviderTransport,
) -> Result<(ProviderOrigins, Url), GithubProviderConfigError> {
    match transport {
        GithubProviderTransport::GithubDotCom => Ok((
            ProviderOrigins::new("https://github.com/", "https://api.github.com/")
                .map_err(|_| GithubProviderConfigError)?,
            Url::parse("https://codeload.github.com/").map_err(|_| GithubProviderConfigError)?,
        )),
        GithubProviderTransport::LoopbackEmulator { api_base, .. } => {
            let mut web = api_base.clone();
            web.set_path("/");
            web.set_query(None);
            web.set_fragment(None);
            let origins = ProviderOrigins::new(web.as_str(), api_base.as_str())
                .map_err(|_| GithubProviderConfigError)?;
            Ok((origins, web))
        }
    }
}
