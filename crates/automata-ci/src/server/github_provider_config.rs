//! Strict non-secret configuration for the optional GitHub provider product.

use std::{collections::BTreeSet, fmt, str::FromStr as _, sync::Arc};

use automata_ci_core::JobAuthorityProfile;
use automata_ci_github_delivery::GithubScheduleServiceConfig;
use automata_ci_results_github::CacheRepositoryMetadata;
use automata_ci_store::{
    GithubCheckName, GithubProviderGitRef, GithubProviderManifestRevision,
    GithubProviderWorkflowSelection, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceJwtIssuer, GithubServerServiceRevision,
    ProviderInstallationId, ProviderRepositoryId, ProviderRepositoryOwnerId,
    ProviderRepositoryVisibility, TenantScope, WorkflowRuntimePolicyRevision,
    github_provider_repository_id,
};
use automata_ci_workflow_service::GithubRunnerPolicy;
use serde::Deserialize;
use serde_json::value::RawValue;
use thiserror::Error;
use url::{Host, Url};
use zeroize::Zeroizing;

use super::SecretSource;

/// Maximum encoded size of the strict GitHub provider configuration document.
pub const MAX_GITHUB_PROVIDER_CONFIG_BYTES: usize = 512 * 1_024;
/// Maximum exact repositories served by one shared GitHub webhook authority.
pub const MAX_GITHUB_PROVIDER_REPOSITORIES: usize = 256;

const CONFIG_SCHEMA: u16 = 1;

/// Sanitized GitHub provider configuration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub provider configuration is invalid")]
pub struct GithubProviderConfigError;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct ConfiguredUuid([u8; 16]);

impl ConfiguredUuid {
    fn parse(value: &str) -> Result<Self, GithubProviderConfigError> {
        if value.len() != 36 {
            return Err(GithubProviderConfigError);
        }
        let mut decoded = [0_u8; 16];
        let mut nibble_index = 0_usize;
        for (index, byte) in value.bytes().enumerate() {
            if matches!(index, 8 | 13 | 18 | 23) {
                if byte != b'-' {
                    return Err(GithubProviderConfigError);
                }
                continue;
            }
            let nibble = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => return Err(GithubProviderConfigError),
            };
            let output_index = nibble_index / 2;
            if nibble_index & 1 == 0 {
                decoded[output_index] = nibble << 4;
            } else {
                decoded[output_index] |= nibble;
            }
            nibble_index += 1;
        }
        if nibble_index != 32 || decoded.iter().all(|byte| *byte == 0) {
            return Err(GithubProviderConfigError);
        }
        Ok(Self(decoded))
    }
}

macro_rules! configured_uuid {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(ConfiguredUuid);

        impl $name {
            fn parse(value: &str) -> Result<Self, GithubProviderConfigError> {
                ConfiguredUuid::parse(value).map(Self)
            }

            /// Returns the canonical 16 UUID bytes for later adapter construction.
            #[must_use]
            pub const fn as_bytes(self) -> [u8; 16] {
                self.0.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&"[configured]")
                    .finish()
            }
        }
    };
}

configured_uuid!(
    /// Non-nil server-owned identity of one configured provider connection.
    GithubProviderConnectionId
);
configured_uuid!(
    /// Non-nil identity of one immutable provider service authority.
    GithubProviderAuthorityId
);

/// Server-derived non-nil internal repository UUID bound within one tenant.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubProviderInternalRepositoryId(ConfiguredUuid);

impl GithubProviderInternalRepositoryId {
    fn derive(tenant: &TenantScope, repository_id: ProviderRepositoryId) -> Self {
        let repository_id = github_provider_repository_id(tenant, repository_id);
        Self(ConfiguredUuid(*repository_id.as_uuid().as_bytes()))
    }

    /// Returns the canonical 16 UUID bytes for later adapter construction.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0.0
    }
}

impl fmt::Debug for GithubProviderInternalRepositoryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("GithubProviderInternalRepositoryId")
            .field(&"[server-derived]")
            .finish()
    }
}

/// One strict GitHub App, webhook authority, and repository registry.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubProviderConfig {
    transport: GithubProviderTransport,
    dashboard_url: Url,
    app: GithubProviderAppConfig,
    webhook: GithubProviderWebhookConfig,
    schedule: GithubProviderScheduleConfig,
    repositories: Arc<[GithubProviderRepositoryConfig]>,
}

impl GithubProviderConfig {
    /// Loads one bounded current configuration from an environment/file reference.
    ///
    /// This step validates only typed non-secret policy and nested source
    /// references. It deliberately does not load the App key or webhook secret.
    /// The later composition boundary must load the sole webhook source exactly
    /// once, construct the shared `GithubWebhookVerifier` from those bytes, and
    /// use the fingerprint derived internally by that verifier. That fingerprint
    /// and [`GithubProviderWebhookConfig::verifier_revision`] must be pinned into
    /// every configured repository manifest. There is no independently supplied
    /// or per-repository verifier fingerprint.
    ///
    /// # Errors
    ///
    /// Returns one sanitized error for unavailable/excessive input, malformed
    /// JSON, unknown fields, unsupported schema, invalid typed values, an
    /// incoherent visibility/authority shape, or duplicate identities.
    pub fn load(source: &SecretSource) -> Result<Self, GithubProviderConfigError> {
        let bytes = source
            .load_bytes(MAX_GITHUB_PROVIDER_CONFIG_BYTES)
            .map_err(|_| GithubProviderConfigError)?;
        let raw: RawConfig =
            serde_json::from_slice(&bytes).map_err(|_| GithubProviderConfigError)?;
        Self::from_raw(raw)
    }

    fn from_raw(raw: RawConfig) -> Result<Self, GithubProviderConfigError> {
        if raw.schema != CONFIG_SCHEMA
            || raw.repositories.is_empty()
            || raw.repositories.len() > MAX_GITHUB_PROVIDER_REPOSITORIES
        {
            return Err(GithubProviderConfigError);
        }
        let app = GithubProviderAppConfig::validate(raw.app)?;
        let webhook = GithubProviderWebhookConfig::validate(raw.webhook)?;
        let transport = GithubProviderTransport::validate(raw.transport)?;
        let dashboard_url = validate_dashboard_url(&raw.dashboard_url, &transport)?;
        let schedule = GithubProviderScheduleConfig::validate(raw.schedule)?;
        let mut repositories = raw
            .repositories
            .into_iter()
            .map(GithubProviderRepositoryConfig::validate)
            .collect::<Result<Vec<_>, _>>()?;
        validate_unique_repositories(&repositories)?;
        repositories.sort_unstable_by_key(|repository| {
            (repository.installation_id, repository.repository_id)
        });
        Ok(Self {
            transport,
            dashboard_url,
            app,
            webhook,
            schedule,
            repositories: repositories.into(),
        })
    }

    /// Returns the closed production or loopback-emulator transport policy.
    #[must_use]
    pub const fn transport(&self) -> &GithubProviderTransport {
        &self.transport
    }

    /// Returns the canonical public Automata dashboard origin used by Check Runs.
    #[must_use]
    pub const fn dashboard_url(&self) -> &Url {
        &self.dashboard_url
    }

    /// Returns the one App identity and private-key source authority.
    #[must_use]
    pub const fn app(&self) -> &GithubProviderAppConfig {
        &self.app
    }

    /// Returns the sole webhook secret source and verifier revision.
    #[must_use]
    pub const fn webhook(&self) -> &GithubProviderWebhookConfig {
        &self.webhook
    }

    /// Returns the bounded non-secret scheduler policy.
    #[must_use]
    pub const fn schedule(&self) -> GithubProviderScheduleConfig {
        self.schedule
    }

    /// Returns repositories in stable installation/repository numeric order.
    #[must_use]
    pub fn repositories(&self) -> &[GithubProviderRepositoryConfig] {
        &self.repositories
    }
}

impl fmt::Debug for GithubProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let public_repositories = self
            .repositories
            .iter()
            .filter(|repository| repository.visibility == ProviderRepositoryVisibility::Public)
            .count();
        formatter
            .debug_struct("GithubProviderConfig")
            .field("transport", &self.transport)
            .field("dashboard_url", &"[configured]")
            .field("app", &self.app)
            .field("webhook", &self.webhook)
            .field("schedule", &self.schedule)
            .field("repository_count", &self.repositories.len())
            .field("public_repository_count", &public_repositories)
            .field(
                "private_repository_count",
                &(self.repositories.len() - public_repositories),
            )
            .finish()
    }
}

fn validate_dashboard_url(
    value: &str,
    transport: &GithubProviderTransport,
) -> Result<Url, GithubProviderConfigError> {
    let url = Url::parse(value).map_err(|_| GithubProviderConfigError)?;
    if url.as_str() != value
        || url.cannot_be_a_base()
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(GithubProviderConfigError);
    }
    match transport {
        GithubProviderTransport::GithubDotCom if url.scheme() == "https" => Ok(url),
        GithubProviderTransport::LoopbackEmulator { .. }
            if url.scheme() == "https"
                || url.scheme() == "http"
                    && url
                        .host_str()
                        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
                        .is_some_and(|address| address.is_loopback()) =>
        {
            Ok(url)
        }
        GithubProviderTransport::GithubDotCom
        | GithubProviderTransport::LoopbackEmulator { .. } => Err(GithubProviderConfigError),
    }
}

/// Closed transport policy for GitHub provider HTTP operations.
///
/// Production always uses the fixed GitHub.com endpoints. Isolated E2E may
/// select one exact loopback HTTP API base; it cannot redirect or fall back to
/// another origin.
#[derive(Clone, Eq, PartialEq)]
pub enum GithubProviderTransport {
    /// Fixed public GitHub.com transport.
    GithubDotCom,
    /// Exact loopback control endpoint and mapped job origin owned by one
    /// isolated protocol emulator.
    LoopbackEmulator {
        api_base: Url,
        job_runtime_origin: Url,
    },
}

impl GithubProviderTransport {
    fn validate(raw: RawTransport) -> Result<Self, GithubProviderConfigError> {
        match raw {
            RawTransport::GithubDotCom => Ok(Self::GithubDotCom),
            RawTransport::LoopbackEmulator {
                api_base,
                job_runtime_origin,
            } => {
                let api_base = Url::parse(&api_base).map_err(|_| GithubProviderConfigError)?;
                let job_runtime_origin =
                    Url::parse(&job_runtime_origin).map_err(|_| GithubProviderConfigError)?;
                if !valid_loopback_api_base(&api_base)
                    || !valid_mapped_job_runtime_origin(&job_runtime_origin)
                    || api_base.port_or_known_default()
                        != job_runtime_origin.port_or_known_default()
                {
                    return Err(GithubProviderConfigError);
                }
                Ok(Self::LoopbackEmulator {
                    api_base,
                    job_runtime_origin,
                })
            }
        }
    }

    /// Returns the isolated emulator API base, when selected.
    #[must_use]
    pub const fn loopback_api_base(&self) -> Option<&Url> {
        match self {
            Self::GithubDotCom => None,
            Self::LoopbackEmulator { api_base, .. } => Some(api_base),
        }
    }

    /// Returns the exact container-mapped origin carried by repository job
    /// authorities for isolated emulation.
    #[must_use]
    pub const fn job_runtime_origin(&self) -> Option<&Url> {
        match self {
            Self::GithubDotCom => None,
            Self::LoopbackEmulator {
                job_runtime_origin, ..
            } => Some(job_runtime_origin),
        }
    }
}

impl fmt::Debug for GithubProviderTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::GithubDotCom => "GithubDotCom",
            Self::LoopbackEmulator { .. } => "LoopbackEmulator([configured])",
        })
    }
}

fn valid_loopback_api_base(url: &Url) -> bool {
    let loopback = match url.host() {
        Some(Host::Domain(domain)) => {
            domain.eq_ignore_ascii_case("localhost")
                || domain
                    .to_ascii_lowercase()
                    .strip_suffix(".localhost")
                    .is_some_and(|prefix| !prefix.is_empty())
        }
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    url.scheme() == "http"
        && loopback
        && url.username().is_empty()
        && url.password().is_none()
        && url.path().ends_with('/')
        && !url.cannot_be_a_base()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn valid_mapped_job_runtime_origin(url: &Url) -> bool {
    url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host.to_ascii_lowercase()
                .strip_suffix(".invalid")
                .is_some_and(|prefix| !prefix.is_empty())
        })
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
}

/// Validated bounded scheduler policy for the GitHub provider.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct GithubProviderScheduleConfig(GithubScheduleServiceConfig);

impl GithubProviderScheduleConfig {
    fn validate(raw: Option<RawSchedule>) -> Result<Self, GithubProviderConfigError> {
        let defaults = GithubScheduleServiceConfig::default();
        let raw = raw.unwrap_or_default();
        GithubScheduleServiceConfig::new(
            raw.poll_millis.unwrap_or(defaults.poll_millis()),
            raw.discovery_claim_millis
                .unwrap_or(defaults.discovery_claim_millis()),
            raw.fire_claim_millis
                .unwrap_or(defaults.fire_claim_millis()),
            raw.retry_millis.unwrap_or(defaults.retry_millis()),
            raw.staleness_millis.unwrap_or(defaults.staleness_millis()),
            raw.maximum_manifests
                .unwrap_or(defaults.maximum_manifests()),
            raw.maximum_fires_per_pass
                .unwrap_or(defaults.maximum_fires_per_pass()),
        )
        .map(Self)
        .map_err(|_| GithubProviderConfigError)
    }

    /// Returns the scheduler service's exact validated configuration.
    #[must_use]
    pub const fn service_config(self) -> GithubScheduleServiceConfig {
        self.0
    }
}

impl fmt::Debug for GithubProviderScheduleConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubProviderScheduleConfig")
            .field("poll_millis", &self.0.poll_millis())
            .field("discovery_claim_millis", &self.0.discovery_claim_millis())
            .field("fire_claim_millis", &self.0.fire_claim_millis())
            .field("retry_millis", &self.0.retry_millis())
            .field("staleness_millis", &self.0.staleness_millis())
            .field("maximum_manifests", &self.0.maximum_manifests())
            .field("maximum_fires_per_pass", &self.0.maximum_fires_per_pass())
            .finish()
    }
}

/// Validated GitHub App identity and private-key source reference.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubProviderAppConfig {
    app_id: GithubServerServiceAppId,
    client_id: GithubServerServiceAppClientId,
    jwt_issuer: GithubServerServiceJwtIssuer,
    private_key_source: SecretSource,
    configuration_revision: GithubServerServiceRevision,
}

impl GithubProviderAppConfig {
    fn validate(raw: RawApp) -> Result<Self, GithubProviderConfigError> {
        let RawApp {
            id,
            client_id,
            jwt_issuer,
            private_key_source,
            configuration_revision,
        } = raw;
        let private_key_source = Zeroizing::new(private_key_source);
        Ok(Self {
            app_id: GithubServerServiceAppId::new(id).map_err(|_| GithubProviderConfigError)?,
            client_id: GithubServerServiceAppClientId::new(client_id)
                .map_err(|_| GithubProviderConfigError)?,
            jwt_issuer: match jwt_issuer {
                RawJwtIssuer::AppId => GithubServerServiceJwtIssuer::AppId,
                RawJwtIssuer::AppClientId => GithubServerServiceJwtIssuer::AppClientId,
            },
            private_key_source: parse_secret_source(private_key_source.as_str())?,
            configuration_revision: GithubServerServiceRevision::new(configuration_revision)
                .map_err(|_| GithubProviderConfigError)?,
        })
    }

    /// Returns the positive numeric GitHub App identity.
    #[must_use]
    pub const fn app_id(&self) -> GithubServerServiceAppId {
        self.app_id
    }

    /// Returns the exact GitHub-issued App client identity.
    #[must_use]
    pub const fn client_id(&self) -> &GithubServerServiceAppClientId {
        &self.client_id
    }

    /// Returns the configured JWT `iss` identity family.
    #[must_use]
    pub const fn jwt_issuer(&self) -> GithubServerServiceJwtIssuer {
        self.jwt_issuer
    }

    /// Returns the validated reference to the App private-key material.
    ///
    /// Later composition must load it once, construct the signer from that key,
    /// and derive the App-key SPKI fingerprint pinned with this configuration
    /// revision; no key fingerprint is accepted from this document.
    #[must_use]
    pub const fn private_key_source(&self) -> &SecretSource {
        &self.private_key_source
    }

    /// Returns the positive immutable App configuration revision.
    #[must_use]
    pub const fn configuration_revision(&self) -> GithubServerServiceRevision {
        self.configuration_revision
    }
}

impl fmt::Debug for GithubProviderAppConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubProviderAppConfig")
            .field("app_id", &self.app_id)
            .field("client_id", &self.client_id)
            .field("jwt_issuer", &self.jwt_issuer)
            .field("private_key_source", &self.private_key_source)
            .field("configuration_revision", &self.configuration_revision)
            .finish()
    }
}

/// Sole configured webhook verification authority for all repositories.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubProviderWebhookConfig {
    hmac_secret_source: SecretSource,
    verifier_revision: GithubServerServiceRevision,
}

impl GithubProviderWebhookConfig {
    fn validate(raw: RawWebhook) -> Result<Self, GithubProviderConfigError> {
        let RawWebhook {
            hmac_secret_source,
            verifier_revision,
        } = raw;
        let hmac_secret_source = Zeroizing::new(hmac_secret_source);
        Ok(Self {
            hmac_secret_source: parse_secret_source(hmac_secret_source.as_str())?,
            verifier_revision: GithubServerServiceRevision::new(verifier_revision)
                .map_err(|_| GithubProviderConfigError)?,
        })
    }

    /// Returns the validated sole HMAC-secret source reference.
    ///
    /// Later composition must load this source only once, enforce the key-size
    /// policy, construct the shared verifier from those bytes, and use the
    /// fingerprint that verifier derives internally.
    #[must_use]
    pub const fn hmac_secret_source(&self) -> &SecretSource {
        &self.hmac_secret_source
    }

    /// Returns the sole revision that every later provider manifest must pin.
    ///
    /// The associated fingerprint is not configuration input. It must be
    /// derived from the same loaded secret bytes used for the shared verifier.
    #[must_use]
    pub const fn verifier_revision(&self) -> GithubServerServiceRevision {
        self.verifier_revision
    }
}

impl fmt::Debug for GithubProviderWebhookConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubProviderWebhookConfig")
            .field("hmac_secret_source", &self.hmac_secret_source)
            .field("verifier_revision", &self.verifier_revision)
            .finish()
    }
}

/// Exact configured repository and its visibility-dependent service authorities.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubProviderRepositoryConfig {
    tenant: TenantScope,
    internal_repository_id: GithubProviderInternalRepositoryId,
    connection_id: GithubProviderConnectionId,
    installation_id: ProviderInstallationId,
    repository_id: ProviderRepositoryId,
    repository_owner_id: ProviderRepositoryOwnerId,
    repository_name: GithubRepositoryName,
    cache_repository: CacheRepositoryMetadata,
    workflow_git_ref: GithubProviderGitRef,
    visibility: ProviderRepositoryVisibility,
    manifest_revision: GithubProviderManifestRevision,
    policy_revision: GithubServerServiceRevision,
    runtime_policy_revision: WorkflowRuntimePolicyRevision,
    authority_profile: JobAuthorityProfile,
    runner_policy: GithubRunnerPolicy,
    workflow_selection: GithubProviderWorkflowSelection,
    check_name: GithubCheckName,
    checks_write_authority: GithubProviderAuthorityConfig,
    private_source_authority: Option<GithubProviderAuthorityConfig>,
}

impl GithubProviderRepositoryConfig {
    fn validate(raw: RawRepository) -> Result<Self, GithubProviderConfigError> {
        let tenant = TenantScope::from_authenticated_tenant_id(raw.tenant_id)
            .map_err(|_| GithubProviderConfigError)?;
        let connection_id = GithubProviderConnectionId::parse(&raw.connection_id)?;
        let installation_id = ProviderInstallationId::new(raw.installation_id)
            .map_err(|_| GithubProviderConfigError)?;
        let repository_id =
            ProviderRepositoryId::new(raw.repository_id).map_err(|_| GithubProviderConfigError)?;
        let internal_repository_id =
            GithubProviderInternalRepositoryId::derive(&tenant, repository_id);
        let repository_owner_id = ProviderRepositoryOwnerId::new(raw.repository_owner_id)
            .map_err(|_| GithubProviderConfigError)?;
        let repository_name =
            GithubRepositoryName::new(raw.repository).map_err(|_| GithubProviderConfigError)?;
        let cache_repository =
            CacheRepositoryMetadata::new(repository_name.as_str(), raw.default_branch)
                .map_err(|_| GithubProviderConfigError)?;
        let workflow_git_ref = GithubProviderGitRef::new(cache_repository.default_branch_ref())
            .map_err(|_| GithubProviderConfigError)?;
        let visibility = match raw.visibility {
            RawVisibility::Public => ProviderRepositoryVisibility::Public,
            RawVisibility::Private => ProviderRepositoryVisibility::Private,
        };
        let manifest_revision = GithubProviderManifestRevision::new(raw.manifest_revision)
            .map_err(|_| GithubProviderConfigError)?;
        let policy_revision = GithubServerServiceRevision::new(raw.policy_revision)
            .map_err(|_| GithubProviderConfigError)?;
        let runtime_policy_revision =
            WorkflowRuntimePolicyRevision::new(raw.runtime_policy_revision)
                .map_err(|_| GithubProviderConfigError)?;
        let authority_profile = match raw.authority_profile {
            RawAuthorityProfile::Standard => JobAuthorityProfile::Standard,
            RawAuthorityProfile::CredentialFree => JobAuthorityProfile::CredentialFree,
        };
        // `RawValue` retains the byte-exact nested object, including duplicate
        // member evidence. The projection codec delegates these bytes exactly
        // once to Store's sole `WorkflowRuntimePolicy` decoder.
        let runner_policy_bytes = raw.runner_policy.get().as_bytes();
        let runner_policy = GithubRunnerPolicy::decode_configuration(runner_policy_bytes)
            .map_err(|_| GithubProviderConfigError)?;
        let workflow_selection = GithubProviderWorkflowSelection::all_direct();
        let check_name =
            GithubCheckName::new(raw.check_name).map_err(|_| GithubProviderConfigError)?;
        let RawAuthorities {
            checks_write,
            private_repository_source_read,
        } = raw.authorities;
        let checks_write_authority = GithubProviderAuthorityConfig::validate(&checks_write)?;
        let private_source_authority = match (visibility, private_repository_source_read) {
            (ProviderRepositoryVisibility::Public, RawPrivateAuthority::Null(())) => None,
            (ProviderRepositoryVisibility::Private, RawPrivateAuthority::Authority(authority)) => {
                Some(GithubProviderAuthorityConfig::validate(&authority)?)
            }
            _ => return Err(GithubProviderConfigError),
        };
        if checks_write_authority.policy_revision != policy_revision
            || private_source_authority
                .as_ref()
                .is_some_and(|authority| authority.policy_revision != policy_revision)
        {
            return Err(GithubProviderConfigError);
        }
        Ok(Self {
            tenant,
            internal_repository_id,
            connection_id,
            installation_id,
            repository_id,
            repository_owner_id,
            repository_name,
            cache_repository,
            workflow_git_ref,
            visibility,
            manifest_revision,
            policy_revision,
            runtime_policy_revision,
            authority_profile,
            runner_policy,
            workflow_selection,
            check_name,
            checks_write_authority,
            private_source_authority,
        })
    }

    /// Returns the exact tenant bound to this repository.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    /// Returns the non-nil internal repository binding.
    #[must_use]
    pub const fn internal_repository_id(&self) -> GithubProviderInternalRepositoryId {
        self.internal_repository_id
    }

    /// Returns the server-owned non-nil provider connection identity.
    #[must_use]
    pub const fn connection_id(&self) -> GithubProviderConnectionId {
        self.connection_id
    }

    /// Returns the positive GitHub App installation identity.
    #[must_use]
    pub const fn installation_id(&self) -> ProviderInstallationId {
        self.installation_id
    }

    /// Returns the stable positive GitHub repository identity.
    #[must_use]
    pub const fn repository_id(&self) -> ProviderRepositoryId {
        self.repository_id
    }

    /// Returns the stable positive numeric GitHub owner identity.
    #[must_use]
    pub const fn repository_owner_id(&self) -> ProviderRepositoryOwnerId {
        self.repository_owner_id
    }

    /// Returns the exact canonical case-sensitive `owner/repository` identity.
    #[must_use]
    pub const fn repository_name(&self) -> &GithubRepositoryName {
        &self.repository_name
    }

    /// Returns server-owned cache metadata for this repository.
    #[must_use]
    pub const fn cache_repository(&self) -> &CacheRepositoryMetadata {
        &self.cache_repository
    }

    /// Returns the revisioned full default-branch ref used for workflow selection.
    #[must_use]
    pub const fn workflow_git_ref(&self) -> &GithubProviderGitRef {
        &self.workflow_git_ref
    }

    /// Returns the exact authenticated visibility expected from signed payloads.
    #[must_use]
    pub const fn visibility(&self) -> ProviderRepositoryVisibility {
        self.visibility
    }

    /// Returns the positive immutable provider-manifest revision.
    #[must_use]
    pub const fn manifest_revision(&self) -> GithubProviderManifestRevision {
        self.manifest_revision
    }

    /// Returns the policy revision shared by the manifest and both authorities.
    #[must_use]
    pub const fn policy_revision(&self) -> GithubServerServiceRevision {
        self.policy_revision
    }

    /// Returns the independent sequential relational runner-policy revision.
    #[must_use]
    pub const fn runtime_policy_revision(&self) -> WorkflowRuntimePolicyRevision {
        self.runtime_policy_revision
    }

    /// Returns the required immutable job-visible authority profile.
    #[must_use]
    pub const fn authority_profile(&self) -> JobAuthorityProfile {
        self.authority_profile
    }

    /// Returns the mandatory canonical historical runner/workspace policy.
    #[must_use]
    pub const fn runner_policy(&self) -> &GithubRunnerPolicy {
        &self.runner_policy
    }

    /// Returns the explicit immutable workflow discovery policy.
    #[must_use]
    pub const fn workflow_selection(&self) -> &GithubProviderWorkflowSelection {
        &self.workflow_selection
    }

    /// Returns the exact provider-facing Check Run name.
    #[must_use]
    pub const fn check_name(&self) -> &GithubCheckName {
        &self.check_name
    }

    /// Returns the mandatory exact Checks-write authority configuration.
    #[must_use]
    pub const fn checks_write_authority(&self) -> &GithubProviderAuthorityConfig {
        &self.checks_write_authority
    }

    /// Returns the exact private-source authority only for a Private repository.
    #[must_use]
    pub const fn private_source_authority(&self) -> Option<&GithubProviderAuthorityConfig> {
        self.private_source_authority.as_ref()
    }
}

impl fmt::Debug for GithubProviderRepositoryConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubProviderRepositoryConfig")
            .field("tenant", &"[redacted]")
            .field("internal_repository_id", &self.internal_repository_id)
            .field("connection_id", &self.connection_id)
            .field("installation_id", &self.installation_id)
            .field("repository_id", &self.repository_id)
            .field("repository_owner_id", &self.repository_owner_id)
            .field("repository_name", &"[redacted]")
            .field("cache_repository", &"[configured]")
            .field("visibility", &self.visibility)
            .field("manifest_revision", &self.manifest_revision)
            .field("policy_revision", &self.policy_revision)
            .field("runtime_policy_revision", &self.runtime_policy_revision)
            .field("authority_profile", &self.authority_profile)
            .field("runner_policy", &"[validated]")
            .field("workflow_git_ref", &"[redacted]")
            .field(
                "workflow_selection",
                &self.workflow_selection.as_durable_str(),
            )
            .field("check_name", &"[redacted]")
            .field("checks_write_authority", &self.checks_write_authority)
            .field("private_source_authority", &self.private_source_authority)
            .finish()
    }
}

/// Exact immutable service-authority UUID and policy revision.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubProviderAuthorityConfig {
    authority_id: GithubProviderAuthorityId,
    policy_revision: GithubServerServiceRevision,
}

impl GithubProviderAuthorityConfig {
    fn validate(raw: &RawAuthority) -> Result<Self, GithubProviderConfigError> {
        Ok(Self {
            authority_id: GithubProviderAuthorityId::parse(&raw.authority_id)?,
            policy_revision: GithubServerServiceRevision::new(raw.policy_revision)
                .map_err(|_| GithubProviderConfigError)?,
        })
    }

    /// Returns the globally unique non-nil authority UUID.
    #[must_use]
    pub const fn authority_id(&self) -> GithubProviderAuthorityId {
        self.authority_id
    }

    /// Returns the positive immutable authority policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> GithubServerServiceRevision {
        self.policy_revision
    }
}

impl fmt::Debug for GithubProviderAuthorityConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubProviderAuthorityConfig")
            .field("authority_id", &self.authority_id)
            .field("policy_revision", &self.policy_revision)
            .finish()
    }
}

fn parse_secret_source(value: &str) -> Result<SecretSource, GithubProviderConfigError> {
    let source = SecretSource::from_str(value).unwrap_or(SecretSource::Invalid);
    if matches!(source, SecretSource::Environment(_) | SecretSource::File(_)) {
        Ok(source)
    } else {
        Err(GithubProviderConfigError)
    }
}

fn validate_unique_repositories(
    repositories: &[GithubProviderRepositoryConfig],
) -> Result<(), GithubProviderConfigError> {
    let mut connection_ids = BTreeSet::new();
    let mut selectors = BTreeSet::new();
    let mut repository_ids = BTreeSet::new();
    let mut repository_names = BTreeSet::new();
    let mut internal_repository_ids = BTreeSet::new();
    let mut authority_ids = BTreeSet::new();
    for repository in repositories {
        if !connection_ids.insert(repository.connection_id)
            || !selectors.insert((repository.installation_id, repository.repository_id))
            || !repository_ids.insert(repository.repository_id)
            || !repository_names.insert(repository.repository_name.as_str().to_ascii_lowercase())
            || !internal_repository_ids.insert(repository.internal_repository_id)
            || !authority_ids.insert(repository.checks_write_authority.authority_id)
            || repository
                .private_source_authority
                .as_ref()
                .is_some_and(|authority| !authority_ids.insert(authority.authority_id))
        {
            return Err(GithubProviderConfigError);
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    schema: u16,
    transport: RawTransport,
    dashboard_url: String,
    app: RawApp,
    webhook: RawWebhook,
    #[serde(default)]
    schedule: Option<RawSchedule>,
    repositories: Vec<RawRepository>,
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum RawTransport {
    GithubDotCom,
    LoopbackEmulator {
        api_base: String,
        job_runtime_origin: String,
    },
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSchedule {
    poll_millis: Option<i64>,
    discovery_claim_millis: Option<i64>,
    fire_claim_millis: Option<i64>,
    retry_millis: Option<i64>,
    staleness_millis: Option<i64>,
    maximum_manifests: Option<u16>,
    maximum_fires_per_pass: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApp {
    id: u64,
    client_id: String,
    jwt_issuer: RawJwtIssuer,
    private_key_source: String,
    configuration_revision: u64,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawJwtIssuer {
    AppId,
    AppClientId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWebhook {
    hmac_secret_source: String,
    verifier_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRepository {
    tenant_id: String,
    connection_id: String,
    installation_id: u64,
    repository_id: u64,
    repository_owner_id: u64,
    repository: String,
    default_branch: String,
    visibility: RawVisibility,
    manifest_revision: u64,
    policy_revision: u64,
    runtime_policy_revision: u64,
    authority_profile: RawAuthorityProfile,
    /// Exact raw JSON retained until Store's sole typed policy codec consumes it.
    runner_policy: Box<RawValue>,
    check_name: String,
    authorities: RawAuthorities,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawVisibility {
    Public,
    Private,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawAuthorityProfile {
    Standard,
    CredentialFree,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuthorities {
    checks_write: RawAuthority,
    private_repository_source_read: RawPrivateAuthority,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawPrivateAuthority {
    Authority(RawAuthority),
    Null(()),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuthority {
    authority_id: String,
    policy_revision: u64,
}
