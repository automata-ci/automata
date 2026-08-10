//! Strict non-secret configuration for the optional GitHub provider product.

use std::{collections::BTreeSet, fmt, str::FromStr as _, sync::Arc};

use automata_ci_core::JobAuthorityProfile;
use automata_ci_store::{
    GithubCheckName, GithubProviderManifestRevision, GithubRepositoryName,
    GithubServerServiceAppClientId, GithubServerServiceAppId, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, ProviderInstallationId, ProviderRepositoryId,
    ProviderRepositoryOwnerId, ProviderRepositoryVisibility, TenantScope,
    WorkflowRuntimePolicyRevision, github_provider_repository_id,
};
use automata_ci_workflow_service::GithubRunnerPolicy;
use serde::Deserialize;
use serde_json::value::RawValue;
use thiserror::Error;
use zeroize::Zeroizing;

use super::SecretSource;

/// Maximum encoded size of the strict GitHub provider configuration document.
pub const MAX_GITHUB_PROVIDER_CONFIG_BYTES: usize = 256 * 1_024;
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
    app: GithubProviderAppConfig,
    webhook: GithubProviderWebhookConfig,
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
            app,
            webhook,
            repositories: repositories.into(),
        })
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
            .field("app", &self.app)
            .field("webhook", &self.webhook)
            .field("repository_count", &self.repositories.len())
            .field("public_repository_count", &public_repositories)
            .field(
                "private_repository_count",
                &(self.repositories.len() - public_repositories),
            )
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
    visibility: ProviderRepositoryVisibility,
    manifest_revision: GithubProviderManifestRevision,
    policy_revision: GithubServerServiceRevision,
    runtime_policy_revision: WorkflowRuntimePolicyRevision,
    authority_profile: JobAuthorityProfile,
    runner_policy: GithubRunnerPolicy,
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
            visibility,
            manifest_revision,
            policy_revision,
            runtime_policy_revision,
            authority_profile,
            runner_policy,
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
            .field("visibility", &self.visibility)
            .field("manifest_revision", &self.manifest_revision)
            .field("policy_revision", &self.policy_revision)
            .field("runtime_policy_revision", &self.runtime_policy_revision)
            .field("authority_profile", &self.authority_profile)
            .field("runner_policy", &"[validated]")
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
    app: RawApp,
    webhook: RawWebhook,
    repositories: Vec<RawRepository>,
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
