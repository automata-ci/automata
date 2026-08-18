//! Typed GitHub provider configuration and factory composition.

use std::{fmt, num::NonZeroU64};

use automata_ci_core::GitObjectAlgorithm;
use automata_ci_provider::{
    ChangedFileCapability, ChangedFileCompleteness, ProviderCapabilities, ProviderCapability,
    ProviderConfigurationDocument, ProviderConfigurationFactory, ProviderConnectionFactoryRequest,
    ProviderConnectionManifest, ProviderConnectionPolicyDocument, ProviderFactoryRequest,
    ProviderFactoryValidationError, ProviderInstanceManifest, ProviderSchemaVersion,
    ProviderTypeId, RepositoryEventCapability, RepositoryEventKind, RichCheckCapability,
    SourceReadCapability,
};
use automata_ci_scm::{RepositoryId, RepositorySourceConnection};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::{GITHUB_API_VERSION, GithubHttpEndpoint, GithubHttpLimits, GithubTrustedOrigins};

const GITHUB_CONFIGURATION_SCHEMA: u16 = 2;
const GITHUB_CONNECTION_SCHEMA: u16 = 1;
const MAX_GITHUB_INSTALLATION_ID: u64 = i64::MAX as u64;
const MAX_GITHUB_APP_PRIVATE_KEY_BYTES: usize = 32 * 1_024;
/// Canonical provider-instance secret name for the GitHub App private key.
pub const GITHUB_APP_PRIVATE_KEY_SECRET_NAME: &str = "app-private-key";
/// Canonical provider-instance secret name for webhook HMAC verification.
pub const GITHUB_WEBHOOK_SECRET_NAME: &str = "webhook-secret";

/// Canonical non-secret configuration owned by one GitHub provider instance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GithubInstanceConfiguration {
    app_id: NonZeroU64,
    app_client_id: String,
    jwt_issuer: GithubJwtIssuer,
    rest_api_version: String,
    archive_origin: String,
}

/// GitHub App identity placed in the `iss` claim of short-lived App JWTs.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubJwtIssuer {
    /// Use the numeric GitHub App identity.
    AppId,
    /// Use the App's stable client identity.
    AppClientId,
}

impl GithubInstanceConfiguration {
    /// Creates one GitHub instance policy with an explicit archive authority.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical credential-bearing or non-HTTPS origin.
    pub fn new(
        app_id: u64,
        app_client_id: impl Into<String>,
        jwt_issuer: GithubJwtIssuer,
        archive_origin: Url,
    ) -> Result<Self, GithubFactoryError> {
        validate_archive_origin(&archive_origin)?;
        let app_id = NonZeroU64::new(app_id)
            .filter(|value| value.get() <= MAX_GITHUB_INSTALLATION_ID)
            .ok_or(GithubFactoryError::InvalidConfiguration)?;
        let app_client_id = app_client_id.into();
        if app_client_id.is_empty()
            || app_client_id.len() > 255
            || !app_client_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(GithubFactoryError::InvalidConfiguration);
        }
        Ok(Self {
            app_id,
            app_client_id,
            jwt_issuer,
            rest_api_version: GITHUB_API_VERSION.to_owned(),
            archive_origin: archive_origin.into(),
        })
    }

    /// Returns the configured GitHub App identity.
    #[must_use]
    pub const fn app_id(&self) -> NonZeroU64 {
        self.app_id
    }

    /// Returns the configured GitHub App client identity.
    #[must_use]
    pub fn app_client_id(&self) -> &str {
        &self.app_client_id
    }

    /// Returns the configured App JWT issuer form.
    #[must_use]
    pub const fn jwt_issuer(&self) -> GithubJwtIssuer {
        self.jwt_issuer
    }

    /// Returns the pinned GitHub REST API version.
    #[must_use]
    pub fn rest_api_version(&self) -> &str {
        &self.rest_api_version
    }

    /// Returns the exact configured archive origin.
    ///
    /// # Errors
    ///
    /// Returns [`GithubFactoryError::InvalidConfiguration`] if the retained
    /// canonical URL can no longer be decoded.
    pub fn archive_origin(&self) -> Result<Url, GithubFactoryError> {
        Url::parse(&self.archive_origin).map_err(|_| GithubFactoryError::InvalidConfiguration)
    }

    /// Encodes this value as the canonical adapter configuration document.
    ///
    /// # Errors
    ///
    /// Returns [`GithubFactoryError::InvalidConfiguration`] if serialization
    /// or common document validation fails.
    pub fn document(&self) -> Result<ProviderConfigurationDocument, GithubFactoryError> {
        let bytes =
            serde_json::to_vec(self).map_err(|_| GithubFactoryError::InvalidConfiguration)?;
        ProviderConfigurationDocument::new(
            ProviderSchemaVersion::new(GITHUB_CONFIGURATION_SCHEMA)
                .map_err(|_| GithubFactoryError::InvalidConfiguration)?,
            bytes,
        )
        .map_err(|_| GithubFactoryError::InvalidConfiguration)
    }

    /// Decodes the current exact canonical GitHub instance schema.
    ///
    /// # Errors
    ///
    /// Rejects schema drift, unknown fields, noncanonical bytes, or invalid values.
    pub fn decode(document: &ProviderConfigurationDocument) -> Result<Self, GithubFactoryError> {
        decode_instance(document)
    }
}

/// Canonical GitHub-specific policy for one repository connection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GithubConnectionPolicy {
    installation_id: NonZeroU64,
    repository: RepositoryId,
}

impl GithubConnectionPolicy {
    /// Binds a GitHub App installation and current repository route.
    ///
    /// # Errors
    ///
    /// Rejects zero or values outside the durable signed 64-bit range.
    pub fn new(installation_id: u64, repository: RepositoryId) -> Result<Self, GithubFactoryError> {
        let installation_id = NonZeroU64::new(installation_id)
            .filter(|value| value.get() <= MAX_GITHUB_INSTALLATION_ID)
            .ok_or(GithubFactoryError::InvalidConnection)?;
        Ok(Self {
            installation_id,
            repository,
        })
    }

    /// Returns the exact GitHub App installation identity.
    #[must_use]
    pub const fn installation_id(&self) -> NonZeroU64 {
        self.installation_id
    }

    /// Returns the current provider-owned repository route.
    #[must_use]
    pub const fn repository(&self) -> &RepositoryId {
        &self.repository
    }

    /// Encodes this value as the canonical adapter connection policy.
    ///
    /// # Errors
    ///
    /// Returns [`GithubFactoryError::InvalidConnection`] if serialization or
    /// common document validation fails.
    pub fn document(&self) -> Result<ProviderConnectionPolicyDocument, GithubFactoryError> {
        let bytes = serde_json::to_vec(self).map_err(|_| GithubFactoryError::InvalidConnection)?;
        ProviderConnectionPolicyDocument::new(
            ProviderSchemaVersion::new(GITHUB_CONNECTION_SCHEMA)
                .map_err(|_| GithubFactoryError::InvalidConnection)?,
            bytes,
        )
        .map_err(|_| GithubFactoryError::InvalidConnection)
    }

    /// Decodes the current exact canonical GitHub connection policy schema.
    ///
    /// # Errors
    ///
    /// Rejects schema drift, unknown fields, noncanonical bytes, or invalid values.
    pub fn decode(document: &ProviderConnectionPolicyDocument) -> Result<Self, GithubFactoryError> {
        decode_connection(document)
    }
}

/// Static GitHub adapter factory registered under the `github` provider type.
pub struct GithubProviderFactory {
    provider_type: ProviderTypeId,
}

impl GithubProviderFactory {
    /// Constructs the built-in GitHub provider factory.
    ///
    /// # Panics
    ///
    /// Panics only if the compile-time `github` provider type stops satisfying
    /// the common identifier contract.
    #[must_use]
    pub fn new() -> Self {
        Self {
            provider_type: ProviderTypeId::new("github")
                .expect("the built-in GitHub provider type is canonical"),
        }
    }

    /// Returns the GitHub capability declaration available at this migration stage.
    ///
    /// # Errors
    ///
    /// Returns [`GithubFactoryError::InvalidCapabilities`] if the built-in
    /// declaration violates the common capability contract.
    pub fn capabilities() -> Result<ProviderCapabilities, GithubFactoryError> {
        let events = [
            RepositoryEventKind::Push,
            RepositoryEventKind::PullRequest,
            RepositoryEventKind::MergeQueue,
            RepositoryEventKind::RepositoryDispatch,
        ];
        ProviderCapabilities::new([
            ProviderCapability::SourceRead(
                SourceReadCapability::new([GitObjectAlgorithm::Sha1])
                    .map_err(|_| GithubFactoryError::InvalidCapabilities)?,
            ),
            ProviderCapability::RepositoryEvents(
                RepositoryEventCapability::new(events)
                    .map_err(|_| GithubFactoryError::InvalidCapabilities)?,
            ),
            ProviderCapability::ChangedFiles(
                ChangedFileCapability::new(
                    [RepositoryEventKind::Push, RepositoryEventKind::PullRequest],
                    ChangedFileCompleteness::ExplicitlyIncomplete,
                )
                .map_err(|_| GithubFactoryError::InvalidCapabilities)?,
            ),
            ProviderCapability::RichChecks(
                RichCheckCapability::new(true, false, true)
                    .map_err(|_| GithubFactoryError::InvalidCapabilities)?,
            ),
        ])
        .map_err(|_| GithubFactoryError::InvalidCapabilities)
    }

    /// Constructs the hardened HTTP/source adapter from non-secret manifest policy.
    ///
    /// # Errors
    ///
    /// Rejects a manifest for another provider type, invalid or noncanonical
    /// configuration, or unsafe provider origins. Plaintext instance secrets
    /// are never passed to this source-only constructor.
    pub fn repository_source(
        &self,
        manifest: &ProviderInstanceManifest,
        user_agent: &str,
        limits: GithubHttpLimits,
    ) -> Result<GithubHttpEndpoint, GithubFactoryError> {
        if manifest.provider_type() != &self.provider_type {
            return Err(GithubFactoryError::ProviderTypeMismatch);
        }
        let configuration = decode_instance(manifest.configuration())?;
        let web =
            Url::parse(manifest.origins().web()).map_err(|_| GithubFactoryError::InvalidOrigins)?;
        let api =
            Url::parse(manifest.origins().api()).map_err(|_| GithubFactoryError::InvalidOrigins)?;
        let trusted = GithubTrustedOrigins::new(web, api, user_agent, limits)
            .map_err(|_| GithubFactoryError::InvalidOrigins)?;
        GithubHttpEndpoint::new_with_archive_origin(trusted, configuration.archive_origin()?)
            .map_err(|_| GithubFactoryError::InvalidOrigins)
    }

    /// Projects one validated connection into the narrow exact-source contract.
    ///
    /// # Errors
    ///
    /// Rejects provider, instance, revision, configuration, capability, or
    /// connection-policy drift.
    pub fn source_connection(
        &self,
        provider: &ProviderInstanceManifest,
        connection: &ProviderConnectionManifest,
    ) -> Result<RepositorySourceConnection, GithubFactoryError> {
        let configuration = connection.configuration();
        if provider.provider_type() != &self.provider_type
            || configuration.repository().instance_id() != provider.instance_id()
            || configuration.provider_revision() != provider.revision()
            || configuration.provider_configuration_digest() != provider.configuration().digest()
            || configuration.capability_digest() != provider.capability_digest()
        {
            return Err(GithubFactoryError::ProviderTypeMismatch);
        }
        let policy = decode_connection(configuration.adapter_policy())?;
        Ok(RepositorySourceConnection::new(
            connection.connection_id(),
            connection
                .configuration()
                .repository()
                .external_id()
                .clone(),
            policy.repository,
        ))
    }
}

impl Default for GithubProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for GithubProviderFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubProviderFactory")
            .field("provider_type", &self.provider_type)
            .finish()
    }
}

impl ProviderConfigurationFactory for GithubProviderFactory {
    fn provider_type(&self) -> &ProviderTypeId {
        &self.provider_type
    }

    fn validate_instance(
        &self,
        request: ProviderFactoryRequest<'_>,
    ) -> Result<ProviderCapabilities, ProviderFactoryValidationError> {
        validate_instance_secrets(request).map_err(map_instance_validation_error)?;
        if request.provider_type() != &self.provider_type {
            return Err(ProviderFactoryValidationError::InvalidConfiguration);
        }
        let web = Url::parse(request.origins().web())
            .map_err(|_| ProviderFactoryValidationError::InvalidOrigins)?;
        let api = Url::parse(request.origins().api())
            .map_err(|_| ProviderFactoryValidationError::InvalidOrigins)?;
        let configuration =
            decode_instance(request.configuration()).map_err(map_instance_validation_error)?;
        let trusted = GithubTrustedOrigins::new(
            web,
            api,
            "automata-provider-validation/1",
            GithubHttpLimits::default(),
        )
        .map_err(|_| ProviderFactoryValidationError::InvalidOrigins)?;
        trusted
            .validate_archive_origin(
                &configuration
                    .archive_origin()
                    .map_err(map_instance_validation_error)?,
            )
            .map_err(|_| ProviderFactoryValidationError::InvalidOrigins)?;
        Self::capabilities().map_err(|_| ProviderFactoryValidationError::InvalidCapabilities)
    }

    fn validate_connection(
        &self,
        request: ProviderConnectionFactoryRequest<'_>,
    ) -> Result<(), ProviderFactoryValidationError> {
        decode_connection(request.connection().configuration().adapter_policy())
            .map(|_| ())
            .map_err(|error| match error {
                GithubFactoryError::UnsupportedSchema => {
                    ProviderFactoryValidationError::UnsupportedSchema
                }
                _ => ProviderFactoryValidationError::InvalidConfiguration,
            })
    }
}

fn decode_instance(
    document: &ProviderConfigurationDocument,
) -> Result<GithubInstanceConfiguration, GithubFactoryError> {
    if document.schema_version().get() != GITHUB_CONFIGURATION_SCHEMA {
        return Err(GithubFactoryError::UnsupportedSchema);
    }
    let decoded = serde_json::from_slice::<GithubInstanceConfiguration>(document.bytes())
        .map_err(|_| GithubFactoryError::InvalidConfiguration)?;
    let canonical =
        serde_json::to_vec(&decoded).map_err(|_| GithubFactoryError::InvalidConfiguration)?;
    if canonical != document.bytes() || decoded.rest_api_version != GITHUB_API_VERSION {
        return Err(GithubFactoryError::InvalidConfiguration);
    }
    validate_archive_origin(&decoded.archive_origin()?)?;
    Ok(decoded)
}

pub(crate) fn decode_connection(
    document: &ProviderConnectionPolicyDocument,
) -> Result<GithubConnectionPolicy, GithubFactoryError> {
    if document.schema_version().get() != GITHUB_CONNECTION_SCHEMA {
        return Err(GithubFactoryError::UnsupportedSchema);
    }
    let decoded = serde_json::from_slice::<GithubConnectionPolicy>(document.bytes())
        .map_err(|_| GithubFactoryError::InvalidConnection)?;
    let canonical =
        serde_json::to_vec(&decoded).map_err(|_| GithubFactoryError::InvalidConnection)?;
    if canonical != document.bytes() || decoded.installation_id.get() > MAX_GITHUB_INSTALLATION_ID {
        return Err(GithubFactoryError::InvalidConnection);
    }
    Ok(decoded)
}

fn validate_instance_secrets(
    request: ProviderFactoryRequest<'_>,
) -> Result<(), GithubFactoryError> {
    let app_key_name =
        automata_ci_provider::ProviderSecretName::new(GITHUB_APP_PRIVATE_KEY_SECRET_NAME)
            .map_err(|_| GithubFactoryError::InvalidSecrets)?;
    let webhook_name = automata_ci_provider::ProviderSecretName::new(GITHUB_WEBHOOK_SECRET_NAME)
        .map_err(|_| GithubFactoryError::InvalidSecrets)?;
    let bindings = request.secret_bindings();
    if bindings.len() != 2
        || bindings.get(&app_key_name).is_none()
        || bindings.get(&webhook_name).is_none()
    {
        return Err(GithubFactoryError::InvalidSecrets);
    }
    let app_key = request
        .secrets()
        .get(&app_key_name)
        .ok_or(GithubFactoryError::InvalidSecrets)?;
    if app_key.len() > MAX_GITHUB_APP_PRIVATE_KEY_BYTES
        || !app_key.expose_secret().starts_with(b"-----BEGIN ")
    {
        return Err(GithubFactoryError::InvalidSecrets);
    }
    let webhook = request
        .secrets()
        .get(&webhook_name)
        .ok_or(GithubFactoryError::InvalidSecrets)?;
    crate::GithubWebhookVerifier::new(webhook.expose_secret())
        .map(|_| ())
        .map_err(|_| GithubFactoryError::InvalidSecrets)
}

fn validate_archive_origin(origin: &Url) -> Result<(), GithubFactoryError> {
    if origin.scheme() != "https"
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(GithubFactoryError::InvalidOrigins);
    }
    Ok(())
}

fn map_instance_validation_error(error: GithubFactoryError) -> ProviderFactoryValidationError {
    match error {
        GithubFactoryError::UnsupportedSchema => ProviderFactoryValidationError::UnsupportedSchema,
        GithubFactoryError::InvalidOrigins => ProviderFactoryValidationError::InvalidOrigins,
        GithubFactoryError::InvalidSecrets => ProviderFactoryValidationError::InvalidSecrets,
        GithubFactoryError::InvalidCapabilities => {
            ProviderFactoryValidationError::InvalidCapabilities
        }
        GithubFactoryError::InvalidConfiguration
        | GithubFactoryError::InvalidConnection
        | GithubFactoryError::ProviderTypeMismatch => {
            ProviderFactoryValidationError::InvalidConfiguration
        }
    }
}

/// Sanitized GitHub factory and typed-policy failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubFactoryError {
    /// The adapter document schema is not implemented.
    #[error("GitHub provider schema is unsupported")]
    UnsupportedSchema,
    /// The instance document is malformed or noncanonical.
    #[error("GitHub provider configuration is invalid")]
    InvalidConfiguration,
    /// Common or adapter-owned origins violate the GitHub trust policy.
    #[error("GitHub provider origins are invalid")]
    InvalidOrigins,
    /// The instance has an unexpected secret binding.
    #[error("GitHub provider secret bindings are invalid")]
    InvalidSecrets,
    /// The GitHub capability declaration is internally inconsistent.
    #[error("GitHub provider capabilities are invalid")]
    InvalidCapabilities,
    /// The connection policy is malformed or noncanonical.
    #[error("GitHub connection policy is invalid")]
    InvalidConnection,
    /// A descriptor or connection belongs to another adapter or instance.
    #[error("GitHub provider identity is inconsistent")]
    ProviderTypeMismatch,
}
