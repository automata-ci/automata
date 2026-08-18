//! Typed GitHub provider configuration and factory composition.

use std::{fmt, num::NonZeroU64};

use automata_ci_core::GitObjectAlgorithm;
use automata_ci_provider::{
    ChangedFileCapability, ChangedFileCompleteness, ProviderCapabilities, ProviderCapability,
    ProviderConfigurationDocument, ProviderConfigurationFactory, ProviderConnectionFactoryRequest,
    ProviderConnectionManifest, ProviderConnectionPolicyDocument, ProviderDescriptor,
    ProviderFactoryRequest, ProviderFactoryValidationError, ProviderSchemaVersion, ProviderTypeId,
    RepositoryEventCapability, RepositoryEventKind, SourceReadCapability,
};
use automata_ci_scm::{RepositoryId, RepositorySourceConnection};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::{GITHUB_API_VERSION, GithubHttpEndpoint, GithubHttpLimits, GithubTrustedOrigins};

const GITHUB_CONFIGURATION_SCHEMA: u16 = 1;
const GITHUB_CONNECTION_SCHEMA: u16 = 1;
const MAX_GITHUB_INSTALLATION_ID: u64 = i64::MAX as u64;

/// Canonical non-secret configuration owned by one GitHub provider instance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GithubInstanceConfiguration {
    rest_api_version: String,
    archive_origin: String,
}

impl GithubInstanceConfiguration {
    /// Creates one GitHub instance policy with an explicit archive authority.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical credential-bearing or non-HTTPS origin.
    pub fn new(archive_origin: Url) -> Result<Self, GithubFactoryError> {
        validate_archive_origin(&archive_origin)?;
        Ok(Self {
            rest_api_version: GITHUB_API_VERSION.to_owned(),
            archive_origin: archive_origin.into(),
        })
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
        ])
        .map_err(|_| GithubFactoryError::InvalidCapabilities)
    }

    /// Constructs the hardened HTTP/source adapter for one validated descriptor.
    ///
    /// # Errors
    ///
    /// Rejects a descriptor for another provider type, invalid or noncanonical
    /// configuration, ambient instance secrets, or unsafe provider origins.
    pub fn repository_source(
        &self,
        descriptor: &ProviderDescriptor,
        user_agent: &str,
        limits: GithubHttpLimits,
    ) -> Result<GithubHttpEndpoint, GithubFactoryError> {
        if descriptor.manifest().provider_type() != &self.provider_type {
            return Err(GithubFactoryError::ProviderTypeMismatch);
        }
        let configuration = decode_instance(descriptor.manifest().configuration())?;
        validate_no_instance_secrets(descriptor.manifest().secrets().len())?;
        let web = Url::parse(descriptor.manifest().origins().web())
            .map_err(|_| GithubFactoryError::InvalidOrigins)?;
        let api = Url::parse(descriptor.manifest().origins().api())
            .map_err(|_| GithubFactoryError::InvalidOrigins)?;
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
        descriptor: &ProviderDescriptor,
        connection: &ProviderConnectionManifest,
    ) -> Result<RepositorySourceConnection, GithubFactoryError> {
        let provider = descriptor.manifest();
        let configuration = connection.configuration();
        if descriptor.manifest().provider_type() != &self.provider_type
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
        validate_no_instance_secrets(request.manifest().secrets().len())
            .map_err(map_instance_validation_error)?;
        if request.secrets().names().next().is_some() {
            return Err(ProviderFactoryValidationError::InvalidSecrets);
        }
        let web = Url::parse(request.manifest().origins().web())
            .map_err(|_| ProviderFactoryValidationError::InvalidOrigins)?;
        let api = Url::parse(request.manifest().origins().api())
            .map_err(|_| ProviderFactoryValidationError::InvalidOrigins)?;
        let configuration = decode_instance(request.manifest().configuration())
            .map_err(map_instance_validation_error)?;
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

fn validate_no_instance_secrets(secret_count: usize) -> Result<(), GithubFactoryError> {
    if secret_count == 0 {
        Ok(())
    } else {
        Err(GithubFactoryError::InvalidSecrets)
    }
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
