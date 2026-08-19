use std::{fmt, num::NonZeroU64};

use automata_ci_core::GitObjectAlgorithm;
use automata_ci_provider::{
    ChangedFileCapability, ChangedFileCompleteness, ProviderCapabilities, ProviderCapability,
    ProviderConfigurationDocument, ProviderConnectionFactoryRequest, ProviderFactoryRequest,
    ProviderFactoryValidationError, ProviderOrigins, ProviderSchemaVersion, ProviderSecretName,
    ProviderTypeId, RepositoryEventCapability, RepositoryEventKind, SourceReadCapability,
};
use automata_ci_scm::RepositoryId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

const FORGEJO_CONFIGURATION_SCHEMA: u16 = 1;
const FORGEJO_CONNECTION_SCHEMA: u16 = 1;
const MAX_ORIGIN_BYTES: usize = 2_048;

/// Provider-instance secret containing a scoped Forgejo access token.
pub const FORGEJO_ACCESS_TOKEN_SECRET_NAME: &str = "access-token";
/// Provider-instance secret used to authenticate Forgejo webhooks.
pub const FORGEJO_WEBHOOK_SECRET_NAME: &str = "webhook-secret";

/// Non-secret configuration for one Forgejo instance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForgejoInstanceConfiguration {
    api_origin: String,
    archive_origin: String,
}

impl ForgejoInstanceConfiguration {
    /// Creates one exact Forgejo API and archive origin pair.
    ///
    /// # Errors
    ///
    /// Returns an error when either origin violates the transport policy.
    pub fn new(api_origin: Url, archive_origin: Url) -> Result<Self, ForgejoFactoryError> {
        validate_origin(&api_origin)?;
        validate_origin(&archive_origin)?;
        Ok(Self {
            api_origin: api_origin.into(),
            archive_origin: archive_origin.into(),
        })
    }

    /// Returns the configured Forgejo API origin.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored canonical origin cannot be parsed.
    pub fn api_origin(&self) -> Result<Url, ForgejoFactoryError> {
        Url::parse(&self.api_origin).map_err(|_| ForgejoFactoryError::InvalidConfiguration)
    }

    /// Returns the credential-free archive origin.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored canonical origin cannot be parsed.
    pub fn archive_origin(&self) -> Result<Url, ForgejoFactoryError> {
        Url::parse(&self.archive_origin).map_err(|_| ForgejoFactoryError::InvalidConfiguration)
    }

    /// Encodes this configuration as the canonical provider document.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or common document validation fails.
    pub fn document(&self) -> Result<ProviderConfigurationDocument, ForgejoFactoryError> {
        let bytes =
            serde_json::to_vec(self).map_err(|_| ForgejoFactoryError::InvalidConfiguration)?;
        ProviderConfigurationDocument::new(
            ProviderSchemaVersion::new(FORGEJO_CONFIGURATION_SCHEMA)
                .map_err(|_| ForgejoFactoryError::InvalidConfiguration)?,
            bytes,
        )
        .map_err(|_| ForgejoFactoryError::InvalidConfiguration)
    }

    /// Decodes the current exact provider document.
    ///
    /// # Errors
    ///
    /// Rejects schema, canonical-byte, origin, and configuration drift.
    pub fn decode(document: &ProviderConfigurationDocument) -> Result<Self, ForgejoFactoryError> {
        if document.schema_version().get() != FORGEJO_CONFIGURATION_SCHEMA {
            return Err(ForgejoFactoryError::UnsupportedSchema);
        }
        let value = serde_json::from_slice::<Self>(document.bytes())
            .map_err(|_| ForgejoFactoryError::InvalidConfiguration)?;
        if serde_json::to_vec(&value).map_err(|_| ForgejoFactoryError::InvalidConfiguration)?
            != document.bytes()
        {
            return Err(ForgejoFactoryError::InvalidConfiguration);
        }
        validate_origin(&value.api_origin()?)?;
        validate_origin(&value.archive_origin()?)?;
        Ok(value)
    }
}

/// Non-secret policy for one Forgejo repository connection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForgejoConnectionPolicy {
    repository: RepositoryId,
    repository_id: NonZeroU64,
}

impl ForgejoConnectionPolicy {
    /// Creates one repository policy with a stable Forgejo repository ID.
    ///
    /// # Errors
    ///
    /// Rejects a zero repository identity.
    pub fn new(repository: RepositoryId, repository_id: u64) -> Result<Self, ForgejoFactoryError> {
        Ok(Self {
            repository,
            repository_id: NonZeroU64::new(repository_id)
                .ok_or(ForgejoFactoryError::InvalidConnection)?,
        })
    }

    /// Returns the exact repository route.
    pub fn repository(&self) -> &RepositoryId {
        &self.repository
    }

    /// Returns the Forgejo numeric repository identity.
    pub const fn repository_id(&self) -> NonZeroU64 {
        self.repository_id
    }

    /// Encodes this policy as the canonical connection document.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or common document validation fails.
    pub fn document(
        &self,
    ) -> Result<automata_ci_provider::ProviderConnectionPolicyDocument, ForgejoFactoryError> {
        let bytes = serde_json::to_vec(self).map_err(|_| ForgejoFactoryError::InvalidConnection)?;
        automata_ci_provider::ProviderConnectionPolicyDocument::new(
            ProviderSchemaVersion::new(FORGEJO_CONNECTION_SCHEMA)
                .map_err(|_| ForgejoFactoryError::InvalidConnection)?,
            bytes,
        )
        .map_err(|_| ForgejoFactoryError::InvalidConnection)
    }
}

/// Static Forgejo provider configuration factory.
pub struct ForgejoProviderFactory {
    provider_type: ProviderTypeId,
}

impl ForgejoProviderFactory {
    /// Constructs the built-in Forgejo factory.
    ///
    /// # Panics
    ///
    /// Panics only if the compile-time provider identifier becomes invalid.
    pub fn new() -> Self {
        Self {
            provider_type: ProviderTypeId::new("forgejo")
                .expect("Forgejo provider type is canonical"),
        }
    }

    /// Returns the capabilities implemented by the foundation adapter.
    ///
    /// # Errors
    ///
    /// Returns an error if the static capability declaration violates the
    /// common provider contract.
    pub fn capabilities() -> Result<ProviderCapabilities, ForgejoFactoryError> {
        ProviderCapabilities::new([
            ProviderCapability::SourceRead(
                SourceReadCapability::new([GitObjectAlgorithm::Sha1])
                    .map_err(|_| ForgejoFactoryError::InvalidCapabilities)?,
            ),
            ProviderCapability::RepositoryEvents(
                RepositoryEventCapability::new([
                    RepositoryEventKind::Push,
                    RepositoryEventKind::PullRequest,
                ])
                .map_err(|_| ForgejoFactoryError::InvalidCapabilities)?,
            ),
            ProviderCapability::ChangedFiles(
                ChangedFileCapability::new(
                    [RepositoryEventKind::Push, RepositoryEventKind::PullRequest],
                    ChangedFileCompleteness::ExplicitlyIncomplete,
                )
                .map_err(|_| ForgejoFactoryError::InvalidCapabilities)?,
            ),
        ])
        .map_err(|_| ForgejoFactoryError::InvalidCapabilities)
    }
}

impl Default for ForgejoProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ForgejoProviderFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ForgejoProviderFactory")
            .field("provider_type", &self.provider_type)
            .finish()
    }
}

impl automata_ci_provider::ProviderConfigurationFactory for ForgejoProviderFactory {
    fn provider_type(&self) -> &ProviderTypeId {
        &self.provider_type
    }

    fn validate_instance(
        &self,
        request: ProviderFactoryRequest<'_>,
    ) -> Result<ProviderCapabilities, ProviderFactoryValidationError> {
        if request.provider_type() != &self.provider_type {
            return Err(ProviderFactoryValidationError::InvalidConfiguration);
        }
        let access = ProviderSecretName::new(FORGEJO_ACCESS_TOKEN_SECRET_NAME)
            .map_err(|_| ProviderFactoryValidationError::InvalidSecrets)?;
        let webhook = ProviderSecretName::new(FORGEJO_WEBHOOK_SECRET_NAME)
            .map_err(|_| ProviderFactoryValidationError::InvalidSecrets)?;
        if request.secret_bindings().len() != 2
            || request.secret_bindings().get(&access).is_none()
            || request.secret_bindings().get(&webhook).is_none()
            || request.secrets().get(&access).is_none()
            || request.secrets().get(&webhook).is_none()
        {
            return Err(ProviderFactoryValidationError::InvalidSecrets);
        }
        ForgejoInstanceConfiguration::decode(request.configuration()).map_err(
            |error| match error {
                ForgejoFactoryError::UnsupportedSchema => {
                    ProviderFactoryValidationError::UnsupportedSchema
                }
                ForgejoFactoryError::InvalidCapabilities => {
                    ProviderFactoryValidationError::InvalidCapabilities
                }
                _ => ProviderFactoryValidationError::InvalidConfiguration,
            },
        )?;
        Self::capabilities().map_err(|_| ProviderFactoryValidationError::InvalidCapabilities)
    }

    fn validate_connection(
        &self,
        request: ProviderConnectionFactoryRequest<'_>,
    ) -> Result<(), ProviderFactoryValidationError> {
        let document = request.connection().configuration().adapter_policy();
        if document.schema_version().get() != FORGEJO_CONNECTION_SCHEMA {
            return Err(ProviderFactoryValidationError::UnsupportedSchema);
        }
        let policy = serde_json::from_slice::<ForgejoConnectionPolicy>(document.bytes())
            .map_err(|_| ProviderFactoryValidationError::InvalidConfiguration)?;
        if serde_json::to_vec(&policy)
            .map_err(|_| ProviderFactoryValidationError::InvalidConfiguration)?
            != document.bytes()
        {
            return Err(ProviderFactoryValidationError::InvalidConfiguration);
        }
        Ok(())
    }
}

fn validate_origin(origin: &Url) -> Result<(), ForgejoFactoryError> {
    if origin.as_str().len() > MAX_ORIGIN_BYTES
        || !origin.username().is_empty()
        || origin.password().is_some()
    {
        return Err(ForgejoFactoryError::InvalidOrigins);
    }
    match origin.scheme() {
        "https" => {}
        "http"
            if origin
                .host_str()
                .is_some_and(|host| host == "127.0.0.1" || host == "localhost") => {}
        _ => return Err(ForgejoFactoryError::InvalidOrigins),
    }
    ProviderOrigins::new(origin.as_str(), origin.as_str())
        .map(|_| ())
        .map_err(|_| ForgejoFactoryError::InvalidOrigins)
}

/// Forgejo factory and policy validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ForgejoFactoryError {
    /// The document schema is not implemented.
    #[error("Forgejo provider schema is unsupported")]
    UnsupportedSchema,
    /// The instance configuration is malformed or noncanonical.
    #[error("Forgejo provider configuration is invalid")]
    InvalidConfiguration,
    /// An origin violates the provider transport policy.
    #[error("Forgejo provider origins are invalid")]
    InvalidOrigins,
    /// The connection policy is malformed.
    #[error("Forgejo connection policy is invalid")]
    InvalidConnection,
    /// The capability declaration is internally inconsistent.
    #[error("Forgejo provider capabilities are invalid")]
    InvalidCapabilities,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_and_connection_documents_are_canonical() {
        let configuration = ForgejoInstanceConfiguration::new(
            Url::parse("https://forgejo.example.test/").unwrap(),
            Url::parse("https://forgejo.example.test/").unwrap(),
        )
        .unwrap();
        let document = configuration.document().unwrap();
        assert_eq!(
            ForgejoInstanceConfiguration::decode(&document).unwrap(),
            configuration
        );

        let policy =
            ForgejoConnectionPolicy::new(RepositoryId::new("automata-ci/automata").unwrap(), 42)
                .unwrap();
        let policy_document = policy.document().unwrap();
        let decoded: ForgejoConnectionPolicy =
            serde_json::from_slice(policy_document.bytes()).unwrap();
        assert_eq!(decoded, policy);
    }

    #[test]
    fn origins_and_capabilities_fail_closed() {
        assert!(
            ForgejoInstanceConfiguration::new(
                Url::parse("http://forgejo.example.test/").unwrap(),
                Url::parse("https://forgejo.example.test/").unwrap(),
            )
            .is_err()
        );
        assert!(
            ForgejoInstanceConfiguration::new(
                Url::parse("http://127.0.0.1:3000/").unwrap(),
                Url::parse("http://127.0.0.1:3000/").unwrap(),
            )
            .is_ok()
        );
        let capabilities = ForgejoProviderFactory::capabilities().unwrap();
        assert_eq!(capabilities.len(), 3);
    }
}
