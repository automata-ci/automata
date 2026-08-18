//! Static provider configuration validation and registry composition.

use std::{collections::BTreeMap, fmt, sync::Arc};

use thiserror::Error;

use crate::{
    ProviderCapabilities, ProviderConnectionManifest, ProviderInstanceManifest, ProviderSecretSet,
    ProviderTypeId, provider_capability_digest,
};

/// Maximum statically linked provider adapter types in one process.
pub const MAX_PROVIDER_FACTORIES: usize = 32;

/// Exact configuration and secret evidence presented to one adapter factory.
#[derive(Clone, Copy)]
pub struct ProviderFactoryRequest<'a> {
    manifest: &'a ProviderInstanceManifest,
    secrets: &'a ProviderSecretSet,
}

impl<'a> ProviderFactoryRequest<'a> {
    /// Binds one immutable manifest to its already verified plaintext secret set.
    #[must_use]
    pub const fn new(
        manifest: &'a ProviderInstanceManifest,
        secrets: &'a ProviderSecretSet,
    ) -> Self {
        Self { manifest, secrets }
    }

    /// Returns the immutable provider manifest.
    #[must_use]
    pub const fn manifest(self) -> &'a ProviderInstanceManifest {
        self.manifest
    }

    /// Returns exact named plaintext values at the adapter boundary.
    #[must_use]
    pub const fn secrets(self) -> &'a ProviderSecretSet {
        self.secrets
    }
}

impl fmt::Debug for ProviderFactoryRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderFactoryRequest")
            .field("instance_id", &self.manifest.instance_id())
            .field("provider_type", self.manifest.provider_type())
            .field("revision", &self.manifest.revision())
            .field("secret_names", &self.secrets.names().collect::<Vec<_>>())
            .finish()
    }
}

/// Validated instance evidence and one connection policy presented to an adapter factory.
#[derive(Clone, Copy)]
pub struct ProviderConnectionFactoryRequest<'a> {
    provider: &'a ProviderDescriptor,
    connection: &'a ProviderConnectionManifest,
}

impl<'a> ProviderConnectionFactoryRequest<'a> {
    /// Binds one connection manifest to its exact validated provider descriptor.
    #[must_use]
    pub const fn new(
        provider: &'a ProviderDescriptor,
        connection: &'a ProviderConnectionManifest,
    ) -> Self {
        Self {
            provider,
            connection,
        }
    }

    /// Returns the already validated provider descriptor.
    #[must_use]
    pub const fn provider(self) -> &'a ProviderDescriptor {
        self.provider
    }

    /// Returns the connection manifest requiring adapter-policy validation.
    #[must_use]
    pub const fn connection(self) -> &'a ProviderConnectionManifest {
        self.connection
    }
}

impl fmt::Debug for ProviderConnectionFactoryRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderConnectionFactoryRequest")
            .field("instance_id", &self.provider.manifest().instance_id())
            .field("connection_id", &self.connection.connection_id())
            .field("connection_revision", &self.connection.revision())
            .finish()
    }
}

/// Statically composed validator for one provider adapter type.
pub trait ProviderConfigurationFactory: fmt::Debug + Send + Sync {
    /// Returns the unique adapter type registered by this factory.
    fn provider_type(&self) -> &ProviderTypeId;

    /// Decodes one exact schema, verifies canonical re-encoding and named
    /// secrets, and returns the adapter's typed capability declaration.
    ///
    /// # Errors
    ///
    /// Fails closed on unknown schema, malformed or noncanonical documents,
    /// unsupported origins, invalid secrets, or impossible capability sets.
    fn validate_instance(
        &self,
        request: ProviderFactoryRequest<'_>,
    ) -> Result<ProviderCapabilities, ProviderFactoryValidationError>;

    /// Decodes and exactly re-encodes one adapter-owned connection policy.
    ///
    /// # Errors
    ///
    /// Fails closed on unknown schema, malformed or noncanonical policy, or
    /// policy inconsistent with the validated provider configuration.
    fn validate_connection(
        &self,
        request: ProviderConnectionFactoryRequest<'_>,
    ) -> Result<(), ProviderFactoryValidationError>;
}

/// Runtime-visible descriptor returned after one adapter validates a manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderDescriptor {
    manifest: ProviderInstanceManifest,
    capabilities: ProviderCapabilities,
}

impl ProviderDescriptor {
    /// Returns the exact immutable provider manifest.
    #[must_use]
    pub const fn manifest(&self) -> &ProviderInstanceManifest {
        &self.manifest
    }

    /// Returns the adapter-validated capabilities.
    #[must_use]
    pub const fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }
}

/// Immutable registry of statically linked provider validation factories.
#[derive(Clone)]
pub struct ProviderFactoryRegistry {
    factories: BTreeMap<ProviderTypeId, Arc<dyn ProviderConfigurationFactory>>,
}

impl ProviderFactoryRegistry {
    /// Builds a bounded, duplicate-free registry.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized input and duplicate provider type IDs.
    pub fn new(
        factories: impl IntoIterator<Item = Arc<dyn ProviderConfigurationFactory>>,
    ) -> Result<Self, ProviderFactoryRegistryError> {
        let mut registered = BTreeMap::new();
        for factory in factories {
            if registered.len() == MAX_PROVIDER_FACTORIES {
                return Err(ProviderFactoryRegistryError::TooManyFactories);
            }
            let provider_type = factory.provider_type().clone();
            if registered.insert(provider_type, factory).is_some() {
                return Err(ProviderFactoryRegistryError::DuplicateFactory);
            }
        }
        if registered.is_empty() {
            return Err(ProviderFactoryRegistryError::NoFactories);
        }
        Ok(Self {
            factories: registered,
        })
    }

    /// Validates one complete manifest and constructs its common descriptor.
    ///
    /// The adapter-returned capability digest must exactly match the durable
    /// manifest. The registry never falls back to another provider type.
    ///
    /// # Errors
    ///
    /// Rejects an unregistered type, adapter validation failure, or capability
    /// digest mismatch.
    pub fn build_descriptor(
        &self,
        manifest: ProviderInstanceManifest,
        secrets: &ProviderSecretSet,
    ) -> Result<ProviderDescriptor, ProviderFactoryRegistryError> {
        if !secrets.matches(manifest.secrets()) {
            return Err(ProviderFactoryRegistryError::SecretEvidence);
        }
        let factory = self
            .factories
            .get(manifest.provider_type())
            .ok_or(ProviderFactoryRegistryError::UnknownProviderType)?;
        if factory.provider_type() != manifest.provider_type() {
            return Err(ProviderFactoryRegistryError::FactoryIdentityMismatch);
        }
        let capabilities = factory
            .validate_instance(ProviderFactoryRequest::new(&manifest, secrets))
            .map_err(ProviderFactoryRegistryError::Validation)?;
        let digest = provider_capability_digest(&capabilities)
            .map_err(|_| ProviderFactoryRegistryError::CapabilityDigest)?;
        if digest != manifest.capability_digest() {
            return Err(ProviderFactoryRegistryError::CapabilityDigest);
        }
        Ok(ProviderDescriptor {
            manifest,
            capabilities,
        })
    }

    /// Validates exact provider evidence and adapter-owned connection policy.
    ///
    /// # Errors
    ///
    /// Rejects a connection pinned to different instance, configuration, or
    /// capability evidence, and propagates adapter policy rejection.
    pub fn validate_connection(
        &self,
        provider: &ProviderDescriptor,
        connection: &ProviderConnectionManifest,
    ) -> Result<(), ProviderFactoryRegistryError> {
        let provider_manifest = provider.manifest();
        let configuration = connection.configuration();
        if configuration.repository().instance_id() != provider_manifest.instance_id()
            || configuration.provider_revision() != provider_manifest.revision()
            || configuration.provider_configuration_digest()
                != provider_manifest.configuration().digest()
            || configuration.capability_digest() != provider_manifest.capability_digest()
        {
            return Err(ProviderFactoryRegistryError::ConnectionEvidence);
        }
        let factory = self
            .factories
            .get(provider_manifest.provider_type())
            .ok_or(ProviderFactoryRegistryError::UnknownProviderType)?;
        factory
            .validate_connection(ProviderConnectionFactoryRequest::new(provider, connection))
            .map_err(ProviderFactoryRegistryError::Validation)
    }

    /// Iterates registered provider type IDs in canonical order.
    pub fn provider_types(&self) -> impl ExactSizeIterator<Item = &ProviderTypeId> {
        self.factories.keys()
    }
}

impl fmt::Debug for ProviderFactoryRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderFactoryRegistry")
            .field("provider_types", &self.factories.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Sanitized adapter-owned configuration rejection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderFactoryValidationError {
    /// The adapter does not implement the requested schema version.
    #[error("provider configuration schema is unsupported")]
    UnsupportedSchema,
    /// The adapter document was malformed or not in canonical form.
    #[error("provider configuration document is invalid")]
    InvalidConfiguration,
    /// Common origins violate adapter-specific trust policy.
    #[error("provider origin policy is invalid")]
    InvalidOrigins,
    /// Named secret requirements were not satisfied.
    #[error("provider secret bindings are invalid")]
    InvalidSecrets,
    /// The adapter could not produce a valid capability declaration.
    #[error("provider capability declaration is invalid")]
    InvalidCapabilities,
}

/// Closed provider-factory registry failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderFactoryRegistryError {
    /// No factory was registered.
    #[error("at least one provider factory is required")]
    NoFactories,
    /// The process-wide adapter bound was exceeded.
    #[error("too many provider factories were registered")]
    TooManyFactories,
    /// Two factories claimed one provider type.
    #[error("a provider factory type was registered more than once")]
    DuplicateFactory,
    /// No exact factory exists for the manifest type.
    #[error("provider type is not registered")]
    UnknownProviderType,
    /// A factory returned an identity inconsistent with its registry key.
    #[error("provider factory identity is inconsistent")]
    FactoryIdentityMismatch,
    /// Adapter validation rejected the configuration.
    #[error(transparent)]
    Validation(ProviderFactoryValidationError),
    /// Plaintext secret evidence did not match the selected manifest.
    #[error("provider secret evidence is inconsistent")]
    SecretEvidence,
    /// Adapter capabilities disagreed with durable evidence.
    #[error("provider capability digest is inconsistent")]
    CapabilityDigest,
    /// A connection was pinned to different provider evidence.
    #[error("provider connection evidence is inconsistent")]
    ConnectionEvidence,
}
