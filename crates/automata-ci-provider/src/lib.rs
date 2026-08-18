//! Provider-neutral source-hosting identities and capabilities.
//!
//! A [`ProviderTypeId`] selects an adapter implementation. A
//! [`ProviderInstanceId`] selects one configured installation of that provider,
//! and all provider-native identities are interpreted within that instance.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod capability;
mod configuration;
mod connection;
mod factory;
mod identity;
mod storage;

pub use capability::{
    AuthorizationCodeLoginCapability, ChangedFileCapability, ChangedFileCompleteness,
    CommitStatusCapability, CommitStatusState, MembershipEvidenceCapability, PkceSupport,
    ProviderCapabilities, ProviderCapabilitiesError, ProviderCapability, ProviderCapabilityKind,
    RepositoryEventCapability, RepositoryEventKind, RichCheckCapability, SourceReadCapability,
    StatusHistoryModel, WorkloadCredentialCapability, WorkloadCredentialProfile,
    WorkloadCredentialRevocation,
};
pub use configuration::{
    MAX_PROVIDER_CONFIGURATION_BYTES, MAX_PROVIDER_ORIGIN_BYTES, MAX_PROVIDER_SCHEMA_VERSION,
    MAX_PROVIDER_SECRET_BINDINGS, MAX_PROVIDER_SECRET_NAME_BYTES, ProviderConfigurationDocument,
    ProviderConfigurationError, ProviderConfigurationRevision, ProviderInstanceManifest,
    ProviderLifecycleState, ProviderOrigins, ProviderSchemaVersion, ProviderSecret,
    ProviderSecretBinding, ProviderSecretBindings, ProviderSecretGeneration, ProviderSecretName,
    ProviderSecretSet, provider_capability_digest,
};
pub use connection::{
    MAX_PROVIDER_ARCHIVE_COMPRESSED_BYTES, MAX_PROVIDER_ARCHIVE_ENTRIES,
    MAX_PROVIDER_ARCHIVE_ENTRY_PATH_BYTES, MAX_PROVIDER_ARCHIVE_EXPANDED_BYTES,
    MAX_PROVIDER_ARCHIVE_WORKFLOWS, MAX_PROVIDER_CONNECTION_POLICY_BYTES,
    MAX_PROVIDER_REPOSITORY_PATH_BYTES, MAX_PROVIDER_WORKFLOW_BYTES, ProviderArchiveLimits,
    ProviderConnectionConfiguration, ProviderConnectionError, ProviderConnectionManifest,
    ProviderConnectionPolicyDocument, ProviderConnectionRevision, ProviderDefaultBranch,
    ProviderRepositoryPath, ProviderRunnerPolicyBinding, ProviderWorkflowSource,
    RepositoryVisibility,
};
pub use factory::{
    MAX_PROVIDER_FACTORIES, ProviderConfigurationFactory, ProviderConnectionFactoryRequest,
    ProviderDescriptor, ProviderFactoryRegistry, ProviderFactoryRegistryError,
    ProviderFactoryRequest, ProviderFactoryValidationError,
};
pub use identity::{
    ExternalDeliveryId, ExternalDeliveryIdentity, ExternalRepositoryId, ExternalRepositoryIdentity,
    ExternalSubjectId, ExternalSubjectIdentity, ExternalSubjectKind, MAX_EXTERNAL_ID_BYTES,
    MAX_PROVIDER_TYPE_ID_BYTES, ProviderConnectionId, ProviderIdentityError, ProviderInstanceId,
    ProviderTypeId,
};
pub use storage::{
    ProviderInstanceRecord, ProviderManifestRepository, ProviderRepositoryError,
    ProviderRepositoryFuture, ProviderSaveOutcome,
};
