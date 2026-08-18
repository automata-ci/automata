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
mod delivery;
mod factory;
mod identity;
mod storage;
mod trigger;
mod webhook;

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
pub use delivery::{
    AcceptProviderDelivery, ClaimProviderDelivery, ClaimedProviderDelivery,
    CompleteProviderDelivery, FailProviderDelivery, MAX_PROVIDER_DELIVERY_ATTEMPTS,
    MAX_PROVIDER_DELIVERY_LEASE_MILLIS, MAX_PROVIDER_DELIVERY_RETRY_MILLIS, ProviderDelivery,
    ProviderDeliveryAcceptOutcome, ProviderDeliveryClaimFence, ProviderDeliveryFailure,
    ProviderDeliveryFuture, ProviderDeliveryModelError, ProviderDeliveryReceipt,
    ProviderDeliveryReplayFingerprint, ProviderDeliveryRepository, ProviderDeliveryRepositoryError,
    ProviderDeliveryState, ProviderWebhookEndpointRecord, ProviderWebhookEndpointRepository,
    RetryProviderDelivery,
};
pub use factory::{
    MAX_PROVIDER_FACTORIES, ProviderConfigurationFactory, ProviderConnectionFactoryRequest,
    ProviderDescriptor, ProviderFactoryRegistry, ProviderFactoryRegistryError,
    ProviderFactoryRequest, ProviderFactoryValidationError,
};
pub use identity::{
    ExternalChangeId, ExternalDeliveryId, ExternalDeliveryIdentity, ExternalMergeQueueId,
    ExternalRepositoryId, ExternalRepositoryIdentity, ExternalSubjectId, ExternalSubjectIdentity,
    ExternalSubjectKind, MAX_EXTERNAL_ID_BYTES, MAX_PROVIDER_TYPE_ID_BYTES, ProviderConnectionId,
    ProviderDeliveryId, ProviderDeliveryWorkerId, ProviderIdentityError, ProviderInstanceId,
    ProviderTypeId, ProviderWebhookEndpointId,
};
pub use storage::{
    ProviderInstanceRecord, ProviderManifestRepository, ProviderRepositoryError,
    ProviderRepositoryFuture, ProviderSaveOutcome,
};
pub use trigger::{
    MAX_NORMALIZED_TRIGGER_BYTES, MAX_PROVIDER_DISPATCH_INPUT_BYTES, MAX_PROVIDER_EVENT_NAME_BYTES,
    MergeQueueActivity, MergeQueueTrigger, NormalizedTrigger, ProviderDispatchInput,
    ProviderEventName, ProviderGitRef, ProviderGitRefKind, ProviderRepository,
    ProviderTriggerError, PullRequestActivity, PullRequestTrigger, PushTrigger,
    RepositoryDispatchTrigger, SealedNormalizedTrigger,
};
pub use webhook::{
    AuthenticatedProviderWebhook, DeliveryAdapter, DeliveryAdapterRegistry,
    DeliveryAdapterRegistryError, MAX_PROVIDER_DELIVERY_OBSERVATION_BYTES,
    MAX_PROVIDER_RAW_WEBHOOK_RETENTION_MILLIS, MAX_PROVIDER_WEBHOOK_BODY_BYTES,
    MAX_PROVIDER_WEBHOOK_HEADER_BYTES, MAX_PROVIDER_WEBHOOK_HEADER_NAME_BYTES,
    MAX_PROVIDER_WEBHOOK_HEADER_VALUE_BYTES, MAX_PROVIDER_WEBHOOK_HEADERS,
    MAX_PROVIDER_WEBHOOK_SECRET_CANDIDATES, PROVIDER_RAW_WEBHOOK_KEY_PREFIX,
    PROVIDER_RAW_WEBHOOK_MEDIA_TYPE, ProviderDeliveryDraft, ProviderDeliveryNormalization,
    ProviderDeliveryObservations, ProviderDeliveryRejection, ProviderWebhookAuthenticationError,
    ProviderWebhookAuthenticationRequest, ProviderWebhookEndpointManifest,
    ProviderWebhookEndpointRevision, ProviderWebhookEndpointState, ProviderWebhookError,
    ProviderWebhookHeaderName, ProviderWebhookHeaders, ProviderWebhookMethod,
    ProviderWebhookRequest, ProviderWebhookSecretCandidate, ProviderWebhookSecretCandidates,
    ProviderWebhookSecretReference, ProviderWebhookSignatureEvidence, RejectedProviderDelivery,
    RejectedProviderDeliveryDraft, VerifiedProviderDelivery, provider_raw_webhook_descriptor,
};
