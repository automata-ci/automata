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
mod control;
mod credential;
mod delivery;
mod factory;
mod human;
mod identity;
mod result;
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
    ProviderConfigurationError, ProviderConfigurationRevision, ProviderInstanceDraft,
    ProviderInstanceManifest, ProviderLifecycleState, ProviderOrigins, ProviderSchemaVersion,
    ProviderSecret, ProviderSecretBinding, ProviderSecretBindings, ProviderSecretGeneration,
    ProviderSecretName, ProviderSecretSet, provider_capability_digest,
};
pub use connection::{
    MAX_PROVIDER_ARCHIVE_COMPRESSED_BYTES, MAX_PROVIDER_ARCHIVE_ENTRIES,
    MAX_PROVIDER_ARCHIVE_ENTRY_PATH_BYTES, MAX_PROVIDER_ARCHIVE_EXPANDED_BYTES,
    MAX_PROVIDER_ARCHIVE_WORKFLOWS, MAX_PROVIDER_CONNECTION_POLICY_BYTES,
    MAX_PROVIDER_REPOSITORY_PATH_BYTES, MAX_PROVIDER_WORKFLOW_BYTES, ProviderArchiveLimits,
    ProviderConnectionConfiguration, ProviderConnectionDraft, ProviderConnectionError,
    ProviderConnectionManifest, ProviderConnectionPolicyDocument, ProviderConnectionRevision,
    ProviderDefaultBranch, ProviderRepositoryPath, ProviderRunnerPolicyBinding,
    ProviderWorkflowSource, RepositoryVisibility,
};
pub use control::{
    MAX_PROVIDER_CONTROL_DOCUMENT_BYTES, ProviderControl, ProviderControlDocument,
    ProviderControlError, ProviderControlKind,
};
pub use credential::{
    ControlCredential, ControlCredentialFuture, ControlCredentialProvider,
    ControlCredentialProviderError, ControlCredentialRequest, ControlCredentialRevocation,
    ControlCredentialStrategy, IssuedWorkloadCredential, MAX_CONTROL_CREDENTIAL_VALIDITY_MILLIS,
    MAX_PROVIDER_CONTROL_OPERATIONS, MAX_WORKLOAD_CREDENTIAL_VALIDITY_MILLIS,
    MAX_WORKLOAD_PERMISSION_NAME_BYTES, MAX_WORKLOAD_PERMISSIONS, ProviderControlOperation,
    ProviderControlOperationSet, ProviderCredentialGeneration, ProviderCredentialModelError,
    RevokeWorkloadCredential, WorkloadCredentialFuture, WorkloadCredentialIssuer,
    WorkloadCredentialMarker, WorkloadCredentialPermission, WorkloadCredentialPermissionSet,
    WorkloadCredentialProviderError, WorkloadCredentialRequest,
    WorkloadCredentialRevocationOutcome,
};
pub use delivery::{
    AcceptProviderDelivery, BindProviderProcessingSource, ClaimProviderProcessing,
    ClaimedProviderProcessing, CompleteProviderProcessing, FailProviderProcessing,
    MAX_PROVIDER_PROCESSING_ATTEMPTS, MAX_PROVIDER_PROCESSING_LEASE_MILLIS,
    MAX_PROVIDER_PROCESSING_RETRY_MILLIS, ProviderDelivery, ProviderDeliveryAcceptOutcome,
    ProviderDeliveryFuture, ProviderDeliveryModelError, ProviderDeliveryReceipt,
    ProviderDeliveryReplayFingerprint, ProviderDeliveryRepository, ProviderDeliveryRepositoryError,
    ProviderProcessingClaimFence, ProviderProcessingClaimSource, ProviderProcessingFailure,
    ProviderProcessingFuture, ProviderProcessingInput, ProviderProcessingReceipt,
    ProviderProcessingRepository, ProviderProcessingRepositoryError, ProviderProcessingState,
    ProviderWebhookEndpointRecord, ProviderWebhookEndpointRepository, RenewProviderProcessing,
    RetryProviderProcessing,
};
pub use factory::{
    MAX_PROVIDER_FACTORIES, ProviderConfigurationFactory, ProviderConnectionFactoryRequest,
    ProviderDescriptor, ProviderFactoryRegistry, ProviderFactoryRegistryError,
    ProviderFactoryRequest, ProviderFactoryValidationError,
};
pub use human::{
    AuthorizationCodeExchange, AuthorizationCodeFuture, AuthorizationCodeProvider,
    AuthorizationCodeRequest, DeviceAuthorization, DeviceAuthorizationFuture,
    DeviceAuthorizationPoll, DeviceAuthorizationProvider, IdentityReader, IdentityReaderFuture,
    MAX_PROVIDER_DEVICE_POLL_MILLIS, MAX_PROVIDER_DISPLAY_NAME_BYTES, MAX_PROVIDER_LOGIN_BYTES,
    MAX_PROVIDER_MEMBERSHIP_ROLE_BYTES, MAX_PROVIDER_MEMBERSHIPS, MembershipReader,
    MembershipReaderFuture, ProviderAuthorizationUrl, ProviderCallbackUri, ProviderHumanCredential,
    ProviderHumanCredentialAuthority, ProviderHumanIdentity, ProviderHumanModelError,
    ProviderHumanProviderError, ProviderMembership, ProviderMembershipRole,
    ProviderMembershipSnapshot, ProviderPkceVerifier,
};
pub use identity::{
    ExternalChangeId, ExternalCredentialId, ExternalDeliveryId, ExternalDeliveryIdentity,
    ExternalMergeQueueId, ExternalRepositoryId, ExternalRepositoryIdentity, ExternalResultId,
    ExternalSubjectId, ExternalSubjectIdentity, ExternalSubjectKind, MAX_EXTERNAL_ID_BYTES,
    MAX_PROVIDER_TYPE_ID_BYTES, ProviderConnectionId, ProviderControlCredentialId,
    ProviderDeliveryId, ProviderIdentityError, ProviderInstanceId, ProviderProcessingInvocationId,
    ProviderProcessingWorkerId, ProviderResultSubjectId, ProviderResultWorkerId, ProviderTypeId,
    ProviderWebhookEndpointId, ProviderWorkloadCredentialId,
};
pub use result::{
    ClaimProviderResult, ClaimedProviderResult, CompleteProviderResult, DesiredProviderResult,
    FailProviderResult, MAX_PROVIDER_RESULT_ANNOTATION_MESSAGE_BYTES,
    MAX_PROVIDER_RESULT_ANNOTATION_TITLE_BYTES, MAX_PROVIDER_RESULT_ANNOTATIONS,
    MAX_PROVIDER_RESULT_DETAILS_URL_BYTES, MAX_PROVIDER_RESULT_LEASE_MILLIS,
    MAX_PROVIDER_RESULT_PUBLICATION_ATTEMPTS, MAX_PROVIDER_RESULT_RETRY_MILLIS,
    MAX_PROVIDER_RESULT_SUMMARY_BYTES, MAX_PROVIDER_RESULT_TITLE_BYTES,
    MAX_PROVIDER_RESULT_TOTAL_CLAIM_MILLIS, ProviderResultAnnotation,
    ProviderResultAnnotationLevel, ProviderResultAnnotationMessage, ProviderResultAnnotationTitle,
    ProviderResultClaimFence, ProviderResultConclusion, ProviderResultDetailsUrl,
    ProviderResultFailureKind, ProviderResultFuture, ProviderResultMarker,
    ProviderResultModelError, ProviderResultPhase, ProviderResultPublicationEvidence,
    ProviderResultPublicationModel, ProviderResultRepository, ProviderResultRepositoryError,
    ProviderResultRetryAfter, ProviderResultSaveOutcome, ProviderResultSubject,
    ProviderResultSubjectKind, ProviderResultSummary, ProviderResultTitle, RenewProviderResult,
    ResultPublisherError, RetryProviderResult, SaveDesiredProviderResult,
};
pub use storage::{
    ProviderInstanceRecord, ProviderManifestRepository, ProviderRepositoryError,
    ProviderRepositoryFuture, ProviderSaveOutcome,
};
pub use trigger::{
    MAX_NORMALIZED_TRIGGER_BYTES, MAX_PROVIDER_DISPATCH_INPUT_BYTES, MAX_PROVIDER_EVENT_NAME_BYTES,
    MergeQueueActivity, MergeQueueTrigger, NormalizedTrigger, ProviderDispatchInput,
    ProviderEventName, ProviderGitRef, ProviderGitRefKind, ProviderRepository,
    ProviderTriggerError, PullRequestActivity, PullRequestTrigger, PushCommitEvidence, PushTrigger,
    RepositoryDispatchTrigger, SealedNormalizedTrigger,
};
pub use webhook::{
    AuthenticatedProviderWebhook, DeliveryAdapter, DeliveryAdapterRegistry,
    DeliveryAdapterRegistryError, MAX_PROVIDER_DELIVERY_OBSERVATION_BYTES,
    MAX_PROVIDER_RAW_WEBHOOK_RETENTION_MILLIS, MAX_PROVIDER_WEBHOOK_BODY_BYTES,
    MAX_PROVIDER_WEBHOOK_HEADER_BYTES, MAX_PROVIDER_WEBHOOK_HEADER_NAME_BYTES,
    MAX_PROVIDER_WEBHOOK_HEADER_VALUE_BYTES, MAX_PROVIDER_WEBHOOK_HEADERS,
    MAX_PROVIDER_WEBHOOK_SECRET_CANDIDATES, PROVIDER_RAW_WEBHOOK_KEY_PREFIX,
    PROVIDER_RAW_WEBHOOK_MEDIA_TYPE, ProviderControlDeliveryDraft, ProviderDeliveryEvidence,
    ProviderDeliveryNormalization, ProviderDeliveryObservations, ProviderDeliveryRejection,
    ProviderTriggerDeliveryDraft, ProviderWebhookAuthenticationError,
    ProviderWebhookAuthenticationRequest, ProviderWebhookEndpointManifest,
    ProviderWebhookEndpointRevision, ProviderWebhookEndpointState, ProviderWebhookError,
    ProviderWebhookHeaderName, ProviderWebhookHeaders, ProviderWebhookMethod,
    ProviderWebhookRequest, ProviderWebhookSecretCandidate, ProviderWebhookSecretCandidates,
    ProviderWebhookSecretReference, ProviderWebhookSignatureEvidence, RejectedProviderDelivery,
    RejectedProviderDeliveryDraft, VerifiedProviderControlDelivery,
    VerifiedProviderTriggerDelivery, provider_raw_webhook_descriptor,
};
