//! Hardened GitHub authentication, repository, Checks, status, deployment, and
//! verified webhook boundaries.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod changed_files;
mod checks;
mod config;
mod endpoint;
mod event;
mod pagination;
mod repository;
mod repository_path;
mod response;
mod webhook;
mod webhook_event;
mod workflow_permissions;

pub use changed_files::{
    GithubChangedFile, GithubChangedFilesEvidenceDigest, GithubCompletePullRequestDiff,
    GithubCompletePushDiff, GithubPullRequestDiffAuthority, GithubPullRequestDiffOutcome,
    GithubPullRequestDiffRequest, GithubPushDiffAuthority, GithubPushDiffIncompleteReason,
    GithubPushDiffOutcome, GithubPushDiffRange, GithubPushDiffRequest,
    MAX_GITHUB_COMPARE_PATH_FILTER_FILES, MAX_GITHUB_PULL_REQUEST_PATH_FILTER_FILES,
};
pub use checks::{
    GithubCheckAnnotation, GithubCheckAnnotationLevel, GithubCheckAppId, GithubCheckCompletion,
    GithubCheckConclusion, GithubCheckCreateIndeterminate, GithubCheckCreateIndeterminateKind,
    GithubCheckDetailsUrl, GithubCheckExternalId, GithubCheckModelError, GithubCheckName,
    GithubCheckOutput, GithubCheckRequestedAction, GithubCheckRetryEvidence, GithubCheckRun,
    GithubCheckRunCreateOutcome, GithubCheckRunId, GithubCheckRunIdentity,
    GithubCheckRunReconciliation, GithubCheckRunState, GithubCheckSuite,
    GithubCheckSuiteCreateOutcome, GithubCheckSuiteId, GithubCheckTimestamp, GithubChecksError,
    GithubObservedCheckConclusion,
};
pub use config::{
    GITHUB_API_VERSION, GithubHttpConfigurationError, GithubHttpLimits, GithubTrustedOrigins,
};
pub use endpoint::GithubHttpEndpoint;
pub use event::{
    GITHUB_EVENT_ENVELOPE_SCHEMA_V1, GITHUB_EVENT_ENVELOPE_V1_MEDIA_TYPE,
    GITHUB_EVENT_REGISTRY_SCHEMA_V1, GITHUB_RAW_EVENT_OBJECT_KEY_PREFIX, GithubEventActivityPolicy,
    GithubEventActor, GithubEventActorKind, GithubEventChangedFilesStrategy,
    GithubEventEnvelopeError, GithubEventFacts, GithubEventRawBlobIdentity,
    GithubEventRecursionPolicy, GithubEventRefFacts, GithubEventRefRule, GithubEventRegistryEntry,
    GithubEventRegistryError, GithubEventRegistryV1, GithubEventRepositoryFacts,
    GithubEventSourceRule, GithubEventTriggerModel, GithubEventTrustFact,
    GithubMergeGroupEventFacts, GithubPullRequestEventFacts, GithubPushEventFacts,
    GithubRepositoryDispatchEventFacts, GithubSealedEventEnvelopeV1, GithubTrustDerivation,
    GithubWorkflowEventKind, MAX_GITHUB_EVENT_ENVELOPE_BYTES, derive_github_trust_snapshot,
};
pub use webhook::{
    AuthenticatedGithubWebhook, GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE, GithubPushRef,
    GithubPushRefKind, GithubPushRepository, GithubRepositoryVisibility, GithubStoredWebhookError,
    GithubWebhookBodyDigest, GithubWebhookError, GithubWebhookEventMetadata, GithubWebhookVerifier,
    GithubWebhookVerifierFingerprint, MAX_GITHUB_PUSH_COMMITS, MAX_GITHUB_WEBHOOK_BODY_BYTES,
    MAX_GITHUB_WEBHOOK_SECRET_BYTES, StoredAuthenticatedGithubWebhook, VerifiedGithubPush,
    X_GITHUB_DELIVERY, X_GITHUB_EVENT, X_HUB_SIGNATURE_256,
    rehydrate_stored_authenticated_github_webhook,
};
pub use webhook_event::{
    GithubCheckRunAction, GithubMergeGroupAction, GithubPullRequestAction, GithubWebhookRef,
    GithubWebhookRepository, VerifiedGithubCheckRun, VerifiedGithubCheckSuite,
    VerifiedGithubMergeGroup, VerifiedGithubPullRequest, VerifiedGithubRepositoryDispatch,
    VerifiedGithubWebhook,
};
pub use workflow_permissions::{
    GithubDefaultWorkflowPermission, GithubWorkflowPermissionDefaults,
    GithubWorkflowPermissionDefaultsRequest,
};
