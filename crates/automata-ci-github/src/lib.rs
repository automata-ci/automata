//! Hardened GitHub authentication, repository, Checks, status, deployment, and
//! verified webhook boundaries.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod changed_files;
mod checks;
mod config;
mod endpoint;
mod pagination;
mod repository;
mod repository_path;
mod response;
mod webhook;
mod webhook_event;

pub use changed_files::{
    GithubCompletePullRequestDiff, GithubCompletePushDiff, GithubPullRequestDiffAuthority,
    GithubPullRequestDiffError, GithubPullRequestDiffOutcome, GithubPullRequestDiffRequest,
    GithubPushDiffAuthority, GithubPushDiffError, GithubPushDiffIncompleteReason,
    GithubPushDiffOutcome, GithubPushDiffRange, GithubPushDiffRequest,
    MAX_COMPLETE_GITHUB_COMPARE_FILES,
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
pub use webhook::{
    AuthenticatedGithubWebhook, GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE,
    GITHUB_PUSH_EVENT_MEDIA_TYPE, GithubPushRef, GithubPushRefKind, GithubPushRepository,
    GithubRepositoryVisibility, GithubStoredPushError, GithubStoredWebhookError,
    GithubWebhookBodyDigest, GithubWebhookError, GithubWebhookEventMetadata, GithubWebhookVerifier,
    GithubWebhookVerifierFingerprint, MAX_GITHUB_PUSH_COMMITS, MAX_GITHUB_WEBHOOK_BODY_BYTES,
    MAX_GITHUB_WEBHOOK_SECRET_BYTES, StoredAuthenticatedGithubPush,
    StoredAuthenticatedGithubWebhook, VerifiedGithubPush, X_GITHUB_DELIVERY, X_GITHUB_EVENT,
    X_HUB_SIGNATURE_256, rehydrate_stored_authenticated_github_push,
    rehydrate_stored_authenticated_github_webhook,
};
pub use webhook_event::{
    GithubCheckRunAction, GithubMergeGroupAction, GithubPullRequestAction, GithubWebhookRef,
    GithubWebhookRepository, VerifiedGithubCheckRun, VerifiedGithubCheckSuite,
    VerifiedGithubMergeGroup, VerifiedGithubPullRequest, VerifiedGithubRepositoryDispatch,
    VerifiedGithubWebhook,
};
