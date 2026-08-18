//! GitHub webhook authentication and provider-neutral trigger normalization.

use std::fmt;

use automata_ci_core::GitObjectId;
use automata_ci_provider::{
    AuthenticatedProviderWebhook, DeliveryAdapter, ExternalChangeId, ExternalDeliveryId,
    ExternalDeliveryIdentity, ExternalMergeQueueId, ExternalRepositoryId,
    ExternalRepositoryIdentity, ExternalSubjectId, ExternalSubjectIdentity, ExternalSubjectKind,
    MergeQueueActivity, MergeQueueTrigger, NormalizedTrigger, ProviderDeliveryDraft,
    ProviderDeliveryId, ProviderDeliveryNormalization, ProviderDeliveryObservations,
    ProviderDeliveryRejection, ProviderDispatchInput, ProviderEventName, ProviderGitRef,
    ProviderGitRefKind, ProviderRepository, ProviderRepositoryPath,
    ProviderWebhookAuthenticationError, ProviderWebhookAuthenticationRequest,
    ProviderWebhookHeaderName, ProviderWebhookRequest, ProviderWebhookSignatureEvidence,
    PullRequestActivity, PullRequestTrigger, PushCommitEvidence, PushTrigger,
    RejectedProviderDeliveryDraft, RepositoryDispatchTrigger, RepositoryVisibility,
};
use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::Serialize;

use crate::{
    GithubEventActor, GithubEventActorKind, GithubMergeGroupAction, GithubPullRequestAction,
    GithubRepositoryVisibility, GithubWebhookError, GithubWebhookRef, GithubWebhookRefKind,
    GithubWebhookRepository, GithubWebhookVerifier, VerifiedGithubMergeGroup,
    VerifiedGithubPullRequest, VerifiedGithubPush, VerifiedGithubRepositoryDispatch,
    VerifiedGithubWebhook, X_GITHUB_DELIVERY, X_GITHUB_EVENT, X_HUB_SIGNATURE_256,
    factory::decode_connection, webhook::AuthenticatedGithubWebhook,
};

const GITHUB_SIGNATURE_SCHEME: &str = "github-hmac-sha256";

/// GitHub implementation of the common authenticate-before-normalize contract.
pub struct GithubDeliveryAdapter {
    provider_type: automata_ci_provider::ProviderTypeId,
    header_names: Vec<ProviderWebhookHeaderName>,
}

impl GithubDeliveryAdapter {
    /// Constructs the stateless built-in GitHub delivery adapter.
    ///
    /// # Panics
    ///
    /// Panics only if compile-time GitHub provider/header identifiers stop
    /// satisfying the common canonical contracts.
    #[must_use]
    pub fn new() -> Self {
        Self {
            provider_type: automata_ci_provider::ProviderTypeId::new("github")
                .expect("the built-in GitHub provider type is canonical"),
            header_names: [X_GITHUB_DELIVERY, X_GITHUB_EVENT, X_HUB_SIGNATURE_256]
                .into_iter()
                .map(|name| {
                    ProviderWebhookHeaderName::new(name)
                        .expect("GitHub webhook header names are canonical")
                })
                .collect(),
        }
    }
}

impl Default for GithubDeliveryAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for GithubDeliveryAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDeliveryAdapter")
            .field("provider_type", &self.provider_type)
            .field("header_names", &self.header_names)
            .finish()
    }
}

impl DeliveryAdapter for GithubDeliveryAdapter {
    fn provider_type(&self) -> &automata_ci_provider::ProviderTypeId {
        &self.provider_type
    }

    fn selected_header_names(&self) -> &[ProviderWebhookHeaderName] {
        &self.header_names
    }

    fn authenticate(
        &self,
        authentication: ProviderWebhookAuthenticationRequest,
    ) -> Result<AuthenticatedProviderWebhook, ProviderWebhookAuthenticationError> {
        let headers = github_headers(authentication.request())?;
        let body = Bytes::copy_from_slice(authentication.request().body());
        let mut accepted = None;
        for candidate in authentication.candidates().iter() {
            let verifier = GithubWebhookVerifier::new(candidate.expose_secret())
                .map_err(|_| ProviderWebhookAuthenticationError::InvalidEvidence)?;
            match verifier.authenticate(&headers, body.clone()) {
                Ok(_) => {
                    accepted = Some(candidate.reference().clone());
                    break;
                }
                Err(GithubWebhookError::AuthenticationFailed) => {}
                Err(_) => return Err(ProviderWebhookAuthenticationError::InvalidEvidence),
            }
        }
        let accepted = accepted.ok_or(ProviderWebhookAuthenticationError::InvalidSignature)?;
        let signature = ProviderWebhookSignatureEvidence::new(GITHUB_SIGNATURE_SCHEME, accepted)
            .map_err(|_| ProviderWebhookAuthenticationError::InvalidEvidence)?;
        AuthenticatedProviderWebhook::new(authentication.into_request(), signature)
            .map_err(|_| ProviderWebhookAuthenticationError::InvalidEvidence)
    }

    fn normalize(
        &self,
        authenticated: AuthenticatedProviderWebhook,
    ) -> ProviderDeliveryNormalization {
        normalize_authenticated(authenticated)
    }
}

fn normalize_authenticated(
    authenticated: AuthenticatedProviderWebhook,
) -> ProviderDeliveryNormalization {
    let request = authenticated.request();
    let instance_id = request.endpoint().instance_id();
    let delivery_header = selected_header(request, X_GITHUB_DELIVERY)
        .expect("authenticated GitHub delivery header remains selected");
    let event_header = selected_header(request, X_GITHUB_EVENT)
        .expect("authenticated GitHub event header remains selected");
    let external_delivery = ExternalDeliveryIdentity::new(
        instance_id,
        ExternalDeliveryId::new(
            std::str::from_utf8(delivery_header)
                .expect("authenticated GitHub delivery ID is ASCII")
                .to_owned(),
        )
        .expect("GitHub delivery ID satisfies the common identity bound"),
    );
    let event_type = ProviderEventName::new(
        std::str::from_utf8(event_header)
            .expect("authenticated GitHub event name is ASCII")
            .to_owned(),
    )
    .expect("GitHub event name satisfies the common event bound");
    let native = AuthenticatedGithubWebhook::from_authenticated_parts(
        delivery_header,
        event_header,
        Bytes::copy_from_slice(request.body()),
    )
    .and_then(AuthenticatedGithubWebhook::normalize);

    let native = match native {
        Ok(native) => native,
        Err(error) => {
            return rejected(
                authenticated,
                external_delivery,
                event_type,
                None,
                match error {
                    GithubWebhookError::UnsupportedEvent => ProviderDeliveryRejection::UnknownEvent,
                    _ => ProviderDeliveryRejection::InvalidPayload,
                },
            );
        }
    };
    let repository = external_repository(instance_id, native.repository());
    if matches!(
        native,
        VerifiedGithubWebhook::CheckRun(_) | VerifiedGithubWebhook::CheckSuite(_)
    ) {
        return rejected(
            authenticated,
            external_delivery,
            event_type,
            Some(repository),
            ProviderDeliveryRejection::UnsupportedEvent,
        );
    }
    let observations =
        observations(&native).expect("fixed GitHub delivery observations satisfy the common bound");
    let trigger = match normalize_trigger(request, &native) {
        Ok(trigger) => trigger,
        Err(reason) => {
            return rejected(
                authenticated,
                external_delivery,
                event_type,
                Some(repository),
                reason,
            );
        }
    };
    let draft = ProviderDeliveryDraft::new(
        ProviderDeliveryId::new(),
        external_delivery,
        event_type,
        authenticated,
        &trigger,
        observations,
    )
    .expect("GitHub normalization preserves common endpoint identities");
    ProviderDeliveryNormalization::Accepted(Box::new(draft))
}

fn normalize_trigger(
    request: &ProviderWebhookRequest,
    event: &VerifiedGithubWebhook,
) -> Result<NormalizedTrigger, ProviderDeliveryRejection> {
    match event {
        VerifiedGithubWebhook::Push(event) => normalize_push(request, event),
        VerifiedGithubWebhook::PullRequest(event) => normalize_pull_request(request, event),
        VerifiedGithubWebhook::MergeGroup(event) => normalize_merge_group(request, event),
        VerifiedGithubWebhook::RepositoryDispatch(event) => {
            normalize_repository_dispatch(request, event)
        }
        VerifiedGithubWebhook::CheckRun(_) | VerifiedGithubWebhook::CheckSuite(_) => {
            Err(ProviderDeliveryRejection::UnsupportedEvent)
        }
    }
}

fn normalize_push(
    request: &ProviderWebhookRequest,
    event: &VerifiedGithubPush,
) -> Result<NormalizedTrigger, ProviderDeliveryRejection> {
    let repository = target_repository(request, event.installation_id().get(), event.repository())?;
    let before = (!event.created())
        .then(|| GitObjectId::from_provider_hex(event.before_commit_sha()))
        .transpose()
        .map_err(|_| ProviderDeliveryRejection::InvalidPayload)?;
    let after = (!event.deleted())
        .then(|| GitObjectId::from_provider_hex(event.after_commit_sha()))
        .transpose()
        .map_err(|_| ProviderDeliveryRejection::InvalidPayload)?;
    let commits = match event.complete_pushed_commit_revisions() {
        Some(commits) => PushCommitEvidence::complete(commits.iter().copied())
            .map_err(|_| ProviderDeliveryRejection::InvalidPayload)?,
        None => PushCommitEvidence::ProviderLimitExceeded,
    };
    let trigger = PushTrigger::new(
        repository,
        git_ref(event.git_ref())?,
        before,
        after,
        commits,
        event.forced(),
        actor(request, event.actor())?,
    )
    .map_err(|_| ProviderDeliveryRejection::InvalidPayload)?;
    Ok(NormalizedTrigger::Push(trigger))
}

fn normalize_pull_request(
    request: &ProviderWebhookRequest,
    event: &VerifiedGithubPullRequest,
) -> Result<NormalizedTrigger, ProviderDeliveryRejection> {
    let target = target_repository(request, event.installation_id().get(), event.repository())?;
    let source = repository(request, event.head_repository())?;
    let activity = match event.action() {
        GithubPullRequestAction::Opened => PullRequestActivity::Opened,
        GithubPullRequestAction::Reopened => PullRequestActivity::Reopened,
        GithubPullRequestAction::Synchronize => PullRequestActivity::Synchronized,
        GithubPullRequestAction::Closed if event.merged() => PullRequestActivity::Merged,
        GithubPullRequestAction::Closed => PullRequestActivity::Closed,
        GithubPullRequestAction::ReadyForReview => PullRequestActivity::ReadyForReview,
        GithubPullRequestAction::ConvertedToDraft => PullRequestActivity::ConvertedToDraft,
        GithubPullRequestAction::Assigned
        | GithubPullRequestAction::AutoMergeDisabled
        | GithubPullRequestAction::AutoMergeEnabled
        | GithubPullRequestAction::Demilestoned
        | GithubPullRequestAction::Dequeued
        | GithubPullRequestAction::Edited
        | GithubPullRequestAction::Enqueued
        | GithubPullRequestAction::Labeled
        | GithubPullRequestAction::Locked
        | GithubPullRequestAction::Milestoned
        | GithubPullRequestAction::ReviewRequestRemoved
        | GithubPullRequestAction::ReviewRequested
        | GithubPullRequestAction::Stacked
        | GithubPullRequestAction::Unassigned
        | GithubPullRequestAction::Unlabeled
        | GithubPullRequestAction::Unlocked => PullRequestActivity::MetadataChanged,
    };
    let trigger = PullRequestTrigger::new(
        ExternalChangeId::new(event.number().to_string())
            .map_err(|_| ProviderDeliveryRejection::InvalidPayload)?,
        activity,
        target,
        source,
        branch_ref(event.base_ref())?,
        branch_ref(event.head_ref())?,
        *event.base_revision(),
        *event.head_revision(),
        event.merge_revision(),
        event.draft(),
        actor(request, event.actor())?,
        actor(request, event.source_actor())?,
    )
    .map_err(|_| ProviderDeliveryRejection::InvalidPayload)?;
    Ok(NormalizedTrigger::PullRequest(trigger))
}

fn normalize_merge_group(
    request: &ProviderWebhookRequest,
    event: &VerifiedGithubMergeGroup,
) -> Result<NormalizedTrigger, ProviderDeliveryRejection> {
    let repository = target_repository(request, event.installation_id().get(), event.repository())?;
    let activity = match event.action() {
        GithubMergeGroupAction::ChecksRequested => MergeQueueActivity::Queued,
        GithubMergeGroupAction::Destroyed => MergeQueueActivity::Removed,
    };
    let trigger = MergeQueueTrigger::new(
        ExternalMergeQueueId::new(event.head_revision().to_string())
            .map_err(|_| ProviderDeliveryRejection::InvalidPayload)?,
        activity,
        repository,
        git_ref(event.base_ref())?,
        *event.base_revision(),
        *event.head_revision(),
        actor(request, event.actor())?,
    )
    .map_err(|_| ProviderDeliveryRejection::InvalidPayload)?;
    Ok(NormalizedTrigger::MergeQueue(trigger))
}

fn normalize_repository_dispatch(
    request: &ProviderWebhookRequest,
    event: &VerifiedGithubRepositoryDispatch,
) -> Result<NormalizedTrigger, ProviderDeliveryRejection> {
    let repository = target_repository(request, event.installation_id().get(), event.repository())?;
    let input = serde_json::to_vec(
        &event
            .client_payload()
            .cloned()
            .map_or(serde_json::Value::Null, serde_json::Value::Object),
    )
    .map_err(|_| ProviderDeliveryRejection::InvalidPayload)?;
    let trigger = RepositoryDispatchTrigger::new(
        repository,
        ProviderEventName::new(event.event_type().to_owned())
            .map_err(|_| ProviderDeliveryRejection::InvalidPayload)?,
        ProviderDispatchInput::new(input).map_err(|_| ProviderDeliveryRejection::InvalidPayload)?,
        actor(request, event.actor())?,
    )
    .map_err(|_| ProviderDeliveryRejection::InvalidPayload)?;
    Ok(NormalizedTrigger::RepositoryDispatch(trigger))
}

fn target_repository(
    request: &ProviderWebhookRequest,
    installation_id: u64,
    native: &GithubWebhookRepository,
) -> Result<ProviderRepository, ProviderDeliveryRejection> {
    let configuration = request.connection().configuration();
    let policy = decode_connection(configuration.adapter_policy())
        .map_err(|_| ProviderDeliveryRejection::IncompleteEvent)?;
    let external_id = native.id().to_string();
    let visibility = visibility(native.visibility());
    if installation_id != policy.installation_id().get()
        || native.full_name() != policy.repository().as_str()
        || external_id != configuration.repository().external_id().as_str()
        || visibility != configuration.visibility()
    {
        return Err(ProviderDeliveryRejection::PayloadIdentityMismatch);
    }
    repository(request, native)
}

fn repository(
    request: &ProviderWebhookRequest,
    native: &GithubWebhookRepository,
) -> Result<ProviderRepository, ProviderDeliveryRejection> {
    let instance_id = request.endpoint().instance_id();
    Ok(ProviderRepository::new(
        external_repository(instance_id, native),
        ProviderRepositoryPath::new(native.full_name().to_owned())
            .map_err(|_| ProviderDeliveryRejection::InvalidPayload)?,
        visibility(native.visibility()),
    ))
}

fn external_repository(
    instance_id: automata_ci_provider::ProviderInstanceId,
    native: &GithubWebhookRepository,
) -> ExternalRepositoryIdentity {
    ExternalRepositoryIdentity::new(
        instance_id,
        ExternalRepositoryId::new(native.id().to_string())
            .expect("GitHub numeric repository IDs satisfy the common identity bound"),
    )
}

fn actor(
    request: &ProviderWebhookRequest,
    actor: Option<&GithubEventActor>,
) -> Result<Option<ExternalSubjectIdentity>, ProviderDeliveryRejection> {
    let Some(actor) = actor else {
        return Ok(None);
    };
    let kind = match actor.kind() {
        Some(GithubEventActorKind::User) => ExternalSubjectKind::User,
        Some(GithubEventActorKind::Organization) => ExternalSubjectKind::Organization,
        Some(GithubEventActorKind::Bot | GithubEventActorKind::Mannequin) => {
            ExternalSubjectKind::ServiceAccount
        }
        None => return Err(ProviderDeliveryRejection::IncompleteEvent),
    };
    Ok(Some(ExternalSubjectIdentity::new(
        request.endpoint().instance_id(),
        kind,
        ExternalSubjectId::new(actor.id().to_string())
            .map_err(|_| ProviderDeliveryRejection::InvalidPayload)?,
    )))
}

fn git_ref(native: &GithubWebhookRef) -> Result<ProviderGitRef, ProviderDeliveryRejection> {
    let kind = match native.kind() {
        GithubWebhookRefKind::Branch => ProviderGitRefKind::Branch,
        GithubWebhookRefKind::Tag => ProviderGitRefKind::Tag,
    };
    ProviderGitRef::new(native.full().to_owned(), kind)
        .map_err(|_| ProviderDeliveryRejection::InvalidPayload)
}

fn branch_ref(value: &str) -> Result<ProviderGitRef, ProviderDeliveryRejection> {
    ProviderGitRef::new(format!("refs/heads/{value}"), ProviderGitRefKind::Branch)
        .map_err(|_| ProviderDeliveryRejection::InvalidPayload)
}

const fn visibility(value: GithubRepositoryVisibility) -> RepositoryVisibility {
    match value {
        GithubRepositoryVisibility::Public => RepositoryVisibility::Public,
        GithubRepositoryVisibility::Private => RepositoryVisibility::Private,
    }
}

#[derive(Serialize)]
struct GithubDeliveryObservations {
    schema: u8,
    installation_id: u64,
    repository_id: u64,
    repository_owner_id: u64,
}

fn observations(
    event: &VerifiedGithubWebhook,
) -> Result<ProviderDeliveryObservations, ProviderDeliveryRejection> {
    let repository = event.repository();
    let bytes = serde_json::to_vec(&GithubDeliveryObservations {
        schema: 1,
        installation_id: event.installation_id().get(),
        repository_id: repository.id().get(),
        repository_owner_id: repository.owner_id().get(),
    })
    .map_err(|_| ProviderDeliveryRejection::InvalidPayload)?;
    ProviderDeliveryObservations::new(bytes).map_err(|_| ProviderDeliveryRejection::InvalidPayload)
}

fn empty_observations() -> ProviderDeliveryObservations {
    ProviderDeliveryObservations::new(Vec::new())
        .expect("empty provider observations satisfy the common bound")
}

fn rejected(
    authenticated: AuthenticatedProviderWebhook,
    external_delivery: ExternalDeliveryIdentity,
    event_type: ProviderEventName,
    repository: Option<ExternalRepositoryIdentity>,
    reason: ProviderDeliveryRejection,
) -> ProviderDeliveryNormalization {
    let draft = RejectedProviderDeliveryDraft::new(
        ProviderDeliveryId::new(),
        external_delivery,
        event_type,
        authenticated,
        repository,
        reason,
        empty_observations(),
    )
    .expect("GitHub rejection evidence preserves the endpoint instance");
    ProviderDeliveryNormalization::Rejected(Box::new(draft))
}

fn github_headers(
    request: &ProviderWebhookRequest,
) -> Result<HeaderMap, ProviderWebhookAuthenticationError> {
    let mut headers = HeaderMap::new();
    for name in [X_GITHUB_DELIVERY, X_GITHUB_EVENT, X_HUB_SIGNATURE_256] {
        let value = selected_header(request, name)
            .ok_or(ProviderWebhookAuthenticationError::InvalidEvidence)?;
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_bytes(value)
                .map_err(|_| ProviderWebhookAuthenticationError::InvalidEvidence)?,
        );
    }
    Ok(headers)
}

fn selected_header<'request>(
    request: &'request ProviderWebhookRequest,
    name: &str,
) -> Option<&'request [u8]> {
    let name = ProviderWebhookHeaderName::new(name).ok()?;
    request.headers().get(&name)
}
