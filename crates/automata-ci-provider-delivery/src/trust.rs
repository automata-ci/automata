//! Provider-neutral trust derivation from authenticated normalized triggers.

use automata_ci_core::{
    GitObjectId, TrustActorEvidence, TrustActorKind, TrustAutomationKind, TrustEventKind,
    TrustEvidence, TrustOriginKind, TrustPolicy, TrustRepositoryEvidence, TrustSnapshot,
    TrustSnapshotError, TrustTokenRecursion, TrustUpstreamEvidence,
};
use automata_ci_provider::{
    ExternalSubjectIdentity, ExternalSubjectKind, MergeQueueActivity, MergeQueueTrigger,
    NormalizedTrigger, ProviderGitRef, ProviderRepository, PullRequestActivity, PullRequestTrigger,
    PushTrigger, RepositoryDispatchTrigger,
};

/// Admission-time evidence resolved after webhook normalization.
#[derive(Clone, Debug)]
pub struct ProviderTrustContext {
    source_revision: GitObjectId,
    execution_ref: ProviderGitRef,
    execution_revision: GitObjectId,
    token_recursion: TrustTokenRecursion,
    upstream: Option<TrustUpstreamEvidence>,
}

impl ProviderTrustContext {
    /// Binds exact source and execution coordinates resolved by the selected provider adapter.
    #[must_use]
    pub const fn new(
        source_revision: GitObjectId,
        execution_ref: ProviderGitRef,
        execution_revision: GitObjectId,
        token_recursion: TrustTokenRecursion,
    ) -> Self {
        Self {
            source_revision,
            execution_ref,
            execution_revision,
            token_recursion,
            upstream: None,
        }
    }

    /// Attaches authenticated upstream evidence for a merge-queue candidate.
    #[must_use]
    pub fn with_upstream(mut self, upstream: TrustUpstreamEvidence) -> Self {
        self.upstream = Some(upstream);
        self
    }
}

/// Evaluates the current trust policy from normalized provider evidence.
///
/// Missing actor, recursion, or merge-queue upstream evidence remains valid but
/// produces a fail-closed incomplete snapshot. Conflicting adapter-resolved
/// source or execution coordinates are rejected.
///
/// # Errors
///
/// Rejects malformed, internally conflicting, or adapter-drifted evidence.
pub fn derive_provider_trust_snapshot(
    trigger: &NormalizedTrigger,
    context: &ProviderTrustContext,
) -> Result<TrustSnapshot, TrustSnapshotError> {
    if trigger
        .workflow_source_revision()
        .is_some_and(|revision| revision != context.source_revision)
        || trigger
            .workflow_execution_ref()
            .is_some_and(|git_ref| git_ref != &context.execution_ref)
        || trigger
            .workflow_execution_revision()
            .is_some_and(|revision| revision != context.execution_revision)
    {
        return Err(TrustSnapshotError::ConflictingEvidence);
    }
    let evidence = match trigger {
        NormalizedTrigger::Push(push) => push_evidence(push, context)?,
        NormalizedTrigger::PullRequest(pull_request) => {
            pull_request_evidence(pull_request, context)?
        }
        NormalizedTrigger::MergeQueue(merge_queue) => merge_queue_evidence(merge_queue, context)?,
        NormalizedTrigger::RepositoryDispatch(dispatch) => dispatch_evidence(dispatch, context)?,
    };
    TrustPolicy::current().evaluate(evidence)
}

fn push_evidence(
    push: &PushTrigger,
    context: &ProviderTrustContext,
) -> Result<TrustEvidence, TrustSnapshotError> {
    let repository = repository(push.repository())?;
    let evidence = TrustEvidence::new(TrustOriginKind::ProviderWebhook, TrustEventKind::Push)
        .with_repositories(repository.clone(), repository)
        .with_refs(
            push.git_ref().full(),
            push.git_ref().full(),
            context.execution_ref.full(),
        )
        .with_revisions(
            context.source_revision.to_string(),
            push.before().unwrap_or(context.source_revision).to_string(),
            context.execution_revision.to_string(),
        )
        .with_fork(false)
        .with_token_recursion(context.token_recursion);
    with_event_actor(evidence, push.actor())
}

fn pull_request_evidence(
    pull_request: &PullRequestTrigger,
    context: &ProviderTrustContext,
) -> Result<TrustEvidence, TrustSnapshotError> {
    let evidence = TrustEvidence::new(
        TrustOriginKind::ProviderWebhook,
        TrustEventKind::PullRequest,
    )
    .with_activity(pull_request_activity(pull_request.activity()))
    .with_repositories(
        repository(pull_request.source_repository())?,
        repository(pull_request.target_repository())?,
    )
    .with_refs(
        pull_request.head_ref().full(),
        pull_request.base_ref().full(),
        context.execution_ref.full(),
    )
    .with_revisions(
        context.source_revision.to_string(),
        pull_request.base_object().to_string(),
        context.execution_revision.to_string(),
    )
    .with_fork(
        pull_request.source_repository().identity() != pull_request.target_repository().identity(),
    )
    .with_token_recursion(context.token_recursion);
    let mut evidence = with_event_actor(evidence, pull_request.actor())?;
    if let Some(author) = actor(pull_request.author())? {
        evidence = evidence.with_source_actor(author);
    }
    Ok(evidence)
}

fn merge_queue_evidence(
    merge_queue: &MergeQueueTrigger,
    context: &ProviderTrustContext,
) -> Result<TrustEvidence, TrustSnapshotError> {
    let repository = repository(merge_queue.repository())?;
    let evidence = TrustEvidence::new(TrustOriginKind::ProviderWebhook, TrustEventKind::MergeGroup)
        .with_activity(merge_queue_activity(merge_queue.activity()))
        .with_repositories(repository.clone(), repository)
        .with_refs(
            merge_queue.candidate_ref().full(),
            merge_queue.target_ref().full(),
            context.execution_ref.full(),
        )
        .with_revisions(
            context.source_revision.to_string(),
            merge_queue.target_object().to_string(),
            context.execution_revision.to_string(),
        )
        .with_fork(false)
        .with_token_recursion(context.token_recursion);
    let mut evidence = with_event_actor(evidence, merge_queue.actor())?;
    if let Some(upstream) = context.upstream.clone() {
        evidence = evidence.with_upstream(upstream);
    }
    Ok(evidence)
}

fn dispatch_evidence(
    dispatch: &RepositoryDispatchTrigger,
    context: &ProviderTrustContext,
) -> Result<TrustEvidence, TrustSnapshotError> {
    let repository = repository(dispatch.repository())?;
    let evidence = TrustEvidence::new(
        TrustOriginKind::ProviderWebhook,
        TrustEventKind::RepositoryDispatch,
    )
    .with_activity(dispatch.event_type().as_str())
    .with_repositories(repository.clone(), repository)
    .with_refs(
        context.execution_ref.full(),
        context.execution_ref.full(),
        context.execution_ref.full(),
    )
    .with_revisions(
        context.source_revision.to_string(),
        context.source_revision.to_string(),
        context.execution_revision.to_string(),
    )
    .with_fork(false)
    .with_token_recursion(context.token_recursion);
    with_event_actor(evidence, dispatch.actor())
}

fn repository(value: &ProviderRepository) -> Result<TrustRepositoryEvidence, TrustSnapshotError> {
    TrustRepositoryEvidence::new(
        value.identity().external_id().as_str(),
        value.owner_id().as_str(),
    )
}

fn with_event_actor(
    mut evidence: TrustEvidence,
    value: Option<&ExternalSubjectIdentity>,
) -> Result<TrustEvidence, TrustSnapshotError> {
    if let Some(actor) = actor(value)? {
        evidence = evidence
            .with_original_actor(actor.clone())
            .with_triggering_actor(actor);
    }
    Ok(evidence)
}

fn actor(
    value: Option<&ExternalSubjectIdentity>,
) -> Result<Option<TrustActorEvidence>, TrustSnapshotError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let (kind, automation) = match value.kind() {
        ExternalSubjectKind::User => (TrustActorKind::User, TrustAutomationKind::None),
        ExternalSubjectKind::Organization | ExternalSubjectKind::Team => {
            (TrustActorKind::Organization, TrustAutomationKind::None)
        }
        ExternalSubjectKind::ServiceAccount => (TrustActorKind::Bot, TrustAutomationKind::Other),
    };
    TrustActorEvidence::new(value.external_id().as_str(), kind, automation).map(Some)
}

const fn pull_request_activity(value: PullRequestActivity) -> &'static str {
    match value {
        PullRequestActivity::Opened => "opened",
        PullRequestActivity::Reopened => "reopened",
        PullRequestActivity::Synchronized => "synchronized",
        PullRequestActivity::Closed => "closed",
        PullRequestActivity::Merged => "merged",
        PullRequestActivity::ReadyForReview => "ready_for_review",
        PullRequestActivity::ConvertedToDraft => "converted_to_draft",
        PullRequestActivity::MetadataChanged => "metadata_changed",
    }
}

const fn merge_queue_activity(value: MergeQueueActivity) -> &'static str {
    match value {
        MergeQueueActivity::Queued => "queued",
        MergeQueueActivity::Removed => "removed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use automata_ci_core::TrustSourceClass;
    use automata_ci_provider::{
        ExternalChangeId, ExternalRepositoryId, ExternalRepositoryIdentity, ExternalSubjectId,
        ExternalSubjectKind, ProviderGitRefKind, ProviderInstanceId, ProviderRepositoryPath,
        PullRequestTrigger, PushCommitEvidence, PushTrigger, RepositoryVisibility,
    };

    fn object(value: char) -> GitObjectId {
        GitObjectId::from_provider_hex(value.to_string().repeat(40)).expect("object")
    }

    fn repository(
        instance: ProviderInstanceId,
        id: &str,
        owner: &str,
        path: &str,
    ) -> ProviderRepository {
        ProviderRepository::new(
            ExternalRepositoryIdentity::new(
                instance,
                ExternalRepositoryId::new(id).expect("repository ID"),
            ),
            ExternalSubjectId::new(owner).expect("owner ID"),
            ProviderRepositoryPath::new(path).expect("repository path"),
            RepositoryVisibility::Private,
        )
    }

    fn actor(instance: ProviderInstanceId, id: &str) -> ExternalSubjectIdentity {
        ExternalSubjectIdentity::new(
            instance,
            ExternalSubjectKind::User,
            ExternalSubjectId::new(id).expect("actor ID"),
        )
    }

    #[test]
    fn push_derivation_is_provider_neutral_and_complete() {
        let instance = ProviderInstanceId::new();
        let git_ref =
            ProviderGitRef::new("refs/heads/main", ProviderGitRefKind::Branch).expect("branch");
        let trigger = NormalizedTrigger::Push(
            PushTrigger::new(
                repository(instance, "42", "7", "owner/repository"),
                git_ref.clone(),
                Some(object('a')),
                Some(object('b')),
                PushCommitEvidence::complete([object('b')]).expect("commits"),
                false,
                Some(actor(instance, "9")),
            )
            .expect("push"),
        );
        let context = ProviderTrustContext::new(
            object('b'),
            git_ref,
            object('b'),
            TrustTokenRecursion::Suppressed,
        );
        let snapshot = derive_provider_trust_snapshot(&trigger, &context).expect("snapshot");
        assert_eq!(snapshot.source_class(), TrustSourceClass::SameRepository);
        assert!(snapshot.evidence_complete());
    }

    #[test]
    fn pull_request_fork_is_derived_from_stable_repository_identities() {
        let instance = ProviderInstanceId::new();
        let head_ref = ProviderGitRef::new("refs/heads/feature", ProviderGitRefKind::Branch)
            .expect("head ref");
        let base_ref =
            ProviderGitRef::new("refs/heads/main", ProviderGitRefKind::Branch).expect("base ref");
        let execution_ref = ProviderGitRef::new("refs/pull/1/merge", ProviderGitRefKind::Synthetic)
            .expect("execution ref");
        let trigger = NormalizedTrigger::PullRequest(Box::new(
            PullRequestTrigger::new(
                ExternalChangeId::new("1").expect("change ID"),
                PullRequestActivity::Synchronized,
                repository(instance, "42", "7", "owner/repository"),
                repository(instance, "84", "8", "fork/repository"),
                base_ref,
                head_ref,
                execution_ref.clone(),
                object('a'),
                object('b'),
                Some(object('c')),
                false,
                Some(actor(instance, "9")),
                Some(actor(instance, "10")),
            )
            .expect("pull request"),
        ));
        let context = ProviderTrustContext::new(
            object('b'),
            execution_ref,
            object('c'),
            TrustTokenRecursion::Suppressed,
        );
        let snapshot = derive_provider_trust_snapshot(&trigger, &context).expect("snapshot");
        assert_eq!(snapshot.source_class(), TrustSourceClass::Fork);
        assert!(snapshot.evidence_complete());
    }
}
