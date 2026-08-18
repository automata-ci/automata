use automata_ci_core::{
    TrustActorEvidence, TrustActorKind, TrustAutomationKind, TrustEventKind, TrustEvidence,
    TrustOriginKind, TrustPolicy, TrustRepositoryEvidence, TrustSnapshot, TrustSnapshotError,
    TrustTokenRecursion, TrustUpstreamEvidence,
};

use super::{
    GithubEventActor, GithubEventActorKind, GithubEventFacts, GithubEventRepositoryFacts,
    GithubMergeGroupEventFacts, GithubPullRequestEventFacts, GithubPushEventFacts,
    GithubRepositoryDispatchEventFacts, GithubSealedEventEnvelopeV1,
};

/// Admission-time facts that cannot be sealed directly from every webhook body.
#[derive(Clone, Debug, Default)]
pub struct GithubTrustDerivation {
    repository_dispatch_revision: Option<Box<str>>,
    repository_dispatch_recursion: Option<TrustTokenRecursion>,
    merge_group_upstream: Option<TrustUpstreamEvidence>,
}

impl GithubTrustDerivation {
    /// Creates an empty fail-closed derivation context.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            repository_dispatch_revision: None,
            repository_dispatch_recursion: None,
            merge_group_upstream: None,
        }
    }

    /// Binds the exact repository-dispatch source revision resolved under the delivery claim.
    #[must_use]
    pub fn with_repository_dispatch_revision(mut self, revision: impl Into<Box<str>>) -> Self {
        self.repository_dispatch_revision = Some(revision.into());
        self
    }

    /// Binds independently authenticated repository-dispatch token-origin evidence.
    #[must_use]
    pub const fn with_repository_dispatch_recursion(
        mut self,
        recursion: TrustTokenRecursion,
    ) -> Self {
        self.repository_dispatch_recursion = Some(recursion);
        self
    }

    /// Binds provider-authenticated transitive merge-group evidence.
    #[must_use]
    pub fn with_merge_group_upstream(mut self, upstream: TrustUpstreamEvidence) -> Self {
        self.merge_group_upstream = Some(upstream);
        self
    }
}

/// Derives one canonical trust snapshot from a sealed facts-only event envelope.
///
/// The raw JSON body is neither accepted nor inspected. Missing actor
/// classification, dispatch recursion, or resolved revision evidence produces
/// a deny-all snapshot. A provider-authenticated merge group without constituent
/// evidence receives conservative merge-queue authority. Conflicting evidence
/// is rejected.
///
/// # Errors
///
/// Returns a sanitized trust invariant failure for conflicting or malformed
/// authenticated facts.
pub fn derive_github_trust_snapshot(
    envelope: &GithubSealedEventEnvelopeV1,
    policy: &TrustPolicy,
    derivation: &GithubTrustDerivation,
) -> Result<TrustSnapshot, TrustSnapshotError> {
    let evidence = match envelope.event() {
        GithubEventFacts::Push(facts) => push_evidence(facts)?,
        GithubEventFacts::PullRequest(facts) => pull_request_evidence(facts)?,
        GithubEventFacts::MergeGroup(facts) => merge_group_evidence(facts, derivation)?,
        GithubEventFacts::RepositoryDispatch(facts) => dispatch_evidence(facts, derivation)?,
    };
    policy.evaluate(evidence)
}

fn push_evidence(facts: &GithubPushEventFacts) -> Result<TrustEvidence, TrustSnapshotError> {
    let repository = repository(facts.target_repository())?;
    let git_ref = facts.git_ref().full();
    let evidence = TrustEvidence::new(TrustOriginKind::ProviderWebhook, TrustEventKind::Push)
        .with_repositories(repository.clone(), repository)
        .with_refs(git_ref, git_ref, git_ref)
        .with_revisions(
            facts.after_revision(),
            facts.before_revision(),
            facts.after_revision(),
        )
        .with_fork(false)
        .with_token_recursion(TrustTokenRecursion::Suppressed);
    with_event_actor(evidence, facts.actor())
}

fn pull_request_evidence(
    facts: &GithubPullRequestEventFacts,
) -> Result<TrustEvidence, TrustSnapshotError> {
    let source_revision = facts.source_revision().to_string();
    let target_revision = facts.target_revision().to_string();
    let execution_revision = facts.execution_revision().to_string();
    let evidence = TrustEvidence::new(
        TrustOriginKind::ProviderWebhook,
        TrustEventKind::PullRequest,
    )
    .with_activity(facts.action().as_str())
    .with_repositories(
        repository(facts.source_repository())?,
        repository(facts.target_repository())?,
    )
    .with_refs(
        facts.source_ref(),
        facts.target_ref(),
        facts.execution_ref(),
    )
    .with_revisions(source_revision, target_revision, execution_revision)
    .with_fork(facts.is_fork())
    .with_token_recursion(TrustTokenRecursion::Suppressed);
    let mut evidence = with_event_actor(evidence, facts.actor())?;
    if let Some(source_actor) = actor(facts.source_actor())? {
        evidence = evidence.with_source_actor(source_actor);
    }
    Ok(evidence)
}

fn merge_group_evidence(
    facts: &GithubMergeGroupEventFacts,
    derivation: &GithubTrustDerivation,
) -> Result<TrustEvidence, TrustSnapshotError> {
    let repository = repository(facts.target_repository())?;
    let execution_ref = facts.execution_ref().full();
    let target_ref = facts.target_ref().full();
    let execution_revision = facts.execution_revision().to_string();
    let target_revision = facts.target_revision().to_string();
    let evidence = TrustEvidence::new(TrustOriginKind::ProviderWebhook, TrustEventKind::MergeGroup)
        .with_activity(facts.action().as_str())
        .with_repositories(repository.clone(), repository)
        .with_refs(execution_ref, target_ref, execution_ref)
        .with_revisions(
            execution_revision.clone(),
            target_revision,
            execution_revision,
        )
        .with_fork(false)
        .with_token_recursion(TrustTokenRecursion::Suppressed);
    let mut evidence = with_event_actor(evidence, facts.actor())?;
    if let Some(upstream) = derivation.merge_group_upstream.clone() {
        evidence = evidence.with_upstream(upstream);
    }
    Ok(evidence)
}

fn dispatch_evidence(
    facts: &GithubRepositoryDispatchEventFacts,
    derivation: &GithubTrustDerivation,
) -> Result<TrustEvidence, TrustSnapshotError> {
    let repository = repository(facts.target_repository())?;
    let evidence = TrustEvidence::new(
        TrustOriginKind::ProviderWebhook,
        TrustEventKind::RepositoryDispatch,
    )
    .with_activity(facts.event_type())
    .with_repositories(repository.clone(), repository)
    .with_refs(facts.git_ref(), facts.git_ref(), facts.git_ref())
    .with_fork(false)
    .with_token_recursion(
        derivation
            .repository_dispatch_recursion
            .unwrap_or(TrustTokenRecursion::Unknown),
    );
    let mut evidence = with_event_actor(evidence, facts.actor())?;
    if let Some(revision) = derivation.repository_dispatch_revision.as_deref() {
        evidence = evidence.with_revisions(revision, revision, revision);
    }
    Ok(evidence)
}

fn with_event_actor(
    mut evidence: TrustEvidence,
    facts: Option<&GithubEventActor>,
) -> Result<TrustEvidence, TrustSnapshotError> {
    if let Some(actor) = actor(facts)? {
        evidence = evidence
            .with_original_actor(actor.clone())
            .with_triggering_actor(actor);
    }
    Ok(evidence)
}

fn repository(
    facts: &GithubEventRepositoryFacts,
) -> Result<TrustRepositoryEvidence, TrustSnapshotError> {
    TrustRepositoryEvidence::new(facts.id().to_string(), facts.owner_id().to_string())
}

fn actor(
    facts: Option<&GithubEventActor>,
) -> Result<Option<TrustActorEvidence>, TrustSnapshotError> {
    let Some(facts) = facts else {
        return Ok(None);
    };
    let (Some(login), Some(kind)) = (facts.login(), facts.kind()) else {
        return Ok(None);
    };
    let kind = match kind {
        GithubEventActorKind::User => TrustActorKind::User,
        GithubEventActorKind::Bot => TrustActorKind::Bot,
        GithubEventActorKind::Organization => TrustActorKind::Organization,
        GithubEventActorKind::Mannequin => TrustActorKind::Mannequin,
    };
    let automation = if login.eq_ignore_ascii_case("dependabot[bot]")
        || login.eq_ignore_ascii_case("dependabot")
    {
        TrustAutomationKind::Dependabot
    } else if kind == TrustActorKind::Bot {
        TrustAutomationKind::Other
    } else {
        TrustAutomationKind::None
    };
    TrustActorEvidence::new(facts.id().to_string(), kind, automation).map(Some)
}
