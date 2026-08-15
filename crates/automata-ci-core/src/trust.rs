//! Versioned, provider-neutral workflow trust evidence and authority reduction.

use std::{fmt, num::NonZeroU64};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::Sha256Digest;

/// Current canonical trust-policy schema.
pub const TRUST_POLICY_SCHEMA_V1: u16 = 1;
/// Current canonical trust-snapshot schema.
pub const TRUST_SNAPSHOT_SCHEMA_V1: u16 = 1;
/// Maximum canonical trust-snapshot size accepted at admission and execution.
pub const MAX_TRUST_SNAPSHOT_BYTES: usize = 32_768;
/// Durable media type for canonical schema-v1 trust snapshots.
pub const TRUST_SNAPSHOT_V1_MEDIA_TYPE: &str =
    "application/vnd.automata.workflow-trust-snapshot.v1+json";

const POLICY_DIGEST_DOMAIN: &[u8] = b"automata.workflow-trust-policy.v1\0";
const SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"automata.workflow-trust-snapshot.v1\0";
const MAX_TRUST_TEXT_BYTES: usize = 1_024;

/// Explicit repository policy for write-capable jobs sourced from forks.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkWritePolicy {
    /// Fork jobs are reduced to read-only repository authority.
    Deny,
    /// Fork jobs may retain requested repository writes; normal secrets remain denied.
    AllowExplicitly,
}

/// Explicit recursion policy for repository-dispatch events.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchRecursionPolicy {
    /// A dispatch with incomplete token-origin evidence is denied authority.
    RequireExternalOrigin,
    /// An authenticated explicit dispatch may recurse under the repository policy.
    AllowExplicitly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustPolicyDocument {
    schema: u16,
    revision: NonZeroU64,
    fork_writes: ForkWritePolicy,
    dispatch_recursion: DispatchRecursionPolicy,
}

/// Immutable policy used to reduce authenticated event authority.
#[derive(Clone, Eq, PartialEq)]
pub struct TrustPolicy {
    document: TrustPolicyDocument,
    canonical_bytes: Box<[u8]>,
    digest: Sha256Digest,
}

impl TrustPolicy {
    /// Builds the current least-authority policy.
    #[must_use]
    pub fn current() -> Self {
        Self::new(
            NonZeroU64::MIN,
            ForkWritePolicy::Deny,
            DispatchRecursionPolicy::RequireExternalOrigin,
        )
    }

    /// Builds a revision-pinned policy with explicit exceptional behavior.
    ///
    /// # Panics
    ///
    /// Panics only if serialization of this closed scalar policy document fails,
    /// which indicates a programming or runtime invariant violation.
    #[must_use]
    pub fn new(
        revision: NonZeroU64,
        fork_writes: ForkWritePolicy,
        dispatch_recursion: DispatchRecursionPolicy,
    ) -> Self {
        let document = TrustPolicyDocument {
            schema: TRUST_POLICY_SCHEMA_V1,
            revision,
            fork_writes,
            dispatch_recursion,
        };
        let canonical_bytes = serde_json::to_vec(&document)
            .expect("trust policy contains only infallible canonical fields");
        let digest = domain_digest(POLICY_DIGEST_DOMAIN, &canonical_bytes);
        Self {
            document,
            canonical_bytes: canonical_bytes.into_boxed_slice(),
            digest,
        }
    }

    /// Returns the policy schema.
    #[must_use]
    pub const fn schema(&self) -> u16 {
        self.document.schema
    }

    /// Returns the immutable policy revision.
    #[must_use]
    pub const fn revision(&self) -> NonZeroU64 {
        self.document.revision
    }

    /// Returns the explicit fork-write policy.
    #[must_use]
    pub const fn fork_write_policy(&self) -> ForkWritePolicy {
        self.document.fork_writes
    }

    /// Returns the explicit repository-dispatch recursion policy.
    #[must_use]
    pub const fn dispatch_recursion_policy(&self) -> DispatchRecursionPolicy {
        self.document.dispatch_recursion
    }

    /// Returns canonical policy bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the domain-separated policy digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Evaluates one bounded authenticated evidence set without I/O.
    ///
    /// # Errors
    ///
    /// Conflicting source/target, fork, event/origin, recursion, or transitive
    /// evidence is rejected. Missing evidence produces a deny-all snapshot.
    pub fn evaluate(&self, evidence: TrustEvidence) -> Result<TrustSnapshot, TrustSnapshotError> {
        evidence.validate()?;
        let complete = evidence.is_complete(self);
        let source = source_classification(&evidence, complete)?;
        let authority = authority_decision(self, source, complete);
        TrustSnapshot::from_document(TrustSnapshotDocument {
            schema: TRUST_SNAPSHOT_SCHEMA_V1,
            policy: self.document.clone(),
            policy_digest: self.digest,
            evidence,
            evidence_complete: complete,
            source,
            authority,
        })
    }
}

impl fmt::Debug for TrustPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustPolicy")
            .field("schema", &self.schema())
            .field("revision", &self.revision())
            .field("digest", &self.digest)
            .field("fork_writes", &self.fork_write_policy())
            .field("dispatch_recursion", &self.dispatch_recursion_policy())
            .finish_non_exhaustive()
    }
}

impl Serialize for TrustPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.document.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TrustPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let document = TrustPolicyDocument::deserialize(deserializer)?;
        if document.schema != TRUST_POLICY_SCHEMA_V1 {
            return Err(D::Error::custom("unsupported trust policy schema"));
        }
        Ok(Self::new(
            document.revision,
            document.fork_writes,
            document.dispatch_recursion,
        ))
    }
}

/// Closed origin of a trust evaluation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustOriginKind {
    /// A signature-authenticated provider webhook.
    ProviderWebhook,
    /// An authenticated human workflow dispatch.
    WorkflowDispatch,
    /// A scheduler-owned fire over exact repository evidence.
    Schedule,
    /// A chained run carrying upstream trust evidence.
    WorkflowRun,
    /// A rerun that must retain the source run's original snapshot.
    Rerun,
}

/// Closed event behavior relevant to authority reduction.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustEventKind {
    /// A repository push.
    Push,
    /// An ordinary pull request.
    PullRequest,
    /// A privileged base-context pull-request transition.
    PullRequestTarget,
    /// A merge-queue group.
    MergeGroup,
    /// An explicit repository dispatch.
    RepositoryDispatch,
    /// A human workflow dispatch.
    WorkflowDispatch,
    /// A scheduler-owned run.
    Schedule,
    /// A chained workflow-run event.
    WorkflowRun,
}

/// Closed authenticated actor kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustActorKind {
    /// Human or service user.
    User,
    /// Provider bot or App identity.
    Bot,
    /// Organization identity.
    Organization,
    /// Imported placeholder identity.
    Mannequin,
    /// Internal scheduler or another non-user service identity.
    System,
}

/// Closed automation classification derived from authenticated actor evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustAutomationKind {
    /// Actor is not recognized as dependency automation.
    None,
    /// GitHub Dependabot automation.
    Dependabot,
    /// Other provider automation that cannot inherit human authority.
    Other,
}

/// Stable authenticated actor evidence retained independently from display data.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustActorEvidence {
    id: Box<str>,
    kind: TrustActorKind,
    automation: TrustAutomationKind,
}

impl TrustActorEvidence {
    /// Creates bounded stable actor evidence.
    ///
    /// # Errors
    ///
    /// Rejects empty, padded, oversized, or control-bearing identities.
    pub fn new(
        id: impl Into<Box<str>>,
        kind: TrustActorKind,
        automation: TrustAutomationKind,
    ) -> Result<Self, TrustSnapshotError> {
        let id = id.into();
        validate_text(&id)?;
        Ok(Self {
            id,
            kind,
            automation,
        })
    }

    /// Returns the stable provider or internal identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the closed actor kind.
    #[must_use]
    pub const fn kind(&self) -> TrustActorKind {
        self.kind
    }

    /// Returns the authenticated automation class.
    #[must_use]
    pub const fn automation(&self) -> TrustAutomationKind {
        self.automation
    }
}

impl fmt::Debug for TrustActorEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustActorEvidence")
            .field("id", &"[REDACTED]")
            .field("kind", &self.kind)
            .field("automation", &self.automation)
            .finish()
    }
}

/// Stable authenticated repository identity used for source/target comparison.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRepositoryEvidence {
    id: Box<str>,
    owner_id: Box<str>,
}

impl TrustRepositoryEvidence {
    /// Creates bounded provider repository and owner identities.
    ///
    /// # Errors
    ///
    /// Rejects invalid identity text.
    pub fn new(
        id: impl Into<Box<str>>,
        owner_id: impl Into<Box<str>>,
    ) -> Result<Self, TrustSnapshotError> {
        let id = id.into();
        let owner_id = owner_id.into();
        validate_text(&id)?;
        validate_text(&owner_id)?;
        Ok(Self { id, owner_id })
    }

    /// Returns the stable repository ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the stable repository-owner ID.
    #[must_use]
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }
}

impl fmt::Debug for TrustRepositoryEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustRepositoryEvidence")
            .field("id", &"[REDACTED]")
            .field("owner_id", &"[REDACTED]")
            .finish()
    }
}

/// Token-origin evidence relevant to event recursion.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustTokenRecursion {
    /// Provider semantics suppress repository-token recursion.
    Suppressed,
    /// The event is authenticated as external to an Automata job token.
    External,
    /// Recursion is explicitly permitted by pinned policy.
    ExplicitlyAllowed,
    /// Token origin is incomplete and cannot authorize a recursive transition.
    Unknown,
}

/// Transitive evidence supplied by a chained workflow run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustUpstreamEvidence {
    snapshot_digest: Sha256Digest,
    chain_depth: u8,
    evidence_complete: bool,
    source: TrustSourceClass,
}

impl TrustUpstreamEvidence {
    /// Creates bounded upstream trust evidence.
    ///
    /// # Errors
    ///
    /// Rejects zero or more-than-three-level chains.
    pub fn new(
        snapshot_digest: Sha256Digest,
        chain_depth: u8,
        evidence_complete: bool,
        source: TrustSourceClass,
    ) -> Result<Self, TrustSnapshotError> {
        if !(1..=3).contains(&chain_depth) {
            return Err(TrustSnapshotError::InvalidTransitiveEvidence);
        }
        Ok(Self {
            snapshot_digest,
            chain_depth,
            evidence_complete,
            source,
        })
    }

    /// Returns the exact upstream snapshot digest.
    #[must_use]
    pub const fn snapshot_digest(&self) -> Sha256Digest {
        self.snapshot_digest
    }

    /// Returns the one-based chain depth.
    #[must_use]
    pub const fn chain_depth(&self) -> u8 {
        self.chain_depth
    }

    /// Reports whether upstream evidence was complete.
    #[must_use]
    pub const fn evidence_complete(&self) -> bool {
        self.evidence_complete
    }

    /// Returns the upstream source classification.
    #[must_use]
    pub const fn source(&self) -> TrustSourceClass {
        self.source
    }
}

/// Authenticated facts consumed by the pure trust policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustEvidence {
    origin: TrustOriginKind,
    event: TrustEventKind,
    activity: Option<Box<str>>,
    original_actor: Option<TrustActorEvidence>,
    triggering_actor: Option<TrustActorEvidence>,
    source_actor: Option<TrustActorEvidence>,
    source_repository: Option<TrustRepositoryEvidence>,
    target_repository: Option<TrustRepositoryEvidence>,
    source_ref: Option<Box<str>>,
    target_ref: Option<Box<str>>,
    execution_ref: Option<Box<str>>,
    source_revision: Option<Box<str>>,
    target_revision: Option<Box<str>>,
    execution_revision: Option<Box<str>>,
    fork: Option<bool>,
    privileged_transition: bool,
    upstream: Option<TrustUpstreamEvidence>,
    token_recursion: TrustTokenRecursion,
}

impl TrustEvidence {
    /// Starts a fail-closed evidence set for one exact origin and event kind.
    #[must_use]
    pub const fn new(origin: TrustOriginKind, event: TrustEventKind) -> Self {
        Self {
            origin,
            event,
            activity: None,
            original_actor: None,
            triggering_actor: None,
            source_actor: None,
            source_repository: None,
            target_repository: None,
            source_ref: None,
            target_ref: None,
            execution_ref: None,
            source_revision: None,
            target_revision: None,
            execution_revision: None,
            fork: None,
            privileged_transition: false,
            upstream: None,
            token_recursion: TrustTokenRecursion::Unknown,
        }
    }

    /// Attaches the closed provider activity.
    #[must_use]
    pub fn with_activity(mut self, value: impl Into<Box<str>>) -> Self {
        self.activity = Some(value.into());
        self
    }

    /// Attaches the actor whose authority created the original run.
    #[must_use]
    pub fn with_original_actor(mut self, value: TrustActorEvidence) -> Self {
        self.original_actor = Some(value);
        self
    }

    /// Attaches the current physical-attempt initiator without upgrading authority.
    #[must_use]
    pub fn with_triggering_actor(mut self, value: TrustActorEvidence) -> Self {
        self.triggering_actor = Some(value);
        self
    }

    /// Attaches a distinct source author.
    #[must_use]
    pub fn with_source_actor(mut self, value: TrustActorEvidence) -> Self {
        self.source_actor = Some(value);
        self
    }

    /// Attaches the source and target repositories independently.
    #[must_use]
    pub fn with_repositories(
        mut self,
        source: TrustRepositoryEvidence,
        target: TrustRepositoryEvidence,
    ) -> Self {
        self.source_repository = Some(source);
        self.target_repository = Some(target);
        self
    }

    /// Attaches only the source repository when target evidence is not yet available.
    #[must_use]
    pub fn with_source_repository(mut self, value: TrustRepositoryEvidence) -> Self {
        self.source_repository = Some(value);
        self
    }

    /// Attaches only the target repository when transitive source evidence is absent.
    #[must_use]
    pub fn with_target_repository(mut self, value: TrustRepositoryEvidence) -> Self {
        self.target_repository = Some(value);
        self
    }

    /// Attaches source, target, and execution references independently.
    #[must_use]
    pub fn with_refs(
        mut self,
        source: impl Into<Box<str>>,
        target: impl Into<Box<str>>,
        execution: impl Into<Box<str>>,
    ) -> Self {
        self.source_ref = Some(source.into());
        self.target_ref = Some(target.into());
        self.execution_ref = Some(execution.into());
        self
    }

    /// Attaches only the source reference.
    #[must_use]
    pub fn with_source_ref(mut self, value: impl Into<Box<str>>) -> Self {
        self.source_ref = Some(value.into());
        self
    }

    /// Attaches only the target reference.
    #[must_use]
    pub fn with_target_ref(mut self, value: impl Into<Box<str>>) -> Self {
        self.target_ref = Some(value.into());
        self
    }

    /// Attaches only the execution reference.
    #[must_use]
    pub fn with_execution_ref(mut self, value: impl Into<Box<str>>) -> Self {
        self.execution_ref = Some(value.into());
        self
    }

    /// Attaches source, target, and execution revisions independently.
    #[must_use]
    pub fn with_revisions(
        mut self,
        source: impl Into<Box<str>>,
        target: impl Into<Box<str>>,
        execution: impl Into<Box<str>>,
    ) -> Self {
        self.source_revision = Some(source.into());
        self.target_revision = Some(target.into());
        self.execution_revision = Some(execution.into());
        self
    }

    /// Attaches only the source revision.
    #[must_use]
    pub fn with_source_revision(mut self, value: impl Into<Box<str>>) -> Self {
        self.source_revision = Some(value.into());
        self
    }

    /// Attaches only the target revision.
    #[must_use]
    pub fn with_target_revision(mut self, value: impl Into<Box<str>>) -> Self {
        self.target_revision = Some(value.into());
        self
    }

    /// Attaches only the execution revision.
    #[must_use]
    pub fn with_execution_revision(mut self, value: impl Into<Box<str>>) -> Self {
        self.execution_revision = Some(value.into());
        self
    }

    /// Attaches the authenticated source/target fork relationship.
    #[must_use]
    pub const fn with_fork(mut self, value: bool) -> Self {
        self.fork = Some(value);
        self
    }

    /// Marks a base-context transition that must preserve source restrictions.
    #[must_use]
    pub const fn with_privileged_transition(mut self, value: bool) -> Self {
        self.privileged_transition = value;
        self
    }

    /// Attaches transitive upstream-run evidence.
    #[must_use]
    pub fn with_upstream(mut self, value: TrustUpstreamEvidence) -> Self {
        self.upstream = Some(value);
        self
    }

    /// Attaches token-origin recursion evidence.
    #[must_use]
    pub const fn with_token_recursion(mut self, value: TrustTokenRecursion) -> Self {
        self.token_recursion = value;
        self
    }

    /// Returns the origin kind.
    #[must_use]
    pub const fn origin(&self) -> TrustOriginKind {
        self.origin
    }

    /// Returns the event kind.
    #[must_use]
    pub const fn event(&self) -> TrustEventKind {
        self.event
    }

    /// Returns the original authority actor.
    #[must_use]
    pub const fn original_actor(&self) -> Option<&TrustActorEvidence> {
        self.original_actor.as_ref()
    }

    /// Returns the current attempt initiator.
    #[must_use]
    pub const fn triggering_actor(&self) -> Option<&TrustActorEvidence> {
        self.triggering_actor.as_ref()
    }

    /// Returns the authenticated source repository.
    #[must_use]
    pub const fn source_repository(&self) -> Option<&TrustRepositoryEvidence> {
        self.source_repository.as_ref()
    }

    /// Returns the authenticated target repository.
    #[must_use]
    pub const fn target_repository(&self) -> Option<&TrustRepositoryEvidence> {
        self.target_repository.as_ref()
    }

    /// Returns the authenticated source ref.
    #[must_use]
    pub fn source_ref(&self) -> Option<&str> {
        self.source_ref.as_deref()
    }

    /// Returns the authenticated target ref.
    #[must_use]
    pub fn target_ref(&self) -> Option<&str> {
        self.target_ref.as_deref()
    }

    /// Returns the exact ref whose source is executed.
    #[must_use]
    pub fn execution_ref(&self) -> Option<&str> {
        self.execution_ref.as_deref()
    }

    /// Returns the authenticated source revision.
    #[must_use]
    pub fn source_revision(&self) -> Option<&str> {
        self.source_revision.as_deref()
    }

    /// Returns the authenticated target revision.
    #[must_use]
    pub fn target_revision(&self) -> Option<&str> {
        self.target_revision.as_deref()
    }

    /// Returns the exact revision whose source is executed.
    #[must_use]
    pub fn execution_revision(&self) -> Option<&str> {
        self.execution_revision.as_deref()
    }

    /// Returns the authenticated fork relationship.
    #[must_use]
    pub const fn fork(&self) -> Option<bool> {
        self.fork
    }

    /// Returns the transitive upstream evidence.
    #[must_use]
    pub const fn upstream(&self) -> Option<&TrustUpstreamEvidence> {
        self.upstream.as_ref()
    }

    /// Returns token-origin recursion evidence.
    #[must_use]
    pub const fn token_recursion(&self) -> TrustTokenRecursion {
        self.token_recursion
    }

    fn validate(&self) -> Result<(), TrustSnapshotError> {
        for value in [
            self.activity.as_deref(),
            self.source_ref.as_deref(),
            self.target_ref.as_deref(),
            self.execution_ref.as_deref(),
            self.source_revision.as_deref(),
            self.target_revision.as_deref(),
            self.execution_revision.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_text(value)?;
        }
        let expected_origin = match self.event {
            TrustEventKind::Push
            | TrustEventKind::PullRequest
            | TrustEventKind::PullRequestTarget
            | TrustEventKind::MergeGroup
            | TrustEventKind::RepositoryDispatch => TrustOriginKind::ProviderWebhook,
            TrustEventKind::WorkflowDispatch => TrustOriginKind::WorkflowDispatch,
            TrustEventKind::Schedule => TrustOriginKind::Schedule,
            TrustEventKind::WorkflowRun => TrustOriginKind::WorkflowRun,
        };
        if self.origin != expected_origin && self.origin != TrustOriginKind::Rerun {
            return Err(TrustSnapshotError::ConflictingEvidence);
        }
        if self.origin == TrustOriginKind::Rerun {
            return Err(TrustSnapshotError::RerunMustReuseSnapshot);
        }
        if let (Some(source), Some(target), Some(fork)) = (
            self.source_repository.as_ref(),
            self.target_repository.as_ref(),
            self.fork,
        ) && (source.id != target.id) != fork
        {
            return Err(TrustSnapshotError::ConflictingEvidence);
        }
        if !matches!(
            self.event,
            TrustEventKind::MergeGroup | TrustEventKind::WorkflowRun
        ) && self.upstream.is_some()
        {
            return Err(TrustSnapshotError::ConflictingEvidence);
        }
        if let Some(upstream) = &self.upstream
            && (!(1..=3).contains(&upstream.chain_depth)
                || upstream
                    .snapshot_digest
                    .as_bytes()
                    .iter()
                    .all(|byte| *byte == 0)
                || upstream.evidence_complete != (upstream.source != TrustSourceClass::Incomplete))
        {
            return Err(TrustSnapshotError::InvalidTransitiveEvidence);
        }
        if self.event == TrustEventKind::RepositoryDispatch
            && self.token_recursion == TrustTokenRecursion::Suppressed
        {
            return Err(TrustSnapshotError::ConflictingEvidence);
        }
        Ok(())
    }

    fn is_complete(&self, policy: &TrustPolicy) -> bool {
        let actor_complete = self.original_actor.is_some();
        let repositories_complete = self.source_repository.is_some()
            && self.target_repository.is_some()
            && self.fork.is_some();
        let refs_complete =
            self.source_ref.is_some() && self.target_ref.is_some() && self.execution_ref.is_some();
        let revisions_complete = self.source_revision.is_some()
            && self.target_revision.is_some()
            && self.execution_revision.is_some();
        let base = actor_complete && repositories_complete && refs_complete && revisions_complete;
        match self.event {
            TrustEventKind::Push => {
                base && self.fork == Some(false)
                    && self.token_recursion == TrustTokenRecursion::Suppressed
            }
            TrustEventKind::PullRequest => base && self.source_actor.is_some(),
            TrustEventKind::PullRequestTarget => {
                base && self.source_actor.is_some() && self.privileged_transition
            }
            TrustEventKind::MergeGroup => {
                base && self
                    .upstream
                    .as_ref()
                    .is_some_and(|upstream| upstream.evidence_complete && upstream.chain_depth <= 3)
            }
            TrustEventKind::RepositoryDispatch => {
                base && (self.token_recursion == TrustTokenRecursion::External
                    || (self.token_recursion == TrustTokenRecursion::ExplicitlyAllowed
                        && policy.dispatch_recursion_policy()
                            == DispatchRecursionPolicy::AllowExplicitly))
            }
            TrustEventKind::WorkflowDispatch | TrustEventKind::Schedule => {
                base && self.fork == Some(false)
            }
            TrustEventKind::WorkflowRun => {
                base && self
                    .upstream
                    .as_ref()
                    .is_some_and(|upstream| upstream.evidence_complete && upstream.chain_depth <= 3)
            }
        }
    }
}

/// Closed source classification shared by every authority consumer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustSourceClass {
    /// Complete same-repository non-Dependabot evidence.
    SameRepository,
    /// Complete fork evidence.
    Fork,
    /// Complete same-repository Dependabot evidence.
    Dependabot,
    /// Complete evidence for another provider automation actor.
    Automation,
    /// Missing transitive or direct evidence; all authority is denied.
    Incomplete,
}

/// Effective repository-permission ceiling.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustPermissionAuthority {
    /// Preserve the exact resolved request.
    Requested,
    /// Reduce every writable scope to at most read and remove write-only scopes.
    ReadOnly,
    /// Deny every repository permission.
    DenyAll,
}

/// Effective normal-secret authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustSecretAuthority {
    /// Normal eligible secrets may be resolved by later scoped policy.
    Eligible,
    /// Normal secrets must not enter runtime context or custody.
    Denied,
}

/// Effective cache authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustCacheAuthority {
    /// Read and write within the exact trust-partitioned cache namespace.
    ReadWrite,
    /// Restore-only access to a trust-partitioned namespace.
    ReadOnly,
    /// No cache credential or cache operation.
    Denied,
}

/// Effective protected-environment authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustEnvironmentAuthority {
    /// Later exact environment policy may admit the job.
    Eligible,
    /// The job cannot enter a protected environment.
    Denied,
}

/// Effective OIDC authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustOidcAuthority {
    /// A later permission and lease proof may issue an OIDC token.
    Eligible,
    /// No OIDC request bearer may be issued.
    Denied,
}

/// Effective output publication class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustOutputAuthority {
    /// Standard output policy applies.
    Standard,
    /// Outputs remain untrusted and cannot authorize privileged consumers.
    Untrusted,
}

/// Effective Results authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustResultsAuthority {
    /// Standard exact-fence Results credentials may be issued.
    Standard,
    /// Results are restricted to untrusted/read-only publication semantics.
    Untrusted,
    /// No Results credential may be issued.
    Denied,
}

/// One coherent authority decision consumed by all execution subsystems.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustAuthorityDecision {
    permissions: TrustPermissionAuthority,
    secrets: TrustSecretAuthority,
    cache: TrustCacheAuthority,
    environment: TrustEnvironmentAuthority,
    oidc: TrustOidcAuthority,
    outputs: TrustOutputAuthority,
    results: TrustResultsAuthority,
}

impl TrustAuthorityDecision {
    /// Returns the repository-permission ceiling.
    #[must_use]
    pub const fn permissions(self) -> TrustPermissionAuthority {
        self.permissions
    }

    /// Returns normal-secret eligibility.
    #[must_use]
    pub const fn secrets(self) -> TrustSecretAuthority {
        self.secrets
    }

    /// Returns cache authority.
    #[must_use]
    pub const fn cache(self) -> TrustCacheAuthority {
        self.cache
    }

    /// Returns protected-environment eligibility.
    #[must_use]
    pub const fn environment(self) -> TrustEnvironmentAuthority {
        self.environment
    }

    /// Returns OIDC eligibility.
    #[must_use]
    pub const fn oidc(self) -> TrustOidcAuthority {
        self.oidc
    }

    /// Returns output publication authority.
    #[must_use]
    pub const fn outputs(self) -> TrustOutputAuthority {
        self.outputs
    }

    /// Returns Results authority.
    #[must_use]
    pub const fn results(self) -> TrustResultsAuthority {
        self.results
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustSnapshotDocument {
    schema: u16,
    policy: TrustPolicyDocument,
    policy_digest: Sha256Digest,
    evidence: TrustEvidence,
    evidence_complete: bool,
    source: TrustSourceClass,
    authority: TrustAuthorityDecision,
}

/// Canonical immutable trust classification and exact authority reduction.
#[derive(Clone, Eq, PartialEq)]
pub struct TrustSnapshot {
    document: TrustSnapshotDocument,
    canonical_bytes: Box<[u8]>,
    digest: Sha256Digest,
    construction_placeholder: bool,
}

impl TrustSnapshot {
    /// Creates a structurally valid deny-all snapshot for absent evidence.
    ///
    /// Production admission must replace this snapshot before projection.
    ///
    /// # Panics
    ///
    /// Panics only if the internally constructed incomplete evidence cannot be
    /// evaluated, which indicates a programming invariant violation.
    #[must_use]
    pub fn deny_all_unclassified() -> Self {
        let policy = TrustPolicy::current();
        let mut snapshot = policy
            .evaluate(TrustEvidence::new(
                TrustOriginKind::ProviderWebhook,
                TrustEventKind::Push,
            ))
            .expect("empty evidence is incomplete rather than conflicting");
        snapshot.construction_placeholder = true;
        snapshot
    }

    /// Rehydrates exact canonical snapshot bytes and validates their digest.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, malformed, noncanonical, unsupported,
    /// internally conflicting, or digest-mismatched snapshots.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        expected_digest: Sha256Digest,
    ) -> Result<Self, TrustSnapshotError> {
        if bytes.is_empty() || bytes.len() > MAX_TRUST_SNAPSHOT_BYTES {
            return Err(TrustSnapshotError::InvalidEncoding);
        }
        let document: TrustSnapshotDocument =
            serde_json::from_slice(bytes).map_err(|_| TrustSnapshotError::InvalidEncoding)?;
        let snapshot = Self::from_document(document)?;
        if snapshot.canonical_bytes.as_ref() != bytes {
            return Err(TrustSnapshotError::NoncanonicalEncoding);
        }
        if snapshot.digest != expected_digest {
            return Err(TrustSnapshotError::DigestMismatch);
        }
        Ok(snapshot)
    }

    fn from_document(document: TrustSnapshotDocument) -> Result<Self, TrustSnapshotError> {
        validate_document(&document)?;
        let canonical_bytes =
            serde_json::to_vec(&document).map_err(|_| TrustSnapshotError::InvalidEncoding)?;
        if canonical_bytes.len() > MAX_TRUST_SNAPSHOT_BYTES {
            return Err(TrustSnapshotError::InvalidEncoding);
        }
        let digest = domain_digest(SNAPSHOT_DIGEST_DOMAIN, &canonical_bytes);
        Ok(Self {
            document,
            canonical_bytes: canonical_bytes.into_boxed_slice(),
            digest,
            construction_placeholder: false,
        })
    }

    /// Returns the snapshot schema.
    #[must_use]
    pub const fn schema(&self) -> u16 {
        self.document.schema
    }

    /// Returns the pinned trust-policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> NonZeroU64 {
        self.document.policy.revision
    }

    /// Returns the pinned trust-policy digest.
    #[must_use]
    pub const fn policy_digest(&self) -> Sha256Digest {
        self.document.policy_digest
    }

    /// Returns the exact authenticated evidence retained by the snapshot.
    #[must_use]
    pub const fn evidence(&self) -> &TrustEvidence {
        &self.document.evidence
    }

    /// Reports whether every event-specific trust dimension was present.
    #[must_use]
    pub const fn evidence_complete(&self) -> bool {
        self.document.evidence_complete
    }

    /// Returns the one source classification shared by all consumers.
    #[must_use]
    pub const fn source_class(&self) -> TrustSourceClass {
        self.document.source
    }

    /// Returns the coherent authority decision shared by all consumers.
    #[must_use]
    pub const fn authority(&self) -> TrustAuthorityDecision {
        self.document.authority
    }

    /// Returns canonical snapshot bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the domain-separated snapshot digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Reports whether this is the fail-closed placeholder for absent evidence.
    #[must_use]
    pub fn is_unclassified(&self) -> bool {
        !self.document.evidence_complete && self.document.source == TrustSourceClass::Incomplete
    }

    /// Reports whether this value is only a local construction default.
    ///
    /// Placeholders are never accepted by durable admission. A snapshot
    /// rehydrated from sealed bytes is not a placeholder, even when its
    /// authenticated evidence is incomplete and therefore deny-all.
    #[must_use]
    pub const fn is_construction_placeholder(&self) -> bool {
        self.construction_placeholder
    }
}

impl fmt::Debug for TrustSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustSnapshot")
            .field("schema", &self.schema())
            .field("policy_revision", &self.policy_revision())
            .field("policy_digest", &self.policy_digest())
            .field("digest", &self.digest)
            .field("event", &self.document.evidence.event)
            .field("source", &self.document.source)
            .field("evidence_complete", &self.document.evidence_complete)
            .field("authority", &self.document.authority)
            .field("facts", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Serialize for TrustSnapshot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.document.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TrustSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let document = TrustSnapshotDocument::deserialize(deserializer)?;
        Self::from_document(document).map_err(D::Error::custom)
    }
}

/// Invalid or conflicting trust evidence, policy, or snapshot encoding.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TrustSnapshotError {
    /// A bounded identity, reference, revision, or activity is malformed.
    #[error("trust evidence contains invalid bounded text")]
    InvalidText,
    /// Authenticated dimensions disagree with one another.
    #[error("trust evidence contains conflicting dimensions")]
    ConflictingEvidence,
    /// A workflow-run chain is empty, excessive, or inconsistent.
    #[error("transitive workflow trust evidence is invalid")]
    InvalidTransitiveEvidence,
    /// A rerun attempted to derive new authority instead of reusing the source snapshot.
    #[error("workflow reruns must retain the original trust snapshot")]
    RerunMustReuseSnapshot,
    /// Snapshot or policy schema is not supported by this build.
    #[error("trust snapshot or policy schema is unsupported")]
    UnsupportedSchema,
    /// Snapshot authority does not match pure policy evaluation.
    #[error("trust snapshot authority is not canonical")]
    NoncanonicalDecision,
    /// Snapshot bytes are malformed, empty, or oversized.
    #[error("trust snapshot encoding is invalid")]
    InvalidEncoding,
    /// Snapshot bytes are valid but not the canonical encoding.
    #[error("trust snapshot encoding is not canonical")]
    NoncanonicalEncoding,
    /// Persisted and rederived snapshot digests disagree.
    #[error("trust snapshot digest does not match")]
    DigestMismatch,
}

fn validate_document(document: &TrustSnapshotDocument) -> Result<(), TrustSnapshotError> {
    if document.schema != TRUST_SNAPSHOT_SCHEMA_V1
        || document.policy.schema != TRUST_POLICY_SCHEMA_V1
    {
        return Err(TrustSnapshotError::UnsupportedSchema);
    }
    let policy = TrustPolicy::new(
        document.policy.revision,
        document.policy.fork_writes,
        document.policy.dispatch_recursion,
    );
    if policy.digest() != document.policy_digest {
        return Err(TrustSnapshotError::DigestMismatch);
    }
    document.evidence.validate()?;
    let complete = document.evidence.is_complete(&policy);
    let source = source_classification(&document.evidence, complete)?;
    let authority = authority_decision(&policy, source, complete);
    if document.evidence_complete != complete
        || document.source != source
        || document.authority != authority
    {
        return Err(TrustSnapshotError::NoncanonicalDecision);
    }
    Ok(())
}

fn source_classification(
    evidence: &TrustEvidence,
    complete: bool,
) -> Result<TrustSourceClass, TrustSnapshotError> {
    if !complete {
        return Ok(TrustSourceClass::Incomplete);
    }
    let source_actor = evidence
        .source_actor
        .as_ref()
        .or(evidence.original_actor.as_ref());
    let dependabot =
        source_actor.is_some_and(|actor| actor.automation == TrustAutomationKind::Dependabot);
    if dependabot && evidence.fork == Some(true) {
        return Err(TrustSnapshotError::ConflictingEvidence);
    }
    if let Some(upstream) = &evidence.upstream {
        return Ok(upstream.source);
    }
    let other_automation =
        source_actor.is_some_and(|actor| actor.automation == TrustAutomationKind::Other);
    Ok(if dependabot {
        TrustSourceClass::Dependabot
    } else if evidence.fork == Some(true) {
        TrustSourceClass::Fork
    } else if other_automation {
        TrustSourceClass::Automation
    } else {
        TrustSourceClass::SameRepository
    })
}

fn authority_decision(
    policy: &TrustPolicy,
    source: TrustSourceClass,
    complete: bool,
) -> TrustAuthorityDecision {
    if !complete || source == TrustSourceClass::Incomplete {
        return TrustAuthorityDecision {
            permissions: TrustPermissionAuthority::DenyAll,
            secrets: TrustSecretAuthority::Denied,
            cache: TrustCacheAuthority::Denied,
            environment: TrustEnvironmentAuthority::Denied,
            oidc: TrustOidcAuthority::Denied,
            outputs: TrustOutputAuthority::Untrusted,
            results: TrustResultsAuthority::Denied,
        };
    }
    match source {
        TrustSourceClass::SameRepository => TrustAuthorityDecision {
            permissions: TrustPermissionAuthority::Requested,
            secrets: TrustSecretAuthority::Eligible,
            cache: TrustCacheAuthority::ReadWrite,
            environment: TrustEnvironmentAuthority::Eligible,
            oidc: TrustOidcAuthority::Eligible,
            outputs: TrustOutputAuthority::Standard,
            results: TrustResultsAuthority::Standard,
        },
        TrustSourceClass::Fork => TrustAuthorityDecision {
            permissions: if policy.fork_write_policy() == ForkWritePolicy::AllowExplicitly {
                TrustPermissionAuthority::Requested
            } else {
                TrustPermissionAuthority::ReadOnly
            },
            secrets: TrustSecretAuthority::Denied,
            cache: TrustCacheAuthority::ReadOnly,
            environment: TrustEnvironmentAuthority::Denied,
            oidc: TrustOidcAuthority::Denied,
            outputs: TrustOutputAuthority::Untrusted,
            results: TrustResultsAuthority::Untrusted,
        },
        TrustSourceClass::Dependabot | TrustSourceClass::Automation => TrustAuthorityDecision {
            permissions: TrustPermissionAuthority::ReadOnly,
            secrets: TrustSecretAuthority::Denied,
            cache: TrustCacheAuthority::ReadOnly,
            environment: TrustEnvironmentAuthority::Denied,
            oidc: TrustOidcAuthority::Denied,
            outputs: TrustOutputAuthority::Untrusted,
            results: TrustResultsAuthority::Untrusted,
        },
        TrustSourceClass::Incomplete => unreachable!(),
    }
}

fn validate_text(value: &str) -> Result<(), TrustSnapshotError> {
    if value.is_empty()
        || value.len() > MAX_TRUST_TEXT_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(TrustSnapshotError::InvalidText);
    }
    Ok(())
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    Sha256Digest::from_bytes(digest.finalize().into())
}
