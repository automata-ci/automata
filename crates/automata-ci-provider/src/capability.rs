//! Typed behavioral capabilities declared by a provider adapter.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ExternalSubjectKind;

/// Repository event class understood by common workflow admission.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryEventKind {
    /// A branch or tag reference changed.
    Push,
    /// A pull or merge request changed.
    PullRequest,
    /// A provider merge queue selected an exact candidate.
    MergeQueue,
    /// An authenticated provider-native repository dispatch was received.
    RepositoryDispatch,
}

/// Completeness guarantee available from the provider changed-file API.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangedFileCompleteness {
    /// Complete evidence is available for every declared event shape.
    Complete,
    /// The adapter can explicitly report incomplete evidence for unsupported or
    /// truncated provider responses.
    ExplicitlyIncomplete,
}

/// Provider commit-status state available to result projection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitStatusState {
    /// Work is queued or running.
    Pending,
    /// Work completed successfully.
    Success,
    /// Workflow work completed unsuccessfully.
    Failure,
    /// Infrastructure prevented workflow completion.
    Error,
    /// Work completed with a neutral or warning result.
    Warning,
    /// Work was deliberately skipped.
    Skipped,
}

/// Provider persistence behavior for one deterministic status context.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusHistoryModel {
    /// One provider object can be updated in place.
    Mutable,
    /// Each write appends a new provider object to status history.
    AppendOnly,
}

/// Actions-compatible workload repository credential profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadCredentialProfile {
    /// Read-only access sufficient for exact repository checkout.
    CheckoutRead,
    /// Provider-mapped write access for an explicitly admitted permission set.
    RepositoryWrite,
}

/// Provider enforcement available for issued workload credentials.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadCredentialRevocation {
    /// The provider enforces a bounded expiry.
    ProviderExpiry,
    /// Automata can explicitly revoke the issued credential.
    Explicit,
}

/// PKCE behavior of an authorization-code provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PkceSupport {
    /// The provider requires PKCE for every authorization request.
    Required,
    /// The provider supports PKCE and the adapter always elects to use it.
    Supported,
    /// The provider does not implement PKCE.
    Unavailable,
}

/// Declared repository events accepted by one adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedRepositoryEventCapability")]
pub struct RepositoryEventCapability {
    events: BTreeSet<RepositoryEventKind>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedRepositoryEventCapability {
    events: BTreeSet<RepositoryEventKind>,
}

impl RepositoryEventCapability {
    /// Creates a non-empty supported event set.
    ///
    /// # Errors
    ///
    /// Rejects an empty set because it would advertise no behavior.
    pub fn new(
        events: impl IntoIterator<Item = RepositoryEventKind>,
    ) -> Result<Self, ProviderCapabilitiesError> {
        let events: BTreeSet<_> = events.into_iter().collect();
        if events.is_empty() {
            return Err(ProviderCapabilitiesError::EmptyRepositoryEvents);
        }
        Ok(Self { events })
    }

    /// Returns the declared event classes.
    #[must_use]
    pub const fn events(&self) -> &BTreeSet<RepositoryEventKind> {
        &self.events
    }
}

impl TryFrom<UncheckedRepositoryEventCapability> for RepositoryEventCapability {
    type Error = ProviderCapabilitiesError;

    fn try_from(value: UncheckedRepositoryEventCapability) -> Result<Self, Self::Error> {
        Self::new(value.events)
    }
}

/// Changed-file behavior declared by one adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedChangedFileCapability")]
pub struct ChangedFileCapability {
    events: BTreeSet<RepositoryEventKind>,
    completeness: ChangedFileCompleteness,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedChangedFileCapability {
    events: BTreeSet<RepositoryEventKind>,
    completeness: ChangedFileCompleteness,
}

impl ChangedFileCapability {
    /// Creates changed-file support for a non-empty event set.
    ///
    /// # Errors
    ///
    /// Rejects an empty set.
    pub fn new(
        events: impl IntoIterator<Item = RepositoryEventKind>,
        completeness: ChangedFileCompleteness,
    ) -> Result<Self, ProviderCapabilitiesError> {
        let events: BTreeSet<_> = events.into_iter().collect();
        if events.is_empty() {
            return Err(ProviderCapabilitiesError::EmptyChangedFileEvents);
        }
        Ok(Self {
            events,
            completeness,
        })
    }

    /// Returns the event classes for which file evidence can be requested.
    #[must_use]
    pub const fn events(&self) -> &BTreeSet<RepositoryEventKind> {
        &self.events
    }

    /// Returns how incomplete provider responses are represented.
    #[must_use]
    pub const fn completeness(&self) -> ChangedFileCompleteness {
        self.completeness
    }
}

impl TryFrom<UncheckedChangedFileCapability> for ChangedFileCapability {
    type Error = ProviderCapabilitiesError;

    fn try_from(value: UncheckedChangedFileCapability) -> Result<Self, Self::Error> {
        Self::new(value.events, value.completeness)
    }
}

/// Commit-status projection behavior declared by one adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedCommitStatusCapability")]
pub struct CommitStatusCapability {
    states: BTreeSet<CommitStatusState>,
    history_model: StatusHistoryModel,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCommitStatusCapability {
    states: BTreeSet<CommitStatusState>,
    history_model: StatusHistoryModel,
}

impl CommitStatusCapability {
    /// Creates a commit-status capability with at least one state.
    ///
    /// # Errors
    ///
    /// Rejects an empty state set.
    pub fn new(
        states: impl IntoIterator<Item = CommitStatusState>,
        history_model: StatusHistoryModel,
    ) -> Result<Self, ProviderCapabilitiesError> {
        let states: BTreeSet<_> = states.into_iter().collect();
        if states.is_empty() {
            return Err(ProviderCapabilitiesError::EmptyCommitStatusStates);
        }
        Ok(Self {
            states,
            history_model,
        })
    }

    /// Returns provider-supported result states.
    #[must_use]
    pub const fn states(&self) -> &BTreeSet<CommitStatusState> {
        &self.states
    }

    /// Returns whether provider status writes mutate or append history.
    #[must_use]
    pub const fn history_model(&self) -> StatusHistoryModel {
        self.history_model
    }
}

impl TryFrom<UncheckedCommitStatusCapability> for CommitStatusCapability {
    type Error = ProviderCapabilitiesError;

    fn try_from(value: UncheckedCommitStatusCapability) -> Result<Self, Self::Error> {
        Self::new(value.states, value.history_model)
    }
}

/// Rich provider check behavior beyond commit statuses.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedRichCheckCapability")]
pub struct RichCheckCapability {
    annotations: bool,
    external_actions: bool,
    native_rerun: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedRichCheckCapability {
    annotations: bool,
    external_actions: bool,
    native_rerun: bool,
}

impl RichCheckCapability {
    /// Creates a rich-check declaration.
    ///
    /// # Errors
    ///
    /// Rejects native rerun without external actions and declarations with no
    /// rich behavior.
    pub const fn new(
        annotations: bool,
        external_actions: bool,
        native_rerun: bool,
    ) -> Result<Self, ProviderCapabilitiesError> {
        if native_rerun && !external_actions {
            return Err(ProviderCapabilitiesError::NativeRerunWithoutActions);
        }
        if !annotations && !external_actions {
            return Err(ProviderCapabilitiesError::EmptyRichChecks);
        }
        Ok(Self {
            annotations,
            external_actions,
            native_rerun,
        })
    }

    /// Returns whether provider checks accept annotations.
    #[must_use]
    pub const fn annotations(self) -> bool {
        self.annotations
    }

    /// Returns whether provider checks expose external actions.
    #[must_use]
    pub const fn external_actions(self) -> bool {
        self.external_actions
    }

    /// Returns whether an external action can request an Automata rerun.
    #[must_use]
    pub const fn native_rerun(self) -> bool {
        self.native_rerun
    }
}

impl TryFrom<UncheckedRichCheckCapability> for RichCheckCapability {
    type Error = ProviderCapabilitiesError;

    fn try_from(value: UncheckedRichCheckCapability) -> Result<Self, Self::Error> {
        Self::new(
            value.annotations,
            value.external_actions,
            value.native_rerun,
        )
    }
}

/// Workload credential behavior declared by one adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedWorkloadCredentialCapability")]
pub struct WorkloadCredentialCapability {
    profiles: BTreeSet<WorkloadCredentialProfile>,
    revocation: BTreeSet<WorkloadCredentialRevocation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedWorkloadCredentialCapability {
    profiles: BTreeSet<WorkloadCredentialProfile>,
    revocation: BTreeSet<WorkloadCredentialRevocation>,
}

impl WorkloadCredentialCapability {
    /// Creates a workload credential declaration.
    ///
    /// # Errors
    ///
    /// Rejects empty profile or revocation sets.
    pub fn new(
        profiles: impl IntoIterator<Item = WorkloadCredentialProfile>,
        revocation: impl IntoIterator<Item = WorkloadCredentialRevocation>,
    ) -> Result<Self, ProviderCapabilitiesError> {
        let profiles: BTreeSet<_> = profiles.into_iter().collect();
        let revocation: BTreeSet<_> = revocation.into_iter().collect();
        if profiles.is_empty() {
            return Err(ProviderCapabilitiesError::EmptyWorkloadProfiles);
        }
        if revocation.is_empty() {
            return Err(ProviderCapabilitiesError::EmptyWorkloadRevocation);
        }
        Ok(Self {
            profiles,
            revocation,
        })
    }

    /// Returns admitted credential profiles.
    #[must_use]
    pub const fn profiles(&self) -> &BTreeSet<WorkloadCredentialProfile> {
        &self.profiles
    }

    /// Returns provider-enforced cleanup mechanisms.
    #[must_use]
    pub const fn revocation(&self) -> &BTreeSet<WorkloadCredentialRevocation> {
        &self.revocation
    }
}

impl TryFrom<UncheckedWorkloadCredentialCapability> for WorkloadCredentialCapability {
    type Error = ProviderCapabilitiesError;

    fn try_from(value: UncheckedWorkloadCredentialCapability) -> Result<Self, Self::Error> {
        Self::new(value.profiles, value.revocation)
    }
}

/// Authorization-code login behavior declared by one adapter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationCodeLoginCapability {
    pkce: PkceSupport,
    loopback_redirect: bool,
}

impl AuthorizationCodeLoginCapability {
    /// Creates an authorization-code login declaration.
    #[must_use]
    pub const fn new(pkce: PkceSupport, loopback_redirect: bool) -> Self {
        Self {
            pkce,
            loopback_redirect,
        }
    }

    /// Returns the provider's PKCE behavior.
    #[must_use]
    pub const fn pkce(self) -> PkceSupport {
        self.pkce
    }

    /// Returns whether CLI loopback redirects are supported.
    #[must_use]
    pub const fn loopback_redirect(self) -> bool {
        self.loopback_redirect
    }
}

/// Membership subject classes readable by one provider adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedMembershipEvidenceCapability")]
pub struct MembershipEvidenceCapability {
    subject_kinds: BTreeSet<ExternalSubjectKind>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedMembershipEvidenceCapability {
    subject_kinds: BTreeSet<ExternalSubjectKind>,
}

impl MembershipEvidenceCapability {
    /// Creates membership evidence support for a non-empty subject-kind set.
    ///
    /// # Errors
    ///
    /// Rejects an empty set.
    pub fn new(
        subject_kinds: impl IntoIterator<Item = ExternalSubjectKind>,
    ) -> Result<Self, ProviderCapabilitiesError> {
        let subject_kinds: BTreeSet<_> = subject_kinds.into_iter().collect();
        if subject_kinds.is_empty() {
            return Err(ProviderCapabilitiesError::EmptyMembershipSubjectKinds);
        }
        Ok(Self { subject_kinds })
    }

    /// Returns provider-readable membership subject kinds.
    #[must_use]
    pub const fn subject_kinds(&self) -> &BTreeSet<ExternalSubjectKind> {
        &self.subject_kinds
    }
}

impl TryFrom<UncheckedMembershipEvidenceCapability> for MembershipEvidenceCapability {
    type Error = ProviderCapabilitiesError;

    fn try_from(value: UncheckedMembershipEvidenceCapability) -> Result<Self, Self::Error> {
        Self::new(value.subject_kinds)
    }
}

/// One typed behavior implemented by a provider adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "configuration", rename_all = "snake_case")]
pub enum ProviderCapability {
    /// Exact immutable repository source can be read.
    SourceRead,
    /// Signed provider events can be normalized.
    RepositoryEvents(RepositoryEventCapability),
    /// Changed-file evidence can be read for declared events.
    ChangedFiles(ChangedFileCapability),
    /// Commit statuses can represent Automata result state.
    CommitStatus(CommitStatusCapability),
    /// Rich provider check objects are available.
    RichChecks(RichCheckCapability),
    /// Attempt-bound repository credentials can be issued.
    WorkloadCredentials(WorkloadCredentialCapability),
    /// OAuth authorization-code login is available.
    AuthorizationCodeLogin(AuthorizationCodeLoginCapability),
    /// OAuth device authorization is available.
    DeviceAuthorizationLogin,
    /// External membership evidence can be read.
    MembershipEvidence(MembershipEvidenceCapability),
    /// Provider webhooks can be installed and reconciled by API.
    ManagedWebhook,
}

impl ProviderCapability {
    /// Returns the unique behavior class represented by this declaration.
    #[must_use]
    pub const fn kind(&self) -> ProviderCapabilityKind {
        match self {
            Self::SourceRead => ProviderCapabilityKind::SourceRead,
            Self::RepositoryEvents(_) => ProviderCapabilityKind::RepositoryEvents,
            Self::ChangedFiles(_) => ProviderCapabilityKind::ChangedFiles,
            Self::CommitStatus(_) => ProviderCapabilityKind::CommitStatus,
            Self::RichChecks(_) => ProviderCapabilityKind::RichChecks,
            Self::WorkloadCredentials(_) => ProviderCapabilityKind::WorkloadCredentials,
            Self::AuthorizationCodeLogin(_) => ProviderCapabilityKind::AuthorizationCodeLogin,
            Self::DeviceAuthorizationLogin => ProviderCapabilityKind::DeviceAuthorizationLogin,
            Self::MembershipEvidence(_) => ProviderCapabilityKind::MembershipEvidence,
            Self::ManagedWebhook => ProviderCapabilityKind::ManagedWebhook,
        }
    }
}

/// Unique class of one provider capability.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCapabilityKind {
    /// Exact repository source read.
    SourceRead,
    /// Signed repository events.
    RepositoryEvents,
    /// Changed-file evidence.
    ChangedFiles,
    /// Commit-status publication.
    CommitStatus,
    /// Rich provider checks.
    RichChecks,
    /// Workload repository credential issuance.
    WorkloadCredentials,
    /// OAuth authorization-code login.
    AuthorizationCodeLogin,
    /// OAuth device authorization login.
    DeviceAuthorizationLogin,
    /// Membership evidence reads.
    MembershipEvidence,
    /// Managed provider webhooks.
    ManagedWebhook,
}

/// Validated, deterministic provider capability declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "Vec<ProviderCapability>", into = "Vec<ProviderCapability>")]
pub struct ProviderCapabilities(BTreeMap<ProviderCapabilityKind, ProviderCapability>);

impl ProviderCapabilities {
    /// Validates and indexes a non-empty capability declaration.
    ///
    /// # Errors
    ///
    /// Rejects an empty declaration, duplicate kinds, changed-file events not
    /// accepted by the event adapter, or managed webhooks without events.
    pub fn new(
        capabilities: impl IntoIterator<Item = ProviderCapability>,
    ) -> Result<Self, ProviderCapabilitiesError> {
        let mut indexed = BTreeMap::new();
        for capability in capabilities {
            validate_capability(&capability)?;
            let kind = capability.kind();
            if indexed.insert(kind, capability).is_some() {
                return Err(ProviderCapabilitiesError::DuplicateCapability(kind));
            }
        }
        if indexed.is_empty() {
            return Err(ProviderCapabilitiesError::EmptyCapabilities);
        }
        validate_cross_capability_invariants(&indexed)?;
        Ok(Self(indexed))
    }

    /// Returns whether the provider implements one behavior class.
    #[must_use]
    pub fn contains(&self, kind: ProviderCapabilityKind) -> bool {
        self.0.contains_key(&kind)
    }

    /// Returns one typed capability by behavior class.
    #[must_use]
    pub fn get(&self, kind: ProviderCapabilityKind) -> Option<&ProviderCapability> {
        self.0.get(&kind)
    }

    /// Iterates in stable capability-kind order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &ProviderCapability> {
        self.0.values()
    }

    /// Returns the number of declared behavior classes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Provider capabilities are always non-empty after validation.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<Vec<ProviderCapability>> for ProviderCapabilities {
    type Error = ProviderCapabilitiesError;

    fn try_from(value: Vec<ProviderCapability>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ProviderCapabilities> for Vec<ProviderCapability> {
    fn from(value: ProviderCapabilities) -> Self {
        value.0.into_values().collect()
    }
}

fn validate_capability(capability: &ProviderCapability) -> Result<(), ProviderCapabilitiesError> {
    match capability {
        ProviderCapability::RepositoryEvents(events) if events.events().is_empty() => {
            Err(ProviderCapabilitiesError::EmptyRepositoryEvents)
        }
        ProviderCapability::ChangedFiles(changed_files) if changed_files.events().is_empty() => {
            Err(ProviderCapabilitiesError::EmptyChangedFileEvents)
        }
        ProviderCapability::CommitStatus(status) if status.states().is_empty() => {
            Err(ProviderCapabilitiesError::EmptyCommitStatusStates)
        }
        ProviderCapability::RichChecks(checks)
            if checks.native_rerun() && !checks.external_actions() =>
        {
            Err(ProviderCapabilitiesError::NativeRerunWithoutActions)
        }
        ProviderCapability::RichChecks(checks)
            if !checks.annotations() && !checks.external_actions() =>
        {
            Err(ProviderCapabilitiesError::EmptyRichChecks)
        }
        ProviderCapability::WorkloadCredentials(credentials)
            if credentials.profiles().is_empty() =>
        {
            Err(ProviderCapabilitiesError::EmptyWorkloadProfiles)
        }
        ProviderCapability::WorkloadCredentials(credentials)
            if credentials.revocation().is_empty() =>
        {
            Err(ProviderCapabilitiesError::EmptyWorkloadRevocation)
        }
        ProviderCapability::MembershipEvidence(membership)
            if membership.subject_kinds().is_empty() =>
        {
            Err(ProviderCapabilitiesError::EmptyMembershipSubjectKinds)
        }
        ProviderCapability::SourceRead
        | ProviderCapability::RepositoryEvents(_)
        | ProviderCapability::ChangedFiles(_)
        | ProviderCapability::CommitStatus(_)
        | ProviderCapability::RichChecks(_)
        | ProviderCapability::WorkloadCredentials(_)
        | ProviderCapability::AuthorizationCodeLogin(_)
        | ProviderCapability::DeviceAuthorizationLogin
        | ProviderCapability::MembershipEvidence(_)
        | ProviderCapability::ManagedWebhook => Ok(()),
    }
}

fn validate_cross_capability_invariants(
    capabilities: &BTreeMap<ProviderCapabilityKind, ProviderCapability>,
) -> Result<(), ProviderCapabilitiesError> {
    if let Some(ProviderCapability::ChangedFiles(changed_files)) =
        capabilities.get(&ProviderCapabilityKind::ChangedFiles)
    {
        let Some(ProviderCapability::RepositoryEvents(repository_events)) =
            capabilities.get(&ProviderCapabilityKind::RepositoryEvents)
        else {
            return Err(ProviderCapabilitiesError::ChangedFilesWithoutEvents);
        };
        if !changed_files.events().is_subset(repository_events.events()) {
            return Err(ProviderCapabilitiesError::ChangedFilesOutsideEvents);
        }
    }
    if capabilities.contains_key(&ProviderCapabilityKind::ManagedWebhook)
        && !capabilities.contains_key(&ProviderCapabilityKind::RepositoryEvents)
    {
        return Err(ProviderCapabilitiesError::ManagedWebhookWithoutEvents);
    }
    Ok(())
}

/// Invalid or internally inconsistent provider capability declaration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderCapabilitiesError {
    /// No capability was declared.
    #[error("a provider must declare at least one capability")]
    EmptyCapabilities,
    /// A behavior class was declared more than once.
    #[error("provider capability {0:?} was declared more than once")]
    DuplicateCapability(ProviderCapabilityKind),
    /// Repository-event support contained no event class.
    #[error("repository event capability must contain at least one event")]
    EmptyRepositoryEvents,
    /// Changed-file support contained no event class.
    #[error("changed-file capability must contain at least one event")]
    EmptyChangedFileEvents,
    /// Changed files were declared without repository event admission.
    #[error("changed-file capability requires repository events")]
    ChangedFilesWithoutEvents,
    /// Changed files were declared for an event the adapter does not accept.
    #[error("changed-file events must be a subset of accepted repository events")]
    ChangedFilesOutsideEvents,
    /// Commit-status support contained no status state.
    #[error("commit-status capability must contain at least one state")]
    EmptyCommitStatusStates,
    /// Rich checks advertised native rerun without external actions.
    #[error("native rerun requires provider external actions")]
    NativeRerunWithoutActions,
    /// Rich checks advertised no rich behavior.
    #[error("rich-check capability must implement annotations or external actions")]
    EmptyRichChecks,
    /// Workload credential support contained no permission profile.
    #[error("workload credential capability must contain at least one profile")]
    EmptyWorkloadProfiles,
    /// Workload credentials had no provider cleanup mechanism.
    #[error("workload credential capability must contain a revocation mechanism")]
    EmptyWorkloadRevocation,
    /// Membership evidence contained no subject kind.
    #[error("membership evidence capability must contain at least one subject kind")]
    EmptyMembershipSubjectKinds,
    /// Managed webhooks were declared without repository events.
    #[error("managed webhook capability requires repository events")]
    ManagedWebhookWithoutEvents,
}
