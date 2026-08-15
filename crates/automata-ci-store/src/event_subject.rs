//! Provider-neutral immutable event selection, progress, and control subjects.

use std::fmt;

use async_trait::async_trait;
use automata_ci_core::{OperationId, RunId, Sha256Digest, UnixMillis};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    GithubScheduleFireId, ProviderDeliveryId, RepositoryId, RepositoryOperationError, TenantScope,
};

/// Current closed origin-registry version.
pub const EVENT_SUBJECT_ORIGIN_REGISTRY_VERSION: u16 = 1;
/// Current immutable event-selection schema.
pub const EVENT_SUBJECT_SELECTION_SCHEMA: u16 = 1;
/// Current terminal event-progress schema.
pub const EVENT_SUBJECT_PROGRESS_SCHEMA: u16 = 1;
/// Current event-control-subject schema.
pub const EVENT_CONTROL_SUBJECT_SCHEMA: u16 = 1;

/// Maximum canonical event-name length in UTF-8 bytes.
pub const MAX_EVENT_SUBJECT_EVENT_NAME_BYTES: usize = 128;
/// Maximum workflow path length in UTF-8 bytes.
pub const MAX_EVENT_SUBJECT_WORKFLOW_PATH_BYTES: usize = 1_024;
/// Maximum immutable source-revision length in UTF-8 bytes.
pub const MAX_EVENT_SUBJECT_SOURCE_REVISION_BYTES: usize = 1_024;
/// Maximum terminal progress reason length in UTF-8 bytes.
pub const MAX_EVENT_SUBJECT_REASON_BYTES: usize = 128;

const MAX_ORIGIN_NAME_BYTES: usize = 64;
const REGISTRY_DIGEST_DOMAIN: &[u8] = b"automata.store.event-subject-origin-registry.v1\0";
const SELECTION_DIGEST_DOMAIN: &[u8] = b"automata.store.event-subject-selection.v1\0";
const PROGRESS_DIGEST_DOMAIN: &[u8] = b"automata.store.event-subject-progress.v1\0";
const CONTROL_DIGEST_DOMAIN: &[u8] = b"automata.store.event-control-subject.v1\0";
const SUBJECT_ID_DOMAIN: &[u8] = b"automata.store.event-subject-id.v1\0";
const CONTROL_ID_DOMAIN: &[u8] = b"automata.store.event-control-subject-id.v1\0";

macro_rules! uuid_identity {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Constructs a non-nil durable UUID identity.
            ///
            /// # Errors
            ///
            /// Rejects the nil UUID sentinel.
            pub fn from_uuid(value: Uuid) -> Result<Self, EventSubjectValueError> {
                if value.is_nil() {
                    return Err(EventSubjectValueError::NilUuid($field));
                }
                Ok(Self(value))
            }

            /// Returns the underlying UUID.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }
    };
}

uuid_identity!(/// Durable identity of one immutable event/workflow selection.
    EventSubjectId, "event subject ID");
uuid_identity!(/// Durable provider-neutral root for one event's control projection.
    EventControlSubjectId, "event control subject ID");

impl EventSubjectId {
    /// Derives the stable `UUIDv8` identity of one origin/workflow selection.
    ///
    /// The event payload, evaluation result, and wall clock are deliberately
    /// excluded. Exact retries of the same tenant/repository/origin/workflow
    /// coordinates therefore converge on one durable subject, while the
    /// selection digest detects changed immutable source or event facts.
    ///
    /// # Errors
    ///
    /// Rejects a nil repository or origin identity and an unsafe workflow path.
    pub fn derive(
        tenant: &TenantScope,
        repository_id: RepositoryId,
        origin: EventSubjectOrigin,
        workflow_path: &str,
    ) -> Result<Self, EventSubjectValueError> {
        if repository_id.as_uuid().is_nil() {
            return Err(EventSubjectValueError::NilUuid("repository ID"));
        }
        origin.validate()?;
        validate_workflow_path(workflow_path)?;

        let mut digest = Sha256::new();
        digest.update(SUBJECT_ID_DOMAIN);
        update_length_prefixed(&mut digest, tenant.as_str().as_bytes());
        digest.update(repository_id.as_uuid().as_bytes());
        digest.update(origin.kind().durable_code().to_be_bytes());
        digest.update(origin.as_uuid().as_bytes());
        update_length_prefixed(&mut digest, workflow_path.as_bytes());
        Ok(Self(sha256_uuid_v8(digest)))
    }
}

impl EventControlSubjectId {
    /// Derives the stable `UUIDv8` control root for one immutable event subject.
    #[must_use]
    pub fn derive(subject_id: EventSubjectId) -> Self {
        let mut digest = Sha256::new();
        digest.update(CONTROL_ID_DOMAIN);
        digest.update(subject_id.as_uuid().as_bytes());
        Self(sha256_uuid_v8(digest))
    }
}

/// Closed durable kind of event origin accepted by the current registry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EventSubjectOriginKind {
    /// An authenticated provider webhook delivery.
    ProviderDelivery,
    /// One immutable scheduled fire.
    ScheduleFire,
    /// One authenticated manual-dispatch operation.
    ManualOperation,
    /// One upstream workflow run used as a chained-event origin.
    WorkflowRun,
}

impl EventSubjectOriginKind {
    /// Returns the stable numeric registry code.
    #[must_use]
    pub const fn durable_code(self) -> u16 {
        match self {
            Self::ProviderDelivery => 1,
            Self::ScheduleFire => 2,
            Self::ManualOperation => 3,
            Self::WorkflowRun => 4,
        }
    }

    /// Returns the stable durable name.
    #[must_use]
    pub const fn as_durable_str(self) -> &'static str {
        match self {
            Self::ProviderDelivery => "provider_delivery",
            Self::ScheduleFire => "schedule_fire",
            Self::ManualOperation => "manual_operation",
            Self::WorkflowRun => "workflow_run",
        }
    }

    /// Decodes one exact code/name pair from the current closed registry.
    ///
    /// # Errors
    ///
    /// Rejects unknown codes and code/name disagreement. There is deliberately
    /// no catch-all origin: a newer producer must not be guessed by an older
    /// consumer.
    pub fn from_durable_parts(code: u16, name: &str) -> Result<Self, EventSubjectValueError> {
        let kind = match code {
            1 => Self::ProviderDelivery,
            2 => Self::ScheduleFire,
            3 => Self::ManualOperation,
            4 => Self::WorkflowRun,
            _ => return Err(EventSubjectValueError::UnknownOriginCode(code)),
        };
        if name != kind.as_durable_str() {
            return Err(EventSubjectValueError::OriginRegistrationMismatch);
        }
        Ok(kind)
    }
}

/// One serialized entry used to verify a closed origin registry at startup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventSubjectOriginRegistration {
    code: u16,
    name: String,
}

impl EventSubjectOriginRegistration {
    /// Constructs one bounded serialized registration.
    ///
    /// This validates only the transport-safe shape. Membership in the closed
    /// registry is checked by [`EventSubjectOriginRegistry::from_durable_entries`].
    ///
    /// # Errors
    ///
    /// Rejects zero codes and non-canonical or oversized names.
    pub fn new(code: u16, name: impl Into<String>) -> Result<Self, EventSubjectValueError> {
        let name = name.into();
        if code == 0 || !is_machine_identifier(&name, MAX_ORIGIN_NAME_BYTES) {
            return Err(EventSubjectValueError::InvalidOriginRegistration);
        }
        Ok(Self { code, name })
    }

    /// Returns the serialized numeric code.
    #[must_use]
    pub const fn code(&self) -> u16 {
        self.code
    }

    /// Returns the serialized durable name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Verified complete origin registry for the exact supported version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventSubjectOriginRegistry {
    version: u16,
    digest: Sha256Digest,
}

impl EventSubjectOriginRegistry {
    /// Returns the current complete built-in registry.
    #[must_use]
    pub fn current() -> Self {
        Self {
            version: EVENT_SUBJECT_ORIGIN_REGISTRY_VERSION,
            digest: origin_registry_digest(
                EVENT_SUBJECT_ORIGIN_REGISTRY_VERSION,
                &EventSubjectOriginKind::ALL,
            ),
        }
    }

    /// Validates a serialized registry without accepting partial or future data.
    ///
    /// Input order is irrelevant. Every current origin must occur exactly once.
    ///
    /// # Errors
    ///
    /// Rejects prior/future versions, unknown or duplicate entries, mismatched
    /// names, and incomplete registries.
    pub fn from_durable_entries(
        version: u16,
        entries: &[EventSubjectOriginRegistration],
    ) -> Result<Self, EventSubjectValueError> {
        if version != EVENT_SUBJECT_ORIGIN_REGISTRY_VERSION {
            return Err(EventSubjectValueError::UnsupportedOriginRegistryVersion {
                expected: EVENT_SUBJECT_ORIGIN_REGISTRY_VERSION,
                actual: version,
            });
        }

        let mut seen = 0_u8;
        for entry in entries {
            let kind = EventSubjectOriginKind::from_durable_parts(entry.code(), entry.name())?;
            let bit = 1_u8 << (kind.durable_code() - 1);
            if seen & bit != 0 {
                return Err(EventSubjectValueError::DuplicateOriginRegistration(kind));
            }
            seen |= bit;
        }
        if seen != EventSubjectOriginKind::COMPLETE_MASK {
            return Err(EventSubjectValueError::IncompleteOriginRegistry);
        }

        Ok(Self::current())
    }

    /// Returns canonical serialized entries in stable code order.
    #[must_use]
    pub fn canonical_entries() -> Vec<EventSubjectOriginRegistration> {
        EventSubjectOriginKind::ALL
            .iter()
            .map(|kind| EventSubjectOriginRegistration {
                code: kind.durable_code(),
                name: kind.as_durable_str().to_owned(),
            })
            .collect()
    }

    /// Returns the exact supported registry version.
    #[must_use]
    pub const fn version(self) -> u16 {
        self.version
    }

    /// Returns the canonical registry digest.
    #[must_use]
    pub const fn digest(self) -> Sha256Digest {
        self.digest
    }
}

impl EventSubjectOriginKind {
    const ALL: [Self; 4] = [
        Self::ProviderDelivery,
        Self::ScheduleFire,
        Self::ManualOperation,
        Self::WorkflowRun,
    ];
    const COMPLETE_MASK: u8 = 0b1111;
}

/// Exact immutable origin identity for an event subject.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EventSubjectOrigin {
    /// An authenticated provider delivery.
    ProviderDelivery(ProviderDeliveryId),
    /// One exact due schedule fire.
    ScheduleFire(GithubScheduleFireId),
    /// One authenticated manual-dispatch operation.
    ManualOperation(OperationId),
    /// One upstream workflow run.
    WorkflowRun(RunId),
}

impl EventSubjectOrigin {
    /// Returns the closed origin kind.
    #[must_use]
    pub const fn kind(self) -> EventSubjectOriginKind {
        match self {
            Self::ProviderDelivery(_) => EventSubjectOriginKind::ProviderDelivery,
            Self::ScheduleFire(_) => EventSubjectOriginKind::ScheduleFire,
            Self::ManualOperation(_) => EventSubjectOriginKind::ManualOperation,
            Self::WorkflowRun(_) => EventSubjectOriginKind::WorkflowRun,
        }
    }

    /// Returns the origin UUID without erasing its durable kind.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        match self {
            Self::ProviderDelivery(id) => id.as_uuid(),
            Self::ScheduleFire(id) => id.as_uuid(),
            Self::ManualOperation(id) => id.as_uuid(),
            Self::WorkflowRun(id) => id.as_uuid(),
        }
    }

    fn validate(self) -> Result<(), EventSubjectValueError> {
        if self.as_uuid().is_nil() {
            return Err(EventSubjectValueError::NilUuid("event origin ID"));
        }
        Ok(())
    }
}

/// One immutable event-to-workflow selection at an exact source revision.
#[derive(Clone, Eq, PartialEq)]
pub struct EventSubjectSelection {
    id: EventSubjectId,
    tenant: TenantScope,
    repository_id: RepositoryId,
    origin: EventSubjectOrigin,
    event_name: String,
    workflow_path: String,
    source_revision: String,
    source_digest: Sha256Digest,
    authority_digest: Sha256Digest,
    selected_at: UnixMillis,
    digest: Sha256Digest,
}

impl EventSubjectSelection {
    /// Constructs and hashes one complete immutable workflow selection.
    ///
    /// # Errors
    ///
    /// Rejects nil identities, invalid event/path/revision text, and a time
    /// before the Unix epoch.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: EventSubjectId,
        tenant: TenantScope,
        repository_id: RepositoryId,
        origin: EventSubjectOrigin,
        event_name: impl Into<String>,
        workflow_path: impl Into<String>,
        source_revision: impl Into<String>,
        source_digest: Sha256Digest,
        authority_digest: Sha256Digest,
        selected_at: UnixMillis,
    ) -> Result<Self, EventSubjectValueError> {
        if repository_id.as_uuid().is_nil() {
            return Err(EventSubjectValueError::NilUuid("repository ID"));
        }
        origin.validate()?;
        let event_name = event_name.into();
        if !is_machine_identifier(&event_name, MAX_EVENT_SUBJECT_EVENT_NAME_BYTES) {
            return Err(EventSubjectValueError::InvalidEventName);
        }
        let workflow_path = workflow_path.into();
        validate_workflow_path(&workflow_path)?;
        let source_revision = source_revision.into();
        validate_bounded_text(
            &source_revision,
            MAX_EVENT_SUBJECT_SOURCE_REVISION_BYTES,
            EventSubjectValueError::InvalidSourceRevision,
        )?;
        validate_timestamp(selected_at)?;
        if id != EventSubjectId::derive(&tenant, repository_id, origin, &workflow_path)? {
            return Err(EventSubjectValueError::SubjectIdDerivationMismatch);
        }

        let digest = selection_digest(
            id,
            &tenant,
            repository_id,
            origin,
            &event_name,
            &workflow_path,
            &source_revision,
            source_digest,
            authority_digest,
            selected_at,
        );
        Ok(Self {
            id,
            tenant,
            repository_id,
            origin,
            event_name,
            workflow_path,
            source_revision,
            source_digest,
            authority_digest,
            selected_at,
            digest,
        })
    }

    /// Rehydrates a selection only when its persisted digest still matches.
    ///
    /// # Errors
    ///
    /// Returns the same validation failures as [`Self::new`] or a digest
    /// mismatch for altered durable fields.
    #[allow(clippy::too_many_arguments)]
    pub fn from_durable_parts(
        id: EventSubjectId,
        tenant: TenantScope,
        repository_id: RepositoryId,
        origin: EventSubjectOrigin,
        event_name: impl Into<String>,
        workflow_path: impl Into<String>,
        source_revision: impl Into<String>,
        source_digest: Sha256Digest,
        authority_digest: Sha256Digest,
        selected_at: UnixMillis,
        expected_digest: Sha256Digest,
    ) -> Result<Self, EventSubjectValueError> {
        let selection = Self::new(
            id,
            tenant,
            repository_id,
            origin,
            event_name,
            workflow_path,
            source_revision,
            source_digest,
            authority_digest,
            selected_at,
        )?;
        if selection.digest != expected_digest {
            return Err(EventSubjectValueError::SelectionDigestMismatch);
        }
        Ok(selection)
    }

    #[must_use]
    pub const fn id(&self) -> EventSubjectId {
        self.id
    }
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }
    #[must_use]
    pub const fn origin(&self) -> EventSubjectOrigin {
        self.origin
    }
    /// Returns the closed origin-registry version pinned by the digest.
    #[must_use]
    pub const fn origin_registry_version(&self) -> u16 {
        EVENT_SUBJECT_ORIGIN_REGISTRY_VERSION
    }
    /// Returns the closed origin-registry digest pinned by the selection.
    #[must_use]
    pub fn origin_registry_digest(&self) -> Sha256Digest {
        EventSubjectOriginRegistry::current().digest()
    }
    #[must_use]
    pub fn event_name(&self) -> &str {
        &self.event_name
    }
    #[must_use]
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }
    #[must_use]
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }
    #[must_use]
    pub const fn source_digest(&self) -> Sha256Digest {
        self.source_digest
    }
    /// Returns the canonical digest of authenticated actor, activity, target,
    /// and trust facts used to select this workflow.
    #[must_use]
    pub const fn authority_digest(&self) -> Sha256Digest {
        self.authority_digest
    }
    #[must_use]
    pub const fn selected_at(&self) -> UnixMillis {
        self.selected_at
    }
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

impl fmt::Debug for EventSubjectSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventSubjectSelection")
            .field("id", &self.id)
            .field("tenant", &"[REDACTED]")
            .field("repository_id", &self.repository_id)
            .field("origin_kind", &self.origin.kind())
            .field("origin_id", &self.origin.as_uuid())
            .field("event_name", &"[REDACTED]")
            .field("workflow_path", &"[REDACTED]")
            .field("source_revision", &"[REDACTED]")
            .field("source_digest", &"[REDACTED]")
            .field("authority_digest", &"[REDACTED]")
            .field("selected_at", &self.selected_at)
            .field("digest", &"[REDACTED]")
            .finish()
    }
}

/// Closed terminal outcome kind for independently replayable progress.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EventSubjectTerminalKind {
    /// Admission created or exactly replayed a run.
    Admitted,
    /// Evaluation intentionally selected no runnable workflow.
    Skipped,
    /// Evaluation failed before admission completed.
    Failed,
}

impl EventSubjectTerminalKind {
    /// Returns the stable durable spelling.
    #[must_use]
    pub const fn as_durable_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
        }
    }
}

/// Validated terminal outcome for one event selection.
#[derive(Clone, Eq, PartialEq)]
pub struct EventSubjectTerminalOutcome {
    kind: EventSubjectTerminalKind,
    run_id: Option<RunId>,
    reason: Option<String>,
}

impl EventSubjectTerminalOutcome {
    /// Constructs an admitted outcome bound to a non-nil run.
    ///
    /// # Errors
    ///
    /// Rejects the nil run sentinel.
    pub fn admitted(run_id: RunId) -> Result<Self, EventSubjectValueError> {
        if run_id.as_uuid().is_nil() {
            return Err(EventSubjectValueError::NilUuid("admitted run ID"));
        }
        Ok(Self {
            kind: EventSubjectTerminalKind::Admitted,
            run_id: Some(run_id),
            reason: None,
        })
    }

    /// Constructs a skipped outcome with one canonical bounded reason.
    ///
    /// # Errors
    ///
    /// Rejects invalid reason identifiers.
    pub fn skipped(reason: impl Into<String>) -> Result<Self, EventSubjectValueError> {
        Self::reasoned(EventSubjectTerminalKind::Skipped, reason)
    }

    /// Constructs a failed outcome with one canonical bounded reason.
    ///
    /// # Errors
    ///
    /// Rejects invalid reason identifiers.
    pub fn failed(reason: impl Into<String>) -> Result<Self, EventSubjectValueError> {
        Self::reasoned(EventSubjectTerminalKind::Failed, reason)
    }

    fn reasoned(
        kind: EventSubjectTerminalKind,
        reason: impl Into<String>,
    ) -> Result<Self, EventSubjectValueError> {
        let reason = reason.into();
        if !is_machine_identifier(&reason, MAX_EVENT_SUBJECT_REASON_BYTES) {
            return Err(EventSubjectValueError::InvalidProgressReason);
        }
        Ok(Self {
            kind,
            run_id: None,
            reason: Some(reason),
        })
    }

    #[must_use]
    pub const fn kind(&self) -> EventSubjectTerminalKind {
        self.kind
    }
    #[must_use]
    pub const fn run_id(&self) -> Option<RunId> {
        self.run_id
    }
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

impl fmt::Debug for EventSubjectTerminalOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventSubjectTerminalOutcome")
            .field("kind", &self.kind)
            .field("run_id", &self.run_id)
            .field("reason", &self.reason.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// One immutable terminal progress record bound to an exact selection digest.
#[derive(Clone, Eq, PartialEq)]
pub struct EventSubjectProgress {
    subject_id: EventSubjectId,
    selection_digest: Sha256Digest,
    outcome: EventSubjectTerminalOutcome,
    recorded_at: UnixMillis,
    digest: Sha256Digest,
}

impl EventSubjectProgress {
    /// Constructs one terminal progress record for an exact selection.
    ///
    /// # Errors
    ///
    /// Rejects a time before the Unix epoch or before immutable selection.
    pub fn new(
        selection: &EventSubjectSelection,
        outcome: EventSubjectTerminalOutcome,
        recorded_at: UnixMillis,
    ) -> Result<Self, EventSubjectValueError> {
        validate_timestamp(recorded_at)?;
        if recorded_at < selection.selected_at() {
            return Err(EventSubjectValueError::TimelineOrder);
        }
        let digest = progress_digest(selection.id(), selection.digest(), &outcome, recorded_at);
        Ok(Self {
            subject_id: selection.id(),
            selection_digest: selection.digest(),
            outcome,
            recorded_at,
            digest,
        })
    }

    /// Rehydrates progress only when both selection and progress digests match.
    ///
    /// # Errors
    ///
    /// Rejects invalid time or altered durable fields.
    pub fn from_durable_parts(
        selection: &EventSubjectSelection,
        outcome: EventSubjectTerminalOutcome,
        recorded_at: UnixMillis,
        expected_digest: Sha256Digest,
    ) -> Result<Self, EventSubjectValueError> {
        let progress = Self::new(selection, outcome, recorded_at)?;
        if progress.digest != expected_digest {
            return Err(EventSubjectValueError::ProgressDigestMismatch);
        }
        Ok(progress)
    }

    #[must_use]
    pub const fn subject_id(&self) -> EventSubjectId {
        self.subject_id
    }
    #[must_use]
    pub const fn selection_digest(&self) -> Sha256Digest {
        self.selection_digest
    }
    #[must_use]
    pub const fn outcome(&self) -> &EventSubjectTerminalOutcome {
        &self.outcome
    }
    #[must_use]
    pub const fn recorded_at(&self) -> UnixMillis {
        self.recorded_at
    }
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
    /// Reports whether this is an exact idempotent replay of another record.
    #[must_use]
    pub fn is_exact_replay_of(&self, other: &Self) -> bool {
        self == other
    }
}

impl fmt::Debug for EventSubjectProgress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventSubjectProgress")
            .field("subject_id", &self.subject_id)
            .field("selection_digest", &"[REDACTED]")
            .field("outcome", &self.outcome)
            .field("recorded_at", &self.recorded_at)
            .field("digest", &"[REDACTED]")
            .finish()
    }
}

/// Provider-neutral control root to which a Check projection can be attached.
#[derive(Clone, Eq, PartialEq)]
pub struct EventControlSubject {
    id: EventControlSubjectId,
    subject_id: EventSubjectId,
    selection_digest: Sha256Digest,
    registered_at: UnixMillis,
    digest: Sha256Digest,
}

impl EventControlSubject {
    /// Constructs a one-selection control root.
    ///
    /// # Errors
    ///
    /// Rejects a time before the Unix epoch or before immutable selection.
    pub fn new(
        id: EventControlSubjectId,
        selection: &EventSubjectSelection,
        registered_at: UnixMillis,
    ) -> Result<Self, EventSubjectValueError> {
        validate_timestamp(registered_at)?;
        if registered_at < selection.selected_at() {
            return Err(EventSubjectValueError::TimelineOrder);
        }
        if id != EventControlSubjectId::derive(selection.id()) {
            return Err(EventSubjectValueError::ControlIdDerivationMismatch);
        }
        let digest = control_digest(id, selection.id(), selection.digest(), registered_at);
        Ok(Self {
            id,
            subject_id: selection.id(),
            selection_digest: selection.digest(),
            registered_at,
            digest,
        })
    }

    /// Rehydrates a control root only when its selection and digest match.
    ///
    /// # Errors
    ///
    /// Rejects invalid time or altered durable fields.
    pub fn from_durable_parts(
        id: EventControlSubjectId,
        selection: &EventSubjectSelection,
        registered_at: UnixMillis,
        expected_digest: Sha256Digest,
    ) -> Result<Self, EventSubjectValueError> {
        let subject = Self::new(id, selection, registered_at)?;
        if subject.digest != expected_digest {
            return Err(EventSubjectValueError::ControlDigestMismatch);
        }
        Ok(subject)
    }

    #[must_use]
    pub const fn id(&self) -> EventControlSubjectId {
        self.id
    }
    #[must_use]
    pub const fn subject_id(&self) -> EventSubjectId {
        self.subject_id
    }
    #[must_use]
    pub const fn selection_digest(&self) -> Sha256Digest {
        self.selection_digest
    }
    #[must_use]
    pub const fn registered_at(&self) -> UnixMillis {
        self.registered_at
    }
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
    /// Reports whether this control root belongs to the exact selection.
    #[must_use]
    pub fn matches_selection(&self, selection: &EventSubjectSelection) -> bool {
        self.subject_id == selection.id() && self.selection_digest == selection.digest()
    }
}

impl fmt::Debug for EventControlSubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventControlSubject")
            .field("id", &self.id)
            .field("subject_id", &self.subject_id)
            .field("selection_digest", &"[REDACTED]")
            .field("registered_at", &self.registered_at)
            .field("digest", &"[REDACTED]")
            .finish()
    }
}

/// Atomic registration request for a selection and its control root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterEventSubject {
    selection: EventSubjectSelection,
    control: EventControlSubject,
}

impl RegisterEventSubject {
    /// Binds a control root to the exact selection being registered.
    ///
    /// # Errors
    ///
    /// Rejects a control root constructed for another selection.
    pub fn new(
        selection: EventSubjectSelection,
        control: EventControlSubject,
    ) -> Result<Self, EventSubjectValueError> {
        if !control.matches_selection(&selection) {
            return Err(EventSubjectValueError::SelectionBindingMismatch);
        }
        Ok(Self { selection, control })
    }

    #[must_use]
    pub const fn selection(&self) -> &EventSubjectSelection {
        &self.selection
    }
    #[must_use]
    pub const fn control(&self) -> &EventControlSubject {
        &self.control
    }
}

/// Successful first registration or exact replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventSubjectRegistrationReceipt {
    selection: EventSubjectSelection,
    control: EventControlSubject,
    replay: bool,
}

impl EventSubjectRegistrationReceipt {
    #[cfg(feature = "adapter-spi")]
    pub(crate) fn new(
        selection: EventSubjectSelection,
        control: EventControlSubject,
        replay: bool,
    ) -> Result<Self, EventSubjectValueError> {
        if !control.matches_selection(&selection) {
            return Err(EventSubjectValueError::SelectionBindingMismatch);
        }
        Ok(Self {
            selection,
            control,
            replay,
        })
    }

    #[must_use]
    pub const fn selection(&self) -> &EventSubjectSelection {
        &self.selection
    }
    #[must_use]
    pub const fn control(&self) -> &EventControlSubject {
        &self.control
    }
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.replay
    }
}

/// Successful first terminal write or exact replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventSubjectProgressReceipt {
    progress: EventSubjectProgress,
    replay: bool,
}

impl EventSubjectProgressReceipt {
    #[cfg(feature = "adapter-spi")]
    pub(crate) const fn new(progress: EventSubjectProgress, replay: bool) -> Self {
        Self { progress, replay }
    }

    #[must_use]
    pub const fn progress(&self) -> &EventSubjectProgress {
        &self.progress
    }
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.replay
    }
}

/// Portable immutable event-subject repository failures.
#[derive(Debug, Error)]
pub enum EventSubjectStoreError {
    #[error(transparent)]
    Operation(#[from] RepositoryOperationError),
    #[error("event subject registration conflicts with immutable durable state")]
    Conflict,
    #[error("event subject was not found")]
    NotFound,
    #[error("durable event subject data is corrupt")]
    CorruptData,
}

/// Invalid event-subject values or durable representations.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EventSubjectValueError {
    #[error("{0} must not be nil")]
    NilUuid(&'static str),
    #[error("event subject origin registration is invalid")]
    InvalidOriginRegistration,
    #[error("event subject origin registry version {actual} is unsupported; expected {expected}")]
    UnsupportedOriginRegistryVersion { expected: u16, actual: u16 },
    #[error("event subject origin registry contains unknown code {0}")]
    UnknownOriginCode(u16),
    #[error("event subject origin registry code and name disagree")]
    OriginRegistrationMismatch,
    #[error("event subject origin registry contains duplicate {0:?}")]
    DuplicateOriginRegistration(EventSubjectOriginKind),
    #[error("event subject origin registry is incomplete")]
    IncompleteOriginRegistry,
    #[error("event subject event name is invalid")]
    InvalidEventName,
    #[error("event subject workflow path is invalid")]
    InvalidWorkflowPath,
    #[error("event subject source revision is invalid")]
    InvalidSourceRevision,
    #[error("event subject terminal reason is invalid")]
    InvalidProgressReason,
    #[error("event subject timestamp is before the Unix epoch")]
    NegativeTimestamp,
    #[error("event subject timeline is not monotonic")]
    TimelineOrder,
    #[error("event subject ID is not the canonical derivation of its coordinates")]
    SubjectIdDerivationMismatch,
    #[error("event control subject ID is not the canonical derivation of its event subject")]
    ControlIdDerivationMismatch,
    #[error("event subject selection digest does not match its fields")]
    SelectionDigestMismatch,
    #[error("event subject progress digest does not match its fields")]
    ProgressDigestMismatch,
    #[error("event control subject digest does not match its fields")]
    ControlDigestMismatch,
    #[error("event control subject is bound to another selection")]
    SelectionBindingMismatch,
}

/// Durable boundary for immutable event selection, progress, and control roots.
#[async_trait]
pub trait EventSubjectRepository: Send + Sync {
    /// Atomically registers or exactly replays a selection and control root.
    async fn register_event_subject(
        &self,
        request: RegisterEventSubject,
    ) -> Result<EventSubjectRegistrationReceipt, EventSubjectStoreError>;

    /// Records one terminal outcome, exactly replaying only identical progress.
    async fn record_event_subject_progress(
        &self,
        progress: EventSubjectProgress,
    ) -> Result<EventSubjectProgressReceipt, EventSubjectStoreError>;

    /// Loads one immutable selection in tenant scope.
    async fn load_event_subject_selection(
        &self,
        tenant: &TenantScope,
        subject_id: EventSubjectId,
    ) -> Result<EventSubjectSelection, EventSubjectStoreError>;

    /// Loads the one control root attached to a selection.
    async fn load_event_control_subject(
        &self,
        tenant: &TenantScope,
        subject_id: EventSubjectId,
    ) -> Result<EventControlSubject, EventSubjectStoreError>;

    /// Loads terminal progress, or `None` while evaluation remains open.
    async fn load_event_subject_progress(
        &self,
        tenant: &TenantScope,
        subject_id: EventSubjectId,
    ) -> Result<Option<EventSubjectProgress>, EventSubjectStoreError>;
}

fn validate_timestamp(value: UnixMillis) -> Result<(), EventSubjectValueError> {
    if value.get() < 0 {
        return Err(EventSubjectValueError::NegativeTimestamp);
    }
    Ok(())
}

fn validate_workflow_path(value: &str) -> Result<(), EventSubjectValueError> {
    if value.is_empty()
        || value.len() > MAX_EVENT_SUBJECT_WORKFLOW_PATH_BYTES
        || value.trim() != value
        || value.starts_with('/')
        || value.contains('\\')
        || value.contains("//")
        || value.chars().any(char::is_control)
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(EventSubjectValueError::InvalidWorkflowPath);
    }
    Ok(())
}

fn validate_bounded_text(
    value: &str,
    maximum: usize,
    error: EventSubjectValueError,
) -> Result<(), EventSubjectValueError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(error);
    }
    Ok(())
}

fn is_machine_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn origin_registry_digest(version: u16, kinds: &[EventSubjectOriginKind]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(REGISTRY_DIGEST_DOMAIN);
    digest.update(version.to_be_bytes());
    digest.update(
        u64::try_from(kinds.len())
            .expect("closed origin registry count fits u64")
            .to_be_bytes(),
    );
    for kind in kinds {
        digest.update(kind.durable_code().to_be_bytes());
        update_length_prefixed(&mut digest, kind.as_durable_str().as_bytes());
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn selection_digest(
    id: EventSubjectId,
    tenant: &TenantScope,
    repository_id: RepositoryId,
    origin: EventSubjectOrigin,
    event_name: &str,
    workflow_path: &str,
    source_revision: &str,
    source_digest: Sha256Digest,
    authority_digest: Sha256Digest,
    selected_at: UnixMillis,
) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(SELECTION_DIGEST_DOMAIN);
    digest.update(EVENT_SUBJECT_SELECTION_SCHEMA.to_be_bytes());
    let origin_registry = EventSubjectOriginRegistry::current();
    digest.update(origin_registry.version().to_be_bytes());
    digest.update(origin_registry.digest().as_bytes());
    digest.update(id.as_uuid().as_bytes());
    update_length_prefixed(&mut digest, tenant.as_str().as_bytes());
    digest.update(repository_id.as_uuid().as_bytes());
    digest.update(origin.kind().durable_code().to_be_bytes());
    digest.update(origin.as_uuid().as_bytes());
    update_length_prefixed(&mut digest, event_name.as_bytes());
    update_length_prefixed(&mut digest, workflow_path.as_bytes());
    update_length_prefixed(&mut digest, source_revision.as_bytes());
    digest.update(source_digest.as_bytes());
    digest.update(authority_digest.as_bytes());
    digest.update(selected_at.get().to_be_bytes());
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn progress_digest(
    subject_id: EventSubjectId,
    selection_digest: Sha256Digest,
    outcome: &EventSubjectTerminalOutcome,
    recorded_at: UnixMillis,
) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(PROGRESS_DIGEST_DOMAIN);
    digest.update(EVENT_SUBJECT_PROGRESS_SCHEMA.to_be_bytes());
    digest.update(subject_id.as_uuid().as_bytes());
    digest.update(selection_digest.as_bytes());
    update_length_prefixed(&mut digest, outcome.kind().as_durable_str().as_bytes());
    if let Some(run_id) = outcome.run_id() {
        digest.update(run_id.as_uuid().as_bytes());
    }
    if let Some(reason) = outcome.reason() {
        update_length_prefixed(&mut digest, reason.as_bytes());
    }
    digest.update(recorded_at.get().to_be_bytes());
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn control_digest(
    id: EventControlSubjectId,
    subject_id: EventSubjectId,
    selection_digest: Sha256Digest,
    registered_at: UnixMillis,
) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(CONTROL_DIGEST_DOMAIN);
    digest.update(EVENT_CONTROL_SUBJECT_SCHEMA.to_be_bytes());
    digest.update(id.as_uuid().as_bytes());
    digest.update(subject_id.as_uuid().as_bytes());
    digest.update(selection_digest.as_bytes());
    digest.update(registered_at.get().to_be_bytes());
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn update_length_prefixed(digest: &mut Sha256, value: &[u8]) {
    digest.update(
        u64::try_from(value.len())
            .expect("bounded event-subject text fits u64")
            .to_be_bytes(),
    );
    digest.update(value);
}

fn sha256_uuid_v8(digest: Sha256) -> Uuid {
    let digest = digest.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // RFC 9562 UUIDv8: application-defined bytes with the standard variant.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}
