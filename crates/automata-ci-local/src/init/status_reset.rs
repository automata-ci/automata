use std::{fmt, future::Future, path::PathBuf, str::FromStr as _};

use automata_ci_core::Sha256Digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

use crate::{DockerInstallationAdapter, Installation, InstallationId, InstallationName};

use super::{
    LocalInitError, LocalInitErrorCode, StateInstallationSelection, StateMaterialization,
    certificates,
    engine::{InitEngine, ResetHelperBinding, SealedEngineStatus, reset_volume_order},
    epoch::{ImmutableEpoch, MaterialDeriver},
    state::{ResetStateSnapshot, StateRecord, StateRoot, StateSnapshot},
};

const STATUS_SCHEMA: &str = "automata.local/status/v1";
const RESET_INTENT_SCHEMA: &str = "automata.local/reset-intent/v1";
const HOST_RESET_ORDER: [StateRecord; 5] = [
    StateRecord::Materialization,
    StateRecord::Certificates,
    StateRecord::MaterialRoot,
    StateRecord::InstallationSelection,
    StateRecord::Epoch,
];

/// Exact high-level state of the explicit local-installation custody root.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalInstallationStatus {
    /// Initialization has not durably committed every sealed host record.
    Incomplete,
    /// Host records and Engine metadata are exact; volume contents were not live-inspected.
    RecordedSealed,
    /// An authority-bound reset transaction is durably completing or replaying.
    ResetInProgress,
}

/// Stable redacted report for one explicitly selected state directory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LocalStatusReport {
    schema: &'static str,
    status: LocalInstallationStatus,
    installation: Option<String>,
    installation_id: Option<String>,
    workers: Option<u16>,
    epoch_fingerprint: Option<Sha256Digest>,
    records: StatusRecords,
    engine: Option<StatusEngine>,
    volume_contents: &'static str,
    reset: Option<StatusReset>,
}

impl LocalStatusReport {
    /// Returns the exact high-level custody state.
    #[must_use]
    pub const fn status(&self) -> LocalInstallationStatus {
        self.status
    }

    /// Returns the canonical installation selector when one is recorded.
    #[must_use]
    pub fn installation(&self) -> Option<&str> {
        self.installation.as_deref()
    }

    /// Returns the immutable installation identity when it is established.
    #[must_use]
    pub fn installation_id(&self) -> Option<&str> {
        self.installation_id.as_deref()
    }

    /// Returns the recorded immutable worker capacity when an epoch exists.
    #[must_use]
    pub const fn workers(&self) -> Option<u16> {
        self.workers
    }

    /// Returns the recorded epoch fingerprint when an epoch exists.
    #[must_use]
    pub const fn epoch_fingerprint(&self) -> Option<Sha256Digest> {
        self.epoch_fingerprint
    }

    /// Returns the number of exact live image representations inspected.
    #[must_use]
    pub fn image_count(&self) -> usize {
        self.engine.as_ref().map_or(0, |engine| engine.images.len())
    }

    /// Returns the number of exact owned volumes currently present.
    #[must_use]
    pub fn volume_count(&self) -> usize {
        self.engine
            .as_ref()
            .map_or(0, |engine| engine.volumes.len())
    }

    /// Returns reset progress as removed and total Engine resources.
    #[must_use]
    pub const fn reset_progress(&self) -> Option<(usize, usize)> {
        match &self.reset {
            Some(reset) => Some((reset.removed_resources, reset.total_resources)),
            None => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct StatusRecords {
    installation_selection: RecordPresence,
    material_root: RecordPresence,
    epoch: RecordPresence,
    certificates: RecordPresence,
    materialization: RecordPresence,
    reset_intent: RecordPresence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
struct RecordPresence(bool);

impl From<bool> for RecordPresence {
    fn from(present: bool) -> Self {
        Self(present)
    }
}

impl From<&StateSnapshot> for StatusRecords {
    fn from(snapshot: &StateSnapshot) -> Self {
        Self {
            installation_selection: snapshot.installation_selection.is_some().into(),
            material_root: snapshot.material_root.is_some().into(),
            epoch: snapshot.epoch.is_some().into(),
            certificates: snapshot.certificates.is_some().into(),
            materialization: snapshot.materialization.is_some().into(),
            reset_intent: snapshot.reset_intent.is_some().into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct StatusEngine {
    identity: &'static str,
    image_representations: &'static str,
    images: Vec<StatusImage>,
    owned_union: &'static str,
    volumes: Vec<StatusVolume>,
    attachments: &'static str,
    unknown_managed_resources: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct StatusImage {
    role: String,
    source_kind: String,
    inspection_reference: String,
    image_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct StatusVolume {
    role: String,
    name: String,
    static_material: bool,
    manifest: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct StatusReset {
    removed_resources: usize,
    total_resources: usize,
}

/// Explicit read-only local status request.
#[derive(Clone)]
pub struct LocalStatusRequest {
    state_directory: PathBuf,
    cancellation: CancellationToken,
}

impl LocalStatusRequest {
    /// Constructs a status request for one canonical absolute state directory.
    #[must_use]
    pub fn new(state_directory: PathBuf, cancellation: CancellationToken) -> Self {
        Self {
            state_directory,
            cancellation,
        }
    }
}

impl fmt::Debug for LocalStatusRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalStatusRequest")
            .field("state_directory", &self.state_directory)
            .finish_non_exhaustive()
    }
}

/// Explicit destructive reset request.
#[derive(Clone)]
pub struct LocalResetRequest {
    state_directory: PathBuf,
    confirmed: bool,
    cancellation: CancellationToken,
}

impl LocalResetRequest {
    /// Constructs one reset request; callers must pass an explicit confirmation.
    #[must_use]
    pub fn new(state_directory: PathBuf, confirmed: bool, cancellation: CancellationToken) -> Self {
        Self {
            state_directory,
            confirmed,
            cancellation,
        }
    }
}

impl fmt::Debug for LocalResetRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalResetRequest")
            .field("state_directory", &self.state_directory)
            .field("confirmed", &self.confirmed)
            .finish_non_exhaustive()
    }
}

/// Successful exact reset result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalResetOutcome {
    installation: InstallationName,
    removed_volumes: u8,
    images_retained: bool,
    completed_after_cancellation: bool,
}

impl LocalResetOutcome {
    /// Returns the reset installation selector.
    #[must_use]
    pub const fn installation(&self) -> &InstallationName {
        &self.installation
    }

    /// Returns the number of deterministic role volumes removed, excluding the identity anchor.
    #[must_use]
    pub const fn removed_volumes(&self) -> u8 {
        self.removed_volumes
    }

    /// Returns whether imported and pulled images were deliberately retained.
    #[must_use]
    pub const fn images_retained(&self) -> bool {
        self.images_retained
    }

    /// Returns whether cancellation arrived after the durable reset intent.
    #[must_use]
    pub const fn completed_after_cancellation(&self) -> bool {
        self.completed_after_cancellation
    }
}

struct EstablishedState {
    installation: Installation,
    epoch: ImmutableEpoch,
}

enum ValidatedHostState {
    Incomplete {
        installation: Option<InstallationName>,
        epoch: Option<ImmutableEpoch>,
    },
    Established(EstablishedState),
}

/// Inspects sealed custody without creating, repairing, or deleting host or Engine state.
///
/// Successful `recorded_sealed` status attests host records, identity, labels,
/// names, image representations, attachments, and the complete managed union.
/// It deliberately does not attest bytes inside named volumes.
///
/// # Errors
///
/// Returns a redacted failure for path, lock, custody, Engine, or cancellation drift.
pub async fn inspect_local_status(
    request: LocalStatusRequest,
) -> Result<LocalStatusReport, LocalInitError> {
    cancellation_checkpoint(&request.cancellation)?;
    let state = StateRoot::observe_existing(&request.state_directory)?;
    let snapshot = state.snapshot_read_only()?;
    let records = StatusRecords::from(&snapshot);
    if let Some(bytes) = snapshot.reset_intent.as_deref() {
        let intent = ResetIntent::from_canonical_bytes(bytes, state.authority_sha256())?;
        intent.validate_intent_bytes(snapshot.reset_intent.as_deref())?;
        intent.validate_status_snapshot(&snapshot)?;
        cancellation_checkpoint(&request.cancellation)?;
        let adapter = connect_adapter().await?;
        let engine = InitEngine::connect(&adapter).await?;
        let (persistent_removed, helper_present) = match engine
            .inspect_reset_progress(&intent.installation, intent.epoch_fingerprint)
            .await
        {
            Ok(removed) => (removed, false),
            Err(error) if intent.helper.is_some() => {
                let Some(epoch_bytes) = snapshot.epoch.as_deref() else {
                    return Err(error);
                };
                let epoch = ImmutableEpoch::from_authority_bound_bytes(
                    epoch_bytes,
                    state.authority_sha256(),
                )?;
                let preflight = engine.preflight_reset(&intent.installation, &epoch).await?;
                if preflight.helper != intent.helper {
                    return Err(error);
                }
                (0, true)
            }
            Err(error) => return Err(error),
        };
        let helper_recorded = intent.helper.is_some();
        let removed = persistent_removed + usize::from(helper_recorded && !helper_present);
        cancellation_checkpoint(&request.cancellation)?;
        return Ok(LocalStatusReport {
            schema: STATUS_SCHEMA,
            status: LocalInstallationStatus::ResetInProgress,
            installation: Some(intent.installation.name().as_str().to_owned()),
            installation_id: Some(intent.installation.id().to_string()),
            workers: None,
            epoch_fingerprint: Some(intent.epoch_fingerprint),
            records,
            engine: None,
            volume_contents: "not_inspected",
            reset: Some(StatusReset {
                removed_resources: removed,
                total_resources: 13 + usize::from(helper_recorded),
            }),
        });
    }

    match validate_host_state(&state, &snapshot)? {
        ValidatedHostState::Incomplete {
            installation,
            epoch,
        } => {
            cancellation_checkpoint(&request.cancellation)?;
            Ok(LocalStatusReport {
                schema: STATUS_SCHEMA,
                status: LocalInstallationStatus::Incomplete,
                installation: installation.map(|name| name.as_str().to_owned()),
                installation_id: epoch
                    .as_ref()
                    .and_then(|epoch| epoch.installation().ok())
                    .map(|installation| installation.id().to_string()),
                workers: epoch.as_ref().map(ImmutableEpoch::workers),
                epoch_fingerprint: epoch.as_ref().map(ImmutableEpoch::fingerprint),
                records,
                engine: None,
                volume_contents: "not_inspected",
                reset: None,
            })
        }
        ValidatedHostState::Established(established) => {
            cancellation_checkpoint(&request.cancellation)?;
            let adapter = connect_adapter().await?;
            let engine = InitEngine::connect(&adapter).await?;
            let engine = engine
                .inspect_sealed(&established.installation, &established.epoch)
                .await?;
            cancellation_checkpoint(&request.cancellation)?;
            Ok(sealed_report(records, &established, engine))
        }
    }
}

/// Exactly removes one established local installation while retaining images and the lock root.
///
/// # Errors
///
/// Returns without Engine mutation unless confirmation, authority, post-guard
/// ownership, full-union, unknown-resource, and attachment preflight all pass.
/// Once the durable reset intent exists, cancellation is latched and the exact
/// destructive transaction is reconciled to completion or a dominant error.
pub async fn reset_local(request: LocalResetRequest) -> Result<LocalResetOutcome, LocalInitError> {
    reset_local_with_connector(request, connect_adapter).await
}

async fn reset_local_with_connector<C, F>(
    request: LocalResetRequest,
    connect: C,
) -> Result<LocalResetOutcome, LocalInitError>
where
    C: FnOnce() -> F,
    F: Future<Output = Result<DockerInstallationAdapter, LocalInitError>>,
{
    if !request.confirmed {
        return Err(LocalInitError::new(
            LocalInitErrorCode::ConfirmationRequired,
        ));
    }
    let state = StateRoot::acquire_existing(&request.state_directory)?;
    let observed_intent = state.observe_reset_intent_for_reset()?;
    let observed_intent_bytes = reset_intent_candidate(&observed_intent)?.map(<[u8]>::to_vec);
    let replay_intent = observed_intent_bytes
        .as_deref()
        .map(|bytes| ResetIntent::from_canonical_bytes(bytes, state.authority_sha256()))
        .transpose()?;
    if replay_intent.is_none() {
        cancellation_checkpoint(&request.cancellation)?;
    }
    let mut snapshot = state.snapshot_for_reset()?;
    if reset_intent_candidate(&snapshot.reset_intent)? != observed_intent_bytes.as_deref() {
        return Err(reset_required());
    }
    if let Some(intent) = replay_intent.as_ref() {
        intent.validate_reset_candidate_snapshot(&snapshot)?;
        let recovered = state.reconcile_validated_reset_intent(
            observed_intent_bytes
                .as_deref()
                .ok_or_else(reset_required)?,
        )?;
        if Some(recovered.as_slice()) != observed_intent_bytes.as_deref() {
            return Err(reset_required());
        }
        snapshot = state.snapshot_for_reset()?;
        intent.validate_reset_snapshot(&snapshot)?;
    }

    let fresh = if replay_intent.is_none() {
        Some(validate_reset_host_state(&state, &snapshot)?)
    } else {
        None
    };

    let adapter = connect().await?;
    let engine = InitEngine::connect(&adapter).await?;
    let intent = if let Some(intent) = replay_intent {
        intent
    } else {
        let established = fresh.ok_or_else(reset_required)?;
        cancellation_checkpoint(&request.cancellation)?;
        let preflight = engine
            .preflight_reset(&established.installation, &established.epoch)
            .await?;
        cancellation_checkpoint(&request.cancellation)?;
        let proposed = ResetIntent::new(state.authority_sha256(), &established, preflight.helper);
        state.store_reset_intent(&proposed.canonical_bytes()?)?;
        snapshot = state.snapshot_for_reset()?;
        let intent = ResetIntent::from_canonical_bytes(
            snapshot
                .reset_intent
                .completed()
                .ok_or_else(reset_required)?,
            state.authority_sha256(),
        )?;
        intent.validate_reset_snapshot(&snapshot)?;
        intent
    };

    snapshot = state.snapshot_for_reset()?;
    intent.validate_reset_snapshot(&snapshot)?;
    let mut cancellation_latched = drive_engine_reset(
        &engine,
        &intent.installation,
        intent.epoch_fingerprint,
        intent.helper.as_ref(),
        &request.cancellation,
    )
    .await?;
    drop(engine);
    drop(adapter);

    snapshot = state.snapshot_for_reset()?;
    intent.validate_reset_snapshot(&snapshot)?;
    let host = StateResetHostDriver {
        state: &state,
        intent: &intent,
    };
    cancellation_latched = erase_host_records(&host, &request.cancellation, cancellation_latched)?;
    Ok(LocalResetOutcome {
        installation: intent.installation.name().clone(),
        removed_volumes: 12,
        images_retained: true,
        completed_after_cancellation: cancellation_latched,
    })
}

trait ResetHostDriver {
    fn validate_remaining(&self) -> Result<(), LocalInitError>;
    fn remove_record(&self, record: StateRecord) -> Result<(), LocalInitError>;
    fn verify_empty(&self) -> Result<(), LocalInitError>;
}

struct StateResetHostDriver<'a> {
    state: &'a StateRoot,
    intent: &'a ValidatedResetIntent,
}

impl ResetHostDriver for StateResetHostDriver<'_> {
    fn validate_remaining(&self) -> Result<(), LocalInitError> {
        let snapshot = self.state.snapshot_for_reset()?;
        self.intent.validate_reset_snapshot(&snapshot)
    }

    fn remove_record(&self, record: StateRecord) -> Result<(), LocalInitError> {
        self.state.remove_record(record)
    }

    fn verify_empty(&self) -> Result<(), LocalInitError> {
        if self.state.snapshot_for_reset()?.is_empty() {
            Ok(())
        } else {
            Err(reset_failed())
        }
    }
}

fn erase_host_records<D: ResetHostDriver>(
    driver: &D,
    cancellation: &CancellationToken,
    mut cancellation_latched: bool,
) -> Result<bool, LocalInitError> {
    for record in HOST_RESET_ORDER {
        driver.validate_remaining()?;
        driver.remove_record(record)?;
        cancellation_latched |= cancellation.is_cancelled();
        driver.validate_remaining()?;
    }
    driver.validate_remaining()?;
    driver.remove_record(StateRecord::ResetIntent)?;
    cancellation_latched |= cancellation.is_cancelled();
    driver.verify_empty()?;
    cancellation_latched |= cancellation.is_cancelled();
    Ok(cancellation_latched)
}

#[async_trait::async_trait]
trait ResetMutationDriver: Sync {
    async fn cleanup_helper(
        &self,
        installation: &Installation,
        epoch_fingerprint: Sha256Digest,
        helper: &ResetHelperBinding,
    ) -> Result<(), LocalInitError>;

    async fn inspect_progress(
        &self,
        installation: &Installation,
        epoch_fingerprint: Sha256Digest,
    ) -> Result<usize, LocalInitError>;

    async fn remove_volume(
        &self,
        installation: &Installation,
        epoch_fingerprint: Sha256Digest,
        role: super::materializer::VolumeRole,
    ) -> Result<(), LocalInitError>;

    async fn remove_anchor(&self, installation: &Installation) -> Result<(), LocalInitError>;
}

#[async_trait::async_trait]
impl ResetMutationDriver for InitEngine<'_> {
    async fn cleanup_helper(
        &self,
        installation: &Installation,
        epoch_fingerprint: Sha256Digest,
        helper: &ResetHelperBinding,
    ) -> Result<(), LocalInitError> {
        self.cleanup_reset_helper(installation, epoch_fingerprint, helper)
            .await
    }

    async fn inspect_progress(
        &self,
        installation: &Installation,
        epoch_fingerprint: Sha256Digest,
    ) -> Result<usize, LocalInitError> {
        self.inspect_reset_progress(installation, epoch_fingerprint)
            .await
    }

    async fn remove_volume(
        &self,
        installation: &Installation,
        epoch_fingerprint: Sha256Digest,
        role: super::materializer::VolumeRole,
    ) -> Result<(), LocalInitError> {
        self.remove_reset_volume(installation, epoch_fingerprint, role)
            .await
    }

    async fn remove_anchor(&self, installation: &Installation) -> Result<(), LocalInitError> {
        self.remove_reset_anchor(installation).await
    }
}

async fn drive_engine_reset<D: ResetMutationDriver>(
    driver: &D,
    installation: &Installation,
    epoch_fingerprint: Sha256Digest,
    helper: Option<&ResetHelperBinding>,
    cancellation: &CancellationToken,
) -> Result<bool, LocalInitError> {
    let mut cancellation_latched = cancellation.is_cancelled();
    if let Some(helper) = helper {
        driver
            .cleanup_helper(installation, epoch_fingerprint, helper)
            .await?;
        cancellation_latched |= cancellation.is_cancelled();
    }
    let mut removed = driver
        .inspect_progress(installation, epoch_fingerprint)
        .await?;
    cancellation_latched |= cancellation.is_cancelled();
    for (index, role) in reset_volume_order().into_iter().enumerate().skip(removed) {
        driver
            .remove_volume(installation, epoch_fingerprint, role)
            .await?;
        cancellation_latched |= cancellation.is_cancelled();
        removed = driver
            .inspect_progress(installation, epoch_fingerprint)
            .await?;
        if removed != index + 1 {
            return Err(reset_failed());
        }
    }
    if removed == 12 {
        driver.remove_anchor(installation).await?;
        cancellation_latched |= cancellation.is_cancelled();
        removed = driver
            .inspect_progress(installation, epoch_fingerprint)
            .await?;
    }
    if removed != 13 {
        return Err(reset_failed());
    }
    Ok(cancellation_latched)
}

fn validate_reset_host_state(
    state: &StateRoot,
    snapshot: &ResetStateSnapshot,
) -> Result<EstablishedState, LocalInitError> {
    let epoch = ImmutableEpoch::from_authority_bound_bytes(
        snapshot.epoch.completed().ok_or_else(reset_required)?,
        state.authority_sha256(),
    )?;
    let installation = epoch.installation()?;
    validate_reset_candidate_conflicts(
        snapshot,
        state.authority_sha256(),
        &installation,
        epoch.fingerprint(),
    )?;
    Ok(EstablishedState {
        installation,
        epoch,
    })
}

fn reset_intent_candidate(
    observation: &super::state::ResetRecordObservation,
) -> Result<Option<&[u8]>, LocalInitError> {
    if observation.completed_present() != observation.completed().is_some()
        || observation.staged_present() != observation.staged().is_some()
    {
        return Err(reset_required());
    }
    match (observation.completed(), observation.staged()) {
        (Some(completed), Some(staged)) if completed == staged => Ok(Some(completed)),
        (Some(_), Some(_)) => Err(reset_required()),
        (Some(completed), None) => Ok(Some(completed)),
        (None, Some(staged)) => Ok(Some(staged)),
        (None, None) if observation.present() => Err(reset_required()),
        (None, None) => Ok(None),
    }
}

fn validate_reset_candidate_conflicts(
    snapshot: &ResetStateSnapshot,
    state_authority_sha256: Sha256Digest,
    installation: &Installation,
    epoch_fingerprint: Sha256Digest,
) -> Result<(), LocalInitError> {
    for bytes in [snapshot.epoch.completed(), snapshot.epoch.staged()]
        .into_iter()
        .flatten()
    {
        if let Ok(candidate) =
            ImmutableEpoch::from_authority_bound_bytes(bytes, state_authority_sha256)
        {
            let candidate_installation = candidate.installation()?;
            if candidate_installation != *installation
                || candidate.fingerprint() != epoch_fingerprint
            {
                return Err(reset_required());
            }
        }
    }
    for bytes in [
        snapshot.installation_selection.completed(),
        snapshot.installation_selection.staged(),
    ]
    .into_iter()
    .flatten()
    {
        if let Ok(selection) = StateInstallationSelection::from_canonical_bytes(bytes)
            && selection != *installation.name()
        {
            return Err(reset_required());
        }
    }
    for bytes in [
        snapshot.materialization.completed(),
        snapshot.materialization.staged(),
    ]
    .into_iter()
    .flatten()
    {
        if let Ok(fingerprint) = StateMaterialization::from_canonical_bytes(bytes)
            && fingerprint != epoch_fingerprint
        {
            return Err(reset_required());
        }
    }
    Ok(())
}

fn validate_status_candidate_conflicts(
    snapshot: &StateSnapshot,
    state_authority_sha256: Sha256Digest,
    installation: &Installation,
    epoch_fingerprint: Sha256Digest,
) -> Result<(), LocalInitError> {
    if let Some(bytes) = snapshot.epoch.as_deref()
        && let Ok(candidate) =
            ImmutableEpoch::from_authority_bound_bytes(bytes, state_authority_sha256)
        && (candidate.installation()? != *installation
            || candidate.fingerprint() != epoch_fingerprint)
    {
        return Err(reset_required());
    }
    if let Some(bytes) = snapshot.installation_selection.as_deref()
        && let Ok(selection) = StateInstallationSelection::from_canonical_bytes(bytes)
        && selection != *installation.name()
    {
        return Err(reset_required());
    }
    if let Some(bytes) = snapshot.materialization.as_deref()
        && let Ok(fingerprint) = StateMaterialization::from_canonical_bytes(bytes)
        && fingerprint != epoch_fingerprint
    {
        return Err(reset_required());
    }
    Ok(())
}

fn validate_host_state(
    state: &StateRoot,
    snapshot: &StateSnapshot,
) -> Result<ValidatedHostState, LocalInitError> {
    let installation = snapshot
        .installation_selection
        .as_deref()
        .map(StateInstallationSelection::from_canonical_bytes)
        .transpose()?;
    let material_root = snapshot
        .material_root
        .as_deref()
        .map(|bytes| <[u8; 32]>::try_from(bytes).map_err(|_| reset_required()))
        .transpose()?;
    if installation.is_none()
        && (material_root.is_some()
            || snapshot.epoch.is_some()
            || snapshot.certificates.is_some()
            || snapshot.materialization.is_some())
        || material_root.is_none()
            && (snapshot.epoch.is_some()
                || snapshot.certificates.is_some()
                || snapshot.materialization.is_some())
        || snapshot.epoch.is_none()
            && (snapshot.certificates.is_some() || snapshot.materialization.is_some())
        || snapshot.certificates.is_none() && snapshot.materialization.is_some()
    {
        return Err(reset_required());
    }
    let epoch = match (snapshot.epoch.as_deref(), material_root.as_ref()) {
        (Some(bytes), Some(root)) => Some(ImmutableEpoch::from_sealed_bytes(
            bytes,
            state.authority_sha256(),
            root,
        )?),
        (None, _) => None,
        (Some(_), None) => return Err(reset_required()),
    };
    if let (Some(selection), Some(epoch)) = (&installation, &epoch) {
        let epoch_installation = epoch.installation()?;
        if epoch_installation.name() != selection {
            return Err(reset_required());
        }
        if let Some(bytes) = snapshot.certificates.as_deref() {
            let deriver = MaterialDeriver::new(
                material_root.ok_or_else(reset_required)?,
                &epoch_installation,
                epoch,
            );
            let _validated = certificates::validate_existing(bytes, &deriver, epoch)?;
        }
        if let Some(bytes) = snapshot.materialization.as_deref()
            && StateMaterialization::from_canonical_bytes(bytes)? != epoch.fingerprint()
        {
            return Err(reset_required());
        }
    }
    if snapshot.installation_selection.is_some()
        && snapshot.material_root.is_some()
        && snapshot.epoch.is_some()
        && snapshot.certificates.is_some()
        && snapshot.materialization.is_some()
    {
        let epoch = epoch.ok_or_else(reset_required)?;
        return Ok(ValidatedHostState::Established(EstablishedState {
            installation: epoch.installation()?,
            epoch,
        }));
    }
    Ok(ValidatedHostState::Incomplete {
        installation,
        epoch,
    })
}

fn sealed_report(
    records: StatusRecords,
    established: &EstablishedState,
    engine: SealedEngineStatus,
) -> LocalStatusReport {
    let images = engine
        .images
        .into_iter()
        .map(|image| StatusImage {
            role: image.role,
            source_kind: image.source_kind,
            inspection_reference: image.inspection_reference,
            image_id: image.image_id,
        })
        .collect();
    let volumes = engine
        .volumes
        .into_iter()
        .map(|volume| StatusVolume {
            role: volume.role.name().to_owned(),
            name: volume.name,
            static_material: volume.static_material,
            manifest: if volume.static_material {
                "recorded_not_live_attested"
            } else {
                "not_applicable"
            },
        })
        .collect();
    LocalStatusReport {
        schema: STATUS_SCHEMA,
        status: LocalInstallationStatus::RecordedSealed,
        installation: Some(established.installation.name().as_str().to_owned()),
        installation_id: Some(established.installation.id().to_string()),
        workers: Some(established.epoch.workers()),
        epoch_fingerprint: Some(established.epoch.fingerprint()),
        records,
        engine: Some(StatusEngine {
            identity: "exact",
            image_representations: "exact",
            images,
            owned_union: "exact",
            volumes,
            attachments: "absent",
            unknown_managed_resources: "absent",
        }),
        volume_contents: "not_inspected",
        reset: None,
    }
}

async fn connect_adapter() -> Result<DockerInstallationAdapter, LocalInitError> {
    DockerInstallationAdapter::connect_fixed_engine()
        .await
        .map_err(super::map_engine_error)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ResetIntent {
    schema: String,
    state_authority_sha256: Sha256Digest,
    installation: ResetInstallation,
    epoch_fingerprint: Sha256Digest,
    role_set_sha256: Sha256Digest,
    helper: Option<ResetHelperBinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ResetInstallation {
    name: String,
    id: String,
    selector_key: String,
    compose_project: String,
}

impl ResetIntent {
    fn new(
        state_authority_sha256: Sha256Digest,
        established: &EstablishedState,
        helper: Option<ResetHelperBinding>,
    ) -> Self {
        Self {
            schema: RESET_INTENT_SCHEMA.to_owned(),
            state_authority_sha256,
            installation: ResetInstallation::from_installation(&established.installation),
            epoch_fingerprint: established.epoch.fingerprint(),
            role_set_sha256: reset_role_set_sha256(),
            helper,
        }
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, LocalInitError> {
        let mut bytes = serde_json::to_vec(self).map_err(|_| reset_required())?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    fn from_canonical_bytes(
        bytes: &[u8],
        state_authority_sha256: Sha256Digest,
    ) -> Result<ValidatedResetIntent, LocalInitError> {
        let intent: Self = serde_json::from_slice(bytes).map_err(|_| reset_required())?;
        if intent.schema != RESET_INTENT_SCHEMA
            || intent.state_authority_sha256 != state_authority_sha256
            || intent.role_set_sha256 != reset_role_set_sha256()
            || intent.canonical_bytes()? != bytes
        {
            return Err(reset_required());
        }
        let installation = intent.installation.to_installation()?;
        Ok(ValidatedResetIntent {
            state_authority_sha256,
            installation,
            epoch_fingerprint: intent.epoch_fingerprint,
            helper: intent.helper,
            canonical_bytes: bytes.to_vec(),
        })
    }
}

struct ValidatedResetIntent {
    state_authority_sha256: Sha256Digest,
    installation: Installation,
    epoch_fingerprint: Sha256Digest,
    helper: Option<ResetHelperBinding>,
    canonical_bytes: Vec<u8>,
}

impl ValidatedResetIntent {
    fn validate_intent_bytes(&self, bytes: Option<&[u8]>) -> Result<(), LocalInitError> {
        if bytes != Some(self.canonical_bytes.as_slice()) {
            return Err(reset_required());
        }
        Ok(())
    }

    fn validate_reset_snapshot(&self, snapshot: &ResetStateSnapshot) -> Result<(), LocalInitError> {
        self.validate_intent_bytes(snapshot.reset_intent.completed())?;
        if snapshot.reset_intent.staged_present() {
            return Err(reset_required());
        }
        self.validate_reset_candidate_snapshot(snapshot)
    }

    fn validate_reset_candidate_snapshot(
        &self,
        snapshot: &ResetStateSnapshot,
    ) -> Result<(), LocalInitError> {
        validate_reset_candidate_conflicts(
            snapshot,
            self.state_authority_sha256,
            &self.installation,
            self.epoch_fingerprint,
        )
    }

    fn validate_status_snapshot(&self, snapshot: &StateSnapshot) -> Result<(), LocalInitError> {
        validate_status_candidate_conflicts(
            snapshot,
            self.state_authority_sha256,
            &self.installation,
            self.epoch_fingerprint,
        )
    }
}

impl ResetInstallation {
    fn from_installation(installation: &Installation) -> Self {
        Self {
            name: installation.name().as_str().to_owned(),
            id: installation.id().to_string(),
            selector_key: installation.selector_key().to_string(),
            compose_project: installation.compose_project().to_string(),
        }
    }

    fn to_installation(&self) -> Result<Installation, LocalInitError> {
        let name = InstallationName::new(self.name.clone()).map_err(|_| reset_required())?;
        let id = InstallationId::from_str(&self.id).map_err(|_| reset_required())?;
        let installation = Installation::verified(name, id);
        if self.selector_key != installation.selector_key().to_string()
            || self.compose_project != installation.compose_project().as_str()
        {
            return Err(reset_required());
        }
        Ok(installation)
    }
}

fn reset_role_set_sha256() -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"automata/local/reset-role-set/v1\0");
    for role in reset_volume_order() {
        let name = role.name().as_bytes();
        hasher.update(
            u16::try_from(name.len())
                .expect("closed volume-role name fits u16")
                .to_be_bytes(),
        );
        hasher.update(name);
    }
    let anchor_contract = b"identity-anchor/volume/schema-1";
    hasher.update(
        u16::try_from(anchor_contract.len())
            .expect("closed identity-anchor contract fits u16")
            .to_be_bytes(),
    );
    hasher.update(anchor_contract);
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn cancellation_checkpoint(cancellation: &CancellationToken) -> Result<(), LocalInitError> {
    if cancellation.is_cancelled() {
        Err(LocalInitError::new(LocalInitErrorCode::Cancelled))
    } else {
        Ok(())
    }
}

fn reset_required() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::ResetRequired)
}

fn reset_failed() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::ResetFailed)
}

#[cfg(test)]
mod tests;
