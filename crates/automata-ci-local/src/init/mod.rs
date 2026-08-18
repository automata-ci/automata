//! Production-consumed x86-64 Linux local-installation initialization.

mod catalog;
mod certificates;
mod compose;
mod engine;
mod epoch;
mod lifecycle;
mod materializer;
mod renderer;
mod state;
mod status_reset;

pub use lifecycle::{
    LocalDownOutcome, LocalDownRequest, LocalUpOutcome, LocalUpRequest, down_local, up_local,
};
pub(crate) use materializer::run_fixed_materializer;
pub use status_reset::{
    LocalInstallationStatus, LocalResetOutcome, LocalResetRequest, LocalStatusReport,
    LocalStatusRequest, inspect_local_status, reset_local,
};

use std::{fmt, future::Future, net::Ipv4Addr, num::NonZeroU16, path::PathBuf};

use automata_ci_core::{EnvironmentProfile, EnvironmentProfileId, OperationId, Sha256Digest};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{
    DesiredSpec, DesiredSpecImages, DesiredSpecInput, DockerInstallationAdapter, DoctorRequest,
    EngineArchitecture, EngineRequest, Installation, InstallationId, InstallationName,
    LocalEngineError, LocalEngineErrorCode, LocalProfile, ResultsTransit, inspect,
};

const LOCAL_INIT_DOCKER_HOST: &str = "unix:///var/run/docker.sock";

/// Stable category for one local initialization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalInitErrorCode {
    /// The explicit state-directory path was not a secure absolute Unix path.
    InvalidStateDirectory,
    /// Another process currently owns the exact initialization lock.
    OperationInProgress,
    /// A state file raced another creator.
    StateCollision,
    /// Existing state or Engine custody requires an explicit reset.
    ResetRequired,
    /// The explicit catalog source was not one local absolute file source.
    InvalidCatalogSource,
    /// The catalog was not the canonical closed current release schema.
    InvalidCatalog,
    /// The exact catalog-declared sibling payload was absent or invalid.
    InvalidCatalogPayload,
    /// The requested worker capacity was outside the release catalog contract.
    InvalidWorkers,
    /// A local custody operation was cancelled before a durable reset transaction.
    Cancelled,
    /// Destructive reset was not explicitly confirmed.
    ConfirmationRequired,
    /// Docker preflight or exact Engine inspection failed.
    EngineUnavailable,
    /// A Docker resource failed its exact immutable custody contract.
    EngineResourceMismatch,
    /// The fixed materialization helper failed or became ambiguous.
    MaterializationFailed,
    /// Exact reset reconciliation could not prove the requested resource absent.
    ResetFailed,
}

impl LocalInitErrorCode {
    const fn message(self) -> &'static str {
        match self {
            Self::InvalidStateDirectory => {
                "the explicit state directory is not a secure absolute Unix directory"
            }
            Self::OperationInProgress => {
                "another local installation operation is already in progress"
            }
            Self::StateCollision => "local initialization state changed concurrently",
            Self::ResetRequired => {
                "local installation custody is missing, incomplete, corrupt, or incompatible; exact init replay or authorized recovery is required"
            }
            Self::InvalidCatalogSource => {
                "catalog source must be one secure explicit file:/absolute/path"
            }
            Self::InvalidCatalog => {
                "the local installation catalog is not canonical current release evidence"
            }
            Self::InvalidCatalogPayload => {
                "the exact catalog-declared sibling payload failed structural or digest verification"
            }
            Self::InvalidWorkers => {
                "requested workers exceed the immutable release-catalog capacity"
            }
            Self::Cancelled => "the local installation operation was cancelled",
            Self::ConfirmationRequired => "local reset requires explicit confirmation",
            Self::EngineUnavailable => "the exact Docker Engine is unavailable for this operation",
            Self::EngineResourceMismatch => {
                "a deterministic Docker resource disagrees with local installation custody"
            }
            Self::MaterializationFailed => {
                "the fixed local materialization helper failed or became ambiguous"
            }
            Self::ResetFailed => {
                "local reset could not prove exact owned-resource deletion complete"
            }
        }
    }
}

/// Redacted local initialization failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub struct LocalInitError {
    code: LocalInitErrorCode,
    message: &'static str,
}

impl LocalInitError {
    pub(super) const fn new(code: LocalInitErrorCode) -> Self {
        Self {
            code,
            message: code.message(),
        }
    }

    /// Returns the stable machine-readable failure category.
    #[must_use]
    pub const fn code(self) -> LocalInitErrorCode {
        self.code
    }
}

/// Complete explicit input to one exact-replay local initialization.
#[derive(Clone)]
pub struct LocalInitRequest {
    state_directory: PathBuf,
    catalog_source: String,
    installation: InstallationName,
    workers: NonZeroU16,
    cancellation: CancellationToken,
    recover_stopped_lock: bool,
}

impl LocalInitRequest {
    /// Constructs one bounded initialization request.
    #[must_use]
    pub fn new(
        state_directory: PathBuf,
        catalog_source: String,
        installation: InstallationName,
        workers: NonZeroU16,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            state_directory,
            catalog_source,
            installation,
            workers,
            cancellation,
            recover_stopped_lock: false,
        }
    }

    /// Explicitly authorizes recovery of one exact stopped initialization lock
    /// after stable, fully validated Engine quiescence is established.
    #[must_use]
    pub const fn with_stopped_lock_recovery(mut self, recover: bool) -> Self {
        self.recover_stopped_lock = recover;
        self
    }
}

impl fmt::Debug for LocalInitRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalInitRequest")
            .field("state_directory", &self.state_directory)
            .field("catalog_source", &self.catalog_source)
            .field("installation", &self.installation)
            .field("workers", &self.workers)
            .field("recover_stopped_lock", &self.recover_stopped_lock)
            .finish_non_exhaustive()
    }
}

/// Successful immutable local epoch sealing; no installation services were started.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalInitOutcome {
    installation: InstallationName,
    workers: NonZeroU16,
}

const INSTALLATION_SELECTION_SCHEMA: &str = "automata.local/installation-selection/v1";
const MATERIALIZATION_SCHEMA: &str = "automata.local/materialization/v1";

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StateInstallationSelection {
    schema: String,
    installation: String,
    selector_key: Sha256Digest,
}

impl StateInstallationSelection {
    fn new(installation: &InstallationName) -> Self {
        Self {
            schema: INSTALLATION_SELECTION_SCHEMA.to_owned(),
            installation: installation.as_str().to_owned(),
            selector_key: Installation::expected(installation).selector_key.digest(),
        }
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, LocalInitError> {
        let mut bytes = serde_json::to_vec(self)
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    fn validate(bytes: &[u8], expected: &Self) -> Result<(), LocalInitError> {
        let actual: Self = serde_json::from_slice(bytes)
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
        if &actual != expected || bytes != actual.canonical_bytes()? {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        Ok(())
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<InstallationName, LocalInitError> {
        let actual: Self = serde_json::from_slice(bytes)
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
        if actual.schema != INSTALLATION_SELECTION_SCHEMA || bytes != actual.canonical_bytes()? {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        let installation = InstallationName::new(actual.installation)
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
        if actual.selector_key != Installation::expected(&installation).selector_key.digest() {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        Ok(installation)
    }
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StateMaterialization {
    schema: String,
    epoch_fingerprint: Sha256Digest,
}

impl StateMaterialization {
    fn new(epoch_fingerprint: Sha256Digest) -> Self {
        Self {
            schema: MATERIALIZATION_SCHEMA.to_owned(),
            epoch_fingerprint,
        }
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, LocalInitError> {
        let mut bytes = serde_json::to_vec(self)
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    fn validate(bytes: &[u8], expected: &Self) -> Result<(), LocalInitError> {
        let actual: Self = serde_json::from_slice(bytes)
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
        if &actual != expected || bytes != actual.canonical_bytes()? {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        Ok(())
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Sha256Digest, LocalInitError> {
        let actual: Self = serde_json::from_slice(bytes)
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
        if actual.schema != MATERIALIZATION_SCHEMA || bytes != actual.canonical_bytes()? {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        Ok(actual.epoch_fingerprint)
    }
}

impl LocalInitOutcome {
    /// Returns the selected installation name.
    #[must_use]
    pub const fn installation(&self) -> &InstallationName {
        &self.installation
    }

    /// Returns the immutable epoch worker capacity.
    #[must_use]
    pub const fn workers(&self) -> NonZeroU16 {
        self.workers
    }
}

/// Seals or exactly replays one immutable local installation epoch without starting services.
///
/// # Errors
///
/// Returns a redacted error when the explicit host custody, release evidence,
/// Docker identity/resources, or fixed materialization protocol fails closed.
#[allow(clippy::too_many_lines)]
#[allow(clippy::large_futures)]
pub async fn initialize_local(
    request: LocalInitRequest,
) -> Result<LocalInitOutcome, LocalInitError> {
    let state = state::StateRoot::acquire(&request.state_directory)?;
    if state.reset_intent_present()? {
        return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
    }
    let evidence = state::EvidenceDirectory::open(&request.catalog_source)?;
    let catalog = catalog::VerifiedCatalog::parse(evidence.catalog())?;
    if request.workers.get() > catalog.maximum_parallel_jobs() {
        return Err(LocalInitError::new(LocalInitErrorCode::InvalidWorkers));
    }
    if request.cancellation.is_cancelled() {
        return Err(LocalInitError::new(LocalInitErrorCode::Cancelled));
    }
    let candidate = evidence.read_candidate(catalog::VerifiedCatalog::candidate_basename())?;
    let candidate_load_archive = catalog.verify_candidate(&candidate)?;
    drop(candidate);

    // Reconcile the one admitted crash frontier and fully census the private
    // namespace before making any Engine call.
    let existing_selection = state.load_installation_selection()?;
    let material_root = state.load_material_root()?;
    let existing_epoch = state.load_epoch()?;
    let existing_certificates = state.load_certificates()?;
    let existing_materialization = state.load_materialization()?;
    state.validate_recovered_layout()?;
    let expected_selection = StateInstallationSelection::new(&request.installation);
    if let Some(bytes) = existing_selection.as_deref() {
        StateInstallationSelection::validate(bytes, &expected_selection)?;
    }

    let report = Box::pin(inspect(DoctorRequest::new(EngineRequest::Docker))).await;
    if !report.ready()
        || report.operating_system() != "linux"
        || report.architecture() != "x86_64"
        || report
            .selected_engine()
            .is_none_or(|selection| !supported_init_host(selection.connection_host()))
    {
        return Err(LocalInitError::new(LocalInitErrorCode::EngineUnavailable));
    }
    let adapter = DockerInstallationAdapter::connect(&report)
        .await
        .map_err(map_engine_error)?;
    let existing_identity = adapter
        .inspect_identity(&request.installation)
        .await
        .map_err(map_engine_error)?;
    let expected = Installation::expected(&request.installation);
    let init_engine = engine::InitEngine::connect(&adapter).await?;
    init_engine.preflight_lifecycle_daemon().await?;
    if material_root.is_some() && existing_selection.is_none()
        || material_root.is_none()
            && (existing_identity.is_some()
                || existing_epoch.is_some()
                || existing_certificates.is_some()
                || existing_materialization.is_some())
        || existing_epoch.is_none()
            && (existing_identity.is_some()
                || existing_certificates.is_some()
                || existing_materialization.is_some())
        || existing_identity.is_none()
            && (existing_certificates.is_some() || existing_materialization.is_some())
    {
        return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
    }
    if request.cancellation.is_cancelled() {
        return Err(LocalInitError::new(LocalInitErrorCode::Cancelled));
    }
    if existing_selection.is_none() {
        state.store_installation_selection(&expected_selection.canonical_bytes()?)?;
    }
    let material_root = match material_root {
        Some(root) => root,
        None => state.create_material_root()?,
    };
    let sealed_epoch = existing_epoch
        .as_deref()
        .map(|bytes| {
            epoch::ImmutableEpoch::from_sealed_bytes(
                bytes,
                state.authority_sha256(),
                &material_root,
            )
        })
        .transpose()?;
    let installation = match (existing_identity.as_ref(), sealed_epoch.as_ref()) {
        (Some(identity), Some(sealed)) if sealed.installation()? != *identity => {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        (Some(identity), _) => identity.clone(),
        (None, Some(sealed)) => sealed.installation()?,
        (None, None) => Installation::verified(request.installation.clone(), InstallationId::new()),
    };
    if installation.name() != &request.installation {
        return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
    }

    let desired = desired_from_catalog(&catalog, &installation, request.workers)?;
    let desired_bytes = desired.canonical_bytes();
    let expected_epoch = epoch::ImmutableEpoch::new(
        &catalog,
        &installation,
        request.workers.get(),
        state.authority_sha256(),
        &material_root,
        digest(&desired_bytes),
        desired.plan_digest(),
    );
    let epoch = if let Some(bytes) = existing_epoch.as_deref() {
        epoch::ImmutableEpoch::from_canonical_bytes(bytes, &expected_epoch)?
    } else {
        state.store_epoch(&expected_epoch.canonical_bytes())?;
        let stored = state
            .load_epoch()?
            .ok_or_else(|| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
        epoch::ImmutableEpoch::from_canonical_bytes(&stored, &expected_epoch)?
    };
    let expected_materialization = StateMaterialization::new(epoch.fingerprint());
    if let Some(bytes) = existing_materialization.as_deref() {
        StateMaterialization::validate(bytes, &expected_materialization)?;
    }
    // Only the exact helper image needed to construct the inert lock may be
    // admitted before election. Every other pull/import is deferred until the
    // retained lock is live.
    let lock_helper = cancellation_bounded(
        &request.cancellation,
        init_engine.qualify_lock_image(&catalog, &candidate_load_archive, &request.cancellation),
    )
    .await?;

    match init_engine
        .inspect_lifecycle_lock_before_identity(&installation, &epoch)
        .await?
    {
        engine::LifecycleLockObservation::Absent => {}
        engine::LifecycleLockObservation::Live { .. } => {
            return Err(LocalInitError::new(LocalInitErrorCode::OperationInProgress));
        }
        engine::LifecycleLockObservation::Stopped { id, .. } => {
            if !request.recover_stopped_lock {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
            init_engine
                .recover_stopped_initialization_lock(
                    &catalog,
                    &installation,
                    &epoch,
                    &id,
                    &request.cancellation,
                )
                .await?;
            if init_engine
                .inspect_lifecycle_lock_before_identity(&installation, &epoch)
                .await?
                != engine::LifecycleLockObservation::Absent
            {
                return Err(LocalInitError::new(
                    LocalInitErrorCode::EngineResourceMismatch,
                ));
            }
        }
    }

    let initial_union = init_engine
        .inspect_owned_union(&expected, existing_identity.as_ref())
        .await?;
    let repeated_identity = adapter
        .inspect_identity(&request.installation)
        .await
        .map_err(map_engine_error)?;
    if repeated_identity != existing_identity
        || initial_union.anchor_present != existing_identity.is_some()
    {
        return Err(LocalInitError::new(
            LocalInitErrorCode::EngineResourceMismatch,
        ));
    }
    let existing_volumes = initial_union.roles.clone();
    let persistent_volumes = !existing_volumes.is_empty();
    let allow_volume_creation =
        volume_creation_allowed(existing_volumes.len(), existing_materialization.is_some())?;
    if persistent_volumes
        && (existing_identity.is_none()
            || existing_epoch.is_none()
            || existing_certificates.is_none()
            || existing_selection.is_none())
        || existing_materialization.is_some() && !persistent_volumes
    {
        return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
    }
    if request.cancellation.is_cancelled() {
        return Err(LocalInitError::new(LocalInitErrorCode::Cancelled));
    }

    let holder = if existing_identity.is_some() {
        init_engine
            .acquire_lifecycle_lock(&installation, &epoch, OperationId::new())
            .await?
    } else {
        init_engine
            .acquire_lifecycle_lock_before_identity(&installation, &epoch, OperationId::new())
            .await?
    };
    let (transaction_cancellation, watcher) =
        lifecycle::linked_cancellation(&request.cancellation, &holder);
    let mutation_fence = holder.mutation_fence(&transaction_cancellation);
    let holder_lost = holder.holder_lost();
    let operation = holder_bounded(&holder_lost, async {
        cancellation_checkpoint(&transaction_cancellation)?;
        if existing_identity.is_none() {
            let created = mutation_fence
                .run(adapter.create_or_adopt_exact_identity(&installation))
                .await?
                .map_err(map_engine_error)?;
            exact_installation_identity(Some(&created), &installation)?;
        } else {
            attest_installation_identity(&adapter, &request.installation, &installation).await?;
        }
        init_engine
            .attest_lifecycle_lock(&installation, &epoch, &holder)
            .await?;
        let helper = cancellation_bounded(
            &transaction_cancellation,
            init_engine.qualify_images(
                &catalog,
                &candidate_load_archive,
                &transaction_cancellation,
                &mutation_fence,
            ),
        )
        .await?;
        if helper.reference != lock_helper.reference || helper.id != lock_helper.id {
            return Err(LocalInitError::new(
                LocalInitErrorCode::EngineResourceMismatch,
            ));
        }
        let lock_identity = Some(holder.exact_identity());
        let preflight_roles = cancellation_bounded(
            &transaction_cancellation,
            init_engine.preflight_owned_union(
                &catalog,
                &installation,
                epoch.fingerprint(),
                &initial_union,
                lock_identity,
                &transaction_cancellation,
            ),
        )
        .await?;
        if preflight_roles != existing_volumes {
            return Err(LocalInitError::new(
                LocalInitErrorCode::EngineResourceMismatch,
            ));
        }
        let deriver = epoch::MaterialDeriver::new(material_root, &installation, &epoch);
        let certificates =
            certificates::load_or_issue(&state, &deriver, &epoch, persistent_volumes)?;
        cancellation_bounded(
            &transaction_cancellation,
            init_engine.elect_desired_and_recover_owned_union(
                &catalog,
                &installation,
                epoch.fingerprint(),
                &initial_union,
                allow_volume_creation,
                lock_identity,
                &transaction_cancellation,
                &mutation_fence,
            ),
        )
        .await?;
        let volumes = cancellation_bounded(
            &transaction_cancellation,
            init_engine.create_or_adopt_volumes(
                &installation,
                epoch.fingerprint(),
                &helper.reference,
                &helper.id,
                allow_volume_creation,
                &transaction_cancellation,
                &mutation_fence,
            ),
        )
        .await?;
        let materialize = materializer::MaterializeRequest::build(
            &epoch,
            &deriver,
            &certificates,
            &desired_bytes,
            existing_materialization.is_none(),
        );
        Box::pin(cancellation_bounded(
            &transaction_cancellation,
            init_engine.run_materializer(
                &installation,
                epoch.fingerprint(),
                &helper.reference,
                &helper.id,
                &volumes,
                &materialize,
                &transaction_cancellation,
                &mutation_fence,
            ),
        ))
        .await?;
        attest_installation_identity(&adapter, &request.installation, &installation).await?;
        init_engine
            .verify_final_owned_union(&installation, epoch.fingerprint(), lock_identity)
            .await?;
        if existing_materialization.is_none() {
            state.validate_before_materialization()?;
            state.store_materialization(&expected_materialization.canonical_bytes()?)?;
        }
        state.validate_complete()?;
        init_engine
            .verify_final_owned_union(&installation, epoch.fingerprint(), lock_identity)
            .await?;
        init_engine
            .attest_lifecycle_lock(&installation, &epoch, &holder)
            .await?;
        attest_installation_identity(&adapter, &request.installation, &installation).await?;
        state.validate_complete()?;
        cancellation_checkpoint(&transaction_cancellation)
    })
    .await;
    watcher.abort();
    if let Err(error) = operation {
        drop(holder);
        return Err(error);
    }
    init_engine
        .release_lifecycle_lock(&installation, &epoch, holder)
        .await?;
    init_engine
        .attest_lifecycle_lock_absent(&installation)
        .await?;
    init_engine
        .verify_final_owned_union(&installation, epoch.fingerprint(), None)
        .await?;
    attest_installation_identity(&adapter, &request.installation, &installation).await?;
    state.validate_complete()?;
    Ok(LocalInitOutcome {
        installation: request.installation,
        workers: request.workers,
    })
}

async fn attest_installation_identity(
    adapter: &DockerInstallationAdapter,
    name: &InstallationName,
    expected: &Installation,
) -> Result<(), LocalInitError> {
    let actual = adapter
        .inspect_identity(name)
        .await
        .map_err(map_engine_error)?;
    exact_installation_identity(actual.as_ref(), expected)
}

fn exact_installation_identity(
    actual: Option<&Installation>,
    expected: &Installation,
) -> Result<(), LocalInitError> {
    if actual != Some(expected) {
        return Err(LocalInitError::new(
            LocalInitErrorCode::EngineResourceMismatch,
        ));
    }
    Ok(())
}

async fn cancellation_bounded<T>(
    cancellation: &CancellationToken,
    operation: impl Future<Output = Result<T, LocalInitError>>,
) -> Result<T, LocalInitError> {
    if cancellation.is_cancelled() {
        return Err(LocalInitError::new(LocalInitErrorCode::Cancelled));
    }
    tokio::pin!(operation);
    tokio::select! {
        biased;
        result = &mut operation => return result,
        () = cancellation.cancelled() => {}
    }
    match operation.await {
        Ok(_) => Err(LocalInitError::new(LocalInitErrorCode::Cancelled)),
        Err(error) => Err(error),
    }
}

async fn holder_bounded<T>(
    holder_lost: &CancellationToken,
    operation: impl Future<Output = Result<T, LocalInitError>>,
) -> Result<T, LocalInitError> {
    if holder_lost.is_cancelled() {
        return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
    }
    tokio::pin!(operation);
    tokio::select! {
        biased;
        () = holder_lost.cancelled() => {
            Err(LocalInitError::new(LocalInitErrorCode::ResetRequired))
        }
        result = &mut operation => result,
    }
}

fn cancellation_checkpoint(cancellation: &CancellationToken) -> Result<(), LocalInitError> {
    if cancellation.is_cancelled() {
        Err(LocalInitError::new(LocalInitErrorCode::Cancelled))
    } else {
        Ok(())
    }
}

fn desired_from_catalog(
    catalog: &catalog::VerifiedCatalog,
    installation: &Installation,
    workers: NonZeroU16,
) -> Result<DesiredSpec, LocalInitError> {
    if catalog.results_port() != 8081 || catalog.runner_control_port() != 9090 {
        return Err(LocalInitError::new(LocalInitErrorCode::InvalidCatalog));
    }
    let profile_id = EnvironmentProfileId::new(catalog.profile().id.clone())
        .map_err(|_| LocalInitError::new(LocalInitErrorCode::InvalidCatalog))?;
    let profile = LocalProfile::new(
        EngineArchitecture::Amd64,
        EnvironmentProfile::new(profile_id, catalog.profile().manifest_sha256),
        catalog.immutable_image("profile"),
    )
    .map_err(|_| LocalInitError::new(LocalInitErrorCode::InvalidCatalog))?;
    let images = DesiredSpecImages::new(
        catalog.immutable_image("automata"),
        catalog.immutable_image("runner"),
        catalog.immutable_image("postgres"),
        catalog.immutable_image("rustfs"),
        catalog.immutable_image("sandbox-guest"),
        catalog.imported_service_proxy(),
    );
    let digest = installation.selector_key().digest();
    let second_octet = 24 + (digest.as_bytes()[3] & 0x07);
    let third_octet = digest.as_bytes()[4] & 0xfe;
    let subnet = format!("172.{second_octet}.{third_octet}.0/23");
    let results = ResultsTransit::new(
        subnet,
        Ipv4Addr::new(172, second_octet, third_octet, 1),
        Ipv4Addr::new(172, second_octet, third_octet, 2),
    )
    .map_err(|_| LocalInitError::new(LocalInitErrorCode::InvalidCatalog))?;
    let input = DesiredSpecInput::new(
        workers,
        NonZeroU16::new(catalog.human_port())
            .ok_or_else(|| LocalInitError::new(LocalInitErrorCode::InvalidCatalog))?,
        profile,
        images,
        results,
    )
    .map_err(|_| LocalInitError::new(LocalInitErrorCode::InvalidCatalog))?;
    DesiredSpec::new(installation, input)
        .map_err(|_| LocalInitError::new(LocalInitErrorCode::InvalidCatalog))
}

fn map_engine_error(error: LocalEngineError) -> LocalInitError {
    let code = match error.code() {
        LocalEngineErrorCode::PreflightRequired
        | LocalEngineErrorCode::ConnectionUnavailable
        | LocalEngineErrorCode::EngineRequestFailed
        | LocalEngineErrorCode::EngineIdentityChanged
        | LocalEngineErrorCode::InvalidEngineResponse => LocalInitErrorCode::EngineUnavailable,
        LocalEngineErrorCode::IdentityCollision
        | LocalEngineErrorCode::InvalidIdentityAnchor
        | LocalEngineErrorCode::IdentityAnchorAttached
        | LocalEngineErrorCode::MutationOutcomeUncertain => {
            LocalInitErrorCode::EngineResourceMismatch
        }
    };
    LocalInitError::new(code)
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn supported_init_host(host: &str) -> bool {
    host == LOCAL_INIT_DOCKER_HOST
}

fn volume_creation_allowed(
    existing_count: usize,
    materialization_complete: bool,
) -> Result<bool, LocalInitError> {
    if existing_count > materializer::VolumeRole::ALL.len()
        || materialization_complete && existing_count != materializer::VolumeRole::ALL.len()
    {
        return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
    }
    Ok(!materialization_complete)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_inputs_derive_disjoint_desired_networks() {
        let catalog = catalog::desired_test_catalog();
        let installation =
            Installation::verified(InstallationName::default(), crate::InstallationId::new());
        let desired = desired_from_catalog(&catalog, &installation, NonZeroU16::new(1).unwrap())
            .expect("the released catalog always constructs one valid Desired plan");
        assert!(desired.results_transit().subnet().starts_with("172."));
        assert!(
            crate::desired_spec::control_subnet_for_spec(&desired)
                .to_string()
                .starts_with("172.")
        );
        assert!(
            crate::desired_spec::egress_subnet_for_spec(&desired)
                .to_string()
                .starts_with("192.168.")
        );
    }

    #[test]
    fn v1_init_authority_is_the_exact_rendered_relay_socket() {
        assert!(supported_init_host("unix:///var/run/docker.sock"));
        for unsupported in [
            "unix:///run/user/1000/docker.sock",
            "unix:///home/operator/.docker/desktop/docker.sock",
            "unix:///var/run/docker-alt.sock",
            "tcp://127.0.0.1:2375",
        ] {
            assert!(!supported_init_host(unsupported), "{unsupported}");
        }
    }

    #[test]
    fn incomplete_fresh_volume_creation_replays_but_established_loss_requires_reset() {
        for existing in 0..=materializer::VolumeRole::ALL.len() {
            assert!(volume_creation_allowed(existing, false).unwrap());
        }
        assert!(!volume_creation_allowed(materializer::VolumeRole::ALL.len(), true).unwrap());
        for missing in [0, materializer::VolumeRole::ALL.len() - 1] {
            assert_eq!(
                volume_creation_allowed(missing, true).unwrap_err().code(),
                LocalInitErrorCode::ResetRequired
            );
        }
    }

    #[test]
    fn final_identity_attestation_rejects_deletion_or_replacement() {
        let name = InstallationName::default();
        let expected = Installation::verified(name.clone(), crate::InstallationId::new());
        assert!(exact_installation_identity(Some(&expected), &expected).is_ok());
        assert_eq!(
            exact_installation_identity(None, &expected)
                .unwrap_err()
                .code(),
            LocalInitErrorCode::EngineResourceMismatch
        );
        let replacement = Installation::verified(name, crate::InstallationId::new());
        assert_eq!(
            exact_installation_identity(Some(&replacement), &expected)
                .unwrap_err()
                .code(),
            LocalInitErrorCode::EngineResourceMismatch
        );
    }
}
