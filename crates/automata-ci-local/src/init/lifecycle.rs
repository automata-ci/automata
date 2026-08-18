//! Durable local lifecycle orchestration and topology convergence.

use std::{fmt, path::PathBuf, str::FromStr as _};

use automata_ci_core::{OperationId, Sha256Digest};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{
    DesiredSpec, DockerInstallationAdapter, DoctorRequest, EngineRequest, Installation,
    InstallationId, InstallationName, inspect,
};

use super::{
    LocalInitError, LocalInitErrorCode, StateInstallationSelection, StateMaterialization,
    certificates::{self, CertificateMaterial},
    compose::{ComposeStep, QualifiedDockerCli},
    engine::{InitEngine, LifecycleTopology},
    epoch::{ImmutableEpoch, MaterialDeriver},
    materializer::{s3_access_key, s3_secret_key},
    renderer::{RelayEngineFacts, render_compose, render_relay_binding, render_runner_config},
    state::{StateRoot, StateSnapshot},
};
use crate::lifecycle_helper::{CasRequest, CasTarget};

const LIFECYCLE_INTENT_SCHEMA: &str = "automata.local/lifecycle-operation/v1";
const PREPARED_INTENT_DOMAIN: &[u8] = b"automata/local/lifecycle-prepared-intent/v1\0";
const MAX_LIFECYCLE_INTENT_BYTES: usize = 16 * 1024;

/// Explicit request to converge one sealed installation to its running plan.
#[derive(Clone)]
pub struct LocalUpRequest {
    state_directory: PathBuf,
    cancellation: CancellationToken,
}

impl LocalUpRequest {
    /// Constructs an `up` request for one exact existing custody root.
    #[must_use]
    pub fn new(state_directory: PathBuf, cancellation: CancellationToken) -> Self {
        Self {
            state_directory,
            cancellation,
        }
    }
}

impl fmt::Debug for LocalUpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalUpRequest")
            .field("state_directory", &self.state_directory)
            .finish_non_exhaustive()
    }
}

/// Successful running lifecycle convergence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalUpOutcome {
    installation: InstallationName,
    plan_sha256: Sha256Digest,
    resumed: bool,
}

impl LocalUpOutcome {
    /// Returns the installation selector that is now running.
    #[must_use]
    pub const fn installation(&self) -> &InstallationName {
        &self.installation
    }

    /// Returns the exact sealed Desired plan digest.
    #[must_use]
    pub const fn plan_sha256(&self) -> Sha256Digest {
        self.plan_sha256
    }

    /// Reports whether a previously durable lifecycle transaction was replayed.
    #[must_use]
    pub const fn resumed(&self) -> bool {
        self.resumed
    }
}

struct EstablishedLifecycle {
    installation: Installation,
    epoch: ImmutableEpoch,
    material_root: Zeroizing<[u8; 32]>,
    certificates: CertificateMaterial,
}

struct BootstrapArtifacts {
    request: Vec<u8>,
    token: Zeroizing<String>,
    runner_id: uuid::Uuid,
    spool_key: Zeroizing<String>,
    s3_access_key: String,
    s3_secret_key: Zeroizing<String>,
}

#[derive(Serialize)]
struct BootstrapRequest {
    schema: &'static str,
    bootstrap_operation_id: uuid::Uuid,
    tenant: BootstrapTenant,
    installation_authority_source_sha256: Sha256Digest,
    enrollment_id: uuid::Uuid,
    runner_group: &'static str,
    token_lifetime_seconds: u64,
}

#[derive(Serialize)]
struct BootstrapTenant {
    tenant_id: String,
    display_name: &'static str,
}

/// Converges one exact sealed installation to the current running topology.
///
/// # Errors
///
/// Fails closed for incomplete or copied custody, an older runtime contract,
/// changed Engine/Compose authority, lifecycle contention, topology drift, or
/// cancellation before the durable transaction begins.
pub async fn up_local(request: LocalUpRequest) -> Result<LocalUpOutcome, LocalInitError> {
    let state = StateRoot::acquire_existing(&request.state_directory)?;
    if state.observe_reset_intent_for_reset()?.present() {
        return Err(reset_required());
    }
    let observed_intent = observe_reconciled_lifecycle_intent(&state)?;
    if !observed_intent.present() {
        cancellation_checkpoint(&request.cancellation)?;
    }
    let snapshot = state.snapshot_for_lifecycle()?;
    if snapshot.reset_intent.is_some() {
        return Err(reset_required());
    }
    let established = validate_established_lifecycle(&state, &snapshot)?;
    established.epoch.require_current_lifecycle_contract()?;
    let (mut intent, resumed) = resolve_lifecycle_intent(
        &state,
        &observed_intent,
        &established,
        LifecycleOperationKind::Up,
    )?;

    if intent.completed() {
        let adapter = DockerInstallationAdapter::connect_fixed_engine()
            .await
            .map_err(super::map_engine_error)?;
        let engine = InitEngine::connect(&adapter).await?;
        let _lock = engine
            .elect_lifecycle_lock(&established.installation, state.authority_sha256(), &intent)
            .await?;
        let desired = load_sealed_desired(&engine, &established).await?;
        let transit_id = match engine
            .inspect_lifecycle_topology(&established.installation, &established.epoch, &desired)
            .await?
        {
            LifecycleTopology::Running { transit_id } => transit_id,
            LifecycleTopology::Empty | LifecycleTopology::Partial => {
                return Err(reset_required());
            }
        };
        intent = finalize_running_up(&state, &engine, &established, &desired, &transit_id, intent)
            .await?;
        return Ok(LocalUpOutcome {
            installation: established.installation.name().clone(),
            plan_sha256: intent.plan_sha256(),
            resumed: true,
        });
    }

    let report = inspect(DoctorRequest::new(EngineRequest::Docker)).await;
    let cli = QualifiedDockerCli::qualify(&report).await?;
    let selection = report.selected_engine().ok_or_else(engine_unavailable)?;
    let adapter = DockerInstallationAdapter::connect(&report)
        .await
        .map_err(super::map_engine_error)?;
    let engine = InitEngine::connect(&adapter).await?;
    let lock = engine
        .elect_lifecycle_lock(&established.installation, state.authority_sha256(), &intent)
        .await?;
    let transaction_cancellation = CancellationToken::new();

    engine
        .attest_lifecycle_lock(
            &established.installation,
            state.authority_sha256(),
            &intent,
            &lock,
        )
        .await?;
    let desired = load_sealed_desired(&engine, &established).await?;
    let rendered = render_compose(&desired);
    cli.execute(
        selection,
        &established.installation,
        &rendered.compose_bytes,
        ComposeStep::Validate,
        &transaction_cancellation,
    )
    .await?;

    match engine
        .inspect_lifecycle_topology(&established.installation, &established.epoch, &desired)
        .await?
    {
        LifecycleTopology::Running { transit_id } => {
            while intent.phase() != LifecyclePhase::Running {
                let next = next_up_phase(intent.phase()).ok_or_else(reset_required)?;
                intent = replace_intent_phase(&state, &intent, next)?;
            }
            intent =
                finalize_running_up(&state, &engine, &established, &desired, &transit_id, intent)
                    .await?;
            return Ok(LocalUpOutcome {
                installation: established.installation.name().clone(),
                plan_sha256: intent.plan_sha256(),
                resumed,
            });
        }
        LifecycleTopology::Empty if resumed && intent.phase() != LifecyclePhase::Prepared => {
            return Err(reset_required());
        }
        LifecycleTopology::Partial if !resumed => return Err(reset_required()),
        LifecycleTopology::Empty | LifecycleTopology::Partial => {}
    }

    if intent.phase() == LifecyclePhase::Prepared {
        engine
            .attest_lifecycle_lock(
                &established.installation,
                state.authority_sha256(),
                &intent,
                &lock,
            )
            .await?;
        let _transit_id = engine
            .ensure_results_transit(&established.installation, &desired)
            .await?;
        engine
            .attest_lifecycle_lock(
                &established.installation,
                state.authority_sha256(),
                &intent,
                &lock,
            )
            .await?;
        intent = replace_intent_phase(&state, &intent, LifecyclePhase::ResultsTransitReady)?;
    }

    if intent.phase() == LifecyclePhase::ResultsTransitReady {
        engine
            .attest_lifecycle_lock(
                &established.installation,
                state.authority_sha256(),
                &intent,
                &lock,
            )
            .await?;
        cli.execute(
            selection,
            &established.installation,
            &rendered.compose_bytes,
            ComposeStep::UpDependencies,
            &transaction_cancellation,
        )
        .await?;
        engine
            .attest_lifecycle_lock(
                &established.installation,
                state.authority_sha256(),
                &intent,
                &lock,
            )
            .await?;
        intent = replace_intent_phase(&state, &intent, LifecyclePhase::DependenciesReady)?;
    }

    let transit_id = engine
        .inspect_results_transit(&established.installation, &desired)
        .await?;
    let artifacts = derive_bootstrap_artifacts(&established)?;

    if intent.phase() == LifecyclePhase::DependenciesReady {
        engine
            .attest_lifecycle_lock(
                &established.installation,
                state.authority_sha256(),
                &intent,
                &lock,
            )
            .await?;
        for service in ["postgres", "rustfs"] {
            engine
                .attest_lifecycle_service(
                    &established.installation,
                    &established.epoch,
                    &desired,
                    service,
                )
                .await?;
        }
        publish_initial_cas(
            &engine,
            &established,
            CasTarget::BootstrapRequest,
            &artifacts.request,
        )
        .await?;
        publish_initial_cas(
            &engine,
            &established,
            CasTarget::BootstrapToken,
            artifacts.token.as_bytes(),
        )
        .await?;
        publish_initial_cas(
            &engine,
            &established,
            CasTarget::RunnerS3AccessKey,
            artifacts.s3_access_key.as_bytes(),
        )
        .await?;
        publish_initial_cas(
            &engine,
            &established,
            CasTarget::RunnerS3SecretKey,
            artifacts.s3_secret_key.as_bytes(),
        )
        .await?;
        publish_initial_cas(
            &engine,
            &established,
            CasTarget::RunnerS3Ca,
            established.certificates.ca_pem.as_bytes(),
        )
        .await?;
        publish_initial_cas(
            &engine,
            &established,
            CasTarget::RunnerSpoolKey,
            artifacts.spool_key.as_bytes(),
        )
        .await?;
        run_oneoff(
            &cli,
            selection,
            &engine,
            &established,
            &desired,
            &rendered.compose_bytes,
            "object-store-init",
        )
        .await?;
        run_oneoff(
            &cli,
            selection,
            &engine,
            &established,
            &desired,
            &rendered.compose_bytes,
            "bootstrap-runner",
        )
        .await?;
        engine
            .attest_lifecycle_lock(
                &established.installation,
                state.authority_sha256(),
                &intent,
                &lock,
            )
            .await?;
        intent = replace_intent_phase(&state, &intent, LifecyclePhase::BootstrapReady)?;
    }

    if intent.phase() == LifecyclePhase::BootstrapReady {
        engine
            .attest_lifecycle_lock(
                &established.installation,
                state.authority_sha256(),
                &intent,
                &lock,
            )
            .await?;
        cli.execute(
            selection,
            &established.installation,
            &rendered.compose_bytes,
            ComposeStep::UpControl,
            &transaction_cancellation,
        )
        .await?;
        let control_id = engine
            .attest_lifecycle_service(
                &established.installation,
                &established.epoch,
                &desired,
                "automata",
            )
            .await?;
        let relay = render_relay_binding(
            &desired,
            &RelayEngineFacts {
                id: selection.engine_id(),
                api_version: selection.api_version(),
                server_version: selection.server_version(),
                architecture: selection.architecture(),
            },
        )?;
        publish_initial_cas(&engine, &established, CasTarget::RelayBinding, &relay).await?;
        let runner_config = render_runner_config(
            &desired,
            &established.installation,
            artifacts.runner_id,
            &transit_id,
            &control_id,
        )?;
        publish_initial_cas(
            &engine,
            &established,
            CasTarget::RunnerConfig,
            &runner_config,
        )
        .await?;
        engine
            .attest_lifecycle_lock(
                &established.installation,
                state.authority_sha256(),
                &intent,
                &lock,
            )
            .await?;
        intent = replace_intent_phase(&state, &intent, LifecyclePhase::RunnerConfigurationReady)?;
    }

    if intent.phase() == LifecyclePhase::RunnerConfigurationReady {
        engine
            .attest_lifecycle_lock(
                &established.installation,
                state.authority_sha256(),
                &intent,
                &lock,
            )
            .await?;
        run_oneoff(
            &cli,
            selection,
            &engine,
            &established,
            &desired,
            &rendered.compose_bytes,
            "runner-enroll",
        )
        .await?;
        cli.execute(
            selection,
            &established.installation,
            &rendered.compose_bytes,
            ComposeStep::UpRelay,
            &transaction_cancellation,
        )
        .await?;
        engine
            .attest_lifecycle_service(
                &established.installation,
                &established.epoch,
                &desired,
                "engine-relay",
            )
            .await?;
        cli.execute(
            selection,
            &established.installation,
            &rendered.compose_bytes,
            ComposeStep::UpRunner,
            &transaction_cancellation,
        )
        .await?;
        engine
            .attest_running_lifecycle(
                &established.installation,
                &established.epoch,
                &desired,
                &transit_id,
            )
            .await?;
        engine
            .attest_lifecycle_lock(
                &established.installation,
                state.authority_sha256(),
                &intent,
                &lock,
            )
            .await?;
        intent = replace_intent_phase(&state, &intent, LifecyclePhase::Running)?;
    }

    finalize_running_up(&state, &engine, &established, &desired, &transit_id, intent).await?;
    Ok(LocalUpOutcome {
        installation: established.installation.name().clone(),
        plan_sha256: desired.plan_digest(),
        resumed,
    })
}

async fn load_sealed_desired(
    engine: &InitEngine<'_>,
    established: &EstablishedLifecycle,
) -> Result<DesiredSpec, LocalInitError> {
    let desired_bytes = engine
        .read_sealed_desired(&established.installation, &established.epoch)
        .await?;
    let desired_sha256 = Sha256Digest::from_bytes(Sha256::digest(&desired_bytes).into());
    let desired = DesiredSpec::from_canonical_bytes(&desired_bytes, &established.installation)
        .map_err(|_| reset_required())?;
    if desired_sha256 != established.epoch.initial_desired_sha256()
        || Some(desired.plan_digest()) != established.epoch.desired_plan_sha256()
    {
        return Err(reset_required());
    }
    Ok(desired)
}

async fn finalize_running_up(
    state: &StateRoot,
    engine: &InitEngine<'_>,
    established: &EstablishedLifecycle,
    desired: &DesiredSpec,
    transit_id: &str,
    mut intent: LifecycleIntent,
) -> Result<LifecycleIntent, LocalInitError> {
    if intent.phase() == LifecyclePhase::Running {
        let lock = engine
            .inspect_lifecycle_lock(&established.installation, state.authority_sha256(), &intent)
            .await?
            .ok_or_else(reset_required)?;
        engine
            .attest_running_lifecycle(
                &established.installation,
                &established.epoch,
                desired,
                transit_id,
            )
            .await?;
        engine
            .attest_lifecycle_lock(
                &established.installation,
                state.authority_sha256(),
                &intent,
                &lock,
            )
            .await?;
        intent = replace_intent_phase(state, &intent, LifecyclePhase::Complete)?;
    }
    if !intent.completed() {
        return Err(reset_required());
    }
    engine
        .attest_running_lifecycle(
            &established.installation,
            &established.epoch,
            desired,
            transit_id,
        )
        .await?;
    if let Some(lock) = engine
        .inspect_lifecycle_lock(&established.installation, state.authority_sha256(), &intent)
        .await?
    {
        engine
            .remove_lifecycle_lock(
                &established.installation,
                state.authority_sha256(),
                &intent,
                &lock,
            )
            .await?;
    }
    engine
        .attest_running_lifecycle(
            &established.installation,
            &established.epoch,
            desired,
            transit_id,
        )
        .await?;
    engine
        .attest_lifecycle_lock_absent(&established.installation)
        .await?;
    state.remove_lifecycle_operation()?;
    Ok(intent)
}

fn observe_reconciled_lifecycle_intent(
    state: &StateRoot,
) -> Result<super::state::ResetRecordObservation, LocalInitError> {
    let mut observed = state.observe_lifecycle_operation()?;
    if observed.completed_present() && observed.completed().is_none() {
        return Err(reset_required());
    }
    let malformed_stage = observed.staged_present()
        && observed
            .staged()
            .is_none_or(|bytes| LifecycleIntent::decode_canonical_unbound(bytes).is_err());
    if malformed_stage {
        state.remove_malformed_lifecycle_stage(observed.staged())?;
        observed = state.observe_lifecycle_operation()?;
    }
    Ok(observed)
}

const fn next_up_phase(current: LifecyclePhase) -> Option<LifecyclePhase> {
    match current {
        LifecyclePhase::Prepared => Some(LifecyclePhase::ResultsTransitReady),
        LifecyclePhase::ResultsTransitReady => Some(LifecyclePhase::DependenciesReady),
        LifecyclePhase::DependenciesReady => Some(LifecyclePhase::BootstrapReady),
        LifecyclePhase::BootstrapReady => Some(LifecyclePhase::RunnerConfigurationReady),
        LifecyclePhase::RunnerConfigurationReady => Some(LifecyclePhase::Running),
        _ => None,
    }
}

fn resolve_lifecycle_intent(
    state: &StateRoot,
    observed: &super::state::ResetRecordObservation,
    established: &EstablishedLifecycle,
    kind: LifecycleOperationKind,
) -> Result<(LifecycleIntent, bool), LocalInitError> {
    let parse = |bytes: &[u8]| {
        let intent = LifecycleIntent::from_canonical_bytes(bytes, state)?;
        intent.validate_binding(state, &established.installation, &established.epoch, kind)?;
        Ok::<LifecycleIntent, LocalInitError>(intent)
    };
    let completed = observed.completed().map(parse).transpose()?;
    let staged = observed.staged().map(parse).transpose()?;
    let (expected, resumed) = match (completed, staged) {
        (None, None) if !observed.present() => {
            let intent =
                LifecycleIntent::new(state, &established.installation, &established.epoch, kind)?;
            let bytes = intent.canonical_bytes()?;
            state.store_lifecycle_operation(&bytes)?;
            (intent, false)
        }
        (None, Some(staged))
            if !observed.completed_present()
                && observed.staged_present()
                && staged.phase() == LifecyclePhase::Prepared =>
        {
            let bytes = staged.canonical_bytes()?;
            state.store_lifecycle_operation(&bytes)?;
            (staged, true)
        }
        (Some(completed), None) if observed.completed_present() && !observed.staged_present() => {
            (completed, true)
        }
        (Some(completed), Some(staged))
            if observed.completed_present() && observed.staged_present() =>
        {
            let completed_bytes = completed.canonical_bytes()?;
            let staged_bytes = staged.canonical_bytes()?;
            if completed == staged {
                state.replace_lifecycle_operation(&completed_bytes, &completed_bytes)?;
                (completed, true)
            } else if completed
                .advance(staged.phase())
                .is_ok_and(|expected| expected == staged)
            {
                state.replace_lifecycle_operation(&completed_bytes, &staged_bytes)?;
                (staged, true)
            } else {
                return Err(reset_required());
            }
        }
        _ => return Err(reset_required()),
    };
    let reread = state.observe_lifecycle_operation()?;
    if !reread.completed_present() || reread.staged_present() {
        return Err(reset_required());
    }
    let bytes = reread.completed().ok_or_else(reset_required)?;
    let stored = parse(bytes)?;
    if stored != expected {
        return Err(reset_required());
    }
    Ok((stored, resumed))
}

async fn publish_initial_cas(
    engine: &InitEngine<'_>,
    established: &EstablishedLifecycle,
    target: CasTarget,
    contents: &[u8],
) -> Result<Sha256Digest, LocalInitError> {
    let request = CasRequest::new(target, None, contents)?;
    engine
        .apply_lifecycle_cas(&established.installation, &established.epoch, &request)
        .await
}

#[allow(clippy::too_many_arguments)]
async fn run_oneoff(
    cli: &QualifiedDockerCli,
    selection: &crate::EngineSelection,
    engine: &InitEngine<'_>,
    established: &EstablishedLifecycle,
    desired: &DesiredSpec,
    compose_bytes: &[u8],
    service: &'static str,
) -> Result<(), LocalInitError> {
    engine
        .reconcile_lifecycle_oneoff(
            &established.installation,
            &established.epoch,
            desired,
            service,
        )
        .await?;
    let name = format!("{}-{service}", established.installation.compose_project());
    cli.execute(
        selection,
        &established.installation,
        compose_bytes,
        ComposeStep::RunOneOff {
            service,
            container_name: &name,
        },
        &CancellationToken::new(),
    )
    .await?;
    engine
        .finish_lifecycle_oneoff(
            &established.installation,
            &established.epoch,
            desired,
            service,
        )
        .await?;
    Ok(())
}

fn replace_intent_phase(
    state: &StateRoot,
    current: &LifecycleIntent,
    next: LifecyclePhase,
) -> Result<LifecycleIntent, LocalInitError> {
    let replacement = current.advance(next)?;
    state.replace_lifecycle_operation(
        &current.canonical_bytes()?,
        &replacement.canonical_bytes()?,
    )?;
    let stored = state
        .load_lifecycle_operation()?
        .ok_or_else(reset_required)?;
    let reread = LifecycleIntent::from_canonical_bytes(&stored, state)?;
    if reread != replacement {
        return Err(reset_required());
    }
    Ok(reread)
}

fn validate_established_lifecycle(
    state: &StateRoot,
    snapshot: &StateSnapshot,
) -> Result<EstablishedLifecycle, LocalInitError> {
    let selection = snapshot
        .installation_selection
        .as_deref()
        .ok_or_else(reset_required)
        .and_then(StateInstallationSelection::from_canonical_bytes)?;
    let material_root = snapshot
        .material_root
        .as_deref()
        .ok_or_else(reset_required)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).map_err(|_| reset_required()))?;
    let epoch = ImmutableEpoch::from_sealed_bytes(
        snapshot.epoch.as_deref().ok_or_else(reset_required)?,
        state.authority_sha256(),
        &material_root,
    )?;
    let installation = epoch.installation()?;
    if installation.name() != &selection {
        return Err(reset_required());
    }
    let deriver = MaterialDeriver::new(material_root, &installation, &epoch);
    let certificates = certificates::validate_existing(
        snapshot
            .certificates
            .as_deref()
            .ok_or_else(reset_required)?,
        &deriver,
        &epoch,
    )?;
    if StateMaterialization::from_canonical_bytes(
        snapshot
            .materialization
            .as_deref()
            .ok_or_else(reset_required)?,
    )? != epoch.fingerprint()
    {
        return Err(reset_required());
    }
    if snapshot.reset_intent.is_some() {
        return Err(reset_required());
    }
    Ok(EstablishedLifecycle {
        installation,
        epoch,
        material_root: Zeroizing::new(material_root),
        certificates,
    })
}

fn derive_bootstrap_artifacts(
    established: &EstablishedLifecycle,
) -> Result<BootstrapArtifacts, LocalInitError> {
    let deriver = MaterialDeriver::new(
        *established.material_root,
        &established.installation,
        &established.epoch,
    );
    let runner_id = deriver.uuid(b"lifecycle/runner-id");
    let request = BootstrapRequest {
        schema: "automata.local/bootstrap-runner-request/v1",
        bootstrap_operation_id: deriver.uuid(b"lifecycle/bootstrap-operation-id"),
        tenant: BootstrapTenant {
            tenant_id: format!("local-{}", established.installation.id().as_uuid().simple()),
            display_name: "Local Automata",
        },
        // This digest identifies the OS-custodied root and detects mismatches;
        // it is not itself an authentication secret or database authority.
        installation_authority_source_sha256: established.epoch.material_root_sha256(),
        enrollment_id: deriver.uuid(b"lifecycle/runner-enrollment-id"),
        runner_group: "default",
        token_lifetime_seconds: 3_600,
    };
    let request = canonical_bytes(&request)?;
    let mut token = Zeroizing::new(String::from("atm_re_"));
    URL_SAFE_NO_PAD.encode_string(
        deriver
            .bytes(b"lifecycle/runner-enrollment-token/v1", 32)
            .as_slice(),
        &mut token,
    );
    let spool_key = lower_hex(
        deriver
            .bytes(b"lifecycle/runner-spool-key/v1", 32)
            .as_slice(),
    );
    Ok(BootstrapArtifacts {
        request,
        token,
        runner_id,
        spool_key: Zeroizing::new(spool_key),
        s3_access_key: s3_access_key(&deriver),
        s3_secret_key: s3_secret_key(&deriver),
    })
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes.iter().copied() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn cancellation_checkpoint(cancellation: &CancellationToken) -> Result<(), LocalInitError> {
    if cancellation.is_cancelled() {
        Err(LocalInitError::new(LocalInitErrorCode::Cancelled))
    } else {
        Ok(())
    }
}

fn engine_unavailable() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::EngineUnavailable)
}

/// Public lifecycle operation selected by one durable intent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum LifecycleOperationKind {
    Up,
    Down,
}

/// Durable monotone lifecycle phase.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum LifecyclePhase {
    Prepared,
    ResultsTransitReady,
    DependenciesReady,
    BootstrapReady,
    RunnerConfigurationReady,
    Running,
    RunnerQuiesced,
    ChildrenRemoved,
    StackRemoved,
    ResultsTransitRemoved,
    Complete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LifecycleInstallation {
    name: String,
    id: String,
    selector_key: Sha256Digest,
    compose_project: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PreparedLifecycleIntent {
    schema: String,
    state_authority_sha256: Sha256Digest,
    installation: LifecycleInstallation,
    epoch_fingerprint: Sha256Digest,
    plan_sha256: Sha256Digest,
    operation_kind: LifecycleOperationKind,
    operation_id: OperationId,
}

/// Canonical, authority-bound lifecycle transaction record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LifecycleIntent {
    schema: String,
    state_authority_sha256: Sha256Digest,
    installation: LifecycleInstallation,
    epoch_fingerprint: Sha256Digest,
    plan_sha256: Sha256Digest,
    operation_kind: LifecycleOperationKind,
    operation_id: OperationId,
    prepared_intent_sha256: Sha256Digest,
    phase: LifecyclePhase,
    completed: bool,
}

impl LifecycleIntent {
    pub(super) fn new(
        state: &StateRoot,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        kind: LifecycleOperationKind,
    ) -> Result<Self, LocalInitError> {
        let plan_sha256 = epoch.desired_plan_sha256().ok_or_else(reset_required)?;
        let prepared = PreparedLifecycleIntent {
            schema: LIFECYCLE_INTENT_SCHEMA.to_owned(),
            state_authority_sha256: state.authority_sha256(),
            installation: LifecycleInstallation::new(installation),
            epoch_fingerprint: epoch.fingerprint(),
            plan_sha256,
            operation_kind: kind,
            operation_id: OperationId::new(),
        };
        let prepared_intent_sha256 = prepared_digest(&prepared)?;
        Ok(Self {
            schema: prepared.schema,
            state_authority_sha256: prepared.state_authority_sha256,
            installation: prepared.installation,
            epoch_fingerprint: prepared.epoch_fingerprint,
            plan_sha256: prepared.plan_sha256,
            operation_kind: prepared.operation_kind,
            operation_id: prepared.operation_id,
            prepared_intent_sha256,
            phase: LifecyclePhase::Prepared,
            completed: false,
        })
    }

    pub(super) fn from_canonical_bytes(
        bytes: &[u8],
        state: &StateRoot,
    ) -> Result<Self, LocalInitError> {
        let intent = Self::decode_canonical_unbound(bytes)?;
        if intent.state_authority_sha256 != state.authority_sha256() {
            return Err(reset_required());
        }
        Ok(intent)
    }

    fn decode_canonical_unbound(bytes: &[u8]) -> Result<Self, LocalInitError> {
        if bytes.is_empty() || bytes.len() > MAX_LIFECYCLE_INTENT_BYTES {
            return Err(reset_required());
        }
        let intent: Self = serde_json::from_slice(bytes).map_err(|_| reset_required())?;
        if bytes != intent.canonical_bytes()?.as_slice()
            || intent.schema != LIFECYCLE_INTENT_SCHEMA
            || intent.installation.parse()?.selector_key().digest()
                != intent.installation.selector_key
            || intent.prepared_intent_sha256 != intent.recompute_prepared_digest()?
            || intent.completed != (intent.phase == LifecyclePhase::Complete)
            || !intent.valid_phase_for_operation()
        {
            return Err(reset_required());
        }
        Ok(intent)
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, LocalInitError> {
        canonical_bytes(self)
    }

    pub(super) fn installation(&self) -> Result<Installation, LocalInitError> {
        self.installation.parse()
    }

    pub(super) const fn epoch_fingerprint(&self) -> Sha256Digest {
        self.epoch_fingerprint
    }

    pub(super) const fn plan_sha256(&self) -> Sha256Digest {
        self.plan_sha256
    }

    pub(super) const fn operation_kind(&self) -> LifecycleOperationKind {
        self.operation_kind
    }

    pub(super) const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    pub(super) const fn prepared_intent_sha256(&self) -> Sha256Digest {
        self.prepared_intent_sha256
    }

    pub(super) const fn phase(&self) -> LifecyclePhase {
        self.phase
    }

    pub(super) const fn completed(&self) -> bool {
        self.completed
    }

    pub(super) fn validate_binding(
        &self,
        state: &StateRoot,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        requested: LifecycleOperationKind,
    ) -> Result<(), LocalInitError> {
        if self.state_authority_sha256 != state.authority_sha256()
            || &self.installation.parse()? != installation
            || self.epoch_fingerprint != epoch.fingerprint()
            || Some(self.plan_sha256) != epoch.desired_plan_sha256()
            || self.operation_kind != requested
        {
            return Err(reset_required());
        }
        Ok(())
    }

    pub(super) fn advance(&self, next: LifecyclePhase) -> Result<Self, LocalInitError> {
        if self.completed || !valid_transition(self.operation_kind, self.phase, next) {
            return Err(reset_required());
        }
        let mut replacement = self.clone();
        replacement.phase = next;
        replacement.completed = next == LifecyclePhase::Complete;
        Ok(replacement)
    }

    fn recompute_prepared_digest(&self) -> Result<Sha256Digest, LocalInitError> {
        prepared_digest(&PreparedLifecycleIntent {
            schema: self.schema.clone(),
            state_authority_sha256: self.state_authority_sha256,
            installation: self.installation.clone(),
            epoch_fingerprint: self.epoch_fingerprint,
            plan_sha256: self.plan_sha256,
            operation_kind: self.operation_kind,
            operation_id: self.operation_id,
        })
    }

    fn valid_phase_for_operation(&self) -> bool {
        match self.operation_kind {
            LifecycleOperationKind::Up => matches!(
                self.phase,
                LifecyclePhase::Prepared
                    | LifecyclePhase::ResultsTransitReady
                    | LifecyclePhase::DependenciesReady
                    | LifecyclePhase::BootstrapReady
                    | LifecyclePhase::RunnerConfigurationReady
                    | LifecyclePhase::Running
                    | LifecyclePhase::Complete
            ),
            LifecycleOperationKind::Down => matches!(
                self.phase,
                LifecyclePhase::Prepared
                    | LifecyclePhase::RunnerQuiesced
                    | LifecyclePhase::ChildrenRemoved
                    | LifecyclePhase::StackRemoved
                    | LifecyclePhase::ResultsTransitRemoved
                    | LifecyclePhase::Complete
            ),
        }
    }
}

impl LifecycleInstallation {
    fn new(installation: &Installation) -> Self {
        Self {
            name: installation.name().as_str().to_owned(),
            id: installation.id().to_string(),
            selector_key: installation.selector_key().digest(),
            compose_project: installation.compose_project().to_string(),
        }
    }

    fn parse(&self) -> Result<Installation, LocalInitError> {
        let name = InstallationName::new(self.name.clone()).map_err(|_| reset_required())?;
        let id = InstallationId::from_str(&self.id).map_err(|_| reset_required())?;
        let installation = Installation::verified(name, id);
        if installation.selector_key().digest() != self.selector_key
            || installation.compose_project().as_str() != self.compose_project
        {
            return Err(reset_required());
        }
        Ok(installation)
    }
}

fn valid_transition(
    kind: LifecycleOperationKind,
    current: LifecyclePhase,
    next: LifecyclePhase,
) -> bool {
    match kind {
        LifecycleOperationKind::Up => matches!(
            (current, next),
            (
                LifecyclePhase::Prepared,
                LifecyclePhase::ResultsTransitReady
            ) | (
                LifecyclePhase::ResultsTransitReady,
                LifecyclePhase::DependenciesReady
            ) | (
                LifecyclePhase::DependenciesReady,
                LifecyclePhase::BootstrapReady
            ) | (
                LifecyclePhase::BootstrapReady,
                LifecyclePhase::RunnerConfigurationReady
            ) | (
                LifecyclePhase::RunnerConfigurationReady,
                LifecyclePhase::Running
            ) | (LifecyclePhase::Running, LifecyclePhase::Complete)
        ),
        LifecycleOperationKind::Down => matches!(
            (current, next),
            (LifecyclePhase::Prepared, LifecyclePhase::RunnerQuiesced)
                | (
                    LifecyclePhase::RunnerQuiesced,
                    LifecyclePhase::ChildrenRemoved
                )
                | (
                    LifecyclePhase::ChildrenRemoved,
                    LifecyclePhase::StackRemoved
                )
                | (
                    LifecyclePhase::StackRemoved,
                    LifecyclePhase::ResultsTransitRemoved
                )
                | (
                    LifecyclePhase::ResultsTransitRemoved,
                    LifecyclePhase::Complete
                )
        ),
    }
}

fn prepared_digest(value: &PreparedLifecycleIntent) -> Result<Sha256Digest, LocalInitError> {
    let bytes = canonical_bytes(value)?;
    let mut hasher = Sha256::new();
    hasher.update(PREPARED_INTENT_DOMAIN);
    hasher.update(
        u32::try_from(bytes.len())
            .expect("bounded lifecycle intent length fits u32")
            .to_be_bytes(),
    );
    hasher.update(bytes);
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, LocalInitError> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| reset_required())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn reset_required() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::ResetRequired)
}

#[cfg(test)]
mod tests;
