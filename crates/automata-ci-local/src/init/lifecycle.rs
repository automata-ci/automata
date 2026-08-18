//! Engine-observed local lifecycle convergence.
//!
//! The host custody root contains immutable installation evidence only. Live
//! convergence is replayed from sealed Desired bytes plus fresh Engine and
//! Compose inspection; there is deliberately no host lifecycle journal or
//! second phase state machine.

// These futures retain one visible transaction boundary so cancellation and sticky-lock
// ordering can be audited without hopping across artificial helper layers.
#![allow(clippy::large_futures, clippy::too_many_arguments)]

use std::{collections::BTreeSet, fmt, future::Future, path::PathBuf};

use automata_ci_core::{OperationId, Sha256Digest};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{
    DesiredSpec, DockerInstallationAdapter, DoctorRequest, EngineRequest, Installation,
    InstallationName, inspect,
};

use super::{
    LocalInitError, LocalInitErrorCode, StateInstallationSelection, StateMaterialization,
    certificates::{self, CertificateMaterial},
    compose::{ComposeStep, QualifiedDockerCli},
    engine::{
        InitEngine, LifecycleLockHolder, LifecycleLockObservation, LifecycleMutationFence,
        LifecycleTopology,
    },
    epoch::{ImmutableEpoch, MaterialDeriver},
    materializer::{MaterializeRequest, s3_access_key, s3_secret_key},
    renderer::{RelayEngineFacts, render_compose, render_relay_binding, render_runner_config},
    state::{StateRoot, StateSnapshot},
};
use crate::lifecycle_helper::{CasRequest, CasTarget};

/// Explicit request to converge one sealed installation to its running plan.
#[derive(Clone)]
pub struct LocalUpRequest {
    state_directory: PathBuf,
    cancellation: CancellationToken,
    recover_stopped_lock: bool,
}

impl LocalUpRequest {
    /// Constructs an `up` request for one exact existing custody root.
    #[must_use]
    pub fn new(state_directory: PathBuf, cancellation: CancellationToken) -> Self {
        Self {
            state_directory,
            cancellation,
            recover_stopped_lock: false,
        }
    }

    /// Explicitly authorizes removal of one exact stopped lifecycle lock only
    /// after the Engine has established stable positive quiescence.
    #[must_use]
    pub const fn with_stopped_lock_recovery(mut self, recover: bool) -> Self {
        self.recover_stopped_lock = recover;
        self
    }
}

impl fmt::Debug for LocalUpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalUpRequest")
            .field("state_directory", &self.state_directory)
            .field("recover_stopped_lock", &self.recover_stopped_lock)
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

    /// Reports whether convergence began from already-realized topology.
    #[must_use]
    pub const fn resumed(&self) -> bool {
        self.resumed
    }
}

/// Explicit request to converge one sealed installation to its durable-down state.
#[derive(Clone)]
pub struct LocalDownRequest {
    state_directory: PathBuf,
    cancellation: CancellationToken,
    recover_stopped_lock: bool,
}

impl LocalDownRequest {
    /// Constructs a `down` request for one exact existing custody root.
    #[must_use]
    pub fn new(state_directory: PathBuf, cancellation: CancellationToken) -> Self {
        Self {
            state_directory,
            cancellation,
            recover_stopped_lock: false,
        }
    }

    /// Explicitly authorizes removal of one exact stopped lifecycle lock only
    /// after the Engine has established stable positive quiescence.
    #[must_use]
    pub const fn with_stopped_lock_recovery(mut self, recover: bool) -> Self {
        self.recover_stopped_lock = recover;
        self
    }
}

impl fmt::Debug for LocalDownRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalDownRequest")
            .field("state_directory", &self.state_directory)
            .field("recover_stopped_lock", &self.recover_stopped_lock)
            .finish_non_exhaustive()
    }
}

/// Successful durable-down lifecycle convergence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalDownOutcome {
    installation: InstallationName,
    plan_sha256: Sha256Digest,
    resumed: bool,
}

impl LocalDownOutcome {
    /// Returns the installation selector that is now down.
    #[must_use]
    pub const fn installation(&self) -> &InstallationName {
        &self.installation
    }

    /// Returns the exact sealed Desired plan digest preserved by `down`.
    #[must_use]
    pub const fn plan_sha256(&self) -> Sha256Digest {
        self.plan_sha256
    }

    /// Reports whether convergence began from a prior partial/down topology.
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
/// caller/holder cancellation.
#[allow(clippy::too_many_lines)]
pub async fn up_local(request: LocalUpRequest) -> Result<LocalUpOutcome, LocalInitError> {
    let state = StateRoot::acquire_existing(&request.state_directory)?;
    let established = load_established_lifecycle(&state)?;
    cancellation_checkpoint(&request.cancellation)?;

    // Resolve and retain both executable authorities before the first Engine
    // lifecycle mutation. The qualified value executes only the held FDs.
    let report = inspect(DoctorRequest::new(EngineRequest::Docker)).await;
    let cli = QualifiedDockerCli::qualify(&report).await?;
    let selection = report.selected_engine().ok_or_else(engine_unavailable)?;
    let adapter = DockerInstallationAdapter::connect(&report)
        .await
        .map_err(super::map_engine_error)?;
    let engine = InitEngine::connect(&adapter).await?;
    engine.preflight_lifecycle_daemon().await?;

    // Metadata and image admission is non-repairing. Desired content is read
    // by an exact disposable helper only after the mutation lock is retained.
    engine
        .preflight_lifecycle_volumes(&established.installation, &established.epoch)
        .await?;
    let expected_desired = established.epoch.desired_spec()?;
    let rendered = render_compose(&expected_desired);
    let expected_runner_id = derive_bootstrap_artifacts(&established)?.runner_id;
    cli.validate(
        selection,
        &established.installation,
        &rendered.compose_bytes,
        &request.cancellation,
    )
    .await?;
    recover_stopped_lock_if_authorized(
        &engine,
        &established,
        &expected_desired,
        &rendered.expected,
        expected_runner_id,
        request.recover_stopped_lock,
        &request.cancellation,
    )
    .await?;
    cancellation_checkpoint(&request.cancellation)?;
    let holder = engine
        .acquire_lifecycle_lock(
            &established.installation,
            &established.epoch,
            OperationId::new(),
        )
        .await?;
    let (transaction_cancellation, watcher) = linked_cancellation(&request.cancellation, &holder);
    let mutation_fence = holder.mutation_fence(&request.cancellation);

    let operation = cancellation_bounded(&transaction_cancellation, async {
        engine
            .attest_lifecycle_lock(&established.installation, &established.epoch, &holder)
            .await?;
        engine
            .preflight_lifecycle_volumes(&established.installation, &established.epoch)
            .await?;
        engine
            .cleanup_lifecycle_disposable_helpers(
                &established.installation,
                &established.epoch,
                &expected_desired,
                &rendered.expected,
                derive_bootstrap_artifacts(&established)?.runner_id,
                &holder,
                &transaction_cancellation,
                &mutation_fence,
            )
            .await?;
        cli.validate(
            selection,
            &established.installation,
            &rendered.compose_bytes,
            &transaction_cancellation,
        )
        .await?;
        engine
            .attest_lifecycle_lock(&established.installation, &established.epoch, &holder)
            .await?;

        let initial = engine
            .inspect_lifecycle_topology(
                &established.installation,
                &established.epoch,
                &expected_desired,
                &rendered.expected,
                expected_runner_id,
            )
            .await?;
        let desired = load_sealed_desired(&engine, &established, &mutation_fence).await?;
        if desired != expected_desired {
            return Err(reset_required());
        }
        attest_sealed_material(
            &engine,
            &established,
            &desired,
            &transaction_cancellation,
            &mutation_fence,
        )
        .await?;
        if engine
            .inspect_lifecycle_topology(
                &established.installation,
                &established.epoch,
                &desired,
                &rendered.expected,
                expected_runner_id,
            )
            .await?
            != initial
        {
            return Err(reset_required());
        }
        engine
            .attest_lifecycle_lock(&established.installation, &established.epoch, &holder)
            .await?;
        let resumed = initial != LifecycleTopology::Empty;
        if let LifecycleTopology::Running { transit_id } = &initial {
            // A syntactically valid dynamic root is not sufficient evidence:
            // replay the durable ensure operations and bind every fixed CAS
            // artifact to its exact derivation and current Engine identities.
            let artifacts = derive_bootstrap_artifacts(&established)?;
            let control_id = engine
                .attest_lifecycle_service(
                    &established.installation,
                    &established.epoch,
                    &desired,
                    &rendered.expected,
                    "automata",
                )
                .await?;
            let relay_id = engine
                .attest_lifecycle_service(
                    &established.installation,
                    &established.epoch,
                    &desired,
                    &rendered.expected,
                    "engine-relay",
                )
                .await?;
            let runner_container_id = engine
                .attest_lifecycle_service(
                    &established.installation,
                    &established.epoch,
                    &desired,
                    &rendered.expected,
                    "runner",
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
            let runner_config = render_runner_config(
                &desired,
                &established.installation,
                artifacts.runner_id,
                transit_id,
                &control_id,
            )?;
            attest_exact_cas_material(
                &engine,
                &established,
                &artifacts,
                &relay,
                &runner_config,
                &relay_id,
                &runner_container_id,
                &mutation_fence,
            )
            .await?;
            // A running runner owns the TLS custody lock for its full
            // lifetime. Completion replay is therefore a read-only
            // attestation branch: it must never rerun enrollment or any other
            // mutating one-off beside the admitted steady services.
            attest_exact_cas_material(
                &engine,
                &established,
                &artifacts,
                &relay,
                &runner_config,
                &relay_id,
                &runner_container_id,
                &mutation_fence,
            )
            .await?;
            let repeated = engine
                .inspect_lifecycle_topology(
                    &established.installation,
                    &established.epoch,
                    &desired,
                    &rendered.expected,
                    expected_runner_id,
                )
                .await?;
            if repeated != initial {
                return Err(reset_required());
            }
            cancellation_checkpoint(&transaction_cancellation)?;
            return Ok((desired, resumed));
        }

        if initial == LifecycleTopology::Partial {
            // Partial exact topology is replaceable realized state, not a
            // durable phase journal. Quiesce admission, remove every attested
            // sibling, and converge from the canonical empty boundary while
            // preserving all twelve persistent volumes.
            cli.execute(
                selection,
                &established.installation,
                &rendered.compose_bytes,
                ComposeStep::StopRunner,
                &transaction_cancellation,
                &mutation_fence,
            )
            .await?;
            engine
                .remove_local_docker_children(
                    &established.installation,
                    &desired,
                    expected_runner_id,
                    &mutation_fence,
                )
                .await?;
            cli.execute(
                selection,
                &established.installation,
                &rendered.compose_bytes,
                ComposeStep::Down,
                &transaction_cancellation,
                &mutation_fence,
            )
            .await?;
            engine
                .remove_results_transit_if_present(
                    &established.installation,
                    &desired,
                    &mutation_fence,
                )
                .await?;
            if engine
                .inspect_lifecycle_topology(
                    &established.installation,
                    &established.epoch,
                    &desired,
                    &rendered.expected,
                    expected_runner_id,
                )
                .await?
                != LifecycleTopology::Empty
            {
                return Err(reset_required());
            }
            engine
                .preflight_lifecycle_volumes(&established.installation, &established.epoch)
                .await?;
            engine
                .attest_lifecycle_lock(&established.installation, &established.epoch, &holder)
                .await?;
        }

        cancellation_checkpoint(&transaction_cancellation)?;
        let transit_id = engine
            .ensure_results_transit(&established.installation, &desired, &mutation_fence)
            .await?;
        engine
            .attest_lifecycle_lock(&established.installation, &established.epoch, &holder)
            .await?;

        cli.execute(
            selection,
            &established.installation,
            &rendered.compose_bytes,
            ComposeStep::UpDependencies,
            &transaction_cancellation,
            &mutation_fence,
        )
        .await?;
        for service in ["postgres", "rustfs"] {
            engine
                .attest_lifecycle_service(
                    &established.installation,
                    &established.epoch,
                    &desired,
                    &rendered.expected,
                    service,
                )
                .await?;
        }
        engine
            .attest_lifecycle_lock(&established.installation, &established.epoch, &holder)
            .await?;

        let artifacts = derive_bootstrap_artifacts(&established)?;
        for (target, contents) in [
            (CasTarget::BootstrapRequest, artifacts.request.as_slice()),
            (CasTarget::BootstrapToken, artifacts.token.as_bytes()),
            (
                CasTarget::RunnerS3AccessKey,
                artifacts.s3_access_key.as_bytes(),
            ),
            (
                CasTarget::RunnerS3SecretKey,
                artifacts.s3_secret_key.as_bytes(),
            ),
            (
                CasTarget::RunnerS3Ca,
                established.certificates.ca_pem.as_bytes(),
            ),
            (CasTarget::RunnerSpoolKey, artifacts.spool_key.as_bytes()),
        ] {
            publish_cas(
                &engine,
                &established,
                target,
                contents,
                None,
                &mutation_fence,
            )
            .await?;
        }
        run_oneoff(
            &cli,
            selection,
            &engine,
            &established,
            &desired,
            &rendered.compose_bytes,
            &rendered.expected,
            "object-store-init",
            &transaction_cancellation,
            &mutation_fence,
        )
        .await?;
        run_oneoff(
            &cli,
            selection,
            &engine,
            &established,
            &desired,
            &rendered.compose_bytes,
            &rendered.expected,
            "bootstrap-runner",
            &transaction_cancellation,
            &mutation_fence,
        )
        .await?;
        engine
            .attest_lifecycle_lock(&established.installation, &established.epoch, &holder)
            .await?;

        cli.execute(
            selection,
            &established.installation,
            &rendered.compose_bytes,
            ComposeStep::UpControl,
            &transaction_cancellation,
            &mutation_fence,
        )
        .await?;
        let control_id = engine
            .attest_lifecycle_service(
                &established.installation,
                &established.epoch,
                &desired,
                &rendered.expected,
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
        publish_replaceable_cas(
            &engine,
            &established,
            CasTarget::RelayBinding,
            &relay,
            &mutation_fence,
        )
        .await?;
        let runner_config = render_runner_config(
            &desired,
            &established.installation,
            artifacts.runner_id,
            &transit_id,
            &control_id,
        )?;
        publish_replaceable_cas(
            &engine,
            &established,
            CasTarget::RunnerConfig,
            &runner_config,
            &mutation_fence,
        )
        .await?;
        engine
            .attest_lifecycle_lock(&established.installation, &established.epoch, &holder)
            .await?;

        run_oneoff(
            &cli,
            selection,
            &engine,
            &established,
            &desired,
            &rendered.compose_bytes,
            &rendered.expected,
            "runner-enroll",
            &transaction_cancellation,
            &mutation_fence,
        )
        .await?;
        cli.execute(
            selection,
            &established.installation,
            &rendered.compose_bytes,
            ComposeStep::UpRelay,
            &transaction_cancellation,
            &mutation_fence,
        )
        .await?;
        engine
            .attest_lifecycle_service(
                &established.installation,
                &established.epoch,
                &desired,
                &rendered.expected,
                "engine-relay",
            )
            .await?;
        cli.execute(
            selection,
            &established.installation,
            &rendered.compose_bytes,
            ComposeStep::UpRunner,
            &transaction_cancellation,
            &mutation_fence,
        )
        .await?;
        let expected_running = LifecycleTopology::Running {
            transit_id: transit_id.clone(),
        };
        let first_running = engine
            .inspect_lifecycle_topology(
                &established.installation,
                &established.epoch,
                &desired,
                &rendered.expected,
                expected_runner_id,
            )
            .await?;
        engine
            .preflight_lifecycle_volumes(&established.installation, &established.epoch)
            .await?;
        let repeated_running = engine
            .inspect_lifecycle_topology(
                &established.installation,
                &established.epoch,
                &desired,
                &rendered.expected,
                expected_runner_id,
            )
            .await?;
        if first_running != expected_running || repeated_running != expected_running {
            return Err(reset_required());
        }
        engine
            .attest_lifecycle_lock(&established.installation, &established.epoch, &holder)
            .await?;
        cancellation_checkpoint(&transaction_cancellation)?;
        Ok((desired, resumed))
    })
    .await;

    watcher.abort();
    let (desired, resumed) = match operation {
        Ok(value) => value,
        Err(error) => {
            // Dropping retained stdin converts the exact holder into sticky
            // stopped recovery evidence. We never claim that an accepted
            // daemon mutation was rolled back.
            drop(holder);
            return Err(error);
        }
    };
    engine
        .release_lifecycle_lock(&established.installation, &established.epoch, holder)
        .await?;
    engine
        .attest_lifecycle_lock_absent(&established.installation)
        .await?;
    let final_topology = engine
        .inspect_lifecycle_topology(
            &established.installation,
            &established.epoch,
            &desired,
            &rendered.expected,
            expected_runner_id,
        )
        .await?;
    if !matches!(final_topology, LifecycleTopology::Running { .. }) {
        return Err(reset_required());
    }
    engine
        .preflight_lifecycle_volumes(&established.installation, &established.epoch)
        .await?;
    if engine
        .inspect_lifecycle_topology(
            &established.installation,
            &established.epoch,
            &desired,
            &rendered.expected,
            expected_runner_id,
        )
        .await?
        != final_topology
    {
        return Err(reset_required());
    }
    Ok(LocalUpOutcome {
        installation: established.installation.name().clone(),
        plan_sha256: desired.plan_digest(),
        resumed,
    })
}

/// Converges one exact sealed installation to durable-down state while
/// preserving Desired, data, history, runner custody, and all sealed volumes.
///
/// # Errors
///
/// Fails closed for incomplete custody, topology drift, contention, or
/// caller/holder cancellation.
#[allow(clippy::too_many_lines)]
pub async fn down_local(request: LocalDownRequest) -> Result<LocalDownOutcome, LocalInitError> {
    let state = StateRoot::acquire_existing(&request.state_directory)?;
    let established = load_established_lifecycle(&state)?;
    cancellation_checkpoint(&request.cancellation)?;
    let report = inspect(DoctorRequest::new(EngineRequest::Docker)).await;
    let cli = QualifiedDockerCli::qualify(&report).await?;
    let selection = report.selected_engine().ok_or_else(engine_unavailable)?;
    let adapter = DockerInstallationAdapter::connect(&report)
        .await
        .map_err(super::map_engine_error)?;
    let engine = InitEngine::connect(&adapter).await?;
    engine.preflight_lifecycle_daemon().await?;
    engine
        .preflight_lifecycle_volumes(&established.installation, &established.epoch)
        .await?;
    let expected_desired = established.epoch.desired_spec()?;
    let rendered = render_compose(&expected_desired);
    let expected_runner_id = derive_bootstrap_artifacts(&established)?.runner_id;
    cli.validate(
        selection,
        &established.installation,
        &rendered.compose_bytes,
        &request.cancellation,
    )
    .await?;
    recover_stopped_lock_if_authorized(
        &engine,
        &established,
        &expected_desired,
        &rendered.expected,
        expected_runner_id,
        request.recover_stopped_lock,
        &request.cancellation,
    )
    .await?;
    cancellation_checkpoint(&request.cancellation)?;
    let holder = engine
        .acquire_lifecycle_lock(
            &established.installation,
            &established.epoch,
            OperationId::new(),
        )
        .await?;
    let (transaction_cancellation, watcher) = linked_cancellation(&request.cancellation, &holder);
    let mutation_fence = holder.mutation_fence(&request.cancellation);

    let operation = cancellation_bounded(&transaction_cancellation, async {
        engine
            .attest_lifecycle_lock(&established.installation, &established.epoch, &holder)
            .await?;
        engine
            .preflight_lifecycle_volumes(&established.installation, &established.epoch)
            .await?;
        engine
            .cleanup_lifecycle_disposable_helpers(
                &established.installation,
                &established.epoch,
                &expected_desired,
                &rendered.expected,
                derive_bootstrap_artifacts(&established)?.runner_id,
                &holder,
                &transaction_cancellation,
                &mutation_fence,
            )
            .await?;
        cli.validate(
            selection,
            &established.installation,
            &rendered.compose_bytes,
            &transaction_cancellation,
        )
        .await?;
        let initial = engine
            .inspect_lifecycle_topology(
                &established.installation,
                &established.epoch,
                &expected_desired,
                &rendered.expected,
                expected_runner_id,
            )
            .await?;
        let desired = load_sealed_desired(&engine, &established, &mutation_fence).await?;
        if desired != expected_desired {
            return Err(reset_required());
        }
        attest_sealed_material(
            &engine,
            &established,
            &desired,
            &transaction_cancellation,
            &mutation_fence,
        )
        .await?;
        if engine
            .inspect_lifecycle_topology(
                &established.installation,
                &established.epoch,
                &desired,
                &rendered.expected,
                expected_runner_id,
            )
            .await?
            != initial
        {
            return Err(reset_required());
        }
        engine
            .attest_lifecycle_lock(&established.installation, &established.epoch, &holder)
            .await?;
        let resumed = !matches!(initial, LifecycleTopology::Running { .. });
        if initial == LifecycleTopology::Empty {
            return Ok((desired, true));
        }

        // Stop the scheduler-facing runner before installation-wide sibling
        // cleanup so no new LocalDocker child can be admitted.
        cli.execute(
            selection,
            &established.installation,
            &rendered.compose_bytes,
            ComposeStep::StopRunner,
            &transaction_cancellation,
            &mutation_fence,
        )
        .await?;
        engine
            .attest_lifecycle_lock(&established.installation, &established.epoch, &holder)
            .await?;
        engine
            .remove_local_docker_children(
                &established.installation,
                &desired,
                expected_runner_id,
                &mutation_fence,
            )
            .await?;
        cli.execute(
            selection,
            &established.installation,
            &rendered.compose_bytes,
            ComposeStep::Down,
            &transaction_cancellation,
            &mutation_fence,
        )
        .await?;
        engine
            .attest_lifecycle_lock(&established.installation, &established.epoch, &holder)
            .await?;
        engine
            .remove_results_transit_if_present(&established.installation, &desired, &mutation_fence)
            .await?;
        let final_empty = engine
            .inspect_lifecycle_topology(
                &established.installation,
                &established.epoch,
                &desired,
                &rendered.expected,
                expected_runner_id,
            )
            .await?;
        if final_empty != LifecycleTopology::Empty {
            return Err(reset_required());
        }
        engine
            .preflight_lifecycle_volumes(&established.installation, &established.epoch)
            .await?;
        if engine
            .inspect_lifecycle_topology(
                &established.installation,
                &established.epoch,
                &desired,
                &rendered.expected,
                expected_runner_id,
            )
            .await?
            != final_empty
        {
            return Err(reset_required());
        }
        cancellation_checkpoint(&transaction_cancellation)?;
        Ok((desired, resumed))
    })
    .await;

    watcher.abort();
    let (desired, resumed) = match operation {
        Ok(value) => value,
        Err(error) => {
            drop(holder);
            return Err(error);
        }
    };
    engine
        .release_lifecycle_lock(&established.installation, &established.epoch, holder)
        .await?;
    engine
        .attest_lifecycle_lock_absent(&established.installation)
        .await?;
    let final_empty = engine
        .inspect_lifecycle_topology(
            &established.installation,
            &established.epoch,
            &desired,
            &rendered.expected,
            expected_runner_id,
        )
        .await?;
    if final_empty != LifecycleTopology::Empty {
        return Err(reset_required());
    }
    engine
        .preflight_lifecycle_volumes(&established.installation, &established.epoch)
        .await?;
    if engine
        .inspect_lifecycle_topology(
            &established.installation,
            &established.epoch,
            &desired,
            &rendered.expected,
            expected_runner_id,
        )
        .await?
        != final_empty
    {
        return Err(reset_required());
    }
    Ok(LocalDownOutcome {
        installation: established.installation.name().clone(),
        plan_sha256: desired.plan_digest(),
        resumed,
    })
}

async fn recover_stopped_lock_if_authorized(
    engine: &InitEngine<'_>,
    established: &EstablishedLifecycle,
    desired: &DesiredSpec,
    expected: &super::renderer::ExpectedLifecycleTopology,
    expected_runner_id: uuid::Uuid,
    authorized: bool,
    cancellation: &CancellationToken,
) -> Result<(), LocalInitError> {
    match engine
        .inspect_lifecycle_lock(&established.installation, &established.epoch)
        .await?
    {
        LifecycleLockObservation::Absent => Ok(()),
        LifecycleLockObservation::Live { .. } => {
            Err(LocalInitError::new(LocalInitErrorCode::OperationInProgress))
        }
        LifecycleLockObservation::Stopped { .. } if !authorized => Err(reset_required()),
        LifecycleLockObservation::Stopped { id, .. } => {
            cancellation_checkpoint(cancellation)?;
            engine
                .recover_stopped_lifecycle_lock(
                    &established.installation,
                    &established.epoch,
                    desired,
                    expected,
                    expected_runner_id,
                    &id,
                    cancellation,
                )
                .await?;
            Ok(())
        }
    }
}

fn load_established_lifecycle(state: &StateRoot) -> Result<EstablishedLifecycle, LocalInitError> {
    if state.observe_reset_intent_for_reset()?.present() {
        return Err(reset_required());
    }
    let snapshot = state.snapshot_read_only()?;
    if snapshot.reset_intent.is_some() {
        return Err(reset_required());
    }
    let established = validate_established_lifecycle(state, &snapshot)?;
    established.epoch.require_current_lifecycle_contract()?;
    Ok(established)
}

async fn load_sealed_desired(
    engine: &InitEngine<'_>,
    established: &EstablishedLifecycle,
    mutation: &LifecycleMutationFence,
) -> Result<DesiredSpec, LocalInitError> {
    let desired_bytes = engine
        .read_sealed_desired(&established.installation, &established.epoch, mutation)
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

async fn attest_sealed_material(
    engine: &InitEngine<'_>,
    established: &EstablishedLifecycle,
    desired: &DesiredSpec,
    cancellation: &CancellationToken,
    mutation: &LifecycleMutationFence,
) -> Result<(), LocalInitError> {
    let deriver = MaterialDeriver::new(
        *established.material_root,
        &established.installation,
        &established.epoch,
    );
    let request = MaterializeRequest::build(
        &established.epoch,
        &deriver,
        &established.certificates,
        &desired.canonical_bytes(),
        false,
    );
    engine
        .attest_materialized_volumes(
            &established.installation,
            &established.epoch,
            &request,
            cancellation,
            mutation,
        )
        .await
}

async fn publish_cas(
    engine: &InitEngine<'_>,
    established: &EstablishedLifecycle,
    target: CasTarget,
    contents: &[u8],
    expected: Option<Sha256Digest>,
    mutation: &LifecycleMutationFence,
) -> Result<Sha256Digest, LocalInitError> {
    let request = CasRequest::new(target, expected, contents)?;
    engine
        .apply_lifecycle_cas(
            &established.installation,
            &established.epoch,
            &request,
            mutation,
        )
        .await
}

async fn publish_replaceable_cas(
    engine: &InitEngine<'_>,
    established: &EstablishedLifecycle,
    target: CasTarget,
    contents: &[u8],
    mutation: &LifecycleMutationFence,
) -> Result<Sha256Digest, LocalInitError> {
    let expected = engine
        .read_lifecycle_cas_digest(
            &established.installation,
            &established.epoch,
            target,
            mutation,
        )
        .await?;
    publish_cas(engine, established, target, contents, expected, mutation).await
}

async fn attest_exact_cas_material(
    engine: &InitEngine<'_>,
    established: &EstablishedLifecycle,
    artifacts: &BootstrapArtifacts,
    relay: &[u8],
    runner_config: &[u8],
    relay_id: &str,
    runner_id: &str,
    mutation: &LifecycleMutationFence,
) -> Result<(), LocalInitError> {
    for (target, contents) in [
        (CasTarget::BootstrapRequest, artifacts.request.as_slice()),
        (CasTarget::BootstrapToken, artifacts.token.as_bytes()),
        (CasTarget::RelayBinding, relay),
        (CasTarget::RunnerConfig, runner_config),
        (
            CasTarget::RunnerS3AccessKey,
            artifacts.s3_access_key.as_bytes(),
        ),
        (
            CasTarget::RunnerS3Ca,
            established.certificates.ca_pem.as_bytes(),
        ),
        (
            CasTarget::RunnerS3SecretKey,
            artifacts.s3_secret_key.as_bytes(),
        ),
        (CasTarget::RunnerSpoolKey, artifacts.spool_key.as_bytes()),
    ] {
        let expected = Sha256Digest::from_bytes(Sha256::digest(contents).into());
        let expected_attachments = match target {
            CasTarget::BootstrapRequest | CasTarget::BootstrapToken => BTreeSet::new(),
            CasTarget::RelayBinding => BTreeSet::from([relay_id.to_owned()]),
            CasTarget::RunnerConfig
            | CasTarget::RunnerS3AccessKey
            | CasTarget::RunnerS3Ca
            | CasTarget::RunnerS3SecretKey
            | CasTarget::RunnerSpoolKey => BTreeSet::from([runner_id.to_owned()]),
        };
        if engine
            .read_lifecycle_cas_digest_with_attachments(
                &established.installation,
                &established.epoch,
                target,
                &expected_attachments,
                mutation,
            )
            .await?
            != Some(expected)
        {
            return Err(reset_required());
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_oneoff(
    cli: &QualifiedDockerCli,
    selection: &crate::EngineSelection,
    engine: &InitEngine<'_>,
    established: &EstablishedLifecycle,
    desired: &DesiredSpec,
    compose_bytes: &[u8],
    expected: &super::renderer::ExpectedLifecycleTopology,
    service: &'static str,
    cancellation: &CancellationToken,
    mutation: &LifecycleMutationFence,
) -> Result<(), LocalInitError> {
    engine
        .reconcile_lifecycle_oneoff(
            &established.installation,
            &established.epoch,
            desired,
            expected,
            service,
            mutation,
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
        cancellation,
        mutation,
    )
    .await?;
    engine
        .finish_lifecycle_oneoff(
            &established.installation,
            &established.epoch,
            desired,
            expected,
            service,
            mutation,
        )
        .await?;
    Ok(())
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
        || snapshot.reset_intent.is_some()
    {
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

pub(super) fn linked_cancellation(
    caller: &CancellationToken,
    holder: &LifecycleLockHolder,
) -> (CancellationToken, JoinHandle<()>) {
    let linked = CancellationToken::new();
    let child = linked.clone();
    let caller = caller.clone();
    let holder_lost = holder.holder_lost();
    let watcher = tokio::spawn(async move {
        tokio::select! {
            () = caller.cancelled() => {}
            () = holder_lost.cancelled() => {}
        }
        child.cancel();
    });
    (linked, watcher)
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

async fn cancellation_bounded<T>(
    cancellation: &CancellationToken,
    operation: impl Future<Output = Result<T, LocalInitError>>,
) -> Result<T, LocalInitError> {
    cancellation_checkpoint(cancellation)?;
    tokio::pin!(operation);
    tokio::select! {
        biased;
        result = &mut operation => result,
        () = cancellation.cancelled() => {
            Err(LocalInitError::new(LocalInitErrorCode::Cancelled))
        }
    }
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, LocalInitError> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| reset_required())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn engine_unavailable() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::EngineUnavailable)
}

fn reset_required() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::ResetRequired)
}

#[cfg(test)]
mod tests;
