use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    future::Future,
    io::{ErrorKind, IoSliceMut, Read as _, Write as _},
    mem::MaybeUninit,
    os::unix::net::UnixStream,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use automata_ci_core::{OperationId, Sha256Digest};
use bollard::{
    Docker,
    container::{AttachContainerResults, LogOutput},
    models::{
        ContainerCreateBody, ContainerSummary, EventMessage, EventMessageTypeEnum, HostConfig,
        HostConfigCgroupnsModeEnum, HostConfigIsolationEnum, ImageConfig, Ipam, IpamConfig, Mount,
        MountBindOptionsPropagationEnum, MountType, MountVolumeOptions, Network,
        NetworkCreateRequest, NetworkInspect, RestartPolicy, RestartPolicyNameEnum,
    },
    query_parameters::{
        AttachContainerOptionsBuilder, CreateContainerOptionsBuilder, ListContainersOptionsBuilder,
        ListNetworksOptionsBuilder, ListVolumesOptionsBuilder, LogsOptionsBuilder,
        RemoveContainerOptionsBuilder, WaitContainerOptionsBuilder,
    },
};
use bytes::Bytes;
use futures::{Stream, StreamExt as _};
use http_body_util::{BodyExt as _, Empty};
use hyper::{Request, StatusCode, client::conn::http1};
use hyper_util::rt::TokioIo;
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SocketAddrUnix,
    SocketFlags, SocketType,
};
use serde::Deserialize;
use tokio::{
    io::{AsyncWrite, AsyncWriteExt as _},
    net::UnixStream as TokioUnixStream,
    sync::{Mutex, OwnedMutexGuard, mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    DesiredSpec, Installation, MAX_LOCAL_DESIRED_SPEC_BYTES,
    lifecycle_helper::{CasDigestRequest, CasDigestResponse, CasRequest, CasTarget},
    local_docker::{
        LifecycleSiblingContainer, LifecycleSiblingNetwork, attest_lifecycle_sibling_custody_union,
        attest_lifecycle_sibling_union,
    },
    results_transport::{
        RESULTS_TRANSIT_GATEWAY_MODE_KEY, RESULTS_TRANSIT_GATEWAY_MODE_VALUE,
        ResultsTransitNetworkShape, exact_results_transit_base, results_transit_labels,
        results_transit_name,
    },
};

use super::{
    ENGINE_TIMEOUT, HELPER_MEMORY_BYTES, HELPER_NANO_CPUS, HELPER_PIDS, HELPER_SHM_BYTES,
    HELPER_TIMEOUT, HelperDriver, InitEngine, LIFECYCLE_ATTESTER_KIND, MAX_ENGINE_RESOURCES,
    SealedEngineStatus, SealedImageStatus, SealedVolumeStatus, engine_resource_mismatch,
    engine_unavailable, exact_container_id, exact_container_id_text, helper_has_ambient_authority,
    helper_log_config, helper_masked_paths, helper_mounts_match, helper_readonly_paths,
    helper_security_options, lifecycle_material_attester_labels, lifecycle_material_attester_name,
    not_found, reset_progress_from_presence, reset_volume_order, validate_helper, validate_volume,
    volume_name, volume_names,
};
use crate::init::{
    LocalInitError, LocalInitErrorCode,
    epoch::ImmutableEpoch,
    materializer::VolumeRole,
    renderer::{
        ExpectedContainer, ExpectedLifecycleTopology, ExpectedMountSource, ExpectedNetwork,
    },
};

const LOCK_KIND: &str = "lifecycle-lock";

const LABEL_MANAGED: &str = "io.automata.local.managed";
const LABEL_INSTALLATION_ID: &str = "io.automata.local.installation-id";
const LABEL_INSTALLATION_KEY: &str = "io.automata.local.installation-key";
const LABEL_COMPOSE_PROJECT: &str = "io.automata.local.compose-project";
const LABEL_EPOCH: &str = "io.automata.local.epoch-fingerprint";
const LABEL_PLAN: &str = "io.automata.local.plan-digest";
const LABEL_RESOURCE_KIND: &str = "io.automata.local.resource-kind";
const LABEL_OPERATION_ID: &str = "io.automata.local.lifecycle-operation-id";
const LABEL_ENGINE_BOOT_ID: &str = "io.automata.local.engine-boot-id";
const LABEL_ENGINE_PID: &str = "io.automata.local.engine-pid";
const LABEL_ENGINE_START_TICKS: &str = "io.automata.local.engine-start-ticks";
const DESIRED_READER_KIND: &str = "lifecycle-desired-reader";
const CAS_WRITER_KIND: &str = "lifecycle-cas-writer";
const CAS_DIGEST_READER_KIND: &str = "lifecycle-cas-digest-reader";
const CAS_MOUNT: &str = "/run/automata-lifecycle-cas";
const MAX_ONEOFF_LOG_BYTES: usize = 64 * 1024;
const RECOVERY_ENGINE_QUIET_PERIOD: Duration = Duration::from_secs(2);
const RECOVERY_ENGINE_QUIET_DEADLINE: Duration = Duration::from_secs(30);
const ENGINE_GENERATION_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const ENGINE_GENERATION_RESPONSE_MAXIMUM_BYTES: usize = 4096;
const ENGINE_GENERATION_REQUEST: &[u8] =
    b"GET /_ping HTTP/1.0\r\nHost: docker\r\nConnection: close\r\n\r\n";
const RECOVERY_EVENT_URI: &str = "/v1.48/events?since=1";
const RECOVERY_EVENT_MAXIMUM_BYTES: usize = 64 * 1024;
const RECOVERY_EVENT_CHUNK_MAXIMUM_BYTES: usize = 256 * 1024;
const ENGINE_INFO_URI: &str = "/v1.48/info";
const ENGINE_INFO_MAXIMUM_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
struct LifecycleDaemonInfo {
    #[serde(rename = "SecurityOptions", default)]
    security_options: Vec<String>,
    #[serde(rename = "MemoryLimit")]
    memory_limit: bool,
    #[serde(rename = "SwapLimit")]
    swap_limit: bool,
    #[serde(rename = "CpuCfsPeriod")]
    cpu_cfs_period: bool,
    #[serde(rename = "CpuCfsQuota")]
    cpu_cfs_quota: bool,
    #[serde(rename = "PidsLimit")]
    pids_limit: bool,
    #[serde(rename = "CgroupVersion")]
    cgroup_version: String,
    #[serde(rename = "LiveRestoreEnabled")]
    live_restore_enabled: bool,
    #[serde(rename = "DefaultRuntime")]
    default_runtime: String,
    #[serde(rename = "DefaultUlimits", default)]
    default_ulimits: Option<HashMap<String, serde_json::Value>>,
}

/// Read-only classification of the deterministic Engine mutation lock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::init) enum LifecycleLockObservation {
    Absent,
    Live {
        id: String,
        operation_id: OperationId,
    },
    Stopped {
        id: String,
        operation_id: OperationId,
    },
}

/// Retained stdin authority for one exact live Engine mutation lock.
///
/// Dropping this value closes stdin and intentionally leaves the resulting
/// stopped container as sticky recovery evidence. Only `release_lifecycle_lock`
/// performs graceful exact-ID removal.
pub(in crate::init) struct LifecycleLockHolder {
    name: String,
    id: String,
    operation_id: OperationId,
    labels: BTreeMap<String, String>,
    daemon_generation: EngineDaemonGeneration,
    input: Option<Pin<Box<dyn AsyncWrite + Send>>>,
    holder_lost: CancellationToken,
    commands: mpsc::Sender<LifecycleLockCommand>,
    mutation_gate: Arc<Mutex<LifecycleMutationGateState>>,
    monitor: JoinHandle<Result<(), LocalInitError>>,
}

enum LifecycleLockCommand {
    AuthorizeMutation(oneshot::Sender<()>),
    BeginRelease {
        acknowledged: oneshot::Sender<()>,
        frame_sent: oneshot::Receiver<()>,
    },
}

/// One live holder's mandatory per-request mutation capability.
///
/// The attach monitor acknowledges each request boundary only while the
/// holder stream is still pending. Holder loss dominates caller cancellation;
/// after either signal no later Engine or Compose mutation can obtain a
/// permit.
#[derive(Clone)]
pub(in crate::init) struct LifecycleMutationFence {
    commands: mpsc::Sender<LifecycleLockCommand>,
    holder_lost: CancellationToken,
    caller: CancellationToken,
    gate: Arc<Mutex<LifecycleMutationGateState>>,
}

#[derive(Debug, Default)]
struct LifecycleMutationGateState {
    closed: bool,
}

#[must_use = "the lifecycle mutation permit must be retained through the Engine request"]
struct LifecycleMutationPermit {
    _gate: OwnedMutexGuard<LifecycleMutationGateState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EngineDaemonGeneration {
    boot_id: uuid::Uuid,
    pid: u32,
    start_ticks: u64,
}

enum RecoveryEventSignal {
    Event(EventMessage),
    Failed,
}

/// One fixed-socket event subscription spanning an exceptional stopped-lock
/// recovery from its first census through the exact destroy/absence proof.
///
/// The subscription starts at the daemon's bounded history (`since=1`). Once
/// the HTTP response headers arrive, Moby's atomic history/live registration
/// makes every event in the header-to-subscribe interval replayable. The exact
/// destroy event is the trailing catch-up barrier for all earlier activity.
struct RecoveryEventFence {
    events: mpsc::Receiver<RecoveryEventSignal>,
    parser: JoinHandle<()>,
    connection: JoinHandle<()>,
    stopped_generation: EngineDaemonGeneration,
    replacement_generation: EngineDaemonGeneration,
    cancellation: Option<CancellationToken>,
}

impl Drop for RecoveryEventFence {
    fn drop(&mut self) {
        self.parser.abort();
        self.connection.abort();
    }
}

impl LifecycleLockHolder {
    /// Cancels as soon as the retained attach stream ends unexpectedly.
    pub(in crate::init) fn holder_lost(&self) -> CancellationToken {
        self.holder_lost.clone()
    }

    pub(in crate::init) fn exact_identity(&self) -> (&str, &str) {
        (&self.name, &self.id)
    }

    pub(in crate::init) fn mutation_fence(
        &self,
        caller: &CancellationToken,
    ) -> LifecycleMutationFence {
        LifecycleMutationFence {
            commands: self.commands.clone(),
            holder_lost: self.holder_lost.clone(),
            caller: caller.clone(),
            gate: Arc::clone(&self.mutation_gate),
        }
    }
}

impl LifecycleMutationFence {
    pub(in crate::init) fn checkpoint(&self) -> Result<(), LocalInitError> {
        if self.holder_lost.is_cancelled() {
            Err(LocalInitError::new(LocalInitErrorCode::ResetRequired))
        } else if self.caller.is_cancelled() {
            Err(LocalInitError::new(LocalInitErrorCode::Cancelled))
        } else {
            Ok(())
        }
    }

    async fn authorize(&self) -> Result<LifecycleMutationPermit, LocalInitError> {
        self.checkpoint()?;
        let gate = tokio::select! {
            biased;
            () = self.holder_lost.cancelled() => {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
            () = self.caller.cancelled() => {
                return Err(LocalInitError::new(LocalInitErrorCode::Cancelled));
            }
            gate = Arc::clone(&self.gate).lock_owned() => gate,
        };
        if gate.closed {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        let (acknowledge, acknowledged) = oneshot::channel();
        tokio::select! {
            biased;
            () = self.holder_lost.cancelled() => {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
            () = self.caller.cancelled() => {
                return Err(LocalInitError::new(LocalInitErrorCode::Cancelled));
            }
            result = self.commands.send(LifecycleLockCommand::AuthorizeMutation(acknowledge)) => {
                result.map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
            }
        }
        tokio::select! {
            biased;
            () = self.holder_lost.cancelled() => {
                Err(LocalInitError::new(LocalInitErrorCode::ResetRequired))
            }
            () = self.caller.cancelled() => {
                Err(LocalInitError::new(LocalInitErrorCode::Cancelled))
            }
            result = acknowledged => {
                result.map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
                Ok(LifecycleMutationPermit { _gate: gate })
            }
        }
    }

    /// Runs one Engine or Compose mutation while holding the single in-flight
    /// permit authorized by the retained lock-output monitor.
    pub(in crate::init) async fn run<Mutation, Output>(
        &self,
        mutation: Mutation,
    ) -> Result<Output, LocalInitError>
    where
        Mutation: Future<Output = Output>,
    {
        let _permit = self.authorize().await?;
        Ok(mutation.await)
    }
}

async fn monitor_lifecycle_lock_output<Output>(
    mut output: Output,
    mut command_requests: mpsc::Receiver<LifecycleLockCommand>,
    holder_lost: CancellationToken,
) -> Result<(), LocalInitError>
where
    Output: Stream + Unpin,
{
    loop {
        let command = tokio::select! {
            biased;
            _unexpected = output.next() => {
                holder_lost.cancel();
                return Err(engine_resource_mismatch());
            }
            command = command_requests.recv() => {
                command.ok_or_else(engine_resource_mismatch)?
            }
        };
        match command {
            LifecycleLockCommand::AuthorizeMutation(acknowledge) => {
                let _ = acknowledge.send(());
            }
            LifecycleLockCommand::BeginRelease {
                acknowledged,
                mut frame_sent,
            } => {
                acknowledged
                    .send(())
                    .map_err(|()| engine_resource_mismatch())?;
                tokio::select! {
                    biased;
                    observed = output.next() => {
                        if observed.is_some() {
                            holder_lost.cancel();
                            return Err(engine_resource_mismatch());
                        }
                        if frame_sent.await.is_err() {
                            holder_lost.cancel();
                            return Err(engine_resource_mismatch());
                        }
                        return Ok(());
                    }
                    confirmation = &mut frame_sent => {
                        if confirmation.is_err() {
                            holder_lost.cancel();
                            return Err(engine_resource_mismatch());
                        }
                    }
                }
                return match output.next().await {
                    None => Ok(()),
                    Some(_) => {
                        holder_lost.cancel();
                        Err(engine_resource_mismatch())
                    }
                };
            }
        }
    }
}

impl RecoveryEventFence {
    async fn open(
        stopped_generation: EngineDaemonGeneration,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, LocalInitError> {
        if let Some(cancellation) = cancellation {
            lifecycle_cancellation_checkpoint(cancellation)?;
        }
        prove_daemon_generation_absent(&stopped_generation)?;
        let replacement_generation = current_engine_daemon_generation()?;
        validate_replacement_daemon_generation(
            &stopped_generation,
            &replacement_generation,
            &replacement_generation,
        )?;

        let stream = TokioUnixStream::connect("/var/run/docker.sock")
            .await
            .map_err(|_| engine_unavailable())?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| engine_unavailable())?;
        let connection = tokio::spawn(async move {
            let _closed = connection.await;
        });
        let request = Request::builder()
            .method("GET")
            .uri(RECOVERY_EVENT_URI)
            .header("host", "docker")
            .header("connection", "close")
            .body(Empty::<Bytes>::new())
            .map_err(|_| engine_unavailable())?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| engine_unavailable())?;
        if response.status() != StatusCode::OK
            || response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .is_none_or(|value| !value.starts_with("application/json"))
        {
            return Err(engine_unavailable());
        }
        drop(sender);

        let (event_sender, events) = mpsc::channel(1);
        let parser = tokio::spawn(forward_recovery_events(response.into_body(), event_sender));
        let mut fence = Self {
            events,
            parser,
            connection,
            stopped_generation,
            replacement_generation,
            cancellation: cancellation.cloned(),
        };
        fence.await_initial_quiet().await?;
        fence.verify_generation()?;
        Ok(fence)
    }

    async fn await_initial_quiet(&mut self) -> Result<(), LocalInitError> {
        let started = tokio::time::Instant::now();
        let mut quiet = Box::pin(tokio::time::sleep(RECOVERY_ENGINE_QUIET_PERIOD));
        let mut deadline = Box::pin(tokio::time::sleep_until(
            started + RECOVERY_ENGINE_QUIET_DEADLINE,
        ));
        loop {
            tokio::select! {
                biased;
                signal = self.events.recv() => match signal {
                    Some(RecoveryEventSignal::Event(_)) => quiet.as_mut().reset(
                        tokio::time::Instant::now() + RECOVERY_ENGINE_QUIET_PERIOD,
                    ),
                    Some(RecoveryEventSignal::Failed) | None => return Err(engine_unavailable()),
                },
                () = recovery_cancellation(self.cancellation.as_ref()) => {
                    return Err(LocalInitError::new(LocalInitErrorCode::Cancelled));
                }
                () = &mut deadline => {
                    return Err(LocalInitError::new(LocalInitErrorCode::OperationInProgress));
                }
                () = &mut quiet => return Ok(()),
            }
        }
    }

    async fn guard<T>(
        &mut self,
        operation: impl std::future::Future<Output = Result<T, LocalInitError>>,
    ) -> Result<T, LocalInitError> {
        tokio::pin!(operation);
        tokio::select! {
            biased;
            signal = self.events.recv() => match signal {
                Some(RecoveryEventSignal::Event(_)) => {
                    Err(LocalInitError::new(LocalInitErrorCode::OperationInProgress))
                }
                Some(RecoveryEventSignal::Failed) | None => Err(engine_unavailable()),
            },
            () = recovery_cancellation(self.cancellation.as_ref()) => {
                Err(LocalInitError::new(LocalInitErrorCode::Cancelled))
            }
            result = &mut operation => result,
        }
    }

    async fn delete_exact_container(
        &mut self,
        docker: &Docker,
        expected_id: &str,
    ) -> Result<bool, LocalInitError> {
        if !exact_container_id_text(expected_id) {
            return Err(engine_resource_mismatch());
        }
        if self
            .cancellation
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            return Err(LocalInitError::new(LocalInitErrorCode::Cancelled));
        }
        self.verify_generation()?;
        let options = RemoveContainerOptionsBuilder::default()
            .force(false)
            .v(false)
            .link(false)
            .build();
        let removal = tokio::time::timeout(
            ENGINE_TIMEOUT,
            docker.remove_container(expected_id, Some(options)),
        );
        tokio::pin!(removal);
        let mut removal_complete = false;
        let mut deadline = Box::pin(tokio::time::sleep(ENGINE_TIMEOUT));
        loop {
            tokio::select! {
                biased;
                signal = self.events.recv() => match signal {
                    Some(RecoveryEventSignal::Event(event))
                        if exact_destroy_event(&event, expected_id) => break,
                    Some(RecoveryEventSignal::Event(_)) => {
                        return Err(LocalInitError::new(LocalInitErrorCode::OperationInProgress));
                    }
                    Some(RecoveryEventSignal::Failed) | None => return Err(engine_unavailable()),
                },
                _untrusted = &mut removal, if !removal_complete => {
                    removal_complete = true;
                }
                () = &mut deadline => return Err(engine_resource_mismatch()),
            }
        }
        Ok(self
            .cancellation
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled))
    }

    fn verify_generation(&self) -> Result<(), LocalInitError> {
        let repeated = current_engine_daemon_generation()?;
        validate_replacement_daemon_generation(
            &self.stopped_generation,
            &self.replacement_generation,
            &repeated,
        )?;
        prove_daemon_generation_absent(&self.stopped_generation)
    }
}

async fn recovery_cancellation(cancellation: Option<&CancellationToken>) {
    match cancellation {
        Some(cancellation) => cancellation.cancelled().await,
        None => std::future::pending().await,
    }
}

async fn forward_recovery_events(
    mut body: hyper::body::Incoming,
    sender: mpsc::Sender<RecoveryEventSignal>,
) {
    let mut buffered = Vec::new();
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            let _ = sender.send(RecoveryEventSignal::Failed).await;
            return;
        };
        let Ok(data) = frame.into_data() else {
            let _ = sender.send(RecoveryEventSignal::Failed).await;
            return;
        };
        if data.len() > RECOVERY_EVENT_CHUNK_MAXIMUM_BYTES {
            let _ = sender.send(RecoveryEventSignal::Failed).await;
            return;
        }
        buffered.extend_from_slice(&data);
        while let Some(newline) = buffered.iter().position(|byte| *byte == b'\n') {
            let line = buffered.drain(..=newline).collect::<Vec<_>>();
            let payload = &line[..line.len().saturating_sub(1)];
            if payload.is_empty() || payload.len() > RECOVERY_EVENT_MAXIMUM_BYTES {
                let _ = sender.send(RecoveryEventSignal::Failed).await;
                return;
            }
            let Ok(event) = serde_json::from_slice(payload) else {
                let _ = sender.send(RecoveryEventSignal::Failed).await;
                return;
            };
            if sender
                .send(RecoveryEventSignal::Event(event))
                .await
                .is_err()
            {
                return;
            }
        }
        if buffered.len() > RECOVERY_EVENT_MAXIMUM_BYTES {
            let _ = sender.send(RecoveryEventSignal::Failed).await;
            return;
        }
    }
    let _ = sender.send(RecoveryEventSignal::Failed).await;
}

fn exact_destroy_event(event: &EventMessage, expected_id: &str) -> bool {
    event.typ == Some(EventMessageTypeEnum::CONTAINER)
        && event.action.as_deref() == Some("destroy")
        && event.actor.as_ref().and_then(|actor| actor.id.as_deref()) == Some(expected_id)
}

async fn load_lifecycle_daemon_info() -> Result<LifecycleDaemonInfo, LocalInitError> {
    tokio::time::timeout(ENGINE_TIMEOUT, async {
        let stream = TokioUnixStream::connect("/var/run/docker.sock")
            .await
            .map_err(|_| engine_unavailable())?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| engine_unavailable())?;
        let connection = tokio::spawn(async move {
            let _closed = connection.await;
        });
        let request = Request::builder()
            .method("GET")
            .uri(ENGINE_INFO_URI)
            .header("host", "docker")
            .header("connection", "close")
            .body(Empty::<Bytes>::new())
            .map_err(|_| engine_unavailable())?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| engine_unavailable())?;
        if response.status() != StatusCode::OK
            || response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .is_none_or(|value| !value.starts_with("application/json"))
        {
            return Err(engine_unavailable());
        }
        drop(sender);
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let data = frame
                .map_err(|_| engine_unavailable())?
                .into_data()
                .map_err(|_| engine_unavailable())?;
            if data.len() > ENGINE_INFO_MAXIMUM_BYTES.saturating_sub(bytes.len()) {
                return Err(engine_unavailable());
            }
            bytes.extend_from_slice(&data);
        }
        connection.abort();
        serde_json::from_slice(&bytes).map_err(|_| engine_unavailable())
    })
    .await
    .map_err(|_| engine_unavailable())?
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::init) enum LifecycleTopology {
    Empty,
    Partial,
    Running { transit_id: String },
}

impl InitEngine<'_> {
    /// Qualifies daemon-wide defaults that cannot be overridden safely by the
    /// closed lifecycle topology. This runs before any lifecycle mutation.
    pub(in crate::init) async fn preflight_lifecycle_daemon(&self) -> Result<(), LocalInitError> {
        self.verify_selected_engine().await?;
        let info = load_lifecycle_daemon_info().await?;
        validate_lifecycle_daemon_info(&info)?;
        self.verify_selected_engine().await
    }

    async fn inspect_rendered_live_ids(
        &self,
        installation: &Installation,
        expected: &ExpectedLifecycleTopology,
    ) -> Result<RenderedLiveIds, LocalInitError> {
        let containers = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.list_containers(Some(
                ListContainersOptionsBuilder::default().all(true).build(),
            )),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        let networks = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker
                .list_networks(Some(ListNetworksOptionsBuilder::default().build())),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if containers.len() > MAX_ENGINE_RESOURCES || networks.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        derive_rendered_live_ids(&containers, &networks, installation, expected)
    }

    async fn attest_namespace_attachment_union(
        &self,
        listed: &[ContainerSummary],
        installation: &Installation,
        expected: &ExpectedLifecycleTopology,
        lifecycle_ids: &BTreeMap<String, String>,
        live_ids: &RenderedLiveIds,
    ) -> Result<(), LocalInitError> {
        let runner_enroll = expected
            .containers
            .get("runner-enroll")
            .filter(|container| container.network_mode.as_deref() == Some("service:automata"))
            .map(|_| format!("{}-runner-enroll", installation.compose_project()))
            .ok_or_else(engine_resource_mismatch)?;
        for summary in listed {
            let id = summary
                .id
                .as_deref()
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?;
            let container = self
                .inspect_container(id)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            let source_name = container
                .name
                .as_deref()
                .and_then(|name| name.strip_prefix('/'))
                .ok_or_else(engine_resource_mismatch)?;
            let host = container
                .host_config
                .as_ref()
                .ok_or_else(engine_resource_mismatch)?;
            for (namespace, mode) in [
                ("network", host.network_mode.as_deref()),
                ("pid", host.pid_mode.as_deref()),
                ("ipc", host.ipc_mode.as_deref()),
            ] {
                let Some(target) = mode.and_then(|mode| mode.strip_prefix("container:")) else {
                    continue;
                };
                let targets_lifecycle = lifecycle_ids
                    .iter()
                    .any(|(name, id)| target == name || target == id);
                if !targets_lifecycle {
                    continue;
                }
                let allowed = namespace == "network"
                    && source_name == runner_enroll
                    && live_ids.control.as_deref() == Some(target);
                if !allowed {
                    return Err(engine_resource_mismatch());
                }
            }
        }
        Ok(())
    }

    async fn begin_stopped_lock_recovery_event_fence(
        &self,
        stopped_lock_id: &str,
        cancellation: Option<&CancellationToken>,
    ) -> Result<RecoveryEventFence, LocalInitError> {
        if !exact_container_id_text(stopped_lock_id) {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await?;
        let stopped = self
            .inspect_container(stopped_lock_id)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        if stopped.state.as_ref().and_then(|state| state.running) != Some(false) {
            return Err(engine_resource_mismatch());
        }
        let labels = stopped
            .config
            .as_ref()
            .and_then(|config| config.labels.as_ref())
            .ok_or_else(engine_resource_mismatch)?;
        let labels = labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<BTreeMap<_, _>>();
        let stopped_generation = daemon_generation_from_labels(&labels)?;
        let mut fence = RecoveryEventFence::open(stopped_generation, cancellation).await?;
        fence.guard(self.verify_selected_engine()).await?;
        Ok(fence)
    }

    /// Non-repairing metadata preflight for the complete sealed volume set.
    ///
    /// Lifecycle attachments are permitted, but every attachment must already
    /// be an exact immutable Engine ID. The full topology census validates the
    /// attached containers before any subsequent mutation.
    pub(in crate::init) async fn preflight_lifecycle_volumes(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
    ) -> Result<SealedEngineStatus, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let images = self.inspect_epoch_images(epoch).await?;
        if images.len() != epoch.image_expectations().count() {
            return Err(engine_resource_mismatch());
        }
        let names = volume_names(installation);
        let labels = super::expected_volume_labels(installation, epoch.fingerprint());
        let expected_names = names
            .values()
            .cloned()
            .chain(std::iter::once(
                installation.anchor_volume_name().to_owned(),
            ))
            .collect::<BTreeSet<_>>();
        let first_union = self
            .inspect_lifecycle_volume_union(installation, &expected_names)
            .await?;
        if first_union != expected_names {
            return Err(engine_resource_mismatch());
        }
        let mut first = BTreeMap::new();
        let mut volumes = Vec::with_capacity(VolumeRole::ALL.len());
        for role in VolumeRole::ALL {
            let name = names.get(&role).ok_or_else(engine_resource_mismatch)?;
            let volume = self
                .inspect_volume(name)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            validate_volume(
                &volume,
                name,
                labels.get(&role).ok_or_else(engine_resource_mismatch)?,
            )?;
            let attachments = self.volume_attachments(name).await?;
            if attachments
                .iter()
                .any(|attachment| !exact_container_id_text(attachment))
            {
                return Err(engine_resource_mismatch());
            }
            first.insert(role, attachments);
            volumes.push(SealedVolumeStatus {
                role,
                name: name.clone(),
                static_material: role.is_static(),
            });
        }
        let mut repeated = BTreeMap::new();
        for role in VolumeRole::ALL {
            let name = names.get(&role).ok_or_else(engine_resource_mismatch)?;
            repeated.insert(role, self.volume_attachments(name).await?);
        }
        let repeated_union = self
            .inspect_lifecycle_volume_union(installation, &expected_names)
            .await?;
        if first != repeated || repeated_union != first_union {
            return Err(engine_resource_mismatch());
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        Ok(SealedEngineStatus { images, volumes })
    }

    async fn inspect_lifecycle_volume_union(
        &self,
        installation: &Installation,
        expected_names: &BTreeSet<String>,
    ) -> Result<BTreeSet<String>, LocalInitError> {
        let listed = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker
                .list_volumes(Some(ListVolumesOptionsBuilder::default().build())),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if listed
            .warnings
            .as_ref()
            .is_some_and(|warnings| !warnings.is_empty())
            || listed
                .volumes
                .as_ref()
                .is_some_and(|volumes| volumes.len() > MAX_ENGINE_RESOURCES)
        {
            return Err(engine_resource_mismatch());
        }
        let installation_id = installation.id().to_string();
        let installation_key = installation.selector_key().to_string();
        let project = installation.compose_project().as_str();
        let prefix = format!("{project}-");
        let mut observed = BTreeSet::new();
        for volume in listed.volumes.unwrap_or_default() {
            let related = volume.name.starts_with(&prefix)
                || volume
                    .labels
                    .get(LABEL_INSTALLATION_ID)
                    .is_some_and(|value| value == &installation_id)
                || volume
                    .labels
                    .get(LABEL_INSTALLATION_KEY)
                    .is_some_and(|value| value == &installation_key)
                || volume
                    .labels
                    .get(LABEL_COMPOSE_PROJECT)
                    .is_some_and(|value| value == project)
                || volume
                    .labels
                    .get("com.docker.compose.project")
                    .is_some_and(|value| value == project);
            if !related {
                continue;
            }
            if !expected_names.contains(&volume.name) || !observed.insert(volume.name) {
                return Err(engine_resource_mismatch());
            }
        }
        Ok(observed)
    }

    async fn attest_reset_quiescent_union(
        &self,
        installation: &Installation,
        holder: &LifecycleLockHolder,
        expected_volumes: &BTreeSet<String>,
    ) -> Result<(), LocalInitError> {
        self.attest_reset_quiescent_lock(installation, &holder.name, &holder.id, expected_volumes)
            .await
    }

    async fn attest_reset_quiescent_lock(
        &self,
        installation: &Installation,
        lock_name: &str,
        lock_id: &str,
        expected_volumes: &BTreeSet<String>,
    ) -> Result<(), LocalInitError> {
        let first = self
            .reset_quiescent_census(installation, lock_name, lock_id, expected_volumes)
            .await?;
        let repeated = self
            .reset_quiescent_census(installation, lock_name, lock_id, expected_volumes)
            .await?;
        if first != repeated {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await
    }

    async fn reset_quiescent_census(
        &self,
        installation: &Installation,
        lock_name: &str,
        lock_id: &str,
        expected_volumes: &BTreeSet<String>,
    ) -> Result<(BTreeSet<String>, BTreeSet<String>, BTreeSet<String>), LocalInitError> {
        let volumes = self
            .inspect_lifecycle_volume_union(installation, expected_volumes)
            .await?;
        if &volumes != expected_volumes {
            return Err(engine_resource_mismatch());
        }
        let installation_id = installation.id().to_string();
        let installation_key = installation.selector_key().to_string();
        let project = installation.compose_project().as_str();
        let project_prefix = format!("{project}-");
        let local_prefix = local_docker_name_prefix(installation);
        let related_labels = |labels: &HashMap<String, String>| {
            labels
                .get(LABEL_INSTALLATION_ID)
                .is_some_and(|value| value == &installation_id)
                || labels
                    .get(LABEL_INSTALLATION_KEY)
                    .is_some_and(|value| value == &installation_key)
                || labels
                    .get(LABEL_COMPOSE_PROJECT)
                    .is_some_and(|value| value == project)
                || labels
                    .get("com.docker.compose.project")
                    .is_some_and(|value| value == project)
        };
        let listed = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.list_containers(Some(
                ListContainersOptionsBuilder::default().all(true).build(),
            )),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if listed.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        let mut containers = BTreeSet::new();
        for summary in listed {
            let labels = summary.labels.as_ref().cloned().unwrap_or_default();
            let names = summary.names.as_deref().unwrap_or_default();
            let related = names.iter().any(|name| {
                let name = name.trim_start_matches('/');
                name.starts_with(&project_prefix) || name.starts_with(&local_prefix)
            }) || related_labels(&labels);
            if !related {
                continue;
            }
            let id = summary
                .id
                .as_deref()
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?;
            if id != lock_id
                || names != [format!("/{lock_name}")]
                || !containers.insert(id.to_owned())
            {
                return Err(engine_resource_mismatch());
            }
        }
        if containers != BTreeSet::from([lock_id.to_owned()]) {
            return Err(engine_resource_mismatch());
        }

        let listed_networks = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker
                .list_networks(Some(ListNetworksOptionsBuilder::default().build())),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if listed_networks.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        let mut networks = BTreeSet::new();
        for network in listed_networks {
            let labels = network.labels.as_ref().cloned().unwrap_or_default();
            let name = network.name.as_deref().unwrap_or_default();
            if name.starts_with(&project_prefix)
                || name.starts_with(&local_prefix)
                || related_labels(&labels)
            {
                let id = network
                    .id
                    .as_deref()
                    .filter(|id| exact_container_id_text(id))
                    .ok_or_else(engine_resource_mismatch)?;
                networks.insert(id.to_owned());
            }
        }
        if !networks.is_empty() {
            return Err(engine_resource_mismatch());
        }
        Ok((volumes, containers, networks))
    }

    /// Acquires the deterministic stdin-held Engine mutation lock.
    ///
    /// An existing lock is never adopted, restarted, or automatically removed:
    /// an exact live holder reports contention and an exact stopped holder is
    /// sticky recovery evidence. Unknown configuration fails closed.
    pub(in crate::init) async fn acquire_lifecycle_lock(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        operation_id: OperationId,
    ) -> Result<LifecycleLockHolder, LocalInitError> {
        self.acquire_lifecycle_lock_inner(installation, epoch, operation_id, true)
            .await
    }

    /// Bootstrap acquisition for initialization before the identity anchor is
    /// created. The caller-selected installation UUID is already sealed in the
    /// immutable epoch; every later assertion uses the ordinary identity-bound
    /// lock attestation.
    pub(in crate::init) async fn acquire_lifecycle_lock_before_identity(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        operation_id: OperationId,
    ) -> Result<LifecycleLockHolder, LocalInitError> {
        self.acquire_lifecycle_lock_inner(installation, epoch, operation_id, false)
            .await
    }

    async fn acquire_lifecycle_lock_inner(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        operation_id: OperationId,
        require_identity: bool,
    ) -> Result<LifecycleLockHolder, LocalInitError> {
        self.verify_selected_engine().await?;
        if require_identity {
            self.verify_installation(installation).await?;
        }
        let image = lifecycle_lock_image(self, epoch).await?;
        let name = lifecycle_lock_name(installation);
        if let Some(existing) = self.inspect_container(&name).await? {
            return Err(
                match classify_lifecycle_lock(
                    &existing,
                    &name,
                    &image.inspection_reference,
                    &image.image_id,
                    &image.labels,
                    installation,
                )? {
                    LifecycleLockObservation::Live { .. } => {
                        LocalInitError::new(LocalInitErrorCode::OperationInProgress)
                    }
                    LifecycleLockObservation::Stopped { .. } => {
                        LocalInitError::new(LocalInitErrorCode::ResetRequired)
                    }
                    LifecycleLockObservation::Absent => engine_resource_mismatch(),
                },
            );
        }

        let daemon_generation = current_engine_daemon_generation()?;
        let labels = lifecycle_lock_expected_labels(
            &image.labels,
            lifecycle_lock_labels(installation, operation_id, &daemon_generation),
        )?;
        let body = lifecycle_lock_body(&image.inspection_reference, &labels);
        let options = CreateContainerOptionsBuilder::default()
            .name(&name)
            .platform("linux/amd64")
            .build();
        let created = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.create_container(Some(options), body),
        )
        .await;
        let created = match created {
            Ok(Ok(created))
                if exact_container_id_text(&created.id) && created.warnings.is_empty() =>
            {
                created
            }
            _ => {
                return Err(self
                    .classify_lock_collision(installation, epoch, &name)
                    .await?);
            }
        };
        let id = created.id;
        self.attest_lifecycle_lock_exact(
            installation,
            &name,
            &id,
            operation_id,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            false,
        )
        .await?;
        if current_engine_daemon_generation()? != daemon_generation {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }

        let attach_options = AttachContainerOptionsBuilder::default()
            .stdin(true)
            .stdout(true)
            .stderr(true)
            .stream(true)
            .logs(false)
            .build();
        let AttachContainerResults { output, input } = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.attach_container(&id, Some(attach_options)),
        )
        .await
        .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?
        .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;

        let holder_lost = CancellationToken::new();
        let (commands, command_requests) = mpsc::channel(1);
        let mutation_gate = Arc::new(Mutex::new(LifecycleMutationGateState::default()));
        let monitor = tokio::spawn(monitor_lifecycle_lock_output(
            output,
            command_requests,
            holder_lost.clone(),
        ));

        let start =
            tokio::time::timeout(ENGINE_TIMEOUT, self.docker.start_container(&id, None)).await;
        if !matches!(start, Ok(Ok(()))) {
            // A successful start response is not trusted, but an ambiguous
            // response may still have started the exact attached container.
            // Fresh exact inspection is the only safe reconciliation.
            let by_id = self
                .inspect_container(&id)
                .await?
                .ok_or_else(|| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
            if classify_lifecycle_lock(
                &by_id,
                &name,
                &image.inspection_reference,
                &image.image_id,
                &image.labels,
                installation,
            )? != (LifecycleLockObservation::Live {
                id: id.clone(),
                operation_id,
            }) {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
        }
        self.attest_lifecycle_lock_exact(
            installation,
            &name,
            &id,
            operation_id,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            true,
        )
        .await?;
        if holder_lost.is_cancelled() {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        if require_identity {
            self.verify_installation(installation).await?;
        }
        self.verify_selected_engine().await?;
        if current_engine_daemon_generation()? != daemon_generation {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        Ok(LifecycleLockHolder {
            name,
            id,
            operation_id,
            labels,
            daemon_generation,
            input: Some(input),
            holder_lost,
            commands,
            mutation_gate,
            monitor,
        })
    }

    /// Re-attests the exact live ID retained by this manager.
    pub(in crate::init) async fn attest_lifecycle_lock(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        holder: &LifecycleLockHolder,
    ) -> Result<(), LocalInitError> {
        self.attest_lifecycle_lock_inner(installation, epoch, holder, true)
            .await
            .map(drop)
    }

    async fn attest_lifecycle_lock_inner(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        holder: &LifecycleLockHolder,
        require_identity: bool,
    ) -> Result<LifecycleLockImage, LocalInitError> {
        if holder.holder_lost.is_cancelled()
            || current_engine_daemon_generation()? != holder.daemon_generation
        {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        self.verify_selected_engine().await?;
        if require_identity {
            self.verify_installation(installation).await?;
        }
        let image = lifecycle_lock_image(self, epoch).await?;
        if holder.labels
            != lifecycle_lock_expected_labels(
                &image.labels,
                lifecycle_lock_labels(installation, holder.operation_id, &holder.daemon_generation),
            )?
        {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        self.attest_lifecycle_lock_exact(
            installation,
            &holder.name,
            &holder.id,
            holder.operation_id,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            true,
        )
        .await?;
        if require_identity {
            self.verify_installation(installation).await?;
        }
        self.verify_selected_engine().await?;
        Ok(image)
    }

    /// Classifies the deterministic lock without mutating it.
    pub(in crate::init) async fn inspect_lifecycle_lock(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
    ) -> Result<LifecycleLockObservation, LocalInitError> {
        self.inspect_lifecycle_lock_inner(installation, epoch, true)
            .await
    }

    pub(in crate::init) async fn inspect_lifecycle_lock_before_identity(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
    ) -> Result<LifecycleLockObservation, LocalInitError> {
        self.inspect_lifecycle_lock_inner(installation, epoch, false)
            .await
    }

    async fn inspect_lifecycle_lock_inner(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        require_identity: bool,
    ) -> Result<LifecycleLockObservation, LocalInitError> {
        self.verify_selected_engine().await?;
        if require_identity {
            self.verify_installation(installation).await?;
        }
        let image = lifecycle_lock_image(self, epoch).await?;
        let name = lifecycle_lock_name(installation);
        let Some(container) = self.inspect_container(&name).await? else {
            if require_identity {
                self.verify_installation(installation).await?;
            }
            self.verify_selected_engine().await?;
            return Ok(LifecycleLockObservation::Absent);
        };
        let observation = classify_lifecycle_lock(
            &container,
            &name,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            installation,
        )?;
        if require_identity {
            self.verify_installation(installation).await?;
        }
        self.verify_selected_engine().await?;
        Ok(observation)
    }

    async fn gracefully_stop_lifecycle_lock(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        holder: &mut LifecycleLockHolder,
        require_identity: bool,
    ) -> Result<LifecycleLockImage, LocalInitError> {
        if holder.holder_lost.is_cancelled() {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        let mut release_gate = tokio::select! {
            biased;
            () = holder.holder_lost.cancelled() => {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
            result = tokio::time::timeout(
                ENGINE_TIMEOUT,
                Arc::clone(&holder.mutation_gate).lock_owned(),
            ) => {
                result.map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?
            }
        };
        if release_gate.closed {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        release_gate.closed = true;
        self.attest_lifecycle_lock_inner(installation, epoch, holder, require_identity)
            .await?;
        if holder.holder_lost.is_cancelled() {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        let (acknowledged, acknowledgment) = oneshot::channel();
        let (frame_sent, frame_confirmation) = oneshot::channel();
        holder
            .commands
            .send(LifecycleLockCommand::BeginRelease {
                acknowledged,
                frame_sent: frame_confirmation,
            })
            .await
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
        tokio::time::timeout(ENGINE_TIMEOUT, acknowledgment)
            .await
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;

        let mut input = holder
            .input
            .take()
            .ok_or_else(|| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
        tokio::time::timeout(
            ENGINE_TIMEOUT,
            input.write_all(&crate::LOCAL_LIFECYCLE_LOCK_RELEASE_FRAME),
        )
        .await
        .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?
        .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
        frame_sent
            .send(())
            .map_err(|()| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
        tokio::time::timeout(ENGINE_TIMEOUT, input.shutdown())
            .await
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
        drop(input);

        let options = WaitContainerOptionsBuilder::default()
            .condition("not-running")
            .build();
        let mut wait = self.docker.wait_container(&holder.id, Some(options));
        tokio::time::timeout(ENGINE_TIMEOUT, async {
            let result = wait
                .next()
                .await
                .ok_or_else(|| LocalInitError::new(LocalInitErrorCode::ResetRequired))?
                .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
            if wait.next().await.is_some() || result.error.is_some() || result.status_code != 0 {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
            Ok(())
        })
        .await
        .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))??;

        let image = lifecycle_lock_image(self, epoch).await?;
        self.attest_lifecycle_lock_exact(
            installation,
            &holder.name,
            &holder.id,
            holder.operation_id,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            false,
        )
        .await?;
        tokio::time::timeout(ENGINE_TIMEOUT, &mut holder.monitor)
            .await
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))??;
        Ok(image)
    }

    /// Gracefully releases only this manager's retained exact live ID.
    pub(in crate::init) async fn release_lifecycle_lock(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        mut holder: LifecycleLockHolder,
    ) -> Result<(), LocalInitError> {
        self.gracefully_stop_lifecycle_lock(installation, epoch, &mut holder, true)
            .await?;

        let options = RemoveContainerOptionsBuilder::default()
            .force(false)
            .v(false)
            .build();
        let _untrusted = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.remove_container(&holder.id, Some(options)),
        )
        .await;
        if self.inspect_container(&holder.id).await?.is_some()
            || self.inspect_container(&holder.name).await?.is_some()
        {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await
    }

    /// Returns the exact number of persistent role volumes already removed by
    /// a lifecycle-aware reset while the retained live lock remains the sole
    /// related container and every related network is absent.
    pub(in crate::init) async fn inspect_lifecycle_reset_volume_progress(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        holder: &LifecycleLockHolder,
    ) -> Result<usize, LocalInitError> {
        self.attest_lifecycle_lock(installation, epoch, holder)
            .await?;
        let names = volume_names(installation);
        let all_names = names
            .values()
            .cloned()
            .chain(std::iter::once(
                installation.anchor_volume_name().to_owned(),
            ))
            .collect::<BTreeSet<_>>();
        let observed = self
            .inspect_lifecycle_volume_union(installation, &all_names)
            .await?;
        if !observed.contains(installation.anchor_volume_name()) {
            return Err(engine_resource_mismatch());
        }
        let labels = super::expected_volume_labels(installation, epoch.fingerprint());
        let mut presence = [false; 12];
        for (index, role) in reset_volume_order().into_iter().enumerate() {
            let name = names.get(&role).ok_or_else(engine_resource_mismatch)?;
            presence[index] = observed.contains(name);
            if !presence[index] {
                continue;
            }
            let volume = self
                .inspect_volume(name)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            validate_volume(
                &volume,
                name,
                labels.get(&role).ok_or_else(engine_resource_mismatch)?,
            )?;
            if !self.volume_attachments(name).await?.is_empty() {
                return Err(engine_resource_mismatch());
            }
        }
        let removed = reset_progress_from_presence(&presence, true)?;
        let expected_remaining = reset_volume_order()[removed..]
            .iter()
            .map(|role| {
                names
                    .get(role)
                    .cloned()
                    .ok_or_else(engine_resource_mismatch)
            })
            .chain(std::iter::once(Ok(installation
                .anchor_volume_name()
                .to_owned())))
            .collect::<Result<BTreeSet<_>, LocalInitError>>()?;
        if observed != expected_remaining {
            return Err(engine_resource_mismatch());
        }
        self.attest_reset_quiescent_union(installation, holder, &expected_remaining)
            .await?;
        self.attest_lifecycle_lock(installation, epoch, holder)
            .await?;
        Ok(removed)
    }

    /// Read-only reset progress under exact sticky stopped-lock evidence.
    /// Two complete quiescent censuses prove that no related process can race
    /// the observation; the stopped container is never removed here.
    pub(in crate::init) async fn inspect_stopped_lifecycle_reset_volume_progress(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        expected_id: &str,
    ) -> Result<usize, LocalInitError> {
        if !exact_container_id_text(expected_id) {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let image = lifecycle_lock_image(self, epoch).await?;
        let name = lifecycle_lock_name(installation);
        let container = self
            .inspect_container(expected_id)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        let operation_id = match classify_lifecycle_lock(
            &container,
            &name,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            installation,
        )? {
            LifecycleLockObservation::Stopped { id, operation_id } if id == expected_id => {
                operation_id
            }
            LifecycleLockObservation::Absent
            | LifecycleLockObservation::Live { .. }
            | LifecycleLockObservation::Stopped { .. } => return Err(engine_resource_mismatch()),
        };
        let names = volume_names(installation);
        let all_names = names
            .values()
            .cloned()
            .chain(std::iter::once(
                installation.anchor_volume_name().to_owned(),
            ))
            .collect::<BTreeSet<_>>();
        let observed = self
            .inspect_lifecycle_volume_union(installation, &all_names)
            .await?;
        if !observed.contains(installation.anchor_volume_name()) {
            return Err(engine_resource_mismatch());
        }
        let labels = super::expected_volume_labels(installation, epoch.fingerprint());
        let mut presence = [false; 12];
        for (index, role) in reset_volume_order().into_iter().enumerate() {
            let volume_name = names.get(&role).ok_or_else(engine_resource_mismatch)?;
            presence[index] = observed.contains(volume_name);
            if presence[index] {
                let volume = self
                    .inspect_volume(volume_name)
                    .await?
                    .ok_or_else(engine_resource_mismatch)?;
                validate_volume(
                    &volume,
                    volume_name,
                    labels.get(&role).ok_or_else(engine_resource_mismatch)?,
                )?;
                if !self.volume_attachments(volume_name).await?.is_empty() {
                    return Err(engine_resource_mismatch());
                }
            }
        }
        let removed = reset_progress_from_presence(&presence, true)?;
        let expected_remaining = reset_volume_order()[removed..]
            .iter()
            .map(|role| {
                names
                    .get(role)
                    .cloned()
                    .ok_or_else(engine_resource_mismatch)
            })
            .chain(std::iter::once(Ok(installation
                .anchor_volume_name()
                .to_owned())))
            .collect::<Result<BTreeSet<_>, LocalInitError>>()?;
        if observed != expected_remaining {
            return Err(engine_resource_mismatch());
        }
        self.attest_reset_quiescent_lock(installation, &name, expected_id, &expected_remaining)
            .await?;
        self.attest_lifecycle_lock_exact(
            installation,
            &name,
            expected_id,
            operation_id,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            false,
        )
        .await?;
        Ok(removed)
    }

    /// Read-only classification of the exact final stopped reset lock after
    /// the identity anchor and all persistent role volumes are absent.
    pub(in crate::init) async fn inspect_orphaned_stopped_reset_lock(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
    ) -> Result<bool, LocalInitError> {
        self.verify_selected_engine().await?;
        if self
            .adapter
            .inspect_identity(installation.name())
            .await
            .map_err(|_| engine_resource_mismatch())?
            .is_some()
        {
            return Err(engine_resource_mismatch());
        }
        let name = lifecycle_lock_name(installation);
        let Some(container) = self.inspect_container(&name).await? else {
            return Ok(false);
        };
        let image = lifecycle_lock_image(self, epoch).await?;
        let (id, operation_id) = match classify_lifecycle_lock(
            &container,
            &name,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            installation,
        )? {
            LifecycleLockObservation::Stopped { id, operation_id } => (id, operation_id),
            LifecycleLockObservation::Live { .. } => {
                return Err(LocalInitError::new(LocalInitErrorCode::OperationInProgress));
            }
            LifecycleLockObservation::Absent => return Err(engine_resource_mismatch()),
        };
        self.attest_reset_quiescent_lock(installation, &name, &id, &BTreeSet::new())
            .await?;
        self.attest_lifecycle_lock_exact(
            installation,
            &name,
            &id,
            operation_id,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            false,
        )
        .await?;
        Ok(true)
    }

    /// Removes the next exact persistent role volume in the closed reset order.
    pub(in crate::init) async fn remove_lifecycle_reset_volume(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        holder: &LifecycleLockHolder,
        role: VolumeRole,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        let removed = self
            .inspect_lifecycle_reset_volume_progress(installation, epoch, holder)
            .await?;
        if reset_volume_order().get(removed).copied() != Some(role) {
            return Err(engine_resource_mismatch());
        }
        let name = volume_name(installation.compose_project().as_str(), role);
        let volume = self
            .inspect_volume(&name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_volume(
            &volume,
            &name,
            &super::volume_labels(installation, epoch.fingerprint(), role),
        )?;
        if !self.volume_attachments(&name).await?.is_empty() {
            return Err(engine_resource_mismatch());
        }
        mutation
            .run(self.remove_volume_and_prove_absent(&name))
            .await??;
        self.attest_lifecycle_lock(installation, epoch, holder)
            .await
    }

    /// Removes the identity anchor while the retained live holder still fences
    /// every Engine mutation, then gracefully releases and deletes only that
    /// exact holder ID.
    pub(in crate::init) async fn remove_reset_anchor_and_release_lock(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        mut holder: LifecycleLockHolder,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        if self
            .inspect_lifecycle_reset_volume_progress(installation, epoch, &holder)
            .await?
            != 12
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let expected = BTreeSet::from([installation.anchor_volume_name().to_owned()]);
        if self
            .inspect_lifecycle_volume_union(installation, &expected)
            .await?
            != expected
        {
            return Err(engine_resource_mismatch());
        }
        self.attest_reset_quiescent_union(installation, &holder, &expected)
            .await?;
        self.attest_lifecycle_lock(installation, epoch, &holder)
            .await?;
        mutation
            .run(self.remove_volume_and_prove_absent(installation.anchor_volume_name()))
            .await??;
        mutation.checkpoint()?;
        if self
            .adapter
            .inspect_identity(installation.name())
            .await
            .map_err(|_| engine_resource_mismatch())?
            .is_some()
        {
            return Err(engine_resource_mismatch());
        }
        let image = self
            .gracefully_stop_lifecycle_lock(installation, epoch, &mut holder, false)
            .await?;
        if current_engine_daemon_generation()? != holder.daemon_generation {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        self.attest_lifecycle_lock_exact(
            installation,
            &holder.name,
            &holder.id,
            holder.operation_id,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            false,
        )
        .await?;
        let options = RemoveContainerOptionsBuilder::default()
            .force(false)
            .v(false)
            .link(false)
            .build();
        let _untrusted = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.remove_container(&holder.id, Some(options)),
        )
        .await;
        if self.inspect_container(&holder.id).await?.is_some()
            || self.inspect_container(&holder.name).await?.is_some()
        {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        self.attest_reset_union_absent(installation).await
    }

    /// Proves the deterministic lifecycle lock name absent without mutation.
    pub(in crate::init) async fn attest_lifecycle_lock_absent(
        &self,
        installation: &Installation,
    ) -> Result<(), LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        if self
            .inspect_container(&lifecycle_lock_name(installation))
            .await?
            .is_some()
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await
    }

    /// Recovers sticky stopped-lock evidence only after a reset intent is
    /// already durable, following two stable, fully validated Engine censuses.
    pub(in crate::init) async fn recover_stopped_lifecycle_reset_lock_after_intent(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        expected_runner_id: uuid::Uuid,
        expected_id: &str,
    ) -> Result<usize, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let mut recovery = self
            .begin_stopped_lock_recovery_event_fence(expected_id, None)
            .await?;
        let first = recovery
            .guard(async {
                crate::init::compose::attest_no_project_compose_processes(installation)?;
                self.inspect_stopped_lifecycle_reset_recovery_census(
                    installation,
                    epoch,
                    desired,
                    expected,
                    expected_runner_id,
                    expected_id,
                )
                .await
            })
            .await?;
        let repeated = recovery
            .guard(async {
                let census = self
                    .inspect_stopped_lifecycle_reset_recovery_census(
                        installation,
                        epoch,
                        desired,
                        expected,
                        expected_runner_id,
                        expected_id,
                    )
                    .await?;
                crate::init::compose::attest_no_project_compose_processes(installation)?;
                Ok(census)
            })
            .await?;
        if first != repeated {
            return Err(engine_resource_mismatch());
        }
        let cancellation_latched = recovery
            .delete_exact_container(&self.docker, expected_id)
            .await?;
        let name = lifecycle_lock_name(installation);
        recovery
            .guard(async {
                if self.inspect_container(expected_id).await?.is_some()
                    || self.inspect_container(&name).await?.is_some()
                {
                    return Err(engine_resource_mismatch());
                }
                self.verify_installation(installation).await?;
                self.verify_selected_engine().await
            })
            .await?;
        recovery.verify_generation()?;
        if cancellation_latched {
            return Err(engine_resource_mismatch());
        }
        Ok(first.0)
    }

    async fn inspect_stopped_lifecycle_reset_recovery_census(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        expected_runner_id: uuid::Uuid,
        expected_id: &str,
    ) -> Result<(usize, Option<LifecycleTopology>), LocalInitError> {
        let names = volume_names(installation);
        let all_names = names
            .values()
            .cloned()
            .chain(std::iter::once(
                installation.anchor_volume_name().to_owned(),
            ))
            .collect::<BTreeSet<_>>();
        let observed = self
            .inspect_lifecycle_volume_union(installation, &all_names)
            .await?;
        if !observed.contains(installation.anchor_volume_name()) {
            return Err(engine_resource_mismatch());
        }
        let mut presence = [false; 12];
        for (index, role) in reset_volume_order().into_iter().enumerate() {
            presence[index] =
                observed.contains(names.get(&role).ok_or_else(engine_resource_mismatch)?);
        }
        let removed = reset_progress_from_presence(&presence, true)?;
        if removed == 0 {
            self.preflight_lifecycle_volumes(installation, epoch)
                .await?;
            let topology = self
                .inspect_lifecycle_topology(
                    installation,
                    epoch,
                    desired,
                    expected,
                    expected_runner_id,
                )
                .await?;
            Ok((removed, Some(topology)))
        } else {
            let expected_remaining = reset_volume_order()[removed..]
                .iter()
                .map(|role| {
                    names
                        .get(role)
                        .cloned()
                        .ok_or_else(engine_resource_mismatch)
                })
                .chain(std::iter::once(Ok(installation
                    .anchor_volume_name()
                    .to_owned())))
                .collect::<Result<BTreeSet<_>, LocalInitError>>()?;
            if observed != expected_remaining {
                return Err(engine_resource_mismatch());
            }
            self.attest_reset_quiescent_lock(
                installation,
                &lifecycle_lock_name(installation),
                expected_id,
                &expected_remaining,
            )
            .await?;
            Ok((removed, None))
        }
    }

    /// Exceptional, operator-authorized recovery for ordinary up/down replay.
    ///
    /// The exact stopped holder is retained while two complete, independently
    /// validated topology censuses and their immutable Engine identities agree.
    /// Only then is that same stopped ID removed. Ordinary lock acquisition
    /// never enters this boundary.
    pub(in crate::init) async fn recover_stopped_lifecycle_lock(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        expected_runner_id: uuid::Uuid,
        expected_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<(), LocalInitError> {
        if !exact_container_id_text(expected_id) {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let expected_operation = match self.inspect_lifecycle_lock(installation, epoch).await? {
            LifecycleLockObservation::Stopped { id, operation_id } if id == expected_id => {
                operation_id
            }
            LifecycleLockObservation::Live { .. } => {
                return Err(LocalInitError::new(LocalInitErrorCode::OperationInProgress));
            }
            LifecycleLockObservation::Absent | LifecycleLockObservation::Stopped { .. } => {
                return Err(engine_resource_mismatch());
            }
        };
        let mut recovery = self
            .begin_stopped_lock_recovery_event_fence(expected_id, Some(cancellation))
            .await?;
        recovery
            .guard(async {
                crate::init::compose::attest_no_project_compose_processes(installation)?;
                self.preflight_lifecycle_volumes(installation, epoch)
                    .await?;
                Ok(())
            })
            .await?;
        let (first_topology, first_identity) = recovery
            .guard(async {
                let topology = self
                    .inspect_lifecycle_topology(
                        installation,
                        epoch,
                        desired,
                        expected,
                        expected_runner_id,
                    )
                    .await?;
                let identity = self
                    .lifecycle_quiescent_identity_census(installation)
                    .await?;
                crate::init::compose::attest_no_project_compose_processes(installation)?;
                Ok((topology, identity))
            })
            .await?;
        let (repeated_topology, repeated_identity) = recovery
            .guard(async {
                let topology = self
                    .inspect_lifecycle_topology(
                        installation,
                        epoch,
                        desired,
                        expected,
                        expected_runner_id,
                    )
                    .await?;
                let identity = self
                    .lifecycle_quiescent_identity_census(installation)
                    .await?;
                crate::init::compose::attest_no_project_compose_processes(installation)?;
                Ok((topology, identity))
            })
            .await?;
        if first_topology != repeated_topology || first_identity != repeated_identity {
            return Err(engine_resource_mismatch());
        }
        recovery
            .guard(async {
                if self.inspect_lifecycle_lock(installation, epoch).await?
                    != (LifecycleLockObservation::Stopped {
                        id: expected_id.to_owned(),
                        operation_id: expected_operation,
                    })
                {
                    return Err(engine_resource_mismatch());
                }
                Ok(())
            })
            .await?;
        let cancellation_latched = recovery
            .delete_exact_container(&self.docker, expected_id)
            .await?;
        recovery
            .guard(async {
                if self.inspect_container(expected_id).await?.is_some()
                    || self
                        .inspect_container(&lifecycle_lock_name(installation))
                        .await?
                        .is_some()
                {
                    return Err(engine_resource_mismatch());
                }
                self.verify_installation(installation).await?;
                self.verify_selected_engine().await
            })
            .await?;
        recovery.verify_generation()?;
        if cancellation_latched {
            Err(LocalInitError::new(LocalInitErrorCode::Cancelled))
        } else {
            Ok(())
        }
    }

    /// Exceptional stopped-lock recovery for initialization before the
    /// identity anchor necessarily exists. One event subscription spans both
    /// complete init-union censuses, the exact-ID destroy, and absence proof.
    pub(in crate::init) async fn recover_stopped_initialization_lock(
        &self,
        catalog: &crate::init::catalog::VerifiedCatalog,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        expected_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<(), LocalInitError> {
        let expected_operation = match self
            .inspect_lifecycle_lock_before_identity(installation, epoch)
            .await?
        {
            LifecycleLockObservation::Stopped { id, operation_id } if id == expected_id => {
                operation_id
            }
            LifecycleLockObservation::Live { .. } => {
                return Err(LocalInitError::new(LocalInitErrorCode::OperationInProgress));
            }
            LifecycleLockObservation::Absent | LifecycleLockObservation::Stopped { .. } => {
                return Err(engine_resource_mismatch());
            }
        };
        let lock_name = lifecycle_lock_name(installation);
        let mut recovery = self
            .begin_stopped_lock_recovery_event_fence(expected_id, Some(cancellation))
            .await?;
        let first = recovery
            .guard(async {
                crate::init::compose::attest_no_project_compose_processes(installation)?;
                self.preflight_initialization_recovery_union(
                    catalog,
                    installation,
                    epoch.fingerprint(),
                    (&lock_name, expected_id),
                )
                .await
            })
            .await?;
        let repeated = recovery
            .guard(async {
                let census = self
                    .preflight_initialization_recovery_union(
                        catalog,
                        installation,
                        epoch.fingerprint(),
                        (&lock_name, expected_id),
                    )
                    .await?;
                crate::init::compose::attest_no_project_compose_processes(installation)?;
                Ok(census)
            })
            .await?;
        if first != repeated {
            return Err(engine_resource_mismatch());
        }
        recovery
            .guard(async {
                if self
                    .inspect_lifecycle_lock_before_identity(installation, epoch)
                    .await?
                    != (LifecycleLockObservation::Stopped {
                        id: expected_id.to_owned(),
                        operation_id: expected_operation,
                    })
                {
                    return Err(engine_resource_mismatch());
                }
                Ok(())
            })
            .await?;
        let cancellation_latched = recovery
            .delete_exact_container(&self.docker, expected_id)
            .await?;
        recovery
            .guard(async {
                if self.inspect_container(expected_id).await?.is_some()
                    || self.inspect_container(&lock_name).await?.is_some()
                {
                    return Err(engine_resource_mismatch());
                }
                self.verify_selected_engine().await
            })
            .await?;
        recovery.verify_generation()?;
        if cancellation_latched {
            Err(LocalInitError::new(LocalInitErrorCode::Cancelled))
        } else {
            Ok(())
        }
    }

    /// Removes the sole exact stopped reset lock after the identity anchor was
    /// already durably deleted but the final exact-ID lock removal crashed.
    pub(in crate::init) async fn recover_orphaned_stopped_reset_lock(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
    ) -> Result<bool, LocalInitError> {
        self.verify_selected_engine().await?;
        if self
            .adapter
            .inspect_identity(installation.name())
            .await
            .map_err(|_| engine_resource_mismatch())?
            .is_some()
        {
            return Err(engine_resource_mismatch());
        }
        let name = lifecycle_lock_name(installation);
        let Some(container) = self.inspect_container(&name).await? else {
            return Ok(false);
        };
        let image = lifecycle_lock_image(self, epoch).await?;
        let (id, operation_id) = match classify_lifecycle_lock(
            &container,
            &name,
            &image.inspection_reference,
            &image.image_id,
            &image.labels,
            installation,
        )? {
            LifecycleLockObservation::Stopped { id, operation_id } => (id, operation_id),
            LifecycleLockObservation::Live { .. } => {
                return Err(LocalInitError::new(LocalInitErrorCode::OperationInProgress));
            }
            LifecycleLockObservation::Absent => return Err(engine_resource_mismatch()),
        };
        let expected_volumes = BTreeSet::new();
        let mut recovery = self
            .begin_stopped_lock_recovery_event_fence(&id, None)
            .await?;
        for _ in 0..2 {
            recovery
                .guard(async {
                    crate::init::compose::attest_no_project_compose_processes(installation)?;
                    self.attest_reset_quiescent_lock(installation, &name, &id, &expected_volumes)
                        .await?;
                    let by_id = self
                        .inspect_container(&id)
                        .await?
                        .ok_or_else(engine_resource_mismatch)?;
                    if classify_lifecycle_lock(
                        &by_id,
                        &name,
                        &image.inspection_reference,
                        &image.image_id,
                        &image.labels,
                        installation,
                    )? != (LifecycleLockObservation::Stopped {
                        id: id.clone(),
                        operation_id,
                    }) {
                        return Err(engine_resource_mismatch());
                    }
                    Ok(())
                })
                .await?;
        }
        recovery.delete_exact_container(&self.docker, &id).await?;
        recovery
            .guard(async {
                if self.inspect_container(&id).await?.is_some()
                    || self.inspect_container(&name).await?.is_some()
                    || self
                        .adapter
                        .inspect_identity(installation.name())
                        .await
                        .map_err(|_| engine_resource_mismatch())?
                        .is_some()
                {
                    return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
                }
                self.verify_selected_engine().await
            })
            .await?;
        recovery.verify_generation()?;
        Ok(true)
    }

    async fn classify_lock_collision(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        name: &str,
    ) -> Result<LocalInitError, LocalInitError> {
        let image = lifecycle_lock_image(self, epoch).await?;
        let container = self
            .inspect_container(name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        Ok(
            match classify_lifecycle_lock(
                &container,
                name,
                &image.inspection_reference,
                &image.image_id,
                &image.labels,
                installation,
            )? {
                LifecycleLockObservation::Live { .. } => {
                    LocalInitError::new(LocalInitErrorCode::OperationInProgress)
                }
                LifecycleLockObservation::Stopped { .. } => {
                    LocalInitError::new(LocalInitErrorCode::ResetRequired)
                }
                LifecycleLockObservation::Absent => engine_resource_mismatch(),
            },
        )
    }

    async fn attest_lifecycle_lock_exact(
        &self,
        installation: &Installation,
        name: &str,
        id: &str,
        operation_id: OperationId,
        image_reference: &str,
        image_id: &str,
        image_labels: &BTreeMap<String, String>,
        running: bool,
    ) -> Result<(), LocalInitError> {
        let expected = if running {
            LifecycleLockObservation::Live {
                id: id.to_owned(),
                operation_id,
            }
        } else {
            LifecycleLockObservation::Stopped {
                id: id.to_owned(),
                operation_id,
            }
        };
        let by_id = self
            .inspect_container(id)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        if classify_lifecycle_lock(
            &by_id,
            name,
            image_reference,
            image_id,
            image_labels,
            installation,
        )? != expected
        {
            return Err(engine_resource_mismatch());
        }
        let by_name = self
            .inspect_container(name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        if classify_lifecycle_lock(
            &by_name,
            name,
            image_reference,
            image_id,
            image_labels,
            installation,
        )? != expected
        {
            return Err(engine_resource_mismatch());
        }
        Ok(())
    }

    /// Reads the sealed canonical Desired bytes through one exact, disposable,
    /// networkless Automata helper and proves the helper absent on every exit.
    pub(in crate::init) async fn read_sealed_desired(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        mutation: &LifecycleMutationFence,
    ) -> Result<Vec<u8>, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let automata = self
            .inspect_epoch_images(epoch)
            .await?
            .into_iter()
            .find(|image| image.role == "automata")
            .ok_or_else(engine_resource_mismatch)?;
        let volumes = volume_names(installation);
        let desired_name = volumes
            .get(&VolumeRole::Desired)
            .ok_or_else(engine_resource_mismatch)?;
        let desired = self
            .inspect_volume(desired_name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        let expected_labels = super::expected_volume_labels(installation, epoch.fingerprint());
        validate_volume(
            &desired,
            desired_name,
            expected_labels
                .get(&VolumeRole::Desired)
                .ok_or_else(engine_resource_mismatch)?,
        )?;
        let name = format!("{}-desired-reader", installation.compose_project());
        let labels = desired_reader_labels(installation, epoch.fingerprint());
        let mut baseline = exact_attachment_set(self, desired_name).await?;
        if let Some(existing) = self.inspect_container(&name).await? {
            let id = existing
                .id
                .as_deref()
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?
                .to_owned();
            validate_desired_reader(
                &existing,
                &id,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                desired_name,
                &labels,
            )?;
            if !baseline.remove(&id) {
                return Err(engine_resource_mismatch());
            }
            self.remove_desired_reader_and_prove_absent(
                &id,
                &name,
                desired_name,
                &baseline,
                mutation,
            )
            .await?;
        }
        baseline = exact_attachment_set(self, desired_name).await?;
        if exact_attachment_set(self, desired_name).await? != baseline {
            return Err(engine_resource_mismatch());
        }

        let options = CreateContainerOptionsBuilder::default()
            .name(&name)
            .platform("linux/amd64")
            .build();
        let created = mutation
            .run(tokio::time::timeout(
                ENGINE_TIMEOUT,
                self.docker.create_container(
                    Some(options),
                    desired_reader_body(&automata.inspection_reference, desired_name, &labels),
                ),
            ))
            .await?;
        let pinned = match created {
            Ok(Ok(created))
                if created.warnings.is_empty() && exact_container_id_text(&created.id) =>
            {
                created.id
            }
            _ => self
                .inspect_container(&name)
                .await?
                .and_then(|container| container.id)
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?,
        };
        let operation = self
            .run_desired_reader(
                &pinned,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                desired_name,
                &labels,
                &baseline,
                mutation,
            )
            .await;
        let cleanup = self
            .remove_desired_reader_and_prove_absent(
                &pinned,
                &name,
                desired_name,
                &baseline,
                mutation,
            )
            .await;
        match (operation, cleanup) {
            (Ok(bytes), Ok(())) => Ok(bytes),
            (Err(error), Ok(())) | (_, Err(error)) => Err(error),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_desired_reader(
        &self,
        pinned: &str,
        name: &str,
        image: &str,
        image_id: &str,
        desired_volume: &str,
        labels: &BTreeMap<String, String>,
        baseline: &BTreeSet<String>,
        mutation: &LifecycleMutationFence,
    ) -> Result<Vec<u8>, LocalInitError> {
        let stopped = self
            .inspect_container(pinned)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_desired_reader(
            &stopped,
            pinned,
            name,
            image,
            image_id,
            desired_volume,
            labels,
        )?;
        let mut expected_attachments = baseline.clone();
        if !expected_attachments.insert(pinned.to_owned())
            || stopped.state.as_ref().and_then(|state| state.running) != Some(false)
            || exact_attachment_set(self, desired_volume).await? != expected_attachments
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await?;
        mutation
            .run(tokio::time::timeout(
                ENGINE_TIMEOUT,
                self.docker.start_container(pinned, None),
            ))
            .await?
            .map_err(|_| engine_resource_mismatch())?
            .map_err(|_| engine_resource_mismatch())?;
        self.verify_selected_engine().await?;
        let mut wait = self.docker.wait_container(
            pinned,
            Some(
                WaitContainerOptionsBuilder::default()
                    .condition("not-running")
                    .build(),
            ),
        );
        let result = tokio::time::timeout(HELPER_TIMEOUT, async {
            let result = wait
                .next()
                .await
                .ok_or_else(engine_resource_mismatch)?
                .map_err(|_| engine_resource_mismatch())?;
            if wait.next().await.is_some() {
                return Err(engine_resource_mismatch());
            }
            Ok(result)
        })
        .await
        .map_err(|_| engine_resource_mismatch())??;
        if result.status_code != 0 || result.error.is_some() {
            return Err(engine_resource_mismatch());
        }
        let exited = self
            .inspect_container(pinned)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_desired_reader(
            &exited,
            pinned,
            name,
            image,
            image_id,
            desired_volume,
            labels,
        )?;
        if exited.state.as_ref().and_then(|state| state.running) != Some(false) {
            return Err(engine_resource_mismatch());
        }
        self.desired_reader_logs(pinned).await
    }

    async fn desired_reader_logs(&self, id: &str) -> Result<Vec<u8>, LocalInitError> {
        let options = LogsOptionsBuilder::default()
            .follow(false)
            .stdout(true)
            .stderr(true)
            .timestamps(false)
            .tail("all")
            .build();
        let mut stream = self.docker.logs(id, Some(options));
        tokio::time::timeout(ENGINE_TIMEOUT, async {
            let mut stdout = Vec::new();
            while let Some(frame) = stream.next().await {
                match frame.map_err(|_| engine_resource_mismatch())? {
                    LogOutput::StdOut { message } => {
                        if stdout.len().saturating_add(message.len()) > MAX_LOCAL_DESIRED_SPEC_BYTES
                        {
                            return Err(engine_resource_mismatch());
                        }
                        stdout.extend_from_slice(&message);
                    }
                    LogOutput::StdErr { message } if message.is_empty() => {}
                    _ => return Err(engine_resource_mismatch()),
                }
            }
            if stdout.is_empty() || !stdout.ends_with(b"\n") {
                return Err(engine_resource_mismatch());
            }
            Ok(stdout)
        })
        .await
        .map_err(|_| engine_resource_mismatch())?
    }

    async fn remove_desired_reader_and_prove_absent(
        &self,
        id: &str,
        name: &str,
        desired_volume: &str,
        baseline: &BTreeSet<String>,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        if !exact_container_id_text(id) {
            return Err(engine_resource_mismatch());
        }
        let options = RemoveContainerOptionsBuilder::default()
            .force(true)
            .v(false)
            .link(false)
            .build();
        let _untrusted = mutation
            .run(tokio::time::timeout(
                ENGINE_TIMEOUT,
                self.docker.remove_container(id, Some(options)),
            ))
            .await?;
        if self.inspect_container(id).await?.is_some()
            || self.inspect_container(name).await?.is_some()
            || exact_attachment_set(self, desired_volume).await? != *baseline
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await
    }

    /// Applies one exact generated-file CAS through a disposable fixed helper.
    ///
    /// The request may contain credentials, so it is carried only over the
    /// attached stdin stream after exact image, container, volume, attachment,
    /// and daemon re-attestation. Every exit removes the pinned helper and
    /// proves both its name and exact ID absent.
    pub(in crate::init) async fn apply_lifecycle_cas(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        request: &CasRequest,
        mutation: &LifecycleMutationFence,
    ) -> Result<Sha256Digest, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let automata = self
            .inspect_epoch_images(epoch)
            .await?
            .into_iter()
            .find(|image| image.role == "automata")
            .ok_or_else(engine_resource_mismatch)?;
        let role = cas_volume_role(request.target());
        let volume_name = volume_name(installation.compose_project().as_str(), role);
        let volume = self
            .inspect_volume(&volume_name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_volume(
            &volume,
            &volume_name,
            &super::expected_volume_labels(installation, epoch.fingerprint())[&role],
        )?;
        if !self.volume_attachments(&volume_name).await?.is_empty() {
            return Err(engine_resource_mismatch());
        }

        let name = format!(
            "{}-{}-cas",
            installation.compose_project(),
            request.target().slug()
        );
        let labels = cas_writer_labels(installation, epoch, request);
        let user = cas_writer_user(request.target());
        let cap_add = if user == "0:0" {
            vec!["DAC_OVERRIDE".to_owned()]
        } else {
            Vec::new()
        };
        if let Some(existing) = self.inspect_container(&name).await? {
            let id = existing
                .id
                .as_deref()
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?
                .to_owned();
            validate_cas_writer(
                &existing,
                &id,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                user,
                &cap_add,
                &labels,
            )?;
            self.remove_cas_writer_and_prove_absent(&id, &name, &volume_name, mutation)
                .await?;
        }

        let created = mutation
            .run(self.driver_create(
                &name,
                cas_writer_body(
                    &automata.inspection_reference,
                    &volume_name,
                    user,
                    &cap_add,
                    &labels,
                ),
            ))
            .await?;
        let pinned = match &created {
            Ok(created) if exact_container_id_text(&created.id) => Some(created.id.clone()),
            _ => self
                .inspect_container(&name)
                .await?
                .and_then(|container| container.id)
                .filter(|id| exact_container_id_text(id)),
        };
        let operation = async {
            let pinned = pinned.as_deref().ok_or_else(engine_resource_mismatch)?;
            if created
                .as_ref()
                .is_ok_and(|created| !created.warnings.is_empty())
            {
                return Err(engine_resource_mismatch());
            }
            self.attest_cas_writer(
                pinned,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                user,
                &cap_add,
                &labels,
                false,
            )
            .await?;
            let mut input = mutation.run(self.driver_attach(pinned)).await??;
            self.verify_selected_engine().await?;
            self.attest_cas_writer(
                pinned,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                user,
                &cap_add,
                &labels,
                false,
            )
            .await?;
            mutation.run(self.driver_start(pinned)).await??;
            self.verify_selected_engine().await?;
            self.attest_cas_writer(
                pinned,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                user,
                &cap_add,
                &labels,
                true,
            )
            .await?;
            let request_bytes = zeroize::Zeroizing::new(request.canonical_bytes()?);
            mutation
                .run(self.driver_send_request(&mut input, &request_bytes))
                .await??;
            drop(input);
            let wait = self.driver_wait(pinned).await?;
            if wait.status_code != 0 || wait.has_error {
                return Err(engine_resource_mismatch());
            }
            let (stdout, stderr) = self.driver_logs(pinned).await?;
            if !stdout.is_empty() || !stderr.is_empty() {
                return Err(engine_resource_mismatch());
            }
            self.attest_cas_writer(
                pinned,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                user,
                &cap_add,
                &labels,
                false,
            )
            .await?;
            Ok(request.replacement_sha256())
        }
        .await;
        let cleanup = match pinned.as_deref() {
            Some(id) => {
                self.remove_cas_writer_and_prove_absent(id, &name, &volume_name, mutation)
                    .await
            }
            None => match self.inspect_container(&name).await? {
                None => Ok(()),
                Some(_) => Err(engine_resource_mismatch()),
            },
        };
        match cleanup {
            Err(error) => Err(error),
            Ok(()) => operation,
        }
    }

    /// Reads the current expected-old digest of one replaceable generated file
    /// through an exact disposable read-only helper.
    pub(in crate::init) async fn read_lifecycle_cas_digest(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        target: CasTarget,
        mutation: &LifecycleMutationFence,
    ) -> Result<Option<Sha256Digest>, LocalInitError> {
        self.read_lifecycle_cas_digest_with_attachments(
            installation,
            epoch,
            target,
            &BTreeSet::new(),
            mutation,
        )
        .await
    }

    /// Reads a lifecycle CAS digest while pinning the exact already-attached
    /// steady service IDs attested by the caller's complete topology census.
    pub(in crate::init) async fn read_lifecycle_cas_digest_with_attachments(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        target: CasTarget,
        expected_attachments: &BTreeSet<String>,
        mutation: &LifecycleMutationFence,
    ) -> Result<Option<Sha256Digest>, LocalInitError> {
        if expected_attachments
            .iter()
            .any(|id| !exact_container_id_text(id))
        {
            return Err(engine_resource_mismatch());
        }
        let request = CasDigestRequest::new(target)?;
        let target = request.target();
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let automata = self
            .inspect_epoch_images(epoch)
            .await?
            .into_iter()
            .find(|image| image.role == "automata")
            .ok_or_else(engine_resource_mismatch)?;
        let role = cas_volume_role(target);
        let volume_name = volume_name(installation.compose_project().as_str(), role);
        let volume = self
            .inspect_volume(&volume_name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_volume(
            &volume,
            &volume_name,
            &super::expected_volume_labels(installation, epoch.fingerprint())[&role],
        )?;
        if self
            .volume_attachments(&volume_name)
            .await?
            .into_iter()
            .collect::<BTreeSet<_>>()
            != *expected_attachments
        {
            return Err(engine_resource_mismatch());
        }
        let name = format!(
            "{}-{}-cas-digest",
            installation.compose_project(),
            target.slug()
        );
        let labels = cas_digest_reader_labels(installation, epoch, target);
        if let Some(existing) = self.inspect_container(&name).await? {
            let id = exact_container_id(&existing)?.to_owned();
            validate_cas_digest_reader(
                &existing,
                &id,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                &labels,
            )?;
            self.remove_cas_reader_and_prove_absent(
                &id,
                &name,
                &volume_name,
                expected_attachments,
                mutation,
            )
            .await?;
        }
        let created = mutation
            .run(self.driver_create(
                &name,
                cas_digest_reader_body(&automata.inspection_reference, &volume_name, &labels),
            ))
            .await?;
        let pinned = match &created {
            Ok(created) if exact_container_id_text(&created.id) => Some(created.id.clone()),
            _ => self
                .inspect_container(&name)
                .await?
                .and_then(|container| container.id)
                .filter(|id| exact_container_id_text(id)),
        };
        let operation = async {
            let pinned = pinned.as_deref().ok_or_else(engine_resource_mismatch)?;
            if created
                .as_ref()
                .is_ok_and(|created| !created.warnings.is_empty())
            {
                return Err(engine_resource_mismatch());
            }
            self.attest_cas_digest_reader(
                pinned,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                &labels,
                expected_attachments,
                false,
            )
            .await?;
            let mut input = mutation.run(self.driver_attach(pinned)).await??;
            self.attest_cas_digest_reader(
                pinned,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                &labels,
                expected_attachments,
                false,
            )
            .await?;
            mutation.run(self.driver_start(pinned)).await??;
            self.attest_cas_digest_reader(
                pinned,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                &labels,
                expected_attachments,
                true,
            )
            .await?;
            let request_bytes = request.canonical_bytes()?;
            mutation
                .run(self.driver_send_request(&mut input, &request_bytes))
                .await??;
            drop(input);
            let wait = self.driver_wait(pinned).await?;
            if wait.status_code != 0 || wait.has_error {
                return Err(engine_resource_mismatch());
            }
            let (stdout, stderr) = self.driver_logs(pinned).await?;
            if !stderr.is_empty() {
                return Err(engine_resource_mismatch());
            }
            let response = CasDigestResponse::from_canonical_bytes(&stdout, target)?;
            self.attest_cas_digest_reader(
                pinned,
                &name,
                &automata.inspection_reference,
                &automata.image_id,
                &volume_name,
                &labels,
                expected_attachments,
                false,
            )
            .await?;
            Ok(response.sha256())
        }
        .await;
        let cleanup = match pinned.as_deref() {
            Some(id) => {
                self.remove_cas_reader_and_prove_absent(
                    id,
                    &name,
                    &volume_name,
                    expected_attachments,
                    mutation,
                )
                .await
            }
            None => match self.inspect_container(&name).await? {
                None => Ok(()),
                Some(_) => Err(engine_resource_mismatch()),
            },
        };
        cleanup?;
        operation
    }

    #[allow(clippy::too_many_arguments)]
    async fn attest_cas_digest_reader(
        &self,
        id: &str,
        name: &str,
        image: &str,
        image_id: &str,
        volume_name: &str,
        labels: &BTreeMap<String, String>,
        expected_attachments: &BTreeSet<String>,
        running: bool,
    ) -> Result<(), LocalInitError> {
        let by_id = self
            .inspect_container(id)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        let by_name = self
            .inspect_container(name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        for container in [&by_id, &by_name] {
            validate_cas_digest_reader(container, id, name, image, image_id, volume_name, labels)?;
            if container.state.as_ref().and_then(|state| state.running) != Some(running) {
                return Err(engine_resource_mismatch());
            }
        }
        let mut attached = expected_attachments.clone();
        if !attached.insert(id.to_owned())
            || self
                .volume_attachments(volume_name)
                .await?
                .into_iter()
                .collect::<BTreeSet<_>>()
                != attached
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await
    }

    #[allow(clippy::too_many_arguments)]
    async fn attest_cas_writer(
        &self,
        id: &str,
        name: &str,
        image: &str,
        image_id: &str,
        volume_name: &str,
        user: &str,
        cap_add: &[String],
        labels: &BTreeMap<String, String>,
        running: bool,
    ) -> Result<(), LocalInitError> {
        self.verify_selected_engine().await?;
        let by_id = self
            .inspect_container(id)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        let by_name = self
            .inspect_container(name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        for container in [&by_id, &by_name] {
            validate_cas_writer(
                container,
                id,
                name,
                image,
                image_id,
                volume_name,
                user,
                cap_add,
                labels,
            )?;
            if container.state.as_ref().and_then(|state| state.running) != Some(running) {
                return Err(engine_resource_mismatch());
            }
        }
        if self.volume_attachments(volume_name).await?.as_slice() != [id] {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await
    }

    async fn remove_cas_writer_and_prove_absent(
        &self,
        id: &str,
        name: &str,
        volume_name: &str,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        if !exact_container_id_text(id) {
            return Err(engine_resource_mismatch());
        }
        let _untrusted = mutation.run(self.driver_force_remove(id)).await?;
        if self.inspect_container(id).await?.is_some()
            || self.inspect_container(name).await?.is_some()
            || !self.volume_attachments(volume_name).await?.is_empty()
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await
    }

    async fn remove_cas_reader_and_prove_absent(
        &self,
        id: &str,
        name: &str,
        volume_name: &str,
        expected_attachments: &BTreeSet<String>,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        if !exact_container_id_text(id) {
            return Err(engine_resource_mismatch());
        }
        let _untrusted = mutation.run(self.driver_force_remove(id)).await?;
        if self.inspect_container(id).await?.is_some()
            || self.inspect_container(name).await?.is_some()
            || self
                .volume_attachments(volume_name)
                .await?
                .into_iter()
                .collect::<BTreeSet<_>>()
                != *expected_attachments
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await
    }

    /// Creates or adopts the lifecycle-owned schema-2 Results transit.
    pub(in crate::init) async fn ensure_results_transit(
        &self,
        installation: &Installation,
        desired: &DesiredSpec,
        mutation: &LifecycleMutationFence,
    ) -> Result<String, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let name = results_transit_name(installation);
        if self.inspect_network_exact(&name).await?.is_none() {
            let request = NetworkCreateRequest {
                name: name.clone(),
                driver: Some("bridge".to_owned()),
                scope: Some("local".to_owned()),
                internal: Some(true),
                attachable: Some(false),
                ingress: Some(false),
                config_only: Some(false),
                config_from: None,
                ipam: Some(Ipam {
                    driver: Some("default".to_owned()),
                    config: Some(vec![IpamConfig {
                        subnet: Some(desired.results_transit().subnet()),
                        gateway: Some(desired.results_transit().gateway().to_string()),
                        ip_range: None,
                        auxiliary_addresses: None,
                    }]),
                    options: Some(HashMap::new()),
                }),
                enable_ipv4: Some(true),
                enable_ipv6: Some(false),
                options: Some(HashMap::from([(
                    RESULTS_TRANSIT_GATEWAY_MODE_KEY.to_owned(),
                    RESULTS_TRANSIT_GATEWAY_MODE_VALUE.to_owned(),
                )])),
                labels: Some(
                    results_transit_labels(installation, desired.plan_digest())
                        .into_iter()
                        .collect(),
                ),
            };
            let _untrusted = mutation
                .run(tokio::time::timeout(
                    ENGINE_TIMEOUT,
                    self.docker.create_network(request),
                ))
                .await?;
        }
        let network = self
            .inspect_network_exact(&name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_results_transit(&network, installation, desired, true)?;
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        network
            .id
            .filter(|id| exact_container_id_text(id))
            .ok_or_else(engine_resource_mismatch)
    }

    /// Classifies only the closed lifecycle-owned service/network namespace.
    /// Any complete candidate is fully attested before `Running` is returned;
    /// callers decide whether a partial state is replayable for the durable
    /// phase they hold.
    pub(in crate::init) async fn inspect_lifecycle_topology(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        expected_runner_id: uuid::Uuid,
    ) -> Result<LifecycleTopology, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        if expected.containers.len() != 8 || expected.networks.len() != 2 {
            return Err(engine_resource_mismatch());
        }
        let images = self
            .inspect_epoch_images(epoch)
            .await?
            .into_iter()
            .map(|image| (image.role.clone(), image))
            .collect::<BTreeMap<_, _>>();
        let lock_image = lifecycle_lock_image(self, epoch).await?;
        let volume_names = volume_names(installation);
        let mut attachment_ids = BTreeSet::new();
        for role in VolumeRole::ALL {
            let volume_name = volume_names
                .get(&role)
                .ok_or_else(engine_resource_mismatch)?;
            attachment_ids.extend(self.volume_attachments(volume_name).await?);
        }
        let expected_names = expected
            .containers
            .iter()
            .map(|(service, container)| {
                let name = if container.oneoff() {
                    format!("{}-{service}", installation.compose_project())
                } else {
                    format!("{}-{service}-1", installation.compose_project())
                };
                (name, service.as_str())
            })
            .collect::<BTreeMap<_, _>>();
        let local_prefix = local_docker_name_prefix(installation);
        let transit_name = results_transit_name(installation);
        let listed_networks = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker
                .list_networks(Some(ListNetworksOptionsBuilder::default().build())),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if listed_networks.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        // Network attachments are a first-class discovery axis. Feeding every
        // endpoint ID from every related candidate network into the container
        // census prevents an unlabeled foreign endpoint from hiding behind an
        // otherwise exact managed network.
        for listed_network in &listed_networks {
            if !lifecycle_network_candidate(
                listed_network,
                installation,
                expected,
                &transit_name,
                &local_prefix,
            ) {
                continue;
            }
            let name = listed_network
                .name
                .as_deref()
                .ok_or_else(engine_resource_mismatch)?;
            let network = self
                .inspect_network_exact(name)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            for id in network
                .containers
                .as_ref()
                .map(HashMap::keys)
                .into_iter()
                .flatten()
            {
                if !exact_container_id_text(id) {
                    return Err(engine_resource_mismatch());
                }
                attachment_ids.insert(id.clone());
            }
        }
        let listed = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.list_containers(Some(
                ListContainersOptionsBuilder::default().all(true).build(),
            )),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if listed.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        let live_ids = derive_rendered_live_ids(&listed, &listed_networks, installation, expected)?;
        let mut present_services = BTreeSet::new();
        let mut all_services_running = true;
        let mut present_oneoffs = BTreeSet::new();
        let mut local_children = 0_usize;
        let mut disposable_helpers = 0_usize;
        let mut discovered_ids = BTreeSet::new();
        let mut present_container_ids = BTreeMap::new();
        let mut namespace_targets = BTreeMap::new();
        for summary in &listed {
            if !lifecycle_container_candidate(
                summary,
                installation,
                &expected_names,
                &attachment_ids,
                &local_prefix,
            ) {
                continue;
            }
            let id = summary
                .id
                .as_deref()
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?
                .to_owned();
            if !discovered_ids.insert(id.clone()) {
                return Err(engine_resource_mismatch());
            }
            let container = self
                .inspect_container(&id)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            let name = container
                .name
                .as_deref()
                .and_then(|name| name.strip_prefix('/'))
                .ok_or_else(engine_resource_mismatch)?;
            if namespace_targets
                .insert(name.to_owned(), id.clone())
                .is_some()
            {
                return Err(engine_resource_mismatch());
            }
            let labels = container
                .config
                .as_ref()
                .and_then(|config| config.labels.as_ref())
                .ok_or_else(engine_resource_mismatch)?;
            let kind = labels.get(LABEL_RESOURCE_KIND).map(String::as_str);
            if name == lifecycle_lock_name(installation) {
                classify_lifecycle_lock(
                    &container,
                    name,
                    &lock_image.inspection_reference,
                    &lock_image.image_id,
                    &lock_image.labels,
                    installation,
                )?;
                continue;
            }
            if validate_lifecycle_disposable_helper(
                &container,
                name,
                installation,
                epoch,
                images
                    .get("automata")
                    .ok_or_else(engine_resource_mismatch)?,
                &volume_names,
            )?
            .is_some()
            {
                disposable_helpers += 1;
                continue;
            }
            if name.starts_with(&local_prefix)
                || labels.contains_key("io.automata.local.job-schema")
            {
                validate_local_docker_container_summary(summary, installation)?;
                local_children += 1;
                continue;
            }
            let service = expected_names
                .get(name)
                .copied()
                .ok_or_else(engine_resource_mismatch)?;
            let rendered = expected
                .containers
                .get(service)
                .ok_or_else(engine_resource_mismatch)?;
            let image = images
                .get(rendered.image_role)
                .ok_or_else(engine_resource_mismatch)?;
            let image_config = self
                .inspect_image(&image.image_id)
                .await?
                .and_then(|image| image.config)
                .ok_or_else(engine_resource_mismatch)?;
            if kind != rendered.labels.get(LABEL_RESOURCE_KIND).map(String::as_str) {
                return Err(engine_resource_mismatch());
            }
            validate_rendered_container(
                &container,
                name,
                &image.image_id,
                installation,
                rendered,
                expected,
                desired,
                &image_config,
                &live_ids,
                false,
            )?;
            if present_container_ids
                .insert(name.to_owned(), id.clone())
                .is_some()
            {
                return Err(engine_resource_mismatch());
            }
            if rendered.oneoff() {
                if !present_oneoffs.insert(service.to_owned()) {
                    return Err(engine_resource_mismatch());
                }
            } else {
                all_services_running &= rendered_container_is_running(&container, rendered);
                if !present_services.insert(service.to_owned()) {
                    return Err(engine_resource_mismatch());
                }
            }
        }
        if !attachment_ids.is_subset(&discovered_ids) {
            return Err(engine_resource_mismatch());
        }
        self.attest_namespace_attachment_union(
            &listed,
            installation,
            expected,
            &namespace_targets,
            &live_ids,
        )
        .await?;
        // Summary/name/label validation is only a discovery filter. Bind the
        // complete LocalDocker sibling union through the production parser and
        // exact Desired/runner authority before this census can classify any
        // topology (including a stopped-lock recovery snapshot).
        self.attest_local_docker_children(installation, desired, expected_runner_id)
            .await?;

        let mut transit = None;
        let mut present_networks = BTreeSet::new();
        for listed_network in &listed_networks {
            if !lifecycle_network_candidate(
                listed_network,
                installation,
                expected,
                &transit_name,
                &local_prefix,
            ) {
                continue;
            }
            let name = listed_network
                .name
                .as_deref()
                .ok_or_else(engine_resource_mismatch)?;
            let network = self
                .inspect_network_exact(name)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            if name == transit_name {
                validate_results_transit(&network, installation, desired, false)?;
                transit = Some(network);
                continue;
            }
            if name.starts_with(&local_prefix)
                || listed_network
                    .labels
                    .as_ref()
                    .is_some_and(|labels| labels.contains_key("io.automata.local.job-schema"))
            {
                let known_names = listed
                    .iter()
                    .filter_map(|summary| summary.names.as_ref())
                    .flatten()
                    .filter_map(|name| name.strip_prefix('/'))
                    .map(str::to_owned)
                    .collect();
                let pinned =
                    validate_local_docker_network(listed_network, installation, &known_names)?;
                validate_local_docker_network_inspect(
                    &network,
                    &pinned,
                    installation,
                    &known_names,
                )?;
                continue;
            }
            let (logical, rendered) = expected
                .networks
                .iter()
                .find(|(_, rendered)| rendered.name == name)
                .ok_or_else(engine_resource_mismatch)?;
            validate_rendered_network(
                &network,
                installation,
                rendered,
                &present_container_ids,
                live_ids.networks.get(name).map(String::as_str),
            )?;
            if !present_networks.insert(logical.clone()) {
                return Err(engine_resource_mismatch());
            }
        }
        let control = present_networks.contains("control");
        let egress = present_networks.contains("egress");
        if present_services.is_empty()
            && present_oneoffs.is_empty()
            && transit.is_none()
            && !control
            && !egress
            && local_children == 0
            && disposable_helpers == 0
        {
            return Ok(LifecycleTopology::Empty);
        }
        if present_services
            == ["postgres", "rustfs", "automata", "engine-relay", "runner"]
                .into_iter()
                .map(str::to_owned)
                .collect()
            && present_oneoffs.is_empty()
            && transit.is_some()
            && control
            && egress
            && disposable_helpers == 0
        {
            if !all_services_running {
                self.verify_installation(installation).await?;
                self.verify_selected_engine().await?;
                return Ok(LifecycleTopology::Partial);
            }
            let transit_id = transit
                .and_then(|network| network.id)
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?;
            self.attest_running_lifecycle(installation, epoch, desired, expected, &transit_id)
                .await?;
            return Ok(LifecycleTopology::Running { transit_id });
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        Ok(LifecycleTopology::Partial)
    }

    pub(in crate::init) async fn attest_results_transit(
        &self,
        installation: &Installation,
        desired: &DesiredSpec,
        expected_id: &str,
        require_empty: bool,
    ) -> Result<NetworkInspect, LocalInitError> {
        if !exact_container_id_text(expected_id) {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await?;
        let name = results_transit_name(installation);
        let network = self
            .inspect_network_exact(&name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_results_transit(&network, installation, desired, require_empty)?;
        if network.id.as_deref() != Some(expected_id) {
            return Err(engine_resource_mismatch());
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        Ok(network)
    }

    /// Removes the separately managed external transit when present, after
    /// exact contract and empty-attachment validation. Absence is idempotent.
    pub(in crate::init) async fn remove_results_transit_if_present(
        &self,
        installation: &Installation,
        desired: &DesiredSpec,
        mutation: &LifecycleMutationFence,
    ) -> Result<bool, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let name = results_transit_name(installation);
        let Some(network) = self.inspect_network_exact(&name).await? else {
            self.verify_installation(installation).await?;
            self.verify_selected_engine().await?;
            return Ok(false);
        };
        validate_results_transit(&network, installation, desired, true)?;
        let expected_id = network
            .id
            .as_deref()
            .filter(|id| exact_container_id_text(id))
            .ok_or_else(engine_resource_mismatch)?;
        let _untrusted = mutation
            .run(tokio::time::timeout(
                ENGINE_TIMEOUT,
                self.docker.remove_network(expected_id),
            ))
            .await?;
        if self.inspect_network_exact(expected_id).await?.is_some()
            || self.inspect_network_exact(&name).await?.is_some()
        {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        Ok(true)
    }

    /// Removes the fully prevalidated replaceable lifecycle topology for a
    /// confirmed reset while preserving every persistent volume.
    ///
    /// The complete discovery union is attested before the first deletion.
    /// Each subsequent deletion is pinned to the inspected immutable ID and
    /// reconciled through both ID and deterministic-name absence.
    pub(in crate::init) async fn remove_lifecycle_topology_for_reset(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        expected_runner_id: uuid::Uuid,
        holder: &LifecycleLockHolder,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        self.attest_lifecycle_lock(installation, epoch, holder)
            .await?;
        self.preflight_lifecycle_volumes(installation, epoch)
            .await?;
        let holder_lost = holder.holder_lost();
        // First validate the complete union while runner admission is still
        // live, then remove and prove that exact runner absent as the positive
        // admission fence. No helper or LocalDocker deletion may precede it.
        self.inspect_lifecycle_topology(installation, epoch, desired, expected, expected_runner_id)
            .await?;
        let live_ids = self
            .inspect_rendered_live_ids(installation, expected)
            .await?;
        let images = self
            .inspect_epoch_images(epoch)
            .await?
            .into_iter()
            .map(|image| (image.role.clone(), image))
            .collect::<BTreeMap<_, _>>();
        let runner = expected
            .containers
            .get("runner")
            .ok_or_else(engine_resource_mismatch)?;
        let runner_name = format!("{}-runner-1", installation.compose_project());
        if let Some(container) = self.inspect_container(&runner_name).await? {
            let id = exact_container_id(&container)?.to_owned();
            let image = images
                .get(runner.image_role)
                .ok_or_else(engine_resource_mismatch)?;
            let image_config = self
                .inspect_image(&image.image_id)
                .await?
                .and_then(|image| image.config)
                .ok_or_else(engine_resource_mismatch)?;
            validate_rendered_container(
                &container,
                &runner_name,
                &image.image_id,
                installation,
                runner,
                expected,
                desired,
                &image_config,
                &live_ids,
                false,
            )?;
            lifecycle_cancellation_checkpoint(&holder_lost)?;
            let options = RemoveContainerOptionsBuilder::default()
                .force(true)
                .v(false)
                .link(false)
                .build();
            let _untrusted = mutation
                .run(tokio::time::timeout(
                    ENGINE_TIMEOUT,
                    self.docker.remove_container(&id, Some(options)),
                ))
                .await?;
            if self.inspect_container(&id).await?.is_some()
                || self.inspect_container(&runner_name).await?.is_some()
            {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
        }
        self.attest_lifecycle_lock(installation, epoch, holder)
            .await?;
        self.inspect_lifecycle_topology(installation, epoch, desired, expected, expected_runner_id)
            .await?;
        self.cleanup_lifecycle_disposable_helpers(
            installation,
            epoch,
            desired,
            expected,
            expected_runner_id,
            holder,
            &holder_lost,
            mutation,
        )
        .await?;
        self.remove_local_docker_children(installation, desired, expected_runner_id, mutation)
            .await?;
        self.attest_lifecycle_lock(installation, epoch, holder)
            .await?;
        for service in [
            "engine-relay",
            "runner-enroll",
            "bootstrap-runner",
            "object-store-init",
            "automata",
            "rustfs",
            "postgres",
        ] {
            let rendered = expected
                .containers
                .get(service)
                .ok_or_else(engine_resource_mismatch)?;
            let name = if rendered.oneoff() {
                format!("{}-{service}", installation.compose_project())
            } else {
                format!("{}-{service}-1", installation.compose_project())
            };
            if let Some(container) = self.inspect_container(&name).await? {
                let id = exact_container_id(&container)?.to_owned();
                let image = images
                    .get(rendered.image_role)
                    .ok_or_else(engine_resource_mismatch)?;
                let image_config = self
                    .inspect_image(&image.image_id)
                    .await?
                    .and_then(|image| image.config)
                    .ok_or_else(engine_resource_mismatch)?;
                validate_rendered_container(
                    &container,
                    &name,
                    &image.image_id,
                    installation,
                    rendered,
                    expected,
                    desired,
                    &image_config,
                    &live_ids,
                    false,
                )?;
                let options = RemoveContainerOptionsBuilder::default()
                    .force(true)
                    .v(false)
                    .link(false)
                    .build();
                let _untrusted = mutation
                    .run(tokio::time::timeout(
                        ENGINE_TIMEOUT,
                        self.docker.remove_container(&id, Some(options)),
                    ))
                    .await?;
                if self.inspect_container(&id).await?.is_some()
                    || self.inspect_container(&name).await?.is_some()
                {
                    return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
                }
            }
            self.attest_lifecycle_lock(installation, epoch, holder)
                .await?;
        }

        for rendered in expected.networks.values() {
            let Some(network) = self.inspect_network_exact(&rendered.name).await? else {
                continue;
            };
            validate_rendered_network(
                &network,
                installation,
                rendered,
                &BTreeMap::new(),
                live_ids.networks.get(&rendered.name).map(String::as_str),
            )?;
            if network
                .containers
                .as_ref()
                .is_some_and(|containers| !containers.is_empty())
            {
                return Err(engine_resource_mismatch());
            }
            let id = network
                .id
                .as_deref()
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?
                .to_owned();
            let _untrusted = mutation
                .run(tokio::time::timeout(
                    ENGINE_TIMEOUT,
                    self.docker.remove_network(&id),
                ))
                .await?;
            if self.inspect_network_exact(&id).await?.is_some()
                || self.inspect_network_exact(&rendered.name).await?.is_some()
            {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
        }
        self.remove_results_transit_if_present(installation, desired, mutation)
            .await?;
        if self
            .inspect_lifecycle_topology(installation, epoch, desired, expected, expected_runner_id)
            .await?
            != LifecycleTopology::Empty
        {
            return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
        }
        self.preflight_lifecycle_volumes(installation, epoch)
            .await?;
        self.attest_lifecycle_lock(installation, epoch, holder)
            .await
    }

    async fn discover_local_docker_children(
        &self,
        installation: &Installation,
        expected_runner_id: uuid::Uuid,
    ) -> Result<
        (
            Vec<PinnedLocalDockerContainer>,
            Vec<PinnedLocalDockerNetwork>,
        ),
        LocalInitError,
    > {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let containers = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.list_containers(Some(
                ListContainersOptionsBuilder::default().all(true).build(),
            )),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        let networks = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker
                .list_networks(Some(ListNetworksOptionsBuilder::default().build())),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if containers.len() > MAX_ENGINE_RESOURCES || networks.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        let prefix = local_docker_name_prefix(installation);
        let mut pinned_containers = Vec::new();
        let mut known_names = BTreeSet::new();
        for summary in &containers {
            if !local_docker_candidate_container(summary, installation, &prefix) {
                continue;
            }
            let pinned = validate_local_docker_container_summary(summary, installation)?;
            if !known_names.insert(pinned.name.clone()) {
                return Err(engine_resource_mismatch());
            }
            let by_id = self
                .inspect_container(&pinned.id)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            let by_name = self
                .inspect_container(&pinned.name)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            if exact_container_id(&by_id)? != pinned.id
                || exact_container_id(&by_name)? != pinned.id
            {
                return Err(engine_resource_mismatch());
            }
            pinned_containers.push(pinned);
        }
        let mut pinned_networks = Vec::new();
        for network in &networks {
            if !local_docker_candidate_network(network, installation, &prefix) {
                continue;
            }
            let pinned = validate_local_docker_network(network, installation, &known_names)?;
            let inspected = self
                .inspect_network_exact(&pinned.id)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            validate_local_docker_network_inspect(&inspected, &pinned, installation, &known_names)?;
            pinned_networks.push(pinned);
        }

        if !pinned_containers.is_empty() || !pinned_networks.is_empty() {
            let runner_ids = pinned_containers
                .iter()
                .map(|item| item.runner_id)
                .chain(pinned_networks.iter().map(|item| item.runner_id))
                .collect::<BTreeSet<_>>();
            if runner_ids != BTreeSet::from([expected_runner_id]) {
                return Err(engine_resource_mismatch());
            }
        }

        // Re-list before mutation to close discovery races.
        let repeated_containers = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.list_containers(Some(
                ListContainersOptionsBuilder::default().all(true).build(),
            )),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        let repeated_networks = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker
                .list_networks(Some(ListNetworksOptionsBuilder::default().build())),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        let repeated_container_ids = repeated_containers
            .iter()
            .filter(|summary| local_docker_candidate_container(summary, installation, &prefix))
            .map(|summary| {
                validate_local_docker_container_summary(summary, installation).map(|item| item.id)
            })
            .collect::<Result<BTreeSet<_>, LocalInitError>>()?;
        let repeated_network_ids = repeated_networks
            .iter()
            .filter(|network| local_docker_candidate_network(network, installation, &prefix))
            .map(|network| {
                validate_local_docker_network(network, installation, &known_names)
                    .map(|item| item.id)
            })
            .collect::<Result<BTreeSet<_>, LocalInitError>>()?;
        if repeated_container_ids
            != pinned_containers
                .iter()
                .map(|item| item.id.clone())
                .collect()
            || repeated_network_ids != pinned_networks.iter().map(|item| item.id.clone()).collect()
        {
            return Err(engine_resource_mismatch());
        }

        Ok((pinned_containers, pinned_networks))
    }

    /// Recovers the sole runner authority from already-present LocalDocker
    /// custody when non-authority host material is missing during reset. The
    /// full sibling parser revalidates this value before any deletion.
    pub(in crate::init) async fn discover_lifecycle_runner_id_for_reset(
        &self,
        installation: &Installation,
    ) -> Result<Option<uuid::Uuid>, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let containers = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.list_containers(Some(
                ListContainersOptionsBuilder::default().all(true).build(),
            )),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        let networks = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker
                .list_networks(Some(ListNetworksOptionsBuilder::default().build())),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if containers.len() > MAX_ENGINE_RESOURCES || networks.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        let prefix = local_docker_name_prefix(installation);
        let mut known_names = BTreeSet::new();
        let mut runner_ids = BTreeSet::new();
        for summary in &containers {
            if !local_docker_candidate_container(summary, installation, &prefix) {
                continue;
            }
            let pinned = validate_local_docker_container_summary(summary, installation)?;
            if !known_names.insert(pinned.name) {
                return Err(engine_resource_mismatch());
            }
            runner_ids.insert(pinned.runner_id);
        }
        for network in &networks {
            if !local_docker_candidate_network(network, installation, &prefix) {
                continue;
            }
            runner_ids.insert(
                validate_local_docker_network(network, installation, &known_names)?.runner_id,
            );
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        sole_local_docker_runner_id(runner_ids)
    }

    /// Performs the production-parser LocalDocker union audit without repair.
    pub(in crate::init) async fn attest_local_docker_children(
        &self,
        installation: &Installation,
        desired: &DesiredSpec,
        expected_runner_id: uuid::Uuid,
    ) -> Result<(), LocalInitError> {
        let (containers, networks) = self
            .discover_local_docker_children(installation, expected_runner_id)
            .await?;
        if containers.is_empty() && networks.is_empty() {
            return Ok(());
        }
        let transit_name = results_transit_name(installation);
        let transit = self
            .inspect_network_exact(&transit_name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_results_transit(&transit, installation, desired, false)?;
        let transit_id = transit
            .id
            .as_deref()
            .filter(|id| exact_container_id_text(id))
            .ok_or_else(engine_resource_mismatch)?;
        let results_name = format!("{}-automata-1", installation.compose_project());
        let results_id = self
            .inspect_container(&results_name)
            .await?
            .and_then(|container| container.id)
            .filter(|id| exact_container_id_text(id))
            .ok_or_else(engine_resource_mismatch)?;
        attest_lifecycle_sibling_union(
            installation,
            desired,
            expected_runner_id,
            transit_id,
            &results_id,
            &local_docker_container_candidates(&containers),
            &local_docker_network_candidates(&networks),
        )
        .await
        .map_err(|_| engine_resource_mismatch())
    }

    /// Discovers, validates, and removes every exact LocalDocker sibling for
    /// this installation. Validation of the complete container/network union
    /// finishes before the first delete, and every delete is reconciled by
    /// exact ID plus deterministic-name absence.
    pub(in crate::init) async fn remove_local_docker_children(
        &self,
        installation: &Installation,
        desired: &DesiredSpec,
        expected_runner_id: uuid::Uuid,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        let (mut pinned_containers, pinned_networks) = self
            .discover_local_docker_children(installation, expected_runner_id)
            .await?;
        attest_lifecycle_sibling_custody_union(
            installation,
            desired,
            expected_runner_id,
            &local_docker_container_candidates(&pinned_containers),
            &local_docker_network_candidates(&pinned_networks),
        )
        .await
        .map_err(|_| engine_resource_mismatch())?;
        pinned_containers.sort_by_key(|item| local_docker_delete_rank(&item.kind));
        for pinned in &pinned_containers {
            let options = RemoveContainerOptionsBuilder::default()
                .force(true)
                .v(false)
                .link(false)
                .build();
            let _untrusted = mutation
                .run(tokio::time::timeout(
                    ENGINE_TIMEOUT,
                    self.docker.remove_container(&pinned.id, Some(options)),
                ))
                .await?;
            if self.inspect_container(&pinned.id).await?.is_some()
                || self.inspect_container(&pinned.name).await?.is_some()
            {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
        }
        for pinned in &pinned_networks {
            let current = self
                .inspect_network_exact(&pinned.id)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            if current
                .containers
                .as_ref()
                .is_some_and(|containers| !containers.is_empty())
            {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
            let _untrusted = mutation
                .run(tokio::time::timeout(
                    ENGINE_TIMEOUT,
                    self.docker.remove_network(&pinned.id),
                ))
                .await?;
            if self.inspect_network_exact(&pinned.id).await?.is_some()
                || self.inspect_network_exact(&pinned.name).await?.is_some()
            {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await
    }

    /// Removes only exact stopped disposable lifecycle helpers left behind by
    /// a manager crash. Two complete discovery/validation passes must agree
    /// before the first exact-ID deletion, and the live holder is re-attested
    /// around every mutation.
    pub(in crate::init) async fn cleanup_lifecycle_disposable_helpers(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        expected_runner_id: uuid::Uuid,
        holder: &LifecycleLockHolder,
        cancellation: &CancellationToken,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        lifecycle_cancellation_checkpoint(cancellation)?;
        self.attest_lifecycle_lock(installation, epoch, holder)
            .await?;
        self.preflight_lifecycle_volumes(installation, epoch)
            .await?;
        let first = self
            .discover_lifecycle_disposable_helpers(installation, epoch)
            .await?;
        lifecycle_cancellation_checkpoint(cancellation)?;
        let repeated = self
            .discover_lifecycle_disposable_helpers(installation, epoch)
            .await?;
        if first != repeated {
            return Err(engine_resource_mismatch());
        }
        // The complete topology/attachment union is the last read-only gate
        // before the first helper deletion. Re-pin the helper set afterwards
        // so the deletion loop consumes exactly the union that this census
        // validated, never an earlier snapshot.
        self.inspect_lifecycle_topology(installation, epoch, desired, expected, expected_runner_id)
            .await?;
        lifecycle_cancellation_checkpoint(cancellation)?;
        if self
            .discover_lifecycle_disposable_helpers(installation, epoch)
            .await?
            != first
        {
            return Err(engine_resource_mismatch());
        }

        for pinned in first {
            lifecycle_cancellation_checkpoint(cancellation)?;
            self.attest_lifecycle_lock(installation, epoch, holder)
                .await?;
            let current_by_id = self
                .inspect_container(&pinned.id)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            let current_by_name = self
                .inspect_container(&pinned.name)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            let images = self
                .inspect_epoch_images(epoch)
                .await?
                .into_iter()
                .map(|image| (image.role.clone(), image))
                .collect::<BTreeMap<_, _>>();
            let automata = images
                .get("automata")
                .ok_or_else(engine_resource_mismatch)?;
            let volumes = volume_names(installation);
            for current in [&current_by_id, &current_by_name] {
                if validate_lifecycle_disposable_helper(
                    current,
                    &pinned.name,
                    installation,
                    epoch,
                    automata,
                    &volumes,
                )? != Some(pinned.clone())
                {
                    return Err(engine_resource_mismatch());
                }
            }
            lifecycle_cancellation_checkpoint(cancellation)?;
            let options = RemoveContainerOptionsBuilder::default()
                .force(true)
                .v(false)
                .link(false)
                .build();
            let _untrusted = mutation
                .run(tokio::time::timeout(
                    ENGINE_TIMEOUT,
                    self.docker.remove_container(&pinned.id, Some(options)),
                ))
                .await?;
            if self.inspect_container(&pinned.id).await?.is_some()
                || self.inspect_container(&pinned.name).await?.is_some()
            {
                return Err(LocalInitError::new(LocalInitErrorCode::ResetRequired));
            }
            self.attest_lifecycle_lock(installation, epoch, holder)
                .await?;
        }
        if !self
            .discover_lifecycle_disposable_helpers(installation, epoch)
            .await?
            .is_empty()
        {
            return Err(engine_resource_mismatch());
        }
        self.preflight_lifecycle_volumes(installation, epoch)
            .await?;
        self.attest_lifecycle_lock(installation, epoch, holder)
            .await
    }

    async fn discover_lifecycle_disposable_helpers(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
    ) -> Result<BTreeSet<PinnedLifecycleHelper>, LocalInitError> {
        let images = self
            .inspect_epoch_images(epoch)
            .await?
            .into_iter()
            .map(|image| (image.role.clone(), image))
            .collect::<BTreeMap<_, _>>();
        let automata = images
            .get("automata")
            .ok_or_else(engine_resource_mismatch)?;
        let volumes = volume_names(installation);
        let project = installation.compose_project().to_string();
        let prefix = format!("{project}-");
        let listed = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.list_containers(Some(
                ListContainersOptionsBuilder::default().all(true).build(),
            )),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if listed.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        let mut helpers = BTreeSet::new();
        for summary in listed {
            let labels = summary.labels.as_ref().cloned().unwrap_or_default();
            let names = summary.names.as_deref().unwrap_or_default();
            let related = labels.get(LABEL_INSTALLATION_ID) == Some(&installation.id().to_string())
                || labels.get(LABEL_INSTALLATION_KEY)
                    == Some(&installation.selector_key().to_string())
                || labels.get(LABEL_COMPOSE_PROJECT) == Some(&project)
                || names.iter().any(|name| {
                    let name = name.trim_start_matches('/');
                    name == lifecycle_material_attester_name(installation)
                        || name == format!("{project}-desired-reader")
                        || (name.starts_with(&prefix)
                            && (name.ends_with("-cas") || name.ends_with("-cas-digest")))
                });
            if !related {
                continue;
            }
            let kind = labels.get(LABEL_RESOURCE_KIND).map(String::as_str);
            let helper_kind = matches!(
                kind,
                Some(
                    LIFECYCLE_ATTESTER_KIND
                        | DESIRED_READER_KIND
                        | CAS_WRITER_KIND
                        | CAS_DIGEST_READER_KIND
                )
            );
            let helper_name = names.iter().any(|name| {
                let name = name.trim_start_matches('/');
                name == lifecycle_material_attester_name(installation)
                    || name == format!("{project}-desired-reader")
                    || (name.starts_with(&prefix)
                        && (name.ends_with("-cas") || name.ends_with("-cas-digest")))
            });
            if !helper_kind && !helper_name {
                continue;
            }
            let id = summary
                .id
                .as_deref()
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?;
            if names.len() != 1 {
                return Err(engine_resource_mismatch());
            }
            let name = names[0]
                .strip_prefix('/')
                .filter(|name| !name.is_empty())
                .ok_or_else(engine_resource_mismatch)?;
            let container = self
                .inspect_container(id)
                .await?
                .ok_or_else(engine_resource_mismatch)?;
            let pinned = validate_lifecycle_disposable_helper(
                &container,
                name,
                installation,
                epoch,
                automata,
                &volumes,
            )?
            .ok_or_else(engine_resource_mismatch)?;
            if !helpers.insert(pinned) {
                return Err(engine_resource_mismatch());
            }
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        Ok(helpers)
    }

    async fn inspect_network_exact(
        &self,
        name: &str,
    ) -> Result<Option<NetworkInspect>, LocalInitError> {
        match tokio::time::timeout(ENGINE_TIMEOUT, self.docker.inspect_network(name, None)).await {
            Ok(Ok(network)) => Ok(Some(network)),
            Ok(Err(error)) if not_found(&error) => Ok(None),
            _ => Err(LocalInitError::new(LocalInitErrorCode::EngineUnavailable)),
        }
    }

    async fn lifecycle_quiescent_identity_census(
        &self,
        installation: &Installation,
    ) -> Result<LifecycleIdentityCensus, LocalInitError> {
        self.lifecycle_identity_census(installation, true).await
    }

    async fn lifecycle_identity_census(
        &self,
        installation: &Installation,
        require_identity: bool,
    ) -> Result<LifecycleIdentityCensus, LocalInitError> {
        let installation_id = installation.id().to_string();
        let installation_key = installation.selector_key().to_string();
        let project = installation.compose_project().to_string();
        let project_prefix = format!("{project}-");
        let local_prefix = local_docker_name_prefix(installation);
        let related = |labels: &HashMap<String, String>| {
            labels.get(LABEL_INSTALLATION_ID) == Some(&installation_id)
                || labels.get(LABEL_INSTALLATION_KEY) == Some(&installation_key)
                || labels.get(LABEL_COMPOSE_PROJECT) == Some(&project)
                || labels.get("com.docker.compose.project") == Some(&project)
        };
        let listed = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.list_containers(Some(
                ListContainersOptionsBuilder::default().all(true).build(),
            )),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if listed.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        let mut containers = BTreeSet::new();
        for summary in listed {
            let labels = summary.labels.as_ref().cloned().unwrap_or_default();
            let names = summary.names.as_deref().unwrap_or_default();
            if !related(&labels)
                && !names.iter().any(|name| {
                    let name = name.trim_start_matches('/');
                    name.starts_with(&project_prefix) || name.starts_with(&local_prefix)
                })
            {
                continue;
            }
            let id = summary
                .id
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?;
            if names.len() != 1 {
                return Err(engine_resource_mismatch());
            }
            let name = names[0]
                .strip_prefix('/')
                .filter(|name| !name.is_empty())
                .ok_or_else(engine_resource_mismatch)?
                .to_owned();
            if !containers.insert((
                id,
                name,
                summary.state.map(|state| state.to_string()),
                summary.status,
            )) {
                return Err(engine_resource_mismatch());
            }
        }
        let listed_networks = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker
                .list_networks(Some(ListNetworksOptionsBuilder::default().build())),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        if listed_networks.len() > MAX_ENGINE_RESOURCES {
            return Err(engine_resource_mismatch());
        }
        let mut networks = BTreeSet::new();
        for network in listed_networks {
            let labels = network.labels.as_ref().cloned().unwrap_or_default();
            let name = network.name.unwrap_or_default();
            if !related(&labels)
                && !name.starts_with(&project_prefix)
                && !name.starts_with(&local_prefix)
            {
                continue;
            }
            let id = network
                .id
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?;
            if name.is_empty() || !networks.insert((id, name)) {
                return Err(engine_resource_mismatch());
            }
        }
        if require_identity {
            self.verify_installation(installation).await?;
        }
        self.verify_selected_engine().await?;
        Ok(LifecycleIdentityCensus {
            containers,
            networks,
        })
    }

    pub(in crate::init) async fn attest_reset_union_absent(
        &self,
        installation: &Installation,
    ) -> Result<(), LocalInitError> {
        let expected_volumes = BTreeSet::new();
        let first_volumes = self
            .inspect_lifecycle_volume_union(installation, &expected_volumes)
            .await?;
        let first = self.lifecycle_identity_census(installation, false).await?;
        let repeated_volumes = self
            .inspect_lifecycle_volume_union(installation, &expected_volumes)
            .await?;
        let repeated = self.lifecycle_identity_census(installation, false).await?;
        if !first_volumes.is_empty()
            || first_volumes != repeated_volumes
            || first != repeated
            || !first.containers.is_empty()
            || !first.networks.is_empty()
            || self
                .adapter
                .inspect_identity(installation.name())
                .await
                .map_err(|_| engine_resource_mismatch())?
                .is_some()
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await
    }

    /// Removes any exact prior instance of a lifecycle one-off so a replay can
    /// issue the same idempotent operation without name ambiguity.
    pub(in crate::init) async fn reconcile_lifecycle_oneoff(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        service: &'static str,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        let name = lifecycle_oneoff_name(installation, service)?;
        let Some(container) = self.inspect_container(&name).await? else {
            return Ok(());
        };
        let id = exact_container_id(&container)?.to_owned();
        self.validate_lifecycle_oneoff(&container, installation, epoch, desired, expected, service)
            .await?;
        self.wait_lifecycle_oneoff(&id).await?;
        self.remove_lifecycle_oneoff_and_prove_absent(&name, &id, mutation)
            .await
    }

    /// Waits for one exact Compose-created one-off, validates its terminal
    /// status and bounded logs, then removes it by pinned ID and proves both
    /// ID and deterministic name absent.
    pub(in crate::init) async fn finish_lifecycle_oneoff(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        service: &'static str,
        mutation: &LifecycleMutationFence,
    ) -> Result<Vec<u8>, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let name = lifecycle_oneoff_name(installation, service)?;
        let container = self
            .inspect_container(&name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        let id = exact_container_id(&container)?.to_owned();
        self.validate_lifecycle_oneoff(&container, installation, epoch, desired, expected, service)
            .await?;
        let status = self.wait_lifecycle_oneoff(&id).await?;
        let stopped = self
            .inspect_container(&id)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        self.validate_lifecycle_oneoff(&stopped, installation, epoch, desired, expected, service)
            .await?;
        let logs = self.lifecycle_oneoff_logs(&id).await?;
        let cleanup = self
            .remove_lifecycle_oneoff_and_prove_absent(&name, &id, mutation)
            .await;
        cleanup?;
        if status != 0 {
            return Err(LocalInitError::new(
                LocalInitErrorCode::MaterializationFailed,
            ));
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        Ok(logs)
    }

    async fn validate_lifecycle_oneoff(
        &self,
        container: &bollard::models::ContainerInspectResponse,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        service: &'static str,
    ) -> Result<(), LocalInitError> {
        let contract = lifecycle_oneoff_contract(service)?;
        let image = self
            .inspect_epoch_images(epoch)
            .await?
            .into_iter()
            .find(|image| image.role == contract.image_role)
            .ok_or_else(engine_resource_mismatch)?;
        let name = lifecycle_oneoff_name(installation, service)?;
        let rendered = expected
            .containers
            .get(service)
            .filter(|container| container.oneoff())
            .ok_or_else(engine_resource_mismatch)?;
        let image_config = self
            .inspect_image(&image.image_id)
            .await?
            .and_then(|image| image.config)
            .ok_or_else(engine_resource_mismatch)?;
        let live_ids = self
            .inspect_rendered_live_ids(installation, expected)
            .await?;
        validate_rendered_container(
            container,
            &name,
            &image.image_id,
            installation,
            rendered,
            expected,
            desired,
            &image_config,
            &live_ids,
            false,
        )
    }

    async fn wait_lifecycle_oneoff(&self, id: &str) -> Result<i64, LocalInitError> {
        let options = WaitContainerOptionsBuilder::default()
            .condition("not-running")
            .build();
        let mut wait = self.docker.wait_container(id, Some(options));
        tokio::time::timeout(HELPER_TIMEOUT, async {
            let result = wait
                .next()
                .await
                .ok_or_else(engine_resource_mismatch)?
                .map_err(|_| engine_resource_mismatch())?;
            if result.error.is_some() || wait.next().await.is_some() {
                return Err(engine_resource_mismatch());
            }
            Ok(result.status_code)
        })
        .await
        .map_err(|_| engine_unavailable())?
    }

    async fn lifecycle_oneoff_logs(&self, id: &str) -> Result<Vec<u8>, LocalInitError> {
        let options = LogsOptionsBuilder::default()
            .follow(false)
            .stdout(true)
            .stderr(true)
            .timestamps(false)
            .tail("all")
            .build();
        let mut frames = self.docker.logs(id, Some(options));
        tokio::time::timeout(ENGINE_TIMEOUT, async {
            let mut bytes = Vec::new();
            while let Some(frame) = frames.next().await {
                let frame = frame.map_err(|_| engine_resource_mismatch())?;
                if !matches!(frame, LogOutput::StdOut { .. } | LogOutput::StdErr { .. })
                    || frame.as_ref().len() > MAX_ONEOFF_LOG_BYTES.saturating_sub(bytes.len())
                {
                    return Err(engine_resource_mismatch());
                }
                bytes.extend_from_slice(frame.as_ref());
            }
            Ok(bytes)
        })
        .await
        .map_err(|_| engine_unavailable())?
    }

    async fn remove_lifecycle_oneoff_and_prove_absent(
        &self,
        name: &str,
        id: &str,
        mutation: &LifecycleMutationFence,
    ) -> Result<(), LocalInitError> {
        let options = RemoveContainerOptionsBuilder::default()
            .force(true)
            .v(false)
            .build();
        let _untrusted = mutation
            .run(tokio::time::timeout(
                ENGINE_TIMEOUT,
                self.docker.remove_container(id, Some(options)),
            ))
            .await?;
        if self.inspect_container(id).await?.is_some()
            || self.inspect_container(name).await?.is_some()
        {
            return Err(engine_resource_mismatch());
        }
        self.verify_selected_engine().await
    }

    /// Attests one exact running Compose service and returns its pinned ID.
    pub(in crate::init) async fn attest_lifecycle_service(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        service: &'static str,
    ) -> Result<String, LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_installation(installation).await?;
        let name = format!("{}-{service}-1", installation.compose_project());
        let container = self
            .inspect_container(&name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        let id = exact_container_id(&container)?.to_owned();
        let rendered = expected
            .containers
            .get(service)
            .filter(|container| !container.oneoff())
            .ok_or_else(engine_resource_mismatch)?;
        let image = self
            .inspect_epoch_images(epoch)
            .await?
            .into_iter()
            .find(|image| image.role == rendered.image_role)
            .ok_or_else(engine_resource_mismatch)?;
        let image_config = self
            .inspect_image(&image.image_id)
            .await?
            .and_then(|image| image.config)
            .ok_or_else(engine_resource_mismatch)?;
        let live_ids = self
            .inspect_rendered_live_ids(installation, expected)
            .await?;
        validate_rendered_container(
            &container,
            &name,
            &image.image_id,
            installation,
            rendered,
            expected,
            desired,
            &image_config,
            &live_ids,
            true,
        )?;
        let by_id = self
            .inspect_container(&id)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        if by_id != container {
            return Err(engine_resource_mismatch());
        }
        self.verify_installation(installation).await?;
        self.verify_selected_engine().await?;
        Ok(id)
    }

    /// Attests all five steady services and the two exact lifecycle networks.
    pub(in crate::init) async fn attest_running_lifecycle(
        &self,
        installation: &Installation,
        epoch: &ImmutableEpoch,
        desired: &DesiredSpec,
        expected: &ExpectedLifecycleTopology,
        transit_id: &str,
    ) -> Result<(), LocalInitError> {
        for service in ["postgres", "rustfs", "automata", "engine-relay", "runner"] {
            self.attest_lifecycle_service(installation, epoch, desired, expected, service)
                .await?;
        }
        self.attest_results_transit(installation, desired, transit_id, false)
            .await?;
        self.attest_control_network(installation, desired).await?;
        self.attest_egress_network(installation, desired).await?;
        Ok(())
    }

    async fn attest_control_network(
        &self,
        installation: &Installation,
        desired: &DesiredSpec,
    ) -> Result<(), LocalInitError> {
        let name = format!("{}-control", installation.compose_project());
        let network = self
            .inspect_network_exact(&name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_control_network(&network, installation, desired)
    }

    async fn attest_egress_network(
        &self,
        installation: &Installation,
        desired: &DesiredSpec,
    ) -> Result<(), LocalInitError> {
        let name = format!("{}-egress", installation.compose_project());
        let network = self
            .inspect_network_exact(&name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_egress_network(&network, installation, desired)
    }
}

fn validate_lifecycle_daemon_info(info: &LifecycleDaemonInfo) -> Result<(), LocalInitError> {
    let security = info
        .security_options
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let required = BTreeSet::from([
        "name=cgroupns",
        "name=seccomp,profile=builtin",
        "name=userns",
    ]);
    let allowed = BTreeSet::from([
        "name=cgroupns",
        "name=no-new-privileges",
        "name=seccomp,profile=builtin",
        "name=userns",
    ]);
    if security.len() != info.security_options.len()
        || !required.is_subset(&security)
        || !security.is_subset(&allowed)
        || !info.memory_limit
        || !info.swap_limit
        || !info.cpu_cfs_period
        || !info.cpu_cfs_quota
        || !info.pids_limit
        || info.cgroup_version != "2"
        || info.live_restore_enabled
        || info.default_runtime != "runc"
        || info
            .default_ulimits
            .as_ref()
            .is_some_and(|limits| !limits.is_empty())
    {
        Err(engine_unavailable())
    } else {
        Ok(())
    }
}

struct PinnedLocalDockerContainer {
    id: String,
    name: String,
    kind: String,
    runner_id: uuid::Uuid,
}

struct PinnedLocalDockerNetwork {
    id: String,
    name: String,
    runner_id: uuid::Uuid,
}

fn local_docker_container_candidates(
    containers: &[PinnedLocalDockerContainer],
) -> Vec<LifecycleSiblingContainer> {
    containers
        .iter()
        .map(|item| LifecycleSiblingContainer {
            id: item.id.clone(),
            name: item.name.clone(),
            kind: item.kind.clone(),
        })
        .collect()
}

fn local_docker_network_candidates(
    networks: &[PinnedLocalDockerNetwork],
) -> Vec<LifecycleSiblingNetwork> {
    networks
        .iter()
        .map(|item| LifecycleSiblingNetwork {
            id: item.id.clone(),
            name: item.name.clone(),
        })
        .collect()
}

fn sole_local_docker_runner_id(
    runner_ids: BTreeSet<uuid::Uuid>,
) -> Result<Option<uuid::Uuid>, LocalInitError> {
    if runner_ids.len() > 1 {
        Err(engine_resource_mismatch())
    } else {
        Ok(runner_ids.into_iter().next())
    }
}

struct RenderedLiveIds {
    control: Option<String>,
    networks: BTreeMap<String, String>,
    none_network: String,
}

#[derive(Eq, PartialEq)]
struct LifecycleIdentityCensus {
    containers: BTreeSet<(String, String, Option<String>, Option<String>)>,
    networks: BTreeSet<(String, String)>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PinnedLifecycleHelper {
    id: String,
    name: String,
}

async fn exact_attachment_set(
    engine: &InitEngine<'_>,
    volume_name: &str,
) -> Result<BTreeSet<String>, LocalInitError> {
    let attachments = engine.volume_attachments(volume_name).await?;
    let mut exact = BTreeSet::new();
    for id in attachments {
        if !exact_container_id_text(&id) || !exact.insert(id) {
            return Err(engine_resource_mismatch());
        }
    }
    Ok(exact)
}

fn cas_target_for_slug(slug: &str) -> Option<CasTarget> {
    [
        CasTarget::BootstrapRequest,
        CasTarget::BootstrapToken,
        CasTarget::RelayBinding,
        CasTarget::RunnerConfig,
        CasTarget::RunnerS3AccessKey,
        CasTarget::RunnerS3Ca,
        CasTarget::RunnerS3SecretKey,
        CasTarget::RunnerSpoolKey,
    ]
    .into_iter()
    .find(|target| target.slug() == slug)
}

fn stopped_disposable_state_is_quiescent(
    container: &bollard::models::ContainerInspectResponse,
) -> bool {
    container.state.as_ref().is_some_and(|state| {
        state.running == Some(false)
            && state.pid.is_none_or(|pid| pid == 0)
            && state.paused == Some(false)
            && state.restarting == Some(false)
            && state.dead == Some(false)
            && state.oom_killed == Some(false)
            && state.error.as_deref().is_none_or(str::is_empty)
    })
}

fn lifecycle_cancellation_checkpoint(
    cancellation: &CancellationToken,
) -> Result<(), LocalInitError> {
    if cancellation.is_cancelled() {
        Err(LocalInitError::new(LocalInitErrorCode::Cancelled))
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_lifecycle_disposable_helper(
    container: &bollard::models::ContainerInspectResponse,
    name: &str,
    installation: &Installation,
    epoch: &ImmutableEpoch,
    automata: &SealedImageStatus,
    volumes: &BTreeMap<VolumeRole, String>,
) -> Result<Option<PinnedLifecycleHelper>, LocalInitError> {
    let id = exact_container_id(container)?.to_owned();
    let labels = container
        .config
        .as_ref()
        .and_then(|config| config.labels.as_ref())
        .into_iter()
        .flatten()
        .filter(|(key, _)| key.starts_with("io.automata.local."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let kind = labels.get(LABEL_RESOURCE_KIND).map(String::as_str);
    let project = installation.compose_project();
    let recognized = match kind {
        Some(LIFECYCLE_ATTESTER_KIND) if name == lifecycle_material_attester_name(installation) => {
            let expected_labels =
                lifecycle_material_attester_labels(installation, epoch.fingerprint());
            validate_helper(
                container,
                &id,
                name,
                &automata.inspection_reference,
                &automata.image_id,
                volumes,
                &expected_labels,
            )
            .map_err(|_| engine_resource_mismatch())?;
            true
        }
        Some(DESIRED_READER_KIND) if name == format!("{project}-desired-reader") => {
            let desired_volume = volumes
                .get(&VolumeRole::Desired)
                .ok_or_else(engine_resource_mismatch)?;
            validate_desired_reader(
                container,
                &id,
                name,
                &automata.inspection_reference,
                &automata.image_id,
                desired_volume,
                &desired_reader_labels(installation, epoch.fingerprint()),
            )?;
            true
        }
        Some(CAS_DIGEST_READER_KIND) => {
            let prefix = format!("{project}-");
            let slug = name
                .strip_prefix(&prefix)
                .and_then(|name| name.strip_suffix("-cas-digest"));
            let target = slug
                .and_then(cas_target_for_slug)
                .ok_or_else(engine_resource_mismatch)?;
            let volume = volumes
                .get(&cas_volume_role(target))
                .ok_or_else(engine_resource_mismatch)?;
            validate_cas_digest_reader(
                container,
                &id,
                name,
                &automata.inspection_reference,
                &automata.image_id,
                volume,
                &cas_digest_reader_labels(installation, epoch, target),
            )?;
            true
        }
        Some(CAS_WRITER_KIND) => {
            let prefix = format!("{project}-");
            let slug = name
                .strip_prefix(&prefix)
                .and_then(|name| name.strip_suffix("-cas"));
            let target = slug
                .and_then(cas_target_for_slug)
                .ok_or_else(engine_resource_mismatch)?;
            let expected = labels
                .get("io.automata.local.cas-expected-sha256")
                .ok_or_else(engine_resource_mismatch)?;
            let replacement = labels
                .get("io.automata.local.cas-replacement-sha256")
                .ok_or_else(engine_resource_mismatch)?;
            let expected_plan = epoch.desired_plan_sha256().map(|digest| digest.to_string());
            if (expected != "absent"
                && expected
                    .parse::<Sha256Digest>()
                    .ok()
                    .is_none_or(|digest| digest.to_string() != *expected))
                || replacement
                    .parse::<Sha256Digest>()
                    .ok()
                    .is_none_or(|digest| digest.to_string() != *replacement)
                || labels.len() != 10
                || labels.get(LABEL_MANAGED).map(String::as_str) != Some("true")
                || labels.get(LABEL_INSTALLATION_ID) != Some(&installation.id().to_string())
                || labels.get(LABEL_INSTALLATION_KEY)
                    != Some(&installation.selector_key().to_string())
                || labels.get(LABEL_COMPOSE_PROJECT) != Some(&project.to_string())
                || labels.get(LABEL_EPOCH) != Some(&epoch.fingerprint().to_string())
                || labels.get(LABEL_PLAN) != expected_plan.as_ref()
                || labels
                    .get("io.automata.local.cas-target")
                    .map(String::as_str)
                    != Some(target.slug())
            {
                return Err(engine_resource_mismatch());
            }
            let volume = volumes
                .get(&cas_volume_role(target))
                .ok_or_else(engine_resource_mismatch)?;
            let user = cas_writer_user(target);
            let cap_add = if user == "0:0" {
                vec!["DAC_OVERRIDE".to_owned()]
            } else {
                Vec::new()
            };
            validate_cas_writer(
                container,
                &id,
                name,
                &automata.inspection_reference,
                &automata.image_id,
                volume,
                user,
                &cap_add,
                &labels,
            )?;
            true
        }
        _ => false,
    };
    if !recognized {
        return Ok(None);
    }
    if !stopped_disposable_state_is_quiescent(container) {
        return Err(engine_resource_mismatch());
    }
    Ok(Some(PinnedLifecycleHelper {
        id,
        name: name.to_owned(),
    }))
}

fn lifecycle_container_candidate(
    summary: &ContainerSummary,
    installation: &Installation,
    expected_names: &BTreeMap<String, &str>,
    attachment_ids: &BTreeSet<String>,
    local_prefix: &str,
) -> bool {
    let names = summary.names.as_ref().into_iter().flatten();
    let deterministic = names.clone().any(|name| {
        let name = name.trim_start_matches('/');
        expected_names.contains_key(name)
            || name == lifecycle_lock_name(installation)
            || lifecycle_disposable_helper_name(name, installation)
            || name.starts_with(local_prefix)
    });
    let labeled = summary.labels.as_ref().is_some_and(|labels| {
        labels.get("com.docker.compose.project")
            == Some(&installation.compose_project().to_string())
            || labels.get(LABEL_INSTALLATION_ID) == Some(&installation.id().to_string())
            || labels.get(LABEL_INSTALLATION_KEY) == Some(&installation.selector_key().to_string())
            || labels.get(LABEL_COMPOSE_PROJECT)
                == Some(&installation.compose_project().to_string())
    });
    deterministic
        || labeled
        || summary
            .id
            .as_ref()
            .is_some_and(|id| attachment_ids.contains(id))
}

fn lifecycle_disposable_helper_name(name: &str, installation: &Installation) -> bool {
    let project = installation.compose_project();
    name == format!("{project}-init-materializer")
        || name == format!("{project}-material-attester")
        || name == format!("{project}-desired-reader")
        || (name.starts_with(&format!("{project}-"))
            && (name.ends_with("-cas") || name.ends_with("-cas-digest")))
}

fn lifecycle_network_candidate(
    network: &Network,
    installation: &Installation,
    expected: &ExpectedLifecycleTopology,
    transit_name: &str,
    local_prefix: &str,
) -> bool {
    let deterministic = network.name.as_deref().is_some_and(|name| {
        name == transit_name
            || name.starts_with(local_prefix)
            || expected
                .networks
                .values()
                .any(|expected| expected.name == name)
    });
    let labeled = network.labels.as_ref().is_some_and(|labels| {
        labels.get("com.docker.compose.project")
            == Some(&installation.compose_project().to_string())
            || labels.get(LABEL_INSTALLATION_ID) == Some(&installation.id().to_string())
            || labels.get(LABEL_INSTALLATION_KEY) == Some(&installation.selector_key().to_string())
            || labels.get(LABEL_COMPOSE_PROJECT)
                == Some(&installation.compose_project().to_string())
    });
    deterministic || labeled
}

#[allow(clippy::too_many_lines)]
fn validate_rendered_network(
    network: &NetworkInspect,
    installation: &Installation,
    expected: &ExpectedNetwork,
    expected_container_ids: &BTreeMap<String, String>,
    expected_id: Option<&str>,
) -> Result<(), LocalInitError> {
    let id = network
        .id
        .as_deref()
        .filter(|id| exact_container_id_text(id))
        .ok_or_else(engine_resource_mismatch)?;
    if expected_id != Some(id) {
        return Err(engine_resource_mismatch());
    }
    let labels = network
        .labels
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let managed = labels
        .iter()
        .filter(|(key, _)| key.starts_with("io.automata.local."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let options = network
        .options
        .as_ref()
        .into_iter()
        .flatten()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let ipam = network.ipam.as_ref().ok_or_else(engine_resource_mismatch)?;
    let configs = ipam
        .config
        .as_deref()
        .ok_or_else(engine_resource_mismatch)?;
    if network.name.as_deref() != Some(expected.name.as_str())
        || network.scope.as_deref() != Some("local")
        || network.driver.as_deref() != Some(expected.driver.as_str())
        || network.internal != Some(expected.internal)
        || network.attachable != Some(expected.attachable)
        || network.enable_ipv4 != Some(true)
        || network.enable_ipv6 != Some(expected.enable_ipv6)
        || network.ingress != Some(false)
        || network.config_only != Some(false)
        || network.config_from.as_ref().is_some_and(|reference| {
            reference
                .network
                .as_deref()
                .is_some_and(|network| !network.is_empty())
        })
        || options != expected.driver_options
        || ipam.driver.as_deref() != Some(expected.ipam_driver.as_str())
        || ipam
            .options
            .as_ref()
            .is_some_and(|options| !options.is_empty())
        || configs
            != [IpamConfig {
                subnet: Some(expected.subnet.clone()),
                gateway: Some(expected.gateway.clone()),
                ip_range: None,
                auxiliary_addresses: None,
            }]
        || managed != expected.labels
        || labels.get("com.docker.compose.project").map(String::as_str)
            != Some(installation.compose_project().as_str())
    {
        return Err(engine_resource_mismatch());
    }
    for endpoint in network
        .containers
        .as_ref()
        .into_iter()
        .flatten()
        .map(|(id, endpoint)| (id, endpoint))
    {
        let name = endpoint
            .1
            .name
            .as_deref()
            .ok_or_else(engine_resource_mismatch)?;
        if !exact_container_id_text(endpoint.0)
            || expected_container_ids.get(name).map(String::as_str) != Some(endpoint.0)
        {
            return Err(engine_resource_mismatch());
        }
    }
    Ok(())
}

fn local_docker_name_prefix(installation: &Installation) -> String {
    format!("automata-local-{}-", installation.id().as_uuid().simple())
}

fn local_docker_candidate_container(
    summary: &ContainerSummary,
    installation: &Installation,
    prefix: &str,
) -> bool {
    summary
        .names
        .as_ref()
        .into_iter()
        .flatten()
        .any(|name| name.trim_start_matches('/').starts_with(prefix))
        || summary.labels.as_ref().is_some_and(|labels| {
            labels.get("io.automata.local.job-schema").is_some()
                && labels.get(LABEL_INSTALLATION_ID) == Some(&installation.id().to_string())
        })
}

fn local_docker_candidate_network(
    network: &Network,
    installation: &Installation,
    prefix: &str,
) -> bool {
    network
        .name
        .as_deref()
        .is_some_and(|name| name.starts_with(prefix))
        || network.labels.as_ref().is_some_and(|labels| {
            labels.get("io.automata.local.job-schema").is_some()
                && labels.get(LABEL_INSTALLATION_ID) == Some(&installation.id().to_string())
        })
}

fn validate_local_docker_container_summary(
    summary: &ContainerSummary,
    installation: &Installation,
) -> Result<PinnedLocalDockerContainer, LocalInitError> {
    let id = summary
        .id
        .as_deref()
        .filter(|id| exact_container_id_text(id))
        .ok_or_else(engine_resource_mismatch)?
        .to_owned();
    let names = summary
        .names
        .as_deref()
        .ok_or_else(engine_resource_mismatch)?;
    if names.len() != 1 {
        return Err(engine_resource_mismatch());
    }
    let name = names[0]
        .strip_prefix('/')
        .ok_or_else(engine_resource_mismatch)?
        .to_owned();
    let labels = summary
        .labels
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let (expected_name, kind, runner_id) = validate_local_docker_labels(labels, installation)?;
    if name != expected_name || kind == "results-front-network" {
        return Err(engine_resource_mismatch());
    }
    Ok(PinnedLocalDockerContainer {
        id,
        name,
        kind,
        runner_id,
    })
}

fn validate_local_docker_network(
    network: &Network,
    installation: &Installation,
    _known_container_names: &BTreeSet<String>,
) -> Result<PinnedLocalDockerNetwork, LocalInitError> {
    let id = network
        .id
        .as_deref()
        .filter(|id| exact_container_id_text(id))
        .ok_or_else(engine_resource_mismatch)?
        .to_owned();
    let name = network
        .name
        .as_deref()
        .ok_or_else(engine_resource_mismatch)?
        .to_owned();
    let labels = network
        .labels
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let (expected_name, kind, runner_id) = validate_local_docker_labels(labels, installation)?;
    if name != expected_name || kind != "results-front-network" {
        return Err(engine_resource_mismatch());
    }
    Ok(PinnedLocalDockerNetwork {
        id,
        name,
        runner_id,
    })
}

fn validate_local_docker_network_inspect(
    network: &NetworkInspect,
    pinned: &PinnedLocalDockerNetwork,
    installation: &Installation,
    known_container_names: &BTreeSet<String>,
) -> Result<(), LocalInitError> {
    let labels = network
        .labels
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let (expected_name, kind, _) = validate_local_docker_labels(labels, installation)?;
    let attached = network
        .containers
        .as_ref()
        .into_iter()
        .flatten()
        .map(|(_, endpoint)| endpoint.name.clone().ok_or_else(engine_resource_mismatch))
        .collect::<Result<BTreeSet<_>, LocalInitError>>()?;
    if network.id.as_deref() != Some(pinned.id.as_str())
        || network.name.as_deref() != Some(pinned.name.as_str())
        || expected_name != pinned.name
        || kind != "results-front-network"
        || !attached.is_subset(known_container_names)
    {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

fn validate_local_docker_labels(
    labels: &HashMap<String, String>,
    installation: &Installation,
) -> Result<(String, String, uuid::Uuid), LocalInitError> {
    const KEYS: [&str; 15] = [
        LABEL_MANAGED,
        "io.automata.local.job-schema",
        LABEL_INSTALLATION_ID,
        LABEL_INSTALLATION_KEY,
        LABEL_COMPOSE_PROJECT,
        "io.automata.local.runner-id",
        "io.automata.local.custody-kind",
        "io.automata.local.slot",
        "io.automata.local.operation-id",
        "io.automata.local.generation",
        "io.automata.local.profile",
        "io.automata.local.profile-sha256",
        "io.automata.local.spec-sha256",
        "io.automata.local.realized-sha256",
        LABEL_RESOURCE_KIND,
    ];
    let managed = labels
        .iter()
        .filter(|(key, _)| key.starts_with("io.automata.local."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    if managed.keys().any(|key| !KEYS.contains(&key.as_str()))
        || managed.get(LABEL_MANAGED).map(String::as_str) != Some("true")
        || managed
            .get("io.automata.local.job-schema")
            .map(String::as_str)
            != Some("2")
        || managed.get(LABEL_INSTALLATION_ID) != Some(&installation.id().to_string())
        || managed.get(LABEL_INSTALLATION_KEY) != Some(&installation.selector_key().to_string())
        || managed.get(LABEL_COMPOSE_PROJECT) != Some(&installation.compose_project().to_string())
    {
        return Err(engine_resource_mismatch());
    }
    let operation_text = managed
        .get("io.automata.local.operation-id")
        .ok_or_else(engine_resource_mismatch)?;
    let operation_id = operation_text
        .parse::<OperationId>()
        .ok()
        .filter(|value| value.to_string() == *operation_text)
        .ok_or_else(engine_resource_mismatch)?;
    let generation_text = managed
        .get("io.automata.local.generation")
        .ok_or_else(engine_resource_mismatch)?;
    let generation = generation_text
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && value.to_string() == *generation_text)
        .ok_or_else(engine_resource_mismatch)?;
    let runner_text = managed
        .get("io.automata.local.runner-id")
        .ok_or_else(engine_resource_mismatch)?;
    let runner_id = uuid::Uuid::parse_str(runner_text)
        .ok()
        .filter(|value| value.hyphenated().to_string() == *runner_text)
        .ok_or_else(engine_resource_mismatch)?;
    if runner_id.is_nil()
        || managed
            .get("io.automata.local.profile")
            .is_none_or(String::is_empty)
        || managed
            .get("io.automata.local.profile-sha256")
            .and_then(|value| value.parse::<Sha256Digest>().ok())
            .is_none()
        || managed
            .get("io.automata.local.spec-sha256")
            .and_then(|value| value.parse::<Sha256Digest>().ok())
            .is_none()
        || managed
            .get("io.automata.local.realized-sha256")
            .and_then(|value| value.parse::<Sha256Digest>().ok())
            .is_none()
    {
        return Err(engine_resource_mismatch());
    }
    let custody = managed
        .get("io.automata.local.custody-kind")
        .map(String::as_str)
        .ok_or_else(engine_resource_mismatch)?;
    match custody {
        "profile-admission"
            if managed.len() == 14 && !managed.contains_key("io.automata.local.slot") => {}
        "job" if managed.len() == 15 => {
            let slot = managed
                .get("io.automata.local.slot")
                .and_then(|value| value.parse::<u16>().ok())
                .filter(|value| *value > 0 && *value <= crate::MAXIMUM_LOCAL_DOCKER_JOB_SLOTS)
                .ok_or_else(engine_resource_mismatch)?;
            if slot.to_string() != managed["io.automata.local.slot"] {
                return Err(engine_resource_mismatch());
            }
        }
        _ => return Err(engine_resource_mismatch()),
    }
    let kind = managed
        .get(LABEL_RESOURCE_KIND)
        .cloned()
        .ok_or_else(engine_resource_mismatch)?;
    let suffix = match kind.as_str() {
        "job-container" => "job",
        "guest-source" => "guest-source",
        "results-proxy-container" => "results-proxy",
        "results-front-network" => "results-front",
        _ => return Err(engine_resource_mismatch()),
    };
    let expected_name = format!(
        "automata-local-{}-{}-{generation}-{suffix}",
        installation.id().as_uuid().simple(),
        operation_id.as_uuid().simple(),
    );
    Ok((expected_name, kind, runner_id))
}

fn local_docker_delete_rank(kind: &str) -> u8 {
    match kind {
        "job-container" => 0,
        "guest-source" => 1,
        "results-proxy-container" => 2,
        _ => 3,
    }
}

fn derive_rendered_live_ids(
    containers: &[ContainerSummary],
    networks: &[Network],
    installation: &Installation,
    expected: &ExpectedLifecycleTopology,
) -> Result<RenderedLiveIds, LocalInitError> {
    let control_name = format!("{}-automata-1", installation.compose_project());
    let mut control = None;
    for summary in containers {
        if !summary
            .names
            .as_ref()
            .into_iter()
            .flatten()
            .any(|name| name.strip_prefix('/') == Some(control_name.as_str()))
        {
            continue;
        }
        let id = summary
            .id
            .as_deref()
            .filter(|id| exact_container_id_text(id))
            .ok_or_else(engine_resource_mismatch)?;
        if control.replace(id.to_owned()).is_some() {
            return Err(engine_resource_mismatch());
        }
    }

    let transit_name = results_transit_name(installation);
    let expected_names = expected
        .networks
        .values()
        .map(|network| network.name.as_str())
        .chain(std::iter::once(transit_name.as_str()))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut pinned_networks = BTreeMap::new();
    let mut none_network = None;
    for network in networks {
        let Some(name) = network.name.as_deref() else {
            continue;
        };
        if name == "none" {
            let id = network
                .id
                .as_deref()
                .filter(|id| exact_container_id_text(id))
                .ok_or_else(engine_resource_mismatch)?;
            if none_network.replace(id.to_owned()).is_some() {
                return Err(engine_resource_mismatch());
            }
            continue;
        }
        if !expected_names.contains(name) {
            continue;
        }
        let id = network
            .id
            .as_deref()
            .filter(|id| exact_container_id_text(id))
            .ok_or_else(engine_resource_mismatch)?;
        if pinned_networks
            .insert(name.to_owned(), id.to_owned())
            .is_some()
        {
            return Err(engine_resource_mismatch());
        }
    }
    Ok(RenderedLiveIds {
        control,
        networks: pinned_networks,
        none_network: none_network.ok_or_else(engine_resource_mismatch)?,
    })
}

#[allow(clippy::too_many_lines)]
fn validate_rendered_container(
    container: &bollard::models::ContainerInspectResponse,
    name: &str,
    image_id: &str,
    installation: &Installation,
    expected: &ExpectedContainer,
    expected_topology: &ExpectedLifecycleTopology,
    desired: &DesiredSpec,
    image: &ImageConfig,
    live_ids: &RenderedLiveIds,
    require_running: bool,
) -> Result<(), LocalInitError> {
    let id = container
        .id
        .as_deref()
        .filter(|id| exact_container_id_text(id))
        .ok_or_else(engine_resource_mismatch)?;
    let config = container
        .config
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let host = container
        .host_config
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let state = container
        .state
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let realized_running = if rendered_process_is_running(state) {
        true
    } else if rendered_process_is_stopped(state) {
        false
    } else {
        return Err(engine_resource_mismatch());
    };
    let network = container
        .network_settings
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let labels = config
        .labels
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let managed = labels
        .iter()
        .filter(|(key, _)| key.starts_with("io.automata.local."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let environment = exact_environment(config.env.as_deref().unwrap_or_default())?;
    let mut expected_environment = exact_environment(image.env.as_deref().unwrap_or_default())?;
    expected_environment.extend(expected.environment.clone());
    let expected_entrypoint = expected
        .entrypoint
        .as_deref()
        .or(image.entrypoint.as_deref())
        .unwrap_or_default();
    let expected_process = expected_entrypoint
        .iter()
        .chain(expected.command.iter())
        .collect::<Vec<_>>();
    let expected_path = expected_process
        .first()
        .map(|value| value.as_str())
        .ok_or_else(engine_resource_mismatch)?;
    let expected_hostname = if expected.network_mode.as_deref() == Some("service:automata") {
        let control = live_ids
            .control
            .as_deref()
            .filter(|id| exact_container_id_text(id))
            .ok_or_else(engine_resource_mismatch)?;
        &control[..12]
    } else {
        &id[..12]
    };
    let expected_args = expected_process
        .get(1..)
        .expect("a nonempty process always has a tail")
        .iter()
        .map(|value| (*value).clone())
        .collect::<Vec<_>>();
    let expected_volumes = image
        .volumes
        .as_deref()
        .unwrap_or_default()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let realized_volumes = config
        .volumes
        .as_deref()
        .unwrap_or_default()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if container.name.as_deref() != Some(format!("/{name}").as_str())
        || container.image.as_deref() != Some(image_id)
        || container.platform.as_deref() != Some("linux")
        || container.path.as_deref() != Some(expected_path)
        || container.args.as_deref().unwrap_or_default() != expected_args
        || expected.platform != "linux/amd64"
        || config.image.as_deref() != Some(expected.image_reference.as_str())
        || config.hostname.as_deref() != Some(expected_hostname)
        || config.domainname.as_deref().unwrap_or_default() != ""
        || config.user.as_deref() != Some(expected.user.as_str())
        || config.cmd.as_deref() != Some(expected.command.as_slice())
        || config.entrypoint.as_deref().unwrap_or_default() != expected_entrypoint
        || config.working_dir.as_deref().unwrap_or_default()
            != image.working_dir.as_deref().unwrap_or_default()
        || config.stop_signal.as_deref().unwrap_or_default()
            != image.stop_signal.as_deref().unwrap_or_default()
        || config.stop_timeout.is_some()
        || config.on_build.as_deref().unwrap_or_default()
            != image.on_build.as_deref().unwrap_or_default()
        || config.shell.as_deref().unwrap_or_default() != image.shell.as_deref().unwrap_or_default()
        || config.args_escaped.unwrap_or(false)
        || realized_volumes != expected_volumes
        || environment != expected_environment
        || config.attach_stdin != Some(expected.stdin_open)
        || config.attach_stdout != Some(true)
        || config.attach_stderr != Some(true)
        || config.open_stdin != Some(expected.stdin_open)
        || config.stdin_once != Some(false)
        || config.tty != Some(expected.tty)
        || config.network_disabled.unwrap_or(false)
        || managed != expected.labels
        || labels.get("com.docker.compose.project").map(String::as_str)
            != Some(installation.compose_project().as_str())
        || labels.get("com.docker.compose.service").map(String::as_str)
            != Some(expected.service.as_str())
        || labels.get("com.docker.compose.oneoff").map(String::as_str)
            != Some(if expected.oneoff() { "True" } else { "False" })
        || host.readonly_rootfs != Some(expected.read_only_root)
        || host.privileged != Some(expected.privileged)
        || host.cap_add.as_deref().unwrap_or_default() != expected.cap_add.as_slice()
        || host.cap_drop.as_deref().unwrap_or_default() != expected.cap_drop.as_slice()
        || host.security_opt.as_deref().unwrap_or_default() != expected.security_opt.as_slice()
        || host.init != Some(expected.init)
        || host.userns_mode.as_deref().unwrap_or_default()
            != expected.userns_mode.as_deref().unwrap_or_default()
        || rendered_host_has_extra_authority(host, expected)
        || host.auto_remove != Some(false)
        || host.log_config.as_ref().and_then(|log| log.typ.as_deref())
            != Some(expected.log_driver.as_str())
        || host
            .log_config
            .as_ref()
            .and_then(|log| log.config.as_ref())
            .is_none_or(|options| {
                options.iter().collect::<BTreeMap<_, _>>()
                    != expected.log_options.iter().collect::<BTreeMap<_, _>>()
            })
        || require_running && !rendered_container_is_running(container, expected)
    {
        return Err(engine_resource_mismatch());
    }

    validate_rendered_mounts(container, host, installation, expected)?;
    validate_rendered_ports(config, host, network, expected, image)?;
    validate_rendered_health(config, expected)?;
    validate_rendered_tmpfs(host, expected)?;
    validate_rendered_restart(host, expected)?;
    validate_rendered_networks(
        network,
        host,
        id,
        name,
        installation,
        expected,
        expected_topology,
        desired,
        live_ids,
        realized_running,
    )
}

fn rendered_process_is_running(state: &bollard::models::ContainerState) -> bool {
    state.running == Some(true)
        && state.paused == Some(false)
        && state.restarting == Some(false)
        && state.dead == Some(false)
        && state.oom_killed == Some(false)
        && state.pid.is_some_and(|pid| pid > 0)
        && state.error.as_deref().is_none_or(str::is_empty)
}

fn rendered_process_is_stopped(state: &bollard::models::ContainerState) -> bool {
    state.running == Some(false)
        && state.paused == Some(false)
        && state.restarting == Some(false)
        && state.dead == Some(false)
        && state.oom_killed == Some(false)
        && state.pid.is_none_or(|pid| pid == 0)
        && state.error.as_deref().is_none_or(str::is_empty)
}

fn rendered_container_is_running(
    container: &bollard::models::ContainerInspectResponse,
    expected: &ExpectedContainer,
) -> bool {
    container.state.as_ref().is_some_and(|state| {
        rendered_process_is_running(state)
            && (expected.healthcheck.is_none()
                || state.health.as_ref().and_then(|health| health.status)
                    == Some(bollard::models::HealthStatusEnum::HEALTHY))
    })
}

fn rendered_host_has_extra_authority(host: &HostConfig, expected: &ExpectedContainer) -> bool {
    let nonempty = |value: Option<&Vec<String>>| value.is_some_and(|value| !value.is_empty());
    let nonzero = |value: Option<i64>| value.is_some_and(|value| value != 0);
    let nonempty_text = |value: Option<&String>| value.is_some_and(|value| !value.is_empty());
    nonempty_text(host.cgroup_parent.as_ref())
        || nonempty_text(host.cpuset_cpus.as_ref())
        || nonempty_text(host.cpuset_mems.as_ref())
        || nonempty_text(host.container_id_file.as_ref())
        || nonempty_text(host.volume_driver.as_ref())
        || host
            .pid_mode
            .as_deref()
            .is_some_and(|mode| !mode.is_empty())
        || host.ipc_mode.as_deref() != Some(expected.ipc.as_str())
        || host
            .uts_mode
            .as_deref()
            .is_some_and(|mode| !mode.is_empty())
        || host.cgroup.as_deref().is_some_and(|mode| !mode.is_empty())
        || host.runtime.as_deref() != Some(expected.runtime.as_str())
        || expected.cgroup != "private"
        || host.cgroupns_mode != Some(HostConfigCgroupnsModeEnum::PRIVATE)
        || host.publish_all_ports == Some(true)
        || host.oom_kill_disable == Some(true)
        || nonzero(host.cpu_shares)
        || nonzero(host.cpu_period)
        || nonzero(host.cpu_quota)
        || nonzero(host.cpu_realtime_period)
        || nonzero(host.cpu_realtime_runtime)
        || host.blkio_weight.is_some_and(|value| value != 0)
        || host
            .blkio_weight_device
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host
            .blkio_device_read_bps
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host
            .blkio_device_write_bps
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host
            .blkio_device_read_iops
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host
            .blkio_device_write_iops
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || nonzero(host.cpu_count)
        || nonzero(host.cpu_percent)
        || nonzero(host.io_maximum_iops)
        || nonzero(host.io_maximum_bandwidth)
        || nonzero(host.memory)
        || nonzero(host.memory_reservation)
        || nonzero(host.memory_swap)
        || nonzero(host.memory_swappiness)
        || nonzero(host.nano_cpus)
        || host
            .pids_limit
            .is_some_and(|value| !matches!(value, -1 | 0))
        || nonzero(host.oom_score_adj)
        || host.devices.as_ref().is_some_and(|value| !value.is_empty())
        || nonempty(host.device_cgroup_rules.as_ref())
        || host
            .device_requests
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host.ulimits.as_ref().is_some_and(|value| !value.is_empty())
        || nonempty(host.binds.as_ref())
        || nonempty(host.volumes_from.as_ref())
        || nonempty(host.dns.as_ref())
        || nonempty(host.dns_options.as_ref())
        || nonempty(host.dns_search.as_ref())
        || nonempty(host.extra_hosts.as_ref())
        || nonempty(host.group_add.as_ref())
        || nonempty(host.links.as_ref())
        || host.console_size.as_deref() != Some([0, 0].as_slice())
        || host.shm_size != i64::try_from(expected.shm_size).ok()
        || host.isolation != Some(HostConfigIsolationEnum::EMPTY)
        || host
            .storage_opt
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host.sysctls.as_ref().is_some_and(|value| !value.is_empty())
        || host
            .annotations
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || !valid_rendered_masked_paths(host.masked_paths.as_deref())
        || host.readonly_paths.as_deref().is_none_or(|paths| {
            paths.iter().collect::<BTreeSet<_>>()
                != helper_readonly_paths().iter().collect::<BTreeSet<_>>()
        })
}

fn valid_rendered_masked_paths(paths: Option<&[String]>) -> bool {
    const REQUIRED: [&str; 11] = [
        "/proc/acpi",
        "/proc/asound",
        "/proc/kcore",
        "/proc/keys",
        "/proc/latency_stats",
        "/proc/sched_debug",
        "/proc/scsi",
        "/proc/timer_list",
        "/proc/timer_stats",
        "/sys/devices/virtual/powercap",
        "/sys/firmware",
    ];
    let Some(paths) = paths else {
        return false;
    };
    let observed = paths.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if observed.len() != paths.len() || REQUIRED.iter().any(|path| !observed.contains(path)) {
        return false;
    }
    observed.into_iter().all(|path| {
        REQUIRED.contains(&path)
            || path == "/proc/interrupts"
            || path
                .strip_prefix("/sys/devices/system/cpu/cpu")
                .and_then(|suffix| suffix.strip_suffix("/thermal_throttle"))
                .and_then(|cpu| cpu.parse::<u32>().ok().map(|index| (cpu, index)))
                .is_some_and(|(cpu, index)| cpu == index.to_string())
    })
}

fn exact_environment(values: &[String]) -> Result<BTreeMap<String, String>, LocalInitError> {
    let mut parsed = BTreeMap::new();
    for value in values {
        let (key, value) = value.split_once('=').ok_or_else(engine_resource_mismatch)?;
        if key.is_empty() || parsed.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(engine_resource_mismatch());
        }
    }
    Ok(parsed)
}

fn validate_rendered_mounts(
    container: &bollard::models::ContainerInspectResponse,
    host: &HostConfig,
    installation: &Installation,
    expected: &ExpectedContainer,
) -> Result<(), LocalInitError> {
    let expected_mounts = expected
        .mounts
        .iter()
        .map(|mount| {
            let (kind, source) = match &mount.source {
                ExpectedMountSource::Volume(role) => (
                    "volume",
                    volume_name(installation.compose_project().as_str(), *role),
                ),
                ExpectedMountSource::Bind { source, .. } => ("bind", source.clone()),
            };
            (
                kind.to_owned(),
                source,
                mount.target.clone(),
                mount.read_only,
                mount.volume_nocopy,
            )
        })
        .collect::<BTreeSet<_>>();
    let mut realized_host = BTreeSet::new();
    for mount in host.mounts.as_deref().unwrap_or_default() {
        let kind = match mount.typ {
            Some(MountType::VOLUME) => "volume",
            Some(MountType::BIND) => "bind",
            _ => return Err(engine_resource_mismatch()),
        };
        let no_copy = if kind == "volume" {
            mount
                .volume_options
                .as_ref()
                .and_then(|options| options.no_copy)
                .unwrap_or(false)
        } else {
            if mount.volume_options.is_some() {
                return Err(engine_resource_mismatch());
            }
            false
        };
        let target = mount
            .target
            .as_deref()
            .ok_or_else(engine_resource_mismatch)?;
        let expected_mount = expected
            .mounts
            .iter()
            .find(|expected| expected.target == target)
            .ok_or_else(engine_resource_mismatch)?;
        if mount
            .consistency
            .as_deref()
            .is_some_and(|value| !value.is_empty())
            || mount.image_options.is_some()
            || mount.tmpfs_options.is_some()
        {
            return Err(engine_resource_mismatch());
        }
        match (&expected_mount.source, kind) {
            (ExpectedMountSource::Volume(_), "volume") => {
                let options = mount
                    .volume_options
                    .as_ref()
                    .ok_or_else(engine_resource_mismatch)?;
                if mount.bind_options.is_some()
                    || options.no_copy != Some(expected_mount.volume_nocopy)
                    || options
                        .labels
                        .as_ref()
                        .is_some_and(|labels| !labels.is_empty())
                    || options.driver_config.is_some()
                    || options
                        .subpath
                        .as_deref()
                        .is_some_and(|subpath| !subpath.is_empty())
                {
                    return Err(engine_resource_mismatch());
                }
            }
            (
                ExpectedMountSource::Bind {
                    create_host_path,
                    propagation,
                    ..
                },
                "bind",
            ) => {
                let options = mount
                    .bind_options
                    .as_ref()
                    .ok_or_else(engine_resource_mismatch)?;
                if mount.volume_options.is_some()
                    || propagation != "rprivate"
                    || options.propagation != Some(MountBindOptionsPropagationEnum::RPRIVATE)
                    || options.non_recursive.unwrap_or(false)
                    || options.create_mountpoint.unwrap_or(false) != *create_host_path
                    || options.read_only_non_recursive.unwrap_or(false)
                    || options.read_only_force_recursive.unwrap_or(false)
                {
                    return Err(engine_resource_mismatch());
                }
            }
            _ => return Err(engine_resource_mismatch()),
        }
        if !realized_host.insert((
            kind.to_owned(),
            mount.source.clone().ok_or_else(engine_resource_mismatch)?,
            target.to_owned(),
            mount.read_only.unwrap_or(false),
            no_copy,
        )) {
            return Err(engine_resource_mismatch());
        }
    }
    if realized_host != expected_mounts {
        return Err(engine_resource_mismatch());
    }
    let expected_realized = expected_mounts
        .iter()
        .map(|(kind, source, target, read_only, _)| {
            (kind.clone(), source.clone(), target.clone(), !*read_only)
        })
        .collect::<BTreeSet<_>>();
    let mut realized = BTreeSet::new();
    for mount in container.mounts.as_deref().unwrap_or_default() {
        let source = if mount.typ.as_deref() == Some("volume") {
            mount.name.clone()
        } else {
            mount.source.clone()
        }
        .ok_or_else(engine_resource_mismatch)?;
        if !realized.insert((
            mount.typ.clone().ok_or_else(engine_resource_mismatch)?,
            source,
            mount
                .destination
                .clone()
                .ok_or_else(engine_resource_mismatch)?,
            mount.rw.ok_or_else(engine_resource_mismatch)?,
        )) {
            return Err(engine_resource_mismatch());
        }
    }
    if realized != expected_realized {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

fn validate_rendered_ports(
    config: &bollard::models::ContainerConfig,
    host: &HostConfig,
    network: &bollard::models::NetworkSettings,
    expected: &ExpectedContainer,
    image: &ImageConfig,
) -> Result<(), LocalInitError> {
    let expected_ports = expected
        .ports
        .iter()
        .map(|port| {
            (
                format!("{}/{}", port.target, port.protocol),
                port.host_ip.clone(),
                port.published.to_string(),
            )
        })
        .collect::<BTreeSet<_>>();
    let exposed = config
        .exposed_ports
        .as_deref()
        .unwrap_or_default()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_exposed = image
        .exposed_ports
        .as_deref()
        .unwrap_or_default()
        .iter()
        .cloned()
        .chain(expected_ports.iter().map(|(port, _, _)| port.clone()))
        .collect::<BTreeSet<_>>();
    if exposed != expected_exposed {
        return Err(engine_resource_mismatch());
    }
    let mut bindings = BTreeSet::new();
    for (port, values) in host.port_bindings.as_ref().into_iter().flatten() {
        for value in values.as_deref().unwrap_or_default() {
            if !bindings.insert((
                port.clone(),
                value.host_ip.clone().unwrap_or_default(),
                value.host_port.clone().unwrap_or_default(),
            )) {
                return Err(engine_resource_mismatch());
            }
        }
    }
    if bindings != expected_ports {
        return Err(engine_resource_mismatch());
    }
    let mut realized = BTreeSet::new();
    for (port, values) in network.ports.as_ref().into_iter().flatten() {
        for value in values.as_deref().unwrap_or_default() {
            realized.insert((
                port.clone(),
                value.host_ip.clone().unwrap_or_default(),
                value.host_port.clone().unwrap_or_default(),
            ));
        }
    }
    if realized != expected_ports {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

fn validate_rendered_health(
    config: &bollard::models::ContainerConfig,
    expected: &ExpectedContainer,
) -> Result<(), LocalInitError> {
    match (&config.healthcheck, &expected.healthcheck) {
        (None, None) => Ok(()),
        (Some(actual), Some(expected))
            if actual.test.as_deref() == Some(expected.test.as_slice())
                && actual.interval == Some(rendered_duration_ns(&expected.interval)?)
                && actual.timeout == Some(rendered_duration_ns(&expected.timeout)?)
                && actual.retries == Some(i64::from(expected.retries))
                && actual.start_period == Some(rendered_duration_ns(&expected.start_period)?)
                && actual.start_interval.is_none_or(|value| value == 0) =>
        {
            Ok(())
        }
        _ => Err(engine_resource_mismatch()),
    }
}

fn rendered_duration_ns(value: &str) -> Result<i64, LocalInitError> {
    let (number, multiplier) = if let Some(value) = value.strip_suffix("ms") {
        (value, 1_000_000_i64)
    } else if let Some(value) = value.strip_suffix('s') {
        (value, 1_000_000_000_i64)
    } else {
        return Err(engine_resource_mismatch());
    };
    number
        .parse::<i64>()
        .ok()
        .and_then(|number| number.checked_mul(multiplier))
        .filter(|number| *number > 0)
        .ok_or_else(engine_resource_mismatch)
}

fn validate_rendered_tmpfs(
    host: &HostConfig,
    expected: &ExpectedContainer,
) -> Result<(), LocalInitError> {
    let mut rendered = BTreeMap::new();
    for value in &expected.tmpfs {
        let (target, options) = value.split_once(':').ok_or_else(engine_resource_mismatch)?;
        if target.is_empty()
            || options.is_empty()
            || rendered
                .insert(target.to_owned(), options.to_owned())
                .is_some()
        {
            return Err(engine_resource_mismatch());
        }
    }
    let actual = host
        .tmpfs
        .as_ref()
        .into_iter()
        .flatten()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    if actual == rendered {
        Ok(())
    } else {
        Err(engine_resource_mismatch())
    }
}

fn validate_rendered_restart(
    host: &HostConfig,
    expected: &ExpectedContainer,
) -> Result<(), LocalInitError> {
    let expected_name = match expected.restart.as_deref() {
        None | Some("no") => RestartPolicyNameEnum::NO,
        Some("unless-stopped") => RestartPolicyNameEnum::UNLESS_STOPPED,
        _ => return Err(engine_resource_mismatch()),
    };
    if host.restart_policy.as_ref().is_some_and(|policy| {
        policy.name == Some(expected_name) && policy.maximum_retry_count.unwrap_or(0) == 0
    }) {
        Ok(())
    } else {
        Err(engine_resource_mismatch())
    }
}

fn validate_rendered_networks(
    network: &bollard::models::NetworkSettings,
    host: &HostConfig,
    id: &str,
    name: &str,
    installation: &Installation,
    expected: &ExpectedContainer,
    expected_topology: &ExpectedLifecycleTopology,
    desired: &DesiredSpec,
    live_ids: &RenderedLiveIds,
    realized_running: bool,
) -> Result<(), LocalInitError> {
    if let Some(mode) = expected.network_mode.as_deref() {
        if mode == "none" {
            if host.network_mode.as_deref() != Some("none")
                || if realized_running {
                    !exact_running_none_network(network, &live_ids.none_network)
                } else {
                    !exact_stopped_none_network(network, &live_ids.none_network)
                }
            {
                return Err(engine_resource_mismatch());
            }
            return Ok(());
        }
        if mode == "service:automata" {
            let control_name = format!("{}-automata-1", installation.compose_project());
            let expected_control = live_ids
                .control
                .as_deref()
                .ok_or_else(engine_resource_mismatch)?;
            if host
                .network_mode
                .as_deref()
                .and_then(|mode| mode.strip_prefix("container:"))
                != Some(expected_control)
                || network
                    .networks
                    .as_ref()
                    .is_some_and(|networks| !networks.is_empty())
                || name == control_name
                || !exact_container_id_text(id)
            {
                return Err(engine_resource_mismatch());
            }
            return Ok(());
        }
        return Err(engine_resource_mismatch());
    }

    let actual = network
        .networks
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    if !realized_running
        && (network.sandbox_id.as_deref() != Some("")
            || network.sandbox_key.as_deref() != Some("")
            || network.ports.as_ref().is_none_or(|ports| !ports.is_empty()))
    {
        return Err(engine_resource_mismatch());
    }
    if actual.len() != expected.networks.len() {
        return Err(engine_resource_mismatch());
    }
    let expected_primary = expected
        .networks
        .keys()
        .next()
        .map(|logical| rendered_network_name(logical, installation))
        .transpose()?
        .ok_or_else(engine_resource_mismatch)?;
    if host.network_mode.as_deref() != Some(expected_primary.as_str()) {
        return Err(engine_resource_mismatch());
    }
    for (logical, expected_endpoint) in &expected.networks {
        let physical = rendered_network_name(logical, installation)?;
        let endpoint = actual.get(&physical).ok_or_else(engine_resource_mismatch)?;
        let (expected_gateway, expected_subnet) = if logical == "results-transit" {
            (
                desired.results_transit().gateway().to_string(),
                desired.results_transit().subnet(),
            )
        } else {
            let network = expected_topology
                .networks
                .get(logical)
                .ok_or_else(engine_resource_mismatch)?;
            (network.gateway.clone(), network.subnet.clone())
        };
        let expected_prefix = expected_subnet
            .rsplit_once('/')
            .and_then(|(_, prefix)| prefix.parse::<i64>().ok())
            .filter(|prefix| (1..=32).contains(prefix))
            .ok_or_else(engine_resource_mismatch)?;
        let ipam = endpoint
            .ipam_config
            .as_ref()
            .ok_or_else(engine_resource_mismatch)?;
        let aliases = endpoint
            .aliases
            .as_deref()
            .unwrap_or_default()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut required_aliases = expected_endpoint
            .aliases
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        required_aliases.insert(name.to_owned());
        required_aliases.insert(expected.service.clone());
        let mut aliases_with_id = required_aliases.clone();
        aliases_with_id.insert(id[..12].to_owned());
        let dns_names = endpoint
            .dns_names
            .as_deref()
            .unwrap_or_default()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let expected_network_id = live_ids
            .networks
            .get(&physical)
            .ok_or_else(engine_resource_mismatch)?;
        let configured_mismatch = ipam.ipv4_address.as_deref()
            != Some(expected_endpoint.ipv4_address.as_str())
            || ipam
                .ipv6_address
                .as_deref()
                .is_some_and(|address| !address.is_empty())
            || ipam
                .link_local_ips
                .as_ref()
                .is_some_and(|addresses| !addresses.is_empty())
            || endpoint
                .links
                .as_ref()
                .is_some_and(|links| !links.is_empty())
            || endpoint
                .driver_opts
                .as_ref()
                .is_some_and(|options| !options.is_empty())
            || endpoint
                .ipv6_gateway
                .as_deref()
                .is_some_and(|gateway| !gateway.is_empty())
            || endpoint
                .global_ipv6_address
                .as_deref()
                .is_some_and(|address| !address.is_empty())
            || endpoint.global_ipv6_prefix_len.unwrap_or(0) != 0
            || endpoint.gw_priority.unwrap_or(0) != expected_endpoint.gateway_priority
            || aliases != required_aliases && aliases != aliases_with_id
            || dns_names != aliases_with_id
            || endpoint.network_id.as_deref() != Some(expected_network_id.as_str());
        let operational_mismatch = if realized_running {
            endpoint.ip_address.as_deref() != Some(expected_endpoint.ipv4_address.as_str())
                || endpoint.gateway.as_deref() != Some(expected_gateway.as_str())
                || endpoint.ip_prefix_len != Some(expected_prefix)
                || endpoint
                    .mac_address
                    .as_deref()
                    .is_none_or(|address| !canonical_unicast_mac(address))
                || endpoint
                    .endpoint_id
                    .as_deref()
                    .is_none_or(|endpoint_id| !exact_container_id_text(endpoint_id))
        } else {
            endpoint
                .endpoint_id
                .as_deref()
                .is_some_and(|endpoint_id| !endpoint_id.is_empty())
                || endpoint
                    .gateway
                    .as_deref()
                    .is_some_and(|gateway| !gateway.is_empty())
                || endpoint
                    .ip_address
                    .as_deref()
                    .is_some_and(|address| !address.is_empty())
                || endpoint.ip_prefix_len.unwrap_or(0) != 0
                || endpoint
                    .mac_address
                    .as_deref()
                    .is_some_and(|address| !address.is_empty())
        };
        if configured_mismatch || operational_mismatch {
            return Err(engine_resource_mismatch());
        }
    }
    Ok(())
}

fn exact_running_none_network(
    network: &bollard::models::NetworkSettings,
    none_network_id: &str,
) -> bool {
    let Some(sandbox_id) = network
        .sandbox_id
        .as_deref()
        .filter(|id| exact_container_id_text(id))
    else {
        return false;
    };
    if network.sandbox_key.as_deref()
        != Some(format!("/var/run/docker/netns/{}", &sandbox_id[..12]).as_str())
        || network.ports.as_ref().is_none_or(|ports| {
            ports.values().any(|bindings| {
                bindings
                    .as_ref()
                    .is_some_and(|bindings| !bindings.is_empty())
            })
        })
    {
        return false;
    }
    let Some(networks) = network
        .networks
        .as_ref()
        .filter(|networks| networks.len() == 1)
    else {
        return false;
    };
    let Some(endpoint) = networks.get("none") else {
        return false;
    };
    endpoint.ipam_config.is_none()
        && endpoint.links.as_ref().is_none_or(Vec::is_empty)
        && endpoint.aliases.as_ref().is_none_or(Vec::is_empty)
        && endpoint.driver_opts.as_ref().is_none_or(HashMap::is_empty)
        && endpoint.dns_names.as_ref().is_none_or(Vec::is_empty)
        && endpoint.gw_priority.unwrap_or(0) == 0
        && endpoint.network_id.as_deref() == Some(none_network_id)
        && endpoint
            .endpoint_id
            .as_deref()
            .is_some_and(exact_container_id_text)
        && endpoint.gateway.as_deref() == Some("")
        && endpoint.ip_address.as_deref() == Some("")
        && endpoint.mac_address.as_deref() == Some("")
        && endpoint.ip_prefix_len == Some(0)
        && endpoint.ipv6_gateway.as_deref() == Some("")
        && endpoint.global_ipv6_address.as_deref() == Some("")
        && endpoint.global_ipv6_prefix_len == Some(0)
}

fn exact_stopped_none_network(
    network: &bollard::models::NetworkSettings,
    none_network_id: &str,
) -> bool {
    if network.sandbox_id.as_deref() != Some("")
        || network.sandbox_key.as_deref() != Some("")
        || network.ports.as_ref().is_none_or(|ports| !ports.is_empty())
    {
        return false;
    }
    let Some(networks) = network
        .networks
        .as_ref()
        .filter(|networks| networks.len() == 1)
    else {
        return false;
    };
    let Some(endpoint) = networks.get("none") else {
        return false;
    };
    endpoint.ipam_config.is_none()
        && endpoint.links.as_ref().is_none_or(Vec::is_empty)
        && endpoint.aliases.as_ref().is_none_or(Vec::is_empty)
        && endpoint.driver_opts.as_ref().is_none_or(HashMap::is_empty)
        && endpoint.dns_names.as_ref().is_none_or(Vec::is_empty)
        && endpoint.gw_priority.unwrap_or(0) == 0
        && endpoint.network_id.as_deref() == Some(none_network_id)
        && endpoint.endpoint_id.as_deref().is_none_or(str::is_empty)
        && endpoint.gateway.as_deref().is_none_or(str::is_empty)
        && endpoint.ip_address.as_deref().is_none_or(str::is_empty)
        && endpoint.mac_address.as_deref().is_none_or(str::is_empty)
        && endpoint.ip_prefix_len.unwrap_or(0) == 0
        && endpoint.ipv6_gateway.as_deref().is_none_or(str::is_empty)
        && endpoint
            .global_ipv6_address
            .as_deref()
            .is_none_or(str::is_empty)
        && endpoint.global_ipv6_prefix_len.unwrap_or(0) == 0
}

fn canonical_unicast_mac(value: &str) -> bool {
    let octets = value
        .split(':')
        .map(|octet| {
            (octet.len() == 2 && octet.bytes().all(|byte| byte.is_ascii_hexdigit()))
                .then(|| u8::from_str_radix(octet, 16).ok())
                .flatten()
        })
        .collect::<Option<Vec<_>>>();
    octets.is_some_and(|octets| {
        octets.len() == 6
            && octets.iter().any(|octet| *octet != 0)
            && octets[0] & 1 == 0
            && value == value.to_ascii_lowercase()
    })
}

fn rendered_network_name(
    logical: &str,
    installation: &Installation,
) -> Result<String, LocalInitError> {
    match logical {
        "control" => Ok(format!("{}-control", installation.compose_project())),
        "egress" => Ok(format!("{}-egress", installation.compose_project())),
        "results-transit" => Ok(results_transit_name(installation)),
        _ => Err(engine_resource_mismatch()),
    }
}

#[derive(Clone, Copy)]
struct LifecycleOneoffContract {
    image_role: &'static str,
}

fn lifecycle_oneoff_contract(
    service: &'static str,
) -> Result<LifecycleOneoffContract, LocalInitError> {
    let contract = match service {
        "object-store-init" => LifecycleOneoffContract {
            image_role: "automata",
        },
        "bootstrap-runner" => LifecycleOneoffContract {
            image_role: "automata",
        },
        "runner-enroll" => LifecycleOneoffContract {
            image_role: "runner",
        },
        _ => return Err(engine_resource_mismatch()),
    };
    Ok(contract)
}

fn lifecycle_oneoff_name(
    installation: &Installation,
    service: &'static str,
) -> Result<String, LocalInitError> {
    lifecycle_oneoff_contract(service)?;
    Ok(format!("{}-{service}", installation.compose_project()))
}

fn validate_egress_network(
    network: &NetworkInspect,
    installation: &Installation,
    desired: &DesiredSpec,
) -> Result<(), LocalInitError> {
    let expected_name = format!("{}-egress", installation.compose_project());
    let subnet = crate::desired_spec::egress_subnet_for_spec(desired);
    let ipam = network.ipam.as_ref().ok_or_else(engine_resource_mismatch)?;
    let labels = network
        .labels
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let managed = labels
        .iter()
        .filter(|(key, _)| key.starts_with("io.automata.local."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let expected_labels = BTreeMap::from([
        (LABEL_MANAGED.to_owned(), "true".to_owned()),
        (
            LABEL_INSTALLATION_ID.to_owned(),
            installation.id().to_string(),
        ),
        (
            LABEL_INSTALLATION_KEY.to_owned(),
            installation.selector_key().to_string(),
        ),
        (
            LABEL_COMPOSE_PROJECT.to_owned(),
            installation.compose_project().to_string(),
        ),
        (LABEL_PLAN.to_owned(), desired.plan_digest().to_string()),
        (LABEL_RESOURCE_KIND.to_owned(), "egress-network".to_owned()),
    ]);
    let expected_options = HashMap::from([
        (
            "com.docker.network.bridge.enable_ip_masquerade".to_owned(),
            "true".to_owned(),
        ),
        (
            "com.docker.network.bridge.gateway_mode_ipv4".to_owned(),
            "nat".to_owned(),
        ),
    ]);
    let expected_container_name = format!("{}-runner-1", installation.compose_project());
    let actual_container_names = network
        .containers
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?
        .values()
        .map(|endpoint| endpoint.name.clone().ok_or_else(engine_resource_mismatch))
        .collect::<Result<BTreeSet<_>, LocalInitError>>()?;
    if network.name.as_deref() != Some(&expected_name)
        || network
            .id
            .as_deref()
            .is_none_or(|id| !exact_container_id_text(id))
        || network.scope.as_deref() != Some("local")
        || network.driver.as_deref() != Some("bridge")
        || network.internal != Some(false)
        || network.attachable != Some(false)
        || network.enable_ipv6 != Some(false)
        || network.options.as_ref() != Some(&expected_options)
        || ipam.driver.as_deref() != Some("default")
        || ipam.config.as_deref()
            != Some(
                [IpamConfig {
                    subnet: Some(subnet.to_string()),
                    gateway: Some(subnet.address(1).to_string()),
                    ip_range: None,
                    auxiliary_addresses: None,
                }]
                .as_slice(),
            )
        || managed != expected_labels
        || actual_container_names != BTreeSet::from([expected_container_name])
    {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

fn validate_control_network(
    network: &NetworkInspect,
    installation: &Installation,
    desired: &DesiredSpec,
) -> Result<(), LocalInitError> {
    let expected_name = format!("{}-control", installation.compose_project());
    let subnet = crate::desired_spec::control_subnet_for_spec(desired);
    let ipam = network.ipam.as_ref().ok_or_else(engine_resource_mismatch)?;
    let labels = network
        .labels
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let managed = labels
        .iter()
        .filter(|(key, _)| key.starts_with("io.automata.local."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let expected_labels = BTreeMap::from([
        (LABEL_MANAGED.to_owned(), "true".to_owned()),
        (
            LABEL_INSTALLATION_ID.to_owned(),
            installation.id().to_string(),
        ),
        (
            LABEL_INSTALLATION_KEY.to_owned(),
            installation.selector_key().to_string(),
        ),
        (
            LABEL_COMPOSE_PROJECT.to_owned(),
            installation.compose_project().to_string(),
        ),
        (LABEL_PLAN.to_owned(), desired.plan_digest().to_string()),
        (LABEL_RESOURCE_KIND.to_owned(), "control-network".to_owned()),
    ]);
    let expected_container_names = ["automata", "postgres", "runner", "rustfs"]
        .into_iter()
        .map(|service| format!("{}-{service}-1", installation.compose_project()))
        .collect::<BTreeSet<_>>();
    let actual_container_names = network
        .containers
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?
        .values()
        .map(|endpoint| endpoint.name.clone().ok_or_else(engine_resource_mismatch))
        .collect::<Result<BTreeSet<_>, LocalInitError>>()?;
    if network.name.as_deref() != Some(&expected_name)
        || network
            .id
            .as_deref()
            .is_none_or(|id| !exact_container_id_text(id))
        || network.scope.as_deref() != Some("local")
        || network.driver.as_deref() != Some("bridge")
        || network.internal != Some(true)
        || network.attachable != Some(false)
        || network.enable_ipv6 != Some(false)
        || ipam.driver.as_deref() != Some("default")
        || ipam.config.as_deref()
            != Some(
                [IpamConfig {
                    subnet: Some(subnet.to_string()),
                    gateway: Some(subnet.address(1).to_string()),
                    ip_range: None,
                    auxiliary_addresses: None,
                }]
                .as_slice(),
            )
        || managed != expected_labels
        || actual_container_names != expected_container_names
    {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

pub(super) fn lifecycle_lock_name(installation: &Installation) -> String {
    format!("{}-lifecycle-lock", installation.compose_project())
}

struct LifecycleLockImage {
    inspection_reference: String,
    image_id: String,
    labels: BTreeMap<String, String>,
}

async fn lifecycle_lock_image(
    engine: &InitEngine<'_>,
    epoch: &ImmutableEpoch,
) -> Result<LifecycleLockImage, LocalInitError> {
    let expectation = epoch
        .image_expectations()
        .find(|image| image.role == "automata")
        .ok_or_else(engine_resource_mismatch)?;
    let image = engine.inspect_epoch_image(expectation).await?;
    let labels = engine
        .inspect_image(&image.inspection_reference)
        .await?
        .and_then(|image| image.config)
        .and_then(|config| config.labels)
        .ok_or_else(engine_resource_mismatch)?
        .into_iter()
        .collect();
    Ok(LifecycleLockImage {
        inspection_reference: image.inspection_reference,
        image_id: image.image_id,
        labels,
    })
}

fn lifecycle_lock_expected_labels(
    image_labels: &BTreeMap<String, String>,
    managed: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, LocalInitError> {
    if image_labels
        .keys()
        .any(|key| key.starts_with("io.automata.local."))
    {
        return Err(engine_resource_mismatch());
    }
    let mut labels = image_labels.clone();
    labels.extend(managed);
    Ok(labels)
}

fn lifecycle_lock_labels(
    installation: &Installation,
    operation_id: OperationId,
    daemon: &EngineDaemonGeneration,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        (LABEL_MANAGED.to_owned(), "true".to_owned()),
        (
            LABEL_INSTALLATION_ID.to_owned(),
            installation.id().to_string(),
        ),
        (
            LABEL_INSTALLATION_KEY.to_owned(),
            installation.selector_key().to_string(),
        ),
        (
            LABEL_COMPOSE_PROJECT.to_owned(),
            installation.compose_project().to_string(),
        ),
        (LABEL_RESOURCE_KIND.to_owned(), LOCK_KIND.to_owned()),
        (LABEL_OPERATION_ID.to_owned(), operation_id.to_string()),
        (LABEL_ENGINE_BOOT_ID.to_owned(), daemon.boot_id.to_string()),
        (LABEL_ENGINE_PID.to_owned(), daemon.pid.to_string()),
        (
            LABEL_ENGINE_START_TICKS.to_owned(),
            daemon.start_ticks.to_string(),
        ),
    ])
}

fn daemon_generation_from_labels(
    labels: &BTreeMap<String, String>,
) -> Result<EngineDaemonGeneration, LocalInitError> {
    let boot_text = labels
        .get(LABEL_ENGINE_BOOT_ID)
        .ok_or_else(engine_resource_mismatch)?;
    let boot_id = uuid::Uuid::parse_str(boot_text)
        .ok()
        .filter(|value| value.hyphenated().to_string() == *boot_text)
        .ok_or_else(engine_resource_mismatch)?;
    let pid_text = labels
        .get(LABEL_ENGINE_PID)
        .ok_or_else(engine_resource_mismatch)?;
    let pid = pid_text
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0 && value.to_string() == *pid_text)
        .ok_or_else(engine_resource_mismatch)?;
    let start_text = labels
        .get(LABEL_ENGINE_START_TICKS)
        .ok_or_else(engine_resource_mismatch)?;
    let start_ticks = start_text
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && value.to_string() == *start_text)
        .ok_or_else(engine_resource_mismatch)?;
    Ok(EngineDaemonGeneration {
        boot_id,
        pid,
        start_ticks,
    })
}

fn current_engine_daemon_generation() -> Result<EngineDaemonGeneration, LocalInitError> {
    let first = probe_engine_daemon_generation()?;
    let repeated = probe_engine_daemon_generation()?;
    if first != repeated {
        return Err(engine_unavailable());
    }
    Ok(first)
}

/// Identifies the process which actually wrote a qualified Docker API
/// response. `SO_PEERCRED` is deliberately insufficient here: with systemd
/// socket activation it identifies PID 1, which owns the listening socket,
/// rather than the `dockerd` process accepting and serving the request.
fn probe_engine_daemon_generation() -> Result<EngineDaemonGeneration, LocalInitError> {
    let socket = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| engine_unavailable())?;
    rustix::net::sockopt::set_socket_passcred(&socket, true).map_err(|_| engine_unavailable())?;
    let address = SocketAddrUnix::new("/var/run/docker.sock").map_err(|_| engine_unavailable())?;
    rustix::net::connect(&socket, &address).map_err(|_| engine_unavailable())?;
    let mut socket = UnixStream::from(socket);
    socket
        .set_read_timeout(Some(ENGINE_GENERATION_PROBE_TIMEOUT))
        .map_err(|_| engine_unavailable())?;
    socket
        .set_write_timeout(Some(ENGINE_GENERATION_PROBE_TIMEOUT))
        .map_err(|_| engine_unavailable())?;
    socket
        .write_all(ENGINE_GENERATION_REQUEST)
        .map_err(|_| engine_unavailable())?;

    let mut response = [0_u8; ENGINE_GENERATION_RESPONSE_MAXIMUM_BYTES];
    let (received, credentials) = {
        let mut iov = [IoSliceMut::new(&mut response)];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmCredentials(1))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let received =
            rustix::net::recvmsg(&socket, &mut iov, &mut ancillary, RecvFlags::CMSG_CLOEXEC)
                .map_err(|_| engine_unavailable())?;
        let mut credentials = None;
        for message in ancillary.drain() {
            match message {
                RecvAncillaryMessage::ScmCredentials(value) if credentials.is_none() => {
                    credentials = Some(value);
                }
                _ => return Err(engine_unavailable()),
            }
        }
        (received.bytes, credentials.ok_or_else(engine_unavailable)?)
    };
    if received == 0 || received >= response.len() {
        return Err(engine_unavailable());
    }
    let mut response = response[..received].to_vec();
    let mut remaining = [0_u8; 512];
    loop {
        match socket.read(&mut remaining) {
            Ok(0) => break,
            Ok(count)
                if response
                    .len()
                    .checked_add(count)
                    .is_some_and(|length| length <= ENGINE_GENERATION_RESPONSE_MAXIMUM_BYTES) =>
            {
                response.extend_from_slice(&remaining[..count]);
            }
            Ok(_) | Err(_) => return Err(engine_unavailable()),
        }
    }
    validate_engine_generation_response(&response)?;

    let pid = u32::try_from(credentials.pid.as_raw_pid()).map_err(|_| engine_unavailable())?;
    if credentials.uid.as_raw() != 0 || credentials.gid.as_raw() != 0 || pid == 0 {
        return Err(engine_unavailable());
    }
    let boot_id = read_boot_id().map_err(|_| engine_unavailable())?;
    let start_ticks = read_process_start_ticks(pid).map_err(|_| engine_unavailable())?;
    Ok(EngineDaemonGeneration {
        boot_id,
        pid,
        start_ticks,
    })
}

fn validate_engine_generation_response(response: &[u8]) -> Result<(), LocalInitError> {
    let (head, body) = response
        .split(|byte| *byte == b'\r')
        .next()
        .and_then(|status| {
            response
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|boundary| (status, &response[boundary + 4..]))
        })
        .ok_or_else(engine_unavailable)?;
    if !matches!(head, b"HTTP/1.0 200 OK" | b"HTTP/1.1 200 OK") || body != b"OK" {
        return Err(engine_unavailable());
    }
    Ok(())
}

fn read_boot_id() -> Result<uuid::Uuid, ()> {
    let text = fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| ())?;
    let text = text.strip_suffix('\n').unwrap_or(&text);
    if text.len() != 36 {
        return Err(());
    }
    uuid::Uuid::parse_str(text)
        .ok()
        .filter(|value| value.hyphenated().to_string() == text)
        .ok_or(())
}

fn read_process_start_ticks(pid: u32) -> Result<u64, ErrorKind> {
    let path = format!("/proc/{pid}/stat");
    let metadata = fs::metadata(&path).map_err(|error| error.kind())?;
    if metadata.len() > 16 * 1024 {
        return Err(ErrorKind::InvalidData);
    }
    let text = fs::read_to_string(path).map_err(|error| error.kind())?;
    let open = text.find(" (").ok_or(ErrorKind::InvalidData)?;
    if text[..open]
        .parse::<u32>()
        .ok()
        .filter(|observed| *observed == pid)
        .is_none()
    {
        return Err(ErrorKind::InvalidData);
    }
    let close = text.rfind(") ").ok_or(ErrorKind::InvalidData)?;
    if close <= open + 1 {
        return Err(ErrorKind::InvalidData);
    }
    text[close + 2..]
        .split_ascii_whitespace()
        .nth(19)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or(ErrorKind::InvalidData)
}

fn prove_daemon_generation_absent(
    generation: &EngineDaemonGeneration,
) -> Result<(), LocalInitError> {
    let current_boot =
        read_boot_id().map_err(|_| LocalInitError::new(LocalInitErrorCode::ResetRequired))?;
    daemon_generation_absence_from_observation(
        generation,
        current_boot,
        read_process_start_ticks(generation.pid),
    )
}

fn daemon_generation_absence_from_observation(
    generation: &EngineDaemonGeneration,
    current_boot: uuid::Uuid,
    observed_start: Result<u64, ErrorKind>,
) -> Result<(), LocalInitError> {
    if current_boot != generation.boot_id {
        return Ok(());
    }
    match observed_start {
        Err(ErrorKind::NotFound) => Ok(()),
        Ok(start_ticks) if start_ticks != generation.start_ticks => Ok(()),
        Ok(_) | Err(_) => Err(LocalInitError::new(LocalInitErrorCode::ResetRequired)),
    }
}

fn validate_replacement_daemon_generation(
    stopped: &EngineDaemonGeneration,
    replacement: &EngineDaemonGeneration,
    repeated: &EngineDaemonGeneration,
) -> Result<(), LocalInitError> {
    if replacement == stopped || repeated != replacement {
        Err(LocalInitError::new(LocalInitErrorCode::ResetRequired))
    } else {
        Ok(())
    }
}

fn lifecycle_lock_body(
    image_reference: &str,
    labels: &BTreeMap<String, String>,
) -> ContainerCreateBody {
    ContainerCreateBody {
        user: Some("65532:65532".to_owned()),
        attach_stdin: Some(true),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        tty: Some(false),
        open_stdin: Some(true),
        stdin_once: Some(true),
        env: Some(Vec::new()),
        cmd: Some(
            crate::LOCAL_LIFECYCLE_LOCK_HOLDER_COMMAND
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ),
        image: Some(image_reference.to_owned()),
        working_dir: Some("/".to_owned()),
        entrypoint: Some(vec!["/usr/local/bin/automata".to_owned()]),
        network_disabled: Some(true),
        labels: Some(labels.clone().into_iter().collect()),
        stop_signal: Some("SIGKILL".to_owned()),
        stop_timeout: Some(0),
        host_config: Some(HostConfig {
            memory: Some(HELPER_MEMORY_BYTES),
            memory_swap: Some(HELPER_MEMORY_BYTES),
            nano_cpus: Some(HELPER_NANO_CPUS),
            pids_limit: Some(HELPER_PIDS),
            console_size: Some(vec![0, 0]),
            shm_size: Some(HELPER_SHM_BYTES),
            isolation: Some(HostConfigIsolationEnum::EMPTY),
            init: Some(false),
            mounts: Some(Vec::new()),
            cap_add: Some(Vec::new()),
            cap_drop: Some(vec!["ALL".to_owned()]),
            network_mode: Some("none".to_owned()),
            restart_policy: Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::NO),
                maximum_retry_count: Some(0),
            }),
            auto_remove: Some(false),
            cgroupns_mode: Some(HostConfigCgroupnsModeEnum::PRIVATE),
            ipc_mode: Some("private".to_owned()),
            readonly_rootfs: Some(true),
            security_opt: Some(helper_security_options()),
            masked_paths: Some(helper_masked_paths()),
            readonly_paths: Some(helper_readonly_paths()),
            log_config: Some(helper_log_config()),
            runtime: Some("runc".to_owned()),
            userns_mode: Some("host".to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn classify_lifecycle_lock(
    container: &bollard::models::ContainerInspectResponse,
    name: &str,
    image_reference: &str,
    image_id: &str,
    image_labels: &BTreeMap<String, String>,
    installation: &Installation,
) -> Result<LifecycleLockObservation, LocalInitError> {
    let id = container
        .id
        .as_deref()
        .filter(|id| exact_container_id_text(id))
        .ok_or_else(engine_resource_mismatch)?;
    let config = container
        .config
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let host = container
        .host_config
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let state = container
        .state
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let network = container
        .network_settings
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let labels = config
        .labels
        .as_ref()
        .into_iter()
        .flatten()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let operation_text = labels
        .get(LABEL_OPERATION_ID)
        .ok_or_else(engine_resource_mismatch)?;
    let operation_id = operation_text
        .parse::<OperationId>()
        .map_err(|_| engine_resource_mismatch())?;
    let daemon_generation = daemon_generation_from_labels(&labels)?;
    let expected_labels = lifecycle_lock_expected_labels(
        image_labels,
        lifecycle_lock_labels(installation, operation_id, &daemon_generation),
    )?;
    if operation_id.to_string() != *operation_text
        || labels != expected_labels
        || container.name.as_deref() != Some(format!("/{name}").as_str())
        || container.image.as_deref() != Some(image_id)
        || container.platform.as_deref() != Some("linux")
        || config.image.as_deref() != Some(image_reference)
        || config.user.as_deref() != Some("65532:65532")
        || config.attach_stdin != Some(true)
        || config.attach_stdout != Some(true)
        || config.attach_stderr != Some(true)
        || config.tty != Some(false)
        || config.open_stdin != Some(true)
        || config.stdin_once != Some(true)
        || config.entrypoint.as_deref() != Some(["/usr/local/bin/automata".to_owned()].as_slice())
        || config.cmd.as_deref()
            != Some(
                crate::LOCAL_LIFECYCLE_LOCK_HOLDER_COMMAND
                    .map(str::to_owned)
                    .as_slice(),
            )
        || config.env.as_ref().is_some_and(|env| !env.is_empty())
        || config.working_dir.as_deref() != Some("/")
        || config.network_disabled != Some(true)
        || config.stop_signal.as_deref() != Some("SIGKILL")
        || config.stop_timeout != Some(0)
        || config.healthcheck.is_some()
        || config.exposed_ports.as_deref()
            != Some([super::HELPER_EXPOSED_PORT.to_owned()].as_slice())
        || config
            .volumes
            .as_ref()
            .is_some_and(|volumes| !volumes.is_empty())
        || config
            .on_build
            .as_ref()
            .is_some_and(|steps| !steps.is_empty())
        || config.shell.as_ref().is_some_and(|shell| !shell.is_empty())
        || host.network_mode.as_deref() != Some("none")
        || host.readonly_rootfs != Some(true)
        || host.privileged.unwrap_or(false)
        || host.auto_remove != Some(false)
        || helper_has_ambient_authority(host)
        || host.cap_drop.as_deref() != Some(["ALL".to_owned()].as_slice())
        || host.cap_add.as_ref().is_none_or(|caps| !caps.is_empty())
        || host.memory != Some(HELPER_MEMORY_BYTES)
        || host.memory_swap != Some(HELPER_MEMORY_BYTES)
        || host.nano_cpus != Some(HELPER_NANO_CPUS)
        || host.pids_limit != Some(HELPER_PIDS)
        || host.binds.as_ref().is_some_and(|binds| !binds.is_empty())
        || host
            .mounts
            .as_ref()
            .is_some_and(|mounts| !mounts.is_empty())
        || host.security_opt.as_deref() != Some(helper_security_options().as_slice())
        || host.masked_paths.as_deref() != Some(helper_masked_paths().as_slice())
        || host.readonly_paths.as_deref() != Some(helper_readonly_paths().as_slice())
        || host.tmpfs.as_ref().is_some_and(|tmpfs| !tmpfs.is_empty())
        || host.log_config.as_ref() != Some(&helper_log_config())
        || container
            .mounts
            .as_ref()
            .is_some_and(|mounts| !mounts.is_empty())
        || network.sandbox_id.as_deref() != Some("")
        || network.sandbox_key.as_deref() != Some("")
        || network.ports.as_ref().is_none_or(|ports| !ports.is_empty())
        || network
            .networks
            .as_ref()
            .is_none_or(|networks| !networks.is_empty())
        || state.paused != Some(false)
        || state.restarting != Some(false)
        || state.dead != Some(false)
        || state.oom_killed != Some(false)
        || state
            .error
            .as_deref()
            .is_some_and(|error| !error.is_empty())
    {
        return Err(engine_resource_mismatch());
    }

    match state.running {
        Some(true) if state.pid.is_some_and(|pid| pid > 0) => Ok(LifecycleLockObservation::Live {
            id: id.to_owned(),
            operation_id,
        }),
        Some(false)
            if state.pid.is_none_or(|pid| pid == 0)
                && state.exit_code.is_none_or(|code| code == 0) =>
        {
            Ok(LifecycleLockObservation::Stopped {
                id: id.to_owned(),
                operation_id,
            })
        }
        _ => Err(engine_resource_mismatch()),
    }
}

fn desired_reader_labels(
    installation: &Installation,
    epoch_fingerprint: Sha256Digest,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        (LABEL_MANAGED.to_owned(), "true".to_owned()),
        (
            LABEL_INSTALLATION_ID.to_owned(),
            installation.id().to_string(),
        ),
        (
            LABEL_INSTALLATION_KEY.to_owned(),
            installation.selector_key().to_string(),
        ),
        (
            LABEL_COMPOSE_PROJECT.to_owned(),
            installation.compose_project().to_string(),
        ),
        (LABEL_EPOCH.to_owned(), epoch_fingerprint.to_string()),
        (
            LABEL_RESOURCE_KIND.to_owned(),
            DESIRED_READER_KIND.to_owned(),
        ),
    ])
}

fn desired_reader_body(
    image: &str,
    desired_volume: &str,
    labels: &BTreeMap<String, String>,
) -> ContainerCreateBody {
    ContainerCreateBody {
        user: Some("65532:65532".to_owned()),
        attach_stdin: Some(false),
        attach_stdout: Some(false),
        attach_stderr: Some(false),
        tty: Some(false),
        open_stdin: Some(false),
        stdin_once: Some(false),
        env: Some(Vec::new()),
        cmd: Some(vec![
            "internal".to_owned(),
            "local".to_owned(),
            "read-desired".to_owned(),
        ]),
        image: Some(image.to_owned()),
        working_dir: Some("/".to_owned()),
        entrypoint: Some(vec!["/usr/local/bin/automata".to_owned()]),
        network_disabled: Some(true),
        labels: Some(labels.clone().into_iter().collect()),
        stop_signal: Some("SIGKILL".to_owned()),
        stop_timeout: Some(0),
        host_config: Some(HostConfig {
            memory: Some(HELPER_MEMORY_BYTES),
            memory_swap: Some(HELPER_MEMORY_BYTES),
            nano_cpus: Some(HELPER_NANO_CPUS),
            pids_limit: Some(HELPER_PIDS),
            console_size: Some(vec![0, 0]),
            shm_size: Some(HELPER_SHM_BYTES),
            isolation: Some(HostConfigIsolationEnum::EMPTY),
            init: Some(false),
            mounts: Some(vec![Mount {
                target: Some("/run/automata-desired".to_owned()),
                source: Some(desired_volume.to_owned()),
                typ: Some(MountType::VOLUME),
                read_only: Some(true),
                volume_options: Some(MountVolumeOptions {
                    no_copy: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            cap_add: Some(Vec::new()),
            cap_drop: Some(vec!["ALL".to_owned()]),
            network_mode: Some("none".to_owned()),
            restart_policy: Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::NO),
                maximum_retry_count: Some(0),
            }),
            auto_remove: Some(false),
            cgroupns_mode: Some(HostConfigCgroupnsModeEnum::PRIVATE),
            ipc_mode: Some("private".to_owned()),
            readonly_rootfs: Some(true),
            security_opt: Some(helper_security_options()),
            masked_paths: Some(helper_masked_paths()),
            readonly_paths: Some(helper_readonly_paths()),
            log_config: Some(helper_log_config()),
            runtime: Some("runc".to_owned()),
            userns_mode: Some("host".to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

const fn cas_volume_role(target: CasTarget) -> VolumeRole {
    match target {
        CasTarget::BootstrapRequest | CasTarget::BootstrapToken => VolumeRole::BootstrapState,
        CasTarget::RelayBinding => VolumeRole::RelayBinding,
        CasTarget::RunnerConfig => VolumeRole::RunnerConfig,
        CasTarget::RunnerS3AccessKey
        | CasTarget::RunnerS3Ca
        | CasTarget::RunnerS3SecretKey
        | CasTarget::RunnerSpoolKey => VolumeRole::RunnerSecrets,
    }
}

const fn cas_writer_user(target: CasTarget) -> &'static str {
    match target {
        CasTarget::RelayBinding | CasTarget::RunnerConfig => "0:0",
        CasTarget::BootstrapRequest
        | CasTarget::BootstrapToken
        | CasTarget::RunnerS3AccessKey
        | CasTarget::RunnerS3Ca
        | CasTarget::RunnerS3SecretKey
        | CasTarget::RunnerSpoolKey => "65532:65532",
    }
}

fn cas_writer_labels(
    installation: &Installation,
    epoch: &ImmutableEpoch,
    request: &CasRequest,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        (LABEL_MANAGED.to_owned(), "true".to_owned()),
        (
            LABEL_INSTALLATION_ID.to_owned(),
            installation.id().to_string(),
        ),
        (
            LABEL_INSTALLATION_KEY.to_owned(),
            installation.selector_key().to_string(),
        ),
        (
            LABEL_COMPOSE_PROJECT.to_owned(),
            installation.compose_project().to_string(),
        ),
        (LABEL_EPOCH.to_owned(), epoch.fingerprint().to_string()),
        (
            LABEL_PLAN.to_owned(),
            epoch
                .desired_plan_sha256()
                .expect("lifecycle CAS requires epoch v2")
                .to_string(),
        ),
        (LABEL_RESOURCE_KIND.to_owned(), CAS_WRITER_KIND.to_owned()),
        (
            "io.automata.local.cas-target".to_owned(),
            request.target().slug().to_owned(),
        ),
        (
            "io.automata.local.cas-expected-sha256".to_owned(),
            request
                .expected_sha256()
                .map_or_else(|| "absent".to_owned(), |digest| digest.to_string()),
        ),
        (
            "io.automata.local.cas-replacement-sha256".to_owned(),
            request.replacement_sha256().to_string(),
        ),
    ])
}

fn cas_digest_reader_labels(
    installation: &Installation,
    epoch: &ImmutableEpoch,
    target: CasTarget,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        (LABEL_MANAGED.to_owned(), "true".to_owned()),
        (
            LABEL_INSTALLATION_ID.to_owned(),
            installation.id().to_string(),
        ),
        (
            LABEL_INSTALLATION_KEY.to_owned(),
            installation.selector_key().to_string(),
        ),
        (
            LABEL_COMPOSE_PROJECT.to_owned(),
            installation.compose_project().to_string(),
        ),
        (LABEL_EPOCH.to_owned(), epoch.fingerprint().to_string()),
        (
            LABEL_RESOURCE_KIND.to_owned(),
            CAS_DIGEST_READER_KIND.to_owned(),
        ),
        (
            "io.automata.local.cas-target".to_owned(),
            target.slug().to_owned(),
        ),
    ])
}

fn cas_digest_reader_body(
    image: &str,
    volume_name: &str,
    labels: &BTreeMap<String, String>,
) -> ContainerCreateBody {
    ContainerCreateBody {
        user: Some("0:0".to_owned()),
        attach_stdin: Some(true),
        attach_stdout: Some(false),
        attach_stderr: Some(false),
        tty: Some(false),
        open_stdin: Some(true),
        stdin_once: Some(true),
        env: Some(Vec::new()),
        cmd: Some(vec![
            "internal".to_owned(),
            "local".to_owned(),
            "read-cas-digest".to_owned(),
        ]),
        image: Some(image.to_owned()),
        working_dir: Some("/".to_owned()),
        entrypoint: Some(vec!["/usr/local/bin/automata".to_owned()]),
        network_disabled: Some(true),
        labels: Some(labels.clone().into_iter().collect()),
        stop_signal: Some("SIGKILL".to_owned()),
        stop_timeout: Some(0),
        host_config: Some(HostConfig {
            memory: Some(HELPER_MEMORY_BYTES),
            memory_swap: Some(HELPER_MEMORY_BYTES),
            nano_cpus: Some(HELPER_NANO_CPUS),
            pids_limit: Some(HELPER_PIDS),
            console_size: Some(vec![0, 0]),
            shm_size: Some(HELPER_SHM_BYTES),
            isolation: Some(HostConfigIsolationEnum::EMPTY),
            init: Some(false),
            mounts: Some(vec![Mount {
                target: Some(CAS_MOUNT.to_owned()),
                source: Some(volume_name.to_owned()),
                typ: Some(MountType::VOLUME),
                read_only: Some(true),
                volume_options: Some(MountVolumeOptions {
                    no_copy: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            cap_add: Some(Vec::new()),
            cap_drop: Some(vec!["ALL".to_owned()]),
            network_mode: Some("none".to_owned()),
            restart_policy: Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::NO),
                maximum_retry_count: Some(0),
            }),
            auto_remove: Some(false),
            cgroupns_mode: Some(HostConfigCgroupnsModeEnum::PRIVATE),
            ipc_mode: Some("private".to_owned()),
            readonly_rootfs: Some(true),
            security_opt: Some(helper_security_options()),
            masked_paths: Some(helper_masked_paths()),
            readonly_paths: Some(helper_readonly_paths()),
            log_config: Some(helper_log_config()),
            runtime: Some("runc".to_owned()),
            userns_mode: Some("host".to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn fixed_disposable_host_is_exact(
    host: &HostConfig,
    expected_mount: &Mount,
    cap_add: &[String],
) -> bool {
    host.mounts
        .as_deref()
        .is_some_and(|actual| helper_mounts_match(actual, std::slice::from_ref(expected_mount)))
        && host.readonly_rootfs == Some(true)
        && host.network_mode.as_deref() == Some("none")
        && host.cap_drop.as_deref() == Some(["ALL".to_owned()].as_slice())
        && host.cap_add.as_deref() == Some(cap_add)
        && host.auto_remove == Some(false)
        && host.privileged == Some(false)
        && host.init == Some(false)
        && host.memory == Some(HELPER_MEMORY_BYTES)
        && host.memory_swap == Some(HELPER_MEMORY_BYTES)
        && host.nano_cpus == Some(HELPER_NANO_CPUS)
        && host.pids_limit == Some(HELPER_PIDS)
        && host.security_opt.as_deref() == Some(helper_security_options().as_slice())
        && host.masked_paths.as_deref() == Some(helper_masked_paths().as_slice())
        && host.readonly_paths.as_deref() == Some(helper_readonly_paths().as_slice())
        && host.log_config.as_ref() == Some(&helper_log_config())
        && host.binds.as_ref().is_none_or(Vec::is_empty)
        && host.tmpfs.as_ref().is_none_or(HashMap::is_empty)
        && !helper_has_ambient_authority(host)
}

fn fixed_disposable_network_is_exact(network: &bollard::models::NetworkSettings) -> bool {
    network.sandbox_id.as_deref() == Some("")
        && network.sandbox_key.as_deref() == Some("")
        && network.ports.as_ref().is_some_and(HashMap::is_empty)
        && network.networks.as_ref().is_some_and(HashMap::is_empty)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn validate_cas_digest_reader(
    container: &bollard::models::ContainerInspectResponse,
    id: &str,
    name: &str,
    image: &str,
    image_id: &str,
    volume_name: &str,
    labels: &BTreeMap<String, String>,
) -> Result<(), LocalInitError> {
    let config = container
        .config
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let host = container
        .host_config
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let network = container
        .network_settings
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let managed = config
        .labels
        .as_ref()
        .into_iter()
        .flatten()
        .filter(|(key, _)| key.starts_with("io.automata.local."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let expected_mount = Mount {
        target: Some(CAS_MOUNT.to_owned()),
        source: Some(volume_name.to_owned()),
        typ: Some(MountType::VOLUME),
        read_only: Some(true),
        volume_options: Some(MountVolumeOptions {
            no_copy: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    };
    if container.id.as_deref() != Some(id)
        || !exact_container_id_text(id)
        || container.name.as_deref() != Some(format!("/{name}").as_str())
        || container.image.as_deref() != Some(image_id)
        || container.platform.as_deref() != Some("linux")
        || config.image.as_deref() != Some(image)
        || config.user.as_deref() != Some("0:0")
        || config.entrypoint.as_deref() != Some(["/usr/local/bin/automata".to_owned()].as_slice())
        || config.cmd.as_deref()
            != Some(
                [
                    "internal".to_owned(),
                    "local".to_owned(),
                    "read-cas-digest".to_owned(),
                ]
                .as_slice(),
            )
        || config.working_dir.as_deref() != Some("/")
        || config.attach_stdin != Some(true)
        || config.attach_stdout != Some(false)
        || config.attach_stderr != Some(false)
        || config.open_stdin != Some(true)
        || config.stdin_once != Some(true)
        || config.tty != Some(false)
        || config.network_disabled != Some(true)
        || config.env.as_ref().is_some_and(|env| !env.is_empty())
        || config.stop_signal.as_deref() != Some("SIGKILL")
        || config.stop_timeout != Some(0)
        || config.healthcheck.is_some()
        || config.exposed_ports.as_deref()
            != Some([super::HELPER_EXPOSED_PORT.to_owned()].as_slice())
        || config
            .volumes
            .as_ref()
            .is_some_and(|volumes| !volumes.is_empty())
        || config
            .on_build
            .as_ref()
            .is_some_and(|steps| !steps.is_empty())
        || config.shell.as_ref().is_some_and(|shell| !shell.is_empty())
        || managed != *labels
        || host.mounts.as_deref().is_none_or(|actual| {
            !helper_mounts_match(actual, std::slice::from_ref(&expected_mount))
        })
        || host.readonly_rootfs != Some(true)
        || host.network_mode.as_deref() != Some("none")
        || host.cap_drop.as_deref() != Some(["ALL".to_owned()].as_slice())
        || host.cap_add.as_ref().is_none_or(|caps| !caps.is_empty())
        || host.auto_remove != Some(false)
        || host.privileged.unwrap_or(false)
        || helper_has_ambient_authority(host)
        || host.memory != Some(HELPER_MEMORY_BYTES)
        || host.memory_swap != Some(HELPER_MEMORY_BYTES)
        || host.nano_cpus != Some(HELPER_NANO_CPUS)
        || host.pids_limit != Some(HELPER_PIDS)
        || host.security_opt.as_deref() != Some(helper_security_options().as_slice())
        || host.masked_paths.as_deref() != Some(helper_masked_paths().as_slice())
        || host.readonly_paths.as_deref() != Some(helper_readonly_paths().as_slice())
        || host.log_config.as_ref() != Some(&helper_log_config())
        || !fixed_disposable_host_is_exact(host, &expected_mount, &[])
        || !fixed_disposable_network_is_exact(network)
    {
        return Err(engine_resource_mismatch());
    }
    let realized = container
        .mounts
        .as_deref()
        .ok_or_else(engine_resource_mismatch)?;
    if realized.len() != 1
        || realized[0].typ.as_deref() != Some("volume")
        || realized[0].name.as_deref() != Some(volume_name)
        || realized[0].destination.as_deref() != Some(CAS_MOUNT)
        || realized[0].rw != Some(false)
        || realized[0].driver.as_deref() != Some("local")
    {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

fn cas_writer_body(
    image: &str,
    volume_name: &str,
    user: &str,
    cap_add: &[String],
    labels: &BTreeMap<String, String>,
) -> ContainerCreateBody {
    ContainerCreateBody {
        user: Some(user.to_owned()),
        attach_stdin: Some(true),
        attach_stdout: Some(false),
        attach_stderr: Some(false),
        tty: Some(false),
        open_stdin: Some(true),
        stdin_once: Some(true),
        env: Some(Vec::new()),
        cmd: Some(vec![
            "internal".to_owned(),
            "local".to_owned(),
            "write-cas".to_owned(),
        ]),
        image: Some(image.to_owned()),
        working_dir: Some("/".to_owned()),
        entrypoint: Some(vec!["/usr/local/bin/automata".to_owned()]),
        network_disabled: Some(true),
        labels: Some(labels.clone().into_iter().collect()),
        stop_signal: Some("SIGKILL".to_owned()),
        stop_timeout: Some(0),
        host_config: Some(HostConfig {
            memory: Some(HELPER_MEMORY_BYTES),
            memory_swap: Some(HELPER_MEMORY_BYTES),
            nano_cpus: Some(HELPER_NANO_CPUS),
            pids_limit: Some(HELPER_PIDS),
            console_size: Some(vec![0, 0]),
            shm_size: Some(HELPER_SHM_BYTES),
            isolation: Some(HostConfigIsolationEnum::EMPTY),
            init: Some(false),
            mounts: Some(vec![Mount {
                target: Some(CAS_MOUNT.to_owned()),
                source: Some(volume_name.to_owned()),
                typ: Some(MountType::VOLUME),
                read_only: Some(false),
                volume_options: Some(MountVolumeOptions {
                    no_copy: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            cap_add: Some(cap_add.to_vec()),
            cap_drop: Some(vec!["ALL".to_owned()]),
            network_mode: Some("none".to_owned()),
            restart_policy: Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::NO),
                maximum_retry_count: Some(0),
            }),
            auto_remove: Some(false),
            cgroupns_mode: Some(HostConfigCgroupnsModeEnum::PRIVATE),
            ipc_mode: Some("private".to_owned()),
            readonly_rootfs: Some(true),
            security_opt: Some(helper_security_options()),
            masked_paths: Some(helper_masked_paths()),
            readonly_paths: Some(helper_readonly_paths()),
            log_config: Some(helper_log_config()),
            runtime: Some("runc".to_owned()),
            userns_mode: Some("host".to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_cas_writer(
    container: &bollard::models::ContainerInspectResponse,
    id: &str,
    name: &str,
    image: &str,
    image_id: &str,
    volume_name: &str,
    user: &str,
    cap_add: &[String],
    labels: &BTreeMap<String, String>,
) -> Result<(), LocalInitError> {
    let config = container
        .config
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let host = container
        .host_config
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let network = container
        .network_settings
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let managed = config
        .labels
        .as_ref()
        .into_iter()
        .flatten()
        .filter(|(key, _)| key.starts_with("io.automata.local."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let expected_mount = Mount {
        target: Some(CAS_MOUNT.to_owned()),
        source: Some(volume_name.to_owned()),
        typ: Some(MountType::VOLUME),
        read_only: Some(false),
        volume_options: Some(MountVolumeOptions {
            no_copy: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    };
    if container.id.as_deref() != Some(id)
        || !exact_container_id_text(id)
        || container.name.as_deref() != Some(format!("/{name}").as_str())
        || container.image.as_deref() != Some(image_id)
        || container.platform.as_deref() != Some("linux")
        || config.image.as_deref() != Some(image)
        || config.user.as_deref() != Some(user)
        || config.entrypoint.as_deref() != Some(["/usr/local/bin/automata".to_owned()].as_slice())
        || config.cmd.as_deref()
            != Some(
                [
                    "internal".to_owned(),
                    "local".to_owned(),
                    "write-cas".to_owned(),
                ]
                .as_slice(),
            )
        || config.working_dir.as_deref() != Some("/")
        || config.attach_stdin != Some(true)
        || config.attach_stdout != Some(false)
        || config.attach_stderr != Some(false)
        || config.open_stdin != Some(true)
        || config.stdin_once != Some(true)
        || config.tty != Some(false)
        || config.network_disabled != Some(true)
        || config.env.as_ref().is_some_and(|env| !env.is_empty())
        || config.stop_signal.as_deref() != Some("SIGKILL")
        || config.stop_timeout != Some(0)
        || config.healthcheck.is_some()
        || config.exposed_ports.as_deref()
            != Some([super::HELPER_EXPOSED_PORT.to_owned()].as_slice())
        || config
            .volumes
            .as_ref()
            .is_some_and(|volumes| !volumes.is_empty())
        || config
            .on_build
            .as_ref()
            .is_some_and(|steps| !steps.is_empty())
        || config.shell.as_ref().is_some_and(|shell| !shell.is_empty())
        || managed != *labels
        || host.mounts.as_deref().is_none_or(|actual| {
            !helper_mounts_match(actual, std::slice::from_ref(&expected_mount))
        })
        || host.readonly_rootfs != Some(true)
        || host.network_mode.as_deref() != Some("none")
        || host.cap_drop.as_deref() != Some(["ALL".to_owned()].as_slice())
        || host.cap_add.as_deref() != Some(cap_add)
        || host.auto_remove != Some(false)
        || !fixed_disposable_host_is_exact(host, &expected_mount, cap_add)
        || !fixed_disposable_network_is_exact(network)
    {
        return Err(engine_resource_mismatch());
    }
    let realized = container
        .mounts
        .as_deref()
        .ok_or_else(engine_resource_mismatch)?;
    if realized.len() != 1
        || realized[0].typ.as_deref() != Some("volume")
        || realized[0].name.as_deref() != Some(volume_name)
        || realized[0].destination.as_deref() != Some(CAS_MOUNT)
        || realized[0].rw != Some(true)
        || realized[0].driver.as_deref() != Some("local")
    {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_desired_reader(
    container: &bollard::models::ContainerInspectResponse,
    id: &str,
    name: &str,
    image: &str,
    image_id: &str,
    desired_volume: &str,
    labels: &BTreeMap<String, String>,
) -> Result<(), LocalInitError> {
    let config = container
        .config
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let host = container
        .host_config
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let network = container
        .network_settings
        .as_ref()
        .ok_or_else(engine_resource_mismatch)?;
    let managed = config
        .labels
        .as_ref()
        .into_iter()
        .flatten()
        .filter(|(key, _)| key.starts_with("io.automata.local."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let expected_mount = Mount {
        target: Some("/run/automata-desired".to_owned()),
        source: Some(desired_volume.to_owned()),
        typ: Some(MountType::VOLUME),
        read_only: Some(true),
        volume_options: Some(MountVolumeOptions {
            no_copy: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    };
    if container.id.as_deref() != Some(id)
        || !exact_container_id_text(id)
        || container.name.as_deref() != Some(format!("/{name}").as_str())
        || container.image.as_deref() != Some(image_id)
        || container.platform.as_deref() != Some("linux")
        || config.image.as_deref() != Some(image)
        || config.user.as_deref() != Some("65532:65532")
        || config.entrypoint.as_deref() != Some(["/usr/local/bin/automata".to_owned()].as_slice())
        || config.cmd.as_deref()
            != Some(
                [
                    "internal".to_owned(),
                    "local".to_owned(),
                    "read-desired".to_owned(),
                ]
                .as_slice(),
            )
        || config.working_dir.as_deref() != Some("/")
        || config.attach_stdin != Some(false)
        || config.attach_stdout != Some(false)
        || config.attach_stderr != Some(false)
        || config.open_stdin != Some(false)
        || config.stdin_once != Some(false)
        || config.tty != Some(false)
        || config.network_disabled != Some(true)
        || config.env.as_ref().is_some_and(|env| !env.is_empty())
        || config.stop_signal.as_deref() != Some("SIGKILL")
        || config.stop_timeout != Some(0)
        || config.healthcheck.is_some()
        || config.exposed_ports.as_deref()
            != Some([super::HELPER_EXPOSED_PORT.to_owned()].as_slice())
        || config
            .volumes
            .as_ref()
            .is_some_and(|volumes| !volumes.is_empty())
        || config
            .on_build
            .as_ref()
            .is_some_and(|steps| !steps.is_empty())
        || config.shell.as_ref().is_some_and(|shell| !shell.is_empty())
        || managed != *labels
        || host.mounts.as_deref().is_none_or(|actual| {
            !helper_mounts_match(actual, std::slice::from_ref(&expected_mount))
        })
        || host.readonly_rootfs != Some(true)
        || host.network_mode.as_deref() != Some("none")
        || host.cap_drop.as_deref() != Some(["ALL".to_owned()].as_slice())
        || host.cap_add.as_ref().is_none_or(|caps| !caps.is_empty())
        || host.auto_remove != Some(false)
        || !fixed_disposable_host_is_exact(host, &expected_mount, &[])
        || !fixed_disposable_network_is_exact(network)
    {
        return Err(engine_resource_mismatch());
    }
    let realized = container
        .mounts
        .as_deref()
        .ok_or_else(engine_resource_mismatch)?;
    if realized.len() != 1
        || realized[0].typ.as_deref() != Some("volume")
        || realized[0].name.as_deref() != Some(desired_volume)
        || realized[0].destination.as_deref() != Some("/run/automata-desired")
        || realized[0].rw != Some(false)
        || realized[0].driver.as_deref() != Some("local")
    {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

fn validate_results_transit(
    network: &NetworkInspect,
    installation: &Installation,
    desired: &DesiredSpec,
    require_empty: bool,
) -> Result<(), LocalInitError> {
    let ipam = network.ipam.as_ref().ok_or_else(engine_resource_mismatch)?;
    let config = ipam
        .config
        .as_deref()
        .ok_or_else(engine_resource_mismatch)?;
    let labels = network
        .labels
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let endpoint_ids = network
        .containers
        .as_ref()
        .map(|containers| containers.keys().cloned().collect())
        .unwrap_or_default();
    let shape = ResultsTransitNetworkShape {
        name: network.name.clone().unwrap_or_default(),
        driver: network.driver.clone().unwrap_or_default(),
        scope: network.scope.clone().unwrap_or_default(),
        enable_ipv4: network.enable_ipv4 == Some(true),
        enable_ipv6: network.enable_ipv6 == Some(true),
        internal: network.internal == Some(true),
        attachable: network.attachable == Some(true),
        ingress: network.ingress == Some(true),
        config_only: network.config_only == Some(true),
        config_from_empty: network
            .config_from
            .as_ref()
            .is_none_or(|reference| reference.network.as_deref().is_none_or(str::is_empty)),
        ipam_driver: ipam.driver.clone().unwrap_or_default(),
        ipam_options: ipam
            .options
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect(),
        options: network
            .options
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect(),
        labels,
        endpoint_ids,
    };
    if !exact_results_transit_base(&shape, installation, desired.plan_digest())
        || network
            .id
            .as_deref()
            .is_none_or(|id| !exact_container_id_text(id))
        || config
            != [IpamConfig {
                subnet: Some(desired.results_transit().subnet()),
                gateway: Some(desired.results_transit().gateway().to_string()),
                ip_range: None,
                auxiliary_addresses: None,
            }]
        || require_empty && !shape.endpoint_ids.is_empty()
    {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

#[cfg(test)]
mod daemon_generation_tests {
    use super::*;
    use futures::channel::mpsc as futures_mpsc;

    fn generation(boot: u128, pid: u32, start_ticks: u64) -> EngineDaemonGeneration {
        EngineDaemonGeneration {
            boot_id: uuid::Uuid::from_u128(boot),
            pid,
            start_ticks,
        }
    }

    fn qualified_daemon_info() -> LifecycleDaemonInfo {
        LifecycleDaemonInfo {
            security_options: vec![
                "name=seccomp,profile=builtin".to_owned(),
                "name=cgroupns".to_owned(),
                "name=userns".to_owned(),
            ],
            memory_limit: true,
            swap_limit: true,
            cpu_cfs_period: true,
            cpu_cfs_quota: true,
            pids_limit: true,
            cgroup_version: "2".to_owned(),
            live_restore_enabled: false,
            default_runtime: "runc".to_owned(),
            default_ulimits: None,
        }
    }

    #[test]
    fn lifecycle_daemon_contract_is_closed_and_fail_closed() {
        let valid = qualified_daemon_info();
        validate_lifecycle_daemon_info(&valid).unwrap();
        let mut optional_nnp = valid.clone();
        optional_nnp
            .security_options
            .push("name=no-new-privileges".to_owned());
        validate_lifecycle_daemon_info(&optional_nnp).unwrap();

        let mut invalid = Vec::new();
        let mut missing_userns = valid.clone();
        missing_userns
            .security_options
            .retain(|option| option != "name=userns");
        invalid.push(missing_userns);
        let mut extra_security = valid.clone();
        extra_security
            .security_options
            .push("name=apparmor".to_owned());
        invalid.push(extra_security);
        let mut duplicate_security = valid.clone();
        duplicate_security
            .security_options
            .push("name=cgroupns".to_owned());
        invalid.push(duplicate_security);
        for mutate in [
            |info: &mut LifecycleDaemonInfo| info.memory_limit = false,
            |info: &mut LifecycleDaemonInfo| info.swap_limit = false,
            |info: &mut LifecycleDaemonInfo| info.cpu_cfs_period = false,
            |info: &mut LifecycleDaemonInfo| info.cpu_cfs_quota = false,
            |info: &mut LifecycleDaemonInfo| info.pids_limit = false,
            |info: &mut LifecycleDaemonInfo| info.live_restore_enabled = true,
        ] {
            let mut changed = valid.clone();
            mutate(&mut changed);
            invalid.push(changed);
        }
        let mut cgroup_one = valid.clone();
        cgroup_one.cgroup_version = "1".to_owned();
        invalid.push(cgroup_one);
        let mut wrong_runtime = valid.clone();
        wrong_runtime.default_runtime = "custom".to_owned();
        invalid.push(wrong_runtime);
        let mut default_ulimits = valid;
        default_ulimits.default_ulimits = Some(HashMap::from([(
            "nofile".to_owned(),
            serde_json::json!({"Hard": 1024, "Name": "nofile", "Soft": 1024}),
        )]));
        invalid.push(default_ulimits);

        for info in invalid {
            assert_eq!(
                validate_lifecycle_daemon_info(&info).unwrap_err().code(),
                LocalInitErrorCode::EngineUnavailable
            );
        }
    }

    #[test]
    fn rendered_masked_paths_normalize_supported_moby_defaults_only() {
        let base = [
            "/proc/acpi",
            "/proc/asound",
            "/proc/kcore",
            "/proc/keys",
            "/proc/latency_stats",
            "/proc/sched_debug",
            "/proc/scsi",
            "/proc/timer_list",
            "/proc/timer_stats",
            "/sys/devices/virtual/powercap",
            "/sys/firmware",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        assert!(valid_rendered_masked_paths(Some(&base)));

        let mut current = base.clone();
        current.extend([
            "/proc/interrupts".to_owned(),
            "/sys/devices/system/cpu/cpu0/thermal_throttle".to_owned(),
            "/sys/devices/system/cpu/cpu12/thermal_throttle".to_owned(),
        ]);
        assert!(valid_rendered_masked_paths(Some(&current)));

        let mut missing = base.clone();
        missing.pop();
        assert!(!valid_rendered_masked_paths(Some(&missing)));
        let mut duplicate = base.clone();
        duplicate.push(base[0].clone());
        assert!(!valid_rendered_masked_paths(Some(&duplicate)));
        for extra in [
            "/proc/unknown",
            "/sys/devices/system/cpu/cpu01/thermal_throttle",
            "/sys/devices/system/cpu/cpu0/other",
        ] {
            let mut invalid = base.clone();
            invalid.push(extra.to_owned());
            assert!(!valid_rendered_masked_paths(Some(&invalid)));
        }
    }

    fn none_endpoint(network_id: &str, running: bool) -> bollard::models::EndpointSettings {
        bollard::models::EndpointSettings {
            network_id: Some(network_id.to_owned()),
            endpoint_id: running.then(|| "c".repeat(64)),
            gateway: running.then(String::new),
            ip_address: running.then(String::new),
            ip_prefix_len: running.then_some(0),
            ipv6_gateway: running.then(String::new),
            global_ipv6_address: running.then(String::new),
            global_ipv6_prefix_len: running.then_some(0),
            mac_address: running.then(String::new),
            ..Default::default()
        }
    }

    #[test]
    fn running_none_network_accepts_only_null_exposed_port_bindings() {
        let sandbox_id = "a".repeat(64);
        let network_id = "b".repeat(64);
        let mut network = bollard::models::NetworkSettings {
            sandbox_id: Some(sandbox_id.clone()),
            sandbox_key: Some(format!("/var/run/docker/netns/{}", &sandbox_id[..12])),
            ports: Some(HashMap::from([("8080/tcp".to_owned(), None)])),
            networks: Some(HashMap::from([(
                "none".to_owned(),
                none_endpoint(&network_id, true),
            )])),
        };
        assert!(exact_running_none_network(&network, &network_id));
        network.ports = Some(HashMap::new());
        assert!(exact_running_none_network(&network, &network_id));
        network.ports = Some(HashMap::from([(
            "8080/tcp".to_owned(),
            Some(vec![bollard::models::PortBinding {
                host_ip: Some("127.0.0.1".to_owned()),
                host_port: Some("8080".to_owned()),
            }]),
        )]));
        assert!(!exact_running_none_network(&network, &network_id));
        network.ports = Some(HashMap::new());
        network
            .networks
            .as_mut()
            .unwrap()
            .get_mut("none")
            .unwrap()
            .aliases = Some(vec!["ambient".to_owned()]);
        assert!(!exact_running_none_network(&network, &network_id));
    }

    #[test]
    fn stopped_none_network_rejects_residual_operational_state() {
        let network_id = "b".repeat(64);
        let mut network = bollard::models::NetworkSettings {
            sandbox_id: Some(String::new()),
            sandbox_key: Some(String::new()),
            ports: Some(HashMap::new()),
            networks: Some(HashMap::from([(
                "none".to_owned(),
                none_endpoint(&network_id, false),
            )])),
        };
        assert!(exact_stopped_none_network(&network, &network_id));
        network
            .networks
            .as_mut()
            .unwrap()
            .get_mut("none")
            .unwrap()
            .ip_address = Some("172.18.0.2".to_owned());
        assert!(!exact_stopped_none_network(&network, &network_id));
        network
            .networks
            .as_mut()
            .unwrap()
            .get_mut("none")
            .unwrap()
            .ip_address = None;
        network.networks.as_mut().unwrap().insert(
            "bridge".to_owned(),
            bollard::models::EndpointSettings::default(),
        );
        assert!(!exact_stopped_none_network(&network, &network_id));
    }

    #[test]
    fn lifecycle_lock_labels_are_the_exact_image_and_managed_union() {
        let image = BTreeMap::from([
            (
                "org.opencontainers.image.source".to_owned(),
                "automata".to_owned(),
            ),
            (
                "org.opencontainers.image.version".to_owned(),
                "1".to_owned(),
            ),
        ]);
        let managed = BTreeMap::from([("io.automata.local.managed".to_owned(), "true".to_owned())]);
        let labels = lifecycle_lock_expected_labels(&image, managed.clone()).unwrap();
        assert_eq!(labels.len(), 3);
        assert_eq!(labels["org.opencontainers.image.source"], "automata");
        assert_eq!(labels["io.automata.local.managed"], "true");

        let mut colliding = image;
        colliding.insert(
            "io.automata.local.ambient".to_owned(),
            "forbidden".to_owned(),
        );
        assert_eq!(
            lifecycle_lock_expected_labels(&colliding, managed)
                .unwrap_err()
                .code(),
            LocalInitErrorCode::EngineResourceMismatch
        );
    }

    #[test]
    fn reset_runner_discovery_accepts_zero_or_one_authority_only() {
        assert_eq!(sole_local_docker_runner_id(BTreeSet::new()).unwrap(), None);
        let first = uuid::Uuid::from_u128(1);
        assert_eq!(
            sole_local_docker_runner_id(BTreeSet::from([first])).unwrap(),
            Some(first)
        );
        assert_eq!(
            sole_local_docker_runner_id(BTreeSet::from([first, uuid::Uuid::from_u128(2)]))
                .unwrap_err()
                .code(),
            LocalInitErrorCode::EngineResourceMismatch
        );
    }

    #[tokio::test]
    async fn holder_eof_wins_over_a_queued_mutation_permit() {
        let output = futures::stream::empty::<()>();
        let lost = CancellationToken::new();
        let (commands, requests) = mpsc::channel(1);
        let (permit, permitted) = oneshot::channel();
        commands
            .send(LifecycleLockCommand::AuthorizeMutation(permit))
            .await
            .unwrap();

        assert!(
            monitor_lifecycle_lock_output(output, requests, lost.clone())
                .await
                .is_err()
        );
        assert!(lost.is_cancelled());
        assert!(permitted.await.is_err());
    }

    #[tokio::test]
    async fn graceful_holder_release_linearizes_before_clean_eof() {
        let (output, output_stream) = futures_mpsc::unbounded::<()>();
        let lost = CancellationToken::new();
        let (commands, requests) = mpsc::channel(1);
        let monitor = tokio::spawn(monitor_lifecycle_lock_output(
            output_stream,
            requests,
            lost.clone(),
        ));
        let (acknowledge, acknowledged) = oneshot::channel();
        let (frame_sent, frame_confirmation) = oneshot::channel();
        commands
            .send(LifecycleLockCommand::BeginRelease {
                acknowledged: acknowledge,
                frame_sent: frame_confirmation,
            })
            .await
            .unwrap();
        acknowledged.await.unwrap();
        frame_sent.send(()).unwrap();
        drop(output);

        assert!(monitor.await.unwrap().is_ok());
        assert!(!lost.is_cancelled());
    }

    #[tokio::test]
    async fn graceful_holder_release_accepts_eof_before_frame_confirmation() {
        let (output, output_stream) = futures_mpsc::unbounded::<()>();
        let lost = CancellationToken::new();
        let (commands, requests) = mpsc::channel(1);
        let monitor = tokio::spawn(monitor_lifecycle_lock_output(
            output_stream,
            requests,
            lost.clone(),
        ));
        let (acknowledge, acknowledged) = oneshot::channel();
        let (frame_sent, frame_confirmation) = oneshot::channel();
        commands
            .send(LifecycleLockCommand::BeginRelease {
                acknowledged: acknowledge,
                frame_sent: frame_confirmation,
            })
            .await
            .unwrap();
        acknowledged.await.unwrap();
        drop(output);
        tokio::task::yield_now().await;
        frame_sent.send(()).unwrap();

        assert!(monitor.await.unwrap().is_ok());
        assert!(!lost.is_cancelled());
    }

    #[tokio::test]
    async fn graceful_holder_release_rejects_eof_without_frame_confirmation() {
        let (output, output_stream) = futures_mpsc::unbounded::<()>();
        let lost = CancellationToken::new();
        let (commands, requests) = mpsc::channel(1);
        let monitor = tokio::spawn(monitor_lifecycle_lock_output(
            output_stream,
            requests,
            lost.clone(),
        ));
        let (acknowledge, acknowledged) = oneshot::channel();
        let (frame_sent, frame_confirmation) = oneshot::channel();
        commands
            .send(LifecycleLockCommand::BeginRelease {
                acknowledged: acknowledge,
                frame_sent: frame_confirmation,
            })
            .await
            .unwrap();
        acknowledged.await.unwrap();
        drop(output);
        drop(frame_sent);

        assert!(monitor.await.unwrap().is_err());
        assert!(lost.is_cancelled());
    }

    #[tokio::test]
    async fn holder_output_wins_over_a_release_frame() {
        let (output, output_stream) = futures_mpsc::unbounded::<()>();
        let lost = CancellationToken::new();
        let (commands, requests) = mpsc::channel(1);
        let monitor = tokio::spawn(monitor_lifecycle_lock_output(
            output_stream,
            requests,
            lost.clone(),
        ));
        let (acknowledge, acknowledged) = oneshot::channel();
        let (frame_sent, frame_confirmation) = oneshot::channel();
        commands
            .send(LifecycleLockCommand::BeginRelease {
                acknowledged: acknowledge,
                frame_sent: frame_confirmation,
            })
            .await
            .unwrap();
        acknowledged.await.unwrap();
        output.unbounded_send(()).unwrap();
        frame_sent.send(()).unwrap();

        assert!(monitor.await.unwrap().is_err());
        assert!(lost.is_cancelled());
    }

    #[test]
    fn holder_loss_dominates_caller_cancellation() {
        let holder_lost = CancellationToken::new();
        let caller = CancellationToken::new();
        holder_lost.cancel();
        caller.cancel();
        let (commands, _requests) = mpsc::channel(1);
        let mutation = LifecycleMutationFence {
            commands,
            holder_lost,
            caller,
            gate: Arc::new(Mutex::new(LifecycleMutationGateState::default())),
        };
        assert_eq!(
            mutation.checkpoint().unwrap_err().code(),
            LocalInitErrorCode::ResetRequired
        );
    }

    #[tokio::test]
    async fn mutation_gate_drains_one_request_then_closes_permanently() {
        let (output, output_stream) = futures_mpsc::unbounded::<()>();
        let holder_lost = CancellationToken::new();
        let caller = CancellationToken::new();
        let (commands, requests) = mpsc::channel(1);
        let monitor = tokio::spawn(monitor_lifecycle_lock_output(
            output_stream,
            requests,
            holder_lost.clone(),
        ));
        let gate = Arc::new(Mutex::new(LifecycleMutationGateState::default()));
        let mutation = LifecycleMutationFence {
            commands,
            holder_lost,
            caller,
            gate: Arc::clone(&gate),
        };
        let (started, start) = oneshot::channel();
        let (finish, finished) = oneshot::channel();
        let running = tokio::spawn({
            let mutation = mutation.clone();
            async move {
                mutation
                    .run(async move {
                        started.send(()).unwrap();
                        let _completed = finished.await;
                    })
                    .await
            }
        });
        start.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), Arc::clone(&gate).lock_owned())
                .await
                .is_err()
        );
        finish.send(()).unwrap();
        running.await.unwrap().unwrap();

        let mut release = Arc::clone(&gate).lock_owned().await;
        release.closed = true;
        drop(release);
        let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let result = mutation
            .run({
                let polled = Arc::clone(&polled);
                async move {
                    polled.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            })
            .await;
        assert_eq!(
            result.unwrap_err().code(),
            LocalInitErrorCode::ResetRequired
        );
        assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));

        drop(output);
        assert!(monitor.await.unwrap().is_err());
    }

    #[test]
    fn stopped_daemon_requires_positive_absence_not_elapsed_time() {
        let stopped = generation(1, 42, 100);
        assert_eq!(
            daemon_generation_absence_from_observation(&stopped, stopped.boot_id, Ok(100))
                .unwrap_err()
                .code(),
            LocalInitErrorCode::ResetRequired
        );
        assert_eq!(
            daemon_generation_absence_from_observation(
                &stopped,
                stopped.boot_id,
                Err(ErrorKind::PermissionDenied),
            )
            .unwrap_err()
            .code(),
            LocalInitErrorCode::ResetRequired
        );
    }

    #[test]
    fn host_reboot_missing_pid_and_pid_reuse_are_positive_absence() {
        let stopped = generation(1, 42, 100);
        assert!(
            daemon_generation_absence_from_observation(
                &stopped,
                uuid::Uuid::from_u128(2),
                Ok(100),
            )
            .is_ok()
        );
        assert!(
            daemon_generation_absence_from_observation(
                &stopped,
                stopped.boot_id,
                Err(ErrorKind::NotFound),
            )
            .is_ok()
        );
        assert!(
            daemon_generation_absence_from_observation(&stopped, stopped.boot_id, Ok(101)).is_ok()
        );
    }

    #[test]
    fn replacement_daemon_must_differ_and_remain_stable_through_the_fence() {
        let stopped = generation(1, 42, 100);
        let replacement = generation(1, 43, 200);
        assert_eq!(
            validate_replacement_daemon_generation(&stopped, &stopped, &stopped)
                .unwrap_err()
                .code(),
            LocalInitErrorCode::ResetRequired
        );
        assert_eq!(
            validate_replacement_daemon_generation(
                &stopped,
                &replacement,
                &generation(1, 44, 300),
            )
            .unwrap_err()
            .code(),
            LocalInitErrorCode::ResetRequired
        );
        assert!(
            validate_replacement_daemon_generation(&stopped, &replacement, &replacement).is_ok()
        );
    }

    #[test]
    fn daemon_generation_labels_are_exact_and_canonical() {
        let installation = Installation::verified(
            crate::InstallationName::default(),
            crate::InstallationId::new(),
        );
        let operation = OperationId::new();
        let generation = generation(1, 42, 100);
        let labels = lifecycle_lock_labels(&installation, operation, &generation);
        assert_eq!(daemon_generation_from_labels(&labels).unwrap(), generation);

        for key in [
            LABEL_ENGINE_BOOT_ID,
            LABEL_ENGINE_PID,
            LABEL_ENGINE_START_TICKS,
        ] {
            let mut malformed = labels.clone();
            malformed.insert(key.to_owned(), "not-canonical".to_owned());
            assert_eq!(
                daemon_generation_from_labels(&malformed)
                    .unwrap_err()
                    .code(),
                LocalInitErrorCode::EngineResourceMismatch
            );
        }
    }

    #[test]
    fn daemon_generation_ping_response_is_closed() {
        validate_engine_generation_response(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .unwrap();
        for invalid in [
            b"HTTP/1.0 500 Internal Server Error\r\n\r\nOK".as_slice(),
            b"HTTP/1.0 200 OK\r\n\r\nNO".as_slice(),
            b"HTTP/1.0 200 OK\n\nOK".as_slice(),
            b"HTTP/1.0 200 OK\r\n\r\nOKextra".as_slice(),
        ] {
            assert_eq!(
                validate_engine_generation_response(invalid)
                    .unwrap_err()
                    .code(),
                LocalInitErrorCode::EngineUnavailable
            );
        }
    }

    #[test]
    #[ignore = "requires the fixed local Docker Engine"]
    fn live_daemon_generation_identifies_the_response_writer() {
        let generation = current_engine_daemon_generation().unwrap();
        assert_ne!(generation.pid, 1, "socket owner is not the response writer");
        let command = fs::read_to_string(format!("/proc/{}/comm", generation.pid)).unwrap();
        assert_eq!(command.trim_end(), "dockerd");
    }
}
